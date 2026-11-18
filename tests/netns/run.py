#!/usr/bin/env python3
"""Root-only Linux integration test: real RIFT processes and WireGuard in netns."""
import base64
import ipaddress
import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = pathlib.Path(os.environ.get("RIFT_BIN", ROOT / "target/release/rift")).resolve()
PID = os.getpid()
VPS = f"rv{PID}"
ROUTER = f"rr{PID}"
CLIENT = f"rc{PID}"
CLIENT_ALT = f"rca{PID}"
BACKEND = f"rbk{PID}"
AGENTS = [f"ra{PID}{n}" for n in (1, 2, 3)]
BR_PUBLIC = f"rbp{PID}"
BR_AGENT = f"rba{PID}"
BR_BACKEND = f"rbb{PID}"
WORK = None
PROCS = []
# A second server behind a 1:1 cloud NAT (Oracle Cloud, AWS, GCP style): only a private
# address is on its interface, a gateway namespace maps a public address onto it.
NAT_VPS = f"rnv{PID}"
NAT_GW = f"rng{PID}"
NAT_AGENT = f"rna{PID}"
BR_NAT = f"rbn{PID}"
# A phone or laptop with a real WireGuard client, for the private VPN access.
DEVICE = f"rdv{PID}"
NETNS = [VPS, ROUTER, CLIENT, CLIENT_ALT, BACKEND, *AGENTS, NAT_VPS, NAT_GW, NAT_AGENT, DEVICE]
PUBLIC_V4 = "198.18.0.1"
PUBLIC_V4_NEW = "198.18.0.2"
PUBLIC_V6 = "2001:db8:42:5249::1"
CLIENT_PUBLIC_V6 = "2001:db8:42:5249::10"
CLIENT_ALT_PUBLIC_V6 = "2001:db8:42:5249::11"
WG_PUBLIC_NAT = "198.18.0.254"
SERVER_HOST = "rift-vps.test"
NAT_PUBLIC_V4 = "198.18.0.50"
NAT_PRIVATE_V4 = "10.99.0.2"
NAT_SERVER_HOST = "rift-nat.test"
MARK = "0x52490000"


def run(args, *, check=True, capture=True, timeout=20, env=None):
    result = subprocess.run([str(x) for x in args], check=False, text=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None,
                            timeout=timeout, env=env)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(map(str,args))}\n"
                           f"stdout: {result.stdout}\nstderr: {result.stderr}")
    return result


def ns(name, *args, check=True, timeout=20, env=None):
    return run(["ip", "netns", "exec", name, *args], check=check, timeout=timeout, env=env)


def sh_ns(name, script, *, check=True):
    return ns(name, "sh", "-ec", script, check=check)


def write(path, value, mode=0o600):
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(value, encoding="utf-8")
    p.chmod(mode)
    return p


def attach(nsname, hostif, nsif, bridge):
    run(["ip", "link", "add", hostif, "type", "veth", "peer", "name", nsif])
    run(["ip", "link", "set", nsif, "netns", nsname])
    run(["ip", "link", "set", hostif, "master", bridge])
    run(["ip", "link", "set", hostif, "up"])
    used = ns(nsname, "ip", "-o", "link", "show").stdout
    link_name = "eth1" if any(" eth0@" in line or " eth0:" in line for line in used.splitlines()) else "eth0"
    ns(nsname, "ip", "link", "set", nsif, "name", link_name)
    ns(nsname, "ip", "link", "set", "lo", "up")
    ns(nsname, "ip", "link", "set", link_name, "up")


def config(state_dir, *, server=False, endpoint=SERVER_HOST,
           public_ips=(PUBLIC_V4, PUBLIC_V4_NEW, PUBLIC_V6)):
    values = [
        f'state_dir = "{state_dir}"', 'interface = "rift0"',
        'wg_port = 51820', 'control_port = 8444',
        'route_table = 51888', 'rule_priority = 11000',
        f'mark = {int(MARK, 16)}', 'mark_mask = 4294901760',
        'keepalive = 3', 'mtu = 1380', 'handshake_timeout = 6',
        'poll_seconds = 2',
    ]
    if server:
        values += [f'public_endpoint = "{endpoint}"',
                   "public_ips = [" + ", ".join(f'"{ip}"' for ip in public_ips) + "]",
                   'enrollment_bind = "0.0.0.0:8443"',
                   'enrollment = "always"']
    return write(WORK / f"{pathlib.Path(state_dir).name}.toml", "\n".join(values) + "\n")


def daemon(name, cfg, command, extra_env=None, label=None):
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    out = (WORK / f"{label or name}.log").open("w", encoding="utf-8")
    process = subprocess.Popen(["ip", "netns", "exec", name, str(BIN),
                                "--config", str(cfg), *command],
                               env=env, stdout=out, stderr=subprocess.STDOUT,
                               start_new_session=True, text=True)
    PROCS.append((process, out, name))
    return process


def cli(name, cfg, *args, env=None):
    cmd_env = os.environ.copy()
    if env:
        cmd_env.update(env)
    return ns(name, str(BIN), "--config", str(cfg), "--json", *args, env=cmd_env)


def status(cfg):
    return json.loads(cli(VPS, cfg, "status").stdout)


def wait_until(predicate, message, timeout=75):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except (RuntimeError, json.JSONDecodeError, OSError):
            pass
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {message}; last={last!r}")


def stop_process(process, sig=signal.SIGINT, timeout=5):
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, sig)
        process.wait(timeout=timeout)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            pass


def cleanup():
    for process, out, _ in reversed(PROCS):
        stop_process(process, signal.SIGKILL)
        out.close()
    run(["ip", "link", "del", BR_PUBLIC], check=False)
    run(["ip", "link", "del", BR_AGENT], check=False)
    run(["ip", "link", "del", BR_BACKEND], check=False)
    run(["ip", "link", "del", BR_NAT], check=False)
    for name in NETNS:
        run(["ip", "netns", "del", name], check=False)
        shutil.rmtree(f"/etc/netns/{name}", ignore_errors=True)
    shutil.rmtree(WORK, ignore_errors=True)


def create_topology():
    run(["ip", "link", "add", BR_PUBLIC, "type", "bridge"])
    run(["ip", "link", "set", BR_PUBLIC, "up"])
    run(["ip", "link", "add", BR_AGENT, "type", "bridge"])
    run(["ip", "link", "set", BR_AGENT, "up"])
    run(["ip", "link", "add", BR_BACKEND, "type", "bridge"])
    run(["ip", "link", "set", BR_BACKEND, "up"])
    for name in NETNS:
        run(["ip", "netns", "add", name])

    attach(VPS, f"hv{PID}", f"nv{PID}", BR_PUBLIC)
    attach(ROUTER, f"hrp{PID}", f"nrp{PID}", BR_PUBLIC)
    attach(ROUTER, f"hra{PID}", f"nra{PID}", BR_AGENT)
    attach(CLIENT, f"hc{PID}", f"nc{PID}", BR_PUBLIC)
    attach(CLIENT_ALT, f"hca{PID}", f"nca{PID}", BR_PUBLIC)
    for i, name in enumerate(AGENTS, start=2):
        attach(name, f"ha{i}{PID}", f"na{i}{PID}", BR_AGENT)
    attach(AGENTS[2], f"hab{PID}", f"nab{PID}", BR_BACKEND)
    attach(BACKEND, f"hbk{PID}", f"nbk{PID}", BR_BACKEND)
    run(["ip", "link", "add", BR_NAT, "type", "bridge"])
    run(["ip", "link", "set", BR_NAT, "up"])
    attach(NAT_GW, f"hgp{PID}", f"ngp{PID}", BR_PUBLIC)
    attach(NAT_GW, f"hgn{PID}", f"ngn{PID}", BR_NAT)
    attach(NAT_VPS, f"hnv{PID}", f"nnv{PID}", BR_NAT)
    attach(NAT_AGENT, f"hna{PID}", f"nna{PID}", BR_AGENT)
    attach(DEVICE, f"hdv{PID}", f"ndv{PID}", BR_PUBLIC)

    ns(VPS, "ip", "addr", "add", f"{PUBLIC_V4}/24", "dev", "eth0")
    ns(VPS, "ip", "addr", "add", f"{PUBLIC_V4_NEW}/24", "dev", "eth0")
    ns(VPS, "ip", "-6", "addr", "add", f"{PUBLIC_V6}/64", "dev", "eth0")
    ns(ROUTER, "ip", "addr", "add", "198.18.0.254/24", "dev", "eth0")
    ns(ROUTER, "ip", "-6", "addr", "add", "2001:db8:42:5249::fe/64", "dev", "eth0")
    ns(VPS, "ip", "-6", "route", "add", "fd42:31::/64", "via", "2001:db8:42:5249::fe")
    ns(CLIENT, "ip", "addr", "add", "198.18.0.10/24", "dev", "eth0")
    ns(CLIENT, "ip", "-6", "addr", "add", f"{CLIENT_PUBLIC_V6}/64", "dev", "eth0")
    ns(CLIENT_ALT, "ip", "addr", "add", "198.18.0.11/24", "dev", "eth0")
    ns(CLIENT_ALT, "ip", "-6", "addr", "add", f"{CLIENT_ALT_PUBLIC_V6}/64", "dev", "eth0")
    ns(ROUTER, "ip", "addr", "add", "172.31.0.1/24", "dev", "eth1")
    ns(ROUTER, "ip", "-6", "addr", "add", "fd42:31::1/64", "dev", "eth1")
    for i, name in enumerate(AGENTS, start=2):
        ns(name, "ip", "addr", "add", f"172.31.0.{i}/24", "dev", "eth0")
        ns(name, "ip", "-6", "addr", "add", f"fd42:31::{i}/64", "dev", "eth0")
        ns(name, "ip", "route", "add", "default", "via", "172.31.0.1")
        ns(name, "ip", "-6", "route", "add", "default", "via", "fd42:31::1")
        host_dir = pathlib.Path(f"/etc/netns/{name}")
        write(host_dir / "hosts", f"127.0.0.1 localhost\n{PUBLIC_V4} {SERVER_HOST}\n", 0o644)
        # WireGuard test interfaces live only inside these disposable namespaces.
        ns(name, "sysctl", "-qw", "net.ipv4.ip_forward=1")
        ns(name, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
    ns(AGENTS[2], "ip", "addr", "add", "10.77.0.1/24", "dev", "eth1")
    ns(BACKEND, "ip", "addr", "add", "10.77.0.2/24", "dev", "eth0")
    ns(BACKEND, "ip", "route", "add", "198.18.0.0/24", "via", "10.77.0.1")
    ns(ROUTER, "sysctl", "-qw", "net.ipv4.ip_forward=1")
    ns(ROUTER, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
    create_nat_cloud_topology()
    ns(DEVICE, "ip", "addr", "add", "198.18.0.20/24", "dev", "eth0")
    write(pathlib.Path(f"/etc/netns/{DEVICE}") / "hosts",
          f"127.0.0.1 localhost\n{PUBLIC_V4} {SERVER_HOST}\n", 0o644)
    ns(VPS, "sysctl", "-qw", "net.ipv4.ip_forward=1")
    ns(VPS, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
    ns(CLIENT, "sysctl", "-qw", "net.ipv4.ip_forward=1")
    ns(CLIENT, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")

    # Agent outer transport goes through this throwaway NAT namespace. Its
    # UDP source port is deliberately translated into a known range.
    sh_ns(ROUTER, "nft add table ip rift_test_nat; "
          "nft 'add chain ip rift_test_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'; "
          "nft add rule ip rift_test_nat postrouting ip saddr 172.31.0.0/24 udp dport 51820 snat to 198.18.0.254:41000-41999 random; "
          "nft add rule ip rift_test_nat postrouting ip saddr 172.31.0.0/24 masquerade")
    sh_ns(ROUTER, "nft add table inet rift_test_filter; "
          "nft 'add chain inet rift_test_filter forward { type filter hook forward priority filter; policy accept; }'")


def create_nat_cloud_topology():
    """The public address lives only on the gateway, which translates it 1:1 to the server's
    private address, as a cloud provider's NAT does. Client addresses are not translated."""
    ns(NAT_GW, "ip", "addr", "add", f"{NAT_PUBLIC_V4}/24", "dev", "eth0")
    ns(NAT_GW, "ip", "addr", "add", "10.99.0.1/24", "dev", "eth1")
    ns(NAT_GW, "sysctl", "-qw", "net.ipv4.ip_forward=1")
    sh_ns(NAT_GW, "nft add table ip cloud_nat; "
          "nft 'add chain ip cloud_nat prerouting { type nat hook prerouting priority dstnat; policy accept; }'; "
          "nft 'add chain ip cloud_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'; "
          f"nft add rule ip cloud_nat prerouting iifname eth0 ip daddr {NAT_PUBLIC_V4} dnat to {NAT_PRIVATE_V4}; "
          f"nft add rule ip cloud_nat postrouting oifname eth0 ip saddr {NAT_PRIVATE_V4} snat to {NAT_PUBLIC_V4}")
    ns(NAT_VPS, "ip", "addr", "add", f"{NAT_PRIVATE_V4}/24", "dev", "eth0")
    ns(NAT_VPS, "ip", "route", "add", "default", "via", "10.99.0.1")
    ns(NAT_VPS, "sysctl", "-qw", "net.ipv4.ip_forward=1")
    ns(NAT_VPS, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
    ns(NAT_AGENT, "ip", "addr", "add", "172.31.0.9/24", "dev", "eth0")
    ns(NAT_AGENT, "ip", "route", "add", "default", "via", "172.31.0.1")
    ns(NAT_AGENT, "sysctl", "-qw", "net.ipv4.ip_forward=1")
    ns(NAT_AGENT, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
    write(pathlib.Path(f"/etc/netns/{NAT_AGENT}") / "hosts",
          f"127.0.0.1 localhost\n{NAT_PUBLIC_V4} {NAT_SERVER_HOST}\n", 0o644)


def install_foreign_state():
    sh_ns(VPS, "nft add table inet rift_preserve; "
          "nft 'add chain inet rift_preserve input { type filter hook input priority 0; policy accept; }'; "
          "nft add rule inet rift_preserve input ip saddr 198.18.0.77 counter comment preserve-me")
    ns(VPS, "ip", "rule", "add", "priority", "18000", "from", "198.18.0.77/32", "lookup", "200")
    return (ns(VPS, "nft", "list", "table", "inet", "rift_preserve").stdout,
            ns(VPS, "ip", "rule", "show").stdout)


ECHO = r'''#!/usr/bin/env python3
import socket,sys
family=socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
kind=socket.SOCK_DGRAM if sys.argv[2] == "udp" else socket.SOCK_STREAM
# Without a fifth argument the reply is the client address the service saw; with one it is
# that fixed text, which names the agent that answered.
tag=sys.argv[5] if len(sys.argv) > 5 else None
s=socket.socket(family,kind); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((sys.argv[3],int(sys.argv[4])))
if kind == socket.SOCK_STREAM:
 s.listen(32)
 while True:
  c,a=s.accept()
  try: c.sendall((tag or a[0]).encode())
  finally: c.close()
else:
 while True:
  data,a=s.recvfrom(4096); s.sendto((tag or a[0]).encode(),a)
'''


def start_echo_process(namespace, script, args, label):
    log = (WORK / f"{label}.log").open("w", encoding="utf-8")
    process = subprocess.Popen(["ip", "netns", "exec", namespace, "python3", str(script), *args],
                               stdout=subprocess.DEVNULL, stderr=log,
                               start_new_session=True, text=True)
    PROCS.append((process, log, namespace))
    return process


def wait_echo_ready(namespace, family, proto, address, port):
    expected_ip = ipaddress.ip_address(address)
    ss_proto = "-t" if proto == "tcp" else "-u"

    def ready():
        result = ns(namespace, "ss", "-H", "-l", "-n", f"-{family}", ss_proto, timeout=5)
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 4 and ss_local_endpoint_matches(
                    fields[-2], expected_ip, port, int(family)):
                return True
        return None

    wait_until(ready, f"{namespace} {family}/{proto} echo socket at {address}:{port}", timeout=25)


def ss_local_endpoint_matches(endpoint, expected_ip, expected_port, family):
    if endpoint.startswith("["):
        close = endpoint.rfind("]")
        if close < 0 or endpoint[close + 1:close + 2] != ":":
            return False
        host, local_port = endpoint[1:close], endpoint[close + 2:]
    else:
        host, separator, local_port = endpoint.rpartition(":")
        if not separator:
            return False
    try:
        local_ip = ipaddress.ip_address(host)
        parsed_port = int(local_port)
    except ValueError:
        return False
    return local_ip.version == family and local_ip == expected_ip and parsed_port == expected_port


def start_echoes(server_cfg):
    echo_file = write(WORK / "echo.py", ECHO, 0o755)
    records = status(server_cfg)["snapshot"]["agents"]
    agents_by_name = {record["name"]: record for record in records}
    for namespace, logical_name in zip(AGENTS, ("agent1", "agent2", "agent3")):
        record = agents_by_name.get(logical_name)
        if not record or record["status"] != "active":
            raise RuntimeError(f"cannot start echo listeners: {logical_name} is not active in the server snapshot")
        v4, v6 = record["tunnel_ipv4"], record["tunnel_ipv6"]
        for fam, address in (("4", v4), ("6", v6)):
            for proto, port in (("tcp", 19080), ("udp", 19081)):
                start_echo_process(namespace, echo_file, [fam, proto, address, str(port)],
                                   f"echo-{logical_name}-{fam}-{proto}")
                wait_echo_ready(namespace, fam, proto, address, port)
    backend_echo = WORK / "backend-echo.py"
    write(backend_echo, ECHO, 0o755)
    start_echo_process(BACKEND, backend_echo, ["4", "tcp", "10.77.0.2", "19082"],
                       "echo-backend-v4-tcp")
    wait_echo_ready(BACKEND, "4", "tcp", "10.77.0.2", 19082)


def start_underlay_echo():
    echo_file = write(WORK / "underlay-echo.py", ECHO, 0o755)
    for fam, address, port in (("4", PUBLIC_V4, "19443"),
                               ("6", PUBLIC_V6, "19444")):
        start_echo_process(VPS, echo_file, [fam, "tcp", address, port],
                           f"echo-underlay-{fam}-tcp")


def check_normal_traffic():
    probe = r'''import socket,sys
fam=socket.AF_INET6 if sys.argv[1]=="6" else socket.AF_INET
s=socket.socket(fam,socket.SOCK_STREAM); s.settimeout(4)
s.bind((sys.argv[2],0)); s.connect((sys.argv[3],int(sys.argv[4]))); s.sendall(b"underlay")
got=s.recv(128).decode(); print(got); assert got==sys.argv[5],(got,sys.argv[5])
'''
    for idx, name in enumerate(AGENTS, start=2):
        cases = [("4", f"172.31.0.{idx}", PUBLIC_V4, "19443", WG_PUBLIC_NAT),
                 ("6", f"fd42:31::{idx}", PUBLIC_V6, "19444", f"fd42:31::{idx}")]
        for fam, src, dst, port, expected in cases:
            result = ns(name, "python3", "-c", probe, fam, src, dst, port, expected).stdout.strip()
            assert result == expected, f"ordinary {fam} underlay traffic did not use its baseline path: {result}"
    print("PASS unmarked TCP traffic still follows the ordinary underlay path")


def wait_agents(server_cfg, count):
    def ready():
        snap = status(server_cfg)["snapshot"]
        agents = snap["agents"]
        return agents if len(agents) >= count and all(a["status"] == "active" for a in agents) else None
    return wait_until(ready, f"{count} agents to become active")


def add_forwards(server_cfg, agent_names):
    ports = {}
    for idx, name in enumerate(agent_names):
        first = 18080 + idx * 4
        cases = [(PUBLIC_V4, first, "tcp", 19080), (PUBLIC_V4, first + 1, "udp", 19081),
                 (PUBLIC_V6, first + 2, "tcp", 19080), (PUBLIC_V6, first + 3, "udp", 19081)]
        for listen_ip, listen_port, proto, target_port in cases:
            cli(VPS, server_cfg, "add", "forward", name,
                f"{listen_port}:{target_port}/{proto}", "--listen-ip", listen_ip,
                env={"RIFT_PUBLIC_ENDPOINT": SERVER_HOST,
                     "RIFT_PUBLIC_IPS": f"{PUBLIC_V4},{PUBLIC_V4_NEW},{PUBLIC_V6}"})
            ports[(name, listen_ip, proto)] = listen_port
    return ports


def wait_policy(server_cfg, count):
    def synced():
        current = status(server_cfg)
        snap = current["snapshot"]
        agents = snap["agents"]
        fully_applied = (current.get("fully_applied") is True
                         and not current.get("pending_forwards")
                         and current.get("apply_error") is None)
        return agents if fully_applied and len(agents) == count and all(
            a["status"] == "active" and a["applied_generation"] >= snap["generation"]
            for a in agents) else None
    return wait_until(synced, "all agents to apply the current forwarding generation")


def traffic_test(agent_names, ports, client_ns=CLIENT,
                 source4="198.18.0.10", source6=CLIENT_PUBLIC_V6):
    client_script = r'''import socket,sys
fam=socket.AF_INET6 if sys.argv[1]=="6" else socket.AF_INET
proto=sys.argv[2]; src=sys.argv[3]; dst=sys.argv[4]; port=int(sys.argv[5])
s=socket.socket(fam,socket.SOCK_DGRAM if proto=="udp" else socket.SOCK_STREAM); s.settimeout(5)
s.bind((src,0)); s.connect((dst,port)); s.sendall(b"rift-test")
got=s.recv(256).decode(); print(got); assert got==src,(got,src)
'''
    for idx, name in enumerate(agent_names):
        for fam, listen_ip, src in (("4", PUBLIC_V4, source4),
                                     ("6", PUBLIC_V6, source6)):
            for proto in ("tcp", "udp"):
                port = ports[(name, listen_ip, proto)]
                out = ns(client_ns, "python3", "-c", client_script, fam, proto, src,
                         listen_ip, str(port)).stdout.strip()
                if out != src:
                    raise RuntimeError(f"{name} {fam}/{proto}: service saw {out}, expected client IP {src}")
        print(f"PASS {name}: source-preserving TCP/UDP forwarding over IPv4 and IPv6")


def translation_ban_test(server_cfg):
    result = json.loads(cli(
        VPS, server_cfg, "add", "forward", "agent1", "18100:19080/tcp",
        "--listen-ip", PUBLIC_V4, "--mode", "translate", "--target-family", "v6",
        env={"RIFT_PUBLIC_ENDPOINT": SERVER_HOST,
             "RIFT_PUBLIC_IPS": f"{PUBLIC_V4},{PUBLIC_V4_NEW},{PUBLIC_V6}"}).stdout)
    forward_id = result["id"]
    wait_policy(server_cfg, 3)
    client = r'''import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(4)
s.bind(("198.18.0.10",0))
try:
 s.connect((sys.argv[1],18100)); s.sendall(b"translation"); data=s.recv(256)
 print(data.decode())
 if sys.argv[2]=="allowed": assert data.decode().startswith("fd88:5249:4654::1"),data
 else: assert data==b"",data
except OSError as e:
 if sys.argv[2]=="allowed": raise
 print(f"blocked:{e}")
'''
    result = ns(CLIENT, "python3", "-c", client, PUBLIC_V4, "allowed").stdout.strip()
    assert result.startswith("fd88:5249:4654::1"), f"translated return path failed: {result}"
    cli(VPS, server_cfg, "add", "ban",
        str(forward_id), "198.18.0.10", "--ttl", "4s",
        env={"RIFT_PUBLIC_ENDPOINT": SERVER_HOST,
             "RIFT_PUBLIC_IPS": f"{PUBLIC_V4},{PUBLIC_V4_NEW},{PUBLIC_V6}"})
    bans = json.loads(cli(VPS, server_cfg, "list", "bans").stdout)
    assert any(b["forward_id"] == forward_id and b["ip"] == "198.18.0.10" for b in bans)
    blocked = ns(CLIENT, "python3", "-c", client, PUBLIC_V4, "blocked", check=False)
    assert blocked.returncode == 0, f"translated path was not blocked: {blocked.stderr}"
    time.sleep(5)
    result = ns(CLIENT, "python3", "-c", client, PUBLIC_V4, "allowed").stdout.strip()
    assert result.startswith("fd88:5249:4654::1"), f"translated path did not recover after TTL: {result}"
    print("PASS agent-applied translated-forward ban blocks source IPv4 and expires by TTL")


def agent_local_ban_test(server_cfg):
    forward = json.loads(cli(
        VPS, server_cfg, "add", "forward", "agent3", "18096:19080/tcp",
        "--listen-ip", PUBLIC_V4, "--mode", "translate", "--target-family", "v6",
        env={"RIFT_PUBLIC_ENDPOINT": SERVER_HOST,
             "RIFT_PUBLIC_IPS": f"{PUBLIC_V4},{PUBLIC_V4_NEW},{PUBLIC_V6}"}).stdout)
    wait_policy(server_cfg, 3)
    probe = r'''import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(3)
s.bind((sys.argv[1],0)); s.connect(("198.18.0.1",18096)); s.sendall(b"agent-ban")
got=s.recv(128).decode(); print(got); assert got.startswith("fd88:5249:4654::1"),got
'''
    assert ns(CLIENT, "python3", "-c", probe, "198.18.0.10").stdout.strip().startswith("fd88:5249:4654::1")
    cli(VPS, server_cfg, "add", "ban",
        str(forward["id"]), "198.18.0.10", "--ttl", "4s",
        env={"RIFT_PUBLIC_ENDPOINT": SERVER_HOST,
             "RIFT_PUBLIC_IPS": f"{PUBLIC_V4},{PUBLIC_V4_NEW},{PUBLIC_V6}"})
    blocked = ns(CLIENT, "python3", "-c", probe, "198.18.0.10", check=False)
    assert blocked.returncode != 0, "agent did not apply the requested source ban"
    assert ns(CLIENT_ALT, "python3", "-c", probe, "198.18.0.11").stdout.strip().startswith("fd88:5249:4654::1"), \
        "agent-local source ban disrupted a different client"
    active = next(a for a in status(server_cfg)["snapshot"]["agents"] if a["name"] == "agent3")
    assert active["status"] == "active", "agent-local service ban interrupted the control channel"
    time.sleep(5)
    restored = ns(CLIENT, "python3", "-c", probe, "198.18.0.10").stdout.strip()
    assert restored.startswith("fd88:5249:4654::1"), f"agent-local ban did not expire by TTL: {restored}"
    print("PASS restricted RIFT ban request reaches the agent, blocks one source, preserves other traffic, and expires by TTL")


def fail2ban_coexistence_test(server_cfg, ports):
    forward = json.loads(cli(
        VPS, server_cfg, "add", "forward", "agent3", "18092:19082/tcp",
        "--listen-ip", PUBLIC_V4,
        env={"RIFT_PUBLIC_ENDPOINT": SERVER_HOST,
             "RIFT_PUBLIC_IPS": f"{PUBLIC_V4},{PUBLIC_V4_NEW},{PUBLIC_V6}"}).stdout)
    forward_id = forward["id"]
    wait_policy(server_cfg, 3)
    agent3 = next(record for record in status(server_cfg)["snapshot"]["agents"]
                  if record["name"] == "agent3")
    agent3_ipv4 = agent3["tunnel_ipv4"]
    sh_ns(AGENTS[2], "nft add table ip rift_it_nat; "
          "nft 'add chain ip rift_it_nat prerouting { type nat hook prerouting priority dstnat; policy accept; }'; "
          f"nft add rule ip rift_it_nat prerouting iifname rift0 ip daddr {agent3_ipv4} tcp dport 19082 dnat to 10.77.0.2:19082")
    sh_ns(AGENTS[2], "nft add table inet f2b_test; "
          "nft 'add chain inet f2b_test input { type filter hook input priority 10; policy accept; }'; "
          "nft 'add chain inet f2b_test forward { type filter hook forward priority 10; policy accept; }'; "
          "nft add rule inet f2b_test input iifname rift0 ip saddr 198.18.0.10 tcp dport 19080 drop; "
          "nft add rule inet f2b_test input iifname rift0 ip saddr 198.18.0.10 udp dport 19081 drop; "
          f"nft add rule inet f2b_test input iifname rift0 ip6 saddr {CLIENT_PUBLIC_V6} tcp dport 19080 drop; "
          f"nft add rule inet f2b_test input iifname rift0 ip6 saddr {CLIENT_PUBLIC_V6} udp dport 19081 drop; "
          "nft add rule inet f2b_test forward iifname rift0 ip saddr 198.18.0.10 ip daddr 10.77.0.2 tcp dport 19082 drop")
    f2b_before = ns(AGENTS[2], "nft", "list", "table", "inet", "f2b_test").stdout

    blocked = []
    for fam, listen_ip, source in (("4", PUBLIC_V4, "198.18.0.10"),
                                   ("6", PUBLIC_V6, CLIENT_PUBLIC_V6)):
        for proto in ("tcp", "udp"):
            port = 18088 + (0 if fam == "4" and proto == "tcp" else
                            1 if fam == "4" else 2 if proto == "tcp" else 3)
            blocked.append(ns(CLIENT, "python3", "-c", _client_probe(), fam, proto,
                              source, listen_ip, str(port), check=False))
    assert all(result.returncode != 0 for result in blocked), \
        "Fail2ban input rules did not block the exact client on all four service paths"

    # The exact source ban must leave another client and the agent control
    # channel usable; a second public client still receives its own source IP.
    traffic_test(["agent3"], ports, client_ns=CLIENT_ALT,
                 source4="198.18.0.11", source6=CLIENT_ALT_PUBLIC_V6)
    source_test = r'''import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(3)
s.bind((sys.argv[1],0)); s.connect(("198.18.0.1",18092)); s.sendall(b"forward-chain")
got=s.recv(128).decode(); print(got); assert got==sys.argv[1],(got,sys.argv[1])
'''
    forward_blocked = ns(CLIENT, "python3", "-c", source_test, "198.18.0.10", check=False)
    assert forward_blocked.returncode != 0, \
        "Fail2ban FORWARD rule did not block the exact source on the backend path"
    assert ns(CLIENT_ALT, "python3", "-c", source_test, "198.18.0.11").stdout.strip() == "198.18.0.11"
    active = next(a for a in status(server_cfg)["snapshot"]["agents"] if a["name"] == "agent3")
    assert active["status"] == "active", "agent control state was affected by the service-only ban"

    # Force a real policy re-apply while the unrelated Fail2ban table exists.
    cli(VPS, server_cfg, "disable", "forward", str(forward_id))
    wait_policy(server_cfg, 3)
    cli(VPS, server_cfg, "enable", "forward", str(forward_id))
    wait_policy(server_cfg, 3)
    assert ns(AGENTS[2], "nft", "list", "table", "inet", "f2b_test").stdout == f2b_before, \
        "RIFT policy re-apply overwrote an independent Fail2ban table"
    ns(AGENTS[2], "nft", "delete", "table", "inet", "f2b_test")
    traffic_test(["agent3"], ports)
    assert ns(CLIENT, "python3", "-c", source_test, "198.18.0.10").stdout.strip() == "198.18.0.10"
    print("PASS foreign Fail2ban-style INPUT/FORWARD rules block one client, preserve RIFT/control/other-client traffic, and removal restores access")


def allow_from_test(server_cfg):
    """--allow-from: only the named sources reach a forward, for each mode and family."""
    env = {"RIFT_PUBLIC_ENDPOINT": SERVER_HOST,
           "RIFT_PUBLIC_IPS": f"{PUBLIC_V4},{PUBLIC_V4_NEW},{PUBLIC_V6}"}
    allowed4, refused4 = "198.18.0.11", "198.18.0.10"
    allowed6, refused6 = CLIENT_ALT_PUBLIC_V6, CLIENT_PUBLIC_V6
    cases = [
        # (spec, listen ip, family, proto, extra options, allowed list)
        ("18120:19080/tcp", PUBLIC_V4, "4", "tcp", [], f"{allowed4},192.0.2.0/24"),
        ("18121:19081/udp", PUBLIC_V4, "4", "udp", [], allowed4),
        ("18122:19080/tcp", PUBLIC_V6, "6", "tcp", [], f"{allowed6}/128"),
        ("18123:19080/tcp", PUBLIC_V4, "4", "tcp",
         ["--mode", "translate", "--target-family", "v6"], allowed4),
    ]
    created = []
    for spec, listen_ip, _, _, extra, allow in cases:
        forward = json.loads(cli(VPS, server_cfg, "add", "forward", "agent2", spec,
                                 "--listen-ip", listen_ip, *extra, "--allow-from", allow,
                                 env=env).stdout)
        assert forward["allow_from"], f"forward {spec} was stored without its sources: {forward}"
        created.append(forward["id"])
    # A list without an address of the listener's family would open the port to no one.
    mismatch = ns(VPS, str(BIN), "--config", str(server_cfg), "--json", "add", "forward",
                  "agent2", "18124/tcp", "--listen-ip", PUBLIC_V4, "--allow-from", allowed6,
                  check=False, env={**os.environ, **env})
    assert mismatch.returncode != 0, "a forward with only IPv6 sources on an IPv4 listener was accepted"
    wait_policy(server_cfg, 3)
    listed = {f["id"]: f for f in json.loads(cli(VPS, server_cfg, "list", "forwards").stdout)}
    assert listed[created[0]]["allow_from"] == [f"{allowed4}/32", "192.0.2.0/24"], listed[created[0]]
    nat = ns(VPS, "nft", "list", "chain", "inet", "rift", "prerouting_nat").stdout
    assert f"ip saddr {{ {allowed4}, 192.0.2.0/24 }}" in nat or f"ip saddr {{ 192.0.2.0/24, {allowed4} }}" in nat, nat

    translated = r'''import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(3)
s.bind((sys.argv[1],0)); s.connect(("198.18.0.1",18123)); s.sendall(b"allow-from")
got=s.recv(128).decode(); print(got); assert got.startswith("fd88:5249:4654::1"),got
'''
    for spec, listen_ip, fam, proto, extra, _ in cases:
        port = spec.split(":")[0]
        allowed, refused = (allowed4, refused4) if fam == "4" else (allowed6, refused6)
        if extra:
            assert ns(CLIENT_ALT, "python3", "-c", translated, allowed).stdout.strip() \
                .startswith("fd88:5249:4654::1"), "allowed client lost the translated forward"
            blocked = ns(CLIENT, "python3", "-c", translated, refused, check=False)
        else:
            seen = ns(CLIENT_ALT, "python3", "-c", _client_probe(), fam, proto, allowed,
                      listen_ip, port).returncode
            assert seen == 0, f"allowed client {allowed} did not reach {spec}"
            blocked = ns(CLIENT, "python3", "-c", _client_probe(), fam, proto, refused,
                         listen_ip, port, check=False)
        assert blocked.returncode != 0, f"client {refused} reached {spec} outside --allow-from"
    # The unrestricted forwards of the same agent still answer the refused client.
    assert ns(CLIENT, "python3", "-c", _client_probe(), "4", "tcp", refused4,
              PUBLIC_V4, "18084").returncode == 0, "--allow-from leaked onto another forward"
    for forward_id in created:
        cli(VPS, server_cfg, "remove", "forward", str(forward_id))
    wait_policy(server_cfg, 3)
    print("PASS --allow-from lets only the listed sources reach transparent IPv4/IPv6 TCP/UDP and translated forwards")


def host_local_proxy_test(server_cfg):
    """A reverse proxy on the VPS itself (Caddy or Nginx from the distribution) reaches a
    local-ingress forward through the public address; clients from the internet do not."""
    env = {"RIFT_PUBLIC_ENDPOINT": SERVER_HOST,
           "RIFT_PUBLIC_IPS": f"{PUBLIC_V4},{PUBLIC_V4_NEW},{PUBLIC_V6}"}
    cases = [("18130:19080/tcp", PUBLIC_V4, "4", "tcp"),
             ("18131:19081/udp", PUBLIC_V4, "4", "udp"),
             ("18132:19080/tcp", PUBLIC_V6, "6", "tcp")]
    created = []
    for spec, listen_ip, _, _ in cases:
        forward = json.loads(cli(VPS, server_cfg, "add", "forward", "agent2", spec,
                                 "--listen-ip", listen_ip, "--ingress", "local", env=env).stdout)
        created.append(forward["id"])
    wait_policy(server_cfg, 3)
    output = ns(VPS, "nft", "list", "chain", "inet", "rift", "output_nat").stdout
    assert "dport 18130" in output and "dport 18132" in output, output
    for spec, listen_ip, fam, proto in cases:
        port = spec.split(":")[0]
        # The VPS connects from its own public address, as a proxy on the host does; the echo
        # on agent2 answers with the source it saw.
        result = ns(VPS, "python3", "-c", _client_probe(), fam, proto, listen_ip, listen_ip, port,
                    check=False)
        assert result.returncode == 0, \
            f"a client on the VPS itself did not reach local forward {spec}: {result.stdout} {result.stderr}"
    # From the internet the same forwards stay closed.
    for spec, listen_ip, fam, proto in cases[:1]:
        port = spec.split(":")[0]
        blocked = ns(CLIENT, "python3", "-c", _client_probe(), fam, proto, "198.18.0.10",
                     listen_ip, port, check=False)
        assert blocked.returncode != 0, f"a local-ingress forward {spec} answered a client from outside"
    for forward_id in created:
        cli(VPS, server_cfg, "remove", "forward", str(forward_id))
    wait_policy(server_cfg, 3)
    assert "output_nat" not in ns(VPS, "nft", "list", "table", "inet", "rift").stdout, \
        "the output chain stayed after the last local forward was removed"
    print("PASS a proxy on the VPS itself reaches local-ingress forwards over IPv4/IPv6 TCP/UDP; outside clients do not")


def _client_probe():
    return r'''import socket,sys
fam=socket.AF_INET6 if sys.argv[1]=="6" else socket.AF_INET
proto=sys.argv[2]; src=sys.argv[3]; dst=sys.argv[4]; port=int(sys.argv[5])
s=socket.socket(fam,socket.SOCK_DGRAM if proto=="udp" else socket.SOCK_STREAM); s.settimeout(2)
s.bind((src,0)); s.connect((dst,port)); s.sendall(b"rift-test")
got=s.recv(256).decode(); assert got==src,(got,src)
'''


def expect_tcp_unreachable(port, destination):
    client = r'''import socket,sys
s=socket.socket(socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET,socket.SOCK_STREAM)
s.settimeout(2)
try: s.connect((sys.argv[1],int(sys.argv[2]))); print("connected"); sys.exit(0)
except OSError: print("unreachable"); sys.exit(3)
'''
    # Bind a deterministic client source so the probe follows the public test path.
    if ":" in destination:
        source, family_arg = CLIENT_PUBLIC_V6, "6"
    else:
        source, family_arg = "198.18.0.10", "4"
    probe = client.replace('s.settimeout(2)', 's.settimeout(2)\ns.bind((sys.argv[3],0))')
    result = ns(CLIENT, "python3", "-c", probe, destination, str(port), source, check=False)
    assert result.returncode == 3, f"forward remained reachable after disable/remove: {result.stdout} {result.stderr}"


def check_routes_and_foreign(prior, baselines):
    foreign_nft_before, foreign_rules_before = prior
    nft_after = ns(VPS, "nft", "list", "table", "inet", "rift_preserve").stdout
    rules_after = ns(VPS, "ip", "rule", "show").stdout
    assert nft_after == foreign_nft_before, "foreign nftables table changed"
    assert rules_after == foreign_rules_before, (
        f"foreign IP policy rules changed: before={foreign_rules_before!r}, after={rules_after!r}")
    for name in AGENTS:
        # Untagged underlay traffic keeps the ordinary default route.
        idx = AGENTS.index(name) + 2
        route = ns(name, "ip", "route", "get", PUBLIC_V4, "from", f"172.31.0.{idx}").stdout.strip()
        assert route == baselines[name][0], f"normal IPv4 route changed: before={baselines[name][0]!r}, after={route!r}"
        route6 = ns(name, "ip", "-6", "route", "get", PUBLIC_V6, "from", f"fd42:31::{idx}").stdout.strip()
        assert route6 == baselines[name][1], f"normal IPv6 route changed: before={baselines[name][1]!r}, after={route6!r}"
        marked = ns(name, "ip", "route", "get", PUBLIC_V4, "mark", MARK).stdout
        assert "dev rift0" in marked, f"fwmark did not select the RIFT tunnel: {marked}"
        marked6 = ns(name, "ip", "-6", "route", "get", PUBLIC_V6, "mark", MARK).stdout
        assert "dev rift0" in marked6, f"IPv6 fwmark did not select the RIFT tunnel: {marked6}"
    print("PASS unmarked routes and unrelated nftables/IP rules remain intact")


def wait_endpoint(server_cfg, predicate, message, timeout=55):
    def current():
        data = status(server_cfg)
        return data if predicate(data) else None
    return wait_until(current, message, timeout)


def migrate_endpoint_ip(server_cfg):
    # Update only agent1's DNS and blackhole its old UDP endpoint. Other
    # agents still use the original address and must be able to reconnect.
    write(f"/etc/netns/{AGENTS[0]}/hosts", f"127.0.0.1 localhost\n{PUBLIC_V4_NEW} {SERVER_HOST}\n", 0o644)
    sh_ns(ROUTER, f"nft add rule inet rift_test_filter forward iifname \"eth1\" ip saddr 172.31.0.2 ip daddr {PUBLIC_V4} udp dport 51820 drop")
    time.sleep(8)
    agent_proc = next(p for p, _, name in PROCS if name == AGENTS[0] and p.poll() is None)
    stop_process(agent_proc, signal.SIGKILL)
    first_agent_cfg = config(WORK / "state-agent1", server=False)
    # Active persisted identity ignores the original one-time invitation.
    daemon(AGENTS[0], first_agent_cfg, ["agent"],
           {"RIFT_SERVER": f"{SERVER_HOST}:8443", "RIFT_AGENT_NAME": "agent1"},
           label="agent1-restarted")
    def moved():
        ep = ns(AGENTS[0], "wg", "show", "rift0", "endpoints", check=False).stdout
        return ep if f"{PUBLIC_V4_NEW}:51820" in ep else None
    wait_until(moved, "agent endpoint to refresh to the new VPS IPv4")
    wait_until(lambda: status(server_cfg)["snapshot"]["agents"][0]["status"] == "active",
               "control synchronization after endpoint move")
    print("PASS IPv4 endpoint/DNS change recovered on the persisted agent identity")


def migrate_nat_port(server_cfg):
    # Replace the SNAT range and discard only this test namespace's connection
    # tracking entries. The next authenticated WireGuard packets exercise
    # WireGuard endpoint roaming on the VPS.
    sh_ns(ROUTER, "nft flush chain ip rift_test_nat postrouting; "
          "nft add rule ip rift_test_nat postrouting ip saddr 172.31.0.0/24 udp dport 51820 snat to 198.18.0.254:42000-42999 random; "
          "nft add rule ip rift_test_nat postrouting ip saddr 172.31.0.0/24 masquerade")
    ns(ROUTER, "conntrack", "-D", "--orig-src", "172.31.0.2", "--orig-dst", PUBLIC_V4_NEW,
       "--proto", "udp", "--dport", "51820", check=False)
    def port_moved():
        endpoints = [p.get("endpoint", "") for p in status(server_cfg)["peers"]]
        return any(endpoint.startswith("198.18.0.254:") and
                   42000 <= int(endpoint.rsplit(":", 1)[1]) <= 42999
                   for endpoint in endpoints)
    wait_until(port_moved, "VPS to observe the new NAT UDP source port", timeout=55)
    print("PASS WireGuard re-established after NAT source-port remapping")


def wait_initial_nat_port(server_cfg):
    def mapped():
        endpoints = [p.get("endpoint", "") for p in status(server_cfg)["peers"]]
        return any(endpoint.startswith("198.18.0.254:") and
                   41000 <= int(endpoint.rsplit(":", 1)[1]) <= 41999
                   for endpoint in endpoints)
    wait_until(mapped, "initial WireGuard NAT UDP source-port mapping", timeout=55)


def replay_and_wrong_ca(server_cfg, replay_token):
    token = json.loads(cli(VPS, server_cfg, "add", "agent", "badca", "--ttl", "15m",
                           env={"RIFT_PUBLIC_ENDPOINT": SERVER_HOST,
                                "RIFT_PUBLIC_IPS": f"{PUBLIC_V4},{PUBLIC_V4_NEW},{PUBLIC_V6}"}).stdout)["token"]
    wrong = WORK / "wrong-ca.crt"
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-keyout", WORK / "wrong-ca.key", "-out", wrong, "-subj", "/CN=wrong-ca"])
    bundle = json.loads(base64.urlsafe_b64decode(token[3:] + "=="))
    bundle["ca_pem"] = wrong.read_text(encoding="utf-8")
    bad_token = "v1." + base64.urlsafe_b64encode(json.dumps(bundle, separators=(",", ":")).encode()).decode().rstrip("=")
    badca_cfg = config(WORK / "state-badca", server=False)
    proc = daemon(AGENTS[2], badca_cfg, ["agent"],
                  {"RIFT_SERVER": f"{SERVER_HOST}:8443", "RIFT_AGENT_NAME": "badca",
                   "RIFT_ENROLLMENT_TOKEN": bad_token}, label="wrong-ca")
    wait_until(lambda: "certificate" in (WORK / "wrong-ca.log").read_text(
        encoding="utf-8", errors="replace").lower(), "wrong-CA TLS rejection", timeout=20)
    stop_process(proc, signal.SIGKILL)
    assert not any(a["name"] == "badca" for a in status(server_cfg)["snapshot"]["agents"]), \
        "agent with wrong TLS CA was enrolled"
    # Agent 1's original invitation was consumed. Reuse it with a fresh state
    # directory and distinct name; enrollment must be rejected by the server.
    replay_cfg = config(WORK / "state-replay", server=False)
    replay_env = {"RIFT_SERVER": f"{SERVER_HOST}:8443", "RIFT_AGENT_NAME": "replay",
                  "RIFT_ENROLLMENT_TOKEN": replay_token}
    second_cfg = config(WORK / "state-replay-second", server=False)
    second = daemon(AGENTS[2], second_cfg, ["agent"], replay_env, label="replay")
    wait_until(lambda: "already used" in (WORK / "replay.log").read_text(
        encoding="utf-8", errors="replace").lower(), "consumed invitation rejection", timeout=20)
    stop_process(second, signal.SIGKILL)
    assert not any(a["name"] == "replay" for a in status(server_cfg)["snapshot"]["agents"]), \
        "replayed invitation was accepted"
    print("PASS wrong CA rejected and consumed enrollment invitation cannot be replayed")


def disable_remove_test(server_cfg):
    cli(VPS, server_cfg, "disable", "agent", "agent3")
    wait_until(lambda: next((a for a in status(server_cfg)["snapshot"]["agents"]
                             if a["name"] == "agent3"), {}).get("status") == "disabled",
               "agent3 to be disabled")
    expect_tcp_unreachable(18088, PUBLIC_V4)
    expect_tcp_unreachable(18090, PUBLIC_V6)
    cli(VPS, server_cfg, "remove", "agent", "agent3")
    wait_until(lambda: not any(a["name"] == "agent3"
                               for a in status(server_cfg)["snapshot"]["agents"]),
               "agent3 and its forwards to be removed")
    expect_tcp_unreachable(18088, PUBLIC_V4)
    expect_tcp_unreachable(18090, PUBLIC_V6)
    print("PASS disabled and removed agents no longer receive IPv4/IPv6 forwards")


def agent_isolation_test(server_cfg):
    """Each forward reaches only its own agent, and agents cannot reach each other."""
    env = {"RIFT_PUBLIC_ENDPOINT": SERVER_HOST,
           "RIFT_PUBLIC_IPS": f"{PUBLIC_V4},{PUBLIC_V4_NEW},{PUBLIC_V6}"}
    echo_file = write(WORK / "echo.py", ECHO, 0o755)
    records = {r["name"]: r for r in status(server_cfg)["snapshot"]["agents"]}
    names = ["agent1", "agent2", "agent3"]
    # Every agent answers on the same target port with its own name.
    for namespace, name in zip(AGENTS, names):
        for fam, address in (("4", records[name]["tunnel_ipv4"]), ("6", records[name]["tunnel_ipv6"])):
            for proto in ("tcp", "udp"):
                start_echo_process(namespace, echo_file, [fam, proto, address, "19083", name],
                                   f"identity-{name}-{fam}-{proto}")
                wait_echo_ready(namespace, fam, proto, address, 19083)
    ports = {}
    for idx, name in enumerate(names):
        for fam, listen_ip in (("4", PUBLIC_V4), ("6", PUBLIC_V6)):
            for proto in ("tcp", "udp"):
                port = 18140 + idx * 4 + (0 if fam == "4" else 2) + (0 if proto == "tcp" else 1)
                cli(VPS, server_cfg, "add", "forward", name, f"{port}:19083/{proto}",
                    "--listen-ip", listen_ip, env=env)
                ports[(name, fam, proto)] = (listen_ip, port)
    wait_policy(server_cfg, 3)
    identity = r"""import socket,sys
fam=socket.AF_INET6 if sys.argv[1]=="6" else socket.AF_INET
s=socket.socket(fam,socket.SOCK_DGRAM if sys.argv[2]=="udp" else socket.SOCK_STREAM); s.settimeout(4)
s.connect((sys.argv[3],int(sys.argv[4]))); s.sendall(b"who")
print(s.recv(64).decode())
"""
    for (name, fam, proto), (listen_ip, port) in ports.items():
        answer = ns(CLIENT, "python3", "-c", identity, fam, proto, listen_ip, str(port)).stdout.strip()
        assert answer == name, f"forward {listen_ip}:{port}/{proto} of {name} was answered by {answer!r}"
    print("PASS every agent's forwards reach only that agent (IPv4/IPv6, TCP/UDP)")

    # The server's WireGuard peers: each agent may send only from its own tunnel addresses,
    # so one agent cannot pose as another inside the tunnel.
    dump = ns(VPS, "wg", "show", "rift0", "allowed-ips").stdout
    allowed = {}
    for line in dump.splitlines():
        key, _, rest = line.partition("\t")
        allowed[key] = set(rest.split())
    for name in names:
        record = records[name]
        own = {f"{record['tunnel_ipv4']}/32", f"{record['tunnel_ipv6']}/128"}
        mine = [ips for ips in allowed.values() if own & ips]
        assert len(mine) == 1, f"{name}'s tunnel addresses belong to {len(mine)} WireGuard peers: {dump}"
        others = set().union(*(
            {f"{records[o]['tunnel_ipv4']}/32", f"{records[o]['tunnel_ipv6']}/128"}
            for o in names if o != name))
        assert not (mine[0] & others), f"{name}'s peer also carries another agent's address: {dump}"

    # Agent to agent through the server: no answer on any family or transport. Each probe
    # gets a host route into the tunnel first, as a compromised agent would add, so the
    # packets really reach the server and it is the server that must drop them.
    probe = r"""import socket,sys
fam=socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
s=socket.socket(fam,socket.SOCK_DGRAM if sys.argv[3]=="udp" else socket.SOCK_STREAM); s.settimeout(2)
try:
    s.connect((sys.argv[1],int(sys.argv[2]))); s.sendall(b"cross"); data=s.recv(64)
    print("answered:"+data.decode()); sys.exit(0)
except OSError as error:
    print(f"no answer: {error}"); sys.exit(3)
"""
    for source_ns, source in zip(AGENTS, names):
        for target in names:
            if target == source:
                continue
            for address in (records[target]["tunnel_ipv4"], records[target]["tunnel_ipv6"]):
                family, prefix = ("-6", "128") if ":" in address else ("-4", "32")
                ns(source_ns, "ip", family, "route", "replace", f"{address}/{prefix}", "dev", "rift0")
                try:
                    for proto in ("tcp", "udp"):
                        result = ns(source_ns, "python3", "-c", probe, address, "19083", proto,
                                    check=False)
                        assert result.returncode == 3, \
                            f"{source} reached {target} at {address}/{proto} through the tunnel: {result.stdout}"
                finally:
                    ns(source_ns, "ip", family, "route", "del", f"{address}/{prefix}", "dev", "rift0",
                       check=False)
    print("PASS agents cannot reach each other's tunnel addresses through the server")


def wait_forwarding_after_restart(server_cfg, names, ports, what):
    def online():
        health = {agent["name"]: agent for agent in status(server_cfg)["agent_health"]}
        return all(health.get(name, {}).get("online") for name in names)
    wait_until(online, f"agents to handshake after {what}", timeout=75)

    def restored():
        traffic_test(names, ports)
        return True
    wait_until(restored, f"forwarded traffic to recover after {what}", timeout=75)


def assert_single_owner_rules(namespace):
    """A crash and a restart must not leave a second copy of RIFT's policy rules."""
    for family in ("-4", "-6"):
        rules = [line for line in ns(namespace, "ip", family, "rule", "show").stdout.splitlines()
                 if line.startswith(("11000:", "11001:"))]
        assert len(rules) == len(set(rules)), f"duplicate RIFT policy rules in {namespace}: {rules}"
    tables = ns(namespace, "nft", "list", "tables").stdout.split("\n")
    assert tables.count("table inet rift") <= 1, f"duplicate RIFT nftables table in {namespace}"


def kill_during_startup(namespace, cfg, command, env, label):
    """Starts a daemon and kills it as soon as it has begun to change the network (its
    WireGuard interface exists), i.e. before it has finished applying its state."""
    process = daemon(namespace, cfg, command, env, label=label)
    def started_changing():
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited before it was interrupted")
        return ns(namespace, "ip", "link", "show", "rift0", check=False, timeout=5).returncode == 0
    deadline = time.monotonic() + 35
    while not started_changing():
        if time.monotonic() > deadline:
            raise RuntimeError(f"{label} never created rift0")
        time.sleep(0.05)
    stop_process(process, signal.SIGKILL)
    assert process.poll() is not None, f"{label} survived SIGKILL"


def interrupt_server_starts(cfg, env):
    """Kills the server again and again a little later in its start, until at least one kill
    landed after it had begun to apply its state (it logged that the enrollment endpoint is
    open) and before it reported ready. A fixed poll can miss that window: the whole start
    takes well under a second."""
    mid_apply = 0
    for attempt in range(60):
        label = f"server-interrupted-{attempt}"
        process = daemon(VPS, cfg, ["server"], env, label=label)
        time.sleep(attempt * 0.01)
        stop_process(process, signal.SIGKILL)
        assert process.poll() is not None, f"{label} survived SIGKILL"
        log = (WORK / f"{label}.log").read_text(encoding="utf-8", errors="replace")
        if "enrollment endpoint" in log and "RIFT server ready" not in log:
            mid_apply += 1
            if mid_apply >= 3:
                break
    assert mid_apply, "no kill landed between the start of apply and 'RIFT server ready'"
    print(f"PASS server killed {mid_apply} time(s) in the middle of applying its state")


def expired_invitation_test(server_cfg, token, created_at):
    """An invitation whose TTL has passed is refused and creates no agent."""
    remaining = created_at + 62 - time.monotonic()
    if remaining > 0:
        time.sleep(remaining)
    invites = status(server_cfg)["invites"]
    assert not any(invite["name"] == "expiring" for invite in invites), \
        f"rift status still lists an expired invitation: {invites}"
    cfg = config(WORK / "state-expired", server=False)
    proc = daemon(AGENTS[2], cfg, ["agent"],
                  {"RIFT_SERVER": f"{SERVER_HOST}:8443", "RIFT_AGENT_NAME": "expiring",
                   "RIFT_ENROLLMENT_TOKEN": token}, label="expired")
    # The server deletes expired invitations when it reconciles; until then it answers
    # "expired or already used", afterwards the token is simply unknown ("invalid invitation").
    wait_until(lambda: "enrollment refused" in (WORK / "expired.log").read_text(
        encoding="utf-8", errors="replace").lower(), "expired invitation rejection", timeout=20)
    stop_process(proc, signal.SIGKILL)
    agents = status(server_cfg)["snapshot"]["agents"]
    assert not any(a["name"] == "expiring" for a in agents), "an expired invitation enrolled an agent"
    print("PASS an invitation is refused once its TTL has passed and creates no agent")


def nat_cloud_test(tokens):
    """A server that has only a private address behind a 1:1 NAT, as on Oracle Cloud, AWS or
    Google Cloud, set up as the README says: RIFT_ALLOW_PRIVATE_LISTENERS=true, the private
    interface address in RIFT_PUBLIC_IPS and the public DNS name in RIFT_PUBLIC_ENDPOINT."""
    env = {"RIFT_PUBLIC_ENDPOINT": NAT_SERVER_HOST, "RIFT_PUBLIC_IPS": NAT_PRIVATE_V4,
           "RIFT_ALLOW_PRIVATE_LISTENERS": "true", "RIFT_ENROLLMENT_BIND": "0.0.0.0:8443",
           "RIFT_ENROLLMENT": "always"}
    cfg = config(WORK / "state-natserver", server=True, endpoint=NAT_SERVER_HOST,
                 public_ips=(NAT_PRIVATE_V4,))
    # Without RIFT_ALLOW_PRIVATE_LISTENERS the server refuses a forward on the private address
    # when it is added (check_port); the unit tests of listener_allowed cover that rule.
    ns(NAT_VPS, str(BIN), "--config", str(cfg), "config", "validate", env={**os.environ, **env})
    daemon(NAT_VPS, cfg, ["server"], env, label="nat-server")

    def nat_status():
        return json.loads(cli(NAT_VPS, cfg, "status", env=env).stdout)
    wait_until(lambda: cli(NAT_VPS, cfg, "status", env=env).returncode == 0,
               "NAT server admin socket", timeout=35)
    token = json.loads(cli(NAT_VPS, cfg, "add", "agent", "natagent", "--ttl", "15m", env=env).stdout)["token"]
    tokens["natagent"] = token
    agent_cfg = config(WORK / "state-natagent", server=False)
    daemon(NAT_AGENT, agent_cfg, ["agent"], {"RIFT_SERVER": f"{NAT_SERVER_HOST}:8443",
                                             "RIFT_AGENT_NAME": "natagent",
                                             "RIFT_ENROLLMENT_TOKEN": token}, label="nat-agent")

    def active():
        agents = nat_status()["snapshot"]["agents"]
        return next((a for a in agents if a["name"] == "natagent" and a["status"] == "active"), None)
    record = wait_until(active, "the agent behind the cloud NAT to become active")
    endpoint = ns(NAT_AGENT, "wg", "show", "rift0", "endpoints").stdout
    assert f"{NAT_PUBLIC_V4}:51820" in endpoint, f"agent does not dial the public NAT address: {endpoint}"

    echo_file = write(WORK / "echo.py", ECHO, 0o755)
    for proto, port in (("tcp", 19080), ("udp", 19081)):
        start_echo_process(NAT_AGENT, echo_file, ["4", proto, record["tunnel_ipv4"], str(port)],
                           f"echo-natagent-{proto}")
        wait_echo_ready(NAT_AGENT, "4", proto, record["tunnel_ipv4"], port)
    for spec in ("18200:19080/tcp", "18201:19081/udp"):
        created = cli(NAT_VPS, cfg, "add", "forward", "natagent", spec, env=env).stdout
        assert NAT_PRIVATE_V4 in created, f"forward {spec} does not listen on the private address: {created}"

    def applied():
        current = nat_status()
        snap = current["snapshot"]
        return (current.get("fully_applied") is True and not current.get("pending_forwards")
                and current.get("apply_error") is None
                and all(a["applied_generation"] >= snap["generation"] for a in snap["agents"]))
    wait_until(applied, "the NAT server's agent to apply its forwards")

    def reachable():
        for proto, port in (("tcp", "18200"), ("udp", "18201")):
            ns(CLIENT, "python3", "-c", _client_probe(), "4", proto, "198.18.0.10",
               NAT_PUBLIC_V4, port)
        return True
    wait_until(reachable, "forwards on the public NAT address", timeout=30)
    print("PASS a server behind a 1:1 cloud NAT enrolls an agent and forwards TCP/UDP "
          "on the public address with the client's own source address")


def plaintext_secret_scan(server_cfg, tokens):
    """No invitation token or private key appears in a log, in normal command output or in
    any state file other than the key's own mode-0600 file."""
    state_dirs = sorted(p for p in WORK.iterdir() if p.is_dir() and p.name.startswith("state-"))
    keys = {}
    for directory in state_dirs:
        for path in directory.rglob("*.key"):
            assert path.stat().st_mode & 0o077 == 0, f"{path} is readable by group or others"
            text = path.read_text(encoding="utf-8", errors="replace")
            lines = [line.strip() for line in text.splitlines()
                     if line.strip() and not line.startswith("-----")]
            # A single long line of the key is enough to recognise a copy of it.
            needle = max(lines, key=len) if lines else ""
            if len(needle) >= 32:
                keys[path] = needle
    assert any(p.name == "wireguard.key" for p in keys), "no WireGuard key was found to scan for"
    # tls-bundle.json is by design the durable source of the generated CA and server keys
    # (src/tls_material.rs); the PEM files are copies of it. It must be private like a key
    # file and is the one other file allowed to hold them.
    containers = set()
    for directory in state_dirs:
        for path in directory.rglob("tls-bundle.json"):
            assert path.stat().st_mode & 0o077 == 0, f"{path} is readable by group or others"
            containers.add(path)
    needles = {f"token of {name}": token for name, token in tokens.items()}
    for path, needle in keys.items():
        needles[f"key {path.relative_to(WORK)}"] = needle
    # Bare secrets inside tokens, in case a token is decoded and its parts logged.
    for name, token in tokens.items():
        try:
            bundle = json.loads(base64.urlsafe_b64decode(token[3:] + "=="))
            needles[f"secret of {name}"] = bundle["secret"]
        except (ValueError, KeyError):
            pass

    outputs = {}
    for args in (["status"], ["list", "agents"], ["list", "forwards"], ["list", "devices"],
                 ["show", "agent", "agent1"], ["logs", "--lines", "2000"], ["doctor"],
                 ["export", "-"]):
        result = ns(VPS, str(BIN), "--config", str(server_cfg), "--json", *args, check=False)
        outputs[f"rift {' '.join(args)}"] = result.stdout + result.stderr
    for log in WORK.glob("*.log"):
        outputs[log.name] = log.read_text(encoding="utf-8", errors="replace")
    for directory in state_dirs:
        for path in directory.rglob("*"):
            if path.is_file() and path not in keys and path not in containers:
                outputs[str(path.relative_to(WORK))] = path.read_bytes().decode("latin-1")
    for where, text in outputs.items():
        for what, needle in needles.items():
            assert needle not in text, f"{what} appears in plain text in {where}"
    print(f"PASS no token or private key in {len(outputs)} logs, outputs and state files; "
          f"{len(keys)} key files are mode 0600")


# ---------- a VPN device: grants, re-import notes and names ----------

DNS_RESPONDER = r"""import socket,sys
# A home DNS server (Pi-hole stand-in). Every A question gets the client address from the
# EDNS Client Subnet option RIFT adds, so the test sees which device RIFT named; without the
# option it answers 192.0.2.53.
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind((sys.argv[1],53))
ECS=bytes([0,8,0,8,0,1,32,0])
while True:
    q,a=s.recvfrom(1024)
    end=12
    while q[end]: end+=q[end]+1
    end+=5
    at=q.find(ECS,end)
    addr=q[at+8:at+12] if at>=0 else bytes([192,0,2,53])
    s.sendto(q[:2]+bytes([0x81,0x80,0,1,0,1,0,0,0,0])+q[12:end]+bytes([0xc0,0x0c,0,1,0,1,0,0,0,60,0,4])+addr,a)
"""

DNS_QUERY = r"""import socket,sys
# Asks sys.argv[1] for an A record of sys.argv[2]; prints the rcode and the address, if any.
name=sys.argv[2]
q=bytes([0x42,0x42,1,0,0,1,0,0,0,0,0,0])+b"".join(bytes([len(l)])+l.encode() for l in name.split("."))+bytes([0,0,1,0,1])
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q,(sys.argv[1],53))
r,_=s.recvfrom(512)
assert r[:2]==q[:2] and r[2]&0x80, r
an=int.from_bytes(r[6:8],"big")
print(r[3]&0x0f, ".".join(map(str,r[-4:])) if an else "-")
"""


def device_apply(config_text, address):
    """Loads a device configuration into the device's WireGuard interface, as the app would:
    the keys, the peer, the routes of AllowedIPs. Address, DNS and MTU are app settings."""
    keep = ("[Interface]", "[Peer]", "PrivateKey", "PublicKey", "Endpoint", "AllowedIPs",
            "PersistentKeepalive")
    lines = [line for line in config_text.splitlines() if line.startswith(keep)]
    conf = write(WORK / "device.conf", "\n".join(lines) + "\n")
    if ns(DEVICE, "ip", "link", "show", "wg0", check=False).returncode != 0:
        ns(DEVICE, "ip", "link", "add", "wg0", "type", "wireguard")
        ns(DEVICE, "ip", "addr", "add", f"{address}/32", "dev", "wg0")
        ns(DEVICE, "ip", "link", "set", "wg0", "mtu", "1380", "up")
    ns(DEVICE, "wg", "setconf", "wg0", str(conf))
    ns(DEVICE, "ip", "route", "flush", "dev", "wg0", check=False)
    allowed = next(line for line in lines if line.startswith("AllowedIPs")).split("=", 1)[1]
    for net in (n.strip() for n in allowed.split(",")):
        if ":" not in net:
            ns(DEVICE, "ip", "route", "replace", net, "dev", "wg0")
    dns = next((line.split("=", 1)[1].strip() for line in config_text.splitlines()
                if line.startswith("DNS")), None)
    return dns


def device_reaches(address, port, proto="tcp", expect=None):
    probe = r"""import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if sys.argv[3]=="udp" else socket.SOCK_STREAM); s.settimeout(3)
try:
    s.connect((sys.argv[1],int(sys.argv[2]))); s.sendall(b"device"); print(s.recv(64).decode())
except OSError as e:
    print(f"no answer: {e}"); sys.exit(3)
"""
    result = ns(DEVICE, "python3", "-c", probe, address, str(port), proto, check=False)
    if expect is not None:
        return result.returncode == 0 and result.stdout.strip() == expect
    return result.returncode == 0


def vpn_device_test(server_cfg):
    """A real WireGuard device: vpn connect, ports and agents it may and may not reach, which
    changes need a new configuration, and the agents' .internal names through its tunnel."""
    agents = {a["name"]: a for a in status(server_cfg)["snapshot"]["agents"]}
    a1, a2, a3 = (agents[n]["tunnel_ipv4"] for n in ("agent1", "agent2", "agent3"))
    connected = json.loads(cli(VPS, server_cfg, "vpn", "connect", "phone", "agent1", "19080/tcp",
                               "--export").stdout)
    assert connected["created"] is True, connected
    assert any("19080" in line for line in connected["reach"]), connected
    peers = {p["name"]: p for p in json.loads(cli(VPS, server_cfg, "list", "devices").stdout)}
    me = peers["phone"]["ipv4"]
    device_apply(connected["config"]["config"], me)
    wait_until(lambda: device_reaches(a1, 19080, expect=me), "the device to reach its grant", timeout=40)
    assert not device_reaches(a1, 19081, "udp"), "a port without a grant answered"
    assert not device_reaches(a2, 19080), "an agent without a grant answered"
    print("PASS a VPN device from vpn connect reaches its grant with its own address, and nothing else")

    # Another port on the same agent: the configuration routes addresses, not ports.
    same = json.loads(cli(VPS, server_cfg, "vpn", "allow", "phone", "agent1", "19081/udp").stdout)
    assert same["reimport"] == [], same
    wait_until(lambda: device_reaches(a1, 19081, "udp", expect=me), "the new port without a new configuration")
    # A new agent changes the configuration, and RIFT says so.
    other = json.loads(cli(VPS, server_cfg, "vpn", "allow", "phone", "agent2", "19080/tcp").stdout)
    assert other["reimport"] == ["phone"], other
    assert not device_reaches(a2, 19080), "the old configuration reached a new agent"
    config = json.loads(cli(VPS, server_cfg, "vpn", "config", "phone", "--export").stdout)["config"]
    device_apply(config, me)
    wait_until(lambda: device_reaches(a2, 19080, expect=me), "the new agent after importing again")
    print("PASS a new port on a known agent needs no new configuration; a new agent does, and RIFT names the device")

    # Names: agent1 on. The device's DNS server becomes the server's tunnel address.
    named = json.loads(cli(VPS, server_cfg, "vpn", "names", "agent", "agent1", "on").stdout)
    assert named["reimport"] == ["phone"], named
    config = json.loads(cli(VPS, server_cfg, "vpn", "config", "phone", "--export").stdout)["config"]
    dns = device_apply(config, me)
    assert dns == "10.13.0.1", config

    def ask(name):
        return ns(DEVICE, "python3", "-c", DNS_QUERY, dns, name).stdout.split()
    assert wait_until(lambda: ask("agent1.internal") == ["0", a1], "agent1.internal through the tunnel", timeout=30)
    assert ask("AGENT1.internal") == ["0", a1], "names are case-insensitive"
    assert ask("agent2.internal") == ["3", "-"], "an agent without names resolved"
    assert ask("agent3.internal") == ["3", "-"], "an agent without a grant resolved"
    # Turning names on for agent2, which the device already uses names for: same DNS line.
    second = json.loads(cli(VPS, server_cfg, "vpn", "names", "agent", "agent2", "on").stdout)
    assert second["reimport"] == [], second
    assert wait_until(lambda: ask("agent2.internal") == ["0", a2], "agent2.internal without a new configuration")

    # Other names go to the device's DNS agent: a home DNS server on agent3, asked by the server.
    start_echo_process(AGENTS[2], write(WORK / "dns-responder.py", DNS_RESPONDER, 0o755), [a3],
                       "dns-responder")
    home = json.loads(cli(VPS, server_cfg, "vpn", "dns", "phone", "agent3").stdout)
    # The DNS line stays the server; the route to agent3 is new, so RIFT asks for a re-import.
    assert home["reimport"] == ["phone"], home
    config = json.loads(cli(VPS, server_cfg, "vpn", "config", "phone", "--export").stdout)["config"]
    assert device_apply(config, me) == "10.13.0.1", config
    # The home DNS server answers with the device address RIFT passed on (EDNS Client Subnet),
    # so a Pi-hole shows the device instead of the server.
    assert wait_until(lambda: ask("example.com") == ["0", me],
                      "example.com through RIFT to the home DNS server, naming the device", timeout=40)
    print("PASS names: NAME.internal only for agents with names and a grant, other names relayed to the device's DNS agent with the device's address")

    # The device opts out: its configuration changes, and the server no longer answers it.
    off = json.loads(cli(VPS, server_cfg, "vpn", "names", "device", "phone", "off").stdout)
    assert off["reimport"] == ["phone"], off
    refused = ns(DEVICE, "python3", "-c", DNS_QUERY, "10.13.0.1", "agent1.internal", check=False)
    assert refused.returncode != 0, f"a device without names still got an answer: {refused.stdout}"
    for args in (["vpn", "names", "agent", "agent1", "off"], ["vpn", "names", "agent", "agent2", "off"],
                 ["vpn", "dns", "phone", "default"], ["remove", "device", "phone"]):
        cli(VPS, server_cfg, *args)
    print("PASS a device that turned names off gets a new configuration and no answers")


def main():
    global WORK
    if sys.platform != "linux" or os.geteuid() != 0:
        raise SystemExit("run this test as root on Linux in a disposable VM")
    if os.environ.get("RIFT_NETNS_DISPOSABLE_VM") != "1":
        raise SystemExit("set RIFT_NETNS_DISPOSABLE_VM=1 only after confirming this is a disposable Linux VM")
    if not BIN.is_file():
        raise SystemExit(f"RIFT binary not found: {BIN} (build with cargo build --release first)")
    for command in ("ip", "ss", "wg", "nft", "conntrack", "openssl", "python3"):
        if shutil.which(command) is None:
            raise SystemExit(f"missing required command: {command}")
    WORK = pathlib.Path(tempfile.mkdtemp(prefix="rift-netns-"))
    try:
        create_topology()
        # Newly assigned IPv6 addresses remain tentative during DAD. Do not bind
        # probe sockets until the real kernel has completed address activation.
        wait_until(lambda: all(not ns(name, "ip", "-6", "address", "show", "tentative").stdout.strip()
                               for name in NETNS),
                   "IPv6 addresses to finish duplicate address detection", timeout=20)
        prior = install_foreign_state()
        start_underlay_echo()
        def underlay_ready():
            check_normal_traffic()
            return True
        wait_until(underlay_ready, "underlay echo listeners to become ready", timeout=20)
        # Normal underlay path must be selected before RIFT owns anything.
        baselines = {name: (ns(name, "ip", "route", "get", PUBLIC_V4,
                               "from", f"172.31.0.{idx}").stdout.strip(),
                            ns(name, "ip", "-6", "route", "get", PUBLIC_V6,
                               "from", f"fd42:31::{idx}").stdout.strip())
                     for idx, name in enumerate(AGENTS, start=2)}
        server_cfg = config(WORK / "state-server", server=True)
        server_env = {"RIFT_PUBLIC_ENDPOINT": SERVER_HOST,
                      "RIFT_PUBLIC_IPS": f"{PUBLIC_V4},{PUBLIC_V4_NEW},{PUBLIC_V6}",
                      "RIFT_ENROLLMENT_BIND": "0.0.0.0:8443",
                      "RIFT_ENROLLMENT": "always"}
        server_proc = daemon(VPS, server_cfg, ["server"], server_env)
        wait_until(lambda: cli(VPS, server_cfg, "status", env=server_env).returncode == 0,
                   "RIFT server admin socket", timeout=35)
        # Created now and used at the end, once its one-minute TTL has passed.
        expiring_token = json.loads(cli(VPS, server_cfg, "add", "agent", "expiring", "--ttl", "1m",
                                        env=server_env).stdout)["token"]
        expiring_created = time.monotonic()
        for secret in (WORK / "state-server" / "tls-server.key",
                       WORK / "state-server" / "tls-ca.key"):
            assert secret.exists() and secret.stat().st_mode & 0o077 == 0, \
                f"auto-generated TLS private key is missing or not mode 0600: {secret}"
        agent_cfgs = []
        tokens = {}
        for idx, name in enumerate(AGENTS, start=1):
            agent_cfg = config(WORK / f"state-agent{idx}", server=False)
            agent_cfgs.append(agent_cfg)
            token = json.loads(cli(VPS, server_cfg, "add", "agent", f"agent{idx}", "--ttl", "15m",
                                   env=server_env).stdout)["token"]
            tokens[f"agent{idx}"] = token
            daemon(name, agent_cfg, ["agent"], {"RIFT_SERVER": f"{SERVER_HOST}:8443",
                                                "RIFT_AGENT_NAME": f"agent{idx}",
                                                "RIFT_ENROLLMENT_TOKEN": token})
        wait_agents(server_cfg, 3)
        wait_initial_nat_port(server_cfg)
        start_echoes(server_cfg)
        ports = add_forwards(server_cfg, ["agent1", "agent2", "agent3"])
        wait_policy(server_cfg, 3)
        traffic_test(["agent1", "agent2", "agent3"], ports)
        agent_isolation_test(server_cfg)
        fail2ban_coexistence_test(server_cfg, ports)
        agent_local_ban_test(server_cfg)
        translation_ban_test(server_cfg)
        allow_from_test(server_cfg)
        host_local_proxy_test(server_cfg)
        vpn_device_test(server_cfg)
        check_routes_and_foreign(prior, baselines)
        check_normal_traffic()
        migrate_endpoint_ip(server_cfg)
        traffic_test(["agent1"], ports)
        print("PASS restarted agent restored its saved forwarding policy")
        migrate_nat_port(server_cfg)
        disable_remove_test(server_cfg)
        replay_and_wrong_ca(server_cfg, tokens["agent1"])
        tokens["expiring"] = expiring_token
        expired_invitation_test(server_cfg, expiring_token, expiring_created)

        # Hard-crash and restart the server with its persistent state. The
        # unrelated nftables table and foreign policy rule must survive.
        stop_process(server_proc, signal.SIGKILL)
        # A label of its own keeps the first server log for the secret scan at the end.
        server_proc = daemon(VPS, server_cfg, ["server"], server_env, label="server-after-crash")
        wait_until(lambda: cli(VPS, server_cfg, "status", env=server_env).returncode == 0,
                   "RIFT server to restart from saved state", timeout=35)
        assert ns(VPS, "nft", "list", "table", "inet", "rift_preserve").stdout == prior[0]
        assert ns(VPS, "ip", "rule", "show").stdout == prior[1], "foreign policy rules changed after restart"
        print("PASS crash/restart preserves existing firewall objects and policy rules")
        wait_forwarding_after_restart(server_cfg, ["agent1", "agent2"], ports, "a server crash")
        assert_single_owner_rules(VPS)
        print("PASS forwarding works again after the server was killed and restarted")

        # Orderly shutdown removes RIFT state without touching unrelated rules;
        # persistent identities and grants restore service after both restart.
        agent_proc = next(proc for proc, _, name in reversed(PROCS)
                          if name == AGENTS[0] and proc.poll() is None)
        for proc in (agent_proc, server_proc):
            proc.send_signal(signal.SIGTERM)
            assert proc.wait(timeout=60) == 0, "RIFT orderly shutdown failed"
        for name in (VPS, AGENTS[0]):
            assert ns(name, "ip", "link", "show", "rift0", check=False).returncode != 0
            assert ns(name, "nft", "list", "table", "inet", "rift", check=False).returncode != 0
            for family in ("-4", "-6"):
                assert not ns(name, "ip", family, "route", "show", "table", "51888", check=False).stdout.strip()
                rules = ns(name, "ip", family, "rule", "show").stdout
                assert not any(line.startswith(("11000:", "11001:")) for line in rules.splitlines())
        assert ns(VPS, "nft", "list", "table", "inet", "rift_preserve").stdout == prior[0]
        assert ns(VPS, "ip", "rule", "show").stdout == prior[1]
        expect_tcp_unreachable(ports[("agent1", PUBLIC_V4, "tcp")], PUBLIC_V4)
        check_normal_traffic()
        # Interrupt both daemons while they start (after they began to change the network),
        # then start them again: the second start must take over the half-applied state.
        agent1_env = {"RIFT_SERVER": f"{SERVER_HOST}:8443", "RIFT_AGENT_NAME": "agent1"}
        interrupt_server_starts(server_cfg, server_env)
        server_proc = daemon(VPS, server_cfg, ["server"], server_env, label="server-after-interrupt")
        wait_until(lambda: cli(VPS, server_cfg, "status", env=server_env).returncode == 0,
                   "server after an interrupted start", timeout=35)
        kill_during_startup(AGENTS[0], agent_cfgs[0], ["agent"], agent1_env, "agent1-interrupted")
        daemon(AGENTS[0], agent_cfgs[0], ["agent"], agent1_env, label="agent1-after-interrupt")
        wait_agents(server_cfg, 2)
        wait_policy(server_cfg, 2)
        # Agent records and applied generations persist across the restart;
        # they do not prove that the new WireGuard interface has handshakes.
        wait_forwarding_after_restart(server_cfg, ["agent1", "agent2"], ports,
                                      "an interrupted start")
        for name in (VPS, AGENTS[0]):
            assert_single_owner_rules(name)
        assert ns(VPS, "nft", "list", "table", "inet", "rift_preserve").stdout == prior[0]
        assert ns(VPS, "ip", "rule", "show").stdout == prior[1]
        check_normal_traffic()
        print("PASS orderly stop cleans networking; a start interrupted mid-apply recovers on "
              "the next start and restores forwarding")
        nat_cloud_test(tokens)
        plaintext_secret_scan(server_cfg, tokens)
        print("PASS namespace integration suite completed; no performance numbers were collected")
    except Exception:
        # Preserve diagnostics in the job log before cleanup removes the scratch directory.
        for logfile in WORK.glob("*.log"):
            print(f"--- {logfile.name} ---", file=sys.stderr)
            print(logfile.read_text(encoding="utf-8", errors="replace")[-5000:], file=sys.stderr)
        raise
    finally:
        cleanup()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        if WORK is not None:
            for logfile in WORK.glob("*.log"):
                print(f"--- {logfile.name} ---", file=sys.stderr)
                print(logfile.read_text(encoding="utf-8", errors="replace")[-3000:], file=sys.stderr)
        raise
