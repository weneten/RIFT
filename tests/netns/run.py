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
NETNS = [VPS, ROUTER, CLIENT, CLIENT_ALT, BACKEND, *AGENTS]
PUBLIC_V4 = "198.18.0.1"
PUBLIC_V4_NEW = "198.18.0.2"
PUBLIC_V6 = "2001:db8:42:5249::1"
CLIENT_PUBLIC_V6 = "2001:db8:42:5249::10"
CLIENT_ALT_PUBLIC_V6 = "2001:db8:42:5249::11"
WG_PUBLIC_NAT = "198.18.0.254"
SERVER_HOST = "rift-vps.test"
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


def config(state_dir, *, server=False):
    values = [
        f'state_dir = "{state_dir}"', 'interface = "rift0"',
        'wg_port = 51820', 'control_port = 8444',
        'route_table = 51888', 'rule_priority = 11000',
        f'mark = {int(MARK, 16)}', 'mark_mask = 4294901760',
        'keepalive = 3', 'mtu = 1380', 'handshake_timeout = 6',
        'poll_seconds = 2',
    ]
    if server:
        values += [f'public_endpoint = "{SERVER_HOST}"',
                   f'public_ips = ["{PUBLIC_V4}", "{PUBLIC_V4_NEW}", "{PUBLIC_V6}"]',
                   'enrollment_bind = "0.0.0.0:8443"',
                   'enrollment_enabled = true']
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
s=socket.socket(family,kind); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((sys.argv[3],int(sys.argv[4])))
if kind == socket.SOCK_STREAM:
 s.listen(32)
 while True:
  c,a=s.accept()
  try: c.sendall(a[0].encode())
  finally: c.close()
else:
 while True:
  data,a=s.recvfrom(4096); s.sendto(a[0].encode(),a)
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
            cli(VPS, server_cfg, "forwards", "add", "--agent", name,
                "--listen-ip", listen_ip, "--listen", str(listen_port),
                "--target", str(target_port), "--protocol", proto,
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
        VPS, server_cfg, "forwards", "add", "--agent", "agent1",
        "--listen-ip", PUBLIC_V4, "--listen", "18100", "--target", "19080",
        "--protocol", "tcp", "--mode", "translate", "--target-family", "v6",
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
    cli(VPS, server_cfg, "bans", "add", "--agent", "agent1",
        "--forward-id", str(forward_id), "--ip", "198.18.0.10", "--ttl", "4s",
        env={"RIFT_PUBLIC_ENDPOINT": SERVER_HOST,
             "RIFT_PUBLIC_IPS": f"{PUBLIC_V4},{PUBLIC_V4_NEW},{PUBLIC_V6}"})
    bans = json.loads(cli(VPS, server_cfg, "bans", "list").stdout)
    assert any(b["forward_id"] == forward_id and b["ip"] == "198.18.0.10" for b in bans)
    blocked = ns(CLIENT, "python3", "-c", client, PUBLIC_V4, "blocked", check=False)
    assert blocked.returncode == 0, f"translated path was not blocked: {blocked.stderr}"
    time.sleep(5)
    result = ns(CLIENT, "python3", "-c", client, PUBLIC_V4, "allowed").stdout.strip()
    assert result.startswith("fd88:5249:4654::1"), f"translated path did not recover after TTL: {result}"
    print("PASS agent-applied translated-forward ban blocks source IPv4 and expires by TTL")


def agent_local_ban_test(server_cfg):
    forward = json.loads(cli(
        VPS, server_cfg, "forwards", "add", "--agent", "agent3",
        "--listen-ip", PUBLIC_V4, "--listen", "18096", "--target", "19080",
        "--protocol", "tcp", "--mode", "translate", "--target-family", "v6",
        env={"RIFT_PUBLIC_ENDPOINT": SERVER_HOST,
             "RIFT_PUBLIC_IPS": f"{PUBLIC_V4},{PUBLIC_V4_NEW},{PUBLIC_V6}"}).stdout)
    wait_policy(server_cfg, 3)
    probe = r'''import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(3)
s.bind((sys.argv[1],0)); s.connect(("198.18.0.1",18096)); s.sendall(b"agent-ban")
got=s.recv(128).decode(); print(got); assert got.startswith("fd88:5249:4654::1"),got
'''
    assert ns(CLIENT, "python3", "-c", probe, "198.18.0.10").stdout.strip().startswith("fd88:5249:4654::1")
    cli(VPS, server_cfg, "bans", "add", "--agent", "agent3",
        "--forward-id", str(forward["id"]), "--ip", "198.18.0.10", "--ttl", "4s",
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
        VPS, server_cfg, "forwards", "add", "--agent", "agent3",
        "--listen-ip", PUBLIC_V4, "--listen", "18092", "--target", "19082",
        "--protocol", "tcp",
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
    cli(VPS, server_cfg, "forwards", "disable", "--id", str(forward_id))
    wait_policy(server_cfg, 3)
    cli(VPS, server_cfg, "forwards", "enable", "--id", str(forward_id))
    wait_policy(server_cfg, 3)
    assert ns(AGENTS[2], "nft", "list", "table", "inet", "f2b_test").stdout == f2b_before, \
        "RIFT policy re-apply overwrote an independent Fail2ban table"
    ns(AGENTS[2], "nft", "delete", "table", "inet", "f2b_test")
    traffic_test(["agent3"], ports)
    assert ns(CLIENT, "python3", "-c", source_test, "198.18.0.10").stdout.strip() == "198.18.0.10"
    print("PASS foreign Fail2ban-style INPUT/FORWARD rules block one client, preserve RIFT/control/other-client traffic, and removal restores access")


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
    # Update only the test agent's namespace DNS, then blackhole the old UDP
    # endpoint at the transit router. Restarting the agent forces stale-peer
    # endpoint refresh from the persisted enrollment hostname.
    write(f"/etc/netns/{AGENTS[0]}/hosts", f"127.0.0.1 localhost\n{PUBLIC_V4_NEW} {SERVER_HOST}\n", 0o644)
    sh_ns(ROUTER, f"nft add rule inet rift_test_filter forward iifname \"eth1\" ip daddr {PUBLIC_V4} udp dport 51820 drop")
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
    token = json.loads(cli(VPS, server_cfg, "agents", "add", "badca", "--ttl", "15m",
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
    cli(VPS, server_cfg, "agents", "disable", "agent3")
    wait_until(lambda: next((a for a in status(server_cfg)["snapshot"]["agents"]
                             if a["name"] == "agent3"), {}).get("status") == "disabled",
               "agent3 to be disabled")
    expect_tcp_unreachable(18088, PUBLIC_V4)
    expect_tcp_unreachable(18090, PUBLIC_V6)
    cli(VPS, server_cfg, "agents", "remove", "agent3")
    wait_until(lambda: not any(a["name"] == "agent3"
                               for a in status(server_cfg)["snapshot"]["agents"]),
               "agent3 and its forwards to be removed")
    expect_tcp_unreachable(18088, PUBLIC_V4)
    expect_tcp_unreachable(18090, PUBLIC_V6)
    print("PASS disabled and removed agents no longer receive IPv4/IPv6 forwards")


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
                      "RIFT_ENROLLMENT_ENABLED": "true"}
        server_proc = daemon(VPS, server_cfg, ["server"], server_env)
        wait_until(lambda: cli(VPS, server_cfg, "status", env=server_env).returncode == 0,
                   "RIFT server admin socket", timeout=35)
        for secret in (WORK / "state-server" / "tls-server.key",
                       WORK / "state-server" / "tls-ca.key"):
            assert secret.exists() and secret.stat().st_mode & 0o077 == 0, \
                f"auto-generated TLS private key is missing or not mode 0600: {secret}"
        agent_cfgs = []
        tokens = {}
        for idx, name in enumerate(AGENTS, start=1):
            agent_cfg = config(WORK / f"state-agent{idx}", server=False)
            agent_cfgs.append(agent_cfg)
            token = json.loads(cli(VPS, server_cfg, "agents", "add", f"agent{idx}", "--ttl", "15m",
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
        fail2ban_coexistence_test(server_cfg, ports)
        agent_local_ban_test(server_cfg)
        translation_ban_test(server_cfg)
        check_routes_and_foreign(prior, baselines)
        check_normal_traffic()
        migrate_endpoint_ip(server_cfg)
        traffic_test(["agent1"], ports)
        print("PASS restarted agent restored its saved forwarding policy")
        migrate_nat_port(server_cfg)
        disable_remove_test(server_cfg)
        replay_and_wrong_ca(server_cfg, tokens["agent1"])

        # Hard-crash and restart the server with its persistent state. The
        # unrelated nftables table and foreign policy rule must survive.
        stop_process(server_proc, signal.SIGKILL)
        server_proc = daemon(VPS, server_cfg, ["server"], server_env)
        wait_until(lambda: cli(VPS, server_cfg, "status", env=server_env).returncode == 0,
                   "RIFT server to restart from saved state", timeout=35)
        assert ns(VPS, "nft", "list", "table", "inet", "rift_preserve").stdout == prior[0]
        assert ns(VPS, "ip", "rule", "show").stdout == prior[1], "foreign policy rules changed after restart"
        print("PASS crash/restart preserves existing firewall objects and policy rules")

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
        server_proc = daemon(VPS, server_cfg, ["server"], server_env)
        wait_until(lambda: cli(VPS, server_cfg, "status", env=server_env).returncode == 0,
                   "server after orderly restart", timeout=35)
        daemon(AGENTS[0], agent_cfgs[0], ["agent"], {"RIFT_SERVER": f"{SERVER_HOST}:8443",
               "RIFT_AGENT_NAME": "agent1"})
        wait_agents(server_cfg, 2)
        wait_policy(server_cfg, 2)
        traffic_test(["agent1"], ports)
        print("PASS orderly stop cleans networking and restart restores forwarding")
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
