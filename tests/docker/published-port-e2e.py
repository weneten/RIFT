#!/usr/bin/env python3
"""Root-only integration check: host RIFT agent forwards into Docker -p backend."""
import json
import hashlib
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid


ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = pathlib.Path(os.environ.get("RIFT_BIN", ROOT / "target/release/rift")).resolve()
ID = f"{os.getpid() % 100000:05d}"
NS = f"rpd{ID}"
CLIENT_NS = f"rpc{ID}"
BRIDGE = f"rpb{ID}"
VPS = f"rift-pub-vps-{ID}"
VPS4, VPS6 = "198.19.11.1", "2001:db8:11::1"
VPSVIP4, VPSVIP6 = "198.19.11.100", "2001:db8:11::100"
CLIENT4, CLIENT6 = "198.19.11.10", "2001:db8:11::10"
HOST4, SERVER4 = "198.20.11.1", "198.20.11.2"
MARK = "0x52490000"
PORTS = {"tcp4": 18080, "udp4": 18081, "tcp6": 18082, "udp6": 18083}
DOCKER_NAME = f"rift-published-{ID}"
DOCKER_NET = f"rift-published-net-{ID}"
SFTP_NAME = f"rift-sftp-{ID}"
SFTP_IMAGE = f"rift-sftp-test:{ID}"
SFTP_PORTS = {"v4": 18084, "v6": 18085}
SFTP4, SFTP6 = "172.30.211.3", "2001:db8:211::3"
TRAEFIK_BACKEND_NAME = f"rift-traefik-backend-{ID}"
TRAEFIK_NAME = f"rift-traefik-{ID}"
TRAEFIK_BACKEND4 = "172.30.211.4"
TRAEFIK_BACKEND6 = "2001:db8:211::4"
TRAEFIK4 = "172.30.211.5"
TRAEFIK6 = "2001:db8:211::5"
TRAEFIK_PORT = 18443
BACKEND4 = "172.30.211.2"
BACKEND6 = "2001:db8:211::2"
WORK = None
PROCS = []
SYSCTLS = {}
TEST_CONTAINERS = []
TEST_IMAGES = []


def run(args, *, check=True, capture=True, timeout=30):
    p = subprocess.run([str(a) for a in args], check=False, text=True,
                       stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.PIPE if capture else None,
                       timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"command failed ({p.returncode}): {args!r}\n{p.stdout}\n{p.stderr}")
    return p


def ns(name, *args, check=True, timeout=30):
    return run(["ip", "netns", "exec", name, *args], check=check, timeout=timeout)


def write(path, text):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    return path


def docker(*args, check=True, timeout=120):
    return run(["docker", *args], check=check, timeout=timeout)


def docker_logs(name):
    result = docker("logs", name, check=False)
    return result.stdout + result.stderr


def run_sftp(args, *, timeout=90):
    """Run one SFTP case, retaining bounded diagnostics and reaping its process group."""
    proc = subprocess.Popen([str(a) for a in args], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = proc.communicate()
        raise RuntimeError(
            f"SFTP command timed out after {timeout}s; stdout tail:\n{stdout[-6000:]}"
            f"\nstderr tail:\n{stderr[-6000:]}")
    if proc.returncode:
        raise RuntimeError(
            f"SFTP command failed ({proc.returncode}); stdout tail:\n{stdout[-6000:]}"
            f"\nstderr tail:\n{stderr[-6000:]}")
    return subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)


def report_failure_diagnostics():
    """Print service logs while containers and daemon log files still exist."""
    for container in TEST_CONTAINERS:
        try:
            logs = docker_logs(container)
        except Exception as exc:
            print(f"--- container {container}: unable to read logs: {exc} ---", file=sys.stderr)
            continue
        if logs.strip():
            print(f"--- container {container} (last 4000 characters) ---", file=sys.stderr)
            print(logs[-4000:], file=sys.stderr)
    if WORK and WORK.is_dir():
        for log in sorted(WORK.glob("*.log")):
            print(f"--- daemon {log.name} (last 4000 characters) ---", file=sys.stderr)
            print(log.read_text(encoding="utf-8", errors="replace")[-4000:], file=sys.stderr)


def daemon(name, cfg, command, env, host=False):
    args = [str(BIN), "--config", str(cfg), *command]
    if not host:
        args = ["ip", "netns", "exec", name, *args]
    out = (WORK / f"{command[-1]}.log").open("w", encoding="utf-8")
    proc = subprocess.Popen(args, env={**os.environ, **env}, stdout=out,
                            stderr=subprocess.STDOUT, start_new_session=True, text=True)
    PROCS.append((proc, out))
    return proc


def stop(proc):
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=10)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def preflight():
    if sys.platform != "linux" or os.geteuid() != 0 or os.environ.get("RIFT_DOCKER_PUBLISHED_VM") != "1":
        raise SystemExit("root and RIFT_DOCKER_PUBLISHED_VM=1 on disposable Linux VM are required")
    if not BIN.is_file():
        raise SystemExit(f"RIFT binary not found: {BIN}; build with cargo build --release first")
    for cmd in ("ip", "wg", "nft", "sysctl", "docker", "python3",
                "ssh-keygen", "sftp", "openssl", "curl"):
        if shutil.which(cmd) is None:
            raise SystemExit(f"missing required command: {cmd}")
    docker("info", timeout=30)
    port_specs = ([(port, socket.SOCK_STREAM) for port in PORTS.values()]
                  + [(port, socket.SOCK_DGRAM) for port in PORTS.values()]
                  + [(port, socket.SOCK_STREAM) for port in SFTP_PORTS.values()]
                  + [(TRAEFIK_PORT, socket.SOCK_STREAM)])
    for family, host in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
        for port, kind in port_specs:
            probe = socket.socket(family, kind)
            try:
                probe.bind((host, port))
            except OSError as exc:
                raise SystemExit(f"test port {host}:{port} is already in use: {exc}")
            finally:
                probe.close()
    links = run(["ip", "-o", "link", "show"]).stdout
    if "rift0:" in links:
        raise SystemExit("host already has rift0; refusing to touch an existing RIFT installation")
    if any(f"{name}:" in links for name in (BRIDGE, f"hv{ID}", f"hp{ID}", f"hc{ID}")):
        raise SystemExit("a generated test link name is already in use")
    netns = run(["ip", "netns", "list"], check=False).stdout.splitlines()
    if any(line.split() and line.split()[0] in (NS, CLIENT_NS) for line in netns):
        raise SystemExit("a generated test network namespace already exists")
    containers = docker("ps", "-a", "--format", "{{.Names}}").stdout.splitlines()
    networks = docker("network", "ls", "--format", "{{.Name}}").stdout.splitlines()
    images = docker("image", "ls", "--format", "{{.Repository}}:{{.Tag}}").stdout.splitlines()
    if any(name in containers for name in (DOCKER_NAME, SFTP_NAME,
                                            TRAEFIK_BACKEND_NAME, TRAEFIK_NAME)) or DOCKER_NET in networks \
            or SFTP_IMAGE in images:
        raise SystemExit("a generated Docker test object already exists")
    if run(["nft", "list", "table", "inet", "rift"], check=False).returncode == 0:
        raise SystemExit("host already has inet rift table; refusing to touch an existing RIFT installation")
    rules = run(["ip", "rule", "show"]).stdout
    if any(f"{priority}:" in rules for priority in ("11000", "11001")):
        raise SystemExit("host rule priority 11000 or 11001 is already occupied")
    routes = run(["ip", "route", "show", "table", "51888"], check=False).stdout.strip()
    if routes:
        raise SystemExit("host route table 51888 is not empty")
    for family in ([], ["-6"]):
        existing = run(["ip", *family, "route", "show", "table", "main", "proto", "242"],
                       check=False).stdout.strip()
        if existing:
            raise SystemExit("host already has protocol-242 routes; refusing to alter them")
    for key in ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding", "net.ipv4.conf.default.rp_filter"):
        value = run(["sysctl", "-n", key]).stdout.strip()
        SYSCTLS[key] = value


def prepare_sysctls():
    # These changes are scoped to the disposable CI VM and restored in finally.
    for key, value in (("net.ipv4.ip_forward", "1"),
                       ("net.ipv6.conf.all.forwarding", "1"),
                       ("net.ipv4.conf.default.rp_filter", "2")):
        run(["sysctl", "-w", f"{key}={value}"])


def create_network():
    run(["ip", "netns", "add", NS])
    run(["ip", "netns", "add", CLIENT_NS])
    run(["ip", "link", "add", BRIDGE, "type", "bridge"])
    run(["ip", "link", "set", BRIDGE, "up"])
    # VPS underlay link to the real host agent.
    run(["ip", "link", "add", f"hv{ID}", "type", "veth", "peer", "name", f"nv{ID}"])
    run(["ip", "link", "set", f"nv{ID}", "netns", NS])
    run(["ip", "addr", "add", f"{HOST4}/30", "dev", f"hv{ID}"])
    run(["ip", "link", "set", f"hv{ID}", "up"])
    ns(NS, "ip", "link", "set", f"nv{ID}", "name", "eth0")
    ns(NS, "ip", "addr", "add", f"{SERVER4}/30", "dev", "eth0")
    ns(NS, "ip", "link", "set", "eth0", "up")
    ns(NS, "ip", "link", "set", "lo", "up")
    # Client/VPS public test segment; public VIPs are aliases on the VPS end.
    for n, host_if, ns_if in ((NS, f"hp{ID}", f"np{ID}"),
                              (CLIENT_NS, f"hc{ID}", f"nc{ID}")):
        run(["ip", "link", "add", host_if, "type", "veth", "peer", "name", ns_if])
        run(["ip", "link", "set", ns_if, "netns", n])
        run(["ip", "link", "set", host_if, "master", BRIDGE])
        run(["ip", "link", "set", host_if, "up"])
        ns(n, "ip", "link", "set", ns_if, "name", "eth1")
        ns(n, "ip", "link", "set", "eth1", "up")
        ns(n, "ip", "link", "set", "lo", "up")
    ns(NS, "ip", "addr", "add", f"{VPS4}/24", "dev", "eth1")
    ns(NS, "ip", "addr", "add", f"{VPSVIP4}/24", "dev", "eth1")
    ns(NS, "ip", "-6", "addr", "add", f"{VPS6}/64", "dev", "eth1")
    ns(NS, "ip", "-6", "addr", "add", f"{VPSVIP6}/64", "dev", "eth1")
    ns(CLIENT_NS, "ip", "addr", "add", f"{CLIENT4}/24", "dev", "eth1")
    ns(CLIENT_NS, "ip", "-6", "addr", "add", f"{CLIENT6}/64", "dev", "eth1")
    for n in (NS, CLIENT_NS):
        ns(n, "sysctl", "-qw", "net.ipv4.ip_forward=1")
        ns(n, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
    cfg = ('state_dir = "' + str(WORK / "vps-state") + '"\ninterface = "rift0"\n'
           'wg_port = 51820\ncontrol_port = 8444\nroute_table = 51888\nrule_priority = 11000\n'
           f'mark = {int(MARK, 16)}\nmark_mask = 4294901760\nmtu = 1380\n'
           f'public_endpoint = "{SERVER4}"\npublic_ips = ["{VPSVIP4}", "{VPSVIP6}"]\n'
           'enrollment_bind = "0.0.0.0:8443"\nenrollment_enabled = true\n')
    server_cfg = write(WORK / "server.toml", cfg)
    agent_cfg = write(WORK / "agent.toml", cfg.replace(str(WORK / "vps-state"), str(WORK / "agent-state")))
    return server_cfg, agent_cfg


def admin(name, cfg, *args):
    return ns(name, str(BIN), "--config", str(cfg), "--json", *args)


def host_admin(cfg, *args):
    return run([str(BIN), "--config", str(cfg), "--json", *args])


def wait_for(desc, predicate, timeout=90):
    limit = time.monotonic() + timeout
    last = None
    while time.monotonic() < limit:
        try:
            last = predicate()
            if last:
                return last
        except (RuntimeError, json.JSONDecodeError, OSError):
            pass
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {desc}; last={last!r}")


BACKEND = r'''import socket,threading
def run(family,kind,address,port):
 s=socket.socket(family,kind); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((address,port))
 if kind==socket.SOCK_STREAM:
  s.listen(64)
  while True:
   c,p=s.accept()
   try:c.sendall(p[0].encode())
   finally:c.close()
 else:
  while True:
   _,p=s.recvfrom(4096); s.sendto(p[0].encode(),p)
for f,addr,ports in ((socket.AF_INET,"0.0.0.0",(18080,18081)),(socket.AF_INET6,"::",(18082,18083))):
 for kind,port in ((socket.SOCK_STREAM,ports[0]),(socket.SOCK_DGRAM,ports[1])):
  threading.Thread(target=run,args=(f,kind,addr,port),daemon=True).start()
threading.Event().wait()
'''


def run_datapath(server_cfg, agent_cfg):
    server_env = {"RIFT_PUBLIC_ENDPOINT": SERVER4,
                  "RIFT_PUBLIC_IPS": f"{VPSVIP4},{VPSVIP6}",
                  "RIFT_ENROLLMENT_BIND": "0.0.0.0:8443",
                  "RIFT_ENROLLMENT_ENABLED": "true"}
    server_proc = daemon(NS, server_cfg, ["server"], server_env)
    wait_for("VPS admin socket", lambda: admin(NS, server_cfg, "status").returncode == 0)
    token = json.loads(admin(NS, server_cfg, "agents", "add", "host-agent", "--ttl", "15m").stdout)["token"]

    backend = WORK / "backend.py"
    backend.write_text(BACKEND, encoding="utf-8")
    docker("network", "create", "--driver", "bridge", "--ipv6",
           "--subnet", "172.30.211.0/24", "--subnet", "2001:db8:211::/64", DOCKER_NET)
    docker("run", "-d", "--name", DOCKER_NAME, "--cap-drop", "ALL", "--read-only",
           "--network", DOCKER_NET, "--ip", BACKEND4, "--ip6", BACKEND6,
           "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m",
           "-p", "0.0.0.0:18080:18080/tcp", "-p", "0.0.0.0:18081:18081/udp",
           "-p", "[::]:18082:18082/tcp", "-p", "[::]:18083:18083/udp",
           "--mount", f"type=bind,src={backend},dst=/opt/backend.py,readonly",
           "python:3.13-slim", "python3", "/opt/backend.py", timeout=240)
    TEST_CONTAINERS.append(DOCKER_NAME)

    agent_env = {"RIFT_SERVER": f"{SERVER4}:8443", "RIFT_AGENT_NAME": "host-agent",
                 "RIFT_ENROLLMENT_TOKEN": token}
    agent_proc = daemon("host", agent_cfg, ["agent"], agent_env, host=True)
    def agent_active():
        state = json.loads(admin(NS, server_cfg, "status").stdout)
        return next((a for a in state["snapshot"]["agents"]
                     if a["name"] == "host-agent" and a["status"] == "active"), None)
    wait_for("host agent enrollment/handshake", agent_active)
    for family, ip, protos in (("v4", VPSVIP4, ("tcp", "udp")),
                               ("v6", VPSVIP6, ("tcp", "udp"))):
        for proto in protos:
            suffix = family[-1]
            name = proto + suffix
            port = PORTS[name]
            admin(NS, server_cfg, "forwards", "add", "--agent", "host-agent",
                  "--listen-ip", ip, "--listen", str(port), "--target", str(port),
                  "--protocol", proto)
    def applied():
        state = json.loads(admin(NS, server_cfg, "status").stdout)
        snap = state["snapshot"]
        peer = next((a for a in snap["agents"] if a["name"] == "host-agent"), None)
        fully_applied = (state.get("fully_applied") is True
                         and not state.get("pending_forwards")
                         and state.get("apply_error") is None)
        return peer if fully_applied and peer and peer["applied_generation"] >= snap["generation"] else None
    wait_for("host agent policy to apply", applied)

    code = r'''import socket,sys
f=socket.AF_INET6 if sys.argv[1]=="6" else socket.AF_INET
k=socket.SOCK_DGRAM if sys.argv[2]=="udp" else socket.SOCK_STREAM
src,dst,port=sys.argv[3],sys.argv[4],int(sys.argv[5])
s=socket.socket(f,k); s.settimeout(8); s.bind((src,0)); s.connect((dst,port)); s.sendall(b"docker-published")
got=s.recv(128).decode(); print(got); assert got==src,(got,src)
'''
    for family, proto, source, destination, port in (
            ("4", "tcp", CLIENT4, VPSVIP4, PORTS["tcp4"]),
            ("4", "udp", CLIENT4, VPSVIP4, PORTS["udp4"]),
            ("6", "tcp", CLIENT6, VPSVIP6, PORTS["tcp6"]),
            ("6", "udp", CLIENT6, VPSVIP6, PORTS["udp6"])):
        got = ns(CLIENT_NS, "python3", "-c", code, family, proto, source, destination, str(port)).stdout.strip()
        if got != source:
            raise RuntimeError(f"Docker published {family}/{proto} backend saw {got}, expected {source}")
        print(f"PASS Docker published bridge {family}/{proto}: backend observed client source {got}")
    sftp_test(server_cfg)
    traefik_test(server_cfg)
    return server_proc, agent_proc


def wait_policy(server_cfg):
    def applied():
        state = json.loads(admin(NS, server_cfg, "status").stdout)
        snap = state["snapshot"]
        peer = next((a for a in snap["agents"] if a["name"] == "host-agent"), None)
        fully_applied = (state.get("fully_applied") is True
                         and not state.get("pending_forwards")
                         and state.get("apply_error") is None)
        return peer if fully_applied and peer and peer["applied_generation"] >= snap["generation"] else None
    wait_for("host agent to apply the new application forward", applied)


def add_app_forward(server_cfg, listen_ip, listen_port, target_port):
    result = json.loads(admin(NS, server_cfg, "forwards", "add", "--agent", "host-agent",
                              "--listen-ip", listen_ip, "--listen", str(listen_port),
                              "--target", str(target_port), "--protocol", "tcp").stdout)
    wait_policy(server_cfg)
    return result


def sftp_test(server_cfg):
    sftp_image = SFTP_IMAGE
    docker("build", "--tag", sftp_image, "--file", ROOT / "tests/docker/Sftp.Dockerfile",
           ROOT / "tests/docker", timeout=900)
    TEST_IMAGES.append(sftp_image)
    key_path = WORK / "sftp-client-ed25519"
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key_path])
    authorized = pathlib.Path(f"{key_path}.pub")
    docker("run", "-d", "--name", SFTP_NAME, "--network", DOCKER_NET,
           "--ip", SFTP4, "--ip6", SFTP6, "--cap-drop", "ALL",
           "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "CHOWN",
           "--cap-add", "SYS_CHROOT",
           "--read-only", "--tmpfs", "/run:rw,noexec,nosuid,size=8m",
           "--tmpfs", "/home/rift-sftp:rw,noexec,nosuid,size=64m",
           "--publish", f"0.0.0.0:{SFTP_PORTS['v4']}:2222/tcp",
           "--publish", f"[::]:{SFTP_PORTS['v6']}:2222/tcp",
           "--mount", f"type=bind,src={authorized},dst=/run/test_authorized_keys,readonly",
           sftp_image)
    TEST_CONTAINERS.append(SFTP_NAME)
    wait_for("SFTP sshd to listen", lambda: "Server listening on" in docker_logs(SFTP_NAME))
    host_key = docker("exec", SFTP_NAME, "cat", "/run/sshd/ssh_host_ed25519_key.pub").stdout.split()
    if len(host_key) < 2 or host_key[0] != "ssh-ed25519":
        raise RuntimeError(f"unexpected generated sshd host key: {host_key!r}")
    known_hosts = write(WORK / "sftp-known_hosts", "\n".join(
        f"[{address}]:{SFTP_PORTS[family]} {host_key[0]} {host_key[1]}"
        for family, address in (("v4", VPSVIP4), ("v6", VPSVIP6))) + "\n")
    for family, address in (("v4", VPSVIP4), ("v6", VPSVIP6)):
        add_app_forward(server_cfg, address, SFTP_PORTS[family], SFTP_PORTS[family])
        payload = WORK / f"sftp-upload-{family}.bin"
        downloaded = WORK / f"sftp-download-{family}.bin"
        payload.write_bytes(os.urandom(131_071))
        remote = f"/home/rift-sftp/transfer-{family}.bin"
        batch = write(WORK / f"sftp-{family}.batch",
                      f"put {payload} {remote}\nget {remote} {downloaded}\n")
        url = f"rift-sftp@[{address}]" if family == "v6" else f"rift-sftp@{address}"
        sftp_command = ["ip", "netns", "exec", CLIENT_NS, "sftp", "-v", "-b", batch,
                        "-F", "/dev/null", "-P", str(SFTP_PORTS[family]),
                        "-oBatchMode=yes", "-oIdentitiesOnly=yes",
                        "-oPreferredAuthentications=publickey", "-oPasswordAuthentication=no",
                        "-oIdentityFile=" + str(key_path), "-oUserKnownHostsFile=" + str(known_hosts),
                        "-oGlobalKnownHostsFile=/dev/null", "-oStrictHostKeyChecking=yes",
                        "-oConnectTimeout=10", url]
        try:
            run_sftp(sftp_command)
        except Exception:
            local_size = payload.stat().st_size if payload.exists() else "missing"
            downloaded_size = downloaded.stat().st_size if downloaded.exists() else "missing"
            try:
                remote_size = docker("exec", SFTP_NAME, "stat", "-c", "%s", "--", remote,
                                     check=False).stdout.strip() or "missing/unavailable"
            except Exception:
                remote_size = "unavailable"
            print(f"SFTP {family} transfer diagnostics: local upload={local_size} bytes, "
                  f"local download={downloaded_size} bytes, remote file={remote_size} bytes",
                  file=sys.stderr)
            raise
        expected = hashlib.sha256(payload.read_bytes()).hexdigest()
        actual = hashlib.sha256(downloaded.read_bytes()).hexdigest()
        remote_hash = docker("exec", SFTP_NAME, "sha256sum", remote).stdout.split()[0]
        if expected != actual or expected != remote_hash:
            raise RuntimeError(f"SFTP {family} upload/download hash mismatch: local={expected}, downloaded={actual}, server={remote_hash}")
        logs = docker_logs(SFTP_NAME)
        if f"Accepted publickey for rift-sftp from {CLIENT4 if family == 'v4' else CLIENT6} port " not in logs:
            raise RuntimeError(f"sshd log did not record original {family} client address")
        print(f"PASS SFTP {family}: strict host-key verification, public-key auth, upload/download SHA-256, original source logged")


def create_traefik_cert(cert_dir):
    cert_dir.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert = cert_dir / "test-ca.key", cert_dir / "test-ca.crt"
    server_key, csr, server_cert = cert_dir / "server.key", cert_dir / "server.csr", cert_dir / "server.crt"
    ext = write(cert_dir / "server.ext",
                f"subjectAltName=IP:{VPSVIP4},IP:{VPSVIP6}\n"
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n")
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
         "-days", "2", "-keyout", ca_key, "-out", ca_cert, "-subj", "/CN=RIFT E2E Test CA"])
    run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
         "-keyout", server_key, "-out", csr, "-subj", "/CN=RIFT Docker Traefik E2E"])
    run(["openssl", "x509", "-req", "-in", csr, "-CA", ca_cert, "-CAkey", ca_key,
         "-CAcreateserial", "-out", server_cert, "-days", "2", "-sha256", "-extfile", ext])
    return ca_cert, server_key, server_cert


def traefik_test(server_cfg):
    cert_dir = WORK / "traefik-material"
    config_dir = WORK / "traefik-config"
    ca_cert, server_key, server_cert = create_traefik_cert(cert_dir)
    config_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(server_key, config_dir / "server.key")
    shutil.copyfile(server_cert, config_dir / "server.crt")
    # Test-only keys/configs are world-readable in this private scratch mount so
    # the official image can run with either its default user or a nonroot UID.
    (config_dir / "server.key").chmod(0o644)
    (config_dir / "server.crt").chmod(0o644)
    static_config = write(config_dir / "traefik.yml", '''
entryPoints:
  websecure:
    address: ":8443"
providers:
  file:
    filename: /etc/traefik/dynamic.yml
    watch: false
accessLog:
  format: json
''')
    static_config.chmod(0o644)
    dynamic_config = write(config_dir / "dynamic.yml", '''
http:
  routers:
    rift-e2e:
      entryPoints: [websecure]
      rule: "PathPrefix(`/`)"
      service: rift-e2e
      tls: {}
  services:
    rift-e2e:
      loadBalancer:
        servers:
          - url: http://traefik-backend:8080
tls:
  certificates:
    - certFile: /etc/traefik/server.crt
      keyFile: /etc/traefik/server.key
''')
    dynamic_config.chmod(0o644)
    backend_code = '''from http.server import BaseHTTPRequestHandler,HTTPServer
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  body=b"traefik-e2e-backend-ok\\n"; self.send_response(200); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
 def log_message(self,*args): pass
HTTPServer(("0.0.0.0",8080),H).serve_forever()
'''
    docker("run", "-d", "--name", TRAEFIK_BACKEND_NAME, "--network", DOCKER_NET,
           "--network-alias", "traefik-backend", "--ip", TRAEFIK_BACKEND4, "--ip6", TRAEFIK_BACKEND6,
           "--cap-drop", "ALL", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m",
           "python:3.13-slim", "python3", "-c", backend_code)
    TEST_CONTAINERS.append(TRAEFIK_BACKEND_NAME)
    docker("run", "-d", "--name", TRAEFIK_NAME, "--network", DOCKER_NET,
           "--ip", TRAEFIK4, "--ip6", TRAEFIK6, "--cap-drop", "ALL", "--read-only",
           "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m",
           "--publish", f"0.0.0.0:{TRAEFIK_PORT}:8443/tcp",
           "--publish", f"[::]:{TRAEFIK_PORT}:8443/tcp",
           "--mount", f"type=bind,src={config_dir},dst=/etc/traefik,readonly",
           "traefik:v3", "--configFile=/etc/traefik/traefik.yml", timeout=240)
    TEST_CONTAINERS.append(TRAEFIK_NAME)
    for address in (VPSVIP4, VPSVIP6):
        add_app_forward(server_cfg, address, TRAEFIK_PORT, TRAEFIK_PORT)
    for family, address in (("v4", VPSVIP4), ("v6", VPSVIP6)):
        url_host = f"[{address}]" if family == "v6" else address
        result = ns(CLIENT_NS, "curl", "--noproxy", "*", "--fail", "--silent", "--show-error",
                    "--cacert", ca_cert, f"https://{url_host}:{TRAEFIK_PORT}/", timeout=30).stdout
        if result != "traefik-e2e-backend-ok\n":
            raise RuntimeError(f"Traefik {family} backend response was unexpected: {result!r}")
    logs = docker_logs(TRAEFIK_NAME)
    entries = []
    for line in logs.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("RequestPath") == "/":
            entries.append(item)
    for source in (CLIENT4, CLIENT6):
        if not any(item.get("ClientHost") == source and int(item.get("DownstreamStatus", 0)) == 200
                   for item in entries):
            raise RuntimeError(f"Traefik JSON access log lacks successful request with ClientHost={source}")
    print("PASS HTTPS through Traefik v3: test CA verified, backend response received, JSON access log retains both original client IPs")


def cleanup():
    for proc, out in reversed(PROCS):
        stop(proc)
        out.close()
    for container in reversed(TEST_CONTAINERS):
        docker("rm", "--force", container, check=False)
    for image in reversed(TEST_IMAGES):
        docker("image", "rm", image, check=False)
    # Preflight guarantees these RIFT identifiers were unused at startup.
    for family in ([], ["-6"]):
        for priority in ("11000", "11001"):
            run(["ip", *family, "rule", "del", "priority", priority], check=False)
        routes = run(["ip", *family, "route", "show", "table", "51888"], check=False).stdout
        for line in routes.splitlines():
            route = line.split()
            if route:
                run(["ip", *family, "route", "del", *route, "table", "51888"], check=False)
        routes = run(["ip", *family, "route", "show", "table", "main", "proto", "242"],
                     check=False).stdout
        for line in routes.splitlines():
            route = line.split()
            if route:
                run(["ip", *family, "route", "del", *route], check=False)
    docker("network", "rm", DOCKER_NET, check=False)
    for link in (f"hv{ID}", f"hp{ID}", f"hc{ID}", BRIDGE):
        run(["ip", "link", "del", link], check=False)
    for name in (NS, CLIENT_NS):
        run(["ip", "netns", "del", name], check=False)
    if run(["ip", "link", "show", "rift0"], check=False).returncode == 0:
        run(["ip", "link", "del", "rift0"], check=False)
    if run(["nft", "list", "table", "inet", "rift"], check=False).returncode == 0:
        run(["nft", "delete", "table", "inet", "rift"], check=False)
    for key, value in SYSCTLS.items():
        run(["sysctl", "-w", f"{key}={value}"], check=False)
    if WORK:
        shutil.rmtree(WORK, ignore_errors=True)


def main():
    global WORK
    preflight()
    try:
        prepare_sysctls()
        WORK = pathlib.Path(tempfile.mkdtemp(prefix="rift-docker-published-"))
        server_cfg, agent_cfg = create_network()
        run_datapath(server_cfg, agent_cfg)
        print("PASS host-network agent reached a real Docker -p service; published ports and client return routes work")
    except Exception:
        report_failure_diagnostics()
        raise
    finally:
        cleanup()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise
