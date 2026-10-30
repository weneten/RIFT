#!/usr/bin/env python3
"""Real single-agent WireGuard datapath check on an isolated Docker bridge."""
import json
import ipaddress
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import uuid


ROOT = pathlib.Path(__file__).resolve().parents[2]
TAG = f"rift-bridge-{uuid.uuid4().hex[:10]}"
NET = f"rift-bridge-{uuid.uuid4().hex[:10]}"
VPS = f"{TAG}-vps"
AGENT = f"{TAG}-agent"
CLIENT = f"{TAG}-client"
VPS4, AGENT4, CLIENT4 = "198.18.90.10", "198.18.90.20", "198.18.90.30"
VPS6, AGENT6, CLIENT6 = "2001:db8:90::10", "2001:db8:90::20", "2001:db8:90::30"
IPS = f"{VPS4},{VPS6}"


def run(args, *, check=True, capture=True, timeout=90):
    p = subprocess.run([str(a) for a in args], text=True,
                       stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.PIPE if capture else None,
                       timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"command failed ({p.returncode}): {args!r}\n{p.stdout}\n{p.stderr}")
    return p


def docker(*args, **kwargs):
    return run(["docker", *args], **kwargs)


def exec_cli(*args):
    return docker("exec", VPS, "rift", "--config", "/etc/rift/config.toml",
                  "--json", *args)


def wait_for(label, predicate, seconds=90):
    until = time.monotonic() + seconds
    last = None
    while time.monotonic() < until:
        try:
            last = predicate()
            if last:
                return last
        except (RuntimeError, ValueError, json.JSONDecodeError):
            pass
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {label}; last={last!r}")


def client_probe(family, proto, source, destination, port):
    code = r'''import socket,sys
family=socket.AF_INET6 if sys.argv[1]=="6" else socket.AF_INET
kind=socket.SOCK_DGRAM if sys.argv[2]=="udp" else socket.SOCK_STREAM
src,dst,port=sys.argv[3],sys.argv[4],int(sys.argv[5])
s=socket.socket(family,kind); s.settimeout(8); s.bind((src,0)); s.connect((dst,port))
s.sendall(b"bridge-datapath"); got=s.recv(256).decode(); print(got)
assert got==src,(got,src)
'''
    return docker("exec", CLIENT, "python3", "-c", code,
                  family, proto, source, destination, str(port)).stdout.strip()


def listener_matches(endpoint, expected_ip, expected_port, family):
    if endpoint.startswith("["):
        close = endpoint.rfind("]")
        if close < 0 or endpoint[close + 1:close + 2] != ":":
            return False
        host, port_text = endpoint[1:close], endpoint[close + 2:]
    else:
        host, separator, port_text = endpoint.rpartition(":")
        if not separator:
            return False
    try:
        actual_ip = ipaddress.ip_address(host)
        actual_port = int(port_text)
    except ValueError:
        return False
    return actual_ip.version == family and actual_ip == expected_ip and actual_port == expected_port


def agent_echo_sockets_ready(tunnel4, tunnel6):
    for family, address in ((4, tunnel4), (6, tunnel6)):
        for proto, option, port in (("tcp", "-t", 19080), ("udp", "-u", 19081)):
            result = docker("exec", AGENT, "ss", "-H", "-l", "-n",
                            f"-{family}", option, check=False)
            if result.returncode != 0 or not any(
                    len(fields := line.split()) >= 4
                    and listener_matches(fields[-2], ipaddress.ip_address(address), port, family)
                    for line in result.stdout.splitlines()):
                return False
    return True


def print_container_diagnostics():
    present = set(docker("ps", "-a", "--format", "{{.Names}}", check=False).stdout.splitlines())
    for name in (AGENT, VPS):
        if name not in present:
            continue
        logs = docker("logs", name, check=False)
        output = logs.stdout + logs.stderr
        if output.strip():
            print(f"--- {name} logs ---", file=sys.stderr)
            print(output[-5000:], file=sys.stderr)
        if name == AGENT:
            echo_log = docker("exec", name, "cat", "/tmp/rift-echo.log", check=False)
            echo_output = echo_log.stdout + echo_log.stderr
            if echo_output.strip():
                print("--- agent echo listener log ---", file=sys.stderr)
                print(echo_output[-3000:], file=sys.stderr)


def main():
    if sys.platform != "linux" or os.environ.get("RIFT_DOCKER_BRIDGE_VM") != "1":
        raise SystemExit("run only on a disposable Linux Docker VM with RIFT_DOCKER_BRIDGE_VM=1")
    docker("info", capture=False)
    with tempfile.TemporaryDirectory(prefix="rift-docker-bridge-") as tmp:
        tmp = pathlib.Path(tmp)
        vps_cfg = tmp / "vps.toml"
        agent_cfg = tmp / "agent.toml"
        cfg = 'state_dir = "/var/lib/rift"\ninterface = "rift0"\nwg_port = 51820\ncontrol_port = 8444\nroute_table = 51888\nrule_priority = 11000\nmark = 1380515840\nmark_mask = 4294901760\nmtu = 1380\nenrollment_bind = "0.0.0.0:8443"\nenrollment = "always"\n'
        vps_cfg.write_text(cfg, encoding="utf-8")
        agent_cfg.write_text(cfg, encoding="utf-8")
        try:
            docker("build", "--tag", TAG, "--file", ROOT / "Dockerfile", ROOT, timeout=900, capture=False)
            docker("build", "--tag", f"{TAG}-agent", "--file", ROOT / "tests/docker/Agent.Dockerfile",
                   "--build-arg", f"RIFT_IMAGE={TAG}", ROOT / "tests/docker", timeout=900, capture=False)
            # Network namespace is explicit and isolated. No host networking or published ports.
            docker("network", "create", "--ipv6", "--subnet", "198.18.90.0/24",
                   "--gateway", "198.18.90.1", "--subnet", "2001:db8:90::/64",
                   "--gateway", "2001:db8:90::1", NET)
            common = ["--network", NET, "--cap-drop", "ALL", "--cap-add", "NET_ADMIN",
                      "--sysctl", "net.ipv4.ip_forward=1",
                      "--sysctl", "net.ipv6.conf.all.forwarding=1",
                      "--sysctl", "net.ipv4.conf.default.rp_filter=2",
                      "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                      "--tmpfs", "/run:rw,noexec,nosuid,size=4m"]
            docker("run", "-d", "--name", VPS, *common,
                   "--ip", VPS4, "--ip6", VPS6,
                   "--mount", f"type=bind,src={vps_cfg},dst=/etc/rift/config.toml,readonly",
                   "--mount", f"type=volume,src={TAG}-vps-state,dst=/var/lib/rift",
                   "--env", "RIFT_PUBLIC_ENDPOINT=rift-vps", "--env", f"RIFT_PUBLIC_IPS={IPS}",
                   "--env", "RIFT_ENROLLMENT_BIND=0.0.0.0:8443", "--env", "RIFT_ENROLLMENT=always",
                   "--network-alias", "rift-vps", TAG,
                   "--config", "/etc/rift/config.toml", "server")
            docker("run", "-d", "--name", CLIENT, "--network", NET, "--ip", CLIENT4,
                   "--ip6", CLIENT6, "python:3.13-slim", "sleep", "infinity", timeout=180)

            vps_command = ["rift", "--config", "/etc/rift/config.toml", "--json", "status"]
            wait_for("server admin socket", lambda: docker("exec", VPS, *vps_command, check=False).returncode == 0)
            invite = json.loads(exec_cli("agents", "add", "core", "--ttl", "15m").stdout)
            docker("run", "-d", "--name", AGENT, *common,
                   "--ip", AGENT4, "--ip6", AGENT6,
                   "--mount", f"type=bind,src={agent_cfg},dst=/etc/rift/config.toml,readonly",
                   "--mount", f"type=volume,src={TAG}-agent-state,dst=/var/lib/rift",
                   "--env", "RIFT_SERVER=rift-vps:8443", "--env", "RIFT_AGENT_NAME=core",
                   "--env", f"RIFT_ENROLLMENT_TOKEN={invite['token']}",
                   "--entrypoint", "/usr/local/sbin/rift-agent-entrypoint", f"{TAG}-agent",
                   "--config", "/etc/rift/config.toml", "agent")
            ready = wait_for("agent to be active", lambda: next((a for a in
                json.loads(exec_cli("status").stdout)["snapshot"]["agents"]
                if a["name"] == "core" and a["status"] == "active"), None))
            tunnel4, tunnel6 = ready["tunnel_ipv4"], ready["tunnel_ipv6"]
            docker("exec", "-d", AGENT, "sh", "-c",
                   'exec python3 /usr/local/libexec/rift-echo.py "$1" "$2" >> /tmp/rift-echo.log 2>&1',
                   "rift-echo", tunnel4, tunnel6)
            wait_for("agent v4/v6 TCP/UDP echo listeners",
                     lambda: agent_echo_sockets_ready(tunnel4, tunnel6))
            forwards = [(VPS4, 18080, "tcp"), (VPS4, 18081, "udp"),
                        (VPS6, 18082, "tcp"), (VPS6, 18083, "udp")]
            for ip, port, proto in forwards:
                exec_cli("forwards", "add", "--agent", "core", "--listen-ip", ip,
                         "--listen", str(port), "--target", "19080" if proto == "tcp" else "19081",
                         "--protocol", proto)
            def applied():
                state = json.loads(exec_cli("status").stdout)
                snap = state["snapshot"]
                active = next((a for a in snap["agents"] if a["name"] == "core"), None)
                fully_applied = (state.get("fully_applied") is True
                                 and not state.get("pending_forwards")
                                 and state.get("apply_error") is None)
                return active if fully_applied and active and active["applied_generation"] >= snap["generation"] else None
            wait_for("agent forwarding policy", applied)

            cases = [("4", "tcp", CLIENT4, VPS4, 18080),
                     ("4", "udp", CLIENT4, VPS4, 18081),
                     ("6", "tcp", CLIENT6, VPS6, 18082),
                     ("6", "udp", CLIENT6, VPS6, 18083)]
            for family, proto, source, destination, port in cases:
                got = client_probe(family, proto, source, destination, port)
                if got != source:
                    raise RuntimeError(f"{family}/{proto}: agent observed {got}, expected client source {source}")
                print(f"PASS Docker bridge {family}/{proto}: WireGuard reply reached original client source {got}")
            print("PASS bridge datapath over real WireGuard; no host networking or published ports")
        except Exception:
            print_container_diagnostics()
            raise
        finally:
            for name in (AGENT, VPS, CLIENT):
                docker("rm", "--force", name, check=False)
            docker("network", "rm", NET, check=False)
            for volume in (f"{TAG}-vps-state", f"{TAG}-agent-state"):
                docker("volume", "rm", volume, check=False)
            docker("image", "rm", f"{TAG}-agent", TAG, check=False)


if __name__ == "__main__":
    main()
