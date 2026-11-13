#!/usr/bin/env python3
"""Docker test: the site configuration `rift add site` writes, run by the real proxies.

For Traefik 3, Traefik 2, Caddy and Nginx it renders a site with the helper's own functions,
starts the proxy next to a small backend on a throwaway Docker network and sends requests from
the host. The proxy sees the network's gateway as the client, so a list naming the gateway must
answer 200 from the backend, a list naming someone else 403, and no list 200.

Nginx Proxy Manager is not started. The "npm" case runs its proxy host layout in plain Nginx:
the helper's `advanced_config` at server level, NPM's ACME challenge location (which says
`allow all`) and `location /`. The challenge path must stay reachable for every list.
"""
import http.client
import importlib.machinery
import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader("rift_site", str(ROOT / "deploy/vps/rift-site"))
spec = importlib.util.spec_from_loader("rift_site", loader)
rift_site = importlib.util.module_from_spec(spec)
loader.exec_module(rift_site)

PID = os.getpid()
NETWORK = f"rift-site-test-{PID}"
SUBNET = "172.30.99.0/24"
GATEWAY = "172.30.99.1"
HOST = "app.example.net"
BACKEND = f"rift-site-backend-{PID}"
BACKEND_URL = "http://backend:8000"
BODY = "rift-backend-ok"
IMAGES = {
    "nginx": "nginx:1.27-alpine",
    "caddy": "caddy:2.8-alpine",
    "traefik3": "traefik:v3.3",
    "traefik2": "traefik:v2.11",
    "backend": "python:3.12-alpine",
}
CONTAINERS = []


def docker(*args, check=True, timeout=120):
    result = subprocess.run(["docker", *args], text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"docker {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def start(name, image, mounts, command=(), alias=None):
    args = ["run", "-d", "--name", name, "--network", NETWORK]
    if alias:
        args += ["--network-alias", alias]
    for source, target in mounts:
        args += ["-v", f"{source}:{target}:ro"]
    docker(*args, image, *command)
    CONTAINERS.append(name)
    return docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)


def stop(name):
    docker("rm", "-f", name, check=False)
    if name in CONTAINERS:
        CONTAINERS.remove(name)


TOKEN = "rift-acme-token"


def status_of(address, path="/"):
    """HTTP status for HOST on the proxy's port 80, or None while it is not ready."""
    try:
        connection = http.client.HTTPConnection(address, 80, timeout=3)
        connection.request("GET", path, headers={"Host": HOST})
        response = connection.getresponse()
        body = response.read().decode(errors="replace")
        return response.status, body
    except OSError:
        return None


def expect(address, wanted, label, timeout=40, path="/", body=BODY):
    """Waits for the expected answer; a proxy may still be loading its configuration."""
    deadline = time.monotonic() + timeout
    seen = None
    while time.monotonic() < deadline:
        seen = status_of(address, path)
        if seen and seen[0] == wanted and (wanted != 200 or body in seen[1]):
            print(f"PASS {label}: {wanted}")
            return
        time.sleep(1)
    raise AssertionError(f"{label}: expected {wanted}, got {seen[0] if seen else 'no answer'}")


def nginx(work, allow):
    conf = work / "nginx.conf"
    conf.write_text(rift_site.render_nginx(HOST, BACKEND_URL, allow), encoding="utf-8")
    return IMAGES["nginx"], [(conf, "/etc/nginx/conf.d/default.conf")], ()


def npm(work, allow):
    """Nginx Proxy Manager's proxy host template, reduced to what decides access."""
    payload = rift_site.npm_host_payload(HOST, "backend", 8000, 0, allow)
    acme = work / "acme" / ".well-known" / "acme-challenge"
    acme.mkdir(parents=True)
    (acme / "token").write_text(TOKEN, encoding="utf-8")
    conf = work / "npm.conf"
    conf.write_text(
        "server {\n"
        "  listen 80;\n"
        f"  server_name {HOST};\n"
        f"{payload['advanced_config']}\n"
        "  location ^~ /.well-known/acme-challenge/ {\n"
        "    auth_basic off;\n"
        "    allow all;\n"
        "    default_type \"text/plain\";\n"
        "    root /data/letsencrypt-acme-challenge;\n"
        "  }\n"
        "  location / {\n"
        f"    proxy_pass {payload['forward_scheme']}://{payload['forward_host']}:{payload['forward_port']};\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    mounts = [(conf, "/etc/nginx/conf.d/default.conf"), (work / "acme", "/data/letsencrypt-acme-challenge")]
    return IMAGES["nginx"], mounts, ()


def caddy(work, allow):
    text = rift_site.render_caddy(HOST, BACKEND_URL, allow)
    # The helper writes a bare domain, which makes Caddy redirect port 80 to HTTPS. The test
    # serves plain HTTP so the matcher is reached without a certificate.
    assert text.startswith(f"{HOST} {{")
    conf = work / "Caddyfile"
    conf.write_text(f"http://{text}", encoding="utf-8")
    return IMAGES["caddy"], [(conf, "/etc/caddy/Caddyfile")], ()


def traefik(major):
    def build(work, allow):
        dynamic = work / "dynamic"
        dynamic.mkdir(exist_ok=True)
        (dynamic / f"{HOST}.yml").write_text(
            rift_site.render_traefik(HOST, BACKEND_URL, "le", "web", "websecure", allow, major),
            encoding="utf-8",
        )
        command = (
            "--entrypoints.web.address=:80",
            "--entrypoints.websecure.address=:443",
            "--providers.file.directory=/dynamic",
            "--providers.file.watch=true",
            "--certificatesresolvers.le.acme.storage=/tmp/acme.json",
            "--certificatesresolvers.le.acme.httpchallenge.entrypoint=web",
            "--certificatesresolvers.le.acme.email=test@example.net",
            # No certificate is ever obtained here; requests use the plain HTTP router.
            "--certificatesresolvers.le.acme.caserver=https://127.0.0.1:1/directory",
        )
        return IMAGES[f"traefik{major}"], [(dynamic, "/dynamic")], command

    return build


def main():
    if shutil.which("docker") is None:
        raise SystemExit("docker is required")
    for image in IMAGES.values():
        if docker("image", "inspect", image, check=False) == "":
            docker("pull", "-q", image, timeout=300)
    work = pathlib.Path(tempfile.mkdtemp(prefix="rift-site-test-"))
    docker("network", "create", "--subnet", SUBNET, "--gateway", GATEWAY, NETWORK)
    try:
        (work / "index.html").write_text(BODY, encoding="utf-8")
        start(BACKEND, IMAGES["backend"], [(work, "/srv")],
              ("python", "-m", "http.server", "8000", "--directory", "/srv"), alias="backend")
        cases = {
            "nginx": nginx,
            "npm": npm,
            "caddy": caddy,
            "traefik v3": traefik(3),
            "traefik v2": traefik(2),
        }
        lists = (
            ("no list", [], 200),
            ("gateway allowed", rift_site.parse_allow_from([f"{GATEWAY}, 2001:db8::/48"]), 200),
            ("gateway not allowed", rift_site.parse_allow_from(["192.0.2.0/24", "198.51.100.7"]), 403),
        )
        for proxy, build in cases.items():
            for label, allow, wanted in lists:
                case_dir = work / f"{proxy.replace(' ', '-')}-{label.replace(' ', '-')}"
                case_dir.mkdir()
                image, mounts, command = build(case_dir, allow)
                name = f"rift-site-proxy-{PID}"
                address = start(name, image, mounts, command)
                try:
                    expect(address, wanted, f"{proxy}, {label}")
                    if proxy == "npm":
                        expect(address, 200, f"npm, {label}, ACME challenge",
                               path="/.well-known/acme-challenge/token", body=TOKEN)
                except AssertionError:
                    print(docker("logs", "--tail", "40", name, check=False), file=sys.stderr)
                    raise
                finally:
                    stop(name)
        print("PASS the site configuration of every proxy lets the allowed client through and refuses the others")
    finally:
        for name in list(CONTAINERS):
            stop(name)
        docker("network", "rm", NETWORK, check=False)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
