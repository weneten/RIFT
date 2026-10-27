# RIFT — Rust Internet Forwarding Tunnel

RIFT is a Rust WireGuard forwarding service with a VPS server and enrolled agents. The deployment examples target Docker Engine on Linux and use host networking; this repository documentation does not claim production-host validation. Docker Desktop on Windows/macOS can build images, but its host-network behavior is not the Linux VPS datapath.

Read [the architecture and security boundaries](docs/architecture.md) and [the recorded verification status](docs/verification.md) before deployment. Source code, comments, CLI commands, diagnostics and documentation use English.

## Start

Use a 64-bit Linux host with Docker Engine and Compose v2. Open UDP `51820` and TCP `8443` in the VPS cloud firewall. Leave TCP `8444` closed on the public interface. Point a DNS name at the VPS address.

On the VPS and on the home server:

```sh
git clone https://github.com/weneten/RIFT.git
cd RIFT
git pull
sudo sh deploy/prepare-host
```

`prepare-host` writes `/etc/sysctl.d/99-rift.conf` and checks that the kernel can create a WireGuard interface. Run it once per machine. RIFT does not change those sysctls itself.

On the VPS, copy the server config and the env file. The copied `config.toml` is complete. The address, the DNS name, and the role are only in `.env`.

```sh
cp deploy/vps/config.toml config.toml
cp .env.example .env
```

Edit `.env` before starting. Set `RIFT_ROLE=server`. `RIFT_PUBLIC_ENDPOINT` is the DNS name agents and the certificate use, without a port. `RIFT_PUBLIC_IPS` is the address configured on the VPS network interface. Packets arrive on that address, so a DNS name is not valid there. Compose reads `.env` in the project directory by itself, so the start commands do not pass `--env-file`.

Start the server only after that edit:

```sh
docker compose pull
docker compose up -d
```

Wait until `docker logs rift-server` prints `RIFT server ready`. The admin socket is not listening before that line. Then create the invitation:

```sh
docker exec rift-server rift --config /etc/rift/config.toml agents add core --ttl 15m
```

Copy the printed `RIFT_SERVER`, `RIFT_AGENT_NAME`, and `RIFT_ENROLLMENT_TOKEN` lines into the home server's `.env`. The token is a one-time secret. Remove it from `.env` after the agent is active.

On the home server, copy the agent config and the env file. That config is complete too. The invitation values go only in `.env`.

```sh
cp deploy/agent/config.toml config.toml
cp .env.example .env
```

Edit `.env` and set `RIFT_ROLE=agent`, plus the three lines from the invitation. Start the agent only after that edit:

```sh
docker compose pull
docker compose up -d
```

Check the tunnel from the VPS. The agent is ready when its status is `active`.

```sh
docker exec rift-server rift --config /etc/rift/config.toml status
```

The home service must listen on `0.0.0.0` or the agent tunnel address. To publish it as HTTPS, run this from the repository on the VPS. The proxy that already owns port 443 must be Traefik, Caddy, or Nginx. DNS for the new name points at the same VPS address.

```sh
deploy/vps/rift-site add core app.example.net 8081 --proxy traefik
deploy/vps/rift-site rm app.example.net
```

The first Traefik add switches Traefik's file provider to a watched directory and recreates that container. Existing Docker-label routes stay in place.

With TLS paths omitted, the server generates a local CA and certificate for `RIFT_PUBLIC_ENDPOINT` and stores them in the `rift-state` volume. `host_firewall` defaults to `auto`, so a UFW host opens enrollment, WireGuard, and the `rift0` forward path without a rule per published port. The cloud firewall still needs UDP `51820`, TCP `8443`, and any public listen port. The Compose service uses host networking and `CAP_NET_ADMIN`. It does not need `--privileged`. Keep `.env` private.

`deploy/vps/compose.yml` and `deploy/agent/compose.yml` build `rift:local` from this repository instead of pulling `weneten/rift:latest`. Use those files when the published image is not the one you want to run.

## CLI

The daemon commands use the mounted config path:

```sh
rift --config /etc/rift/config.toml server
rift --config /etc/rift/config.toml agent
```

Administrative commands such as `rift status` and `rift agents add NAME --ttl 15m` connect to the local state/admin socket. Run them in the server container or on the host with the same config path and access to its state volume. Use `rift --help` for the command list supported by the built version.

`rift forwards add` accepts `--ingress public` (the default) or `--ingress local`. Local ingress publishes the port to interfaces other than the public NIC, which is the path used by a reverse proxy on the same VPS. `deploy/vps/rift-site` turns one home port into an HTTPS name on the proxy that already listens on port 443. See [deploy.md](docs/deploy.md).

## Build

Build a local image for the current platform:

```sh
docker build -t rift:local .
```

Pushes to `main` publish `weneten/rift:latest` for `linux/amd64` and `linux/arm64`. The root `docker-compose.yml` runs that image. The steps are in [Start](#start).

## Development and integration checks

See [docs/deploy.md](docs/deploy.md) for the preflight, firewall coexistence, rollback, and performance procedure. [tests/netns/run.sh](tests/netns/run.sh) is a Linux-only integration harness intended to exercise real network namespaces and WireGuard; it requires root, kernel WireGuard, RIFT binaries, and Linux networking tools. Docker integration tests cover both an isolated bridged deployment and Docker-published ports used by a host-network agent. CI is configured to run formatting, linting, unit tests, the namespace harness, and these Docker tests. Those workflows have not been run from this Windows host. Performance results must be collected on the target class of VPS and must not be inferred from CI.
