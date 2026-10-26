# RIFT — Rust Internet Forwarding Tunnel

RIFT is a Rust WireGuard forwarding service with a VPS server and enrolled agents. The deployment examples target Docker Engine on Linux and use host networking; this repository documentation does not claim production-host validation. Docker Desktop on Windows/macOS can build images, but its host-network behavior is not the Linux VPS datapath.

Read [the architecture and security boundaries](docs/architecture.md) and [the recorded verification status](docs/verification.md) before deployment. Source code, comments, CLI commands, diagnostics and documentation use English.

## Linux host requirements

- A 64-bit Linux VPS and Docker Engine with Compose v2.
- A Linux kernel with WireGuard support and `iproute2`; verify the actual kernel with `ip link add ... type wireguard` in a disposable network namespace. The WireGuard module is a host-kernel feature; it is not installed by the container image.
- Inspect the current forwarding sysctls, routes, policy rules, and firewall before deployment.
- The current RIFT dataplane requires both `net.ipv4.ip_forward=1` and `net.ipv6.conf.all.forwarding=1`; RIFT reads but does not change these host-wide sysctls. New `rift0` interfaces need loose IPv4 reverse-path filtering (`net.ipv4.conf.default.rp_filter=2`) when the kernel/container cannot set the interface value itself. Avoid disabling reverse-path filtering globally. If the IPv6 uplink uses router advertisements, review its `accept_ra` behavior after enabling forwarding.
- Cloud firewall/security-group and host firewall rules that permit inbound TCP 8443 for enrollment and UDP 51820 for WireGuard. TCP 8444 is the control service and should remain reachable only through the WireGuard interface; do not expose it publicly.
- A public DNS name or IP address for the VPS. `RIFT_PUBLIC_ENDPOINT` excludes the WireGuard port; the server configuration's `wg_port` defaults to 51820.

RIFT requires `CAP_NET_ADMIN` to configure interfaces and routes. The supplied Compose files use host networking, so this capability affects the VPS network namespace. Run the first deployment in a disposable Linux VM, review `docker compose config`, and keep an independent SSH session available. The service does not need `--privileged`, `SYS_ADMIN`, or `NET_RAW` in the supplied configuration. Do not use a global firewall flush or edit Docker-managed chains as part of setup or cleanup.

## Configure and start the VPS server

From the repository root, copy `.env.example` to `.env`, then set `RIFT_PUBLIC_ENDPOINT` to the VPS DNS name or address (without a port) and `RIFT_PUBLIC_IPS` to the comma-separated public addresses the server should use. Keep `.env` private; it contains enrollment material after an agent invitation is created.

Review the mounted settings in `deploy/vps/config.toml`, then validate and start:

```sh
docker compose --env-file .env -f deploy/vps/compose.yml config
docker compose --env-file .env -f deploy/vps/compose.yml up -d --build
docker compose --env-file .env -f deploy/vps/compose.yml logs -f
```

If all TLS paths are omitted, the server generates a local CA and a server certificate using the hostname or IP in `RIFT_PUBLIC_ENDPOINT`, and stores the private material in the persistent `/var/lib/rift` volume. The invitation bundles the CA trust anchor and one-time secret for agent enrollment. A deployment with externally managed certificates can set all three `tls_cert`, `tls_key`, and `tls_ca` paths in the VPS TOML config; mount those files read-only and keep the CA file matched to the server certificate.

In production, a deployment copy may live elsewhere if the same relative layout is preserved: `.env` at the project root and the Compose file at `deploy/vps/compose.yml`. The config file is mounted read-only at `/etc/rift/config.toml`; persistent identity and state live in the named `rift-state` volume mounted at `/var/lib/rift`.

## Enroll an agent

On the VPS, create a short-lived invitation. Copy the printed invitation value directly into the agent's private `.env` file:

```sh
docker compose --env-file .env -f deploy/vps/compose.yml exec rift-server \
  rift --config /etc/rift/config.toml agents add core --ttl 15m
```

Set `RIFT_SERVER` to `hostname:8443`, `RIFT_AGENT_NAME` to the chosen agent name, and `RIFT_ENROLLMENT_TOKEN` to the invitation value in the agent host's `.env`. The invitation bundles a one-time secret and the server TLS trust anchor. `RIFT_SERVER` includes the enrollment port; `RIFT_PUBLIC_ENDPOINT` does not. Keep the token secret and remove it from `.env` after successful enrollment. The agent connects over TLS, then establishes the WireGuard tunnel.

Start the agent from the repository root on its Linux host:

```sh
docker compose --env-file .env -f deploy/agent/compose.yml config --quiet
docker compose --env-file .env -f deploy/agent/compose.yml up -d --build
docker compose --env-file .env -f deploy/agent/compose.yml logs -f
```

Each VPS/agent host should have its own deployment `.env`, Compose project, and persistent state volume. For a third-party agent, use the documented enrollment flow and least privilege; do not share the VPS state volume.

## CLI

The daemon commands use the mounted config path:

```sh
rift --config /etc/rift/config.toml server
rift --config /etc/rift/config.toml agent
```

Administrative commands such as `rift status` and `rift agents add NAME --ttl 15m` connect to the local state/admin socket. Run them in the server container or on the host with the same config path and access to its state volume. Use `rift --help` for the command list supported by the built version.

## Build

Build a local image for the current platform:

```sh
docker build -t rift:local .
```

Build amd64 and arm64 images with Buildx:

```sh
docker buildx build --platform linux/amd64,linux/arm64 --output type=oci,dest=rift-images.tar .
```

The OCI archive contains both target architectures. To publish a multi-platform manifest, use a configured registry and an explicit registry tag with `--push`.

## Development and integration checks

See [docs/deploy.md](docs/deploy.md) for the preflight, firewall coexistence, rollback, and performance procedure. [tests/netns/run.sh](tests/netns/run.sh) is a Linux-only integration harness intended to exercise real network namespaces and WireGuard; it requires root, kernel WireGuard, RIFT binaries, and Linux networking tools. Docker integration tests cover both an isolated bridged deployment and Docker-published ports used by a host-network agent. CI is configured to run formatting, linting, unit tests, the namespace harness, and these Docker tests. Those workflows have not been run from this Windows host. Performance results must be collected on the target class of VPS and must not be inferred from CI.
