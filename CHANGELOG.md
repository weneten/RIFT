# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/). Within a major version, configuration settings keep their meaning, stored state is migrated on update (after a copy of the old state is kept), and a server serves agents of its own and of the previous release. Update the server first, then the agents.

## [Unreleased]

## [1.0.0]

First release. RIFT publishes services of home servers behind NAT or CGNAT through a VPS: the home server (agent) dials the VPS (server) over WireGuard, and the server forwards public ports to it or lets private VPN devices reach it. See the [README](https://github.com/weneten/RIFT/blob/v1.0.0/README.md) for setup and the [test matrix](https://github.com/weneten/RIFT/blob/v1.0.0/docs/deploy.md#functional-test-matrix) for what is tested and what is not.

### Setup

- `sudo sh deploy/setup-server` sets up the server in one step: it asks for the public address, the endpoint agents dial and the web panel (with detected defaults, or `--endpoint`, `--public-ips`, `--panel`/`--no-panel`, `--yes`), recognises a cloud NAT, prepares the host, writes the configuration, installs the `rift` command and waits until the server is ready.
- `rift add agent NAME` creates a single-use, expiring, TLS-pinned invitation and prints `sudo sh deploy/join SERVER NAME TOKEN`, which sets up the agent in one step and removes the used token from `.env` afterwards. Inviting an existing name again moves the agent to a reinstalled host and keeps its addresses, forwards and grants.
- Host scripts: `deploy/prepare-host` (sysctls, WireGuard check; also in Proxmox LXC containers), `deploy/install-cli`, `deploy/uninstall-host`, and `deploy/field-check`, which collects a report without secrets about a host and checks that RIFT comes back alone after a reboot.
- Docker image for `linux/amd64` and `linux/arm64`; `RIFT_VERSION` in `.env` pins a release. The image contains the licenses of RIFT, of the Rust crates in the binary and a list of its Debian packages (see `NOTICE`).

### Forwards and sites

- TCP and UDP forwards from the server's public addresses to an agent (`rift add forward`): transparent, so the service sees the client's own address, or translated between IPv4 and IPv6.
- `--allow-from ADDRESS[,NETWORK...]` limits a forward to the named clients.
- Time-limited client bans on translated forwards: `rift add ban FORWARD_ID IP [--ttl 1h]`.
- HTTPS sites through Traefik, Caddy, Nginx or Nginx Proxy Manager on the VPS (`rift add site`), optionally limited with `--allow-from`. `sudo sh deploy/setup-proxy traefik|caddy|npm` sets up Traefik, Caddy or Nginx Proxy Manager in Docker the way `rift add site` expects it, on any distribution, and `deploy/setup-server` offers it. With `--migrate` it switches from one of them to another: it stops the old one, sets up the new one and moves every site (the forwards stay), or starts the old one again if the new one cannot be set up. Caddy in a container is reloaded there (`rift proxy caddy --container NAME --sites-dir DIR`). A proxy installed on the VPS itself, such as Caddy or Nginx from the distribution, reaches local-ingress forwards too. `rift remove site` says what it removed; `rift list forwards` shows which site a forward belongs to.

### Private VPN access

- VPN devices that reach chosen ports, hosts or networks behind an agent without a public port: `rift vpn connect DEVICE AGENT TARGET...` creates the device, grants the targets and prints the QR code; `rift vpn allow`/`deny` change grants later.
- Every change says which devices must import their configuration again; another port on an agent a device already reaches needs none. A grant that the agent's own limits (`RIFT_AGENT_ALLOW_*`) refuse is reported as stored but not reachable.
- DNS through an agent (`rift vpn dns`) and internet exits through the server or an agent.
- Names: `rift vpn names agent NAME on` lets every device with a grant on the agent reach it as `NAME.internal`. The server answers these names only for agents a device has a grant on and passes other lookups to the device's DNS agent, with the device's address as EDNS Client Subnet, or to `RIFT_VPN_DNS`. `rift vpn names device NAME off` keeps a device out.

### Operation

- Web panel with password and optional two-factor login, reachable over the VPN (`rift panel connect`) or, behind a TLS proxy, publicly; a public panel takes the password over HTTPS only. For networks that block WireGuard's UDP, `sudo sh deploy/publish-panel DOMAIN` puts the panel behind the proxy of `deploy/setup-proxy` at `https://DOMAIN` and allows changes there (`RIFT_WEBPANEL_CONTROL=public`); the panel port stays off the internet. Two-factor login is strongly advised then; without it the server and the panel warn. It manages agents, forwards, sites, bans, VPN devices, exits and names, exports and imports settings (with a preview before anything changes) and downloads a backup after asking for the password and code again; restore stays on the CLI.
- `rift status`, `rift doctor`, `rift list ...` and `--json` output; `rift list agents` shows each agent's RIFT version and `rift status` names agents older than the server.
- `rift backup` and `rift restore` for the server state; `rift export` and `rift import` move forwards, sites, devices, grants and names to another server. The web panel offers export, import and backup through the same code on the host.
- Stored state and the agent identity carry a format number and are migrated on update, after a copy of the old state is kept; state from a newer RIFT is refused. State written by builds before 1.0 is migrated as well.
- The agent's own limits (`RIFT_AGENT_ALLOW_PORTS`, `RIFT_AGENT_ALLOW_SUBNETS`, `RIFT_AGENT_ALLOW_EXIT`) bound what the server can open on it.
- Security reports go through GitHub's private vulnerability reporting (`SECURITY.md`).

[Unreleased]: https://github.com/weneten/RIFT/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/weneten/RIFT/releases/tag/v1.0.0
