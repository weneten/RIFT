# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/); while the major version is 0, a minor version may change configuration, state or the agent protocol. Use the same version on the server and every agent.

## [Unreleased]

### Added

- Stored state is migrated on update instead of refused. `state.db` has a format number; RIFT copies an older database to `state-before-vN-TIME.db` (mode 0600) in the state volume and migrates it in one transaction. A database from a newer RIFT is refused with a clear message instead of the old advice to delete the volume. RIFT 0.1 state is read as format 1. An agent's `identity.json` has a format number too, and an agent drops a cached policy it cannot read; the server sends it again.

- Names for VPN devices: `rift vpn names agent NAME on` lets every device with a grant on the agent reach it as `NAME.internal`, for example `http://pp.internal:3000`. The name follows the agent, so a new agent under the same name is found again. A small DNS server on the server's tunnel address answers these names only for the agents a device has a grant on, with their IPv4 tunnel address, and passes all other lookups on to the device's DNS agent (`rift vpn dns`) or `RIFT_VPN_DNS`. `rift vpn names device NAME off` keeps a device out. Turning names on or off lists the devices whose main profile changed. In the web panel: "Names on/off" per agent and "Use RIFT's names" per device. `rift list agents` has a DNS NAME column.

- `sudo sh deploy/join SERVER NAME TOKEN` sets up an agent in one step: host preparation, `config.toml` and `.env`, the `rift` command, start, waiting for the server to accept it, and removing the used token from `.env`. `rift add agent` and the web panel's invitation dialog print this command first; the three `.env` lines follow for a manual setup.
- `sudo sh deploy/setup-server` sets up the server in one step. It asks for the public address, the endpoint and the web panel, with the values it detects as defaults (or takes `--endpoint`, `--public-ips`, `--panel`/`--no-panel`, `--yes`), recognises a cloud NAT, then prepares the host, writes the configuration, installs the `rift` command, starts the server and waits until it is ready.
- `rift vpn connect` and the panel's "Connect device" say whether the device must import its configuration again: another port on an agent the device already reaches needs no new configuration, because a configuration routes addresses, not ports.

- `rift vpn connect DEVICE AGENT TARGET... [--export]`: creates the device if it does not exist, grants the targets like `rift vpn allow` and prints the QR code with the addresses to open, for example `rift vpn connect phone node1 3000/tcp`. The web panel's "Add device" dialog is now "Connect device" and does the same. A target that is not valid fails before a device is created.

- `rift add forward ... --allow-from ADDRESS[,NETWORK...]`: only the named clients reach the forward; the server neither redirects nor relays anyone else. Shown in the FROM column of `rift list forwards`, in the web panel, and carried by `rift export` / `rift import`.
- `rift add site ... --allow-from ADDRESS[,NETWORK...]`: the reverse proxy answers other clients with 403 (Traefik `ipAllowList`/`ipWhiteList`, Caddy `remote_ip`, Nginx and Nginx Proxy Manager `allow`/`deny`). Also in the web panel's site dialog, the site queue and export files.

### Changed

- `rift add ban FORWARD_ID IP [--ttl 1h]` no longer takes the agent: a forward ID belongs to exactly one agent, which RIFT now looks up itself. The old form `rift add ban AGENT FORWARD_ID IP` is gone. A ban on a transparent forward says why it cannot work and what to use instead.
- `deploy/prepare-host` works in LXC containers (for example on Proxmox VE): it recognises the container, checks WireGuard without a network namespace where it may not create one, and says to load the module on the host when it is missing. It also says when the kernel has no IPv6. The README has a section on running RIFT in a Proxmox LXC container.
- `rift vpn config DEVICE [AGENT]` prints the QR code; `--export` prints the configuration file. This is the form of `rift panel connect NAME [--export]`. The old `rift vpn config qr|export ...` answers with the new form. The device names `qr` and `export` are reserved.
- Every change says which devices must import their configuration again: the server compares each device's main profile before and after (a grant on a new agent, names, panel access, an agent removed or disabled, ...) and answers them in `reimport`. The CLI prints `rift vpn config DEVICE` for them; the web panel shows a notice with a QR-code button per device and, in a device's Access dialog, whether the change needs a new import. Before, `rift vpn allow` on a new agent said nothing, and the panel claimed a DNS change always needed one.
- A grant, DNS server or forward that the agent's own limits (`RIFT_AGENT_ALLOW_*`) refuse is no longer reported as working: `rift vpn allow` printed the refusal and then "DEVICE may now reach AGENT". The message now says it is stored but not reachable until the agent allows it; `rift vpn connect` and the panel's "Connect device" list such ports apart.
- `rift remove site DOMAIN` says what it removed (proxy configuration, forward and agent) instead of printing nothing. The web panel shows the same text.
- `rift list bans` shows the expiry as a UTC date and time instead of Unix seconds (`--json` is unchanged).
- `rift vpn deny` no longer accepts `--snat`, which had no effect there.
- `rift add site --help`, `rift proxy --help` and the help of the other host commands show the full help text instead of a short usage error. `rift restore --help` lists `--no-safety-backup`.
- The Docker image contains the licenses of RIFT, of the Rust crates in the binary (`THIRD_PARTY_LICENSES.md`) and a list of its Debian packages with their source versions, under `/usr/share/doc/rift/`; see `NOTICE`.

### Tests

- The namespace suite (`tests/netns/run.py`) also checks agent isolation, forwarding after a server crash, daemons killed in the middle of their start, a server behind a simulated 1:1 cloud NAT, an expired invitation and that no token or private key appears in logs, command output or state files. Unit tests check expired invitations and that the invitation secret is not stored.

### Fixed

- A server or agent killed between creating its WireGuard interface and tagging it as its own could not start again until the interface was deleted by hand ("ip link JSON did not return the interface alias"). The next start now tags the interface, but only while RIFT's ownership marker is still pending and the interface is untouched (no key, no peers). Found by the new interrupted-start test.
- An agent checks that IPv4 and IPv6 forwarding are enabled before it enrolls. Before, a host without forwarding reserved the invitation and then stopped, and an agent without a persistent volume could not use that invitation again.

## [0.1.0]

First pre-release. Not yet recommended for production; see the open release gates in [docs/deploy.md](docs/deploy.md#functional-test-matrix).

### Added

- Server and agent connected through WireGuard, with single-use, TLS-pinned agent enrollment (`rift add agent`).
- TCP and UDP forwards from the server's public addresses to an agent: transparent (keeps the client address) or translated between IPv4 and IPv6.
- Time-limited client bans on translated forwards (`rift add ban`).
- HTTPS sites through an existing Traefik, Caddy, Nginx or Nginx Proxy Manager (`rift add site`).
- Private VPN devices with per-port, per-host and per-network grants, QR or file export, DNS through an agent, and internet exits through the server or an agent.
- Web panel reachable over the VPN, with password and optional two-factor login.
- `rift backup` and `rift restore` for the server state.
- Host scripts: `deploy/prepare-host`, `deploy/install-cli`, `deploy/uninstall-host`.
- Docker image for `linux/amd64` and `linux/arm64`; a `vX.Y.Z` tag publishes `weneten/rift:X.Y.Z`, and `RIFT_VERSION` in `.env` pins it.

[Unreleased]: https://github.com/weneten/RIFT/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/weneten/RIFT/releases/tag/v0.1.0
