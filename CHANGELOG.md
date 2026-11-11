# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/); while the major version is 0, a minor version may change configuration, state or the agent protocol. Use the same version on the server and every agent.

## [Unreleased]

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
