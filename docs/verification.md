# Verification status

Recorded on 2026-10-26. Prepared test coverage is separate from executed evidence.

## Executed successfully

- Rust stable 1.99.1, native Windows MSVC build.
- `cargo fmt --all -- --check`.
- `cargo clippy --all-targets -- -D warnings`.
- `cargo test --all-targets`: 35 tests, no failures or ignored tests (30 library, 3 CLI, 2 TLS integration tests).
- Real IPv4-to-IPv6 TCP and IPv6-to-IPv4 UDP loopback translation, including translated-forward ban checks.
- Real TLS loopback transport: valid DNS/IP SANs accepted; wrong CA, wrong hostname and expired certificate rejected before enrollment data is decoded.
- Enrollment-state reservation, replay, expiry, cancellation, key rotation, duplicate/overlapping grants, generation acknowledgments and persisted apply-failure tests.
- Recovery of automatic TLS material from the committed bundle after missing derived files; conflicting files preserved.
- Missing IPv4/IPv6 FIB tables are treated as empty during initial routing ownership checks and agent route installation; other command failures and partial dumps remain errors.
- Agent route ownership accepts the numeric `RTN_UNREACHABLE` output from `ip -N` and compares interface names and metrics as complete fields.
- Linux x86_64 source/type checking and strict Clippy through the Zig cross toolchain, including Linux-only Unix-socket code. This is not a Linux runtime test or a linked Linux release artifact.
- Both supplied Compose files pass `docker compose config --quiet`; an already-enrolled agent can omit its token.
- All Python integration harnesses pass syntax compilation. Code/comments/commands/documentation were checked for unintended German text.
- GitHub Actions Linux namespace suite passed on Ubuntu 24.04 with real kernel WireGuard and three concurrently enrolled agents: transparent IPv4/IPv6 TCP/UDP, original client addresses, foreign firewall/policy-rule preservation, Fail2ban-style bans, translated-forward bans, endpoint/DNS changes, NAT port changes, saved-policy recovery, disabled/removed agents, wrong-CA rejection, consumed-token replay rejection, and server crash/restart. Evidence: [CI run 40350188780, job 121671110496](https://github.com/weneten/RIFT/actions/runs/40350188780/job/121671110496), commit `050d01f`.

The local test process needed permission to use loopback sockets outside the Windows sandbox. A complete Linux link was attempted, but the Windows Zig linker wrapper failed on path/argument quoting in this workspace. That host-tooling failure does not supply a Linux build result; the Docker and Linux CI builds remain the authoritative build checks.

## Pending runtime verification

- Isolated Docker bridge WireGuard path and real Docker-published backend ports with a host-network agent.
- SFTP IPv4/IPv6 upload/download, hash comparison, strict SSH host-key verification and original-address log checks.
- HTTPS through Traefik v3 with a trusted test certificate and original-address JSON access logs.
- Multiarchitecture amd64/arm64 OCI image build workflow.

These require disposable Linux runners with the documented kernel features. Docker Desktop's engine was not available on this workstation. GitHub Actions has executed the Rust checks, Linux release builds, and full namespace suite successfully. Docker and application runtime verification remains pending. No service was deployed to a VPS from this session.

## Private VPN access: not yet verified on a kernel

The `rift vpn` feature has unit coverage only: rule rendering and ordering, state validation, rollback filtering, CLI parsing, client configuration and address allocation. No Linux runtime test has been executed for it. Before relying on it, exercise on a disposable runner with real WireGuard and nftables:

1. A registered device completes a handshake with the server and reaches the granted agent address (`server`).
2. A key that is not registered gets no handshake; a registered device cannot reach another agent, a non-granted port, or a subnet without a grant.
3. A device with only `server` cannot reach any LAN host; with a network grant it can, with and without `--snat` (and with a static route on the LAN router for the non-NAT case).
4. Two devices cannot reach each other; a device cannot reach the server's tunnel address or control port.
5. `rift remove device`, `rift disable device` and `rift vpn deny` cut established and new flows immediately.
6. Server and agent restarts restore the same access; a failed apply leaves public forwards working.
7. Existing public forwards behave as before, with the home router still closed to inbound connections.
8. UFW with `host_firewall = "auto"`: device traffic works and unrelated drops remain.

## Internet exit: unit-tested only

The internet exit (devices with `internet via server` or `internet via AGENT`) has unit coverage only: allocation of the device IPv6 address and the reserved gateway, CLI parsing of `internet`, client configurations for no exit, the server and an agent (AllowedIPs, DNS families, MTU, endpoint port, error text before the agent reported a key), server nftables (masquerade, IPv6 masquerade versus explicit drop, order before the final drops, exclusion of the pools), agent nftables (masquerade, private-range block with the allowed-subnet exception in front, IPv6 dropped without a global address, always-present lockdown), the agent's refusal and the implied exit port, creation, port assignment and removal of the managed exit forward and its protection from `remove forward`/`disable forward`, UFW plans, and the panel action needing a trusted connection. No Linux runtime test has been executed. On a disposable VPS and a disposable agent with real WireGuard and nftables:

1. Exit through the VPS: handshake, `curl https://ifconfig.me` shows the VPS address; `ping -6` and a site that needs IPv6 work only if `RIFT_PUBLIC_IPS` has an IPv6 address, otherwise IPv6 fails and nothing leaks; DNS goes through `RIFT_VPN_DNS`; the device cannot reach another device, the VPS's control port or `169.254.169.254`.
2. Exit through an agent with `RIFT_AGENT_ALLOW_EXIT=true`: `rift-exit` exists with the right peers, `rift list forwards` shows the `exit` forward on the first IPv4/IPv6 address, the phone gets a handshake with the agent, shows the agent's home address and cannot reach the home LAN (but can reach a network listed in `RIFT_AGENT_ALLOW_SUBNETS`) or services on the agent host; MTU 1300 passes full-size packets in both directions (`ping -M do -s 1272`).
3. An agent host without global IPv6: the device's IPv6 does not work and does not leak. An agent with `RIFT_AGENT_ALLOW_EXIT=false`: `rift vpn allow DEVICE AGENT internet` warns, the device shows `refused by agent`, no forward is published.
4. `rift vpn deny`, `rift disable device` and `rift remove device` remove the forward (when no other device uses it), the peer on `rift-exit` and, after the last device, the interface; a server and agent restart restores the same state.
5. With UFW: `rift:exit` rules appear and disappear on both sides, and unrelated drops stay.
6. Re-import of a configuration after each change, and test-ipv6.com on the device.

## Web panel: not yet verified on a kernel

The web panel has unit coverage (configuration parsing, source checks, read/write separation, proxy headers, nft and UFW rule rendering, client AllowedIPs, HTTP parsing limits, login, session, CSRF header, action list, short-form forwards, password file mode, and two-factor login against the RFC 6238 test vectors: window, replay, lockout, required mode; this is unit-tested only, with no real authenticator app) and was driven in headless Chromium against a fake backend (login, invitation, forwards, devices with QR code, grants, cancel, log, diagnostics, read-only view behind a proxy header, light/dark, 390 px width, no CSP violations). It has not run inside a real server container. Before relying on it, check on a disposable server:

1. `RIFT_WEBPANEL=true` with `private`: the panel answers on `127.0.0.1` and through `ssh -L`, but not on the public address.
2. `rift panel connect` yields a working WireGuard configuration; the device opens `http://10.13.0.1:8090` but still cannot reach the control port, other devices or ungranted agents; `rift panel deny`, `rift disable device` and `rift remove device` cut it off.
3. An agent or a device without the panel flag cannot connect to the panel port.
4. `public` with and without `RIFT_WEBPANEL_ALLOW`, with UFW active and with `host_firewall = "off"`.
5. Changes from a public address, an allow-listed address and loopback behind a reverse proxy are refused; from loopback and a panel device they work, including an invitation, a forward, a device with QR code and a grant.

## Enrollment port in `auto` mode: not yet verified on a kernel

Unit tests cover the configuration parsing; the listener lifecycle has not run in a container. Check that 8443 is closed at start without invitations, opens with `rift add agent` and with an invitation from the panel, stays open until the agent is active, and closes after activation, `rift remove invite`, agent removal and expiry (within about 10 s). With UFW, RIFT's `rift:enrollment` rule should appear and disappear with it. `RIFT_ENROLLMENT=always` keeps it open; `off` refuses invitations.

## Export, import, backup and restore: unit-tested only

Unit tests cover the pure planning of an import (agent mapping and filters, unknown and inactive agents, duplicate and overlapping forwards, listen-address replacement, devices with flags and grants, subnets behind two agents, format check), the repair of forwards on addresses the server lacks, the agent endpoint choice, the report layout, CLI parsing, and the host helper (site planning, archive layout and validation, volume lookup, restore sequence with mocked Docker). The state backup runs `tar` and SQLite for real in a test (WAL database with an open writer, socket excluded, mode 0600). Nothing has been run against a real Docker volume or a second VPS. Before relying on it, on disposable machines:

1. `sudo rift backup` on a server with agents, forwards, a VPN device and a site; the archive lists `server/state.db`, the key files and `host/rift-site/sites.json`, and `rift backup` runs while the server serves traffic.
2. On a second server with a different `RIFT_PUBLIC_IPS`: `docker compose up -d`, then `sudo rift restore`. Agents reconnect after DNS or `RIFT_SERVER` changes, VPN devices still connect with their old configuration, forwards moved to the new address work, and the site's proxy configuration exists again.
3. `rift export` and `rift import` into a reinstalled server with re-enrolled agents, with and without `--map`, `--skip-agent` and `--dry-run`; a port in use is reported without stopping the rest.
4. A restore interrupted halfway leaves `rift-server` stopped and a second `rift restore` succeeds.

## Agent allowlists: unit-tested only

`RIFT_AGENT_ALLOW_PORTS` and `RIFT_AGENT_ALLOW_SUBNETS` are covered by unit tests of parsing and of the policy filter; no container or kernel test has run. Check on a disposable agent that a refused forward stays pending, that a network grant is refused until the network is listed, and that both appear in `rift status`.

## Release gates

Run the configured Linux and Docker jobs, review failures and archive their results. Before production acceptance, additionally exercise full host reboots, startup-interruption fault injection, existing management SSH and the intended host-firewall/Docker-backend combination. Collect iperf3 measurements against ordinary WireGuard on representative hardware. No throughput, downtime or production-safety benchmark is claimed in this repository.
