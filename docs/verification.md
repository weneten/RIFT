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

1. A registered device completes a handshake with the server and reaches the granted agent address (`--server`).
2. A key that is not registered gets no handshake; a registered device cannot reach another agent, a non-granted port, or a subnet without a grant.
3. A device with only `--server` cannot reach any LAN host; with `--subnet` it can, with and without `--snat` (and with a static route on the LAN router for the non-NAT case).
4. Two devices cannot reach each other; a device cannot reach the server's tunnel address or control port.
5. `peer revoke`, `peer disable` and `deny` cut established and new flows immediately.
6. Server and agent restarts restore the same access; a failed apply leaves public forwards working.
7. Existing public forwards behave as before, with the home router still closed to inbound connections.
8. UFW with `host_firewall = "auto"`: device traffic works and unrelated drops remain.

## Release gates

Run the configured Linux and Docker jobs, review failures and archive their results. Before production acceptance, additionally exercise full host reboots, startup-interruption fault injection, existing management SSH and the intended host-firewall/Docker-backend combination. Collect iperf3 measurements against ordinary WireGuard on representative hardware. No throughput, downtime or production-safety benchmark is claimed in this repository.
