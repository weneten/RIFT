# Verification status

Recorded on 2026-10-26. Prepared test coverage is separate from executed evidence.

## Executed successfully

- Rust stable 1.99.1, native Windows MSVC build.
- `cargo fmt --all -- --check`.
- `cargo clippy --all-targets -- -D warnings`.
- `cargo test --all-targets`: 32 tests, no failures or ignored tests (27 library, 3 CLI, 2 TLS integration tests).
- Real IPv4-to-IPv6 TCP and IPv6-to-IPv4 UDP loopback translation, including translated-forward ban checks.
- Real TLS loopback transport: valid DNS/IP SANs accepted; wrong CA, wrong hostname and expired certificate rejected before enrollment data is decoded.
- Enrollment-state reservation, replay, expiry, cancellation, key rotation, duplicate/overlapping grants, generation acknowledgments and persisted apply-failure tests.
- Recovery of automatic TLS material from the committed bundle after missing derived files; conflicting files preserved.
- Linux x86_64 source/type checking and strict Clippy through the Zig cross toolchain, including Linux-only Unix-socket code. This is not a Linux runtime test or a linked Linux release artifact.
- Both supplied Compose files pass `docker compose config --quiet`; an already-enrolled agent can omit its token.
- All Python integration harnesses pass syntax compilation. Code/comments/commands/documentation were checked for unintended German text.

The local test process needed permission to use loopback sockets outside the Windows sandbox. A complete Linux link was attempted, but the Windows Zig linker wrapper failed on path/argument quoting in this workspace. That host-tooling failure does not supply a Linux build result; the Docker and Linux CI builds remain the authoritative build checks.

## Prepared, not executed here

- Linux namespace suite with actual WireGuard, three agents, transparent IPv4/IPv6 TCP/UDP, NAT/endpoint changes, saved-policy recovery, service revocation, token replay and foreign firewall preservation.
- Fail2ban-style foreign INPUT/FORWARD bans and translated-forward scoped ban/expiry tests.
- Isolated Docker bridge WireGuard path and real Docker-published backend ports with a host-network agent.
- SFTP IPv4/IPv6 upload/download, hash comparison, strict SSH host-key verification and original-address log checks.
- HTTPS through Traefik v3 with a trusted test certificate and original-address JSON access logs.
- Multiarchitecture amd64/arm64 OCI image build workflow.

These require disposable Linux runners with the documented kernel features. Docker Desktop's engine was not available on this workstation. No CI workflow was pushed or executed from this session, and no service was deployed to a VPS.

## Release gates

Run the configured Linux and Docker jobs, review failures and archive their results. Before production acceptance, additionally exercise full host reboots, startup-interruption fault injection, existing management SSH and the intended host-firewall/Docker-backend combination. Collect iperf3 measurements against ordinary WireGuard on representative hardware. No throughput, downtime or production-safety benchmark is claimed in this repository.
