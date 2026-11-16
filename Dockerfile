# syntax=docker/dockerfile:1
FROM rust:1-bookworm AS build
WORKDIR /src

# BuildKit builds this stage for the requested target platform (amd64/arm64).
# Keeping the Rust and C toolchains out of the runtime image limits its size.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates iproute2 iptables nftables wireguard-tools \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0700 /var/lib/rift /etc/rift
COPY --from=build /src/target/release/rift /usr/local/bin/rift
# Licenses of RIFT and of everything it ships with; see NOTICE.
COPY LICENSE NOTICE THIRD_PARTY_LICENSES.md /usr/share/doc/rift/
RUN dpkg-query -W -f='${binary:Package} ${Version} source: ${source:Package} ${source:Version}\n' \
      > /usr/share/doc/rift/debian-packages.txt
USER 0:0
WORKDIR /
HEALTHCHECK --interval=30s --timeout=20s --start-period=90s --retries=3 \
  CMD /usr/local/bin/rift --config /etc/rift/config.toml status >/dev/null 2>&1 || exit 1
ENTRYPOINT ["/usr/local/bin/rift"]
