# RIFT — Rust Internet Forwarding Tunnel

RIFT connects a public-facing **server** to one or more **agents** through WireGuard. It publishes selected TCP and UDP ports from the server to services reachable on an agent's tunnel address. A server or agent can be a physical machine, virtual machine, or another suitable Linux host; the names describe their roles, not where they run.

```text
Client ── TCP / UDP ──> RIFT server ── WireGuard ──> RIFT agent ──> service
                         public address                target port
```

The agent initiates the connection to the server. RIFT manages the tunnel, explicit forwarding grants and the necessary Linux networking rules. A separate reverse proxy can terminate HTTPS and route domain names to HTTP services through RIFT.

> The examples use Linux Docker Engine with host networking. Host networking and `CAP_NET_ADMIN` let RIFT change the host's networking. Test the deployment and firewall interaction on a disposable system before production. Docker Desktop on Windows or macOS is useful for builds, but does not reproduce this Linux host-network datapath. See [verification status](docs/verification.md) for what has actually been tested.

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Install the server](#install-the-server)
- [Connect an agent](#connect-an-agent)
- [Supported protocols](#supported-protocols)
- [Publish services](#publish-services)
- [Publish websites with HTTPS](#publish-websites-with-https)
- [Manage agents and forwards](#manage-agents-and-forwards)
- [Configuration](#configuration)
- [Operations and troubleshooting](#operations-and-troubleshooting)
- [Build and development](#build-and-development)
- [Further documentation](#further-documentation)

## How it works

- **Server:** receives public traffic, manages invitations and assigns forwards to agents. It needs a reachable endpoint and an address configured on its network interface for each published listener.
- **Agent:** connects to the server and receives only the grants assigned to it. The destination is the agent's own tunnel IPv4 or IPv6 address and the configured target port, not an arbitrary address elsewhere on its network.
- **Transparent forwarding:** the default for matching address families; the service can see the original client IP. The service must accept traffic addressed to the agent's tunnel address. A Docker service may instead publish its port on the agent host.
- **Translation:** explicitly bridges IPv4 and IPv6 using a userspace forwarder. The service sees the server's tunnel address instead of the original client address; the server logs the original address.

For example, `--listen 2222 --target 22 --protocol tcp` publishes TCP port 2222 on the server to TCP port 22 on the chosen agent. A forward does not install, configure or secure the destination application.

## Requirements

On both machines:

- 64-bit Linux with a kernel capable of creating WireGuard interfaces, Docker Engine, Docker Compose v2 and Git. The published image targets `linux/amd64` and `linux/arm64`.
- Administrative access to prepare the host and run Docker. The Compose service uses host networking and `NET_ADMIN`.
- Non-overlapping RIFT address pools and reserved routing table, rule priority and packet marks. Review existing routes, firewall rules and Docker networking before deployment.

On the server:

- A DNS name or IP address reachable by the agent for enrollment and WireGuard. The public address used in forwards must actually be assigned to a server network interface; a DNS name is not valid for `RIFT_PUBLIC_IPS`. A network that only supplies an externally NATed address without assigning it to the server interface (typical for Oracle Cloud, AWS and Google Cloud) needs `RIFT_ALLOW_PRIVATE_LISTENERS=true` and the private interface address in `RIFT_PUBLIC_IPS`; see the configuration table below. That setup follows from the code and unit tests but has not been verified on a real NAT cloud.
- Allow incoming UDP **51820** for WireGuard and TCP **8443** for enrollment, plus each public TCP or UDP service port you choose. Adjust upstream firewall/security-group rules as well as the host firewall. TCP **8444** is tunnel control and must not be exposed publicly.
- For a website, a DNS record for its domain and an existing supported reverse proxy listening on TCP 443. Certificate issuance may also require TCP 80.

The agent needs outbound connectivity to the server's enrollment and WireGuard ports. The application must listen on the agent tunnel address, for example `0.0.0.0` for IPv4, or be published through Docker on the agent host. Binding only to `127.0.0.1` is insufficient for a direct tunnel destination.

## Install the server

Run the following on **each** Linux machine that will run RIFT:

```sh
git clone https://github.com/weneten/RIFT.git
cd RIFT
sudo sh deploy/prepare-host
```

The preparation script checks WireGuard and installs persistent forwarding and reverse-path filtering settings in `/etc/sysctl.d/99-rift.conf`. These are host-wide settings; review [the deployment preflight](docs/deploy.md#preflight-before-changing-host-networking), including IPv6 router advertisement implications, before running it.

On the **server**, create the configuration:

```sh
cp deploy/vps/config.toml config.toml
cp .env.server.example .env
chmod 600 .env
```

Edit `.env`, replacing the example values with real ones:

```dotenv
COMPOSE_PROFILES=server
RIFT_PUBLIC_ENDPOINT=rift.example.net
RIFT_PUBLIC_IPS=203.0.113.10
```

`rift.example.net` must resolve to the server endpoint. The example IP is a documentation placeholder: replace it with the actual address assigned to the server interface. `RIFT_PUBLIC_ENDPOINT` has no scheme or port and is also used as the enrollment certificate name. `RIFT_PUBLIC_IPS` may contain comma-separated addresses. Keep `COMPOSE_PROFILES=server`.

Start and check the server:

```sh
docker compose pull
docker compose up -d
docker logs -f rift-server
```

Wait for `RIFT server ready`, then leave the log view with Ctrl+C. On the **server**, install the host CLI from the checkout:

```sh
sudo sh deploy/vps/install-cli
```

This installs `/usr/local/bin/rift` and the site helper under `/usr/local/lib/rift`. It replaces any existing files at those paths. The command runs on the server and forwards administrative arguments to the `rift-server` Docker container; it requires Docker access (use `sudo rift ...` if your user cannot access Docker). `sudo rift site ...` runs the host-side proxy helper and requires Python 3 and administrator access. Ensure `/usr/local/bin` is in your PATH, including sudo's PATH. The original `docker exec rift-server rift --config /etc/rift/config.toml ...` remains available.

Check the server with:

```sh
rift status
```

By default RIFT creates its own enrollment CA and certificate in the persistent `rift-state` volume. This certificate is for agent enrollment, not your website's HTTPS certificate. Keep the volume and its backups private.

## Connect an agent

On the **server**, create a short-lived, single-use invitation. Choose a unique name for each agent:

```sh
rift agents add node1 --ttl 15m
```

The output contains `RIFT_SERVER`, `RIFT_AGENT_NAME` and `RIFT_ENROLLMENT_TOKEN`. Treat the token as a secret and transfer all three lines securely to the agent.

On the **agent**, from its own checkout:

```sh
cp deploy/agent/config.toml config.toml
cp .env.agent.example .env
chmod 600 .env
```

Edit `.env`: keep `COMPOSE_PROFILES=agent` and replace the three invitation values with the exact output. `RIFT_SERVER` includes the enrollment port. Start the agent:

```sh
docker compose pull
docker compose up -d
docker logs -f rift-agent
```

On the **server**, verify that the agent becomes `active`:

```sh
rift agents list
rift status
```

Once active, remove the token line from the agent's `.env`; preserve its state volume for reconnection. If the invitation expires or is lost, cancel it and create another on the server. Repeat this process with a different name for every additional agent.

## Supported protocols

RIFT offers exactly two transport protocols for published forwards: **TCP** and **UDP**. The `--protocol` option accepts `tcp` or `udp` and defaults to `tcp`. Both are available for IPv4 and IPv6, in transparent mode and in cross-family translation mode. A separate forward is required for each transport and public IP/port combination.

Application protocols use those transports; RIFT forwards their traffic without installing the application, interpreting its protocol, or automatically discovering additional ports. Examples are illustrative, not a claim that every application has been individually tested:

| Application protocol or service | Transport to forward | Notes |
| --- | --- | --- |
| HTTP, HTTPS, WebSocket, SSH and SFTP | TCP | HTTPS may terminate at the application or at a reverse proxy. SSH and SFTP require their own authentication and host-key verification. |
| DNS | UDP and TCP | Create both grants when clients need both transports. Configure and secure the DNS server separately. |
| QUIC and HTTP/3 | UDP | The application or proxy must support and configure QUIC/HTTP/3 itself; traditional HTTP/HTTPS also commonly needs TCP. |
| Game, voice and other custom services | TCP, UDP, or both | Consult the application's documentation for every port, transport and advertised address it requires. |

ICMP/ICMPv6, SCTP, GRE, ESP and other non-TCP/UDP IP protocols cannot be published as RIFT port forwards. In particular, `ping` is not a test of a TCP or UDP forward. RIFT's own WireGuard tunnel uses UDP; its enrollment protocol uses TLS over TCP, and its control channel runs inside the tunnel. These are RIFT's internal connections, not additional values accepted by `--protocol`.

Protocols that negotiate additional ports or embed addresses, such as FTP in some configurations, require application-specific setup and explicit forwards for each required port. RIFT does not automatically rewrite application payloads or open ports. Validate such services with their real clients.

## Publish services

Run administrative commands on the **server**. The following examples use `node1` and assume one address in `RIFT_PUBLIC_IPS`. Replace ports with those used by your services. With multiple configured addresses, add `--listen-ip` with the desired address to every `forwards add` command.

`forwards add` also has a short form: `rift forwards add AGENT SPEC...`, where each `SPEC` is `LISTEN[:TARGET][/tcp|/udp|/both]`. The target defaults to the listen port and the protocol to `tcp`; `both` creates a TCP and a UDP forward. Ranges such as `5000-5002` work. For example, `rift forwards add node1 53/both 8080:80` replaces the two long `--agent … --protocol …` commands for port 53 plus a forward from 8080 to 80. Options such as `--listen-ip`, `--ingress` and `--mode` still apply to every forward of the command. The short form cannot be mixed with `--agent`, `--listen`, `--target` or `--protocol`. If a later forward of one command fails, the earlier ones stay created.

### TCP example

Publish an SSH service listening on the agent's port 22 as server port 2222:

```sh
rift forwards add \
  --agent node1 --listen 2222 --target 22 --protocol tcp
```

Allow TCP 2222 in the relevant upstream firewall. From a separate client, test `ssh -p 2222 USER@rift.example.net` and verify the SSH host key through a trusted channel. Configure authentication and access controls in the SSH service itself.

### UDP example

Publish a UDP service on agent port 27015 as server port 27015:

```sh
rift forwards add \
  --agent node1 --listen 27015 --target 27015 --protocol udp
```

Allow UDP 27015 upstream and test with the application's own client. UDP and TCP are separate grants: if an application requires both, add one forward for each protocol and allow both in the firewall.

### DNS example: TCP and UDP

If a DNS server on the agent is configured to listen on port 53 for both transports, publish both using two independent grants:

```sh
rift forwards add \
  --agent node1 --listen 53 --target 53 --protocol udp
rift forwards add \
  --agent node1 --listen 53 --target 53 --protocol tcp
```

Allow both TCP and UDP 53 in the upstream firewall and use a DNS client to test both modes against the server address. Ensure neither port conflicts with existing services, and configure the DNS server's access controls before exposing it.

### Port ranges and addresses

Ranges use `start-end`; both ranges must have the same length and contain at most 4096 ports. Corresponding ports map in order:

```sh
rift forwards add \
  --agent node1 --listen 30000-30002 --target 40000-40002 --protocol udp
```

For multiple server addresses, explicitly select a configured address, for example `--listen-ip 203.0.113.10`. Replace it with an actual assigned address. The default is `--mode transparent --ingress public`, and the target family defaults to the listener's IP family. Check the created ID and apply status:

```sh
rift forwards list
rift status
```

A grant may remain pending while the agent applies it. Test from a separate client after it is active; a successful command alone does not prove firewall or application reachability.

### IPv4-to-IPv6 and IPv6-to-IPv4

Translation requires different listener and target families and must be requested explicitly. For example, an IPv4 listener forwarding to the agent's IPv6 tunnel address:

```sh
rift forwards add \
  --agent node1 --listen-ip 203.0.113.10 --listen 8080 --target 8080 \
  --protocol tcp --mode translate --target-family v6
```

Replace the listener with your configured IPv4 address and ensure the application listens on the agent's IPv6 tunnel address. For the opposite direction, use a configured IPv6 `--listen-ip` and `--target-family v4`. Translation runs in userspace and changes the source address visible to the destination. `--ingress local` is supported only for transparent forwards.

## Publish websites with HTTPS

RIFT forwards ports; a reverse proxy provides hostname routing and HTTPS. The installed `rift site` command uses the repository’s `deploy/vps/rift-site` helper to configure an **existing** Traefik, Caddy or Nginx proxy. The directory name is historical: the server can run on any suitable Linux host.

### Example: a new Caddy proxy in Docker

This example starts a separate Caddy container on the server and uses a manually created local-ingress forward. It requires Docker bridge networking, a free TCP 80 and 443 on the server, a reachable public IPv4 address assigned to its interface, and an HTTP service on `node1` port 8081. Replace the example domain and IP throughout. Configure the domain's A record and allow TCP 80 and 443 through all relevant firewalls before starting Caddy. Use a real domain for automatic certificate issuance.

First create the forward on the **server**:

```sh
rift forwards add \
  --agent node1 --listen 20000 --target 8081 --protocol tcp --ingress local
```

If the server has multiple configured addresses, add `--listen-ip` with the desired IPv4 address. Port 20000 must be available; choose another if needed. Do not open it publicly. Then create a separate proxy project on the server:

```sh
mkdir -p caddy
cat > caddy/Caddyfile <<'EOF'
app.example.net {
    reverse_proxy 203.0.113.10:20000
}
EOF
cat > caddy/compose.yml <<'EOF'
services:
  caddy:
    image: caddy:2
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config
volumes:
  caddy-data:
  caddy-config:
EOF
docker compose -f caddy/compose.yml up -d
docker compose -f caddy/compose.yml logs -f
```

Replace `203.0.113.10` in the Caddyfile with the same actual interface address used by the forward. Caddy's Docker bridge traffic must enter the host through a non-public interface so the local-ingress rule can match it. Confirm this path and any host firewall rules on your system. After Caddy obtains its certificate, test `https://app.example.net` externally. For another site, create another local-ingress forward on a different unused port and add another domain block to the Caddyfile; restart the Caddy Compose service after editing it. Keep Caddy's data volume for certificate persistence. To remove a site, remove its block, restart Caddy, then remove the corresponding forward by ID.

### Using the `rift site` helper

### Prepare the website and proxy

1. Start the HTTP application on the agent, for example on port `8081`, listening on its tunnel address or on `0.0.0.0`. If it runs in Docker, publish the port on the agent host. Confirm the application itself works before adding RIFT.
2. Create an A or AAAA DNS record for `app.example.net` pointing to the server's reachable address. Replace all example names with your own.
3. Set up one supported proxy on the server and confirm it owns TCP 443. Open TCP 443 and, if required for certificates, TCP 80. Configure certificate issuance for your domain.
4. Ensure the proxy can reach the server public address through an interface other than the public-address NIC, such as a Docker bridge. The helper creates a `local` ingress forward which matches packets entering on such an interface; a host-local connection that bypasses prerouting is not equivalent. Verify the actual packet path for your proxy setup.

The helper assumes particular proxy layouts: Traefik uses a watched file provider, entrypoints `web` and `websecure`, and certificate resolver `myresolver`; Caddy and Nginx must load the generated site directories (`/etc/caddy/rift-sites` and `/etc/nginx/rift-sites`). Adapt your proxy configuration to those paths and reload commands. The helper stores its settings and site records in `/var/lib/rift-site/sites.json`. It expects exactly one configured server public address. Inspect the helper and back up proxy configuration before using it on an existing installation.

### Add a site

On the **server**, from the checkout, choose the proxy that already owns port 443:

```sh
sudo rift site add node1 app.example.net 8081 --proxy traefik
```

Alternatively, use `--proxy caddy`, `--proxy nginx` or `--proxy npm` (Nginx Proxy Manager) with the corresponding existing proxy. The helper allocates a port in `20000-20999`, creates a local-ingress TCP forward and writes a proxy configuration. The allocated port is for the proxy path and should not be opened publicly. Test `https://app.example.net` from an external client and check the proxy certificate and application response.

Traefik uses its configured certificate resolver. The first add may migrate a recognized single-file Traefik provider to a watched directory, or add a watched file provider (`--providers.file.directory=/dynamic`, plus a volume for `<compose project>/dynamic`) to a Traefik that only uses Docker labels; it edits the Compose file (keeping a `.rift-bak` copy) and recreates the Traefik service, so expect a short interruption. Existing Docker-label routes remain. This needs Traefik to run from a Compose file with the container name `traefik` and a list-style `command:` and `volumes:`. Caddy obtains certificates through its configuration. For Nginx, the helper invokes `certbot --nginx` if available; without it the site is written but TLS is not requested, so configure a certificate separately. For Nginx and Nginx Proxy Manager, `RIFT_REQUEST_CERTIFICATE` in the server `.env` controls certificates: `true` (default) requests a Let's Encrypt certificate for each new site, which means accepting the Let's Encrypt terms of service (certbot is run with `--agree-tos`); `false` skips it and you handle TLS yourself. The optional `RIFT_LETSENCRYPT_EMAIL=you@example.net` is the contact for expiry notices. Without it certbot registers without an email, and Nginx Proxy Manager, which requires one, uses the admin login address. Traefik and Caddy ignore both settings. HTTP traffic between proxy and agent is carried inside WireGuard.

Nginx Proxy Manager is configured through its API at `http://127.0.0.1:81` (change `npm.url` in `/var/lib/rift-site/sites.json` if needed). Put an NPM admin login and the Let's Encrypt address in the server `.env` (already `chmod 600`) and recreate the server container with `docker compose up -d --force-recreate`:

```sh
RIFT_NPM_EMAIL=admin@example.net
RIFT_NPM_PASSWORD=...
# Optional, see above. Certificate requests are on by default and force HTTPS.
RIFT_LETSENCRYPT_EMAIL=admin@example.net
```

The helper reads these values from the running server container, which Compose fills from `.env`; they are visible to root through `docker inspect`. They also work as environment variables of the `rift site` call or in `/etc/rift/site.env`. With `RIFT_REQUEST_CERTIFICATE=false` the proxy host is created without TLS and you request a certificate in the NPM UI. `rift site remove` deletes the proxy host again, and its certificate too when that was issued for this domain alone and no other host, redirection, 404 host or stream uses it; shared and wildcard certificates are kept.

To remove a site and its forward:

```sh
sudo rift site remove app.example.net
```

`sudo rift site list` shows the sites the helper manages with their forward ID and whether that forward still exists. On the server, `rift forwards list` (the installed CLI) adds a SITE column with the domain and proxy of each forward that `rift site` created; `rift --json forwards list` and the command inside the container are unchanged. Manage these forwards only through `rift site`: if you delete one with `rift forwards remove`, `list` shows it as `missing` and running `rift site add` for the same site creates it again.

To inspect or change the helper's default proxy:

```sh
sudo rift site proxy
sudo rift site proxy caddy
```

For a custom reverse proxy, create a transparent TCP forward with `--ingress local` and configure the proxy to connect to the server address and allocated port via an appropriate incoming interface. Local ingress excludes packets arriving on a NIC that owns a configured public address; it is not a general-purpose loopback listener. See [architecture](docs/architecture.md#transparent-packet-path).

## Manage agents and forwards

All commands in this section run on the server. IDs are returned by `forwards list` and `forwards add`; replace `1` with the actual ID.

```sh
# Inspect agents and their state
rift agents list
rift agents show node1

# Temporarily disable or re-enable an agent
rift agents disable node1
rift agents enable node1

# Remove an agent, or cancel a pending invitation
rift agents remove node1
rift agents cancel-invite node1

# Inspect, disable, enable or remove a forward
rift forwards list
rift forwards disable --id 1
rift forwards enable --id 1
rift forwards remove --id 1
```

`agents rename` and `agents rotate` are also available; inspect `rift agents --help` and the relevant subcommand's help before using them. For translated forwards, `bans add --agent NAME --forward-id ID --ip ADDRESS --ttl 1h` blocks an original client address temporarily; `bans list` shows bans. Bans expire by TTL; there is no explicit remove command. Use `--json` for machine-readable administrative output and `rift --help` for the full CLI.

Forwards are shown as a compact table, including the ID used for removal, agent, listener, target port, ingress and state. Agent names are resolved when available; an ID is shown if they cannot be retrieved. For example:

```text
ID  AGENT  PROTO  LISTEN                  TARGET  FAMILY  INGRESS  MODE         STATE
5   node1  TCP    203.0.113.10:25001     5201    v4      local    transparent  enabled
```

Normal commands print concise status and confirmations. Use `rift --json status`, `rift --json forwards list`, or `rift --json doctor` for complete machine-readable data. The `--json` format is also used by the site helper and integration tools.

## Configuration

`config.toml` contains static settings; `.env` supplies the Compose profile and the documented environment overrides. Compose reads the project `.env` automatically. Agents, invitations and forwards are stored in the persistent state volume rather than in TOML.

| Setting | Default / role | Purpose |
| --- | --- | --- |
| `RIFT_PUBLIC_ENDPOINT` | Server | Reachable DNS name or IP, without port; enrollment certificate identity. |
| `RIFT_PUBLIC_IPS` | Server | Comma-separated addresses assigned to server interfaces for listeners. |
| `RIFT_ENROLLMENT_BIND` | `0.0.0.0:8443` | Enrollment listener. |
| `RIFT_ENROLLMENT_ENABLED` | `true` | Enables enrollment. |
| `RIFT_ALLOW_PRIVATE_LISTENERS` | `false` | Server. Set `true` behind a cloud NAT (e.g. Oracle Cloud), where the public address is not assigned to the interface: put the private interface address in `RIFT_PUBLIC_IPS`, keep the public DNS name in `RIFT_PUBLIC_ENDPOINT`, and open the ports in the cloud's firewall. Allows private and ULA listener addresses; loopback, link-local, multicast and unspecified stay forbidden, as does an address inside a tunnel pool. |
| `RIFT_WG_PORT` | `51820` | Server. WireGuard UDP port; use another one if 51820 is taken on the host. Restart required. |
| `RIFT_IPV4_POOL`, `RIFT_SERVER_IPV4` | `10.13.0.0/24`, `10.13.0.1` | Server. Override the IPv4 tunnel pool if it overlaps a host network (the default avoids Podman's 10.88.0.0/16, Docker's 172.16/12 and common WireGuard 10.8.0.0/24). The server address must be inside the pool; restart required. |
| `RIFT_IPV6_POOL`, `RIFT_SERVER_IPV6` | `fd88:5249:4654::/64`, `fd88:5249:4654::1` | Server. Same for IPv6 (ULA pool). |
| `RIFT_SERVER`, `RIFT_AGENT_NAME`, `RIFT_ENROLLMENT_TOKEN` | Agent | Invitation values; remove token after enrollment. |
| `interface`, `wg_port`, `control_port` | `rift0`, `51820`, `8444` | WireGuard interface and ports. |
| `ipv4_pool`, `ipv6_pool` | `10.13.0.0/24`, `fd88:5249:4654::/64` | Tunnel address pools; avoid overlaps. |
| `route_table`, `rule_priority`, `mark`, `mark_mask` | See example TOML | Reserved routing and packet-mark resources. |
| `mtu`, `host_firewall` | `1380`, `auto` | Tunnel MTU and UFW integration. |

`host_firewall = "auto"` adds RIFT-owned UFW chain jumps when UFW user chains exist; it does not configure upstream firewalls or override unrelated firewall drops. With another firewall or `host_firewall = "off"`, configure the required input and forwarding paths yourself. TCP 8444 is for tunnel control only. See [deployment preflight](docs/deploy.md#preflight-before-changing-host-networking) for details.

For external enrollment TLS material, configure `tls_cert`, `tls_key` and `tls_ca` together in TOML and mount all files read-only into the container at those paths. Without them, RIFT generates its own CA and certificate; the automatic certificate is valid for one year, so plan certificate maintenance before future enrollments. Consult [architecture and security](docs/architecture.md) for trust and recovery details.

Validate the effective configuration and inspect prerequisites in the relevant running container:

```sh
rift config validate
rift doctor
```

`reload` reconciles supported mutable settings. Changes to interface, pools, routing reservations, listener ports or TLS identity require a restart. See `src/config.rs` for the full validated configuration and defaults.

## Operations and troubleshooting

### Logs and health

```sh
docker compose ps
docker logs --tail 100 rift-server
docker logs --tail 100 rift-agent
rift status
rift logs --lines 100
```

Run the container-specific log command on the machine hosting that role.

- **Agent is not active:** check the invitation name, token and expiry; server readiness; DNS; TCP 8443 and UDP 51820 reachability; and both container logs. Enrollment checks the certificate name and CA.
- **Forward exists but traffic fails:** inspect `status` for pending or failed application; verify the correct agent, IP, port and protocol; check upstream and host firewall rules; and verify the service listens on the appropriate tunnel address or published host port. Test from a separate client.
- **Website fails:** check DNS, TCP 80/443, which proxy owns 443, certificate issuance, proxy configuration and logs, and the local-ingress packet path. Ensure the agent application serves HTTP on the configured port.
- **Conflicting routes or firewall:** review existing interfaces, pools, routing table, priorities and marks. RIFT refuses conflicting ownership; do not flush unrelated rules to make it start.

### Updates, persistence and recovery

To update the published image, on each host from its own checkout:

```sh
git pull
docker compose pull
docker compose up -d
docker compose ps
```

On the server, run `sudo sh deploy/vps/install-cli` again after `git pull` to update the installed CLI and site helper. Check logs, agent status and representative services after the update. Review configuration changes before replacing your local `config.toml` or `.env`.

The `rift-state` volume contains identities, keys, certificates and dynamic configuration. Protect and back up the state on **both** server and agent, and test restoration. A normal `docker compose down` asks RIFT to remove its owned networking configuration; a subsequent `docker compose up -d` recreates it from the retained volume. A crash, forced kill or cleanup error can leave network state behind; inspect the logs and use the ownership-aware recovery procedure in [docs/deploy.md](docs/deploy.md#rollout-and-rollback). `docker compose down -v` and volume pruning can delete the state; agents and invitations cannot be recovered merely by restarting. Host-wide sysctl settings installed by `deploy/prepare-host` remain in place.

### Uninstall

Stop the containers, then remove the host-side parts (installed CLI, site helper, `/etc/sysctl.d/99-rift.conf`, and any network objects a crash left behind):

```bash
docker compose down
sudo sh deploy/uninstall-host
```

The state volume (CA, keys, agents, forwards) is kept so a later install can reconnect. Add `--purge` to delete the volume and the image as well. The live forwarding sysctls, `.env`, `config.toml` and proxy configuration written by `rift site` are not touched; the script prints what remains.

## Build and development

The root Compose file pulls `weneten/rift:latest`. To build and use the local source instead, use `deploy/vps/compose.yml` on the server or `deploy/agent/compose.yml` on the agent, with the matching `.env` and configuration; inspect the rendered configuration before starting. To build an image directly:

```sh
docker build -t rift:local .
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

The Linux network-namespace and Docker integration harnesses require disposable Linux systems and elevated privileges. They change networking and must not be run on a production host. Their prerequisites, test scope and limitations are documented in [docs/deploy.md](docs/deploy.md#functional-test-matrix).

## Further documentation

- [Architecture and security boundaries](docs/architecture.md): packet paths, enrollment, translation, state and recovery.
- [Deployment and verification](docs/deploy.md): preflight, firewall coexistence, rollout, rollback, integration tests and performance procedure.
- [Recorded verification status](docs/verification.md): executed checks and outstanding release gates.
