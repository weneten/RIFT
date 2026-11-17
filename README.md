<p align="center"><img src="docs/logo.svg" alt="RIFT logo" width="96"></p>

# RIFT — Rust Internet Forwarding Tunnel

RIFT connects a public-facing **server** to one or more **agents** through WireGuard. It publishes selected TCP and UDP ports from the server to services reachable on an agent's tunnel address. A server or agent can be a physical machine, virtual machine, or another suitable Linux host; the names describe their roles, not where they run.

```text
Client ── TCP / UDP ──> RIFT server ── WireGuard ──> RIFT agent ──> service
                         public address                target port
```

The agent initiates the connection to the server. RIFT manages the tunnel, explicit forwarding grants and the necessary Linux networking rules. A separate reverse proxy can terminate HTTPS and route domain names to HTTP services through RIFT.

> **Pre-release (0.x).** RIFT changes the host's firewall, routing and sysctls. The namespace test suite covers agent isolation, forwarding after a server crash or an interrupted start, a simulated 1:1 cloud NAT, expired invitations and a scan for plain-text secrets; a deployment on a real NAT cloud, host reboots and performance are still open. See the [functional test matrix](docs/deploy.md#functional-test-matrix). Configuration and state formats may change between 0.x versions. Read the [changelog](CHANGELOG.md) before updating.

> The examples use Linux Docker Engine with host networking. Host networking and `CAP_NET_ADMIN` let RIFT change the host's networking. Test the deployment and firewall interaction on a disposable system before production. Docker Desktop on Windows or macOS is useful for builds, but does not reproduce this Linux host-network datapath.

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Install the server](#install-the-server)
- [Connect an agent](#connect-an-agent)
- [Harden the agent](#harden-the-agent)
- [Run in an LXC container (Proxmox VE)](#run-in-an-lxc-container-proxmox-ve)
- [Supported protocols](#supported-protocols)
- [Publish services](#publish-services)
- [Publish websites with HTTPS](#publish-websites-with-https)
- [Manage agents and forwards](#manage-agents-and-forwards)
- [Private VPN access](#private-vpn-access)
- [Use RIFT as a VPN (exit)](#use-rift-as-a-vpn-exit)
- [Web panel](#web-panel)
- [Back up, move or rebuild](#back-up-move-or-rebuild)
- [Command reference](#command-reference)
- [Configuration](#configuration)
- [Operations and troubleshooting](#operations-and-troubleshooting)
- [Build and development](#build-and-development)
- [Further documentation](#further-documentation)
- [License](#license)

## How it works

- **Server:** receives public traffic, manages invitations and assigns forwards to agents. It needs a reachable endpoint and an address configured on its network interface for each published listener.
- **Agent:** connects to the server and receives only the grants assigned to it. The destination is the agent's own tunnel IPv4 or IPv6 address and the configured target port, not an arbitrary address elsewhere on its network.
- **Transparent forwarding:** the default for matching address families; the service can see the original client IP. The service must accept traffic addressed to the agent's tunnel address. A Docker service may instead publish its port on the agent host.
- **Translation:** explicitly bridges IPv4 and IPv6 using a userspace forwarder. The service sees the server's tunnel address instead of the original client address; the server logs the original address.

For example, `rift add forward node1 2222:22/tcp` publishes TCP port 2222 on the server to TCP port 22 on the chosen agent. A forward does not install, configure or secure the destination application.

## Requirements

On both machines:

- 64-bit Linux with a kernel capable of creating WireGuard interfaces, Docker Engine, Docker Compose v2 and Git. The published image targets `linux/amd64` and `linux/arm64`.
- Administrative access to prepare the host and run Docker. The Compose service uses host networking and `NET_ADMIN`.
- Non-overlapping RIFT address pools and reserved routing table, rule priority and packet marks. Review existing routes, firewall rules and Docker networking before deployment.

On the server:

- A DNS name or IP address reachable by the agent for enrollment and WireGuard. The public address used in forwards must actually be assigned to a server network interface; a DNS name is not valid for `RIFT_PUBLIC_IPS`. A network that only supplies an externally NATed address without assigning it to the server interface (typical for Oracle Cloud, AWS and Google Cloud) needs `RIFT_ALLOW_PRIVATE_LISTENERS=true` and the private interface address in `RIFT_PUBLIC_IPS`; see the configuration table below. The namespace test suite runs this setup behind a simulated 1:1 NAT (enrollment, WireGuard and TCP/UDP forwards with the client's own address); it has not yet been verified on a real cloud provider.
- Allow incoming UDP **51820** for WireGuard and TCP **8443** for enrollment, plus each public TCP or UDP service port you choose. Adjust upstream firewall/security-group rules as well as the host firewall. By default the server only listens on 8443 while an invitation is open (see [Connect an agent](#connect-an-agent)). TCP **8444** is tunnel control and must not be exposed publicly.
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

Install the host command (it reads `COMPOSE_PROFILES` from `.env`, so `.env` must exist first; run it before the first start):

```sh
sudo sh deploy/install-cli
```

This installs `/usr/local/bin/rift`, which runs `rift` inside the `rift-server` container, and replaces any existing file at that path. It requires Docker access (use `sudo rift ...` if your user cannot access Docker). Ensure `/usr/local/bin` is in your PATH, including sudo's PATH. The original `docker exec rift-server rift --config /etc/rift/config.toml ...` remains available. On the server the script also installs the site helper under `/usr/local/lib/rift`, which `sudo rift add site ...` and the other site commands run (they require Python 3 and administrator access). It creates `/var/lib/rift-site` and `/var/lib/rift-site-queue` (mounted into the server container) and enables the systemd path unit `rift-site-queue.path` that lets the web panel add and remove sites.

Start the server:

```sh
docker compose pull
docker compose up -d
docker logs -f rift-server
```

Wait for `RIFT server ready`, then leave the log view with Ctrl+C.

Check the server with:

```sh
rift status
```

By default RIFT creates its own enrollment CA and certificate in the persistent `rift-state` volume. This certificate is for agent enrollment, not your website's HTTPS certificate. Keep the volume and its backups private.

## Connect an agent

On the **server**, create a short-lived, single-use invitation. Choose a unique name for each agent:

```sh
rift add agent node1 --ttl 15m
```

The output contains `RIFT_SERVER`, `RIFT_AGENT_NAME` and `RIFT_ENROLLMENT_TOKEN`. Treat the token as a secret and transfer all three lines securely to the agent.

The enrollment port opens with the invitation. With the default `RIFT_ENROLLMENT=auto` the server listens on TCP 8443 (and RIFT's UFW rule for it exists) only while at least one invitation is open. It closes again as soon as the last agent is active or the last invitation has expired or been cancelled; expiry is noticed within one reconcile interval (10 s). RIFT can only close the port on the server itself: a rule in your cloud firewall or security group stays open, but nothing listens behind it. Set `RIFT_ENROLLMENT=always` to keep the port open permanently, or `off` to turn enrollment off. `rift status` shows the port's state and the open invitations.

On the **agent**, from its own checkout:

```sh
cp deploy/agent/config.toml config.toml
cp .env.agent.example .env
chmod 600 .env
```

Edit `.env`: keep `COMPOSE_PROFILES=agent` and replace the three invitation values with the exact output. `RIFT_SERVER` includes the enrollment port.

Install the host command, as on the server, so `rift status`, `rift doctor` and `rift logs` work here (they run inside `rift-agent`):

```sh
sudo sh deploy/install-cli
```

Start the agent:

```sh
docker compose pull
docker compose up -d
docker logs -f rift-agent
```

Leave the log view with Ctrl+C once it shows no errors; the server confirms the enrollment below.

On the **server**, verify that the agent becomes `active`:

```sh
rift list agents
rift status
```

Once active, remove the token line from the agent's `.env`; preserve its state volume for reconnection. If the invitation expires or is lost, cancel it and create another on the server. Repeat this process with a different name for every additional agent.

## Harden the agent

The server tells each agent which ports to forward and which VPN grants to enforce. The agent applies that blindly unless you cap it. These optional settings in the agent's `.env` do that locally, so even a compromised server cannot open more of your home server or LAN than you allowed:

| Variable | Default | Meaning |
| --- | --- | --- |
| `RIFT_AGENT_ALLOW_PORTS` | empty (no limit) | Comma-separated `PORT` or `PORT-PORT`, each optionally with `/tcp`, `/udp` or `/both` (default both), for example `22/tcp,80,443,27015-27020/udp`. The agent refuses forwards and VPN port grants that are not entirely inside this list. It also refuses `server` and `full` VPN grants, because they reach every port. |
| `RIFT_AGENT_ALLOW_SUBNETS` | empty (no LAN access) | Comma-separated private IPv4 networks behind the agent, for example `192.168.178.0/24`. A VPN network grant works only when its network lies inside one of these, and devices that use the agent as [internet exit](#use-rift-as-a-vpn-exit) may reach them. |
| `RIFT_AGENT_ALLOW_EXIT` | `false` | `true` offers the agent's internet connection as an [exit for VPN devices](#use-rift-as-a-vpn-exit). It also allows the one UDP port of that exit, whatever `RIFT_AGENT_ALLOW_PORTS` says. |

The secure default for subnets is deliberate: until you list a network, no device can reach your LAN through this agent, whatever the server grants. Restart the agent after changing `.env` (`docker compose up -d --force-recreate`).

The agent reports its limits to the server with every sync, so the server knows them too:

- `rift add forward` and `rift vpn allow` (and the web panel) still add an entry outside the limits but warn at once, for example `forward 1 was added, but agent node1 will refuse it: the agent allows only ports 3001,1337,8090 (RIFT_AGENT_ALLOW_PORTS); add 8081/tcp`.
- `rift list forwards` shows such a forward as `refused`, `rift status` names the reason, and `rift list devices` marks refused grants. The server does not publish a refused forward, so no public port opens without a service behind it; other forwards are unaffected. Once you allow the port on the agent, the forward becomes active on the next sync.

The agent still enforces its lists itself, whatever the server sends; the server's view only serves the warnings.

## Run in an LXC container (Proxmox VE)

The server and the agent can also run in an LXC container, for example on Proxmox VE, with Docker inside the container. RIFT then changes only the container's own network, not the host's. This setup follows from how LXC shares the host kernel and has not yet been verified on a real Proxmox host; try it on a spare container first.

On the **Proxmox host**, load the WireGuard module (a container cannot load kernel modules) and keep it loaded after a reboot:

```sh
modprobe wireguard
echo wireguard > /etc/modules-load.d/wireguard.conf
```

Create a Debian 12 container with the features Docker needs, `nesting=1` and `keyctl=1` (Options > Features in the web interface, or `--features nesting=1,keyctl=1` with `pct create` / `pct set`). An unprivileged container is enough. Inside it, install Docker and Git, then follow [Install the server](#install-the-server) or [Connect an agent](#connect-an-agent) as on any host:

```sh
apt update && apt install -y curl git ca-certificates
curl -fsSL https://get.docker.com | sh
git clone https://github.com/weneten/RIFT.git
cd RIFT
sh deploy/prepare-host
```

`deploy/prepare-host` recognises the container. It sets the forwarding sysctls of the container's own network namespace, checks WireGuard without creating a network namespace where an unprivileged container may not, and says what to do on the host when the module is missing or Docker lacks the container features. `rift doctor` in the container then shows the usual checks.

Points specific to LXC:

- **Agent:** a forward reaches services in the same container (for example Docker containers next to RIFT), not services in other containers or VMs; see [How it works](#how-it-works). Other guests on your LAN are reachable only privately, through VPN network grants and `RIFT_AGENT_ALLOW_SUBNETS`.
- **Server:** the public address must be assigned to the container's interface (for example a bridge with its own public IP). If the Proxmox host forwards the ports to a private container address instead, set it up as behind a cloud NAT: `RIFT_ALLOW_PRIVATE_LISTENERS=true` and the container's private address in `RIFT_PUBLIC_IPS`.
- Open UDP 51820 and TCP 8443 (and your forward ports) in the Proxmox firewall as well, if it is enabled for the container.

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

Run administrative commands on the **server**. The following examples use `node1`. Replace ports with those used by your services. A forward listens on the server's first IPv4 address in `RIFT_PUBLIC_IPS`. With an IPv6 address there too, a short-form spec can end in `/v6` (IPv6 only) or `/all` (IPv4 and IPv6, one forward each); `/v4` is the default and may be written out.

`add forward` also has a short form: `rift add forward AGENT SPEC...`, where each `SPEC` is `LISTEN[:TARGET]/tcp`, `/udp` or `/both`, optionally followed by `/v4`, `/v6` or `/all` for the server address. The protocol is always required; `both` creates a TCP and a UDP forward. The target defaults to the listen port. Ranges such as `5000-5002/udp` work. For example, `rift add forward node1 53/both 8080:80/tcp/all` creates TCP and UDP 53 on IPv4 plus 8080 → 80 on IPv4 and IPv6. Options such as `--ingress` and `--mode` still apply to every forward of the command.

Every forward is transparent unless you add `--mode translate`: the service sees the client's real address. For an IPv6 listener the service must therefore accept IPv6 on the agent's tunnel address (listen on `::`; Docker-published ports usually do). If it only listens on IPv4, add `--mode translate`; that runs in userspace and the service sees the server's tunnel address instead of the client's. The server logs the original address, but tools on the agent that block by source address, such as Fail2ban or CrowdSec, can then no longer tell clients apart and would block the server for everyone. Use translation only where that does not matter.

If a later forward of one command fails, the earlier ones stay created.

### TCP example

Publish an SSH service listening on the agent's port 22 as server port 2222:

```sh
rift add forward node1 2222:22/tcp
```

Allow TCP 2222 in the relevant upstream firewall. From a separate client, test `ssh -p 2222 USER@rift.example.net` and verify the SSH host key through a trusted channel. Configure authentication and access controls in the SSH service itself.

### UDP example

Publish a UDP service on agent port 27015 as server port 27015:

```sh
rift add forward node1 27015/udp
```

Allow UDP 27015 upstream and test with the application's own client. UDP and TCP are separate grants: if an application requires both, add one forward for each protocol and allow both in the firewall.

### DNS example: TCP and UDP

If a DNS server on the agent is configured to listen on port 53 for both transports, `both` creates one forward per transport:

```sh
rift add forward node1 53/both
```

Allow both TCP and UDP 53 in the upstream firewall and use a DNS client to test both modes against the server address. Ensure neither port conflicts with existing services, and configure the DNS server's access controls before exposing it.

### Port ranges and addresses

Ranges use `start-end`; both ranges must have the same length and contain at most 4096 ports. Corresponding ports map in order:

```sh
rift add forward node1 30000-30002:40000-40002/udp
```

`--listen-ip ADDRESS` picks one specific configured address instead of `/v4`, `/v6` or `/all`; it is only needed with several addresses of the same family. The default ingress is `public`; the mode is transparent unless `--mode translate` is given (see above). Check the created ID and apply status:

```sh
rift list forwards
rift status
```

A grant may remain pending while the agent applies it. Test from a separate client after it is active; a successful command alone does not prove firewall or application reachability.

### Limit a forward to known clients

`--allow-from` lets only the named client addresses or networks through; everyone else gets no answer, as on a closed port:

```sh
rift add forward node1 2222:22/tcp --allow-from 198.51.100.7,203.0.113.0/24
```

Separate entries with commas or repeat the option. A bare address means that one host. IPv4 entries apply to IPv4 listeners and IPv6 entries to IPv6 listeners, so `/all` needs at least one of each. `rift list forwards` shows the list in the FROM column (`any` without one). The server enforces it before the packet enters the tunnel: transparent forwards are not redirected for other sources, translated forwards drop their connections. To change the list, remove the forward and add it again.

The source is the address the server sees. A client behind NAT or a mobile network has no fixed address, and a VPN device connects with its public address, not its VPN address, because device profiles are split-tunnel. For your own devices use a [VPN grant](#private-vpn-access) instead: `rift vpn allow DEVICE AGENT 22/tcp` reaches the service at the agent's tunnel address without any public port. `--allow-from` does not apply to `--ingress local`; for sites use `rift add site ... --allow-from`.

### IPv4-to-IPv6 and IPv6-to-IPv4

Translation bridges different listener and target families. It must be requested explicitly. For example, an IPv4 listener forwarding to the agent's IPv6 tunnel address:

```sh
rift add forward node1 8080/tcp --mode translate --target-family v6
```

Ensure the application listens on the agent's IPv6 tunnel address. For the opposite direction, an IPv6 listener to an IPv4-only service, use `rift add forward node1 8080/tcp/v6 --mode translate`. Translation runs in userspace and changes the source address visible to the destination. `--ingress local` is supported only for transparent forwards.

### Agent at home with IPv6 only

An agent whose Internet connection has no public IPv4 address (for example DS-Lite or an IPv6-only fibre line) still works, and its services become reachable over IPv4 through the server. The tunnel itself carries IPv4 and IPv6 regardless of the home connection, so a normal forward such as `rift add forward node1 8080:80/tcp` publishes the service on the server's IPv4 address. Requirements:

- the server has IPv6, and `RIFT_PUBLIC_ENDPOINT` has an AAAA record (agents dial that name; an A record alone is not enough);
- UDP 51820 and TCP 8443 are allowed over IPv6 in the cloud firewall too (the enrollment port listens on IPv6 whenever `RIFT_ENROLLMENT_BIND` is `0.0.0.0:…`, the default; RIFT opens both in the host firewall);
- the service on the agent listens on `0.0.0.0` or on the agent's tunnel address, as for any forward.

`RIFT_PUBLIC_IPS` needs the server's IPv6 address only if you also want `/v6` or `/all` forwards.

## Publish websites with HTTPS

RIFT forwards ports; a reverse proxy provides hostname routing and HTTPS. The installed `rift add site`, `rift remove site` and `rift list sites` commands use the repository’s `deploy/vps/rift-site` helper to configure an **existing** Traefik, Caddy or Nginx proxy. The directory name is historical: the server can run on any suitable Linux host.

### Example: a new Caddy proxy in Docker

This example starts a separate Caddy container on the server and uses a manually created local-ingress forward. It requires Docker bridge networking, a free TCP 80 and 443 on the server, a reachable public IPv4 address assigned to its interface, and an HTTP service on `node1` port 8081. Replace the example domain and IP throughout. Configure the domain's A record and allow TCP 80 and 443 through all relevant firewalls before starting Caddy. Use a real domain for automatic certificate issuance.

First create the forward on the **server**:

```sh
rift add forward node1 20000:8081/tcp --ingress local
```

The forward listens on the first IPv4 address in `RIFT_PUBLIC_IPS`. Port 20000 must be available; choose another if needed. Do not open it publicly. Then create a separate proxy project on the server:

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

### Using the site commands

The host commands `rift add site`, `rift remove site` and `rift list sites` set up the forward and the proxy configuration for you. Prepare the application and the proxy first, then add the site.

#### Prepare the website and proxy

1. Start the HTTP application on the agent, for example on port `8081`, listening on its tunnel address or on `0.0.0.0`. If it runs in Docker, publish the port on the agent host. Confirm the application itself works before adding RIFT.
2. Create an A or AAAA DNS record for `app.example.net` pointing to the server's reachable address. Replace all example names with your own.
3. Set up one supported proxy on the server and confirm it owns TCP 443. Open TCP 443 and, if required for certificates, TCP 80. Configure certificate issuance for your domain.
4. Ensure the proxy can reach the server public address through an interface other than the public-address NIC, such as a Docker bridge. The helper creates a `local` ingress forward which matches packets entering on such an interface; a host-local connection that bypasses prerouting is not equivalent. Verify the actual packet path for your proxy setup.

The helper assumes particular proxy layouts: Traefik uses a watched file provider, entrypoints `web` and `websecure`, and certificate resolver `myresolver`; Caddy and Nginx must load the generated site directories (`/etc/caddy/rift-sites` and `/etc/nginx/rift-sites`). Adapt your proxy configuration to those paths and reload commands. The helper stores its settings and site records in `/var/lib/rift-site/sites.json`. It uses the first IPv4 address in `RIFT_PUBLIC_IPS` for the proxy's local hop; clients can still reach the site over IPv6 when the proxy listens on IPv6 and the domain has an AAAA record. Inspect the helper and back up proxy configuration before using it on an existing installation.

#### Add a site

On the **server**, from the checkout, choose the proxy that already owns port 443:

```sh
sudo rift add site node1 app.example.net 8081 traefik
```

Alternatively, end the command with `caddy`, `nginx` or `npm` (Nginx Proxy Manager) with the corresponding existing proxy. The helper allocates a port in `20000-20999`, creates a local-ingress TCP forward and writes a proxy configuration. The allocated port is for the proxy path and should not be opened publicly. The output ends with the DNS record the site needs and whether it already resolves there (`ok`, `missing` or `wrong`); create or fix the record before the first visit, since the certificate needs it too. Test `https://app.example.net` from an external client and check the proxy certificate and application response.

Traefik uses its configured certificate resolver. The first add may migrate a recognized single-file Traefik provider to a watched directory, or add a watched file provider (`--providers.file.directory=/dynamic`, plus a volume for `<compose project>/dynamic`) to a Traefik that only uses Docker labels; it edits the Compose file (keeping a `.rift-bak` copy) and recreates the Traefik service, so expect a short interruption. Existing Docker-label routes remain. This needs Traefik to run from a Compose file with the container name `traefik` and a list-style `command:` and `volumes:`. Caddy obtains certificates through its configuration. For Nginx, the helper invokes `certbot --nginx` if available; without it the site is written but TLS is not requested, so configure a certificate separately. For Nginx and Nginx Proxy Manager, `RIFT_REQUEST_CERTIFICATE` in the server `.env` controls certificates: `true` (default) requests a Let's Encrypt certificate for each new site, which means accepting the Let's Encrypt terms of service (certbot is run with `--agree-tos`); `false` skips it and you handle TLS yourself. The optional `RIFT_LETSENCRYPT_EMAIL=you@example.net` is the contact for expiry notices. Without it certbot registers without an email, and Nginx Proxy Manager, which requires one, uses the admin login address. Traefik and Caddy ignore both settings. HTTP traffic between proxy and agent is carried inside WireGuard.

Nginx Proxy Manager is configured through its API at `http://127.0.0.1:81` (change `npm.url` in `/var/lib/rift-site/sites.json` if needed). Put an NPM admin login and the Let's Encrypt address in the server `.env` (already `chmod 600`) and recreate the server container with `docker compose up -d --force-recreate`:

```sh
RIFT_NPM_EMAIL=admin@example.net
RIFT_NPM_PASSWORD=...
# Optional, see above. Certificate requests are on by default and force HTTPS.
RIFT_LETSENCRYPT_EMAIL=admin@example.net
```

The helper reads these values from the running server container, which Compose fills from `.env`; they are visible to root through `docker inspect`. They also work as environment variables of the site command or in `/etc/rift/site.env`. With `RIFT_REQUEST_CERTIFICATE=false` the proxy host is created without TLS and you request a certificate in the NPM UI. `rift remove site` deletes the proxy host again, and its certificate too when that was issued for this domain alone and no other host, redirection, 404 host or stream uses it; shared and wildcard certificates are kept.

To let only known clients open a site, add `--allow-from` with addresses or networks; the proxy answers everyone else with 403:

```sh
sudo rift add site node1 app.example.net 8081 traefik --allow-from 198.51.100.7,2001:db8:1::/48
```

Running `rift add site` again for the same domain replaces the list; without `--allow-from` the site is open to everyone again. Traefik gets an `ipAllowList` middleware (`ipWhiteList` when its image tag says version 2), Caddy a `remote_ip` matcher, Nginx `allow`/`deny` inside `location /` (the certbot challenge stays reachable) and Nginx Proxy Manager the same lines in the host's advanced configuration. The proxy checks the address it sees: behind a CDN or another proxy that is the CDN's address, and with Docker's userland proxy (for example IPv6 to a container) it can be Docker's gateway. Check from an allowed and a refused client after adding. `rift list sites` shows the list in the FROM column.

To remove a site and its forward:

```sh
sudo rift remove site app.example.net
```

The helper remembers which RIFT installation its site records belong to. After a fresh installation (for example `docker compose down -v`), the next site command removes the old records and their proxy configuration and says so, so no domain keeps pointing at a dead port.

The web panel adds and removes sites through a host service that runs these same commands; see [Web panel](#web-panel) for the queue and what it is allowed to do. `sudo rift list sites` shows the sites the helper manages with their forward ID and whether that forward still exists. On the server, `rift list forwards` (the installed CLI) adds a SITE column with the domain and proxy of each forward that `rift add site` created; `rift --json list forwards` and the command inside the container are unchanged. Manage these forwards only through the site commands: if you delete one with `rift remove forward`, `list` shows it as `missing` and running `rift add site` for the same site creates it again.

To inspect or change the helper's default proxy:

```sh
sudo rift proxy
sudo rift proxy caddy
```

For a custom reverse proxy, create a transparent TCP forward with `--ingress local` and configure the proxy to connect to the server address and allocated port via an appropriate incoming interface. Local ingress excludes packets arriving on a NIC that owns a configured public address; it is not a general-purpose loopback listener. See [architecture](docs/architecture.md#transparent-packet-path).

## Manage agents and forwards

All commands in this section run on the server. IDs are returned by `rift list forwards` and `rift add forward`; replace `1` with the actual ID.

```sh
# Inspect agents and their state
rift list agents
rift show agent node1

# Temporarily disable or re-enable an agent
rift disable agent node1
rift enable agent node1

# Remove an agent, or cancel a pending invitation
rift remove agent node1
rift remove invite node1

# Reinstalled home server or lost agent volume: invite the same name again
rift add agent node1

# Inspect, disable, enable or remove a forward
rift list forwards
rift disable forward 1
rift enable forward 1
rift remove forward 1
```

**Reinstalling an agent.** If a home server is reinstalled or its `rift-state` volume is lost, run `rift add agent NAME` again with its existing name (or "Re-invite" in the web panel) and start the new install with that invitation. The new install takes over the agent's key and keeps its ID, tunnel addresses, forwards, VPN grants, exits and sites, so VPN devices need no new profile. The old install stops working as soon as the invitation is used; until then nothing changes. Only an active agent can be invited again; enable a disabled one first.

`rift rename agent OLD NEW` and `rift rotate agent NAME` are also available; `rift --help` lists every command. For translated forwards, `rift add ban AGENT FORWARD_ID ADDRESS --ttl 1h` blocks an original client address temporarily; `rift list bans` shows bans. Bans expire by TTL; there is no explicit remove command. Use `--json` for machine-readable administrative output and `rift --help` for the full CLI.

Forwards are shown as a compact table: the ID used for removal, agent, listener, target port, ingress, allowed sources (FROM), mode, purpose and state. Agent names are resolved when available; an ID is shown if they cannot be retrieved. On the server, the installed `rift` adds a SITE column for forwards that `rift add site` manages. For example:

```text
ID  AGENT  PROTO  LISTEN              TARGET  FAMILY  INGRESS  FROM  MODE         PURPOSE  STATE    SITE
1   node1  TCP    203.0.113.10:2222   22      v4      public   any   transparent  user     enabled
5   node1  TCP    203.0.113.10:20000  8081    v4      local    any   transparent  user     enabled  app.example.net (caddy)
```

Normal commands print concise status and confirmations. Use `rift --json status`, `rift --json list forwards`, or `rift --json doctor` for complete machine-readable data. The `--json` format is also used by the site helper and integration tools.

## Private VPN access

Besides publishing ports, RIFT can give your own phones and laptops private access to an agent through the server. Each device is an extra WireGuard peer on the server's `rift0`; its traffic is forwarded into the existing agent tunnel. The home router needs no inbound port forwarding, and public forwards are unchanged.

```text
phone ── WireGuard ──> RIFT server ── existing tunnel ──> RIFT agent ──> home server
                       (VPN peer 10.14.0.x)                             └─> optional LAN
```

Everything is denied until you allow it. A device reaches only what a grant names, and devices cannot reach each other or the server itself.

**The short way.** One command on the **server** creates the device if it does not exist yet, allows what you name and prints the QR code for the WireGuard app, followed by the addresses to open:

```sh
rift vpn connect iphone node1 3000/tcp
```

Scan the code, switch the tunnel on and open the address it names, for example `http://10.13.0.2:3000` (node1's tunnel address). No public port is opened: only devices with a grant reach the service. To add another service later, run the command again with its port and scan the new code; `--export > iphone.conf` prints the file instead. In the web panel, "Connect device" in the VPN devices card does the same.

The same in single steps:

```sh
rift add device iphone                       # key pair + address from the VPN pool
rift vpn allow iphone node1 server           # the home server itself
rift vpn config iphone                       # QR code: scan it in the WireGuard app
rift vpn config iphone --export > iphone.conf  # or export a file (contains the private key)
```

`rift vpn allow DEVICE AGENT TARGET...` takes one or more targets, for example `rift vpn allow iphone node1 22/tcp 53/both`:

| Target | Reaches |
| --- | --- |
| `server` | TCP, UDP and ping to the agent host's tunnel address. |
| `22/tcp` | Only that port or range (`8000-8010/tcp`, `53/both`) on the agent host. |
| `full` | Every IP protocol to the agent host. Still not its LAN. |
| `192.168.178.0/24` | An explicitly named private network behind the agent; add `--snat` if the LAN router has no route back (see below). |

Manage devices with `rift list devices`, `rift disable device NAME` / `rift enable device NAME` (reversible) and `rift remove device NAME` (deletes the device, its key and its grants). `rift vpn deny NAME AGENT [TARGET...]` withdraws grants; without selectors it withdraws everything on that agent. A network grant made with `--snat` is withdrawn without repeating `--snat`. Revocation and denial close the path on the server in the same reconcile pass; the agent follows on its next sync.

Main profiles are split-tunnel unless the device has the server [internet exit](#use-rift-as-a-vpn-exit): `AllowedIPs` lists only the granted addresses. Every device has an IPv4 and an IPv6 address; grants use IPv4 only. Exported files and QR codes contain the device's private key, which stays in a mode-0600 file under the state volume and is never logged.

**Reaching the LAN.** A network grant (for example `rift vpn allow iphone node1 192.168.178.0/24`) forwards through the agent host and is the only grant that touches the LAN. The agent refuses it unless its owner lists the network in `RIFT_AGENT_ALLOW_SUBNETS` (see [Harden the agent](#harden-the-agent)). Then choose one:

- Add a static route on the home router for the VPN pool (default `10.14.0.0/24`) via the agent host's LAN address, so LAN hosts can answer. Source addresses stay visible.
- Or add `--snat`: the agent masquerades the device behind its own LAN address and no router change is needed. NAT applies only to the granted device and network.

The agent host itself answers on its LAN address too, as long as that address lies in a granted subnet. A granted network must not exist on the server, overlap a RIFT pool, or be granted behind two different agents; RIFT refuses those. Change the VPN pool with `RIFT_VPN_POOL` (and `RIFT_VPN_POOL6`; restart required) if `10.14.0.0/24` collides with something.

**A DNS server at home.** To use an AdGuard Home or Pi-hole on an agent while on the go, without opening port 53 to the internet:

```sh
rift vpn dns iphone node1        # node1's tunnel address becomes the DNS server
rift vpn config iphone           # import the main profile again
rift vpn dns iphone default      # back to the default
```

This writes `DNS = <node1's tunnel address>` into the device's main profile, also without an exit, and allows port 53 (UDP and TCP) on node1 for the device; with the exit through this server it replaces `RIFT_VPN_DNS`. The DNS server must listen on the agent's tunnel address (on `0.0.0.0` or through a published Docker port) and sees each device's own VPN address. A device has at most one such DNS server; `rift vpn deny iphone node1` removes it with the other grants. Extra profiles through an agent exit keep `RIFT_VPN_DNS`. While the tunnel is on, every name lookup of the device depends on that agent: if it or the DNS server is down, names do not resolve until the tunnel is switched off. The web panel offers the same as "DNS server" in a device's Access dialog.

**Trust boundary.** The server authenticates devices by WireGuard key, and the agent enforces its own input and forwarding rules by the device's VPN source address. A compromised server can forge an allowed source address, so the agent-side rules limit mistakes and stolen device keys, not a hostile server. What a hostile server can reach is capped by the agent's own `RIFT_AGENT_ALLOW_PORTS` and `RIFT_AGENT_ALLOW_SUBNETS`: it can never open a port outside the first or the LAN outside the second. Protecting against that needs end-to-end authentication between device and agent, which RIFT does not provide for grants; an exit through an agent is end to end between the device and the agent.

## Use RIFT as a VPN (exit)

A device can also send **all** its internet traffic through RIFT, like a commercial VPN. One device can have several exits at once, each as its own WireGuard profile:

| Profile | Where the traffic leaves | Add with | Import with |
| --- | --- | --- | --- |
| main profile | Without an exit, only what the device's grants and the panel name. With the server exit, the VPS's connection; websites see the VPS's address. | `rift vpn allow DEVICE exit` (the server exit) | `rift vpn config DEVICE` |
| one per agent | That agent's connection, for example your home line; websites see your home address. | `rift vpn allow DEVICE AGENT exit` | `rift vpn config DEVICE AGENT` |

```sh
rift add device iphone
rift vpn allow iphone exit        # main profile: exit through the VPS
rift vpn allow iphone node1 exit  # extra profile: exit through the agent node1
rift vpn allow iphone node2 exit  # and another one through node2
rift vpn config iphone            # scan the main profile in the WireGuard app
rift vpn config iphone node1      # scan the profile for node1
```

`exit` may sit beside other targets: `rift vpn allow iphone node1 22/tcp exit` grants port 22 on `node1` and adds the exit through `node1`. Exits add up: allowing another one keeps the others. Remove one at a time: `rift vpn deny iphone exit` ends the server exit, `rift vpn deny iphone node1 exit` only the one through `node1`, and `rift vpn deny iphone node1` withdraws every grant on `node1` together with that exit. After a change RIFT names the profile to import again, for example `Import the profile: rift vpn config iphone node1`. `rift list devices` shows the exits in the ACCESS column (`exit via server; exit via node1; exit via node2`, each with `(refused by agent)` or `(waiting for the agent)` when it does not work yet). The agent names `exit` and `default` are reserved.

**One device, several profiles.** Every profile of a device uses the same key pair and the same addresses; only one of them is active on the phone at a time, so you switch between them in the WireGuard app. The main profile reaches the web panel and the grants as usual, and with the server exit it also carries all internet traffic. A profile for an agent ends at that agent instead, so the panel and the grants on the VPS are **not** reachable while it is active: switch back to the main profile for those. The web panel offers the same in a device's Access dialog: a "Main profile" block with the box "Send all traffic through this server", an "Extra profiles" block with one switch per agent, a QR code or configuration button per profile, and a note after each change saying which profile to import again or delete in the WireGuard app. The devices table shows them apart, for example `main: exit via server · profiles: node1`.

### Exit through the VPS

The device's configuration routes `0.0.0.0/0, ::/0` through the usual WireGuard endpoint and sets `DNS` (see below). The VPS forwards the device's traffic to its uplink and masquerades it; replies come back only for connections the device opened. Everything else stays as isolated as before: a device still cannot reach other devices or the VPS itself (except the panel it was granted), and reaches the agents' tunnel addresses only through its grants. The exit reaches the internet only: private and local networks (the RIFT pools, Docker bridges and other containers on the VPS, the provider's private network, `169.254.0.0/16` cloud metadata, `fc00::/7`) are never part of it. If UFW manages the host, RIFT adds forwarding rules commented `rift:exit` while a device uses this exit.

### Exit through a home server

An agent can offer its own internet connection. It is **off by default**; the agent's owner opts in on the agent, in its `.env`, and restarts it:

```dotenv
RIFT_AGENT_ALLOW_EXIT=true
```

Then `rift vpn allow iphone node1 exit` gives the device a profile that sends its traffic through `node1`. If the agent has not opted in, RIFT stores the choice but warns (`agent node1 will refuse it: … set RIFT_AGENT_ALLOW_EXIT=true on the agent`), and the device shows `refused by agent`.

How it works: the device runs a **second WireGuard tunnel to the agent**, inside the agent's tunnel to the VPS.

```text
phone ── WireGuard A (end to end) ───────────────────────────> agent ── NAT ──> Internet
          └─ UDP to the VPS's exit port ─ RIFT server ─ agent tunnel ─┘
```

- The agent creates a second WireGuard interface `rift-exit` with its own key pair, stored on the agent (`exit.key` in its state volume, mode 0600). It reports the public key, whether it has global IPv6 and the port it listens on to the server with every sync.
- The server assigns each agent that is in use one UDP port from `exit_port_min`..`exit_port_max` (default 51821 to 51899, never the WireGuard port) and publishes it like a normal transparent UDP forward on the server's first IPv4 address (and first IPv6 address, if `RIFT_PUBLIC_IPS` has one). **Open that UDP port in your cloud firewall**, as for any forward. The forward belongs to RIFT: it shows in `rift list forwards` with purpose `exit`, `rift remove forward` and `rift disable forward` refuse it, and it disappears when no enabled device uses that exit. The agent accepts it without an entry in `RIFT_AGENT_ALLOW_PORTS`: `RIFT_AGENT_ALLOW_EXIT` implies that one port.
- The traffic between the phone and the agent is encrypted end to end with the device key (the same key the server holds for the device) and the agent's exit key. The VPS relays only ciphertext. A hostile VPS could still add a device of its own to the agent's exit, which is why the agent's owner must opt in.
- The agent masquerades the traffic towards its internet connection. It **blocks private and local destinations** (RFC 1918, `100.64.0.0/10`, `169.254.0.0/16`, loopback, multicast, `fc00::/7`, `fe80::/10`, and with them every RIFT pool) unless they lie inside `RIFT_AGENT_ALLOW_SUBNETS`, and devices on this interface reach nothing on the agent host itself. Your home network is therefore closed to the device unless you list it.
- The configuration is a profile of its own (`rift vpn config DEVICE AGENT`): `MTU` is the server's `mtu` minus 80 (1300 by default) because of the second tunnel, and the endpoint is `RIFT_PUBLIC_ENDPOINT` with the exit port. The profile reaches neither the web panel nor the grants of the device. Panel and grants work in the main profile only, so switch profiles in the WireGuard app to use them.
- Traffic crosses the VPS twice (phone to VPS to home, and back), so the VPS's bandwidth and the home upload speed both limit you. If the agent has not reported its exit key yet, `rift vpn config` says why there is no configuration yet.
- On the agent, `rift doctor` shows whether the exit is offered and whether the host has a global IPv6 address; on the server it counts the exit devices and names what an agent still lacks. If a host firewall drops forwarding on the agent (UFW, Docker), RIFT adds `rift:exit` forwarding rules for `rift-exit` and the default-route interfaces. `rift-exit`, its key and its rules disappear when the exit is no longer used or the agent stops offering it.

The first host address of each VPN pool (`10.14.0.1` and `fd88:5249:4655::1` by default) belongs to the exit interface of every agent and is never given to a device.

### IPv4, IPv6 and DNS

Every device gets an IPv4 address from `RIFT_VPN_POOL` and an IPv6 address from `RIFT_VPN_POOL6` (a ULA network, default `fd88:5249:4655::/64`), and its configuration lists both. Grants (`server`, `full`, ports, networks) stay IPv4 only.

- An exit carries IPv6 only if it has a global IPv6 address: for the VPS, an IPv6 address in `RIFT_PUBLIC_IPS`; for an agent, a global address on its host (reported automatically). The device's IPv6 is masqueraded there.
- Otherwise the device's IPv6 traffic is **dropped, not leaked**: the configuration still routes `::/0` into the tunnel, where it is rejected at once, so nothing leaves around the VPN and apps fall back to IPv4 without waiting. `rift doctor` and the answer to `rift vpn allow` tell you when this applies.
- `RIFT_VPN_DNS` (default `9.9.9.9,2620:fe::fe`, Quad9) is written as `DNS` into configurations that have an exit: always the IPv4 servers, the IPv6 ones only if that exit carries IPv6. Without an exit there is no `DNS` line. The list needs at least one IPv4 address. The servers are reached through the exit.
- To check a setup, open [test-ipv6.com](https://test-ipv6.com) on the device. With an exit without IPv6 it should show IPv4 working through the exit's address and no IPv6, and no leak of your own address.

Pools, DNS and ports in the configuration: see the [Configuration](#configuration) table.

## Web panel

The server can serve a web panel with what the CLI does: agents and invitations, forwards and bans, VPN devices with their grants, internet exit and WireGuard configuration (as QR code or file; "Connect device" creates a device, grants ports on an agent and shows its QR code in one step), panel access, sites, reconcile, the recent log and diagnostics. Only printing the panel password stays in the CLI. The panel is **off** by default. Enable it in the server `.env` and recreate the container:

```dotenv
RIFT_WEBPANEL=true
RIFT_WEBPANEL_ACCESS=private   # or public
```

```sh
docker compose up -d --force-recreate
rift panel status
rift panel password
```

Without `RIFT_WEBPANEL_PASSWORD` RIFT generates a 24-character password once and keeps it in the state volume (`webpanel.password`, mode 0600); `rift panel password` prints it. A password you set yourself needs at least 12 characters. Logins are serialised and a wrong password costs one second; a session lasts 12 hours and ends with a restart. After 10 failed logins in a row, all logins are refused for 15 minutes.

**Two-factor login.** The panel can ask for a one-time code from an authenticator app (TOTP: SHA-1, 6 digits, 30 seconds) in addition to the password. Turn it on in the panel (Panel section, Enable: scan the QR code, enter the current code) or on the server:

```bash
rift panel 2fa setup        # prints a QR code and the secret
rift panel 2fa confirm 123456
rift panel 2fa status
```

Once it is on, the login form has a code field, and a wrong password and a wrong code give the same error. A code works once. Turning it off in the panel needs a current code. With `RIFT_WEBPANEL_2FA=required` nobody can log in until it has been set up with the CLI, and the panel cannot turn it off. If the authenticator app is lost, run `rift panel 2fa reset` on the server (root access to the server is the recovery path); it deletes the secret (`webpanel.totp` in the state volume) and ends all panel sessions. The CLI never prints current codes.

**Who can connect.** Every connection is checked against its source address before anything else:

| `RIFT_WEBPANEL_ACCESS` | Listens on | Allowed sources |
| --- | --- | --- |
| `private` (default) | `127.0.0.1` (and `::1`) and the server tunnel address (`10.13.0.1`) | loopback, VPN devices granted with `rift panel allow`, and `RIFT_WEBPANEL_ALLOW` |
| `public` | every address | everyone if `RIFT_WEBPANEL_ALLOW` is empty; otherwise loopback, granted VPN devices and `RIFT_WEBPANEL_ALLOW` |

`RIFT_WEBPANEL_ALLOW` is rarely needed: devices from `rift panel connect` are always allowed without an entry. It takes comma-separated addresses or networks, which may only read. In public mode a non-empty list restricts the panel to these addresses (for example your fixed home IP) plus the server and the panel devices. In private mode only addresses arriving through the tunnel can use it, which in practice means an agent host (`10.13.0.x`).

**Who can change things.** Every logged-in session can read. Changes, and anything that shows a secret (invitation tokens, a device's private key), need a trusted connection as well:

- a connection from loopback without proxy headers: on the server itself or through an SSH tunnel, or
- a VPN device with panel access (`rift panel connect`, `rift panel allow`).

Everything else is read-only: public addresses, `RIFT_WEBPANEL_ALLOW` entries and any request carrying `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` or `X-Real-IP`. That last rule exists because a reverse proxy on the same host also connects from loopback. A proxy that strips or never sends these headers would make its clients look local, so do not put such a proxy in front of the panel. `RIFT_WEBPANEL_CONTROL=off` makes the panel read-only for everyone; there is deliberately no setting that allows changes over the public path. A trusted device plus the password is administrator access to your network: it can publish ports, invite agents and create VPN devices. If such a device is lost, remove it with `rift remove device NAME` and change the password.

**Private mode from your own computer.** Either use an SSH tunnel and open `http://127.0.0.1:8090`:

```sh
ssh -L 8090:127.0.0.1:8090 user@rift.example.net
```

or add a WireGuard device for the panel in one step on the server:

```sh
rift panel connect laptop                         # creates the VPN device if needed, grants the panel, prints a QR code
rift panel connect laptop --export > laptop.conf  # the same as a file (contains the private key)
```

Import the configuration into the WireGuard app, connect, and open `http://10.13.0.1:8090` (the server's `RIFT_SERVER_IPV4`). The device reaches only that port on the server; its configuration routes only the server's tunnel address, plus whatever `rift vpn allow` grants it on agents. `rift panel allow NAME` grants an existing VPN device; re-import its configuration afterwards so it routes the server address. `rift panel deny NAME` withdraws panel access and keeps the device's other grants. Disabling or removing the device also ends its panel access.

**Sites in the panel.** The panel has a Sites card (domain, agent, target port, proxy, and whether the site's forward is `ok`, `missing` or `refused`) with "Add site" and "Remove". Sites need root, Docker and the proxy's files, which the container does not have, so the panel works through a narrow bridge to the host:

- The server container mounts `/var/lib/rift-site` **read-only** (the helper's `sites.json`, which the card lists) and `/var/lib/rift-site-queue` read-write. Nothing else of the host is visible, and the container cannot write to the site records or the proxy configuration.
- An add or remove from a trusted connection (the same rule as every other change) validates the request in the panel first (agent name, domain of at most 253 characters, port 1-65535, proxy `traefik`, `caddy`, `nginx` or `npm`, or none) and writes one small JSON file into the queue: `{id, action: "add", agent, host, port, proxy?}` or `{id, action: "remove", host}`. At most 20 requests wait at a time.
- On the host, the systemd units `rift-site-queue.path` and `rift-site-queue.service` (installed by `deploy/install-cli`) run `rift-site process-queue` when a request appears. It checks every request again, trusting nothing from the container: only the actions `add` and `remove`, exactly their keys, a request id that matches the file name, the same name, domain, port and proxy rules, an optional `allow_from` list of addresses or networks, no links, at most 4 KiB. A request that fails any check is refused without running anything. A valid one goes through the same code as `sudo rift add site` and `sudo rift remove site`; no request text reaches a shell. The answer (`ok` and the helper's output or error) is written to `<id>.result.json`, the request file is deleted, and results older than a day are cleaned up. The panel polls for the answer for up to 30 seconds and shows it.

If the host command is not installed, the card says that sites are managed on the host. If it is installed but the units are not active, a request ends with "The host service did not pick up the request; is `rift-site-queue.path` installed and active?". Run `sudo sh deploy/install-cli` (also after `git pull`) and check `systemctl status rift-site-queue.path`. It creates `/var/lib/rift-site` and `/var/lib/rift-site-queue`. If Docker creates them first (Compose v2 does for a missing bind source) the panel works the same once the units exist. `sudo sh deploy/uninstall-host` removes the units and `--purge` also the queue directory.

**Public mode** opens the port in the host firewall (`host_firewall = "auto"`); open it in any upstream firewall or cloud security group yourself. The panel speaks plain HTTP. In public mode the password and session cookie cross the network unencrypted, so prefer private mode, restrict `RIFT_WEBPANEL_ALLOW`, or put a TLS reverse proxy in front (the cookie is marked `Secure` when the proxy sends `X-Forwarded-Proto: https`). Public sessions are read-only, so a password read off the network alone allows no changes; it still shows your agents, ports and devices.

The panel port (default 8090, `RIFT_WEBPANEL_PORT`) must differ from the control and enrollment ports. Panel settings need a restart; `rift reload` refuses to change them.

## Back up, move or rebuild

RIFT has two ways to save a server. Pick by what you want to keep.

| | `rift export` / `rift import` | `rift backup` / `rift restore` |
| --- | --- | --- |
| Holds | Agent names, forwards, VPN devices with their grants, sites. | The whole state: agents and their keys, forwards, VPN devices and their keys, enrollment CA, panel secrets, sites. |
| Secrets | None. The file is safe to keep and share. | Every key. **Keep the file private.** |
| Agents | Must be added and enrolled again (`rift add agent`). | Keep working: they reconnect to the restored server. |
| Devices | Get new keys; import their configuration again. | Unchanged. |
| Use it to | Rebuild from scratch, copy settings to another server, keep a readable record. | Move to another VPS or recover from a lost disk without touching agents or devices. |

All four commands run on the server and read or write files in your current directory. `rift restore` needs `sudo`. The others need only Docker access; the examples run `rift backup` with `sudo` so that the archive, which holds every key, belongs to root.

### Export and import settings

```sh
rift export                                        # writes rift-export-2026-11-01.json here
rift export /root/settings.json                    # or a name of your choice
rift import rift-export-2026-11-01.json --dry-run  # what would happen; changes nothing
rift import rift-export-2026-11-01.json
```

An import creates what is missing and leaves everything else alone. It never creates agents, because an agent needs its own enrollment. Entries of an agent that does not exist (or is not active yet) are skipped and the report tells you what to do. Forwards that are already there are reported as present; a forward whose ports are taken is reported as failed and the rest carries on. If a forward listens on an address the new server does not have, it goes to the first address of the same IP version from `RIFT_PUBLIC_IPS` (the report says so), or is skipped when there is none. Devices are created with new keys, with their enabled state, panel access and grants. Sites are created through your reverse proxy again, like `rift add site`. A file with an export format this version does not know is refused.

Filters, applied after the renaming:

```sh
rift import settings.json --map node2=node1            # the entries of agent node2 go to node1
rift import settings.json --skip-agent node2           # leave node2 out
rift import settings.json --agent node1 --agent node3  # only these agents
rift import settings.json --map node2=node1 --skip-agent node3 --dry-run
```

`--map OLD=NEW` moves everything of agent OLD to agent NEW (the last mapping of an agent wins). `--agent NAME` and `--skip-agent NAME` use the names after mapping; both can be repeated. A device whose grants all belong to left-out agents is not created.

The report groups what happened:

```text
Created (3)
  forward node1 2222:22/tcp on 203.0.113.10 (the server has no address 198.51.100.7; used 203.0.113.10)
  device phone (new keys; re-import the device config: rift vpn config phone)
  site app.example.org (agent node1, port 8080, caddy) (DNS: app.example.org -> 203.0.113.10)

Already present (1)
  forward node1 53/udp on 203.0.113.10

Skipped (1)
  3 entries for agent node2: no such agent; create it with `rift add agent node2` or use --map node2=NAME

Failed (1)
  forward node1 80/tcp on 203.0.113.10: the public port range overlaps forward 4
```

`rift --json import FILE` prints the same report as JSON. The file is plain JSON with `"format": 1`; forwards, devices and sites refer to agents by name.

### Back up and restore everything

```sh
sudo rift backup                          # writes rift-backup-2026-11-01.tar.gz here, mode 0600
sudo rift restore rift-backup-2026-11-01.tar.gz
```

The backup is one `.tar.gz` with three parts: a small manifest, `server/` (everything in the container's `/var/lib/rift`) and `host/rift-site/` (the site records in `/var/lib/rift-site`). The database is copied with SQLite's online backup (`VACUUM INTO`), so a backup taken while RIFT runs is consistent; the archive is streamed out of the container, so nothing large is staged in its small `/tmp`. The proxy configuration files themselves are not part of it; the site records are, and a restore writes the proxy configuration again.

`rift restore` asks for confirmation (`--yes` skips the question). It checks the archive first, then stops `rift-server`, replaces the content of its state volume with the backup, restores the site records, starts the container again and re-creates the proxy configuration of the restored sites. Before it changes anything it saves the current state as `rift-before-restore-DATE-TIME.tar.gz` in the current directory, so a wrong archive can be undone by restoring that file (`--no-safety-backup` skips this, for example when the server cannot start).

### Move to a new VPS with backup and restore

Agents, devices and sites keep working; only the address changes.

1. On the old server: `sudo rift backup`. Copy the file to the new server over a channel you trust (`scp`). It holds every key.
2. On the new server, install RIFT as in [Install the server](#install-the-server), with your `.env` (`RIFT_PUBLIC_ENDPOINT` may be a new name: RIFT issues a new enrollment certificate for it from the same CA, which agents already trust) and the same values for the pools and ports you changed (`RIFT_IPV4_POOL`, `RIFT_WG_PORT`, ...). Set `RIFT_PUBLIC_IPS` to the **new** addresses, run `docker compose up -d` and `sudo sh deploy/install-cli`. For websites, have your reverse proxy running too.
3. Stop the old server's container (`docker compose down`) so two servers never use the same keys.
4. Run `sudo rift restore rift-backup-2026-11-01.tar.gz` on the new server.
5. Point DNS at the new server: the name in `RIFT_PUBLIC_ENDPOINT` and the names of your sites. If your agents connect to a raw IP address instead of a name, edit `RIFT_SERVER` in each agent's `.env` to the new address and run `docker compose up -d` there; the agent then dials that address with the WireGuard port it already knows. Nothing else changes on the agent.
6. Open the ports in the new cloud firewall or security group: UDP 51820 (or `RIFT_WG_PORT`), the TCP/UDP ports of your forwards, 80 and 443 for sites.
7. Check `rift status` and `rift list forwards`.

Forwards that listened on an address the new server does not have are moved at startup to the first address of the same IP version in `RIFT_PUBLIC_IPS`; `rift status` names each one it moved, and the log has a warning. If there is no address of that version (an IPv6 forward on a server without IPv6), or the ports are already taken there, the forward stays where it is and `rift status` and `rift doctor` list it as not applicable until you change `RIFT_PUBLIC_IPS` or remove it.

### Rebuild with export and import

For a fresh start that keeps your settings, not your keys:

1. `rift export`, and copy the file away.
2. Reinstall the server as in [Install the server](#install-the-server).
3. For every agent: `rift add agent NAME` on the server, and the three `.env` lines on the agent. The agent needs a clean state volume (`docker compose down -v` there), because it was enrolled with the old server. Wait until `rift list agents` shows it as active.
4. `rift import rift-export-2026-11-01.json --dry-run`, read the report, then run it again without `--dry-run`. Use `--map OLD=NEW` for agents that now have another name and `--skip-agent NAME` for ones you do not bring back.
5. Import the configuration of every VPN device again (`rift vpn config NAME`): the devices have new keys.

## Command reference

All commands run on the **server** unless noted. `rift COMMAND --help` shows the details of each, including the host commands (sites, `proxy`, `export`, `import`, `backup`, `restore`). `--json` before the command gives machine-readable output, for example `rift --json list forwards`.

**Overview**

| Command | What it does |
| --- | --- |
| `rift status` | Health of the server, agents, enrollment port, open invitations and refused forwards. |
| `rift doctor` | Checks kernel tools, WireGuard, nftables and the host firewall. |
| `rift logs [--lines N]` | Recent log entries of the running server or agent (default 100). |
| `rift reload` | Re-reads `config.toml` and applies the current state again. |
| `rift config validate` | Checks `config.toml` and the `.env` values; reports the first error. |

**Agents (home servers)**

| Command | What it does |
| --- | --- |
| `rift add agent NAME [--ttl 15m]` | Creates a single-use invitation and prints the three `.env` lines for the agent. Opens the enrollment port until the agent is active. |
| `rift list agents` | All agents with state and tunnel addresses. |
| `rift show agent NAME` | Every stored detail of one agent. |
| `rift remove invite NAME` | Cancels an open invitation. |
| `rift remove agent NAME` | Deletes an agent with its forwards and VPN grants. |
| `rift disable agent NAME` / `rift enable agent NAME` | Switches an agent and everything on it off and on again. |
| `rift rename agent OLD NEW` | Renames an agent. |
| `rift rotate agent NAME` | Gives the agent a new WireGuard key on its next sync. |

**Forwards (published ports)**

| Command | What it does |
| --- | --- |
| `rift add forward AGENT SPEC...` | Publishes ports. `SPEC` is `LISTEN[:TARGET]/tcp`, `/udp` or `/both`, optionally ending in `/v4` (default), `/v6` or `/all`. Example: `rift add forward node1 2222:22/tcp 53/both 8080:80/tcp/all`. |
| … `--mode translate` | Bridges IPv4 and IPv6: an IPv6 listener (`/v6`) to an IPv4-only service, or with `--target-family v6` an IPv4 listener to the agent's IPv6 address. The service then sees the server, not the client; see [IPv4-to-IPv6 and IPv6-to-IPv4](#ipv4-to-ipv6-and-ipv6-to-ipv4). |
| … `--ingress local` | Only for a reverse proxy on the server; not reachable from the Internet. |
| … `--listen-ip ADDRESS` | A specific server address, only needed with several addresses of the same IP version. |
| … `--allow-from ADDRESS[,NETWORK...]` | Only these clients reach the forward; see [Limit a forward to known clients](#limit-a-forward-to-known-clients). |
| `rift list forwards` | All forwards with ID, purpose (`user`, or `exit` for the managed forward of an [internet exit](#use-rift-as-a-vpn-exit)) and state (`enabled`, `disabled`, `pending`, `refused`); on the server with a SITE column. |
| `rift remove forward ID` | Deletes a forward. Refuses an `exit` forward. |
| `rift disable forward ID` / `rift enable forward ID` | Switches a forward off and on again. |
| `rift add ban AGENT FORWARD_ID IP [--ttl 1h]` | Blocks a client address on a translated forward for a while. |
| `rift list bans` | Active bans with their expiry time (UTC). |

**Websites (host commands, run with `sudo` on the server)**

| Command | What it does |
| --- | --- |
| `rift add site AGENT DOMAIN PORT [traefik\|caddy\|nginx\|npm] [--allow-from ADDRESS[,NETWORK...]]` | Publishes `https://DOMAIN` through your reverse proxy to `PORT` on the agent. Without a proxy word the default is used. With `--allow-from` the proxy answers other clients with 403. |
| `rift list sites` | All sites with their forward state (`ok`, `missing`, `refused`). |
| `rift remove site DOMAIN` | Removes the site, its proxy configuration and its forward. |
| `rift proxy [traefik\|caddy\|nginx\|npm]` | Shows or sets the default proxy. |

The web panel runs `add site` and `remove site` through the host service (`rift-site-queue.path`, installed by `deploy/install-cli`); see [Web panel](#web-panel).

**VPN devices (phones, laptops)**

| Command | What it does |
| --- | --- |
| `rift vpn connect DEVICE AGENT TARGET... [--snat] [--export]` | Creates the device if needed, grants the targets (as `vpn allow`) and prints its configuration as a QR code with the addresses to open. Example: `rift vpn connect phone node1 3000/tcp`. |
| `rift add device NAME` | Registers a device with a key and an address. It reaches nothing yet. |
| `rift list devices` | All devices with state, last handshake and access, including the exits (`exit via server; exit via node1; exit via node2`). |
| `rift vpn allow DEVICE AGENT TARGET... [--snat]` | Grants access. `TARGET` is `22/tcp` (port or range), `server` (the agent host), `full` (all protocols to the host), a network such as `192.168.178.30/32` (`--snat` for networks whose router has no route back), or `exit`: adds an internet exit through that agent, as an extra profile of the device. |
| `rift vpn allow DEVICE exit` | Adds the server as an internet exit of the device (main profile). Other exits stay; import the profile RIFT names. |
| `rift vpn deny DEVICE AGENT [TARGET...]` | Withdraws access; without a target everything on that agent, including the exit through it. |
| `rift vpn deny DEVICE exit` / `rift vpn deny DEVICE AGENT exit` | Ends the exit through the server / through that agent; the device's other exits stay. |
| `rift vpn dns DEVICE AGENT` / `rift vpn dns DEVICE default` | Makes the agent's tunnel address the DNS server of the device's main profile and allows port 53 there / goes back to the default. |
| `rift vpn config DEVICE [AGENT] [--export]` | WireGuard configuration as a QR code, or with `--export` as a file (both contain the private key): the main profile, or with `AGENT` the profile of the exit through that agent. Same form as `rift panel connect NAME [--export]`. |
| `rift disable device NAME` / `rift enable device NAME` | Cuts a device off and lets it back in; key and grants stay. |
| `rift remove device NAME` | Deletes the device, its key and its grants. |

**Web panel**

| Command | What it does |
| --- | --- |
| `rift panel status` | Whether the panel is on, its addresses and which devices may open it. |
| `rift panel password` | Prints the login password. |
| `rift panel connect NAME [--export]` | Creates a VPN device for the panel (or reuses one), grants it access and prints its configuration. |
| `rift panel allow NAME` / `rift panel deny NAME` | Grants or withdraws panel access of an existing device. |
| `rift panel 2fa status` | Whether two-factor login is on and required. |
| `rift panel 2fa setup` then `rift panel 2fa confirm CODE` | Sets up two-factor login with an authenticator app. |
| `rift panel 2fa reset` | Turns two-factor login off and ends all sessions, for a lost phone. |

**Save and move (run on the server, files in the current directory; see [Back up, move or rebuild](#back-up-move-or-rebuild))**

| Command | What it does |
| --- | --- |
| `rift export [FILE]` | Saves agents, forwards, VPN devices with grants and sites as JSON, without keys. Default file `rift-export-DATE.json`. |
| `rift import FILE` | Creates what the file holds and the server lacks; never creates agents. Prints what was created, already present, skipped or failed. |
| … `--dry-run` | Shows what would happen and changes nothing. |
| … `--agent NAME` / `--skip-agent NAME` | Imports only, or leaves out, the entries of an agent. Repeatable. |
| … `--map OLD=NEW` | Puts the entries of agent OLD on agent NEW. Repeatable. |
| `sudo rift backup [FILE]` | Saves the whole state, **including every key**, as a private `.tar.gz` (mode 0600). Default file `rift-backup-DATE.tar.gz`. |
| `sudo rift restore FILE [--yes] [--no-safety-backup]` | Replaces all state on this server with a backup, restarts it and re-creates the proxy configuration of the sites. First saves the current state as `rift-before-restore-DATE-TIME.tar.gz` unless `--no-safety-backup` is given. |

**Run by Docker Compose, not by hand:** `rift server` (the server) and `rift agent` (an agent).

## Configuration

`config.toml` contains static settings; `.env` supplies the Compose profile and the documented environment overrides. Compose reads the project `.env` automatically. Agents, invitations and forwards are stored in the persistent state volume rather than in TOML.

| Setting | Default / role | Purpose |
| --- | --- | --- |
| `RIFT_PUBLIC_ENDPOINT` | Server | Reachable DNS name or IP, without port; enrollment certificate identity. |
| `RIFT_PUBLIC_IPS` | Server | Comma-separated addresses assigned to server interfaces for listeners; forwards use the first IPv4 (`/v6`, `/all` for IPv6), `rift add site` the first IPv4. |
| `RIFT_ENROLLMENT_BIND` | `0.0.0.0:8443` | Enrollment listener. |
| `RIFT_ENROLLMENT` | `auto` | `auto`: listen on the enrollment port only while an invitation is open; `always`: always; `off`: no enrollment. |
| `RIFT_ALLOW_PRIVATE_LISTENERS` | `false` | Server. Set `true` behind a cloud NAT (e.g. Oracle Cloud), where the public address is not assigned to the interface: put the private interface address in `RIFT_PUBLIC_IPS`, keep the public DNS name in `RIFT_PUBLIC_ENDPOINT`, and open the ports in the cloud's firewall. Allows private and ULA listener addresses; loopback, link-local, multicast and unspecified stay forbidden, as does an address inside a tunnel pool. |
| `RIFT_WG_PORT` | `51820` | Server. WireGuard UDP port; use another one if 51820 is taken on the host. Restart required. |
| `RIFT_IPV4_POOL`, `RIFT_SERVER_IPV4` | `10.13.0.0/24`, `10.13.0.1` | Server. Override the IPv4 tunnel pool if it overlaps a host network (the default avoids Podman's 10.88.0.0/16, Docker's 172.16/12 and common WireGuard 10.8.0.0/24). The server address must be inside the pool; restart required. |
| `RIFT_IPV6_POOL`, `RIFT_SERVER_IPV6` | `fd88:5249:4654::/64`, `fd88:5249:4654::1` | Server. Same for IPv6 (ULA pool). |
| `RIFT_VPN_POOL` | `10.14.0.0/24` | Server. IPv4 addresses for [private VPN devices](#private-vpn-access); must not overlap the IPv4 tunnel pool or a granted LAN; restart required. The first host is reserved for the exit interface of agents. |
| `RIFT_VPN_POOL6` | `fd88:5249:4655::/64` | Server. IPv6 addresses of VPN devices; a ULA network that must not overlap `RIFT_IPV6_POOL`; restart required. The first host is reserved. |
| `RIFT_VPN_DNS` | `9.9.9.9,2620:fe::fe` | Server. DNS servers written into configurations that have an [internet exit](#use-rift-as-a-vpn-exit), unless the device has its own (`rift vpn dns`); needs one IPv4 address, IPv6 ones are used only where the exit carries IPv6. |
| `RIFT_WEBPANEL` | `false` | Server. Serves the [web panel](#web-panel). Restart required. |
| `RIFT_WEBPANEL_ACCESS` | `private` | Server. `private`: loopback and tunnel address only; `public`: every address. |
| `RIFT_WEBPANEL_PORT` | `8090` | Server. TCP port of the panel. |
| `RIFT_WEBPANEL_CONTROL` | `private` | Server. `private`: changes from loopback without proxy headers and from panel VPN devices; `off`: read-only everywhere. |
| `RIFT_WEBPANEL_ALLOW` | empty | Server. Extra allowed source addresses or networks, comma-separated. |
| `RIFT_WEBPANEL_2FA` | `optional` | Server. `optional`: one-time code at login once someone turned it on; `required`: no login until `rift panel 2fa setup` and `confirm` ran. Restart required. |
| `RIFT_WEBPANEL_PASSWORD` | generated | Server. Panel password, at least 12 characters; `rift panel password` shows the effective one. |
| `RIFT_SERVER`, `RIFT_AGENT_NAME`, `RIFT_ENROLLMENT_TOKEN` | Agent | Invitation values; remove token after enrollment. If the host of `RIFT_SERVER` later differs from the server address stored at enrollment, the agent dials the new host with the stored WireGuard port; after a server move, editing `RIFT_SERVER` is enough. |
| `RIFT_AGENT_ALLOW_PORTS` | empty | Agent. Ports the agent may open for forwards and VPN grants, e.g. `22/tcp,80,27015-27020/udp`; empty means no limit. See [Harden the agent](#harden-the-agent). |
| `RIFT_AGENT_ALLOW_SUBNETS` | empty | Agent. Networks behind the agent that VPN network grants and internet-exit devices may reach; empty means no LAN access. |
| `RIFT_AGENT_ALLOW_EXIT` | `false` | Agent. `true` offers the agent's internet connection as an [exit for VPN devices](#use-rift-as-a-vpn-exit). |
| `exit_port_min`, `exit_port_max` | `51821`, `51899` | Server, in `config.toml`. UDP ports the server assigns to the internet exits of agents; must not contain the WireGuard, control or enrollment port. Restart required. |
| `interface`, `wg_port`, `control_port` | `rift0`, `51820`, `8444` | WireGuard interface and ports. |
| `ipv4_pool`, `ipv6_pool` | `10.13.0.0/24`, `fd88:5249:4654::/64` | Tunnel address pools; avoid overlaps. |
| `route_table`, `rule_priority`, `mark`, `mark_mask` | See example TOML | Reserved routing and packet-mark resources. |
| `mtu`, `host_firewall` | `1380`, `auto` | Tunnel MTU and host firewall integration. |

`host_firewall = "auto"` opens exactly what RIFT needs in the host firewall: in the UFW user chains when UFW is active, otherwise in front of any other firewall that drops by default, such as the final `REJECT` of Oracle Cloud images or Docker's forward policy (the rules are readable by `iptables`, so `netfilter-persistent save` keeps working, and a saved copy restores exactly the same rules). RIFT checks them on every reconcile (`poll_seconds`, 10 s): if a firewall reload, a Docker restart or `ufw reload` removes them, they are back within seconds. It does not touch cloud firewalls or security groups. With `host_firewall = "off"`, configure the required input and forwarding paths yourself. TCP 8444 is for tunnel control only. See [deployment preflight](docs/deploy.md#preflight-before-changing-host-networking) for details.

For external enrollment TLS material, configure `tls_cert`, `tls_key` and `tls_ca` together in TOML and mount all files read-only into the container at those paths. Without them, RIFT generates its own CA and a server certificate valid for one year. Agents check only the server certificate's dates, not the CA's, so the CA never needs replacing. It issues a new server certificate from the same CA by itself when `RIFT_PUBLIC_ENDPOINT` changes or less than 30 days are left (checked at start and every few seconds while the enrollment port is open; a running listener switches to the new certificate); agents keep trusting it. External certificates are never replaced. Consult [architecture and security](docs/architecture.md) for trust and recovery details.

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

- **Agent is not active:** check the invitation name, token and expiry; server readiness; DNS; TCP 8443 and UDP 51820 reachability (with `auto`, 8443 only listens while the invitation is open; see `rift status`); and both container logs. Enrollment checks the certificate name and CA.
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

`docker compose pull` fetches `weneten/rift:latest`, which follows the main branch. To stay on a release instead, check out its tag and set the same version in `.env` on the server and every agent:

```sh
git fetch --tags
git checkout v0.1.0
```

```sh
echo RIFT_VERSION=0.1.0 >> .env
```

Then run `docker compose pull` and `docker compose up -d`. Keep the checkout and `RIFT_VERSION` on the same release, because the `rift` command and the site helper come from the checkout. Releases and their changes are listed in [CHANGELOG.md](CHANGELOG.md).

On each host, run `sudo sh deploy/install-cli` again after `git pull` to update the installed `rift` command (on the server, also the site helper). Check logs, agent status and representative services after the update. Review configuration changes before replacing your local `config.toml` or `.env`.

The `rift-state` volume contains identities, keys, certificates and dynamic configuration. Protect and back up the state on **both** server and agent, and test restoration. On the server, `rift backup` and `rift restore` do this for you; see [Back up, move or rebuild](#back-up-move-or-rebuild). The agent's state volume is backed up with your usual volume tools. A normal `docker compose down` asks RIFT to remove its owned networking configuration; a subsequent `docker compose up -d` recreates it from the retained volume. A crash, forced kill or cleanup error can leave network state behind; inspect the logs and use the ownership-aware recovery procedure in [docs/deploy.md](docs/deploy.md#rollout-and-rollback). `docker compose down -v` and volume pruning can delete the state; agents and invitations cannot be recovered merely by restarting. Host-wide sysctl settings installed by `deploy/prepare-host` remain in place.

### Uninstall

Stop the containers, then remove the host-side parts (installed CLI, site helper, `/etc/sysctl.d/99-rift.conf`, and any network objects a crash left behind):

```bash
docker compose down
sudo sh deploy/uninstall-host
```

The state volume (CA, keys, agents, forwards) and the site records are kept so a later install can reconnect. Add `--purge` to delete the volume and the image as well; it also removes the proxy configuration written by `rift add site` and the helper's state in `/var/lib/rift-site` (a Nginx Proxy Manager host has to be deleted in its interface). The live forwarding sysctls, `.env` and `config.toml` are not touched; the script prints what remains.

## Build and development

The root Compose file pulls `weneten/rift:latest`, or `weneten/rift:$RIFT_VERSION` when that is set; the published image is the only deployment path. Pushing to `main` publishes `latest`; pushing a tag `vX.Y.Z` that matches the `Cargo.toml` version publishes `X.Y.Z` for `linux/amd64` and `linux/arm64`. For development, the checks are:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

The Linux network-namespace and Docker integration harnesses require disposable Linux systems and elevated privileges. They change networking and must not be run on a production host. Their prerequisites, test scope and limitations are documented in [docs/deploy.md](docs/deploy.md#functional-test-matrix).

## Further documentation

- [Architecture and security boundaries](docs/architecture.md): packet paths, enrollment, translation, state and recovery.
- [Deployment and verification](docs/deploy.md): preflight, firewall coexistence, rollout, rollback, integration tests and performance procedure.

## License

RIFT is released under the [MIT License](LICENSE).

The `rift` binary contains third-party Rust crates under permissive licenses (MIT, Apache-2.0, ISC, BSD-3-Clause, Unicode-3.0); their full license texts are in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md). The Docker image also contains unmodified Debian packages, some of them under the GPL (for example iproute2, iptables, nftables and wireguard-tools), which RIFT runs as separate programs. [NOTICE](NOTICE) lists them and says where their licenses and sources are; inside the image all of these files are in `/usr/share/doc/rift/`.

After changing dependencies, regenerate the third-party list (CI checks that it is current and that every license is on the list in `about.toml`):

```sh
cargo install cargo-about@0.9.3 --locked --features cli
cargo about generate --locked --fail about.hbs -o THIRD_PARTY_LICENSES.md
```
