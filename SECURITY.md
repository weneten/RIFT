# Security policy

RIFT changes the firewall, routing and sysctls of the hosts it runs on, holds WireGuard and TLS keys, and can publish ports to the internet. Please report weaknesses privately so they can be fixed before they are known.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: on the repository page, open **Security**, then **Report a vulnerability**. Only the maintainers see the report.

Please do not open a public issue, discussion or pull request for a vulnerability.

A useful report says:

- the RIFT version (`rift --version`, or the image tag) and whether it concerns the server, the agent, the web panel or the host scripts;
- what an attacker needs (network position, a VPN device, a stolen key, access to the server ...) and what they gain;
- steps or a proof of concept to reproduce it, on a disposable system.

The maintainers aim to confirm a report within a week and to agree on a disclosure date with you once a fix is ready. This is a goal, not a guarantee: RIFT is maintained in spare time.

## Supported versions

Fixes go into the newest release of the current major version (1.x). Older releases get no separate fixes; update to the newest one (server first, then the agents, see the README).

## Scope

In scope, among others:

- reaching a published port, a VPN grant, an agent's LAN or the server itself beyond what the configuration allows;
- one agent or VPN device reaching another, or posing as one;
- bypassing an agent's own limits (`RIFT_AGENT_ALLOW_PORTS`, `RIFT_AGENT_ALLOW_SUBNETS`, `RIFT_AGENT_ALLOW_EXIT`);
- enrolling without a valid invitation, or reusing one;
- reading keys, tokens or the panel password, or finding them in logs, outputs or files other than their own;
- logging in to the web panel without the password and code, or making changes from a read-only session (including a request through a proxy while `RIFT_WEBPANEL_CONTROL` is not `public`, or from a source outside `RIFT_WEBPANEL_PROXIES`);
- the host scripts (`deploy/`) doing something other than they say.

Out of scope:

- what a hostile server can reach within an agent's own limits; the [trust boundary](README.md#private-vpn-access) describes it;
- findings that need root on the server or agent host;
- the services you publish through RIFT and their own security;
- denial of service by flooding public ports.
