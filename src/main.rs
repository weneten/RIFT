use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use ipnet::Ipv4Net;
use rift::{config::Config, model::*, protocol::AdminRequest};
use std::{net::IpAddr, path::PathBuf};

mod output;

#[derive(Parser)]
#[command(name = "rift", version, about = "Rust Internet Forwarding Tunnel")]
struct Cli {
    #[arg(long, global = true, default_value = "/etc/rift/config.toml")]
    config: PathBuf,
    #[arg(long, global = true, help = "Machine-readable JSON output")]
    json: bool,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Run the public VPS server.
    Server,
    /// Enroll or reconnect this home-server agent.
    Agent,
    /// Show tunnel, peer and configuration health.
    Status,
    /// Inspect kernel tools and networking prerequisites.
    Doctor,
    /// Manage agent identities and enrollment invitations on the VPS.
    Agents {
        #[command(subcommand)]
        command: Agents,
    },
    /// Manage published TCP and UDP services on the VPS.
    Forwards {
        #[command(subcommand)]
        command: Forwards,
    },
    /// Block an original client address for a translated forward.
    Bans {
        #[command(subcommand)]
        command: Bans,
    },
    /// Give phones and laptops private access to chosen agents through the VPS.
    Vpn {
        #[command(subcommand)]
        command: Vpn,
    },
    /// The optional web panel on the VPS (RIFT_WEBPANEL=true in the server .env).
    Panel {
        #[command(subcommand)]
        command: PanelCommand,
    },
    /// Validate the local TOML configuration and environment overrides.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Reconcile desired state and reload supported configuration settings.
    Reload,
    /// Read recent structured log entries from the local daemon.
    Logs {
        #[arg(long, default_value_t = 100)]
        lines: usize,
    },
}
#[derive(Subcommand)]
enum Vpn {
    /// Register, list, disable or revoke devices.
    Peer {
        #[command(subcommand)]
        command: VpnPeers,
    },
    /// Let a device reach an agent. Without an allow, a device reaches nothing.
    Allow(VpnAccessArgs),
    /// Withdraw access again. Without --server/--full/--port/--subnet, withdraws all of it on that agent.
    Deny(VpnAccessArgs),
    /// Export the WireGuard configuration of a device.
    Config {
        #[command(subcommand)]
        command: VpnConfig,
    },
}
#[derive(Subcommand)]
enum VpnPeers {
    Add {
        name: String,
    },
    List,
    Enable {
        name: String,
    },
    /// Keep the device and its grants but cut it off until it is enabled again.
    Disable {
        name: String,
    },
    /// Delete the device, its key and its grants. This cannot be undone.
    Revoke {
        name: String,
    },
}
#[derive(Subcommand)]
enum VpnConfig {
    /// Print the configuration, which contains the device's private key.
    Export { name: String },
    /// Print the configuration as a QR code for the WireGuard app.
    Qr { name: String },
}
#[derive(Args)]
struct VpnAccessArgs {
    /// Device name.
    peer: String,
    #[arg(long)]
    agent: String,
    /// TCP, UDP and ping to the agent host itself.
    #[arg(long)]
    server: bool,
    /// Every IP protocol to the agent host itself. Not its LAN.
    #[arg(long)]
    full: bool,
    /// One port or range on the agent host, as PORT/tcp, PORT/udp or PORT/both. Repeatable.
    #[arg(long = "port", value_name = "PORT/PROTO")]
    ports: Vec<String>,
    /// A network behind the agent, such as 192.168.178.0/24. Repeatable.
    #[arg(long = "subnet", value_name = "CIDR")]
    subnets: Vec<Ipv4Net>,
    /// Masquerade the device's address on the agent, for LANs without a route to the VPN pool.
    #[arg(long, requires = "subnets")]
    snat: bool,
}
impl VpnAccessArgs {
    fn accesses(&self) -> Result<Vec<VpnAccess>> {
        rift::vpn::accesses(
            self.server,
            self.full,
            &self.ports,
            &self.subnets,
            self.snat,
        )
    }
}
#[derive(Subcommand)]
enum PanelCommand {
    /// Show whether the panel is on, its addresses and the devices that may open it.
    Status,
    /// Print the panel password.
    Password,
    /// Create a VPN device for the panel (or reuse an existing one), grant it access and
    /// print its WireGuard configuration as a QR code.
    Connect {
        name: String,
        /// Print the configuration file instead of a QR code.
        #[arg(long)]
        export: bool,
    },
    /// Let an existing VPN device open the panel.
    Allow { name: String },
    /// Withdraw a device's panel access. Its other VPN grants stay.
    Deny { name: String },
    /// Two-factor (one-time code) login for the panel.
    #[command(name = "2fa")]
    TwoFactor {
        #[command(subcommand)]
        command: TwoFactorCommand,
    },
}
#[derive(Subcommand)]
enum TwoFactorCommand {
    /// Show whether two-factor login is on and whether it is required.
    Status,
    /// Create a secret and print it as a QR code for an authenticator app.
    Setup,
    /// Turn two-factor login on with a code from the app.
    Confirm { code: String },
    /// Delete the secret and end all panel sessions. The way back in if the app is lost.
    Reset,
}
#[derive(Subcommand)]
enum ConfigCommand {
    Validate,
}
#[derive(Subcommand)]
enum Agents {
    List,
    Show {
        name: String,
    },
    Add {
        name: String,
        #[arg(long, default_value = "15m")]
        ttl: String,
    },
    Remove {
        name: String,
    },
    Disable {
        name: String,
    },
    Enable {
        name: String,
    },
    Rename {
        name: String,
        new_name: String,
    },
    Rotate {
        name: String,
    },
    CancelInvite {
        name: String,
    },
}
#[derive(Subcommand)]
enum Forwards {
    List,
    /// Add forwards. Short form: AGENT SPEC..., where SPEC is LISTEN[:TARGET]/tcp|udp|both
    /// with an optional /v4 (default), /v6 or /all for the server address, for example
    /// `rift forwards add node1 53/both 8080:80/tcp/all`. The long options are the alternative.
    Add {
        #[arg(
            value_name = "AGENT SPEC",
            conflicts_with_all = ["agent", "listen", "target", "protocol"]
        )]
        short: Vec<String>,
        #[arg(long, required_unless_present = "short")]
        agent: Option<String>,
        #[arg(long, required_unless_present = "short")]
        listen: Option<PortRange>,
        #[arg(long, required_unless_present = "short")]
        target: Option<PortRange>,
        #[arg(long)]
        protocol: Option<Protocol>,
        /// A specific server address instead of /v4, /v6 or /all. Rarely needed.
        #[arg(long)]
        listen_ip: Option<IpAddr>,
        #[arg(long,value_parser=["v4","v6"])]
        target_family: Option<String>,
        /// Default transparent; translate bridges IPv4 and IPv6.
        #[arg(long,value_parser=["transparent","translate"])]
        mode: Option<String>,
        #[arg(long, default_value = "public", value_parser = ["public", "local"])]
        ingress: String,
    },
    Remove {
        #[arg(long)]
        id: u64,
    },
    Disable {
        #[arg(long)]
        id: u64,
    },
    Enable {
        #[arg(long)]
        id: u64,
    },
}
#[derive(Subcommand)]
enum Bans {
    List,
    Add {
        #[arg(long)]
        agent: String,
        #[arg(long)]
        forward_id: u64,
        #[arg(long)]
        ip: IpAddr,
        #[arg(long, default_value = "1h")]
        ttl: String,
    },
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("rift: {error:#}");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    let cli = Cli::parse();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "rift=info".into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(rift::audit::writer)
        .json()
        .init();
    let config = Config::load(&cli.config)?;
    let invitation = matches!(
        &cli.command,
        Command::Agents {
            command: Agents::Add { .. }
        }
    );
    // Further forwards of one short-form `forwards add`, sent after the first one.
    let mut more: Vec<AdminRequest> = Vec::new();
    let request = match cli.command {
        Command::Server => return rift::daemon::run_server(config, cli.config).await,
        Command::Agent => return rift::daemon::run_agent(config).await,
        Command::Doctor => {
            let result = rift::net::Kernel::new(config).doctor().await?;
            if cli.json {
                println!("{}", serde_json::to_string(&result)?);
            } else {
                println!("{}", output::doctor(&result));
            }
            return Ok(());
        }
        Command::Config {
            command: ConfigCommand::Validate,
        } => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({"valid": true, "config": cli.config})
                );
            } else {
                println!("Configuration valid: {}", cli.config.display());
            }
            return Ok(());
        }
        Command::Vpn {
            command: Vpn::Config { command },
        } => {
            let (name, qr) = match command {
                VpnConfig::Export { name } => (name, false),
                VpnConfig::Qr { name } => (name, true),
            };
            return vpn_config(&config, cli.json, name, qr).await;
        }
        Command::Panel {
            command: PanelCommand::Connect { name, export },
        } => return panel_connect(&config, cli.json, name, export).await,
        Command::Panel {
            command:
                PanelCommand::TwoFactor {
                    command: TwoFactorCommand::Setup,
                },
        } => return two_factor_setup(&config, cli.json).await,
        Command::Panel { command } => match command {
            PanelCommand::Status => AdminRequest::PanelStatus,
            PanelCommand::Password => AdminRequest::PanelPassword,
            PanelCommand::Allow { name } => AdminRequest::PanelAllow {
                name,
                allowed: true,
            },
            PanelCommand::Deny { name } => AdminRequest::PanelAllow {
                name,
                allowed: false,
            },
            PanelCommand::TwoFactor { command } => match command {
                TwoFactorCommand::Status => AdminRequest::PanelTwoFactorStatus,
                TwoFactorCommand::Confirm { code } => AdminRequest::PanelTwoFactorConfirm { code },
                TwoFactorCommand::Reset => AdminRequest::PanelTwoFactorReset,
                TwoFactorCommand::Setup => unreachable!("handled above"),
            },
            PanelCommand::Connect { .. } => unreachable!("handled above"),
        },
        Command::Vpn { command } => match command {
            Vpn::Peer { command } => match command {
                VpnPeers::Add { name } => AdminRequest::VpnPeerAdd { name },
                VpnPeers::List => AdminRequest::VpnPeerList,
                VpnPeers::Enable { name } => AdminRequest::VpnPeerEnable {
                    name,
                    enabled: true,
                },
                VpnPeers::Disable { name } => AdminRequest::VpnPeerEnable {
                    name,
                    enabled: false,
                },
                VpnPeers::Revoke { name } => AdminRequest::VpnPeerRevoke { name },
            },
            Vpn::Allow(args) => {
                let mut requests =
                    args.accesses()?
                        .into_iter()
                        .map(|access| AdminRequest::VpnAllow {
                            peer: args.peer.clone(),
                            agent: args.agent.clone(),
                            access,
                        });
                let first = requests.next().context(
                    "choose what to allow: --server, --full, --port PORT/PROTO or --subnet CIDR",
                )?;
                more.extend(requests);
                first
            }
            Vpn::Deny(args) => {
                let accesses = args.accesses()?;
                let selected: Vec<Option<VpnAccess>> = if accesses.is_empty() {
                    vec![None]
                } else {
                    accesses.into_iter().map(Some).collect()
                };
                let mut requests = selected.into_iter().map(|access| AdminRequest::VpnDeny {
                    peer: args.peer.clone(),
                    agent: args.agent.clone(),
                    access,
                });
                let first = requests.next().context("nothing to deny")?;
                more.extend(requests);
                first
            }
            Vpn::Config { .. } => unreachable!("handled above"),
        },
        Command::Status => AdminRequest::Status,
        Command::Reload => AdminRequest::Reload,
        Command::Logs { lines } => AdminRequest::Logs {
            lines: lines.min(1000),
        },
        Command::Agents { command } => match command {
            Agents::List => AdminRequest::AgentsList,
            Agents::Show { name } => AdminRequest::AgentsShow { name },
            Agents::Add { name, ttl } => AdminRequest::Invite {
                name,
                ttl_seconds: duration(&ttl)?,
            },
            Agents::Remove { name } => AdminRequest::AgentRemove { name },
            Agents::Disable { name } => AdminRequest::AgentDisable { name },
            Agents::Enable { name } => AdminRequest::AgentEnable { name },
            Agents::Rename { name, new_name } => AdminRequest::AgentRename { name, new_name },
            Agents::Rotate { name } => AdminRequest::AgentRotate { name },
            Agents::CancelInvite { name } => AdminRequest::CancelInvite { name },
        },
        Command::Forwards { command } => match command {
            Forwards::List => AdminRequest::ForwardsList,
            Forwards::Remove { id } => AdminRequest::ForwardRemove { id },
            Forwards::Disable { id } => AdminRequest::ForwardEnable { id, enabled: false },
            Forwards::Enable { id } => AdminRequest::ForwardEnable { id, enabled: true },
            Forwards::Add {
                short,
                agent,
                listen,
                target,
                protocol,
                listen_ip,
                target_family,
                mode,
                ingress,
            } => {
                let (agent, plans) = if let Some((name, specs)) = short.split_first() {
                    anyhow::ensure!(
                            !specs.is_empty(),
                            "name at least one port with its protocol, for example: rift forwards add {name} 8080:80/tcp"
                        );
                    (name.clone(), parse_forward_specs(specs)?)
                } else {
                    (
                        agent.context("--agent is required")?,
                        vec![ForwardPlan {
                            listen: listen.context("--listen is required")?,
                            target: target.context("--target is required")?,
                            protocol: protocol.unwrap_or(Protocol::Tcp),
                            on: None,
                        }],
                    )
                };
                let options = ForwardOptions {
                    listen_ip,
                    on: None,
                    mode: mode.map(|m| {
                        if m == "translate" {
                            ForwardMode::Translate
                        } else {
                            ForwardMode::Transparent
                        }
                    }),
                    target_family: target_family.map(|f| {
                        if f == "v6" {
                            Family::V6
                        } else {
                            Family::V4
                        }
                    }),
                    ingress: if ingress == "local" {
                        Ingress::Local
                    } else {
                        Ingress::Public
                    },
                };
                let forwards = build_forwards(&agent, &plans, &config.public_ips, options)?;
                let mut requests = forwards.into_iter().map(AdminRequest::ForwardAdd);
                let first = requests.next().context("nothing to add")?;
                more.extend(requests);
                first
            }
        },
        Command::Bans { command } => match command {
            Bans::List => AdminRequest::BansList,
            Bans::Add {
                agent,
                forward_id,
                ip,
                ttl,
            } => AdminRequest::Ban {
                agent,
                forward_id,
                ip,
                ttl_seconds: duration(&ttl)?,
            },
        },
    };
    let response = rift::daemon::admin_call(&config, request.clone()).await?;
    if !response.ok {
        bail!(
            "{}",
            response.error.unwrap_or_else(|| "operation failed".into())
        );
    }
    show(&config, cli.json, invitation, &request, &response).await?;
    for request in more {
        let response = rift::daemon::admin_call(&config, request.clone())
            .await
            .context("earlier forwards of this command were already added")?;
        if !response.ok {
            bail!(
                "{} (earlier forwards of this command were already added)",
                response.error.unwrap_or_else(|| "operation failed".into())
            );
        }
        show(&config, cli.json, false, &request, &response).await?;
    }
    Ok(())
}
async fn admin_ok(config: &Config, request: AdminRequest) -> Result<serde_json::Value> {
    let response = rift::daemon::admin_call(config, request).await?;
    if !response.ok {
        bail!(
            "{}",
            response.error.unwrap_or_else(|| "operation failed".into())
        );
    }
    Ok(response.data)
}
/// The short way onto the panel: one device, panel access, and its configuration.
async fn panel_connect(config: &Config, json: bool, name: String, export: bool) -> Result<()> {
    let status = admin_ok(config, AdminRequest::PanelStatus).await?;
    anyhow::ensure!(
        status["enabled"].as_bool() == Some(true),
        "the web panel is off; set RIFT_WEBPANEL=true in the server .env and recreate the container"
    );
    let peers = admin_ok(config, AdminRequest::VpnPeerList).await?;
    let exists = peers
        .as_array()
        .into_iter()
        .flatten()
        .any(|p| p["name"].as_str() == Some(name.as_str()));
    if !exists {
        admin_ok(config, AdminRequest::VpnPeerAdd { name: name.clone() }).await?;
        eprintln!("VPN device {name} created.");
    }
    let granted = admin_ok(
        config,
        AdminRequest::PanelAllow {
            name: name.clone(),
            allowed: true,
        },
    )
    .await?;
    vpn_config(config, json, name, !export).await?;
    if !json {
        if let Some(url) = granted["urls"]
            .as_array()
            .and_then(|urls| urls.get(1))
            .and_then(|u| u["url"].as_str())
        {
            eprintln!("Once the device is connected, open {url}. Password: rift panel password");
        }
    }
    Ok(())
}
/// Prints the new secret as a QR code, like `vpn config qr`. Codes are never shown here: a
/// code readable on the server would not be a second factor.
async fn two_factor_setup(config: &Config, json: bool) -> Result<()> {
    let data = admin_ok(config, AdminRequest::PanelTwoFactorSetup).await?;
    if json {
        println!("{}", serde_json::to_string(&data)?);
        return Ok(());
    }
    let uri = data["uri"].as_str().unwrap_or_default();
    println!("{}", rift::vpn::qr(uri)?);
    println!("Secret: {}", data["secret"].as_str().unwrap_or_default());
    println!("Link:   {uri}");
    eprintln!(
        "Scan the code with an authenticator app, or type the secret in. The secret is shown once."
    );
    eprintln!("Then turn two-factor login on with: rift panel 2fa confirm CODE");
    Ok(())
}
async fn vpn_config(config: &Config, json: bool, name: String, qr: bool) -> Result<()> {
    let data = admin_ok(config, AdminRequest::VpnConfig { name }).await?;
    let text = data["config"].as_str().unwrap_or_default();
    if json {
        println!("{}", serde_json::to_string(&data)?);
    } else if qr {
        println!("{}", rift::vpn::qr(text)?);
        eprintln!("Scan this in the WireGuard app. The code contains the device's private key.");
    } else {
        print!("{text}");
        eprintln!("This file contains the device's private key; store and delete it with care.");
    }
    Ok(())
}
async fn show(
    config: &Config,
    json: bool,
    invitation: bool,
    request: &AdminRequest,
    response: &rift::protocol::AdminResponse,
) -> Result<()> {
    if let Some(warning) = response.data["warning"].as_str().filter(|_| !json) {
        eprintln!("Warning: {warning}");
    }
    if json {
        println!("{}", serde_json::to_string(&response.data)?);
    } else if invitation {
        println!(
            "RIFT_SERVER={}\nRIFT_AGENT_NAME={}\nRIFT_ENROLLMENT_TOKEN={}",
            response.data["server"].as_str().unwrap_or_default(),
            response.data["name"].as_str().unwrap_or_default(),
            response.data["token"].as_str().unwrap_or_default()
        );
        eprintln!("Copy these values into the agent's private .env file. This invitation is single-use and expires.");
        if response.data["enrollment"].as_str() == Some("auto") {
            eprintln!("The enrollment port is open until the agent is active or the invitation expires or is cancelled.");
        }
    } else {
        let agents = if matches!(
            request,
            AdminRequest::ForwardsList | AdminRequest::ForwardAdd(_)
        ) {
            rift::daemon::admin_call(config, AdminRequest::AgentsList)
                .await
                .ok()
                .filter(|response| response.ok)
                .map(|response| response.data)
        } else {
            None
        };
        println!(
            "{}",
            output::render(request, &response.data, agents.as_ref())
        );
    }
    Ok(())
}
fn duration(s: &str) -> Result<u64> {
    let seconds = humantime::parse_duration(s)?.as_secs();
    anyhow::ensure!(seconds > 0, "duration must be positive");
    Ok(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vpn_cli_parses() {
        for args in [
            vec!["rift", "vpn", "peer", "add", "iphone"],
            vec!["rift", "vpn", "peer", "list"],
            vec!["rift", "vpn", "peer", "revoke", "iphone"],
            vec![
                "rift", "vpn", "allow", "iphone", "--agent", "home", "--server",
            ],
            vec![
                "rift", "vpn", "allow", "iphone", "--agent", "home", "--port", "22/tcp", "--port",
                "53/both",
            ],
            vec![
                "rift",
                "vpn",
                "allow",
                "iphone",
                "--agent",
                "home",
                "--subnet",
                "192.168.178.0/24",
                "--snat",
            ],
            vec!["rift", "vpn", "deny", "iphone", "--agent", "home"],
            vec!["rift", "vpn", "config", "export", "iphone"],
            vec!["rift", "vpn", "config", "qr", "iphone"],
            vec!["rift", "panel", "status"],
            vec!["rift", "panel", "password"],
            vec!["rift", "panel", "connect", "laptop"],
            vec!["rift", "panel", "connect", "laptop", "--export"],
            vec!["rift", "panel", "allow", "laptop"],
            vec!["rift", "panel", "deny", "laptop"],
            vec!["rift", "panel", "2fa", "status"],
            vec!["rift", "panel", "2fa", "setup"],
            vec!["rift", "panel", "2fa", "confirm", "123456"],
            vec!["rift", "panel", "2fa", "reset"],
        ] {
            Cli::try_parse_from(&args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
        // --snat only makes sense together with a subnet.
        assert!(Cli::try_parse_from([
            "rift", "vpn", "allow", "iphone", "--agent", "home", "--server", "--snat"
        ])
        .is_err());
    }
    #[test]
    fn vpn_selectors_become_accesses() {
        let args = |extra: &[&str]| {
            let mut argv = vec!["rift", "vpn", "allow", "iphone", "--agent", "home"];
            argv.extend(extra);
            match Cli::try_parse_from(argv).unwrap().command {
                Command::Vpn {
                    command: Vpn::Allow(args),
                } => args.accesses(),
                _ => unreachable!(),
            }
        };
        assert!(args(&[]).unwrap().is_empty());
        assert_eq!(args(&["--port", "53/both"]).unwrap().len(), 2);
        assert!(args(&["--port", "22:80/tcp"]).is_err());
        assert!(args(&["--port", "22"]).is_err());
        assert_eq!(
            args(&["--subnet", "192.168.178.0/24", "--snat"]).unwrap(),
            vec![VpnAccess::Subnet {
                net: "192.168.178.0/24".parse().unwrap(),
                snat: true
            }]
        );
    }
    #[test]
    fn documented_cli_parses() {
        Cli::try_parse_from([
            "rift",
            "forwards",
            "add",
            "--agent",
            "nas",
            "--listen",
            "2222",
            "--target",
            "22",
            "--protocol",
            "tcp",
        ])
        .unwrap();
    }
    #[test]
    fn translation_is_explicit() {
        Cli::try_parse_from([
            "rift",
            "forwards",
            "add",
            "--agent",
            "core",
            "--listen",
            "443",
            "--target",
            "443",
            "--mode",
            "translate",
            "--target-family",
            "v4",
        ])
        .unwrap();
    }
    #[test]
    fn short_form_parses_ports_targets_and_protocols() {
        let specs: Vec<String> = ["53/both", "8080:80/tcp", "5000-5002/udp", "443:8443/tcp"]
            .map(String::from)
            .to_vec();
        let plans = parse_forward_specs(&specs).unwrap();
        let shown: Vec<_> = plans
            .iter()
            .map(|p| {
                (
                    p.listen.start,
                    p.listen.end,
                    p.target.start,
                    p.target.end,
                    p.protocol == Protocol::Udp,
                )
            })
            .collect();
        assert_eq!(
            shown,
            vec![
                (53, 53, 53, 53, false),
                (53, 53, 53, 53, true),
                (8080, 8080, 80, 80, false),
                (5000, 5002, 5000, 5002, true),
                (443, 443, 8443, 8443, false),
            ]
        );
        for bad in [
            "0/tcp",
            "99999/tcp",
            "80/icmp",
            "80:abc/tcp",
            "x/tcp",
            "80",
            "8080:80",
            "53/",
        ] {
            assert!(parse_forward_specs(&[bad.to_string()]).is_err(), "{bad}");
        }
    }
    #[test]
    fn short_form_and_long_options_do_not_mix() {
        Cli::try_parse_from(["rift", "forwards", "add", "node1", "53/both"]).unwrap();
        assert!(
            Cli::try_parse_from(["rift", "forwards", "add", "node1", "53", "--listen", "80"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["rift", "forwards", "add"]).is_err());
        assert!(Cli::try_parse_from(["rift", "forwards", "add", "--agent", "a"]).is_err());
    }
    #[test]
    fn rejects_invalid_range() {
        assert!(Cli::try_parse_from([
            "rift", "forwards", "add", "--agent", "core", "--listen", "0", "--target", "22"
        ])
        .is_err());
    }
    #[test]
    fn local_ingress_is_explicit() {
        let cli = Cli::try_parse_from([
            "rift",
            "forwards",
            "add",
            "--agent",
            "core",
            "--listen",
            "20000",
            "--target",
            "8081",
            "--ingress",
            "local",
        ])
        .unwrap();
        let Command::Forwards {
            command: Forwards::Add { ingress, .. },
        } = cli.command
        else {
            panic!("forwards add");
        };
        assert_eq!(ingress, "local");
    }
}
