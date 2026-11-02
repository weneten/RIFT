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
    /// List agents, forwards, bans or VPN devices.
    List {
        #[command(subcommand)]
        what: ListWhat,
    },
    /// Show one agent in detail.
    Show {
        #[command(subcommand)]
        what: ShowWhat,
    },
    /// Add an agent invitation, forward, ban, VPN device or site.
    Add {
        #[command(subcommand)]
        what: AddWhat,
    },
    /// Remove an agent, invitation, forward, VPN device or site.
    Remove {
        #[command(subcommand)]
        what: RemoveWhat,
    },
    /// Switch an agent, forward or VPN device off without deleting it.
    Disable {
        #[command(subcommand)]
        what: ToggleWhat,
    },
    /// Switch a disabled agent, forward or VPN device on again.
    Enable {
        #[command(subcommand)]
        what: ToggleWhat,
    },
    /// Rename an agent.
    Rename {
        #[command(subcommand)]
        what: RenameWhat,
    },
    /// Issue a new credential for an agent.
    Rotate {
        #[command(subcommand)]
        what: RotateWhat,
    },
    /// Show or change the reverse proxy that `rift add site` uses (host command).
    Proxy { name: Option<String> },
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
    /// Save settings (agents, forwards, devices, sites) to a JSON file.
    ///
    /// The file holds no keys, tokens or IDs, so it is safe to keep and share. Default file:
    /// rift-export-YYYY-MM-DD.json in the current directory. Load it again with `rift import`.
    Export {
        /// Where to write; `-` prints to standard output.
        file: Option<PathBuf>,
    },
    /// Create what an export file holds and this server lacks.
    ///
    /// Agents are never created: add and enroll them first with `rift add agent`. Entries of an
    /// agent that does not exist or is not active are skipped and reported. Existing things are
    /// left alone; a conflict (a port in use) is reported and the rest goes on. New VPN devices
    /// get new keys, so their configuration must be imported again on the device.
    Import(ImportArgs),
    /// Save everything, including every key, as one private archive.
    ///
    /// For moving the server or recovering it with `rift restore`. The file contains every key
    /// of this server: keep it private. Default file: rift-backup-YYYY-MM-DD.tar.gz in the
    /// current directory.
    Backup {
        /// Where to write; `-` writes the archive to standard output.
        file: Option<PathBuf>,
    },
    /// Replace all state on this server with a backup (host command, run with sudo).
    ///
    /// Stops the server container, replaces its state with the backup, starts it again and
    /// re-creates the proxy configuration of the restored sites. Everything that is on this
    /// server now is lost.
    Restore {
        /// A file made by `rift backup`.
        file: PathBuf,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}
#[derive(Args)]
struct ImportArgs {
    /// Export file; `-` reads standard input.
    file: PathBuf,
    /// Import only entries of this agent (after --map). Repeatable.
    #[arg(long = "agent", value_name = "NAME")]
    agents: Vec<String>,
    /// Leave out entries of this agent (after --map). Repeatable.
    #[arg(long = "skip-agent", value_name = "NAME")]
    skip_agents: Vec<String>,
    /// Put the entries of agent OLD on agent NEW. Repeatable.
    #[arg(long, value_name = "OLD=NEW", value_parser = parse_map)]
    map: Vec<(String, String)>,
    /// Show what would happen and change nothing.
    #[arg(long)]
    dry_run: bool,
}
fn parse_map(value: &str) -> Result<(String, String), String> {
    match value.split_once('=') {
        Some((old, new)) if !old.is_empty() && !new.is_empty() && !new.contains('=') => {
            Ok((old.into(), new.into()))
        }
        _ => Err("use OLD=NEW, for example core2=core".into()),
    }
}
#[derive(Subcommand)]
enum Vpn {
    /// Let a device reach an agent: `rift vpn allow DEVICE AGENT TARGET...`, for example
    /// `rift vpn allow iphone core 22/tcp 53/both`. Without an allow, a device reaches nothing.
    ///
    /// Use `exit` as a target to add an exit through that agent's connection
    /// (`rift vpn allow iphone core exit`), or alone to add the exit through this server
    /// (`rift vpn allow iphone exit`). A device can have both and several agent exits; each
    /// is its own WireGuard profile (`rift vpn config qr iphone core`), and the device
    /// switches between them in the WireGuard app.
    Allow(VpnAccessArgs),
    /// Withdraw access again. Without a target, withdraws all of it on that agent, including
    /// the exit through it. `rift vpn deny DEVICE exit` ends the exit through this server and
    /// `rift vpn deny DEVICE AGENT exit` only the one through that agent.
    Deny(VpnAccessArgs),
    /// Export the WireGuard configuration of a device: its main profile, or with an agent
    /// name the profile of the exit through that agent.
    Config {
        #[command(subcommand)]
        command: VpnConfig,
    },
}
#[derive(Subcommand)]
enum VpnConfig {
    /// Print the configuration, which contains the device's private key: `rift vpn config
    /// export DEVICE` for the main profile, `... DEVICE AGENT` for the exit through an agent.
    Export {
        name: String,
        /// The agent whose exit profile to print.
        agent: Option<String>,
    },
    /// Print the configuration as a QR code for the WireGuard app.
    Qr {
        name: String,
        /// The agent whose exit profile to print.
        agent: Option<String>,
    },
}
#[derive(Args)]
struct VpnAccessArgs {
    /// Device name.
    peer: String,
    /// The agent, then what to allow: PORT/tcp, PORT/udp or PORT/both (ranges like
    /// 8000-8010/tcp), `server`, `full`, a network behind the agent such as 192.168.178.0/24,
    /// or `exit`. Several are allowed. Just `exit` means the exit through this server.
    #[arg(value_name = "AGENT TARGET", required = true, num_args = 1..)]
    rest: Vec<String>,
    /// Masquerade the device's address on the agent, for LANs without a route to the VPN pool.
    #[arg(long)]
    snat: bool,
}
/// What a `vpn allow` or `vpn deny` command names.
#[derive(Debug, PartialEq, Eq)]
struct VpnPlan {
    agent: Option<String>,
    accesses: Vec<VpnAccess>,
    /// The internet exit this command adds or removes: the server, or the agent it names.
    exit: Option<Exit>,
}
impl VpnAccessArgs {
    fn plan(&self) -> Result<VpnPlan> {
        if self.rest == ["exit"] {
            return Ok(VpnPlan {
                agent: None,
                accesses: Vec::new(),
                exit: Some(Exit::Server),
            });
        }
        let agent = self.rest[0].clone();
        anyhow::ensure!(
            agent != "exit",
            "name the agent first: `rift vpn allow DEVICE AGENT ... exit`. The exit through this server is `rift vpn allow DEVICE exit` on its own"
        );
        let exit = self.rest[1..].iter().any(|t| t == "exit");
        Ok(VpnPlan {
            accesses: self.accesses(&self.rest[1..])?,
            exit: exit.then(|| Exit::Agent(agent.clone())),
            agent: Some(agent),
        })
    }
    fn accesses(&self, targets: &[String]) -> Result<Vec<VpnAccess>> {
        let (mut server, mut full) = (false, false);
        let (mut ports, mut subnets) = (Vec::new(), Vec::new());
        for target in targets {
            match target.as_str() {
                "exit" => {}
                "server" => server = true,
                "full" => full = true,
                t if t
                    .split('/')
                    .nth(1)
                    .is_some_and(|p| !p.chars().all(|c| c.is_ascii_digit())) =>
                {
                    ports.push(t.to_string())
                }
                t => subnets.push(t.parse::<Ipv4Net>().with_context(|| {
                    format!("{t:?} is not PORT/tcp|udp|both, server, full, internet or a network like 192.168.178.0/24")
                })?),
            }
        }
        anyhow::ensure!(
            !self.snat || !subnets.is_empty(),
            "--snat applies only to a network such as 192.168.178.0/24"
        );
        rift::vpn::accesses(server, full, &ports, &subnets, self.snat)
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
    /// Check config.toml and the environment and report the first error.
    Validate,
}
#[derive(Subcommand)]
enum ListWhat {
    /// Agents with their state and tunnel addresses.
    Agents,
    /// Forwards with their state (enabled, disabled, pending or refused).
    Forwards,
    /// Active bans of translated forwards.
    Bans,
    /// VPN devices.
    Devices,
    /// Sites (host command only).
    Sites,
}
#[derive(Subcommand)]
enum ShowWhat {
    /// Every stored detail of one agent.
    Agent { name: String },
}
#[derive(Subcommand)]
enum AddWhat {
    /// Create an agent and print its single-use invitation.
    Agent {
        name: String,
        #[arg(long, default_value = "15m")]
        ttl: String,
    },
    /// Publish ports: AGENT SPEC..., where SPEC is LISTEN[:TARGET]/tcp|udp|both with an optional
    /// /v4 (default), /v6 or /all for the server address, for example
    /// `rift add forward node1 53/both 8080:80/tcp/all`.
    Forward {
        agent: String,
        /// LISTEN[:TARGET]/tcp|udp|both, optionally ending in /v4, /v6 or /all.
        #[arg(value_name = "SPEC", required = true)]
        specs: Vec<String>,
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
    /// Block an original client address for a translated forward.
    Ban {
        agent: String,
        forward_id: u64,
        ip: IpAddr,
        #[arg(long, default_value = "1h")]
        ttl: String,
    },
    /// Register a VPN device.
    Device { name: String },
    /// Publish a domain through the reverse proxy (host command only).
    Site {
        agent: String,
        host: String,
        port: u16,
        /// traefik, caddy, nginx or npm; default: the one `rift proxy` shows.
        proxy: Option<String>,
    },
}
#[derive(Subcommand)]
enum RemoveWhat {
    /// Delete an agent with its forwards and VPN grants.
    Agent { name: String },
    /// Cancel an open invitation.
    Invite { name: String },
    /// Delete a forward by its ID.
    Forward { id: u64 },
    /// Delete the device, its key and its grants. This cannot be undone.
    Device { name: String },
    /// Remove a site (host command only).
    Site { host: String },
}
#[derive(Subcommand)]
enum ToggleWhat {
    /// An agent with all its forwards and VPN grants.
    Agent { name: String },
    /// One forward by its ID.
    Forward { id: u64 },
    /// A VPN device; it keeps its key and grants.
    Device { name: String },
}
#[derive(Subcommand)]
enum RenameWhat {
    /// Give an agent a new name.
    Agent { name: String, new_name: String },
}
#[derive(Subcommand)]
enum RotateWhat {
    /// Give an agent a new WireGuard key on its next sync.
    Agent { name: String },
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
        Command::Add {
            what: AddWhat::Agent { .. }
        }
    );
    // Further forwards of one short-form `add forward`, sent after the first one.
    let mut more: Vec<AdminRequest> = Vec::new();
    let request = match cli.command {
        Command::Server => return rift::daemon::run_server(config, cli.config).await,
        Command::Export { file } => return export_command(&config, cli.json, file).await,
        Command::Import(args) => return import_command(&config, cli.json, args).await,
        Command::Backup { file } => return backup_command(&config, cli.json, file),
        Command::Restore { .. } => bail!("restore replaces the state of the server and runs on the server host, not inside the container; run `sudo rift restore FILE` there"),
        Command::Agent => return rift::daemon::run_agent(config).await,
        Command::Doctor => {
            let mut result = rift::net::Kernel::new(config.clone()).doctor().await?;
            let mut checks = rift::net::Checks::default();
            server_checks(&config, &mut checks).await;
            if let Some(list) = result["checks"].as_array_mut() {
                list.extend(checks.0);
            }
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
            let (name, agent, qr) = match command {
                VpnConfig::Export { name, agent } => (name, agent, false),
                VpnConfig::Qr { name, agent } => (name, agent, true),
            };
            return vpn_config(&config, cli.json, name, agent, qr).await;
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
            Vpn::Allow(args) => {
                let mut requests = vpn_allow_requests(&args)?.into_iter();
                let first = requests.next().context(
                    "choose what to allow, for example: 22/tcp, server, full, 192.168.178.0/24 or internet",
                )?;
                more.extend(requests);
                first
            }
            Vpn::Deny(args) => {
                let mut requests = vpn_deny_requests(&args)?.into_iter();
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
        Command::List { what } => match what {
            ListWhat::Agents => AdminRequest::AgentsList,
            ListWhat::Forwards => AdminRequest::ForwardsList,
            ListWhat::Bans => AdminRequest::BansList,
            ListWhat::Devices => AdminRequest::VpnPeerList,
            ListWhat::Sites => bail!("sites are managed by the host command; run it on the server, not inside the container"),
        },
        Command::Show { what: ShowWhat::Agent { name } } => AdminRequest::AgentsShow { name },
        Command::Add { what } => match what {
            AddWhat::Agent { name, ttl } => AdminRequest::Invite {
                name,
                ttl_seconds: duration(&ttl)?,
            },
            AddWhat::Forward {
                agent,
                specs,
                listen_ip,
                target_family,
                mode,
                ingress,
            } => {
                let plans = parse_forward_specs(&specs)?;
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
            AddWhat::Ban {
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
            AddWhat::Device { name } => AdminRequest::VpnPeerAdd { name },
            AddWhat::Site { .. } => bail!("sites are managed by the host command; run it on the server, not inside the container"),
        },
        Command::Remove { what } => match what {
            RemoveWhat::Agent { name } => AdminRequest::AgentRemove { name },
            RemoveWhat::Invite { name } => AdminRequest::CancelInvite { name },
            RemoveWhat::Forward { id } => AdminRequest::ForwardRemove { id },
            RemoveWhat::Device { name } => AdminRequest::VpnPeerRevoke { name },
            RemoveWhat::Site { .. } => bail!("sites are managed by the host command; run it on the server, not inside the container"),
        },
        Command::Disable { what } => match what {
            ToggleWhat::Agent { name } => AdminRequest::AgentDisable { name },
            ToggleWhat::Forward { id } => AdminRequest::ForwardEnable { id, enabled: false },
            ToggleWhat::Device { name } => AdminRequest::VpnPeerEnable { name, enabled: false },
        },
        Command::Enable { what } => match what {
            ToggleWhat::Agent { name } => AdminRequest::AgentEnable { name },
            ToggleWhat::Forward { id } => AdminRequest::ForwardEnable { id, enabled: true },
            ToggleWhat::Device { name } => AdminRequest::VpnPeerEnable { name, enabled: true },
        },
        Command::Rename { what: RenameWhat::Agent { name, new_name } } => {
            AdminRequest::AgentRename { name, new_name }
        }
        Command::Rotate { what: RotateWhat::Agent { name } } => AdminRequest::AgentRotate { name },
        Command::Proxy { .. } => bail!("sites are managed by the host command; run it on the server, not inside the container"),
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
            .context("earlier parts of this command were already applied")?;
        if !response.ok {
            bail!(
                "{} (earlier parts of this command were already applied)",
                response.error.unwrap_or_else(|| "operation failed".into())
            );
        }
        show(&config, cli.json, false, &request, &response).await?;
    }
    Ok(())
}
/// The requests of `rift vpn allow`: the grants first, then the internet exit.
fn vpn_allow_requests(args: &VpnAccessArgs) -> Result<Vec<AdminRequest>> {
    let plan = args.plan()?;
    let mut requests = Vec::new();
    if let Some(agent) = &plan.agent {
        for access in plan.accesses {
            requests.push(AdminRequest::VpnAllow {
                peer: args.peer.clone(),
                agent: agent.clone(),
                access,
            });
        }
    }
    if let Some(exit) = plan.exit {
        requests.push(AdminRequest::VpnExit {
            peer: args.peer.clone(),
            exit,
        });
    }
    Ok(requests)
}
/// The requests of `rift vpn deny`. Without any target, everything on the agent goes.
fn vpn_deny_requests(args: &VpnAccessArgs) -> Result<Vec<AdminRequest>> {
    let plan = args.plan()?;
    let mut requests = Vec::new();
    if plan.accesses.is_empty() && plan.exit.is_none() {
        requests.push(AdminRequest::VpnDeny {
            peer: args.peer.clone(),
            agent: plan
                .agent
                .clone()
                .context("name the agent whose access to withdraw")?,
            access: None,
        });
    }
    if let Some(agent) = &plan.agent {
        for access in plan.accesses {
            requests.push(AdminRequest::VpnDeny {
                peer: args.peer.clone(),
                agent: agent.clone(),
                access: Some(access),
            });
        }
    }
    if let Some(exit) = plan.exit {
        requests.push(AdminRequest::VpnExitClear {
            peer: args.peer.clone(),
            agent: match exit {
                Exit::Agent(agent) => Some(agent),
                _ => None,
            },
        });
    }
    Ok(requests)
}
fn dated(prefix: &str, suffix: &str) -> PathBuf {
    format!(
        "{prefix}-{}.{suffix}",
        time::OffsetDateTime::now_utc().date()
    )
    .into()
}
async fn export_command(config: &Config, json: bool, file: Option<PathBuf>) -> Result<()> {
    let data = admin_ok(config, AdminRequest::Export).await?;
    let export: rift::portable::Export = serde_json::from_value(data)?;
    let text = serde_json::to_string_pretty(&export)? + "\n";
    let grants: usize = export.devices.iter().map(|d| d.grants.len()).sum();
    let summary = format!(
        "{} agent(s), {} forward(s), {} device(s) with {grants} grant(s)",
        export.agents.len(),
        export.forwards.len(),
        export.devices.len()
    );
    if file.as_deref() == Some(std::path::Path::new("-")) {
        print!("{text}");
        eprintln!("Exported {summary}.");
        return Ok(());
    }
    let path = file.unwrap_or_else(|| dated("rift-export", "json"));
    std::fs::write(&path, text).with_context(|| format!("write {}", path.display()))?;
    if json {
        println!(
            "{}",
            serde_json::json!({"file":path,"agents":export.agents.len(),"forwards":export.forwards.len(),"devices":export.devices.len(),"grants":grants})
        );
    } else {
        println!(
            "{}\nExported {summary}. It holds no keys or tokens.",
            path.display()
        );
    }
    Ok(())
}
async fn import_command(config: &Config, json: bool, args: ImportArgs) -> Result<()> {
    let bytes = if args.file == std::path::Path::new("-") {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut bytes)?;
        bytes
    } else {
        std::fs::read(&args.file).with_context(|| format!("read {}", args.file.display()))?
    };
    let data = rift::portable::Export::parse(&bytes)?;
    let sites = data.sites.len();
    let options = rift::portable::ImportOptions {
        agents: args.agents,
        skip_agents: args.skip_agents,
        map: args.map,
        dry_run: args.dry_run,
    };
    let report = admin_ok(config, AdminRequest::Import { data, options }).await?;
    if json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!("{}", output::import_report(&report)?);
        if sites > 0 {
            eprintln!("The file lists {sites} site(s). Sites are imported by the host command: run `sudo rift import` on the server.");
        }
    }
    Ok(())
}
fn backup_command(config: &Config, json: bool, file: Option<PathBuf>) -> Result<()> {
    let to_stdout = file.as_deref() == Some(std::path::Path::new("-"));
    let path = if to_stdout {
        None
    } else {
        Some(file.unwrap_or_else(|| dated("rift-backup", "tar.gz")))
    };
    rift::backup::write(config, path.as_deref())?;
    if let Some(path) = path {
        if json {
            println!("{}", serde_json::json!({"file":path}));
        } else {
            println!("{}", path.display());
        }
    }
    eprintln!("This backup contains every key of this server. Keep it private.");
    Ok(())
}
async fn server_checks(config: &Config, checks: &mut rift::net::Checks) {
    use rift::net::{FAIL, OK, WARN};
    if config.public_ips.is_empty() && config.public_endpoint.is_empty() {
        return;
    }
    let Ok(status) = admin_ok(config, AdminRequest::Status).await else {
        checks.push(
            FAIL,
            "RIFT server".into(),
            "not reachable on its admin socket; is the container running?".into(),
        );
        return;
    };
    match status["apply_error"].as_str() {
        Some(error) => checks.push(
            FAIL,
            "Configuration".into(),
            format!("not applied: {error}"),
        ),
        None => checks.push(OK, "Configuration".into(), "applied".into()),
    }
    for agent in status["agent_health"].as_array().into_iter().flatten() {
        let name = agent["name"].as_str().unwrap_or("?");
        let online = agent["online"].as_bool() == Some(true);
        let ready = agent["configuration_ready"].as_bool() == Some(true);
        let (state, detail) = match (online, ready) {
            (true, true) => (OK, "online and up to date".to_string()),
            (true, false) => (
                WARN,
                "online but has not applied the latest configuration; are both sides on the same version?".into(),
            ),
            (false, _) => (WARN, "offline; check the agent's container and logs".into()),
        };
        checks.push(state, format!("Agent {name}"), detail);
        if let Some(error) = agent["last_error"].as_str() {
            checks.push(WARN, format!("Agent {name}"), error.to_string());
        }
    }
    exit_checks(config, &status, checks);
    for refused in status["refused_forwards"].as_array().into_iter().flatten() {
        checks.push(
            WARN,
            format!("Forward {}", refused["id"]),
            refused["reason"].as_str().unwrap_or("refused").to_string(),
        );
    }
    for stuck in status["inapplicable_forwards"]
        .as_array()
        .into_iter()
        .flatten()
    {
        checks.push(
            WARN,
            format!("Forward {}", stuck["id"]),
            stuck["reason"]
                .as_str()
                .unwrap_or("not applicable")
                .to_string(),
        );
    }
    if config.webpanel {
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], config.webpanel_port));
        let up = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(address),
        )
        .await
        .is_ok_and(|c| c.is_ok());
        checks.push(
            if up { OK } else { FAIL },
            "Web panel".into(),
            if up {
                format!("answers on port {}", config.webpanel_port)
            } else {
                format!("nothing answers on 127.0.0.1:{}", config.webpanel_port)
            },
        );
    }
}
/// The internet exits in use: how many devices, whether the VPS carries IPv6 for them, and
/// whether each agent they use has what it needs.
fn exit_checks(config: &Config, status: &serde_json::Value, checks: &mut rift::net::Checks) {
    use rift::net::{OK, WARN};
    let empty = Vec::new();
    let devices = status["snapshot"]["vpn_peers"].as_array().unwrap_or(&empty);
    let enabled = |p: &&serde_json::Value| p["enabled"].as_bool() == Some(true);
    let via_server = devices
        .iter()
        .filter(enabled)
        .filter(|p| p["server_exit"].as_bool() == Some(true))
        .count();
    // One entry per agent exit of an enabled device: the agent's ID.
    let via_agents: Vec<&serde_json::Value> = devices
        .iter()
        .filter(enabled)
        .flat_map(|p| p["agent_exits"].as_array().unwrap_or(&empty))
        .collect();
    if via_server + via_agents.len() == 0 {
        return;
    }
    checks.push(
        OK,
        "Internet exits".into(),
        format!(
            "{via_server} device(s) via this server, {} exit(s) via agents",
            via_agents.len()
        ),
    );
    if via_server > 0 {
        let ipv6 = config.public_ips.iter().any(IpAddr::is_ipv6);
        checks.push(
            if ipv6 { OK } else { WARN },
            "Server exit IPv6".into(),
            if ipv6 {
                "the IPv6 address in RIFT_PUBLIC_IPS carries the devices' IPv6 traffic".into()
            } else {
                "RIFT_PUBLIC_IPS has no IPv6 address: devices exiting here get no IPv6 (it is dropped, not leaked)".into()
            },
        );
    }
    for agent in status["snapshot"]["agents"].as_array().unwrap_or(&empty) {
        let id = &agent["id"];
        if !via_agents.contains(&id) {
            continue;
        }
        let name = agent["name"].as_str().unwrap_or("?");
        let problem = if agent["limits"]["exit"].as_bool() == Some(false) {
            Some("refuses the exit: set RIFT_AGENT_ALLOW_EXIT=true on the agent")
        } else if agent["exit"].is_null() {
            Some("has not reported its exit key yet; is it online and RIFT_AGENT_ALLOW_EXIT=true?")
        } else {
            None
        };
        match problem {
            Some(problem) => checks.push(WARN, format!("Exit via agent {name}"), problem.into()),
            None => checks.push(
                OK,
                format!("Exit via agent {name}"),
                if agent["exit"]["ipv6"].as_bool() == Some(true) {
                    "ready, with IPv6".into()
                } else {
                    "ready; the agent host has no global IPv6, so the devices' IPv6 is dropped"
                        .into()
                },
            ),
        }
    }
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
    vpn_config(config, json, name, None, !export).await?;
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
async fn vpn_config(
    config: &Config,
    json: bool,
    name: String,
    agent: Option<String>,
    qr: bool,
) -> Result<()> {
    let data = admin_ok(config, AdminRequest::VpnConfig { name, agent }).await?;
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
            vec!["rift", "add", "device", "iphone"],
            vec!["rift", "list", "devices"],
            vec!["rift", "enable", "device", "iphone"],
            vec!["rift", "disable", "device", "iphone"],
            vec!["rift", "remove", "device", "iphone"],
            vec!["rift", "vpn", "allow", "iphone", "home", "server"],
            vec![
                "rift", "vpn", "allow", "iphone", "home", "22/tcp", "53/both",
            ],
            vec![
                "rift",
                "vpn",
                "allow",
                "iphone",
                "home",
                "192.168.178.0/24",
                "--snat",
            ],
            vec!["rift", "vpn", "deny", "iphone", "home"],
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
        // --snat only makes sense together with a network.
        let snat =
            Cli::try_parse_from(["rift", "vpn", "allow", "iphone", "home", "server", "--snat"])
                .unwrap();
        let Command::Vpn {
            command: Vpn::Allow(args),
        } = snat.command
        else {
            unreachable!()
        };
        assert!(args.plan().is_err());
    }
    fn vpn_plan(argv: &[&str]) -> Option<Result<VpnPlan>> {
        match Cli::try_parse_from(argv).map(|c| c.command) {
            Ok(Command::Vpn {
                command: Vpn::Allow(args) | Vpn::Deny(args),
            }) => Some(args.plan()),
            _ => None,
        }
    }
    fn vpn_requests(argv: &[&str]) -> Result<Vec<AdminRequest>> {
        match Cli::try_parse_from(argv).unwrap().command {
            Command::Vpn {
                command: Vpn::Allow(args),
            } => vpn_allow_requests(&args),
            Command::Vpn {
                command: Vpn::Deny(args),
            } => vpn_deny_requests(&args),
            _ => unreachable!(),
        }
    }
    #[test]
    fn vpn_short_form_names_device_agent_and_targets() {
        let plan = vpn_plan(&[
            "rift",
            "vpn",
            "allow",
            "iphone",
            "core",
            "22/tcp",
            "53/both",
            "server",
            "192.168.178.0/24",
            "--snat",
        ])
        .unwrap()
        .unwrap();
        assert_eq!(plan.agent.as_deref(), Some("core"));
        assert_eq!(plan.exit, None);
        assert_eq!(
            plan.accesses,
            vec![
                VpnAccess::Server,
                VpnAccess::Port {
                    protocol: Protocol::Tcp,
                    ports: "22".parse().unwrap()
                },
                VpnAccess::Port {
                    protocol: Protocol::Tcp,
                    ports: "53".parse().unwrap()
                },
                VpnAccess::Port {
                    protocol: Protocol::Udp,
                    ports: "53".parse().unwrap()
                },
                VpnAccess::Subnet {
                    net: "192.168.178.0/24".parse().unwrap(),
                    snat: true
                },
            ]
        );
        // Without targets, deny withdraws everything on that agent.
        let plan = vpn_plan(&["rift", "vpn", "deny", "iphone", "core"])
            .unwrap()
            .unwrap();
        assert_eq!(plan.agent.as_deref(), Some("core"));
        assert!(plan.accesses.is_empty() && plan.exit.is_none());
        assert!(vpn_plan(&["rift", "vpn", "allow", "iphone", "core", "22"])
            .unwrap()
            .is_err());
        assert!(vpn_plan(&["rift", "vpn", "allow", "iphone", "core", "nas"])
            .unwrap()
            .is_err());
        // The agent is required and the old long options are gone.
        assert!(vpn_plan(&["rift", "vpn", "allow", "iphone"]).is_none());
        assert!(vpn_plan(&["rift", "vpn", "allow", "iphone", "core", "--server"]).is_none());
        assert!(
            vpn_plan(&["rift", "vpn", "allow", "iphone", "--agent", "core", "server"]).is_none()
        );
    }
    #[test]
    fn internet_selects_the_exit_through_the_server_or_an_agent() {
        // Alone: the VPS.
        let plan = vpn_plan(&["rift", "vpn", "allow", "iphone", "exit"])
            .unwrap()
            .unwrap();
        assert_eq!(
            plan,
            VpnPlan {
                agent: None,
                accesses: vec![],
                exit: Some(Exit::Server)
            }
        );
        // After an agent: that agent, and it may come with grants.
        let plan = vpn_plan(&["rift", "vpn", "allow", "iphone", "core", "exit"])
            .unwrap()
            .unwrap();
        assert_eq!(plan.exit, Some(Exit::Agent("core".into())));
        assert!(plan.accesses.is_empty());
        let requests =
            vpn_requests(&["rift", "vpn", "allow", "iphone", "core", "22/tcp", "exit"]).unwrap();
        assert_eq!(requests.len(), 2, "the grant, then the exit");
        assert!(matches!(
            &requests[0],
            AdminRequest::VpnAllow { agent, .. } if agent == "core"
        ));
        assert!(matches!(
            &requests[1],
            AdminRequest::VpnExit { peer, exit: Exit::Agent(agent) } if peer == "iphone" && agent == "core"
        ));
        let requests = vpn_requests(&["rift", "vpn", "allow", "iphone", "exit"]).unwrap();
        assert!(matches!(
            requests.as_slice(),
            [AdminRequest::VpnExit {
                exit: Exit::Server,
                ..
            }]
        ));
        // `internet` first with more behind it is ambiguous.
        assert!(
            vpn_plan(&["rift", "vpn", "allow", "iphone", "exit", "22/tcp"])
                .unwrap()
                .is_err()
        );
        // Allowing nothing is an error the command reports; the agent alone allows nothing.
        assert!(vpn_requests(&["rift", "vpn", "allow", "iphone", "core"])
            .unwrap()
            .is_empty());
    }
    #[test]
    fn deny_internet_clears_only_the_named_exit() {
        let requests = vpn_requests(&["rift", "vpn", "deny", "iphone", "exit"]).unwrap();
        assert!(matches!(
            requests.as_slice(),
            [AdminRequest::VpnExitClear { agent: None, .. }]
        ));
        let requests = vpn_requests(&["rift", "vpn", "deny", "iphone", "core", "exit"]).unwrap();
        assert!(matches!(
            requests.as_slice(),
            [AdminRequest::VpnExitClear { agent: Some(a), .. }] if a == "core"
        ));
        // Without targets everything on the agent goes; with some, only those.
        let requests = vpn_requests(&["rift", "vpn", "deny", "iphone", "core"]).unwrap();
        assert!(matches!(
            requests.as_slice(),
            [AdminRequest::VpnDeny { access: None, .. }]
        ));
        let requests =
            vpn_requests(&["rift", "vpn", "deny", "iphone", "core", "22/tcp", "exit"]).unwrap();
        assert_eq!(requests.len(), 2);
    }
    #[test]
    fn exits_add_up_and_come_off_one_at_a_time() {
        // Several exits are added with separate commands; none replaces another.
        let exits = |argv: &[&str]| {
            vpn_requests(argv)
                .unwrap()
                .into_iter()
                .map(|r| match r {
                    AdminRequest::VpnExit { exit, .. } => format!("add {exit:?}"),
                    AdminRequest::VpnExitClear { agent, .. } => format!("remove {agent:?}"),
                    AdminRequest::VpnDeny { access: None, .. } => "deny all".to_string(),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            exits(&["rift", "vpn", "allow", "iphone", "exit"]),
            ["add Server"]
        );
        assert_eq!(
            exits(&["rift", "vpn", "allow", "iphone", "core2", "exit"]),
            [r#"add Agent("core2")"#]
        );
        assert_eq!(
            exits(&["rift", "vpn", "deny", "iphone", "exit"]),
            ["remove None"]
        );
        assert_eq!(
            exits(&["rift", "vpn", "deny", "iphone", "core2", "exit"]),
            [r#"remove Some("core2")"#]
        );
        assert_eq!(
            exits(&["rift", "vpn", "deny", "iphone", "core2"]),
            ["deny all"]
        );
        // The profiles: the main one, or that of an agent's exit.
        let config = |argv: &[&str]| match Cli::try_parse_from(argv).unwrap().command {
            Command::Vpn {
                command:
                    Vpn::Config {
                        command: VpnConfig::Export { name, agent } | VpnConfig::Qr { name, agent },
                    },
            } => (name, agent),
            _ => unreachable!(),
        };
        assert_eq!(
            config(&["rift", "vpn", "config", "qr", "iphone"]),
            ("iphone".into(), None)
        );
        assert_eq!(
            config(&["rift", "vpn", "config", "export", "iphone", "core"]),
            ("iphone".into(), Some("core".into()))
        );
        assert!(Cli::try_parse_from(["rift", "vpn", "config", "qr", "iphone", "a", "b"]).is_err());
    }
    #[test]
    fn vpn_targets_become_accesses() {
        let args = |extra: &[&str]| {
            let mut argv = vec!["rift", "vpn", "allow", "iphone", "home"];
            argv.extend(extra);
            vpn_plan(&argv).unwrap().map(|plan| plan.accesses)
        };
        assert!(args(&[]).unwrap().is_empty());
        assert_eq!(args(&["53/both"]).unwrap().len(), 2);
        assert!(args(&["22:80/tcp"]).is_err());
        assert!(args(&["22"]).is_err());
        assert_eq!(
            args(&["192.168.178.0/24", "--snat"]).unwrap(),
            vec![VpnAccess::Subnet {
                net: "192.168.178.0/24".parse().unwrap(),
                snat: true
            }]
        );
    }
    #[test]
    fn doctor_reports_exits_and_what_each_agent_still_needs() {
        let status = serde_json::json!({"snapshot":{
            "agents":[
                {"id":"a","name":"core","limits":{"exit":true},"exit":{"ipv6":false}},
                {"id":"b","name":"cabin","limits":{"exit":false},"exit":null},
                {"id":"c","name":"idle","limits":{"exit":false},"exit":null}],
            "vpn_peers":[
                {"enabled":true,"server_exit":true,"agent_exits":["a"]},
                {"enabled":true,"server_exit":false,"agent_exits":["a","b"]},
                {"enabled":false,"server_exit":false,"agent_exits":["c"]},
                {"enabled":true,"server_exit":false,"agent_exits":[]}]}});
        let run = |config: &Config| {
            let mut checks = rift::net::Checks::default();
            exit_checks(config, &status, &mut checks);
            checks
                .0
                .iter()
                .map(|c| {
                    format!(
                        "{} {}: {}",
                        c["status"].as_str().unwrap(),
                        c["check"].as_str().unwrap(),
                        c["detail"].as_str().unwrap()
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        let v4 = Config {
            public_ips: vec!["203.0.113.10".parse().unwrap()],
            ..Default::default()
        };
        let text = run(&v4);
        assert!(
            text.contains("1 device(s) via this server, 3 exit(s) via agents"),
            "{text}"
        );
        assert!(text.contains("warn Server exit IPv6"), "{text}");
        assert!(
            text.contains("ok Exit via agent core: ready; the agent host has no global IPv6"),
            "{text}"
        );
        assert!(
            text.contains("warn Exit via agent cabin: refuses the exit"),
            "{text}"
        );
        assert!(
            !text.contains("idle"),
            "a disabled device does not count: {text}"
        );
        let v6 = Config {
            public_ips: vec![
                "203.0.113.10".parse().unwrap(),
                "2001:db8::10".parse().unwrap(),
            ],
            ..Default::default()
        };
        assert!(run(&v6).contains("ok Server exit IPv6"));
        let mut none = rift::net::Checks::default();
        exit_checks(
            &v4,
            &serde_json::json!({"snapshot":{"vpn_peers":[]}}),
            &mut none,
        );
        assert!(none.0.is_empty(), "nothing to report without exits");
    }
    #[test]
    fn documented_cli_parses() {
        for args in [
            vec!["rift", "add", "forward", "nas", "2222:22/tcp"],
            vec![
                "rift",
                "add",
                "forward",
                "nas",
                "53/both",
                "8080:80/tcp/all",
            ],
            vec![
                "rift",
                "add",
                "forward",
                "nas",
                "8080/tcp",
                "--listen-ip",
                "203.0.113.10",
            ],
        ] {
            Cli::try_parse_from(&args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
    }
    #[test]
    fn translation_is_explicit() {
        Cli::try_parse_from([
            "rift",
            "add",
            "forward",
            "core",
            "443/tcp",
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
    fn forwards_need_an_agent_and_a_spec_and_the_long_form_is_gone() {
        Cli::try_parse_from(["rift", "add", "forward", "node1", "53/both"]).unwrap();
        assert!(Cli::try_parse_from(["rift", "add", "forward"]).is_err());
        assert!(Cli::try_parse_from(["rift", "add", "forward", "node1"]).is_err());
        for long in ["--agent", "--listen", "--target", "--protocol"] {
            assert!(
                Cli::try_parse_from(["rift", "add", "forward", "node1", "80/tcp", long, "x"])
                    .is_err(),
                "{long}"
            );
        }
    }
    #[test]
    fn rejects_invalid_range() {
        assert!(parse_forward_specs(&["0:22/tcp".into()]).is_err());
    }
    #[test]
    fn local_ingress_is_explicit() {
        let cli = Cli::try_parse_from([
            "rift",
            "add",
            "forward",
            "core",
            "20000:8081/tcp",
            "--ingress",
            "local",
        ])
        .unwrap();
        let Command::Add {
            what: AddWhat::Forward { ingress, .. },
        } = cli.command
        else {
            panic!("add forward");
        };
        assert_eq!(ingress, "local");
    }
    #[test]
    fn verb_first_commands_parse() {
        for args in [
            vec!["rift", "list", "agents"],
            vec!["rift", "list", "forwards"],
            vec!["rift", "list", "bans"],
            vec!["rift", "list", "devices"],
            vec!["rift", "show", "agent", "core"],
            vec!["rift", "add", "agent", "core"],
            vec!["rift", "add", "agent", "core", "--ttl", "15m"],
            vec!["rift", "remove", "invite", "core"],
            vec!["rift", "remove", "agent", "core"],
            vec!["rift", "disable", "agent", "core"],
            vec!["rift", "enable", "agent", "core"],
            vec!["rift", "rename", "agent", "core", "home"],
            vec!["rift", "rotate", "agent", "core"],
            vec!["rift", "remove", "forward", "3"],
            vec!["rift", "disable", "forward", "3"],
            vec!["rift", "enable", "forward", "3"],
            vec![
                "rift",
                "add",
                "ban",
                "core",
                "3",
                "203.0.113.9",
                "--ttl",
                "1h",
            ],
            vec!["rift", "add", "ban", "core", "3", "203.0.113.9"],
            vec!["rift", "list", "sites"],
            vec!["rift", "add", "site", "core", "app.example.org", "8080"],
            vec!["rift", "remove", "site", "app.example.org"],
            vec!["rift", "proxy"],
            vec!["rift", "proxy", "caddy"],
        ] {
            Cli::try_parse_from(&args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
        let cli = Cli::try_parse_from(["rift", "add", "ban", "core", "3", "203.0.113.9"]).unwrap();
        let Command::Add {
            what:
                AddWhat::Ban {
                    agent,
                    forward_id,
                    ttl,
                    ..
                },
        } = cli.command
        else {
            panic!("add ban");
        };
        assert_eq!(
            (agent.as_str(), forward_id, ttl.as_str()),
            ("core", 3, "1h")
        );
        let cli = Cli::try_parse_from(["rift", "remove", "forward", "7"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Remove {
                what: RemoveWhat::Forward { id: 7 }
            }
        ));
        assert!(Cli::try_parse_from(["rift", "remove", "forward", "--id", "7"]).is_err());
        assert!(Cli::try_parse_from(["rift", "remove", "forward", "x"]).is_err());
    }
    #[test]
    fn old_command_forms_are_gone() {
        for args in [
            vec!["rift", "forwards", "list"],
            vec!["rift", "agents", "add", "x"],
            vec!["rift", "agents", "list"],
            vec!["rift", "bans", "list"],
            vec!["rift", "vpn", "peer", "list"],
            vec!["rift", "site", "list"],
        ] {
            assert!(Cli::try_parse_from(&args).is_err(), "{args:?}");
        }
    }
    #[test]
    fn export_import_backup_and_restore_parse() {
        for args in [
            vec!["rift", "export"],
            vec!["rift", "export", "mine.json"],
            vec!["rift", "backup"],
            vec!["rift", "backup", "-"],
            vec!["rift", "restore", "b.tar.gz"],
            vec!["rift", "restore", "b.tar.gz", "--yes"],
            vec!["rift", "import", "mine.json"],
            vec!["rift", "import", "-", "--dry-run"],
        ] {
            Cli::try_parse_from(&args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
        let cli = Cli::try_parse_from([
            "rift",
            "import",
            "f.json",
            "--agent",
            "core",
            "--agent",
            "nas",
            "--skip-agent",
            "core2",
            "--map",
            "core2=core",
            "--map",
            "a=b",
            "--dry-run",
        ])
        .unwrap();
        let Command::Import(args) = cli.command else {
            panic!("import");
        };
        assert_eq!(args.agents, ["core", "nas"]);
        assert_eq!(args.skip_agents, ["core2"]);
        assert_eq!(
            args.map,
            [("core2".into(), "core".into()), ("a".into(), "b".into())]
        );
        assert!(args.dry_run);
        for bad in ["core2", "=core", "core2=", "a=b=c"] {
            assert!(
                Cli::try_parse_from(["rift", "import", "f.json", "--map", bad]).is_err(),
                "{bad}"
            );
        }
        assert!(Cli::try_parse_from(["rift", "import"]).is_err());
        assert!(Cli::try_parse_from(["rift", "restore"]).is_err());
    }
}
