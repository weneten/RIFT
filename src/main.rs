use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use rift::{config::Config, model::*, protocol::AdminRequest};
use std::{net::IpAddr, path::PathBuf};

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
    Add {
        #[arg(long)]
        agent: String,
        #[arg(long)]
        listen: PortRange,
        #[arg(long)]
        target: PortRange,
        #[arg(long, default_value = "tcp")]
        protocol: Protocol,
        #[arg(long)]
        listen_ip: Option<IpAddr>,
        #[arg(long,value_parser=["v4","v6"])]
        target_family: Option<String>,
        #[arg(long,default_value="transparent",value_parser=["transparent","translate"])]
        mode: String,
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
    let request = match cli.command {
        Command::Server => return rift::daemon::run_server(config, cli.config).await,
        Command::Agent => return rift::daemon::run_agent(config).await,
        Command::Doctor => {
            let result = rift::net::Kernel::new(config).doctor().await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }
        Command::Config {
            command: ConfigCommand::Validate,
        } => {
            println!("Configuration valid: {}", cli.config.display());
            return Ok(());
        }
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
        Command::Forwards { command } => {
            match command {
                Forwards::List => AdminRequest::ForwardsList,
                Forwards::Remove { id } => AdminRequest::ForwardRemove { id },
                Forwards::Disable { id } => AdminRequest::ForwardEnable { id, enabled: false },
                Forwards::Enable { id } => AdminRequest::ForwardEnable { id, enabled: true },
                Forwards::Add {
                    agent,
                    listen,
                    target,
                    protocol,
                    listen_ip,
                    target_family,
                    mode,
                } => {
                    let ip = listen_ip.or_else(|| if config.public_ips.len() == 1 { config.public_ips.first().copied() } else { None }).context("use --listen-ip when the VPS has zero or multiple configured public IPs")?;
                    let family = match target_family.as_deref() {
                        Some("v4") => Family::V4,
                        Some("v6") => Family::V6,
                        _ => Family::of(ip),
                    };
                    let forward = Forward {
                        id: 0,
                        agent_id: agent,
                        listen_ip: ip,
                        listen_ports: listen,
                        target_ports: target,
                        protocol,
                        mode: if mode == "translate" {
                            ForwardMode::Translate
                        } else {
                            ForwardMode::Transparent
                        },
                        target_family: family,
                        enabled: true,
                        generation: 0,
                    };
                    forward.validate()?;
                    AdminRequest::ForwardAdd(forward)
                }
            }
        }
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
    let response = rift::daemon::admin_call(&config, request).await?;
    if !response.ok {
        bail!(
            "{}",
            response.error.unwrap_or_else(|| "operation failed".into())
        );
    }
    if cli.json {
        println!("{}", serde_json::to_string(&response.data)?);
    } else if invitation {
        println!(
            "RIFT_SERVER={}\nRIFT_AGENT_NAME={}\nRIFT_ENROLLMENT_TOKEN={}",
            response.data["server"].as_str().unwrap_or_default(),
            response.data["name"].as_str().unwrap_or_default(),
            response.data["token"].as_str().unwrap_or_default()
        );
        eprintln!("Copy these values into the agent's private .env file. This invitation is single-use and expires.");
    } else {
        println!("{}", serde_json::to_string_pretty(&response.data)?);
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
    fn rejects_invalid_range() {
        assert!(Cli::try_parse_from([
            "rift", "forwards", "add", "--agent", "core", "--listen", "0", "--target", "22"
        ])
        .is_err());
    }
}
