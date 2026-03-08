mod commands;
mod config;

use clap::{Parser, Subcommand};
use commands::OutputFormat;

#[derive(Parser)]
#[command(name = "ion-drift", version, about = "Mikrotik RouterOS management CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Router hostname or IP (overrides config file)
    #[arg(long, global = true)]
    host: Option<String>,

    /// Router API port
    #[arg(long, global = true)]
    port: Option<u16>,

    /// RouterOS username (overrides config file)
    #[arg(long, short = 'u', global = true)]
    user: Option<String>,

    /// RouterOS password (prefer DRIFT_ROUTER_PASSWORD env var)
    #[arg(long, short = 'p', global = true)]
    password: Option<String>,

    /// Path to CA certificate for TLS verification
    #[arg(long, global = true)]
    ca_cert: Option<String>,

    /// Path to config file
    #[arg(long, global = true)]
    config: Option<String>,

    /// Output format
    #[arg(long, global = true, default_value = "table", value_enum)]
    format: OutputFormat,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// System information and identity
    #[command(subcommand)]
    System(commands::system::SystemCommand),

    /// List and inspect interfaces
    #[command(subcommand)]
    Interfaces(commands::interfaces::InterfacesCommand),

    /// IP addresses, routes, DHCP
    #[command(subcommand)]
    Ip(commands::ip::IpCommand),

    /// Firewall filter, NAT, and mangle rules
    #[command(subcommand)]
    Firewall(commands::firewall::FirewallCommand),

    /// View system logs
    Log(commands::logs::LogCommand),

    /// Show lifetime WAN traffic counters
    Traffic(commands::traffic::TrafficCommand),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Disable color if requested, if NO_COLOR env is set, or if not a terminal
    let no_color = cli.no_color
        || std::env::var("NO_COLOR").is_ok()
        || !std::io::IsTerminal::is_terminal(&std::io::stdout());

    if let Err(e) = run(cli, no_color).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Data directory for SQLite databases (traffic).
fn data_dir() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("ion-drift")
}

async fn run(cli: Cli, no_color: bool) -> anyhow::Result<()> {
    let data_dir = data_dir();
    std::fs::create_dir_all(&data_dir)?;

    // All commands need a router connection
    let config_path = cli.config
        .map(std::path::PathBuf::from)
        .unwrap_or_else(config::CliConfig::default_path);
    let file_cfg = config::CliConfig::load(&config_path)
        .map_err(|e| anyhow::anyhow!(e))?;

    let mk_config = config::build_mikrotik_config(
        &file_cfg,
        cli.host.as_deref(),
        cli.user.as_deref(),
        cli.password.as_deref(),
        cli.ca_cert.as_deref(),
        cli.port,
    ).map_err(|e| anyhow::anyhow!(e))?;

    let client = mikrotik_core::MikrotikClient::new(mk_config)?;

    match cli.command {
        Commands::System(cmd) => commands::system::run(cmd, &client, cli.format).await?,
        Commands::Interfaces(cmd) => commands::interfaces::run(cmd, &client, cli.format, no_color).await?,
        Commands::Ip(cmd) => commands::ip::run(cmd, &client, cli.format, no_color).await?,
        Commands::Firewall(cmd) => commands::firewall::run(cmd, &client, cli.format, no_color).await?,
        Commands::Log(cmd) => commands::logs::run(cmd, &client, cli.format).await?,
        Commands::Traffic(cmd) => commands::traffic::run(cmd, &client, cli.format, &data_dir).await?,
    }

    Ok(())
}
