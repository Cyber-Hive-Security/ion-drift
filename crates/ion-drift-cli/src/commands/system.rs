use clap::Subcommand;
use mikrotik_core::MikrotikClient;

use super::{OutputFormat, format_bytes, print_single};

#[derive(Subcommand)]
pub enum SystemCommand {
    /// Show system resource usage (CPU, memory, uptime)
    Resources,
    /// Show router identity (name)
    Identity,
}

pub async fn run(cmd: SystemCommand, client: &MikrotikClient, format: OutputFormat) -> anyhow::Result<()> {
    match cmd {
        SystemCommand::Resources => {
            let res = client.system_resources().await?;
            let used_mem = res.total_memory - res.free_memory;
            print_single(&res, format, &[
                ("Board", res.board_name.clone()),
                ("Platform", res.platform.clone()),
                ("Version", res.version.clone()),
                ("Uptime", res.uptime.clone()),
                ("CPU", format!("{} x {} MHz", res.cpu_count, res.cpu_frequency)),
                ("CPU Load", format!("{}%", res.cpu_load)),
                ("Memory", format!(
                    "{} / {} ({:.1}%)",
                    format_bytes(used_mem),
                    format_bytes(res.total_memory),
                    res.memory_usage_percent(),
                )),
                ("Storage", format!(
                    "{} / {} ({:.1}%)",
                    format_bytes(res.total_hdd_space - res.free_hdd_space),
                    format_bytes(res.total_hdd_space),
                    res.hdd_usage_percent(),
                )),
            ]);
        }
        SystemCommand::Identity => {
            let id = client.system_identity().await?;
            print_single(&id, format, &[
                ("Name", id.name.clone()),
            ]);
        }
    }
    Ok(())
}
