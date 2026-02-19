use clap::Subcommand;
use mikrotik_core::MikrotikClient;

use super::{OutputFormat, print_rows, status_colored};

#[derive(Subcommand)]
pub enum IpCommand {
    /// List IP addresses
    Addresses,
    /// List routes
    Routes,
    /// List DHCP server leases
    #[command(subcommand)]
    Dhcp(DhcpCommand),
}

#[derive(Subcommand)]
pub enum DhcpCommand {
    /// List DHCP leases
    Leases {
        /// Show only active (bound) leases
        #[arg(long)]
        active: bool,
    },
}

pub async fn run(
    cmd: IpCommand,
    client: &MikrotikClient,
    format: OutputFormat,
    no_color: bool,
) -> anyhow::Result<()> {
    match cmd {
        IpCommand::Addresses => {
            let addrs = client.ip_addresses().await?;
            print_rows(&addrs, format,
                &["Address", "Network", "Interface", "Disabled", "Comment"],
                |a| vec![
                    a.address.clone(),
                    a.network.clone(),
                    a.interface.clone(),
                    if a.disabled { "yes".into() } else { "".into() },
                    a.comment.clone().unwrap_or_default(),
                ],
            );
        }
        IpCommand::Routes => {
            let routes = client.ip_routes().await?;
            print_rows(&routes, format,
                &["Dst Address", "Gateway", "Distance", "Table", "Status"],
                |r| {
                    let active = r.active.unwrap_or(false);
                    vec![
                        r.dst_address.clone(),
                        r.gateway.clone().unwrap_or_else(|| "—".into()),
                        r.distance.map(|d| d.to_string()).unwrap_or_default(),
                        r.routing_table.clone().unwrap_or_else(|| "main".into()),
                        status_colored(active, no_color),
                    ]
                },
            );
        }
        IpCommand::Dhcp(DhcpCommand::Leases { active }) => {
            let mut leases = client.dhcp_leases().await?;
            if active {
                leases.retain(|l| l.status.as_deref() == Some("bound"));
            }
            print_rows(&leases, format,
                &["Address", "MAC", "Hostname", "Server", "Status", "Expires"],
                |l| vec![
                    l.address.clone(),
                    l.mac_address.clone().unwrap_or_default(),
                    l.host_name.clone().unwrap_or_default(),
                    l.server.clone().unwrap_or_default(),
                    l.status.clone().unwrap_or_default(),
                    l.expires_after.clone().unwrap_or_default(),
                ],
            );
        }
    }
    Ok(())
}
