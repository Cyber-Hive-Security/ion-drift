use clap::Subcommand;
use mikrotik_core::MikrotikClient;

use super::{OutputFormat, format_bytes, print_rows, status_colored};

#[derive(Subcommand)]
pub enum InterfacesCommand {
    /// List all interfaces
    List {
        /// Filter by type (ether, vlan, bridge, wg, loopback)
        #[arg(long, short = 't')]
        r#type: Option<String>,
        /// Show only running interfaces
        #[arg(long)]
        running: bool,
    },
    /// List VLAN interfaces
    Vlans,
}

pub async fn run(
    cmd: InterfacesCommand,
    client: &MikrotikClient,
    format: OutputFormat,
    no_color: bool,
) -> anyhow::Result<()> {
    match cmd {
        InterfacesCommand::List { r#type, running } => {
            let mut ifaces = client.interfaces().await?;

            if let Some(ref t) = r#type {
                ifaces.retain(|i| i.iface_type == *t);
            }
            if running {
                ifaces.retain(|i| i.running);
            }

            print_rows(&ifaces, format,
                &["Name", "Type", "Status", "MAC", "RX", "TX", "Comment"],
                |i| vec![
                    i.name.clone(),
                    i.iface_type.clone(),
                    status_colored(i.running, no_color),
                    i.mac_address.clone().unwrap_or_default(),
                    i.rx_byte.map(format_bytes).unwrap_or_default(),
                    i.tx_byte.map(format_bytes).unwrap_or_default(),
                    i.comment.clone().unwrap_or_default(),
                ],
            );
        }
        InterfacesCommand::Vlans => {
            let vlans = client.vlan_interfaces().await?;
            print_rows(&vlans, format,
                &["Name", "VLAN ID", "Interface", "Status", "Comment"],
                |v| vec![
                    v.name.clone(),
                    v.vlan_id.to_string(),
                    v.interface.clone(),
                    status_colored(v.running, no_color),
                    v.comment.clone().unwrap_or_default(),
                ],
            );
        }
    }
    Ok(())
}
