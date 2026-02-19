use clap::Subcommand;
use mikrotik_core::MikrotikClient;

use super::{OutputFormat, action_colored, format_bytes, print_rows};

#[derive(Subcommand)]
pub enum FirewallCommand {
    /// List filter rules
    Filter {
        /// Filter by chain (input, forward, output)
        #[arg(long)]
        chain: Option<String>,
    },
    /// List NAT rules
    Nat {
        /// Filter by chain (srcnat, dstnat)
        #[arg(long)]
        chain: Option<String>,
    },
    /// List mangle rules
    Mangle {
        /// Filter by chain
        #[arg(long)]
        chain: Option<String>,
    },
}

pub async fn run(
    cmd: FirewallCommand,
    client: &MikrotikClient,
    format: OutputFormat,
    no_color: bool,
) -> anyhow::Result<()> {
    match cmd {
        FirewallCommand::Filter { chain } => {
            let mut rules = client.firewall_filter_rules().await?;
            if let Some(ref c) = chain {
                rules.retain(|r| r.chain == *c);
            }
            print_rows(&rules, format,
                &["#", "Chain", "Action", "Src", "Dst", "Proto", "Port", "In", "Out", "Bytes", "Comment"],
                |r| vec![
                    r.id.clone(),
                    r.chain.clone(),
                    action_colored(&r.action, no_color),
                    r.src_address.clone().unwrap_or_default(),
                    r.dst_address.clone().unwrap_or_default(),
                    r.protocol.clone().unwrap_or_default(),
                    r.dst_port.clone().unwrap_or_default(),
                    r.in_interface.clone()
                        .or_else(|| r.in_interface_list.clone())
                        .unwrap_or_default(),
                    r.out_interface.clone()
                        .or_else(|| r.out_interface_list.clone())
                        .unwrap_or_default(),
                    r.bytes.map(format_bytes).unwrap_or_default(),
                    r.comment.clone().unwrap_or_default(),
                ],
            );
        }
        FirewallCommand::Nat { chain } => {
            let mut rules = client.firewall_nat_rules().await?;
            if let Some(ref c) = chain {
                rules.retain(|r| r.chain == *c);
            }
            print_rows(&rules, format,
                &["#", "Chain", "Action", "Src", "Dst", "Proto", "Port", "To Addr", "To Port", "Comment"],
                |r| vec![
                    r.id.clone(),
                    r.chain.clone(),
                    action_colored(&r.action, no_color),
                    r.src_address.clone().unwrap_or_default(),
                    r.dst_address.clone().unwrap_or_default(),
                    r.protocol.clone().unwrap_or_default(),
                    r.dst_port.clone().unwrap_or_default(),
                    r.to_addresses.clone().unwrap_or_default(),
                    r.to_ports.clone().unwrap_or_default(),
                    r.comment.clone().unwrap_or_default(),
                ],
            );
        }
        FirewallCommand::Mangle { chain } => {
            let mut rules = client.firewall_mangle_rules().await?;
            if let Some(ref c) = chain {
                rules.retain(|r| r.chain == *c);
            }
            print_rows(&rules, format,
                &["#", "Chain", "Action", "Src", "Dst", "Mark", "Bytes", "Comment"],
                |r| vec![
                    r.id.clone(),
                    r.chain.clone(),
                    action_colored(&r.action, no_color),
                    r.src_address.clone().unwrap_or_default(),
                    r.dst_address.clone().unwrap_or_default(),
                    r.new_packet_mark.clone()
                        .or_else(|| r.new_connection_mark.clone())
                        .or_else(|| r.new_routing_mark.clone())
                        .unwrap_or_default(),
                    r.bytes.map(format_bytes).unwrap_or_default(),
                    r.comment.clone().unwrap_or_default(),
                ],
            );
        }
    }
    Ok(())
}
