//! Smoke test — validates all resource models against a real RouterOS device.
//!
//! Usage:
//!   cargo run --example smoke_test -- --host router.kaziik.xyz --user ion-drift --password <pass> --ca-cert /etc/ssl/certs/kaziik-root-ca.pem

use mikrotik_core::{MikrotikClient, MikrotikConfig};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let host = get_arg(&args, "--host").unwrap_or_else(|| "router.kaziik.xyz".into());
    let user = get_arg(&args, "--user").unwrap_or_else(|| "ion-drift".into());
    let password = get_arg(&args, "--password").expect("--password is required");
    let ca_cert = get_arg(&args, "--ca-cert");

    let config = MikrotikConfig {
        host,
        port: 443,
        tls: true,
        ca_cert_path: ca_cert.map(PathBuf::from),
        username: user,
        password,
    };

    let client = MikrotikClient::new(config)?;

    // ── System ────────────────────────────────────────────
    print_section("System Identity");
    let identity = client.system_identity().await?;
    println!("  Router name: {}", identity.name);

    print_section("System Resources");
    let res = client.system_resources().await?;
    println!("  Board:    {}", res.board_name);
    println!("  Version:  {}", res.version);
    println!("  CPU:      {} x {} MHz ({}% load)", res.cpu_count, res.cpu_frequency, res.cpu_load);
    println!("  Memory:   {:.1}% used ({} / {} MB)",
        res.memory_usage_percent(),
        (res.total_memory - res.free_memory) / 1_048_576,
        res.total_memory / 1_048_576);
    println!("  Uptime:   {}", res.uptime);

    // ── Interfaces ────────────────────────────────────────
    print_section("Interfaces");
    let ifaces = client.interfaces().await?;
    println!("  Total: {}", ifaces.len());
    for iface in &ifaces {
        let status = if iface.running { "UP" } else { "down" };
        println!("  {:20} {:8} {:6} {}",
            iface.name, iface.iface_type, status,
            iface.comment.as_deref().unwrap_or(""));
    }

    print_section("VLAN Interfaces");
    let vlans = client.vlan_interfaces().await?;
    println!("  Total: {}", vlans.len());
    for vlan in &vlans {
        println!("  {:20} VLAN {:4} on {}",
            vlan.name, vlan.vlan_id, vlan.interface);
    }

    // ── IP ────────────────────────────────────────────────
    print_section("IP Addresses");
    let addrs = client.ip_addresses().await?;
    println!("  Total: {}", addrs.len());
    for addr in &addrs {
        println!("  {:25} on {}", addr.address, addr.interface);
    }

    print_section("Routes");
    let routes = client.ip_routes().await?;
    println!("  Total: {}", routes.len());
    for route in routes.iter().take(10) {
        println!("  {:25} via {:20} {}",
            route.dst_address,
            route.gateway.as_deref().unwrap_or("—"),
            if route.active.unwrap_or(false) { "active" } else { "" });
    }
    if routes.len() > 10 {
        println!("  ... and {} more", routes.len() - 10);
    }

    print_section("DHCP Leases");
    let leases = client.dhcp_leases().await?;
    let active = leases.iter().filter(|l| l.status.as_deref() == Some("bound")).count();
    println!("  Total: {} ({} active)", leases.len(), active);
    for lease in leases.iter().take(10) {
        println!("  {:16} {:18} {:20} {}",
            lease.address,
            lease.mac_address.as_deref().unwrap_or("—"),
            lease.host_name.as_deref().unwrap_or("—"),
            lease.status.as_deref().unwrap_or("—"));
    }
    if leases.len() > 10 {
        println!("  ... and {} more", leases.len() - 10);
    }

    // ── Firewall ──────────────────────────────────────────
    print_section("Firewall Filter Rules");
    let filters = client.firewall_filter_rules().await?;
    println!("  Total: {}", filters.len());
    for rule in filters.iter().take(5) {
        println!("  {:10} {:10} {}",
            rule.chain, rule.action,
            rule.comment.as_deref().unwrap_or("(no comment)"));
    }
    if filters.len() > 5 {
        println!("  ... and {} more", filters.len() - 5);
    }

    print_section("Firewall NAT Rules");
    let nats = client.firewall_nat_rules().await?;
    println!("  Total: {}", nats.len());

    print_section("Firewall Mangle Rules");
    let mangles = client.firewall_mangle_rules().await?;
    println!("  Total: {}", mangles.len());

    // ── Log ───────────────────────────────────────────────
    print_section("Log Entries (last 5)");
    let logs = client.log_entries().await?;
    println!("  Total: {}", logs.len());
    for entry in logs.iter().rev().take(5) {
        println!("  {} [{}] {}",
            entry.time,
            entry.topics.as_deref().unwrap_or("—"),
            entry.message);
    }

    println!("\n All resource models validated successfully!");
    Ok(())
}

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn print_section(name: &str) {
    println!("\n── {} ──", name);
}
