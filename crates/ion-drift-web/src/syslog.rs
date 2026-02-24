//! RouterOS syslog listener for capturing firewall events.
//!
//! Receives UDP syslog messages from the Mikrotik router and parses
//! firewall log entries to capture connections that polling may miss.

use std::sync::Arc;

use crate::connection_store::{ConnectionStore, SyslogEvent};
use crate::geo::GeoCache;

/// Parse a RouterOS syslog line into a SyslogEvent.
///
/// Expected format (with log-prefix "ION"):
/// ```text
/// <priority>MMM DD HH:MM:SS router firewall,info ION forward: in:IFACE out:IFACE, ...
/// ```
pub fn parse_routeros_syslog(line: &str) -> Option<SyslogEvent> {
    // Find the firewall message portion after the syslog header
    let msg = if let Some(idx) = line.find("ION ") {
        &line[idx + 4..]
    } else if let Some(idx) = line.find("firewall") {
        // Fallback: find firewall topic
        if let Some(msg_start) = line[idx..].find(' ') {
            &line[idx + msg_start + 1..]
        } else {
            return None;
        }
    } else {
        return None;
    };

    // Parse: "forward: in:ether1 out:V-25, connection-state:new src-mac XX:XX, proto TCP (SYN), 1.2.3.4:80->5.6.7.8:443, len 60"
    let chain = msg.split(':').next().unwrap_or("").trim();

    let protocol = if msg.contains("proto TCP") {
        "tcp"
    } else if msg.contains("proto UDP") {
        "udp"
    } else if msg.contains("proto ICMP") {
        "icmp"
    } else {
        return None;
    };

    // Extract src and dst IP:port from "SRC_IP:SRC_PORT->DST_IP:DST_PORT"
    let arrow_idx = msg.find("->")?;
    let before_arrow = &msg[..arrow_idx];
    let after_arrow = &msg[arrow_idx + 2..];

    // Find the IP:port segment before the arrow (scan backwards from arrow for space or comma)
    let src_segment = before_arrow.rsplit([' ', ',']).next()?.trim();
    // Find the IP:port segment after the arrow (scan forwards to comma or space)
    let dst_segment = after_arrow.split([',', ' ']).next()?.trim();

    let (src_ip, _src_port) = split_addr(src_segment);
    let (dst_ip, dst_port) = split_addr(dst_segment);

    let dst_port_num = dst_port.and_then(|p| p.parse::<i64>().ok());

    // Extract src-mac
    let src_mac = msg
        .find("src-mac ")
        .map(|i| &msg[i + 8..])
        .and_then(|s| s.split([',', ' ']).next())
        .map(String::from);

    // Extract in-interface
    let in_interface = msg
        .find("in:")
        .map(|i| &msg[i + 3..])
        .and_then(|s| s.split([' ', ',']).next())
        .map(String::from);

    // Derive action from chain/prefix
    let action = if chain.contains("drop") || msg.contains("DROP") {
        Some("drop".to_string())
    } else if chain.contains("reject") {
        Some("reject".to_string())
    } else {
        Some("accept".to_string())
    };

    // Timestamp: use current time (syslog timestamps are often imprecise)
    let timestamp = crate::connection_store::now_iso_pub();

    Some(SyslogEvent {
        protocol: protocol.to_string(),
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        src_port: None,
        dst_port: dst_port_num,
        src_mac,
        action,
        in_interface,
        timestamp,
    })
}

fn split_addr(s: &str) -> (&str, Option<&str>) {
    if let Some(colon) = s.rfind(':') {
        (&s[..colon], Some(&s[colon + 1..]))
    } else {
        (s, None)
    }
}

/// Spawn the syslog listener as a tokio task.
/// Listens on UDP and inserts parsed events into the connection store.
pub fn spawn_syslog_listener(
    port: u16,
    store: Arc<ConnectionStore>,
    geo_cache: Arc<GeoCache>,
) {
    tokio::spawn(async move {
        let addr = format!("0.0.0.0:{port}");
        let socket = match tokio::net::UdpSocket::bind(&addr).await {
            Ok(s) => {
                tracing::info!("syslog listener started on UDP {addr}");
                s
            }
            Err(e) => {
                tracing::error!("failed to bind syslog listener on {addr}: {e}");
                return;
            }
        };

        let mut buf = [0u8; 4096];
        let mut batch: Vec<SyslogEvent> = Vec::with_capacity(100);
        let mut last_flush = tokio::time::Instant::now();
        let mut total_received: u64 = 0;
        let mut total_parsed: u64 = 0;
        let mut total_unparsed: u64 = 0;
        let mut last_stats = tokio::time::Instant::now();

        loop {
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                socket.recv_from(&mut buf),
            )
            .await;

            match result {
                Ok(Ok((len, _addr))) => {
                    total_received += 1;
                    if let Ok(line) = std::str::from_utf8(&buf[..len]) {
                        if let Some(event) = parse_routeros_syslog(line) {
                            total_parsed += 1;
                            batch.push(event);
                        } else {
                            total_unparsed += 1;
                            tracing::trace!("syslog: unparsable line: {}", line.trim());
                        }
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!("syslog recv error: {e}");
                }
                Err(_) => {
                    // Timeout — flush if we have events
                }
            }

            // Flush batch every 5 seconds or when it reaches 100 events
            if batch.len() >= 100 || (last_flush.elapsed().as_secs() >= 5 && !batch.is_empty()) {
                let count = batch.len();
                for event in batch.drain(..) {
                    if let Err(e) = store.upsert_from_syslog(&event, &geo_cache) {
                        tracing::debug!("syslog insert error: {e}");
                    }
                }
                tracing::debug!("syslog: flushed {count} events");
                last_flush = tokio::time::Instant::now();
            }

            // Log stats every 5 minutes at INFO level
            if last_stats.elapsed().as_secs() >= 300 && total_received > 0 {
                tracing::info!(
                    "syslog stats: received={total_received}, parsed={total_parsed}, unparsed={total_unparsed}"
                );
                last_stats = tokio::time::Instant::now();
            }
        }
    });
}
