//! Nmap network scanner for device discovery and fingerprinting.
//!
//! Executes `/usr/bin/nmap` as a subprocess, parses XML output with quick-xml,
//! and stores results in SwitchStore. Safety: single concurrent scan via AtomicBool,
//! VLAN whitelist prevents scanning arbitrary targets, exclusion list, 30-minute timeout.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ion_drift_storage::switch::{NmapResult, NmapScan, SwitchStore};

/// Nmap scanner with single-scan enforcement.
pub struct NmapScanner {
    switch_store: Arc<SwitchStore>,
    scanning: Arc<AtomicBool>,
}

/// Scan profile controlling nmap flags and expected duration.
#[derive(Debug, Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanProfile {
    Quick,
    Standard,
    Deep,
}

impl ScanProfile {
    fn flags(&self) -> Vec<&'static str> {
        match self {
            ScanProfile::Quick => vec!["-sn"],
            ScanProfile::Standard => vec!["-sS", "-sV", "-O", "--top-ports", "100"],
            ScanProfile::Deep => vec!["-sS", "-sV", "-O", "-sC", "-p-"],
        }
    }

    fn timeout_secs(&self) -> u64 {
        match self {
            ScanProfile::Quick => 120,
            ScanProfile::Standard => 600,
            ScanProfile::Deep => 1800,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ScanProfile::Quick => "quick",
            ScanProfile::Standard => "standard",
            ScanProfile::Deep => "deep",
        }
    }
}

/// Look up CIDR for a VLAN from the DB config.
async fn vlan_to_cidr(switch_store: &SwitchStore, vlan_id: u32) -> Option<String> {
    let configs = switch_store.get_vlan_configs().await.ok()?;
    configs
        .iter()
        .find(|c| c.vlan_id == vlan_id as u16)
        .and_then(|c| c.subnet.clone())
}

/// Check whether nmap is available on the system.
pub fn nmap_available() -> bool {
    std::path::Path::new("/usr/bin/nmap").exists()
}

/// Whether this VLAN has "loose" or "monitor" sensitivity (e.g. IoT VLANs).
pub async fn is_iot_vlan(switch_store: &SwitchStore, vlan_id: u32) -> bool {
    let configs = switch_store.get_vlan_configs().await.unwrap_or_default();
    configs
        .iter()
        .find(|c| c.vlan_id == vlan_id as u16)
        .and_then(|c| c.sensitivity.as_deref())
        .map(|s| matches!(s, "loose" | "monitor"))
        .unwrap_or(false)
}

impl NmapScanner {
    pub fn new(switch_store: Arc<SwitchStore>) -> Self {
        Self {
            switch_store,
            scanning: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Whether a scan is currently running.
    pub fn is_scanning(&self) -> bool {
        self.scanning.load(Ordering::Relaxed)
    }

    /// Start a scan on the given VLAN. Returns the scan ID or an error.
    pub async fn start_scan(
        &self,
        vlan_id: u32,
        profile: ScanProfile,
    ) -> Result<String, String> {
        // Validate VLAN — look up subnet from DB
        let cidr = vlan_to_cidr(&self.switch_store, vlan_id).await
            .ok_or_else(|| format!("unknown VLAN {vlan_id} — no subnet configured"))?;

        // Check nmap availability
        if !nmap_available() {
            return Err("nmap not found at /usr/bin/nmap".to_string());
        }

        // Enforce single scan
        if self.scanning.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err()
        {
            return Err("a scan is already running".to_string());
        }

        let scan_id = uuid::Uuid::new_v4().to_string();

        // Get exclusions
        let exclusions = self.switch_store.get_scan_exclusions().await
            .map_err(|e| {
                self.scanning.store(false, Ordering::SeqCst);
                format!("failed to get exclusions: {e}")
            })?;

        let now = chrono_now();
        let scan = NmapScan {
            id: scan_id.clone(),
            vlan_id,
            profile: profile.as_str().to_string(),
            status: "running".to_string(),
            target_count: 254, // /24
            discovered_count: 0,
            started_at: Some(now.clone()),
            completed_at: None,
            error: None,
            created_at: now,
        };

        if let Err(e) = self.switch_store.insert_nmap_scan(&scan).await {
            self.scanning.store(false, Ordering::SeqCst);
            return Err(format!("failed to create scan record: {e}"));
        }

        // Spawn the scan in a background task
        let store = Arc::clone(&self.switch_store);
        let scanning = Arc::clone(&self.scanning);
        let sid = scan_id.clone();

        tokio::spawn(async move {
            let result = run_nmap_scan(&store, &sid, &cidr, profile, &exclusions).await;
            scanning.store(false, Ordering::SeqCst);

            match result {
                Ok(count) => {
                    let _ = store.update_nmap_scan(
                        &sid,
                        "completed",
                        count,
                        None,
                        Some(&chrono_now()),
                    ).await;
                    tracing::info!(scan_id = %sid, discovered = count, "nmap scan completed");
                }
                Err(e) => {
                    let _ = store.update_nmap_scan(
                        &sid,
                        "failed",
                        0,
                        Some(&e),
                        Some(&chrono_now()),
                    ).await;
                    tracing::error!(scan_id = %sid, error = %e, "nmap scan failed");
                }
            }
        });

        Ok(scan_id)
    }
}

/// Execute nmap and parse results.
async fn run_nmap_scan(
    store: &SwitchStore,
    scan_id: &str,
    cidr: &str,
    profile: ScanProfile,
    exclusions: &[ion_drift_storage::switch::ScanExclusion],
) -> Result<i32, String> {
    let mut args: Vec<String> = profile.flags().into_iter().map(|s| s.to_string()).collect();
    args.push("-oX".to_string());
    args.push("-".to_string());

    // Add exclusions
    if !exclusions.is_empty() {
        let exclude_list: Vec<&str> = exclusions.iter().map(|e| e.ip_address.as_str()).collect();
        args.push("--exclude".to_string());
        args.push(exclude_list.join(","));
    }

    args.push(cidr.to_string());

    let timeout = std::time::Duration::from_secs(profile.timeout_secs());

    // Run nmap in a blocking task
    let output = tokio::time::timeout(timeout, tokio::task::spawn_blocking(move || {
        std::process::Command::new("/usr/bin/nmap")
            .args(&args)
            .output()
    }))
    .await
    .map_err(|_| "scan timed out".to_string())?
    .map_err(|e| format!("task join error: {e}"))?
    .map_err(|e| format!("nmap execution error: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("nmap exited with {}: {}", output.status, stderr));
    }

    let xml = String::from_utf8_lossy(&output.stdout);
    let hosts = parse_nmap_xml(&xml)?;

    let mut count = 0i32;
    for host in &hosts {
        let result = NmapResult {
            id: 0, // auto-increment
            scan_id: scan_id.to_string(),
            ip_address: host.ip.clone(),
            mac_address: host.mac.clone(),
            hostname: host.hostname.clone(),
            os_guess: host.os_guess.clone(),
            os_accuracy: host.os_accuracy,
            open_ports: if host.ports.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&host.ports).unwrap_or_default())
            },
            device_type: host.device_type.clone(),
            created_at: chrono_now(),
        };

        if let Err(e) = store.insert_nmap_result(&result).await {
            tracing::warn!(ip = %host.ip, "failed to store nmap result: {e}");
            continue;
        }

        // Update network identity if we have a MAC
        if let Some(ref mac) = host.mac {
            let device_type = host.device_type.as_deref();
            let dt_confidence = if device_type.is_some() { 0.85 } else { 0.0 };
            let _ = store.upsert_network_identity(
                mac,
                Some(&host.ip),
                host.hostname.as_deref(),
                None, // manufacturer from nmap isn't reliable
                None,
                None,
                None,
                None,
                None,
                None,
                0.3, // basic confidence from scan
                device_type,
                if device_type.is_some() { Some("nmap") } else { None },
                dt_confidence,
            ).await;
        }

        count += 1;
    }

    Ok(count)
}

// ── Nmap XML parsing ────────────────────────────────────────────

#[derive(Debug, Default)]
struct ParsedHost {
    ip: String,
    mac: Option<String>,
    hostname: Option<String>,
    os_guess: Option<String>,
    os_accuracy: Option<i32>,
    ports: Vec<ParsedPort>,
    device_type: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ParsedPort {
    port: u16,
    proto: String,
    state: String,
    service: String,
    version: String,
}

fn parse_nmap_xml(xml: &str) -> Result<Vec<ParsedHost>, String> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml);
    let mut hosts = Vec::new();
    let mut current_host: Option<ParsedHost> = None;
    let mut in_host = false;
    let mut in_ports = false;
    let mut in_os = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let local_name = e.name();
                let name = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                match name {
                    "host" => {
                        in_host = true;
                        current_host = Some(ParsedHost::default());
                    }
                    "address" if in_host => {
                        if let Some(ref mut host) = current_host {
                            let mut addr_type = String::new();
                            let mut addr = String::new();
                            for attr in e.attributes().flatten() {
                                let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                                let val = String::from_utf8_lossy(&attr.value).to_string();
                                match key {
                                    "addrtype" => addr_type = val,
                                    "addr" => addr = val,
                                    _ => {}
                                }
                            }
                            match addr_type.as_str() {
                                "ipv4" => host.ip = addr,
                                "mac" => host.mac = Some(normalize_mac(&addr)),
                                _ => {}
                            }
                        }
                    }
                    "hostname" if in_host => {
                        if let Some(ref mut host) = current_host {
                            for attr in e.attributes().flatten() {
                                if std::str::from_utf8(attr.key.as_ref()).unwrap_or("") == "name" {
                                    host.hostname = Some(
                                        String::from_utf8_lossy(&attr.value).to_string(),
                                    );
                                }
                            }
                        }
                    }
                    "ports" if in_host => in_ports = true,
                    "port" if in_ports => {
                        if let Some(ref mut host) = current_host {
                            let mut port_num = 0u16;
                            let mut proto = String::new();
                            for attr in e.attributes().flatten() {
                                let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                                let val = String::from_utf8_lossy(&attr.value).to_string();
                                match key {
                                    "portid" => port_num = val.parse().unwrap_or(0),
                                    "protocol" => proto = val,
                                    _ => {}
                                }
                            }
                            host.ports.push(ParsedPort {
                                port: port_num,
                                proto,
                                state: String::new(),
                                service: String::new(),
                                version: String::new(),
                            });
                        }
                    }
                    "state" if in_ports => {
                        if let Some(ref mut host) = current_host {
                            if let Some(port) = host.ports.last_mut() {
                                for attr in e.attributes().flatten() {
                                    if std::str::from_utf8(attr.key.as_ref()).unwrap_or("")
                                        == "state"
                                    {
                                        port.state =
                                            String::from_utf8_lossy(&attr.value).to_string();
                                    }
                                }
                            }
                        }
                    }
                    "service" if in_ports => {
                        if let Some(ref mut host) = current_host {
                            if let Some(port) = host.ports.last_mut() {
                                for attr in e.attributes().flatten() {
                                    let key =
                                        std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                                    let val =
                                        String::from_utf8_lossy(&attr.value).to_string();
                                    match key {
                                        "name" => port.service = val,
                                        "product" | "version" => {
                                            if !val.is_empty() {
                                                if !port.version.is_empty() {
                                                    port.version.push(' ');
                                                }
                                                port.version.push_str(&val);
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                    "os" if in_host => in_os = true,
                    "osmatch" if in_os => {
                        if let Some(ref mut host) = current_host {
                            if host.os_guess.is_none() {
                                for attr in e.attributes().flatten() {
                                    let key =
                                        std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                                    let val =
                                        String::from_utf8_lossy(&attr.value).to_string();
                                    match key {
                                        "name" => host.os_guess = Some(val),
                                        "accuracy" => {
                                            host.os_accuracy = val.parse().ok();
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                let local_name = e.name();
                let name = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                match name {
                    "host" => {
                        in_host = false;
                        if let Some(mut host) = current_host.take() {
                            // Filter to only open ports
                            host.ports.retain(|p| p.state == "open");
                            // Infer device type
                            host.device_type = infer_device_type(&host);
                            if !host.ip.is_empty() {
                                hosts.push(host);
                            }
                        }
                    }
                    "ports" => in_ports = false,
                    "os" => in_os = false,
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {e}")),
            _ => {}
        }
    }

    Ok(hosts)
}

/// Infer device type from nmap scan results (OS guess + open ports).
fn infer_device_type(host: &ParsedHost) -> Option<String> {
    // Check OS guess first
    if let Some(ref os) = host.os_guess {
        let os_lower = os.to_lowercase();
        if os_lower.contains("router") || os_lower.contains("routeros") {
            return Some("router".to_string());
        }
        if os_lower.contains("switch") {
            return Some("switch".to_string());
        }
        if os_lower.contains("printer") || os_lower.contains("print server") {
            return Some("printer".to_string());
        }
        if os_lower.contains("camera") || os_lower.contains("dvr") || os_lower.contains("nvr") {
            return Some("camera".to_string());
        }
        if os_lower.contains("phone") || os_lower.contains("android") || os_lower.contains("ios") {
            return Some("phone".to_string());
        }
        if os_lower.contains("linux") || os_lower.contains("unix") {
            // Could be server or computer — check ports
        }
        if os_lower.contains("windows") {
            return Some("computer".to_string());
        }
    }

    // Check open ports for signatures
    let has_port = |p: u16| host.ports.iter().any(|pp| pp.port == p);
    let service_contains = |s: &str| {
        host.ports
            .iter()
            .any(|pp| pp.service.to_lowercase().contains(s) || pp.version.to_lowercase().contains(s))
    };

    if has_port(554) || service_contains("rtsp") {
        return Some("camera".to_string());
    }
    if has_port(9100) || has_port(631) || service_contains("ipp") || service_contains("printer") {
        return Some("printer".to_string());
    }
    if has_port(8443) && service_contains("mikrotik") {
        return Some("router".to_string());
    }
    if has_port(32400) || service_contains("plex") {
        return Some("media_server".to_string());
    }
    if has_port(8080) && service_contains("unifi") {
        return Some("network_equipment".to_string());
    }
    if (has_port(80) || has_port(443)) && (has_port(22) || has_port(8006)) {
        return Some("server".to_string());
    }

    None
}

/// Normalize a MAC address to uppercase colon-separated format.
fn normalize_mac(mac: &str) -> String {
    mac.to_uppercase()
        .replace('-', ":")
}

/// Current timestamp in ISO 8601 format.
fn chrono_now() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple ISO format without chrono dependency
    let secs_per_day = 86400u64;
    let days = now / secs_per_day;
    let secs_today = now % secs_per_day;
    let hours = secs_today / 3600;
    let minutes = (secs_today % 3600) / 60;
    let seconds = secs_today % 60;

    // Approximate date calculation (good enough for timestamps)
    let mut y = 1970i64;
    let mut remaining_days = days as i64;

    loop {
        let days_in_year = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            366
        } else {
            365
        };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }

    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut m = 1;
    for &md in &month_days {
        if remaining_days < md {
            break;
        }
        remaining_days -= md;
        m += 1;
    }
    let d = remaining_days + 1;

    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}
