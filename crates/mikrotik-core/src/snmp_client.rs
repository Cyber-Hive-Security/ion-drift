//! SNMP client for generic managed switches.
//!
//! Uses standard MIBs (IF-MIB, Q-BRIDGE-MIB, BRIDGE-MIB, LLDP-MIB, SNMPv2-MIB)
//! to poll any SNMP-capable switch. Supports SNMPv2c (community string) and
//! SNMPv3 (AuthPriv with SHA/MD5 + DES/AES128).

use std::collections::HashMap;
use std::time::Duration;

use snmp2::{v3, Oid, SyncSession, Value};

use crate::error::MikrotikError;

// ─── OID Constants (u64 for Oid::from) ──────────────────────────

// SNMPv2-MIB — system info
const OID_SYS_DESCR: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
const OID_SYS_NAME: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];
const OID_SYS_UPTIME: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];

// IF-MIB — interface table
const OID_IF_DESCR: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 2];
const OID_IF_ADMIN_STATUS: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 7];
const OID_IF_OPER_STATUS: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 8];
const OID_IF_SPEED: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 5];
const OID_IF_PHYS_ADDRESS: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 6];

// IF-MIB extended — ifXTable (64-bit counters + ifName)
const OID_IF_NAME: &[u64] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1];
const OID_IF_HIGH_SPEED: &[u64] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 15];
const OID_IF_HC_IN_OCTETS: &[u64] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6];
const OID_IF_HC_OUT_OCTETS: &[u64] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10];
const OID_IF_HC_IN_UCAST: &[u64] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 7];
const OID_IF_HC_OUT_UCAST: &[u64] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 11];

// BRIDGE-MIB — bridge port to ifIndex mapping
const OID_DOT1D_BASE_PORT_IF_INDEX: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2];

// BRIDGE-MIB — forwarding table (fallback MAC table)
const OID_DOT1D_TP_FDB_ADDRESS: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 1];
const OID_DOT1D_TP_FDB_PORT: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2];

// Q-BRIDGE-MIB — VLAN-aware MAC table
const OID_DOT1Q_TP_FDB_PORT: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2];

// Q-BRIDGE-MIB — VLAN table
const OID_DOT1Q_VLAN_STATIC_NAME: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 3, 1, 1];
const OID_DOT1Q_VLAN_STATIC_EGRESS: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 3, 1, 2];
const OID_DOT1Q_VLAN_STATIC_UNTAGGED: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 3, 1, 4];

// LLDP-MIB — remote systems data
const OID_LLDP_REM_SYS_NAME: &[u64] = &[1, 3, 6, 1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 9];
const OID_LLDP_REM_PORT_ID: &[u64] = &[1, 3, 6, 1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 7];
const OID_LLDP_REM_PORT_DESC: &[u64] = &[1, 3, 6, 1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 8];
const OID_LLDP_REM_CHASSIS_ID: &[u64] = &[1, 3, 6, 1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 5];

// ─── Data Types ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SnmpSystemInfo {
    pub sys_name: String,
    pub sys_descr: String,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone)]
pub struct SnmpInterface {
    pub index: u32,
    pub name: String,
    pub descr: String,
    pub oper_status: bool,
    pub admin_status: bool,
    pub speed_mbps: u64,
    pub mac_address: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Debug, Clone)]
pub struct SnmpMacEntry {
    pub mac_address: String,
    pub port_index: u32,
    pub vlan_id: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct SnmpLldpNeighbor {
    pub local_port_index: u32,
    pub remote_sys_name: String,
    pub remote_port_id: String,
    pub remote_port_desc: Option<String>,
    pub remote_chassis_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SnmpVlanEntry {
    pub vlan_id: u16,
    pub name: String,
    pub egress_ports: Vec<u32>,
    pub untagged_ports: Vec<u32>,
}

// ─── Client ─────────────────────────────────────────────────────

/// SNMP client for generic managed switches using standard MIBs.
/// Supports both SNMPv2c (community string) and SNMPv3 (AuthPriv).
#[derive(Clone, Debug)]
pub struct SnmpClient {
    pub host: String,
    pub port: u16,
    // v2c
    pub community: Option<String>,
    // v3
    pub v3_username: Option<String>,
    pub v3_auth_password: Option<String>,
    pub v3_auth_protocol: Option<String>,
    pub v3_priv_password: Option<String>,
    pub v3_priv_protocol: Option<String>,
}

impl SnmpClient {
    /// Create a new SNMPv2c client. Does not make any network requests.
    pub fn new_v2c(host: String, port: u16, community: String) -> Self {
        Self {
            host,
            port,
            community: Some(community),
            v3_username: None,
            v3_auth_password: None,
            v3_auth_protocol: None,
            v3_priv_password: None,
            v3_priv_protocol: None,
        }
    }

    /// Create a new SNMPv3 client with AuthPriv. Does not make any network requests.
    pub fn new_v3(
        host: String,
        port: u16,
        username: String,
        auth_password: String,
        auth_protocol: String,
        priv_password: String,
        priv_protocol: String,
    ) -> Self {
        Self {
            host,
            port,
            community: None,
            v3_username: Some(username),
            v3_auth_password: Some(auth_password),
            v3_auth_protocol: Some(auth_protocol),
            v3_priv_password: Some(priv_password),
            v3_priv_protocol: Some(priv_protocol),
        }
    }

    fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Returns true if this client is configured for SNMPv3.
    pub fn is_v3(&self) -> bool {
        self.v3_username.is_some()
    }

    /// Create a new SNMP session (v2c or v3 depending on configuration).
    fn create_session(&self) -> Result<SyncSession, MikrotikError> {
        if let Some(ref username) = self.v3_username {
            let auth_proto = match self.v3_auth_protocol.as_deref() {
                Some("MD5") => v3::AuthProtocol::Md5,
                _ => v3::AuthProtocol::Sha1,
            };
            let cipher = match self.v3_priv_protocol.as_deref() {
                Some("DES") => v3::Cipher::Des,
                // Default to AES128 — more secure than DES and universally supported.
                // DES requires the OpenSSL legacy provider on OpenSSL 3.x.
                _ => v3::Cipher::Aes128,
            };

            let auth_pw = self.v3_auth_password.as_deref().unwrap_or("");
            let priv_pw = self.v3_priv_password.clone().unwrap_or_default();

            let security = v3::Security::new(username.as_bytes(), auth_pw.as_bytes())
                .with_auth_protocol(auth_proto)
                .with_auth(v3::Auth::AuthPriv {
                    cipher,
                    privacy_password: priv_pw.into_bytes(),
                });

            let mut sess = SyncSession::new_v3(
                &self.addr(),
                Some(Duration::from_secs(5)),
                0,
                security,
            )
            .map_err(|e| MikrotikError::Snmp(format!("v3 session: {e}")))?;

            // Engine ID discovery — required for v3
            sess.init()
                .map_err(|e| MikrotikError::Snmp(format!("v3 init: {e}")))?;

            Ok(sess)
        } else {
            let community = self.community.as_deref().unwrap_or("public");
            SyncSession::new_v2c(
                &self.addr(),
                community.as_bytes(),
                Some(Duration::from_secs(5)),
                0,
            )
            .map_err(|e| MikrotikError::Snmp(format!("v2c session: {e}")))
        }
    }

    /// Test connectivity by reading sysName.
    pub async fn test_connection(&self) -> Result<String, MikrotikError> {
        let info = self.get_system_info().await?;
        Ok(info.sys_name)
    }

    /// Read SNMPv2-MIB system group (sysName, sysDescr, sysUpTime).
    pub async fn get_system_info(&self) -> Result<SnmpSystemInfo, MikrotikError> {
        let client = self.clone();

        tokio::task::spawn_blocking(move || {
            let mut sess = client.create_session()?;

            let sys_name_oid = make_oid(OID_SYS_NAME)?;
            let sys_descr_oid = make_oid(OID_SYS_DESCR)?;
            let sys_uptime_oid = make_oid(OID_SYS_UPTIME)?;

            let response = sess
                .get_many(&[&sys_name_oid, &sys_descr_oid, &sys_uptime_oid])
                .map_err(|e| MikrotikError::Snmp(format!("get: {e}")))?;

            let mut sys_name = String::new();
            let mut sys_descr = String::new();
            let mut uptime_secs: u64 = 0;

            for (oid, val) in response.varbinds {
                if oid == sys_name_oid {
                    sys_name = value_to_string(&val);
                } else if oid == sys_descr_oid {
                    sys_descr = value_to_string(&val);
                } else if oid == sys_uptime_oid {
                    // sysUpTime is in hundredths of a second
                    uptime_secs = value_to_u64(&val) / 100;
                }
            }

            if sys_name.is_empty() {
                return Err(MikrotikError::Snmp(
                    "no sysName returned — check credentials".into(),
                ));
            }

            Ok(SnmpSystemInfo {
                sys_name,
                sys_descr,
                uptime_secs,
            })
        })
        .await
        .map_err(|e| MikrotikError::Snmp(format!("task join: {e}")))?
    }

    /// Read all interfaces via IF-MIB + ifXTable (64-bit counters).
    pub async fn get_interfaces(&self) -> Result<Vec<SnmpInterface>, MikrotikError> {
        let client = self.clone();

        tokio::task::spawn_blocking(move || {
            let mut sess = client.create_session()?;

            // Walk each column of the interface tables
            let if_descr = walk_string_column(&mut sess, OID_IF_DESCR)?;
            let if_admin = walk_u64_column(&mut sess, OID_IF_ADMIN_STATUS)?;
            let if_oper = walk_u64_column(&mut sess, OID_IF_OPER_STATUS)?;
            let if_speed = walk_u64_column(&mut sess, OID_IF_SPEED)?;
            let if_phys_raw = walk_raw_column(&mut sess, OID_IF_PHYS_ADDRESS)?;

            // ifXTable columns (may not exist on all devices)
            let if_name = walk_string_column(&mut sess, OID_IF_NAME).unwrap_or_default();
            let if_high_speed = walk_u64_column(&mut sess, OID_IF_HIGH_SPEED).unwrap_or_default();
            let if_hc_in = walk_u64_column(&mut sess, OID_IF_HC_IN_OCTETS).unwrap_or_default();
            let if_hc_out = walk_u64_column(&mut sess, OID_IF_HC_OUT_OCTETS).unwrap_or_default();
            let if_hc_in_pkts = walk_u64_column(&mut sess, OID_IF_HC_IN_UCAST).unwrap_or_default();
            let if_hc_out_pkts =
                walk_u64_column(&mut sess, OID_IF_HC_OUT_UCAST).unwrap_or_default();

            // Collect all interface indices
            let mut indices: Vec<u32> = if_descr.keys().copied().collect();
            indices.sort_unstable();

            let mut interfaces = Vec::new();
            for idx in indices {
                let name = if_name
                    .get(&idx)
                    .cloned()
                    .unwrap_or_else(|| if_descr.get(&idx).cloned().unwrap_or_default());
                let descr = if_descr.get(&idx).cloned().unwrap_or_default();

                // ifHighSpeed in Mbps, fallback to ifSpeed in bps
                let speed_mbps = if_high_speed
                    .get(&idx)
                    .copied()
                    .unwrap_or_else(|| if_speed.get(&idx).copied().unwrap_or(0) / 1_000_000);

                let mac_address = if_phys_raw.get(&idx).and_then(|bytes| {
                    if bytes.len() == 6 && bytes.iter().any(|b| *b != 0) {
                        Some(format_mac(bytes))
                    } else {
                        None
                    }
                });

                interfaces.push(SnmpInterface {
                    index: idx,
                    name,
                    descr,
                    admin_status: if_admin.get(&idx).copied().unwrap_or(0) == 1,
                    oper_status: if_oper.get(&idx).copied().unwrap_or(0) == 1,
                    speed_mbps,
                    mac_address,
                    rx_bytes: if_hc_in.get(&idx).copied().unwrap_or(0),
                    tx_bytes: if_hc_out.get(&idx).copied().unwrap_or(0),
                    rx_packets: if_hc_in_pkts.get(&idx).copied().unwrap_or(0),
                    tx_packets: if_hc_out_pkts.get(&idx).copied().unwrap_or(0),
                });
            }

            Ok(interfaces)
        })
        .await
        .map_err(|e| MikrotikError::Snmp(format!("task join: {e}")))?
    }

    /// Read the bridge port -> ifIndex mapping table.
    pub async fn get_bridge_port_map(&self) -> Result<HashMap<u32, u32>, MikrotikError> {
        let client = self.clone();

        tokio::task::spawn_blocking(move || {
            let mut sess = client.create_session()?;
            let map = walk_u64_column(&mut sess, OID_DOT1D_BASE_PORT_IF_INDEX)?;
            Ok(map
                .into_iter()
                .map(|(k, v)| (k, v as u32))
                .collect())
        })
        .await
        .map_err(|e| MikrotikError::Snmp(format!("task join: {e}")))?
    }

    /// Read the Q-BRIDGE-MIB MAC table (VLAN-aware).
    /// Returns entries with bridge port indices — caller must resolve to ifName.
    pub async fn get_mac_table(&self) -> Result<Vec<SnmpMacEntry>, MikrotikError> {
        let client = self.clone();

        tokio::task::spawn_blocking(move || {
            let mut sess = client.create_session()?;
            let base_oid = make_oid(OID_DOT1Q_TP_FDB_PORT)?;
            let base_len = oid_components(&base_oid).len();

            let mut entries = Vec::new();
            let mut current_oid = base_oid.clone();

            loop {
                let response = match sess.getnext(&current_oid) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("SNMP walk error: {e}");
                        break;
                    }
                };

                let mut advanced = false;
                for (oid, val) in response.varbinds {
                    if !oid.starts_with(&base_oid) {
                        return Ok(entries);
                    }

                    // OID suffix: {VLAN_ID}.{MAC_b1}...{MAC_b6}
                    let components = oid_components(&oid);
                    let suffix = &components[base_len..];
                    if suffix.len() == 7 {
                        let vlan_id = suffix[0] as u16;
                        let mac = format!(
                            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                            suffix[1], suffix[2], suffix[3], suffix[4], suffix[5], suffix[6]
                        );
                        let port_index = value_to_u64(&val) as u32;
                        if port_index > 0 {
                            entries.push(SnmpMacEntry {
                                mac_address: mac,
                                port_index,
                                vlan_id: Some(vlan_id),
                            });
                        }
                    }

                    current_oid = oid.to_owned();
                    advanced = true;
                }

                if !advanced {
                    break;
                }
            }

            Ok(entries)
        })
        .await
        .map_err(|e| MikrotikError::Snmp(format!("task join: {e}")))?
    }

    /// Read the BRIDGE-MIB forwarding table (fallback, no VLAN info).
    pub async fn get_mac_table_bridge(&self) -> Result<Vec<SnmpMacEntry>, MikrotikError> {
        let client = self.clone();

        tokio::task::spawn_blocking(move || {
            let mut sess = client.create_session()?;

            let addr_oid = make_oid(OID_DOT1D_TP_FDB_ADDRESS)?;
            let port_oid = make_oid(OID_DOT1D_TP_FDB_PORT)?;
            let addr_base_len = oid_components(&addr_oid).len();
            let port_base_len = oid_components(&port_oid).len();

            // Walk address column to get MAC -> suffix mapping
            let mut mac_by_suffix: HashMap<String, String> = HashMap::new();
            let mut current = addr_oid.clone();
            loop {
                let response = match sess.getnext(&current) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("SNMP walk error: {e}");
                        break;
                    }
                };
                let mut advanced = false;
                for (oid, val) in response.varbinds {
                    if !oid.starts_with(&addr_oid) {
                        break;
                    }
                    if let Value::OctetString(bytes) = val {
                        if bytes.len() == 6 {
                            let components = oid_components(&oid);
                            let suffix_key = components[addr_base_len..]
                                .iter()
                                .map(|s| s.to_string())
                                .collect::<Vec<_>>()
                                .join(".");
                            mac_by_suffix.insert(suffix_key, format_mac(bytes));
                        }
                    }
                    current = oid.to_owned();
                    advanced = true;
                }
                if !advanced {
                    break;
                }
            }

            // Walk port column
            let mut port_by_suffix: HashMap<String, u32> = HashMap::new();
            let mut current = port_oid.clone();
            loop {
                let response = match sess.getnext(&current) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("SNMP walk error: {e}");
                        break;
                    }
                };
                let mut advanced = false;
                for (oid, val) in response.varbinds {
                    if !oid.starts_with(&port_oid) {
                        break;
                    }
                    let components = oid_components(&oid);
                    let suffix_key = components[port_base_len..]
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(".");
                    port_by_suffix.insert(suffix_key, value_to_u64(&val) as u32);
                    current = oid.to_owned();
                    advanced = true;
                }
                if !advanced {
                    break;
                }
            }

            let mut entries = Vec::new();
            for (suffix, mac) in &mac_by_suffix {
                if let Some(&port) = port_by_suffix.get(suffix) {
                    if port > 0 {
                        entries.push(SnmpMacEntry {
                            mac_address: mac.clone(),
                            port_index: port,
                            vlan_id: None,
                        });
                    }
                }
            }

            Ok(entries)
        })
        .await
        .map_err(|e| MikrotikError::Snmp(format!("task join: {e}")))?
    }

    /// Read LLDP-MIB remote systems table.
    pub async fn get_lldp_neighbors(&self) -> Result<Vec<SnmpLldpNeighbor>, MikrotikError> {
        let client = self.clone();

        tokio::task::spawn_blocking(move || {
            let mut sess = client.create_session()?;

            // LLDP OID index: {timeMark}.{localPortNum}.{remIndex}
            let sys_names = walk_lldp_string(&mut sess, OID_LLDP_REM_SYS_NAME)?;
            let port_ids = walk_lldp_string(&mut sess, OID_LLDP_REM_PORT_ID)?;
            let port_descs = walk_lldp_string(&mut sess, OID_LLDP_REM_PORT_DESC)?;
            let chassis_ids = walk_lldp_raw(&mut sess, OID_LLDP_REM_CHASSIS_ID)?;

            let mut neighbors = Vec::new();
            for ((local_port, rem_idx), name) in &sys_names {
                let port_id = port_ids
                    .get(&(*local_port, *rem_idx))
                    .cloned()
                    .unwrap_or_default();
                let port_desc = port_descs.get(&(*local_port, *rem_idx)).cloned();
                let chassis_id = chassis_ids.get(&(*local_port, *rem_idx)).map(|bytes| {
                    if bytes.len() == 6 {
                        format_mac(bytes)
                    } else {
                        String::from_utf8_lossy(bytes).to_string()
                    }
                });

                neighbors.push(SnmpLldpNeighbor {
                    local_port_index: *local_port,
                    remote_sys_name: name.clone(),
                    remote_port_id: port_id,
                    remote_port_desc: port_desc,
                    remote_chassis_id: chassis_id,
                });
            }

            Ok(neighbors)
        })
        .await
        .map_err(|e| MikrotikError::Snmp(format!("task join: {e}")))?
    }

    /// Read Q-BRIDGE-MIB VLAN static table.
    pub async fn get_vlan_membership(&self) -> Result<Vec<SnmpVlanEntry>, MikrotikError> {
        let client = self.clone();

        tokio::task::spawn_blocking(move || {
            let mut sess = client.create_session()?;

            let names_oid = make_oid(OID_DOT1Q_VLAN_STATIC_NAME)?;
            let egress_oid = make_oid(OID_DOT1Q_VLAN_STATIC_EGRESS)?;
            let untagged_oid = make_oid(OID_DOT1Q_VLAN_STATIC_UNTAGGED)?;

            // Walk VLAN names
            let mut vlan_names: HashMap<u16, String> = HashMap::new();
            walk_indexed_fn(&mut sess, &names_oid, |suffix, val| {
                if let Some(&vlan_id) = suffix.first() {
                    vlan_names.insert(vlan_id as u16, value_to_string(&val));
                }
            })?;

            // Walk egress port bitmaps
            let mut egress_map: HashMap<u16, Vec<u32>> = HashMap::new();
            walk_indexed_raw_fn(&mut sess, &egress_oid, |suffix, bytes| {
                if let Some(&vlan_id) = suffix.first() {
                    egress_map.insert(vlan_id as u16, decode_portlist(bytes));
                }
            })?;

            // Walk untagged port bitmaps
            let mut untagged_map: HashMap<u16, Vec<u32>> = HashMap::new();
            walk_indexed_raw_fn(&mut sess, &untagged_oid, |suffix, bytes| {
                if let Some(&vlan_id) = suffix.first() {
                    untagged_map.insert(vlan_id as u16, decode_portlist(bytes));
                }
            })?;

            let mut entries = Vec::new();
            for (&vlan_id, name) in &vlan_names {
                entries.push(SnmpVlanEntry {
                    vlan_id,
                    name: name.clone(),
                    egress_ports: egress_map.get(&vlan_id).cloned().unwrap_or_default(),
                    untagged_ports: untagged_map.get(&vlan_id).cloned().unwrap_or_default(),
                });
            }

            entries.sort_by_key(|e| e.vlan_id);
            Ok(entries)
        })
        .await
        .map_err(|e| MikrotikError::Snmp(format!("task join: {e}")))?
    }
}

// Note: SNMPv3 sessions may return `Error::AuthUpdated` when the remote
// engine's boot/time counters change.  After `sess.init()` this is rare.
// Walk functions treat it as a normal error (break early); the next poll
// cycle will succeed since the library caches the updated engine params.

// ─── Helpers ────────────────────────────────────────────────────

/// Build an Oid from a u64 slice.
fn make_oid(components: &[u64]) -> Result<Oid<'static>, MikrotikError> {
    Oid::from(components).map_err(|e| MikrotikError::Snmp(format!("oid: {e:?}")))
}

/// Extract OID components as a Vec<u64>.
fn oid_components(oid: &Oid) -> Vec<u64> {
    oid.iter()
        .map(|it| it.collect::<Vec<u64>>())
        .unwrap_or_default()
}

/// Get the suffix of `oid` after `base` prefix as u64 components.
fn oid_suffix(oid: &Oid, base_len: usize) -> Vec<u64> {
    let all = oid_components(oid);
    if all.len() > base_len {
        all[base_len..].to_vec()
    } else {
        Vec::new()
    }
}

/// Walk an SNMP table column, collecting string values keyed by the first suffix component.
fn walk_string_column(
    sess: &mut SyncSession,
    base_oids: &[u64],
) -> Result<HashMap<u32, String>, MikrotikError> {
    let base = make_oid(base_oids)?;
    let base_len = oid_components(&base).len();
    let mut map = HashMap::new();
    let mut current = base.clone();

    loop {
        let response = match sess.getnext(&current) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("SNMP walk error: {e}");
                break;
            }
        };

        let mut advanced = false;
        for (oid, val) in response.varbinds {
            if !oid.starts_with(&base) {
                return Ok(map);
            }
            let suffix = oid_suffix(&oid, base_len);
            if let Some(&idx) = suffix.first() {
                map.insert(idx as u32, value_to_string(&val));
            }
            current = oid.to_owned();
            advanced = true;
        }

        if !advanced {
            break;
        }
    }

    Ok(map)
}

/// Walk an SNMP table column, collecting u64 values keyed by the first suffix component.
fn walk_u64_column(
    sess: &mut SyncSession,
    base_oids: &[u64],
) -> Result<HashMap<u32, u64>, MikrotikError> {
    let base = make_oid(base_oids)?;
    let base_len = oid_components(&base).len();
    let mut map = HashMap::new();
    let mut current = base.clone();

    loop {
        let response = match sess.getnext(&current) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("SNMP walk error: {e}");
                break;
            }
        };

        let mut advanced = false;
        for (oid, val) in response.varbinds {
            if !oid.starts_with(&base) {
                return Ok(map);
            }
            let suffix = oid_suffix(&oid, base_len);
            if let Some(&idx) = suffix.first() {
                map.insert(idx as u32, value_to_u64(&val));
            }
            current = oid.to_owned();
            advanced = true;
        }

        if !advanced {
            break;
        }
    }

    Ok(map)
}

/// Walk an SNMP table column, collecting raw bytes keyed by the first suffix component.
fn walk_raw_column(
    sess: &mut SyncSession,
    base_oids: &[u64],
) -> Result<HashMap<u32, Vec<u8>>, MikrotikError> {
    let base = make_oid(base_oids)?;
    let base_len = oid_components(&base).len();
    let mut map = HashMap::new();
    let mut current = base.clone();

    loop {
        let response = match sess.getnext(&current) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("SNMP walk error: {e}");
                break;
            }
        };

        let mut advanced = false;
        for (oid, val) in response.varbinds {
            if !oid.starts_with(&base) {
                return Ok(map);
            }
            let suffix = oid_suffix(&oid, base_len);
            if let Some(&idx) = suffix.first() {
                if let Value::OctetString(bytes) = val {
                    map.insert(idx as u32, bytes.to_vec());
                }
            }
            current = oid.to_owned();
            advanced = true;
        }

        if !advanced {
            break;
        }
    }

    Ok(map)
}

/// Walk LLDP table column. LLDP index: {timeMark}.{localPortNum}.{remIndex}
/// Returns map of (localPortNum, remIndex) -> string value.
fn walk_lldp_string(
    sess: &mut SyncSession,
    base_oids: &[u64],
) -> Result<HashMap<(u32, u32), String>, MikrotikError> {
    let base = make_oid(base_oids)?;
    let base_len = oid_components(&base).len();
    let mut map = HashMap::new();
    let mut current = base.clone();

    loop {
        let response = match sess.getnext(&current) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("SNMP walk error: {e}");
                break;
            }
        };

        let mut advanced = false;
        for (oid, val) in response.varbinds {
            if !oid.starts_with(&base) {
                return Ok(map);
            }
            let suffix = oid_suffix(&oid, base_len);
            // suffix: [timeMark, localPortNum, remIndex]
            if suffix.len() >= 3 {
                let local_port = suffix[1] as u32;
                let rem_idx = suffix[2] as u32;
                map.insert((local_port, rem_idx), value_to_string(&val));
            }
            current = oid.to_owned();
            advanced = true;
        }

        if !advanced {
            break;
        }
    }

    Ok(map)
}

/// Walk LLDP table column returning raw bytes (for chassis ID).
fn walk_lldp_raw(
    sess: &mut SyncSession,
    base_oids: &[u64],
) -> Result<HashMap<(u32, u32), Vec<u8>>, MikrotikError> {
    let base = make_oid(base_oids)?;
    let base_len = oid_components(&base).len();
    let mut map = HashMap::new();
    let mut current = base.clone();

    loop {
        let response = match sess.getnext(&current) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("SNMP walk error: {e}");
                break;
            }
        };

        let mut advanced = false;
        for (oid, val) in response.varbinds {
            if !oid.starts_with(&base) {
                return Ok(map);
            }
            let suffix = oid_suffix(&oid, base_len);
            if suffix.len() >= 3 {
                let local_port = suffix[1] as u32;
                let rem_idx = suffix[2] as u32;
                if let Value::OctetString(bytes) = val {
                    map.insert((local_port, rem_idx), bytes.to_vec());
                }
            }
            current = oid.to_owned();
            advanced = true;
        }

        if !advanced {
            break;
        }
    }

    Ok(map)
}

/// Walk a table and call a closure with (suffix_components, value).
fn walk_indexed_fn(
    sess: &mut SyncSession,
    base: &Oid,
    mut handler: impl FnMut(&[u64], Value),
) -> Result<(), MikrotikError> {
    let base_len = oid_components(base).len();
    let mut current = base.clone();

    loop {
        let response = match sess.getnext(&current) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("SNMP walk error: {e}");
                break;
            }
        };

        let mut advanced = false;
        for (oid, val) in response.varbinds {
            if !oid.starts_with(base) {
                return Ok(());
            }
            let suffix = oid_suffix(&oid, base_len);
            handler(&suffix, val);
            current = oid.to_owned();
            advanced = true;
        }

        if !advanced {
            break;
        }
    }

    Ok(())
}

/// Walk a table returning raw bytes for OctetString entries.
fn walk_indexed_raw_fn(
    sess: &mut SyncSession,
    base: &Oid,
    mut handler: impl FnMut(&[u64], &[u8]),
) -> Result<(), MikrotikError> {
    let base_len = oid_components(base).len();
    let mut current = base.clone();

    loop {
        let response = match sess.getnext(&current) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("SNMP walk error: {e}");
                break;
            }
        };

        let mut advanced = false;
        for (oid, val) in response.varbinds {
            if !oid.starts_with(base) {
                return Ok(());
            }
            let suffix = oid_suffix(&oid, base_len);
            if let Value::OctetString(bytes) = val {
                handler(&suffix, bytes);
            }
            current = oid.to_owned();
            advanced = true;
        }

        if !advanced {
            break;
        }
    }

    Ok(())
}

/// Extract a string from an SNMP value.
fn value_to_string(val: &Value) -> String {
    match val {
        Value::OctetString(bytes) => String::from_utf8_lossy(bytes).to_string(),
        Value::Integer(n) => n.to_string(),
        Value::Counter32(n) => n.to_string(),
        Value::Counter64(n) => n.to_string(),
        Value::Unsigned32(n) => n.to_string(),
        Value::Timeticks(n) => n.to_string(),
        Value::ObjectIdentifier(oid) => oid.to_id_string(),
        _ => String::new(),
    }
}

/// Extract a u64 from an SNMP value.
fn value_to_u64(val: &Value) -> u64 {
    match val {
        Value::Integer(n) => *n as u64,
        Value::Counter32(n) => *n as u64,
        Value::Counter64(n) => *n,
        Value::Unsigned32(n) => *n as u64,
        Value::Timeticks(n) => *n as u64,
        _ => 0,
    }
}

/// Format 6 bytes as a MAC address string.
fn format_mac(bytes: &[u8]) -> String {
    if bytes.len() == 6 {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    } else {
        bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// Decode an SNMP PortList bitmap (OCTET STRING) into port indices (1-based).
/// MSB of first byte = port 1, next bit = port 2, etc.
fn decode_portlist(bytes: &[u8]) -> Vec<u32> {
    let mut ports = Vec::new();
    for (byte_idx, &byte) in bytes.iter().enumerate() {
        for bit in 0..8 {
            if byte & (0x80 >> bit) != 0 {
                ports.push((byte_idx * 8 + bit + 1) as u32);
            }
        }
    }
    ports
}
