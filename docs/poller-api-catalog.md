# Background Poller API Call Catalog

Every background task that polls the Mikrotik RB4011 router via its REST API.

**API Client:** `MikrotikClient` in `crates/mikrotik-core/src/client.rs`
- `get<T: DeserializeOwned>(path) -> Result<T, MikrotikError>` — `GET /rest/{path}`, deserializes JSON
- `post<T: DeserializeOwned, B: Serialize>(path, body) -> Result<T, MikrotikError>` — `POST /rest/{path}`
- All convenience methods (below) delegate to `get()` or `post()`

---

### Poller: spawn_traffic_poller
File: `crates/ion-drift-web/src/tasks/traffic.rs`
Function: `spawn_traffic_poller`
Interval: 10s (live rates); lifetime totals every 90 ticks (~15 min)
API Calls:
  1. `client.interfaces()` — `GET /rest/interface` -> `Vec<Interface>` (every 10s)
  2. `tracker.poll(&client)` which calls `client.interfaces()` — `GET /rest/interface` -> `Vec<Interface>` (every ~15 min)
Dependency: sequential (interfaces every tick; tracker.poll every 90th tick)
Priority: high

---

### Poller: spawn_vlan_metrics_poller
File: `crates/ion-drift-web/src/tasks/traffic.rs`
Function: `spawn_vlan_metrics_poller`
Interval: 60s
API Calls:
  1. `client.vlan_interfaces()` — `GET /rest/interface/vlan` -> `Vec<VlanInterface>`
  2. `client.monitor_traffic(name)` — `POST /rest/interface/monitor-traffic` (body: `{"interface": name, "once": ""}`) -> `Vec<MonitorTrafficEntry>` (one per VLAN, concurrent)
Dependency: sequential — step 1 fetches VLAN list, step 2 fans out concurrently per VLAN
Priority: normal

---

### Poller: spawn_metrics_poller
File: `crates/ion-drift-web/src/tasks/metrics.rs`
Function: `spawn_metrics_poller`
Interval: 60s
API Calls:
  1. `client.system_resources()` — `GET /rest/system/resource` -> `SystemResource`
Dependency: single call
Priority: normal

---

### Poller: spawn_drops_poller
File: `crates/ion-drift-web/src/tasks/metrics.rs`
Function: `spawn_drops_poller`
Interval: 60s
API Calls:
  1. `client.firewall_filter_rules()` — `GET /rest/ip/firewall/filter` -> `Vec<FilterRule>`
Dependency: single call
Priority: normal

---

### Poller: spawn_connection_metrics_poller
File: `crates/ion-drift-web/src/tasks/metrics.rs`
Function: `spawn_connection_metrics_poller`
Interval: 60s
API Calls:
  1. `client.firewall_connections(".id,protocol")` — `GET /rest/ip/firewall/connection?.proplist=.id,protocol` -> `Vec<ConnectionEntry>`
Dependency: single call
Priority: normal

---

### Poller: spawn_log_aggregation
File: `crates/ion-drift-web/src/tasks/metrics.rs`
Function: `spawn_log_aggregation`
Interval: 3600s (hourly), 120s startup delay
API Calls:
  1. `client.log_entries()` — `GET /rest/log` -> `Vec<LogEntry>`
Dependency: single call
Priority: low

---

### Poller: spawn_connection_persister
File: `crates/ion-drift-web/src/tasks/connections.rs`
Function: `spawn_connection_persister`
Interval: 30s, 60s startup delay
API Calls (concurrent via `tokio::join!`):
  1. `client.firewall_connections_full()` — `GET /rest/ip/firewall/connection` -> `Vec<FullConnectionEntry>`
  2. `client.arp_table()` — `GET /rest/ip/arp` -> `Vec<ArpEntry>` (inside `build_ip_to_mac`)
  3. `client.dhcp_leases()` — `GET /rest/ip/dhcp-server/lease` -> `Vec<DhcpLease>` (inside `build_ip_to_mac`)
Dependency: calls 1+2+3 are concurrent (tokio::join); 2 and 3 are also joined together inside build_ip_to_mac
Priority: high

---

### Poller: spawn_connection_pruner
File: `crates/ion-drift-web/src/tasks/connections.rs`
Function: `spawn_connection_pruner`
Interval: 24h, 3h startup delay
API Calls: **none** (DB-only pruning)
Priority: low

---

### Poller: spawn_behavior_collector
File: `crates/ion-drift-web/src/tasks/behavior.rs`
Function: `spawn_behavior_collector`
Interval: 60s, 180s startup delay
API Calls (per cycle, in order):
  **Step 1 — refresh_firewall_cache:**
  1. `client.firewall_filter_rules()` — `GET /rest/ip/firewall/filter` -> `Vec<FilterRule>` (cached, refreshes every 5 min)

  **Step 2 — collect_observations:**
  2. `client.arp_table()` — `GET /rest/ip/arp` -> `Vec<ArpEntry>` (concurrent with 3)
  3. `client.dhcp_leases()` — `GET /rest/ip/dhcp-server/lease` -> `Vec<DhcpLease>` (concurrent with 2)

  **Step 3 — detect_blocked_attempts:**
  4. `client.log_entries()` — `GET /rest/log` -> `Vec<LogEntry>`
  5. `client.arp_table()` — `GET /rest/ip/arp` -> `Vec<ArpEntry>` (concurrent with 6)
  6. `client.dhcp_leases()` — `GET /rest/ip/dhcp-server/lease` -> `Vec<DhcpLease>` (concurrent with 5)
Dependency: steps 1-2-3 are sequential; within each step, calls are concurrent where noted
Priority: high

---

### Poller: spawn_behavior_maintenance
File: `crates/ion-drift-web/src/tasks/behavior.rs`
Function: `spawn_behavior_maintenance`
Interval: daily at 3 AM + one startup run (after 5 min delay)
API Calls: **none** (DB-only: recompute baselines, prune, classify, auto-resolve)
Priority: low

---

### Poller: spawn_behavior_auto_classifier
File: `crates/ion-drift-web/src/tasks/behavior.rs`
Function: `spawn_behavior_auto_classifier`
Interval: 3600s (hourly)
API Calls: **none** (DB-only: auto-resolve stale anomalies)
Priority: low

---

### Poller: spawn_correlation_engine
File: `crates/ion-drift-web/src/correlation_engine.rs`
Function: `spawn_correlation_engine`
Interval: 60s, 90s startup delay
API Calls:
  **Step 0b — sync_vlan_config_from_router:**
  1. `router_client.vlan_interfaces()` — `GET /rest/interface/vlan` -> `Vec<VlanInterface>`
  2. `router_client.ip_addresses()` — `GET /rest/ip/address` -> `Vec<IpAddress>`

  **Step 1 — port role classification (router bridge hosts):**
  3. `router_client.bridge_hosts()` — `GET /rest/interface/bridge/host` -> `Vec<BridgeHost>`

  **Step 2 — identity assembly:**
  4. `router_client.arp_table()` — `GET /rest/ip/arp` -> `Vec<ArpEntry>`
  5. `router_client.dhcp_leases()` — `GET /rest/ip/dhcp-server/lease` -> `Vec<DhcpLease>`
Dependency: sequential (steps run in order within run_correlation)
Priority: high

---

### Poller: spawn_anomaly_correlator
File: `crates/ion-drift-web/src/anomaly_correlator.rs`
Function: `spawn_anomaly_correlator`
Interval: 60s, 300s startup delay
API Calls: **none** (DB-only: cross-references port flow anomalies with device behavior anomalies)
Priority: normal

---

### Poller: spawn_passive_discovery
File: `crates/ion-drift-web/src/passive_discovery.rs`
Function: `spawn_passive_discovery`
Interval: 120s, 150s startup delay
API Calls:
  **Step 1 — extract_nat_service_ports:**
  1. `router.firewall_nat_rules()` — `GET /rest/ip/firewall/nat` -> `Vec<NatRule>`
  2. `router.firewall_filter_rules()` — `GET /rest/ip/firewall/filter` -> `Vec<FilterRule>`

  **Step 2 — main discovery:**
  3. `router.firewall_connections_full()` — `GET /rest/ip/firewall/connection` -> `Vec<FullConnectionEntry>`
Dependency: sequential (step 1 before step 2)
Priority: normal

---

### Poller: spawn_alert_engine
File: `crates/ion-drift-web/src/alerting.rs`
Function: `spawn_alert_engine`
Interval: 60s, 30s startup delay
API Calls (conditional — only when `dhcp_pool_exhausted` rule is enabled):
  1. `state.mikrotik.dhcp_servers()` — `GET /rest/ip/dhcp-server` -> `Vec<DhcpServer>` (concurrent with 2, 3)
  2. `state.mikrotik.ip_pools()` — `GET /rest/ip/pool` -> `Vec<IpPool>` (concurrent with 1, 3)
  3. `state.mikrotik.dhcp_leases()` — `GET /rest/ip/dhcp-server/lease` -> `Vec<DhcpLease>` (concurrent with 1, 2)
Dependency: calls 1+2+3 concurrent via tokio::join!; other alert types are DB-only
Priority: normal

---

### Poller: spawn_policy_sync
File: `crates/ion-drift-web/src/tasks/policy_sync.rs`
Function: `spawn_policy_sync`
Interval: 3600s (hourly), runs immediately on startup
API Calls (sequential):
  1. `client.dhcp_networks()` — `GET /rest/ip/dhcp-server/network` -> `Vec<DhcpNetwork>`
  2. `client.dns_config()` — `GET /rest/ip/dns` -> `DnsConfig`
  3. `client.ip_routes()` — `GET /rest/ip/route` -> `Vec<Route>`
  4. `client.firewall_address_lists()` — `GET /rest/ip/firewall/address-list` -> `Vec<AddressListEntry>`
  5. `client.firewall_filter_rules()` — `GET /rest/ip/firewall/filter` -> `Vec<FilterRule>`
Dependency: sequential (each step processes results before the next)
Priority: normal

---

## Summary: API Endpoint Load

| REST Path | Pollers | Min Interval |
|-----------|---------|-------------|
| `interface` | traffic_poller | 10s |
| `interface/vlan` | vlan_metrics, correlation_engine | 60s |
| `interface/monitor-traffic` (POST) | vlan_metrics | 60s (N calls) |
| `system/resource` | metrics_poller | 60s |
| `ip/firewall/filter` | drops_poller, behavior_collector, passive_discovery, policy_sync | 60s |
| `ip/firewall/connection?.proplist=...` | connection_metrics_poller | 60s |
| `ip/firewall/connection` (full) | connection_persister, passive_discovery | 30s |
| `ip/arp` | connection_persister, behavior_collector(x2), correlation_engine | 30s |
| `ip/dhcp-server/lease` | connection_persister, behavior_collector(x2), correlation_engine, alert_engine | 30s |
| `log` | log_aggregation, behavior_collector | 60s |
| `interface/bridge/host` | correlation_engine | 60s |
| `ip/address` | correlation_engine | 60s |
| `ip/firewall/nat` | passive_discovery | 120s |
| `ip/firewall/address-list` | policy_sync | 3600s |
| `ip/dhcp-server/network` | policy_sync | 3600s |
| `ip/dns` | policy_sync | 3600s |
| `ip/route` | policy_sync | 3600s |
| `ip/dhcp-server` | alert_engine | 60s (conditional) |
| `ip/pool` | alert_engine | 60s (conditional) |
