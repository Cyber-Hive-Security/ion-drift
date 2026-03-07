// Auth types (standard casing — hand-written Rust structs)

export interface AuthStatus {
  authenticated: boolean;
  user?: UserInfo;
}

export interface UserInfo {
  user_id: string;
  username: string;
  email: string | null;
}

// System types (kebab-case from #[serde(rename_all = "kebab-case")])

export interface SystemResource {
  ".id"?: string;
  uptime: string;
  version: string;
  "build-time"?: string;
  "factory-software"?: string;
  "free-memory": number;
  "total-memory": number;
  cpu: string;
  "cpu-count": number;
  "cpu-frequency": number;
  "cpu-load": number;
  "free-hdd-space": number;
  "total-hdd-space": number;
  "architecture-name"?: string;
  "board-name": string;
  platform: string;
  "mac-address"?: string;
}

export interface SystemIdentity {
  name: string;
}

// Interface types (kebab-case)

export interface RouterInterface {
  ".id": string;
  name: string;
  "default-name"?: string;
  type: string;
  mtu?: number;
  "actual-mtu"?: number;
  "mac-address"?: string;
  running: boolean;
  disabled: boolean;
  comment?: string;
  "rx-byte"?: number;
  "tx-byte"?: number;
  "rx-packet"?: number;
  "tx-packet"?: number;
  "last-link-up-time"?: string;
}

export interface VlanInterface {
  ".id": string;
  name: string;
  "vlan-id": number;
  interface: string;
  mtu?: number;
  running: boolean;
  disabled: boolean;
  comment?: string;
  "mac-address"?: string;
}

// IP types (kebab-case)

export interface IpAddress {
  ".id": string;
  address: string;
  network: string;
  interface: string;
  "actual-interface"?: string;
  disabled: boolean;
  dynamic?: boolean;
  invalid?: boolean;
  comment?: string;
}

export interface Route {
  ".id": string;
  "dst-address": string;
  gateway?: string;
  distance?: number;
  "routing-table"?: string;
  scope?: string;
  active?: boolean;
  dynamic?: boolean;
  disabled?: boolean;
  comment?: string;
}

export interface DhcpLease {
  ".id": string;
  address: string;
  "mac-address"?: string;
  "host-name"?: string;
  server?: string;
  status?: string;
  "active-address"?: string;
  "active-mac-address"?: string;
  "expires-after"?: string;
  "last-seen"?: string;
  dynamic?: boolean;
  disabled?: boolean;
  comment?: string;
}

// Firewall types (kebab-case)

export interface FilterRule {
  ".id": string;
  chain: string;
  action: string;
  "src-address"?: string;
  "dst-address"?: string;
  protocol?: string;
  "src-port"?: string;
  "dst-port"?: string;
  "in-interface"?: string;
  "out-interface"?: string;
  "in-interface-list"?: string;
  "out-interface-list"?: string;
  "src-address-list"?: string;
  "dst-address-list"?: string;
  "connection-state"?: string;
  "connection-nat-state"?: string;
  disabled?: boolean;
  dynamic?: boolean;
  bytes?: number;
  packets?: number;
  comment?: string;
  log?: string;
  "log-prefix"?: string;
}

export interface NatRule {
  ".id": string;
  chain: string;
  action: string;
  "src-address"?: string;
  "dst-address"?: string;
  protocol?: string;
  "src-port"?: string;
  "dst-port"?: string;
  "in-interface"?: string;
  "out-interface"?: string;
  "in-interface-list"?: string;
  "out-interface-list"?: string;
  "to-addresses"?: string;
  "to-ports"?: string;
  disabled?: boolean;
  dynamic?: boolean;
  bytes?: number;
  packets?: number;
  comment?: string;
}

export interface MangleRule {
  ".id": string;
  chain: string;
  action: string;
  "src-address"?: string;
  "dst-address"?: string;
  protocol?: string;
  "src-port"?: string;
  "dst-port"?: string;
  "in-interface"?: string;
  "out-interface"?: string;
  passthrough?: string;
  "new-packet-mark"?: string;
  "new-connection-mark"?: string;
  "new-routing-mark"?: string;
  disabled?: boolean;
  dynamic?: boolean;
  bytes?: number;
  packets?: number;
  comment?: string;
}

// Log types (kebab-case — raw from RouterOS, kept for backwards compat)

export interface LogEntry {
  ".id": string;
  time: string;
  topics?: string;
  message: string;
}

// Structured log types (snake_case — custom Rust structs)

export interface ParsedFields {
  direction?: string;
  in_interface?: string;
  out_interface?: string;
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  protocol?: string;
  action?: string;
  mac?: string;
  length?: number;
  src_country?: GeoInfo;
  dst_country?: GeoInfo;
  src_flagged: boolean;
  dst_flagged: boolean;
  manufacturer?: string;
}

export interface StructuredLogEntry {
  id: string;
  timestamp: string;
  topics: string[];
  level: string;
  prefix?: string;
  message: string;
  parsed?: ParsedFields;
  /** Raw messages from non-terminating log rules that matched the same packet. */
  paired_messages?: string[];
}

export interface IpCount {
  ip: string;
  count: number;
  country?: GeoInfo;
  flagged: boolean;
}

export interface PortCount {
  port: number;
  count: number;
  protocol?: string;
}

export interface InterfaceCount {
  interface: string;
  count: number;
}

export interface TimeCount {
  minute: string;
  count: number;
}

export interface LogAnalytics {
  total: number;
  by_severity: Record<string, number>;
  by_action: Record<string, number>;
  by_topic: Record<string, number>;
  top_dropped_sources: IpCount[];
  top_targeted_ports: PortCount[];
  drops_per_interface: InterfaceCount[];
  volume_over_time: TimeCount[];
}

export interface LogsResponse {
  entries: StructuredLogEntry[];
  analytics: LogAnalytics;
}

// Traffic types (snake_case — custom Rust structs, not RouterOS models)

export interface LifetimeTraffic {
  rx_bytes: number;
  tx_bytes: number;
  interface: string;
}

// Metrics types (snake_case — custom Rust structs)

export interface MetricsPoint {
  timestamp: number;
  cpu_load: number;
  memory_used: number;
  memory_total: number;
}

// Live traffic types (snake_case — custom Rust structs)

export interface TrafficSample {
  timestamp: number;
  rx_bps: number;
  tx_bps: number;
}

// IP pool / DHCP server types (kebab-case)

export interface IpPool {
  ".id": string;
  name: string;
  ranges: string;
  comment?: string;
}

export interface DhcpServer {
  ".id": string;
  name: string;
  interface: string;
  "address-pool"?: string;
  disabled?: boolean;
  comment?: string;
}

// VLAN flow types (snake_case — custom Rust structs)

export interface VlanFlow {
  source: string;
  target: string;
  bytes: number;
}

// Connection summary types (snake_case — custom Rust structs)

export interface ConnectionSummary {
  total_connections: number;
  tcp_count: number;
  udp_count: number;
  other_count: number;
  max_entries: number | null;
  flagged_count: number;
}

// Full connections page types (snake_case — custom Rust structs)

export interface GeoInfo {
  country_code: string;
  country: string;
  city?: string;
  isp?: string;
  asn?: string;
  org?: string;
  lat?: number;
  lon?: number;
}

export interface ConnectionEntry {
  id: string;
  protocol: string;
  src_address: string;
  src_port: string;
  dst_address: string;
  dst_port: string;
  tcp_state: string | null;
  timeout: string | null;
  orig_bytes: number;
  repl_bytes: number;
  connection_mark: string | null;
  src_geo: GeoInfo | null;
  dst_geo: GeoInfo | null;
  flagged: boolean;
}

export interface ConnectionsPageSummary {
  total: number;
  by_protocol: Record<string, number>;
  by_state: Record<string, number>;
  flagged_count: number;
  max_entries: number | null;
}

export interface ConnectionsPageResponse {
  connections: ConnectionEntry[];
  summary: ConnectionsPageSummary;
}

// ARP types (snake_case — custom Rust structs)

export interface ArpEntry {
  id: string;
  address: string;
  mac_address: string | null;
  interface: string | null;
  dynamic: boolean | null;
  complete: boolean | null;
  disabled: boolean | null;
  comment: string | null;
  manufacturer: string | null;
}

// Enhanced DHCP lease with ARP status (snake_case — custom Rust structs)

export interface DhcpLeaseStatus {
  id: string;
  address: string;
  mac_address: string | null;
  host_name: string | null;
  server: string | null;
  status: string | null;
  expires_after: string | null;
  last_seen: string | null;
  dynamic: boolean | null;
  disabled: boolean | null;
  comment: string | null;
  manufacturer: string | null;
  arp_status: string;
}

// Pool utilization with ARP (snake_case — custom Rust structs)

export interface PoolUtilization {
  name: string;
  interface: string;
  pool_name: string;
  total_ips: number;
  bound_count: number;
  active_on_network: number;
  pct: number;
}

// Firewall drops types (snake_case — custom Rust structs)

export interface DropCountryEntry {
  code: string;
  name: string;
  count: number;
  flagged: boolean;
}

export interface FirewallDropsSummary {
  total_drop_packets: number;
  total_drop_bytes: number;
  top_drop_countries: DropCountryEntry[];
}

// VLAN activity types (snake_case — custom Rust structs)

export interface VlanActivityEntry {
  name: string;
  rx_bps: number;
  tx_bps: number;
}

// Drop metrics history (snake_case — custom Rust structs)

export interface DropMetricsPoint {
  timestamp: number;
  drop_packets: number;
  drop_bytes: number;
}

// Connection metrics history (snake_case — custom Rust structs)

export interface ConnectionMetricsPoint {
  timestamp: number;
  total: number;
  tcp: number;
  udp: number;
  other: number;
}

// VLAN metrics history (snake_case — custom Rust structs)

export interface VlanMetricsPoint {
  timestamp: number;
  vlan_name: string;
  rx_bps: number;
  tx_bps: number;
}

// Log aggregate roll-ups (snake_case — custom Rust structs)

export interface LogAggregate {
  timestamp: number;
  period_start: number;
  period_end: number;
  total_entries: number;
  drop_count: number;
  accept_count: number;
  top_drop_source: string | null;
  top_drop_source_count: number;
  top_target_port: number | null;
  top_target_port_count: number;
  drops_by_interface: string;
}

// Network map live status (snake_case — custom Rust structs)

export interface DeviceStatus {
  ip: string;
  mac: string | null;
  hostname: string | null;
  manufacturer: string | null;
  in_arp: boolean;
  dhcp_status: string | null;
  dhcp_server: string | null;
  expires_after: string | null;
  last_seen: string | null;
  hop_count: number | null;
  internet_path: string | null;
}

export interface InterfaceStatus {
  name: string;
  running: boolean;
  rx_byte: number;
  tx_byte: number;
  rx_rate_bps: number;
  tx_rate_bps: number;
  disabled: boolean;
}

export interface NetworkMapStatus {
  devices: DeviceStatus[];
  interfaces: InterfaceStatus[];
  timestamp: number;
}

// Behavior / Device Fingerprinting types (snake_case — custom Rust structs)

export interface DeviceProfile {
  mac: string;
  hostname: string | null;
  manufacturer: string | null;
  current_ip: string | null;
  current_vlan: number | null;
  first_seen: number;
  last_seen: number;
  learning_until: number;
  baseline_status: string;
  notes: string | null;
}

export interface DeviceBaseline {
  id: number;
  mac: string;
  protocol: string;
  dst_port: number | null;
  dst_subnet: string;
  direction: string;
  avg_bytes_per_hour: number;
  max_bytes_per_hour: number;
  observation_count: number;
  computed_at: number;
}

export interface DeviceAnomaly {
  id: number;
  mac: string;
  timestamp: number;
  anomaly_type: string;
  severity: string;
  confidence: number;
  description: string;
  details: string | null;
  vlan: number;
  firewall_correlation: string | null;
  firewall_rule_id: string | null;
  firewall_rule_comment: string | null;
  status: string;
  resolved_at: number | null;
  resolved_by: string | null;
}

export interface VlanBehaviorSummary {
  vlan: number;
  device_count: number;
  baselined_count: number;
  learning_count: number;
  sparse_count: number;
  pending_anomaly_count: number;
}

export interface BehaviorOverview {
  total_devices: number;
  baselined_devices: number;
  learning_devices: number;
  sparse_devices: number;
  pending_anomalies: number;
  critical_anomalies: number;
  warning_anomalies: number;
  vlan_summaries: VlanBehaviorSummary[];
}

export interface VlanBehaviorDetail {
  vlan: number;
  devices: DeviceProfile[];
  anomalies: DeviceAnomaly[];
}

export interface PortFlowContext {
  port: number;
  protocol: string;
  port_is_baselined: boolean;
  port_days_in_baseline: number;
  correlated: boolean;
  other_devices_count: number;
  network_level_classification: string;
  total_network_bytes_on_port: number;
}

export interface AnomalyLink {
  id: number;
  port_anomaly_type: string;
  flow_direction: string;
  protocol: string;
  dst_port: number;
  device_mac: string;
  device_ip: string;
  device_vlan: string | null;
  device_hostname: string | null;
  behavior_anomaly_id: number | null;
  correlated: boolean;
  source: string;
  severity: string;
  device_bytes: number;
  device_connections: number;
  port_is_baselined: boolean;
  port_days_in_baseline: number;
  created_at: string;
  resolved_at: string | null;
  resolved_by: string | null;
}

export interface DeviceDetailResponse {
  profile: DeviceProfile;
  baselines: DeviceBaseline[];
  anomalies: DeviceAnomaly[];
  port_flow_contexts: PortFlowContext[];
}

export interface AlertCount {
  pending_count: number;
  critical_count: number;
  warning_count: number;
  anomaly_macs: string[];
}

// Settings / Secrets types (snake_case — custom Rust structs)

export interface SecretStatus {
  name: string;
  updated_at: number;
  key_current: boolean;
  auto_generated?: boolean;
  stored: boolean;
}

export interface SecretsStatusResponse {
  secrets: SecretStatus[];
  key_fingerprint: string;
}

export interface UpdateSecretsRequest {
  router_username?: string;
  router_password?: string;
  oidc_client_secret?: string;
  certwarden_cert_api_key?: string;
  certwarden_key_api_key?: string;
  maxmind_account_id?: string;
  maxmind_license_key?: string;
}

export interface UpdateSecretsResponse {
  updated: string[];
}

export interface RegenerateSessionResponse {
  status: string;
}

export interface EncryptionStatusResponse {
  key_fingerprint: string;
  source: string;
  all_secrets_current: boolean;
}

export interface CertStatusResponse {
  subject_cn: string;
  issuer_cn: string;
  not_before: number;
  not_after: number;
  seconds_until_expiry: number;
  serial: string;
  auto_renewal_enabled: boolean;
  renewal_threshold_days: number;
  check_interval_hours: number;
}

// Connection history types (snake_case — custom Rust structs)

export interface ConnectionHistoryEntry {
  id: number;
  conntrack_id: string | null;
  protocol: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number | null;
  src_mac: string | null;
  src_vlan: string | null;
  src_hostname: string | null;
  dst_vlan: string | null;
  dst_hostname: string | null;
  first_seen: string;
  last_seen: string;
  closed: boolean;
  last_state: string | null;
  duration_seconds: number | null;
  bytes_tx: number;
  bytes_rx: number;
  data_source: string;
  poll_count: number;
  dst_is_external: boolean;
  geo_country_code: string | null;
  geo_country: string | null;
  geo_city: string | null;
  geo_asn: number | null;
  geo_org: string | null;
  geo_lat: number | null;
  geo_lon: number | null;
  flagged: boolean;
  anomaly_id: number | null;
}

export interface PaginatedHistory {
  items: ConnectionHistoryEntry[];
  total: number;
  page: number;
  per_page: number;
}

export interface GeoSummaryEntry {
  country_code: string;
  country: string;
  lat: number;
  lon: number;
  connection_count: number;
  unique_sources: number;
  unique_destinations: number;
  total_tx: number;
  total_rx: number;
  top_orgs: string[];
  flagged_count: number;
}

export interface CitySummaryEntry {
  city: string;
  country_code: string;
  lat: number;
  lon: number;
  connection_count: number;
  unique_ips: number;
  bytes_tx: number;
  bytes_rx: number;
  top_orgs: string[];
  flagged_count: number;
}

export interface PortSummaryEntry {
  dst_port: number;
  protocol: string;
  total_bytes: number;
  flow_count: number;
  unique_sources: number;
  unique_destinations: number;
}

export type PortDirection = "outbound" | "inbound" | "internal";

export type FlowClassification =
  | "normal"
  | "new_port"
  | "volume_spike"
  | "source_anomaly"
  | "disappeared";

export interface InvolvedDevice {
  mac: string;
  ip: string;
  hostname: string | null;
  vlan: string | null;
  bytes: number;
  connections: number;
  has_behavior_anomaly: boolean;
  behavior_anomaly_id: number | null;
  correlated: boolean;
}

export interface ClassifiedPortFlow {
  dst_port: number;
  protocol: string;
  total_bytes: number;
  flow_count: number;
  unique_sources: number;
  unique_destinations: number;
  classification: FlowClassification;
  baseline_avg_bytes: number | null;
  volume_ratio: number | null;
  days_in_baseline: number;
  top_sources: string[];
  new_sources: string[];
  involved_devices: InvolvedDevice[];
}

export interface ClassifiedPortSummary {
  anomaly_count: number;
  has_baselines: boolean;
  flows: ClassifiedPortFlow[];
  disappeared: ClassifiedPortFlow[];
}

export interface PortBaselineStatus {
  total_baselines: number;
  outbound_count: number;
  internal_count: number;
  last_computed: string | null;
}

export interface WeeklySnapshot {
  id: number;
  snapshot_week: string;
  snapshot_type: string;
  period_start: string;
  period_end: string;
  data: string;
  summary: string;
  created_at: string;
}

export interface SnapshotListEntry {
  week: string;
  types: string[];
  summary: string;
}

export interface SyslogStatus {
  port: number;
  enabled: boolean;
  events_today: number;
  events_week: number;
  listening: boolean;
}

export interface GeoIpStatus {
  has_maxmind: boolean;
  has_credentials: boolean;
}

export interface ConnectionHistoryStats {
  retention_days: number;
  row_count: number;
  db_size_bytes: number;
  oldest_record: string | null;
}

// ── Multi-device types (snake_case — custom Rust structs) ─────────

export interface NetworkDevice {
  id: string;
  name: string;
  host: string;
  port: number;
  tls: boolean;
  ca_cert_path: string | null;
  device_type: string;
  model: string | null;
  is_primary: boolean;
  enabled: boolean;
  poll_interval_secs: number;
  created_at: number;
  updated_at: number;
  /** "Online", "Offline", or "Unknown" */
  status: string;
  /** Router identity when online */
  identity?: string;
  /** Error message when offline */
  error?: string;
}

export interface CreateDeviceRequest {
  id: string;
  name: string;
  host: string;
  port?: number;
  tls?: boolean;
  ca_cert_path?: string;
  device_type: string;
  model?: string;
  is_primary?: boolean;
  enabled?: boolean;
  poll_interval_secs?: number;
  username: string;
  password: string;
  // SNMPv3 extras
  snmp_auth_protocol?: string;
  snmp_priv_password?: string;
  snmp_priv_protocol?: string;
}

export interface UpdateDeviceRequest {
  name?: string;
  host?: string;
  port?: number;
  tls?: boolean;
  ca_cert_path?: string;
  model?: string;
  enabled?: boolean;
  poll_interval_secs?: number;
  username?: string;
  password?: string;
  // SNMPv3 extras
  snmp_auth_protocol?: string;
  snmp_priv_password?: string;
  snmp_priv_protocol?: string;
}

export interface TestConnectionRequest {
  host: string;
  port?: number;
  tls?: boolean;
  ca_cert_path?: string;
  device_type?: string;
  username: string;
  password: string;
  snmp_auth_protocol?: string;
  snmp_priv_password?: string;
  snmp_priv_protocol?: string;
}

export interface TestConnectionResponse {
  status: "online" | "offline";
  identity?: string;
  error?: string;
}

// ── Switch data types (from switch_store.rs) ─────────────────

/** Port metrics from GET /api/devices/{id}/ports.
 *  Rust tuple: (port_name, rx_bytes, tx_bytes, timestamp, speed?, running) */
export type PortMetricsTuple = [string, number, number, number, string | null, boolean];

export interface MacTableEntry {
  device_id: string;
  mac_address: string;
  port_name: string;
  bridge: string;
  vlan_id: number | null;
  is_local: boolean;
  first_seen: number;
  last_seen: number;
}

export interface NeighborEntry {
  device_id: string;
  interface: string;
  mac_address: string | null;
  address: string | null;
  identity: string | null;
  platform: string | null;
  board: string | null;
  version: string | null;
  first_seen: number;
  last_seen: number;
}

export interface NetworkIdentity {
  mac_address: string;
  best_ip: string | null;
  hostname: string | null;
  manufacturer: string | null;
  switch_device_id: string | null;
  switch_port: string | null;
  vlan_id: number | null;
  discovery_protocol: string | null;
  remote_identity: string | null;
  remote_platform: string | null;
  first_seen: number;
  last_seen: number;
  confidence: number;
  device_type: string | null;
  device_type_source: string | null;
  device_type_confidence: number;
  human_confirmed: boolean;
  human_label: string | null;
  disposition: DeviceDisposition;
  is_infrastructure: boolean | null;
  switch_binding_source: string;
  link_speed_mbps: number | null;
}

export type DeviceDisposition = "unknown" | "my_device" | "external" | "ignored" | "flagged";

export interface VlanMembershipEntry {
  port_name: string;
  vlan_id: number;
  tagged: boolean;
}

export interface PortRoleEntry {
  device_id: string;
  port_name: string;
  role: string;
  vlan_count: number;
  mac_count: number;
  has_lldp_neighbor: boolean;
  updated_at: number;
}

export interface DevicePort {
  port_name: string;
  speed: string | null;
  running: boolean;
  role: string | null;
  mac_count: number | null;
}

export interface IdentityStats {
  total: number;
  confirmed: number;
  unconfirmed: number;
  by_device_type: Record<string, number>;
  by_source: Record<string, number>;
  by_disposition: Record<string, number>;
}

export interface NmapScan {
  id: string;
  vlan_id: number;
  profile: string;
  status: string;
  target_count: number;
  discovered_count: number;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
  created_at: string;
}

export interface NmapResult {
  id: number;
  scan_id: string;
  ip_address: string;
  mac_address: string | null;
  hostname: string | null;
  os_guess: string | null;
  os_accuracy: number | null;
  open_ports: string | null;
  device_type: string | null;
  created_at: string;
}

export interface ScanExclusion {
  ip_address: string;
  reason: string | null;
  created_at: string;
}

export interface ScanStatus {
  scanning: boolean;
  nmap_available: boolean;
}

export interface UpdateIdentityRequest {
  device_type?: string;
  human_label?: string;
  switch_device_id?: string;
  switch_port?: string;
  is_infrastructure?: boolean | null;
}

export interface StartScanRequest {
  vlan_id: number;
  profile: "quick" | "standard" | "deep";
}

// ── Observed Services (Passive Discovery) ─────────────────────

export interface ObservedService {
  ip_address: string;
  port: number;
  protocol: string;
  service_name: string | null;
  first_seen: number;
  last_seen: number;
  connection_count: number;
}

// ── Port MAC Bindings & Violations ─────────────────────────────

export interface PortMacBinding {
  device_id: string;
  port_name: string;
  expected_mac: string;
  created_at: string;
  created_by: string;
}

export interface PortViolation {
  id: number;
  device_id: string;
  port_name: string;
  expected_mac: string;
  actual_mac: string | null;
  violation_type: "mac_mismatch" | "device_missing";
  first_seen: string;
  last_seen: string;
  resolved: boolean;
  resolved_at: string | null;
}

// ── Backbone Links ────────────────────────────────────────────

export interface BackboneLink {
  id: number;
  device_a: string;
  port_a: string | null;
  device_b: string;
  port_b: string | null;
  label: string | null;
  speed_mbps: number | null;
  link_type: string | null;
  created_at: string;
}

export interface CreateBackboneLinkRequest {
  device_a: string;
  port_a?: string;
  device_b: string;
  port_b?: string;
  label?: string;
  link_type?: string;
  speed_mbps?: number;
}

export interface UpdateBackboneLinkRequest {
  port_a?: string;
  port_b?: string;
  label?: string;
  link_type?: string;
  speed_mbps?: number;
}

// ── Neighbor Aliases ───────────────────────────────────────────

export interface NeighborAlias {
  id: number;
  match_type: "mac" | "identity";
  match_value: string;
  action: "alias" | "hide";
  target_device_id: string | null;
  created_at: string;
}

export interface CreateNeighborAliasRequest {
  match_type: "mac" | "identity";
  match_value: string;
  action: "alias" | "hide";
  target_device_id?: string;
}

// ── Network Topology ───────────────────────────────────────────

export type TopologyNodeKind =
  | "router"
  | "managed_switch"
  | "unmanaged_switch"
  | "access_point"
  | "server"
  | "workstation"
  | "camera"
  | "printer"
  | "phone"
  | "iot"
  | "smart_home"
  | "media_player"
  | "unknown";

export type TopologyEdgeKind = "trunk" | "access" | "wireless" | "uplink";
export type TopologyNodeStatus = "online" | "offline" | "unknown";

export interface TopologyNode {
  id: string;
  label: string;
  ip: string | null;
  mac: string | null;
  kind: TopologyNodeKind;
  vlan_id: number | null;
  vlans_served: number[];
  device_type: string | null;
  manufacturer: string | null;
  is_infrastructure: boolean;
  layer: number;
  x: number;
  y: number;
  position_source: string;
  first_seen: number;
  last_seen: number;
  parent_id: string | null;
  switch_port: string | null;
  status: TopologyNodeStatus;
  confidence: number;
  disposition: DeviceDisposition;
}

export interface TopologyEdge {
  source: string;
  target: string;
  kind: TopologyEdgeKind;
  source_port: string | null;
  target_port: string | null;
  vlans: number[];
  speed_mbps: number | null;
  traffic_bps: number | null;
}

export interface TopologyVlanGroup {
  vlan_id: number;
  name: string;
  color: string;
  subnet: string;
  node_count: number;
  bbox_x: number;
  bbox_y: number;
  bbox_w: number;
  bbox_h: number;
  position_source: string;
}

export interface NetworkTopologyResponse {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  vlan_groups: TopologyVlanGroup[];
  computed_at: number;
  node_count: number;
  edge_count: number;
  infrastructure_count: number;
  endpoint_count: number;
}

export interface TopologyPosition {
  node_id: string;
  x: number;
  y: number;
  source: string;
  updated_at: string;
}

export interface SectorPosition {
  vlan_id: number;
  x: number;
  y: number;
  width: number | null;
  height: number | null;
  source: string;
  updated_at: string;
}

// ── VLAN Config ─────────────────────────────────────────────────
export interface VlanConfig {
  vlan_id: number;
  name: string;
  media_type: "wired" | "wireless" | "mixed";
  subnet: string | null;
  color: string | null;
  sensitivity: string | null;
}

// ── Topology Inference ──────────────────────────────────────────

export interface InferenceStatus {
  mode: string;
  total_macs: number;
  state_distribution: Record<string, number>;
  avg_confidence: number;
  divergence_count: number;
  divergence_categories: Record<string, number>;
  last_cycle_ts: number;
}

export interface CandidateFeatures {
  edge_likelihood: number;
  persistence: number;
  vlan_consistency: number;
  downstream_preference: number;
  recency: number;
  graph_depth_score: number;
  device_class_fit: number;
  transit_penalty: number;
  contradiction_penalty: number;
  router_penalty: number;
  wireless_attachment_likelihood: number;
  wap_path_consistency: number;
  ap_feeder_penalty: number;
}

export interface ScoredCandidate {
  mac: string;
  device_id: string;
  port_name: string;
  vlan_id: number | null;
  candidate_type: string;
  observation_count: number;
  suppressed: boolean;
  suppression_reason: string | null;
  features: CandidateFeatures;
  score: number;
}

export interface AttachmentStateRow {
  mac_address: string;
  state: string;
  current_device_id: string | null;
  current_port_name: string | null;
  previous_device_id: string | null;
  previous_port_name: string | null;
  current_score: number;
  confidence: number;
  consecutive_wins: number;
  consecutive_losses: number;
  updated_at: number;
}

export interface InferenceMacDetail {
  mac: string;
  state: AttachmentStateRow;
  current_binding: {
    device_id: string;
    port: string;
    source: string;
  } | null;
  candidates: ScoredCandidate[];
  explanation: string[];
}

export interface ObservationStats {
  total_observations: number;
  unique_macs: number;
  observations_per_device: Record<string, number>;
}

// ── Provision / Setup Wizard types ──────────────────────────────

export interface ProvisionInterface {
  name: string;
  type: string;
  running: boolean;
  comment: string | null;
}

export interface ProvisionConfig {
  wan_interface: string;
  syslog_host: string;
  syslog_port: number;
  router_source_ip: string;
}

export interface ProvisionItem {
  id: string;
  category: string;
  action: string;
  title: string;
  description: string;
  detail: Record<string, unknown>;
}

export interface ProvisionPlan {
  items: ProvisionItem[];
  summary: {
    create: number;
    skip: number;
    update: number;
    total_mangle: number;
    total_syslog: number;
    total_firewall: number;
  };
}

export interface ApplyItemResult {
  id: string;
  title: string;
  success: boolean;
  error: string | null;
}

export interface ApplyResult {
  results: ApplyItemResult[];
  succeeded: number;
  failed: number;
}
