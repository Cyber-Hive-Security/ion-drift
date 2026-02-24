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

// Speedtest types (snake_case — custom Rust structs)

export interface ProviderResult {
  provider: string;
  download_mbps: number;
  upload_mbps: number;
  latency_ms: number;
  server_location: string | null;
}

export interface SpeedTestResult {
  providers: ProviderResult[];
  median_download_mbps: number;
  median_upload_mbps: number;
  median_latency_ms: number;
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
  pending_anomaly_count: number;
}

export interface BehaviorOverview {
  total_devices: number;
  baselined_devices: number;
  learning_devices: number;
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

export interface DeviceDetailResponse {
  profile: DeviceProfile;
  baselines: DeviceBaseline[];
  anomalies: DeviceAnomaly[];
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

export interface PortSummaryEntry {
  dst_port: number;
  protocol: string;
  total_bytes: number;
  flow_count: number;
  unique_sources: number;
  unique_destinations: number;
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
