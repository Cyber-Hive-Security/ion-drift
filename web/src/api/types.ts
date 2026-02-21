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

// Log types (kebab-case)

export interface LogEntry {
  ".id": string;
  time: string;
  topics?: string;
  message: string;
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
}

// Firewall drops types (snake_case — custom Rust structs)

export interface FirewallDropsSummary {
  total_drop_packets: number;
  total_drop_bytes: number;
}

// VLAN activity types (snake_case — custom Rust structs)

export interface VlanActivityEntry {
  name: string;
  rx_bps: number;
  tx_bps: number;
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
