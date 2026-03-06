import { useQuery, useMutation, useQueryClient, keepPreviousData } from "@tanstack/react-query";
import { apiFetch } from "./client";
import type {
  AuthStatus,
  SystemResource,
  SystemIdentity,
  RouterInterface,
  VlanInterface,
  IpAddress,
  Route,
  DhcpLease,
  IpPool,
  DhcpServer,
  FilterRule,
  NatRule,
  MangleRule,
  LogEntry,
  LogsResponse,
  LifetimeTraffic,
  TrafficSample,
  MetricsPoint,
  VlanFlow,
  ConnectionSummary,
  ConnectionsPageResponse,
  ArpEntry,
  DhcpLeaseStatus,
  PoolUtilization,
  FirewallDropsSummary,
  VlanActivityEntry,
  DropMetricsPoint,
  ConnectionMetricsPoint,
  VlanMetricsPoint,
  LogAggregate,
  NetworkMapStatus,
  BehaviorOverview,
  VlanBehaviorDetail,
  DeviceDetailResponse,
  DeviceAnomaly,
  AlertCount,
  SecretsStatusResponse,
  UpdateSecretsRequest,
  UpdateSecretsResponse,
  RegenerateSessionResponse,
  EncryptionStatusResponse,
  CertStatusResponse,
  PaginatedHistory,
  GeoSummaryEntry,
  PortSummaryEntry,
  PortDirection,
  ClassifiedPortSummary,
  PortBaselineStatus,
  CitySummaryEntry,
  SnapshotListEntry,
  WeeklySnapshot,
  SyslogStatus,
  GeoIpStatus,
  ConnectionHistoryStats,
  NetworkDevice,
  CreateDeviceRequest,
  UpdateDeviceRequest,
  TestConnectionRequest,
  TestConnectionResponse,
  PortMetricsTuple,
  MacTableEntry,
  NeighborEntry,
  NetworkIdentity,
  VlanMembershipEntry,
  PortRoleEntry,
  DevicePort,
  IdentityStats,
  NmapScan,
  NmapResult,
  ScanExclusion,
  ScanStatus,
  UpdateIdentityRequest,
  StartScanRequest,
  ObservedService,
  PortMacBinding,
  PortViolation,
  BackboneLink,
  CreateBackboneLinkRequest,
  UpdateBackboneLinkRequest,
  NeighborAlias,
  CreateNeighborAliasRequest,
  DeviceDisposition,
  NetworkTopologyResponse,
  TopologyPosition,
  SectorPosition,
  VlanConfig,
} from "./types";

// Auth

export function useAuthStatus() {
  return useQuery({
    queryKey: ["auth", "status"],
    queryFn: () => apiFetch<AuthStatus>("/auth/status"),
    staleTime: Infinity,
    retry: false,
  });
}

// System

export function useSystemResources() {
  return useQuery({
    queryKey: ["system", "resources"],
    queryFn: () => apiFetch<SystemResource>("/api/system/resources"),
    refetchInterval: 30_000,
  });
}

export function useSystemIdentity() {
  return useQuery({
    queryKey: ["system", "identity"],
    queryFn: () => apiFetch<SystemIdentity>("/api/system/identity"),
    staleTime: 300_000,
  });
}

// Interfaces

export function useInterfaces(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["interfaces"],
    queryFn: () => apiFetch<RouterInterface[]>("/api/interfaces"),
    enabled: options?.enabled ?? true,
  });
}

export function useVlans(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["interfaces", "vlans"],
    queryFn: () => apiFetch<VlanInterface[]>("/api/interfaces/vlans"),
    enabled: options?.enabled ?? true,
  });
}

// IP

export function useIpAddresses(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["ip", "addresses"],
    queryFn: () => apiFetch<IpAddress[]>("/api/ip/addresses"),
    enabled: options?.enabled ?? true,
  });
}

export function useIpRoutes(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["ip", "routes"],
    queryFn: () => apiFetch<Route[]>("/api/ip/routes"),
    enabled: options?.enabled ?? true,
  });
}

export function useDhcpLeases(options?: { polling?: boolean; enabled?: boolean }) {
  return useQuery({
    queryKey: ["ip", "dhcp-leases"],
    queryFn: () => apiFetch<DhcpLease[]>("/api/ip/dhcp-leases"),
    refetchInterval: options?.polling ? 60_000 : false,
    enabled: options?.enabled ?? true,
  });
}

export function useIpPools(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["ip", "pools"],
    queryFn: () => apiFetch<IpPool[]>("/api/ip/pools"),
    enabled: options?.enabled ?? true,
  });
}

export function useDhcpServers(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["ip", "dhcp-servers"],
    queryFn: () => apiFetch<DhcpServer[]>("/api/ip/dhcp-servers"),
    enabled: options?.enabled ?? true,
  });
}

// Firewall

export function useFirewallFilter(chain?: string, options?: { enabled?: boolean }) {
  const params = chain ? `?chain=${encodeURIComponent(chain)}` : "";
  return useQuery({
    queryKey: ["firewall", "filter", chain],
    queryFn: () => apiFetch<FilterRule[]>(`/api/firewall/filter${params}`),
    enabled: options?.enabled ?? true,
  });
}

export function useFirewallNat(chain?: string, options?: { enabled?: boolean }) {
  const params = chain ? `?chain=${encodeURIComponent(chain)}` : "";
  return useQuery({
    queryKey: ["firewall", "nat", chain],
    queryFn: () => apiFetch<NatRule[]>(`/api/firewall/nat${params}`),
    enabled: options?.enabled ?? true,
  });
}

export function useFirewallMangle(chain?: string, options?: { enabled?: boolean }) {
  const params = chain ? `?chain=${encodeURIComponent(chain)}` : "";
  return useQuery({
    queryKey: ["firewall", "mangle", chain],
    queryFn: () => apiFetch<MangleRule[]>(`/api/firewall/mangle${params}`),
    enabled: options?.enabled ?? true,
  });
}

// Logs

export function useLogs(topics?: string, limit?: number, options?: { refetchInterval?: number | false }) {
  const params = new URLSearchParams();
  if (topics) params.set("topics", topics);
  if (limit) params.set("limit", String(limit));
  const qs = params.toString();
  return useQuery({
    queryKey: ["logs", topics, limit],
    queryFn: () => apiFetch<LogEntry[]>(`/api/logs${qs ? `?${qs}` : ""}`),
    refetchInterval: options?.refetchInterval ?? false,
  });
}

export function useStructuredLogs(params: {
  topics?: string;
  limit?: number;
  action?: string;
  severity?: string;
  refetchInterval?: number | false;
}) {
  const qs = new URLSearchParams();
  if (params.topics) qs.set("topics", params.topics);
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.action) qs.set("action", params.action);
  if (params.severity) qs.set("severity", params.severity);
  const qsStr = qs.toString();
  return useQuery({
    queryKey: ["logs", "structured", params.topics, params.limit, params.action, params.severity],
    queryFn: () => apiFetch<LogsResponse>(`/api/logs${qsStr ? `?${qsStr}` : ""}`),
    refetchInterval: params.refetchInterval ?? false,
  });
}

// Traffic

export function useTraffic() {
  return useQuery({
    queryKey: ["traffic"],
    queryFn: () => apiFetch<LifetimeTraffic>("/api/traffic"),
    refetchInterval: 60_000,
  });
}

export function useLiveTraffic() {
  return useQuery({
    queryKey: ["traffic", "live"],
    queryFn: () => apiFetch<TrafficSample[]>("/api/traffic/live"),
    refetchInterval: 5_000,
  });
}

export function useVlanFlows() {
  return useQuery({
    queryKey: ["traffic", "vlan-flows"],
    queryFn: () => apiFetch<VlanFlow[]>("/api/traffic/vlan-flows"),
    refetchInterval: 60_000,
  });
}

// Connections

export function useConnectionSummary() {
  return useQuery({
    queryKey: ["connections", "summary"],
    queryFn: () => apiFetch<ConnectionSummary>("/api/connections/summary"),
    refetchInterval: 30_000,
  });
}

export function useConnectionsPage() {
  return useQuery({
    queryKey: ["connections", "page"],
    queryFn: () => apiFetch<ConnectionsPageResponse>("/api/connections/page"),
    refetchInterval: 30_000,
  });
}

// ARP

export function useArpTable(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["ip", "arp"],
    queryFn: () => apiFetch<ArpEntry[]>("/api/ip/arp"),
    enabled: options?.enabled ?? true,
  });
}

export function useDhcpLeasesStatus(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["ip", "dhcp-leases-status"],
    queryFn: () => apiFetch<DhcpLeaseStatus[]>("/api/ip/dhcp-leases-status"),
    refetchInterval: 60_000,
    enabled: options?.enabled ?? true,
  });
}

export function usePoolUtilization(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["ip", "pool-utilization"],
    queryFn: () => apiFetch<PoolUtilization[]>("/api/ip/pool-utilization"),
    enabled: options?.enabled ?? true,
  });
}

// Firewall Drops

export function useFirewallDrops() {
  return useQuery({
    queryKey: ["firewall", "drops"],
    queryFn: () => apiFetch<FirewallDropsSummary>("/api/firewall/drops"),
    refetchInterval: 30_000,
  });
}

// VLAN Activity

export function useVlanActivity() {
  return useQuery({
    queryKey: ["traffic", "vlan-activity"],
    queryFn: () => apiFetch<VlanActivityEntry[]>("/api/traffic/vlan-activity"),
    refetchInterval: 10_000,
  });
}

// Metrics

export function useMetricsHistory(range: "24h" | "7d") {
  return useQuery({
    queryKey: ["metrics", "history", range],
    queryFn: () => apiFetch<MetricsPoint[]>(`/api/metrics/history?range=${range}`),
    refetchInterval: 60_000,
  });
}

// Historical metrics

export function useDropsHistory(range: "24h" | "7d") {
  return useQuery({
    queryKey: ["metrics", "drops", range],
    queryFn: () => apiFetch<DropMetricsPoint[]>(`/api/metrics/drops?range=${range}`),
    refetchInterval: 60_000,
  });
}

export function useConnectionsHistory(range: "24h" | "7d") {
  return useQuery({
    queryKey: ["metrics", "connections", range],
    queryFn: () =>
      apiFetch<ConnectionMetricsPoint[]>(`/api/metrics/connections?range=${range}`),
    refetchInterval: 60_000,
  });
}

export function useVlanMetricsHistory(range: "24h" | "7d") {
  return useQuery({
    queryKey: ["metrics", "vlans", range],
    queryFn: () =>
      apiFetch<VlanMetricsPoint[]>(`/api/metrics/vlans?range=${range}`),
    refetchInterval: 60_000,
  });
}

export function useLogTrends(range: "24h" | "7d") {
  return useQuery({
    queryKey: ["metrics", "log-trends", range],
    queryFn: () =>
      apiFetch<LogAggregate[]>(`/api/metrics/log-trends?range=${range}`),
    refetchInterval: 300_000,
  });
}

// Network Map Status

export function useNetworkMapStatus(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["network-map", "status"],
    queryFn: () => apiFetch<NetworkMapStatus>("/api/network-map/status"),
    refetchInterval: 10_000,
    enabled: options?.enabled ?? true,
  });
}

// Behavior

export function useBehaviorOverview() {
  return useQuery({
    queryKey: ["behavior", "overview"],
    queryFn: () => apiFetch<BehaviorOverview>("/api/behavior/overview"),
    refetchInterval: 30_000,
  });
}

export function useBehaviorVlan(vlanId: number) {
  return useQuery({
    queryKey: ["behavior", "vlan", vlanId],
    queryFn: () =>
      apiFetch<VlanBehaviorDetail>(`/api/behavior/vlan/${vlanId}`),
    refetchInterval: 30_000,
  });
}

export function useBehaviorDevice(mac: string | null) {
  return useQuery({
    queryKey: ["behavior", "device", mac],
    queryFn: () =>
      apiFetch<DeviceDetailResponse>(
        `/api/behavior/device/${encodeURIComponent(mac!)}`,
      ),
    refetchInterval: 30_000,
    enabled: !!mac,
  });
}

export function useBehaviorAnomalies(params?: {
  status?: string;
  severity?: string;
  vlan?: number;
  limit?: number;
}) {
  const qs = new URLSearchParams();
  if (params?.status) qs.set("status", params.status);
  if (params?.severity) qs.set("severity", params.severity);
  if (params?.vlan != null) qs.set("vlan", String(params.vlan));
  if (params?.limit) qs.set("limit", String(params.limit));
  const qsStr = qs.toString();
  return useQuery({
    queryKey: ["behavior", "anomalies", params],
    queryFn: () =>
      apiFetch<DeviceAnomaly[]>(
        `/api/behavior/anomalies${qsStr ? `?${qsStr}` : ""}`,
      ),
    refetchInterval: 15_000,
  });
}

export function useResolveAnomaly() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, action }: { id: number; action: string }) =>
      apiFetch<{ success: boolean }>(`/api/behavior/anomalies/${id}/resolve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["behavior"] });
    },
  });
}

export function useBehaviorAlerts() {
  return useQuery({
    queryKey: ["behavior", "alerts"],
    queryFn: () => apiFetch<AlertCount>("/api/behavior/alerts"),
    refetchInterval: 15_000,
  });
}

// Anomaly Links

export function useAnomalyLinks() {
  return useQuery({
    queryKey: ["behavior", "anomaly-links"],
    queryFn: () =>
      apiFetch<import("./types").AnomalyLink[]>("/api/behavior/anomaly-links"),
    refetchInterval: 60_000,
  });
}

export function useResolveAnomalyLink() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiFetch<{ success: boolean }>(
        `/api/behavior/anomaly-links/${id}/resolve`,
        { method: "POST" },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["behavior"] });
      queryClient.invalidateQueries({ queryKey: ["connections", "port-summary-classified"] });
    },
  });
}

// Settings / Secrets

export function useSecretsStatus() {
  return useQuery({
    queryKey: ["settings", "secrets"],
    queryFn: () => apiFetch<SecretsStatusResponse>("/api/settings/secrets"),
    retry: false,
  });
}

export function useEncryptionStatus() {
  return useQuery({
    queryKey: ["settings", "encryption"],
    queryFn: () => apiFetch<EncryptionStatusResponse>("/api/settings/encryption"),
    retry: false,
  });
}

export function useCertStatus() {
  return useQuery({
    queryKey: ["settings", "cert"],
    queryFn: () => apiFetch<CertStatusResponse>("/api/settings/cert"),
    refetchInterval: 300_000,
    retry: false,
  });
}

export function useUpdateSecrets() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: UpdateSecretsRequest) =>
      apiFetch<UpdateSecretsResponse>("/api/settings/secrets", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["settings", "secrets"] });
    },
  });
}

export function useRegenerateSession() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch<RegenerateSessionResponse>(
        "/api/settings/secrets/session/regenerate",
        { method: "POST" },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["settings", "secrets"] });
    },
  });
}

// Connection History

export function useConnectionHistory(params?: {
  page?: number;
  per_page?: number;
  protocol?: string;
  country?: string;
  flagged_only?: boolean;
  external_only?: boolean;
  search?: string;
}) {
  const qs = new URLSearchParams();
  if (params?.page != null) qs.set("page", String(params.page));
  if (params?.per_page != null) qs.set("per_page", String(params.per_page));
  if (params?.protocol) qs.set("protocol", params.protocol);
  if (params?.country) qs.set("country", params.country);
  if (params?.flagged_only) qs.set("flagged_only", "true");
  if (params?.external_only) qs.set("external_only", "true");
  if (params?.search) qs.set("search", params.search);
  const qsStr = qs.toString();
  return useQuery({
    queryKey: ["connections", "history", params],
    queryFn: () =>
      apiFetch<PaginatedHistory>(
        `/api/connections/history${qsStr ? `?${qsStr}` : ""}`,
      ),
    refetchInterval: 30_000,
  });
}

export function useGeoSummary(days = 30) {
  return useQuery({
    queryKey: ["connections", "geo-summary", days],
    queryFn: () =>
      apiFetch<GeoSummaryEntry[]>(
        `/api/connections/geo-summary?days=${days}`,
      ),
    refetchInterval: 60_000,
    placeholderData: keepPreviousData,
  });
}

export function usePortSummary(days = 7, direction?: PortDirection) {
  const dirParam = direction ? `&direction=${direction}` : "";
  return useQuery({
    queryKey: ["connections", "port-summary", days, direction ?? "all"],
    queryFn: () =>
      apiFetch<PortSummaryEntry[]>(
        `/api/connections/port-summary?days=${days}${dirParam}`,
      ),
    refetchInterval: 60_000,
  });
}

export function useClassifiedPortSummary(days = 1, direction?: PortDirection) {
  const dirParam = direction ? `&direction=${direction}` : "";
  return useQuery({
    queryKey: ["connections", "port-summary-classified", days, direction ?? "all"],
    queryFn: () =>
      apiFetch<ClassifiedPortSummary>(
        `/api/connections/port-summary-classified?days=${days}${dirParam}`,
      ),
    refetchInterval: 60_000,
  });
}

export function usePortBaselineStatus() {
  return useQuery({
    queryKey: ["behavior", "port-baseline"],
    queryFn: () =>
      apiFetch<PortBaselineStatus>("/api/behavior/port-baseline"),
    staleTime: 300_000,
  });
}

export function useCitySummary(days = 7, minConnections = 50) {
  return useQuery({
    queryKey: ["connections", "city-summary", days, minConnections],
    queryFn: () =>
      apiFetch<CitySummaryEntry[]>(
        `/api/connections/city-summary?days=${days}&min_connections=${minConnections}`,
      ),
    refetchInterval: 60_000,
    placeholderData: keepPreviousData,
  });
}

export function useConnectionHistoryStats() {
  return useQuery({
    queryKey: ["connections", "stats"],
    queryFn: () =>
      apiFetch<ConnectionHistoryStats>("/api/connections/stats"),
    staleTime: 300_000,
  });
}

// History (Snapshots)

export function useSnapshots() {
  return useQuery({
    queryKey: ["history", "snapshots"],
    queryFn: () =>
      apiFetch<SnapshotListEntry[]>("/api/history/snapshots"),
    staleTime: 300_000,
  });
}

export function useSnapshot(week: string | null, type: string) {
  return useQuery({
    queryKey: ["history", "snapshot", week, type],
    queryFn: () =>
      apiFetch<WeeklySnapshot | null>(
        `/api/history/snapshot/${encodeURIComponent(week!)}/${encodeURIComponent(type)}`,
      ),
    enabled: !!week,
    staleTime: Infinity,
  });
}

// Settings — Syslog & GeoIP

export function useSyslogStatus() {
  return useQuery({
    queryKey: ["settings", "syslog"],
    queryFn: () => apiFetch<SyslogStatus>("/api/settings/syslog"),
    refetchInterval: 30_000,
  });
}

export function useGeoIpStatus() {
  return useQuery({
    queryKey: ["settings", "geoip"],
    queryFn: () => apiFetch<GeoIpStatus>("/api/settings/geoip"),
    staleTime: 300_000,
  });
}

// ── Network Devices ──────────────────────────────────────────────

export function useDevices() {
  return useQuery({
    queryKey: ["devices"],
    queryFn: () => apiFetch<NetworkDevice[]>("/api/devices"),
    refetchInterval: 30_000,
  });
}

export function useCreateDevice() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: CreateDeviceRequest) =>
      apiFetch<{ id: string; identity: string; message: string }>(
        "/api/devices",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(data),
        },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
  });
}

export function useUpdateDevice() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateDeviceRequest }) =>
      apiFetch<{ message: string }>(`/api/devices/${encodeURIComponent(id)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
  });
}

export function useDeleteDevice() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ message: string }>(
        `/api/devices/${encodeURIComponent(id)}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
  });
}

export function useTestDeviceConnection() {
  return useMutation({
    mutationFn: (data: TestConnectionRequest) =>
      apiFetch<TestConnectionResponse>("/api/devices/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      }),
  });
}

// ── Device-specific data queries ─────────────────────────────

export function useDeviceResources(deviceId: string | undefined) {
  return useQuery({
    queryKey: ["devices", deviceId, "resources"],
    queryFn: () =>
      apiFetch<SystemResource>(
        `/api/devices/${encodeURIComponent(deviceId!)}/resources`,
      ),
    refetchInterval: 30_000,
    enabled: !!deviceId,
  });
}

export function useDeviceInterfaces(deviceId: string | undefined) {
  return useQuery({
    queryKey: ["devices", deviceId, "interfaces"],
    queryFn: () =>
      apiFetch<RouterInterface[]>(
        `/api/devices/${encodeURIComponent(deviceId!)}/interfaces`,
      ),
    refetchInterval: 30_000,
    enabled: !!deviceId,
  });
}

export function useDevicePorts(deviceId: string | undefined) {
  return useQuery({
    queryKey: ["devices", deviceId, "ports"],
    queryFn: () =>
      apiFetch<PortMetricsTuple[]>(
        `/api/devices/${encodeURIComponent(deviceId!)}/ports`,
      ),
    refetchInterval: 30_000,
    enabled: !!deviceId,
  });
}

export function useDeviceMacTable(deviceId: string | undefined) {
  return useQuery({
    queryKey: ["devices", deviceId, "mac-table"],
    queryFn: () =>
      apiFetch<MacTableEntry[]>(
        `/api/devices/${encodeURIComponent(deviceId!)}/mac-table`,
      ),
    refetchInterval: 60_000,
    enabled: !!deviceId,
  });
}

export function useDeviceNeighbors(deviceId: string | undefined) {
  return useQuery({
    queryKey: ["devices", deviceId, "neighbors"],
    queryFn: () =>
      apiFetch<NeighborEntry[]>(
        `/api/devices/${encodeURIComponent(deviceId!)}/neighbors`,
      ),
    refetchInterval: 60_000,
    enabled: !!deviceId,
  });
}

export function useDeviceVlans(deviceId: string | undefined) {
  return useQuery({
    queryKey: ["devices", deviceId, "vlans"],
    queryFn: () =>
      apiFetch<VlanMembershipEntry[]>(
        `/api/devices/${encodeURIComponent(deviceId!)}/vlans`,
      ),
    refetchInterval: 120_000,
    enabled: !!deviceId,
  });
}

export function useDevicePortRoles(deviceId: string | undefined) {
  return useQuery({
    queryKey: ["devices", deviceId, "port-roles"],
    queryFn: () =>
      apiFetch<PortRoleEntry[]>(
        `/api/devices/${encodeURIComponent(deviceId!)}/port-roles`,
      ),
    refetchInterval: 60_000,
    enabled: !!deviceId,
  });
}

export function useDevicePortList(deviceId: string | undefined) {
  return useQuery({
    queryKey: ["devices", deviceId, "port-list"],
    queryFn: () =>
      apiFetch<DevicePort[]>(
        `/api/devices/${encodeURIComponent(deviceId!)}/port-list`,
      ),
    refetchInterval: 60_000,
    enabled: !!deviceId,
  });
}

// ── Network-wide correlation queries ─────────────────────────

export function useNetworkIdentities() {
  return useQuery({
    queryKey: ["network", "identities"],
    queryFn: () => apiFetch<NetworkIdentity[]>("/api/network/identities"),
    refetchInterval: 60_000,
  });
}

export function useNetworkPortRoles() {
  return useQuery({
    queryKey: ["network", "port-roles"],
    queryFn: () => apiFetch<PortRoleEntry[]>("/api/network/port-roles"),
    refetchInterval: 60_000,
  });
}

// ── Identity management ─────────────────────────────────────────

export function useIdentityStats() {
  return useQuery({
    queryKey: ["network", "identities", "stats"],
    queryFn: () => apiFetch<IdentityStats>("/api/network/identities/stats"),
    refetchInterval: 30_000,
  });
}

export function useReviewQueue(limit = 50, offset = 0) {
  return useQuery({
    queryKey: ["network", "identities", "review-queue", limit, offset],
    queryFn: () =>
      apiFetch<NetworkIdentity[]>(
        `/api/network/identities/review-queue?limit=${limit}&offset=${offset}`
      ),
    refetchInterval: 30_000,
  });
}

export function useUpdateIdentity() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ mac, data }: { mac: string; data: UpdateIdentityRequest }) =>
      apiFetch<{ updated: boolean }>(
        `/api/network/identities/${encodeURIComponent(mac)}`,
        { method: "PUT", body: JSON.stringify(data) }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "identities"] });
    },
  });
}

export function useBulkConfirmIdentities() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (macs: string[]) =>
      apiFetch<{ confirmed: number }>("/api/network/identities/bulk-confirm", {
        method: "POST",
        body: JSON.stringify({ macs }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "identities"] });
    },
  });
}

export function useResetIdentityField() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ mac, field }: { mac: string; field: string }) =>
      apiFetch<{ reset: boolean }>(
        `/api/network/identities/${encodeURIComponent(mac)}/fields/${encodeURIComponent(field)}`,
        { method: "DELETE" }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "identities"] });
    },
  });
}

// ── Observed services (passive discovery) ───────────────────────

export function useObservedServices(ip?: string) {
  const params = ip ? `?ip=${encodeURIComponent(ip)}` : "";
  return useQuery({
    queryKey: ["network", "services", ip ?? "all"],
    queryFn: () => apiFetch<ObservedService[]>(`/api/network/services${params}`),
    refetchInterval: 60_000,
  });
}

// ── Disposition ──────────────────────────────────────────────────

export function useSetDisposition() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ mac, disposition }: { mac: string; disposition: DeviceDisposition }) =>
      apiFetch<{ updated: boolean }>(
        `/api/network/identities/${encodeURIComponent(mac)}/disposition`,
        { method: "PUT", body: JSON.stringify({ disposition }) }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "identities"] });
      queryClient.invalidateQueries({ queryKey: ["network", "topology"] });
    },
  });
}

export function useBulkDisposition() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ macs, disposition }: { macs: string[]; disposition: DeviceDisposition }) =>
      apiFetch<{ updated: number }>("/api/network/identities/bulk-disposition", {
        method: "POST",
        body: JSON.stringify({ macs, disposition }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "identities"] });
    },
  });
}

// ── Port MAC bindings ───────────────────────────────────────────

export function usePortBindings(deviceId?: string) {
  const params = deviceId ? `?device_id=${encodeURIComponent(deviceId)}` : "";
  return useQuery({
    queryKey: ["network", "port-bindings", deviceId ?? "all"],
    queryFn: () => apiFetch<PortMacBinding[]>(`/api/network/port-bindings${params}`),
    refetchInterval: 60_000,
  });
}

export function usePortBindingsForDevice(deviceId: string) {
  return useQuery({
    queryKey: ["network", "port-bindings", deviceId],
    queryFn: () =>
      apiFetch<PortMacBinding[]>(
        `/api/network/port-bindings/${encodeURIComponent(deviceId)}`
      ),
    refetchInterval: 60_000,
  });
}

export function useCreatePortBinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { device_id: string; port_name: string; expected_mac: string }) =>
      apiFetch<{ created: boolean }>("/api/network/port-bindings", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "port-bindings"] });
      queryClient.invalidateQueries({ queryKey: ["network", "port-violations"] });
    },
  });
}

export function useUpdatePortBinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      device_id,
      port_name,
      expected_mac,
    }: {
      device_id: string;
      port_name: string;
      expected_mac: string;
    }) =>
      apiFetch<{ updated: boolean }>(
        `/api/network/port-bindings/${encodeURIComponent(device_id)}/${encodeURIComponent(port_name)}`,
        { method: "PUT", body: JSON.stringify({ expected_mac }) }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "port-bindings"] });
      queryClient.invalidateQueries({ queryKey: ["network", "port-violations"] });
    },
  });
}

export function useDeletePortBinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ device_id, port_name }: { device_id: string; port_name: string }) =>
      apiFetch<{ deleted: boolean }>(
        `/api/network/port-bindings/${encodeURIComponent(device_id)}/${encodeURIComponent(port_name)}`,
        { method: "DELETE" }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "port-bindings"] });
      queryClient.invalidateQueries({ queryKey: ["network", "port-violations"] });
    },
  });
}

// ── Port violations ─────────────────────────────────────────────

export function usePortViolations(deviceId?: string) {
  const params = deviceId ? `?device_id=${encodeURIComponent(deviceId)}` : "";
  return useQuery({
    queryKey: ["network", "port-violations", deviceId ?? "all"],
    queryFn: () => apiFetch<PortViolation[]>(`/api/network/port-violations${params}`),
    refetchInterval: 30_000,
  });
}

export function usePortViolationsForDevice(deviceId: string) {
  return useQuery({
    queryKey: ["network", "port-violations", deviceId],
    queryFn: () =>
      apiFetch<PortViolation[]>(
        `/api/network/port-violations/${encodeURIComponent(deviceId)}`
      ),
    refetchInterval: 30_000,
  });
}

export function useResolvePortViolation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiFetch<{ resolved: boolean }>(
        `/api/network/port-violations/${id}/resolve`,
        { method: "PUT" }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "port-violations"] });
    },
  });
}

// ── Nmap scans ──────────────────────────────────────────────────

export function useScanStatus() {
  return useQuery({
    queryKey: ["scans", "status"],
    queryFn: () => apiFetch<ScanStatus>("/api/scans/status"),
    refetchInterval: 10_000,
  });
}

export function useScans(limit = 20) {
  return useQuery({
    queryKey: ["scans", "list", limit],
    queryFn: () => apiFetch<NmapScan[]>(`/api/scans?limit=${limit}`),
    refetchInterval: 10_000,
  });
}

export function useScanDetail(scanId?: string) {
  return useQuery({
    queryKey: ["scans", "detail", scanId],
    queryFn: () => apiFetch<NmapScan | null>(`/api/scans/${encodeURIComponent(scanId!)}`),
    enabled: !!scanId,
    refetchInterval: 5_000,
  });
}

export function useScanResults(scanId?: string) {
  return useQuery({
    queryKey: ["scans", "results", scanId],
    queryFn: () =>
      apiFetch<NmapResult[]>(`/api/scans/${encodeURIComponent(scanId!)}/results`),
    enabled: !!scanId,
  });
}

export function useStartScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: StartScanRequest) =>
      apiFetch<{ scan_id: string; status: string }>("/api/scans", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });
}

export function useScanExclusions() {
  return useQuery({
    queryKey: ["scans", "exclusions"],
    queryFn: () => apiFetch<ScanExclusion[]>("/api/scans/exclusions"),
    refetchInterval: 60_000,
  });
}

export function useAddExclusion() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { ip: string; reason: string }) =>
      apiFetch<{ ok: boolean }>("/api/scans/exclusions", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans", "exclusions"] });
    },
  });
}

export function useRemoveExclusion() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (ip: string) =>
      apiFetch<{ removed: boolean }>(
        `/api/scans/exclusions/${encodeURIComponent(ip)}`,
        { method: "DELETE" }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans", "exclusions"] });
    },
  });
}

// ── Network Topology ─────────────────────────────────────────

export function useNetworkTopology() {
  return useQuery({
    queryKey: ["network", "topology"],
    queryFn: () => apiFetch<NetworkTopologyResponse>("/api/network/topology"),
    refetchInterval: 30_000,
  });
}

export function useTopologyPositions() {
  return useQuery({
    queryKey: ["network", "topology", "positions"],
    queryFn: () => apiFetch<TopologyPosition[]>("/api/network/topology/positions"),
    staleTime: 60_000,
  });
}

export function useRefreshTopology() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch<{ status: string; nodes: number }>("/api/network/topology/refresh", {
        method: "POST",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "topology"] });
    },
  });
}

export function useUpdateNodePosition() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ nodeId, x, y }: { nodeId: string; x: number; y: number }) =>
      apiFetch<{ status: string }>(
        `/api/network/topology/positions/${encodeURIComponent(nodeId)}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ x, y }),
        },
      ),
    onSuccess: (_data, { nodeId, x, y }) => {
      // Optimistic cache patch — avoids refetch from stale topology cache
      queryClient.setQueryData<NetworkTopologyResponse>(["network", "topology"], (old) => {
        if (!old) return old;
        return {
          ...old,
          nodes: old.nodes.map((n) =>
            n.id === nodeId ? { ...n, x, y, position_source: "human" } : n,
          ),
        };
      });
    },
  });
}

export function useResetNodePosition() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (nodeId: string) =>
      apiFetch<{ removed: boolean }>(
        `/api/network/topology/positions/${encodeURIComponent(nodeId)}`,
        { method: "DELETE" },
      ),
    onSuccess: (_data, nodeId) => {
      // Optimistic cache patch — mark as auto-positioned
      queryClient.setQueryData<NetworkTopologyResponse>(["network", "topology"], (old) => {
        if (!old) return old;
        return {
          ...old,
          nodes: old.nodes.map((n) =>
            n.id === nodeId ? { ...n, position_source: "auto" } : n,
          ),
        };
      });
    },
  });
}

export function useSectorPositions() {
  return useQuery({
    queryKey: ["network", "topology", "sectors"],
    queryFn: () => apiFetch<SectorPosition[]>("/api/network/topology/sectors"),
    staleTime: 60_000,
  });
}

export function useUpdateSectorPosition() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      vlanId,
      x,
      y,
      width,
      height,
    }: {
      vlanId: number;
      x: number;
      y: number;
      width?: number;
      height?: number;
    }) =>
      apiFetch<{ status: string }>(
        `/api/network/topology/sectors/${vlanId}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ x, y, width, height }),
        },
      ),
    onSuccess: (_data, { vlanId, x, y, width, height }) => {
      // Optimistic cache patch
      queryClient.setQueryData<NetworkTopologyResponse>(["network", "topology"], (old) => {
        if (!old) return old;
        return {
          ...old,
          vlan_groups: old.vlan_groups.map((g) =>
            g.vlan_id === vlanId
              ? {
                  ...g,
                  bbox_x: x,
                  bbox_y: y,
                  bbox_w: width ?? g.bbox_w,
                  bbox_h: height ?? g.bbox_h,
                  position_source: "human",
                }
              : g,
          ),
        };
      });
    },
  });
}

export function useResetSectorPosition() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (vlanId: number) =>
      apiFetch<{ removed: boolean }>(
        `/api/network/topology/sectors/${vlanId}`,
        { method: "DELETE" },
      ),
    onSuccess: (_data, vlanId) => {
      queryClient.setQueryData<NetworkTopologyResponse>(["network", "topology"], (old) => {
        if (!old) return old;
        return {
          ...old,
          vlan_groups: old.vlan_groups.map((g) =>
            g.vlan_id === vlanId ? { ...g, position_source: "auto" } : g,
          ),
        };
      });
    },
  });
}

export function useBatchUpdateNodePositions() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (positions: { node_id: string; x: number; y: number }[]) =>
      apiFetch<{ status: string; count: number }>(
        "/api/network/topology/positions",
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ positions }),
        },
      ),
    onSuccess: (_data, positions) => {
      // Optimistic cache update — mark all moved nodes as human-positioned
      const posMap = new Map(positions.map((p) => [p.node_id, p]));
      queryClient.setQueryData<NetworkTopologyResponse>(["network", "topology"], (old) => {
        if (!old) return old;
        return {
          ...old,
          nodes: old.nodes.map((n) => {
            const p = posMap.get(n.id);
            return p ? { ...n, x: p.x, y: p.y, position_source: "human" } : n;
          }),
        };
      });
    },
  });
}

// ── Backbone Links ──────────────────────────────────────────────

export function useBackboneLinks() {
  return useQuery({
    queryKey: ["network", "backbone-links"],
    queryFn: () => apiFetch<BackboneLink[]>("/api/network/backbone-links"),
    refetchInterval: 60_000,
  });
}

export function useCreateBackboneLink() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateBackboneLinkRequest) =>
      apiFetch<{ id: number }>("/api/network/backbone-links", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "backbone-links"] });
      queryClient.invalidateQueries({ queryKey: ["network", "topology"] });
    },
  });
}

export function useDeleteBackboneLink() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiFetch<{ removed: boolean }>(`/api/network/backbone-links/${id}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "backbone-links"] });
      queryClient.invalidateQueries({ queryKey: ["network", "topology"] });
    },
  });
}

export function useUpdateBackboneLink() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...body }: { id: number } & UpdateBackboneLinkRequest) =>
      apiFetch<{ updated: boolean }>(`/api/network/backbone-links/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "backbone-links"] });
      queryClient.invalidateQueries({ queryKey: ["network", "topology"] });
    },
  });
}

// ── Neighbor Aliases ────────────────────────────────────────────

export function useNeighborAliases() {
  return useQuery({
    queryKey: ["network", "neighbor-aliases"],
    queryFn: () => apiFetch<NeighborAlias[]>("/api/network/neighbor-aliases"),
    refetchInterval: 60_000,
  });
}

export function useCreateNeighborAlias() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateNeighborAliasRequest) =>
      apiFetch<{ id: number }>("/api/network/neighbor-aliases", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "neighbor-aliases"] });
      queryClient.invalidateQueries({ queryKey: ["network", "topology"] });
    },
  });
}

export function useDeleteNeighborAlias() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiFetch<{ removed: boolean }>(`/api/network/neighbor-aliases/${id}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "neighbor-aliases"] });
      queryClient.invalidateQueries({ queryKey: ["network", "topology"] });
    },
  });
}

// ── VLAN Config ─────────────────────────────────────────────────

export function useVlanConfigs() {
  return useQuery({
    queryKey: ["network", "vlan-config"],
    queryFn: () => apiFetch<VlanConfig[]>("/api/network/vlan-config"),
    refetchInterval: 60_000,
  });
}

// ── Infrastructure Identities ───────────────────────────────────

export function useInfrastructureIdentities() {
  return useQuery({
    queryKey: ["network", "identities", "infrastructure"],
    queryFn: () => apiFetch<NetworkIdentity[]>("/api/network/identities/infrastructure"),
    refetchInterval: 60_000,
  });
}

export function useUpdateVlanConfig() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (config: VlanConfig) =>
      apiFetch<{ ok: boolean }>(`/api/network/vlan-config/${config.vlan_id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(config),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "vlan-config"] });
      queryClient.invalidateQueries({ queryKey: ["network", "topology"] });
    },
  });
}
