import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
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
  SpeedTestResult,
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

// Speedtest

export function useSpeedtestLatest() {
  return useQuery({
    queryKey: ["speedtest", "latest"],
    queryFn: () => apiFetch<SpeedTestResult>("/api/speedtest/latest"),
    refetchInterval: 300_000,
    retry: false,
  });
}

export function useSpeedtestHistory(limit = 10) {
  return useQuery({
    queryKey: ["speedtest", "history", limit],
    queryFn: () =>
      apiFetch<SpeedTestResult[]>(`/api/speedtest/history?limit=${limit}`),
  });
}

export function useSpeedtestStatus() {
  return useQuery({
    queryKey: ["speedtest", "status"],
    queryFn: () => apiFetch<{ running: boolean }>("/api/speedtest/status"),
    refetchInterval: 3_000,
  });
}

export function useRunSpeedtest() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch<{ status: string }>("/api/speedtest/run", { method: "POST" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["speedtest", "status"] });
    },
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
