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
  LifetimeTraffic,
  TrafficSample,
  MetricsPoint,
  SpeedTestResult,
  VlanFlow,
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
