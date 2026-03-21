import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "../client";
import type {
  SystemResource,
  SystemIdentity,
  RouterInterface,
  RouterInterfaceUtilization,
  VlanInterface,
  IpAddress,
  Route,
  DhcpLease,
  IpPool,
  DhcpServer,
  VlanFlow,
  ArpEntry,
  DhcpLeaseStatus,
  PoolUtilization,
  VlanActivityEntry,
  VlanMetricsPoint,
  VlanConfig,
} from "../types";

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

export function useRouterInterfaceUtilization() {
  return useQuery({
    queryKey: ["interfaces", "utilization"],
    queryFn: () => apiFetch<RouterInterfaceUtilization[]>("/api/interfaces/utilization"),
    refetchInterval: 10_000,
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

// VLAN

export function useVlanFlows() {
  return useQuery({
    queryKey: ["traffic", "vlan-flows"],
    queryFn: () => apiFetch<VlanFlow[]>("/api/traffic/vlan-flows"),
    refetchInterval: 60_000,
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

export function useVlanActivity() {
  return useQuery({
    queryKey: ["traffic", "vlan-activity"],
    queryFn: () => apiFetch<VlanActivityEntry[]>("/api/traffic/vlan-activity"),
    refetchInterval: 10_000,
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

export function useVlanConfigs() {
  return useQuery({
    queryKey: ["network", "vlan-config"],
    queryFn: () => apiFetch<VlanConfig[]>("/api/network/vlan-config"),
    refetchInterval: 60_000,
  });
}

export function useArpTable(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["ip", "arp"],
    queryFn: () => apiFetch<ArpEntry[]>("/api/ip/arp"),
    enabled: options?.enabled ?? true,
  });
}
