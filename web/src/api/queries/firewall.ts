import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "../client";
import type {
  FilterRule,
  NatRule,
  MangleRule,
  FirewallDropsSummary,
} from "../types";

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

export function useFirewallDrops() {
  return useQuery({
    queryKey: ["firewall", "drops"],
    queryFn: () => apiFetch<FirewallDropsSummary>("/api/firewall/drops"),
    refetchInterval: 30_000,
  });
}
