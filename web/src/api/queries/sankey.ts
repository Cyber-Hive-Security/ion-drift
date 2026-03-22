import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "../client";
import type {
  SankeyNetworkResponse,
  SankeyVlanResponse,
  SankeyDeviceResponse,
  SankeyDestinationPeersResponse,
  ConversationDetailResponse,
  Investigation,
  InvestigationStats,
} from "../types";

// ── Sankey Investigation ─────────────────────────────────────

export function useSankeyNetwork(range = "24h") {
  return useQuery({
    queryKey: ["sankey", "network", range],
    queryFn: () => apiFetch<SankeyNetworkResponse>(`/api/sankey/network?range=${range}`),
    refetchInterval: 30_000,
  });
}

export function useSankeyVlan(vlanId: string | undefined, range = "24h", destVlan?: string, country?: string) {
  const params = new URLSearchParams({ range });
  if (destVlan) params.set("dest_vlan", destVlan);
  if (country) params.set("country", country);
  return useQuery({
    queryKey: ["sankey", "vlan", vlanId, range, destVlan, country],
    queryFn: () => apiFetch<SankeyVlanResponse>(`/api/sankey/vlan/${encodeURIComponent(vlanId!)}?${params}`),
    enabled: !!vlanId,
    refetchInterval: 30_000,
  });
}

export function useSankeyDevice(mac: string | undefined, range = "24h", country?: string) {
  const params = new URLSearchParams({ range });
  if (country) params.set("country", country);
  return useQuery({
    queryKey: ["sankey", "device", mac, range, country],
    queryFn: () => apiFetch<SankeyDeviceResponse>(`/api/sankey/device/${encodeURIComponent(mac!)}?${params}`),
    enabled: !!mac,
    refetchInterval: 30_000,
  });
}

export function useSankeyDestinationPeers(ip: string | undefined, range = "24h") {
  return useQuery({
    queryKey: ["sankey", "destination", ip, range],
    queryFn: () => apiFetch<SankeyDestinationPeersResponse>(`/api/sankey/destination/${encodeURIComponent(ip!)}/devices?range=${range}`),
    enabled: !!ip,
  });
}

export function useSankeyConversation(mac: string, destIp: string, range = "24h", page = 1) {
  return useQuery({
    queryKey: ["sankey", "conversation", mac, destIp, range, page],
    queryFn: () => apiFetch<ConversationDetailResponse>(
      `/api/sankey/device/${encodeURIComponent(mac)}/destination/${encodeURIComponent(destIp)}?range=${range}&page=${page}`,
    ),
    enabled: !!mac && !!destIp,
  });
}

// ── Investigation Engine ──────────────────────────────────────

export function useInvestigations(params?: {
  verdict?: string;
  mac?: string;
  limit?: number;
  offset?: number;
}) {
  const qs = new URLSearchParams();
  if (params?.verdict) qs.set("verdict", params.verdict);
  if (params?.mac) qs.set("mac", params.mac);
  if (params?.limit) qs.set("limit", String(params.limit));
  if (params?.offset) qs.set("offset", String(params.offset));
  const q = qs.toString();
  return useQuery({
    queryKey: ["investigations", params],
    queryFn: () => apiFetch<Investigation[]>(`/api/investigations${q ? `?${q}` : ""}`),
    refetchInterval: 30_000,
  });
}

export function useInvestigationByAnomaly(anomalyId: number | null) {
  return useQuery({
    queryKey: ["investigations", "anomaly", anomalyId],
    queryFn: () => apiFetch<Investigation>(`/api/investigations/anomaly/${anomalyId}`),
    enabled: anomalyId != null,
  });
}

export function useDeviceInvestigations(mac: string | null) {
  return useQuery({
    queryKey: ["investigations", "device", mac],
    queryFn: () => apiFetch<Investigation[]>(`/api/investigations/device/${encodeURIComponent(mac!)}`),
    enabled: mac != null,
    refetchInterval: 30_000,
  });
}

export function useInvestigationStats(hours = 24) {
  return useQuery({
    queryKey: ["investigations", "stats", hours],
    queryFn: () => apiFetch<InvestigationStats>(`/api/investigations/stats?hours=${hours}`),
    refetchInterval: 30_000,
  });
}
