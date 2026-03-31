import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "../client";
import type {
  BehaviorOverview,
  VlanBehaviorDetail,
  DeviceDetailResponse,
  DeviceAnomaly,
  AlertCount,
  PortBaselineStatus,
} from "../types";

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
  tier?: number;
  limit?: number;
}) {
  const qs = new URLSearchParams();
  if (params?.status) qs.set("status", params.status);
  if (params?.severity) qs.set("severity", params.severity);
  if (params?.vlan != null) qs.set("vlan", String(params.vlan));
  if (params?.tier != null) qs.set("tier", String(params.tier));
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

export function useBulkResolveAnomalies() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ action, ids }: { action: string; ids?: number[] }) =>
      apiFetch<{ success: boolean; updated: number }>("/api/behavior/anomalies/bulk", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, ids }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["behavior"] });
    },
  });
}

export function useDeleteAllAnomalies() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch<{ deleted: number }>("/api/behavior/anomalies", {
        method: "DELETE",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["behavior"] });
    },
  });
}

export interface BehaviorResetCounts {
  anomalies: number;
  baselines: number;
  observations: number;
  profiles: number;
  boosts: number;
  watermarks: number;
  policy_deviations: number;
}

export function useResetPreview() {
  return useQuery({
    queryKey: ["behavior", "reset-preview"],
    queryFn: () => apiFetch<BehaviorResetCounts>("/api/behavior/reset-preview"),
    enabled: false, // only fetch on demand
  });
}

export function useResetBehavior() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch<BehaviorResetCounts>("/api/behavior/reset", {
        method: "POST",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["behavior"] });
    },
  });
}

export function useBehaviorAlerts(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["behavior", "alerts"],
    queryFn: () => apiFetch<AlertCount>("/api/behavior/alerts"),
    refetchInterval: 15_000,
    enabled: options?.enabled ?? true,
  });
}

// Anomaly Links

export function useAnomalyLinks() {
  return useQuery({
    queryKey: ["behavior", "anomaly-links"],
    queryFn: () =>
      apiFetch<import("../types").AnomalyLink[]>("/api/behavior/anomaly-links"),
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

export interface AnomalyTrendPoint {
  date: string;
  vlan: number;
  count: number;
}

export function useAnomalyTrend(days = 7) {
  return useQuery({
    queryKey: ["behavior", "anomaly-trend", days],
    queryFn: () =>
      apiFetch<AnomalyTrendPoint[]>(`/api/behavior/anomaly-trend?days=${days}`),
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
