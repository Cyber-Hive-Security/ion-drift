import { useQuery, useMutation, useQueryClient, keepPreviousData } from "@tanstack/react-query";
import { apiFetch } from "../client";
import type {
  SecretsStatusResponse,
  UpdateSecretsRequest,
  UpdateSecretsResponse,
  EncryptionStatusResponse,
  CertStatusResponse,
  MetricsPoint,
  DropMetricsPoint,
  LogAggregate,
  NetworkMapStatus,
  SnapshotListEntry,
  WeeklySnapshot,
  SyslogStatus,
  GeoIpStatus,
  MapConfig,
  VlanConfig,
  AlertRule,
  AlertHistoryEntry,
  AlertStatus,
  DeliveryChannelConfig,
  LicenseStatus,
} from "../types";

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

// Metrics

export function useMetricsHistory(range: "24h" | "7d") {
  return useQuery({
    queryKey: ["metrics", "history", range],
    queryFn: () => apiFetch<MetricsPoint[]>(`/api/metrics/history?range=${range}`),
    refetchInterval: 60_000,
    placeholderData: keepPreviousData,
  });
}

export function useDropsHistory(range: "24h" | "7d") {
  return useQuery({
    queryKey: ["metrics", "drops", range],
    queryFn: () => apiFetch<DropMetricsPoint[]>(`/api/metrics/drops?range=${range}`),
    refetchInterval: 60_000,
    placeholderData: keepPreviousData,
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

export function useUpdateGeoipDatabases() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch<{ downloaded: string[] }>("/api/settings/geoip/update", {
        method: "POST",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["settings", "geoip"] });
    },
  });
}

export function useMapConfig() {
  return useQuery({
    queryKey: ["settings", "map-config"],
    queryFn: () => apiFetch<MapConfig>("/api/settings/map-config"),
    staleTime: Infinity,
  });
}

export function useMonitoredRegions() {
  return useQuery({
    queryKey: ["settings", "monitored-regions"],
    queryFn: () => apiFetch<string[]>("/api/settings/monitored-regions"),
  });
}

export function useUpdateMonitoredRegions() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (regions: string[]) =>
      apiFetch<string[]>("/api/settings/monitored-regions", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ regions }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["settings", "monitored-regions"] });
      qc.invalidateQueries({ queryKey: ["settings", "map-config"] });
    },
  });
}

// VLAN Config update

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

// ── Alerting ─────────────────────────────────────────────────

export function useAlertRules() {
  return useQuery({
    queryKey: ["alerts", "rules"],
    queryFn: () => apiFetch<AlertRule[]>("/api/alerts/rules"),
  });
}

export function useAlertStatus() {
  return useQuery({
    queryKey: ["alerts", "status"],
    queryFn: () => apiFetch<AlertStatus>("/api/alerts/status"),
    refetchInterval: 30_000,
  });
}

export function useAlertHistory(limit = 50) {
  return useQuery({
    queryKey: ["alerts", "history", limit],
    queryFn: () => apiFetch<AlertHistoryEntry[]>(`/api/alerts/history?limit=${limit}`),
    refetchInterval: 30_000,
  });
}

export function useAlertChannels() {
  return useQuery({
    queryKey: ["alerts", "channels"],
    queryFn: () => apiFetch<DeliveryChannelConfig[]>("/api/alerts/channels"),
  });
}

export function useUpdateAlertRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...data }: { id: number } & Record<string, unknown>) =>
      apiFetch<{ ok: boolean }>(`/api/alerts/rules/${id}`, {
        method: "PUT",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts", "rules"] });
    },
  });
}

export function useCreateAlertRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiFetch<AlertRule>("/api/alerts/rules", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts", "rules"] });
    },
  });
}

export function useDeleteAlertRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiFetch<{ ok: boolean }>(`/api/alerts/rules/${id}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts", "rules"] });
    },
  });
}

export function useDeleteAlertHistory() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch<{ deleted: number }>("/api/alerts/history", {
        method: "DELETE",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts", "history"] });
    },
  });
}

export function useUpdateAlertChannel() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ channel, ...data }: { channel: string } & Record<string, unknown>) =>
      apiFetch<{ ok: boolean }>(`/api/alerts/channels/${encodeURIComponent(channel)}`, {
        method: "PUT",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts", "channels"] });
    },
  });
}

export function useTestAlertChannel() {
  return useMutation({
    mutationFn: (channel: string) =>
      apiFetch<{ ok: boolean }>(`/api/alerts/channels/${encodeURIComponent(channel)}/test`, {
        method: "POST",
      }),
  });
}

// ── License ─────────────────────────────────────────────────────

export function useLicenseStatus() {
  return useQuery({
    queryKey: ["license"],
    queryFn: () => apiFetch<LicenseStatus>("/api/license"),
    staleTime: 60_000,
  });
}
