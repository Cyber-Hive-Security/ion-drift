import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { apiFetch } from "../client";
import type {
  LifetimeTraffic,
  TrafficSample,
  ConnectionSummary,
  ConnectionsPageResponse,
  ConnectionMetricsPoint,
  PaginatedHistory,
  GeoSummaryEntry,
  PortSummaryEntry,
  PortDirection,
  ClassifiedPortSummary,
  CitySummaryEntry,
  ConnectionHistoryStats,
  LogEntry,
  LogsResponse,
  CountrySummary,
} from "../types";

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

export function useConnectionsHistory(range: "24h" | "7d") {
  return useQuery({
    queryKey: ["metrics", "connections", range],
    queryFn: () =>
      apiFetch<ConnectionMetricsPoint[]>(`/api/metrics/connections?range=${range}`),
    refetchInterval: 60_000,
  });
}

export interface HistoryQueryParams {
  page?: number;
  per_page?: number;
  src_ip?: string;
  dst_ip?: string;
  dst_port?: number;
  protocol?: string;
  country?: string;
  after?: string;
  before?: string;
  flagged?: boolean;
  flagged_only?: boolean;
  external_only?: boolean;
  search?: string;
}

export function useConnectionHistory(params?: HistoryQueryParams) {
  const qs = new URLSearchParams();
  if (params?.page != null) qs.set("page", String(params.page));
  if (params?.per_page != null) qs.set("per_page", String(params.per_page));
  if (params?.src_ip) qs.set("src_ip", params.src_ip);
  if (params?.dst_ip) qs.set("dst_ip", params.dst_ip);
  if (params?.dst_port != null) qs.set("dst_port", String(params.dst_port));
  if (params?.protocol) qs.set("protocol", params.protocol);
  if (params?.country) qs.set("country", params.country);
  if (params?.after) qs.set("after", params.after);
  if (params?.before) qs.set("before", params.before);
  if (params?.flagged) qs.set("flagged", "true");
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

export function useConnectionHistoryStats() {
  return useQuery({
    queryKey: ["connections", "stats"],
    queryFn: () =>
      apiFetch<ConnectionHistoryStats>("/api/connections/stats"),
    staleTime: 300_000,
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

export function useCountrySummary(countryCode: string | null, days = 30) {
  return useQuery({
    queryKey: ["connections", "country-summary", countryCode, days],
    queryFn: () =>
      apiFetch<CountrySummary>(
        `/api/connections/country/${countryCode}/summary?days=${days}`,
      ),
    enabled: !!countryCode,
    staleTime: 60_000,
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
