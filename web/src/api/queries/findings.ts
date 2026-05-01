import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "../client";

// ── Types — mirror crates/ion-drift-storage/src/findings.rs::Finding ─────

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "open" | "acknowledged" | "resolved";

export type FindingEvidence =
  | { type: "anomaly"; anomaly_id: number }
  | { type: "connection"; connection_id: number }
  | { type: "custom"; label: string; payload: unknown };

export interface Finding {
  id: number;
  module_name: string;
  finding_id: string;
  title: string;
  narrative: string;
  severity: FindingSeverity;
  category: string;
  recommended_actions: string[];
  evidence: FindingEvidence[];
  device_macs: string[];
  metadata: unknown | null;
  timestamp: number;
  received_at: number;
  envelope_event_id: string | null;
  envelope_nonce: string | null;
  status: FindingStatus;
  acknowledged_at: number | null;
  acknowledged_by: string | null;
  resolved_at: number | null;
  resolved_by: string | null;
  resolution_note: string | null;
}

export interface FindingsSummary {
  total: number;
  open_count: number;
  acknowledged_count: number;
  resolved_count: number;
  critical_open: number;
  high_open: number;
  medium_open: number;
  low_open: number;
  info_open: number;
}

export interface FindingsFilters {
  status?: FindingStatus;
  severity?: FindingSeverity;
  module?: string;
  category?: string;
  since?: number;
  limit?: number;
  offset?: number;
}

// ── Queries ──────────────────────────────────────────────────────────────

export function useFindings(filters?: FindingsFilters) {
  const qs = new URLSearchParams();
  if (filters?.status) qs.set("status", filters.status);
  if (filters?.severity) qs.set("severity", filters.severity);
  if (filters?.module) qs.set("module", filters.module);
  if (filters?.category) qs.set("category", filters.category);
  if (filters?.since != null) qs.set("since", String(filters.since));
  if (filters?.limit != null) qs.set("limit", String(filters.limit));
  if (filters?.offset != null) qs.set("offset", String(filters.offset));
  const qsStr = qs.toString();
  return useQuery({
    queryKey: ["findings", "list", filters],
    queryFn: () =>
      apiFetch<Finding[]>(`/api/findings${qsStr ? `?${qsStr}` : ""}`),
    refetchInterval: 30_000,
  });
}

export function useFinding(id: number | null) {
  return useQuery({
    queryKey: ["findings", "detail", id],
    queryFn: () => apiFetch<Finding>(`/api/findings/${id}`),
    enabled: id != null,
  });
}

export function useFindingsSummary() {
  return useQuery({
    queryKey: ["findings", "summary"],
    queryFn: () => apiFetch<FindingsSummary>("/api/findings/summary"),
    refetchInterval: 15_000,
  });
}

export function useAcknowledgeFinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiFetch<{ id: number; status: string }>(
        `/api/findings/${id}/acknowledge`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}",
        },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings"] });
    },
  });
}

export function useResolveFinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, note }: { id: number; note?: string }) =>
      apiFetch<{ id: number; status: string }>(
        `/api/findings/${id}/resolve`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ note: note ?? null }),
        },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings"] });
    },
  });
}
