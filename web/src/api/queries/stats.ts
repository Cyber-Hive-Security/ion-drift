import { useQuery, useMutation } from "@tanstack/react-query";
import { apiFetch } from "../client";
import type { PageViewEntry, DiagnosticReport } from "../types";

export function usePageViews(days = 30) {
  return useQuery({
    queryKey: ["stats", "page-views", days],
    queryFn: () =>
      apiFetch<PageViewEntry[]>(`/api/stats/page-views?days=${days}`),
    refetchInterval: 60_000,
  });
}

export function useDiagnosticReport() {
  return useQuery({
    queryKey: ["stats", "report"],
    queryFn: () => apiFetch<DiagnosticReport>("/api/stats/report"),
    enabled: false,
  });
}

export function useRecordPageView() {
  return useMutation({
    mutationFn: (data: { page: string; context: string }) =>
      apiFetch<{ recorded: boolean }>("/api/stats/page-view", {
        method: "POST",
        body: JSON.stringify(data),
      }),
  });
}
