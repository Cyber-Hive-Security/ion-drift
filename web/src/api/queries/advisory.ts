import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "../client";

// Mirrors crates/ion-drift-web/src/routes/advisory_feed.rs::FeedStatusResponse

export type FeedConsent = "unanswered" | "on" | "off";

export interface FeedSourceState {
  source: "nvd" | "kev";
  last_success_at: number | null;
  last_attempt_at: number;
  last_error: string | null;
  records: number;
}

export interface AdvisoryFeedStatus {
  consent: FeedConsent;
  set_by: string | null;
  set_at: number | null;
  sources: FeedSourceState[];
  stale: boolean;
}

const FEED_KEY = ["advisory", "feed"] as const;

export function useAdvisoryFeedStatus() {
  return useQuery({
    queryKey: FEED_KEY,
    queryFn: () => apiFetch<AdvisoryFeedStatus>("/api/advisory/feed"),
    refetchInterval: 60_000,
  });
}

export function useSetAdvisoryFeedConsent() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (consent: "on" | "off") =>
      apiFetch<AdvisoryFeedStatus>("/api/advisory/feed/consent", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ consent }),
      }),
    onSuccess: (data) => {
      queryClient.setQueryData(FEED_KEY, data);
    },
  });
}
