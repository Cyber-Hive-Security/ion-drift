import { useState } from "react";
import { useAuth } from "@/hooks/use-auth";
import { useAdvisoryFeedStatus, useSetAdvisoryFeedConsent } from "@/api/queries";
import { FEED_HOSTS, FEED_OFF_WARNING } from "@/components/advisory-feed-consent";

function when(ts: number | null): string {
  return ts == null ? "never" : new Date(ts * 1000).toLocaleString();
}

export function SettingsAdvisoryFeed() {
  const { user } = useAuth();
  const { data } = useAdvisoryFeedStatus();
  const setConsent = useSetAdvisoryFeedConsent();
  const [confirmingOff, setConfirmingOff] = useState(false);
  if (!data) return null;

  const label = data.consent === "on" ? "On" : data.consent === "off" ? "Off" : "Awaiting confirmation";

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <h3 className="text-sm font-semibold">Vulnerability feed</h3>
      <p className="mt-1 text-sm text-muted-foreground">
        Daily download of public RouterOS vulnerability data from {FEED_HOSTS.join(" and ")}. Nothing about this
        installation is sent.
      </p>
      <p className="mt-3 text-sm">
        Status: <span className="font-medium">{label}</span>
        {data.set_by && <> — set by {data.set_by} on {when(data.set_at)}</>}
      </p>
      {data.sources.length > 0 && (
        <ul className="mt-2 space-y-1 text-xs text-muted-foreground">
          {data.sources.map((s) => (
            <li key={s.source}>
              {s.source.toUpperCase()}: last success {when(s.last_success_at)}, {s.records} records
              {s.last_error && <> — last error: {s.last_error}</>}
            </li>
          ))}
        </ul>
      )}
      {user?.is_admin && data.consent !== "unanswered" && (
        <div className="mt-4">
          {data.consent === "off" ? (
            <button type="button" onClick={() => setConsent.mutate("on")} disabled={setConsent.isPending}
              className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground">
              Turn on
            </button>
          ) : confirmingOff ? (
            <div className="space-y-3 rounded-md border border-amber-500/40 bg-amber-500/10 p-3">
              <p className="text-sm text-amber-200">{FEED_OFF_WARNING}</p>
              <div className="flex gap-2">
                <button type="button" onClick={() => setConfirmingOff(false)}
                  className="rounded-md border border-border px-3 py-1.5 text-sm">Back</button>
                <button type="button"
                  onClick={() => setConsent.mutate("off", { onSuccess: () => setConfirmingOff(false) })}
                  disabled={setConsent.isPending}
                  className="rounded-md bg-red-600 px-3 py-1.5 text-sm font-medium text-white">
                  Turn off anyway
                </button>
              </div>
            </div>
          ) : (
            <button type="button" onClick={() => setConfirmingOff(true)}
              className="rounded-md border border-border px-3 py-1.5 text-sm">
              Turn off
            </button>
          )}
        </div>
      )}
    </div>
  );
}
