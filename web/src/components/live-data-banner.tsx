import { WifiOff } from "lucide-react";

interface LiveDataBannerProps {
  /** From the API response: `false` when the router is unreachable. */
  liveAvailable: boolean;
  /** ISO timestamp of the last-known data, when available. */
  asOf?: string | null;
}

/**
 * Shown when the router (the live data source) is unreachable and a view is
 * displaying last-known / stored data instead of live conntrack or logs.
 *
 * Renders nothing when live data is available, so callers can mount it
 * unconditionally and simply pass the response's `live_available` flag
 * (DRIFT P3 graceful degradation).
 */
export function LiveDataBanner({ liveAvailable, asOf }: LiveDataBannerProps) {
  if (liveAvailable) return null;

  let asOfLabel: string | null = null;
  if (asOf) {
    const d = new Date(asOf);
    asOfLabel = Number.isNaN(d.getTime()) ? asOf : d.toLocaleString();
  }

  return (
    <div
      role="status"
      className="mb-4 flex items-start gap-2 rounded-md border border-amber-600/30 bg-amber-900/30 px-4 py-3 text-sm text-amber-200"
    >
      <WifiOff className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <p className="flex-1 min-w-0">
        Router unreachable — showing last-known data.
        {asOfLabel ? (
          <span className="opacity-80"> Last updated {asOfLabel}.</span>
        ) : (
          <span className="opacity-80"> No stored data is available yet.</span>
        )}
      </p>
    </div>
  );
}
