import { useAdvisoryFeedStatus } from "@/api/queries";

/**
 * Findings-page notice for the two states where "no vulnerability findings"
 * must not be read as "no vulnerabilities": feed off, and feed data stale.
 */
export function AdvisoryFeedStatusBanner() {
  const { data } = useAdvisoryFeedStatus();
  if (!data) return null;

  if (data.consent === "off") {
    // Turning the feed off stops downloads; checks keep using what was last stored.
    const downloads = data.sources.map((s) => s.last_success_at).filter((t): t is number => t != null);
    const newest = downloads.length === 0 ? null : Math.max(...downloads);
    return (
      <div role="status" className="mb-4 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-200">
        The vulnerability feed is off.{" "}
        {newest == null
          ? "Nothing was ever downloaded, so only advisories bundled with this release are evaluated."
          : `Checks continue against vulnerability data last downloaded on ${new Date(newest * 1000).toLocaleDateString()}.`}{" "}
        New vulnerabilities are not learned: newly published or newly exploited RouterOS vulnerabilities will not be
        reported. An administrator can change this in Settings → Security.
      </div>
    );
  }

  if (data.consent === "on" && data.stale) {
    const failing = data.sources.filter((s) => s.last_error);
    // A source that has never succeeded is stale since first fetch, regardless of the others.
    const successes = data.sources.map((s) => s.last_success_at);
    const oldest =
      successes.length === 0 || successes.some((t) => t == null)
        ? null
        : Math.min(...(successes as number[]));
    return (
      <div role="status" className="mb-4 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-200">
        Vulnerability data stale since {oldest == null ? "first fetch" : new Date(oldest * 1000).toLocaleString()}.
        {failing.map((s) => (
          <span key={s.source}> {s.source.toUpperCase()} last error: {s.last_error}.</span>
        ))}
      </div>
    );
  }

  return null;
}
