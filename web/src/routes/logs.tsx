import { useState } from "react";
import { useLogs } from "@/api/queries";
import { PageShell } from "@/components/layout/page-shell";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { cn } from "@/lib/utils";

const LIMITS = [50, 100, 200, 500] as const;

export function LogsPage() {
  const [topics, setTopics] = useState("");
  const [limit, setLimit] = useState<number>(100);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const logs = useLogs(topics || undefined, limit, {
    refetchInterval: autoRefresh ? 5_000 : false,
  });

  return (
    <PageShell
      title="Logs"
      onRefresh={() => logs.refetch()}
      isRefreshing={logs.isFetching}
    >
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <input
          type="text"
          placeholder="Filter by topics (e.g. firewall,error)"
          value={topics}
          onChange={(e) => setTopics(e.target.value)}
          className="rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground"
        />
        <select
          value={limit}
          onChange={(e) => setLimit(Number(e.target.value))}
          className="rounded-md border border-border bg-background px-2 py-1.5 text-sm text-foreground"
        >
          {LIMITS.map((l) => (
            <option key={l} value={l}>
              {l} entries
            </option>
          ))}
        </select>
        <label className="flex items-center gap-1.5 text-sm text-muted-foreground">
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => setAutoRefresh(e.target.checked)}
            className="rounded"
          />
          Auto-refresh
        </label>
      </div>

      {logs.isLoading && <LoadingSpinner />}
      {logs.error && (
        <ErrorDisplay message={logs.error.message} onRetry={() => logs.refetch()} />
      )}

      {logs.data && (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                <th className="px-3 py-2 text-left font-medium text-muted-foreground w-24">
                  Time
                </th>
                <th className="px-3 py-2 text-left font-medium text-muted-foreground w-36">
                  Topics
                </th>
                <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                  Message
                </th>
              </tr>
            </thead>
            <tbody>
              {logs.data.map((entry) => (
                <tr
                  key={entry[".id"]}
                  className="border-b border-border/50 hover:bg-muted/30"
                >
                  <td className="px-3 py-1.5 font-mono text-xs text-muted-foreground whitespace-nowrap">
                    {entry.time}
                  </td>
                  <td className="px-3 py-1.5">
                    {entry.topics && (
                      <div className="flex flex-wrap gap-1">
                        {entry.topics.split(",").map((t) => (
                          <span
                            key={t}
                            className={cn(
                              "inline-flex rounded px-1.5 py-0.5 text-xs",
                              t.includes("error") || t.includes("critical")
                                ? "bg-destructive/15 text-destructive"
                                : t.includes("warning")
                                  ? "bg-warning/15 text-warning"
                                  : "bg-muted text-muted-foreground",
                            )}
                          >
                            {t.trim()}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-xs">
                    {entry.message}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </PageShell>
  );
}
