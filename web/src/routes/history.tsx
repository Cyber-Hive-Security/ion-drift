import { useState } from "react";
import { useConnectionHistory } from "@/api/queries";
import { PageShell } from "@/components/layout/page-shell";
import { HistoryHelp } from "@/components/help-content";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { DataTable, type Column } from "@/components/data-table";
import { formatBytes, formatNumber } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { ConnectionHistoryEntry } from "@/api/types";

// ── Connection history table columns ────────────────────────

const historyColumns: Column<ConnectionHistoryEntry>[] = [
  {
    key: "protocol",
    header: "Proto",
    render: (r) => (
      <span className="font-mono text-xs uppercase">{r.protocol}</span>
    ),
  },
  {
    key: "src_ip",
    header: "Source",
    render: (r) => (
      <span className="font-mono text-xs">
        {r.src_ip}
        {r.src_hostname && (
          <span className="ml-1 text-muted-foreground">
            ({r.src_hostname})
          </span>
        )}
      </span>
    ),
  },
  {
    key: "dst_ip",
    header: "Destination",
    render: (r) => (
      <span className="font-mono text-xs">
        {r.dst_ip}
        {r.dst_port != null && `:${r.dst_port}`}
        {r.dst_hostname && (
          <span className="ml-1 text-muted-foreground">
            ({r.dst_hostname})
          </span>
        )}
      </span>
    ),
  },
  {
    key: "geo_country",
    header: "Country",
    render: (r) =>
      r.geo_country ? (
        <span className="text-xs">
          {r.geo_country_code && (
            <span className="mr-1">{r.geo_country_code}</span>
          )}
          {r.geo_country}
        </span>
      ) : (
        <span className="text-xs text-muted-foreground">Local</span>
      ),
  },
  {
    key: "bytes_tx",
    header: "TX / RX",
    render: (r) => (
      <span className="font-mono text-xs">
        {formatBytes(r.bytes_tx)} / {formatBytes(r.bytes_rx)}
      </span>
    ),
  },
  {
    key: "data_source",
    header: "Source",
    render: (r) => (
      <span
        className={cn(
          "rounded px-1.5 py-0.5 text-[10px] font-medium",
          r.data_source === "poll"
            ? "bg-primary/15 text-primary"
            : r.data_source === "syslog"
              ? "bg-warning/15 text-warning"
              : "bg-success/15 text-success",
        )}
      >
        {r.data_source}
      </span>
    ),
  },
  {
    key: "first_seen",
    header: "First Seen",
    render: (r) => (
      <span className="text-xs text-muted-foreground">
        {new Date(r.first_seen).toLocaleString()}
      </span>
    ),
  },
  {
    key: "flagged",
    header: "",
    render: (r) =>
      r.flagged ? (
        <span className="h-2 w-2 rounded-full bg-destructive inline-block" />
      ) : null,
  },
];

// ── Main History Page ───────────────────────────────────────

export function HistoryPage() {
  const [historyPage, setHistoryPage] = useState(1);
  const [countryFilter, setCountryFilter] = useState<string | undefined>();

  const connectionHistory = useConnectionHistory({
    page: historyPage,
    per_page: 50,
    country: countryFilter,
    external_only: true,
  });

  return (
    <PageShell title="History" help={<HistoryHelp />}>
      {/* Country filter badge */}
      {countryFilter && (
        <div className="mb-3 flex items-center gap-2">
          <span className="text-xs text-muted-foreground">
            Filtered by country:
          </span>
          <button
            onClick={() => {
              setCountryFilter(undefined);
              setHistoryPage(1);
            }}
            className="inline-flex items-center gap-1 rounded-full bg-primary/15 px-2.5 py-0.5 text-xs font-medium text-primary hover:bg-primary/25"
          >
            {countryFilter}
            <span className="ml-0.5">&times;</span>
          </button>
        </div>
      )}

      {connectionHistory.error ? (
        <ErrorDisplay message={String(connectionHistory.error)} />
      ) : connectionHistory.isLoading ? (
        <div className="flex h-96 items-center justify-center">
          <LoadingSpinner />
        </div>
      ) : connectionHistory.data ? (
        <div className="space-y-3">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>
              {formatNumber(connectionHistory.data.total)} connections
              {countryFilter && ` from ${countryFilter}`}
            </span>
            <div className="flex items-center gap-2">
              <button
                disabled={historyPage <= 1}
                onClick={() => setHistoryPage((p) => p - 1)}
                className="rounded border border-border px-2 py-0.5 disabled:opacity-30"
              >
                Prev
              </button>
              <span>
                Page {connectionHistory.data.page} of{" "}
                {Math.ceil(
                  connectionHistory.data.total /
                    connectionHistory.data.per_page,
                ) || 1}
              </span>
              <button
                disabled={
                  historyPage >=
                  Math.ceil(
                    connectionHistory.data.total /
                      connectionHistory.data.per_page,
                  )
                }
                onClick={() => setHistoryPage((p) => p + 1)}
                className="rounded border border-border px-2 py-0.5 disabled:opacity-30"
              >
                Next
              </button>
            </div>
          </div>
          <DataTable
            columns={historyColumns}
            data={connectionHistory.data.items}
            rowKey={(r) => String(r.id)}
          />
        </div>
      ) : null}
    </PageShell>
  );
}
