import { useState, useMemo } from "react";
import {
  useGeoSummary,
  usePortSummary,
  useSnapshots,
  useSnapshot,
  useConnectionHistory,
} from "@/api/queries";
import { PageShell } from "@/components/layout/page-shell";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { DataTable, type Column } from "@/components/data-table";
import { WorldMap } from "@/features/world-map/world-map";
import { PortSankey } from "@/features/world-map/port-sankey";
import { formatBytes, formatNumber } from "@/lib/format";
import { cn } from "@/lib/utils";
import type {
  ConnectionHistoryEntry,
  GeoSummaryEntry,
  PortSummaryEntry,
} from "@/api/types";
import { Globe, BarChart3, Table2 } from "lucide-react";

// ── Tab definitions ─────────────────────────────────────────

type TabId = "world-map" | "port-flows" | "history-table";

const TABS: { id: TabId; label: string; icon: typeof Globe }[] = [
  { id: "world-map", label: "World Map", icon: Globe },
  { id: "port-flows", label: "Port Flows", icon: BarChart3 },
  { id: "history-table", label: "History", icon: Table2 },
];

// ── Time range options ──────────────────────────────────────

type TimeRange = "1" | "7" | "30";

const TIME_RANGES: { value: TimeRange; label: string }[] = [
  { value: "1", label: "24h" },
  { value: "7", label: "7d" },
  { value: "30", label: "30d" },
];

// ── Week picker ─────────────────────────────────────────────

function WeekPicker({
  weeks,
  selected,
  onSelect,
}: {
  weeks: string[];
  selected: string | null;
  onSelect: (w: string | null) => void;
}) {
  if (weeks.length === 0) return null;

  return (
    <div className="flex items-center gap-2 text-xs">
      <button
        onClick={() => onSelect(null)}
        className={cn(
          "rounded-md px-2.5 py-1 transition-colors",
          selected === null
            ? "bg-primary/15 text-primary font-medium"
            : "text-muted-foreground hover:bg-muted hover:text-foreground",
        )}
      >
        Live
      </button>
      {weeks.map((w) => (
        <button
          key={w}
          onClick={() => onSelect(w)}
          className={cn(
            "rounded-md px-2.5 py-1 transition-colors",
            selected === w
              ? "bg-primary/15 text-primary font-medium"
              : "text-muted-foreground hover:bg-muted hover:text-foreground",
          )}
        >
          {w}
        </button>
      ))}
    </div>
  );
}

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
            ? "bg-blue-500/15 text-blue-400"
            : r.data_source === "syslog"
              ? "bg-amber-500/15 text-amber-400"
              : "bg-green-500/15 text-green-400",
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
        <span className="h-2 w-2 rounded-full bg-red-500 inline-block" />
      ) : null,
  },
];

// ── Main History Page ───────────────────────────────────────

export function HistoryPage() {
  const [activeTab, setActiveTab] = useState<TabId>("world-map");
  const [timeRange, setTimeRange] = useState<TimeRange>("7");
  const [selectedWeek, setSelectedWeek] = useState<string | null>(null);
  const [countryFilter, setCountryFilter] = useState<string | undefined>();
  const [historyPage, setHistoryPage] = useState(1);

  // Live data queries
  const geoSummary = useGeoSummary(Number(timeRange));
  const portSummary = usePortSummary(Number(timeRange));
  const snapshots = useSnapshots();
  const connectionHistory = useConnectionHistory({
    page: historyPage,
    per_page: 50,
    country: countryFilter,
    external_only: true,
  });

  // Snapshot data (when a week is selected)
  const worldMapSnapshot = useSnapshot(selectedWeek, "world_map");
  const portSnapshot = useSnapshot(selectedWeek, "sankey_port");

  // Available weeks
  const availableWeeks = useMemo(
    () => (snapshots.data ?? []).map((s) => s.week),
    [snapshots.data],
  );

  // Resolve which data to show — snapshot or live
  const mapData: GeoSummaryEntry[] = useMemo(() => {
    if (selectedWeek && worldMapSnapshot.data?.data) {
      try {
        return JSON.parse(worldMapSnapshot.data.data) as GeoSummaryEntry[];
      } catch {
        return [];
      }
    }
    return geoSummary.data ?? [];
  }, [selectedWeek, worldMapSnapshot.data, geoSummary.data]);

  const portData: PortSummaryEntry[] = useMemo(() => {
    if (selectedWeek && portSnapshot.data?.data) {
      try {
        return JSON.parse(portSnapshot.data.data) as PortSummaryEntry[];
      } catch {
        return [];
      }
    }
    return portSummary.data ?? [];
  }, [selectedWeek, portSnapshot.data, portSummary.data]);

  const isLoading =
    (activeTab === "world-map" && (selectedWeek ? worldMapSnapshot.isLoading : geoSummary.isLoading)) ||
    (activeTab === "port-flows" && (selectedWeek ? portSnapshot.isLoading : portSummary.isLoading)) ||
    (activeTab === "history-table" && connectionHistory.isLoading);

  const error =
    (activeTab === "world-map" && geoSummary.error) ||
    (activeTab === "port-flows" && portSummary.error) ||
    (activeTab === "history-table" && connectionHistory.error);

  function handleCountryClick(code: string) {
    setCountryFilter(code === countryFilter ? undefined : code);
    setActiveTab("history-table");
    setHistoryPage(1);
  }

  return (
    <PageShell title="History">
      {/* Controls row */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        {/* Tabs */}
        <div className="flex items-center gap-1 rounded-lg border border-border bg-card p-1">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={cn(
                "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
                activeTab === id
                  ? "bg-primary/15 text-primary"
                  : "text-muted-foreground hover:bg-muted hover:text-foreground",
              )}
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
            </button>
          ))}
        </div>

        {/* Time range selector (live mode only) */}
        {!selectedWeek && activeTab !== "history-table" && (
          <div className="flex items-center gap-1 rounded-lg border border-border bg-card p-1">
            {TIME_RANGES.map(({ value, label }) => (
              <button
                key={value}
                onClick={() => setTimeRange(value)}
                className={cn(
                  "rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
                  timeRange === value
                    ? "bg-primary/15 text-primary"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground",
                )}
              >
                {label}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Week picker */}
      {availableWeeks.length > 0 && activeTab !== "history-table" && (
        <div className="mb-4">
          <WeekPicker
            weeks={availableWeeks}
            selected={selectedWeek}
            onSelect={setSelectedWeek}
          />
        </div>
      )}

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

      {/* Content */}
      {isLoading ? (
        <div className="flex h-96 items-center justify-center">
          <LoadingSpinner />
        </div>
      ) : error ? (
        <ErrorDisplay message={String(error)} />
      ) : (
        <>
          {activeTab === "world-map" && (
            <WorldMap
              data={mapData}
              onCountryClick={handleCountryClick}
              timeRange={selectedWeek ?? timeRange}
            />
          )}

          {activeTab === "port-flows" && <PortSankey data={portData} />}

          {activeTab === "history-table" && connectionHistory.data && (
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
          )}
        </>
      )}
    </PageShell>
  );
}
