import { useState, useCallback } from "react";
import { Microscope, Filter, X } from "lucide-react";
import { Link, useSearch, useNavigate } from "@tanstack/react-router";
import { useConnectionHistory } from "@/api/queries";
import { PageShell } from "@/components/layout/page-shell";
import { HistoryHelp } from "@/components/help-content";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { DataTable, type Column } from "@/components/data-table";
import { DeviceLink } from "@/components/device-link";
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
        {r.src_mac ? (
          <DeviceLink mac={r.src_mac} label={r.src_ip} className="font-mono text-xs" />
        ) : (
          r.src_ip
        )}
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
  {
    key: "investigate",
    header: "",
    render: (r) =>
      r.src_mac ? (
        <Link
          to="/sankey"
          search={{ mac: r.src_mac }}
          className="rounded p-1 text-muted-foreground hover:bg-primary/15 hover:text-primary"
          title="Investigate source device"
        >
          <Microscope className="h-3.5 w-3.5" />
        </Link>
      ) : null,
  },
];

// ── Filter state ────────────────────────────────────────────

interface Filters {
  src_ip: string;
  dst_ip: string;
  dst_port: string;
  protocol: string;
  country: string;
  after: string;
  before: string;
  flagged: boolean;
}

const EMPTY_FILTERS: Filters = {
  src_ip: "",
  dst_ip: "",
  dst_port: "",
  protocol: "",
  country: "",
  after: "",
  before: "",
  flagged: false,
};

function filtersFromSearch(search: Record<string, string | undefined>): Filters {
  return {
    src_ip: search.src_ip ?? "",
    dst_ip: search.dst_ip ?? "",
    dst_port: search.dst_port ?? "",
    protocol: search.protocol ?? "",
    country: search.country ?? "",
    after: search.after ?? "",
    before: search.before ?? "",
    flagged: search.flagged === "true",
  };
}

function hasActiveFilters(f: Filters): boolean {
  return !!(f.src_ip || f.dst_ip || f.dst_port || f.protocol || f.country || f.after || f.before || f.flagged);
}

// ── Filter Bar ──────────────────────────────────────────────

function HistoryFilterBar({
  filters,
  onChange,
  onClear,
}: {
  filters: Filters;
  onChange: (f: Filters) => void;
  onClear: () => void;
}) {
  const [open, setOpen] = useState(hasActiveFilters(filters));
  const active = hasActiveFilters(filters);

  return (
    <div className="mb-3">
      <div className="flex items-center gap-2">
        <button
          onClick={() => setOpen((o) => !o)}
          className={cn(
            "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
            active
              ? "bg-primary text-primary-foreground"
              : "bg-muted text-muted-foreground hover:text-foreground",
          )}
        >
          <Filter className="h-3 w-3" />
          Filters
          {active && <span className="ml-0.5 rounded-full bg-primary-foreground/20 px-1.5 text-[10px]">ON</span>}
        </button>
        {active && (
          <button
            onClick={onClear}
            className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
          >
            <X className="h-3 w-3" />
            Clear
          </button>
        )}
      </div>

      {open && (
        <div className="mt-2 grid grid-cols-2 gap-2 rounded-lg border border-border bg-card p-3 sm:grid-cols-3 lg:grid-cols-4">
          <FilterInput
            label="Source IP"
            placeholder="10.20.25.100"
            value={filters.src_ip}
            onChange={(v) => onChange({ ...filters, src_ip: v })}
          />
          <FilterInput
            label="Dest IP"
            placeholder="1.1.1.1"
            value={filters.dst_ip}
            onChange={(v) => onChange({ ...filters, dst_ip: v })}
          />
          <FilterInput
            label="Dest Port"
            placeholder="443"
            value={filters.dst_port}
            onChange={(v) => onChange({ ...filters, dst_port: v })}
          />
          <div>
            <label className="mb-1 block text-[10px] font-medium text-muted-foreground">Protocol</label>
            <select
              value={filters.protocol}
              onChange={(e) => onChange({ ...filters, protocol: e.target.value })}
              className="w-full rounded border border-border bg-background px-2 py-1 text-xs"
            >
              <option value="">All</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
            </select>
          </div>
          <FilterInput
            label="Country Code"
            placeholder="US"
            value={filters.country}
            onChange={(v) => onChange({ ...filters, country: v })}
          />
          <FilterInput
            label="After"
            placeholder="2026-03-01"
            value={filters.after}
            onChange={(v) => onChange({ ...filters, after: v })}
            type="date"
          />
          <FilterInput
            label="Before"
            placeholder="2026-03-30"
            value={filters.before}
            onChange={(v) => onChange({ ...filters, before: v })}
            type="date"
          />
          <div className="flex items-end pb-0.5">
            <label className="inline-flex items-center gap-1.5 text-xs">
              <input
                type="checkbox"
                checked={filters.flagged}
                onChange={(e) => onChange({ ...filters, flagged: e.target.checked })}
                className="rounded"
              />
              Flagged only
            </label>
          </div>
        </div>
      )}
    </div>
  );
}

function FilterInput({
  label,
  placeholder,
  value,
  onChange,
  type = "text",
}: {
  label: string;
  placeholder: string;
  value: string;
  onChange: (v: string) => void;
  type?: string;
}) {
  return (
    <div>
      <label className="mb-1 block text-[10px] font-medium text-muted-foreground">{label}</label>
      <input
        type={type}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded border border-border bg-background px-2 py-1 text-xs font-mono placeholder:text-muted-foreground/50"
      />
    </div>
  );
}

// ── Active filter badges ────────────────────────────────────

function ActiveFilterBadges({ filters, onChange }: { filters: Filters; onChange: (f: Filters) => void }) {
  const badges: { label: string; clear: () => void }[] = [];
  if (filters.src_ip) badges.push({ label: `src: ${filters.src_ip}`, clear: () => onChange({ ...filters, src_ip: "" }) });
  if (filters.dst_ip) badges.push({ label: `dst: ${filters.dst_ip}`, clear: () => onChange({ ...filters, dst_ip: "" }) });
  if (filters.dst_port) badges.push({ label: `port: ${filters.dst_port}`, clear: () => onChange({ ...filters, dst_port: "" }) });
  if (filters.protocol) badges.push({ label: filters.protocol.toUpperCase(), clear: () => onChange({ ...filters, protocol: "" }) });
  if (filters.country) badges.push({ label: `country: ${filters.country}`, clear: () => onChange({ ...filters, country: "" }) });
  if (filters.after) badges.push({ label: `after: ${filters.after}`, clear: () => onChange({ ...filters, after: "" }) });
  if (filters.before) badges.push({ label: `before: ${filters.before}`, clear: () => onChange({ ...filters, before: "" }) });
  if (filters.flagged) badges.push({ label: "flagged", clear: () => onChange({ ...filters, flagged: false }) });

  if (badges.length === 0) return null;

  return (
    <div className="mb-2 flex flex-wrap gap-1.5">
      {badges.map((b) => (
        <button
          key={b.label}
          onClick={b.clear}
          className="inline-flex items-center gap-1 rounded-full bg-primary/15 px-2 py-0.5 text-[10px] font-medium text-primary hover:bg-primary/25"
        >
          {b.label}
          <X className="h-2.5 w-2.5" />
        </button>
      ))}
    </div>
  );
}

// ── Main History Page ───────────────────────────────────────

export function HistoryPage() {
  const search = useSearch({ from: "/history" });
  const navigate = useNavigate();
  const [historyPage, setHistoryPage] = useState(1);
  const [filters, setFilters] = useState<Filters>(() => filtersFromSearch(search));

  const handleFiltersChange = useCallback((f: Filters) => {
    setFilters(f);
    setHistoryPage(1);
    // Sync to URL
    navigate({
      to: "/history",
      search: {
        src_ip: f.src_ip || undefined,
        dst_ip: f.dst_ip || undefined,
        dst_port: f.dst_port || undefined,
        protocol: f.protocol || undefined,
        country: f.country || undefined,
        after: f.after || undefined,
        before: f.before || undefined,
        flagged: f.flagged ? "true" : undefined,
      },
      replace: true,
    });
  }, [navigate]);

  const handleClear = useCallback(() => {
    handleFiltersChange(EMPTY_FILTERS);
  }, [handleFiltersChange]);

  const connectionHistory = useConnectionHistory({
    page: historyPage,
    per_page: 50,
    src_ip: filters.src_ip || undefined,
    dst_ip: filters.dst_ip || undefined,
    dst_port: filters.dst_port ? Number(filters.dst_port) : undefined,
    protocol: filters.protocol || undefined,
    country: filters.country || undefined,
    after: filters.after || undefined,
    before: filters.before || undefined,
    flagged: filters.flagged || undefined,
    external_only: true,
  });

  return (
    <PageShell title="History" help={<HistoryHelp />}>
      <HistoryFilterBar
        filters={filters}
        onChange={handleFiltersChange}
        onClear={handleClear}
      />
      <ActiveFilterBadges filters={filters} onChange={handleFiltersChange} />

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
              {hasActiveFilters(filters) && " (filtered)"}
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
