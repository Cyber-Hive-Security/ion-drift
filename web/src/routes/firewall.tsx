import { useState, useMemo, type CSSProperties } from "react";
import { Microscope } from "lucide-react";
import { Link } from "@tanstack/react-router";
import {
  useFirewallFilter,
  useFirewallNat,
  useFirewallMangle,
} from "@/api/queries";
import { DataTable, type Column } from "@/components/data-table";
import { PageShell } from "@/components/layout/page-shell";
import { FirewallHelp } from "@/components/help-content";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { formatBytes, formatNumber } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { FilterRule, NatRule, MangleRule } from "@/api/types";

function RuleCell({ value, disabled }: { value?: string | null; disabled?: boolean }) {
  if (!value) return <span className="text-muted-foreground/50">—</span>;
  return (
    <span className={cn("font-mono text-xs", disabled && "opacity-50")}>
      {value}
    </span>
  );
}

type Numbered<T> = T & { _ruleNum: number };

const filterColumns: Column<Numbered<FilterRule>>[] = [
  { key: "num", header: "#", render: (r) => <span className="text-muted-foreground text-xs">{r._ruleNum}</span>, sortValue: (r) => r._ruleNum },
  { key: "chain", header: "Chain", render: (r) => r.chain, sortValue: (r) => r.chain },
  {
    key: "action",
    header: "Action",
    render: (r) => (
      <span
        className={cn(
          "inline-flex rounded px-1.5 py-0.5 text-xs font-medium",
          r.action === "drop" && "bg-destructive/15 text-destructive",
          r.action === "accept" && "bg-success/15 text-success",
          r.action === "reject" && "bg-warning/15 text-warning",
          !["drop", "accept", "reject"].includes(r.action) && "bg-muted text-muted-foreground",
        )}
      >
        {r.action}
      </span>
    ),
  },
  { key: "src", header: "Src Address", render: (r) => <RuleCell value={r["src-address"]} disabled={r.disabled ?? false} /> },
  { key: "dst", header: "Dst Address", render: (r) => <RuleCell value={r["dst-address"]} disabled={r.disabled ?? false} /> },
  { key: "proto", header: "Proto", render: (r) => r.protocol ?? "—" },
  { key: "dport", header: "Dst Port", render: (r) => <RuleCell value={r["dst-port"]} /> },
  {
    key: "bytes",
    header: "Bytes",
    render: (r) => (r.bytes != null ? formatBytes(r.bytes, 1) : "—"),
    sortValue: (r) => r.bytes ?? 0,
  },
  {
    key: "packets",
    header: "Packets",
    render: (r) => (r.packets != null ? formatNumber(r.packets) : "—"),
    sortValue: (r) => r.packets ?? 0,
  },
  { key: "comment", header: "Comment", render: (r) => <span className={cn(r.disabled && "opacity-50")}>{r.comment ?? ""}</span> },
  {
    key: "investigate",
    header: "",
    render: (r) =>
      r["src-address"] ? (
        <Link
          to="/sankey"
          search={{ mac: r["src-address"] }}
          className="rounded p-1 text-muted-foreground hover:bg-primary/15 hover:text-primary"
          title={`Investigate ${r["src-address"]}`}
        >
          <Microscope className="h-3.5 w-3.5" />
        </Link>
      ) : null,
  },
];

const natColumns: Column<Numbered<NatRule>>[] = [
  { key: "num", header: "#", render: (r) => <span className="text-muted-foreground text-xs">{r._ruleNum}</span>, sortValue: (r) => r._ruleNum },
  { key: "chain", header: "Chain", render: (r) => r.chain, sortValue: (r) => r.chain },
  {
    key: "action",
    header: "Action",
    render: (r) => <span className="rounded bg-muted px-1.5 py-0.5 text-xs font-medium">{r.action}</span>,
  },
  { key: "src", header: "Src", render: (r) => <RuleCell value={r["src-address"]} /> },
  { key: "dst", header: "Dst", render: (r) => <RuleCell value={r["dst-address"]} /> },
  { key: "proto", header: "Proto", render: (r) => r.protocol ?? "—" },
  { key: "to-addr", header: "To Addr", render: (r) => <RuleCell value={r["to-addresses"]} /> },
  { key: "to-port", header: "To Port", render: (r) => <RuleCell value={r["to-ports"]} /> },
  { key: "bytes", header: "Bytes", render: (r) => (r.bytes != null ? formatBytes(r.bytes, 1) : "—"), sortValue: (r) => r.bytes ?? 0 },
  { key: "comment", header: "Comment", render: (r) => r.comment ?? "" },
];

const mangleColumns: Column<Numbered<MangleRule>>[] = [
  { key: "num", header: "#", render: (r) => <span className="text-muted-foreground text-xs">{r._ruleNum}</span>, sortValue: (r) => r._ruleNum },
  { key: "chain", header: "Chain", render: (r) => r.chain, sortValue: (r) => r.chain },
  { key: "action", header: "Action", render: (r) => <span className="rounded bg-muted px-1.5 py-0.5 text-xs font-medium">{r.action}</span> },
  { key: "src", header: "Src", render: (r) => <RuleCell value={r["src-address"]} /> },
  { key: "dst", header: "Dst", render: (r) => <RuleCell value={r["dst-address"]} /> },
  { key: "pkt-mark", header: "Pkt Mark", render: (r) => <RuleCell value={r["new-packet-mark"]} /> },
  { key: "conn-mark", header: "Conn Mark", render: (r) => <RuleCell value={r["new-connection-mark"]} /> },
  { key: "bytes", header: "Bytes", render: (r) => (r.bytes != null ? formatBytes(r.bytes, 1) : "—"), sortValue: (r) => r.bytes ?? 0 },
  { key: "comment", header: "Comment", render: (r) => r.comment ?? "" },
];

/** Compute heatmap background style based on rule bytes relative to max. */
function makeHeatmapStyle(
  maxBytes: number,
  getAction: (row: { bytes?: number }) => string,
) {
  return (row: { bytes?: number }): CSSProperties | undefined => {
    const bytes = row.bytes ?? 0;
    if (bytes === 0 || maxBytes === 0) return undefined;

    // Log scale for better distribution
    const intensity = Math.log(1 + bytes) / Math.log(1 + maxBytes);
    const opacity = 0.03 + intensity * 0.12; // range 0.03 to 0.15

    const action = getAction(row);
    if (action === "drop" || action === "reject") {
      return { backgroundColor: `rgba(239, 68, 68, ${opacity})` }; // red
    }
    if (action === "accept") {
      return { backgroundColor: `rgba(34, 197, 94, ${opacity})` }; // green
    }
    return { backgroundColor: `rgba(148, 163, 184, ${opacity})` }; // gray
  };
}

type Tab = "filter" | "nat" | "mangle";

export function FirewallPage() {
  const [tab, setTab] = useState<Tab>("filter");
  const [chainFilter, setChainFilter] = useState("");

  const filter = useFirewallFilter(undefined, { enabled: tab === "filter" });
  const nat = useFirewallNat(undefined, { enabled: tab === "nat" });
  const mangle = useFirewallMangle(undefined, { enabled: tab === "mangle" });

  const queries = { filter, nat, mangle };
  const query = queries[tab];

  // Number rules by their position in the API response (rule order)
  const numberedData = useMemo(() => {
    if (!query.data) return [];
    return (query.data as Array<{ chain: string }>).map((r, i) => ({
      ...r,
      _ruleNum: i,
    }));
  }, [query.data]);

  // Get unique chains for the current tab
  const chains = useMemo(() => {
    if (!numberedData.length) return [];
    return [...new Set(numberedData.map((r) => r.chain))].sort();
  }, [numberedData]);

  // Filter data by chain (rule numbers preserved from original order)
  const filteredData = useMemo(() => {
    if (!chainFilter) return numberedData;
    return numberedData.filter((r) => r.chain === chainFilter);
  }, [numberedData, chainFilter]);

  // Compute max bytes for heatmap scaling
  const maxBytes = useMemo(() => {
    if (!filteredData.length) return 0;
    return Math.max(
      ...filteredData.map((r) => (r as { bytes?: number }).bytes ?? 0),
    );
  }, [filteredData]);

  const filterHeatmap = useMemo(
    () => makeHeatmapStyle(maxBytes, (r) => (r as Numbered<FilterRule>).action ?? ""),
    [maxBytes],
  );
  const natHeatmap = useMemo(
    () => makeHeatmapStyle(maxBytes, (r) => (r as Numbered<NatRule>).action ?? ""),
    [maxBytes],
  );
  const mangleHeatmap = useMemo(
    () => makeHeatmapStyle(maxBytes, (r) => (r as Numbered<MangleRule>).action ?? ""),
    [maxBytes],
  );

  return (
    <PageShell
      title="Firewall"
      onRefresh={() => query.refetch()}
      isRefreshing={query.isFetching}
      help={<FirewallHelp />}
    >
      <div className="mb-4 flex items-center gap-4">
        <div className="flex gap-2">
          {(["filter", "nat", "mangle"] as const).map((t) => (
            <button
              key={t}
              onClick={() => { setTab(t); setChainFilter(""); }}
              className={cn(
                "rounded-md px-3 py-1.5 text-sm font-medium capitalize transition-colors",
                tab === t
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted text-muted-foreground hover:text-foreground",
              )}
            >
              {t}
            </button>
          ))}
        </div>
        {chains.length > 0 && (
          <select
            value={chainFilter}
            onChange={(e) => setChainFilter(e.target.value)}
            className="rounded-md border border-border bg-background px-2 py-1.5 text-sm text-foreground"
          >
            <option value="">All chains</option>
            {chains.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        )}
      </div>

      {query.isLoading && <LoadingSpinner />}
      {query.error && (
        <ErrorDisplay message={query.error.message} onRetry={() => query.refetch()} />
      )}

      {tab === "filter" && filter.data && (
        <DataTable columns={filterColumns} data={filteredData as Numbered<FilterRule>[]} rowKey={(r) => r[".id"]} searchable searchPlaceholder="Search filter rules..." rowStyle={filterHeatmap as (row: Numbered<FilterRule>) => CSSProperties | undefined} />
      )}
      {tab === "nat" && nat.data && (
        <DataTable columns={natColumns} data={filteredData as Numbered<NatRule>[]} rowKey={(r) => r[".id"]} searchable searchPlaceholder="Search NAT rules..." rowStyle={natHeatmap as (row: Numbered<NatRule>) => CSSProperties | undefined} />
      )}
      {tab === "mangle" && mangle.data && (
        <DataTable columns={mangleColumns} data={filteredData as Numbered<MangleRule>[]} rowKey={(r) => r[".id"]} searchable searchPlaceholder="Search mangle rules..." rowStyle={mangleHeatmap as (row: Numbered<MangleRule>) => CSSProperties | undefined} />
      )}
    </PageShell>
  );
}
