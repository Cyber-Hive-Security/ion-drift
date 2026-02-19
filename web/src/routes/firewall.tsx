import { useState, useMemo } from "react";
import {
  useFirewallFilter,
  useFirewallNat,
  useFirewallMangle,
} from "@/api/queries";
import { DataTable, type Column } from "@/components/data-table";
import { PageShell } from "@/components/layout/page-shell";
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

const filterColumns: Column<FilterRule>[] = [
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
];

const natColumns: Column<NatRule>[] = [
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

const mangleColumns: Column<MangleRule>[] = [
  { key: "chain", header: "Chain", render: (r) => r.chain, sortValue: (r) => r.chain },
  { key: "action", header: "Action", render: (r) => <span className="rounded bg-muted px-1.5 py-0.5 text-xs font-medium">{r.action}</span> },
  { key: "src", header: "Src", render: (r) => <RuleCell value={r["src-address"]} /> },
  { key: "dst", header: "Dst", render: (r) => <RuleCell value={r["dst-address"]} /> },
  { key: "pkt-mark", header: "Pkt Mark", render: (r) => <RuleCell value={r["new-packet-mark"]} /> },
  { key: "conn-mark", header: "Conn Mark", render: (r) => <RuleCell value={r["new-connection-mark"]} /> },
  { key: "bytes", header: "Bytes", render: (r) => (r.bytes != null ? formatBytes(r.bytes, 1) : "—"), sortValue: (r) => r.bytes ?? 0 },
  { key: "comment", header: "Comment", render: (r) => r.comment ?? "" },
];

type Tab = "filter" | "nat" | "mangle";

export function FirewallPage() {
  const [tab, setTab] = useState<Tab>("filter");
  const [chainFilter, setChainFilter] = useState("");

  const filter = useFirewallFilter();
  const nat = useFirewallNat();
  const mangle = useFirewallMangle();

  const queries = { filter, nat, mangle };
  const query = queries[tab];

  // Get unique chains for the current tab
  const chains = useMemo(() => {
    const data = query.data as Array<{ chain: string }> | undefined;
    if (!data) return [];
    return [...new Set(data.map((r) => r.chain))].sort();
  }, [query.data]);

  // Filter data by chain
  const filteredData = useMemo(() => {
    if (!query.data) return [];
    if (!chainFilter) return query.data;
    return (query.data as Array<{ chain: string }>).filter(
      (r) => r.chain === chainFilter,
    );
  }, [query.data, chainFilter]);

  return (
    <PageShell
      title="Firewall"
      onRefresh={() => query.refetch()}
      isRefreshing={query.isFetching}
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
        <DataTable columns={filterColumns} data={filteredData as FilterRule[]} rowKey={(r) => r[".id"]} />
      )}
      {tab === "nat" && nat.data && (
        <DataTable columns={natColumns} data={filteredData as NatRule[]} rowKey={(r) => r[".id"]} />
      )}
      {tab === "mangle" && mangle.data && (
        <DataTable columns={mangleColumns} data={filteredData as MangleRule[]} rowKey={(r) => r[".id"]} />
      )}
    </PageShell>
  );
}
