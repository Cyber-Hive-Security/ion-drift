import { useState, useMemo } from "react";
import { useConnectionsPage } from "@/api/queries";
import { PageShell } from "@/components/layout/page-shell";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { DataTable, type Column } from "@/components/data-table";
import { formatBytes, formatNumber } from "@/lib/format";
import { countryFlag, isPrivateIp } from "@/lib/country";
import { cn } from "@/lib/utils";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import type { ConnectionEntry, ConnectionsPageResponse } from "@/api/types";

const PROTOCOL_COLORS: Record<string, string> = {
  tcp: "oklch(0.65 0.18 250)",
  udp: "oklch(0.65 0.2 145)",
  icmp: "oklch(0.65 0.2 60)",
  other: "oklch(0.55 0.05 285)",
};

type FilterMode = "all" | "flagged" | "tcp" | "udp" | "external";

// ── Summary Bar ──────────────────────────────────────────────────

function SummaryBar({ data }: { data: ConnectionsPageResponse }) {
  const { summary } = data;
  const protoData = Object.entries(summary.by_protocol).map(([name, value]) => ({
    name,
    value,
    color: PROTOCOL_COLORS[name] ?? PROTOCOL_COLORS.other,
  }));

  const stateEntries = Object.entries(summary.by_state)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 6);

  return (
    <div className="mb-4 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
      {/* Total */}
      <div className="rounded-lg border border-border bg-card p-4">
        <p className="text-xs font-medium text-muted-foreground">
          Active Connections
        </p>
        <p className="mt-1 text-3xl font-bold">{formatNumber(summary.total)}</p>
        {summary.max_entries != null && (
          <p className="mt-1 text-xs text-muted-foreground">
            of {formatNumber(summary.max_entries)} max
          </p>
        )}
      </div>

      {/* Protocol donut */}
      <div className="rounded-lg border border-border bg-card p-4">
        <p className="mb-2 text-xs font-medium text-muted-foreground">
          By Protocol
        </p>
        <div className="flex items-center gap-3">
          <PieChart width={80} height={80}>
            <Pie
              data={protoData}
              cx={40}
              cy={40}
              innerRadius={22}
              outerRadius={36}
              dataKey="value"
              strokeWidth={0}
              isAnimationActive={false}
            >
              {protoData.map((entry) => (
                <Cell key={entry.name} fill={entry.color} />
              ))}
            </Pie>
          </PieChart>
          <div className="flex flex-col gap-1 text-xs">
            {protoData.map((p) => (
              <span key={p.name} className="flex items-center gap-1.5">
                <span
                  className="inline-block h-2 w-2 rounded-full"
                  style={{ backgroundColor: p.color }}
                />
                <span className="uppercase">{p.name}</span>
                <span className="text-muted-foreground">
                  {formatNumber(p.value)}
                </span>
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Flagged */}
      <div className="rounded-lg border border-border bg-card p-4">
        <p className="text-xs font-medium text-muted-foreground">
          Flagged Countries
        </p>
        {summary.flagged_count > 0 ? (
          <div className="mt-1 flex items-center gap-2">
            <span className="relative flex h-3 w-3">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-75" />
              <span className="relative inline-flex h-3 w-3 rounded-full bg-red-500" />
            </span>
            <span className="text-2xl font-bold text-red-500">
              {summary.flagged_count}
            </span>
          </div>
        ) : (
          <p className="mt-1 text-2xl font-bold text-emerald-500">0</p>
        )}
        <p className="mt-1 text-xs text-muted-foreground">
          {summary.flagged_count > 0
            ? `${summary.flagged_count} connections to flagged countries`
            : "No flagged connections"}
        </p>
      </div>

      {/* States breakdown */}
      <div className="rounded-lg border border-border bg-card p-4">
        <p className="mb-2 text-xs font-medium text-muted-foreground">
          Connection States
        </p>
        <div className="flex flex-col gap-1 text-xs">
          {stateEntries.map(([state, count]) => (
            <div key={state} className="flex justify-between">
              <span className="font-mono">{state}</span>
              <span className="text-muted-foreground">
                {formatNumber(count)}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Top Talkers ──────────────────────────────────────────────────

function TopTalkers({ connections }: { connections: ConnectionEntry[] }) {
  const topDstByCount = useMemo(() => {
    const counts = new Map<string, number>();
    for (const c of connections) {
      counts.set(c.dst_address, (counts.get(c.dst_address) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);
  }, [connections]);

  const topDstByBytes = useMemo(() => {
    const sums = new Map<string, number>();
    for (const c of connections) {
      sums.set(
        c.dst_address,
        (sums.get(c.dst_address) ?? 0) + c.orig_bytes + c.repl_bytes,
      );
    }
    return [...sums.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);
  }, [connections]);

  const topSrcByCount = useMemo(() => {
    const counts = new Map<string, number>();
    for (const c of connections) {
      if (isPrivateIp(c.src_address)) {
        counts.set(c.src_address, (counts.get(c.src_address) ?? 0) + 1);
      }
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);
  }, [connections]);

  return (
    <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
      <TalkerPanel title="Top Dst IPs (by count)" entries={topDstByCount} format={(v) => `${v}`} />
      <TalkerPanel title="Top Dst IPs (by bytes)" entries={topDstByBytes} format={formatBytes} />
      <TalkerPanel title="Top Src IPs (by count)" entries={topSrcByCount} format={(v) => `${v}`} />
    </div>
  );
}

function TalkerPanel({
  title,
  entries,
  format,
}: {
  title: string;
  entries: [string, number][];
  format: (v: number) => string;
}) {
  const max = entries[0]?.[1] ?? 1;
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <p className="mb-3 text-xs font-medium text-muted-foreground">{title}</p>
      <div className="flex flex-col gap-1.5">
        {entries.map(([ip, value]) => (
          <div key={ip} className="flex items-center gap-2 text-xs">
            <span className="w-28 shrink-0 truncate font-mono">{ip}</span>
            <div className="relative h-3 flex-1 rounded bg-muted">
              <div
                className="h-3 rounded bg-primary/40"
                style={{ width: `${(value / max) * 100}%` }}
              />
            </div>
            <span className="w-16 shrink-0 text-right text-muted-foreground">
              {format(value)}
            </span>
          </div>
        ))}
        {entries.length === 0 && (
          <p className="text-xs text-muted-foreground">No data</p>
        )}
      </div>
    </div>
  );
}

// ── Geo Distribution ─────────────────────────────────────────────

function GeoDistribution({ connections }: { connections: ConnectionEntry[] }) {
  const countryData = useMemo(() => {
    const counts = new Map<string, { name: string; count: number; flagged: boolean }>();
    for (const c of connections) {
      for (const country of [c.src_country, c.dst_country]) {
        if (country) {
          const existing = counts.get(country.code);
          if (existing) {
            existing.count++;
          } else {
            counts.set(country.code, {
              name: country.name,
              count: 1,
              flagged: false, // will check below
            });
          }
        }
      }
      // Mark flagged
      if (c.flagged) {
        if (c.src_country) {
          const e = counts.get(c.src_country.code);
          if (e) e.flagged = true;
        }
        if (c.dst_country) {
          const e = counts.get(c.dst_country.code);
          if (e) e.flagged = true;
        }
      }
    }
    return [...counts.entries()]
      .map(([code, d]) => ({ code, ...d }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 20);
  }, [connections]);

  if (countryData.length === 0) return null;

  return (
    <div className="mt-4 rounded-lg border border-border bg-card p-4">
      <p className="mb-3 text-xs font-medium text-muted-foreground">
        Connections by Country
      </p>
      <ResponsiveContainer width="100%" height={Math.max(200, countryData.length * 24)}>
        <BarChart data={countryData} layout="vertical" margin={{ left: 60 }}>
          <XAxis type="number" tick={{ fontSize: 10, fill: "oklch(0.55 0.01 285)" }} />
          <YAxis
            type="category"
            dataKey="code"
            tick={{ fontSize: 11, fill: "oklch(0.75 0.01 285)" }}
            width={50}
            tickFormatter={(code: string) => `${countryFlag(code)} ${code}`}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "oklch(0.175 0.015 285)",
              border: "1px solid oklch(0.3 0.015 285)",
              borderRadius: "6px",
              color: "oklch(0.95 0.01 285)",
              fontSize: "12px",
            }}
            formatter={(value: number, _: string, props: { payload?: { name?: string } }) => [
              formatNumber(value),
              props.payload?.name ?? "",
            ]}
          />
          <Bar dataKey="count" isAnimationActive={false}>
            {countryData.map((entry) => (
              <Cell
                key={entry.code}
                fill={entry.flagged ? "oklch(0.6 0.2 25)" : "oklch(0.55 0.15 250)"}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── Connections Table ─────────────────────────────────────────────

const connectionColumns: Column<ConnectionEntry>[] = [
  {
    key: "protocol",
    header: "Proto",
    render: (r) => (
      <span className="rounded bg-muted px-1.5 py-0.5 text-xs font-medium uppercase">
        {r.protocol}
      </span>
    ),
    sortValue: (r) => r.protocol,
  },
  {
    key: "src",
    header: "Src Address",
    render: (r) => (
      <span className="font-mono text-xs">
        {r.src_address}
        {r.src_port ? `:${r.src_port}` : ""}
      </span>
    ),
    sortValue: (r) => r.src_address,
  },
  {
    key: "dst",
    header: "Dst Address",
    render: (r) => (
      <span className="font-mono text-xs">
        {r.dst_address}
        {r.dst_port ? `:${r.dst_port}` : ""}
      </span>
    ),
    sortValue: (r) => r.dst_address,
  },
  {
    key: "state",
    header: "State",
    render: (r) => (
      <span className="text-xs">{r.tcp_state ?? "—"}</span>
    ),
    sortValue: (r) => r.tcp_state ?? "",
  },
  {
    key: "orig_bytes",
    header: "Orig Bytes",
    render: (r) => <span className="text-xs">{formatBytes(r.orig_bytes, 1)}</span>,
    sortValue: (r) => r.orig_bytes,
  },
  {
    key: "repl_bytes",
    header: "Reply Bytes",
    render: (r) => <span className="text-xs">{formatBytes(r.repl_bytes, 1)}</span>,
    sortValue: (r) => r.repl_bytes,
  },
  {
    key: "timeout",
    header: "Timeout",
    render: (r) => <span className="text-xs">{r.timeout ?? "—"}</span>,
  },
  {
    key: "country",
    header: "Country",
    render: (r) => {
      const dst = r.dst_country;
      if (!dst) return <span className="text-xs text-muted-foreground">—</span>;
      return (
        <span className="text-xs">
          {countryFlag(dst.code)} {dst.code}
        </span>
      );
    },
    sortValue: (r) => r.dst_country?.code ?? "ZZZ",
  },
  {
    key: "flagged",
    header: "Flag",
    render: (r) =>
      r.flagged ? (
        <span className="inline-flex rounded-full bg-red-500/15 px-2 py-0.5 text-xs font-medium text-red-500">
          Flagged
        </span>
      ) : null,
    sortValue: (r) => (r.flagged ? 0 : 1),
  },
];

// ── Main Page ────────────────────────────────────────────────────

export function ConnectionsPage() {
  const { data, isLoading, error, refetch, isFetching } = useConnectionsPage();
  const [filter, setFilter] = useState<FilterMode>("all");

  const filteredConnections = useMemo(() => {
    if (!data) return [];
    let conns = data.connections;
    switch (filter) {
      case "flagged":
        conns = conns.filter((c) => c.flagged);
        break;
      case "tcp":
        conns = conns.filter((c) => c.protocol === "tcp");
        break;
      case "udp":
        conns = conns.filter((c) => c.protocol === "udp");
        break;
      case "external":
        conns = conns.filter(
          (c) => !isPrivateIp(c.dst_address) || !isPrivateIp(c.src_address),
        );
        break;
    }
    // Sort flagged to top by default
    return [...conns].sort((a, b) => {
      if (a.flagged && !b.flagged) return -1;
      if (!a.flagged && b.flagged) return 1;
      return 0;
    });
  }, [data, filter]);

  if (isLoading) return <LoadingSpinner />;
  if (error)
    return (
      <PageShell title="Connections">
        <ErrorDisplay message={error.message} onRetry={() => refetch()} />
      </PageShell>
    );
  if (!data) return null;

  const filters: { mode: FilterMode; label: string }[] = [
    { mode: "all", label: "All" },
    { mode: "flagged", label: "Flagged Only" },
    { mode: "tcp", label: "TCP" },
    { mode: "udp", label: "UDP" },
    { mode: "external", label: "External Only" },
  ];

  return (
    <PageShell
      title="Connections"
      onRefresh={() => refetch()}
      isRefreshing={isFetching}
    >
      <SummaryBar data={data} />

      {/* Filter buttons */}
      <div className="mb-3 flex gap-2">
        {filters.map((f) => (
          <button
            key={f.mode}
            onClick={() => setFilter(f.mode)}
            className={cn(
              "rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
              filter === f.mode
                ? "bg-primary text-primary-foreground"
                : "bg-muted text-muted-foreground hover:text-foreground",
              f.mode === "flagged" &&
                data.summary.flagged_count > 0 &&
                filter !== "flagged" &&
                "border border-red-500/30",
            )}
          >
            {f.label}
            {f.mode === "flagged" && data.summary.flagged_count > 0 && (
              <span className="ml-1.5 inline-flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[10px] text-white">
                {data.summary.flagged_count}
              </span>
            )}
          </button>
        ))}
      </div>

      <DataTable
        columns={connectionColumns}
        data={filteredConnections}
        rowKey={(r) => r.id}
        searchable
        searchPlaceholder="Search connections..."
        defaultSort={{ key: "flagged" }}
        rowStyle={(r) =>
          r.flagged
            ? { borderLeft: "3px solid oklch(0.6 0.2 25)" }
            : undefined
        }
      />

      <TopTalkers connections={data.connections} />
      <GeoDistribution connections={data.connections} />
    </PageShell>
  );
}
