import { useState, useMemo, useCallback, useEffect } from "react";
import { useSearch } from "@tanstack/react-router";
import {
  useConnectionsPage,
  useConnectionsHistory,
  useGeoSummary,
  useCitySummary,
  useCountrySummary,
  useSnapshots,
  useSnapshot,
  useMapConfig,
} from "@/api/queries";
import { PageShell } from "@/components/layout/page-shell";
import { ConnectionsHelp } from "@/components/help-content";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { DataTable, type Column } from "@/components/data-table";
import { WorldMap } from "@/features/world-map/world-map";
import { formatBytes, formatNumber } from "@/lib/format";
import { countryFlag, isPrivateIp, vlanLabel } from "@/lib/country";
import { useVlanLookup } from "@/hooks/use-vlan-lookup";
import { cn } from "@/lib/utils";
import { portLabel } from "@/lib/services";
import { ChevronDown, ChevronRight, Filter, Globe, Microscope, Network, X } from "lucide-react";
import { Link } from "@tanstack/react-router";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import type { ConnectionEntry, ConnectionsPageResponse, CountrySummary, GeoSummaryEntry } from "@/api/types";

// ── Tab definitions ─────────────────────────────────────────

type ConnTabId = "world-map" | "connections";

const CONN_TABS: { id: ConnTabId; label: string; icon: typeof Globe }[] = [
  { id: "world-map", label: "World Map", icon: Globe },
  { id: "connections", label: "Connections", icon: Network },
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

// ── Country stats table columns ──────────────────────────────

const countryColumns: Column<GeoSummaryEntry>[] = [
  {
    key: "country",
    header: "Country",
    render: (r) => (
      <span className="text-xs">
        {countryFlag(r.country_code)}{" "}
        <span className="font-medium">{r.country}</span>
      </span>
    ),
    sortValue: (r) => r.country,
  },
  {
    key: "code",
    header: "Code",
    render: (r) => (
      <span className="font-mono text-xs text-muted-foreground">
        {r.country_code}
      </span>
    ),
    sortValue: (r) => r.country_code,
  },
  {
    key: "connections",
    header: "Connections",
    render: (r) => (
      <span className="font-mono text-xs">{formatNumber(r.connection_count)}</span>
    ),
    sortValue: (r) => r.connection_count,
  },
  {
    key: "sources",
    header: "Sources",
    render: (r) => (
      <span className="font-mono text-xs">{formatNumber(r.unique_sources)}</span>
    ),
    sortValue: (r) => r.unique_sources,
  },
  {
    key: "destinations",
    header: "Destinations",
    render: (r) => (
      <span className="font-mono text-xs">{formatNumber(r.unique_destinations)}</span>
    ),
    sortValue: (r) => r.unique_destinations,
  },
  {
    key: "tx",
    header: "TX",
    render: (r) => (
      <span className="font-mono text-xs">{formatBytes(r.total_tx)}</span>
    ),
    sortValue: (r) => r.total_tx,
  },
  {
    key: "rx",
    header: "RX",
    render: (r) => (
      <span className="font-mono text-xs">{formatBytes(r.total_rx)}</span>
    ),
    sortValue: (r) => r.total_rx,
  },
  {
    key: "flagged",
    header: "Flagged",
    render: (r) =>
      r.flagged_count > 0 ? (
        <span className="font-mono text-xs text-destructive">{formatNumber(r.flagged_count)}</span>
      ) : (
        <span className="font-mono text-xs text-muted-foreground">0</span>
      ),
    sortValue: (r) => r.flagged_count,
  },
];

const PROTOCOL_COLORS: Record<string, string> = {
  tcp: "#2FA4FF",
  udp: "#21D07A",
  icmp: "#FFC857",
  other: "#8A929D",
};

type FilterMode = "all" | "flagged" | "tcp" | "udp" | "external";
type GroupMode = "flat" | "src" | "dst" | "vlan" | "protocol";

function groupKey(conn: ConnectionEntry, mode: GroupMode): string {
  switch (mode) {
    case "src":
      return conn.src_address;
    case "dst":
      return conn.dst_address;
    case "vlan": {
      const parts = conn.src_address.split(".");
      return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}` : "other";
    }
    case "protocol":
      return conn.protocol.toUpperCase();
    default:
      return "";
  }
}

function groupLabel(key: string, conns: ConnectionEntry[], mode: GroupMode, ipToVlan?: (ip: string) => string | null): string {
  switch (mode) {
    case "src": {
      const label = isPrivateIp(key) ? vlanLabel(key, ipToVlan) : null;
      const geo = conns[0]?.src_geo;
      const parts = [key];
      if (label) parts.push(label);
      else if (geo) parts.push(`${countryFlag(geo.country_code)} ${geo.country}`);
      return parts.join(" \u00b7 ");
    }
    case "dst": {
      const label = isPrivateIp(key) ? vlanLabel(key, ipToVlan) : null;
      const geo = conns[0]?.dst_geo;
      const parts = [key];
      if (label) parts.push(label);
      else if (geo) parts.push(`${countryFlag(geo.country_code)} ${geo.country}`);
      return parts.join(" \u00b7 ");
    }
    case "vlan":
      return vlanLabel(key + ".0", ipToVlan) ?? `Subnet ${key}.0/24`;
    case "protocol":
      return key;
    default:
      return key;
  }
}

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
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-destructive opacity-75" />
              <span className="relative inline-flex h-3 w-3 rounded-full bg-destructive" />
            </span>
            <span className="text-2xl font-bold text-destructive">
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

function TopTalkers({
  connections,
  onDstClick,
  onSrcClick,
}: {
  connections: ConnectionEntry[];
  onDstClick?: (ip: string) => void;
  onSrcClick?: (ip: string) => void;
}) {
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
    <div className="mb-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
      <TalkerPanel title="Top Dst IPs (by count)" entries={topDstByCount} format={(v) => `${v}`} onEntryClick={onDstClick} />
      <TalkerPanel title="Top Dst IPs (by bytes)" entries={topDstByBytes} format={formatBytes} onEntryClick={onDstClick} />
      <TalkerPanel title="Top Src IPs (by count)" entries={topSrcByCount} format={(v) => `${v}`} onEntryClick={onSrcClick} />
    </div>
  );
}

function TalkerPanel({
  title,
  entries,
  format,
  onEntryClick,
}: {
  title: string;
  entries: [string, number][];
  format: (v: number) => string;
  onEntryClick?: (value: string) => void;
}) {
  const max = entries[0]?.[1] ?? 1;
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <p className="mb-3 text-xs font-medium text-muted-foreground">{title}</p>
      <div className="flex flex-col gap-1.5">
        {entries.map(([ip, value]) => (
          <div
            key={ip}
            className={cn(
              "flex items-center gap-2 text-xs",
              onEntryClick && "cursor-pointer rounded px-1 -mx-1 hover:bg-muted/50 transition-colors",
            )}
            onClick={onEntryClick ? () => onEntryClick(ip) : undefined}
          >
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

function GeoDistribution({
  connections,
  onCountryClick,
}: {
  connections: ConnectionEntry[];
  onCountryClick?: (countryCode: string) => void;
}) {
  const countryData = useMemo(() => {
    const counts = new Map<string, { name: string; count: number; flagged: boolean }>();
    for (const c of connections) {
      for (const geo of [c.src_geo, c.dst_geo]) {
        if (geo) {
          const existing = counts.get(geo.country_code);
          if (existing) {
            existing.count++;
          } else {
            counts.set(geo.country_code, {
              name: geo.country,
              count: 1,
              flagged: false, // will check below
            });
          }
        }
      }
      // Mark flagged
      if (c.flagged) {
        if (c.src_geo) {
          const e = counts.get(c.src_geo.country_code);
          if (e) e.flagged = true;
        }
        if (c.dst_geo) {
          const e = counts.get(c.dst_geo.country_code);
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
          <XAxis type="number" tick={{ fontSize: 10, fill: "#8A929D" }} />
          <YAxis
            type="category"
            dataKey="code"
            tick={{ fontSize: 11, fill: "#9AA6B2" }}
            width={50}
            tickFormatter={(code: string) => `${countryFlag(code)} ${code}`}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "#2C3038",
              border: "1px solid #444B55",
              borderRadius: "6px",
              color: "#E6EDF3",
              fontSize: "12px",
            }}
            formatter={(value: number, _: string, props: { payload?: { name?: string } }) => [
              formatNumber(value),
              props.payload?.name ?? "",
            ]}
          />
          <Bar
            dataKey="count"
            isAnimationActive={false}
            cursor={onCountryClick ? "pointer" : undefined}
            onClick={onCountryClick ? (_: unknown, index: number) => {
              const entry = countryData[index];
              if (entry) onCountryClick(entry.code);
            } : undefined}
          >
            {countryData.map((entry) => (
              <Cell
                key={entry.code}
                fill={entry.flagged ? "#FF4D4F" : "#2FA4FF"}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── Connections Table ─────────────────────────────────────────────

function connectionColumns(ipToVlan?: (ip: string) => string | null): Column<ConnectionEntry>[] { return [
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
    key: "geo",
    header: "Location",
    render: (r) => {
      const geo = r.dst_geo;
      if (geo) {
        const parts = [countryFlag(geo.country_code), geo.country];
        if (geo.city) parts.push(`\u00b7 ${geo.city}`);
        if (geo.isp) parts.push(`\u00b7 ${geo.isp}`);
        return (
          <span className="text-xs" title={[geo.country, geo.city, geo.org, geo.asn].filter(Boolean).join(" \u00b7 ")}>
            {parts.join(" ")}
          </span>
        );
      }
      // Private IP — show VLAN label
      const label = vlanLabel(r.dst_address, ipToVlan);
      if (label) {
        return <span className="text-xs text-muted-foreground">{label}</span>;
      }
      return <span className="text-xs text-muted-foreground">—</span>;
    },
    sortValue: (r) => r.dst_geo?.country_code ?? "ZZZ",
  },
  {
    key: "flagged",
    header: "Flag",
    render: (r) =>
      r.flagged ? (
        <span className="inline-flex rounded-full bg-red-500/15 px-2 py-0.5 text-xs font-medium text-destructive">
          Flagged
        </span>
      ) : null,
    sortValue: (r) => (r.flagged ? 0 : 1),
  },
]; }

// ── Grouped Connections View ─────────────────────────────────────

interface GroupEntry {
  key: string;
  label: string;
  connections: ConnectionEntry[];
  totalOrig: number;
  totalRepl: number;
  flaggedCount: number;
}

function GroupedConnectionsView({
  connections,
  groupMode,
  columns,
  rowStyle,
}: {
  connections: ConnectionEntry[];
  groupMode: Exclude<GroupMode, "flat">;
  columns: Column<ConnectionEntry>[];
  rowStyle?: (row: ConnectionEntry) => React.CSSProperties | undefined;
}) {
  const vlanLookup = useVlanLookup();
  const groups = useMemo(() => {
    const map = new Map<string, ConnectionEntry[]>();
    for (const conn of connections) {
      const k = groupKey(conn, groupMode);
      const arr = map.get(k);
      if (arr) arr.push(conn);
      else map.set(k, [conn]);
    }
    const entries: GroupEntry[] = [];
    for (const [k, conns] of map) {
      let totalOrig = 0;
      let totalRepl = 0;
      let flaggedCount = 0;
      for (const c of conns) {
        totalOrig += c.orig_bytes;
        totalRepl += c.repl_bytes;
        if (c.flagged) flaggedCount++;
      }
      entries.push({
        key: k,
        label: groupLabel(k, conns, groupMode, vlanLookup.ipToVlanLabel),
        connections: conns,
        totalOrig,
        totalRepl,
        flaggedCount,
      });
    }
    // Sort by total bytes descending (heaviest talkers first)
    entries.sort((a, b) => b.totalOrig + b.totalRepl - (a.totalOrig + a.totalRepl));
    return entries;
  }, [connections, groupMode]);

  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const toggleGroup = useCallback((key: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  const allExpanded = expanded.size === groups.length;
  const toggleAll = useCallback(() => {
    if (allExpanded) {
      setExpanded(new Set());
    } else {
      setExpanded(new Set(groups.map((g) => g.key)));
    }
  }, [allExpanded, groups]);

  return (
    <div>
      <div className="mb-2 flex items-center justify-between">
        <span className="text-xs text-muted-foreground">
          {groups.length} groups \u00b7 {connections.length} connections
        </span>
        <button
          onClick={toggleAll}
          className="text-xs text-muted-foreground hover:text-foreground"
        >
          {allExpanded ? "Collapse All" : "Expand All"}
        </button>
      </div>

      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/50">
              <th className="w-8 px-2 py-2" />
              {columns.map((col) => (
                <th
                  key={col.key}
                  className="px-3 py-2 text-left font-medium text-muted-foreground"
                >
                  {col.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {groups.map((group) => {
              const isOpen = expanded.has(group.key);
              return (
                <GroupRows
                  key={group.key}
                  group={group}
                  isOpen={isOpen}
                  onToggle={() => toggleGroup(group.key)}
                  columns={columns}
                  rowStyle={rowStyle}
                />
              );
            })}
            {groups.length === 0 && (
              <tr>
                <td
                  colSpan={columns.length + 1}
                  className="px-3 py-8 text-center text-muted-foreground"
                >
                  No connections
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function GroupRows({
  group,
  isOpen,
  onToggle,
  columns,
  rowStyle,
}: {
  group: GroupEntry;
  isOpen: boolean;
  onToggle: () => void;
  columns: Column<ConnectionEntry>[];
  rowStyle?: (row: ConnectionEntry) => React.CSSProperties | undefined;
}) {
  return (
    <>
      <tr
        className="cursor-pointer border-b border-border bg-muted/30 hover:bg-muted/50"
        onClick={onToggle}
      >
        <td className="px-2 py-2 text-muted-foreground">
          {isOpen ? (
            <ChevronDown className="h-4 w-4" />
          ) : (
            <ChevronRight className="h-4 w-4" />
          )}
        </td>
        <td colSpan={columns.length} className="px-3 py-2">
          <div className="flex items-center gap-3">
            <span className="font-medium">{group.label}</span>
            <span className="text-xs text-muted-foreground">
              {group.connections.length} conn{group.connections.length !== 1 ? "s" : ""}
            </span>
            <span className="text-xs text-muted-foreground">
              {formatBytes(group.totalOrig, 1)} \u2191
            </span>
            <span className="text-xs text-muted-foreground">
              {formatBytes(group.totalRepl, 1)} \u2193
            </span>
            {group.flaggedCount > 0 && (
              <span className="inline-flex rounded-full bg-red-500/15 px-2 py-0.5 text-[10px] font-medium text-destructive">
                {group.flaggedCount} flagged
              </span>
            )}
          </div>
        </td>
      </tr>
      {isOpen &&
        group.connections.map((conn) => (
          <tr
            key={conn.id}
            className="border-b border-border/50 hover:bg-muted/20"
            style={rowStyle?.(conn)}
          >
            <td />
            {columns.map((col) => (
              <td key={col.key} className="px-3 py-2">
                {col.render(conn)}
              </td>
            ))}
          </tr>
        ))}
    </>
  );
}

// ── Column Filter Dropdown ───────────────────────────────────────

interface FilterOption {
  value: string;
  label: string;
  count: number;
}

function ColumnFilterDropdown({
  options,
  selected,
  onSelectionChange,
  onClose,
}: {
  options: FilterOption[];
  selected: Set<string>;
  onSelectionChange: (selected: Set<string>) => void;
  onClose: () => void;
}) {
  const [search, setSearch] = useState("");
  const filtered = search
    ? options.filter((o) => o.label.toLowerCase().includes(search.toLowerCase()))
    : options;

  const allSelected = filtered.every((o) => selected.has(o.value));

  const toggleAll = () => {
    const next = new Set(selected);
    if (allSelected) {
      for (const o of filtered) next.delete(o.value);
    } else {
      for (const o of filtered) next.add(o.value);
    }
    onSelectionChange(next);
  };

  const toggleOne = (value: string) => {
    const next = new Set(selected);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    onSelectionChange(next);
  };

  return (
    <div
      className="absolute top-full left-0 z-50 mt-1 w-56 rounded-lg border border-border bg-card shadow-lg"
      onClick={(e) => e.stopPropagation()}
    >
      <div className="border-b border-border p-2">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search..."
          className="w-full rounded border border-border bg-background px-2 py-1 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none"
          autoFocus
        />
      </div>
      <div className="max-h-48 overflow-y-auto p-1">
        <label className="flex cursor-pointer items-center gap-2 rounded px-2 py-1 text-xs hover:bg-muted/50">
          <input
            type="checkbox"
            checked={allSelected}
            onChange={toggleAll}
            className="rounded"
          />
          <span className="font-medium">Select All</span>
        </label>
        {filtered.map((opt) => (
          <label
            key={opt.value}
            className="flex cursor-pointer items-center gap-2 rounded px-2 py-1 text-xs hover:bg-muted/50"
          >
            <input
              type="checkbox"
              checked={selected.has(opt.value)}
              onChange={() => toggleOne(opt.value)}
              className="rounded"
            />
            <span className="flex-1 truncate">{opt.label}</span>
            <span className="text-muted-foreground">{opt.count}</span>
          </label>
        ))}
        {filtered.length === 0 && (
          <p className="px-2 py-2 text-xs text-muted-foreground">No matches</p>
        )}
      </div>
      <div className="flex justify-between border-t border-border p-2">
        <button
          onClick={() => onSelectionChange(new Set())}
          className="text-xs text-muted-foreground hover:text-foreground"
        >
          Clear
        </button>
        <button
          onClick={onClose}
          className="rounded bg-primary px-3 py-1 text-xs font-medium text-primary-foreground"
        >
          Apply
        </button>
      </div>
    </div>
  );
}

/** Compute top-N filter options for a connection field. */
function computeFilterOptions(
  connections: ConnectionEntry[],
  field: string,
): FilterOption[] {
  const counts = new Map<string, number>();
  for (const c of connections) {
    let value: string;
    switch (field) {
      case "src":
        value = c.src_address;
        break;
      case "dst":
        value = c.dst_address;
        break;
      case "dst_port":
        value = c.dst_port || "";
        break;
      case "protocol":
        value = c.protocol.toUpperCase();
        break;
      case "state":
        value = c.tcp_state ?? "none";
        break;
      case "country":
        value = c.dst_geo?.country_code ?? "";
        break;
      default:
        value = "";
    }
    if (value) counts.set(value, (counts.get(value) ?? 0) + 1);
  }

  const entries = [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15);

  return entries.map(([value, count]) => {
    let label = value;
    if (field === "dst_port") label = portLabel(value);
    else if (field === "country") {
      const geo = connections.find((c) => c.dst_geo?.country_code === value)?.dst_geo;
      label = geo ? `${countryFlag(geo.country_code)} ${geo.country}` : value;
    }
    return { value, label, count };
  });
}

// ── Connection History Chart ─────────────────────────────────────

type HistoryRange = "24h" | "7d";

function ConnectionHistoryChart() {
  const [range, setRange] = useState<HistoryRange>("24h");
  const history = useConnectionsHistory(range);
  const data = history.data ?? [];

  const chartData = data.map((p) => ({
    time:
      range === "24h"
        ? new Date(p.timestamp * 1000).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
          })
        : new Date(p.timestamp * 1000).toLocaleDateString([], {
            month: "short",
            day: "numeric",
            hour: "2-digit",
          }),
    tcp: p.tcp,
    udp: p.udp,
    other: p.other,
  }));

  if (chartData.length < 2) return null;

  return (
    <div className="mb-4 rounded-lg border border-border bg-card p-4">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-sm font-medium text-muted-foreground">
          Connection History
        </h3>
        <div className="flex gap-2">
          {(["24h", "7d"] as const).map((r) => (
            <button
              key={r}
              onClick={() => setRange(r)}
              className={cn(
                "rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
                range === r
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted text-muted-foreground hover:text-foreground",
              )}
            >
              {r}
            </button>
          ))}
        </div>
      </div>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={chartData}>
          <defs>
            <linearGradient id="connTcpGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#2FA4FF" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#2FA4FF" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="connUdpGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#21D07A" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#21D07A" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="connOtherGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#8A929D" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#8A929D" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#444B55" />
          <XAxis
            dataKey="time"
            tick={{ fill: "#8A929D", fontSize: 11 }}
            interval="preserveStartEnd"
          />
          <YAxis
            tick={{ fill: "#8A929D", fontSize: 11 }}
            tickFormatter={(v: number) => formatNumber(v)}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "#2C3038",
              border: "1px solid #444B55",
              borderRadius: "6px",
              color: "#E6EDF3",
              fontSize: "12px",
            }}
            formatter={(value: number, name: string) => [
              formatNumber(value),
              name.toUpperCase(),
            ]}
          />
          <Area
            type="monotone"
            dataKey="tcp"
            stackId="1"
            stroke="#2FA4FF"
            strokeWidth={1.5}
            fill="url(#connTcpGrad)"
            isAnimationActive={false}
          />
          <Area
            type="monotone"
            dataKey="udp"
            stackId="1"
            stroke="#21D07A"
            strokeWidth={1.5}
            fill="url(#connUdpGrad)"
            isAnimationActive={false}
          />
          <Area
            type="monotone"
            dataKey="other"
            stackId="1"
            stroke="#8A929D"
            strokeWidth={1.5}
            fill="url(#connOtherGrad)"
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── Country Investigation Panel ───────────────────────────────────

function CountryInvestigationPanel({
  countryCode,
  onClose,
  onViewConnections,
}: {
  countryCode: string;
  onClose: () => void;
  onViewConnections: (code: string) => void;
}) {
  const summary = useCountrySummary(countryCode);
  const data = summary.data;

  return (
    <div className="mt-4 rounded-lg border border-primary/30 bg-card p-4">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-sm font-semibold">
          {countryFlag(countryCode)} {data?.country || countryCode} — Investigation
        </h3>
        <div className="flex items-center gap-2">
          <Link
            to="/sankey"
            search={{ country: countryCode }}
            className="inline-flex items-center gap-1 rounded-md bg-primary/10 px-2.5 py-1 text-xs font-medium text-primary hover:bg-primary/20"
          >
            <Microscope className="h-3 w-3" />
            Investigate in Sankey
          </Link>
          <button
            onClick={() => onViewConnections(countryCode)}
            className="rounded-md bg-muted px-2.5 py-1 text-xs font-medium text-muted-foreground hover:text-foreground"
          >
            View connections
          </button>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {summary.isLoading ? (
        <div className="flex h-24 items-center justify-center text-sm text-muted-foreground">Loading...</div>
      ) : !data ? (
        <div className="text-sm text-muted-foreground">No data available for this country.</div>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          {/* Summary stats */}
          <div className="space-y-2">
            <div className="text-xs text-muted-foreground">Total</div>
            <div className="text-lg font-bold">{formatNumber(data.total_connections)} connections</div>
            <div className="text-xs text-muted-foreground">
              {formatBytes(data.total_tx)} sent · {formatBytes(data.total_rx)} received
            </div>
          </div>

          {/* Top devices */}
          <div>
            <div className="mb-1.5 text-xs font-medium text-muted-foreground">Top Devices</div>
            <div className="space-y-1">
              {data.top_devices.slice(0, 5).map((d) => (
                <div key={d.src_mac} className="flex items-center justify-between text-xs">
                  <Link
                    to="/sankey"
                    search={{ mac: d.src_mac, country: countryCode }}
                    className="truncate font-mono text-primary hover:underline"
                    title={d.src_mac}
                  >
                    {d.hostname || d.src_ip}
                  </Link>
                  <span className="ml-2 text-muted-foreground">{formatNumber(d.connection_count)}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Top destinations */}
          <div>
            <div className="mb-1.5 text-xs font-medium text-muted-foreground">Top Destinations</div>
            <div className="space-y-1">
              {data.top_destinations.slice(0, 5).map((d) => (
                <div key={d.dst_ip} className="flex items-center justify-between text-xs">
                  <span className="truncate font-mono" title={d.dst_ip}>
                    {d.org || d.dst_ip}
                  </span>
                  <span className="ml-2 text-muted-foreground">{formatNumber(d.connection_count)}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Top ports */}
          {data.top_ports.length > 0 && (
            <div>
              <div className="mb-1.5 text-xs font-medium text-muted-foreground">Top Ports</div>
              <div className="space-y-1">
                {data.top_ports.slice(0, 5).map((p) => (
                  <div key={`${p.protocol}-${p.dst_port}`} className="flex items-center justify-between text-xs">
                    <span>{portLabel(p.dst_port)} ({p.protocol.toUpperCase()})</span>
                    <span className="text-muted-foreground">{formatNumber(p.connection_count)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Timeline sparkline */}
          {data.timeline.length > 1 && (
            <div className="lg:col-span-2">
              <div className="mb-1.5 text-xs font-medium text-muted-foreground">Connection Timeline</div>
              <ResponsiveContainer width="100%" height={80}>
                <AreaChart data={data.timeline}>
                  <defs>
                    <linearGradient id="countryGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="oklch(0.65 0.2 250)" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="oklch(0.65 0.2 250)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="date" tick={{ fill: "oklch(0.65 0.01 285)", fontSize: 9 }} interval="preserveStartEnd" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "oklch(0.175 0.015 285)",
                      border: "1px solid oklch(0.3 0.015 285)",
                      borderRadius: "6px",
                      color: "oklch(0.95 0.01 285)",
                      fontSize: "11px",
                    }}
                    formatter={(value: number) => [formatNumber(value), "Connections"]}
                  />
                  <Area
                    type="monotone"
                    dataKey="connection_count"
                    stroke="oklch(0.65 0.2 250)"
                    strokeWidth={1.5}
                    fill="url(#countryGrad)"
                    dot={false}
                    isAnimationActive={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main Page ────────────────────────────────────────────────────

type ColumnFilterField = "src" | "dst" | "dst_port" | "protocol" | "state" | "country" | "city";

const COLUMN_FILTER_DEFS: { field: ColumnFilterField; label: string }[] = [
  { field: "src", label: "Source" },
  { field: "dst", label: "Destination" },
  { field: "dst_port", label: "Dst Port" },
  { field: "protocol", label: "Protocol" },
  { field: "state", label: "State" },
  { field: "country", label: "Country" },
  { field: "city", label: "City" },
];

function getFilterValue(c: ConnectionEntry, field: ColumnFilterField): string {
  switch (field) {
    case "src": return c.src_address;
    case "dst": return c.dst_address;
    case "dst_port": return c.dst_port || "";
    case "protocol": return c.protocol.toUpperCase();
    case "state": return c.tcp_state ?? "none";
    case "country": return c.dst_geo?.country_code ?? "";
    case "city": return c.dst_geo?.city ?? "";
  }
}

export function ConnectionsPage() {
  const search = useSearch({ from: "/connections" });
  // If URL has filter params, start on connections tab
  const hasUrlFilters = !!(search.country || search.city || search.protocol || search.dst_port || search.src_ip || search.dst_ip);
  const [activeTab, setActiveTab] = useState<ConnTabId>(
    (search.tab as ConnTabId) || (hasUrlFilters ? "connections" : "world-map"),
  );

  const [investigateCountry, setInvestigateCountry] = useState<string | null>(search.country ?? null);

  // ── World map state ──
  const [timeRange, setTimeRange] = useState<TimeRange>("7");
  const [selectedWeek, setSelectedWeek] = useState<string | null>(null);
  const mapConfig = useMapConfig();
  const home = useMemo<[number, number] | null>(
    () =>
      mapConfig.data?.home_lon != null && mapConfig.data?.home_lat != null
        ? [mapConfig.data.home_lon, mapConfig.data.home_lat]
        : null,
    [mapConfig.data?.home_lon, mapConfig.data?.home_lat],
  );
  const homeCountry = mapConfig.data?.home_country ?? null;
  const geoSummary = useGeoSummary(Number(timeRange));
  const citySummary = useCitySummary(Number(timeRange), 50);
  const snapshots = useSnapshots();
  const worldMapSnapshot = useSnapshot(selectedWeek, "world_map");
  const availableWeeks = useMemo(
    () => (snapshots.data ?? []).map((s) => s.week),
    [snapshots.data],
  );
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
  const mapLoading =
    selectedWeek ? worldMapSnapshot.isLoading : geoSummary.isLoading;

  // ── Connections tab state ──
  const { data, isLoading, error, refetch, isFetching } = useConnectionsPage();
  const vlanLookup = useVlanLookup();
  const [filter, setFilter] = useState<FilterMode>("all");
  const [groupMode, setGroupMode] = useState<GroupMode>("flat");
  const initialFilters = useMemo(() => {
    const f: Record<string, Set<string>> = {};
    if (search.country) f.country = new Set([search.country]);
    if (search.city) f.city = new Set([search.city]);
    if (search.dst_port) f.dst_port = new Set([search.dst_port]);
    if (search.protocol) f.protocol = new Set([search.protocol]);
    if (search.src_ip) f.src = new Set([search.src_ip]);
    if (search.dst_ip) f.dst = new Set([search.dst_ip]);
    return f;
  }, []);
  const [columnFilters, setColumnFilters] = useState<Record<string, Set<string>>>(initialFilters);
  const [openFilter, setOpenFilter] = useState<ColumnFilterField | null>(null);

  // Pre-filter by mode buttons
  const modeFiltered = useMemo(() => {
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
    return conns;
  }, [data, filter]);

  // Apply column filters on top
  const filteredConnections = useMemo(() => {
    let conns = modeFiltered;
    for (const [field, selected] of Object.entries(columnFilters)) {
      if (selected.size === 0) continue;
      conns = conns.filter((c) => selected.has(getFilterValue(c, field as ColumnFilterField)));
    }
    // Sort flagged to top by default
    return [...conns].sort((a, b) => {
      if (a.flagged && !b.flagged) return -1;
      if (!a.flagged && b.flagged) return 1;
      return 0;
    });
  }, [modeFiltered, columnFilters]);

  // Compute filter options from mode-filtered data (before column filters)
  const filterOptions = useMemo(() => {
    const opts: Record<string, FilterOption[]> = {};
    for (const def of COLUMN_FILTER_DEFS) {
      opts[def.field] = computeFilterOptions(modeFiltered, def.field);
    }
    return opts;
  }, [modeFiltered]);

  const activeFilterCount = Object.values(columnFilters).filter((s) => s.size > 0).length;

  const clearAllColumnFilters = useCallback(() => {
    setColumnFilters({});
  }, []);

  const updateColumnFilter = useCallback((field: string, selected: Set<string>) => {
    setColumnFilters((prev) => ({ ...prev, [field]: selected }));
  }, []);

  const removeColumnFilter = useCallback((field: string) => {
    setColumnFilters((prev) => {
      const next = { ...prev };
      delete next[field];
      return next;
    });
  }, []);

  // Click handlers for data cards → set column filter for that IP/country
  const handleDstIpClick = useCallback((ip: string) => {
    setColumnFilters((prev) => ({ ...prev, dst: new Set([ip]) }));
  }, []);

  const handleSrcIpClick = useCallback((ip: string) => {
    setColumnFilters((prev) => ({ ...prev, src: new Set([ip]) }));
  }, []);

  const handleCountryClick = useCallback((code: string) => {
    setColumnFilters((prev) => ({ ...prev, country: new Set([code]) }));
  }, []);

  // Master reset: clear mode filter + all column filters
  const resetAllFilters = useCallback(() => {
    setFilter("all");
    setColumnFilters({});
  }, []);

  // Close filter dropdown on outside click
  useEffect(() => {
    if (!openFilter) return;
    const handler = () => setOpenFilter(null);
    // Delay to avoid closing on the same click that opened it
    const id = setTimeout(() => document.addEventListener("click", handler), 0);
    return () => {
      clearTimeout(id);
      document.removeEventListener("click", handler);
    };
  }, [openFilter]);

  // World map click → show country investigation panel
  const handleMapCountryClick = useCallback((code: string) => {
    setInvestigateCountry(code);
  }, []);

  const handleMapCityClick = useCallback((city: string, countryCode: string) => {
    setColumnFilters((prev) => ({ ...prev, country: new Set([countryCode]), city: new Set([city]) }));
    setActiveTab("connections");
  }, []);

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
      onRefresh={activeTab === "connections" ? () => refetch() : undefined}
      isRefreshing={activeTab === "connections" ? isFetching : false}
      help={<ConnectionsHelp />}
    >
      {/* Tab bar */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-1 rounded-lg border border-border bg-card p-1">
          {CONN_TABS.map(({ id, label, icon: Icon }) => (
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

        {/* Time range selector (world map tab, live mode only) */}
        {activeTab === "world-map" && !selectedWeek && (
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

      {/* Week picker (world map tab only) */}
      {activeTab === "world-map" && availableWeeks.length > 0 && (
        <div className="mb-4">
          <WeekPicker
            weeks={availableWeeks}
            selected={selectedWeek}
            onSelect={setSelectedWeek}
          />
        </div>
      )}

      {/* ── World Map Tab ── */}
      {activeTab === "world-map" && (
        <>
          <p className="mb-3 text-xs text-muted-foreground">
            Outbound connections from the network to external destinations.
          </p>
          {geoSummary.error ? (
            <ErrorDisplay message={String(geoSummary.error)} />
          ) : (
            <>
              <WorldMap
                data={mapData}
                cityData={citySummary.data ?? []}
                isLoading={mapLoading}
                onCountryClick={handleMapCountryClick}
                onCityClick={handleMapCityClick}
                timeRange={selectedWeek ?? timeRange}
                home={home}
                homeCountry={homeCountry}
              />
              {investigateCountry && (
                <CountryInvestigationPanel
                  countryCode={investigateCountry}
                  onClose={() => setInvestigateCountry(null)}
                  onViewConnections={(code) => {
                    setColumnFilters((prev) => ({ ...prev, country: new Set([code]) }));
                    setActiveTab("connections");
                    setInvestigateCountry(null);
                  }}
                />
              )}
              {mapData.length > 0 && (
                <div className="mt-6">
                  <h2 className="mb-3 text-lg font-semibold">Country Breakdown</h2>
                  <DataTable
                    columns={countryColumns}
                    data={mapData}
                    rowKey={(r) => r.country_code}
                    defaultSort={{ key: "connections", asc: false }}
                    searchable
                    searchPlaceholder="Search countries..."
                    rowStyle={(r) =>
                      r.flagged_count > 0
                        ? { borderLeft: "3px solid #FF4D4F" }
                        : undefined
                    }
                  />
                </div>
              )}
            </>
          )}
        </>
      )}

      {/* ── Connections Tab ── */}
      {activeTab === "connections" && (isLoading ? (
        <div className="flex h-96 items-center justify-center">
          <LoadingSpinner />
        </div>
      ) : error ? (
        <ErrorDisplay message={error.message} onRetry={() => refetch()} />
      ) : !data ? null : (
        <>
      <SummaryBar data={data} />

      <ConnectionHistoryChart />

      <TopTalkers
        connections={data.connections}
        onDstClick={handleDstIpClick}
        onSrcClick={handleSrcIpClick}
      />
      <GeoDistribution
        connections={data.connections}
        onCountryClick={handleCountryClick}
      />

      {/* Filter buttons */}
      <div className="mb-3 flex flex-wrap gap-2">
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
              <span className="ml-1.5 inline-flex h-4 w-4 items-center justify-center rounded-full bg-destructive text-[10px] text-destructive-foreground">
                {data.summary.flagged_count}
              </span>
            )}
          </button>
        ))}

        <span className="mx-1 self-center text-border">|</span>

        {/* Group mode selector */}
        {(
          [
            { mode: "flat", label: "Flat" },
            { mode: "src", label: "By Source" },
            { mode: "dst", label: "By Dest" },
            { mode: "vlan", label: "By VLAN" },
            { mode: "protocol", label: "By Protocol" },
          ] as { mode: GroupMode; label: string }[]
        ).map((g) => (
          <button
            key={g.mode}
            onClick={() => setGroupMode(g.mode)}
            className={cn(
              "rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors",
              groupMode === g.mode
                ? "bg-primary/80 text-primary-foreground"
                : "bg-muted/60 text-muted-foreground hover:text-foreground",
            )}
          >
            {g.label}
          </button>
        ))}
      </div>

      {/* Column filters */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground">Filter by:</span>
        {COLUMN_FILTER_DEFS.map((def) => {
          const active = (columnFilters[def.field]?.size ?? 0) > 0;
          return (
            <div key={def.field} className="relative">
              <button
                onClick={() => setOpenFilter(openFilter === def.field ? null : def.field)}
                className={cn(
                  "inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium transition-colors",
                  active
                    ? "bg-primary/20 text-primary border border-primary/40"
                    : "bg-muted/40 text-muted-foreground hover:text-foreground",
                )}
              >
                <Filter className="h-3 w-3" />
                {def.label}
                {active && (
                  <span className="ml-0.5 rounded-full bg-primary px-1.5 text-[10px] text-primary-foreground">
                    {columnFilters[def.field].size}
                  </span>
                )}
              </button>
              {openFilter === def.field && (
                <ColumnFilterDropdown
                  options={filterOptions[def.field]}
                  selected={columnFilters[def.field] ?? new Set()}
                  onSelectionChange={(s) => updateColumnFilter(def.field, s)}
                  onClose={() => setOpenFilter(null)}
                />
              )}
            </div>
          );
        })}
        {activeFilterCount > 0 && (
          <button
            onClick={clearAllColumnFilters}
            className="text-xs text-muted-foreground hover:text-foreground"
          >
            Clear All
          </button>
        )}
      </div>

      {/* Active filter pills */}
      {(activeFilterCount > 0 || filter !== "all") && (
        <div className="mb-3 flex flex-wrap items-center gap-1.5">
          {filter !== "all" && (
            <span className="inline-flex items-center gap-1 rounded-full bg-primary/10 px-2.5 py-0.5 text-xs text-primary">
              Mode: {filter}
              <button
                onClick={() => setFilter("all")}
                className="hover:text-foreground"
              >
                <X className="h-3 w-3" />
              </button>
            </span>
          )}
          {COLUMN_FILTER_DEFS.map((def) => {
            const selected = columnFilters[def.field];
            if (!selected || selected.size === 0) return null;
            return (
              <span
                key={def.field}
                className="inline-flex items-center gap-1 rounded-full bg-primary/10 px-2.5 py-0.5 text-xs text-primary"
              >
                {def.label}: {selected.size} selected
                <button
                  onClick={() => removeColumnFilter(def.field)}
                  className="hover:text-foreground"
                >
                  <X className="h-3 w-3" />
                </button>
              </span>
            );
          })}
          <span className="self-center text-xs text-muted-foreground">
            {filteredConnections.length} of {data.connections.length} shown
          </span>
          <button
            onClick={resetAllFilters}
            className="ml-2 rounded-md border border-border bg-muted px-2.5 py-1 text-xs font-medium text-muted-foreground hover:bg-muted/80 hover:text-foreground transition-colors"
          >
            Reset Filters
          </button>
        </div>
      )}

      {groupMode === "flat" ? (
        <DataTable
          columns={connectionColumns(vlanLookup.ipToVlanLabel)}
          data={filteredConnections}
          rowKey={(r) => r.id}
          searchable
          searchPlaceholder="Search connections..."
          defaultSort={{ key: "flagged" }}
          rowStyle={(r) =>
            r.flagged
              ? { borderLeft: "3px solid #FF4D4F" }
              : undefined
          }
        />
      ) : (
        <GroupedConnectionsView
          connections={filteredConnections}
          groupMode={groupMode}
          columns={connectionColumns(vlanLookup.ipToVlanLabel)}
          rowStyle={(r) =>
            r.flagged
              ? { borderLeft: "3px solid #FF4D4F" }
              : undefined
          }
        />
      )}
        </>
      ))}
    </PageShell>
  );
}
