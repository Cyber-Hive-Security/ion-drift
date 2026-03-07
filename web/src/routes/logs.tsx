import { useState, useMemo, useRef, useCallback, useEffect } from "react";
import {
  ScrollText,
  Shield,
  ShieldAlert,
  AlertTriangle,
  Info,
  XCircle,
  ChevronDown,
  ChevronRight,
  Radio,
  Search,
  BarChart3,
  Globe,
} from "lucide-react";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import { useStructuredLogs, useLogTrends } from "@/api/queries";
import { PageShell } from "@/components/layout/page-shell";
import { LogsHelp } from "@/components/help-content";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { cn } from "@/lib/utils";
import { countryFlag } from "@/lib/country";
import type {
  StructuredLogEntry,
  LogAnalytics,
  IpCount,
  PortCount,
} from "@/api/types";

// ── Constants ────────────────────────────────────────────────────

const LIMITS = [100, 250, 500, 1000] as const;

const TOPIC_LABELS: Record<string, string> = {
  firewall: "Firewall",
  dhcp: "DHCP",
  interface: "Interface",
  system: "System",
  wireguard: "WireGuard",
  dns: "DNS",
};

const SEVERITY_COLORS: Record<string, string> = {
  info: "bg-emerald-500",
  warning: "bg-warning",
  error: "bg-destructive",
  critical: "bg-destructive",
};


// ── Logs Page ────────────────────────────────────────────────────

export function LogsPage() {
  const [limit, setLimit] = useState<number>(500);
  const [topicFilter, setTopicFilter] = useState<string | null>(null);
  const [actionFilter, setActionFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [textSearch, setTextSearch] = useState("");
  const [srcIpSearch, setSrcIpSearch] = useState("");
  const [dstIpSearch, setDstIpSearch] = useState("");
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const [liveTail, setLiveTail] = useState(false);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [showAnalytics, setShowAnalytics] = useState(true);

  const logs = useStructuredLogs({
    topics: topicFilter ?? undefined,
    limit,
    action: actionFilter !== "all" ? actionFilter : undefined,
    severity: severityFilter !== "all" ? severityFilter : undefined,
    refetchInterval: liveTail ? 2_000 : false,
  });

  const data = logs.data;
  const entries = data?.entries ?? [];
  const analytics = data?.analytics;

  // Client-side text/IP/flagged filtering
  const filtered = useMemo(() => {
    let result = entries;

    if (textSearch.trim()) {
      const q = textSearch.trim().toLowerCase();
      try {
        const regex = new RegExp(q, "i");
        result = result.filter(
          (e) => regex.test(e.message) || (e.prefix && regex.test(e.prefix))
        );
      } catch {
        result = result.filter(
          (e) =>
            e.message.toLowerCase().includes(q) ||
            (e.prefix && e.prefix.toLowerCase().includes(q))
        );
      }
    }

    if (srcIpSearch.trim()) {
      const q = srcIpSearch.trim();
      result = result.filter((e) => e.parsed?.src_ip?.includes(q));
    }

    if (dstIpSearch.trim()) {
      const q = dstIpSearch.trim();
      result = result.filter((e) => e.parsed?.dst_ip?.includes(q));
    }

    if (flaggedOnly) {
      result = result.filter(
        (e) => e.parsed?.src_flagged || e.parsed?.dst_flagged
      );
    }

    return result;
  }, [entries, textSearch, srcIpSearch, dstIpSearch, flaggedOnly]);

  // Group consecutive identical log entries
  const grouped = useMemo(() => groupEntries(filtered), [filtered]);

  // Available topics from analytics
  const availableTopics = useMemo(() => {
    if (!analytics) return [];
    return Object.keys(analytics.by_topic).sort();
  }, [analytics]);

  const toggleExpand = useCallback((id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  return (
    <PageShell
      title="Logs"
      onRefresh={() => logs.refetch()}
      isRefreshing={logs.isFetching}
      help={<LogsHelp />}
    >
      {/* Summary Bar */}
      {analytics && <SummaryBar analytics={analytics} />}

      {/* Log Trends (persistent history from SQLite) */}
      <LogTrendsSection />

      {/* Filter Bar */}
      <div className="mb-4 space-y-3">
        {/* Row 1: Topic pills + limit + live tail */}
        <div className="flex flex-wrap items-center gap-2">
          <PillButton
            active={topicFilter === null}
            onClick={() => setTopicFilter(null)}
          >
            All
          </PillButton>
          {availableTopics.map((t) => (
            <PillButton
              key={t}
              active={topicFilter === t}
              onClick={() => setTopicFilter(topicFilter === t ? null : t)}
            >
              {TOPIC_LABELS[t] ?? t}
              <span className="ml-1 text-xs opacity-60">
                {analytics?.by_topic[t] ?? 0}
              </span>
            </PillButton>
          ))}

          <div className="ml-auto flex items-center gap-2">
            <select
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
              className="rounded-md border border-border bg-background px-2 py-1.5 text-xs text-foreground"
            >
              {LIMITS.map((l) => (
                <option key={l} value={l}>
                  Last {l}
                </option>
              ))}
            </select>

            <button
              onClick={() => setLiveTail(!liveTail)}
              className={cn(
                "flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium transition-colors",
                liveTail
                  ? "border-destructive/50 bg-destructive/10 text-destructive"
                  : "border-border text-muted-foreground hover:bg-muted"
              )}
            >
              <Radio
                className={cn("h-3.5 w-3.5", liveTail && "animate-pulse")}
              />
              Live Tail
            </button>
          </div>
        </div>

        {/* Row 2: Action + severity filters */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-muted-foreground">Action:</span>
          {["all", "drop", "accept"].map((a) => (
            <PillButton
              key={a}
              active={actionFilter === a}
              onClick={() => setActionFilter(a)}
              variant={
                a === "drop" ? "danger" : a === "accept" ? "success" : "default"
              }
            >
              {a === "all" ? "All" : a.charAt(0).toUpperCase() + a.slice(1)}
            </PillButton>
          ))}

          <span className="ml-4 text-xs text-muted-foreground">Severity:</span>
          {["all", "info", "warning", "error", "critical"].map((s) => (
            <PillButton
              key={s}
              active={severityFilter === s}
              onClick={() => setSeverityFilter(s)}
            >
              {s === "all" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)}
            </PillButton>
          ))}
        </div>

        {/* Row 3: Search fields */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search messages (regex)"
              value={textSearch}
              onChange={(e) => setTextSearch(e.target.value)}
              className="rounded-md border border-border bg-background pl-8 pr-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground w-56"
            />
          </div>
          <input
            type="text"
            placeholder="Src IP"
            value={srcIpSearch}
            onChange={(e) => setSrcIpSearch(e.target.value)}
            className="rounded-md border border-border bg-background px-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground w-32"
          />
          <input
            type="text"
            placeholder="Dst IP"
            value={dstIpSearch}
            onChange={(e) => setDstIpSearch(e.target.value)}
            className="rounded-md border border-border bg-background px-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground w-32"
          />
          <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <input
              type="checkbox"
              checked={flaggedOnly}
              onChange={(e) => setFlaggedOnly(e.target.checked)}
              className="rounded"
            />
            <ShieldAlert className="h-3.5 w-3.5 text-destructive" />
            Flagged Only
          </label>

          <button
            onClick={() => setShowAnalytics(!showAnalytics)}
            className={cn(
              "ml-auto flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs transition-colors",
              showAnalytics
                ? "border-primary/50 bg-primary/10 text-primary"
                : "border-border text-muted-foreground hover:bg-muted"
            )}
          >
            <BarChart3 className="h-3.5 w-3.5" />
            Analytics
          </button>
        </div>
      </div>

      {logs.isLoading && <LoadingSpinner />}
      {logs.error && (
        <ErrorDisplay
          message={logs.error.message}
          onRetry={() => logs.refetch()}
        />
      )}

      {data && (
        <div className="flex gap-4">
          {/* Main content */}
          <div className="flex-1 min-w-0">
            <LogTable
              groups={grouped}
              expandedIds={expandedIds}
              onToggleExpand={toggleExpand}
              liveTail={liveTail}
            />
          </div>

          {/* Analytics panel */}
          {showAnalytics && analytics && (
            <div className="hidden xl:block w-80 shrink-0">
              <AnalyticsPanel analytics={analytics} />
            </div>
          )}
        </div>
      )}

      {/* Mobile analytics below table */}
      {showAnalytics && analytics && (
        <div className="mt-4 xl:hidden">
          <AnalyticsPanel analytics={analytics} />
        </div>
      )}
    </PageShell>
  );
}

// ── Summary Bar ──────────────────────────────────────────────────

function SummaryBar({ analytics }: { analytics: LogAnalytics }) {
  const sevEntries = [
    { key: "info", label: "Info", icon: Info, color: "text-emerald-400" },
    {
      key: "warning",
      label: "Warn",
      icon: AlertTriangle,
      color: "text-warning",
    },
    { key: "error", label: "Error", icon: XCircle, color: "text-destructive" },
    {
      key: "critical",
      label: "Crit",
      icon: ShieldAlert,
      color: "text-destructive",
    },
  ];

  return (
    <div className="mb-4 flex flex-wrap items-center gap-4 rounded-lg border border-border bg-card p-3">
      <div className="flex items-center gap-2">
        <ScrollText className="h-4 w-4 text-muted-foreground" />
        <span className="text-sm font-medium">{analytics.total}</span>
        <span className="text-xs text-muted-foreground">entries</span>
      </div>
      <div className="h-6 w-px bg-border" />

      {sevEntries.map(({ key, label, icon: Icon, color }) => {
        const count = analytics.by_severity[key] ?? 0;
        if (count === 0) return null;
        return (
          <div key={key} className="flex items-center gap-1.5">
            <Icon
              className={cn(
                "h-3.5 w-3.5",
                color,
                key === "critical" && count > 0 && "animate-pulse"
              )}
            />
            <span className={cn("text-xs font-medium", color)}>{count}</span>
            <span className="text-xs text-muted-foreground">{label}</span>
          </div>
        );
      })}

      <div className="h-6 w-px bg-border" />

      <div className="flex items-center gap-1.5">
        <Shield className="h-3.5 w-3.5 text-destructive" />
        <span className="text-xs font-medium text-destructive">
          {analytics.by_action["drop"] ?? 0}
        </span>
        <span className="text-xs text-muted-foreground">Drops</span>
      </div>
      <div className="flex items-center gap-1.5">
        <Shield className="h-3.5 w-3.5 text-emerald-400" />
        <span className="text-xs font-medium text-emerald-400">
          {analytics.by_action["accept"] ?? 0}
        </span>
        <span className="text-xs text-muted-foreground">Accepts</span>
      </div>
    </div>
  );
}

// ── Pill Button ──────────────────────────────────────────────────

function PillButton({
  active,
  onClick,
  children,
  variant = "default",
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
  variant?: "default" | "danger" | "success";
}) {
  const activeColors =
    variant === "danger"
      ? "border-destructive/50 bg-destructive/10 text-destructive"
      : variant === "success"
        ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-400"
        : "border-primary/50 bg-primary/10 text-primary";

  return (
    <button
      onClick={onClick}
      className={cn(
        "rounded-full border px-3 py-1 text-xs font-medium transition-colors",
        active
          ? activeColors
          : "border-border text-muted-foreground hover:bg-muted hover:text-foreground"
      )}
    >
      {children}
    </button>
  );
}

// ── Log Entry Grouping ───────────────────────────────────────────

interface GroupedEntry {
  entry: StructuredLogEntry;
  count: number;
}

function groupEntries(entries: StructuredLogEntry[]): GroupedEntry[] {
  if (entries.length === 0) return [];

  const groups: GroupedEntry[] = [];
  let current: GroupedEntry | null = null;

  for (const entry of entries) {
    if (
      current &&
      current.entry.prefix === entry.prefix &&
      current.entry.parsed?.src_ip === entry.parsed?.src_ip &&
      current.entry.parsed?.dst_ip === entry.parsed?.dst_ip &&
      current.entry.parsed?.dst_port === entry.parsed?.dst_port &&
      current.entry.parsed?.protocol === entry.parsed?.protocol &&
      current.entry.parsed?.action === entry.parsed?.action
    ) {
      current.count++;
    } else {
      if (current) groups.push(current);
      current = { entry, count: 1 };
    }
  }
  if (current) groups.push(current);

  return groups;
}

// ── Log Table ────────────────────────────────────────────────────

function LogTable({
  groups,
  expandedIds,
  onToggleExpand,
  liveTail,
}: {
  groups: GroupedEntry[];
  expandedIds: Set<string>;
  onToggleExpand: (id: string) => void;
  liveTail: boolean;
}) {
  const tableRef = useRef<HTMLDivElement>(null);
  const [hovering, setHovering] = useState(false);

  // Auto-scroll in live tail mode
  useEffect(() => {
    if (liveTail && !hovering && tableRef.current) {
      tableRef.current.scrollTop = 0;
    }
  }, [groups, liveTail, hovering]);

  // Reverse for live tail (newest first)
  const displayGroups = liveTail ? [...groups].reverse() : groups;

  return (
    <div
      ref={tableRef}
      className="overflow-auto rounded-lg border border-border"
      style={{ maxHeight: "calc(100vh - 340px)" }}
      onMouseEnter={() => setHovering(true)}
      onMouseLeave={() => setHovering(false)}
    >
      <table className="w-full text-xs">
        <thead className="sticky top-0 z-10">
          <tr className="border-b border-border bg-muted/80 backdrop-blur">
            <th className="w-8 px-2 py-2" />
            <th className="px-2 py-2 text-left font-medium text-muted-foreground w-36">
              Time
            </th>
            <th className="px-2 py-2 text-left font-medium text-muted-foreground w-10">
              Sev
            </th>
            <th className="px-2 py-2 text-left font-medium text-muted-foreground w-20">
              Action
            </th>
            <th className="px-2 py-2 text-left font-medium text-muted-foreground w-14">
              Proto
            </th>
            <th className="px-2 py-2 text-left font-medium text-muted-foreground">
              Source
            </th>
            <th className="px-1 py-2 text-center font-medium text-muted-foreground w-6">

            </th>
            <th className="px-2 py-2 text-left font-medium text-muted-foreground">
              Destination
            </th>
            <th className="px-2 py-2 text-left font-medium text-muted-foreground w-40">
              Interface
            </th>
            <th className="px-2 py-2 text-right font-medium text-muted-foreground w-14">
              Size
            </th>
          </tr>
        </thead>
        <tbody>
          {displayGroups.map((group) => (
            <LogRow
              key={group.entry.id}
              group={group}
              expanded={expandedIds.has(group.entry.id)}
              onToggle={() => onToggleExpand(group.entry.id)}
              isNew={liveTail}
            />
          ))}
          {displayGroups.length === 0 && (
            <tr>
              <td
                colSpan={10}
                className="py-12 text-center text-sm text-muted-foreground"
              >
                No log entries match the current filters.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

// ── Log Row ──────────────────────────────────────────────────────

function LogRow({
  group,
  expanded,
  onToggle,
  isNew,
}: {
  group: GroupedEntry;
  expanded: boolean;
  onToggle: () => void;
  isNew: boolean;
}) {
  const { entry, count } = group;
  const p = entry.parsed;
  const isDrop = p?.action === "drop";
  const isAccept = p?.action === "accept";
  const isFlagged = p?.src_flagged || p?.dst_flagged;

  // Border color by severity/action
  const borderColor = isDrop
    ? "border-l-red-500"
    : entry.level === "critical"
      ? "border-l-red-600"
      : entry.level === "error"
        ? "border-l-red-400"
        : entry.level === "warning"
          ? "border-l-yellow-500"
          : isAccept
            ? "border-l-emerald-500/50"
            : "border-l-transparent";

  return (
    <>
      <tr
        onClick={onToggle}
        className={cn(
          "border-b border-border/50 border-l-2 cursor-pointer transition-colors hover:bg-muted/30",
          borderColor,
          isDrop && "bg-destructive/5",
          isFlagged && "bg-destructive/10",
          isNew && "animate-in fade-in duration-300"
        )}
      >
        {/* Expand toggle */}
        <td className="px-2 py-1.5 text-muted-foreground">
          {expanded ? (
            <ChevronDown className="h-3.5 w-3.5" />
          ) : (
            <ChevronRight className="h-3.5 w-3.5" />
          )}
        </td>

        {/* Timestamp */}
        <td className="px-2 py-1.5 font-mono text-muted-foreground whitespace-nowrap">
          {entry.timestamp.length > 11
            ? entry.timestamp.slice(11)
            : entry.timestamp}
          {count > 1 && (
            <span className="ml-1.5 inline-flex items-center rounded bg-muted px-1 py-0.5 text-[10px] font-semibold text-muted-foreground">
              x{count}
            </span>
          )}
        </td>

        {/* Severity dot */}
        <td className="px-2 py-1.5">
          <span
            className={cn(
              "inline-block h-2 w-2 rounded-full",
              SEVERITY_COLORS[entry.level] ?? "bg-gray-500",
              entry.level === "critical" && "animate-pulse"
            )}
            title={entry.level}
          />
        </td>

        {/* Action badge */}
        <td className="px-2 py-1.5">
          {p?.action && (
            <span
              className={cn(
                "inline-flex rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                isDrop
                  ? "bg-destructive/15 text-destructive"
                  : isAccept
                    ? "bg-emerald-500/15 text-emerald-400"
                    : "bg-muted text-muted-foreground"
              )}
            >
              {p.action}
            </span>
          )}
          {!p?.action && entry.prefix && (
            <span className="text-[10px] text-muted-foreground">
              {entry.prefix}
            </span>
          )}
          {entry.paired_messages && entry.paired_messages.length > 0 && (
            <span className="ml-1 inline-flex items-center rounded bg-primary/15 px-1 py-0.5 text-[10px] font-medium text-primary">
              {1 + entry.paired_messages.length} rules
            </span>
          )}
        </td>

        {/* Protocol */}
        <td className="px-2 py-1.5 font-mono uppercase">
          {p?.protocol
            ? p.protocol.split(" ")[0]
            : entry.topics.find(
                (t) =>
                  t !== "info" &&
                  t !== "firewall" &&
                  t !== "warning" &&
                  t !== "error"
              ) ?? ""}
        </td>

        {/* Source */}
        <td className="px-2 py-1.5 font-mono">
          {p?.src_ip && (
            <span className={cn(p.src_flagged && "text-destructive")}>
              {p.src_ip}
              {p.src_port != null && (
                <span className="text-muted-foreground">:{p.src_port}</span>
              )}
              {p.src_country && (
                <span className="ml-1 text-[10px]">
                  {countryFlag(p.src_country.country_code)}
                </span>
              )}
            </span>
          )}
        </td>

        {/* Direction arrow */}
        <td className="px-1 py-1.5 text-center text-muted-foreground">
          {p?.src_ip && p?.dst_ip ? "→" : ""}
        </td>

        {/* Destination */}
        <td className="px-2 py-1.5 font-mono">
          {p?.dst_ip && (
            <span className={cn(p.dst_flagged && "text-destructive")}>
              {p.dst_ip}
              {p.dst_port != null && (
                <span className="text-muted-foreground">:{p.dst_port}</span>
              )}
              {p.dst_country && (
                <span className="ml-1 text-[10px]">
                  {countryFlag(p.dst_country.country_code)}
                </span>
              )}
            </span>
          )}
          {!p && (
            <span className="text-muted-foreground">
              {entry.message.slice(0, 80)}
              {entry.message.length > 80 ? "…" : ""}
            </span>
          )}
        </td>

        {/* Interface */}
        <td className="px-2 py-1.5 text-muted-foreground">
          {p?.in_interface && (
            <span>
              {p.in_interface}
              {p.out_interface && (
                <span>
                  <span className="mx-0.5">→</span>
                  {p.out_interface}
                </span>
              )}
            </span>
          )}
        </td>

        {/* Size */}
        <td className="px-2 py-1.5 text-right font-mono text-muted-foreground">
          {p?.length != null ? `${p.length}B` : ""}
        </td>
      </tr>

      {/* Expanded detail row */}
      {expanded && (
        <tr className="border-b border-border/50 bg-muted/20">
          <td colSpan={10} className="px-6 py-3">
            <ExpandedDetail entry={entry} />
          </td>
        </tr>
      )}
    </>
  );
}

// ── Expanded Detail ──────────────────────────────────────────────

function ExpandedDetail({ entry }: { entry: StructuredLogEntry }) {
  const p = entry.parsed;
  const hasPaired = entry.paired_messages && entry.paired_messages.length > 0;

  return (
    <div className="space-y-2">
      {hasPaired && (
        <div className="text-[10px] font-medium text-primary uppercase tracking-wider">
          Terminating rule
        </div>
      )}
      <div className="font-mono text-xs text-foreground bg-background/50 rounded p-2 whitespace-pre-wrap break-all">
        {entry.message}
      </div>
      {hasPaired && (
        <>
          <div className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
            Non-terminating log {entry.paired_messages!.length === 1 ? "rule" : "rules"}
          </div>
          {entry.paired_messages!.map((msg, i) => (
            <div
              key={i}
              className="font-mono text-xs text-muted-foreground bg-background/30 rounded p-2 whitespace-pre-wrap break-all border border-border/30"
            >
              {msg}
            </div>
          ))}
        </>
      )}
      <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs">
        <Field label="Topics" value={entry.topics.join(", ")} />
        <Field label="Level" value={entry.level} />
        {entry.prefix && <Field label="Prefix" value={entry.prefix} />}
        {p?.direction && <Field label="Direction" value={p.direction} />}
        {p?.in_interface && <Field label="In" value={p.in_interface} />}
        {p?.out_interface && <Field label="Out" value={p.out_interface} />}
        {p?.protocol && <Field label="Protocol" value={p.protocol} />}
        {p?.src_ip && (
          <Field
            label="Source"
            value={`${p.src_ip}${p.src_port != null ? `:${p.src_port}` : ""}`}
          />
        )}
        {p?.dst_ip && (
          <Field
            label="Destination"
            value={`${p.dst_ip}${p.dst_port != null ? `:${p.dst_port}` : ""}`}
          />
        )}
        {p?.mac && <Field label="MAC" value={p.mac} />}
        {p?.manufacturer && (
          <Field label="Manufacturer" value={p.manufacturer} />
        )}
        {p?.length != null && <Field label="Length" value={`${p.length}`} />}
        {p?.src_country && (
          <Field
            label="Src Country"
            value={`${countryFlag(p.src_country.country_code)} ${p.src_country.country} (${p.src_country.country_code})`}
          />
        )}
        {p?.dst_country && (
          <Field
            label="Dst Country"
            value={`${countryFlag(p.dst_country.country_code)} ${p.dst_country.country} (${p.dst_country.country_code})`}
          />
        )}
      </div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="text-muted-foreground">{label}: </span>
      <span className="font-medium text-foreground">{value}</span>
    </div>
  );
}

// ── Log Trends Section ──────────────────────────────────────────

type TrendsRange = "24h" | "7d";

function LogTrendsSection() {
  const [range, setRange] = useState<TrendsRange>("24h");
  const trends = useLogTrends(range);
  const data = trends.data ?? [];

  if (data.length < 2) return null;

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
    drops: p.drop_count,
    accepts: p.accept_count,
    total: p.total_entries,
  }));

  // Find recurring top drop sources
  const srcCounts = new Map<string, number>();
  for (const p of data) {
    if (p.top_drop_source) {
      srcCounts.set(
        p.top_drop_source,
        (srcCounts.get(p.top_drop_source) ?? 0) + p.top_drop_source_count,
      );
    }
  }
  const topSources = [...srcCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return (
    <div className="mb-4 rounded-lg border border-border bg-card p-4">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-sm font-medium text-muted-foreground">
          Log Trends
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

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Drops per hour */}
        <div>
          <p className="mb-2 text-xs text-muted-foreground">Drops per Hour</p>
          <ResponsiveContainer width="100%" height={120}>
            <BarChart data={chartData}>
              <XAxis
                dataKey="time"
                tick={{ fill: "#8A929D", fontSize: 9 }}
                interval="preserveStartEnd"
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  background: "#2C3038",
                  border: "1px solid #444B55",
                  borderRadius: 6,
                  fontSize: 11,
                }}
                formatter={(value: number, name: string) => [
                  value.toLocaleString(),
                  name.charAt(0).toUpperCase() + name.slice(1),
                ]}
              />
              <Bar dataKey="drops" fill="#FF4D4F" radius={[2, 2, 0, 0]} isAnimationActive={false} />
              <Bar dataKey="accepts" fill="#21D07A" radius={[2, 2, 0, 0]} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Recurring drop sources */}
        {topSources.length > 0 && (
          <div>
            <p className="mb-2 text-xs text-muted-foreground">
              Recurring Drop Sources ({range})
            </p>
            <div className="space-y-1.5">
              {topSources.map(([ip, count]) => (
                <div
                  key={ip}
                  className="flex items-center justify-between text-xs"
                >
                  <span className="font-mono text-foreground">{ip}</span>
                  <span className="text-muted-foreground tabular-nums">
                    {count.toLocaleString()} drops
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Analytics Panel ──────────────────────────────────────────────

function AnalyticsPanel({ analytics }: { analytics: LogAnalytics }) {
  return (
    <div className="space-y-4">
      {/* Top Dropped Sources */}
      {analytics.top_dropped_sources.length > 0 && (
        <AnalyticsCard title="Top Dropped Sources" icon={Shield}>
          <div className="space-y-1.5">
            {analytics.top_dropped_sources.map((item) => (
              <DroppedSourceRow key={item.ip} item={item} />
            ))}
          </div>
        </AnalyticsCard>
      )}

      {/* Top Targeted Ports */}
      {analytics.top_targeted_ports.length > 0 && (
        <AnalyticsCard title="Top Targeted Ports" icon={Globe}>
          <div className="space-y-1.5">
            {analytics.top_targeted_ports.map((item) => (
              <TargetedPortRow
                key={`${item.port}-${item.protocol}`}
                item={item}
                maxCount={analytics.top_targeted_ports[0].count}
              />
            ))}
          </div>
        </AnalyticsCard>
      )}

      {/* Drops per Interface */}
      {analytics.drops_per_interface.length > 0 && (
        <AnalyticsCard title="Drops by Interface" icon={ShieldAlert}>
          <ResponsiveContainer width="100%" height={analytics.drops_per_interface.length * 28 + 10}>
            <BarChart
              data={analytics.drops_per_interface}
              layout="vertical"
              margin={{ left: 0, right: 10, top: 0, bottom: 0 }}
            >
              <XAxis type="number" hide />
              <YAxis
                type="category"
                dataKey="interface"
                width={100}
                tick={{ fontSize: 10, fill: "#9AA6B2" }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  background: "#2C3038",
                  border: "1px solid #444B55",
                  borderRadius: 6,
                  fontSize: 11,
                }}
                formatter={(value: number) => [value.toLocaleString(), "Drops"]}
              />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {analytics.drops_per_interface.map((_, i) => (
                  <Cell
                    key={i}
                    fill={["#FF4FD8", "#FF4D4F", "#FFC857"][i % 3]}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </AnalyticsCard>
      )}

      {/* Log Volume Over Time */}
      {analytics.volume_over_time.length > 1 && (
        <AnalyticsCard title="Volume / Minute" icon={BarChart3}>
          <ResponsiveContainer width="100%" height={80}>
            <AreaChart
              data={analytics.volume_over_time}
              margin={{ left: 0, right: 0, top: 4, bottom: 0 }}
            >
              <defs>
                <linearGradient id="volGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#2FA4FF" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#2FA4FF" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis
                dataKey="minute"
                tick={{ fontSize: 9, fill: "#8A929D" }}
                tickFormatter={(v: string) => (v.length > 11 ? v.slice(11) : v)}
                interval="preserveStartEnd"
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  background: "#2C3038",
                  border: "1px solid #444B55",
                  borderRadius: 6,
                  fontSize: 11,
                }}
                labelFormatter={(v: string) => v}
                formatter={(value: number) => [value, "entries"]}
              />
              <Area
                type="monotone"
                dataKey="count"
                stroke="#2FA4FF"
                strokeWidth={1.5}
                fill="url(#volGrad)"
                dot={false}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </AnalyticsCard>
      )}
    </div>
  );
}

function AnalyticsCard({
  title,
  icon: Icon,
  children,
}: {
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-border bg-card p-3">
      <div className="mb-2 flex items-center gap-2 text-xs font-medium text-muted-foreground">
        <Icon className="h-3.5 w-3.5" />
        {title}
      </div>
      {children}
    </div>
  );
}

function DroppedSourceRow({ item }: { item: IpCount }) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <span
        className={cn(
          "font-mono flex-1 truncate",
          item.flagged ? "text-destructive" : "text-foreground"
        )}
      >
        {item.ip}
        {item.country && (
          <span className="ml-1 text-[10px]">
            {countryFlag(item.country.country_code)} {item.country.country_code}
          </span>
        )}
      </span>
      <span className="font-mono text-muted-foreground tabular-nums">
        {item.count}
      </span>
    </div>
  );
}

function TargetedPortRow({
  item,
  maxCount,
}: {
  item: PortCount;
  maxCount: number;
}) {
  const pct = maxCount > 0 ? (item.count / maxCount) * 100 : 0;
  return (
    <div className="space-y-0.5">
      <div className="flex items-center justify-between text-xs">
        <span className="font-mono text-foreground">
          {item.port}
          <span className="ml-1 text-muted-foreground uppercase">
            {item.protocol}
          </span>
        </span>
        <span className="font-mono text-muted-foreground tabular-nums">
          {item.count}
        </span>
      </div>
      <div className="h-1 w-full rounded-full bg-muted">
        <div
          className="h-1 rounded-full bg-destructive/60"
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
