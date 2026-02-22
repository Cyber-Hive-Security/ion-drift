import { useState, useMemo } from "react";
import {
  useBehaviorOverview,
  useBehaviorAnomalies,
  useResolveAnomaly,
} from "@/api/queries";
import { PageShell } from "@/components/layout/page-shell";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { DataTable, type Column } from "@/components/data-table";
import { cn } from "@/lib/utils";
import type {
  BehaviorOverview,
  DeviceAnomaly,
  VlanBehaviorSummary,
} from "@/api/types";
import {
  Activity,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Brain,
  ChevronDown,
  ChevronRight,
  Check,
  Flag,
  X,
} from "lucide-react";

// ── VLAN names for display ───────────────────────────────────

const VLAN_NAMES: Record<number, string> = {
  2: "Network Mgmt",
  6: "Employer Isolated",
  10: "Cyber Hive Security",
  25: "Trusted Services",
  30: "Trusted Wired",
  35: "Trusted Wireless",
  40: "Guest",
  90: "IoT Internet",
  99: "IoT Restricted",
};

// ── Severity styling ─────────────────────────────────────────

function severityColor(severity: string): string {
  switch (severity) {
    case "critical":
      return "text-red-500";
    case "alert":
      return "text-orange-500";
    case "warning":
      return "text-amber-500";
    case "info":
      return "text-blue-400";
    default:
      return "text-muted-foreground";
  }
}

function severityBg(severity: string): string {
  switch (severity) {
    case "critical":
      return "bg-red-500/10 border-red-500/30";
    case "alert":
      return "bg-orange-500/10 border-orange-500/30";
    case "warning":
      return "bg-amber-500/10 border-amber-500/30";
    case "info":
      return "bg-blue-500/10 border-blue-500/30";
    default:
      return "bg-muted border-border";
  }
}

function formatTimeAgo(ts: number): string {
  const secs = Math.floor(Date.now() / 1000 - ts);
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

// ── Stats Row ────────────────────────────────────────────────

function StatsRow({ data }: { data: BehaviorOverview }) {
  return (
    <div className="mb-4 grid grid-cols-2 gap-4 md:grid-cols-4">
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="mb-1 flex items-center gap-2 text-xs font-medium text-muted-foreground">
          <Activity className="h-3.5 w-3.5" />
          Total Devices
        </div>
        <p className="text-2xl font-bold">{data.total_devices}</p>
      </div>
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="mb-1 flex items-center gap-2 text-xs font-medium text-muted-foreground">
          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
          Baselined
        </div>
        <p className="text-2xl font-bold text-emerald-500">
          {data.baselined_devices}
        </p>
      </div>
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="mb-1 flex items-center gap-2 text-xs font-medium text-muted-foreground">
          <Brain className="h-3.5 w-3.5 text-blue-500" />
          Learning
        </div>
        <p className="text-2xl font-bold text-blue-500">
          {data.learning_devices}
        </p>
      </div>
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="mb-1 flex items-center gap-2 text-xs font-medium text-muted-foreground">
          <AlertTriangle className="h-3.5 w-3.5 text-amber-500" />
          Pending Anomalies
        </div>
        <p
          className={cn(
            "text-2xl font-bold",
            data.pending_anomalies > 0 ? "text-amber-500" : "text-emerald-500",
          )}
        >
          {data.pending_anomalies}
        </p>
      </div>
    </div>
  );
}

// ── Alert Banners ────────────────────────────────────────────

function AlertBanners({ data }: { data: BehaviorOverview }) {
  const learningCount = data.learning_devices;
  const hasCritical = data.critical_anomalies > 0;
  const hasWarning = data.warning_anomalies > 0;

  return (
    <>
      {learningCount > 0 && (
        <div className="mb-3 flex items-center gap-2 rounded-md border border-blue-500/30 bg-blue-500/10 px-4 py-2 text-sm text-blue-400">
          <Brain className="h-4 w-4" />
          Baseline learning in progress — {learningCount} device
          {learningCount !== 1 ? "s" : ""} building profiles...
        </div>
      )}
      {(hasCritical || hasWarning) && (
        <div className="mb-3 flex items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-sm text-amber-400">
          <AlertTriangle className="h-4 w-4" />
          {data.pending_anomalies} anomal
          {data.pending_anomalies !== 1 ? "ies" : "y"} require review
          {hasCritical && (
            <span className="ml-1 text-red-500">
              — {data.critical_anomalies} critical
            </span>
          )}
          {hasWarning && (
            <span className="ml-1">
              , {data.warning_anomalies} warning
            </span>
          )}
        </div>
      )}
    </>
  );
}

// ── VLAN Section (Accordion) ─────────────────────────────────

function VlanSection({
  summary,
  anomalies,
  resolveMutation,
}: {
  summary: VlanBehaviorSummary;
  anomalies: DeviceAnomaly[];
  resolveMutation: ReturnType<typeof useResolveAnomaly>;
}) {
  const hasAnomalies = summary.pending_anomaly_count > 0;
  const [expanded, setExpanded] = useState(hasAnomalies);

  const vlanAnomalies = useMemo(
    () => anomalies.filter((a) => a.vlan === summary.vlan),
    [anomalies, summary.vlan],
  );

  return (
    <div
      className={cn(
        "mb-2 rounded-lg border bg-card",
        hasAnomalies ? "border-amber-500/30" : "border-border",
      )}
    >
      <button
        className="flex w-full items-center gap-3 px-4 py-3 text-left"
        onClick={() => setExpanded(!expanded)}
      >
        {expanded ? (
          <ChevronDown className="h-4 w-4 text-muted-foreground" />
        ) : (
          <ChevronRight className="h-4 w-4 text-muted-foreground" />
        )}
        <span className="font-medium">
          VLAN {summary.vlan}:{" "}
          {VLAN_NAMES[summary.vlan] ?? "Unknown"}
        </span>
        <span className="ml-auto flex items-center gap-3 text-xs text-muted-foreground">
          <span>{summary.device_count} devices</span>
          {summary.pending_anomaly_count > 0 && (
            <span className="rounded-full bg-amber-500/15 px-2 py-0.5 text-amber-500">
              {summary.pending_anomaly_count} anomal
              {summary.pending_anomaly_count !== 1 ? "ies" : "y"}
            </span>
          )}
          {summary.learning_count > 0 && (
            <span className="rounded-full bg-blue-500/15 px-2 py-0.5 text-blue-400">
              {summary.learning_count} learning
            </span>
          )}
        </span>
      </button>
      {expanded && vlanAnomalies.length > 0 && (
        <div className="border-t border-border px-4 py-3">
          <p className="mb-2 text-xs font-medium text-muted-foreground">
            Pending Anomalies
          </p>
          <div className="flex flex-col gap-2">
            {vlanAnomalies.map((a) => (
              <AnomalyCard
                key={a.id}
                anomaly={a}
                resolveMutation={resolveMutation}
              />
            ))}
          </div>
        </div>
      )}
      {expanded && vlanAnomalies.length === 0 && (
        <div className="border-t border-border px-4 py-3 text-xs text-muted-foreground">
          No pending anomalies for this VLAN.
        </div>
      )}
    </div>
  );
}

// ── Anomaly Card ─────────────────────────────────────────────

function AnomalyCard({
  anomaly,
  resolveMutation,
}: {
  anomaly: DeviceAnomaly;
  resolveMutation: ReturnType<typeof useResolveAnomaly>;
}) {
  const isPending = anomaly.status === "pending";

  return (
    <div
      className={cn(
        "rounded-md border px-3 py-2 text-sm",
        severityBg(anomaly.severity),
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <span
              className={cn(
                "text-xs font-semibold uppercase",
                severityColor(anomaly.severity),
              )}
            >
              {anomaly.severity}
            </span>
            <span className="rounded bg-muted px-1.5 py-0.5 text-xs">
              {anomaly.anomaly_type.replace(/_/g, " ")}
            </span>
            <span className="text-xs text-muted-foreground">
              {formatTimeAgo(anomaly.timestamp)}
            </span>
          </div>
          <p className="mt-1 text-xs">{anomaly.description}</p>
          <p className="mt-0.5 text-xs text-muted-foreground">
            MAC: {anomaly.mac}
            {anomaly.firewall_correlation && (
              <span className="ml-2">
                FW: {anomaly.firewall_correlation}
              </span>
            )}
          </p>
        </div>
        {isPending && (
          <div className="flex shrink-0 items-center gap-1">
            <button
              className="rounded p-1 text-emerald-500 hover:bg-emerald-500/15"
              title="Accept"
              onClick={() =>
                resolveMutation.mutate({ id: anomaly.id, action: "accepted" })
              }
            >
              <Check className="h-3.5 w-3.5" />
            </button>
            <button
              className="rounded p-1 text-amber-500 hover:bg-amber-500/15"
              title="Flag for review"
              onClick={() =>
                resolveMutation.mutate({ id: anomaly.id, action: "flagged" })
              }
            >
              <Flag className="h-3.5 w-3.5" />
            </button>
            <button
              className="rounded p-1 text-muted-foreground hover:bg-muted"
              title="Dismiss"
              onClick={() =>
                resolveMutation.mutate({ id: anomaly.id, action: "dismissed" })
              }
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        )}
        {!isPending && (
          <span className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
            {anomaly.status}
          </span>
        )}
      </div>
    </div>
  );
}

// ── Anomalies Table ──────────────────────────────────────────

const anomalyColumns: Column<DeviceAnomaly>[] = [
  {
    key: "severity",
    header: "Severity",
    render: (r) => (
      <span
        className={cn("text-xs font-semibold uppercase", severityColor(r.severity))}
      >
        {r.severity}
      </span>
    ),
    sortValue: (r) => {
      const order: Record<string, number> = { critical: 0, alert: 1, warning: 2, info: 3 };
      return order[r.severity] ?? 4;
    },
  },
  {
    key: "mac",
    header: "Device",
    render: (r) => <span className="font-mono text-xs">{r.mac}</span>,
    sortValue: (r) => r.mac,
  },
  {
    key: "type",
    header: "Type",
    render: (r) => (
      <span className="text-xs">{r.anomaly_type.replace(/_/g, " ")}</span>
    ),
    sortValue: (r) => r.anomaly_type,
  },
  {
    key: "description",
    header: "Description",
    render: (r) => (
      <span className="max-w-xs truncate text-xs" title={r.description}>
        {r.description}
      </span>
    ),
  },
  {
    key: "vlan",
    header: "VLAN",
    render: (r) => <span className="text-xs">{r.vlan}</span>,
    sortValue: (r) => r.vlan,
  },
  {
    key: "timestamp",
    header: "Time",
    render: (r) => (
      <span className="text-xs text-muted-foreground">
        {formatTimeAgo(r.timestamp)}
      </span>
    ),
    sortValue: (r) => -r.timestamp,
  },
  {
    key: "status",
    header: "Status",
    render: (r) => (
      <span
        className={cn(
          "rounded px-1.5 py-0.5 text-xs",
          r.status === "pending"
            ? "bg-amber-500/15 text-amber-500"
            : "bg-muted text-muted-foreground",
        )}
      >
        {r.status}
      </span>
    ),
    sortValue: (r) => r.status,
  },
];

// ── Main Page ────────────────────────────────────────────────

type TabMode = "overview" | "anomalies";
type AnomalyFilter = "all" | "pending" | "accepted" | "flagged" | "dismissed";

export function BehaviorPage() {
  const [tab, setTab] = useState<TabMode>("overview");
  const [anomalyFilter, setAnomalyFilter] = useState<AnomalyFilter>("pending");

  const overview = useBehaviorOverview();
  const anomaliesQuery = useBehaviorAnomalies({
    status: anomalyFilter === "all" ? undefined : anomalyFilter,
    limit: 200,
  });
  const resolveMutation = useResolveAnomaly();

  if (overview.isLoading) return <LoadingSpinner />;
  if (overview.error) {
    return (
      <PageShell title="Behavior">
        <ErrorDisplay
          message={overview.error.message}
          onRetry={() => overview.refetch()}
        />
      </PageShell>
    );
  }
  if (!overview.data) return null;

  const data = overview.data;
  const anomalies = anomaliesQuery.data ?? [];

  // Sort VLANs: those with anomalies first
  const sortedSummaries = [...data.vlan_summaries].sort((a, b) => {
    if (a.pending_anomaly_count > 0 && b.pending_anomaly_count === 0) return -1;
    if (a.pending_anomaly_count === 0 && b.pending_anomaly_count > 0) return 1;
    return a.vlan - b.vlan;
  });

  const tabs: { mode: TabMode; label: string }[] = [
    { mode: "overview", label: "Overview" },
    { mode: "anomalies", label: "Anomalies" },
  ];

  const statusFilters: { mode: AnomalyFilter; label: string }[] = [
    { mode: "all", label: "All" },
    { mode: "pending", label: "Pending" },
    { mode: "accepted", label: "Accepted" },
    { mode: "flagged", label: "Flagged" },
    { mode: "dismissed", label: "Dismissed" },
  ];

  return (
    <PageShell
      title="Behavior"
      onRefresh={() => {
        overview.refetch();
        anomaliesQuery.refetch();
      }}
      isRefreshing={overview.isFetching || anomaliesQuery.isFetching}
    >
      <AlertBanners data={data} />
      <StatsRow data={data} />

      {/* Tabs */}
      <div className="mb-4 flex gap-2">
        {tabs.map((t) => (
          <button
            key={t.mode}
            onClick={() => setTab(t.mode)}
            className={cn(
              "rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
              tab === t.mode
                ? "bg-primary text-primary-foreground"
                : "bg-muted text-muted-foreground hover:text-foreground",
            )}
          >
            {t.label}
            {t.mode === "anomalies" && data.pending_anomalies > 0 && (
              <span className="ml-1.5 inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-amber-500 px-1 text-[10px] text-white">
                {data.pending_anomalies}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Overview tab */}
      {tab === "overview" && (
        <div>
          {sortedSummaries.map((s) => (
            <VlanSection
              key={s.vlan}
              summary={s}
              anomalies={anomalies}
              resolveMutation={resolveMutation}
            />
          ))}
          {sortedSummaries.length === 0 && (
            <div className="rounded-lg border border-border bg-card p-8 text-center text-muted-foreground">
              <Shield className="mx-auto mb-3 h-8 w-8" />
              <p>No devices tracked yet.</p>
              <p className="mt-1 text-xs">
                Devices will appear after the behavior collector runs (60s
                intervals, 3-min startup delay).
              </p>
            </div>
          )}
        </div>
      )}

      {/* Anomalies tab */}
      {tab === "anomalies" && (
        <div>
          {/* Status filter */}
          <div className="mb-3 flex gap-2">
            {statusFilters.map((f) => (
              <button
                key={f.mode}
                onClick={() => setAnomalyFilter(f.mode)}
                className={cn(
                  "rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                  anomalyFilter === f.mode
                    ? "bg-primary text-primary-foreground"
                    : "bg-muted text-muted-foreground hover:text-foreground",
                )}
              >
                {f.label}
              </button>
            ))}
          </div>

          <DataTable
            columns={anomalyColumns}
            data={anomalies}
            rowKey={(r) => String(r.id)}
            searchable
            searchPlaceholder="Search anomalies..."
            defaultSort={{ key: "severity" }}
            rowStyle={(r) =>
              r.severity === "critical"
                ? { borderLeft: "3px solid oklch(0.6 0.2 25)" }
                : r.severity === "alert" || r.severity === "warning"
                  ? { borderLeft: "3px solid oklch(0.7 0.2 70)" }
                  : undefined
            }
          />
        </div>
      )}
    </PageShell>
  );
}
