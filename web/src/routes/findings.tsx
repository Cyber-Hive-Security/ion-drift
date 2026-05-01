import { useState, useMemo } from "react";
import {
  useFindings,
  useAcknowledgeFinding,
  useResolveFinding,
  type Finding,
  type FindingSeverity,
  type FindingStatus,
  type FindingEvidence,
} from "@/api/queries";
import { PageShell } from "@/components/layout/page-shell";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { DataTable, type Column } from "@/components/data-table";
import { DeviceLink } from "@/components/device-link";
import { cn } from "@/lib/utils";
import {
  findingSeverityBg,
  findingSeverityColor,
} from "@/lib/severity";
import { Filter, Check, CheckCheck } from "lucide-react";

const STATUS_FILTERS: { value: FindingStatus | "all"; label: string }[] = [
  { value: "all", label: "All" },
  { value: "open", label: "Open" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "resolved", label: "Resolved" },
];

const SEVERITIES: FindingSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

function formatTimeAgo(ts: number): string {
  const diff = Date.now() / 1000 - ts;
  if (diff < 60) return `${Math.floor(diff)}s`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h`;
  return `${Math.floor(diff / 86400)}d`;
}

function statusBadge(status: FindingStatus): string {
  switch (status) {
    case "open":
      return "border-warning/40 bg-warning/10 text-warning";
    case "acknowledged":
      return "border-primary/40 bg-primary/10 text-primary";
    case "resolved":
      return "border-success/40 bg-success/10 text-success";
  }
}

function EvidenceItem({ ev }: { ev: FindingEvidence }) {
  if (ev.type === "anomaly") {
    return (
      <span className="inline-block rounded border border-border bg-muted px-2 py-0.5 text-xs font-mono">
        Anomaly #{ev.anomaly_id}
      </span>
    );
  }
  if (ev.type === "connection") {
    return (
      <span className="inline-block rounded border border-border bg-muted px-2 py-0.5 text-xs font-mono">
        Connection #{ev.connection_id}
      </span>
    );
  }
  return (
    <details className="rounded border border-border bg-muted/50 px-2 py-1 text-xs">
      <summary className="cursor-pointer font-medium">{ev.label}</summary>
      <pre className="mt-1 overflow-x-auto text-[11px] text-muted-foreground">
        {JSON.stringify(ev.payload, null, 2)}
      </pre>
    </details>
  );
}

function FindingDetail({ finding }: { finding: Finding }) {
  const ack = useAcknowledgeFinding();
  const resolve = useResolveFinding();

  const onAck = () => ack.mutate(finding.id);
  const onResolve = () => {
    const note = window.prompt("Resolution note (optional):") ?? undefined;
    resolve.mutate({ id: finding.id, note: note || undefined });
  };

  const canAck = finding.status === "open";
  const canResolve =
    finding.status === "open" || finding.status === "acknowledged";

  return (
    <div
      className={cn(
        "border-l-2 p-4 space-y-4",
        findingSeverityBg(finding.severity),
      )}
    >
      <div>
        <h3 className="text-sm font-semibold mb-1">Narrative</h3>
        <p className="whitespace-pre-wrap text-sm text-muted-foreground">
          {finding.narrative}
        </p>
      </div>

      {finding.recommended_actions.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold mb-1">Recommended actions</h3>
          <ul className="list-disc pl-5 text-sm text-muted-foreground space-y-0.5">
            {finding.recommended_actions.map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ul>
        </div>
      )}

      {finding.evidence.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold mb-1">Evidence</h3>
          <div className="flex flex-wrap gap-2">
            {finding.evidence.map((ev, i) => (
              <EvidenceItem key={i} ev={ev} />
            ))}
          </div>
        </div>
      )}

      {finding.metadata != null && (
        <details className="rounded border border-border bg-background/50 px-3 py-2 text-xs">
          <summary className="cursor-pointer font-semibold">Metadata</summary>
          <pre className="mt-2 overflow-x-auto text-[11px] text-muted-foreground">
            {JSON.stringify(finding.metadata, null, 2)}
          </pre>
        </details>
      )}

      <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
        <span>
          <span className="font-semibold">Module:</span> {finding.module_name}
        </span>
        <span>
          <span className="font-semibold">Finding ID:</span>{" "}
          <code>{finding.finding_id}</code>
        </span>
        {finding.acknowledged_by && (
          <span>
            Ack'd by {finding.acknowledged_by}
            {finding.acknowledged_at
              ? ` (${formatTimeAgo(finding.acknowledged_at)} ago)`
              : ""}
          </span>
        )}
        {finding.resolved_by && (
          <span>
            Resolved by {finding.resolved_by}
            {finding.resolution_note ? `: "${finding.resolution_note}"` : ""}
          </span>
        )}
      </div>

      {(canAck || canResolve) && (
        <div className="flex gap-2 pt-1">
          {canAck && (
            <button
              type="button"
              onClick={onAck}
              disabled={ack.isPending}
              className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 text-xs font-medium hover:bg-muted disabled:opacity-50"
            >
              <Check className="h-3.5 w-3.5" />
              Acknowledge
            </button>
          )}
          {canResolve && (
            <button
              type="button"
              onClick={onResolve}
              disabled={resolve.isPending}
              className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 text-xs font-medium hover:bg-muted disabled:opacity-50"
            >
              <CheckCheck className="h-3.5 w-3.5" />
              Resolve
            </button>
          )}
        </div>
      )}
    </div>
  );
}

export function FindingsPage() {
  const [statusFilter, setStatusFilter] = useState<FindingStatus | "all">(
    "open",
  );
  const [severityFilter, setSeverityFilter] = useState<Set<FindingSeverity>>(
    new Set(),
  );
  const [moduleFilter, setModuleFilter] = useState<string>("");
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const filters = useMemo(
    () => ({
      status: statusFilter === "all" ? undefined : statusFilter,
      module: moduleFilter || undefined,
      category: categoryFilter || undefined,
      limit: 200,
    }),
    [statusFilter, moduleFilter, categoryFilter],
  );

  const findingsQ = useFindings(filters);

  const filtered = useMemo(() => {
    if (!findingsQ.data) return [];
    if (severityFilter.size === 0) return findingsQ.data;
    return findingsQ.data.filter((f) => severityFilter.has(f.severity));
  }, [findingsQ.data, severityFilter]);

  const moduleOptions = useMemo(() => {
    const all = (findingsQ.data ?? []).map((f) => f.module_name);
    return Array.from(new Set(all)).sort();
  }, [findingsQ.data]);

  const toggleSeverity = (s: FindingSeverity) => {
    setSeverityFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  const columns: Column<Finding>[] = [
    {
      key: "severity",
      header: "Severity",
      width: "100px",
      render: (f) => (
        <span
          className={cn(
            "text-xs font-semibold uppercase",
            findingSeverityColor(f.severity),
          )}
        >
          {f.severity}
        </span>
      ),
      sortValue: (f) => f.severity,
    },
    {
      key: "module",
      header: "Module",
      width: "140px",
      render: (f) => (
        <span className="text-xs font-mono text-muted-foreground">
          {f.module_name}
        </span>
      ),
      sortValue: (f) => f.module_name,
    },
    {
      key: "title",
      header: "Title",
      render: (f) => <span className="text-sm">{f.title}</span>,
      sortValue: (f) => f.title,
    },
    {
      key: "category",
      header: "Category",
      width: "120px",
      render: (f) => (
        <span className="text-xs text-muted-foreground">{f.category}</span>
      ),
      sortValue: (f) => f.category,
    },
    {
      key: "devices",
      header: "Devices",
      width: "200px",
      render: (f) =>
        f.device_macs.length === 0 ? (
          <span className="text-xs text-muted-foreground">—</span>
        ) : (
          <div className="flex flex-wrap gap-1">
            {f.device_macs.slice(0, 3).map((mac) => (
              <DeviceLink key={mac} mac={mac} />
            ))}
            {f.device_macs.length > 3 && (
              <span className="text-xs text-muted-foreground">
                +{f.device_macs.length - 3}
              </span>
            )}
          </div>
        ),
      sortValue: (f) => f.device_macs.join(","),
    },
    {
      key: "status",
      header: "Status",
      width: "120px",
      render: (f) => (
        <span
          className={cn(
            "inline-block rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase",
            statusBadge(f.status),
          )}
        >
          {f.status}
        </span>
      ),
      sortValue: (f) => f.status,
    },
    {
      key: "age",
      header: "Age",
      width: "70px",
      render: (f) => (
        <span className="text-xs text-muted-foreground">
          {formatTimeAgo(f.timestamp)}
        </span>
      ),
      sortValue: (f) => -f.timestamp,
    },
  ];

  return (
    <PageShell
      title="Findings"
      onRefresh={() => findingsQ.refetch()}
      isRefreshing={findingsQ.isFetching}
    >
      <div className="mb-4 space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <Filter className="h-4 w-4 text-muted-foreground" />
          {STATUS_FILTERS.map((s) => (
            <button
              key={s.value}
              type="button"
              onClick={() => setStatusFilter(s.value)}
              className={cn(
                "rounded-md border px-3 py-1 text-xs font-medium",
                statusFilter === s.value
                  ? "border-primary bg-primary/10 text-primary"
                  : "border-border bg-background text-muted-foreground hover:bg-muted",
              )}
            >
              {s.label}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-muted-foreground">Severity:</span>
          {SEVERITIES.map((s) => {
            const active = severityFilter.has(s);
            return (
              <button
                key={s}
                type="button"
                onClick={() => toggleSeverity(s)}
                className={cn(
                  "rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase",
                  active
                    ? cn(findingSeverityBg(s), findingSeverityColor(s))
                    : "border-border bg-background text-muted-foreground hover:bg-muted",
                )}
              >
                {s}
              </button>
            );
          })}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            value={moduleFilter}
            onChange={(e) => setModuleFilter(e.target.value)}
            className="rounded-md border border-border bg-background px-2 py-1 text-xs"
          >
            <option value="">All modules</option>
            {moduleOptions.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
          <input
            type="text"
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            placeholder="Category…"
            className="rounded-md border border-border bg-background px-2 py-1 text-xs"
          />
        </div>
      </div>

      {findingsQ.isLoading && <LoadingSpinner />}
      {findingsQ.error && (
        <ErrorDisplay
          message={findingsQ.error.message}
          onRetry={() => findingsQ.refetch()}
        />
      )}
      {findingsQ.data && (
        <DataTable
          columns={columns}
          data={filtered}
          rowKey={(f) => String(f.id)}
          emptyMessage="No findings match the current filters."
          defaultSort={{ key: "age", asc: true }}
          searchable
          searchPlaceholder="Search title / module / category…"
          onRowClick={(f) =>
            setExpandedId((prev) => (prev === f.id ? null : f.id))
          }
          expandedRow={(f) =>
            expandedId === f.id ? <FindingDetail finding={f} /> : null
          }
        />
      )}
    </PageShell>
  );
}
