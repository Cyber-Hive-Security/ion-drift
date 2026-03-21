import { useState, useMemo, useCallback } from "react";
import { usePageViews, useDiagnosticReport } from "@/api/queries";
import { PageShell } from "@/components/layout/page-shell";
import { LoadingSpinner } from "@/components/loading-spinner";
import { Loader2, Download, Copy, X, BarChart3 } from "lucide-react";
import type { DiagnosticReport, PageViewEntry } from "@/api/types";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

// ── Helpers ──────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function formatNumber(n: number | null | undefined): string {
  return (n ?? 0).toLocaleString();
}

const PAGE_LABELS: Record<string, string> = {
  dashboard: "Dashboard",
  interfaces: "Interfaces",
  ip: "IP",
  firewall: "Firewall",
  connections: "Connections",
  logs: "Logs",
  behavior: "Behavior",
  policy: "Policy",
  history: "History",
  settings: "Settings",
  statistics: "Statistics",
  topology: "Topology",
  identity: "Identities",
  backbone: "Backbone",
  inference: "Inference",
  investigation: "Investigation",
  "switch-detail": "Switch Detail",
  "setup-wizard": "Setup Wizard",
};

// ── Page View Bar Chart ──────────────────────────────────────

function aggregateDailyViews(entries: PageViewEntry[]) {
  const byDate = new Map<string, number>();
  for (const e of entries) {
    byDate.set(e.view_date, (byDate.get(e.view_date) ?? 0) + e.view_count);
  }
  return Array.from(byDate.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([date, views]) => ({
      date: new Date(date).toLocaleDateString([], { month: "short", day: "numeric" }),
      views,
    }));
}

function aggregateByPage(entries: PageViewEntry[]) {
  const byPage = new Map<string, number>();
  for (const e of entries) {
    byPage.set(e.page, (byPage.get(e.page) ?? 0) + e.view_count);
  }
  return Array.from(byPage.entries())
    .sort(([, a], [, b]) => b - a)
    .map(([page, views]) => ({ page, views }));
}

function PageViewsChart({ data }: { data: ReturnType<typeof aggregateDailyViews> }) {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <h3 className="mb-3 text-sm font-medium text-muted-foreground">
        Daily Page Views (Last 30 Days)
      </h3>
      {data.length > 0 ? (
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0 0)" />
            <XAxis
              dataKey="date"
              tick={{ fontSize: 11, fill: "oklch(0.55 0 0)" }}
              interval="preserveStartEnd"
            />
            <YAxis
              tick={{ fontSize: 11, fill: "oklch(0.55 0 0)" }}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "oklch(0.15 0.01 260)",
                border: "1px solid oklch(0.25 0 0)",
                borderRadius: "6px",
                fontSize: "12px",
              }}
            />
            <Bar
              dataKey="views"
              fill="oklch(0.65 0.18 250)"
              radius={[3, 3, 0, 0]}
              isAnimationActive={false}
            />
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <div className="flex h-[220px] items-center justify-center text-sm text-muted-foreground">
          No page view data yet. Views will appear as you navigate.
        </div>
      )}
    </div>
  );
}

function PageViewCards({ data }: { data: ReturnType<typeof aggregateByPage> }) {
  if (data.length === 0) return null;
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6">
      {data.map(({ page, views }) => (
        <div
          key={page}
          className="rounded-lg border border-border bg-card p-3 text-center"
        >
          <div className="text-xs text-muted-foreground">
            {PAGE_LABELS[page] ?? page}
          </div>
          <div className="mt-1 text-2xl font-bold tabular-nums">
            {formatNumber(views)}
          </div>
          <div className="text-[10px] text-muted-foreground">views</div>
        </div>
      ))}
    </div>
  );
}

// ── Report Modal ─────────────────────────────────────────────

function ReportSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mb-4">
      <h4 className="mb-2 border-b border-border pb-1 text-sm font-semibold text-primary">
        {title}
      </h4>
      <div className="space-y-1">{children}</div>
    </div>
  );
}

function ReportRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-mono text-foreground">{value}</span>
    </div>
  );
}

function ReportModal({
  report,
  onClose,
}: {
  report: DiagnosticReport;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);

  const handleDownload = useCallback(() => {
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ion-drift-report-${report.generated_at.slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [report]);

  const handleCopy = useCallback(async () => {
    await navigator.clipboard.writeText(JSON.stringify(report, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [report]);

  const env = report.environment;
  const scale = report.scale;
  const feat = report.feature_adoption;
  const eng = report.engine_health;
  const pv = report.page_views;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="relative mx-4 flex max-h-[85vh] w-full max-w-2xl flex-col rounded-xl border border-border bg-card shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <h3 className="text-lg font-semibold">Diagnostic Report</h3>
          <button
            onClick={onClose}
            className="rounded p-1 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto px-5 py-4">
          <ReportSection title="General">
            <ReportRow label="Generated" value={new Date(report.generated_at).toLocaleString()} />
            <ReportRow label="Version" value={report.version} />
            <ReportRow label="Data Directory" value={env.data_directory} />
            <ReportRow label="Data Dir Size" value={formatBytes(env.data_dir_size_bytes)} />
            <ReportRow label="OIDC Configured" value={env.oidc_configured ? "Yes" : "No"} />
            <ReportRow label="TLS Enabled" value={env.tls_enabled ? "Yes" : "No"} />
          </ReportSection>

          <ReportSection title="Scale">
            <ReportRow label="Network Identities" value={formatNumber(scale.network_identity_count)} />
            <ReportRow label="Connection History Rows" value={formatNumber(scale.connection_history_rows)} />
            <ReportRow label="Connection DB Size" value={formatBytes(scale.connection_db_size_bytes)} />
            <ReportRow label="VLANs Configured" value={formatNumber(scale.vlan_config_count)} />
            <ReportRow label="Syslog Events (Today)" value={formatNumber(scale.syslog_events_today)} />
            <ReportRow label="Syslog Events (Week)" value={formatNumber(scale.syslog_events_week)} />
          </ReportSection>

          <ReportSection title="Feature Adoption">
            <ReportRow label="OIDC" value={feat.oidc_enabled ? "Enabled" : "Disabled"} />
            <ReportRow label="Alert Rules" value={formatNumber(feat.alert_rule_count)} />
            <ReportRow label="Backbone Links" value={formatNumber(feat.backbone_link_count)} />
            <ReportRow label="Human-Confirmed IDs" value={formatNumber(feat.confirmed_identity_count)} />
            <ReportRow label="GeoIP" value={feat.geoip_enabled ? "Enabled" : "Disabled"} />
          </ReportSection>

          <ReportSection title="Behavior Engine">
            <ReportRow label="Total Devices" value={formatNumber(eng.behavior.total_devices)} />
            <ReportRow label="Baselined" value={formatNumber(eng.behavior.baselined)} />
            <ReportRow label="Learning" value={formatNumber(eng.behavior.learning)} />
            <ReportRow label="Sparse" value={formatNumber(eng.behavior.sparse)} />
            <ReportRow label="Pending Anomalies" value={formatNumber(eng.behavior.pending_anomalies)} />
            <ReportRow label="Critical Anomalies" value={formatNumber(eng.behavior.critical_anomalies)} />
            <ReportRow label="Warning Anomalies" value={formatNumber(eng.behavior.warning_anomalies)} />
          </ReportSection>

          <ReportSection title="Investigations (30d)">
            <ReportRow label="Total" value={formatNumber(eng.investigations.total)} />
            <ReportRow label="Benign" value={formatNumber(eng.investigations.benign)} />
            <ReportRow label="Routine" value={formatNumber(eng.investigations.routine)} />
            <ReportRow label="Suspicious" value={formatNumber(eng.investigations.suspicious)} />
            <ReportRow label="Threat" value={formatNumber(eng.investigations.threat)} />
            <ReportRow label="Inconclusive" value={formatNumber(eng.investigations.inconclusive)} />
          </ReportSection>

          <ReportSection title="Page Views">
            <ReportRow label="Period" value={`${pv.days_covered} days`} />
            <ReportRow label="Total Views" value={formatNumber(pv.total_views)} />
            {pv.by_page.map(({ page, total_views }) => (
              <ReportRow
                key={page}
                label={PAGE_LABELS[page] ?? page}
                value={formatNumber(total_views)}
              />
            ))}
          </ReportSection>
        </div>

        {/* Footer */}
        <div className="border-t border-border px-5 py-3">
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleDownload}
              className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground transition-colors hover:bg-primary/90"
            >
              <Download className="h-3.5 w-3.5" />
              Download as JSON
            </button>
            <button
              onClick={handleCopy}
              className="inline-flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            >
              <Copy className="h-3.5 w-3.5" />
              {copied ? "Copied!" : "Copy to Clipboard"}
            </button>
          </div>
          <p className="mt-2 text-xs text-muted-foreground">
            Email your report to{" "}
            <span className="font-mono text-foreground">scott@mycyberhive.com</span>{" "}
            to help us improve Ion Drift.
          </p>
        </div>
      </div>
    </div>
  );
}

// ── Scale & Engine Cards (from report) ───────────────────────

function ScaleCards({ report }: { report: DiagnosticReport }) {
  const s = report.scale;
  const cards = [
    { label: "Network Identities", value: formatNumber(s.network_identity_count) },
    { label: "Connections Tracked", value: formatNumber(s.connection_history_rows) },
    { label: "VLANs", value: formatNumber(s.vlan_config_count) },
    { label: "Syslog Events (Today)", value: formatNumber(s.syslog_events_today) },
  ];
  return (
    <div>
      <h2 className="mb-3 text-lg font-semibold">Scale Metrics</h2>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {cards.map((c) => (
          <div
            key={c.label}
            className="rounded-lg border border-border bg-card p-4 text-center"
          >
            <div className="text-xs text-muted-foreground">{c.label}</div>
            <div className="mt-1 text-2xl font-bold tabular-nums">{c.value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function EngineHealthCards({ report }: { report: DiagnosticReport }) {
  const beh = report.engine_health.behavior;
  const inv = report.engine_health.investigations;
  return (
    <div>
      <h2 className="mb-3 text-lg font-semibold">Engine Health</h2>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
        {/* Behavior */}
        <div className="rounded-lg border border-border bg-card p-4">
          <h3 className="mb-2 text-sm font-medium text-muted-foreground">Behavior Baselines</h3>
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-sm">
              <span>Total Devices</span>
              <span className="font-mono font-bold">{formatNumber(beh.total_devices)}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span>Baselined</span>
              <span className="font-mono font-bold text-success">{formatNumber(beh.baselined)}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span>Learning</span>
              <span className="font-mono font-bold text-blue-400">{formatNumber(beh.learning)}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span>Sparse</span>
              <span className="font-mono font-bold text-muted-foreground">{formatNumber(beh.sparse)}</span>
            </div>
          </div>
        </div>

        {/* Anomalies */}
        <div className="rounded-lg border border-border bg-card p-4">
          <h3 className="mb-2 text-sm font-medium text-muted-foreground">Anomalies</h3>
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-sm">
              <span>Pending</span>
              <span className="font-mono font-bold text-warning">{formatNumber(beh.pending_anomalies)}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span>Critical</span>
              <span className="font-mono font-bold text-destructive">{formatNumber(beh.critical_anomalies)}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span>Warning</span>
              <span className="font-mono font-bold text-warning">{formatNumber(beh.warning_anomalies)}</span>
            </div>
          </div>
        </div>

        {/* Investigations */}
        <div className="rounded-lg border border-border bg-card p-4">
          <h3 className="mb-2 text-sm font-medium text-muted-foreground">Investigations (30d)</h3>
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-sm">
              <span>Total</span>
              <span className="font-mono font-bold">{formatNumber(inv.total)}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span>Benign</span>
              <span className="font-mono font-bold text-success">{formatNumber(inv.benign)}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span>Suspicious</span>
              <span className="font-mono font-bold text-warning">{formatNumber(inv.suspicious)}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span>Threat</span>
              <span className="font-mono font-bold text-destructive">{formatNumber(inv.threat)}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Main Page ────────────────────────────────────────────────

export function StatisticsPage() {
  const pageViews = usePageViews(30);
  const report = useDiagnosticReport();
  const [modalOpen, setModalOpen] = useState(false);

  const dailyData = useMemo(
    () => aggregateDailyViews(pageViews.data ?? []),
    [pageViews.data],
  );
  const byPage = useMemo(
    () => aggregateByPage(pageViews.data ?? []),
    [pageViews.data],
  );

  const handleGenerateReport = useCallback(() => {
    report.refetch().then((result) => {
      if (result.data) setModalOpen(true);
    });
  }, [report]);

  return (
    <PageShell title="Statistics">
      {/* Header actions */}
      <div className="-mt-4 mb-6 flex justify-end">
        <button
          onClick={handleGenerateReport}
          disabled={report.isFetching}
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50"
        >
          {report.isFetching ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <BarChart3 className="h-4 w-4" />
          )}
          Generate Diagnostic Report
        </button>
      </div>

      <div className="space-y-6">
        {/* Page Views Section */}
        <div>
          <h2 className="mb-3 text-lg font-semibold">Page Views</h2>
          {pageViews.isLoading ? (
            <LoadingSpinner />
          ) : (
            <>
              <PageViewsChart data={dailyData} />
              <div className="mt-4">
                <PageViewCards data={byPage} />
              </div>
            </>
          )}
        </div>

        {/* Scale & Engine sections — only when report data exists */}
        {report.data && (
          <>
            <ScaleCards report={report.data} />
            <EngineHealthCards report={report.data} />
          </>
        )}
      </div>

      {/* Report Modal */}
      {modalOpen && report.data && (
        <ReportModal
          report={report.data}
          onClose={() => setModalOpen(false)}
        />
      )}
    </PageShell>
  );
}
