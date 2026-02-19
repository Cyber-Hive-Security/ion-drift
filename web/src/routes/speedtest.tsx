import { useSpeedtestLatest, useSpeedtestHistory } from "@/api/queries";
import { PageShell } from "@/components/layout/page-shell";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { StatCard } from "@/components/stat-card";
import { formatMbps, formatTimestamp } from "@/lib/format";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { Gauge, Wifi } from "lucide-react";

export function SpeedtestPage() {
  const latest = useSpeedtestLatest();
  const history = useSpeedtestHistory(20);

  const chartData = (history.data ?? [])
    .slice()
    .reverse()
    .map((r) => ({
      date: new Date(r.timestamp * 1000).toLocaleDateString(),
      download: Number(r.median_download_mbps.toFixed(1)),
      upload: Number(r.median_upload_mbps.toFixed(1)),
    }));

  return (
    <PageShell
      title="Speed Test"
      onRefresh={() => {
        latest.refetch();
        history.refetch();
      }}
      isRefreshing={latest.isFetching || history.isFetching}
    >
      {latest.isLoading && <LoadingSpinner />}
      {latest.error && (
        <ErrorDisplay
          message={latest.error.message}
          onRetry={() => latest.refetch()}
        />
      )}

      {latest.data && (
        <>
          {/* Latest result summary */}
          <div className="mb-6 grid grid-cols-1 gap-4 md:grid-cols-3">
            <StatCard title="Download" icon={<Gauge className="h-4 w-4" />}>
              <div className="text-3xl font-bold text-success">
                {formatMbps(latest.data.median_download_mbps)}
              </div>
            </StatCard>
            <StatCard title="Upload" icon={<Gauge className="h-4 w-4" />}>
              <div className="text-3xl font-bold text-primary">
                {formatMbps(latest.data.median_upload_mbps)}
              </div>
            </StatCard>
            <StatCard title="Latency" icon={<Wifi className="h-4 w-4" />}>
              <div className="text-3xl font-bold text-foreground">
                {latest.data.median_latency_ms.toFixed(0)} ms
              </div>
            </StatCard>
          </div>

          {/* Per-provider breakdown */}
          <h2 className="mb-3 text-lg font-semibold">Provider Results</h2>
          <div className="mb-6 grid grid-cols-1 gap-3 md:grid-cols-3">
            {latest.data.providers.map((p) => (
              <div
                key={p.provider}
                className="rounded-lg border border-border bg-card p-3"
              >
                <div className="mb-2 text-sm font-medium capitalize">
                  {p.provider}
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-muted-foreground">Down:</span>{" "}
                    <span className="font-medium">
                      {formatMbps(p.download_mbps)}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Up:</span>{" "}
                    <span className="font-medium">
                      {formatMbps(p.upload_mbps)}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Latency:</span>{" "}
                    <span className="font-medium">
                      {p.latency_ms.toFixed(0)} ms
                    </span>
                  </div>
                  {p.server_location && (
                    <div>
                      <span className="text-muted-foreground">Server:</span>{" "}
                      <span className="font-medium">{p.server_location}</span>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>

          <p className="mb-6 text-xs text-muted-foreground">
            Last test: {formatTimestamp(latest.data.timestamp)}
          </p>
        </>
      )}

      {/* History chart */}
      {chartData.length > 1 && (
        <>
          <h2 className="mb-3 text-lg font-semibold">History</h2>
          <div className="mb-6 rounded-lg border border-border bg-card p-4">
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.015 285)" />
                <XAxis
                  dataKey="date"
                  tick={{ fill: "oklch(0.65 0.01 285)", fontSize: 12 }}
                />
                <YAxis
                  tick={{ fill: "oklch(0.65 0.01 285)", fontSize: 12 }}
                  tickFormatter={(v: number) => `${v}`}
                  label={{
                    value: "Mbps",
                    angle: -90,
                    position: "insideLeft",
                    fill: "oklch(0.65 0.01 285)",
                  }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "oklch(0.175 0.015 285)",
                    border: "1px solid oklch(0.3 0.015 285)",
                    borderRadius: "6px",
                    color: "oklch(0.95 0.01 285)",
                  }}
                />
                <Legend />
                <Line
                  type="monotone"
                  dataKey="download"
                  stroke="oklch(0.65 0.2 145)"
                  strokeWidth={2}
                  dot={{ r: 3 }}
                  name="Download"
                />
                <Line
                  type="monotone"
                  dataKey="upload"
                  stroke="oklch(0.65 0.18 250)"
                  strokeWidth={2}
                  dot={{ r: 3 }}
                  name="Upload"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </>
      )}

      {/* History table */}
      {history.data && history.data.length > 0 && (
        <>
          <h2 className="mb-3 text-lg font-semibold">Recent Results</h2>
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/50">
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                    Date
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                    Download
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                    Upload
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                    Latency
                  </th>
                </tr>
              </thead>
              <tbody>
                {history.data.map((r, i) => (
                  <tr
                    key={i}
                    className="border-b border-border/50 hover:bg-muted/30"
                  >
                    <td className="px-3 py-2 text-xs text-muted-foreground">
                      {formatTimestamp(r.timestamp)}
                    </td>
                    <td className="px-3 py-2 font-medium text-success">
                      {formatMbps(r.median_download_mbps)}
                    </td>
                    <td className="px-3 py-2 font-medium text-primary">
                      {formatMbps(r.median_upload_mbps)}
                    </td>
                    <td className="px-3 py-2">
                      {r.median_latency_ms.toFixed(0)} ms
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </PageShell>
  );
}
