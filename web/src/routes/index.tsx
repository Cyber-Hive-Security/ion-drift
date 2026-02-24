import { useState } from "react";
import {
  useSystemResources,
  useTraffic,
  useSpeedtestLatest,
  useDhcpLeases,
  useMetricsHistory,
  useConnectionSummary,
  useFirewallDrops,
} from "@/api/queries";
import { CpuCard } from "@/components/dashboard/cpu-card";
import { MemoryCard } from "@/components/dashboard/memory-card";
import { UptimeCard } from "@/components/dashboard/uptime-card";
import { TrafficCard } from "@/components/dashboard/traffic-card";
import { SpeedtestCard } from "@/components/dashboard/speedtest-card";
import { DhcpCard } from "@/components/dashboard/dhcp-card";
import { ConnectionsCard } from "@/components/dashboard/connections-card";
import { FirewallDropsCard } from "@/components/dashboard/firewall-drops-card";
import { VlanActivitySection } from "@/components/dashboard/vlan-activity";
import { VlanTrafficBreakdown } from "@/components/dashboard/vlan-sankey";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { PageShell } from "@/components/layout/page-shell";
import { StatCard } from "@/components/stat-card";
import { cn } from "@/lib/utils";
import { Loader2 } from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

function CardSkeleton({ title }: { title: string }) {
  return (
    <StatCard title={title} icon={<Loader2 className="h-4 w-4 animate-spin" />}>
      <div className="flex h-12 items-center justify-center text-sm text-muted-foreground">
        Loading...
      </div>
    </StatCard>
  );
}

type HistoryRange = "24h" | "7d";

function SystemHistorySection() {
  const [range, setRange] = useState<HistoryRange>("24h");
  const history = useMetricsHistory(range);
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
    cpu: p.cpu_load,
    memory:
      p.memory_total > 0
        ? Number(((p.memory_used / p.memory_total) * 100).toFixed(1))
        : 0,
  }));

  return (
    <div className="mt-6">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-lg font-semibold">System History</h2>
        <div className="flex gap-2">
          {(["24h", "7d"] as const).map((r) => (
            <button
              key={r}
              onClick={() => setRange(r)}
              className={cn(
                "rounded-md px-3 py-1 text-sm font-medium transition-colors",
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
      {chartData.length > 1 ? (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="rounded-lg border border-border bg-card p-4">
            <h3 className="mb-2 text-sm font-medium text-muted-foreground">
              CPU Load
            </h3>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="sysCpuGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="oklch(0.65 0.2 145)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="oklch(0.65 0.2 145)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.015 285)" />
                <XAxis
                  dataKey="time"
                  tick={{ fill: "oklch(0.65 0.01 285)", fontSize: 11 }}
                  interval="preserveStartEnd"
                />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fill: "oklch(0.65 0.01 285)", fontSize: 11 }}
                  tickFormatter={(v: number) => `${v}%`}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "oklch(0.175 0.015 285)",
                    border: "1px solid oklch(0.3 0.015 285)",
                    borderRadius: "6px",
                    color: "oklch(0.95 0.01 285)",
                    fontSize: "12px",
                  }}
                  formatter={(value: number) => [`${value}%`, "CPU"]}
                />
                <Area
                  type="monotone"
                  dataKey="cpu"
                  stroke="oklch(0.65 0.2 145)"
                  strokeWidth={2}
                  fill="url(#sysCpuGrad)"
                  dot={false}
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="rounded-lg border border-border bg-card p-4">
            <h3 className="mb-2 text-sm font-medium text-muted-foreground">
              Memory Usage
            </h3>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="sysMemGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="oklch(0.65 0.18 250)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="oklch(0.65 0.18 250)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.015 285)" />
                <XAxis
                  dataKey="time"
                  tick={{ fill: "oklch(0.65 0.01 285)", fontSize: 11 }}
                  interval="preserveStartEnd"
                />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fill: "oklch(0.65 0.01 285)", fontSize: 11 }}
                  tickFormatter={(v: number) => `${v}%`}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "oklch(0.175 0.015 285)",
                    border: "1px solid oklch(0.3 0.015 285)",
                    borderRadius: "6px",
                    color: "oklch(0.95 0.01 285)",
                    fontSize: "12px",
                  }}
                  formatter={(value: number) => [`${value}%`, "Memory"]}
                />
                <Area
                  type="monotone"
                  dataKey="memory"
                  stroke="oklch(0.65 0.18 250)"
                  strokeWidth={2}
                  fill="url(#sysMemGrad)"
                  dot={false}
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      ) : (
        <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
          Collecting metrics data... Charts will appear after a few minutes.
        </div>
      )}
    </div>
  );
}

export function DashboardPage() {
  const system = useSystemResources();
  const traffic = useTraffic();
  const speedtest = useSpeedtestLatest();
  const dhcp = useDhcpLeases({ polling: true });
  const connections = useConnectionSummary();
  const drops = useFirewallDrops();

  if (system.isLoading) return <LoadingSpinner />;
  if (system.error)
    return (
      <PageShell title="Dashboard">
        <ErrorDisplay
          message={system.error.message}
          onRetry={() => system.refetch()}
        />
      </PageShell>
    );

  return (
    <PageShell title="Dashboard">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {system.data && <CpuCard data={system.data} />}
        {system.data && <MemoryCard data={system.data} />}
        {system.data && <UptimeCard data={system.data} />}
        {drops.data ? <FirewallDropsCard data={drops.data} /> : <CardSkeleton title="Firewall Drops" />}
        {traffic.data ? <TrafficCard data={traffic.data} /> : <CardSkeleton title="WAN Traffic" />}
        <SpeedtestCard data={speedtest.data && "median_download_mbps" in speedtest.data ? speedtest.data : null} />
        {dhcp.data ? <DhcpCard data={dhcp.data} /> : <CardSkeleton title="DHCP Leases" />}
        {connections.data ? <ConnectionsCard data={connections.data} /> : <CardSkeleton title="Connections" />}
      </div>

      <VlanActivitySection />

      <SystemHistorySection />

      <div className="mt-6">
        <VlanTrafficBreakdown />
      </div>
    </PageShell>
  );
}
