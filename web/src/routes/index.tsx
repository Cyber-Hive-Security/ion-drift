import { useState, useCallback } from "react";
import { useNavigate, Link } from "@tanstack/react-router";
import {
  useSystemResources,
  useTraffic,
  useDhcpLeases,
  useMetricsHistory,
  useConnectionSummary,
  useFirewallDrops,
} from "@/api/queries";
import { UptimeCard } from "@/components/dashboard/uptime-card";
import { TrafficCard } from "@/components/dashboard/traffic-card";
import { DhcpCard } from "@/components/dashboard/dhcp-card";
import { ConnectionsCard } from "@/components/dashboard/connections-card";
import { FirewallDropsCard } from "@/components/dashboard/firewall-drops-card";
import { VlanActivitySection } from "@/components/dashboard/vlan-activity";
import { VlanTrafficBreakdown } from "@/components/dashboard/vlan-sankey";
import { DirectionalPortSankeys } from "@/features/world-map/port-sankey";
import { NetworkDevicesCard } from "@/components/dashboard/network-devices-card";
import { IdentityOverviewCard } from "@/components/dashboard/identity-overview-card";
import { InvestigationCard } from "@/components/dashboard/investigation-card";
import { ScanPressureCard } from "@/components/dashboard/scan-pressure-card";
import { PolicyDeviationsCard } from "@/components/dashboard/policy-deviations-card";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { PageShell } from "@/components/layout/page-shell";
import { DashboardHelp } from "@/components/help-content";
import { StatCard } from "@/components/stat-card";
import { CardErrorBoundary } from "@/components/card-error-boundary";
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
  const navigate = useNavigate();
  const system = useSystemResources();
  const traffic = useTraffic();
  const dhcp = useDhcpLeases({ polling: true });
  const connections = useConnectionSummary();
  const drops = useFirewallDrops();
  const handleSankeyClick = useCallback((srcVlanId: string, dstVlanId: string) => {
    // VLAN IDs are resolved by the backend from the router's interface/vlan table —
    // no regex parsing of interface names needed.
    navigate({ to: "/sankey" as "/", search: { vlan: srcVlanId, dest: dstVlanId } });
  }, [navigate]);
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
    <PageShell title="Dashboard" help={<DashboardHelp />}>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        <CardErrorBoundary name="Firewall Drops">
          {drops.data ? <Link to="/firewall" className="block"><FirewallDropsCard data={drops.data} /></Link> : <CardSkeleton title="Firewall Drops" />}
        </CardErrorBoundary>
        <CardErrorBoundary name="WAN Traffic">
          {traffic.data ? <Link to="/connections" className="block"><TrafficCard data={traffic.data} /></Link> : <CardSkeleton title="WAN Traffic" />}
        </CardErrorBoundary>
        <CardErrorBoundary name="Network Devices">
          <NetworkDevicesCard />
        </CardErrorBoundary>
        <CardErrorBoundary name="Connections">
          {connections.data ? <ConnectionsCard data={connections.data} /> : <CardSkeleton title="Connections" />}
        </CardErrorBoundary>
        <CardErrorBoundary name="Identity Overview">
          <IdentityOverviewCard />
        </CardErrorBoundary>
        <CardErrorBoundary name="DHCP Leases">
          {dhcp.data ? <DhcpCard data={dhcp.data} /> : <CardSkeleton title="DHCP Leases" />}
        </CardErrorBoundary>
        <CardErrorBoundary name="Investigations">
          <InvestigationCard />
        </CardErrorBoundary>
        <CardErrorBoundary name="WAN Scan Pressure">
          <ScanPressureCard />
        </CardErrorBoundary>
        <CardErrorBoundary name="Policy Deviations">
          <PolicyDeviationsCard />
        </CardErrorBoundary>
      </div>

      <CardErrorBoundary name="VLAN Activity">
        <VlanActivitySection />
      </CardErrorBoundary>

      <CardErrorBoundary name="System History">
        <SystemHistorySection />
      </CardErrorBoundary>

      <CardErrorBoundary name="VLAN Traffic Breakdown">
        <div className="mt-6">
          <VlanTrafficBreakdown onLinkClick={handleSankeyClick} />
        </div>
      </CardErrorBoundary>

      <CardErrorBoundary name="Port Sankeys">
        <div className="mt-6">
          <DirectionalPortSankeys
            days={1}
            onFlowClick={(protocol, port) => {
              navigate({ to: "/connections" as "/", search: { protocol, dst_port: port, tab: "connections" } });
            }}
          />
        </div>
      </CardErrorBoundary>

      <div className="mt-6 flex justify-end">
        {system.data && <div className="w-full md:w-1/2 xl:w-1/3"><UptimeCard data={system.data} /></div>}
      </div>
    </PageShell>
  );
}
