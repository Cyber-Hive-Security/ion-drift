import {
  useSystemResources,
  useTraffic,
  useSpeedtestLatest,
  useDhcpLeases,
} from "@/api/queries";
import { CpuCard } from "@/components/dashboard/cpu-card";
import { MemoryCard } from "@/components/dashboard/memory-card";
import { UptimeCard } from "@/components/dashboard/uptime-card";
import { TrafficCard } from "@/components/dashboard/traffic-card";
import { SpeedtestCard } from "@/components/dashboard/speedtest-card";
import { DhcpCard } from "@/components/dashboard/dhcp-card";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { PageShell } from "@/components/layout/page-shell";
import { StatCard } from "@/components/stat-card";
import { Loader2 } from "lucide-react";

function CardSkeleton({ title }: { title: string }) {
  return (
    <StatCard title={title} icon={<Loader2 className="h-4 w-4 animate-spin" />}>
      <div className="flex h-12 items-center justify-center text-sm text-muted-foreground">
        Loading...
      </div>
    </StatCard>
  );
}

export function DashboardPage() {
  const system = useSystemResources();
  const traffic = useTraffic();
  const speedtest = useSpeedtestLatest();
  const dhcp = useDhcpLeases({ polling: true });

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
        {traffic.data ? <TrafficCard data={traffic.data} /> : <CardSkeleton title="WAN Traffic" />}
        <SpeedtestCard data={speedtest.data ?? null} />
        {dhcp.data ? <DhcpCard data={dhcp.data} /> : <CardSkeleton title="DHCP Leases" />}
      </div>
    </PageShell>
  );
}
