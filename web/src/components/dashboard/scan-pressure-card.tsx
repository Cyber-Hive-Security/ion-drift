import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/api/client";

interface WanScanBucket {
  bucket: number;
  total_probes: number;
  unique_sources: number;
  unique_ports: number;
  top_ports: string | null;
  top_countries: string | null;
}

function useWanScanPressure(hours = 24) {
  return useQuery({
    queryKey: ["wan-scan-pressure", hours],
    queryFn: () => apiFetch<WanScanBucket[]>(`/api/behavior/wan-scan-pressure?hours=${hours}`),
    refetchInterval: 60_000,
  });
}

function Sparkline({ data, height = 40 }: { data: number[]; height?: number }) {
  if (data.length < 2) return null;
  const max = data.reduce((m, v) => Math.max(m, v), 1);
  const width = 200;
  const points = data.map((v, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = height - (v / max) * height;
    return `${x},${y}`;
  }).join(" ");
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full" style={{ height }}>
      <polyline
        points={points}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        className="text-primary"
      />
    </svg>
  );
}

export function ScanPressureCard() {
  const { data, isLoading } = useWanScanPressure(24);

  if (isLoading || !data) {
    return (
      <div className="rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold text-muted-foreground">WAN Scan Pressure</h3>
        <p className="mt-2 text-xs text-muted-foreground">Loading...</p>
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold text-muted-foreground">WAN Scan Pressure</h3>
        <p className="mt-2 text-xs text-muted-foreground">No scan data collected yet</p>
      </div>
    );
  }

  const totalProbes = data.reduce((sum, b) => sum + b.total_probes, 0);
  const avgPerHour = data.length > 0 ? Math.round(totalProbes / data.length) : 0;
  const sparkData = data.map((b) => b.total_probes);

  // Get top ports from the most recent bucket
  const lastBucket = data[data.length - 1];
  let topPorts: { port: number; count: number }[] = [];
  if (lastBucket?.top_ports) {
    try { topPorts = JSON.parse(lastBucket.top_ports); } catch {}
  }
  let topCountries: { country: string; count: number }[] = [];
  if (lastBucket?.top_countries) {
    try { topCountries = JSON.parse(lastBucket.top_countries); } catch {}
  }

  return (
    <div className="rounded-lg border border-border p-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-muted-foreground">WAN Scan Pressure</h3>
        <span className="text-xs text-muted-foreground">24h</span>
      </div>
      <div className="mt-2 flex items-baseline gap-2">
        <span className="text-2xl font-bold">{totalProbes.toLocaleString()}</span>
        <span className="text-xs text-muted-foreground">probes ({avgPerHour}/hr avg)</span>
      </div>
      <div className="mt-2">
        <Sparkline data={sparkData} />
      </div>
      <div className="mt-3 flex gap-4 text-xs text-muted-foreground">
        {topPorts.length > 0 && (
          <div>
            <span className="font-medium">Top ports: </span>
            {topPorts.slice(0, 5).map((p) => p.port).join(", ")}
          </div>
        )}
        {topCountries.length > 0 && (
          <div>
            <span className="font-medium">Top sources: </span>
            {topCountries.slice(0, 3).map((c) => c.country).join(", ")}
          </div>
        )}
      </div>
    </div>
  );
}
