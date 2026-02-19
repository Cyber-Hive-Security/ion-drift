import { Gauge } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { formatMbps, formatTimestamp } from "@/lib/format";
import type { SpeedTestResult } from "@/api/types";

export function SpeedtestCard({
  data,
}: {
  data: SpeedTestResult | null;
}) {
  if (!data) {
    return (
      <StatCard title="Speedtest" icon={<Gauge className="h-4 w-4" />}>
        <p className="text-sm text-muted-foreground">No results yet</p>
      </StatCard>
    );
  }

  return (
    <StatCard title="Speedtest" icon={<Gauge className="h-4 w-4" />}>
      <div className="grid grid-cols-2 gap-4">
        <div>
          <div className="text-xs text-muted-foreground">Download</div>
          <div className="text-xl font-bold text-success">
            {formatMbps(data.median_download_mbps)}
          </div>
        </div>
        <div>
          <div className="text-xs text-muted-foreground">Upload</div>
          <div className="text-xl font-bold text-primary">
            {formatMbps(data.median_upload_mbps)}
          </div>
        </div>
      </div>
      <p className="mt-2 text-xs text-muted-foreground">
        {data.median_latency_ms.toFixed(0)} ms latency &middot;{" "}
        {formatTimestamp(data.timestamp)}
      </p>
    </StatCard>
  );
}
