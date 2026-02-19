import { ArrowDownUp } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { formatBytes } from "@/lib/format";
import type { LifetimeTraffic } from "@/api/types";

export function TrafficCard({ data }: { data: LifetimeTraffic }) {
  return (
    <StatCard title="WAN Traffic" icon={<ArrowDownUp className="h-4 w-4" />}>
      <div className="grid grid-cols-2 gap-4">
        <div>
          <div className="text-xs text-muted-foreground">Download</div>
          <div className="text-xl font-bold text-success">
            {formatBytes(data.rx_bytes)}
          </div>
        </div>
        <div>
          <div className="text-xs text-muted-foreground">Upload</div>
          <div className="text-xl font-bold text-primary">
            {formatBytes(data.tx_bytes)}
          </div>
        </div>
      </div>
      <p className="mt-2 text-xs text-muted-foreground">
        Lifetime on {data.interface}
      </p>
    </StatCard>
  );
}
