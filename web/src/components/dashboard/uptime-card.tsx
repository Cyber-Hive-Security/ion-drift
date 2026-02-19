import { Clock } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { formatUptime } from "@/lib/format";
import type { SystemResource } from "@/api/types";

export function UptimeCard({ data }: { data: SystemResource }) {
  return (
    <StatCard title="Uptime" icon={<Clock className="h-4 w-4" />}>
      <div className="text-3xl font-bold text-foreground">
        {formatUptime(data.uptime)}
      </div>
      <p className="mt-2 text-xs text-muted-foreground">
        {data["board-name"]} &middot; RouterOS {data.version}
      </p>
    </StatCard>
  );
}
