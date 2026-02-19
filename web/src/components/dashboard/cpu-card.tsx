import { Cpu } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { cn } from "@/lib/utils";
import { percentColor } from "@/lib/format";
import type { SystemResource } from "@/api/types";

export function CpuCard({ data }: { data: SystemResource }) {
  const load = data["cpu-load"];
  return (
    <StatCard title="CPU Load" icon={<Cpu className="h-4 w-4" />}>
      <div className={cn("text-3xl font-bold", percentColor(load))}>
        {load}%
      </div>
      <div className="mt-2 h-2 overflow-hidden rounded-full bg-muted">
        <div
          className={cn(
            "h-full rounded-full transition-all",
            load >= 90
              ? "bg-destructive"
              : load >= 70
                ? "bg-warning"
                : "bg-success",
          )}
          style={{ width: `${load}%` }}
        />
      </div>
      <p className="mt-2 text-xs text-muted-foreground">
        {data.cpu} &middot; {data["cpu-count"]} cores &middot;{" "}
        {data["cpu-frequency"]} MHz
      </p>
    </StatCard>
  );
}
