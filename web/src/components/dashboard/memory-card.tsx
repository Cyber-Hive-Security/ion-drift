import { MemoryStick } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { cn } from "@/lib/utils";
import { formatBytes, percentColor } from "@/lib/format";
import type { SystemResource } from "@/api/types";

export function MemoryCard({ data }: { data: SystemResource }) {
  const total = data["total-memory"];
  const free = data["free-memory"];
  const used = total - free;
  const pct = total > 0 ? Math.round((used / total) * 100) : 0;

  return (
    <StatCard title="Memory" icon={<MemoryStick className="h-4 w-4" />}>
      <div className={cn("text-3xl font-bold", percentColor(pct))}>{pct}%</div>
      <div className="mt-2 h-2 overflow-hidden rounded-full bg-muted">
        <div
          className={cn(
            "h-full rounded-full transition-all",
            pct >= 90
              ? "bg-destructive"
              : pct >= 70
                ? "bg-warning"
                : "bg-success",
          )}
          style={{ width: `${pct}%` }}
        />
      </div>
      <p className="mt-2 text-xs text-muted-foreground">
        {formatBytes(used)} / {formatBytes(total)}
      </p>
    </StatCard>
  );
}
