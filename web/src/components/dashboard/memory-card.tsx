import { MemoryStick } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { cn } from "@/lib/utils";
import { formatBytes, percentColor } from "@/lib/format";
import { useMetricsHistory } from "@/api/queries";
import { AreaChart, Area, ResponsiveContainer } from "recharts";
import type { SystemResource } from "@/api/types";

export function MemoryCard({ data }: { data: SystemResource }) {
  const total = data["total-memory"];
  const free = data["free-memory"];
  const used = total - free;
  const pct = total > 0 ? Math.round((used / total) * 100) : 0;
  const history = useMetricsHistory("24h");

  const chartData = (history.data ?? []).map((p) => ({
    t: p.timestamp,
    v: p.memory_total > 0 ? (p.memory_used / p.memory_total) * 100 : 0,
  }));

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
      {chartData.length > 1 && (
        <div className="mt-3" style={{ height: 60 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="memGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="oklch(0.65 0.18 250)" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="oklch(0.65 0.18 250)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <Area
                type="monotone"
                dataKey="v"
                stroke="oklch(0.65 0.18 250)"
                strokeWidth={1.5}
                fill="url(#memGrad)"
                dot={false}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
      <p className="mt-2 text-xs text-muted-foreground">
        {formatBytes(used)} / {formatBytes(total)}
      </p>
    </StatCard>
  );
}
