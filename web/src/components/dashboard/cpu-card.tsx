import { Cpu } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { cn } from "@/lib/utils";
import { percentColor } from "@/lib/format";
import { useMetricsHistory } from "@/api/queries";
import { AreaChart, Area, ResponsiveContainer } from "recharts";
import type { SystemResource } from "@/api/types";

export function CpuCard({ data }: { data: SystemResource }) {
  const load = data["cpu-load"];
  const history = useMetricsHistory("24h");

  const chartData = (history.data ?? []).map((p) => ({
    t: p.timestamp,
    v: p.cpu_load,
  }));

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
      {chartData.length > 1 && (
        <div className="mt-3" style={{ height: 60 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="cpuGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="oklch(0.65 0.2 145)" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="oklch(0.65 0.2 145)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <Area
                type="monotone"
                dataKey="v"
                stroke="oklch(0.65 0.2 145)"
                strokeWidth={1.5}
                fill="url(#cpuGrad)"
                dot={false}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
      <p className="mt-2 text-xs text-muted-foreground">
        {data.cpu} &middot; {data["cpu-count"]} cores &middot;{" "}
        {data["cpu-frequency"]} MHz
      </p>
    </StatCard>
  );
}
