import { useState } from "react";
import { Shield } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { formatBytes } from "@/lib/format";
import { countryFlag } from "@/lib/country";
import { AreaChart, Area, ResponsiveContainer, Tooltip, XAxis } from "recharts";
import { useDropsHistory } from "@/api/queries";
import { cn } from "@/lib/utils";
import type { FirewallDropsSummary } from "@/api/types";

function compactNumber(n: number): string {
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}G`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

type Range = "24h" | "7d";

export function FirewallDropsCard({ data }: { data: FirewallDropsSummary }) {
  const [range, setRange] = useState<Range>("24h");
  const history = useDropsHistory(range);

  // Compute deltas between consecutive points for the sparkline
  const sparkData = (history.data ?? []).map((p, i, arr) => {
    const prev = i > 0 ? arr[i - 1] : p;
    return {
      time: new Date(p.timestamp * 1000).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      }),
      delta: Math.max(0, p.drop_packets - prev.drop_packets),
    };
  });

  // Color based on recent deltas
  const recent = sparkData.slice(-5);
  const avg =
    recent.length > 0
      ? recent.reduce((s, d) => s + d.delta, 0) / recent.length
      : 0;
  const sparkColor =
    avg > 1000
      ? "oklch(0.65 0.2 30)"
      : avg > 100
        ? "oklch(0.7 0.18 85)"
        : "oklch(0.65 0.2 145)";

  return (
    <StatCard title="Firewall Drops" icon={<Shield className="h-4 w-4" />}>
      <div className="flex items-start justify-between">
        <div className="text-3xl font-bold text-foreground">
          {compactNumber(data.total_drop_packets)}
        </div>
        <div className="flex gap-1">
          {(["24h", "7d"] as const).map((r) => (
            <button
              key={r}
              onClick={() => setRange(r)}
              className={cn(
                "rounded px-1.5 py-0.5 text-[10px] font-medium transition-colors",
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
      <p className="mt-2 text-xs text-muted-foreground">
        packets dropped &middot; {formatBytes(data.total_drop_bytes)}
      </p>
      {data.top_drop_countries.length > 0 && (
        <p className="mt-1 text-xs">
          <span className="text-muted-foreground">Top: </span>
          {data.top_drop_countries.slice(0, 3).map((c, i) => (
            <span key={c.code}>
              {i > 0 && (
                <span className="text-muted-foreground"> &middot; </span>
              )}
              <span
                className={c.flagged ? "text-red-500" : "text-muted-foreground"}
              >
                {countryFlag(c.code)} {c.code} ({compactNumber(c.count)})
              </span>
            </span>
          ))}
        </p>
      )}
      {sparkData.length > 1 && (
        <div className="mt-2">
          <ResponsiveContainer width="100%" height={60}>
            <AreaChart data={sparkData}>
              <defs>
                <linearGradient
                  id="dropSparkGrad"
                  x1="0"
                  y1="0"
                  x2="0"
                  y2="1"
                >
                  <stop offset="5%" stopColor={sparkColor} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={sparkColor} stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" hide />
              <Tooltip
                contentStyle={{
                  backgroundColor: "oklch(0.175 0.015 285)",
                  border: "1px solid oklch(0.3 0.015 285)",
                  borderRadius: "6px",
                  color: "oklch(0.95 0.01 285)",
                  fontSize: "11px",
                }}
                formatter={(value: number) => [
                  compactNumber(value),
                  "new drops",
                ]}
              />
              <Area
                type="monotone"
                dataKey="delta"
                stroke={sparkColor}
                strokeWidth={1.5}
                fill="url(#dropSparkGrad)"
                dot={false}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </StatCard>
  );
}
