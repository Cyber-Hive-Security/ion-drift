import { ArrowDownUp } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { formatBytes } from "@/lib/format";
import { useLiveTraffic } from "@/api/queries";
import {
  AreaChart,
  Area,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import type { LifetimeTraffic } from "@/api/types";

function formatBps(bps: number): string {
  if (bps <= 0) return "0 bps";
  const units = ["bps", "Kbps", "Mbps", "Gbps"];
  const i = Math.floor(Math.log(bps) / Math.log(1000));
  return `${(bps / Math.pow(1000, i)).toFixed(1)} ${units[i]}`;
}

export function TrafficCard({ data }: { data: LifetimeTraffic }) {
  const live = useLiveTraffic();
  const samples = live.data ?? [];

  const chartData = samples.map((s) => ({
    t: s.timestamp,
    rx: s.rx_bps,
    tx: s.tx_bps,
  }));

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
      {chartData.length > 1 && (
        <>
          <div className="mt-3" style={{ height: 80 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="rxGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#21D07A" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#21D07A" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="txGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#2FA4FF" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#2FA4FF" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#2C3038",
                    border: "1px solid #444B55",
                    borderRadius: "6px",
                    color: "#E6EDF3",
                    fontSize: "12px",
                  }}
                  formatter={(value: number, name: string) => [
                    formatBps(value),
                    name === "rx" ? "Download" : "Upload",
                  ]}
                  labelFormatter={() => ""}
                />
                <Area
                  type="monotone"
                  dataKey="rx"
                  stroke="#21D07A"
                  strokeWidth={1.5}
                  fill="url(#rxGrad)"
                  dot={false}
                  isAnimationActive={false}
                />
                <Area
                  type="monotone"
                  dataKey="tx"
                  stroke="#2FA4FF"
                  strokeWidth={1.5}
                  fill="url(#txGrad)"
                  dot={false}
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            Live bandwidth &middot; last {Math.round(chartData.length * 10 / 60)} min
          </p>
        </>
      )}
      <p className="mt-2 text-xs text-muted-foreground">
        Lifetime on {data.interface}
      </p>
    </StatCard>
  );
}
