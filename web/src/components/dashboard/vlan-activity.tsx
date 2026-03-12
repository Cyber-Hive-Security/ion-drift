import { useState, useMemo } from "react";
import { Network, ChevronDown, ChevronRight, Microscope } from "lucide-react";
import { Link } from "@tanstack/react-router";
import { useVlanActivity, useVlanMetricsHistory } from "@/api/queries";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { cn } from "@/lib/utils";
import type { VlanActivityEntry } from "@/api/types";

type Range = "24h" | "7d";

function formatBps(bps: number): string {
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(1)} Gbps`;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbps`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} Kbps`;
  return `${bps} bps`;
}

interface SparkPoint {
  time: string;
  rx: number;
  tx: number;
}

function VlanRow({
  entry,
  sparkData,
  expanded,
  onToggle,
}: {
  entry: VlanActivityEntry;
  sparkData: SparkPoint[];
  expanded: boolean;
  onToggle: () => void;
}) {
  const total = entry.rx_bps + entry.tx_bps;
  const dimmed = total === 0;

  return (
    <div>
      <div
        onClick={onToggle}
        className={cn(
          "flex cursor-pointer items-center gap-3 rounded-md border border-border bg-card px-3 py-2 transition-colors hover:bg-muted/30",
          dimmed && "opacity-40",
          expanded && "rounded-b-none border-b-0",
        )}
      >
        <span className="text-muted-foreground">
          {expanded ? (
            <ChevronDown className="h-3 w-3" />
          ) : (
            <ChevronRight className="h-3 w-3" />
          )}
        </span>
        <span className="w-24 shrink-0 truncate text-xs font-medium text-foreground">
          {entry.name}
        </span>
        <div className="w-[120px] shrink-0">
          {sparkData.length > 1 ? (
            <ResponsiveContainer width={120} height={24}>
              <AreaChart data={sparkData}>
                <Area
                  type="monotone"
                  dataKey="rx"
                  stroke="#21D07A"
                  strokeWidth={1}
                  fill="#21D07A"
                  fillOpacity={0.15}
                  dot={false}
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-6" />
          )}
        </div>
        <div className="flex flex-col text-right text-[10px] text-muted-foreground">
          <span>
            <span className="text-emerald-400">&#x25B2;</span>{" "}
            {formatBps(entry.rx_bps)}
          </span>
          <span>
            <span className="text-primary">&#x25BC;</span>{" "}
            {formatBps(entry.tx_bps)}
          </span>
        </div>
        <Link
          to="/sankey"
          search={{ vlan: entry.name }}
          onClick={(e) => e.stopPropagation()}
          className="ml-auto rounded p-1 text-muted-foreground hover:bg-primary/15 hover:text-primary"
          title="Investigate VLAN traffic"
        >
          <Microscope className="h-3.5 w-3.5" />
        </Link>
      </div>
      {expanded && sparkData.length > 1 && (
        <div className="rounded-b-md border border-t-0 border-border bg-card p-3">
          <ResponsiveContainer width="100%" height={120}>
            <AreaChart data={sparkData}>
              <defs>
                <linearGradient id={`vlanRx-${entry.name}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#21D07A" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#21D07A" stopOpacity={0} />
                </linearGradient>
                <linearGradient id={`vlanTx-${entry.name}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#2FA4FF" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#2FA4FF" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis
                dataKey="time"
                tick={{ fill: "#8A929D", fontSize: 9 }}
                interval="preserveStartEnd"
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: "#8A929D", fontSize: 9 }}
                tickFormatter={(v: number) => formatBps(v)}
                width={60}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#2C3038",
                  border: "1px solid #444B55",
                  borderRadius: "6px",
                  color: "#E6EDF3",
                  fontSize: "11px",
                }}
                formatter={(value: number, name: string) => [
                  formatBps(value),
                  name === "rx" ? "RX" : "TX",
                ]}
              />
              <Area
                type="monotone"
                dataKey="rx"
                stroke="#21D07A"
                strokeWidth={1.5}
                fill={`url(#vlanRx-${entry.name})`}
                dot={false}
                isAnimationActive={false}
              />
              <Area
                type="monotone"
                dataKey="tx"
                stroke="#2FA4FF"
                strokeWidth={1.5}
                fill={`url(#vlanTx-${entry.name})`}
                dot={false}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}

export function VlanActivitySection() {
  const [range, setRange] = useState<Range>("24h");
  const [expandedVlan, setExpandedVlan] = useState<string | null>(null);
  const { data: vlans } = useVlanActivity();
  const history = useVlanMetricsHistory(range);

  // Group history points by VLAN name
  const sparkByVlan = useMemo(() => {
    const map: Record<string, SparkPoint[]> = {};
    for (const p of history.data ?? []) {
      if (!map[p.vlan_name]) map[p.vlan_name] = [];
      map[p.vlan_name].push({
        time: new Date(p.timestamp * 1000).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
        }),
        rx: p.rx_bps,
        tx: p.tx_bps,
      });
    }
    return map;
  }, [history.data]);

  if (!vlans) return null;

  // Sort by total throughput descending
  const sorted = [...vlans].sort(
    (a, b) => b.rx_bps + b.tx_bps - (a.rx_bps + a.tx_bps),
  );

  return (
    <div className="mt-6">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Network className="h-4 w-4 text-muted-foreground" />
          <h2 className="text-lg font-semibold">VLAN Activity</h2>
        </div>
        <div className="flex gap-2">
          {(["24h", "7d"] as const).map((r) => (
            <button
              key={r}
              onClick={() => setRange(r)}
              className={cn(
                "rounded-md px-3 py-1 text-sm font-medium transition-colors",
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
      <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
        {sorted.map((entry) => (
          <VlanRow
            key={entry.name}
            entry={entry}
            sparkData={sparkByVlan[entry.name] ?? []}
            expanded={expandedVlan === entry.name}
            onToggle={() =>
              setExpandedVlan(
                expandedVlan === entry.name ? null : entry.name,
              )
            }
          />
        ))}
      </div>
    </div>
  );
}
