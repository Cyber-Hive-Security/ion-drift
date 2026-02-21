import { useRef } from "react";
import { Network } from "lucide-react";
import { useVlanActivity } from "@/api/queries";
import { AreaChart, Area, ResponsiveContainer } from "recharts";
import type { VlanActivityEntry } from "@/api/types";

interface HistorySample {
  rx: number;
}

type VlanHistory = Record<string, HistorySample[]>;

function formatBps(bps: number): string {
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(1)} Gbps`;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbps`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} Kbps`;
  return `${bps} bps`;
}

function VlanRow({
  entry,
  sparkData,
}: {
  entry: VlanActivityEntry;
  sparkData: HistorySample[];
}) {
  const total = entry.rx_bps + entry.tx_bps;
  const dimmed = total === 0;

  return (
    <div
      className={`flex items-center gap-3 rounded-md border border-border bg-card px-3 py-2 ${
        dimmed ? "opacity-40" : ""
      }`}
    >
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
                stroke="oklch(0.65 0.2 145)"
                strokeWidth={1}
                fill="oklch(0.65 0.2 145)"
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
          <span className="text-emerald-400">&#x25B2;</span> {formatBps(entry.rx_bps)}
        </span>
        <span>
          <span className="text-blue-400">&#x25BC;</span> {formatBps(entry.tx_bps)}
        </span>
      </div>
    </div>
  );
}

export function VlanActivitySection() {
  const { data: vlans } = useVlanActivity();
  const historyRef = useRef<VlanHistory>({});

  if (!vlans) return null;

  // Update ring buffers
  const history = historyRef.current;
  for (const v of vlans) {
    if (!history[v.name]) history[v.name] = [];
    history[v.name] = [
      ...history[v.name].slice(-49),
      { rx: v.rx_bps },
    ];
  }

  // Sort by total throughput descending
  const sorted = [...vlans].sort(
    (a, b) => b.rx_bps + b.tx_bps - (a.rx_bps + a.tx_bps),
  );

  return (
    <div className="mt-6">
      <div className="mb-3 flex items-center gap-2">
        <Network className="h-4 w-4 text-muted-foreground" />
        <h2 className="text-lg font-semibold">VLAN Activity</h2>
      </div>
      <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
        {sorted.map((entry) => (
          <VlanRow
            key={entry.name}
            entry={entry}
            sparkData={history[entry.name] ?? []}
          />
        ))}
      </div>
    </div>
  );
}
