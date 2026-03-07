import { useMemo } from "react";
import { cn } from "@/lib/utils";
import type { PortUtilization } from "@/api/types";
import { utilizationColor, utilizationLabel, formatBitrate } from "@/lib/utilization";
import { Activity } from "lucide-react";

interface SaturatedLinksCardProps {
  utilization?: PortUtilization[];
  onSelectPort?: (port: string) => void;
}

export function SaturatedLinksCard({ utilization, onSelectPort }: SaturatedLinksCardProps) {
  const stats = useMemo(() => {
    if (!utilization || utilization.length === 0) return null;

    const active = utilization.filter((u) => u.running && u.utilization > 0.05);
    if (active.length === 0) return null;

    const above70 = active.filter((u) => u.utilization > 0.7);
    const above95 = active.filter((u) => u.utilization > 0.95);
    const maxUtil = Math.max(...active.map((u) => u.utilization));
    const top3 = [...active].sort((a, b) => b.utilization - a.utilization).slice(0, 3);

    return { activeCount: active.length, above70Count: above70.length, above95Count: above95.length, maxUtil, top3 };
  }, [utilization]);

  if (!stats) return null;

  const severity = stats.above95Count > 0 ? "critical" : stats.above70Count > 0 ? "warning" : "normal";

  return (
    <div
      className={cn(
        "rounded-lg border p-3 shadow-sm",
        severity === "critical"
          ? "border-red-500/40 bg-red-500/5"
          : severity === "warning"
            ? "border-amber-500/40 bg-amber-500/5"
            : "border-border bg-card",
      )}
    >
      <div className="flex items-center gap-2 mb-2">
        <Activity
          className={cn(
            "h-4 w-4",
            severity === "critical"
              ? "text-red-500"
              : severity === "warning"
                ? "text-amber-500"
                : "text-muted-foreground",
          )}
        />
        <span className="text-sm font-semibold">Link Utilization</span>
        <span className="text-xs text-muted-foreground">
          {stats.activeCount} active
          {stats.above70Count > 0 && ` · ${stats.above70Count} above 70%`}
        </span>
      </div>
      <div className="flex gap-3">
        {stats.top3.map((port) => (
          <button
            key={port.port_name}
            onClick={() => onSelectPort?.(port.port_name)}
            className="flex items-center gap-2 rounded-md bg-background/60 px-2.5 py-1.5 text-left hover:bg-accent/50 transition-colors"
          >
            <span className="text-xs font-mono font-medium">{port.port_name}</span>
            <div className="h-1.5 w-12 rounded-full bg-muted overflow-hidden">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${Math.max(port.utilization * 100, 2)}%`,
                  backgroundColor: utilizationColor(port.utilization),
                }}
              />
            </div>
            <span
              className="text-[10px] font-medium whitespace-nowrap"
              style={{ color: utilizationColor(port.utilization) }}
            >
              {utilizationLabel(port.utilization)}
            </span>
            <span className="text-[10px] text-muted-foreground">
              ↑{formatBitrate(port.tx_rate_bps)} ↓{formatBitrate(port.rx_rate_bps)}
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}
