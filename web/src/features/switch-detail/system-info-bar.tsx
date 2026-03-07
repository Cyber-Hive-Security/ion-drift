import { cn } from "@/lib/utils";
import { formatUptime, percentColor } from "@/lib/format";
import type { SystemResource, NetworkDevice } from "@/api/types";
import { Server, Cpu, MemoryStick, Clock, Wifi, Hash } from "lucide-react";

interface SystemInfoBarProps {
  resource: SystemResource;
  device?: NetworkDevice;
}

export function SystemInfoBar({ resource, device }: SystemInfoBarProps) {
  const isSwos = resource.platform === "SwOS";
  const cpuLoad = resource["cpu-load"];
  const totalMem = parseInt(String(resource["total-memory"])) || 0;
  const freeMem = parseInt(String(resource["free-memory"])) || 0;
  const memPct = totalMem > 0 ? Math.round(((totalMem - freeMem) / totalMem) * 100) : 0;

  return (
    <div className="rounded-lg border border-border bg-card p-4 shadow-sm">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        {/* Device identity */}
        <div className="flex items-center gap-2">
          <Server className="h-4 w-4 text-primary" />
          <span className="font-semibold text-foreground">
            {device?.name ?? "Switch"}
          </span>
          {device?.model && (
            <span className="text-xs text-muted-foreground">{device.model}</span>
          )}
        </div>

        {/* Status dot */}
        <div className="flex items-center gap-1.5">
          <span
            className={cn(
              "inline-block h-2 w-2 rounded-full",
              device?.status === "Online"
                ? "bg-success"
                : device?.status === "Offline"
                  ? "bg-destructive"
                  : "bg-gray-400",
            )}
          />
          <span className="text-xs text-muted-foreground">
            {device?.status ?? "Unknown"}
          </span>
        </div>

        {/* OS version */}
        <div className="text-xs text-muted-foreground">
          {isSwos ? "SwOS" : "RouterOS"} {resource.version}
        </div>

        {/* Board name */}
        <div className="text-xs text-muted-foreground">
          {resource["board-name"]}
        </div>

        {/* Uptime */}
        <div className="flex items-center gap-1.5">
          <Clock className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-xs text-muted-foreground">
            {formatUptime(resource.uptime)}
          </span>
        </div>

        {/* CPU — RouterOS only */}
        {!isSwos && (
          <div className="flex items-center gap-1.5">
            <Cpu className="h-3.5 w-3.5 text-muted-foreground" />
            <span className={cn("text-xs font-medium", percentColor(cpuLoad))}>
              {cpuLoad}%
            </span>
            <div className="h-1.5 w-16 overflow-hidden rounded-full bg-muted">
              <div
                className={cn(
                  "h-full rounded-full transition-all",
                  cpuLoad >= 90 ? "bg-destructive" : cpuLoad >= 70 ? "bg-warning" : "bg-success",
                )}
                style={{ width: `${cpuLoad}%` }}
              />
            </div>
          </div>
        )}

        {/* Memory — RouterOS only */}
        {!isSwos && (
          <div className="flex items-center gap-1.5">
            <MemoryStick className="h-3.5 w-3.5 text-muted-foreground" />
            <span className={cn("text-xs font-medium", percentColor(memPct))}>
              {memPct}%
            </span>
            <div className="h-1.5 w-16 overflow-hidden rounded-full bg-muted">
              <div
                className={cn(
                  "h-full rounded-full transition-all",
                  memPct >= 90 ? "bg-destructive" : memPct >= 70 ? "bg-warning" : "bg-success",
                )}
                style={{ width: `${memPct}%` }}
              />
            </div>
          </div>
        )}

        {/* MAC address — SwOS only */}
        {isSwos && resource["mac-address"] && (
          <div className="flex items-center gap-1.5">
            <Hash className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="text-xs font-mono text-muted-foreground">
              {resource["mac-address"]}
            </span>
          </div>
        )}

        {/* Management IP */}
        {device && (
          <div className="flex items-center gap-1.5 ml-auto">
            <Wifi className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="text-xs font-mono text-muted-foreground">
              {device.host}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
