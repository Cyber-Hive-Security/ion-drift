import { Server } from "lucide-react";
import { Link } from "@tanstack/react-router";
import { StatCard } from "@/components/stat-card";
import { useDevices } from "@/api/queries";
import { cn } from "@/lib/utils";

export function NetworkDevicesCard() {
  const { data: devices = [] } = useDevices();
  const onlineCount = devices.filter((d) => d.status === "Online").length;
  const anyOffline = devices.some((d) => d.status === "Offline");

  if (devices.length === 0) return null;

  return (
    <StatCard
      title={`Network Devices (${onlineCount}/${devices.length})`}
      icon={<Server className="h-4 w-4" />}
      className={anyOffline ? "border-destructive/30" : undefined}
    >
      <div className="space-y-1.5">
        {devices.map((device) => (
          <Link
            key={device.id}
            to={
              device.device_type === "switch"
                ? (`/switches/${device.id}` as "/")
                : "/"
            }
            className="flex items-center gap-2 rounded p-1.5 text-sm transition-colors hover:bg-muted/30"
          >
            <span
              className={cn(
                "inline-block h-2 w-2 flex-shrink-0 rounded-full",
                device.status === "Online"
                  ? "bg-success"
                  : device.status === "Offline"
                    ? "bg-destructive"
                    : "bg-gray-400",
              )}
            />
            <span className="font-medium truncate">{device.name}</span>
            <span
              className={cn(
                "flex-shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                device.device_type === "router"
                  ? "bg-warning/20 text-warning"
                  : "bg-cyan-500/20 text-cyan-400",
              )}
            >
              {device.device_type}
            </span>
            {device.model && (
              <span className="ml-auto hidden text-xs text-muted-foreground lg:inline">
                {device.model}
              </span>
            )}
          </Link>
        ))}
      </div>
    </StatCard>
  );
}
