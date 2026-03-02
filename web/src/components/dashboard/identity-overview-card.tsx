import { Fingerprint, AlertTriangle, ShieldAlert } from "lucide-react";
import { Link } from "@tanstack/react-router";
import { StatCard } from "@/components/stat-card";
import { useIdentityStats, usePortViolations } from "@/api/queries";

export function IdentityOverviewCard() {
  const { data: stats } = useIdentityStats();
  const { data: violations = [] } = usePortViolations();

  if (!stats) return null;

  // Device counts: my_device + unknown are "monitored", external/ignored excluded
  const myDevices = stats.by_disposition?.my_device ?? 0;
  const unknown = stats.by_disposition?.unknown ?? 0;
  const flagged = stats.by_disposition?.flagged ?? 0;
  const external = stats.by_disposition?.external ?? 0;
  const ignored = stats.by_disposition?.ignored ?? 0;
  const monitoredCount = myDevices + unknown;

  return (
    <StatCard
      title="Network Identities"
      icon={<Fingerprint className="h-4 w-4" />}
      className={flagged > 0 ? "border-red-500/30" : undefined}
    >
      <Link
        to={"/network/identities" as "/"}
        className="block space-y-2 rounded p-1 transition-colors hover:bg-muted/20"
      >
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-bold">{monitoredCount}</span>
          <span className="text-xs text-muted-foreground">monitored devices</span>
        </div>
        <div className="flex flex-wrap gap-1.5 text-[10px]">
          <span className="rounded-full border border-green-500/30 bg-green-500/20 px-2 py-0.5 text-green-400">
            {myDevices} confirmed
          </span>
          <span className="rounded-full border border-border bg-muted px-2 py-0.5 text-muted-foreground">
            {unknown} unknown
          </span>
          {external > 0 && (
            <span className="rounded-full border border-blue-500/30 bg-blue-500/20 px-2 py-0.5 text-blue-400">
              {external} external
            </span>
          )}
          {ignored > 0 && (
            <span className="rounded-full border border-border/50 bg-muted/50 px-2 py-0.5 text-muted-foreground/50">
              {ignored} ignored
            </span>
          )}
          {flagged > 0 && (
            <span className="flex items-center gap-1 rounded-full border border-red-500/30 bg-red-500/20 px-2 py-0.5 font-medium text-red-400">
              <ShieldAlert className="h-3 w-3" />
              {flagged} flagged
            </span>
          )}
        </div>
        {violations.length > 0 && (
          <div className="flex items-center gap-1.5 rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-[10px] text-amber-400">
            <AlertTriangle className="h-3 w-3" />
            {violations.length} port violation{violations.length !== 1 ? "s" : ""}
          </div>
        )}
      </Link>
    </StatCard>
  );
}
