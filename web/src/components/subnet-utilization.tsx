import { cn } from "@/lib/utils";
import type { IpPool, DhcpServer, DhcpLease } from "@/api/types";

interface SubnetUtilizationProps {
  pools: IpPool[];
  servers: DhcpServer[];
  leases: DhcpLease[];
}

function parsePoolSize(ranges: string): number {
  let total = 0;
  for (const range of ranges.split(",")) {
    const trimmed = range.trim();
    const parts = trimmed.split("-");
    if (parts.length === 2) {
      total += ipToNum(parts[1]) - ipToNum(parts[0]) + 1;
    } else if (parts.length === 1) {
      total += 1;
    }
  }
  return total;
}

function ipToNum(ip: string): number {
  const parts = ip.trim().split(".");
  return parts.reduce((acc, p) => acc * 256 + Number(p), 0);
}

export function SubnetUtilization({
  pools,
  servers,
  leases,
}: SubnetUtilizationProps) {
  const rows = servers
    .filter((s) => !(s.disabled ?? false))
    .map((server) => {
      const pool = pools.find((p) => p.name === server["address-pool"]);
      const totalIps = pool ? parsePoolSize(pool.ranges) : 0;
      const boundCount = leases.filter(
        (l) => l.server === server.name && l.status === "bound",
      ).length;
      const pct = totalIps > 0 ? Math.round((boundCount / totalIps) * 100) : 0;

      return {
        name: server.name,
        iface: server.interface,
        poolName: server["address-pool"] ?? "—",
        totalIps,
        boundCount,
        pct,
      };
    })
    .sort((a, b) => b.pct - a.pct);

  if (rows.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        No active DHCP servers found.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      {rows.map((r) => (
        <div key={r.name} className="rounded-lg border border-border bg-card p-3">
          <div className="mb-2 flex items-center justify-between">
            <div>
              <span className="font-medium text-sm">{r.name}</span>
              <span className="ml-2 text-xs text-muted-foreground">
                {r.iface} &middot; pool: {r.poolName}
              </span>
            </div>
            <span className="text-sm font-medium">
              {r.boundCount} / {r.totalIps}
              <span className="ml-1 text-xs text-muted-foreground">
                ({r.pct}%)
              </span>
            </span>
          </div>
          <div className="h-2.5 overflow-hidden rounded-full bg-muted">
            <div
              className={cn(
                "h-full rounded-full transition-all",
                r.pct > 90
                  ? "bg-destructive"
                  : r.pct > 70
                    ? "bg-warning"
                    : "bg-success",
              )}
              style={{ width: `${Math.min(r.pct, 100)}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}
