import { Link } from "@tanstack/react-router";
import { Plug2 } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { formatNumber } from "@/lib/format";
import type { ConnectionSummary } from "@/api/types";

function progressColor(pct: number): string {
  if (pct >= 90) return "bg-red-500";
  if (pct >= 70) return "bg-yellow-500";
  return "bg-emerald-500";
}

export function ConnectionsCard({ data }: { data: ConnectionSummary }) {
  const pct =
    data.max_entries != null && data.max_entries > 0
      ? (data.total_connections / data.max_entries) * 100
      : null;

  return (
    <Link to="/connections" className="block">
      <StatCard
        title="Connections"
        icon={
          <span className="relative">
            <Plug2 className="h-4 w-4" />
            {data.flagged_count > 0 && (
              <span className="absolute -right-1 -top-1 h-2 w-2 rounded-full bg-red-500" />
            )}
          </span>
        }
        className="cursor-pointer transition-colors hover:border-primary/30"
      >
        <div className="text-3xl font-bold text-foreground">
          {formatNumber(data.total_connections)}
        </div>
        <p className="mt-2 text-xs text-muted-foreground">
          TCP: {formatNumber(data.tcp_count)} &middot; UDP:{" "}
          {formatNumber(data.udp_count)} &middot; Other:{" "}
          {formatNumber(data.other_count)}
        </p>
        {data.flagged_count > 0 && (
          <p className="mt-1 text-xs font-medium text-red-500">
            {data.flagged_count} flagged connection{data.flagged_count !== 1 ? "s" : ""}
          </p>
        )}
        {pct != null && data.max_entries != null && (
          <>
            <div className="mt-2 h-1.5 w-full rounded-full bg-muted">
              <div
                className={`h-1.5 rounded-full transition-all ${progressColor(pct)}`}
                style={{ width: `${Math.min(pct, 100)}%` }}
              />
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              {pct.toFixed(0)}% of {formatNumber(data.max_entries)} max
            </p>
          </>
        )}
      </StatCard>
    </Link>
  );
}
