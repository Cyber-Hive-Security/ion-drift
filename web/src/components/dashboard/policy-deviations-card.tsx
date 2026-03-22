import { Link } from "@tanstack/react-router";
import { ShieldAlert } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { usePolicyDeviationCounts } from "@/api/queries";

export function PolicyDeviationsCard() {
  const { data } = usePolicyDeviationCounts();

  if (!data || data.total === 0) return null;

  return (
    <Link to="/policy" className="block">
      <StatCard
        title="Policy Deviations"
        icon={<ShieldAlert className="h-4 w-4" />}
        className="cursor-pointer transition-colors hover:border-primary/30"
      >
        <div className="text-3xl font-bold text-foreground">{data.total}</div>
        <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs">
          {data.new > 0 && (
            <span className="font-medium text-warning">{data.new} new</span>
          )}
          {data.acknowledged > 0 && (
            <span className="text-muted-foreground">
              {data.acknowledged} acknowledged
            </span>
          )}
          {data.resolved > 0 && (
            <span className="text-emerald-400">{data.resolved} resolved</span>
          )}
        </div>
        {data.dns > 0 && (
          <p className="mt-1 text-xs text-muted-foreground">
            {data.dns} DNS deviation{data.dns !== 1 ? "s" : ""}
          </p>
        )}
      </StatCard>
    </Link>
  );
}
