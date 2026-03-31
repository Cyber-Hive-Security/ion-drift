import { Link } from "@tanstack/react-router";
import { AlertTriangle } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { useBehaviorOverview } from "@/api/queries";

export function AnomalyOverviewCard() {
  const { data } = useBehaviorOverview();

  if (!data || data.pending_anomalies === 0) return null;

  return (
    <Link to="/behavior" className="block">
      <StatCard
        title="Behavior Anomalies"
        icon={<AlertTriangle className="h-4 w-4" />}
        className="cursor-pointer transition-colors hover:border-primary/30"
      >
        <div className="text-3xl font-bold text-foreground">
          {data.pending_anomalies}
        </div>
        <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs">
          {data.critical_anomalies > 0 && (
            <span className="font-medium text-destructive">
              {data.critical_anomalies} critical
            </span>
          )}
          {data.warning_anomalies > 0 && (
            <span className="font-medium text-warning">
              {data.warning_anomalies} warning
            </span>
          )}
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          {data.baselined_devices} of {data.total_devices} devices baselined
        </p>
      </StatCard>
    </Link>
  );
}
