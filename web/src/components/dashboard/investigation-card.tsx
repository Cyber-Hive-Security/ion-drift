import { Link } from "@tanstack/react-router";
import { Microscope } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { useInvestigationStats } from "@/api/queries";
import { cn } from "@/lib/utils";

export function InvestigationCard() {
  const stats = useInvestigationStats();
  const data = stats.data;

  if (!data || data.total === 0) return null;

  const items = [
    { label: "Benign", count: data.benign, color: "text-emerald-400" },
    { label: "Routine", count: data.routine, color: "text-sky-400" },
    { label: "Suspicious", count: data.suspicious, color: "text-amber-400" },
    { label: "Threat", count: data.threat, color: "text-destructive" },
    { label: "Inconclusive", count: data.inconclusive, color: "text-muted-foreground" },
  ];

  const actionable = data.suspicious + data.threat;

  return (
    <Link to="/behavior" className="block">
      <StatCard
        title="Investigations (24h)"
        icon={<Microscope className="h-4 w-4" />}
        className="cursor-pointer transition-colors hover:border-primary/30"
      >
        <div className="text-3xl font-bold text-foreground">{data.total}</div>
        <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1">
          {items
            .filter((i) => i.count > 0)
            .map((i) => (
              <span key={i.label} className={cn("text-xs font-medium", i.color)}>
                {i.count} {i.label.toLowerCase()}
              </span>
            ))}
        </div>
        {actionable > 0 && (
          <p className="mt-1 text-xs font-medium text-warning">
            {actionable} require review
          </p>
        )}
      </StatCard>
    </Link>
  );
}
