import { Users } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import type { DhcpLease } from "@/api/types";

export function DhcpCard({ data }: { data: DhcpLease[] }) {
  const active = data.filter((l) => l.status === "bound").length;

  return (
    <StatCard title="DHCP Leases" icon={<Users className="h-4 w-4" />}>
      <div className="text-3xl font-bold text-foreground">{data.length}</div>
      <p className="mt-2 text-xs text-muted-foreground">
        {active} active &middot; {data.length - active} other
      </p>
    </StatCard>
  );
}
