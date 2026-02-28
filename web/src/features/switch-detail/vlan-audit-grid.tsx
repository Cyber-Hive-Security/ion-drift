import { useMemo } from "react";
import { VLAN_CONFIG } from "@/features/network-map/data";
import type { VlanMembershipEntry, PortRoleEntry } from "@/api/types";
import { portSortKey, portShortName } from "./utils";

interface VlanAuditGridProps {
  vlans: VlanMembershipEntry[];
  portRoles: PortRoleEntry[];
}

export function VlanAuditGrid({ vlans }: VlanAuditGridProps) {
  // Build unique sorted port names and VLAN IDs
  const { portNames, vlanIds, membershipMap } = useMemo(() => {
    const ports = new Set<string>();
    const vlIds = new Set<number>();
    const map = new Map<string, { tagged: boolean }>();

    for (const v of vlans) {
      ports.add(v.port_name);
      vlIds.add(v.vlan_id);
      map.set(`${v.port_name}:${v.vlan_id}`, { tagged: v.tagged });
    }

    const sortedPorts = [...ports].sort((a, b) => portSortKey(a) - portSortKey(b));
    const sortedVlans = [...vlIds].sort((a, b) => a - b);

    return { portNames: sortedPorts, vlanIds: sortedVlans, membershipMap: map };
  }, [vlans]);

  if (vlanIds.length === 0) {
    return (
      <div>
        <h2 className="mb-3 text-lg font-semibold">VLAN Membership Audit</h2>
        <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
          No VLAN membership data available yet.
        </div>
      </div>
    );
  }

  return (
    <div>
      <h2 className="mb-3 text-lg font-semibold">VLAN Membership Audit</h2>
      <div className="overflow-x-auto rounded-lg border border-border bg-card shadow-sm">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border bg-muted/50">
              <th className="sticky left-0 z-10 bg-muted/50 px-3 py-2 text-left font-medium text-muted-foreground">
                VLAN
              </th>
              {portNames.map((port) => (
                <th
                  key={port}
                  className="px-1.5 py-2 text-center font-medium text-muted-foreground whitespace-nowrap"
                >
                  {portShortName(port)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {vlanIds.map((vlanId) => {
              const vlanCfg = VLAN_CONFIG[vlanId];
              const color = vlanCfg?.color ?? "#666";

              return (
                <tr key={vlanId} className="border-b border-border/30">
                  <td className="sticky left-0 z-10 bg-card px-3 py-1.5 font-medium text-muted-foreground whitespace-nowrap">
                    <span className="inline-flex items-center gap-1.5">
                      <span
                        className="inline-block h-2 w-2 rounded-sm"
                        style={{ backgroundColor: color }}
                      />
                      {vlanId}
                      {vlanCfg && (
                        <span className="text-[10px] text-muted-foreground/70">
                          {vlanCfg.name}
                        </span>
                      )}
                    </span>
                  </td>
                  {portNames.map((port) => {
                    const membership = membershipMap.get(`${port}:${vlanId}`);
                    if (!membership) {
                      return (
                        <td key={port} className="px-1.5 py-1.5 text-center text-muted-foreground/30">
                          &middot;
                        </td>
                      );
                    }
                    return (
                      <td
                        key={port}
                        className="px-1.5 py-1.5 text-center font-bold"
                        style={{
                          backgroundColor: membership.tagged
                            ? `${color}40`
                            : `${color}90`,
                          color: "#fff",
                        }}
                      >
                        {membership.tagged ? "T" : "U"}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
