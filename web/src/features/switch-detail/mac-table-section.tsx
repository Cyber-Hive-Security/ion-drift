import { useMemo } from "react";
import { DataTable, type Column } from "@/components/data-table";
import { useVlanLookup } from "@/hooks/use-vlan-lookup";
import { X } from "lucide-react";
import type { MacTableEntry, NetworkIdentity } from "@/api/types";
import { relativeTime } from "./utils";
import { formatTimestamp } from "@/lib/format";

interface MacRow {
  mac_address: string;
  port_name: string;
  vlan_id: number | null;
  vlanColor: string;
  ip: string;
  hostname: string;
  manufacturer: string;
  is_local: boolean;
  first_seen: number;
  last_seen: number;
}

interface MacTableSectionProps {
  macTable: MacTableEntry[];
  identities: NetworkIdentity[];
  portFilter: string | null;
  onClearFilter: () => void;
}

export function MacTableSection({
  macTable,
  identities,
  portFilter,
  onClearFilter,
}: MacTableSectionProps) {
  const vlan = useVlanLookup();

  // Build identity lookup
  const identityMap = useMemo(() => {
    const map = new Map<string, NetworkIdentity>();
    for (const id of identities) {
      map.set(id.mac_address.toLowerCase(), id);
    }
    return map;
  }, [identities]);

  // Build enriched rows
  const rows = useMemo(() => {
    let filtered = macTable.filter((e) => !e.is_local);
    if (portFilter) {
      filtered = filtered.filter((e) => e.port_name === portFilter);
    }
    return filtered.map((entry) => {
      const identity = identityMap.get(entry.mac_address.toLowerCase());
      return {
        mac_address: entry.mac_address,
        port_name: entry.port_name,
        vlan_id: entry.vlan_id,
        vlanColor:
          entry.vlan_id !== null
            ? vlan.color(entry.vlan_id)
            : "transparent",
        ip: identity?.best_ip ?? "",
        hostname: identity?.hostname ?? "",
        manufacturer: identity?.manufacturer ?? "",
        is_local: entry.is_local,
        first_seen: entry.first_seen,
        last_seen: entry.last_seen,
      };
    });
  }, [macTable, identityMap, portFilter, vlan]);

  const columns: Column<MacRow>[] = [
    {
      key: "mac",
      header: "MAC Address",
      sortValue: (r) => r.mac_address,
      render: (r) => <span className="font-mono text-xs">{r.mac_address}</span>,
    },
    {
      key: "port",
      header: "Port",
      sortValue: (r) => r.port_name,
      render: (r) => <span className="font-mono text-xs">{r.port_name}</span>,
    },
    {
      key: "vlan",
      header: "VLAN",
      sortValue: (r) => r.vlan_id ?? 0,
      render: (r) =>
        r.vlan_id !== null ? (
          <span className="inline-flex items-center gap-1.5">
            <span
              className="inline-block h-2 w-2 rounded-sm"
              style={{ backgroundColor: r.vlanColor }}
            />
            <span className="text-xs">{r.vlan_id}</span>
          </span>
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        ),
    },
    {
      key: "ip",
      header: "IP",
      sortValue: (r) => r.ip,
      render: (r) => (
        <span className="font-mono text-xs">
          {r.ip || <span className="text-muted-foreground">—</span>}
        </span>
      ),
    },
    {
      key: "hostname",
      header: "Hostname",
      sortValue: (r) => r.hostname,
      render: (r) => (
        <span className="text-xs">
          {r.hostname || <span className="text-muted-foreground">—</span>}
        </span>
      ),
    },
    {
      key: "manufacturer",
      header: "Manufacturer",
      sortValue: (r) => r.manufacturer,
      render: (r) => (
        <span className="text-xs">
          {r.manufacturer || <span className="text-muted-foreground">—</span>}
        </span>
      ),
    },
    {
      key: "first_seen",
      header: "First Seen",
      sortValue: (r) => r.first_seen,
      render: (r) => (
        <span className="text-xs text-muted-foreground" title={formatTimestamp(r.first_seen)}>
          {relativeTime(r.first_seen)}
        </span>
      ),
    },
    {
      key: "last_seen",
      header: "Last Seen",
      sortValue: (r) => r.last_seen,
      render: (r) => (
        <span className="text-xs text-muted-foreground" title={formatTimestamp(r.last_seen)}>
          {relativeTime(r.last_seen)}
        </span>
      ),
    },
  ];

  return (
    <div>
      <div className="mb-3 flex items-center gap-3">
        <h2 className="text-lg font-semibold">MAC Address Table</h2>
        {portFilter && (
          <button
            onClick={onClearFilter}
            className="inline-flex items-center gap-1 rounded-full bg-primary/10 px-2.5 py-1 text-xs font-medium text-primary hover:bg-primary/20 transition-colors"
          >
            Port: {portFilter}
            <X className="h-3 w-3" />
          </button>
        )}
        <span className="text-xs text-muted-foreground">
          {rows.length} {rows.length === 1 ? "entry" : "entries"}
        </span>
      </div>
      <DataTable
        columns={columns}
        data={rows}
        rowKey={(r) => `${r.mac_address}-${r.port_name}`}
        defaultSort={{ key: "last_seen", asc: false }}
        searchable
        searchPlaceholder="Search MAC, IP, hostname..."
        emptyMessage={
          portFilter
            ? `No MAC addresses found on port ${portFilter}`
            : "No MAC addresses learned yet"
        }
      />
    </div>
  );
}
