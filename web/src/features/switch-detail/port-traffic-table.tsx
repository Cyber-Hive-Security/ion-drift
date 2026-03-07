import { useMemo, useRef, useEffect } from "react";
import { DataTable, type Column } from "@/components/data-table";
import { cn } from "@/lib/utils";
import { VLAN_CONFIG } from "@/features/network-map/data";
import { formatBytes } from "@/lib/format";
import type {
  PortMetricsTuple,
  RouterInterface,
  PortRoleEntry,
  MacTableEntry,
  NetworkIdentity,
} from "@/api/types";
import { portSortKey, getPortPrimaryVlan } from "./utils";
import type { VlanMembershipEntry } from "@/api/types";

interface PortRow {
  portName: string;
  vlanId: number | null;
  vlanColor: string;
  running: boolean;
  speed: string | null;
  rxBytes: number;
  txBytes: number;
  connectedDevice: string;
  role: string;
}

interface PortTrafficTableProps {
  ports: PortMetricsTuple[];
  interfaces: RouterInterface[];
  portRoles: PortRoleEntry[];
  macTable: MacTableEntry[];
  identities: NetworkIdentity[];
  vlans?: VlanMembershipEntry[];
  selectedPort: string | null;
  onSelectPort: (port: string | null) => void;
  deviceId?: string;
}

export function PortTrafficTable({
  ports,
  interfaces,
  portRoles,
  identities,
  vlans = [],
  selectedPort,
  deviceId,
}: PortTrafficTableProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  // Build latest metrics per port
  const latestMetrics = useMemo(() => {
    const map = new Map<string, PortMetricsTuple>();
    for (const tuple of ports) {
      const [name, , , ts] = tuple;
      const existing = map.get(name);
      if (!existing || ts > existing[3]) {
        map.set(name, tuple);
      }
    }
    return map;
  }, [ports]);

  // Role map
  const roleMap = useMemo(() => {
    const map = new Map<string, string>();
    for (const r of portRoles) map.set(r.port_name, r.role);
    return map;
  }, [portRoles]);

  // Identity by port
  const identityByPort = useMemo(() => {
    const map = new Map<string, NetworkIdentity>();
    for (const id of identities) {
      if (id.switch_port && (!deviceId || id.switch_device_id === deviceId)) {
        const existing = map.get(id.switch_port);
        if (!existing || id.confidence > existing.confidence) {
          map.set(id.switch_port, id);
        }
      }
    }
    return map;
  }, [identities, deviceId]);

  // Build rows
  const rows = useMemo(() => {
    const allPortNames = new Set<string>();
    for (const [name] of latestMetrics) allPortNames.add(name);
    for (const iface of interfaces) {
      if (iface.name) allPortNames.add(iface.name);
    }

    const result: PortRow[] = [];
    for (const portName of allPortNames) {
      if (portName === "bridge" || portName === "lo") continue;

      const metrics = latestMetrics.get(portName);
      const identity = identityByPort.get(portName);
      const vlanId = getPortPrimaryVlan(portName, vlans);
      const vlanColor = vlanId !== null ? (VLAN_CONFIG[vlanId]?.color ?? "#666") : "transparent";

      result.push({
        portName,
        vlanId,
        vlanColor,
        running: metrics ? metrics[5] : false,
        speed: metrics ? metrics[4] : null,
        rxBytes: metrics ? metrics[1] : 0,
        txBytes: metrics ? metrics[2] : 0,
        connectedDevice: identity?.hostname ?? identity?.manufacturer ?? identity?.mac_address ?? "",
        role: roleMap.get(portName) ?? "",
      });
    }

    return result.sort((a, b) => portSortKey(a.portName) - portSortKey(b.portName));
  }, [latestMetrics, interfaces, identityByPort, vlans, roleMap]);

  // Scroll to selected port row
  useEffect(() => {
    if (selectedPort && scrollRef.current) {
      const row = scrollRef.current.querySelector(`[data-port="${selectedPort}"]`);
      row?.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [selectedPort]);

  const columns: Column<PortRow>[] = [
    {
      key: "port",
      header: "Port",
      sortValue: (r) => portSortKey(r.portName),
      render: (r) => <span className="font-mono text-xs">{r.portName}</span>,
    },
    {
      key: "vlan",
      header: "VLAN",
      sortValue: (r) => r.vlanId ?? 0,
      render: (r) =>
        r.vlanId !== null ? (
          <span className="inline-flex items-center gap-1.5">
            <span
              className="inline-block h-2 w-2 rounded-sm"
              style={{ backgroundColor: r.vlanColor }}
            />
            <span className="text-xs">{r.vlanId}</span>
          </span>
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        ),
    },
    {
      key: "status",
      header: "Status",
      sortValue: (r) => (r.running ? 1 : 0),
      render: (r) => (
        <span className={cn("text-xs font-medium", r.running ? "text-success" : "text-destructive")}>
          {r.running ? "Up" : "Down"}
        </span>
      ),
    },
    {
      key: "speed",
      header: "Speed",
      sortValue: (r) => r.speed ?? "",
      render: (r) => (
        <span className="text-xs text-muted-foreground">{r.speed ?? "—"}</span>
      ),
    },
    {
      key: "rx",
      header: "Rx Total",
      sortValue: (r) => r.rxBytes,
      render: (r) => (
        <span className="text-xs font-mono">{r.rxBytes > 0 ? formatBytes(r.rxBytes) : "—"}</span>
      ),
    },
    {
      key: "tx",
      header: "Tx Total",
      sortValue: (r) => r.txBytes,
      render: (r) => (
        <span className="text-xs font-mono">{r.txBytes > 0 ? formatBytes(r.txBytes) : "—"}</span>
      ),
    },
    {
      key: "device",
      header: "Connected Device",
      sortValue: (r) => r.connectedDevice,
      render: (r) => (
        <span className="text-xs truncate max-w-[180px] inline-block">
          {r.connectedDevice || <span className="text-muted-foreground">—</span>}
        </span>
      ),
    },
    {
      key: "role",
      header: "Role",
      sortValue: (r) => r.role,
      render: (r) =>
        r.role ? (
          <span
            className={cn(
              "inline-flex rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase",
              r.role === "trunk"
                ? "bg-warning/20 text-warning"
                : r.role === "uplink"
                  ? "bg-primary/20 text-primary"
                  : r.role === "access"
                    ? "bg-success/20 text-success"
                    : "bg-muted text-muted-foreground",
            )}
          >
            {r.role}
          </span>
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        ),
    },
  ];

  return (
    <div ref={scrollRef}>
      <h2 className="mb-3 text-lg font-semibold">Port Traffic</h2>
      <DataTable
        columns={columns}
        data={rows}
        rowKey={(r) => r.portName}
        defaultSort={{ key: "port", asc: true }}
        searchable
        searchPlaceholder="Search ports..."
        rowStyle={(r) =>
          selectedPort === r.portName
            ? { backgroundColor: "#2FA4FF14" }
            : undefined
        }
      />
    </div>
  );
}
