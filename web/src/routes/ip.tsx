import { useState } from "react";
import {
  useIpAddresses,
  useIpRoutes,
  useArpTable,
  useDhcpLeasesStatus,
  usePoolUtilization,
} from "@/api/queries";
import { DataTable, type Column } from "@/components/data-table";
import { PageShell } from "@/components/layout/page-shell";
import { IpHelp } from "@/components/help-content";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { Badge } from "@/components/badge";
import { cn } from "@/lib/utils";
import type { IpAddress, Route, ArpEntry, DhcpLeaseStatus, PoolUtilization } from "@/api/types";

const addressColumns: Column<IpAddress>[] = [
  {
    key: "address",
    header: "Address",
    render: (r) => <span className="font-mono text-sm">{r.address}</span>,
    sortValue: (r) => r.address,
  },
  {
    key: "network",
    header: "Network",
    render: (r) => <span className="font-mono text-sm">{r.network}</span>,
  },
  { key: "interface", header: "Interface", render: (r) => r.interface, sortValue: (r) => r.interface },
  {
    key: "dynamic",
    header: "Dynamic",
    render: (r) => (r.dynamic ? <Badge active={false} label="Dynamic" /> : ""),
  },
  { key: "comment", header: "Comment", render: (r) => r.comment ?? "" },
];

const routeColumns: Column<Route>[] = [
  {
    key: "dst",
    header: "Destination",
    render: (r) => <span className="font-mono text-sm">{r["dst-address"]}</span>,
    sortValue: (r) => r["dst-address"],
  },
  { key: "gateway", header: "Gateway", render: (r) => r.gateway ?? "—" },
  { key: "distance", header: "Distance", render: (r) => r.distance ?? "—", sortValue: (r) => r.distance ?? 999 },
  { key: "table", header: "Table", render: (r) => r["routing-table"] ?? "main" },
  {
    key: "active",
    header: "Active",
    render: (r) => <Badge active={r.active ?? false} label={r.active ? "Yes" : "No"} />,
  },
  { key: "comment", header: "Comment", render: (r) => r.comment ?? "" },
];

function ipToNum(ip: string): number {
  const parts = ip.split(".");
  return parts.reduce((acc, p) => acc * 256 + Number(p), 0);
}

// ── ARP Tab columns ──────────────────────────────────────────────

const arpColumns: Column<ArpEntry>[] = [
  {
    key: "address",
    header: "IP Address",
    render: (r) => <span className="font-mono text-sm">{r.address}</span>,
    sortValue: (r) => ipToNum(r.address),
  },
  {
    key: "mac",
    header: "MAC Address",
    render: (r) => (
      <div>
        <span className="font-mono text-sm">{r.mac_address ?? "—"}</span>
        {r.manufacturer && (
          <p className="text-[10px] text-muted-foreground">{r.manufacturer}</p>
        )}
      </div>
    ),
    sortValue: (r) => r.mac_address ?? "",
  },
  {
    key: "interface",
    header: "Interface",
    render: (r) => r.interface ?? "—",
    sortValue: (r) => r.interface ?? "",
  },
  {
    key: "dynamic",
    header: "Dynamic",
    render: (r) =>
      r.dynamic ? (
        <Badge active={false} label="Yes" />
      ) : (
        <span className="text-xs">No</span>
      ),
    sortValue: (r) => (r.dynamic ? 1 : 0),
  },
  {
    key: "complete",
    header: "Complete",
    render: (r) => {
      if (r.complete === false) {
        return (
          <span className="inline-flex rounded-full bg-destructive/15 px-2 py-0.5 text-xs font-medium text-destructive">
            Incomplete
          </span>
        );
      }
      return <span className="text-xs text-muted-foreground">Yes</span>;
    },
    sortValue: (r) => (r.complete ? 1 : 0),
  },
  {
    key: "manufacturer",
    header: "Manufacturer",
    render: (r) => (
      <span className="text-xs text-muted-foreground">
        {r.manufacturer ?? "—"}
      </span>
    ),
    sortValue: (r) => r.manufacturer ?? "",
  },
];

// ── Enhanced DHCP columns ────────────────────────────────────────

const dhcpStatusColumns: Column<DhcpLeaseStatus>[] = [
  {
    key: "address",
    header: "IP Address",
    render: (r) => <span className="font-mono text-sm">{r.address}</span>,
    sortValue: (r) => ipToNum(r.address),
  },
  {
    key: "mac",
    header: "MAC",
    render: (r) => (
      <div>
        <span className="font-mono text-sm">{r.mac_address ?? "—"}</span>
        {r.manufacturer && (
          <p className="text-[10px] text-muted-foreground">{r.manufacturer}</p>
        )}
      </div>
    ),
    sortValue: (r) => r.mac_address ?? "",
  },
  {
    key: "hostname",
    header: "Hostname",
    render: (r) => r.host_name ?? "—",
    sortValue: (r) => r.host_name ?? "",
  },
  {
    key: "manufacturer",
    header: "Manufacturer",
    render: (r) => (
      <span className="text-xs text-muted-foreground">
        {r.manufacturer ?? "—"}
      </span>
    ),
    sortValue: (r) => r.manufacturer ?? "",
  },
  { key: "server", header: "Server", render: (r) => r.server ?? "—", sortValue: (r) => r.server ?? "" },
  {
    key: "status",
    header: "Status",
    render: (r) => (
      <Badge active={r.status === "bound"} label={r.status ?? "unknown"} />
    ),
    sortValue: (r) => r.status ?? "",
  },
  {
    key: "network_status",
    header: "Network Status",
    render: (r) => {
      if (r.arp_status === "active") {
        return (
          <span className="inline-flex items-center gap-1 text-xs">
            <span className="h-2 w-2 rounded-full bg-emerald-500" />
            Active
          </span>
        );
      }
      if (r.arp_status === "stale") {
        return (
          <span className="inline-flex items-center gap-1 text-xs text-warning">
            <span className="h-2 w-2 rounded-full bg-warning" />
            Stale
          </span>
        );
      }
      return (
        <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
          <span className="h-2 w-2 rounded-full bg-muted-foreground/40" />
          Offline
        </span>
      );
    },
    sortValue: (r) =>
      r.arp_status === "active" ? 0 : r.arp_status === "stale" ? 1 : 2,
  },
  { key: "expires", header: "Expires", render: (r) => r.expires_after ?? "—" },
  { key: "comment", header: "Comment", render: (r) => r.comment ?? "" },
];

// ── Enhanced Pool Utilization ────────────────────────────────────

function EnhancedPoolUtilization({ data }: { data: PoolUtilization[] }) {
  if (data.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        No active DHCP servers found.
      </p>
    );
  }

  const rows = [...data].sort((a, b) => b.pct - a.pct);

  return (
    <div className="space-y-3">
      {rows.map((r) => (
        <div key={r.name} className="rounded-lg border border-border bg-card p-3">
          <div className="mb-2 flex items-center justify-between">
            <div>
              <span className="text-sm font-medium">{r.name}</span>
              <span className="ml-2 text-xs text-muted-foreground">
                {r.interface} &middot; pool: {r.pool_name}
              </span>
            </div>
            <span className="text-sm font-medium">
              {r.bound_count} / {r.total_ips}
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
          <p className="mt-1.5 text-xs text-muted-foreground">
            {r.active_on_network} active on network &middot;{" "}
            {r.bound_count} leases assigned
          </p>
        </div>
      ))}
    </div>
  );
}

// ── IP Page ──────────────────────────────────────────────────────

type Tab = "addresses" | "routes" | "dhcp" | "arp" | "utilization";

export function IpPage() {
  const [tab, setTab] = useState<Tab>("addresses");
  const addresses = useIpAddresses({ enabled: tab === "addresses" });
  const routes = useIpRoutes({ enabled: tab === "routes" });
  const arp = useArpTable({ enabled: tab === "arp" });
  const dhcpStatus = useDhcpLeasesStatus({ enabled: tab === "dhcp" });
  const poolUtil = usePoolUtilization({ enabled: tab === "utilization" });

  const queries: Record<string, { isFetching: boolean; refetch: () => void; isLoading: boolean; error: Error | null }> = {
    addresses,
    routes,
    arp,
    dhcp: dhcpStatus,
    utilization: poolUtil,
  };
  const query = queries[tab];

  return (
    <PageShell
      title="IP"
      onRefresh={() => query.refetch()}
      isRefreshing={query.isFetching}
      help={<IpHelp />}
    >
      <div className="mb-4 flex gap-2">
        {([
          ["addresses", "Addresses"],
          ["routes", "Routes"],
          ["dhcp", "DHCP Leases"],
          ["arp", "ARP"],
          ["utilization", "Utilization"],
        ] as const).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={cn(
              "rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
              tab === key
                ? "bg-primary text-primary-foreground"
                : "bg-muted text-muted-foreground hover:text-foreground",
            )}
          >
            {label}
          </button>
        ))}
      </div>

      {query.isLoading && <LoadingSpinner />}
      {query.error && (
        <ErrorDisplay message={query.error.message} onRetry={() => query.refetch()} />
      )}

      {tab === "addresses" && addresses.data && (
        <DataTable columns={addressColumns} data={addresses.data} rowKey={(r) => r[".id"]} searchable searchPlaceholder="Search addresses..." />
      )}
      {tab === "routes" && routes.data && (
        <DataTable columns={routeColumns} data={routes.data} rowKey={(r) => r[".id"]} searchable searchPlaceholder="Search routes..." />
      )}
      {tab === "dhcp" && dhcpStatus.data && (
        <DataTable columns={dhcpStatusColumns} data={dhcpStatus.data} rowKey={(r) => r.id} defaultSort={{ key: "address" }} searchable searchPlaceholder="Search leases..." />
      )}
      {tab === "arp" && arp.data && (
        <DataTable columns={arpColumns} data={arp.data} rowKey={(r) => r.id} searchable searchPlaceholder="Search ARP table..." />
      )}
      {tab === "utilization" && poolUtil.data && (
        <EnhancedPoolUtilization data={poolUtil.data} />
      )}
    </PageShell>
  );
}
