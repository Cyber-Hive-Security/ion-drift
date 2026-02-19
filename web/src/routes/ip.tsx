import { useState } from "react";
import { useIpAddresses, useIpRoutes, useDhcpLeases } from "@/api/queries";
import { DataTable, type Column } from "@/components/data-table";
import { PageShell } from "@/components/layout/page-shell";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { cn } from "@/lib/utils";
import type { IpAddress, Route, DhcpLease } from "@/api/types";

function Badge({
  active,
  label,
}: {
  active: boolean;
  label: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex rounded-full px-2 py-0.5 text-xs font-medium",
        active ? "bg-success/15 text-success" : "bg-muted text-muted-foreground",
      )}
    >
      {label}
    </span>
  );
}

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

const dhcpColumns: Column<DhcpLease>[] = [
  {
    key: "address",
    header: "IP Address",
    render: (r) => <span className="font-mono text-sm">{r.address}</span>,
    sortValue: (r) => r.address,
  },
  {
    key: "mac",
    header: "MAC",
    render: (r) => <span className="font-mono text-sm">{r["mac-address"] ?? "—"}</span>,
  },
  {
    key: "hostname",
    header: "Hostname",
    render: (r) => r["host-name"] ?? "—",
    sortValue: (r) => r["host-name"] ?? "",
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
  { key: "expires", header: "Expires", render: (r) => r["expires-after"] ?? "—" },
  { key: "comment", header: "Comment", render: (r) => r.comment ?? "" },
];

type Tab = "addresses" | "routes" | "dhcp";

export function IpPage() {
  const [tab, setTab] = useState<Tab>("addresses");
  const addresses = useIpAddresses();
  const routes = useIpRoutes();
  const dhcp = useDhcpLeases();

  const queries = { addresses, routes, dhcp };
  const query = queries[tab];

  return (
    <PageShell
      title="IP"
      onRefresh={() => query.refetch()}
      isRefreshing={query.isFetching}
    >
      <div className="mb-4 flex gap-2">
        {([
          ["addresses", "Addresses"],
          ["routes", "Routes"],
          ["dhcp", "DHCP Leases"],
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
        <DataTable columns={addressColumns} data={addresses.data} rowKey={(r) => r[".id"]} />
      )}
      {tab === "routes" && routes.data && (
        <DataTable columns={routeColumns} data={routes.data} rowKey={(r) => r[".id"]} />
      )}
      {tab === "dhcp" && dhcp.data && (
        <DataTable columns={dhcpColumns} data={dhcp.data} rowKey={(r) => r[".id"]} />
      )}
    </PageShell>
  );
}
