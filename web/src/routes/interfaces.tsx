import { useState } from "react";
import { useInterfaces, useVlans } from "@/api/queries";
import { DataTable, type Column } from "@/components/data-table";
import { PageShell } from "@/components/layout/page-shell";
import { InterfacesHelp } from "@/components/help-content";
import { RouterPortGrid } from "@/components/router-port-grid";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { formatBytes } from "@/lib/format";
import { Badge } from "@/components/badge";
import { cn } from "@/lib/utils";
import type { RouterInterface, VlanInterface } from "@/api/types";

const ifaceColumns: Column<RouterInterface>[] = [
  {
    key: "name",
    header: "Name",
    render: (r) => <span className="font-medium">{r.name}</span>,
    sortValue: (r) => r.name,
  },
  { key: "type", header: "Type", render: (r) => r.type, sortValue: (r) => r.type },
  { key: "mtu", header: "MTU", render: (r) => r.mtu ?? "—" },
  { key: "mac", header: "MAC", render: (r) => r["mac-address"] ?? "—" },
  {
    key: "running",
    header: "Status",
    render: (r) => <Badge active={r.running} label={r.running ? "Up" : "Down"} />,
    sortValue: (r) => (r.running ? 1 : 0),
  },
  {
    key: "rx",
    header: "RX",
    render: (r) => (r["rx-byte"] != null ? formatBytes(r["rx-byte"]) : "—"),
    sortValue: (r) => r["rx-byte"] ?? 0,
  },
  {
    key: "tx",
    header: "TX",
    render: (r) => (r["tx-byte"] != null ? formatBytes(r["tx-byte"]) : "—"),
    sortValue: (r) => r["tx-byte"] ?? 0,
  },
  { key: "comment", header: "Comment", render: (r) => r.comment ?? "" },
];

const vlanColumns: Column<VlanInterface>[] = [
  {
    key: "name",
    header: "Name",
    render: (r) => <span className="font-medium">{r.name}</span>,
    sortValue: (r) => r.name,
  },
  {
    key: "vlan-id",
    header: "VLAN ID",
    render: (r) => r["vlan-id"],
    sortValue: (r) => r["vlan-id"],
  },
  { key: "interface", header: "Parent", render: (r) => r.interface },
  { key: "mtu", header: "MTU", render: (r) => r.mtu ?? "—" },
  {
    key: "running",
    header: "Status",
    render: (r) => <Badge active={r.running} label={r.running ? "Up" : "Down"} />,
    sortValue: (r) => (r.running ? 1 : 0),
  },
  { key: "comment", header: "Comment", render: (r) => r.comment ?? "" },
];

export function InterfacesPage() {
  const [tab, setTab] = useState<"all" | "vlans">("all");
  const ifaces = useInterfaces();
  const vlans = useVlans({ enabled: tab === "vlans" });

  const query = tab === "all" ? ifaces : vlans;

  return (
    <PageShell
      title="Interfaces"
      onRefresh={() => query.refetch()}
      isRefreshing={query.isFetching}
      help={<InterfacesHelp />}
    >
      {ifaces.data && <RouterPortGrid interfaces={ifaces.data} />}

      <div className="mb-4 flex gap-2">
        {(["all", "vlans"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={cn(
              "rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
              tab === t
                ? "bg-primary text-primary-foreground"
                : "bg-muted text-muted-foreground hover:text-foreground",
            )}
          >
            {t === "all" ? "All Interfaces" : "VLANs"}
          </button>
        ))}
      </div>

      {query.isLoading && <LoadingSpinner />}
      {query.error && (
        <ErrorDisplay message={query.error.message} onRetry={() => query.refetch()} />
      )}

      {tab === "all" && ifaces.data && (
        <DataTable
          columns={ifaceColumns}
          data={ifaces.data}
          rowKey={(r) => r[".id"]}
          searchable
          searchPlaceholder="Search interfaces..."
        />
      )}
      {tab === "vlans" && vlans.data && (
        <DataTable
          columns={vlanColumns}
          data={vlans.data}
          rowKey={(r) => r[".id"]}
          searchable
          searchPlaceholder="Search VLANs..."
        />
      )}
    </PageShell>
  );
}
