import { useState } from "react";
import { useParams } from "@tanstack/react-router";
import { PageShell } from "@/components/layout/page-shell";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import {
  useDevices,
  useDeviceResources,
  useDeviceInterfaces,
  useDevicePorts,
  useDeviceMacTable,
  useDeviceVlans,
  useDevicePortRoles,
  useNetworkIdentities,
} from "@/api/queries";
import { SystemInfoBar } from "./system-info-bar";
import { PortGrid } from "./port-grid";
import { PortTrafficTable } from "./port-traffic-table";
import { MacTableSection } from "./mac-table-section";
import { VlanAuditGrid } from "./vlan-audit-grid";

function SwitchDetailPage({ deviceId }: { deviceId: string }) {
  const [selectedPort, setSelectedPort] = useState<string | null>(null);

  const { data: devices } = useDevices();
  const device = devices?.find((d) => d.id === deviceId);

  const resources = useDeviceResources(deviceId);
  const interfaces = useDeviceInterfaces(deviceId);
  const ports = useDevicePorts(deviceId);
  const macTable = useDeviceMacTable(deviceId);
  const vlans = useDeviceVlans(deviceId);
  const portRoles = useDevicePortRoles(deviceId);
  const identities = useNetworkIdentities();

  if (resources.isLoading) return <LoadingSpinner />;

  if (resources.error) {
    return (
      <PageShell title="Switch Detail">
        <ErrorDisplay
          message={resources.error.message}
          onRetry={() => resources.refetch()}
        />
      </PageShell>
    );
  }

  const title = device?.name ?? `Switch ${deviceId}`;

  return (
    <PageShell title={title}>
      {/* System Info Bar */}
      {resources.data && (
        <SystemInfoBar resource={resources.data} device={device} />
      )}

      {/* Port Grid */}
      <div className="mt-6">
        <PortGrid
          ports={ports.data ?? []}
          vlans={vlans.data ?? []}
          portRoles={portRoles.data ?? []}
          macTable={macTable.data ?? []}
          identities={identities.data ?? []}
          selectedPort={selectedPort}
          onSelectPort={setSelectedPort}
          deviceId={deviceId}
        />
      </div>

      {/* Port Traffic Table */}
      <div className="mt-6">
        <PortTrafficTable
          ports={ports.data ?? []}
          interfaces={interfaces.data ?? []}
          portRoles={portRoles.data ?? []}
          macTable={macTable.data ?? []}
          identities={identities.data ?? []}
          vlans={vlans.data ?? []}
          selectedPort={selectedPort}
          onSelectPort={setSelectedPort}
          deviceId={deviceId}
        />
      </div>

      {/* MAC Address Table */}
      <div className="mt-6">
        <MacTableSection
          macTable={macTable.data ?? []}
          identities={identities.data ?? []}
          portFilter={selectedPort}
          onClearFilter={() => setSelectedPort(null)}
        />
      </div>

      {/* VLAN Membership Audit */}
      <div className="mt-6">
        <VlanAuditGrid
          vlans={vlans.data ?? []}
          portRoles={portRoles.data ?? []}
        />
      </div>
    </PageShell>
  );
}

/** Route wrapper that extracts the deviceId param. */
export function SwitchDetailPageWrapper() {
  const { deviceId } = useParams({ strict: false }) as { deviceId: string };
  if (!deviceId) {
    return (
      <PageShell title="Switch Detail">
        <div className="text-center text-muted-foreground">No device selected.</div>
      </PageShell>
    );
  }
  return <SwitchDetailPage deviceId={deviceId} />;
}
