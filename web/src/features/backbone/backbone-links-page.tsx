import { useMemo, useState } from "react";
import { useBackboneLinks, useCreateBackboneLink, useDeleteBackboneLink, useDevices, useInfrastructureIdentities } from "@/api/queries";
import type { NetworkDevice, NetworkIdentity } from "@/api/types";
import { Cable, Trash2, Plus } from "lucide-react";

export function BackboneLinksPage() {
  const links = useBackboneLinks();
  const devices = useDevices();
  const infraIdentities = useInfrastructureIdentities();
  const createMutation = useCreateBackboneLink();
  const deleteMutation = useDeleteBackboneLink();

  const [deviceA, setDeviceA] = useState("");
  const [portA, setPortA] = useState("");
  const [deviceB, setDeviceB] = useState("");
  const [portB, setPortB] = useState("");
  const [label, setLabel] = useState("");

  const managedDevices = devices.data ?? [];
  const managedIds = useMemo(() => new Set(managedDevices.map((d) => d.id)), [managedDevices]);

  // Build a combined name lookup: managed devices + infrastructure identities
  const nameMap = useMemo(() => {
    const map = new Map<string, string>();
    for (const d of managedDevices) {
      map.set(d.id, d.name);
    }
    for (const ident of infraIdentities.data ?? []) {
      const key = ident.hostname ?? ident.mac_address;
      if (!map.has(key)) {
        map.set(key, ident.hostname ?? ident.mac_address);
      }
    }
    return map;
  }, [managedDevices, infraIdentities.data]);

  // Infrastructure identities not already in managed devices
  const discoveredInfra = useMemo(() => {
    return (infraIdentities.data ?? []).filter(
      (ident) => !managedIds.has(ident.hostname ?? ident.mac_address),
    );
  }, [infraIdentities.data, managedIds]);

  const canSubmit = deviceA && deviceB && deviceA !== deviceB && !createMutation.isPending;

  function handleAdd() {
    if (!canSubmit) return;
    createMutation.mutate(
      {
        device_a: deviceA,
        port_a: portA || undefined,
        device_b: deviceB,
        port_b: portB || undefined,
        label: label || undefined,
      },
      {
        onSuccess: () => {
          setDeviceA("");
          setPortA("");
          setDeviceB("");
          setPortB("");
          setLabel("");
        },
      },
    );
  }

  function resolveName(id: string) {
    return nameMap.get(id) ?? id;
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Cable className="h-6 w-6 text-primary" />
        <div>
          <h1 className="text-xl font-bold text-foreground">Backbone Links</h1>
          <p className="text-sm text-muted-foreground">
            Manually define switch-to-switch connections for devices without LLDP (e.g. SwOS switches).
            Backbone links force trunk port classification and correct device attribution.
          </p>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/50 text-left text-xs text-muted-foreground">
              <th className="px-3 py-2">Device A</th>
              <th className="px-3 py-2">Port A</th>
              <th className="px-3 py-2 text-center">Link</th>
              <th className="px-3 py-2">Device B</th>
              <th className="px-3 py-2">Port B</th>
              <th className="px-3 py-2">Label</th>
              <th className="px-3 py-2">Created</th>
              <th className="px-3 py-2 w-10" />
            </tr>
          </thead>
          <tbody>
            {/* Add form row */}
            <tr className="border-b border-border bg-card">
              <td className="px-3 py-2">
                <DeviceSelect value={deviceA} onChange={setDeviceA} managed={managedDevices} infra={discoveredInfra} />
              </td>
              <td className="px-3 py-2">
                <input
                  type="text"
                  value={portA}
                  onChange={(e) => setPortA(e.target.value)}
                  placeholder="e.g. sfp-sfpplus1"
                  className="w-full rounded border border-border bg-background px-2 py-1 text-xs text-foreground placeholder:text-muted-foreground"
                />
              </td>
              <td className="px-3 py-2 text-center text-muted-foreground">
                <Cable className="mx-auto h-4 w-4" />
              </td>
              <td className="px-3 py-2">
                <DeviceSelect value={deviceB} onChange={setDeviceB} managed={managedDevices} infra={discoveredInfra} />
              </td>
              <td className="px-3 py-2">
                <input
                  type="text"
                  value={portB}
                  onChange={(e) => setPortB(e.target.value)}
                  placeholder="e.g. port5"
                  className="w-full rounded border border-border bg-background px-2 py-1 text-xs text-foreground placeholder:text-muted-foreground"
                />
              </td>
              <td className="px-3 py-2">
                <input
                  type="text"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  placeholder="Optional description"
                  className="w-full rounded border border-border bg-background px-2 py-1 text-xs text-foreground placeholder:text-muted-foreground"
                />
              </td>
              <td className="px-3 py-2" />
              <td className="px-3 py-2">
                <button
                  onClick={handleAdd}
                  disabled={!canSubmit}
                  className="rounded bg-primary p-1.5 text-primary-foreground hover:bg-primary/90 disabled:opacity-40"
                  title="Add backbone link"
                >
                  <Plus className="h-3.5 w-3.5" />
                </button>
              </td>
            </tr>

            {/* Existing links */}
            {links.data?.map((link) => (
              <tr key={link.id} className="border-b border-border last:border-0 hover:bg-muted/30">
                <td className="px-3 py-2 font-mono text-foreground">{resolveName(link.device_a)}</td>
                <td className="px-3 py-2 font-mono text-muted-foreground">{link.port_a ?? "—"}</td>
                <td className="px-3 py-2 text-center text-muted-foreground">↔</td>
                <td className="px-3 py-2 font-mono text-foreground">{resolveName(link.device_b)}</td>
                <td className="px-3 py-2 font-mono text-muted-foreground">{link.port_b ?? "—"}</td>
                <td className="px-3 py-2 text-muted-foreground">{link.label ?? "—"}</td>
                <td className="px-3 py-2 text-muted-foreground">{link.created_at.slice(0, 10)}</td>
                <td className="px-3 py-2">
                  <button
                    onClick={() => deleteMutation.mutate(link.id)}
                    disabled={deleteMutation.isPending}
                    className="rounded p-1 text-muted-foreground hover:bg-destructive/20 hover:text-destructive"
                    title="Delete link"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </td>
              </tr>
            ))}

            {/* Empty state */}
            {links.data && links.data.length === 0 && (
              <tr>
                <td colSpan={8} className="px-3 py-8 text-center text-sm text-muted-foreground">
                  No backbone links configured. Add one above to define a switch-to-switch connection.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Validation hint */}
      {deviceA && deviceB && deviceA === deviceB && (
        <p className="text-xs text-destructive">Device A and Device B must be different.</p>
      )}
    </div>
  );
}

function DeviceSelect({
  value,
  onChange,
  managed,
  infra,
}: {
  value: string;
  onChange: (v: string) => void;
  managed: NetworkDevice[];
  infra: NetworkIdentity[];
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="w-full rounded border border-border bg-background px-2 py-1 text-xs text-foreground"
    >
      <option value="">Select device...</option>
      <optgroup label="Managed Devices">
        {managed.map((d) => (
          <option key={d.id} value={d.id}>
            {d.name}
          </option>
        ))}
      </optgroup>
      {infra.length > 0 && (
        <optgroup label="Discovered Infrastructure">
          {infra.map((d) => {
            const key = d.hostname ?? d.mac_address;
            return (
              <option key={key} value={key}>
                {d.hostname ?? d.mac_address} ({d.device_type ?? "unknown"})
              </option>
            );
          })}
        </optgroup>
      )}
    </select>
  );
}

export default BackboneLinksPage;
