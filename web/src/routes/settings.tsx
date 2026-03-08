import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { PageShell } from "@/components/layout/page-shell";
import { SettingsHelp } from "@/components/help-content";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import {
  useSecretsStatus,
  useEncryptionStatus,
  useUpdateSecrets,
  useRegenerateSession,
  useCertStatus,
  useSyslogStatus,
  useGeoIpStatus,
  useConnectionHistoryStats,
  useDevices,
  useCreateDevice,
  useUpdateDevice,
  useDeleteDevice,
  useTestDeviceConnection,
  useVlanConfigs,
  useUpdateVlanConfig,
  useAlertRules,
  useAlertHistory,
  useAlertChannels,
  useUpdateAlertRule,
  useCreateAlertRule,
  useDeleteAlertRule,
  useDeleteAlertHistory,
  useUpdateAlertChannel,
  useTestAlertChannel,
  useAlertStatus,
} from "@/api/queries";
import type { CreateDeviceRequest, TestConnectionRequest, UpdateDeviceRequest, VlanConfig, AlertRule } from "@/api/types";
import {
  Shield,
  Key,
  RefreshCw,
  Check,
  AlertTriangle,
  X,
  FileKey,
  Radio,
  Globe,
  Database,
  Server,
  Plus,
  Trash2,
  Plug,
  Pencil,
  Network,
  Bell,
  Send,
  ChevronDown,
  ChevronRight,
  Wand2,
} from "lucide-react";
import { formatBytes, formatNumber } from "@/lib/format";

export function SettingsPage() {
  return (
    <PageShell title="Settings" help={<SettingsHelp />}>
      <div className="space-y-6">
        <div className="flex justify-end">
          <Link
            to={"/setup-wizard" as "/"}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow hover:bg-primary/90 transition-colors"
          >
            <Wand2 className="h-4 w-4" />
            Setup Wizard
          </Link>
        </div>
        <AlertRulesSection />
        <AlertHistorySection />
        <AlertChannelsSection />
        <NetworkDevicesSection />
        <VlanConfigSection />
        <SecretsSection />
        <CertWardenSection />
        <EncryptionSection />
        <SyslogSection />
        <GeoIpSection />
        <ConnectionHistorySection />
      </div>
    </PageShell>
  );
}

// ── VLAN Config Section ──────────────────────────────────────────

function VlanConfigSection() {
  const { data: configs, isLoading, error } = useVlanConfigs();
  const updateConfig = useUpdateVlanConfig();

  if (isLoading) return <LoadingSpinner />;
  if (error) return <ErrorDisplay message={error.message} />;
  if (!configs || configs.length === 0) return null;

  function handleMediaTypeChange(config: VlanConfig, newType: "wired" | "wireless" | "mixed") {
    updateConfig.mutate({ ...config, media_type: newType });
  }

  function handleNameChange(config: VlanConfig, newName: string) {
    updateConfig.mutate({ ...config, name: newName });
  }

  function handleSubnetChange(config: VlanConfig, newSubnet: string) {
    updateConfig.mutate({ ...config, subnet: newSubnet || null });
  }

  function handleColorChange(config: VlanConfig, newColor: string) {
    updateConfig.mutate({ ...config, color: newColor });
  }

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <div className="mb-4 flex items-center gap-2">
        <Network className="h-5 w-5 text-primary" />
        <h2 className="text-lg font-semibold">VLAN Configuration</h2>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs text-muted-foreground">
              <th className="px-2 py-2">VLAN</th>
              <th className="px-2 py-2">Name</th>
              <th className="px-2 py-2">Media Type</th>
              <th className="px-2 py-2">Subnet</th>
              <th className="px-2 py-2">Color</th>
            </tr>
          </thead>
          <tbody>
            {configs.map((cfg) => (
              <tr key={cfg.vlan_id} className="border-b border-border/50">
                <td className="px-2 py-2 font-mono">{cfg.vlan_id}</td>
                <td className="px-2 py-2">
                  <input
                    type="text"
                    defaultValue={cfg.name}
                    onBlur={(e) => {
                      if (e.target.value !== cfg.name) handleNameChange(cfg, e.target.value);
                    }}
                    className="w-full rounded border border-border bg-background px-2 py-1 text-xs"
                  />
                </td>
                <td className="px-2 py-2">
                  <select
                    value={cfg.media_type}
                    onChange={(e) => handleMediaTypeChange(cfg, e.target.value as "wired" | "wireless" | "mixed")}
                    className="rounded border border-border bg-background px-2 py-1 text-xs"
                  >
                    <option value="wired">Wired</option>
                    <option value="wireless">Wireless</option>
                    <option value="mixed">Mixed</option>
                  </select>
                </td>
                <td className="px-2 py-2">
                  <input
                    type="text"
                    defaultValue={cfg.subnet ?? ""}
                    onBlur={(e) => {
                      if (e.target.value !== (cfg.subnet ?? "")) handleSubnetChange(cfg, e.target.value);
                    }}
                    className="w-full rounded border border-border bg-background px-2 py-1 text-xs font-mono"
                  />
                </td>
                <td className="px-2 py-2">
                  <input
                    type="color"
                    value={cfg.color ?? "#888888"}
                    onChange={(e) => handleColorChange(cfg, e.target.value)}
                    className="h-7 w-10 cursor-pointer rounded border border-border bg-background"
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Network Devices Section ────────────────────────────────────

function NetworkDevicesSection() {
  const { data: devices, isLoading, error } = useDevices();
  const [showAddForm, setShowAddForm] = useState(false);
  const [editingDeviceId, setEditingDeviceId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ status: string; identity?: string; error?: string } | null>(null);

  const createDevice = useCreateDevice();
  const updateDevice = useUpdateDevice();
  const deleteDevice = useDeleteDevice();
  const testConnection = useTestDeviceConnection();

  const [form, setForm] = useState({
    id: "",
    name: "",
    host: "",
    port: "443",
    tls: true,
    device_type: "switch" as "router" | "switch" | "swos_switch" | "snmp_switch",
    model: "",
    poll_interval_secs: "60",
    username: "",
    password: "",
    snmp_version: "v3" as "v2c" | "v3",
    snmp_auth_protocol: "SHA" as "SHA" | "MD5",
    snmp_priv_password: "",
    snmp_priv_protocol: "DES" as "DES" | "AES128",
  });

  const [editForm, setEditForm] = useState({
    name: "",
    host: "",
    port: "443",
    tls: true,
    model: "",
    poll_interval_secs: "60",
    username: "",
    password: "",
  });

  if (isLoading) return <LoadingSpinner />;
  if (error)
    return (
      <ErrorDisplay
        message={
          error instanceof Error ? error.message : "Failed to load devices"
        }
      />
    );

  const handleTest = async () => {
    setTestResult(null);
    const payload: TestConnectionRequest = {
      host: form.host,
      port: parseInt(form.port) || (form.device_type === "snmp_switch" ? 161 : form.device_type === "swos_switch" ? 80 : 443),
      tls: form.tls,
      device_type: form.device_type,
      username: form.username,
      password: form.password,
      ...(form.device_type === "snmp_switch" && form.snmp_version === "v3" ? {
        snmp_auth_protocol: form.snmp_auth_protocol,
        snmp_priv_password: form.snmp_priv_password,
        snmp_priv_protocol: form.snmp_priv_protocol,
      } : {}),
    };
    const result = await testConnection.mutateAsync(payload);
    setTestResult(result);
  };

  const handleAdd = async () => {
    const defaultPort = form.device_type === "snmp_switch" ? 161 : form.device_type === "swos_switch" ? 80 : 443;
    const payload: CreateDeviceRequest = {
      id: form.id,
      name: form.name,
      host: form.host,
      port: parseInt(form.port) || defaultPort,
      tls: form.tls,
      device_type: form.device_type,
      model: form.model || undefined,
      poll_interval_secs: parseInt(form.poll_interval_secs) || 60,
      username: form.username,
      password: form.password,
    };
    if (form.device_type === "snmp_switch" && form.snmp_version === "v3") {
      payload.snmp_auth_protocol = form.snmp_auth_protocol;
      payload.snmp_priv_password = form.snmp_priv_password;
      payload.snmp_priv_protocol = form.snmp_priv_protocol;
    }
    await createDevice.mutateAsync(payload);
    setShowAddForm(false);
    setForm({
      id: "",
      name: "",
      host: "",
      port: "443",
      tls: true,
      device_type: "switch",
      model: "",
      poll_interval_secs: "60",
      username: "",
      password: "",
      snmp_version: "v3",
      snmp_auth_protocol: "SHA",
      snmp_priv_password: "",
      snmp_priv_protocol: "DES",
    });
    setTestResult(null);
  };

  const handleDelete = async (id: string) => {
    if (!confirm(`Remove device "${id}"? This cannot be undone.`)) return;
    await deleteDevice.mutateAsync(id);
  };

  const handleStartEdit = (device: typeof devices extends (infer T)[] | undefined ? T : never) => {
    setEditingDeviceId(device.id);
    setEditForm({
      name: device.name,
      host: device.host,
      port: String(device.port),
      tls: device.tls,
      model: device.model ?? "",
      poll_interval_secs: String(device.poll_interval_secs),
      username: "",
      password: "",
    });
  };

  const handleSaveEdit = async () => {
    if (!editingDeviceId) return;
    const data: UpdateDeviceRequest = {
      name: editForm.name || undefined,
      host: editForm.host || undefined,
      port: parseInt(editForm.port) || 443,
      tls: editForm.tls,
      model: editForm.model || undefined,
      poll_interval_secs: parseInt(editForm.poll_interval_secs) || 60,
    };
    if (editForm.username) data.username = editForm.username;
    if (editForm.password) data.password = editForm.password;
    await updateDevice.mutateAsync({ id: editingDeviceId, data });
    setEditingDeviceId(null);
  };

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center justify-between border-b border-border p-4">
        <div className="flex items-center gap-3">
          <Network className="h-5 w-5 text-primary" />
          <div>
            <h2 className="text-lg font-semibold">Network Devices</h2>
            <p className="text-xs text-muted-foreground">
              Managed Mikrotik devices (router + switches)
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="flex items-center gap-1.5 rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90"
        >
          <Plus className="h-3.5 w-3.5" />
          Add Device
        </button>
      </div>

      <div className="divide-y divide-border">
        {devices?.map((device) => (
          <div key={device.id}>
            <div className="flex items-center gap-4 px-4 py-3">
              <Server className="h-4 w-4 text-muted-foreground flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">{device.name}</span>
                  <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground uppercase">
                    {device.device_type === "swos_switch" ? "SwOS" : device.device_type === "snmp_switch" ? "SNMP" : device.device_type === "switch" ? "RouterOS" : device.device_type}
                  </span>
                  {device.is_primary && (
                    <span className="rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">
                      primary
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2 mt-0.5">
                  <span
                    className={`inline-block h-2 w-2 rounded-full ${
                      device.status === "Online"
                        ? "bg-success"
                        : device.status === "Offline"
                          ? "bg-destructive"
                          : "bg-gray-400"
                    }`}
                  />
                  <span className="text-xs text-muted-foreground">
                    {device.host}:{device.port}
                    {device.identity ? ` — ${device.identity}` : ""}
                    {device.error ? ` — ${device.error}` : ""}
                  </span>
                  {device.model && (
                    <span className="text-xs text-muted-foreground">
                      &middot; {device.model}
                    </span>
                  )}
                </div>
              </div>
              <button
                onClick={() => editingDeviceId === device.id ? setEditingDeviceId(null) : handleStartEdit(device)}
                className="rounded p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground"
                title="Edit device"
              >
                <Pencil className="h-4 w-4" />
              </button>
              {!device.is_primary && (
                <button
                  onClick={() => handleDelete(device.id)}
                  disabled={deleteDevice.isPending}
                  className="rounded p-1.5 text-muted-foreground hover:bg-destructive/10 hover:text-destructive disabled:opacity-50"
                  title="Remove device"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              )}
            </div>

            {editingDeviceId === device.id && (
              <div className="border-t border-border/50 px-4 py-3 space-y-3 bg-muted/20">
                <h3 className="text-sm font-semibold flex items-center gap-2">
                  <Pencil className="h-3.5 w-3.5" /> Edit {device.name}
                </h3>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs text-muted-foreground mb-1">Display Name</label>
                    <input
                      type="text"
                      value={editForm.name}
                      onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                      className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-muted-foreground mb-1">Host</label>
                    <input
                      type="text"
                      value={editForm.host}
                      onChange={(e) => setEditForm({ ...editForm, host: e.target.value })}
                      className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
                    />
                  </div>
                  <div className="flex gap-3">
                    <div className="flex-1">
                      <label className="block text-xs text-muted-foreground mb-1">Port</label>
                      <input
                        type="number"
                        value={editForm.port}
                        onChange={(e) => setEditForm({ ...editForm, port: e.target.value })}
                        className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
                      />
                    </div>
                    <div className="flex items-end pb-1">
                      <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
                        <input
                          type="checkbox"
                          checked={editForm.tls}
                          onChange={(e) => setEditForm({ ...editForm, tls: e.target.checked })}
                        />
                        TLS
                      </label>
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs text-muted-foreground mb-1">Model</label>
                    <input
                      type="text"
                      value={editForm.model}
                      onChange={(e) => setEditForm({ ...editForm, model: e.target.value })}
                      className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-muted-foreground mb-1">Username</label>
                    <input
                      type="text"
                      value={editForm.username}
                      onChange={(e) => setEditForm({ ...editForm, username: e.target.value })}
                      className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-muted-foreground mb-1">
                      Password <span className="text-muted-foreground/60">(leave blank to keep current)</span>
                    </label>
                    <input
                      type="password"
                      value={editForm.password}
                      placeholder="unchanged"
                      onChange={(e) => setEditForm({ ...editForm, password: e.target.value })}
                      className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-muted-foreground mb-1">Poll Interval (seconds)</label>
                    <input
                      type="number"
                      value={editForm.poll_interval_secs}
                      onChange={(e) => setEditForm({ ...editForm, poll_interval_secs: e.target.value })}
                      className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
                    />
                  </div>
                </div>

                {updateDevice.error && (
                  <div className="rounded bg-destructive/10 px-3 py-2 text-xs text-destructive">
                    {updateDevice.error instanceof Error ? updateDevice.error.message : "Failed to update device"}
                  </div>
                )}

                <div className="flex gap-2 pt-1">
                  <button
                    onClick={handleSaveEdit}
                    disabled={!editForm.name || !editForm.host || !editForm.username || updateDevice.isPending}
                    className="rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                  >
                    {updateDevice.isPending ? "Saving..." : "Save Changes"}
                  </button>
                  <button
                    onClick={() => setEditingDeviceId(null)}
                    className="rounded border border-border px-3 py-1.5 text-xs font-medium hover:bg-muted"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        ))}

        {(!devices || devices.length === 0) && (
          <div className="px-4 py-6 text-center text-sm text-muted-foreground">
            No devices registered
          </div>
        )}
      </div>

      {showAddForm && (
        <div className="border-t border-border p-4 space-y-3 bg-muted/30">
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <Plus className="h-4 w-4" /> Add New Device
          </h3>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-muted-foreground mb-1">
                Device ID
              </label>
              <input
                type="text"
                placeholder="e.g. crs326-office"
                value={form.id}
                onChange={(e) => setForm({ ...form, id: e.target.value })}
                className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-muted-foreground mb-1">
                Display Name
              </label>
              <input
                type="text"
                placeholder="e.g. CRS326 Office"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-muted-foreground mb-1">
                Host
              </label>
              <input
                type="text"
                placeholder="e.g. 10.2.2.2"
                value={form.host}
                onChange={(e) => setForm({ ...form, host: e.target.value })}
                className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
              />
            </div>
            <div className="flex gap-3">
              <div className="flex-1">
                <label className="block text-xs text-muted-foreground mb-1">
                  Port
                </label>
                <input
                  type="number"
                  value={form.port}
                  onChange={(e) => setForm({ ...form, port: e.target.value })}
                  className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
                />
              </div>
              <div className="flex items-end pb-1">
                <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  <input
                    type="checkbox"
                    checked={form.tls}
                    onChange={(e) =>
                      setForm({ ...form, tls: e.target.checked })
                    }
                  />
                  TLS
                </label>
              </div>
            </div>
            <div>
              <label className="block text-xs text-muted-foreground mb-1">
                Type
              </label>
              <select
                value={form.device_type}
                onChange={(e) => {
                  const dt = e.target.value as "router" | "switch" | "swos_switch" | "snmp_switch";
                  if (dt === "snmp_switch") {
                    setForm({ ...form, device_type: dt, port: "161", tls: false, snmp_version: "v3" });
                  } else if (dt === "swos_switch") {
                    setForm({ ...form, device_type: dt, port: "80", tls: false });
                  } else if (form.device_type === "swos_switch" || form.device_type === "snmp_switch") {
                    // Switching away from SwOS/SNMP — restore RouterOS defaults
                    setForm({ ...form, device_type: dt, port: "443", tls: true });
                  } else {
                    setForm({ ...form, device_type: dt });
                  }
                }}
                className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
              >
                <option value="switch">Switch (RouterOS)</option>
                <option value="router">Router</option>
                <option value="swos_switch">Switch (SwOS)</option>
                <option value="snmp_switch">Switch (SNMP)</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-muted-foreground mb-1">
                Model (optional)
              </label>
              <input
                type="text"
                placeholder="e.g. CRS326-24G-2S+"
                value={form.model}
                onChange={(e) => setForm({ ...form, model: e.target.value })}
                className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
              />
            </div>
            {form.device_type === "snmp_switch" && (
            <div>
              <label className="block text-xs text-muted-foreground mb-1">SNMP Version</label>
              <select
                value={form.snmp_version}
                onChange={(e) => setForm({ ...form, snmp_version: e.target.value as "v2c" | "v3" })}
                className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
              >
                <option value="v3">SNMPv3 (AuthPriv)</option>
                <option value="v2c">SNMPv2c</option>
              </select>
            </div>
            )}
            {(form.device_type !== "snmp_switch" || form.snmp_version === "v3") && (
            <div>
              <label className="block text-xs text-muted-foreground mb-1">
                {form.device_type === "snmp_switch" ? "Security Name" : "Username"}
              </label>
              <input
                type="text"
                placeholder={form.device_type === "snmp_switch" ? "snmpuser" : "admin"}
                value={form.username}
                onChange={(e) =>
                  setForm({ ...form, username: e.target.value })
                }
                className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
              />
            </div>
            )}
            <div>
              <label className="block text-xs text-muted-foreground mb-1">
                {form.device_type === "snmp_switch"
                  ? form.snmp_version === "v3" ? "Auth Password" : "Community String"
                  : "Password"}
              </label>
              <input
                type="password"
                placeholder={form.device_type === "snmp_switch" && form.snmp_version === "v2c" ? "public" : undefined}
                value={form.password}
                onChange={(e) =>
                  setForm({ ...form, password: e.target.value })
                }
                className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
              />
            </div>
            {form.device_type === "snmp_switch" && form.snmp_version === "v3" && (
            <>
              <div>
                <label className="block text-xs text-muted-foreground mb-1">Auth Protocol</label>
                <select
                  value={form.snmp_auth_protocol}
                  onChange={(e) => setForm({ ...form, snmp_auth_protocol: e.target.value as "SHA" | "MD5" })}
                  className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
                >
                  <option value="SHA">SHA</option>
                  <option value="MD5">MD5</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-muted-foreground mb-1">Privacy Password <span className="text-muted-foreground/60">(optional)</span></label>
                <input
                  type="password"
                  placeholder="Leave empty for authNoPriv"
                  value={form.snmp_priv_password}
                  onChange={(e) => setForm({ ...form, snmp_priv_password: e.target.value })}
                  className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs text-muted-foreground mb-1">Privacy Protocol</label>
                <select
                  value={form.snmp_priv_protocol}
                  onChange={(e) => setForm({ ...form, snmp_priv_protocol: e.target.value as "DES" | "AES128" })}
                  className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
                >
                  <option value="DES">DES</option>
                  <option value="AES128">AES-128</option>
                </select>
              </div>
            </>
            )}
            <div>
              <label className="block text-xs text-muted-foreground mb-1">
                Poll Interval (seconds)
              </label>
              <input
                type="number"
                value={form.poll_interval_secs}
                onChange={(e) =>
                  setForm({ ...form, poll_interval_secs: e.target.value })
                }
                className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
              />
            </div>
          </div>

          {testResult && (
            <div
              className={`rounded px-3 py-2 text-xs ${
                testResult.status === "online"
                  ? "bg-success/10 text-success"
                  : "bg-destructive/10 text-destructive"
              }`}
            >
              {testResult.status === "online"
                ? `Connected: ${testResult.identity}`
                : `Failed: ${testResult.error}`}
            </div>
          )}

          {createDevice.error && (
            <div className="rounded bg-destructive/10 px-3 py-2 text-xs text-destructive">
              {createDevice.error instanceof Error
                ? createDevice.error.message
                : "Failed to add device"}
            </div>
          )}

          <div className="flex gap-2 pt-1">
            <button
              onClick={handleTest}
              disabled={
                !form.host ||
                !form.password ||
                (form.device_type !== "snmp_switch" && !form.username) ||
                (form.device_type === "snmp_switch" && form.snmp_version === "v3" && !form.username) ||
                testConnection.isPending
              }
              className="flex items-center gap-1.5 rounded border border-border px-3 py-1.5 text-xs font-medium hover:bg-muted disabled:opacity-50"
            >
              <Plug className="h-3.5 w-3.5" />
              {testConnection.isPending ? "Testing..." : "Test Connection"}
            </button>
            <button
              onClick={handleAdd}
              disabled={
                !form.id ||
                !form.name ||
                !form.host ||
                !form.password ||
                (form.device_type !== "snmp_switch" && !form.username) ||
                (form.device_type === "snmp_switch" && form.snmp_version === "v3" && !form.username) ||
                createDevice.isPending
              }
              className="rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {createDevice.isPending ? "Adding..." : "Add Device"}
            </button>
            <button
              onClick={() => {
                setShowAddForm(false);
                setTestResult(null);
              }}
              className="rounded border border-border px-3 py-1.5 text-xs font-medium hover:bg-muted"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Secrets Section ─────────────────────────────────────────────

function SecretsSection() {
  const { data, isLoading, error } = useSecretsStatus();
  const [editingSecret, setEditingSecret] = useState<string | null>(null);
  const [editValue, setEditValue] = useState("");
  const [confirmRegenerate, setConfirmRegenerate] = useState(false);

  const updateSecrets = useUpdateSecrets();
  const regenerateSession = useRegenerateSession();

  if (isLoading) return <LoadingSpinner />;
  if (error) {
    // 404 means secrets manager isn't enabled
    if ("status" in error && (error as { status: number }).status === 404) {
      return (
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="flex items-center gap-3 mb-3">
            <Shield className="h-5 w-5 text-muted-foreground" />
            <h2 className="text-lg font-semibold">Encrypted Secrets</h2>
          </div>
          <p className="text-sm text-muted-foreground">
            Secrets encryption is not enabled. Add an{" "}
            <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
              [oidc.bootstrap]
            </code>{" "}
            section to your config to enable encrypted secrets at rest.
          </p>
        </div>
      );
    }
    return <ErrorDisplay message={error instanceof Error ? error.message : "Failed to load secrets"} />;
  }
  if (!data) return null;

  const handleSave = async (secretName: string) => {
    if (!editValue.trim()) return;
    const payload: Record<string, string> = {};
    payload[secretName] = editValue;
    await updateSecrets.mutateAsync(payload);
    setEditingSecret(null);
    setEditValue("");
  };

  const handleRegenerate = async () => {
    await regenerateSession.mutateAsync();
    setConfirmRegenerate(false);
    // This will likely redirect to login since all sessions are cleared
  };

  const secretLabels: Record<string, string> = {
    router_username: "Router Username",
    router_password: "Router Password",
    oidc_client_secret: "OIDC Client Secret",
    session_secret: "Session Secret",
    certwarden_cert_api_key: "CertWarden Certificate API Key",
    certwarden_key_api_key: "CertWarden Private Key API Key",
    maxmind_account_id: "MaxMind Account ID",
    maxmind_license_key: "MaxMind License Key",
  };

  const isPasswordField = (name: string) =>
    name === "router_password" ||
    name === "oidc_client_secret" ||
    name === "certwarden_cert_api_key" ||
    name === "certwarden_key_api_key" ||
    name === "maxmind_license_key";

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-3 border-b border-border p-4">
        <Shield className="h-5 w-5 text-primary" />
        <div>
          <h2 className="text-lg font-semibold">Encrypted Secrets</h2>
          <p className="text-xs text-muted-foreground">
            Key fingerprint:{" "}
            <code className="font-mono">{data.key_fingerprint}</code>
          </p>
        </div>
      </div>

      <div className="divide-y divide-border">
        {data.secrets.map((secret) => (
          <div key={secret.name} className="flex items-center gap-4 px-4 py-3">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">
                  {secretLabels[secret.name] || secret.name}
                </span>
                {secret.auto_generated && (
                  <span className="rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">
                    auto-generated
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2 mt-0.5">
                {!secret.stored ? (
                  <>
                    <X className="h-3 w-3 text-muted-foreground" />
                    <span className="text-xs text-muted-foreground">
                      Not configured
                    </span>
                  </>
                ) : secret.key_current ? (
                  <>
                    <Check className="h-3 w-3 text-success" />
                    <span className="text-xs text-muted-foreground">
                      Encrypted &middot; Updated{" "}
                      {new Date(secret.updated_at * 1000).toLocaleDateString(
                        undefined,
                        {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                          hour: "2-digit",
                          minute: "2-digit",
                        },
                      )}
                    </span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="h-3 w-3 text-warning" />
                    <span className="text-xs text-muted-foreground">
                      Key mismatch &middot; Updated{" "}
                      {new Date(secret.updated_at * 1000).toLocaleDateString(
                        undefined,
                        {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                          hour: "2-digit",
                          minute: "2-digit",
                        },
                      )}
                    </span>
                  </>
                )}
              </div>
            </div>

            <div className="flex items-center gap-2">
              {secret.name === "session_secret" ? (
                confirmRegenerate ? (
                  <div className="flex items-center gap-1">
                    <span className="text-xs text-warning mr-1">
                      This will log out all users
                    </span>
                    <button
                      onClick={handleRegenerate}
                      disabled={regenerateSession.isPending}
                      className="rounded bg-warning px-2.5 py-1 text-xs font-medium text-background hover:bg-warning/80 disabled:opacity-50"
                    >
                      {regenerateSession.isPending ? "..." : "Confirm"}
                    </button>
                    <button
                      onClick={() => setConfirmRegenerate(false)}
                      className="rounded bg-muted px-2 py-1 text-xs text-muted-foreground hover:text-foreground"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </div>
                ) : (
                  <button
                    onClick={() => setConfirmRegenerate(true)}
                    className="flex items-center gap-1.5 rounded bg-muted px-2.5 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground"
                  >
                    <RefreshCw className="h-3 w-3" />
                    Regenerate
                  </button>
                )
              ) : editingSecret === secret.name ? (
                <div className="flex items-center gap-1">
                  <input
                    type={isPasswordField(secret.name) ? "password" : "text"}
                    value={editValue}
                    onChange={(e) => setEditValue(e.target.value)}
                    className="w-48 rounded border border-border bg-background px-2 py-1 text-xs focus:border-primary focus:outline-none"
                    placeholder={`New ${secretLabels[secret.name]?.toLowerCase() || "value"}`}
                    autoFocus
                    onKeyDown={(e) => {
                      if (e.key === "Enter") handleSave(secret.name);
                      if (e.key === "Escape") {
                        setEditingSecret(null);
                        setEditValue("");
                      }
                    }}
                  />
                  <button
                    onClick={() => handleSave(secret.name)}
                    disabled={
                      updateSecrets.isPending || !editValue.trim()
                    }
                    className="rounded bg-primary px-2.5 py-1 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                  >
                    {updateSecrets.isPending ? "..." : "Save"}
                  </button>
                  <button
                    onClick={() => {
                      setEditingSecret(null);
                      setEditValue("");
                    }}
                    className="rounded bg-muted px-2 py-1 text-xs text-muted-foreground hover:text-foreground"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </div>
              ) : (
                <button
                  onClick={() => {
                    setEditingSecret(secret.name);
                    setEditValue("");
                  }}
                  className="rounded bg-muted px-2.5 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground"
                >
                  {secret.stored ? "Update" : "Add"}
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── CertWarden Section ──────────────────────────────────────────

function CertWardenSection() {
  const { data, isLoading, error } = useCertStatus();

  if (isLoading) return <LoadingSpinner />;
  if (error) {
    if ("status" in error && (error as { status: number }).status === 500) {
      return (
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="flex items-center gap-3 mb-3">
            <FileKey className="h-5 w-5 text-muted-foreground" />
            <h2 className="text-lg font-semibold">mTLS Certificate</h2>
          </div>
          <p className="text-sm text-muted-foreground">
            No certificate found on disk. Complete setup to provision a certificate from CertWarden.
          </p>
        </div>
      );
    }
    return null;
  }
  if (!data) return null;

  const daysUntilExpiry = Math.floor(data.seconds_until_expiry / 86400);
  const isExpiringSoon = daysUntilExpiry <= data.renewal_threshold_days && daysUntilExpiry > 0;
  const isExpired = data.seconds_until_expiry <= 0;

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-3 border-b border-border p-4">
        <FileKey className="h-5 w-5 text-primary" />
        <h2 className="text-lg font-semibold">mTLS Certificate</h2>
      </div>

      <div className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Subject</span>
          <code className="text-sm font-mono">{data.subject_cn}</code>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Issuer</span>
          <code className="text-sm font-mono">{data.issuer_cn}</code>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Not Before</span>
          <span className="text-sm">
            {new Date(data.not_before * 1000).toLocaleDateString(undefined, {
              month: "short",
              day: "numeric",
              year: "numeric",
            })}
          </span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Expires</span>
          <div className="flex items-center gap-1.5">
            {isExpired ? (
              <>
                <AlertTriangle className="h-3.5 w-3.5 text-destructive" />
                <span className="text-sm text-destructive">Expired</span>
              </>
            ) : isExpiringSoon ? (
              <>
                <AlertTriangle className="h-3.5 w-3.5 text-warning" />
                <span className="text-sm text-warning">
                  {new Date(data.not_after * 1000).toLocaleDateString(undefined, {
                    month: "short",
                    day: "numeric",
                    year: "numeric",
                  })}{" "}
                  ({daysUntilExpiry}d remaining)
                </span>
              </>
            ) : (
              <>
                <Check className="h-3.5 w-3.5 text-success" />
                <span className="text-sm">
                  {new Date(data.not_after * 1000).toLocaleDateString(undefined, {
                    month: "short",
                    day: "numeric",
                    year: "numeric",
                  })}{" "}
                  ({daysUntilExpiry}d remaining)
                </span>
              </>
            )}
          </div>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Serial</span>
          <code className="text-xs font-mono text-muted-foreground">{data.serial}</code>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Auto-Renewal</span>
          <div className="flex items-center gap-1.5">
            {data.auto_renewal_enabled ? (
              <>
                <Check className="h-3.5 w-3.5 text-success" />
                <span className="text-sm text-success">
                  Enabled (every {data.check_interval_hours}h, renew within {data.renewal_threshold_days}d)
                </span>
              </>
            ) : (
              <span className="text-sm text-muted-foreground">Disabled</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Encryption Key Section ──────────────────────────────────────

function EncryptionSection() {
  const { data, isLoading, error } = useEncryptionStatus();

  if (isLoading) return <LoadingSpinner />;
  if (error) {
    if ("status" in error && (error as { status: number }).status === 404) {
      return null; // Don't show encryption section if not enabled
    }
    return <ErrorDisplay message={error instanceof Error ? error.message : "Failed to load encryption status"} />;
  }
  if (!data) return null;

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-3 border-b border-border p-4">
        <Key className="h-5 w-5 text-primary" />
        <h2 className="text-lg font-semibold">Encryption Key</h2>
      </div>

      <div className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">KEK Fingerprint</span>
          <code className="text-sm font-mono">{data.key_fingerprint}</code>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Key Source</span>
          <span className="text-sm">
            {data.source === "keycloak_mtls" ? "Keycloak mTLS" : data.source}
          </span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Secrets Status</span>
          <div className="flex items-center gap-1.5">
            {data.all_secrets_current ? (
              <>
                <Check className="h-3.5 w-3.5 text-success" />
                <span className="text-sm text-success">
                  All secrets current
                </span>
              </>
            ) : (
              <>
                <AlertTriangle className="h-3.5 w-3.5 text-warning" />
                <span className="text-sm text-warning">
                  Key mismatch detected
                </span>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Syslog Section ──────────────────────────────────────────────

function SyslogSection() {
  const { data, isLoading } = useSyslogStatus();

  if (isLoading) return <LoadingSpinner />;
  if (!data) return null;

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-3 border-b border-border p-4">
        <Radio className="h-5 w-5 text-primary" />
        <h2 className="text-lg font-semibold">Syslog Listener</h2>
      </div>

      <div className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Status</span>
          <div className="flex items-center gap-1.5">
            {data.listening ? (
              <>
                <span className="h-2 w-2 rounded-full bg-success animate-pulse" />
                <span className="text-sm text-success">Listening</span>
              </>
            ) : (
              <>
                <span className="h-2 w-2 rounded-full bg-muted-foreground" />
                <span className="text-sm text-muted-foreground">Stopped</span>
              </>
            )}
          </div>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Port</span>
          <code className="text-sm font-mono">{data.port}</code>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Events Today</span>
          <span className="text-sm">{formatNumber(data.events_today)}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Events This Week</span>
          <span className="text-sm">{formatNumber(data.events_week)}</span>
        </div>

        <div className="mt-4 rounded-md bg-muted/50 p-3">
          <p className="text-xs font-medium text-muted-foreground mb-2">
            RouterOS Configuration
          </p>
          <pre className="text-xs font-mono text-muted-foreground whitespace-pre-wrap select-all">
{`/system logging action
add name=ion-drift target=remote remote=<ion-drift-ip> remote-port=${data.port} bsd-syslog=yes

/system logging
add action=ion-drift topics=firewall`}
          </pre>
        </div>
      </div>
    </div>
  );
}

// ── GeoIP Section ───────────────────────────────────────────────

function GeoIpSection() {
  const { data, isLoading } = useGeoIpStatus();

  if (isLoading) return <LoadingSpinner />;
  if (!data) return null;

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-3 border-b border-border p-4">
        <Globe className="h-5 w-5 text-primary" />
        <h2 className="text-lg font-semibold">GeoIP Database</h2>
      </div>

      <div className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">MaxMind Database</span>
          <div className="flex items-center gap-1.5">
            {data.has_maxmind ? (
              <>
                <Check className="h-3.5 w-3.5 text-success" />
                <span className="text-sm text-success">Loaded</span>
              </>
            ) : (
              <>
                <AlertTriangle className="h-3.5 w-3.5 text-warning" />
                <span className="text-sm text-warning">Not loaded</span>
              </>
            )}
          </div>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">MaxMind Credentials</span>
          <div className="flex items-center gap-1.5">
            {data.has_credentials ? (
              <>
                <Check className="h-3.5 w-3.5 text-success" />
                <span className="text-sm text-success">Configured</span>
              </>
            ) : (
              <span className="text-sm text-muted-foreground">Not configured</span>
            )}
          </div>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Fallback</span>
          <span className="text-sm">ip-api.com (rate-limited)</span>
        </div>
        {!data.has_credentials && (
          <p className="text-xs text-muted-foreground mt-2">
            Add MaxMind Account ID and License Key in the Encrypted Secrets section above to enable auto-download.
            Free account required &mdash;{" "}
            <a
              href="https://www.maxmind.com/en/geolite2/signup"
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline"
            >
              sign up at maxmind.com
            </a>
          </p>
        )}
        {!data.has_maxmind && data.has_credentials && (
          <p className="text-xs text-muted-foreground mt-2">
            Credentials configured. Place GeoLite2-City.mmdb and GeoLite2-ASN.mmdb in the{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">data/geoip/</code>{" "}
            directory, or restart to trigger auto-download.
          </p>
        )}
      </div>
    </div>
  );
}

// ── Alert Rules Section ──────────────────────────────────────────

function AlertRulesSection() {
  const { data: rules, isLoading } = useAlertRules();
  const { data: status } = useAlertStatus();
  const updateRule = useUpdateAlertRule();
  const createRule = useCreateAlertRule();
  const deleteRule = useDeleteAlertRule();
  const [showAdd, setShowAdd] = useState(false);
  const [newRule, setNewRule] = useState({ name: "", event_type: "anomaly_critical", cooldown_seconds: "300" });

  if (isLoading) return <LoadingSpinner />;

  const eventTypes = [
    "anomaly_critical", "anomaly_correlated", "anomaly_warning",
    "device_new", "device_flagged", "device_offline",
    "port_violation", "interface_down",
  ];

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center justify-between border-b border-border p-4">
        <div className="flex items-center gap-3">
          <Bell className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-semibold">Alert Rules</h2>
          {status && (
            <span className="text-xs text-muted-foreground">
              {status.enabled_rules}/{status.total_rules} enabled — {status.alerts_fired_today} today
            </span>
          )}
        </div>
        <button
          onClick={() => setShowAdd(!showAdd)}
          className="flex items-center gap-1 rounded border border-border px-3 py-1.5 text-xs hover:bg-accent"
        >
          <Plus className="h-3.5 w-3.5" /> Add Rule
        </button>
      </div>

      {showAdd && (
        <div className="border-b border-border p-4 bg-muted/30 flex flex-wrap items-end gap-3">
          <div>
            <label className="text-xs text-muted-foreground">Name</label>
            <input
              className="block w-48 rounded border border-border bg-background px-2 py-1 text-sm"
              value={newRule.name}
              onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
              placeholder="My Rule"
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground">Event Type</label>
            <select
              className="block rounded border border-border bg-background px-2 py-1 text-sm"
              value={newRule.event_type}
              onChange={(e) => setNewRule({ ...newRule, event_type: e.target.value })}
            >
              {eventTypes.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs text-muted-foreground">Cooldown (s)</label>
            <input
              className="block w-24 rounded border border-border bg-background px-2 py-1 text-sm"
              type="number"
              value={newRule.cooldown_seconds}
              onChange={(e) => setNewRule({ ...newRule, cooldown_seconds: e.target.value })}
            />
          </div>
          <button
            className="rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            disabled={!newRule.name || createRule.isPending}
            onClick={async () => {
              await createRule.mutateAsync({
                name: newRule.name,
                event_type: newRule.event_type,
                cooldown_seconds: parseInt(newRule.cooldown_seconds) || 300,
              });
              setShowAdd(false);
              setNewRule({ name: "", event_type: "anomaly_critical", cooldown_seconds: "300" });
            }}
          >
            {createRule.isPending ? "Creating…" : "Create"}
          </button>
        </div>
      )}

      <div className="divide-y divide-border">
        {rules?.map((rule) => (
          <AlertRuleRow key={rule.id} rule={rule} onUpdate={updateRule} onDelete={deleteRule} />
        ))}
        {(!rules || rules.length === 0) && (
          <div className="p-4 text-sm text-muted-foreground">No alert rules configured.</div>
        )}
      </div>
    </div>
  );
}

function AlertRuleRow({
  rule,
  onUpdate,
  onDelete,
}: {
  rule: AlertRule;
  onUpdate: ReturnType<typeof useUpdateAlertRule>;
  onDelete: ReturnType<typeof useDeleteAlertRule>;
}) {
  const isDefault = rule.id <= 8;
  const channels: string[] = (() => {
    try { return JSON.parse(rule.delivery_channels); } catch { return []; }
  })();

  return (
    <div className="flex items-center gap-4 px-4 py-3">
      <button
        className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors ${
          rule.enabled ? "bg-primary" : "bg-muted"
        }`}
        onClick={() => onUpdate.mutate({ id: rule.id, enabled: !rule.enabled })}
      >
        <span
          className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${
            rule.enabled ? "translate-x-4" : "translate-x-1"
          }`}
        />
      </button>

      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium truncate">{rule.name}</div>
        <div className="text-xs text-muted-foreground">
          {rule.event_type}
          {rule.severity_filter && ` (${rule.severity_filter})`}
          {" · "}
          {rule.cooldown_seconds}s cooldown
          {" · "}
          {channels.join(", ") || "no channels"}
        </div>
      </div>

      {!isDefault && (
        <button
          className="rounded p-1 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
          onClick={() => {
            if (confirm(`Delete rule "${rule.name}"?`)) {
              onDelete.mutate(rule.id);
            }
          }}
        >
          <Trash2 className="h-4 w-4" />
        </button>
      )}
    </div>
  );
}

// ── Alert History Section ────────────────────────────────────────

function AlertHistorySection() {
  const { data: history, isLoading } = useAlertHistory(50);
  const clearHistory = useDeleteAlertHistory();
  const [expandedId, setExpandedId] = useState<number | null>(null);

  if (isLoading) return <LoadingSpinner />;

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center justify-between border-b border-border p-4">
        <div className="flex items-center gap-3">
          <Bell className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-semibold">Alert History</h2>
          {history && (
            <span className="text-xs text-muted-foreground">
              {history.length} recent alerts
            </span>
          )}
        </div>
        {history && history.length > 0 && (
          <button
            className="flex items-center gap-1 rounded border border-destructive/50 px-3 py-1.5 text-xs text-destructive hover:bg-destructive/10 disabled:opacity-50"
            disabled={clearHistory.isPending}
            onClick={() => {
              if (confirm("Clear all alert history?")) clearHistory.mutate();
            }}
          >
            <Trash2 className="h-3.5 w-3.5" /> Clear
          </button>
        )}
      </div>

      <div className="divide-y divide-border max-h-96 overflow-y-auto">
        {history?.map((entry) => {
          const attempted: string[] = (() => { try { return JSON.parse(entry.channels_attempted); } catch { return []; } })();
          const succeeded: string[] = (() => { try { return JSON.parse(entry.channels_succeeded); } catch { return []; } })();
          const allOk = attempted.length > 0 && attempted.length === succeeded.length;
          const expanded = expandedId === entry.id;

          return (
            <div key={entry.id}>
              <button
                className="w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-accent/50"
                onClick={() => setExpandedId(expanded ? null : entry.id)}
              >
                {expanded ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground shrink-0" /> : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />}
                <span className={`text-xs font-medium rounded px-1.5 py-0.5 ${
                  entry.severity === "critical" ? "bg-destructive/20 text-destructive" :
                  entry.severity === "warning" ? "bg-yellow-500/20 text-yellow-600" :
                  "bg-muted text-muted-foreground"
                }`}>
                  {entry.severity}
                </span>
                <span className="text-sm truncate flex-1">{entry.title}</span>
                <span className="text-xs text-muted-foreground shrink-0">
                  {allOk ? "✅" : "❌"} {attempted.join(",")}
                </span>
                <span className="text-xs text-muted-foreground shrink-0">
                  {new Date(entry.fired_at + "Z").toLocaleString(undefined, {
                    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
                  })}
                </span>
              </button>
              {expanded && (
                <div className="px-4 pb-3 pl-12 text-xs text-muted-foreground whitespace-pre-wrap">
                  {entry.body}
                  {entry.device_mac && (
                    <div className="mt-1">Device: {entry.device_hostname || entry.device_mac} {entry.device_ip && `(${entry.device_ip})`}</div>
                  )}
                </div>
              )}
            </div>
          );
        })}
        {(!history || history.length === 0) && (
          <div className="p-4 text-sm text-muted-foreground">No alerts fired yet.</div>
        )}
      </div>
    </div>
  );
}

// ── Alert Channels Section ──────────────────────────────────────

function AlertChannelsSection() {
  const { data: channels, isLoading } = useAlertChannels();
  const updateChannel = useUpdateAlertChannel();
  const testChannel = useTestAlertChannel();
  const [testResults, setTestResults] = useState<Record<string, { ok: boolean; error?: string }>>({});

  if (isLoading) return <LoadingSpinner />;

  const handleTest = async (channel: string) => {
    setTestResults((prev) => ({ ...prev, [channel]: { ok: true } }));
    try {
      await testChannel.mutateAsync(channel);
      setTestResults((prev) => ({ ...prev, [channel]: { ok: true } }));
    } catch (e) {
      setTestResults((prev) => ({ ...prev, [channel]: { ok: false, error: e instanceof Error ? e.message : "Failed" } }));
    }
  };

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-3 border-b border-border p-4">
        <Send className="h-5 w-5 text-primary" />
        <h2 className="text-lg font-semibold">Delivery Channels</h2>
      </div>

      <div className="divide-y divide-border">
        {channels?.map((ch) => (
          <ChannelCard key={ch.channel} config={ch} onUpdate={updateChannel} onTest={handleTest} testResult={testResults[ch.channel]} />
        ))}
      </div>
    </div>
  );
}

function ChannelCard({
  config,
  onUpdate,
  onTest,
  testResult,
}: {
  config: { channel: string; enabled: boolean; config_json: Record<string, unknown> };
  onUpdate: ReturnType<typeof useUpdateAlertChannel>;
  onTest: (channel: string) => void;
  testResult?: { ok: boolean; error?: string };
}) {
  const cfg = config.config_json;

  const handleBlur = (field: string, value: string) => {
    onUpdate.mutate({ channel: config.channel, [field]: value });
  };

  const channelLabel = config.channel === "ntfy" ? "ntfy" : config.channel === "smtp" ? "SMTP" : "Webhook";

  return (
    <div className="p-4 space-y-3">
      <div className="flex items-center justify-between">
        <span className="font-medium text-sm">{channelLabel}</span>
        <div className="flex items-center gap-2">
          {testResult && (
            <span className={`text-xs ${testResult.ok ? "text-green-500" : "text-destructive"}`}>
              {testResult.ok ? "✅ Sent" : `❌ ${testResult.error}`}
            </span>
          )}
          <button
            className="rounded border border-border px-2 py-1 text-xs hover:bg-accent"
            onClick={() => onTest(config.channel)}
          >
            Test
          </button>
          <button
            className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors ${
              config.enabled ? "bg-primary" : "bg-muted"
            }`}
            onClick={() => onUpdate.mutate({ channel: config.channel, enabled: !config.enabled })}
          >
            <span className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${
              config.enabled ? "translate-x-4" : "translate-x-1"
            }`} />
          </button>
        </div>
      </div>

      {config.channel === "ntfy" && (
        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="text-xs text-muted-foreground">Server URL</label>
            <input
              className="block w-full rounded border border-border bg-background px-2 py-1 text-sm"
              defaultValue={(cfg.url as string) || "https://ntfy.sh"}
              onBlur={(e) => handleBlur("url", e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground">Topic</label>
            <input
              className="block w-full rounded border border-border bg-background px-2 py-1 text-sm"
              defaultValue={(cfg.topic as string) || ""}
              onBlur={(e) => handleBlur("topic", e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground">Token (optional)</label>
            <input
              type="password"
              className="block w-full rounded border border-border bg-background px-2 py-1 text-sm"
              defaultValue={(cfg.token as string) || ""}
              onBlur={(e) => handleBlur("token", e.target.value)}
            />
          </div>
        </div>
      )}

      {config.channel === "webhook" && (
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-muted-foreground">URL</label>
            <input
              className="block w-full rounded border border-border bg-background px-2 py-1 text-sm"
              defaultValue={(cfg.url as string) || ""}
              onBlur={(e) => handleBlur("url", e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground">Secret (optional)</label>
            <input
              type="password"
              className="block w-full rounded border border-border bg-background px-2 py-1 text-sm"
              defaultValue={(cfg.secret as string) || ""}
              onBlur={(e) => handleBlur("secret", e.target.value)}
            />
          </div>
        </div>
      )}

      {config.channel === "smtp" && (
        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="text-xs text-muted-foreground">Host</label>
            <input
              className="block w-full rounded border border-border bg-background px-2 py-1 text-sm"
              defaultValue={(cfg.host as string) || ""}
              onBlur={(e) => handleBlur("host", e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground">Port</label>
            <input
              type="number"
              className="block w-full rounded border border-border bg-background px-2 py-1 text-sm"
              defaultValue={String(cfg.port ?? 587)}
              onBlur={(e) => handleBlur("port", e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground">Username</label>
            <input
              className="block w-full rounded border border-border bg-background px-2 py-1 text-sm"
              defaultValue={(cfg.username as string) || ""}
              onBlur={(e) => handleBlur("username", e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground">From</label>
            <input
              className="block w-full rounded border border-border bg-background px-2 py-1 text-sm"
              defaultValue={(cfg.from as string) || ""}
              onBlur={(e) => handleBlur("from", e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground">To (comma-separated)</label>
            <input
              className="block w-full rounded border border-border bg-background px-2 py-1 text-sm"
              defaultValue={Array.isArray(cfg.to) ? (cfg.to as string[]).join(", ") : ""}
              onBlur={(e) => {
                const arr = e.target.value.split(",").map((s) => s.trim()).filter(Boolean);
                onUpdate.mutate({ channel: "smtp", to: arr });
              }}
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground">Password</label>
            <input
              type="password"
              className="block w-full rounded border border-border bg-background px-2 py-1 text-sm"
              placeholder="••••••••"
              onBlur={(e) => {
                if (e.target.value) handleBlur("password", e.target.value);
              }}
            />
          </div>
        </div>
      )}
    </div>
  );
}

// ── Connection History Section ──────────────────────────────────

function ConnectionHistorySection() {
  const { data, isLoading } = useConnectionHistoryStats();

  if (isLoading) return <LoadingSpinner />;
  if (!data) return null;

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-3 border-b border-border p-4">
        <Database className="h-5 w-5 text-primary" />
        <h2 className="text-lg font-semibold">Connection History</h2>
      </div>

      <div className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Retention</span>
          <span className="text-sm">{data.retention_days} days</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Records</span>
          <span className="text-sm">{formatNumber(data.row_count)}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Database Size</span>
          <span className="text-sm">{formatBytes(data.db_size_bytes)}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Oldest Record</span>
          <span className="text-sm">
            {data.oldest_record
              ? new Date(data.oldest_record).toLocaleDateString(undefined, {
                  month: "short",
                  day: "numeric",
                  year: "numeric",
                })
              : "No records yet"}
          </span>
        </div>
      </div>
    </div>
  );
}
