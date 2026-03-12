import { useState } from "react";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import {
  useDevices,
  useCreateDevice,
  useUpdateDevice,
  useDeleteDevice,
  useTestDeviceConnection,
} from "@/api/queries";
import type { CreateDeviceRequest, TestConnectionRequest, UpdateDeviceRequest } from "@/api/types";
import {
  Network,
  Server,
  Plus,
  Trash2,
  Plug,
  Pencil,
} from "lucide-react";

export function SettingsDevices() {
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
                    {device.identity ? ` \u2014 ${device.identity}` : ""}
                    {device.error ? ` \u2014 ${device.error}` : ""}
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
