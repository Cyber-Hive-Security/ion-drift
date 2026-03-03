import { useState } from "react";
import { PageShell } from "@/components/layout/page-shell";
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
} from "@/api/queries";
import type { CreateDeviceRequest, UpdateDeviceRequest } from "@/api/types";
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
} from "lucide-react";
import { formatBytes, formatNumber } from "@/lib/format";

export function SettingsPage() {
  return (
    <PageShell title="Settings">
      <div className="space-y-6">
        <NetworkDevicesSection />
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
    device_type: "switch" as "router" | "switch" | "swos_switch",
    model: "",
    poll_interval_secs: "60",
    username: "",
    password: "",
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
    const result = await testConnection.mutateAsync({
      host: form.host,
      port: parseInt(form.port) || (form.device_type === "swos_switch" ? 80 : 443),
      tls: form.tls,
      device_type: form.device_type,
      username: form.username,
      password: form.password,
    });
    setTestResult(result);
  };

  const handleAdd = async () => {
    const defaultPort = form.device_type === "swos_switch" ? 80 : 443;
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
                    {device.device_type === "swos_switch" ? "SwOS" : device.device_type}
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
                        ? "bg-green-500"
                        : device.status === "Offline"
                          ? "bg-red-500"
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
                  <div className="rounded bg-red-500/10 px-3 py-2 text-xs text-red-400">
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
                  const dt = e.target.value as "router" | "switch" | "swos_switch";
                  if (dt === "swos_switch") {
                    setForm({ ...form, device_type: dt, port: "80", tls: false });
                  } else if (form.device_type === "swos_switch") {
                    // Switching away from SwOS — restore RouterOS defaults
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
            <div>
              <label className="block text-xs text-muted-foreground mb-1">
                Username
              </label>
              <input
                type="text"
                placeholder="admin"
                value={form.username}
                onChange={(e) =>
                  setForm({ ...form, username: e.target.value })
                }
                className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-muted-foreground mb-1">
                Password
              </label>
              <input
                type="password"
                value={form.password}
                onChange={(e) =>
                  setForm({ ...form, password: e.target.value })
                }
                className="w-full rounded border border-border bg-background px-2.5 py-1.5 text-sm"
              />
            </div>
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
                  ? "bg-green-500/10 text-green-400"
                  : "bg-red-500/10 text-red-400"
              }`}
            >
              {testResult.status === "online"
                ? `Connected: ${testResult.identity}`
                : `Failed: ${testResult.error}`}
            </div>
          )}

          {createDevice.error && (
            <div className="rounded bg-red-500/10 px-3 py-2 text-xs text-red-400">
              {createDevice.error instanceof Error
                ? createDevice.error.message
                : "Failed to add device"}
            </div>
          )}

          <div className="flex gap-2 pt-1">
            <button
              onClick={handleTest}
              disabled={
                !form.host || !form.username || testConnection.isPending
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
                !form.username ||
                !form.password ||
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
                  <span className="rounded bg-blue-500/10 px-1.5 py-0.5 text-[10px] font-medium text-blue-400">
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
                    <Check className="h-3 w-3 text-green-500" />
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
                    <AlertTriangle className="h-3 w-3 text-amber-500" />
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
                    <span className="text-xs text-amber-400 mr-1">
                      This will log out all users
                    </span>
                    <button
                      onClick={handleRegenerate}
                      disabled={regenerateSession.isPending}
                      className="rounded bg-amber-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-amber-500 disabled:opacity-50"
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
                <AlertTriangle className="h-3.5 w-3.5 text-red-500" />
                <span className="text-sm text-red-500">Expired</span>
              </>
            ) : isExpiringSoon ? (
              <>
                <AlertTriangle className="h-3.5 w-3.5 text-amber-500" />
                <span className="text-sm text-amber-500">
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
                <Check className="h-3.5 w-3.5 text-green-500" />
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
                <Check className="h-3.5 w-3.5 text-green-500" />
                <span className="text-sm text-green-500">
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
                <Check className="h-3.5 w-3.5 text-green-500" />
                <span className="text-sm text-green-500">
                  All secrets current
                </span>
              </>
            ) : (
              <>
                <AlertTriangle className="h-3.5 w-3.5 text-amber-500" />
                <span className="text-sm text-amber-500">
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
                <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
                <span className="text-sm text-green-500">Listening</span>
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
                <Check className="h-3.5 w-3.5 text-green-500" />
                <span className="text-sm text-green-500">Loaded</span>
              </>
            ) : (
              <>
                <AlertTriangle className="h-3.5 w-3.5 text-amber-500" />
                <span className="text-sm text-amber-500">Not loaded</span>
              </>
            )}
          </div>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">MaxMind Credentials</span>
          <div className="flex items-center gap-1.5">
            {data.has_credentials ? (
              <>
                <Check className="h-3.5 w-3.5 text-green-500" />
                <span className="text-sm text-green-500">Configured</span>
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
