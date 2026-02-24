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
} from "@/api/queries";
import {
  Shield,
  Key,
  RefreshCw,
  Check,
  AlertTriangle,
  X,
  FileKey,
} from "lucide-react";

export function SettingsPage() {
  return (
    <PageShell title="Settings">
      <div className="space-y-6">
        <SecretsSection />
        <CertWardenSection />
        <EncryptionSection />
      </div>
    </PageShell>
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
  };

  const isPasswordField = (name: string) =>
    name === "router_password" ||
    name === "oidc_client_secret" ||
    name === "certwarden_cert_api_key" ||
    name === "certwarden_key_api_key";

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
                {secret.key_current ? (
                  <Check className="h-3 w-3 text-green-500" />
                ) : (
                  <AlertTriangle className="h-3 w-3 text-amber-500" />
                )}
                <span className="text-xs text-muted-foreground">
                  {secret.key_current ? "Encrypted" : "Key mismatch"} &middot;
                  Updated{" "}
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
                  Update
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
