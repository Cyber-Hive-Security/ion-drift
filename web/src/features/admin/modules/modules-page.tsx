import { useState } from "react";
import { PageShell } from "@/components/layout/page-shell";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import {
  useAdminModules,
  useSetModuleEnabled,
  useTestModuleConnection,
  useUnregisterModule,
  type RegisteredModule,
} from "@/api/queries/admin-modules";
import { RegisterModuleForm } from "./register-form";
import {
  CheckCircle2,
  Clock,
  Plug,
  Power,
  PowerOff,
  Trash2,
  XCircle,
} from "lucide-react";

export function AdminModulesPage() {
  const { data, isLoading, error } = useAdminModules();
  const [showForm, setShowForm] = useState(false);

  return (
    <PageShell title="Modules">
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground max-w-2xl">
            External modules registered with Drift. Each module runs as its own
            service; Drift delivers subscribed events over signed webhooks and
            reverse-proxies admin requests to the module's HTTP API.
          </p>
          <button
            onClick={() => setShowForm((v) => !v)}
            className="rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
          >
            {showForm ? "Cancel" : "Register module"}
          </button>
        </div>

        {showForm && (
          <RegisterModuleForm onDone={() => setShowForm(false)} />
        )}

        {isLoading && <LoadingSpinner />}
        {error && <ErrorDisplay error={error} />}
        {data && data.modules.length === 0 && !showForm && (
          <div className="rounded-lg border border-dashed border-border p-8 text-center text-sm text-muted-foreground">
            No modules registered yet. Click{" "}
            <span className="font-medium">Register module</span> to add one.
          </div>
        )}
        {data && data.modules.length > 0 && (
          <div className="space-y-3">
            {data.modules.map((m) => (
              <ModuleCard key={m.id} module={m} />
            ))}
          </div>
        )}
      </div>
    </PageShell>
  );
}

function ModuleCard({ module }: { module: RegisteredModule }) {
  const setEnabled = useSetModuleEnabled();
  const unregister = useUnregisterModule();
  const test = useTestModuleConnection();
  const [testError, setTestError] = useState<string | null>(null);
  const [testOk, setTestOk] = useState(false);

  const lastSeen =
    module.last_seen_at != null
      ? new Date(module.last_seen_at * 1000).toLocaleString()
      : "never";

  async function handleTest() {
    setTestError(null);
    setTestOk(false);
    try {
      await test.mutateAsync(module.name);
      setTestOk(true);
    } catch (e) {
      setTestError(e instanceof Error ? e.message : String(e));
    }
  }

  async function handleRemove() {
    if (!confirm(`Unregister module "${module.name}"? Drift will stop delivering events to it.`)) {
      return;
    }
    await unregister.mutateAsync(module.name);
  }

  return (
    <div className="rounded-lg border border-border bg-card p-4 space-y-3">
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Plug className="h-4 w-4 text-muted-foreground" />
            <h3 className="text-base font-semibold">{module.name}</h3>
            <span className="text-xs text-muted-foreground">
              v{module.manifest.version}
            </span>
            {module.enabled ? (
              <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-400">
                <CheckCircle2 className="h-3 w-3" />
                enabled
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">
                <XCircle className="h-3 w-3" />
                disabled
              </span>
            )}
          </div>
          {module.manifest.description && (
            <p className="text-sm text-muted-foreground">
              {module.manifest.description}
            </p>
          )}
          <p className="text-xs font-mono text-muted-foreground">{module.url}</p>
          <p className="text-xs text-muted-foreground flex items-center gap-1">
            <Clock className="h-3 w-3" />
            last seen: {lastSeen}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleTest}
            disabled={test.isPending}
            className="rounded-md border border-border px-3 py-1.5 text-xs font-medium hover:bg-accent disabled:opacity-50"
          >
            {test.isPending ? "Testing..." : "Test"}
          </button>
          <button
            onClick={() =>
              setEnabled.mutate({ name: module.name, enabled: !module.enabled })
            }
            disabled={setEnabled.isPending}
            className="rounded-md border border-border px-3 py-1.5 text-xs font-medium hover:bg-accent disabled:opacity-50"
            title={module.enabled ? "Disable" : "Enable"}
          >
            {module.enabled ? (
              <PowerOff className="h-3.5 w-3.5" />
            ) : (
              <Power className="h-3.5 w-3.5" />
            )}
          </button>
          <button
            onClick={handleRemove}
            disabled={unregister.isPending}
            className="rounded-md border border-destructive/50 px-3 py-1.5 text-xs font-medium text-destructive hover:bg-destructive/10 disabled:opacity-50"
            title="Unregister"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {testError && (
        <div className="rounded-md border border-destructive/30 bg-destructive/5 p-2 text-xs text-destructive">
          Test failed: {testError}
        </div>
      )}
      {testOk && (
        <div className="rounded-md border border-emerald-500/30 bg-emerald-500/5 p-2 text-xs text-emerald-400">
          Manifest probe OK.
        </div>
      )}

      <div className="grid grid-cols-2 gap-4 pt-2 border-t border-border text-xs">
        <div>
          <p className="font-medium text-muted-foreground mb-1">
            Subscribed events
          </p>
          {module.manifest.subscribed_events.length === 0 ? (
            <p className="text-muted-foreground/60">none</p>
          ) : (
            <ul className="space-y-0.5">
              {module.manifest.subscribed_events.map((k) => (
                <li key={k} className="font-mono">
                  {k}
                </li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <p className="font-medium text-muted-foreground mb-1">
            Exposed routes
          </p>
          {module.manifest.exposed_routes.length === 0 ? (
            <p className="text-muted-foreground/60">none</p>
          ) : (
            <ul className="space-y-0.5">
              {module.manifest.exposed_routes.map((r) => (
                <li key={`${r.method} ${r.path}`} className="font-mono">
                  <span className="text-muted-foreground">{r.method}</span>{" "}
                  {r.path}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
