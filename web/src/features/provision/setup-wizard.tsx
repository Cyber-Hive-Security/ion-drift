import { useState, useMemo, useCallback } from "react";
import { PageShell } from "@/components/layout/page-shell";
import { SetupWizardHelp } from "@/components/help-content";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { cn } from "@/lib/utils";
import { useDevices, useProvisionInterfaces } from "@/api/queries";
import { apiFetch } from "@/api/client";
import type {
  ProvisionConfig,
  ProvisionItem,
  ProvisionPlan,
  ApplyResult,
  ApplyItemResult,
  NetworkDevice,
} from "@/api/types";
import {
  Settings,
  Wifi,
  Shield,
  Activity,
  Check,
  X,
  ChevronDown,
  ChevronRight,
  Loader2,
  AlertTriangle,
} from "lucide-react";

// ── Step indicator ──────────────────────────────────────────────

const STEPS = ["Configure", "Review Plan", "Applying", "Results"] as const;

function StepIndicator({ current }: { current: number }) {
  return (
    <div className="flex items-center gap-2 mb-6">
      {STEPS.map((label, i) => {
        const done = i < current;
        const active = i === current;
        return (
          <div key={label} className="flex items-center gap-2">
            {i > 0 && (
              <div
                className={cn(
                  "h-px w-8",
                  done ? "bg-primary" : "bg-border",
                )}
              />
            )}
            <div className="flex items-center gap-1.5">
              <div
                className={cn(
                  "flex h-6 w-6 items-center justify-center rounded-full text-xs font-bold",
                  done
                    ? "bg-success text-background"
                    : active
                      ? "bg-primary text-background"
                      : "bg-secondary text-muted-foreground",
                )}
              >
                {done ? <Check className="h-3.5 w-3.5" /> : i + 1}
              </div>
              <span
                className={cn(
                  "text-xs font-medium hidden sm:inline",
                  active ? "text-foreground" : "text-muted-foreground",
                )}
              >
                {label}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Action badge ────────────────────────────────────────────────

function ActionBadge({ action }: { action: string }) {
  const cls =
    action === "create"
      ? "bg-primary/15 text-primary border-primary/30"
      : action === "update"
        ? "bg-warning/15 text-warning border-warning/30"
        : "bg-muted text-muted-foreground border-border";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider border",
        cls,
      )}
    >
      {action}
    </span>
  );
}

// ── Collapsible section ─────────────────────────────────────────

function CollapsibleSection({
  title,
  icon: Icon,
  count,
  defaultOpen,
  children,
}: {
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  count: number;
  defaultOpen: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-secondary/50 transition-colors"
      >
        {open ? (
          <ChevronDown className="h-4 w-4 text-muted-foreground flex-shrink-0" />
        ) : (
          <ChevronRight className="h-4 w-4 text-muted-foreground flex-shrink-0" />
        )}
        <Icon className="h-4 w-4 text-primary flex-shrink-0" />
        <span className="text-sm font-semibold text-foreground">{title}</span>
        <span className="ml-auto inline-flex h-5 min-w-5 items-center justify-center rounded-full bg-secondary px-1.5 text-[10px] font-bold text-muted-foreground">
          {count}
        </span>
      </button>
      {open && <div className="border-t border-border">{children}</div>}
    </div>
  );
}

// ── Plan item row ───────────────────────────────────────────────

function PlanItemRow({
  item,
  checked,
  onToggle,
}: {
  item: ProvisionItem;
  checked: boolean;
  onToggle: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const isSkip = item.action === "skip";

  return (
    <div
      className={cn(
        "border-b border-border last:border-b-0 px-4 py-3",
        isSkip && "opacity-60",
      )}
    >
      <div className="flex items-start gap-3">
        <input
          type="checkbox"
          checked={checked}
          onChange={onToggle}
          disabled={isSkip}
          className="mt-1 h-4 w-4 rounded border-border bg-background accent-primary"
        />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <ActionBadge action={item.action} />
            <span className="text-sm font-medium text-foreground">
              {item.title}
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">
            {item.description}
          </p>
        </div>
        <button
          onClick={() => setExpanded((e) => !e)}
          className="flex-shrink-0 rounded p-1 hover:bg-secondary text-muted-foreground"
          title={expanded ? "Hide detail" : "Show RouterOS detail"}
        >
          {expanded ? (
            <ChevronDown className="h-3.5 w-3.5" />
          ) : (
            <ChevronRight className="h-3.5 w-3.5" />
          )}
        </button>
      </div>
      {expanded && (
        <div className="mt-2 ml-7 rounded bg-background border border-border p-3 overflow-x-auto">
          <pre className="text-xs text-muted-foreground whitespace-pre-wrap font-mono">
            {JSON.stringify(item.detail, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

// ── Step 1: Configure ───────────────────────────────────────────

function StepConfigure({
  onSubmit,
}: {
  onSubmit: (deviceId: string, config: ProvisionConfig) => void;
}) {
  const { data: devices = [], isLoading: devicesLoading } = useDevices();
  const routers = useMemo(
    () => devices.filter((d: NetworkDevice) => d.device_type === "router"),
    [devices],
  );

  const [deviceId, setDeviceId] = useState<string>("");
  const [wanInterface, setWanInterface] = useState("");
  const [syslogHost, setSyslogHost] = useState(window.location.hostname);
  const [syslogPort, setSyslogPort] = useState(5514);
  const [routerSourceIp, setRouterSourceIp] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedDevice = routers.find((d: NetworkDevice) => d.id === deviceId);
  const { data: interfaces = [], isLoading: ifLoading } =
    useProvisionInterfaces(deviceId || null);

  // Auto-suggest WAN interface
  const suggestedWan = useMemo(() => {
    const wan = interfaces.find(
      (iface) =>
        iface.name.toUpperCase().includes("WAN") ||
        (iface.comment && iface.comment.toUpperCase().includes("WAN")),
    );
    return wan?.name ?? "";
  }, [interfaces]);

  // When interfaces load with a suggestion, auto-fill if empty
  const prevSuggested = useState("")[0];
  if (suggestedWan && !wanInterface && suggestedWan !== prevSuggested) {
    setWanInterface(suggestedWan);
  }

  // Auto-suggest router source IP from device host
  const suggestedIp = selectedDevice?.host ?? "";
  if (suggestedIp && !routerSourceIp && deviceId) {
    setRouterSourceIp(suggestedIp);
  }

  const canSubmit =
    deviceId && wanInterface && syslogHost && syslogPort && routerSourceIp;

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setLoading(true);
    setError(null);
    try {
      onSubmit(deviceId, {
        wan_interface: wanInterface,
        syslog_host: syslogHost,
        syslog_port: syslogPort,
        router_source_ip: routerSourceIp,
      });
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to generate plan");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-xl">
      <div className="rounded-lg border border-border bg-card p-5 space-y-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <Settings className="h-4 w-4 text-primary" />
          Provision Configuration
        </h3>

        {/* Device selector */}
        <div>
          <label className="block text-xs font-medium text-muted-foreground mb-1">
            Target Device
          </label>
          {devicesLoading ? (
            <LoadingSpinner className="p-2" />
          ) : routers.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No router-type devices found. Add a router in Settings first.
            </p>
          ) : (
            <select
              value={deviceId}
              onChange={(e) => {
                setDeviceId(e.target.value);
                setWanInterface("");
                setRouterSourceIp("");
              }}
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
            >
              <option value="">Select a router...</option>
              {routers.map((d: NetworkDevice) => (
                <option key={d.id} value={d.id}>
                  {d.name} ({d.host}) {d.status === "Online" ? "" : `[${d.status}]`}
                </option>
              ))}
            </select>
          )}
        </div>

        {/* WAN interface */}
        {deviceId && (
          <div>
            <label className="block text-xs font-medium text-muted-foreground mb-1">
              WAN Interface
            </label>
            {ifLoading ? (
              <LoadingSpinner className="p-2" />
            ) : interfaces.length === 0 ? (
              <p className="text-xs text-destructive">
                Could not load interfaces. Is the device online?
              </p>
            ) : (
              <select
                value={wanInterface}
                onChange={(e) => setWanInterface(e.target.value)}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
              >
                <option value="">Select WAN interface...</option>
                {interfaces.map((iface) => (
                  <option key={iface.name} value={iface.name}>
                    {iface.name}
                    {iface.type ? ` (${iface.type})` : ""}
                    {iface.running ? "" : " [down]"}
                    {iface.comment ? ` - ${iface.comment}` : ""}
                  </option>
                ))}
              </select>
            )}
            {suggestedWan && (
              <p className="text-[10px] text-muted-foreground mt-0.5">
                Auto-selected: detected &quot;WAN&quot; in interface name
              </p>
            )}
          </div>
        )}

        {/* Syslog host */}
        <div>
          <label className="block text-xs font-medium text-muted-foreground mb-1">
            Syslog Host
          </label>
          <input
            type="text"
            value={syslogHost}
            onChange={(e) => setSyslogHost(e.target.value)}
            placeholder="e.g. 10.20.25.27"
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
          />
          <p className="text-[10px] text-muted-foreground mt-0.5">
            Where Ion Drift&apos;s syslog listener runs (defaults to this browser&apos;s host)
          </p>
        </div>

        {/* Syslog port */}
        <div>
          <label className="block text-xs font-medium text-muted-foreground mb-1">
            Syslog Port
          </label>
          <input
            type="number"
            value={syslogPort}
            onChange={(e) => setSyslogPort(Number(e.target.value))}
            min={1}
            max={65535}
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
          />
        </div>

        {/* Router source IP */}
        {deviceId && (
          <div>
            <label className="block text-xs font-medium text-muted-foreground mb-1">
              Router Source IP
            </label>
            <input
              type="text"
              value={routerSourceIp}
              onChange={(e) => setRouterSourceIp(e.target.value)}
              placeholder="e.g. 10.20.25.1"
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
            />
            <p className="text-[10px] text-muted-foreground mt-0.5">
              The router&apos;s own IP used as syslog source address (auto-filled from device host)
            </p>
          </div>
        )}
      </div>

      {error && <ErrorDisplay message={error} />}

      <button
        onClick={handleSubmit}
        disabled={!canSubmit || loading}
        className={cn(
          "flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors",
          canSubmit && !loading
            ? "bg-primary text-primary-foreground hover:bg-primary/90"
            : "bg-secondary text-muted-foreground cursor-not-allowed",
        )}
      >
        {loading && <Loader2 className="h-4 w-4 animate-spin" />}
        Generate Plan
      </button>
    </div>
  );
}

// ── Step 2: Review Plan ─────────────────────────────────────────

function StepReview({
  plan,
  onApply,
  onBack,
}: {
  plan: ProvisionPlan;
  onApply: (selectedIds: string[]) => void;
  onBack: () => void;
}) {
  const [selected, setSelected] = useState<Set<string>>(() => {
    const initial = new Set<string>();
    for (const item of plan.items) {
      if (item.action === "create" || item.action === "update") {
        initial.add(item.id);
      }
    }
    return initial;
  });

  const toggle = useCallback((id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  // Group items by category
  const syslogItems = plan.items.filter(
    (i) => i.category === "syslog_action" || i.category === "syslog_rule",
  );
  const firewallItems = plan.items.filter(
    (i) => i.category === "firewall_log",
  );
  const mangleItems = plan.items.filter(
    (i) => i.category === "mangle_rule",
  );

  // Group mangle items by source interface for display
  const mangleBySource = useMemo(() => {
    const groups = new Map<string, ProvisionItem[]>();
    for (const item of mangleItems) {
      const src =
        (item.detail as Record<string, string>)["in-interface"] ??
        (item.detail as Record<string, string>)["src-interface"] ??
        "unknown";
      if (!groups.has(src)) groups.set(src, []);
      groups.get(src)!.push(item);
    }
    return groups;
  }, [mangleItems]);

  const selectedCount = selected.size;
  const { create: createCount, skip: skipCount, update: updateCount } = plan.summary;

  return (
    <div className="space-y-4">
      {/* Summary bar */}
      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-card px-4 py-3">
        <span className="text-sm font-semibold text-foreground">Plan Summary:</span>
        {createCount > 0 && (
          <span className="text-xs text-primary font-medium">
            {createCount} to create
          </span>
        )}
        {skipCount > 0 && (
          <span className="text-xs text-muted-foreground font-medium">
            {skipCount} already exist
          </span>
        )}
        {updateCount > 0 && (
          <span className="text-xs text-warning font-medium">
            {updateCount} to update
          </span>
        )}
        <span className="ml-auto text-xs text-muted-foreground">
          {selectedCount} selected
        </span>
      </div>

      {/* Syslog section */}
      {syslogItems.length > 0 && (
        <CollapsibleSection
          title="Syslog Configuration"
          icon={Wifi}
          count={syslogItems.length}
          defaultOpen={true}
        >
          {syslogItems.map((item) => (
            <PlanItemRow
              key={item.id}
              item={item}
              checked={selected.has(item.id)}
              onToggle={() => toggle(item.id)}
            />
          ))}
        </CollapsibleSection>
      )}

      {/* Firewall log section */}
      {firewallItems.length > 0 && (
        <CollapsibleSection
          title="Firewall Log Rules"
          icon={Shield}
          count={firewallItems.length}
          defaultOpen={true}
        >
          {firewallItems.map((item) => (
            <PlanItemRow
              key={item.id}
              item={item}
              checked={selected.has(item.id)}
              onToggle={() => toggle(item.id)}
            />
          ))}
        </CollapsibleSection>
      )}

      {/* Mangle rules section */}
      {mangleItems.length > 0 && (
        <CollapsibleSection
          title="Traffic Flow Counters"
          icon={Activity}
          count={mangleItems.length}
          defaultOpen={false}
        >
          {mangleBySource.size > 1 ? (
            // Sub-grouped by source interface
            Array.from(mangleBySource.entries()).map(([src, items]) => (
              <div key={src}>
                <div className="px-4 py-1.5 bg-secondary/30 border-b border-border">
                  <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                    Source: {src}
                  </span>
                  <span className="ml-2 text-[10px] text-muted-foreground">
                    ({items.length} rules)
                  </span>
                </div>
                {items.map((item) => (
                  <PlanItemRow
                    key={item.id}
                    item={item}
                    checked={selected.has(item.id)}
                    onToggle={() => toggle(item.id)}
                  />
                ))}
              </div>
            ))
          ) : (
            mangleItems.map((item) => (
              <PlanItemRow
                key={item.id}
                item={item}
                checked={selected.has(item.id)}
                onToggle={() => toggle(item.id)}
              />
            ))
          )}
        </CollapsibleSection>
      )}

      {/* Action buttons */}
      <div className="flex items-center gap-3 pt-2">
        <button
          onClick={onBack}
          className="rounded-md border border-border px-4 py-2 text-sm font-medium text-muted-foreground hover:bg-secondary transition-colors"
        >
          Back
        </button>
        <button
          onClick={() => onApply(Array.from(selected))}
          disabled={selectedCount === 0}
          className={cn(
            "flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors",
            selectedCount > 0
              ? "bg-primary text-primary-foreground hover:bg-primary/90"
              : "bg-secondary text-muted-foreground cursor-not-allowed",
          )}
        >
          Apply {selectedCount} Selected
        </button>
      </div>
    </div>
  );
}

// ── Step 3: Applying ────────────────────────────────────────────

function StepApplying({ plan }: { plan: ProvisionPlan }) {
  return (
    <div className="space-y-4 max-w-xl">
      <div className="rounded-lg border border-border bg-card p-5 text-center space-y-3">
        <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
        <p className="text-sm font-medium text-foreground">
          Applying configuration changes...
        </p>
        <p className="text-xs text-muted-foreground">
          Configuring {plan.items.length} items on the router. Do not navigate away.
        </p>
      </div>
    </div>
  );
}

// ── Step 4: Results ─────────────────────────────────────────────

function StepResults({
  results,
  onDone,
  onRetryFailed,
}: {
  results: ApplyResult;
  onDone: () => void;
  onRetryFailed: () => void;
}) {
  const hasFailed = results.failed > 0;

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div
        className={cn(
          "rounded-lg border p-4 flex items-center gap-3",
          hasFailed
            ? "border-destructive/30 bg-destructive/5"
            : "border-success/30 bg-success/5",
        )}
      >
        {hasFailed ? (
          <AlertTriangle className="h-6 w-6 text-destructive flex-shrink-0" />
        ) : (
          <Check className="h-6 w-6 text-success flex-shrink-0" />
        )}
        <div>
          <p className="text-sm font-semibold text-foreground">
            {hasFailed
              ? `${results.succeeded} succeeded, ${results.failed} failed`
              : `All ${results.succeeded} items applied successfully`}
          </p>
          {hasFailed && (
            <p className="text-xs text-muted-foreground mt-0.5">
              Review failed items below. You can retry them individually.
            </p>
          )}
        </div>
      </div>

      {/* Results list */}
      <div className="rounded-lg border border-border bg-card overflow-hidden">
        {results.results.map((r: ApplyItemResult) => (
          <div
            key={r.id}
            className="flex items-center gap-3 border-b border-border last:border-b-0 px-4 py-2.5"
          >
            {r.success ? (
              <Check className="h-4 w-4 text-success flex-shrink-0" />
            ) : (
              <X className="h-4 w-4 text-destructive flex-shrink-0" />
            )}
            <div className="flex-1 min-w-0">
              <span className="text-sm text-foreground">{r.title}</span>
              {r.error && (
                <p className="text-xs text-destructive mt-0.5">{r.error}</p>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Action buttons */}
      <div className="flex items-center gap-3 pt-2">
        {hasFailed && (
          <button
            onClick={onRetryFailed}
            className="flex items-center gap-2 rounded-md border border-warning/50 bg-warning/10 px-4 py-2 text-sm font-medium text-warning hover:bg-warning/20 transition-colors"
          >
            <AlertTriangle className="h-4 w-4" />
            Retry Failed
          </button>
        )}
        <button
          onClick={onDone}
          className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
        >
          Done
        </button>
      </div>
    </div>
  );
}

// ── Main wizard ─────────────────────────────────────────────────

export function SetupWizard() {
  const [step, setStep] = useState(0);
  const [deviceId, setDeviceId] = useState<string>("");
  const [config, setConfig] = useState<ProvisionConfig | null>(null);
  const [plan, setPlan] = useState<ProvisionPlan | null>(null);
  const [results, setResults] = useState<ApplyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [planLoading, setPlanLoading] = useState(false);
  const [, setSelectedIds] = useState<string[]>([]);

  const handleConfigure = async (devId: string, cfg: ProvisionConfig) => {
    setDeviceId(devId);
    setConfig(cfg);
    setPlanLoading(true);
    setError(null);
    try {
      const planResult = await apiFetch<ProvisionPlan>(
        `/api/devices/${encodeURIComponent(devId)}/provision/plan`,
        {
          method: "POST",
          body: JSON.stringify(cfg),
        },
      );
      setPlan(planResult);
      setStep(1);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to generate plan");
    } finally {
      setPlanLoading(false);
    }
  };

  const handleApply = async (ids: string[]) => {
    if (!config || !deviceId || ids.length === 0) return;
    setSelectedIds(ids);
    setStep(2);
    setError(null);
    try {
      const applyResult = await apiFetch<ApplyResult>(
        `/api/devices/${encodeURIComponent(deviceId)}/provision/apply`,
        {
          method: "POST",
          body: JSON.stringify({
            config,
            item_ids: ids,
          }),
        },
      );
      setResults(applyResult);
      setStep(3);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to apply changes");
      setStep(1); // Go back to review on error
    }
  };

  const handleRetryFailed = () => {
    if (!results) return;
    const failedIds = results.results
      .filter((r: ApplyItemResult) => !r.success)
      .map((r: ApplyItemResult) => r.id);
    if (failedIds.length > 0) {
      handleApply(failedIds);
    }
  };

  const handleDone = () => {
    setStep(0);
    setDeviceId("");
    setConfig(null);
    setPlan(null);
    setResults(null);
    setError(null);
    setSelectedIds([]);
  };

  return (
    <PageShell title="Setup Wizard" help={<SetupWizardHelp />}>
      <StepIndicator current={step} />

      {error && step !== 2 && (
        <div className="mb-4">
          <ErrorDisplay message={error} onRetry={() => setError(null)} />
        </div>
      )}

      {step === 0 && (
        <>
          {planLoading ? (
            <div className="space-y-4 max-w-xl">
              <div className="rounded-lg border border-border bg-card p-5 text-center space-y-3">
                <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
                <p className="text-sm font-medium text-foreground">
                  Generating provisioning plan...
                </p>
                <p className="text-xs text-muted-foreground">
                  Analyzing current router configuration and computing required changes.
                </p>
              </div>
            </div>
          ) : (
            <StepConfigure onSubmit={handleConfigure} />
          )}
        </>
      )}

      {step === 1 && plan && (
        <StepReview
          plan={plan}
          onApply={handleApply}
          onBack={() => setStep(0)}
        />
      )}

      {step === 2 && plan && <StepApplying plan={plan} />}

      {step === 3 && results && (
        <StepResults
          results={results}
          onDone={handleDone}
          onRetryFailed={handleRetryFailed}
        />
      )}
    </PageShell>
  );
}
