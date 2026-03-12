import { useState } from "react";
import { LoadingSpinner } from "@/components/loading-spinner";
import {
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
import type { AlertRule } from "@/api/types";
import {
  Bell,
  Plus,
  Trash2,
  Send,
  ChevronDown,
  ChevronRight,
} from "lucide-react";

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
            {createRule.isPending ? "Creating\u2026" : "Create"}
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
          {" \u00b7 "}
          {rule.cooldown_seconds}s cooldown
          {" \u00b7 "}
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
                  {allOk ? "\u2705" : "\u274c"} {attempted.join(",")}
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
              {testResult.ok ? "\u2705 Sent" : `\u274c ${testResult.error}`}
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
              defaultValue={(cfg.url as string) || ""}
              placeholder="https://ntfy.sh or self-hosted URL"
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
              placeholder="\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"
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

// ── Exported composite component ─────────────────────────────────

export function SettingsAlerts() {
  return (
    <div className="space-y-6">
      <AlertRulesSection />
      <AlertHistorySection />
      <AlertChannelsSection />
    </div>
  );
}
