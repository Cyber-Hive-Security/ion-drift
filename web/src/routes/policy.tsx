import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/api/client";
import { PageShell } from "@/components/layout/page-shell";
import { DataTable, type Column } from "@/components/data-table";
import { LoadingSpinner } from "@/components/loading-spinner";
import { useVlanLookup } from "@/hooks/use-vlan-lookup";
import {
  usePolicyDeviations, useResolvePolicyDeviation, useDeleteAllDeviations, useAttackTechniques,
  useCreatePolicy, useUpdatePolicy, useDeletePolicy,
} from "@/api/queries";
import type { PolicyDeviation } from "@/api/types";
import { Lock, Pencil, Trash2, Plus, X, Download } from "lucide-react";

interface PolicyEntry {
  id: number;
  service: string;
  protocol: string | null;
  port: number | null;
  authorized_targets: string[];
  vlan_scope: number[] | null;
  source: string;
  priority: string;
  last_synced: number;
  user_created: boolean;
}

interface IonTagEntry {
  rule_id: string;
  chain: string;
  action: string;
  tag: string;
  comment: string;
  rule_summary: string;
  last_synced: number;
}

interface PolicyOverview {
  policies: PolicyEntry[];
  ion_tags: IonTagEntry[];
  policy_count: number;
  tag_count: number;
}

function usePolicyOverview() {
  return useQuery({
    queryKey: ["policy"],
    queryFn: () => apiFetch<PolicyOverview>("/api/policy"),
    refetchInterval: 60_000,
  });
}

function formatTimeAgo(ts: number): string {
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

const priorityColor: Record<string, string> = {
  critical: "text-destructive",
  high: "text-warning",
  medium: "text-muted-foreground",
  low: "text-muted-foreground/60",
};

const tagColor: Record<string, string> = {
  critical: "bg-destructive/15 text-destructive",
  ignore: "bg-muted text-muted-foreground",
  digest: "bg-amber-400/15 text-amber-400",
};

function policyColumns(
  vlanNames: Record<number, string>,
  onEdit: (policy: PolicyEntry) => void,
  onDelete: (policy: PolicyEntry) => void,
): Column<PolicyEntry>[] {
  return [
    {
      key: "service",
      header: "Service",
      width: "100px",
      render: (r) => <span className="text-xs font-semibold uppercase">{r.service}</span>,
      sortValue: (r) => r.service,
    },
    {
      key: "protocol",
      header: "Proto",
      width: "65px",
      render: (r) => (
        <span className="font-mono text-xs text-muted-foreground">
          {r.protocol ?? "any"}{r.port != null ? `:${r.port}` : ""}
        </span>
      ),
      sortValue: (r) => `${r.protocol ?? ""}:${r.port ?? 0}`,
    },
    {
      key: "targets",
      header: "Authorized Targets",
      render: (r) => (
        <span className="max-w-sm truncate font-mono text-xs" title={r.authorized_targets.join(", ")}>
          {r.authorized_targets.length === 0 ? <span className="text-warning">flag all</span> : r.authorized_targets.join(", ")}
        </span>
      ),
    },
    {
      key: "vlan",
      header: "VLAN Scope",
      width: "120px",
      render: (r) => {
        if (!r.vlan_scope) return <span className="text-xs text-muted-foreground">All VLANs</span>;
        return (
          <span className="text-xs">
            {r.vlan_scope.map((v) => vlanNames[v] ?? `VLAN ${v}`).join(", ")}
          </span>
        );
      },
    },
    {
      key: "source",
      header: "Source",
      width: "100px",
      render: (r) => (
        <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
          {r.user_created ? "admin" : <><Lock className="h-3 w-3" /> router</>}
        </span>
      ),
      sortValue: (r) => r.user_created ? "a" : "z",
    },
    {
      key: "priority",
      header: "Priority",
      width: "80px",
      render: (r) => (
        <span className={`text-xs font-medium ${priorityColor[r.priority] ?? ""}`}>
          {r.priority}
        </span>
      ),
      sortValue: (r) => {
        const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
        return order[r.priority] ?? 4;
      },
    },
    {
      key: "actions",
      header: "",
      width: "70px",
      render: (r) => {
        if (!r.user_created) return null;
        return (
          <div className="flex items-center gap-1">
            <button onClick={() => onEdit(r)} className="rounded p-1 hover:bg-muted" title="Edit policy">
              <Pencil className="h-3.5 w-3.5 text-muted-foreground" />
            </button>
            <button onClick={() => onDelete(r)} className="rounded p-1 hover:bg-destructive/10" title="Delete policy">
              <Trash2 className="h-3.5 w-3.5 text-destructive/70" />
            </button>
          </div>
        );
      },
    },
  ];
}

function ionTagColumns(): Column<IonTagEntry>[] {
  return [
    {
      key: "tag",
      header: "Tag",
      width: "90px",
      render: (r) => (
        <span className={`rounded px-1.5 py-0.5 text-xs font-semibold uppercase ${tagColor[r.tag] ?? ""}`}>
          {r.tag}
        </span>
      ),
      sortValue: (r) => {
        const order: Record<string, number> = { critical: 0, digest: 1, ignore: 2 };
        return order[r.tag] ?? 3;
      },
    },
    {
      key: "chain",
      header: "Chain",
      width: "80px",
      render: (r) => <span className="font-mono text-xs">{r.chain}</span>,
      sortValue: (r) => r.chain,
    },
    {
      key: "action",
      header: "Action",
      width: "70px",
      render: (r) => <span className="font-mono text-xs">{r.action}</span>,
      sortValue: (r) => r.action,
    },
    {
      key: "summary",
      header: "Rule",
      render: (r) => (
        <span className="max-w-sm truncate font-mono text-xs" title={r.rule_summary}>
          {r.rule_summary}
        </span>
      ),
    },
    {
      key: "comment",
      header: "Comment",
      render: (r) => <span className="max-w-xs truncate text-xs text-muted-foreground">{r.comment}</span>,
    },
    {
      key: "synced",
      header: "Synced",
      width: "100px",
      render: (r) => <span className="text-xs text-muted-foreground">{formatTimeAgo(r.last_synced)}</span>,
      sortValue: (r) => -r.last_synced,
    },
  ];
}

// ── Policy Form Modal ────────────────────────────────────────────

interface PolicyFormProps {
  editing: PolicyEntry | null;
  vlanNames: Record<number, string>;
  onClose: () => void;
}

function PolicyFormModal({ editing, vlanNames, onClose }: PolicyFormProps) {
  const createMutation = useCreatePolicy();
  const updateMutation = useUpdatePolicy();

  const [service, setService] = useState(editing?.service ?? "");
  const [protocol, setProtocol] = useState(editing?.protocol ?? "udp");
  const [port, setPort] = useState(editing?.port?.toString() ?? "");
  const [targets, setTargets] = useState(editing?.authorized_targets.join("\n") ?? "");
  const [selectedVlans, setSelectedVlans] = useState<number[]>(editing?.vlan_scope ?? []);
  const [globalScope, setGlobalScope] = useState(!editing?.vlan_scope);
  const [priority, setPriority] = useState(editing?.priority ?? "medium");
  const [error, setError] = useState<string | null>(null);

  const vlanIds = Object.keys(vlanNames).map(Number).sort((a, b) => a - b);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const parsedTargets = targets.split("\n").map((t) => t.trim()).filter(Boolean);
    const parsedPort = port ? parseInt(port, 10) : null;
    const vlanScope = globalScope ? null : selectedVlans.length > 0 ? selectedVlans : null;

    try {
      if (editing) {
        await updateMutation.mutateAsync({
          id: editing.id,
          authorized_targets: parsedTargets,
          vlan_scope: vlanScope,
          priority,
        });
      } else {
        await createMutation.mutateAsync({
          service: service.toLowerCase(),
          protocol: protocol === "any" ? null : protocol,
          port: parsedPort,
          authorized_targets: parsedTargets,
          vlan_scope: vlanScope,
          priority,
        });
      }
      onClose();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to save policy";
      setError(msg);
    }
  };

  const isPending = createMutation.isPending || updateMutation.isPending;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={onClose}>
      <div className="w-full max-w-lg rounded-lg border bg-card p-6 shadow-xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold">{editing ? "Edit Policy" : "Create Policy"}</h3>
          <button onClick={onClose} className="rounded p-1 hover:bg-muted"><X className="h-4 w-4" /></button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {!editing && (
            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className="text-xs font-medium text-muted-foreground">Service</label>
                <input
                  type="text"
                  value={service}
                  onChange={(e) => setService(e.target.value)}
                  placeholder="dns, ntp, custom"
                  className="mt-1 w-full rounded-md border border-input bg-background px-3 py-1.5 text-sm"
                  required
                />
              </div>
              <div>
                <label className="text-xs font-medium text-muted-foreground">Protocol</label>
                <select
                  value={protocol}
                  onChange={(e) => setProtocol(e.target.value)}
                  className="mt-1 w-full rounded-md border border-input bg-background px-3 py-1.5 text-sm"
                >
                  <option value="udp">UDP</option>
                  <option value="tcp">TCP</option>
                  <option value="any">Any</option>
                </select>
              </div>
              <div>
                <label className="text-xs font-medium text-muted-foreground">Port</label>
                <input
                  type="number"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  placeholder="53"
                  min={1}
                  max={65535}
                  className="mt-1 w-full rounded-md border border-input bg-background px-3 py-1.5 text-sm"
                />
              </div>
            </div>
          )}

          <div>
            <label className="text-xs font-medium text-muted-foreground">Authorized Targets (one per line, IP or CIDR)</label>
            <textarea
              value={targets}
              onChange={(e) => setTargets(e.target.value)}
              rows={4}
              placeholder={"10.20.25.5\n10.20.25.6\n192.168.1.0/24"}
              className="mt-1 w-full rounded-md border border-input bg-background px-3 py-1.5 font-mono text-sm"
            />
          </div>

          <div>
            <label className="text-xs font-medium text-muted-foreground">VLAN Scope</label>
            <div className="mt-1 flex items-center gap-3">
              <label className="flex items-center gap-1.5 text-sm">
                <input
                  type="checkbox"
                  checked={globalScope}
                  onChange={(e) => setGlobalScope(e.target.checked)}
                  className="rounded"
                />
                All VLANs
              </label>
            </div>
            {!globalScope && (
              <div className="mt-2 flex flex-wrap gap-2">
                {vlanIds.map((id) => (
                  <label key={id} className="flex items-center gap-1.5 text-xs">
                    <input
                      type="checkbox"
                      checked={selectedVlans.includes(id)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedVlans([...selectedVlans, id]);
                        } else {
                          setSelectedVlans(selectedVlans.filter((v) => v !== id));
                        }
                      }}
                      className="rounded"
                    />
                    {vlanNames[id] ?? `VLAN ${id}`}
                  </label>
                ))}
              </div>
            )}
          </div>

          <div>
            <label className="text-xs font-medium text-muted-foreground">Priority</label>
            <select
              value={priority}
              onChange={(e) => setPriority(e.target.value)}
              className="mt-1 w-full rounded-md border border-input bg-background px-3 py-1.5 text-sm"
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {error && (
            <p className="text-sm text-destructive">{error}</p>
          )}

          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose} className="rounded-md border px-4 py-1.5 text-sm hover:bg-muted">
              Cancel
            </button>
            <button
              type="submit"
              disabled={isPending}
              className="rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90"
            >
              {isPending ? "Saving..." : editing ? "Update" : "Create"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Policy Page ─────────────────────────────────────────────────

export function PolicyPage() {
  const { data, isLoading, error } = usePolicyOverview();
  const vlan = useVlanLookup();
  const deleteMutation = useDeletePolicy();

  const [showForm, setShowForm] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<PolicyEntry | null>(null);

  if (isLoading) return <LoadingSpinner />;
  if (error) return <PageShell title="Policy Map"><p className="text-destructive">Failed to load policy data</p></PageShell>;
  if (!data) return null;

  const handleEdit = (policy: PolicyEntry) => {
    setEditingPolicy(policy);
    setShowForm(true);
  };

  const handleDelete = (policy: PolicyEntry) => {
    if (!window.confirm(`Delete policy "${policy.service}" (${policy.protocol ?? "any"}:${policy.port ?? "any"})? This cannot be undone.`)) return;
    deleteMutation.mutate(policy.id);
  };

  const handleCloseForm = () => {
    setShowForm(false);
    setEditingPolicy(null);
  };

  return (
    <PageShell title="Infrastructure Policy Map">
      <p className="mb-4 text-sm text-muted-foreground">
        Authoritative service map derived from router configuration. Synced every 60 minutes.
        {data.policy_count > 0 && ` ${data.policy_count} policies, ${data.tag_count} ION tags.`}
      </p>

      <div className="flex items-center justify-between mb-2">
        <h2 className="text-lg font-semibold">Service Policies</h2>
        <button
          onClick={() => { setEditingPolicy(null); setShowForm(true); }}
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90"
        >
          <Plus className="h-3.5 w-3.5" />
          Add Policy
        </button>
      </div>
      <div className="mb-6">
        <DataTable
          columns={policyColumns(vlan.names, handleEdit, handleDelete)}
          data={data.policies}
          rowKey={(r) => String(r.id)}
          emptyMessage="No policies synced yet — sync runs on startup and every 60 minutes"
          searchable
          searchPlaceholder="Search policies..."
          defaultSort={{ key: "service", asc: true }}
        />
      </div>

      {data.ion_tags.length > 0 && (
        <>
          <h2 className="mb-2 text-lg font-semibold">Firewall ION Tags</h2>
          <DataTable
            columns={ionTagColumns()}
            data={data.ion_tags}
            rowKey={(r) => r.rule_id}
            emptyMessage="No ION tags found in firewall rules"
            searchable
            searchPlaceholder="Search tags..."
            defaultSort={{ key: "tag", asc: true }}
          />
        </>
      )}
      <PolicyDeviationsSection />

      {showForm && (
        <PolicyFormModal
          editing={editingPolicy}
          vlanNames={vlan.names}
          onClose={handleCloseForm}
        />
      )}
    </PageShell>
  );
}

// ── Policy Deviations Section ─────────────────────────────────

const statusColor: Record<string, string> = {
  new: "bg-warning/15 text-warning",
  acknowledged: "bg-sky-400/15 text-sky-400",
  resolved: "bg-emerald-400/15 text-emerald-400",
  dismissed: "bg-muted text-muted-foreground",
};

const severityColor: Record<string, string> = {
  informational: "text-muted-foreground",
  warning: "text-warning",
  critical: "text-destructive",
};

function deviationColumns(
  attackDb: Record<string, { name: string; url: string }> | undefined,
  onResolve: (id: number, action: string) => void,
  vlanName: (id: number) => string,
): Column<PolicyDeviation>[] {
  return [
    {
      key: "type",
      header: "Type",
      width: "110px",
      render: (r) => (
        <span className="rounded bg-primary/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-primary">
          {r.deviation_type.replace("_", " ")}
        </span>
      ),
      sortValue: (r) => r.deviation_type,
    },
    {
      key: "device",
      header: "Device",
      width: "180px",
      render: (r) => (
        <div className="text-xs">
          {r.device_hostname && <div className="font-medium truncate" title={r.device_hostname}>{r.device_hostname}</div>}
          <div className="font-mono text-muted-foreground">{r.ip_address}</div>
        </div>
      ),
      sortValue: (r) => r.device_hostname ?? r.mac_address,
    },
    {
      key: "vlan",
      header: "VLAN",
      width: "100px",
      render: (r) => (
        <span className="text-xs text-muted-foreground">
          {r.vlan != null ? vlanName(r.vlan) : "—"}
        </span>
      ),
      sortValue: (r) => r.vlan ?? -1,
    },
    {
      key: "expected",
      header: "Expected",
      render: (r) => (
        <div className="text-xs">
          {r.expected_label && <div className="text-emerald-400 truncate" title={r.expected_label}>{r.expected_label}</div>}
          <div className={`font-mono ${r.expected_label ? "text-emerald-400/60" : "text-emerald-400"}`}>{r.expected}</div>
        </div>
      ),
    },
    {
      key: "actual",
      header: "Actual",
      render: (r) => (
        <div className="text-xs">
          {r.actual_label && <div className="text-destructive truncate" title={r.actual_label}>{r.actual_label}</div>}
          <div className={`font-mono ${r.actual_label ? "text-destructive/60" : "text-destructive"}`}>{r.actual}</div>
        </div>
      ),
    },
    {
      key: "attack",
      header: "ATT&CK",
      render: (r) => (
        <div className="flex flex-wrap gap-1">
          {r.attack_techniques.map((t) => {
            const tech = attackDb?.[t];
            return (
              <a
                key={t}
                href={tech?.url ?? `https://attack.mitre.org/techniques/${t.replace(".", "/")}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded bg-amber-400/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-400 hover:bg-amber-400/20"
                title={tech?.name ?? t}
              >
                {t}
              </a>
            );
          })}
        </div>
      ),
    },
    {
      key: "severity",
      header: "Severity",
      width: "90px",
      render: (r) => (
        <span className={`text-xs font-medium ${severityColor[r.severity] ?? ""}`}>
          {r.severity}
        </span>
      ),
    },
    {
      key: "count",
      header: "Count",
      width: "65px",
      render: (r) => <span className="font-mono text-xs">{r.occurrence_count}</span>,
      sortValue: (r) => r.occurrence_count,
    },
    {
      key: "status",
      header: "Status",
      width: "100px",
      render: (r) => (
        <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${statusColor[r.status] ?? ""}`}>
          {r.status}
        </span>
      ),
      sortValue: (r) => {
        const order: Record<string, number> = { new: 0, acknowledged: 1, resolved: 2, dismissed: 3 };
        return order[r.status] ?? 3;
      },
    },
    {
      key: "first_seen",
      header: "First Seen",
      width: "100px",
      render: (r) => <span className="text-xs text-muted-foreground">{formatTimeAgo(r.first_seen)}</span>,
      sortValue: (r) => -r.first_seen,
    },
    {
      key: "last_seen",
      header: "Last Seen",
      width: "100px",
      render: (r) => <span className="text-xs text-muted-foreground">{formatTimeAgo(r.last_seen)}</span>,
      sortValue: (r) => -r.last_seen,
    },
    {
      key: "actions",
      header: "",
      width: "90px",
      render: (r) => {
        if (r.status === "resolved") return null;
        return (
          <select
            className="rounded border border-border bg-background px-1.5 py-0.5 text-[10px]"
            defaultValue=""
            onChange={(e) => {
              if (e.target.value) {
                onResolve(r.id, e.target.value);
                e.target.value = "";
              }
            }}
          >
            <option value="" disabled>Resolve...</option>
            <option value="acknowledge">Acknowledge</option>
            <option value="authorize">Authorize</option>
            <option value="deny_all">Flag All</option>
            <option value="dismiss">Dismiss</option>
          </select>
        );
      },
    },
  ];
}

function PolicyDeviationsSection() {
  const { data: response, isLoading } = usePolicyDeviations({ limit: 500 });
  const { data: attackDb } = useAttackTechniques();
  const resolveMutation = useResolvePolicyDeviation();
  const deleteAllMutation = useDeleteAllDeviations();
  const vlanLookup = useVlanLookup();

  const deviations = response?.deviations;
  const totalCount = response?.total_count ?? 0;
  const truncated = response?.truncated ?? false;
  const techniques = attackDb?.techniques;

  const handleResolve = (id: number, action: string) => {
    resolveMutation.mutate({ id, action });
  };

  const handleDeleteAll = () => {
    if (!window.confirm(`Delete all ${totalCount} policy deviations? This cannot be undone.`)) return;
    deleteAllMutation.mutate();
  };

  const handleExport = () => {
    if (!deviations || deviations.length === 0) return;
    const headers = ["Type", "Device", "IP", "VLAN", "Expected", "Actual", "Severity", "Status", "Count", "First Seen", "Last Seen", "ATT&CK"];
    const rows = deviations.map((d) => [
      d.deviation_type,
      d.device_hostname ?? d.mac_address,
      d.ip_address,
      d.vlan != null ? vlanLookup.name(d.vlan) : "",
      d.expected,
      d.actual,
      d.severity,
      d.status,
      String(d.occurrence_count),
      new Date(d.first_seen * 1000).toISOString(),
      new Date(d.last_seen * 1000).toISOString(),
      d.attack_techniques.join(" "),
    ]);
    // Sanitize cells to prevent CSV formula injection (=, +, -, @, \t, \r)
    const sanitize = (v: string) => /^[=+\-@\t\r]/.test(v) ? `'${v}` : v;
    const csv = [headers, ...rows].map((r) => r.map((c) => `"${sanitize(c).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `policy-deviations-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (isLoading || !deviations || deviations.length === 0) return null;

  return (
    <>
      <div className="flex items-center justify-between mt-6 mb-2">
        <h2 className="text-lg font-semibold">Policy Deviations</h2>
        <div className="flex items-center gap-2">
          <button
            className="inline-flex items-center gap-1.5 rounded-md border border-border px-3 py-1 text-xs font-medium text-muted-foreground hover:bg-muted transition-colors"
            onClick={handleExport}
          >
            <Download className="h-3.5 w-3.5" />
            Export CSV
          </button>
          <button
            className="inline-flex items-center gap-1.5 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-1 text-xs font-medium text-destructive hover:bg-destructive/20 transition-colors"
            onClick={handleDeleteAll}
            disabled={deleteAllMutation.isPending}
          >
            {deleteAllMutation.isPending ? "Deleting..." : `Delete All (${totalCount})`}
          </button>
        </div>
      </div>
      {truncated && (
        <p className="mb-2 text-xs text-warning">
          Showing {deviations.length} of {totalCount} deviations. Increase limit or use filters to see all.
        </p>
      )}
      <DataTable
        columns={deviationColumns(techniques, handleResolve, vlanLookup.name)}
        data={deviations}
        rowKey={(r) => String(r.id)}
        emptyMessage="No policy deviations detected"
        searchable
        searchPlaceholder="Search deviations..."
        defaultSort={{ key: "last_seen", asc: true }}
      />
    </>
  );
}
