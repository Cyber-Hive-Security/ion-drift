import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/api/client";
import { PageShell } from "@/components/layout/page-shell";
import { DataTable, type Column } from "@/components/data-table";
import { LoadingSpinner } from "@/components/loading-spinner";
import { useVlanLookup } from "@/hooks/use-vlan-lookup";
import { usePolicyDeviations, useResolvePolicyDeviation, useAttackTechniques } from "@/api/queries";
import type { PolicyDeviation } from "@/api/types";

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

function policyColumns(vlanNames: Record<number, string>): Column<PolicyEntry>[] {
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
          {r.authorized_targets.join(", ")}
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
      width: "140px",
      render: (r) => <span className="text-xs text-muted-foreground">{r.source}</span>,
      sortValue: (r) => r.source,
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
      key: "synced",
      header: "Last Synced",
      width: "100px",
      render: (r) => <span className="text-xs text-muted-foreground">{formatTimeAgo(r.last_synced)}</span>,
      sortValue: (r) => -r.last_synced,
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

export function PolicyPage() {
  const { data, isLoading, error } = usePolicyOverview();
  const vlan = useVlanLookup();

  if (isLoading) return <LoadingSpinner />;
  if (error) return <PageShell title="Policy Map"><p className="text-destructive">Failed to load policy data</p></PageShell>;
  if (!data) return null;

  return (
    <PageShell title="Infrastructure Policy Map">
      <p className="mb-4 text-sm text-muted-foreground">
        Authoritative service map derived from router configuration. Synced every 60 minutes.
        {data.policy_count > 0 && ` ${data.policy_count} policies, ${data.tag_count} ION tags.`}
      </p>

      <h2 className="mb-2 text-lg font-semibold">Service Policies</h2>
      <div className="mb-6">
        <DataTable
          columns={policyColumns(vlan.names)}
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
    </PageShell>
  );
}

// ── Policy Deviations Section ─────────────────────────────────

const statusColor: Record<string, string> = {
  new: "bg-warning/15 text-warning",
  acknowledged: "bg-sky-400/15 text-sky-400",
  resolved: "bg-emerald-400/15 text-emerald-400",
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
      width: "140px",
      render: (r) => (
        <div className="text-xs">
          <div className="font-mono">{r.mac_address}</div>
          <div className="text-muted-foreground">{r.ip_address}</div>
        </div>
      ),
      sortValue: (r) => r.mac_address,
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
      render: (r) => <span className="font-mono text-xs text-emerald-400">{r.expected}</span>,
    },
    {
      key: "actual",
      header: "Actual",
      render: (r) => <span className="font-mono text-xs text-destructive">{r.actual}</span>,
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
        const order: Record<string, number> = { new: 0, acknowledged: 1, resolved: 2 };
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
            <option value="deny_all">Deny All</option>
            <option value="dismiss">Dismiss</option>
          </select>
        );
      },
    },
  ];
}

function PolicyDeviationsSection() {
  const { data: deviations, isLoading } = usePolicyDeviations({ limit: 200 });
  const { data: attackDb } = useAttackTechniques();
  const resolveMutation = useResolvePolicyDeviation();
  const vlanLookup = useVlanLookup();

  const techniques = attackDb?.techniques;

  const handleResolve = (id: number, action: string) => {
    resolveMutation.mutate({ id, action });
  };

  if (isLoading || !deviations || deviations.length === 0) return null;

  return (
    <>
      <h2 className="mb-2 mt-6 text-lg font-semibold">Policy Deviations</h2>
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
