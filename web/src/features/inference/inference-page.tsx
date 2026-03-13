import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/api/client";
import {
  useInferenceStatus,
  useInferenceMacDetail,
  useInferenceObservations,
  useNetworkIdentities,
} from "@/api/queries";
import { PageShell } from "@/components/layout/page-shell";
import { InferenceHelp } from "@/components/help-content";
import { LoadingSpinner } from "@/components/loading-spinner";
import { ErrorDisplay } from "@/components/error-display";
import { DataTable, type Column } from "@/components/data-table";
import { StatCard } from "@/components/stat-card";
import { cn } from "@/lib/utils";
import type {
  ScoredCandidate,
  AttachmentStateRow,
} from "@/api/types";
import {
  Brain,
  Activity,
  AlertTriangle,
  GitCompareArrows,
  BarChart3,
  ChevronDown,
  ChevronRight,
  Eye,
} from "lucide-react";

// ── Hooks ───────────────────────────────────────────────────────

function useAttachmentStates() {
  return useQuery({
    queryKey: ["network", "inference", "states"],
    queryFn: () =>
      apiFetch<AttachmentStateRow[]>("/api/network/inference/states"),
    refetchInterval: 30_000,
  });
}

// ── State badge colors ──────────────────────────────────────────

const STATE_COLORS: Record<string, string> = {
  unknown: "bg-gray-500/20 text-gray-400",
  candidate: "bg-primary/20 text-primary",
  probable: "bg-cyan-500/20 text-cyan-400",
  stable: "bg-success/20 text-success",
  roaming: "bg-purple-500/20 text-purple-400",
  conflicted: "bg-destructive/20 text-destructive",
  human_pinned: "bg-warning/20 text-warning",
};

const MODE_COLORS: Record<string, string> = {
  legacy: "bg-gray-600 text-gray-200",
  shadow: "bg-warning text-background",
  active: "bg-success text-background",
};

function StateBadge({ state }: { state: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium",
        STATE_COLORS[state] ?? STATE_COLORS.unknown,
      )}
    >
      {state}
    </span>
  );
}

function ModeBadge({ mode }: { mode: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold",
        MODE_COLORS[mode] ?? MODE_COLORS.legacy,
      )}
    >
      {mode.toUpperCase()}
    </span>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color =
    pct >= 70 ? "bg-success" : pct >= 40 ? "bg-warning" : "bg-destructive";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 rounded-full bg-muted">
        <div
          className={cn("h-full rounded-full", color)}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs text-muted-foreground">{pct}%</span>
    </div>
  );
}

// ── Feature breakdown ───────────────────────────────────────────

function FeatureBreakdown({ candidate }: { candidate: ScoredCandidate }) {
  const f = candidate.features;
  const features = [
    { name: "Edge Likelihood", value: f.edge_likelihood, weight: 2.0 },
    { name: "Persistence", value: f.persistence, weight: 1.5 },
    { name: "VLAN Consistency", value: f.vlan_consistency, weight: 1.2 },
    { name: "Downstream Pref.", value: f.downstream_preference, weight: 1.0 },
    { name: "Recency", value: f.recency, weight: 0.8 },
    { name: "Graph Depth", value: f.graph_depth_score, weight: 0.6 },
    { name: "Device Class Fit", value: f.device_class_fit, weight: 0.6 },
    { name: "Transit Penalty", value: f.transit_penalty, weight: -2.0 },
    { name: "Contradiction Pen.", value: f.contradiction_penalty, weight: -1.5 },
    { name: "Router Penalty", value: f.router_penalty, weight: -3.0 },
    { name: "Wireless Attach.", value: f.wireless_attachment_likelihood, weight: 1.3 },
    { name: "WAP Path Consist.", value: f.wap_path_consistency, weight: 0.8 },
    { name: "AP Feeder Penalty", value: f.ap_feeder_penalty, weight: -1.0 },
  ];

  return (
    <div className="mt-2 rounded border border-border bg-card/50 p-3">
      <div className="mb-2 flex items-center justify-between text-xs">
        <span className="font-medium">
          {candidate.device_id} / {candidate.port_name || "(WAP)"}
          {candidate.vlan_id != null && (
            <span className="ml-2 text-muted-foreground">
              VLAN {candidate.vlan_id}
            </span>
          )}
          <span className="ml-2 text-muted-foreground">
            ({candidate.candidate_type}, {candidate.observation_count} obs)
          </span>
        </span>
        <span className="font-mono">
          Score: {candidate.score.toFixed(2)}
          {candidate.suppressed && (
            <span className="ml-2 text-destructive">
              (suppressed{candidate.suppression_reason ? `: ${candidate.suppression_reason}` : ""})
            </span>
          )}
        </span>
      </div>
      <div className="grid grid-cols-3 gap-x-4 gap-y-1 text-[11px]">
        {features.map((feat) => (
          <div key={feat.name} className="flex justify-between">
            <span className="text-muted-foreground">{feat.name}</span>
            <span className="font-mono">
              {feat.value.toFixed(2)}{" "}
              <span className="text-muted-foreground">
                ({"\u00d7"}{feat.weight.toFixed(1)})
              </span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Expanded MAC detail ─────────────────────────────────────────

function MacDetail({ mac }: { mac: string }) {
  const { data, isLoading, error } = useInferenceMacDetail(mac);

  if (isLoading) return <div className="p-4"><LoadingSpinner /></div>;
  if (error) return <div className="p-4"><ErrorDisplay message={String(error)} /></div>;
  if (!data) return null;

  return (
    <div className="space-y-3 border-t border-border bg-muted/30 px-4 py-3">
      {/* Explanation */}
      {data.explanation.length > 0 && (
        <div>
          <h4 className="mb-1 text-xs font-semibold text-muted-foreground">
            Explanation
          </h4>
          <ul className="list-inside list-disc space-y-0.5 text-xs">
            {data.explanation.map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Current legacy binding */}
      {data.current_binding && (
        <div className="text-xs">
          <span className="font-semibold text-muted-foreground">
            Legacy binding:{" "}
          </span>
          <span className="font-mono">
            {data.current_binding.device_id} / {data.current_binding.port}
          </span>
          <span className="ml-2 text-muted-foreground">
            (source: {data.current_binding.source})
          </span>
        </div>
      )}

      {/* Previous binding (roaming) */}
      {data.state.previous_device_id && (
        <div className="text-xs">
          <span className="font-semibold text-muted-foreground">
            Previous binding:{" "}
          </span>
          <span className="font-mono">
            {data.state.previous_device_id} / {data.state.previous_port_name}
          </span>
        </div>
      )}

      {/* Candidates */}
      <div>
        <h4 className="mb-1 text-xs font-semibold text-muted-foreground">
          Candidates ({data.candidates.length})
        </h4>
        {data.candidates.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            No candidates in observation window
          </p>
        ) : (
          data.candidates.map((c, i) => (
            <FeatureBreakdown key={i} candidate={c} />
          ))
        )}
      </div>
    </div>
  );
}

// ── MAC table row type ──────────────────────────────────────────

interface MacRow {
  mac_address: string;
  state: string;
  device_id: string;
  port_name: string;
  score: number;
  confidence: number;
  consecutive_wins: number;
  divergent: boolean;
}

// ── Main page ───────────────────────────────────────────────────

export function InferencePage({ embedded = false }: { embedded?: boolean }) {
  const status = useInferenceStatus();
  const observations = useInferenceObservations();
  const statesQuery = useAttachmentStates();
  const identitiesQuery = useNetworkIdentities();
  const [expandedMac, setExpandedMac] = useState<string | null>(null);

  const states = statesQuery.data ?? [];
  const identities = identitiesQuery.data ?? [];

  // Build identity lookup for divergence detection
  const identityMap = useMemo(() => {
    const m = new Map<string, { device_id: string; port: string }>();
    for (const ident of identities) {
      if (ident.switch_device_id && ident.switch_port) {
        m.set(ident.mac_address.toUpperCase(), {
          device_id: ident.switch_device_id,
          port: ident.switch_port,
        });
      }
    }
    return m;
  }, [identities]);

  // Build table rows
  const rows: MacRow[] = useMemo(() => {
    return states.map((st) => {
      const legacy = identityMap.get(st.mac_address.toUpperCase());
      const divergent =
        !!legacy &&
        !!(st.current_device_id || st.current_port_name) &&
        (legacy.device_id !== (st.current_device_id ?? "") ||
          legacy.port !== (st.current_port_name ?? ""));
      return {
        mac_address: st.mac_address,
        state: st.state,
        device_id: st.current_device_id ?? "—",
        port_name: st.current_port_name ?? "—",
        score: st.current_score,
        confidence: st.confidence,
        consecutive_wins: st.consecutive_wins,
        divergent,
      };
    });
  }, [states, identityMap]);

  const columns: Column<MacRow>[] = useMemo(
    () => [
      {
        key: "expand",
        header: "",
        render: (row: MacRow) => (
          <button
            onClick={(e) => {
              e.stopPropagation();
              setExpandedMac(
                expandedMac === row.mac_address ? null : row.mac_address,
              );
            }}
            className="text-muted-foreground hover:text-foreground"
          >
            {expandedMac === row.mac_address ? (
              <ChevronDown className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
          </button>
        ),
      },
      {
        key: "mac",
        header: "MAC",
        render: (row: MacRow) => (
          <span className="font-mono text-xs">{row.mac_address}</span>
        ),
        sortValue: (row: MacRow) => row.mac_address,
      },
      {
        key: "state",
        header: "State",
        render: (row: MacRow) => <StateBadge state={row.state} />,
        sortValue: (row: MacRow) => row.state,
      },
      {
        key: "device",
        header: "Device / Port",
        render: (row: MacRow) => (
          <span className="text-xs">
            {row.device_id} / {row.port_name}
          </span>
        ),
        sortValue: (row: MacRow) => `${row.device_id}/${row.port_name}`,
      },
      {
        key: "confidence",
        header: "Confidence",
        render: (row: MacRow) => <ConfidenceBar value={row.confidence} />,
        sortValue: (row: MacRow) => row.confidence,
      },
      {
        key: "score",
        header: "Score",
        render: (row: MacRow) => (
          <span className="font-mono text-xs">{row.score.toFixed(2)}</span>
        ),
        sortValue: (row: MacRow) => row.score,
      },
      {
        key: "wins",
        header: "Wins",
        render: (row: MacRow) => (
          <span className="text-xs">{row.consecutive_wins}</span>
        ),
        sortValue: (row: MacRow) => row.consecutive_wins,
      },
      {
        key: "divergent",
        header: "Div",
        headerTitle: "Divergent from legacy binding",
        render: (row: MacRow) =>
          row.divergent ? (
            <span className="inline-block h-2.5 w-2.5 rounded-full bg-warning" />
          ) : null,
        sortValue: (row: MacRow) => (row.divergent ? 1 : 0),
      },
    ],
    [expandedMac],
  );

  if (status.isLoading) {
    const loading = <LoadingSpinner />;
    if (embedded) return loading;
    return <PageShell title="Topology Inference" help={<InferenceHelp />}>{loading}</PageShell>;
  }

  if (status.error || !status.data) {
    const err = <ErrorDisplay message={status.error ? String(status.error) : "No data available"} />;
    if (embedded) return err;
    return <PageShell title="Topology Inference" help={<InferenceHelp />}>{err}</PageShell>;
  }

  const s = status.data;

  const content = (
    <div>
      {/* Mode banner */}
      <div className="mb-4 flex items-center gap-3">
        <Brain className="h-5 w-5 text-primary" />
        <span className="text-sm font-medium">Mode:</span>
        <ModeBadge mode={s.mode} />
        {s.mode === "shadow" && (
          <span className="text-xs text-muted-foreground">
            Inference runs alongside legacy — results logged but not applied
          </span>
        )}
        {s.mode === "active" && (
          <span className="text-xs text-muted-foreground">
            Inference writes bindings to identity store
          </span>
        )}
        {s.mode === "legacy" && (
          <span className="text-xs text-muted-foreground">
            Inference engine disabled — using legacy binding only
          </span>
        )}
      </div>

      {/* Stats row */}
      <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard title="MACs Tracked" icon={<Activity className="h-4 w-4" />}>
          <div className="text-2xl font-bold">{s.total_macs}</div>
        </StatCard>

        <StatCard
          title="Avg Confidence"
          icon={<BarChart3 className="h-4 w-4" />}
        >
          <div className="text-2xl font-bold">
            {(s.avg_confidence * 100).toFixed(0)}%
          </div>
        </StatCard>

        <StatCard
          title="Divergences"
          icon={<GitCompareArrows className="h-4 w-4" />}
        >
          <div className="text-2xl font-bold">{s.divergence_count}</div>
          {s.divergence_categories &&
            typeof s.divergence_categories === "object" &&
            Object.keys(s.divergence_categories).length > 0 ? (
            <div className="flex flex-wrap gap-1 mt-1">
              {Object.entries(s.divergence_categories).map(([cat, count]) => (
                <span
                  key={cat}
                  className="inline-flex items-center rounded-full bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground"
                >
                  {cat.replace(/_/g, " ")}: {String(count)}
                </span>
              ))}
            </div>
          ) : (
            <div className="text-xs text-muted-foreground">
              inference {"\u2260"} legacy
            </div>
          )}
        </StatCard>

        <StatCard title="State Distribution" icon={<Eye className="h-4 w-4" />}>
          <div className="flex flex-wrap gap-1">
            {s.state_distribution && typeof s.state_distribution === "object" &&
              Object.entries(s.state_distribution).map(([state, count]) => (
              <span key={state} className="text-xs">
                <StateBadge state={state} />{" "}
                <span className="font-mono">{String(count)}</span>
              </span>
            ))}
          </div>
        </StatCard>
      </div>

      {/* Observation stats */}
      {observations.data && (
        <div className="mb-4 flex flex-wrap items-center gap-x-6 gap-y-1 text-xs text-muted-foreground">
          <span>
            Observations (10m window):{" "}
            <span className="font-mono font-medium text-foreground">
              {observations.data.total_observations}
            </span>
          </span>
          <span>
            Unique MACs:{" "}
            <span className="font-mono font-medium text-foreground">
              {observations.data.unique_macs}
            </span>
          </span>
          {observations.data.observations_per_device &&
            typeof observations.data.observations_per_device === "object" &&
            Object.entries(observations.data.observations_per_device).map(
            ([dev, count]) => (
              <span key={dev}>
                {dev}:{" "}
                <span className="font-mono font-medium text-foreground">
                  {String(count)}
                </span>
              </span>
            ),
          )}
        </div>
      )}

      {/* MAC table */}
      {states.length === 0 && !statesQuery.isLoading ? (
        <div className="flex flex-col items-center justify-center rounded-lg border border-border bg-card py-12 text-center">
          <AlertTriangle className="mb-2 h-8 w-8 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">
            No MAC attachment states yet.
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            The inference engine needs observations from switch pollers. Check
            that TOPOLOGY_INFERENCE_MODE is set to "shadow" or "active".
          </p>
        </div>
      ) : (
        <>
          <DataTable
            columns={columns}
            data={rows}
            rowKey={(r) => r.mac_address}
            searchable
            searchPlaceholder="Search MAC, device, port..."
            defaultSort={{ key: "confidence", asc: false }}
            expandedRow={(r) =>
              expandedMac === r.mac_address ? <MacDetail mac={r.mac_address} /> : null
            }
          />
        </>
      )}
  </div>
  );

  if (embedded) return content;
  return <PageShell title="Topology Inference" help={<InferenceHelp />}>{content}</PageShell>;
}

export default InferencePage;
