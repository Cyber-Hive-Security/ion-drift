import { useState, useRef, useEffect, useCallback, useMemo } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useSearch, useNavigate } from "@tanstack/react-router";
import { PageShell } from "@/components/layout/page-shell";
import { InvestigationHelp } from "@/components/help-content";
import { ErrorBoundary } from "@/components/error-boundary";
import { ErrorDisplay } from "@/components/error-display";
import {
  useSankeyNetwork,
  useSankeyVlan,
  useSankeyDevice,
  useSankeyDestinationPeers,
  useSankeyConversation,
  useDeviceInvestigations,
} from "@/api/queries";
import { apiFetch } from "@/api/client";
import type {
  SankeyVlanResponse,
  SankeyDeviceResponse,
  Investigation,
} from "@/api/types";
import { formatBytes } from "@/lib/format";
import { cn } from "@/lib/utils";
import { countryFlag } from "@/lib/country";
import { ChevronRight, ArrowLeft, Download, Flag, Copy, Search, Network, Microscope, ChevronDown } from "lucide-react";

const RANGES = ["1h", "6h", "24h", "7d", "30d"] as const;

function TimeRangeSelector({
  value,
  onChange,
}: {
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="flex gap-1">
      {RANGES.map((r) => (
        <button
          key={r}
          onClick={() => onChange(r)}
          className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
            value === r
              ? "bg-primary text-primary-foreground"
              : "bg-muted text-muted-foreground hover:bg-accent"
          }`}
        >
          {r}
        </button>
      ))}
    </div>
  );
}

function Breadcrumb({
  items,
}: {
  items: { label: string; onClick?: () => void }[];
}) {
  return (
    <div className="flex items-center gap-1 text-sm text-muted-foreground">
      {items.map((item, i) => (
        <span key={i} className="flex items-center gap-1">
          {i > 0 && <ChevronRight className="h-3.5 w-3.5" />}
          {item.onClick ? (
            <button
              onClick={item.onClick}
              className="hover:text-foreground transition-colors"
            >
              {item.label}
            </button>
          ) : (
            <span className="text-foreground font-medium">{item.label}</span>
          )}
        </span>
      ))}
    </div>
  );
}

// ── Skeleton loading components ──────────────────────────────

function SkeletonCard({ lines = 3 }: { lines?: number }) {
  return (
    <div className="rounded-lg border border-border bg-card p-4 animate-pulse">
      <div className="h-4 w-32 rounded bg-muted mb-3" />
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} className="h-3 rounded bg-muted mb-2" style={{ width: `${80 - i * 15}%` }} />
      ))}
    </div>
  );
}

function SkeletonGrid({ count = 4 }: { count?: number }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="rounded-lg border border-border bg-card p-3 animate-pulse">
          <div className="h-4 w-20 rounded bg-muted mb-2" />
          <div className="h-3 w-28 rounded bg-muted mb-1" />
          <div className="h-3 w-24 rounded bg-muted" />
        </div>
      ))}
    </div>
  );
}

function SkeletonTable({ rows = 5 }: { rows?: number }) {
  return (
    <div className="rounded-lg border border-border bg-card animate-pulse">
      <div className="border-b border-border p-3">
        <div className="h-4 w-32 rounded bg-muted" />
      </div>
      <div className="divide-y divide-border">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="flex items-center gap-4 px-4 py-2.5">
            <div className="h-3 w-20 rounded bg-muted" />
            <div className="h-3 w-3 rounded bg-muted" />
            <div className="h-3 w-20 rounded bg-muted" />
            <div className="h-3 flex-1 rounded bg-muted" />
          </div>
        ))}
      </div>
    </div>
  );
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-border bg-card p-12 text-center">
      <Search className="h-8 w-8 text-muted-foreground/50" />
      <p className="text-sm text-muted-foreground">{message}</p>
    </div>
  );
}

// ── Context menu ─────────────────────────────────────────────

interface ContextMenuItem {
  label: string;
  icon?: React.ReactNode;
  onClick: () => void;
}

function ContextMenu({
  x,
  y,
  items,
  onClose,
}: {
  x: number;
  y: number;
  items: ContextMenuItem[];
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const keyHandler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("mousedown", handler);
    document.addEventListener("keydown", keyHandler);
    return () => {
      document.removeEventListener("mousedown", handler);
      document.removeEventListener("keydown", keyHandler);
    };
  }, [onClose]);

  return (
    <div
      ref={ref}
      className="fixed z-50 min-w-[160px] rounded-md border border-border bg-popover py-1 shadow-lg animate-in fade-in-0 zoom-in-95"
      style={{ left: x, top: y }}
    >
      {items.map((item, i) => (
        <button
          key={i}
          onClick={() => { item.onClick(); onClose(); }}
          className="flex w-full items-center gap-2 px-3 py-1.5 text-xs text-popover-foreground hover:bg-accent transition-colors"
        >
          {item.icon}
          {item.label}
        </button>
      ))}
    </div>
  );
}

// ── Crossfade wrapper ────────────────────────────────────────

function FadeIn({ children }: { children: React.ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    el.style.opacity = "0";
    el.style.transform = "translateY(4px)";
    requestAnimationFrame(() => {
      el.style.transition = "opacity 200ms ease-out, transform 200ms ease-out";
      el.style.opacity = "1";
      el.style.transform = "translateY(0)";
    });
  }, []);

  return <div ref={ref}>{children}</div>;
}

// ── Clipboard helper ─────────────────────────────────────────

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).catch(() => {});
}

/** Format a bare VLAN ID for display: "35" → "VLAN 35", "WAN" stays "WAN". */
function vlanLabel(id: string): string {
  if (!id || id === "WAN") return id;
  return `VLAN ${id}`;
}

type View =
  | { level: "network" }
  | { level: "vlan"; vlanId: string; destVlan?: string }
  | { level: "device"; mac: string }
  | { level: "conversation"; mac: string; destIp: string };

export function SankeyInvestigationPage() {
  const search = useSearch({ from: "/sankey" });
  const navigate = useNavigate();
  const [range, setRange] = useState(search.country ? "30d" : "24h");

  // Derive initial view from URL search params
  const initialView = useMemo((): View => {
    if (search.mac) return { level: "device", mac: search.mac };
    if (search.vlan) return { level: "vlan", vlanId: search.vlan, destVlan: search.dest };
    // Country param → jump straight to WAN vlan (all country traffic is WAN)
    if (search.country) return { level: "vlan", vlanId: "WAN" };
    return { level: "network" };
  }, []); // Only compute once on mount

  const [view, setViewState] = useState<View>(initialView);

  // Wrap setView to sync URL
  const setView = useCallback((v: View) => {
    setViewState(v);
    const params: Record<string, string | undefined> = {};
    if (v.level === "vlan") {
      params.vlan = v.vlanId;
      params.dest = v.destVlan;
    } else if (v.level === "device") {
      params.mac = v.mac;
    } else if (v.level === "conversation") {
      params.mac = v.mac;
    }
    // Keep country if it was in original params
    if (search.country) params.country = search.country;
    navigate({ to: "/sankey", search: params, replace: true });
  }, [navigate, search.country]);

  const breadcrumb = (() => {
    const items: { label: string; onClick?: () => void }[] = [
      {
        label: "Network",
        onClick:
          view.level !== "network"
            ? () => setView({ level: "network" })
            : undefined,
      },
    ];
    if (view.level === "vlan") {
      items.push({ label: vlanLabel(view.vlanId) });
    }
    if (view.level === "device") {
      items.push({ label: view.mac });
    }
    if (view.level === "conversation") {
      items.push({
        label: view.mac,
        onClick: () => setView({ level: "device", mac: view.mac }),
      });
      items.push({ label: view.destIp });
    }
    return items;
  })();

  return (
    <PageShell title="Investigation" help={<InvestigationHelp />}>
      <ErrorBoundary>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Breadcrumb items={breadcrumb} />
              {search.country && (
                <span className="inline-flex items-center gap-1 rounded-full bg-destructive/15 px-2.5 py-0.5 text-xs font-medium text-destructive">
                  {countryFlag(search.country)} {search.country}
                </span>
              )}
            </div>
            <TimeRangeSelector value={range} onChange={setRange} />
          </div>

          {view.level === "network" && (
            <FadeIn key="network">
              <NetworkOverview
                range={range}
                onSelectVlan={(vlanId, destVlan) =>
                  setView({ level: "vlan", vlanId, destVlan })
                }
              />
            </FadeIn>
          )}
          {view.level === "vlan" && (
            <FadeIn key={`vlan-${view.vlanId}`}>
              <VlanDetail
                vlanId={view.vlanId}
                destVlan={view.destVlan}
                range={range}
                onBack={() => setView({ level: "network" })}
                onSelectDevice={(mac) => setView({ level: "device", mac })}
              />
            </FadeIn>
          )}
          {view.level === "device" && (
            <FadeIn key={`device-${view.mac}`}>
              <DeviceTrace
                mac={view.mac}
                range={range}
                onBack={() => setView({ level: "network" })}
                onSelectConversation={(mac, destIp) =>
                  setView({ level: "conversation", mac, destIp })
                }
              />
            </FadeIn>
          )}
          {view.level === "conversation" && (
            <FadeIn key={`conv-${view.mac}-${view.destIp}`}>
              <ConversationDetail
                mac={view.mac}
                destIp={view.destIp}
                range={range}
                onBack={() => setView({ level: "device", mac: view.mac })}
              />
            </FadeIn>
          )}
        </div>
      </ErrorBoundary>
    </PageShell>
  );
}

// ── Network Overview (Level 0) ──────────────────────────────

function NetworkOverview({
  range,
  onSelectVlan,
}: {
  range: string;
  onSelectVlan: (vlanId: string, destVlan?: string) => void;
}) {
  const { data, isLoading, error, refetch } = useSankeyNetwork(range);
  const queryClient = useQueryClient();

  // Prefetch VLAN detail on hover
  const prefetchVlan = useCallback(
    (vlanId: string) => {
      queryClient.prefetchQuery({
        queryKey: ["sankey", "vlan", vlanId, range, undefined],
        queryFn: () => apiFetch<SankeyVlanResponse>(`/api/sankey/vlan/${encodeURIComponent(vlanId)}?range=${range}`),
        staleTime: 20_000,
      });
    },
    [queryClient, range],
  );

  if (isLoading) {
    return (
      <div className="space-y-4">
        <SkeletonGrid count={6} />
        <SkeletonTable rows={5} />
      </div>
    );
  }
  if (error) return <ErrorDisplay message={error instanceof Error ? error.message : "Failed to load"} onRetry={() => refetch()} />;
  if (!data) return null;

  if (data.vlans.length === 0 && data.flows.length === 0) {
    return <EmptyState message="No network flows found in this time range." />;
  }

  return (
    <div className="space-y-4">
      {/* VLAN summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
        {data.vlans.map((vlan) => (
          <button
            key={vlan.vlan_id}
            onClick={() => onSelectVlan(vlan.vlan_id)}
            onMouseEnter={() => prefetchVlan(vlan.vlan_id)}
            className="rounded-lg border border-border bg-card p-3 text-left hover:border-primary/50 transition-colors"
          >
            <div className="text-sm font-medium">{vlanLabel(vlan.vlan_id)}</div>
            <div className="text-xs text-muted-foreground mt-1">
              {vlan.device_count} devices · {formatBytes(vlan.total_bytes)}
            </div>
            <div className="text-xs text-muted-foreground">
              {vlan.total_connections} connections
            </div>
          </button>
        ))}
      </div>

      {/* Flow table */}
      <div className="rounded-lg border border-border bg-card">
        <div className="border-b border-border p-3">
          <h3 className="text-sm font-semibold">Inter-VLAN Flows</h3>
        </div>
        <div className="divide-y divide-border max-h-96 overflow-y-auto">
          {data.flows.map((flow, i) => (
            <button
              key={i}
              className="w-full flex items-center gap-4 px-4 py-2.5 text-left hover:bg-accent/50 transition-colors"
              onClick={() => {
                // When source is WAN, drill into the destination VLAN (our local devices)
                // instead of WAN (100s of external IPs)
                if (flow.src_vlan === "WAN" && flow.dst_vlan !== "WAN") {
                  onSelectVlan(flow.dst_vlan, flow.src_vlan);
                } else {
                  onSelectVlan(flow.src_vlan, flow.dst_vlan);
                }
              }}
            >
              <span className="text-sm font-medium w-24">{vlanLabel(flow.src_vlan)}</span>
              <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
              <span className="text-sm font-medium w-24">{vlanLabel(flow.dst_vlan)}</span>
              <span className="text-xs text-muted-foreground flex-1 text-right">
                {formatBytes(flow.bytes)} · {flow.connections} conn
              </span>
              {flow.anomaly_count > 0 && (
                <span className="rounded-full bg-destructive/20 px-2 py-0.5 text-[10px] font-bold text-destructive">
                  {flow.anomaly_count} anomalies
                </span>
              )}
            </button>
          ))}
          {data.flows.length === 0 && (
            <div className="p-4 text-sm text-muted-foreground">
              No flows in this time range.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── VLAN Detail (Level 1) ───────────────────────────────────

function VlanDetail({
  vlanId,
  destVlan,
  range,
  onBack,
  onSelectDevice,
}: {
  vlanId: string;
  destVlan?: string;
  range: string;
  onBack: () => void;
  onSelectDevice: (mac: string) => void;
}) {
  const { data, isLoading, error, refetch } = useSankeyVlan(vlanId, range, destVlan);
  const queryClient = useQueryClient();
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number; mac: string; hostname?: string; ip?: string } | null>(null);

  // Prefetch device trace on hover
  const prefetchDevice = useCallback(
    (mac: string) => {
      queryClient.prefetchQuery({
        queryKey: ["sankey", "device", mac, range],
        queryFn: () => apiFetch<SankeyDeviceResponse>(`/api/sankey/device/${encodeURIComponent(mac)}?range=${range}`),
        staleTime: 20_000,
      });
    },
    [queryClient, range],
  );

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="h-5 w-24" />
        <SkeletonTable rows={4} />
        <SkeletonTable rows={4} />
      </div>
    );
  }
  if (error) return <ErrorDisplay message={error instanceof Error ? error.message : "Failed to load"} onRetry={() => refetch()} />;
  if (!data) return null;

  const flowStateColor = (state: string) => {
    switch (state) {
      case "baselined": return "text-green-500";
      case "learning": return "text-gray-400";
      case "unbaselined": return "text-amber-500";
      default: return "text-muted-foreground";
    }
  };

  return (
    <div className="space-y-4">
      <button
        onClick={onBack}
        className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> Back to Network
      </button>

      {destVlan && (
        <div className="text-xs text-muted-foreground">
          Filtered to flows: {vlanLabel(vlanId)} → {vlanLabel(destVlan)}
        </div>
      )}

      {data.devices.length === 0 && data.flows.length === 0 && (
        <EmptyState message="No devices or flows found in this VLAN for the selected time range." />
      )}

      {/* Devices */}
      {data.devices.length > 0 && (
        <div className="rounded-lg border border-border bg-card">
          <div className="border-b border-border p-3">
            <h3 className="text-sm font-semibold">Devices ({data.devices.length})</h3>
          </div>
          <div className="divide-y divide-border max-h-64 overflow-y-auto">
            {data.devices.map((dev) => (
              <button
                key={dev.mac}
                className="w-full flex items-center gap-4 px-4 py-2 text-left hover:bg-accent/50"
                onClick={() => onSelectDevice(dev.mac)}
                onMouseEnter={() => prefetchDevice(dev.mac)}
                onContextMenu={(e) => {
                  e.preventDefault();
                  setCtxMenu({ x: e.clientX, y: e.clientY, mac: dev.mac, hostname: dev.hostname ?? undefined, ip: dev.ip ?? undefined });
                }}
              >
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium truncate">
                    {dev.hostname || dev.mac}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {dev.ip || dev.mac}
                    {dev.baseline_status && (
                      <span className={`ml-2 ${flowStateColor(dev.baseline_status)}`}>
                        {dev.baseline_status}
                      </span>
                    )}
                  </div>
                </div>
                <span className="text-xs text-muted-foreground">
                  {formatBytes(dev.total_bytes)} · {dev.total_connections} conn
                </span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Flows */}
      {data.flows.length > 0 && (
        <div className="rounded-lg border border-border bg-card">
          <div className="border-b border-border p-3">
            <h3 className="text-sm font-semibold">Flows ({data.flows.length})</h3>
          </div>
          <div className="divide-y divide-border max-h-64 overflow-y-auto">
            {data.flows.map((flow, i) => (
              <div
                key={i}
                className="flex items-center gap-4 px-4 py-2"
              >
                <span className="text-xs font-mono w-36 truncate">{flow.src_mac}</span>
                <ChevronRight className="h-3 w-3 text-muted-foreground" />
                <span className="text-xs font-medium w-24">{flow.dst_group}</span>
                <span className="text-xs text-muted-foreground flex-1 text-right">
                  {formatBytes(flow.bytes)} · {flow.connections} conn
                </span>
                <span className={`text-[10px] font-medium ${flowStateColor(flow.flow_state)}`}>
                  {flow.flow_state}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Context menu */}
      {ctxMenu && (
        <ContextMenu
          x={ctxMenu.x}
          y={ctxMenu.y}
          onClose={() => setCtxMenu(null)}
          items={[
            {
              label: "Trace Device",
              icon: <Search className="h-3 w-3" />,
              onClick: () => onSelectDevice(ctxMenu.mac),
            },
            {
              label: "Copy MAC",
              icon: <Copy className="h-3 w-3" />,
              onClick: () => copyToClipboard(ctxMenu.mac),
            },
            ...(ctxMenu.ip ? [{
              label: "Copy IP",
              icon: <Copy className="h-3 w-3" />,
              onClick: () => copyToClipboard(ctxMenu.ip!),
            }] : []),
          ]}
        />
      )}
    </div>
  );
}

// ── Device Trace (Level 2) ──────────────────────────────────

// ── Verdict colors ──────────────────────────────────────────
const VERDICT_CLASSES: Record<string, string> = {
  benign: "bg-green-500/15 text-green-400",
  routine: "bg-blue-500/15 text-blue-400",
  suspicious: "bg-yellow-500/15 text-yellow-400",
  threat: "bg-red-500/15 text-red-400",
  inconclusive: "bg-zinc-500/15 text-zinc-400",
};

function DeviceInvestigationsPanel({ mac }: { mac: string }) {
  const { data: investigations } = useDeviceInvestigations(mac);
  const [expanded, setExpanded] = useState<number | null>(null);

  if (!investigations || investigations.length === 0) return null;

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-2 border-b border-border p-3">
        <Microscope className="h-4 w-4 text-primary" />
        <h3 className="text-sm font-semibold">Investigations ({investigations.length})</h3>
      </div>
      <div className="divide-y divide-border max-h-72 overflow-y-auto">
        {investigations.map((inv: Investigation) => (
          <div key={inv.id} className="px-4 py-2">
            <button
              onClick={() => setExpanded(expanded === inv.id ? null : inv.id)}
              className="flex w-full items-center gap-2 text-left"
            >
              <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-medium uppercase", VERDICT_CLASSES[inv.verdict] ?? VERDICT_CLASSES.inconclusive)}>
                {inv.verdict}
              </span>
              <span className="flex-1 truncate text-xs">{inv.summary}</span>
              <ChevronDown className={cn("h-3 w-3 text-muted-foreground transition-transform", expanded === inv.id && "rotate-180")} />
            </button>
            {expanded === inv.id && (
              <div className="mt-2 space-y-1 pl-2 text-xs text-muted-foreground">
                {inv.dst_ip && <div>Destination: <span className="font-mono">{inv.dst_ip}</span> {inv.dst_org && `(${inv.dst_org})`}</div>}
                {inv.dst_country && <div>Country: {inv.dst_country}</div>}
                {inv.dst_is_cdn && <div className="text-green-400">CDN/Cloud service detected</div>}
                {inv.dst_seen_by_device_count > 0 && <div>{inv.dst_seen_by_device_count} other devices also connect here</div>}
                {inv.evidence_chain && (
                  <div className="mt-1">
                    <div className="text-[10px] font-medium text-foreground/70 mb-0.5">Evidence Chain:</div>
                    {JSON.parse(inv.evidence_chain).map((step: { check: string; result: string; passed: boolean }, i: number) => (
                      <div key={i} className="flex items-center gap-1 text-[10px]">
                        <span className={step.passed ? "text-green-400" : "text-red-400"}>{step.passed ? "✓" : "✗"}</span>
                        <span>{step.check}: {step.result}</span>
                      </div>
                    ))}
                  </div>
                )}
                <div className="text-[10px] text-muted-foreground/60">
                  {new Date(inv.investigated_at).toLocaleString()}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function DeviceTrace({
  mac,
  range,
  onBack,
  onSelectConversation,
}: {
  mac: string;
  range: string;
  onBack: () => void;
  onSelectConversation: (mac: string, destIp: string) => void;
}) {
  const { data, isLoading, error, refetch } = useSankeyDevice(mac, range);
  const [selectedDst, setSelectedDst] = useState<string | null>(null);
  const peers = useSankeyDestinationPeers(selectedDst ?? undefined, range);
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number; ip: string; hostname?: string } | null>(null);

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="h-5 w-16" />
        <SkeletonCard lines={2} />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <SkeletonTable rows={4} />
          <SkeletonTable rows={4} />
        </div>
      </div>
    );
  }
  if (error) return <ErrorDisplay message={error instanceof Error ? error.message : "Failed to load"} onRetry={() => refetch()} />;
  if (!data) return null;

  return (
    <div className="space-y-4">
      <button
        onClick={onBack}
        className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> Back
      </button>

      {/* Device info */}
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="text-sm font-semibold">
          {data.hostname || data.mac}
        </div>
        <div className="text-xs text-muted-foreground">
          {data.ip || data.mac}
          {data.baseline_status && ` · ${data.baseline_status}`}
        </div>
      </div>

      <DeviceInvestigationsPanel mac={mac} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Protocols */}
        <div className="rounded-lg border border-border bg-card">
          <div className="border-b border-border p-3">
            <h3 className="text-sm font-semibold">Protocols ({data.protocols.length})</h3>
          </div>
          <div className="divide-y divide-border max-h-64 overflow-y-auto">
            {data.protocols.map((p, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-2">
                <span className="text-xs font-medium w-24">{p.service_name}</span>
                <span className="text-[10px] text-muted-foreground">{p.protocol}/{p.dst_port}</span>
                <span className="text-xs text-muted-foreground flex-1 text-right">
                  {formatBytes(p.bytes)} · {p.connections} conn
                </span>
              </div>
            ))}
            {data.protocols.length === 0 && (
              <div className="p-4 text-xs text-muted-foreground">No protocol data available.</div>
            )}
          </div>
        </div>

        {/* Destinations */}
        <div className="rounded-lg border border-border bg-card">
          <div className="border-b border-border p-3">
            <h3 className="text-sm font-semibold">Destinations ({data.destinations.length})</h3>
          </div>
          <div className="divide-y divide-border max-h-64 overflow-y-auto">
            {data.destinations.map((d, i) => (
              <button
                key={i}
                className="w-full flex items-center gap-3 px-4 py-2 text-left hover:bg-accent/50"
                onClick={() => setSelectedDst(selectedDst === d.dst_ip ? null : d.dst_ip)}
                onContextMenu={(e) => {
                  e.preventDefault();
                  setCtxMenu({ x: e.clientX, y: e.clientY, ip: d.dst_ip, hostname: d.dst_hostname ?? undefined });
                }}
              >
                <span className="text-xs font-mono flex-1 truncate">
                  {d.dst_hostname || d.dst_ip}
                  {d.is_external && (
                    <span className="ml-1 text-[10px] text-amber-500">ext</span>
                  )}
                </span>
                <span className="text-xs text-muted-foreground">
                  {formatBytes(d.bytes)} · {d.connections} conn
                </span>
                <button
                  className="text-[10px] text-primary hover:underline ml-1"
                  onClick={(e) => {
                    e.stopPropagation();
                    onSelectConversation(mac, d.dst_ip);
                  }}
                >
                  Detail
                </button>
              </button>
            ))}
            {data.destinations.length === 0 && (
              <div className="p-4 text-xs text-muted-foreground">No destinations found.</div>
            )}
          </div>
        </div>
      </div>

      {/* Who Else? panel */}
      {selectedDst && (
        <FadeIn key={`peers-${selectedDst}`}>
          <div className="rounded-lg border border-border bg-card">
            <div className="border-b border-border p-3 flex items-center justify-between">
              <h3 className="text-sm font-semibold">
                Who Else? — {selectedDst}
              </h3>
              <button
                onClick={() => setSelectedDst(null)}
                className="text-xs text-muted-foreground hover:text-foreground"
              >
                Close
              </button>
            </div>
            {peers.isLoading ? (
              <div className="divide-y divide-border">
                {Array.from({ length: 3 }).map((_, i) => (
                  <div key={i} className="flex items-center gap-3 px-4 py-2 animate-pulse">
                    <div className="h-3 w-32 rounded bg-muted" />
                    <div className="h-3 flex-1 rounded bg-muted" />
                  </div>
                ))}
              </div>
            ) : peers.error ? (
              <div className="p-4">
                <ErrorDisplay message="Failed to load peers" onRetry={() => peers.refetch()} className="border-0 bg-transparent p-2" />
              </div>
            ) : (
              <div className="divide-y divide-border max-h-48 overflow-y-auto">
                {peers.data?.peers.map((p, i) => (
                  <div key={i} className="flex items-center gap-3 px-4 py-2">
                    <span className="text-xs font-mono flex-1 truncate">
                      {p.hostname || p.mac}
                      {p.ip && <span className="ml-1 text-muted-foreground">({p.ip})</span>}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {formatBytes(p.bytes)} · {p.connections} conn
                    </span>
                  </div>
                ))}
                {peers.data?.peers.length === 0 && (
                  <div className="p-4 text-xs text-muted-foreground">
                    No other devices communicating with this destination.
                  </div>
                )}
              </div>
            )}
          </div>
        </FadeIn>
      )}

      {/* Flagged flows */}
      {data.flows.some((f) => f.flagged) && (
        <div className="rounded-lg border border-destructive/30 bg-card">
          <div className="border-b border-border p-3">
            <h3 className="text-sm font-semibold text-destructive">
              Flagged Flows ({data.flows.filter((f) => f.flagged).length})
            </h3>
          </div>
          <div className="divide-y divide-border max-h-48 overflow-y-auto">
            {data.flows
              .filter((f) => f.flagged)
              .map((f, i) => (
                <div key={i} className="flex items-center gap-3 px-4 py-2">
                  <span className="text-xs font-medium">{f.protocol}/{f.dst_port}</span>
                  <ChevronRight className="h-3 w-3 text-muted-foreground" />
                  <span className="text-xs font-mono truncate">{f.dst_ip}</span>
                  <span className="text-xs text-muted-foreground flex-1 text-right">
                    {formatBytes(f.bytes)} · {f.connections} conn
                  </span>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Context menu */}
      {ctxMenu && (
        <ContextMenu
          x={ctxMenu.x}
          y={ctxMenu.y}
          onClose={() => setCtxMenu(null)}
          items={[
            {
              label: "View Conversation",
              icon: <Network className="h-3 w-3" />,
              onClick: () => onSelectConversation(mac, ctxMenu.ip),
            },
            {
              label: "Copy IP",
              icon: <Copy className="h-3 w-3" />,
              onClick: () => copyToClipboard(ctxMenu.ip),
            },
            ...(ctxMenu.hostname ? [{
              label: "Copy Hostname",
              icon: <Copy className="h-3 w-3" />,
              onClick: () => copyToClipboard(ctxMenu.hostname!),
            }] : []),
          ]}
        />
      )}
    </div>
  );
}

// ── Conversation Detail (Level 3) ───────────────────────────

function ConversationDetail({
  mac,
  destIp,
  range,
  onBack,
}: {
  mac: string;
  destIp: string;
  range: string;
  onBack: () => void;
}) {
  const [page, setPage] = useState(1);
  const { data, isLoading, error, refetch } = useSankeyConversation(mac, destIp, range, page);

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="h-5 w-24" />
        <SkeletonCard lines={4} />
        <SkeletonCard lines={2} />
        <SkeletonTable rows={5} />
      </div>
    );
  }
  if (error) return <ErrorDisplay message={error instanceof Error ? error.message : "Failed to load"} onRetry={() => refetch()} />;
  if (!data) return null;

  const exportCsv = () => {
    if (!data.connections.length) return;
    const header = "id,protocol,src_port,dst_port,bytes_tx,bytes_rx,first_seen,last_seen,flagged\n";
    const rows = data.connections
      .map((c) =>
        [c.id, c.protocol, c.src_port ?? "", c.dst_port ?? "", c.bytes_tx, c.bytes_rx, c.first_seen, c.last_seen, c.flagged].join(","),
      )
      .join("\n");
    const blob = new Blob([header + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `conversation_${mac}_${destIp}_${range}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (data.summary.total_connections === 0 && data.connections.length === 0) {
    return (
      <div className="space-y-4">
        <button
          onClick={onBack}
          className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> Back to Device
        </button>
        <EmptyState message={`No conversations found between ${mac} and ${destIp} in this time range.`} />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <button
        onClick={onBack}
        className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> Back to Device
      </button>

      {/* Summary header */}
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="flex items-center justify-between mb-2">
          <div>
            <div className="text-sm font-semibold">
              {data.src_hostname || data.src_mac} → {data.dst_hostname || data.dst_ip}
            </div>
            <div className="text-xs text-muted-foreground">
              {data.baseline_status && <span className="mr-2">{data.baseline_status}</span>}
              {data.summary.protocols.join(", ")}
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={exportCsv}
              className="flex items-center gap-1 rounded px-2 py-1 text-xs text-muted-foreground hover:bg-accent"
            >
              <Download className="h-3.5 w-3.5" /> CSV
            </button>
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3">
          <div>
            <div className="text-[10px] uppercase text-muted-foreground">Total Traffic</div>
            <div className="text-sm font-medium">{formatBytes(data.summary.total_bytes)}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase text-muted-foreground">Connections</div>
            <div className="text-sm font-medium">{data.summary.total_connections}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase text-muted-foreground">Flagged</div>
            <div className="text-sm font-medium text-destructive">{data.summary.flagged_count}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase text-muted-foreground">Time Span</div>
            <div className="text-xs font-medium">
              {data.summary.first_seen ? new Date(data.summary.first_seen).toLocaleString() : "—"}
            </div>
          </div>
        </div>
      </div>

      {/* Timeline */}
      {data.timeline.length > 0 && (
        <div className="rounded-lg border border-border bg-card p-4">
          <h3 className="text-sm font-semibold mb-3">Activity Timeline</h3>
          <div className="flex items-end gap-px h-24">
            {(() => {
              const maxBytes = Math.max(...data.timeline.map((b) => b.bytes), 1);
              return data.timeline.map((bucket, i) => (
                <div
                  key={i}
                  className="flex-1 bg-primary/60 rounded-t hover:bg-primary/80 transition-colors relative group"
                  style={{ height: `${(bucket.bytes / maxBytes) * 100}%`, minHeight: bucket.bytes > 0 ? "2px" : "0" }}
                >
                  <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 hidden group-hover:block z-10 rounded bg-popover px-2 py-1 text-[10px] shadow whitespace-nowrap">
                    {formatBytes(bucket.bytes)} · {bucket.connections} conn
                    <br />
                    {bucket.bucket}
                  </div>
                </div>
              ));
            })()}
          </div>
        </div>
      )}

      {/* Connection table */}
      <div className="rounded-lg border border-border bg-card">
        <div className="border-b border-border p-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold">
            Connections ({data.summary.total_connections})
          </h3>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            Page {data.current_page} of {data.total_pages}
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={data.current_page <= 1}
              className="px-2 py-0.5 rounded hover:bg-accent disabled:opacity-30"
            >
              Prev
            </button>
            <button
              onClick={() => setPage((p) => Math.min(data.total_pages, p + 1))}
              disabled={data.current_page >= data.total_pages}
              className="px-2 py-0.5 rounded hover:bg-accent disabled:opacity-30"
            >
              Next
            </button>
          </div>
        </div>
        <div className="divide-y divide-border max-h-96 overflow-y-auto">
          {data.connections.map((conn) => (
            <div
              key={conn.id}
              className={`flex items-center gap-3 px-4 py-2 ${conn.flagged ? "bg-destructive/5" : ""}`}
            >
              <span className="text-xs font-medium w-16">{conn.protocol}</span>
              <span className="text-[10px] text-muted-foreground w-20">
                {conn.dst_port ? `:${conn.dst_port}` : "—"}
              </span>
              <span className="text-xs font-mono text-muted-foreground flex-1">
                ↑{formatBytes(conn.bytes_tx)} ↓{formatBytes(conn.bytes_rx)}
              </span>
              <span className="text-[10px] text-muted-foreground w-28 text-right">
                {new Date(conn.first_seen).toLocaleTimeString()}
              </span>
              {conn.flagged && (
                <Flag className="h-3 w-3 text-destructive" />
              )}
            </div>
          ))}
          {data.connections.length === 0 && (
            <div className="p-4 text-sm text-muted-foreground">
              No connections in this time range.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
