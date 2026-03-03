import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import {
  useNetworkTopology,
  useRefreshTopology,
  useUpdateNodePosition,
  useResetNodePosition,
} from "@/api/queries";
import type { TopologyNode, NetworkTopologyResponse } from "@/api/types";
import {
  createTopologyMapInstance,
  type TopologyMapInstance,
} from "./hooks/use-d3-topology";
import { VLAN_COLORS, VLAN_NAMES } from "@/constants/vlans";
import {
  RefreshCw,
  Search,
  X,
  Eye,
  EyeOff,
  Maximize2,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

// ─── Detail Panel ───────────────────────────────────────

function DetailPanel({
  node,
  onClose,
}: {
  node: TopologyNode;
  onClose: () => void;
}) {
  const vlanColor = node.vlan_id != null ? VLAN_COLORS[node.vlan_id] ?? "#888" : "#888";

  return (
    <div className="absolute right-0 top-0 z-20 flex h-full w-80 flex-col border-l border-border bg-card/95 backdrop-blur">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <h3
          className="truncate text-sm font-bold"
          style={{ color: vlanColor }}
        >
          {node.label}
        </h3>
        <button
          onClick={onClose}
          className="rounded p-1 text-muted-foreground hover:bg-muted"
        >
          <X className="h-4 w-4" />
        </button>
      </div>
      <div className="flex-1 overflow-y-auto p-4 text-sm">
        <dl className="space-y-2">
          <Row label="Kind" value={node.kind} />
          <Row label="Status" value={node.status} />
          {node.ip && <Row label="IP" value={node.ip} />}
          {node.mac && <Row label="MAC" value={node.mac} />}
          {node.vlan_id != null && (
            <Row
              label="VLAN"
              value={`${node.vlan_id} — ${VLAN_NAMES[node.vlan_id] ?? ""}`}
            />
          )}
          {node.device_type && <Row label="Device Type" value={node.device_type} />}
          {node.manufacturer && <Row label="Manufacturer" value={node.manufacturer} />}
          {node.switch_port && <Row label="Switch Port" value={node.switch_port} />}
          {node.parent_id && <Row label="Connected To" value={node.parent_id} />}
          <Row label="Layer" value={String(node.layer)} />
          <Row label="Infrastructure" value={node.is_infrastructure ? "Yes" : "No"} />
          {node.vlans_served.length > 0 && (
            <Row label="VLANs Served" value={node.vlans_served.join(", ")} />
          )}
          <Row
            label="Position"
            value={node.position_source === "human" ? "Pinned" : "Auto"}
          />
        </dl>
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-2">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="truncate text-right font-mono text-foreground">{value}</dd>
    </div>
  );
}

// ─── Legend ──────────────────────────────────────────────

function Legend({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  return (
    <div className="absolute bottom-12 left-3 z-20 rounded-lg border border-border bg-card/90 backdrop-blur">
      <button
        onClick={onToggle}
        className="flex w-full items-center justify-between px-3 py-1.5 text-xs font-semibold text-muted-foreground hover:text-foreground"
      >
        Legend
        {collapsed ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
      </button>
      {!collapsed && (
        <div className="border-t border-border px-3 py-2 text-[10px] text-muted-foreground">
          <div className="space-y-1">
            <div className="font-semibold text-foreground">Nodes</div>
            <div className="flex items-center gap-2">
              <span className="inline-block h-3 w-5 rounded border border-yellow-500 bg-yellow-500/15" />
              Router
            </div>
            <div className="flex items-center gap-2">
              <span className="inline-block h-3 w-4 rounded-sm border border-cyan-400 bg-cyan-400/15" />
              Switch
            </div>
            <div className="flex items-center gap-2">
              <span className="inline-block h-2.5 w-2.5 rounded-full border border-cyan-400 bg-cyan-400/15" />
              Access Point
            </div>
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 rounded-full border border-gray-400 bg-gray-400/15" />
              Endpoint
            </div>
          </div>
          <div className="mt-2 space-y-1">
            <div className="font-semibold text-foreground">Edges</div>
            <div className="flex items-center gap-2">
              <span className="inline-block h-0 w-5 border-t-2 border-cyan-400" />
              Trunk
            </div>
            <div className="flex items-center gap-2">
              <span className="inline-block h-0 w-5 border-t-2 border-yellow-500" />
              Uplink
            </div>
            <div className="flex items-center gap-2">
              <span className="inline-block h-0 w-5 border-t border-gray-500" />
              Access
            </div>
            <div className="flex items-center gap-2">
              <span className="inline-block h-0 w-5 border-t border-dashed border-gray-500" />
              Wireless
            </div>
          </div>
          <div className="mt-2 space-y-1">
            <div className="font-semibold text-foreground">Status</div>
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 rounded-full bg-green-500 shadow-[0_0_4px_#00ff88]" />
              Online
            </div>
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 rounded-full bg-red-500 shadow-[0_0_4px_#ff4444]" />
              Offline
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px]">{"\uD83D\uDCCC"}</span>
              Pinned position
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── VLAN Filter Chips ──────────────────────────────────

function VlanFilterBar({
  activeVlans,
  onToggle,
  dataVlans,
}: {
  activeVlans: Set<number> | null;
  onToggle: (vlan: number) => void;
  dataVlans: number[];
}) {
  // Only show VLANs that actually have data, sorted by ID
  const vlans = dataVlans.length > 0
    ? [...dataVlans].sort((a, b) => a - b)
    : Object.keys(VLAN_COLORS).map(Number).sort((a, b) => a - b);

  return (
    <div className="flex flex-wrap gap-1">
      {vlans.map((v) => {
        const active = activeVlans === null || activeVlans.has(v);
        return (
          <button
            key={v}
            onClick={() => onToggle(v)}
            className="rounded-full border px-2 py-0.5 text-[10px] font-mono transition-colors"
            style={{
              borderColor: VLAN_COLORS[v],
              backgroundColor: active ? VLAN_COLORS[v] + "22" : "transparent",
              color: active ? VLAN_COLORS[v] : "#555",
              opacity: active ? 1 : 0.4,
            }}
          >
            {v}
          </button>
        );
      })}
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────

export function TopologyPage() {
  const svgRef = useRef<SVGSVGElement>(null);
  const mapRef = useRef<TopologyMapInstance | null>(null);
  const prevDataRef = useRef<NetworkTopologyResponse | null>(null);
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [showEndpoints, setShowEndpoints] = useState(true);
  const [legendCollapsed, setLegendCollapsed] = useState(true);
  const [vlanFilter, setVlanFilter] = useState<Set<number> | null>(null);

  const topology = useNetworkTopology();
  const refreshMutation = useRefreshTopology();
  const positionMutation = useUpdateNodePosition();
  const resetMutation = useResetNodePosition();

  // Derive VLANs actually present in topology data (for filter pills)
  const dataVlans = useMemo(() => {
    if (!topology.data) return [];
    const vlans = new Set<number>();
    topology.data.vlan_groups.forEach((g) => vlans.add(g.vlan_id));
    return Array.from(vlans);
  }, [topology.data]);

  // ── Initialize D3 instance ──
  useEffect(() => {
    if (!svgRef.current) return;

    const instance = createTopologyMapInstance(svgRef.current, {
      onNodeClick: (node) => setSelectedNode(node),
      onDragEnd: (nodeId, x, y) => {
        positionMutation.mutate({ nodeId, x, y });
      },
      onUnpin: (nodeId) => {
        mapRef.current?.clearDraggedPosition(nodeId);
        resetMutation.mutate(nodeId);
      },
    });
    mapRef.current = instance;

    return () => {
      instance.destroy();
      mapRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Render when data changes ──
  useEffect(() => {
    if (!mapRef.current || !topology.data) return;
    // Avoid re-render if data is the same object reference
    if (prevDataRef.current === topology.data) return;
    prevDataRef.current = topology.data;
    mapRef.current.render(topology.data);
  }, [topology.data]);

  // ── Search ──
  useEffect(() => {
    if (!mapRef.current) return;
    mapRef.current.search(searchTerm);
  }, [searchTerm]);

  // ── Endpoint toggle ──
  useEffect(() => {
    mapRef.current?.setEndpointsVisible(showEndpoints);
  }, [showEndpoints]);

  // ── VLAN filter ──
  useEffect(() => {
    mapRef.current?.setVlanFilter(vlanFilter);
  }, [vlanFilter]);

  const handleVlanToggle = useCallback((vlan: number) => {
    setVlanFilter((prev) => {
      if (prev === null) {
        // All are active, toggling one off → show all except this one
        const next = new Set(dataVlans.filter((v) => v !== vlan));
        return next;
      }
      const next = new Set(prev);
      if (next.has(vlan)) {
        next.delete(vlan);
        // If all are removed, reset to null (show all)
        if (next.size === 0) return null;
      } else {
        next.add(vlan);
        // If all are added back, reset to null
        if (next.size === dataVlans.length) return null;
      }
      return next;
    });
  }, [dataVlans]);

  const handleResetView = useCallback(() => {
    mapRef.current?.resetView();
  }, []);

  const handleClearSelection = useCallback(() => {
    setSelectedNode(null);
    mapRef.current?.clearSelection();
  }, []);

  const data = topology.data;
  const ago = data?.computed_at
    ? formatAgo(data.computed_at)
    : "—";

  return (
    <div className="relative flex h-full flex-col overflow-hidden bg-background">
      {/* Top Bar */}
      <div className="z-10 flex flex-wrap items-center gap-2 border-b border-border bg-card px-3 py-2">
        {/* Search */}
        <div className="relative">
          <Search className="absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search nodes..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="h-7 w-48 rounded-md border border-border bg-background pl-7 pr-7 text-xs text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none"
          />
          {searchTerm && (
            <button
              onClick={() => setSearchTerm("")}
              className="absolute right-1.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              <X className="h-3 w-3" />
            </button>
          )}
        </div>

        {/* VLAN chips */}
        <VlanFilterBar activeVlans={vlanFilter} onToggle={handleVlanToggle} dataVlans={dataVlans} />

        <div className="flex-1" />

        {/* Endpoints toggle */}
        <button
          onClick={() => setShowEndpoints((prev) => !prev)}
          className="flex items-center gap-1.5 rounded-md border border-border px-2 py-1 text-xs text-muted-foreground hover:bg-muted hover:text-foreground"
          title={showEndpoints ? "Hide endpoints" : "Show endpoints"}
        >
          {showEndpoints ? <Eye className="h-3.5 w-3.5" /> : <EyeOff className="h-3.5 w-3.5" />}
          Endpoints
        </button>

        {/* Reset view */}
        <button
          onClick={handleResetView}
          className="rounded-md border border-border p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
          title="Reset zoom"
        >
          <Maximize2 className="h-3.5 w-3.5" />
        </button>

        {/* Refresh */}
        <button
          onClick={() => refreshMutation.mutate()}
          disabled={refreshMutation.isPending}
          className="flex items-center gap-1.5 rounded-md border border-border px-2 py-1 text-xs text-muted-foreground hover:bg-muted hover:text-foreground disabled:opacity-50"
          title="Force recompute topology"
        >
          <RefreshCw
            className={`h-3.5 w-3.5 ${refreshMutation.isPending ? "animate-spin" : ""}`}
          />
          Refresh
        </button>
      </div>

      {/* Canvas */}
      <div className="relative flex-1">
        <svg
          ref={svgRef}
          className="h-full w-full"
          style={{ background: "#0d0d24" }}
        />

        {/* Detail Panel */}
        {selectedNode && (
          <DetailPanel node={selectedNode} onClose={handleClearSelection} />
        )}

        {/* Legend */}
        <Legend
          collapsed={legendCollapsed}
          onToggle={() => setLegendCollapsed((p) => !p)}
        />
      </div>

      {/* Status Bar */}
      <div className="z-10 flex items-center gap-4 border-t border-border bg-card px-3 py-1 text-[10px] text-muted-foreground">
        {data ? (
          <>
            <span>{data.node_count} devices</span>
            <span className="text-border">|</span>
            <span>{data.infrastructure_count} infrastructure</span>
            <span className="text-border">|</span>
            <span>{data.endpoint_count} endpoints</span>
            <span className="text-border">|</span>
            <span>{data.edge_count} connections</span>
            <span className="flex-1" />
            <span>{"\u21BB"} {ago}</span>
          </>
        ) : topology.isLoading ? (
          <span>Loading topology...</span>
        ) : (
          <span>No topology data available</span>
        )}
      </div>
    </div>
  );
}

function formatAgo(epochSec: number): string {
  const diffMs = Date.now() - epochSec * 1000;
  if (diffMs < 0) return "just now";
  const secs = Math.floor(diffMs / 1000);
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  return `${hrs}h ago`;
}

export default TopologyPage;
