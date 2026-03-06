import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import {
  useNetworkTopology,
  useRefreshTopology,
  useUpdateNodePosition,
  useResetNodePosition,
  useUpdateSectorPosition,
  useResetSectorPosition,
  useBatchUpdateNodePositions,
  useDevices,
  useCreateNeighborAlias,
  useSetDisposition,
} from "@/api/queries";
import type { TopologyNode, NetworkTopologyResponse, NetworkDevice } from "@/api/types";
import {
  createTopologyMapInstance,
  type TopologyMapInstance,
} from "./hooks/use-d3-topology";
import { VLAN_COLORS, VLAN_NAMES } from "@/constants/vlans";
import "../topology/topology-map.css";
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

const LEGEND_NODES = [
  { color: "#ffd700", label: "Router" },
  { color: "#00e5ff", label: "Switch" },
  { color: "#00c853", label: "Access Point" },
  { color: "#90a4ae", label: "Endpoint" },
] as const;

const LEGEND_SPEEDS = [
  { width: 3.5, color: "#ffd700", label: "10 Gbps" },
  { width: 2.5, color: "#ff8c00", label: "5 Gbps" },
  { width: 2.0, color: "#00e5ff", label: "2.5 Gbps" },
  { width: 1.2, color: "#00f0ff", label: "1 Gbps" },
] as const;

const LEGEND_EDGES = [
  { color: "#00e5ff", width: 2, dash: false, label: "Trunk" },
  { color: "#ffd700", width: 2, dash: false, label: "Uplink" },
  { color: "#666", width: 1, dash: false, label: "Access" },
  { color: "#666", width: 1, dash: true, label: "Wireless" },
] as const;

function LegendSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mt-2 first:mt-0">
      <div
        className="mb-1 text-[9px] font-bold tracking-[2px]"
        style={{ color: "#ffd700", fontFamily: "'Orbitron', monospace" }}
      >
        {title}
      </div>
      <div className="space-y-0.5">{children}</div>
    </div>
  );
}

function Legend({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<{ startX: number; startY: number; origLeft: number; origTop: number } | null>(null);
  const didDragRef = useRef(false);

  const handlePointerDown = useCallback((e: React.PointerEvent) => {
    const el = containerRef.current;
    if (!el) return;
    didDragRef.current = false;
    dragRef.current = {
      startX: e.clientX,
      startY: e.clientY,
      origLeft: el.offsetLeft,
      origTop: el.offsetTop,
    };
    el.setPointerCapture(e.pointerId);
  }, []);

  const handlePointerMove = useCallback((e: React.PointerEvent) => {
    const d = dragRef.current;
    const el = containerRef.current;
    if (!d || !el) return;
    const dx = e.clientX - d.startX;
    const dy = e.clientY - d.startY;
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) didDragRef.current = true;
    el.style.left = `${d.origLeft + dx}px`;
    el.style.top = `${d.origTop + dy}px`;
  }, []);

  const handlePointerUp = useCallback((e: React.PointerEvent) => {
    if (!dragRef.current) return;
    containerRef.current?.releasePointerCapture(e.pointerId);
    dragRef.current = null;
  }, []);

  const handleToggleClick = useCallback(() => {
    if (!didDragRef.current) onToggle();
  }, [onToggle]);

  return (
    <div
      ref={containerRef}
      className={`absolute z-20 overflow-y-auto rounded-lg border backdrop-blur ${collapsed ? "w-auto" : "w-[200px]"}`}
      style={{
        bottom: 48,
        left: 12,
        background: "rgba(8, 16, 32, 0.92)",
        borderColor: collapsed ? "rgba(255, 215, 0, 0.3)" : "rgba(0, 240, 255, 0.12)",
        maxHeight: "calc(100% - 80px)",
      }}
    >
      <div
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onClick={handleToggleClick}
        className="flex w-full cursor-grab items-center justify-between gap-2 px-3 py-1.5 text-xs font-semibold select-none hover:text-foreground active:cursor-grabbing"
        style={{ color: "#ffd700", fontFamily: "'Orbitron', monospace", fontSize: "10px", letterSpacing: "2px" }}
      >
        LEGEND
        {collapsed ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
      </div>
      {!collapsed && (
        <div className="border-t px-3 py-2 text-[10px]" style={{ borderColor: "rgba(0, 240, 255, 0.08)", color: "#c0d0e0" }}>
          {/* Nodes */}
          <LegendSection title="NODES">
            {LEGEND_NODES.map((n) => (
              <div key={n.label} className="flex items-center gap-2">
                <svg width="14" height="12" viewBox="-7 -6 14 12">
                  <polygon
                    points="5.2,3 0,6 -5.2,3 -5.2,-3 0,-6 5.2,-3"
                    fill={n.color + "20"}
                    stroke={n.color}
                    strokeWidth="1"
                  />
                </svg>
                {n.label}
              </div>
            ))}
          </LegendSection>

          {/* Speed Tiers */}
          <LegendSection title="CONNECTIONS">
            {LEGEND_SPEEDS.map((s) => (
              <div key={s.label} className="flex items-center gap-2">
                <span
                  className="inline-block h-0 w-5 flex-shrink-0"
                  style={{ borderTop: `${s.width}px solid ${s.color}` }}
                />
                {s.label}
              </div>
            ))}
          </LegendSection>

          {/* Edge Types */}
          <LegendSection title="EDGE TYPES">
            {LEGEND_EDGES.map((e) => (
              <div key={e.label} className="flex items-center gap-2">
                <span
                  className="inline-block h-0 w-5 flex-shrink-0"
                  style={{
                    borderTop: `${e.width}px ${e.dash ? "dashed" : "solid"} ${e.color}`,
                  }}
                />
                {e.label}
              </div>
            ))}
          </LegendSection>

          {/* VLAN Sectors */}
          <LegendSection title="VLAN SECTORS">
            {Object.entries(VLAN_COLORS).map(([vid, color]) => (
              <div key={vid} className="flex items-center gap-2">
                <span
                  className="inline-block h-2.5 w-2.5 flex-shrink-0 rounded-sm"
                  style={{ background: color, opacity: 0.6 }}
                />
                <span>
                  <span style={{ color: "#5a7080" }}>{vid}:</span> {VLAN_NAMES[Number(vid)] ?? ""}
                </span>
              </div>
            ))}
          </LegendSection>

          {/* Status */}
          <LegendSection title="STATUS">
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 flex-shrink-0 rounded-full bg-green-500 shadow-[0_0_4px_#00ff88]" />
              Online
            </div>
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 flex-shrink-0 rounded-full bg-red-500 shadow-[0_0_4px_#ff4444]" />
              Offline
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px]">{"\uD83D\uDCCC"}</span>
              Pinned
            </div>
          </LegendSection>

          {/* Controls */}
          <LegendSection title="CONTROLS">
            {([
              ["Drag", "Move nodes / sectors"],
              ["Scroll", "Zoom in / out"],
              ["Click", "Select node"],
              ["Right-click", "Context menu"],
            ] as const).map(([key, desc]) => (
              <div key={key} className="flex items-center gap-2">
                <kbd
                  className="inline-block min-w-[50px] rounded px-1 py-px text-center text-[9px]"
                  style={{
                    fontFamily: "'Share Tech Mono', monospace",
                    color: "#5a7080",
                    background: "rgba(255,255,255,0.04)",
                    border: "1px solid rgba(255,255,255,0.08)",
                  }}
                >
                  {key}
                </kbd>
                <span>{desc}</span>
              </div>
            ))}
          </LegendSection>
        </div>
      )}
    </div>
  );
}

// ─── Node Context Menu ───────────────────────────────────

interface ContextMenuState {
  node: TopologyNode;
  x: number;
  y: number;
}

function NodeContextMenu({
  menu,
  devices,
  onClose,
  onAlias,
  onHide,
  onSetDisposition,
  onSelect,
}: {
  menu: ContextMenuState;
  devices: NetworkDevice[];
  onClose: () => void;
  onAlias: (matchType: "mac" | "identity", matchValue: string, targetDeviceId: string) => void;
  onHide: (matchType: "mac" | "identity", matchValue: string) => void;
  onSetDisposition: (mac: string, disposition: "ignored" | "flagged") => void;
  onSelect: (node: TopologyNode) => void;
}) {
  const { node, x, y } = menu;
  const [showDevicePicker, setShowDevicePicker] = useState(false);
  const [filter, setFilter] = useState("");
  const menuRef = useRef<HTMLDivElement>(null);

  // Close on Escape
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [onClose]);

  // Clamp position to viewport
  const style: React.CSSProperties = {
    position: "fixed",
    left: Math.min(x, window.innerWidth - 260),
    top: Math.min(y, window.innerHeight - 300),
    zIndex: 50,
  };

  const matchType: "mac" | "identity" = node.mac ? "mac" : "identity";
  const matchValue = node.mac ?? node.id;

  const isUnregisteredInfra = node.is_infrastructure && node.confidence < 1.0;
  const isEndpoint = !node.is_infrastructure;
  const isRegisteredInfra = node.is_infrastructure && node.confidence >= 1.0;

  const filteredDevices = devices.filter(
    (d) =>
      d.name.toLowerCase().includes(filter.toLowerCase()) ||
      d.id.toLowerCase().includes(filter.toLowerCase()),
  );

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40"
        onClick={onClose}
        onContextMenu={(e) => {
          e.preventDefault();
          onClose();
        }}
      />

      {/* Menu */}
      <div
        ref={menuRef}
        style={style}
        className="min-w-[200px] rounded-lg border border-border bg-card/95 py-1 shadow-xl backdrop-blur"
      >
        {/* Header */}
        <div className="border-b border-border px-3 py-1.5 text-xs font-semibold text-muted-foreground truncate">
          {node.label}
        </div>

        {isUnregisteredInfra && !showDevicePicker && (
          <>
            <button
              onClick={() => setShowDevicePicker(true)}
              className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-foreground hover:bg-muted"
            >
              <span className="text-muted-foreground">→</span>
              This is...
            </button>
            <button
              onClick={() => {
                onHide(matchType, matchValue);
                onClose();
              }}
              className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-foreground hover:bg-muted"
            >
              <span className="text-muted-foreground">×</span>
              Hide from topology
            </button>
          </>
        )}

        {isUnregisteredInfra && showDevicePicker && (
          <div className="p-2">
            <input
              type="text"
              placeholder="Filter devices..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="mb-1 w-full rounded border border-border bg-background px-2 py-1 text-xs text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none"
              autoFocus
            />
            <div className="max-h-40 overflow-y-auto">
              {filteredDevices.map((d) => (
                <button
                  key={d.id}
                  onClick={() => {
                    onAlias(matchType, matchValue, d.id);
                    onClose();
                  }}
                  className="flex w-full items-center gap-2 rounded px-2 py-1 text-left text-xs text-foreground hover:bg-muted"
                >
                  <span className="font-mono text-muted-foreground">{d.id}</span>
                  <span className="truncate">{d.name}</span>
                </button>
              ))}
              {filteredDevices.length === 0 && (
                <div className="px-2 py-1 text-xs text-muted-foreground">No devices found</div>
              )}
            </div>
          </div>
        )}

        {isEndpoint && (
          <>
            {node.mac && (
              <button
                onClick={() => {
                  onSetDisposition(node.mac!, "ignored");
                  onClose();
                }}
                className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-foreground hover:bg-muted"
              >
                <span className="text-muted-foreground">×</span>
                Hide from topology
              </button>
            )}
            {node.mac && (
              <button
                onClick={() => {
                  onSetDisposition(node.mac!, "flagged");
                  onClose();
                }}
                className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-foreground hover:bg-muted"
              >
                <span className="text-yellow-500">⚠</span>
                Flag device
              </button>
            )}
          </>
        )}

        {isRegisteredInfra && (
          <>
            <button
              onClick={() => {
                onSelect(node);
                onClose();
              }}
              className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-foreground hover:bg-muted"
            >
              <span className="text-muted-foreground">ℹ</span>
              View device details
            </button>
          </>
        )}
      </div>
    </>
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
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [showEndpoints, setShowEndpoints] = useState(true);
  const [legendCollapsed, setLegendCollapsed] = useState(false);
  const [vlanFilter, setVlanFilter] = useState<Set<number> | null>(null);

  const topology = useNetworkTopology();
  const refreshMutation = useRefreshTopology();
  const positionMutation = useUpdateNodePosition();
  const resetMutation = useResetNodePosition();
  const sectorPositionMutation = useUpdateSectorPosition();
  const batchPositionMutation = useBatchUpdateNodePositions();
  const sectorResetMutation = useResetSectorPosition();
  const devicesList = useDevices();
  const createAliasMutation = useCreateNeighborAlias();
  const dispositionMutation = useSetDisposition();

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
      onContextMenu: (node, screenX, screenY) => {
        setContextMenu({ node, x: screenX, y: screenY });
      },
      onDragEnd: (nodeId, x, y) => {
        positionMutation.mutate({ nodeId, x, y });
      },
      onUnpin: (nodeId) => {
        mapRef.current?.clearDraggedPosition(nodeId);
        resetMutation.mutate(nodeId);
      },
      onSectorDragEnd: (vlanId, x, y, width, height) => {
        sectorPositionMutation.mutate({ vlanId, x, y, width, height });
      },
      onSectorNodesDrag: (positions) => {
        batchPositionMutation.mutate(positions);
      },
      onSectorReset: (vlanId) => {
        sectorResetMutation.mutate(vlanId);
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
          className="topology-root h-full w-full"
          style={{ background: "#0d0d24" }}
        />

        {/* Detail Panel */}
        {selectedNode && (
          <DetailPanel node={selectedNode} onClose={handleClearSelection} />
        )}

        {/* Context Menu */}
        {contextMenu && (
          <NodeContextMenu
            menu={contextMenu}
            devices={devicesList.data ?? []}
            onClose={() => setContextMenu(null)}
            onAlias={async (matchType, matchValue, targetDeviceId) => {
              await createAliasMutation.mutateAsync({
                match_type: matchType,
                match_value: matchValue,
                action: "alias",
                target_device_id: targetDeviceId,
              });
              refreshMutation.mutate();
            }}
            onHide={async (matchType, matchValue) => {
              await createAliasMutation.mutateAsync({
                match_type: matchType,
                match_value: matchValue,
                action: "hide",
              });
              refreshMutation.mutate();
            }}
            onSetDisposition={async (mac, disposition) => {
              await dispositionMutation.mutateAsync({ mac, disposition });
              refreshMutation.mutate();
            }}
            onSelect={(node) => setSelectedNode(node)}
          />
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
