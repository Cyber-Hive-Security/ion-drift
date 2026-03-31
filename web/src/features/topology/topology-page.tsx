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
  useResetLayout,
} from "@/api/queries";
import type { TopologyNode, NetworkTopologyResponse, NetworkDevice } from "@/api/types";
import {
  createTopologyMapInstance,
  type TopologyMapInstance,
} from "./hooks/use-d3-topology";
import { useVlanLookup } from "@/hooks/use-vlan-lookup";
import "../topology/topology-map.css";
import { Link } from "@tanstack/react-router";
import {
  RefreshCw,
  Search,
  X,
  Eye,
  EyeOff,
  Maximize2,
  Grid3x3,
  ChevronDown,
  ChevronUp,
  Microscope,
  Activity,
  History,
  RotateCcw,
} from "lucide-react";

// ─── Detail Panel ───────────────────────────────────────

function DetailPanel({
  node,
  onClose,
}: {
  node: TopologyNode;
  onClose: () => void;
}) {
  const vlan = useVlanLookup();
  const vlanColor = node.vlan_id != null ? vlan.color(node.vlan_id) : "#888";

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
              value={`${node.vlan_id} — ${vlan.name(node.vlan_id)}`}
            />
          )}
          {node.device_type && <Row label="Device Type" value={node.device_type} />}
          {node.manufacturer && <Row label="Manufacturer" value={node.manufacturer} />}
          {node.baseline_status && <Row label="Baseline" value={node.baseline_status.charAt(0).toUpperCase() + node.baseline_status.slice(1)} />}
          {node.binding_source && node.binding_source !== "unknown" && (
            <Row label="Binding" value={`${node.binding_source}${node.binding_tier ? ` (${node.binding_tier})` : ""}`} />
          )}
          {node.attachment_state && node.attachment_state !== "unknown" && (
            <Row label="Inference" value={node.attachment_state.charAt(0).toUpperCase() + node.attachment_state.slice(1)} />
          )}
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

// Device type icon paths (same as ICON_PATHS in use-d3-topology.ts — duplicated for legend rendering)
const LEGEND_ICON_PATHS: Record<string, string> = {
  router: "M12,2C6.48,2,2,6.48,2,12s4.48,10,10,10,10-4.48,10-10S17.52,2,12,2Zm-1,17.93c-3.94-.49-7-3.85-7-7.93,0-.62.08-1.22.21-1.79L9,15v1a2,2,0,0,0,2,2Zm6.9-2.54A2,2,0,0,0,17,16H16V13a1,1,0,0,0-1-1H9V10h2a1,1,0,0,0,1-1V7h2a2,2,0,0,0,2-2v-.41A8,8,0,0,1,20,12,7.88,7.88,0,0,1,18.9,17.39Z",
  switch: "M20,3H4A2,2,0,0,0,2,5V19a2,2,0,0,0,2,2H20a2,2,0,0,0,2-2V5A2,2,0,0,0,20,3ZM10,17H6V15h4Zm0-4H6V11h4Zm0-4H6V7h4Zm8,8H12V15h6Zm0-4H12V11h6Zm0-4H12V7h6Z",
  ap: "M12,21L15.6,16.2C14.6,15.45,13.35,15,12,15C10.65,15,9.4,15.45,8.4,16.2L12,21M12,3C7.95,3,4.21,4.34,1.2,6.6L3,9C5.5,7.12,8.62,6,12,6C15.38,6,18.5,7.12,21,9L22.8,6.6C19.79,4.34,16.05,3,12,3M12,9C9.3,9,6.81,9.89,4.8,11.4L6.6,13.8C8.1,12.67,9.97,12,12,12C14.03,12,15.9,12.67,17.4,13.8L19.2,11.4C17.19,9.89,14.7,9,12,9Z",
  server: "M4,1H20A1,1,0,0,1,21,2V22A1,1,0,0,1,20,23H4A1,1,0,0,1,3,22V2A1,1,0,0,1,4,1M5,3V21H19V3H5M12,17A1.5,1.5,0,1,1,13.5,15.5,1.5,1.5,0,0,1,12,17M8,7H16V13H8V7Z",
  workstation: "M21,16H3V4H21M21,2H3C1.89,2,1,2.89,1,4V16A2,2,0,0,0,3,18H10V20H8V22H16V20H14V18H21A2,2,0,0,0,23,16V4C23,2.89,22.1,2,21,2Z",
  camera: "M9,3V4H5V7H4V3H9M15,3H20V7H19V4H15V3M4,17V21H9V20H5V17H4M19,17V20H15V21H20V17H19M7,7H17V17H7V7M9,9V15H15V9H9Z",
  phone: "M6.62,10.79C8.06,13.62 10.38,15.94 13.21,17.38L15.41,15.18C15.69,14.9 16.08,14.82 16.43,14.93C17.55,15.3 18.75,15.5 20,15.5A1,1 0,0,1,21,16.5V20A1,1,0,0,1,20,21A17,17,0,0,1,3,4A1,1,0,0,1,4,3H7.5A1,1,0,0,1,8.5,4C8.5,5.25,8.7,6.45,9.07,7.57C9.18,7.92,9.1,8.31,8.82,8.59L6.62,10.79Z",
  iot: "M9,3V4H5V7H4V3H9M15,3H20V7H19V4H15V3M4,17V21H9V20H5V17H4M19,17V20H15V21H20V17H19M7,7H17V17H7V7M9,9V15H15V9H9Z",
  media: "M8,5.14V19.14L19,12.14L8,5.14Z",
  printer: "M18,3H6V7H18M19,12A1,1,0,0,1,18,11A1,1,0,0,1,19,10A1,1,0,0,1,20,11A1,1,0,0,1,19,12M16,19H8V14H16M19,8H5A3,3,0,0,0,2,11V17H6V21H18V17H22V11A3,3,0,0,0,19,8Z",
  unknown: "M11,18H13V16H11V18M12,2A10,10,0,0,0,2,12A10,10,0,0,0,12,22A10,10,0,0,0,22,12A10,10,0,0,0,12,2M12,20C7.59,20,4,16.41,4,12C4,7.59,7.59,4,12,4C16.41,4,20,7.59,20,12C20,16.41,16.41,20,12,20M12,6A4,4,0,0,0,8,10H10A2,2,0,0,1,12,8A2,2,0,0,1,14,10C14,12,11,11.75,11,14H13C13,12.5,16,12.25,16,10A4,4,0,0,0,12,6Z",
};

const LEGEND_DEVICE_TYPES = [
  { icon: "router", label: "Router", color: "#2FA4FF" },
  { icon: "switch", label: "Switch", color: "#00E5FF" },
  { icon: "ap", label: "Access Point", color: "#00E5FF" },
  { icon: "server", label: "Server", color: "#00E5FF" },
  { icon: "workstation", label: "Workstation", color: "#E6EDF3" },
  { icon: "camera", label: "Camera", color: "#E6EDF3" },
  { icon: "phone", label: "Phone", color: "#E6EDF3" },
  { icon: "iot", label: "IoT / Smart Home", color: "#E6EDF3" },
  { icon: "media", label: "Media Player", color: "#E6EDF3" },
  { icon: "printer", label: "Printer", color: "#E6EDF3" },
  { icon: "unknown", label: "Unknown", color: "#E6EDF3" },
] as const;

const LEGEND_SPEEDS = [
  { width: 3.5, color: "#2FA4FF", label: "10 Gbps" },
  { width: 2.5, color: "#FF4FD8", label: "5 Gbps" },
  { width: 2.0, color: "#7A5CFF", label: "2.5 Gbps" },
  { width: 1.2, color: "#00E5FF", label: "1 Gbps" },
] as const;

const LEGEND_EDGES = [
  { color: "#00E5FF", width: 2, dash: false, label: "Trunk" },
  { color: "#2FA4FF", width: 2, dash: false, label: "Uplink" },
  { color: "#8A929D", width: 1, dash: false, label: "Access" },
  { color: "#8A929D", width: 1, dash: true, label: "Wireless" },
] as const;

function LegendSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mt-2 first:mt-0">
      <div
        className="mb-1 text-[9px] font-bold tracking-[2px]"
        style={{ color: "#2FA4FF", fontFamily: "'Orbitron', monospace" }}
      >
        {title}
      </div>
      <div className="space-y-0.5">{children}</div>
    </div>
  );
}

function Legend({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  const vlan = useVlanLookup();
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
  }, []);

  const handlePointerMove = useCallback((e: React.PointerEvent) => {
    const d = dragRef.current;
    const el = containerRef.current;
    if (!d || !el) return;
    const dx = e.clientX - d.startX;
    const dy = e.clientY - d.startY;
    if (!didDragRef.current && Math.abs(dx) <= 3 && Math.abs(dy) <= 3) return;
    if (!didDragRef.current) {
      didDragRef.current = true;
      el.setPointerCapture(e.pointerId);
    }
    el.style.left = `${d.origLeft + dx}px`;
    el.style.top = `${d.origTop + dy}px`;
  }, []);

  const handlePointerUp = useCallback((e: React.PointerEvent) => {
    if (!dragRef.current) return;
    if (didDragRef.current) {
      containerRef.current?.releasePointerCapture(e.pointerId);
    }
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
        className="flex w-full cursor-pointer items-center justify-between gap-2 px-3 py-1.5 text-xs font-semibold select-none hover:text-foreground active:cursor-grabbing"
        style={{ color: "#2FA4FF", fontFamily: "'Orbitron', monospace", fontSize: "10px", letterSpacing: "2px" }}
      >
        LEGEND
        {collapsed ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
      </div>
      {!collapsed && (
        <div className="border-t px-3 py-2 text-[10px]" style={{ borderColor: "rgba(42, 50, 61, 0.5)", color: "#9AA6B2" }}>
          {/* Device Types */}
          <LegendSection title="DEVICE TYPES">
            <div className="mb-1 text-[9px] italic" style={{ color: "#666" }}>
              Color = VLAN &middot; Icon = type
            </div>
            {LEGEND_DEVICE_TYPES.map((n) => (
              <div key={n.label} className="flex items-center gap-2">
                <svg width="16" height="16" viewBox="0 0 24 24" className="flex-shrink-0">
                  <path d={LEGEND_ICON_PATHS[n.icon]} fill={n.color} opacity={0.85} />
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
            {Object.entries(vlan.colors).map(([vid, color]) => (
              <div key={vid} className="flex items-center gap-2">
                <span
                  className="inline-block h-2.5 w-2.5 flex-shrink-0 rounded-sm"
                  style={{ background: color, opacity: 0.6 }}
                />
                <span>
                  <span style={{ color: "#8A929D" }}>{vid}:</span> {vlan.name(Number(vid))}
                </span>
              </div>
            ))}
          </LegendSection>

          {/* Status */}
          <LegendSection title="STATUS">
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 flex-shrink-0 rounded-full bg-success shadow-[0_0_4px_#21D07A]" />
              Online
            </div>
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 flex-shrink-0 rounded-full bg-destructive shadow-[0_0_4px_#FF4D4F]" />
              Offline
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px]">{"\uD83D\uDCCC"}</span>
              Pinned
            </div>
          </LegendSection>

          {/* Baseline */}
          <LegendSection title="BASELINE">
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 flex-shrink-0 rounded-full" style={{ background: "#21D07A" }} />
              Baselined
            </div>
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 flex-shrink-0 rounded-full" style={{ background: "#2FA4FF" }} />
              Learning
            </div>
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 flex-shrink-0 rounded-full" style={{ background: "#FFAA00" }} />
              Sparse
            </div>
          </LegendSection>

          {/* Binding Source */}
          <LegendSection title="BINDING">
            <div className="flex items-center gap-2">
              <span className="inline-block h-0 w-4 flex-shrink-0" style={{ borderTop: "1.5px solid #9AA6B2" }} />
              Authoritative
            </div>
            <div className="flex items-center gap-2">
              <span className="inline-block h-0 w-4 flex-shrink-0" style={{ borderTop: "1.5px dashed #9AA6B2" }} />
              Observed
            </div>
            <div className="flex items-center gap-2">
              <span className="inline-block h-0 w-4 flex-shrink-0" style={{ borderTop: "1.5px dotted #9AA6B2" }} />
              Inferred
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
                    color: "#8A929D",
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
  onSnapNode,
  onSnapVlan,
}: {
  menu: ContextMenuState;
  devices: NetworkDevice[];
  onClose: () => void;
  onAlias: (matchType: "mac" | "identity", matchValue: string, targetDeviceId: string) => void;
  onHide: (matchType: "mac" | "identity", matchValue: string) => void;
  onSetDisposition: (mac: string, disposition: "ignored" | "flagged") => void;
  onSelect: (node: TopologyNode) => void;
  onSnapNode: (nodeId: string) => void;
  onSnapVlan: (vlanId: number) => void;
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
                <span className="text-warning">⚠</span>
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

        {/* Investigation links */}
        {node.mac && (
          <div className="border-t border-border mt-0.5 pt-0.5">
            <Link
              to="/sankey"
              search={{ mac: node.mac }}
              onClick={onClose}
              className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-foreground hover:bg-muted"
            >
              <Microscope className="h-3 w-3 text-muted-foreground" />
              Investigate traffic
            </Link>
            <Link
              to="/behavior"
              onClick={onClose}
              className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-foreground hover:bg-muted"
            >
              <Activity className="h-3 w-3 text-muted-foreground" />
              View behavior
            </Link>
            <Link
              to="/history"
              onClick={onClose}
              className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-foreground hover:bg-muted"
            >
              <History className="h-3 w-3 text-muted-foreground" />
              Connection history
            </Link>
          </div>
        )}

        {/* Snap options — always available */}
        <div className="border-t border-border mt-0.5 pt-0.5">
          <button
            onClick={() => {
              onSnapNode(node.id);
              onClose();
            }}
            className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-foreground hover:bg-muted"
          >
            <Grid3x3 className="h-3 w-3 text-muted-foreground" />
            Snap to grid
          </button>
          {node.vlan_id != null && (
            <button
              onClick={() => {
                onSnapVlan(node.vlan_id!);
                onClose();
              }}
              className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-foreground hover:bg-muted"
            >
              <Grid3x3 className="h-3 w-3 text-muted-foreground" />
              Snap VLAN {node.vlan_id} to grid
            </button>
          )}
        </div>
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
  const vlan = useVlanLookup();
  // Only show VLANs that actually have data, sorted by ID
  const vlans = dataVlans.length > 0
    ? [...dataVlans].sort((a, b) => a - b)
    : Object.keys(vlan.colors).map(Number).sort((a, b) => a - b);

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
              borderColor: vlan.color(v),
              backgroundColor: active ? vlan.color(v) + "22" : "transparent",
              color: active ? vlan.color(v) : "#555",
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
  const vlan = useVlanLookup();
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
  const resetLayoutMutation = useResetLayout();
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

    const instance = createTopologyMapInstance(svgRef.current, vlan.colors, {
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

  const handleSnapToGrid = useCallback(() => {
    const positions = mapRef.current?.snapToGrid();
    if (positions && positions.length > 0) {
      batchPositionMutation.mutate(positions);
    }
  }, [batchPositionMutation]);

  const handleSnapVlanToGrid = useCallback((vlanId: number) => {
    const positions = mapRef.current?.snapVlanToGrid(vlanId);
    if (positions && positions.length > 0) {
      batchPositionMutation.mutate(positions);
    }
  }, [batchPositionMutation]);

  const handleSnapNodeToGrid = useCallback((nodeId: string) => {
    const positions = mapRef.current?.snapNodeToGrid(nodeId);
    if (positions && positions.length > 0) {
      batchPositionMutation.mutate(positions);
    }
  }, [batchPositionMutation]);

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

        {/* Snap to grid */}
        <button
          onClick={handleSnapToGrid}
          className="rounded-md border border-border p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
          title="Snap all nodes to grid"
        >
          <Grid3x3 className="h-3.5 w-3.5" />
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
        <button
          onClick={() => {
            if (window.confirm("Reset all node and sector positions to auto-layout? This cannot be undone.")) {
              resetLayoutMutation.mutate();
            }
          }}
          disabled={resetLayoutMutation.isPending}
          className="flex items-center gap-1.5 rounded-md border border-border px-2 py-1 text-xs text-muted-foreground hover:bg-muted hover:text-foreground disabled:opacity-50"
          title="Clear all pinned positions and recompute layout"
        >
          <RotateCcw
            className={`h-3.5 w-3.5 ${resetLayoutMutation.isPending ? "animate-spin" : ""}`}
          />
          Reset Layout
        </button>
      </div>

      {/* Canvas */}
      <div className="relative flex-1">
        <svg
          ref={svgRef}
          className="topology-root h-full w-full"
          style={{ background: "#24272C" }}
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
            onSnapNode={handleSnapNodeToGrid}
            onSnapVlan={handleSnapVlanToGrid}
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
