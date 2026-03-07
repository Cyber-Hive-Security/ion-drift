// ============================================================
//  D3 Rendering Engine for Auto-Generated Network Topology
//  D3 owns the SVG canvas; React owns the UI chrome.
//  Enhanced: hexagonal nodes, icons, stars, particles, speed tiers
// ============================================================

import * as d3 from "d3";
import type {
  TopologyNode,
  TopologyEdge,
  TopologyVlanGroup,
  NetworkTopologyResponse,
} from "@/api/types";
import { VLAN_COLORS } from "@/constants/vlans";
import { escHtml } from "@/lib/utils";

// ─── Constants ──────────────────────────────────────────

const MAP_WIDTH = 4000;
const MAP_HEIGHT = 3000;
const HEX_RADIUS = 22;
const HEX_RADIUS_SM = 12; // Endpoints
const INFRA_LABEL_MAX = 24;
const ENDPOINT_LABEL_MAX = 16;
const STAR_COUNT = 200;

// ─── Icon Paths (24x24 viewBox) ─────────────────────────

const ICON_PATHS: Record<string, string> = {
  router:
    "M12,2C6.48,2,2,6.48,2,12s4.48,10,10,10,10-4.48,10-10S17.52,2,12,2Zm-1,17.93c-3.94-.49-7-3.85-7-7.93,0-.62.08-1.22.21-1.79L9,15v1a2,2,0,0,0,2,2Zm6.9-2.54A2,2,0,0,0,17,16H16V13a1,1,0,0,0-1-1H9V10h2a1,1,0,0,0,1-1V7h2a2,2,0,0,0,2-2v-.41A8,8,0,0,1,20,12,7.88,7.88,0,0,1,18.9,17.39Z",
  switch:
    "M20,3H4A2,2,0,0,0,2,5V19a2,2,0,0,0,2,2H20a2,2,0,0,0,2-2V5A2,2,0,0,0,20,3ZM10,17H6V15h4Zm0-4H6V11h4Zm0-4H6V7h4Zm8,8H12V15h6Zm0-4H12V11h6Zm0-4H12V7h6Z",
  ap: "M12,21L15.6,16.2C14.6,15.45,13.35,15,12,15C10.65,15,9.4,15.45,8.4,16.2L12,21M12,3C7.95,3,4.21,4.34,1.2,6.6L3,9C5.5,7.12,8.62,6,12,6C15.38,6,18.5,7.12,21,9L22.8,6.6C19.79,4.34,16.05,3,12,3M12,9C9.3,9,6.81,9.89,4.8,11.4L6.6,13.8C8.1,12.67,9.97,12,12,12C14.03,12,15.9,12.67,17.4,13.8L19.2,11.4C17.19,9.89,14.7,9,12,9Z",
  server:
    "M4,1H20A1,1,0,0,1,21,2V22A1,1,0,0,1,20,23H4A1,1,0,0,1,3,22V2A1,1,0,0,1,4,1M5,3V21H19V3H5M12,17A1.5,1.5,0,1,1,13.5,15.5,1.5,1.5,0,0,1,12,17M8,7H16V13H8V7Z",
  workstation:
    "M21,16H3V4H21M21,2H3C1.89,2,1,2.89,1,4V16A2,2,0,0,0,3,18H10V20H8V22H16V20H14V18H21A2,2,0,0,0,23,16V4C23,2.89,22.1,2,21,2Z",
  camera:
    "M9,3V4H5V7H4V3H9M15,3H20V7H19V4H15V3M4,17V21H9V20H5V17H4M19,17V20H15V21H20V17H19M7,7H17V17H7V7M9,9V15H15V9H9Z",
  phone:
    "M6.62,10.79C8.06,13.62 10.38,15.94 13.21,17.38L15.41,15.18C15.69,14.9 16.08,14.82 16.43,14.93C17.55,15.3 18.75,15.5 20,15.5A1,1 0,0,1,21,16.5V20A1,1,0,0,1,20,21A17,17,0,0,1,3,4A1,1,0,0,1,4,3H7.5A1,1,0,0,1,8.5,4C8.5,5.25,8.7,6.45,9.07,7.57C9.18,7.92,9.1,8.31,8.82,8.59L6.62,10.79Z",
  iot: "M9,3V4H5V7H4V3H9M15,3H20V7H19V4H15V3M4,17V21H9V20H5V17H4M19,17V20H15V21H20V17H19M7,7H17V17H7V7M9,9V15H15V9H9Z",
  printer:
    "M18,3H6V7H18M19,12A1,1,0,0,1,18,11A1,1,0,0,1,19,10A1,1,0,0,1,20,11A1,1,0,0,1,19,12M16,19H8V14H16M19,8H5A3,3,0,0,0,2,11V17H6V21H18V17H22V11A3,3,0,0,0,19,8Z",
  smarthome:
    "M12,3L2,12H5V20H19V12H22M12,18A2,2,0,0,1,10,16A2,2,0,0,1,12,14A2,2,0,0,1,14,16A2,2,0,0,1,12,18M14.5,10H9.5L12,7L14.5,10Z",
  media: "M8,5.14V19.14L19,12.14L8,5.14Z",
  unknown:
    "M11,18H13V16H11V18M12,2A10,10,0,0,0,2,12A10,10,0,0,0,12,22A10,10,0,0,0,22,12A10,10,0,0,0,12,2M12,20C7.59,20,4,16.41,4,12C4,7.59,7.59,4,12,4C16.41,4,20,7.59,20,12C20,16.41,16.41,20,12,20M12,6A4,4,0,0,0,8,10H10A2,2,0,0,1,12,8A2,2,0,0,1,14,10C14,12,11,11.75,11,14H13C13,12.5,16,12.25,16,10A4,4,0,0,0,12,6Z",
};

// Map TopologyNodeKind → icon key
function kindToIcon(kind: string): string {
  switch (kind) {
    case "router": return "router";
    case "managed_switch":
    case "unmanaged_switch": return "switch";
    case "access_point": return "ap";
    case "server": return "server";
    case "workstation": return "workstation";
    case "camera": return "camera";
    case "phone": return "phone";
    case "iot": return "iot";
    case "printer": return "printer";
    case "smart_home": return "smarthome";
    case "media_player": return "media";
    default: return "unknown";
  }
}

// ─── Speed Tier Styling ─────────────────────────────────

interface SpeedStyle {
  color: string;
  width: number;
  label: string;
}

function speedStyle(mbps: number | null): SpeedStyle {
  if (mbps == null) return { color: "#00E5FF", width: 1.2, label: "" };
  if (mbps >= 10000) return { color: "#2FA4FF", width: 3.5, label: "10G" };
  if (mbps >= 5000) return { color: "#FF4FD8", width: 2.5, label: "5G" };
  if (mbps >= 2500) return { color: "#7A5CFF", width: 2.0, label: "2.5G" };
  if (mbps >= 1000) return { color: "#00E5FF", width: 1.2, label: "1G" };
  return { color: "#6B7785", width: 0.8, label: `${mbps}M` };
}

// ─── Public Types ───────────────────────────────────────

export interface TopologyCallbacks {
  onNodeClick?: (node: TopologyNode) => void;
  onContextMenu?: (node: TopologyNode, screenX: number, screenY: number) => void;
  onDragEnd?: (nodeId: string, x: number, y: number) => void;
  onUnpin?: (nodeId: string) => void;
  onSectorDragEnd?: (vlanId: number, x: number, y: number, width: number, height: number) => void;
  onSectorNodesDrag?: (positions: { node_id: string; x: number; y: number }[]) => void;
  onSectorReset?: (vlanId: number) => void;
}

export interface TopologyMapInstance {
  destroy: () => void;
  render: (data: NetworkTopologyResponse) => void;
  search: (term: string) => string[];
  highlightNode: (id: string) => void;
  clearSelection: () => void;
  resetView: () => void;
  setVlanFilter: (vlans: Set<number> | null) => void;
  setKindFilter: (kinds: Set<string> | null) => void;
  setEndpointsVisible: (visible: boolean) => void;
  clearDraggedPosition: (nodeId: string) => void;
}

// ─── Helpers ───────────────────────────────────────────

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 1) + "\u2026" : s;
}

function hexPath(r: number): string {
  const pts: [number, number][] = [];
  for (let i = 0; i < 6; i++) {
    const angle = (Math.PI / 3) * i - Math.PI / 6;
    pts.push([r * Math.cos(angle), r * Math.sin(angle)]);
  }
  return "M" + pts.map((p) => p.join(",")).join("L") + "Z";
}

// ─── Factory ────────────────────────────────────────────

export function createTopologyMapInstance(
  svgElement: SVGSVGElement,
  callbacks: TopologyCallbacks,
): TopologyMapInstance {
  // ── All helpers scoped inside factory ──

  function nodeColor(node: TopologyNode): string {
    if (node.kind === "router") return "#2FA4FF";
    if (node.kind === "managed_switch") return "#00E5FF";
    if (node.kind === "unmanaged_switch") return "#7A5CFF";
    if (node.kind === "access_point") return "#7A5CFF";
    if (node.kind === "server") return "#2FA4FF";
    if (node.kind === "camera") return "#6B7785";
    if (node.kind === "media_player") return "#FF4FD8";
    if (node.vlan_id != null && VLAN_COLORS[node.vlan_id]) return VLAN_COLORS[node.vlan_id];
    if (node.is_infrastructure) return "#00E5FF";
    return "#E6EDF3";
  }

  function hexRadius(node: TopologyNode): number {
    if (node.kind === "router") return HEX_RADIUS + 4;
    if (node.kind === "managed_switch" || node.kind === "unmanaged_switch") return HEX_RADIUS;
    if (node.kind === "access_point") return HEX_RADIUS - 2;
    if (node.is_infrastructure) return HEX_RADIUS - 4;
    return HEX_RADIUS_SM;
  }

  function isHub(node: TopologyNode): boolean {
    return node.kind === "router" || node.kind === "managed_switch";
  }

  /** Map traffic bps to stroke width using log10.
   *  0 bps → 0.6,  1 Kbps → 1.0,  1 Mbps → 2.0,  100 Mbps → 3.5,  1 Gbps → 4.5 */
  function trafficWidth(bps: number): number {
    if (bps <= 0) return 0.6;
    const log = Math.log10(bps); // 3=1K, 6=1M, 9=1G
    return Math.min(0.6 + (log - 2) * 0.55, 6);
  }

  function edgeWidth(edge: TopologyEdge): number {
    if (edge.traffic_bps != null && edge.traffic_bps > 0) return trafficWidth(edge.traffic_bps);
    if (edge.speed_mbps != null) return speedStyle(edge.speed_mbps).width;
    switch (edge.kind) {
      case "trunk": return 2.5;
      case "uplink": return 2;
      case "access": return 0.8;
      case "wireless": return 0.8;
      default: return 1;
    }
  }

  function edgeDash(edge: TopologyEdge): string {
    if (edge.kind === "wireless") return "4,3";
    if (edge.kind === "access" && !edge.source_port) return "3,3";
    return "none";
  }

  function edgeColor(edge: TopologyEdge): string {
    if (edge.speed_mbps != null) return speedStyle(edge.speed_mbps).color;
    if (edge.kind === "uplink") return "#2FA4FF";
    if (edge.kind === "trunk") return "#00E5FF";
    if (edge.vlans.length === 1 && VLAN_COLORS[edge.vlans[0]]) return VLAN_COLORS[edge.vlans[0]];
    return "#6B7785";
  }

  function edgeSpeedLabel(edge: TopologyEdge): string {
    if (edge.speed_mbps != null) return speedStyle(edge.speed_mbps).label;
    return "";
  }

  function matchesSearch(node: TopologyNode, term: string): boolean {
    const lower = term.toLowerCase();
    const fields = [
      node.label,
      node.ip,
      node.mac,
      node.kind,
      node.device_type,
      node.manufacturer,
      node.vlan_id != null ? String(node.vlan_id) : null,
    ];
    return fields.some((f) => f && f.toLowerCase().includes(lower));
  }

  function isNew(node: TopologyNode): boolean {
    if (!node.first_seen) return false;
    return Date.now() - node.first_seen * 1000 < 86400_000;
  }

  // ── Mutable state ──
  let currentData: NetworkTopologyResponse | null = null;
  let nodeMap: Map<string, TopologyNode> = new Map();
  let selectedNodeId: string | null = null;
  let vlanFilter: Set<number> | null = null;
  let kindFilter: Set<string> | null = null;
  let showEndpoints = true;
  let tooltip: HTMLDivElement | null = null;
  let hasInitialFit = false;
  let currentScale = 1;
  let destroyed = false;
  const draggedPositions: Map<string, { x: number; y: number }> = new Map();

  // ── SVG setup ──
  const svg = d3
    .select(svgElement)
    .attr("viewBox", `0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`)
    .attr("preserveAspectRatio", "xMidYMid meet");

  svg.selectAll("*").remove();

  const defs = svg.append("defs");

  // Glow filters
  function addGlowFilter(id: string, color: string, opacity: number, stdDev: number) {
    const f = defs
      .append("filter")
      .attr("id", id)
      .attr("x", "-50%")
      .attr("y", "-50%")
      .attr("width", "200%")
      .attr("height", "200%");
    f.append("feGaussianBlur").attr("stdDeviation", stdDev).attr("result", "blur");
    f.append("feFlood")
      .attr("flood-color", color)
      .attr("flood-opacity", opacity)
      .attr("result", "color");
    f.append("feComposite")
      .attr("in", "color")
      .attr("in2", "blur")
      .attr("operator", "in")
      .attr("result", "tinted");
    const m = f.append("feMerge");
    m.append("feMergeNode").attr("in", "tinted");
    m.append("feMergeNode").attr("in", "SourceGraphic");
  }

  addGlowFilter("glow-active", "#21D07A", 0.4, 4);
  addGlowFilter("glow-inactive", "#FF4D4F", 0.4, 4);
  addGlowFilter("glow-anomaly", "#FFC857", 0.5, 5);
  addGlowFilter("glow-selected", "#ffffff", 0.6, 6);

  // Soft glow for general hex nodes
  const fSoft = defs
    .append("filter")
    .attr("id", "glow-soft")
    .attr("x", "-50%")
    .attr("y", "-50%")
    .attr("width", "200%")
    .attr("height", "200%");
  fSoft.append("feGaussianBlur").attr("stdDeviation", 3).attr("result", "blur");
  const mSoft = fSoft.append("feMerge");
  mSoft.append("feMergeNode").attr("in", "blur");
  mSoft.append("feMergeNode").attr("in", "SourceGraphic");

  // Line glow for connections
  const lineGlow = defs
    .append("filter")
    .attr("id", "line-glow")
    .attr("x", "-20%")
    .attr("y", "-20%")
    .attr("width", "140%")
    .attr("height", "140%");
  lineGlow.append("feGaussianBlur").attr("stdDeviation", 2).attr("result", "blur");
  const lm = lineGlow.append("feMerge");
  lm.append("feMergeNode").attr("in", "blur");
  lm.append("feMergeNode").attr("in", "SourceGraphic");

  // Zoom & pan
  const zoomGroup = svg.append("g").attr("id", "topo-zoom-group");
  const zoomBehavior = d3
    .zoom<SVGSVGElement, unknown>()
    .scaleExtent([0.05, 5])
    .on("zoom", (event) => {
      zoomGroup.attr("transform", event.transform);
      currentScale = event.transform.k;
      updateLabelVisibility();
    });
  svg.call(zoomBehavior);

  // SVG layers (bottom to top)
  const layerStars = zoomGroup.append("g").attr("class", "layer-stars");
  const layerGrid = zoomGroup.append("g").attr("class", "layer-grid");
  const layerVlanBg = zoomGroup.append("g").attr("class", "layer-vlan-bg");
  const layerEdges = zoomGroup.append("g").attr("class", "layer-edges");
  const layerParticles = zoomGroup.append("g").attr("class", "layer-particles").attr("pointer-events", "none");
  const layerNodes = zoomGroup.append("g").attr("class", "layer-nodes");
  const layerLabels = zoomGroup.append("g").attr("class", "layer-labels");
  const layerSectorDrag = zoomGroup.append("g").attr("class", "layer-sector-drag");

  // ── Stars ──
  function renderStars() {
    layerStars.selectAll("*").remove();
    for (let i = 0; i < STAR_COUNT; i++) {
      layerStars
        .append("circle")
        .attr("class", "topo-star")
        .attr("cx", Math.random() * MAP_WIDTH)
        .attr("cy", Math.random() * MAP_HEIGHT)
        .attr("r", Math.random() * 1.2 + 0.3)
        .style("fill", "#fff")
        .style("opacity", 0)
        .style("--dur", Math.random() * 4 + 2 + "s")
        .style("--delay", Math.random() * 5 + "s");
    }
  }

  // ── Grid ──
  function renderGrid() {
    layerGrid.selectAll("*").remove();
    const gridSpacing = 60;
    for (let x = 0; x <= MAP_WIDTH; x += gridSpacing) {
      layerGrid
        .append("line")
        .attr("class", "topo-grid-line")
        .attr("x1", x).attr("y1", 0)
        .attr("x2", x).attr("y2", MAP_HEIGHT)
        .attr("stroke", "rgba(0, 240, 255, 0.04)")
        .attr("stroke-width", 0.5);
    }
    for (let y = 0; y <= MAP_HEIGHT; y += gridSpacing) {
      layerGrid
        .append("line")
        .attr("class", "topo-grid-line")
        .attr("x1", 0).attr("y1", y)
        .attr("x2", MAP_WIDTH).attr("y2", y)
        .attr("stroke", "rgba(0, 240, 255, 0.04)")
        .attr("stroke-width", 0.5);
    }
  }

  // ── Tooltip ──
  function createTooltip(): HTMLDivElement {
    if (tooltip) return tooltip;
    const div = document.createElement("div");
    div.style.cssText =
      "position:fixed;pointer-events:none;z-index:9999;background:rgba(11,15,20,0.95);" +
      "border:1px solid rgba(42,50,61,0.8);border-radius:6px;padding:8px 12px;" +
      "font-size:12px;color:#E6EDF3;max-width:300px;display:none;" +
      "font-family:'Share Tech Mono',monospace;box-shadow:0 4px 20px rgba(0,0,0,0.5);backdrop-filter:blur(8px);";
    document.body.appendChild(div);
    tooltip = div;
    return div;
  }

  function showTooltip(event: MouseEvent, node: TopologyNode) {
    const tip = createTooltip();
    const lines: string[] = [];
    lines.push(`<strong style="color:${nodeColor(node)}">${escHtml(node.label)}</strong>`);
    if (node.kind) lines.push(`<span style="color:#6B7785">Kind:</span> ${escHtml(node.kind)}`);
    if (node.ip) lines.push(`<span style="color:#6B7785">IP:</span> ${escHtml(node.ip)}`);
    if (node.mac) lines.push(`<span style="color:#6B7785">MAC:</span> ${escHtml(node.mac)}`);
    if (node.vlan_id != null) lines.push(`<span style="color:#6B7785">VLAN:</span> ${node.vlan_id}`);
    if (node.device_type) lines.push(`<span style="color:#6B7785">Type:</span> ${escHtml(node.device_type)}`);
    if (node.manufacturer) lines.push(`<span style="color:#6B7785">Mfg:</span> ${escHtml(node.manufacturer)}`);
    if (node.switch_port) {
      lines.push(`<span style="color:#6B7785">Port:</span> ${escHtml(node.switch_port)}`);
    } else if (node.parent_id) {
      lines.push(`<span style="color:#6B7785">Port:</span> <em style="color:#2A323D">downstream of ${escHtml(node.parent_id)}</em>`);
    }
    tip.innerHTML = lines.join("<br>");
    tip.style.display = "block";
    tip.style.left = `${event.clientX + 12}px`;
    tip.style.top = `${event.clientY - 10}px`;
  }

  function showEdgeTooltip(event: MouseEvent, edge: TopologyEdge) {
    const tip = createTooltip();
    const src = nodeMap.get(edge.source);
    const tgt = nodeMap.get(edge.target);
    const speedLbl = edgeSpeedLabel(edge);
    const lines: string[] = [];
    lines.push(`<span style="color:#00E5FF;font-weight:600">${escHtml(edge.kind)}</span>`);
    lines.push(`<span style="color:#6B7785">${escHtml(src?.label || edge.source)} &harr; ${escHtml(tgt?.label || edge.target)}</span>`);
    if (speedLbl) lines.push(`<span style="color:#2FA4FF">${escHtml(speedLbl)}</span>`);
    if (edge.source_port || edge.target_port) {
      lines.push(`<span style="color:#6B7785">${escHtml(edge.source_port || "?")} → ${escHtml(edge.target_port || "?")}</span>`);
    }
    tip.innerHTML = lines.join("<br>");
    tip.style.display = "block";
    tip.style.left = `${event.clientX + 12}px`;
    tip.style.top = `${event.clientY - 10}px`;
  }

  function hideTooltip() {
    if (tooltip) tooltip.style.display = "none";
  }

  // ── Visibility helpers ──
  function isNodeVisible(node: TopologyNode): boolean {
    if (node.disposition === "ignored") return false;
    if (!showEndpoints && !node.is_infrastructure) return false;
    if (vlanFilter && node.vlan_id != null && !vlanFilter.has(node.vlan_id)) return false;
    if (kindFilter && !kindFilter.has(node.kind)) return false;
    return true;
  }

  function isEdgeVisible(edge: TopologyEdge): boolean {
    const src = nodeMap.get(edge.source);
    const tgt = nodeMap.get(edge.target);
    if (!src || !tgt) return false;
    return isNodeVisible(src) && isNodeVisible(tgt);
  }

  function nodeOpacity(node: TopologyNode): number {
    if (vlanFilter && node.vlan_id != null && !vlanFilter.has(node.vlan_id)) return 0.08;
    if (kindFilter && !kindFilter.has(node.kind)) return 0.08;
    if (node.disposition === "external") return 0.4;
    return 1;
  }

  function statusFilter(node: TopologyNode): string {
    if (selectedNodeId === node.id) return "url(#glow-selected)";
    if (node.status === "online") return "url(#glow-active)";
    if (node.status === "offline") return "url(#glow-inactive)";
    return "url(#glow-soft)";
  }

  // ── Particle animation ──
  function animateParticle(
    p: d3.Selection<SVGCircleElement, unknown, null, undefined>,
    edge: TopologyEdge,
  ) {
    if (destroyed) return;
    const src = nodeMap.get(edge.source);
    const tgt = nodeMap.get(edge.target);
    if (!src || !tgt) return;

    const speed = edge.speed_mbps ?? 1000;
    const dur = Math.max(600, Math.min(4000, 5000 - Math.log10(speed + 1) * 1000));

    const fwd = Math.random() > 0.5;
    p.attr("cx", fwd ? src.x : tgt.x)
      .attr("cy", fwd ? src.y : tgt.y)
      .attr("opacity", 0.8)
      .transition()
      .duration(dur)
      .ease(d3.easeLinear)
      .attr("cx", fwd ? tgt.x : src.x)
      .attr("cy", fwd ? tgt.y : src.y)
      .on("end", () => animateParticle(p, edge));
  }

  // ── Main render ──
  function renderAll(data: NetworkTopologyResponse) {
    currentData = data;
    nodeMap.clear();

    // Merge locally-dragged positions to prevent snap-back from stale refetches.
    data.nodes.forEach((n) => {
      const dragged = draggedPositions.get(n.id);
      if (dragged) {
        if (n.position_source === "human") {
          draggedPositions.delete(n.id);
        } else {
          n.x = dragged.x;
          n.y = dragged.y;
          n.position_source = "human";
        }
      }
      nodeMap.set(n.id, n);
    });

    renderStars();
    renderGrid();
    renderVlanBackgrounds(data.vlan_groups);
    renderEdges(data.edges);
    renderNodes(data.nodes);
  }

  // ── VLAN background sectors ──
  function renderVlanBackgrounds(groups: TopologyVlanGroup[]) {
    layerVlanBg.selectAll("*").remove();
    layerSectorDrag.selectAll("*").remove();

    groups.forEach((group) => {
      const color = group.color || VLAN_COLORS[group.vlan_id] || "#555";

      const g = layerVlanBg.append("g")
        .attr("class", `vlan-bg-${group.vlan_id}`)
        .attr("data-vlan-id", group.vlan_id);

      const rect = g.append("rect")
        .attr("class", "sector-rect")
        .attr("x", group.bbox_x)
        .attr("y", group.bbox_y)
        .attr("width", group.bbox_w)
        .attr("height", group.bbox_h)
        .attr("rx", 12)
        .attr("fill", color)
        .attr("fill-opacity", 0.05)
        .attr("stroke", color)
        .attr("stroke-opacity", 0.25)
        .attr("stroke-width", group.position_source === "human" ? 2 : 1)
        .attr("stroke-dasharray", "8,4");

      g.append("text")
        .attr("class", "sector-header")
        .attr("x", group.bbox_x + 12)
        .attr("y", group.bbox_y + 18)
        .attr("fill", color)
        .attr("fill-opacity", 0.6)
        .attr("font-size", 11)
        .attr("font-family", "'Orbitron', monospace")
        .attr("font-weight", "bold")
        .attr("letter-spacing", "2px")
        .attr("pointer-events", "none")
        .text(`SECTOR-${group.vlan_id} \u2014 ${group.name}`);

      if (group.subnet) {
        g.append("text")
          .attr("class", "sector-subnet")
          .attr("x", group.bbox_x + 12)
          .attr("y", group.bbox_y + 33)
          .attr("fill", color)
          .attr("fill-opacity", 0.35)
          .attr("font-size", 9)
          .attr("font-family", "'Share Tech Mono', monospace")
          .text(group.subnet);
      }

      g.append("text")
        .attr("class", "sector-count")
        .attr("x", group.bbox_x + group.bbox_w - 12)
        .attr("y", group.bbox_y + 18)
        .attr("text-anchor", "end")
        .attr("fill", color)
        .attr("fill-opacity", 0.4)
        .attr("font-size", 10)
        .attr("font-family", "'Share Tech Mono', monospace")
        .text(`${group.node_count} devices`);

      // Pin indicator
      if (group.position_source === "human") {
        g.append("text")
          .attr("class", "sector-pin")
          .attr("x", group.bbox_x + group.bbox_w - 30)
          .attr("y", group.bbox_y + 18)
          .attr("text-anchor", "end")
          .attr("font-size", 10)
          .attr("cursor", "pointer")
          .text("\uD83D\uDCCC")
          .on("click", function (event: MouseEvent) {
            event.stopPropagation();
            callbacks.onSectorReset?.(group.vlan_id);
          });
      }

      // Corner marks
      const sz = 12;
      const corners: [number, number, number, number][] = [
        [group.bbox_x, group.bbox_y, 1, 1],
        [group.bbox_x + group.bbox_w, group.bbox_y, -1, 1],
        [group.bbox_x, group.bbox_y + group.bbox_h, 1, -1],
        [group.bbox_x + group.bbox_w, group.bbox_y + group.bbox_h, -1, -1],
      ];
      corners.forEach(([cx, cy, dx, dy]) => {
        g.append("path")
          .attr("d", `M${cx},${cy + dy * sz} L${cx},${cy} L${cx + dx * sz},${cy}`)
          .attr("fill", "none")
          .attr("stroke", color)
          .attr("stroke-width", 2)
          .attr("stroke-opacity", 0.35);
      });

      // ── Sector drag overlay (in layerSectorDrag — above all other layers) ──
      // Visual elements stay in layerVlanBg but interactive drag handles
      // are placed in layerSectorDrag (topmost layer) to prevent edges,
      // particles, and nodes from blocking mouse events.
      let dragStartX = 0;
      let dragStartY = 0;
      let origBboxX = group.bbox_x;
      let origBboxY = group.bbox_y;

      const HEADER_H = 42; // height of the draggable header area
      const dragOverlay = layerSectorDrag.append("rect")
        .attr("class", `sector-drag-${group.vlan_id}`)
        .attr("data-vlan-id", group.vlan_id)
        .attr("x", group.bbox_x)
        .attr("y", group.bbox_y)
        .attr("width", group.bbox_w)
        .attr("height", HEADER_H)
        .attr("fill", "transparent")
        .attr("cursor", "grab");

      const sectorDrag = d3.drag<SVGRectElement, unknown>()
        .on("start", function (event) {
          dragStartX = event.x;
          dragStartY = event.y;
          origBboxX = group.bbox_x;
          origBboxY = group.bbox_y;
          d3.select(this).attr("cursor", "grabbing");
        })
        .on("drag", function (event) {
          const dx = event.x - dragStartX;
          const dy = event.y - dragStartY;
          const newX = origBboxX + dx;
          const newY = origBboxY + dy;

          // Update visual elements in layerVlanBg
          g.select(".sector-rect")
            .attr("x", newX).attr("y", newY);
          g.select(".sector-header")
            .attr("x", newX + 12).attr("y", newY + 18);
          g.select(".sector-subnet")
            .attr("x", newX + 12).attr("y", newY + 33);
          g.select(".sector-count")
            .attr("x", newX + group.bbox_w - 12).attr("y", newY + 18);
          g.select(".sector-pin")
            .attr("x", newX + group.bbox_w - 30).attr("y", newY + 18);
          // Update drag overlay position
          d3.select(this).attr("x", newX).attr("y", newY);
          // Update resize handle
          layerSectorDrag.select(`.sector-resize-${group.vlan_id}`)
            .attr("x", newX + group.bbox_w - 14).attr("y", newY + group.bbox_h - 14);

          // Move all nodes in this VLAN
          if (currentData) {
            currentData.nodes.forEach((node) => {
              if (node.vlan_id === group.vlan_id) {
                const nodeG = layerNodes.select(`[data-node-id="${CSS.escape(node.id)}"]`);
                if (!nodeG.empty()) {
                  nodeG.attr("transform", `translate(${node.x + dx},${node.y + dy})`);
                }
              }
            });
          }
        })
        .on("end", function (event) {
          d3.select(this).attr("cursor", "grab");
          const dx = event.x - dragStartX;
          const dy = event.y - dragStartY;
          if (Math.abs(dx) < 2 && Math.abs(dy) < 2) return;

          const newX = origBboxX + dx;
          const newY = origBboxY + dy;

          // Commit node position changes + update edges
          if (currentData) {
            currentData.nodes.forEach((node) => {
              if (node.vlan_id === group.vlan_id) {
                node.x += dx;
                node.y += dy;
                layerLabels.selectAll(`[data-node-id="${CSS.escape(node.id)}"]`).each(function () {
                  const el = d3.select(this);
                  const curX = parseFloat(el.attr("x")) || 0;
                  const curY = parseFloat(el.attr("y")) || 0;
                  el.attr("x", curX + dx).attr("y", curY + dy);
                });
                layerEdges.selectAll<SVGGElement, unknown>(".edge").each(function () {
                  const eg = d3.select(this);
                  const srcId = eg.attr("data-source");
                  const tgtId = eg.attr("data-target");
                  if (srcId === node.id || tgtId === node.id) {
                    const src = nodeMap.get(srcId || "");
                    const tgt = nodeMap.get(tgtId || "");
                    if (src && tgt) {
                      eg.select("line")
                        .attr("x1", src.x).attr("y1", src.y)
                        .attr("x2", tgt.x).attr("y2", tgt.y);
                    }
                  }
                });
              }
            });
          }

          // Update corner marks
          g.selectAll("path").remove();
          const sz2 = 12;
          const corners2: [number, number, number, number][] = [
            [newX, newY, 1, 1],
            [newX + group.bbox_w, newY, -1, 1],
            [newX, newY + group.bbox_h, 1, -1],
            [newX + group.bbox_w, newY + group.bbox_h, -1, -1],
          ];
          corners2.forEach(([cx, cy, cdx, cdy]) => {
            g.append("path")
              .attr("d", `M${cx},${cy + cdy * sz2} L${cx},${cy} L${cx + cdx * sz2},${cy}`)
              .attr("fill", "none")
              .attr("stroke", color)
              .attr("stroke-width", 2)
              .attr("stroke-opacity", 0.35);
          });

          group.bbox_x = newX;
          group.bbox_y = newY;
          group.position_source = "human";
          callbacks.onSectorDragEnd?.(group.vlan_id, newX, newY, group.bbox_w, group.bbox_h);

          // Batch-save all node positions in this VLAN sector
          if (currentData && callbacks.onSectorNodesDrag) {
            const movedNodes: { node_id: string; x: number; y: number }[] = [];
            currentData.nodes.forEach((node) => {
              if (node.vlan_id === group.vlan_id) {
                movedNodes.push({ node_id: node.id, x: node.x, y: node.y });
              }
            });
            if (movedNodes.length > 0) {
              callbacks.onSectorNodesDrag(movedNodes);
            }
          }
        });

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      dragOverlay.call(sectorDrag as any);

      // ── Resize handle (also in layerSectorDrag for interactivity) ──
      const handleSize = 14;
      layerSectorDrag.append("rect")
        .attr("class", `sector-resize-${group.vlan_id}`)
        .attr("data-vlan-id", group.vlan_id)
        .attr("x", group.bbox_x + group.bbox_w - handleSize)
        .attr("y", group.bbox_y + group.bbox_h - handleSize)
        .attr("width", handleSize)
        .attr("height", handleSize)
        .attr("rx", 2)
        .attr("fill", color)
        .attr("fill-opacity", 0.25)
        .attr("stroke", color)
        .attr("stroke-opacity", 0.5)
        .attr("stroke-width", 1)
        .attr("cursor", "nwse-resize")
        .call(
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          d3.drag<SVGRectElement, unknown>()
            .on("start", function () {
              origBboxX = group.bbox_x;
              origBboxY = group.bbox_y;
            })
            .on("drag", function (event) {
              const newW = Math.max(100, event.x - group.bbox_x);
              const newH = Math.max(60, event.y - group.bbox_y);
              rect.attr("width", newW).attr("height", newH);
              g.select(".sector-count")
                .attr("x", group.bbox_x + newW - 12);
              g.select(".sector-pin")
                .attr("x", group.bbox_x + newW - 30);
              dragOverlay.attr("width", newW);
              d3.select(this)
                .attr("x", group.bbox_x + newW - handleSize)
                .attr("y", group.bbox_y + newH - handleSize);
            })
            .on("end", function (event) {
              const newW = Math.max(100, event.x - group.bbox_x);
              const newH = Math.max(60, event.y - group.bbox_y);
              group.bbox_w = newW;
              group.bbox_h = newH;
              group.position_source = "human";
              callbacks.onSectorDragEnd?.(group.vlan_id, group.bbox_x, group.bbox_y, newW, newH);
            }) as any, // eslint-disable-line @typescript-eslint/no-explicit-any
        );
    });
  }

  // ── Edges ──
  function renderEdges(edges: TopologyEdge[]) {
    layerEdges.selectAll("*").remove();
    layerParticles.selectAll("*").remove();

    edges.forEach((edge) => {
      const src = nodeMap.get(edge.source);
      const tgt = nodeMap.get(edge.target);
      if (!src || !tgt) return;

      const visible = isEdgeVisible(edge);
      const g = layerEdges.append("g")
        .attr("class", "edge")
        .attr("data-source", edge.source)
        .attr("data-target", edge.target)
        .attr("opacity", visible ? 1 : 0.05);

      const line = g.append("line")
        .attr("x1", src.x).attr("y1", src.y)
        .attr("x2", tgt.x).attr("y2", tgt.y)
        .attr("stroke", edgeColor(edge))
        .attr("stroke-width", edgeWidth(edge))
        .attr("stroke-dasharray", edgeDash(edge))
        .attr("stroke-opacity", edge.kind === "access" ? 0.4 : 0.7)
        .attr("filter", edge.kind === "trunk" || edge.kind === "uplink" ? "url(#line-glow)" : "");

      // Edge hover tooltip
      line
        .on("mouseenter", function (event: MouseEvent) {
          showEdgeTooltip(event, edge);
        })
        .on("mousemove", function (event: MouseEvent) {
          if (tooltip) {
            tooltip.style.left = `${event.clientX + 12}px`;
            tooltip.style.top = `${event.clientY - 10}px`;
          }
        })
        .on("mouseleave", function () {
          hideTooltip();
        });

      // Port labels for trunk/uplink
      if ((edge.kind === "trunk" || edge.kind === "uplink") && (edge.source_port || edge.target_port)) {
        const dx = tgt.x - src.x;
        const dy = tgt.y - src.y;

        if (edge.source_port) {
          g.append("text")
            .attr("x", src.x + dx * 0.15)
            .attr("y", src.y + dy * 0.15 - 6)
            .attr("text-anchor", "middle")
            .attr("fill", "#6B7785")
            .attr("font-size", 8)
            .attr("font-family", "'Share Tech Mono', monospace")
            .text(edge.source_port);
        }
        if (edge.target_port) {
          g.append("text")
            .attr("x", src.x + dx * 0.85)
            .attr("y", src.y + dy * 0.85 - 6)
            .attr("text-anchor", "middle")
            .attr("fill", "#6B7785")
            .attr("font-size", 8)
            .attr("font-family", "'Share Tech Mono', monospace")
            .text(edge.target_port);
        }

        // Speed label at midpoint
        const spdLabel = edgeSpeedLabel(edge);
        if (spdLabel) {
          g.append("text")
            .attr("x", src.x + dx * 0.5)
            .attr("y", src.y + dy * 0.5 - 8)
            .attr("text-anchor", "middle")
            .attr("fill", edgeColor(edge))
            .attr("font-size", 9)
            .attr("font-family", "'Share Tech Mono', monospace")
            .attr("font-weight", "bold")
            .attr("opacity", 0.7)
            .text(spdLabel);
        }
      }

      // Animated particles for trunk/uplink edges
      if (edge.kind === "trunk" || edge.kind === "uplink") {
        const particleColor = edgeColor(edge);
        const particleR = edge.speed_mbps != null && edge.speed_mbps >= 10000 ? 2.5 : 1.5;
        const p = layerParticles
          .append("circle")
          .attr("class", "topo-particle")
          .attr("r", particleR)
          .attr("fill", particleColor)
          .attr("filter", "url(#glow-soft)");
        animateParticle(p, edge);
      }
    });
  }

  // ── Nodes ──
  function renderNodes(nodes: TopologyNode[]) {
    layerNodes.selectAll("*").remove();
    layerLabels.selectAll("*").remove();

    // Sort: infrastructure first
    const sorted = [...nodes].sort((a, b) => {
      if (a.is_infrastructure && !b.is_infrastructure) return -1;
      if (!a.is_infrastructure && b.is_infrastructure) return 1;
      return 0;
    });

    let endpointIdx = 0;
    sorted.forEach((node) => {
      const visible = isNodeVisible(node);
      const opacity = nodeOpacity(node);
      const epIdx = node.is_infrastructure ? -1 : endpointIdx++;
      const r = hexRadius(node);
      const color = nodeColor(node);

      const g = layerNodes
        .append("g")
        .attr("class", `topo-node topo-node-${node.kind}`)
        .attr("data-node-id", node.id)
        .attr("transform", `translate(${node.x},${node.y})`)
        .attr("opacity", visible ? opacity : 0)
        .attr("cursor", "pointer")
        .attr("filter", statusFilter(node));

      // Hub pulse rings for routers and managed switches
      if (isHub(node)) {
        g.append("circle")
          .attr("class", "topo-hub-pulse")
          .attr("cx", 0).attr("cy", 0)
          .attr("r", r)
          .attr("stroke", color)
          .attr("fill", "none")
          .attr("stroke-width", 1);
        g.append("circle")
          .attr("class", "topo-hub-pulse")
          .attr("cx", 0).attr("cy", 0)
          .attr("r", r)
          .attr("stroke", color)
          .attr("fill", "none")
          .attr("stroke-width", 1)
          .style("animation-delay", "1.5s");
      }

      // Hexagonal shape
      g.append("path")
        .attr("class", "topo-hex")
        .attr("d", hexPath(r))
        .attr("fill", color)
        .attr("fill-opacity", node.is_infrastructure ? 0.1 : 0.06)
        .attr("stroke", color)
        .attr("stroke-width", node.is_infrastructure ? 1.5 : 1);

      // Icon inside hexagon (infrastructure nodes only — endpoints are too small)
      if (node.is_infrastructure || r >= HEX_RADIUS_SM + 2) {
        const iconKey = kindToIcon(node.kind);
        const iconPath = ICON_PATHS[iconKey] || ICON_PATHS.unknown;
        const iconScale = (r / HEX_RADIUS) * 0.75;
        g.append("g")
          .attr("class", "topo-node-icon")
          .attr("transform", `translate(${-12 * iconScale}, ${-12 * iconScale}) scale(${iconScale})`)
          .append("path")
          .attr("d", iconPath)
          .attr("fill", color)
          .attr("opacity", 0.85);
      }

      // "NEW" badge
      if (isNew(node)) {
        g.append("circle")
          .attr("cx", r + 4)
          .attr("cy", -(r + 4))
          .attr("r", 5)
          .attr("fill", "#FFC857")
          .attr("stroke", "#000")
          .attr("stroke-width", 0.5);
        g.append("text")
          .attr("x", r + 4)
          .attr("y", -(r + 1))
          .attr("text-anchor", "middle")
          .attr("fill", "#000")
          .attr("font-size", 5)
          .attr("font-weight", "bold")
          .text("N");
      }

      // Flagged device red ring
      if (node.disposition === "flagged") {
        g.append("path")
          .attr("d", hexPath(r + 4))
          .attr("fill", "none")
          .attr("stroke", "#FF4D4F")
          .attr("stroke-width", 2)
          .attr("stroke-dasharray", "4,2");
        g.append("text")
          .attr("x", r + 8)
          .attr("y", r + 2)
          .attr("font-size", 10)
          .text("\u26A0");
      }

      // External device dashed border
      if (node.disposition === "external") {
        g.append("path")
          .attr("d", hexPath(r + 3))
          .attr("fill", "none")
          .attr("stroke", "#2FA4FF")
          .attr("stroke-width", 1)
          .attr("stroke-dasharray", "3,3")
          .attr("opacity", 0.6);
      }

      // Unregistered infra indicator
      if (node.is_infrastructure && node.disposition === "unknown" && node.confidence < 1.0) {
        g.append("path")
          .attr("d", hexPath(r + 5))
          .attr("fill", "none")
          .attr("stroke", "#FFC857")
          .attr("stroke-width", 1.5)
          .attr("stroke-dasharray", "4,3")
          .attr("opacity", 0.7);
        g.append("circle")
          .attr("cx", r + 6)
          .attr("cy", -(r + 4))
          .attr("r", 6)
          .attr("fill", "#FFC857")
          .attr("stroke", "#000")
          .attr("stroke-width", 0.5)
          .attr("cursor", "pointer");
        g.append("text")
          .attr("x", r + 6)
          .attr("y", -(r + 1))
          .attr("text-anchor", "middle")
          .attr("fill", "#000")
          .attr("font-size", 8)
          .attr("font-weight", "bold")
          .attr("cursor", "pointer")
          .text("?")
          .on("click", function (event: MouseEvent) {
            event.stopPropagation();
            callbacks.onContextMenu?.(node, event.clientX, event.clientY);
          });
      }

      // Pin icon
      if (node.position_source === "human") {
        g.append("text")
          .attr("class", "pin-icon")
          .attr("x", -(r + 6))
          .attr("y", -(r + 2))
          .attr("font-size", 10)
          .attr("text-anchor", "middle")
          .attr("cursor", "pointer")
          .text("\uD83D\uDCCC")
          .on("click", function (event) {
            event.stopPropagation();
            callbacks.onUnpin?.(node.id);
          });
      }

      // Hover
      g.on("mouseover", function (event) {
        d3.select(this).attr("filter", "url(#glow-selected)");
        showTooltip(event, node);
      })
        .on("mousemove", function (event) {
          if (tooltip) {
            tooltip.style.left = `${event.clientX + 12}px`;
            tooltip.style.top = `${event.clientY - 10}px`;
          }
        })
        .on("mouseout", function () {
          d3.select(this).attr("filter", statusFilter(node));
          hideTooltip();
        })
        .on("click", function () {
          selectedNodeId = node.id;
          layerNodes.selectAll(".topo-node").each(function () {
            const el = d3.select(this);
            const nid = el.attr("data-node-id");
            const n = nodeMap.get(nid || "");
            if (n) el.attr("filter", statusFilter(n));
          });
          d3.select(this).attr("filter", "url(#glow-selected)");
          callbacks.onNodeClick?.(node);
        })
        .on("contextmenu", function (event: MouseEvent) {
          event.preventDefault();
          event.stopPropagation();
          callbacks.onContextMenu?.(node, event.clientX, event.clientY);
        });

      // Drag behavior
      const drag = d3.drag<SVGGElement, unknown>()
        .on("drag", function (event) {
          d3.select(this).attr("transform", `translate(${event.x},${event.y})`);
          node.x = event.x;
          node.y = event.y;
          layerEdges.selectAll<SVGGElement, unknown>(".edge").each(function () {
            const eg = d3.select(this);
            const srcId = eg.attr("data-source");
            const tgtId = eg.attr("data-target");
            if (srcId === node.id || tgtId === node.id) {
              const src = nodeMap.get(srcId || "");
              const tgt = nodeMap.get(tgtId || "");
              if (src && tgt) {
                eg.select("line")
                  .attr("x1", src.x).attr("y1", src.y)
                  .attr("x2", tgt.x).attr("y2", tgt.y);
              }
            }
          });
          layerLabels.selectAll<SVGTextElement, unknown>(`[data-node-id="${CSS.escape(node.id)}"]`).each(function () {
            const el = d3.select(this);
            const isSubLabel = el.classed("node-sublabel");
            const labelX = node.is_infrastructure ? r + 8 : 0;
            const labelY = node.is_infrastructure ? 4 : r + 14;
            el.attr("x", event.x + labelX);
            el.attr("y", event.y + labelY + (isSubLabel ? 13 : 0));
          });
        })
        .on("end", function (event) {
          draggedPositions.set(node.id, { x: event.x, y: event.y });
          callbacks.onDragEnd?.(node.id, event.x, event.y);
        });

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      g.call(drag as any);

      // Node label
      if (visible) {
        const labelX = node.is_infrastructure ? r + 8 : 0;
        const stagger = node.is_infrastructure ? 0 : (epIdx % 2 === 0 ? 5 : -5);
        const labelY = node.is_infrastructure ? 4 : r + 14 + stagger;
        const anchor = node.is_infrastructure ? "start" : "middle";
        const fontSize = node.is_infrastructure ? 11 : 9;
        const maxLen = node.is_infrastructure ? INFRA_LABEL_MAX : ENDPOINT_LABEL_MAX;

        layerLabels.append("text")
          .attr("class", "node-label topo-node-hostname")
          .attr("data-node-id", node.id)
          .attr("x", node.x + labelX)
          .attr("y", node.y + labelY)
          .attr("text-anchor", anchor)
          .attr("fill", color)
          .attr("fill-opacity", 1)
          .attr("font-size", fontSize)
          .attr("font-family", "'Rajdhani', sans-serif")
          .attr("font-weight", node.is_infrastructure ? "700" : "600")
          .text(truncate(node.label, maxLen));

        // IP sublabel for infrastructure
        if (node.is_infrastructure && node.ip) {
          layerLabels.append("text")
            .attr("class", "node-sublabel topo-node-ip")
            .attr("data-node-id", node.id)
            .attr("x", node.x + labelX)
            .attr("y", node.y + labelY + 13)
            .attr("text-anchor", anchor)
            .attr("fill", "#6B7785")
            .attr("font-size", 9)
            .attr("font-family", "'Share Tech Mono', monospace")
            .text(node.ip);
        }
      }
    });
  }

  // ── Filter update ──
  function updateVisibility() {
    if (!currentData) return;

    layerNodes.selectAll<SVGGElement, unknown>(".topo-node").each(function () {
      const el = d3.select(this);
      const nid = el.attr("data-node-id");
      const node = nodeMap.get(nid || "");
      if (!node) return;
      const visible = isNodeVisible(node);
      el.attr("opacity", visible ? nodeOpacity(node) : 0);
    });

    layerLabels.selectAll<SVGTextElement, unknown>(".node-label, .node-sublabel").each(function () {
      const el = d3.select(this);
      const nid = el.attr("data-node-id");
      const node = nodeMap.get(nid || "");
      if (!node) return;
      el.attr("opacity", isNodeVisible(node) ? 1 : 0);
    });

    layerEdges.selectAll<SVGGElement, unknown>(".edge").each(function () {
      const eg = d3.select(this);
      const srcId = eg.attr("data-source");
      const tgtId = eg.attr("data-target");
      const src = nodeMap.get(srcId || "");
      const tgt = nodeMap.get(tgtId || "");
      if (!src || !tgt) return;
      const visible = isNodeVisible(src) && isNodeVisible(tgt);
      eg.attr("opacity", visible ? 1 : 0.05);
    });

    if (currentData.vlan_groups) {
      currentData.vlan_groups.forEach((group) => {
        const bg = layerVlanBg.select(`.vlan-bg-${group.vlan_id}`);
        if (!bg.empty()) {
          const visible = !vlanFilter || vlanFilter.has(group.vlan_id);
          bg.attr("opacity", visible ? 1 : 0.08);
        }
        // Also toggle drag overlays
        const dragEl = layerSectorDrag.select(`.sector-drag-${group.vlan_id}`);
        const resizeEl = layerSectorDrag.select(`.sector-resize-${group.vlan_id}`);
        const dVis = !vlanFilter || vlanFilter.has(group.vlan_id);
        if (!dragEl.empty()) dragEl.attr("pointer-events", dVis ? "all" : "none");
        if (!resizeEl.empty()) resizeEl.attr("pointer-events", dVis ? "all" : "none");
      });
    }
  }

  // ── Zoom-dependent label visibility ──
  function updateLabelVisibility() {
    const registeredKinds = new Set(["router", "managed_switch"]);

    layerLabels
      .selectAll<SVGTextElement, unknown>(".node-label")
      .each(function () {
        const el = d3.select(this);
        const nid = el.attr("data-node-id") || "";
        const node = nodeMap.get(nid);
        if (!node) return;
        if (!isNodeVisible(node)) {
          el.attr("opacity", 0);
          return;
        }
        if (node.is_infrastructure && registeredKinds.has(node.kind)) {
          el.attr("opacity", 1);
        } else {
          el.attr("opacity", currentScale > 0.5 ? 1 : 0);
        }
      });

    layerLabels
      .selectAll<SVGTextElement, unknown>(".node-sublabel")
      .each(function () {
        const el = d3.select(this);
        const nid = el.attr("data-node-id") || "";
        const node = nodeMap.get(nid);
        if (!node || !isNodeVisible(node)) {
          el.attr("opacity", 0);
          return;
        }
        el.attr("opacity", currentScale > 0.7 ? 1 : 0);
      });

    layerEdges.selectAll<SVGTextElement, unknown>("text").each(function () {
      d3.select(this).attr("opacity", currentScale > 0.8 ? 1 : 0);
    });
  }

  // ── Zoom-to-fit helper ──
  function zoomToFit(animate = false) {
    if (!currentData) return;
    if (currentData.nodes.length === 0 && currentData.vlan_groups.length === 0) return;

    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    currentData.nodes.forEach((n) => {
      if (n.x < minX) minX = n.x;
      if (n.y < minY) minY = n.y;
      if (n.x > maxX) maxX = n.x;
      if (n.y > maxY) maxY = n.y;
    });
    currentData.vlan_groups.forEach((g) => {
      if (g.bbox_x < minX) minX = g.bbox_x;
      if (g.bbox_y < minY) minY = g.bbox_y;
      if (g.bbox_x + g.bbox_w > maxX) maxX = g.bbox_x + g.bbox_w;
      if (g.bbox_y + g.bbox_h > maxY) maxY = g.bbox_y + g.bbox_h;
    });
    const pad = 80;
    minX -= pad; minY -= pad; maxX += pad; maxY += pad;
    const w = maxX - minX;
    const h = maxY - minY;
    const svgRect = svgElement.getBoundingClientRect();
    if (svgRect.width === 0 || svgRect.height === 0) return;
    const scaleX = svgRect.width / w;
    const scaleY = svgRect.height / h;
    const scale = Math.min(scaleX, scaleY, 1.0);
    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;
    const tx = svgRect.width / 2 - cx * scale;
    const ty = svgRect.height / 2 - cy * scale;

    const transform = d3.zoomIdentity.translate(tx, ty).scale(scale);
    if (animate) {
      svg.transition().duration(500).call(zoomBehavior.transform, transform);
    } else {
      svg.call(zoomBehavior.transform, transform);
    }
  }

  // ── Initial render ──
  renderStars();
  renderGrid();

  // ── Public API ──
  return {
    destroy() {
      destroyed = true;
      svg.selectAll("*").interrupt();
      svg.selectAll("*").remove();
      svg.on(".zoom", null);
      if (tooltip) {
        tooltip.remove();
        tooltip = null;
      }
    },

    render(data: NetworkTopologyResponse) {
      renderAll(data);
      if (!hasInitialFit) {
        hasInitialFit = true;
        zoomToFit(false);
      }
      updateLabelVisibility();
    },

    search(term: string): string[] {
      if (!term || !currentData) {
        layerNodes.selectAll(".topo-node").attr("opacity", function () {
          const nid = d3.select(this).attr("data-node-id");
          const n = nodeMap.get(nid || "");
          return n && isNodeVisible(n) ? 1 : 0;
        });
        layerLabels.selectAll<SVGTextElement, unknown>(".node-label, .node-sublabel").each(function () {
          const el = d3.select(this);
          const nid = el.attr("data-node-id") || "";
          const n = nodeMap.get(nid);
          el.attr("opacity", n && isNodeVisible(n) ? 1 : 0);
        });
        return [];
      }
      const matches: string[] = [];
      currentData.nodes.forEach((node) => {
        if (matchesSearch(node, term)) matches.push(node.id);
      });
      layerNodes.selectAll<SVGGElement, unknown>(".topo-node").each(function () {
        const el = d3.select(this);
        const nid = el.attr("data-node-id") || "";
        el.attr("opacity", matches.includes(nid) ? 1 : 0.1);
      });
      layerLabels.selectAll<SVGTextElement, unknown>(".node-label, .node-sublabel").each(function () {
        const el = d3.select(this);
        const nid = el.attr("data-node-id") || "";
        el.attr("opacity", matches.includes(nid) ? 1 : 0.1);
      });
      if (matches.length > 0) {
        const first = nodeMap.get(matches[0]);
        if (first) {
          const svgRect = svgElement.getBoundingClientRect();
          const scale = 1.5;
          svg.transition().duration(500).call(
            zoomBehavior.transform,
            d3.zoomIdentity
              .translate(svgRect.width / 2 - first.x * scale, svgRect.height / 2 - first.y * scale)
              .scale(scale),
          );
        }
      }
      return matches;
    },

    highlightNode(id: string) {
      selectedNodeId = id;
      layerNodes.selectAll<SVGGElement, unknown>(".topo-node").each(function () {
        const el = d3.select(this);
        const nid = el.attr("data-node-id");
        if (nid === id) {
          el.attr("filter", "url(#glow-selected)");
          const node = nodeMap.get(id);
          if (node) {
            const svgRect = svgElement.getBoundingClientRect();
            const scale = 1.5;
            svg.transition().duration(500).call(
              zoomBehavior.transform,
              d3.zoomIdentity
                .translate(svgRect.width / 2 - node.x * scale, svgRect.height / 2 - node.y * scale)
                .scale(scale),
            );
          }
        }
      });
    },

    clearSelection() {
      selectedNodeId = null;
      layerNodes.selectAll<SVGGElement, unknown>(".topo-node").each(function () {
        const el = d3.select(this);
        const nid = el.attr("data-node-id");
        const n = nodeMap.get(nid || "");
        if (n) el.attr("filter", statusFilter(n));
      });
      updateVisibility();
    },

    resetView() {
      zoomToFit(true);
    },

    setVlanFilter(vlans: Set<number> | null) {
      vlanFilter = vlans;
      updateVisibility();
    },

    setKindFilter(kinds: Set<string> | null) {
      kindFilter = kinds;
      updateVisibility();
    },

    setEndpointsVisible(visible: boolean) {
      showEndpoints = visible;
      updateVisibility();
    },

    clearDraggedPosition(nodeId: string) {
      draggedPositions.delete(nodeId);
    },
  };
}
