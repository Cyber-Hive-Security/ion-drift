// ============================================================
//  D3 Rendering Engine for Auto-Generated Network Topology
//  D3 owns the SVG canvas; React owns the UI chrome.
// ============================================================

import * as d3 from "d3";
import type {
  TopologyNode,
  TopologyEdge,
  TopologyVlanGroup,
  NetworkTopologyResponse,
} from "@/api/types";
import { VLAN_COLORS } from "@/constants/vlans";

// ─── Constants ──────────────────────────────────────────

const MAP_WIDTH = 4000;
const MAP_HEIGHT = 3000;

// ─── Public Types ───────────────────────────────────────

export interface TopologyCallbacks {
  onNodeClick?: (node: TopologyNode) => void;
  onDragEnd?: (nodeId: string, x: number, y: number) => void;
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
}

// ─── Factory ────────────────────────────────────────────

export function createTopologyMapInstance(
  svgElement: SVGSVGElement,
  callbacks: TopologyCallbacks,
): TopologyMapInstance {
  // ── All helpers scoped inside factory ──

  function nodeColor(node: TopologyNode): string {
    if (node.kind === "router") return "#ffd700";
    if (node.vlan_id != null && VLAN_COLORS[node.vlan_id]) return VLAN_COLORS[node.vlan_id];
    if (node.is_infrastructure) return "#00e5ff";
    return "#888888";
  }

  function nodeRadius(node: TopologyNode): number {
    switch (node.kind) {
      case "router": return 20;
      case "managed_switch":
      case "unmanaged_switch": return 16;
      case "access_point": return 14;
      case "server": return 10;
      case "camera":
      case "iot": return 7;
      default:
        return node.is_infrastructure ? 14 : 8;
    }
  }

  function nodeShape(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    g: d3.Selection<SVGGElement, any, any, any>,
    node: TopologyNode,
  ): void {
    const r = nodeRadius(node);
    const color = nodeColor(node);

    if (node.kind === "router") {
      // Rounded rectangle
      g.append("rect")
        .attr("x", -20)
        .attr("y", -15)
        .attr("width", 40)
        .attr("height", 30)
        .attr("rx", 6)
        .attr("fill", color)
        .attr("fill-opacity", 0.15)
        .attr("stroke", color)
        .attr("stroke-width", 2);
    } else if (node.kind === "managed_switch" || node.kind === "unmanaged_switch") {
      // Rectangle
      g.append("rect")
        .attr("x", -18)
        .attr("y", -12)
        .attr("width", 36)
        .attr("height", 24)
        .attr("rx", 3)
        .attr("fill", color)
        .attr("fill-opacity", 0.15)
        .attr("stroke", color)
        .attr("stroke-width", 1.5);
    } else if (node.kind === "access_point") {
      // Circle with signal arcs
      g.append("circle")
        .attr("r", r)
        .attr("fill", color)
        .attr("fill-opacity", 0.15)
        .attr("stroke", color)
        .attr("stroke-width", 1.5);
      // Signal arcs
      for (let i = 1; i <= 2; i++) {
        g.append("path")
          .attr("d", d3.arc()({
            innerRadius: r + i * 4,
            outerRadius: r + i * 4 + 1,
            startAngle: -Math.PI / 3,
            endAngle: Math.PI / 3,
          })!)
          .attr("fill", color)
          .attr("opacity", 0.4);
      }
    } else {
      // Circle for everything else
      g.append("circle")
        .attr("r", r)
        .attr("fill", color)
        .attr("fill-opacity", node.is_infrastructure ? 0.2 : 0.12)
        .attr("stroke", color)
        .attr("stroke-width", node.is_infrastructure ? 1.5 : 1);
    }
  }

  function edgeWidth(edge: TopologyEdge): number {
    switch (edge.kind) {
      case "trunk": return 2.5;
      case "uplink": return 2;
      case "access": return 0.8;
      case "wireless": return 0.8;
      default: return 1;
    }
  }

  function edgeDash(edge: TopologyEdge): string {
    return edge.kind === "wireless" ? "4,3" : "none";
  }

  function edgeColor(edge: TopologyEdge): string {
    if (edge.kind === "uplink") return "#ffd700";
    if (edge.kind === "trunk") return "#00e5ff";
    if (edge.vlans.length === 1 && VLAN_COLORS[edge.vlans[0]]) return VLAN_COLORS[edge.vlans[0]];
    return "#555555";
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
    // first_seen is Unix epoch in seconds
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

  addGlowFilter("glow-active", "#00ff88", 0.3, 4);
  addGlowFilter("glow-inactive", "#ff4444", 0.3, 4);
  addGlowFilter("glow-anomaly", "#ffaa00", 0.45, 5);
  addGlowFilter("glow-selected", "#ffffff", 0.5, 6);

  // Soft glow for general node hover
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

  // Zoom & pan
  const zoomGroup = svg.append("g").attr("id", "topo-zoom-group");
  const zoomBehavior = d3
    .zoom<SVGSVGElement, unknown>()
    .scaleExtent([0.1, 5])
    .on("zoom", (event) => {
      zoomGroup.attr("transform", event.transform);
    });
  svg.call(zoomBehavior);

  // SVG layers (bottom to top)
  const layerGrid = zoomGroup.append("g").attr("class", "layer-grid");
  const layerVlanBg = zoomGroup.append("g").attr("class", "layer-vlan-bg");
  const layerEdges = zoomGroup.append("g").attr("class", "layer-edges");
  const layerNodes = zoomGroup.append("g").attr("class", "layer-nodes");
  const layerLabels = zoomGroup.append("g").attr("class", "layer-labels");

  // ── Grid ──
  function renderGrid() {
    layerGrid.selectAll("*").remove();
    const gridSpacing = 60;
    for (let x = 0; x <= MAP_WIDTH; x += gridSpacing) {
      layerGrid
        .append("line")
        .attr("x1", x).attr("y1", 0)
        .attr("x2", x).attr("y2", MAP_HEIGHT)
        .attr("stroke", "#1a1a2e")
        .attr("stroke-width", 0.5);
    }
    for (let y = 0; y <= MAP_HEIGHT; y += gridSpacing) {
      layerGrid
        .append("line")
        .attr("x1", 0).attr("y1", y)
        .attr("x2", MAP_WIDTH).attr("y2", y)
        .attr("stroke", "#1a1a2e")
        .attr("stroke-width", 0.5);
    }
  }

  // ── Tooltip ──
  function createTooltip(): HTMLDivElement {
    if (tooltip) return tooltip;
    const div = document.createElement("div");
    div.style.cssText =
      "position:fixed;pointer-events:none;z-index:9999;background:rgba(10,10,30,0.95);" +
      "border:1px solid rgba(0,240,255,0.3);border-radius:6px;padding:8px 12px;" +
      "font-size:12px;color:#e0e0e0;max-width:300px;display:none;font-family:monospace;";
    document.body.appendChild(div);
    tooltip = div;
    return div;
  }

  function showTooltip(event: MouseEvent, node: TopologyNode) {
    const tip = createTooltip();
    const lines: string[] = [];
    lines.push(`<strong style="color:${nodeColor(node)}">${node.label}</strong>`);
    if (node.kind) lines.push(`<span style="color:#888">Kind:</span> ${node.kind}`);
    if (node.ip) lines.push(`<span style="color:#888">IP:</span> ${node.ip}`);
    if (node.mac) lines.push(`<span style="color:#888">MAC:</span> ${node.mac}`);
    if (node.vlan_id != null) lines.push(`<span style="color:#888">VLAN:</span> ${node.vlan_id}`);
    if (node.device_type) lines.push(`<span style="color:#888">Type:</span> ${node.device_type}`);
    if (node.manufacturer) lines.push(`<span style="color:#888">Mfg:</span> ${node.manufacturer}`);
    if (node.switch_port) lines.push(`<span style="color:#888">Port:</span> ${node.switch_port}`);
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
    // Ignored devices hidden by default
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
    // External devices dimmed
    if (node.disposition === "external") return 0.4;
    return 1;
  }

  // ── Main render ──
  function renderAll(data: NetworkTopologyResponse) {
    currentData = data;
    nodeMap.clear();
    data.nodes.forEach((n) => nodeMap.set(n.id, n));

    renderGrid();
    renderVlanBackgrounds(data.vlan_groups);
    renderEdges(data.edges);
    renderNodes(data.nodes);
  }

  // ── VLAN background sectors ──
  function renderVlanBackgrounds(groups: TopologyVlanGroup[]) {
    layerVlanBg.selectAll("*").remove();

    groups.forEach((group) => {
      if (group.node_count === 0) return;
      const color = group.color || VLAN_COLORS[group.vlan_id] || "#555";

      const g = layerVlanBg.append("g").attr("class", `vlan-bg-${group.vlan_id}`);

      // Background rectangle
      g.append("rect")
        .attr("x", group.bbox_x)
        .attr("y", group.bbox_y)
        .attr("width", group.bbox_w)
        .attr("height", group.bbox_h)
        .attr("rx", 12)
        .attr("fill", color)
        .attr("fill-opacity", 0.04)
        .attr("stroke", color)
        .attr("stroke-opacity", 0.15)
        .attr("stroke-width", 1);

      // VLAN label at top
      g.append("text")
        .attr("x", group.bbox_x + 12)
        .attr("y", group.bbox_y + 18)
        .attr("fill", color)
        .attr("fill-opacity", 0.5)
        .attr("font-size", 11)
        .attr("font-family", "monospace")
        .text(`VLAN ${group.vlan_id} — ${group.name}`);

      // Subnet label
      if (group.subnet) {
        g.append("text")
          .attr("x", group.bbox_x + 12)
          .attr("y", group.bbox_y + 32)
          .attr("fill", color)
          .attr("fill-opacity", 0.3)
          .attr("font-size", 9)
          .attr("font-family", "monospace")
          .text(group.subnet);
      }

      // Node count badge
      g.append("text")
        .attr("x", group.bbox_x + group.bbox_w - 12)
        .attr("y", group.bbox_y + 18)
        .attr("text-anchor", "end")
        .attr("fill", color)
        .attr("fill-opacity", 0.35)
        .attr("font-size", 10)
        .attr("font-family", "monospace")
        .text(`${group.node_count} devices`);
    });
  }

  // ── Edges ──
  function renderEdges(edges: TopologyEdge[]) {
    layerEdges.selectAll("*").remove();

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

      // Main line
      g.append("line")
        .attr("x1", src.x).attr("y1", src.y)
        .attr("x2", tgt.x).attr("y2", tgt.y)
        .attr("stroke", edgeColor(edge))
        .attr("stroke-width", edgeWidth(edge))
        .attr("stroke-dasharray", edgeDash(edge))
        .attr("stroke-opacity", edge.kind === "access" ? 0.3 : 0.6);

      // Port labels for trunk/uplink edges
      if ((edge.kind === "trunk" || edge.kind === "uplink") && (edge.source_port || edge.target_port)) {
        const mx = (src.x + tgt.x) / 2;
        const my = (src.y + tgt.y) / 2;
        const parts: string[] = [];
        if (edge.source_port) parts.push(edge.source_port);
        if (edge.target_port) parts.push(edge.target_port);
        const label = parts.join(" \u2194 ");

        g.append("text")
          .attr("x", mx)
          .attr("y", my - 6)
          .attr("text-anchor", "middle")
          .attr("fill", "#666")
          .attr("font-size", 8)
          .attr("font-family", "monospace")
          .text(label);
      }
    });
  }

  // ── Nodes ──
  function renderNodes(nodes: TopologyNode[]) {
    layerNodes.selectAll("*").remove();
    layerLabels.selectAll("*").remove();

    // Sort: infrastructure first (so endpoints render on top of z-stack)
    const sorted = [...nodes].sort((a, b) => {
      if (a.is_infrastructure && !b.is_infrastructure) return -1;
      if (!a.is_infrastructure && b.is_infrastructure) return 1;
      return 0;
    });

    sorted.forEach((node) => {
      const visible = isNodeVisible(node);
      const opacity = nodeOpacity(node);

      const g = layerNodes
        .append("g")
        .attr("class", `topo-node topo-node-${node.kind}`)
        .attr("data-node-id", node.id)
        .attr("transform", `translate(${node.x},${node.y})`)
        .attr("opacity", visible ? opacity : 0)
        .attr("cursor", "pointer")
        .attr("filter", node.status === "online" ? "url(#glow-active)" :
               node.status === "offline" ? "url(#glow-inactive)" : "");

      // Draw shape
      nodeShape(g, node);

      // "NEW" badge for recently discovered
      if (isNew(node)) {
        g.append("circle")
          .attr("cx", nodeRadius(node) + 4)
          .attr("cy", -(nodeRadius(node) + 4))
          .attr("r", 5)
          .attr("fill", "#ffaa00")
          .attr("stroke", "#000")
          .attr("stroke-width", 0.5);
        g.append("text")
          .attr("x", nodeRadius(node) + 4)
          .attr("y", -(nodeRadius(node) + 1))
          .attr("text-anchor", "middle")
          .attr("fill", "#000")
          .attr("font-size", 5)
          .attr("font-weight", "bold")
          .text("N");
      }

      // Flagged device red ring
      if (node.disposition === "flagged") {
        g.append("circle")
          .attr("r", nodeRadius(node) + 4)
          .attr("fill", "none")
          .attr("stroke", "#ef4444")
          .attr("stroke-width", 2)
          .attr("stroke-dasharray", "4,2");
        g.append("text")
          .attr("x", nodeRadius(node) + 8)
          .attr("y", nodeRadius(node) + 2)
          .attr("font-size", 10)
          .text("\u26A0"); // ⚠ warning sign
      }

      // External device dashed border
      if (node.disposition === "external") {
        g.append("circle")
          .attr("r", nodeRadius(node) + 3)
          .attr("fill", "none")
          .attr("stroke", "#3b82f6")
          .attr("stroke-width", 1)
          .attr("stroke-dasharray", "3,3")
          .attr("opacity", 0.6);
      }

      // Pin icon for human-positioned nodes
      if (node.position_source === "human") {
        g.append("text")
          .attr("x", -(nodeRadius(node) + 6))
          .attr("y", -(nodeRadius(node) + 2))
          .attr("font-size", 10)
          .attr("text-anchor", "middle")
          .text("\uD83D\uDCCC");
      }

      // Hover
      g.on("mouseover", function (event) {
        d3.select(this).attr("filter", "url(#glow-soft)");
        showTooltip(event, node);
      })
        .on("mousemove", function (event) {
          if (tooltip) {
            tooltip.style.left = `${event.clientX + 12}px`;
            tooltip.style.top = `${event.clientY - 10}px`;
          }
        })
        .on("mouseout", function () {
          // Restore status-based filter
          d3.select(this).attr("filter",
            selectedNodeId === node.id ? "url(#glow-selected)" :
            node.status === "online" ? "url(#glow-active)" :
            node.status === "offline" ? "url(#glow-inactive)" : "",
          );
          hideTooltip();
        })
        .on("click", function () {
          selectedNodeId = node.id;
          // Clear previous selection highlight
          layerNodes.selectAll(".topo-node").each(function () {
            const el = d3.select(this);
            const nid = el.attr("data-node-id");
            const n = nodeMap.get(nid || "");
            if (n) {
              el.attr("filter",
                n.status === "online" ? "url(#glow-active)" :
                n.status === "offline" ? "url(#glow-inactive)" : "",
              );
            }
          });
          // Highlight selected
          d3.select(this).attr("filter", "url(#glow-selected)");
          callbacks.onNodeClick?.(node);
        });

      // Drag behavior
      const drag = d3.drag<SVGGElement, unknown>()
        .on("drag", function (event) {
          d3.select(this).attr("transform", `translate(${event.x},${event.y})`);
          // Update node coords in our map for edge re-rendering
          node.x = event.x;
          node.y = event.y;
          // Update connected edges
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
        })
        .on("end", function (event) {
          callbacks.onDragEnd?.(node.id, event.x, event.y);
        });

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      g.call(drag as any);

      // Node label (below node for endpoints, to the right for infrastructure)
      if (visible) {
        const labelX = node.is_infrastructure ? nodeRadius(node) + 8 : 0;
        const labelY = node.is_infrastructure ? 4 : nodeRadius(node) + 14;
        const anchor = node.is_infrastructure ? "start" : "middle";
        const fontSize = node.is_infrastructure ? 11 : 9;

        layerLabels.append("text")
          .attr("class", "node-label")
          .attr("data-node-id", node.id)
          .attr("x", node.x + labelX)
          .attr("y", node.y + labelY)
          .attr("text-anchor", anchor)
          .attr("fill", nodeColor(node))
          .attr("fill-opacity", 0.8)
          .attr("font-size", fontSize)
          .attr("font-family", "monospace")
          .attr("font-weight", node.is_infrastructure ? "bold" : "normal")
          .text(node.label);

        // IP sublabel for infrastructure
        if (node.is_infrastructure && node.ip) {
          layerLabels.append("text")
            .attr("class", "node-sublabel")
            .attr("data-node-id", node.id)
            .attr("x", node.x + labelX)
            .attr("y", node.y + labelY + 13)
            .attr("text-anchor", anchor)
            .attr("fill", "#666")
            .attr("font-size", 9)
            .attr("font-family", "monospace")
            .text(node.ip);
        }
      }
    });
  }

  // ── Filter update (re-renders visibility without full rebuild) ──
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

    // Update VLAN backgrounds
    if (currentData.vlan_groups) {
      currentData.vlan_groups.forEach((group) => {
        const bg = layerVlanBg.select(`.vlan-bg-${group.vlan_id}`);
        if (!bg.empty()) {
          const visible = !vlanFilter || vlanFilter.has(group.vlan_id);
          bg.attr("opacity", visible ? 1 : 0.08);
        }
      });
    }
  }

  // ── Initial grid render ──
  renderGrid();

  // ── Public API ──
  return {
    destroy() {
      svg.selectAll("*").remove();
      svg.on(".zoom", null);
      if (tooltip) {
        tooltip.remove();
        tooltip = null;
      }
    },

    render(data: NetworkTopologyResponse) {
      renderAll(data);
      // Auto-fit: zoom to show all nodes with padding
      if (data.nodes.length > 0) {
        let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        data.nodes.forEach((n) => {
          if (n.x < minX) minX = n.x;
          if (n.y < minY) minY = n.y;
          if (n.x > maxX) maxX = n.x;
          if (n.y > maxY) maxY = n.y;
        });
        const pad = 200;
        minX -= pad; minY -= pad; maxX += pad; maxY += pad;
        const w = maxX - minX;
        const h = maxY - minY;
        const svgRect = svgElement.getBoundingClientRect();
        const scaleX = svgRect.width / w;
        const scaleY = svgRect.height / h;
        const scale = Math.min(scaleX, scaleY, 1.5);
        const cx = (minX + maxX) / 2;
        const cy = (minY + maxY) / 2;
        const tx = svgRect.width / 2 - cx * scale;
        const ty = svgRect.height / 2 - cy * scale;

        svg.call(
          zoomBehavior.transform,
          d3.zoomIdentity.translate(tx, ty).scale(scale),
        );
      }
    },

    search(term: string): string[] {
      if (!term || !currentData) {
        layerNodes.selectAll(".topo-node").attr("opacity", function () {
          const nid = d3.select(this).attr("data-node-id");
          const n = nodeMap.get(nid || "");
          return n && isNodeVisible(n) ? 1 : 0;
        });
        return [];
      }
      const matches: string[] = [];
      currentData.nodes.forEach((node) => {
        if (matchesSearch(node, term)) matches.push(node.id);
      });
      // Dim non-matching, highlight matching
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
      // Zoom to first match
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
          // Zoom to it
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
        if (n) {
          el.attr("filter",
            n.status === "online" ? "url(#glow-active)" :
            n.status === "offline" ? "url(#glow-inactive)" : "",
          );
        }
      });
      updateVisibility();
    },

    resetView() {
      svg.transition().duration(500).call(
        zoomBehavior.transform,
        d3.zoomIdentity,
      );
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
  };
}
