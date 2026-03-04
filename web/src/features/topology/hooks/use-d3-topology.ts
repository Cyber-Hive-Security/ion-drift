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
import { escHtml } from "@/lib/utils";

// ─── Constants ──────────────────────────────────────────

const MAP_WIDTH = 4000;
const MAP_HEIGHT = 3000;
const INFRA_LABEL_MAX = 24;
const ENDPOINT_LABEL_MAX = 16;

// ─── Public Types ───────────────────────────────────────

export interface TopologyCallbacks {
  onNodeClick?: (node: TopologyNode) => void;
  onDragEnd?: (nodeId: string, x: number, y: number) => void;
  onUnpin?: (nodeId: string) => void;
  onSectorDragEnd?: (vlanId: number, x: number, y: number, width: number, height: number) => void;
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
    return "#aaaaaa";
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
      g.append("rect")
        .attr("x", -20)
        .attr("y", -15)
        .attr("width", 40)
        .attr("height", 30)
        .attr("rx", 6)
        .attr("fill", color)
        .attr("fill-opacity", 0.3)
        .attr("stroke", color)
        .attr("stroke-width", 2.5);
    } else if (node.kind === "managed_switch" || node.kind === "unmanaged_switch") {
      g.append("rect")
        .attr("x", -18)
        .attr("y", -12)
        .attr("width", 36)
        .attr("height", 24)
        .attr("rx", 3)
        .attr("fill", color)
        .attr("fill-opacity", 0.25)
        .attr("stroke", color)
        .attr("stroke-width", 2);
    } else if (node.kind === "access_point") {
      g.append("circle")
        .attr("r", r)
        .attr("fill", color)
        .attr("fill-opacity", 0.25)
        .attr("stroke", color)
        .attr("stroke-width", 2);
      for (let i = 1; i <= 2; i++) {
        g.append("path")
          .attr("d", d3.arc()({
            innerRadius: r + i * 4,
            outerRadius: r + i * 4 + 1,
            startAngle: -Math.PI / 3,
            endAngle: Math.PI / 3,
          })!)
          .attr("fill", color)
          .attr("opacity", 0.6);
      }
    } else {
      g.append("circle")
        .attr("r", r)
        .attr("fill", color)
        .attr("fill-opacity", node.is_infrastructure ? 0.3 : 0.2)
        .attr("stroke", color)
        .attr("stroke-width", node.is_infrastructure ? 2 : 1.5);
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
    if (edge.kind === "wireless") return "4,3";
    // Inferred access edge: device is downstream but exact port unknown
    if (edge.kind === "access" && !edge.source_port) return "3,3";
    return "none";
  }

  function edgeColor(edge: TopologyEdge): string {
    if (edge.kind === "uplink") return "#ffd700";
    if (edge.kind === "trunk") return "#00e5ff";
    if (edge.vlans.length === 1 && VLAN_COLORS[edge.vlans[0]]) return VLAN_COLORS[edge.vlans[0]];
    return "#666666";
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
  // Positions set by drag — survives re-renders until backend confirms
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

  addGlowFilter("glow-active", "#00ff88", 0.4, 4);
  addGlowFilter("glow-inactive", "#ff4444", 0.4, 4);
  addGlowFilter("glow-anomaly", "#ffaa00", 0.5, 5);
  addGlowFilter("glow-selected", "#ffffff", 0.6, 6);

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
    .scaleExtent([0.05, 5])
    .on("zoom", (event) => {
      zoomGroup.attr("transform", event.transform);
      currentScale = event.transform.k;
      updateLabelVisibility();
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
        .attr("stroke", "#1e1e3a")
        .attr("stroke-width", 0.5);
    }
    for (let y = 0; y <= MAP_HEIGHT; y += gridSpacing) {
      layerGrid
        .append("line")
        .attr("x1", 0).attr("y1", y)
        .attr("x2", MAP_WIDTH).attr("y2", y)
        .attr("stroke", "#1e1e3a")
        .attr("stroke-width", 0.5);
    }
  }

  // ── Tooltip ──
  function createTooltip(): HTMLDivElement {
    if (tooltip) return tooltip;
    const div = document.createElement("div");
    div.style.cssText =
      "position:fixed;pointer-events:none;z-index:9999;background:rgba(10,10,30,0.95);" +
      "border:1px solid rgba(0,240,255,0.4);border-radius:6px;padding:8px 12px;" +
      "font-size:12px;color:#e0e0e0;max-width:300px;display:none;font-family:monospace;";
    document.body.appendChild(div);
    tooltip = div;
    return div;
  }

  function showTooltip(event: MouseEvent, node: TopologyNode) {
    const tip = createTooltip();
    const lines: string[] = [];
    lines.push(`<strong style="color:${nodeColor(node)}">${escHtml(node.label)}</strong>`);
    if (node.kind) lines.push(`<span style="color:#999">Kind:</span> ${escHtml(node.kind)}`);
    if (node.ip) lines.push(`<span style="color:#999">IP:</span> ${escHtml(node.ip)}`);
    if (node.mac) lines.push(`<span style="color:#999">MAC:</span> ${escHtml(node.mac)}`);
    if (node.vlan_id != null) lines.push(`<span style="color:#999">VLAN:</span> ${node.vlan_id}`);
    if (node.device_type) lines.push(`<span style="color:#999">Type:</span> ${escHtml(node.device_type)}`);
    if (node.manufacturer) lines.push(`<span style="color:#999">Mfg:</span> ${escHtml(node.manufacturer)}`);
    if (node.switch_port) {
      lines.push(`<span style="color:#999">Port:</span> ${escHtml(node.switch_port)}`);
    } else if (node.parent_id) {
      lines.push(`<span style="color:#999">Port:</span> <em style="color:#777">unknown — downstream of ${escHtml(node.parent_id)}</em>`);
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
    return "";
  }

  // ── Main render ──
  function renderAll(data: NetworkTopologyResponse) {
    currentData = data;
    nodeMap.clear();

    // Merge locally-dragged positions to prevent snap-back from stale refetches.
    // The backend topology cache only updates on recompute (120s), so refetches
    // after a position save return stale auto-computed positions.
    data.nodes.forEach((n) => {
      const dragged = draggedPositions.get(n.id);
      if (dragged) {
        if (n.position_source === "human") {
          // Backend confirmed the save — clear local override
          draggedPositions.delete(n.id);
        } else {
          // Override with local position until backend catches up
          n.x = dragged.x;
          n.y = dragged.y;
          n.position_source = "human";
        }
      }
      nodeMap.set(n.id, n);
    });

    renderGrid();
    renderVlanBackgrounds(data.vlan_groups);
    renderEdges(data.edges);
    renderNodes(data.nodes);
  }

  // ── VLAN background sectors ──
  function renderVlanBackgrounds(groups: TopologyVlanGroup[]) {
    layerVlanBg.selectAll("*").remove();

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
        .attr("fill-opacity", 0.07)
        .attr("stroke", color)
        .attr("stroke-opacity", 0.3)
        .attr("stroke-width", group.position_source === "human" ? 2 : 1);

      const headerLabel = g.append("text")
        .attr("class", "sector-header")
        .attr("x", group.bbox_x + 12)
        .attr("y", group.bbox_y + 18)
        .attr("fill", color)
        .attr("fill-opacity", 0.8)
        .attr("font-size", 12)
        .attr("font-family", "monospace")
        .attr("font-weight", "bold")
        .attr("cursor", "grab")
        .text(`VLAN ${group.vlan_id} \u2014 ${group.name}`);

      if (group.subnet) {
        g.append("text")
          .attr("class", "sector-subnet")
          .attr("x", group.bbox_x + 12)
          .attr("y", group.bbox_y + 33)
          .attr("fill", color)
          .attr("fill-opacity", 0.5)
          .attr("font-size", 10)
          .attr("font-family", "monospace")
          .text(group.subnet);
      }

      g.append("text")
        .attr("class", "sector-count")
        .attr("x", group.bbox_x + group.bbox_w - 12)
        .attr("y", group.bbox_y + 18)
        .attr("text-anchor", "end")
        .attr("fill", color)
        .attr("fill-opacity", 0.5)
        .attr("font-size", 10)
        .attr("font-family", "monospace")
        .text(`${group.node_count} devices`);

      // Pin indicator for human-positioned sectors
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

      // ── Sector drag (on header label) ──
      let dragStartX = 0;
      let dragStartY = 0;
      let origBboxX = group.bbox_x;
      let origBboxY = group.bbox_y;

      const sectorDrag = d3.drag<SVGTextElement, unknown>()
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

          // Move the entire sector group
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
          g.select(".resize-handle")
            .attr("x", newX + group.bbox_w - 14).attr("y", newY + group.bbox_h - 14);

          // Move contained nodes by the same delta
          if (currentData) {
            currentData.nodes.forEach((node) => {
              if (node.vlan_id === group.vlan_id) {
                const nodeG = layerNodes.select(`[data-node-id="${node.id}"]`);
                if (!nodeG.empty()) {
                  const nx = node.x + dx;
                  const ny = node.y + dy;
                  nodeG.attr("transform", `translate(${nx},${ny})`);
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

          // Persist node positions for contained nodes
          if (currentData) {
            currentData.nodes.forEach((node) => {
              if (node.vlan_id === group.vlan_id) {
                node.x += dx;
                node.y += dy;
                // Update labels
                layerLabels.selectAll(`[data-node-id="${node.id}"]`).each(function () {
                  const el = d3.select(this);
                  const curX = parseFloat(el.attr("x")) || 0;
                  const curY = parseFloat(el.attr("y")) || 0;
                  el.attr("x", curX + dx).attr("y", curY + dy);
                });
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
              }
            });
          }

          // Update group data
          group.bbox_x = newX;
          group.bbox_y = newY;
          group.position_source = "human";
          callbacks.onSectorDragEnd?.(group.vlan_id, newX, newY, group.bbox_w, group.bbox_h);
        });

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      headerLabel.call(sectorDrag as any);

      // ── Resize handle (bottom-right corner) ──
      const handleSize = 12;
      g.append("rect")
        .attr("class", "resize-handle")
        .attr("x", group.bbox_x + group.bbox_w - handleSize - 2)
        .attr("y", group.bbox_y + group.bbox_h - handleSize - 2)
        .attr("width", handleSize)
        .attr("height", handleSize)
        .attr("rx", 2)
        .attr("fill", color)
        .attr("fill-opacity", 0.2)
        .attr("stroke", color)
        .attr("stroke-opacity", 0.4)
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
              d3.select(this)
                .attr("x", group.bbox_x + newW - handleSize - 2)
                .attr("y", group.bbox_y + newH - handleSize - 2);
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

      g.append("line")
        .attr("x1", src.x).attr("y1", src.y)
        .attr("x2", tgt.x).attr("y2", tgt.y)
        .attr("stroke", edgeColor(edge))
        .attr("stroke-width", edgeWidth(edge))
        .attr("stroke-dasharray", edgeDash(edge))
        .attr("stroke-opacity", edge.kind === "access" ? 0.5 : 0.85);

      // Port labels for trunk/uplink: place near each end instead of midpoint
      if ((edge.kind === "trunk" || edge.kind === "uplink") && (edge.source_port || edge.target_port)) {
        const dx = tgt.x - src.x;
        const dy = tgt.y - src.y;

        if (edge.source_port) {
          g.append("text")
            .attr("x", src.x + dx * 0.15)
            .attr("y", src.y + dy * 0.15 - 6)
            .attr("text-anchor", "middle")
            .attr("fill", "#888")
            .attr("font-size", 8)
            .attr("font-family", "monospace")
            .text(edge.source_port);
        }
        if (edge.target_port) {
          g.append("text")
            .attr("x", src.x + dx * 0.85)
            .attr("y", src.y + dy * 0.85 - 6)
            .attr("text-anchor", "middle")
            .attr("fill", "#888")
            .attr("font-size", 8)
            .attr("font-family", "monospace")
            .text(edge.target_port);
        }
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

    let endpointIdx = 0;
    sorted.forEach((node) => {
      const visible = isNodeVisible(node);
      const opacity = nodeOpacity(node);
      const epIdx = node.is_infrastructure ? -1 : endpointIdx++;

      const g = layerNodes
        .append("g")
        .attr("class", `topo-node topo-node-${node.kind}`)
        .attr("data-node-id", node.id)
        .attr("transform", `translate(${node.x},${node.y})`)
        .attr("opacity", visible ? opacity : 0)
        .attr("cursor", "pointer")
        .attr("filter", statusFilter(node));

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
          .text("\u26A0");
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

      // Pin icon for human-positioned nodes — click to unpin
      if (node.position_source === "human") {
        g.append("text")
          .attr("class", "pin-icon")
          .attr("x", -(nodeRadius(node) + 6))
          .attr("y", -(nodeRadius(node) + 2))
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
          d3.select(this).attr("filter", statusFilter(node));
          hideTooltip();
        })
        .on("click", function () {
          selectedNodeId = node.id;
          // Clear previous selection highlight
          layerNodes.selectAll(".topo-node").each(function () {
            const el = d3.select(this);
            const nid = el.attr("data-node-id");
            const n = nodeMap.get(nid || "");
            if (n) el.attr("filter", statusFilter(n));
          });
          // Highlight selected
          d3.select(this).attr("filter", "url(#glow-selected)");
          callbacks.onNodeClick?.(node);
        });

      // Drag behavior
      const drag = d3.drag<SVGGElement, unknown>()
        .on("drag", function (event) {
          d3.select(this).attr("transform", `translate(${event.x},${event.y})`);
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
          // Update label position
          layerLabels.selectAll<SVGTextElement, unknown>(`[data-node-id="${node.id}"]`).each(function () {
            const el = d3.select(this);
            const isSubLabel = el.classed("node-sublabel");
            const labelX = node.is_infrastructure ? nodeRadius(node) + 8 : 0;
            const labelY = node.is_infrastructure ? 4 : nodeRadius(node) + 14;
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
        const labelX = node.is_infrastructure ? nodeRadius(node) + 8 : 0;
        // Stagger endpoint labels: odd-index 5px higher, even-index 5px lower
        const stagger = node.is_infrastructure ? 0 : (epIdx % 2 === 0 ? 5 : -5);
        const labelY = node.is_infrastructure ? 4 : nodeRadius(node) + 14 + stagger;
        const anchor = node.is_infrastructure ? "start" : "middle";
        const fontSize = node.is_infrastructure ? 11 : 9;
        const maxLen = node.is_infrastructure ? INFRA_LABEL_MAX : ENDPOINT_LABEL_MAX;

        layerLabels.append("text")
          .attr("class", "node-label")
          .attr("data-node-id", node.id)
          .attr("x", node.x + labelX)
          .attr("y", node.y + labelY)
          .attr("text-anchor", anchor)
          .attr("fill", nodeColor(node))
          .attr("fill-opacity", 1)
          .attr("font-size", fontSize)
          .attr("font-family", "monospace")
          .attr("font-weight", node.is_infrastructure ? "bold" : "normal")
          .text(truncate(node.label, maxLen));

        // IP sublabel for infrastructure
        if (node.is_infrastructure && node.ip) {
          layerLabels.append("text")
            .attr("class", "node-sublabel")
            .attr("data-node-id", node.id)
            .attr("x", node.x + labelX)
            .attr("y", node.y + labelY + 13)
            .attr("text-anchor", anchor)
            .attr("fill", "#888")
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

  // ── Zoom-dependent label visibility ──
  function updateLabelVisibility() {
    // Registered infrastructure labels (router, managed_switch): always visible
    // Unregistered infrastructure labels (WAPs, unmanaged switches): scale > 0.5
    // Endpoint labels: visible at scale > 0.5
    // IP sublabels: visible at scale > 0.7
    // Port labels (on edges): visible at scale > 0.8
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
    // Need at least nodes OR vlan_groups to compute a bounding box
    if (currentData.nodes.length === 0 && currentData.vlan_groups.length === 0) return;

    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    currentData.nodes.forEach((n) => {
      if (n.x < minX) minX = n.x;
      if (n.y < minY) minY = n.y;
      if (n.x > maxX) maxX = n.x;
      if (n.y > maxY) maxY = n.y;
    });
    // Also incorporate VLAN group bounding boxes (includes empty sectors)
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
    // Cap at 1.0 to prevent over-zoom; no floor so wide layouts fit
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
      // Only auto-fit on the FIRST render. Subsequent data refreshes
      // preserve the user's current zoom/pan position.
      if (!hasInitialFit) {
        hasInitialFit = true;
        zoomToFit(false);
      }
      // Ensure labels respect current zoom level after re-render
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
