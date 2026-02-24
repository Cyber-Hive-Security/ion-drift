// ============================================================
//  Core D3 Rendering Engine for the Network Map
//  D3 owns the SVG canvas; React owns the UI chrome.
// ============================================================

// Extend SVGLineElement for connection tooltip storage
declare global {
  interface SVGLineElement {
    __connTooltip?: HTMLDivElement;
  }
}

import * as d3 from "d3";
import type {
  NetworkNode,
  Connection,
  MapCallbacks,
  MapInstance,
  VlanLayout,
} from "../types";
import type { DeviceStatus, InterfaceStatus } from "@/api/types";
import {
  MAP_WIDTH,
  MAP_HEIGHT,
  HEX_RADIUS,
  ICON_PATHS,
  VLAN_LAYOUT as VLAN_LAYOUT_INIT,
  POSITIONS_25,
} from "../constants";
import {
  VLAN_CONFIG,
  NODE_TYPES,
  NODES_RAW,
  CONNECTIONS,
  CONNECTION_STYLES,
} from "../data";

// ─── Helpers ────────────────────────────────────────────

function hexPath(r: number): string {
  const pts: [number, number][] = [];
  for (let i = 0; i < 6; i++) {
    const angle = (Math.PI / 3) * i - Math.PI / 6;
    pts.push([r * Math.cos(angle), r * Math.sin(angle)]);
  }
  return "M" + pts.map((p) => p.join(",")).join("L") + "Z";
}

function getIconPath(type: string): string {
  const t = NODE_TYPES[type];
  if (!t) return ICON_PATHS.vm;
  return ICON_PATHS[t.icon] || ICON_PATHS.vm;
}

function getNodeColor(node: NetworkNode): string {
  return NODE_TYPES[node.type]?.color || "#888";
}

function matchesSearch(node: NetworkNode, term: string): boolean {
  const fields = [
    node.hostname,
    node.ip,
    node.role,
    node.id,
    String(node.vlan),
    VLAN_CONFIG[node.vlan]?.name || "",
    NODE_TYPES[node.type]?.label || "",
  ];
  if (node.containers) {
    node.containers.forEach((c) => {
      fields.push(c.name, c.role || "", c.ports || "");
    });
  }
  if (node.details) node.details.forEach((d) => fields.push(d));
  return fields.some((f) => f && f.toLowerCase().includes(term));
}

// ─── Factory ────────────────────────────────────────────

export function createMapInstance(
  svgElement: SVGSVGElement,
  callbacks: MapCallbacks,
): MapInstance {
  // ── Throughput animation helpers (scoped inside factory to avoid TDZ issues) ──

  function vlanForIp(ip: string): number | null {
    const parts = ip.split(".");
    if (parts.length !== 4) return null;
    const prefix3 = `${parts[0]}.${parts[1]}.${parts[2]}`;
    const vlanKeys = Object.keys(VLAN_CONFIG);
    for (const vlan of vlanKeys) {
      const cfg = VLAN_CONFIG[+vlan];
      if (cfg && cfg.subnet.startsWith(prefix3 + ".")) return +vlan;
    }
    return null;
  }

  function findVlanIface(
    vlanId: number,
    ifaceMap: Map<string, InterfaceStatus>,
  ): InterfaceStatus | undefined {
    for (const pattern of [`vlan${vlanId}`, `vlan-${vlanId}`, `VLAN${vlanId}`]) {
      const iface = ifaceMap.get(pattern);
      if (iface) return iface;
    }
    for (const [name, iface] of ifaceMap) {
      if (name.toLowerCase() === `vlan${vlanId}`) return iface;
    }
    return undefined;
  }

  function rateToDuration(rateBps: number): number {
    if (rateBps <= 0) return 6000;
    const logRate = Math.log10(rateBps);
    return Math.max(300, Math.min(6000, 6500 - logRate * 700));
  }

  function rateToWidth(rateBps: number, baseWidth: number): number {
    if (rateBps <= 0) return baseWidth;
    return Math.min(baseWidth + 4, baseWidth + Math.log10(rateBps + 1) / 3);
  }

  // ── Deep-copy mutable state ──
  const nodes: NetworkNode[] = NODES_RAW.map((n) => ({
    ...n,
    specs: { ...n.specs },
    details: [...n.details],
    containers: n.containers ? n.containers.map((c) => ({ ...c })) : undefined,
    x: 0,
    y: 0,
  }));

  const connections: Connection[] = CONNECTIONS.map((c) => ({ ...c }));

  // Deep-copy VLAN layout so dragging doesn't mutate the shared constant
  const vlanLayout: Record<number, VlanLayout> = {};
  for (const [k, v] of Object.entries(VLAN_LAYOUT_INIT)) {
    vlanLayout[+k] = { ...v };
  }

  const nodeById: Record<string, NetworkNode> = {};
  nodes.forEach((n) => {
    nodeById[n.id] = n;
  });

  let showContainers = false;

  // ── Layout nodes ──
  const cx25 = vlanLayout[25].cx;
  const cy25 = vlanLayout[25].cy;
  const vlanGroups: Record<number, NetworkNode[]> = {};
  nodes.forEach((n) => {
    if (!vlanGroups[n.vlan]) vlanGroups[n.vlan] = [];
    vlanGroups[n.vlan].push(n);
  });

  (vlanGroups[25] || []).forEach((n) => {
    const pos = POSITIONS_25[n.id];
    if (pos) {
      n.x = cx25 + pos.x;
      n.y = cy25 + pos.y;
    } else {
      n.x = cx25 + (Math.random() - 0.5) * 600;
      n.y = cy25 + (Math.random() - 0.5) * 400;
    }
  });

  Object.keys(vlanGroups).forEach((vlan) => {
    if (+vlan === 25) return;
    const group = vlanGroups[+vlan];
    const layout = vlanLayout[+vlan];
    if (!layout) return;
    const cols = Math.ceil(Math.sqrt(group.length));
    const spacing = 80;
    group.forEach((n, i) => {
      const row = Math.floor(i / cols);
      const col = i % cols;
      n.x =
        layout.cx - ((cols - 1) * spacing) / 2 + col * spacing;
      n.y =
        layout.cy -
        ((Math.ceil(group.length / cols) - 1) * spacing) / 2 +
        row * spacing;
    });
  });

  // ── SVG setup ──
  const svg = d3
    .select(svgElement)
    .attr("viewBox", `0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`)
    .attr("preserveAspectRatio", "xMidYMid meet");

  // Clear any previous render (React strict mode double-mount)
  svg.selectAll("*").remove();

  const defs = svg.append("defs");

  // Glow filters
  (
    [
      ["glow-soft", 3],
      ["glow-strong", 6],
    ] as [string, number][]
  ).forEach(([id, dev]) => {
    const f = defs
      .append("filter")
      .attr("id", id)
      .attr("x", "-50%")
      .attr("y", "-50%")
      .attr("width", "200%")
      .attr("height", "200%");
    f.append("feGaussianBlur").attr("stdDeviation", dev).attr("result", "blur");
    const merge = f.append("feMerge");
    merge.append("feMergeNode").attr("in", "blur");
    merge.append("feMergeNode").attr("in", "SourceGraphic");
  });

  // Live status glow filters (green = active, red = inactive)
  {
    const fActive = defs
      .append("filter")
      .attr("id", "glow-active")
      .attr("x", "-50%")
      .attr("y", "-50%")
      .attr("width", "200%")
      .attr("height", "200%");
    fActive.append("feGaussianBlur").attr("stdDeviation", 4).attr("result", "blur");
    // Tint the glow green
    fActive
      .append("feFlood")
      .attr("flood-color", "#00ff88")
      .attr("flood-opacity", 0.3)
      .attr("result", "color");
    fActive
      .append("feComposite")
      .attr("in", "color")
      .attr("in2", "blur")
      .attr("operator", "in")
      .attr("result", "tinted");
    const mActive = fActive.append("feMerge");
    mActive.append("feMergeNode").attr("in", "tinted");
    mActive.append("feMergeNode").attr("in", "SourceGraphic");

    const fInactive = defs
      .append("filter")
      .attr("id", "glow-inactive")
      .attr("x", "-50%")
      .attr("y", "-50%")
      .attr("width", "200%")
      .attr("height", "200%");
    fInactive.append("feGaussianBlur").attr("stdDeviation", 4).attr("result", "blur");
    fInactive
      .append("feFlood")
      .attr("flood-color", "#ff4444")
      .attr("flood-opacity", 0.3)
      .attr("result", "color");
    fInactive
      .append("feComposite")
      .attr("in", "color")
      .attr("in2", "blur")
      .attr("operator", "in")
      .attr("result", "tinted");
    const mInactive = fInactive.append("feMerge");
    mInactive.append("feMergeNode").attr("in", "tinted");
    mInactive.append("feMergeNode").attr("in", "SourceGraphic");

    // Anomaly glow — amber/orange
    const fAnomaly = defs
      .append("filter")
      .attr("id", "glow-anomaly")
      .attr("x", "-50%")
      .attr("y", "-50%")
      .attr("width", "200%")
      .attr("height", "200%");
    fAnomaly.append("feGaussianBlur").attr("stdDeviation", 5).attr("result", "blur");
    fAnomaly
      .append("feFlood")
      .attr("flood-color", "#ffaa00")
      .attr("flood-opacity", 0.45)
      .attr("result", "color");
    fAnomaly
      .append("feComposite")
      .attr("in", "color")
      .attr("in2", "blur")
      .attr("operator", "in")
      .attr("result", "tinted");
    const mAnomaly = fAnomaly.append("feMerge");
    mAnomaly.append("feMergeNode").attr("in", "tinted");
    mAnomaly.append("feMergeNode").attr("in", "SourceGraphic");
  }

  const lineGlow = defs
    .append("filter")
    .attr("id", "line-glow")
    .attr("x", "-20%")
    .attr("y", "-20%")
    .attr("width", "140%")
    .attr("height", "140%");
  lineGlow
    .append("feGaussianBlur")
    .attr("stdDeviation", 2)
    .attr("result", "blur");
  const lm = lineGlow.append("feMerge");
  lm.append("feMergeNode").attr("in", "blur");
  lm.append("feMergeNode").attr("in", "SourceGraphic");

  // Zoom & pan
  const zoomGroup = svg.append("g").attr("id", "zoom-group");
  const zoomBehavior = d3
    .zoom<SVGSVGElement, unknown>()
    .scaleExtent([0.15, 4])
    .on("zoom", (event) => {
      zoomGroup.attr("transform", event.transform);
    });
  svg.call(zoomBehavior);

  // Layers
  const layerStars = zoomGroup.append("g");
  const layerGrid = zoomGroup.append("g");
  const layerZones = zoomGroup.append("g");
  const layerConnections = zoomGroup.append("g");
  const layerParticles = zoomGroup.append("g");
  const layerNodes = zoomGroup.append("g");
  const layerContainers = zoomGroup.append("g");

  // ── Update connections helper ──
  function updateConnections() {
    layerConnections.selectAll<SVGLineElement, unknown>(".connection-line").each(
      function () {
        const el = d3.select(this);
        const srcNode = nodeById[el.attr("data-source")!];
        const tgtNode = nodeById[el.attr("data-target")!];
        if (srcNode && tgtNode) {
          el.attr("x1", srcNode.x)
            .attr("y1", srcNode.y)
            .attr("x2", tgtNode.x)
            .attr("y2", tgtNode.y);
        }
      },
    );
  }

  // ── Render stars ──
  for (let i = 0; i < 200; i++) {
    layerStars
      .append("circle")
      .attr("class", "star")
      .attr("cx", Math.random() * MAP_WIDTH)
      .attr("cy", Math.random() * MAP_HEIGHT)
      .attr("r", Math.random() * 1.2 + 0.3)
      .style("--dur", Math.random() * 4 + 2 + "s")
      .style("--delay", Math.random() * 5 + "s");
  }

  // ── Render grid ──
  const gridSpacing = 60;
  for (let x = 0; x <= MAP_WIDTH; x += gridSpacing) {
    layerGrid
      .append("line")
      .attr("class", "grid-line")
      .attr("x1", x)
      .attr("y1", 0)
      .attr("x2", x)
      .attr("y2", MAP_HEIGHT);
  }
  for (let y = 0; y <= MAP_HEIGHT; y += gridSpacing) {
    layerGrid
      .append("line")
      .attr("class", "grid-line")
      .attr("x1", 0)
      .attr("y1", y)
      .attr("x2", MAP_WIDTH)
      .attr("y2", y);
  }

  // ── Corner marks helper ──
  function drawCornerMarks(
    g: d3.Selection<SVGGElement, unknown, null, undefined>,
    layout: VlanLayout,
    color: string,
  ) {
    const corners: [number, number][] = [
      [layout.cx - layout.w / 2, layout.cy - layout.h / 2],
      [layout.cx + layout.w / 2, layout.cy - layout.h / 2],
      [layout.cx - layout.w / 2, layout.cy + layout.h / 2],
      [layout.cx + layout.w / 2, layout.cy + layout.h / 2],
    ];
    corners.forEach(([cx, cy], i) => {
      const sz = 12;
      const dx = i % 2 === 0 ? 1 : -1;
      const dy = i < 2 ? 1 : -1;
      g.append("path")
        .attr("class", "corner-mark")
        .attr(
          "d",
          `M${cx},${cy + dy * sz} L${cx},${cy} L${cx + dx * sz},${cy}`,
        )
        .attr("fill", "none")
        .attr("stroke", color)
        .attr("stroke-width", 2)
        .attr("stroke-opacity", 0.5);
    });
  }

  // ── Render VLAN zones (draggable) ──
  const zoneDrag = d3
    .drag<SVGGElement, unknown>()
    .on("start", function () {
      d3.select(this).classed("dragging", true).raise();
    })
    .on("drag", function (event) {
      const vlan = +d3.select(this).attr("data-vlan")!;
      const layout = vlanLayout[vlan];

      layout.cx += event.dx;
      layout.cy += event.dy;

      const g = d3.select(this);
      g.select(".vlan-zone")
        .attr("x", layout.cx - layout.w / 2)
        .attr("y", layout.cy - layout.h / 2);
      g.selectAll(".corner-mark").remove();
      drawCornerMarks(
        g as d3.Selection<SVGGElement, unknown, null, undefined>,
        layout,
        VLAN_CONFIG[vlan]?.color || "#fff",
      );
      g.select(".vlan-label")
        .attr("x", layout.cx - layout.w / 2 + 16)
        .attr("y", layout.cy - layout.h / 2 + 20);
      g.select(".vlan-sublabel")
        .attr("x", layout.cx - layout.w / 2 + 16)
        .attr("y", layout.cy - layout.h / 2 + 34);

      nodes
        .filter((n) => n.vlan === vlan)
        .forEach((n) => {
          n.x += event.dx;
          n.y += event.dy;
        });
      layerNodes
        .selectAll<SVGGElement, NetworkNode>(".node-group")
        .each(function (d) {
          if (d.vlan === vlan) {
            d3.select(this).attr("transform", `translate(${d.x}, ${d.y})`);
          }
        });
      updateConnections();
      if (showContainers) renderContainers();
    })
    .on("end", function () {
      d3.select(this).classed("dragging", false);
    });

  Object.entries(vlanLayout).forEach(([vlan, layout]) => {
    const config = VLAN_CONFIG[+vlan];
    if (!config) return;

    const g = layerZones
      .append("g")
      .attr("class", "vlan-zone-group")
      .attr("data-vlan", vlan)
      .call(zoneDrag);

    g.append("rect")
      .attr("class", "vlan-zone")
      .attr("x", layout.cx - layout.w / 2)
      .attr("y", layout.cy - layout.h / 2)
      .attr("width", layout.w)
      .attr("height", layout.h)
      .attr("fill", config.color)
      .attr("stroke", config.color)
      .attr("rx", 8);

    drawCornerMarks(
      g as d3.Selection<SVGGElement, unknown, null, undefined>,
      layout,
      config.color,
    );

    g.append("text")
      .attr("class", "vlan-label")
      .attr("x", layout.cx - layout.w / 2 + 16)
      .attr("y", layout.cy - layout.h / 2 + 20)
      .attr("fill", config.color)
      .text(config.code + " \u2014 " + config.name);

    g.append("text")
      .attr("class", "vlan-sublabel")
      .attr("x", layout.cx - layout.w / 2 + 16)
      .attr("y", layout.cy - layout.h / 2 + 34)
      .attr("fill", config.color)
      .text(config.subnet);
  });

  // ── Render connections ──
  connections.forEach((conn) => {
    const src = nodeById[conn.source];
    const tgt = nodeById[conn.target];
    if (!src || !tgt) return;
    const style = CONNECTION_STYLES[conn.type] || CONNECTION_STYLES.network;
    const line = layerConnections
      .append("line")
      .attr("class", "connection-line")
      .attr("data-source", conn.source)
      .attr("data-target", conn.target)
      .attr("x1", src.x)
      .attr("y1", src.y)
      .attr("x2", tgt.x)
      .attr("y2", tgt.y)
      .attr("stroke", style.color)
      .attr("stroke-width", style.width)
      .attr("filter", "url(#line-glow)");
    if (style.dash) line.attr("stroke-dasharray", style.dash);

    // Particle animation on fast links
    if (
      conn.type === "backbone" ||
      conn.type === "5g" ||
      conn.type === "2.5g" ||
      conn.type === "hypervisor"
    ) {
      const p = layerParticles
        .append("circle")
        .attr("class", "connection-particle")
        .attr("r", conn.type === "backbone" ? 2.5 : 1.5)
        .attr("fill", style.color)
        .attr("filter", "url(#glow-soft)");
      animateParticle(p, conn);
    }
  });

  function animateParticle(
    p: d3.Selection<SVGCircleElement, unknown, null, undefined>,
    conn: Connection,
  ) {
    const src = nodeById[conn.source];
    const tgt = nodeById[conn.target];
    if (!src || !tgt) return;

    // Read live rate for dynamic speed
    const key = `${conn.source}-${conn.target}`;
    const rate = connectionRates.get(key) ?? 0;
    const dur = rateToDuration(rate);

    // Fade particles on zero-traffic connections
    p.attr("opacity", rate > 0 ? 0.9 : 0.3);

    const fwd = Math.random() > 0.5;
    p.attr("cx", fwd ? src.x : tgt.x)
      .attr("cy", fwd ? src.y : tgt.y)
      .transition()
      .duration(dur)
      .ease(d3.easeLinear)
      .attr("cx", fwd ? tgt.x : src.x)
      .attr("cy", fwd ? tgt.y : src.y)
      .on("end", () => animateParticle(p, conn));
  }

  // ── Connection hover tooltips ──
  layerConnections
    .selectAll<SVGLineElement, unknown>(".connection-line")
    .on("mouseenter", function (event: MouseEvent) {
      const el = d3.select(this);
      const srcId = el.attr("data-source")!;
      const tgtId = el.attr("data-target")!;
      const src = nodeById[srcId];
      const tgt = nodeById[tgtId];
      // Find connection type
      const conn = connections.find(
        (c) =>
          (c.source === srcId && c.target === tgtId) ||
          (c.source === tgtId && c.target === srcId),
      );
      const style = conn ? CONNECTION_STYLES[conn.type] : null;
      const label = style?.label || conn?.type || "link";

      // Show throughput rate if available
      const rateKey = `${srcId}-${tgtId}`;
      const rate = connectionRates.get(rateKey) ?? 0;
      let rateText = "";
      if (rate > 0) {
        if (rate >= 1_000_000_000) rateText = `${(rate / 1_000_000_000).toFixed(1)} Gbps`;
        else if (rate >= 1_000_000) rateText = `${(rate / 1_000_000).toFixed(1)} Mbps`;
        else if (rate >= 1_000) rateText = `${(rate / 1_000).toFixed(1)} Kbps`;
        else rateText = `${rate} bps`;
      }

      const tip = document.createElement("div");
      tip.className = "nm-tooltip nm-conn-tooltip";
      tip.innerHTML = `<div class="tt-name">${label}</div><div class="tt-ip">${src?.hostname || srcId} &harr; ${tgt?.hostname || tgtId}</div>${rateText ? `<div class="tt-role">${rateText}</div>` : ""}`;
      document.body.appendChild(tip);
      tip.style.left = event.clientX + 14 + "px";
      tip.style.top = event.clientY + 14 + "px";
      (this as SVGLineElement).__connTooltip = tip;
    })
    .on("mousemove", function (event: MouseEvent) {
      const tip = (this as SVGLineElement).__connTooltip;
      if (tip) {
        tip.style.left = event.clientX + 14 + "px";
        tip.style.top = event.clientY + 14 + "px";
      }
    })
    .on("mouseleave", function () {
      const tip = (this as SVGLineElement).__connTooltip;
      if (tip) {
        tip.remove();
        (this as SVGLineElement).__connTooltip = undefined;
      }
    });

  // Live status data stores
  let deviceStatusMap: Map<string, DeviceStatus> = new Map();
  let interfaceStatusMap: Map<string, InterfaceStatus> = new Map();
  // Per-connection rate (total bps) for animation speed
  const connectionRates: Map<string, number> = new Map();

  // ── Render nodes (draggable) ──
  const nodeDrag = d3
    .drag<SVGGElement, NetworkNode>()
    .on("start", function () {
      d3.select(this).raise().classed("dragging", true);
    })
    .on("drag", function (event, d) {
      d.x = event.x;
      d.y = event.y;
      d3.select(this).attr("transform", `translate(${d.x}, ${d.y})`);
      updateConnections();
    })
    .on("end", function () {
      d3.select(this).classed("dragging", false);
      if (showContainers) renderContainers();
    });

  const groups = layerNodes
    .selectAll<SVGGElement, NetworkNode>(".node-group")
    .data(nodes, (d) => d.id)
    .enter()
    .append("g")
    .attr("class", "node-group")
    .attr("data-id", (d) => d.id)
    .attr("transform", (d) => `translate(${d.x}, ${d.y})`)
    .call(nodeDrag)
    .on("click", (event, d) => {
      event.stopPropagation();
      callbacks.onSelectNode(d);
    })
    .on("mouseenter", (event, d) =>
      callbacks.onHoverNode(event as unknown as MouseEvent, d),
    )
    .on("mousemove", (event) =>
      callbacks.onMoveHover(event as unknown as MouseEvent),
    )
    .on("mouseleave", () => callbacks.onLeaveNode());

  // Hub pulse rings
  groups
    .filter((d) => !!d.isHub)
    .each(function () {
      const g = d3.select(this);
      const c = getNodeColor(g.datum() as NetworkNode);
      g.append("circle")
        .attr("class", "node-pulse")
        .attr("cx", 0)
        .attr("cy", 0)
        .attr("stroke", c);
      g.append("circle")
        .attr("class", "node-pulse")
        .attr("cx", 0)
        .attr("cy", 0)
        .attr("stroke", c)
        .style("animation-delay", "1.5s");
    });

  // Hexagon
  groups
    .append("path")
    .attr("class", "node-hex")
    .attr("d", hexPath(HEX_RADIUS))
    .attr("fill", (d) => getNodeColor(d))
    .attr("stroke", (d) => getNodeColor(d));

  // Icon
  groups
    .append("g")
    .attr("class", "node-icon")
    .attr("transform", "translate(-10, -14) scale(0.85)")
    .append("path")
    .attr("d", (d) => getIconPath(d.type))
    .attr("fill", (d) => getNodeColor(d))
    .attr("opacity", 0.9);

  // Labels
  groups
    .append("text")
    .attr("class", "node-hostname")
    .attr("y", HEX_RADIUS + 14)
    .text((d) => d.hostname);
  groups
    .append("text")
    .attr("class", "node-ip")
    .attr("y", HEX_RADIUS + 26)
    .text((d) => d.ip);

  // Status dots
  groups
    .filter((d) => !!d.status)
    .append("circle")
    .attr("class", (d) => "node-status-dot status-" + d.status)
    .attr("cx", HEX_RADIUS - 4)
    .attr("cy", -HEX_RADIUS + 4);

  // ── Containers ──
  function renderContainers() {
    layerContainers.selectAll("*").remove();
    if (!showContainers) return;

    nodes
      .filter((n) => n.containers && n.containers.length > 0)
      .forEach((host) => {
        const cg = layerContainers.append("g").attr("data-host", host.id);
        const cols = 2,
          boxW = 110,
          boxH = 22,
          gap = 4;
        const startX = host.x + HEX_RADIUS + 20;
        const startY =
          host.y -
          (Math.ceil(host.containers!.length / cols) * (boxH + gap)) / 2;

        cg.append("line")
          .attr("x1", host.x + HEX_RADIUS)
          .attr("y1", host.y)
          .attr("x2", startX - 4)
          .attr("y2", host.y)
          .attr("stroke", "#b388ff")
          .attr("stroke-width", 0.5)
          .attr("stroke-dasharray", "3,3")
          .attr("opacity", 0.4);

        host.containers!.forEach((c, i) => {
          const col = i % cols,
            row = Math.floor(i / cols);
          const x = startX + col * (boxW + gap),
            y = startY + row * (boxH + gap);
          const ig = cg
            .append("g")
            .attr("class", "container-group")
            .attr("transform", `translate(${x}, ${y})`)
            .on("click", (event: Event) => {
              event.stopPropagation();
              callbacks.onSelectNode(host, c);
            });
          ig.append("rect")
            .attr("class", "container-rect")
            .attr("width", boxW)
            .attr("height", boxH);
          ig.append("text")
            .attr("class", "container-name")
            .attr("x", 5)
            .attr("y", 10)
            .text(c.name);
          ig.append("text")
            .attr("class", "container-port")
            .attr("x", 5)
            .attr("y", 18)
            .text(c.ports || "");
        });
      });
  }

  // ── Highlight helpers ──
  function highlightConnectionsForNode(nodeId: string) {
    const connected = new Set([nodeId]);
    layerConnections
      .selectAll<SVGLineElement, unknown>(".connection-line")
      .each(function () {
        const s = this.getAttribute("data-source")!;
        const t = this.getAttribute("data-target")!;
        if (s === nodeId || t === nodeId) {
          connected.add(s);
          connected.add(t);
          d3.select(this).classed("highlighted", true).classed("dimmed", false);
        } else {
          d3.select(this)
            .classed("highlighted", false)
            .classed("dimmed", true);
        }
      });
    layerNodes
      .selectAll<SVGGElement, unknown>(".node-group")
      .each(function () {
        const id = this.getAttribute("data-id")!;
        d3.select(this)
          .classed("highlighted", connected.has(id))
          .classed("dimmed", !connected.has(id));
      });
  }

  function clearHighlights() {
    layerConnections
      .selectAll(".connection-line")
      .classed("highlighted", false)
      .classed("dimmed", false);
    layerNodes
      .selectAll(".node-group")
      .classed("highlighted", false)
      .classed("dimmed", false);
  }

  // ── SVG background click ──
  svg.on("click", () => {
    callbacks.onBackgroundClick();
  });

  // ── Initial zoom animation ──
  svg.call(
    zoomBehavior.transform,
    d3.zoomIdentity.translate(0, 0).scale(0.35),
  );
  setTimeout(() => {
    const container = svgElement.parentElement;
    const w = container?.clientWidth || window.innerWidth;
    const h = container?.clientHeight || window.innerHeight;
    svg
      .transition()
      .duration(1500)
      .ease(d3.easeCubicOut)
      .call(
        zoomBehavior.transform,
        d3.zoomIdentity
          .translate(
            w / 2 - (MAP_WIDTH * 0.55) / 2,
            h / 2 - (MAP_HEIGHT * 0.55) / 2,
          )
          .scale(0.55),
      );
  }, 200);

  // ── Return imperative API ──
  return {
    destroy() {
      // Stop all D3 transitions to prevent memory leaks
      svg.selectAll("*").interrupt();
      svg.on("click", null);
      svg.on(".zoom", null);
      svg.selectAll("*").remove();
    },

    setShowContainers(show: boolean) {
      showContainers = show;
      renderContainers();
    },

    search(term: string) {
      const t = term.toLowerCase().trim();
      if (!t) {
        layerNodes
          .selectAll(".node-group")
          .classed("dimmed", false)
          .classed("search-match", false);
        layerConnections
          .selectAll(".connection-line")
          .classed("dimmed", false);
        return;
      }
      const matched = new Set<string>();
      layerNodes
        .selectAll<SVGGElement, NetworkNode>(".node-group")
        .each(function (d) {
          const m = matchesSearch(d, t);
          if (m) matched.add(d.id);
          d3.select(this).classed("dimmed", !m).classed("search-match", m);
        });
      layerConnections
        .selectAll<SVGLineElement, unknown>(".connection-line")
        .each(function () {
          const s = this.getAttribute("data-source")!;
          const tg = this.getAttribute("data-target")!;
          d3.select(this).classed("dimmed", !matched.has(s) && !matched.has(tg));
        });
    },

    highlightNode(nodeId: string) {
      layerNodes.selectAll(".node-group").classed("selected", false);
      layerNodes
        .select(`[data-id="${nodeId}"]`)
        .classed("selected", true);
      highlightConnectionsForNode(nodeId);
    },

    clearSelection() {
      layerNodes.selectAll(".node-group").classed("selected", false);
      clearHighlights();
    },

    resetView() {
      const container = svgElement.parentElement;
      const w = container?.clientWidth || window.innerWidth;
      const h = container?.clientHeight || window.innerHeight;
      svg
        .transition()
        .duration(750)
        .call(
          zoomBehavior.transform,
          d3.zoomIdentity
            .translate(
              w / 2 - (MAP_WIDTH * 0.55) / 2,
              h / 2 - (MAP_HEIGHT * 0.55) / 2,
            )
            .scale(0.55),
        );
    },

    updateDeviceStatuses(devices: DeviceStatus[], anomalyMacs?: Set<string>) {
      // Build IP → DeviceStatus lookup
      deviceStatusMap = new Map(devices.map((d) => [d.ip, d]));

      // Update each node group
      layerNodes
        .selectAll<SVGGElement, NetworkNode>(".node-group")
        .each(function (d) {
          const status = deviceStatusMap.get(d.ip);
          // Store on datum for tooltip access
          d.liveStatus = status;

          const g = d3.select(this);
          const hex = g.select<SVGPathElement>(".node-hex");

          // Check if this device has pending anomalies (by MAC)
          const hasAnomaly = status?.mac && anomalyMacs?.has(status.mac.toUpperCase());

          if (hasAnomaly) {
            // Anomaly — amber glow (highest priority)
            g.classed("nm-node-anomaly", true)
              .classed("nm-node-active", false)
              .classed("nm-node-inactive", false)
              .classed("nm-node-unknown", false);
            hex.attr("stroke", "#ffaa00").attr("filter", "url(#glow-anomaly)");
          } else if (status) {
            g.classed("nm-node-anomaly", false);
            if (status.in_arp) {
              // Active — green glow
              g.classed("nm-node-active", true)
                .classed("nm-node-inactive", false)
                .classed("nm-node-unknown", false);
              hex.attr("stroke", "#00ff88").attr("filter", "url(#glow-active)");
            } else {
              // In DHCP but not in ARP — red glow
              g.classed("nm-node-active", false)
                .classed("nm-node-inactive", true)
                .classed("nm-node-unknown", false);
              hex
                .attr("stroke", "#ff4444")
                .attr("filter", "url(#glow-inactive)");
            }
          } else {
            // No status data — keep default
            g.classed("nm-node-anomaly", false)
              .classed("nm-node-active", false)
              .classed("nm-node-inactive", false)
              .classed("nm-node-unknown", true);
            hex
              .attr("stroke", getNodeColor(d))
              .attr("filter", "url(#glow-soft)");
          }
        });

      // Update connection pulse classes based on endpoint statuses
      layerConnections
        .selectAll<SVGLineElement, unknown>(".connection-line")
        .each(function () {
          const el = d3.select(this);
          const srcIp = nodeById[el.attr("data-source")!]?.ip;
          const tgtIp = nodeById[el.attr("data-target")!]?.ip;
          const srcActive = srcIp ? deviceStatusMap.get(srcIp)?.in_arp : false;
          const tgtActive = tgtIp ? deviceStatusMap.get(tgtIp)?.in_arp : false;
          el.classed("nm-conn-active", !!(srcActive && tgtActive));
        });
    },

    updateInterfaceStatuses(interfaces: InterfaceStatus[]) {
      interfaceStatusMap = new Map(interfaces.map((i) => [i.name, i]));

      // Build VLAN → total rate lookup
      const vlanRates: Map<number, number> = new Map();
      let totalRate = 0;
      for (const [vlan] of Object.entries(VLAN_CONFIG)) {
        const iface = findVlanIface(+vlan, interfaceStatusMap);
        if (iface) {
          const rate = iface.rx_rate_bps + iface.tx_rate_bps;
          vlanRates.set(+vlan, rate);
          totalRate += rate;
        }
      }

      // Compute per-connection rate
      connections.forEach((conn) => {
        const key = `${conn.source}-${conn.target}`;
        const src = nodeById[conn.source];
        const tgt = nodeById[conn.target];
        if (!src || !tgt) return;

        let rate = 0;
        if (conn.type === "backbone" || conn.type === "5g") {
          // Backbone/5G carry aggregate traffic — use total rate
          rate = totalRate;
        } else if (conn.type === "2.5g") {
          // 2.5G links carry their connected VLAN's traffic
          const vlan = vlanForIp(tgt.ip) ?? vlanForIp(src.ip);
          rate = vlan != null ? (vlanRates.get(vlan) ?? 0) : totalRate;
        } else if (conn.type === "hypervisor") {
          // Hypervisor — VM on VLAN 25
          rate = vlanRates.get(25) ?? 0;
        } else {
          // Other logical connections — use endpoint VLAN rate
          const srcVlan = vlanForIp(src.ip);
          const tgtVlan = vlanForIp(tgt.ip);
          const srcRate = srcVlan != null ? (vlanRates.get(srcVlan) ?? 0) : 0;
          const tgtRate = tgtVlan != null ? (vlanRates.get(tgtVlan) ?? 0) : 0;
          rate = Math.max(srcRate, tgtRate);
        }

        connectionRates.set(key, rate);
      });

      // Update connection line width and opacity based on rate
      layerConnections
        .selectAll<SVGLineElement, unknown>(".connection-line")
        .each(function () {
          const el = d3.select(this);
          const srcId = el.attr("data-source")!;
          const tgtId = el.attr("data-target")!;
          const key = `${srcId}-${tgtId}`;
          const rate = connectionRates.get(key) ?? 0;

          // Find base style
          const conn = connections.find(
            (c) =>
              (c.source === srcId && c.target === tgtId) ||
              (c.source === tgtId && c.target === srcId),
          );
          const style = conn ? CONNECTION_STYLES[conn.type] : null;
          const baseWidth = style?.width ?? 1.2;

          el.transition()
            .duration(1000)
            .attr("stroke-width", rateToWidth(rate, baseWidth))
            .attr("stroke-opacity", rate > 0 ? 1 : 0.4);
        });
    },
  };
}
