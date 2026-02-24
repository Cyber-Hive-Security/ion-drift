import { useMemo, useRef } from "react";
import { Sankey, Rectangle, Layer } from "recharts";
import { formatBytes } from "@/lib/format";
import { portLabel } from "@/lib/services";
import type { PortSummaryEntry } from "@/api/types";

// Distinct colors for source groupings
const PORT_COLORS = [
  "oklch(0.65 0.18 250)",  // blue
  "oklch(0.65 0.2 145)",   // green
  "oklch(0.65 0.2 30)",    // orange
  "oklch(0.65 0.2 330)",   // pink
  "oklch(0.65 0.2 200)",   // teal
  "oklch(0.65 0.2 90)",    // yellow-green
  "oklch(0.65 0.18 280)",  // purple
  "oklch(0.65 0.2 60)",    // gold
  "oklch(0.65 0.2 170)",   // cyan
  "oklch(0.65 0.15 0)",    // red
];

function getColor(index: number): string {
  return PORT_COLORS[index % PORT_COLORS.length];
}

const MIN_SCALED_VALUE = 2;

function scaleBytes(bytes: number): number {
  return Math.max(MIN_SCALED_VALUE, Math.log10(bytes + 1));
}

interface SankeyNodePayload {
  x: number;
  y: number;
  width: number;
  height: number;
  index: number;
  payload: { name: string; color: string; value: number; rawValue: number };
  containerWidth: number;
}

function CustomNode(props: SankeyNodePayload) {
  const { x, y, width, height, payload, containerWidth } = props;
  const isLeft = x < containerWidth / 2;

  return (
    <Layer>
      <Rectangle
        x={x}
        y={y}
        width={width}
        height={height}
        fill={payload.color}
        fillOpacity={1}
      />
      <text
        x={isLeft ? x - 6 : x + width + 6}
        y={y + height / 2}
        textAnchor={isLeft ? "end" : "start"}
        dominantBaseline="central"
        fill="oklch(0.85 0.01 285)"
        fontSize={11}
      >
        {payload.name}
      </text>
      <text
        x={isLeft ? x - 6 : x + width + 6}
        y={y + height / 2 + 14}
        textAnchor={isLeft ? "end" : "start"}
        dominantBaseline="central"
        fill="oklch(0.55 0.01 285)"
        fontSize={10}
      >
        {formatBytes(payload.rawValue)}
      </text>
    </Layer>
  );
}

interface SankeyLinkPayload {
  sourceX: number;
  targetX: number;
  sourceY: number;
  targetY: number;
  sourceControlX: number;
  targetControlX: number;
  linkWidth: number;
  index: number;
  payload: {
    source: { name: string; color: string };
    target: { name: string };
    value: number;
    rawBytes: number;
  };
}

interface PortSankeyProps {
  data: PortSummaryEntry[];
}

export function PortSankey({ data }: PortSankeyProps) {
  const tooltipRef = useRef<HTMLDivElement>(null);

  const LinkWithTooltip = useMemo(() => {
    return function SankeyLink(props: SankeyLinkPayload) {
      const {
        sourceX, targetX, sourceY, targetY,
        sourceControlX, targetControlX, linkWidth, payload,
      } = props;

      const updateTooltip = (e: React.MouseEvent) => {
        const el = tooltipRef.current;
        if (!el) return;
        el.style.display = "block";
        el.style.left = `${e.clientX + 14}px`;
        el.style.top = `${e.clientY - 12}px`;
        const src = payload.source.name.trim();
        const dst = payload.target.name.trim();
        el.textContent = "";
        const line1 = document.createElement("span");
        line1.style.fontWeight = "500";
        line1.textContent = `${src} \u2192 ${dst}`;
        el.appendChild(line1);
        el.appendChild(document.createElement("br"));
        el.appendChild(document.createTextNode(formatBytes(payload.rawBytes)));
      };

      const hideTooltip = () => {
        const el = tooltipRef.current;
        if (el) el.style.display = "none";
      };

      return (
        <path
          d={`
            M${sourceX},${sourceY + linkWidth / 2}
            C${sourceControlX},${sourceY + linkWidth / 2}
              ${targetControlX},${targetY + linkWidth / 2}
              ${targetX},${targetY + linkWidth / 2}
            L${targetX},${targetY - linkWidth / 2}
            C${targetControlX},${targetY - linkWidth / 2}
              ${sourceControlX},${sourceY - linkWidth / 2}
              ${sourceX},${sourceY - linkWidth / 2}
            Z
          `}
          fill={payload.source.color}
          fillOpacity={0.25}
          stroke={payload.source.color}
          strokeWidth={0}
          strokeOpacity={0.5}
          onMouseEnter={(e) => {
            e.currentTarget.setAttribute("fill-opacity", "0.5");
            e.currentTarget.setAttribute("stroke-width", "2");
            updateTooltip(e);
          }}
          onMouseMove={updateTooltip}
          onMouseLeave={(e) => {
            e.currentTarget.setAttribute("fill-opacity", "0.25");
            e.currentTarget.setAttribute("stroke-width", "0");
            hideTooltip();
          }}
          style={{ cursor: "pointer" }}
        />
      );
    };
  }, []);

  const sankeyData = useMemo(() => {
    if (!data || data.length === 0) return null;

    // Group ports by protocol, take top 20
    const sorted = [...data].sort((a, b) => b.total_bytes - a.total_bytes).slice(0, 20);

    // Left side: protocols
    // Right side: destination ports
    const protocols = [...new Set(sorted.map((d) => d.protocol))].sort();
    const ports = sorted.map((d) => portLabel(String(d.dst_port)));

    const nodeCount = protocols.length + ports.length;

    // Per-protocol total for labels
    const protoTotals = new Map<string, number>();
    for (const entry of sorted) {
      protoTotals.set(
        entry.protocol,
        (protoTotals.get(entry.protocol) ?? 0) + entry.total_bytes,
      );
    }

    const nodes = [
      ...protocols.map((p, i) => ({
        name: `${p.toUpperCase()} `,
        color: getColor(i),
        rawValue: protoTotals.get(p) ?? 0,
      })),
      ...sorted.map((entry) => ({
        name: ` ${portLabel(String(entry.dst_port))}`,
        color: getColor(protocols.indexOf(entry.protocol)),
        rawValue: entry.total_bytes,
      })),
    ];

    const links = sorted.map((entry, i) => ({
      source: protocols.indexOf(entry.protocol),
      target: protocols.length + i,
      value: scaleBytes(entry.total_bytes),
      rawBytes: entry.total_bytes,
    }));

    return { nodes, links, nodeCount };
  }, [data]);

  if (!sankeyData) {
    return (
      <div className="rounded-lg border border-border bg-card p-4">
        <h3 className="mb-3 text-sm font-medium text-muted-foreground">
          Port Flows (24h)
        </h3>
        <p className="text-sm text-muted-foreground">
          No port traffic data available yet.
        </p>
      </div>
    );
  }

  const rightNodes = sankeyData.nodeCount - (sankeyData.nodes.length - sankeyData.nodeCount);
  const chartHeight = Math.max(400, rightNodes * 35);

  return (
    <div className="rounded-lg border border-border bg-card p-4 overflow-visible">
      <h3 className="mb-3 text-sm font-medium text-muted-foreground">
        Port Flows — Top 20 by Bytes (24h)
      </h3>
      <div className="sankey-container" style={{ overflow: "visible" }}>
        <Sankey
          width={800}
          height={chartHeight}
          data={sankeyData}
          nodeWidth={10}
          nodePadding={16}
          linkCurvature={0.5}
          iterations={64}
          sort={true}
          margin={{ top: 10, right: 140, bottom: 30, left: 80 }}
          node={
            ((props: SankeyNodePayload) => (
              <CustomNode {...props} containerWidth={800} />
            )) as any
          }
          link={LinkWithTooltip as any}
        />
      </div>
      <div
        ref={tooltipRef}
        style={{
          display: "none",
          position: "fixed",
          pointerEvents: "none",
          zIndex: 50,
          backgroundColor: "oklch(0.175 0.015 285)",
          border: "1px solid oklch(0.3 0.015 285)",
          color: "oklch(0.95 0.01 285)",
          borderRadius: "6px",
          padding: "6px 12px",
          fontSize: "12px",
          lineHeight: "1.5",
        }}
      />
    </div>
  );
}
