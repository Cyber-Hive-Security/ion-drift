import { useMemo, useRef } from "react";
import { formatBytes } from "@/lib/format";
import { useVlanFlows } from "@/api/queries";
import { Sankey, Rectangle, Layer } from "recharts";

// Distinct colors for VLAN sources
const VLAN_COLORS = [
  "#21D07A",   // green
  "#2FA4FF",  // blue
  "#FF4FD8",    // orange
  "#FF4FD8",   // pink
  "#00E5FF",   // teal
  "#FFC857",    // yellow-green
  "#7A5CFF",  // purple
  "#FFC857",    // gold
  "#00E5FF",   // cyan
  "#FF4D4F",    // red
];

function getColor(index: number): string {
  return VLAN_COLORS[index % VLAN_COLORS.length];
}

/** Minimum scaled value so tiny flows still get visible band width. */
const MIN_SCALED_VALUE = 2;

/** Scale raw bytes to a log10 value for proportional band width.
 *  Compresses the 100,000x+ range between dominant and minor flows into ~3-5x. */
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
        fill="#E6EDF3"
        fontSize={11}
      >
        {payload.name}
      </text>
      <text
        x={isLeft ? x - 6 : x + width + 6}
        y={y + height / 2 + 14}
        textAnchor={isLeft ? "end" : "start"}
        dominantBaseline="central"
        fill="#8A929D"
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

// CustomLink is created inside VlanTrafficBreakdown (needs closure access to tooltip ref)

export function VlanTrafficBreakdown() {
  const { data: flows, isLoading } = useVlanFlows();
  const tooltipRef = useRef<HTMLDivElement>(null);

  // Link component created here so it has closure access to tooltipRef.
  // Uses direct DOM manipulation for the tooltip to avoid re-rendering
  // the entire Sankey on every mouse move.
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
  }, []); // tooltipRef is stable, formatBytes is a module import

  const sankeyData = useMemo(() => {
    if (!flows || flows.length === 0) return null;

    // Collect unique node names from flows
    const nameSet = new Set<string>();
    for (const f of flows) {
      nameSet.add(f.source);
      nameSet.add(f.target);
    }
    const nodeNames = Array.from(nameSet).sort();
    const n = nodeNames.length;

    // Compute raw byte totals per sender/receiver for display labels
    const senderTotals = new Map<number, number>();
    const receiverTotals = new Map<number, number>();
    for (const f of flows) {
      const srcIdx = nodeNames.indexOf(f.source);
      const dstIdx = nodeNames.indexOf(f.target);
      senderTotals.set(srcIdx, (senderTotals.get(srcIdx) ?? 0) + f.bytes);
      receiverTotals.set(dstIdx, (receiverTotals.get(dstIdx) ?? 0) + f.bytes);
    }

    // Build nodes: left column (sender) + right column (receiver)
    // Index 0..n-1 = senders, n..2n-1 = receivers
    const nodes = [
      ...nodeNames.map((name, i) => ({
        name: `${name} `,  // trailing space distinguishes sender node labels
        color: getColor(i),
        rawValue: senderTotals.get(i) ?? 0,
      })),
      ...nodeNames.map((name, i) => ({
        name: ` ${name}`,  // leading space distinguishes receiver node labels
        color: getColor(i),
        rawValue: receiverTotals.get(i) ?? 0,
      })),
    ];

    // Build links with log-scaled values for band width, raw bytes for labels
    const links = flows.map((f) => {
      const srcIdx = nodeNames.indexOf(f.source);
      const dstIdx = nodeNames.indexOf(f.target);
      return {
        source: srcIdx,
        target: n + dstIdx,
        value: scaleBytes(f.bytes),
        rawBytes: f.bytes,
      };
    });

    return { nodes, links };
  }, [flows]);

  if (isLoading) {
    return (
      <div className="rounded-lg border border-border bg-card p-4">
        <h3 className="mb-3 text-sm font-medium text-muted-foreground">
          Inter-VLAN Traffic Flows
        </h3>
        <p className="text-sm text-muted-foreground">Loading flow data...</p>
      </div>
    );
  }

  if (!sankeyData) {
    return (
      <div className="rounded-lg border border-border bg-card p-4">
        <h3 className="mb-3 text-sm font-medium text-muted-foreground">
          Inter-VLAN Traffic Flows
        </h3>
        <p className="text-sm text-muted-foreground">
          No inter-VLAN traffic recorded yet. Flow counters are accumulating
          data.
        </p>
      </div>
    );
  }

  // Auto-height: node padding (24) + band height + room for the 14px subtitle
  // below the last node. Use 70px per node to be generous, and add extra bottom
  // margin so the last row's subtitle text is never clipped.
  const sideNodes = sankeyData.nodes.length / 2;
  const chartHeight = Math.max(400, sideNodes * 70);

  return (
    <div className="rounded-lg border border-border bg-card p-4 overflow-visible">
      <h3 className="mb-3 text-sm font-medium text-muted-foreground">
        Inter-VLAN Traffic Flows
      </h3>
      <div className="sankey-container" style={{ overflow: "visible" }}>
        <Sankey
          width={800}
          height={chartHeight}
          data={sankeyData}
          nodeWidth={10}
          nodePadding={24}
          linkCurvature={0.5}
          iterations={64}
          sort={true}
          margin={{ top: 10, right: 120, bottom: 30, left: 120 }}
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
          backgroundColor: "#2C3038",
          border: "1px solid #444B55",
          color: "#E6EDF3",
          borderRadius: "6px",
          padding: "6px 12px",
          fontSize: "12px",
          lineHeight: "1.5",
        }}
      />
    </div>
  );
}
