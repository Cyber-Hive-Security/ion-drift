import { useMemo } from "react";
import { formatBytes } from "@/lib/format";
import { useVlanFlows } from "@/api/queries";
import { Sankey, Tooltip, Rectangle, Layer } from "recharts";

// Distinct colors for VLAN sources
const VLAN_COLORS = [
  "oklch(0.65 0.2 145)",   // green
  "oklch(0.65 0.18 250)",  // blue
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
  return VLAN_COLORS[index % VLAN_COLORS.length];
}

interface SankeyNodePayload {
  x: number;
  y: number;
  width: number;
  height: number;
  index: number;
  payload: { name: string; color: string; value: number };
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
        {formatBytes(payload.value)}
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
  };
}

function CustomLink(props: SankeyLinkPayload) {
  const {
    sourceX,
    targetX,
    sourceY,
    targetY,
    sourceControlX,
    targetControlX,
    linkWidth,
    payload,
  } = props;

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
      }}
      onMouseLeave={(e) => {
        e.currentTarget.setAttribute("fill-opacity", "0.25");
        e.currentTarget.setAttribute("stroke-width", "0");
      }}
      style={{ cursor: "pointer" }}
    />
  );
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: Array<{
    name?: string;
    payload?: {
      source?: { name: string };
      target?: { name: string };
      value?: number;
      name?: string;
    };
  }>;
}

function CustomTooltip({ active, payload }: CustomTooltipProps) {
  if (!active || !payload || payload.length === 0) return null;

  const item = payload[0]?.payload;
  if (!item) return null;

  // Link tooltip
  if (item.source && item.target && item.value !== undefined) {
    return (
      <div
        className="rounded-md border px-3 py-2 text-xs"
        style={{
          backgroundColor: "oklch(0.175 0.015 285)",
          borderColor: "oklch(0.3 0.015 285)",
          color: "oklch(0.95 0.01 285)",
        }}
      >
        <span className="font-medium">
          {item.source.name} &rarr; {item.target.name}
        </span>
        <br />
        {formatBytes(item.value)}
      </div>
    );
  }

  // Node tooltip
  if (item.name && item.value !== undefined) {
    return (
      <div
        className="rounded-md border px-3 py-2 text-xs"
        style={{
          backgroundColor: "oklch(0.175 0.015 285)",
          borderColor: "oklch(0.3 0.015 285)",
          color: "oklch(0.95 0.01 285)",
        }}
      >
        <span className="font-medium">{item.name}</span>
        <br />
        {formatBytes(item.value)}
      </div>
    );
  }

  return null;
}

export function VlanTrafficBreakdown() {
  const { data: flows, isLoading } = useVlanFlows();

  const sankeyData = useMemo(() => {
    if (!flows || flows.length === 0) return null;

    // Collect unique VLAN names from flows
    const vlanSet = new Set<string>();
    for (const f of flows) {
      vlanSet.add(f.source);
      vlanSet.add(f.target);
    }
    const vlanNames = Array.from(vlanSet).sort();
    const n = vlanNames.length;

    // Build nodes: left column (sender) + right column (receiver)
    // Index 0..n-1 = senders, n..2n-1 = receivers
    const nodes = [
      ...vlanNames.map((name, i) => ({
        name: `${name} `,  // trailing space distinguishes sender node labels
        color: getColor(i),
      })),
      ...vlanNames.map((name, i) => ({
        name: ` ${name}`,  // leading space distinguishes receiver node labels
        color: getColor(i),
      })),
    ];

    // Build links
    const links = flows.map((f) => {
      const srcIdx = vlanNames.indexOf(f.source);
      const dstIdx = vlanNames.indexOf(f.target);
      return {
        source: srcIdx,
        target: n + dstIdx,
        value: f.bytes,
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

  const nodeCount = sankeyData.nodes.length / 2;
  const chartHeight = Math.max(300, nodeCount * 50 + 60);

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <h3 className="mb-3 text-sm font-medium text-muted-foreground">
        Inter-VLAN Traffic Flows
      </h3>
      <Sankey
        width={800}
        height={chartHeight}
        data={sankeyData}
        nodeWidth={10}
        nodePadding={24}
        linkCurvature={0.5}
        iterations={64}
        sort={true}
        margin={{ top: 10, right: 120, bottom: 10, left: 120 }}
        node={
          ((props: SankeyNodePayload) => (
            <CustomNode {...props} containerWidth={800} />
          )) as any
        }
        link={CustomLink as any}
      >
        <Tooltip content={<CustomTooltip />} />
      </Sankey>
    </div>
  );
}
