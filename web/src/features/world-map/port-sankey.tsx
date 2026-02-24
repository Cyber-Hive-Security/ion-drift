import { useMemo, useRef } from "react";
import { Sankey, Rectangle, Layer } from "recharts";
import { formatBytes } from "@/lib/format";
import { portLabel } from "@/lib/services";
import { useClassifiedPortSummary } from "@/api/queries";
import type {
  ClassifiedPortFlow,
  ClassifiedPortSummary,
  FlowClassification,
  PortDirection,
} from "@/api/types";

// ── Anomaly color map ──────────────────────────────────────────

const CLASSIFICATION_COLORS: Record<
  FlowClassification,
  { udp: string; tcp: string }
> = {
  normal: {
    udp: "oklch(0.65 0.2 145)", // green
    tcp: "oklch(0.65 0.18 250)", // blue
  },
  new_port: {
    udp: "#ef4444", // red
    tcp: "#ef4444",
  },
  volume_spike: {
    udp: "#f59e0b", // amber
    tcp: "#f59e0b",
  },
  source_anomaly: {
    udp: "#f59e0b", // amber
    tcp: "#f59e0b",
  },
  disappeared: {
    udp: "#6b7280", // gray
    tcp: "#6b7280",
  },
};

function getFlowColor(
  classification: FlowClassification,
  protocol: string,
): string {
  const colors = CLASSIFICATION_COLORS[classification] ?? CLASSIFICATION_COLORS.normal;
  return protocol === "udp" ? colors.udp : colors.tcp;
}

// Distinct colors for source protocol groupings (normal mode)
const PROTOCOL_COLORS: Record<string, string> = {
  tcp: "oklch(0.65 0.18 250)", // blue
  udp: "oklch(0.65 0.2 145)", // green
  icmp: "oklch(0.65 0.2 30)", // orange
  other: "oklch(0.65 0.2 330)", // pink
};

function getProtocolColor(protocol: string): string {
  return PROTOCOL_COLORS[protocol] ?? "oklch(0.65 0.15 0)";
}

const MIN_SCALED_VALUE = 2;

function scaleBytes(bytes: number): number {
  return Math.max(MIN_SCALED_VALUE, Math.log10(bytes + 1));
}

// ── CSS class for anomaly animation ────────────────────────────

function flowCssClass(classification: FlowClassification): string {
  switch (classification) {
    case "new_port":
      return "flow-new-port";
    case "volume_spike":
      return "flow-volume-spike";
    case "disappeared":
      return "flow-disappeared";
    default:
      return "";
  }
}

// ── Badge text for port labels ─────────────────────────────────

function badgeText(flow: ClassifiedPortFlow): string {
  switch (flow.classification) {
    case "new_port":
      return "NEW  ";
    case "volume_spike": {
      const ratio = flow.volume_ratio ?? 0;
      const label = ratio >= 10 ? `${Math.round(ratio)}x` : `${ratio.toFixed(1)}x`;
      return `\u2191${label}  `;
    }
    case "source_anomaly":
      return "";
    case "disappeared":
      return "MISSING  ";
    default:
      return "";
  }
}

// ── Sankey node renderer ───────────────────────────────────────

interface SankeyNodePayload {
  x: number;
  y: number;
  width: number;
  height: number;
  index: number;
  payload: {
    name: string;
    color: string;
    value: number;
    rawValue: number;
    badge?: string;
    classification?: FlowClassification;
    baselineAvg?: number;
  };
  containerWidth: number;
}

function CustomNode(props: SankeyNodePayload) {
  const { x, y, width, height, payload, containerWidth } = props;
  const isLeft = x < containerWidth / 2;
  const cls = payload.classification;
  const isAnomaly = cls && cls !== "normal";

  const badgeColor =
    cls === "new_port"
      ? "#ef4444"
      : cls === "volume_spike" || cls === "source_anomaly"
        ? "#f59e0b"
        : cls === "disappeared"
          ? "#6b7280"
          : undefined;

  return (
    <Layer>
      <Rectangle
        x={x}
        y={y}
        width={width}
        height={height}
        fill={payload.color}
        fillOpacity={cls === "disappeared" ? 0.4 : 1}
      />
      <text
        x={isLeft ? x - 6 : x + width + 6}
        y={y + height / 2}
        textAnchor={isLeft ? "end" : "start"}
        dominantBaseline="central"
        fill={isAnomaly ? badgeColor : "oklch(0.85 0.01 285)"}
        fontSize={11}
        fontWeight={isAnomaly ? 600 : 400}
      >
        {payload.badge ? payload.badge : ""}
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
        {cls === "disappeared" && payload.baselineAvg
          ? `(baseline: ${formatBytes(payload.baselineAvg)}/day)`
          : formatBytes(payload.rawValue)}
      </text>
    </Layer>
  );
}

// ── Sankey link renderer ───────────────────────────────────────

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
    classification?: FlowClassification;
  };
}

// ── PortSankey component ───────────────────────────────────────

interface PortSankeyProps {
  summary: ClassifiedPortSummary;
  title: string;
}

export function PortSankey({ summary, title }: PortSankeyProps) {
  const tooltipRef = useRef<HTMLDivElement>(null);

  // Combine active flows + disappeared ghost flows
  const allFlows = useMemo(() => {
    const active = summary.flows;
    const ghosts = summary.disappeared.map((f) => ({
      ...f,
      // Use baseline volume for Sankey width so ghost flows have visible width
      total_bytes: f.baseline_avg_bytes ?? 0,
    }));
    return [...active, ...ghosts];
  }, [summary]);

  const LinkWithTooltip = useMemo(() => {
    return function SankeyLink(props: SankeyLinkPayload) {
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

      const cls = payload.classification ?? "normal";
      const cssClass = flowCssClass(cls);
      const isDashed = cls === "disappeared";

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
        el.appendChild(
          document.createTextNode(formatBytes(payload.rawBytes)),
        );
        if (cls !== "normal") {
          el.appendChild(document.createElement("br"));
          const badge = document.createElement("span");
          badge.style.color =
            cls === "new_port"
              ? "#ef4444"
              : cls === "disappeared"
                ? "#6b7280"
                : "#f59e0b";
          badge.textContent =
            cls === "new_port"
              ? "NEW PORT"
              : cls === "volume_spike"
                ? "VOLUME SPIKE"
                : cls === "source_anomaly"
                  ? "NEW SOURCE"
                  : cls === "disappeared"
                    ? "MISSING"
                    : cls.toUpperCase();
          el.appendChild(badge);
        }
      };

      const hideTooltip = () => {
        const el = tooltipRef.current;
        if (el) el.style.display = "none";
      };

      return (
        <path
          className={cssClass}
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
          fillOpacity={isDashed ? 0.1 : 0.25}
          stroke={payload.source.color}
          strokeWidth={isDashed ? 1.5 : 0}
          strokeDasharray={isDashed ? "8 4" : undefined}
          strokeOpacity={isDashed ? 0.6 : 0.5}
          onMouseEnter={(e) => {
            if (!isDashed) {
              e.currentTarget.setAttribute("fill-opacity", "0.5");
              e.currentTarget.setAttribute("stroke-width", "2");
            }
            updateTooltip(e);
          }}
          onMouseMove={updateTooltip}
          onMouseLeave={(e) => {
            if (!isDashed) {
              e.currentTarget.setAttribute("fill-opacity", "0.25");
              e.currentTarget.setAttribute("stroke-width", "0");
            }
            hideTooltip();
          }}
          style={{ cursor: "pointer" }}
        />
      );
    };
  }, []);

  const sankeyData = useMemo(() => {
    if (!allFlows || allFlows.length === 0) return null;

    const sorted = [...allFlows]
      .sort((a, b) => b.total_bytes - a.total_bytes)
      .slice(0, 30);

    const protocols = [...new Set(sorted.map((d) => d.protocol))].sort();

    // Per-protocol total for labels
    const protoTotals = new Map<string, number>();
    for (const entry of sorted) {
      protoTotals.set(
        entry.protocol,
        (protoTotals.get(entry.protocol) ?? 0) + entry.total_bytes,
      );
    }

    const nodes = [
      ...protocols.map((p) => ({
        name: `${p.toUpperCase()} `,
        color: getProtocolColor(p),
        rawValue: protoTotals.get(p) ?? 0,
      })),
      ...sorted.map((entry) => ({
        name: ` ${portLabel(String(entry.dst_port))}`,
        color: getFlowColor(entry.classification, entry.protocol),
        rawValue: entry.total_bytes,
        badge: badgeText(entry),
        classification: entry.classification,
        baselineAvg: entry.baseline_avg_bytes ?? undefined,
      })),
    ];

    const links = sorted.map((entry, i) => ({
      source: protocols.indexOf(entry.protocol),
      target: protocols.length + i,
      value: scaleBytes(entry.total_bytes),
      rawBytes: entry.total_bytes,
      classification: entry.classification,
    }));

    return { nodes, links, portCount: sorted.length };
  }, [allFlows]);

  if (!sankeyData) return null;

  const chartHeight = Math.max(300, sankeyData.portCount * 30);

  // Build alert banner
  const anomalies = summary.flows.filter(
    (f) => f.classification !== "normal",
  );
  const newPorts = anomalies.filter((f) => f.classification === "new_port");
  const volumeSpikes = anomalies.filter(
    (f) => f.classification === "volume_spike",
  );
  const sourceAnomalies = anomalies.filter(
    (f) => f.classification === "source_anomaly",
  );
  const disappeared = summary.disappeared;
  const hasAnomalies = anomalies.length > 0 || disappeared.length > 0;
  const hasCritical = newPorts.length > 0;

  return (
    <div className="rounded-lg border border-border bg-card p-4 overflow-visible">
      {hasAnomalies && (
        <AnomalyBanner
          newPorts={newPorts}
          volumeSpikes={volumeSpikes}
          sourceAnomalies={sourceAnomalies}
          disappeared={disappeared}
          hasCritical={hasCritical}
        />
      )}
      <h3 className="mb-3 text-sm font-medium text-muted-foreground">
        {title}
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

// ── Alert banner ───────────────────────────────────────────────

function AnomalyBanner({
  newPorts,
  volumeSpikes,
  sourceAnomalies,
  disappeared,
  hasCritical,
}: {
  newPorts: ClassifiedPortFlow[];
  volumeSpikes: ClassifiedPortFlow[];
  sourceAnomalies: ClassifiedPortFlow[];
  disappeared: ClassifiedPortFlow[];
  hasCritical: boolean;
}) {
  const totalAnomalies =
    newPorts.length +
    volumeSpikes.length +
    sourceAnomalies.length +
    disappeared.length;

  const items: string[] = [];

  for (const p of newPorts) {
    const svc = portLabel(String(p.dst_port));
    items.push(`NEW port ${svc} (${formatBytes(p.total_bytes)})`);
  }
  for (const p of volumeSpikes) {
    const svc = portLabel(String(p.dst_port));
    const ratio = p.volume_ratio ?? 0;
    const label = ratio >= 10 ? `${Math.round(ratio)}x` : `${ratio.toFixed(1)}x`;
    items.push(`${svc} volume ${label} baseline`);
  }
  for (const p of sourceAnomalies) {
    const svc = portLabel(String(p.dst_port));
    items.push(`${svc} new source`);
  }
  for (const p of disappeared) {
    const svc = portLabel(String(p.dst_port));
    items.push(`${svc} missing`);
  }

  const bgClass = hasCritical
    ? "bg-red-500/10 border-red-500/30 text-red-300"
    : "bg-amber-500/10 border-amber-500/30 text-amber-300";

  return (
    <div
      className={`mb-3 rounded-md border px-3 py-2 text-xs font-medium ${bgClass}`}
    >
      <span className="mr-2">
        {totalAnomalies} anomal{totalAnomalies === 1 ? "y" : "ies"}
      </span>
      {items.map((item, i) => (
        <span key={i} className="mr-2">
          &middot; {item}
        </span>
      ))}
    </div>
  );
}

// ── Directional wrapper ──────────────────────────────────────

const DIRECTIONS: { key: PortDirection; title: string }[] = [
  { key: "outbound", title: "Outbound Port Flows (24h)" },
  { key: "inbound", title: "Inbound Port Flows (24h)" },
  { key: "internal", title: "Internal Port Flows (24h)" },
];

interface DirectionalPortSankeysProps {
  days: number;
}

export function DirectionalPortSankeys({
  days,
}: DirectionalPortSankeysProps) {
  return (
    <div className="space-y-6">
      {DIRECTIONS.map(({ key, title }) => (
        <DirectionSection
          key={key}
          direction={key}
          title={title}
          days={days}
        />
      ))}
    </div>
  );
}

function DirectionSection({
  direction,
  title,
  days,
}: {
  direction: PortDirection;
  title: string;
  days: number;
}) {
  const { data, isLoading } = useClassifiedPortSummary(days, direction);

  if (
    !isLoading &&
    (!data || (data.flows.length === 0 && data.disappeared.length === 0))
  )
    return null;

  if (isLoading) {
    return (
      <div className="rounded-lg border border-border bg-card p-4">
        <h3 className="mb-3 text-sm font-medium text-muted-foreground">
          {title}
        </h3>
        <p className="text-sm text-muted-foreground">Loading...</p>
      </div>
    );
  }

  return <PortSankey summary={data!} title={title} />;
}
