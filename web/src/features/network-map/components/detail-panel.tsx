import React from "react";
import type { NetworkNode } from "../types";
import { VLAN_CONFIG, NODE_TYPES, NODES_RAW } from "../data";
import { ICON_PATHS } from "../constants";

interface DetailPanelProps {
  node: NetworkNode | null;
  onClose: () => void;
}

function getIconPath(type: string): string {
  const t = NODE_TYPES[type];
  if (!t) return ICON_PATHS.vm;
  return ICON_PATHS[t.icon] || ICON_PATHS.vm;
}

function getNodeColor(type: string): string {
  return NODE_TYPES[type]?.color || "#888";
}

function formatSpecKey(key: string): string {
  return key.replace(/([A-Z])/g, " $1").replace(/^./, (s) => s.toUpperCase());
}

export function DetailPanel({ node, onClose }: DetailPanelProps) {
  const color = node ? getNodeColor(node.type) : "#888";

  const idFields: [string, string][] = node
    ? [
        ["IP Address", node.ip],
        [
          "VLAN",
          `${node.vlan} \u2014 ${VLAN_CONFIG[node.vlan]?.name || "Unknown"}`,
        ],
        ["Type", NODE_TYPES[node.type]?.label || node.type],
        ["Status", node.status || "Operational"],
      ]
    : [];

  if (node?.parent) {
    const p = NODES_RAW.find((n) => n.id === node.parent);
    idFields.push(["Host", p ? p.hostname : node.parent]);
  }

  const hasSpecs = node?.specs && Object.keys(node.specs).length > 0;
  const hasContainers = node?.containers && node.containers.length > 0;
  const hasDetails = node?.details && node.details.length > 0;

  return (
    <div className={`nm-detail-panel ${node ? "visible" : ""}`}>
      <button className="nm-detail-close" onClick={onClose}>
        &times;
      </button>

      {node && (
        <>
          <div className="nm-detail-header">
            <div className="nm-detail-icon" style={{ borderColor: color }}>
              <svg viewBox="0 0 24 24">
                <path d={getIconPath(node.type)} fill={color} />
              </svg>
            </div>
            <div>
              <h2 className="nm-detail-hostname" style={{ color }}>
                {node.hostname}
              </h2>
              <p className="nm-detail-role">{node.role}</p>
            </div>
          </div>

          <div className="nm-detail-section">
            <h3>IDENTIFICATION</h3>
            <div className="nm-detail-grid">
              {idFields.map(([label, value]) => (
                <React.Fragment key={label}>
                  <span className="label">{label}</span>
                  <span className="value">{value}</span>
                </React.Fragment>
              ))}
            </div>
          </div>

          {hasSpecs && (
            <div className="nm-detail-section">
              <h3>SPECIFICATIONS</h3>
              <div className="nm-detail-grid">
                {Object.entries(node.specs).map(([k, v]) => (
                  <React.Fragment key={k}>
                    <span className="label">{formatSpecKey(k)}</span>
                    <span className="value">{v}</span>
                  </React.Fragment>
                ))}
              </div>
            </div>
          )}

          {hasContainers && (
            <div className="nm-detail-section">
              <h3>SERVICES / CONTAINERS</h3>
              <div className="nm-services-list">
                {node.containers!.map((c) => (
                  <div key={c.id} className="nm-service-item">
                    <span className="svc-name">{c.name}</span>
                    <span className="svc-port">{c.ports || ""}</span>
                    <span className="svc-role">{c.role || ""}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {hasDetails && (
            <div className="nm-detail-section">
              <h3>INTELLIGENCE NOTES</h3>
              <ul className="nm-detail-notes">
                {node.details.map((d, i) => (
                  <li key={i}>{d}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="nm-detail-footer">
            <span className="nm-classification">
              CLASSIFICATION: INTERNAL USE ONLY
            </span>
          </div>
        </>
      )}
    </div>
  );
}
