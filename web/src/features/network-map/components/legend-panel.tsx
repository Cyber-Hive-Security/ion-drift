import { NODE_TYPES, CONNECTION_STYLES, VLAN_CONFIG } from "../data";

interface LegendPanelProps {
  show: boolean;
}

export function LegendPanel({ show }: LegendPanelProps) {
  return (
    <div className={`nm-legend-panel ${show ? "" : "hidden"}`}>
      <h3>LEGEND</h3>
      {Object.entries(NODE_TYPES)
        .filter(([k]) => k !== "container")
        .map(([k, v]) => (
          <div key={k} className="nm-legend-item">
            <div className="nm-legend-swatch" style={{ background: v.color }} />
            <span>{v.label}</span>
          </div>
        ))}

      <h3>CONNECTIONS</h3>
      {Object.entries(CONNECTION_STYLES).map(([k, v]) => (
        <div key={k} className="nm-legend-item">
          <div
            className="nm-legend-line"
            style={
              v.dash
                ? { borderTop: `2px dashed ${v.color}`, background: "none" }
                : { background: v.color }
            }
          />
          <span>{v.label}</span>
        </div>
      ))}

      <h3>VLAN SECTORS</h3>
      {Object.entries(VLAN_CONFIG).map(([vlan, config]) => (
        <div key={vlan} className="nm-legend-item">
          <div
            className="nm-legend-swatch"
            style={{ background: config.color, opacity: 0.6 }}
          />
          <span>VLAN {vlan}: {config.name}</span>
        </div>
      ))}

      <h3>CONTROLS</h3>
      <div className="nm-legend-controls">
        <div className="nm-legend-item"><kbd>Drag</kbd> <span>Move nodes</span></div>
        <div className="nm-legend-item"><kbd>Scroll</kbd> <span>Zoom</span></div>
        <div className="nm-legend-item"><kbd>Click</kbd> <span>Select node</span></div>
        <div className="nm-legend-item"><kbd>/</kbd> <span>Search</span></div>
      </div>
    </div>
  );
}
