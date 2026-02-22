import { useNavigate } from "@tanstack/react-router";
import type { NetworkMapStatus } from "@/api/types";

interface StatusBarProps {
  status: NetworkMapStatus | undefined;
  isLoading: boolean;
  anomalyCount?: number;
}

function formatTimeAgo(timestamp: number): string {
  const seconds = Math.floor(Date.now() / 1000 - timestamp);
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  return `${Math.floor(minutes / 60)}h ago`;
}

export function StatusBar({ status, isLoading, anomalyCount = 0 }: StatusBarProps) {
  const navigate = useNavigate();
  if (!status && !isLoading) return null;

  const activeDevices = status?.devices.filter((d) => d.in_arp).length ?? 0;
  const totalDevices = status?.devices.length ?? 0;
  const runningIfaces = status?.interfaces.filter((i) => i.running && !i.disabled).length ?? 0;
  const totalIfaces = status?.interfaces.length ?? 0;

  return (
    <div className="nm-status-bar">
      <div className="nm-status-item">
        <span className="nm-status-dot-indicator nm-dot-green" />
        <span className="nm-status-label">DEVICES</span>
        <span className="nm-status-value">
          <span className="nm-status-active">{activeDevices}</span>
          <span className="nm-status-sep">/</span>
          <span className="nm-status-total">{totalDevices}</span>
        </span>
      </div>
      <div className="nm-status-divider" />
      <div className="nm-status-item">
        <span className="nm-status-dot-indicator nm-dot-blue" />
        <span className="nm-status-label">INTERFACES</span>
        <span className="nm-status-value">
          <span className="nm-status-active">{runningIfaces}</span>
          <span className="nm-status-sep">/</span>
          <span className="nm-status-total">{totalIfaces}</span>
        </span>
      </div>
      {anomalyCount > 0 && (
        <>
          <div className="nm-status-divider" />
          <div
            className="nm-status-item"
            style={{ cursor: "pointer" }}
            onClick={() => navigate({ to: "/behavior" })}
          >
            <span className="nm-status-dot-indicator" style={{ background: "#f59e0b" }} />
            <span className="nm-status-label" style={{ color: "#f59e0b" }}>ANOMALIES</span>
            <span className="nm-status-value" style={{ color: "#f59e0b" }}>{anomalyCount}</span>
          </div>
        </>
      )}
      <div className="nm-status-divider" />
      <div className="nm-status-item">
        <span className="nm-status-label">UPDATED</span>
        <span className="nm-status-value nm-status-time">
          {isLoading && !status
            ? "loading..."
            : status
              ? formatTimeAgo(status.timestamp)
              : "--"}
        </span>
      </div>
    </div>
  );
}
