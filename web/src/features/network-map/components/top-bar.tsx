import { useState, useEffect } from "react";

interface TopBarProps {
  searchTerm: string;
  onSearchChange: (term: string) => void;
  showContainers: boolean;
  onToggleContainers: () => void;
  showLegend: boolean;
  onToggleLegend: () => void;
  onResetView: () => void;
  searchInputRef: React.RefObject<HTMLInputElement | null>;
}

export function TopBar({
  searchTerm,
  onSearchChange,
  showContainers,
  onToggleContainers,
  showLegend,
  onToggleLegend,
  onResetView,
  searchInputRef,
}: TopBarProps) {
  const [clock, setClock] = useState("");

  useEffect(() => {
    function tick() {
      const now = new Date();
      const p = (n: number) => String(n).padStart(2, "0");
      setClock(`${p(now.getHours())}:${p(now.getMinutes())}:${p(now.getSeconds())}`);
    }
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="nm-top-bar">
      <div className="nm-top-bar-left">
        <span style={{ fontSize: 18, color: "#2FA4FF", filter: "drop-shadow(0 0 6px rgba(47,164,255,0.5))" }}>
          &#x2B22;
        </span>
        <span style={{ fontFamily: "'Orbitron', monospace", fontSize: 13, fontWeight: 700, color: "#00E5FF", letterSpacing: 2 }}>
          TACTICAL MAP
        </span>
      </div>

      <div className="nm-top-bar-center">
        <div className="nm-search-box">
          <svg className="nm-search-icon" viewBox="0 0 24 24" width="16" height="16">
            <circle cx="11" cy="11" r="7" fill="none" stroke="currentColor" strokeWidth="2" />
            <line x1="16" y1="16" x2="22" y2="22" stroke="currentColor" strokeWidth="2" />
          </svg>
          <input
            ref={searchInputRef}
            type="text"
            className="nm-search-input"
            placeholder="Search host, IP, VLAN, or service..."
            autoComplete="off"
            value={searchTerm}
            onChange={(e) => onSearchChange(e.target.value)}
          />
          <kbd>/</kbd>
        </div>
      </div>

      <div className="nm-top-bar-right">
        <button onClick={onResetView} title="Reset View">
          <svg viewBox="0 0 24 24" width="18" height="18">
            <path d="M3 12a9 9 0 1 1 3 6.7" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            <polyline points="3 7 3 13 9 13" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </button>
        <button
          onClick={onToggleContainers}
          title="Toggle Containers"
          className={showContainers ? "active" : ""}
        >
          <svg viewBox="0 0 24 24" width="18" height="18">
            <rect x="3" y="3" width="7" height="7" rx="1" fill="none" stroke="currentColor" strokeWidth="2" />
            <rect x="14" y="3" width="7" height="7" rx="1" fill="none" stroke="currentColor" strokeWidth="2" />
            <rect x="3" y="14" width="7" height="7" rx="1" fill="none" stroke="currentColor" strokeWidth="2" />
            <rect x="14" y="14" width="7" height="7" rx="1" fill="none" stroke="currentColor" strokeWidth="2" />
          </svg>
        </button>
        <button
          onClick={onToggleLegend}
          title="Toggle Legend"
          className={showLegend ? "active" : ""}
        >
          <svg viewBox="0 0 24 24" width="18" height="18">
            <rect x="3" y="3" width="18" height="18" rx="2" fill="none" stroke="currentColor" strokeWidth="2" />
            <line x1="8" y1="8" x2="16" y2="8" stroke="currentColor" strokeWidth="2" />
            <line x1="8" y1="12" x2="16" y2="12" stroke="currentColor" strokeWidth="2" />
            <line x1="8" y1="16" x2="13" y2="16" stroke="currentColor" strokeWidth="2" />
          </svg>
        </button>
        <span className="nm-clock">{clock}</span>
      </div>
    </div>
  );
}
