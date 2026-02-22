interface BootOverlayProps {
  phase: "booting" | "fading" | "done";
  visibleLines: number;
  progress: number;
  bootLines: string[];
}

export function BootOverlay({ phase, visibleLines, progress, bootLines }: BootOverlayProps) {
  if (phase === "done") return null;

  return (
    <div className={`nm-boot-overlay ${phase === "fading" ? "fade-out" : ""}`}>
      <div className="nm-boot-content">
        <div className="nm-boot-logo">
          <svg viewBox="0 0 120 120" width="120" height="120">
            <polygon points="60,10 110,90 10,90" fill="none" stroke="#00f0ff" strokeWidth="2" opacity="0.6" />
            <polygon points="60,25 95,82 25,82" fill="none" stroke="#00f0ff" strokeWidth="1.5" opacity="0.4" />
            <circle cx="60" cy="58" r="12" fill="none" stroke="#ffd700" strokeWidth="2" />
            <circle cx="60" cy="58" r="4" fill="#ffd700" />
          </svg>
        </div>
        <div className="nm-boot-text">
          {bootLines.slice(0, visibleLines).map((line, i) => (
            <div
              key={i}
              className="line"
              style={{
                color: line.includes("DONE")
                  ? "#00ff88"
                  : line.includes("AUTH")
                    ? "#ffd700"
                    : undefined,
              }}
            >
              {line}
            </div>
          ))}
        </div>
        <div className="nm-boot-progress">
          <div className="nm-boot-progress-bar" style={{ width: `${progress}%` }} />
        </div>
      </div>
    </div>
  );
}
