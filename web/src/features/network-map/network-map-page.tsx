import { useState, useEffect, useCallback, useRef } from "react";
import type { NetworkNode, ContainerInfo, MapInstance } from "./types";
import { useBootSequence } from "./hooks/use-boot-sequence";
import { BootOverlay } from "./components/boot-overlay";
import { TopBar } from "./components/top-bar";
import { MapCanvas } from "./components/map-canvas";
import { DetailPanel } from "./components/detail-panel";
import { LegendPanel } from "./components/legend-panel";
import "./network-map.css";

export function NetworkMapPage() {
  const boot = useBootSequence();
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(null);
  const [showContainers, setShowContainers] = useState(false);
  const [showLegend, setShowLegend] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");

  const mapInstanceRef = useRef<MapInstance | null>(null);
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const tooltipRef = useRef<HTMLDivElement | null>(null);

  // ── Node selection ──
  const handleSelectNode = useCallback(
    (node: NetworkNode, _container?: ContainerInfo) => {
      setSelectedNode(node);
    },
    [],
  );

  const handleClearSelection = useCallback(() => {
    setSelectedNode(null);
  }, []);

  // ── Tooltip ──
  const handleHover = useCallback((event: MouseEvent, node: NetworkNode) => {
    if (tooltipRef.current) {
      tooltipRef.current.remove();
      tooltipRef.current = null;
    }
    const el = document.createElement("div");
    el.className = "nm-tooltip";
    el.innerHTML = `<div class="tt-name">${node.hostname}</div><div class="tt-ip">${node.ip}</div><div class="tt-role">${node.role}</div>`;
    document.body.appendChild(el);
    el.style.left = event.clientX + 14 + "px";
    el.style.top = event.clientY + 14 + "px";
    tooltipRef.current = el;
  }, []);

  const handleMoveHover = useCallback((event: MouseEvent) => {
    if (tooltipRef.current) {
      tooltipRef.current.style.left = event.clientX + 14 + "px";
      tooltipRef.current.style.top = event.clientY + 14 + "px";
    }
  }, []);

  const handleLeaveHover = useCallback(() => {
    if (tooltipRef.current) {
      tooltipRef.current.remove();
      tooltipRef.current = null;
    }
  }, []);

  // Cleanup tooltip on unmount
  useEffect(() => {
    return () => {
      if (tooltipRef.current) {
        tooltipRef.current.remove();
        tooltipRef.current = null;
      }
    };
  }, []);

  // ── Keyboard shortcuts ──
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        if (
          document.activeElement === searchInputRef.current &&
          searchTerm
        ) {
          setSearchTerm("");
          searchInputRef.current?.blur();
        } else if (selectedNode) {
          setSelectedNode(null);
        }
      }
      if (
        e.key === "/" &&
        document.activeElement?.tagName !== "INPUT"
      ) {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [searchTerm, selectedNode]);

  const bootDone = boot.phase === "done";

  return (
    <div className="network-map-root flex flex-1 flex-col overflow-hidden">
      <BootOverlay
        phase={boot.phase}
        visibleLines={boot.visibleLines}
        progress={boot.progress}
        bootLines={boot.bootLines}
      />

      {bootDone && (
        <>
          <TopBar
            searchTerm={searchTerm}
            onSearchChange={setSearchTerm}
            showContainers={showContainers}
            onToggleContainers={() => setShowContainers((s) => !s)}
            showLegend={showLegend}
            onToggleLegend={() => setShowLegend((s) => !s)}
            onResetView={() => mapInstanceRef.current?.resetView()}
            searchInputRef={searchInputRef}
          />

          <MapCanvas
            showContainers={showContainers}
            searchTerm={searchTerm}
            selectedNode={selectedNode}
            onSelectNode={handleSelectNode}
            onClearSelection={handleClearSelection}
            onHover={handleHover}
            onMoveHover={handleMoveHover}
            onLeaveHover={handleLeaveHover}
            instanceRef={mapInstanceRef}
          />

          <DetailPanel node={selectedNode} onClose={handleClearSelection} />
          <LegendPanel show={showLegend} />

          <div className="nm-scanline" />
        </>
      )}
    </div>
  );
}
