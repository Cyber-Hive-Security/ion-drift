import { useState, useEffect, useCallback, useRef } from "react";
import type { NetworkNode, ContainerInfo, MapInstance } from "./types";
import { useBootSequence } from "./hooks/use-boot-sequence";
import { useNetworkMapStatus, useBehaviorAlerts } from "@/api/queries";
import { BootOverlay } from "./components/boot-overlay";
import { TopBar } from "./components/top-bar";
import { MapCanvas } from "./components/map-canvas";
import { DetailPanel } from "./components/detail-panel";
import { LegendPanel } from "./components/legend-panel";
import { StatusBar } from "./components/status-bar";
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

  // Live status polling — only after boot sequence completes
  const statusQuery = useNetworkMapStatus({ enabled: boot.phase === "done" });
  const alertsQuery = useBehaviorAlerts();

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

  // ── Tooltip (enhanced with live status) ──
  const handleHover = useCallback((event: MouseEvent, node: NetworkNode) => {
    if (tooltipRef.current) {
      tooltipRef.current.remove();
      tooltipRef.current = null;
    }
    const el = document.createElement("div");
    el.className = "nm-tooltip";

    let html = `<div class="tt-name">${node.hostname}</div><div class="tt-ip">${node.ip}</div><div class="tt-role">${node.role}</div>`;

    // Append live status details if available
    const ls = node.liveStatus;
    if (ls) {
      const parts: string[] = [];
      if (ls.mac) parts.push(`<span class="tt-dim">MAC</span> ${ls.mac}`);
      if (ls.manufacturer) parts.push(`<span class="tt-dim">MFG</span> ${ls.manufacturer}`);
      if (ls.dhcp_status) parts.push(`<span class="tt-dim">DHCP</span> ${ls.dhcp_status}`);
      if (ls.expires_after) parts.push(`<span class="tt-dim">EXP</span> ${ls.expires_after}`);
      if (ls.last_seen) parts.push(`<span class="tt-dim">SEEN</span> ${ls.last_seen}`);
      parts.push(
        `<span class="tt-dim">ARP</span> <span class="${ls.in_arp ? "tt-green" : "tt-red"}">${ls.in_arp ? "active" : "offline"}</span>`,
      );
      // Hop count to internet
      if (ls.hop_count != null) {
        parts.push(`<span class="tt-dim">HOPS</span> ${ls.hop_count} ${ls.internet_path ?? ""}`);
      } else if (ls.internet_path) {
        parts.push(`<span class="tt-dim">HOPS</span> <span class="tt-red">\u221e ${ls.internet_path}</span>`);
      }
      html += `<div class="tt-status">${parts.join("<br>")}</div>`;
    }

    el.innerHTML = html;
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

  // ── Sync live status to D3 map ──
  useEffect(() => {
    if (!statusQuery.data || !mapInstanceRef.current) return;
    const anomalyMacs = new Set(alertsQuery.data?.anomaly_macs ?? []);
    mapInstanceRef.current.updateDeviceStatuses(statusQuery.data.devices, anomalyMacs);
    mapInstanceRef.current.updateInterfaceStatuses(statusQuery.data.interfaces);
  }, [statusQuery.data, alertsQuery.data]);

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
          <StatusBar
            status={statusQuery.data}
            isLoading={statusQuery.isLoading}
            anomalyCount={alertsQuery.data?.pending_count ?? 0}
          />

          <div className="nm-scanline" />
        </>
      )}
    </div>
  );
}
