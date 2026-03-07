import { useState, useMemo } from "react";
import { cn } from "@/lib/utils";
import { VLAN_CONFIG } from "@/features/network-map/data";
import type {
  PortMetricsTuple,
  VlanMembershipEntry,
  PortRoleEntry,
  MacTableEntry,
  NetworkIdentity,
  PortMacBinding,
  PortViolation,
  PortUtilization,
} from "@/api/types";
import {
  portToGridPosition,
  portShortName,
  portSortKey,
  getPortVlanColor,
  getPortPrimaryVlan,
  vlanName,
} from "./utils";
import { formatBytes } from "@/lib/format";
import { utilizationColor, utilizationLabel, formatBitrate } from "@/lib/utilization";

interface PortGridProps {
  ports: PortMetricsTuple[];
  vlans: VlanMembershipEntry[];
  portRoles: PortRoleEntry[];
  macTable: MacTableEntry[];
  identities: NetworkIdentity[];
  selectedPort: string | null;
  onSelectPort: (port: string | null) => void;
  deviceId?: string;
  bindings?: PortMacBinding[];
  violations?: PortViolation[];
  utilization?: PortUtilization[];
}

interface PortCellData {
  portName: string;
  shortName: string;
  running: boolean;
  speed: string | null;
  rxBytes: number;
  txBytes: number;
  primaryVlanId: number | null;
  vlanColor: string;
  vlanCount: number;
  macCount: number;
  role: string | null;
  connectedDevice: string | null;
  connectedMac: string | null;
  connectedIp: string | null;
  connectedManufacturer: string | null;
  hasBound: boolean;
  hasViolation: boolean;
  utilization: number;
  rxRateBps: number;
  txRateBps: number;
  ratedSpeedMbps: number;
  speedSource: string;
}

export function PortGrid({
  ports,
  vlans,
  portRoles,
  macTable,
  identities,
  selectedPort,
  onSelectPort,
  deviceId,
  bindings = [],
  violations = [],
  utilization = [],
}: PortGridProps) {
  const [hoveredPort, setHoveredPort] = useState<string | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });

  // Build a map of latest metrics per port
  const latestMetrics = useMemo(() => {
    const map = new Map<string, PortMetricsTuple>();
    for (const tuple of ports) {
      const [name, , , ts] = tuple;
      const existing = map.get(name);
      if (!existing || ts > existing[3]) {
        map.set(name, tuple);
      }
    }
    return map;
  }, [ports]);

  // Count MACs per port
  const macCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const entry of macTable) {
      if (!entry.is_local) {
        counts.set(entry.port_name, (counts.get(entry.port_name) ?? 0) + 1);
      }
    }
    return counts;
  }, [macTable]);

  // Build port role map
  const roleMap = useMemo(() => {
    const map = new Map<string, PortRoleEntry>();
    for (const r of portRoles) {
      map.set(r.port_name, r);
    }
    return map;
  }, [portRoles]);

  // Identity lookup by switch_port
  const identityByPort = useMemo(() => {
    const map = new Map<string, NetworkIdentity>();
    for (const id of identities) {
      if (id.switch_port && (!deviceId || id.switch_device_id === deviceId)) {
        // Keep the highest confidence identity per port
        const existing = map.get(id.switch_port);
        if (!existing || id.confidence > existing.confidence) {
          map.set(id.switch_port, id);
        }
      }
    }
    return map;
  }, [identities, deviceId]);

  // Binding lookup by port name
  const bindingByPort = useMemo(() => {
    const map = new Map<string, PortMacBinding>();
    for (const b of bindings) map.set(b.port_name, b);
    return map;
  }, [bindings]);

  // Violation lookup by port name
  const violationByPort = useMemo(() => {
    const map = new Map<string, PortViolation>();
    for (const v of violations) map.set(v.port_name, v);
    return map;
  }, [violations]);

  // Utilization lookup by port name
  const utilByPort = useMemo(() => {
    const map = new Map<string, PortUtilization>();
    for (const u of utilization) map.set(u.port_name, u);
    return map;
  }, [utilization]);

  // Build cell data for all known ports
  const portCells = useMemo(() => {
    const allPortNames = new Set<string>();
    for (const [name] of latestMetrics) allPortNames.add(name);
    for (const v of vlans) allPortNames.add(v.port_name);
    for (const r of portRoles) allPortNames.add(r.port_name);

    const cells: PortCellData[] = [];
    for (const portName of allPortNames) {
      const metrics = latestMetrics.get(portName);
      const portVlans = vlans.filter((v) => v.port_name === portName);
      const role = roleMap.get(portName);
      const identity = identityByPort.get(portName);
      const util = utilByPort.get(portName);

      cells.push({
        portName,
        shortName: portShortName(portName),
        running: metrics ? metrics[5] : false,
        speed: metrics ? metrics[4] : null,
        rxBytes: metrics ? metrics[1] : 0,
        txBytes: metrics ? metrics[2] : 0,
        primaryVlanId: getPortPrimaryVlan(portName, vlans),
        vlanColor: getPortVlanColor(portName, vlans),
        vlanCount: portVlans.length,
        macCount: macCounts.get(portName) ?? 0,
        role: role?.role ?? null,
        connectedDevice: identity?.hostname ?? identity?.manufacturer ?? null,
        connectedMac: identity?.mac_address ?? null,
        connectedIp: identity?.best_ip ?? null,
        connectedManufacturer: identity?.manufacturer ?? null,
        hasBound: bindingByPort.has(portName),
        hasViolation: violationByPort.has(portName),
        utilization: util?.utilization ?? 0,
        rxRateBps: util?.rx_rate_bps ?? 0,
        txRateBps: util?.tx_rate_bps ?? 0,
        ratedSpeedMbps: util?.rated_speed_mbps ?? 0,
        speedSource: util?.speed_source ?? "",
      });
    }

    return cells.sort((a, b) => portSortKey(a.portName) - portSortKey(b.portName));
  }, [latestMetrics, vlans, portRoles, macCounts, roleMap, identityByPort, bindingByPort, violationByPort, utilByPort]);

  // Separate copper ports (with grid positions) from SFP and other ports
  const { topRow, bottomRow, sfpTop, sfpBottom, otherPorts } = useMemo(() => {
    const top: (PortCellData | null)[] = [];
    const bottom: (PortCellData | null)[] = [];
    let st: PortCellData | null = null;
    let sb: PortCellData | null = null;
    const other: PortCellData[] = [];

    // Determine max columns for copper ports
    let maxCol = 11; // Default CRS326 = 12 columns (0-11)
    for (const cell of portCells) {
      const pos = portToGridPosition(cell.portName);
      if (pos && pos.col >= 0) {
        maxCol = Math.max(maxCol, pos.col);
      }
    }

    // Initialize arrays
    for (let i = 0; i <= maxCol; i++) {
      top.push(null);
      bottom.push(null);
    }

    for (const cell of portCells) {
      const pos = portToGridPosition(cell.portName);
      if (!pos) {
        // Skip bridge interface and similar
        if (cell.portName !== "bridge") {
          other.push(cell);
        }
        continue;
      }
      if (pos.col === -1) {
        // SFP port
        if (pos.row === "top") st = cell;
        else sb = cell;
      } else if (pos.col <= maxCol) {
        if (pos.row === "top") top[pos.col] = cell;
        else bottom[pos.col] = cell;
      }
    }

    return { topRow: top, bottomRow: bottom, sfpTop: st, sfpBottom: sb, otherPorts: other };
  }, [portCells]);

  const hoveredCell = portCells.find((c) => c.portName === hoveredPort);

  function handleMouseEnter(portName: string, e: React.MouseEvent) {
    setHoveredPort(portName);
    setTooltipPos({ x: e.clientX, y: e.clientY });
  }

  function handleMouseMove(e: React.MouseEvent) {
    setTooltipPos({ x: e.clientX, y: e.clientY });
  }

  function handleMouseLeave() {
    setHoveredPort(null);
  }

  function renderPortCell(cell: PortCellData | null, key: string) {
    if (!cell) {
      return <div key={key} className="h-9 w-full rounded border border-border/20 bg-muted/20" />;
    }

    const isSfp = cell.portName.startsWith("sfp");
    const isSelected = selectedPort === cell.portName;
    const isTrunk = cell.vlanCount > 1;
    const util = cell.running ? cell.utilization : 0;
    const utilColor = utilizationColor(util);

    return (
      <div
        key={key}
        className={cn(
          "relative flex h-9 w-full cursor-pointer items-center justify-center rounded text-[9px] font-bold transition-all",
          cell.hasViolation
            ? "border-2 border-red-500"
            : cell.running
              ? isSfp
                ? "border-2 border-yellow-400/60"
                : "border-2 border-green-500/60"
              : "border-2 border-dashed border-muted-foreground/30",
          isSelected && "ring-2 ring-primary ring-offset-1 ring-offset-background",
        )}
        style={{
          backgroundColor: cell.vlanColor,
          backgroundImage: isTrunk
            ? `repeating-linear-gradient(45deg, transparent, transparent 3px, rgba(0,0,0,0.15) 3px, rgba(0,0,0,0.15) 6px)`
            : undefined,
          boxShadow: util > 0.05
            ? `inset 0 0 12px ${utilColor}40`
            : undefined,
        }}
        onClick={() => onSelectPort(isSelected ? null : cell.portName)}
        onMouseEnter={(e) => handleMouseEnter(cell.portName, e)}
        onMouseMove={handleMouseMove}
        onMouseLeave={handleMouseLeave}
      >
        <span className="text-white drop-shadow-[0_1px_2px_rgba(0,0,0,0.8)]">
          {cell.shortName}
        </span>
        {/* Speed indicator dot */}
        {cell.running && cell.speed && (
          <span
            className={cn(
              "absolute bottom-0.5 right-0.5 h-1 w-1 rounded-full",
              cell.speed.includes("10G") ? "bg-yellow-400" : cell.speed.includes("1G") ? "bg-green-400" : "bg-blue-400",
            )}
          />
        )}
        {/* Binding lock icon */}
        {cell.hasBound && !cell.hasViolation && (
          <span className="absolute top-0 left-0.5 text-[7px] leading-none text-white/80 drop-shadow-[0_1px_1px_rgba(0,0,0,0.8)]">
            🔒
          </span>
        )}
        {/* Violation alert */}
        {cell.hasViolation && (
          <span className="absolute top-0 left-0.5 text-[8px] leading-none animate-pulse drop-shadow-[0_1px_1px_rgba(0,0,0,0.8)]">
            ⚠️
          </span>
        )}
        {/* Utilization bar */}
        {cell.running && util > 0.01 && (
          <div
            className="absolute bottom-0 left-0 h-[3px] rounded-b transition-all"
            style={{
              width: `${Math.min(100, util * 100)}%`,
              backgroundColor: utilColor,
            }}
          />
        )}
      </div>
    );
  }

  if (portCells.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
        No port data available yet. Waiting for switch polling...
      </div>
    );
  }

  return (
    <div className="relative">
      <h2 className="mb-3 text-lg font-semibold">Port Grid</h2>
      <div className="rounded-lg border border-border bg-card p-4 shadow-sm">
        {/* Switch face layout */}
        <div className="flex items-center gap-4">
          {/* Copper ports grid */}
          <div className="flex-1">
            <div
              className="grid gap-1"
              style={{
                gridTemplateColumns: `repeat(${topRow.length}, minmax(0, 1fr))`,
              }}
            >
              {/* Top row */}
              {topRow.map((cell, i) => renderPortCell(cell, `top-${i}`))}
              {/* Bottom row */}
              {bottomRow.map((cell, i) => renderPortCell(cell, `bot-${i}`))}
            </div>
          </div>

          {/* SFP+ ports */}
          {(sfpTop || sfpBottom) && (
            <>
              <div className="w-px self-stretch bg-border" />
              <div className="grid w-14 grid-rows-2 gap-1">
                {renderPortCell(sfpTop, "sfp-top")}
                {renderPortCell(sfpBottom, "sfp-bot")}
              </div>
            </>
          )}
        </div>

        {/* Legend */}
        <div className="mt-3 flex flex-wrap gap-3 border-t border-border pt-3">
          {Object.entries(VLAN_CONFIG).map(([id, cfg]) => (
            <div key={id} className="flex items-center gap-1.5">
              <span
                className="inline-block h-2.5 w-2.5 rounded-sm"
                style={{ backgroundColor: cfg.color }}
              />
              <span className="text-[10px] text-muted-foreground">
                {id} {cfg.name}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Tooltip */}
      {hoveredCell && hoveredPort && (
        <div
          className="pointer-events-none fixed z-50 max-w-xs rounded-md border border-border bg-card p-3 shadow-lg"
          style={{
            left: tooltipPos.x + 14,
            top: tooltipPos.y + 14,
          }}
        >
          <div className="mb-1.5 font-semibold text-sm text-foreground">
            {hoveredCell.portName}
          </div>
          <div className="space-y-1 text-xs text-muted-foreground">
            <div className="flex justify-between gap-4">
              <span>Status</span>
              <span className={hoveredCell.running ? "text-green-400" : "text-red-400"}>
                {hoveredCell.running ? "Link Up" : "Link Down"}
              </span>
            </div>
            {hoveredCell.speed && (
              <div className="flex justify-between gap-4">
                <span>Speed</span>
                <span className="text-foreground">{hoveredCell.speed}</span>
              </div>
            )}
            {hoveredCell.primaryVlanId !== null && (
              <div className="flex justify-between gap-4">
                <span>VLAN</span>
                <span className="text-foreground">
                  {hoveredCell.primaryVlanId} — {vlanName(hoveredCell.primaryVlanId)}
                  {hoveredCell.vlanCount > 1 && ` (+${hoveredCell.vlanCount - 1})`}
                </span>
              </div>
            )}
            {hoveredCell.role && (
              <div className="flex justify-between gap-4">
                <span>Role</span>
                <span className="text-foreground capitalize">{hoveredCell.role}</span>
              </div>
            )}
            {hoveredCell.utilization > 0 && (
              <>
                <div className="flex justify-between gap-4">
                  <span>Utilization</span>
                  <span className="font-medium" style={{ color: utilizationColor(hoveredCell.utilization) }}>
                    {utilizationLabel(hoveredCell.utilization)}
                  </span>
                </div>
                <div className="flex justify-between gap-4">
                  <span>Rx Rate</span>
                  <span className="text-foreground">{formatBitrate(hoveredCell.rxRateBps)}</span>
                </div>
                <div className="flex justify-between gap-4">
                  <span>Tx Rate</span>
                  <span className="text-foreground">{formatBitrate(hoveredCell.txRateBps)}</span>
                </div>
                <div className="flex justify-between gap-4">
                  <span>Rated Speed</span>
                  <span className="text-foreground">{hoveredCell.ratedSpeedMbps >= 1000 ? `${hoveredCell.ratedSpeedMbps / 1000} Gbps` : `${hoveredCell.ratedSpeedMbps} Mbps`}</span>
                </div>
              </>
            )}
            {(hoveredCell.rxBytes > 0 || hoveredCell.txBytes > 0) && (
              <>
                <div className="flex justify-between gap-4">
                  <span>Rx Total</span>
                  <span className="text-foreground">{formatBytes(hoveredCell.rxBytes)}</span>
                </div>
                <div className="flex justify-between gap-4">
                  <span>Tx Total</span>
                  <span className="text-foreground">{formatBytes(hoveredCell.txBytes)}</span>
                </div>
              </>
            )}
            {hoveredCell.macCount > 0 && (
              <div className="flex justify-between gap-4">
                <span>MACs</span>
                <span className="text-foreground">{hoveredCell.macCount}</span>
              </div>
            )}
            {hoveredCell.connectedDevice && (
              <div className="mt-1.5 border-t border-border/50 pt-1.5">
                <div className="font-medium text-foreground">{hoveredCell.connectedDevice}</div>
                {hoveredCell.connectedIp && (
                  <div className="font-mono text-[10px]">{hoveredCell.connectedIp}</div>
                )}
                {hoveredCell.connectedMac && (
                  <div className="font-mono text-[10px]">{hoveredCell.connectedMac}</div>
                )}
                {hoveredCell.connectedManufacturer && hoveredCell.connectedManufacturer !== hoveredCell.connectedDevice && (
                  <div className="text-[10px]">{hoveredCell.connectedManufacturer}</div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Other ports (non-copper, non-SFP) */}
      {otherPorts.length > 0 && (
        <div className="mt-3">
          <h3 className="mb-2 text-xs font-medium text-muted-foreground uppercase tracking-wider">
            Other Interfaces
          </h3>
          <div className="flex flex-wrap gap-1">
            {otherPorts.map((cell) => (
              <div
                key={cell.portName}
                className={cn(
                  "h-8 w-16 cursor-pointer rounded border text-[9px] font-medium flex items-center justify-center",
                  cell.running ? "border-green-500/40" : "border-muted-foreground/20",
                  selectedPort === cell.portName && "ring-2 ring-primary",
                )}
                style={{ backgroundColor: cell.vlanColor }}
                onClick={() => onSelectPort(selectedPort === cell.portName ? null : cell.portName)}
              >
                <span className="text-white drop-shadow-[0_1px_2px_rgba(0,0,0,0.8)]">
                  {cell.shortName}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
