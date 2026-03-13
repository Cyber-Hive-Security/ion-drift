import { useState, useMemo } from "react";
import { cn } from "@/lib/utils";
import { formatBytes } from "@/lib/format";
import {
  portToGridPosition,
  portShortName,
  portSortKey,
  portFamily,
} from "@/features/switch-detail/utils";
import type { RouterInterface } from "@/api/types";

interface PortCell {
  name: string;
  /** Original interface name (e.g. "ether1") for grid positioning — falls back to name */
  defaultName: string;
  shortName: string;
  running: boolean;
  disabled: boolean;
  rxBytes: number;
  txBytes: number;
  type: string;
  comment: string;
  mac: string;
}

export function RouterPortGrid({ interfaces }: { interfaces: RouterInterface[] }) {
  const [hovered, setHovered] = useState<string | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });

  // Build cells from physical interfaces only (active families)
  const cells = useMemo(() => {
    const all: PortCell[] = interfaces.map((iface) => {
      // Use default-name (original hw name like "ether1") for grid layout;
      // fall back to the user-given name if default-name isn't present.
      const defaultName = iface["default-name"] ?? iface.name;
      return {
        name: iface.name,
        defaultName,
        shortName: portShortName(defaultName),
        running: iface.running,
        disabled: iface.disabled,
        rxBytes: iface["rx-byte"] ?? 0,
        txBytes: iface["tx-byte"] ?? 0,
        type: iface.type,
        comment: iface.comment ?? "",
        mac: iface["mac-address"] ?? "",
      };
    });

    // Only include ports that have a grid position (based on default/hw name)
    const gridEligible = all.filter((c) => portToGridPosition(c.defaultName) !== null);

    // Filter to active families
    const familyMap = new Map<string, PortCell[]>();
    for (const cell of gridEligible) {
      const fam = portFamily(cell.defaultName);
      const list = familyMap.get(fam) ?? [];
      list.push(cell);
      familyMap.set(fam, list);
    }
    const activeFamilies = new Set<string>();
    for (const [fam, members] of familyMap) {
      if (members.some((c) => c.running)) activeFamilies.add(fam);
    }

    return gridEligible
      .filter((c) => activeFamilies.has(portFamily(c.defaultName)))
      .sort((a, b) => portSortKey(a.defaultName) - portSortKey(b.defaultName));
  }, [interfaces]);

  // Build grid rows
  const { topRow, bottomRow, sfpTop, sfpBottom } = useMemo(() => {
    let st: PortCell | null = null;
    let sb: PortCell | null = null;
    const gridded: { cell: PortCell; col: number; row: "top" | "bottom" }[] = [];

    for (const cell of cells) {
      const pos = portToGridPosition(cell.defaultName);
      if (!pos) continue;
      if (pos.col === -1) {
        if (pos.row === "top") st = cell;
        else sb = cell;
      } else {
        gridded.push({ cell, col: pos.col, row: pos.row });
      }
    }

    const usedCols = [...new Set(gridded.map((g) => g.col))].sort((a, b) => a - b);
    const colRemap = new Map<number, number>();
    usedCols.forEach((col, idx) => colRemap.set(col, idx));

    const numCols = usedCols.length;
    const top: (PortCell | null)[] = Array(numCols).fill(null);
    const bottom: (PortCell | null)[] = Array(numCols).fill(null);

    for (const { cell, col, row } of gridded) {
      const mapped = colRemap.get(col)!;
      if (row === "top") top[mapped] = cell;
      else bottom[mapped] = cell;
    }

    return { topRow: top, bottomRow: bottom, sfpTop: st, sfpBottom: sb };
  }, [cells]);

  const maxTraffic = useMemo(() => {
    let max = 1;
    for (const c of cells) max = Math.max(max, c.rxBytes + c.txBytes);
    return max;
  }, [cells]);

  const hoveredCell = cells.find((c) => c.name === hovered);

  if (cells.length === 0) return null;

  function renderCell(cell: PortCell | null, key: string) {
    if (!cell) {
      return <div key={key} className="h-9 w-full rounded border border-border/20 bg-muted/20" />;
    }

    const traffic = (cell.rxBytes + cell.txBytes) / maxTraffic;
    const glowOpacity = cell.running ? Math.max(0.05, traffic * 0.5) : 0;
    const isSfp = cell.defaultName.startsWith("sfp");

    return (
      <div
        key={key}
        className={cn(
          "relative flex h-9 w-full items-center justify-center rounded text-[9px] font-bold transition-all",
          cell.running
            ? isSfp
              ? "border-2 border-yellow-400/60"
              : "border-2 border-green-500/60"
            : "border-2 border-dashed border-muted-foreground/30",
        )}
        style={{
          backgroundColor: cell.running ? "rgba(33, 208, 122, 0.15)" : "rgba(138, 146, 157, 0.1)",
          boxShadow: glowOpacity > 0.1
            ? `inset 0 0 12px rgba(255,255,255,${glowOpacity})`
            : undefined,
        }}
        onMouseEnter={(e) => {
          setHovered(cell.name);
          setTooltipPos({ x: e.clientX, y: e.clientY });
        }}
        onMouseMove={(e) => setTooltipPos({ x: e.clientX, y: e.clientY })}
        onMouseLeave={() => setHovered(null)}
      >
        <span className={cn("drop-shadow-[0_1px_2px_rgba(0,0,0,0.6)]", cell.running ? "text-foreground" : "text-muted-foreground")}>
          {cell.shortName}
        </span>
      </div>
    );
  }

  return (
    <div className="relative mb-4">
      <div className="rounded-lg border border-border bg-card p-4 shadow-sm">
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <div
              className="grid gap-1"
              style={{ gridTemplateColumns: `repeat(${topRow.length}, minmax(0, 1fr))` }}
            >
              {topRow.map((cell, i) => renderCell(cell, `top-${i}`))}
              {bottomRow.map((cell, i) => renderCell(cell, `bot-${i}`))}
            </div>
          </div>
          {(sfpTop || sfpBottom) && (
            <>
              <div className="w-px self-stretch bg-border" />
              <div className="grid w-14 grid-rows-2 gap-1">
                {renderCell(sfpTop, "sfp-top")}
                {renderCell(sfpBottom, "sfp-bot")}
              </div>
            </>
          )}
        </div>
      </div>

      {/* Tooltip */}
      {hoveredCell && (
        <div
          className="pointer-events-none fixed z-50 max-w-xs rounded-md border border-border bg-card p-3 shadow-lg"
          style={{ left: tooltipPos.x + 14, top: tooltipPos.y + 14 }}
        >
          <div className="mb-1.5 text-sm font-semibold text-foreground">
            {hoveredCell.name}
            {hoveredCell.name !== hoveredCell.defaultName && (
              <span className="ml-2 font-normal text-muted-foreground">({hoveredCell.defaultName})</span>
            )}
            {hoveredCell.comment && (
              <span className="ml-2 font-normal text-muted-foreground">{hoveredCell.name !== hoveredCell.defaultName ? "— " : "("}{hoveredCell.comment}{hoveredCell.name === hoveredCell.defaultName && ")"}</span>
            )}
          </div>
          <div className="space-y-1 text-xs text-muted-foreground">
            <div className="flex justify-between gap-4">
              <span>Status</span>
              <span className={hoveredCell.running ? "text-success" : "text-destructive"}>
                {hoveredCell.disabled ? "Disabled" : hoveredCell.running ? "Link Up" : "Link Down"}
              </span>
            </div>
            <div className="flex justify-between gap-4">
              <span>Type</span>
              <span className="text-foreground">{hoveredCell.type}</span>
            </div>
            {hoveredCell.mac && (
              <div className="flex justify-between gap-4">
                <span>MAC</span>
                <span className="font-mono text-foreground">{hoveredCell.mac}</span>
              </div>
            )}
            {(hoveredCell.rxBytes > 0 || hoveredCell.txBytes > 0) && (
              <>
                <div className="flex justify-between gap-4">
                  <span>Rx</span>
                  <span className="text-foreground">{formatBytes(hoveredCell.rxBytes)}</span>
                </div>
                <div className="flex justify-between gap-4">
                  <span>Tx</span>
                  <span className="text-foreground">{formatBytes(hoveredCell.txBytes)}</span>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
