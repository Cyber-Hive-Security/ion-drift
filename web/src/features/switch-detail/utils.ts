import { VLAN_CONFIG } from "@/features/network-map/data";
import type { VlanMembershipEntry } from "@/api/types";

/** Map a port name to its physical grid position on the switch face. */
export function portToGridPosition(
  portName: string,
): { row: "top" | "bottom"; col: number } | null {
  const etherMatch = portName.match(/^ether(\d+)$/);
  if (etherMatch) {
    const num = parseInt(etherMatch[1]);
    if (num < 1 || num > 48) return null;
    // Mikrotik CRS: odd ports on top row, even on bottom
    return {
      row: num % 2 === 1 ? "top" : "bottom",
      col: Math.ceil(num / 2) - 1,
    };
  }
  if (portName === "sfp-sfpplus1") return { row: "top", col: -1 }; // SFP marker
  if (portName === "sfp-sfpplus2") return { row: "bottom", col: -1 };
  return null;
}

/** Abbreviate port name for display inside the port cell. */
export function portShortName(portName: string): string {
  const etherMatch = portName.match(/^ether(\d+)$/);
  if (etherMatch) return `e${etherMatch[1]}`;
  if (portName === "sfp-sfpplus1") return "S1";
  if (portName === "sfp-sfpplus2") return "S2";
  return portName.slice(0, 4);
}

/** Numeric sort key for natural port ordering. */
export function portSortKey(portName: string): number {
  const etherMatch = portName.match(/^ether(\d+)$/);
  if (etherMatch) return parseInt(etherMatch[1]);
  if (portName === "sfp-sfpplus1") return 100;
  if (portName === "sfp-sfpplus2") return 101;
  return 200;
}

/** Get VLAN background color for a port. Prefers untagged VLAN as primary. */
export function getPortVlanColor(
  portName: string,
  vlans: VlanMembershipEntry[],
): string {
  const portVlans = vlans.filter((v) => v.port_name === portName);
  if (portVlans.length === 0) return "oklch(0.2 0.01 285)";
  const untagged = portVlans.find((v) => !v.tagged);
  const primaryVlanId = untagged?.vlan_id ?? portVlans[0].vlan_id;
  return VLAN_CONFIG[primaryVlanId]?.color ?? "#666666";
}

/** Get the primary VLAN ID for a port (untagged preferred). */
export function getPortPrimaryVlan(
  portName: string,
  vlans: VlanMembershipEntry[],
): number | null {
  const portVlans = vlans.filter((v) => v.port_name === portName);
  if (portVlans.length === 0) return null;
  const untagged = portVlans.find((v) => !v.tagged);
  return untagged?.vlan_id ?? portVlans[0].vlan_id;
}

/** Get VLAN name for display. */
export function vlanName(vlanId: number): string {
  return VLAN_CONFIG[vlanId]?.name ?? `VLAN ${vlanId}`;
}

/** Format bytes per second as a human-readable rate. */
export function formatRate(bytesPerSec: number): string {
  if (bytesPerSec <= 0) return "0 bps";
  const bps = bytesPerSec * 8;
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(1)} Gbps`;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbps`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} Kbps`;
  return `${Math.round(bps)} bps`;
}

/** Format a unix timestamp as relative time ("2m ago"). */
export function relativeTime(timestamp: number): string {
  const now = Math.floor(Date.now() / 1000);
  const diff = now - timestamp;
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
