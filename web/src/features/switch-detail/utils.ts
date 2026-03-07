import { VLAN_CONFIG } from "@/constants/vlans";
import type { VlanMembershipEntry } from "@/api/types";

/**
 * Extract the numeric port index from various naming conventions.
 * Returns null if the name doesn't match any known physical port pattern.
 *
 * Supported patterns:
 *   Mikrotik:  ether1, sfp-sfpplus1
 *   Netgear:   g1, mg5, xmg9, xg10  (GigE / Multi-Gig / 5G / 10G)
 *   Generic:   port1, ge1, te1, xe1
 */
function extractPortNumber(portName: string): number | null {
  // Mikrotik ether ports
  const etherMatch = portName.match(/^ether(\d+)$/);
  if (etherMatch) return parseInt(etherMatch[1]);

  // Netgear multi-speed ports: xg10, xmg9, mg5, g1
  const netgearMatch = portName.match(/^(?:xg|xmg|mg|g)(\d+)$/);
  if (netgearMatch) return parseInt(netgearMatch[1]);

  // Generic patterns: port1, ge1, te1, xe1, fa1
  const genericMatch = portName.match(/^(?:port|ge|te|xe|fa)(\d+)$/i);
  if (genericMatch) return parseInt(genericMatch[1]);

  return null;
}

/** Map a port name to its physical grid position on the switch face. */
export function portToGridPosition(
  portName: string,
): { row: "top" | "bottom"; col: number } | null {
  // SFP/SFP+ ports get their own slot
  if (portName === "sfp-sfpplus1") return { row: "top", col: -1 };
  if (portName === "sfp-sfpplus2") return { row: "bottom", col: -1 };

  const num = extractPortNumber(portName);
  if (num == null || num < 1 || num > 48) return null;

  // Odd ports on top row, even on bottom — pairs in columns
  return {
    row: num % 2 === 1 ? "top" : "bottom",
    col: Math.ceil(num / 2) - 1,
  };
}

/**
 * Extract the family/prefix of a port name for grouping.
 * e.g. "g1" → "g", "ether5" → "ether", "Port-channel1" → "port-channel",
 *      "sfp-sfpplus1" → "sfp-sfpplus", "ch3" → "ch"
 */
export function portFamily(portName: string): string {
  const m = portName.match(/^([a-zA-Z][a-zA-Z\-]*?)(\d+)$/);
  if (m) return m[1].toLowerCase();
  return portName.toLowerCase();
}

/** Abbreviate port name for display inside the port cell. */
export function portShortName(portName: string): string {
  const etherMatch = portName.match(/^ether(\d+)$/);
  if (etherMatch) return `e${etherMatch[1]}`;
  if (portName === "sfp-sfpplus1") return "S1";
  if (portName === "sfp-sfpplus2") return "S2";
  // Netgear: keep as-is since names are already short (g1, mg5, xg10)
  if (/^(?:xg|xmg|mg|g)\d+$/.test(portName)) return portName;
  // Generic: ge1, te1, etc.
  if (/^(?:ge|te|xe|fa)\d+$/i.test(portName)) return portName;
  return portName.slice(0, 4);
}

/** Numeric sort key for natural port ordering. */
export function portSortKey(portName: string): number {
  if (portName === "sfp-sfpplus1") return 100;
  if (portName === "sfp-sfpplus2") return 101;
  const num = extractPortNumber(portName);
  if (num != null) return num;
  return 200;
}

/** Get VLAN background color for a port. Prefers untagged VLAN as primary. */
export function getPortVlanColor(
  portName: string,
  vlans: VlanMembershipEntry[],
): string {
  const portVlans = vlans.filter((v) => v.port_name === portName);
  if (portVlans.length === 0) return "#2C3038";
  const untagged = portVlans.find((v) => !v.tagged);
  const primaryVlanId = untagged?.vlan_id ?? portVlans[0].vlan_id;
  return VLAN_CONFIG[primaryVlanId]?.color ?? "#8A929D";
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
