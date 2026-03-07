import type { VlanConfig, VlanMembershipEntry } from "@/api/types";

/**
 * Extract the numeric port index from various naming conventions.
 * Returns null if the name doesn't match any known physical port pattern.
 *
 * Supported patterns:
 *   Mikrotik:   ether1, sfp-sfpplus1
 *   Netgear:    g1, mg5, xmg9, xg10  (GigE / Multi-Gig / 5G / 10G)
 *   Cisco-like: GigabitEthernet0/1, Gi1/0/1, Te1/0/1, Fa0/1
 *   Linux:      eth0, enp0s1
 *   Numeric:    0/1, 1/0/1 (last number is port index)
 *   Generic:    port1, ge1, te1, xe1, fa1
 */
function extractPortNumber(portName: string): number | null {
  // Mikrotik ether ports
  const etherMatch = portName.match(/^ether(\d+)$/);
  if (etherMatch) return parseInt(etherMatch[1]);

  // Netgear multi-speed ports: xg10, xmg9, mg5, g1
  const netgearMatch = portName.match(/^(?:xg|xmg|mg|g)(\d+)$/);
  if (netgearMatch) return parseInt(netgearMatch[1]);

  // Generic short prefixes: port1, ge1, te1, xe1, fa1, eth0
  const genericMatch = portName.match(/^(?:port|ge|te|xe|fa|eth)(\d+)$/i);
  if (genericMatch) return parseInt(genericMatch[1]);

  // Cisco full names: GigabitEthernet0/1, TenGigabitEthernet1/0/2, FastEthernet0/1
  // Also abbreviated: Gi1/0/1, Te1/0/1, Fa0/1
  const ciscoMatch = portName.match(
    /^(?:GigabitEthernet|TenGigabitEthernet|FastEthernet|Gi|Te|Fa|Eth)[\d/]*?(\d+)$/i,
  );
  if (ciscoMatch) return parseInt(ciscoMatch[1]);

  // Slash-delimited numeric: 0/1, 1/0/1, 0/0/1 — use the last number
  const slashMatch = portName.match(/^[\d/]+$/);
  if (slashMatch) {
    const parts = portName.split("/");
    const last = parseInt(parts[parts.length - 1]);
    if (!isNaN(last)) return last;
  }

  // Last resort: any trailing number after a prefix
  const trailingMatch = portName.match(/(\d+)$/);
  if (trailingMatch) return parseInt(trailingMatch[1]);

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
 *      "sfp-sfpplus1" → "sfp-sfpplus", "GigabitEthernet0/1" → "gigabitethernet",
 *      "0/1" → "slot0", "1/0/1" → "slot1/0"
 */
export function portFamily(portName: string): string {
  // Standard prefix+number: g1, ether5, GigabitEthernet0/1, Gi1/0/1
  const m = portName.match(/^([a-zA-Z][a-zA-Z\-]*?)[\d/]+$/);
  if (m) return m[1].toLowerCase();
  // Slash-delimited numeric only: 0/1 → "slot0", 1/0/1 → "slot1/0"
  if (/^[\d/]+$/.test(portName)) {
    const parts = portName.split("/");
    if (parts.length >= 2) return `slot${parts.slice(0, -1).join("/")}`;
    return "port";
  }
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
  // Generic short: ge1, te1, etc.
  if (/^(?:ge|te|xe|fa|eth)\d+$/i.test(portName)) return portName;
  // Cisco full names → abbreviate: GigabitEthernet0/1 → Gi0/1
  const ciscoFull = portName.match(/^(GigabitEthernet|TenGigabitEthernet|FastEthernet)([\d/]+)$/i);
  if (ciscoFull) {
    const prefix = ciscoFull[1].toLowerCase().startsWith("ten") ? "Te"
      : ciscoFull[1].toLowerCase().startsWith("gig") ? "Gi" : "Fa";
    return `${prefix}${ciscoFull[2]}`;
  }
  // Slash-delimited: 0/1 → just the number
  if (/^[\d/]+$/.test(portName)) {
    const parts = portName.split("/");
    return parts[parts.length - 1];
  }
  // Anything with a trailing number: extract prefix initial + number
  const trailingMatch = portName.match(/^([a-zA-Z])[a-zA-Z\-]*?(\d+)$/);
  if (trailingMatch) return `${trailingMatch[1].toLowerCase()}${trailingMatch[2]}`;
  return portName.length > 5 ? portName.slice(0, 5) : portName;
}

/** Numeric sort key for natural port ordering. */
export function portSortKey(portName: string): number {
  if (portName === "sfp-sfpplus1") return 10000;
  if (portName === "sfp-sfpplus2") return 10001;
  const num = extractPortNumber(portName);
  if (num != null) return num;
  return 20000;
}

/** Get VLAN background color for a port. Prefers untagged VLAN as primary. */
export function getPortVlanColor(
  portName: string,
  vlans: VlanMembershipEntry[],
  vlanConfigs?: Record<number, VlanConfig>,
): string {
  const portVlans = vlans.filter((v) => v.port_name === portName);
  if (portVlans.length === 0) return "#2C3038";
  const untagged = portVlans.find((v) => !v.tagged);
  const primaryVlanId = untagged?.vlan_id ?? portVlans[0].vlan_id;
  return vlanConfigs?.[primaryVlanId]?.color ?? "#8A929D";
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
export function vlanName(vlanId: number, vlanConfigs?: Record<number, VlanConfig>): string {
  return vlanConfigs?.[vlanId]?.name ?? `VLAN ${vlanId}`;
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
