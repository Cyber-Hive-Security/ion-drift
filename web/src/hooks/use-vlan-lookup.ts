import { useMemo } from "react";
import { useVlanConfigs } from "@/api/queries";
import type { VlanConfig } from "@/api/types";

export interface VlanLookup {
  configs: Record<number, VlanConfig>;
  colors: Record<number, string>;
  names: Record<number, string>;
  subnets: Record<number, string>;
  /** Get color for a VLAN ID, with fallback */
  color: (id: number) => string;
  /** Get name for a VLAN ID, with fallback */
  name: (id: number) => string;
  /** Get subnet for a VLAN ID */
  subnet: (id: number) => string | null;
  /** Match an IP to a VLAN label using CIDR subnets */
  ipToVlanLabel: (ip: string) => string | null;
  isLoading: boolean;
}

const DEFAULT_COLOR = "#888888";

/** Parse CIDR like "10.20.25.0/24" into network number and mask bits. */
function parseCidr(cidr: string): { network: number; mask: number } | null {
  const [ipPart, prefixStr] = cidr.split("/");
  if (!ipPart || !prefixStr) return null;
  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;
  const octets = ipPart.split(".").map(Number);
  if (octets.length !== 4 || octets.some((o) => isNaN(o) || o < 0 || o > 255))
    return null;
  const ip =
    ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>>
    0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { network: (ip & mask) >>> 0, mask };
}

function ipToU32(ip: string): number | null {
  const octets = ip.split(".").map(Number);
  if (octets.length !== 4 || octets.some((o) => isNaN(o) || o < 0 || o > 255))
    return null;
  return (
    ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>>
    0
  );
}

export function useVlanLookup(): VlanLookup {
  const { data, isLoading } = useVlanConfigs();

  return useMemo(() => {
    const configs: Record<number, VlanConfig> = {};
    const colors: Record<number, string> = {};
    const names: Record<number, string> = {};
    const subnets: Record<number, string> = {};
    const cidrEntries: { vlanId: number; network: number; mask: number; prefixLen: number; name: string }[] = [];

    for (const cfg of data ?? []) {
      configs[cfg.vlan_id] = cfg;
      colors[cfg.vlan_id] = cfg.color ?? DEFAULT_COLOR;
      names[cfg.vlan_id] = cfg.name;
      if (cfg.subnet) {
        subnets[cfg.vlan_id] = cfg.subnet;
        const parsed = parseCidr(cfg.subnet);
        if (parsed) {
          const [, prefixStr] = cfg.subnet.split("/");
          cidrEntries.push({
            vlanId: cfg.vlan_id,
            network: parsed.network,
            mask: parsed.mask,
            prefixLen: parseInt(prefixStr, 10),
            name: cfg.name,
          });
        }
      }
    }

    // Sort by longest prefix first for best match
    cidrEntries.sort((a, b) => b.prefixLen - a.prefixLen);

    function color(id: number): string {
      return colors[id] ?? DEFAULT_COLOR;
    }

    function name(id: number): string {
      return names[id] ?? `VLAN ${id}`;
    }

    function subnet(id: number): string | null {
      return subnets[id] ?? null;
    }

    function ipToVlanLabel(ip: string): string | null {
      const u32 = ipToU32(ip);
      if (u32 === null) return null;
      for (const entry of cidrEntries) {
        if ((u32 & entry.mask) >>> 0 === entry.network) {
          return `VLAN ${entry.vlanId} \u00b7 ${entry.name}`;
        }
      }
      return null;
    }

    return { configs, colors, names, subnets, color, name, subnet, ipToVlanLabel, isLoading };
  }, [data, isLoading]);
}
