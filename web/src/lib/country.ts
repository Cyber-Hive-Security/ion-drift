/** Convert a 2-letter ISO country code to a flag emoji. */
export function countryFlag(code: string): string {
  const upper = code.toUpperCase();
  if (upper.length !== 2) return "";
  const codePoints = [...upper].map(
    (c) => 0x1f1e6 + c.charCodeAt(0) - 65,
  );
  return String.fromCodePoint(...codePoints);
}

/** Check if an IP is in RFC1918 private range. */
export function isPrivateIp(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return false;
  return (
    parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    parts[0] === 127
  );
}

/** Map private IP subnets to VLAN labels. */
const VLAN_MAP: Record<string, string> = {
  "10.20.25": "VLAN 25 \u00b7 Services",
  "10.20.30": "VLAN 30 \u00b7 Trusted Wired",
  "10.20.35": "VLAN 35 \u00b7 Trusted Wireless",
  "172.20.10": "VLAN 10 \u00b7 Cyber Hive",
  "172.20.6": "VLAN 6 \u00b7 Employer",
  "192.168.90": "VLAN 90 \u00b7 IoT Internet",
  "192.168.99": "VLAN 99 \u00b7 IoT Restricted",
  "10.2.2": "VLAN 2 \u00b7 Management",
};

/** Get a VLAN label for a private IP address. */
export function vlanLabel(ip: string): string | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  // Try 3-octet match first, then 2-octet
  const key3 = `${parts[0]}.${parts[1]}.${parts[2]}`;
  return VLAN_MAP[key3] ?? null;
}
