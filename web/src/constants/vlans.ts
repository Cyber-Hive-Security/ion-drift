// Shared VLAN color and name constants used across the topology page
// and any other feature that needs VLAN visual identity.
// Source of truth mirrors the tactical map's VLAN_CONFIG.

export const VLAN_COLORS: Record<number, string> = {
  2: "#00f0ff",
  6: "#888888",
  10: "#ff4444",
  25: "#00b4d8",
  30: "#22cc88",
  35: "#44ddaa",
  40: "#ffaa00",
  90: "#f97316",
  99: "#7FFF00",
};

export const VLAN_NAMES: Record<number, string> = {
  2: "Network Mgmt",
  6: "Employer Isolated",
  10: "Cyber Hive Security",
  25: "Trusted Services",
  30: "Trusted Wired",
  35: "Trusted Wireless",
  40: "Guest",
  90: "IoT Internet",
  99: "IoT Restricted",
};

export const VLAN_SUBNETS: Record<number, string> = {
  2: "10.2.2.0/24",
  6: "172.20.6.0/24",
  10: "172.20.10.0/24",
  25: "10.20.25.0/24",
  30: "10.20.30.0/24",
  35: "10.20.35.0/24",
  40: "\u2014",
  90: "192.168.90.0/24",
  99: "192.168.99.0/24",
};
