// Shared VLAN color and name constants used across the topology page
// and any other feature that needs VLAN visual identity.
// Source of truth mirrors the tactical map's VLAN_CONFIG.

export const VLAN_COLORS: Record<number, string> = {
  2: "#00E5FF",
  6: "#6B7785",
  10: "#FF4D4F",
  25: "#2FA4FF",
  30: "#21D07A",
  35: "#32FF9C",
  40: "#FFC857",
  90: "#7A5CFF",
  99: "#FF4FD8",
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
