// Shared VLAN color and name constants used across the app.
// Single source of truth for VLAN visual identity.

export interface VlanConfig {
  name: string;
  code: string;
  color: string;
  subnet: string;
}

export const VLAN_CONFIG: Record<number, VlanConfig> = {
  2: { name: "NETWORK MGMT", code: "SECTOR-02", color: "#00E5FF", subnet: "10.2.2.0/24" },
  6: { name: "EMPLOYER ISOLATED", code: "SECTOR-06", color: "#8A929D", subnet: "172.20.6.0/24" },
  10: { name: "CYBER HIVE SECURITY", code: "SECTOR-10", color: "#FF4D4F", subnet: "172.20.10.0/24" },
  25: { name: "TRUSTED SERVICES", code: "SECTOR-25", color: "#2FA4FF", subnet: "10.20.25.0/24" },
  30: { name: "TRUSTED WIRED", code: "SECTOR-30", color: "#21D07A", subnet: "10.20.30.0/24" },
  35: { name: "TRUSTED WIRELESS", code: "SECTOR-35", color: "#32FF9C", subnet: "10.20.35.0/24" },
  40: { name: "GUEST", code: "SECTOR-40", color: "#FFC857", subnet: "\u2014" },
  90: { name: "IoT INTERNET", code: "SECTOR-90", color: "#7A5CFF", subnet: "192.168.90.0/24" },
  99: { name: "IoT RESTRICTED", code: "SECTOR-99", color: "#FF4FD8", subnet: "192.168.99.0/24" },
};

export const VLAN_COLORS: Record<number, string> = {
  2: "#00E5FF",
  6: "#8A929D",
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
