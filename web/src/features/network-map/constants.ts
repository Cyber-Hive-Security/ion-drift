// ============================================================
//  Network Map — Layout Constants & Icon Paths
// ============================================================

import type { VlanLayout } from "./types";

export const MAP_WIDTH = 3200;
export const MAP_HEIGHT = 2200;
export const HEX_RADIUS = 22;

// SVG icon paths (24x24 viewBox)
export const ICON_PATHS: Record<string, string> = {
  router:
    "M12,2C6.48,2,2,6.48,2,12s4.48,10,10,10,10-4.48,10-10S17.52,2,12,2Zm-1,17.93c-3.94-.49-7-3.85-7-7.93,0-.62.08-1.22.21-1.79L9,15v1a2,2,0,0,0,2,2Zm6.9-2.54A2,2,0,0,0,17,16H16V13a1,1,0,0,0-1-1H9V10h2a1,1,0,0,0,1-1V7h2a2,2,0,0,0,2-2v-.41A8,8,0,0,1,20,12,7.88,7.88,0,0,1,18.9,17.39Z",
  switch:
    "M20,3H4A2,2,0,0,0,2,5V19a2,2,0,0,0,2,2H20a2,2,0,0,0,2-2V5A2,2,0,0,0,20,3ZM10,17H6V15h4Zm0-4H6V11h4Zm0-4H6V7h4Zm8,8H12V15h6Zm0-4H12V11h6Zm0-4H12V7h6Z",
  proxmox:
    "M4,2H20A2,2,0,0,1,22,4V20A2,2,0,0,1,20,22H4A2,2,0,0,1,2,20V4A2,2,0,0,1,4,2M6,6V18H18V6H6M8,8H16V10H8V8M8,12H13V14H8V12",
  storage:
    "M12,3C7.58,3,4,4.79,4,7V17C4,19.21,7.59,21,12,21S20,19.21,20,17V7C20,4.79,16.42,3,12,3M12,5C15.87,5,18,6.5,18,7S15.87,9,12,9,6,7.5,6,7,8.13,5,12,5M18,17C18,17.5,15.87,19,12,19S6,17.5,6,17V14.77C7.61,15.55,9.72,16,12,16S16.39,15.55,18,14.77V17M18,12.45C16.7,13.4,14.42,14,12,14S7.3,13.4,6,12.45V9.64C7.47,10.47,9.61,11,12,11S16.53,10.47,18,9.64V12.45Z",
  docker:
    "M21,10.5H20V7.5A1.5,1.5,0,0,0,18.5,6H15V3.5A1.5,1.5,0,0,0,13.5,2H10.5A1.5,1.5,0,0,0,9,3.5V6H5.5A1.5,1.5,0,0,0,4,7.5V10.5H3A1,1,0,0,0,2,11.5V13C2,16.59,5.07,19.5,9,20.66V22H15V20.66C18.93,19.5,22,16.59,22,13V11.5A1,1,0,0,0,21,10.5M10.5,3.5H13.5V6H10.5V3.5M5.5,7.5H18.5V10.5H5.5V7.5Z",
  security:
    "M12,1L3,5V11C3,16.55,6.84,21.74,12,23C17.16,21.74,21,16.55,21,11V5L12,1M12,5A3,3,0,0,1,15,8V10H17V18H7V10H9V8A3,3,0,0,1,12,5M12,7A1,1,0,0,0,11,8V10H13V8A1,1,0,0,0,12,7Z",
  media: "M8,5.14V19.14L19,12.14L8,5.14Z",
  network:
    "M12,21L15.6,16.2C14.6,15.45,13.35,15,12,15C10.65,15,9.4,15.45,8.4,16.2L12,21M12,3C7.95,3,4.21,4.34,1.2,6.6L3,9C5.5,7.12,8.62,6,12,6C15.38,6,18.5,7.12,21,9L22.8,6.6C19.79,4.34,16.05,3,12,3M12,9C9.3,9,6.81,9.89,4.8,11.4L6.6,13.8C8.1,12.67,9.97,12,12,12C14.03,12,15.9,12.67,17.4,13.8L19.2,11.4C17.19,9.89,14.7,9,12,9Z",
  iot: "M9,3V4H5V7H4V3H9M15,3H20V7H19V4H15V3M4,17V21H9V20H5V17H4M19,17V20H15V21H20V17H19M7,7H17V17H7V7M9,9V15H15V9H9Z",
  workstation:
    "M21,16H3V4H21M21,2H3C1.89,2,1,2.89,1,4V16A2,2,0,0,0,3,18H10V20H8V22H16V20H14V18H21A2,2,0,0,0,23,16V4C23,2.89,22.1,2,21,2Z",
  vm: "M4,1H20A1,1,0,0,1,21,2V22A1,1,0,0,1,20,23H4A1,1,0,0,1,3,22V2A1,1,0,0,1,4,1M5,3V21H19V3H5M12,17A1.5,1.5,0,1,1,13.5,15.5,1.5,1.5,0,0,1,12,17M8,7H16V13H8V7Z",
  lxc: "M5,3H19A2,2,0,0,1,21,5V19A2,2,0,0,1,19,21H5A2,2,0,0,1,3,19V5A2,2,0,0,1,5,3M7,7V9H9V7H7M11,7V9H13V7H11M7,11V13H9V11H7M11,11V13H13V11H11M7,15V17H9V15H7Z",
  mail: "M20,8L12,13L4,8V6L12,11L20,6M20,4H4C2.89,4,2,4.89,2,6V18A2,2,0,0,0,4,20H20A2,2,0,0,0,22,18V6C22,4.89,21.1,4,20,4Z",
  monitor:
    "M12,2A10,10,0,0,0,2,12A10,10,0,0,0,12,22A10,10,0,0,0,22,12A10,10,0,0,0,12,2M12,20A8,8,0,0,1,4,12A8,8,0,0,1,12,4A8,8,0,0,1,20,12A8,8,0,0,1,12,20M12,6A6,6,0,0,0,6,12H8A4,4,0,0,1,12,8V6M12,10A2,2,0,0,0,10,12H12V10Z",
  vpn: "M12,1L3,5V11C3,16.55,6.84,21.74,12,23C17.16,21.74,21,16.55,21,11V5L12,1M10,17L6,13L7.41,11.59L10,14.17L16.59,7.58L18,9L10,17Z",
  dns: "M12,2C6.48,2,2,6.48,2,12S6.48,22,12,22,22,17.52,22,12,17.52,2,12,2M4,12C4,7.58,7.58,4,12,4V20C7.58,20,4,16.42,4,12Z",
  agent:
    "M12,2A2,2,0,0,1,14,4C14,4.74,13.6,5.39,13,5.73V7H14A7,7,0,0,1,21,14H22A1,1,0,0,1,23,15V18A1,1,0,0,1,22,19H21V20A2,2,0,0,1,19,22H5A2,2,0,0,1,3,20V19H2A1,1,0,0,1,1,18V15A1,1,0,0,1,2,14H3A7,7,0,0,1,10,7H11V5.73A2,2,0,0,1,12,2M7.5,13A2.5,2.5,0,0,0,5,15.5,2.5,2.5,0,0,0,7.5,18,2.5,2.5,0,0,0,10,15.5,2.5,2.5,0,0,0,7.5,13M16.5,13A2.5,2.5,0,0,0,14,15.5,2.5,2.5,0,0,0,16.5,18,2.5,2.5,0,0,0,19,15.5,2.5,2.5,0,0,0,16.5,13Z",
};

// VLAN zone bounding boxes on the 3200x2200 canvas
export const VLAN_LAYOUT: Record<number, VlanLayout> = {
  25: { cx: MAP_WIDTH / 2, cy: MAP_HEIGHT / 2, w: 1800, h: 1000 },
  10: { cx: MAP_WIDTH / 2 + 1050, cy: MAP_HEIGHT / 2 - 350, w: 400, h: 350 },
  2: { cx: MAP_WIDTH / 2 - 1100, cy: MAP_HEIGHT / 2 - 300, w: 400, h: 450 },
  30: { cx: MAP_WIDTH / 2 - 1000, cy: MAP_HEIGHT / 2 + 350, w: 350, h: 250 },
  35: { cx: MAP_WIDTH / 2 - 550, cy: MAP_HEIGHT / 2 + 500, w: 350, h: 250 },
  6: { cx: MAP_WIDTH / 2 + 1050, cy: MAP_HEIGHT / 2 + 350, w: 250, h: 180 },
  90: { cx: MAP_WIDTH / 2 + 500, cy: MAP_HEIGHT / 2 + 500, w: 400, h: 250 },
  99: { cx: MAP_WIDTH / 2 + 100, cy: MAP_HEIGHT / 2 + 550, w: 350, h: 200 },
};

// Hardcoded node positions within VLAN 25 (offsets from zone center)
export const POSITIONS_25: Record<string, { x: number; y: number }> = {
  mikrotik: { x: -20, y: -50 },
  mt326: { x: 0, y: 0 },
  holocron1: { x: -300, y: -250 },
  holocron2: { x: 300, y: -250 },
  relay1: { x: 550, y: -100 },
  ca: { x: -180, y: 120 },
  keycloak: { x: 180, y: -80 },
  spike: { x: 350, y: 60 },
  stalwart: { x: 100, y: 120 },
  commnet: { x: -300, y: 20 },
  truenas: { x: -500, y: 80 },
  opencloud: { x: -600, y: 180 },
  plex: { x: -600, y: -100 },
  dockeryard: { x: 500, y: 120 },
  kuatdockeryard: { x: 650, y: -30 },
  packetfence: { x: -100, y: 200 },
  adguard: { x: -450, y: -250 },
  technitium: { x: -350, y: -350 },
  elk: { x: 50, y: 250 },
  seconion: { x: -50, y: 330 },
  "wireguard-25": { x: 680, y: -200 },
  gameserver: { x: -180, y: -350 },
  rustbuilder: { x: -80, y: -280 },
  ai: { x: -500, y: 200 },
  "n8n-learn": { x: -400, y: -180 },
  jumpbox: { x: -200, y: -200 },
  csilla: { x: 200, y: -180 },
  analyzer: { x: 400, y: -180 },
  "rusbuild-ai": { x: 50, y: -350 },
  "truenas-bak": { x: -650, y: 300 },
  "b2-cloud": { x: -750, y: 380 },
  protectli: { x: 200, y: 300 },
};

// Boot sequence lines
export const BOOT_LINES = [
  "[ BOOT ] Initializing Hive Tactical Display v2.1...",
  "[ AUTH ] Authenticating svc-claude@kaziik.xyz",
  "[ AUTH ] LDAP bind successful \u2014 clearance: OPERATOR",
  "[ SCAN ] Enumerating VLAN sectors...",
  "[ SCAN ] SECTOR-02: Network Management  \u2014 8 devices",
  "[ SCAN ] SECTOR-10: Cyber Hive Security  \u2014 5 nodes",
  "[ SCAN ] SECTOR-25: Trusted Services     \u2014 30+ nodes",
  "[ SCAN ] SECTOR-30: Trusted Wired        \u2014 3 endpoints",
  "[ SCAN ] SECTOR-35: Trusted Wireless      \u2014 4 endpoints",
  "[ SCAN ] SECTOR-90: IoT Internet          \u2014 5 devices",
  "[ SCAN ] SECTOR-99: IoT Restricted        \u2014 5 cameras",
  "[ TOPO ] Mapping Proxmox cluster topology...",
  "[ TOPO ] Mapping Docker container stacks...",
  "[ TOPO ] Resolving network connections...",
  "[ GRID ] Rendering tactical grid overlay...",
  "[ DONE ] All systems nominal. Display ready.",
];
