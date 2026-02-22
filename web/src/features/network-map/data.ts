// ============================================================
//  THE HIVE TACTICAL DISPLAY — Network Topology Data
//  All data sourced from CLAUDE.md infrastructure documentation
// ============================================================

import type {
  VlanConfig,
  NodeTypeConfig,
  NetworkNodeRaw,
  Connection,
  ConnectionStyle,
} from "./types";

export const VLAN_CONFIG: Record<number, VlanConfig> = {
  2: { name: "NETWORK MGMT", code: "SECTOR-02", color: "#00f0ff", subnet: "10.2.2.0/24" },
  6: { name: "EMPLOYER ISOLATED", code: "SECTOR-06", color: "#888888", subnet: "172.20.6.0/24" },
  10: { name: "CYBER HIVE SECURITY", code: "SECTOR-10", color: "#ff4444", subnet: "172.20.10.0/24" },
  25: { name: "TRUSTED SERVICES", code: "SECTOR-25", color: "#00b4d8", subnet: "10.20.25.0/24" },
  30: { name: "TRUSTED WIRED", code: "SECTOR-30", color: "#22cc88", subnet: "10.20.30.0/24" },
  35: { name: "TRUSTED WIRELESS", code: "SECTOR-35", color: "#44ddaa", subnet: "10.20.35.0/24" },
  40: { name: "GUEST", code: "SECTOR-40", color: "#ffaa00", subnet: "\u2014" },
  90: { name: "IoT INTERNET", code: "SECTOR-90", color: "#666666", subnet: "192.168.90.0/24" },
  99: { name: "IoT RESTRICTED", code: "SECTOR-99", color: "#444444", subnet: "192.168.99.0/24" },
};

export const NODE_TYPES: Record<string, NodeTypeConfig> = {
  router: { icon: "router", color: "#ffd700", label: "Router/Firewall" },
  switch: { icon: "switch", color: "#00e5ff", label: "Core Switch" },
  proxmox: { icon: "proxmox", color: "#00b4d8", label: "Proxmox Node" },
  storage: { icon: "storage", color: "#00ff88", label: "Storage" },
  "docker-host": { icon: "docker", color: "#b388ff", label: "Docker Host" },
  security: { icon: "security", color: "#ff4444", label: "Security/IAM" },
  media: { icon: "media", color: "#ff8c00", label: "Media Server" },
  network: { icon: "network", color: "#00f0ff", label: "Network Device" },
  iot: { icon: "iot", color: "#666666", label: "IoT Device" },
  workstation: { icon: "workstation", color: "#cccccc", label: "Workstation" },
  vm: { icon: "vm", color: "#0088cc", label: "Virtual Machine" },
  lxc: { icon: "lxc", color: "#0099aa", label: "LXC Container" },
  container: { icon: "container", color: "#9966ff", label: "Docker Container" },
  mail: { icon: "mail", color: "#00ccff", label: "Mail Server" },
  monitor: { icon: "monitor", color: "#ffaa00", label: "Monitoring" },
  vpn: { icon: "vpn", color: "#22cc66", label: "VPN" },
  dns: { icon: "dns", color: "#00f0ff", label: "DNS" },
  agent: { icon: "agent", color: "#00ffcc", label: "AI Agent" },
};

export const NODES_RAW: NetworkNodeRaw[] = [
  // ── VLAN 25 — TRUSTED SERVICES ──
  {
    id: "mikrotik", hostname: "RB4011", ip: "10.20.25.1", vlan: 25, type: "router",
    role: "Primary Gateway / Firewall",
    specs: { model: "Mikrotik RB4011iGS+5HacQ2HnD", cpu: "Quad-core IPQ-4019 / AL21400", ram: "1 GB", interfaces: "10x 1GbE, 1x SFP+", internet: "1 Gbps symmetrical fiber" },
    details: ["Primary router for all VLANs", "FastTrack with HW offload enabled", "WireGuard UDP 58813 from WAN", "Firewall interface lists: LAN (trusted VLANs 2,10,25,30,35) / UNTRUST (6,40,90,99)", "Router mgmt restricted to VLANs 30/35", "10 Gbps DAC backbone to CRS326 switch"],
  },
  {
    id: "mt326", hostname: "CRS326-Office", ip: "10.2.2.2", vlan: 2, type: "switch",
    role: "Core Switch (Office)", isHub: true,
    specs: { model: "Mikrotik CRS326-24G-2S+" },
    details: ["Core switch \u2014 primary interconnect for all devices", "24x 1GbE + 2x SFP+", "10 Gbps DAC uplink to RB4011", "Connects Proxmox cluster, TrueNAS, Plex, and downstream switches/WAPs"],
  },
  {
    id: "ca", hostname: "CA", ip: "10.20.25.2", vlan: 25, type: "security",
    role: "Certificate Authority (Smallstep)",
    specs: { software: "step-ca v0.29.0", runtime: "Go 1.24.13", hsm: "YubiKey 5 (PIV 9a=root, 9c=intermediate)" },
    details: ["Built from source \u2014 no pre-built binaries", "YubiKey-backed \u2014 no private keys on disk", "Self-healing health check w/ Uptime Kuma reporting", "NO SSH ACCESS (by design)", "CVE-2025-44005 + CVE-2025-66406: Patched (2026-02-07)", "setcap CAP_NET_BIND_SERVICE for non-root binding"],
  },
  {
    id: "keycloak", hostname: "HolonetID", ip: "10.20.25.3", vlan: 25, type: "security",
    role: "Identity & Access Management (Keycloak)", parent: "holocron2",
    specs: { software: "Keycloak 26.0.7", type: "VM on holocron2", db: "MariaDB (localhost:3306)", realm: "TheHolonet" },
    details: ["OIDC SSO for: Proxmox, VaultWarden, Gitea, Paperless, KitchenOwl, Homarr, Ko-Pellet", "LDAP federation: ou=users only (services excluded by design)", "SMTP via svc-keycloak on Stalwart (port 587 STARTTLS)", "Admin API: master realm token endpoint"],
  },
  {
    id: "packetfence", hostname: "PacketFence", ip: "10.20.25.4", vlan: 25, type: "security",
    role: "Network Access Control",
    specs: { software: "PacketFence" }, details: ["NAC for network access control"],
  },
  {
    id: "adguard", hostname: "AdGuard Home", ip: "10.20.25.5", vlan: 25, type: "dns",
    role: "DNS Filtering", parent: "relay1",
    specs: { software: "AdGuard Home", type: "LXC on relay1" },
    details: ["DNS filtering layer", "Upstream: Technitium (authoritative)", "DNS flow: Client -> AdGuard -> Technitium -> upstream"],
  },
  {
    id: "technitium", hostname: "Technitium", ip: "10.20.25.6", vlan: 25, type: "dns",
    role: "Authoritative DNS", parent: "holocron1",
    specs: { software: "Technitium DNS Server", type: "LXC on holocron1" },
    details: ["Authoritative for kaziik.xyz and *.mycyberhive.com", "Receives queries from AdGuard Home", "Forwards unknown zones upstream"],
  },
  {
    id: "spike", hostname: "Spike", ip: "10.20.25.7", vlan: 25, type: "security",
    role: "Directory Service (OpenLDAP)", parent: "holocron2",
    specs: { software: "OpenLDAP (slapd)", type: "LXC on holocron2 (CT 506)", protocol: "ldaps://spike.kaziik.xyz:636", baseDN: "dc=kaziik,dc=xyz" },
    details: ["ou=users: human accounts (federated to Keycloak)", "ou=services: service accounts (NOT in Keycloak)", "Admin DN: cn=admin,dc=kaziik,dc=xyz", "userPassword ACL: self-read only", "All service accounts use inetOrgPerson (NOT posixAccount)", "Access via pct exec 506 from holocron2"],
  },
  {
    id: "commnet", hostname: "Commnet", ip: "10.20.25.8", vlan: 25, type: "docker-host",
    role: "Reverse Proxy Hub", parent: "holocron1",
    specs: { type: "VM on holocron1", containers: "4" },
    details: ["Traefik reverse proxy with OAuth2 Proxy forward auth", "Routes: n8n, Frigate, Immich/pics, CertWarden, Gitea, VaultWarden", "Redis for OAuth2 session storage"],
    containers: [
      { id: "traefik", name: "Traefik", ports: "80, 443, 8080", role: "Reverse Proxy" },
      { id: "oauth2proxy", name: "OAuth2 Proxy", ports: "\u2014", role: "Forward Auth" },
      { id: "redis-commnet", name: "Redis", ports: "6379 (int)", role: "Session Store" },
      { id: "certwarden", name: "CertWarden", ports: "4050-4051", role: "Certificate Management" },
    ],
  },
  {
    id: "stalwart", hostname: "Mail", ip: "10.20.25.9", vlan: 25, type: "mail",
    role: "Mail Server (Stalwart)", parent: "holocron2",
    specs: { software: "Stalwart Mail v0.15.3", type: "VM on holocron2", config: "/opt/stalwart-mail/etc/config.toml", storage: "RocksDB" },
    details: ["Internal-only mail server \u2014 no external send/receive", "LDAP auth method: lookup (bind-as-user)", "Listeners: SMTP(25), Submission(587/465), IMAP(143/993), POP3(110/995), HTTP(8080/443)", "All services auth using uid as SMTP username"],
  },
  {
    id: "elk", hostname: "ELK", ip: "10.20.25.10", vlan: 25, type: "monitor",
    role: "Monitoring (ELK Stack)",
    specs: { software: "Elasticsearch, Logstash, Kibana" }, details: ["Centralized logging and monitoring"],
  },
  {
    id: "seconion", hostname: "Security Onion", ip: "10.20.25.11", vlan: 25, type: "security",
    role: "IDS / Security Monitoring", status: "down",
    specs: { hardware: "Ryzen 1800X, ~16 GB RAM", software: "Security Onion" },
    details: ["Currently DOWN \u2014 pending reimage", "Bare metal host \u2014 no VMs", "Will be reimaged with Wazuh deployment"],
  },
  {
    id: "truenas", hostname: "TrueNAS", ip: "10.20.25.12", vlan: 25, type: "storage",
    role: "Primary Storage (TrueNAS SCALE)",
    specs: { cpu: "AMD EPYC 7302P (16C/32T)", ram: "256 GB ECC", pools: "MitMSto (RAIDZ2 4x6TB HDD) + Raptor (RAIDZ2 4x1TB NVMe + 1TB) + VMData (RAIDZ2 4x2TB NVMe + 1.9TB)", totalDrives: "18 drives", boot: "Samsung 850 EVO 250G" },
    details: ["Runs OpenCloud and AI (LLM) as apps", "ZFS snapshots on all 3 pools (hourly/daily/weekly/monthly)", "B2 off-site backup: rclone crypt -> GrivykBackups bucket (540G)", "CIFS shares mounted on Plex: MitMSto, Raptor", "Raptor pool: tax records, legal docs \u2014 Tier 1 irreplaceable"],
  },
  {
    id: "opencloud", hostname: "OpenCloud", ip: "10.20.25.13", vlan: 25, type: "storage",
    role: "Cloud File Storage",
    specs: { software: "OpenCloud", host: "Runs on TrueNAS" }, details: ["Self-hosted cloud storage platform"],
  },
  {
    id: "plex", hostname: "Plex", ip: "10.20.25.15", vlan: 25, type: "media",
    role: "Media Server (Plex)",
    specs: { cpu: "AMD Ryzen 7 3800X", ram: "32 GB", gpu: "NVIDIA RTX 3050", storage: "/mnt/data1 (RAID0 2x3.6T), /mnt/data2 (single 7.3T)", warning: "NO redundancy on local storage" },
    details: ["Bare metal \u2014 no VMs", "MitMSto CIFS mount at /mnt/mitmsto", "Raptor mount at /home/yodaadmin/Raptor", "Immich upload backup cron (4 AM daily rsync to MitMSto)", "UFW restricts SSH sources", "Cert renewal: monthly (90-day certs)", "Inter-VLAN: access to VLAN 99 cameras"],
  },
  {
    id: "wireguard-25", hostname: "WG-Beacon-1", ip: "10.20.25.16", vlan: 25, type: "vpn",
    role: "WireGuard Dashboard", parent: "relay1",
    specs: { software: "WireGuard + WG Dashboard", type: "LXC on relay1" },
    details: ["WireGuard VPN management UI", "External access: UDP 58813 from WAN via Mikrotik"],
  },
  {
    id: "kuatdockeryard", hostname: "Kuat Docker Yard", ip: "10.20.25.17", vlan: 25, type: "docker-host",
    role: "Docker Host (Hapes Cluster)", parent: "relay1",
    specs: { type: "VM on relay1", containers: "4" },
    details: ["Portainer agent, VaultWarden, Gitea + PostgreSQL", "Part of Hapes Cluster on relay1"],
    containers: [
      { id: "gitea", name: "Gitea", ports: "3000, 2222", role: "Git Hosting" },
      { id: "gitea-db", name: "Gitea DB", ports: "5432 (int)", role: "PostgreSQL 16" },
      { id: "vaultwarden", name: "VaultWarden", ports: "8080, 3012", role: "Password Manager" },
      { id: "portainer-agent-kuat", name: "Portainer Agent", ports: "9001", role: "Container Mgmt Agent" },
    ],
  },
  {
    id: "dockeryard", hostname: "Docker Yard", ip: "10.20.25.18", vlan: 25, type: "docker-host",
    role: "Primary Docker Host", parent: "holocron2",
    specs: { type: "VM on holocron2", containers: "20" },
    details: ["Main Docker workload host", "Portainer primary instance", "20 containers across multiple stacks"],
    containers: [
      { id: "portainer", name: "Portainer", ports: "9443, 8000", role: "Container Mgmt" },
      { id: "bookstack", name: "BookStack", ports: "6875", role: "Wiki / Docs" },
      { id: "bookstack-db", name: "BookStack DB", ports: "3306 (int)", role: "MariaDB" },
      { id: "paperless", name: "Paperless-ngx", ports: "8085", role: "Document Mgmt" },
      { id: "paperless-db", name: "Paperless DB", ports: "5432 (int)", role: "PostgreSQL 16" },
      { id: "paperless-gotenberg", name: "Gotenberg", ports: "3000 (int)", role: "Doc Conversion" },
      { id: "paperless-tika", name: "Tika", ports: "9998 (int)", role: "Content Extraction" },
      { id: "paperless-redis", name: "Paperless Redis", ports: "6379 (int)", role: "Cache" },
      { id: "kitchenowl-front", name: "KitchenOwl Web", ports: "8080", role: "Grocery/Recipe UI" },
      { id: "kitchenowl-back", name: "KitchenOwl API", ports: "\u2014", role: "Grocery/Recipe API" },
      { id: "uptime-kuma", name: "Uptime Kuma", ports: "3001", role: "Uptime Monitoring" },
      { id: "homarr", name: "Homarr", ports: "7575", role: "Dashboard" },
      { id: "onlyoffice", name: "OnlyOffice", ports: "8081", role: "Office Suite" },
      { id: "cyberchef", name: "CyberChef", ports: "8084", role: "Data Toolkit" },
      { id: "it-tools", name: "IT-Tools", ports: "8083", role: "Dev Utilities" },
      { id: "bentopdf", name: "BentoPDF", ports: "8082", role: "PDF Generator" },
      { id: "drawio", name: "Draw.io", ports: "32768", role: "Diagramming" },
      { id: "ko-pellet", name: "Ko-Pellet", ports: "8998", role: "Ko-Pellet" },
      { id: "omada", name: "Omada Controller", ports: "8043, 8088", role: "WiFi Mgmt (VLAN 2)" },
      { id: "certwarden-client", name: "CertWarden Client", ports: "5055", role: "Cert Client" },
    ],
  },
  {
    id: "rustbuilder", hostname: "RustBuilder", ip: "10.20.25.26", vlan: 25, type: "vm",
    role: "Rust Build Server", parent: "holocron1",
    specs: { type: "VM on holocron1" }, details: ["Rust compilation workloads"],
  },
  {
    id: "gameserver", hostname: "Game Server", ip: "10.20.25.27", vlan: 25, type: "agent",
    role: "Game Server / Claude Code Host", parent: "holocron1",
    specs: { type: "VM on holocron1" },
    details: ["Claude Code (svc-claude) runs here", "Minecraft servers (3x MC + status site + Mumble)", "This tactical display is hosted here"],
  },
  {
    id: "ai", hostname: "AI", ip: "10.20.25.28", vlan: 25, type: "vm",
    role: "AI Workloads",
    specs: { host: "TrueNAS" }, details: ["LLM and AI workloads running on TrueNAS"],
  },
  {
    id: "holocron1", hostname: "Holocron1", ip: "10.20.25.32", vlan: 25, type: "proxmox",
    role: "Proxmox Node 1",
    specs: { model: "Minisforum MS-A1", cpu: "AMD Ryzen AI 9 HX-370", ram: "96 GB", storage: "NVMe", network: "2.5GbE + USB NIC", vmInterface: "10.20.25.35" },
    details: ["LXCs: Technitium, Jumpbox", "VMs: Commnet, Game-server, n8n-learning, RustBuilder"],
  },
  {
    id: "holocron2", hostname: "Holocron2", ip: "10.20.25.33", vlan: 25, type: "proxmox",
    role: "Proxmox Node 2",
    specs: { model: "Minisforum MS-A1", cpu: "AMD Ryzen AI 9 HX-370", ram: "96 GB", storage: "NVMe", network: "2.5GbE + USB NIC", vmInterface: "10.20.25.36" },
    details: ["LXCs: Csilla, OpenLDAP (Spike)", "VMs: Keycloak, DockerYard, Stalwart, Analyzer", "No sudo package \u2014 use PVE root shell for privileged ops"],
  },
  {
    id: "relay1", hostname: "Relay1", ip: "10.20.25.34", vlan: 25, type: "proxmox",
    role: "Proxmox Node 3",
    specs: { cpu: "AMD Ryzen 7 5800H", ram: "32 GB", vmInterface: "10.20.25.37" },
    details: ["LXCs: WireGuard, AdGuard Home", "VMs: KuatDockerYard"],
  },
  {
    id: "csilla", hostname: "Csilla", ip: "10.20.25.104", vlan: 25, type: "lxc",
    role: "Unknown LXC", parent: "holocron2",
    specs: { type: "LXC on holocron2" }, details: ["Purpose unknown"],
  },
  {
    id: "n8n-learn", hostname: "n8n-Learn", ip: "10.20.25.105", vlan: 25, type: "vm",
    role: "n8n Learning Instance", parent: "holocron1",
    specs: { type: "VM on holocron1", software: "n8n" }, details: ["n8n learning/development instance"],
  },
  {
    id: "jumpbox", hostname: "Jumpbox", ip: "10.20.25.116", vlan: 25, type: "lxc",
    role: "SSH Jumpbox", parent: "holocron1",
    specs: { type: "LXC on holocron1" }, details: ["V2 Jumpbox for SSH access"],
  },
  {
    id: "analyzer", hostname: "Analyzer", ip: "10.20.25.118", vlan: 25, type: "vm",
    role: "Analyzer", parent: "holocron2",
    specs: { type: "VM on holocron2" }, details: ["Analysis workloads"],
  },
  {
    id: "rusbuild-ai", hostname: "RusBuild-AI", ip: "10.20.25.108", vlan: 25, type: "vm",
    role: "Rust Build + AI",
    specs: {}, details: ["Rust build AI workload"],
  },

  // ── VLAN 10 — CYBER HIVE SECURITY ──
  {
    id: "wireguard-10", hostname: "WireGuard", ip: "172.20.10.2", vlan: 10, type: "vpn",
    role: "WireGuard VPN", specs: {}, details: ["CHS VPN endpoint"],
  },
  {
    id: "mpc1", hostname: "MPC1", ip: "172.20.10.3", vlan: 10, type: "vm",
    role: "Unknown", specs: {}, details: ["Purpose unknown"],
  },
  {
    id: "hcs-docker", hostname: "HCS-Docker", ip: "172.20.10.4", vlan: 10, type: "docker-host",
    role: "CHS Docker Host", specs: {}, details: ["Cyber Hive Security Docker workloads"],
  },
  {
    id: "scout-ingest", hostname: "Scout-Ingest", ip: "172.20.10.5", vlan: 10, type: "security",
    role: "Security Ingest", specs: {}, details: ["Security data ingestion pipeline"],
  },
  {
    id: "headscale", hostname: "Headscale", ip: "172.20.10.6", vlan: 10, type: "vpn",
    role: "Tailscale Control Server",
    specs: { software: "Headscale" }, details: ["Self-hosted Tailscale control plane"],
  },

  // ── VLAN 2 — NETWORK MANAGEMENT ──
  {
    id: "mt310", hostname: "MT310-Office", ip: "10.2.2.3", vlan: 2, type: "network",
    role: "Mikrotik Switch (Office)", specs: { model: "Mikrotik CRS310" }, details: ["Office switch"],
  },
  {
    id: "netgear", hostname: "Netgear", ip: "10.2.2.4", vlan: 2, type: "network",
    role: "Netgear Multi-Gig Switch",
    specs: { model: "Netgear MS510TXPP", ports: "8x Multi-Gig (1/2.5/5/10G) + 2x SFP+" }, details: ["Network switch"],
  },
  {
    id: "mt106-office", hostname: "MT-106 Office", ip: "10.2.2.5", vlan: 2, type: "network",
    role: "Mikrotik Switch (Office)", specs: { model: "Mikrotik CRS106" }, details: ["Office switch"],
  },
  {
    id: "mt106-basement", hostname: "MT-106 Basement", ip: "10.2.2.6", vlan: 2, type: "network",
    role: "Mikrotik Switch (Basement)", specs: { model: "Mikrotik CRS106" }, details: ["Basement switch"],
  },
  {
    id: "wap-master", hostname: "WAP Master Bed", ip: "10.2.2.7", vlan: 2, type: "network",
    role: "Wireless AP (Master Bedroom)", specs: {}, details: ["Master bedroom WiFi coverage"],
  },
  {
    id: "wap-main", hostname: "WAP Main Floor", ip: "10.2.2.8", vlan: 2, type: "network",
    role: "Wireless AP (Main Floor)", specs: {}, details: ["Main floor WiFi coverage"],
  },
  {
    id: "wap-basement", hostname: "WAP Basement", ip: "10.2.2.9", vlan: 2, type: "network",
    role: "Wireless AP (Basement)", specs: {}, details: ["Basement WiFi coverage"],
  },

  // ── VLAN 30 — TRUSTED WIRED ──
  {
    id: "chs-scout1", hostname: "CHS-Scout1", ip: "10.20.30.85", vlan: 30, type: "security",
    role: "CHS Scout", specs: {}, details: ["Cyber Hive Security scout node"],
  },
  {
    id: "viscid7", hostname: "Viscid7", ip: "10.20.30.93", vlan: 30, type: "workstation",
    role: "Workstation", specs: {}, details: ["Workstation (waiting/standby)"],
  },
  {
    id: "viscidsleek8-wired", hostname: "ViscidSleek8", ip: "10.20.30.99", vlan: 30, type: "workstation",
    role: "Workstation (Wired)", specs: {}, details: ["Primary workstation \u2014 wired connection"],
  },

  // ── VLAN 35 — TRUSTED WIRELESS ──
  {
    id: "mobile-viscid8", hostname: "Mobile-Viscid-8", ip: "10.20.35.2", vlan: 35, type: "workstation",
    role: "Mobile Device", specs: {}, details: ["Mobile endpoint"],
  },
  {
    id: "pixel8pro", hostname: "Pixel 8 Pro", ip: "10.20.35.3", vlan: 35, type: "workstation",
    role: "Phone", specs: { model: "Google Pixel 8 Pro" }, details: ["Primary phone"],
  },
  {
    id: "zephyrus", hostname: "Zephyrus", ip: "10.20.35.22", vlan: 35, type: "workstation",
    role: "Gaming Laptop", specs: { model: "ASUS ROG Zephyrus GM501GM" }, details: ["ASUS gaming laptop \u2014 WiFi"],
  },
  {
    id: "viscidsleek8-wifi", hostname: "ViscidSleek8", ip: "10.20.35.52", vlan: 35, type: "workstation",
    role: "Workstation (WiFi)", specs: {}, details: ["Primary workstation \u2014 WiFi connection"],
  },

  // ── VLAN 6 — EMPLOYER ISOLATED ──
  {
    id: "employer-device", hostname: "D63Z1T2", ip: "172.20.6.2", vlan: 6, type: "workstation",
    role: "Work Device", specs: {}, details: ["Employer-issued device \u2014 fully isolated VLAN"],
  },

  // ── VLAN 90 — IoT INTERNET ──
  {
    id: "samsung-iot", hostname: "Samsung", ip: "192.168.90.3", vlan: 90, type: "iot",
    role: "Samsung Device", specs: {}, details: ["Samsung smart device"],
  },
  {
    id: "rokugoku", hostname: "RokuGoku", ip: "192.168.90.5", vlan: 90, type: "iot",
    role: "Roku Streaming", specs: {}, details: ["Roku streaming device"],
  },
  {
    id: "roku-masterbed", hostname: "Roku MasterBed", ip: "192.168.90.6", vlan: 90, type: "iot",
    role: "Roku Streaming (Master Bedroom)", specs: {}, details: ["Roku streaming device \u2014 master bedroom"],
  },
  {
    id: "rachio", hostname: "Rachio", ip: "192.168.90.7", vlan: 90, type: "iot",
    role: "Sprinkler Controller", specs: { model: "Rachio 11BC94" }, details: ["Smart sprinkler/irrigation controller"],
  },
  {
    id: "nest", hostname: "Nest Thermostat", ip: "192.168.90.8", vlan: 90, type: "iot",
    role: "Smart Thermostat", specs: { model: "Nest Thermostat 109C" }, details: ["Google Nest thermostat"],
  },

  // ── VLAN 99 — IoT RESTRICTED ──
  {
    id: "cam1", hostname: "Camera 1", ip: "192.168.99.2", vlan: 99, type: "iot",
    role: "Security Camera", specs: {}, details: ["NVR / Frigate-connected camera", "No internet access (VLAN 99)"],
  },
  {
    id: "cam2", hostname: "Camera 2", ip: "192.168.99.3", vlan: 99, type: "iot",
    role: "Security Camera", specs: {}, details: ["NVR / Frigate-connected camera"],
  },
  {
    id: "cam3", hostname: "Camera 3", ip: "192.168.99.4", vlan: 99, type: "iot",
    role: "Security Camera", specs: {}, details: ["NVR / Frigate-connected camera"],
  },
  {
    id: "cam4", hostname: "Camera 4", ip: "192.168.99.5", vlan: 99, type: "iot",
    role: "Security Camera", specs: {}, details: ["NVR / Frigate-connected camera"],
  },
  {
    id: "cam5", hostname: "Camera 5", ip: "192.168.99.6", vlan: 99, type: "iot",
    role: "Security Camera", specs: {}, details: ["NVR / Frigate-connected camera"],
  },

  // ── Non-Proxmox bare-metal hosts ──
  {
    id: "truenas-bak", hostname: "TrueNAS Bak", ip: "\u2014", vlan: 25, type: "storage",
    role: "Backup NAS", status: "down",
    specs: { cpu: "AMD Ryzen 7 1800X", ram: "~16 GB" },
    details: ["Backup NAS \u2014 not yet configured", "Needs physical access for setup", "Bare metal \u2014 no VMs"],
  },
  {
    id: "b2-cloud", hostname: "Backblaze B2", ip: "Cloud", vlan: 25, type: "storage",
    role: "Off-site Encrypted Backup",
    specs: { provider: "Backblaze B2", bucket: "GrivykBackups", encryption: "rclone crypt (client-side)", size: "~540 GB", schedule: "Weekly (Sunday 3 AM)" },
    details: ["Encrypted with rclone crypt \u2014 passwords in Keeper", "Contents: Photos (321G), Immich uploads (138G), Raptor/Critical (1.8G)", "Remote: b2-crypt: on TrueNAS", "Old B2 backup (431G) was unrecoverable \u2014 deleted, started fresh"],
  },
  {
    id: "protectli", hostname: "Protectli VP2440", ip: "\u2014", vlan: 25, type: "security",
    role: "Planned: IDS / Log Collector", status: "planned",
    specs: { model: "Protectli VP2440" },
    details: ["To be repurposed as:", "- IDS sensor (Suricata/Zeek)", "- Log collector (Wazuh/syslog)", "- Ansible/Semaphore runner"],
  },
];

export const CONNECTIONS: Connection[] = [
  // 10G backbone chain
  { source: "mikrotik", target: "mt326", type: "backbone" },
  { source: "mt326", target: "mt310", type: "backbone" },
  { source: "mt310", target: "netgear", type: "backbone" },
  { source: "mt326", target: "truenas", type: "backbone" },

  // 5G
  { source: "netgear", target: "plex", type: "5g" },

  // 2.5G
  { source: "mt326", target: "holocron1", type: "2.5g" },
  { source: "mt326", target: "holocron2", type: "2.5g" },
  { source: "mt326", target: "relay1", type: "2.5g" },
  { source: "mt326", target: "viscid7", type: "2.5g" },
  { source: "mt326", target: "truenas-bak", type: "2.5g" },
  { source: "netgear", target: "wap-master", type: "2.5g" },
  { source: "netgear", target: "wap-main", type: "2.5g" },

  // 1G network
  { source: "mt326", target: "mt106-office", type: "network" },
  { source: "mt326", target: "mt106-basement", type: "network" },
  { source: "mt326", target: "seconion", type: "network" },
  { source: "mt106-basement", target: "wap-basement", type: "network" },

  // Hypervisor
  { source: "holocron1", target: "commnet", type: "hypervisor" },
  { source: "holocron1", target: "gameserver", type: "hypervisor" },
  { source: "holocron1", target: "technitium", type: "hypervisor" },
  { source: "holocron1", target: "jumpbox", type: "hypervisor" },
  { source: "holocron1", target: "n8n-learn", type: "hypervisor" },
  { source: "holocron1", target: "rustbuilder", type: "hypervisor" },
  { source: "holocron2", target: "keycloak", type: "hypervisor" },
  { source: "holocron2", target: "dockeryard", type: "hypervisor" },
  { source: "holocron2", target: "stalwart", type: "hypervisor" },
  { source: "holocron2", target: "spike", type: "hypervisor" },
  { source: "holocron2", target: "csilla", type: "hypervisor" },
  { source: "holocron2", target: "analyzer", type: "hypervisor" },
  { source: "relay1", target: "kuatdockeryard", type: "hypervisor" },
  { source: "relay1", target: "wireguard-25", type: "hypervisor" },
  { source: "relay1", target: "adguard", type: "hypervisor" },

  // Service / auth / dns / storage
  { source: "adguard", target: "technitium", type: "dns" },
  { source: "commnet", target: "stalwart", type: "service" },
  { source: "commnet", target: "kuatdockeryard", type: "service" },
  { source: "commnet", target: "dockeryard", type: "service" },
  { source: "keycloak", target: "spike", type: "auth" },
  { source: "stalwart", target: "spike", type: "auth" },
  { source: "keycloak", target: "stalwart", type: "service" },
  { source: "plex", target: "truenas", type: "storage" },
  { source: "mt326", target: "ca", type: "network" },
  { source: "mt326", target: "packetfence", type: "network" },
  { source: "mt326", target: "elk", type: "network" },
  { source: "mt326", target: "opencloud", type: "network" },
  { source: "truenas", target: "opencloud", type: "service" },
  { source: "truenas", target: "ai", type: "service" },
  { source: "truenas", target: "truenas-bak", type: "storage" },
  { source: "truenas", target: "b2-cloud", type: "storage" },
  { source: "mt326", target: "protectli", type: "network" },
  { source: "mt326", target: "rusbuild-ai", type: "network" },

  // CHS (VLAN 10)
  { source: "mt326", target: "hcs-docker", type: "network" },
  { source: "mt326", target: "wireguard-10", type: "network" },
  { source: "mt326", target: "mpc1", type: "network" },
  { source: "mt326", target: "scout-ingest", type: "network" },
  { source: "mt326", target: "headscale", type: "network" },

  // Wired (VLAN 30)
  { source: "mt326", target: "chs-scout1", type: "network" },
  { source: "mt326", target: "viscidsleek8-wired", type: "network" },

  // Wireless (VLAN 35)
  { source: "wap-main", target: "mobile-viscid8", type: "network" },
  { source: "wap-main", target: "pixel8pro", type: "network" },
  { source: "wap-main", target: "zephyrus", type: "network" },
  { source: "wap-main", target: "viscidsleek8-wifi", type: "network" },

  // Employer (VLAN 6)
  { source: "mt326", target: "employer-device", type: "network" },

  // IoT (VLAN 90)
  { source: "mt326", target: "samsung-iot", type: "network" },
  { source: "mt326", target: "rokugoku", type: "network" },
  { source: "mt326", target: "roku-masterbed", type: "network" },
  { source: "mt326", target: "rachio", type: "network" },
  { source: "mt326", target: "nest", type: "network" },

  // Cameras (VLAN 99)
  { source: "plex", target: "cam1", type: "network" },
  { source: "plex", target: "cam2", type: "network" },
  { source: "plex", target: "cam3", type: "network" },
  { source: "plex", target: "cam4", type: "network" },
  { source: "plex", target: "cam5", type: "network" },
];

export const CONNECTION_STYLES: Record<string, ConnectionStyle> = {
  backbone: { color: "#ffd700", width: 3.5, dash: null, label: "10 Gbps" },
  "5g": { color: "#ff8c00", width: 2.5, dash: null, label: "5 Gbps" },
  "2.5g": { color: "#00e5ff", width: 2, dash: null, label: "2.5 Gbps" },
  network: { color: "#00f0ff", width: 1.2, dash: null, label: "1 Gbps" },
  hypervisor: { color: "#00b4d8", width: 1.5, dash: "4,4", label: "Hypervisor" },
  service: { color: "#00ff88", width: 1, dash: "6,3", label: "Service" },
  auth: { color: "#ff4444", width: 1, dash: "2,4", label: "Auth" },
  dns: { color: "#ffaa00", width: 1, dash: "8,4", label: "DNS" },
  storage: { color: "#00ff88", width: 2, dash: null, label: "Storage" },
};
