# Policy Deviation Detection: Visibility Boundaries

Ion Drift's policy deviation detection operates at **Layer 3/4** by analyzing the router's connection tracking table. This document explains what the detector can and cannot see, and recommends complementary controls for traffic outside its visibility boundary.

## What the Detector Sees

The detector cross-references active connections (from RouterOS `/ip/firewall/connection`) against infrastructure policies derived from your DHCP, DNS, and NTP configuration. It identifies:

- **DNS deviations** — devices sending port 53 (UDP/TCP) traffic to servers not authorized by your DHCP DNS option or router DNS config
- **NTP deviations** — devices sending port 123 (UDP) traffic to servers not authorized by DHCP option 42

Every connection in the tracking table includes source/destination IP, port, and protocol — enough to deterministically match against policy.

## What the Detector Cannot See

### Encrypted DNS (DoH / DoT)

- **DNS over HTTPS (DoH)** — DNS queries tunneled inside HTTPS (port 443). Indistinguishable from normal HTTPS traffic in the connection table.
- **DNS over TLS (DoT)** — DNS queries over TLS on port 853. Visible as a connection to port 853, but not currently detected as a DNS deviation since the detector only monitors port 53.

**Mitigation:** Block outbound port 853 at the firewall. For DoH, consider blocking known DoH provider IPs (Cloudflare 1.1.1.1, Google 8.8.8.8 on port 443) or use a DNS sinkhole.

### VPN and Tunnel Evasion

- **WireGuard, OpenVPN, IPSec** — traffic tunneled through VPN connections bypasses connection tracking for the inner payload. The outer VPN connection is visible, but the DNS/NTP queries inside the tunnel are not.
- **SSH tunnels / SOCKS proxies** — similar to VPN: the outer connection is visible, inner traffic is opaque.

**Mitigation:** Monitor for unexpected VPN protocols (WireGuard UDP, OpenVPN TCP/UDP on non-standard ports). Ion Drift's connection tracking will show the tunnel endpoint — investigate devices with persistent connections to unknown VPN servers.

### DNS Tunneling

Exfiltration or C2 over DNS (e.g., `iodine`, `dnscat2`) uses legitimate port-53 traffic to authorized DNS servers. The queries contain encoded data in subdomain labels. Since the traffic goes to an authorized server on the correct port, no deviation is generated.

**Mitigation:** DNS tunneling detection requires deep packet inspection (DPI) or DNS query log analysis — monitoring query entropy, subdomain length, and NXDOMAIN rates. This is outside Ion Drift's scope; consider a dedicated DNS security tool or IDS (Suricata, Zeek).

### Network Time Security (NTS)

NTS is an authenticated extension to NTP. NTS-KE (Key Establishment) uses port 4460/TCP, while the actual time sync still uses port 123/UDP. The port-123 traffic will be detected normally, but the NTS-KE handshake on port 4460 will not trigger an NTP deviation.

**Mitigation:** No action needed in most cases — the time synchronization itself still uses port 123 and will be caught. Monitor port 4460 connections if NTS usage is a concern.

### FastTrack Bypass

RouterOS FastTrack offloads established connections from the CPU for performance. FastTracked connections may not appear in the connection tracking table at the time of the detection scan. This means some long-lived connections (especially high-throughput flows) might be missed.

**Mitigation:** Ion Drift runs detection every 60 seconds. Connections are typically visible during establishment before FastTrack takes over. The risk of missing a deviation due to FastTrack is low for DNS/NTP (short-lived queries), but higher for persistent connections.

## Complementary Controls

| Gap | Recommended Control |
|-----|-------------------|
| DoH | Firewall rules blocking known DoH IPs on port 443 |
| DoT | Firewall rule blocking outbound port 853 |
| VPN tunnels | IDS rules for VPN protocol signatures |
| DNS tunneling | DNS query log analysis (Zeek, Suricata, Pi-hole logs) |
| Encrypted protocols | Network segmentation + strict egress filtering |

## Design Philosophy

Ion Drift is designed to work **air-gapped** with **no external API calls**. This means detection is limited to what can be observed from the router's own data. The trade-off is deliberate: reliable, deterministic detection of common misconfigurations (wrong DNS server, rogue NTP) without privacy-invasive deep packet inspection or cloud-dependent threat intelligence.

For environments that require DPI or encrypted traffic analysis, deploy a complementary IDS/IPS (Suricata, Zeek, Security Onion) alongside Ion Drift.
