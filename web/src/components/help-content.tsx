// Contextual help content for each page.
// Rendered inside the PageShell help panel.

export function DashboardHelp() {
  return (
    <>
      <p>
        The dashboard provides a real-time overview of your network. Cards
        auto-refresh and show live data from your Mikrotik router.
      </p>
      <h3>Cards</h3>
      <dl>
        <dt>Connections</dt>
        <dd>Active connection-tracked sessions on the router (TCP, UDP, etc.). A red dot in the sidebar means flagged connections exist.</dd>
        <dt>Network Devices</dt>
        <dd>Managed switches and access points that Ion Drift polls for MAC tables and port status.</dd>
        <dt>Identity Overview</dt>
        <dd>Summary of discovered network identities — MAC addresses mapped to switch ports.</dd>
        <dt>Firewall Drops</dt>
        <dd>Recent packets dropped by firewall rules. Spikes may indicate scans or misconfigurations.</dd>
        <dt>WAN Traffic</dt>
        <dd>Inbound/outbound bandwidth on the WAN interface over time.</dd>
        <dt>DHCP Leases</dt>
        <dd>Active DHCP leases across all VLANs with lease counts per pool.</dd>
      </dl>
      <h3>Sections</h3>
      <dl>
        <dt>VLAN Activity</dt>
        <dd>Per-VLAN traffic volume using mangle passthrough counters on the router.</dd>
        <dt>System History</dt>
        <dd>CPU, memory, and disk usage trends sampled over time.</dd>
        <dt>VLAN Traffic Breakdown</dt>
        <dd>Proportional traffic per VLAN shown as a bar chart.</dd>
        <dt>Directional Port Sankeys</dt>
        <dd>Flow diagrams showing which VLANs are talking to which destination ports and services.</dd>
      </dl>
    </>
  );
}

export function InterfacesHelp() {
  return (
    <>
      <p>
        View all network interfaces and VLAN configurations on the router.
      </p>
      <h3>Tabs</h3>
      <dl>
        <dt>All Interfaces</dt>
        <dd>Every physical and virtual interface — bridges, VLANs, bonds, ethernet ports. Shows link status, speed, MAC address, and traffic counters.</dd>
        <dt>VLANs</dt>
        <dd>VLAN interface details including VLAN ID, parent bridge, and tagged/untagged port membership.</dd>
      </dl>
      <h3>Key Terms</h3>
      <dl>
        <dt>Running</dt>
        <dd>Interface has link (cable connected, peer detected). Disabled interfaces are administratively shut down.</dd>
        <dt>MTU</dt>
        <dd>Maximum Transmission Unit — largest packet size the interface will send without fragmentation.</dd>
        <dt>Tx/Rx</dt>
        <dd>Transmitted and received byte/packet counters since last reset.</dd>
      </dl>
    </>
  );
}

export function IpHelp() {
  return (
    <>
      <p>
        IP address management, routing, DHCP, ARP, and subnet utilization for the router.
      </p>
      <h3>Tabs</h3>
      <dl>
        <dt>Addresses</dt>
        <dd>IP addresses assigned to router interfaces. Each address belongs to a subnet and is bound to an interface.</dd>
        <dt>Routes</dt>
        <dd>The routing table — how the router decides where to forward packets. Includes connected, static, and dynamic routes.</dd>
        <dt>DHCP Leases</dt>
        <dd>Devices that received an IP address from the router's DHCP server, with hostname, MAC, and lease expiry.</dd>
        <dt>ARP</dt>
        <dd>Address Resolution Protocol table — maps IP addresses to MAC addresses on local network segments.</dd>
        <dt>Utilization</dt>
        <dd>Subnet usage showing how full each DHCP pool is and which IPs are in use.</dd>
      </dl>
    </>
  );
}

export function FirewallHelp() {
  return (
    <>
      <p>
        View firewall filter, NAT, and mangle rules configured on the router. Rules are read-only in this view.
      </p>
      <h3>Tabs</h3>
      <dl>
        <dt>Filter</dt>
        <dd>Packet filtering rules (accept, drop, reject). These control what traffic is allowed through the router. Organized by chain (input, forward, output).</dd>
        <dt>NAT</dt>
        <dd>Network Address Translation rules. <code>srcnat</code> masquerades internal IPs for outbound traffic. <code>dstnat</code> maps external ports to internal services.</dd>
        <dt>Mangle</dt>
        <dd>Packet marking and modification rules. Ion Drift uses mangle passthrough rules (prefixed <code>ion-drift-flow:</code>) to count VLAN-to-VLAN and VLAN-to-WAN traffic.</dd>
      </dl>
      <h3>Key Terms</h3>
      <dl>
        <dt>Chain</dt>
        <dd>Processing stage — <code>input</code> (to router), <code>forward</code> (through router), <code>output</code> (from router), <code>prerouting</code>/<code>postrouting</code> (NAT/mangle).</dd>
        <dt>Bytes / Packets</dt>
        <dd>Cumulative counters showing how much traffic matched each rule.</dd>
        <dt>Disabled</dt>
        <dd>Rule exists but is not active. Shown with reduced opacity.</dd>
      </dl>
    </>
  );
}

export function ConnectionsHelp() {
  return (
    <>
      <p>
        Live view of all connection-tracked sessions passing through the router. Updated every 15 seconds.
      </p>
      <h3>Key Terms</h3>
      <dl>
        <dt>Flagged</dt>
        <dd>Connections to destinations on threat intelligence lists or with suspicious characteristics. Review these for potential compromise or unwanted traffic.</dd>
        <dt>Source / Destination</dt>
        <dd>The internal device (source) and the remote endpoint (destination) of each connection.</dd>
        <dt>NAT Dst</dt>
        <dd>If the connection was DNAT'd (port-forwarded), this shows the original destination before translation.</dd>
        <dt>State</dt>
        <dd>Connection tracking state: <code>established</code> (active), <code>time-wait</code> (closing), <code>new</code> (just opened).</dd>
        <dt>GeoIP</dt>
        <dd>Approximate geographic location of the remote IP, derived from GeoIP databases.</dd>
      </dl>
      <h3>Filters</h3>
      <ul>
        <li><strong>Flagged Only</strong> — show only threat-flagged connections</li>
        <li><strong>TCP / UDP</strong> — filter by protocol</li>
        <li><strong>External Only</strong> — hide LAN-to-LAN connections</li>
      </ul>
    </>
  );
}

export function BehaviorHelp() {
  return (
    <>
      <p>
        Behavioral anomaly detection. Ion Drift builds baseline traffic profiles per device and alerts when behavior deviates significantly.
      </p>
      <h3>Key Terms</h3>
      <dl>
        <dt>Anomaly</dt>
        <dd>A detected deviation from a device's normal traffic pattern — new ports, volume spikes, unusual destinations, or disappeared flows.</dd>
        <dt>Pending</dt>
        <dd>Anomalies awaiting review. Shown as a badge count in the sidebar.</dd>
        <dt>Accepted</dt>
        <dd>Anomalies you confirmed as expected behavior. The baseline updates to include this pattern.</dd>
        <dt>Dismissed</dt>
        <dd>Anomalies you marked as not concerning but that shouldn't update the baseline.</dd>
        <dt>Flagged</dt>
        <dd>Anomalies you marked as genuinely suspicious for further investigation.</dd>
        <dt>Severity</dt>
        <dd>Risk level: <strong>critical</strong> (new unexpected ports/services), <strong>warning</strong> (volume spikes), <strong>info</strong> (minor deviations).</dd>
      </dl>
    </>
  );
}

export function HistoryHelp() {
  return (
    <>
      <p>
        Historical trends for router system metrics and network events. Data is sampled periodically and stored in the local database.
      </p>
      <h3>Key Terms</h3>
      <dl>
        <dt>CPU / Memory / Disk</dt>
        <dd>Router resource utilization over time. Sustained high values may indicate overload.</dd>
        <dt>Connections Over Time</dt>
        <dd>Historical connection count trend — useful for identifying traffic pattern changes.</dd>
        <dt>History Table</dt>
        <dd>Raw sample records with timestamps. Can be filtered by metric type and time range.</dd>
      </dl>
    </>
  );
}

export function LogsHelp() {
  return (
    <>
      <p>
        RouterOS system logs received via syslog. Ion Drift captures logs from the router and stores them for search and analysis.
      </p>
      <h3>Key Terms</h3>
      <dl>
        <dt>Topic</dt>
        <dd>RouterOS log category — <code>firewall</code>, <code>system</code>, <code>dhcp</code>, <code>wireless</code>, etc. Filter by topic to focus on specific subsystems.</dd>
        <dt>Severity</dt>
        <dd>Log level: <code>error</code>, <code>warning</code>, <code>info</code>, <code>debug</code>.</dd>
        <dt>Live Tail</dt>
        <dd>When enabled, new log entries appear automatically as they arrive.</dd>
      </dl>
      <h3>Log Trends</h3>
      <p>The trends chart shows log volume over time, broken down by topic. Spikes in firewall logs often correlate with port scans or rule changes.</p>
    </>
  );
}

export function SettingsHelp() {
  return (
    <>
      <p>
        Configure Ion Drift's connection to your Mikrotik router and managed switches.
      </p>
      <h3>Devices</h3>
      <p>
        Add your router and switches here. Ion Drift needs the REST API address, credentials, and (for HTTPS) the CA certificate path to connect.
      </p>
      <dl>
        <dt>Primary Router</dt>
        <dd>The main Mikrotik router that Ion Drift polls for connections, firewall rules, DHCP, ARP, etc. Only one router can be primary.</dd>
        <dt>Switches</dt>
        <dd>Managed switches polled for MAC address tables and port status. Supports Mikrotik SwOS, RouterOS switches, and SNMP-capable switches.</dd>
      </dl>
    </>
  );
}

export function IdentityManagerHelp() {
  return (
    <>
      <p>
        Network identity discovery and management. Each identity maps a MAC address to the switch port where it was last observed.
      </p>
      <h3>Key Terms</h3>
      <dl>
        <dt>Identity</dt>
        <dd>A discovered device on the network, identified by MAC address and mapped to a switch port. Includes hostname (from DHCP/ARP), device type, and VLAN.</dd>
        <dt>Source</dt>
        <dd>How the identity was discovered: <code>mac_table</code> (switch polling), <code>dhcp</code> (DHCP lease), <code>arp</code> (ARP table), or <code>manual</code> (user-created).</dd>
        <dt>Confirmed</dt>
        <dd>Whether a human has verified the identity's port assignment. Confirmed identities are trusted by the inference engine.</dd>
        <dt>Port Violation</dt>
        <dd>A MAC address appeared on a different port than expected, or a device disappeared from its assigned port. May indicate cable changes or unauthorized moves.</dd>
        <dt>Disposition</dt>
        <dd>Visibility state: <code>visible</code> (active), <code>hidden</code> (manually suppressed), or <code>infrastructure</code> (switches/APs — excluded from endpoint lists).</dd>
      </dl>
    </>
  );
}

export function InferenceHelp() {
  return (
    <>
      <p>
        The topology inference engine automatically determines which switch port each device is connected to by analyzing MAC table observations over time.
      </p>
      <h3>Modes</h3>
      <dl>
        <dt>Legacy</dt>
        <dd>Inference engine disabled. Port assignments come only from direct MAC table lookups.</dd>
        <dt>Shadow</dt>
        <dd>Inference runs and logs results but does NOT write bindings. Use this to evaluate accuracy before going active.</dd>
        <dt>Active</dt>
        <dd>Inference writes port bindings to the identity store. Results are live.</dd>
      </dl>
      <h3>Key Terms</h3>
      <dl>
        <dt>Confidence</dt>
        <dd>How certain the engine is about a MAC's port assignment (0–100%). Based on observation consistency, candidate scoring, and consecutive wins.</dd>
        <dt>Score</dt>
        <dd>Weighted sum of feature scores for the top candidate. Higher is better. Features include edge likelihood, persistence, VLAN consistency, and penalties for routers/transits.</dd>
        <dt>Consecutive Wins</dt>
        <dd>How many scoring cycles in a row the current top candidate has won. More wins increase confidence.</dd>
        <dt>Divergence</dt>
        <dd>When inference assigns a different port than the legacy (MAC table) binding. The "Div" column flags these for review.</dd>
        <dt>State</dt>
        <dd>
          <ul>
            <li><strong>unknown</strong> — not enough observations yet</li>
            <li><strong>candidate</strong> — a top candidate exists but confidence is low</li>
            <li><strong>probable</strong> — strong candidate, building confidence</li>
            <li><strong>stable</strong> — high confidence, consistent winner</li>
            <li><strong>roaming</strong> — device moved to a different port</li>
            <li><strong>conflicted</strong> — multiple candidates with similar scores</li>
            <li><strong>human_pinned</strong> — manually confirmed, inference defers</li>
          </ul>
        </dd>
      </dl>
    </>
  );
}

export function SetupWizardHelp() {
  return (
    <>
      <p>
        The Setup Wizard configures your Mikrotik router with the mangle rules, syslog, and firewall logging rules that Ion Drift needs to collect traffic data.
      </p>
      <h3>What Gets Created</h3>
      <dl>
        <dt>Mangle Rules</dt>
        <dd>Passthrough rules in the <code>prerouting</code> chain that count bytes per VLAN-to-VLAN and VLAN-to-WAN flow. These do NOT modify traffic — they only count it.</dd>
        <dt>Syslog Action</dt>
        <dd>A logging action that sends router logs to Ion Drift's syslog receiver for storage and analysis.</dd>
        <dt>Firewall Log Rules</dt>
        <dd>Filter rules that log new connection events (with <code>ION</code> prefix) so Ion Drift can track connection patterns.</dd>
      </dl>
      <h3>Steps</h3>
      <ul>
        <li><strong>Configure</strong> — Select the router and WAN interface</li>
        <li><strong>Review Plan</strong> — See exactly what will be created, skipped, or updated. Every rule is shown with its full RouterOS payload.</li>
        <li><strong>Apply</strong> — Selected items are applied to the router. Each item reports success or failure individually.</li>
        <li><strong>Results</strong> — Summary of what was applied</li>
      </ul>
    </>
  );
}
