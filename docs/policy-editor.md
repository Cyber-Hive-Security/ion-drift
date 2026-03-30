# Policy Editor

Ion Drift maintains an infrastructure policy map derived from your router's configuration. The policy editor lets you create custom policies that the deviation detector enforces alongside the router-synced ones.

## How Policies Work

Policies define what network behavior is authorized. The deviation detector compares observed traffic against these policies and flags violations.

**Two sources of policies:**

- **Router-synced** — automatically derived from your router's DHCP, DNS, and gateway configuration. Updated every 60 minutes. Shown with a lock icon in the UI (read-only).
- **Admin-created** — defined by you through the policy editor or resolve actions. Protected from router sync overwrite. Shown with edit/delete icons in the UI.

### Policy Fields

| Field | Description | Example |
|-------|-------------|---------|
| **Service** | The service type being monitored | `dns`, `ntp`, `custom` |
| **Protocol** | Transport protocol | `udp`, `tcp`, or Any |
| **Port** | Destination port number (1-65535) | `53` (DNS), `123` (NTP) |
| **Authorized Targets** | IP addresses or CIDRs that devices are allowed to contact | `10.20.25.5`, `192.168.1.0/24` |
| **VLAN Scope** | Which VLANs this policy applies to | Specific VLANs or "All VLANs" (global) |
| **Priority** | Severity level when violated | `critical`, `high`, `medium`, `low` |

### How Detection Works

Every 60 seconds, the detector:

1. Loads all policies (router-synced + admin-created)
2. Queries recent connections for each monitored service (DNS port 53, NTP port 123)
3. For each connection, checks if the destination IP is in the authorized targets for that device's VLAN
4. If not authorized: creates a deviation with the relevant MITRE ATT&CK techniques
5. Connections blocked by the firewall (zero reply bytes) are excluded — if the firewall is enforcing the policy, it's not a deviation
6. The router's own WAN IP is excluded (its upstream DNS/NTP traffic is not a violation)

## Creating a Policy

1. Navigate to **Policy** in the sidebar
2. Click **Add Policy** above the Service Policies table
3. Fill in the form:
   - **Service**: Enter the service name (e.g., `dns`, `ntp`, or any custom name)
   - **Protocol**: Select UDP, TCP, or Any
   - **Port**: Enter the destination port
   - **Authorized Targets**: Enter one IP or CIDR per line. These are the servers devices are allowed to contact. Leave empty to flag all traffic on this port ("Flag All" mode).
   - **VLAN Scope**: Check "All VLANs" for a global policy, or uncheck and select specific VLANs
   - **Priority**: Select the severity level for violations
4. Click **Create**

### Conflict Detection

The editor enforces two types of conflicts:

- **Hard conflict**: A policy with the same service/protocol/port/VLAN scope already exists. You'll see a 409 error with the existing policy ID. You must delete the existing one first or change the scope.
- **Soft conflict**: Your authorized targets overlap with another policy's targets for the same service and VLAN. You'll see a 409 error unless you include `force: true` in the request (API only — the UI does not currently expose this).

## Editing a Policy

Only admin-created policies can be edited. Router-synced policies show a lock icon.

1. Find the policy in the Service Policies table
2. Click the pencil icon on an admin-created policy
3. Modify the authorized targets, VLAN scope, or priority
4. Click **Update**

Note: the service, protocol, and port cannot be changed after creation. To change these, delete the policy and create a new one.

## Deleting a Policy

Only admin-created policies can be deleted. Router-synced policies cannot be removed through the UI — they are managed by the router sync cycle.

1. Click the trash icon on an admin-created policy
2. Confirm the deletion

## Resolve Actions on Deviations

When you see a policy deviation, the **Resolve** dropdown offers four actions:

| Action | What It Does |
|--------|-------------|
| **Authorize** | Adds the observed server IP to the authorized targets for that service/VLAN. Creates or updates an admin policy. The deviation is marked "resolved" and hidden from the default view. |
| **Flag All** | Creates a policy with empty authorized targets for that service/VLAN. This means ALL traffic on that port will generate deviations — it's an observation stance, not router enforcement. |
| **Acknowledge** | Marks the deviation as "acknowledged" (blue badge). No policy change. The deviation stays visible but stops being "new." If the same violation recurs, it stays acknowledged. |
| **Dismiss** | Marks the deviation as "dismissed" (hidden from default view). No policy change. If the same violation recurs, it stays dismissed. |

### Important Notes on Resolve Actions

- **Authorize** and **Flag All** require the deviation to have a VLAN scope. Deviations without a VLAN will return an error.
- Policies created by **Authorize** are admin-protected (`user_created = true`) and survive router sync cycles.
- **Authorize** merges targets — if a VLAN-scoped policy already exists, the new target is added to the existing list rather than creating a duplicate policy.

## Admin Policy Protection

Admin-created policies are protected from the router sync cycle:

- The `user_created` flag prevents the stale policy reaper from deleting them
- When the router sync runs and finds a matching policy tuple (same service/protocol/port/VLAN), it updates `last_synced` but does NOT overwrite the authorized targets, source, or priority
- Once a policy is marked as admin-created, it can never be downgraded back to router-synced by a subsequent sync

This means your custom policies persist across restarts, sync cycles, and router configuration changes.

## Per-VLAN Severity

Deviation severity is computed from two factors:

- **VLAN sensitivity** (configured in Settings > VLAN Config) — acts as the floor
- **Policy priority** — can only escalate, never diminish

Examples:
- Low-priority NTP policy on a critical VLAN = **critical** deviation (VLAN dominates)
- High-priority DNS policy on a low-sensitivity VLAN = **high** deviation (policy escalates)
- Low-priority policy on a low-sensitivity VLAN = **informational**

## CSV Export

Click **Export CSV** in the deviations section to download all visible deviations. The CSV includes:

- Type, Device hostname, IP, VLAN name
- Expected and Actual servers
- Severity, Status, Occurrence count
- First Seen and Last Seen timestamps (ISO 8601)
- ATT&CK technique IDs

Cell values are sanitized to prevent spreadsheet formula injection.

## Delete All Deviations

Click **Delete All (N)** to purge all policy deviations. This requires confirmation and cannot be undone. Use this after making network changes (e.g., reconfiguring NTP servers) to start fresh.

## MITRE ATT&CK Mappings

| Service | Techniques | Description |
|---------|-----------|-------------|
| DNS | T1071.004, T1568, T1048.003, T1583.001 | Application Layer Protocol, Dynamic Resolution, Exfiltration Over Alternative Protocol, Acquire Infrastructure |
| NTP | T1124 | System Time Discovery |

Each deviation links to the MITRE ATT&CK page for the relevant techniques.
