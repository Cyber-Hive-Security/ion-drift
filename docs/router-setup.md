# Router and Switch Setup Guide

This guide covers the recommended MikroTik RouterOS configuration for
Ion Drift. These settings are not strictly required — Drift will work
with default configurations — but they significantly improve topology
accuracy and network visibility.

## 1. API User

Ion Drift communicates with your router via the RouterOS REST API.
Create a dedicated API user with read-only access for normal monitoring.

```
/user/group/add name=ion-drift-ro policy=read,api,rest-api
/user/add name=ion-drift group=ion-drift-ro password=<SECURE_PASSWORD>
```

### Write access for provisioning

The Setup Wizard (Settings > Setup) creates mangle rules, syslog
configuration, and firewall log rules on your router. These changes
require temporary write permission.

**Option A: Temporary write (recommended)**

Add write permission before running the Setup Wizard, remove it after:
```
/user/group/set [find name=ion-drift-ro] policy=read,write,api,rest-api
```

After provisioning completes:
```
/user/group/set [find name=ion-drift-ro] policy=read,api,rest-api
```

**Option B: Separate provisioning user**
```
/user/group/add name=ion-drift-rw policy=read,write,api,rest-api
/user/add name=ion-drift-provision group=ion-drift-rw password=<SECURE_PASSWORD>
```

Use this user only during setup, then disable it.

## 2. Neighbor Discovery (MNDP)

MikroTik devices use MNDP (MikroTik Neighbor Discovery Protocol) to
discover each other on the network. Ion Drift uses this data to build
the network topology — it is the primary source for switch-to-switch
and switch-to-router link discovery.

### Why it matters

Without MNDP, Drift cannot automatically discover:
- Which switches are connected to which ports
- The physical topology of your network
- Device identities (router name, switch model, firmware version)

You would need to manually define all connections via backbone links,
and the topology would not self-correct when links change.

### Recommended configuration

Enable MNDP **only on your management VLAN interface**. Do not enable
it on trunk ports, customer-facing ports, or WAN interfaces.

On each MikroTik device (router and all managed switches):

```
# Create an interface list for MNDP (if it doesn't exist)
/interface/list/add name=mndp-allowed

# Add your management VLAN interface to the list
# (use the exact interface name from /interface print)
/interface/list/member/add interface=<MGMT_VLAN_INTERFACE> list=mndp-allowed

# Restrict MNDP to the management VLAN only
/ip/neighbor/discovery-settings/set discover-interface-list=mndp-allowed
```

Replace `<MGMT_VLAN_INTERFACE>` with your actual management VLAN
interface name. Common examples:
- `vlan2-mgmt`
- `VLAN2-Mgmt`
- `V-2-T-Management`

To find your management VLAN interface name:
```
/interface print where type=vlan
```

### Security considerations

MNDP broadcasts include device identity, firmware version, board model,
and MAC address. Restricting MNDP to the management VLAN ensures this
information is only visible to trusted infrastructure devices — not to
endpoints, guest networks, or WAN-facing interfaces.

**Never enable MNDP on WAN interfaces.** ISP equipment may be visible
via MNDP, exposing their infrastructure details to your network.

### Device identity

Each MikroTik device should have a unique system identity set:
```
/system/identity/set name=<DEVICE_NAME>
```

This identity is what appears in the topology. If left at the factory
default ("MikroTik"), Drift cannot distinguish between devices and
will show generic nodes in the topology.

Recommended naming convention: include the model and location, e.g.,
`RB4011-Office`, `CRS326-Office`, `CRS310-Basement`.

## 3. SNMP (for non-RouterOS switches)

For managed switches that do not run RouterOS (e.g., Netgear, Cisco,
Ubiquiti), Drift uses SNMP for monitoring. Register these devices in
Settings > Devices with their SNMP credentials.

Drift supports SNMPv2c and SNMPv3. SNMPv3 is recommended for
production networks.

## 4. What the Setup Wizard creates

When you run the Setup Wizard (Settings > Setup), it creates the
following on your router with your explicit approval:

| Item | What it does | Impact |
|------|-------------|--------|
| **Mangle rules** | Passthrough counters for inter-VLAN and WAN traffic | Zero — passthrough does not alter packets |
| **Syslog action** | Directs firewall logs to Drift's syslog listener | Adds a remote log destination |
| **Logging rule** | Routes the "firewall" topic to the syslog action | Enables connection tracking via syslog |
| **Firewall log rules** | Logs new connections in forward and input chains | Log-only rules appended to chain end |

None of these changes filter, drop, redirect, or alter any traffic.
All are identified with an "iondrift" label and can be removed at any
time through your router's management interface.

## 5. Stale data

Drift automatically prunes stale data:
- MAC table entries older than 1 hour
- Port role entries older than 1 hour
- Neighbor discovery entries older than 4 hours

If you move a device, rename it, or disable MNDP, the old data will
be automatically cleaned up within 4 hours. To force an immediate
cleanup, restart the Drift service.
