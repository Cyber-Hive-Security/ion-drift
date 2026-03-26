# SNMP Switch Profiles

Ion Drift monitors managed switches via SNMP using **vendor profiles** — configuration modules that tell Ion Drift how to interpret each vendor's SNMP data.

## What a Profile Does

Every managed switch implements the same standard SNMP MIBs, but vendors differ in how they populate them. A profile handles these differences:

| Aspect | What varies | Profile controls |
|--------|-------------|-----------------|
| **Interface naming** | Netgear: `g1`, Cisco: `GigabitEthernet1/0/1`, Aruba: `Port 1` | `friendly_name_fn` — maps raw ifName/ifDescr to clean display names |
| **Port classification** | Which ifType values are physical, LAG, VLAN, management | `physical_if_types`, `lag_if_types` arrays |
| **Hidden interfaces** | Internal/virtual interfaces that clutter the UI | `hidden_index_ranges` — filtered from display |
| **Counter support** | Some firmware doesn't return 64-bit counters or stats | Detected at poll time, but profile can flag known limitations |
| **Vendor detection** | Matching `sysDescr` to the correct profile | `detect_profile()` match string |

## Without a Profile

If no vendor-specific profile matches, Ion Drift uses the **generic fallback**. This means:

- Standard SNMP OIDs are walked successfully — data comes back
- Interface classification uses generic ifType mapping — basic physical/LAG/VLAN detection works
- Interface names display as-is from the device (`ifName` or `ifDescr`) — may be verbose, duplicated, or inconsistent
- No hidden interface filtering — internal/management interfaces show up as noise
- Counters work, but port indexing may be off for vendors with non-standard index ranges

**The switch works, but the display may be rough.** A dedicated profile cleans this up.

## Supported Vendors

| Vendor | Profile | Detection | Notes |
|--------|---------|-----------|-------|
| Netgear ProSafe | `NETGEAR_PROFILE` | `sysDescr` contains "netgear" or "prosafe" | Tested on MS510TXPP. Handles multi-gig naming, hidden indices. |
| Generic | `GENERIC_PROFILE` | Fallback for all unrecognized devices | Standard MIB-II classification only. |

## Contributing a Profile

If your switch shows display issues (wrong port names, hidden ports visible, missing data), you can help us build a profile by collecting SNMP data from your device.

### Step 1: Run the Collection Script

The script walks standard SNMP OIDs and outputs a text file with the data we need. **All sensitive data is automatically anonymized** — MAC addresses are OUI-only (vendor bytes preserved, last 3 octets replaced), hostnames are redacted, and port descriptions are blanked.

```bash
# Download
curl -O https://raw.githubusercontent.com/Cyber-Hive-Security/ion-drift/main/scripts/snmp-profile-collect.sh
chmod +x snmp-profile-collect.sh

# SNMPv2c
./snmp-profile-collect.sh -v 2c -c <community> <switch-ip>

# SNMPv3
./snmp-profile-collect.sh -v 3 -u <user> -a SHA -A <authpass> -l authNoPriv <switch-ip>

# SNMPv3 with privacy
./snmp-profile-collect.sh -v 3 -u <user> -a SHA -A <authpass> -x AES -X <privpass> -l authPriv <switch-ip>
```

Requires `net-snmp` tools (`snmpwalk`, `snmpget`). Install via:
- Debian/Ubuntu: `apt install snmp`
- macOS: `brew install net-snmp`
- RHEL/Fedora: `dnf install net-snmp-utils`

### Step 2: Review the Output

The script produces a file like `snmp-profile-20260325-143022.txt`. Review it before sharing — the anonymization is automatic but you should verify nothing sensitive slipped through.

### What the Script Collects

| Data | Why we need it |
|------|---------------|
| sysDescr, sysObjectID | Vendor detection — how to match your device automatically |
| ifType | Port classification — which interfaces are physical, LAG, VLAN, management |
| ifName, ifDescr | Naming convention — how to build friendly display names |
| ifAlias | Whether the device supports user-defined port descriptions |
| ifOperStatus | Confirm the interface walk completes successfully |
| ifHighSpeed | Whether high-speed counters are supported |
| ifHCInOctets, ifHCOutOctets | Whether 64-bit traffic counters work (5 sample entries) |
| ifPhysAddress | Switch's own MAC OUIs for vendor confirmation |
| Q-BRIDGE FDB | Whether the MAC address table is queryable (entry count only, no actual MACs) |
| LLDP | Whether LLDP neighbor discovery works (entry count only, no neighbor details) |
| Entity MIB | Hardware model identification |

**What it does NOT collect:** No network topology, no connected device MACs, no neighbor hostnames, no IP addresses, no traffic data.

### Step 3: Submit

Open an issue on [GitHub](https://github.com/Cyber-Hive-Security/ion-drift/issues) with:
- The output file attached
- Your switch model and firmware version
- Any display issues you're seeing in Ion Drift (screenshots help)

We'll use the data to build a profile and include it in the next release.

## Profile Architecture

Profiles are defined in `crates/mikrotik-core/src/snmp_profile.rs`. Each profile is a static `SnmpProfile` struct:

```rust
pub struct SnmpProfile {
    pub physical_if_types: &'static [u32],    // IANA ifType values for physical ports
    pub lag_if_types: &'static [u32],         // ifType values for LAG/trunk groups
    pub hidden_index_ranges: &'static [(u32, u32)],  // Index ranges to filter out
    pub friendly_name_fn: fn(u32, &str, &str) -> String,  // Index + ifName + ifDescr → display name
}
```

Vendor detection is in `detect_profile()`, which matches against `sysDescr`. The profile is selected once per poll cycle and applied to all interface classification and naming.
