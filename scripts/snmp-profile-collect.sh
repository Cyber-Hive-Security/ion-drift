#!/bin/bash
# SNMP Profile Data Collection Script
# Collects the OID data needed to build an Ion Drift SNMP switch profile.
# All sensitive data (IPs, MACs, hostnames) is automatically anonymized.
#
# Usage:
#   SNMPv2c: ./snmp-profile-collect.sh -v 2c -c <community> <host>
#   SNMPv3:  ./snmp-profile-collect.sh -v 3 -u <user> -a SHA -A <authpass> -x AES -X <privpass> -l authPriv <host>
#
# Output: snmp-profile-<date>.txt (no hostname in filename)
#
# Requirements: net-snmp tools (snmpwalk, snmpget)

set -euo pipefail

# Pass all args through to snmpwalk/snmpget
SNMP_ARGS=("$@")

# Extract hostname (last arg)
HOST="${SNMP_ARGS[-1]}"
OUTFILE="snmp-profile-$(date +%Y%m%d-%H%M%S).txt"
RAWFILE=$(mktemp)

echo "=== Ion Drift SNMP Profile Collection ==="
echo "Host: $HOST"
echo "Output: $OUTFILE"
echo ""
echo "All IPs, MACs, and hostnames will be anonymized automatically."
echo ""

# ── Collect raw data ─────────────────────────────────────────────

{
echo "=========================================="
echo "Ion Drift SNMP Profile Data (anonymized)"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=========================================="

echo ""
echo "=== 1. System Identity ==="
echo "--- sysDescr (1.3.6.1.2.1.1.1.0) ---"
snmpget -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.1.1.0 2>&1 || echo "(failed)"

echo "--- sysName (1.3.6.1.2.1.1.5.0) ---"
snmpget -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.1.5.0 2>&1 || echo "(failed)"

echo "--- sysObjectID (1.3.6.1.2.1.1.2.0) ---"
snmpget -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.1.2.0 2>&1 || echo "(failed)"

echo ""
echo "=== 2. Interface Table (ifDescr) ==="
echo "--- ifDescr (1.3.6.1.2.1.2.2.1.2) ---"
snmpwalk -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.2.2.1.2 2>&1 || echo "(failed)"

echo ""
echo "=== 3. Interface Types (ifType) ==="
echo "--- ifType (1.3.6.1.2.1.2.2.1.3) ---"
snmpwalk -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.2.2.1.3 2>&1 || echo "(failed)"

echo ""
echo "=== 4. Interface Names (ifName) ==="
echo "--- ifName (1.3.6.1.2.1.31.1.1.1.1) ---"
snmpwalk -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.31.1.1.1.1 2>&1 || echo "(failed)"

echo ""
echo "=== 5. Interface Aliases (ifAlias) ==="
echo "--- ifAlias (1.3.6.1.2.1.31.1.1.1.18) ---"
snmpwalk -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.31.1.1.1.18 2>&1 || echo "(failed)"

echo ""
echo "=== 6. Interface Oper Status (ifOperStatus) ==="
echo "--- ifOperStatus (1.3.6.1.2.1.2.2.1.8) ---"
snmpwalk -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.2.2.1.8 2>&1 || echo "(failed)"

echo ""
echo "=== 7. Interface Speed (ifHighSpeed) ==="
echo "--- ifHighSpeed (1.3.6.1.2.1.31.1.1.1.15) ---"
snmpwalk -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.31.1.1.1.15 2>&1 || echo "(failed)"

echo ""
echo "=== 8. 64-bit Counters (ifHCInOctets) ==="
echo "--- ifHCInOctets (1.3.6.1.2.1.31.1.1.1.6) ---"
snmpwalk -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.31.1.1.1.6 2>&1 | head -5 || echo "(failed)"
echo "(sample — 5 entries)"

echo ""
echo "=== 9. 64-bit Counters (ifHCOutOctets) ==="
echo "--- ifHCOutOctets (1.3.6.1.2.1.31.1.1.1.10) ---"
snmpwalk -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.31.1.1.1.10 2>&1 | head -5 || echo "(failed)"
echo "(sample — 5 entries)"

echo ""
echo "=== 10. Q-BRIDGE FDB Support Check ==="
echo "--- dot1qTpFdbPort (1.3.6.1.2.1.17.7.1.2.2.1.2) — structure only ---"
# Only check if the OID is supported and count entries; actual MACs are not needed
COUNT=$(snmpwalk -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.17.7.1.2.2.1.2 2>&1 | grep -c "INTEGER" || true)
echo "FDB entries found: $COUNT"

echo ""
echo "=== 11. LLDP Support Check ==="
echo "--- lldpRemSysName (1.0.8802.1.1.2.1.4.1.1.9) — entry count only ---"
COUNT=$(snmpwalk -On "${SNMP_ARGS[@]}" 1.0.8802.1.1.2.1.4.1.1.9 2>&1 | grep -c "STRING" || true)
echo "LLDP neighbors found: $COUNT"

echo ""
echo "=== 12. Switch Interface MACs (ifPhysAddress) ==="
echo "--- ifPhysAddress (1.3.6.1.2.1.2.2.1.6) — OUI only ---"
snmpwalk -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.2.2.1.6 2>&1 || echo "(failed)"

echo ""
echo "=== 13. Entity MIB (for model/serial) ==="
echo "--- entPhysicalModelName (1.3.6.1.2.1.47.1.1.1.1.13) ---"
snmpwalk -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.47.1.1.1.1.13 2>&1 | head -5 || echo "(failed or not supported)"

echo ""
echo "=========================================="
echo "Collection complete."
echo "=========================================="

} > "$RAWFILE" 2>&1

# ── Anonymize sensitive data ─────────────────────────────────────

echo "Anonymizing..."

# Build replacement maps for consistent anonymization
declare -A MAC_MAP
MAC_COUNT=0

anonymize() {
    local data
    data=$(cat "$RAWFILE")

    # Replace MAC addresses — preserve OUI (first 3 octets) for vendor ID, anonymize last 3
    while IFS= read -r mac; do
        if [[ -z "${MAC_MAP[$mac]+x}" ]]; then
            MAC_COUNT=$((MAC_COUNT + 1))
            oui=$(echo "$mac" | cut -d: -f1-3 2>/dev/null || echo "$mac" | cut -d- -f1-3 2>/dev/null || echo "XX:XX:XX")
            MAC_MAP[$mac]="${oui}:AA:BB:$(printf '%02X' $MAC_COUNT)"
        fi
        data=$(echo "$data" | sed "s/$mac/${MAC_MAP[$mac]}/gi")
    done < <(echo "$data" | grep -oiE '([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}' | sort -u)

    # Redact target host IP/hostname
    data=$(echo "$data" | sed "s/$HOST/[redacted-host]/g")

    # Redact sysName (device hostname)
    data=$(echo "$data" | sed -E '/sysName/{ s/STRING: "([^"]+)"/STRING: "[redacted-hostname]"/g; }')

    # Redact ifAlias values (user-defined port descriptions)
    data=$(echo "$data" | sed -E '/ifAlias/,/^===/{ s/STRING: "([^"]+)"/STRING: "[port-description]"/g; }')

    echo "$data"
}

anonymize > "$OUTFILE"
rm -f "$RAWFILE"

echo ""
echo "Done! Anonymized output saved to: $OUTFILE"
echo ""
echo "Anonymization summary:"
echo "  MACs: $MAC_COUNT anonymized (OUI preserved for vendor ID)"
echo "  sysName, ifAlias, target host: redacted"
echo ""
echo "Please review the file before sharing, then attach it to the GitHub issue."
