#!/bin/bash
# SNMP Profile Data Collection Script
# Collects the OID data needed to build an Ion Drift SNMP switch profile.
#
# Usage:
#   SNMPv2c: ./snmp-profile-collect.sh -v 2c -c <community> <host>
#   SNMPv3:  ./snmp-profile-collect.sh -v 3 -u <user> -a SHA -A <authpass> -x AES -X <privpass> -l authPriv <host>
#
# Output: snmp-profile-<hostname>-<date>.txt
#
# Requirements: net-snmp tools (snmpwalk, snmpget)

set -euo pipefail

# Pass all args through to snmpwalk/snmpget
SNMP_ARGS=("$@")

# Extract hostname (last arg)
HOST="${SNMP_ARGS[-1]}"
SAFE_HOST=$(echo "$HOST" | tr '.:' '-')
OUTFILE="snmp-profile-${SAFE_HOST}-$(date +%Y%m%d-%H%M%S).txt"

echo "=== Ion Drift SNMP Profile Collection ==="
echo "Host: $HOST"
echo "Output: $OUTFILE"
echo ""

{
echo "=========================================="
echo "Ion Drift SNMP Profile Data"
echo "Host: $HOST"
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
snmpwalk -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.31.1.1.1.6 2>&1 | head -20 || echo "(failed)"
echo "(truncated to 20 entries)"

echo ""
echo "=== 9. 64-bit Counters (ifHCOutOctets) ==="
echo "--- ifHCOutOctets (1.3.6.1.2.1.31.1.1.1.10) ---"
snmpwalk -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.31.1.1.1.10 2>&1 | head -20 || echo "(failed)"
echo "(truncated to 20 entries)"

echo ""
echo "=== 10. MAC Address Table (Q-BRIDGE dot1qTpFdbPort) ==="
echo "--- dot1qTpFdbPort (1.3.6.1.2.1.17.7.1.2.2.1.2) ---"
snmpwalk -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.17.7.1.2.2.1.2 2>&1 | head -30 || echo "(failed)"
echo "(truncated to 30 entries)"

echo ""
echo "=== 11. LLDP Remote System Name ==="
echo "--- lldpRemSysName (1.0.8802.1.1.2.1.4.1.1.9) ---"
snmpwalk -On "${SNMP_ARGS[@]}" 1.0.8802.1.1.2.1.4.1.1.9 2>&1 || echo "(failed or no LLDP neighbors)"

echo ""
echo "=== 12. LLDP Remote Chassis ID ==="
echo "--- lldpRemChassisId (1.0.8802.1.1.2.1.4.1.1.5) ---"
snmpwalk -On "${SNMP_ARGS[@]}" 1.0.8802.1.1.2.1.4.1.1.5 2>&1 || echo "(failed or no LLDP neighbors)"

echo ""
echo "=== 13. LLDP Remote Port Description ==="
echo "--- lldpRemPortDesc (1.0.8802.1.1.2.1.4.1.1.8) ---"
snmpwalk -On "${SNMP_ARGS[@]}" 1.0.8802.1.1.2.1.4.1.1.8 2>&1 || echo "(failed or no LLDP neighbors)"

echo ""
echo "=== 14. Interface Physical Address (ifPhysAddress) ==="
echo "--- ifPhysAddress (1.3.6.1.2.1.2.2.1.6) ---"
snmpwalk -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.2.2.1.6 2>&1 || echo "(failed)"

echo ""
echo "=== 15. Entity MIB (for model/serial) ==="
echo "--- entPhysicalModelName (1.3.6.1.2.1.47.1.1.1.1.13) ---"
snmpwalk -On "${SNMP_ARGS[@]}" 1.3.6.1.2.1.47.1.1.1.1.13 2>&1 | head -5 || echo "(failed or not supported)"

echo ""
echo "=========================================="
echo "Collection complete."
echo "=========================================="

} > "$OUTFILE" 2>&1

echo "Done! Output saved to: $OUTFILE"
echo "Please share this file in the GitHub issue."
