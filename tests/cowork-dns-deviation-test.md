# DNS Policy Deviation — Functional Test Prompt

Use this prompt with Claude Cowork (browser-connected) to exercise the DNS policy deviation feature.

---

## Prompt

You are testing the DNS Policy Deviation feature in Ion Drift, a network monitoring tool. The app should already be loaded in your browser. Work through each test case, recording what you observe. Take a screenshot at each step.

### Prerequisites Check

1. Navigate to the **Dashboard**. Confirm you see a "Policy Deviations" card. Note the count (may be 0 if no deviations detected yet).
2. Navigate to **Settings > Devices**. Confirm there is at least one router connected (status: Online).
3. Wait at least 2 minutes for the policy deviation detector to complete its first cycle (runs every 60s).

### Test 1: Deviation Detection

1. Navigate to the **Policy** page (sidebar).
2. Look for a "Deviations" section or tab. Are there any DNS deviations listed?
3. For each deviation, verify it shows:
   - Source MAC address
   - Source IP and VLAN
   - Deviation type (`dns_unauthorized` or `dns_unclassified`)
   - Expected vs. Actual DNS server
   - ATT&CK technique pills (should show T1071.004, T1568, T1048.003, or T1583.001)
   - Severity level
   - Occurrence count
   - First seen / Last seen timestamps
4. Click an ATT&CK technique pill — does it open the MITRE ATT&CK page for that technique?
5. **Record:** How many deviations are shown? Are any devices listed that you'd expect to be compliant (false positives)?

### Test 2: Policy Page — Authorized DNS

1. Still on the **Policy** page, look for the DNS policy section.
2. Are authorized DNS servers listed? Note which IPs are shown.
3. Do they match the DNS servers configured on the router (from DHCP/DNS config)?

### Test 3: Resolve Actions

1. Find a DNS deviation in the list.
2. Try each resolve action (if available):
   - **Authorize** — should add the observed DNS server to the VLAN-scoped policy. After authorizing, does the deviation disappear on the next cycle?
   - **Dismiss** — should hide the deviation. Does it reappear if the same violation recurs?
   - **Acknowledge** — should mark as seen but keep visible. Does the status change?
3. **Record:** Which actions are available? Do they behave as described?

### Test 4: Dashboard Integration

1. Navigate back to the **Dashboard**.
2. Does the Policy Deviations card reflect the current count?
3. If you authorized a deviation in Test 3, has the count decreased?

### Test 5: Investigation Page

1. Click on a device that has a DNS deviation (from the Devices list or topology).
2. Navigate to its **Investigation** page.
3. Look for policy deviation cards in the investigation view.
4. Do the deviation cards show ATT&CK context?
5. Is there a link back to the Policy page for resolution?

### Test 6: DNS Server Exclusion

1. On the Policy page, check if your actual DNS servers (the ones devices SHOULD be using) are excluded from deviations.
2. DNS servers should NOT appear as deviating devices — their outbound port-53 traffic is recursive resolution, not a policy violation.
3. **Record:** Are any DNS servers incorrectly flagged?

### Test 7: Diagnostic Report

1. Navigate to **Settings > Statistics** (or Diagnostics).
2. Generate a diagnostic report.
3. Does the report include a policy deviations section?
4. What information is included?

### Summary

After completing all tests, provide:
1. **Pass/Fail** for each test case
2. **Screenshots** of any failures or unexpected behavior
3. **False positives** — devices flagged that shouldn't be
4. **Missing data** — expected deviations that don't appear
5. **UI issues** — anything confusing, broken, or hard to find
6. **Overall assessment** — is this feature ready to graduate from beta?
