# Switch VLAN Membership: Physical Ports Only — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Revised during review (2026-10-25):** the ethernet-list filter below was replaced before merge. Filtering to ethernet names would also drop bonds, wireless and VXLAN bridge members, and VLAN membership feeds port roles (`correlation_engine.rs`) and topology `vlans_served`. The merged helper is `fn vlan_membership(vlans: &[BridgeVlan]) -> Vec<VlanMembershipEntry>` and skips only `port == vlan.bridge`, using the VLAN row's own `bridge` field. No ethernet dependency, no empty-set guard. Tests: bridge skipped, bond/wlan kept, first VLAN id wins. The rest of this document is the original plan as executed up to that point.

**Goal:** Stop the RouterOS switch poller from recording the bridge interface (or any other non-ethernet name) as a VLAN member, so the port grid no longer maps "bridge1" onto port 1 and hides ether1.

**Architecture:** The poller already fetches `interface/ethernet` in the same batch as `interface/bridge/vlan`. Build the set of ethernet names once, then expand the tagged/untagged lists into membership rows through a pure helper that drops names outside that set. If the ethernet list failed to load (set empty), keep every row rather than wiping VLAN data on a transient error — the same guard the SNMP poller uses. The grid's exact-match `"bridge"` special case is then dead and is removed.

**Tech Stack:** Rust 1.96 edition 2024 (`crates/ion-drift-web`), React 19 / TypeScript 5.7 / Vitest (`web/`).

## Global Constraints

- No schema change. Membership rows are replaced wholesale each poll (`set_vlan_membership`), so existing bridge rows on upgraded instances clear on the next poll.
- SwOS and SNMP pollers are untouched. SNMP already filters against its physical set; SwOS resolves names from the link table.
- The ethernet list is the only source of truth for "physical". No name regexes, no prefix lists.
- Empty physical set → no filtering (keep rows). Never drop all VLAN data because one request failed.
- Line endings are mixed per file; `switch_poller.rs`, `port-grid.tsx` and `CHANGELOG.md` are CRLF. Check with `file` and edit with python `newline=''`.
- Clippy at zero (`-D warnings`), ESLint 0 errors, all tests green before commit.
- Commit trailers: `Co-Authored-By: Claude Mythos 5.1 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_01V7Qgi9QkxNzZgG3NLnDAGJ`.

---

### Task 1: Filter VLAN membership to ethernet ports in the RouterOS switch poller

**Files:**
- Modify: `crates/ion-drift-web/src/switch_poller.rs:198-311`
- Modify: `web/src/features/switch-detail/port-grid.tsx:224-229`
- Modify: `CHANGELOG.md` (0.5.6 Fixed section + "five items" count)

**Interfaces:**
- Consumes: `mikrotik_core::resources::bridge::BridgeVlan { vlan_ids: String, tagged: Option<String>, untagged: Option<String>, .. }`, `ion_drift_storage::switch::VlanMembershipEntry { port_name: String, vlan_id: u32, tagged: bool }`.
- Produces: `fn vlan_membership(vlans: &[BridgeVlan], physical: &HashSet<String>) -> Vec<VlanMembershipEntry>` (private to `switch_poller.rs`).

- [ ] **Step 1: Write the failing tests**

Append to `crates/ion-drift-web/src/switch_poller.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::vlan_membership;
    use mikrotik_core::resources::bridge::BridgeVlan;
    use std::collections::HashSet;

    fn vlan(ids: &str, tagged: Option<&str>, untagged: Option<&str>) -> BridgeVlan {
        BridgeVlan {
            id: "*1".into(),
            bridge: "bridge1".into(),
            vlan_ids: ids.into(),
            tagged: tagged.map(str::to_string),
            untagged: untagged.map(str::to_string),
            current_tagged: None,
            current_untagged: None,
            dynamic: None,
        }
    }

    fn physical(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn bridge_interface_is_not_a_vlan_member() {
        // RouterOS lists the bridge itself as tagged on the management VLAN.
        let vlans = [vlan("99", Some("bridge1,ether1"), Some("ether2"))];
        let rows = vlan_membership(&vlans, &physical(&["ether1", "ether2", "ether3"]));
        let names: Vec<_> = rows.iter().map(|r| r.port_name.as_str()).collect();
        assert_eq!(names, ["ether1", "ether2"]);
        assert!(rows[0].tagged && !rows[1].tagged);
        assert!(rows.iter().all(|r| r.vlan_id == 99));
    }

    #[test]
    fn empty_physical_set_keeps_every_row() {
        // Ethernet list failed to load: never wipe VLAN data on a transient error.
        let vlans = [vlan("10", Some("bridge1"), Some("ether1"))];
        let rows = vlan_membership(&vlans, &HashSet::new());
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn first_vlan_id_wins_and_unparseable_is_skipped() {
        let vlans = [vlan("10,20", None, Some("ether1")), vlan("bogus", None, Some("ether1"))];
        let rows = vlan_membership(&vlans, &physical(&["ether1"]));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].vlan_id, 10);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ion-drift-web --lib switch_poller::tests`
Expected: compile error, `vlan_membership` not found.

- [ ] **Step 3: Implement the helper and use it**

Add above `poll_switch` in `switch_poller.rs`:

```rust
/// Expand bridge VLAN tagged/untagged lists into membership rows for physical
/// ports. RouterOS lists the bridge itself as a tagged member of the
/// management VLAN; it is not a port and must not reach the port grid.
/// An empty `physical` set means the ethernet list was unavailable: keep every
/// row rather than wipe VLAN data on a transient error.
fn vlan_membership(
    vlans: &[mikrotik_core::resources::bridge::BridgeVlan],
    physical: &std::collections::HashSet<String>,
) -> Vec<VlanMembershipEntry> {
    let mut rows = Vec::new();
    for vlan in vlans {
        // vlan_ids can be "10" or "10,20" — use the primary one
        let Some(vlan_id) = vlan.vlan_ids.split(',').next().and_then(|s| s.trim().parse().ok()) else {
            continue;
        };
        for (list, tagged) in [(&vlan.tagged, true), (&vlan.untagged, false)] {
            for port in list.as_deref().unwrap_or("").split(',') {
                let port = port.trim();
                if port.is_empty() || (!physical.is_empty() && !physical.contains(port)) {
                    continue;
                }
                rows.push(VlanMembershipEntry { port_name: port.to_string(), vlan_id, tagged });
            }
        }
    }
    rows
}
```

In `poll_switch`, right after the `deserialize_result` block, capture the physical set before `ethernet_res` is consumed:

```rust
let physical_ports: std::collections::HashSet<String> = ethernet_res
    .as_ref()
    .map(|ifaces| ifaces.iter().map(|i| i.name.clone()).collect())
    .unwrap_or_default();
```

Replace the body of `if let Ok(vlans) = bridge_vlans_res { ... }` (the manual loop building `membership_entries`) with:

```rust
if let Ok(vlans) = bridge_vlans_res {
    let rows = vlan_membership(&vlans, &physical_ports);
    if let Err(e) = store.set_vlan_membership(device_id, &rows).await {
        tracing::warn!(device = %device_id, "vlan membership: {e}");
    }
} else if let Err(e) = bridge_vlans_res {
    tracing::warn!(device = %device_id, "bridge_vlans: {e}");
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ion-drift-web --lib switch_poller::tests`
Expected: 3 passed.

- [ ] **Step 5: Remove the dead special case in the port grid**

In `web/src/features/switch-detail/port-grid.tsx` replace:

```ts
      if (!pos) {
        if (cell.portName !== "bridge") {
          other.push(cell);
        }
        continue;
      }
```

with:

```ts
      if (!pos) {
        other.push(cell);
        continue;
      }
```

Run: `cd web && npm run lint && npx vitest run && npm run build`
Expected: 0 errors, all tests pass, build ok.

- [ ] **Step 6: CHANGELOG**

In the 0.5.6 section, change "five items under Fixed" to "six items under Fixed" and add as the first bullet under `### Fixed` (CRLF preserved):

```
- **Switch port grid showed the bridge as port 1.** RouterOS lists the bridge interface itself as a tagged member of the management VLAN, and the switch poller recorded it as a VLAN member like any port. On a switch whose bridge is named `bridge1`, the port grid read the trailing digit as port 1 and drew it over ether1. VLAN membership is now limited to the switch's ethernet interfaces; the bridge no longer appears on the port grid or the VLAN audit grid. Existing rows clear on the first poll after upgrade.
```

- [ ] **Step 7: Full battery and commit**

Run from the worktree root: `cargo test --workspace --locked`, `cargo clippy --workspace --locked --all-targets -- -D warnings`, `scripts/check-internal-identifiers.sh` (staged), `gitleaks git --no-banner .`
Expected: all green.

```bash
git add crates/ion-drift-web/src/switch_poller.rs web/src/features/switch-detail/port-grid.tsx CHANGELOG.md docs/superpowers/plans/2026-10-25-switch-vlan-physical-ports.md
git commit -m "fix(switch): record VLAN membership for ethernet ports only"
```
