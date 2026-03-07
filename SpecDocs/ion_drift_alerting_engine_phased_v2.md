# Ion Drift Feature Spec
## Alerting Engine — Phased Implementation Plan (v2)

> This document restructures the Alerting Engine into a safer, execution-ready **4-phase feature plan**.
>
> The product direction remains the same:
> - add configurable alerting on top of existing anomaly and infrastructure signals
> - deliver notifications through ntfy, webhook, and SMTP
> - expose alert configuration and history in Settings
>
> The main change is delivery strategy:
> **build this in four phases instead of one broad implementation pass**.

---

# 1. Executive Summary

The Alerting Engine is a high-value feature because Ion Drift already detects meaningful events but has no notification layer. The platform currently identifies anomalies, correlations, and state transitions, but all of that intelligence stays trapped inside the UI.

The original spec is strong, but it bundles together:

- new alerting schema and persistence
- a background evaluation engine
- three delivery channels
- settings UI for channels and rules
- alert history UX
- a global alert bell
- event-state tracking for interfaces and registered devices

That is too much for one pass if the goal is a clean, low-risk release.

This phased plan breaks the work into:

1. **Core Alert Engine Foundation**
2. **Delivery Channels and Testability**
3. **Rules, History, and Settings UX**
4. **Global Alert UX and Secondary Event Expansion**

This structure reduces risk, isolates the most failure-prone pieces, and lets the alert system become useful early before it becomes broad.

---

# 2. Product Goals

## Primary goals
- notify operators when meaningful events occur
- keep alert generation deterministic and explainable
- preserve the current anomaly and telemetry systems as read-only sources
- make alert delivery configurable without requiring deep setup
- provide traceability through alert history and cooldown tracking

## Secondary goals
- improve operator responsiveness
- create a reusable event-to-notification pipeline for future features
- support self-hosted-friendly delivery paths first

## Non-goals
- no changes to behavioral anomaly computation
- no changes to port flow baseline computation
- no on-call scheduling or escalation chains
- no PagerDuty / OpsGenie / enterprise incident management integrations
- no automated remediation
- no browser notification or in-app sound system

---

# 3. Scope Boundary

## Existing systems that remain unchanged
- behavioral engine logic
- anomaly cross-reference pipeline
- connection history pipeline
- encrypted secrets architecture except for adding SMTP password usage
- existing Settings sections outside the new Alerts section
- all unrelated backend routes

## New feature area
A new alerting subsystem consisting of:
- alert configuration persistence
- a periodic alert evaluation task
- delivery channel dispatchers
- Settings > Alerts
- alert history views
- a top-nav alert bell

---

# 4. Shared Design Principles Across All Phases

1. **Read existing sources; do not rewrite them**
2. **Alert generation must be deterministic**
3. **Cooldowns must be enforced centrally**
4. **Delivery failures must be recorded, not retried blindly**
5. **UI follows existing Settings patterns** — auto-save on field blur with a momentary "Saved" indicator, matching the VLAN config section behavior throughout
6. **Add event coverage gradually, not all at once**
7. **Separate "engine correctness" from "channel breadth"**

---

# 5. Shared Technical Foundations

These are required across phases.

## 5.1 Core tables

Add to `switch.db`:

```sql
CREATE TABLE IF NOT EXISTS alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    event_type TEXT NOT NULL,
    severity_filter TEXT,                        -- "critical", "warning", "info", NULL = all
    vlan_filter TEXT,                            -- JSON array of vlan_ids, NULL = all VLANs
    disposition_filter TEXT,                     -- "my_device", "external", "flagged", "unknown", NULL = all
    cooldown_seconds INTEGER NOT NULL DEFAULT 300,
    delivery_channels TEXT NOT NULL DEFAULT '[]', -- JSON array: ["ntfy", "webhook", "smtp"]
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alert_delivery_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL UNIQUE,               -- "ntfy", "webhook", "smtp"
    enabled INTEGER NOT NULL DEFAULT 0,
    config_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS alert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL REFERENCES alert_rules(id),
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    device_mac TEXT,
    device_hostname TEXT,
    device_ip TEXT,
    vlan_id INTEGER,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    channels_attempted TEXT NOT NULL DEFAULT '[]',
    channels_succeeded TEXT NOT NULL DEFAULT '[]',
    fired_at TEXT NOT NULL DEFAULT (datetime('now')),
    anomaly_id INTEGER
);

CREATE TABLE IF NOT EXISTS alert_cooldowns (
    rule_id INTEGER NOT NULL,
    subject TEXT NOT NULL,
    last_fired_at TEXT NOT NULL,
    PRIMARY KEY (rule_id, subject)
);

-- Tracks prior state for transition-based event types.
-- The alert engine reads this table on each cycle to detect state changes,
-- then updates it after evaluation. Populated on first engine run from
-- current live state (no alert fired for initial population).
CREATE TABLE IF NOT EXISTS alert_state_cache (
    key TEXT NOT NULL PRIMARY KEY,              -- e.g. "interface:ether1", "device:42", "identity:AA:BB:CC:DD:EE:FF:disposition"
    value TEXT NOT NULL,                        -- last known state as text
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

Initialize `alert_delivery_config` with three rows on first startup (one per channel, all disabled):

```sql
INSERT OR IGNORE INTO alert_delivery_config (channel, enabled, config_json) VALUES
    ('ntfy', 0, '{"url": "https://ntfy.sh", "topic": "", "token": ""}'),
    ('webhook', 0, '{"url": "", "secret": ""}'),
    ('smtp', 0, '{"host": "", "port": 587, "username": "", "from": "", "to": []}');
```

## 5.2 Secrets handling

SMTP password is stored only via the existing encrypted secrets mechanism under the key `smtp_password`. It must never be returned from any API response.

When `PUT /api/alerts/channels/smtp` receives a `password` field, encrypt and store it via the existing secrets path. If the `password` field is absent from the request, leave the existing stored password unchanged.

## 5.3 Event subject model

Cooldowns are keyed by `(rule_id, subject)`. Subject values must be deterministic:

| Event Type | Subject Key |
|---|---|
| `anomaly_critical`, `anomaly_warning`, `anomaly_correlated` | device MAC (e.g. `AA:BB:CC:DD:EE:FF`) |
| `device_new` | device MAC |
| `device_flagged` | device MAC |
| `port_violation` | `port:{device_id}:{port_name}` |
| `interface_down` | `interface:{interface_name}` |
| `device_offline` | `device:{device_id}` |
| `dhcp_pool_exhausted` | `dhcp:{pool_name}` |
| `firewall_drop_spike` | `system:firewall_drop_spike` |

## 5.4 Delivery policy

Across all phases:
- best-effort, one attempt per channel
- timeout bounded per channel (ntfy: 10s, webhook: 10s, SMTP: 15s)
- no immediate retry loop
- record attempted and succeeded channels in `alert_history`
- on failure, log the error and continue — the next engine cycle will re-evaluate if the condition persists and cooldown allows

## 5.5 Transition detection via alert_state_cache

Several event types require detecting a state *transition* rather than a current condition. The engine uses `alert_state_cache` for this. The pattern for all transition-based events is:

1. Read the current live state (e.g., interface `running` flag, device `status`, identity `disposition`)
2. Read the prior state from `alert_state_cache` using the relevant key
3. If prior state does not exist (first engine run), write current state to cache and **do not fire an alert**
4. If prior state exists and differs from current state in a way that matches a rule, fire the alert
5. After evaluation, upsert `alert_state_cache` with the current state

This ensures that:
- no spurious alerts fire on engine startup or restart
- `device_flagged` only fires when disposition transitions *to* `flagged`, not on every cycle for already-flagged devices
- `interface_down` only fires on the running→not-running edge, not continuously while the interface remains down

---

# 6. Phase 1 — Core Alert Engine Foundation

## 6.1 Goal

Deliver the minimum viable alerting engine:
- persistence schema
- background task
- five highest-confidence event types
- history recording
- cooldown enforcement
- ntfy delivery only

This phase proves that the platform can detect, de-duplicate, construct, deliver, and record alerts.

## 6.2 Backend scope

### Database initialization

Create all four core tables plus `alert_state_cache`. Initialize `alert_delivery_config` rows. Seed default rules (see Section 5, defaults for Phase 1 event types only — add remaining defaults in later phases as their event types land).

### Background task

- 30 second startup delay
- 60 second evaluation interval

### Initial event types for Phase 1

Implement only:

| Event Type | Source | Trigger Condition |
|---|---|---|
| `anomaly_critical` | `behavior.db → anomalies` | New row with `severity = 'critical'` and `id > last_seen_id` and `created_at > datetime('now', '-5 minutes')` |
| `anomaly_correlated` | `connections.db → anomaly_links` | New row with `correlated = 1` and `id > last_seen_id` and `created_at > datetime('now', '-5 minutes')` |
| `device_new` | `switch.db → network_identities` | Row with `first_seen > datetime('now', '-{poll_interval}s')` and `disposition = 'unknown'` |
| `device_flagged` | `switch.db → network_identities` | Disposition transition to `flagged` (via `alert_state_cache`, see Section 5.5) |
| `port_violation` | `switch.db → port_violations` | New unresolved row (status != 'resolved') with `id > last_seen_id` |

**Checking for new anomalies and violations:** Store the highest `id` seen from each source table in `alert_state_cache` under keys `anomaly:last_id`, `anomaly_link:last_id`, and `port_violation:last_id`. On each cycle, query `WHERE id > {last_seen_id}`. This prevents re-alerting after restart.

**device_new safety note:** Verify before Phase 1 ships that the correlation engine never updates `first_seen` on an existing identity. If it does under any condition (e.g., MAC collision resolution), the `device_new` event will produce false positives. The invariant must hold: `first_seen` is written once on initial insert and never updated.

**device_flagged implementation:** On each engine cycle, query `network_identities WHERE disposition = 'flagged'`. For each flagged identity, look up `alert_state_cache` key `identity:{mac}:disposition`. If the cached value is not `flagged` (or does not exist), this is a new transition — fire the alert. After evaluation, upsert the cache with value `flagged`. When an identity's disposition changes away from `flagged`, update the cache to the new value so a future re-flagging will fire again.

### Cooldown enforcement

Before firing any alert:
1. Query `alert_cooldowns WHERE rule_id = ? AND subject = ?`
2. If row exists and `last_fired_at > datetime('now', '-{cooldown_seconds}s')`, skip
3. After delivery, upsert `alert_cooldowns` with current timestamp

### Alert payload templates (Phase 1 event types)

```
anomaly_critical:
  title: "🔴 Critical Anomaly — {device_hostname}"
  body:  "{anomaly_type} on {device_hostname} ({ip}) [VLAN {vlan_name}]: {anomaly_details}. Severity: critical."

anomaly_correlated:
  title: "🔴 Correlated Anomaly — {device_hostname}"
  body:  "Both behavioral engine and port flow baseline flagged {device_hostname} ({ip}): {anomaly_details}. Higher confidence of genuine anomalous behavior."

device_new:
  title: "🆕 New Device Detected"
  body:  "Unknown device appeared on network: {mac} ({manufacturer}), IP {ip}, VLAN {vlan_name}. Review in Identity Manager."

device_flagged:
  title: "🚩 Device Flagged"
  body:  "{device_hostname} ({ip}) has been marked as flagged. Review in Identity Manager."

port_violation:
  title: "🔒 Port Security Violation"
  body:  "{violation_type} on {switch_name} port {port}: expected {expected_mac}, found {actual_mac}."
```

## 6.3 Delivery channel scope in Phase 1

### ntfy only

Send a POST request to `{config.url}/{config.topic}`:

```
POST https://ntfy.sh/{topic}
Authorization: Bearer {token}     (omit header if token is empty)
Content-Type: text/plain
X-Title: {title}
X-Priority: {priority}
X-Tags: ion-drift,{event_type}

{body}
```

ntfy priority mapping:
- `critical` → `5` (urgent, bypasses Do Not Disturb)
- `warning` → `3` (default)
- `info` → `1` (min)

Timeout: 10 seconds. On failure, log and record in `channels_attempted` without `channels_succeeded`. Do not retry. Use the `reqwest` crate (already present in workspace).

### Not in Phase 1
- no webhook delivery
- no SMTP delivery

## 6.4 API scope in Phase 1

Implement:
- `GET /api/alerts/rules` — list all rules
- `GET /api/alerts/status` — engine status: enabled rule count, last check timestamp
- `GET /api/alerts/history?limit=50&offset=0` — paginated, newest first
- `DELETE /api/alerts/history` — clear history

`GET /api/alerts/rules` is required in Phase 1, not optional. The backend needs it to verify seeding is correct during development, and Phase 3 frontend depends on it.

## 6.5 Default rules seeded in Phase 1

```sql
INSERT INTO alert_rules (name, enabled, event_type, severity_filter, cooldown_seconds, delivery_channels) VALUES
    ('Critical Anomaly',   1, 'anomaly_critical',   'critical', 300,  '["ntfy"]'),
    ('Correlated Anomaly', 1, 'anomaly_correlated',  'critical', 300,  '["ntfy"]'),
    ('New Unknown Device', 1, 'device_new',           NULL,      3600, '["ntfy"]'),
    ('Flagged Device',     1, 'device_flagged',       NULL,      300,  '["ntfy"]'),
    ('Port Violation',     1, 'port_violation',       NULL,      600,  '["ntfy"]');
```

Remaining default rules (for Phase 3 event types) are seeded in Phase 3.

## 6.6 Acceptance criteria for Phase 1
- alert tables and `alert_state_cache` initialize correctly on fresh start
- default rules and channel config rows seed correctly
- alert background task runs every 60 seconds
- ntfy live test fires and delivers
- cooldowns suppress repeated alerts correctly
- alert history records `channels_attempted` and `channels_succeeded`
- `device_flagged` does not fire on startup for already-flagged devices
- `device_new` does not fire for devices that existed before Phase 1 was deployed
- no existing anomaly logic changes

---

# 7. Phase 2 — Delivery Channels and Testability

## 7.1 Goal

Expand delivery capability and make channels independently testable before the rules UI exists.

## 7.2 Backend scope

### Webhook

```
POST {config.url}
Content-Type: application/json
X-Ion-Drift-Signature: sha256={hmac_hex}   (omit if secret is empty)

{
  "event_type": "...",
  "severity": "...",
  "title": "...",
  "body": "...",
  "device_mac": "...",
  "device_hostname": "...",
  "device_ip": "...",
  "vlan_id": 99,
  "vlan_name": "...",
  "fired_at": "2026-03-07T14:23:00Z",
  "anomaly_id": 142
}
```

HMAC signature: `HMAC-SHA256(secret, request_body_bytes)`, hex-encoded. Include header only if `config.secret` is non-empty. Timeout: 10 seconds. Cargo deps: `hmac = "0.12"`, `sha2 = "0.10"`, `hex = "0.4"` (check workspace before adding).

### SMTP

Use `lettre = { version = "0.11", features = ["smtp-transport", "tokio1-rustls-tls", "builder"] }` (check workspace before adding).

```
From: Ion Drift <{config.from}>
To: {config.to joined by ", "}
Subject: {title}
Content-Type: text/plain

{body}

--
Ion Drift Network Security
{fired_at}
```

Use STARTTLS on port 587, SSL on port 465. Retrieve password from encrypted secrets via key `smtp_password`. If the secret doesn't exist, log an error and skip delivery. Timeout: 15 seconds.

### Channel test routes

`POST /api/alerts/channels/{channel}/test` sends:
```
title: "Ion Drift — Test Alert"
body:  "This is a test notification from Ion Drift. If you received this, your {channel} delivery channel is configured correctly."
```
Returns `{"success": true}` or `{"success": false, "error": "..."}`. Works independently of whether any rules are enabled.

## 7.3 API scope in Phase 2

Implement:
- `GET /api/alerts/channels` — returns config for all three channels; password fields are **never** returned
- `PUT /api/alerts/channels/{channel}` — update config; for SMTP, if `password` field present, encrypt and store; if absent, leave existing password unchanged
- `POST /api/alerts/channels/{channel}/test`

## 7.4 Settings UI scope in Phase 2

Build only the **Delivery Channels** card in Settings > Alerts.

**Auto-save behavior:** Auto-save on field blur, matching the existing VLAN config section pattern. Show a momentary "Saved" indicator after successful save. This is consistent with the rest of Settings and requires no special UX affordance.

**ntfy section:**
- Enable toggle
- Server URL field (default `https://ntfy.sh`, supports self-hosted)
- Topic field
- Token field (password input, optional)
- "Send Test" button → calls `POST /api/alerts/channels/ntfy/test`, shows ✅ or ❌ inline

**Webhook section:**
- Enable toggle
- URL field
- Secret field (password input, optional)
- "Send Test" button

**SMTP section:**
- Enable toggle
- Host, Port (number input), Username, From fields
- To field (comma-separated addresses, stored as JSON array)
- Password field (password input — write-only, never pre-populated from server response)
- "Send Test" button

Hook: `useAlertChannels()` → `GET /api/alerts/channels`, `refetchInterval: none`. `useUpdateChannel()` → mutation → `PUT /api/alerts/channels/{channel}`, `onSuccess: invalidate useAlertChannels`. `useTestChannel()` → mutation → `POST /api/alerts/channels/{channel}/test`, returns `{ success, error? }`.

## 7.5 Acceptance criteria for Phase 2
- all three channels can be configured and saved
- password fields are never populated from server response
- all three test routes fire successfully with valid config
- failures return actionable error messages
- settings channel card auto-saves consistently with the rest of Settings

---

# 8. Phase 3 — Rules, History, and Settings UX

## 8.1 Goal

Full operator control over alert rules and a complete Settings > Alerts management experience. Adds three additional event types including the infrastructure transition events.

## 8.2 Backend scope

### Additional event types in Phase 3

| Event Type | Source | Trigger Condition |
|---|---|---|
| `anomaly_warning` | `behavior.db → anomalies` | New row with `severity = 'warning'` and `id > last_seen_id` |
| `interface_down` | Router interface poll | Transition: `running = true → false` (via `alert_state_cache` key `interface:{name}`) |
| `device_offline` | `secrets.db → devices` | Transition: `status = 'online' → 'offline'` (via `alert_state_cache` key `device:{id}`) |

**interface_down implementation:** On each engine cycle, fetch the current interface list from the router polling data already in AppState (do not issue a new API call). For each interface, look up `alert_state_cache` key `interface:{name}`. If cached value was `running` and current value is `not_running`, fire `interface_down`. Also log an `interface_up` info event to `alert_history` (severity `info`, no alert delivery by default) on the reverse transition. After evaluation, upsert cache with current running state.

**device_offline implementation:** On each engine cycle, read `devices.status` from `secrets.db`. For each device, look up `alert_state_cache` key `device:{id}`. Fire `device_offline` on `online → offline` transition. After evaluation, upsert cache.

### Additional payload templates

```
anomaly_warning:
  title: "🟡 Warning — {device_hostname}"
  body:  "{anomaly_type} on {device_hostname} ({ip}) [VLAN {vlan_name}]: {anomaly_details}."

interface_down:
  title: "⚠️ Interface Down — {interface_name}"
  body:  "Router interface {interface_name} is no longer running. Check physical connection or RouterOS interface status."

device_offline:
  title: "⚠️ Device Offline — {device_name}"
  body:  "Registered device {device_name} ({host}) is not responding. Last seen: {last_seen}."
```

### Rule CRUD

Implement:
- `POST /api/alerts/rules` — create rule
- `PUT /api/alerts/rules/{id}` — update (name, enabled, severity_filter, vlan_filter, disposition_filter, cooldown_seconds, delivery_channels)
- `DELETE /api/alerts/rules/{id}` — delete (non-default rules only — enforce in handler)

### Additional default rules seeded in Phase 3

```sql
INSERT INTO alert_rules (name, enabled, event_type, severity_filter, cooldown_seconds, delivery_channels) VALUES
    ('Warning Anomaly',             1, 'anomaly_warning',  'warning', 600,  '["ntfy"]'),
    ('Interface Down',              1, 'interface_down',    NULL,     300,  '["ntfy"]'),
    ('Registered Device Offline',   1, 'device_offline',    NULL,     300,  '["ntfy"]');
```

### Alert history pagination

Ensure the history endpoint supports `limit` and `offset` parameters and returns rows newest first. Response shape must include the full `body` field so the frontend row-expansion works without a separate detail call.

## 8.3 Frontend scope

### Alert Rules card

A table of all alert rules. Columns: Name, Event Type, Severity Filter, Cooldown, Channels, Enabled.

- Enable/disable toggle per rule — immediate `PUT` on toggle
- Edit button → inline row editing for: name, cooldown, severity filter, delivery channels (multi-select checkboxes: ntfy, webhook, smtp)
- VLAN filter and disposition filter fields are included if implementation cost is low; if not, they are deferred to Phase 4 as a controlled expansion
- Delete button with confirmation for non-default rules
- "Add Rule" button → inline new row

Auto-save on blur for inline fields. No modal dialogs. Pattern matches Backbone Links page inline editing.

Hooks: `useAlertRules()` → `GET /api/alerts/rules`, `refetchInterval: none`. `useUpdateRule()` → `PUT /api/alerts/rules/{id}`, `onSuccess: invalidate useAlertRules`. `useCreateRule()` → `POST /api/alerts/rules`, `onSuccess: invalidate useAlertRules`. `useDeleteRule()` → `DELETE /api/alerts/rules/{id}`, `onSuccess: invalidate useAlertRules`.

### Alert History card

Columns: Time, Rule Name, Event Type, Severity, Device, Title, Channels (icons), Status (✅ / ❌).

- Default: last 50 alerts
- Click row to expand and show full body
- "Clear History" button with confirmation
- Auto-refresh via TanStack Query (30s interval)

Hook: `useAlertHistory(limit?: number)` → `GET /api/alerts/history?limit={limit ?? 50}`, `refetchInterval: 30_000`. `useDeleteAlertHistory()` → `DELETE /api/alerts/history`, `onSuccess: invalidate useAlertHistory`.

## 8.4 Acceptance criteria for Phase 3
- rules can be created, edited, and deleted (non-default only)
- rule changes take effect on the next engine cycle
- interface down and device offline transitions alert correctly
- existing Phase 1 events unaffected
- history table renders, expands rows, clears correctly
- settings page remains coherent with all three cards present

---

# 9. Phase 4 — Global Alert UX and Secondary Event Expansion

## 9.1 Goal

Complete the operator-facing alert experience and add the two remaining infrastructure-heavy event types.

## 9.2 Backend scope

### Additional event types in Phase 4

| Event Type | Source | Trigger Condition |
|---|---|---|
| `dhcp_pool_exhausted` | Router DHCP poll | Any DHCP pool utilization exceeds 90% |
| `firewall_drop_spike` | `metrics.db → drop_metrics` | Drop rate in latest sample is >3x the 1-hour rolling average |

These are intentionally deferred because they depend on threshold interpretation that should be validated against live data before shipping. If either telemetry source proves unreliable or spammy during testing, the threshold should be tuned before the event type is enabled in the default rules.

**dhcp_pool_exhausted implementation:** Subject key is `dhcp:{pool_name}`. Cooldown default 3600s to prevent repeated alerts for a pool that stays near capacity.

**firewall_drop_spike implementation:** Subject key is `system:firewall_drop_spike`. Compare the most recent `drop_metrics` sample against the average of the prior 60 samples (1 hour at 60s interval). Fire if `current_rate > 3 * avg_rate`. Only fire if `avg_rate > 0` (skip if no baseline exists yet).

### Additional payload templates

```
dhcp_pool_exhausted:
  title: "⚠️ DHCP Pool Near Exhaustion"
  body:  "DHCP pool '{pool_name}' is {utilization}% full ({used}/{total} leases). Action required."

firewall_drop_spike:
  title: "🔴 Firewall Drop Spike"
  body:  "Firewall drop rate is {current_rate}/min, {multiplier}x above the 1-hour average of {avg_rate}/min."
```

### Additional default rules seeded in Phase 4

```sql
INSERT INTO alert_rules (name, enabled, event_type, severity_filter, cooldown_seconds, delivery_channels) VALUES
    ('DHCP Pool Exhaustion', 1, 'dhcp_pool_exhausted',  NULL, 3600, '["ntfy"]'),
    ('Firewall Drop Spike',  1, 'firewall_drop_spike',   NULL, 600,  '["ntfy"]');
```

### Status endpoint expansion

Add to `GET /api/alerts/status` response:
- `unread_count_24h` — count of `alert_history` rows where `fired_at > datetime('now', '-24 hours')` (used by bell badge)
- `last_check_at` — timestamp of last engine cycle
- `enabled_rule_count`

## 9.3 Frontend scope

### Alert Bell

Add a bell icon to the top navigation bar.

- Badge: count of alerts fired in last 24 hours that have not been acknowledged
- Badge logic: `unread_count_24h` from `GET /api/alerts/status`, compared against `last_read_timestamp` stored in localStorage
- Poll `GET /api/alerts/status` every 60 seconds for badge count
- Click → slide-in panel from the right showing last 20 alerts from `alert_history`, newest first
- Each alert shows: severity icon, title, device name, time ago
- "Mark All Read" button — stores current timestamp as `last_read_timestamp` in localStorage, clears badge
- "View All" link → scrolls to Alert History card in Settings

**localStorage note:** Unread state is intentionally client-local. The badge resets if the user switches browsers or clears localStorage. This is an acceptable tradeoff for this feature scope and avoids a server-side acknowledgements table. Document this behavior in Settings > Alerts section as a tooltip or helper text: "Unread state is tracked per browser."

### Advanced filters (if deferred from Phase 3)

If Phase 3 omitted VLAN filter or disposition filter fields from the rules table, add them now.

## 9.4 Acceptance criteria for Phase 4
- bell badge updates correctly on each 60s poll
- slide-in panel renders last 20 alerts with correct severity icons and timestamps
- mark-all-read clears the badge
- DHCP and drop-spike events fire correctly when telemetry source is present and stable
- no existing alert functionality regresses

---

# 10. Shared Event Source Reference

## Authoritative source per event type

| Phase | Event Type | Source |
|---|---|---|
| 1 | `anomaly_critical` | `behavior.db → anomalies` |
| 1 | `anomaly_correlated` | `connections.db → anomaly_links` |
| 1 | `device_new` | `switch.db → network_identities` |
| 1 | `device_flagged` | `switch.db → network_identities` (transition via `alert_state_cache`) |
| 1 | `port_violation` | `switch.db → port_violations` |
| 3 | `anomaly_warning` | `behavior.db → anomalies` |
| 3 | `interface_down` | Router interface poll (transition via `alert_state_cache`) |
| 3 | `device_offline` | `secrets.db → devices` (transition via `alert_state_cache`) |
| 4 | `dhcp_pool_exhausted` | Router DHCP poll |
| 4 | `firewall_drop_spike` | `metrics.db → drop_metrics` |

**Hard rule:** No event type should be implemented by approximating logic that the system does not already reliably produce. If a telemetry source is not trustworthy, defer the event.

---

# 11. Shared Payload Construction Guidance

Implement templates as code-side formatting helpers, not a dynamic template editor. Severity normalizes to `critical`, `warning`, or `info` and drives:
- title icon (🔴 / 🟡 / ⚠️)
- ntfy priority (5 / 3 / 1)
- badge treatment in the alert bell
- severity column presentation in history table

---

# 12. Shared UX Rules

1. alert settings must be understandable without reading docs
2. test buttons must provide clear pass/fail feedback inline
3. history should be easy to scan first, expand second
4. badge counts must remain lightweight (single status endpoint, 60s poll)
5. delivery configuration must not expose secrets after save — password fields are always blank on load
6. alerting must feel like an operator feature, not a workflow builder
7. auto-save on blur throughout, consistent with the rest of Settings

---

# 13. What Not to Build in Any Phase

- PagerDuty / OpsGenie / incident platform integrations
- escalation chains or on-call scheduling
- SMS integrations
- browser native notifications or in-app sounds
- alert remediation actions (Ion Arc territory)
- server-side per-user acknowledgement state
- custom notification template editor

---

# 14. Recommended Implementation Order

## Phase 1
- all four tables + `alert_state_cache`
- ntfy delivery
- background task
- cooldown logic
- five initial event types
- `GET /api/alerts/rules`, status, history basics

## Phase 2
- webhook delivery
- SMTP delivery
- test routes
- channel settings card (auto-save on blur)
- `GET/PUT /api/alerts/channels`

## Phase 3
- rule CRUD routes
- alert rules UI card (inline editing)
- alert history UI card (row expansion, clear)
- interface/device transition trackers
- warning + offline event types
- additional default rules

## Phase 4
- alert bell + slide-in panel + mark-all-read
- `unread_count_24h` in status endpoint
- DHCP / drop-spike event types
- advanced filters if deferred from Phase 3

---

# 15. Risk Register

## Risk: alert spam from unstable event detection
Mitigation: cooldown enforcement, phased event rollout, highest-confidence events first.

## Risk: SMTP complexity delays the whole feature
Mitigation: isolated to Phase 2. ntfy is first-class and usable from Phase 1.

## Risk: device_flagged fires on every cycle for already-flagged devices
Mitigation: `alert_state_cache` transition model (Section 5.5) ensures alerts fire only on the edge, not on the steady state. Explicit acceptance criterion in Phase 1.

## Risk: device_new fires for devices that predated Phase 1 deployment
Mitigation: on first engine run, populate `alert_state_cache` with all current identity MACs under a `device_new:last_scan` timestamp equal to now, so existing devices are not treated as new. Alternatively, simply set `last_seen_id` for new identity tracking to the current max `id` on first run.

## Risk: interface_down and device_offline state trackers fire on engine restart
Mitigation: `alert_state_cache` persistence in SQLite (not AppState memory) means state survives restarts. On restart, the engine reads prior state from the table and only fires on genuine transitions.

## Risk: unread state resets on browser/localStorage clear
Mitigation: explicitly documented behavior. Acceptable tradeoff for this scope. Server-side acknowledgements table deferred intentionally.

## Risk: settings UX becomes inconsistent with rest of app
Mitigation: auto-save on blur throughout, matching VLAN config section. No Save buttons introduced.

## Risk: DHCP/drop events depend on unstable thresholds
Mitigation: deferred to Phase 4. Gate on verified source reliability before enabling default rules.

---

# 16. Shared Build and Validation Checklist

## Phase 1
- `cargo build` passes, zero errors
- `cd web && npm run build` passes, zero TypeScript errors
- ntfy live test works
- alert fires on real or seeded qualifying event
- cooldown suppresses repeat correctly
- `device_flagged` does not fire on startup for pre-existing flagged devices
- history records `channels_attempted` / `channels_succeeded`

## Phase 2
- webhook test works with and without HMAC secret
- SMTP test works with STARTTLS
- password never returned from `GET /api/alerts/channels`
- channel configs auto-save correctly on blur

## Phase 3
- rules can be created, edited, deleted
- rule changes affect live firing on next cycle
- history UI renders, expands, clears
- interface down and device offline fire on transition only (not on restart)
- settings page remains coherent

## Phase 4
- bell badge updates on 60s poll
- mark-all-read clears badge
- DHCP and drop-spike events fire correctly
- no regressions across Phases 1–3

---

# 17. Commit Structure

Each phase ships as its own commit on a dedicated branch, reviewed by CC before merge to main. Suggested branch names: `feat/alerting-p1`, `feat/alerting-p2`, `feat/alerting-p3`, `feat/alerting-p4`.

Example commit message for Phase 1:

```
feat: alerting engine phase 1 — core engine, ntfy, 5 event types

- New tables: alert_rules, alert_delivery_config, alert_history,
  alert_cooldowns, alert_state_cache (switch.db)
- Background task (60s interval, 30s startup delay)
- Event types: anomaly_critical, anomaly_correlated, device_new,
  device_flagged, port_violation
- Transition detection via alert_state_cache (device_flagged)
- ntfy delivery with priority mapping
- Cooldown enforcement per (rule_id, subject)
- Default rules seeded for Phase 1 event types
- API: GET /api/alerts/rules, /api/alerts/status, /api/alerts/history,
  DELETE /api/alerts/history
- No changes to behavioral engine, anomaly pipeline, or other features
```
