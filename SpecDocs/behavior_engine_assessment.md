
# Ion Drift Behavior Engine — Opinionated Architectural Assessment

> Source reviewed: `behavior-engine.md`

---

# Executive Summary

The behavior engine is **conceptually strong** and already shows the right architecture for a lightweight NDR-style behavioral system:

- per-device learning period
- baseline recomputation
- anomaly detection on top of learned behavior
- firewall drop enrichment
- cross-correlation with port-level context
- operator resolution workflow

This is not a toy design. It has real product legs.

That said, in its current form, the engine has **three major architectural weaknesses** that will limit trust and operational usefulness if left unchanged:

1. **Baseline promotion is tied to a 24-hour timer instead of wall-clock eligibility**
2. **Learning and baseline recomputation are too coarse-grained**
3. **Detection logic is still relatively brittle for real-world endpoint behavior**

My opinionated conclusion:

> The engine is good enough to be the core of Ion Drift’s behavioral story, but it is **not yet robust enough to be treated as a fully trustworthy alerting source without hardening**.

The good news is that this is not a rewrite problem. It is a **timing, baseline quality, and confidence model problem**.

---

# 1. What Is Strong

## 1.1 The overall architecture is right

The separation between:

- observation collection
- nightly maintenance
- anomaly correlation
- auto-classification

is the correct high-level design.

That gives you:
- clean mental boundaries
- easier troubleshooting
- future extensibility
- less coupling between ingestion and investigation

The engine reads like an actual product subsystem, not just a background cron job.

---

## 1.2 The baseline model is operationally understandable

The device baseline keys are sensible:

- protocol
- destination port
- destination subnet
- direction

That is a practical starting feature space. It is simple enough to compute cheaply and expressive enough to surface:
- new destinations
- new services
- new protocols
- volume spikes

That is exactly the right “first real version” for a behavioral engine.

---

## 1.3 The anomaly taxonomy is good

The current anomaly set is a strong baseline:

- `volume_spike`
- `new_port`
- `new_protocol`
- `new_destination`
- `blocked_attempt`

These are understandable to an operator and map cleanly to action.

You resisted the temptation to create overly clever anomaly types before the engine is mature. That was the right choice.

---

## 1.4 Cross-correlation is strategically important

The fact that device-level anomalies are not isolated from port-level anomalies is one of the best parts of the design.

That correlation layer is how Ion Drift starts moving from:
- “I noticed something weird”
to
- “I noticed something weird and another system agrees”

That is exactly how you build operator trust.

---

## 1.5 The resolution workflow is well thought out

The status model:

- pending
- accepted
- flagged
- dismissed
- auto_dismissed

is good.

Especially good is the fact that the operator can distinguish:
- confirmed expected
- confirmed suspicious
- not concerning

That is the beginning of a real human-in-the-loop learning system.

---

# 2. The Biggest Problems

## 2.1 Promotion tied to nightly maintenance is the biggest architectural flaw

This is the single most important issue in the document.

Right now baseline promotion effectively behaves like:

> “Device becomes baselined only when the maintenance timer happens to run after the learning window.”

That creates multiple bad outcomes:

- 7-day learning is not really 7 days; it is 7–8+ days
- server restarts can delay promotion indefinitely
- operator expectations and system behavior drift apart
- baselining quality becomes dependent on server uptime patterns rather than device evidence

This is not just inconvenient. It is an architectural correctness issue.

### Recommendation
Decouple **eligibility** from **maintenance schedule**.

A device should be promoted when:

- `learning_until <= now`
- and a usable minimum baseline has been computed

That can be checked every collection cycle or every hourly maintenance sweep. The baseline recomputation job can remain nightly, but promotion eligibility should not depend on a 24-hour sleep cycle.

### Strong recommendation
Replace:
- “promotion happens during nightly maintenance”

with:
- “promotion happens whenever the device becomes eligible and minimum baseline quality is satisfied”

This is the most important change I would make.

---

## 2.2 Baseline recomputation is too coarse and too delayed

Nightly recomputation is cheap and simple, but it is not responsive enough for a system that is otherwise collecting every 60 seconds.

This creates two problems:

1. the baseline lags current behavior too much
2. newly accepted expected behavior takes too long to become normal

That makes operator-confirmed learning too sluggish.

### Recommendation
Move to a **hybrid baseline schedule**:

- keep full recomputation daily
- add lightweight per-device recomputation or incremental update every 1–6 hours for active devices

This does not need to be expensive. Even an hourly rolling refresh for recently active baselined devices would materially improve quality.

---

## 2.3 The engine promotes empty baselines too easily

The document explicitly says empty baselines are valid.

That is operationally understandable, but it creates a dangerous mode:

- quiet device learns “nothing”
- becomes baselined
- first real traffic triggers multiple novelty anomalies

This may be acceptable for some VLANs, but it is not universally desirable.

### Recommendation
Add a **minimum evidence threshold for baseline maturity**.

For example, promotion should require one of:
- minimum total observation count
- minimum active days seen
- minimum distinct baseline entries
- or fallback classification as “sparse baseline”

### Better status model
Instead of only:
- `learning`
- `baselined`

consider:
- `learning`
- `sparse`
- `baselined`

A sparse device can still be monitored, but novelty anomalies should be treated more cautiously.

---

# 3. Detection Logic Weaknesses

## 3.1 Volume spike logic is too simple

Current rule:
- projected hourly bytes > baseline max × 3.0

This is a fine first rule, but it is brittle.

Problems:
- baseline max is sensitive to outliers
- no notion of variance
- no time-of-day sensitivity
- bursty but legitimate devices may flap
- quiet devices may look extreme too easily

### Recommendation
Move toward a confidence-aware spike model, not just a multiplier on max.

A practical next step:
- compare against both max and average
- require a minimum absolute byte threshold
- add a minimum observation count threshold before spike logic is trusted

Example:
- trigger only if projected hourly > max × 3
- and projected hourly > avg × 5
- and projected hourly > absolute floor (e.g. 5 MB/hr)

That will reduce noise.

---

## 3.2 New-destination logic is useful but can be noisy

`new_destination` is a high-value anomaly, but subnet-level novelty can still be noisy if:
- cloud providers shift IP ranges
- CDNs vary
- devices use rotating endpoints

### Recommendation
For external traffic, consider optional grouping by:
- ASN
- org
- or broader subnet family

Not instead of subnet, but as supporting context.

This would let the engine say:
- “new IP/subnet, but same org/asn” → lower confidence
- “new org/asn entirely” → higher confidence

That would be a major upgrade in usefulness.

---

## 3.3 No explicit confidence model

Right now the engine has:
- anomaly type
- severity
- description
- details

But no explicit **confidence score**.

That means:
- everything of the same severity feels equally credible
- UI and alerting cannot distinguish weak from strong signals
- operator trust depends too much on raw text and repeated experience

### Recommendation
Add a numeric confidence field, even if it starts simple.

Example contributors:
- baseline age
- observation count
- recurrence count
- correlation presence
- VLAN strictness
- whether the anomaly is first-seen vs repeated
- whether the device baseline is sparse

This would materially improve downstream alerting quality.

---

# 4. Data Model and Timing Concerns

## 4.1 Observation cadence is fine, but “hourly projection” is a blunt instrument

The 60-second sampling cadence is reasonable.

The issue is not cadence; it is that the engine converts one minute of behavior into one hour of projected behavior too aggressively.

That is a valid approximation, but it needs guardrails.

### Recommendation
For spike decisions, require persistence across:
- 2–3 consecutive recent windows
or
- a rolling 5-minute aggregate

This is a small change with a big benefit.

---

## 4.2 Restart sensitivity is too high

The document correctly calls out that restarts reset maintenance timing.

That means critical engine behaviors depend on process uptime rather than persisted schedule semantics.

### Recommendation
Persist scheduler metadata:
- last maintenance run timestamp
- last anomaly scan watermark
- last correlator pass
- last auto-classifier pass

Then on startup:
- determine what is overdue
- run immediately if needed

This is an important hardening step.

---

## 4.3 Dedup window is globally simple, but likely too rigid long-term

A one-hour dedup window is a fine starting point, but anomaly classes behave differently.

Examples:
- `blocked_attempt` may need shorter dedup if repeated rapidly from malware
- `new_destination` might be fine at 1 hour
- `volume_spike` might need persistence rather than pure dedup

### Recommendation
Eventually move dedup to per-anomaly-type configuration.

Not urgent, but worth planning.

---

# 5. Severity Model Review

## 5.1 VLAN-based severity is a strong idea

The tiered VLAN severity model is one of the better choices in the system.

It acknowledges a core truth:

> behavior that is normal on user VLANs may be suspicious on restricted VLANs

That is exactly right.

---

## 5.2 But severity is carrying too much weight

Currently severity encodes:
- anomaly class seriousness
- VLAN sensitivity
- practical priority

That is useful, but it compresses too many dimensions into one field.

### Recommendation
Keep severity, but add:
- confidence
- maybe `priority_reason` or structured metadata

This would let alerting later distinguish:
- critical + low confidence
- warning + very high confidence
- correlated + operator-important

Right now severity alone is doing too much.

---

# 6. API and UX Assessment

## 6.1 API shape is good

The API surfaces look sensible and aligned with operator workflows:
- overview
- alerts
- anomalies
- VLAN view
- device view
- correlation links

That is a good investigative shape.

---

## 6.2 Resolution semantics are strong, but learning loop is incomplete

The document hints that:
- accepted anomalies update baseline

That is the right direction, but it is not described as a formal feedback loop.

### Recommendation
Make the learning loop explicit:

- `accepted` should contribute to future expected behavior
- `dismissed` should suppress future operator noise but not necessarily teach the baseline
- `flagged` should harden future alerting priority for similar events

That would make the engine feel increasingly intelligent over time.

---

# 7. Most Important Architectural Recommendations

## Priority 1 — Decouple promotion from nightly maintenance
Do this first.

### Proposed change
Promotion eligibility should be evaluated on a short recurring cadence, not only in the 24-hour job.

### Result
- no indefinite delays from restarts
- 7-day learning means what it says
- more predictable operator experience

---

## Priority 2 — Add baseline maturity tiers
Replace the binary model with a more honest one.

### Proposed statuses
- `learning`
- `sparse`
- `baselined`

### Result
- fewer misleading novelty anomalies
- better trust in early post-learning behavior
- cleaner operator messaging

---

## Priority 3 — Add confidence scoring
Introduce a numeric confidence score on anomalies.

### Inputs
- baseline age
- baseline observation count
- anomaly recurrence
- VLAN strictness
- cross-correlation presence
- sparse-vs-mature baseline

### Result
- better UI prioritization
- better alerting
- better operator trust

---

## Priority 4 — Persist scheduler watermarks and maintenance timestamps
Make engine behavior resilient to restart patterns.

### Persist
- last maintenance run
- last anomaly ID processed
- last correlator pass
- last auto-classifier pass

### Result
- less timing drift
- less restart sensitivity
- more predictable operation

---

## Priority 5 — Improve spike logic with persistence and floors
Keep the current rule, but harden it.

### Add
- absolute byte floor
- minimum baseline evidence threshold
- 2–3 cycle persistence before firing

### Result
- less noise
- better trust in spike alerts

---

# 8. Recommended Near-Term Roadmap

## Phase 1 — Hardening
- decouple promotion from nightly maintenance
- persist maintenance watermarks
- add sparse baseline state
- add minimum baseline evidence threshold

## Phase 2 — Detection quality
- add confidence field
- improve volume spike logic
- add recurrence-aware anomaly context
- add baseline maturity context to API/UI

## Phase 3 — Enrichment and adaptation
- external destination confidence using ASN/org grouping
- explicit operator feedback loop into baseline handling
- per-anomaly-type dedup tuning

---

# 9. Final Opinionated Verdict

The behavior engine is **good architecture with one serious timing flaw and several expected first-generation detection weaknesses**.

My overall assessment:

- **Foundation quality:** strong
- **Operational maturity:** moderate
- **Alert-readiness today:** moderate, but not yet fully trustworthy
- **Rewrite needed:** no
- **Hardening needed:** yes, especially around promotion timing and baseline confidence

If I were building Ion Drift into a serious operator product, I would absolutely keep this engine and invest in it.

But I would not market it internally as:
> “fully reliable behavioral anomaly detection”

yet.

I would describe it more honestly as:
> **an effective first-generation behavioral detection engine that needs timing hardening and confidence modeling before it becomes a primary alerting authority**.

That is a very good place to be. It means the system is worth refining, not replacing.
