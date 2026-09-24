# Advisory catalog — curation contract

This directory is the **bundled seed catalog**: the advisories Drift ships with. At startup the
loader reads every `*.json` here, then every `*.json` in the operator overlay directory under the
runtime data dir. Entries merge by `advisory_id`, and **the higher `catalog_version` wins** — that
is how an operator corrects or extends a shipped advisory without editing the image.

Nothing in this directory is compiled in. No CVE id and no detector name appears in a Rust literal;
the link between an advisory and the signals that evidence it lives only in the `signals` array
below and in the `advisory_signal` table it populates. Core stays module-agnostic, and a new
advisory is a JSON file, not a release.

## Rules

- **Original prose only.** Every `title`, `narrative` and `mitigations` string is written here, by
  us, from scratch. Do not paste vendor, CISA or NVD wording, and do not lightly reword it either —
  a close paraphrase is still a derivative. Read the sources, understand the mechanism, then explain
  it in your own words to the operator who has to act on it. This is a deliberate
  copyright-avoidance decision, not a style preference. Cite the sources by URL in `references` and
  nowhere else.
- **Write for the operator of the affected platform.** A mitigation should name the actual command,
  path or setting the reader will type. "Restrict management access" is not a mitigation;
  `/ip/service set api address=<mgmt-cidr>` is.
- **Every `signal_id` must already exist in `EMITTED_SIGNALS`** (`crates/ion-drift-web/src/advisory/signals.rs`).
  That constant is the complete set of signals core can actually emit. An entry naming anything else
  is rejected at load: the loader logs a warning, skips the file, keeps the last-known-good catalog,
  and marks the catalog **degraded**. Adding a signal to the catalog therefore comes *after* adding
  it to the registry, never before.
- **`no_fixed_release` is always set explicitly and is never inferred.** An empty `fixed_versions`
  means "we have not recorded a fixed version"; `no_fixed_release: true` means "the vendor has
  published no fix and we do not expect one". Those are different claims and the UI treats them
  differently — inferring the second from the first would tell operators to stop waiting for a
  patch that is in fact coming. Set both fields deliberately, every time.
- **`requires_surface_class` must be non-empty and known.** An entry with a missing or unrecognised
  class is rejected the same way an unknown signal is.
- **Catalog content is untrusted input.** It is third-party data by construction, including anything
  an operator drops into the overlay. The loader binds every value as a SQL parameter and fails soft
  on anything malformed. Keep it that way: a bad advisory file degrades the catalog, it never takes
  the process down.
- **`version_constraint` is `null` or a non-empty array of ranges.** Each range is an object with any of
  `start_including`, `start_excluding`, `end_including`, `end_excluding`, `exact` — the same shape the NVD
  feed produces, e.g. `[{"start_including": "7.0", "end_excluding": "7.24.2"}]`. A range may not combine
  `exact` with any start/end bound. Anything else (including the old `"< 7.16"` string form) is rejected
  at load and degrades the catalog. An advisory with a constraint raises a version finding on every
  device in range; one without a constraint raises only service-exposure and exploitation findings.

## Bumping `catalog_version`

`catalog_version` is a single integer per file, and it is what decides a merge conflict. Bump it by
one **whenever you change any advisory in the file** — new entry, corrected narrative, added
mitigation, revised severity. Leaving it flat while editing content means an operator overlay at the
same version may silently win or lose depending on load order, and a corrected shipped advisory may
never reach a deployment that already has the old one stored.

Set `generated_at` to the date of the edit (`YYYY-MM-DD`) in the same commit.

Operator overlays follow the same rule from the other side: to override a shipped advisory, copy the
entry into an overlay file with a `catalog_version` **higher** than the bundled one. To let a later
Drift release take the override back, drop the overlay file.

## Files

| File | Contents |
|------|----------|
| `mikrotik.json` | RouterOS / Cloud Hosted Router advisories. Currently CVE-2026-16347 (API brute-force exposure, no fixed release). |
