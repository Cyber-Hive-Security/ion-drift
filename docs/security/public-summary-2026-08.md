# Security self-audit — public summary (August 2026)

*Draft for the README / docs site. Publish the summary and the disclosure policy; keep the detailed
finding list internal until the items marked "before distribution" are fixed.*

---

## Ion Drift security self-audit, August 2026

Ion Drift is written with AI assistance — 93% of its commits are co-authored by Claude Code. That is
worth saying plainly, because AI-assisted codebases have a reputation for a specific set of security
defects. So we audited Ion Drift against that exact list: the seven defects a dev-shop owner
reported finding in nearly every AI-built codebase they inspected.

**Five of the seven do not apply or were not found. One is not applicable to our architecture. One
we found, and it is the one no scanner catches.**

| Defect | Result |
|---|---|
| Secrets committed to the repo or exposed in the frontend | Not found — 547 commits scanned, clean under two rule sets |
| UI-only authorization (API answers anyone who calls it) | Not found — all 183 API routes reject unauthenticated calls |
| IDOR (user A reads user B's records) | Not applicable — Ion Drift is a single-tenant appliance |
| Absent error handling / no observability | Not found — 33 panic-capable calls in production code; background tasks are supervised and restart |
| Backups that have never been restore-tested | We restored one, end to end, as part of this audit |
| Payments trusting the client | Not applicable — there is no payment path; licensing is offline signature verification |
| Silent rewrites in code nobody reviews | **Found.** See below. |

### What we verified, and how

Not by reading the code and declaring it fine. Specifically:

- **Secrets:** `gitleaks` across the entire git history — twice, once with our config and once with
  default rules ignoring our own allowlist. No leaks, and no credential to rotate.
- **Authorization:** we booted a real instance and probed every one of its API routes without
  credentials. All 183 returned `401`. None returned data.
- **Sessions:** our docs claim a stolen session database can't be replayed because sessions are
  stored hashed. We tested the claim — the value the API exposes is the SHA-256 of the cookie token,
  and replaying it returns `401`.
- **First-run setup:** attempts to claim a fresh instance without the setup token, and with a wrong
  token, were both rejected and created no account.
- **Backups:** we took a backup, wiped the data directory, restored, and restarted. The admin account
  authenticated and encrypted secrets decrypted under the same key.

### What we found

The defect we did find is the seventh: **drift in code nobody is reviewing.** Our alerting engine and
advisory engine are well covered by tests. Our behaviour-baselining, correlation, and log-parsing
engines — several thousand lines that produce the analytics customers actually rely on — carry no
automated tests at all. Nothing there is known to be wrong. The point is that if something *became*
wrong, no test would fail and the output is statistical enough that a human might not notice.

We also found that the regression test guarding our admin-only endpoints only inspects about a third
of them, because of a limitation in how it parses the router. Every one of those endpoints is
correctly guarded today — we verified all 59 individually — but the test protecting them was weaker
than it looked.

Both are being fixed. We are publishing them because a security product that only reports its clean
results is not reporting.

### What this does and does not mean

This audit means those seven defect classes were checked against this codebase and the results are
written down. **It does not mean Ion Drift is secure.** It was performed by us, not by an
independent third party, and it was not a penetration test. It did not cover non-admin role
enforcement at runtime, device-interaction paths, or frontend XSS. Those limitations are stated in
full in the internal report, and we would rather say so than imply coverage we do not have.

If you find something we missed, our disclosure policy is in [SECURITY.md](../../SECURITY.md): report
it privately, we acknowledge within 72 hours, and we fix or coordinate disclosure within 30 days.
