# v0.5.2a Release Smoke Test — Cowork Prompt

Use this prompt with Claude Cowork (browser-connected) after upgrading an
instance to the `0.5.2a` image. It exercises the upgrade path, the
security-hardening changes with visible UI surface, and the module registry
(shipping in a release for the first time).

---

## Prompt

You are smoke-testing Ion Drift v0.5.2a, a network monitoring tool, right
after an upgrade from a pre-0.5.2 version. Work through each test case in
order, recording what you observe. Take a screenshot at each step. Report
any deviation from the expected result — and also anything that merely
looks off (layout glitches, empty widgets that should have data, error
toasts).

### Test 1: Upgrade forced re-login (session hashing)

This release stores session tokens hashed, which invalidates every
pre-upgrade session on purpose.

1. Load the app root. **Expected:** you are NOT silently logged in — you
   land on the login page (any pre-upgrade session is invalid).
2. Log in with the provided credentials. **Expected:** login succeeds
   normally, no error, lands on the Dashboard.
3. **Record:** did anything about the login flow look different or broken?

### Test 2: Version surfaces (the v0.5.2a fix)

1. Navigate to **Settings → System**. Find the "About Ion Drift" card.
   **Expected:** Version shows `0.5.2a` — NOT a dash ("—"), NOT "dev".
2. Open a new browser tab directly to `<base-url>/health`.
   **Expected:** exactly `{"status":"ok"}` — no version field, no other
   keys. (The version must not be disclosed on this unauthenticated
   endpoint.)
3. **Record:** both observations with screenshots.

### Test 3: Login failure behavior (rate limiting / enumeration)

1. Log out. Attempt to log in with the real username and a WRONG password.
   **Expected:** a generic invalid-credentials error.
2. Attempt with a NONSENSE username and any password. **Expected:** the
   SAME generic error — nothing revealing whether the username exists.
3. Retry the wrong password ~6–8 times quickly. **Expected:** either the
   same generic error or an explicit rate-limit/too-many-attempts message —
   never a crash, hang, or 500 page.
4. Log back in correctly. **Expected:** succeeds (a few failures must not
   lock the real operator out permanently).

### Test 4: Module registry (first release with this feature)

1. Navigate to the module admin page (Settings area or sidebar — look for
   **Modules**). **Expected:** the page renders; if no modules are
   registered, a sensible empty state (not a spinner forever, not an error).
2. Open the module registration form. Submit it EMPTY. **Expected:** inline
   validation errors, no crash.
3. Fill a syntactically valid but unreachable URL (e.g.
   `http://192.0.2.1:9/module`) with plausible values elsewhere and submit.
   **Expected:** a clean, generic error (connection/registration failed) —
   no stack trace, no raw internal detail.
4. Navigate to the **Findings** page. **Expected:** renders with an empty
   state or real findings — no error.

### Test 5: Data-bearing pages regression sweep

Visit each page, wait for it to settle, screenshot, and note whether real
data appears and whether any error toast/console-visible failure shows:

1. **Dashboard** — cards populated, uptime card shows RouterOS version.
2. **Topology** — map renders devices/links.
3. **Connections** — table populates; open the **world map / geo view**:
   country data appears (validates the GeoIP database seeding).
4. **Policy** — policy list and any deviations render.
5. **Behavior** — overview loads.
6. **Statistics** — page renders (page-view tracking in this release
   returns 204s; confirm no error appears from that).

### Test 6: Mutating actions still work (CSRF guard tightened)

The CSRF guard now applies to every mutating request, including no-body
ones. These should all still work from the real UI:

1. Acknowledge (then un-acknowledge, if offered) an alert or finding —
   any harmless toggle available.
2. Change any innocuous setting and save; change it back.
   **Expected:** both round-trips succeed — a 403 here means the CSRF
   change broke a legitimate flow, which is a release blocker. Report it
   with the exact action taken.

### Test 7: Logout

1. Log out. **Expected:** returned to login page.
2. Press Back / revisit an app URL directly. **Expected:** no
   authenticated content renders; you are sent to login.

### Reporting

Summarize as a table: test #, PASS/FAIL/PARTIAL, one-line observation,
screenshot reference. List every anomaly separately at the end, however
minor.
