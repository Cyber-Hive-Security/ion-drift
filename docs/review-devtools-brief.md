# Ion Drift — Dev Console Follow-Up Review Brief

Thanks for the thorough UI review. For a follow-up pass, we'd like you to spend ~15 minutes with Chrome DevTools open while navigating the app. Here's exactly what to check and what we care about.

---

## 1. Network Tab (most important)

Open **Network tab** before logging in. Keep it open through login → dashboard → navigate a few pages → investigation drill-down.

### What to check

- **Auth flow**: On login, does the response body contain any sensitive data (passwords, tokens, secrets)? Session should be cookie-only — no JWT or token in response body.
- **Response sizes**: Are any API responses unusually large (>1MB)? Flag the endpoint and rough size. The topology and connection history endpoints are the most likely candidates.
- **Failed requests**: Any 4xx/5xx errors during normal navigation? Note the URL and status code.
- **Cache headers**: Click a few API responses (e.g., `/api/network/interfaces`, `/api/behavior/overview`). Do they have `Cache-Control` headers? We expect no browser caching on API responses.
- **Request headers**: On any mutation (POST/PUT/DELETE), check if a CSRF token header is sent. We use SameSite cookies instead — if you see no CSRF header, that's expected behavior, not a bug.
- **Polling frequency**: Several pages poll on intervals (10s, 30s, 60s). On the Dashboard, count how many requests fire in 30 seconds. If it's more than ~10, flag it — we may be over-polling.

### Known expected behavior
- `/api/network/connections` polls every 10s on the Connections page
- `/api/behavior/overview` polls every 30s
- `/health` is hit by the Docker healthcheck every 30s (ignore this)

---

## 2. Application Tab — Cookies

Navigate to **Application → Cookies → [your ion-drift URL]**.

### What to check

- **Session cookie name**: Should be `ion_drift_session`
- **HttpOnly flag**: Must be `true` (prevents JavaScript access)
- **Secure flag**: Should be `true` if accessed over HTTPS, `false` is acceptable over plain HTTP in a homelab context
- **SameSite**: Should be `Lax`
- **Path**: Should be `/`
- **Any other cookies**: Flag anything unexpected — there should be only one cookie

---

## 3. Application Tab — Local Storage / Session Storage / IndexedDB

### What to check

- **Is anything stored?** We don't intentionally use client-side storage. If you see keys in Local Storage, Session Storage, or IndexedDB, flag them with the key names and a sample of the values.
- **Sensitive data**: If any stored values contain IPs, MACs, hostnames, credentials, or session tokens, that's a finding.

---

## 4. Console Tab

Keep the **Console** open (filter to Errors and Warnings) while navigating through:
1. Dashboard
2. Topology (let it render fully)
3. World Map (zoom in/out, click a country)
4. Investigation → pick a VLAN → pick a device
5. Identity Manager (scroll through the table)
6. Settings → each tab

### What to check

- **React errors**: Any red errors mentioning "Cannot read property," "undefined is not a function," component stack traces
- **Unhandled promise rejections**: Usually means an API call failed without a catch
- **CSP violations**: Messages like "Refused to load script/style/image" — these indicate our Content Security Policy is blocking something that should be allowed (or correctly blocking something that shouldn't be there)
- **Deprecation warnings**: Note but low priority
- **Memory warnings**: If the console shows memory pressure warnings, especially on Topology or World Map

### Known expected behavior
- React StrictMode may log double-render warnings in development — ignore these
- A brief 401 on page load before session is established is expected

---

## 5. Performance (optional, if time permits)

Open **Performance tab**, click Record, navigate from Dashboard → Topology → World Map → back to Dashboard. Stop recording.

### What to check

- **Long tasks**: Any yellow/red blocks >100ms? Note which page/interaction triggered them.
- **Memory trend**: Does the memory line trend upward without coming back down? If you navigate away from Topology and memory doesn't drop, that's a D3 cleanup leak.
- **Bundle size**: In Network tab, filter by JS. What's the total transfer size of the initial page load? Flag if >2MB gzipped.

---

## What NOT to worry about

- Mixed content warnings if you're accessing over HTTP (expected in homelab)
- `favicon.ico` 404 (cosmetic)
- Slow responses from the router API (that's the Mikrotik, not us)
- Any `ws://` or WebSocket connection attempts (we don't use WebSockets — if you see them, it's a browser extension)

---

## Reporting format

For each finding, just note:
- **Where**: Page + DevTools tab
- **What**: The observation (screenshot or copy-paste appreciated)
- **Severity**: Your judgment — security concern / bug / performance / cosmetic
