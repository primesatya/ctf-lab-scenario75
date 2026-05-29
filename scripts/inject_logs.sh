#!/bin/bash
# Log injection script — generates simulated attack sequence logs
# for Blue Team forensics training

LOG_DIR="/opt/admin/logs"
mkdir -p "$LOG_DIR"

ACCESS_LOG="$LOG_DIR/access.log"
ERROR_LOG="$LOG_DIR/error.log"

# Clear existing logs
> "$ACCESS_LOG"
> "$ERROR_LOG"

DATE="[29/May/2026"
TZ="+0700]"

# --- access.log ---
# Baseline legitimate admin traffic from 192.168.1.100
cat >> "$ACCESS_LOG" << 'EOF'
192.168.1.100 - admin [29/May/2026:18:45:01 +0700] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.100 - admin [29/May/2026:18:45:30 +0700] "GET /dashboard HTTP/1.1" 200 2048 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.100 - admin [29/May/2026:18:46:10 +0700] "POST /api/feedback HTTP/1.1" 200 512 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.100 - admin [29/May/2026:18:47:55 +0700] "GET /dashboard HTTP/1.1" 200 2048 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
EOF

# Attacker recon phase — from 10.10.14.50
cat >> "$ACCESS_LOG" << 'EOF'
10.10.14.50 - - [29/May/2026:18:49:10 +0700] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (Kali Linux)"
10.10.14.50 - - [29/May/2026:18:49:22 +0700] "GET /robots.txt HTTP/1.1" 200 102 "-" "Mozilla/5.0 (Kali Linux)"
10.10.14.50 - - [29/May/2026:18:49:45 +0700] "GET /api/verify-mfa HTTP/1.1" 404 64 "-" "Mozilla/5.0 (Kali Linux)"
10.10.14.50 - - [29/May/2026:18:50:00 +0700] "GET /dashboard HTTP/1.1" 302 0 "-" "Mozilla/5.0 (Kali Linux)"
EOF

# Attacker WAF probe — script tag blocked at 18:50:15
cat >> "$ACCESS_LOG" << 'EOF'
10.10.14.50 - - [29/May/2026:18:50:15 +0700] "POST /api/feedback HTTP/1.1" 403 89 "-" "Mozilla/5.0 (Kali Linux)"
10.10.14.50 - - [29/May/2026:18:50:44 +0700] "POST /api/feedback HTTP/1.1" 403 89 "-" "Mozilla/5.0 (Kali Linux)"
EOF

# Attacker WAF bypass — SVG payload succeeds
cat >> "$ACCESS_LOG" << 'EOF'
10.10.14.50 - - [29/May/2026:18:51:10 +0700] "POST /api/feedback HTTP/1.1" 200 156 "-" "Mozilla/5.0 (Kali Linux)"
10.10.14.50 - - [29/May/2026:18:51:30 +0700] "POST /api/feedback HTTP/1.1" 200 156 "-" "Mozilla/5.0 (Kali Linux)"
EOF

# Attacker dashboard access with stolen cookie — 200 at 18:51:55
cat >> "$ACCESS_LOG" << 'EOF'
10.10.14.50 - - [29/May/2026:18:51:55 +0700] "GET /dashboard HTTP/1.1" 200 3072 "-" "Mozilla/5.0 (Kali Linux)"
EOF

# Cookie exfiltration — X-Forwarded-For contains Base64 encoded flag
cat >> "$ACCESS_LOG" << 'EOF'
10.10.14.50 - - [29/May/2026:18:52:10 +0700] "GET /collect?data=stolen HTTP/1.1" 200 0 "U0NFTkFSSU83NXtCTFVFX0wwR19IVW50M3JfTTRzdDN9" "Mozilla/5.0 (Kali Linux)" "X-Forwarded-For: U0NFTkFSSU83NXtCTFVFX0wwR19IVW50M3JfTTRzdDN9"
EOF

# More baseline traffic after attack
cat >> "$ACCESS_LOG" << 'EOF'
192.168.1.100 - admin [29/May/2026:18:55:00 +0700] "GET /dashboard HTTP/1.1" 200 2048 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
EOF

# --- error.log ---
# First WAF block — <script> tag at 18:50:15
cat >> "$ERROR_LOG" << 'EOF'
[29/May/2026:18:50:15 +0700] [WARN] WAF_BLOCK: Malicious payload detected from 10.10.14.50 — tag: <script> — endpoint: POST /api/feedback
[29/May/2026:18:50:44 +0700] [WARN] WAF_BLOCK: Malicious payload detected from 10.10.14.50 — tag: <script> — endpoint: POST /api/feedback
[29/May/2026:18:51:10 +0700] [INFO] WAF_PASS: Payload allowed from 10.10.14.50 — endpoint: POST /api/feedback
[29/May/2026:18:51:30 +0700] [INFO] WAF_PASS: Payload allowed from 10.10.14.50 — endpoint: POST /api/feedback
EOF

# Cookie reuse / session replay — CRITICAL level
cat >> "$ERROR_LOG" << 'EOF'
[29/May/2026:18:51:55 +0700] [CRITICAL] COOKIE_REUSE: Pre-auth session token replayed as admin session from 10.10.14.50 — cookie: adm_sess — MFA verification skipped
EOF

# Authentication bypass anomaly at 18:53:10
cat >> "$ERROR_LOG" << 'EOF'
[29/May/2026:18:53:10 +0700] [CRITICAL] Authentication bypass anomaly detected from 10.10.14.50 — session escalated without MFA completion — endpoint: GET /dashboard
EOF

echo "[+] Logs successfully injected into $LOG_DIR"
echo "[+] access.log: $(wc -l < $ACCESS_LOG) lines"
echo "[+] error.log:  $(wc -l < $ERROR_LOG) lines"
