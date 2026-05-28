#!/bin/bash
# Setup script — provisions the CTF lab environment on a fresh Linux VM

set -e

echo "[*] Setting up CTF Lab - Scenario 75"

# Create log directory
mkdir -p /opt/admin/logs
chmod 755 /opt/admin/logs
echo "[+] Log directory created at /opt/admin/logs"

# Run log injection
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "$SCRIPT_DIR/inject_logs.sh"
echo "[+] Attack logs injected"

# Make scripts executable
chmod +x "$SCRIPT_DIR"/*.sh
echo "[+] Scripts marked executable"

echo ""
echo "[*] Setup complete. Run the lab with:"
echo "    docker compose up --build -d"
echo ""
echo "[*] Access points:"
echo "    Web App  : http://localhost:3075"
echo "    SSH      : ssh analyst@localhost -p 2275  (password: blue_team_rocks)"
echo "    Logs     : /opt/admin/logs/"
