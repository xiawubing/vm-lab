#!/bin/bash
# Top-level orchestrator: boot a CVE environment and launch the Claude Code agent.
#
# Usage:
#   ./run.sh CVE-2017-6074
#   ./run.sh CVE-2022-0847
#   AGENT=shell ./run.sh CVE-2017-7308   # drop into shell instead of auto-run

set -euo pipefail

CVE_ID="${1:?Usage: $0 CVE-YYYY-NNNNN}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REGISTRY="$SCRIPT_DIR/cve-registry.json"

if [ ! -f "$REGISTRY" ]; then
    echo "ERROR: Registry not found: $REGISTRY"
    exit 1
fi

# Read CVE config from registry
if ! python3 -c "import json, sys; d=json.load(open('$REGISTRY')); sys.exit(0 if '$CVE_ID' in d else 1)" 2>/dev/null; then
    echo "ERROR: Unknown CVE: $CVE_ID"
    echo "Available CVEs:"
    python3 -c "import json; [print(f'  {k}  ({v[\"type\"]})') for k,v in json.load(open('$REGISTRY')).items()]"
    exit 1
fi

# Extract config fields
read -r SSH_PORT SSH_USER SSH_PASSWORD VM_SCRIPT KERNEL_SOURCE_URL KERNEL_SOURCE_DIR <<< \
    "$(python3 -c "
import json
c = json.load(open('$REGISTRY'))['$CVE_ID']
print(c['ssh_port'], c['ssh_user'], c['ssh_password'], c['script'],
      c.get('kernel_source_url',''), c.get('kernel_source_dir',''))
")"

echo "=============================================="
echo "  CVE Lab: $CVE_ID"
echo "  VM script : $VM_SCRIPT"
echo "  SSH       : ${SSH_USER}@127.0.0.1:${SSH_PORT}"
echo "  Kernel src: ${KERNEL_SOURCE_DIR:-none}"
echo "=============================================="

# 1. Start VM controller in background (kills any existing one first)
if pgrep -f "vm_controller.py" >/dev/null 2>&1; then
    echo "[*] Stopping existing VM controller..."
    pkill -f "vm_controller.py" || true
    sleep 1
fi

echo "[*] Starting VM controller for $CVE_ID..."
python3 "$SCRIPT_DIR/vm_controller.py" --cve "$CVE_ID" &
CONTROLLER_PID=$!
sleep 1

# Ensure controller gets cleaned up on exit
trap "echo '[*] Stopping VM controller (pid $CONTROLLER_PID)...'; kill $CONTROLLER_PID 2>/dev/null; wait $CONTROLLER_PID 2>/dev/null" EXIT

# 2. Build and launch Docker container
echo "[*] Building and launching agent container..."
cd "$SCRIPT_DIR/agent-container"

# Clean up any stale containers to prevent duplicate log output
docker compose down --remove-orphans 2>/dev/null || true

CVE_ID="$CVE_ID" \
CVE_ID_LOWER="$(echo "$CVE_ID" | tr '[:upper:]' '[:lower:]')" \
VM_SSH_PORT="$SSH_PORT" \
VM_SSH_USER="$SSH_USER" \
VM_SSH_PASSWORD="$SSH_PASSWORD" \
KERNEL_SOURCE_URL="$KERNEL_SOURCE_URL" \
KERNEL_SOURCE_DIR="$KERNEL_SOURCE_DIR" \
AGENT="${AGENT:-}" \
docker compose up --build --force-recreate

# After agent exits, offer manual access if VM is still running
echo ""
echo "[*] Agent finished. VM may still be running."
echo "    SSH in manually:  ssh -p ${SSH_PORT} ${SSH_USER}@127.0.0.1"
echo "    Stop VM:          pkill -f 'qemu.*hostfwd.*:${SSH_PORT}-'"
