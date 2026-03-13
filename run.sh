#!/bin/bash
# Top-level orchestrator: boot a CVE environment and launch the Claude Code agent.
#
# Usage:
#   ./run.sh CVE-2017-6074                              # CVE Lab (cloud-init)
#   ./run.sh CVE-2023-0461_mitigation-6.1               # kernelCTF
#   AGENT=shell ./run.sh CVE-2017-7308                   # drop into shell instead of auto-run

set -euo pipefail

CVE_ID="${1:?Usage: $0 CVE-YYYY-NNNNN[_release]}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REGISTRY="$SCRIPT_DIR/cve-registry.json"
KERNEL_SRC_DIR="$HOME/kernel-src"

if [ ! -f "$REGISTRY" ]; then
    echo "ERROR: Registry not found: $REGISTRY"
    exit 1
fi

# Read CVE config from registry
CONFIG_JSON="$(python3 -c "
import json, sys
reg = json.load(open('$REGISTRY'))
if '$CVE_ID' not in reg:
    print('NOT_FOUND', file=sys.stderr)
    sys.exit(1)
import json as j
print(j.dumps(reg['$CVE_ID']))
" 2>/dev/null)" || {
    echo "ERROR: Unknown CVE: $CVE_ID"
    echo "Available CVEs (first 20):"
    python3 -c "import json; items=list(json.load(open('$REGISTRY')).items())[:20]; [print(f'  {k}  ({v.get(\"type\",\"\")})')for k,v in items]"
    exit 1
}

# Parse config fields
BOOT_MODE="$(echo "$CONFIG_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('boot_mode','cloud-init'))")"
SSH_PORT="$(echo "$CONFIG_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['ssh_port'])")"
SSH_USER="$(echo "$CONFIG_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['ssh_user'])")"
SSH_PASSWORD="$(echo "$CONFIG_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['ssh_password'])")"

# Mode-specific setup
KERNEL_SOURCE_URL=""
KERNEL_SOURCE_DIR=""
COMPOSE_EXTRA_FILES=""

if [ "$BOOT_MODE" = "kernelctf" ]; then
    RELEASE="$(echo "$CONFIG_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['release'])")"
    KERNEL_TAG="$(echo "$CONFIG_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('kernel_tag',''))")"
    COS_BUILD="$(echo "$CONFIG_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('cos_build',''))")"
    CVE_DIR="$(echo "$CONFIG_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('cve_dir',''))")"

    echo "=============================================="
    echo "  kernelCTF: $CVE_ID"
    echo "  Release   : $RELEASE"
    echo "  SSH       : ${SSH_USER}@127.0.0.1:${SSH_PORT}"
    if [ -n "$KERNEL_TAG" ]; then
        echo "  Kernel tag: $KERNEL_TAG"
    elif [ -n "$COS_BUILD" ]; then
        echo "  COS build : $COS_BUILD"
    fi
    echo "=============================================="

    # Prepare kernel source
    if [ -n "$KERNEL_TAG" ]; then
        # LTS / mitigation: checkout from linux-stable bare repo
        LINUX_STABLE="$KERNEL_SRC_DIR/linux-stable"
        if [ ! -d "$LINUX_STABLE" ]; then
            echo "ERROR: linux-stable repo not found at $LINUX_STABLE"
            echo "Run: cd kernelctf && ./setup.sh --kernel-src"
            exit 1
        fi
        WORKTREE="$KERNEL_SRC_DIR/worktrees/$KERNEL_TAG"
        if [ ! -d "$WORKTREE" ]; then
            echo "[*] Creating worktree for $KERNEL_TAG..."
            mkdir -p "$KERNEL_SRC_DIR/worktrees"
            git -C "$LINUX_STABLE" worktree add "$WORKTREE" "$KERNEL_TAG" 2>/dev/null || {
                echo "ERROR: Tag $KERNEL_TAG not found in linux-stable"
                echo "Try: cd $LINUX_STABLE && git fetch --all"
                exit 1
            }
        fi
        ln -sfn "$WORKTREE" "$KERNEL_SRC_DIR/active"
        echo "[+] Kernel source: $KERNEL_TAG -> $WORKTREE"

    elif [ -n "$COS_BUILD" ]; then
        # COS: download kernel-src.tar.gz if not cached
        COS_DIR="$KERNEL_SRC_DIR/cos/$COS_BUILD"
        if [ ! -d "$COS_DIR" ] || [ -z "$(ls -A "$COS_DIR" 2>/dev/null)" ]; then
            echo "[*] Downloading COS kernel source for build $COS_BUILD..."
            mkdir -p "$COS_DIR"
            COS_URL="https://storage.googleapis.com/cos-tools/$COS_BUILD/kernel-src.tar.gz"
            if ! wget --timeout=60 --tries=3 -c -q --show-progress \
                    -O "$COS_DIR/kernel-src.tar.gz" "$COS_URL"; then
                echo "ERROR: Failed to download COS kernel source"
                echo "URL: $COS_URL"
                rm -rf "$COS_DIR"
                exit 1
            fi
            echo "[*] Extracting..."
            tar -xzf "$COS_DIR/kernel-src.tar.gz" -C "$COS_DIR/"
            rm -f "$COS_DIR/kernel-src.tar.gz"
            echo "[+] COS kernel source cached at $COS_DIR"
        fi
        ln -sfn "$COS_DIR" "$KERNEL_SRC_DIR/active"
        echo "[+] Kernel source: COS $COS_BUILD -> $COS_DIR"
    fi

    BOOT_MODE="kernelctf"
    KERNEL_SRC_PATH="${KERNEL_SRC_DIR}/active"

else
    # cloud-init mode
    VM_SCRIPT="$(echo "$CONFIG_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['script'])")"
    KERNEL_SOURCE_URL="$(echo "$CONFIG_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('kernel_source_url',''))")"
    KERNEL_SOURCE_DIR="$(echo "$CONFIG_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('kernel_source_dir',''))")"

    echo "=============================================="
    echo "  CVE Lab: $CVE_ID"
    echo "  VM script : $VM_SCRIPT"
    echo "  SSH       : ${SSH_USER}@127.0.0.1:${SSH_PORT}"
    echo "  Kernel src: ${KERNEL_SOURCE_DIR:-none}"
    echo "=============================================="

    BOOT_MODE=""
    KERNEL_SRC_PATH=""
fi

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
cleanup() {
    echo "[*] Stopping VM controller (pid $CONTROLLER_PID)..."
    kill $CONTROLLER_PID 2>/dev/null
    wait $CONTROLLER_PID 2>/dev/null
}
trap cleanup EXIT

# 2. Build and launch Docker container
echo "[*] Building and launching agent container..."
cd "$SCRIPT_DIR/agent-container"

# Clean up any stale containers to prevent duplicate log output
docker compose down --remove-orphans 2>/dev/null || true

# Ensure log directory exists and is writable by container's agent user (UID 1000).
# Docker auto-creates bind-mount dirs as root:root, so fix ownership if needed.
LOG_DIR="$SCRIPT_DIR/agent-logs"
if [ -d "$LOG_DIR" ] && [ ! -w "$LOG_DIR" ]; then
    echo "[*] Fixing agent-logs ownership (requires sudo)..."
    sudo chown "$(id -u):$(id -g)" "$LOG_DIR" 2>/dev/null \
        || docker run --rm -v "$LOG_DIR":/d alpine chown "$(id -u):$(id -g)" /d \
        || { echo "ERROR: Cannot fix $LOG_DIR permissions. Run: sudo chown \$(id -u):\$(id -g) $LOG_DIR"; exit 1; }
fi
mkdir -p "$LOG_DIR" "$LOG_DIR/code"
chmod 777 "$LOG_DIR" "$LOG_DIR/code"

CVE_ID="$CVE_ID" \
CVE_ID_LOWER="$(echo "$CVE_ID" | tr '[:upper:]' '[:lower:]')" \
CVE_DIR="${CVE_DIR:-$CVE_ID}" \
VM_SSH_PORT="$SSH_PORT" \
VM_SSH_USER="$SSH_USER" \
VM_SSH_PASSWORD="$SSH_PASSWORD" \
KERNEL_SOURCE_URL="$KERNEL_SOURCE_URL" \
KERNEL_SOURCE_DIR="$KERNEL_SOURCE_DIR" \
BOOT_MODE="$BOOT_MODE" \
KERNEL_SRC_PATH="$KERNEL_SRC_PATH" \
AGENT="${AGENT:-}" \
docker compose up --build --force-recreate

# After agent exits, show session summary
echo ""
echo "=============================================="
echo "  Agent session complete: $CVE_ID"
echo "=============================================="
echo ""

# Find and display the latest log
LATEST_MD=$(ls -t "$LOG_DIR"/session_*.md 2>/dev/null | head -1)
if [ -n "$LATEST_MD" ]; then
    echo "  Session log:  $LATEST_MD"
    echo ""
    # Show the summary section from the Markdown log
    if grep -q "## Session Summary" "$LATEST_MD" 2>/dev/null; then
        echo "  --- Summary ---"
        sed -n '/## Session Summary/,$ p' "$LATEST_MD" | head -10 | sed 's/^/  /'
        echo ""
    fi
fi

# List code iterations
CODE_FILES=$(ls "$LOG_DIR/code"/*_v*.c 2>/dev/null)
if [ -n "$CODE_FILES" ]; then
    echo "  Code iterations:"
    for f in $CODE_FILES; do
        echo "    $(basename "$f")  ($(wc -l < "$f") lines)"
    done
    LATEST_CODE=$(ls -t "$LOG_DIR/code"/*_latest.c 2>/dev/null | head -1)
    if [ -n "$LATEST_CODE" ]; then
        echo ""
        echo "  Latest code: $LATEST_CODE"
    fi
    echo ""
fi

echo "  SSH:  ssh -p ${SSH_PORT} ${SSH_USER}@127.0.0.1"
echo "  Stop: pkill -f 'qemu.*hostfwd.*:${SSH_PORT}-'"
