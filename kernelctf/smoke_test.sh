#!/bin/bash
# smoke_test.sh — End-to-end smoke test for kernelCTF interactive mode.
#
# Automates the manual interactive workflow:
#   1. Compile exploit with run.sh's patching logic (source patch + shell_trap)
#   2. Boot interactive VM with a unique flag file (with retries)
#   3. Deploy compiled binaries to exp-interactive/ via 9p
#   4. Set up shell_trap via SSH
#   5. Run exploit via SSH
#   6. Verify flag appears in output (SSH or serial)
#
# Usage:
#   ./smoke_test.sh <cve-dir> [options]
#
# Options:
#   --timeout SECS          Total test timeout (default: 180)
#   --exploit-timeout SECS  Exploit execution timeout (default: 90)
#   --max-attempts N        Max retry attempts (default: 3)
#   --nokaslr               Disable KASLR for debugging
#   --skip-compile          Reuse existing exp/ binaries
#   --port PORT             SSH port (default: 2250)
#   --no-shell-trap         Skip shell_trap setup (rely on source patch only)
#
# Examples:
#   ./smoke_test.sh CVE-2024-0193_mitigation
#   ./smoke_test.sh CVE-2024-0193_mitigation --skip-compile --nokaslr

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNELCTF_POCS="/home/xia/security-research/pocs/linux/kernelctf"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*"; }

# --- Parse arguments ---

CVE_DIR=""
TIMEOUT=180
EXPLOIT_TIMEOUT=90
MAX_ATTEMPTS=3
NOKASLR=false
SKIP_COMPILE=false
SSH_PORT=2250
SETUP_SHELL_TRAP=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout)          TIMEOUT="$2"; shift 2 ;;
        --exploit-timeout)  EXPLOIT_TIMEOUT="$2"; shift 2 ;;
        --max-attempts)     MAX_ATTEMPTS="$2"; shift 2 ;;
        --nokaslr)          NOKASLR=true; shift ;;
        --skip-compile)     SKIP_COMPILE=true; shift ;;
        --port)             SSH_PORT="$2"; shift 2 ;;
        --no-shell-trap)    SETUP_SHELL_TRAP=false; shift ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)                  CVE_DIR="$1"; shift ;;
    esac
done

if [ -z "$CVE_DIR" ]; then
    echo "Usage: $0 <cve-dir> [options]"
    echo "Try --help for details."
    exit 1
fi

# --- Resolve CVE → release ---

CVE_PATH="$KERNELCTF_POCS/$CVE_DIR"
if [ ! -d "$CVE_PATH" ]; then
    err "CVE directory not found: $CVE_PATH"
    exit 1
fi

RELEASE_RAW=$(ls "$CVE_PATH/exploit/" 2>/dev/null | head -1)
if [ -z "$RELEASE_RAW" ]; then
    err "No exploit subdirectory found in $CVE_PATH/exploit/"
    exit 1
fi

RELEASE="$RELEASE_RAW"
[[ "$RELEASE" == "mitigation-6.1" ]] && RELEASE="mitigation-6.1-v2"
EXPLOIT_SRC="$CVE_PATH/exploit/$RELEASE_RAW"

# --- Common setup ---

mkdir -p "$SCRIPT_DIR/logs"
FLAG_FILE="$SCRIPT_DIR/logs/smoke_flag"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR -o ServerAliveInterval=5 -o ServerAliveCountMax=3"
VM_PID=""

stop_vm() {
    if [ -n "$VM_PID" ] && kill -0 "$VM_PID" 2>/dev/null; then
        kill "$VM_PID" 2>/dev/null
        wait "$VM_PID" 2>/dev/null || true
    fi
    VM_PID=""
}
trap stop_vm EXIT

echo ""
echo "========================================================"
echo -e "  ${CYAN}kernelCTF Interactive Smoke Test${NC}"
echo -e "  CVE:      ${GREEN}$CVE_DIR${NC}"
echo -e "  Release:  ${GREEN}$RELEASE${NC}"
echo -e "  Port:     ${GREEN}$SSH_PORT${NC}"
echo -e "  Attempts: ${GREEN}$MAX_ATTEMPTS${NC}"
echo "========================================================"
echo ""

# ==============================================================
# Step 1: Compile exploit (reuse run.sh's patching logic)
# ==============================================================

if ! $SKIP_COMPILE; then
    info "=== Step 1: Compiling exploit ==="

    rm -rf "$SCRIPT_DIR/exp"
    mkdir -p "$SCRIPT_DIR/exp"

    # Copy source files (exclude bzImage and pre-compiled exploit binary)
    for f in "$EXPLOIT_SRC"/*; do
        fname="$(basename "$f")"
        [ "$fname" = "bzImage" ] && continue
        [ "$fname" = "exploit" ] && continue
        cp -a "$f" "$SCRIPT_DIR/exp/" 2>/dev/null || true
    done

    # keyutils.h stub (syscall-based, no libkeyutils-dev needed)
    if [ ! -f "$SCRIPT_DIR/exp/keyutils.h" ]; then
        cat > "$SCRIPT_DIR/exp/keyutils.h" << 'KEYUTILS_EOF'
#ifndef _KEYUTILS_H
#define _KEYUTILS_H
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
typedef int32_t key_serial_t;
#define KEY_SPEC_PROCESS_KEYRING -2
#define KEYCTL_REVOKE 3
#define KEYCTL_READ 11
#define KEYCTL_UNLINK 9
static inline key_serial_t add_key(const char *type, const char *description,
    const void *payload, size_t plen, key_serial_t ringid) {
    return (key_serial_t)syscall(__NR_add_key, type, description, payload, plen, ringid);
}
static inline long keyctl_read(key_serial_t key, char *buffer, size_t buflen) {
    return syscall(__NR_keyctl, KEYCTL_READ, key, buffer, buflen);
}
static inline long keyctl_revoke(key_serial_t key) {
    return syscall(__NR_keyctl, KEYCTL_REVOKE, key);
}
static inline long keyctl_unlink(key_serial_t key, key_serial_t ringid) {
    return syscall(__NR_keyctl, KEYCTL_UNLINK, key, ringid);
}
#endif
KEYUTILS_EOF
    fi

    # CBQ compatibility header
    if [ -f "$SCRIPT_DIR/exp/exploit.c" ] && ! grep -q "cbq_compat.h" "$SCRIPT_DIR/exp/exploit.c"; then
        cp "$SCRIPT_DIR/patches/cbq_compat.h" "$SCRIPT_DIR/exp/"
        sed -i 's|#include "netlink_utils.h"|#include "cbq_compat.h"\n#include "netlink_utils.h"|' "$SCRIPT_DIR/exp/exploit.c"
    fi

    # Source patching: shell spawn → flag read
    if [ -f "$SCRIPT_DIR/exp/exploit.c" ] && grep -qE 'exec[lv][ep]?\s*\(.*(/bin/(ba)?sh|"(ba)?sh")|/bin/(ba)?sh|system\s*\(.*(/bin/sh|cat.*/flag)' "$SCRIPT_DIR/exp/exploit.c"; then
        info "Patching shell-spawning function to read flag..."
        python3 "$SCRIPT_DIR/patches/patch_shell_spawn.py" "$SCRIPT_DIR/exp/exploit.c" 2>&1 || true
    fi

    # Compile
    COMPILED=false
    cd "$SCRIPT_DIR/exp"
    if [ -f Makefile ]; then
        info "Makefile detected — building..."
        if timeout 120 make exploit </dev/null 2>&1; then
            COMPILED=true
            ok "Makefile compilation succeeded"
        else
            warn "Makefile compilation failed"
            # Try with prerequisites (download + build libmnl/libnftnl)
            if grep -q '^prerequisites\|^libnftnl-build\|^libmnl-build' Makefile 2>/dev/null && [ ! -f exploit ]; then
                info "Building prerequisites + exploit..."
                if timeout 180 make prerequisites </dev/null 2>&1 && timeout 120 make exploit </dev/null 2>&1; then
                    COMPILED=true
                    ok "Compilation with prerequisites succeeded"
                else
                    warn "Compilation with prerequisites also failed"
                fi
            fi
            # Fallback: simple gcc
            if [ -f exploit.c ] && [ ! -f exploit ]; then
                info "Trying fallback gcc compilation..."
                C_FILES=$(ls *.c 2>/dev/null | tr '\n' ' ')
                if gcc -I. -D_GNU_SOURCE -o exploit $C_FILES -O0 -static -lpthread 2>&1; then
                    COMPILED=true
                    ok "Fallback compilation succeeded"
                fi
            fi
        fi
    elif [ -f exploit.c ]; then
        if gcc -I. -D_GNU_SOURCE -o exploit exploit.c -O0 -static -s 2>&1; then
            COMPILED=true
            ok "Compilation succeeded"
        fi
    fi
    cd "$SCRIPT_DIR"

    # Use pre-compiled binary as last resort
    if [ ! -f "$SCRIPT_DIR/exp/exploit" ]; then
        if [ -f "$EXPLOIT_SRC/exploit" ]; then
            info "Using pre-compiled binary from repo"
            cp "$EXPLOIT_SRC/exploit" "$SCRIPT_DIR/exp/exploit"
        else
            err "No exploit binary available"
            exit 1
        fi
    fi
    chmod +x "$SCRIPT_DIR/exp/exploit"
    ok "Exploit: $(file "$SCRIPT_DIR/exp/exploit" | cut -d: -f2 | xargs)"

    # Compile shell_trap
    if gcc -static -O0 -o "$SCRIPT_DIR/exp/shell_trap" "$SCRIPT_DIR/patches/shell_trap.c" 2>&1; then
        chmod +x "$SCRIPT_DIR/exp/shell_trap"
        ok "shell_trap compiled"
    else
        warn "shell_trap compilation failed"
    fi
else
    info "=== Step 1: Skipping compilation (--skip-compile) ==="
    if [ ! -f "$SCRIPT_DIR/exp/exploit" ]; then
        err "No compiled exploit in exp/. Run without --skip-compile."
        exit 1
    fi
    ok "Using existing exp/ binaries"
fi

# ==============================================================
# Retry loop: Steps 2-6 (boot VM, deploy, exploit, verify)
# ==============================================================

FOUND=false
ATTEMPT=0
TOTAL_START=$(date +%s)

while [ "$ATTEMPT" -lt "$MAX_ATTEMPTS" ] && ! $FOUND; do
    ATTEMPT=$((ATTEMPT + 1))

    info "========== Attempt $ATTEMPT/$MAX_ATTEMPTS =========="

    # --- Step 2: Create fresh flag ---
    FLAG="kernelCTF{smoke-$(date +%s)-$(head -c 4 /dev/urandom | xxd -p)}"
    echo -n "$FLAG" > "$FLAG_FILE"
    info "Flag: $FLAG"

    SERIAL_LOG="$SCRIPT_DIR/logs/smoke_serial_${ATTEMPT}_$(date +%s).txt"
    EXPLOIT_LOG="$SCRIPT_DIR/logs/smoke_exploit_${ATTEMPT}_$(date +%s).txt"

    # --- Step 3: Boot interactive VM ---
    info "Booting VM..."

    # Kill any leftover QEMU using our SSH port
    if ss -tlnp 2>/dev/null | grep -q ":${SSH_PORT} "; then
        warn "Port $SSH_PORT in use, freeing..."
        LISTEN_PID=$(ss -tlnp 2>/dev/null | grep ":${SSH_PORT} " | grep -oP 'pid=\K[0-9]+' | head -1)
        if [ -n "$LISTEN_PID" ]; then
            kill "$LISTEN_PID" 2>/dev/null || true
            sleep 2
        fi
    fi

    INTERACTIVE_ARGS=("$CVE_DIR" --flag "$FLAG_FILE" --reset --port "$SSH_PORT")
    $NOKASLR && INTERACTIVE_ARGS+=(--nokaslr)

    "$SCRIPT_DIR/interactive.sh" "${INTERACTIVE_ARGS[@]}" > "$SERIAL_LOG" 2>&1 &
    VM_PID=$!
    sleep 3

    if ! kill -0 "$VM_PID" 2>/dev/null; then
        err "VM failed to start"
        tail -10 "$SERIAL_LOG" 2>/dev/null
        continue
    fi
    ok "VM started (PID $VM_PID)"

    # --- Step 4: Deploy compiled binaries via 9p ---
    # interactive.sh already copied RAW source to exp-interactive/.
    # Now overwrite with compiled+patched binaries (9p = instant visibility in VM).
    cp "$SCRIPT_DIR/exp/exploit" "$SCRIPT_DIR/exp-interactive/exploit"
    chmod +x "$SCRIPT_DIR/exp-interactive/exploit"
    if [ -f "$SCRIPT_DIR/exp/shell_trap" ]; then
        cp "$SCRIPT_DIR/exp/shell_trap" "$SCRIPT_DIR/exp-interactive/shell_trap"
        chmod +x "$SCRIPT_DIR/exp-interactive/shell_trap"
    fi
    ok "Binaries deployed to exp-interactive/"

    # --- Step 5: Wait for SSH ---
    info "Waiting for SSH..."
    MAX_SSH_WAIT=90
    ELAPSED=0
    SSH_OK=false

    while [ $ELAPSED -lt $MAX_SSH_WAIT ]; do
        if sshpass -p user ssh $SSH_OPTS -p "$SSH_PORT" user@127.0.0.1 true 2>/dev/null; then
            SSH_OK=true
            ok "SSH ready (${ELAPSED}s)"
            break
        fi
        if ! kill -0 "$VM_PID" 2>/dev/null; then
            err "VM died during boot"
            break
        fi
        sleep 2
        ELAPSED=$((ELAPSED + 2))
    done

    if ! $SSH_OK; then
        warn "SSH not available, skipping to next attempt"
        stop_vm
        continue
    fi

    # Verify exploit binary is visible in VM
    sshpass -p user ssh $SSH_OPTS -p "$SSH_PORT" user@127.0.0.1 \
        'ls -la /home/user/exploit/exploit /home/user/exploit/shell_trap 2>&1' || true

    # --- Step 6: Set up shell_trap ---
    if $SETUP_SHELL_TRAP && [ -f "$SCRIPT_DIR/exp-interactive/shell_trap" ]; then
        info "Setting up shell_trap..."
        TRAP_OUTPUT=$(sshpass -p root ssh $SSH_OPTS -p "$SSH_PORT" root@127.0.0.1 \
            'cp /bin/sh /tmp/sh.real && chmod +x /tmp/sh.real && mount --bind /home/user/exploit/shell_trap /bin/sh && [ -f /bin/bash ] && mount --bind /home/user/exploit/shell_trap /bin/bash && echo SHELL_TRAP_OK' 2>&1 || true)
        if echo "$TRAP_OUTPUT" | grep -q "SHELL_TRAP_OK"; then
            ok "shell_trap active"
        else
            warn "shell_trap setup issue: $TRAP_OUTPUT"
        fi
    fi

    # --- Step 7: Run exploit ---
    info "Running exploit..."
    ATTEMPT_START=$(date +%s)

    set +e
    timeout "$EXPLOIT_TIMEOUT" sshpass -p user ssh $SSH_OPTS -p "$SSH_PORT" user@127.0.0.1 \
        'cd /home/user/exploit && ./exploit' > "$EXPLOIT_LOG" 2>&1
    EXPLOIT_EXIT=$?
    set -e

    DURATION=$(( $(date +%s) - ATTEMPT_START ))
    info "Exploit finished in ${DURATION}s (exit: $EXPLOIT_EXIT)"

    # Wait for pending serial output (kernel panic output may still be flushing)
    sleep 3

    # --- Verify flag ---
    SOURCE=""

    # Check SSH output (patched getroot() prints flag to stdout)
    if grep -qF "$FLAG" "$EXPLOIT_LOG" 2>/dev/null; then
        FOUND=true
        SOURCE="SSH output"
    fi

    # Check serial log (shell_trap prints to serial, or exploit output via console)
    if ! $FOUND && grep -qF "$FLAG" "$SERIAL_LOG" 2>/dev/null; then
        FOUND=true
        SOURCE="serial log"
    fi

    # Last resort: check if /tmp/flag became world-readable (exploit chmod'd it)
    if ! $FOUND && kill -0 "$VM_PID" 2>/dev/null; then
        REMOTE_FLAG=$(timeout 5 sshpass -p user ssh $SSH_OPTS -p "$SSH_PORT" user@127.0.0.1 \
            'cat /tmp/flag 2>/dev/null || true' 2>/dev/null || true)
        if [ "$REMOTE_FLAG" = "$FLAG" ]; then
            FOUND=true
            SOURCE="remote /tmp/flag"
        fi
    fi

    if $FOUND; then
        ok "Flag found via $SOURCE!"
    else
        warn "Attempt $ATTEMPT failed (${DURATION}s)"
        # Show brief failure reason
        if grep -q "NX-protected page\|kernel panic\|BUG:" "$SERIAL_LOG" 2>/dev/null; then
            warn "Kernel panic detected (exploit reliability issue, will retry)"
        fi
    fi

    # Stop VM for next attempt (or final cleanup)
    stop_vm
done

TOTAL_DURATION=$(( $(date +%s) - TOTAL_START ))

# --- Final report ---
echo ""
echo "============================================================"
if $FOUND; then
    echo -e "  ${GREEN}[SUCCESS]${NC} Flag verified via ${GREEN}$SOURCE${NC}"
    echo -e "  Attempt:   $ATTEMPT/$MAX_ATTEMPTS"
    echo -e "  Duration:  ${TOTAL_DURATION}s total"
    echo -e "  Flag:      $FLAG"
    echo ""
    echo "  Exploit achieved root privilege escalation."
else
    echo -e "  ${RED}[FAILED]${NC} Flag not found after $MAX_ATTEMPTS attempts (${TOTAL_DURATION}s)"
    echo ""
    echo "  Last SSH output:"
    tail -20 "$EXPLOIT_LOG" 2>/dev/null | sed 's/^/    /'
    echo ""
    echo "  Last serial log (last 30 lines):"
    tail -30 "$SERIAL_LOG" 2>/dev/null | sed 's/^/    /'
fi
echo "============================================================"
echo "  Last serial log: $SERIAL_LOG"
echo "  Last exploit log: $EXPLOIT_LOG"
echo "============================================================"

$FOUND
