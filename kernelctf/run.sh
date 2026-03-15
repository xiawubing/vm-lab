#!/bin/bash
# Run and verify a kernelCTF exploit.
#
# Usage:
#   ./run.sh <cve-dir> [release-name]
#
# Example:
#   ./run.sh CVE-2023-0461_mitigation mitigation-6.1-v2
#
# The script will:
#   1. Compile the exploit from the CVE directory
#   2. Generate a unique flag file
#   3. Launch the kernelCTF VM
#   4. Monitor output for the flag (proof of root privilege escalation)
#   5. Report success or failure

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNELCTF_POCS="/home/xia/security-research/pocs/linux/kernelctf"
TIMEOUT=120

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*"; }

usage() {
    echo "Usage: $0 <cve-dir> [release-name]"
    echo ""
    echo "  cve-dir:      CVE directory name (e.g. CVE-2023-0461_mitigation)"
    echo "  release-name: kernelCTF release (auto-detected from exploit/ if omitted)"
    echo ""
    echo "Examples:"
    echo "  $0 CVE-2023-0461_mitigation"
    echo "  $0 CVE-2023-0461_mitigation mitigation-6.1-v2"
    exit 1
}

CVE_DIR="${1:-}"
RELEASE="${2:-}"

if [ -z "$CVE_DIR" ]; then usage; fi

CVE_PATH="$KERNELCTF_POCS/$CVE_DIR"
if [ ! -d "$CVE_PATH" ]; then
    err "CVE directory not found: $CVE_PATH"
    exit 1
fi

# Auto-detect release name from exploit/ subdirectory
if [ -z "$RELEASE" ]; then
    RELEASE=$(ls "$CVE_PATH/exploit/" 2>/dev/null | head -1)
    if [ -z "$RELEASE" ]; then
        err "No exploit subdirectory found in $CVE_PATH/exploit/"
        exit 1
    fi
    info "Auto-detected release: $RELEASE"
fi

# Map release names (kernelCTF does this for mitigation-6.1)
if [ "$RELEASE" = "mitigation-6.1" ]; then
    RELEASE="mitigation-6.1-v2"
    info "Mapped release: mitigation-6.1 → mitigation-6.1-v2"
fi

EXPLOIT_SRC="$CVE_PATH/exploit/${2:-$(ls "$CVE_PATH/exploit/" | head -1)}"
RELEASE_DIR="$SCRIPT_DIR/releases/$RELEASE"

# --- Pre-flight checks ---

if [ ! -f "$RELEASE_DIR/bzImage" ]; then
    err "bzImage not found for release $RELEASE"
    echo "    Run: ./setup.sh $RELEASE"
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/images/rootfs_repro_v2.img" ]; then
    err "rootfs_repro_v2.img not found. Run: ./setup.sh"
    exit 1
fi

# --- Step 1: Compile the exploit ---

info "=== Compiling exploit from $EXPLOIT_SRC ==="

rm -rf "$SCRIPT_DIR/exp"
mkdir -p "$SCRIPT_DIR/exp"

# Copy all source files (*.c, *.h, *.s, *.py, Makefile, run.sh, deps, libs, etc.)
# Exclude bzImage (large kernel) and pre-compiled exploit binary (we compile fresh)
for f in "$EXPLOIT_SRC"/*; do
    fname="$(basename "$f")"
    [ "$fname" = "bzImage" ] && continue
    [ "$fname" = "exploit" ] && continue
    cp -a "$f" "$SCRIPT_DIR/exp/" 2>/dev/null || true
done

# Create keyutils.h stub (syscall-based, no libkeyutils-dev needed)
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

# Add CBQ compatibility header and include it
if [ -f "$SCRIPT_DIR/exp/exploit.c" ] && ! grep -q "cbq_compat.h" "$SCRIPT_DIR/exp/exploit.c"; then
    cp "$SCRIPT_DIR/patches/cbq_compat.h" "$SCRIPT_DIR/exp/"
    # Insert #include "cbq_compat.h" before #include "netlink_utils.h"
    sed -i 's|#include "netlink_utils.h"|#include "cbq_compat.h"\n#include "netlink_utils.h"|' "$SCRIPT_DIR/exp/exploit.c"
fi

# Best-effort shell patching (init.sh privilege escalation monitor is the primary mechanism)
# Match: execve("/bin/sh"), split /bin/sh in variable, or system("cat /flag")
if [ -f "$SCRIPT_DIR/exp/exploit.c" ] && grep -qE 'exec[lv][ep]?\s*\(.*(/bin/(ba)?sh|"(ba)?sh")|/bin/(ba)?sh|system\s*\(.*(/bin/sh|cat.*/flag)' "$SCRIPT_DIR/exp/exploit.c"; then
    info "Patching shell-spawning function to read flag directly..."
    python3 "$SCRIPT_DIR/patches/patch_shell_spawn.py" "$SCRIPT_DIR/exp/exploit.c" 2>&1 || true
fi

# Try compilation
# NOTE: no `make prerequisites` — it calls `sudo apt-get` which blocks in automation.
# All needed packages should be pre-installed via setup.sh --deps.
# stdin is redirected from /dev/null to prevent any interactive prompts.
COMPILED=false
cd "$SCRIPT_DIR/exp"
if [ -f Makefile ]; then
    info "Makefile detected — building with make..."
    if timeout 120 make exploit </dev/null 2>&1; then
        ok "Makefile compilation succeeded"
        COMPILED=true
    else
        warn "Makefile compilation failed"
        # Try building prerequisites (e.g. libmnl, libnftnl) and retry
        if grep -q '^prerequisites\|^libnftnl-build\|^libmnl-build' Makefile 2>/dev/null && [ ! -f exploit ]; then
            info "Trying make prerequisites + make exploit..."
            if timeout 180 make prerequisites </dev/null 2>&1 && timeout 120 make exploit </dev/null 2>&1; then
                ok "Compilation with prerequisites succeeded"
                COMPILED=true
            else
                warn "Compilation with prerequisites also failed"
            fi
        fi
        # Fallback: if Makefile failed but exploit.c exists, try simple gcc
        if [ -f exploit.c ] && [ ! -f exploit ]; then
            info "Trying fallback gcc compilation..."
            # Collect all .c files in current directory
            C_FILES=$(ls *.c 2>/dev/null | tr '\n' ' ')
            if gcc -I. -D_GNU_SOURCE -o exploit $C_FILES -O0 -static -lpthread 2>&1; then
                ok "Fallback gcc compilation succeeded"
                COMPILED=true
            else
                # Try with just exploit.c
                if gcc -I. -D_GNU_SOURCE -o exploit exploit.c -O0 -static -lpthread 2>&1; then
                    ok "Fallback single-file compilation succeeded"
                    COMPILED=true
                fi
            fi
        fi
    fi
elif [ -f exploit.c ]; then
    info "Compiling exploit.c..."
    if gcc -I. -D_GNU_SOURCE -o exploit exploit.c -O0 -static -s 2>&1; then
        ok "Compilation succeeded"
        COMPILED=true
    else
        warn "Compilation failed"
    fi
fi
cd "$SCRIPT_DIR"

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
ok "Exploit binary ready: $(file "$SCRIPT_DIR/exp/exploit" | cut -d: -f2 | xargs)"

# Compile shell_trap (bind-mounted over /bin/sh in VM to intercept post-exploit shell spawns)
info "Compiling shell_trap..."
if gcc -static -O0 -o "$SCRIPT_DIR/exp/shell_trap" "$SCRIPT_DIR/patches/shell_trap.c" 2>&1; then
    chmod +x "$SCRIPT_DIR/exp/shell_trap"
    ok "shell_trap ready"
else
    warn "shell_trap compilation failed — relying on source patch + PEM only"
fi

# --- Step 2 & 3: Generate flag, launch VM (with retries) ---

MAX_ATTEMPTS="${KCTF_MAX_ATTEMPTS:-3}"
FOUND=false
ATTEMPT=0
DURATION=0

mkdir -p "$SCRIPT_DIR/logs"
rm -f "$SCRIPT_DIR/logs/repro_log_"*.txt
chmod +x "$SCRIPT_DIR/qemu.sh"

while [ "$ATTEMPT" -lt "$MAX_ATTEMPTS" ] && ! $FOUND; do
    ATTEMPT=$((ATTEMPT + 1))

    FLAG="kernelCTF{$(cat /proc/sys/kernel/random/uuid)}"
    FLAG_FILE="$SCRIPT_DIR/logs/flag"
    echo -n "$FLAG" > "$FLAG_FILE"

    info "=== Attempt $ATTEMPT/$MAX_ATTEMPTS: Launching VM ($RELEASE) ==="
    info "Flag: $FLAG"

    LOG_FILE="$SCRIPT_DIR/logs/repro_log_$(date +%s).txt"
    START_TIME=$(date +%s)

    timeout "$TIMEOUT" "$SCRIPT_DIR/qemu.sh" "$RELEASE_DIR" "$FLAG_FILE" &> "$LOG_FILE" &
    QEMU_PID=$!

    # Poll log file for flag
    ELAPSED=0
    while [ $ELAPSED -lt $TIMEOUT ]; do
        sleep 2
        ELAPSED=$(( $(date +%s) - START_TIME ))

        if grep -qF "$FLAG" "$LOG_FILE" 2>/dev/null; then
            FOUND=true
            break
        fi

        if ! kill -0 "$QEMU_PID" 2>/dev/null; then
            if grep -qF "$FLAG" "$LOG_FILE" 2>/dev/null; then
                FOUND=true
            fi
            break
        fi

        if [ $((ELAPSED % 10)) -eq 0 ]; then
            printf "\r${CYAN}[*]${NC} Waiting... %ds/%ds" "$ELAPSED" "$TIMEOUT"
        fi
    done

    echo ""

    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true

    DURATION=$(( $(date +%s) - START_TIME ))

    if ! $FOUND; then
        warn "Attempt $ATTEMPT failed after ${DURATION}s (timing race, will retry)"
    fi
done

# --- Step 4: Report results ---

echo ""
echo "=============================================="

if $FOUND; then
    echo -e "${GREEN}  [SUCCESS] Flag found after ${DURATION}s${NC}"
    echo "  Flag: $FLAG"
    echo ""
    echo "  Exploit achieved root privilege escalation."
else
    echo -e "${RED}  [FAILED] Flag not found after ${DURATION}s${NC}"
    echo ""
    echo "  Last 30 lines of output:"
    echo "  ---"
    tail -30 "$LOG_FILE" 2>/dev/null | sed 's/^/  /'
fi

echo "=============================================="
echo "Full log: $LOG_FILE"

$FOUND
