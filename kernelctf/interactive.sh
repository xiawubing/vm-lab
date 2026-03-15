#!/bin/bash
# Interactive kernelCTF VM launcher with SSH access.
#
# Boots a kernelCTF kernel in QEMU with a writable rootfs overlay,
# SSH port forwarding, and exploit source files mounted via 9p.
#
# Usage:
#   ./interactive.sh <cve-or-release> [options]
#
# Options:
#   --port PORT    SSH port on host (default: 2250)
#   --reset        Delete existing overlay and start fresh
#   --list         List available CVEs with their releases
#   --no-exploit   Don't copy exploit source
#   --nokaslr      Disable KASLR for easier debugging
#   --flag FILE    Pass flag file as /dev/vdb (root-only readable in VM)
#
# Examples:
#   ./interactive.sh CVE-2023-0461_mitigation
#   ./interactive.sh mitigation-6.1-v2 --port 2251
#   ./interactive.sh CVE-2023-0461_mitigation --nokaslr --reset

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNELCTF_POCS="/home/xia/security-research/pocs/linux/kernelctf"
DEFAULT_PORT=2250

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*"; }

usage() {
    echo "Usage: $0 <cve-or-release> [options]"
    echo ""
    echo "  <cve-or-release>   CVE directory name or kernelCTF release name"
    echo ""
    echo "Options:"
    echo "  --port PORT    SSH port on host (default: $DEFAULT_PORT)"
    echo "  --reset        Delete overlay, start fresh"
    echo "  --list         List available CVEs"
    echo "  --no-exploit   Don't copy exploit source"
    echo "  --nokaslr      Disable KASLR"
    echo "  --flag FILE    Pass flag file as /dev/vdb (root-only readable in VM)"
    echo ""
    echo "Examples:"
    echo "  $0 CVE-2023-0461_mitigation"
    echo "  $0 mitigation-6.1-v2 --port 2251"
    exit 0
}

list_cves() {
    echo "Available kernelCTF CVEs:"
    echo ""
    if [ -d "$KERNELCTF_POCS" ]; then
        for d in "$KERNELCTF_POCS"/CVE-*/; do
            [ -d "$d" ] || continue
            cve=$(basename "$d")
            releases=$(ls "$d/exploit/" 2>/dev/null | tr '\n' ', ' | sed 's/,$//')
            if [ -n "$releases" ]; then
                printf "  %-45s %s\n" "$cve" "$releases"
            fi
        done
    else
        err "security-research repo not found: $KERNELCTF_POCS"
    fi
    exit 0
}

# --- Parse arguments ---

TARGET=""
SSH_PORT="$DEFAULT_PORT"
RESET=false
NO_EXPLOIT=false
NOKASLR=false
LOCK_ROOT=false
FLAG_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)      SSH_PORT="$2"; shift 2 ;;
        --reset)     RESET=true; shift ;;
        --list|-l)   list_cves ;;
        --no-exploit) NO_EXPLOIT=true; shift ;;
        --nokaslr)   NOKASLR=true; shift ;;
        --lock-root) LOCK_ROOT=true; shift ;;
        --flag)      FLAG_FILE="$2"; shift 2 ;;
        --help|-h)   usage ;;
        *)           TARGET="$1"; shift ;;
    esac
done

if [ -z "$TARGET" ]; then usage; fi

# --- Resolve target → release name ---

CVE_DIR=""
RELEASE=""
EXPLOIT_SRC=""

if [[ "$TARGET" == CVE-* ]]; then
    CVE_DIR="$TARGET"
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
    # Map known release aliases
    [[ "$RELEASE" == "mitigation-6.1" ]] && RELEASE="mitigation-6.1-v2"

    EXPLOIT_SRC="$CVE_PATH/exploit/$RELEASE_RAW"
    info "CVE: $CVE_DIR -> release: $RELEASE"
else
    RELEASE="$TARGET"
fi

# --- Paths ---

RELEASE_DIR="$SCRIPT_DIR/releases/$RELEASE"
BZIMAGE="$RELEASE_DIR/bzImage"
ROOTFS="$SCRIPT_DIR/images/rootfs_repro_v2.img"
RAMDISK="$SCRIPT_DIR/images/ramdisk_v1.img"
OVERLAY_DIR="$SCRIPT_DIR/images"
OVERLAY="$OVERLAY_DIR/${RELEASE}-interactive.qcow2"

# --- Pre-flight checks ---

if [ ! -f "$BZIMAGE" ]; then
    info "bzImage not found for $RELEASE, downloading..."
    "$SCRIPT_DIR/setup.sh" "$RELEASE"
fi

if [ ! -f "$BZIMAGE" ]; then
    err "bzImage still not found: $BZIMAGE"
    exit 1
fi

if [ ! -f "$ROOTFS" ]; then
    err "No rootfs image found. Run: ./setup.sh"
    exit 1
fi

if [ ! -f "$RAMDISK" ]; then
    err "ramdisk_v1.img not found. Run: ./setup.sh"
    exit 1
fi

# --- Create qcow2 overlay (writable, backed by rootfs) ---

mkdir -p "$OVERLAY_DIR"

if $RESET && [ -f "$OVERLAY" ]; then
    info "Removing existing overlay..."
    rm -f "$OVERLAY"
fi

# Validate existing overlay's backing file matches current ROOTFS
if [ -f "$OVERLAY" ]; then
    BACKING=$(qemu-img info --output=json "$OVERLAY" 2>/dev/null | \
              python3 -c "import sys,json; print(json.load(sys.stdin).get('full-backing-filename',''))" 2>/dev/null || true)
    if [ -n "$BACKING" ] && [ "$BACKING" != "$ROOTFS" ]; then
        warn "Overlay backing file mismatch: $BACKING != $ROOTFS"
        info "Deleting stale overlay..."
        rm -f "$OVERLAY"
    fi
    # Also check virtual size — overlays created before the 4G fix are undersized
    if [ -f "$OVERLAY" ]; then
        VSIZE=$(qemu-img info --output=json "$OVERLAY" 2>/dev/null | \
                python3 -c "import sys,json; print(json.load(sys.stdin).get('virtual-size',0))" 2>/dev/null || echo 0)
        if [ "$VSIZE" -lt 4294967296 ] 2>/dev/null; then
            warn "Overlay virtual size too small ($((VSIZE/1048576)) MiB < 4096 MiB)"
            info "Deleting undersized overlay..."
            rm -f "$OVERLAY"
        fi
    fi
fi

if [ ! -f "$OVERLAY" ]; then
    info "Creating qcow2 overlay..."
    # Virtual size must cover the full partition table (4G) — the raw rootfs is
    # truncated to ~618 MiB to save space, but the partition inside spans 4 GiB.
    # Without the explicit size, newer kernels (>=6.6) cannot mount the ext4
    # filesystem because the journal lives beyond the truncated boundary.
    qemu-img create -f qcow2 -b "$ROOTFS" -F raw "$OVERLAY" 4G 2>/dev/null
    ok "Overlay: $OVERLAY"
fi

# --- Prepare exploit source ---

EXP_DIR="$SCRIPT_DIR/exp-interactive"
mkdir -p "$EXP_DIR"

if $NO_EXPLOIT; then
    # Thoroughly clean exploit directory for agent mode — remove ALL contents
    # including subdirectories, hidden files, and files with restricted permissions
    # from previous interactive sessions or 9p writes.
    find "$EXP_DIR" -mindepth 1 -delete 2>/dev/null || {
        rm -rf "$EXP_DIR"
        mkdir -p "$EXP_DIR"
    }
    ok "Exploit directory cleaned (agent starts from scratch)"
elif [ -n "$EXPLOIT_SRC" ] && [ -d "$EXPLOIT_SRC" ]; then
    rm -rf "$EXP_DIR"/*
    cp "$EXPLOIT_SRC"/* "$EXP_DIR/" 2>/dev/null || true
    ok "Exploit source copied from $(basename "$EXPLOIT_SRC")"
fi

# --- Kernel command line ---

CMDLINE="console=ttyS0 root=/dev/vda1 rootfstype=ext4 rw"
CMDLINE="$CMDLINE sysctl.io_uring_disabled=2 hostname=$RELEASE"

# Hardening for mitigation instances
if [[ "$RELEASE" == mitigation-* ]]; then
    CMDLINE="$CMDLINE sysctl.kernel.dmesg_restrict=1 sysctl.kernel.kptr_restrict=2"
    CMDLINE="$CMDLINE sysctl.kernel.unprivileged_bpf_disabled=2 sysctl.net.core.bpf_jit_harden=1"
    CMDLINE="$CMDLINE sysctl.kernel.yama.ptrace_scope=1 slab_virtual=1 slab_virtual_guards=1"
fi

if $NOKASLR; then
    CMDLINE="$CMDLINE nokaslr"
    info "KASLR disabled"
fi

if $LOCK_ROOT; then
    CMDLINE="$CMDLINE lockroot=1"
fi

# init=/init triggers rootfs's /init which mounts 9p 'init' tag and runs init.sh
CMDLINE="$CMDLINE init=/init"

# --- Print connection info ---

echo ""
echo "=============================================="
echo -e "  Kernel:   ${GREEN}$RELEASE${NC}"
[ -n "$CVE_DIR" ] && echo -e "  CVE:      ${GREEN}$CVE_DIR${NC}"
echo -e "  SSH:      ${GREEN}ssh -p $SSH_PORT user@127.0.0.1${NC}"
if $LOCK_ROOT; then
    echo -e "  Creds:    user / user  (root locked)"
else
    echo -e "  Creds:    user / user  |  root / root"
fi
echo -e "  Exploit:  /home/user/exploit/"
echo -e "  Reset:    $0 $TARGET --reset"
echo -e "  Exit VM:  Ctrl+A then X"
echo "=============================================="
echo ""

# --- Launch QEMU ---

QEMU_ARGS=(
    -m 3.5G
    -nographic
    -no-reboot
    -enable-kvm
    -cpu host,-avx512f
    -smp cores=2
    -kernel "$BZIMAGE"
    -initrd "$RAMDISK"
    -drive "file=$OVERLAY,if=virtio,format=qcow2,discard=unmap"
    -nic "user,model=virtio-net-pci,hostfwd=tcp::${SSH_PORT}-:22"
    -virtfs "local,path=$SCRIPT_DIR/init-interactive,mount_tag=init,security_model=none,readonly=on"
    -virtfs "local,path=$EXP_DIR,mount_tag=exp,security_model=none"
)

# Flag file as /dev/vdb for root-only flag verification
if [ -n "$FLAG_FILE" ]; then
    if [ ! -f "$FLAG_FILE" ]; then
        err "Flag file not found: $FLAG_FILE"
        exit 1
    fi
    QEMU_ARGS+=(-drive "file=$FLAG_FILE,if=virtio,format=raw,readonly=on")
    info "Flag file attached as /dev/vdb"
fi

QEMU_ARGS+=(-append "$CMDLINE")

exec qemu-system-x86_64 "${QEMU_ARGS[@]}"
