#!/bin/bash
# Download kernelCTF infrastructure files and per-release kernel images.
#
# Usage:
#   ./setup.sh                          # Download base files only
#   ./setup.sh mitigation-6.1-v2        # Download base + specific release bzImage
#   ./setup.sh --deps                   # Install host dependencies only
#   ./setup.sh --list                   # Show known release names

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STORAGE_BASE="https://storage.googleapis.com/kernelctf-build"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*"; }

download() {
    local url="$1" dest="$2"
    if [ -f "$dest" ]; then ok "Already exists: $(basename "$dest")"; return 0; fi
    mkdir -p "$(dirname "$dest")"
    info "Downloading: $(basename "$dest")"
    if ! wget -q --show-progress -O "$dest.tmp" "$url"; then
        rm -f "$dest.tmp"; err "Failed: $url"; return 1
    fi
    mv "$dest.tmp" "$dest"
    ok "Saved: $dest ($(du -sh "$dest" | cut -f1))"
}

install_deps() {
    info "Checking dependencies..."
    local missing=()
    command -v qemu-system-x86_64 &>/dev/null || missing+=("qemu-system-x86")
    command -v expect &>/dev/null || missing+=("expect")
    command -v inotifywait &>/dev/null || missing+=("inotify-tools")
    command -v gcc &>/dev/null || missing+=("build-essential")
    dpkg -s libkeyutils-dev &>/dev/null 2>&1 || missing+=("libkeyutils-dev")

    local unique=($(echo "${missing[@]}" 2>/dev/null | tr ' ' '\n' | sort -u))
    if [ ${#unique[@]} -eq 0 ]; then
        ok "All dependencies installed."
    else
        warn "Missing: ${unique[*]}"
        read -p "Install now? [y/N] " -n 1 -r; echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo apt-get update && sudo apt-get install -y "${unique[@]}"
            ok "Dependencies installed."
        fi
    fi
}

download_base() {
    info "=== Downloading kernelCTF base files ==="

    # rootfs_repro_v2.img: used for automated exploit verification
    mkdir -p "$SCRIPT_DIR/images"

    download "$STORAGE_BASE/files/rootfs_repro_v2.img.gz" "$SCRIPT_DIR/images/rootfs_repro_v2.img.gz"
    if [ ! -f "$SCRIPT_DIR/images/rootfs_repro_v2.img" ]; then
        info "Decompressing rootfs_repro_v2..."
        gzip -dk "$SCRIPT_DIR/images/rootfs_repro_v2.img.gz"
        ok "Decompressed: rootfs_repro_v2.img"
    else
        ok "Already exists: rootfs_repro_v2.img"
    fi

    # rootfs_v3.img: used for interactive local_runner (optional, large)
    download "$STORAGE_BASE/files/rootfs_v3.img.gz" "$SCRIPT_DIR/images/rootfs_v3.img.gz"
    if [ ! -f "$SCRIPT_DIR/images/rootfs_v3.img" ]; then
        info "Decompressing rootfs_v3..."
        gzip -dk "$SCRIPT_DIR/images/rootfs_v3.img.gz"
        ok "Decompressed: rootfs_v3.img"
    else
        ok "Already exists: rootfs_v3.img"
    fi

    download "$STORAGE_BASE/files/ramdisk_v1.img" "$SCRIPT_DIR/images/ramdisk_v1.img"
}

download_release() {
    local release="$1"
    info "=== Downloading bzImage for $release ==="
    mkdir -p "$SCRIPT_DIR/releases/$release"
    download "$STORAGE_BASE/releases/$release/bzImage" "$SCRIPT_DIR/releases/$release/bzImage"
}

show_list() {
    echo "Known kernelCTF release names (non-exhaustive):"
    echo ""
    echo "  Mitigation instances:"
    echo "    mitigation-6.1-v2           Kernel 6.1.x with experimental mitigations"
    echo "    mitigation-v3-6.1.55        Kernel 6.1.55 with v3 mitigations"
    echo "    mitigation-v3b-6.1.55       Kernel 6.1.55 with v3b mitigations"
    echo "    mitigation-v4-6.6           Kernel 6.6.x with v4 mitigations"
    echo ""
    echo "  LTS instances:"
    echo "    lts-6.1.x                   Various 6.1.x LTS versions"
    echo "    lts-6.6.x                   Various 6.6.x LTS versions"
    echo ""
    echo "  COS instances:"
    echo "    cos-XXX-YYYYY.ZZZ.WW        Container-Optimized OS versions"
    echo ""
    echo "  Check exact release names in each CVE's exploit/ subdirectory."
    echo "  E.g.: ls kernelctf/CVE-2023-0461_mitigation/exploit/"
    echo "         → mitigation-6.1"
}

main() {
    case "${1:-}" in
        --deps|-d) install_deps; return 0 ;;
        --list|-l) show_list; return 0 ;;
        --help|-h)
            echo "Usage: $0 [--deps|--list|<release-name>...]"
            return 0 ;;
    esac

    install_deps
    download_base

    # Download specific releases if provided
    for release in "$@"; do
        download_release "$release"
    done

    ok "Setup complete."
}

main "$@"
