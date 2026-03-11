#!/bin/bash
# Download kernelCTF infrastructure files and per-release kernel images.
#
# Usage:
#   ./setup.sh                          # Download base files only
#   ./setup.sh mitigation-6.1-v2        # Download base + specific release bzImage
#   ./setup.sh --all                    # Download ALL releases found in security-research repo
#   ./setup.sh --kernel-src             # Clone linux-stable bare repo for kernel source
#   ./setup.sh --deps                   # Install host dependencies only
#   ./setup.sh --list                   # Show known release names
#   ./setup.sh --verify                 # Verify which releases are downloaded/missing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STORAGE_BASE="https://storage.googleapis.com/kernelctf-build"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*"; }

SECURITY_RESEARCH_DIR="$HOME/security-research"
KERNEL_SRC_DIR="$HOME/kernel-src"

download() {
    local url="$1" dest="$2"
    if [ -f "$dest" ]; then ok "Already exists: $(basename "$dest")"; return 0; fi
    mkdir -p "$(dirname "$dest")"
    info "Downloading: $(basename "$dest")"
    if ! wget -q --show-progress --timeout=30 --tries=3 -c -O "$dest.tmp" "$url"; then
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
    dpkg -s libmnl-dev &>/dev/null 2>&1 || missing+=("libmnl-dev")
    dpkg -s libnftnl-dev &>/dev/null 2>&1 || missing+=("libnftnl-dev")
    # kernelCTF exploit build dependencies (covers sudo apt-get in 45+ Makefiles)
    dpkg -s libnl-nf-3-dev &>/dev/null 2>&1 || missing+=("libnl-nf-3-dev")
    dpkg -s libnl-cli-3-dev &>/dev/null 2>&1 || missing+=("libnl-cli-3-dev")
    dpkg -s libnl-route-3-dev &>/dev/null 2>&1 || missing+=("libnl-route-3-dev")
    dpkg -s libip4tc-dev &>/dev/null 2>&1 || missing+=("libip4tc-dev")
    command -v musl-gcc &>/dev/null || missing+=("musl-tools")
    command -v nasm &>/dev/null || missing+=("nasm")

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

# Scan security-research repo for all unique release names
scan_releases() {
    local sr_dir="$SECURITY_RESEARCH_DIR/pocs/linux/kernelctf"
    if [ ! -d "$sr_dir" ]; then
        err "security-research repo not found at $sr_dir"
        return 1
    fi
    find "$sr_dir" -mindepth 3 -maxdepth 3 -type d -path "*/exploit/*" \
        | sed 's|.*/exploit/||' | sort -u
}

# Download all releases found in security-research repo
download_all_releases() {
    local releases
    releases=$(scan_releases) || return 1
    local total succeeded=0 failed=0 skipped=0
    total=$(echo "$releases" | wc -l)
    local failed_log="$SCRIPT_DIR/setup-failed.log"
    : > "$failed_log"

    info "=== Downloading ALL $total releases ==="
    echo ""

    while IFS= read -r release; do
        local dest="$SCRIPT_DIR/releases/$release/bzImage"
        if [ -f "$dest" ]; then
            ok "Already exists: $release/bzImage"
            ((skipped++)) || true
            continue
        fi
        mkdir -p "$SCRIPT_DIR/releases/$release"
        info "Downloading bzImage for $release..."
        if wget -q --timeout=30 --tries=3 -c \
                -O "$dest.tmp" "$STORAGE_BASE/releases/$release/bzImage" 2>&1; then
            mv "$dest.tmp" "$dest"
            ok "Saved: $release/bzImage ($(du -sh "$dest" | cut -f1))"
            ((succeeded++)) || true
        else
            rm -f "$dest.tmp"
            err "Failed: $release"
            echo "$release" >> "$failed_log"
            ((failed++)) || true
        fi
    done <<< "$releases"

    echo ""
    info "=== Download Summary ==="
    ok "  Succeeded: $succeeded"
    if [ "$skipped" -gt 0 ]; then
        ok "  Skipped (already exist): $skipped"
    fi
    if [ "$failed" -gt 0 ]; then
        err "  Failed: $failed (see $failed_log)"
    else
        rm -f "$failed_log"
    fi
    ok "  Total: $total"
}

# Verify which releases are downloaded and which are missing
verify_releases() {
    local releases
    releases=$(scan_releases) || return 1
    local total present=0 missing=0
    total=$(echo "$releases" | wc -l)

    info "=== Verifying $total releases ==="
    local missing_list=()
    while IFS= read -r release; do
        if [ -f "$SCRIPT_DIR/releases/$release/bzImage" ]; then
            ((present++)) || true
        else
            ((missing++)) || true
            missing_list+=("$release")
        fi
    done <<< "$releases"

    echo ""
    ok "  Present: $present/$total"
    if [ "$missing" -gt 0 ]; then
        warn "  Missing: $missing"
        for r in "${missing_list[@]}"; do
            echo "    - $r"
        done
    else
        ok "  All releases downloaded!"
    fi
}

# Clone linux-stable bare repo for kernel source checkout
clone_kernel_src() {
    local dest="$KERNEL_SRC_DIR/linux-stable"
    if [ -d "$dest" ]; then
        ok "linux-stable already exists at $dest"
        info "Running git fetch to update..."
        cd "$dest" && git fetch --all
        ok "linux-stable updated."
        return 0
    fi
    mkdir -p "$KERNEL_SRC_DIR"
    info "Cloning linux-stable bare repo (~4-5GB, this will take a while)..."
    if timeout 3600 git clone --bare \
        https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git "$dest"; then
        ok "linux-stable cloned to $dest"
    else
        err "Failed to clone linux-stable (timeout or network error)"
        err "If partially downloaded, retry with: cd $dest && git fetch"
        return 1
    fi
}

main() {
    case "${1:-}" in
        --deps|-d) install_deps; return 0 ;;
        --list|-l) show_list; return 0 ;;
        --all|-a)
            install_deps
            download_base
            download_all_releases
            ok "Setup complete."
            return 0
            ;;
        --kernel-src)
            clone_kernel_src
            return 0
            ;;
        --verify|-v)
            verify_releases
            return 0
            ;;
        --help|-h)
            echo "Usage: $0 [--deps|--list|--all|--kernel-src|--verify|<release-name>...]"
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
