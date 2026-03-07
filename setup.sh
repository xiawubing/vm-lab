#!/bin/bash
# setup.sh — Download all large binary artifacts needed by the vm-lab.
#
# Usage:
#   ./setup.sh              # Download everything (~4.5 GB)
#   ./setup.sh 6074         # Download only what CVE-2017-6074 needs
#   ./setup.sh 6074 7308    # Download for multiple CVEs
#   ./setup.sh --list       # Show all supported CVEs
#   ./setup.sh --deps       # Install host dependencies only
#
# Each CVE's start_vm script will also check for missing files and tell you
# what to download, but this script automates the entire process.

set -euo pipefail

VM_LAB="$(cd "$(dirname "$0")" && pwd)"

# ─── Color helpers ───────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*"; }

# ─── Download helper ─────────────────────────────────────────────────────────

download() {
    local url="$1"
    local dest="$2"

    if [ -f "$dest" ]; then
        ok "Already exists: $dest"
        return 0
    fi

    mkdir -p "$(dirname "$dest")"
    info "Downloading: $(basename "$dest")"
    echo "    $url"

    if ! wget -q --show-progress -O "$dest.tmp" "$url"; then
        rm -f "$dest.tmp"
        err "Failed to download: $url"
        return 1
    fi

    mv "$dest.tmp" "$dest"
    ok "Saved: $dest ($(du -sh "$dest" | cut -f1))"
}

# ─── Base images ─────────────────────────────────────────────────────────────
# These are shared across multiple CVEs.

download_ubuntu_1604() {
    download \
        "https://cloud-images.ubuntu.com/releases/xenial/release/ubuntu-16.04-server-cloudimg-amd64-disk1.img" \
        "$VM_LAB/images/ubuntu-16.04-server-cloudimg-amd64.img"
}

download_ubuntu_1604_3() {
    # CVE-2018-1000001 needs the 16.04.3 point release (glibc 2.23-0ubuntu9).
    # The "release" URL always points to the latest 16.04.x; use a dated snapshot
    # from before 16.04.4 (released 2018-03-01) to get the right glibc version.
    download \
        "https://cloud-images.ubuntu.com/releases/xenial/release-20171121.1/ubuntu-16.04-server-cloudimg-amd64-disk1.img" \
        "$VM_LAB/images/ubuntu-16.04.3-base.img"
}

download_ubuntu_2004() {
    download \
        "https://cloud-images.ubuntu.com/releases/focal/release/ubuntu-20.04-server-cloudimg-amd64.img" \
        "$VM_LAB/images/ubuntu-20.04-server-cloudimg-amd64.img"
}

download_centos_7() {
    download \
        "https://cloud.centos.org/centos/7/images/CentOS-7-x86_64-GenericCloud.qcow2" \
        "$VM_LAB/images/centos-7-server-cloudimg-amd64.qcow2"
}

# ─── Kernel packages ────────────────────────────────────────────────────────

download_kernel_4_4_0_62() {
    download \
        "http://launchpadlibrarian.net/302967570/linux-image-4.4.0-62-generic_4.4.0-62.83_amd64.deb" \
        "$VM_LAB/kernel/xenial-4.4.0-62/linux-image-4.4.0-62-generic_4.4.0-62.83_amd64.deb"
    download \
        "http://launchpadlibrarian.net/302967532/linux-image-extra-4.4.0-62-generic_4.4.0-62.83_amd64.deb" \
        "$VM_LAB/kernel/xenial-4.4.0-62/linux-image-extra-4.4.0-62-generic_4.4.0-62.83_amd64.deb"
}

download_kernel_4_8_0_41() {
    download \
        "http://launchpadlibrarian.net/309600146/linux-image-4.8.0-41-generic_4.8.0-41.44~16.04.1_amd64.deb" \
        "$VM_LAB/kernel/xenial-hwe-4.8.0-41/linux-image-4.8.0-41-generic_4.8.0-41.44~16.04.1_amd64.deb"
}

download_kernel_4_13_0() {
    download \
        "https://kernel.ubuntu.com/mainline/v4.13/linux-image-4.13.0-041300-generic_4.13.0-041300.201709031731_amd64.deb" \
        "$VM_LAB/kernel/mainline-4.13.0/linux-image-4.13.0-041300-generic_4.13.0-041300.201709031731_amd64.deb"
}

download_kernel_4_4_0_116() {
    download \
        "http://launchpadlibrarian.net/356811216/linux-image-4.4.0-116-generic_4.4.0-116.140_amd64.deb" \
        "$VM_LAB/kernel/xenial-4.4.0-116/linux-image-4.4.0-116-generic_4.4.0-116.140_amd64.deb"
}

download_kernel_4_19_0() {
    local deb="$VM_LAB/kernel/mainline-4.19.0/linux-image-unsigned-4.19.0-041900-generic_4.19.0-041900.201810221809_amd64.deb"
    local vmlinuz="$VM_LAB/kernel/mainline-4.19.0/extracted/boot/vmlinuz-4.19.0-041900-generic"

    download \
        "https://kernel.ubuntu.com/mainline/v4.19/linux-image-unsigned-4.19.0-041900-generic_4.19.0-041900.201810221809_amd64.deb" \
        "$deb"

    # Extract vmlinuz from the .deb (needed for direct -kernel boot)
    if [ ! -f "$vmlinuz" ]; then
        info "Extracting vmlinuz from .deb..."
        local extract_dir="$VM_LAB/kernel/mainline-4.19.0/extracted"
        mkdir -p "$extract_dir"
        cd "$extract_dir"
        ar x "$deb" data.tar.xz 2>/dev/null || ar x "$deb" data.tar.gz 2>/dev/null
        if [ -f data.tar.xz ]; then
            tar xf data.tar.xz ./boot/ --strip-components=0 2>/dev/null || true
            tar xf data.tar.xz ./usr/share/doc/ --strip-components=0 2>/dev/null || true
            rm -f data.tar.xz
        elif [ -f data.tar.gz ]; then
            tar xf data.tar.gz ./boot/ --strip-components=0 2>/dev/null || true
            tar xf data.tar.gz ./usr/share/doc/ --strip-components=0 2>/dev/null || true
            rm -f data.tar.gz
        fi
        rm -f control.tar.* debian-binary
        cd "$VM_LAB"
        if [ -f "$vmlinuz" ]; then
            ok "Extracted: $vmlinuz"
        else
            err "Failed to extract vmlinuz from .deb"
        fi
    else
        ok "Already exists: $vmlinuz"
    fi
}

download_kernel_5_10_source() {
    local tarball="$VM_LAB/kernel/linux-5.10.tar.xz"
    local bzimage="$VM_LAB/kernel/linux-5.10/arch/x86/boot/bzImage"

    download \
        "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.10.tar.xz" \
        "$tarball"

    if [ ! -f "$bzimage" ]; then
        warn "Kernel 5.10 needs to be compiled manually after download."
        warn "Steps:"
        echo "    cd $VM_LAB/kernel"
        echo "    tar xf linux-5.10.tar.xz"
        echo "    cd linux-5.10"
        echo "    make defconfig"
        echo "    # Enable CONFIG_PIPE_BUF_FLAG_CAN_MERGE (default in 5.10)"
        echo "    make -j\$(nproc)"
        echo "    # Result: arch/x86/boot/bzImage"
    else
        ok "Already exists: $bzimage"
    fi
}

# ─── Per-CVE setup functions ────────────────────────────────────────────────

setup_CVE_2017_5123() {
    info "=== CVE-2017-5123 (waitid missing access_ok, kernel 4.13.0) ==="
    download_ubuntu_1604
    download_kernel_4_13_0
}

setup_CVE_2017_6074() {
    info "=== CVE-2017-6074 (DCCP double-free, kernel 4.4.0-62) ==="
    download_ubuntu_1604
    download_kernel_4_4_0_62
}

setup_CVE_2017_7308() {
    info "=== CVE-2017-7308 (AF_PACKET heap OOB, kernel 4.8.0-41) ==="
    download_ubuntu_1604
    download_kernel_4_8_0_41
}

setup_CVE_2017_16995() {
    info "=== CVE-2017-16995 (BPF verifier sign extension, kernel 4.4.0-116) ==="
    download_ubuntu_1604
    download_kernel_4_4_0_116
}

setup_CVE_2017_1000112() {
    info "=== CVE-2017-1000112 (UFO memory corruption, kernel 4.8.0-41) ==="
    download_ubuntu_1604
    download_kernel_4_8_0_41
}

setup_CVE_2017_1000367() {
    info "=== CVE-2017-1000367 (sudo tty race, CentOS 7) ==="
    download_centos_7
}

setup_CVE_2018_1000001() {
    info "=== CVE-2018-1000001 (glibc realpath underflow, Ubuntu 16.04.3) ==="
    download_ubuntu_1604_3
}

setup_CVE_2018_18955() {
    info "=== CVE-2018-18955 (user ns id mapping, kernel 4.19.0) ==="
    download_ubuntu_2004
    download_kernel_4_19_0
}

setup_CVE_2022_0847() {
    info "=== CVE-2022-0847 (Dirty Pipe, kernel 5.10) ==="
    download_ubuntu_2004
    download_kernel_5_10_source
}

# ─── Host dependency check ──────────────────────────────────────────────────

install_deps() {
    info "Checking host dependencies..."
    local missing=()

    for cmd in qemu-system-x86_64 qemu-img; do
        command -v "$cmd" &>/dev/null || missing+=("qemu-system-x86" "qemu-utils")
    done
    command -v genisoimage &>/dev/null || command -v cloud-localds &>/dev/null || missing+=("genisoimage")
    command -v mcopy &>/dev/null || missing+=("mtools")
    command -v mkfs.vfat &>/dev/null || missing+=("dosfstools")
    command -v wget &>/dev/null || missing+=("wget")
    command -v sshpass &>/dev/null || missing+=("sshpass")
    command -v ar &>/dev/null || missing+=("binutils")

    # Deduplicate
    local unique_missing=($(echo "${missing[@]}" | tr ' ' '\n' | sort -u))

    if [ ${#unique_missing[@]} -eq 0 ]; then
        ok "All host dependencies are installed."
    else
        warn "Missing packages: ${unique_missing[*]}"
        echo ""
        echo "    sudo apt install -y ${unique_missing[*]}"
        echo ""
        read -p "Install now? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo apt-get update && sudo apt-get install -y "${unique_missing[@]}"
            ok "Dependencies installed."
        else
            warn "Skipping dependency installation."
        fi
    fi
}

# ─── CVE name normalization ─────────────────────────────────────────────────

# Accept flexible CVE references: "6074", "2017-6074", "CVE-2017-6074"
normalize_cve() {
    local input="$1"

    # Map short numbers to full CVE IDs
    case "$input" in
        5123|2017-5123|CVE-2017-5123)       echo "CVE-2017-5123" ;;
        6074|2017-6074|CVE-2017-6074)       echo "CVE-2017-6074" ;;
        7308|2017-7308|CVE-2017-7308)       echo "CVE-2017-7308" ;;
        16995|2017-16995|CVE-2017-16995)    echo "CVE-2017-16995" ;;
        1000112|2017-1000112|CVE-2017-1000112) echo "CVE-2017-1000112" ;;
        1000367|2017-1000367|CVE-2017-1000367) echo "CVE-2017-1000367" ;;
        1000001|2018-1000001|CVE-2018-1000001) echo "CVE-2018-1000001" ;;
        18955|2018-18955|CVE-2018-18955)    echo "CVE-2018-18955" ;;
        0847|847|2022-0847|CVE-2022-0847)   echo "CVE-2022-0847" ;;
        *) err "Unknown CVE: $input"; return 1 ;;
    esac
}

setup_cve() {
    local cve
    cve=$(normalize_cve "$1") || return 1
    local func="setup_${cve//-/_}"
    "$func"
}

# ─── Main ───────────────────────────────────────────────────────────────────

ALL_CVES=(
    "CVE-2017-5123"
    "CVE-2017-6074"
    "CVE-2017-7308"
    "CVE-2017-16995"
    "CVE-2017-1000112"
    "CVE-2017-1000367"
    "CVE-2018-1000001"
    "CVE-2018-18955"
    "CVE-2022-0847"
)

show_list() {
    echo "Supported CVEs:"
    echo ""
    echo "  CVE-2017-5123     waitid() missing access_ok       kernel 4.13.0        ~780 MB"
    echo "  CVE-2017-6074     DCCP double-free                 kernel 4.4.0-62      ~785 MB"
    echo "  CVE-2017-7308     AF_PACKET heap OOB               kernel 4.8.0-41      ~750 MB"
    echo "  CVE-2017-16995    BPF verifier sign extension      kernel 4.4.0-116     ~750 MB"
    echo "  CVE-2017-1000112  UFO memory corruption            kernel 4.8.0-41      ~750 MB"
    echo "  CVE-2017-1000367  sudo tty race (not kernel)       CentOS 7 default     ~860 MB"
    echo "  CVE-2018-1000001  glibc realpath() underflow       Ubuntu 16.04.3       ~770 MB"
    echo "  CVE-2018-18955    user namespace id mapping        kernel 4.19.0        ~1.9 GB"
    echo "  CVE-2022-0847     Dirty Pipe                       kernel 5.10          ~2.0 GB"
    echo ""
    echo "Usage:"
    echo "  ./setup.sh              # Download all (~4.5 GB, shared base images deduplicated)"
    echo "  ./setup.sh 6074         # Download only CVE-2017-6074 requirements"
    echo "  ./setup.sh 6074 7308    # Download for multiple CVEs"
    echo "  ./setup.sh --deps       # Install host dependencies only"
}

show_usage() {
    echo "Usage: ./setup.sh [OPTIONS] [CVE...]"
    echo ""
    echo "Options:"
    echo "  --list    Show all supported CVEs and estimated download sizes"
    echo "  --deps    Install host dependencies only (qemu, genisoimage, etc.)"
    echo "  --help    Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./setup.sh              # Download everything"
    echo "  ./setup.sh 6074         # Just CVE-2017-6074"
    echo "  ./setup.sh 6074 7308    # Multiple CVEs"
}

main() {
    if [ $# -eq 0 ]; then
        # Download everything
        install_deps
        echo ""
        info "Downloading artifacts for all ${#ALL_CVES[@]} CVEs..."
        echo ""
        for cve in "${ALL_CVES[@]}"; do
            setup_cve "$cve"
            echo ""
        done
        ok "All downloads complete."
        echo ""
        info "You can now boot any VM with:"
        echo "    ./start_vm_CVE-2017-6074.sh"
        return 0
    fi

    case "$1" in
        --list|-l)
            show_list
            return 0
            ;;
        --deps|-d)
            install_deps
            return 0
            ;;
        --help|-h)
            show_usage
            return 0
            ;;
    esac

    # Specific CVEs requested
    install_deps
    echo ""
    for arg in "$@"; do
        setup_cve "$arg"
        echo ""
    done
    ok "Downloads complete."
}

main "$@"
