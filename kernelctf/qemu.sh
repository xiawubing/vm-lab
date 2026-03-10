#!/bin/bash
# Launch kernelCTF QEMU VM with exploit mounted via 9p virtfs.
#
# Usage: ./qemu.sh <release-dir> <flag-file> [extra-kernel-params]
#   release-dir: path containing bzImage (e.g. releases/mitigation-6.1-v2)
#   flag-file:   path to flag file

set -e

RELEASE_DIR="$1"
FLAG_FILE="$2"
EXTRA_PARAMS="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BZIMAGE="$RELEASE_DIR/bzImage"
ROOTFS="$SCRIPT_DIR/images/rootfs_repro_v2.img"
RAMDISK="$SCRIPT_DIR/images/ramdisk_v1.img"

if [ ! -f "$BZIMAGE" ]; then echo "ERROR: bzImage not found: $BZIMAGE"; exit 1; fi
if [ ! -f "$ROOTFS" ]; then echo "ERROR: rootfs not found: $ROOTFS"; exit 1; fi
if [ ! -f "$RAMDISK" ]; then echo "ERROR: ramdisk not found: $RAMDISK"; exit 1; fi

# Build kernel command line
RELEASE_NAME="$(basename "$RELEASE_DIR")"
CMDLINE="console=ttyS0 root=/dev/vda1 rootfstype=ext4 rootflags=discard ro"
CMDLINE="$CMDLINE sysctl.io_uring_disabled=2 hostname=$RELEASE_NAME"

# Apply hardening for mitigation instances (all mitigation-* releases)
if [[ "$RELEASE_NAME" == mitigation-* ]]; then
    CMDLINE="$CMDLINE sysctl.kernel.dmesg_restrict=1 sysctl.kernel.kptr_restrict=2"
    CMDLINE="$CMDLINE sysctl.kernel.unprivileged_bpf_disabled=2 sysctl.net.core.bpf_jit_harden=1"
    CMDLINE="$CMDLINE sysctl.kernel.yama.ptrace_scope=1 slab_virtual=1 slab_virtual_guards=1"
fi

if [ -n "$EXTRA_PARAMS" ]; then
    CMDLINE="$CMDLINE $EXTRA_PARAMS"
fi

exec qemu-system-x86_64 \
    -m 3.5G \
    -nographic \
    -no-reboot \
    -monitor none \
    -enable-kvm \
    -cpu host,-avx512f \
    -smp cores=2 \
    -kernel "$BZIMAGE" \
    -initrd "$RAMDISK" \
    -nic "user,model=virtio-net-pci" \
    -drive "file=$ROOTFS,if=virtio,format=raw,readonly=on,discard=unmap,aio=native,cache=none" \
    -drive "file=$FLAG_FILE,if=virtio,format=raw,readonly=on" \
    -virtfs "local,path=$SCRIPT_DIR/init,mount_tag=init,security_model=none,readonly=on" \
    -virtfs "local,path=$SCRIPT_DIR/exp,mount_tag=exp,security_model=none,readonly=on" \
    -append "$CMDLINE init=/init"
