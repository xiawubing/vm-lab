#!/bin/bash
set -x

mkdir -p /proc /sys
mount -t proc none /proc 2>/dev/null || true
mount -t sysfs none /sys 2>/dev/null || true

mkdir -p /tmp/exp_ro
mount -t 9p exp /tmp/exp_ro

mkdir -p /tmp/exp
chown user:user /tmp/exp
chmod a+rx /tmp/exp

cp /tmp/exp_ro/* /tmp/exp/
chmod a+rx /tmp/exp/*

# Set up loopback for network-dependent exploits
ifconfig lo 127.0.0.1 netmask 255.0.0.0 up 2>/dev/null || ip link set lo up 2>/dev/null || true

CMD="/tmp/exp/exploit"
if [[ " $* " == *" kaslr_leak=1 "* ]]; then
    KASLR_BASE=$(head -n 1 /proc/kallsyms | cut -d " " -f1)
    CMD="$CMD $KASLR_BASE"
fi

echo "running exploit, cmd='$CMD', ::EXPLOIT OUTPUT FROM HERE::"
su user -c "$CMD"
