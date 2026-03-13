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

# Extract flag from /dev/vdb to a file (root-only readable)
# chmod 400 preserves test integrity: only processes with uid=0 can read it
# Rootfs is read-only, so write to /tmp/flag first, then try /flag as well
# IMPORTANT: disable xtrace to avoid leaking flag content into VM serial output
# (run.sh uses grep to detect the flag — xtrace would cause a false positive)
set +x
if [ -b /dev/vdb ]; then
    FLAG_CONTENT=$(dd if=/dev/vdb bs=512 count=1 2>/dev/null | tr -d '\0')
    if [ -n "$FLAG_CONTENT" ]; then
        echo -n "$FLAG_CONTENT" > /tmp/flag
        chmod 400 /tmp/flag
        # Try to also create /flag (works if rootfs is writable)
        echo -n "$FLAG_CONTENT" > /flag 2>/dev/null && chmod 400 /flag 2>/dev/null || true
    fi
fi
set -x

CMD="/tmp/exp/exploit"
if [[ " $* " == *" kaslr_leak=1 "* ]]; then
    KASLR_BASE=$(head -n 1 /proc/kallsyms | cut -d " " -f1)
    CMD="$CMD $KASLR_BASE"
fi

echo "running exploit, cmd='$CMD', ::EXPLOIT OUTPUT FROM HERE::"

# Run exploit as unprivileged user, with a background privilege escalation monitor.
# EXPLOIT_PID is the PID of the 'su' process; the actual exploit is its child.
su user -c "$CMD" &
EXPLOIT_PID=$!

# Privilege escalation monitor:
# Detects when any descendant of the exploit process (identified by EXPLOIT_PID)
# achieves euid=0. This covers execve("/bin/sh"), execlp, system(), etc.
# On detection, prints the flag and kills the exploit tree.
(
    set +x  # no xtrace — avoid leaking flag or cluttering serial output

    # Check if a PID is a proper descendant of a target PID (child, grandchild, etc.)
    # Does NOT count the target PID itself as a descendant.
    is_descendant() {
        local target="$1" check="$2" depth=0
        # Skip the target itself (su process runs as root by design)
        [ "$check" = "$target" ] && return 1
        while [ -n "$check" ] && [ "$check" != "0" ] && [ "$check" != "1" ] && [ $depth -lt 10 ]; do
            [ "$check" = "$target" ] && return 0
            check=$(awk '/^PPid:/{print $2}' "/proc/$check/status" 2>/dev/null)
            depth=$((depth + 1))
        done
        return 1
    }

    sleep 0.2  # brief pause for su to drop privileges; must be fast to catch quick exploits

    while kill -0 $EXPLOIT_PID 2>/dev/null; do
        for status_file in /proc/[0-9]*/status; do
            pid=$(echo "$status_file" | cut -d/ -f3)

            # Only check euid for processes that descend from the exploit
            euid=$(awk '/^Uid:/{print $3}' "$status_file" 2>/dev/null)
            [ "$euid" != "0" ] && continue
            [ -z "$euid" ] && continue

            # Skip kernel threads (ppid 0 or 2) and PID 1
            [ "$pid" = "1" ] && continue
            ppid=$(awk '/^PPid:/{print $2}' "$status_file" 2>/dev/null)
            [ "$ppid" = "0" ] || [ "$ppid" = "2" ] && continue

            # Must be a descendant of EXPLOIT_PID (the su process)
            if is_descendant "$EXPLOIT_PID" "$pid"; then
                name=$(awk '/^Name:/{print $2}' "$status_file" 2>/dev/null)
                echo "PRIVESC_DETECTED: pid=$pid name=$name euid=0"
                if [ -f /tmp/flag ]; then
                    cat /tmp/flag
                    echo ""
                elif [ -f /flag ]; then
                    cat /flag
                    echo ""
                else
                    dd if=/dev/vdb bs=512 count=1 2>/dev/null | tr -d '\0'
                    echo ""
                fi
                sleep 1
                kill -9 $EXPLOIT_PID 2>/dev/null
                exit 0
            fi
        done
        sleep 0.5
    done
) &
MONITOR_PID=$!

wait $EXPLOIT_PID 2>/dev/null
EXPLOIT_EXIT=$?

# Give monitor a moment to detect late privesc (exploit exited but shell may linger)
sleep 2
kill $MONITOR_PID 2>/dev/null
wait $MONITOR_PID 2>/dev/null

# Keep init alive to avoid "Attempted to kill init!" kernel panic.
# run.sh will kill QEMU after detecting the flag or hitting timeout.
# Also do a final flag check: if exploit got root and exited cleanly,
# it may have left breadcrumbs we can detect.
set +x
# Final attempt: check if any process wrote the flag to stdout already
# If not, check if /tmp/flag is now world-readable (exploit may have chmod'd it)
if [ -f /tmp/flag ] && [ -r /tmp/flag ]; then
    cat /tmp/flag
    echo ""
fi
exec sleep 3600
