#!/bin/bash
# Interactive kernelCTF init: networking, SSH, exploit source, serial console.
#
# This script is executed by the rootfs's /init, which:
#   1. Mounts tmpfs on /tmp
#   2. Mounts 9p "init" tag at /tmp/init
#   3. Runs /tmp/init/init.sh (this script)
#
# IMPORTANT: Do NOT re-mount /tmp — the rootfs's /init already set it up
# and /tmp/init contains our dropbear binaries via 9p.

export PATH=/sbin:/bin:/usr/sbin:/usr/bin

echo "[*] Interactive init starting..."

# Basic filesystem setup (some may already be mounted by initramfs)
mkdir -p /proc /sys /dev /run
mount -t proc none /proc 2>/dev/null || true
mount -t sysfs none /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts 2>/dev/null || true
mount -t tmpfs tmpfs /dev/shm 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true
# NOTE: /tmp is already mounted by rootfs's /init — do NOT remount it

# Hostname from kernel cmdline
HOSTNAME=$(cat /proc/cmdline | tr ' ' '\n' | grep '^hostname=' | cut -d= -f2)
[ -n "$HOSTNAME" ] && hostname "$HOSTNAME"

# Check if root should be locked (agent/benchmark mode)
LOCK_ROOT=false
if cat /proc/cmdline | tr ' ' '\n' | grep -q '^lockroot=1$'; then
    LOCK_ROOT=true
fi

# --- Extract flag from /dev/vdb (benchmark mode) ---
# Flag file is passed as a virtio block device by interactive.sh --flag.
# Write to /tmp/flag with chmod 400 root:root so only euid=0 can read it.
if [ -b /dev/vdb ]; then
    FLAG_CONTENT=$(dd if=/dev/vdb bs=512 count=1 2>/dev/null | tr -d '\0')
    if [ -n "$FLAG_CONTENT" ]; then
        (umask 177; echo -n "$FLAG_CONTENT" > /tmp/flag)
        echo "[+] Flag installed at /tmp/flag (root-only readable)"
    fi
fi

# --- Copy dropbear from 9p mount (do this EARLY, before anything might disturb /tmp) ---
INIT_9P="/tmp/init"
if [ -x "$INIT_9P/dropbear" ]; then
    cp "$INIT_9P/dropbear" /usr/sbin/dropbear
    cp "$INIT_9P/dropbearkey" /usr/sbin/dropbearkey 2>/dev/null || true
    echo "[+] Dropbear binaries copied from 9p mount"
fi

# --- Networking helper functions ---
# The rootfs may have broken shared libraries (e.g. libbpf.so.0 missing for ip,
# libdns-export.so.1110 missing for dhclient). Use ifconfig as fallback.

link_up() {
    ip link set "$1" up 2>/dev/null && return 0
    ifconfig "$1" up 2>/dev/null && return 0
    # Last resort: write directly to sysfs
    echo 1 > "/sys/class/net/$1/flags" 2>/dev/null
    return $?
}

assign_ip() {
    local iface="$1" addr="$2" gw="$3"
    ip addr add "$addr" dev "$iface" 2>/dev/null || \
        ifconfig "$iface" "$(echo "$addr" | cut -d/ -f1)" netmask 255.255.255.0 2>/dev/null
    ip route add default via "$gw" 2>/dev/null || \
        route add default gw "$gw" 2>/dev/null
    echo "nameserver 10.0.2.3" > /etc/resolv.conf
}

# --- Networking ---
echo "[*] Setting up networking..."
link_up lo

# Dynamic interface detection: find a real network interface
# Skip loopback and virtual interfaces (bond*, br*, veth*, docker*, virbr*)
IFACE=""
for candidate in $(ls /sys/class/net/ 2>/dev/null); do
    case "$candidate" in
        lo|bond*|br*|veth*|docker*|virbr*) continue ;;
    esac
    # Prefer interfaces with a device backing (real hardware/virtio)
    if [ -e "/sys/class/net/$candidate/device" ]; then
        IFACE="$candidate"
        break
    fi
done
# Fallback: first non-loopback, non-virtual interface
if [ -z "$IFACE" ]; then
    for candidate in $(ls /sys/class/net/ 2>/dev/null); do
        case "$candidate" in
            lo|bond*|br*|veth*|docker*|virbr*) continue ;;
        esac
        IFACE="$candidate"
        break
    done
fi

if [ -n "$IFACE" ]; then
    link_up "$IFACE"
    sleep 1

    # Try DHCP first (QEMU user networking provides DHCP)
    DHCP_OK=false
    if command -v dhclient &>/dev/null; then
        dhclient "$IFACE" 2>/dev/null &
        DHCP_PID=$!
        sleep 3
        # Check if dhclient succeeded (interface has an IP)
        if ip addr show "$IFACE" 2>/dev/null | grep -q "inet " || \
           ifconfig "$IFACE" 2>/dev/null | grep -q "inet "; then
            DHCP_OK=true
        else
            kill "$DHCP_PID" 2>/dev/null
        fi
    fi
    if ! $DHCP_OK && command -v udhcpc &>/dev/null; then
        udhcpc -i "$IFACE" -q 2>/dev/null &
        sleep 2
        if ip addr show "$IFACE" 2>/dev/null | grep -q "inet " || \
           ifconfig "$IFACE" 2>/dev/null | grep -q "inet "; then
            DHCP_OK=true
        fi
    fi
    if ! $DHCP_OK; then
        # Manual config for QEMU user networking (default gateway 10.0.2.2)
        echo "[*] DHCP failed, using manual IP config"
        assign_ip "$IFACE" "10.0.2.15/24" "10.0.2.2"
    fi
    echo "[+] Network interface $IFACE configured"
else
    echo "[!] No network interface found"
fi

# --- User accounts ---
echo "[*] Setting up users..."
if ! id user &>/dev/null; then
    useradd -m -s /bin/bash user 2>/dev/null
else
    usermod -s /bin/bash user 2>/dev/null
fi
echo "user:user" | chpasswd 2>/dev/null
if $LOCK_ROOT; then
    passwd -l root 2>/dev/null || usermod -L root 2>/dev/null || true
    echo "[*] Root password locked (agent mode)"
else
    echo "root:root" | chpasswd 2>/dev/null
fi

# --- SSH ---
echo "[*] Setting up SSH..."
SSH_STARTED=false

if [ -x /usr/sbin/dropbear ]; then
    mkdir -p /etc/dropbear
    if [ -x /usr/sbin/dropbearkey ]; then
        # Pre-generate ALL key types to avoid -R race conditions.
        # With -R, Dropbear generates missing keys on first connection, which
        # can cause "EOF during negotiation" for concurrent/subsequent clients
        # that negotiate a key type still being generated.
        /usr/sbin/dropbearkey -t rsa    -f /etc/dropbear/dropbear_rsa_host_key    2>/dev/null
        /usr/sbin/dropbearkey -t ecdsa  -f /etc/dropbear/dropbear_ecdsa_host_key  2>/dev/null
        /usr/sbin/dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key 2>/dev/null
    fi
    # -B: allow blank passwords (we set passwords above, but just in case)
    # No -R needed: all key types are pre-generated above
    /usr/sbin/dropbear -B -p 22 2>/dev/null
    echo "[+] Dropbear SSH started on port 22 (all host keys pre-generated)"
    SSH_STARTED=true
elif command -v sshd &>/dev/null; then
    mkdir -p /run/sshd /etc/ssh
    for type in rsa ecdsa ed25519; do
        keyfile="/etc/ssh/ssh_host_${type}_key"
        [ -f "$keyfile" ] || ssh-keygen -t "$type" -f "$keyfile" -N "" -q 2>/dev/null
    done
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null
    /usr/sbin/sshd 2>/dev/null
    echo "[+] OpenSSH server started"
    SSH_STARTED=true
else
    echo "[!] No SSH server available — use serial console"
    echo "[!] Run kernelctf/setup.sh to build dropbear"
fi

# --- Exploit workspace ---
mkdir -p /home/user/exploit
mount -t 9p exp /home/user/exploit -o trans=virtio 2>/dev/null && \
    echo "[+] Exploit workspace at /home/user/exploit/ (writable)" || \
    echo "[!] No exploit workspace mounted"
chown -R user:user /home/user 2>/dev/null

# --- Ready ---
echo ""
echo "=========================================="
echo "  Kernel: $(uname -r)"
if $LOCK_ROOT; then
    echo "  user / user  (root locked)"
else
    echo "  user / user  |  root / root"
fi
echo "  Exploit dir:  /home/user/exploit/"
if $SSH_STARTED; then
    echo "  SSH:          ready"
fi
echo "  Ctrl+A X to quit QEMU"
echo "=========================================="
echo ""

# Interactive shell loop (always as unprivileged user; use 'su root' if needed)
while true; do
    setsid su -s /bin/bash - user </dev/console >/dev/console 2>&1 || su -s /bin/bash - user
    echo ""
    echo "[*] Shell exited. Press Enter for new shell, Ctrl+A X to quit."
    read -t 30 || break
done
