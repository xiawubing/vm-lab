#!/bin/bash
# Interactive kernelCTF init: networking, SSH, exploit source, serial console.

export PATH=/sbin:/bin:/usr/sbin:/usr/bin

echo "[*] Interactive init starting..."

# Basic filesystem setup (some may already be mounted by initramfs)
mkdir -p /proc /sys /dev /tmp /run
mount -t proc none /proc 2>/dev/null || true
mount -t sysfs none /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts 2>/dev/null || true
mount -t tmpfs tmpfs /dev/shm 2>/dev/null || true
mount -t tmpfs tmpfs /tmp 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true

# Hostname from kernel cmdline
HOSTNAME=$(cat /proc/cmdline | tr ' ' '\n' | grep '^hostname=' | cut -d= -f2)
[ -n "$HOSTNAME" ] && hostname "$HOSTNAME"

# --- Networking ---
echo "[*] Setting up networking..."
ip link set lo up 2>/dev/null

# Try common interface names
for iface in eth0 ens3 enp0s3; do
    if ip link show "$iface" &>/dev/null; then
        ip link set "$iface" up 2>/dev/null
        # Try DHCP first (QEMU user networking provides DHCP)
        if command -v dhclient &>/dev/null; then
            dhclient "$iface" 2>/dev/null &
            sleep 2
        else
            # Manual config for QEMU user networking
            ip addr add 10.0.2.15/24 dev "$iface" 2>/dev/null
            ip route add default via 10.0.2.2 2>/dev/null
            echo "nameserver 10.0.2.3" > /etc/resolv.conf
        fi
        echo "[+] Network interface $iface up"
        break
    fi
done

# --- User accounts ---
echo "[*] Setting up users..."
# Ensure user exists with bash shell
if ! id user &>/dev/null; then
    useradd -m -s /bin/bash user 2>/dev/null
else
    usermod -s /bin/bash user 2>/dev/null
fi
echo "user:user" | chpasswd 2>/dev/null
echo "root:root" | chpasswd 2>/dev/null

# --- SSH ---
if ! command -v sshd &>/dev/null; then
    echo "[*] Installing SSH server (first boot only, needs ~30s)..."
    # Wait for DHCP/network to be ready
    for i in $(seq 1 10); do
        if ping -c1 -W1 10.0.2.2 &>/dev/null; then break; fi
        sleep 1
    done
    apt-get update -qq 2>/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server 2>&1 | tail -3
fi

if command -v sshd &>/dev/null; then
    mkdir -p /run/sshd /etc/ssh
    # Generate host keys if needed
    for type in rsa ecdsa ed25519; do
        keyfile="/etc/ssh/ssh_host_${type}_key"
        [ -f "$keyfile" ] || ssh-keygen -t "$type" -f "$keyfile" -N "" -q 2>/dev/null
    done
    # Allow password auth and root login
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null
    /usr/sbin/sshd 2>/dev/null
    echo "[+] SSH server started"
else
    echo "[!] SSH not available — use serial console"
fi

# --- Exploit source ---
mkdir -p /home/user/exploit
mount -t 9p exp /home/user/exploit -o trans=virtio 2>/dev/null && \
    echo "[+] Exploit source at /home/user/exploit/" || \
    echo "[!] No exploit source mounted"
chown -R user:user /home/user 2>/dev/null

# --- Ready ---
echo ""
echo "=========================================="
echo "  Kernel: $(uname -r)"
echo "  user / user  |  root / root"
echo "  Exploit dir:  /home/user/exploit/"
echo "  Ctrl+A X to quit QEMU"
echo "=========================================="
echo ""

# Interactive shell loop
while true; do
    setsid bash -l </dev/console >/dev/console 2>&1 || bash -l
    echo ""
    echo "[*] Shell exited. Press Enter for new shell, Ctrl+A X to quit."
    read -t 30 || break
done
