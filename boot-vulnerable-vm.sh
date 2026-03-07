#!/bin/bash
# Boot a kernel vulnerable to CVE-2018-18955
# Affected: Linux 4.15.x - 4.19.1 (fixed in 4.19.2)
#
# Login credentials after boot:
#   Username: ubuntu
#   Password: ubuntu

KERNEL_PATH="$HOME/vm-lab/kernel/mainline-4.19.0/extracted/boot/vmlinuz-4.19.0-041900-generic"
IMAGE_PATH="$HOME/vm-lab/images/ubuntu-20.04-server-cloudimg-amd64.img"
CLOUD_INIT_DIR="$HOME/vm-lab/cloud-init"
SEED_ISO="$CLOUD_INIT_DIR/seed.iso"

# Check kernel exists
if [ ! -f "$KERNEL_PATH" ]; then
    echo "ERROR: Vulnerable kernel not found at $KERNEL_PATH"
    exit 1
fi

# Create cloud-init config if not exists
if [ ! -f "$SEED_ISO" ]; then
    echo "[*] Creating cloud-init configuration..."
    mkdir -p "$CLOUD_INIT_DIR"
    
    # Create user-data
    cat > "$CLOUD_INIT_DIR/user-data" << 'EOF'
#cloud-config
password: ubuntu
chpasswd: { expire: False }
ssh_pwauth: True
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: 'ubuntu'
packages:
  - build-essential
  - uidmap
runcmd:
  - systemctl start ssh
  - systemctl enable ssh
  - sysctl -w kernel.unprivileged_userns_clone=1
  - echo "ubuntu:100000:65536" >> /etc/subuid
  - echo "ubuntu:100000:65536" >> /etc/subgid
EOF

    # Create meta-data
    cat > "$CLOUD_INIT_DIR/meta-data" << 'EOF'
instance-id: vulnerable-vm
local-hostname: vulnerable-vm
EOF

    # Create seed.iso
    if command -v genisoimage &> /dev/null; then
        genisoimage -output "$SEED_ISO" -volid cidata -joliet -rock \
            "$CLOUD_INIT_DIR/user-data" "$CLOUD_INIT_DIR/meta-data"
    else
        echo "[-] Need genisoimage: sudo apt install genisoimage"
        exit 1
    fi
fi

echo "=============================================="
echo "  Booting Vulnerable VM (Linux 4.19.0)"
echo "  Login: ubuntu / ubuntu"
echo "  SSH:   ssh -p 2223 ubuntu@127.0.0.1"
echo "  Exit:  Ctrl+A then X"
echo "=============================================="

sudo qemu-system-x86_64 \
    -kernel "$KERNEL_PATH" \
    -hda "$IMAGE_PATH" \
    -cdrom "$SEED_ISO" \
    -append "root=/dev/sda1 console=ttyS0 earlyprintk=serial ro" \
    -m 4G -smp 2 -nographic \
    -netdev user,id=net0,hostfwd=tcp::2223-:22 \
    -device virtio-net-pci,netdev=net0
