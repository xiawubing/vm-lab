# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

This is a **Linux kernel/userspace vulnerability lab** for security research and education. Each `start_vm_CVE-*.sh` script boots a QEMU VM running a specific vulnerable kernel or userspace version, ready for exploit development and testing.

## Architecture

### VM launcher scripts (`start_vm_CVE-*.sh`)

Each script is self-contained and follows a consistent pattern:
1. **Pre-flight checks** — verifies kernel .deb, base image, and tools (qemu-img, genisoimage) exist
2. **FAT disk creation** — packages kernel .deb(s) into a FAT image (`kernel-pkg.img`) so cloud-init installs them without network access
3. **qcow2 overlay** — creates a copy-on-write overlay backed by a read-only base image (delete overlay to reset VM)
4. **cloud-init seed ISO** — generates `seed.iso` with user-data/meta-data for automated VM provisioning (user creation, kernel install, sysctl tuning, reboot)
5. **QEMU boot** — launches VM with GRUB boot (most scripts) or direct `-kernel` boot

All artifacts are created lazily on first run and cached for subsequent boots.

### Key directories

- `images/` — base cloud images (Ubuntu 16.04, 20.04, CentOS 7) and per-CVE working overlays
- `kernel/` — vulnerable kernel packages and source trees organized by version (e.g., `xenial-4.4.0-62/`, `mainline-4.13.0/`)
- `cloud-init/` — per-CVE subdirectories with user-data, meta-data, and seed.iso
- `linux-4.19.1/` — full kernel source tree (for CVE-2018-18955 / CVE-2022-0847 research)

### CVE inventory and SSH ports

| CVE | Type | Kernel/Version | Base OS | SSH Port |
|-----|------|---------------|---------|----------|
| CVE-2017-5123 | waitid() missing access_ok | 4.13.0 | Ubuntu 16.04 | 2225 |
| CVE-2017-6074 | DCCP double-free | 4.4.0-62 | Ubuntu 16.04 | 2226 |
| CVE-2017-7308 | AF_PACKET heap OOB | 4.8.0-41 | Ubuntu 16.04 | 2227 |
| CVE-2017-16995 | BPF verifier sign extension | 4.4.0-116 | Ubuntu 16.04 | 2228 |
| CVE-2017-1000112 | UFO memory corruption | 4.8.0-41 | Ubuntu 16.04 | 2229 |
| CVE-2017-1000367 | sudo tty race (not kernel) | CentOS default | CentOS 7 | 2230 |
| CVE-2018-1000001 | glibc realpath() underflow | Ubuntu default | Ubuntu 16.04.3 | 2224 |
| CVE-2018-18955 | user namespace id mapping | 4.19.0 | Ubuntu 20.04 | 2223 |
| CVE-2022-0847 | Dirty Pipe | 5.10 | Ubuntu 20.04 | 2222 |

### Default credentials

- **Ubuntu VMs**: `ubuntu` / `ubuntu`
- **CentOS VM** (CVE-2017-1000367): `centos` / `centos` (exploit user: `toor` / `toor`)

## Common operations

```bash
# Boot a specific CVE lab
./start_vm_CVE-2017-6074.sh

# SSH into a running VM (use port from table above)
ssh -p 2226 ubuntu@127.0.0.1

# Copy exploit source into VM
scp -P 2226 ~/linux-kernel-exploits/2017/CVE-2017-6074/poc.c ubuntu@127.0.0.1:~/

# Reset a VM to clean state (delete the overlay)
rm ~/vm-lab/images/ubuntu-16.04-cve-2017-6074-working.img

# Exit QEMU console
# Ctrl+A then X
```

## Conventions for new CVE scripts

- Assign a unique SSH port (next available in 222x-223x range)
- Use qcow2 overlays backed by shared base images — never modify base images directly
- Deliver kernel packages via FAT disk image (`-hdb`), not in-VM downloads
- cloud-init handles all provisioning: kernel install, sysctl config, module loading, reboot
- Include detailed vulnerability description and exploit usage in the script header comment
- Boot via GRUB (no `-kernel` flag) when the CVE needs initrd/modules; use `-kernel` only for simple direct-boot cases

## Host dependencies

`qemu-system-x86_64`, `qemu-img`, `genisoimage` (or `cloud-localds`), `mcopy` (mtools), `mkfs.vfat` (dosfstools)

Exploit source files are expected in `~/linux-kernel-exploits/<year>/<CVE>/`.
