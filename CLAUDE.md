# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

This is a **Linux kernel/userspace vulnerability lab** for security research and education. It provides:
1. QEMU VMs running specific vulnerable kernel versions, ready for exploit development
2. A Docker-based agent system where Claude Code can autonomously compile and run exploits against the VMs via MCP tools

## Repository structure

```
vm-lab/
├── run.sh                    # Top-level orchestrator (boots VM + launches agent container)
├── setup.sh                  # Downloads base images, kernel packages, installs host deps
├── vm_controller.py          # HTTP REST service for VM lifecycle management (port 8222)
├── boot-vulnerable-vm.sh     # Standalone boot script (CVE-2018-18955 only)
├── cve-registry.json         # Central CVE metadata (ports, credentials, kernels, scripts)
├── vm-scripts/               # Per-CVE VM launcher scripts
│   └── start_vm_CVE-*.sh     # Self-contained QEMU boot scripts (9 total)
├── cloud-init/               # Per-CVE cloud-init provisioning configs
│   └── CVE-*/                # user-data, meta-data, seed.iso per CVE
├── agent-container/          # Docker-based exploit development agent
│   ├── Dockerfile            # Ubuntu 22.04 + build tools + Claude Code CLI
│   ├── docker-compose.yml    # Container orchestration config
│   ├── entrypoint.sh         # Container startup (validates env, launches Claude)
│   ├── mcp_ssh_server.py     # MCP server exposing SSH/SFTP/VM-control tools
│   ├── stream_filter.py      # Formats Claude's JSON stream output for terminal
│   ├── .mcp.json             # MCP server registration
│   ├── CLAUDE.md             # Agent-specific workflow documentation
│   ├── requirements.txt      # Python deps (fastmcp, paramiko)
│   └── cve-info/             # Per-CVE PoC documentation and exploit code
│       └── CVE-*.md          # Vulnerability details, PoC source, compile flags
├── images/                   # (gitignored) Base cloud images + per-CVE qcow2 overlays
├── kernel/                   # (gitignored) Vulnerable kernel .deb packages
└── kernelctf/                # kernelCTF exploit testing infrastructure
    ├── run.sh                # Compile + run exploit against kernelCTF VM (automated)
    ├── interactive.sh        # Boot kernelCTF VM with SSH + writable overlay (debug)
    ├── qemu.sh               # Low-level QEMU launcher (called by run.sh)
    ├── setup.sh              # Download kernelCTF base images and release bzImages
    ├── releases/             # Per-release kernel bzImages (e.g. mitigation-6.1-v2/)
    ├── images/               # rootfs_repro_v2.img, rootfs_v3.img, ramdisk_v1.img, overlays
    ├── exp/                  # Compiled exploit binary (written by run.sh, read-only 9p mount)
    ├── exp-interactive/      # Exploit source for interactive mode (writable 9p mount)
    ├── init/init.sh          # Non-interactive init: mounts exp via 9p, runs exploit as user
    ├── init-interactive/init.sh  # Interactive init: SSH, networking, shell loop
    ├── patches/cbq_compat.h  # Compat shim for CBQ netlink structs (applied by run.sh)
    └── logs/                 # VM output logs and flag files
```

## Architecture

### End-to-end workflow

```
./run.sh CVE-2017-6074
    │
    ├── Reads cve-registry.json for CVE metadata
    ├── Starts vm_controller.py (HTTP API on port 8222)
    ├── Launches Docker agent container
    │       │
    │       ├── entrypoint.sh validates VM connectivity
    │       ├── Starts MCP SSH server (mcp_ssh_server.py)
    │       └── Launches Claude Code with CVE-specific prompt
    │               │
    │               ├── Reads /app/cve-info/CVE-*.md
    │               ├── Calls MCP tools (vm_execute, vm_compile_and_run, vm_run_exploit)
    │               │       │
    │               │       ├── SSH/SFTP to QEMU VM (paramiko)
    │               │       └── HTTP to vm_controller.py (start/stop/restart)
    │               └── Reports exploit results
    │
    └── vm-scripts/start_vm_CVE-*.sh boots the QEMU VM
```

### VM launcher scripts (`vm-scripts/start_vm_CVE-*.sh`)

Each script is self-contained and follows a consistent pattern:
1. **Pre-flight checks** — verifies kernel .deb, base image, and tools (qemu-img, genisoimage) exist
2. **FAT disk creation** — packages kernel .deb(s) into a FAT image (`kernel-pkg.img`) so cloud-init installs them without network access
3. **qcow2 overlay** — creates a copy-on-write overlay backed by a read-only base image (delete overlay to reset VM)
4. **cloud-init seed ISO** — generates `seed.iso` with user-data/meta-data for automated VM provisioning (user creation, kernel install, sysctl tuning, reboot)
5. **QEMU boot** — launches VM with GRUB boot (most scripts) or direct `-kernel` boot

All artifacts are created lazily on first run and cached for subsequent boots.

### VM controller (`vm_controller.py`)

HTTP REST service running on the host (port 8222) for VM lifecycle management:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/status` | GET | Check if QEMU is running, get PID |
| `/start` | POST | Start the VM, wait for SSH readiness |
| `/stop` | POST | Kill QEMU process |
| `/restart` | POST | Stop + start + wait for SSH |
| `/log` | GET | Get last 50 lines of VM boot output |

Configured via `--cve` argument; reads `cve-registry.json` for script/port mapping.

### MCP SSH server (`agent-container/mcp_ssh_server.py`)

FastMCP server exposing these tools to the Claude Code agent inside Docker:

| Tool | Purpose |
|------|---------|
| `vm_check_status()` | Get kernel version via SSH |
| `vm_execute(command, timeout)` | Run shell command on VM |
| `vm_upload_file(local, remote)` | SFTP upload to VM |
| `vm_download_file(remote, local)` | SFTP download from VM |
| `vm_compile_and_run(source_code, filename, compile_flags, run_timeout, upload_only)` | Compile C code on VM, optionally run |
| `vm_run_exploit(binary, success_marker, failure_marker, poll_timeout, poll_interval, max_retries)` | Run exploit with auto-retry and VM restart on crash |
| `vm_start()` / `vm_stop()` / `vm_restart()` | VM lifecycle via controller HTTP API |

### CVE registry (`cve-registry.json`)

Central metadata for all CVEs. Each entry contains:
- `script` — VM launcher script name (in `vm-scripts/`)
- `ssh_port`, `ssh_user`, `ssh_password` — VM connection details
- `base_os` — Ubuntu 16.04, 20.04, or CentOS 7
- `kernel` — vulnerable kernel version string
- `kernel_source_url`, `kernel_source_dir` — for optional kernel source download
- `type` — vulnerability description

### Key directories

- `images/` — (gitignored) base cloud images (Ubuntu 16.04, 20.04, CentOS 7) and per-CVE working overlays
- `kernel/` — (gitignored) vulnerable kernel packages organized by version (e.g., `xenial-4.4.0-62/`, `mainline-4.13.0/`)
- `cloud-init/` — per-CVE subdirectories with user-data, meta-data, and seed.iso
- `agent-container/cve-info/` — per-CVE markdown files with PoC source code, compile flags, and success/failure markers

## kernelCTF infrastructure (`kernelctf/`)

A separate subsystem for testing exploits against official [kernelCTF](https://google.github.io/security-research/kernelctf/rules.html) release kernels. It mirrors the kernelCTF reproduction environment locally.

### Workflow

```
kernelctf/run.sh CVE-2023-0461_mitigation
    │
    ├── Reads exploit source from ~/security-research/pocs/linux/kernelctf/<CVE>/exploit/<release>/
    ├── Copies + patches source into kernelctf/exp/ (cbq_compat.h, keyutils.h stub, getroot() patch)
    ├── Compiles: gcc -I. -o exploit exploit.c -O0 -static -s
    ├── Generates a unique flag: kernelCTF{<uuid>} written to kernelctf/logs/flag
    ├── Launches kernelctf/qemu.sh (up to 3 retries, 120s timeout each)
    │       │
    │       ├── Boots bzImage from kernelctf/releases/<release>/
    │       ├── Mounts rootfs_repro_v2.img (read-only), ramdisk_v1.img as initrd
    │       ├── Passes flag file as /dev/vdb (virtio block device)
    │       ├── Mounts kernelctf/exp/ via 9p (mount_tag=exp, read-only)
    │       └── Runs kernelctf/init/init.sh as init=
    │               └── Runs /tmp/exp/exploit as unprivileged user
    │
    └── Polls VM output for the flag string → reports SUCCESS or FAILURE
```

### Scripts

| Script | Purpose |
|--------|---------|
| `kernelctf/run.sh <cve-dir> [release]` | Compile, patch, and run exploit; up to 3 retries |
| `kernelctf/interactive.sh <cve-or-release> [--port PORT] [--reset] [--nokaslr]` | Boot with SSH, writable overlay, exploit source at `/home/user/exploit/` |
| `kernelctf/qemu.sh <release-dir> <flag-file>` | Raw QEMU launcher (called by run.sh) |
| `kernelctf/setup.sh [release...] [--deps] [--list]` | Download rootfs/ramdisk/bzImage from `storage.googleapis.com/kernelctf-build` |

### Key design details

- **Source patching**: `run.sh` automatically injects `cbq_compat.h`, a `keyutils.h` syscall stub, and patches `getroot()` to read `/flag` (via `/dev/vdb`) and print it — avoiding interactive bash which would block automated runs.
- **Mitigation kernel hardening**: when `RELEASE` starts with `mitigation-`, QEMU cmdline adds `dmesg_restrict=1`, `kptr_restrict=2`, `unprivileged_bpf_disabled=2`, `slab_virtual=1`, etc.
- **Interactive mode overlays**: `interactive.sh` creates a qcow2 overlay backed by `rootfs_repro_v2.img` for a persistent writable session. Delete the overlay (`kernelctf/images/<release>-interactive.qcow2`) to reset.
- **Exploit source location**: CVE exploit sources live in `~/security-research/pocs/linux/kernelctf/<CVE>/exploit/<release>/` (separate repo, not in vm-lab).
- **Credentials (interactive)**: `user` / `user` and `root` / `root`; SSH port default 2250.

### Common operations

```bash
# Run exploit automatically (compile + VM + flag check)
cd kernelctf && ./run.sh CVE-2023-0461_mitigation

# Download base images + a specific release bzImage
cd kernelctf && ./setup.sh mitigation-6.1-v2

# Boot interactive VM for manual debugging
cd kernelctf && ./interactive.sh CVE-2023-0461_mitigation --nokaslr
ssh -p 2250 user@127.0.0.1

# List available CVEs in security-research repo
cd kernelctf && ./interactive.sh --list

# Reset interactive overlay to clean state
rm kernelctf/images/mitigation-6.1-v2-interactive.qcow2
```

## CVE inventory

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
# Full automated run: boot VM + launch agent container
./run.sh CVE-2017-6074

# Interactive shell instead of agent
AGENT=shell ./run.sh CVE-2017-6074

# Download all base images and kernel packages
./setup.sh

# Download artifacts for a single CVE
./setup.sh 6074

# Install only host dependencies
./setup.sh --deps

# List available CVEs
./setup.sh --list

# Boot a VM manually (without the agent)
./vm-scripts/start_vm_CVE-2017-6074.sh

# SSH into a running VM (use port from table above)
ssh -p 2226 ubuntu@127.0.0.1

# Copy exploit source into VM
scp -P 2226 exploit.c ubuntu@127.0.0.1:~/

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
- Add the new CVE to `cve-registry.json` with all required fields
- Create a corresponding `agent-container/cve-info/CVE-*.md` with PoC details, compile flags, and success/failure markers
- Place the VM launcher script in `vm-scripts/`

## Conventions for the agent container

- Agent-created files use the `agent_` prefix (e.g., `agent_poc.c`)
- The MCP server handles auto-retry for semi-reliable kernel exploits — do not manually retry in agent logic
- The agent runs as non-root user `agent` (UID 1000) since Claude Code refuses to run as root
- Claude Code is invoked with `claude-sonnet-4-6` model, `--max-budget-usd 5.00`

## Anti-patterns (do NOT do these)

<!-- Add lessons learned here. Every time Claude makes a mistake, add a line so it never happens again. -->

### VM and QEMU
- Do NOT modify base images directly — always use qcow2 overlays
- Do NOT hardcode SSH ports — always read from `cve-registry.json`
- Do NOT use `-kernel` boot for CVEs that need initrd/modules — use GRUB boot instead
- Do NOT delete a qcow2 overlay while the VM is running — stop the VM first
- Do NOT assume VMs boot instantly — cloud-init provisioning can take 30+ seconds after SSH becomes available

### Exploit development
- Do NOT assume x86_64 syscall numbers on i386 kernels — check `unistd_32.h`
- Do NOT compile exploits with optimization (`-O2`) by default — use `-O0` or flags from the CVE info file to preserve intended behavior
- Do NOT assume kernel symbols are readable — check `/proc/kallsyms` access (may require root or `kptr_restrict=0`)
- Do NOT run untested exploit code as root — always test as unprivileged user first, privilege escalation is the exploit's job

### Agent container
- Do NOT manually retry kernel exploits in agent logic — the MCP `vm_run_exploit` tool handles auto-retry and VM restart on crash
- Do NOT use `apt` on CentOS VMs — use `yum`
- Do NOT forget the `agent_` prefix for agent-created files

### Scripts and infrastructure
- Do NOT download kernel packages inside the VM — deliver them via FAT disk image (`-hdb`)
- Do NOT create cloud-init configs that require network access — VMs are air-gapped
- Do NOT reuse SSH ports across CVEs — each CVE gets a unique port from the 222x-223x range

## Debugging notes

<!-- Common issues and their solutions. Add entries as you encounter and solve problems. -->

- **VM hangs at boot**: check cloud-init `user-data` for YAML syntax errors first
- **SSH connection refused after VM starts**: wait 30s — cloud-init may still be installing kernel packages and rebooting
- **Exploit compiles but segfaults**: check kernel ASLR/SMEP/SMAP status (`cat /proc/cpuinfo | grep smep`, `cat /proc/sys/kernel/randomize_va_space`) before debugging the code
- **VM kernel panic on exploit run**: this is expected for some exploits — use `vm_run_exploit` with `max_retries` to auto-restart and retry
- **`genisoimage` not found**: run `./setup.sh --deps` to install host dependencies
- **qcow2 overlay corrupted**: delete the overlay file in `images/` and reboot — it will be recreated from the base image

## Host dependencies

`qemu-system-x86_64`, `qemu-img`, `genisoimage` (or `cloud-localds`), `mcopy` (mtools), `mkfs.vfat` (dosfstools), `docker`, `docker-compose`, `sshpass`

The `setup.sh` script can install these automatically via `./setup.sh --deps`.
