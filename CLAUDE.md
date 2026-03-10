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
└── kernel/                   # (gitignored) Vulnerable kernel .deb packages
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

## Host dependencies

`qemu-system-x86_64`, `qemu-img`, `genisoimage` (or `cloud-localds`), `mcopy` (mtools), `mkfs.vfat` (dosfstools), `docker`, `docker-compose`, `sshpass`

The `setup.sh` script can install these automatically via `./setup.sh --deps`.
