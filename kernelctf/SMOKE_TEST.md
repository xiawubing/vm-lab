# kernelCTF Interactive Smoke Test

End-to-end test that compiles a patched exploit, boots an interactive VM with a flag file,
deploys the binary via 9p, sets up shell_trap, runs the exploit via SSH, and verifies
the flag was printed (proving root privilege escalation).

## Quick start

```bash
# Full compile + test (recommended for first run)
./smoke_test.sh CVE-2023-6560_mitigation

# Skip compilation (reuse exp/ from previous run)
./smoke_test.sh CVE-2023-6560_mitigation --skip-compile

# Debug mode (KASLR disabled, more attempts)
./smoke_test.sh CVE-2024-0193_mitigation --nokaslr --max-attempts 10
```

## How it works

```
smoke_test.sh CVE-XXXX_mitigation
    │
    ├── Step 1: Compile exploit (run.sh patching logic)
    │   ├── Copy source from ~/security-research/pocs/linux/kernelctf/
    │   ├── Inject cbq_compat.h, keyutils.h stub
    │   ├── Patch getroot() to read /tmp/flag instead of spawning shell
    │   ├── Compile with Makefile (prerequisites if needed) or fallback gcc
    │   └── Compile shell_trap (bind-mount shim for /bin/sh)
    │
    ├── Retry loop (up to --max-attempts):
    │   ├── Step 2: Generate unique flag → logs/smoke_flag
    │   ├── Step 3: Boot interactive VM (--reset, --flag, background)
    │   │   └── interactive.sh copies source to exp-interactive/, boots QEMU
    │   ├── Step 4: Deploy compiled binaries to exp-interactive/ via 9p
    │   │   └── Overwrites raw source with patched+compiled exploit + shell_trap
    │   │       (9p pass-through = instant visibility in VM)
    │   ├── Step 5: Wait for SSH (poll sshpass every 2s, max 90s)
    │   ├── Step 6: SSH as root → set up shell_trap
    │   │   └── cp /bin/sh /tmp/sh.real; mount --bind shell_trap /bin/sh /bin/bash
    │   ├── Step 7: SSH as user → run exploit
    │   │   └── timeout $EXPLOIT_TIMEOUT sshpass ssh user './exploit'
    │   └── Verify: check SSH output + serial log + remote /tmp/flag for flag
    │
    └── Report: SUCCESS (flag source, duration) or FAILED (logs)
```

## Flag verification (3-tier)

1. **SSH output** (primary): patched getroot() reads /tmp/flag and printf's it to stdout,
   captured by SSH client. Works when kernel survives.
2. **Serial log** (fallback): shell_trap prints flag to /dev/console when intercepting
   post-exploit /bin/sh. Survives kernel panic (serial is QEMU pipe, not TCP).
3. **Remote /tmp/flag** (last resort): if VM is alive, SSH in and try to read
   /tmp/flag in case exploit made it world-readable.

## Problems identified and solutions

### Problem 1: interactive.sh overwrites exp-interactive/

**Symptom**: Compiled exploit binary and shell_trap copied to `exp-interactive/` are
deleted when `interactive.sh` starts.

**Root cause**: `interactive.sh` lines 209-211 do `rm -rf "$EXP_DIR"/*` then copy
raw (unpatched) source from the security-research repo.

**Solution**: Deploy compiled binaries AFTER `interactive.sh` starts (but before the
VM mounts 9p). Since 9p is a pass-through filesystem, changes on the host are
instantly visible in the VM. The smoke test sleeps 3s for interactive.sh to finish
prep work, then copies `exp/exploit` and `exp/shell_trap` to `exp-interactive/`.

### Problem 2: shell_trap not set up in interactive mode

**Symptom**: init-interactive/init.sh does NOT bind-mount shell_trap over /bin/sh.
Only the non-interactive init/init.sh does this.

**Root cause**: Interactive mode is designed for manual debugging, not automated testing.

**Solution**: SSH as root to set up shell_trap before running the exploit:
```bash
ssh root@VM 'cp /bin/sh /tmp/sh.real && mount --bind shell_trap /bin/sh /bin/bash'
```
This must happen BEFORE the exploit runs. After shell_trap is mounted, subsequent
SSH commands use /tmp/sh.real (via shell_trap's transparent passthrough for non-root).

### Problem 3: SSH output lost on kernel panic

**Symptom**: Exploit achieves root but kernel panics before SSH relays stdout.
Flag is never captured.

**Root cause**: SSH uses TCP which requires ACKs. Kernel panic kills the network
stack before pending TCP segments are acknowledged. Serial console (QEMU pipe to
host) is not affected by kernel panics.

**Solution**: The smoke test checks BOTH SSH output and serial log for the flag.
The patched getroot() does `printf()` which goes to SSH stdout. Shell_trap also
`printf()`s to stdout. If the kernel panics mid-output, the serial log may have
partial output that includes the flag.

### Problem 4: CVE-2024-0193 exploit unreliable in interactive mode

**Symptom**: Exploit consistently causes "kernel tried to execute NX-protected page"
with uid=1000 (never achieves root) in interactive mode. Works intermittently in
non-interactive mode (but with false positives — see Problem 5).

**Root cause**: The interactive VM has a richer kernel state (networking, DHCP, SSH
server, user shell) which changes the slab heap layout. The nftables UAF exploit's
heap spray assumes a minimal environment. The KASLR bypass ("majority vote") also
fails consistently, causing the exploit to use an incorrect kernel base address.

Additionally, recompilation with locally-built libmnl/libnftnl produces a different
binary than the original author's pre-compiled version. Our recompiled binary never
achieves uid=0, while the pre-compiled binary sometimes does (but still crashes).

**Status**: Known limitation. Use CVE-2023-6560_mitigation for smoke testing instead.

### Problem 5: init/init.sh false positive in run.sh mode

**Symptom**: run.sh reports SUCCESS for CVE-2024-0193 but the exploit didn't actually
achieve root privilege escalation.

**Root cause**: init/init.sh's final check (lines 141-144) runs `cat /tmp/flag` as
PID 1 (root). Since root can always read the file (chmod 400 root:root), the flag is
printed regardless of whether the exploit succeeded. run.sh detects the flag in the
serial log and declares success.

**Evidence**: The "successful" run showed "majority vote failed" (KASLR bypass failed),
exit code 141 (SIGPIPE), and no "PRIVESC_DETECTED" from the monitor. The flag was
printed by init.sh's root-privileged final check, not by the exploit.

**Fix needed**: init/init.sh's final check should verify that the exploit's user can
read /tmp/flag (e.g., `su user -c 'cat /tmp/flag'`), not that PID 1 can.

## Tested CVEs

| CVE | Release | Result | Notes |
|-----|---------|--------|-------|
| CVE-2023-6560_mitigation | mitigation-v4-6.6 | **PASS** (2/2, 1st attempt) | io_uring exploit, ~88s, very reliable |
| CVE-2024-0193_mitigation | mitigation-v3-6.1.55 | **FAIL** (0/13 attempts) | nftables UAF, always kernel panic in interactive mode |

## Options reference

| Option | Default | Description |
|--------|---------|-------------|
| `--timeout SECS` | 180 | Total test timeout |
| `--exploit-timeout SECS` | 90 | Per-exploit execution timeout |
| `--max-attempts N` | 3 | Max retry attempts |
| `--nokaslr` | off | Disable KASLR (debugging) |
| `--skip-compile` | off | Reuse existing exp/ binaries |
| `--port PORT` | 2250 | SSH port for VM |
| `--no-shell-trap` | off | Skip shell_trap setup |

## Files

| File | Purpose |
|------|---------|
| `smoke_test.sh` | Main test script |
| `logs/smoke_serial_*.txt` | VM serial console output per attempt |
| `logs/smoke_exploit_*.txt` | Exploit SSH stdout per attempt |
| `logs/smoke_flag` | Current flag file (passed to VM as /dev/vdb) |
| `exp/` | Compiled exploit + shell_trap (populated by smoke_test.sh or run.sh) |
| `exp-interactive/` | 9p-shared directory mounted at /home/user/exploit/ in VM |

---

## Manual interactive tutorial

手动交互式验证流程。需要 **两个终端**（Terminal A 运行 VM，Terminal B 在 host 上操作）。

### 前置知识

```
Host (WSL2)                          VM (QEMU)
┌──────────────────┐                ┌──────────────────┐
│ kernelctf/       │                │                  │
│   exp-interactive/│───── 9p ─────▶│ /home/user/      │
│     exploit       │  (pass-through)│   exploit/       │
│     shell_trap    │               │     exploit      │
│                  │                │     shell_trap   │
│ /tmp/myflag      │── /dev/vdb ──▶│ /tmp/flag        │
│                  │  (virtio blk)  │ (chmod 400 root) │
└──────────────────┘                └──────────────────┘
```

- `exp-interactive/` 通过 9p 挂载到 VM 的 `/home/user/exploit/`，**host 上改文件 VM 里立刻可见**
- flag 通过 virtio block device 传入 VM，init 脚本自动提取到 `/tmp/flag` (只有 root 能读)
- **串口比 SSH 可靠**：kernel panic 时 TCP 包会丢，串口是 QEMU 直接 pipe 到终端不会丢

### Step 0: 编译打补丁的 exploit

用 `smoke_test.sh` 的编译步骤（只编译不跑 VM）或 `run.sh`：

```bash
cd ~/vm-lab/kernelctf

# 方法 A: 用 smoke_test.sh 编译后 Ctrl+C（编译完会自动进入 VM 启动阶段）
./smoke_test.sh CVE-2023-6560_mitigation --max-attempts 0
# 编译完成后 exp/ 目录有: exploit (patched), shell_trap

# 方法 B: 用 run.sh 编译（它会启动 VM 跑测试，编译完可以 Ctrl+C）
./run.sh CVE-2023-6560_mitigation
# Ctrl+C 中断（exploit 和 shell_trap 已经在 exp/ 里了）

# 确认产物
ls -la exp/exploit exp/shell_trap
file exp/exploit   # 应该是 statically linked ELF
```

编译做了什么：
1. 从 `~/security-research/` 复制源码到 `exp/`
2. 注入 `cbq_compat.h`、`keyutils.h` stub
3. **patch_shell_spawn.py** 把 `getroot()` 里的 `execve("/bin/sh")` 替换为读 `/tmp/flag` 并 `printf`
4. `gcc -static` 编译
5. 编译 `shell_trap`（bind-mount 到 `/bin/sh` 的 flag 读取 shim）

### Step 1: 创建 flag 文件

```bash
# Terminal B (host)
echo -n "kernelCTF{manual-test-$(date +%s)}" > /tmp/myflag
cat /tmp/myflag   # 记住这个 flag，后面验证用
```

### Step 2: 启动 interactive VM

```bash
# Terminal A (host) — 这个终端会变成 VM 的串口控制台
cd ~/vm-lab/kernelctf
./interactive.sh CVE-2023-6560_mitigation --flag /tmp/myflag --reset
```

等待看到：
```
==========================================
  Kernel: 6.6.0+
  user / user  |  root / root
  Exploit dir:  /home/user/exploit/
  SSH:          ready
  Ctrl+A X to quit QEMU
==========================================

user@mitigation-v4-6:~$
```

> **注意**: `interactive.sh` 启动时会把 security-research 的原始源码复制到
> `exp-interactive/`，**覆盖之前的文件**。所以必须在 VM 启动后（下一步）再部署编译产物。

### Step 3: 部署编译好的 exploit（host 端，9p 即时生效）

```bash
# Terminal B (host) — VM 启动后立刻执行
cd ~/vm-lab/kernelctf
cp exp/exploit exp-interactive/exploit
cp exp/shell_trap exp-interactive/shell_trap
chmod +x exp-interactive/exploit exp-interactive/shell_trap

# 验证（可选）
ls -la exp-interactive/
```

因为 9p 是 pass-through，VM 里 `/home/user/exploit/` 会立刻看到新的二进制文件。

### Step 4: 设置 shell_trap（VM 串口控制台 或 SSH）

#### 方法 A: 串口控制台（Terminal A，更可靠）

在 Terminal A 的串口控制台里：

```bash
# 当前是 user，先切 root
su root
# 密码: root

# 备份真实 shell
cp /bin/sh /tmp/sh.real
chmod +x /tmp/sh.real

# bind-mount shell_trap
mount --bind /home/user/exploit/shell_trap /bin/sh
mount --bind /home/user/exploit/shell_trap /bin/bash

# 验证
ls -la /bin/sh   # 大小应该和 shell_trap 一样
cat /tmp/flag     # 确认 flag 在（root 能读）

# 切回 user（用 /tmp/sh.real 避免触发 shell_trap）
su user -s /tmp/sh.real
```

#### 方法 B: SSH（Terminal B）

```bash
# Terminal B (host)
# 设置 shell_trap
sshpass -p root ssh -o StrictHostKeyChecking=no -p 2250 root@127.0.0.1 \
  'cp /bin/sh /tmp/sh.real && chmod +x /tmp/sh.real && \
   mount --bind /home/user/exploit/shell_trap /bin/sh && \
   mount --bind /home/user/exploit/shell_trap /bin/bash && \
   echo "shell_trap OK"'
```

> **shell_trap 的工作原理**: 当 euid=0 的进程执行 `/bin/sh` 时，shell_trap 会先读
> `/tmp/flag` 并 printf 到 stdout，然后 exec `/tmp/sh.real`（真实 shell）。
> euid!=0 的进程则直接透传到 `/tmp/sh.real`，不受影响。

### Step 5: 运行 exploit

#### 方法 A: 串口控制台（推荐，输出最可靠）

```bash
# Terminal A — 在 user shell 里
cd /home/user/exploit
./exploit
```

exploit 如果提权成功：
- **patched exploit**: `getroot()` 直接读 `/tmp/flag` 并 printf 到串口，然后 `exit(0)`
- **unpatched exploit**: `getroot()` 调 `execve("/bin/sh")`，触发 shell_trap 读 flag 打印到串口

串口输出示例（CVE-2023-6560 成功）：
```
[+] exploit.c:315 uring_fd @ 517
[+] exploit.c:355 fake_page @ 200200000 phys_leak @ 1ae00000
[+] exploit.c:369 core_pattern_pte @ 8000000019db3067
kernelCTF{manual-test-1773561184}       ← flag！
```

如果 kernel panic：
```
[  10.421960] kernel tried to execute NX-protected page - exploit attempt? (uid: 1000)
[  10.470671] Kernel panic - not syncing: Fatal exception in interrupt
```
说明 exploit 未能提权（uid: 1000），需要重试或换 exploit。

#### 方法 B: SSH

```bash
# Terminal B (host)
sshpass -p user ssh -o StrictHostKeyChecking=no -p 2250 user@127.0.0.1 \
  'cd /home/user/exploit && ./exploit'
```

> **注意**: 如果 kernel panic，SSH 连接会断开，输出可能丢失。此时去 Terminal A
> 看串口输出更可靠。

### Step 6: 验证结果

检查输出中是否包含你在 Step 1 设置的 flag：
```
kernelCTF{manual-test-XXXXXXXX}
```

如果看到 flag = **exploit 成功提权到 root 并读取了只有 root 能读的文件**。

### Step 7: 退出 VM

```
# 在串口控制台按:
Ctrl+A 然后 X
```

### 如果 exploit 失败需要重试

kernel panic 后 VM 会退出（`-no-reboot`），需要重新启动：

```bash
# Terminal A — 重新启动 VM（--reset 删除 overlay 从头来）
./interactive.sh CVE-2023-6560_mitigation --flag /tmp/myflag --reset

# Terminal B — VM 启动后重新部署 + 设置 shell_trap（重复 Step 3-4）
cp exp/exploit exp-interactive/exploit
cp exp/shell_trap exp-interactive/shell_trap
chmod +x exp-interactive/exploit exp-interactive/shell_trap
```

### 完整的快速流程（适合熟练后使用）

```bash
# === Host Terminal B ===
cd ~/vm-lab/kernelctf
CVE=CVE-2023-6560_mitigation

# 编译 (首次)
./smoke_test.sh $CVE --max-attempts 1  # 或用已有的 exp/

# 创建 flag
echo -n "kernelCTF{test-$(date +%s)}" > /tmp/myflag

# === Host Terminal A ===
./interactive.sh $CVE --flag /tmp/myflag --reset
# 等待 "SSH: ready"

# === Host Terminal B (VM 启动后) ===
cp exp/exploit exp-interactive/exploit
cp exp/shell_trap exp-interactive/shell_trap
chmod +x exp-interactive/{exploit,shell_trap}

sshpass -p root ssh -o StrictHostKeyChecking=no -p 2250 root@127.0.0.1 \
  'cp /bin/sh /tmp/sh.real && chmod +x /tmp/sh.real && \
   mount --bind /home/user/exploit/shell_trap /bin/sh && \
   mount --bind /home/user/exploit/shell_trap /bin/bash'

# === Terminal A (串口) 或 Terminal B (SSH) ===
# 串口: 在 VM 里直接 cd /home/user/exploit && ./exploit
# SSH:
sshpass -p user ssh -o StrictHostKeyChecking=no -p 2250 user@127.0.0.1 \
  'cd /home/user/exploit && ./exploit'

# 看到 flag = 成功。 Ctrl+A X 退出 VM。
```

### Troubleshooting

| 现象 | 原因 | 解决 |
|------|------|------|
| `exp-interactive/exploit` 是源码不是二进制 | 忘了 Step 3（interactive.sh 覆盖了） | 重新 `cp exp/exploit exp-interactive/exploit` |
| SSH 连不上 | VM 还在启动 | 等串口显示 "SSH: ready" |
| `mount --bind` 报错 | 不是 root | `su root` (密码 root) |
| Exploit 显示 uid=1000 然后 kernel panic | 提权失败，堆布局不对 | 重试；或换 CVE |
| SSH 断了没看到输出 | Kernel panic 杀了 TCP | 去串口终端看输出 |
| flag 没打印但 exploit exit 0 | 可能 /tmp/flag 不存在 | 确认用了 `--flag` 参数启动 VM |
| shell_trap 没触发 | Patched exploit 直接读 flag 不走 shell | 正常，看 exploit stdout 有没有 flag |
