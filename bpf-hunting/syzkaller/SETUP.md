# Syzkaller + KMSAN on vm-lab

Checklist for setting up a BPF-focused fuzzing environment.
Goal: find upstream bugs, not just kernelCTF-triggerable ones — so enable everything
(io_uring, userns, nftables) even though kernelCTF target disables them.

## 0. Choose kernel version

| Version | Why |
|---|---|
| `6.12.x` LTS | **Current kernelCTF LTS target.** Primary hunting + exploit development. |
| `6.6.x` LTS  | kernelCTF Mitigation-track base. Also matches CVE-2025-38502 original PoC (6.6.95). |
| `master` bpf-next | Pre-merge bugs — report upstream directly for credit. |

Recommended: primary tree is **linux-6.12** for kernelCTF LTS submissions.
Keep linux-6.6 side tree for reproducing known exploits + mitigation study.

## 1. Kernel config

Base on `make defconfig` + enable these. Syzkaller will need most of them anyway.

### Sanitizers (mandatory)
```
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_OUTLINE=y
CONFIG_KMSAN=y                   # crucial — catches uninit reads (CVE-2025-38502-adjacent)
CONFIG_KCSAN=y                   # race detection, optional but valuable
CONFIG_UBSAN=y
CONFIG_UBSAN_BOUNDS=y
CONFIG_KFENCE=y
CONFIG_FAULT_INJECTION=y
CONFIG_FAIL_MAKE_REQUEST=y
```

### Debugging
```
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_LIST=y
CONFIG_DEBUG_PLIST=y
CONFIG_DEBUG_SG=y
CONFIG_DEBUG_ATOMIC_SLEEP=y
CONFIG_DEBUG_WX=y
CONFIG_REFCOUNT_FULL=y
CONFIG_FORTIFY_SOURCE=y
CONFIG_LOCKDEP=y
CONFIG_PROVE_LOCKING=y
CONFIG_RCU_TORTURE_TEST=m
```

### BPF full surface
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_UNPRIV_DEFAULT_OFF=n  # allow unpriv for wider coverage
CONFIG_BPF_STREAM_PARSER=y
CONFIG_BPF_EVENTS=y
CONFIG_BPF_LSM=y
CONFIG_CGROUP_BPF=y
CONFIG_NETFILTER_XT_MATCH_BPF=y
CONFIG_NET_CLS_BPF=y
CONFIG_NET_ACT_BPF=y
CONFIG_NET_SCH_BPF=y
CONFIG_XDP_SOCKETS=y
CONFIG_BPF_PRELOAD=y
CONFIG_DEBUG_INFO_BTF=y          # BTF needed for modern BPF
CONFIG_DEBUG_INFO_BTF_MODULES=y
```

### Attack surface (keep enabled for bug hunting, disable separately for kernelCTF)
```
CONFIG_USER_NS=y
CONFIG_IO_URING=y
CONFIG_NF_TABLES=y
CONFIG_NETFILTER=y
CONFIG_NET_SCHED=y
```

## 2. Build kernel

```bash
# Primary: 6.12 for current kernelCTF LTS target
cd ~/vm-lab/kernel/linux-6.12
make O=../build-bpf-fuzz-6.12 defconfig
# merge our extras
cat ~/vm-lab/bpf-hunting/syzkaller/extra.config >> ../build-bpf-fuzz-6.12/.config
make O=../build-bpf-fuzz-6.12 olddefconfig
make O=../build-bpf-fuzz-6.12 -j$(nproc) bzImage
```

Verify sanitizers are actually built in:
```bash
grep -E "CONFIG_KASAN=|CONFIG_KMSAN=" ../build-bpf-fuzz-6.12/.config
```

For reproducing CVE-2025-38502, build linux-6.6 with the same recipe into
`../build-bpf-fuzz-6.6/` — but note that the published PoC uses hard-coded
offsets for 6.6.95 specifically, so prefer checking out that exact tag.

## 3. Syzkaller setup

```bash
cd ~
go install github.com/google/syzkaller/...@latest   # or clone & build per docs
git clone https://github.com/google/syzkaller
cd syzkaller
make TARGETOS=linux TARGETARCH=amd64
```

### Config (syzkaller.cfg)
```json
{
  "target": "linux/amd64",
  "http": "127.0.0.1:56741",
  "workdir": "/home/xia/vm-lab/bpf-hunting/syzkaller/workdir",
  "kernel_obj": "/home/xia/vm-lab/kernel/build-bpf-fuzz",
  "image": "/home/xia/vm-lab/images/stretch.img",
  "sshkey": "/home/xia/vm-lab/images/stretch.id_rsa",
  "syzkaller": "/home/xia/syzkaller",
  "procs": 4,
  "type": "qemu",
  "vm": {
    "count": 4,
    "kernel": "/home/xia/vm-lab/kernel/build-bpf-fuzz/arch/x86/boot/bzImage",
    "cpu": 2,
    "mem": 2048
  },
  "enable_syscalls": [
    "bpf", "bpf$*",
    "perf_event_open", "perf_event_open$*",
    "socket$*", "setsockopt$*", "getsockopt$*",
    "openat$cgroup*", "openat$bpf*",
    "mount$bpf*",
    "syz_bpf_prog_open", "syz_init_net_socket"
  ],
  "disable_syscalls": [
    "reboot", "shutdown"
  ]
}
```

## 4. Run

```bash
~/syzkaller/bin/syz-manager -config syzkaller.cfg
```

Dashboard: http://localhost:56741 — watch `crashes/` for new reports.

## 5. Triage crashes

Each crash directory contains:
- `description` — one-liner
- `report*` — full KASAN/KMSAN dump
- `repro.c` / `repro.syz` — reproducer
- `log*` — kernel log leading up to crash

**Classify before spending time:**
1. `ls workdir/crashes/*/description | xargs -I{} cat {}`
2. Dedup: many will be same root cause under different entry points
3. Prioritize: `KMSAN` > `KASAN slab-out-of-bounds` > `KASAN use-after-free` > others
4. For each unique crash → new note in `../notes/daily.md` with crash hash

## 6. BPF-specific tuning

Default syzkaller BPF coverage is weak. Improve by:

### Custom syzlang descriptors
Look at `syzkaller/sys/linux/bpf.txt` and extend:
- Add more `struct_ops` variants (under-fuzzed)
- Add BPF token flows
- Add `BPF_PROG_TEST_RUN` for every `prog_type`

### Program-graph seed corpus
Seed with real kernelCTF exploit programs:
```bash
# Extract BPF insn sequences from ~/vm-lab/kernelctf submissions
# feed as syzkaller hints
```

### Lonial Con pattern corpus
Any `bpf_*_run_ctx` + tail_call combo deserves a dedicated syzlang rule.

## 7. Known pitfalls in WSL2

- `CONFIG_KMSAN` may require LLVM 17+ to build cleanly. Use `CC=clang LLVM=1`.
- WSL2 kernel virt is limited; if KVM nested fails, use pure `-cpu qemu64`.
- Don't run `make clean` in the vm-lab VM itself — it wipes shared host libs.

## References

- syzkaller docs: https://github.com/google/syzkaller/blob/master/docs/linux/setup.md
- KMSAN docs: https://www.kernel.org/doc/html/latest/dev-tools/kmsan.html
- Dmitry Vyukov's BPF fuzzing talk (LPC): track the corpus tips
- Lonial Con's BPF methodology (via lore.kernel.org patch trails)

---
_Checklist — tick as you go:_

- [ ] Built kernel with KASAN + KMSAN
- [ ] Verified sanitizers active (run a deliberate OOB, confirm KASAN reports)
- [ ] Syzkaller base install working
- [ ] BPF syscall coverage enabled in config
- [ ] Crash triage directory structure created
- [ ] Seeded corpus from kernelCTF exploits
- [ ] First overnight run completed
