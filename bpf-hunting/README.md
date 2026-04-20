# BPF Vulnerability Hunting

Personal research workspace for BPF subsystem bug hunting.
Strategy: 1-day → 0-day → kernelCTF submission → paper material.

## Directory layout

```
bpf-hunting/
├── README.md                   # this file — master roadmap
├── patterns/                   # static pattern scanning
│   ├── scanner.py              # pattern scanner (grep + context)
│   ├── README.md               # how to run
│   └── results/                # scan output snapshots (timestamped)
├── syzkaller/
│   └── SETUP.md                # syzkaller + KMSAN on vm-lab
├── cve-catalog/                # 2024-2026 BPF CVE database, organized by bug class
│   ├── README.md               # index
│   └── by-class/
│       ├── runtime-ctx-mismatch.md    # CVE-2025-38502 class
│       ├── map-refcnt-uaf.md          # CVE-2023-52447 class
│       ├── test-run-family.md         # bpf_test_run entry-point bugs
│       ├── verifier-logic.md          # verifier arithmetic/bounds bugs
│       └── jit-codegen.md             # JIT-specific bugs
├── writeups/                   # deep walkthroughs per CVE
│   └── CVE-2025-38502.md       # cgroup_storage OOB via tail_call
└── notes/
    └── daily.md                # research journal
```

## Target kernels

kernelCTF as of 2026-Q1 targets three tracks; our priority ordering:

| Track         | Kernel version          | Local tree                          | Priority |
|---------------|-------------------------|-------------------------------------|----------|
| LTS (main)    | linux-6.12.x            | `~/vm-lab/kernel/linux-6.12/`       | primary  |
| Mitigation    | linux-6.6 (hardened)    | `~/vm-lab/kernel/linux-6.6/`        | secondary |
| COS           | cos-121 (6.12 base)     | _not cloned_ — Google fork, skipped | — |

Primary hunting = **linux-6.12**. Keep linux-6.6 as a side tree for:
- Reproducing CVE-2025-38502 (original PoC targeted 6.6.95)
- Studying Mitigation track backport diffs

Version source of truth: the most recent kernelCTF submission folder (e.g.
`CVE-2025-40019_lts_cos_mitigation` contains `lts-6.12.48`, `cos-121-…`,
`mitigation-v4-6.6`). Re-check every few months — kernel rotates every 2-4 weeks.

## Roadmap

### Phase 1: Foundation (weeks 1-2)
- [x] Set up directory structure
- [ ] Clone linux-6.12 (primary) + linux-6.6 (secondary) into `~/vm-lab/kernel/`
- [ ] Reproduce CVE-2025-38502 on linux-6.6.95 (original PoC target)
- [ ] Run pattern scanner on linux-6.12 tree, triage top hits
- [ ] Build fuzzing kernel (KASAN + KMSAN + BPF full stack) on 6.12

### Phase 2: Sibling hunting (weeks 3-6)
- [ ] Exploit PERCPU cgroup_storage variant of 38502
- [ ] Scan for "runtime ctx mismatch" class siblings systematically
- [ ] Reproduce 2-3 more BPF CVEs to build muscle memory

### Phase 3: Independent discovery (months 2-4)
- [ ] Build BPF program-graph fuzzer (LLM-guided prog composition)
- [ ] Run 24/7 syzkaller on vm-lab, triage crashes
- [ ] Submit first independently-found BPF bug upstream

### Phase 4: kernelCTF (months 4-6)
- [ ] Select 1-day from pattern catalog, write exploit for kernelCTF LTS target
- [ ] Submit kernelCTF entry
- [ ] Extract paper material: "AI-assisted BPF bug class discovery"

## Active hypotheses

| ID  | Hypothesis                                                                  | Evidence                                                                 | Status     |
|-----|-----------------------------------------------------------------------------|--------------------------------------------------------------------------|------------|
| H1  | PERCPU variant of CVE-2025-38502 is independently exploitable                | Fix commit `abad3d0b` patches both flavors; PERCPU has no public exploit  | to verify  |
| H2  | `bpf_trace_run_ctx` has similar per-program state that can cross tail_call  | Same pattern as `bpf_cg_run_ctx`; not yet hardened by `storage_cookie[]`  | to scan    |
| H3  | BPF token + struct_ops are under-audited (2024+ new code)                   | Low CVE density vs code age suggests undiscovered bugs                    | to scan    |
| H4  | `for_each_cgroup_storage_type` pattern appears elsewhere with same bug      | Mechanical extension of 38502 fix                                         | to grep    |

## High-signal sources (check weekly)

- [bpf mailing list](https://lore.kernel.org/bpf/) — patches + `Fixes:` trails
- [syzbot bpf](https://syzkaller.appspot.com/upstream?manager=ci-upstream-bpf-kasan-gce) — live crashes
- [kernelCTF submissions](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf) — what's being rewarded
- Lonial Con's lore patches — prolific BPF bug reporter

## Related files in ~/vm-lab/

- `cve-registry.json` — existing CVE reproduction database
- `kernelctf/` — kernelCTF-specific setup
- `kernel/` — kernel source/build trees

## Conventions

- Every new CVE studied → add entry to `cve-catalog/by-class/<class>.md` AND write a full walkthrough in `writeups/`
- Every scanner run → snapshot to `patterns/results/YYYY-MM-DD_<scope>.txt` before triage
- Daily journal in `notes/daily.md` (newest at top)

---
_Last updated: 2026-04-19_
