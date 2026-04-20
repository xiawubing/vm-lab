# Research Journal

Newest entries at top. Keep each dated entry short — just enough to resume tomorrow.

---

## 2026-04-19 (late evening) — P0-Stage-1 complete: hypothesis REFUTED

**Target:** does `kprobe_multi_link_prog_run` + `session_cookies[]` have a
CVE-2025-38502-class bug (size mismatch across tail_call)?

**Verdict: NO.** Structural refutation, not a "hard to exploit" answer.

### Evidence (Stage 1.1 + 1.2)

1. `bpf_kprobe_multi_run_ctx` stores `link*` **directly** in the stack-allocated
   run_ctx (bpf_trace.c:2543-2547) — not via `prog_item`. 38502's bug pattern
   required prog-array-item indirection, which is absent here.

2. Helper `bpf_kprobe_multi_cookie` (bpf_trace.c:2714) reads `link->cookies[]`
   and the bound `link->cnt` from the **same** link struct. `bsearch` over
   `link->addrs[0..cnt-1]` guarantees the derived offset is in [0, cnt-1],
   so `cookies[offset]` is in-bounds — atomic consistency.

3. `bpf_session_cookie()` returns `__u64 *` (single u64, not an array) — no
   verifier-level size ambiguity exists to exploit.

4. Even if A tail-calls B, both see the same `run_ctx->link`. Since bound and
   array are fields of the same struct, there is no cross-program size
   mismatch possible.

### Structural lesson

38502 pattern: **per-program state via `prog_item` indirection, size from map attribute**
Multi-kprobe/uprobe/session pattern: **per-event state in stack run_ctx, size from attached link**

The two patterns look similar at a `container_of(current->bpf_ctx,...)` grep,
but are structurally different. My original scanner pattern over-fires.

### Stage 1.3 side-finding (noted earlier)

`ad6fface76da` (2026-02-25) — fixed a NULL deref in `show_fdinfo` callback when
`cookies == NULL`. Different bug class (missing existence check, not size
mismatch). Doesn't touch my hypothesis.

### Actions taken

1. Updated `cve-catalog/by-class/runtime-ctx-mismatch.md`:
   - Added "Ruled out" table for all 4 audited *_run_ctx types
   - Added comparative structural breakdown (38502 vs multi-kprobe idiom)
2. Added new scanner pattern `prog-item-indexed-state` — more targeted
   regex `->prog_item->\w+\[` captures only the true 38502 idiom
3. Demoted broader `runtime-ctx-mismatch` pattern to first-pass triage only

### Remaining open hypothesis

**H1 (PERCPU cgroup_storage variant):** still the only serious candidate.
Fix `abad3d0b` patches both SHARED and PERCPU via `storage_cookie[]`. Before
writing any exploit, verify LTS 6.12 and 6.6 backport completeness.

### Time log

| Stage | Budgeted | Actual |
|---|---|---|
| 1.3 history | 15 min | ~20 min |
| 1.1 data flow | 30 min | ~25 min |
| 1.2 reachability | 30 min | ~15 min (short-circuited by structural no-go) |
| 1.4 writeup | 15 min | in progress |

Finished under budget. Saved ~1 hour by doing 1.3 first (even though no fix
was found, the commit survey primed the code reading).

### Next

- [ ] Run new `prog-item-indexed-state` pattern on 6.12 to see if any siblings match
- [ ] Verify `storage_cookie[]` backport to 6.12 and 6.6 stable branches
- [ ] Document this outcome as "negative result" pattern for P1 scanner tuning

---

## 2026-04-19 (evening)

**Verified current kernelCTF target kernel versions.** Pulled metadata from
the most recent submission (`CVE-2025-40019_lts_cos_mitigation`):

- LTS:        `lts-6.12.48`            ← primary target
- COS:        `cos-121-18867.199.56`   (6.12 base)
- Mitigation: `mitigation-v4-6.6`      (hardened 6.6)

LTS track moved from 6.6 → 6.12 sometime in 2025-H2. Mitigation stays on 6.6.
Versions rotate every 2-4 weeks; re-check by looking at the latest CVE folder
in `google/security-research/pocs/linux/kernelctf/`.

Updated `README.md` with a "Target kernels" section, and `syzkaller/SETUP.md`
build commands to use `linux-6.12` as primary. CVE-2025-38502 reproduction
stays on 6.6.95 (original PoC hard-codes that version's offsets).

Skipped COS: Google fork, custom build infra (`cos.googlesource.com`),
low ROI for independent research.

**Next:** clone both 6.12 and 6.6 trees into `~/vm-lab/kernel/`.

---

## 2026-04-19

**Set up `bpf-hunting/` workspace.** Goal: BPF subsystem vuln hunting pipeline
from 1-day study → pattern scanner → syzkaller → original discovery.

Populated:
- `README.md` — 4-phase roadmap (foundation → siblings → independent → kCTF)
- `patterns/scanner.py` — 5 patterns derived from CVE-2025-38502 and friends
- `syzkaller/SETUP.md` — kernel config checklist, KMSAN-forward
- `cve-catalog/` — indexed by bug class, seeded with 38502 + 52447 + JIT/verifier stubs
- `writeups/CVE-2025-38502.md` — full walkthrough with comparison vs 52447

**Key takeaways from initial study:**
- CVE-2025-38502 fix commit `abad3d0b` by Lonial Con reveals a **bug class**, not a one-off.
  The pattern — per-program state keyed by runtime ctx, sized by a map — recurs in at
  least 4 other `*_run_ctx` types. PERCPU variant is the most immediately actionable sibling.
- kernelCTF 2025-07 rules killed several historical attack surfaces (userns, io_uring,
  nftables). Remaining viable classes: kTLS, BPF, vsock, AF_ALG. BPF is the best match
  for my background.
- `bpf_test_run` is the highest-leverage entry point for 1-day bugs because (a) it's
  under-audited, (b) triggers synthetic paths with weaker validation, (c) enabled on
  kernelCTF target.

**Next:**
- [ ] Run `patterns/scanner.py` against `~/vm-lab/kernel/linux` once I confirm tree exists
- [ ] Verify build env for LTS 6.6.95 to reproduce 38502
- [ ] Start `cve-catalog/by-class/map-refcnt-uaf.md` stub with my existing 2023-52447 notes

---
