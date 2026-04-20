# Pattern Scanner

Static scanner for known BPF bug-class patterns.

## Quick start

```bash
# List available patterns
python3 scanner.py --list

# Scan all patterns against your kernel tree
python3 scanner.py ~/vm-lab/kernel/linux --out results/$(date +%F)_all.txt

# Single pattern, eyeball output
python3 scanner.py ~/vm-lab/kernel/linux -p runtime-ctx-mismatch
```

## Patterns

| Name                    | Derived from CVE | What it finds                                                        |
|-------------------------|------------------|----------------------------------------------------------------------|
| `runtime-ctx-mismatch`  | 2025-38502       | `container_of(current->bpf_ctx, …)` — per-program state read-back    |
| `for-each-storage-iter` | 2025-38502 fix   | `for_each_cgroup_storage_type` — sibling flavors often unpatched     |
| `value-size-access`     | 2023-52447 class | `map->value_size` as length argument — OOB if alloc != access        |
| `runtime-ctx-callers`   | generalization   | All `*_run_ctx` types — attack surface audit list                    |
| `test-run-entries`      | 2025-38502 path  | `bpf_prog_test_run_*` entry points — low-friction triggers           |

## Triage workflow

1. Run scanner, save output to `results/YYYY-MM-DD_*.txt`
2. For each hit, open the file and answer:
   - Is the per-program state sized/typed by a map?
   - Can a tail-called program reach this code with a different map?
   - Does the fix commit history show this exact file was recently hardened?
3. Promising hits → open a dated note in `../notes/daily.md` with CVE-style writeup stub

## Adding patterns

Edit `scanner.py` and append to `PATTERNS`. Each new pattern should:
- Be derived from a concrete public CVE fix (document in `description`)
- Restrict `paths` to BPF-relevant subdirs to keep signal/noise high
- Use `context` generous enough (5-8 lines) to judge a hit without opening the file
