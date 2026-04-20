#!/usr/bin/env python3
"""
BPF static pattern scanner.

Scans a Linux kernel tree for patterns known to host BPF bugs.
Each pattern is derived from a real public CVE fix, so hits are concrete
bug-class candidates, not just noise.

Usage:
    python3 scanner.py /path/to/linux
    python3 scanner.py /path/to/linux --pattern runtime-ctx-mismatch
    python3 scanner.py /path/to/linux --list
    python3 scanner.py /path/to/linux --out ../results/scan.txt

Patterns:
    runtime-ctx-mismatch   CVE-2025-38502 class: container_of(current->bpf_ctx, ...)
                           where per-program state is read back with caller's map size
    for-each-storage-iter  Fix-everywhere iterator: for_each_cgroup_storage_type
    value-size-access      map->value_size used as length argument to mem*/copy_*
    runtime-ctx-callers    All users of *_run_ctx containers, for manual review
    test-run-entries       All bpf_prog_test_run_* functions (38502 trigger surface)

Exit codes:
    0 = scan completed (hits may or may not exist)
    1 = usage / path error
"""

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Pattern:
    name: str
    description: str
    regex: str
    paths: list[str]      # restrict to these subdirs (globs)
    context: int = 3      # rg -C value
    multiline: bool = False


PATTERNS: dict[str, Pattern] = {
    "runtime-ctx-mismatch": Pattern(
        name="runtime-ctx-mismatch",
        description=(
            "CVE-2025-38502 class. Finds container_of(current->bpf_ctx, ...) "
            "where runtime context is read back. Each hit is a candidate for "
            "per-program state mismatch across tail_call."
        ),
        regex=r"container_of\s*\(\s*current->bpf_ctx",
        paths=["kernel/bpf/", "net/bpf/", "include/linux/bpf"],
        context=5,
    ),
    "for-each-storage-iter": Pattern(
        name="for-each-storage-iter",
        description=(
            "Iterator macros that fan out over all storage flavors. "
            "If a fix only addressed one flavor, siblings may be unpatched."
        ),
        regex=r"for_each_cgroup_storage_type\b",
        paths=["kernel/bpf/", "net/bpf/", "include/linux/bpf"],
        context=8,
    ),
    "value-size-access": Pattern(
        name="value-size-access",
        description=(
            "map->value_size used as length to memcpy/memset/copy_from_user etc. "
            "Mismatches between storage allocation size and access size become OOB."
        ),
        regex=r"map->value_size\s*[,)]|->value_size\s*\)\s*(?:;|,)",
        paths=["kernel/bpf/", "net/bpf/"],
        context=3,
    ),
    "runtime-ctx-callers": Pattern(
        name="runtime-ctx-callers",
        description=(
            "All *_run_ctx types — each is a per-program state channel worth auditing "
            "for cross-tail_call semantics."
        ),
        regex=r"\bbpf_\w+_run_ctx\b",
        paths=["kernel/bpf/", "net/bpf/", "kernel/trace/", "include/linux/"],
        context=2,
    ),
    "test-run-entries": Pattern(
        name="test-run-entries",
        description=(
            "All BPF_PROG_TEST_RUN entry points per prog_type. Each is an attacker-"
            "accessible path to trigger obscure code (38502 was reached via test_run)."
        ),
        regex=r"bpf_prog_test_run_\w+\s*\(",
        paths=["kernel/bpf/", "net/bpf/"],
        context=1,
    ),
    "prog-item-indexed-state": Pattern(
        name="prog-item-indexed-state",
        description=(
            "Refined 38502 signature: accesses to ctx->prog_item->FIELD[...] "
            "where FIELD is sized by a user-controlled map attribute. Unlike "
            "the broader runtime-ctx-mismatch, this targets the cross-program "
            "indirection that made 38502 exploitable. run_ctxs that embed state "
            "directly (kprobe_multi, uprobe_multi, session) do NOT match."
        ),
        regex=r"->prog_item->\w+\[",
        paths=["kernel/bpf/", "net/bpf/", "include/linux/"],
        context=5,
    ),
}


def have_rg() -> bool:
    return subprocess.run(
        ["which", "rg"], capture_output=True, check=False
    ).returncode == 0


def run_ripgrep(pat: Pattern, root: Path) -> str:
    cmd = [
        "rg",
        "-n",
        "--color=never",
        "-C", str(pat.context),
        "-e", pat.regex,
    ]
    if pat.multiline:
        cmd.extend(["-U", "--multiline-dotall"])
    for p in pat.paths:
        cmd.append(str(root / p))
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout


def run_grep_fallback(pat: Pattern, root: Path) -> str:
    # Minimal fallback — lose context but keep it working without rg.
    paths = [str(root / p) for p in pat.paths]
    cmd = ["grep", "-rn", "-E", pat.regex, "--include=*.c", "--include=*.h", *paths]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout


def scan_one(pat: Pattern, root: Path) -> tuple[str, int]:
    output = run_ripgrep(pat, root) if have_rg() else run_grep_fallback(pat, root)
    hit_count = len(
        [l for l in output.splitlines() if re.search(r":\d+:", l)]
    )
    header = (
        f"\n{'=' * 72}\n"
        f"Pattern: {pat.name}\n"
        f"{pat.description}\n"
        f"Regex:   {pat.regex}\n"
        f"Hits:    {hit_count} (approximate)\n"
        f"{'=' * 72}\n"
    )
    return header + output, hit_count


def main() -> int:
    ap = argparse.ArgumentParser(description="BPF static pattern scanner")
    ap.add_argument("kernel_root", nargs="?", help="Path to Linux kernel tree")
    ap.add_argument("--pattern", "-p", help="Run only one pattern by name")
    ap.add_argument("--list", "-l", action="store_true", help="List patterns and exit")
    ap.add_argument("--out", "-o", help="Write results to file (also prints summary)")
    args = ap.parse_args()

    if args.list:
        for name, p in PATTERNS.items():
            print(f"  {name:25s} {p.description.splitlines()[0]}")
        return 0

    if not args.kernel_root:
        ap.print_usage()
        return 1

    root = Path(args.kernel_root).expanduser().resolve()
    if not (root / "MAINTAINERS").exists():
        print(f"[!] {root} does not look like a kernel tree", file=sys.stderr)
        return 1

    targets = (
        [PATTERNS[args.pattern]]
        if args.pattern
        else list(PATTERNS.values())
    )
    if args.pattern and args.pattern not in PATTERNS:
        print(f"[!] unknown pattern: {args.pattern}", file=sys.stderr)
        return 1

    chunks: list[str] = []
    summary: list[tuple[str, int]] = []
    for pat in targets:
        body, hits = scan_one(pat, root)
        chunks.append(body)
        summary.append((pat.name, hits))

    full = "\n".join(chunks)
    if args.out:
        Path(args.out).write_text(full)
        print(f"[+] wrote {args.out}")

    print("\n--- summary ---")
    for name, hits in summary:
        print(f"  {name:25s} {hits:>5d} hits")
    print()
    if not args.out:
        print("(re-run with --out to save full output for triage)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
