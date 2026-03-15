#!/usr/bin/env python3
"""Stability test: run each benchmark CVE exploit N times and measure pass rate.

Compares actual pass rates against stability_notes from benchmark_baseline.json.

Usage:
    ./stability_test.py                          # test all baseline CVEs, 10 runs each
    ./stability_test.py --runs 5                  # 5 runs per CVE
    ./stability_test.py --filter 'CVE-2023-3390'  # test only matching CVEs
    ./stability_test.py --resume stability-results/PREV.json  # resume interrupted run
    ./stability_test.py --dry-run                 # show what would run
    ./stability_test.py --timeout 300             # per-run timeout (default 480s)
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BASELINE_PATH = SCRIPT_DIR / "benchmark_baseline.json"
KERNELCTF_POCS = Path.home() / "security-research/pocs/linux/kernelctf"
RESULTS_DIR = SCRIPT_DIR / "stability-results"


def load_baseline() -> list[dict]:
    with open(BASELINE_PATH) as f:
        data = json.load(f)
    return data.get("entries", [])



def check_preflight(entry: dict) -> str | None:
    """Return skip reason if prerequisites are missing, None if OK."""
    release = entry["release"]
    cve_dir = entry["cve_dir"]

    actual_release = release
    if release == "mitigation-6.1":
        actual_release = "mitigation-6.1-v2"

    bzimage = SCRIPT_DIR / "releases" / actual_release / "bzImage"
    if not bzimage.exists():
        return f"bzImage not found for release {actual_release}"

    rootfs = SCRIPT_DIR / "images" / "rootfs_repro_v2.img"
    if not rootfs.exists():
        return "rootfs_repro_v2.img not found"

    exploit_dir = KERNELCTF_POCS / cve_dir / "exploit"
    if not exploit_dir.is_dir():
        return f"exploit source dir not found: {exploit_dir}"

    return None


def kill_stale_qemu():
    """Kill any leftover QEMU processes from kernelCTF runs."""
    try:
        subprocess.run(
            ["pkill", "-f", "qemu-system-x86_64.*mount_tag=exp"],
            capture_output=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    time.sleep(1)


def run_once(cve_dir: str, release: str, timeout: int) -> tuple[bool, float]:
    """Run run.sh once. Returns (passed, duration_seconds)."""
    start = time.monotonic()
    try:
        proc = subprocess.Popen(
            [str(SCRIPT_DIR / "run.sh"), cve_dir, release],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            cwd=str(SCRIPT_DIR),
            preexec_fn=os.setsid,
        )
        try:
            proc.communicate(timeout=timeout)
            passed = proc.returncode == 0
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (ProcessLookupError, OSError):
                pass
            time.sleep(3)
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            try:
                proc.communicate(timeout=10)
            except Exception:
                proc.kill()
                proc.wait()
            passed = False
    except Exception:
        passed = False

    duration = time.monotonic() - start
    return passed, round(duration, 1)


def save_results(results_file: Path, results: list[dict], metadata: dict):
    data = {"metadata": metadata, "results": results}
    tmp = results_file.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    tmp.rename(results_file)


def load_previous_results(path: Path) -> dict[str, dict]:
    with open(path) as f:
        data = json.load(f)
    return {r["registry_key"]: r for r in data.get("results", [])}



def print_summary(results: list[dict], total_runs: int):
    print()
    print("=" * 85)
    print("STABILITY TEST SUMMARY")
    print("=" * 85)
    print(
        f"{'CVE':<50} {'RESULT':>8} {'RUN#':>6} {'EXPECTED':>15}"
    )
    print("-" * 85)

    pass_count = 0
    fail_count = 0
    skip_count = 0

    for r in results:
        if r.get("skipped"):
            skip_count += 1
            continue

        key = r["registry_key"]
        outcome = r.get("outcome", "FAIL")
        first_pass = r.get("first_pass_run")
        runs_used = r.get("total_runs", 0)
        notes = r.get("stability_notes", "")

        if outcome == "PASS":
            pass_count += 1
            run_str = f"{first_pass}/{total_runs}"
        else:
            fail_count += 1
            run_str = f"0/{total_runs}"

        marker = ""
        if outcome == "FAIL":
            marker = " !!"

        display_key = key[:48] if len(key) > 48 else key
        print(
            f"  {display_key:<48} {outcome:>8} {run_str:>6} {notes:>15}{marker}"
        )

    print("-" * 85)
    tested = len(results) - skip_count
    print(f"  Tested: {tested}  |  PASS: {pass_count}  |  FAIL: {fail_count}  |  Skipped: {skip_count}")

    if fail_count > 0:
        print(f"\n  {fail_count} CVE(s) failed all {total_runs} runs — may need investigation.")
    print("=" * 85)


def main():
    parser = argparse.ArgumentParser(
        description="Stability test: run each baseline CVE N times and measure pass rate"
    )
    parser.add_argument(
        "--runs", type=int, default=10,
        help="Number of runs per CVE (default: 10)",
    )
    parser.add_argument(
        "--filter",
        help="Regex filter on registry key (e.g. 'CVE-2023-3390')",
    )
    parser.add_argument(
        "--resume", type=Path,
        help="Resume from a previous results JSON file (skips completed CVEs)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would run without executing",
    )
    parser.add_argument(
        "--timeout", type=int, default=480,
        help="Per-run timeout in seconds (default: 480)",
    )
    args = parser.parse_args()

    entries = load_baseline()

    if args.filter:
        pattern = re.compile(args.filter)
        entries = [e for e in entries if pattern.search(e["registry_key"])]

    if not entries:
        print("No matching CVEs found.", file=sys.stderr)
        sys.exit(1)

    if args.dry_run:
        for e in entries:
            skip = check_preflight(e)
            marker = "  SKIP " if skip else "  RUN  "
            notes = e.get("stability_notes", "")
            print(f"{marker} {e['registry_key']}  (notes: {notes})")
            if skip:
                print(f"         reason: {skip}")
        ready = sum(1 for e in entries if check_preflight(e) is None)
        print(f"\n{ready}/{len(entries)} ready ({args.runs} runs each, timeout={args.timeout}s)")
        return

    # Load previous results for resuming
    previous: dict[str, dict] = {}
    if args.resume:
        if not args.resume.exists():
            print(f"Resume file not found: {args.resume}", file=sys.stderr)
            sys.exit(1)
        previous = load_previous_results(args.resume)
        print(f"Loaded {len(previous)} previous results from {args.resume}")

    # Setup output
    run_id = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    results_file = RESULTS_DIR / f"{run_id}.json"

    metadata = {
        "run_id": run_id,
        "started_at": datetime.now().isoformat(),
        "runs_per_cve": args.runs,
        "timeout": args.timeout,
        "filter": args.filter,
        "total_cves": len(entries),
    }

    results: list[dict] = []
    interrupted = False

    def handle_sigint(signum, frame):
        nonlocal interrupted
        interrupted = True
        print("\n\nInterrupted! Saving partial results...")

    original_handler = signal.signal(signal.SIGINT, handle_sigint)

    print(f"Stability test: {len(entries)} CVEs x {args.runs} runs, timeout={args.timeout}s")
    print(f"Results: {results_file}")
    print()

    try:
        for i, entry in enumerate(entries, 1):
            if interrupted:
                break

            key = entry["registry_key"]
            cve_dir = entry["cve_dir"]
            release = entry["release"]
            notes = entry.get("stability_notes", "")

            # Resume: skip if already completed with full runs
            if key in previous:
                prev = previous[key]
                if prev.get("completed") and prev.get("total_runs", 0) >= args.runs:
                    results.append(prev)
                    print(
                        f"[{i}/{len(entries)}] {key}: "
                        f"{prev['passes']}/{prev['total_runs']} PASS (resumed)"
                    )
                    continue

            # Preflight
            skip_reason = check_preflight(entry)
            cmd = f"./run.sh {cve_dir} {release}"

            if skip_reason:
                result = {
                    "registry_key": key,
                    "cve_dir": cve_dir,
                    "release": release,
                    "command": cmd,
                    "stability_notes": notes,
                    "skipped": True,
                    "skip_reason": skip_reason,
                    "passes": 0,
                    "fails": 0,
                    "total_runs": 0,
                    "completed": True,
                    "durations": [],
                }
                results.append(result)
                print(f"[{i}/{len(entries)}] {key}: SKIP ({skip_reason})")
                save_results(results_file, results, metadata)
                continue

            # Run until first PASS or max runs exhausted
            first_pass_run = None
            fails = 0
            durations = []

            print(f"[{i}/{len(entries)}] {key} (expected: {notes})")

            for run_num in range(1, args.runs + 1):
                if interrupted:
                    break

                kill_stale_qemu()
                passed, duration = run_once(cve_dir, release, args.timeout)
                durations.append(duration)

                if passed:
                    first_pass_run = run_num
                    print(
                        f"  run {run_num}/{args.runs}: PASS ({duration:.0f}s)  "
                        f"=> first PASS at run {run_num}, stopping"
                    )
                    break
                else:
                    fails += 1
                    print(
                        f"  run {run_num}/{args.runs}: FAIL ({duration:.0f}s)  "
                        f"[{fails} consecutive fails]"
                    )

            completed = not interrupted
            outcome = "PASS" if first_pass_run else "FAIL"

            result = {
                "registry_key": key,
                "cve_dir": cve_dir,
                "release": release,
                "command": cmd,
                "stability_notes": notes,
                "skipped": False,
                "outcome": outcome,
                "first_pass_run": first_pass_run,
                "total_runs": len(durations),
                "completed": completed,
                "durations": durations,
                "total_duration_s": round(sum(durations), 1),
            }
            results.append(result)

            if completed:
                if first_pass_run:
                    print(f"  => PASS on run {first_pass_run}/{args.runs} (expected: {notes})")
                else:
                    print(f"  => FAIL all {args.runs} runs (expected: {notes})")
                print()

            save_results(results_file, results, metadata)

    finally:
        signal.signal(signal.SIGINT, original_handler)
        metadata["finished_at"] = datetime.now().isoformat()
        metadata["interrupted"] = interrupted
        save_results(results_file, results, metadata)
        kill_stale_qemu()
        print_summary(results, args.runs)
        print(f"\nResults saved to: {results_file}")


if __name__ == "__main__":
    main()
