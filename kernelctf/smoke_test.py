#!/usr/bin/env python3
"""Batch smoke test for all kernelCTF CVE exploits.

Runs kernelctf/run.sh for each kernelCTF CVE in the registry, collecting
results and producing a summary report.

Usage:
    ./smoke_test.py                           # test all kernelCTF CVEs
    ./smoke_test.py --filter 'lts-6.1'        # test only matching CVEs
    ./smoke_test.py --release mitigation-6.1  # test only one release
    ./smoke_test.py --resume smoke-results/PREV.json  # resume interrupted run
    ./smoke_test.py --dry-run                 # show what would run
    ./smoke_test.py --list                    # list all testable CVEs
    ./smoke_test.py --timeout 600             # per-CVE timeout (default 480s)
    ./smoke_test.py --stop-on-fail 5          # stop after N failures
    ./smoke_test.py --skip-outcomes COMPILE_ERROR SKIP  # skip known outcomes on resume
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
REGISTRY_PATH = SCRIPT_DIR.parent / "cve-registry.json"
KERNELCTF_POCS = Path.home() / "security-research/pocs/linux/kernelctf"
RESULTS_DIR = SCRIPT_DIR / "smoke-results"

# Outcome classifications
PASS = "PASS"
FAIL = "FAIL"
COMPILE_ERROR = "COMPILE_ERROR"
TIMEOUT = "TIMEOUT"
SKIP = "SKIP"
ERROR = "ERROR"


def load_registry() -> dict:
    with open(REGISTRY_PATH) as f:
        return json.load(f)


def get_kernelctf_entries(registry: dict) -> list[tuple[str, dict]]:
    """Return sorted list of (key, entry) for kernelCTF CVEs."""
    entries = [
        (key, entry)
        for key, entry in registry.items()
        if entry.get("boot_mode") == "kernelctf"
    ]
    entries.sort(key=lambda x: x[0])
    return entries


def check_preflight(entry: dict) -> str | None:
    """Return skip reason if prerequisites are missing, None if OK."""
    release = entry["release"]
    cve_dir = entry["cve_dir"]

    # Map release name same way run.sh does
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

    # Check that the release subdirectory exists
    release_dirs = [d.name for d in exploit_dir.iterdir() if d.is_dir()]
    if not release_dirs:
        return f"no exploit subdirectories in {exploit_dir}"

    return None


def classify_outcome(exit_code: int, log_content: str, timed_out: bool) -> str:
    """Classify the test outcome based on exit code and log content."""
    if timed_out:
        # Timeout during compilation (e.g. sudo apt-get blocking) — not a VM timeout
        if "sudo apt" in log_content and "Launching VM" not in log_content:
            return COMPILE_ERROR
        return TIMEOUT
    if exit_code == 0:
        return PASS
    # Check for compilation failures
    if "No exploit binary available" in log_content:
        return COMPILE_ERROR
    # If compilation failed but pre-compiled binary was used, classify by runtime result
    if "Makefile compilation failed" in log_content or "Compilation failed" in log_content:
        if "Using pre-compiled binary" not in log_content:
            return COMPILE_ERROR
        # Fall through — pre-compiled binary was used, classify by runtime
    if exit_code == 1:
        return FAIL
    return ERROR


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
    # Brief pause for cleanup
    time.sleep(1)


def run_single_test(
    registry_key: str,
    entry: dict,
    log_dir: Path,
    timeout: int,
) -> dict:
    """Run a single CVE test and return result dict."""
    cve_dir = entry["cve_dir"]
    release = entry["release"]
    log_file = log_dir / f"{registry_key}.log"

    result = {
        "registry_key": registry_key,
        "cve_dir": cve_dir,
        "release": release,
        "outcome": None,
        "exit_code": None,
        "duration_seconds": 0,
        "log_file": str(log_file.relative_to(SCRIPT_DIR)),
    }

    # Pre-flight check
    skip_reason = check_preflight(entry)
    if skip_reason:
        result["outcome"] = SKIP
        result["skip_reason"] = skip_reason
        log_file.write_text(f"SKIPPED: {skip_reason}\n")
        return result

    start = time.monotonic()
    timed_out = False
    output = ""

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
            output, _ = proc.communicate(timeout=timeout)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            # Kill entire process group (run.sh, make, QEMU, etc.)
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGTERM)
            except (ProcessLookupError, OSError):
                pass
            time.sleep(3)
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            # Read remaining output after kill (communicate() drains the pipe)
            try:
                output, _ = proc.communicate(timeout=10)
            except (subprocess.TimeoutExpired, Exception):
                try:
                    output = proc.stdout.read() or ""
                except Exception:
                    output = ""
                proc.kill()
                proc.wait()
            exit_code = -1
            output += f"\n\n--- TIMEOUT after {timeout}s ---\n"
    except Exception as e:
        exit_code = -2
        output = f"Exception running test: {e}\n"

    duration = time.monotonic() - start

    # Write log
    log_file.write_text(output)

    result["exit_code"] = exit_code
    result["duration_seconds"] = round(duration, 1)
    result["outcome"] = classify_outcome(exit_code, output, timed_out)

    return result


def save_results(results_file: Path, results: list[dict], metadata: dict):
    """Save results atomically (write to .tmp then rename)."""
    data = {
        "metadata": metadata,
        "results": results,
    }
    tmp = results_file.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    tmp.rename(results_file)


def load_previous_results(path: Path) -> dict[str, dict]:
    """Load previous results keyed by registry_key."""
    with open(path) as f:
        data = json.load(f)
    return {r["registry_key"]: r for r in data.get("results", [])}


def print_summary(results: list[dict]):
    """Print a summary table of outcomes."""
    counts: dict[str, int] = {}
    failures: list[dict] = []
    total_duration = 0

    for r in results:
        outcome = r["outcome"]
        counts[outcome] = counts.get(outcome, 0) + 1
        total_duration += r.get("duration_seconds", 0)
        if outcome not in (PASS, SKIP):
            failures.append(r)

    print("\n" + "=" * 60)
    print("SMOKE TEST SUMMARY")
    print("=" * 60)
    print(f"  Total:          {len(results)}")
    for outcome in [PASS, FAIL, COMPILE_ERROR, TIMEOUT, SKIP, ERROR]:
        if outcome in counts:
            print(f"  {outcome:<16}{counts[outcome]}")
    print(f"  Duration:       {total_duration:.0f}s ({total_duration/60:.1f}m)")
    print("=" * 60)

    if failures:
        print(f"\nFailed tests ({len(failures)}):")
        for r in failures:
            extra = ""
            if r["outcome"] == TIMEOUT:
                extra = " (timeout)"
            elif r["outcome"] == COMPILE_ERROR:
                extra = " (compile)"
            print(f"  [{r['outcome']}] {r['registry_key']}{extra}")
            if r.get("log_file"):
                print(f"         log: {r['log_file']}")
    else:
        print("\nAll tests passed!")


def main():
    parser = argparse.ArgumentParser(
        description="Batch smoke test for kernelCTF CVE exploits"
    )
    parser.add_argument(
        "--filter",
        help="Regex filter on registry key (e.g. 'lts-6.1', 'CVE-2023-3611')",
    )
    parser.add_argument(
        "--release",
        help="Test only CVEs targeting this release",
    )
    parser.add_argument(
        "--resume",
        type=Path,
        help="Resume from a previous results JSON file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would run without executing",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all testable CVEs",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=480,
        help="Per-CVE timeout in seconds (default: 480)",
    )
    parser.add_argument(
        "--stop-on-fail",
        type=int,
        default=0,
        help="Stop after N failures (0=never stop)",
    )
    parser.add_argument(
        "--skip-outcomes",
        nargs="+",
        default=[],
        help="When resuming, re-run CVEs with these outcomes instead of skipping (e.g. --skip-outcomes FAIL TIMEOUT)",
    )
    args = parser.parse_args()

    registry = load_registry()
    entries = get_kernelctf_entries(registry)

    # Apply filters
    if args.filter:
        pattern = re.compile(args.filter)
        entries = [(k, e) for k, e in entries if pattern.search(k)]
    if args.release:
        entries = [(k, e) for k, e in entries if e.get("release") == args.release]

    if not entries:
        print("No matching CVEs found.", file=sys.stderr)
        sys.exit(1)

    # --list mode
    if args.list:
        for key, entry in entries:
            skip = check_preflight(entry)
            status = "READY" if skip is None else f"SKIP ({skip})"
            print(f"  {key:<50} {status}")
        ready = sum(1 for k, e in entries if check_preflight(e) is None)
        print(f"\n{ready}/{len(entries)} ready to test")
        return

    # --dry-run mode
    if args.dry_run:
        for key, entry in entries:
            skip = check_preflight(entry)
            marker = "  SKIP " if skip else "  RUN  "
            print(f"{marker} {key}  (cve_dir={entry['cve_dir']} release={entry['release']})")
            if skip:
                print(f"         reason: {skip}")
        ready = sum(1 for k, e in entries if check_preflight(e) is None)
        print(f"\n{ready}/{len(entries)} would run (timeout={args.timeout}s each)")
        return

    # Load previous results for resuming
    previous: dict[str, dict] = {}
    if args.resume:
        if not args.resume.exists():
            print(f"Resume file not found: {args.resume}", file=sys.stderr)
            sys.exit(1)
        previous = load_previous_results(args.resume)
        # If --skip-outcomes specified, remove those from previous so they re-run
        if args.skip_outcomes:
            rerun_keys = [
                k for k, v in previous.items()
                if v.get("outcome") in args.skip_outcomes
            ]
            for k in rerun_keys:
                del previous[k]
            print(
                f"Loaded {len(previous)} previous results from {args.resume} "
                f"(re-running {len(rerun_keys)} with outcomes: {', '.join(args.skip_outcomes)})"
            )
        else:
            print(f"Loaded {len(previous)} previous results from {args.resume}")

    # Setup output directory
    run_id = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    log_dir = RESULTS_DIR / run_id
    log_dir.mkdir(parents=True, exist_ok=True)
    results_file = RESULTS_DIR / f"{run_id}.json"

    metadata = {
        "run_id": run_id,
        "started_at": datetime.now().isoformat(),
        "timeout": args.timeout,
        "filter": args.filter,
        "release": args.release,
        "resume_from": str(args.resume) if args.resume else None,
        "total_cves": len(entries),
    }

    results: list[dict] = []
    fail_count = 0
    interrupted = False

    # SIGINT handler for clean shutdown
    def handle_sigint(signum, frame):
        nonlocal interrupted
        interrupted = True
        print("\n\nInterrupted! Saving partial results...")

    original_handler = signal.signal(signal.SIGINT, handle_sigint)

    print(f"Smoke test: {len(entries)} CVEs, timeout={args.timeout}s")
    print(f"Results: {results_file}")
    print(f"Logs:    {log_dir}/")
    print()

    try:
        for i, (key, entry) in enumerate(entries, 1):
            if interrupted:
                break

            # Skip if already in previous results (resume mode)
            if key in previous:
                prev = previous[key]
                results.append(prev)
                print(
                    f"[{i}/{len(entries)}] {key}: {prev['outcome']} (resumed, "
                    f"{prev.get('duration_seconds', 0):.0f}s)"
                )
                if prev["outcome"] not in (PASS, SKIP):
                    fail_count += 1
                continue

            # Kill stale QEMU between tests
            kill_stale_qemu()

            print(f"[{i}/{len(entries)}] {key}...", end=" ", flush=True)

            result = run_single_test(key, entry, log_dir, args.timeout)
            results.append(result)

            # Print inline result
            outcome = result["outcome"]
            duration = result.get("duration_seconds", 0)
            extra = ""
            if outcome == SKIP:
                extra = f" ({result.get('skip_reason', '')})"
            print(f"{outcome} ({duration:.0f}s){extra}")

            # Save incrementally
            save_results(results_file, results, metadata)

            if outcome not in (PASS, SKIP):
                fail_count += 1

            if args.stop_on_fail and fail_count >= args.stop_on_fail:
                print(f"\nStopping: reached {fail_count} failures (--stop-on-fail {args.stop_on_fail})")
                break
    finally:
        signal.signal(signal.SIGINT, original_handler)

        # Final save
        metadata["finished_at"] = datetime.now().isoformat()
        metadata["interrupted"] = interrupted
        save_results(results_file, results, metadata)

        # Kill any leftover QEMU
        kill_stale_qemu()

        print_summary(results)
        print(f"\nResults saved to: {results_file}")


if __name__ == "__main__":
    main()
