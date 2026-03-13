#!/bin/bash
# Display benchmark progress and statistics from the record file.
#
# Usage:
#   ./benchmark_status.sh              # Summary view
#   ./benchmark_status.sh --detail     # Show per-CVE status
#   ./benchmark_status.sh --failures   # Show only failures

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RECORD="$SCRIPT_DIR/benchmark_record.jsonl"
BASELINE="$SCRIPT_DIR/benchmark_baseline.json"

MODE="${1:---summary}"

if [ ! -f "$RECORD" ]; then
    echo "No benchmark record yet. Run ./run_benchmark.sh to start."
    exit 0
fi

python3 << 'PYEOF'
import json, sys, os

record_file = os.environ.get('RECORD', 'benchmark_record.jsonl')
baseline_file = os.environ.get('BASELINE', 'benchmark_baseline.json')
mode = sys.argv[1] if len(sys.argv) > 1 else '--summary'

# Read records
records = {}
with open(record_file) as f:
    for line in f:
        r = json.loads(line.strip())
        records[r['registry_key']] = r

# Read baseline
baseline = json.load(open(baseline_file))
total_baseline = baseline['total']

# Stats
success = sum(1 for r in records.values() if r['status'] == 'success')
fail = sum(1 for r in records.values() if r['status'] == 'fail')
timeout = sum(1 for r in records.values() if r['status'] == 'timeout')
error = sum(1 for r in records.values() if r['status'] == 'error')
pending = total_baseline - len(records)

print("=" * 60)
print(f"  kernelCTF Agent Benchmark Status")
print(f"  Baseline: {total_baseline} CVEs")
print(f"  Completed: {len(records)} / {total_baseline}")
print(f"  Success: {success}  Fail: {fail}  Timeout: {timeout}  Error: {error}")
print(f"  Pending: {pending}")
if len(records) > 0:
    avg_dur = sum(r.get('duration_s', 0) for r in records.values()) / len(records)
    print(f"  Avg duration: {avg_dur:.0f}s")
    print(f"  Success rate: {success}/{len(records)} ({100*success/len(records):.1f}%)")
print("=" * 60)

if mode == '--detail':
    print(f"\n{'CVE Key':<55s} {'Status':<10s} {'Duration':<10s} {'Exit'}")
    print("-" * 85)
    for e in baseline['entries']:
        key = e['registry_key']
        if key in records:
            r = records[key]
            print(f"{key:<55s} {r['status']:<10s} {r.get('duration_s',0):>6.0f}s    {r.get('exit_code','?')}")
        else:
            print(f"{key:<55s} {'pending':<10s}")

elif mode == '--failures':
    fails = [r for r in records.values() if r['status'] in ('fail', 'timeout', 'error')]
    if not fails:
        print("\nNo failures yet!")
    else:
        print(f"\n{'CVE Key':<55s} {'Status':<10s} {'Duration':<10s} {'Log'}")
        print("-" * 120)
        for r in sorted(fails, key=lambda x: x['registry_key']):
            print(f"{r['registry_key']:<55s} {r['status']:<10s} {r.get('duration_s',0):>6.0f}s    {r.get('log_file','')}")

PYEOF
