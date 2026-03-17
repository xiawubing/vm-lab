# Plan: MCP Tool Cleanup & Usage Optimization

## Context

Analyzed 10 agent sessions (9 `.md` + 1 `.jsonl`) across CVE-2024-0582, CVE-2023-0193, CVE-2023-0461, CVE-2023-6560. All sessions use the kernelCTF workflow: compile in container with `gcc -static` → `vm_upload_file` → `vm_execute`.

## Problem

12 MCP tools defined in `mcp_ssh_server.py`. 1 is completely redundant (wastes context tokens + agent thinking time). 3 are critically underused, leading to observable failures (blind restart loops, manual retry instead of auto-retry).

## Tool Usage Data

| Tool | Calls | Sessions | Verdict |
|------|-------|----------|---------|
| `vm_execute` | ~92 | 7/10 | Core |
| `vm_upload_file` | ~24 | 6/10 | Core |
| `vm_check_status` | ~23 | 6/10 | Core |
| `vm_restart` | ~17 | 4/10 | Core |
| `vm_start` | ~10 | 5/10 | Core |
| `vm_run_exploit` | 5 | 3/10 | Underused |
| `vm_get_log` | 3 | 2/10 | Underused |
| `vm_stop` | 1 | 1/10 | Keep (low cost) |
| `vm_verify_flag` | 0 | 0/10 | Keep (success criterion, no session achieved root yet) |
| `vm_download_file` | 0 | 0/10 | Keep (low cost, legitimate utility) |
| `vm_compile_and_run` | 0 | 0/10 | **Remove** |
| `vm_reset_overlay` | 0 | 0/10 | Underused |

---

## Change 1: Remove `vm_compile_and_run`

### Why

- kernelCTF VMs have **no compiler**. The tool uploads C source to the VM and compiles there with `gcc`, which doesn't exist.
- CLAUDE.md already says: "The VM has no compiler — you must always cross-compile in the container."
- Agent tried to use it twice (CVE-2023-0193), rejected both times: *"Wait, this is kernelCTF mode, not cloud-init mode. So vm_compile_and_run won't work."*
- Costs ~400 tokens of permanent context (docstring + 5 parameters), plus agent wastes thinking tokens considering and rejecting it each session.

### What about old cloud-init VMs?

The CVE-2017-*/CVE-2018-* VMs do have `gcc`, but no session has targeted them since the kernelCTF focus. Container-local `gcc -static` + upload is more reliable anyway (consistent toolchain). If needed later, re-adding the tool takes minutes.

### File changes

**`agent-container/mcp_ssh_server.py`**: Delete the `vm_compile_and_run` function (lines 302-403).

**`agent-container/CLAUDE.md`**: Remove `vm_compile_and_run` row from the "Available MCP Tools" table.

---

## Change 2: Hook to prevent blind restart loops

### Problem

Sessions routinely call `vm_restart` 5-9 times without checking console output. The CVE-2024-0582 session spent its entire $5 budget on 27 lifecycle calls (13 `vm_check_status` + 9 `vm_restart` + 4 `vm_start` + 1 `vm_stop`) and **zero** exploit runs. `vm_get_log` was never called.

CLAUDE.md says "Do NOT blindly retry vm_restart() more than 2-3 times — always check vm_get_log()", but the agent ignores it.

### Solution

Add hook check in `post_tool_use.py`: after 2+ consecutive `vm_restart` (or `vm_start`) without an intervening `vm_get_log`, inject:

```
STOP blind restarts. You have restarted N times without checking console output.
Call vm_get_log() NOW to diagnose why the VM isn't coming up.
```

### File changes

**`agent-container/.claude/hooks/post_tool_use.py`**: Add check, track `consecutive_restarts` in `/tmp/agent_state.json`.

---

## Change 3: Hook to nudge `vm_run_exploit` for retry scenarios

### Problem

`vm_run_exploit` has auto-retry + auto-restart-on-crash, but agent prefers manual `vm_execute` loops (losing crash recovery). Only 5 calls across 3 sessions.

Root cause: agent treats exploit runs as interactive debugging (run → check dmesg → adjust), not fire-and-forget. This is correct during development, but wrong during the "run N times and hope the race wins" phase.

### Solution

Add hook check in `post_tool_use.py`: after 3+ `vm_execute` calls running the same binary path, inject:

```
You are manually retrying the same exploit. Use vm_run_exploit(remote_binary, max_retries=5)
for automatic retry with crash recovery instead of manual vm_execute loops.
```

### File changes

**`agent-container/.claude/hooks/post_tool_use.py`**: Add check, track `recent_binary_runs` in `/tmp/agent_state.json`.

---

## Change 4: Strengthen CLAUDE.md guidance for underused tools

### `vm_reset_overlay`

Add to "Troubleshooting SSH Failures" section:

```
If vm_restart fails 3+ times AND vm_get_log shows kernel panic or init errors,
call vm_reset_overlay() to delete the corrupted overlay and get a clean boot.
Do NOT keep restarting a broken overlay.
```

### `vm_run_exploit`

Add to "Step 7: Run and observe":

```
For race-condition exploits or heap sprays that need multiple attempts,
use vm_run_exploit(remote_binary, max_retries=5) instead of manual vm_execute loops.
It handles VM crash detection and automatic restart between attempts.
```

### File changes

**`agent-container/CLAUDE.md`**: Two additions, ~4 lines each.

---

## State tracking additions

New fields in `/tmp/agent_state.json` (managed by `post_tool_use.py`):

```json
{
  "consecutive_restarts": 0,
  "recent_binary_runs": [
    {"binary": "/tmp/agent_exploit", "timestamp": 1710000000},
    {"binary": "/tmp/agent_exploit", "timestamp": 1710000030}
  ]
}
```

- `consecutive_restarts`: incremented on `vm_restart`/`vm_start`, reset on any other MCP tool call
- `recent_binary_runs`: last 5 `vm_execute` calls where command matches a binary path pattern (`/tmp/agent_*` or `/home/*/agent_*`)

---

## Token impact

| Change | Effect |
|--------|--------|
| Remove `vm_compile_and_run` from MCP tool list | -400 tokens/turn (permanent) |
| Remove CLAUDE.md references to compile-on-VM | -100 tokens/turn (permanent) |
| Add CLAUDE.md guidance for underused tools | +80 tokens/turn |
| **Net savings** | **~420 tokens/turn** |

Plus eliminates ~200 thinking tokens per session where agent considers and rejects `vm_compile_and_run`.

---

## Implementation order

1. `mcp_ssh_server.py` — delete `vm_compile_and_run`
2. `agent-container/CLAUDE.md` — remove references, add guidance for underused tools
3. `post_tool_use.py` — add checks #11 (blind restart) and #12 (manual retry)
4. Rebuild Docker image
5. Test: `AGENT=shell ./run.sh CVE-2023-6560`, manually invoke tools to verify hooks fire

## Verification

- [ ] `vm_compile_and_run` absent from MCP tool list (run `claude /tools` in container)
- [ ] Hook #11: simulate 3 consecutive `vm_restart` → confirm nudge message appears
- [ ] Hook #12: simulate 3 `vm_execute ./agent_exploit` → confirm nudge message appears
- [ ] Run full session, confirm no regressions in core tools (vm_execute, vm_upload_file, vm_restart)
