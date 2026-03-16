#!/usr/bin/env python3
"""Integration tests for anti-overthinking hooks.

Tests the full hook lifecycle with realistic Claude Code JSON payloads.
Validates: JSON I/O protocol, state file management, corrective messages,
stop-gate logic, and edge cases.

Usage:
    python3 tests/test_hooks.py
    # or from repo root:
    cd agent-container && python3 tests/test_hooks.py
"""

import json
import os
import subprocess
import sys
import tempfile
import time

# ── Config ──────────────────────────────────────────────────────────────
HOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", ".claude", "hooks")
STATE_FILE = "/tmp/agent_state.json"

# Resolve absolute paths
SESSION_START = os.path.join(HOOKS_DIR, "session_start.py")
POST_TOOL_USE = os.path.join(HOOKS_DIR, "post_tool_use.py")
STOP_GATE = os.path.join(HOOKS_DIR, "stop_gate.py")

passed = 0
failed = 0
errors = []


def run_hook(script: str, stdin_data: dict) -> tuple[str, str, int]:
    """Run a hook script with JSON stdin, return (stdout, stderr, exit_code)."""
    result = subprocess.run(
        [sys.executable, script],
        input=json.dumps(stdin_data),
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def write_state(state: dict):
    """Write a state file directly."""
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def read_state() -> dict:
    """Read the current state file."""
    with open(STATE_FILE) as f:
        return json.load(f)


def cleanup_state():
    """Remove state file if it exists."""
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)


def check(name: str, condition: bool, detail: str = ""):
    """Record a test result."""
    global passed, failed
    if condition:
        passed += 1
        print(f"  \033[32m✓\033[0m {name}")
    else:
        failed += 1
        msg = f"  \033[31m✗\033[0m {name}"
        if detail:
            msg += f" — {detail}"
        print(msg)
        errors.append(name)


# ═══════════════════════════════════════════════════════════════════════
# SECTION 1: SessionStart hook
# ═══════════════════════════════════════════════════════════════════════
print("\n\033[1m=== 1. SessionStart Hook ===\033[0m\n")

# Test 1.1: Basic initialization
cleanup_state()
stdout, stderr, code = run_hook(SESSION_START, {
    "session_id": "test-001",
    "hook_event_name": "SessionStart",
    "source": "startup",
    "cwd": "/workspace",
    "permission_mode": "default",
})
check("1.1 exit code is 0", code == 0, f"got {code}")
check("1.2 state file created", os.path.exists(STATE_FILE))

state = read_state()
check("1.3 session_start is a timestamp", isinstance(state["session_start"], float))
check("1.4 last_tool_time is a timestamp", isinstance(state["last_tool_time"], float))
check("1.5 skills_invoked is empty list", state["skills_invoked"] == [])
check("1.6 cve_info_read is False", state["cve_info_read"] is False)
check("1.7 compile_count is 0", state["compile_count"] == 0)
check("1.8 code_files_written is empty list", state["code_files_written"] == [])
check("1.9 stop_block_count is 0", state["stop_block_count"] == 0)

# Validate output JSON structure
output = json.loads(stdout)
check("1.10 output has hookSpecificOutput",
      "hookSpecificOutput" in output)
check("1.11 hookEventName is SessionStart",
      output["hookSpecificOutput"]["hookEventName"] == "SessionStart")
check("1.12 additionalContext present",
      "additionalContext" in output["hookSpecificOutput"])
check("1.13 additionalContext mentions kernel-exploit-index",
      "kernel-exploit-index" in output["hookSpecificOutput"]["additionalContext"])


# Test 1.2: Idempotent — running again overwrites cleanly
stdout2, _, code2 = run_hook(SESSION_START, {
    "session_id": "test-002",
    "hook_event_name": "SessionStart",
    "source": "startup",
    "cwd": "/workspace",
    "permission_mode": "default",
})
state2 = read_state()
check("1.14 re-run creates fresh state",
      state2["session_start"] >= state["session_start"])

# Test 1.3: Handles empty stdin gracefully
result = subprocess.run(
    [sys.executable, SESSION_START],
    input="",
    capture_output=True,
    text=True,
    timeout=10,
)
check("1.15 empty stdin doesn't crash", result.returncode == 0)


# ═══════════════════════════════════════════════════════════════════════
# SECTION 2: PostToolUse hook — CVE info read detection
# ═══════════════════════════════════════════════════════════════════════
print("\n\033[1m=== 2. PostToolUse: CVE Info Read ===\033[0m\n")

# Reset state fresh
cleanup_state()
run_hook(SESSION_START, {"hook_event_name": "SessionStart", "source": "startup",
                          "cwd": "/workspace", "permission_mode": "default"})

# 2.1: Read a CVE info file → should remind about kernel-exploit-index
stdout, _, code = run_hook(POST_TOOL_USE, {
    "session_id": "test-001",
    "hook_event_name": "PostToolUse",
    "tool_name": "Read",
    "tool_input": {"file_path": "/app/cve-info/CVE-2023-6560.md"},
    "tool_response": {"content": "...", "success": True},
    "tool_use_id": "toolu_001",
    "cwd": "/workspace",
    "permission_mode": "default",
})
check("2.1 exit code is 0", code == 0, f"got {code}")
output = json.loads(stdout) if stdout else {}
ctx = output.get("hookSpecificOutput", {}).get("additionalContext", "")
check("2.2 reminds about kernel-exploit-index",
      "kernel-exploit-index" in ctx, f"got: {ctx[:100]}")
check("2.3 output has correct hookEventName",
      output.get("hookSpecificOutput", {}).get("hookEventName") == "PostToolUse")

state = read_state()
check("2.4 cve_info_read set to True", state["cve_info_read"] is True)
check("2.5 last_tool_time updated", state["last_tool_time"] > state["session_start"])


# 2.2: Non-Read/Skill tool after CVE read without skill → should get REMINDER
# Need session_start old enough to pass the 30s grace period
state = read_state()
state["session_start"] = time.time() - 60  # 60s ago
write_state(state)
stdout, _, code = run_hook(POST_TOOL_USE, {
    "session_id": "test-001",
    "hook_event_name": "PostToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "echo test"},
    "tool_response": {"output": "test", "exit_code": 0},
    "tool_use_id": "toolu_002",
    "cwd": "/workspace",
    "permission_mode": "default",
})
# CVE was already read, skill not invoked yet → should get REMINDER
output = json.loads(stdout) if stdout else {}
ctx = output.get("hookSpecificOutput", {}).get("additionalContext", "")
check("2.6 reminder fires on non-Read tool after CVE read without skill",
      "REMINDER" in ctx, f"got: {ctx[:100]}")


# ═══════════════════════════════════════════════════════════════════════
# SECTION 3: PostToolUse hook — Skill tracking
# ═══════════════════════════════════════════════════════════════════════
print("\n\033[1m=== 3. PostToolUse: Skill Tracking ===\033[0m\n")

# 3.1: Invoke kernel-exploit-index
stdout, _, code = run_hook(POST_TOOL_USE, {
    "session_id": "test-001",
    "hook_event_name": "PostToolUse",
    "tool_name": "Skill",
    "tool_input": {"skill": "kernel-exploit-index"},
    "tool_response": {"content": "..."},
    "tool_use_id": "toolu_003",
    "cwd": "/workspace",
    "permission_mode": "default",
})
state = read_state()
check("3.1 kernel-exploit-index tracked in skills_invoked",
      "kernel-exploit-index" in state["skills_invoked"])
output = json.loads(stdout) if stdout else {}
ctx = output.get("hookSpecificOutput", {}).get("additionalContext", "")
check("3.2 positive reinforcement after index skill",
      "write" in ctx.lower() or "code" in ctx.lower(), f"got: {ctx[:100]}")


# 3.2: Invoke another skill
stdout, _, code = run_hook(POST_TOOL_USE, {
    "session_id": "test-001",
    "hook_event_name": "PostToolUse",
    "tool_name": "Skill",
    "tool_input": {"skill": "kernel-exploit-dirty-pagetable"},
    "tool_response": {"content": "..."},
    "tool_use_id": "toolu_004",
    "cwd": "/workspace",
    "permission_mode": "default",
})
state = read_state()
check("3.3 second skill also tracked",
      "kernel-exploit-dirty-pagetable" in state["skills_invoked"])
check("3.4 both skills in list", len(state["skills_invoked"]) == 2)


# 3.3: After index is invoked, no more REMINDER on subsequent tools
stdout, _, code = run_hook(POST_TOOL_USE, {
    "session_id": "test-001",
    "hook_event_name": "PostToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "echo hello"},
    "tool_response": {"output": "hello", "exit_code": 0},
    "tool_use_id": "toolu_005",
    "cwd": "/workspace",
    "permission_mode": "default",
})
check("3.5 no REMINDER after skill invoked",
      stdout == "" or "REMINDER" not in stdout, f"got: {stdout[:100]}")


# ═══════════════════════════════════════════════════════════════════════
# SECTION 4: PostToolUse hook — Time gap detection
# ═══════════════════════════════════════════════════════════════════════
print("\n\033[1m=== 4. PostToolUse: Time Gap Detection ===\033[0m\n")

# 4.1: Simulate 3-minute gap
state = read_state()
state["last_tool_time"] = time.time() - 200  # 200s ago
write_state(state)

stdout, _, code = run_hook(POST_TOOL_USE, {
    "session_id": "test-001",
    "hook_event_name": "PostToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "ls"},
    "tool_response": {"output": "...", "exit_code": 0},
    "tool_use_id": "toolu_006",
    "cwd": "/workspace",
    "permission_mode": "default",
})
output = json.loads(stdout) if stdout else {}
ctx = output.get("hookSpecificOutput", {}).get("additionalContext", "")
check("4.1 time gap warning fires at 200s",
      "WARNING" in ctx and ("3m" in ctx or "elapsed" in ctx), f"got: {ctx[:150]}")


# 4.2: No warning when gap < 120s
state = read_state()
# last_tool_time was just updated by the previous hook run
# Simulate a quick follow-up
stdout, _, code = run_hook(POST_TOOL_USE, {
    "session_id": "test-001",
    "hook_event_name": "PostToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "ls"},
    "tool_response": {"output": "...", "exit_code": 0},
    "tool_use_id": "toolu_007",
    "cwd": "/workspace",
    "permission_mode": "default",
})
check("4.2 no warning when gap < 120s",
      stdout == "" or "WARNING" not in stdout, f"got: {stdout[:100]}")


# ═══════════════════════════════════════════════════════════════════════
# SECTION 5: PostToolUse hook — Compile tracking
# ═══════════════════════════════════════════════════════════════════════
print("\n\033[1m=== 5. PostToolUse: Compile & Code Tracking ===\033[0m\n")

# 5.1: Write a .c file → tracked
stdout, _, code = run_hook(POST_TOOL_USE, {
    "session_id": "test-001",
    "hook_event_name": "PostToolUse",
    "tool_name": "Write",
    "tool_input": {"file_path": "/tmp/agent_exploit.c", "content": "int main() {}"},
    "tool_response": {"success": True},
    "tool_use_id": "toolu_008",
    "cwd": "/workspace",
    "permission_mode": "default",
})
state = read_state()
check("5.1 .c file tracked in code_files_written",
      "/tmp/agent_exploit.c" in state["code_files_written"])

# 5.2: Edit a .c file → tracked (no duplicate)
stdout, _, code = run_hook(POST_TOOL_USE, {
    "session_id": "test-001",
    "hook_event_name": "PostToolUse",
    "tool_name": "Edit",
    "tool_input": {"file_path": "/tmp/agent_exploit.c", "old_string": "int", "new_string": "void"},
    "tool_response": {"success": True},
    "tool_use_id": "toolu_009",
    "cwd": "/workspace",
    "permission_mode": "default",
})
state = read_state()
check("5.2 no duplicate entries",
      state["code_files_written"].count("/tmp/agent_exploit.c") == 1)

# 5.3: gcc command → compile_count incremented
state_before = read_state()
stdout, _, code = run_hook(POST_TOOL_USE, {
    "session_id": "test-001",
    "hook_event_name": "PostToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "gcc -static -o /tmp/agent_exploit agent_exploit.c -O0"},
    "tool_response": {"output": "", "exit_code": 0},
    "tool_use_id": "toolu_010",
    "cwd": "/workspace",
    "permission_mode": "default",
})
state = read_state()
check("5.3 compile_count incremented",
      state["compile_count"] == state_before["compile_count"] + 1)

# 5.4: non-gcc Bash → compile_count unchanged
cc_before = state["compile_count"]
stdout, _, code = run_hook(POST_TOOL_USE, {
    "session_id": "test-001",
    "hook_event_name": "PostToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "echo hello"},
    "tool_response": {"output": "hello", "exit_code": 0},
    "tool_use_id": "toolu_011",
    "cwd": "/workspace",
    "permission_mode": "default",
})
state = read_state()
check("5.4 non-gcc bash doesn't increment compile_count",
      state["compile_count"] == cc_before)

# 5.5: Write a non-.c file → NOT tracked
stdout, _, code = run_hook(POST_TOOL_USE, {
    "session_id": "test-001",
    "hook_event_name": "PostToolUse",
    "tool_name": "Write",
    "tool_input": {"file_path": "/tmp/notes.txt", "content": "test"},
    "tool_response": {"success": True},
    "tool_use_id": "toolu_012",
    "cwd": "/workspace",
    "permission_mode": "default",
})
state = read_state()
check("5.5 non-.c file NOT tracked",
      "/tmp/notes.txt" not in state["code_files_written"])


# ═══════════════════════════════════════════════════════════════════════
# SECTION 6: PostToolUse hook — Elapsed-without-compile urgency
# ═══════════════════════════════════════════════════════════════════════
print("\n\033[1m=== 6. PostToolUse: Elapsed-Without-Compile ===\033[0m\n")

# 6.1: >300s with no compile → URGENT
state = read_state()
state["session_start"] = time.time() - 400  # 400s ago
state["compile_count"] = 0
state["last_tool_time"] = time.time()  # no gap warning
write_state(state)

stdout, _, code = run_hook(POST_TOOL_USE, {
    "session_id": "test-001",
    "hook_event_name": "PostToolUse",
    "tool_name": "Read",
    "tool_input": {"file_path": "/src/something.c"},
    "tool_response": {"content": "..."},
    "tool_use_id": "toolu_013",
    "cwd": "/workspace",
    "permission_mode": "default",
})
output = json.loads(stdout) if stdout else {}
ctx = output.get("hookSpecificOutput", {}).get("additionalContext", "")
check("6.1 URGENT warning at 400s with no compile",
      "URGENT" in ctx, f"got: {ctx[:100]}")

# 6.2: >300s WITH compile → no URGENT
state = read_state()
state["session_start"] = time.time() - 400
state["compile_count"] = 1
write_state(state)

stdout, _, code = run_hook(POST_TOOL_USE, {
    "session_id": "test-001",
    "hook_event_name": "PostToolUse",
    "tool_name": "Read",
    "tool_input": {"file_path": "/src/something.c"},
    "tool_response": {"content": "..."},
    "tool_use_id": "toolu_014",
    "cwd": "/workspace",
    "permission_mode": "default",
})
check("6.2 no URGENT when compile_count > 0",
      stdout == "" or "URGENT" not in stdout)


# ═══════════════════════════════════════════════════════════════════════
# SECTION 7: PostToolUse hook — MCP tool handling
# ═══════════════════════════════════════════════════════════════════════
print("\n\033[1m=== 7. PostToolUse: MCP Tool Handling ===\033[0m\n")

# Reset state
cleanup_state()
run_hook(SESSION_START, {"hook_event_name": "SessionStart", "source": "startup",
                          "cwd": "/workspace", "permission_mode": "default"})

# 7.1: MCP tool updates last_tool_time
state_before = read_state()
time.sleep(0.1)  # ensure timestamp difference
stdout, _, code = run_hook(POST_TOOL_USE, {
    "session_id": "test-001",
    "hook_event_name": "PostToolUse",
    "tool_name": "mcp__vm-ssh__vm_execute",
    "tool_input": {"command": "uname -r", "timeout": 30},
    "tool_response": {"content": "6.6.0+"},
    "tool_use_id": "toolu_015",
    "cwd": "/workspace",
    "permission_mode": "default",
})
state = read_state()
check("7.1 MCP tool updates last_tool_time",
      state["last_tool_time"] > state_before["last_tool_time"])

# 7.2: MCP vm_compile_and_run with gcc → should track compile
# (tool_name is MCP, but it doesn't contain "gcc" in tool_input.command)
# Our hook only checks Bash for gcc — MCP compile is different
check("7.2 MCP tools don't false-positive on compile tracking",
      state["compile_count"] == 0)


# ═══════════════════════════════════════════════════════════════════════
# SECTION 8: Stop gate hook
# ═══════════════════════════════════════════════════════════════════════
print("\n\033[1m=== 8. Stop Gate Hook ===\033[0m\n")

# 8.1: No compile → block
cleanup_state()
run_hook(SESSION_START, {"hook_event_name": "SessionStart", "source": "startup",
                          "cwd": "/workspace", "permission_mode": "default"})
stdout, _, code = run_hook(STOP_GATE, {
    "session_id": "test-001",
    "hook_event_name": "Stop",
    "stop_hook_active": False,
    "last_assistant_message": "I analyzed the vulnerability...",
    "cwd": "/workspace",
    "permission_mode": "default",
})
check("8.1 exit code 0", code == 0)
output = json.loads(stdout)
check("8.2 decision is block", output.get("decision") == "block")
check("8.3 reason mentions writing code",
      "code" in output.get("reason", "").lower() or "exploit" in output.get("reason", "").lower())
check("8.4 no hookSpecificOutput wrapper (Stop uses top-level)",
      "hookSpecificOutput" not in output)
state = read_state()
check("8.5 stop_block_count incremented to 1", state["stop_block_count"] == 1)


# 8.2: Code written but not compiled → block with specific message
state = read_state()
state["code_files_written"] = ["/tmp/agent_exploit.c"]
state["compile_count"] = 0
write_state(state)
stdout, _, code = run_hook(STOP_GATE, {
    "session_id": "test-001",
    "hook_event_name": "Stop",
    "stop_hook_active": False,
    "last_assistant_message": "...",
    "cwd": "/workspace",
    "permission_mode": "default",
})
output = json.loads(stdout)
check("8.6 block mentions 'never compiled'",
      "compiled" in output.get("reason", "").lower() or "compile" in output.get("reason", "").lower())


# 8.3: Compile done → allow stop
state = read_state()
state["compile_count"] = 1
state["stop_block_count"] = 0
write_state(state)
stdout, _, code = run_hook(STOP_GATE, {
    "session_id": "test-001",
    "hook_event_name": "Stop",
    "stop_hook_active": False,
    "last_assistant_message": "...",
    "cwd": "/workspace",
    "permission_mode": "default",
})
check("8.7 allows stop when compiled (no stdout)", stdout == "")
check("8.8 exit code 0", code == 0)


# 8.4: Loop prevention — stop_block_count >= 2
state = read_state()
state["compile_count"] = 0
state["stop_block_count"] = 2
write_state(state)
stdout, _, code = run_hook(STOP_GATE, {
    "session_id": "test-001",
    "hook_event_name": "Stop",
    "stop_hook_active": False,
    "last_assistant_message": "...",
    "cwd": "/workspace",
    "permission_mode": "default",
})
check("8.9 allows stop after 2 blocks (loop prevention)", stdout == "")


# 8.5: stop_hook_active = True → allow
state = read_state()
state["compile_count"] = 0
state["stop_block_count"] = 0
write_state(state)
stdout, _, code = run_hook(STOP_GATE, {
    "session_id": "test-001",
    "hook_event_name": "Stop",
    "stop_hook_active": True,
    "last_assistant_message": "...",
    "cwd": "/workspace",
    "permission_mode": "default",
})
check("8.10 allows stop when stop_hook_active=True", stdout == "")


# 8.6: Missing state file → allow (fail open)
cleanup_state()
stdout, _, code = run_hook(STOP_GATE, {
    "session_id": "test-001",
    "hook_event_name": "Stop",
    "stop_hook_active": False,
    "last_assistant_message": "...",
    "cwd": "/workspace",
    "permission_mode": "default",
})
check("8.11 allows stop when no state file (fail open)", stdout == "")
check("8.12 exit code 0 (fail open)", code == 0)


# ═══════════════════════════════════════════════════════════════════════
# SECTION 9: Edge cases
# ═══════════════════════════════════════════════════════════════════════
print("\n\033[1m=== 9. Edge Cases ===\033[0m\n")

# 9.1: Malformed JSON input → fail open
result = subprocess.run(
    [sys.executable, POST_TOOL_USE],
    input="not json at all",
    capture_output=True,
    text=True,
    timeout=10,
)
check("9.1 malformed JSON → exit 0 (fail open)", result.returncode == 0)

# 9.2: Empty tool_input → no crash
cleanup_state()
run_hook(SESSION_START, {"hook_event_name": "SessionStart", "source": "startup",
                          "cwd": "/workspace", "permission_mode": "default"})
stdout, _, code = run_hook(POST_TOOL_USE, {
    "session_id": "test-001",
    "hook_event_name": "PostToolUse",
    "tool_name": "Read",
    "tool_input": {},
    "tool_use_id": "toolu_020",
    "cwd": "/workspace",
    "permission_mode": "default",
})
check("9.2 empty tool_input doesn't crash", code == 0)

# 9.3: Missing tool_name → no crash
stdout, _, code = run_hook(POST_TOOL_USE, {
    "session_id": "test-001",
    "hook_event_name": "PostToolUse",
    "tool_use_id": "toolu_021",
    "cwd": "/workspace",
    "permission_mode": "default",
})
check("9.3 missing tool_name doesn't crash", code == 0)

# 9.4: Concurrent state file access (simulate by running two hooks rapidly)
cleanup_state()
run_hook(SESSION_START, {"hook_event_name": "SessionStart", "source": "startup",
                          "cwd": "/workspace", "permission_mode": "default"})
# Run two PostToolUse hooks in rapid succession
for i in range(5):
    run_hook(POST_TOOL_USE, {
        "session_id": "test-001",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": f"echo {i}"},
        "tool_use_id": f"toolu_rapid_{i}",
        "cwd": "/workspace",
        "permission_mode": "default",
    })
state = read_state()
check("9.4 state file valid after rapid hook calls",
      isinstance(state, dict) and "last_tool_time" in state)


# ═══════════════════════════════════════════════════════════════════════
# SECTION 10: Full lifecycle simulation
# ═══════════════════════════════════════════════════════════════════════
print("\n\033[1m=== 10. Full Lifecycle Simulation ===\033[0m\n")

# Simulate the ideal workflow: start → read CVE → invoke skill → write code → compile → stop
cleanup_state()

# Step 1: Session start
run_hook(SESSION_START, {"hook_event_name": "SessionStart", "source": "startup",
                          "cwd": "/workspace", "permission_mode": "default"})
state = read_state()
check("10.1 session initialized", state["compile_count"] == 0)

# Step 2: Read CVE info → expect skill reminder
stdout, _, _ = run_hook(POST_TOOL_USE, {
    "session_id": "lifecycle",
    "hook_event_name": "PostToolUse",
    "tool_name": "Read",
    "tool_input": {"file_path": "/app/cve-info/CVE-2023-6560.md"},
    "tool_response": {"content": "..."},
    "tool_use_id": "t1",
    "cwd": "/workspace",
    "permission_mode": "default",
})
ctx = json.loads(stdout).get("hookSpecificOutput", {}).get("additionalContext", "")
check("10.2 CVE read triggers skill reminder", "kernel-exploit-index" in ctx)

# Step 3: Invoke index skill → expect positive nudge
stdout, _, _ = run_hook(POST_TOOL_USE, {
    "session_id": "lifecycle",
    "hook_event_name": "PostToolUse",
    "tool_name": "Skill",
    "tool_input": {"skill": "kernel-exploit-index"},
    "tool_response": {"content": "..."},
    "tool_use_id": "t2",
    "cwd": "/workspace",
    "permission_mode": "default",
})
ctx = json.loads(stdout).get("hookSpecificOutput", {}).get("additionalContext", "")
check("10.3 index skill gets positive nudge", "code" in ctx.lower() or "write" in ctx.lower())

# Step 4: Write code → tracked
run_hook(POST_TOOL_USE, {
    "session_id": "lifecycle",
    "hook_event_name": "PostToolUse",
    "tool_name": "Write",
    "tool_input": {"file_path": "/tmp/agent_exploit.c", "content": "int main(){}"},
    "tool_response": {"success": True},
    "tool_use_id": "t3",
    "cwd": "/workspace",
    "permission_mode": "default",
})
state = read_state()
check("10.4 code file tracked", "/tmp/agent_exploit.c" in state["code_files_written"])

# Step 5: Compile → tracked
run_hook(POST_TOOL_USE, {
    "session_id": "lifecycle",
    "hook_event_name": "PostToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "gcc -static -o /tmp/agent_exploit /tmp/agent_exploit.c"},
    "tool_response": {"output": "", "exit_code": 0},
    "tool_use_id": "t4",
    "cwd": "/workspace",
    "permission_mode": "default",
})
state = read_state()
check("10.5 compile tracked", state["compile_count"] == 1)

# Step 6: Stop → should be allowed
stdout, _, code = run_hook(STOP_GATE, {
    "session_id": "lifecycle",
    "hook_event_name": "Stop",
    "stop_hook_active": False,
    "last_assistant_message": "Done.",
    "cwd": "/workspace",
    "permission_mode": "default",
})
check("10.6 stop allowed after compile", stdout == "")
check("10.7 exit code 0", code == 0)


# ═══════════════════════════════════════════════════════════════════════
# SECTION 11: settings.json validation
# ═══════════════════════════════════════════════════════════════════════
print("\n\033[1m=== 11. settings.json Validation ===\033[0m\n")

settings_path = os.path.join(os.path.dirname(__file__), "..", ".claude", "settings.json")
with open(settings_path) as f:
    settings = json.load(f)

hooks_config = settings.get("hooks", {})
check("11.1 has SessionStart hooks", "SessionStart" in hooks_config)
check("11.2 has PostToolUse hooks", "PostToolUse" in hooks_config)
check("11.3 has Stop hooks", "Stop" in hooks_config)

# Validate PostToolUse matchers
post_matchers = [entry.get("matcher", "") for entry in hooks_config.get("PostToolUse", [])]
check("11.4 Read matcher present", "Read" in post_matchers)
check("11.5 Skill matcher present", "Skill" in post_matchers)
check("11.6 Bash matcher present", "Bash" in post_matchers)
check("11.7 Write matcher present", "Write" in post_matchers)
check("11.8 Edit matcher present", "Edit" in post_matchers)
check("11.9 MCP matcher present", "mcp__vm-ssh__.*" in post_matchers)

# Validate all hook commands reference existing scripts
for event_name, entries in hooks_config.items():
    for entry in entries:
        for hook in entry.get("hooks", []):
            cmd = hook.get("command", "")
            # Extract script path from command (format: "python3 /path/to/script.py")
            parts = cmd.split()
            if len(parts) >= 2:
                script_path = parts[1]
                # Map container path to local path for validation
                local_path = script_path.replace(
                    "/workspace/.claude/hooks/",
                    os.path.join(os.path.dirname(__file__), "..", ".claude", "hooks") + "/"
                )
                check(f"11.x script exists: {os.path.basename(local_path)}",
                      os.path.exists(local_path), f"missing: {local_path}")


# ═══════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════
cleanup_state()

print(f"\n\033[1m{'=' * 50}\033[0m")
print(f"\033[1m  Results: {passed} passed, {failed} failed\033[0m")
if errors:
    print(f"\033[31m  Failed tests:\033[0m")
    for e in errors:
        print(f"\033[31m    - {e}\033[0m")
print(f"\033[1m{'=' * 50}\033[0m\n")

sys.exit(1 if failed > 0 else 0)
