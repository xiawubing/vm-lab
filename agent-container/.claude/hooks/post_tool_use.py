#!/usr/bin/env python3
"""PostToolUse hook: track state and inject corrective reminders.

This is the primary anti-overthinking mechanism. Fires after every tool call and
conditionally injects additionalContext to keep the agent on track.

Checks performed:
1. Time gap detection — warns if >120s since last tool call (long thinking)
2. Elapsed-without-compile — urgent warning if >300s with no compile attempt
3. CVE info read detection — reminds to invoke kernel-exploit-index skill
4. Skill invocation tracking — records which skills have been used
5. Code file tracking — records .c/.h files written
6. Compile tracking — counts gcc invocations
"""

import json
import os
import sys
import time


STATE_FILE = "/tmp/agent_state.json"


def load_state():
    """Load state, creating defaults if missing."""
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        now = time.time()
        return {
            "session_start": now,
            "last_tool_time": now,
            "skills_invoked": [],
            "cve_info_read": False,
            "compile_count": 0,
            "code_files_written": [],
            "stop_block_count": 0,
        }


def save_state(state):
    """Atomic write to state file."""
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.rename(tmp, STATE_FILE)


def main():
    try:
        event = json.loads(sys.stdin.read())
    except Exception:
        sys.exit(0)  # fail open

    state = load_state()
    now = time.time()
    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {})
    messages = []

    # ── 1. Time gap detection ──
    prev_tool_time = state.get("last_tool_time", now)
    gap = now - prev_tool_time
    if gap > 120:
        gap_min = int(gap // 60)
        gap_sec = int(gap % 60)
        messages.append(
            f"WARNING: {gap_min}m{gap_sec}s elapsed since your last tool action. "
            f"You spent that time thinking instead of acting. "
            f"Write code NOW. Do not reason further — convert your best idea into C code immediately."
        )

    # ── 2. Elapsed-without-compile check ──
    session_start = state.get("session_start", now)
    elapsed_s = now - session_start
    if elapsed_s > 300 and state.get("compile_count", 0) == 0:
        minutes = int(elapsed_s // 60)
        messages.append(
            f"URGENT: {minutes} minutes elapsed and you have NOT compiled any code. "
            f"Write a minimal crash trigger NOW, even if incomplete. "
            f"A 20-line program that calls the vulnerable syscall is better than no code. "
            f"Compile and run it immediately."
        )

    # ── 3. CVE info read detection ──
    if tool_name == "Read":
        file_path = tool_input.get("file_path", "")
        if "/cve-info/" in file_path:
            state["cve_info_read"] = True
            if "kernel-exploit-index" not in state.get("skills_invoked", []):
                messages.append(
                    "You just read the CVE info file. Your NEXT action MUST be: "
                    'invoke the kernel-exploit-index skill via Skill tool '
                    '(skill: "kernel-exploit-index"). '
                    "Do NOT start reasoning about exploitation strategy — the skill has a complete "
                    "decision tree covering technique selection for all vulnerability types."
                )

    # ── 4. Skill invocation tracking ──
    if tool_name == "Skill":
        skill_name = tool_input.get("skill", "")
        if skill_name and skill_name not in state.get("skills_invoked", []):
            state.setdefault("skills_invoked", []).append(skill_name)
        # After the index skill, nudge toward writing code
        if skill_name == "kernel-exploit-index":
            messages.append(
                "Good — index skill invoked. Now invoke the specific technique skill(s) "
                "it recommended, then IMMEDIATELY write your first agent_exploit.c. "
                "Do NOT spend more than 1 thinking step before writing code."
            )

    # ── 5. Code file tracking ──
    if tool_name in ("Write", "Edit"):
        file_path = tool_input.get("file_path", "")
        if file_path and file_path.endswith((".c", ".h")):
            code_files = state.get("code_files_written", [])
            if file_path not in code_files:
                code_files.append(file_path)
                state["code_files_written"] = code_files

    # ── 6. Compile tracking ──
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        if "gcc" in cmd or "make" in cmd:
            state["compile_count"] = state.get("compile_count", 0) + 1

    # ── 7. Post-CVE-read skill reminder (fires on any tool if CVE was read but skill not invoked) ──
    if (
        state.get("cve_info_read", False)
        and "kernel-exploit-index" not in state.get("skills_invoked", [])
        and tool_name not in ("Read", "Skill")  # don't double-warn on Read (handled above)
        and elapsed_s > 30  # give a small grace period
    ):
        messages.append(
            "REMINDER: You read the CVE info but have NOT invoked kernel-exploit-index yet. "
            "Do it NOW before continuing."
        )

    # ── Update last_tool_time AFTER gap detection ──
    state["last_tool_time"] = now
    save_state(state)

    # ── Output ──
    if messages:
        combined = "\n\n".join(messages)
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": combined,
            }
        }
        print(json.dumps(output))


if __name__ == "__main__":
    main()
