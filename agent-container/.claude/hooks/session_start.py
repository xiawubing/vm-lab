#!/usr/bin/env python3
"""SessionStart hook: initialize shared state file for anti-overthinking system."""

import json
import os
import sys
import time


STATE_FILE = "/tmp/agent_state.json"


def main():
    try:
        # Read stdin (required by hook protocol, but we don't need it)
        sys.stdin.read()
    except Exception:
        pass

    # Initialize state file
    now = time.time()
    state = {
        "session_start": now,
        "last_tool_time": now,
        "skills_invoked": [],
        "cve_info_read": False,
        "compile_count": 0,
        "code_files_written": [],
        "stop_block_count": 0,
        "file_read_counts": {},
        "journal_last_mtime": 0,
        "journal_stale_count": 0,
        "flag_verified": False,
        "flag_verified_time": None,
        "flag_value": None,
        "root_achieved": False,
        "candidate_flags_checked": [],
        "tool_action_count": 0,
    }

    try:
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.rename(tmp, STATE_FILE)
    except Exception as e:
        print(f"session_start: failed to write state: {e}", file=sys.stderr)
        sys.exit(0)

    # Pre-create hypothesis journal with template
    journal_path = os.environ.get("AGENT_JOURNAL_PATH", "/workspace/agent_journal.md")
    try:
        if not os.path.exists(journal_path):
            with open(journal_path, "w") as f:
                f.write(
                    "# Hypothesis Journal\n"
                    "\n"
                    "## Conclusions (settled — do NOT revisit)\n"
                    "\n"
                    "## Current Hypothesis\n"
                    "\n"
                    "## Backlog\n"
                )
    except Exception as e:
        print(f"session_start: failed to create journal: {e}", file=sys.stderr)

    # Inject opening directive
    output = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": (
                "WORKFLOW ENFORCED BY HOOKS: "
                "After reading CVE info, you MUST invoke kernel-exploit-index skill "
                "BEFORE any exploitation reasoning. "
                "You MUST write your first agent_exploit.c within 5 minutes. "
                "Every thinking step without a tool action is wasted budget. "
                "These rules are monitored — violations trigger warnings and may block session exit."
            ),
        }
    }
    print(json.dumps(output))


if __name__ == "__main__":
    main()
