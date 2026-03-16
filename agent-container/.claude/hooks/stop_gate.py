#!/usr/bin/env python3
"""Stop hook: block session exit if no compile attempt was made.

Three safeguards against infinite blocking:
1. stop_hook_active from stdin — Claude Code sets this when agent is already forced to continue
2. stop_block_count in state file — after 2 blocks, allow stop regardless
3. --max-budget-usd — Claude Code force-terminates when budget exhausted
"""

import json
import os
import sys


STATE_FILE = "/tmp/agent_state.json"


def main():
    try:
        event = json.loads(sys.stdin.read())
    except Exception:
        sys.exit(0)  # fail open

    # Load state
    try:
        with open(STATE_FILE) as f:
            state = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # No state file — allow stop to prevent blocking on broken setup
        sys.exit(0)

    compile_count = state.get("compile_count", 0)
    code_files = state.get("code_files_written", [])
    stop_block_count = state.get("stop_block_count", 0)
    stop_hook_active = event.get("stop_hook_active", False)

    # Safeguard: if already in forced-continuation or blocked too many times, allow stop
    if stop_hook_active or stop_block_count >= 2:
        sys.exit(0)

    # Allow stop if at least one compile was attempted
    if compile_count > 0:
        sys.exit(0)

    # Block: no compile attempt made
    state["stop_block_count"] = stop_block_count + 1
    try:
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.rename(tmp, STATE_FILE)
    except Exception:
        pass  # state update failed, but still block this time

    if not code_files:
        reason = (
            "You have NOT written ANY exploit code. "
            "You MUST write at least one agent_exploit.c, compile it with "
            "gcc -static -I/src/include/uapi -I/src/arch/x86/include/uapi, "
            "upload to VM, and run it before the session can end. "
            "Write a minimal crash trigger NOW — even 20 lines is enough."
        )
    else:
        reason = (
            f"You wrote {len(code_files)} source file(s) but NEVER compiled them. "
            "Compile your code now: "
            "gcc -static -I/src/include/uapi -I/src/arch/x86/include/uapi "
            "-o /tmp/agent_exploit agent_exploit.c -O0 "
            "then upload and run it."
        )

    output = {"decision": "block", "reason": reason}
    print(json.dumps(output))


if __name__ == "__main__":
    main()
