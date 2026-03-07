#!/usr/bin/env python3
"""Filter Claude Code stream-json output into readable real-time format.

Reads JSON lines from stdin and prints a human-readable summary:
- Assistant text messages
- Tool calls (name + truncated args)
- Tool results (truncated)
- Errors

Deduplicates assistant events: Claude Code emits multiple assistant events
per message with accumulating content blocks. We track what we've already
printed and only output new blocks.

Usage:
    claude -p --verbose --output-format stream-json "prompt" | python3 stream_filter.py
"""

import json
import sys

# ANSI colors
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

MAX_RESULT_LEN = 500


def truncate(s: str, max_len: int = MAX_RESULT_LEN) -> str:
    s = s.strip()
    if len(s) > max_len:
        return s[:max_len] + f"{DIM}... ({len(s)} chars total){RESET}"
    return s


def print_block(block):
    if block.get("type") == "text":
        text = block.get("text", "")
        if text.strip():
            print(f"\n{BOLD}{CYAN}[Claude]{RESET} {text}")
    elif block.get("type") == "tool_use":
        tool_name = block.get("name", "?")
        tool_input = block.get("input", {})
        args_summary = ""
        if isinstance(tool_input, dict):
            for k, v in tool_input.items():
                v_str = str(v)
                if len(v_str) > 120:
                    v_str = v_str[:120] + "..."
                args_summary += f"\n    {k}: {v_str}"
        print(f"\n{YELLOW}[Tool Call]{RESET} {BOLD}{tool_name}{RESET}{args_summary}")


# Track assistant message deduplication
_last_msg_id = None
_printed_block_count = 0

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue

    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue

    etype = event.get("type", "")

    if etype == "assistant":
        msg = event.get("message", {})
        msg_id = msg.get("id")
        blocks = msg.get("content", [])

        if msg_id and msg_id == _last_msg_id:
            # Same message emitted again with more content — only print new blocks
            new_blocks = blocks[_printed_block_count:]
        else:
            # New message
            new_blocks = blocks
            _last_msg_id = msg_id

        for block in new_blocks:
            print_block(block)

        _printed_block_count = len(blocks)

    elif etype == "tool_result":
        content = event.get("content", "")
        if isinstance(content, list):
            parts = []
            for c in content:
                if isinstance(c, dict) and c.get("type") == "text":
                    parts.append(c.get("text", ""))
                elif isinstance(c, str):
                    parts.append(c)
            content = "\n".join(parts)
        elif isinstance(content, dict):
            content = content.get("text", str(content))
        content = str(content)
        print(f"{GREEN}[Result]{RESET} {truncate(content)}")

    elif etype == "error":
        error = event.get("error", event)
        print(f"\n{RED}[Error]{RESET} {error}")

    elif etype == "system":
        msg = event.get("message", "")
        if isinstance(msg, dict):
            for block in msg.get("content", []):
                if block.get("type") == "text":
                    print(f"{DIM}[System] {block['text']}{RESET}")
        elif msg:
            print(f"{DIM}[System] {msg}{RESET}")

    sys.stdout.flush()
