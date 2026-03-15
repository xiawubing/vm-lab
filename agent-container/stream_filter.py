#!/usr/bin/env python3
"""Filter Claude Code stream-json output into readable terminal + Markdown log.

Reads JSON lines from stdin and:
1. Prints a detailed, readable terminal output (with ANSI colors)
2. Writes a Markdown session log to /workspace/logs/
3. Saves each PoC source code iteration to /workspace/logs/code/

Design:
- Terminal: concise one-line summaries (no inline code or diffs)
- Markdown log: references to saved files (no inline code dumps)
- Code/diffs saved to logs/code/ for separate viewing
- Compile errors and exploit results shown in full (important feedback)

Usage:
    claude -p --verbose --output-format stream-json "prompt" \
        | python3 stream_filter.py [--log-dir /workspace/logs] [--cve CVE-XXXX]
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# ── ANSI colors ──────────────────────────────────────────────────────────
CYAN    = "\033[36m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
RED     = "\033[31m"
MAGENTA = "\033[35m"
DIM     = "\033[2m"
BOLD    = "\033[1m"
RESET   = "\033[0m"
WHITE   = "\033[97m"
BG_RED  = "\033[41m"
BG_GREEN= "\033[42m"

# ── Config ───────────────────────────────────────────────────────────────
MAX_RESULT_LEN   = 2000   # max chars of tool output to show in terminal
THINKING_PREVIEW = 3      # lines of thinking to show

# ── Parse args ───────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument("--log-dir", default="/workspace/logs")
parser.add_argument("--cve", default=os.environ.get("CVE_ID", "unknown"))
args, _ = parser.parse_known_args()

LOG_DIR  = Path(args.log_dir)
LOG_DIR.mkdir(parents=True, exist_ok=True)

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
session_tag = f"{args.cve}_{timestamp}"
CODE_DIR = LOG_DIR / "code" / session_tag
CODE_DIR.mkdir(parents=True, exist_ok=True)
MD_LOG   = LOG_DIR / f"session_{session_tag}.md"

# ── State ────────────────────────────────────────────────────────────────
_last_msg_id = None
_seen_block_ids = set()  # track tool_use IDs we've already processed
_iteration = 0           # PoC code revision counter
_step_num = 0            # sequential step counter for log
_start_time = datetime.now()
_total_input_tokens = 0
_total_output_tokens = 0


def tprint(*a, **kw):
    """Print to terminal with flush."""
    print(*a, **kw)
    sys.stdout.flush()


def md(text: str):
    """Append to Markdown log file."""
    with open(MD_LOG, "a") as f:
        f.write(text)


def step(label: str) -> int:
    """Increment step counter and return it."""
    global _step_num
    _step_num += 1
    return _step_num


def elapsed() -> str:
    """Time since session start."""
    dt = datetime.now() - _start_time
    m, s = divmod(int(dt.total_seconds()), 60)
    return f"{m}:{s:02d}"


def truncate(s: str, max_len: int = MAX_RESULT_LEN) -> str:
    s = s.strip()
    if len(s) > max_len:
        return s[:max_len] + f"\n{DIM}... ({len(s)} chars total){RESET}"
    return s


def save_source(filename: str, content: str):
    """Save a PoC source code iteration to disk."""
    global _iteration
    _iteration += 1
    # Save numbered copy
    stem = Path(filename).stem
    suffix = Path(filename).suffix or ".c"
    versioned = CODE_DIR / f"{stem}_v{_iteration}{suffix}"
    versioned.write_text(content)
    # Also save as "latest"
    latest = CODE_DIR / f"{stem}_latest{suffix}"
    latest.write_text(content)
    return str(versioned), _iteration


# ── Markdown log header ─────────────────────────────────────────────────
md(f"# Exploit Development Session: {args.cve}\n\n")
md(f"- **Started**: {_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
md(f"- **CVE**: {args.cve}\n\n")
md(f"---\n\n")


# ── Process events ──────────────────────────────────────────────────────

def handle_thinking(text: str):
    """Show a brief summary of thinking and log full text."""
    lines = text.strip().split("\n")
    preview = lines[:THINKING_PREVIEW]
    preview_text = "\n".join(f"    {l}" for l in preview)
    if len(lines) > THINKING_PREVIEW:
        preview_text += f"\n    {DIM}... ({len(lines)} lines){RESET}"
    tprint(f"\n{DIM}[Thinking]{RESET}")
    tprint(preview_text)

    n = step("thinking")
    md(f"### Step {n} — Thinking [{elapsed()}]\n\n")
    md(f"<details>\n<summary>Agent reasoning ({len(lines)} lines)</summary>\n\n")
    md(f"```\n{text.strip()}\n```\n\n")
    md(f"</details>\n\n")


def handle_text(text: str):
    """Agent's spoken output."""
    if not text.strip():
        return
    tprint(f"\n{BOLD}{CYAN}[Agent]{RESET} {text}")

    n = step("text")
    md(f"### Step {n} — Agent Message [{elapsed()}]\n\n")
    md(f"> {text.strip()}\n\n")


def handle_write(file_path: str, content: str):
    """Agent writes a new source file."""
    fname = Path(file_path).name
    saved_path, ver = save_source(fname, content)

    tprint(f"\n{BOLD}{MAGENTA}[CODE v{ver}]{RESET} {BOLD}{fname}{RESET}  "
           f"{DIM}({len(content.splitlines())} lines) → {saved_path}{RESET}")

    n = step("write")
    md(f"### Step {n} — Write Source Code [{elapsed()}]\n\n")
    md(f"**File**: `{file_path}` (v{ver}, {len(content.splitlines())} lines)  \n")
    md(f"**Saved to**: `{saved_path}`\n\n")


def handle_edit(file_path: str, old_str: str, new_str: str):
    """Agent edits a source file."""
    fname = Path(file_path).name

    global _iteration
    _iteration += 1

    # Save diff to file
    diff_file = CODE_DIR / f"edit_{_iteration}.diff"
    diff_text = f"--- a/{fname}\n+++ b/{fname}\n"
    for line in old_str.strip().splitlines():
        diff_text += f"-{line}\n"
    for line in new_str.strip().splitlines():
        diff_text += f"+{line}\n"
    diff_file.write_text(diff_text)

    tprint(f"\n{BOLD}{YELLOW}[EDIT #{_iteration}]{RESET} {BOLD}{fname}{RESET}  "
           f"{DIM}→ {diff_file}{RESET}")

    n = step("edit")
    md(f"### Step {n} — Edit Source Code [{elapsed()}]\n\n")
    md(f"**File**: `{file_path}` (edit #{_iteration})  \n")
    md(f"**Diff saved to**: `{diff_file}`\n\n")


def handle_compile(tool_name: str, tool_input: dict):
    """Agent compiles code (Bash gcc or vm_compile_and_run)."""
    if "vm_compile_and_run" in tool_name:
        src = tool_input.get("source_code", "")
        fname = tool_input.get("filename", "exploit.c")
        flags = tool_input.get("compile_flags", "")
        upload_only = tool_input.get("upload_only", False)

        saved_path, ver = save_source(fname, src)
        tprint(f"\n{BOLD}{MAGENTA}[COMPILE v{ver}]{RESET} {BOLD}{fname}{RESET}  "
               f"flags='{flags}'  upload_only={upload_only}  "
               f"{DIM}({len(src.splitlines())} lines) → {saved_path}{RESET}")

        n = step("compile")
        md(f"### Step {n} — Compile on VM [{elapsed()}]\n\n")
        md(f"**File**: `{fname}` (v{ver}), **Flags**: `{flags}`  \n")
        md(f"**Saved to**: `{saved_path}`\n\n")
    else:
        # Bash gcc command
        cmd = tool_input.get("command", "")
        tprint(f"\n{BOLD}{YELLOW}[COMPILE]{RESET} {cmd}")

        n = step("compile")
        md(f"### Step {n} — Compile [{elapsed()}]\n\n")
        md(f"```bash\n{cmd}\n```\n\n")


def handle_upload(tool_input: dict):
    """Agent uploads a file to VM."""
    local = tool_input.get("local_path", "?")
    remote = tool_input.get("remote_path", "?")
    tprint(f"\n{YELLOW}[UPLOAD]{RESET} {local} → {BOLD}{remote}{RESET}")

    n = step("upload")
    md(f"### Step {n} — Upload to VM [{elapsed()}]\n\n")
    md(f"- Local: `{local}`\n- Remote: `{remote}`\n\n")


def handle_run_exploit(tool_input: dict):
    """Agent runs the exploit."""
    binary = tool_input.get("remote_binary", "?")
    success_marker = tool_input.get("success_marker", "got r00t")
    retries = tool_input.get("max_retries", 1)
    tprint(f"\n{BOLD}{RED}[RUN EXPLOIT]{RESET} {binary}")
    tprint(f"  success_marker='{success_marker}'  max_retries={retries}")

    n = step("run_exploit")
    md(f"### Step {n} — Run Exploit [{elapsed()}]\n\n")
    md(f"- **Binary**: `{binary}`\n")
    md(f"- **Success marker**: `{success_marker}`\n")
    md(f"- **Max retries**: {retries}\n\n")


def handle_execute(tool_input: dict):
    """Agent executes a command on VM."""
    cmd = tool_input.get("command", "?")
    tprint(f"\n{YELLOW}[VM]{RESET} $ {cmd}")

    n = step("vm_execute")
    md(f"### Step {n} — VM Command [{elapsed()}]\n\n")
    md(f"```bash\n{cmd}\n```\n\n")


def _md_truncate(s: str, max_len: int = 500) -> str:
    """Truncate for Markdown log (no ANSI codes)."""
    s = s.strip()
    if len(s) > max_len:
        return s[:max_len] + f"\n... ({len(s)} chars total)"
    return s


def handle_tool_result(content: str, tool_id: str = ""):
    """Display tool result with context-aware formatting."""
    content = content.strip()

    # Detect compile results (only for actual compile output, not SSH errors)
    if "compilation succeeded" in content.lower():
        tprint(f"  {BG_GREEN}{BOLD} COMPILE OK {RESET}")
        tprint(f"{GREEN}{truncate(content, 1000)}{RESET}")
        md(f"**Result**: Compilation succeeded\n\n")
        return

    if "compilation failed" in content.lower():
        tprint(f"  {BG_RED}{BOLD} COMPILE FAILED {RESET}")
        tprint(f"{RED}{truncate(content, 2000)}{RESET}")
        md(f"**Result**: Compilation FAILED\n\n")
        md(f"```\n{_md_truncate(content, 2000)}\n```\n\n")
        return

    # Detect gcc errors (but not SSH errors that happen to contain "error:")
    if "error:" in content and ("gcc" in content.lower() or ".c:" in content):
        tprint(f"  {BG_RED}{BOLD} COMPILE ERROR {RESET}")
        tprint(f"{RED}{truncate(content, 2000)}{RESET}")
        md(f"**Result**: Compile error\n\n")
        md(f"```\n{_md_truncate(content, 2000)}\n```\n\n")
        return

    # Detect flag verification
    if "FLAG_VERIFIED" in content:
        tprint(f"\n  {BG_GREEN}{BOLD} ★ FLAG VERIFIED ★ {RESET}")
        tprint(f"{GREEN}{content}{RESET}")
        md(f"**Result**: **FLAG_VERIFIED** — Root privilege escalation confirmed\n\n")
        md(f"```\n{_md_truncate(content, 500)}\n```\n\n")
        return

    if "FLAG_INCORRECT" in content:
        tprint(f"  {RED}[FLAG INCORRECT]{RESET} {content.strip()}")
        md(f"**Result**: FLAG_INCORRECT\n\n")
        return

    # Detect exploit results
    if "SUCCESS" in content:
        tprint(f"\n  {BG_GREEN}{BOLD} ★ EXPLOIT SUCCESS ★ {RESET}")
        tprint(f"{GREEN}{content}{RESET}")
        md(f"**Result**: **SUCCESS**\n\n")
        md(f"```\n{_md_truncate(content, 1000)}\n```\n\n")
        return

    if "CRASHED" in content or "kernel panic" in content.lower():
        tprint(f"  {BG_RED}{BOLD} VM CRASHED {RESET}")
        tprint(f"{RED}{truncate(content, 1500)}{RESET}")
        md(f"**Result**: VM CRASHED\n\n")
        md(f"```\n{_md_truncate(content, 500)}\n```\n\n")
        return

    if "FAILURE" in content or "TIMEOUT" in content:
        tprint(f"  {RED}[FAILED]{RESET} {truncate(content, 1500)}")
        md(f"**Result**: FAILED\n\n")
        md(f"```\n{_md_truncate(content, 1000)}\n```\n\n")
        return

    # Detect SSH/VM connectivity errors
    if "VM likely crashed" in content or "SSHException" in content or "Unable to connect" in content:
        tprint(f"  {RED}[VM UNREACHABLE]{RESET} {truncate(content, 500)}")
        md(f"**Result**: VM unreachable — {_md_truncate(content, 200)}\n\n")
        return

    # Detect VM status
    if "VM is up" in content or "Kernel:" in content:
        tprint(f"  {GREEN}[VM]{RESET} {content.strip()}")
        md(f"**Result**: {_md_truncate(content, 300)}\n\n")
        return

    if "Uploaded" in content:
        tprint(f"  {GREEN}[OK]{RESET} {content.strip()}")
        md(f"**Result**: {_md_truncate(content, 200)}\n\n")
        return

    # Generic result — short summary only, no full dump
    tprint(f"  {DIM}[Result]{RESET} {truncate(content)}")
    lines = content.split("\n")
    md(f"**Result**: ({len(lines)} lines, {len(content)} chars)\n\n")


def handle_tool_use(block: dict):
    """Route tool_use blocks to specific handlers."""
    name = block.get("name", "")
    inp = block.get("input", {})

    # Source code operations
    if name == "Write":
        path = inp.get("file_path", "")
        content = inp.get("content", "")
        if path.endswith((".c", ".h", ".py", ".sh")):
            handle_write(path, content)
            return

    if name == "Edit":
        path = inp.get("file_path", "")
        if path.endswith((".c", ".h", ".py", ".sh")):
            handle_edit(path, inp.get("old_string", ""), inp.get("new_string", ""))
            return

    # Compile operations
    if "vm_compile_and_run" in name:
        handle_compile(name, inp)
        return

    if name == "Bash":
        cmd = inp.get("command", "")
        if "gcc" in cmd or "make" in cmd:
            handle_compile(name, inp)
            return

    # VM operations
    if "vm_upload_file" in name:
        handle_upload(inp)
        return

    if "vm_run_exploit" in name:
        handle_run_exploit(inp)
        return

    if "vm_execute" in name:
        handle_execute(inp)
        return

    if "vm_check_status" in name:
        tprint(f"\n{YELLOW}[VM]{RESET} Checking VM status...")
        md(f"### Step {step('check')} — Check VM Status [{elapsed()}]\n\n")
        return

    if "vm_start" in name:
        tprint(f"\n{YELLOW}[VM]{RESET} Starting VM...")
        md(f"### Step {step('start')} — Start VM [{elapsed()}]\n\n")
        return

    if "vm_restart" in name:
        tprint(f"\n{YELLOW}[VM]{RESET} Restarting VM...")
        md(f"### Step {step('restart')} — Restart VM [{elapsed()}]\n\n")
        return

    if "vm_get_log" in name:
        tprint(f"\n{YELLOW}[VM]{RESET} Fetching VM console log...")
        md(f"### Step {step('log')} — VM Console Log [{elapsed()}]\n\n")
        return

    # File reads (for kernel source analysis)
    if name == "Read":
        path = inp.get("file_path", "")
        tprint(f"\n{DIM}[Read]{RESET} {path}")
        n = step("read")
        md(f"### Step {n} — Read File [{elapsed()}]\n\n")
        md(f"**File**: `{path}`\n\n")
        return

    if name in ("Grep", "Glob"):
        pattern = inp.get("pattern", "")
        tprint(f"\n{DIM}[{name}]{RESET} {pattern}")
        return

    # Generic tool call
    args_str = ""
    for k, v in inp.items():
        v_str = str(v)
        if len(v_str) > 150:
            v_str = v_str[:150] + "..."
        args_str += f"\n    {k}: {v_str}"
    tprint(f"\n{YELLOW}[Tool]{RESET} {BOLD}{name}{RESET}{args_str}")


# ── Main loop ────────────────────────────────────────────────────────────

tprint(f"\n{BOLD}{WHITE}{'=' * 60}{RESET}")
tprint(f"{BOLD}{WHITE}  Exploit Development Session: {args.cve}{RESET}")
tprint(f"{BOLD}{WHITE}  {_start_time.strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
tprint(f"{BOLD}{WHITE}  Log: {MD_LOG}{RESET}")
tprint(f"{BOLD}{WHITE}  Code: {CODE_DIR}/{RESET}")
tprint(f"{BOLD}{WHITE}{'=' * 60}{RESET}\n")

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

        # Track token usage
        usage = msg.get("usage", {})
        if usage:
            _total_input_tokens += usage.get("input_tokens", 0)
            _total_output_tokens += usage.get("output_tokens", 0)

        # Deduplication: Claude Code emits each block as a separate event
        # with the same msg_id but replacing (not accumulating) content.
        # Track by block ID (for tool_use) or msg_id+type (for others).
        is_new_msg = (msg_id != _last_msg_id)
        _last_msg_id = msg_id

        for block in blocks:
            btype = block.get("type", "")
            block_id = block.get("id", "")  # tool_use blocks have unique IDs

            # Deduplicate: skip blocks we've already processed
            if btype == "tool_use" and block_id:
                if block_id in _seen_block_ids:
                    continue
                _seen_block_ids.add(block_id)
            elif btype == "thinking":
                dedup_key = f"{msg_id}:thinking"
                if dedup_key in _seen_block_ids:
                    continue
                _seen_block_ids.add(dedup_key)
            elif btype == "text":
                dedup_key = f"{msg_id}:text"
                if dedup_key in _seen_block_ids:
                    continue
                _seen_block_ids.add(dedup_key)
            else:
                continue

            if btype == "thinking":
                handle_thinking(block.get("thinking", ""))
            elif btype == "text":
                handle_text(block.get("text", ""))
            elif btype == "tool_use":
                handle_tool_use(block)

    elif etype == "user":
        # Tool results
        msg = event.get("message", {})
        for block in msg.get("content", []):
            if block.get("type") == "tool_result":
                content = block.get("content", "")
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
                # Skip tool_reference blocks (system metadata)
                if isinstance(content, str) and content.strip():
                    handle_tool_result(content, block.get("tool_use_id", ""))

    elif etype == "error":
        error = event.get("error", event)
        tprint(f"\n{BG_RED}{BOLD} ERROR {RESET} {RED}{error}{RESET}")
        md(f"### ERROR [{elapsed()}]\n\n```\n{error}\n```\n\n")

    elif etype == "system":
        subtype = event.get("subtype", "")
        if subtype == "init":
            model = event.get("model", "?")
            tools = event.get("tools", [])
            tprint(f"{DIM}[System] Model: {model}, Tools: {len(tools)}{RESET}")
            md(f"**Model**: {model}, **Tools**: {len(tools)}\n\n---\n\n")

    sys.stdout.flush()


# ── Session summary ──────────────────────────────────────────────────────
end_time = datetime.now()
duration = end_time - _start_time
m, s = divmod(int(duration.total_seconds()), 60)

tprint(f"\n{BOLD}{WHITE}{'=' * 60}{RESET}")
tprint(f"{BOLD}{WHITE}  Session Complete{RESET}")
tprint(f"  Duration: {m}m {s}s")
tprint(f"  Steps: {_step_num}")
tprint(f"  Code iterations: {_iteration}")
tprint(f"  Tokens: {_total_input_tokens:,} in / {_total_output_tokens:,} out")
tprint(f"  Log: {MD_LOG}")
tprint(f"  Code: {CODE_DIR}/")
tprint(f"{BOLD}{WHITE}{'=' * 60}{RESET}")

md(f"\n---\n\n## Session Summary\n\n")
md(f"- **Duration**: {m}m {s}s\n")
md(f"- **Steps**: {_step_num}\n")
md(f"- **Code iterations**: {_iteration}\n")
md(f"- **Tokens**: {_total_input_tokens:,} in / {_total_output_tokens:,} out\n")
md(f"- **Ended**: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
