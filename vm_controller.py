#!/usr/bin/env python3
"""VM Controller — lightweight HTTP service for managing QEMU VMs.

Runs on the host. Allows the Docker-based MCP server to start/stop/restart
VMs via HTTP requests.

Usage:
    python3 vm_controller.py [--port 8222] [--vm-dir /home/xia/vm-lab]

Endpoints:
    GET  /status          — Check if QEMU process is running
    POST /start           — Start the VM (runs start_vm script)
    POST /stop            — Stop the VM (kills QEMU process)
    POST /restart         — Stop then start
    GET  /log             — Last 50 lines of VM boot output
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import threading

# Configurable
VM_DIR = Path.home() / "vm-lab"
VM_SCRIPT = "start_vm_CVE-2017-6074.sh"
QEMU_PROCESS_NAME = "qemu-system-x86_64"
SSH_PORT = 2226  # used to identify the specific VM

# Track the VM process we started
_vm_proc: subprocess.Popen | None = None
_vm_lock = threading.Lock()
_vm_log: list[str] = []
MAX_LOG_LINES = 200


def _find_vm_pid() -> int | None:
    """Find the PID of the QEMU process for this VM by SSH port."""
    try:
        result = subprocess.run(
            ["pgrep", "-f", f"{QEMU_PROCESS_NAME}.*hostfwd.*:{SSH_PORT}-"],
            capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout.strip():
            pids = result.stdout.strip().split("\n")
            return int(pids[0])
    except Exception:
        pass
    return None


def _is_vm_running() -> bool:
    """Check if the VM QEMU process is alive."""
    global _vm_proc
    with _vm_lock:
        # Check our tracked process first
        if _vm_proc is not None:
            if _vm_proc.poll() is None:
                return True
            _vm_proc = None
        # Fall back to pgrep
        return _find_vm_pid() is not None


def _stop_vm() -> str:
    """Stop the VM by killing the QEMU process."""
    global _vm_proc
    with _vm_lock:
        # Try our tracked process first
        if _vm_proc is not None and _vm_proc.poll() is None:
            _vm_proc.terminate()
            try:
                _vm_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                _vm_proc.kill()
                _vm_proc.wait(timeout=5)
            _vm_proc = None
            return "VM stopped (tracked process)"

        # Fall back to finding by pgrep
        pid = _find_vm_pid()
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
                # Wait for it to die
                for _ in range(20):
                    time.sleep(0.5)
                    if _find_vm_pid() is None:
                        return f"VM stopped (pid {pid})"
                os.kill(pid, signal.SIGKILL)
                return f"VM killed (pid {pid})"
            except ProcessLookupError:
                return "VM process already exited"
            except PermissionError:
                return f"Permission denied killing pid {pid}"
        return "VM is not running"


def _start_vm() -> str:
    """Start the VM by running the start script."""
    global _vm_proc, _vm_log
    with _vm_lock:
        # Check if already running
        if _vm_proc is not None and _vm_proc.poll() is None:
            return "VM is already running (tracked process)"
        if _find_vm_pid() is not None:
            return "VM is already running (found via pgrep)"

        script_path = VM_DIR / VM_SCRIPT
        if not script_path.exists():
            return f"VM script not found: {script_path}"

        _vm_log = []
        _vm_proc = subprocess.Popen(
            ["bash", str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(VM_DIR),
        )

        # Start a thread to capture output
        def _capture_output():
            global _vm_log
            for line in iter(_vm_proc.stdout.readline, b""):
                decoded = line.decode("utf-8", errors="replace").rstrip()
                _vm_log.append(decoded)
                if len(_vm_log) > MAX_LOG_LINES:
                    _vm_log = _vm_log[-MAX_LOG_LINES:]

        t = threading.Thread(target=_capture_output, daemon=True)
        t.start()

        return f"VM starting (pid {_vm_proc.pid})"


def _wait_for_ssh(timeout: int = 180) -> str:
    """Wait for VM SSH to become accessible."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            result = subprocess.run(
                ["sshpass", "-p", "ubuntu", "ssh",
                 "-o", "StrictHostKeyChecking=no",
                 "-o", "ConnectTimeout=3",
                 "-p", str(SSH_PORT),
                 "ubuntu@127.0.0.1", "uname -r"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                kernel = result.stdout.strip()
                return f"VM is ready. Kernel: {kernel}"
        except (subprocess.TimeoutExpired, Exception):
            pass
        time.sleep(5)
    return f"Timeout after {timeout}s waiting for SSH"


class VMHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, data: dict):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        if self.path == "/status":
            running = _is_vm_running()
            self._send_json(200, {
                "running": running,
                "pid": _find_vm_pid(),
            })
        elif self.path == "/log":
            self._send_json(200, {
                "lines": _vm_log[-50:],
            })
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        if self.path == "/stop":
            msg = _stop_vm()
            self._send_json(200, {"message": msg})

        elif self.path == "/start":
            msg = _start_vm()
            if "starting" in msg.lower():
                # Wait for SSH
                ssh_msg = _wait_for_ssh()
                self._send_json(200, {"message": msg, "ssh": ssh_msg})
            else:
                self._send_json(200, {"message": msg})

        elif self.path == "/restart":
            stop_msg = _stop_vm()
            time.sleep(2)  # Brief pause between stop and start
            start_msg = _start_vm()
            if "starting" in start_msg.lower():
                ssh_msg = _wait_for_ssh()
                self._send_json(200, {
                    "stop": stop_msg,
                    "start": start_msg,
                    "ssh": ssh_msg,
                })
            else:
                self._send_json(200, {
                    "stop": stop_msg,
                    "start": start_msg,
                })
        else:
            self._send_json(404, {"error": "Not found"})

    def log_message(self, format, *args):
        print(f"[vm-controller] {args[0]}")


def main():
    global VM_DIR
    parser = argparse.ArgumentParser(description="VM Controller HTTP Service")
    parser.add_argument("--port", type=int, default=8222)
    parser.add_argument("--vm-dir", type=str, default=str(VM_DIR))
    args = parser.parse_args()

    VM_DIR = Path(args.vm_dir)

    server = HTTPServer(("0.0.0.0", args.port), VMHandler)
    print(f"[vm-controller] Listening on port {args.port}")
    print(f"[vm-controller] VM dir: {VM_DIR}")
    print(f"[vm-controller] VM script: {VM_SCRIPT}")
    print(f"[vm-controller] Endpoints: GET /status, POST /start, POST /stop, POST /restart, GET /log")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[vm-controller] Shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
