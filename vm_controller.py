#!/usr/bin/env python3
"""VM Controller — lightweight HTTP service for managing QEMU VMs.

Runs on the host. Allows the Docker-based MCP server to start/stop/restart
VMs via HTTP requests. Reads CVE configuration from cve-registry.json.

Usage:
    python3 vm_controller.py --cve CVE-2017-6074 [--port 8222] [--vm-dir /home/xia/vm-lab]

Endpoints:
    GET  /status          — Check if QEMU process is running
    POST /start           — Start the VM (runs start_vm script)
    POST /stop            — Stop the VM (kills QEMU process)
    POST /restart         — Stop then start
    POST /reset           — Stop VM + delete overlay for fresh boot (kernelCTF only)
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

# Configurable — set from registry via --cve
VM_DIR = Path.home() / "vm-lab"
VM_SCRIPT = ""
BOOT_MODE = "cloud-init"   # "cloud-init" or "kernelctf"
RELEASE = ""                # kernelCTF release name (e.g. "mitigation-6.1-v2")
FLAG_FILE = ""              # optional flag file path for benchmark verification
QEMU_PROCESS_NAME = "qemu-system-x86_64"
SSH_PORT = 0
SSH_USER = "ubuntu"
SSH_PASSWORD = "ubuntu"

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
    """Start the VM by running the appropriate start script."""
    global _vm_proc, _vm_log
    with _vm_lock:
        # Check if already running
        if _vm_proc is not None and _vm_proc.poll() is None:
            return "VM is already running (tracked process)"
        if _find_vm_pid() is not None:
            return "VM is already running (found via pgrep)"

        if BOOT_MODE == "kernelctf":
            # kernelCTF mode: use interactive.sh with --no-exploit (agent generates PoC)
            script_path = VM_DIR / "kernelctf" / "interactive.sh"
            if not script_path.exists():
                return f"interactive.sh not found: {script_path}"
            cmd = ["bash", str(script_path), RELEASE,
                   "--port", str(SSH_PORT), "--no-exploit", "--lock-root",
                   "--reset"]
            if FLAG_FILE:
                cmd += ["--flag", FLAG_FILE]
        else:
            # cloud-init mode: use vm-scripts/
            script_path = VM_DIR / VM_SCRIPT
            if not script_path.exists():
                return f"VM script not found: {script_path}"
            cmd = ["bash", str(script_path)]

        _vm_log = []
        _vm_proc = subprocess.Popen(
            cmd,
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

        return f"VM starting (pid {_vm_proc.pid}, mode={BOOT_MODE})"


def _wait_for_ssh(timeout: int = 180) -> str:
    """Wait for VM SSH to become accessible and stable.

    Performs two SSH checks with a gap to confirm the server is truly ready
    (Dropbear with -R generates host keys on first connection, which can
    cause subsequent connections to fail with EOF during negotiation).
    """
    start = time.time()
    ssh_cmd = [
        "sshpass", "-p", SSH_PASSWORD, "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=3",
        "-p", str(SSH_PORT),
        f"{SSH_USER}@127.0.0.1",
    ]
    kernel = ""
    while time.time() - start < timeout:
        # Check if VM process exited early (kernel panic during boot)
        with _vm_lock:
            if _vm_proc is not None and _vm_proc.poll() is not None:
                recent = "\n".join(_vm_log[-20:]) if _vm_log else "(no output)"
                return f"VM exited (code {_vm_proc.returncode}) before SSH was ready. Console:\n{recent}"
        try:
            result = subprocess.run(
                ssh_cmd + ["uname -r"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                kernel = result.stdout.strip()
                break
        except (subprocess.TimeoutExpired, Exception):
            pass
        time.sleep(5)
    else:
        recent = "\n".join(_vm_log[-20:]) if _vm_log else "(no output)"
        return f"Timeout after {timeout}s waiting for SSH. Console:\n{recent}"

    # Stability check: verify SSH works reliably after initial success.
    # Dropbear may still be settling (key generation, socket setup).
    # Retry up to 3 times to confirm SSH is truly stable.
    for stability_attempt in range(3):
        time.sleep(2)
        try:
            result = subprocess.run(
                ssh_cmd + ["true"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                break
        except (subprocess.TimeoutExpired, Exception):
            pass
    else:
        # All stability checks failed — wait a bit longer
        time.sleep(5)

    return f"VM is ready. Kernel: {kernel}"


def _reset_overlay() -> str:
    """Delete the qcow2 overlay so next boot creates a fresh one. KernelCTF mode only."""
    if BOOT_MODE != "kernelctf":
        return "Reset only supported in kernelCTF mode"
    if _is_vm_running():
        stop_msg = _stop_vm()
    else:
        stop_msg = "VM was not running"
    overlay_dir = VM_DIR / "kernelctf" / "images"
    overlay = overlay_dir / f"{RELEASE}-interactive.qcow2"
    if overlay.exists():
        overlay.unlink()
        return f"{stop_msg}. Overlay deleted: {overlay.name}. Next boot will create a fresh one."
    return f"{stop_msg}. No overlay found at {overlay}"


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

        elif self.path == "/reset":
            msg = _reset_overlay()
            self._send_json(200, {"message": msg})

        elif self.path == "/verify-flag":
            if not FLAG_FILE:
                self._send_json(200, {"verified": False, "message": "No flag configured"})
                return
            # Read POST body for candidate flag
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode() if content_length else ""
            try:
                candidate = json.loads(body).get("flag", "")
            except (json.JSONDecodeError, AttributeError):
                candidate = body.strip()
            # Compare against the flag file on disk
            try:
                expected = Path(FLAG_FILE).read_text().strip()
            except FileNotFoundError:
                self._send_json(200, {"verified": False, "message": "Flag file not found"})
                return
            if candidate.strip() == expected:
                self._send_json(200, {"verified": True, "message": "FLAG_VERIFIED"})
            else:
                self._send_json(200, {"verified": False, "message": "FLAG_INCORRECT"})

        else:
            self._send_json(404, {"error": "Not found"})

    def log_message(self, format, *args):
        print(f"[vm-controller] {args[0]}")


def _load_cve_config(cve_id: str, vm_dir: Path):
    """Load CVE configuration from registry."""
    global VM_SCRIPT, BOOT_MODE, RELEASE, SSH_PORT, SSH_USER, SSH_PASSWORD
    registry_path = vm_dir / "cve-registry.json"
    if not registry_path.exists():
        print(f"[vm-controller] ERROR: Registry not found: {registry_path}")
        sys.exit(1)
    with open(registry_path) as f:
        registry = json.load(f)
    if cve_id not in registry:
        print(f"[vm-controller] ERROR: Unknown CVE: {cve_id}")
        print(f"[vm-controller] Available: {', '.join(sorted(registry.keys()))}")
        sys.exit(1)
    cfg = registry[cve_id]
    BOOT_MODE = cfg.get("boot_mode", "cloud-init")
    SSH_PORT = cfg["ssh_port"]
    SSH_USER = cfg["ssh_user"]
    SSH_PASSWORD = cfg["ssh_password"]
    if BOOT_MODE == "kernelctf":
        RELEASE = cfg["release"]
    else:
        VM_SCRIPT = cfg["script"]


def main():
    global VM_DIR
    parser = argparse.ArgumentParser(description="VM Controller HTTP Service")
    parser.add_argument("--cve", type=str, required=True, help="CVE ID (e.g. CVE-2017-6074)")
    parser.add_argument("--port", type=int, default=8222)
    parser.add_argument("--vm-dir", type=str, default=str(VM_DIR))
    parser.add_argument("--flag-file", type=str, default="",
                        help="Flag file path for benchmark verification")
    args = parser.parse_args()

    VM_DIR = Path(args.vm_dir)
    _load_cve_config(args.cve, VM_DIR)
    global FLAG_FILE
    FLAG_FILE = args.flag_file

    server = HTTPServer(("0.0.0.0", args.port), VMHandler)
    print(f"[vm-controller] CVE: {args.cve}")
    print(f"[vm-controller] Listening on port {args.port}")
    print(f"[vm-controller] VM dir: {VM_DIR}")
    print(f"[vm-controller] Boot mode: {BOOT_MODE}")
    if BOOT_MODE == "kernelctf":
        print(f"[vm-controller] Release: {RELEASE} (SSH port {SSH_PORT}, user {SSH_USER})")
    else:
        print(f"[vm-controller] VM script: {VM_SCRIPT} (SSH port {SSH_PORT}, user {SSH_USER})")
    print(f"[vm-controller] Endpoints: GET /status, POST /start, POST /stop, POST /restart, POST /reset, GET /log")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[vm-controller] Shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
