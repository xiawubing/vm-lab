#!/usr/bin/env python3
"""MCP SSH Server for CVE exploit development.

Provides tools for Claude Code to interact with a QEMU VM running
a vulnerable kernel/userspace via SSH/SFTP, and to compile exploit code
on the VM.
"""

import os
import socket
import threading
import time
import urllib.request
import urllib.error
import json
from pathlib import Path

import paramiko
from fastmcp import FastMCP

mcp = FastMCP("vm-ssh")

# VM connection config from environment
VM_HOST = os.environ.get("VM_SSH_HOST", "host.docker.internal")
VM_PORT = int(os.environ.get("VM_SSH_PORT", "2226"))
VM_USER = os.environ.get("VM_SSH_USER", "ubuntu")
VM_PASSWORD = os.environ.get("VM_SSH_PASSWORD", "ubuntu")

# VM controller URL (runs on host)
VM_CONTROLLER_URL = os.environ.get("VM_CONTROLLER_URL", "http://host.docker.internal:8222")

# Connection pool
_ssh_lock = threading.Lock()
_ssh_client: paramiko.SSHClient | None = None


def _get_ssh() -> paramiko.SSHClient:
    """Get or create a reusable SSH connection to the VM."""
    global _ssh_client
    with _ssh_lock:
        if _ssh_client is not None:
            # Check if connection is still alive
            try:
                _ssh_client.exec_command("true", timeout=5)
                return _ssh_client
            except Exception:
                try:
                    _ssh_client.close()
                except Exception:
                    pass
                _ssh_client = None

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=VM_HOST,
            port=VM_PORT,
            username=VM_USER,
            password=VM_PASSWORD,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        _ssh_client = client
        return _ssh_client


def _ssh_error_message(e: Exception) -> str:
    """Return a clear error message when the VM is unreachable."""
    cve_id = os.environ.get("CVE_ID", "unknown")
    return (
        f"VM likely crashed or unreachable. Use vm_restart() to bring it back, "
        f"or restart from the host for {cve_id}.\n"
        f"SSH error: {type(e).__name__}: {e}"
    )


_SSH_ERRORS = (
    paramiko.ssh_exception.NoValidConnectionsError,
    paramiko.ssh_exception.SSHException,
    paramiko.ssh_exception.AuthenticationException,
    socket.timeout,
    socket.error,
    ConnectionRefusedError,
    ConnectionResetError,
    OSError,
    EOFError,
    TimeoutError,
)


def _reset_ssh():
    """Reset the pooled SSH connection."""
    global _ssh_client
    with _ssh_lock:
        _ssh_client = None


@mcp.tool()
def vm_check_status() -> str:
    """Check VM SSH connectivity and return kernel version."""
    try:
        client = _get_ssh()
        _, stdout, _ = client.exec_command("uname -r", timeout=10)
        kernel = stdout.read().decode().strip()
        return f"VM is up. Kernel: {kernel}"
    except _SSH_ERRORS as e:
        return _ssh_error_message(e)


@mcp.tool()
def vm_execute(command: str, timeout: int = 30) -> str:
    """Run a command in the VM via SSH.

    Args:
        command: Shell command to execute in the VM.
        timeout: Command timeout in seconds (default 30).

    Returns:
        Combined stdout and stderr output, or crash message.
    """
    try:
        client = _get_ssh()
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode()
        err = stderr.read().decode()
        exit_code = stdout.channel.recv_exit_status()
        result = ""
        if out:
            result += out
        if err:
            result += f"\n[stderr]\n{err}"
        result += f"\n[exit code: {exit_code}]"
        return result.strip()
    except _SSH_ERRORS as e:
        # Reset pooled connection on failure
        global _ssh_client
        with _ssh_lock:
            _ssh_client = None
        return _ssh_error_message(e)


@mcp.tool()
def vm_upload_file(local_path: str, remote_path: str) -> str:
    """Upload a file from the Docker container to the VM via SFTP.

    Args:
        local_path: Path to the file inside the Docker container.
        remote_path: Destination path on the VM.

    Returns:
        Success message or error details.
    """
    try:
        client = _get_ssh()
        sftp = client.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()
        return f"Uploaded {local_path} -> {remote_path}"
    except _SSH_ERRORS as e:
        return _ssh_error_message(e)
    except FileNotFoundError:
        return f"Local file not found: {local_path}"


@mcp.tool()
def vm_download_file(remote_path: str, local_path: str) -> str:
    """Download a file from the VM to the Docker container via SFTP.

    Args:
        remote_path: Path to the file on the VM.
        local_path: Destination path inside the Docker container.

    Returns:
        Success message or error details.
    """
    try:
        client = _get_ssh()
        sftp = client.open_sftp()
        sftp.get(remote_path, local_path)
        sftp.close()
        return f"Downloaded {remote_path} -> {local_path}"
    except _SSH_ERRORS as e:
        return _ssh_error_message(e)
    except FileNotFoundError:
        return f"Remote file not found: {remote_path}"


@mcp.tool()
def vm_compile_and_run(
    source_code: str,
    filename: str = "exploit.c",
    compile_flags: str = "",
    run_timeout: int = 30,
    upload_only: bool = False,
) -> str:
    """Compile C source on the VM and optionally run.

    Uploads the source code to the VM via SFTP, compiles with the VM's
    native gcc (ensuring ABI compatibility with the VM's kernel), and
    optionally executes the resulting binary.

    Set upload_only=True to compile without running. Use this for
    exploits that never exit — follow up with vm_run_exploit() to
    execute with success/failure detection.

    Args:
        source_code: C source code to compile.
        filename: Source filename (default: exploit.c).
        compile_flags: Extra gcc flags (e.g. "-lpthread -DDEBUG").
        run_timeout: Execution timeout in seconds (default 30).
        upload_only: If True, skip execution after compile (default False).

    Returns:
        Compilation output + program output, or error details.
    """
    binary_name = Path(filename).stem
    remote_src = f"/home/{VM_USER}/{filename}"
    remote_bin = f"/home/{VM_USER}/{binary_name}"

    # Upload source to VM
    src_path = f"/tmp/{filename}"
    try:
        with open(src_path, "w") as f:
            f.write(source_code)
    except OSError as e:
        return f"Failed to write source file: {e}"

    try:
        client = _get_ssh()
        sftp = client.open_sftp()
        sftp.put(src_path, remote_src)
        sftp.close()
    except _SSH_ERRORS as e:
        return _ssh_error_message(e)
    except Exception as e:
        return f"[upload failed: {e}]"

    output = f"[uploaded {filename} to {remote_src}]\n"

    # Compile on VM with native gcc
    gcc_cmd = f"gcc {compile_flags} -o {remote_bin} {remote_src}"
    try:
        _, stdout, stderr = client.exec_command(gcc_cmd, timeout=60)
        gcc_out = stdout.read().decode()
        gcc_err = stderr.read().decode()
        gcc_exit = stdout.channel.recv_exit_status()
    except _SSH_ERRORS as e:
        return output + _ssh_error_message(e)

    if gcc_out:
        output += f"[compile stdout]\n{gcc_out}\n"
    if gcc_err:
        output += f"[compile stderr]\n{gcc_err}\n"
    if gcc_exit != 0:
        output += f"[compilation failed with exit code {gcc_exit}]"
        return output.strip()

    output += "[compilation succeeded]\n"

    # Flush to disk so binary survives kernel crashes
    try:
        client.exec_command("sync", timeout=10)
    except _SSH_ERRORS:
        pass

    if upload_only:
        return output.strip()

    # Execute on VM
    try:
        _, stdout, stderr = client.exec_command(remote_bin, timeout=run_timeout)
        out = stdout.read().decode()
        err = stderr.read().decode()
        exit_code = stdout.channel.recv_exit_status()
        if out:
            output += f"[program stdout]\n{out}\n"
        if err:
            output += f"[program stderr]\n{err}\n"
        output += f"[exit code: {exit_code}]"
    except _SSH_ERRORS as e:
        # VM likely crashed from the exploit
        global _ssh_client
        with _ssh_lock:
            _ssh_client = None
        output += "\n" + _ssh_error_message(e)

    return output.strip()


def _controller_request(method: str, path: str) -> dict:
    """Make a request to the host VM controller service."""
    url = f"{VM_CONTROLLER_URL}{path}"
    req = urllib.request.Request(url, method=method)
    if method == "POST":
        req.add_header("Content-Length", "0")
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        return {"error": f"VM controller unreachable at {url}: {e}. Is vm_controller.py running on the host?"}
    except Exception as e:
        return {"error": f"VM controller request failed: {e}"}


@mcp.tool()
def vm_start() -> str:
    """Start the QEMU VM via the host controller. Waits for SSH to become accessible.

    Returns:
        Status message indicating if VM started and SSH is ready.
    """
    global _ssh_client
    with _ssh_lock:
        _ssh_client = None
    result = _controller_request("POST", "/start")
    if "error" in result:
        return result["error"]
    parts = [result.get("message", "")]
    if "ssh" in result:
        parts.append(result["ssh"])
    return " | ".join(parts)


@mcp.tool()
def vm_stop() -> str:
    """Stop the QEMU VM via the host controller (kills QEMU process).

    Returns:
        Status message.
    """
    global _ssh_client
    with _ssh_lock:
        _ssh_client = None
    result = _controller_request("POST", "/stop")
    if "error" in result:
        return result["error"]
    return result.get("message", str(result))


@mcp.tool()
def vm_restart() -> str:
    """Restart the QEMU VM: stop, then start, then wait for SSH.

    Use this after the VM crashes from an exploit. Takes 1-3 minutes.

    Returns:
        Status of stop, start, and SSH readiness.
    """
    global _ssh_client
    with _ssh_lock:
        _ssh_client = None
    result = _controller_request("POST", "/restart")
    if "error" in result:
        return result["error"]
    parts = []
    if "stop" in result:
        parts.append(f"Stop: {result['stop']}")
    if "start" in result:
        parts.append(f"Start: {result['start']}")
    if "ssh" in result:
        parts.append(f"SSH: {result['ssh']}")
    return " | ".join(parts)


@mcp.tool()
def vm_run_exploit(
    remote_binary: str,
    success_marker: str = "got r00t",
    failure_marker: str = "something went wrong",
    poll_timeout: int = 45,
    poll_interval: int = 2,
    max_retries: int = 1,
) -> str:
    """Run a binary on the VM and poll for success/failure, with automatic retries.

    Launches the binary in background with output redirected to a file.
    Polls the file for success_marker or failure_marker strings.

    If max_retries > 1 and the attempt results in CRASHED or FAILURE,
    automatically restarts the VM and retries. Use max_retries=5 for
    semi-reliable kernel exploits (~50% success rate per attempt).

    Args:
        remote_binary: Path to binary on VM (e.g. /home/ubuntu/poc).
        success_marker: String indicating success (default: "got r00t").
        failure_marker: String indicating failure (default: "something went wrong").
        poll_timeout: Max seconds to wait per attempt (default: 45).
        poll_interval: Seconds between output checks (default: 2).
        max_retries: Total attempts before giving up (default: 1).

    Returns:
        SUCCESS with output, or FAILED with full attempt history.
    """
    all_output = ""

    for attempt in range(1, max_retries + 1):
        if max_retries > 1:
            all_output += f"\n=== Attempt {attempt}/{max_retries} ===\n"

        # Verify binary exists on VM
        try:
            client = _get_ssh()
            _, stdout, _ = client.exec_command(
                f"test -x {remote_binary} && echo EXISTS || echo MISSING",
                timeout=10,
            )
            check = stdout.read().decode().strip()
            if "MISSING" in check:
                all_output += f"[Binary {remote_binary} not found — recompile needed]\n"
                return all_output.strip()
        except _SSH_ERRORS as e:
            _reset_ssh()
            all_output += f"[VM unreachable: {e}]\n"
            if attempt < max_retries:
                all_output += _do_restart()
                continue
            return all_output.strip()

        # Launch exploit in background
        output_file = f"/tmp/exploit_output_{int(time.time())}.txt"
        try:
            _, stdout, _ = client.exec_command(
                f"nohup stdbuf -oL {remote_binary} > {output_file} 2>&1 & echo $!",
                timeout=10,
            )
            pid_line = stdout.read().decode().strip()
            pid = pid_line.split()[-1] if pid_line else "unknown"
        except _SSH_ERRORS as e:
            _reset_ssh()
            all_output += f"[Failed to launch: {e}]\n"
            if attempt < max_retries:
                all_output += _do_restart()
                continue
            return all_output.strip()

        all_output += f"[Started PID {pid}]\n"

        # Poll for result
        outcome = _poll_exploit(output_file, pid, success_marker,
                                failure_marker, poll_timeout, poll_interval)

        all_output += outcome["log"]

        if outcome["status"] == "SUCCESS":
            return all_output.strip()

        # Non-success: restart and retry if attempts remain
        if attempt < max_retries:
            _reset_ssh()
            all_output += _do_restart()
            continue

    return all_output.strip()


def _poll_exploit(output_file, pid, success_marker, failure_marker,
                  poll_timeout, poll_interval):
    """Poll exploit output file. Returns dict with status and log."""
    log = ""
    elapsed = 0

    while elapsed < poll_timeout:
        time.sleep(poll_interval)
        elapsed += poll_interval

        try:
            client = _get_ssh()
            _, stdout, _ = client.exec_command(
                f"cat {output_file} 2>/dev/null", timeout=10,
            )
            content = stdout.read().decode()

            if success_marker in content:
                log += f"[SUCCESS after ~{elapsed}s]\n{content}"
                return {"status": "SUCCESS", "log": log}

            if failure_marker in content:
                log += f"[FAILURE after ~{elapsed}s]\n{content}"
                return {"status": "FAILURE", "log": log}

            # Check if process exited
            _, stdout2, _ = client.exec_command(
                f"kill -0 {pid} 2>/dev/null; echo $?", timeout=5,
            )
            alive = stdout2.read().decode().strip()
            if alive != "0" and content:
                log += f"[PROCESS EXITED after ~{elapsed}s]\n{content}"
                return {"status": "EXITED", "log": log}

        except _SSH_ERRORS:
            _reset_ssh()
            log += f"[CRASHED after ~{elapsed}s — kernel panicked]\n"
            return {"status": "CRASHED", "log": log}

    # Timeout
    try:
        client = _get_ssh()
        _, stdout, _ = client.exec_command(
            f"cat {output_file} 2>/dev/null", timeout=10,
        )
        content = stdout.read().decode()
        log += f"[TIMEOUT after {poll_timeout}s]\n{content}"
    except _SSH_ERRORS:
        _reset_ssh()
        log += f"[TIMEOUT after {poll_timeout}s — VM unreachable]\n"

    return {"status": "TIMEOUT", "log": log}


def _do_restart():
    """Restart VM via controller. Returns log string."""
    log = "[Restarting VM...]\n"
    _reset_ssh()
    result = _controller_request("POST", "/restart")
    if "error" in result:
        log += f"[Restart error: {result['error']}]\n"
    else:
        parts = []
        if "ssh" in result:
            parts.append(result["ssh"])
        if "message" in result:
            parts.append(result["message"])
        log += f"[VM ready: {' | '.join(parts)}]\n"
    return log


if __name__ == "__main__":
    mcp.run()
