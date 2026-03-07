#!/bin/bash
set -e

echo "=== CVE-2017-6074 Exploit Development Agent ==="
echo "VM target: ${VM_SSH_HOST}:${VM_SSH_PORT}"

# Quick SSH check with hard 8s timeout (agent can use vm_start() if VM is down)
echo "Checking VM SSH connectivity..."
if timeout 8 sshpass -p "${VM_SSH_PASSWORD:-ubuntu}" \
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    -p "${VM_SSH_PORT:-2226}" \
    "${VM_SSH_USER:-ubuntu}@${VM_SSH_HOST:-host.docker.internal}" \
    "uname -r" 2>/dev/null; then
    echo "VM is accessible!"
else
    echo "VM not reachable — agent will use vm_start() to bring it up"
fi

# Verify API key is available
if [ -z "${ANTHROPIC_API_KEY}" ]; then
    echo "ERROR: ANTHROPIC_API_KEY is not set."
    echo "Run: ANTHROPIC_API_KEY=sk-ant-... docker compose up"
    exit 1
else
    echo "ANTHROPIC_API_KEY is set (${#ANTHROPIC_API_KEY} chars)"
fi

# Launch mode
if [ "${AGENT}" = "shell" ]; then
    echo "Starting interactive shell..."
    exec /bin/bash
else
    echo "Starting Claude Code agent..."
    cd /workspace
    claude -p --model claude-sonnet-4-6 --dangerously-skip-permissions \
        --max-budget-usd 5.00 \
        --verbose --output-format stream-json \
        "Read CLAUDE.md for your mission and step-by-step instructions. It contains the full PoC source code. Follow the steps exactly: verify VM, check environment, run the trigger, then run the full PoC exploit. Report results at each step." \
        2>/dev/null | python3 /app/stream_filter.py
fi
