#!/bin/bash
set -e

CVE_ID="${CVE_ID:?CVE_ID environment variable is required}"

echo "=== ${CVE_ID} Exploit Development Agent ==="
echo "VM target: ${VM_SSH_HOST}:${VM_SSH_PORT} (user: ${VM_SSH_USER})"

# Quick SSH check with hard 8s timeout (agent can use vm_start() if VM is down)
echo "Checking VM SSH connectivity..."
if timeout 8 sshpass -p "${VM_SSH_PASSWORD}" \
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    -p "${VM_SSH_PORT}" \
    "${VM_SSH_USER}@${VM_SSH_HOST:-host.docker.internal}" \
    "uname -r" 2>/dev/null; then
    echo "VM is accessible!"
else
    echo "VM not reachable — agent will use vm_start() to bring it up"
fi

# Verify API key is available
if [ -z "${ANTHROPIC_API_KEY}" ]; then
    echo "ERROR: ANTHROPIC_API_KEY is not set."
    echo "Run: ANTHROPIC_API_KEY=sk-ant-... ./run.sh ${CVE_ID}"
    exit 1
else
    echo "ANTHROPIC_API_KEY is set (${#ANTHROPIC_API_KEY} chars)"
fi

# Check if CVE info file exists (CVE_DIR may differ from CVE_ID for kernelctf entries)
CVE_INFO_NAME="${CVE_DIR:-$CVE_ID}"
CVE_INFO="/app/cve-info/${CVE_INFO_NAME}.md"
if [ -f "$CVE_INFO" ]; then
    echo "CVE info: $CVE_INFO"
else
    echo "WARNING: No CVE info file found at $CVE_INFO"
    echo "The agent will have limited CVE-specific guidance."
fi

# Launch mode
if [ "${AGENT}" = "shell" ]; then
    echo "Starting interactive shell..."
    exec /bin/bash
else
    echo "Starting Claude Code agent..."
    cd /workspace
    mkdir -p /workspace/logs/code

    # Stream filter produces both terminal output and Markdown log
    claude -p --model claude-sonnet-4-6 --dangerously-skip-permissions \
        --max-budget-usd 2.50 \
        --verbose --output-format stream-json \
        "You are testing ${CVE_ID}. Read CLAUDE.md for your tools and workflow, then read /app/cve-info/${CVE_INFO_NAME}.md for the vulnerability details and PoC source code. Follow the steps: verify VM, check environment, compile the PoC, run the exploit, and report results." \
        2>/dev/null | python3 /app/stream_filter.py --cve "${CVE_ID}" --log-dir /workspace/logs

    echo ""
    echo "=== Session logs ==="
    echo "  Markdown log:  $(ls -t /workspace/logs/session_*.md 2>/dev/null | head -1)"
    echo "  Code versions: /workspace/logs/code/"
    ls -la /workspace/logs/code/ 2>/dev/null | grep -v "^total" | grep -v "^d" || echo "  (no code generated)"
fi
