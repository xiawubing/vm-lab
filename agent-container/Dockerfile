FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# System packages: build tools, static libs, SSH client, debugging tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    gcc-multilib \
    libc6-dev \
    linux-libc-dev \
    python3 \
    python3-pip \
    python3-venv \
    openssh-client \
    sshpass \
    curl \
    wget \
    git \
    gdb \
    strace \
    file \
    xz-utils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Node.js 20.x LTS
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Claude Code
RUN npm install -g @anthropic-ai/claude-code

# Download and extract kernel source (mainline 4.4.62)
RUN mkdir -p /src && \
    wget -q https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.4.62.tar.xz -O /tmp/linux-4.4.62.tar.xz && \
    tar -xf /tmp/linux-4.4.62.tar.xz -C /src/ && \
    rm /tmp/linux-4.4.62.tar.xz

# Python venv with MCP dependencies
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt /tmp/requirements.txt
RUN /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

# Create non-root user (Claude Code refuses --dangerously-skip-permissions as root)
RUN useradd -m -s /bin/bash -u 1000 agent && \
    mkdir -p /workspace /app && \
    chown -R agent:agent /workspace /opt/venv

# Application files
COPY --chown=agent:agent mcp_ssh_server.py /app/mcp_ssh_server.py
COPY --chown=agent:agent cve-info/ /app/cve-info/
COPY --chown=agent:agent .mcp.json /workspace/.mcp.json
COPY --chown=agent:agent CLAUDE.md /workspace/CLAUDE.md
COPY --chown=agent:agent stream_filter.py /app/stream_filter.py
COPY --chown=agent:agent entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# SSH config for non-root user
RUN mkdir -p /home/agent/.ssh && \
    echo "Host *\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null" > /home/agent/.ssh/config && \
    chown -R agent:agent /home/agent/.ssh

# Make kernel source readable by agent
RUN chown -R agent:agent /src

# Pre-configure Claude Code: skip onboarding wizard
RUN mkdir -p /home/agent/.claude && \
    echo '{"hasCompletedOnboarding": true}' > /home/agent/.claude.json && \
    chown -R agent:agent /home/agent/.claude /home/agent/.claude.json

USER agent
WORKDIR /workspace

ENTRYPOINT ["/app/entrypoint.sh"]
