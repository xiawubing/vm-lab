FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# System packages: build tools, static libs, SSH client, debugging tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    gcc-multilib \
    libc6-dev \
    linux-libc-dev \
    libkeyutils-dev \
    libmnl-dev \
    libnftnl-dev \
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

# Download and extract kernel source (conditional on build arg)
ARG KERNEL_SOURCE_URL=""
ARG KERNEL_SOURCE_DIR=""
RUN if [ -n "$KERNEL_SOURCE_URL" ]; then \
        mkdir -p /src && \
        wget -q "$KERNEL_SOURCE_URL" -O /tmp/kernel-source.tar.xz && \
        tar -xf /tmp/kernel-source.tar.xz -C /src/ && \
        rm /tmp/kernel-source.tar.xz && \
        echo "Kernel source installed: /src/$KERNEL_SOURCE_DIR"; \
    else \
        mkdir -p /src && \
        echo "No kernel source requested"; \
    fi

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
COPY --chown=agent:agent .claude/skills/ /workspace/.claude/skills/
COPY --chown=agent:agent .claude/hooks/ /workspace/.claude/hooks/
COPY --chown=agent:agent .claude/settings.json /workspace/.claude/settings.json
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
