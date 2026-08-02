# syntax=docker/dockerfile:1.7

###############################################################################
# Stage 1 — build the virtualenv with uv (locked, reproducible)
###############################################################################
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependencies are resolved from the lockfile only, so this layer stays cached
# until pyproject.toml / uv.lock actually change.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

###############################################################################
# Stage 2 — slim runtime
###############################################################################
FROM python:3.13-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="jadx-mcp-server" \
      org.opencontainers.image.description="MCP server bridging JADX-GUI's AI MCP plugin to MCP clients" \
      org.opencontainers.image.source="https://github.com/Applone/jadx-mcp-server" \
      org.opencontainers.image.licenses="AGPL-3.0"

# socat backs the opt-in insecure bind relay (see docker-entrypoint.sh).
RUN apt-get update \
    && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 jadx \
    && useradd --system --uid 10001 --gid jadx --create-home --home-dir /home/jadx jadx

# In OAuth proxy mode FastMCP persists dynamically registered clients under its
# home directory. The root filesystem is read-only, so point that at a
# dedicated path the compose files back with a volume. Without this the server
# dies at startup with "Read-only file system: /home/jadx/.local".
RUN mkdir -p /data && chown jadx:jadx /data
VOLUME ["/data"]

WORKDIR /app

COPY --from=builder --chown=jadx:jadx /app/.venv /app/.venv
COPY --chown=jadx:jadx jadx_mcp_server.py ./
COPY --chown=jadx:jadx src ./src
COPY --chown=jadx:jadx docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV PATH="/app/.venv/bin:${PATH}" \
    FASTMCP_HOME=/data \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MCP_PORT=8651 \
    MCP_HOST=127.0.0.1 \
    JADX_HOST=host.docker.internal \
    JADX_PORT=8650

USER jadx

EXPOSE 8651

# The MCP endpoint answers only to authenticated / negotiated requests, so the
# healthcheck asserts the listener is accepting connections rather than probing
# a route.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import os,socket;socket.create_connection(('127.0.0.1',int(os.environ['MCP_PORT'])),3).close()"

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
