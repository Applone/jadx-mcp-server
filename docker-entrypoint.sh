#!/usr/bin/env bash
#
# Entrypoint for the containerised JADX MCP server.
#
# All configuration comes from the environment (see .env.example); nothing is
# hardcoded in docker-compose.yml. Any extra CLI flags passed to `docker run` /
# `docker compose run` are appended verbatim to the server invocation.
#
set -euo pipefail

MCP_HOST="${MCP_HOST:-127.0.0.1}"
MCP_PORT="${MCP_PORT:-8651}"
JADX_HOST="${JADX_HOST:-host.docker.internal}"
JADX_PORT="${JADX_PORT:-8650}"
MCP_INTERNAL_PORT="${MCP_INTERNAL_PORT:-18651}"
JADX_MCP_ALLOW_INSECURE_BIND="${JADX_MCP_ALLOW_INSECURE_BIND:-false}"

# Address the relay listens on inside the container's network namespace.
# 0.0.0.0 is correct for bridge networking (the namespace is private, and the
# host-side exposure is decided by MCP_PUBLISH_ADDR). Under host networking the
# namespace IS the host, so this must be 127.0.0.1 unless OAuth is configured.
RELAY_BIND="${RELAY_BIND:-0.0.0.0}"

log() { printf '[entrypoint] %s\n' "$*" >&2; }

is_loopback() {
  case "$1" in
    127.0.0.1 | localhost | ::1) return 0 ;;
    *) return 1 ;;
  esac
}

# The server refuses to bind a non-loopback address unless JADX_MCP_OAUTH_MODE
# is set — an unauthenticated MCP endpoint on a routable interface would be a
# remote code-analysis surface for anyone who can reach it. A container's
# published port is exactly that kind of interface, so the guard is upheld here
# rather than worked around silently.
if ! is_loopback "$MCP_HOST" && [[ -z "${JADX_MCP_OAUTH_MODE:-}" ]]; then
  log "ERROR: MCP_HOST=${MCP_HOST} is not a loopback address but JADX_MCP_OAUTH_MODE is unset."
  log "       Either set JADX_MCP_OAUTH_MODE=remote|proxy (see OAUTH.md), or keep"
  log "       MCP_HOST=127.0.0.1 and set JADX_MCP_ALLOW_INSECURE_BIND=true to expose"
  log "       the loopback listener through the container's published port."
  exit 78 # EX_CONFIG
fi

RELAY_PID=""
cleanup() {
  [[ -n "$RELAY_PID" ]] && kill "$RELAY_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

BIND_HOST="$MCP_HOST"
BIND_PORT="$MCP_PORT"

if is_loopback "$MCP_HOST" && [[ "${JADX_MCP_ALLOW_INSECURE_BIND,,}" == "true" ]]; then
  # Development convenience: the server keeps its loopback-only bind, and socat
  # forwards the container's published port to it. This does NOT add
  # authentication — publish the port to the host's loopback only
  # (127.0.0.1:8651:8651) and never to a shared network.
  BIND_PORT="$MCP_INTERNAL_PORT"
  log "WARNING: JADX_MCP_ALLOW_INSECURE_BIND=true — exposing an UNAUTHENTICATED MCP"
  log "         endpoint on ${RELAY_BIND}:${MCP_PORT}. Use only on a trusted host."
  socat "TCP-LISTEN:${MCP_PORT},fork,reuseaddr,bind=${RELAY_BIND}" \
        "TCP:127.0.0.1:${BIND_PORT}" &
  RELAY_PID=$!
fi

log "MCP listener  : ${BIND_HOST}:${BIND_PORT} (published as ${MCP_PORT})"
log "JADX plugin   : ${JADX_HOST}:${JADX_PORT}"
log "Public OAuth  : ${JADX_MCP_OAUTH_MODE:-disabled}"

exec python /app/jadx_mcp_server.py \
  --http \
  --host "$BIND_HOST" \
  --port "$BIND_PORT" \
  --jadx-host "$JADX_HOST" \
  --jadx-port "$JADX_PORT" \
  "$@"
