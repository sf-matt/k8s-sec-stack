#!/usr/bin/env bash
# Generates local MCP client settings for an authenticated port-forward.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="${NAMESPACE:-security}"

echo "==> Reading the event-sink query credential from namespace: $NAMESPACE"
QUERY_TOKEN="$(kubectl -n "$NAMESPACE" get secret mcp-event-sink-auth -o jsonpath='{.data.EVENT_SINK_QUERY_TOKEN}' | base64 --decode)"
if [[ -z "$QUERY_TOKEN" ]]; then
  echo "ERROR: event-sink query credential is empty" >&2
  exit 1
fi

echo "    REPO_ROOT : $REPO_ROOT"
echo "    SINK_URL  : http://127.0.0.1:8080"

generate() {
  local dest="$1"
  cat > "$dest" <<EOF
{
  "mcpServers": {
    "k8s-sec-mcp": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--project", "mcp-server", "k8s-sec-mcp"],
      "cwd": "$REPO_ROOT",
      "env": {
        "FALCO_SINK_URL": "http://127.0.0.1:8080",
        "FALCO_SINK_TOKEN": "$QUERY_TOKEN"
      }
    }
  }
}
EOF
  echo "    wrote $dest"
}

generate "$REPO_ROOT/.mcp.json"
generate "$REPO_ROOT/.claude/settings.json"

echo ""
echo "==> Start the authenticated local access path in a separate terminal:"
echo "    kubectl -n $NAMESPACE port-forward service/mcp-event-sink 8080:8080"
echo "==> Then restart your MCP client. The generated files contain a sensitive query token."
