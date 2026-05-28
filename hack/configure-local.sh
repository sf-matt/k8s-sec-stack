#!/usr/bin/env bash
# Generates .mcp.json and .claude/settings.json from the live cluster state.
# Run once after cloning, and again if your node IP changes.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Detecting node IP from current kubecontext ($(kubectl config current-context))"
NODE_IP="$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"

if [[ -z "$NODE_IP" ]]; then
  echo "ERROR: could not detect node IP from cluster" >&2
  exit 1
fi

echo "    REPO_ROOT : $REPO_ROOT"
echo "    NODE_IP   : $NODE_IP"

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
        "FALCO_SINK_URL": "http://$NODE_IP:32080"
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
echo "==> Done. Restart Claude Code to pick up the new MCP config."
