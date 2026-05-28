#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="security"

echo "==> Using current kubecontext: $(kubectl config current-context)"
kubectl cluster-info

echo "==> Adding Helm repos"
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo add aqua          https://aquasecurity.github.io/helm-charts
helm repo add kubescape     https://kubescape.github.io/helm-charts
helm repo add kyverno       https://kyverno.github.io/kyverno
helm repo update

echo "==> Updating chart dependencies"
helm dependency update ./charts/k8s-sec-stack

echo "==> Installing k8s-sec-stack into namespace: $NAMESPACE"
helm upgrade --install k8s-sec-stack ./charts/k8s-sec-stack \
  --namespace "$NAMESPACE" \
  --create-namespace \
  --wait \
  --timeout 10m

echo ""
echo "==> Stack deployed. Verifying CRDs are available..."
sleep 5
kubectl get vulnerabilityreports   -A 2>/dev/null | head -5 || echo "    VulnerabilityReports not yet populated (trivy-operator scanning in background)"
kubectl get policyreports          -A 2>/dev/null | head -5 || echo "    PolicyReports not yet populated"
kubectl get clustercompliancereports 2>/dev/null | head -5 || echo "    ClusterComplianceReports not yet populated"

echo ""
echo "==> Done. Deploy demo workloads with:"
echo "    kubectl apply -f demo/"
echo ""
echo "==> Generate local MCP config (run once per machine):"
echo "    ./hack/configure-local.sh"
echo ""
echo "==> Then restart Claude Code and run the MCP server with:"
echo "    cd mcp-server && uv run k8s-sec-mcp"
