#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="security"
EVENT_SINK_IMAGE="k8s-sec-event-sink:0.1.0"

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

echo "==> Building the local event-sink image"
docker build --tag "$EVENT_SINK_IMAGE" ./event-sink

CURRENT_CONTEXT="$(kubectl config current-context)"
if [[ "$CURRENT_CONTEXT" == kind-* ]]; then
  KIND_CLUSTER="${CURRENT_CONTEXT#kind-}"
  echo "==> Loading the event-sink image into kind cluster: $KIND_CLUSTER"
  kind load docker-image "$EVENT_SINK_IMAGE" --name "$KIND_CLUSTER"
else
  echo "ERROR: bootstrap supports kind contexts for loading the local event-sink image; current context is $CURRENT_CONTEXT" >&2
  exit 1
fi

echo "==> Installing k8s-sec-stack into namespace: $NAMESPACE"
helm upgrade --install k8s-sec-stack ./charts/k8s-sec-stack \
  --namespace "$NAMESPACE" \
  --create-namespace \
  --set eventSink.image.repository=k8s-sec-event-sink \
  --set eventSink.image.tag=0.1.0 \
  --set eventSink.image.pullPolicy=Never \
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
echo "==> Start a port-forward, then restart your MCP client and run the server with:"
echo "    kubectl -n $NAMESPACE port-forward service/mcp-event-sink 8080:8080"
echo "    cd mcp-server && uv run k8s-sec-mcp"
