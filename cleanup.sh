#!/usr/bin/env bash
# =============================================================================
# scenarios/ai-workload/cleanup.sh
# Sanitise the lab: remove all three enforcement/observation layers AND tear down
# the entire mock AI workload (pod + service + configmap) that setup.sh
# scaffolded, so nothing this demo created is left behind.
# =============================================================================
set -euo pipefail
SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# OSS defaults (this is the only flavor the public repo ships)
NAMESPACE="${NAMESPACE:-ai-workload-oss}"
AGENT_NAMESPACE="${AGENT_NAMESPACE:-ai-agent-oss}"
MCP_URL="${MCP_URL:-http://ai-inference.ai-workload-oss.svc.cluster.local:8080/mcp/tools/call}"
SPLUNK_SOURCETYPE="${SPLUNK_SOURCETYPE:-tetragon}"

# Shared library first: resolves KUBECONFIG so cleanup runs self-contained too.
# shellcheck source=lib-checks.sh
source "${SCENARIO_DIR}/lib-checks.sh"
# shellcheck source=workload.sh
source "${SCENARIO_DIR}/workload.sh"

echo "[ai-workload/cleanup] Removing microsegmentation policy (if applied)..."
kubectl delete -f "${SCENARIO_DIR}/network-policy.yaml" --ignore-not-found

echo "[ai-workload/cleanup] Removing enforcement policy (if applied)..."
kubectl delete -f "${SCENARIO_DIR}/enforce-policy.yaml" --ignore-not-found

echo "[ai-workload/cleanup] Removing observability policy..."
kubectl delete -f "${SCENARIO_DIR}/tracing-policy.yaml" --ignore-not-found

echo "[ai-workload/cleanup] Tearing down the mock AI workload (pod + service + configmap)..."
delete_workload

echo "[ai-workload/cleanup] Deleting namespaces ${NAMESPACE} and ${AGENT_NAMESPACE}..."
kubectl delete namespace "${NAMESPACE}" --ignore-not-found
kubectl delete namespace "${AGENT_NAMESPACE}" --ignore-not-found

echo "[ai-workload/cleanup] Done. Lab sanitised — nothing this demo created remains."
