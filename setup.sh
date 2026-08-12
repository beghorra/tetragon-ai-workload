#!/usr/bin/env bash
# =============================================================================
# scenarios/ai-workload/setup.sh
# Self-contained deploy for the "Guard the Model" AI-workload demo.
#
# Unlike the shared-attacker-pod scenarios, this demo owns its whole workload:
# setup.sh SCAFFOLDS the entire mock AI application from scratch (a python
# inference/agent server + its crown jewels — a fake model-weights file and an
# inference API secret) and cleanup.sh TEARS IT ALL DOWN, so the lab is left
# sanitised after every run.
#
# What this does:
#   * generate the agent server and ship it as a ConfigMap
#   * deploy the mock AI workload (pod + service) and wait until it is serving
#   * clear any stale enforce / microsegmentation policy so the OBSERVE pass
#     starts with nothing loaded to stop the compromise
#   * apply the cluster-wide OBSERVE policy (-> Splunk) and wait for enabled
#   * print the observe-state board from the shared check library
# =============================================================================
set -euo pipefail
SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SCENARIO_DIR}"
# OSS defaults (this is the only flavor the public repo ships)
NAMESPACE="${NAMESPACE:-ai-workload-oss}"
AGENT_NAMESPACE="${AGENT_NAMESPACE:-ai-agent-oss}"
MCP_URL="${MCP_URL:-http://ai-inference.ai-workload-oss.svc.cluster.local:8080/mcp/tools/call}"
SPLUNK_SOURCETYPE="${SPLUNK_SOURCETYPE:-tetragon}"
TARGET_POD="${TARGET_POD:-ai-inference}"
AGENT_POD="${AGENT_POD:-agent-driver}"

# Shared library first: single source of truth for checks AND cluster-access
# bootstrap (resolves KUBECONFIG so this runs self-contained from a laptop).
# shellcheck source=lib-checks.sh
source "${SCENARIO_DIR}/lib-checks.sh"
# shellcheck source=workload.sh
source "${SCENARIO_DIR}/workload.sh"

echo "[ai-workload/setup] Scaffolding + deploying the mock AI workload (MCP server in ${NAMESPACE}, agent driver in ${AGENT_NAMESPACE})..."
deploy_workload

echo "[ai-workload/setup] Clearing stale ENFORCE + microsegmentation so the observe pass starts clean..."
kubectl delete -f "${SCENARIO_DIR}/enforce-policy.yaml" --ignore-not-found
kubectl delete -f "${SCENARIO_DIR}/network-policy.yaml" --ignore-not-found

echo "[ai-workload/setup] Applying OBSERVE policy (cluster-wide -> Splunk)..."
kubectl apply -f "${SCENARIO_DIR}/tracing-policy.yaml"

echo "[ai-workload/setup] Waiting for ai-workload observe policy to reach enabled..."
bash "${REPO_ROOT}/scripts/wait-policies-enabled.sh" "ai-workload-observe" 60

# Shared checks (single source of truth with attack.sh) -- show the observe-state
# board so the presenter can confirm the AI workload is live, the observe policy
# is loaded, and the inference API is serving before running the compromise.
# lib-checks.sh is already sourced at the top of this script.
echo
echo "[ai-workload/setup] Observe-state board:"
show_workload
show_policies
show_context
check_app_neutral "post-setup (observe state)"

echo "[ai-workload/setup] Ready. Run: bash scenarios/ai-workload/attack.sh"
