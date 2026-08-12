#!/usr/bin/env bash
# =============================================================================
# scenarios/ai-workload/lib-checks.sh
#
# Shared verification helpers for the "Guard the Model" AI agent + MCP demo. This is
# the SINGLE SOURCE OF TRUTH for every kubectl / tetra / HTTP check the demo
# shows, so the setup ("observe") flow and the attack ("compromise") flow can
# never drift apart. Both setup.sh and attack.sh source this file.
#
# Usage:
#   * Sourced    : `source scenarios/ai-workload/lib-checks.sh` then call the
#                  functions below.
#   * Standalone : `bash scenarios/ai-workload/lib-checks.sh`        -> status board
#                  `bash scenarios/ai-workload/lib-checks.sh watch`  -> live events
#
# The workload we protect IS the MCP tool server pod. Its continuity is proven
# from a NEUTRAL pod (not the compromised one): after the enforce pass the egress
# microsegmentation policy locks the MCP pod's own egress to DNS, so any probe
# from inside it would be severed by the network layer. Ingress to the service is
# untouched, so a neighbour reaching http://ai-inference:8080/health proves the
# MCP server kept serving while the attacker inside it was contained.
# =============================================================================

NAMESPACE="${NAMESPACE:-ai-workload}"
AGENT_NAMESPACE="${AGENT_NAMESPACE:-ai-agent}"
TETRAGON_NS="${TETRAGON_NS:-tetragon}"
TARGET_POD="${TARGET_POD:-ai-inference}"
AGENT_POD="${AGENT_POD:-agent-driver}"
# Reached from agent-driver over the REAL pod network -- crosses the namespace boundary.
APP_SVC_URL="${APP_SVC_URL:-http://ai-inference.ai-workload.svc.cluster.local:8080/health}"
# The crown jewels the compromise goes after.
MODEL_PATH="${MODEL_PATH:-/models/model.safetensors}"
SECRET_PATH="${SECRET_PATH:-/etc/ai/api-key}"

# =============================================================================
# Cluster access bootstrap -- make the scenario self-contained.
#
# If a kind cluster runs on a remote VM, a laptop reaches it through
# ~/.kube/<cluster>.kubeconfig (set CLUSTER_NAME to match your cluster's name).
# If KUBECONFIG is not already exported, adopt that kubeconfig automatically so
# setup.sh / attack.sh / cleanup.sh work without a manual
# `export KUBECONFIG=...`. An explicit KUBECONFIG always wins; on the VM/host
# itself (where KUBECONFIG points at ~/.kube/config and no per-cluster file
# exists) this is a no-op.
# =============================================================================
ensure_kubeconfig() {
  [[ -n "${KUBECONFIG:-}" ]] && return 0
  local cluster candidate
  cluster="${CLUSTER_NAME:-kind}"
  candidate="${HOME}/.kube/${cluster}.kubeconfig"
  if [[ -f "${candidate}" ]]; then
    export KUBECONFIG="${candidate}"
    printf '[ai-workload] using lab kubeconfig: %s\n' "${candidate}" >&2
  fi
}
ensure_kubeconfig

# =============================================================================
# Presentation helpers (colour + spacing).
#
# Shared palette so this scenario matches the kill-chain and CVE demos exactly on
# camera. Colours auto-disable when stdout is not a TTY or NO_COLOR is set (so
# piped logs stay clean); force with DEMO_COLOR=1, disable with DEMO_COLOR=0.
# =============================================================================
if [[ -n "${NO_COLOR:-}" || "${DEMO_COLOR:-auto}" == "0" ]]; then
  _ui_color=0
elif [[ "${DEMO_COLOR:-auto}" == "1" || -t 1 ]]; then
  _ui_color=1
else
  _ui_color=0
fi

if [[ "${_ui_color}" == "1" ]]; then
  C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
  C_RED=$'\e[38;5;203m';  C_GREEN=$'\e[38;5;42m';  C_YELLOW=$'\e[38;5;220m'
  C_BLUE=$'\e[38;5;39m';  C_CYAN=$'\e[38;5;44m';   C_MAGENTA=$'\e[38;5;170m'
  C_GREY=$'\e[38;5;245m'
else
  C_RESET=''; C_BOLD=''; C_DIM=''; C_RED=''; C_GREEN=''; C_YELLOW=''
  C_BLUE=''; C_CYAN=''; C_MAGENTA=''; C_GREY=''
fi

# Horizontal rules, built once (no hand-counting of box-drawing glyphs).
UI_LINE="$(printf '═%.0s' $(seq 1 64))"
UI_RULE="$(printf '─%.0s' $(seq 1 64))"

ui_rule()  { printf '%s%s%s\n' "${C_GREY}" "${UI_RULE}" "${C_RESET}"; }
_hr()      { ui_rule; }

# A framed banner. $1 = title, $2 = subtitle (optional). Keep BOTH ASCII-only —
# the padding uses %-62s and multibyte glyphs would throw the right border off.
ui_banner() {
  local title="$1" sub="${2:-}" b="${C_BOLD}${C_BLUE}"
  printf '\n%s╔%s╗%s\n' "$b" "${UI_LINE}" "$C_RESET"
  printf '%s║%s %s%-62s%s %s║%s\n' \
    "$b" "$C_RESET" "${C_BOLD}${C_CYAN}" "$title" "$C_RESET" "$b" "$C_RESET"
  [[ -n "$sub" ]] && printf '%s║%s %s%-62s%s %s║%s\n' \
    "$b" "$C_RESET" "$C_DIM" "$sub" "$C_RESET" "$b" "$C_RESET"
  printf '%s╚%s╝%s\n\n' "$b" "${UI_LINE}" "$C_RESET"
}

ui_check() { printf '\n%s%s▸ %s%s\n' "${C_BOLD}" "${C_CYAN}" "$*" "${C_RESET}"; }
ui_ok()    { printf '  %s✔%s %s\n' "${C_GREEN}"  "${C_RESET}" "$*"; }
ui_bad()   { printf '  %s✘%s %s\n' "${C_RED}"    "${C_RESET}" "$*"; }
ui_warn()  { printf '  %s⚠%s %s\n' "${C_YELLOW}" "${C_RESET}" "$*"; }
ui_step()  { printf '  %s→%s %s\n' "${C_BLUE}"   "${C_RESET}" "$*"; }
ui_note()  { printf '  %s%s%s\n'   "${C_DIM}"    "$*" "${C_RESET}"; }

# Echo the tetragon agent pod co-located with the AI pod's node, so `tetra`
# reads the per-agent counters for the node that actually enforced.
tetragon_pod() {
  local node
  node="$(kubectl -n "${NAMESPACE}" get pod "${TARGET_POD}" \
    -o jsonpath='{.spec.nodeName}' 2>/dev/null)"
  [[ -z "${node}" ]] && return 1
  kubectl -n "${TETRAGON_NS}" get pod \
    -l app.kubernetes.io/name=tetragon \
    --field-selector "spec.nodeName=${node}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# Show the MCP tool server (and its restart count -- the continuity signal) plus
# neighbouring pods. After the enforce pass the MCP pod must still be Running with
# 0 restarts: only the malicious PROCESSES were killed (exit 137), the MCP
# server itself never died.
show_workload() {
  ui_check "AI workload state — namespace ${NAMESPACE}"
  local out
  out="$(kubectl -n "${NAMESPACE}" get pod "${TARGET_POD}" \
    -o custom-columns=POD:.metadata.name,STATUS:.status.phase,RESTARTS:.status.containerStatuses[0].restartCount,NODE:.spec.nodeName,IMAGE:.spec.containers[0].image \
    2>/dev/null)"
  if [[ -n "${out}" ]]; then printf '%s\n' "${out}" | sed "s/^/  ${C_DIM}/;s/\$/${C_RESET}/"
  else ui_bad "pod ${TARGET_POD} not found — run setup.sh first"; fi
  echo
  ui_note "Agent driver — namespace ${AGENT_NAMESPACE} (the real network caller):"
  kubectl -n "${AGENT_NAMESPACE}" get pod "${AGENT_POD}" \
    -o custom-columns=POD:.metadata.name,STATUS:.status.phase,NODE:.spec.nodeName \
    --no-headers 2>/dev/null | sed "s/^/    ${C_DIM}/;s/\$/${C_RESET}/" \
    || ui_note "    (agent-driver not found — run setup.sh first)"
  ui_rule
}

# Prove the inference service is serving from the AI pod itself (observe/before).
# Uses python urllib — the model's own runtime, which no enforce control kills.
# $1 = a label for the moment we are probing at.
check_app() {
  local when="${1:-now}"
  ui_check "Inference API reachability (${when}) — GET http://localhost:8080/health"
  kubectl exec -i -n "${NAMESPACE}" "${TARGET_POD}" -- \
    env G="${C_GREEN}" R="${C_RED}" Z="${C_RESET}" D="${C_DIM}" \
    python3 - <<'PY' 2>/dev/null || ui_bad "probe failed (inference API not reachable)"
import os, urllib.request
g = os.environ.get("G", ""); r = os.environ.get("R", "")
z = os.environ.get("Z", ""); d = os.environ.get("D", "")
try:
    with urllib.request.urlopen("http://localhost:8080/health", timeout=5) as resp:
        body = resp.read(160).decode(errors="replace").replace("\n", " ").strip()
        print(f"  {g}\u2714{z} HTTP {resp.status} OK  \u2190  the model is serving")
        print(f"  {d}body: {body[:120]}{z}")
except Exception as e:
    print(f"  {r}\u2718{z} HTTP request FAILED: {e}")
    raise SystemExit(1)
PY
  ui_rule
}

# Prove continuity from the agent's own driver pod, over the REAL pod network
# and the REAL Service DNS name -- crossing the ai-agent -> ai-workload boundary
# the ingress-allow CiliumNetworkPolicy governs. This is the ONE caller that
# policy still permits; anything else attempting the same call is denied.
# $1 = a label for the moment we are probing at.
check_app_neutral() {
  local when="${1:-now}"
  ui_check "Model-service continuity (${when}) — from agent-driver, over the real network"
  ui_step "vantage: ${AGENT_POD}.${AGENT_NAMESPACE}  ->  GET ${APP_SVC_URL}"
  local body
  body="$(kubectl -n "${AGENT_NAMESPACE}" exec "${AGENT_POD}" -- \
    python3 -c "import urllib.request; print(urllib.request.urlopen('${APP_SVC_URL}', timeout=5).read().decode())" \
    2>/dev/null | tr -d '\n' | head -c 160)"
  if [[ -n "${body}" ]]; then
    ui_ok "the model service is serving"
    printf '  %sbody: %s%s\n' "${C_DIM}" "${body}" "${C_RESET}"
  else
    ui_bad "probe failed (service not reachable)"
  fi
  ui_note "→ the model kept serving and the ONE legitimate caller (agent-driver) stayed"
  ui_note "  allowed while the AI pod's own egress was locked to DNS."
  ui_rule
}

# Show the live Tetragon policy counters for this scenario. NPOST = observed
# events (observe pass), NENFORCE = SIGKILLs issued (enforce pass).
show_policies() {
  local tp
  tp="$(tetragon_pod)"
  if [[ -z "${tp}" ]]; then
    ui_check "Tetragon policy counters"
    ui_bad "could not locate a tetragon agent pod for ${TARGET_POD}'s node."
    ui_rule
    return 1
  fi
  ui_check "Tetragon policy counters on ${tp}  (NPOST=observed, NENFORCE=SIGKILL)"
  kubectl -n "${TETRAGON_NS}" exec "${tp}" -c tetragon -- \
    tetra tracingpolicy list -o json 2>/dev/null \
    | python3 -c '
import sys, json
try:
    rows = [p for p in json.load(sys.stdin).get("policies", []) if "ai-workload" in p.get("name", "")]
except Exception:
    sys.exit(0)
if not rows:
    sys.exit(0)
tty = sys.stdout.isatty()
b = "\033[1m" if tty else ""
g = "\033[38;5;42m" if tty else ""
z = "\033[0m" if tty else ""
print("  {}{:<22}{:<13}{:>6}{:>10}{}".format(b, "POLICY", "MODE", "NPOST", "NENFORCE", z))
for p in rows:
    mode = p.get("mode", "").replace("TP_MODE_", "").lower()
    ac = p.get("stats", {}).get("action_counters", {})
    print("  {:<22}{:<13}{}{:>6}{:>10}{}".format(p.get("name", ""), mode, g, ac.get("post", "0"), ac.get("signal", "0"), z))
' \
    || ui_note "(no ai-workload policies loaded yet)"
  echo
  ui_check "Microsegmentation layer, CiliumNetworkPolicy (egress-deny + ingress-allow)"
  local found=0
  for cnp in ai-workload-egress-deny ai-workload-ingress-allow; do
    if kubectl -n "${NAMESPACE}" get ciliumnetworkpolicy "${cnp}" \
        --no-headers 2>/dev/null | grep -q .; then
      kubectl -n "${NAMESPACE}" get ciliumnetworkpolicy "${cnp}" \
        --no-headers 2>/dev/null | sed "s/^/  ${C_DIM}/;s/\$/${C_RESET}/"
      found=1
    fi
  done
  [[ "${found}" == "0" ]] && ui_note "(no ai-workload CiliumNetworkPolicy applied — the model is unsegmented)"
  ui_rule
}

# Prove WHY this compromise is possible here (not just that it happened): the AI
# pod runs as root, mounts a Kubernetes service-account token, and — most of all
# — holds the crown jewels an AI workload is uniquely valuable for: the model
# weights and the inference API secret.
show_context() {
  ui_check "Why the AI workload is a target — inside ${TARGET_POD}"
  ui_step "identity / privilege inside the pod:"
  kubectl exec -n "${NAMESPACE}" "${TARGET_POD}" -- id 2>/dev/null \
    | sed "s/^/      ${C_DIM}/;s/\$/${C_RESET}/" || ui_note "    (could not read id)"
  ui_step "the crown jewels the compromise goes after:"
  kubectl exec -n "${NAMESPACE}" "${TARGET_POD}" -- \
    sh -c "ls -lh ${MODEL_PATH} ${SECRET_PATH} 2>/dev/null" 2>/dev/null \
    | sed "s/^/      ${C_DIM}/;s/\$/${C_RESET}/" || ui_note "    (could not stat crown jewels)"
  ui_step "Kubernetes service-account token is mounted (a credential to move deeper):"
  kubectl exec -n "${NAMESPACE}" "${TARGET_POD}" -- \
    sh -c 'test -f /var/run/secrets/kubernetes.io/serviceaccount/token && echo present || echo absent' 2>/dev/null \
    | sed 's/^/      token: /' || ui_note "    token: unknown"
  ui_rule
}

# Stream the live Tetragon events for THIS scenario straight from the agent.
# Recommended "side terminal" for a recording: zero indexing lag. Filtered to the
# two scenario policies so only the compromise's events appear.
watch_events() {
  local tp
  tp="$(tetragon_pod)"
  if [[ -z "${tp}" ]]; then
    ui_bad "Could not locate a tetragon agent pod for ${TARGET_POD}'s node." >&2
    return 1
  fi
  printf '%s%s▸ Streaming ai-workload events from %s (Ctrl-C to stop)%s\n' \
    "${C_BOLD}" "${C_CYAN}" "${tp}" "${C_RESET}" >&2
  printf '  %scmd: kubectl -n %s exec %s -c tetragon -- \\%s\n' \
    "${C_DIM}" "${TETRAGON_NS}" "${tp}" "${C_RESET}" >&2
  printf '  %s       tetra getevents -o compact --timestamps \\%s\n' "${C_DIM}" "${C_RESET}" >&2
  printf '  %s         --policy-names ai-workload-observe,ai-workload-enforce%s\n' "${C_DIM}" "${C_RESET}" >&2
  ui_rule
  kubectl -n "${TETRAGON_NS}" exec "${tp}" -c tetragon -- \
    tetra getevents -o compact --timestamps \
      --policy-names ai-workload-observe,ai-workload-enforce
}

# Full point-in-time status board (used when run standalone).
status_board() {
  ui_banner "Guard the Model -- AI workload protection" "status board  ($(date -u +%FT%TZ))"
  show_workload
  show_policies
  show_context
  check_app_neutral "current"
}

# When executed directly (not sourced): `bash lib-checks.sh watch` streams the
# live scenario events (recording side terminal); anything else prints the
# point-in-time status board.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  case "${1:-status}" in
    watch|events|stream) watch_events ;;
    *)                   status_board ;;
  esac
fi
