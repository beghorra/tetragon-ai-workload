#!/usr/bin/env bash
# scripts/wait-policies-enabled.sh
# Poll until Tetragon TracingPolicies reach "enabled" state.
#
# Usage:
#   bash scripts/wait-policies-enabled.sh [pattern] [timeout]
#     pattern: regex to match policy names (default: ".*")
#     timeout: max seconds to wait (default: 60)
#
# Examples:
#   bash scripts/wait-policies-enabled.sh                   # wait for all
#   bash scripts/wait-policies-enabled.sh "fim-" 30         # only fim policies, 30s
#   bash scripts/wait-policies-enabled.sh "observe$" 45     # only ones ending in -observe

set -uo pipefail
PATTERN="${1:-.*}"
TIMEOUT="${2:-60}"

echo "[wait-policies] Waiting for policies matching '${PATTERN}' to reach enabled (timeout ${TIMEOUT}s)..."

LAST_STATE=""
for i in $(seq 1 "$TIMEOUT"); do
  OUTPUT=$(kubectl exec -n tetragon ds/tetragon -c tetragon -- \
    tetra tracingpolicy list 2>/dev/null || echo "")

  if [[ -z "$OUTPUT" ]]; then
    sleep 1
    continue
  fi

  # Skip header line, filter by pattern, count total vs enabled
  FILTERED=$(echo "$OUTPUT" | tail -n +2 | awk -v p="$PATTERN" '$2 ~ p')
  TOTAL=$(echo "$FILTERED" | grep -c . || echo 0)
  ENABLED=$(echo "$FILTERED" | awk '$3=="enabled"' | grep -c . || echo 0)

  STATE="${ENABLED}/${TOTAL}"
  if [[ "$STATE" != "$LAST_STATE" ]]; then
    echo "[wait-policies] ${STATE} enabled..."
    LAST_STATE="$STATE"
  fi

  if [[ "$TOTAL" -gt 0 && "$ENABLED" == "$TOTAL" ]]; then
    echo "[wait-policies] All ${ENABLED} matching policies are enabled."
    exit 0
  fi

  sleep 1
done

echo "[wait-policies] TIMEOUT: only ${ENABLED:-0}/${TOTAL:-0} enabled after ${TIMEOUT}s"
echo "[wait-policies] Run: kubectl exec -n tetragon ds/tetragon -c tetragon -- tetra tracingpolicy list"
exit 1
