#\!/usr/bin/env bash
# =============================================================================
# scenarios/ai-workload/agent-chat.sh -- thin launcher for the agent-chat front-end
#
# The chat logic lives in lib-agent-chat.sh and is sourced by attack.sh, so it is
# also reachable from the interactive menu (options g / G / s). This launcher is
# the standalone entrypoint for driving the guided prompt-injection story on its
# own, without the menu.
#
#   bash scenarios/ai-workload/agent-chat.sh [observe|enforce|both]
#     observe (default) -- the agent is tricked and every tool call lands.
#     enforce           -- arm the four controls, replay the SAME conversation;
#                          each malicious tool call dies at its layer.
#     both              -- observe, pause, enforce, then the close, then cleanup.
#
# Pacing knobs:  TYPING=1, TYPE_DELAY=0.012, INTERACTIVE=1 (enter-to-advance).
# =============================================================================
set -uo pipefail
CHAT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# attack.sh guards its own dispatch, so sourcing it is side-effect free and pulls
# in env, libs, exec_mcp, the six link functions, and lib-agent-chat.sh.
# shellcheck source=attack.sh
source "${CHAT_DIR}/attack.sh"

require_pods || exit 1
ui_banner "Guard the Model -- the agent chat" \
  "You watch the manipulation. The kernel watches the workload."
case "${1:-observe}" in
  observe|o) chat_observe ;;
  enforce|e) chat_enforce ;;
  both|all)  chat_observe; pause; chat_enforce; the_close; run_cleanup ;;
  *) echo "usage: ${BASH_SOURCE[0]##*/} [observe|enforce|both]"; exit 2 ;;
esac
