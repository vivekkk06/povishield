#!/usr/bin/env bash
# PoViShield Local Terminal Shell Integration Hook
#
# Source this file in your local terminal:
#   source scripts/povishield_shell_hook.sh
#
# Once sourced, running 'pv <command>' or './povishield <command>' or
# entering the interactive shell via 'pv shell' will execute your commands
# under policy-gated confinement and live-stream them to the web console.

POVISHIELD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)"

alias pv="${POVISHIELD_DIR}/povishield"
alias povishield="${POVISHIELD_DIR}/povishield"

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║          PoViShield Shell Integration & Live Web Terminal Hook               ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo "[OK] 'pv' and 'povishield' commands are now active in this shell session."
echo "[OK] Every execution is policy-confined and live-streamed to http://localhost:5175"
echo ""
echo "Try running:"
echo "  pv uname -a              # Executed under seccomp confinement"
echo "  pv ls /tmp               # Sandboxed directory list"
echo "  pv echo 'Hello World'    # Confined output"
echo "  pv shell                 # Real-time interactive sandboxed terminal"
echo "════════════════════════════════════════════════════════════════════════════════"
