#!/usr/bin/env bash
# PoViShield Remote Linux Agent Installer & Provisioner
set -euo pipefail

SERVER=""
CODE=""
NAME=""
START_AGENT="false"

usage() {
    echo "PoViShield Agent Installer"
    echo "Usage: $0 --server <URL> --code <PAIRING_CODE> [--name <DEVICE_NAME>] [--start]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)
            SERVER="$2"
            shift 2
            ;;
        --code)
            CODE="$2"
            shift 2
            ;;
        --name)
            NAME="$2"
            shift 2
            ;;
        --start)
            START_AGENT="true"
            shift 1
            ;;
        *)
            usage
            ;;
    esac
done

if [ -z "$SERVER" ] || [ -z "$CODE" ]; then
    usage
fi

echo "=========================================================================="
echo "         PoViShield Linux Security Endpoint Agent Setup                   "
echo "=========================================================================="

# Check Linux OS
if [ "$(uname -s)" != "Linux" ]; then
    echo "[ERROR] PoViShield endpoint security agent currently requires Linux." >&2
    exit 1
fi

echo "[CHECK] Operating System: Linux ($(uname -r) $(uname -m))"

# Check Python 3
if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] python3 is required to run the PoViShield agent." >&2
    exit 1
fi

PYTHON_VER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
echo "[CHECK] Python Environment: $PYTHON_VER"

# If in local repo
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd || echo "")"
if [ -n "$REPO_DIR" ] && [ -f "$REPO_DIR/agent/povishield_agent.py" ]; then
    echo "[SETUP] Using local PoViShield installation at: $REPO_DIR"
    python3 "$REPO_DIR/agent/povishield_agent.py" pair --server "$SERVER" --code "$CODE" ${NAME:+--name "$NAME"}
    if [ "$START_AGENT" = "true" ]; then
        echo "[START] Starting PoViShield agent in background..."
        nohup python3 "$REPO_DIR/agent/povishield_agent.py" start > /tmp/povishield_agent.log 2>&1 &
        echo "[SUCCESS] Agent running in background (PID: $!). Telemetry streaming to dashboard."
    fi
else
    # Remote target host setup into ~/.povishield
    INSTALL_DIR="$HOME/.povishield"
    mkdir -p "$INSTALL_DIR"
    echo "[SETUP] Downloading PoViShield agent components to $INSTALL_DIR..."
    curl -sSL "${SERVER}/api/agent/script" -o "$INSTALL_DIR/povishield_agent.py"
    python3 "$INSTALL_DIR/povishield_agent.py" pair --server "$SERVER" --code "$CODE" ${NAME:+--name "$NAME"}
    if [ "$START_AGENT" = "true" ]; then
        echo "[START] Starting PoViShield agent in background..."
        nohup python3 "$INSTALL_DIR/povishield_agent.py" start > "$INSTALL_DIR/agent.log" 2>&1 &
        echo "[SUCCESS] Agent running in background (PID: $!). Telemetry streaming to dashboard."
    fi
fi

echo "=========================================================================="
echo "[SUCCESS] PoViShield Agent successfully installed and paired!"
echo "To manage or start the background monitoring loop manually:"
echo "  povishield agent start"
echo "=========================================================================="
