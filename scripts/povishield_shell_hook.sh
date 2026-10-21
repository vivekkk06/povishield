#!/usr/bin/env bash
# PoViShield Local Terminal Shell Integration & Command Interception Hook
#
# When sourced in a Linux terminal or ~/.bashrc, this hook:
# 1. Puts 'pv' and 'povishield' commands on your PATH.
# 2. Uses non-intrusive preexec & PROMPT_COMMAND hooks to capture terminal
#    command executions (e.g. /usr/bin/echo 'Hello from PoViShield', uname, ls)
#    and stream them in real time to the PoViShield Security Console.
# 3. Enables interactive seccomp-bpf sandboxed shell via 'pv shell'.

POVISHIELD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)"
POVISHIELD_API="${POVISHIELD_API:-http://127.0.0.1:8000}"

# 1. Ensure povishield binaries are on PATH
if [[ ":$PATH:" != *":${POVISHIELD_DIR}:"* ]]; then
    export PATH="${POVISHIELD_DIR}:${PATH}"
fi

alias pv="${POVISHIELD_DIR}/povishield"
alias povishield="${POVISHIELD_DIR}/povishield"

# 2. Command telemetry reporter
__povishield_record_cmd() {
    local raw_cmd="$1"
    local exit_code="${2:-0}"
    local duration_ms="${3:-0}"

    if [[ -z "$raw_cmd" ]]; then
        return 0
    fi

    # Filter internal shell builtins, navigation, and prompt hooks
    case "$raw_cmd" in
        *"__povi"*|*"PROMPT_COMMAND"*|"cd "*|"cd"|"pwd"|"clear"|"history"*|"exit"|"logout"|"true"|"false"|"source "*|"source"|". "*)
            return 0
            ;;
        *"povishield "*|*"pv "*)
            # Handled directly by povishield CLI wrapper
            return 0
            ;;
    esac

    # Dispatch to local background reporter script
    if [ -f "${POVISHIELD_DIR}/scripts/record_terminal_cmd.py" ]; then
        python3 "${POVISHIELD_DIR}/scripts/record_terminal_cmd.py" \
            --cmd "$raw_cmd" \
            --exit-code "$exit_code" \
            --duration "$duration_ms" \
            --pid "$$" \
            --ppid "$PPID" \
            --server "$POVISHIELD_API" >/dev/null 2>&1 &
        disown $! 2>/dev/null || true
    fi
}

# 3. Bash DEBUG trap and prompt hook
__povishield_debug_trap() {
    local cmd="$BASH_COMMAND"
    if [[ -z "$cmd" || "$cmd" == *"__povi"* || "$cmd" == *"PROMPT_COMMAND"* ]]; then
        return 0
    fi
    __POVISHIELD_ACTIVE_CMD="$cmd"
    __POVISHIELD_START_TIME=$(date +%s%3N 2>/dev/null || python3 -c "import time; print(int(time.time()*1000))" 2>/dev/null || echo "0")
}

__povishield_prompt_hook() {
    local last_exit=$?
    if [[ -n "${__POVISHIELD_ACTIVE_CMD:-}" ]]; then
        local end_time=$(date +%s%3N 2>/dev/null || python3 -c "import time; print(int(time.time()*1000))" 2>/dev/null || echo "0")
        local dur=0
        if [[ "$end_time" -gt "$__POVISHIELD_START_TIME" && "$__POVISHIELD_START_TIME" -gt 0 ]]; then
            dur=$(( end_time - __POVISHIELD_START_TIME ))
        fi
        local to_record="$__POVISHIELD_ACTIVE_CMD"
        unset __POVISHIELD_ACTIVE_CMD
        unset __POVISHIELD_START_TIME
        __povishield_record_cmd "$to_record" "$last_exit" "$dur"
    fi
}

# Attach hook to interactive Bash sessions
if [ -n "${BASH_VERSION:-}" ]; then
    set +o functrace 2>/dev/null || true
    trap '__povishield_debug_trap' DEBUG
    if [[ "${PROMPT_COMMAND:-}" != *"__povishield_prompt_hook"* ]]; then
        if [ -n "${PROMPT_COMMAND:-}" ]; then
            PROMPT_COMMAND="__povishield_prompt_hook; ${PROMPT_COMMAND}"
        else
            PROMPT_COMMAND="__povishield_prompt_hook"
        fi
    fi
fi
