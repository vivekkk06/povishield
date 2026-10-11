#!/usr/bin/env bash
# Read-only audit of the repository. Output goes to results/audit.txt (and the screen).
cd "$(dirname "$0")/.." || exit 1
mkdir -p results
{
echo "===== GIT ====="; git status --short 2>/dev/null; git log -5 --oneline 2>/dev/null
echo; echo "===== SOURCE TREE ====="
find src include api frontend/src tests evaluation docs scripts -maxdepth 3 -type f \
    ! -path '*/node_modules/*' ! -path '*/.venv/*' ! -path '*/__pycache__/*' ! -name '*.bak*' ! -name '*.precheck' 2>/dev/null | sort
echo; echo "===== TODO / FIXME ====="
grep -RInE 'TODO|FIXME|XXX|NOT IMPLEMENTED' src include api frontend/src tests evaluation docs scripts \
    --exclude-dir=node_modules --exclude-dir=.venv --exclude-dir=__pycache__ --exclude='*.bak*' 2>/dev/null || true
echo; echo "===== UNCHECKED RETURN VALUES IN SECURITY-CRITICAL CALLS (src/runtime) ====="
grep -nE '^\s*(mount|umount2|mkdir|chdir|sethostname|chroot|setns|unshare|prctl|capset|syscall)\(' src/runtime/*.c 2>/dev/null || true
echo; echo "===== SIGNAL / WAIT HANDLING ====="
grep -nE 'waitpid|sigaction|signal\(|SIGTERM|SIGINT|PDEATHSIG|kill\(' src/runtime/*.c src/tracer/*.c 2>/dev/null
echo; echo "===== SANDBOX KEY STEPS ====="
grep -nE 'pivot_root|CLONE_NEW|PR_SET_NO_NEW_PRIVS|PR_CAPBSET_DROP|cgroup|ps_apply_seccomp|--keep-caps' src/runtime/sandbox.c 2>/dev/null
echo; echo "===== API ROUTES ====="
grep -RInE '@(app|router)\.(get|post|put|patch|delete)' api --include='*.py' 2>/dev/null || echo "(none found)"
echo; echo "===== FRONTEND DATA SOURCES (fetch/axios/EventSource/WebSocket) ====="
grep -RInE 'fetch\(|axios|EventSource|WebSocket' frontend/src 2>/dev/null | head -40 || true
} 2>&1 | tee results/audit.txt
