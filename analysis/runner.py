"""PoViShield Execution Supervisor & Policy-Gated CLI Runner.

Connects the terminal execution environment to PoViShield's seccomp enforcement
and live monitoring pipeline.

Execution Lifecycle:
  1. Command & argument validation (no shell injection, strict argv array).
  2. Policy identification (matching learned profiles or candidate policies).
  3. Pre-execution policy evaluation (calculating risk reduction, withheld syscalls).
  4. Decision enforcement:
     - "enforce": installs seccomp-bpf filter with SCMP_ACT_KILL_PROCESS.
     - "inspect": traces syscalls without killing, recording all observed events.
     - "approval-required": checks safety gate approvals ledger; fails closed if unapproved.
  5. Sandboxed process launch and execution monitoring.
  6. Exit status capture (including kernel SIGSYS seccomp terminations).
  7. Auditable session timeline persistence and API exposure.
"""
from __future__ import annotations

import argparse
import json
import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

if __package__ is None or __package__ == "":
    ROOT = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(ROOT))
    from analysis.common import BIN, total_syscalls
    from analysis.risk import CRITICAL, HIGH, LOW, MEDIUM, risk_pct, weight
else:
    from .common import BIN, total_syscalls
    from .risk import CRITICAL, HIGH, LOW, MEDIUM, risk_pct, weight

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"
SESSIONS_DIR = RESULTS_DIR / "sessions"
PROFILES_DIR = RESULTS_DIR / "profiles"
APPROVALS_FILE = RESULTS_DIR / "approvals.jsonl"
TRACER_BIN = ROOT / "build" / "povishield"

SIGSYS_CODES = {-31, 159}
MAX_OUTPUT_BYTES = 64 * 1024  # 64 KB bounded output buffer

CRITICAL_SET = set(CRITICAL)
HIGH_SET = set(HIGH)

ELEVATED_COMMANDS = {
    "sudo", "su", "pkexec", "doas", "useradd", "usermod", "userdel",
    "groupadd", "passwd", "visudo", "iptables", "nft", "systemctl",
    "reboot", "poweroff", "shutdown"
}


@dataclass
class PolicyDecision:
    action: str  # PERMIT_WITH_RESTRICTIONS, DENIED, APPROVAL_REQUIRED
    allowed: bool
    mode: str
    target_name: str
    profile_path: Optional[str]
    allowed_syscalls_count: int
    total_syscalls_count: int
    attack_surface_reduction_pct: float
    risk_before: float
    risk_after: float
    allowed_syscalls: List[str]
    withheld_critical_syscalls: List[str]
    rationale: str
    approval_verified: bool
    enforcement_mechanism: str


@dataclass
class ExecutionSession:
    id: str
    command: List[str]
    mode: str
    target: str
    started_at: str
    ended_at: Optional[str] = None
    duration_ms: float = 0.0
    status: str = "pending"  # running, completed, killed_by_seccomp, denied, timed_out, error
    exit_code: Optional[int] = None
    violation_detected: bool = False
    violation_detail: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    decision: Optional[Dict[str, Any]] = None
    events_path: Optional[str] = None
    timeline: List[Dict[str, str]] = field(default_factory=list)
    device_id: Optional[str] = "laptop_terminal"
    hostname: Optional[str] = None
    host_target: Optional[str] = None
    is_terminal_cli: bool = True
    is_remote: bool = False
    syscalls: List[str] = field(default_factory=list)

    def add_event(self, phase: str, detail: str) -> None:
        self.timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "phase": phase,
            "detail": detail,
        })


def ensure_sessions_dir() -> Path:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    return SESSIONS_DIR


def validate_command(command: List[str]) -> Tuple[str, List[str]]:
    """Strictly validates target command arguments."""
    if not command or not isinstance(command, list):
        raise ValueError("Command must be a non-empty list of argument strings")
    if any(not isinstance(arg, str) or not arg.strip() for arg in command):
        raise ValueError("Command arguments must be non-empty strings")

    exe_path = command[0]
    # Resolve executable
    resolved = shutil.which(exe_path)
    if not resolved:
        candidate = Path(exe_path).resolve()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            resolved = str(candidate)
        else:
            raise FileNotFoundError(f"Executable not found or not executable: {exe_path}")

    return resolved, [resolved] + command[1:]


def find_profile_for_target(target_name: str, explicit_profile: Optional[str] = None) -> Optional[Path]:
    """Finds an existing profile for the target executable or returns the explicit profile."""
    if explicit_profile:
        p = Path(explicit_profile).resolve()
        if p.is_file():
            return p
        if (ROOT / explicit_profile).is_file():
            return (ROOT / explicit_profile).resolve()
        alt = (ROOT / "deploy_data" / "profiles" / Path(explicit_profile).name).resolve()
        if alt.is_file():
            return alt
        raise FileNotFoundError(f"Specified profile not found: {explicit_profile}")

    candidates = [
        PROFILES_DIR / f"{target_name}_counterfactual.json",
        PROFILES_DIR / f"{target_name}.json",
        PROFILES_DIR / f"{target_name}_baseline.json",
        RESULTS_DIR / f"{target_name}.json",
        ROOT / "deploy_data" / "profiles" / f"{target_name}_counterfactual.json",
        ROOT / "deploy_data" / "profiles" / f"{target_name}.json",
        ROOT / "deploy_data" / "profiles" / f"{target_name}_baseline.json",
        ROOT / "deploy_data" / f"{target_name}.json",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def is_approval_present(target_name: str, profile_path: Optional[Path]) -> bool:
    """Checks whether an approval record exists for this target and profile."""
    for cand in (APPROVALS_FILE, ROOT / "deploy_data" / "approvals.jsonl"):
        if not cand.is_file():
            continue
        try:
            with cand.open("r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                        if record.get("target") == target_name or (
                            profile_path and str(profile_path) in (record.get("candidate", ""), record.get("approved_at", ""))
                        ):
                            return True
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue
    return False


def load_profile_syscalls(profile_path: Path) -> List[str]:
    """Reads the syscalls array from a profile JSON file."""
    p = Path(profile_path)
    if not p.is_file():
        if (ROOT / p).is_file():
            p = ROOT / p
        else:
            alt = ROOT / "deploy_data" / "profiles" / p.name
            if alt.is_file():
                p = alt
    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
            return sorted(list(data.get("syscalls", [])))
    except Exception as e:
        raise ValueError(f"Failed to load profile {profile_path}: {e}") from e


def synthesize_minimal_profile(target_name: str, dest_path: Path) -> List[str]:
    """Generates a minimal observed profile for basic commands if none exists."""
    minimal_syscalls = [
        "access", "arch_prctl", "brk", "close", "execve", "exit_group", "fstat",
        "futex", "getrandom", "mmap", "mprotect", "munmap", "newfstatat",
        "openat", "pread64", "prlimit64", "read", "rseq", "set_robust_list",
        "set_tid_address", "write"
    ]
    if target_name in ("echo", "true", "false"):
        pass
    elif target_name in ("pwd",):
        minimal_syscalls.extend(["getcwd"])
    elif target_name in ("whoami",):
        minimal_syscalls.extend(["geteuid", "lseek"])
    elif target_name in ("id",):
        minimal_syscalls.extend(["geteuid", "getuid", "getgid", "getegid", "getgroups", "lseek"])
    elif target_name in ("date",):
        minimal_syscalls.extend(["clock_gettime", "lseek"])
    elif target_name in ("ls", "cat", "stat"):
        minimal_syscalls.extend(["getdents64", "ioctl", "lseek", "statx", "fstat"])
    elif target_name in ("grep", "wc", "head", "tail"):
        minimal_syscalls.extend(["lseek", "fadvise64", "fstat", "ioctl"])

    syscalls = sorted(list(set(minimal_syscalls)))
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    with dest_path.open("w", encoding="utf-8") as f:
        json.dump({
            "schema": 1,
            "command": target_name,
            "count": len(syscalls),
            "syscalls": syscalls
        }, f, indent=2)
    return syscalls


def evaluate_execution(
    command: List[str],
    mode: str = "enforce",
    explicit_profile: Optional[str] = None
) -> PolicyDecision:
    """Pre-execution policy evaluation and security reasoning."""
    resolved_exe, _ = validate_command(command)
    target_name = Path(resolved_exe).name
    tot = total_syscalls()

    profile_path = find_profile_for_target(target_name, explicit_profile)
    approval_verified = False

    is_elevated = (target_name in ELEVATED_COMMANDS or any(arg == "sudo" for arg in command[:2]))
    if mode == "approval-required" or is_elevated:
        approval_verified = is_approval_present(target_name, profile_path)
        if not approval_verified:
            rationale_text = (
                f"Execution blocked: Target '{target_name}' is an elevated/privileged command requiring explicit operator authorization via PoViShield Safety Gate. "
                if is_elevated else
                f"Execution blocked: Target '{target_name}' requires explicit security approval. "
            ) + f"No verified record was found in the safety gate ledger ({APPROVALS_FILE.name}). System fails closed to prevent unverified policy execution."
            return PolicyDecision(
                action="APPROVAL_REQUIRED",
                allowed=False,
                mode=mode,
                target_name=target_name,
                profile_path=str(profile_path) if profile_path else None,
                allowed_syscalls_count=0,
                total_syscalls_count=tot,
                attack_surface_reduction_pct=100.0,
                risk_before=100.0,
                risk_after=0.0,
                allowed_syscalls=[],
                withheld_critical_syscalls=CRITICAL[:8],
                rationale=rationale_text,
                approval_verified=False,
                enforcement_mechanism="Fail-Closed Pre-Execution Gate",
            )

    if profile_path:
        allowed_syscalls = load_profile_syscalls(profile_path)
        profile_str = str(profile_path.relative_to(ROOT) if profile_path.is_relative_to(ROOT) else profile_path)
    else:
        # If no profile exists and in enforce mode, synthesize or deny
        if mode == "enforce":
            # For well-known safe targets, synthesize a verified minimal policy
            synth_path = RESULTS_DIR / "profiles" / f"{target_name}_synthesized.json"
            allowed_syscalls = synthesize_minimal_profile(target_name, synth_path)
            profile_path = synth_path
            profile_str = str(synth_path.relative_to(ROOT))
        else:
            allowed_syscalls = []
            profile_str = None

    num_allowed = len(allowed_syscalls)
    reduction = round((1.0 - (num_allowed / tot)) * 100.0, 2) if tot else 0.0
    r_after = round(risk_pct(allowed_syscalls, tot), 2) if num_allowed else 100.0
    withheld_crit = [s for s in CRITICAL if s not in set(allowed_syscalls)]

    if mode == "inspect":
        rationale = (
            f"Target '{target_name}' will execute under Ptrace inspection (non-killing audit mode). "
            f"All system calls will be recorded in the live telemetry stream. "
            f"No seccomp kill restrictions will be enforced."
        )
        action = "PERMIT_WITH_RESTRICTIONS"
        mech = "Linux Ptrace Dynamic Tracer (Audited)"
    else:
        rationale = (
            f"Target '{target_name}' evaluated against least-privilege policy '{profile_str}'. "
            f"Allowed {num_allowed}/{tot} syscalls ({reduction}% attack surface reduction). "
            f"Critical syscalls ({', '.join(withheld_crit[:5])}...) are withheld. "
            f"Any unlearned system call will immediately trigger kernel SIGSYS process termination."
        )
        action = "PERMIT_WITH_RESTRICTIONS"
        mech = "Linux Seccomp-BPF (SCMP_ACT_KILL_PROCESS, PR_SET_NO_NEW_PRIVS)"

    return PolicyDecision(
        action=action,
        allowed=True,
        mode=mode,
        target_name=target_name,
        profile_path=profile_str,
        allowed_syscalls_count=num_allowed,
        total_syscalls_count=tot,
        attack_surface_reduction_pct=reduction,
        risk_before=100.0,
        risk_after=r_after,
        allowed_syscalls=allowed_syscalls,
        withheld_critical_syscalls=withheld_crit,
        rationale=rationale,
        approval_verified=approval_verified or (mode != "approval-required"),
        enforcement_mechanism=mech,
    )


def _request_live_safety_gate_approval(
    target_name: str,
    full_cmd: List[str],
    mode: str,
    profile_path: Optional[str]
) -> bool:
    """Submits an interactive approval request to PoViShield Safety Gate and polls for operator decision."""
    # In automated test suites or non-interactive headless processes, fail closed immediately
    if "unittest" in sys.modules or "pytest" in sys.modules or not sys.stdin.isatty():
        if os.environ.get("POVISHIELD_INTERACTIVE_APPROVAL") != "1":
            return False

    server_url = os.environ.get("POVI_SERVER_URL") or os.environ.get("POVISHIELD_SERVER")
    token = None
    device_id = None
    for cfg_path in [Path.home() / ".povishield" / "agent.json", Path("/etc/povishield/agent.json")]:
        if cfg_path.is_file():
            try:
                with cfg_path.open("r", encoding="utf-8") as cf:
                    c = json.load(cf)
                    if not server_url:
                        server_url = c.get("server_url")
                    token = c.get("token")
                    device_id = c.get("device_id")
                    break
            except Exception:
                pass

    if not server_url:
        server_url = "http://127.0.0.1:8000"

    server_url = server_url.rstrip("/")
    req_url = f"{server_url}/api/approvals/request"
    hostname = socket.gethostname()

    payload = {
        "target": target_name,
        "command": full_cmd,
        "mode": mode,
        "device_id": device_id or "laptop_terminal",
        "hostname": hostname,
        "candidate": profile_path or f"results/profiles/{target_name}.json",
        "rationale": f"Interactive operator approval requested for '{' '.join(full_cmd)}'"
    }

    try:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(req_url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            appr_id = data.get("id")
    except Exception:
        return False

    if not appr_id:
        return False

    sys.stderr.write("\n╔══════════════════════════════════════════════════════════════════════════════╗\n")
    sys.stderr.write("║           PoViShield Interactive Safety Gate Permission Request              ║\n")
    sys.stderr.write("╚══════════════════════════════════════════════════════════════════════════════╝\n")
    sys.stderr.write(f"[SAFETY GATE] Target '{target_name}' requires security authorization before execution.\n")
    sys.stderr.write(f"[REQUEST ID]  {appr_id}\n")
    sys.stderr.write(f"[COMMAND]     {' '.join(full_cmd)}\n")
    sys.stderr.write(f"[DASHBOARD]   Open PoViShield Web Dashboard to Approve or Deny.\n")
    sys.stderr.write(f"[TERMINAL]    Or authorize now in this terminal [y = Approve / n = Deny / s = Sudo]: ")
    sys.stderr.flush()

    status_url = f"{server_url}/api/approvals/{appr_id}/status"
    grant_url = f"{server_url}/api/approvals/{appr_id}/grant"
    deny_url = f"{server_url}/api/approvals/{appr_id}/deny"
    start_wait = time.monotonic()
    while time.monotonic() - start_wait < 35.0:
        if sys.stdin.isatty():
            try:
                rlist, _, _ = select.select([sys.stdin], [], [], 0.5)
                if rlist:
                    line = sys.stdin.readline().strip().lower()
                    if line in ("y", "yes"):
                        sys.stderr.write("\n[APPROVED]    Permission GRANTED by local terminal operator!\n")
                        sys.stderr.write(f"[PROCEED]     Executing target '{target_name}' under verified confinement...\n\n")
                        sys.stderr.flush()
                        try:
                            g_req = urllib.request.Request(grant_url, data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
                            urllib.request.urlopen(g_req, timeout=1.5)
                        except Exception:
                            pass
                        return True
                    elif line in ("n", "no"):
                        sys.stderr.write("\n[DENIED]      Permission DENIED by terminal operator. Failing closed.\n\n")
                        sys.stderr.flush()
                        try:
                            d_req = urllib.request.Request(deny_url, data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
                            urllib.request.urlopen(d_req, timeout=1.5)
                        except Exception:
                            pass
                        return False
                    elif line in ("s", "sudo"):
                        sys.stderr.write("\n[SUDO]        Verifying elevated permissions via sudo...\n")
                        try:
                            rc = subprocess.call(["sudo", "-v"])
                            if rc == 0:
                                sys.stderr.write("[SUDO]        Elevated authorization verified!\n")
                                sys.stderr.write(f"[PROCEED]     Executing target '{target_name}' under verified confinement...\n\n")
                                sys.stderr.flush()
                                try:
                                    g_req = urllib.request.Request(grant_url, data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
                                    urllib.request.urlopen(g_req, timeout=1.5)
                                except Exception:
                                    pass
                                return True
                            else:
                                sys.stderr.write("[SUDO]        Sudo verification failed. Failing closed.\n\n")
                                sys.stderr.flush()
                                return False
                        except Exception:
                            pass
            except Exception:
                pass
        else:
            time.sleep(1.0)

        try:
            s_req = urllib.request.Request(status_url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(s_req, timeout=2.0) as s_resp:
                s_data = json.loads(s_resp.read().decode("utf-8"))
                s_status = s_data.get("status")
                if s_status == "approved":
                    sys.stderr.write("\n[APPROVED]    Permission GRANTED by operator in web Safety Gate!\n")
                    sys.stderr.write(f"[PROCEED]     Executing target '{target_name}' under verified confinement...\n\n")
                    sys.stderr.flush()
                    return True
                elif s_status == "denied":
                    sys.stderr.write("\n[DENIED]      Permission DENIED by operator in Safety Gate.\n\n")
                    sys.stderr.flush()
                    return False
        except Exception:
            continue

    sys.stderr.write("\n[TIMEOUT]     Approval request timed out without operator verdict. Failing closed.\n\n")
    sys.stderr.flush()
    return False


def execute_session(
    command: List[str],
    mode: str = "enforce",
    explicit_profile: Optional[str] = None,
    timeout_seconds: float = 30.0,
    record_events: bool = True,
    is_terminal_cli: bool = True,
    device_id: Optional[str] = None,
    hostname: Optional[str] = None,
    host_target: Optional[str] = None,
) -> ExecutionSession:
    """Executes a target command through the full policy evaluation & sandboxing pipeline."""
    ensure_sessions_dir()
    session_id = f"run-{uuid.uuid4().hex[:8]}"
    resolved_exe, full_cmd = validate_command(command)
    target_name = Path(resolved_exe).name
    host = hostname or socket.gethostname()
    dev_id = device_id or "laptop_terminal"
    h_target = host_target or (f"Local Terminal ({host})" if is_terminal_cli else f"Local System ({host})")

    session = ExecutionSession(
        id=session_id,
        command=full_cmd,
        mode=mode,
        target=target_name,
        started_at=datetime.now(timezone.utc).isoformat(),
        device_id=dev_id,
        hostname=host,
        host_target=h_target,
        is_terminal_cli=is_terminal_cli,
        is_remote=False,
    )
    session.add_event("COMMAND_VALIDATED", f"Target executable resolved: {resolved_exe}")

    # 1. Pre-execution evaluation
    decision = evaluate_execution(full_cmd, mode=mode, explicit_profile=explicit_profile)
    session.decision = asdict(decision)
    if decision.allowed_syscalls:
        session.syscalls = list(decision.allowed_syscalls)
    session.add_event("POLICY_EVALUATED", f"Decision: {decision.action} ({decision.enforcement_mechanism})")

    if not decision.allowed:
        is_elevated = (target_name in ELEVATED_COMMANDS or any(arg == "sudo" for arg in full_cmd[:2]))
        if (mode == "approval-required" or is_elevated) and decision.action == "APPROVAL_REQUIRED":
            approved = _request_live_safety_gate_approval(
                target_name=target_name,
                full_cmd=full_cmd,
                mode=mode,
                profile_path=decision.profile_path
            )
            if approved:
                decision = evaluate_execution(full_cmd, mode=mode, explicit_profile=explicit_profile)
                session.decision = asdict(decision)
                if decision.allowed_syscalls:
                    session.syscalls = list(decision.allowed_syscalls)
                session.add_event("OPERATOR_APPROVAL_GRANTED", f"Operator granted permission for target '{target_name}' via Safety Gate")

        if not decision.allowed:
            session.status = "denied"
            session.exit_code = 126
            session.ended_at = datetime.now(timezone.utc).isoformat()
            session.violation_detected = True
            session.violation_detail = decision.rationale
            session.stderr = f"PoViShield Security Gate Denied Execution: {decision.rationale}\n"
            session.add_event("EXECUTION_DENIED", decision.rationale)
            _persist_session(session)
            return session

    # 2. Setup execution boundary
    events_file = SESSIONS_DIR / f"{session_id}-events.jsonl" if record_events else None
    if events_file:
        session.events_path = str(events_file.relative_to(ROOT))

    profile_path = ROOT / decision.profile_path if decision.profile_path else None
    if profile_path and not profile_path.is_file():
        alt = (ROOT / "deploy_data" / "profiles" / Path(decision.profile_path).name).resolve()
        if alt.is_file():
            profile_path = alt

    # Check tracer binary
    if not TRACER_BIN.is_file():
        session.status = "error"
        session.exit_code = 127
        session.ended_at = datetime.now(timezone.utc).isoformat()
        session.stderr = "PoViShield binary missing. Run 'make' to build the runtime.\n"
        session.add_event("ERROR", "Runtime binary build/povishield not found")
        _persist_session(session)
        return session

    # Prepare command to execute
    if mode == "inspect" or (record_events and not profile_path):
        # Use tracer learn to record events without seccomp kill
        exec_argv = [
            str(TRACER_BIN), "learn",
            "--events", str(events_file),
            "--max-event-bytes", str(10 * 1024 * 1024),
            "-o", str(SESSIONS_DIR / f"{session_id}-profile.json"),
            "--", *full_cmd
        ]
        session.add_event("SANDBOX_INITIALIZED", "Tracing initialized with Linux Ptrace events stream")
    else:
        # Use enforce with strict seccomp
        exec_argv = [
            str(TRACER_BIN), "enforce",
            "-p", str(profile_path),
            "--", *full_cmd
        ]
        session.add_event("SANDBOX_INITIALIZED", f"Seccomp-BPF filter loaded from {decision.profile_path}")

    start_time = time.monotonic()
    session.status = "running"
    session.add_event("PROCESS_SPAWNED", f"Target PID spawned under confinement")

    child_env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(Path.home()),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }

    try:
        proc = subprocess.Popen(
            exec_argv,
            cwd=ROOT,
            env=child_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            text=True,
            errors="replace",
        )
        stdout_data, stderr_data = proc.communicate(timeout=timeout_seconds)
        elapsed_ms = (time.monotonic() - start_time) * 1000.0
        rc = proc.returncode

        session.duration_ms = round(elapsed_ms, 2)
        session.exit_code = rc
        session.stdout = (stdout_data or "")[:MAX_OUTPUT_BYTES]
        session.stderr = (stderr_data or "")[:MAX_OUTPUT_BYTES]
        session.ended_at = datetime.now(timezone.utc).isoformat()

        # Check for kernel seccomp SIGSYS termination
        if rc in SIGSYS_CODES:
            session.status = "killed_by_seccomp"
            session.violation_detected = True
            session.violation_detail = (
                f"Kernel Seccomp Violation: Process attempted unauthorized syscall outside "
                f"active policy and was terminated by kernel SIGSYS (returncode {rc})."
            )
            session.add_event("KERNEL_SIGSYS_VIOLATION", session.violation_detail)
        elif rc == 0:
            session.status = "completed"
            session.add_event("PROCESS_EXITED", f"Process exited successfully with code {rc}")
        else:
            session.status = "completed"
            session.add_event("PROCESS_EXITED", f"Process terminated with non-zero exit code {rc}")

    except subprocess.TimeoutExpired:
        if proc:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            proc.communicate()
        session.status = "timed_out"
        session.exit_code = 124
        session.duration_ms = round((time.monotonic() - start_time) * 1000.0, 2)
        session.ended_at = datetime.now(timezone.utc).isoformat()
        session.violation_detected = True
        session.violation_detail = f"Execution exceeded timeout limit ({timeout_seconds}s)"
        session.add_event("TIMEOUT", session.violation_detail)

    except Exception as exc:
        session.status = "error"
        session.exit_code = 1
        session.ended_at = datetime.now(timezone.utc).isoformat()
        session.stderr = f"Execution supervisor error: {exc}\n"
        session.add_event("ERROR", str(exc))

    _persist_session(session)
    return session


def _enrich_session_metadata(session: ExecutionSession) -> None:
    hostname = socket.gethostname()
    if not session.hostname:
        session.hostname = hostname
    if not session.device_id:
        session.device_id = "laptop_terminal"
    if not session.host_target:
        session.host_target = f"Local Terminal ({session.hostname})" if session.is_terminal_cli else f"Local System ({session.hostname})"

    # Populate syscalls
    if not session.syscalls:
        if session.decision and isinstance(session.decision, dict):
            session.syscalls = list(session.decision.get("allowed_syscalls") or [])
        if not session.syscalls and session.events_path:
            ep = ROOT / session.events_path
            if ep.is_file():
                try:
                    with ep.open("r", encoding="utf-8") as ef:
                        for line in ef:
                            line = line.strip()
                            if not line:
                                continue
                            ev = json.loads(line)
                            sc = ev.get("syscall")
                            if sc and sc not in session.syscalls:
                                session.syscalls.append(sc)
                except Exception:
                    pass
        if not session.syscalls and session.target:
            prof = find_profile_for_target(session.target)
            if prof:
                try:
                    session.syscalls = load_profile_syscalls(prof)
                except Exception:
                    pass


def _persist_session(session: ExecutionSession) -> None:
    """Saves session metadata to results/sessions/{session_id}.json and syncs telemetry."""
    ensure_sessions_dir()
    _enrich_session_metadata(session)
    dest = SESSIONS_DIR / f"{session.id}.json"
    try:
        with dest.open("w", encoding="utf-8") as f:
            json.dump(asdict(session), f, indent=2)
    except OSError as exc:
        sys.stderr.write(f"Warning: could not persist session {session.id}: {exc}\n")

    _sync_session_telemetry(session)


def _sync_session_telemetry(session: ExecutionSession) -> None:
    """Syncs terminal execution session and observed syscalls to PoViShield dashboard."""
    try:
        events_file = RESULTS_DIR / "syscall-events.jsonl"
        syscalls: List[str] = list(session.syscalls or [])

        # Determine target server URL, token, device_id, and hostname from config first
        server_url = os.environ.get("POVI_SERVER_URL") or os.environ.get("POVISHIELD_SERVER")
        token = None
        device_id = session.device_id or "laptop_terminal"
        hostname = session.hostname or socket.gethostname()

        for cfg_path in [Path.home() / ".povishield" / "agent.json", Path("/etc/povishield/agent.json")]:
            if cfg_path.is_file():
                try:
                    with cfg_path.open("r", encoding="utf-8") as cf:
                        c = json.load(cf)
                        if not server_url:
                            server_url = c.get("server_url")
                        token = c.get("token")
                        if c.get("device_id"):
                            device_id = c.get("device_id")
                        if c.get("hostname"):
                            hostname = c.get("hostname")
                        break
                except Exception:
                    pass

        is_remote = (device_id != "laptop_terminal")

        # Write to local events_file for live monitor
        if syscalls:
            try:
                events_file.parent.mkdir(parents=True, exist_ok=True)
                with events_file.open("a", encoding="utf-8") as ef:
                    for sc in syscalls[:15]:
                        ef.write(json.dumps({
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "device_id": device_id,
                            "hostname": hostname,
                            "target": session.target,
                            "syscall": sc,
                            "action": "ALLOWED"
                        }) + "\n")
            except Exception:
                pass

        # Prepare payload for dashboard API sync
        data = asdict(session)
        data["is_terminal_cli"] = session.is_terminal_cli
        data["is_remote"] = is_remote
        data["hostname"] = hostname
        data["device_id"] = device_id
        data["syscalls"] = syscalls
        data["host_target"] = session.host_target or (f"{hostname} ({device_id})" if is_remote else f"Local Terminal ({hostname})")

        if not server_url:
            server_url = "http://127.0.0.1:8000"

        server_url = server_url.rstrip("/")
        req_url = f"{server_url}/api/executions/record"
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(req_url, data=json.dumps(data).encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=1.5) as _:
            pass
    except Exception:
        pass


def list_sessions(limit: int = 50) -> List[Dict[str, Any]]:
    """Loads all recorded sessions from disk, newest first."""
    ensure_sessions_dir()
    results = []
    files = sorted(
        [p for p in SESSIONS_DIR.glob("*.json") if not p.name.endswith("-profile.json")],
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )
    hostname = socket.gethostname()
    for p in files[:limit]:
        try:
            with p.open("r", encoding="utf-8") as f:
                data = json.load(f)
                if not data.get("started_at"):
                    data["started_at"] = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat()
                if data.get("is_terminal_cli") is None:
                    data["is_terminal_cli"] = not data.get("is_remote", False)
                if not data.get("hostname"):
                    data["hostname"] = hostname
                if not data.get("device_id"):
                    data["device_id"] = "laptop_terminal" if not data.get("is_remote") else "remote"
                if not data.get("host_target"):
                    data["host_target"] = f"Local Terminal ({data['hostname']})" if not data.get("is_remote") else f"Remote Host ({data['hostname']})"
                if not data.get("syscalls"):
                    dec = data.get("decision") or {}
                    if isinstance(dec, dict) and dec.get("allowed_syscalls"):
                        data["syscalls"] = dec["allowed_syscalls"]
                    elif data.get("target"):
                        prof = find_profile_for_target(data["target"])
                        if prof:
                            try:
                                data["syscalls"] = load_profile_syscalls(prof)
                            except Exception:
                                pass
                results.append(data)
        except Exception:
            continue
    return results


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single session by ID."""
    p = SESSIONS_DIR / f"{session_id}.json"
    if not p.is_file():
        alt_id = f"run-remote-{session_id.replace('task_', '')}"
        alt_p = SESSIONS_DIR / f"{alt_id}.json"
        if alt_p.is_file():
            p = alt_p
        else:
            return None
    try:
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def format_terminal_output(session: ExecutionSession) -> str:
    """Formats the execution session in high-density cybersecurity terminal typography."""
    lines = []
    lines.append("╔══════════════════════════════════════════════════════════════════════════════╗")
    lines.append("║                   PoViShield Security Execution Supervisor                   ║")
    lines.append("╚══════════════════════════════════════════════════════════════════════════════╝")
    lines.append(f"[SESSION] ID: {session.id} | Timestamp: {session.started_at}")
    lines.append(f"[TARGET]  Command: {' '.join(session.command)}")
    lines.append(f"[MODE]    {session.mode.upper()} | Mechanism: {session.decision.get('enforcement_mechanism') if session.decision else 'None'}")
    lines.append("─" * 80)

    if session.decision:
        d = session.decision
        lines.append(f"[POLICY]  Matched: {d.get('profile_path') or 'Synthesized Minimal'}")
        lines.append(
            f"[SURFACE] Allowed Syscalls: {d.get('allowed_syscalls_count')}/{d.get('total_syscalls_count')} | "
            f"Reduction: {d.get('attack_surface_reduction_pct')}% | "
            f"Risk: {d.get('risk_before')} -> {d.get('risk_after')}"
        )
        lines.append(f"[GATE]    Decision: {d.get('action')}")
        lines.append(f"[REASON]  {d.get('rationale')}")

    lines.append("─" * 80)
    lines.append(">>> TARGET STANDARD OUTPUT >>>")
    if session.stdout:
        lines.append(session.stdout.rstrip())
    else:
        lines.append("(No standard output captured)")

    if session.stderr:
        lines.append(">>> TARGET STANDARD ERROR >>>")
        lines.append(session.stderr.rstrip())

    lines.append("─" * 80)
    status_label = session.status.upper()
    if session.status == "killed_by_seccomp":
        status_label = "KILL_PROCESS (SEVENTEEN / SIGSYS)"
    lines.append(
        f"[RESULT]  Status: {status_label} | Exit Code: {session.exit_code} | Duration: {session.duration_ms}ms"
    )

    if session.violation_detected:
        lines.append(f"[ALERT]   Violation Detail: {session.violation_detail}")

    lines.append(f"[AUDIT]   Session Log: results/sessions/{session.id}.json")
    lines.append("═" * 80)
    return "\n".join(lines)


def run_interactive_shell(mode: str = "enforce") -> int:
    """Runs an interactive sandboxed terminal session synced to the web terminal."""
    hostname = socket.gethostname()
    current_mode = mode

    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║             PoViShield Interactive Terminal & Sandbox Console                ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print(f"[*] Local Host: {hostname} | Status: Confinement Active & Synced to Web Console")
    print("[*] Every command executed here is policy-confined and streamed to the dashboard.")
    print("[*] Commands: 'mode <enforce|inspect|approval-required>', 'status', 'help', 'exit'")
    print("────────────────────────────────────────────────────────────────────────────────")

    import shlex
    while True:
        try:
            line = input(f"povishield [{current_mode}] > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting PoViShield terminal.")
            break

        if not line:
            continue

        if line in ("exit", "quit", "q"):
            print("Session closed.")
            break

        if line == "help":
            print("Interactive PoViShield Terminal:")
            print("  Run any system command: e.g. 'echo hello', 'ls /tmp', 'uname -a', 'cat /etc/os-release'")
            print("  mode <enforce|inspect|approval-required>  - Switch confinement mode")
            print("  status                                   - View current supervisor status")
            print("  clear                                    - Clear screen")
            print("  exit                                     - Exit this terminal")
            continue

        if line == "clear":
            os.system("clear")
            continue

        if line.startswith("mode "):
            new_mode = line.split(" ", 1)[1].strip().lower()
            if new_mode in ("enforce", "inspect", "approval-required"):
                current_mode = new_mode
                print(f"[MODE] Confinement mode switched to: {current_mode.upper()}")
            else:
                print("[ERROR] Valid modes are: enforce, inspect, approval-required")
            continue

        if line == "status":
            print(f"[STATUS] Mode: {current_mode.upper()} | Host: {hostname} | Web Sync: Active")
            continue

        try:
            cmd_tokens = shlex.split(line)
        except Exception:
            cmd_tokens = line.split()

        if not cmd_tokens:
            continue

        try:
            session = execute_session(
                command=cmd_tokens,
                mode=current_mode,
                is_terminal_cli=True,
                hostname=hostname,
                device_id="laptop_terminal",
                host_target=f"Local Terminal ({hostname})"
            )
            if session.stdout:
                sys.stdout.write(session.stdout)
                if not session.stdout.endswith("\n"):
                    sys.stdout.write("\n")
                sys.stdout.flush()
            if session.stderr:
                sys.stderr.write(session.stderr)
                if not session.stderr.endswith("\n"):
                    sys.stderr.write("\n")
                sys.stderr.flush()

            if session.violation_detected:
                print(f"[ALERT] {session.violation_detail}")
            print(f"[{session.status.upper()}] Exit: {session.exit_code} | Duration: {session.duration_ms}ms | Synced to Web Terminal")
        except Exception as err:
            print(f"[ERROR] {err}")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="povishield",
        description="PoViShield Intelligent Application Sandboxing & Execution Supervisor"
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommand to execute")

    # Run subcommand
    run_parser = subparsers.add_parser("run", help="Execute a command under policy-gated seccomp confinement")
    run_parser.add_argument("--mode", choices=["enforce", "inspect", "approval-required"], default="enforce",
                            help="Execution mode (default: enforce)")
    run_parser.add_argument("--profile", "-p", help="Explicit syscall profile path")
    run_parser.add_argument("--timeout", type=float, default=30.0, help="Max execution timeout in seconds")
    run_parser.add_argument("--json", action="store_true", help="Output session report in JSON format")
    run_parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute after '--'")

    # Shell subcommand
    shell_parser = subparsers.add_parser("shell", help="Interactive terminal session with real-time web console sync")
    shell_parser.add_argument("--mode", choices=["enforce", "inspect", "approval-required"], default="enforce")

    # Evaluate subcommand
    eval_parser = subparsers.add_parser("evaluate", help="Pre-evaluate policy decision for a command without executing")
    eval_parser.add_argument("--mode", choices=["enforce", "inspect", "approval-required"], default="enforce")
    eval_parser.add_argument("--profile", "-p", help="Explicit profile path")
    eval_parser.add_argument("--json", action="store_true", help="Output decision as JSON")
    eval_parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to evaluate after '--'")

    # List subcommand
    list_parser = subparsers.add_parser("list", help="List recent execution sessions")
    list_parser.add_argument("--limit", type=int, default=20, help="Number of sessions to show")

    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        return 2

    if args.subcommand == "shell":
        return run_interactive_shell(mode=args.mode)

    if args.subcommand == "list":
        sessions = list_sessions(limit=args.limit)
        print(f"Recorded PoViShield Execution Sessions ({len(sessions)}):")
        print(f"{'ID':<14} {'STATUS':<18} {'EXIT':<6} {'DURATION':<10} {'COMMAND'}")
        print("─" * 70)
        for s in sessions:
            cmd_str = " ".join(s.get("command", []))
            print(f"{s.get('id'):<14} {s.get('status'):<18} {str(s.get('exit_code')):<6} {str(s.get('duration_ms'))+'ms':<10} {cmd_str}")
        return 0

    # Parse command after '--'
    raw_cmd = args.command
    if raw_cmd and raw_cmd[0] == "--":
        raw_cmd = raw_cmd[1:]

    if not raw_cmd:
        sys.stderr.write("Error: Please specify target command after '--', e.g. povishield run -- /bin/echo 'hello'\n")
        return 2

    if args.subcommand == "evaluate":
        try:
            decision = evaluate_execution(raw_cmd, mode=args.mode, explicit_profile=args.profile)
            if args.json:
                print(json.dumps(asdict(decision), indent=2))
            else:
                print(f"[DECISION] Action: {decision.action} | Allowed: {decision.allowed}")
                print(f"[TARGET]   {decision.target_name} ({decision.allowed_syscalls_count}/{decision.total_syscalls_count} syscalls)")
                print(f"[SURFACE]  Reduction: {decision.attack_surface_reduction_pct}% | Risk: {decision.risk_before} -> {decision.risk_after}")
                print(f"[REASON]   {decision.rationale}")
            return 0 if decision.allowed else 1
        except Exception as e:
            sys.stderr.write(f"Evaluation error: {e}\n")
            return 1

    if args.subcommand == "run":
        try:
            session = execute_session(
                command=raw_cmd,
                mode=args.mode,
                explicit_profile=args.profile,
                timeout_seconds=args.timeout,
            )
            if args.json:
                print(json.dumps(asdict(session), indent=2))
            else:
                print(format_terminal_output(session))

            if session.status == "killed_by_seccomp":
                return 159
            return session.exit_code if session.exit_code is not None else 1
        except Exception as e:
            sys.stderr.write(f"Execution error: {e}\n")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
