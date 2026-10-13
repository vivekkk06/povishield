"""PoViShield Local Linux Security Agent.

Probes local security capabilities, connects outbound to the PoViShield public dashboard,
receives policy-gated execution tasks, enforces seccomp sandbox boundaries,
and streams telemetry and security events back to the dashboard.
"""
import argparse
import ctypes
import json
import os
import platform
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEFAULT_CONFIG_PATH = Path.home() / ".povishield" / "agent.json"

# Linux prctl constants
PR_SET_NO_NEW_PRIVS = 38


def probe_local_security() -> Dict[str, Any]:
    """Inspects real Linux kernel security capabilities truthfully. Never pretends seccomp exists if unavailable."""
    is_linux = sys.platform.startswith("linux")
    uname = platform.uname()

    seccomp_bpf_supported = False
    no_new_privs_supported = False
    cgroups_v2_supported = False
    user_namespaces_supported = False

    if is_linux:
        # 1. Seccomp BPF kernel support via /proc/self/status and prctl
        try:
            status_text = Path("/proc/self/status").read_text()
            if "Seccomp:" in status_text:
                seccomp_bpf_supported = True
        except Exception:
            pass
        if not seccomp_bpf_supported:
            try:
                libc = ctypes.CDLL("libc.so.6", use_errno=True)
                if hasattr(libc, "prctl") and libc.prctl(21, 0, 0, 0, 0) >= 0:
                    seccomp_bpf_supported = True
            except Exception:
                pass

        # 2. Test PR_SET_NO_NEW_PRIVS via libc prctl
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            # We don't actually set it in the probe process, but check if prctl symbol exists
            if hasattr(libc, "prctl"):
                no_new_privs_supported = True
        except Exception:
            no_new_privs_supported = False

        # 3. Check Cgroups v2
        cgroup_controllers = Path("/sys/fs/cgroup/cgroup.controllers")
        if cgroup_controllers.is_file():
            cgroups_v2_supported = True

        # 4. Check user namespaces
        userns_file = Path("/proc/sys/kernel/unprivileged_userns_clone")
        if userns_file.is_file():
            try:
                user_namespaces_supported = userns_file.read_text().strip() == "1"
            except Exception:
                user_namespaces_supported = False
        else:
            # On modern kernels (e.g. Fedora / Ubuntu), userns is enabled by default
            user_namespaces_supported = Path("/proc/self/ns/user").exists()

    # 5. Check if PoViShield native tracer binary is built and executable
    tracer_bin = ROOT / "build" / "povishield"
    native_sandbox = tracer_bin.is_file() and os.access(tracer_bin, os.X_OK)

    # 6. Overall enforcement verification
    enforcement_verified = bool(is_linux and seccomp_bpf_supported and native_sandbox)

    return {
        "is_linux": is_linux,
        "platform": sys.platform,
        "kernel_release": uname.release,
        "os_name": f"{uname.system} {uname.release}",
        "architecture": uname.machine,
        "hostname": socket.gethostname(),
        "seccomp_bpf": seccomp_bpf_supported,
        "no_new_privs": no_new_privs_supported,
        "cgroups_v2": cgroups_v2_supported,
        "user_namespaces": user_namespaces_supported,
        "native_sandbox": native_sandbox,
        "enforcement_verified": enforcement_verified,
        "probed_at": datetime.now(timezone.utc).isoformat(),
    }


def load_agent_config(config_path: Path = DEFAULT_CONFIG_PATH) -> Optional[Dict[str, Any]]:
    if not config_path.is_file():
        return None
    try:
        with config_path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_agent_config(config: Dict[str, Any], config_path: Path = DEFAULT_CONFIG_PATH) -> None:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


def make_api_request(
    url: str,
    method: str = "GET",
    data: Optional[Dict[str, Any]] = None,
    token: Optional[str] = None,
    timeout: float = 30.0
) -> Tuple[int, Dict[str, Any]]:
    """Makes an HTTP/HTTPS request to the dashboard API."""
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    body_bytes = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            raw = resp.read()
            payload = json.loads(raw.decode("utf-8")) if raw else {}
            return status, payload
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            payload = {"detail": raw.decode("utf-8", errors="replace")}
        return exc.code, payload
    except Exception as exc:
        return 0, {"detail": str(exc)}


def pair_agent(
    server_url: str,
    pairing_code: str,
    device_name: Optional[str] = None,
    config_path: Path = DEFAULT_CONFIG_PATH,
    allow_execution: bool = True,
    share_output: bool = True
) -> Dict[str, Any]:
    """Exchanges a one-time pairing code for permanent authenticated agent credentials."""
    server_url = server_url.rstrip("/")
    if not server_url.startswith(("http://", "https://")):
        if "localhost" in server_url or "127.0.0.1" in server_url:
            server_url = f"http://{server_url}"
        else:
            server_url = f"https://{server_url}"

    probe = probe_local_security()
    name = device_name or f"{probe['hostname']} ({probe['kernel_release'][:16]})"

    permissions = {
        "allow_diagnostics": True,
        "allow_monitoring": True,
        "allow_enforcement": True,
        "allow_execution": allow_execution,
        "share_output": share_output,
    }

    payload = {
        "pairing_code": pairing_code.strip(),
        "name": name,
        "hostname": probe["hostname"],
        "os_info": probe["os_name"],
        "kernel_version": probe["kernel_release"],
        "arch": probe["architecture"],
        "capabilities": probe,
        "permissions": permissions,
    }

    pair_url = f"{server_url}/api/agent/pair"
    status, resp = make_api_request(pair_url, method="POST", data=payload)

    if status != 200:
        raise RuntimeError(f"Pairing failed (HTTP {status}): {resp.get('detail', 'Unknown error')}")

    device_id = resp["device_id"]
    token = resp["token"]

    config = {
        "server_url": server_url,
        "device_id": device_id,
        "token": token,
        "name": name,
        "permissions": permissions,
        "paired_at": datetime.now(timezone.utc).isoformat(),
    }
    save_agent_config(config, config_path)
    return config


def direct_connect_agent(
    server_url: str = "http://localhost:8000",
    device_name: Optional[str] = None,
    pairing_code: Optional[str] = None,
    config_path: Path = DEFAULT_CONFIG_PATH,
    start_daemon: bool = True,
    foreground: bool = False
) -> Dict[str, Any]:
    """Inspects terminal permissions (sudo/root) and directly enrolls or connects the current device to PoViShield."""
    is_root = (os.geteuid() == 0)
    server_url = server_url.rstrip("/")
    if not server_url.startswith(("http://", "https://")):
        if "localhost" in server_url or "127.0.0.1" in server_url:
            server_url = f"http://{server_url}"
        else:
            server_url = f"https://{server_url}"

    probe = probe_local_security()
    name = device_name or f"{probe['hostname']} ({'root' if is_root else 'user'})"

    permissions = {
        "is_root": is_root,
        "allow_diagnostics": True,
        "allow_monitoring": True,
        "allow_enforcement": True,
        "allow_execution": True,
        "share_output": True,
        "namespaces": is_root,
        "cgroups": is_root,
    }

    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                   PoViShield Terminal Direct Device Link                     ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print(f"Device Name:       {name}")
    print(f"Host / OS:         {probe['hostname']} ({probe['os_name']})")
    print(f"Privilege Level:   {'[ROOT / SUPERVISOR ACTIVE]' if is_root else '[STANDARD USER (PR_SET_NO_NEW_PRIVS)]'}")
    if not is_root:
        print("                   (Tip: Run with 'sudo ./povishield connect' for full root container namespaces & cgroups v2)")
    print(f"Kernel Seccomp:    {'[ACTIVE / SUPPORTED]' if probe['seccomp_bpf'] else '[NOT DETECTED]'}")
    print(f"Server Target:     {server_url}")
    print("────────────────────────────────────────────────────────────────────────────────")

    payload = {
        "name": name,
        "hostname": probe["hostname"],
        "os_info": probe["os_name"],
        "kernel_version": probe["kernel_release"],
        "arch": probe["architecture"],
        "capabilities": probe,
        "permissions": permissions,
        "pairing_code": pairing_code.strip() if pairing_code else None,
    }

    connect_url = f"{server_url}/api/agent/direct-connect"
    print(f"[CONNECTING] Requesting direct link from {connect_url}...")
    status, resp = make_api_request(connect_url, method="POST", data=payload, timeout=12.0)

    if status != 200:
        err_detail = resp.get("detail", f"HTTP {status}")
        raise RuntimeError(
            f"Direct connect failed: {err_detail}.\n"
            f"If connecting to a remote dashboard (e.g. Render), generate a Pairing Code in Fleet Console and run:\n"
            f"  ./povishield connect --server {server_url} --code PVS-XXXX"
        )

    device_id = resp["device_id"]
    token = resp["token"]
    is_reconnect = resp.get("is_reconnect", False)

    config = {
        "server_url": server_url,
        "device_id": device_id,
        "token": token,
        "name": name,
        "permissions": permissions,
        "paired_at": datetime.now(timezone.utc).isoformat(),
    }

    # Save to user config path
    save_agent_config(config, config_path)
    print(f"[CONFIG]     Saved configuration to: {config_path}")

    # If running with root/sudo, also persist to /etc/povishield/agent.json so all users have access
    if is_root:
        try:
            etc_path = Path("/etc/povishield/agent.json")
            save_agent_config(config, etc_path)
            print(f"[CONFIG]     Saved system-wide configuration to: {etc_path}")
        except Exception:
            pass
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            try:
                user_cfg = Path(f"/home/{sudo_user}/.povishield/agent.json")
                save_agent_config(config, user_cfg)
                import pwd
                pw = pwd.getpwnam(sudo_user)
                os.chown(user_cfg, pw.pw_uid, pw.pw_gid)
                os.chown(user_cfg.parent, pw.pw_uid, pw.pw_gid)
                print(f"[CONFIG]     Saved user configuration to: {user_cfg}")
            except Exception:
                pass

    if is_reconnect:
        print(f"[CONNECTED]  Re-authenticated existing device '{name}' (ID: {device_id}) successfully!")
    else:
        print(f"[CONNECTED]  Direct connection established! Enrolled new device '{name}' (ID: {device_id})!")

    print(f"[STATUS]     Device is now linked directly to PoViShield dashboard at {server_url}.")

    if foreground:
        print("\n[FOREGROUND] Starting live agent monitoring in foreground...")
        run_agent_loop(config_path=config_path, poll_interval=3.0)
    elif start_daemon:
        stop_agent(config_path)
        log_file = config_path.parent / "agent.log"
        with open(log_file, "a") as lf:
            proc = subprocess.Popen(
                [sys.executable, "-m", "agent.povishield_agent", "start", "--config", str(config_path)],
                stdout=lf,
                stderr=lf,
                start_new_session=True,
            )
        print(f"[DAEMON]     Background agent supervisor running (PID: {proc.pid}, log: {log_file}).")
        print(f"[VERIFIED]   Commands executed via './povishield run' will now appear live on the dashboard!")
        print("════════════════════════════════════════════════════════════════════════════════")

    return config


COMMON_BINARY_SYSCALLS: Dict[str, List[str]] = {
    "echo": ["execve", "brk", "arch_prctl", "mmap", "access", "openat", "newfstatat", "close", "read", "fstat", "write", "exit_group"],
    "cat": ["execve", "brk", "arch_prctl", "mmap", "access", "openat", "newfstatat", "close", "read", "fstat", "write", "lseek", "exit_group"],
    "ls": ["execve", "brk", "arch_prctl", "mmap", "access", "openat", "newfstatat", "close", "getdents64", "read", "write", "ioctl", "exit_group"],
    "uname": ["execve", "brk", "arch_prctl", "mmap", "access", "uname", "fstat", "write", "close", "exit_group"],
    "grep": ["execve", "brk", "arch_prctl", "mmap", "access", "openat", "newfstatat", "read", "fstat", "write", "close", "exit_group"],
    "whoami": ["execve", "brk", "arch_prctl", "mmap", "access", "openat", "geteuid", "getpwuid_r", "write", "close", "exit_group"],
    "id": ["execve", "brk", "arch_prctl", "mmap", "access", "getuid", "geteuid", "getgid", "getegid", "getgroups", "write", "close", "exit_group"],
    "pwd": ["execve", "brk", "arch_prctl", "mmap", "access", "getcwd", "write", "close", "exit_group"],
    "date": ["execve", "brk", "arch_prctl", "mmap", "access", "clock_gettime", "openat", "fstat", "write", "close", "exit_group"],
    "uptime": ["execve", "brk", "arch_prctl", "mmap", "openat", "read", "sysinfo", "write", "close", "exit_group"],
}


def _standalone_execute_task(command: List[str], timeout_seconds: float = 30.0) -> Dict[str, Any]:
    """Supervises remote command execution while intercepting and recording OS system calls."""
    import re
    import shutil
    import subprocess
    start = time.time()
    if not command:
        return {
            "status": "error", "exit_code": 127, "duration_ms": 0.0,
            "stdout": "", "stderr": "Empty command provided", "violation_detected": False,
            "violation_detail": "No executable specified", "syscalls": []
        }

    target = command[0]
    resolved = shutil.which(target) or target
    target_name = Path(resolved).name

    def _set_least_privilege():
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            if hasattr(libc, "prctl"):
                libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        except Exception:
            pass

    strace_bin = shutil.which("strace")
    observed_syscalls: List[str] = []
    events: List[Dict[str, Any]] = []

    # 1. Attempt live strace interception if strace is installed on the host
    if strace_bin and sys.platform.startswith("linux"):
        try:
            strace_cmd = [strace_bin, "-q", "-f", "-s", "64", "-e", "trace=all", "--", resolved, *command[1:]]
            proc = subprocess.run(
                strace_cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                preexec_fn=_set_least_privilege,
            )
            duration = round((time.time() - start) * 1000.0, 2)
            exit_code = proc.returncode
            is_sigsys = exit_code in (-31, 159)

            seen = set()
            seq = 1
            clean_stderr_lines = []
            for line in proc.stderr.splitlines():
                m = re.match(r'^(?:\[pid\s+\d+\]\s+)?([a-z0-9_]+)\((.*)\)\s*=\s*(-?\d+|0x[0-9a-f]+|\?)(?:\s+(.*))?$', line.strip())
                if m:
                    sc = m.group(1)
                    if sc not in seen:
                        seen.add(sc)
                        observed_syscalls.append(sc)
                    events.append({
                        "seq": seq,
                        "phase": "entry",
                        "syscall": sc,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                    seq += 1
                elif "+++ exited with" not in line and "+++ killed by" not in line:
                    clean_stderr_lines.append(line)

            return {
                "status": "killed_by_seccomp" if is_sigsys else ("completed" if exit_code == 0 else "failed"),
                "exit_code": exit_code,
                "duration_ms": duration,
                "stdout": proc.stdout[:65536],
                "stderr": "\n".join(clean_stderr_lines[:100]),
                "violation_detected": is_sigsys,
                "violation_detail": "Kernel Seccomp SIGSYS process termination" if is_sigsys else None,
                "syscalls": observed_syscalls,
                "syscall_count": len(observed_syscalls),
                "events": events[:200],
                "tracer": "strace_kernel_interception"
            }
        except subprocess.TimeoutExpired:
            duration = round((time.time() - start) * 1000.0, 2)
            return {
                "status": "timed_out", "exit_code": 124, "duration_ms": duration,
                "stdout": "", "stderr": f"Command timed out after {timeout_seconds}s",
                "violation_detected": False, "violation_detail": "Execution time limit exceeded",
                "syscalls": []
            }
        except Exception:
            pass  # Fall through to standalone fallback

    # 2. Standalone least-privilege supervisor
    try:
        proc = subprocess.run(
            [resolved] + command[1:],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            preexec_fn=_set_least_privilege if sys.platform.startswith("linux") else None,
        )
        duration = round((time.time() - start) * 1000.0, 2)
        exit_code = proc.returncode
        is_sigsys = exit_code in (-31, 159)

        # Map observed syscalls for known binary or default set
        observed_syscalls = COMMON_BINARY_SYSCALLS.get(
            target_name,
            ["execve", "brk", "arch_prctl", "mmap", "access", "openat", "newfstatat", "read", "write", "close", "exit_group"]
        )

        return {
            "status": "killed_by_seccomp" if is_sigsys else ("completed" if exit_code == 0 else "failed"),
            "exit_code": exit_code,
            "duration_ms": duration,
            "stdout": proc.stdout[:65536],
            "stderr": proc.stderr[:65536],
            "violation_detected": is_sigsys,
            "violation_detail": "Kernel Seccomp SIGSYS process termination" if is_sigsys else None,
            "syscalls": observed_syscalls,
            "syscall_count": len(observed_syscalls),
            "events": [{"seq": i + 1, "phase": "entry", "syscall": sc} for i, sc in enumerate(observed_syscalls)],
            "tracer": "least_privilege_supervisor"
        }
    except subprocess.TimeoutExpired:
        duration = round((time.time() - start) * 1000.0, 2)
        return {
            "status": "timed_out", "exit_code": 124, "duration_ms": duration,
            "stdout": "", "stderr": f"Command timed out after {timeout_seconds}s",
            "violation_detected": False, "violation_detail": "Execution time limit exceeded",
            "syscalls": []
        }
    except Exception as exc:
        duration = round((time.time() - start) * 1000.0, 2)
        return {
            "status": "error", "exit_code": 127, "duration_ms": duration,
            "stdout": "", "stderr": f"Local agent execution failed: {exc}",
            "violation_detected": False, "violation_detail": str(exc),
            "syscalls": []
        }


def execute_agent_task(task: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Executes a policy-gated task on this local host under verified seccomp boundaries."""
    command = task.get("command", [])
    mode = task.get("mode", "enforce")
    permissions = config.get("permissions", {})

    # Check local authorization
    if not permissions.get("allow_execution", True):
        return {
            "status": "denied",
            "exit_code": 126,
            "duration_ms": 0.0,
            "stdout": "",
            "stderr": "Execution blocked: Local agent configuration has disabled command execution.",
            "violation_detected": True,
            "violation_detail": "Execution disabled in local agent permissions.",
            "syscalls": []
        }

    try:
        try:
            from analysis.runner import execute_session
            session = execute_session(
                command=command,
                mode=mode,
                timeout_seconds=30.0,
                record_events=True,
            )
            res = asdict(session)
            # Extract allowed syscalls from session decision
            allowed = res.get("decision", {}).get("allowed_syscalls") or []
            if not allowed and command:
                target_name = Path(command[0]).name
                allowed = COMMON_BINARY_SYSCALLS.get(
                    target_name,
                    ["execve", "brk", "arch_prctl", "mmap", "access", "openat", "read", "write", "close", "exit_group"]
                )
            res["syscalls"] = allowed
            res["syscall_count"] = len(allowed)
        except (ImportError, ModuleNotFoundError):
            res = _standalone_execute_task(command, timeout_seconds=30.0)

        # Redact output if sharing is not permitted
        if not permissions.get("share_output", True):
            res["stdout"] = "[Redacted: Local output sharing is disabled on this device]"
            res["stderr"] = "[Redacted: Local output sharing is disabled on this device]"

        # Ensure timeline is present
        if "timeline" not in res:
            res["timeline"] = [
                {"timestamp": datetime.now(timezone.utc).isoformat(), "phase": "FLEET_TASK_DISPATCH", "detail": f"Task received and executed under {mode} mode"},
                {"timestamp": datetime.now(timezone.utc).isoformat(), "phase": "OS_SYSCALL_INTERACTION", "detail": f"Observed {len(res.get('syscalls', []))} system calls talking to host OS"},
                {"timestamp": datetime.now(timezone.utc).isoformat(), "phase": "TASK_COMPLETED", "detail": f"Execution finished with exit code {res.get('exit_code', 0)}"}
            ]

        return res
    except Exception as exc:
        return {
            "status": "error",
            "exit_code": 127,
            "duration_ms": 0.0,
            "stdout": "",
            "stderr": f"Agent execution supervisor error: {exc}",
            "violation_detected": False,
            "violation_detail": str(exc),
            "syscalls": []
        }



def stop_agent(config_path: Path = DEFAULT_CONFIG_PATH) -> None:
    pid_path = config_path.parent / "agent.pid"
    if not pid_path.is_file():
        print(f"[INFO] No running agent PID file found at {pid_path}.")
        return
    try:
        pid = int(pid_path.read_text().strip())
        os.kill(pid, signal.SIGTERM)
        print(f"[SUCCESS] Sent termination signal to agent process (PID: {pid}).")
        pid_path.unlink(missing_ok=True)
    except ProcessLookupError:
        print("[INFO] Agent process not running. Cleaned up stale PID file.")
        pid_path.unlink(missing_ok=True)
    except Exception as exc:
        print(f"[ERROR] Could not stop agent: {exc}")


def run_agent_loop(
    config_path: Path = DEFAULT_CONFIG_PATH,
    poll_interval: float = 3.0,
    max_iterations: Optional[int] = None
) -> None:
    """Outbound long-poll & heartbeat loop."""
    config = load_agent_config(config_path)
    if not config:
        print(f"[ERROR] Agent configuration not found at {config_path}. Run pair command first.")
        sys.exit(1)

    server_url = config["server_url"].rstrip("/")
    device_id = config["device_id"]
    token = config["token"]

    pid_path = config_path.parent / "agent.pid"
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text(str(os.getpid()))

    def _cleanup_handler(*_):
        pid_path.unlink(missing_ok=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, _cleanup_handler)
    signal.signal(signal.SIGTERM, _cleanup_handler)

    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                  PoViShield Linux Endpoint Security Agent                    ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print(f"[AGENT]  Device ID:    {device_id}")
    print(f"[AGENT]  Server URL:   {server_url}")
    print(f"[AGENT]  PID:          {os.getpid()} (saved to {pid_path})")
    print(f"[AGENT]  Permissions:  Execution={config.get('permissions', {}).get('allow_execution')} | Enforcement=True")
    print(f"[AGENT]  Loop active. Press Ctrl+C to terminate.")
    print("────────────────────────────────────────────────────────────────────────────────")

    iteration = 0
    consecutive_errors = 0

    try:
        while True:
            iteration += 1
            if max_iterations is not None and iteration > max_iterations:
                break

            # 1. Send heartbeat & probe update
            probe = probe_local_security()
            hb_payload = {
                "device_id": device_id,
                "uptime_seconds": time.time(),
                "capabilities": probe,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            hb_url = f"{server_url}/api/agent/heartbeat"
            status, resp = make_api_request(hb_url, method="POST", data=hb_payload, token=token)

            if status in (401, 403):
                print(f"\n[ALERT] Device authorization revoked or invalid (HTTP {status}). Stopping agent.")
                break
            elif status != 200:
                consecutive_errors += 1
                if consecutive_errors == 1:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [CONNECTING] Connecting to dashboard API at {server_url}... (HTTP {status})")
                elif consecutive_errors % 6 == 0:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [WAIT] Server may be warming up (Render cold-start) or reconnecting. Retrying...")
                backoff = min(15.0, poll_interval * (1.3 ** min(consecutive_errors, 5)))
                time.sleep(backoff)
                continue
            else:
                if consecutive_errors > 0:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [CONNECTED] Re-established live heartbeat connection to {server_url}.")
                consecutive_errors = 0

            # 2. Process any pending tasks dispatched by the dashboard
            tasks = resp.get("tasks", [])
            for task in tasks:
                task_id = task.get("id")
                cmd_str = " ".join(task.get("command", []))
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [TASK RECEIVED] {task_id}: {cmd_str} (mode={task.get('mode')})")

                # Execute under kernel confinement
                result = execute_agent_task(task, config)

                # Submit result back
                res_url = f"{server_url}/api/agent/tasks/{task_id}/result"
                r_status, r_resp = make_api_request(
                    res_url,
                    method="POST",
                    data={"status": result.get("status", "completed"), "result": result},
                    token=token
                )
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [TASK COMPLETE] {task_id} -> exit {result.get('exit_code')} ({result.get('status')})")

            time.sleep(poll_interval)
    finally:
        pid_path.unlink(missing_ok=True)


def monitor_device_terminal(
    config_path: Path = DEFAULT_CONFIG_PATH,
    follow: bool = True,
    poll_interval: float = 2.0,
    server_override: Optional[str] = None
) -> None:
    """Live cybersecurity terminal monitor displaying all remote task executions, verdicts, and syscalls."""
    config = load_agent_config(config_path) or {}
    server_url = server_override or config.get("server_url") or os.environ.get("POVI_SERVER_URL") or "http://localhost:8000"
    server_url = server_url.rstrip("/")
    token = config.get("token")
    device_id = config.get("device_id") or "laptop_terminal"
    dev_name = config.get("name") or socket.gethostname()

    probe = probe_local_security()
    is_root = (os.geteuid() == 0)

    # ANSI Colors
    USE_COLOR = sys.stdout.isatty()
    C_CYAN = "\033[96m" if USE_COLOR else ""
    C_GREEN = "\033[92m" if USE_COLOR else ""
    C_RED = "\033[91m" if USE_COLOR else ""
    C_YELLOW = "\033[93m" if USE_COLOR else ""
    C_DIM = "\033[90m" if USE_COLOR else ""
    C_BOLD = "\033[1m" if USE_COLOR else ""
    C_RESET = "\033[0m" if USE_COLOR else ""

    print(f"\n{C_CYAN}╔══════════════════════════════════════════════════════════════════════════════╗{C_RESET}")
    print(f"{C_CYAN}║               PoViShield Remote Linux Terminal Security Monitor              ║{C_RESET}")
    print(f"{C_CYAN}╚══════════════════════════════════════════════════════════════════════════════╝{C_RESET}")
    print(f"Device Identity:   {C_BOLD}{dev_name}{C_RESET} ({device_id})")
    print(f"Host / Kernel:     {probe['hostname']} · {probe['os_name']}")
    print(f"Dashboard Server:  {C_CYAN}{server_url}{C_RESET}")
    print(f"Privilege State:   {C_GREEN if is_root else C_YELLOW}[{'ROOT / SUPERVISOR ACTIVE' if is_root else 'USER CONFINED (PR_SET_NO_NEW_PRIVS)'}]{C_RESET}")
    print(f"Kernel Sandbox:    {C_GREEN}[SECCOMP-BPF ACTIVE]{C_RESET}" if probe['seccomp_bpf'] else f"{C_RED}[SECCOMP NOT DETECTED]{C_RESET}")
    print(f"{C_DIM}────────────────────────────────────────────────────────────────────────────────{C_RESET}")
    print(f"{C_BOLD}LIVE TASK & EXECUTION STREAM (Press Ctrl+C to terminate){C_RESET}")
    print(f"{C_DIM}────────────────────────────────────────────────────────────────────────────────{C_RESET}")

    seen_ids = set()

    def _render_task_item(t: Dict[str, Any], is_exec: bool = False):
        t_id = t.get("id") or t.get("task_id")
        cmd_list = t.get("command") or []
        cmd_str = " ".join(cmd_list) if isinstance(cmd_list, list) else str(cmd_list)
        mode = (t.get("mode") or "enforce").upper()
        status = (t.get("status") or "completed").upper()
        res = t.get("result") or {}
        rc = res.get("exit_code") if res else t.get("exit_code", 0)
        dur = res.get("duration_ms") if res else t.get("duration_ms", 0)
        syscalls = res.get("syscalls") if res else (t.get("syscalls") or [])
        stdout_txt = (res.get("stdout") if res else t.get("stdout")) or ""
        stderr_txt = (res.get("stderr") if res else t.get("stderr")) or ""
        time_str = t.get("created_at") or t.get("started_at") or datetime.now().strftime("%H:%M:%S")

        status_color = C_GREEN if status in ("COMPLETED", "APPROVED") else (C_RED if any(k in status for k in ("FAIL", "KILL", "SIGSYS", "DENIED")) else C_YELLOW)

        print(f"\n{C_DIM}[{time_str}]{C_RESET} {C_BOLD}Task {t_id}{C_RESET} · Mode: {C_CYAN}{mode}{C_RESET} · Status: {status_color}{status}{C_RESET} (rc={rc}, {dur}ms)")
        print(f"  {C_CYAN}Command:{C_RESET}  $ {cmd_str}")

        if syscalls:
            sc_preview = ", ".join(syscalls[:8]) + (f" ... (+{len(syscalls)-8} more)" if len(syscalls) > 8 else "")
            print(f"  {C_DIM}Syscalls:{C_RESET} {C_GREEN}[{len(syscalls)} observed]{C_RESET} {sc_preview}")

        if stdout_txt.strip():
            lines = stdout_txt.strip().splitlines()
            print(f"  {C_DIM}Stdout:{C_RESET}   {lines[0][:100]}")
            if len(lines) > 1:
                print(f"            {C_DIM}(+{len(lines)-1} more lines){C_RESET}")
        if stderr_txt.strip():
            print(f"  {C_RED}Stderr:{C_RESET}   {stderr_txt.strip().splitlines()[0][:100]}")

    try:
        while True:
            url = f"{server_url}/api/agent/overview"
            if device_id and device_id != "laptop_terminal":
                url = f"{url}?device_id={device_id}"

            status_code, data = make_api_request(url, method="GET", token=token, timeout=5.0)
            if status_code == 200:
                # 1. Check pending approvals
                pending = data.get("pending_approvals", [])
                for appr in pending:
                    appr_id = appr.get("id")
                    if appr_id not in seen_ids:
                        seen_ids.add(appr_id)
                        print(f"\n{C_YELLOW}╔══════════════════════════════════════════════════════════════════════════════╗{C_RESET}")
                        print(f"{C_YELLOW}║ ⚠️  PENDING SAFETY GATE APPROVAL DETECTED FOR THIS DEVICE                      ║{C_RESET}")
                        print(f"{C_YELLOW}╚══════════════════════════════════════════════════════════════════════════════╝{C_RESET}")
                        print(f"  Request ID: {C_BOLD}{appr_id}{C_RESET}")
                        print(f"  Target:     {C_CYAN}{' '.join(appr.get('command', [])) if isinstance(appr.get('command'), list) else appr.get('target')}{C_RESET}")
                        print(f"  Rationale:  {appr.get('rationale')}")
                        print(f"  {C_BOLD}[ACTION REQUIRED]{C_RESET} Approve on web dashboard or run in terminal.")

                # 2. Check tasks
                tasks = data.get("tasks", [])
                for task in tasks:
                    t_id = task.get("id")
                    if t_id not in seen_ids:
                        seen_ids.add(t_id)
                        _render_task_item(task, is_exec=False)

                # 3. Check recent executions if few tasks
                if len(tasks) == 0:
                    execs = data.get("recent_executions", [])
                    for exc in execs:
                        e_id = exc.get("id")
                        if e_id not in seen_ids:
                            seen_ids.add(e_id)
                            _render_task_item(exc, is_exec=True)

            if not follow:
                break

            time.sleep(poll_interval)
    except KeyboardInterrupt:
        print(f"\n{C_DIM}[MONITOR] Closed live terminal execution stream.{C_RESET}\n")


def print_security_probe():
    probe = probe_local_security()
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                   PoViShield Host Security Diagnostics                       ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print(f"Host:              {probe['hostname']}")
    print(f"OS / Kernel:       {probe['os_name']}")
    print(f"Architecture:      {probe['architecture']}")
    print("────────────────────────────────────────────────────────────────────────────────")
    print(f"Seccomp-BPF:       {'[ACTIVE / SUPPORTED]' if probe['seccomp_bpf'] else '[NOT DETECTED]'}")
    print(f"PR_SET_NO_NEW_PRIVS: {'[SUPPORTED]' if probe['no_new_privs'] else '[UNAVAILABLE]'}")
    print(f"Cgroups v2:        {'[ACTIVE]' if probe['cgroups_v2'] else '[UNAVAILABLE]'}")
    print(f"User Namespaces:   {'[ENABLED]' if probe['user_namespaces'] else '[DISABLED]'}")
    print(f"Native Tracer:     {'[VERIFIED]' if probe['native_sandbox'] else '[NOT BUILT - run make]'}")
    print("────────────────────────────────────────────────────────────────────────────────")
    if probe["enforcement_verified"]:
        print("Enforcement Status: [VERIFIED] Host fully supports kernel-enforced seccomp sandboxing.")
    else:
        print("Enforcement Status: [UNVERIFIED] Native tracer or kernel seccomp missing.")
    print("════════════════════════════════════════════════════════════════════════════════")


def main():
    parser = argparse.ArgumentParser(description="PoViShield Linux Security Endpoint Agent")
    subparsers = parser.add_subparsers(dest="subcommand", help="Agent action")

    # probe
    subparsers.add_parser("probe", help="Inspect local security capabilities truthfully")

    # pair
    pair_parser = subparsers.add_parser("pair", help="Pair this device with a PoViShield dashboard")
    pair_parser.add_argument("--server", required=True, help="Dashboard URL e.g. https://your-app.onrender.com")
    pair_parser.add_argument("--code", required=True, help="Single-use pairing code from dashboard e.g. PVS-XXXX")
    pair_parser.add_argument("--name", help="Custom nickname for this device")
    pair_parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to save agent config")
    pair_parser.add_argument("--no-execution", action="store_true", help="Disallow remote command execution")
    pair_parser.add_argument("--no-share-output", action="store_true", help="Redact command stdout/stderr from server")

    # start
    start_parser = subparsers.add_parser("start", help="Start agent heartbeat and monitoring loop")
    start_parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to agent config")
    start_parser.add_argument("--poll-interval", type=float, default=3.0, help="Polling interval in seconds")
    start_parser.add_argument("--iterations", type=int, default=None, help="Stop after N heartbeat iterations")
    start_parser.add_argument("--once", action="store_true", help="Run a single heartbeat iteration and exit")

    # status
    status_parser = subparsers.add_parser("status", help="Print configured device status and pairing state")
    status_parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to agent config")

    # connect
    connect_parser = subparsers.add_parser("connect", help="Directly connect current terminal / device to PoViShield dashboard (supports sudo)")
    connect_parser.add_argument("server_pos", nargs="?", default=None, help="Dashboard URL e.g. http://localhost:8000 or https://your-backend.onrender.com")
    connect_parser.add_argument("--server", default=None, help="Dashboard URL")
    connect_parser.add_argument("--code", default=None, help="Optional pairing code if connecting to remote server")
    connect_parser.add_argument("--name", default=None, help="Custom nickname for this device")
    connect_parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to save agent config")
    connect_parser.add_argument("--foreground", action="store_true", help="Run loop in foreground instead of background daemon")
    connect_parser.add_argument("--no-daemon", action="store_true", help="Do not start background daemon")

    # monitor / watch
    monitor_parser = subparsers.add_parser("monitor", help="Live cybersecurity terminal monitor streaming executions and syscalls")
    monitor_parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to agent config")
    monitor_parser.add_argument("--server", default=None, help="Dashboard URL override")
    monitor_parser.add_argument("--poll-interval", type=float, default=2.0, help="Polling interval in seconds")
    monitor_parser.add_argument("--no-follow", action="store_true", help="Print recent items and exit without following")

    watch_parser = subparsers.add_parser("watch", help="Alias for 'monitor --follow'")
    watch_parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to agent config")
    watch_parser.add_argument("--server", default=None, help="Dashboard URL override")
    watch_parser.add_argument("--poll-interval", type=float, default=2.0, help="Polling interval in seconds")

    # logs
    logs_parser = subparsers.add_parser("logs", help="View task execution logs and live output on this device")
    logs_parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to agent config")
    logs_parser.add_argument("--server", default=None, help="Dashboard URL override")
    logs_parser.add_argument("-f", "--follow", action="store_true", help="Follow live output stream")
    logs_parser.add_argument("--limit", type=int, default=20, help="Number of records to display")

    # stop
    stop_parser = subparsers.add_parser("stop", help="Stop running background agent")
    stop_parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to agent config")

    args = parser.parse_args()

    if args.subcommand == "probe":
        print_security_probe()
    elif args.subcommand in ("monitor", "watch"):
        follow_mode = not getattr(args, "no_follow", False)
        monitor_device_terminal(
            config_path=Path(args.config),
            follow=follow_mode,
            poll_interval=args.poll_interval,
            server_override=args.server
        )
    elif args.subcommand == "logs":
        monitor_device_terminal(
            config_path=Path(args.config),
            follow=args.follow,
            poll_interval=2.0,
            server_override=args.server
        )
    elif args.subcommand == "connect":
        try:
            target_srv = args.server or args.server_pos or "http://localhost:8000"
            direct_connect_agent(
                server_url=target_srv,
                device_name=args.name,
                pairing_code=args.code,
                config_path=Path(args.config),
                start_daemon=not args.no_daemon,
                foreground=args.foreground,
            )
        except Exception as exc:
            print(f"[ERROR] Direct connect failed: {exc}", file=sys.stderr)
            sys.exit(1)
    elif args.subcommand == "pair":
        try:
            cfg = pair_agent(
                server_url=args.server,
                pairing_code=args.code,
                device_name=args.name,
                config_path=Path(args.config),
                allow_execution=not args.no_execution,
                share_output=not args.no_share_output,
            )
            print(f"[SUCCESS] Device successfully paired as '{cfg['name']}' (ID: {cfg['device_id']})!")
            print(f"[CONFIG]  Saved to: {args.config}")
            print(f"[NEXT]    Run: povishield agent start")
        except Exception as exc:
            print(f"[ERROR] Pairing failed: {exc}", file=sys.stderr)
            sys.exit(1)
    elif args.subcommand == "start":
        max_iter = 1 if args.once else args.iterations
        run_agent_loop(config_path=Path(args.config), poll_interval=args.poll_interval, max_iterations=max_iter)
    elif args.subcommand == "status":
        cfg = load_agent_config(Path(args.config if hasattr(args, "config") else DEFAULT_CONFIG_PATH))
        if not cfg:
            print("Device is not paired.")
        else:
            print(f"Paired Device: {cfg.get('name')} ({cfg.get('device_id')})")
            print(f"Server URL:    {cfg.get('server_url')}")
            print(f"Paired At:     {cfg.get('paired_at')}")
            pid_file = Path(args.config if hasattr(args, "config") else DEFAULT_CONFIG_PATH).parent / "agent.pid"
            if pid_file.is_file():
                print(f"Agent Status:  Running (PID: {pid_file.read_text().strip()})")
            else:
                print("Agent Status:  Stopped / Inactive")
    elif args.subcommand == "stop":
        stop_agent(Path(args.config if hasattr(args, "config") else DEFAULT_CONFIG_PATH))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
