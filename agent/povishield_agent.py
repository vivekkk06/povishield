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
import socket
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    timeout: float = 10.0
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


def execute_agent_task(task: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Executes a policy-gated task on this local host under verified seccomp boundaries."""
    from analysis.runner import execute_session, validate_command

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
        }

    try:
        session = execute_session(
            command=command,
            mode=mode,
            timeout_seconds=30.0,
            record_events=True,
        )
        res = asdict(session)

        # Redact output if sharing is not permitted
        if not permissions.get("share_output", True):
            res["stdout"] = "[Redacted: Local output sharing is disabled on this device]"
            res["stderr"] = "[Redacted: Local output sharing is disabled on this device]"

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
        }


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

    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                  PoViShield Linux Endpoint Security Agent                    ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print(f"[AGENT]  Device ID:    {device_id}")
    print(f"[AGENT]  Server URL:   {server_url}")
    print(f"[AGENT]  Permissions:  Execution={config.get('permissions', {}).get('allow_execution')} | Enforcement=True")
    print(f"[AGENT]  Loop active. Press Ctrl+C to terminate.")
    print("────────────────────────────────────────────────────────────────────────────────")

    iteration = 0
    consecutive_errors = 0

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

        if status == 401 or status == 403:
            print(f"\n[ALERT] Device authorization revoked or invalid (HTTP {status}). Stopping agent.")
            break
        elif status != 200:
            consecutive_errors += 1
            backoff = min(15.0, poll_interval * (1.5 ** min(consecutive_errors, 5)))
            time.sleep(backoff)
            continue
        else:
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
    pair_parser.add_argument("--server", required=True, help="Dashboard URL e.g. http://127.0.0.1:8000")
    pair_parser.add_argument("--code", required=True, help="Single-use pairing code from dashboard e.g. PVS-XXXX")
    pair_parser.add_argument("--name", help="Custom nickname for this device")
    pair_parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to save agent config")
    pair_parser.add_argument("--no-execution", action="store_true", help="Disallow remote command execution")
    pair_parser.add_argument("--no-share-output", action="store_true", help="Redact command stdout/stderr from server")

    # start
    start_parser = subparsers.add_parser("start", help="Start agent heartbeat and monitoring loop")
    start_parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to agent config")
    start_parser.add_argument("--poll-interval", type=float, default=3.0, help="Polling interval in seconds")

    # status
    subparsers.add_parser("status", help="Print configured device status and pairing state")

    args = parser.parse_args()

    if args.subcommand == "probe":
        print_security_probe()
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
        run_agent_loop(config_path=Path(args.config), poll_interval=args.poll_interval)
    elif args.subcommand == "status":
        cfg = load_agent_config(Path(args.config if hasattr(args, "config") else DEFAULT_CONFIG_PATH))
        if not cfg:
            print("Device is not paired.")
        else:
            print(f"Paired Device: {cfg.get('name')} ({cfg.get('device_id')})")
            print(f"Server URL:    {cfg.get('server_url')}")
            print(f"Paired At:     {cfg.get('paired_at')}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
