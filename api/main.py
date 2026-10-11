import json
from pathlib import Path
from typing import Any
import ipaddress
import os
import signal
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from fastapi.middleware.cors import CORSMiddleware

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
EVENTS_FILE = RESULTS / "syscall-events.jsonl"

# Local, bounded research sessions. This observes behavior; it does not sandbox it.
MONITOR_MAX_SECONDS = 30
MONITOR_MAX_EVENT_BYTES = 10 * 1024 * 1024
MONITOR_READ_MAX_BYTES = 256 * 1024
MONITOR_LOCK = threading.RLock()
MONITOR_SESSIONS: dict[str, dict[str, Any]] = {}
DENIED_EXECUTABLES = {
    "sh", "bash", "dash", "zsh", "fish", "csh", "tcsh",
    "python", "python2", "python3", "python3.14", "pypy", "perl",
    "ruby", "node", "deno", "php", "lua", "busybox",
    "sudo", "su", "pkexec", "doas", "rm", "dd", "mkfs", "fdisk",
    "parted", "mount", "umount", "reboot", "shutdown", "poweroff",
    "useradd", "userdel", "usermod", "passwd", "chown", "chmod",
}

class MonitorStartRequest(BaseModel):
    command: list[str] = Field(min_length=1, max_length=16)
    timeout_seconds: int = Field(default=MONITOR_MAX_SECONDS, ge=1, le=MONITOR_MAX_SECONDS)

# --- who is really calling? ------------------------------------------------------------------------------------
# A web page in your browser also connects from 127.0.0.1, so the TCP peer proves nothing about the caller.
# Host is checked against DNS rebinding, Origin against cross-site requests. Keep TRUSTED_ORIGINS in sync with
# the CORS allow_origins list below; override with POVISHIELD_ALLOWED_ORIGINS="http://a:1,http://b:2".
TRUSTED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}
TRUSTED_ORIGINS = {o.strip() for o in os.environ.get(
    "POVISHIELD_ALLOWED_ORIGINS",
    "http://127.0.0.1:5175,http://localhost:5175,http://127.0.0.1:4173,http://localhost:4173").split(",") if o.strip()}

# Only these may be traced. Deliberately small and read-only: no env/find/xargs/awk/sed/tar/git/curl and no
# `sort` (--compress-program runs an arbitrary program). Add absolute paths with POVISHIELD_MONITOR_ALLOW=/a:/b
SAFE_EXECUTABLE_NAMES = (
    "ls", "cat", "echo", "printf", "true", "false", "sleep", "date", "uname", "id", "whoami", "pwd", "stat", "df", "du",
    "wc", "head", "tail", "grep", "cut", "tr", "uniq", "nl", "seq", "basename", "dirname", "sha256sum", "md5sum", "base64",
)


def _allowed_executables() -> set[str]:
    import shutil
    found = {str(Path(x).resolve()) for x in os.environ.get("POVISHIELD_MONITOR_ALLOW", "").split(":") if x}
    for name in SAFE_EXECUTABLE_NAMES:
        path = shutil.which(name, path="/usr/local/bin:/usr/bin:/bin")
        if path:
            found.add(str(Path(path).resolve()))
    return found


ALLOWED_EXECUTABLES = _allowed_executables()
MAX_RUNNING_SESSIONS = 3


def _require_local_request(request: Request) -> None:
    def deny(detail: str):
        raise HTTPException(status_code=403, detail=detail)

    host = request.client.host if request.client else ""
    try:
        if not ipaddress.ip_address(host).is_loopback:
            deny("Live monitoring is restricted to localhost")
    except ValueError:
        deny("Live monitoring is restricted to localhost")
    hdr = request.headers.get("host", "")
    name = (hdr.split("]")[0] + "]") if hdr.startswith("[") else hdr.rsplit(":", 1)[0]
    if name not in TRUSTED_HOSTS:
        deny("Untrusted Host header")
    origin = request.headers.get("origin")
    if origin is not None and origin not in TRUSTED_ORIGINS:     # absent for curl/scripts; present for every browser POST
        deny("Untrusted Origin")


def _session_payload(session: dict[str, Any]) -> dict[str, Any]:
    running = session["status"] == "running"
    return {
        "id": session["id"], "status": session["status"], "command": session["command"],
        "started_at": session["started_at"], "ended_at": session.get("ended_at"),
        "elapsed_seconds": round(max(0.0, time.time() - session["started_epoch"]), 2) if running else session.get("elapsed_seconds", 0),
        "exit_code": session.get("exit_code"), "reason": session.get("reason"),
        "source": session["events_path"].relative_to(ROOT).as_posix(),
        "data_type": "live_session" if running else "session_trace", "live": running,
        "max_runtime_seconds": session["timeout_seconds"], "max_event_bytes": MONITOR_MAX_EVENT_BYTES,
    }

def _kill_session_process(session: dict[str, Any]) -> bool:
    """Terminate the monitor process group and confirm the tracer has exited."""
    proc = session["process"]
    pgid = proc.pid  # Popen uses start_new_session=True, so pid is the process-group ID.

    if proc.poll() is None:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                return False

    if proc.poll() is None:
        return False
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False

def _monitor_watchdog(session_id: str) -> None:
    while True:
        with MONITOR_LOCK:
            session = MONITOR_SESSIONS.get(session_id)
            if not session or session["status"] != "running": return
            proc = session["process"]
            elapsed = time.monotonic() - session["started_monotonic"]
            try: event_size = session["events_path"].stat().st_size
            except OSError: event_size = 0
            reason = None
            terminal = None
            if elapsed >= session["timeout_seconds"]: reason, terminal = "runtime_limit", "timed_out"
            # The tracer returns 75 when it stops before the next whole event
            # would exceed its byte cap. Detect this even if the file is a few
            # bytes below the cap, which is expected with whole-record writes.
            elif proc.poll() == 75: reason, terminal = "event_size_limit", "event_limit"
            elif event_size >= MONITOR_MAX_EVENT_BYTES: reason, terminal = "event_size_limit", "event_limit"
            elif proc.poll() is not None: terminal = "exited"
            if terminal:
                if terminal in {"timed_out", "event_limit"}: _kill_session_process(session)
                session["status"] = terminal
                session["reason"] = reason
                session["exit_code"] = proc.poll()
                session["ended_at"] = datetime.now(timezone.utc).isoformat()
                session["elapsed_seconds"] = round(time.monotonic() - session["started_monotonic"], 2)
                return
        time.sleep(0.2)

app = FastAPI(
    title="PoViShield API",
    description="Read-only API for sandbox evaluation and policy artifacts",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def read_json(filename: str) -> Any:
    path = RESULTS / filename

    # Only read known JSON files directly under results/
    if path.parent != RESULTS or not path.is_file():
        raise HTTPException(status_code=404, detail="Result file not found")

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        raise HTTPException(
            status_code=500,
            detail=f"Could not read {filename}",
        )


@app.get("/api/health")
def health():
    tracer = ROOT / "build" / "povishield"
    with MONITOR_LOCK:
        live_connected = any(item["status"] == "running" for item in MONITOR_SESSIONS.values())
    return {
        "status": "ok", "service": "PoViShield API", "mode": "local process monitor",
        "engine_connected": tracer.is_file() and os.access(tracer, os.X_OK),
        "live_events_connected": live_connected,
    }


@app.post("/api/monitor/sessions")
def start_monitor_session(payload: MonitorStartRequest, request: Request):
    _require_local_request(request)
    if os.geteuid() == 0:
        raise HTTPException(status_code=403, detail="Do not run the dashboard/API as root")
    if any(not isinstance(arg, str) or not arg or len(arg) > 512 for arg in payload.command):
        raise HTTPException(status_code=400, detail="command must be an argv array of short, non-empty strings")
    executable = Path(payload.command[0])
    if not executable.is_absolute():
        raise HTTPException(status_code=400, detail="Executable must be an absolute path; shell parsing is not supported")
    resolved = executable.resolve()
    if resolved.name in DENIED_EXECUTABLES:
        raise HTTPException(status_code=400, detail=f"Refusing shell/interpreter or high-risk command: {resolved.name}")
    if str(resolved) not in ALLOWED_EXECUTABLES:
        raise HTTPException(status_code=400, detail=f"{resolved.name} is not on the monitor allow-list "
                                                    f"(add an absolute path with POVISHIELD_MONITOR_ALLOW)")
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise HTTPException(status_code=400, detail="Executable does not exist or is not executable")
    tracer = ROOT / "build" / "povishield"
    if not tracer.is_file() or not os.access(tracer, os.X_OK):
        raise HTTPException(status_code=503, detail="Build the PoViShield tracer first with: make")
    with MONITOR_LOCK:
        running = sum(1 for x in MONITOR_SESSIONS.values() if x["status"] == "running")
    if running >= MAX_RUNNING_SESSIONS:
        raise HTTPException(status_code=429, detail=f"At most {MAX_RUNNING_SESSIONS} monitoring sessions may run at once")
    RESULTS.mkdir(parents=True, exist_ok=True)
    sid = uuid.uuid4().hex[:12]
    events_path, profile_path = RESULTS / f"live-{sid}-events.jsonl", RESULTS / f"live-{sid}-profile.json"
    child_env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(Path.home()), "LANG": os.environ.get("LANG", "C.UTF-8")}
    argv = [str(tracer), "learn", "-o", str(profile_path), "--events", str(events_path),
            "--max-event-bytes", str(MONITOR_MAX_EVENT_BYTES), "--", str(resolved), *payload.command[1:]]
    try:
        proc = subprocess.Popen(argv, cwd=ROOT, env=child_env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not start tracer: {exc.strerror}") from exc
    session = {
        "id": sid, "status": "running", "command": [str(resolved), *payload.command[1:]],
        "started_at": datetime.now(timezone.utc).isoformat(), "started_epoch": time.time(),
        "started_monotonic": time.monotonic(), "timeout_seconds": payload.timeout_seconds,
        "events_path": events_path, "profile_path": profile_path, "process": proc,
        "reason": None, "exit_code": None,
    }
    with MONITOR_LOCK: MONITOR_SESSIONS[sid] = session
    threading.Thread(target=_monitor_watchdog, args=(sid,), daemon=True).start()
    return _session_payload(session)


@app.get("/api/monitor/sessions/{session_id}")
def get_monitor_session(session_id: str, request: Request):
    _require_local_request(request)
    with MONITOR_LOCK:
        session = MONITOR_SESSIONS.get(session_id)
        if not session: raise HTTPException(status_code=404, detail="Monitoring session not found")
        return _session_payload(session)


@app.post("/api/monitor/sessions/{session_id}/stop")
def stop_monitor_session(session_id: str, request: Request):
    _require_local_request(request)
    with MONITOR_LOCK:
        session = MONITOR_SESSIONS.get(session_id)
        if not session: raise HTTPException(status_code=404, detail="Monitoring session not found")
        if session["status"] == "running":
            cleanup_ok = _kill_session_process(session)
            session["status"] = "stopped" if cleanup_ok else "cleanup_failed"
            session["reason"] = "user_stopped" if cleanup_ok else "process_cleanup_unconfirmed"
            session["exit_code"] = session["process"].poll()
            session["ended_at"] = datetime.now(timezone.utc).isoformat()
            session["elapsed_seconds"] = round(time.monotonic() - session["started_monotonic"], 2)
        return _session_payload(session)


@app.get("/api/monitor/sessions/{session_id}/events")
def get_monitor_session_events(session_id: str, request: Request, offset: int = 0, limit: int = 100):
    _require_local_request(request)
    if offset < 0 or limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="offset must be >= 0 and limit must be between 1 and 200")
    with MONITOR_LOCK:
        session = MONITOR_SESSIONS.get(session_id)
        if not session: raise HTTPException(status_code=404, detail="Monitoring session not found")
        event_path = session["events_path"]
    events, malformed, next_offset, bytes_read = [], 0, offset, 0
    try:
        with event_path.open("rb") as handle:
            size = event_path.stat().st_size
            if offset > size: raise HTTPException(status_code=416, detail="offset is beyond the event file")
            handle.seek(offset)
            while len(events) < limit and bytes_read < MONITOR_READ_MAX_BYTES:
                before = handle.tell()
                line = handle.readline(65536)
                if not line: break
                if not line.endswith(b"\n"):
                    handle.seek(before)
                    break
                bytes_read += len(line)
                next_offset = handle.tell()
                try:
                    item = json.loads(line.decode("utf-8"))
                    if not isinstance(item, dict) or item.get("phase") not in {"entry", "exit"}: malformed += 1; continue
                    if not isinstance(item.get("seq"), int) or not isinstance(item.get("pid"), int): malformed += 1; continue
                    if not isinstance(item.get("syscall_nr"), int) or not isinstance(item.get("syscall"), str): malformed += 1; continue
                    event = {"seq": item["seq"], "pid": item["pid"], "phase": item["phase"], "syscall_nr": item["syscall_nr"], "syscall": item["syscall"]}
                    if item["phase"] == "exit" and isinstance(item.get("return_value"), int): event["return_value"] = item["return_value"]
                    events.append(event)
                except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError): malformed += 1
    except HTTPException: raise
    except FileNotFoundError: events = []
    except OSError as exc: raise HTTPException(status_code=500, detail="Could not read session events") from exc
    with MONITOR_LOCK:
        session = MONITOR_SESSIONS.get(session_id)
        status = _session_payload(session) if session else None
    return {"session": status, "data_type": "live_session" if status and status["live"] else "session_trace",
        "live": bool(status and status["live"]), "source": event_path.relative_to(ROOT).as_posix(),
        "count": len(events), "malformed_records": malformed, "offset": offset,
        "next_offset": next_offset, "events": events}


@app.get("/api/overview")
def overview():
    data = read_json("results.json")

    return {
        "source": "results/results.json",
        "generated_at": None,
        "environment": data.get("env", {}),
        "aggregate": data.get("aggregate", {}),
        "targets": data.get("targets", []),
        "data_type": "measured_local_evaluation",
        "live_monitoring": False,
    }


@app.get("/api/experiments")
def experiments():
    data = read_json("results.json")
    escape_data = read_json("escape.json") if (RESULTS / "escape.json").is_file() else None

    report_path = RESULTS / "report.md"
    report = report_path.read_text(encoding="utf-8") if report_path.is_file() else None

    return {
        "evaluation": data,
        "escape_results": escape_data,
        "report": report,
        "source": "local generated artifacts",
    }



@app.get("/api/events/profile")
def syscall_events_profile():
    import json
    from collections import Counter
    from fastapi import HTTPException

    event_file = RESULTS / "syscall-events.jsonl"
    if not event_file.exists():
        return {"source": str(event_file.relative_to(ROOT)), "data_type": "recorded_trace",
                "live": False, "total_records": 0, "entry_records": 0,
                "unique_syscalls": 0, "malformed_records": 0, "syscalls": []}
    counts = Counter()
    numbers = {}
    total_records = entry_records = malformed_records = 0
    try:
        with event_file.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        malformed_records += 1
                        continue
                    total_records += 1
                    if event.get("phase") != "entry":
                        continue
                    number = event.get("syscall_nr")
                    name = event.get("syscall") or (f"syscall_{number}" if number is not None else "unknown")
                    counts[str(name)] += 1
                    if str(name) not in numbers and number is not None:
                        numbers[str(name)] = number
                    entry_records += 1
                except (json.JSONDecodeError, TypeError, ValueError):
                    malformed_records += 1
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not read syscall trace: {exc}") from exc
    rows = [{"syscall": name, "syscall_nr": numbers.get(name), "count": count}
            for name, count in counts.most_common()]
    return {"source": str(event_file.relative_to(ROOT)), "data_type": "recorded_trace",
            "live": False, "total_records": total_records, "entry_records": entry_records,
            "unique_syscalls": len(rows), "malformed_records": malformed_records, "syscalls": rows}


@app.get("/api/events")
def events(limit: int = 100):
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 500")

    if not EVENTS_FILE.is_file():
        raise HTTPException(status_code=404, detail="No saved syscall trace found")

    try:
        with EVENTS_FILE.open("rb") as file:
            size = file.seek(0, 2)
            file.seek(max(0, size - 1_000_000))
            lines = file.read().decode("utf-8", errors="replace").splitlines()
    except OSError:
        raise HTTPException(status_code=500, detail="Could not read syscall trace")

    parsed = []
    malformed = 0
    for line in lines:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue
        if not isinstance(item, dict):
            malformed += 1
            continue

        phase = item.get("phase")
        if phase not in {"entry", "exit"}:
            malformed += 1
            continue
        if not isinstance(item.get("seq"), int) or not isinstance(item.get("pid"), int):
            malformed += 1
            continue
        if not isinstance(item.get("syscall_nr"), int) or not isinstance(item.get("syscall"), str):
            malformed += 1
            continue

        event = {
            "seq": item["seq"],
            "pid": item["pid"],
            "phase": phase,
            "syscall_nr": item["syscall_nr"],
            "syscall": item["syscall"],
        }
        if phase == "exit" and isinstance(item.get("return_value"), int):
            event["return_value"] = item["return_value"]
        parsed.append(event)

    selected = list(reversed(parsed[-limit:]))
    return {
        "source": "results/syscall-events.jsonl",
        "data_type": "recorded_trace",
        "live": False,
        "count": len(selected),
        "total_valid_records_in_read_window": len(parsed),
        "malformed_records_in_read_window": malformed,
        "events": selected,
    }


@app.get("/api/policies")
def policies():
    items = []

    for path in sorted(RESULTS.glob("*.json")):
        if path.name in {"results.json", "escape.json"}:
            continue

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            items.append({
                "name": path.name,
                "size_bytes": path.stat().st_size,
                "data": data,
            })
        except (json.JSONDecodeError, OSError):
            items.append({
                "name": path.name,
                "error": "Could not parse policy artifact",
            })

    return {
        "items": items,
        "count": len(items),
        "note": "Artifact listing only; this endpoint does not enforce policies.",
    }
