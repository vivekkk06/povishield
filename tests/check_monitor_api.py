#!/usr/bin/env python3
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / "api/.venv/bin/python"
BASE = None
SERVER = None


def request(method, path, body=None, timeout=5):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {}
        return exc.code, payload


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print("[PASS]", message)


def main():
    global BASE, SERVER

    if os.geteuid() == 0:
        print("[FAIL] Do not run API integration tests as root.")
        return 1

    if not PYTHON.is_file():
        print("[FAIL] API virtual environment is missing:", PYTHON)
        return 1

    if not (ROOT / "build/povishield").is_file():
        print("[FAIL] Build the tracer first: make")
        return 1

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    BASE = f"http://127.0.0.1:{port}"
    log = open("/tmp/povishield-monitor-api.log", "w")
    session_id = None

    try:
        SERVER = subprocess.Popen(
            [
                str(PYTHON), "-m", "uvicorn", "api.main:app",
                "--host", "127.0.0.1", "--port", str(port),
            ],
            cwd=ROOT,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

        for _ in range(50):
            if SERVER.poll() is not None:
                raise RuntimeError("API server exited; see /tmp/povishield-monitor-api.log")
            try:
                status, health = request("GET", "/api/health", timeout=1)
                if status == 200:
                    break
            except Exception:
                time.sleep(0.2)
        else:
            raise RuntimeError("API did not start; see /tmp/povishield-monitor-api.log")

        check(health.get("engine_connected") is True, "health reports tracer available")

        status, invalid = request(
            "POST", "/api/monitor/sessions",
            {"command": ["sh", "-c", "echo unsafe"], "timeout_seconds": 3},
        )
        check(status == 400, "shell command is rejected")

        status, invalid = request(
            "POST", "/api/monitor/sessions",
            {"command": ["relative-command"], "timeout_seconds": 3},
        )
        check(status == 400, "relative executable path is rejected")

        status, invalid = request(
            "POST", "/api/monitor/sessions",
            {"command": ["/usr/bin/sleep", "3"], "timeout_seconds": 31},
        )
        check(status == 422, "timeout above the configured maximum is rejected")

        status, started = request(
            "POST", "/api/monitor/sessions",
            {"command": ["/usr/bin/sleep", "10"], "timeout_seconds": 15},
        )
        check(status == 200 and started.get("id"), "permitted process starts")
        session_id = started["id"]

        status, health = request("GET", "/api/health")
        check(status == 200 and health.get("live_events_connected") is True,
              "health reports an active monitoring session")

        time.sleep(0.5)
        encoded_id = urllib.parse.quote(session_id, safe="")
        status, page = request(
            "GET", f"/api/monitor/sessions/{encoded_id}/events?offset=0&limit=10"
        )
        check(status == 200, "session event endpoint responds")
        check(page.get("source", "").endswith("-events.jsonl"),
              "event response identifies the session trace")
        check(page.get("malformed_records") == 0,
              "event reader reports no malformed records")

        events = page.get("events", [])
        check(isinstance(events, list), "events are returned as a list")
        if events:
            item = events[0]
            check(
                isinstance(item.get("seq"), int)
                and isinstance(item.get("pid"), int)
                and item.get("phase") in ("entry", "exit")
                and isinstance(item.get("syscall"), str),
                "event has the expected fields",
            )
            next_offset = page["next_offset"]
            status, next_page = request(
                "GET",
                f"/api/monitor/sessions/{encoded_id}/events"
                f"?offset={next_offset}&limit=10",
            )
            check(status == 200, "event pagination accepts the returned byte offset")
        else:
            print("[INFO] No complete event records yet; event field check deferred.")

        status, bad_offset = request(
            "GET",
            f"/api/monitor/sessions/{encoded_id}/events?offset=-1&limit=10",
        )
        check(status == 400, "negative event offset is rejected")

        status, bad_limit = request(
            "GET",
            f"/api/monitor/sessions/{encoded_id}/events?offset=0&limit=201",
        )
        check(status == 400, "event limit above 200 is rejected")

        status, stopped = request(
            "POST", f"/api/monitor/sessions/{encoded_id}/stop"
        )
        check(status == 200 and stopped.get("status") == "stopped",
              "active session stops cleanly")

        status, final = request("GET", f"/api/monitor/sessions/{encoded_id}")
        check(status == 200 and final.get("live") is False,
              "stopped session reports non-live status")

        status, missing = request(
            "GET", "/api/monitor/sessions/nonexistent-session"
        )
        check(status == 404, "unknown session returns 404")

        print("\nMONITOR API INTEGRATION TESTS PASSED")
        return 0

    except Exception as exc:
        print(f"\n[FAIL] {exc}")
        print("API log: /tmp/povishield-monitor-api.log")
        return 1
    finally:
        if session_id and BASE:
            try:
                request(
                    "POST",
                    f"/api/monitor/sessions/{session_id}/stop",
                    timeout=2,
                )
            except Exception:
                pass
        if SERVER and SERVER.poll() is None:
            SERVER.terminate()
            try:
                SERVER.wait(timeout=3)
            except subprocess.TimeoutExpired:
                SERVER.kill()
                SERVER.wait()
        log.close()


if __name__ == "__main__":
    sys.exit(main())
