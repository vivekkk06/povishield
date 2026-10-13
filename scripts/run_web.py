#!/usr/bin/env python3
"""Unified supervisor to launch both PoViShield FastAPI backend and Vite frontend console."""
import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT / "frontend"


def is_api_healthy(url: str = "http://127.0.0.1:8000/api/health") -> bool:
    try:
        with urllib.request.urlopen(url, timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False


def get_python_exe() -> str:
    for candidate in [ROOT / ".venv" / "bin" / "python", ROOT / "api" / ".venv" / "bin" / "python"]:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return sys.executable


def main():
    procs = []

    def cleanup(signum=None, frame=None):
        print("\n[POVISHIELD] Shutting down web platform...")
        for p in procs:
            if p.poll() is None:
                try:
                    p.terminate()
                    p.wait(timeout=2)
                except Exception:
                    p.kill()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    py_exe = get_python_exe()

    # 1. Start or verify FastAPI backend on port 8000
    if is_api_healthy():
        print("[POVISHIELD] FastAPI backend already active on http://127.0.0.1:8000")
    else:
        print("[POVISHIELD] Starting FastAPI backend on http://127.0.0.1:8000...")
        api_proc = subprocess.Popen(
            [py_exe, "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1", "--port", "8000", "--reload"],
            cwd=str(ROOT),
        )
        procs.append(api_proc)

        # Wait for API to be ready
        for _ in range(30):
            if is_api_healthy():
                break
            time.sleep(0.3)
        if not is_api_healthy():
            print("[WARN] API startup taking longer than expected, continuing...")

    # 2. Start Frontend Vite server on port 5175
    print("[POVISHIELD] Starting Frontend Vite console on http://localhost:5175...")
    fe_proc = subprocess.Popen(
        ["npm", "run", "dev"],
        cwd=str(FRONTEND_DIR),
    )
    procs.append(fe_proc)

    print("\n" + "=" * 74)
    print("  PoViShield Security Operations Platform Running")
    print("=" * 74)
    print("  -> Security Console UI: http://localhost:5175 (or http://127.0.0.1:5175)")
    print("  -> REST API:            http://127.0.0.1:8000/api")
    print("  -> Interactive Docs:    http://127.0.0.1:8000/docs")
    print("=" * 74)
    print("  Press Ctrl+C to terminate both servers.\n")

    try:
        while True:
            for p in procs:
                if p.poll() is not None:
                    print(f"[POVISHIELD] Process exited with code {p.returncode}")
                    cleanup()
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()


if __name__ == "__main__":
    main()
