"""Shared helpers: profile I/O and the native syscall count (from libseccomp, not hardcoded)."""
import json, platform, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "build" / "povishield"


def load_profile(path):
    with open(path) as f:
        return set(json.load(f)["syscalls"])


def save_profile(path, syscalls, command="merged"):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump({"schema": 1, "command": command, "arch": platform.machine(),
                   "count": len(syscalls), "syscalls": sorted(syscalls)}, f, indent=2)


def total_syscalls():
    out = subprocess.run([str(BIN), "info", "total-syscalls"], capture_output=True, text=True, check=True)
    return int(out.stdout.strip())
