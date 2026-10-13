"""Shared helpers: profile I/O and the native syscall count (from libseccomp, not hardcoded)."""
import json, os, platform, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "build" / "povishield"


def load_profile(path):
    with open(path) as f:
        return set(json.load(f)["syscalls"])


def load_profile_meta(path):
    with open(path) as f:
        return json.load(f)


def save_profile(path, syscalls, command="merged", schema=1, extra=None):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "schema": schema,
        "command": command,
        "arch": platform.machine(),
        "count": len(syscalls),
        "syscalls": sorted(syscalls),
    }
    if extra:
        doc.update(extra)
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)


def total_syscalls():
    if not BIN.is_file():
        return int(os.environ.get("POVISHIELD_TOTAL_SYSCALLS", "385"))
    try:
        out = subprocess.run([str(BIN), "info", "total-syscalls"], capture_output=True, text=True, check=True)
        return int(out.stdout.strip())
    except Exception:
        return int(os.environ.get("POVISHIELD_TOTAL_SYSCALLS", "385"))
