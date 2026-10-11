"""Shared helpers for the test suite."""
import os, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analysis.common import BIN  # noqa: E402

IS_ROOT = os.geteuid() == 0
_probe = None


def build_probe():
    """Static probe binary (so it runs inside a minimal rootfs). None if it cannot be built."""
    global _probe
    if _probe is None:
        out = Path(tempfile.mkdtemp(prefix="ps-probe-")) / "probe"
        r = subprocess.run(["gcc", "-static", "-O1", "-Wall", str(ROOT / "tests" / "rootfs" / "probe.c"), "-o", str(out)],
                           capture_output=True)
        _probe = out if r.returncode == 0 else False
    return _probe or None


def run(args, timeout=60, **kw):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=timeout, **kw)


def run_help_text():
    """Text of `povishield run --help` (used to detect optional features such as --keep-caps)."""
    try:
        r = run([BIN, "run", "--help"], timeout=10)
        return r.stdout + r.stderr
    except Exception:
        return ""


def cgroup_v2_usable():
    cg = Path("/sys/fs/cgroup")
    if not (cg / "cgroup.controllers").exists() or not IS_ROOT:
        return False
    d = cg / f"povishield-selftest-{os.getpid()}"
    try:
        d.mkdir()
        d.rmdir()
        return True
    except OSError:
        return False


def mountinfo_lines():
    return Path("/proc/self/mountinfo").read_text().splitlines()


def leftover_cgroups():
    return sorted(p.name for p in Path("/sys/fs/cgroup").glob("povishield-*") if "selftest" not in p.name)
