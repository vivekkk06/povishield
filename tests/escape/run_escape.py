#!/usr/bin/env python3
"""Runs every escape program under 4-5 configs and prints a blocked/ESCAPED matrix.
Run as root in a throwaway VM:  sudo make escape"""
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from analysis.common import BIN, save_profile, load_profile
from analysis.merge import merge_profiles

ESC = ROOT / "build" / "escape"
RES = ROOT / "results"


def learn(cmd, out):
    subprocess.run([str(BIN), "learn", "-o", str(out), "--"] + cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return load_profile(out)


def main():
    if os.geteuid() != 0:
        print("WARNING: not root. Privileged-call tests will fail everywhere and prove nothing. Use sudo.")
    RES.mkdir(exist_ok=True)
    tmp = Path(tempfile.mkdtemp())
    # a benign profile (what a harmless program such as `ls` needs)
    benign = RES / "profiles" / "benign-for-escape.json"
    save_profile(benign, merge_profiles([learn(["ls", "-la", "/"], tmp / "a.json"),
                                         learn(["cat", "/etc/hostname"], tmp / "b.json")]))
    configs = {
        "bare":       lambda b, d: [b, d],
        "seccomp":    lambda b, d: [str(BIN), "enforce", "-p", str(benign), "--", b, d],
        "namespaces": lambda b, d: [str(BIN), "run", "--", b, d],
        "full":       lambda b, d: [str(BIN), "run", "--mem", "256", "--pids", "64", "--profile", str(benign), "--", b, d],
    }
    if shutil.which("docker"):
        configs["docker-default"] = lambda b, d: ["docker", "run", "--rm", "-v", f"{ESC}:/t:ro", "debian:stable-slim", "/t/" + Path(b).name, d]

    tests = sorted(p for p in ESC.glob("*") if p.name.startswith(("esc_", "limit_")))
    result = {}
    print(f"{'test':<14}" + "".join(f"{c:<16}" for c in configs))
    rows = {t.name: {} for t in tests}
    for cname, mk in configs.items():
        d = tempfile.mkdtemp()
        ctl = subprocess.run(mk(str(ESC / "control_ok"), d), capture_output=True, text=True)
        control_ok = ctl.returncode == 0 and "OK" in ctl.stdout
        blocked = 0
        for t in tests:
            try:
                r = subprocess.run(mk(str(t), d), capture_output=True, text=True, timeout=30)
                escaped = r.returncode == 0 and "ESCAPED" in r.stdout
            except subprocess.TimeoutExpired:
                escaped = False
            rows[t.name][cname] = "ESCAPED" if escaped else "blocked"
            blocked += not escaped
        result[cname] = {"blocked": blocked, "total": len(tests), "control_ok": control_ok,
                         "tests": {n: rows[n][cname] for n in rows}}
        shutil.rmtree(d, ignore_errors=True)
    for n, r in rows.items():
        print(f"{n:<14}" + "".join(f"{r[c]:<16}" for c in configs))
    print(f"{'BLOCKED':<14}" + "".join(f"{result[c]['blocked']}/{result[c]['total']:<14}" for c in configs))
    bad = [c for c in configs if not result[c]["control_ok"]]
    if bad:
        print(f"WARNING: control program failed under {bad}: those columns are invalid (config broke a harmless program).")
    (RES / "escape.json").write_text(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
