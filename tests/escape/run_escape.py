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
    if shutil.which("docker") and os.environ.get("PS_DOCKER") == "1":
        configs["docker-default"] = lambda b, d: ["docker", "run", "--rm", "-v", f"{ESC}:/t:ro,z", "debian:stable-slim", "/t/" + Path(b).name, d]

    RF = os.environ.get("PS_ROOTFS")
    if RF and Path(RF, "t", "control_ok").exists():
        # profile for static binaries: learned from the harmless control only, never from the attack tests
        static_prof = RES / "profiles" / "benign-static.json"
        save_profile(static_prof, learn([str(ROOT / "build" / "escape-static" / "control_ok"), "/tmp"],
                                        tmp / "static.json"))
        configs["full+rootfs"] = lambda b, d: [str(BIN), "run", "--rootfs", RF, "--mem", "256", "--pids", "64",
                                               "--profile", str(static_prof), "--", "/t/" + Path(b).name, "/tmp"]

    if RF and Path(RF, "t", "control_ok").exists():
        # isolates the rootfs from seccomp: no --profile
        configs["rootfs-only"] = lambda b, d: [str(BIN), "run", "--rootfs", RF, "--mem", "256", "--pids", "64",
                                               "--", "/t/" + Path(b).name, "/tmp"]

    tests = sorted(p for p in ESC.glob("*") if p.name.startswith(("esc_", "limit_")))
    result = {}
    print(f"{'test':<14}" + "".join(f"{c:<16}" for c in configs))
    rows = {t.name: {} for t in tests}
    for cname, mk in configs.items():
        d = tempfile.mkdtemp()
        ctl = subprocess.run(mk(str(ESC / "control_ok"), d), capture_output=True, text=True, timeout=120)
        control_ok = ctl.returncode == 0 and "OK" in ctl.stdout
        if not control_ok:
            print(f"[{cname}] control FAILED rc={ctl.returncode} stdout={ctl.stdout!r} stderr={ctl.stderr[-300:]!r}")
        counts = {"ESCAPED": 0, "BLOCKED_SIGSYS": 0, "KILLED_BY_LIMIT": 0, "DENIED": 0, "NO_ESCAPE_MARKER": 0, "TIMEOUT": 0, "ERROR": 0}
        if not control_ok:
            for t in tests:
                rows[t.name][cname] = "INVALID_CONFIG"
            result[cname] = {
                "status": "INVALID_CONFIG",
                "blocked": None,
                "total": len(tests),
                "control_ok": False,
                "tests": {n: rows[n][cname] for n in rows},
            }
            shutil.rmtree(d, ignore_errors=True)
            continue

        for t in tests:
            argv = mk(str(t), d)
            try:
                r = subprocess.run(
                    argv, capture_output=True, text=True, timeout=30
                )
                if "ESCAPED:" in r.stdout:
                    status = "ESCAPED"
                elif r.returncode in (-31, 159):
                    status = "BLOCKED_SIGSYS"      # killed by seccomp
                elif r.returncode in (-9, 137):
                    status = "KILLED_BY_LIMIT"     # OOM / limit kill
                elif r.returncode == 1:
                    status = "DENIED"              # test ran, escape refused
                elif r.returncode < 0:
                    status = "ERROR"
                else:
                    # A non-escape result alone does not prove a security block.
                    status = "NO_ESCAPE_MARKER"
            except subprocess.TimeoutExpired:
                status = "TIMEOUT"
            except (OSError, subprocess.SubprocessError) as exc:
                print(f"ERROR running {t.name} under {cname}: {exc}", file=sys.stderr)
                status = "ERROR"

            rows[t.name][cname] = status
            counts[status] += 1

        result[cname] = {
            "status": "VALID",
            "blocked": None,
            "total": len(tests),
            "control_ok": True,
            "counts": counts,
            "tests": {n: rows[n][cname] for n in rows},
        }
        shutil.rmtree(d, ignore_errors=True)
    for n, r in rows.items():
        print(f"{n:<14}" + "".join(f"{r[c]:<20}" for c in configs))

    print("\\n========== SUMMARY ==========")
    for cname in configs:
        item = result[cname]
        if item["status"] == "INVALID_CONFIG":
            print(f"{cname}: INVALID_CONFIG (control program failed)")
            continue
        counts = item["counts"]
        print(
            f"{cname}: ESCAPED={counts['ESCAPED']}, "
            f"NO_ESCAPE_MARKER={counts['NO_ESCAPE_MARKER']}, "
            f"TIMEOUT={counts['TIMEOUT']}, ERROR={counts['ERROR']}"
        )
    print("Note: NO_ESCAPE_MARKER does not prove that a security boundary blocked the test.")
    (RES / "escape.json").write_text(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
