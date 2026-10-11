#!/usr/bin/env python3
"""Does the dashboard API show REAL data? HTTP 200 is not enough.

 1. discovers every parameterless GET route from the API's /openapi.json
 2. reports status, size and whether the payload is empty
 3. generates a real learn + enforce-kill event with the CLI
 4. re-reads every route and reports which ones changed

Usage: python3 scripts/verify_dashboard.py           (API default http://127.0.0.1:8000, override with API=...)"""
import hashlib, json, os, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

API = os.environ.get("API", "http://127.0.0.1:8000").rstrip("/")
ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "build" / "povishield"


def get(path):
    try:
        with urllib.request.urlopen(API + path, timeout=8) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:                                   # connection refused, timeout, ...
        return None, str(e).encode()


def routes():
    st, body = get("/openapi.json")
    if st != 200:
        return None
    paths = json.loads(body).get("paths", {})
    return sorted(p for p, ops in paths.items() if "get" in ops and "{" not in p)


def describe(body):
    try:
        j = json.loads(body)
    except Exception:
        return "non-JSON"
    if j in ([], {}, None, ""):
        return "EMPTY"
    if isinstance(j, list):
        return f"list[{len(j)}]"
    if isinstance(j, dict):
        return f"object({len(j)} keys)"
    return type(j).__name__


def snapshot(rs):
    return {r: (lambda sb: (sb[0], hashlib.sha256(sb[1]).hexdigest(), describe(sb[1])))(get(r)) for r in rs}


def main():
    rs = routes()
    if rs is None:
        print(f"API not reachable at {API} (or no /openapi.json).\nStart it:  .venv/bin/python -m uvicorn api.main:app --host 127.0.0.1 --port 8000")
        return 2
    print(f"{len(rs)} parameterless GET routes on {API}\n")
    before = snapshot(rs)
    for r, (st, _, d) in before.items():
        print(f"  {st}  {r:<40} {d}")

    print("\ngenerating a real learn + enforce-kill event ...")
    d = Path(tempfile.mkdtemp())
    results = ROOT / "results"
    results.mkdir(exist_ok=True)
    if BIN.exists():
        subprocess.run([str(BIN), "learn", "-o", str(results / "dashboard-probe.json"), "--", "/bin/echo", "probe"],
                       capture_output=True)
        subprocess.run([str(BIN), "learn", "-o", str(d / "e.json"), "--", "/bin/echo", "x"], capture_output=True)
        k = subprocess.run([str(BIN), "enforce", "-p", str(d / "e.json"), "--", "/bin/ls", "/"], capture_output=True)
        print(f"  enforce exit status {k.returncode} (-31 or 159 = killed by seccomp)")
    time.sleep(3)
    after = snapshot(rs)
    changed = [r for r in rs if before[r][1] != after[r][1]]
    print()
    if changed:
        print("Routes whose data changed after the events (LIVE):")
        for r in changed:
            print(f"  {r}: {before[r][2]} -> {after[r][2]}")
    else:
        print("VERDICT: no route reflected the new events. The dashboard shows saved/static data only,\n"
              "or reads a different directory than the CLI writes to. Do not describe it as live.")
    empty = [r for r in rs if after[r][2] == "EMPTY"]
    if empty:
        print("\nEmpty routes (not populated):", ", ".join(empty))
    return 0


if __name__ == "__main__":
    sys.exit(main())
