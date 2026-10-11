#!/usr/bin/env python3
"""Security checks for the live-monitor API. Needs the API running (default http://127.0.0.1:8000).

A browser always connects to a local server from 127.0.0.1, so "the peer is loopback" does NOT tell you the request
came from you. These tests check the controls that do: Host header (DNS rebinding), Origin header (cross-site
requests) and an allow-list of executables (the denylist alone is bypassable via /usr/bin/env, find, xargs, ...)."""
import json, os, shutil, sys, urllib.error, urllib.request

API = os.environ.get("API", "http://127.0.0.1:8000").rstrip("/")
GOOD_ORIGIN = os.environ.get("GOOD_ORIGIN", "http://127.0.0.1:5175")
results, sessions = [], []


def call(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(API + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except Exception:
            return e.code, None


def check(name, ok, detail=""):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"   ({detail})" if detail and not ok else ""))


def start(argv, headers=None):
    st, js = call("POST", "/api/monitor/sessions", {"command": argv, "timeout_seconds": 5}, headers)
    if st == 200 and js and js.get("id"):
        sessions.append(js["id"])
    return st, js


def main():
    st, _ = call("GET", "/api/health")
    if st != 200:
        print(f"API not reachable at {API}")
        return 2
    sleep = shutil.which("sleep")
    env, sort, find = shutil.which("env"), shutil.which("sort"), shutil.which("find")

    st, _ = start([sleep, "2"])
    check("allow-listed program starts (no Origin header, like curl)", st == 200, f"status {st}")
    st, _ = start([sleep, "2"], {"Origin": GOOD_ORIGIN})
    check("allow-listed program starts from the dashboard origin", st == 200, f"status {st}")

    st, _ = start([sleep, "2"], {"Origin": "https://evil.example"})
    check("cross-site Origin is rejected", st == 403, f"status {st}")
    st, _ = start([sleep, "2"], {"Origin": "null"})
    check("opaque Origin 'null' (sandboxed iframe, file://) is rejected", st == 403, f"status {st}")
    st, _ = start([sleep, "2"], {"Host": "evil.example:8000"})
    check("foreign Host header (DNS rebinding) is rejected", st == 403, f"status {st}")
    st, _ = call("GET", "/api/monitor/sessions/doesnotexist", headers={"Host": "evil.example"})
    check("foreign Host is rejected on GET endpoints too (403, not 404)", st == 403, f"status {st}")

    for label, path, args in (("env (runs any program)", env, ["sh", "-c", "true"]),
                              ("sort --compress-program (runs any program)", sort, ["--compress-program=/bin/true", "/dev/null"]),
                              ("find -exec", find, [".", "-maxdepth", "0", "-exec", "true", "{}", ";"])):
        if path:
            st, _ = start([path, *args])
            check(f"{label} is rejected", st in (400, 403), f"status {st}")

    for sid in sessions:
        call("POST", f"/api/monitor/sessions/{sid}/stop")
    ok = all(results)
    print(f"\n{sum(results)}/{len(results)} passed" + ("" if ok else "  <-- see FAIL lines"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
