#!/usr/bin/env python3
"""Hardens the live-monitor endpoints in api/main.py. Anchored edits only; backs the file up first.

  1. _require_local_request also checks the Host header (DNS rebinding) and the Origin header (cross-site requests)
  2. executables must be on an allow-list (the denylist stays as a second layer)
  3. at most 3 monitoring sessions may run at once
"""
import pathlib, sys

p = pathlib.Path("api/main.py")
if not p.exists():
    sys.exit("run from the project root (api/main.py not found)")
s = p.read_text()
if "ALLOWED_EXECUTABLES" in s:
    sys.exit("already hardened; nothing to do")

# ---- 1. trust checks -------------------------------------------------------------------------------------------
a = s.find("def _require_local_request(request: Request) -> None:")
b = s.find("def _session_payload", a)
if a < 0 or b < 0:
    sys.exit("anchor for _require_local_request not found (file was customised); not modified")
NEW_GUARD = '''# --- who is really calling? ------------------------------------------------------------------------------------
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


'''
s = s[:a] + NEW_GUARD + s[b:]

# ---- 2. executable allow-list ----------------------------------------------------------------------------------
old = '''    if resolved.name in DENIED_EXECUTABLES:
        raise HTTPException(status_code=400, detail=f"Refusing shell/interpreter or high-risk command: {resolved.name}")
'''
if old not in s:
    sys.exit("anchor for the denylist check not found; not modified")
s = s.replace(old, old + '''    if str(resolved) not in ALLOWED_EXECUTABLES:
        raise HTTPException(status_code=400, detail=f"{resolved.name} is not on the monitor allow-list "
                                                    f"(add an absolute path with POVISHIELD_MONITOR_ALLOW)")
''', 1)

# ---- 3. concurrency cap ----------------------------------------------------------------------------------------
old2 = "    RESULTS.mkdir(parents=True, exist_ok=True)\n    sid = uuid.uuid4().hex[:12]\n"
if old2 not in s:
    sys.exit("anchor for the session start not found; not modified")
s = s.replace(old2, '''    with MONITOR_LOCK:
        running = sum(1 for x in MONITOR_SESSIONS.values() if x["status"] == "running")
    if running >= MAX_RUNNING_SESSIONS:
        raise HTTPException(status_code=429, detail=f"At most {MAX_RUNNING_SESSIONS} monitoring sessions may run at once")
''' + old2, 1)

pathlib.Path(".backups").mkdir(exist_ok=True)
pathlib.Path(".backups/api_main.py.pre-harden").write_text(p.read_text())
p.write_text(s)
print("api/main.py hardened. Backup: .backups/api_main.py.pre-harden")
print("Check that TRUSTED_ORIGINS matches your CORS allow_origins list, then restart uvicorn.")
