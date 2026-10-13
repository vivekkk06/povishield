"""Public, read-only entry point for hosted deployments.

Start with: uvicorn api.public_app:app --host 0.0.0.0 --port $PORT
Only the GET routes below are reachable. The monitor, executions, pairing,
devices, agent routes, install script and API docs all answer 404.
"""
import os
import re

from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

import api.main as _main
from api.main import app

# A hosted server has no compiled tracer. Use the stored syscall count instead of
# running build/povishield (override with POVISHIELD_TOTAL_SYSCALLS).
if not (_main.ROOT / "build" / "povishield").is_file():
    _TOTAL = int(os.environ.get("POVISHIELD_TOTAL_SYSCALLS", "385"))
    for _name in ("api.main", "analysis.common", "analysis.risk"):
        try:
            _mod = __import__(_name, fromlist=["x"])
        except ImportError:
            continue
        if hasattr(_mod, "total_syscalls"):
            _mod.total_syscalls = lambda: _TOTAL

_ALLOWED = re.compile(
    r"^/(?:api/(?:health|overview|experiments|events(?:/profile)?|policies(?:/compare)?|"
    r"ablation/(?:results|noisy)|ledgers(?:/[A-Za-z0-9_.-]+(?:/audit)?)?|approvals)|health)?$"
)


@app.middleware("http")
async def public_read_only(request: Request, call_next):
    if request.method in ("GET", "HEAD", "OPTIONS") and _ALLOWED.match(request.url.path):
        return await call_next(request)
    return JSONResponse({"detail": "Not found"}, status_code=404)


# Added last, so it is the outermost layer: blocked requests also carry CORS
# headers and the browser reports the real 404 instead of "NetworkError".
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(_main.TRUSTED_ORIGINS),
    allow_credentials=False,
    allow_methods=["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
