"""Public entry point for hosted cloud deployments.

Start with: uvicorn api.public_app:app --host 0.0.0.0 --port $PORT
Provides full access to PoViShield device fleet management, policy evaluation,
execution tracing, pairing, and research data on cloud platforms.
"""
import os
import re

os.environ.setdefault("POVISHIELD_ALLOW_REMOTE", "1")

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

# If strict read-only mode is explicitly enabled by the operator, restrict non-GET routes:
if os.environ.get("POVISHIELD_STRICT_READ_ONLY", "0").lower() in ("1", "true", "yes"):
    _ALLOWED = re.compile(
        r"^/(?:api/(?:health|overview|experiments|events(?:/profile)?|policies(?:/compare)?|"
        r"ablation/(?:results|noisy|targets|trial|minimize)|ledgers(?:/[A-Za-z0-9_.-]+(?:/audit)?)?|approvals)|health)?$"
    )

    @app.middleware("http")
    async def public_read_only(request: Request, call_next):
        if request.method in ("GET", "HEAD", "OPTIONS") and _ALLOWED.match(request.url.path):
            return await call_next(request)
        return JSONResponse({"detail": "Not found in read-only mode"}, status_code=404)

# Added last, so it is the outermost layer: requests carry cloud-compatible CORS headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if "*" in _main.TRUSTED_ORIGINS else sorted(_main.TRUSTED_ORIGINS),
    allow_origin_regex=r"^https?://(127\.0\.0\.1|localhost|\[::1\]|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|([a-zA-Z0-9-]+\.)*vercel\.app|([a-zA-Z0-9-]+\.)*onrender\.com|([a-zA-Z0-9-]+\.)*render\.com)(:\d+)?$",
    allow_credentials=False,
    allow_methods=["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
