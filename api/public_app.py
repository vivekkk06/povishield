"""Public, read-only entry point for hosted deployments.

Start with: uvicorn api.public_app:app --host 0.0.0.0 --port $PORT
Only the GET routes below are reachable. The monitor, executions, pairing,
devices, agent routes, install script and API docs all answer 404.
"""
import re

from starlette.requests import Request
from starlette.responses import JSONResponse

from api.main import app

_ALLOWED = re.compile(
    r"^/(?:api/(?:health|overview|experiments|events(?:/profile)?|policies(?:/compare)?|"
    r"ablation/(?:results|noisy)|ledgers(?:/[A-Za-z0-9_.-]+(?:/audit)?)?|approvals)|health)?$"
)


@app.middleware("http")
async def public_read_only(request: Request, call_next):
    if request.method in ("GET", "HEAD", "OPTIONS") and _ALLOWED.match(request.url.path):
        return await call_next(request)
    return JSONResponse({"detail": "Not found"}, status_code=404)
