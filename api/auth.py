"""Authentication and authorization guards for users and remote PoViShield devices."""
import hashlib
import secrets
from typing import Any, Dict, Optional

try:
    from fastapi import HTTPException, Request
except ImportError:
    class HTTPException(Exception):  # type: ignore
        def __init__(self, status_code: int, detail: Any = None):
            self.status_code = status_code
            self.detail = detail
            super().__init__(f"HTTP {status_code}: {detail}")
    Request = Any  # type: ignore

from api.database import get_device_by_token_hash, get_or_create_user, get_user, update_device_heartbeat


def hash_token(token: str) -> str:
    """Computes SHA-256 digest of secret token for secure database indexing."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_device_token() -> str:
    """Generates a high-entropy bearer token for paired devices."""
    return f"pvs_agent_{secrets.token_hex(24)}"


def get_current_user(
    request: Request,
    x_povishield_user: Optional[str] = None,
    authorization: Optional[str] = None
) -> Dict[str, Any]:
    """Resolves authenticated dashboard user. In single-tenant/local mode defaults to 'usr_operator'."""
    # Read from request headers if not passed directly
    if not x_povishield_user and hasattr(request, "headers"):
        x_povishield_user = request.headers.get("x-povishield-user")
    if not authorization and hasattr(request, "headers"):
        authorization = request.headers.get("authorization")

    # 1. Check custom user header
    if x_povishield_user and isinstance(x_povishield_user, str):
        clean_user = x_povishield_user.strip()
        user_id = f"usr_{clean_user}"
        return get_or_create_user(user_id, clean_user)

    # 2. Check Bearer token if user-style
    if authorization and isinstance(authorization, str) and authorization.startswith("Bearer usr_"):
        user_id = authorization.split("Bearer ", 1)[1].strip()
        user = get_user(user_id)
        if user:
            return user
        return get_or_create_user(user_id, user_id.replace("usr_", ""))

    # 3. Default to operator
    return get_or_create_user("usr_operator", "operator", "operator@povishield.local")


def get_authenticated_device(
    request: Request,
    authorization: Optional[str] = None
) -> Dict[str, Any]:
    """Authenticates a device via its secret Bearer token and verifies it is not revoked."""
    if not authorization and hasattr(request, "headers"):
        authorization = request.headers.get("authorization")

    if not authorization or not isinstance(authorization, str) or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    raw_token = authorization.split("Bearer ", 1)[1].strip()
    if not raw_token:
        raise HTTPException(status_code=401, detail="Empty bearer token")

    thash = hash_token(raw_token)
    device = get_device_by_token_hash(thash)
    if not device:
        raise HTTPException(status_code=401, detail="Invalid device credentials")

    if device.get("status") == "revoked":
        raise HTTPException(status_code=403, detail="Device authorization has been revoked")

    # Update device heartbeat
    update_device_heartbeat(device["id"], status="online")
    return device
