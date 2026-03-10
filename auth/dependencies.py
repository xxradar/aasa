"""FastAPI dependencies for auth."""

from __future__ import annotations
from typing import Optional

from fastapi import Request, HTTPException, status

from .jwt import verify_token
from .database import get_db
from .models import User
from config import settings


def get_current_user(request: Request) -> Optional[User]:
    """Extract the current user from the JWT cookie. Returns None if not authenticated."""
    if not settings.auth_enabled:
        return None

    token = request.cookies.get("access_token")
    if not token:
        return None

    payload = verify_token(token)
    if not payload:
        return None

    user_id = int(payload.get("sub", 0))
    if not user_id:
        return None

    return get_db().get_by_id(user_id)


def require_auth(request: Request) -> User:
    """Dependency that requires authentication. Raises 401 if not authenticated."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return user
