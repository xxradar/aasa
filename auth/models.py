"""Auth data models."""

from __future__ import annotations
from pydantic import BaseModel, EmailStr, Field
from typing import Optional


class UserCreate(BaseModel):
    """Registration request."""
    email: str = Field(..., description="Email address")
    password: str = Field(..., min_length=8, description="Password (min 8 chars)")
    name: Optional[str] = None


class UserLogin(BaseModel):
    """Login request."""
    email: str
    password: str


class User(BaseModel):
    """User record returned to frontend."""
    id: int
    email: str
    name: Optional[str] = None
    provider: str = "local"  # local, github, google
    avatar_url: Optional[str] = None


class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str
    token_type: str = "bearer"
    user: User
