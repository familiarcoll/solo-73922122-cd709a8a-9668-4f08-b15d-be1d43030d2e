"""Pydantic request/response models."""
from __future__ import annotations

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=16, max_length=512)
    # Client-generated random request id; makes retries idempotent.
    request_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._\-]+$")


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    access_expires_in: int
    refresh_expires_in: int
    family_id: int
    request_id: str | None = None


class Identity(BaseModel):
    user_id: int
    username: str
    family_id: int
    access_token_hash: str = Field(
        description="Only the SHA-256 hash is stored server-side; echoed for verification."
    )
    access_expires_at: int


class Health(BaseModel):
    status: str
    db: str
    pid: int
