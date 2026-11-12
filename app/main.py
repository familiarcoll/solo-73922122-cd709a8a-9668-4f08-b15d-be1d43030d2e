"""FastAPI entry point.

Run two identical processes (see docker-compose.yml: api-a / api-b) behind a
load balancer; every process shares the same SQLite file and every mutating
operation is one atomic ``BEGIN IMMEDIATE`` transaction.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import sqlite3
import time
from typing import AsyncIterator

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse

from .config import get_settings
from .db import db_connection, immediate_tx, init_db, janitor_once
from .models import Health, Identity, LoginRequest, RefreshRequest, TokenPair
from .services import (
    AuthError,
    authenticate,
    authenticate_access_token,
    issue_family,
    rotate,
)

# ---------------------------------------------------------------------------
# Logging: secrets must never reach the logs. We never log request bodies,
# and add a defense-in-depth filter that scrubs token/password-looking values.
# ---------------------------------------------------------------------------
_SECRET_PATTERN = re.compile(
    r'((?:refresh_token|access_token|password|FERNET_KEY|DEMO_USER_PASSWORD)'
    r'["\']?\s*[:=]\s*["\']?)[A-Za-z0-9._\-]+',
    re.IGNORECASE,
)


class SecretRedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        if _SECRET_PATTERN.search(msg):
            record.msg = _SECRET_PATTERN.sub(r"\1***REDACTED***", msg)
            record.args = ()
        return True


def _configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.addFilter(SecretRedactingFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error", "app"):
        logger = logging.getLogger(name)
        logger.handlers = [handler]
        logger.propagate = False


_configure_logging()
log = logging.getLogger("app")

BEARER_PREFIX = "Bearer "


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Initialize schema + demo account on boot (idempotent, safe on every
    # process and every restart).
    init_db()
    log.info("startup complete pid=%s db=%s", os.getpid(), get_settings().db_path)

    async def janitor_loop() -> None:
        # Both processes may run the janitor; deletes are idempotent and
        # transactional, so concurrent cleanup is harmless.
        while True:
            try:
                await asyncio.to_thread(janitor_once)
            except Exception:  # pragma: no cover - janitor must never kill the process
                log.exception("janitor sweep failed")
            await asyncio.sleep(300)

    task = asyncio.create_task(janitor_loop())
    app.state.janitor_task = task
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


app = FastAPI(
    title="Refresh Token Rotation & Family Revocation API",
    version="1.0.0",
    lifespan=lifespan,
    description=(
        "登录后签发短期访问令牌（60 秒）与可轮换刷新令牌（10 分钟）。\n\n"
        "- 刷新令牌一次性使用：旧令牌只能换出一对新令牌。\n"
        "- 同 (旧令牌, request_id) 在 30 秒内重试返回**完全相同**的令牌对。\n"
        "- 任何其他方式复用已消费令牌 → 永久撤销整个令牌家族，"
        "后续刷新与身份查询一律拒绝；其他登录家族不受影响；已撤销家族不能靠重试恢复。\n"
        "- 令牌仅存 SHA-256 哈希；幂等回执以启动配置提供的 Fernet 密钥加密保存。\n"
        "- 两个 API 进程共享同一 SQLite 库，所有轮换/撤销在单事务内原子提交。"
    ),
)


@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    # Note: do not echo any token material in error responses or logs.
    log.info("auth failure path=%s code=%s", request.url.path, exc.code)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


def get_db() -> sqlite3.Connection:
    with db_connection() as conn:
        yield conn


@app.get("/", include_in_schema=False)
def root() -> dict:
    return {
        "service": "refresh-token-rotation",
        "docs": "/docs",
        "endpoints": [
            "POST /api/auth/login",
            "POST /api/auth/refresh",
            "GET  /api/auth/me",
            "GET  /health",
        ],
    }


@app.get("/health", response_model=Health, tags=["system"])
def health(conn: sqlite3.Connection = Depends(get_db)) -> Health:
    conn.execute("SELECT 1")
    return Health(status="ok", db=get_settings().db_path, pid=os.getpid())


@app.post("/api/auth/login", response_model=TokenPair, tags=["auth"])
def login(body: LoginRequest, conn: sqlite3.Connection = Depends(get_db)) -> TokenPair:
    """密码登录，签发一个新令牌家族（访问令牌 60s + 刷新令牌 10min）。"""
    settings = get_settings()
    user = authenticate(conn, settings, body.username, body.password)
    with immediate_tx(conn):
        pair = issue_family(conn, settings, user_id=user["id"], request_id=None)
    log.info("login ok user_id=%s family_id=%s", user["id"], pair["family_id"])
    return TokenPair(**pair)


@app.post("/api/auth/refresh", response_model=TokenPair, tags=["auth"])
def refresh(body: RefreshRequest, conn: sqlite3.Connection = Depends(get_db)) -> TokenPair:
    """原子轮换；30 秒内同 request_id 重试返回原令牌对；复用即撤销整个家族。

    ``rotate`` owns the transaction itself: a revocation triggered by token
    reuse is committed before the 401 is raised, so the security decision is
    durable even though the request fails.
    """
    settings = get_settings()
    pair = rotate(conn, settings, body.refresh_token, body.request_id)
    return TokenPair(**pair)


def _extract_bearer(authorization: str | None) -> str:
    if not authorization or not authorization.startswith(BEARER_PREFIX):
        raise AuthError(401, "missing_bearer", "请在 Authorization 头中提供 Bearer 访问令牌")
    token = authorization[len(BEARER_PREFIX):].strip()
    if not token:
        raise AuthError(401, "missing_bearer", "Bearer 令牌为空")
    return token


@app.get("/api/auth/me", response_model=Identity, tags=["auth"])
def me(
    authorization: str | None = Header(default=None),
    conn: sqlite3.Connection = Depends(get_db),
) -> Identity:
    """凭访问令牌查询身份；家族被撤销后此接口同样拒绝。"""
    token = _extract_bearer(authorization)
    row = authenticate_access_token(conn, token)
    return Identity(
        user_id=row["user_id"],
        username=row["username"],
        family_id=row["family_id"],
        access_token_hash=row["token_hash"],
        access_expires_at=row["expires_at"],
    )
