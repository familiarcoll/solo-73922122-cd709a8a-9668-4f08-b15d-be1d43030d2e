"""Authentication services: login, atomic rotation, idempotent retry, theft detection."""
from __future__ import annotations

import json
import sqlite3
import time

from .config import Settings
from .security import (
    decrypt_receipt,
    encrypt_receipt,
    generate_token,
    hash_token,
    verify_password,
)


class AuthError(Exception):
    """Mapped to an HTTP error in the API layer. ``status`` drives the code."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


# ---- login ----------------------------------------------------------------


def authenticate(
    conn: sqlite3.Connection, settings: Settings, username: str, password: str
) -> sqlite3.Row:
    row = conn.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    # Constant-ish path: verify against a dummy hash when the user is missing
    # so response timing does not disclose which usernames exist.
    if row is None:
        verify_password(
            password,
            "pbkdf2_sha256$240000$AAAAAAAAAAAAAAAAAAAAAA$"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
        raise AuthError(401, "invalid_credentials", "用户名或密码错误")
    if not verify_password(password, row["password_hash"]):
        raise AuthError(401, "invalid_credentials", "用户名或密码错误")
    return row


def issue_pair(
    conn: sqlite3.Connection,
    settings: Settings,
    family_id: int,
    request_id: str | None,
) -> dict:
    """Mint one access + one refresh token inside an EXISTING family.

    Every rotation stays in the same family, so revoking the family invalidates
    the whole token chain at once. Runs inside the caller's transaction; only
    hashes are persisted.
    """
    now = int(time.time())
    access_raw = generate_token()
    refresh_raw = generate_token()
    conn.execute(
        "INSERT INTO access_tokens (family_id, token_hash, expires_at, created_at) "
        "VALUES (?, ?, ?, ?)",
        (family_id, hash_token(access_raw), now + settings.access_ttl, now),
    )
    conn.execute(
        "INSERT INTO refresh_tokens (family_id, token_hash, expires_at, created_at) "
        "VALUES (?, ?, ?, ?)",
        (family_id, hash_token(refresh_raw), now + settings.refresh_ttl, now),
    )
    return {
        "access_token": access_raw,
        "refresh_token": refresh_raw,
        "token_type": "bearer",
        "access_expires_in": settings.access_ttl,
        "refresh_expires_in": settings.refresh_ttl,
        "family_id": family_id,
        "request_id": request_id,
    }


def issue_family(
    conn: sqlite3.Connection,
    settings: Settings,
    user_id: int,
    request_id: str | None,
) -> dict:
    """Create a new token family (at login) with its first token pair."""
    now = int(time.time())
    cur = conn.execute(
        "INSERT INTO token_families (user_id, created_at) VALUES (?, ?)",
        (user_id, now),
    )
    family_id = cur.lastrowid
    return issue_pair(conn, settings, family_id, request_id)


# ---- refresh / rotation ---------------------------------------------------


def _receipt_payload(pair: dict) -> bytes:
    return json.dumps(pair, separators=(",", ":"), sort_keys=True).encode("utf-8")


def rotate(
    conn: sqlite3.Connection,
    settings: Settings,
    refresh_token: str,
    request_id: str,
) -> dict:
    """Rotate a refresh token and manage its own atomic transaction.

    A successful rotation (or an idempotent retry read) commits normally.
    Token theft revokes the whole family and that revocation is COMMITTED
    before the 401 is raised, so the security decision is durable even though
    the request itself fails. Any other exception rolls back untouched.
    """
    from .db import immediate_tx

    error: AuthError | None = None
    result: dict | None = None
    try:
        with immediate_tx(conn):
            result = _rotate_locked(conn, settings, refresh_token, request_id)
    except AuthError as exc:
        # Revocation errors are raised after the helper has already ended the
        # transaction (revocation committed, or a read-only rejection rolled
        # back); capture and re-raise outside the transaction context.
        if exc.code not in ("token_reuse_revoked", "family_revoked"):
            raise
        error = exc
    if error is not None:
        raise error
    assert result is not None
    return result


def _rotate_locked(
    conn: sqlite3.Connection,
    settings: Settings,
    refresh_token: str,
    request_id: str,
) -> dict:
    """Rotation logic; caller holds an open ``BEGIN IMMEDIATE`` transaction."""
    now = int(time.time())
    token_hash = hash_token(refresh_token)

    row = conn.execute(
        """
        SELECT rt.id, rt.family_id, rt.consumed, rt.expires_at,
               f.revoked, f.revoke_reason
          FROM refresh_tokens rt
          JOIN token_families f ON f.id = rt.family_id
         WHERE rt.token_hash = ?
        """,
        (token_hash,),
    ).fetchone()

    if row is None:
        # Unknown token: nothing to revoke, nothing to return.
        raise AuthError(401, "invalid_token", "刷新令牌无效")

    family_id = row["family_id"]

    # 1) A revoked family stays revoked. Retries cannot resurrect it. No write
    #    happened in this transaction, so roll back and reject.
    if row["revoked"]:
        conn.execute("ROLLBACK")
        raise AuthError(
            401,
            "family_revoked",
            f"令牌家族已被永久撤销（原因：{row['revoke_reason'] or '未知'}），重试无法恢复",
        )

    # 2) Expired tokens are rejected. Expiry alone does not revoke the family
    #    (legitimate expiry is not theft), but the token can no longer rotate.
    if row["expires_at"] <= now:
        raise AuthError(401, "token_expired", "刷新令牌已过期，请重新登录")

    # 3) Idempotent retry: same consumed token + same request_id inside the
    #    30 s window -> hand back the exact same encrypted token pair.
    if row["consumed"]:
        receipt = conn.execute(
            "SELECT encrypted_response, expires_at FROM refresh_receipts "
            "WHERE old_refresh_hash = ? AND request_id = ?",
            (token_hash, request_id),
        ).fetchone()
        if receipt is not None and receipt["expires_at"] > now:
            return json.loads(decrypt_receipt(receipt["encrypted_response"]))

        # 4) Any other reuse of a consumed token = token theft. Revoke the
        #    ENTIRE family permanently and COMMIT before returning the error,
        #    so the revocation survives even though this request is rejected.
        conn.execute(
            "UPDATE token_families "
            "SET revoked = 1, revoke_reason = ?, revoked_at = ? WHERE id = ?",
            ("refresh_token_reuse_detected", now, family_id),
        )
        conn.execute("COMMIT")
        raise AuthError(
            401,
            "token_reuse_revoked",
            "检测到已消费刷新令牌被复用，该令牌家族已被永久撤销",
        )

    # 5) First, valid presentation: consume old token and mint a new pair in
    #    the SAME family so a later revocation covers the whole chain.
    conn.execute(
        "UPDATE refresh_tokens SET consumed = 1, consumed_at = ? WHERE id = ?",
        (now, row["id"]),
    )
    pair = issue_pair(conn, settings, family_id=family_id, request_id=request_id)

    conn.execute(
        "INSERT INTO refresh_receipts "
        "(family_id, old_refresh_hash, request_id, encrypted_response, "
        " created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        (
            family_id,
            token_hash,
            request_id,
            encrypt_receipt(_receipt_payload(pair)),
            now,
            now + settings.idempotency_ttl,
        ),
    )
    return pair


# ---- access token introspection ------------------------------------------


def authenticate_access_token(
    conn: sqlite3.Connection, access_token: str
) -> sqlite3.Row:
    now = int(time.time())
    row = conn.execute(
        """
        SELECT at.token_hash, at.expires_at, at.family_id,
               f.revoked, f.revoke_reason, f.user_id, u.username
          FROM access_tokens at
          JOIN token_families f ON f.id = at.family_id
          JOIN users u ON u.id = f.user_id
         WHERE at.token_hash = ?
        """,
        (hash_token(access_token),),
    ).fetchone()
    if row is None:
        raise AuthError(401, "invalid_token", "访问令牌无效")
    if row["revoked"]:
        raise AuthError(
            401,
            "family_revoked",
            f"令牌家族已被永久撤销（原因：{row['revoke_reason'] or '未知'}）",
        )
    if row["expires_at"] <= now:
        raise AuthError(401, "token_expired", "访问令牌已过期，请使用刷新令牌续期")
    return row
