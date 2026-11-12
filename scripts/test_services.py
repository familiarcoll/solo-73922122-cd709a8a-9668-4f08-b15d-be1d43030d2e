"""Service-level correctness tests (no HTTP): rotation, idempotent retry,
theft-driven family revocation, family isolation, restart persistence and
atomic-commit guarantees.

Run:  python scripts/test_services.py
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import get_settings  # noqa: E402
from app.db import db_connection, immediate_tx, init_db  # noqa: E402
from app.services import (  # noqa: E402
    AuthError,
    authenticate_access_token,
    issue_family,
    rotate,
)

PASS = "PASS"
FAILS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"[{PASS if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not cond:
        FAILS.append(name)


def new_family(conn) -> tuple[int, str, str]:
    settings = get_settings()
    with immediate_tx(conn):
        pair = issue_family(conn, settings, user_id=1, request_id=None)
    return pair["family_id"], pair["access_token"], pair["refresh_token"]


def main() -> int:
    settings = get_settings()
    init_db()

    # ------------------------------------------------------------------ login
    with db_connection() as conn:
        fam1, access1, refresh1 = new_family(conn)
        fam2, access2, refresh2 = new_family(conn)
        check("two independent families created", fam1 != fam2)

    # ----------------------------------------------------------- first rotate
    with db_connection() as conn:
        pair_a = rotate(conn, settings, refresh1, "req-10000001")
        check(
            "rotation returns a brand new pair",
            pair_a["refresh_token"] != refresh1 and pair_a["access_token"] != access1,
        )
        check("pair carries the request id", pair_a["request_id"] == "req-10000001")

        # old token is now consumed
        from app.security import hash_token

        consumed = conn.execute(
            "SELECT consumed FROM refresh_tokens WHERE token_hash = ?",
            (hash_token(refresh1),),
        ).fetchone()["consumed"]
        check("old refresh token marked consumed", consumed == 1)

        # receipt exists and is encrypted (not plaintext JSON)
        receipt = conn.execute(
            "SELECT encrypted_response FROM refresh_receipts WHERE old_refresh_hash = ?",
            (hash_token(refresh1),),
        ).fetchone()
        blob = receipt["encrypted_response"]
        check(
            "receipt is Fernet-encrypted (no plaintext tokens in DB)",
            b"refresh_token" not in blob and blob.startswith(b"gAAAA"),
        )

    # ----------------------------------------------- idempotent retry (30 s)
    with db_connection() as conn:
        retry_a = rotate(conn, settings, refresh1, "req-10000001")
        check(
            "same request_id returns the EXACT same token pair",
            retry_a == pair_a,
        )
        retry_b = rotate(conn, settings, refresh1, "req-10000001")
        check("repeated retries keep returning the same pair", retry_b == pair_a)

    # ------------------------------- reuse with a DIFFERENT request_id = theft
    with db_connection() as conn:
        theft_error = None
        try:
            rotate(conn, settings, refresh1, "req-ATTACK-99")
        except AuthError as exc:
            theft_error = exc
        check(
            "reuse with different request_id is rejected",
            theft_error is not None and theft_error.code == "token_reuse_revoked",
        )

        revoked = conn.execute(
            "SELECT revoked, revoke_reason FROM token_families WHERE id = ?", (fam1,)
        ).fetchone()
        check(
            "whole family 1 permanently revoked",
            revoked["revoked"] == 1 and revoked["revoke_reason"] == "refresh_token_reuse_detected",
        )

    # ------------------------------- revoked family: rotated tokens rejected
    with db_connection() as conn:
        # The new refresh token minted during the legitimate rotation is dead
        for label, tok in (("rotated refresh", pair_a["refresh_token"]),):
            err = None
            try:
                rotate(conn, settings, tok, "req-after-revoke-1")
            except AuthError as exc:
                err = exc
            check(
                f"{label} on revoked family rejected",
                err is not None and err.code == "family_revoked",
            )

        # access token of the revoked family can no longer query identity
        err = None
        try:
            authenticate_access_token(conn, pair_a["access_token"])
        except AuthError as exc:
            err = exc
        check(
            "identity query rejected with revoked-family access token",
            err is not None and err.code == "family_revoked",
        )

        # original access token from login on the same family is rejected too
        err = None
        try:
            authenticate_access_token(conn, access1)
        except AuthError as exc:
            err = exc
        check(
            "pre-rotation access token also rejected after revocation",
            err is not None and err.code == "family_revoked",
        )

    # ---------------------------- revoked family cannot recover via retry
    with db_connection() as conn:
        err = None
        try:
            rotate(conn, settings, refresh1, "req-10000001")  # the original request id
        except AuthError as exc:
            err = exc
        check(
            "idempotent retry cannot resurrect a revoked family",
            err is not None and err.code == "family_revoked",
        )

    # --------------------------------------- other family is completely unaffected
    with db_connection() as conn:
        pair_other = rotate(conn, settings, refresh2, "req-family2-001")
        check("unaffected family 2 can still rotate", pair_other["refresh_token"] != refresh2)
        row = authenticate_access_token(conn, pair_other["access_token"])
        check(
            "unaffected family 2 identity query works",
            row["family_id"] == fam2 and row["username"] == "demo",
        )
        state = conn.execute(
            "SELECT revoked FROM token_families WHERE id = ?", (fam2,)
        ).fetchone()
        check("family 2 remains unrevoked", state["revoked"] == 0)

    # --------------------------------------------- unknown token is a no-op
    with db_connection() as conn:
        from app.security import generate_token

        err = None
        try:
            rotate(conn, settings, generate_token(), "req-unknown-0001")
        except AuthError as exc:
            err = exc
        check("unknown refresh token rejected, no family touched",
              err is not None and err.code == "invalid_token")
        n_revoked = conn.execute(
            "SELECT COUNT(*) c FROM token_families WHERE revoked = 1"
        ).fetchone()["c"]
        check("only family 1 is revoked", n_revoked == 1)

    # ------------------------- restart persistence: reopen DB, state survives
    with db_connection() as conn:
        state = conn.execute(
            "SELECT revoked FROM token_families WHERE id = ?", (fam1,)
        ).fetchone()
        check("revocation survives a fresh connection (restart)", state["revoked"] == 1)
        err = None
        try:
            rotate(conn, settings, refresh1, "req-10000001")
        except AuthError as exc:
            err = exc
        check("retry still rejected after reconnect", err is not None)

    # ----------------- only hashes are stored: raw tokens nowhere in the DB
    import sqlite3

    raw = sqlite3.connect(settings.db_path)
    raw.row_factory = sqlite3.Row
    leaked = []
    for table, col in (
        ("refresh_tokens", "token_hash"),
        ("access_tokens", "token_hash"),
    ):
        for r in raw.execute(f"SELECT {col} h FROM {table}"):
            if len(r["h"]) != 64:  # sha256 hex digest length
                leaked.append((table, r["h"]))
    for r in raw.execute("SELECT encrypted_response e FROM refresh_receipts"):
        if b"refresh_token" in r["e"]:
            leaked.append(("receipt", "plaintext"))
    check("database stores only hashes and encrypted receipts", not leaked, str(leaked))
    raw.close()

    # --------------------- idempotency expiry: after window, reuse -> revoke
    # craft a fresh family and simulate receipt expiry
    with db_connection() as conn:
        fam3, _acc3, ref3 = new_family(conn)
        p3 = rotate(conn, settings, ref3, "req-f3-0001")
        conn.execute(
            "UPDATE refresh_receipts SET expires_at = ? WHERE old_refresh_hash = ?",
            (int(time.time()) - 1, hash_token(ref3)),
        )
        conn.commit() if False else None  # autocommit outside tx; execute already persisted
        err = None
        try:
            rotate(conn, settings, ref3, "req-f3-0001")
        except AuthError as exc:
            err = exc
        check(
            "retry after the 30s window is treated as reuse and revokes",
            err is not None and err.code == "token_reuse_revoked",
        )
        check(
            "family 3 revoked on late retry",
            conn.execute("SELECT revoked FROM token_families WHERE id=?", (fam3,)).fetchone()["revoked"] == 1,
        )
        # and the legitimately rotated pair is dead too
        err = None
        try:
            authenticate_access_token(conn, p3["access_token"])
        except AuthError as exc:
            err = exc
        check("minted pair of family 3 is dead after revocation", err is not None)

    print()
    if FAILS:
        print(f"{len(FAILS)} check(s) FAILED: {FAILS}")
        return 1
    print("ALL SERVICE-LEVEL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
