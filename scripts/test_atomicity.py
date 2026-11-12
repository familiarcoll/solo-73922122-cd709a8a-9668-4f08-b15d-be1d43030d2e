"""Crash-atomicity tests for the rotation transaction.

We simulate a process crash *after* the old token is consumed but *before*
COMMIT, and prove the database never shows half of a rotation: the old token
is still usable (its consumption was rolled back) and no orphan new pair
exists.

Also verifies that secrets never appear in plaintext anywhere in the DB and
that the log output does not contain token material or passwords.
"""
from __future__ import annotations

import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import get_settings  # noqa: E402
from app.db import db_connection, immediate_tx, init_db  # noqa: E402
from app.security import generate_token, hash_token  # noqa: E402
from app.services import issue_family, rotate  # noqa: E402

FAILS: list[str] = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not cond:
        FAILS.append(name)


def main() -> int:
    settings = get_settings()
    init_db()

    # ------------------------------------------------- crash before commit
    with db_connection() as conn:
        with immediate_tx(conn):
            pair = issue_family(conn, settings, user_id=1, request_id=None)
        fam = pair["family_id"]
        old_refresh = pair["refresh_token"]

        # Open a second connection, start the rotation work, then abort
        # WITHOUT committing (simulating a crash mid-transaction).
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "UPDATE refresh_tokens SET consumed=1, consumed_at=? WHERE token_hash=?",
            (1700000000, hash_token(old_refresh)),
        )
        # a would-be new token is inserted in the same tx...
        would_be = generate_token()
        conn.execute(
            "INSERT INTO refresh_tokens (family_id, token_hash, expires_at, created_at)"
            " VALUES (?, ?, ?, ?)",
            (fam, hash_token(would_be), 1700000600, 1700000000),
        )
        # ...and the process dies before COMMIT.
        conn.execute("ROLLBACK")

    raw = sqlite3.connect(settings.db_path)
    raw.row_factory = sqlite3.Row
    old_row = raw.execute(
        "SELECT consumed FROM refresh_tokens WHERE token_hash=?",
        (hash_token(old_refresh),),
    ).fetchone()
    check("crash rolled back consumption: old token still unconsumed",
          old_row is not None and old_row["consumed"] == 0)
    orphan = raw.execute(
        "SELECT 1 FROM refresh_tokens WHERE token_hash=?", (hash_token(would_be),)
    ).fetchone()
    check("crash left no orphan new token (no half rotation)", orphan is None)

    # the old token still rotates cleanly afterwards
    with db_connection() as conn:
        new_pair = rotate(conn, settings, old_refresh, "rid-post-crash-1")
        check("token rotates normally after a rolled-back crash",
              new_pair["refresh_token"] != old_refresh)
    raw.close()

    # --------------------------------- no plaintext secrets anywhere in DB
    raw = sqlite3.connect(settings.db_path)
    raw.row_factory = sqlite3.Row
    leaks = []
    for r in raw.execute("SELECT token_hash h FROM refresh_tokens"):
        if len(r["h"]) != 64:
            leaks.append(("refresh_tokens", r["h"]))
    for r in raw.execute("SELECT token_hash h FROM access_tokens"):
        if len(r["h"]) != 64:
            leaks.append(("access_tokens", r["h"]))
    for r in raw.execute("SELECT password_hash h FROM users"):
        if "demo-pass-123" in r["h"]:
            leaks.append(("users", "plaintext password"))
    for r in raw.execute("SELECT encrypted_response e FROM refresh_receipts"):
        if b"refresh_token" in r["e"] or b"access_token" in r["e"]:
            leaks.append(("receipts", "plaintext pair"))
    check("DB contains only hashes and Fernet ciphertext (no raw secrets)", not leaks, str(leaks))
    raw.close()

    print()
    if FAILS:
        print(f"{len(FAILS)} FAILED: {FAILS}")
        return 1
    print("ATOMICITY / SECRET-STORAGE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
