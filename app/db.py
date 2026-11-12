"""SQLite persistence layer.

A single database file is shared by both API processes. Correctness across
processes and restarts rests on:

* WAL journal mode + busy timeout, so readers never block writers and a
  second process simply waits instead of failing with "database is locked".
* Every security-sensitive mutation (token rotation, retry receipt write,
  whole-family revocation) runs inside one ``BEGIN IMMEDIATE`` transaction and
  is committed atomically — a crash leaves either the old pair or the new
  pair, never half of a rotation.
"""
from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Iterator

from .config import get_settings
from .security import hash_password

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS token_families (
    id             INTEGER PRIMARY KEY,
    user_id        INTEGER NOT NULL REFERENCES users(id),
    revoked        INTEGER NOT NULL DEFAULT 0,
    revoke_reason  TEXT,
    created_at     INTEGER NOT NULL,
    revoked_at     INTEGER
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id                 INTEGER PRIMARY KEY,
    family_id          INTEGER NOT NULL REFERENCES token_families(id),
    token_hash         TEXT NOT NULL UNIQUE,
    consumed           INTEGER NOT NULL DEFAULT 0,
    expires_at         INTEGER NOT NULL,
    created_at         INTEGER NOT NULL,
    consumed_at        INTEGER
);

CREATE TABLE IF NOT EXISTS access_tokens (
    id          INTEGER PRIMARY KEY,
    family_id   INTEGER NOT NULL REFERENCES token_families(id),
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL
);

-- Idempotency receipts, one row per successfully consumed refresh token.
-- The old refresh token hash plus request_id uniquely identify a retry,
-- and the whole new pair is stored Fernet-encrypted.
CREATE TABLE IF NOT EXISTS refresh_receipts (
    id                  INTEGER PRIMARY KEY,
    family_id           INTEGER NOT NULL REFERENCES token_families(id),
    old_refresh_hash    TEXT NOT NULL,
    request_id          TEXT NOT NULL,
    encrypted_response  BLOB NOT NULL,
    created_at          INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL,
    UNIQUE(old_refresh_hash, request_id)
);

CREATE INDEX IF NOT EXISTS idx_refresh_family  ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_access_family   ON access_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_receipt_expiry  ON refresh_receipts(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_expiry  ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_access_expiry   ON access_tokens(expires_at);
"""


def _connect() -> sqlite3.Connection:
    settings = get_settings()
    os.makedirs(os.path.dirname(settings.db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(
        settings.sqlite_url,
        uri=True,
        timeout=30.0,
        isolation_level=None,  # explicit transaction control
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    # busy_timeout must be set before any statement that might block.
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    # WAL is a persistent database property; when two processes boot at the
    # same time the mode switch can briefly collide, so retry until it sticks.
    for attempt in range(50):
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            break
        except sqlite3.OperationalError:
            if attempt == 49:
                raise
            time.sleep(0.1)
    conn.execute("PRAGMA synchronous=FULL")
    return conn


@contextmanager
def db_connection() -> Iterator[sqlite3.Connection]:
    """A short-lived connection per request (FastAPI dependency)."""
    conn = _connect()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def immediate_tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Acquire the SQLite write lock up front; commit on success, rollback on error.

    The body may also commit or roll back manually (e.g. a theft revocation
    that must be persisted before an HTTP error is raised); both states are
    detected so the context never issues a second, failing statement.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        # Only commit if the body did not end the transaction itself.
        if conn.in_transaction:
            conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def init_db() -> None:
    """Create schema and seed the demo account. Safe to run on every boot."""
    settings = get_settings()
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            # NB: sqlite3 .executescript() would issue an implicit COMMIT,
            # which would break our explicit transaction; execute statements
            # one by one instead.
            for stmt in _SCHEMA.split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(stmt)
            now = int(time.time())
            row = conn.execute(
                "SELECT id FROM users WHERE username = ?", (settings.demo_username,)
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO users (username, password_hash, created_at) "
                    "VALUES (?, ?, ?)",
                    (
                        settings.demo_username,
                        hash_password(settings.demo_password),
                        now,
                    ),
                )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


def janitor_once() -> int:
    """Hard-delete rows whose security relevance has fully expired.

    Revoked family rows and consumed refresh rows are *retained* past expiry
    (they must keep rejecting retries/reuse forever); only genuinely expired
    non-security data is removed. Returns the number of deleted rows.
    """
    settings = get_settings()
    now = int(time.time())
    cutoff = now - settings.retention
    deleted = 0
    conn = _connect()
    try:
        with immediate_tx(conn):
            cur = conn.execute(
                "DELETE FROM refresh_receipts WHERE expires_at < ?", (now,)
            )
            deleted += cur.rowcount
            # Access tokens: once expired they can no longer authenticate;
            # keep them for retention for forensics, then drop.
            cur = conn.execute(
                "DELETE FROM access_tokens WHERE expires_at < ?", (cutoff,)
            )
            deleted += cur.rowcount
            # Consumed refresh tokens may only be dropped long after expiry
            # AND only when no receipt references them anymore.
            cur = conn.execute(
                """
                DELETE FROM refresh_tokens
                 WHERE consumed = 1
                   AND expires_at < ?
                   AND token_hash NOT IN (SELECT old_refresh_hash FROM refresh_receipts)
                """,
                (cutoff,),
            )
            deleted += cur.rowcount
    finally:
        conn.close()
    return deleted
