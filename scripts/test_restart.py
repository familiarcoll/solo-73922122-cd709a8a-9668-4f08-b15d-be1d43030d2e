"""Restart-persistence + atomicity tests against already-running processes.

Scenario A (persistence):
  login -> rotate -> trigger theft -> prove revocation; then the test asks
  the operator (or a wrapper script) to restart BOTH processes and re-proves
  that revocation, consumed tokens and idempotent receipts survive.

Scenario B (no half rotation):
  For every rotation, count rows inside the family and assert the invariant
  "exactly one unconsumed, unexpired refresh token exists at any time".

Usage: python scripts/test_restart.py <baseA> <baseB> [--after-restart]
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request

A, B = sys.argv[1].rstrip("/"), sys.argv[2].rstrip("/")
AFTER_RESTART = "--after-restart" in sys.argv
DB = os.environ["AUTH_DB_PATH"]
FAILS: list[str] = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not cond:
        FAILS.append(name)


def call(method, base, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def active_refresh_count(family_id):
    with db() as c:
        return c.execute(
            "SELECT COUNT(*) n FROM refresh_tokens "
            "WHERE family_id=? AND consumed=0 AND expires_at>?",
            (family_id, int(time.time())),
        ).fetchone()["n"]


def main():
    if not AFTER_RESTART:
        # --- build a revoked family and remember its identifiers in a file ---
        s, login = call("POST", A, "/api/auth/login",
                        {"username": "demo", "password": "demo-pass-123"})
        fam = login["family_id"]
        s, rot = call("POST", B, "/api/auth/refresh",
                      {"refresh_token": login["refresh_token"], "request_id": "rid-persist-1"})
        assert s == 200
        # invariant after one rotation: exactly one active refresh token
        check("post-rotation invariant: exactly 1 active refresh token",
              active_refresh_count(fam) == 1)
        # theft
        s, _ = call("POST", A, "/api/auth/refresh",
                    {"refresh_token": login["refresh_token"], "request_id": "rid-thief-xx"})
        check("theft triggers revocation", s == 401)
        with db() as c:
            revoked = c.execute("SELECT revoked FROM token_families WHERE id=?",
                                (fam,)).fetchone()["revoked"]
        check("family revoked before restart", revoked == 1)
        with open("/tmp/restart_state.json", "w") as f:
            json.dump({
                "family_id": fam,
                "old_refresh": login["refresh_token"],
                "new_refresh": rot["refresh_token"],
                "new_access": rot["access_token"],
                "request_id": "rid-persist-1",
            }, f)
        print("\nState saved. Restart both processes now, then re-run with --after-restart")
    else:
        st = json.load(open("/tmp/restart_state.json"))
        fam = st["family_id"]
        # revocation survived
        with db() as c:
            row = c.execute(
                "SELECT revoked, revoke_reason FROM token_families WHERE id=?", (fam,)
            ).fetchone()
        check("revocation persisted across restart",
              row["revoked"] == 1 and row["revoke_reason"] == "refresh_token_reuse_detected")
        # refresh rejected on both processes after restart
        for base, label in ((A, "A"), (B, "B")):
            s, body = call("POST", base, "/api/auth/refresh",
                           {"refresh_token": st["new_refresh"], "request_id": "rid-post-reboot"})
            check(f"refresh rejected on process {label} after restart",
                  s == 401 and body["error"]["code"] == "family_revoked")
            s, body = call("GET", base, "/api/auth/me", token=st["new_access"])
            check(f"identity rejected on process {label} after restart",
                  s == 401 and body["error"]["code"] == "family_revoked")
        # idempotent retry cannot restore
        s, body = call("POST", A, "/api/auth/refresh",
                       {"refresh_token": st["old_refresh"], "request_id": st["request_id"]})
        check("retry cannot resurrect revoked family after restart",
              s == 401 and body["error"]["code"] == "family_revoked")

        # a fresh, healthy family still works across both restarted processes
        s, login = call("POST", B, "/api/auth/login",
                        {"username": "demo", "password": "demo-pass-123"})
        check("login works after restart", s == 200)
        s, me = call("GET", A, "/api/auth/me", token=login["access_token"])
        check("identity cross-process after restart", s == 200 and me["family_id"] == login["family_id"])
        s, rot = call("POST", A, "/api/auth/refresh",
                      {"refresh_token": login["refresh_token"], "request_id": "rid-reboot-rot"})
        check("rotation works after restart", s == 200)
        check("invariant holds: exactly 1 active refresh token",
              active_refresh_count(login["family_id"]) == 1)
        # idempotent receipt persisted across restart too
        s, retry = call("POST", B, "/api/auth/refresh",
                        {"refresh_token": login["refresh_token"], "request_id": "rid-reboot-rot"})
        check("idempotent receipt survived restart (same pair via other process)",
              s == 200 and retry == rot)

    print()
    if FAILS:
        print(f"{len(FAILS)} FAILED: {FAILS}")
        return 1
    print("RESTART TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
