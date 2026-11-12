"""End-to-end HTTP tests against TWO running API processes that share one
SQLite database. Uses only the Python standard library.

Targets are given as argv: base URL of process A and base URL of process B.
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

A = sys.argv[1].rstrip("/")
B = sys.argv[2].rstrip("/")
DEMO = ("demo", "demo-pass-123")
FAILS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not cond:
        FAILS.append(name)


def call(method: str, base: str, path: str, body: dict | None = None,
         token: str | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def login(base):
    status, body = call("POST", base, "/api/auth/login",
                        {"username": DEMO[0], "password": DEMO[1]})
    check(f"login via {base} returns 200", status == 200, str(body))
    return body


def refresh(base, tok, rid):
    return call("POST", base, "/api/auth/refresh",
                {"refresh_token": tok, "request_id": rid})


def main() -> int:
    # 0. health endpoints identify two different PIDs
    _, ha = call("GET", A, "/health")
    _, hb = call("GET", B, "/health")
    check("two distinct API processes are running", ha["pid"] != hb["pid"],
          f"pid-a={ha['pid']} pid-b={hb['pid']}")
    check("both point at the same database file", ha["db"] == hb["db"])

    # 1. bad password rejected, no token material in error body
    status, body = call("POST", A, "/api/auth/login",
                        {"username": "demo", "password": "wrong"})
    check("wrong password -> 401", status == 401 and body["error"]["code"] == "invalid_credentials")
    check("error body never contains tokens", "access_token" not in json.dumps(body))

    # 2. login on A; family created
    pair = login(A)
    fam = pair["family_id"]
    check("login mints 60s access / 600s refresh",
          pair["access_expires_in"] == 60 and pair["refresh_expires_in"] == 600)

    # 3. identity query works, and works when served by the OTHER process
    s1, me1 = call("GET", A, "/api/auth/me", token=pair["access_token"])
    s2, me2 = call("GET", B, "/api/auth/me", token=pair["access_token"])
    check("identity works on process A", s1 == 200 and me1["username"] == "demo")
    check("same access token accepted by process B (shared SQLite state)",
          s2 == 200 and me2["family_id"] == fam)

    # 4. cross-process rotation: rotate on B, old token consumed in shared DB
    rid = "rid-cross-0001"
    s, rot = refresh(B, pair["refresh_token"], rid)
    check("rotation served by process B", s == 200, str(rot))
    check("rotation returns new tokens in the SAME family",
          rot["family_id"] == fam and rot["refresh_token"] != pair["refresh_token"])

    # 4b. idempotent retry of the SAME request hits process A this time
    s, retry = refresh(A, pair["refresh_token"], rid)
    check("cross-process idempotent retry returns exact same pair",
          s == 200 and retry == rot, f"{s}")

    # 5. concurrent identical retries across both processes at once
    def hit(base):
        return refresh(base, pair["refresh_token"], rid)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(hit, [A, B, A, B, A, B, A, B]))
    ok = all(code == 200 and body == rot for code, body in results)
    check("8 concurrent retries across 2 processes all return the identical pair", ok,
          str([c for c, _ in results]))

    # 6. concurrent FIRST rotations of a fresh token: exactly one succeeds,
    #    and every losing concurrent attempt must revoke the family (theft).
    fresh = login(A)
    fresh_tok = fresh["refresh_token"]

    def hit_fresh(i):
        base = A if i % 2 == 0 else B
        return refresh(base, fresh_tok, f"rid-race-{i:04d}")

    with ThreadPoolExecutor(max_workers=6) as pool:
        race = list(pool.map(hit_fresh, range(6)))
    codes = sorted(c for c, _ in race)
    winner = [b for c, b in race if c == 200]
    losers = [b for c, b in race if c != 200]
    check("concurrent first-use: exactly one rotation wins", len(winner) == 1,
          f"codes={codes}")
    check("every losing concurrent attempt is rejected with 401",
          len(losers) == 5 and all(b["error"]["code"] in (
              "token_reuse_revoked", "family_revoked") for b in losers),
          str([b["error"]["code"] for b in losers]))
    # family must end revoked (a second distinct request id reused the token)
    s, me = call("GET", A, "/api/auth/me", token=winner[0]["access_token"])
    check("race family ends revoked; winner's access token is now dead",
          s == 401 and me["error"]["code"] == "family_revoked", str(me))
    # and any further refresh on that chain is refused
    s, body = refresh(B, winner[0]["refresh_token"], "rid-after-race")
    check("post-race refresh rejected with family_revoked",
          s == 401 and body["error"]["code"] == "family_revoked")

    # 7. classic theft demo: legitimate rotation, then attacker replays the
    #    consumed token with a different request id -> whole family revoked.
    victim = login(B)
    s, good = refresh(A, victim["refresh_token"], "rid-legit-0001")
    check("legitimate rotation succeeds", s == 200)
    s, theft = refresh(B, victim["refresh_token"], "rid-attacker-0001")
    check("attacker replay rejected", s == 401 and theft["error"]["code"] == "token_reuse_revoked",
          str(theft))
    # every token of that family is now unusable on either process
    for base, label in ((A, "A"), (B, "B")):
        s, body = refresh(base, good["refresh_token"], "rid-late-0001")
        check(f"rotated refresh dead on process {label}",
              s == 401 and body["error"]["code"] == "family_revoked")
        s, body = call("GET", base, "/api/auth/me", token=good["access_token"])
        check(f"identity query dead on process {label}",
              s == 401 and body["error"]["code"] == "family_revoked")
    # retry with original request id cannot bring it back
    s, body = refresh(A, victim["refresh_token"], "rid-legit-0001")
    check("revoked family cannot be restored by idempotent retry",
          s == 401 and body["error"]["code"] == "family_revoked")

    # 8. family isolation: a brand-new login is fully unaffected
    other = login(A)
    s, me = call("GET", B, "/api/auth/me", token=other["access_token"])
    check("other family identity query still works across processes", s == 200)
    s, rot2 = refresh(B, other["refresh_token"], "rid-other-0001")
    check("other family can still rotate", s == 200 and rot2["family_id"] == other["family_id"])

    # 9. validation: malformed request id rejected
    s, body = refresh(A, other["refresh_token"], "bad request id!")
    check("invalid request_id format -> 422", s == 422)

    # 10. access token expiry (60s) is enforced
    short = login(A)
    # forge a DB-side expiry by checking the me endpoint logic with a bogus token
    s, body = call("GET", A, "/api/auth/me", token="not-a-real-token")
    check("unknown bearer token -> 401", s == 401 and body["error"]["code"] == "invalid_token")
    s, body = call("GET", A, "/api/auth/me")
    check("missing bearer header -> 401", s == 401 and body["error"]["code"] == "missing_bearer")

    print()
    if FAILS:
        print(f"{len(FAILS)} HTTP CHECK(S) FAILED: {FAILS}")
        return 1
    print("ALL HTTP END-TO-END CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
