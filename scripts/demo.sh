#!/usr/bin/env bash
# End-to-end demo of refresh-token rotation, idempotent retry, theft detection
# and whole-family revocation. Works against the Docker Compose entry point
# (default) or the two direct process ports.
#
# Usage:
#   ./scripts/demo.sh                 # via Nginx load balancer :8080
#   BASE=http://localhost:8001 ./scripts/demo.sh   # direct to process A
set -euo pipefail

BASE="${BASE:-http://localhost:8080}"
USERNAME="${DEMO_USERNAME:-demo}"
PASSWORD="${DEMO_USER_PASSWORD:-demo-pass-123}"

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }
post() { curl -s -X POST "$BASE$1" -H 'Content-Type: application/json' -d "$2"; }
get() { curl -s "$BASE$1" -H "Authorization: Bearer $2"; }

say "0. health (two API processes behind the load balancer)"
curl -s "$BASE/health"; echo

say "1. login -> access token (60s) + refresh token (10min)"
LOGIN=$(post /api/auth/login "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")
echo "$LOGIN"
ACCESS=$(printf '%s' "$LOGIN" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
REFRESH=$(printf '%s' "$LOGIN" | python3 -c 'import sys,json;print(json.load(sys.stdin)["refresh_token"])')
FAMILY=$(printf '%s' "$LOGIN" | python3 -c 'import sys,json;print(json.load(sys.stdin)["family_id"])')
REQ_ID="req-demo-$(date +%s)"

say "2. query identity with the access token"
get /api/auth/me "$ACCESS"; echo

say "3. rotate: exchange the refresh token for a brand-new pair (request_id=$REQ_ID)"
ROTATED=$(post /api/auth/refresh "{\"refresh_token\":\"$REFRESH\",\"request_id\":\"$REQ_ID\"}")
echo "$ROTATED"
NEW_ACCESS=$(printf '%s' "$ROTATED" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
NEW_REFRESH=$(printf '%s' "$ROTATED" | python3 -c 'import sys,json;print(json.load(sys.stdin)["refresh_token"])')

say "4. idempotent RETRY with the SAME (old token, request_id) within 30s"
say "   -> must return the EXACT SAME token pair"
RETRY=$(post /api/auth/refresh "{\"refresh_token\":\"$REFRESH\",\"request_id\":\"$REQ_ID\"}")
echo "$RETRY"
if [ "$RETRY" = "$ROTATED" ]; then echo "RESULT: identical pair OK"; else echo "RESULT: MISMATCH FAIL"; fi

say "5. the OLD refresh token can no longer be used normally"
say "   attacker replays it with a DIFFERENT request_id -> whole family revoked"
post /api/auth/refresh "{\"refresh_token\":\"$REFRESH\",\"request_id\":\"req-attacker-0001\"}"; echo

say "6. every token of family $FAMILY is now rejected (refresh + identity)"
post /api/auth/refresh "{\"refresh_token\":\"$NEW_REFRESH\",\"request_id\":\"req-after-revoke\"}"; echo
get /api/auth/me "$NEW_ACCESS"; echo

say "7. idempotent retry CANNOT resurrect the revoked family"
post /api/auth/refresh "{\"refresh_token\":\"$REFRESH\",\"request_id\":\"$REQ_ID\"}"; echo

say "8. a SEPARATE login family is completely unaffected"
OTHER=$(post /api/auth/login "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")
OTHER_ACCESS=$(printf '%s' "$OTHER" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
get /api/auth/me "$OTHER_ACCESS"; echo

printf '\n\033[1;32mDemo complete. Interactive docs: %s/docs\033[0m\n' "$BASE"
