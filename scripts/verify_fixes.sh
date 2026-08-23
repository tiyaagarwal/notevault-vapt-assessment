#!/usr/bin/env bash
# Automates the retest evidence in report/VAPT_Report.md §4 — replays each
# finding's PoC against the vulnerable build (default :4001) and the fixed
# build (default :4002) and asserts the fixed build is no longer exploitable.
set -uo pipefail

VULN_URL="${VULN_URL:-http://localhost:4001}"
FIXED_URL="${FIXED_URL:-http://localhost:4002}"
PASS=0
FAIL=0

check() {
  local desc="$1" got="$2" want="$3"
  if [ "$got" = "$want" ]; then
    echo "  PASS - $desc"
    PASS=$((PASS + 1))
  else
    echo "  FAIL - $desc (expected '$want', got '$got')"
    FAIL=$((FAIL + 1))
  fi
}

echo "== VULN-05: unauthenticated debug endpoint on fixed build should be gone =="
status=$(curl -s -o /dev/null -w "%{http_code}" "$FIXED_URL/api/debug/config")
check "GET /api/debug/config returns 404" "$status" "404"

echo "== Logging in as alice on both builds =="
curl -s -c /tmp/vapt_vuln_cookies.txt -X POST "$VULN_URL/api/login" \
  -H "Content-Type: application/json" -d '{"username":"alice","password":"alice123"}' >/dev/null
curl -s -c /tmp/vapt_fixed_cookies.txt -X POST "$FIXED_URL/api/login" \
  -H "Content-Type: application/json" -d '{"username":"alice","password":"alice123"}' >/dev/null

echo "== VULN-03: IDOR - alice requesting note 3 (admin's) on the fixed build =="
status=$(curl -s -o /dev/null -w "%{http_code}" -b /tmp/vapt_fixed_cookies.txt "$FIXED_URL/api/notes/3")
check "GET /api/notes/3 as alice returns 403" "$status" "403"

echo "== VULN-01: SQLi UNION payload against /api/search on the fixed build =="
resp=$(curl -s -b /tmp/vapt_fixed_cookies.txt -G "$FIXED_URL/api/search" \
  --data-urlencode "q=%' UNION SELECT id,password_hash,username FROM users-- ")
check "search response is an empty array" "$resp" "[]"

echo "== VULN-02: stored XSS payload is escaped on render on the fixed build =="
curl -s -b /tmp/vapt_fixed_cookies.txt -X POST "$FIXED_URL/api/notes/1/comments" \
  -H "Content-Type: application/json" -d '{"body":"<script>alert(1)</script>"}' >/dev/null
rendered=$(curl -s -b /tmp/vapt_fixed_cookies.txt "$FIXED_URL/notes/1")
if echo "$rendered" | grep -q '&lt;script&gt;alert(1)&lt;/script&gt;'; then
  check "comment body is HTML-escaped" "escaped" "escaped"
else
  check "comment body is HTML-escaped" "NOT escaped" "escaped"
fi

echo "== VULN-04: old vulnerable-build JWT secret no longer forges a valid session =="
script_dir="$(cd "$(dirname "$0")" && pwd)"
forged=$(NODE_PATH="$script_dir/../fixed/node_modules" node -e "console.log(require('jsonwebtoken').sign({id:3,username:'admin',role:'admin'}, 'notevault_secret_123'))")
status=$(curl -s -o /dev/null -w "%{http_code}" --cookie "token=$forged" "$FIXED_URL/api/notes/3")
check "forged token against fixed build returns 401" "$status" "401"

rm -f /tmp/vapt_vuln_cookies.txt /tmp/vapt_fixed_cookies.txt

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
