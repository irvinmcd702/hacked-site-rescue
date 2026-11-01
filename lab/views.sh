#!/usr/bin/env bash
# The same home page through three pairs of eyes: the logged-in owner,
# a visitor from Turkey (behind Cloudflare) and Googlebot.
set -euo pipefail
cd "$(dirname "$0")"
source .env
URL="${1:-http://localhost:8090/}"
jar=$(mktemp)
trap 'rm -f "$jar"' EXIT

curl -s -c "$jar" -b "wordpress_test_cookie=WP%20Cookie%20check" \
  --data-urlencode "log=${ADMIN_USER}" --data-urlencode "pwd=${ADMIN_PASSWORD}" \
  -d "wp-submit=Log+In&testcookie=1" -o /dev/null "http://localhost:8090/wp-login.php"

count() { grep -o 'casino\|bahis\|bonus' | wc -l | tr -d ' '; }

echo "owner (logged in): $(curl -s -b "$jar" "$URL" | count) spam words"
echo "visitor, Turkey:   $(curl -s -H 'CF-IPCountry: TR' "$URL" | count) spam words"
echo "Googlebot:         $(curl -s -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' "$URL" | count) spam words"
echo "visitor, US:       $(curl -s -H 'CF-IPCountry: US' "$URL" | count) spam words"
