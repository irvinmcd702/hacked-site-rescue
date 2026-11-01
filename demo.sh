#!/usr/bin/env bash
# The whole story on a fresh lab: clean site → infected → scanned → cleaned
# → scanned again → a simulated day later, scanned once more.
# Run from the repository root: ./demo.sh
set -euo pipefail
cd "$(dirname "$0")"
source lab/.env

# Build the scanner for whatever runs this script.
goos=linux; ext=""
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) goos=windows; ext=".exe" ;; esac
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD:/src" -v hsr-gomod:/go/pkg/mod -w /src/scanner \
  -e GOOS=$goos -e CGO_ENABLED=0 golang:1.27-alpine go build -o bin/rescue$ext ./cmd/rescue
RESCUE=./scanner/bin/rescue$ext

export RESCUE_DB="wordpress:${DB_PASSWORD}@tcp(127.0.0.1:33061)/wordpress"
export RESCUE_ADMIN_USER="$ADMIN_USER" RESCUE_ADMIN_PASSWORD="$ADMIN_PASSWORD"

copy_site() { rm -rf lab/site-copy; docker cp rescue-lab-wordpress-1:/var/www/html lab/site-copy >/dev/null; }
scan() { # $1 = output dir, $2 = extra flags
  copy_site
  MSYS_NO_PATHCONV=1 $RESCUE -root lab/site-copy -url http://localhost:8090 -pages "/,/whitening-myths/" -out "$1" ${2:-} || true
}
wp() { (cd lab && MSYS_NO_PATHCONV=1 docker compose run --rm -T cli wp "$@"); }

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "1. Fresh lab"
(cd lab && docker compose down -v >/dev/null 2>&1 || true)
rm -rf report/out report/after report/day-later lab/backups/*
# The WP-CLI container runs as www-data and writes backups here.
mkdir -p lab/backups && chmod 777 lab/backups
./lab/seed.sh | tail -1

step "2. Infect"
./lab/infect.sh | tail -1
./lab/views.sh

step "3. Scan the infected site"
scan report/out "-log lab/logs/access.log"

step "3b. Why a quick cleanup fails: delete the visible injector only, wait for cron"
(cd lab && MSYS_NO_PATHCONV=1 docker compose run --rm -T --entrypoint sh cli -c "rm -f /var/www/html/wp-content/mu-plugins/wp-cache-helper.php" >/dev/null 2>&1)
echo "after deleting the file:"; ./lab/views.sh | sed -n 2p
wp cron event run wp_update_plugins_check >/dev/null 2>&1
echo "an hour later (cron ran):"; ./lab/views.sh | sed -n 2p

step "4. Build the cleanup plan"
MSYS_NO_PATHCONV=1 $RESCUE plan -findings report/out/findings.json -root lab/site-copy -owner "$ADMIN_USER" -out report/out

step "5. Apply it"
(cd lab && MSYS_NO_PATHCONV=1 docker compose run --rm -T --entrypoint sh cli /plan/plan.sh)

step "6. Scan again"
scan report/after
./lab/views.sh

step "7. A day later: run every scheduled task, load pages, scan once more"
wp cron event run --due-now >/dev/null || true
wp cron event list --fields=hook --format=csv | tail -n +2 | while read -r h; do wp cron event run "$h" >/dev/null 2>&1 || true; done
curl -s -o /dev/null http://localhost:8090/
scan report/day-later
./lab/views.sh

step "8. Owner report"
MSYS_NO_PATHCONV=1 $RESCUE report -site "Brightline Dental" -before report/out -after report/after -later report/day-later -out report/owner-report.html

step "Result"
for d in out after day-later; do
  printf '%-10s %s\n' "$d" "$(grep -m1 -E '^\*\*' report/$d/report.md)"
done
# The demo fails unless the site is clean after cleanup and stays clean.
for d in after day-later; do
  grep -q '^\*\*0 critical · 0 high · 0 medium' report/$d/report.md || { echo "FAIL: $d is not clean"; exit 1; }
done
echo "PASS"
