#!/usr/bin/env bash
# Builds the clean Brightline Dental site. Run from lab/: ./seed.sh
set -euo pipefail
cd "$(dirname "$0")"
source .env

wp() { MSYS_NO_PATHCONV=1 docker compose run --rm -T cli wp "$@"; }

docker compose up -d db wordpress
for _ in $(seq 1 60); do
  wp db check >/dev/null 2>&1 && break
  sleep 2
done

if ! wp core is-installed 2>/dev/null; then
  wp core install --url="http://localhost:8090" --title="Brightline Dental" \
    --admin_user="${ADMIN_USER}" --admin_password="${ADMIN_PASSWORD}" \
    --admin_email="owner@brightline-dental.example" --skip-email
fi

wp option update blogdescription "Family dentistry in Maple Grove"
wp rewrite structure '/%postname%/' --hard
wp theme activate twentytwentyfive
wp plugin delete hello akismet >/dev/null 2>&1 || true

# The outdated plugin the attacker will come in through.
MSYS_NO_PATHCONV=1 docker compose run --rm -T --entrypoint sh cli -c \
  'rm -rf /var/www/html/wp-content/plugins/simple-gallery-lite && cp -r /plugins/simple-gallery-lite /var/www/html/wp-content/plugins/'
wp plugin activate simple-gallery-lite

wp eval-file /content/pages.php
echo "clean site ready: http://localhost:8090"
