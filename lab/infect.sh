#!/usr/bin/env bash
# Infects the seeded lab site. Run from lab/ after ./seed.sh
set -euo pipefail
cd "$(dirname "$0")"

MSYS_NO_PATHCONV=1 docker compose run --rm -T cli wp eval-file /infect/infect.php
# 7. The web server log the attacker left behind.
mkdir -p logs
cp infect/access.log logs/access.log
echo "lab infected: http://localhost:8090"
