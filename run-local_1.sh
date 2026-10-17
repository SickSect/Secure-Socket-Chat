#!/bin/bash
# Usage: ./run-local.sh server|client
# Loads .env (app/.env or repo root) into the environment, then runs the Gradle task.
# Gradle tasks run with app/ as working dir, so relative paths like certs/... resolve correctly.
set -euo pipefail
cd "$(dirname "$0")"

ENV_FILE=""
for f in app/.env .env; do
  [ -f "$f" ] && ENV_FILE="$f" && break
done

if [ -n "$ENV_FILE" ]; then
  echo ">> loading $ENV_FILE"
  set -a
  # tr strips Windows CRLF line endings
  source <(tr -d '\r' < "$ENV_FILE")
  set +a
else
  echo ">> WARNING: no .env found, using defaults from application.yml"
fi

case "${1:-}" in
  server) ./gradlew bootRun ;;
  client) ./gradlew runClient --console=plain ;;
  *) echo "usage: $0 server|client"; exit 1 ;;
esac
