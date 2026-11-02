#!/usr/bin/env bash
# DFIR-IRIS (case management) in Docker on WSL, pinned, bound to localhost only.
#   ./lab/iris/setup-iris.sh          # first run: clone, generate secrets, start; later runs: just start
# UI: https://localhost:8444  (user "administrator", password in lab/.secrets/iris.env)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TAG="${IRIS_TAG:-v2.4.29}"
PORT="${IRIS_PORT:-8444}"
DIR="$ROOT/lab/iris/iris-web"
ENVF="$ROOT/lab/.secrets/iris.env"

[[ -d "$DIR" ]] || git clone -q --depth 1 --branch "$TAG" https://github.com/dfir-iris/iris-web.git "$DIR"

if [[ ! -f "$ENVF" ]]; then
  r() { openssl rand -hex "$1"; }
  (umask 077; sed -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(r 24)|" \
      -e "s|^POSTGRES_ADMIN_PASSWORD=.*|POSTGRES_ADMIN_PASSWORD=$(r 24)|" \
      -e "s|^IRIS_SECRET_KEY=.*|IRIS_SECRET_KEY=$(r 32)|" \
      -e "s|^IRIS_SECURITY_PASSWORD_SALT=.*|IRIS_SECURITY_PASSWORD_SALT=$(r 16)|" \
      -e "s|^INTERFACE_HTTPS_PORT=.*|INTERFACE_HTTPS_PORT=$PORT|" \
      -e "s|^SERVER_NAME=.*|SERVER_NAME=localhost|" \
      -e "s|^#IRIS_ADM_PASSWORD=.*|IRIS_ADM_PASSWORD=Iris-$(r 12)!|" \
      -e "s|^#IRIS_ADM_API_KEY=.*|IRIS_ADM_API_KEY=$(r 32)|" \
      -e "s|^#IRIS_ADM_EMAIL=.*|IRIS_ADM_EMAIL=admin@lab.local|" \
      -e "s|^#IRIS_ADM_USERNAME=.*|IRIS_ADM_USERNAME=administrator|" \
      "$DIR/.env.model" > "$ENVF")
  echo "generated $ENVF"
fi
install -m 600 "$ENVF" "$DIR/.env"

# Publish on localhost only (the upstream file binds every interface; with WSL mirrored networking
# that would include the home network). !override replaces the list instead of appending to it.
cat > "$DIR/docker-compose.override.yml" <<YML
services:
  nginx:
    ports: !override
      - "127.0.0.1:${PORT}:${PORT}"
YML

cd "$DIR"
docker compose pull -q
docker compose up -d
echo "waiting for IRIS on https://localhost:${PORT} ..."
for i in $(seq 1 90); do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:${PORT}/login" || true)
  [[ "$code" == "200" ]] && { echo "IRIS is up (https://localhost:${PORT}, user administrator)"; exit 0; }
  sleep 5
done
echo "IRIS did not come up; check: docker compose -f $DIR/docker-compose.yml logs app" >&2; exit 1
