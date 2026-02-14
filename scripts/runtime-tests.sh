#!/bin/sh
set -e

COMPOSE_FILE="deploy/docker-compose.test.yml"
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-deploy-runtime}
NETWORK_NAME="${PROJECT_NAME}_default"
CURL_IMAGE=${CURL_IMAGE:-curlimages/curl:8.5.0}
PYTHON_IMAGE=${PYTHON_IMAGE:-python:3.12-alpine}
ENV_FILE=${NSS_ENV_FILE:-.env}

dotenv_value() {
  key="$1"
  file="$2"
  [ -f "$file" ] || return 1
  value=$(sed -n "s/^${key}=//p" "$file" | head -n 1)
  [ -n "$value" ] || return 1
  printf '%s' "$value"
}

DOTENV_ADMIN_USER=$(dotenv_value NSS_ADMIN_BOOTSTRAP_USER "$ENV_FILE" || true)
DOTENV_ADMIN_PASS=$(dotenv_value NSS_ADMIN_BOOTSTRAP_PASSWORD "$ENV_FILE" || true)

ADMIN_USER=${NSS_ADMIN_BOOTSTRAP_USER:-${DOTENV_ADMIN_USER:-admin}}
ADMIN_PASS=${NSS_ADMIN_BOOTSTRAP_PASSWORD:-${DOTENV_ADMIN_PASS:-change-me}}

curl_net() {
  docker run --rm --network "$NETWORK_NAME" "$CURL_IMAGE" "$@"
}

json_get() {
  field="$1"
  docker run --rm -i "$PYTHON_IMAGE" python -c "import sys, json; data=json.load(sys.stdin); print(data${field})"
}

cleanup() {
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" up -d --build

echo "Waiting for master to be ready..."
for i in $(seq 1 30); do
  if curl_net -sf http://master:9100/readyz >/dev/null; then
    break
  fi
  sleep 2
  if [ "$i" -eq 30 ]; then
    echo "master not ready" >&2
    exit 1
  fi
done

curl_net -sf http://master:9100/healthz >/dev/null
curl_net -sf http://master:9100/readyz >/dev/null

BAD_CODE=$(curl_net -s -o /dev/null -w "%{http_code}" http://master:9000/)
if [ "$BAD_CODE" -eq 200 ]; then
  echo "expected unauthenticated S3 list to fail" >&2
  exit 1
fi

BAD_CODE=$(curl_net -s -o /dev/null -w "%{http_code}" \
  -X POST http://master:9001/admin/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"nope","password":"bad"}')
if [ "$BAD_CODE" -eq 200 ]; then
  echo "expected admin login failure" >&2
  exit 1
fi

ADMIN_RESPONSE=$(curl_net -s -w "\n%{http_code}" \
  -X POST http://master:9001/admin/v1/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}")
ADMIN_HTTP_CODE=$(printf '%s' "$ADMIN_RESPONSE" | tail -n 1)
ADMIN_JSON=$(printf '%s' "$ADMIN_RESPONSE" | sed '$d')
if [ "$ADMIN_HTTP_CODE" -ne 200 ]; then
  echo "admin login failed with HTTP ${ADMIN_HTTP_CODE}" >&2
  printf '%s\n' "$ADMIN_JSON" >&2
  exit 1
fi
if [ -z "$ADMIN_JSON" ]; then
  echo "admin login response body is empty" >&2
  exit 1
fi
ADMIN_TOKEN=$(printf '%s' "$ADMIN_JSON" | json_get "['token']")
if [ -z "$ADMIN_TOKEN" ]; then
  echo "admin login response does not contain token" >&2
  printf '%s\n' "$ADMIN_JSON" >&2
  exit 1
fi

curl_net -sf -H "Authorization: Bearer ${ADMIN_TOKEN}" http://master:9001/admin/v1/cluster/nodes >/dev/null

ME_CODE=$(curl_net -s -o /dev/null -w "%{http_code}" http://master:9001/console/v1/me)
if [ "$ME_CODE" -eq 200 ]; then
  echo "expected console /me unauthorized" >&2
  exit 1
fi

echo "Runtime tests completed"
