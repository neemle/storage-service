#!/bin/sh
set -eu

COMPOSE_FILE="deploy/docker-compose.test.yml"
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-deploy-memcheck}
NETWORK_NAME="${PROJECT_NAME}_default"
TOOL_IMAGE=${NSS_MEMCHECK_IMAGE:-nss-memcheck-tools:latest}
RESULTS_ROOT=${NSS_TEST_RESULTS_DIR:-test-results}
RESULTS_DIR="${RESULTS_ROOT}/memcheck"
VALGRIND_CONTAINER="${PROJECT_NAME}-valgrind-app"
DATA_DIR_IN_CONTAINER="/app/scripts/tmp/memcheck-data"
POSTGRES_DSN="postgres://nss:nss@postgres:5432/nss?sslmode=disable&connect_timeout=120"
ENV_FILE=${NSS_ENV_FILE:-.env}
SUPPRESSIONS_FILE="/app/scripts/valgrind.supp"

dotenv_value() {
  key="$1"
  file="$2"
  [ -f "$file" ] || return 1
  value=$(sed -n "s/^${key}=//p" "$file" | head -n 1)
  [ -n "$value" ] || return 1
  printf '%s' "$value"
}

ensure_tool_image() {
  if docker image inspect "$TOOL_IMAGE" >/dev/null 2>&1; then
    return
  fi
  docker build -f deploy/Dockerfile.memcheck -t "$TOOL_IMAGE" .
}

wait_for_postgres() {
  i=1
  while [ "$i" -le 30 ]; do
    if docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" \
      exec -T postgres pg_isready -U nss -d nss >/dev/null 2>&1; then
      return
    fi
    i=$((i + 1))
    sleep 2
  done
  echo "postgres not ready" >&2
  exit 1
}

curl_net() {
  docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.5.0 --max-time 30 "$@"
}

parse_leaks() {
  log_file="$1"
  summary_file="$2"
  definitely=$(awk '/definitely lost:/ {gsub(",", "", $4); print $4; exit}' "$log_file")
  indirectly=$(awk '/indirectly lost:/ {gsub(",", "", $4); print $4; exit}' "$log_file")
  possibly=$(awk '/possibly lost:/ {gsub(",", "", $4); print $4; exit}' "$log_file")
  [ -n "${definitely}" ] || definitely=-1
  [ -n "${indirectly}" ] || indirectly=-1
  [ -n "${possibly}" ] || possibly=-1
  {
    echo "definitely_lost_bytes=${definitely}"
    echo "indirectly_lost_bytes=${indirectly}"
    echo "possibly_lost_bytes=${possibly}"
  } > "$summary_file"
  [ "$definitely" -eq 0 ] && [ "$indirectly" -eq 0 ] && [ "$possibly" -eq 0 ]
}

parse_error_summary() {
  log_file="$1"
  summary_file="$2"
  errors=$(awk '/ERROR SUMMARY:/ {print $4; exit}' "$log_file")
  [ -n "${errors}" ] || errors=-1
  echo "error_summary=${errors}" >> "$summary_file"
  [ "$errors" -eq 0 ]
}

stop_memcheck_app() {
  if ! docker ps --format '{{.Names}}' | grep -qx "$VALGRIND_CONTAINER"; then
    return
  fi

  docker exec "$VALGRIND_CONTAINER" sh -c "pkill -TERM nss || true" >/dev/null 2>&1 || true

  i=1
  while [ "$i" -le 30 ]; do
    if ! docker ps --format '{{.Names}}' | grep -qx "$VALGRIND_CONTAINER"; then
      return
    fi
    i=$((i + 1))
    sleep 1
  done

  docker stop -t 30 "$VALGRIND_CONTAINER" >/dev/null 2>&1 || true
}

cleanup() {
  docker rm -f "$VALGRIND_CONTAINER" >/dev/null 2>&1 || true
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" \
    --profile redis --profile rabbitmq down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$RESULTS_DIR"
mkdir -p scripts/tmp/memcheck-data
ensure_tool_image

SECRET_KEY=$(dotenv_value NSS_SECRET_ENCRYPTION_KEY_BASE64 "$ENV_FILE" || true)
JWT_KEY=$(dotenv_value NSS_JWT_SIGNING_KEY_BASE64 "$ENV_FILE" || true)
INTERNAL_TOKEN=$(dotenv_value NSS_INTERNAL_SHARED_TOKEN "$ENV_FILE" || true)
ADMIN_USER=$(dotenv_value NSS_ADMIN_BOOTSTRAP_USER "$ENV_FILE" || true)
ADMIN_PASS=$(dotenv_value NSS_ADMIN_BOOTSTRAP_PASSWORD "$ENV_FILE" || true)
[ -n "$SECRET_KEY" ] || SECRET_KEY="DuxkyH7t7fs6TnMN+oEv0RZ++KvFwQJLulQm9AyAAmo="
[ -n "$JWT_KEY" ] || JWT_KEY="r/lEP0YY6tXlX0ITS2yte4A6dizsXfaQyEaUllG9cNw="
[ -n "$INTERNAL_TOKEN" ] || INTERNAL_TOKEN="1739d09514c62ad91499f636350c4a3d9d15644aaf794713"
[ -n "$ADMIN_USER" ] || ADMIN_USER="admin"
[ -n "$ADMIN_PASS" ] || ADMIN_PASS="LocalAdmin!2026UseStrongSecret"

docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" \
  --profile redis --profile rabbitmq down -v >/dev/null 2>&1 || true
docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" --profile redis --profile rabbitmq up -d postgres redis rabbitmq
wait_for_postgres

docker run --rm \
  --network "$NETWORK_NAME" \
  -v "$(pwd):/app" \
  -w /app \
  -e NSS_MODE=master \
  -e NSS_POSTGRES_DSN="$POSTGRES_DSN" \
  -e NSS_DATA_DIRS="$DATA_DIR_IN_CONTAINER" \
  -e NSS_INTERNAL_ADVERTISE=http://nss-memcheck-app:9003 \
  -e NSS_SECRET_ENCRYPTION_KEY_BASE64="$SECRET_KEY" \
  -e NSS_JWT_SIGNING_KEY_BASE64="$JWT_KEY" \
  -e NSS_INTERNAL_SHARED_TOKEN="$INTERNAL_TOKEN" \
  -e NSS_ADMIN_BOOTSTRAP_USER="$ADMIN_USER" \
  -e NSS_ADMIN_BOOTSTRAP_PASSWORD="$ADMIN_PASS" \
  -e NSS_ADMIN_BOOTSTRAP_FORCE_PASSWORD=true \
  -e NSS_INSECURE_DEV=true \
  "$TOOL_IMAGE" \
  sh -c '/usr/local/cargo/bin/cargo run -p nss -- --migrate-only'

docker run --rm \
  --network "$NETWORK_NAME" \
  -v "$(pwd):/app" \
  -w /app \
  "$TOOL_IMAGE" \
  sh -c '/usr/local/cargo/bin/cargo build -p nss'

rm -f "${RESULTS_DIR}/valgrind.log" "${RESULTS_DIR}/summary.txt" "${RESULTS_DIR}/app.log"
docker rm -f "$VALGRIND_CONTAINER" >/dev/null 2>&1 || true

docker run -d \
  --name "$VALGRIND_CONTAINER" \
  --network "$NETWORK_NAME" \
  -v "$(pwd):/app" \
  -w /app \
  -e NSS_MODE=master \
  -e NSS_POSTGRES_DSN="$POSTGRES_DSN" \
  -e NSS_DATA_DIRS="$DATA_DIR_IN_CONTAINER" \
  -e NSS_INTERNAL_ADVERTISE=http://nss-memcheck-app:9003 \
  -e NSS_SECRET_ENCRYPTION_KEY_BASE64="$SECRET_KEY" \
  -e NSS_JWT_SIGNING_KEY_BASE64="$JWT_KEY" \
  -e NSS_INTERNAL_SHARED_TOKEN="$INTERNAL_TOKEN" \
  -e NSS_ADMIN_BOOTSTRAP_USER="$ADMIN_USER" \
  -e NSS_ADMIN_BOOTSTRAP_PASSWORD="$ADMIN_PASS" \
  -e NSS_ADMIN_BOOTSTRAP_FORCE_PASSWORD=true \
  -e NSS_INSECURE_DEV=true \
  "$TOOL_IMAGE" \
  sh -c '
    set -e
    exec valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
      --suppressions='"$SUPPRESSIONS_FILE"' \
      --log-file=/tmp/valgrind.log target/debug/nss
  ' >/dev/null

sleep "${NSS_MEMCHECK_WARMUP_SECONDS:-20}"

if ! docker ps --format '{{.Names}}' | grep -qx "$VALGRIND_CONTAINER"; then
  docker logs "$VALGRIND_CONTAINER" > "${RESULTS_DIR}/app.log" 2>&1 || true
  echo "memcheck app exited before warmup completed" >&2
  exit 1
fi

curl_net -sf http://nss-memcheck-app:9100/healthz >/dev/null 2>&1 || true
curl_net -sf http://nss-memcheck-app:9100/metrics >/dev/null 2>&1 || true

stop_memcheck_app
docker logs "$VALGRIND_CONTAINER" > "${RESULTS_DIR}/app.log" 2>&1 || true
docker cp "${VALGRIND_CONTAINER}:/tmp/valgrind.log" "${RESULTS_DIR}/valgrind.log" >/dev/null 2>&1 || true

if [ ! -f "${RESULTS_DIR}/valgrind.log" ]; then
  echo "valgrind log not found at ${RESULTS_DIR}/valgrind.log" >&2
  exit 1
fi

if ! parse_leaks "${RESULTS_DIR}/valgrind.log" "${RESULTS_DIR}/summary.txt"; then
  cat "${RESULTS_DIR}/summary.txt"
  echo "memory leak check failed" >&2
  exit 1
fi

if ! parse_error_summary "${RESULTS_DIR}/valgrind.log" "${RESULTS_DIR}/summary.txt"; then
  cat "${RESULTS_DIR}/summary.txt"
  echo "memcheck error summary is non-zero" >&2
  exit 1
fi

cat "${RESULTS_DIR}/summary.txt"
echo "memory leak check passed"
