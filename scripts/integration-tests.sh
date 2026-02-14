#!/bin/sh
set -e

COMPOSE_FILE="deploy/docker-compose.test.yml"
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-$(basename "$(dirname "$COMPOSE_FILE")")}
NETWORK_NAME="${PROJECT_NAME}_default"
RUST_IMAGE=${RUST_IMAGE:-}
TEST_IMAGE=${NSS_TEST_IMAGE:-}
INTEGRATION_COVERAGE_LINES=${NSS_INTEGRATION_COVERAGE_LINES:-100}
INTEGRATION_COVERAGE_FUNCTIONS=${NSS_INTEGRATION_COVERAGE_FUNCTIONS:-100}
INTEGRATION_COVERAGE_REGIONS=${NSS_INTEGRATION_COVERAGE_REGIONS:-100}
TEST_THREADS=${NSS_TEST_THREADS:-1}
TEST_PROFILE=${NSS_TEST_PROFILE:-test}
INTEGRATION_SHARDS=${NSS_TEST_SHARDS:-1}

if [ "$INTEGRATION_SHARDS" -gt 1 ]; then
  exec ./scripts/integration-tests-sharded.sh
fi

ensure_test_image() {
  image="$1"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    NSS_TEST_IMAGE="$image" ./scripts/build-test-image.sh
  fi
}

PROFILE_ARGS=""
case "$TEST_PROFILE" in
  release) PROFILE_ARGS="--release" ;;
  test) PROFILE_ARGS="" ;;
  *) PROFILE_ARGS="--profile ${TEST_PROFILE}" ;;
esac

cleanup() {
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [ -n "$TEST_IMAGE" ]; then
  ensure_test_image "$TEST_IMAGE"
else
  if [ -n "$RUST_IMAGE" ]; then
    TEST_IMAGE="$RUST_IMAGE"
  else
    TEST_IMAGE="nss-test-runner:latest"
    ensure_test_image "$TEST_IMAGE"
  fi
fi

docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true

docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" --profile redis --profile rabbitmq up -d postgres redis rabbitmq

echo "Waiting for postgres to be ready..."
for i in $(seq 1 30); do
  if docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" \
    exec -T postgres pg_isready -U nss -d nss >/dev/null 2>&1; then
    break
  fi
  sleep 2
  if [ "$i" -eq 30 ]; then
    echo "postgres not ready" >&2
    exit 1
  fi
done

echo "Waiting for redis to be ready..."
for i in $(seq 1 30); do
  if docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" exec -T redis redis-cli ping >/dev/null 2>&1; then
    break
  fi
  sleep 2
  if [ "$i" -eq 30 ]; then
    echo "redis not ready" >&2
    exit 1
  fi
done

echo "Waiting for rabbitmq to be ready..."
for i in $(seq 1 30); do
  if docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" \
    exec -T rabbitmq rabbitmq-diagnostics -q ping >/dev/null 2>&1; then
    break
  fi
  sleep 2
  if [ "$i" -eq 30 ]; then
    echo "rabbitmq not ready" >&2
    exit 1
  fi
done

docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" run --rm master /app/nss --migrate-only

docker run --rm \
  --network "$NETWORK_NAME" \
  -v "$(pwd):/app" \
  -v "$(pwd)/.rustup:/root/.rustup" \
  -w /app \
  -e CARGO_HOME=/app/.cargo \
  -e RUSTUP_NONINTERACTIVE=1 \
  -e RUST_BACKTRACE=1 \
  -e NSS_POSTGRES_DSN=postgres://nss:nss@postgres:5432/nss?sslmode=disable \
  -e NSS_REDIS_URL=redis://redis:6379 \
  -e NSS_RABBIT_URL=amqp://rabbitmq:5672/%2f \
  -e CARGO_INCREMENTAL=1 \
  "$TEST_IMAGE" \
  sh -c "if ! cargo llvm-cov --version >/dev/null 2>&1; then cargo install cargo-llvm-cov --locked; fi && \
    if ! rustup component list --installed | grep -q '^llvm-tools-preview'; then \
      rustup component add llvm-tools-preview; \
    fi && \
    cargo llvm-cov -p nss_core ${PROFILE_ARGS} \
      --fail-under-lines ${INTEGRATION_COVERAGE_LINES} \
      --fail-under-functions ${INTEGRATION_COVERAGE_FUNCTIONS} \
      --fail-under-regions ${INTEGRATION_COVERAGE_REGIONS} -- --test-threads=${TEST_THREADS}"
