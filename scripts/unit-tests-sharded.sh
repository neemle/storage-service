#!/bin/sh
set -e

COMPOSE_FILE="deploy/docker-compose.test.yml"
BASE_PROJECT=${COMPOSE_PROJECT_NAME:-$(basename "$(dirname "$COMPOSE_FILE")")}
SHARDS=${NSS_TEST_SHARDS:-6}
TEST_IMAGE=${NSS_TEST_IMAGE:-nss-test-runner:latest}
UNIT_COVERAGE_LINES=${NSS_UNIT_COVERAGE_LINES:-100}
UNIT_COVERAGE_FUNCTIONS=${NSS_UNIT_COVERAGE_FUNCTIONS:-100}
UNIT_COVERAGE_REGIONS=${NSS_UNIT_COVERAGE_REGIONS:-100}
TEST_THREADS=${NSS_TEST_THREADS:-1}
TEST_PROFILE=${NSS_TEST_PROFILE:-test}

if [ "$SHARDS" -le 1 ]; then
  exec ./scripts/unit-tests.sh
fi

ensure_test_image() {
  image="$1"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    NSS_TEST_IMAGE="$image" ./scripts/build-test-image.sh
  fi
}

env_profile_args() {
  case "$TEST_PROFILE" in
    release) echo "--release" ;;
    test) echo "" ;;
    *) echo "--profile ${TEST_PROFILE}" ;;
  esac
}

PROFILE_ARGS=$(env_profile_args)

ensure_test_image "$TEST_IMAGE"

TMP_DIR="scripts/tmp/unit-shards"
mkdir -p "$TMP_DIR"
TEST_LIST="$TMP_DIR/tests.list"
TEST_BIN_PATH="$TMP_DIR/test-binary.path"
rm -f "$TMP_DIR"/exit-* "$TMP_DIR"/shard-*.log 2>/dev/null || true

# Clean old coverage data
rm -f target/llvm-cov-target/*.profraw 2>/dev/null || true
mkdir -p target/llvm-cov-build

# Build the instrumented test binary once, then list tests from it.

docker run --rm \
  -v "$(pwd):/app" \
  -v "$(pwd)/.rustup:/root/.rustup" \
  -w /app \
  -e CARGO_HOME=/app/.cargo \
  -e RUSTUP_NONINTERACTIVE=1 \
  -e CARGO_LLVM_COV_TARGET_DIR=/app/target/llvm-cov-target \
  -e CARGO_LLVM_COV_BUILD_DIR=/app/target/llvm-cov-build \
  "$TEST_IMAGE" \
  sh -c "cargo llvm-cov -p nss_core --lib $PROFILE_ARGS --no-report -- --list" \
  | awk '/: test$/{sub(/:$/,"",$1); print $1}' > "$TEST_LIST"

# Clear profraw produced by the list run.
rm -f target/llvm-cov-target/*.profraw 2>/dev/null || true

docker run --rm \
  -v "$(pwd):/app" \
  -w /app \
  "$TEST_IMAGE" \
  sh -c "find /app/target/llvm-cov-target -type f -perm -111 -name 'nss_core-*' \
    -printf '%T@ %p\n' | sort -nr | head -n 1 | cut -d ' ' -f2-" \
  > "$TEST_BIN_PATH"

TEST_BIN=$(cat "$TEST_BIN_PATH")
if [ -z "$TEST_BIN" ]; then
  echo "test binary not found" >&2
  exit 1
fi

python3 - <<'PY'
import os
import pathlib

shards = int(os.environ.get("NSS_TEST_SHARDS", "4"))

test_list = pathlib.Path("scripts/tmp/unit-shards/tests.list").read_text().splitlines()

test_list = [t.strip() for t in test_list if t.strip()]

parts = [[] for _ in range(shards)]
for idx, name in enumerate(test_list):
    parts[idx % shards].append(name)

for i, shard_tests in enumerate(parts, start=1):
    shard_file = pathlib.Path(f"scripts/tmp/unit-shards/shard-{i}.list")
    shard_file.write_text("\n".join(shard_tests) + ("\n" if shard_tests else ""))
PY

# Shared infrastructure: one set of services for all shards
PROJECT_NAME="${BASE_PROJECT}_unit"
docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" --profile redis --profile rabbitmq up -d postgres redis rabbitmq

cleanup() {
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

NETWORK_NAME="${PROJECT_NAME}_default"

echo "Waiting for postgres..."
for attempt in $(seq 1 30); do
  if docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" \
    exec -T postgres pg_isready -U nss -d nss >/dev/null 2>&1; then
    break
  fi
  sleep 2
  if [ "$attempt" -eq 30 ]; then
    echo "postgres not ready" >&2
    exit 1
  fi
done

echo "Waiting for redis..."
for attempt in $(seq 1 30); do
  if docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" exec -T redis redis-cli ping >/dev/null 2>&1; then
    break
  fi
  sleep 2
  if [ "$attempt" -eq 30 ]; then
    echo "redis not ready" >&2
    exit 1
  fi
done

echo "Waiting for rabbitmq..."
for attempt in $(seq 1 30); do
  if docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" \
    exec -T rabbitmq rabbitmq-diagnostics -q ping >/dev/null 2>&1; then
    break
  fi
  sleep 2
  if [ "$attempt" -eq 30 ]; then
    echo "rabbitmq not ready" >&2
    exit 1
  fi
done

# Create per-shard databases so each shard has its own namespace
for i in $(seq 1 "$SHARDS"); do
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" exec -T postgres \
    psql -U nss -d nss -c "CREATE DATABASE nss_shard_${i} OWNER nss;" >/dev/null 2>&1 || true
done

# Run shards in parallel against shared infrastructure
for i in $(seq 1 "$SHARDS"); do
  FILTER_ARGS=$(tr '\n' ' ' < "scripts/tmp/unit-shards/shard-${i}.list")
  LLVM_PROFILE_FILE="/app/target/llvm-cov-target/unit-shard-${i}-%p-%m.profraw"
  LOG_FILE="$TMP_DIR/shard-${i}.log"

  (
    set +e
    docker run --rm \
      --name "${BASE_PROJECT}_unit_runner_${i}" \
      --network "$NETWORK_NAME" \
      -v "$(pwd):/app" \
      -v "$(pwd)/.rustup:/root/.rustup" \
      -w /app \
      -e CARGO_HOME=/app/.cargo \
      -e RUSTUP_NONINTERACTIVE=1 \
      -e RUST_BACKTRACE=1 \
      -e CARGO_INCREMENTAL=1 \
      -e LLVM_PROFILE_FILE="$LLVM_PROFILE_FILE" \
      -e NSS_POSTGRES_DSN=postgres://nss:nss@postgres:5432/nss_shard_${i}?sslmode=disable \
      -e NSS_REDIS_URL=redis://redis:6379 \
      -e NSS_RABBIT_URL=amqp://rabbitmq:5672/%2f \
      "$TEST_IMAGE" \
      sh -c "if [ -z \"$FILTER_ARGS\" ]; then exit 0; fi; \
        \"$TEST_BIN\" --test-threads=$TEST_THREADS --exact $FILTER_ARGS" \
      >"$LOG_FILE" 2>&1
    status=$?
    echo "$status" > "$TMP_DIR/exit-${i}"
  ) &

done

wait

# Check shard exit codes
FAILED=0
for i in $(seq 1 "$SHARDS"); do
  code=$(cat "$TMP_DIR/exit-${i}" 2>/dev/null || echo 1)
  if [ "$code" -ne 0 ]; then
    echo "Shard ${i} failed with exit code ${code}" >&2
    cat "$TMP_DIR/shard-${i}.log" >&2
    FAILED=1
  fi

done

if [ "$FAILED" -ne 0 ]; then
  exit 1
fi

# Generate merged report without running tests

docker run --rm \
  -v "$(pwd):/app" \
  -v "$(pwd)/.rustup:/root/.rustup" \
  -w /app \
  -e CARGO_HOME=/app/.cargo \
  -e RUSTUP_NONINTERACTIVE=1 \
  -e RUST_BACKTRACE=1 \
  -e NSS_TEST_BIN="$TEST_BIN" \
  "$TEST_IMAGE" \
  sh -c '
    set -e
    LLVM_BIN_DIR="$(rustc --print target-libdir)/../bin"
    PROFRAW_GLOB="/app/target/llvm-cov-target/unit-shard-*.profraw"
    if ! ls ${PROFRAW_GLOB} >/dev/null 2>&1; then
      echo "no profraw files found for unit shards" >&2
      exit 1
    fi
    "$LLVM_BIN_DIR/llvm-profdata" merge -sparse ${PROFRAW_GLOB} -o /app/target/llvm-cov-target/unit-merged.profdata
    SOURCES="$(find /app/internal -name "*.rs" -print)"
    "$LLVM_BIN_DIR/llvm-cov" report \
      --instr-profile=/app/target/llvm-cov-target/unit-merged.profdata \
      "$NSS_TEST_BIN" \
      --sources $SOURCES \
      > /app/scripts/tmp/unit-shards/coverage.txt
  '

python3 - <<'PY'
import os
import re
from pathlib import Path

report = Path("scripts/tmp/unit-shards/coverage.txt").read_text().splitlines()
total = next((line for line in report if line.startswith("TOTAL")), "")
if not total:
    raise SystemExit("coverage report missing TOTAL line")

percents = [float(val.strip("%")) for val in re.findall(r"\d+\.\d+%", total)]
if len(percents) < 3:
    raise SystemExit(f"unexpected coverage line: {total}")

region_cover, func_cover, line_cover = percents[:3]

min_lines = float(os.environ.get("UNIT_COVERAGE_LINES", "100"))
min_funcs = float(os.environ.get("UNIT_COVERAGE_FUNCTIONS", "100"))
min_regions = float(os.environ.get("UNIT_COVERAGE_REGIONS", "100"))

print(Path("scripts/tmp/unit-shards/coverage.txt").read_text())

failed = False
if line_cover < min_lines:
    print(f"Line coverage {line_cover:.2f}% below {min_lines:.2f}%")
    failed = True
if func_cover < min_funcs:
    print(f"Function coverage {func_cover:.2f}% below {min_funcs:.2f}%")
    failed = True
if region_cover < min_regions:
    print(f"Region coverage {region_cover:.2f}% below {min_regions:.2f}%")
    failed = True

if failed:
    raise SystemExit(1)
PY
