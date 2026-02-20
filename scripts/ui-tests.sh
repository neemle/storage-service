#!/bin/sh
set -e

COMPOSE_FILE="deploy/docker-compose.test.yml"
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-$(basename "$(dirname "$COMPOSE_FILE")")}
NETWORK_NAME="${PROJECT_NAME}_default"
PLAYWRIGHT_IMAGE=${PLAYWRIGHT_IMAGE:-mcr.microsoft.com/playwright:v1.58.2-jammy}
PLAYWRIGHT_PROJECTS=${NSS_PLAYWRIGHT_PROJECTS:-base ui}
ENV_FILE=${NSS_ENV_FILE:-.env}
RESULTS_ROOT=${NSS_TEST_RESULTS_DIR:-test-results}
BASE_PROJECTS="base-desktop-chromium base-tablet-portrait base-tablet-landscape \
base-mobile-iphone base-mobile-pixel base-mobile-samsung"
UI_PROJECTS="ui-desktop-chromium ui-tablet-portrait ui-tablet-landscape \
ui-mobile-iphone ui-mobile-pixel ui-mobile-samsung"
if [ -n "${NSS_RESULTS_LABEL:-}" ]; then
  RESULTS_LABEL="$NSS_RESULTS_LABEL"
elif [ "$PLAYWRIGHT_PROJECTS" = "base" ]; then
  RESULTS_LABEL="ui-base"
elif [ "$PLAYWRIGHT_PROJECTS" = "ui" ]; then
  RESULTS_LABEL="ui-e2e"
else
  RESULTS_LABEL="ui-tests"
fi
RESULTS_DIR="${RESULTS_ROOT}/${RESULTS_LABEL}"

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

expand_projects() {
  expanded=""
  for token in $(printf '%s' "$PLAYWRIGHT_PROJECTS" | tr ',' ' '); do
    case "$token" in
      base)
        expanded="$expanded $BASE_PROJECTS"
        ;;
      ui)
        expanded="$expanded $UI_PROJECTS"
        ;;
      *)
        expanded="$expanded $token"
        ;;
    esac
  done
  printf '%s\n' "$expanded" | xargs
}

copy_playwright_results() {
  mkdir -p "$RESULTS_DIR"
  mkdir -p "${RESULTS_DIR}/test-results" "${RESULTS_DIR}/playwright-report"
  if [ -d tests/playwright/test-results ]; then
    rm -rf "${RESULTS_DIR}/test-results"
    cp -R tests/playwright/test-results "${RESULTS_DIR}/test-results"
  fi
  if [ -d tests/playwright/playwright-report ]; then
    rm -rf "${RESULTS_DIR}/playwright-report"
    cp -R tests/playwright/playwright-report "${RESULTS_DIR}/playwright-report"
  fi
}

cleanup() {
  copy_playwright_results
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

curl_net() {
  docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.5.0 "$@"
}

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

echo "Waiting for replica to be ready..."
for i in $(seq 1 30); do
  if curl_net -sf http://replica:9100/readyz >/dev/null; then
    break
  fi
  sleep 2
  if [ "$i" -eq 30 ]; then
    echo "replica not ready" >&2
    exit 1
  fi
done

mkdir -p tests/playwright/test-results
mkdir -p "$RESULTS_DIR"
rm -rf tests/playwright/test-results tests/playwright/playwright-report

set -x

docker run --rm \
  --network "$NETWORK_NAME" \
  -e NSS_UI_URL="http://master:9001" \
  -e NSS_ADMIN_BOOTSTRAP_USER="$ADMIN_USER" \
  -e NSS_ADMIN_BOOTSTRAP_PASSWORD="$ADMIN_PASS" \
  -e NSS_PLAYWRIGHT_PROJECTS="$(expand_projects)" \
  -v "$(pwd):/workspace" \
  -w /workspace/tests/playwright \
  "$PLAYWRIGHT_IMAGE" \
  sh -lc '
    set -e
    npm ci
    projects=$(printf "%s\n" "$NSS_PLAYWRIGHT_PROJECTS" | xargs)
    args=""
    has_base=0
    has_ui=0
    for project in $projects; do
      args="$args --project=$project"
      case "$project" in
      base-*)
        has_base=1
        ;;
      ui-*)
        has_ui=1
        ;;
      esac
    done
    npx playwright test $args
    report_file="test-results/playwright-report.json"
    if [ ! -f "$report_file" ]; then
      echo "Playwright JSON report not found" >&2
      exit 1
    fi
    for project in $projects; do
      if ! grep -Eq "\"projectName\"[[:space:]]*:[[:space:]]*\"$project\"" "$report_file"; then
        echo "Playwright project $project was not executed" >&2
        exit 1
      fi
    done
    expected=$(node -e "
      const fs = require(\"fs\");
      const report = JSON.parse(fs.readFileSync(process.argv[1], \"utf8\"));
      console.log(report.stats?.expected ?? 0);
    " "$report_file")
    videos=$(find test-results -type f -name "*.webm" | wc -l | tr -d " ")
    if [ "$videos" -lt "$expected" ]; then
      echo "expected at least $expected videos, got $videos" >&2
      exit 1
    fi
    if [ "$has_base" -eq 1 ] && [ "$has_ui" -eq 1 ] && [ "$expected" -le 3 ]; then
      echo "expected full UI suite (>3 tests), got $expected" >&2
      exit 1
    fi
    if ! find test-results -type f -name "*.webm" -print -quit | grep -q .; then
      echo "no Playwright videos were generated" >&2
      exit 1
    fi
  '
