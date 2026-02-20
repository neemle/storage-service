#!/bin/sh
set -e

COMPOSE_BASE="deploy/docker-compose.test.yml"
COMPOSE_AUTH="deploy/docker-compose.auth.test.yml"
PLAYWRIGHT_IMAGE=${PLAYWRIGHT_IMAGE:-mcr.microsoft.com/playwright:v1.58.2-jammy}
RESULTS_ROOT=${NSS_TEST_RESULTS_DIR:-test-results}
RESULTS_DIR="${RESULTS_ROOT}/external-auth"
MODES=${NSS_EXTERNAL_AUTH_MODES:-"oidc oauth2 saml2"}
PROJECTS=${NSS_PLAYWRIGHT_PROJECTS:-ui-desktop-chromium}
CURRENT_PROJECT=""
PLAYWRIGHT_RUN_SCRIPT=$(cat <<'EOF'
set -e
npm ci
args=""
for project in $(printf "%s\n" "$NSS_PLAYWRIGHT_PROJECTS" | tr "," " "); do
  args="$args --project=$project"
done
npx playwright test ui/external-auth.spec.ts $args
report_file="test-results/playwright-report.json"
if [ ! -f "$report_file" ]; then
  echo "Playwright JSON report not found for external auth" >&2
  exit 1
fi
unexpected=$(node -e "
  const fs = require(\"fs\");
  const report = JSON.parse(fs.readFileSync(process.argv[1], \"utf8\"));
  console.log(report.stats?.unexpected ?? 0);
" "$report_file")
if [ "$unexpected" -gt 0 ]; then
  echo "Playwright reported $unexpected unexpected external auth failures" >&2
  exit 1
fi
for project in $(printf "%s\n" "$NSS_PLAYWRIGHT_PROJECTS" | tr "," " "); do
  if ! grep -Eq "\"projectName\"[[:space:]]*:[[:space:]]*\"$project\"" "$report_file"; then
    echo "Playwright project $project was not executed for external auth" >&2
    exit 1
  fi
done
videos=$(find test-results -type f -name "*.webm" | wc -l | tr -d " ")
if [ "$videos" -lt 1 ]; then
  echo "no Playwright videos generated for external auth" >&2
  exit 1
fi
EOF
)

copy_results() {
  mode="$1"
  mode_dir="${RESULTS_DIR}/${mode}"
  mkdir -p "$mode_dir"
  rm -rf "${mode_dir}/test-results" "${mode_dir}/playwright-report"
  if [ -d tests/playwright/test-results ]; then
    cp -R tests/playwright/test-results "${mode_dir}/test-results"
  fi
  if [ -d tests/playwright/playwright-report ]; then
    cp -R tests/playwright/playwright-report "${mode_dir}/playwright-report"
  fi
}

down_project() {
  project="$1"
  docker compose -p "$project" -f "$COMPOSE_BASE" -f "$COMPOSE_AUTH" down -v >/dev/null 2>&1 || true
}

cleanup() {
  if [ -n "$CURRENT_PROJECT" ]; then
    down_project "$CURRENT_PROJECT"
  fi
}
trap cleanup EXIT

curl_net() {
  network="$1"
  shift
  docker run --rm --network "$network" curlimages/curl:8.5.0 "$@"
}

wait_http() {
  network="$1"
  url="$2"
  name="$3"
  for i in $(seq 1 45); do
    if curl_net "$network" -sf "$url" >/dev/null; then
      return 0
    fi
    sleep 2
    if [ "$i" -eq 45 ]; then
      echo "${name} not ready: ${url}" >&2
      return 1
    fi
  done
}

run_playwright() {
  network="$1"
  mode="$2"
  projects="$3"
  docker run --rm \
    --network "$network" \
    -e NSS_UI_URL="http://master:9001" \
    -e NSS_EXTERNAL_AUTH_TEST="1" \
    -e NSS_EXPECTED_AUTH_MODE="$mode" \
    -e NSS_EXTERNAL_IDP_URL="http://keycloak:8080" \
    -e NSS_EXTERNAL_USER="admin" \
    -e NSS_EXTERNAL_PASSWORD="admin" \
    -e NSS_PLAYWRIGHT_PROJECTS="$projects" \
    -v "$(pwd):/workspace" \
    -w /workspace/tests/playwright \
    "$PLAYWRIGHT_IMAGE" \
    sh -lc "$PLAYWRIGHT_RUN_SCRIPT"
}

run_mode() {
  mode="$1"
  projects="$2"
  project="nss-auth-${mode}"
  network="${project}_default"
  CURRENT_PROJECT="$project"
  down_project "$project"

  NSS_AUTH_MODE_OVERRIDE="$mode" \
    docker compose -p "$project" -f "$COMPOSE_BASE" -f "$COMPOSE_AUTH" up -d --build

  wait_http "$network" "http://master:9100/readyz" "master"
  wait_http "$network" "http://keycloak:8080/realms/nss/.well-known/openid-configuration" "keycloak"

  rm -rf tests/playwright/test-results tests/playwright/playwright-report
  run_playwright "$network" "$mode" "$projects"
  copy_results "$mode"
  down_project "$project"
  CURRENT_PROJECT=""
}

mkdir -p "$RESULTS_DIR"
for mode in $MODES; do
  echo "running external auth test for mode: ${mode}"
  run_mode "$mode" "$PROJECTS"
done

echo "external auth tests passed for modes: $MODES (projects: $PROJECTS)"
