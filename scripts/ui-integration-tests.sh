#!/bin/sh
set -e

UI_TEST_IMAGE=${UI_TEST_IMAGE:-node:24-bookworm}
RESULTS_ROOT=${NSS_TEST_RESULTS_DIR:-test-results}
RESULTS_DIR="${RESULTS_ROOT}/ui-integration"

mkdir -p "$RESULTS_DIR"

docker run --rm \
  -v "$(pwd):/app" \
  -v /app/web/console-ui/node_modules \
  -e NSS_RESULTS_DIR="$RESULTS_DIR" \
  -w /app/web/console-ui \
  "$UI_TEST_IMAGE" \
  sh -lc '
    set -e
    npm ci
    mkdir -p "/app/${NSS_RESULTS_DIR}"
    output="/app/${NSS_RESULTS_DIR}/output.log"
    if npm run test:integration >"$output" 2>&1; then
      cat "$output"
    else
      cat "$output"
      exit 1
    fi
  '
