#!/bin/sh
set -eu

RESULTS_ROOT=${NSS_TEST_RESULTS_DIR:-test-results}
SUMMARY_FILE="${RESULTS_ROOT}/summary.txt"
ALL_STAGES="api-unit ui-unit security api-integration ui-integration external-auth \
  cluster memcheck api-curl api-it ui-base ui-e2e runtime production"
ENC_STAGES="cluster api-curl api-it ui-base ui-e2e runtime production"

print_supported() {
  cat <<'EOF'
Supported test types:
  all
  api-unit
  api-integration
  api-curl
  api-it
  ui-unit
  ui-integration
  ui-base
  ui-e2e
  external-auth
  cluster
  runtime
  production
  security
  memcheck
  enc (expanded to end-to-end chain)
Usage:
  ./scripts/run-tests.sh all
  ./scripts/run-tests.sh api-unit
  ./scripts/run-tests.sh api-unit,api-integration
  ./scripts/run-tests.sh api-curl ui-base ui-e2e
EOF
}

stage_command() {
  case "$1" in
    api-unit) echo "./scripts/unit-tests.sh" ;;
    api-integration) echo "./scripts/integration-tests.sh" ;;
    api-curl) echo "./scripts/curl-tests.sh" ;;
    api-it) echo "./scripts/it.sh" ;;
    ui-unit) echo "./scripts/ui-unit-tests.sh" ;;
    ui-integration) echo "./scripts/ui-integration-tests.sh" ;;
    external-auth) echo "./scripts/external-auth-tests.sh" ;;
    ui-base) echo "NSS_RESULTS_LABEL=ui-base NSS_PLAYWRIGHT_PROJECTS=base ./scripts/ui-tests.sh" ;;
    ui-e2e) echo "NSS_RESULTS_LABEL=ui-e2e NSS_PLAYWRIGHT_PROJECTS=ui ./scripts/ui-tests.sh" ;;
    cluster) echo "./scripts/cluster-tests.sh" ;;
    runtime) echo "./scripts/runtime-tests.sh" ;;
    production) echo "NSS_RESULTS_LABEL=production-tests ./scripts/production-tests.sh" ;;
    security) echo "./scripts/security-audit.sh" ;;
    memcheck) echo "./scripts/memory-leak-check.sh" ;;
    *)
      echo "unknown test type: $1" >&2
      print_supported
      exit 1
      ;;
  esac
}

resolve_stages() {
  if [ "$#" -eq 0 ]; then
    echo "$ALL_STAGES"
    return
  fi
  selected=""
  all_requested=0
  for raw in "$@"; do
    append_tokens_from_arg "$raw"
  done
  if [ "$all_requested" -eq 1 ]; then
    echo "$ALL_STAGES"
  else
    echo "$selected"
  fi
}

append_tokens_from_arg() {
  raw="$1"
  for item in $(printf '%s' "$raw" | tr ',' ' '); do
    append_token "$item"
  done
}

append_token() {
  token="$1"
  case "$token" in
    "") ;;
    all) all_requested=1 ;;
    enc) selected="$selected $ENC_STAGES" ;;
    api-unit|api-integration|api-curl|api-it|ui-unit|ui-integration|ui-base|ui-e2e|external-auth)
      selected="$selected $token"
      ;;
    cluster|runtime|production|security|memcheck)
      selected="$selected $token"
      ;;
    *)
      echo "unknown test type: $token" >&2
      print_supported
      exit 1
      ;;
  esac
}

append_summary() {
  stage="$1"
  status="$2"
  duration="$3"
  log_file="$4"
  {
    echo "=== ${stage} ==="
    echo "RESULT: ${status} (${duration}s)"
    echo "LOG: ${log_file}"
    echo
  } >> "$SUMMARY_FILE"
}

run_stage() {
  stage="$1"
  cmd="$2"
  stage_dir="${RESULTS_ROOT}/${stage}"
  log_file="${stage_dir}/output.log"
  mkdir -p "$stage_dir"
  echo "[${stage}] $cmd"
  start=$(date +%s)
  if sh -lc "$cmd" >"$log_file" 2>&1; then
    status="PASS"
    rc=0
  else
    status="FAIL"
    rc=$?
  fi
  end=$(date +%s)
  duration=$((end - start))
  append_summary "$stage" "$status" "$duration" "$log_file"
  if [ "$status" = "FAIL" ]; then
    tail -n 200 "$log_file" >&2 || true
    return "$rc"
  fi
  return 0
}

mkdir -p "$RESULTS_ROOT"
: > "$SUMMARY_FILE"
export NSS_TEST_RESULTS_DIR="$RESULTS_ROOT"

for raw in "$@"; do
  for item in $(printf '%s' "$raw" | tr ',' ' '); do
    case "$item" in
      list|help|-h|--help)
        print_supported
        exit 0
        ;;
    esac
  done
done

STAGES=$(resolve_stages "$@")
if [ -z "$STAGES" ]; then
  echo "no stages selected" >&2
  exit 1
fi

for stage in $STAGES; do
  command=$(stage_command "$stage")
  if ! run_stage "$stage" "$command"; then
    cat "$SUMMARY_FILE"
    exit 1
  fi
done

cat "$SUMMARY_FILE"
echo "all selected stages passed"
