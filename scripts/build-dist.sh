#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT_DIR="${ROOT_DIR}/dist"
DOCKERFILE="${NSS_DIST_DOCKERFILE:-${ROOT_DIR}/deploy/Dockerfile.dist}"
IMAGE="${NSS_DIST_IMAGE:-nss-dist-builder:local}"

PLATFORMS=(
  "linux-amd64"
  "linux-aarch64"
  "linux-musl-x64"
  "windows-x64"
  "windows-aarch64"
  "mac-x64"
  "mac-aarch64"
)

usage() {
  echo "Usage: $(basename "$0") [PLATFORM|all]"
  echo ""
  echo "Build nss binaries for the specified platform inside Docker."
  echo "Output is placed in dist/<platform>/nss[.exe]."
  echo ""
  echo "Platforms:"
  for p in "${PLATFORMS[@]}"; do
    echo "  ${p}"
  done
  echo "  all           Build all platforms"
  echo ""
  echo "Examples:"
  echo "  $(basename "$0") linux-amd64"
  echo "  $(basename "$0") all"
  exit 1
}

TARGET="${1:-}"
if [[ -z "${TARGET}" ]]; then
  usage
fi

# Validate the target
if [[ "${TARGET}" != "all" ]]; then
  valid=false
  for p in "${PLATFORMS[@]}"; do
    if [[ "${p}" == "${TARGET}" ]]; then
      valid=true
      break
    fi
  done
  if [[ "${valid}" != "true" ]]; then
    echo "Unknown platform: ${TARGET}" >&2
    echo "" >&2
    usage
  fi
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

docker build -f "${DOCKERFILE}" -t "${IMAGE}" "${ROOT_DIR}"

mkdir -p "${OUT_DIR}"

USER_ARGS=()
if command -v id >/dev/null 2>&1; then
  USER_ARGS=("-u" "$(id -u):$(id -g)")
fi

docker run --rm \
  "${USER_ARGS[@]}" \
  -e CARGO_HOME=/work/.cargo \
  -e HOME=/tmp \
  -e NSS_BUILD_TARGET="${TARGET}" \
  -v "${ROOT_DIR}:/work" \
  -v "${OUT_DIR}:/out" \
  -w /work \
  "${IMAGE}" \
  /work/scripts/build-dist-inner.sh
