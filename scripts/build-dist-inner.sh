#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=${ROOT_DIR:-/work}
OUT_DIR=${OUT_DIR:-/out}
TARGET=${NSS_BUILD_TARGET:-all}

# ── platform → rust triple mapping ──────────────────────────────
declare -A TRIPLES=(
  [linux-amd64]=x86_64-unknown-linux-gnu
  [linux-aarch64]=aarch64-unknown-linux-gnu
  [linux-musl-x64]=x86_64-unknown-linux-musl
  [windows-x64]=x86_64-pc-windows-gnu
  [windows-aarch64]=aarch64-pc-windows-gnullvm
  [mac-x64]=x86_64-apple-darwin
  [mac-aarch64]=aarch64-apple-darwin
)

declare -A EXTENSIONS=(
  [linux-amd64]=""
  [linux-aarch64]=""
  [linux-musl-x64]=""
  [windows-x64]=".exe"
  [windows-aarch64]=".exe"
  [mac-x64]=""
  [mac-aarch64]=""
)

ALL_PLATFORMS=(
  linux-amd64
  linux-aarch64
  linux-musl-x64
  windows-x64
  windows-aarch64
  mac-x64
  mac-aarch64
)

# ── resolve which platforms to build ────────────────────────────
if [[ "${TARGET}" == "all" ]]; then
  SELECTED=("${ALL_PLATFORMS[@]}")
else
  SELECTED=("${TARGET}")
fi

# ── build the console-ui and embed it ──────────────────────────
build_ui() {
  local name=$1
  local dest=$2
  local dir="${ROOT_DIR}/web/${name}"
  cd "${dir}"
  npm ci
  npm run build:embed
  rm -rf "${dest}"/*
  cp -R "${dir}/dist"/* "${dest}/"
}

mkdir -p "${OUT_DIR}/ui"
build_ui "console-ui" "${OUT_DIR}/ui"
rm -rf "${ROOT_DIR}/internal/embedded-ui"/*
cp -R "${OUT_DIR}/ui"/* "${ROOT_DIR}/internal/embedded-ui/"

# ── build each selected platform ───────────────────────────────
build_target() {
  local platform=$1
  local triple="${TRIPLES[${platform}]}"
  local ext="${EXTENSIONS[${platform}]}"

  echo "── building ${platform} (${triple}) ──"

  if [[ "${triple}" == *apple-darwin* ]]; then
    local sdk
    sdk=$(ls -d /opt/macos-sdk/MacOSX*.sdk 2>/dev/null | head -1)
    if [[ -z "${sdk}" ]]; then
      echo "ERROR: macOS SDK not found in /opt/macos-sdk" >&2
      return 1
    fi
    export SDKROOT="${sdk}"
    echo "   SDKROOT=${SDKROOT}"
  else
    unset SDKROOT
  fi

  rustup target add "${triple}"
  cargo zigbuild --release --target "${triple}" -p nss
  mkdir -p "${OUT_DIR}/${platform}"
  cp "${ROOT_DIR}/target/${triple}/release/nss${ext}" "${OUT_DIR}/${platform}/nss${ext}"
  echo "   → ${OUT_DIR}/${platform}/nss${ext}"
}

for platform in "${SELECTED[@]}"; do
  build_target "${platform}"
done

echo ""
echo "Done. Binaries:"
for platform in "${SELECTED[@]}"; do
  local_ext="${EXTENSIONS[${platform}]}"
  echo "  dist/${platform}/nss${local_ext}"
done
