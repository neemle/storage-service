#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  cat <<'EOF' >&2
Usage:
  ./scripts/build-production-image.sh <image-name> <version-tag> [master|replica]
Example:
  ./scripts/build-production-image.sh a/b 0.1.0
EOF
  exit 1
fi

IMAGE_NAME="$1"
VERSION_TAG="$2"
IMAGE_TYPE="${3:-master}"
RESULTS_ROOT=${NSS_TEST_RESULTS_DIR:-test-results}
RESULTS_DIR="${RESULTS_ROOT}/build-image"
SAFE_NAME=$(printf '%s-%s-%s' "$IMAGE_NAME" "$VERSION_TAG" "$IMAGE_TYPE" | tr '/:' '__')
LOG_FILE="${RESULTS_DIR}/${SAFE_NAME}.log"

case "$IMAGE_TYPE" in
  master) DOCKERFILE="deploy/Dockerfile.master" ;;
  replica) DOCKERFILE="deploy/Dockerfile.replica" ;;
  *)
    echo "unsupported image type: ${IMAGE_TYPE} (expected master or replica)" >&2
    exit 1
    ;;
esac

mkdir -p "$RESULTS_DIR"

if docker buildx build --load \
  --build-arg NSS_APP_VERSION="$VERSION_TAG" \
  -f "$DOCKERFILE" \
  -t "${IMAGE_NAME}:${VERSION_TAG}" \
  -t "${IMAGE_NAME}:latest" \
  . >"$LOG_FILE" 2>&1; then
  cat "$LOG_FILE"
else
  cat "$LOG_FILE"
  exit 1
fi

echo "built image ${IMAGE_NAME}:${VERSION_TAG}"
echo "built image ${IMAGE_NAME}:latest"
echo "app version build arg NSS_APP_VERSION=${VERSION_TAG}"
