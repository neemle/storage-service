#!/bin/sh
set -eu

IMAGE_NAME=${1:-nss-enterprise-check}
IMAGE_TAG=${2:-local}
ROLE=${3:-master}
APP_VERSION=${NSS_APP_VERSION:-0.1.0}

case "$ROLE" in
  master) DOCKERFILE="deploy/Dockerfile.master" ;;
  replica) DOCKERFILE="deploy/Dockerfile.replica" ;;
  *)
    echo "unsupported role: $ROLE (use master|replica)" >&2
    exit 1
    ;;
esac

IMAGE_REF="${IMAGE_NAME}:${IMAGE_TAG}"
BUILDER_REF="${IMAGE_NAME}:${IMAGE_TAG}-builder"

build_images() {
  docker build -f "$DOCKERFILE" --build-arg NSS_APP_VERSION="$APP_VERSION" -t "$IMAGE_REF" .
  docker build --target builder -f "$DOCKERFILE" --build-arg NSS_APP_VERSION="$APP_VERSION" -t "$BUILDER_REF" .
}

verify_runtime_binary() {
  docker run --rm --entrypoint /app/nss "$IMAGE_REF" --version >/dev/null
}

verify_runtime_has_no_shell() {
  if docker run --rm --entrypoint /bin/sh "$IMAGE_REF" -c 'echo shell-found' >/dev/null 2>&1; then
    echo "runtime image must not contain /bin/sh" >&2
    exit 1
  fi
}

verify_binary_is_static() {
  output=$(docker run --rm --entrypoint sh "$BUILDER_REF" -lc 'ldd /app/nss 2>&1 || true')
  if printf '%s\n' "$output" | grep -Eq 'not a dynamic executable|statically linked'; then
    return
  fi
  echo "binary is not static" >&2
  printf '%s\n' "$output" >&2
  exit 1
}

build_images
verify_runtime_binary
verify_runtime_has_no_shell
verify_binary_is_static

echo "distroless verification passed for $ROLE ($IMAGE_REF)"
