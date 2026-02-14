#!/bin/sh
set -e

IMAGE=${NSS_TEST_IMAGE:-nss-test-runner:latest}

exec docker build -f deploy/test-runner.Dockerfile -t "$IMAGE" .
