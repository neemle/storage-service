#!/bin/sh
set -e

docker compose -f deploy/docker-compose.yml run --rm master /app/nss --migrate-only
