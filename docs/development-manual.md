# Development Manual

This manual describes local development workflows for Neemle Storage Service (NSS).

## Prerequisites
- Docker and Docker Compose v2
- Optional: Node.js 24+ (UI-only local workflow)

## Local Start
1. `cp .env.dist .env`
2. `docker compose up --build`
3. Open `http://localhost:${NSS_UI_PORT:-9001}`

## Core Test Workflow
Use fail-fast orchestration:

```bash
./scripts/run-tests.sh all
```

Targeted stages are also supported:

```bash
./scripts/run-tests.sh api-unit
./scripts/run-tests.sh api-integration
./scripts/run-tests.sh api-curl
./scripts/run-tests.sh ui-base ui-e2e
./scripts/run-tests.sh runtime production
```

## Build Workflow
- Distribution artifacts: `npm run build:dist -- all`
- Production image build: `./scripts/build-production-image.sh <image> <tag>`

## Quality Gates
Run before pushing:

```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
python3 scripts/quality-check.py
./scripts/security-audit.sh
./scripts/run-tests.sh all
```
