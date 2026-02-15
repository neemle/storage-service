# AI And Agent Guide

This document gives AI coding agents a fast, project-specific onboarding:
- what Neemle Storage Service is,
- where core logic lives,
- how to run and validate changes safely.

## What This Project Is

Neemle Storage Service (NSS) is a self-hosted, single-site, S3-compatible object storage service.

Primary surfaces:
- S3 API for object operations (`:9000`)
- Unified Console/Admin API + UI (`:9001`)
- Internal replication API (`:9003` master, `:9010` replica)
- Prometheus metrics (`:9100`)

Business source of truth is `functional.md`.

## Source Of Truth Order

Use this order when reading and implementing:
1. `functional.md`
2. `agents.md` (or `claude.md`) for non-negotiable engineering constraints
3. `README.md` for local workflows
4. `docs/configuration-guide.md` and `docs/installation-guide.md`
5. OpenAPI docs in `docs/openapi-*.yaml`

If docs disagree, align behavior to `functional.md`.

## Repository Map

- `cmd/nss`, `cmd/nss-master`, `cmd/nss-replica`: binaries/entrypoints
- `internal/api`: API handlers and route wiring
- `internal/meta`: DB access, migrations, repositories
- `internal/storage`: chunk/object storage and replication logic
- `internal/s3`: S3 protocol handling (SigV4, XML, chunking)
- `internal/obs`: metrics
- `web/console-ui`: Angular UI
- `tests/playwright`: UI end-to-end suites
- `scripts`: dockerized test/build/release commands

## Local Setup

1. Create local env:

```bash
cp .env.dist .env
```

Required security checks before running:
- set strong `NSS_ADMIN_BOOTSTRAP_PASSWORD`
- set strong `NSS_INTERNAL_SHARED_TOKEN`
- keep `NSS_CORS_ALLOW_ORIGINS` explicit unless `NSS_INSECURE_DEV=true`
- optionally set `NSS_JWT_SIGNING_KEY_BASE64` (otherwise NSS derives a separate JWT key)

2. Start local stack:

```bash
docker compose up --build
```

3. Endpoints:
- UI/API: `http://localhost:9001`
- S3: `http://localhost:9000`
- Metrics: `http://localhost:9100/metrics`
- Replica S3:
  - `http://localhost:9004` (`slave-delivery`, read)
  - `http://localhost:9005` (`slave-backup`, serving blocked)
  - `http://localhost:9006` (`slave-volume`, serving blocked)
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000`

## Agent Workflow For Changes

1. Read `functional.md` sections affected by the task.
2. Make minimal scope-limited changes in relevant modules.
3. Keep constraints:
   - line length `<= 120`
   - function length `<= 30` non-empty non-comment lines
   - no unsafe typing shortcuts
4. Run validation before finishing.

Recommended validation:

```bash
python3 scripts/quality-check.py
cargo check --tests
```

## Test Pipeline (Fail-Fast)

Run in order:
1. `./scripts/unit-tests.sh`
2. `./scripts/ui-unit-tests.sh`
3. `./scripts/integration-tests.sh`
4. `./scripts/ui-integration-tests.sh`
5. `./scripts/cluster-tests.sh`
6. `./scripts/curl-tests.sh`
7. `./scripts/it.sh`
8. `NSS_PLAYWRIGHT_PROJECTS=\"base\" ./scripts/ui-tests.sh`
9. `NSS_PLAYWRIGHT_PROJECTS=\"ui\" ./scripts/ui-tests.sh`
10. `./scripts/runtime-tests.sh`
11. `./scripts/production-tests.sh`

All suites must run dockerized.

Playwright artifacts are expected at:
- `tests/playwright/playwright-report`
- `tests/playwright/test-results`

## CI/CD Behavior

- Push and PR builds run build + fail-fast test stages.
- Tag builds (for example `v1.2.3`) also build and publish release binaries.

## Safety Rules For Agents

- Do not introduce breaking API behavior without explicit approval.
- Do not weaken validation/auth/security logic.
- Do not disable tests, coverage, or reporting.
- Do not edit CI/CD unless task explicitly requests it.
- Prefer clear, minimal, auditable diffs.
