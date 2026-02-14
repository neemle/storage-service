# Neemle Storage Service Usage Guide

This document explains what operational problems NSS addresses and how to use NSS capabilities to solve them.
For normative behavior and acceptance criteria, see `functional.md`.

## Where NSS Fits

NSS is a fit when you need:

- Self-hosted, S3-compatible object storage in a single-site deployment.
- Unified operator workflows for buckets, objects, keys, users, replication, snapshots, and backups.
- Read scaling and distributed delivery via replicas, while keeping write control on master.
- Built-in security controls (WORM, audit log, SigV4, OIDC/internal auth).
- Built-in observability in local/demo stacks with Prometheus, Loki, and Grafana.

NSS is not a fit when you need:

- Multi-region active-active storage semantics.
- A managed cloud service operated by a third party.

## Problems NSS Solves

## 1) Problem: App Teams Need S3 But Must Stay Self-Hosted

How NSS solves it:

- Provides an S3-compatible data plane for bucket and object workflows.
- Provides a unified console/admin API and web UI for operators.
- Supports private access and controlled public-read buckets.

Operational result:

- Existing S3 clients can be used without reworking core object workflows.

Related use cases:

- `UC-002`, `UC-003`, `UC-005`

## 2) Problem: Single Disk Paths Become Hotspots and Operational Risk

How NSS solves it:

- Supports multiple storage directories via `NSS_DATA_DIRS` (comma-separated).
- Spreads chunk I/O across configured data paths.
- Supports replica participation with replication-factor and write-quorum controls.

Operational result:

- Better I/O distribution, easier capacity expansion, and better resilience to single-path degradation.

Related use cases:

- `UC-004`

## 3) Problem: Need Read Delivery Through Replicas Without Reissuing Credentials

How NSS solves it:

- Master-issued access keys and presigned URLs are accepted by replica read paths.
- Replica sub-mode controls behavior:
  - `delivery`: replica serves read traffic.
  - `backup`: replica does not serve client content and can be used for backup-only operation.
- Replica mode is remotely controlled from master.

Operational result:

- Decentralized content delivery for reads, with centralized write control on master.

Related use cases:

- `UC-004`, `UC-005`, `UC-011`

## 4) Problem: Need Short-Lived, Controlled Sharing of Private Objects

How NSS solves it:

- Uses SigV4-compatible request validation.
- Supports presigned URLs for private bucket/object reads.
- Enforces signature validity and expiration.

Operational result:

- Private content can be shared securely without exposing long-lived credentials.

Related use cases:

- `UC-005`

## 5) Problem: Need Identity Flexibility (Local Auth or Corporate IdP)

How NSS solves it:

- Supports `NSS_AUTH_MODE=internal` for local username/password auth.
- Supports `NSS_AUTH_MODE=oidc` for OIDC providers (for example Keycloak).
- Supports `NSS_AUTH_MODE=oauth2` and `NSS_AUTH_MODE=saml2` through OIDC-compatible provider bridges.
- In external auth mode, NSS validates provider tokens and maps admin access from configured claims/groups.

Operational result:

- Same storage platform can operate in standalone mode or enterprise SSO mode.

Related use cases:

- `UC-001`, `UC-012`

## 6) Problem: Compliance Requires Immutable Backup Targets and Auditability

How NSS solves it:

- Encrypts chunk payload files at rest by default, with key-id envelopes for rotation.
- Supports WORM-enabled backup buckets (`is_worm=true`).
- Applies write-once semantics to WORM buckets: first object create is allowed, overwrite/delete
  mutations are rejected on data-plane and console mutation APIs.
- Provides admin audit logs with pagination.

Operational result:

- Stronger control over retention-sensitive backup data and better traceability of admin actions.

Related use cases:

- `UC-008`, `UC-010`

## 7) Problem: Need Fast Recovery Points and Policy-Driven Backups

How NSS solves it:

- Snapshot policies:
  - Triggers: `hourly`, `daily`, `weekly`, `monthly`, `on_create_change`
  - On-demand snapshots
  - Restore a new bucket from snapshot
- Backup policies:
  - Types: `full`, `incremental`, `differential`
  - Schedules: `hourly`, `daily`, `weekly`, `monthly`, `on_demand`
  - Strategies: `3-2-1`, `3-2-1-1-0`, `4-3-2`
  - Retention count enforcement
  - External target descriptors are validated and can be connection-tested from API/UI
- Backup export formats: `tar`, `tar.gz` (max gzip compression for `tar.gz`)

Operational result:

- Flexible restore points and backup governance with exportable archives for external workflows.
- Operators can pick backup strategy and retention settings faster using built-in Admin UI hints.

Related use cases:

- `UC-009`, `UC-010`, `UC-012` (backup archive export)

### Admin UI Hints (Storage Protection)

In `Admin -> Storage protection`, NSS provides inline operator hints for:

- Backup strategy selection:
  - `3-2-1` for baseline resilience.
  - `3-2-1-1-0` for immutable + verification-heavy compliance workflows.
  - `4-3-2` for higher copy depth in high-change workloads.
- WORM behavior (first write allowed, overwrite/delete blocked).
- Snapshot restore expectation (restore creates a new bucket).
- Replica sub-mode intent (`delivery` for serving reads, `backup` for backup-only role).
- External targets JSON guidance (`Show example`) with `s3` and `sftp` gateway templates.

### Manual Backup And Restore (API)

Use these steps for an operator-driven backup/restore flow in development.
For a dedicated runbook with UI and API flows, see `docs/backup-restore-manual.md`.

1. Authenticate as admin and capture token:

```bash
BASE_URL=http://localhost:9001
ADMIN_USER=admin
ADMIN_PASS=change-me
TOKEN=$(curl -s -X POST "${BASE_URL}/admin/v1/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" | jq -r '.token')
```

2. Mark backup bucket as WORM (required before backup policy creation):

```bash
BACKUP_BUCKET=bak-prod
curl -s -X PATCH "${BASE_URL}/admin/v1/storage/buckets/${BACKUP_BUCKET}/worm" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"isWorm":true}'
```

3. Create backup policy (`full`, `incremental`, or `differential`):

```bash
SOURCE_BUCKET=src-prod
POLICY_ID=$(curl -s -X POST "${BASE_URL}/admin/v1/storage/backup-policies" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d "{
    \"name\":\"prod-daily-full\",
    \"scope\":\"master\",
    \"sourceBucketName\":\"${SOURCE_BUCKET}\",
    \"backupBucketName\":\"${BACKUP_BUCKET}\",
    \"backupType\":\"full\",
    \"scheduleKind\":\"daily\",
    \"strategy\":\"3-2-1\",
    \"retentionCount\":7,
    \"enabled\":true,
    \"externalTargets\":[]
  }" | jq -r '.id')
```

4. Trigger on-demand backup run and capture snapshot source:

```bash
RUN_JSON=$(curl -s -X POST "${BASE_URL}/admin/v1/storage/backups/${POLICY_ID}/run" \
  -H "Authorization: Bearer ${TOKEN}")
RUN_ID=$(printf '%s' "${RUN_JSON}" | jq -r '.id')
SNAPSHOT_ID=$(printf '%s' "${RUN_JSON}" | jq -r '.snapshotId')
```

5. Export backup archive (`tar` or `tar.gz`):

```bash
curl -L -X GET "${BASE_URL}/admin/v1/storage/backups/runs/${RUN_ID}/export?format=tar.gz" \
  -H "Authorization: Bearer ${TOKEN}" \
  -o "backup-${RUN_ID}.tar.gz"
```

6. Restore a new bucket from the backup run snapshot:

```bash
RESTORE_BUCKET=restore-prod-from-run
curl -s -X POST "${BASE_URL}/admin/v1/storage/snapshots/${SNAPSHOT_ID}/restore" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d "{\"bucketName\":\"${RESTORE_BUCKET}\"}"
```

7. Verify restored content:

```bash
CONSOLE_TOKEN=$(curl -s -X POST "${BASE_URL}/console/v1/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" | jq -r '.token')
curl -s -X GET "${BASE_URL}/console/v1/buckets/${RESTORE_BUCKET}/objects?limit=100" \
  -H "Authorization: Bearer ${CONSOLE_TOKEN}" | jq
```

Notes:
- For `full` backups, each run captures current source state; `changedSince` is `null`.
- For `incremental`, run the same policy twice (or more); subsequent runs set `changedSince` to prior success.
- For `differential`, first run is baseline; later runs set `changedSince` to baseline success time.
- Restore always creates a new bucket from snapshot data and leaves source/backup buckets unchanged.
- You can repeat step 6 with a different `RESTORE_BUCKET` to validate multiple restore points from different runs.

## 8) Problem: Teams Need Immediate Visibility Into Cluster Health and Behavior

How NSS solves it:

- Exposes native Prometheus metrics endpoint (`/metrics`) on nodes.
- Supports Loki log storage and Prometheus block storage in dedicated NSS buckets.
- Provides demo topology with one master, two replicas, and preprovisioned Grafana dashboards.

Operational result:

- Faster incident triage and clearer runtime visibility in development/demo environments.

Related use cases:

- `UC-013`

## Adoption Checklist

Use NSS effectively by confirming these decisions early:

- Authentication mode (`internal` or `oidc`) and required env values.
- Data path layout (`NSS_DATA_DIRS`) and replica topology.
- Replication factor and write quorum for durability/availability tradeoff.
- WORM bucket policy for backup targets.
- Snapshot/backup policies and retention strategy.
- Observability bucket names and dashboard access model.

## Enterprise Readiness Notes

NSS enforces enterprise-oriented gates in CI and local scripts:

- Security:
  - `cargo audit` with repository policy (`scripts/security-audit.sh`)
  - strict compile-time linting on production targets (`cargo clippy --workspace -- -D warnings`)
  - encrypted chunk storage at rest + WORM controls for backup buckets
- Reliability:
  - Dockerized memcheck gate with `definitely/indirectly/possibly lost == 0`
  - fail-fast staged test pipeline (unit -> integration -> curl -> UI -> runtime -> production)
  - Playwright full UI/production runners verify requested projects are executed and that every executed
    test has a video artifact
- Runtime hardening:
  - distroless runtime image validation (no shell in runtime image)
  - static binary linkage check via `scripts/verify-distroless.sh`

Practical scope:
- These controls reduce risk materially, but no software can claim mathematically absolute
  "zero security issues forever"; NSS relies on continuous updates, audits, and patching.

## Reference Docs

- `functional.md`
- `README.md`
- `docs/configuration-guide.md`
- `docs/functional-description.md`
