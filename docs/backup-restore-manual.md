# Backup And Restore Manual

This manual provides operator runbooks for backup and restore in Neemle Storage Service (NSS).

For normative behavior and acceptance criteria, see `functional.md` (`UC-009`, `UC-010`, `UC-012`).

## What This Solves

- Reproducible recovery points for bucket data.
- Policy-based backup execution (`full`, `incremental`, `differential`).
- Immutable backup targets via WORM buckets.
- Offsite copy fan-out through external targets (for example S3 and SFTP gateway).
- Deterministic restore into a new bucket without mutating source buckets.

## Preconditions

- NSS stack is running and reachable.
- You can log in as admin.
- Source bucket already exists and contains data.
- Backup bucket already exists.
- Backup bucket is set to WORM (`is_worm=true`).

## External Targets JSON Examples

Use these in `Admin -> Storage protection -> External targets JSON` or in the backup policy API payload.

```json
[
  {
    "name": "offsite-s3",
    "kind": "s3",
    "endpoint": "https://storage.example.com/offsite/{objectKey}",
    "method": "PUT",
    "enabled": true,
    "timeoutSeconds": 20,
    "headers": {
      "Authorization": "Bearer <token>"
    }
  },
  {
    "name": "archive-sftp-gateway",
    "kind": "sftp",
    "endpoint": "https://gateway.example.com/sftp/upload/{objectKey}",
    "method": "PUT",
    "enabled": true,
    "timeoutSeconds": 20,
    "headers": {
      "Authorization": "Bearer <token>"
    }
  }
]
```

Notes:
- `kind: "sftp"` supports connectivity checks with `sftp://` endpoints.
- For backup upload, use an HTTP(S) SFTP gateway endpoint (`https://...`) rather than direct `sftp://`.
- Endpoint supports `{objectKey}` placeholder.

## UI Runbook (Operator Flow)

1. Open `Admin -> Storage protection`.
2. Select backup bucket in the WORM section and enable WORM.
3. Configure snapshot policy for the source bucket (optional but recommended).
4. In Backup policy:
- Set name, scope (`master` or `replica`), source bucket, backup bucket.
- Choose type (`full`, `incremental`, `differential`).
- Choose schedule and strategy (`3-2-1`, `3-2-1-1-0`, `4-3-2`).
- Set retention count.
- Click `Show example`, then customize external targets JSON.
5. Click `Test remote targets`.
6. Click `Create backup policy`.
7. In Backup policies table, click `Run backup` for on-demand execution.
8. In Backup runs table:
- Verify `status=success`.
- Export `tar` or `tar.gz` when needed.
9. In Snapshots table, restore to a new bucket name.
10. Verify restored bucket/object list in console.

## API Runbook (Scriptable Flow)

### 1. Login as admin

```bash
BASE_URL=http://localhost:9001
ADMIN_USER=admin
ADMIN_PASS=change-me
TOKEN=$(curl -s -X POST "${BASE_URL}/admin/v1/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" | jq -r '.token')
```

### 2. Mark backup bucket as WORM

```bash
BACKUP_BUCKET=bak-prod
curl -s -X PATCH "${BASE_URL}/admin/v1/storage/buckets/${BACKUP_BUCKET}/worm" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"isWorm":true}'
```

### 3. Create backup policy

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
    \"externalTargets\":[
      {
        \"name\":\"offsite-s3\",
        \"kind\":\"s3\",
        \"endpoint\":\"https://storage.example.com/offsite/{objectKey}\",
        \"method\":\"PUT\",
        \"enabled\":true
      },
      {
        \"name\":\"archive-sftp-gateway\",
        \"kind\":\"sftp\",
        \"endpoint\":\"https://gateway.example.com/sftp/upload/{objectKey}\",
        \"method\":\"PUT\",
        \"enabled\":true
      }
    ]
  }" | jq -r '.id')
```

### 4. Trigger backup run

```bash
RUN_JSON=$(curl -s -X POST "${BASE_URL}/admin/v1/storage/backups/${POLICY_ID}/run" \
  -H "Authorization: Bearer ${TOKEN}")
RUN_ID=$(printf '%s' "${RUN_JSON}" | jq -r '.id')
SNAPSHOT_ID=$(printf '%s' "${RUN_JSON}" | jq -r '.snapshotId')
```

### 5. Export archive

```bash
curl -L -X GET "${BASE_URL}/admin/v1/storage/backups/runs/${RUN_ID}/export?format=tar.gz" \
  -H "Authorization: Bearer ${TOKEN}" \
  -o "backup-${RUN_ID}.tar.gz"
```

### 6. Restore from snapshot tied to backup run

```bash
RESTORE_BUCKET=restore-prod-from-run
curl -s -X POST "${BASE_URL}/admin/v1/storage/snapshots/${SNAPSHOT_ID}/restore" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d "{\"bucketName\":\"${RESTORE_BUCKET}\"}"
```

### 7. Verify restored content

```bash
CONSOLE_TOKEN=$(curl -s -X POST "${BASE_URL}/console/v1/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" | jq -r '.token')
curl -s -X GET "${BASE_URL}/console/v1/buckets/${RESTORE_BUCKET}/objects?limit=100" \
  -H "Authorization: Bearer ${CONSOLE_TOKEN}" | jq
```

## Backup Type Behavior

- `full`: every successful run captures complete current source view.
- `incremental`: captures changes since previous successful run.
- `differential`: captures changes since last full baseline.

## Restore Safety Rules

- Restore always creates a new bucket.
- Source bucket and backup bucket are unchanged by restore operation.
- WORM backup bucket continues rejecting overwrite/delete mutation requests.
