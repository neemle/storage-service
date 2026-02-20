# OpenStorageService — task.md (Codex autonomous implementation spec)

> Build a self-hosted, single-site object storage platform that is an alternative to MinIO and **fully compatible with the S3 server API used by common clients**, plus **User UI**, **Admin UI**, **Admin REST API**, **S3-style events**, **chunked internal storage distributed across replicas**, **internal checksums + repair**, and **Prometheus metrics out of the box**.
>
> **Hard constraints**
> - **No multi-zone / no multi-region features** (single site).
> - **PostgreSQL is required** for metadata/control-plane.
> - **Redis is optional** (cache). Service must run fully without it.
> - **RabbitMQ is optional but required for events**. Service must run fully (except events) without it.
> - **Startup configuration via environment variables**.
> - Do not depend on any AWS services; this is a standalone system.

---

## 0. Definition of Done (DoD)

A build is “done” when:

1. `docker compose up` brings up:
    - master node
    - postgres
    - (optional) one replica node
    - (optional) redis + rabbitmq (service still works without them)
2. A user can:
    - log into the web console
    - generate an **Access Key** + **Secret Key** (secret shown once)
    - use those credentials with a standard S3 client/SDK to:
        - create bucket
        - put/get/head/delete object
        - list objects (ListObjectsV2)
        - multipart upload & download
3. Admin can:
    - log into admin UI
    - create/disable users
    - view cluster nodes
    - generate join tokens
    - connect replica(s) to master
4. Objects are stored internally as **chunks**, distributed across replicas with a configurable replication factor.
5. Internal **checksums** exist per chunk; read verifies integrity and falls back to other replicas; repair is scheduled.
6. `/metrics` is available (Prometheus format) for every node.
7. If RabbitMQ is not configured, all event features are disabled cleanly; core storage remains fully functional.
8. If Redis is not configured, system uses in-memory fallbacks and remains functional.

---

## 1. Tech stack (pin these choices to avoid ambiguity)

- Language: **Go** (>= 1.22)
- HTTP: `net/http` + `chi` router (or `echo` if you prefer; choose one)
- Postgres: `pgx` + connection pool
- Migrations: `golang-migrate/migrate` (or `pressly/goose`; choose one)
- Frontend: **React + Vite** (two apps: user-console and admin-console)
    - Use a shared component library where possible
- Metrics: Prometheus client (`promhttp`)
- Optional Redis client: `redis/go-redis`
- Optional RabbitMQ client: `rabbitmq/amqp091-go`
- Auth:
    - Console/Admin sessions: signed JWT **or** opaque tokens in Postgres (choose one; must work without Redis)
    - S3 API auth: **SigV4** using access key + secret key

---

## 2. Repo layout (must create)

```
/cmd
  /nss-master        # master binary
  /nss-replica       # replica binary
/internal
  /api               # HTTP handlers (S3, admin, console, internal)
  /auth              # console/admin auth, password hashing, token/session logic
  /s3                # S3 protocol: routing, XML, errors, SigV4 verify, presign
  /policy            # policy evaluation (MVP: basic allow-by-owner + bucket policy optional)
  /meta              # postgres repositories + migrations
  /storage
    /chunkstore      # local disk chunk storage, atomic write, range read
    /replication     # placement + write quorum + repair scheduling
    /manifest        # object manifests (object_version -> ordered chunk IDs)
  /jobs              # lifecycle, scrubber, GC, repair worker
  /events            # event generation and Rabbit publisher (optional)
  /obs               # metrics, healthz, readyz
/web
  /console-ui        # Console + admin UI (merged)
/deploy
  docker-compose.yml
  Dockerfile.master
  Dockerfile.replica
/docs
  openapi-admin.yaml
  openapi-console.yaml
```

---

## 3. Runtime modes & topology

### 3.1 Node modes

Each node runs with `NSS_MODE`:

- `master`
    - exposes public endpoints:
        - S3 API: `:9000`
        - Console + Admin API + UI: `:9001`
        - Metrics: `:9100`
    - may also store chunks locally (recommended)

- `replica`
    - exposes internal chunk store API: `:9010` (internal network only)
    - metrics: `:9100`
    - heartbeats to master

### 3.2 Single-site cluster

- One master
- Zero or more replicas
- Replication factor `N` controls how many nodes store each chunk.

---

## 4. Configuration via environment variables

### 4.1 Required env vars (master)

- `NSS_MODE=master`
- `NSS_POSTGRES_DSN=postgres://user:pass@postgres:5432/nss?sslmode=disable`
- `NSS_DATA_DIRS=/data`  
  (master can store chunks; required to simplify MVP)
- `NSS_ADMIN_BOOTSTRAP_USER=admin`
- `NSS_ADMIN_BOOTSTRAP_PASSWORD=change-me`
- `NSS_SECRET_ENCRYPTION_KEY_BASE64=...`  
  32 bytes base64 (AES-256 key) used to encrypt access-key secrets at rest.

### 4.2 Required env vars (replica)

- `NSS_MODE=replica`
- `NSS_POSTGRES_DSN=...` (replica may read config; keep required for simplicity)
- `NSS_DATA_DIRS=/data`
- `NSS_MASTER_URL=http://master:9003` (internal master port for join/heartbeat)
- `NSS_JOIN_TOKEN=...`

### 4.3 Optional env vars

Storage/replication:
- `NSS_REPLICATION_FACTOR=1` (default 1)
- `NSS_WRITE_QUORUM=1` (default = replication factor)
- `NSS_CHUNK_SIZE_BYTES=` (if set, overrides auto default)
- `NSS_CHUNK_MIN_BYTES=4194304` (4 MiB)
- `NSS_CHUNK_MAX_BYTES=67108864` (64 MiB)
- `NSS_CHECKSUM_ALGO=crc32c|sha256|both` (default `crc32c`)
- `NSS_SCRUB_INTERVAL_SECONDS=3600`
- `NSS_REPAIR_WORKERS=4`

Networking:
- `NSS_S3_LISTEN=:9000`
- `NSS_API_LISTEN=:9001`
- `NSS_INTERNAL_LISTEN=:9003` (master internal)
- `NSS_REPLICA_LISTEN=:9010` (replica internal)
- `NSS_METRICS_LISTEN=:9100`

Optional integrations:
- `NSS_REDIS_URL=redis://redis:6379/0` (optional)
- `NSS_RABBIT_URL=amqp://guest:guest@rabbitmq:5672/` (optional; enables events)

Dev aids (optional):
- `NSS_LOG_LEVEL=debug|info|warn|error`
- `NSS_CORS_ALLOW_ORIGINS=*` (for UI dev)
- `NSS_INSECURE_DEV=true` (allows HTTP + relaxed cookies; MUST default false)

### 4.4 Chunk size default algorithm (MUST implement)

If `NSS_CHUNK_SIZE_BYTES` is not set:
1. Determine filesystem block size from the first `NSS_DATA_DIRS` entry (statfs).
2. `chunk_size = fs_block_size`
3. While `chunk_size < NSS_CHUNK_MIN_BYTES`: `chunk_size *= 2`
4. If `chunk_size > NSS_CHUNK_MAX_BYTES`: clamp to max.
5. Ensure `chunk_size` is an integer multiple of `fs_block_size` (it will be).

---

## 5. Postgres schema (minimum viable)

Use migrations to create:

### 5.1 Users & credentials

- `users`
    - `id uuid pk`
    - `username text unique not null`
    - `display_name text`
    - `password_hash text not null`
    - `status text not null` (`active|disabled`)
    - `created_at timestamptz not null`
    - `updated_at timestamptz not null`

- `access_keys`
    - `access_key_id text pk`
    - `user_id uuid fk users(id)`
    - `label text not null`
    - `status text not null` (`active|disabled|deleted`)
    - `secret_encrypted bytea not null`
    - `secret_kid text not null` (for future rotation; set “v1”)
    - `created_at timestamptz not null`
    - `last_used_at timestamptz`
    - `deleted_at timestamptz`

### 5.2 Buckets & objects

- `buckets`
    - `id uuid pk`
    - `name text unique not null`
    - `owner_user_id uuid fk users(id)`
    - `created_at timestamptz not null`
    - `versioning_status text not null` (`off|enabled|suspended`)
    - `lifecycle_config_xml text` (nullable)
    - `cors_config_xml text` (nullable)
    - `website_config_xml text` (nullable)
    - `notification_config_xml text` (nullable)

- `object_versions`
    - `id uuid pk`
    - `bucket_id uuid fk buckets(id)`
    - `object_key text not null`
    - `version_id text not null` (public version id)
    - `is_delete_marker boolean not null default false`
    - `size_bytes bigint not null default 0`
    - `etag text` (S3-visible)
    - `content_type text`
    - `metadata_json jsonb not null default '{}'`
    - `tags_json jsonb not null default '{}'`
    - `created_at timestamptz not null`
    - `current boolean not null` (denormalized current pointer)
    - indexes:
        - `(bucket_id, object_key, current)`
        - `(bucket_id, object_key, created_at desc)`

### 5.3 Multipart uploads

- `multipart_uploads`
    - `id uuid pk`
    - `bucket_id uuid fk`
    - `object_key text not null`
    - `upload_id text unique not null`
    - `initiated_at timestamptz not null`
    - `status text not null` (`active|aborted|completed`)

- `multipart_parts`
    - `upload_id text fk multipart_uploads(upload_id)`
    - `part_number int not null`
    - `size_bytes bigint not null`
    - `etag text not null`
    - `manifest_id uuid not null` (points to staged manifest)
    - primary key `(upload_id, part_number)`

### 5.4 Chunking & placement

- `nodes`
    - `node_id uuid pk`
    - `role text not null` (`master|replica`)
    - `address_internal text not null` (e.g. http://replica1:9010)
    - `status text not null` (`online|offline|draining`)
    - `last_heartbeat_at timestamptz`
    - `capacity_bytes bigint`
    - `free_bytes bigint`
    - `created_at timestamptz not null`

- `join_tokens`
    - `token_id uuid pk`
    - `token_hash text not null`
    - `expires_at timestamptz not null`
    - `used_at timestamptz`

- `chunks`
    - `chunk_id uuid pk`
    - `size_bytes int not null`
    - `checksum_algo text not null` (`crc32c|sha256`)
    - `checksum_value bytea not null`
    - `created_at timestamptz not null`

- `chunk_replicas`
    - `chunk_id uuid fk chunks(chunk_id)`
    - `node_id uuid fk nodes(node_id)`
    - `state text not null` (`present|repairing|missing`)
    - `stored_at timestamptz`
    - primary key `(chunk_id, node_id)`

- `manifests`
    - `id uuid pk`
    - `total_size_bytes bigint not null`
    - `created_at timestamptz not null`

- `manifest_chunks`
    - `manifest_id uuid fk manifests(id)`
    - `chunk_index int not null`
    - `chunk_id uuid fk chunks(chunk_id)`
    - primary key `(manifest_id, chunk_index)`

- `object_version_manifests`
    - `object_version_id uuid fk object_versions(id)`
    - `manifest_id uuid fk manifests(id)`
    - primary key `(object_version_id)`

### 5.5 Audit logs (minimum)

- `audit_log`
    - `id uuid pk`
    - `ts timestamptz not null`
    - `actor_user_id uuid`
    - `actor_ip text`
    - `action text not null`
    - `target_type text`
    - `target_id text`
    - `outcome text not null` (`success|failure`)
    - `details_json jsonb not null default '{}'`

---

## 6. APIs to implement

### 6.1 S3 API (public on master)

**Must support:**
- Addressing:
    - Path-style: `/{bucket}/{key...}`
    - Virtual-host: `{bucket}.host/{key...}`

**Auth:**
- SigV4 header auth
- SigV4 query auth (presigned URLs)
- Support `UNSIGNED-PAYLOAD` for GET and common SDK behaviors.

**Core operations (MVP MUST):**
Buckets:
- `GET /` (ListBuckets)
- `PUT /{bucket}` (CreateBucket)
- `HEAD /{bucket}`
- `DELETE /{bucket}`
- `GET /{bucket}?location` (GetBucketLocation) — can return a constant like “local”

Objects:
- `PUT /{bucket}/{key}` (PutObject)
- `GET /{bucket}/{key}` (GetObject) — support `Range`
- `HEAD /{bucket}/{key}`
- `DELETE /{bucket}/{key}`
- `POST /{bucket}?delete` (DeleteObjects multi-delete)
- `GET /{bucket}?list-type=2` (ListObjectsV2) — prefix/delimiter/max-keys/continuation-token/start-after
- `GET /{bucket}` (ListObjects legacy; minimal)

Multipart (MVP MUST):
- `POST /{bucket}/{key}?uploads` (CreateMultipartUpload)
- `PUT /{bucket}/{key}?partNumber=N&uploadId=...` (UploadPart)
- `GET /{bucket}/{key}?uploadId=...` (ListParts)
- `POST /{bucket}/{key}?uploadId=...` (CompleteMultipartUpload)
- `DELETE /{bucket}/{key}?uploadId=...` (AbortMultipartUpload)
- `GET /{bucket}?uploads` (ListMultipartUploads)

Versioning (Phase 2 MUST, but implement if feasible in MVP):
- `GET /{bucket}?versioning`
- `PUT /{bucket}?versioning`
- `GET /{bucket}/{key}?versionId=...`
- `DELETE /{bucket}/{key}?versionId=...`
- `GET /{bucket}?versions`

Bucket notifications config:
- `GET /{bucket}?notification`
- `PUT /{bucket}?notification`

**Behavior requirements**
- S3-style XML responses for listings and errors.
- S3-style error codes (`NoSuchBucket`, `NoSuchKey`, `AccessDenied`, `InvalidAccessKeyId`, `SignatureDoesNotMatch`, etc.).
- Must return stable `ETag`.
    - Non-multipart: MD5 of full object content is acceptable.
    - Multipart: composite ETag (`md5(concat(md5(part_i))) + "-" + partCount`) is acceptable.

**Note:** Keep scope realistic. Aim for AWS CLI + SDK compatibility, not 100% of S3 features.

---

### 6.2 Console API (public on master)

Auth:
- `POST /console/v1/login`
- `POST /console/v1/logout`
- `GET /console/v1/me`

Access keys (self-service):
- `GET /console/v1/access-keys` (no secrets)
- `POST /console/v1/access-keys` → returns `accessKeyId` + `secretAccessKey` once
- `PATCH /console/v1/access-keys/{accessKeyId}` (disable)
- `DELETE /console/v1/access-keys/{accessKeyId}`

Presign helper (optional but recommended):
- `POST /console/v1/presign` `{ method, bucket, key, expiresSeconds }` -> `{ url }`

Bucket/object browsing endpoints for UI convenience (optional if UI calls S3 API directly):
- minimal endpoints to list buckets and objects

---

### 6.3 Admin API (public on master)

Auth:
- `POST /admin/v1/login`
- `POST /admin/v1/logout`
- `GET /admin/v1/me`

Users:
- `GET /admin/v1/users`
- `POST /admin/v1/users`
- `PATCH /admin/v1/users/{userId}` (enable/disable, reset password)
- `DELETE /admin/v1/users/{userId}` (optional)

Cluster:
- `GET /admin/v1/cluster/nodes`
- `POST /admin/v1/cluster/join-tokens` -> join token
- `POST /admin/v1/cluster/nodes/{nodeId}/drain` (optional)
- `DELETE /admin/v1/cluster/nodes/{nodeId}` (optional)

Audit:
- `GET /admin/v1/audit?since=&until=&userId=&action=`

---

### 6.4 Internal API (master internal + replica internal)

#### Master internal (listen `NSS_INTERNAL_LISTEN`)

Join:
- `POST /internal/v1/cluster/join`
    - headers: `Authorization: Bearer <join_token>`
    - body: `{ "addressInternal": "http://replica1:9010", "capacityBytes": 0, "freeBytes": 0 }`
    - response: `{ "nodeId": "...", "clusterConfig": { chunkSizeBytes, replicationFactor, writeQuorum, checksumAlgo } }`

Heartbeat:
- `POST /internal/v1/cluster/heartbeat`
    - body: `{ nodeId, freeBytes, capacityBytes, dataDirs: [...], ts }`

Placement lookup (optional for replicas):
- `GET /internal/v1/cluster/config`

#### Replica internal (listen `NSS_REPLICA_LISTEN`)

Chunk operations:
- `PUT /internal/v1/chunks/{chunkId}`
    - headers: `X-Checksum-Algo`, `X-Checksum-Value` (base64)
    - body: raw bytes of chunk
    - response: `201`
- `GET /internal/v1/chunks/{chunkId}`
    - supports `Range` (optional; can read full chunk and slice)
- `HEAD /internal/v1/chunks/{chunkId}`
- `DELETE /internal/v1/chunks/{chunkId}` (for GC/drain)

Security:
- Internal APIs must require a shared secret or mTLS.  
  MVP: shared bearer token via env `NSS_INTERNAL_SHARED_TOKEN` on all nodes.

---

## 7. Storage implementation details

### 7.1 Chunk store (local disk)

For each `NSS_DATA_DIRS`:
- store chunks in sharded directories: `chunks/aa/bb/{chunkId}`
- atomic write:
    - write to temp file
    - fsync
    - rename to final
- compute checksum while streaming in

### 7.2 Object write path (PUT Object / multipart completion)

1. Authenticate request (SigV4).
2. Authorize (MVP: only owner can access; later add policies).
3. Create a new object_version row (pending) or stage data.
4. Stream request body through chunker:
    - for each chunk:
        - compute checksum
        - choose replica nodes (placement)
        - `PUT chunk` to each chosen node
        - wait for `write_quorum` acks
        - record chunk + replicas in Postgres (can batch, but must commit consistently)
5. Create manifest with ordered chunk IDs.
6. Commit object_version + current pointer transactionally.
7. Emit event (if enabled).

Failure handling:
- If any chunk fails to meet quorum: abort request, mark staged chunks as unreferenced, allow GC job to clean them later.

### 7.3 Object read path (GET/HEAD)

1. Authenticate/authorize.
2. Resolve current version (or requested versionId).
3. Load manifest (chunk list).
4. For each required chunk:
    - pick an online replica with `present` state
    - fetch chunk bytes (stream)
    - verify checksum during read
    - if checksum mismatch:
        - mark replica chunk as suspect
        - retry another replica
        - schedule repair job to restore missing/failed replica

Range reads:
- Convert byte range to chunk_index range; trim start/end.

### 7.4 Repair & scrubber

- Repair worker: ensures each chunk has `replication_factor` healthy replicas.
- Scrubber: periodically verifies a sample or full scan of chunks; rate-limited.

---

## 8. Events (RabbitMQ optional)

### 8.1 Behavior

- If `NSS_RABBIT_URL` is set:
    - enable bucket notification configuration
    - publish events on object create/delete
- If not set:
    - event delivery disabled
    - notification config endpoints must return a clear error OR accept config but show “inactive” (choose one and be consistent).

### 8.2 RabbitMQ topology (recommendation)

- Exchange: `nss.events` (topic)
- Routing keys:
    - `s3.object.created`
    - `s3.object.removed`
- Message: JSON in S3 event notification style:
    - `Records: [{ eventName, eventTime, s3: { bucket: { name }, object: { key, size, eTag, versionId? }}, ... }]`

---

## 9. Redis (optional cache)

If `NSS_REDIS_URL` is set:
- use redis for:
    - rate limiting (login + S3 auth failures)
    - caching manifest lookups
    - session storage (optional)
      If not set:
- in-memory fallback with the same interface.

**Must not break functionality without Redis.**

---

## 10. Observability (Prometheus)

Expose:
- `GET /metrics`
- `GET /healthz` (always 200 if process alive)
- `GET /readyz` (200 only if:
    - Postgres reachable
    - data dirs writable
    - (replica) master reachable or has joined)

Metrics (minimum):
- `nss_http_requests_total{service,route,method,status}`
- `nss_http_request_duration_seconds_bucket{...}`
- `nss_s3_requests_total{op,status}`
- `nss_s3_bytes_in_total`, `nss_s3_bytes_out_total`
- `nss_chunk_write_total{result}`, `nss_chunk_read_total{result}`
- `nss_checksum_mismatch_total`
- `nss_repair_jobs_total{result}`, `nss_repair_backlog`
- `nss_node_heartbeat_age_seconds{node_id}`

---

## 11. Web UIs

### 11.1 User Console UI (MVP)

Pages:
- Login
- Buckets list
- Bucket object browser:
    - upload (single + multipart for large)
    - download
    - delete
- Access Keys:
    - create keypair (show secret once)
    - list keys (no secrets)
    - disable/delete
- Presigned URL generator (optional but recommended)

### 11.2 Admin UI (MVP)

Pages:
- Login
- Users:
    - create/disable/reset password
- Cluster:
    - nodes list + status
    - generate join token
- Audit log viewer
- Metrics/links page (optional)

---

## 12. Testing requirements

### 12.1 Unit tests (Go)

- SigV4 verification correctness for:
    - header auth
    - query auth
    - unsigned payload
- Chunker:
    - correct chunk boundaries
    - correct checksum computation
- Postgres repos:
    - transactional object finalize
    - versioning pointer updates
- Replica chunk API:
    - PUT/GET/HEAD integrity

### 12.2 Integration tests (docker compose)

Provide `deploy/docker-compose.yml` with:
- postgres
- master
- (optional) replica
- (optional) redis
- (optional) rabbitmq

Integration test script (`./scripts/it.sh`) must:
1. Bring up stack
2. Create admin + user
3. Login user console API
4. Create access key
5. Use **AWS CLI in a container** (recommended) with `--endpoint-url` to run:
    - create bucket
    - put object
    - list objects
    - get object
    - multipart upload (e.g., `aws s3 cp largefile ...`)
6. Disable key and assert auth fails.

### 12.3 Cluster tests (replica join)

- Start master + replica
- Admin generates join token
- Replica joins
- Upload object
- Assert `chunk_replicas` shows expected placements
- Kill one replica → reads still succeed if replication_factor >= 2 (if configured)

---

## 13. Implementation plan (milestones)

### Milestone A — Foundations
- Project scaffolding, docker-compose, postgres migrations
- Admin bootstrap login
- Console login + key issuance (secret one-time)
- Local chunkstore (single node)
- Basic S3 API: list/create bucket, put/get/delete object, list objects v2
- Prometheus metrics + health endpoints

### Milestone B — SigV4 compatibility + multipart
- Full SigV4 header & query support
- Presigned URLs
- Multipart upload endpoints
- Composite ETag support

### Milestone C — Cluster replication
- master internal API (join tokens, heartbeat)
- replica internal chunk API
- placement + replication factor + write quorum
- read fallback and repair scheduling

### Milestone D — Integrity, scrubber, lifecycle
- per-chunk checksums + read verify
- scrubber job
- lifecycle: abort incomplete multipart; expire objects (basic)

### Milestone E — Events (RabbitMQ)
- bucket notification config endpoints
- event generation + Rabbit publish
- admin UI event status (optional)

---

## 14. Important constraints & pitfalls (read carefully)

- **Never expose Secret Access Key again** after creation; only show once.
- Store secrets encrypted (AES-GCM) because SigV4 verification needs plaintext.
- Avoid buffering entire objects in memory; always stream.
- Ensure object finalization is atomic: only becomes visible after all chunks are committed and manifest stored.
- Range reads must work correctly across chunk boundaries.
- S3 error responses must be XML and match common clients’ expectations.
- If RabbitMQ/Redis not configured, service must still run and pass core S3 tests.

---

## 15. Deliverables checklist (Codex must produce)

- [ ] Go master + replica binaries
- [ ] Postgres migrations + schema
- [ ] S3 API core + multipart + (optionally) versioning
- [ ] Console API + User UI (login + access keys + object browser)
- [ ] Admin API + Admin UI (users + cluster join)
- [ ] Chunked storage + replication across replicas
- [ ] Checksums + read verification + repair queue
- [ ] `/metrics`, `/healthz`, `/readyz`
- [ ] docker-compose + Dockerfiles
- [ ] integration test script using AWS CLI container
- [ ] basic documentation in README (how to run, env vars)

---

## 16. Command expectations

Provide in README:

- Start:
    - `docker compose -f deploy/docker-compose.yml up --build`
- Run migrations automatically on startup (recommended) or via:
    - `./scripts/migrate.sh`
- Run tests:
    - `go test ./...`
    - `./scripts/it.sh`

---

End of task.md
