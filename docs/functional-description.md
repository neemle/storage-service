# Functional Description

Neemle Storage Service is a self-hosted, single-site object storage platform implemented in Rust.
It exposes an S3-compatible API for application workloads, plus dedicated admin/console APIs and UIs
for operational tasks.

## Components

- Master service
  - S3 API (port 9000)
  - Unified Console + Admin API/UI (port 9001)
  - Internal/replication API (port 9003)
  - Metrics endpoint (port 9100)
- Replica service (optional)
  - S3-compatible read data-plane for distributed content delivery
  - Joins the master for chunk replication
- Prometheus + Thanos sidecar
  - Scrapes native node metrics from master and replicas
  - Uploads Prometheus TSDB blocks to Neemle Storage Service object bucket
- Loki + Promtail
  - Collects container logs and stores log objects in Neemle Storage Service bucket
- Grafana
  - Preprovisioned Prometheus/Loki data sources and demo dashboards
- Postgres
  - Stores metadata, users, access keys, audit logs, and system state
- Redis (optional)
  - Cache and rate-limiting assistance
- RabbitMQ (optional)
  - Event delivery and async integrations

## Roles and Access

- Admin
  - Bootstrap admin credentials are configured via environment variables
  - Manages users, cluster join tokens, and cluster visibility
- Console user
  - Manages buckets, objects, metadata, and access keys
  - Generates presigned URLs for uploads, downloads, and deletes

## Core Workflows

- User onboarding
  1) Admin creates a console user.
  2) Console user signs in and creates access keys.
- Bucket management
  - Create, rename, and delete buckets.
  - Toggle public read access per bucket.
- Object management
  - Upload, download, rename, delete, and list objects.
  - View and edit object metadata.
  - Browse keys using prefix-based “folder” navigation.
- URL access
  - Public buckets expose stable object URLs.
  - Private buckets use short-lived presigned download URLs.
- Replication
  - Replicas join with a time-limited join token.
  - Chunks are replicated based on configured replication and quorum settings.
- Snapshots and backups
  - Snapshot policies capture immutable bucket state on schedule or on-create-change.
  - Backup policies execute full/incremental/differential runs into WORM backup buckets.
  - Backup runs are exportable as `tar` or `tar.gz`.

## Storage Model

- Objects are stored as chunks on disk (`NSS_DATA_DIRS`) with manifests recorded in Postgres.
- Chunk payload files are encrypted at rest by default with authenticated envelopes carrying key ids,
  enabling key rotation without breaking reads of older encrypted chunks.
- Metadata (object key, size, content type, ETag, custom metadata) is stored and indexed in Postgres.
- Multipart uploads are supported and cleaned up by a background GC interval.

### Why multiple data directories help

- `NSS_DATA_DIRS` can reference multiple mount points.
- NSS can distribute chunk placement across these paths, reducing single-disk bottlenecks for write-heavy
  and scan-heavy workloads.
- Operators can add storage by mounting another directory and extending `NSS_DATA_DIRS` without changing
  external API contracts.
- Isolating data across directories can improve operational recovery when one path fails or degrades.

## Replication behavior and benefits

- A replica joins the cluster with a time-limited join token created by an admin.
- Master tracks node heartbeat/state via internal endpoints and only uses healthy replicas for writes.
- Replication factor and write quorum parameters define durability guarantees for each write.
- Master handles client writes; replicas handle authenticated/presigned reads for out-of-the-box distributed
  content delivery.
- Access keys and presigned URLs issued by master are accepted by replica S3 endpoints for read requests.
- Replica sub-mode is remotely controlled by master:
  - `delivery`: replica serves read traffic.
  - `backup`: replica does not serve client S3 content.
- For presigned URL consistency across nodes, use one shared S3 public hostname/load balancer that fronts
  master and replica S3 endpoints.
- Multi-node replication improves availability for object reads and durability for chunk data after
  single-node failures.

## Security and Integrity

- Access keys are encrypted at rest using `NSS_SECRET_ENCRYPTION_KEY_BASE64`.
- Chunk payloads are encrypted at rest using chunk encryption settings:
  - `NSS_CHUNK_ENCRYPTION_ENABLED`
  - `NSS_CHUNK_ENCRYPTION_ACTIVE_KEY_ID`
  - `NSS_CHUNK_ENCRYPTION_KEY_BASE64` or `NSS_CHUNK_ENCRYPTION_KEYS`
- Legacy plaintext chunk reads can be temporarily allowed during migration by setting
  `NSS_CHUNK_ENCRYPTION_ALLOW_PLAINTEXT_READ=true`.
- JWT sessions use a dedicated signing key (`NSS_JWT_SIGNING_KEY_BASE64`) or a derived signing key.
- Access-key update/delete operations are owner-scoped and reject cross-user mutations.
- WORM buckets use write-once semantics: first object create is allowed, overwrite/delete
  mutations are rejected.
- Non-dev mode rejects insecure `change-me` values for bootstrap/internal shared secrets.
- API sessions for admin/console use signed tokens.
- S3 requests are authenticated with SigV4 signatures.
- Optional checksum validation (`crc32c`, `sha256`, or both).
- Rate limiting is enforced for repeated authentication failures.

## Observability

- Structured logs with configurable log level (`NSS_LOG_LEVEL`).
- Prometheus-style metrics endpoint.
- Audit log records for admin and console actions.
- Snapshot and backup policy/run state is persisted in Postgres for operational traceability.
- Root compose demo includes Prometheus, Loki, Promtail, and Grafana out of the box.
- Loki object data is stored in bucket `NSS_OBS_LOKI_BUCKET`.
- Thanos sidecar uploads Prometheus TSDB blocks to bucket `NSS_OBS_PROM_BUCKET`.
- Grafana dashboards are preprovisioned and fed by live demo traffic generated in stack.
