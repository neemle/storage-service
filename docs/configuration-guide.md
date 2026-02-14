# Configuration Guide

Neemle Storage Service is configured entirely through environment variables. Most settings are read at
startup and apply to the master and replica services.

## Required settings

These must be set for the master:

- `NSS_MODE` (required)
  - `master` or `replica`
- `NSS_POSTGRES_DSN` (required)
  - Example: `postgres://nss:nss@postgres:5432/nss?sslmode=disable`
- `NSS_DATA_DIRS` (required)
  - Comma-separated list of storage paths, e.g. `/data` or `/data1,/data2`
  - Using multiple paths helps distribute chunk I/O and makes future capacity expansion easier.
- `NSS_SECRET_ENCRYPTION_KEY_BASE64` (required)
  - Base64-encoded 32 bytes
- `NSS_JWT_SIGNING_KEY_BASE64` (optional, recommended)
  - Base64-encoded 32 bytes used for JWT signing.
  - If omitted, NSS derives a dedicated signing key from `NSS_SECRET_ENCRYPTION_KEY_BASE64`.
- `NSS_CHUNK_ENCRYPTION_ENABLED` (optional, default `true`)
  - Enables encryption-at-rest for chunk payload files under `NSS_DATA_DIRS`.
- `NSS_CHUNK_ENCRYPTION_ACTIVE_KEY_ID` (optional, default `default`)
  - Key id attached to newly written encrypted chunks.
- `NSS_CHUNK_ENCRYPTION_ALLOW_PLAINTEXT_READ` (optional, default `true`)
  - Migration compatibility mode for reading legacy plaintext chunks.
  - Set to `false` after migration to enforce encrypted-only reads.
- `NSS_CHUNK_ENCRYPTION_KEY_BASE64` (optional)
  - Optional dedicated 32-byte base64 key for chunk encryption.
  - Used when `NSS_CHUNK_ENCRYPTION_KEYS` is not set.
- `NSS_CHUNK_ENCRYPTION_KEYS` (optional)
  - Keyring for rotation using format `key_id:base64,key_id2:base64`.
  - Must include the active key id when set.
- `NSS_AUTH_MODE` (optional, default `internal`)
  - `internal`, `oidc`, `oauth2`, or `saml2`

When `NSS_AUTH_MODE` is `oidc`, `oauth2`, or `saml2`, these become required:

- `NSS_OIDC_ISSUER_URL`
  - Example: `https://keycloak.example.com/realms/nss`
- `NSS_OIDC_CLIENT_ID`
- `NSS_OIDC_REDIRECT_URL`
  - Example: `https://storage.example.com/console/v1/oidc/callback`
- `NSS_OIDC_ADMIN_GROUPS`
  - Comma-separated groups allowed to act as NSS admins in external auth mode.

For local `docker-compose.yml`, the DSN is composed from split DB settings in `.env`:

- `DB_HOST`
- `DB_PORT`
- `DB_USER`
- `DB_PASS`
- `DB_BASE`

## `.env` reference (local defaults)

The repository includes `.env.dist` as the default local template. Copy it to `.env` and adjust secrets.

- `NSS_MODE=master`
  - Runtime mode for local stack (`master` or `replica`).
- `CARGO_PKG_VERSION=0.1.0`
  - Application version value surfaced by runtime and build scripts.
- `DB_HOST=postgres`
  - Postgres host used by Docker Compose when building `NSS_POSTGRES_DSN`.
- `DB_PORT=5432`
  - Postgres port used by Docker Compose when building `NSS_POSTGRES_DSN`.
- `DB_USER=nss`
  - Postgres user used by Docker Compose when building `NSS_POSTGRES_DSN`.
- `DB_PASS=nss`
  - Postgres password used by Docker Compose when building `NSS_POSTGRES_DSN`.
- `DB_BASE=nss`
  - Postgres database name used by Docker Compose when building `NSS_POSTGRES_DSN`.
- `NSS_DATA_DIRS=/data`
  - Data directories mounted in containers for chunk/object storage.
- `NSS_ADMIN_BOOTSTRAP_USER=admin`
  - Initial bootstrap admin username.
- `NSS_ADMIN_BOOTSTRAP_PASSWORD=LocalAdmin!2026UseStrongSecret`
  - Initial bootstrap admin password.
  - Must not be `change-me` when `NSS_INSECURE_DEV=false`.
- `NSS_ADMIN_BOOTSTRAP_FORCE_PASSWORD=true`
  - When `true`, master startup re-syncs bootstrap admin password to `.env` value.
  - Useful for deterministic local/demo bootstraps on reused local DB data.
- `NSS_AUTH_MODE=internal`
  - Authentication mode:
    - `internal`: username/password login against local users.
    - `oidc`: browser login through OIDC provider (for example Keycloak).
    - `oauth2`: browser login via OAuth2 authorization code flow using OIDC-compatible metadata.
    - `saml2`: browser login via SAML2 IdP bridge exposing OIDC-compatible login metadata to NSS.
- `NSS_OIDC_ISSUER_URL=http://keycloak:8080/realms/nss`
  - OIDC issuer base URL used for discovery.
- `NSS_OIDC_CLIENT_ID=nss-console`
  - OIDC client id used during auth code exchange.
- `NSS_OIDC_CLIENT_SECRET=`
  - Optional OIDC client secret (required by some providers/clients).
- `NSS_OIDC_REDIRECT_URL=http://localhost:9001/console/v1/oidc/callback`
  - Redirect URI registered on OIDC provider.
- `NSS_OIDC_SCOPES=openid profile email`
  - Space-separated OIDC scopes requested during login.
- `NSS_OIDC_AUDIENCE=nss-console`
  - Expected `aud` claim for ID token validation (defaults to client id).
- `NSS_OIDC_USERNAME_CLAIM=preferred_username`
  - OIDC claim used to map/create NSS user username.
- `NSS_OIDC_DISPLAY_NAME_CLAIM=name`
  - OIDC claim used as display name for first-time user creation.
- `NSS_OIDC_GROUPS_CLAIM=groups`
  - Claim path used to read group/role memberships (supports dot path syntax).
- `NSS_OIDC_ADMIN_GROUPS=nss-admin`
  - Comma-separated groups that grant admin privileges in OIDC mode.
- `NSS_SECRET_ENCRYPTION_KEY_BASE64=...`
  - Base64-encoded 32-byte key for secret encryption at rest.
- `NSS_JWT_SIGNING_KEY_BASE64=...`
  - Base64-encoded 32-byte key for JWT session signing.
  - Optional: if omitted, NSS derives a distinct signing key from encryption key material.
- `NSS_CHUNK_ENCRYPTION_ENABLED=true`
  - Enables encryption-at-rest for chunk payloads in `NSS_DATA_DIRS`.
- `NSS_CHUNK_ENCRYPTION_ACTIVE_KEY_ID=default`
  - Key id used for encrypting new chunks.
- `NSS_CHUNK_ENCRYPTION_ALLOW_PLAINTEXT_READ=false`
  - Strict mode for encrypted-only chunk reads.
  - Set `true` temporarily during migration from plaintext chunk files.
- `NSS_CHUNK_ENCRYPTION_KEY_BASE64=`
  - Optional dedicated active chunk key (32-byte base64).
  - Empty value means fallback to `NSS_SECRET_ENCRYPTION_KEY_BASE64`.
- `NSS_CHUNK_ENCRYPTION_KEYS=`
  - Optional rotation keyring in format `key_id:base64,key_id2:base64`.
  - When set, it must include `NSS_CHUNK_ENCRYPTION_ACTIVE_KEY_ID`.
- `NSS_INTERNAL_SHARED_TOKEN=1739d09514c62ad91499f636350c4a3d9d15644aaf794713`
  - Shared bearer token for internal service-to-service endpoints.
  - Must not be `change-me` when `NSS_INSECURE_DEV=false`.
- `NSS_REPLICATION_FACTOR=1`
  - Target number of replicas per write in local/default setup.
- `NSS_WRITE_QUORUM=1`
  - Minimum successful writes required to acknowledge a write.
- `NSS_REPLICA_SUB_MODE=delivery`
  - Initial replica runtime sub-mode (`delivery` or `backup`).
  - Master-admin runtime config can override this during operation.
- `NSS_S3_MAX_TIME_SKEW_SECONDS=900`
  - Allowed timestamp skew for signed S3 requests.
- `NSS_MULTIPART_TTL_SECONDS=86400`
  - Expiration for unfinished multipart uploads.
- `NSS_GC_INTERVAL_SECONDS=3600`
  - Background garbage-collection interval.
- `NSS_CORS_ALLOW_ORIGINS=http://localhost:9001`
  - Allowed origins for API/UI CORS in local development.
- `NSS_API_LISTEN=:9001`
  - Unified API/UI listen address.
- `NSS_INTERNAL_ADVERTISE=http://master:9003`
  - Advertised internal address for master-to-replica communication.
- `NSS_REPLICA_ADVERTISE=http://replica:9010`
  - Advertised replica address for replication traffic.
- `NSS_S3_PUBLIC_URL=http://localhost:9000`
  - Public S3 base URL used in links and presigned URL generation.
- `NSS_MIGRATION_AUTO_REPAIR=true`
  - Dev safety valve for SQLx migration checksum mismatch recovery on local persisted DB.
  - Only migration version `0004` is auto-repaired when enabled.
- `NSS_REPLICA1_JOIN_TOKEN=replica-1-join-token-demo`
  - Static join token used by root compose demo for `replica1`.
- `NSS_REPLICA2_JOIN_TOKEN=replica-2-join-token-demo`
  - Static join token used by root compose demo for `replica2`.
- `NSS_OBS_ACCESS_KEY_LABEL=observability-bootstrap`
  - Label used when observability bootstrap creates an S3 access key.
- `NSS_OBS_LOKI_BUCKET=nss-observability-loki`
  - Bucket used by Loki object storage backend.
- `NSS_OBS_PROM_BUCKET=nss-observability-prometheus`
  - Bucket used by Thanos sidecar for Prometheus TSDB block uploads.
- `NSS_OBS_DEMO_BUCKET=nss-observability-demo`
  - Bucket used by demo traffic generator for live dashboard data.
- `GRAFANA_ADMIN_USER=admin`
  - Grafana bootstrap username for local demo stack.
- `GRAFANA_ADMIN_PASSWORD=admin`
  - Grafana bootstrap password for local demo stack.

## Identity and access

- `NSS_ADMIN_BOOTSTRAP_USER` (default `admin`)
- `NSS_ADMIN_BOOTSTRAP_PASSWORD` (default `change-me`)
  - Non-dev mode rejects `change-me`.
- `NSS_AUTH_MODE` (default `internal`)
  - `internal`, `oidc`, `oauth2`, or `saml2`.
- `NSS_JWT_SIGNING_KEY_BASE64` (optional)
  - Dedicated JWT signing key. If omitted, NSS derives one from encryption key material.
- `NSS_INTERNAL_SHARED_TOKEN` (default `change-me`)
  - Shared bearer token for internal APIs.
  - Non-dev mode rejects `change-me`.
- OIDC settings (used when `NSS_AUTH_MODE` is `oidc`, `oauth2`, or `saml2`):
  - `NSS_OIDC_ISSUER_URL` (required in external auth mode)
  - `NSS_OIDC_CLIENT_ID` (required in external auth mode)
  - `NSS_OIDC_CLIENT_SECRET` (optional)
  - `NSS_OIDC_REDIRECT_URL` (required in external auth mode)
  - `NSS_OIDC_SCOPES` (default `openid profile email`)
  - `NSS_OIDC_AUDIENCE` (default: client id)
  - `NSS_OIDC_USERNAME_CLAIM` (default `preferred_username`)
  - `NSS_OIDC_DISPLAY_NAME_CLAIM` (default `name`)
  - `NSS_OIDC_GROUPS_CLAIM` (default `groups`; dot-path supported)
  - `NSS_OIDC_ADMIN_GROUPS` (comma-separated admin groups)

## Networking

Listen addresses default to all interfaces on the listed ports:

- `NSS_S3_LISTEN` (default `:9000`)
- `NSS_API_LISTEN` (default `:9001`)
- `NSS_INTERNAL_LISTEN` (default `:9003`)
- `NSS_REPLICA_LISTEN` (default `:9010`)
- `NSS_METRICS_LISTEN` (default `:9100`)

Advertised addresses (optional):
- `NSS_INTERNAL_ADVERTISE`
- `NSS_REPLICA_ADVERTISE`

CORS:
- `NSS_CORS_ALLOW_ORIGINS`
  - Comma-separated list.
  - `*` is allowed only when `NSS_INSECURE_DEV=true`.

## S3 and URLs

- `NSS_S3_PUBLIC_URL`
  - Public base URL for S3 links and presigned URLs (useful behind a reverse proxy)
- `NSS_S3_MAX_TIME_SKEW_SECONDS` (default `900`)

## Storage and replication

- `NSS_REPLICATION_FACTOR` (default `1`)
- `NSS_WRITE_QUORUM` (default = replication factor)
- `NSS_CHUNK_SIZE_BYTES` (optional)
- `NSS_CHUNK_MIN_BYTES` (default `4194304`)
- `NSS_CHUNK_MAX_BYTES` (default `67108864`)
- `NSS_CHECKSUM_ALGO` (default `crc32c`)
  - `crc32c`, `sha256`, or `both`
- `NSS_CHUNK_ENCRYPTION_ENABLED` (default `true`)
- `NSS_CHUNK_ENCRYPTION_ACTIVE_KEY_ID` (default `default`)
- `NSS_CHUNK_ENCRYPTION_ALLOW_PLAINTEXT_READ` (default `true`)
- `NSS_CHUNK_ENCRYPTION_KEY_BASE64` (optional)
- `NSS_CHUNK_ENCRYPTION_KEYS` (optional)

Replica-only settings:
- `NSS_MASTER_URL` (required for replicas)
- `NSS_JOIN_TOKEN` (required for replicas)
- `NSS_REPLICA_SUB_MODE` (optional, default `delivery`)
  - `delivery`: replica serves authenticated/presigned reads.
  - `backup`: replica blocks client S3 serving and runs backup-only workload.

Operational notes:
- Replication factor controls how many nodes should hold chunk replicas.
- Write quorum controls how many successful writes are required before acknowledging writes.
- Master S3 data-plane remains the write endpoint; replica S3 data-plane is intended for read delivery.
- Master-created access keys and master-generated presigned URLs are valid on replica read endpoints.
- Use one shared `NSS_S3_PUBLIC_URL` host (typically behind a load balancer) across master/replicas so
  presigned URL host/signature validation remains consistent.
- For multi-disk hosts, set `NSS_DATA_DIRS` to multiple mount points to reduce single-disk hot spots.
- Snapshot and backup schedules/retention/targets are configured through admin APIs (stored in Postgres), not
  environment variables.
- Backup destination buckets must be marked WORM (`is_worm=true`), otherwise backup policy creation is rejected.
- Chunk encryption notes:
  - New chunk writes are encrypted at rest when chunk encryption is enabled.
  - Rotation is achieved by changing active key id while keeping old key ids in keyring.
  - Disable plaintext compatibility after migration for strict encrypted-only operation.

## Background jobs

- `NSS_SCRUB_INTERVAL_SECONDS` (default `3600`)
- `NSS_REPAIR_WORKERS` (default `4`)
- `NSS_MULTIPART_TTL_SECONDS` (default `86400`)
- `NSS_GC_INTERVAL_SECONDS` (default `3600`)

## Optional services

- `NSS_REDIS_URL`
- `NSS_RABBIT_URL`

If unset, Neemle Storage Service uses in-memory fallbacks and events are disabled.

## Logging and dev options

- `NSS_LOG_LEVEL` (default `info`)
- `NSS_INSECURE_DEV` (default `false`)

## Postgres connection tuning

- `NSS_POSTGRES_CONNECT_RETRIES` (default `30`)
- `NSS_POSTGRES_CONNECT_DELAY_MS` (default `1000`)

## Migration path override

- `NSS_MIGRATIONS_DIR` (optional)
  - Overrides SQL migration directory lookup.
  - If unset, NSS checks `/app/migrations`, then `internal/meta/migrations`, then `meta/migrations`.

## UI serving

- `NSS_UI_DIR` (optional)
  - When set, serve the UI from this directory instead of the embedded bundle.

### Runtime UI overrides

The UI loads a runtime config script before bootstrapping.
Replace this file to override the API base without rebuilding (only when using `NSS_UI_DIR`):

- `/ui/assets/runtime-config.js`

Example:

```js
window.__API_BASE__ = 'https://api.example.com';
```

Legacy variables `window.__CONSOLE_API_BASE__` and `window.__ADMIN_API_BASE__` are still honored if
`window.__API_BASE__` is not set.
