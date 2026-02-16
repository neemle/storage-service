# Neemle Storage Service Functional Specification

This document is the business and behavior source of truth for this repository.
When implementation and docs differ, this document wins.

## Product Identity

- Product name: **Neemle Storage Service**
- Short description: self-hosted, single-site, S3-compatible object storage
- Primary surfaces:
  - S3 API for application data access
  - Unified Console/Admin API + web UI for operations
  - Internal replication API for cluster membership and chunk movement

## Why It Works

- Object data is written to local chunk storage (`NSS_DATA_DIRS`) and described by metadata rows in Postgres.
- Multiple `NSS_DATA_DIRS` values let operators spread chunk I/O across disks, reducing contention and
  improving recovery options when a single disk path degrades.
- The service can present S3-compatible behavior because object, bucket, multipart, and auth flows map to
  explicit handlers backed by metadata and chunk operations.
- Admin and console workflows are stable because user/session/access-key state is persisted and validated
  before each privileged action.
- Authentication mode is explicit:
  - `internal`: local username/password credentials are validated by Neemle Storage Service.
  - `oidc`: browser login is delegated to an OpenID Connect provider (for example Keycloak), and NSS
    issues local session tokens only after validating provider ID tokens.
  - `oauth2`: browser login uses the same authorization-code redirect/callback pipeline as OIDC, with
    provider metadata/token validation configured through OIDC-compatible env values.
  - `saml2`: browser login is federated through an external identity provider bridge that exposes an
    OIDC-compatible authorization-code surface to NSS.
- Replica join and heartbeat paths let the master reason about node availability and replication state.
- Every node (master and replica) periodically refreshes its filesystem capacity and free bytes in the
  database so that the console and admin APIs report up-to-date `maxAvailableBytes` per bucket.
- Replication factor and write quorum settings allow balancing durability and write availability for
  single-site clusters with one or more replicas.
- Master-issued access keys and presigned URLs are validated against shared metadata so replicas can
  serve read traffic out of the box for distributed content delivery.
- Snapshot policies can automatically capture immutable bucket point-in-time records on
  `hourly`, `daily`, `weekly`, `monthly`, and `on_create_change` triggers.
- On-demand snapshots can be created manually for any bucket and used to create a new bucket from
  the recorded object state.
- Backup policies can run `full`, `incremental`, or `differential` executions on
  `hourly`, `daily`, `weekly`, `monthly`, and `on_demand` triggers.
- Backup policies support strategy declarations `3-2-1`, `3-2-1-1-0`, and `4-3-2`, plus external
  target descriptors for S3/Glacier/SFTP/other services.
- External backup targets are validated on policy create/update and can be connection-tested through
  admin APIs and the console UI before policy execution.
- Backup archives are exportable as `tar` or `tar.gz` and can be generated on-demand with maximum
  gzip compression for `tar.gz`.
- Chunk payload files in `NSS_DATA_DIRS` are encrypted at rest using an authenticated envelope that
  carries a key id, so active encryption keys can rotate without breaking reads of older chunks.
- Migration mode can temporarily allow plaintext legacy chunk reads while new and rewritten chunks
  are persisted encrypted.
- Observability demo topology runs one master and three replicas (delivery, backup, volume),
  with Prometheus/Loki/Grafana attached.
- Loki writes logs to a dedicated bucket in Neemle Storage Service.
- Thanos sidecar uploads Prometheus TSDB blocks to a dedicated Neemle Storage Service bucket.
- Node runtime model is explicit:
  - `master`: control-plane node for writes, policy management, scheduling, and cluster coordination.
  - `slave-delivery`: read-delivery node for authenticated and presigned S3 read traffic.
  - `slave-backup`: backup-only node that never serves client S3 content.
  - `slave-volume`: storage-capacity node focused on replicated chunk durability and recovery workflows.
- Slave runtime mode and slave backup policy assignment are configured remotely from master admin APIs.

## Business Rules And Invariants

- Scope is single-site only. Multi-region behavior is out of scope.
- `NSS_SECRET_ENCRYPTION_KEY_BASE64` must decode to 32 bytes.
- `NSS_AUTH_MODE` controls login mode and must be `internal`, `oidc`, `oauth2`, or `saml2`.
- When `NSS_AUTH_MODE` is `oidc`, `oauth2`, or `saml2`, OIDC-compatible issuer/client/redirect settings
  must be configured and valid.
- JWT signing must use key material separated from secret-at-rest encryption keys.
- Access keys are encrypted at rest.
- Chunk payloads are encrypted at rest by default when data is written to local storage paths.
- Encrypted chunk envelopes must include a key id resolvable from configured chunk encryption keys.
- When plaintext legacy read compatibility is disabled, plaintext chunk payloads are rejected.
- S3 API authentication uses SigV4.
- Public bucket reads can bypass private presign requirements; private buckets require auth or presigned URLs.
- Bootstrap admin credentials must exist at startup.
- If `NSS_ADMIN_BOOTSTRAP_FORCE_PASSWORD=true`, master startup re-syncs bootstrap admin password
  to the configured env value.
- In non-dev mode (`NSS_INSECURE_DEV=false`), `NSS_ADMIN_BOOTSTRAP_PASSWORD` and
  `NSS_INTERNAL_SHARED_TOKEN` must not use insecure default values.
- Slaves must present a valid join token to join a cluster.
- External object writes are handled by master data-plane endpoints.
- `slave-delivery` data-plane endpoints are read-only for client traffic.
- `slave-backup` and `slave-volume` reject client S3 traffic.
- WORM buckets enforce write-once semantics for user traffic: first object creation is allowed,
  while overwrite/delete and other mutating requests are rejected.
- Console/API CORS with credentials requires explicit allowed origins; wildcard origin is only allowed in dev mode.
- If Redis or RabbitMQ are not configured, core storage still works with in-memory/event-disabled fallbacks.
- Console UI is structured into dedicated pages/components so authentication, settings, and operational views
  can evolve independently without changing business behavior.
- Console Admin storage section provides inline operator help hints for WORM, snapshot, backup strategy,
  and node mode decisions.
- Console Admin storage section is split into operator-safe parts:
  - Nodes
  - Buckets
  - Snapshots
  - Backups
- Embedded UI static assets include precompressed `.gz` variants generated at build time using maximum gzip
  compression and are served with `Content-Encoding: gzip` when the client advertises gzip support.
- Dev demo `docker compose up --build` starts one master plus three connected replicas
  (`slave-delivery`, `slave-backup`, `slave-volume`) and includes Prometheus, Loki, and Grafana
  with preprovisioned dashboards.
- Observability object storage uses separate buckets for logs and metrics blocks.

## Use Cases

### UC-001: Admin bootstrap and sign-in

Happy path:
1. Operator starts master with bootstrap admin credentials.
2. Admin signs in from the unified UI:
   - by username/password when `NSS_AUTH_MODE=internal`, or
   - via provider redirect/callback when `NSS_AUTH_MODE` is `oidc`, `oauth2`, or `saml2`.
3. Admin can access cluster and user management views.

Failure modes:
- Invalid credentials return auth failure.
- OIDC state/nonce or token validation failures return auth failure.
- OAuth2/SAML2 broker redirect/token failures return auth failure.
- Missing/invalid session token blocks admin routes.

Acceptance:
- Admin login returns a token and UI session state.
- Unauthorized access is rejected.
- Login behavior follows configured auth mode and does not silently fall back to another mode.

### UC-002: Console key lifecycle

Happy path:
1. Signed-in console user creates an access key.
2. Service returns key id and secret once.
3. User can disable and delete keys.

Failure modes:
- Invalid session token returns unauthorized.
- Duplicate/invalid operations return validation or conflict errors.
- Attempting to update/delete another user's access key returns forbidden.

Acceptance:
- Created keys can be listed and managed by their owner according to policy.

### UC-003: Bucket and object lifecycle

Happy path:
1. User creates a bucket.
2. User uploads, lists, downloads, renames, and deletes objects.
3. User updates object metadata.

Failure modes:
- Missing bucket/object returns not found.
- Invalid names/requests return validation errors.
- Auth failures return unauthorized/forbidden.

Acceptance:
- Metadata and object state remain consistent after each operation.
- Console bucket listing includes `boundNodeIds` and `maxAvailableBytes` derived from writable bound volumes.
- When no explicit binding exists, free-space calculations use the default writable volume set.

### UC-004: Replica join and replication

Happy path:
1. Admin creates join token.
2. Replica starts with token and joins master.
3. Cluster reports replica online and records chunk replicas.
4. Replica serves object reads using master-issued access keys and presigned URLs.

Failure modes:
- Invalid/expired token blocks join.
- Offline replica does not receive new writes until healthy.
- Client write attempts to replica data-plane endpoints are rejected.

Acceptance:
- Joined replica appears in node inventory and participates in replication paths.
- Joined replica can serve authenticated and presigned read traffic for distributed content delivery.

### UC-005: Public and presigned URL access

Happy path:
1. Public bucket object can be fetched from its public URL.
2. Private bucket object can be fetched via valid presigned URL.
3. Access keys created on master authenticate valid read access on replica data-plane endpoints.
4. Presigned URLs generated by master are accepted by replica data-plane endpoints for read access.

Failure modes:
- Expired/invalid signatures are rejected.
- Private object without auth/presign is rejected.

Acceptance:
- URL behavior matches bucket visibility and signature validity.
- Replica-delivered reads follow the same auth and signature rules as master-delivered reads.

### UC-006: CI/CD delivery contract

Happy path:
1. Every push/PR runs the full fail-fast test pipeline in order.
2. Every push/PR runs Rust dependency advisory audit using repository policy (`audit.toml`).
3. Tag push additionally produces release binaries and publishes release artifacts.

Failure modes:
- Any failing stage stops downstream stages.
- Release artifacts are not published when prior stages fail.

Acceptance:
- CI executes stages in this order: unit, integration, curl, base UI, UI, runtime, production.
  Unit stage includes backend unit and frontend unit tests.
  Integration stage includes backend integration and frontend integration tests.
- CI blocks build/test stages when security audit fails (except explicitly ignored advisories in policy).
- All test suites run in Docker containers.
- Frontend Playwright runs always produce HTML report plus screenshot/video artifacts under
  `test-results/*`.
- UI/production Playwright runners must verify that each requested project executes and that videos exist
  for all executed tests.
- Tag builds publish cross-platform binaries as release assets.

Operational tooling acceptance:
- `scripts/run-tests.sh` supports fail-fast full pipeline (`all`) and targeted stage keys
  (for example `api-unit`, `api-integration`, `api-curl`, `enc`).
- `scripts/memory-leak-check.sh` runs Dockerized leak checks and emits summary/logs in
  `test-results/memcheck/*`.
- Memcheck quality gate fails on non-zero `definitely_lost_bytes` or `indirectly_lost_bytes`.
  `possibly_lost_bytes` is recorded as warning because runtime internals can produce false positives.
- `scripts/build-production-image.sh <image> <tag>` builds two tags (`<tag>` and `latest`) and
  sets app build version via build arg.

### UC-007: Console UI delivery and rendering contract

Happy path:
1. Operator opens the console UI from the embedded backend static bundle.
2. Browser requests assets with `Accept-Encoding: gzip`.
3. Service responds with precompressed UI assets and correct content type/encoding headers.
4. User navigates login, settings, and operations views rendered by dedicated UI components.

Failure modes:
- If a compressed variant is unavailable, the uncompressed asset is served.
- Missing static assets return not found.

Acceptance:
- Build outputs for embedded UI contain both original assets and `.gz` variants.
- UI routing fallback (`index.html`) remains functional for client-side routes.
- Admin storage protection view shows inline operator hints for backup strategies (`3-2-1`, `3-2-1-1-0`,
  `4-3-2`) and related WORM/snapshot/replica operations.
- Visual/behavioral output remains equivalent to existing console business use cases (UC-001..UC-005).

### UC-008: Admin audit pagination

Happy path:
1. Admin opens audit view.
2. UI requests audit entries with offset/limit.
3. UI paginates forward/backward using server-side slices.

Failure modes:
- Unauthorized request is rejected.
- Invalid pagination params are rejected.

Acceptance:
- Audit endpoint honors `offset` and `limit` query params.
- UI pagination controls correctly reflect available next/previous pages.

### UC-009: Bucket snapshot lifecycle and restore

Happy path:
1. Admin configures snapshot policy for a bucket (scheduled or `on_create_change`) or requests an on-demand snapshot.
2. Service stores immutable snapshot entries for current object versions in that bucket.
3. Admin restores a new bucket from a snapshot.

Failure modes:
- Missing bucket/snapshot returns not found.
- Invalid trigger value or invalid restore request returns validation error.
- Unauthorized request is rejected.

Acceptance:
- Snapshot records include trigger kind, timestamp, object count, and total size.
- Restore creates a new bucket with object metadata/content matching snapshot entries.
- Admin UI lists snapshot policies for the selected bucket and can load/edit policy values.

### UC-010: Backup policy execution and retention

Happy path:
1. Admin creates backup policy with type (`full|incremental|differential`), schedule, strategy, retention,
   and backup bucket target.
2. Scheduler (or on-demand execution) runs the policy.
3. Service writes archive objects to backup bucket and records backup run metadata.
4. Retention policy prunes oldest run metadata beyond configured keep count.

Failure modes:
- Backup policy referencing non-WORM backup bucket is rejected.
- Invalid schedule/type/strategy is rejected.
- Invalid external target descriptors or unreachable target endpoints are rejected by the
  connection-test workflow.
- Backup run failures are recorded with error status.

Acceptance:
- Backup runs are queryable with status, trigger, archive path, and size.
- Backup retention configuration is enforced after successful runs.
- Backup scope accepts `master` and `slave` (`replica` alias accepted); persisted scope remains canonical
  (`master` or `replica`).
- Slave-scoped backup policies are accepted only for nodes configured as `slave-backup`.
- Admin UI can create and update backup policies without direct API calls.
- Admin API and UI provide remote target connection testing for configured backup destinations.
- Admin UI `Show example` loads valid external target JSON including both `s3` and `sftp` target templates.

### UC-011: Slave node mode control

Happy path:
1. Admin sets slave runtime mode remotely from master.
2. Slave syncs runtime mode.
3. In `slave-delivery` mode, node serves authenticated/presigned reads.
4. In `slave-backup` mode, node rejects client S3 traffic and can execute slave-scoped backup policies.
5. In `slave-volume` mode, node rejects client S3 traffic and remains focused on storage durability tasks.

Failure modes:
- Unauthorized runtime mode update is rejected.
- Unknown runtime mode value is rejected.

Acceptance:
- Runtime mode changes are persisted and applied without changing business identity or auth rules.
- Non-delivery modes block client content serving on slave data-plane endpoints.
- Slave backup scheduling is active only while local sub-mode is `backup`.

### UC-012: Federated login (OIDC/OAuth2/SAML2 bridge)

Happy path:
1. Operator sets `NSS_AUTH_MODE` to `oidc`, `oauth2`, or `saml2` and configures OIDC-compatible env values.
2. User starts login from UI and is redirected to provider authorization endpoint.
3. Provider returns authorization code to NSS callback.
4. NSS exchanges code for tokens, validates ID token (issuer, audience, signature, nonce), and creates a local
   session token.
5. User is redirected back to UI as signed-in user.

Failure modes:
- Missing federated auth configuration blocks startup.
- Invalid callback `state` or missing `code` is rejected.
- Token exchange failure or invalid ID token is rejected.

Acceptance:
- Federated auth flow is available for `oidc`, `oauth2`, and `saml2` modes.
- Internal password login endpoint is rejected when auth mode is not `internal`.
- Admin authorization in federated mode is derived from configured claims/groups policy.

### UC-012: Backup archive export

Happy path:
1. Admin requests backup run export in `tar` or `tar.gz`.
2. Service generates archive from recorded backup source state.
3. Admin downloads archive for external transfer or offline restore workflows.

Failure modes:
- Missing backup run returns not found.
- Invalid export format returns validation error.
- Unauthorized request is rejected.

Acceptance:
- Export endpoint supports `tar` and `tar.gz`.
- `tar.gz` uses maximum gzip compression.
- Export behavior is deterministic for the same backup run content.

### UC-014: Chunk encryption at rest and key rotation

Happy path:
1. Operator starts NSS with chunk encryption enabled.
2. New chunk writes are persisted as encrypted envelopes containing key id + nonce + ciphertext.
3. Reads decrypt payloads using configured keyring and envelope key id.
4. Operator rotates active key id while retaining previous keys for decryption of older chunks.

Failure modes:
- Active key id missing from keyring fails startup/runtime initialization.
- Encrypted chunk references unknown key id and read is rejected.
- Legacy plaintext payload is rejected when plaintext compatibility is disabled.

Acceptance:
- New writes are encrypted at rest for object, snapshot, backup, and observability bucket data.
- Reads remain backward compatible for existing encrypted chunks after active key rotation.
- Legacy plaintext compatibility is explicit and configurable for migration windows.

### UC-013: Observability demo stack

Happy path:
1. Operator runs `docker compose up --build` from repository root.
2. Stack starts one master, three replicas (`slave-delivery`, `slave-backup`, `slave-volume`),
   Prometheus, Loki, Promtail, Grafana, and demo traffic generator.
3. Observability bootstrap creates dedicated buckets and credentials in Neemle Storage Service.
4. Prometheus scrapes node metrics and exports TSDB snapshots to a storage bucket.
5. Loki stores logs in storage bucket.
6. Grafana opens with preprovisioned data sources and dashboards showing live cluster data.

Failure modes:
- If observability bootstrap cannot authenticate or create buckets, dependent observability services do not start.
- If replica join token seeding fails, replicas do not join and distributed read demo remains unavailable.

Acceptance:
- Root compose topology includes one master and three replicas joined to the same cluster.
- Grafana has preprovisioned dashboards and data sources for Prometheus and Loki.
- Loki logs and Prometheus TSDB blocks use distinct Neemle Storage Service buckets.

## Documentation Consistency Rules

- `README.md` must match this document for project name and operational/testing flow.
- API/document titles must use "Neemle Storage Service" naming.
