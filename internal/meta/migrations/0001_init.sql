CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    username text UNIQUE NOT NULL,
    display_name text,
    password_hash text NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS access_keys (
    access_key_id text PRIMARY KEY,
    user_id uuid REFERENCES users(id),
    label text NOT NULL,
    status text NOT NULL,
    secret_encrypted bytea NOT NULL,
    secret_kid text NOT NULL,
    created_at timestamptz NOT NULL,
    last_used_at timestamptz,
    deleted_at timestamptz
);

CREATE TABLE IF NOT EXISTS buckets (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    name text UNIQUE NOT NULL,
    owner_user_id uuid REFERENCES users(id),
    created_at timestamptz NOT NULL,
    versioning_status text NOT NULL,
    lifecycle_config_xml text,
    cors_config_xml text,
    website_config_xml text,
    notification_config_xml text
);

CREATE TABLE IF NOT EXISTS object_versions (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    bucket_id uuid REFERENCES buckets(id),
    object_key text NOT NULL,
    version_id text NOT NULL,
    is_delete_marker boolean NOT NULL DEFAULT false,
    size_bytes bigint NOT NULL DEFAULT 0,
    etag text,
    content_type text,
    metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    tags_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL,
    current boolean NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_object_versions_current
    ON object_versions(bucket_id, object_key, current);
CREATE INDEX IF NOT EXISTS idx_object_versions_created
    ON object_versions(bucket_id, object_key, created_at DESC);

CREATE TABLE IF NOT EXISTS multipart_uploads (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    bucket_id uuid REFERENCES buckets(id),
    object_key text NOT NULL,
    upload_id text UNIQUE NOT NULL,
    initiated_at timestamptz NOT NULL,
    status text NOT NULL
);

CREATE TABLE IF NOT EXISTS multipart_parts (
    upload_id text REFERENCES multipart_uploads(upload_id),
    part_number int NOT NULL,
    size_bytes bigint NOT NULL,
    etag text NOT NULL,
    manifest_id uuid NOT NULL,
    PRIMARY KEY (upload_id, part_number)
);

CREATE TABLE IF NOT EXISTS nodes (
    node_id uuid PRIMARY KEY,
    role text NOT NULL,
    address_internal text NOT NULL,
    status text NOT NULL,
    last_heartbeat_at timestamptz,
    capacity_bytes bigint,
    free_bytes bigint,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS join_tokens (
    token_id uuid PRIMARY KEY,
    token_hash text NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);

CREATE TABLE IF NOT EXISTS chunks (
    chunk_id uuid PRIMARY KEY,
    size_bytes int NOT NULL,
    checksum_algo text NOT NULL,
    checksum_value bytea NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS chunk_replicas (
    chunk_id uuid REFERENCES chunks(chunk_id),
    node_id uuid REFERENCES nodes(node_id),
    state text NOT NULL,
    stored_at timestamptz,
    PRIMARY KEY (chunk_id, node_id)
);

CREATE TABLE IF NOT EXISTS manifests (
    id uuid PRIMARY KEY,
    total_size_bytes bigint NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS manifest_chunks (
    manifest_id uuid REFERENCES manifests(id),
    chunk_index int NOT NULL,
    chunk_id uuid REFERENCES chunks(chunk_id),
    PRIMARY KEY (manifest_id, chunk_index)
);

CREATE TABLE IF NOT EXISTS object_version_manifests (
    object_version_id uuid REFERENCES object_versions(id),
    manifest_id uuid REFERENCES manifests(id),
    PRIMARY KEY (object_version_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id uuid PRIMARY KEY,
    ts timestamptz NOT NULL,
    actor_user_id uuid,
    actor_ip text,
    action text NOT NULL,
    target_type text,
    target_id text,
    outcome text NOT NULL,
    details_json jsonb NOT NULL DEFAULT '{}'::jsonb
);
