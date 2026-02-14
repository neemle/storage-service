ALTER TABLE buckets
ADD COLUMN IF NOT EXISTS is_worm boolean NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS bucket_snapshot_policies (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    bucket_id uuid NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
    trigger_kind text NOT NULL CHECK (
        trigger_kind IN ('hourly', 'daily', 'weekly', 'monthly', 'on_create_change')
    ),
    retention_count integer NOT NULL CHECK (retention_count > 0),
    enabled boolean NOT NULL DEFAULT true,
    last_snapshot_at timestamptz,
    created_by_user_id uuid REFERENCES users(id),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (bucket_id, trigger_kind)
);

CREATE INDEX IF NOT EXISTS idx_snapshot_policy_trigger_due
    ON bucket_snapshot_policies(enabled, trigger_kind, last_snapshot_at);

CREATE TABLE IF NOT EXISTS bucket_snapshots (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    bucket_id uuid NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
    trigger_kind text NOT NULL CHECK (
        trigger_kind IN (
            'hourly',
            'daily',
            'weekly',
            'monthly',
            'on_create_change',
            'on_demand',
            'backup_full',
            'backup_incremental',
            'backup_differential'
        )
    ),
    created_by_user_id uuid REFERENCES users(id),
    object_count bigint NOT NULL DEFAULT 0,
    total_size_bytes bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bucket_snapshots_bucket_created
    ON bucket_snapshots(bucket_id, created_at DESC);

CREATE TABLE IF NOT EXISTS bucket_snapshot_objects (
    snapshot_id uuid NOT NULL REFERENCES bucket_snapshots(id) ON DELETE CASCADE,
    object_key text NOT NULL,
    version_id text NOT NULL,
    manifest_id uuid NOT NULL REFERENCES manifests(id),
    size_bytes bigint NOT NULL,
    content_type text,
    metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    tags_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    object_created_at timestamptz NOT NULL,
    PRIMARY KEY (snapshot_id, object_key, version_id)
);

CREATE INDEX IF NOT EXISTS idx_snapshot_objects_snapshot
    ON bucket_snapshot_objects(snapshot_id);

CREATE TABLE IF NOT EXISTS bucket_change_events (
    bucket_id uuid PRIMARY KEY REFERENCES buckets(id) ON DELETE CASCADE,
    changed_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS backup_policies (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    name text NOT NULL,
    scope text NOT NULL CHECK (scope IN ('master', 'replica')),
    node_id uuid REFERENCES nodes(node_id) ON DELETE SET NULL,
    source_bucket_id uuid NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
    backup_bucket_id uuid NOT NULL REFERENCES buckets(id) ON DELETE RESTRICT,
    backup_type text NOT NULL CHECK (backup_type IN ('full', 'incremental', 'differential')),
    schedule_kind text NOT NULL CHECK (
        schedule_kind IN ('hourly', 'daily', 'weekly', 'monthly', 'on_demand')
    ),
    strategy text NOT NULL CHECK (strategy IN ('3-2-1', '3-2-1-1-0', '4-3-2')),
    retention_count integer NOT NULL CHECK (retention_count > 0),
    enabled boolean NOT NULL DEFAULT true,
    external_targets_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    last_run_at timestamptz,
    created_by_user_id uuid REFERENCES users(id),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_backup_policies_scope_node_enabled
    ON backup_policies(enabled, scope, node_id, schedule_kind, last_run_at);

CREATE TABLE IF NOT EXISTS backup_runs (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id uuid NOT NULL REFERENCES backup_policies(id) ON DELETE CASCADE,
    snapshot_id uuid REFERENCES bucket_snapshots(id) ON DELETE SET NULL,
    backup_type text NOT NULL CHECK (backup_type IN ('full', 'incremental', 'differential')),
    changed_since timestamptz,
    trigger_kind text NOT NULL,
    status text NOT NULL CHECK (status IN ('running', 'success', 'failed')),
    archive_format text NOT NULL CHECK (archive_format IN ('tar', 'tar.gz')),
    archive_object_key text,
    archive_size_bytes bigint,
    error_text text,
    started_at timestamptz NOT NULL,
    completed_at timestamptz
);

CREATE INDEX IF NOT EXISTS idx_backup_runs_policy_started
    ON backup_runs(policy_id, started_at DESC);

CREATE TABLE IF NOT EXISTS replica_runtime_config (
    node_id uuid PRIMARY KEY REFERENCES nodes(node_id) ON DELETE CASCADE,
    sub_mode text NOT NULL CHECK (sub_mode IN ('delivery', 'backup')),
    updated_by_user_id uuid REFERENCES users(id),
    updated_at timestamptz NOT NULL
);
