CREATE TABLE IF NOT EXISTS bucket_volume_bindings (
    bucket_id uuid NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
    node_id uuid NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (bucket_id, node_id)
);

CREATE INDEX IF NOT EXISTS idx_bucket_volume_bindings_bucket
    ON bucket_volume_bindings(bucket_id);

CREATE INDEX IF NOT EXISTS idx_bucket_volume_bindings_node
    ON bucket_volume_bindings(node_id);
