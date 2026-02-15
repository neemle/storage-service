ALTER TABLE replica_runtime_config
    DROP CONSTRAINT IF EXISTS replica_runtime_config_sub_mode_check;

ALTER TABLE replica_runtime_config
    ADD CONSTRAINT replica_runtime_config_sub_mode_check
    CHECK (sub_mode IN ('delivery', 'backup', 'volume'));
