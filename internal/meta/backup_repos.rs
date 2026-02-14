use crate::meta::models::{
    BackupPolicy, BackupRun, Bucket, BucketSnapshot, BucketSnapshotObject, BucketSnapshotPolicy,
    Node, ReplicaRuntimeConfig,
};
use crate::meta::repos::Repo;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct BackupPolicyCreate {
    pub name: String,
    pub scope: String,
    pub node_id: Option<Uuid>,
    pub source_bucket_id: Uuid,
    pub backup_bucket_id: Uuid,
    pub backup_type: String,
    pub schedule_kind: String,
    pub strategy: String,
    pub retention_count: i32,
    pub enabled: bool,
    pub external_targets_json: Value,
    pub created_by_user_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct BackupPolicyPatch {
    pub name: Option<String>,
    pub backup_type: Option<String>,
    pub schedule_kind: Option<String>,
    pub strategy: Option<String>,
    pub retention_count: Option<i32>,
    pub enabled: Option<bool>,
    pub external_targets_json: Option<Value>,
    pub node_id: Option<Option<Uuid>>,
}

struct ResolvedBackupPolicyPatch<'a> {
    name: &'a str,
    node_id: Option<Uuid>,
    backup_type: &'a str,
    schedule_kind: &'a str,
    strategy: &'a str,
    retention_count: i32,
    enabled: bool,
    external_targets: &'a Value,
}

impl<'a> ResolvedBackupPolicyPatch<'a> {
    fn from(existing: &'a BackupPolicy, patch: &'a BackupPolicyPatch) -> Self {
        Self {
            name: patch.name.as_deref().unwrap_or(existing.name.as_str()),
            node_id: patch.node_id.unwrap_or(existing.node_id),
            backup_type: patch
                .backup_type
                .as_deref()
                .unwrap_or(existing.backup_type.as_str()),
            schedule_kind: patch
                .schedule_kind
                .as_deref()
                .unwrap_or(existing.schedule_kind.as_str()),
            strategy: patch
                .strategy
                .as_deref()
                .unwrap_or(existing.strategy.as_str()),
            retention_count: patch.retention_count.unwrap_or(existing.retention_count),
            enabled: patch.enabled.unwrap_or(existing.enabled),
            external_targets: patch
                .external_targets_json
                .as_ref()
                .unwrap_or(&existing.external_targets_json),
        }
    }
}

fn insert_backup_policy_sql() -> &'static str {
    concat!(
        "INSERT INTO backup_policies ",
        "(name, scope, node_id, source_bucket_id, backup_bucket_id, backup_type, schedule_kind, ",
        "strategy, retention_count, enabled, external_targets_json, ",
        "created_by_user_id, created_at, updated_at) ",
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *"
    )
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SnapshotSourceRow {
    object_key: String,
    version_id: String,
    manifest_id: Uuid,
    size_bytes: i64,
    content_type: Option<String>,
    metadata_json: Value,
    tags_json: Value,
    object_created_at: DateTime<Utc>,
}

impl Repo {
    pub async fn get_node(&self, node_id: Uuid) -> Result<Option<Node>, sqlx::Error> {
        sqlx::query_as::<_, Node>("SELECT * FROM nodes WHERE node_id=$1")
            .bind(node_id)
            .fetch_optional(self.pool())
            .await
    }

    pub async fn get_bucket_by_id(&self, bucket_id: Uuid) -> Result<Option<Bucket>, sqlx::Error> {
        sqlx::query_as::<_, Bucket>("SELECT * FROM buckets WHERE id=$1")
            .bind(bucket_id)
            .fetch_optional(self.pool())
            .await
    }

    pub async fn list_all_buckets(&self) -> Result<Vec<Bucket>, sqlx::Error> {
        sqlx::query_as::<_, Bucket>("SELECT * FROM buckets ORDER BY created_at DESC")
            .fetch_all(self.pool())
            .await
    }

    pub async fn update_bucket_worm(
        &self,
        bucket_id: Uuid,
        is_worm: bool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE buckets SET is_worm=$1 WHERE id=$2")
            .bind(is_worm)
            .bind(bucket_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    pub async fn upsert_snapshot_policy(
        &self,
        bucket_id: Uuid,
        trigger_kind: &str,
        retention_count: i32,
        enabled: bool,
        created_by_user_id: Option<Uuid>,
    ) -> Result<BucketSnapshotPolicy, sqlx::Error> {
        let now = Utc::now();
        sqlx::query_as::<_, BucketSnapshotPolicy>(
            concat!(
                "INSERT INTO bucket_snapshot_policies ",
                "(bucket_id, trigger_kind, retention_count, enabled, created_by_user_id, created_at, updated_at) ",
                "VALUES ($1,$2,$3,$4,$5,$6,$7) ",
                "ON CONFLICT (bucket_id, trigger_kind) DO UPDATE SET ",
                "retention_count=EXCLUDED.retention_count, enabled=EXCLUDED.enabled, updated_at=EXCLUDED.updated_at ",
                "RETURNING *"
            ),
        )
        .bind(bucket_id)
        .bind(trigger_kind)
        .bind(retention_count)
        .bind(enabled)
        .bind(created_by_user_id)
        .bind(now)
        .bind(now)
        .fetch_one(self.pool())
        .await
    }

    pub async fn list_snapshot_policies(&self) -> Result<Vec<BucketSnapshotPolicy>, sqlx::Error> {
        sqlx::query_as::<_, BucketSnapshotPolicy>(
            "SELECT * FROM bucket_snapshot_policies ORDER BY created_at DESC",
        )
        .fetch_all(self.pool())
        .await
    }

    pub async fn list_enabled_snapshot_policies(
        &self,
    ) -> Result<Vec<BucketSnapshotPolicy>, sqlx::Error> {
        sqlx::query_as::<_, BucketSnapshotPolicy>(
            "SELECT * FROM bucket_snapshot_policies WHERE enabled=true ORDER BY created_at ASC",
        )
        .fetch_all(self.pool())
        .await
    }

    pub async fn touch_snapshot_policy_run(
        &self,
        policy_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE bucket_snapshot_policies SET last_snapshot_at=$1, updated_at=$2 WHERE id=$3",
        )
        .bind(at)
        .bind(at)
        .bind(policy_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn mark_bucket_changed(&self, bucket_id: Uuid) -> Result<(), sqlx::Error> {
        let now = Utc::now();
        sqlx::query(concat!(
            "INSERT INTO bucket_change_events (bucket_id, changed_at) VALUES ($1,$2) ",
            "ON CONFLICT (bucket_id) DO UPDATE SET changed_at=EXCLUDED.changed_at",
        ))
        .bind(bucket_id)
        .bind(now)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn bucket_changed_after(
        &self,
        bucket_id: Uuid,
        after: Option<DateTime<Utc>>,
    ) -> Result<bool, sqlx::Error> {
        let changed = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
            "SELECT changed_at FROM bucket_change_events WHERE bucket_id=$1",
        )
        .bind(bucket_id)
        .fetch_optional(self.pool())
        .await?
        .flatten();
        let Some(changed_at) = changed else {
            return Ok(false);
        };
        Ok(after.is_none_or(|ts| changed_at > ts))
    }

    pub async fn clear_bucket_changed(&self, bucket_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM bucket_change_events WHERE bucket_id=$1")
            .bind(bucket_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    pub async fn create_bucket_snapshot(
        &self,
        bucket_id: Uuid,
        trigger_kind: &str,
        created_by_user_id: Option<Uuid>,
    ) -> Result<BucketSnapshot, sqlx::Error> {
        let mut tx = self.pool().begin().await?;
        let mut snapshot = self
            .insert_bucket_snapshot_row(&mut tx, bucket_id, trigger_kind, created_by_user_id)
            .await?;
        let rows = self.load_snapshot_source_rows(&mut tx, bucket_id).await?;
        snapshot.object_count = rows.len() as i64;
        snapshot.total_size_bytes = rows.iter().map(|row| row.size_bytes).sum::<i64>();
        self.insert_snapshot_objects(&mut tx, snapshot.id, &rows)
            .await?;
        self.update_snapshot_totals(&mut tx, snapshot.id, &rows)
            .await?;
        tx.commit().await?;
        Ok(snapshot)
    }

    async fn insert_bucket_snapshot_row(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        bucket_id: Uuid,
        trigger_kind: &str,
        created_by_user_id: Option<Uuid>,
    ) -> Result<BucketSnapshot, sqlx::Error> {
        sqlx::query_as::<_, BucketSnapshot>(
            concat!(
                "INSERT INTO bucket_snapshots (bucket_id, trigger_kind, created_by_user_id, created_at) ",
                "VALUES ($1,$2,$3,$4) RETURNING *",
            ),
        )
        .bind(bucket_id)
        .bind(trigger_kind)
        .bind(created_by_user_id)
        .bind(Utc::now())
        .fetch_one(&mut **tx)
        .await
    }

    async fn load_snapshot_source_rows(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        bucket_id: Uuid,
    ) -> Result<Vec<SnapshotSourceRow>, sqlx::Error> {
        sqlx::query_as::<_, SnapshotSourceRow>(
            concat!(
                "SELECT ov.object_key, ov.version_id, ovm.manifest_id, ov.size_bytes, ov.content_type, ",
                "ov.metadata_json, ov.tags_json, ov.created_at AS object_created_at ",
                "FROM object_versions ov ",
                "JOIN object_version_manifests ovm ON ovm.object_version_id=ov.id ",
                "WHERE ov.bucket_id=$1 AND ov.current=true AND ov.is_delete_marker=false ",
                "ORDER BY ov.object_key ASC",
            ),
        )
        .bind(bucket_id)
        .fetch_all(&mut **tx)
        .await
    }

    async fn insert_snapshot_objects(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        snapshot_id: Uuid,
        rows: &[SnapshotSourceRow],
    ) -> Result<(), sqlx::Error> {
        for row in rows {
            sqlx::query(concat!(
                "INSERT INTO bucket_snapshot_objects ",
                "(snapshot_id, object_key, version_id, manifest_id, size_bytes, content_type, ",
                "metadata_json, tags_json, object_created_at) ",
                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            ))
            .bind(snapshot_id)
            .bind(&row.object_key)
            .bind(&row.version_id)
            .bind(row.manifest_id)
            .bind(row.size_bytes)
            .bind(&row.content_type)
            .bind(&row.metadata_json)
            .bind(&row.tags_json)
            .bind(row.object_created_at)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    async fn update_snapshot_totals(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        snapshot_id: Uuid,
        rows: &[SnapshotSourceRow],
    ) -> Result<(), sqlx::Error> {
        let object_count = rows.len() as i64;
        let total_size_bytes = rows.iter().map(|row| row.size_bytes).sum::<i64>();
        sqlx::query("UPDATE bucket_snapshots SET object_count=$1, total_size_bytes=$2 WHERE id=$3")
            .bind(object_count)
            .bind(total_size_bytes)
            .bind(snapshot_id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    pub async fn list_bucket_snapshots(
        &self,
        bucket_id: Uuid,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<BucketSnapshot>, sqlx::Error> {
        sqlx::query_as::<_, BucketSnapshot>(concat!(
            "SELECT * FROM bucket_snapshots WHERE bucket_id=$1 ",
            "ORDER BY created_at DESC, id DESC OFFSET $2 LIMIT $3",
        ))
        .bind(bucket_id)
        .bind(offset)
        .bind(limit)
        .fetch_all(self.pool())
        .await
    }

    pub async fn get_bucket_snapshot(
        &self,
        snapshot_id: Uuid,
    ) -> Result<Option<BucketSnapshot>, sqlx::Error> {
        sqlx::query_as::<_, BucketSnapshot>("SELECT * FROM bucket_snapshots WHERE id=$1")
            .bind(snapshot_id)
            .fetch_optional(self.pool())
            .await
    }

    pub async fn list_snapshot_objects(
        &self,
        snapshot_id: Uuid,
    ) -> Result<Vec<BucketSnapshotObject>, sqlx::Error> {
        sqlx::query_as::<_, BucketSnapshotObject>(concat!(
            "SELECT * FROM bucket_snapshot_objects WHERE snapshot_id=$1 ",
            "ORDER BY object_key ASC, version_id DESC",
        ))
        .bind(snapshot_id)
        .fetch_all(self.pool())
        .await
    }

    pub async fn create_bucket_from_snapshot(
        &self,
        snapshot_id: Uuid,
        target_bucket_name: &str,
        owner_user_id: Uuid,
    ) -> Result<Bucket, sqlx::Error> {
        let mut tx = self.pool().begin().await?;
        let bucket = self
            .insert_restored_bucket(&mut tx, target_bucket_name, owner_user_id)
            .await?;
        let objects = self
            .load_snapshot_objects_for_restore(&mut tx, snapshot_id)
            .await?;
        self.restore_snapshot_objects(&mut tx, bucket.id, &objects)
            .await?;
        tx.commit().await?;
        Ok(bucket)
    }

    async fn insert_restored_bucket(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        target_bucket_name: &str,
        owner_user_id: Uuid,
    ) -> Result<Bucket, sqlx::Error> {
        sqlx::query_as::<_, Bucket>(
            concat!(
                "INSERT INTO buckets (name, owner_user_id, created_at, versioning_status, public_read, is_worm) ",
                "VALUES ($1,$2,$3,'off',false,false) RETURNING *",
            ),
        )
        .bind(target_bucket_name)
        .bind(owner_user_id)
        .bind(Utc::now())
        .fetch_one(&mut **tx)
        .await
    }

    async fn load_snapshot_objects_for_restore(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        snapshot_id: Uuid,
    ) -> Result<Vec<BucketSnapshotObject>, sqlx::Error> {
        sqlx::query_as::<_, BucketSnapshotObject>(
            "SELECT * FROM bucket_snapshot_objects WHERE snapshot_id=$1 ORDER BY object_key ASC",
        )
        .bind(snapshot_id)
        .fetch_all(&mut **tx)
        .await
    }

    async fn restore_snapshot_objects(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        bucket_id: Uuid,
        objects: &[BucketSnapshotObject],
    ) -> Result<(), sqlx::Error> {
        for object in objects {
            let object_version_id = self.insert_restored_version(tx, bucket_id, object).await?;
            self.link_restored_manifest(tx, object_version_id, object.manifest_id)
                .await?;
        }
        Ok(())
    }

    async fn insert_restored_version(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        bucket_id: Uuid,
        object: &BucketSnapshotObject,
    ) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar::<_, Uuid>(
            concat!(
                "INSERT INTO object_versions (bucket_id, object_key, version_id, is_delete_marker, size_bytes, ",
                "etag, content_type, metadata_json, tags_json, created_at, current) ",
                "VALUES ($1,$2,$3,false,$4,NULL,$5,$6,$7,$8,true) RETURNING id",
            ),
        )
        .bind(bucket_id)
        .bind(&object.object_key)
        .bind(&object.version_id)
        .bind(object.size_bytes)
        .bind(&object.content_type)
        .bind(&object.metadata_json)
        .bind(&object.tags_json)
        .bind(Utc::now())
        .fetch_one(&mut **tx)
        .await
    }

    async fn link_restored_manifest(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        object_version_id: Uuid,
        manifest_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO object_version_manifests (object_version_id, manifest_id) VALUES ($1,$2)",
        )
        .bind(object_version_id)
        .bind(manifest_id)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    pub async fn prune_bucket_snapshots(
        &self,
        bucket_id: Uuid,
        keep: i32,
    ) -> Result<u64, sqlx::Error> {
        if keep < 1 {
            return Ok(0);
        }
        let result = sqlx::query(
            concat!(
                "DELETE FROM bucket_snapshots s ",
                "WHERE s.bucket_id=$1 AND s.id IN (",
                "    SELECT old.id FROM (",
                "        SELECT id FROM bucket_snapshots WHERE bucket_id=$1 ",
                "        ORDER BY created_at DESC, id DESC OFFSET $2",
                "    ) AS old ",
                "    WHERE old.id NOT IN (SELECT snapshot_id FROM backup_runs WHERE snapshot_id IS NOT NULL)",
                ")",
            ),
        )
        .bind(bucket_id)
        .bind(keep as i64)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn create_backup_policy(
        &self,
        input: &BackupPolicyCreate,
    ) -> Result<BackupPolicy, sqlx::Error> {
        let now = Utc::now();
        sqlx::query_as::<_, BackupPolicy>(insert_backup_policy_sql())
            .bind(&input.name)
            .bind(&input.scope)
            .bind(input.node_id)
            .bind(input.source_bucket_id)
            .bind(input.backup_bucket_id)
            .bind(&input.backup_type)
            .bind(&input.schedule_kind)
            .bind(&input.strategy)
            .bind(input.retention_count)
            .bind(input.enabled)
            .bind(&input.external_targets_json)
            .bind(input.created_by_user_id)
            .bind(now)
            .bind(now)
            .fetch_one(self.pool())
            .await
    }

    pub async fn update_backup_policy(
        &self,
        policy_id: Uuid,
        patch: &BackupPolicyPatch,
    ) -> Result<Option<BackupPolicy>, sqlx::Error> {
        let Some(existing) = self.get_backup_policy(policy_id).await? else {
            return Ok(None);
        };
        let resolved = ResolvedBackupPolicyPatch::from(&existing, patch);
        let updated = self.update_backup_policy_row(policy_id, &resolved).await?;
        Ok(Some(updated))
    }

    async fn update_backup_policy_row(
        &self,
        policy_id: Uuid,
        patch: &ResolvedBackupPolicyPatch<'_>,
    ) -> Result<BackupPolicy, sqlx::Error> {
        sqlx::query_as::<_, BackupPolicy>(
            concat!(
                "UPDATE backup_policies SET name=$1, node_id=$2, backup_type=$3, schedule_kind=$4, strategy=$5, ",
                "retention_count=$6, enabled=$7, external_targets_json=$8, updated_at=$9 WHERE id=$10 RETURNING *",
            ),
        )
        .bind(patch.name)
        .bind(patch.node_id)
        .bind(patch.backup_type)
        .bind(patch.schedule_kind)
        .bind(patch.strategy)
        .bind(patch.retention_count)
        .bind(patch.enabled)
        .bind(patch.external_targets)
        .bind(Utc::now())
        .bind(policy_id)
        .fetch_one(self.pool())
        .await
    }

    pub async fn list_backup_policies(&self) -> Result<Vec<BackupPolicy>, sqlx::Error> {
        sqlx::query_as::<_, BackupPolicy>("SELECT * FROM backup_policies ORDER BY created_at DESC")
            .fetch_all(self.pool())
            .await
    }

    pub async fn list_enabled_backup_policies(&self) -> Result<Vec<BackupPolicy>, sqlx::Error> {
        sqlx::query_as::<_, BackupPolicy>(
            "SELECT * FROM backup_policies WHERE enabled=true ORDER BY created_at ASC",
        )
        .fetch_all(self.pool())
        .await
    }

    pub async fn get_backup_policy(
        &self,
        policy_id: Uuid,
    ) -> Result<Option<BackupPolicy>, sqlx::Error> {
        sqlx::query_as::<_, BackupPolicy>("SELECT * FROM backup_policies WHERE id=$1")
            .bind(policy_id)
            .fetch_optional(self.pool())
            .await
    }

    pub async fn touch_backup_policy_run(
        &self,
        policy_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE backup_policies SET last_run_at=$1, updated_at=$2 WHERE id=$3")
            .bind(at)
            .bind(at)
            .bind(policy_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    pub async fn create_backup_run(
        &self,
        policy_id: Uuid,
        snapshot_id: Option<Uuid>,
        backup_type: &str,
        changed_since: Option<DateTime<Utc>>,
        trigger_kind: &str,
        archive_format: &str,
    ) -> Result<BackupRun, sqlx::Error> {
        sqlx::query_as::<_, BackupRun>(
            concat!(
                "INSERT INTO backup_runs (policy_id, snapshot_id, backup_type, changed_since, trigger_kind, ",
                "status, archive_format, started_at) VALUES ($1,$2,$3,$4,$5,'running',$6,$7) RETURNING *",
            ),
        )
        .bind(policy_id)
        .bind(snapshot_id)
        .bind(backup_type)
        .bind(changed_since)
        .bind(trigger_kind)
        .bind(archive_format)
        .bind(Utc::now())
        .fetch_one(self.pool())
        .await
    }

    pub async fn complete_backup_run_success(
        &self,
        run_id: Uuid,
        archive_object_key: &str,
        archive_size_bytes: i64,
    ) -> Result<(), sqlx::Error> {
        let now = Utc::now();
        sqlx::query(concat!(
            "UPDATE backup_runs SET status='success', archive_object_key=$1, ",
            "archive_size_bytes=$2, completed_at=$3 ",
            "WHERE id=$4",
        ))
        .bind(archive_object_key)
        .bind(archive_size_bytes)
        .bind(now)
        .bind(run_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn complete_backup_run_failure(
        &self,
        run_id: Uuid,
        error_text: &str,
    ) -> Result<(), sqlx::Error> {
        let now = Utc::now();
        sqlx::query(
            "UPDATE backup_runs SET status='failed', error_text=$1, completed_at=$2 WHERE id=$3",
        )
        .bind(error_text)
        .bind(now)
        .bind(run_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn get_backup_run(&self, run_id: Uuid) -> Result<Option<BackupRun>, sqlx::Error> {
        sqlx::query_as::<_, BackupRun>("SELECT * FROM backup_runs WHERE id=$1")
            .bind(run_id)
            .fetch_optional(self.pool())
            .await
    }

    pub async fn list_backup_runs(
        &self,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<BackupRun>, sqlx::Error> {
        sqlx::query_as::<_, BackupRun>(
            "SELECT * FROM backup_runs ORDER BY started_at DESC, id DESC OFFSET $1 LIMIT $2",
        )
        .bind(offset)
        .bind(limit)
        .fetch_all(self.pool())
        .await
    }

    pub async fn list_backup_runs_for_policy(
        &self,
        policy_id: Uuid,
    ) -> Result<Vec<BackupRun>, sqlx::Error> {
        sqlx::query_as::<_, BackupRun>(
            "SELECT * FROM backup_runs WHERE policy_id=$1 ORDER BY started_at DESC, id DESC",
        )
        .bind(policy_id)
        .fetch_all(self.pool())
        .await
    }

    pub async fn delete_backup_run(&self, run_id: Uuid) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM backup_runs WHERE id=$1")
            .bind(run_id)
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected())
    }

    pub async fn set_replica_runtime_mode(
        &self,
        node_id: Uuid,
        sub_mode: &str,
        updated_by_user_id: Option<Uuid>,
    ) -> Result<ReplicaRuntimeConfig, sqlx::Error> {
        let now = Utc::now();
        sqlx::query_as::<_, ReplicaRuntimeConfig>(
            concat!(
                "INSERT INTO replica_runtime_config (node_id, sub_mode, updated_by_user_id, updated_at) ",
                "VALUES ($1,$2,$3,$4) ",
                "ON CONFLICT (node_id) DO UPDATE SET sub_mode=EXCLUDED.sub_mode, ",
                "updated_by_user_id=EXCLUDED.updated_by_user_id, updated_at=EXCLUDED.updated_at ",
                "RETURNING *",
            ),
        )
        .bind(node_id)
        .bind(sub_mode)
        .bind(updated_by_user_id)
        .bind(now)
        .fetch_one(self.pool())
        .await
    }

    pub async fn get_replica_runtime_mode(
        &self,
        node_id: Uuid,
    ) -> Result<Option<ReplicaRuntimeConfig>, sqlx::Error> {
        sqlx::query_as::<_, ReplicaRuntimeConfig>(
            "SELECT * FROM replica_runtime_config WHERE node_id=$1",
        )
        .bind(node_id)
        .fetch_optional(self.pool())
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{BackupPolicyCreate, BackupPolicyPatch, Repo};
    use crate::test_support::{self, FailTriggerGuard, TableRenameGuard};
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;

    async fn setup_repo() -> Repo {
        let pool = test_support::setup_pool().await;
        test_support::reset_db(&pool).await;
        Repo::new(pool)
    }

    async fn seed_bucket(repo: &Repo, name: &str) -> crate::meta::models::Bucket {
        let user = repo
            .create_user(&format!("user-{name}"), Some("User"), "hash", "active")
            .await
            .expect("user");
        repo.create_bucket(name, user.id).await.expect("bucket")
    }

    async fn seed_object(repo: &Repo, bucket: &crate::meta::models::Bucket, key: &str) {
        let chunk_id = Uuid::new_v4();
        repo.insert_chunk_metadata(chunk_id, 4, "crc32c", &[1, 2, 3, 4])
            .await
            .expect("chunk");
        repo.finalize_object_version(
            bucket.id,
            key,
            &Uuid::new_v4().to_string(),
            4,
            "etag",
            Some("text/plain"),
            &json!({ "meta": "value" }),
            &json!({}),
            &[chunk_id],
            false,
        )
        .await
        .expect("version");
    }

    #[tokio::test]
    async fn snapshot_and_restore_paths_work() {
        let repo = setup_repo().await;
        let bucket = seed_bucket(&repo, "source").await;
        seed_object(&repo, &bucket, "a.txt").await;

        let policy = repo
            .upsert_snapshot_policy(bucket.id, "daily", 3, true, None)
            .await
            .expect("policy");
        assert_eq!(policy.trigger_kind, "daily");

        let snapshot = repo
            .create_bucket_snapshot(bucket.id, "on_demand", None)
            .await
            .expect("snapshot");
        assert_eq!(snapshot.object_count, 1);

        let objects = repo
            .list_snapshot_objects(snapshot.id)
            .await
            .expect("objects");
        assert_eq!(objects.len(), 1);

        let restored = repo
            .create_bucket_from_snapshot(snapshot.id, "restored", bucket.owner_user_id)
            .await
            .expect("restore");
        let current = repo
            .list_objects_current(restored.id, None, None, 10)
            .await
            .expect("list");
        assert_eq!(current.len(), 1);
    }

    #[tokio::test]
    async fn backup_policy_and_runtime_config_paths_work() {
        let repo = setup_repo().await;
        let source = seed_bucket(&repo, "source-backup").await;
        seed_object(&repo, &source, "file.txt").await;
        let backup_bucket = seed_bucket(&repo, "backup-target").await;
        repo.update_bucket_worm(backup_bucket.id, true)
            .await
            .expect("worm");

        let policy = repo
            .create_backup_policy(&BackupPolicyCreate {
                name: "daily".to_string(),
                scope: "master".to_string(),
                node_id: None,
                source_bucket_id: source.id,
                backup_bucket_id: backup_bucket.id,
                backup_type: "full".to_string(),
                schedule_kind: "daily".to_string(),
                strategy: "3-2-1".to_string(),
                retention_count: 2,
                enabled: true,
                external_targets_json: json!([]),
                created_by_user_id: None,
            })
            .await
            .expect("policy");
        assert_eq!(policy.backup_type, "full");

        let snapshot = repo
            .create_bucket_snapshot(source.id, "backup_full", None)
            .await
            .expect("snapshot");
        let run = repo
            .create_backup_run(
                policy.id,
                Some(snapshot.id),
                "full",
                None,
                "on_demand",
                "tar.gz",
            )
            .await
            .expect("run");
        repo.complete_backup_run_success(run.id, "nss-backups/p.tar.gz", 100)
            .await
            .expect("success");
        let run = repo
            .get_backup_run(run.id)
            .await
            .expect("lookup")
            .expect("exists");
        assert_eq!(run.status, "success");

        let node_id = Uuid::new_v4();
        repo.upsert_node(
            node_id,
            "replica",
            "http://replica:9010",
            "online",
            None,
            None,
            Some(Utc::now()),
        )
        .await
        .expect("node");
        let runtime = repo
            .set_replica_runtime_mode(node_id, "backup", None)
            .await
            .expect("runtime");
        assert_eq!(runtime.sub_mode, "backup");
        let loaded = repo
            .get_replica_runtime_mode(runtime.node_id)
            .await
            .expect("lookup")
            .expect("exists");
        assert_eq!(loaded.sub_mode, "backup");
    }

    #[tokio::test]
    async fn bucket_change_and_snapshot_policy_paths_work() {
        let repo = setup_repo().await;
        let bucket = seed_bucket(&repo, "changes").await;
        repo.mark_bucket_changed(bucket.id).await.expect("mark");
        assert!(repo
            .bucket_changed_after(bucket.id, None)
            .await
            .expect("changed"));
        repo.clear_bucket_changed(bucket.id).await.expect("clear");
        assert!(!repo
            .bucket_changed_after(bucket.id, None)
            .await
            .expect("changed"));

        let policy = repo
            .upsert_snapshot_policy(bucket.id, "hourly", 2, true, Some(bucket.owner_user_id))
            .await
            .expect("policy");
        repo.touch_snapshot_policy_run(policy.id, Utc::now())
            .await
            .expect("touch");
        let enabled = repo
            .list_enabled_snapshot_policies()
            .await
            .expect("enabled");
        assert_eq!(enabled.len(), 1);
        let pruned = repo
            .prune_bucket_snapshots(bucket.id, 0)
            .await
            .expect("prune");
        assert_eq!(pruned, 0);
    }

    #[tokio::test]
    async fn bucket_changed_after_honors_cutoff_timestamp() {
        let repo = setup_repo().await;
        let bucket = seed_bucket(&repo, "changes-after").await;
        repo.mark_bucket_changed(bucket.id).await.expect("mark");
        let future = Utc::now() + chrono::Duration::seconds(60);
        let changed = repo
            .bucket_changed_after(bucket.id, Some(future))
            .await
            .expect("changed");
        assert!(!changed);
    }

    #[tokio::test]
    async fn backup_policy_update_and_failure_paths_work() {
        let repo = setup_repo().await;
        let source = seed_bucket(&repo, "source-update").await;
        let backup = seed_bucket(&repo, "backup-update").await;
        let created = repo
            .create_backup_policy(&BackupPolicyCreate {
                name: "nightly".to_string(),
                scope: "master".to_string(),
                node_id: None,
                source_bucket_id: source.id,
                backup_bucket_id: backup.id,
                backup_type: "full".to_string(),
                schedule_kind: "daily".to_string(),
                strategy: "3-2-1".to_string(),
                retention_count: 2,
                enabled: true,
                external_targets_json: json!([]),
                created_by_user_id: None,
            })
            .await
            .expect("policy");
        let patch = BackupPolicyPatch {
            name: Some("nightly-2".to_string()),
            backup_type: Some("incremental".to_string()),
            schedule_kind: None,
            strategy: None,
            retention_count: Some(3),
            enabled: Some(false),
            external_targets_json: Some(
                json!([{ "name": "t", "kind": "other", "endpoint": "https://x" }]),
            ),
            node_id: Some(None),
        };
        let updated = repo
            .update_backup_policy(created.id, &patch)
            .await
            .expect("update")
            .expect("updated");
        assert_eq!(updated.name, "nightly-2");
        assert!(repo
            .list_enabled_backup_policies()
            .await
            .expect("enabled")
            .is_empty());
        assert!(repo
            .get_backup_policy(Uuid::new_v4())
            .await
            .expect("missing")
            .is_none());

        let run = repo
            .create_backup_run(updated.id, None, "incremental", None, "on_demand", "tar.gz")
            .await
            .expect("run");
        repo.complete_backup_run_failure(run.id, "failed")
            .await
            .expect("failure");
        let loaded = repo
            .get_backup_run(run.id)
            .await
            .expect("run")
            .expect("run");
        assert_eq!(loaded.status, "failed");
        assert_eq!(repo.list_backup_runs(0, 10).await.expect("runs").len(), 1);
        assert_eq!(repo.delete_backup_run(run.id).await.expect("delete"), 1);
    }

    #[tokio::test]
    async fn lookup_paths_cover_nodes_and_buckets() {
        let repo = setup_repo().await;
        let bucket = seed_bucket(&repo, "lookup").await;
        assert!(repo.get_node(Uuid::new_v4()).await.expect("node").is_none());
        let all = repo.list_all_buckets().await.expect("buckets");
        assert_eq!(all.len(), 1);
        let found = repo
            .get_bucket_by_id(bucket.id)
            .await
            .expect("bucket")
            .expect("bucket");
        assert_eq!(found.name, "lookup");
    }

    fn base_policy_create(
        source_bucket_id: Uuid,
        backup_bucket_id: Uuid,
        name: &str,
    ) -> BackupPolicyCreate {
        BackupPolicyCreate {
            name: name.to_string(),
            scope: "master".to_string(),
            node_id: None,
            source_bucket_id,
            backup_bucket_id,
            backup_type: "full".to_string(),
            schedule_kind: "daily".to_string(),
            strategy: "3-2-1".to_string(),
            retention_count: 2,
            enabled: true,
            external_targets_json: json!([]),
            created_by_user_id: None,
        }
    }

    fn name_patch(value: &str) -> BackupPolicyPatch {
        BackupPolicyPatch {
            name: Some(value.to_string()),
            backup_type: None,
            schedule_kind: None,
            strategy: None,
            retention_count: None,
            enabled: None,
            external_targets_json: None,
            node_id: Some(None),
        }
    }

    async fn seed_snapshot(repo: &Repo, bucket_name: &str, object_key: &str) -> (Uuid, Uuid) {
        let bucket = seed_bucket(repo, bucket_name).await;
        seed_object(repo, &bucket, object_key).await;
        let snapshot = repo
            .create_bucket_snapshot(bucket.id, "on_demand", None)
            .await
            .expect("snapshot");
        (bucket.owner_user_id, snapshot.id)
    }

    #[tokio::test]
    async fn repo_methods_map_errors_with_unreachable_pool() {
        let repo = test_support::broken_repo();
        assert!(repo
            .touch_snapshot_policy_run(Uuid::new_v4(), Utc::now())
            .await
            .is_err());
        assert!(repo.mark_bucket_changed(Uuid::new_v4()).await.is_err());
        assert!(repo.clear_bucket_changed(Uuid::new_v4()).await.is_err());
        assert!(repo
            .create_bucket_from_snapshot(Uuid::new_v4(), "restore-x", Uuid::new_v4())
            .await
            .is_err());
        assert!(repo
            .prune_bucket_snapshots(Uuid::new_v4(), 1)
            .await
            .is_err());
        assert!(repo
            .complete_backup_run_failure(Uuid::new_v4(), "failed")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn backup_policy_update_maps_update_error() {
        let repo = setup_repo().await;
        let source = seed_bucket(&repo, "policy-update-source").await;
        let backup = seed_bucket(&repo, "policy-update-backup").await;
        let policy = repo
            .create_backup_policy(&base_policy_create(source.id, backup.id, "policy-update"))
            .await
            .expect("policy");
        let fail = FailTriggerGuard::create(repo.pool(), "backup_policies", "BEFORE", "UPDATE")
            .await
            .expect("failpoint");
        let err = repo
            .update_backup_policy(policy.id, &name_patch("policy-updated"))
            .await
            .unwrap_err();
        assert!(err.as_database_error().is_some());
        fail.remove().await.expect("remove failpoint");
    }

    #[tokio::test]
    async fn create_bucket_snapshot_maps_source_lookup_error() {
        let repo = setup_repo().await;
        let bucket = seed_bucket(&repo, "snapshot-source-lookup").await;
        let renamed = TableRenameGuard::rename(repo.pool(), "object_versions")
            .await
            .expect("rename object_versions");
        let err = repo
            .create_bucket_snapshot(bucket.id, "on_demand", None)
            .await
            .unwrap_err();
        assert!(err.as_database_error().is_some());
        renamed.restore().await.expect("restore object_versions");
    }

    #[tokio::test]
    async fn create_bucket_snapshot_maps_object_insert_error() {
        let repo = setup_repo().await;
        let bucket = seed_bucket(&repo, "snapshot-object-insert").await;
        seed_object(&repo, &bucket, "a.txt").await;
        let fail =
            FailTriggerGuard::create(repo.pool(), "bucket_snapshot_objects", "BEFORE", "INSERT")
                .await
                .expect("failpoint");
        let err = repo
            .create_bucket_snapshot(bucket.id, "on_demand", None)
            .await
            .unwrap_err();
        assert!(err.as_database_error().is_some());
        fail.remove().await.expect("remove failpoint");
    }

    #[tokio::test]
    async fn create_bucket_snapshot_maps_totals_update_error() {
        let repo = setup_repo().await;
        let bucket = seed_bucket(&repo, "snapshot-totals-update").await;
        seed_object(&repo, &bucket, "a.txt").await;
        let fail = FailTriggerGuard::create(repo.pool(), "bucket_snapshots", "BEFORE", "UPDATE")
            .await
            .expect("failpoint");
        let err = repo
            .create_bucket_snapshot(bucket.id, "on_demand", None)
            .await
            .unwrap_err();
        assert!(err.as_database_error().is_some());
        fail.remove().await.expect("remove failpoint");
    }

    #[tokio::test]
    async fn create_bucket_snapshot_maps_commit_error() {
        let repo = setup_repo().await;
        let bucket = seed_bucket(&repo, "snapshot-commit").await;
        seed_object(&repo, &bucket, "a.txt").await;
        let fail = FailTriggerGuard::create_deferred(
            repo.pool(),
            "bucket_snapshot_objects",
            "AFTER",
            "INSERT",
        )
        .await
        .expect("deferred failpoint");
        let err = repo
            .create_bucket_snapshot(bucket.id, "on_demand", None)
            .await
            .unwrap_err();
        assert!(err.as_database_error().is_some());
        fail.remove().await.expect("remove failpoint");
    }

    #[tokio::test]
    async fn create_bucket_from_snapshot_maps_bucket_insert_error() {
        let repo = setup_repo().await;
        let (owner_user_id, snapshot_id) = seed_snapshot(&repo, "restore-insert", "one.txt").await;
        let renamed = TableRenameGuard::rename(repo.pool(), "buckets")
            .await
            .expect("rename buckets");
        let err = repo
            .create_bucket_from_snapshot(snapshot_id, "restore-bucket-insert", owner_user_id)
            .await
            .unwrap_err();
        assert!(err.as_database_error().is_some());
        renamed.restore().await.expect("restore buckets");
    }

    #[tokio::test]
    async fn create_bucket_from_snapshot_maps_snapshot_object_lookup_error() {
        let repo = setup_repo().await;
        let (owner_user_id, snapshot_id) = seed_snapshot(&repo, "restore-lookup", "one.txt").await;
        let renamed = TableRenameGuard::rename(repo.pool(), "bucket_snapshot_objects")
            .await
            .expect("rename snapshot objects");
        let err = repo
            .create_bucket_from_snapshot(snapshot_id, "restore-bucket-lookup", owner_user_id)
            .await
            .unwrap_err();
        assert!(err.as_database_error().is_some());
        renamed.restore().await.expect("restore snapshot objects");
    }

    #[tokio::test]
    async fn create_bucket_from_snapshot_maps_version_insert_error() {
        let repo = setup_repo().await;
        let (owner_user_id, snapshot_id) = seed_snapshot(&repo, "restore-version", "one.txt").await;
        let fail = FailTriggerGuard::create(repo.pool(), "object_versions", "BEFORE", "INSERT")
            .await
            .expect("failpoint");
        let err = repo
            .create_bucket_from_snapshot(snapshot_id, "restore-bucket-version", owner_user_id)
            .await
            .unwrap_err();
        assert!(err.as_database_error().is_some());
        fail.remove().await.expect("remove failpoint");
    }

    #[tokio::test]
    async fn create_bucket_from_snapshot_maps_manifest_link_error() {
        let repo = setup_repo().await;
        let (owner_user_id, snapshot_id) = seed_snapshot(&repo, "restore-link", "one.txt").await;
        let fail =
            FailTriggerGuard::create(repo.pool(), "object_version_manifests", "BEFORE", "INSERT")
                .await
                .expect("failpoint");
        let err = repo
            .create_bucket_from_snapshot(snapshot_id, "restore-bucket-link", owner_user_id)
            .await
            .unwrap_err();
        assert!(err.as_database_error().is_some());
        fail.remove().await.expect("remove failpoint");
    }

    #[tokio::test]
    async fn create_bucket_from_snapshot_maps_commit_error() {
        let repo = setup_repo().await;
        let (owner_user_id, snapshot_id) = seed_snapshot(&repo, "restore-commit", "one.txt").await;
        let fail =
            FailTriggerGuard::create_deferred(repo.pool(), "object_versions", "AFTER", "INSERT")
                .await
                .expect("deferred failpoint");
        let err = repo
            .create_bucket_from_snapshot(snapshot_id, "restore-bucket-commit", owner_user_id)
            .await
            .unwrap_err();
        assert!(err.as_database_error().is_some());
        fail.remove().await.expect("remove failpoint");
    }
}
