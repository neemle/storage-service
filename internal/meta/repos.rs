use crate::meta::models::*;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

#[cfg(test)]
mod checksum_failpoints {
    use std::sync::atomic::{AtomicBool, Ordering};

    static FORCE_NONE: AtomicBool = AtomicBool::new(false);
    static FORCE_ALGO_ERROR: AtomicBool = AtomicBool::new(false);
    static FORCE_VALUE_ERROR: AtomicBool = AtomicBool::new(false);

    pub(super) struct ChecksumNoneGuard;
    pub(super) struct ChecksumAlgoErrorGuard;
    pub(super) struct ChecksumValueErrorGuard;

    impl Drop for ChecksumNoneGuard {
        fn drop(&mut self) {
            FORCE_NONE.store(false, Ordering::SeqCst);
        }
    }

    impl Drop for ChecksumAlgoErrorGuard {
        fn drop(&mut self) {
            FORCE_ALGO_ERROR.store(false, Ordering::SeqCst);
        }
    }

    impl Drop for ChecksumValueErrorGuard {
        fn drop(&mut self) {
            FORCE_VALUE_ERROR.store(false, Ordering::SeqCst);
        }
    }

    pub(super) fn guard() -> ChecksumNoneGuard {
        FORCE_NONE.store(true, Ordering::SeqCst);
        ChecksumNoneGuard
    }

    pub(super) fn guard_algo_error() -> ChecksumAlgoErrorGuard {
        FORCE_ALGO_ERROR.store(true, Ordering::SeqCst);
        ChecksumAlgoErrorGuard
    }

    pub(super) fn guard_value_error() -> ChecksumValueErrorGuard {
        FORCE_VALUE_ERROR.store(true, Ordering::SeqCst);
        ChecksumValueErrorGuard
    }

    pub(super) fn take_none() -> bool {
        FORCE_NONE.swap(false, Ordering::SeqCst)
    }

    pub(super) fn take_algo_error() -> bool {
        FORCE_ALGO_ERROR.swap(false, Ordering::SeqCst)
    }

    pub(super) fn take_value_error() -> bool {
        FORCE_VALUE_ERROR.swap(false, Ordering::SeqCst)
    }
}

#[cfg(test)]
pub(crate) fn checksum_none_guard() -> impl Drop {
    checksum_failpoints::guard()
}

#[cfg(test)]
fn checksum_error_flags() -> (bool, bool) {
    (
        checksum_failpoints::take_algo_error(),
        checksum_failpoints::take_value_error(),
    )
}

#[cfg(not(test))]
fn checksum_error_flags() -> (bool, bool) {
    (false, false)
}

#[cfg(test)]
pub(crate) fn checksum_algo_error_guard() -> impl Drop {
    checksum_failpoints::guard_algo_error()
}

#[cfg(test)]
pub(crate) fn checksum_value_error_guard() -> impl Drop {
    checksum_failpoints::guard_value_error()
}

#[cfg(test)]
mod commit_failpoints {
    use std::sync::atomic::{AtomicBool, Ordering};

    static FORCE_FAIL: AtomicBool = AtomicBool::new(false);

    pub(super) struct CommitFailGuard;

    impl Drop for CommitFailGuard {
        fn drop(&mut self) {
            FORCE_FAIL.store(false, Ordering::SeqCst);
        }
    }

    pub(super) fn guard() -> CommitFailGuard {
        FORCE_FAIL.store(true, Ordering::SeqCst);
        CommitFailGuard
    }

    pub(super) fn take_fail() -> bool {
        FORCE_FAIL.swap(false, Ordering::SeqCst)
    }
}

#[cfg(test)]
pub(crate) fn commit_fail_guard() -> impl Drop {
    commit_failpoints::guard()
}

#[cfg(test)]
mod delete_version_failpoints {
    use std::sync::atomic::{AtomicBool, Ordering};

    static FORCE_LATEST_FETCH_ERROR: AtomicBool = AtomicBool::new(false);

    pub(super) struct LatestFetchErrorGuard;

    impl Drop for LatestFetchErrorGuard {
        fn drop(&mut self) {
            FORCE_LATEST_FETCH_ERROR.store(false, Ordering::SeqCst);
        }
    }

    pub(super) fn guard_latest_fetch_error() -> LatestFetchErrorGuard {
        FORCE_LATEST_FETCH_ERROR.store(true, Ordering::SeqCst);
        LatestFetchErrorGuard
    }

    pub(super) fn take_latest_fetch_error() -> bool {
        FORCE_LATEST_FETCH_ERROR.swap(false, Ordering::SeqCst)
    }
}

#[cfg(test)]
pub(crate) fn delete_version_latest_fetch_error_guard() -> impl Drop {
    delete_version_failpoints::guard_latest_fetch_error()
}

#[cfg(test)]
mod delete_other_versions_failpoints {
    use std::sync::atomic::{AtomicBool, Ordering};

    static FORCE_FAIL: AtomicBool = AtomicBool::new(false);

    pub(super) struct DeleteOtherVersionsFailGuard;

    impl Drop for DeleteOtherVersionsFailGuard {
        fn drop(&mut self) {
            FORCE_FAIL.store(false, Ordering::SeqCst);
        }
    }

    pub(super) fn guard() -> DeleteOtherVersionsFailGuard {
        FORCE_FAIL.store(true, Ordering::SeqCst);
        DeleteOtherVersionsFailGuard
    }

    pub(super) fn take_fail() -> bool {
        FORCE_FAIL.swap(false, Ordering::SeqCst)
    }
}

#[cfg(test)]
pub(crate) fn delete_other_versions_fail_guard() -> impl Drop {
    delete_other_versions_failpoints::guard()
}

async fn commit_tx(tx: Transaction<'_, Postgres>) -> Result<(), sqlx::Error> {
    #[cfg(test)]
    if commit_failpoints::take_fail() {
        return Err(sqlx::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "failpoint",
        )));
    }
    tx.commit().await
}
pub struct Repo {
    pool: PgPool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChunkReplicaNode {
    pub chunk_id: Uuid,
    pub node_id: Uuid,
    pub state: String,
    pub stored_at: Option<DateTime<Utc>>,
    pub role: String,
    pub address_internal: String,
    pub status: String,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub capacity_bytes: Option<i64>,
    pub free_bytes: Option<i64>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct DeleteVersionResult {
    pub found: bool,
    pub was_current: bool,
}

struct ObjectVersionInsert<'a> {
    bucket_id: Uuid,
    object_key: &'a str,
    version_id: &'a str,
    size_bytes: i64,
    etag: &'a str,
    content_type: Option<&'a str>,
    metadata_json: &'a Value,
    tags_json: &'a Value,
    is_delete_marker: bool,
}

#[allow(clippy::too_many_arguments)]
fn object_version_insert<'a>(
    bucket_id: Uuid,
    object_key: &'a str,
    version_id: &'a str,
    size_bytes: i64,
    etag: &'a str,
    content_type: Option<&'a str>,
    metadata_json: &'a Value,
    tags_json: &'a Value,
    is_delete_marker: bool,
) -> ObjectVersionInsert<'a> {
    ObjectVersionInsert {
        bucket_id,
        object_key,
        version_id,
        size_bytes,
        etag,
        content_type,
        metadata_json,
        tags_json,
        is_delete_marker,
    }
}

impl Repo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn ensure_admin_user(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<User, sqlx::Error> {
        self.ensure_admin_user_with_policy(username, password_hash, false)
            .await
    }

    pub async fn ensure_admin_user_with_policy(
        &self,
        username: &str,
        password_hash: &str,
        force_password: bool,
    ) -> Result<User, sqlx::Error> {
        if let Some(user) = self.find_user_by_username(username).await? {
            if force_password {
                self.update_user_password(user.id, password_hash).await?;
                let mut updated = user;
                updated.password_hash = password_hash.to_string();
                return Ok(updated);
            }
            return Ok(user);
        }
        self.create_user(username, None, password_hash, "active")
            .await
    }

    pub async fn create_user(
        &self,
        username: &str,
        display_name: Option<&str>,
        password_hash: &str,
        status: &str,
    ) -> Result<User, sqlx::Error> {
        let now = Utc::now();
        sqlx::query_as::<_, User>(
            r#"INSERT INTO users (username, display_name, password_hash, status, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *"#,
        )
        .bind(username)
        .bind(display_name)
        .bind(password_hash)
        .bind(status)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn list_users(&self) -> Result<Vec<User>, sqlx::Error> {
        sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
    }

    pub async fn find_user_by_username(&self, username: &str) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE username=$1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE id=$1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn update_user_status(&self, user_id: Uuid, status: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET status=$1, updated_at=$2 WHERE id=$3")
            .bind(status)
            .bind(Utc::now())
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_user_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET password_hash=$1, updated_at=$2 WHERE id=$3")
            .bind(password_hash)
            .bind(Utc::now())
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn create_access_key(
        &self,
        access_key_id: &str,
        user_id: Uuid,
        label: &str,
        status: &str,
        secret_encrypted: &[u8],
    ) -> Result<AccessKey, sqlx::Error> {
        let now = Utc::now();
        sqlx::query_as::<_, AccessKey>(
            r#"INSERT INTO access_keys (access_key_id, user_id, label, status, secret_encrypted, secret_kid, created_at)
            VALUES ($1, $2, $3, $4, $5, 'v1', $6)
            RETURNING *"#,
        )
        .bind(access_key_id)
        .bind(user_id)
        .bind(label)
        .bind(status)
        .bind(secret_encrypted)
        .bind(now)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn list_access_keys(&self, user_id: Uuid) -> Result<Vec<AccessKey>, sqlx::Error> {
        sqlx::query_as::<_, AccessKey>(
            "SELECT * FROM access_keys WHERE user_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC",
        )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
    }

    pub async fn get_access_key(
        &self,
        access_key_id: &str,
    ) -> Result<Option<AccessKey>, sqlx::Error> {
        sqlx::query_as::<_, AccessKey>(
            "SELECT * FROM access_keys WHERE access_key_id=$1 AND status='active' AND deleted_at IS NULL",
        )
            .bind(access_key_id)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn update_access_key_status(
        &self,
        access_key_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE access_keys SET status=$1 WHERE access_key_id=$2")
            .bind(status)
            .bind(access_key_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_access_key_status_for_user(
        &self,
        access_key_id: &str,
        user_id: Uuid,
        status: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE access_keys SET status=$1 WHERE access_key_id=$2 AND user_id=$3 AND deleted_at IS NULL",
        )
        .bind(status)
        .bind(access_key_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn delete_access_key(&self, access_key_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE access_keys SET status='deleted', deleted_at=$1 WHERE access_key_id=$2",
        )
        .bind(Utc::now())
        .bind(access_key_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_access_key_for_user(
        &self,
        access_key_id: &str,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(concat!(
            "UPDATE access_keys SET status='deleted', deleted_at=$1 ",
            "WHERE access_key_id=$2 AND user_id=$3 AND deleted_at IS NULL",
        ))
        .bind(Utc::now())
        .bind(access_key_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn touch_access_key_usage(&self, access_key_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE access_keys SET last_used_at=$1 WHERE access_key_id=$2")
            .bind(Utc::now())
            .bind(access_key_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn create_bucket(
        &self,
        name: &str,
        owner_user_id: Uuid,
    ) -> Result<Bucket, sqlx::Error> {
        let now = Utc::now();
        sqlx::query_as::<_, Bucket>(
            r#"INSERT INTO buckets (name, owner_user_id, created_at, versioning_status, public_read)
            VALUES ($1, $2, $3, 'off', false)
            RETURNING *"#,
        )
        .bind(name)
        .bind(owner_user_id)
        .bind(now)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn list_buckets(&self, owner_user_id: Uuid) -> Result<Vec<Bucket>, sqlx::Error> {
        sqlx::query_as::<_, Bucket>(
            "SELECT * FROM buckets WHERE owner_user_id=$1 ORDER BY created_at DESC",
        )
        .bind(owner_user_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_bucket(&self, name: &str) -> Result<Option<Bucket>, sqlx::Error> {
        sqlx::query_as::<_, Bucket>("SELECT * FROM buckets WHERE name=$1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn delete_bucket(&self, name: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM buckets WHERE name=$1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_bucket_notification(
        &self,
        bucket_id: Uuid,
        config_xml: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE buckets SET notification_config_xml=$1 WHERE id=$2")
            .bind(config_xml)
            .bind(bucket_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_bucket_versioning(
        &self,
        bucket_id: Uuid,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE buckets SET versioning_status=$1 WHERE id=$2")
            .bind(status)
            .bind(bucket_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_bucket_name(&self, bucket_id: Uuid, name: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE buckets SET name=$1 WHERE id=$2")
            .bind(name)
            .bind(bucket_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_bucket_public(
        &self,
        bucket_id: Uuid,
        public_read: bool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE buckets SET public_read=$1 WHERE id=$2")
            .bind(public_read)
            .bind(bucket_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_objects_current(
        &self,
        bucket_id: Uuid,
        prefix: Option<&str>,
        start_after: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ObjectVersion>, sqlx::Error> {
        let mut builder =
            sqlx::QueryBuilder::new("SELECT * FROM object_versions WHERE bucket_id = ");
        builder.push_bind(bucket_id);
        builder.push(" AND current=true AND is_delete_marker=false");
        if let Some(prefix_val) = prefix {
            let mut upper = prefix_val.to_string();
            upper.push(char::MAX);
            builder.push(" AND object_key >= ");
            builder.push_bind(prefix_val);
            builder.push(" AND object_key < ");
            builder.push_bind(upper);
        }
        if let Some(start_val) = start_after {
            builder.push(" AND object_key > ");
            builder.push_bind(start_val);
        }
        builder.push(" ORDER BY object_key ASC LIMIT ");
        builder.push_bind(limit);
        let query = builder.build_query_as::<ObjectVersion>();
        query.fetch_all(&self.pool).await
    }

    pub async fn update_object_metadata(
        &self,
        bucket_id: Uuid,
        object_key: &str,
        metadata_json: &Value,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE object_versions SET metadata_json=$1 WHERE bucket_id=$2 AND object_key=$3 AND current=true",
        )
        .bind(metadata_json)
        .bind(bucket_id)
        .bind(object_key)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() > 0 {
            let _ = self.mark_bucket_changed(bucket_id).await;
        }
        Ok(result.rows_affected())
    }

    pub async fn rename_object_key(
        &self,
        bucket_id: Uuid,
        from_key: &str,
        to_key: &str,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE object_versions SET object_key=$1 WHERE bucket_id=$2 AND object_key=$3",
        )
        .bind(to_key)
        .bind(bucket_id)
        .bind(from_key)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() > 0 {
            let _ = self.mark_bucket_changed(bucket_id).await;
        }
        Ok(result.rows_affected())
    }

    pub async fn create_manifest(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        total_size: i64,
        chunks: &[Uuid],
    ) -> Result<Uuid, sqlx::Error> {
        let manifest_id = Uuid::new_v4();
        sqlx::query("INSERT INTO manifests (id, total_size_bytes, created_at) VALUES ($1, $2, $3)")
            .bind(manifest_id)
            .bind(total_size)
            .bind(Utc::now())
            .execute(&mut **tx)
            .await?;
        for (idx, chunk_id) in chunks.iter().enumerate() {
            sqlx::query("INSERT INTO manifest_chunks (manifest_id, chunk_index, chunk_id) VALUES ($1, $2, $3)")
                .bind(manifest_id)
                .bind(idx as i32)
                .bind(chunk_id)
                .execute(&mut **tx)
                .await?;
        }
        Ok(manifest_id)
    }

    async fn clear_current_object_versions(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        bucket_id: Uuid,
        object_key: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE object_versions SET current=false WHERE bucket_id=$1 AND object_key=$2 AND current=true",
        )
        .bind(bucket_id)
        .bind(object_key)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_object_version_row(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        input: &ObjectVersionInsert<'_>,
    ) -> Result<ObjectVersion, sqlx::Error> {
        sqlx::query_as(
            r#"INSERT INTO object_versions
            (
                bucket_id, object_key, version_id, is_delete_marker, size_bytes, etag,
                content_type, metadata_json, tags_json, created_at, current
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true)
            RETURNING *"#,
        )
        .bind(input.bucket_id)
        .bind(input.object_key)
        .bind(input.version_id)
        .bind(input.is_delete_marker)
        .bind(input.size_bytes)
        .bind(input.etag)
        .bind(input.content_type)
        .bind(input.metadata_json)
        .bind(input.tags_json)
        .bind(Utc::now())
        .fetch_one(&mut **tx)
        .await
    }

    async fn link_manifest_to_object_version(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        object_version_id: Uuid,
        manifest_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO object_version_manifests (object_version_id, manifest_id) VALUES ($1, $2)",
        )
        .bind(object_version_id)
        .bind(manifest_id)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    #[rustfmt::skip]
    #[allow(clippy::too_many_arguments)]
    pub async fn finalize_object_version(
        &self, bucket_id: Uuid, object_key: &str, version_id: &str, size_bytes: i64, etag: &str,
        content_type: Option<&str>, metadata_json: &Value, tags_json: &Value, manifest_chunks: &[Uuid],
        is_delete_marker: bool,
    ) -> Result<ObjectVersion, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let insert = object_version_insert(bucket_id, object_key, version_id, size_bytes, etag, content_type,
            metadata_json, tags_json, is_delete_marker);
        let object_version = self.finalize_object_version_tx(&mut tx, &insert, manifest_chunks).await?;
        self.finish_finalize_object_version(tx, bucket_id, object_version).await
    }

    async fn finish_finalize_object_version(
        &self,
        tx: Transaction<'_, Postgres>,
        bucket_id: Uuid,
        object_version: ObjectVersion,
    ) -> Result<ObjectVersion, sqlx::Error> {
        tx.commit().await?;
        let _ = self.mark_bucket_changed(bucket_id).await;
        Ok(object_version)
    }

    async fn finalize_object_version_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        insert: &ObjectVersionInsert<'_>,
        manifest_chunks: &[Uuid],
    ) -> Result<ObjectVersion, sqlx::Error> {
        self.clear_current_object_versions(tx, insert.bucket_id, insert.object_key)
            .await?;
        let object_version = self.insert_object_version_row(tx, insert).await?;
        let manifest_id = self
            .create_manifest(tx, insert.size_bytes, manifest_chunks)
            .await?;
        self.link_manifest_to_object_version(tx, object_version.id, manifest_id)
            .await?;
        Ok(object_version)
    }

    pub async fn get_object_current(
        &self,
        bucket_id: Uuid,
        object_key: &str,
    ) -> Result<Option<(ObjectVersion, Uuid)>, sqlx::Error> {
        let object = sqlx::query_as::<_, ObjectVersion>(
            r#"SELECT * FROM object_versions
            WHERE bucket_id=$1 AND object_key=$2 AND current=true AND is_delete_marker=false"#,
        )
        .bind(bucket_id)
        .bind(object_key)
        .fetch_optional(&self.pool)
        .await?;

        let Some(object_version) = object else {
            return Ok(None);
        };

        let manifest_id: Uuid = sqlx::query_scalar(
            "SELECT manifest_id FROM object_version_manifests WHERE object_version_id=$1",
        )
        .bind(object_version.id)
        .fetch_one(&self.pool)
        .await?;

        Ok(Some((object_version, manifest_id)))
    }

    pub async fn get_object_version(
        &self,
        bucket_id: Uuid,
        object_key: &str,
        version_id: &str,
    ) -> Result<Option<(ObjectVersion, Uuid)>, sqlx::Error> {
        let object = sqlx::query_as::<_, ObjectVersion>(
            r#"SELECT * FROM object_versions
            WHERE bucket_id=$1 AND object_key=$2 AND version_id=$3"#,
        )
        .bind(bucket_id)
        .bind(object_key)
        .bind(version_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(object_version) = object else {
            return Ok(None);
        };

        let manifest_id: Uuid = sqlx::query_scalar(
            "SELECT manifest_id FROM object_version_manifests WHERE object_version_id=$1",
        )
        .bind(object_version.id)
        .fetch_one(&self.pool)
        .await?;

        Ok(Some((object_version, manifest_id)))
    }

    async fn lookup_marker_created_at(
        &self,
        bucket_id: Uuid,
        key_marker: Option<&str>,
        version_id_marker: Option<&str>,
    ) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
        let (Some(key_marker), Some(version_marker)) = (key_marker, version_id_marker) else {
            return Ok(None);
        };
        let marker = self
            .get_object_version(bucket_id, key_marker, version_marker)
            .await?;
        Ok(marker.map(|(version, _)| version.created_at))
    }

    fn apply_prefix_filter<'a>(
        builder: &mut sqlx::QueryBuilder<'a, Postgres>,
        prefix: Option<&'a str>,
    ) {
        if let Some(prefix_val) = prefix {
            let mut upper = prefix_val.to_string();
            upper.push(char::MAX);
            builder.push(" AND object_key >= ");
            builder.push_bind(prefix_val);
            builder.push(" AND object_key < ");
            builder.push_bind(upper);
        }
    }

    fn apply_key_marker_filter<'a>(
        builder: &mut sqlx::QueryBuilder<'a, Postgres>,
        key_marker: Option<&'a str>,
        marker_created_at: Option<DateTime<Utc>>,
    ) {
        let Some(marker) = key_marker else {
            return;
        };
        if let Some(created_at) = marker_created_at {
            builder.push(" AND (object_key > ");
            builder.push_bind(marker);
            builder.push(" OR (object_key = ");
            builder.push_bind(marker);
            builder.push(" AND created_at < ");
            builder.push_bind(created_at);
            builder.push("))");
            return;
        }
        builder.push(" AND object_key > ");
        builder.push_bind(marker);
    }

    pub async fn list_object_versions(
        &self,
        bucket_id: Uuid,
        prefix: Option<&str>,
        key_marker: Option<&str>,
        version_id_marker: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ObjectVersion>, sqlx::Error> {
        let marker_created_at = self
            .lookup_marker_created_at(bucket_id, key_marker, version_id_marker)
            .await?;
        let mut builder =
            sqlx::QueryBuilder::new("SELECT * FROM object_versions WHERE bucket_id = ");
        builder.push_bind(bucket_id);
        Self::apply_prefix_filter(&mut builder, prefix);
        Self::apply_key_marker_filter(&mut builder, key_marker, marker_created_at);
        builder.push(" ORDER BY object_key ASC, created_at DESC LIMIT ");
        builder.push_bind(limit);
        let query = builder.build_query_as::<ObjectVersion>();
        query.fetch_all(&self.pool).await
    }

    async fn load_object_version_for_delete(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        bucket_id: Uuid,
        object_key: &str,
        version_id: &str,
    ) -> Result<Option<ObjectVersion>, sqlx::Error> {
        sqlx::query_as::<_, ObjectVersion>(
            "SELECT * FROM object_versions WHERE bucket_id=$1 AND object_key=$2 AND version_id=$3",
        )
        .bind(bucket_id)
        .bind(object_key)
        .bind(version_id)
        .fetch_optional(&mut **tx)
        .await
    }

    async fn load_manifest_id_for_object_version(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        object_version_id: Uuid,
    ) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT manifest_id FROM object_version_manifests WHERE object_version_id=$1",
        )
        .bind(object_version_id)
        .fetch_one(&mut **tx)
        .await
    }

    async fn delete_manifest_resources(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        object_version_id: Uuid,
        manifest_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM object_version_manifests WHERE object_version_id=$1")
            .bind(object_version_id)
            .execute(&mut **tx)
            .await?;
        sqlx::query("DELETE FROM manifest_chunks WHERE manifest_id=$1")
            .bind(manifest_id)
            .execute(&mut **tx)
            .await?;
        sqlx::query("DELETE FROM manifests WHERE id=$1")
            .bind(manifest_id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    async fn delete_object_version_row(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        object_version_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM object_versions WHERE id=$1")
            .bind(object_version_id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    #[cfg(test)]
    fn use_latest_fetch_fail_query() -> bool {
        delete_version_failpoints::take_latest_fetch_error()
    }

    #[cfg(not(test))]
    fn use_latest_fetch_fail_query() -> bool {
        false
    }

    fn latest_version_query(use_fail_query: bool) -> &'static str {
        if use_fail_query {
            return concat!(
                "SELECT id FROM missing_versions WHERE bucket_id=$1 AND object_key=$2 ",
                "ORDER BY created_at DESC LIMIT 1",
            );
        }
        concat!(
            "SELECT id FROM object_versions WHERE bucket_id=$1 AND object_key=$2 ",
            "ORDER BY created_at DESC LIMIT 1",
        )
    }

    async fn promote_latest_object_version(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        bucket_id: Uuid,
        object_key: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE object_versions SET current=false WHERE bucket_id=$1 AND object_key=$2",
        )
        .bind(bucket_id)
        .bind(object_key)
        .execute(&mut **tx)
        .await?;
        let latest_query = Self::latest_version_query(Self::use_latest_fetch_fail_query());
        let latest: Option<Uuid> = sqlx::query_scalar(latest_query)
            .bind(bucket_id)
            .bind(object_key)
            .fetch_optional(&mut **tx)
            .await?;
        if let Some(latest_id) = latest {
            sqlx::query("UPDATE object_versions SET current=true WHERE id=$1")
                .bind(latest_id)
                .execute(&mut **tx)
                .await?;
        }
        Ok(())
    }

    pub async fn delete_object_version(
        &self,
        bucket_id: Uuid,
        object_key: &str,
        version_id: &str,
    ) -> Result<DeleteVersionResult, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let object = self
            .load_object_version_for_delete(&mut tx, bucket_id, object_key, version_id)
            .await?;
        let Some(object_version) = object else {
            return Ok(Self::not_found_delete_version_result());
        };
        self.delete_version_data(&mut tx, object_version.id).await?;

        if object_version.current {
            self.promote_latest_object_version(&mut tx, bucket_id, object_key)
                .await?;
        }

        tx.commit().await?;
        let _ = self.mark_bucket_changed(bucket_id).await;
        Ok(Self::found_delete_version_result(object_version.current))
    }

    fn not_found_delete_version_result() -> DeleteVersionResult {
        DeleteVersionResult {
            found: false,
            was_current: false,
        }
    }

    fn found_delete_version_result(was_current: bool) -> DeleteVersionResult {
        DeleteVersionResult {
            found: true,
            was_current,
        }
    }

    async fn delete_version_data(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        object_version_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        let manifest_id = self
            .load_manifest_id_for_object_version(tx, object_version_id)
            .await?;
        self.delete_manifest_resources(tx, object_version_id, manifest_id)
            .await?;
        self.delete_object_version_row(tx, object_version_id).await
    }

    pub async fn delete_other_object_versions(
        &self,
        bucket_id: Uuid,
        object_key: &str,
        keep_version_id: &str,
    ) -> Result<(), sqlx::Error> {
        #[cfg(test)]
        if delete_other_versions_failpoints::take_fail() {
            return Err(sqlx::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "failpoint",
            )));
        }
        let versions = sqlx::query_scalar::<_, String>(
            "SELECT version_id FROM object_versions WHERE bucket_id=$1 AND object_key=$2 AND version_id<>$3",
        )
        .bind(bucket_id)
        .bind(object_key)
        .bind(keep_version_id)
        .fetch_all(&self.pool)
        .await?;
        for version_id in versions {
            let _ = self
                .delete_object_version(bucket_id, object_key, &version_id)
                .await?;
        }
        Ok(())
    }

    pub async fn delete_all_object_versions(
        &self,
        bucket_id: Uuid,
        object_key: &str,
    ) -> Result<(), sqlx::Error> {
        let versions = sqlx::query_scalar::<_, String>(
            "SELECT version_id FROM object_versions WHERE bucket_id=$1 AND object_key=$2",
        )
        .bind(bucket_id)
        .bind(object_key)
        .fetch_all(&self.pool)
        .await?;
        for version_id in versions {
            let _ = self
                .delete_object_version(bucket_id, object_key, &version_id)
                .await?;
        }
        Ok(())
    }

    pub async fn get_manifest_chunks(
        &self,
        manifest_id: Uuid,
    ) -> Result<Vec<ManifestChunk>, sqlx::Error> {
        sqlx::query_as::<_, ManifestChunk>(
            "SELECT * FROM manifest_chunks WHERE manifest_id=$1 ORDER BY chunk_index ASC",
        )
        .bind(manifest_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn create_multipart_upload(
        &self,
        bucket_id: Uuid,
        object_key: &str,
        upload_id: &str,
    ) -> Result<MultipartUpload, sqlx::Error> {
        let now = Utc::now();
        sqlx::query_as::<_, MultipartUpload>(
            r#"INSERT INTO multipart_uploads (bucket_id, object_key, upload_id, initiated_at, status)
            VALUES ($1, $2, $3, $4, 'active')
            RETURNING *"#,
        )
        .bind(bucket_id)
        .bind(object_key)
        .bind(upload_id)
        .bind(now)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn get_multipart_upload(
        &self,
        upload_id: &str,
    ) -> Result<Option<MultipartUpload>, sqlx::Error> {
        sqlx::query_as::<_, MultipartUpload>("SELECT * FROM multipart_uploads WHERE upload_id=$1")
            .bind(upload_id)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn list_multipart_uploads(
        &self,
        bucket_id: Uuid,
    ) -> Result<Vec<MultipartUpload>, sqlx::Error> {
        sqlx::query_as::<_, MultipartUpload>(
            "SELECT * FROM multipart_uploads WHERE bucket_id=$1 ORDER BY initiated_at DESC",
        )
        .bind(bucket_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn upsert_multipart_part(
        &self,
        upload_id: &str,
        part_number: i32,
        size_bytes: i64,
        etag: &str,
        manifest_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"INSERT INTO multipart_parts (upload_id, part_number, size_bytes, etag, manifest_id)
            VALUES ($1,$2,$3,$4,$5)
            ON CONFLICT (upload_id, part_number) DO UPDATE
            SET size_bytes=EXCLUDED.size_bytes, etag=EXCLUDED.etag, manifest_id=EXCLUDED.manifest_id"#,
        )
        .bind(upload_id)
        .bind(part_number)
        .bind(size_bytes)
        .bind(etag)
        .bind(manifest_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_multipart_parts(
        &self,
        upload_id: &str,
    ) -> Result<Vec<MultipartPart>, sqlx::Error> {
        sqlx::query_as::<_, MultipartPart>(
            "SELECT * FROM multipart_parts WHERE upload_id=$1 ORDER BY part_number ASC",
        )
        .bind(upload_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn complete_multipart_upload(&self, upload_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE multipart_uploads SET status='completed' WHERE upload_id=$1")
            .bind(upload_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn abort_multipart_upload(&self, upload_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE multipart_uploads SET status='aborted' WHERE upload_id=$1")
            .bind(upload_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_stale_multipart_uploads(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<String>, sqlx::Error> {
        sqlx::query_scalar::<_, String>(
            "SELECT upload_id FROM multipart_uploads WHERE status='active' AND initiated_at < $1",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn cleanup_multipart_upload(&self, upload_id: &str) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let manifest_ids = sqlx::query_scalar::<_, Uuid>(
            "SELECT manifest_id FROM multipart_parts WHERE upload_id=$1",
        )
        .bind(upload_id)
        .fetch_all(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM multipart_parts WHERE upload_id=$1")
            .bind(upload_id)
            .execute(&mut *tx)
            .await?;
        for manifest_id in manifest_ids {
            sqlx::query("DELETE FROM manifest_chunks WHERE manifest_id=$1")
                .bind(manifest_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM manifests WHERE id=$1")
                .bind(manifest_id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("UPDATE multipart_uploads SET status='aborted' WHERE upload_id=$1")
            .bind(upload_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_orphan_manifest_ids(&self, limit: i64) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar::<_, Uuid>(
            r#"SELECT id FROM manifests
               WHERE id NOT IN (SELECT manifest_id FROM object_version_manifests)
                 AND id NOT IN (SELECT manifest_id FROM multipart_parts)
                 AND id NOT IN (SELECT manifest_id FROM bucket_snapshot_objects)
               LIMIT $1"#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn delete_manifest(&self, manifest_id: Uuid) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM manifest_chunks WHERE manifest_id=$1")
            .bind(manifest_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM manifests WHERE id=$1")
            .bind(manifest_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_orphan_chunk_ids(&self, limit: i64) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar::<_, Uuid>(
            r#"SELECT chunk_id FROM chunks
               WHERE chunk_id NOT IN (SELECT DISTINCT chunk_id FROM manifest_chunks)
               LIMIT $1"#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn delete_chunk_metadata(&self, chunk_id: Uuid) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM chunk_replicas WHERE chunk_id=$1")
            .bind(chunk_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM chunks WHERE chunk_id=$1")
            .bind(chunk_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn insert_chunk_metadata(
        &self,
        chunk_id: Uuid,
        size_bytes: i32,
        checksum_algo: &str,
        checksum_value: &[u8],
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO chunks (chunk_id, size_bytes, checksum_algo, checksum_value, created_at) \
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(chunk_id)
        .bind(size_bytes)
        .bind(checksum_algo)
        .bind(checksum_value)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_chunk_replica(
        &self,
        chunk_id: Uuid,
        node_id: Uuid,
        state: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO chunk_replicas (chunk_id, node_id, state, stored_at) VALUES ($1,$2,$3,$4)",
        )
        .bind(chunk_id)
        .bind(node_id)
        .bind(state)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_chunk_replica_state(
        &self,
        chunk_id: Uuid,
        node_id: Uuid,
        state: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE chunk_replicas SET state=$1 WHERE chunk_id=$2 AND node_id=$3")
            .bind(state)
            .bind(chunk_id)
            .bind(node_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_chunk_ids(&self, limit: i64) -> Result<Vec<Uuid>, sqlx::Error> {
        let rows = sqlx::query_scalar::<_, Uuid>(
            "SELECT chunk_id FROM chunks ORDER BY created_at DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn fetch_chunk_checksum_row(
        &self,
        chunk_id: Uuid,
        algo_error: bool,
        value_error: bool,
    ) -> Result<Option<sqlx::postgres::PgRow>, sqlx::Error> {
        let query = if algo_error {
            "SELECT checksum_value FROM chunks WHERE chunk_id=$1"
        } else if value_error {
            "SELECT checksum_algo FROM chunks WHERE chunk_id=$1"
        } else {
            "SELECT checksum_algo, checksum_value FROM chunks WHERE chunk_id=$1"
        };
        sqlx::query(query)
            .bind(chunk_id)
            .fetch_optional(&self.pool)
            .await
    }

    fn parse_chunk_checksum_row(
        row: sqlx::postgres::PgRow,
    ) -> Result<(String, Vec<u8>), sqlx::Error> {
        let algo: String = row.try_get("checksum_algo")?;
        let value: Vec<u8> = row.try_get("checksum_value")?;
        Ok((algo, value))
    }

    pub async fn get_chunk_checksum(
        &self,
        chunk_id: Uuid,
    ) -> Result<Option<(String, Vec<u8>)>, sqlx::Error> {
        #[cfg(test)]
        if checksum_failpoints::take_none() {
            return Ok(None);
        }
        let (algo_error, value_error) = checksum_error_flags();
        let row = self
            .fetch_chunk_checksum_row(chunk_id, algo_error, value_error)
            .await?;
        if let Some(row) = row {
            let checksum = Self::parse_chunk_checksum_row(row)?;
            return Ok(Some(checksum));
        }
        Ok(None)
    }

    pub async fn list_chunk_replicas_with_nodes(
        &self,
        chunk_id: Uuid,
    ) -> Result<Vec<ChunkReplicaNode>, sqlx::Error> {
        sqlx::query_as::<_, ChunkReplicaNode>(
            r#"SELECT cr.chunk_id, cr.node_id, cr.state, cr.stored_at,
                      n.role, n.address_internal, n.status, n.last_heartbeat_at,
                      n.capacity_bytes, n.free_bytes, n.created_at
               FROM chunk_replicas cr
               JOIN nodes n ON cr.node_id = n.node_id
               WHERE cr.chunk_id = $1"#,
        )
        .bind(chunk_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn list_nodes(&self) -> Result<Vec<Node>, sqlx::Error> {
        sqlx::query_as::<_, Node>("SELECT * FROM nodes ORDER BY created_at ASC")
            .fetch_all(&self.pool)
            .await
    }

    pub async fn get_node_by_address(
        &self,
        address_internal: &str,
    ) -> Result<Option<Node>, sqlx::Error> {
        sqlx::query_as::<_, Node>("SELECT * FROM nodes WHERE address_internal=$1")
            .bind(address_internal)
            .fetch_optional(&self.pool)
            .await
    }

    fn node_timestamps(last_heartbeat_at: Option<DateTime<Utc>>) -> (DateTime<Utc>, DateTime<Utc>) {
        let now = Utc::now();
        (now, last_heartbeat_at.unwrap_or(now))
    }

    #[allow(clippy::too_many_arguments)]
    async fn upsert_node_record(
        &self,
        node_id: Uuid,
        role: &str,
        address_internal: &str,
        status: &str,
        capacity_bytes: Option<i64>,
        free_bytes: Option<i64>,
        now: DateTime<Utc>,
        last_heartbeat_at: DateTime<Utc>,
    ) -> Result<Node, sqlx::Error> {
        sqlx::query_as::<_, Node>(
            r#"INSERT INTO nodes
            (node_id, role, address_internal, status, last_heartbeat_at, capacity_bytes, free_bytes, created_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
            ON CONFLICT (node_id) DO UPDATE
            SET status=EXCLUDED.status, last_heartbeat_at=EXCLUDED.last_heartbeat_at,
                capacity_bytes=EXCLUDED.capacity_bytes, free_bytes=EXCLUDED.free_bytes
            RETURNING *"#,
        )
        .bind(node_id).bind(role).bind(address_internal).bind(status)
        .bind(last_heartbeat_at).bind(capacity_bytes).bind(free_bytes).bind(now)
        .fetch_one(&self.pool)
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_node(
        &self,
        node_id: Uuid,
        role: &str,
        address_internal: &str,
        status: &str,
        capacity_bytes: Option<i64>,
        free_bytes: Option<i64>,
        last_heartbeat_at: Option<DateTime<Utc>>,
    ) -> Result<Node, sqlx::Error> {
        let (now, heartbeat_at) = Self::node_timestamps(last_heartbeat_at);
        self.upsert_node_record(
            node_id,
            role,
            address_internal,
            status,
            capacity_bytes,
            free_bytes,
            now,
            heartbeat_at,
        )
        .await
    }

    pub async fn update_node_heartbeat(
        &self,
        node_id: Uuid,
        capacity_bytes: Option<i64>,
        free_bytes: Option<i64>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE nodes SET last_heartbeat_at=$1, capacity_bytes=$2, free_bytes=$3, status='online' WHERE node_id=$4",
        )
        .bind(Utc::now())
        .bind(capacity_bytes)
        .bind(free_bytes)
        .bind(node_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn create_join_token(
        &self,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<JoinToken, sqlx::Error> {
        let token_id = Uuid::new_v4();
        sqlx::query_as::<_, JoinToken>(
            "INSERT INTO join_tokens (token_id, token_hash, expires_at) VALUES ($1,$2,$3) RETURNING *",
        )
        .bind(token_id)
        .bind(token_hash)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn consume_join_token(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<JoinToken>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let token = sqlx::query_as::<_, JoinToken>(
            "SELECT * FROM join_tokens
             WHERE token_hash=$1 AND used_at IS NULL AND expires_at > $2
             ORDER BY expires_at DESC, token_id DESC
             LIMIT 1
             FOR UPDATE",
        )
        .bind(token_hash)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(token_row) = token.clone() {
            sqlx::query("UPDATE join_tokens SET used_at=$1 WHERE token_id=$2")
                .bind(now)
                .bind(token_row.token_id)
                .execute(&mut *tx)
                .await?;
            commit_tx(tx).await?;
            return Ok(Some(token_row));
        }
        commit_tx(tx).await?;
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_audit_log(
        &self,
        actor_user_id: Option<Uuid>,
        actor_ip: Option<&str>,
        action: &str,
        target_type: Option<&str>,
        target_id: Option<&str>,
        outcome: &str,
        details_json: &Value,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"INSERT INTO audit_log
            (id, ts, actor_user_id, actor_ip, action, target_type, target_id, outcome, details_json)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)"#,
        )
        .bind(Uuid::new_v4())
        .bind(Utc::now())
        .bind(actor_user_id)
        .bind(actor_ip)
        .bind(action)
        .bind(target_type)
        .bind(target_id)
        .bind(outcome)
        .bind(details_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_audit_logs(
        &self,
        since: Option<DateTime<Utc>>,
        until: Option<DateTime<Utc>>,
        user_id: Option<Uuid>,
        action: Option<&str>,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<AuditLog>, sqlx::Error> {
        let mut builder = sqlx::QueryBuilder::new("SELECT * FROM audit_log WHERE 1=1");
        append_audit_filters(&mut builder, since, until, user_id, action);
        builder.push(" ORDER BY ts DESC, id DESC LIMIT ");
        builder.push_bind(limit);
        builder.push(" OFFSET ");
        builder.push_bind(offset);
        let query = builder.build_query_as::<AuditLog>();
        query.fetch_all(&self.pool).await
    }
}

fn append_audit_filters<'a>(
    builder: &mut sqlx::QueryBuilder<'a, sqlx::Postgres>,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    user_id: Option<Uuid>,
    action: Option<&'a str>,
) {
    if let Some(since_val) = since {
        builder.push(" AND ts >= ");
        builder.push_bind(since_val);
    }
    if let Some(until_val) = until {
        builder.push(" AND ts <= ");
        builder.push_bind(until_val);
    }
    if let Some(user_val) = user_id {
        builder.push(" AND actor_user_id = ");
        builder.push_bind(user_val);
    }
    if let Some(action_val) = action {
        builder.push(" AND action = ");
        builder.push_bind(action_val);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;
    use crate::test_support::{FailTriggerGuard, TableRenameGuard};
    use chrono::{Duration, Utc};
    use serde_json::json;

    async fn setup_repo() -> Repo {
        let pool = test_support::setup_pool().await;
        test_support::reset_db(&pool).await;
        Repo::new(pool)
    }

    async fn create_user(repo: &Repo, username: &str) -> User {
        repo.create_user(username, Some(username), "hash", "active")
            .await
            .expect("create user")
    }

    async fn create_bucket(repo: &Repo, user_id: Uuid, name: &str) -> Bucket {
        repo.create_bucket(name, user_id).await.expect("bucket")
    }

    async fn insert_chunk(repo: &Repo, chunk_id: Uuid) {
        repo.insert_chunk_metadata(chunk_id, 4, "crc32c", &[1, 2, 3, 4])
            .await
            .expect("chunk metadata");
    }

    async fn create_manifest(repo: &Repo, total_size: i64, chunks: &[Uuid]) -> Uuid {
        let mut tx = repo.pool().begin().await.expect("tx");
        let manifest_id = repo
            .create_manifest(&mut tx, total_size, chunks)
            .await
            .expect("manifest");
        tx.commit().await.expect("commit");
        manifest_id
    }

    async fn setup_bucket_with_chunk(repo: &Repo, bucket_name: &str) -> (Bucket, Uuid) {
        let user = create_user(repo, &format!("user-{}", Uuid::new_v4())).await;
        let bucket = create_bucket(repo, user.id, bucket_name).await;
        let chunk_id = Uuid::new_v4();
        insert_chunk(repo, chunk_id).await;
        (bucket, chunk_id)
    }

    async fn create_version(
        repo: &Repo,
        bucket: &Bucket,
        key: &str,
        version_id: &str,
        chunk_id: Uuid,
    ) -> ObjectVersion {
        repo.finalize_object_version(
            bucket.id,
            key,
            version_id,
            4,
            "etag",
            None,
            &json!({}),
            &json!({}),
            &[chunk_id],
            false,
        )
        .await
        .expect("version")
    }

    async fn setup_upload_with_part(repo: &Repo, bucket: &Bucket, upload_id: &str) -> Uuid {
        let upload = repo
            .create_multipart_upload(bucket.id, "object.bin", upload_id)
            .await
            .expect("upload");
        let chunk_id = Uuid::new_v4();
        insert_chunk(repo, chunk_id).await;
        let manifest_id = create_manifest(repo, 4, &[chunk_id]).await;
        repo.upsert_multipart_part(&upload.upload_id, 1, 4, "etag1", manifest_id)
            .await
            .expect("part");
        manifest_id
    }

    async fn assert_admin_creation_and_lookup(repo: &Repo) -> User {
        let admin = repo
            .ensure_admin_user("admin", "hash")
            .await
            .expect("ensure admin");
        let admin_again = repo
            .ensure_admin_user("admin", "hash2")
            .await
            .expect("ensure admin");
        assert_eq!(admin.id, admin_again.id);
        let users = repo.list_users().await.expect("list users");
        assert_eq!(users.len(), 1);
        let found = repo
            .find_user_by_username("admin")
            .await
            .expect("find user")
            .expect("exists");
        assert_eq!(found.id, admin.id);
        let forced = repo
            .ensure_admin_user_with_policy("admin", "hash3", true)
            .await
            .expect("force admin password");
        assert_eq!(forced.id, admin.id);
        assert_eq!(forced.password_hash, "hash3");
        assert_user_missing_by_username(repo, "missing").await;
        admin
    }

    async fn assert_user_missing_by_username(repo: &Repo, username: &str) {
        assert!(repo
            .find_user_by_username(username)
            .await
            .expect("find")
            .is_none());
    }

    async fn assert_admin_update_paths(repo: &Repo, admin_id: Uuid) {
        let found_by_id = repo
            .find_user_by_id(admin_id)
            .await
            .expect("find")
            .expect("exists");
        assert_eq!(found_by_id.username, "admin");
        assert!(repo
            .find_user_by_id(Uuid::new_v4())
            .await
            .expect("find")
            .is_none());
        repo.update_user_status(admin_id, "inactive")
            .await
            .expect("status");
        repo.update_user_password(admin_id, "newhash")
            .await
            .expect("password");
        let updated = repo
            .find_user_by_id(admin_id)
            .await
            .expect("find")
            .expect("exists");
        assert_eq!(updated.status, "inactive");
        assert_eq!(updated.password_hash, "newhash");
    }

    #[tokio::test]
    async fn ensure_admin_user_with_policy_reports_force_password_update_error() {
        let repo = setup_repo().await;
        repo.ensure_admin_user_with_policy("admin-force-error", "hash-a", false)
            .await
            .expect("seed admin");
        let guard =
            test_support::FailTriggerGuard::create(repo.pool(), "users", "BEFORE", "UPDATE")
                .await
                .expect("trigger");
        let err = repo
            .ensure_admin_user_with_policy("admin-force-error", "hash-b", true)
            .await
            .expect_err("update error");
        assert!(
            err.to_string().contains("failpoint"),
            "unexpected error: {err}"
        );
        guard.remove().await.expect("remove trigger");
    }

    async fn assert_access_key_lifecycle(repo: &Repo, user_id: Uuid) {
        let key_id = create_test_access_key(repo, user_id, "AKIAADMIN").await;
        let listed = repo.list_access_keys(user_id).await.expect("list keys");
        assert_eq!(listed.len(), 1);
        assert_key_exists(repo, &key_id).await;
        repo.update_access_key_status(&key_id, "disabled")
            .await
            .expect("disable");
        assert_key_missing(repo, &key_id).await;
        repo.touch_access_key_usage(&key_id).await.expect("touch");
        assert_eq!(repo.list_access_keys(user_id).await.expect("list").len(), 1);
        repo.delete_access_key(&key_id).await.expect("delete");
        assert!(repo
            .list_access_keys(user_id)
            .await
            .expect("list")
            .is_empty());
    }

    async fn assert_access_key_owner_scope(repo: &Repo) {
        let owner = create_user(repo, "owner-key-user").await;
        let other = create_user(repo, "other-key-user").await;
        let key_id = create_test_access_key(repo, owner.id, "AKIAOWNED").await;
        assert_non_owner_cannot_mutate_key(repo, &key_id, other.id).await;
        assert_key_exists(repo, &key_id).await;
        assert_owner_can_mutate_key(repo, &key_id, owner.id).await;
    }

    async fn create_test_access_key(repo: &Repo, user_id: Uuid, access_key_id: &str) -> String {
        repo.create_access_key(access_key_id, user_id, "label", "active", b"secret")
            .await
            .expect("create key")
            .access_key_id
    }

    async fn assert_key_exists(repo: &Repo, access_key_id: &str) {
        assert!(repo
            .get_access_key(access_key_id)
            .await
            .expect("get")
            .is_some());
    }

    async fn assert_key_missing(repo: &Repo, access_key_id: &str) {
        assert!(repo
            .get_access_key(access_key_id)
            .await
            .expect("get")
            .is_none());
    }

    async fn assert_non_owner_cannot_mutate_key(repo: &Repo, access_key_id: &str, user_id: Uuid) {
        let updated = repo
            .update_access_key_status_for_user(access_key_id, user_id, "disabled")
            .await
            .expect("update as other");
        assert!(!updated);
        let deleted = repo
            .delete_access_key_for_user(access_key_id, user_id)
            .await
            .expect("delete as other");
        assert!(!deleted);
    }

    async fn assert_owner_can_mutate_key(repo: &Repo, access_key_id: &str, user_id: Uuid) {
        let updated = repo
            .update_access_key_status_for_user(access_key_id, user_id, "disabled")
            .await
            .expect("update as owner");
        assert!(updated);
        let deleted = repo
            .delete_access_key_for_user(access_key_id, user_id)
            .await
            .expect("delete as owner");
        assert!(deleted);
    }

    async fn assert_bucket_initial_lookup(repo: &Repo, user_id: Uuid, bucket: &Bucket) {
        let buckets = repo.list_buckets(user_id).await.expect("list");
        assert_eq!(buckets.len(), 1);
        let found = repo
            .get_bucket("bucket-one")
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(found.id, bucket.id);
    }

    async fn assert_bucket_updates_and_delete(repo: &Repo, bucket: &Bucket) {
        repo.update_bucket_notification(bucket.id, "<NotificationConfiguration/>")
            .await
            .expect("notification");
        repo.update_bucket_versioning(bucket.id, "enabled")
            .await
            .expect("versioning");
        repo.update_bucket_public(bucket.id, true)
            .await
            .expect("public");
        repo.update_bucket_name(bucket.id, "bucket-two")
            .await
            .expect("rename");
        let renamed = repo
            .get_bucket("bucket-two")
            .await
            .expect("get")
            .expect("exists");
        assert!(renamed.public_read);
        assert_eq!(renamed.versioning_status, "enabled");
        repo.delete_bucket("bucket-two").await.expect("delete");
        assert!(repo.get_bucket("bucket-two").await.expect("get").is_none());
    }

    #[tokio::test]
    async fn user_and_access_key_lifecycle() {
        let repo = setup_repo().await;
        let admin = assert_admin_creation_and_lookup(&repo).await;
        assert_admin_update_paths(&repo, admin.id).await;
        assert_access_key_lifecycle(&repo, admin.id).await;
    }

    #[tokio::test]
    async fn access_key_owner_scope() {
        let repo = setup_repo().await;
        assert_access_key_owner_scope(&repo).await;
    }

    #[tokio::test]
    async fn bucket_lifecycle() {
        let repo = setup_repo().await;
        let user = create_user(&repo, "bucket-user").await;
        let bucket = create_bucket(&repo, user.id, "bucket-one").await;
        assert_bucket_initial_lookup(&repo, user.id, &bucket).await;
        assert_bucket_updates_and_delete(&repo, &bucket).await;
    }

    async fn seed_object_chunks(repo: &Repo) -> [Uuid; 5] {
        let chunks = [
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        ];
        for chunk in chunks.iter().copied() {
            insert_chunk(repo, chunk).await;
        }
        chunks
    }

    async fn finalize_basic_version(
        repo: &Repo,
        bucket_id: Uuid,
        key: &str,
        version_id: &str,
        chunk_id: Uuid,
    ) -> ObjectVersion {
        repo.finalize_object_version(
            bucket_id,
            key,
            version_id,
            4,
            "etag",
            None,
            &json!({}),
            &json!({}),
            &[chunk_id],
            false,
        )
        .await
        .expect("version")
    }

    async fn seed_object_versions(repo: &Repo, bucket_id: Uuid, chunks: &[Uuid; 5]) {
        let _ = finalize_basic_version(repo, bucket_id, "alpha", "v1", chunks[0]).await;
        let _ = finalize_basic_version(repo, bucket_id, "alpha", "v2", chunks[1]).await;
        let _ = finalize_basic_version(repo, bucket_id, "beta", "b1", chunks[2]).await;
    }

    async fn assert_object_listing_paths(repo: &Repo, bucket_id: Uuid) {
        let all_current = repo
            .list_objects_current(bucket_id, None, None, 10)
            .await
            .expect("list");
        assert_eq!(all_current.len(), 2);
        assert_eq!(
            repo.list_objects_current(bucket_id, Some("al"), None, 10)
                .await
                .expect("list")
                .len(),
            1,
        );
        assert!(repo
            .list_objects_current(bucket_id, Some("zz"), None, 10)
            .await
            .expect("list")
            .is_empty());
        assert_eq!(
            repo.list_objects_current(bucket_id, None, Some("alpha"), 10)
                .await
                .expect("list")
                .len(),
            1,
        );
    }

    async fn assert_object_update_lookup_paths(repo: &Repo, bucket_id: Uuid) {
        assert_object_update_counts(repo, bucket_id).await;
        assert_object_current_lookup(repo, bucket_id, "alpha", true).await;
        assert_object_current_lookup(repo, bucket_id, "missing", false).await;
    }

    async fn assert_object_update_counts(repo: &Repo, bucket_id: Uuid) {
        assert_eq!(
            repo.update_object_metadata(bucket_id, "alpha", &json!({"hello": "world"}))
                .await
                .expect("update"),
            1,
        );
        assert_eq!(
            repo.update_object_metadata(bucket_id, "missing", &json!({}))
                .await
                .expect("update"),
            0,
        );
        assert_eq!(
            repo.rename_object_key(bucket_id, "beta", "beta2")
                .await
                .expect("rename"),
            1
        );
        assert_eq!(
            repo.rename_object_key(bucket_id, "missing", "x")
                .await
                .expect("rename"),
            0
        );
    }

    async fn assert_object_current_lookup(
        repo: &Repo,
        bucket_id: Uuid,
        key: &str,
        should_exist: bool,
    ) {
        let has_value = repo
            .get_object_current(bucket_id, key)
            .await
            .expect("current")
            .is_some();
        assert_eq!(has_value, should_exist);
    }

    async fn assert_object_version_lookups(repo: &Repo, bucket_id: Uuid) {
        assert!(repo
            .get_object_version(bucket_id, "alpha", "v1")
            .await
            .expect("version")
            .is_some());
        assert!(repo
            .get_object_version(bucket_id, "alpha", "nope")
            .await
            .expect("version")
            .is_none());
        assert!(!repo
            .list_object_versions(bucket_id, None, None, None, 10)
            .await
            .expect("versions")
            .is_empty());
        assert!(!repo
            .list_object_versions(bucket_id, None, Some("alpha"), Some("v2"), 10)
            .await
            .expect("versions")
            .is_empty());
        assert!(!repo
            .list_object_versions(bucket_id, None, Some("alpha"), Some("nope"), 10)
            .await
            .expect("versions")
            .is_empty());
    }

    async fn assert_manifest_and_deletes(repo: &Repo, bucket_id: Uuid, chunk_for_v3: Uuid) {
        let manifest_id = load_manifest_id(repo, bucket_id, "alpha", "v2").await;
        assert_manifest_has_chunks(repo, manifest_id).await;
        assert_missing_object_version_delete(repo, bucket_id, "alpha", "missing").await;
        let deleted_non_current = repo
            .delete_object_version(bucket_id, "alpha", "v1")
            .await
            .expect("delete");
        assert!(deleted_non_current.found);
        assert!(!deleted_non_current.was_current);
        let _ = finalize_basic_version(repo, bucket_id, "alpha", "v3", chunk_for_v3).await;
        assert_delete_marks_current(repo, bucket_id, "alpha", "v3").await;
        assert_delete_marks_current(repo, bucket_id, "alpha", "v2").await;
    }

    async fn load_manifest_id(repo: &Repo, bucket_id: Uuid, key: &str, version_id: &str) -> Uuid {
        let (_obj, manifest_id) = repo
            .get_object_version(bucket_id, key, version_id)
            .await
            .expect("version")
            .expect("exists");
        manifest_id
    }

    async fn assert_manifest_has_chunks(repo: &Repo, manifest_id: Uuid) {
        assert!(!repo
            .get_manifest_chunks(manifest_id)
            .await
            .expect("chunks")
            .is_empty());
    }

    async fn assert_missing_object_version_delete(
        repo: &Repo,
        bucket_id: Uuid,
        key: &str,
        version_id: &str,
    ) {
        let result = repo
            .delete_object_version(bucket_id, key, version_id)
            .await
            .expect("delete");
        assert!(!result.found);
    }

    async fn assert_delete_marks_current(
        repo: &Repo,
        bucket_id: Uuid,
        key: &str,
        version_id: &str,
    ) {
        assert!(
            repo.delete_object_version(bucket_id, key, version_id)
                .await
                .expect("delete")
                .was_current
        );
    }

    async fn assert_delete_other_and_all(repo: &Repo, bucket_id: Uuid, chunks: &[Uuid; 5]) {
        let _ = finalize_basic_version(repo, bucket_id, "gamma", "g1", chunks[4]).await;
        let _ = finalize_basic_version(repo, bucket_id, "gamma", "g2", chunks[0]).await;
        repo.delete_other_object_versions(bucket_id, "gamma", "g2")
            .await
            .expect("delete others");
        assert_eq!(
            repo.list_object_versions(bucket_id, Some("gamma"), None, None, 10)
                .await
                .expect("versions")
                .len(),
            1,
        );
        let _ = finalize_basic_version(repo, bucket_id, "delta", "d1", chunks[1]).await;
        let _ = finalize_basic_version(repo, bucket_id, "delta", "d2", chunks[2]).await;
        repo.delete_all_object_versions(bucket_id, "delta")
            .await
            .expect("delete all");
        assert!(repo
            .list_object_versions(bucket_id, Some("delta"), None, None, 10)
            .await
            .expect("versions")
            .is_empty());
    }

    #[tokio::test]
    async fn object_versions_and_listing_paths() {
        let repo = setup_repo().await;
        let user = create_user(&repo, "object-user").await;
        let bucket = create_bucket(&repo, user.id, "object-bucket").await;
        let chunks = seed_object_chunks(&repo).await;
        seed_object_versions(&repo, bucket.id, &chunks).await;
        assert_object_listing_paths(&repo, bucket.id).await;
        assert_object_update_lookup_paths(&repo, bucket.id).await;
        assert_object_version_lookups(&repo, bucket.id).await;
        assert_manifest_and_deletes(&repo, bucket.id, chunks[3]).await;
        assert_delete_other_and_all(&repo, bucket.id, &chunks).await;
    }

    async fn assert_multipart_listing_paths(repo: &Repo, bucket_id: Uuid) -> MultipartUpload {
        let upload = repo
            .create_multipart_upload(bucket_id, "big.bin", "upload-1")
            .await
            .expect("upload");
        let listed = repo
            .list_multipart_uploads(bucket_id)
            .await
            .expect("list uploads");
        assert_eq!(listed.len(), 1);
        assert!(repo
            .get_multipart_upload(&upload.upload_id)
            .await
            .expect("get")
            .is_some());
        upload
    }

    async fn assert_multipart_part_updates(repo: &Repo, upload_id: &str) {
        let chunk_part = Uuid::new_v4();
        insert_chunk(repo, chunk_part).await;
        let manifest_id = create_manifest(repo, 5, &[chunk_part]).await;
        repo.upsert_multipart_part(upload_id, 1, 5, "etag1", manifest_id)
            .await
            .expect("part");
        repo.upsert_multipart_part(upload_id, 1, 6, "etag2", manifest_id)
            .await
            .expect("part update");
        let parts = repo.list_multipart_parts(upload_id).await.expect("parts");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].etag, "etag2");
        repo.complete_multipart_upload(upload_id)
            .await
            .expect("complete");
    }

    async fn assert_abort_and_stale_paths(repo: &Repo, bucket_id: Uuid) {
        repo.create_multipart_upload(bucket_id, "other.bin", "upload-2")
            .await
            .expect("upload2");
        repo.abort_multipart_upload("upload-2")
            .await
            .expect("abort");
        let stale = repo
            .create_multipart_upload(bucket_id, "stale.bin", "upload-3")
            .await
            .expect("stale");
        let cutoff = stale.initiated_at + Duration::seconds(1);
        let stale_list = repo
            .list_stale_multipart_uploads(cutoff)
            .await
            .expect("stale list");
        assert!(stale_list.contains(&stale.upload_id));
    }

    async fn assert_cleanup_upload_path(repo: &Repo, bucket_id: Uuid) {
        let cleanup = repo
            .create_multipart_upload(bucket_id, "cleanup.bin", "upload-4")
            .await
            .expect("cleanup");
        let cleanup_chunk = Uuid::new_v4();
        insert_chunk(repo, cleanup_chunk).await;
        let cleanup_manifest = create_manifest(repo, 4, &[cleanup_chunk]).await;
        repo.upsert_multipart_part(&cleanup.upload_id, 1, 4, "etag3", cleanup_manifest)
            .await
            .expect("cleanup part");
        repo.cleanup_multipart_upload(&cleanup.upload_id)
            .await
            .expect("cleanup");
        assert!(repo
            .list_multipart_parts(&cleanup.upload_id)
            .await
            .expect("parts")
            .is_empty());
    }

    #[tokio::test]
    async fn multipart_cleanup_paths_minimal() {
        let repo = setup_repo().await;
        let user = create_user(&repo, "multipart-user").await;
        let bucket = create_bucket(&repo, user.id, "multipart-bucket").await;
        let upload = assert_multipart_listing_paths(&repo, bucket.id).await;
        assert_multipart_part_updates(&repo, &upload.upload_id).await;
        assert_abort_and_stale_paths(&repo, bucket.id).await;
        assert_cleanup_upload_path(&repo, bucket.id).await;
    }

    async fn setup_node(repo: &Repo) -> Node {
        let node_id = Uuid::new_v4();
        let node = repo
            .upsert_node(
                node_id,
                "master",
                "http://localhost:1000",
                "online",
                Some(100),
                Some(50),
                None,
            )
            .await
            .expect("node");
        let _ = repo
            .upsert_node(
                node_id,
                "master",
                "http://localhost:1000",
                "online",
                Some(200),
                Some(100),
                Some(Utc::now()),
            )
            .await
            .expect("node");
        node
    }

    async fn assert_node_lookup_paths(repo: &Repo, node: &Node) {
        assert_eq!(repo.list_nodes().await.expect("nodes").len(), 1);
        assert!(repo
            .get_node_by_address(&node.address_internal)
            .await
            .expect("get")
            .is_some());
        assert!(repo
            .get_node_by_address("http://localhost:9999")
            .await
            .expect("get")
            .is_none());
    }

    async fn assert_chunk_replica_and_checksum_paths(repo: &Repo, node_id: Uuid) -> Uuid {
        repo.update_node_heartbeat(node_id, Some(80), Some(40))
            .await
            .expect("heartbeat");
        let chunk_id = Uuid::new_v4();
        insert_chunk(repo, chunk_id).await;
        repo.insert_chunk_replica(chunk_id, node_id, "present")
            .await
            .expect("replica");
        repo.update_chunk_replica_state(chunk_id, node_id, "repair")
            .await
            .expect("replica");
        assert_chunk_replica_count(repo, chunk_id, 1).await;
        assert_eq!(repo.list_chunk_ids(10).await.expect("chunks").len(), 1);
        assert_chunk_checksum_presence(repo, chunk_id, true).await;
        assert_chunk_checksum_presence(repo, Uuid::new_v4(), false).await;
        chunk_id
    }

    async fn assert_chunk_replica_count(repo: &Repo, chunk_id: Uuid, expected: usize) {
        assert_eq!(
            repo.list_chunk_replicas_with_nodes(chunk_id)
                .await
                .expect("replicas")
                .len(),
            expected,
        );
    }

    async fn assert_chunk_checksum_presence(repo: &Repo, chunk_id: Uuid, should_exist: bool) {
        let has_checksum = repo
            .get_chunk_checksum(chunk_id)
            .await
            .expect("checksum")
            .is_some();
        assert_eq!(has_checksum, should_exist);
    }

    async fn assert_chunk_orphan_cleanup_paths(repo: &Repo, chunk_id: Uuid) {
        assert!(repo
            .list_orphan_chunk_ids(10)
            .await
            .expect("orphans")
            .contains(&chunk_id));
        let manifest_id = create_manifest(repo, 4, &[chunk_id]).await;
        let orphan_manifests = repo.list_orphan_manifest_ids(10).await.expect("orphans");
        assert!(orphan_manifests.contains(&manifest_id));
        repo.delete_manifest(manifest_id)
            .await
            .expect("delete manifest");
        repo.delete_chunk_metadata(chunk_id)
            .await
            .expect("delete chunk");
        assert!(repo.list_chunk_ids(10).await.expect("chunks").is_empty());
    }

    async fn assert_chunk_paths_for_node(repo: &Repo, node_id: Uuid) {
        let chunk_id = assert_chunk_replica_and_checksum_paths(repo, node_id).await;
        assert_chunk_orphan_cleanup_paths(repo, chunk_id).await;
    }

    #[tokio::test]
    async fn chunk_and_node_paths() {
        let repo = setup_repo().await;
        let node = setup_node(&repo).await;
        assert_node_lookup_paths(&repo, &node).await;
        assert_chunk_paths_for_node(&repo, node.node_id).await;
    }

    async fn assert_join_token_paths(repo: &Repo, now: DateTime<Utc>) {
        let token = repo
            .create_join_token("token-hash", now + Duration::seconds(60))
            .await
            .expect("token");
        assert!(repo
            .consume_join_token(&token.token_hash, now)
            .await
            .expect("consume")
            .is_some());
        assert!(repo
            .consume_join_token(&token.token_hash, now + Duration::seconds(1))
            .await
            .expect("consume")
            .is_none());
        let expired = repo
            .create_join_token("expired-hash", now - Duration::seconds(5))
            .await
            .expect("token");
        assert!(repo
            .consume_join_token(&expired.token_hash, now)
            .await
            .expect("consume")
            .is_none());
        assert!(repo
            .consume_join_token("missing", now)
            .await
            .expect("consume")
            .is_none());
    }

    async fn assert_audit_log_paths(repo: &Repo, now: DateTime<Utc>) {
        let user = create_user(repo, "audit-user").await;
        insert_primary_audit_log(repo, user.id).await;
        assert_filtered_audit_log_paths(repo, user.id, now).await;
        assert_audit_log_pagination(repo).await;
    }

    async fn insert_primary_audit_log(repo: &Repo, user_id: Uuid) {
        repo.insert_audit_log(
            Some(user_id),
            Some("127.0.0.1"),
            "action",
            Some("bucket"),
            Some("id"),
            "ok",
            &json!({"detail": "value"}),
        )
        .await
        .expect("audit");
    }

    async fn assert_filtered_audit_log_paths(repo: &Repo, user_id: Uuid, now: DateTime<Utc>) {
        let logs = repo
            .list_audit_logs(
                Some(now - Duration::seconds(1)),
                Some(now + Duration::seconds(1)),
                Some(user_id),
                Some("action"),
                0,
                200,
            )
            .await
            .expect("logs");
        assert!(!logs.is_empty());
        assert!(!repo
            .list_audit_logs(None, None, None, None, 0, 200)
            .await
            .expect("logs")
            .is_empty());
    }

    async fn assert_audit_log_pagination(repo: &Repo) {
        repo.insert_audit_log(None, None, "action-2", None, None, "ok", &json!({}))
            .await
            .expect("audit");
        let page_one = repo
            .list_audit_logs(None, None, None, None, 0, 1)
            .await
            .expect("page one");
        let page_two = repo
            .list_audit_logs(None, None, None, None, 1, 1)
            .await
            .expect("page two");
        assert_eq!(page_one.len(), 1);
        assert_eq!(page_two.len(), 1);
        assert_ne!(page_one[0].id, page_two[0].id);
    }

    #[tokio::test]
    async fn join_tokens_and_audit_logs() {
        let repo = setup_repo().await;
        let now = Utc::now();
        assert_join_token_paths(&repo, now).await;
        assert_audit_log_paths(&repo, now).await;
    }

    async fn seed_object_metadata_versions(repo: &Repo, bucket_id: Uuid, chunk_id: Uuid) {
        let _ = finalize_basic_version(repo, bucket_id, "obj", "v1", chunk_id).await;
        let _ = finalize_basic_version(repo, bucket_id, "obj", "v2", chunk_id).await;
    }

    async fn assert_object_metadata_paths(repo: &Repo, bucket_id: Uuid) {
        assert!(repo
            .get_object_current(bucket_id, "obj")
            .await
            .expect("current")
            .is_some());
        assert!(repo
            .get_object_version(bucket_id, "obj", "v1")
            .await
            .expect("version")
            .is_some());
        assert!(!repo
            .list_object_versions(bucket_id, Some("obj"), Some("obj"), Some("v2"), 10)
            .await
            .expect("list")
            .is_empty());
        assert_eq!(
            repo.update_object_metadata(bucket_id, "obj", &json!({"updated": "yes"}))
                .await
                .expect("update metadata"),
            1,
        );
        assert!(
            repo.rename_object_key(bucket_id, "obj", "obj-renamed")
                .await
                .expect("rename")
                > 0
        );
    }

    async fn assert_object_version_cleanup(repo: &Repo, bucket_id: Uuid) {
        let deleted = repo
            .delete_object_version(bucket_id, "obj-renamed", "v2")
            .await
            .expect("delete");
        assert!(deleted.found);
        assert!(deleted.was_current);
        repo.delete_other_object_versions(bucket_id, "obj-renamed", "v1")
            .await
            .expect("delete others");
        repo.delete_all_object_versions(bucket_id, "obj-renamed")
            .await
            .expect("delete all");
    }

    #[tokio::test]
    async fn object_metadata_and_version_paths() {
        let repo = setup_repo().await;
        let user = create_user(&repo, "meta-object-user").await;
        let bucket = create_bucket(&repo, user.id, "meta-object-bucket").await;
        let chunk_id = Uuid::new_v4();
        insert_chunk(&repo, chunk_id).await;
        seed_object_metadata_versions(&repo, bucket.id, chunk_id).await;
        assert_object_metadata_paths(&repo, bucket.id).await;
        assert_object_version_cleanup(&repo, bucket.id).await;
    }

    async fn assert_multipart_complete_abort(repo: &Repo, bucket_id: Uuid, manifest_id: Uuid) {
        let upload = repo
            .create_multipart_upload(bucket_id, "object", "upload-1")
            .await
            .expect("upload");
        repo.upsert_multipart_part(&upload.upload_id, 1, 4, "etag", manifest_id)
            .await
            .expect("part");
        assert_eq!(
            repo.list_multipart_parts(&upload.upload_id)
                .await
                .expect("parts")
                .len(),
            1,
        );
        repo.complete_multipart_upload(&upload.upload_id)
            .await
            .expect("complete");
        repo.abort_multipart_upload(&upload.upload_id)
            .await
            .expect("abort");
    }

    async fn assert_multipart_cleanup(repo: &Repo, bucket_id: Uuid, chunk_id: Uuid) {
        let upload = repo
            .create_multipart_upload(bucket_id, "object", "upload-2")
            .await
            .expect("upload");
        let manifest_id = create_manifest(repo, 4, &[chunk_id]).await;
        repo.upsert_multipart_part(&upload.upload_id, 1, 4, "etag", manifest_id)
            .await
            .expect("part");
        repo.cleanup_multipart_upload(&upload.upload_id)
            .await
            .expect("cleanup");
    }

    #[tokio::test]
    async fn multipart_and_cleanup_paths() {
        let repo = setup_repo().await;
        let user = create_user(&repo, "meta-multipart-user").await;
        let bucket = create_bucket(&repo, user.id, "multipart-bucket").await;
        let chunk_id = Uuid::new_v4();
        insert_chunk(&repo, chunk_id).await;
        let manifest_id = create_manifest(&repo, 4, &[chunk_id]).await;
        assert_multipart_complete_abort(&repo, bucket.id, manifest_id).await;
        assert_multipart_cleanup(&repo, bucket.id, chunk_id).await;
    }

    async fn setup_meta_audit_node(repo: &Repo) -> Node {
        let node = repo
            .upsert_node(
                Uuid::new_v4(),
                "master",
                "http://node",
                "online",
                Some(10),
                Some(5),
                Some(Utc::now()),
            )
            .await
            .expect("node");
        repo.update_node_heartbeat(node.node_id, Some(9), Some(4))
            .await
            .expect("heartbeat");
        node
    }

    async fn assert_meta_audit_log(repo: &Repo, user_id: Uuid) {
        repo.insert_audit_log(
            Some(user_id),
            Some("127.0.0.1"),
            "meta.action",
            Some("bucket"),
            Some("id"),
            "ok",
            &json!({}),
        )
        .await
        .expect("audit");
        let logs = repo
            .list_audit_logs(None, None, Some(user_id), Some("meta.action"), 0, 200)
            .await
            .expect("logs");
        assert!(!logs.is_empty());
    }

    async fn assert_chunk_replica_audit_paths(repo: &Repo, user_id: Uuid, node_id: Uuid) {
        let chunk_id = Uuid::new_v4();
        repo.insert_chunk_metadata(chunk_id, 4, "crc32c", &[1, 2, 3, 4])
            .await
            .expect("chunk");
        assert!(repo
            .get_chunk_checksum(chunk_id)
            .await
            .expect("checksum")
            .is_some());
        repo.insert_chunk_replica(chunk_id, node_id, "present")
            .await
            .expect("replica");
        repo.update_chunk_replica_state(chunk_id, node_id, "missing")
            .await
            .expect("update");
        repo.delete_chunk_metadata(chunk_id).await.expect("delete");
        assert_meta_audit_log(repo, user_id).await;
    }

    #[tokio::test]
    async fn chunk_replica_and_audit_paths() {
        let repo = setup_repo().await;
        let user = create_user(&repo, "meta-audit-user").await;
        let node = setup_meta_audit_node(&repo).await;
        assert_chunk_replica_audit_paths(&repo, user.id, node.node_id).await;
    }

    #[tokio::test]
    async fn consume_join_token_paths() {
        let repo = setup_repo().await;
        let token_hash = "hash";
        let expires_at = Utc::now() + Duration::minutes(10);
        let token = repo
            .create_join_token(token_hash, expires_at)
            .await
            .expect("token");
        let consumed = repo
            .consume_join_token(token_hash, Utc::now())
            .await
            .expect("consume");
        assert_eq!(consumed.as_ref().map(|t| t.token_id), Some(token.token_id));

        let consumed = repo
            .consume_join_token(token_hash, Utc::now())
            .await
            .expect("consume");
        assert!(consumed.is_none());

        let replacement = repo
            .create_join_token(token_hash, Utc::now() + Duration::minutes(10))
            .await
            .expect("token");
        let consumed = repo
            .consume_join_token(token_hash, Utc::now())
            .await
            .expect("consume");
        assert_eq!(
            consumed.as_ref().map(|row| row.token_id),
            Some(replacement.token_id)
        );

        let expired_hash = "expired";
        repo.create_join_token(expired_hash, Utc::now() - Duration::minutes(1))
            .await
            .expect("token");
        let consumed = repo
            .consume_join_token(expired_hash, Utc::now())
            .await
            .expect("consume");
        assert!(consumed.is_none());
    }

    #[tokio::test]
    async fn touch_access_key_usage_reports_error() {
        let repo = test_support::broken_repo();
        let err = repo.touch_access_key_usage("missing").await.unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[tokio::test]
    async fn create_manifest_error_paths() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();

        let mut tx = repo.pool().begin().await.expect("tx");
        let guard = TableRenameGuard::rename(&pool, "manifests")
            .await
            .expect("rename");
        let err = repo
            .create_manifest(&mut tx, 4, &[Uuid::new_v4()])
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        let _ = tx.rollback().await;
        guard.restore().await.expect("restore");

        test_support::reset_db(&pool).await;
        let mut tx = repo.pool().begin().await.expect("tx");
        let guard = FailTriggerGuard::create(&pool, "manifest_chunks", "AFTER", "INSERT")
            .await
            .expect("guard");
        let err = repo
            .create_manifest(&mut tx, 4, &[Uuid::new_v4()])
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        let _ = tx.rollback().await;
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn finalize_object_version_reports_begin_error() {
        let repo = test_support::broken_repo();
        let err = repo
            .finalize_object_version(
                Uuid::new_v4(),
                "key",
                "v1",
                1,
                "etag",
                None,
                &json!({}),
                &json!({}),
                &[],
                false,
            )
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    async fn expect_finalize_object_version_error(repo: &Repo, bucket_id: Uuid, chunk_id: Uuid) {
        let err = repo
            .finalize_object_version(
                bucket_id,
                "alpha",
                "v1",
                4,
                "etag",
                None,
                &json!({}),
                &json!({}),
                &[chunk_id],
                false,
            )
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    async fn expect_finalize_error_with_rename(
        repo: &Repo,
        pool: &PgPool,
        bucket_name: &str,
        table: &str,
    ) {
        test_support::reset_db(pool).await;
        let (bucket, chunk_id) = setup_bucket_with_chunk(repo, bucket_name).await;
        let guard = TableRenameGuard::rename(pool, table).await.expect("rename");
        expect_finalize_object_version_error(repo, bucket.id, chunk_id).await;
        guard.restore().await.expect("restore");
    }

    async fn expect_finalize_error_with_trigger(
        repo: &Repo,
        pool: &PgPool,
        bucket_name: &str,
        table: &str,
        deferred: bool,
    ) {
        test_support::reset_db(pool).await;
        let (bucket, chunk_id) = setup_bucket_with_chunk(repo, bucket_name).await;
        let guard = if deferred {
            FailTriggerGuard::create_deferred(pool, table, "AFTER", "INSERT")
                .await
                .expect("guard")
        } else {
            FailTriggerGuard::create(pool, table, "AFTER", "INSERT")
                .await
                .expect("guard")
        };
        expect_finalize_object_version_error(repo, bucket.id, chunk_id).await;
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn finalize_object_version_error_paths() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();
        expect_finalize_error_with_rename(&repo, &pool, "finalize-update", "object_versions").await;
        for (bucket_name, table, deferred) in finalize_error_trigger_cases() {
            expect_finalize_error_with_trigger(&repo, &pool, bucket_name, table, deferred).await;
        }
    }

    fn finalize_error_trigger_cases() -> [(&'static str, &'static str, bool); 4] {
        [
            ("finalize-insert", "object_versions", false),
            ("finalize-manifest", "manifest_chunks", false),
            ("finalize-link", "object_version_manifests", false),
            ("finalize-commit", "object_versions", true),
        ]
    }

    async fn expect_object_current_lookup_error(repo: &Repo, pool: &PgPool, bucket_id: Uuid) {
        let guard = TableRenameGuard::rename(pool, "object_version_manifests")
            .await
            .expect("rename");
        let err = repo
            .get_object_current(bucket_id, "alpha")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.restore().await.expect("restore");
    }

    async fn expect_object_version_lookup_error(
        repo: &Repo,
        pool: &PgPool,
        bucket_id: Uuid,
        table: &str,
    ) {
        let guard = TableRenameGuard::rename(pool, table).await.expect("rename");
        let err = repo
            .get_object_version(bucket_id, "alpha", "v1")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.restore().await.expect("restore");
    }

    async fn expect_list_versions_lookup_error(repo: &Repo, pool: &PgPool, bucket_id: Uuid) {
        let guard = TableRenameGuard::rename(pool, "object_versions")
            .await
            .expect("rename");
        let err = repo
            .list_object_versions(bucket_id, None, Some("alpha"), Some("v1"), 10)
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.restore().await.expect("restore");
    }

    async fn create_latest_current_fail_trigger(pool: &PgPool) -> (String, String) {
        let fn_name = format!("nss_fail_current_true_{}", Uuid::new_v4().simple());
        let trigger_name = format!("nss_fail_current_true_{}", Uuid::new_v4().simple());
        let create_fn = format!(
            concat!(
                "CREATE OR REPLACE FUNCTION {}() RETURNS trigger AS $$ BEGIN IF NEW.current ",
                "THEN RAISE EXCEPTION 'failpoint'; END IF; RETURN NEW; END; $$ LANGUAGE plpgsql;"
            ),
            fn_name
        );
        sqlx::query(&create_fn).execute(pool).await.expect("fn");
        let create_trigger = format!(
            "CREATE TRIGGER {} AFTER UPDATE ON object_versions FOR EACH ROW EXECUTE FUNCTION {}();",
            trigger_name, fn_name
        );
        sqlx::query(&create_trigger)
            .execute(pool)
            .await
            .expect("trigger");
        (fn_name, trigger_name)
    }

    async fn drop_latest_current_fail_trigger(pool: &PgPool, fn_name: &str, trigger_name: &str) {
        let drop_trigger = format!("DROP TRIGGER IF EXISTS {} ON object_versions", trigger_name);
        sqlx::query(&drop_trigger)
            .execute(pool)
            .await
            .expect("drop trigger");
        let drop_fn = format!("DROP FUNCTION IF EXISTS {}()", fn_name);
        sqlx::query(&drop_fn).execute(pool).await.expect("drop fn");
    }

    #[tokio::test]
    async fn object_lookup_error_paths() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();
        let (bucket, chunk_id) = setup_bucket_with_chunk(&repo, "lookup-errors").await;
        let _ = create_version(&repo, &bucket, "alpha", "v1", chunk_id).await;
        expect_object_current_lookup_error(&repo, &pool, bucket.id).await;
        expect_object_version_lookup_error(&repo, &pool, bucket.id, "object_versions").await;
        expect_object_version_lookup_error(&repo, &pool, bucket.id, "object_version_manifests")
            .await;
        expect_list_versions_lookup_error(&repo, &pool, bucket.id).await;
    }

    #[tokio::test]
    async fn delete_object_version_reports_query_error() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();
        let guard = TableRenameGuard::rename(&pool, "object_versions")
            .await
            .expect("rename");
        let err = repo
            .delete_object_version(Uuid::new_v4(), "alpha", "v1")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.restore().await.expect("restore");
    }

    #[tokio::test]
    async fn delete_object_version_reports_manifest_lookup_error() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();
        let (bucket, chunk_id) = setup_bucket_with_chunk(&repo, "delete-lookup").await;
        let _ = create_version(&repo, &bucket, "alpha", "v1", chunk_id).await;
        let guard = TableRenameGuard::rename(&pool, "object_version_manifests")
            .await
            .expect("rename");
        let err = repo
            .delete_object_version(bucket.id, "alpha", "v1")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.restore().await.expect("restore");
    }

    #[tokio::test]
    async fn delete_object_version_reports_manifest_link_delete_error() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();
        let (bucket, chunk_id) = setup_bucket_with_chunk(&repo, "delete-link").await;
        let _ = create_version(&repo, &bucket, "alpha", "v1", chunk_id).await;
        let guard = FailTriggerGuard::create(&pool, "object_version_manifests", "AFTER", "DELETE")
            .await
            .expect("guard");
        let err = repo
            .delete_object_version(bucket.id, "alpha", "v1")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn delete_object_version_reports_manifest_chunks_delete_error() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();
        let (bucket, chunk_id) = setup_bucket_with_chunk(&repo, "delete-chunks").await;
        let _ = create_version(&repo, &bucket, "alpha", "v1", chunk_id).await;
        let guard = FailTriggerGuard::create(&pool, "manifest_chunks", "AFTER", "DELETE")
            .await
            .expect("guard");
        let err = repo
            .delete_object_version(bucket.id, "alpha", "v1")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn delete_object_version_reports_manifest_delete_error() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();
        let (bucket, chunk_id) = setup_bucket_with_chunk(&repo, "delete-manifest").await;
        let _ = create_version(&repo, &bucket, "alpha", "v1", chunk_id).await;
        let guard = FailTriggerGuard::create(&pool, "manifests", "AFTER", "DELETE")
            .await
            .expect("guard");
        let err = repo
            .delete_object_version(bucket.id, "alpha", "v1")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn delete_object_version_reports_object_delete_error() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();
        let (bucket, chunk_id) = setup_bucket_with_chunk(&repo, "delete-object").await;
        let _ = create_version(&repo, &bucket, "alpha", "v1", chunk_id).await;
        let guard = FailTriggerGuard::create(&pool, "object_versions", "AFTER", "DELETE")
            .await
            .expect("guard");
        let err = repo
            .delete_object_version(bucket.id, "alpha", "v1")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn delete_object_version_reports_current_update_error() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();
        let (bucket, chunk_id) = setup_bucket_with_chunk(&repo, "delete-update").await;
        let _ = create_version(&repo, &bucket, "alpha", "v1", chunk_id).await;
        let _ = create_version(&repo, &bucket, "alpha", "v2", chunk_id).await;
        let guard = FailTriggerGuard::create(&pool, "object_versions", "AFTER", "UPDATE")
            .await
            .expect("guard");
        let err = repo
            .delete_object_version(bucket.id, "alpha", "v2")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn delete_object_version_reports_latest_update_error() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();
        let (bucket, chunk_id) = setup_bucket_with_chunk(&repo, "delete-latest").await;
        let _ = create_version(&repo, &bucket, "alpha", "v1", chunk_id).await;
        let _ = create_version(&repo, &bucket, "alpha", "v2", chunk_id).await;
        let (fn_name, trigger_name) = create_latest_current_fail_trigger(&pool).await;
        let err = repo
            .delete_object_version(bucket.id, "alpha", "v2")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        drop_latest_current_fail_trigger(&pool, &fn_name, &trigger_name).await;
    }

    #[tokio::test]
    async fn delete_object_version_reports_latest_fetch_error() {
        let repo = setup_repo().await;
        let (bucket, chunk_id) = setup_bucket_with_chunk(&repo, "delete-latest-fetch").await;
        let _ = create_version(&repo, &bucket, "alpha", "v1", chunk_id).await;
        let _ = create_version(&repo, &bucket, "alpha", "v2", chunk_id).await;
        let _guard = delete_version_latest_fetch_error_guard();
        let err = repo
            .delete_object_version(bucket.id, "alpha", "v2")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[tokio::test]
    async fn delete_object_version_reports_commit_error() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();
        let (bucket, chunk_id) = setup_bucket_with_chunk(&repo, "delete-commit").await;
        let _ = create_version(&repo, &bucket, "alpha", "v1", chunk_id).await;
        let guard = FailTriggerGuard::create_deferred(&pool, "object_versions", "AFTER", "DELETE")
            .await
            .expect("guard");
        let err = repo
            .delete_object_version(bucket.id, "alpha", "v1")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn delete_other_object_versions_error_paths() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();

        let guard = TableRenameGuard::rename(&pool, "object_versions")
            .await
            .expect("rename");
        let err = repo
            .delete_other_object_versions(Uuid::new_v4(), "alpha", "v1")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.restore().await.expect("restore");

        test_support::reset_db(&pool).await;
        let (bucket, chunk_id) = setup_bucket_with_chunk(&repo, "delete-other").await;
        let _ = create_version(&repo, &bucket, "alpha", "v1", chunk_id).await;
        let _ = create_version(&repo, &bucket, "alpha", "v2", chunk_id).await;
        let guard = FailTriggerGuard::create(&pool, "object_versions", "AFTER", "DELETE")
            .await
            .expect("guard");
        let err = repo
            .delete_other_object_versions(bucket.id, "alpha", "v2")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn delete_all_object_versions_error_paths() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();

        let guard = TableRenameGuard::rename(&pool, "object_versions")
            .await
            .expect("rename");
        let err = repo
            .delete_all_object_versions(Uuid::new_v4(), "alpha")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.restore().await.expect("restore");

        test_support::reset_db(&pool).await;
        let (bucket, chunk_id) = setup_bucket_with_chunk(&repo, "delete-all").await;
        let _ = create_version(&repo, &bucket, "alpha", "v1", chunk_id).await;
        let guard = FailTriggerGuard::create(&pool, "object_versions", "AFTER", "DELETE")
            .await
            .expect("guard");
        let err = repo
            .delete_all_object_versions(bucket.id, "alpha")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn upsert_multipart_part_reports_error() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();
        let (bucket, chunk_id) = setup_bucket_with_chunk(&repo, "multipart-error").await;
        let upload = repo
            .create_multipart_upload(bucket.id, "object", "upload-err")
            .await
            .expect("upload");
        let manifest_id = create_manifest(&repo, 4, &[chunk_id]).await;
        let guard = FailTriggerGuard::create(&pool, "multipart_parts", "AFTER", "INSERT")
            .await
            .expect("guard");
        let err = repo
            .upsert_multipart_part(&upload.upload_id, 1, 4, "etag", manifest_id)
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn complete_multipart_upload_reports_error() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();
        let (bucket, _chunk_id) = setup_bucket_with_chunk(&repo, "multipart-complete").await;
        let upload = repo
            .create_multipart_upload(bucket.id, "object", "upload-complete")
            .await
            .expect("upload");
        let guard = TableRenameGuard::rename(&pool, "multipart_uploads")
            .await
            .expect("rename");
        let err = repo
            .complete_multipart_upload(&upload.upload_id)
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.restore().await.expect("restore");
    }

    async fn assert_cleanup_broken_repo_error() {
        let broken = test_support::broken_repo();
        let err = broken.cleanup_multipart_upload("upload").await.unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    async fn assert_cleanup_query_error(repo: &Repo, pool: &PgPool) {
        test_support::reset_db(pool).await;
        let (bucket, _chunk_id) = setup_bucket_with_chunk(repo, "cleanup-query").await;
        let upload = repo
            .create_multipart_upload(bucket.id, "object", "upload-1")
            .await
            .expect("upload");
        let guard = TableRenameGuard::rename(pool, "multipart_parts")
            .await
            .expect("rename");
        let err = repo
            .cleanup_multipart_upload(&upload.upload_id)
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.restore().await.expect("restore");
    }

    async fn assert_cleanup_trigger_error(
        repo: &Repo,
        pool: &PgPool,
        bucket_name: &str,
        upload_id: &str,
        table: &str,
        op: &str,
        deferred: bool,
    ) {
        test_support::reset_db(pool).await;
        let (bucket, _chunk_id) = setup_bucket_with_chunk(repo, bucket_name).await;
        let _manifest_id = setup_upload_with_part(repo, &bucket, upload_id).await;
        let guard = if deferred {
            FailTriggerGuard::create_deferred(pool, table, "AFTER", op)
                .await
                .expect("guard")
        } else {
            FailTriggerGuard::create(pool, table, "AFTER", op)
                .await
                .expect("guard")
        };
        let err = repo.cleanup_multipart_upload(upload_id).await.unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn cleanup_multipart_upload_error_paths() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();
        assert_cleanup_broken_repo_error().await;
        assert_cleanup_query_error(&repo, &pool).await;
        for (bucket_name, upload_id, table, op, deferred) in CLEANUP_TRIGGER_CASES {
            assert_cleanup_trigger_error(&repo, &pool, bucket_name, upload_id, table, op, deferred)
                .await;
        }
    }

    const CLEANUP_TRIGGER_CASES: [(&str, &str, &str, &str, bool); 5] = [
        (
            "cleanup-delete",
            "upload-2",
            "multipart_parts",
            "DELETE",
            false,
        ),
        (
            "cleanup-chunks",
            "upload-3",
            "manifest_chunks",
            "DELETE",
            false,
        ),
        (
            "cleanup-manifests",
            "upload-4",
            "manifests",
            "DELETE",
            false,
        ),
        (
            "cleanup-update",
            "upload-5",
            "multipart_uploads",
            "UPDATE",
            false,
        ),
        (
            "cleanup-commit",
            "upload-6",
            "multipart_uploads",
            "UPDATE",
            true,
        ),
    ];

    async fn assert_delete_manifest_broken_repo_error() {
        let broken = test_support::broken_repo();
        let err = broken.delete_manifest(Uuid::new_v4()).await.unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    async fn assert_delete_manifest_trigger_error(
        repo: &Repo,
        pool: &PgPool,
        bucket_name: &str,
        table: &str,
        deferred: bool,
    ) {
        test_support::reset_db(pool).await;
        let (_bucket, chunk_id) = setup_bucket_with_chunk(repo, bucket_name).await;
        let manifest_id = create_manifest(repo, 4, &[chunk_id]).await;
        let guard = if deferred {
            FailTriggerGuard::create_deferred(pool, table, "AFTER", "DELETE")
                .await
                .expect("guard")
        } else {
            FailTriggerGuard::create(pool, table, "AFTER", "DELETE")
                .await
                .expect("guard")
        };
        let err = repo.delete_manifest(manifest_id).await.unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn delete_manifest_error_paths() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();
        assert_delete_manifest_broken_repo_error().await;
        assert_delete_manifest_trigger_error(
            &repo,
            &pool,
            "delete-manifest-chunk",
            "manifest_chunks",
            false,
        )
        .await;
        assert_delete_manifest_trigger_error(&repo, &pool, "delete-manifest", "manifests", false)
            .await;
        assert_delete_manifest_trigger_error(
            &repo,
            &pool,
            "delete-manifest-commit",
            "manifests",
            true,
        )
        .await;
    }

    async fn assert_delete_chunk_broken_repo_error() {
        let broken = test_support::broken_repo();
        let err = broken
            .delete_chunk_metadata(Uuid::new_v4())
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    async fn assert_delete_chunk_replica_trigger_error(repo: &Repo, pool: &PgPool) {
        test_support::reset_db(pool).await;
        let (_bucket, chunk_id) = setup_bucket_with_chunk(repo, "delete-chunk-replicas").await;
        let node_id = Uuid::new_v4();
        repo.upsert_node(
            node_id,
            "replica",
            "http://node",
            "online",
            None,
            None,
            None,
        )
        .await
        .expect("node");
        repo.insert_chunk_replica(chunk_id, node_id, "present")
            .await
            .expect("replica");
        let guard = FailTriggerGuard::create(pool, "chunk_replicas", "AFTER", "DELETE")
            .await
            .expect("guard");
        let err = repo.delete_chunk_metadata(chunk_id).await.unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.remove().await.expect("remove");
    }

    async fn assert_delete_chunk_trigger_error(
        repo: &Repo,
        pool: &PgPool,
        bucket_name: &str,
        deferred: bool,
    ) {
        test_support::reset_db(pool).await;
        let (_bucket, chunk_id) = setup_bucket_with_chunk(repo, bucket_name).await;
        let guard = if deferred {
            FailTriggerGuard::create_deferred(pool, "chunks", "AFTER", "DELETE")
                .await
                .expect("guard")
        } else {
            FailTriggerGuard::create(pool, "chunks", "AFTER", "DELETE")
                .await
                .expect("guard")
        };
        let err = repo.delete_chunk_metadata(chunk_id).await.unwrap_err();
        assert!(!err.to_string().is_empty());
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn delete_chunk_metadata_error_paths() {
        let repo = setup_repo().await;
        let pool = repo.pool().clone();
        assert_delete_chunk_broken_repo_error().await;
        assert_delete_chunk_replica_trigger_error(&repo, &pool).await;
        assert_delete_chunk_trigger_error(&repo, &pool, "delete-chunk", false).await;
        assert_delete_chunk_trigger_error(&repo, &pool, "delete-chunk-commit", true).await;
    }

    #[tokio::test]
    async fn update_chunk_replica_state_reports_error() {
        let repo = test_support::broken_repo();
        let err = repo
            .update_chunk_replica_state(Uuid::new_v4(), Uuid::new_v4(), "missing")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[tokio::test]
    async fn delete_object_version_updates_latest_current() {
        let repo = setup_repo().await;
        let (bucket, chunk_id) = setup_bucket_with_chunk(&repo, "delete-latest-current").await;
        let first = create_version(&repo, &bucket, "alpha", "v1", chunk_id).await;
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        let _second = create_version(&repo, &bucket, "alpha", "v2", chunk_id).await;
        let result = repo
            .delete_object_version(bucket.id, "alpha", "v2")
            .await
            .expect("delete");
        assert!(result.found);
        assert!(result.was_current);
        let current = repo
            .get_object_current(bucket.id, "alpha")
            .await
            .expect("current")
            .expect("current");
        assert_eq!(current.0.version_id, first.version_id);
    }

    #[tokio::test]
    async fn delete_object_version_handles_missing_latest() {
        let repo = setup_repo().await;
        let (bucket, chunk_id) = setup_bucket_with_chunk(&repo, "delete-single-current").await;
        let version = create_version(&repo, &bucket, "alpha", "v1", chunk_id).await;
        let result = repo
            .delete_object_version(bucket.id, "alpha", &version.version_id)
            .await
            .expect("delete");
        assert!(result.found);
        assert!(result.was_current);
        let current = repo
            .get_object_current(bucket.id, "alpha")
            .await
            .expect("current");
        assert!(current.is_none());
    }

    #[tokio::test]
    async fn get_chunk_checksum_returns_value() {
        let repo = setup_repo().await;
        let (_bucket, chunk_id) = setup_bucket_with_chunk(&repo, "checksum-present").await;
        let checksum = repo.get_chunk_checksum(chunk_id).await.expect("checksum");
        assert!(checksum.is_some());
    }

    #[tokio::test]
    async fn get_chunk_checksum_reports_algo_error() {
        let repo = setup_repo().await;
        let (_bucket, chunk_id) = setup_bucket_with_chunk(&repo, "checksum-algo-error").await;
        let _guard = checksum_algo_error_guard();
        let err = repo.get_chunk_checksum(chunk_id).await.unwrap_err();
        assert!(err.to_string().contains("checksum_algo"));
    }

    #[tokio::test]
    async fn get_chunk_checksum_reports_value_error() {
        let repo = setup_repo().await;
        let (_bucket, chunk_id) = setup_bucket_with_chunk(&repo, "checksum-value-error").await;
        let _guard = checksum_value_error_guard();
        let err = repo.get_chunk_checksum(chunk_id).await.unwrap_err();
        assert!(err.to_string().contains("checksum_value"));
    }

    #[tokio::test]
    async fn consume_join_token_commits_on_valid_and_missing() {
        let repo = setup_repo().await;
        let now = Utc::now();
        let token = repo
            .create_join_token("token-commit", now + Duration::seconds(60))
            .await
            .expect("token");
        let consumed = repo
            .consume_join_token(&token.token_hash, now)
            .await
            .expect("consume");
        assert!(consumed.is_some());
        let missing = repo
            .consume_join_token("missing-token", now)
            .await
            .expect("consume");
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn consume_join_token_reports_update_error() {
        let repo = setup_repo().await;
        let now = Utc::now();
        let token = repo
            .create_join_token("token-update-error", now + Duration::seconds(60))
            .await
            .expect("token");
        let guard = FailTriggerGuard::create(repo.pool(), "join_tokens", "BEFORE", "UPDATE")
            .await
            .expect("trigger");
        let err = repo
            .consume_join_token(&token.token_hash, now)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("failpoint"));
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn consume_join_token_reports_commit_error_for_valid() {
        let repo = setup_repo().await;
        let now = Utc::now();
        let token = repo
            .create_join_token("token-commit-error", now + Duration::seconds(60))
            .await
            .expect("token");
        let _guard = commit_fail_guard();
        let err = repo
            .consume_join_token(&token.token_hash, now)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("failpoint"));
    }

    #[tokio::test]
    async fn consume_join_token_reports_commit_error_for_missing() {
        let repo = setup_repo().await;
        let now = Utc::now();
        let _guard = commit_fail_guard();
        let err = repo
            .consume_join_token("missing-commit", now)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("failpoint"));
    }
}
