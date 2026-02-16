use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub password_hash: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AccessKey {
    pub access_key_id: String,
    pub user_id: Uuid,
    pub label: String,
    pub status: String,
    pub secret_encrypted: Vec<u8>,
    pub secret_kid: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Bucket {
    pub id: Uuid,
    pub name: String,
    pub owner_user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub versioning_status: String,
    pub public_read: bool,
    pub is_worm: bool,
    pub lifecycle_config_xml: Option<String>,
    pub cors_config_xml: Option<String>,
    pub website_config_xml: Option<String>,
    pub notification_config_xml: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BucketVolumeBinding {
    pub bucket_id: Uuid,
    pub node_id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ObjectVersion {
    pub id: Uuid,
    pub bucket_id: Uuid,
    pub object_key: String,
    pub version_id: String,
    pub is_delete_marker: bool,
    pub size_bytes: i64,
    pub etag: Option<String>,
    pub content_type: Option<String>,
    pub metadata_json: Value,
    pub tags_json: Value,
    pub created_at: DateTime<Utc>,
    pub current: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MultipartUpload {
    pub id: Uuid,
    pub bucket_id: Uuid,
    pub object_key: String,
    pub upload_id: String,
    pub initiated_at: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MultipartPart {
    pub upload_id: String,
    pub part_number: i32,
    pub size_bytes: i64,
    pub etag: String,
    pub manifest_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Node {
    pub node_id: Uuid,
    pub role: String,
    pub address_internal: String,
    pub status: String,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub capacity_bytes: Option<i64>,
    pub free_bytes: Option<i64>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct JoinToken {
    pub token_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Chunk {
    pub chunk_id: Uuid,
    pub size_bytes: i32,
    pub checksum_algo: String,
    pub checksum_value: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ChunkReplica {
    pub chunk_id: Uuid,
    pub node_id: Uuid,
    pub state: String,
    pub stored_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Manifest {
    pub id: Uuid,
    pub total_size_bytes: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ManifestChunk {
    pub manifest_id: Uuid,
    pub chunk_index: i32,
    pub chunk_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ObjectVersionManifest {
    pub object_version_id: Uuid,
    pub manifest_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLog {
    pub id: Uuid,
    pub ts: DateTime<Utc>,
    pub actor_user_id: Option<Uuid>,
    pub actor_ip: Option<String>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub outcome: String,
    pub details_json: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BucketSnapshotPolicy {
    pub id: Uuid,
    pub bucket_id: Uuid,
    pub trigger_kind: String,
    pub retention_count: i32,
    pub enabled: bool,
    pub last_snapshot_at: Option<DateTime<Utc>>,
    pub created_by_user_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BucketSnapshot {
    pub id: Uuid,
    pub bucket_id: Uuid,
    pub trigger_kind: String,
    pub created_by_user_id: Option<Uuid>,
    pub object_count: i64,
    pub total_size_bytes: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BucketSnapshotObject {
    pub snapshot_id: Uuid,
    pub object_key: String,
    pub version_id: String,
    pub manifest_id: Uuid,
    pub size_bytes: i64,
    pub content_type: Option<String>,
    pub metadata_json: Value,
    pub tags_json: Value,
    pub object_created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BackupPolicy {
    pub id: Uuid,
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
    pub last_run_at: Option<DateTime<Utc>>,
    pub created_by_user_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BackupRun {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub snapshot_id: Option<Uuid>,
    pub backup_type: String,
    pub changed_since: Option<DateTime<Utc>>,
    pub trigger_kind: String,
    pub status: String,
    pub archive_format: String,
    pub archive_object_key: Option<String>,
    pub archive_size_bytes: Option<i64>,
    pub error_text: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ReplicaRuntimeConfig {
    pub node_id: Uuid,
    pub sub_mode: String,
    pub updated_by_user_id: Option<Uuid>,
    pub updated_at: DateTime<Utc>,
}
