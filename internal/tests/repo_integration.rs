use nss_core::backup::{test_external_target_connection, ExternalBackupTarget, ExternalTargetKind};
use nss_core::meta::integration;
use nss_core::meta::repos::Repo;
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;
use tokio::sync::OnceCell;
use uuid::Uuid;

static MIGRATIONS: OnceCell<()> = OnceCell::const_new();

async fn setup_pool() -> PgPool {
    let dsn = std::env::var("NSS_POSTGRES_DSN")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("NSS_POSTGRES_DSN or DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&dsn)
        .await
        .expect("connect to postgres");
    MIGRATIONS
        .get_or_init(|| async {
            nss_core::meta::migrate::run_migrations(&pool)
                .await
                .expect("run migrations");
        })
        .await;
    pool
}

fn broken_repo() -> Repo {
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(250))
        .connect_lazy("postgres://nss:nss@127.0.0.1:1/nss?sslmode=disable&connect_timeout=1")
        .expect("lazy pool");
    Repo::new(pool)
}

async fn reset_db(pool: &PgPool) {
    sqlx::query(
        "TRUNCATE TABLE audit_log, access_keys, multipart_parts, multipart_uploads, \
object_version_manifests, manifest_chunks, manifests, chunk_replicas, chunks, \
object_versions, buckets, join_tokens, nodes, users RESTART IDENTITY CASCADE",
    )
    .execute(pool)
    .await
    .expect("truncate tables");
}

#[tokio::test]
async fn user_bucket_and_access_key_flow() {
    let pool = setup_pool().await;
    reset_db(&pool).await;
    let repo = Repo::new(pool);
    let (user, bucket) = provision_user_and_bucket(&repo).await;
    let access_key_id = issue_and_verify_access_key(&repo, user.id).await;
    verify_access_key_lifecycle(&repo, user.id, &access_key_id).await;
    assert_bucket_visibility(&repo, user.id, &bucket.name).await;
}

async fn provision_user_and_bucket(
    repo: &Repo,
) -> (nss_core::meta::models::User, nss_core::meta::models::Bucket) {
    integration::provision_user_and_bucket(
        &repo,
        "integration-user",
        Some("Integration User"),
        "hash",
        "integration-bucket",
    )
    .await
    .expect("provision user and bucket")
}

async fn issue_and_verify_access_key(repo: &Repo, user_id: Uuid) -> String {
    let access =
        integration::issue_access_key(repo, "AKIAINTEGRATION", user_id, "primary", b"secret")
            .await
            .expect("issue access key");
    let keys = repo.list_access_keys(user_id).await.expect("list keys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].access_key_id, access.access_key_id);
    access.access_key_id
}

async fn verify_access_key_lifecycle(repo: &Repo, user_id: Uuid, access_key_id: &str) {
    integration::deactivate_access_key(repo, access_key_id)
        .await
        .expect("disable access key");
    let active = repo
        .get_access_key(access_key_id)
        .await
        .expect("get access key");
    assert!(active.is_none());
    integration::delete_access_key(repo, access_key_id)
        .await
        .expect("delete access key");
    let keys_after = repo.list_access_keys(user_id).await.expect("list keys");
    assert_eq!(keys_after.len(), 0);
}

async fn assert_bucket_visibility(repo: &Repo, user_id: Uuid, bucket_name: &str) {
    let buckets = repo.list_buckets(user_id).await.expect("list buckets");
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].name, bucket_name);
}

fn sftp_target(endpoint: &str) -> ExternalBackupTarget {
    ExternalBackupTarget {
        name: "integration-sftp".to_string(),
        kind: ExternalTargetKind::Sftp,
        endpoint: endpoint.to_string(),
        enabled: Some(true),
        method: None,
        headers: None,
        timeout_seconds: Some(1),
    }
}

fn ssh_target(endpoint: &str) -> ExternalBackupTarget {
    ExternalBackupTarget {
        name: "integration-ssh".to_string(),
        kind: ExternalTargetKind::Ssh,
        endpoint: endpoint.to_string(),
        enabled: Some(true),
        method: None,
        headers: None,
        timeout_seconds: Some(1),
    }
}

async fn finalize_single_chunk_object_version(
    repo: &Repo,
    bucket_id: Uuid,
    object_key: &str,
    version_id: &str,
    chunk_id: Uuid,
) {
    repo.insert_chunk_metadata(chunk_id, 4, "sha256", &[1, 2, 3, 4])
        .await
        .expect("insert chunk");
    repo.finalize_object_version(
        bucket_id,
        object_key,
        version_id,
        4,
        &format!("etag-{version_id}"),
        Some("application/octet-stream"),
        &json!({}),
        &json!({}),
        &[chunk_id],
        false,
    )
    .await
    .expect("finalize object version");
}

#[tokio::test]
async fn bucket_configuration_updates() {
    let pool = setup_pool().await;
    reset_db(&pool).await;
    let repo = Repo::new(pool);

    let (_user, bucket) = integration::provision_user_and_bucket(
        &repo,
        "config-user",
        Some("Config User"),
        "hash",
        "config-bucket",
    )
    .await
    .expect("provision user and bucket");

    let notification =
        "<NotificationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>";
    integration::configure_bucket(&repo, bucket.id, notification, "enabled")
        .await
        .expect("configure bucket");

    let updated = repo
        .get_bucket(&bucket.name)
        .await
        .expect("get bucket")
        .expect("bucket exists");
    assert_eq!(updated.versioning_status, "enabled");
    assert_eq!(
        updated.notification_config_xml.as_deref(),
        Some(notification)
    );
}

#[tokio::test]
async fn configure_bucket_fails_with_bad_connection() {
    let repo = broken_repo();
    let err = integration::configure_bucket(
        &repo,
        Uuid::new_v4(),
        "<NotificationConfiguration/>",
        "enabled",
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut
    ));
}

#[tokio::test]
async fn provision_user_and_bucket_fails_on_duplicate_bucket() {
    let pool = setup_pool().await;
    reset_db(&pool).await;
    let repo = Repo::new(pool);

    let (_user, bucket) = integration::provision_user_and_bucket(
        &repo,
        "duplicate-bucket-user",
        Some("Duplicate Bucket User"),
        "hash",
        "duplicate-bucket",
    )
    .await
    .expect("provision user and bucket");

    let err = integration::provision_user_and_bucket(
        &repo,
        "another-user",
        Some("Another User"),
        "hash",
        &bucket.name,
    )
    .await
    .unwrap_err();

    assert!(matches!(err, sqlx::Error::Database(_)));
}

#[tokio::test]
async fn provision_user_and_bucket_fails_with_bad_connection() {
    let repo = broken_repo();
    let err = integration::provision_user_and_bucket(
        &repo,
        "offline-user",
        Some("Offline User"),
        "hash",
        "offline-bucket",
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut
    ));
}

#[tokio::test]
async fn test_external_sftp_target_connection_reports_connectivity() {
    let target = sftp_target("sftp://127.0.0.1:1");
    let err = test_external_target_connection(&target).await.unwrap_err();
    assert!(err.contains("sftp connectivity check"));
}

#[tokio::test]
async fn test_external_ssh_target_connection_reports_connectivity() {
    let target = ssh_target("ssh://127.0.0.1:1");
    let err = test_external_target_connection(&target).await.unwrap_err();
    assert!(err.contains("ssh connectivity check"));
}

#[tokio::test]
async fn checksum_lookup_and_current_version_promotion_flow() {
    let pool = setup_pool().await;
    reset_db(&pool).await;
    let repo = Repo::new(pool);
    let (_user, bucket) = provision_user_and_bucket(&repo).await;
    let object_key = "coverage-object";
    let first_chunk = Uuid::new_v4();
    let second_chunk = Uuid::new_v4();

    finalize_single_chunk_object_version(&repo, bucket.id, object_key, "v1", first_chunk).await;
    finalize_single_chunk_object_version(&repo, bucket.id, object_key, "v2", second_chunk).await;

    let checksum = repo
        .get_chunk_checksum(second_chunk)
        .await
        .expect("checksum lookup")
        .expect("checksum exists");
    assert_eq!(checksum.0, "sha256");
    assert_eq!(checksum.1, vec![1, 2, 3, 4]);

    let deleted = repo
        .delete_object_version(bucket.id, object_key, "v2")
        .await
        .expect("delete current version");
    assert!(deleted.found);
    assert!(deleted.was_current);

    let current = repo
        .get_object_current(bucket.id, object_key)
        .await
        .expect("current object lookup")
        .expect("current object exists");
    assert_eq!(current.0.version_id, "v1");
}
