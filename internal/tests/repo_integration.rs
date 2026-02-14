use nss_core::meta::integration;
use nss_core::meta::repos::Repo;
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
