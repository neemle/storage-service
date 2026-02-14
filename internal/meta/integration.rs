use crate::meta::models::{AccessKey, Bucket, User};
use crate::meta::repos::Repo;
use sqlx::Error;
use uuid::Uuid;

pub async fn provision_user_and_bucket(
    repo: &Repo,
    username: &str,
    display_name: Option<&str>,
    password_hash: &str,
    bucket_name: &str,
) -> Result<(User, Bucket), Error> {
    let user = repo
        .create_user(username, display_name, password_hash, "active")
        .await?;
    let bucket = repo.create_bucket(bucket_name, user.id).await?;
    Ok((user, bucket))
}

pub async fn issue_access_key(
    repo: &Repo,
    access_key_id: &str,
    user_id: Uuid,
    label: &str,
    secret_encrypted: &[u8],
) -> Result<AccessKey, Error> {
    repo.create_access_key(access_key_id, user_id, label, "active", secret_encrypted)
        .await
}

pub async fn deactivate_access_key(repo: &Repo, access_key_id: &str) -> Result<(), Error> {
    repo.update_access_key_status(access_key_id, "disabled")
        .await
}

pub async fn delete_access_key(repo: &Repo, access_key_id: &str) -> Result<(), Error> {
    repo.delete_access_key(access_key_id).await
}

pub async fn configure_bucket(
    repo: &Repo,
    bucket_id: Uuid,
    notification_xml: &str,
    versioning_status: &str,
) -> Result<(), Error> {
    sqlx::query("UPDATE buckets SET notification_config_xml=$1, versioning_status=$2 WHERE id=$3")
        .bind(notification_xml)
        .bind(versioning_status)
        .bind(bucket_id)
        .execute(repo.pool())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;
    use uuid::Uuid;

    #[tokio::test]
    async fn integration_helpers_cover_paths() {
        let pool = test_support::setup_pool().await;
        test_support::reset_db(&pool).await;
        let repo = Repo::new(pool);

        let (user, bucket) = provision_user_and_bucket(
            &repo,
            "integration-user",
            Some("Integration User"),
            "hash",
            "integration-bucket",
        )
        .await
        .expect("provision");

        let access = issue_access_key(&repo, "AKIATEST", user.id, "primary", b"secret")
            .await
            .expect("issue");
        assert_eq!(access.user_id, user.id);

        deactivate_access_key(&repo, &access.access_key_id)
            .await
            .expect("deactivate");

        delete_access_key(&repo, &access.access_key_id)
            .await
            .expect("delete");

        configure_bucket(&repo, bucket.id, "<NotificationConfiguration/>", "enabled")
            .await
            .expect("configure");
        let updated = repo.get_bucket(&bucket.name).await.expect("bucket");
        assert!(updated.is_some());
    }

    #[tokio::test]
    async fn integration_helpers_return_errors_on_broken_repo() {
        let repo = test_support::broken_repo();
        let result = provision_user_and_bucket(
            &repo,
            "broken-user",
            Some("Broken"),
            "hash",
            "broken-bucket",
        )
        .await;
        assert!(result.is_err());

        let err = issue_access_key(&repo, "AKIABROKEN", Uuid::new_v4(), "label", b"secret").await;
        assert!(err.is_err());

        let err = deactivate_access_key(&repo, "AKIABROKEN").await;
        assert!(err.is_err());

        let err = delete_access_key(&repo, "AKIABROKEN").await;
        assert!(err.is_err());

        let err = configure_bucket(
            &repo,
            Uuid::new_v4(),
            "<NotificationConfiguration/>",
            "enabled",
        )
        .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn provision_user_and_bucket_reports_bucket_error() {
        let pool = test_support::setup_pool().await;
        test_support::reset_db(&pool).await;
        let repo = Repo::new(pool);
        let user = repo
            .create_user("dup-user", Some("Dup"), "hash", "active")
            .await
            .expect("user");
        repo.create_bucket("dup-bucket", user.id)
            .await
            .expect("bucket");
        let result =
            provision_user_and_bucket(&repo, "other-user", Some("Other"), "hash", "dup-bucket")
                .await;
        assert!(result.is_err());
    }
}
