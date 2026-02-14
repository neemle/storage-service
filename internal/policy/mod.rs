use crate::meta::models::{Bucket, User};

pub fn can_access_bucket(user: &User, bucket: &Bucket) -> bool {
    user.id == bucket.owner_user_id && user.status == "active"
}

#[cfg(test)]
mod tests {
    use super::can_access_bucket;
    use crate::meta::models::{Bucket, User};
    use chrono::Utc;
    use uuid::Uuid;

    fn user_with_status(status: &str) -> User {
        User {
            id: Uuid::new_v4(),
            username: "user".to_string(),
            display_name: None,
            password_hash: "hash".to_string(),
            status: status.to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn bucket_for_user(owner: &User) -> Bucket {
        Bucket {
            id: Uuid::new_v4(),
            name: "bucket".to_string(),
            owner_user_id: owner.id,
            created_at: Utc::now(),
            versioning_status: "off".to_string(),
            public_read: false,
            is_worm: false,
            lifecycle_config_xml: None,
            cors_config_xml: None,
            website_config_xml: None,
            notification_config_xml: None,
        }
    }

    #[test]
    fn access_allows_owner_when_active() {
        let user = user_with_status("active");
        let bucket = bucket_for_user(&user);
        assert!(can_access_bucket(&user, &bucket));
    }

    #[test]
    fn access_rejects_inactive_user_or_other_owner() {
        let user = user_with_status("disabled");
        let bucket = bucket_for_user(&user);
        assert!(!can_access_bucket(&user, &bucket));

        let other = user_with_status("active");
        assert!(!can_access_bucket(&other, &bucket));
    }
}
