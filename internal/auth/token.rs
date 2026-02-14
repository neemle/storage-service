use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

#[cfg(test)]
static FORCE_ISSUE_ERROR: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
pub fn set_force_issue_error(value: bool) {
    FORCE_ISSUE_ERROR.store(value, Ordering::SeqCst);
}

#[cfg(test)]
pub fn clear_force_issue_error() {
    FORCE_ISSUE_ERROR.store(false, Ordering::SeqCst);
}

#[cfg(test)]
pub struct ForceIssueErrorGuard;

#[cfg(test)]
impl Drop for ForceIssueErrorGuard {
    fn drop(&mut self) {
        clear_force_issue_error();
    }
}

#[cfg(test)]
pub fn force_issue_error_guard() -> ForceIssueErrorGuard {
    set_force_issue_error(true);
    ForceIssueErrorGuard
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub user_id: Uuid,
    pub is_admin: bool,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Clone)]
pub struct TokenManager {
    encoding: EncodingKey,
    decoding: DecodingKey,
    ttl: Duration,
}

impl TokenManager {
    pub fn new(secret: &[u8], ttl: Duration) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
            ttl,
        }
    }

    pub fn issue(&self, user_id: Uuid, is_admin: bool) -> Result<String, String> {
        #[cfg(test)]
        if FORCE_ISSUE_ERROR.swap(false, Ordering::SeqCst) {
            return Err("token encode failed".into());
        }
        self.issue_with_header(Header::new(Algorithm::HS256), user_id, is_admin)
    }

    fn issue_with_header(
        &self,
        header: Header,
        user_id: Uuid,
        is_admin: bool,
    ) -> Result<String, String> {
        let now = Utc::now();
        let exp = now + self.ttl;
        let claims = Claims {
            sub: user_id.to_string(),
            user_id,
            is_admin,
            iat: now.timestamp() as usize,
            exp: exp.timestamp() as usize,
        };
        encode(&header, &claims, &self.encoding).map_err(|_| "token encode failed".into())
    }

    pub fn verify(&self, token: &str) -> Result<Claims, String> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        let data = decode::<Claims>(token, &self.decoding, &validation)
            .map_err(|_| "token decode failed".to_string())?;
        Ok(data.claims)
    }

    pub fn exp_for_now(&self) -> DateTime<Utc> {
        Utc::now() + self.ttl
    }
}

#[cfg(test)]
mod tests {
    use super::TokenManager;
    use chrono::{Duration, Utc};
    use jsonwebtoken::{Algorithm, Header};
    use uuid::Uuid;

    #[test]
    fn issue_and_verify_token() {
        let manager = TokenManager::new(b"secret", Duration::hours(2));
        let user_id = Uuid::new_v4();
        let token = manager.issue(user_id, true).expect("issue");
        let claims = manager.verify(&token).expect("verify");
        assert_eq!(claims.user_id, user_id);
        assert!(claims.is_admin);
        assert_eq!(claims.sub, user_id.to_string());
        assert!(claims.exp >= claims.iat);
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let manager = TokenManager::new(b"secret", Duration::hours(1));
        let other = TokenManager::new(b"other", Duration::hours(1));
        let token = manager.issue(Uuid::new_v4(), false).expect("issue");
        let err = other.verify(&token).unwrap_err();
        assert_eq!(err, "token decode failed");
    }

    #[test]
    fn verify_rejects_expired_token() {
        let manager = TokenManager::new(b"secret", Duration::seconds(-3600));
        let token = manager.issue(Uuid::new_v4(), false).expect("issue");
        let err = manager.verify(&token).unwrap_err();
        assert_eq!(err, "token decode failed");
    }

    #[test]
    fn issue_rejects_invalid_algorithm() {
        let manager = TokenManager::new(b"secret", Duration::hours(1));
        let err = manager
            .issue_with_header(Header::new(Algorithm::RS256), Uuid::new_v4(), false)
            .unwrap_err();
        assert_eq!(err, "token encode failed");
    }

    #[test]
    fn exp_for_now_matches_ttl_window() {
        let manager = TokenManager::new(b"secret", Duration::minutes(10));
        let before = Utc::now();
        let exp = manager.exp_for_now();
        let after = Utc::now() + Duration::minutes(10);
        assert!(exp >= before);
        assert!(exp <= after + Duration::seconds(1));
    }
}
