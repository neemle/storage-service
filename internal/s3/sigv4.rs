use crate::api::AppState;
use crate::meta::models::{AccessKey, User};
use crate::s3::errors::S3Error;
use crate::s3::sigv4_core::{
    build_canonical_request, build_string_to_sign, calculate_signature, parse_amz_date,
    parse_authorization, parse_presigned, SigV4Params,
};
use crate::util::crypto;
use chrono::Utc;
use percent_encoding::percent_decode_str;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone)]
pub struct AuthResult {
    pub user: User,
    pub access_key_id: String,
    pub payload_hash: String,
}

pub async fn authenticate_request(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    method: &str,
    path: &str,
    query: Option<&str>,
) -> Result<AuthResult, S3Error> {
    let query_str = query.unwrap_or("");
    let params = parse_request_params(headers, method, query_str)?;
    let access_key = load_access_key(state, &params).await?;
    let secret = decrypt_access_key_secret(state, &access_key)?;
    verify_signature_and_time_window(state, headers, method, path, query_str, &params, &secret)
        .await?;
    state
        .repo
        .touch_access_key_usage(&params.access_key)
        .await
        .ok();
    let user = load_active_user(state, access_key.user_id).await?;
    Ok(AuthResult {
        user,
        access_key_id: params.access_key,
        payload_hash: params.payload_hash,
    })
}

fn parse_request_params(
    headers: &axum::http::HeaderMap,
    method: &str,
    query_str: &str,
) -> Result<SigV4Params, S3Error> {
    if query_str.contains("X-Amz-Algorithm=") {
        return parse_presigned(query_str);
    }
    parse_authorization(headers, method)
}

async fn load_access_key(state: &AppState, params: &SigV4Params) -> Result<AccessKey, S3Error> {
    let access_key = state
        .repo
        .get_access_key(&params.access_key)
        .await
        .map_err(|_| access_key_error(params.is_presigned))?;
    let Some(access_key) = access_key else {
        let err = access_key_error(params.is_presigned);
        return Err(handle_s3_failure(state, &params.access_key, err).await);
    };
    Ok(access_key)
}

fn access_key_error(is_presigned: bool) -> S3Error {
    if is_presigned {
        S3Error::InvalidAccessKeyId
    } else {
        S3Error::AccessDenied
    }
}

fn decrypt_access_key_secret(state: &AppState, access_key: &AccessKey) -> Result<String, S3Error> {
    let secret = crypto::decrypt_secret(&state.encryption_key, &access_key.secret_encrypted)
        .map_err(|_| S3Error::SignatureDoesNotMatch)?;
    String::from_utf8(secret).map_err(|_| S3Error::SignatureDoesNotMatch)
}

async fn verify_signature_and_time_window(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    method: &str,
    path: &str,
    query_str: &str,
    params: &SigV4Params,
    secret: &str,
) -> Result<(), S3Error> {
    let signature = compute_signature(headers, method, path, query_str, params, secret)?;
    if signature != params.signature {
        let err =
            handle_s3_failure(state, &params.access_key, S3Error::SignatureDoesNotMatch).await;
        return Err(err);
    }
    verify_time_window(state, params).await
}

fn compute_signature(
    headers: &axum::http::HeaderMap,
    method: &str,
    path: &str,
    query_str: &str,
    params: &SigV4Params,
    secret: &str,
) -> Result<String, S3Error> {
    let decoded_path = percent_decode_str(path).decode_utf8_lossy();
    let canonical_request = build_canonical_request(
        method,
        decoded_path.as_ref(),
        query_str,
        headers,
        &params.signed_headers,
        &params.payload_hash,
        params.is_presigned,
    )?;
    let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = build_string_to_sign(
        &params.algorithm,
        &params.amz_date,
        &params.credential_scope,
        &canonical_hash,
    );
    calculate_signature(secret, &params.credential_scope, &string_to_sign)
}

async fn verify_time_window(state: &AppState, params: &SigV4Params) -> Result<(), S3Error> {
    let request_time = parse_amz_date(&params.amz_date)?;
    let max_skew_seconds = state.config.s3_max_time_skew_seconds.max(0);
    let skew_seconds = (Utc::now() - request_time).num_seconds().abs();
    if skew_seconds > max_skew_seconds {
        let err = handle_s3_failure(state, &params.access_key, S3Error::RequestTimeTooSkewed).await;
        return Err(err);
    }
    if let Some(expires) = params.expires {
        let expires_at = request_time + chrono::Duration::seconds(expires);
        if Utc::now() > expires_at {
            let err =
                handle_s3_failure(state, &params.access_key, S3Error::RequestTimeTooSkewed).await;
            return Err(err);
        }
    }
    Ok(())
}

async fn load_active_user(state: &AppState, user_id: Uuid) -> Result<User, S3Error> {
    let user = state
        .repo
        .find_user_by_id(user_id)
        .await
        .map_err(|_| S3Error::AccessDenied)?
        .ok_or(S3Error::AccessDenied)?;
    if user.status != "active" {
        return Err(S3Error::AccessDenied);
    }
    Ok(user)
}

async fn handle_s3_failure(state: &AppState, access_key: &str, err: S3Error) -> S3Error {
    let key = format!("s3-auth:{}", access_key);
    let allowed = state
        .rate_limiter
        .register_failure(&key, 25, 60)
        .await
        .unwrap_or(true);
    if !allowed {
        return S3Error::TooManyRequests;
    }
    err
}

pub use crate::s3::sigv4_core::presign_url;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;
    use crate::util::crypto;
    use axum::http::{HeaderMap, HeaderValue};
    use chrono::{TimeZone, Utc};
    use sqlx;

    fn build_auth_headers(
        method: &str,
        path: &str,
        query: &str,
        access_key: &str,
        secret: &str,
        amz_date: &str,
        include_payload_hash: bool,
        payload_hash: &str,
    ) -> HeaderMap {
        let mut headers = base_auth_headers(amz_date);
        let signed_headers =
            signed_headers_for_payload(&mut headers, include_payload_hash, payload_hash);
        let auth_value = build_authorization_value(
            method,
            path,
            query,
            access_key,
            secret,
            amz_date,
            payload_hash,
            &headers,
            &signed_headers,
        );
        headers.insert(
            "authorization",
            HeaderValue::from_str(&auth_value).expect("authorization"),
        );
        headers
    }

    #[allow(clippy::too_many_arguments)]
    fn build_authorization_value(
        method: &str,
        path: &str,
        query: &str,
        access_key: &str,
        secret: &str,
        amz_date: &str,
        payload_hash: &str,
        headers: &HeaderMap,
        signed_headers: &[String],
    ) -> String {
        let credential_scope = credential_scope(amz_date);
        signed_authorization(AuthSignInput {
            access_key,
            amz_date,
            credential_scope: &credential_scope,
            headers,
            method,
            path,
            payload_hash,
            query,
            secret,
            signed_headers,
        })
    }

    fn base_auth_headers(amz_date: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost"));
        headers.insert(
            "x-amz-date",
            HeaderValue::from_str(amz_date).expect("x-amz-date"),
        );
        headers
    }

    fn signed_headers_for_payload(
        headers: &mut HeaderMap,
        include_payload_hash: bool,
        payload_hash: &str,
    ) -> Vec<String> {
        let mut signed_headers = vec!["host".to_string(), "x-amz-date".to_string()];
        if include_payload_hash {
            headers.insert(
                "x-amz-content-sha256",
                HeaderValue::from_str(payload_hash).expect("payload hash"),
            );
            signed_headers.insert(1, "x-amz-content-sha256".to_string());
        }
        signed_headers
    }

    fn credential_scope(amz_date: &str) -> String {
        format!("{}/us-east-1/s3/aws4_request", &amz_date[..8])
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_authorization(input: AuthSignInput<'_>) -> String {
        let signature = auth_signature(&input);
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            input.access_key,
            input.credential_scope,
            input.signed_headers.join(";"),
            signature
        )
    }

    fn auth_signature(input: &AuthSignInput<'_>) -> String {
        let canonical_request = crate::s3::sigv4_core::build_canonical_request(
            input.method,
            input.path,
            input.query,
            input.headers,
            input.signed_headers,
            input.payload_hash,
            false,
        )
        .expect("canonical");
        let canonical_hash = hex::encode(sha2::Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign = crate::s3::sigv4_core::build_string_to_sign(
            "AWS4-HMAC-SHA256",
            input.amz_date,
            input.credential_scope,
            &canonical_hash,
        );
        crate::s3::sigv4_core::calculate_signature(
            input.secret,
            input.credential_scope,
            &string_to_sign,
        )
        .expect("signature")
    }

    struct AuthSignInput<'a> {
        access_key: &'a str,
        amz_date: &'a str,
        credential_scope: &'a str,
        headers: &'a HeaderMap,
        method: &'a str,
        path: &'a str,
        payload_hash: &'a str,
        query: &'a str,
        secret: &'a str,
        signed_headers: &'a [String],
    }

    async fn build_state_with_skew(skew_seconds: i64) -> AppState {
        let pool = test_support::setup_pool().await;
        test_support::reset_db(&pool).await;
        let data_dir = test_support::new_temp_dir("sigv4").await;
        let mut config = test_support::base_config("master", data_dir);
        config.s3_max_time_skew_seconds = skew_seconds;
        let metrics = crate::obs::Metrics::new();
        let chunk_store =
            crate::storage::chunkstore::ChunkStore::from_runtime(&config).expect("store");
        AppState::new(config, pool, chunk_store, metrics)
            .await
            .expect("state")
    }

    async fn create_user_and_key(
        state: &AppState,
        access_key_id: &str,
        secret: &[u8],
        key_status: &str,
        user_status: &str,
    ) -> crate::meta::models::User {
        let username = format!("sigv4-{}", access_key_id.to_lowercase());
        let user = state
            .repo
            .create_user(&username, Some("SigV4 User"), "hash", user_status)
            .await
            .expect("user");
        let encrypted = crypto::encrypt_secret(&state.encryption_key, secret).expect("encrypt");
        state
            .repo
            .create_access_key(access_key_id, user.id, "label", key_status, &encrypted)
            .await
            .expect("key");
        user
    }

    fn localhost_presign_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:9000"));
        headers
    }

    fn encoded_presigned_path(raw_key: &str, access_key: &str, secret: &str) -> String {
        let url = presign_url(
            "GET",
            "http://localhost:9000",
            "bucket",
            raw_key,
            access_key,
            secret,
            900,
            "us-east-1",
        )
        .expect("presign");
        url::Url::parse(&url).expect("url").path().to_string()
    }

    async fn assert_inactive_key_rejected(state: &AppState, amz_date: &str) {
        let inactive_key = "AKIAINACTIVE";
        let _ = create_user_and_key(state, inactive_key, b"secret", "disabled", "active").await;
        let headers = build_auth_headers(
            "GET",
            "/",
            "",
            inactive_key,
            "secret",
            amz_date,
            false,
            "UNSIGNED-PAYLOAD",
        );
        let err = authenticate_request(state, &headers, "GET", "/", None).await;
        assert!(err.is_err());
    }

    async fn assert_wrong_signature_rejected(state: &AppState, amz_date: &str) {
        let access_key = "AKIASIG";
        let _ = create_user_and_key(state, access_key, b"secret", "active", "active").await;
        let headers = build_auth_headers(
            "GET",
            "/",
            "",
            access_key,
            "wrong",
            amz_date,
            false,
            "UNSIGNED-PAYLOAD",
        );
        let err = authenticate_request(state, &headers, "GET", "/", None).await;
        assert!(err.is_err());
    }

    async fn assert_expired_presigned_rejected(state: &AppState, access_key: &str, secret: &str) {
        let _ = create_user_and_key(state, access_key, secret.as_bytes(), "active", "active").await;
        let url = presign_url(
            "GET",
            "http://localhost:9000",
            "bucket",
            "object",
            access_key,
            secret,
            -1,
            "us-east-1",
        )
        .expect("presign");
        let parsed = url::Url::parse(&url).expect("url");
        let err = authenticate_request(
            state,
            &localhost_presign_headers(),
            "GET",
            "/bucket/object",
            parsed.query(),
        )
        .await
        .err()
        .expect("expected skew error");
        assert_eq!(err, S3Error::RequestTimeTooSkewed);
    }

    async fn assert_presigned_repo_error(state: &AppState, headers: &HeaderMap, query: &str) {
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let err = authenticate_request(&broken, headers, "GET", "/bucket/object", Some(query))
            .await
            .err()
            .expect("expected error");
        assert_eq!(err, S3Error::InvalidAccessKeyId);
    }

    async fn assert_bad_secret_signature_mismatch(state: &AppState, amz_date: &str) {
        let access_key = "AKIABADSECRET";
        let secret = b"secret";
        let encrypted = crypto::encrypt_secret(&vec![8u8; 32], secret).expect("encrypt");
        let user = state
            .repo
            .create_user("badsecret", None, "hash", "active")
            .await
            .expect("user");
        state
            .repo
            .create_access_key(access_key, user.id, "label", "active", &encrypted)
            .await
            .expect("key");
        let headers = build_auth_headers(
            "GET",
            "/",
            "",
            access_key,
            "secret",
            amz_date,
            false,
            "UNSIGNED-PAYLOAD",
        );
        let err = authenticate_request(state, &headers, "GET", "/", None)
            .await
            .err()
            .expect("expected error");
        assert_eq!(err, S3Error::SignatureDoesNotMatch);
    }

    async fn assert_missing_user_repo_error(state: &AppState, headers: &HeaderMap) {
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let err = authenticate_request(&broken, headers, "GET", "/", None)
            .await
            .err()
            .expect("expected error");
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[tokio::test]
    async fn authenticate_request_success_with_header() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIAAUTH";
        let secret = "secret";
        let user =
            create_user_and_key(&state, access_key, secret.as_bytes(), "active", "active").await;
        let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let headers = build_auth_headers(
            "GET",
            "/",
            "",
            access_key,
            secret,
            &amz_date,
            false,
            "UNSIGNED-PAYLOAD",
        );
        let result = authenticate_request(&state, &headers, "GET", "/", None)
            .await
            .expect("auth");
        assert_eq!(result.user.id, user.id);
        assert_eq!(result.access_key_id, access_key);
    }

    #[tokio::test]
    async fn authenticate_request_success_with_presigned() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIAPRESIGN";
        let secret = "secret";
        let _user =
            create_user_and_key(&state, access_key, secret.as_bytes(), "active", "active").await;
        let url = presign_url(
            "GET",
            "http://localhost:9000",
            "bucket",
            "object",
            access_key,
            secret,
            900,
            "us-east-1",
        )
        .expect("presign");
        let parsed = url::Url::parse(&url).expect("url");
        let query = parsed.query().unwrap_or("");
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:9000"));
        let result = authenticate_request(&state, &headers, "GET", "/bucket/object", Some(query))
            .await
            .expect("auth");
        assert_eq!(result.access_key_id, access_key);
    }

    #[tokio::test]
    async fn authenticate_request_accepts_encoded_path_for_header_auth() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIAENCODED";
        let secret = "secret";
        let user =
            create_user_and_key(&state, access_key, secret.as_bytes(), "active", "active").await;
        let raw_key = "folder/\u{043F}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442} file.txt";
        let raw_path = format!("/bucket/{}", raw_key);
        let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let headers = build_auth_headers(
            "GET",
            &raw_path,
            "",
            access_key,
            secret,
            &amz_date,
            false,
            "UNSIGNED-PAYLOAD",
        );
        let path = encoded_presigned_path(raw_key, access_key, secret);
        let result = authenticate_request(&state, &headers, "GET", &path, None)
            .await
            .expect("auth");
        assert_eq!(result.access_key_id, access_key);
        assert_eq!(result.user.id, user.id);
    }

    #[tokio::test]
    async fn authenticate_request_accepts_encoded_path_for_presigned() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIAENCODED2";
        let secret = "secret";
        let _user =
            create_user_and_key(&state, access_key, secret.as_bytes(), "active", "active").await;
        let raw_key = "folder/\u{043F}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442} file.txt";
        let url = presign_url(
            "GET",
            "http://localhost:9000",
            "bucket",
            raw_key,
            access_key,
            secret,
            900,
            "us-east-1",
        )
        .expect("presign");
        let parsed = url::Url::parse(&url).expect("url");
        let query = parsed.query().unwrap_or("");
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:9000"));
        let result = authenticate_request(&state, &headers, "GET", parsed.path(), Some(query))
            .await
            .expect("auth");
        assert_eq!(result.access_key_id, access_key);
    }

    #[tokio::test]
    async fn authenticate_request_presigned_parse_error() {
        let state = build_state_with_skew(900).await;
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:9000"));
        let err = authenticate_request(
            &state,
            &headers,
            "GET",
            "/bucket/object",
            Some("X-Amz-Algorithm=AWS4-HMAC-SHA256"),
        )
        .await
        .err()
        .expect("error");
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[tokio::test]
    async fn authenticate_request_presigned_missing_access_key_returns_invalid() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIAMISSING";
        let secret = "secret";
        let url = presign_url(
            "GET",
            "http://localhost:9000",
            "bucket",
            "object",
            access_key,
            secret,
            60,
            "us-east-1",
        )
        .expect("presign");
        let parsed = url::Url::parse(&url).expect("url");
        let query = parsed.query().unwrap_or("");
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:9000"));
        let err = authenticate_request(&state, &headers, "GET", "/bucket/object", Some(query))
            .await
            .err()
            .expect("error");
        assert_eq!(err, S3Error::InvalidAccessKeyId);
    }

    #[tokio::test]
    async fn authenticate_request_rejects_invalid_credential_scope() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIABADSCOPE";
        let secret = "secret";
        let _user =
            create_user_and_key(&state, access_key, secret.as_bytes(), "active", "active").await;
        let amz_date = "20250101T000000Z";
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost"));
        headers.insert("x-amz-date", HeaderValue::from_static(amz_date));
        let auth_value = format!(
            "AWS4-HMAC-SHA256 Credential={}/bad, SignedHeaders=host;x-amz-date, Signature=deadbeef",
            access_key
        );
        headers.insert("authorization", HeaderValue::from_str(&auth_value).unwrap());
        let err = authenticate_request(&state, &headers, "GET", "/", None)
            .await
            .err()
            .expect("error");
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[tokio::test]
    async fn authenticate_request_rejects_invalid_amz_date() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIABADDATE";
        let secret = "secret";
        let _user =
            create_user_and_key(&state, access_key, secret.as_bytes(), "active", "active").await;
        let headers = build_auth_headers(
            "GET",
            "/",
            "",
            access_key,
            secret,
            "20250101BAD",
            false,
            "UNSIGNED-PAYLOAD",
        );
        let err = authenticate_request(&state, &headers, "GET", "/", None)
            .await
            .err()
            .expect("error");
        assert_eq!(err, S3Error::RequestTimeTooSkewed);
    }

    #[tokio::test]
    async fn authenticate_request_rejects_unknown_and_inactive() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIAUNKNOWN";
        let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let headers = build_auth_headers(
            "GET",
            "/",
            "",
            access_key,
            "secret",
            &amz_date,
            false,
            "UNSIGNED-PAYLOAD",
        );
        let err = authenticate_request(&state, &headers, "GET", "/", None).await;
        assert!(err.is_err());
        assert_inactive_key_rejected(&state, &amz_date).await;
    }

    #[tokio::test]
    async fn authenticate_request_rejects_inactive_access_key() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIADISABLED";
        let _user = create_user_and_key(&state, access_key, b"secret", "disabled", "active").await;
        let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let headers = build_auth_headers(
            "GET",
            "/",
            "",
            access_key,
            "secret",
            &amz_date,
            false,
            "UNSIGNED-PAYLOAD",
        );
        let err = authenticate_request(&state, &headers, "GET", "/", None).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn authenticate_request_rejects_bad_secret_and_signature() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIABADSECRET";
        let _user =
            create_user_and_key(&state, access_key, &[0xff, 0xfe], "active", "active").await;
        let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let headers = build_auth_headers(
            "GET",
            "/",
            "",
            access_key,
            "secret",
            &amz_date,
            false,
            "UNSIGNED-PAYLOAD",
        );
        let err = authenticate_request(&state, &headers, "GET", "/", None).await;
        assert!(err.is_err());
        assert_wrong_signature_rejected(&state, &amz_date).await;
    }

    #[tokio::test]
    async fn authenticate_request_rejects_time_skew_and_expired() {
        let state = build_state_with_skew(0).await;
        let access_key = "AKIASKEW";
        let secret = "secret";
        let _user =
            create_user_and_key(&state, access_key, secret.as_bytes(), "active", "active").await;
        let old = Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap();
        let amz_date = old.format("%Y%m%dT%H%M%SZ").to_string();
        let headers = build_auth_headers(
            "GET",
            "/",
            "",
            access_key,
            secret,
            &amz_date,
            false,
            "UNSIGNED-PAYLOAD",
        );
        let err = authenticate_request(&state, &headers, "GET", "/", None).await;
        let err = err.err().expect("expected skew error");
        assert_eq!(err, S3Error::RequestTimeTooSkewed);
        let state = build_state_with_skew(900).await;
        assert_expired_presigned_rejected(&state, "AKIAEXPIRE", secret).await;
    }

    #[tokio::test]
    async fn authenticate_request_reports_user_lookup_error() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIAUSERERR";
        let secret = "secret";
        let _user =
            create_user_and_key(&state, access_key, secret.as_bytes(), "active", "active").await;
        let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let headers = build_auth_headers(
            "GET",
            "/",
            "",
            access_key,
            secret,
            &amz_date,
            false,
            "UNSIGNED-PAYLOAD",
        );
        let pool = state.repo.pool().clone();
        sqlx::query("ALTER TABLE users RENAME TO users_backup")
            .execute(&pool)
            .await
            .expect("rename");
        let result = authenticate_request(&state, &headers, "GET", "/", None).await;
        let _ = sqlx::query("ALTER TABLE users_backup RENAME TO users")
            .execute(&pool)
            .await;
        let err = result.err().expect("error");
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[tokio::test]
    async fn authenticate_request_rejects_inactive_user() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIAINACTIVEUSER";
        let secret = "secret";
        let _user =
            create_user_and_key(&state, access_key, secret.as_bytes(), "active", "inactive").await;
        let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let headers = build_auth_headers(
            "GET",
            "/",
            "",
            access_key,
            secret,
            &amz_date,
            false,
            "UNSIGNED-PAYLOAD",
        );
        let err = authenticate_request(&state, &headers, "GET", "/", None).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn authenticate_request_rejects_missing_signed_header() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIAHASH";
        let secret = "secret";
        let _user =
            create_user_and_key(&state, access_key, secret.as_bytes(), "active", "active").await;
        let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let payload_hash = hex::encode(sha2::Sha256::digest(b""));
        let mut headers = build_auth_headers(
            "PUT",
            "/bucket/object",
            "",
            access_key,
            secret,
            &amz_date,
            true,
            &payload_hash,
        );
        headers.remove("x-amz-content-sha256");
        let err = authenticate_request(&state, &headers, "PUT", "/bucket/object", None).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn handle_s3_failure_rate_limits() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIARATE";
        let _user = create_user_and_key(&state, access_key, b"secret", "active", "active").await;
        let mut last = S3Error::AccessDenied;
        for _ in 0..26 {
            last = handle_s3_failure(&state, access_key, S3Error::AccessDenied).await;
        }
        assert_eq!(last, S3Error::TooManyRequests);
    }

    #[tokio::test]
    async fn authenticate_request_presigned_and_repo_errors() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIAPRESIGN";
        let secret = "secret";
        let user =
            create_user_and_key(&state, access_key, secret.as_bytes(), "active", "active").await;
        let url = presign_url(
            "GET",
            "http://localhost:9000",
            "bucket",
            "object",
            access_key,
            secret,
            60,
            "us-east-1",
        )
        .expect("presign");
        let parsed = url::Url::parse(&url).expect("url");
        let query = parsed.query().unwrap_or("");
        let headers = localhost_presign_headers();
        let auth = authenticate_request(&state, &headers, "GET", "/bucket/object", Some(query))
            .await
            .expect("auth");
        assert_eq!(auth.user.id, user.id);
        assert_presigned_repo_error(&state, &headers, query).await;
    }

    #[tokio::test]
    async fn authenticate_request_reports_repo_error_for_header_auth() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIAREPOERR";
        let secret = "secret";
        let _user =
            create_user_and_key(&state, access_key, secret.as_bytes(), "active", "active").await;
        let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let headers = build_auth_headers(
            "GET",
            "/",
            "",
            access_key,
            secret,
            &amz_date,
            false,
            "UNSIGNED-PAYLOAD",
        );
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let err = authenticate_request(&broken, &headers, "GET", "/", None)
            .await
            .err()
            .expect("expected error");
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[tokio::test]
    async fn authenticate_request_updates_access_key_usage() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIALASTUSED";
        let secret = "secret";
        let _user =
            create_user_and_key(&state, access_key, secret.as_bytes(), "active", "active").await;
        let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let headers = build_auth_headers(
            "GET",
            "/",
            "",
            access_key,
            secret,
            &amz_date,
            false,
            "UNSIGNED-PAYLOAD",
        );
        authenticate_request(&state, &headers, "GET", "/", None)
            .await
            .expect("auth");
        let key = state.repo.get_access_key(access_key).await.expect("key");
        assert!(key.and_then(|val| val.last_used_at).is_some());
    }

    #[tokio::test]
    async fn authenticate_request_rejects_inactive_key_and_bad_secret() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIAINACTIVEKEY";
        let _user = create_user_and_key(&state, access_key, b"secret", "inactive", "active").await;
        let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let headers = build_auth_headers(
            "GET",
            "/",
            "",
            access_key,
            "secret",
            &amz_date,
            false,
            "UNSIGNED-PAYLOAD",
        );
        let err = authenticate_request(&state, &headers, "GET", "/", None)
            .await
            .err()
            .expect("expected error");
        assert_eq!(err, S3Error::AccessDenied);
        assert_bad_secret_signature_mismatch(&state, &amz_date).await;
    }

    #[tokio::test]
    async fn authenticate_request_rejects_missing_user() {
        let state = build_state_with_skew(900).await;
        let access_key = "AKIAMISSINGUSER";
        let secret = "secret";
        let user =
            create_user_and_key(&state, access_key, secret.as_bytes(), "active", "active").await;
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user.id)
            .execute(state.repo.pool())
            .await
            .expect("delete user");
        let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let headers = build_auth_headers(
            "GET",
            "/",
            "",
            access_key,
            secret,
            &amz_date,
            false,
            "UNSIGNED-PAYLOAD",
        );
        let err = authenticate_request(&state, &headers, "GET", "/", None)
            .await
            .err()
            .expect("expected error");
        assert_eq!(err, S3Error::AccessDenied);
        assert_missing_user_repo_error(&state, &headers).await;
    }
}
