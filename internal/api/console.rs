use crate::api::auth::{
    clear_cookie, clear_session_cookie, extract_token, session_cookie, transient_cookie,
    verify_claims,
};
use crate::api::AppState;
use crate::auth::oidc::{authorization_url, exchange_code_for_identity, generate_state_nonce};
use crate::auth::token::Claims;
use crate::auth::{access_keys, password};
use crate::s3::sigv4;
use crate::util::crypto;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Redirect;
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;
use uuid::Uuid;

#[cfg(test)]
use std::sync::atomic::{AtomicU8, Ordering};

#[cfg(test)]
static BUCKET_LOOKUP_FAILPOINT: AtomicU8 = AtomicU8::new(0);

#[cfg(test)]
fn consume_bucket_lookup_failpoint() -> bool {
    if BUCKET_LOOKUP_FAILPOINT.load(Ordering::SeqCst) == 1 {
        BUCKET_LOOKUP_FAILPOINT.store(0, Ordering::SeqCst);
        true
    } else {
        false
    }
}

#[cfg(test)]
struct BucketLookupFailpointGuard;

#[cfg(test)]
impl Drop for BucketLookupFailpointGuard {
    fn drop(&mut self) {
        BUCKET_LOOKUP_FAILPOINT.store(0, Ordering::SeqCst);
    }
}

#[cfg(test)]
fn bucket_lookup_failpoint_guard() -> BucketLookupFailpointGuard {
    BUCKET_LOOKUP_FAILPOINT.store(1, Ordering::SeqCst);
    BucketLookupFailpointGuard
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    token: String,
    user: UserResponse,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UserResponse {
    id: Uuid,
    username: String,
    display_name: Option<String>,
    status: String,
    is_admin: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessKeyResponse {
    access_key_id: String,
    label: String,
    status: String,
    created_at: String,
    last_used_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateAccessKeyRequest {
    label: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateAccessKeyResponse {
    access_key_id: String,
    secret_access_key: String,
}

#[derive(Debug, Deserialize)]
struct UpdateAccessKeyRequest {
    status: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthConfigResponse {
    mode: String,
    external_auth_enabled: bool,
    external_auth_type: Option<String>,
    external_login_path: Option<String>,
    oidc_enabled: bool,
    oidc_login_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

const OIDC_STATE_COOKIE: &str = "nss_oidc_state";
const OIDC_NONCE_COOKIE: &str = "nss_oidc_nonce";

pub fn router(state: AppState) -> Router {
    let router: Router<AppState> = Router::new();
    let router = add_console_auth_routes(router);
    let router = add_console_bucket_routes(router);
    add_console_access_key_routes(router).with_state(state)
}

fn add_console_auth_routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route("/console/v1/auth/config", get(auth_config))
        .route("/console/v1/login", post(login))
        .route("/console/v1/oidc/start", get(oidc_start))
        .route("/console/v1/oidc/callback", get(oidc_callback))
        .route("/console/v1/logout", post(logout))
        .route("/console/v1/me", get(me))
        .route("/console/v1/change-password", post(change_password))
}

fn add_console_bucket_routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route("/console/v1/buckets", get(list_buckets))
        .route("/console/v1/buckets/{bucket}", patch(update_bucket))
        .route("/console/v1/buckets/{bucket}/objects", get(list_objects))
        .route(
            "/console/v1/buckets/{bucket}/objects/{*key}",
            get(get_object_detail).patch(update_object),
        )
        .route(
            "/console/v1/buckets/{bucket}/object-url/{*key}",
            get(get_object_download_url),
        )
        .route("/console/v1/presign", post(presign))
}

fn add_console_access_key_routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route(
            "/console/v1/access-keys",
            get(list_access_keys).post(create_access_key),
        )
        .route(
            "/console/v1/access-keys/{access_key_id}",
            patch(update_access_key).delete(delete_access_key),
        )
}

fn unauthorized_error() -> (StatusCode, String) {
    (StatusCode::UNAUTHORIZED, "unauthorized".into())
}

fn forbidden_error() -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, "forbidden".into())
}

fn bucket_lookup_error() -> (StatusCode, &'static str) {
    (StatusCode::INTERNAL_SERVER_ERROR, "bucket lookup failed")
}

fn bucket_not_found_error() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "bucket not found")
}

fn oidc_only_error() -> (StatusCode, String) {
    (
        StatusCode::BAD_REQUEST,
        "password login is disabled; use external identity login".into(),
    )
}

fn oidc_not_configured_error() -> (StatusCode, String) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "external auth is not configured".into(),
    )
}

fn uses_external_auth(state: &AppState) -> bool {
    state.config.auth_mode.uses_external_identity()
}

fn external_login_path(state: &AppState) -> Option<&'static str> {
    if uses_external_auth(state) {
        return Some("/console/v1/oidc/start");
    }
    None
}

fn oidc_config_or_error(
    state: &AppState,
) -> Result<&crate::util::config::OidcConfig, (StatusCode, String)> {
    state
        .config
        .oidc
        .as_ref()
        .ok_or_else(oidc_not_configured_error)
}

async fn require_claims(
    state: &AppState,
    headers: &HeaderMap,
    jar: &CookieJar,
) -> Result<Claims, (StatusCode, String)> {
    let token = extract_token(headers, Some(jar)).ok_or_else(unauthorized_error)?;
    verify_claims(state, &token).map_err(|_| unauthorized_error())
}

fn require_non_empty_key(key: &str) -> Result<(), (StatusCode, String)> {
    if key.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "object key is required".into()));
    }
    Ok(())
}

async fn load_owned_bucket(
    state: &AppState,
    bucket_name: &str,
    owner_user_id: Uuid,
    lookup_error: (StatusCode, &str),
    not_found_error: (StatusCode, &str),
) -> Result<crate::meta::models::Bucket, (StatusCode, String)> {
    let bucket = state
        .repo
        .get_bucket(bucket_name)
        .await
        .map_err(|_| (lookup_error.0, lookup_error.1.to_string()))?
        .ok_or((not_found_error.0, not_found_error.1.to_string()))?;
    if bucket.owner_user_id != owner_user_id {
        return Err(forbidden_error());
    }
    Ok(bucket)
}

fn object_summary_json(object: crate::meta::models::ObjectVersion) -> Value {
    serde_json::json!({
        "key": object.object_key,
        "sizeBytes": object.size_bytes,
        "etag": object.etag,
        "contentType": object.content_type,
        "lastModified": object.created_at.to_rfc3339()
    })
}

fn to_user_response(user: crate::meta::models::User, is_admin: bool) -> UserResponse {
    UserResponse {
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        status: user.status,
        is_admin,
    }
}

async fn auth_config(State(state): State<AppState>) -> Json<AuthConfigResponse> {
    if uses_external_auth(&state) {
        return Json(AuthConfigResponse {
            mode: state.config.auth_mode.as_str().to_string(),
            external_auth_enabled: true,
            external_auth_type: Some(state.config.auth_mode.as_str().to_string()),
            external_login_path: external_login_path(&state).map(|value| value.to_string()),
            oidc_enabled: true,
            oidc_login_path: external_login_path(&state).map(|value| value.to_string()),
        });
    }
    Json(AuthConfigResponse {
        mode: state.config.auth_mode.as_str().to_string(),
        external_auth_enabled: false,
        external_auth_type: None,
        external_login_path: None,
        oidc_enabled: false,
        oidc_login_path: None,
    })
}

async fn oidc_start(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), (StatusCode, String)> {
    if !uses_external_auth(&state) {
        return Err((
            StatusCode::BAD_REQUEST,
            "external auth mode is disabled".into(),
        ));
    }
    let oidc = oidc_config_or_error(&state)?;
    let (state_token, nonce) = generate_state_nonce();
    let url = authorization_url(oidc, &state_token, &nonce)
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "oidc authorization failed".into()))?;
    let jar = jar
        .add(transient_cookie(
            OIDC_STATE_COOKIE,
            &state_token,
            state.config.insecure_dev,
        ))
        .add(transient_cookie(
            OIDC_NONCE_COOKIE,
            &nonce,
            state.config.insecure_dev,
        ));
    Ok((jar, Redirect::to(&url)))
}

async fn oidc_callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<OidcCallbackQuery>,
) -> Result<(CookieJar, Redirect), (StatusCode, String)> {
    if !uses_external_auth(&state) {
        return Err((
            StatusCode::BAD_REQUEST,
            "external auth mode is disabled".into(),
        ));
    }
    let oidc = oidc_config_or_error(&state)?;
    let (code, state_param) = callback_code_and_state(&query)?;
    let nonce = validate_oidc_state_and_nonce(&jar, state_param)?;
    let identity = exchange_code_for_identity(oidc, code, &nonce)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "oidc login failed".into()))?;
    let user = ensure_oidc_user(&state, &identity).await?;
    let token = issue_login_token(&state, user.id, identity.is_admin)?;
    let jar = clear_oidc_cookies(jar).add(session_cookie(&token, state.config.insecure_dev));
    let _ = record_audit(&state, Some(user.id), "console.login", "success", None).await;
    Ok((jar, Redirect::to("/")))
}

fn callback_code_and_state(
    query: &OidcCallbackQuery,
) -> Result<(&str, &str), (StatusCode, String)> {
    let code = query
        .code
        .as_deref()
        .ok_or((StatusCode::BAD_REQUEST, "missing code".into()))?;
    let state = query
        .state
        .as_deref()
        .ok_or((StatusCode::BAD_REQUEST, "missing state".into()))?;
    Ok((code, state))
}

fn validate_oidc_state_and_nonce(
    jar: &CookieJar,
    state_param: &str,
) -> Result<String, (StatusCode, String)> {
    let expected_state = oidc_cookie_value(jar, OIDC_STATE_COOKIE, "missing oidc state")?;
    if expected_state != state_param {
        return Err((StatusCode::UNAUTHORIZED, "invalid oidc state".into()));
    }
    oidc_cookie_value(jar, OIDC_NONCE_COOKIE, "missing oidc nonce")
}

fn oidc_cookie_value(
    jar: &CookieJar,
    name: &str,
    error: &str,
) -> Result<String, (StatusCode, String)> {
    jar.get(name)
        .map(|cookie| cookie.value().to_string())
        .ok_or((StatusCode::UNAUTHORIZED, error.to_string()))
}

fn clear_oidc_cookies(jar: CookieJar) -> CookieJar {
    jar.add(clear_cookie(OIDC_STATE_COOKIE))
        .add(clear_cookie(OIDC_NONCE_COOKIE))
}

async fn ensure_oidc_user(
    state: &AppState,
    identity: &crate::auth::oidc::OidcIdentity,
) -> Result<crate::meta::models::User, (StatusCode, String)> {
    if let Some(user) = state
        .repo
        .find_user_by_username(&identity.username)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid oidc user".into()))?
    {
        if user.status != "active" {
            return Err((StatusCode::FORBIDDEN, "user is disabled".into()));
        }
        return Ok(user);
    }
    create_oidc_user(state, identity).await
}

async fn create_oidc_user(
    state: &AppState,
    identity: &crate::auth::oidc::OidcIdentity,
) -> Result<crate::meta::models::User, (StatusCode, String)> {
    let password = oidc_temp_password();
    let password_hash = password::hash_password(&password)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "hash failed".into()))?;
    state
        .repo
        .create_user(
            &identity.username,
            identity.display_name.as_deref(),
            &password_hash,
            "active",
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "create failed".into()))
}

fn oidc_temp_password() -> String {
    #[cfg(test)]
    if std::env::var("NSS_FORCE_OIDC_HASH_ERROR")
        .map(|value| value == "1")
        .unwrap_or(false)
    {
        return "__force_hash_error__".to_string();
    }
    Uuid::new_v4().to_string()
}

async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<LoginRequest>,
) -> Result<(CookieJar, Json<LoginResponse>), (StatusCode, String)> {
    if uses_external_auth(&state) {
        return Err(oidc_only_error());
    }
    let user = resolve_login_user(&state, &payload).await?;
    let is_admin = user.username == state.config.admin_bootstrap_user;
    let token = issue_login_token(&state, user.id, is_admin)?;
    let response = LoginResponse {
        token: token.clone(),
        user: to_user_response(user, is_admin),
    };
    let jar = jar.add(session_cookie(&token, state.config.insecure_dev));
    record_login_success(&state, response.user.id).await;
    Ok((jar, Json(response)))
}

async fn resolve_login_user(
    state: &AppState,
    payload: &LoginRequest,
) -> Result<crate::meta::models::User, (StatusCode, String)> {
    if let Some(user) = validate_login_user(state, payload).await? {
        return Ok(user);
    }
    Err(register_login_failure(state, &payload.username).await)
}

fn issue_login_token(
    state: &AppState,
    user_id: Uuid,
    is_admin: bool,
) -> Result<String, (StatusCode, String)> {
    state
        .token_manager
        .issue(user_id, is_admin)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "token failed".into()))
}

async fn record_login_success(state: &AppState, user_id: Uuid) {
    let _ = record_audit(state, Some(user_id), "console.login", "success", None).await;
}

async fn validate_login_user(
    state: &AppState,
    payload: &LoginRequest,
) -> Result<Option<crate::meta::models::User>, (StatusCode, String)> {
    let user = state
        .repo
        .find_user_by_username(&payload.username)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid credentials".into()))?;
    let Some(user) = user else {
        return Ok(None);
    };
    if user.status != "active" {
        return Ok(None);
    }
    let valid_password = password::verify_password(&user.password_hash, &payload.password)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid credentials".into()))?;
    if !valid_password {
        return Ok(None);
    }
    Ok(Some(user))
}

async fn register_login_failure(state: &AppState, username: &str) -> (StatusCode, String) {
    let key = format!("login:{}", username);
    let allowed = state
        .rate_limiter
        .register_failure(&key, 10, 60)
        .await
        .unwrap_or(true);
    if !allowed {
        return (StatusCode::TOO_MANY_REQUESTS, "too many attempts".into());
    }
    let _ = record_audit(
        state,
        None,
        "console.login",
        "failure",
        Some(json!({ "username": username })),
    )
    .await;
    (StatusCode::UNAUTHORIZED, "invalid credentials".into())
}

async fn logout(jar: CookieJar) -> (CookieJar, StatusCode) {
    let jar = jar.add(clear_session_cookie());
    (jar, StatusCode::NO_CONTENT)
}

async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    let token = extract_token(&headers, Some(&jar))
        .ok_or((StatusCode::UNAUTHORIZED, "unauthorized".into()))?;
    let claims = verify_claims(&state, &token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "unauthorized".into()))?;
    let user = state
        .repo
        .find_user_by_id(claims.user_id)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "unauthorized".into()))?
        .ok_or((StatusCode::UNAUTHORIZED, "unauthorized".into()))?;
    Ok(Json(UserResponse {
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        status: user.status,
        is_admin: claims.is_admin,
    }))
}

fn validate_change_password_payload(
    payload: &ChangePasswordRequest,
) -> Result<(), (StatusCode, String)> {
    if payload.current_password.trim().is_empty() || payload.new_password.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "currentPassword and newPassword are required".into(),
        ));
    }
    if payload.new_password == payload.current_password {
        return Err((
            StatusCode::BAD_REQUEST,
            "new password must be different".into(),
        ));
    }
    if payload.new_password.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            "new password must be at least 8 characters".into(),
        ));
    }
    Ok(())
}

async fn load_active_claim_user(
    state: &AppState,
    claims: &Claims,
) -> Result<crate::meta::models::User, (StatusCode, String)> {
    let user = state
        .repo
        .find_user_by_id(claims.user_id)
        .await
        .map_err(|_| unauthorized_error())?
        .ok_or_else(unauthorized_error)?;
    if user.status != "active" {
        return Err(unauthorized_error());
    }
    Ok(user)
}

fn verify_current_password(
    user: &crate::meta::models::User,
    current_password: &str,
) -> Result<(), (StatusCode, String)> {
    let valid = password::verify_password(&user.password_hash, current_password)
        .map_err(|_| unauthorized_error())?;
    if !valid {
        return Err(unauthorized_error());
    }
    Ok(())
}

async fn persist_new_password(
    state: &AppState,
    user_id: Uuid,
    new_password: &str,
) -> Result<(), (StatusCode, String)> {
    let password_hash = password::hash_password(new_password)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "hash failed".into()))?;
    state
        .repo
        .update_user_password(user_id, &password_hash)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "update failed".into()))
}

async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    validate_change_password_payload(&payload)?;
    let claims = require_claims(&state, &headers, &jar).await?;
    let user = load_active_claim_user(&state, &claims).await?;
    verify_current_password(&user, &payload.current_password)?;
    persist_new_password(&state, user.id, &payload.new_password).await?;
    let _ = record_audit(
        &state,
        Some(user.id),
        "console.password.change",
        "success",
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_access_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Json<Vec<AccessKeyResponse>>, (StatusCode, String)> {
    let token = extract_token(&headers, Some(&jar))
        .ok_or((StatusCode::UNAUTHORIZED, "unauthorized".into()))?;
    let claims = verify_claims(&state, &token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "unauthorized".into()))?;
    let keys = state
        .repo
        .list_access_keys(claims.user_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "list failed".into()))?;
    let response = keys
        .into_iter()
        .map(|key| AccessKeyResponse {
            access_key_id: key.access_key_id,
            label: key.label,
            status: key.status,
            created_at: key.created_at.to_rfc3339(),
            last_used_at: key.last_used_at.map(|ts| ts.to_rfc3339()),
        })
        .collect();
    Ok(Json(response))
}

async fn list_buckets(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, String)> {
    let token = extract_token(&headers, Some(&jar))
        .ok_or((StatusCode::UNAUTHORIZED, "unauthorized".into()))?;
    let claims = verify_claims(&state, &token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "unauthorized".into()))?;
    let buckets = state
        .repo
        .list_buckets(claims.user_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "list failed".into()))?;
    let response = buckets
        .into_iter()
        .map(|bucket| {
            serde_json::json!({
                "id": bucket.id,
                "name": bucket.name,
                "createdAt": bucket.created_at.to_rfc3339(),
                "versioningStatus": bucket.versioning_status,
                "publicRead": bucket.public_read,
                "isWorm": bucket.is_worm
            })
        })
        .collect();
    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListObjectsQuery {
    prefix: Option<String>,
    start_after: Option<String>,
    max_keys: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateBucketRequest {
    name: Option<String>,
    public_read: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateObjectRequest {
    new_key: Option<String>,
    metadata: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ObjectDetailResponse {
    key: String,
    size_bytes: i64,
    etag: Option<String>,
    content_type: Option<String>,
    last_modified: String,
    metadata: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ObjectUrlQuery {
    expires_seconds: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ObjectUrlResponse {
    url: String,
    public: bool,
}

async fn list_objects(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(bucket): Path<String>,
    Query(query): Query<ListObjectsQuery>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, String)> {
    let claims = require_claims(&state, &headers, &jar).await?;
    let bucket = load_owned_bucket(
        &state,
        &bucket,
        claims.user_id,
        (StatusCode::NOT_FOUND, "bucket not found"),
        (StatusCode::NOT_FOUND, "bucket not found"),
    )
    .await?;
    let max_keys = query.max_keys.unwrap_or(1000).min(1000);
    let objects = state
        .repo
        .list_objects_current(
            bucket.id,
            query.prefix.as_deref(),
            query.start_after.as_deref(),
            max_keys,
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "list failed".into()))?;
    let response = objects.into_iter().map(object_summary_json).collect();
    Ok(Json(response))
}

async fn lookup_bucket_with_failpoint(
    state: &AppState,
    name: &str,
) -> Result<Option<crate::meta::models::Bucket>, sqlx::Error> {
    #[cfg(test)]
    if consume_bucket_lookup_failpoint() {
        return Err(sqlx::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "failpoint",
        )));
    }
    state.repo.get_bucket(name).await
}

async fn ensure_bucket_name_available(
    state: &AppState,
    existing_name: &str,
    new_name: &str,
) -> Result<(), (StatusCode, String)> {
    if new_name == existing_name {
        return Ok(());
    }
    let lookup = lookup_bucket_with_failpoint(state, new_name)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bucket lookup failed".into(),
            )
        })?;
    if lookup.is_some() {
        return Err((StatusCode::CONFLICT, "bucket already exists".into()));
    }
    Ok(())
}

async fn maybe_update_bucket_public(
    state: &AppState,
    user_id: Uuid,
    bucket: &crate::meta::models::Bucket,
    public_read: Option<bool>,
) -> Result<(), (StatusCode, String)> {
    let Some(public_read) = public_read else {
        return Ok(());
    };
    state
        .repo
        .update_bucket_public(bucket.id, public_read)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "update failed".into()))?;
    let _ = record_audit(
        state,
        Some(user_id),
        "console.bucket.public",
        "success",
        Some(json!({ "bucket": bucket.name, "public": public_read })),
    )
    .await;
    Ok(())
}

async fn rename_bucket_and_audit(
    state: &AppState,
    user_id: Uuid,
    bucket: &crate::meta::models::Bucket,
    new_name: &str,
) -> Result<(), (StatusCode, String)> {
    state
        .repo
        .update_bucket_name(bucket.id, new_name)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "rename failed".into()))?;
    let _ = record_audit(
        state,
        Some(user_id),
        "console.bucket.rename",
        "success",
        Some(json!({ "from": bucket.name, "to": new_name })),
    )
    .await;
    Ok(())
}

async fn maybe_rename_bucket(
    state: &AppState,
    user_id: Uuid,
    bucket: &crate::meta::models::Bucket,
    name: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    let Some(name) = name else {
        return Ok(());
    };
    let new_name = name.trim();
    if new_name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "bucket name required".into()));
    }
    ensure_bucket_name_available(state, &bucket.name, new_name).await?;
    if new_name == bucket.name {
        return Ok(());
    }
    rename_bucket_and_audit(state, user_id, bucket, new_name).await
}

async fn update_bucket(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(bucket): Path<String>,
    Json(payload): Json<UpdateBucketRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = require_claims(&state, &headers, &jar).await?;
    let existing = load_owned_bucket(
        &state,
        &bucket,
        claims.user_id,
        bucket_lookup_error(),
        bucket_not_found_error(),
    )
    .await?;
    ensure_bucket_mutable(&existing)?;
    maybe_update_bucket_public(&state, claims.user_id, &existing, payload.public_read).await?;
    maybe_rename_bucket(&state, claims.user_id, &existing, payload.name.as_deref()).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_object_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path((bucket, key)): Path<(String, String)>,
) -> Result<Json<ObjectDetailResponse>, (StatusCode, String)> {
    let claims = require_claims(&state, &headers, &jar).await?;
    require_non_empty_key(&key)?;
    let bucket = load_owned_bucket(
        &state,
        &bucket,
        claims.user_id,
        bucket_lookup_error(),
        bucket_not_found_error(),
    )
    .await?;
    let object = state
        .repo
        .get_object_current(bucket.id, &key)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "object not found".into()))?
        .ok_or((StatusCode::NOT_FOUND, "object not found".into()))?;
    let (version, _manifest_id) = object;
    Ok(Json(to_object_detail_response(version)))
}

fn to_object_detail_response(version: crate::meta::models::ObjectVersion) -> ObjectDetailResponse {
    ObjectDetailResponse {
        key: version.object_key,
        size_bytes: version.size_bytes,
        etag: version.etag,
        content_type: version.content_type,
        last_modified: version.created_at.to_rfc3339(),
        metadata: version.metadata_json,
    }
}

async fn ensure_object_key_available(
    state: &AppState,
    bucket_id: Uuid,
    new_key: &str,
) -> Result<(), (StatusCode, String)> {
    let existing = state
        .repo
        .get_object_current(bucket_id, new_key)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "object lookup failed".into(),
            )
        })?;
    if existing.is_some() {
        return Err((StatusCode::CONFLICT, "object already exists".into()));
    }
    Ok(())
}

async fn rename_object_and_audit(
    state: &AppState,
    user_id: Uuid,
    bucket: &crate::meta::models::Bucket,
    key: &str,
    new_key: &str,
) -> Result<(), (StatusCode, String)> {
    let updated = state
        .repo
        .rename_object_key(bucket.id, key, new_key)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "rename failed".into()))?;
    if updated == 0 {
        return Err((StatusCode::NOT_FOUND, "object not found".into()));
    }
    let _ = record_audit(
        state,
        Some(user_id),
        "console.object.rename",
        "success",
        Some(json!({ "bucket": bucket.name, "from": key, "to": new_key })),
    )
    .await;
    Ok(())
}

async fn rename_object_if_requested(
    state: &AppState,
    user_id: Uuid,
    bucket: &crate::meta::models::Bucket,
    key: &str,
    new_key: Option<&str>,
) -> Result<String, (StatusCode, String)> {
    let Some(new_key_raw) = new_key else {
        return Ok(key.to_string());
    };
    let new_key = new_key_raw.trim();
    if new_key.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "new key required".into()));
    }
    if new_key == key {
        return Ok(key.to_string());
    }
    ensure_object_key_available(state, bucket.id, new_key).await?;
    rename_object_and_audit(state, user_id, bucket, key, new_key).await?;
    Ok(new_key.to_string())
}

async fn update_object_metadata_if_requested(
    state: &AppState,
    user_id: Uuid,
    bucket: &crate::meta::models::Bucket,
    key: &str,
    metadata: Option<Value>,
) -> Result<(), (StatusCode, String)> {
    let Some(metadata) = metadata else {
        return Ok(());
    };
    let validated = validate_metadata(&metadata)?;
    update_object_metadata(state, bucket.id, key, &validated).await?;
    record_object_metadata_audit(state, user_id, &bucket.name, key).await;
    Ok(())
}

async fn update_object_metadata(
    state: &AppState,
    bucket_id: Uuid,
    key: &str,
    metadata: &Value,
) -> Result<(), (StatusCode, String)> {
    let updated = state
        .repo
        .update_object_metadata(bucket_id, key, metadata)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "metadata update failed".into(),
            )
        })?;
    if updated == 0 {
        return Err((StatusCode::NOT_FOUND, "object not found".into()));
    }
    Ok(())
}

async fn record_object_metadata_audit(
    state: &AppState,
    user_id: Uuid,
    bucket_name: &str,
    key: &str,
) {
    let _ = record_audit(
        state,
        Some(user_id),
        "console.object.metadata",
        "success",
        Some(json!({ "bucket": bucket_name, "key": key })),
    )
    .await;
}

async fn update_object(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path((bucket, key)): Path<(String, String)>,
    Json(payload): Json<UpdateObjectRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = require_claims(&state, &headers, &jar).await?;
    let bucket = load_mutable_owned_bucket(&state, &bucket, claims.user_id).await?;
    let effective_key = rename_object_if_requested(
        &state,
        claims.user_id,
        &bucket,
        &key,
        payload.new_key.as_deref(),
    )
    .await?;
    update_object_metadata_if_requested(
        &state,
        claims.user_id,
        &bucket,
        &effective_key,
        payload.metadata,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn load_mutable_owned_bucket(
    state: &AppState,
    bucket_name: &str,
    owner_user_id: Uuid,
) -> Result<crate::meta::models::Bucket, (StatusCode, String)> {
    let bucket = load_owned_bucket(
        state,
        bucket_name,
        owner_user_id,
        bucket_lookup_error(),
        bucket_not_found_error(),
    )
    .await?;
    ensure_bucket_mutable(&bucket)?;
    Ok(bucket)
}

fn ensure_bucket_mutable(bucket: &crate::meta::models::Bucket) -> Result<(), (StatusCode, String)> {
    if bucket.is_worm {
        return Err((StatusCode::FORBIDDEN, "WORM bucket is immutable".into()));
    }
    Ok(())
}

fn extract_download_token(
    state: &AppState,
    headers: &HeaderMap,
    jar: &CookieJar,
    key: &str,
) -> Result<String, (StatusCode, String)> {
    if let Some(token) = extract_token(headers, Some(jar)) {
        return Ok(token);
    }
    if !key.is_empty() && state.config.s3_public_url.is_none() && headers.get("host").is_none() {
        return Err((StatusCode::BAD_REQUEST, "missing host header".into()));
    }
    Err(unauthorized_error())
}

async fn ensure_object_exists(
    state: &AppState,
    bucket_id: Uuid,
    key: &str,
) -> Result<(), (StatusCode, String)> {
    let exists = state
        .repo
        .get_object_current(bucket_id, key)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "object lookup failed".into(),
            )
        })?
        .is_some();
    if !exists {
        return Err((StatusCode::NOT_FOUND, "object not found".into()));
    }
    Ok(())
}

async fn build_private_download_url(
    state: &AppState,
    user_id: Uuid,
    endpoint: &str,
    bucket_name: &str,
    key: &str,
    expires: i64,
) -> Result<String, (StatusCode, String)> {
    let (access_key_id, secret_str) = resolve_signing_key(state, user_id, None).await?;
    sigv4::presign_url(
        "GET",
        endpoint,
        bucket_name,
        key,
        &access_key_id,
        &secret_str,
        expires,
        "us-east-1",
    )
    .map_err(|err| (StatusCode::BAD_REQUEST, err))
}

async fn get_object_download_url(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path((bucket_name, key)): Path<(String, String)>,
    Query(query): Query<ObjectUrlQuery>,
) -> Result<Json<ObjectUrlResponse>, (StatusCode, String)> {
    let (user_id, bucket) =
        load_download_bucket(&state, &headers, &jar, &bucket_name, &key).await?;
    let endpoint = resolve_s3_endpoint(&state.config, &headers)?;
    if bucket.public_read {
        let url = build_object_url(&endpoint, &bucket.name, &key)?;
        return Ok(Json(ObjectUrlResponse { url, public: true }));
    }
    let expires = normalized_download_expiry(query.expires_seconds);
    let url =
        build_private_download_url(&state, user_id, &endpoint, &bucket.name, &key, expires).await?;
    Ok(Json(ObjectUrlResponse { url, public: false }))
}

async fn load_download_bucket(
    state: &AppState,
    headers: &HeaderMap,
    jar: &CookieJar,
    bucket_name: &str,
    key: &str,
) -> Result<(Uuid, crate::meta::models::Bucket), (StatusCode, String)> {
    let token = extract_download_token(state, headers, jar, key)?;
    let claims = verify_claims(state, &token).map_err(|_| unauthorized_error())?;
    require_non_empty_key(key)?;
    let bucket = load_owned_bucket(
        state,
        bucket_name,
        claims.user_id,
        bucket_not_found_error(),
        bucket_not_found_error(),
    )
    .await?;
    ensure_object_exists(state, bucket.id, key).await?;
    Ok((claims.user_id, bucket))
}

fn normalized_download_expiry(requested_seconds: Option<i64>) -> i64 {
    requested_seconds.unwrap_or(300).min(7 * 24 * 3600)
}

fn validate_metadata(value: &Value) -> Result<Value, (StatusCode, String)> {
    let obj = value
        .as_object()
        .ok_or((StatusCode::BAD_REQUEST, "metadata must be an object".into()))?;
    for (key, val) in obj {
        if key.trim().is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "metadata keys must be non-empty".into(),
            ));
        }
        if !val.is_string() {
            return Err((
                StatusCode::BAD_REQUEST,
                "metadata values must be strings".into(),
            ));
        }
    }
    Ok(value.clone())
}

fn encrypt_secret_for_access_key(
    state: &AppState,
    secret: &str,
) -> Result<Vec<u8>, (StatusCode, String)> {
    crypto::encrypt_secret(&state.encryption_key, secret.as_bytes()).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "encryption failed".into(),
        )
    })
}

async fn persist_created_access_key(
    state: &AppState,
    user_id: Uuid,
    label: &str,
    access_key_id: &str,
    encrypted: &[u8],
) -> Result<(), (StatusCode, String)> {
    state
        .repo
        .create_access_key(access_key_id, user_id, label, "active", encrypted)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "create failed".into()))?;
    let _ = record_audit(
        state,
        Some(user_id),
        "console.access_key.create",
        "success",
        Some(json!({ "accessKeyId": access_key_id, "label": label })),
    )
    .await;
    Ok(())
}

async fn create_access_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(payload): Json<CreateAccessKeyRequest>,
) -> Result<Json<CreateAccessKeyResponse>, (StatusCode, String)> {
    let claims = require_claims(&state, &headers, &jar).await?;
    let access_key_id = access_keys::generate_access_key_id();
    let secret = access_keys::generate_secret_access_key();
    let encrypted = encrypt_secret_for_access_key(&state, &secret)?;
    persist_created_access_key(
        &state,
        claims.user_id,
        &payload.label,
        &access_key_id,
        &encrypted,
    )
    .await?;
    Ok(Json(CreateAccessKeyResponse {
        access_key_id,
        secret_access_key: secret,
    }))
}

async fn update_access_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(access_key_id): Path<String>,
    Json(payload): Json<UpdateAccessKeyRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = require_claims(&state, &headers, &jar).await?;
    let updated = state
        .repo
        .update_access_key_status_for_user(&access_key_id, claims.user_id, &payload.status)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "update failed".into()))?;
    if !updated {
        return Err(forbidden_error());
    }
    let _ = record_audit(
        &state,
        Some(claims.user_id),
        "console.access_key.update",
        "success",
        Some(json!({ "accessKeyId": access_key_id, "status": payload.status })),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_access_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(access_key_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = require_claims(&state, &headers, &jar).await?;
    let deleted = state
        .repo
        .delete_access_key_for_user(&access_key_id, claims.user_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "delete failed".into()))?;
    if !deleted {
        return Err(forbidden_error());
    }
    let _ = record_audit(
        &state,
        Some(claims.user_id),
        "console.access_key.delete",
        "success",
        Some(json!({ "accessKeyId": access_key_id })),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PresignRequest {
    method: String,
    bucket: String,
    key: String,
    expires_seconds: Option<i64>,
    access_key_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct PresignResponse {
    url: String,
}

async fn presign(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(payload): Json<PresignRequest>,
) -> Result<Json<PresignResponse>, (StatusCode, String)> {
    let token = extract_token(&headers, Some(&jar))
        .ok_or((StatusCode::UNAUTHORIZED, "unauthorized".into()))?;
    let claims = verify_claims(&state, &token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "unauthorized".into()))?;
    let (access_key_id, secret_str) =
        resolve_signing_key(&state, claims.user_id, payload.access_key_id.as_deref()).await?;

    let endpoint = resolve_s3_endpoint(&state.config, &headers)?;
    let expires = payload.expires_seconds.unwrap_or(900).min(7 * 24 * 3600);
    let url = sigv4::presign_url(
        &payload.method,
        &endpoint,
        &payload.bucket,
        &payload.key,
        &access_key_id,
        &secret_str,
        expires,
        "us-east-1",
    )
    .map_err(|err| (StatusCode::BAD_REQUEST, err))?;

    Ok(Json(PresignResponse { url }))
}

fn resolve_s3_endpoint(
    config: &crate::util::config::Config,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, String)> {
    if let Some(url) = config.s3_public_url.clone() {
        return Ok(url);
    }
    let host = headers
        .get("host")
        .and_then(|val| val.to_str().ok())
        .ok_or((StatusCode::BAD_REQUEST, "missing host header".into()))?;
    let host = if let Some((name, _port)) = host.split_once(':') {
        format!("{}:9000", name)
    } else {
        format!("{}:9000", host)
    };
    Ok(format!("http://{}", host))
}

fn decrypt_access_key_secret(
    state: &AppState,
    encrypted: &[u8],
) -> Result<String, (StatusCode, String)> {
    let secret =
        crate::util::crypto::decrypt_secret(&state.encryption_key, encrypted).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "secret decrypt failed".into(),
            )
        })?;
    String::from_utf8(secret)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "invalid secret".into()))
}

async fn resolve_explicit_signing_key(
    state: &AppState,
    user_id: Uuid,
    access_key_id: &str,
) -> Result<(String, String), (StatusCode, String)> {
    let key = state
        .repo
        .get_access_key(access_key_id)
        .await
        .map_err(|_| (StatusCode::FORBIDDEN, "access key not found".into()))?
        .ok_or((StatusCode::FORBIDDEN, "access key not found".into()))?;
    if key.user_id != user_id {
        return Err((StatusCode::FORBIDDEN, "access key not owned".into()));
    }
    let secret_str = decrypt_access_key_secret(state, &key.secret_encrypted)?;
    Ok((key.access_key_id, secret_str))
}

async fn resolve_active_signing_key(
    state: &AppState,
    user_id: Uuid,
) -> Result<Option<(String, String)>, (StatusCode, String)> {
    let keys = state.repo.list_access_keys(user_id).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "access key lookup failed".into(),
        )
    })?;
    let Some(key) = keys.into_iter().find(|key| key.status == "active") else {
        return Ok(None);
    };
    let secret_str = decrypt_access_key_secret(state, &key.secret_encrypted)?;
    Ok(Some((key.access_key_id, secret_str)))
}

async fn create_auto_signing_key(
    state: &AppState,
    user_id: Uuid,
) -> Result<(String, String), (StatusCode, String)> {
    let access_key_id = access_keys::generate_access_key_id();
    let secret = access_keys::generate_secret_access_key();
    let encrypted = encrypt_secret_for_access_key(state, &secret)?;
    state
        .repo
        .create_access_key(&access_key_id, user_id, "ui-system", "active", &encrypted)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "create failed".into()))?;
    let _ = record_audit(
        state,
        Some(user_id),
        "console.access_key.auto_create",
        "success",
        Some(json!({ "accessKeyId": access_key_id, "label": "ui-system" })),
    )
    .await;
    Ok((access_key_id, secret))
}

async fn resolve_signing_key(
    state: &AppState,
    user_id: Uuid,
    access_key_id: Option<&str>,
) -> Result<(String, String), (StatusCode, String)> {
    if let Some(access_key_id) = access_key_id {
        return resolve_explicit_signing_key(state, user_id, access_key_id).await;
    }
    if let Some(active_key) = resolve_active_signing_key(state, user_id).await? {
        return Ok(active_key);
    }
    create_auto_signing_key(state, user_id).await
}

fn build_object_url(
    endpoint: &str,
    bucket: &str,
    key: &str,
) -> Result<String, (StatusCode, String)> {
    let mut url =
        Url::parse(endpoint).map_err(|_| (StatusCode::BAD_REQUEST, "invalid endpoint".into()))?;
    let path = if key.is_empty() {
        format!("/{}", bucket)
    } else {
        format!("/{}/{}", bucket, key)
    };
    url.set_path(&path);
    Ok(url.to_string())
}

async fn record_audit(
    state: &AppState,
    actor_user_id: Option<Uuid>,
    action: &str,
    outcome: &str,
    details: Option<serde_json::Value>,
) -> Result<(), String> {
    let details = details.unwrap_or_else(|| json!({}));
    state
        .repo
        .insert_audit_log(actor_user_id, None, action, None, None, outcome, &details)
        .await
        .map_err(|err| format!("audit failed: {err}"))
}

#[cfg(test)]
mod tests {
    use super::{
        auth_config, bucket_lookup_failpoint_guard, build_object_url, callback_code_and_state,
        change_password, clear_oidc_cookies, create_access_key, create_oidc_user,
        delete_access_key, ensure_bucket_mutable, ensure_oidc_user, external_login_path,
        get_object_detail, get_object_download_url, list_access_keys, list_buckets, list_objects,
        load_active_claim_user, login, logout, me, oidc_callback, oidc_start, persist_new_password,
        presign, record_audit, register_login_failure, resolve_s3_endpoint, resolve_signing_key,
        update_access_key, update_bucket, update_object, validate_metadata,
        validate_oidc_state_and_nonce, verify_current_password, AuthConfigResponse,
        ChangePasswordRequest, CreateAccessKeyRequest, ListObjectsQuery, LoginRequest,
        ObjectUrlQuery, OidcCallbackQuery, PresignRequest, UpdateAccessKeyRequest,
        UpdateBucketRequest, UpdateObjectRequest, OIDC_NONCE_COOKIE, OIDC_STATE_COOKIE,
    };
    use crate::auth::access_keys;
    use crate::auth::oidc::OidcIdentity;
    use crate::auth::password;
    use crate::auth::token::{force_issue_error_guard, Claims};
    use crate::storage::checksum::Checksum;
    use crate::test_support::{self, FailTriggerGuard, TableRenameGuard};
    use crate::util::config::{AuthMode, OidcConfig};
    use crate::util::crypto::{self, force_encrypt_error_guard};
    use axum::extract::{Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::Json;
    use axum_extra::extract::cookie::{Cookie, CookieJar};
    use serde_json::json;
    use sqlx;
    use tokio::sync::oneshot;
    use uuid::Uuid;

    async fn create_user_and_token(
        state: &crate::api::AppState,
    ) -> (crate::meta::models::User, String) {
        let hash = password::hash_password("secret").expect("hash");
        let user = state
            .repo
            .create_user("console-user", Some("Console User"), &hash, "active")
            .await
            .expect("user");
        let token = state.token_manager.issue(user.id, false).expect("token");
        (user, token)
    }

    fn auth_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", token).parse().expect("auth"),
        );
        headers
    }

    fn list_objects_query() -> Query<ListObjectsQuery> {
        Query(ListObjectsQuery {
            prefix: None,
            start_after: None,
            max_keys: None,
        })
    }

    fn update_bucket_payload(
        name: Option<&str>,
        public_read: Option<bool>,
    ) -> Json<UpdateBucketRequest> {
        Json(UpdateBucketRequest {
            name: name.map(|value| value.to_string()),
            public_read,
        })
    }

    fn create_access_key_payload(label: &str) -> Json<CreateAccessKeyRequest> {
        Json(CreateAccessKeyRequest {
            label: label.to_string(),
        })
    }

    fn update_access_key_payload(status: &str) -> Json<UpdateAccessKeyRequest> {
        Json(UpdateAccessKeyRequest {
            status: status.to_string(),
        })
    }

    fn change_password_payload(
        current_password: &str,
        new_password: &str,
    ) -> Json<ChangePasswordRequest> {
        Json(ChangePasswordRequest {
            current_password: current_password.to_string(),
            new_password: new_password.to_string(),
        })
    }

    fn sample_oidc_config() -> OidcConfig {
        OidcConfig {
            issuer_url: "https://sso.example.com/realms/nss".to_string(),
            client_id: "nss-console".to_string(),
            client_secret: None,
            redirect_url: "http://localhost:9001/console/v1/oidc/callback".to_string(),
            scopes: "openid profile email".to_string(),
            username_claim: "preferred_username".to_string(),
            display_name_claim: "name".to_string(),
            groups_claim: "groups".to_string(),
            admin_groups: vec!["nss-admin".to_string()],
            audience: "nss-console".to_string(),
        }
    }

    fn oidc_query(code: Option<&str>, state: Option<&str>) -> Query<OidcCallbackQuery> {
        Query(OidcCallbackQuery {
            code: code.map(|value| value.to_string()),
            state: state.map(|value| value.to_string()),
        })
    }

    fn sample_identity(username: &str, is_admin: bool) -> OidcIdentity {
        OidcIdentity {
            subject: format!("sub-{username}"),
            username: username.to_string(),
            display_name: Some(format!("Display {username}")),
            is_admin,
        }
    }

    async fn auth_config_for_external_mode(mode: AuthMode) -> AuthConfigResponse {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.auth_mode = mode;
        state.config.oidc = Some(sample_oidc_config());
        let Json(response): Json<AuthConfigResponse> = auth_config(State(state)).await;
        response
    }

    fn assert_external_auth_mode(response: &AuthConfigResponse, mode: &str) {
        assert_eq!(response.mode, mode);
        assert_eq!(response.external_auth_type.as_deref(), Some(mode));
        assert_eq!(
            response.external_login_path.as_deref(),
            Some("/console/v1/oidc/start")
        );
        assert!(response.oidc_enabled);
        assert_eq!(
            response.oidc_login_path.as_deref(),
            Some("/console/v1/oidc/start")
        );
    }

    fn set_test_oidc_identity_json(value: &str) -> Option<String> {
        let previous = std::env::var("NSS_TEST_OIDC_IDENTITY_JSON").ok();
        std::env::set_var("NSS_TEST_OIDC_IDENTITY_JSON", value);
        previous
    }

    async fn build_oidc_callback_state_and_jar() -> (crate::api::AppState, CookieJar) {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.auth_mode = AuthMode::Oidc;
        state.config.oidc = Some(sample_oidc_config());
        let jar = with_oidc_cookie(
            with_oidc_cookie(CookieJar::new(), OIDC_STATE_COOKIE, "state-1"),
            OIDC_NONCE_COOKIE,
            "nonce-1",
        );
        (state, jar)
    }

    async fn seed_worm_object(
        state: &crate::api::AppState,
        bucket_id: Uuid,
        key: &str,
    ) {
        let checksum = Checksum::compute(state.config.checksum_algo, b"worm-data");
        let chunk_id = Uuid::new_v4();
        state
            .repo
            .insert_chunk_metadata(chunk_id, 9, checksum.algo.as_str(), &checksum.value)
            .await
            .expect("chunk");
        state
            .repo
            .finalize_object_version(
                bucket_id,
                key,
                "v1",
                9,
                "etag",
                Some("text/plain"),
                &json!({}),
                &json!({}),
                &[chunk_id],
                false,
            )
            .await
            .expect("object");
    }

    async fn create_worm_console_bucket(
        state: &crate::api::AppState,
        owner_user_id: Uuid,
    ) -> crate::meta::models::Bucket {
        let bucket = state
            .repo
            .create_bucket("worm-console", owner_user_id)
            .await
            .expect("bucket");
        state
            .repo
            .update_bucket_worm(bucket.id, true)
            .await
            .expect("worm");
        seed_worm_object(state, bucket.id, "worm.txt").await;
        bucket
    }

    async fn expect_update_object_error(
        state: &crate::api::AppState,
        headers: HeaderMap,
        bucket: &str,
        key: &str,
        expected: StatusCode,
    ) {
        let err = update_object(
            State(state.clone()),
            headers,
            CookieJar::new(),
            Path((bucket.to_string(), key.to_string())),
            Json(UpdateObjectRequest {
                new_key: Some("new-worm.txt".to_string()),
                metadata: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, expected);
    }

    async fn assert_change_password_lookup_error(state: &crate::api::AppState) {
        let missing_token = state
            .token_manager
            .issue(Uuid::new_v4(), false)
            .expect("token");
        expect_change_password_error(
            state,
            auth_headers(&missing_token),
            change_password_payload("secret", "new-secret-123"),
            StatusCode::UNAUTHORIZED,
        )
        .await;
    }

    async fn assert_change_password_hash_error(state: &crate::api::AppState) {
        let hash = password::hash_password("secret").expect("hash");
        let user = state
            .repo
            .create_user("hash-change-user", None, &hash, "active")
            .await
            .expect("user");
        let token = state.token_manager.issue(user.id, false).expect("token");
        expect_change_password_error(
            state,
            auth_headers(&token),
            change_password_payload("secret", "__force_hash_error__"),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
    }

    fn spawn_test_server(
        listener: tokio::net::TcpListener,
        app: axum::Router,
        started_tx: oneshot::Sender<()>,
    ) -> tokio::task::JoinHandle<std::io::Result<()>> {
        let _ = started_tx.send(());
        tokio::spawn(std::future::IntoFuture::into_future(axum::serve(
            listener, app,
        )))
    }

    async fn spawn_oidc_discovery_server() -> (String, tokio::task::JoinHandle<std::io::Result<()>>)
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let issuer = format!("http://{addr}");
        let app = axum::Router::new().route(
            "/.well-known/openid-configuration",
            axum::routing::get({
                let issuer = issuer.clone();
                move || {
                    let issuer = issuer.clone();
                    async move {
                        axum::Json(json!({
                            "issuer": issuer,
                            "authorization_endpoint": format!("{issuer}/authorize"),
                            "token_endpoint": format!("{issuer}/token"),
                            "jwks_uri": format!("{issuer}/jwks")
                        }))
                    }
                }
            }),
        );
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let handle = spawn_test_server(listener, app, started_tx);
        let _ = started_rx.await;
        (issuer, handle)
    }

    fn with_oidc_cookie(jar: CookieJar, name: &str, value: &str) -> CookieJar {
        jar.add(Cookie::new(name.to_string(), value.to_string()))
    }

    fn restore_env(key: &str, previous: Option<String>) {
        if let Some(value) = previous {
            std::env::set_var(key, value);
        } else {
            std::env::remove_var(key);
        }
    }

    async fn expect_me_error(
        state: &crate::api::AppState,
        headers: HeaderMap,
        expected: StatusCode,
    ) {
        let err = me(State(state.clone()), headers, CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, expected);
    }

    async fn expect_change_password_error(
        state: &crate::api::AppState,
        headers: HeaderMap,
        payload: Json<ChangePasswordRequest>,
        expected: StatusCode,
    ) {
        let err = change_password(State(state.clone()), headers, CookieJar::new(), payload)
            .await
            .unwrap_err();
        assert_eq!(err.0, expected);
    }

    async fn assert_change_password_validation_errors(state: &crate::api::AppState, token: &str) {
        expect_change_password_error(
            state,
            auth_headers(token),
            change_password_payload("wrong-secret", "new-secret"),
            StatusCode::UNAUTHORIZED,
        )
        .await;
        expect_change_password_error(
            state,
            auth_headers(token),
            change_password_payload("secret", "secret"),
            StatusCode::BAD_REQUEST,
        )
        .await;
        expect_change_password_error(
            state,
            auth_headers(token),
            change_password_payload("secret", "short"),
            StatusCode::BAD_REQUEST,
        )
        .await;
    }

    async fn expect_list_access_keys_error(
        state: &crate::api::AppState,
        headers: HeaderMap,
        expected: StatusCode,
    ) {
        let err = list_access_keys(State(state.clone()), headers, CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, expected);
    }

    async fn expect_list_buckets_error(
        state: &crate::api::AppState,
        headers: HeaderMap,
        expected: StatusCode,
    ) {
        let err = list_buckets(State(state.clone()), headers, CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, expected);
    }

    async fn expect_list_objects_error(
        state: &crate::api::AppState,
        headers: HeaderMap,
        bucket: &str,
        expected: StatusCode,
    ) {
        let err = list_objects(
            State(state.clone()),
            headers,
            CookieJar::new(),
            Path(bucket.to_string()),
            list_objects_query(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, expected);
    }

    async fn expect_update_bucket_error(
        state: &crate::api::AppState,
        headers: HeaderMap,
        bucket: &str,
        payload: Json<UpdateBucketRequest>,
        expected: StatusCode,
    ) {
        let err = update_bucket(
            State(state.clone()),
            headers,
            CookieJar::new(),
            Path(bucket.to_string()),
            payload,
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, expected);
    }

    async fn expect_get_object_detail_error(
        state: &crate::api::AppState,
        headers: HeaderMap,
        bucket: &str,
        key: &str,
        expected: StatusCode,
    ) {
        let err = get_object_detail(
            State(state.clone()),
            headers,
            CookieJar::new(),
            Path((bucket.to_string(), key.to_string())),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, expected);
    }

    #[tokio::test]
    async fn login_marks_admin_user() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let payload = Json(LoginRequest {
            username: state.config.admin_bootstrap_user.clone(),
            password: state.config.admin_bootstrap_password.clone(),
        });
        let (_jar, response) = login(State(state), CookieJar::new(), payload)
            .await
            .expect("login");
        assert!(response.0.user.is_admin);
    }

    #[tokio::test]
    async fn auth_config_reports_oidc_mode() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.auth_mode = AuthMode::Oidc;
        state.config.oidc = Some(sample_oidc_config());
        let Json(response): Json<AuthConfigResponse> = auth_config(State(state)).await;
        assert_eq!(response.mode, "oidc");
        assert!(response.external_auth_enabled);
        assert_eq!(response.external_auth_type.as_deref(), Some("oidc"));
        assert_eq!(
            response.external_login_path.as_deref(),
            Some("/console/v1/oidc/start")
        );
        assert!(response.oidc_enabled);
        assert_eq!(
            response.oidc_login_path.as_deref(),
            Some("/console/v1/oidc/start")
        );
    }

    #[tokio::test]
    async fn auth_config_reports_internal_mode() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let Json(response): Json<AuthConfigResponse> = auth_config(State(state)).await;
        assert_eq!(response.mode, "internal");
        assert!(!response.external_auth_enabled);
        assert!(response.external_auth_type.is_none());
        assert!(response.external_login_path.is_none());
        assert!(!response.oidc_enabled);
        assert!(response.oidc_login_path.is_none());
    }

    #[tokio::test]
    async fn external_login_path_returns_none_for_internal_auth() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        assert!(external_login_path(&state).is_none());
    }

    #[tokio::test]
    async fn auth_config_reports_oauth2_and_saml2_modes() {
        let oauth = auth_config_for_external_mode(AuthMode::Oauth2).await;
        assert_external_auth_mode(&oauth, "oauth2");
        let saml = auth_config_for_external_mode(AuthMode::Saml2).await;
        assert_external_auth_mode(&saml, "saml2");
    }

    #[tokio::test]
    async fn oidc_start_rejects_disabled_and_missing_config() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let err = oidc_start(State(state.clone()), CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);

        let mut oidc_state = state;
        oidc_state.config.auth_mode = AuthMode::Oidc;
        oidc_state.config.oidc = None;
        let err = oidc_start(State(oidc_state), CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn callback_code_and_state_validates_required_fields() {
        let missing_code = callback_code_and_state(&oidc_query(None, Some("s")).0).unwrap_err();
        assert_eq!(missing_code.0, StatusCode::BAD_REQUEST);

        let missing_state = callback_code_and_state(&oidc_query(Some("c"), None).0).unwrap_err();
        assert_eq!(missing_state.0, StatusCode::BAD_REQUEST);

        let query = oidc_query(Some("c"), Some("s"));
        let values = callback_code_and_state(&query.0).expect("values");
        assert_eq!(values, ("c", "s"));
    }

    #[test]
    fn validate_oidc_state_and_nonce_validates_expected_cookies() {
        let jar = with_oidc_cookie(
            with_oidc_cookie(CookieJar::new(), OIDC_STATE_COOKIE, "state-1"),
            OIDC_NONCE_COOKIE,
            "nonce-1",
        );
        let nonce = validate_oidc_state_and_nonce(&jar, "state-1").expect("nonce");
        assert_eq!(nonce, "nonce-1");

        let state_err = validate_oidc_state_and_nonce(&jar, "state-2").unwrap_err();
        assert_eq!(state_err.0, StatusCode::UNAUTHORIZED);

        let nonce_err = validate_oidc_state_and_nonce(&CookieJar::new(), "state-1").unwrap_err();
        assert_eq!(nonce_err.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn clear_oidc_cookies_replaces_values() {
        let jar = with_oidc_cookie(
            with_oidc_cookie(CookieJar::new(), OIDC_STATE_COOKIE, "state-1"),
            OIDC_NONCE_COOKIE,
            "nonce-1",
        );
        let cleared = clear_oidc_cookies(jar);
        let state = cleared.get(OIDC_STATE_COOKIE).expect("state cookie");
        let nonce = cleared.get(OIDC_NONCE_COOKIE).expect("nonce cookie");
        assert!(state.value().is_empty());
        assert!(nonce.value().is_empty());
    }

    #[tokio::test]
    async fn oidc_callback_rejects_disabled_and_missing_config() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let err = oidc_callback(
            State(state.clone()),
            CookieJar::new(),
            oidc_query(Some("code"), Some("state-1")),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);

        let mut oidc_state = state;
        oidc_state.config.auth_mode = AuthMode::Oidc;
        oidc_state.config.oidc = None;
        let err = oidc_callback(
            State(oidc_state),
            CookieJar::new(),
            oidc_query(Some("code"), Some("state-1")),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn oidc_callback_validates_query_and_cookie_state() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.auth_mode = AuthMode::Oidc;
        state.config.oidc = Some(sample_oidc_config());
        let missing_code = oidc_callback(
            State(state.clone()),
            CookieJar::new(),
            oidc_query(None, Some("state-1")),
        )
        .await
        .unwrap_err();
        assert_eq!(missing_code.0, StatusCode::BAD_REQUEST);
        let missing_nonce = oidc_callback(
            State(state),
            with_oidc_cookie(CookieJar::new(), OIDC_STATE_COOKIE, "state-1"),
            oidc_query(Some("code"), Some("state-1")),
        )
        .await
        .unwrap_err();
        assert_eq!(missing_nonce.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn oidc_start_and_callback_map_exchange_errors() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.auth_mode = AuthMode::Oidc;
        let mut oidc = sample_oidc_config();
        oidc.issuer_url = "http://127.0.0.1:1".to_string();
        state.config.oidc = Some(oidc);
        let err = oidc_start(State(state.clone()), CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_GATEWAY);
        let jar = with_oidc_cookie(
            with_oidc_cookie(CookieJar::new(), OIDC_STATE_COOKIE, "state-1"),
            OIDC_NONCE_COOKIE,
            "nonce-1",
        );
        let err = oidc_callback(State(state), jar, oidc_query(Some("code"), Some("state-1")))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn oidc_start_success_sets_transient_cookies() {
        let (issuer, handle) = spawn_oidc_discovery_server().await;
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.auth_mode = AuthMode::Oidc;
        let mut oidc = sample_oidc_config();
        oidc.issuer_url = issuer;
        state.config.oidc = Some(oidc);
        let (jar, _redirect) = oidc_start(State(state), CookieJar::new())
            .await
            .expect("start");
        assert!(jar.get(OIDC_STATE_COOKIE).is_some());
        assert!(jar.get(OIDC_NONCE_COOKIE).is_some());
        handle.abort();
    }

    #[tokio::test]
    async fn oidc_callback_success_sets_session_cookie() {
        let prev = std::env::var("NSS_TEST_OIDC_IDENTITY_JSON").ok();
        std::env::set_var(
            "NSS_TEST_OIDC_IDENTITY_JSON",
            r#"{"subject":"sub-1","username":"oidc-ok","display_name":"OIDC OK","is_admin":false}"#,
        );
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.auth_mode = AuthMode::Oidc;
        state.config.oidc = Some(sample_oidc_config());
        let jar = with_oidc_cookie(
            with_oidc_cookie(CookieJar::new(), OIDC_STATE_COOKIE, "state-1"),
            OIDC_NONCE_COOKIE,
            "nonce-1",
        );
        let (result_jar, _redirect) =
            oidc_callback(State(state), jar, oidc_query(Some("code"), Some("state-1")))
                .await
                .expect("callback");
        assert!(result_jar.get("nss_session").is_some());
        restore_env("NSS_TEST_OIDC_IDENTITY_JSON", prev);
    }

    #[tokio::test]
    async fn oidc_callback_maps_user_and_token_errors() {
        let prev = set_test_oidc_identity_json(
            r#"{"subject":"sub-2","username":"oidc-fail","display_name":"OIDC FAIL","is_admin":false}"#,
        );
        let (state, jar) = build_oidc_callback_state_and_jar().await;
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let user_err = oidc_callback(State(broken), jar.clone(), oidc_query(Some("code"), Some("state-1")))
            .await
            .unwrap_err();
        assert_eq!(user_err.0, StatusCode::UNAUTHORIZED);
        let _guard = crate::auth::token::force_issue_error_guard();
        let token_err = oidc_callback(State(state), jar, oidc_query(Some("code"), Some("state-1")))
            .await
            .unwrap_err();
        assert_eq!(token_err.0, StatusCode::INTERNAL_SERVER_ERROR);
        restore_env("NSS_TEST_OIDC_IDENTITY_JSON", prev);
    }

    #[tokio::test]
    async fn ensure_oidc_user_handles_existing_and_create_paths() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let hash = password::hash_password("secret").expect("hash");
        state
            .repo
            .create_user("oidc-disabled", None, &hash, "disabled")
            .await
            .expect("user");

        let disabled = ensure_oidc_user(&state, &sample_identity("oidc-disabled", false))
            .await
            .unwrap_err();
        assert_eq!(disabled.0, StatusCode::FORBIDDEN);

        let created = ensure_oidc_user(&state, &sample_identity("oidc-created", true))
            .await
            .expect("created");
        assert_eq!(created.username, "oidc-created");
        assert_eq!(created.status, "active");

        let hash = password::hash_password("secret").expect("hash");
        state
            .repo
            .create_user("oidc-active", None, &hash, "active")
            .await
            .expect("active");
        let existing = ensure_oidc_user(&state, &sample_identity("oidc-active", false))
            .await
            .expect("existing");
        assert_eq!(existing.username, "oidc-active");
    }

    #[tokio::test]
    async fn ensure_and_create_oidc_user_report_internal_errors() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let mut broken_state = state.clone();
        broken_state.repo = test_support::broken_repo();
        let lookup_err = ensure_oidc_user(&broken_state, &sample_identity("oidc-broken", false))
            .await
            .unwrap_err();
        assert_eq!(lookup_err.0, StatusCode::UNAUTHORIZED);
        let prev = std::env::var("NSS_FORCE_OIDC_HASH_ERROR").ok();
        std::env::set_var("NSS_FORCE_OIDC_HASH_ERROR", "1");
        let hash_err = create_oidc_user(&state, &sample_identity("oidc-hash", false))
            .await
            .unwrap_err();
        assert_eq!(hash_err.0, StatusCode::INTERNAL_SERVER_ERROR);
        restore_env("NSS_FORCE_OIDC_HASH_ERROR", prev);
        let create_err = create_oidc_user(&broken_state, &sample_identity("oidc-create", false))
            .await
            .unwrap_err();
        assert_eq!(create_err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn ensure_bucket_mutable_rejects_worm_buckets() {
        let bucket = crate::meta::models::Bucket {
            id: Uuid::new_v4(),
            name: "worm-bucket".to_string(),
            owner_user_id: Uuid::new_v4(),
            created_at: chrono::Utc::now(),
            versioning_status: "suspended".to_string(),
            public_read: false,
            is_worm: true,
            lifecycle_config_xml: None,
            cors_config_xml: None,
            website_config_xml: None,
            notification_config_xml: None,
        };
        let err = ensure_bucket_mutable(&bucket).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn update_bucket_and_object_reject_worm_bucket() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (user, token) = create_user_and_token(&state).await;
        let headers = auth_headers(&token);
        let bucket = create_worm_console_bucket(&state, user.id).await;
        expect_update_bucket_error(
            &state,
            headers.clone(),
            &bucket.name,
            update_bucket_payload(None, None),
            StatusCode::FORBIDDEN,
        )
        .await;
        expect_update_object_error(
            &state,
            headers,
            &bucket.name,
            "worm.txt",
            StatusCode::FORBIDDEN,
        )
        .await;
    }

    #[tokio::test]
    async fn me_rejects_missing_token_before_claim_lookup() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let err = me(State(state), HeaderMap::new(), CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    async fn assert_password_login_rejected_for_mode(mode: AuthMode) {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.auth_mode = mode;
        state.config.oidc = Some(sample_oidc_config());
        let err = login(
            State(state),
            CookieJar::new(),
            Json(LoginRequest {
                username: "user".to_string(),
                password: "secret".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn password_login_is_rejected_in_external_auth_modes() {
        assert_password_login_rejected_for_mode(AuthMode::Oidc).await;
        assert_password_login_rejected_for_mode(AuthMode::Oauth2).await;
        assert_password_login_rejected_for_mode(AuthMode::Saml2).await;
    }

    #[tokio::test]
    async fn login_logout_and_me_flow() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let hash = password::hash_password("secret").expect("hash");
        state
            .repo
            .create_user("console-login", None, &hash, "active")
            .await
            .expect("user");
        let payload = Json(LoginRequest {
            username: "console-login".to_string(),
            password: "secret".to_string(),
        });
        let (jar, _response) = login(State(state.clone()), CookieJar::new(), payload)
            .await
            .expect("login");
        assert!(jar.get("nss_session").is_some());

        let me_response = me(State(state.clone()), HeaderMap::new(), jar.clone())
            .await
            .expect("me");
        assert_eq!(me_response.0.username, "console-login");
        assert!(!me_response.0.is_admin);

        let (_jar, status) = logout(jar).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn login_fails_for_inactive_user() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let hash = password::hash_password("secret").expect("hash");
        state
            .repo
            .create_user("inactive", None, &hash, "disabled")
            .await
            .expect("user");
        let payload = Json(LoginRequest {
            username: "inactive".to_string(),
            password: "secret".to_string(),
        });
        let err = login(State(state), CookieJar::new(), payload)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_fails_for_unknown_user() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let payload = Json(LoginRequest {
            username: "missing".to_string(),
            password: "secret".to_string(),
        });
        let err = login(State(state), CookieJar::new(), payload)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn change_password_updates_credentials() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let hash = password::hash_password("old-secret").expect("hash");
        let user = state
            .repo
            .create_user("password-user", None, &hash, "active")
            .await
            .expect("user");
        let token = state.token_manager.issue(user.id, false).expect("token");
        let status = change_password(
            State(state.clone()),
            auth_headers(&token),
            CookieJar::new(),
            change_password_payload("old-secret", "new-secret-123"),
        )
        .await
        .expect("change password");
        assert_eq!(status, StatusCode::NO_CONTENT);
        let payload = Json(LoginRequest {
            username: "password-user".to_string(),
            password: "new-secret-123".to_string(),
        });
        let result = login(State(state), CookieJar::new(), payload).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn change_password_rejects_invalid_requests() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let hash = password::hash_password("secret").expect("hash");
        let user = state
            .repo
            .create_user("password-errors", None, &hash, "active")
            .await
            .expect("user");
        let token = state.token_manager.issue(user.id, false).expect("token");
        expect_change_password_error(
            &state,
            HeaderMap::new(),
            change_password_payload("secret", "new-secret"),
            StatusCode::UNAUTHORIZED,
        )
        .await;
        assert_change_password_validation_errors(&state, &token).await;
        expect_change_password_error(
            &state,
            auth_headers(&token),
            change_password_payload(" ", " "),
            StatusCode::BAD_REQUEST,
        )
        .await;
    }

    #[tokio::test]
    async fn password_helpers_map_internal_errors() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let user = state
            .repo
            .create_user("bad-pass", None, "not-a-hash", "active")
            .await
            .expect("user");
        let verify_err = verify_current_password(&user, "secret").unwrap_err();
        assert_eq!(verify_err.0, StatusCode::UNAUTHORIZED);
        let hash_err = persist_new_password(&state, user.id, "__force_hash_error__")
            .await
            .unwrap_err();
        assert_eq!(hash_err.0, StatusCode::INTERNAL_SERVER_ERROR);
        let mut broken_state = state.clone();
        broken_state.repo = test_support::broken_repo();
        let update_err = persist_new_password(&broken_state, user.id, "new-secret-123")
            .await
            .unwrap_err();
        assert_eq!(update_err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn load_active_claim_user_reports_repo_error() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            user_id: Uuid::new_v4(),
            is_admin: false,
            exp: 1,
            iat: 1,
        };
        state.repo = test_support::broken_repo();
        let err = load_active_claim_user(&state, &claims).await.unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn load_active_claim_user_rejects_disabled_user() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let hash = password::hash_password("secret").expect("hash");
        let user = state
            .repo
            .create_user("disabled-claims", None, &hash, "disabled")
            .await
            .expect("user");
        let claims = Claims {
            sub: user.id.to_string(),
            user_id: user.id,
            is_admin: false,
            exp: 1,
            iat: 1,
        };
        let err = load_active_claim_user(&state, &claims).await.unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn load_active_claim_user_rejects_missing_user() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            user_id: Uuid::new_v4(),
            is_admin: false,
            exp: 1,
            iat: 1,
        };
        let err = load_active_claim_user(&state, &claims).await.unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn change_password_maps_user_lookup_and_hash_errors() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        assert_change_password_lookup_error(&state).await;
        assert_change_password_hash_error(&state).await;
    }

    #[test]
    fn restore_env_sets_existing_value() {
        let prev = std::env::var("NSS_TEST_RESTORE_ENV").ok();
        std::env::set_var("NSS_TEST_RESTORE_ENV", "original");
        restore_env("NSS_TEST_RESTORE_ENV", Some("restored".to_string()));
        let value = std::env::var("NSS_TEST_RESTORE_ENV").expect("value");
        assert_eq!(value, "restored");
        restore_env("NSS_TEST_RESTORE_ENV", prev);
    }

    #[tokio::test]
    async fn login_rejects_wrong_password() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let hash = password::hash_password("secret").expect("hash");
        state
            .repo
            .create_user("wrong-pass", None, &hash, "active")
            .await
            .expect("user");
        let payload = Json(LoginRequest {
            username: "wrong-pass".to_string(),
            password: "bad".to_string(),
        });
        let err = login(State(state), CookieJar::new(), payload)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_rate_limits_after_failures() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let mut last = None;
        for _ in 0..11 {
            let payload = Json(LoginRequest {
                username: "rate-limit".to_string(),
                password: "bad".to_string(),
            });
            last = Some(login(State(state.clone()), CookieJar::new(), payload).await);
        }
        let err = last.expect("result").unwrap_err();
        assert!(err.0 == StatusCode::UNAUTHORIZED || err.0 == StatusCode::TOO_MANY_REQUESTS);
    }

    async fn assert_login_repo_error() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        let payload = Json(LoginRequest {
            username: "missing".to_string(),
            password: "secret".to_string(),
        });
        let err = login(State(state), CookieJar::new(), payload)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    macro_rules! __assert_login_hash_and_issue_errors_body {
        () => {
            let (state, _pool, _dir) = test_support::build_state("master").await;
            let user = state
                .repo
                .create_user("bad-hash", None, "not-a-hash", "active")
                .await
                .expect("user");
            let payload = Json(LoginRequest {
                username: "bad-hash".to_string(),
                password: "secret".to_string(),
            });
            let err = login(State(state.clone()), CookieJar::new(), payload)
                .await
                .unwrap_err();
            assert_eq!(err.0, StatusCode::UNAUTHORIZED);
            let valid_hash = password::hash_password("secret").expect("hash");
            state
                .repo
                .update_user_password(user.id, &valid_hash)
                .await
                .expect("password update");
            let _issue_guard = force_issue_error_guard();
            let payload = Json(LoginRequest {
                username: "bad-hash".to_string(),
                password: "secret".to_string(),
            });
            let err = login(State(state), CookieJar::new(), payload)
                .await
                .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        };
    }

    async fn assert_login_hash_and_issue_errors() {
        __assert_login_hash_and_issue_errors_body!();
    }

    #[tokio::test]
    async fn login_reports_repo_and_hash_errors() {
        assert_login_repo_error().await;
        assert_login_hash_and_issue_errors().await;
    }

    #[tokio::test]
    async fn me_and_list_access_keys_error_paths() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        expect_me_error(&state, HeaderMap::new(), StatusCode::UNAUTHORIZED).await;
        expect_me_error(&state, auth_headers("bad"), StatusCode::UNAUTHORIZED).await;
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let token = state
            .token_manager
            .issue(state.node_id, false)
            .expect("token");
        expect_me_error(&broken, auth_headers(&token), StatusCode::UNAUTHORIZED).await;
        expect_list_access_keys_error(&state, HeaderMap::new(), StatusCode::UNAUTHORIZED).await;
        expect_list_access_keys_error(&state, auth_headers("bad"), StatusCode::UNAUTHORIZED).await;
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        expect_list_access_keys_error(
            &broken,
            auth_headers(&token),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
    }

    async fn assert_bucket_list_error_paths(state: &crate::api::AppState, token: &str) {
        expect_list_buckets_error(state, HeaderMap::new(), StatusCode::UNAUTHORIZED).await;
        expect_list_buckets_error(state, auth_headers("bad"), StatusCode::UNAUTHORIZED).await;
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        expect_list_buckets_error(
            &broken,
            auth_headers(token),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
    }

    async fn assert_object_list_error_paths(state: &crate::api::AppState, token: &str) {
        expect_list_objects_error(state, HeaderMap::new(), "missing", StatusCode::UNAUTHORIZED)
            .await;
        expect_list_objects_error(
            state,
            auth_headers("bad"),
            "missing",
            StatusCode::UNAUTHORIZED,
        )
        .await;
        expect_list_objects_error(state, auth_headers(token), "missing", StatusCode::NOT_FOUND)
            .await;
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        expect_list_objects_error(
            &broken,
            auth_headers(token),
            "missing",
            StatusCode::NOT_FOUND,
        )
        .await;
    }

    #[tokio::test]
    async fn bucket_and_object_error_paths() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let token = state
            .token_manager
            .issue(state.node_id, false)
            .expect("token");
        assert_bucket_list_error_paths(&state, &token).await;
        assert_object_list_error_paths(&state, &token).await;
    }

    macro_rules! __update_bucket_and_object_error_paths_body {
        () => {
            let (state, _pool, _dir) = test_support::build_state("master").await;
            let (user, token) = create_user_and_token(&state).await;
            let mut headers = auth_headers(&token);
            headers.insert("host", "localhost".parse().expect("host"));
            let empty_payload = update_bucket_payload(None, None);
            expect_update_bucket_error(
                &state,
                HeaderMap::new(),
                "missing",
                update_bucket_payload(None, None),
                StatusCode::UNAUTHORIZED,
            )
            .await;
            expect_update_bucket_error(
                &state,
                auth_headers("bad"),
                "missing",
                empty_payload,
                StatusCode::UNAUTHORIZED,
            )
            .await;
            expect_update_bucket_error(
                &state,
                headers.clone(),
                "missing",
                update_bucket_payload(None, None),
                StatusCode::NOT_FOUND,
            )
            .await;

            let bucket = state
                .repo
                .create_bucket("bucket-errors", user.id)
                .await
                .expect("bucket");
            let mut broken = state.clone();
            broken.repo = test_support::broken_repo();
            expect_update_bucket_error(
                &broken,
                headers.clone(),
                &bucket.name,
                update_bucket_payload(None, Some(true)),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .await;

            let mut broken = state.clone();
            broken.repo = test_support::broken_repo();
            expect_update_bucket_error(
                &broken,
                headers.clone(),
                &bucket.name,
                update_bucket_payload(Some("renamed"), None),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .await;
            expect_get_object_detail_error(
                &state,
                HeaderMap::new(),
                &bucket.name,
                "key",
                StatusCode::UNAUTHORIZED,
            )
            .await;
            expect_get_object_detail_error(
                &state,
                auth_headers("bad"),
                &bucket.name,
                "key",
                StatusCode::UNAUTHORIZED,
            )
            .await;
            expect_get_object_detail_error(
                &state,
                headers.clone(),
                "missing",
                "key",
                StatusCode::NOT_FOUND,
            )
            .await;
        };
    }

    #[tokio::test]
    async fn update_bucket_and_object_error_paths() {
        __update_bucket_and_object_error_paths_body!();
    }

    macro_rules! __update_object_and_download_url_error_paths_body {
        () => {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (user, token) = create_user_and_token(&state).await;
        let mut headers = auth_headers(&token);
        headers.insert("host", "localhost".parse().expect("host"));
        let bucket = state
            .repo
            .create_bucket("obj-errors", user.id)
            .await
            .expect("bucket");

        let err = update_object(
            State(state.clone()),
            HeaderMap::new(),
            CookieJar::new(),
            Path((bucket.name.clone(), "key".to_string())),
            Json(UpdateObjectRequest {
                new_key: None,
                metadata: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let err = update_object(
            State(state.clone()),
            auth_headers("bad"),
            CookieJar::new(),
            Path((bucket.name.clone(), "key".to_string())),
            Json(UpdateObjectRequest {
                new_key: None,
                metadata: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let err = update_object(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(("missing".to_string(), "key".to_string())),
            Json(UpdateObjectRequest {
                new_key: None,
                metadata: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);

        let other_user = state
            .repo
            .create_user("other", None, "hash", "active")
            .await
            .expect("user");
        let other_bucket = state
            .repo
            .create_bucket("other-bucket", other_user.id)
            .await
            .expect("bucket");
        let err = update_object(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path((other_bucket.name.clone(), "key".to_string())),
            Json(UpdateObjectRequest {
                new_key: None,
                metadata: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let err = update_object(
            State(broken),
            headers.clone(),
            CookieJar::new(),
            Path((bucket.name.clone(), "key".to_string())),
            Json(UpdateObjectRequest {
                new_key: Some("new".to_string()),
                metadata: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let err = update_object(
            State(broken),
            headers.clone(),
            CookieJar::new(),
            Path((bucket.name.clone(), "key".to_string())),
            Json(UpdateObjectRequest {
                new_key: None,
                metadata: Some(json!({"k":"v"})),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

        let err = get_object_download_url(
            State(state.clone()),
            HeaderMap::new(),
            CookieJar::new(),
            Path((bucket.name.clone(), "".to_string())),
            Query(ObjectUrlQuery {
                expires_seconds: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let err = get_object_download_url(
            State(state.clone()),
            auth_headers("bad"),
            CookieJar::new(),
            Path((bucket.name.clone(), "".to_string())),
            Query(ObjectUrlQuery {
                expires_seconds: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let mut headers = headers.clone();
        headers.insert("host", "localhost".parse().expect("host"));
        let err = get_object_download_url(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path((bucket.name.clone(), "missing".to_string())),
            Query(ObjectUrlQuery {
                expires_seconds: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);

        sqlx::query("ALTER TABLE object_versions RENAME TO object_versions_backup")
            .execute(state.repo.pool())
            .await
            .expect("rename");
        let result = get_object_download_url(
            State(state.clone()),
            headers,
            CookieJar::new(),
            Path((bucket.name.clone(), "missing".to_string())),
            Query(ObjectUrlQuery {
                expires_seconds: None,
            }),
        )
        .await;
        let _ = sqlx::query("ALTER TABLE object_versions_backup RENAME TO object_versions")
            .execute(state.repo.pool())
            .await;
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        };
    }

    #[tokio::test]
    async fn update_object_and_download_url_error_paths() {
        __update_object_and_download_url_error_paths_body!();
    }

    macro_rules! __download_url_and_access_key_errors_body {
        () => {
            let (state, _pool, _dir) = test_support::build_state("master").await;
            let (user, token) = create_user_and_token(&state).await;
            let mut headers = auth_headers(&token);
            headers.insert("host", "localhost".parse().expect("host"));
            let bucket = state
                .repo
                .create_bucket("download-errors", user.id)
                .await
                .expect("bucket");
            state
                .repo
                .finalize_object_version(
                    bucket.id,
                    "key",
                    "v1",
                    0,
                    "etag",
                    None,
                    &json!({}),
                    &json!({}),
                    &[],
                    false,
                )
                .await
                .expect("object");

            let _encrypt_guard = force_encrypt_error_guard();
            let err = get_object_download_url(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Path((bucket.name.clone(), "key".to_string())),
                Query(ObjectUrlQuery {
                    expires_seconds: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

            let mut broken = state.clone();
            broken.repo = test_support::broken_repo();
            let err = get_object_download_url(
                State(broken),
                headers.clone(),
                CookieJar::new(),
                Path((bucket.name.clone(), "key".to_string())),
                Query(ObjectUrlQuery {
                    expires_seconds: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::NOT_FOUND);

            let bad_headers = HeaderMap::new();
            let err = get_object_download_url(
                State(state.clone()),
                bad_headers,
                CookieJar::new(),
                Path((bucket.name.clone(), "key".to_string())),
                Query(ObjectUrlQuery {
                    expires_seconds: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);

            let mut state_with_public = state.clone();
            state_with_public.config.s3_public_url = Some("http://[::1".to_string());
            state_with_public
                .repo
                .update_bucket_public(bucket.id, true)
                .await
                .expect("public");
            state_with_public.repo = state.repo.clone();
            let err = get_object_download_url(
                State(state_with_public),
                headers.clone(),
                CookieJar::new(),
                Path((bucket.name.clone(), "key".to_string())),
                Query(ObjectUrlQuery {
                    expires_seconds: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);

            let mut state_with_invalid_presign = state.clone();
            state_with_invalid_presign.config.s3_public_url = Some("http://[::1".to_string());
            let err = get_object_download_url(
                State(state_with_invalid_presign),
                headers.clone(),
                CookieJar::new(),
                Path((bucket.name.clone(), "key".to_string())),
                Query(ObjectUrlQuery {
                    expires_seconds: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);
        };
    }

    #[tokio::test]
    async fn download_url_and_access_key_errors() {
        __download_url_and_access_key_errors_body!();
    }

    macro_rules! __access_key_and_presign_error_paths_body {
        () => {
            let (state, _pool, _dir) = test_support::build_state("master").await;
            let (_user, token) = create_user_and_token(&state).await;
            let mut headers = auth_headers(&token);
            headers.insert("host", "localhost".parse().expect("host"));

            let err = create_access_key(
                State(state.clone()),
                HeaderMap::new(),
                CookieJar::new(),
                Json(CreateAccessKeyRequest {
                    label: "label".to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::UNAUTHORIZED);

            let err = create_access_key(
                State(state.clone()),
                auth_headers("bad"),
                CookieJar::new(),
                Json(CreateAccessKeyRequest {
                    label: "label".to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::UNAUTHORIZED);

            let _encrypt_guard = force_encrypt_error_guard();
            let err = create_access_key(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Json(CreateAccessKeyRequest {
                    label: "label".to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

            let mut broken = state.clone();
            broken.repo = test_support::broken_repo();
            let err = create_access_key(
                State(broken),
                headers.clone(),
                CookieJar::new(),
                Json(CreateAccessKeyRequest {
                    label: "label".to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

            let err = update_access_key(
                State(state.clone()),
                HeaderMap::new(),
                CookieJar::new(),
                Path("ak".to_string()),
                Json(UpdateAccessKeyRequest {
                    status: "inactive".to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::UNAUTHORIZED);

            let err = update_access_key(
                State(state.clone()),
                auth_headers("bad"),
                CookieJar::new(),
                Path("ak".to_string()),
                Json(UpdateAccessKeyRequest {
                    status: "inactive".to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::UNAUTHORIZED);

            let mut broken = state.clone();
            broken.repo = test_support::broken_repo();
            let err = update_access_key(
                State(broken),
                headers.clone(),
                CookieJar::new(),
                Path("ak".to_string()),
                Json(UpdateAccessKeyRequest {
                    status: "inactive".to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

            let err = delete_access_key(
                State(state.clone()),
                HeaderMap::new(),
                CookieJar::new(),
                Path("ak".to_string()),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::UNAUTHORIZED);

            let err = delete_access_key(
                State(state.clone()),
                auth_headers("bad"),
                CookieJar::new(),
                Path("ak".to_string()),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::UNAUTHORIZED);

            let mut broken = state.clone();
            broken.repo = test_support::broken_repo();
            let err = delete_access_key(
                State(broken),
                headers.clone(),
                CookieJar::new(),
                Path("ak".to_string()),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

            let err = presign(
                State(state.clone()),
                HeaderMap::new(),
                CookieJar::new(),
                Json(PresignRequest {
                    method: "GET".to_string(),
                    bucket: "b".to_string(),
                    key: "k".to_string(),
                    expires_seconds: None,
                    access_key_id: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::UNAUTHORIZED);

            let err = presign(
                State(state.clone()),
                auth_headers("bad"),
                CookieJar::new(),
                Json(PresignRequest {
                    method: "GET".to_string(),
                    bucket: "b".to_string(),
                    key: "k".to_string(),
                    expires_seconds: None,
                    access_key_id: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::UNAUTHORIZED);

            let mut broken = state.clone();
            broken.repo = test_support::broken_repo();
            let err = presign(
                State(broken),
                headers.clone(),
                CookieJar::new(),
                Json(PresignRequest {
                    method: "GET".to_string(),
                    bucket: "b".to_string(),
                    key: "k".to_string(),
                    expires_seconds: None,
                    access_key_id: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

            let mut bad_headers = HeaderMap::new();
            bad_headers.insert(
                "Authorization",
                format!("Bearer {}", token).parse().expect("auth"),
            );
            let err = presign(
                State(state.clone()),
                bad_headers,
                CookieJar::new(),
                Json(PresignRequest {
                    method: "GET".to_string(),
                    bucket: "b".to_string(),
                    key: "k".to_string(),
                    expires_seconds: None,
                    access_key_id: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);

            let mut bad_state = state.clone();
            bad_state.config.s3_public_url = Some("http://[::1".to_string());
            let err = presign(
                State(bad_state),
                headers.clone(),
                CookieJar::new(),
                Json(PresignRequest {
                    method: "GET".to_string(),
                    bucket: "b".to_string(),
                    key: "k".to_string(),
                    expires_seconds: None,
                    access_key_id: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);
        };
    }

    #[tokio::test]
    async fn access_key_and_presign_error_paths() {
        __access_key_and_presign_error_paths_body!();
    }

    macro_rules! __resolve_signing_key_error_paths_body {
        () => {
            let (state, _pool, _dir) = test_support::build_state("master").await;
            let (user, _token) = create_user_and_token(&state).await;
            crypto::clear_force_encrypt_error();

            let mut broken = state.clone();
            broken.repo = test_support::broken_repo();
            let err = resolve_signing_key(&broken, user.id, Some("missing"))
                .await
                .unwrap_err();
            assert_eq!(err.0, StatusCode::FORBIDDEN);

            crypto::clear_force_encrypt_error();
            let secret =
                crypto::encrypt_secret(&state.encryption_key, b"\xff\xff").expect("encrypt");
            state
                .repo
                .create_access_key("BADUTF8", user.id, "label", "active", &secret)
                .await
                .expect("key");
            let err = resolve_signing_key(&state, user.id, Some("BADUTF8"))
                .await
                .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

            let other_key = vec![9u8; 32];
            crypto::clear_force_encrypt_error();
            let secret = crypto::encrypt_secret(&other_key, b"secret").expect("encrypt");
            state
                .repo
                .create_access_key("BADKEY", user.id, "label", "active", &secret)
                .await
                .expect("key");
            let err = resolve_signing_key(&state, user.id, Some("BADKEY"))
                .await
                .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

            let mut broken = state.clone();
            broken.repo = test_support::broken_repo();
            let err = resolve_signing_key(&broken, user.id, None)
                .await
                .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

            let _encrypt_guard = force_encrypt_error_guard();
            let err = resolve_signing_key(&state, user.id, None)
                .await
                .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

            let mut broken = state.clone();
            broken.repo = test_support::broken_repo();
            let err = resolve_signing_key(&broken, user.id, None)
                .await
                .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

            let other_user = state
                .repo
                .create_user("list-key-user", None, "hash", "active")
                .await
                .expect("user");
            crypto::clear_force_encrypt_error();
            let secret =
                crypto::encrypt_secret(&state.encryption_key, b"\xff\xff").expect("encrypt");
            state
                .repo
                .create_access_key("LISTUTF8", other_user.id, "label", "active", &secret)
                .await
                .expect("key");
            let err = resolve_signing_key(&state, other_user.id, None)
                .await
                .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

            let other_key = vec![7u8; 32];
            crypto::clear_force_encrypt_error();
            let secret = crypto::encrypt_secret(&other_key, b"secret").expect("encrypt");
            state
                .repo
                .create_access_key("LISTBAD", other_user.id, "label", "active", &secret)
                .await
                .expect("key");
            let err = resolve_signing_key(&state, other_user.id, None)
                .await
                .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        };
    }

    #[tokio::test]
    async fn resolve_signing_key_error_paths() {
        __resolve_signing_key_error_paths_body!();
    }

    #[tokio::test]
    async fn audit_record_errors_are_reported() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        let err = super::record_audit(&state, None, "action", "fail", None)
            .await
            .unwrap_err();
        assert!(err.contains("audit failed"));
    }

    macro_rules! __access_key_lifecycle_body {
        () => {
            let (state, _pool, _dir) = test_support::build_state("master").await;
            let (_user, token) = create_user_and_token(&state).await;
            let mut headers = auth_headers(&token);
            headers.insert("host", "localhost".parse().expect("host"));

            let list = list_access_keys(State(state.clone()), headers.clone(), CookieJar::new())
                .await
                .expect("list");
            assert!(list.0.is_empty());

            let created = create_access_key(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Json(CreateAccessKeyRequest {
                    label: "primary".to_string(),
                }),
            )
            .await
            .expect("create");
            assert!(!created.0.access_key_id.is_empty());
            assert!(!created.0.secret_access_key.is_empty());

            let status = update_access_key(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Path(created.0.access_key_id.clone()),
                Json(UpdateAccessKeyRequest {
                    status: "inactive".to_string(),
                }),
            )
            .await
            .expect("update");
            assert_eq!(status, StatusCode::NO_CONTENT);

            state
                .repo
                .touch_access_key_usage(&created.0.access_key_id)
                .await
                .expect("touch");
            let list = list_access_keys(State(state.clone()), headers.clone(), CookieJar::new())
                .await
                .expect("list");
            assert!(list.0[0].last_used_at.is_some());

            let status = delete_access_key(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Path(created.0.access_key_id),
            )
            .await
            .expect("delete");
            assert_eq!(status, StatusCode::NO_CONTENT);
        };
    }

    #[tokio::test]
    async fn access_key_lifecycle() {
        __access_key_lifecycle_body!();
    }

    macro_rules! __access_key_update_delete_forbidden_for_other_user_body {
        () => {
            let (state, _pool, _dir) = test_support::build_state("master").await;
            let (_owner, owner_token) = create_user_and_token(&state).await;
            let other_hash = password::hash_password("secret").expect("hash");
            let other = state
                .repo
                .create_user("access-key-other", None, &other_hash, "active")
                .await
                .expect("user");
            let other_token = state.token_manager.issue(other.id, false).expect("token");
            let owner_headers = auth_headers(&owner_token);
            let other_headers = auth_headers(&other_token);

            let created = create_access_key(
                State(state.clone()),
                owner_headers.clone(),
                CookieJar::new(),
                create_access_key_payload("owner-key"),
            )
            .await
            .expect("create");

            let err = update_access_key(
                State(state.clone()),
                other_headers.clone(),
                CookieJar::new(),
                Path(created.0.access_key_id.clone()),
                update_access_key_payload("inactive"),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::FORBIDDEN);

            let err = delete_access_key(
                State(state.clone()),
                other_headers,
                CookieJar::new(),
                Path(created.0.access_key_id.clone()),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::FORBIDDEN);

            let status = delete_access_key(
                State(state),
                owner_headers,
                CookieJar::new(),
                Path(created.0.access_key_id),
            )
            .await
            .expect("owner delete");
            assert_eq!(status, StatusCode::NO_CONTENT);
        };
    }

    #[tokio::test]
    async fn access_key_update_delete_forbidden_for_other_user() {
        __access_key_update_delete_forbidden_for_other_user_body!();
    }

    #[tokio::test]
    async fn register_login_failure_tracks_audit() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let err = register_login_failure(&state, "missing-user").await;
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_buckets_includes_versioning_and_public_fields() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (user, token) = create_user_and_token(&state).await;
        let headers = auth_headers(&token);
        let bucket = state
            .repo
            .create_bucket("bucket-fields", user.id)
            .await
            .expect("bucket");
        state
            .repo
            .update_bucket_versioning(bucket.id, "enabled")
            .await
            .expect("versioning");
        state
            .repo
            .update_bucket_public(bucket.id, true)
            .await
            .expect("public");

        let list = list_buckets(State(state), headers, CookieJar::new())
            .await
            .expect("list");
        let first = list.0.first().expect("bucket");
        assert_eq!(first["versioningStatus"], "enabled");
        assert_eq!(first["publicRead"], true);
        assert_eq!(first["isWorm"], false);
    }

    #[tokio::test]
    async fn update_bucket_renames_and_sets_public() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (user, token) = create_user_and_token(&state).await;
        let headers = auth_headers(&token);
        let bucket = state
            .repo
            .create_bucket("bucket-update", user.id)
            .await
            .expect("bucket");

        let payload = Json(UpdateBucketRequest {
            name: Some("bucket-updated".to_string()),
            public_read: Some(true),
        });
        let status = update_bucket(
            State(state.clone()),
            headers,
            CookieJar::new(),
            Path(bucket.name.clone()),
            payload,
        )
        .await
        .expect("update");
        assert_eq!(status, StatusCode::NO_CONTENT);

        let updated = state.repo.get_bucket("bucket-updated").await.expect("get");
        assert!(updated.expect("bucket").public_read);
    }

    macro_rules! __update_object_renames_and_updates_metadata_body {
        () => {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (user, token) = create_user_and_token(&state).await;
        let headers = auth_headers(&token);
        let bucket = state
            .repo
            .create_bucket("object-update", user.id)
            .await
            .expect("bucket");
        let chunk_id = Uuid::new_v4();
        let checksum = Checksum::compute(state.config.checksum_algo, b"data");
        state
            .repo
            .insert_chunk_metadata(chunk_id, 4, checksum.algo.as_str(), &checksum.value)
            .await
            .expect("chunk");
        state
            .repo
            .finalize_object_version(
                bucket.id,
                "old-key",
                "v1",
                4,
                "etag",
                Some("text/plain"),
                &json!({}),
                &json!({}),
                &[chunk_id],
                false,
            )
            .await
            .expect("object");

        let payload = Json(UpdateObjectRequest {
            new_key: Some("new-key".to_string()),
            metadata: Some(json!({ "owner": "user" })),
        });
        let status = update_object(
            State(state.clone()),
            headers,
            CookieJar::new(),
            Path(("object-update".to_string(), "old-key".to_string())),
            payload,
        )
        .await
        .expect("update");
        assert_eq!(status, StatusCode::NO_CONTENT);

        let updated = state
            .repo
            .get_object_current(bucket.id, "new-key")
            .await
            .expect("object")
            .expect("exists")
            .0;
        assert_eq!(updated.metadata_json, json!({ "owner": "user" }));
        };
    }

    #[tokio::test]
    async fn update_object_renames_and_updates_metadata() {
        __update_object_renames_and_updates_metadata_body!();
    }

    #[tokio::test]
    async fn update_object_rejects_blank_key() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (user, token) = create_user_and_token(&state).await;
        let headers = auth_headers(&token);
        let bucket = state
            .repo
            .create_bucket("object-blank", user.id)
            .await
            .expect("bucket");
        let payload = Json(UpdateObjectRequest {
            new_key: Some("   ".to_string()),
            metadata: None,
        });
        let err = update_object(
            State(state),
            headers,
            CookieJar::new(),
            Path((bucket.name, "key".to_string())),
            payload,
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    macro_rules! __get_object_detail_forbidden_for_other_user_body {
        () => {
            let (state, _pool, _dir) = test_support::build_state("master").await;
            let (_user, token) = create_user_and_token(&state).await;
            let other = state
                .repo
                .create_user("other-user", None, "hash", "active")
                .await
                .expect("user");
            let bucket = state
                .repo
                .create_bucket("detail-bucket", other.id)
                .await
                .expect("bucket");
            let chunk_id = Uuid::new_v4();
            let checksum = Checksum::compute(state.config.checksum_algo, b"data");
            state
                .repo
                .insert_chunk_metadata(chunk_id, 4, checksum.algo.as_str(), &checksum.value)
                .await
                .expect("chunk");
            state
                .repo
                .finalize_object_version(
                    bucket.id,
                    "secret",
                    "v1",
                    4,
                    "etag",
                    Some("text/plain"),
                    &json!({}),
                    &json!({}),
                    &[chunk_id],
                    false,
                )
                .await
                .expect("object");

            let headers = auth_headers(&token);
            let err = get_object_detail(
                State(state),
                headers,
                CookieJar::new(),
                Path(("detail-bucket".to_string(), "secret".to_string())),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::FORBIDDEN);
        };
    }

    #[tokio::test]
    async fn get_object_detail_forbidden_for_other_user() {
        __get_object_detail_forbidden_for_other_user_body!();
    }

    macro_rules! __get_object_download_url_for_private_bucket_uses_presign_body {
        () => {
            let (state, _pool, _dir) = test_support::build_state("master").await;
            let (user, token) = create_user_and_token(&state).await;
            let bucket = state
                .repo
                .create_bucket("private-bucket", user.id)
                .await
                .expect("bucket");
            let chunk_id = Uuid::new_v4();
            let checksum = Checksum::compute(state.config.checksum_algo, b"data");
            state
                .repo
                .insert_chunk_metadata(chunk_id, 4, checksum.algo.as_str(), &checksum.value)
                .await
                .expect("chunk");
            state
                .repo
                .finalize_object_version(
                    bucket.id,
                    "file.txt",
                    "v1",
                    4,
                    "etag",
                    Some("text/plain"),
                    &json!({}),
                    &json!({}),
                    &[chunk_id],
                    false,
                )
                .await
                .expect("object");

            let mut headers = auth_headers(&token);
            headers.insert("host", "localhost".parse().expect("host"));
            let response = get_object_download_url(
                State(state),
                headers,
                CookieJar::new(),
                Path(("private-bucket".to_string(), "file.txt".to_string())),
                Query(ObjectUrlQuery {
                    expires_seconds: Some(60),
                }),
            )
            .await
            .expect("url");
            assert!(!response.0.public);
            assert!(response.0.url.contains("X-Amz-Algorithm"));
        };
    }

    #[tokio::test]
    async fn get_object_download_url_for_private_bucket_uses_presign() {
        __get_object_download_url_for_private_bucket_uses_presign_body!();
    }

    macro_rules! __get_object_download_url_missing_host_for_private_bucket_reports_error_body {
        () => {
            let (state, _pool, _dir) = test_support::build_state("master").await;
            let (user, token) = create_user_and_token(&state).await;
            let bucket = state
                .repo
                .create_bucket("nohost-bucket", user.id)
                .await
                .expect("bucket");
            let chunk_id = Uuid::new_v4();
            let checksum = Checksum::compute(state.config.checksum_algo, b"data");
            state
                .repo
                .insert_chunk_metadata(chunk_id, 4, checksum.algo.as_str(), &checksum.value)
                .await
                .expect("chunk");
            state
                .repo
                .finalize_object_version(
                    bucket.id,
                    "file.txt",
                    "v1",
                    4,
                    "etag",
                    Some("text/plain"),
                    &json!({}),
                    &json!({}),
                    &[chunk_id],
                    false,
                )
                .await
                .expect("object");

            let headers = auth_headers(&token);
            let err = get_object_download_url(
                State(state),
                headers,
                CookieJar::new(),
                Path(("nohost-bucket".to_string(), "file.txt".to_string())),
                Query(ObjectUrlQuery {
                    expires_seconds: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);
        };
    }

    #[tokio::test]
    async fn get_object_download_url_missing_host_for_private_bucket_reports_error() {
        __get_object_download_url_missing_host_for_private_bucket_reports_error_body!();
    }

    macro_rules! __get_object_download_url_presign_invalid_endpoint_reports_error_body {
        () => {
            let (state, _pool, _dir) = test_support::build_state("master").await;
            let (user, token) = create_user_and_token(&state).await;
            let bucket = state
                .repo
                .create_bucket("presign-error", user.id)
                .await
                .expect("bucket");
            let chunk_id = Uuid::new_v4();
            let checksum = Checksum::compute(state.config.checksum_algo, b"data");
            state
                .repo
                .insert_chunk_metadata(chunk_id, 4, checksum.algo.as_str(), &checksum.value)
                .await
                .expect("chunk");
            state
                .repo
                .finalize_object_version(
                    bucket.id,
                    "file.txt",
                    "v1",
                    4,
                    "etag",
                    Some("text/plain"),
                    &json!({}),
                    &json!({}),
                    &[chunk_id],
                    false,
                )
                .await
                .expect("object");

            let mut bad_state = state.clone();
            bad_state.config.s3_public_url = Some("http://[".to_string());
            let mut headers = auth_headers(&token);
            headers.insert("host", "localhost".parse().expect("host"));
            let err = get_object_download_url(
                State(bad_state),
                headers,
                CookieJar::new(),
                Path(("presign-error".to_string(), "file.txt".to_string())),
                Query(ObjectUrlQuery {
                    expires_seconds: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);
        };
    }

    #[tokio::test]
    async fn get_object_download_url_presign_invalid_endpoint_reports_error() {
        __get_object_download_url_presign_invalid_endpoint_reports_error_body!();
    }

    #[test]
    fn validate_metadata_rejects_invalid_entries() {
        let err = validate_metadata(&json!({"": "value"})).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let err = validate_metadata(&json!({"key": 1})).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_access_key_reports_encryption_failure() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (_user, token) = create_user_and_token(&state).await;
        let headers = auth_headers(&token);
        let _guard = force_encrypt_error_guard();
        let err = create_access_key(
            State(state),
            headers,
            CookieJar::new(),
            Json(CreateAccessKeyRequest {
                label: "fail".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn resolve_signing_key_auto_creates_when_missing() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (user, _token) = create_user_and_token(&state).await;
        let (access_key_id, secret) = resolve_signing_key(&state, user.id, None)
            .await
            .expect("signing key");
        assert!(!access_key_id.is_empty());
        assert!(!secret.is_empty());
    }

    #[tokio::test]
    async fn resolve_signing_key_with_explicit_access_key() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (user, _token) = create_user_and_token(&state).await;
        let secret_plain = b"secret";
        let encrypted =
            crypto::encrypt_secret(&state.encryption_key, secret_plain).expect("encrypt");
        state
            .repo
            .create_access_key("EXPLICIT", user.id, "label", "active", &encrypted)
            .await
            .expect("key");
        let (_id, secret) = resolve_signing_key(&state, user.id, Some("EXPLICIT"))
            .await
            .expect("resolve");
        assert_eq!(secret, "secret");
    }

    #[test]
    fn build_object_url_handles_empty_key_and_invalid_endpoint() {
        let url = build_object_url("http://localhost:9000", "bucket", "").expect("url");
        assert!(url.ends_with("/bucket"));
        let err = build_object_url("not a url", "bucket", "key").unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn record_audit_succeeds() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        record_audit(
            &state,
            None,
            "console.test",
            "ok",
            Some(json!({"ok": true})),
        )
        .await
        .expect("audit");
    }

    #[test]
    fn resolve_s3_endpoint_handles_host_with_port() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "localhost:9010".parse().expect("host"));
        let config = test_support::base_config("master", std::path::PathBuf::from("/tmp"));
        let endpoint = resolve_s3_endpoint(&config, &headers).expect("endpoint");
        assert!(endpoint.ends_with(":9000"));
    }

    macro_rules! __bucket_and_object_flow_body {
        () => {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (user, token) = create_user_and_token(&state).await;
        let headers = auth_headers(&token);
        let bucket = state
            .repo
            .create_bucket("console-bucket", user.id)
            .await
            .expect("bucket");

        let list = list_buckets(State(state.clone()), headers.clone(), CookieJar::new())
            .await
            .expect("list");
        assert_eq!(list.0.len(), 1);

        let update = Json(UpdateBucketRequest {
            name: None,
            public_read: Some(true),
        });
        let status = update_bucket(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(bucket.name.clone()),
            update,
        )
        .await
        .expect("update bucket");
        assert_eq!(status, StatusCode::NO_CONTENT);

        let chunk_id = Uuid::new_v4();
        let checksum = Checksum::compute(state.config.checksum_algo, b"data");
        state
            .repo
            .insert_chunk_metadata(chunk_id, 4, checksum.algo.as_str(), &checksum.value)
            .await
            .expect("chunk");
        let object = state
            .repo
            .finalize_object_version(
                bucket.id,
                "key.txt",
                "v1",
                4,
                "etag",
                Some("text/plain"),
                &json!({}),
                &json!({}),
                &[chunk_id],
                false,
            )
            .await
            .expect("object");

        let query = Query(ListObjectsQuery {
            prefix: Some("key".to_string()),
            start_after: None,
            max_keys: Some(10),
        });
        let objects = list_objects(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path("console-bucket".to_string()),
            query,
        )
        .await
        .expect("objects");
        assert_eq!(objects.0.len(), 1);

        let detail = get_object_detail(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(("console-bucket".to_string(), "key.txt".to_string())),
        )
        .await
        .expect("detail");
        assert_eq!(detail.0.key, object.object_key);

        let update = Json(UpdateObjectRequest {
            new_key: Some("renamed.txt".to_string()),
            metadata: Some(json!({"owner":"user"})),
        });
        let status = update_object(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(("console-bucket".to_string(), "key.txt".to_string())),
            update,
        )
        .await
        .expect("update");
        assert_eq!(status, StatusCode::NO_CONTENT);

        let rename = Json(UpdateBucketRequest {
            name: Some("renamed-bucket".to_string()),
            public_read: None,
        });
        let status = update_bucket(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path("console-bucket".to_string()),
            rename,
        )
        .await
        .expect("rename bucket");
        assert_eq!(status, StatusCode::NO_CONTENT);
        };
    }

    #[tokio::test]
    async fn bucket_and_object_flow() {
        __bucket_and_object_flow_body!();
    }

    macro_rules! __bucket_access_forbidden_for_other_user_body {
        () => {
            let (state, _pool, _dir) = test_support::build_state("master").await;
            let (owner, owner_token) = create_user_and_token(&state).await;
            let (other, other_token) = {
                let hash = password::hash_password("secret").expect("hash");
                let user = state
                    .repo
                    .create_user("other-user", None, &hash, "active")
                    .await
                    .expect("user");
                let token = state.token_manager.issue(user.id, false).expect("token");
                (user, token)
            };
            let bucket = state
                .repo
                .create_bucket("forbidden-bucket", owner.id)
                .await
                .expect("bucket");
            let other_headers = auth_headers(&other_token);

            let query = Query(ListObjectsQuery {
                prefix: None,
                start_after: None,
                max_keys: Some(10),
            });
            let err = list_objects(
                State(state.clone()),
                other_headers.clone(),
                CookieJar::new(),
                Path(bucket.name.clone()),
                query,
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::FORBIDDEN);

            let update = Json(UpdateBucketRequest {
                name: None,
                public_read: Some(false),
            });
            let err = update_bucket(
                State(state.clone()),
                other_headers.clone(),
                CookieJar::new(),
                Path(bucket.name.clone()),
                update,
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::FORBIDDEN);

            let err = get_object_detail(
                State(state.clone()),
                other_headers.clone(),
                CookieJar::new(),
                Path((bucket.name.clone(), "key.txt".to_string())),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::FORBIDDEN);

            let err = get_object_download_url(
                State(state),
                other_headers,
                CookieJar::new(),
                Path((bucket.name, "key.txt".to_string())),
                Query(ObjectUrlQuery {
                    expires_seconds: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::FORBIDDEN);

            let _ = owner_token;
            let _ = other;
        };
    }

    #[tokio::test]
    async fn bucket_access_forbidden_for_other_user() {
        __bucket_access_forbidden_for_other_user_body!();
    }

    macro_rules! __update_bucket_validates_name_and_conflict_body {
        () => {
            let (state, _pool, _dir) = test_support::build_state("master").await;
            let (user, token) = create_user_and_token(&state).await;
            let headers = auth_headers(&token);
            state
                .repo
                .create_bucket("bucket-one", user.id)
                .await
                .expect("bucket");
            state
                .repo
                .create_bucket("bucket-two", user.id)
                .await
                .expect("bucket");

            let empty = Json(UpdateBucketRequest {
                name: Some("   ".to_string()),
                public_read: None,
            });
            let err = update_bucket(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Path("bucket-one".to_string()),
                empty,
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);

            let conflict = Json(UpdateBucketRequest {
                name: Some("bucket-two".to_string()),
                public_read: None,
            });
            let err = update_bucket(
                State(state),
                headers,
                CookieJar::new(),
                Path("bucket-one".to_string()),
                conflict,
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::CONFLICT);
        };
    }

    #[tokio::test]
    async fn update_bucket_validates_name_and_conflict() {
        __update_bucket_validates_name_and_conflict_body!();
    }

    macro_rules! __update_object_error_paths_body {
        () => {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (user, token) = create_user_and_token(&state).await;
        let headers = auth_headers(&token);
        let bucket = state
            .repo
            .create_bucket("object-errors", user.id)
            .await
            .expect("bucket");
        let chunk_id = Uuid::new_v4();
        let checksum = Checksum::compute(state.config.checksum_algo, b"data");
        state
            .repo
            .insert_chunk_metadata(chunk_id, 4, checksum.algo.as_str(), &checksum.value)
            .await
            .expect("chunk");
        state
            .repo
            .finalize_object_version(
                bucket.id,
                "alpha.txt",
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
            .expect("alpha");
        let chunk_id = Uuid::new_v4();
        state
            .repo
            .insert_chunk_metadata(chunk_id, 4, checksum.algo.as_str(), &checksum.value)
            .await
            .expect("chunk");
        state
            .repo
            .finalize_object_version(
                bucket.id,
                "beta.txt",
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
            .expect("beta");

        let empty_key = Json(UpdateObjectRequest {
            new_key: Some("   ".to_string()),
            metadata: None,
        });
        let err = update_object(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path((bucket.name.clone(), "alpha.txt".to_string())),
            empty_key,
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);

        let conflict = Json(UpdateObjectRequest {
            new_key: Some("beta.txt".to_string()),
            metadata: None,
        });
        let err = update_object(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path((bucket.name.clone(), "alpha.txt".to_string())),
            conflict,
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);

        let missing = Json(UpdateObjectRequest {
            new_key: Some("new.txt".to_string()),
            metadata: None,
        });
        let err = update_object(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path((bucket.name.clone(), "missing.txt".to_string())),
            missing,
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);

        let invalid_meta = Json(UpdateObjectRequest {
            new_key: None,
            metadata: Some(json!({"key": 1})),
        });
        let err = update_object(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path((bucket.name.clone(), "alpha.txt".to_string())),
            invalid_meta,
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);

        let missing_meta = Json(UpdateObjectRequest {
            new_key: None,
            metadata: Some(json!({"key": "value"})),
        });
        let err = update_object(
            State(state),
            headers,
            CookieJar::new(),
            Path((bucket.name, "missing.txt".to_string())),
            missing_meta,
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        };
    }

    #[tokio::test]
    async fn update_object_error_paths() {
        __update_object_error_paths_body!();
    }

    #[tokio::test]
    async fn me_rejects_missing_user() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (user, token) = create_user_and_token(&state).await;
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user.id)
            .execute(state.repo.pool())
            .await
            .expect("delete");
        let err = me(State(state), auth_headers(&token), CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_objects_reports_repo_error() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let (user, token) = create_user_and_token(&state).await;
        let headers = auth_headers(&token);
        let bucket = state
            .repo
            .create_bucket("list-error", user.id)
            .await
            .expect("bucket");
        let guard = TableRenameGuard::rename(&pool, "object_versions")
            .await
            .expect("rename");
        let result = list_objects(
            State(state),
            headers,
            CookieJar::new(),
            Path(bucket.name),
            Query(ListObjectsQuery {
                prefix: None,
                start_after: None,
                max_keys: None,
            }),
        )
        .await;
        guard.restore().await.expect("restore");
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    macro_rules! __update_bucket_reports_lookup_and_update_errors_body {
        () => {
            let (state, pool, _dir) = test_support::build_state("master").await;
            let (user, token) = create_user_and_token(&state).await;
            let headers = auth_headers(&token);
            let bucket = state
                .repo
                .create_bucket("bucket-errors", user.id)
                .await
                .expect("bucket");

            let trigger = FailTriggerGuard::create(&pool, "buckets", "BEFORE", "UPDATE")
                .await
                .expect("trigger");
            let err = update_bucket(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Path(bucket.name.clone()),
                Json(UpdateBucketRequest {
                    name: None,
                    public_read: Some(true),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

            let err = update_bucket(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Path(bucket.name.clone()),
                Json(UpdateBucketRequest {
                    name: Some("bucket-errors-rename".to_string()),
                    public_read: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
            trigger.remove().await.expect("trigger remove");

            let _guard = bucket_lookup_failpoint_guard();
            let err = update_bucket(
                State(state),
                headers,
                CookieJar::new(),
                Path(bucket.name),
                Json(UpdateBucketRequest {
                    name: Some("bucket-errors-new".to_string()),
                    public_read: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        };
    }

    #[tokio::test]
    async fn update_bucket_reports_lookup_and_update_errors() {
        __update_bucket_reports_lookup_and_update_errors_body!();
    }

    macro_rules! __get_object_detail_reports_repo_errors_body {
        () => {
            let (state, pool, _dir) = test_support::build_state("master").await;
            let (user, token) = create_user_and_token(&state).await;
            let headers = auth_headers(&token);
            let bucket = state
                .repo
                .create_bucket("detail-errors", user.id)
                .await
                .expect("bucket");

            let guard = TableRenameGuard::rename(&pool, "buckets")
                .await
                .expect("rename");
            let result = get_object_detail(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Path((bucket.name.clone(), "key".to_string())),
            )
            .await;
            guard.restore().await.expect("restore");
            let err = result.unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

            let guard = TableRenameGuard::rename(&pool, "object_versions")
                .await
                .expect("rename");
            let result = get_object_detail(
                State(state),
                headers,
                CookieJar::new(),
                Path((bucket.name, "key".to_string())),
            )
            .await;
            guard.restore().await.expect("restore");
            let err = result.unwrap_err();
            assert_eq!(err.0, StatusCode::NOT_FOUND);
        };
    }

    #[tokio::test]
    async fn get_object_detail_reports_repo_errors() {
        __get_object_detail_reports_repo_errors_body!();
    }

    macro_rules! __update_object_reports_repo_errors_body {
        () => {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let (user, token) = create_user_and_token(&state).await;
        let headers = auth_headers(&token);
        let bucket = state
            .repo
            .create_bucket("obj-repo-errors", user.id)
            .await
            .expect("bucket");
        let chunk_id = Uuid::new_v4();
        let checksum = Checksum::compute(state.config.checksum_algo, b"data");
        state
            .repo
            .insert_chunk_metadata(chunk_id, 4, checksum.algo.as_str(), &checksum.value)
            .await
            .expect("chunk");
        state
            .repo
            .finalize_object_version(
                bucket.id,
                "old-key",
                "v1",
                4,
                "etag",
                Some("text/plain"),
                &json!({}),
                &json!({}),
                &[chunk_id],
                false,
            )
            .await
            .expect("object");

        let guard = TableRenameGuard::rename(&pool, "object_versions")
            .await
            .expect("rename");
        let result = update_object(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path((bucket.name.clone(), "old-key".to_string())),
            Json(UpdateObjectRequest {
                new_key: Some("new-key".to_string()),
                metadata: None,
            }),
        )
        .await;
        guard.restore().await.expect("restore");
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

        let trigger = FailTriggerGuard::create(&pool, "object_versions", "BEFORE", "UPDATE")
            .await
            .expect("trigger");
        let err = update_object(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path((bucket.name.clone(), "old-key".to_string())),
            Json(UpdateObjectRequest {
                new_key: Some("newer-key".to_string()),
                metadata: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

        let err = update_object(
            State(state),
            headers,
            CookieJar::new(),
            Path((bucket.name, "old-key".to_string())),
            Json(UpdateObjectRequest {
                new_key: None,
                metadata: Some(json!({"k":"v"})),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        trigger.remove().await.expect("trigger remove");
        };
    }

    #[tokio::test]
    async fn update_object_reports_repo_errors() {
        __update_object_reports_repo_errors_body!();
    }

    macro_rules! __download_url_reports_missing_key_and_endpoint_errors_body {
        () => {
            let (state, _pool, _dir) = test_support::build_state("master").await;
            let (user, token) = create_user_and_token(&state).await;
            let mut headers = auth_headers(&token);
            let bucket = state
                .repo
                .create_bucket("download-endpoint", user.id)
                .await
                .expect("bucket");
            let chunk_id = Uuid::new_v4();
            let checksum = Checksum::compute(state.config.checksum_algo, b"data");
            state
                .repo
                .insert_chunk_metadata(chunk_id, 4, checksum.algo.as_str(), &checksum.value)
                .await
                .expect("chunk");
            state
                .repo
                .finalize_object_version(
                    bucket.id,
                    "key",
                    "v1",
                    4,
                    "etag",
                    Some("text/plain"),
                    &json!({}),
                    &json!({}),
                    &[chunk_id],
                    false,
                )
                .await
                .expect("object");

            let err = get_object_download_url(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Path((bucket.name.clone(), "".to_string())),
                Query(ObjectUrlQuery {
                    expires_seconds: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);

            headers.insert("host", "localhost".parse().expect("host"));
            let mut public_bucket = bucket.clone();
            public_bucket.public_read = true;
            state
                .repo
                .update_bucket_public(public_bucket.id, true)
                .await
                .expect("public");
            let err = get_object_download_url(
                State(state.clone()),
                auth_headers(&token),
                CookieJar::new(),
                Path((public_bucket.name.clone(), "key".to_string())),
                Query(ObjectUrlQuery {
                    expires_seconds: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);

            let err = get_object_download_url(
                State(state.clone()),
                auth_headers(&token),
                CookieJar::new(),
                Path((bucket.name.clone(), "key".to_string())),
                Query(ObjectUrlQuery {
                    expires_seconds: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);

            let mut bad_state = state.clone();
            bad_state.config.s3_public_url = Some("http://[::1".to_string());
            let err = get_object_download_url(
                State(bad_state),
                headers,
                CookieJar::new(),
                Path((bucket.name, "key".to_string())),
                Query(ObjectUrlQuery {
                    expires_seconds: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);
        };
    }

    #[tokio::test]
    async fn download_url_reports_missing_key_and_endpoint_errors() {
        __download_url_reports_missing_key_and_endpoint_errors_body!();
    }

    #[tokio::test]
    async fn download_url_reports_missing_bucket() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (_user, token) = create_user_and_token(&state).await;
        let headers = auth_headers(&token);
        let err = get_object_download_url(
            State(state),
            headers,
            CookieJar::new(),
            Path(("missing-bucket".to_string(), "key".to_string())),
            Query(ObjectUrlQuery {
                expires_seconds: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn resolve_signing_key_reports_auto_create_errors() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let (user, _token) = create_user_and_token(&state).await;

        {
            let _guard = force_encrypt_error_guard();
            let err = resolve_signing_key(&state, user.id, None)
                .await
                .unwrap_err();
            assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        }

        let guard = TableRenameGuard::rename(&pool, "access_keys")
            .await
            .expect("rename");
        let result = resolve_signing_key(&state, user.id, None).await;
        guard.restore().await.expect("restore");
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn resolve_signing_key_reports_create_access_key_error() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let (user, _token) = create_user_and_token(&state).await;
        let guard = FailTriggerGuard::create(&pool, "access_keys", "AFTER", "INSERT")
            .await
            .expect("guard");
        let err = resolve_signing_key(&state, user.id, None)
            .await
            .unwrap_err();
        guard.remove().await.expect("remove");
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn get_object_detail_rejects_empty_or_missing_key() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (user, token) = create_user_and_token(&state).await;
        let headers = auth_headers(&token);
        let bucket = state
            .repo
            .create_bucket("detail-bucket", user.id)
            .await
            .expect("bucket");

        let err = get_object_detail(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path((bucket.name.clone(), "".to_string())),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);

        let err = get_object_detail(
            State(state),
            headers,
            CookieJar::new(),
            Path((bucket.name, "missing.txt".to_string())),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    macro_rules! __list_objects_defaults_and_bucket_name_noop_body {
        () => {
            let (state, _pool, _dir) = test_support::build_state("master").await;
            let (user, token) = create_user_and_token(&state).await;
            let headers = auth_headers(&token);
            let bucket = state
                .repo
                .create_bucket("default-list", user.id)
                .await
                .expect("bucket");

            let query = Query(ListObjectsQuery {
                prefix: None,
                start_after: None,
                max_keys: None,
            });
            let result = list_objects(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Path(bucket.name.clone()),
                query,
            )
            .await
            .expect("list");
            assert!(result.0.is_empty());

            let same_name = Json(UpdateBucketRequest {
                name: Some(bucket.name.clone()),
                public_read: None,
            });
            let status = update_bucket(
                State(state),
                headers,
                CookieJar::new(),
                Path(bucket.name),
                same_name,
            )
            .await
            .expect("update");
            assert_eq!(status, StatusCode::NO_CONTENT);
        };
    }

    #[tokio::test]
    async fn list_objects_defaults_and_bucket_name_noop() {
        __list_objects_defaults_and_bucket_name_noop_body!();
    }

    macro_rules! __update_object_noop_on_same_key_body {
        () => {
            let (state, _pool, _dir) = test_support::build_state("master").await;
            let (user, token) = create_user_and_token(&state).await;
            let headers = auth_headers(&token);
            let bucket = state
                .repo
                .create_bucket("noop-bucket", user.id)
                .await
                .expect("bucket");
            let chunk_id = Uuid::new_v4();
            let checksum = Checksum::compute(state.config.checksum_algo, b"data");
            state
                .repo
                .insert_chunk_metadata(chunk_id, 4, checksum.algo.as_str(), &checksum.value)
                .await
                .expect("chunk");
            state
                .repo
                .finalize_object_version(
                    bucket.id,
                    "same.txt",
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
                .expect("object");

            let update = Json(UpdateObjectRequest {
                new_key: Some("same.txt".to_string()),
                metadata: None,
            });
            let status = update_object(
                State(state),
                headers,
                CookieJar::new(),
                Path((bucket.name, "same.txt".to_string())),
                update,
            )
            .await
            .expect("update");
            assert_eq!(status, StatusCode::NO_CONTENT);
        };
    }

    #[tokio::test]
    async fn update_object_noop_on_same_key() {
        __update_object_noop_on_same_key_body!();
    }

    #[tokio::test]
    async fn resolve_signing_key_rejects_unowned_access_key() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (user, _token) = create_user_and_token(&state).await;
        let other_hash = password::hash_password("secret").expect("hash");
        let other = state
            .repo
            .create_user("other-owner", None, &other_hash, "active")
            .await
            .expect("user");
        let secret = access_keys::generate_secret_access_key();
        let encrypted =
            crypto::encrypt_secret(&state.encryption_key, secret.as_bytes()).expect("encrypt");
        let access_key_id = access_keys::generate_access_key_id();
        state
            .repo
            .create_access_key(&access_key_id, other.id, "label", "active", &encrypted)
            .await
            .expect("create key");

        let err = resolve_signing_key(&state, user.id, Some(&access_key_id))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn helpers_cover_host_without_port_and_empty_key() {
        let config = test_support::base_config("master", std::env::temp_dir());
        let mut headers = HeaderMap::new();
        headers.insert("host", "example.com".parse().expect("host"));
        let endpoint = resolve_s3_endpoint(&config, &headers).expect("endpoint");
        assert_eq!(endpoint, "http://example.com:9000");

        let url = build_object_url("http://localhost:9000", "bucket", "").expect("url");
        assert!(url.ends_with("/bucket"));
    }

    macro_rules! __object_download_url_public_and_private_body {
        () => {
            let (mut state, _pool, _dir) = test_support::build_state("master").await;
            let (user, token) = create_user_and_token(&state).await;
            let headers = auth_headers(&token);
            let bucket = state
                .repo
                .create_bucket("public-bucket", user.id)
                .await
                .expect("bucket");
            state
                .repo
                .update_bucket_public(bucket.id, true)
                .await
                .expect("public");

            let chunk_id = Uuid::new_v4();
            let checksum = Checksum::compute(state.config.checksum_algo, b"data");
            state
                .repo
                .insert_chunk_metadata(chunk_id, 4, checksum.algo.as_str(), &checksum.value)
                .await
                .expect("chunk");
            state
                .repo
                .finalize_object_version(
                    bucket.id,
                    "key.txt",
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
                .expect("object");

            state.config.s3_public_url = Some("http://localhost:9000".to_string());
            let url = get_object_download_url(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Path(("public-bucket".to_string(), "key.txt".to_string())),
                Query(ObjectUrlQuery {
                    expires_seconds: None,
                }),
            )
            .await
            .expect("url");
            assert!(url.0.public);
            assert!(url.0.url.contains("/public-bucket/key.txt"));

            let bucket_private = state
                .repo
                .create_bucket("private-bucket", user.id)
                .await
                .expect("bucket");
            let chunk_id = Uuid::new_v4();
            state
                .repo
                .insert_chunk_metadata(chunk_id, 4, checksum.algo.as_str(), &checksum.value)
                .await
                .expect("chunk");
            state
                .repo
                .finalize_object_version(
                    bucket_private.id,
                    "secret.txt",
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
                .expect("object");

            let url = get_object_download_url(
                State(state.clone()),
                headers,
                CookieJar::new(),
                Path(("private-bucket".to_string(), "secret.txt".to_string())),
                Query(ObjectUrlQuery {
                    expires_seconds: Some(60),
                }),
            )
            .await
            .expect("url");
            assert!(!url.0.public);
        };
    }

    #[tokio::test]
    async fn object_download_url_public_and_private() {
        __object_download_url_public_and_private_body!();
    }

    macro_rules! __presign_and_signing_key_resolution_body {
        () => {
            let (state, _pool, _dir) = test_support::build_state("master").await;
            let (user, token) = create_user_and_token(&state).await;
            let mut headers = auth_headers(&token);
            headers.insert("host", "localhost:9000".parse().expect("host"));

            let request = Json(PresignRequest {
                method: "GET".to_string(),
                bucket: "bucket".to_string(),
                key: "object".to_string(),
                expires_seconds: Some(10),
                access_key_id: None,
            });
            let response = presign(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                request,
            )
            .await
            .expect("presign");
            assert!(response.0.url.contains("X-Amz-Algorithm"));

            let (access_key_id, _secret) = resolve_signing_key(&state, user.id, None)
                .await
                .expect("signing key");
            let err = resolve_signing_key(&state, user.id, Some("missing"))
                .await
                .unwrap_err();
            assert_eq!(err.0, StatusCode::FORBIDDEN);
            let _ = resolve_signing_key(&state, user.id, Some(&access_key_id))
                .await
                .expect("signing key");
        };
    }

    #[tokio::test]
    async fn presign_and_signing_key_resolution() {
        __presign_and_signing_key_resolution_body!();
    }

    #[test]
    fn helpers_validate_metadata_and_urls() {
        let err = validate_metadata(&json!("bad")).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let err = validate_metadata(&json!({"": "value"})).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let ok = validate_metadata(&json!({"key": "value"})).expect("ok");
        assert!(ok.is_object());

        let url = build_object_url("http://localhost:9000", "bucket", "key").expect("url");
        assert!(url.contains("/bucket/key"));
        let err = build_object_url("not a url", "bucket", "key").unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn resolve_s3_endpoint_prefers_public_url() {
        let mut config = test_support::base_config("master", std::env::temp_dir());
        config.s3_public_url = Some("http://public:9000".to_string());
        let headers = HeaderMap::new();
        let endpoint = resolve_s3_endpoint(&config, &headers).expect("endpoint");
        assert_eq!(endpoint, "http://public:9000");
    }

    #[test]
    fn resolve_s3_endpoint_uses_host_header() {
        let config = test_support::base_config("master", std::env::temp_dir());
        let mut headers = HeaderMap::new();
        headers.insert("host", "example.com:8080".parse().expect("host"));
        let endpoint = resolve_s3_endpoint(&config, &headers).expect("endpoint");
        assert_eq!(endpoint, "http://example.com:9000");

        let headers = HeaderMap::new();
        let err = resolve_s3_endpoint(&config, &headers).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }
}
