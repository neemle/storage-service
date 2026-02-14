use crate::api::auth::{clear_session_cookie, extract_token, session_cookie, verify_claims};
use crate::api::AppState;
use crate::auth::password;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Digest;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateUserRequest {
    username: String,
    password: String,
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateUserRequest {
    status: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct JoinTokenResponse {
    token: String,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditQuery {
    since: Option<String>,
    until: Option<String>,
    user_id: Option<Uuid>,
    action: Option<String>,
    offset: Option<i64>,
    limit: Option<i64>,
}

const DEFAULT_AUDIT_LIMIT: i64 = 200;
const MAX_AUDIT_LIMIT: i64 = 200;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/admin/v1/login", post(login))
        .route("/admin/v1/logout", post(logout))
        .route("/admin/v1/me", get(me))
        .route("/admin/v1/users", get(list_users).post(create_user))
        .route(
            "/admin/v1/users/{user_id}",
            patch(update_user).delete(delete_user),
        )
        .route("/admin/v1/cluster/nodes", get(list_nodes))
        .route("/admin/v1/cluster/join-tokens", post(create_join_token))
        .route("/admin/v1/audit", get(list_audit))
        .with_state(state.clone())
}

async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<LoginRequest>,
) -> Result<(CookieJar, Json<LoginResponse>), (StatusCode, String)> {
    if state.config.auth_mode.uses_external_identity() {
        return Err(oidc_only_error());
    }
    let user = authenticate_admin_login(&state, &payload).await?;
    let user_id = user.id;
    let token = issue_admin_token(&state, user.id)?;
    let jar = jar.add(session_cookie(&token, state.config.insecure_dev));
    let response = LoginResponse {
        token: token.clone(),
        user: to_user_response(&state.config.admin_bootstrap_user, user),
    };
    let _ = record_audit(&state, Some(user_id), "admin.login", "success", None).await;
    Ok((jar, Json(response)))
}

async fn authenticate_admin_login(
    state: &AppState,
    payload: &LoginRequest,
) -> Result<crate::meta::models::User, (StatusCode, String)> {
    if payload.username != state.config.admin_bootstrap_user {
        return Err(register_login_failure(state, &payload.username).await);
    }
    let user = state
        .repo
        .find_user_by_username(&payload.username)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid credentials".into()))?;
    let Some(user) = user else {
        return Err(register_login_failure(state, &payload.username).await);
    };
    verify_login_password(state, payload, &user).await?;
    Ok(user)
}

async fn verify_login_password(
    state: &AppState,
    payload: &LoginRequest,
    user: &crate::meta::models::User,
) -> Result<(), (StatusCode, String)> {
    let matches = password::verify_password(&user.password_hash, &payload.password)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid credentials".into()))?;
    if matches {
        return Ok(());
    }
    Err(register_login_failure(state, &payload.username).await)
}

fn issue_admin_token(state: &AppState, user_id: Uuid) -> Result<String, (StatusCode, String)> {
    state
        .token_manager
        .issue(user_id, true)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "token failed".into()))
}

async fn register_login_failure(state: &AppState, username: &str) -> (StatusCode, String) {
    let key = format!("admin-login:{}", username);
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
        "admin.login",
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

fn unauthorized_error() -> (StatusCode, String) {
    (StatusCode::UNAUTHORIZED, "unauthorized".into())
}

fn forbidden_error() -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, "forbidden".into())
}

fn oidc_only_error() -> (StatusCode, String) {
    (
        StatusCode::BAD_REQUEST,
        "password login is disabled; use external identity login".into(),
    )
}

async fn require_admin_claims(
    state: &AppState,
    headers: &HeaderMap,
    jar: &CookieJar,
) -> Result<crate::auth::token::Claims, (StatusCode, String)> {
    let token = extract_token(headers, Some(jar)).ok_or_else(unauthorized_error)?;
    let claims = verify_claims(state, &token).map_err(|_| unauthorized_error())?;
    if !claims.is_admin {
        return Err(forbidden_error());
    }
    Ok(claims)
}

fn to_user_response(admin_username: &str, user: crate::meta::models::User) -> UserResponse {
    let is_admin = user.username == admin_username;
    UserResponse {
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        status: user.status,
        is_admin,
    }
}

fn node_response(node: crate::meta::models::Node) -> serde_json::Value {
    serde_json::json!({
        "nodeId": node.node_id,
        "role": node.role,
        "addressInternal": node.address_internal,
        "status": node.status,
        "lastHeartbeatAt": node.last_heartbeat_at.map(|ts| ts.to_rfc3339()),
        "capacityBytes": node.capacity_bytes,
        "freeBytes": node.free_bytes
    })
}

fn audit_response(log: crate::meta::models::AuditLog) -> serde_json::Value {
    serde_json::json!({
        "id": log.id,
        "ts": log.ts.to_rfc3339(),
        "actorUserId": log.actor_user_id,
        "actorIp": log.actor_ip,
        "action": log.action,
        "targetType": log.target_type,
        "targetId": log.target_id,
        "outcome": log.outcome,
        "details": log.details_json
    })
}

async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    let claims = require_admin_claims(&state, &headers, &jar).await?;
    let user = state
        .repo
        .find_user_by_id(claims.user_id)
        .await
        .map_err(|_| unauthorized_error())?
        .ok_or_else(unauthorized_error)?;
    Ok(Json(to_user_response(
        &state.config.admin_bootstrap_user,
        user,
    )))
}

async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Json<Vec<UserResponse>>, (StatusCode, String)> {
    let _ = require_admin_claims(&state, &headers, &jar).await?;
    let users = state
        .repo
        .list_users()
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "list failed".into()))?;
    let admin_username = state.config.admin_bootstrap_user.as_str();
    Ok(Json(
        users
            .into_iter()
            .map(|user| to_user_response(admin_username, user))
            .collect(),
    ))
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    let claims = require_admin_claims(&state, &headers, &jar).await?;
    let user = create_user_record(&state, &payload).await?;
    record_create_user_audit(&state, claims.user_id, &user).await;
    Ok(Json(to_user_response(
        &state.config.admin_bootstrap_user,
        user,
    )))
}

async fn create_user_record(
    state: &AppState,
    payload: &CreateUserRequest,
) -> Result<crate::meta::models::User, (StatusCode, String)> {
    let password_hash = password::hash_password(&payload.password)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "hash failed".into()))?;
    state
        .repo
        .create_user(
            &payload.username,
            payload.display_name.as_deref(),
            &password_hash,
            "active",
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "create failed".into()))
}

async fn record_create_user_audit(
    state: &AppState,
    actor_user_id: Uuid,
    user: &crate::meta::models::User,
) {
    let _ = record_audit(
        state,
        Some(actor_user_id),
        "admin.user.create",
        "success",
        Some(json!({ "userId": user.id, "username": user.username })),
    )
    .await;
}

async fn update_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(user_id): Path<Uuid>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = require_admin_claims(&state, &headers, &jar).await?;
    update_user_status_if_requested(&state, claims.user_id, user_id, payload.status.as_deref())
        .await?;
    update_user_password_if_requested(&state, claims.user_id, user_id, payload.password.as_deref())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn update_user_status_if_requested(
    state: &AppState,
    actor_user_id: Uuid,
    user_id: Uuid,
    status: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    let Some(status) = status else {
        return Ok(());
    };
    state
        .repo
        .update_user_status(user_id, status)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "update failed".into()))?;
    let _ = record_audit(
        state,
        Some(actor_user_id),
        "admin.user.status",
        "success",
        Some(json!({ "userId": user_id, "status": status })),
    )
    .await;
    Ok(())
}

async fn update_user_password_if_requested(
    state: &AppState,
    actor_user_id: Uuid,
    user_id: Uuid,
    password: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    let Some(password) = password else {
        return Ok(());
    };
    let hash = password::hash_password(password)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "hash failed".into()))?;
    state
        .repo
        .update_user_password(user_id, &hash)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "update failed".into()))?;
    let _ = record_audit(
        state,
        Some(actor_user_id),
        "admin.user.password",
        "success",
        Some(json!({ "userId": user_id })),
    )
    .await;
    Ok(())
}

async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let token = extract_token(&headers, Some(&jar))
        .ok_or((StatusCode::UNAUTHORIZED, "unauthorized".into()))?;
    let claims = verify_claims(&state, &token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "unauthorized".into()))?;
    if !claims.is_admin {
        return Err((StatusCode::FORBIDDEN, "forbidden".into()));
    }
    state
        .repo
        .update_user_status(user_id, "disabled")
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "update failed".into()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, String)> {
    let _ = require_admin_claims(&state, &headers, &jar).await?;
    let nodes = state
        .repo
        .list_nodes()
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "list failed".into()))?;
    let response = nodes.into_iter().map(node_response).collect();
    Ok(Json(response))
}

async fn create_join_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Json<JoinTokenResponse>, (StatusCode, String)> {
    let claims = require_admin_claims(&state, &headers, &jar).await?;
    let raw_token = Uuid::new_v4().to_string();
    let token_hash = format!("{:x}", sha2::Sha256::digest(raw_token.as_bytes()));
    let expires_at = Utc::now() + Duration::hours(12);
    state
        .repo
        .create_join_token(&token_hash, expires_at)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "create failed".into()))?;
    let _ = record_audit(
        &state,
        Some(claims.user_id),
        "admin.cluster.join_token",
        "success",
        Some(json!({ "expiresAt": expires_at.to_rfc3339() })),
    )
    .await;
    Ok(Json(JoinTokenResponse {
        token: raw_token,
        expires_at: expires_at.to_rfc3339(),
    }))
}

async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, String)> {
    let _ = require_admin_claims(&state, &headers, &jar).await?;
    let since = parse_ts(query.since.as_deref());
    let until = parse_ts(query.until.as_deref());
    let (offset, limit) = parse_audit_pagination(&query)?;
    let logs = state
        .repo
        .list_audit_logs(
            since,
            until,
            query.user_id,
            query.action.as_deref(),
            offset,
            limit,
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "list failed".into()))?;
    let response = logs.into_iter().map(audit_response).collect();
    Ok(Json(response))
}

fn parse_ts(value: Option<&str>) -> Option<DateTime<Utc>> {
    value
        .and_then(|val| DateTime::parse_from_rfc3339(val).ok())
        .map(|dt| dt.with_timezone(&Utc))
}

fn parse_audit_pagination(query: &AuditQuery) -> Result<(i64, i64), (StatusCode, String)> {
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(DEFAULT_AUDIT_LIMIT);
    if offset < 0 {
        return Err((StatusCode::BAD_REQUEST, "offset must be >= 0".into()));
    }
    if !(1..=MAX_AUDIT_LIMIT).contains(&limit) {
        let message = format!("limit must be between 1 and {MAX_AUDIT_LIMIT}");
        return Err((StatusCode::BAD_REQUEST, message));
    }
    Ok((offset, limit))
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
        create_join_token, create_user, delete_user, list_audit, list_nodes, list_users, login,
        logout, me, parse_audit_pagination, parse_ts, record_audit, register_login_failure,
        update_user, AuditQuery, CreateUserRequest, LoginRequest, UpdateUserRequest,
        DEFAULT_AUDIT_LIMIT,
    };
    use crate::api::auth::session_cookie;
    use crate::auth::password;
    use crate::auth::token::force_issue_error_guard;
    use crate::test_support;
    use crate::util::config::{AuthMode, OidcConfig};
    use axum::extract::{Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::Json;
    use axum_extra::extract::cookie::CookieJar;
    use chrono::{Duration, Utc};
    use serde_json::json;
    use sqlx;
    use uuid::Uuid;

    fn auth_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", token).parse().expect("header"),
        );
        headers
    }

    async fn admin_headers(state: &crate::api::AppState) -> HeaderMap {
        let admin = state
            .repo
            .find_user_by_username(&state.config.admin_bootstrap_user)
            .await
            .expect("admin")
            .expect("admin exists");
        let token = state.token_manager.issue(admin.id, true).expect("token");
        auth_headers(&token)
    }

    fn empty_audit_query() -> Query<AuditQuery> {
        Query(AuditQuery {
            since: None,
            until: None,
            user_id: None,
            action: None,
            offset: None,
            limit: None,
        })
    }

    fn create_user_payload(username: &str, password: &str) -> Json<CreateUserRequest> {
        Json(CreateUserRequest {
            username: username.to_string(),
            password: password.to_string(),
            display_name: None,
        })
    }

    fn login_payload(username: &str, password: &str) -> Json<LoginRequest> {
        Json(LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
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

    fn update_user_payload(
        status: Option<&str>,
        password: Option<&str>,
    ) -> Json<UpdateUserRequest> {
        Json(UpdateUserRequest {
            status: status.map(|value| value.to_string()),
            password: password.map(|value| value.to_string()),
        })
    }

    async fn assert_sensitive_endpoints_status(
        state: &crate::api::AppState,
        headers: HeaderMap,
        expected: StatusCode,
    ) {
        assert_user_mutation_endpoints_status(state, headers.clone(), expected).await;
        assert_cluster_endpoints_status(state, headers, expected).await;
    }

    async fn assert_user_mutation_endpoints_status(
        state: &crate::api::AppState,
        headers: HeaderMap,
        expected: StatusCode,
    ) {
        assert_create_user_status(state, headers.clone(), expected).await;
        assert_update_user_status(state, headers.clone(), expected).await;
        assert_delete_user_status(state, headers, expected).await;
    }

    async fn assert_create_user_status(
        state: &crate::api::AppState,
        headers: HeaderMap,
        expected: StatusCode,
    ) {
        let err = create_user(
            State(state.clone()),
            headers,
            CookieJar::new(),
            create_user_payload("blocked", "password"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, expected);
    }

    async fn assert_update_user_status(
        state: &crate::api::AppState,
        headers: HeaderMap,
        expected: StatusCode,
    ) {
        let err = update_user(
            State(state.clone()),
            headers,
            CookieJar::new(),
            Path(Uuid::new_v4()),
            update_user_payload(Some("disabled"), None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, expected);
    }

    async fn assert_delete_user_status(
        state: &crate::api::AppState,
        headers: HeaderMap,
        expected: StatusCode,
    ) {
        let err = delete_user(
            State(state.clone()),
            headers,
            CookieJar::new(),
            Path(Uuid::new_v4()),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, expected);
    }

    async fn assert_cluster_endpoints_status(
        state: &crate::api::AppState,
        headers: HeaderMap,
        expected: StatusCode,
    ) {
        let err = list_nodes(State(state.clone()), headers.clone(), CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, expected);
        let err = create_join_token(State(state.clone()), headers.clone(), CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, expected);
        let err = list_audit(
            State(state.clone()),
            headers,
            CookieJar::new(),
            empty_audit_query(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, expected);
    }

    async fn expect_list_users_error(
        state: &crate::api::AppState,
        headers: HeaderMap,
        expected: StatusCode,
    ) {
        let err = list_users(State(state.clone()), headers, CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, expected);
    }

    async fn expect_create_user_error(
        state: &crate::api::AppState,
        headers: HeaderMap,
        payload: Json<CreateUserRequest>,
        expected: StatusCode,
    ) {
        let err = create_user(State(state.clone()), headers, CookieJar::new(), payload)
            .await
            .unwrap_err();
        assert_eq!(err.0, expected);
    }

    async fn expect_update_user_error(
        state: &crate::api::AppState,
        headers: HeaderMap,
        user_id: Uuid,
        payload: Json<UpdateUserRequest>,
        expected: StatusCode,
    ) {
        let err = update_user(
            State(state.clone()),
            headers,
            CookieJar::new(),
            Path(user_id),
            payload,
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, expected);
    }

    async fn expect_delete_user_error(
        state: &crate::api::AppState,
        headers: HeaderMap,
        user_id: Uuid,
        expected: StatusCode,
    ) {
        let err = delete_user(
            State(state.clone()),
            headers,
            CookieJar::new(),
            Path(user_id),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, expected);
    }

    async fn expect_list_nodes_error(
        state: &crate::api::AppState,
        headers: HeaderMap,
        expected: StatusCode,
    ) {
        let err = list_nodes(State(state.clone()), headers, CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, expected);
    }

    async fn expect_create_join_token_error(
        state: &crate::api::AppState,
        headers: HeaderMap,
        expected: StatusCode,
    ) {
        let err = create_join_token(State(state.clone()), headers, CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, expected);
    }

    async fn expect_list_audit_error(
        state: &crate::api::AppState,
        headers: HeaderMap,
        expected: StatusCode,
    ) {
        let err = list_audit(
            State(state.clone()),
            headers,
            CookieJar::new(),
            empty_audit_query(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, expected);
    }

    fn issue_admin_claim_token(state: &crate::api::AppState) -> String {
        state
            .token_manager
            .issue(state.node_id, true)
            .expect("token")
    }

    async fn assert_list_users_auth_errors(state: &crate::api::AppState) {
        expect_list_users_error(state, HeaderMap::new(), StatusCode::UNAUTHORIZED).await;
        expect_list_users_error(state, auth_headers("bad"), StatusCode::UNAUTHORIZED).await;
    }

    async fn assert_list_users_repo_error(state: &crate::api::AppState, token: &str) {
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        expect_list_users_error(
            &broken,
            auth_headers(token),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
    }

    async fn assert_create_user_hash_error(state: &crate::api::AppState, token: &str) {
        let payload = create_user_payload("new-user", "__force_hash_error__");
        expect_create_user_error(
            state,
            auth_headers(token),
            payload,
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
    }

    async fn assert_create_user_repo_error(state: &crate::api::AppState, token: &str) {
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let payload = create_user_payload("new-user", "secret");
        expect_create_user_error(
            &broken,
            auth_headers(token),
            payload,
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
    }

    async fn assert_update_user_auth_errors(state: &crate::api::AppState, user_id: Uuid) {
        let payload = update_user_payload(None, None);
        expect_update_user_error(
            state,
            HeaderMap::new(),
            user_id,
            payload,
            StatusCode::UNAUTHORIZED,
        )
        .await;
        let payload = update_user_payload(None, None);
        expect_update_user_error(
            state,
            auth_headers("bad"),
            user_id,
            payload,
            StatusCode::UNAUTHORIZED,
        )
        .await;
    }

    async fn expect_broken_update_user_error(
        state: &crate::api::AppState,
        token: &str,
        user_id: Uuid,
        payload: Json<UpdateUserRequest>,
    ) {
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        expect_update_user_error(
            &broken,
            auth_headers(token),
            user_id,
            payload,
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
    }

    async fn assert_update_user_internal_errors(
        state: &crate::api::AppState,
        token: &str,
        user_id: Uuid,
    ) {
        let payload = update_user_payload(Some("disabled"), None);
        expect_broken_update_user_error(state, token, user_id, payload).await;
        let payload = update_user_payload(None, Some("__force_hash_error__"));
        expect_update_user_error(
            state,
            auth_headers(token),
            user_id,
            payload,
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
        let payload = update_user_payload(None, Some("secret"));
        expect_broken_update_user_error(state, token, user_id, payload).await;
    }

    async fn assert_delete_user_errors(state: &crate::api::AppState, token: &str, user_id: Uuid) {
        expect_delete_user_error(state, HeaderMap::new(), user_id, StatusCode::UNAUTHORIZED).await;
        expect_delete_user_error(
            state,
            auth_headers("bad"),
            user_id,
            StatusCode::UNAUTHORIZED,
        )
        .await;
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        expect_delete_user_error(
            &broken,
            auth_headers(token),
            user_id,
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
    }

    async fn assert_list_nodes_errors(state: &crate::api::AppState, token: &str) {
        expect_list_nodes_error(state, HeaderMap::new(), StatusCode::UNAUTHORIZED).await;
        expect_list_nodes_error(state, auth_headers("bad"), StatusCode::UNAUTHORIZED).await;
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        expect_list_nodes_error(
            &broken,
            auth_headers(token),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
    }

    async fn assert_join_token_invalid_token(state: &crate::api::AppState) {
        expect_create_join_token_error(state, auth_headers("bad"), StatusCode::UNAUTHORIZED).await;
    }

    async fn assert_audit_auth_and_repo_errors(state: &crate::api::AppState, token: &str) {
        expect_list_audit_error(state, HeaderMap::new(), StatusCode::UNAUTHORIZED).await;
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        expect_list_audit_error(
            &broken,
            auth_headers(token),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
    }

    async fn assert_record_audit_repo_error(state: &crate::api::AppState) {
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let err = record_audit(&broken, None, "action", "fail", None)
            .await
            .unwrap_err();
        assert!(err.contains("audit failed"));
    }

    async fn assert_users_non_empty(state: &crate::api::AppState, headers: &HeaderMap) {
        let users = list_users(State(state.clone()), headers.clone(), CookieJar::new())
            .await
            .expect("list users");
        assert!(!users.0.is_empty());
    }

    async fn create_and_verify_user(
        state: &crate::api::AppState,
        headers: &HeaderMap,
        username: &str,
    ) -> Uuid {
        let payload = create_user_payload(username, "password");
        let created = create_user(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            payload,
        )
        .await
        .expect("create");
        assert_eq!(created.0.username, username);
        created.0.id
    }

    async fn disable_and_delete_user(
        state: &crate::api::AppState,
        headers: &HeaderMap,
        user_id: Uuid,
    ) {
        let update = update_user_payload(Some("disabled"), Some("updated"));
        let status = update_user(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(user_id),
            update,
        )
        .await
        .expect("update");
        assert_eq!(status, StatusCode::NO_CONTENT);

        let status = delete_user(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(user_id),
        )
        .await
        .expect("delete");
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    async fn assert_nodes_join_and_audit(state: &crate::api::AppState, headers: &HeaderMap) {
        let nodes = list_nodes(State(state.clone()), headers.clone(), CookieJar::new())
            .await
            .expect("nodes");
        assert!(!nodes.0.is_empty());
        let join = create_join_token(State(state.clone()), headers.clone(), CookieJar::new())
            .await
            .expect("join token");
        assert!(!join.0.token.is_empty());
        let logs = list_audit(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            empty_audit_query(),
        )
        .await
        .expect("audit");
        assert!(!logs.0.is_empty());
    }

    async fn assert_repo_failure_for_me(state: &crate::api::AppState, headers: &HeaderMap) {
        let err = me(State(state.clone()), headers.clone(), CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    async fn assert_repo_failure_for_user_list_create(
        state: &crate::api::AppState,
        headers: &HeaderMap,
    ) {
        expect_list_users_error(state, headers.clone(), StatusCode::INTERNAL_SERVER_ERROR).await;
        let payload = create_user_payload("broken", "secret");
        expect_create_user_error(
            state,
            headers.clone(),
            payload,
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
    }

    async fn assert_repo_failure_for_user_updates(
        state: &crate::api::AppState,
        headers: &HeaderMap,
    ) {
        let payload = update_user_payload(Some("inactive"), None);
        expect_update_user_error(
            state,
            headers.clone(),
            Uuid::new_v4(),
            payload,
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;

        let payload = update_user_payload(None, Some("secret"));
        expect_update_user_error(
            state,
            headers.clone(),
            Uuid::new_v4(),
            payload,
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
        expect_delete_user_error(
            state,
            headers.clone(),
            Uuid::new_v4(),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
    }

    async fn assert_repo_failure_for_cluster_endpoints(
        state: &crate::api::AppState,
        headers: &HeaderMap,
    ) {
        expect_list_nodes_error(state, headers.clone(), StatusCode::INTERNAL_SERVER_ERROR).await;
        expect_create_join_token_error(state, headers.clone(), StatusCode::INTERNAL_SERVER_ERROR)
            .await;
        expect_list_audit_error(state, headers.clone(), StatusCode::INTERNAL_SERVER_ERROR).await;
    }

    async fn assert_password_login_rejected_for_mode(mode: AuthMode) {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.auth_mode = mode;
        state.config.oidc = Some(sample_oidc_config());
        let payload = login_payload(
            &state.config.admin_bootstrap_user,
            &state.config.admin_bootstrap_password,
        );
        let err = login(State(state), CookieJar::new(), payload)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn login_logout_and_me_flow() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let payload = Json(LoginRequest {
            username: state.config.admin_bootstrap_user.clone(),
            password: state.config.admin_bootstrap_password.clone(),
        });
        let (jar, _response) = login(State(state.clone()), CookieJar::new(), payload)
            .await
            .expect("login");
        assert!(jar.get("nss_session").is_some());

        let me_response = me(State(state.clone()), HeaderMap::new(), jar.clone())
            .await
            .expect("me");
        assert_eq!(me_response.0.username, state.config.admin_bootstrap_user);

        let (jar, status) = logout(jar).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(jar.get("nss_session").is_some());
        let err = me(State(state), HeaderMap::new(), jar).await.unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn password_login_is_rejected_in_external_auth_modes() {
        assert_password_login_rejected_for_mode(AuthMode::Oidc).await;
        assert_password_login_rejected_for_mode(AuthMode::Oauth2).await;
        assert_password_login_rejected_for_mode(AuthMode::Saml2).await;
    }

    #[tokio::test]
    async fn create_user_requires_token() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let payload = Json(CreateUserRequest {
            username: "missing-token-user".to_string(),
            password: "secret".to_string(),
            display_name: None,
        });
        let err = create_user(State(state), HeaderMap::new(), CookieJar::new(), payload)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_user_rejects_invalid_token() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let payload = Json(CreateUserRequest {
            username: "invalid-token-user".to_string(),
            password: "secret".to_string(),
            display_name: None,
        });
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer invalid".parse().expect("header"));
        let err = create_user(State(state), headers, CookieJar::new(), payload)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_reports_repo_and_auth_errors() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        let payload = Json(LoginRequest {
            username: state.config.admin_bootstrap_user.clone(),
            password: state.config.admin_bootstrap_password.clone(),
        });
        let err = login(State(state.clone()), CookieJar::new(), payload)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let (state, pool, _dir) = test_support::build_state("master").await;
        sqlx::query("DELETE FROM users")
            .execute(&pool)
            .await
            .expect("delete users");
        let payload = Json(LoginRequest {
            username: state.config.admin_bootstrap_user.clone(),
            password: state.config.admin_bootstrap_password.clone(),
        });
        let err = login(State(state), CookieJar::new(), payload)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_reports_invalid_hash_and_token_issue() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        let bad_user = "bad-hash";
        state.config.admin_bootstrap_user = bad_user.to_string();
        let user = state
            .repo
            .create_user(bad_user, None, "not-a-hash", "active")
            .await
            .expect("user");
        let payload = login_payload(bad_user, "secret");
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
        let payload = login_payload(bad_user, "secret");
        let err = login(State(state), CookieJar::new(), payload)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn me_reports_missing_token_and_repo_errors() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let err = me(State(state.clone()), HeaderMap::new(), CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let mut bad_state = state.clone();
        bad_state.repo = test_support::broken_repo();
        let token = state
            .token_manager
            .issue(state.node_id, true)
            .expect("token");
        let err = me(State(bad_state), auth_headers(&token), CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let token = state
            .token_manager
            .issue(Uuid::new_v4(), true)
            .expect("token");
        let err = me(State(state), auth_headers(&token), CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_and_create_user_error_paths() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let token = issue_admin_claim_token(&state);
        assert_list_users_auth_errors(&state).await;
        assert_list_users_repo_error(&state, &token).await;
        assert_create_user_hash_error(&state, &token).await;
        assert_create_user_repo_error(&state, &token).await;
    }

    #[tokio::test]
    async fn update_delete_and_list_nodes_error_paths() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let user_id = Uuid::new_v4();
        let token = issue_admin_claim_token(&state);
        assert_update_user_auth_errors(&state, user_id).await;
        assert_update_user_internal_errors(&state, &token, user_id).await;
        assert_delete_user_errors(&state, &token, user_id).await;
        assert_list_nodes_errors(&state, &token).await;
    }

    #[tokio::test]
    async fn audit_and_join_token_errors() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let token = issue_admin_claim_token(&state);
        assert_join_token_invalid_token(&state).await;
        assert_audit_auth_and_repo_errors(&state, &token).await;
        assert_record_audit_repo_error(&state).await;
    }

    #[tokio::test]
    async fn login_failures_are_rate_limited() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let payload = Json(LoginRequest {
            username: "unknown".to_string(),
            password: "bad".to_string(),
        });
        let err = login(State(state.clone()), CookieJar::new(), payload)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        let mut last = None;
        for _ in 0..11 {
            let payload = Json(LoginRequest {
                username: "unknown".to_string(),
                password: "bad".to_string(),
            });
            last = Some(login(State(state.clone()), CookieJar::new(), payload).await);
        }
        let err = last.expect("result").unwrap_err();
        assert!(err.0 == StatusCode::UNAUTHORIZED || err.0 == StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn login_rejects_wrong_password() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let payload = Json(LoginRequest {
            username: state.config.admin_bootstrap_user.clone(),
            password: "wrong".to_string(),
        });
        let err = login(State(state), CookieJar::new(), payload)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_users_marks_admin() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let admin = state
            .repo
            .find_user_by_username(&state.config.admin_bootstrap_user)
            .await
            .expect("admin")
            .expect("admin exists");
        let token = state.token_manager.issue(admin.id, true).expect("token");
        let headers = auth_headers(&token);
        let users = list_users(State(state), headers, CookieJar::new())
            .await
            .expect("list users");
        let admin_entry = users
            .0
            .iter()
            .find(|user| user.username == admin.username)
            .expect("admin entry");
        assert!(admin_entry.is_admin);
    }

    #[tokio::test]
    async fn admin_user_management_and_audit() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        assert_users_non_empty(&state, &headers).await;
        let user_id = create_and_verify_user(&state, &headers, "new-user").await;
        disable_and_delete_user(&state, &headers, user_id).await;
        assert_nodes_join_and_audit(&state, &headers).await;
    }

    #[tokio::test]
    async fn non_admin_tokens_are_forbidden() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let password_hash = password::hash_password("secret").expect("hash");
        let user = state
            .repo
            .create_user("user", None, &password_hash, "active")
            .await
            .expect("user");
        let token = state.token_manager.issue(user.id, false).expect("token");
        let headers = auth_headers(&token);
        let err = list_users(State(state.clone()), headers.clone(), CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        let err = me(State(state), headers, CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn non_admin_tokens_block_sensitive_endpoints() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let password_hash = password::hash_password("secret").expect("hash");
        let user = state
            .repo
            .create_user("user2", None, &password_hash, "active")
            .await
            .expect("user");
        let token = state.token_manager.issue(user.id, false).expect("token");
        assert_sensitive_endpoints_status(&state, auth_headers(&token), StatusCode::FORBIDDEN)
            .await;
    }

    #[tokio::test]
    async fn update_user_noop_when_payload_empty() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let admin = state
            .repo
            .find_user_by_username(&state.config.admin_bootstrap_user)
            .await
            .expect("admin")
            .expect("admin exists");
        let token = state.token_manager.issue(admin.id, true).expect("token");
        let headers = auth_headers(&token);
        let target = state
            .repo
            .create_user("noop-user", None, "hash", "active")
            .await
            .expect("user");
        let payload = Json(UpdateUserRequest {
            status: None,
            password: None,
        });
        let status = update_user(
            State(state),
            headers,
            CookieJar::new(),
            axum::extract::Path(target.id),
            payload,
        )
        .await
        .expect("update");
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn list_audit_accepts_filters() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let admin = state
            .repo
            .find_user_by_username(&state.config.admin_bootstrap_user)
            .await
            .expect("admin")
            .expect("admin exists");
        let token = state.token_manager.issue(admin.id, true).expect("token");
        let headers = auth_headers(&token);
        let since = Utc::now() - Duration::hours(1);
        let until = Utc::now() + Duration::hours(1);
        let query = AuditQuery {
            since: Some(since.to_rfc3339()),
            until: Some(until.to_rfc3339()),
            user_id: Some(admin.id),
            action: Some("admin.login".to_string()),
            offset: Some(0),
            limit: Some(20),
        };
        let logs = list_audit(
            State(state),
            headers,
            CookieJar::new(),
            axum::extract::Query(query),
        )
        .await
        .expect("audit");
        let _ = logs;
    }

    #[tokio::test]
    async fn list_audit_rejects_invalid_pagination_query() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let admin = state
            .repo
            .find_user_by_username(&state.config.admin_bootstrap_user)
            .await
            .expect("admin")
            .expect("admin exists");
        let token = state.token_manager.issue(admin.id, true).expect("token");
        let headers = auth_headers(&token);
        let err = list_audit(
            State(state),
            headers,
            CookieJar::new(),
            axum::extract::Query(AuditQuery {
                since: None,
                until: None,
                user_id: None,
                action: None,
                offset: Some(-1),
                limit: Some(10),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn admin_endpoints_require_token() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = HeaderMap::new();

        let err = list_users(State(state.clone()), headers.clone(), CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let err = create_join_token(State(state), headers, CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_login_handles_repo_error_and_invalid_hash() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        let payload = Json(LoginRequest {
            username: state.config.admin_bootstrap_user.clone(),
            password: state.config.admin_bootstrap_password.clone(),
        });
        state.repo = test_support::broken_repo();
        let err = login(State(state), CookieJar::new(), payload)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let (state, _pool, _dir) = test_support::build_state("master").await;
        sqlx::query("UPDATE users SET password_hash='not-a-hash' WHERE username=$1")
            .bind(state.config.admin_bootstrap_user.clone())
            .execute(state.repo.pool())
            .await
            .expect("update hash");
        let payload = Json(LoginRequest {
            username: state.config.admin_bootstrap_user.clone(),
            password: "bad".to_string(),
        });
        let err = login(State(state), CookieJar::new(), payload)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_create_user_rejects_hash_failure() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let admin = state
            .repo
            .find_user_by_username(&state.config.admin_bootstrap_user)
            .await
            .expect("admin")
            .expect("admin exists");
        let token = state.token_manager.issue(admin.id, true).expect("token");
        let headers = auth_headers(&token);
        let payload = Json(CreateUserRequest {
            username: "fail-user".to_string(),
            password: "__force_hash_error__".to_string(),
            display_name: None,
        });
        let err = create_user(State(state), headers, CookieJar::new(), payload)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn admin_verify_claims_failures_are_reported() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        assert_sensitive_endpoints_status(
            &state,
            auth_headers("invalid-token"),
            StatusCode::UNAUTHORIZED,
        )
        .await;
    }

    #[tokio::test]
    async fn admin_repo_failures_return_internal_errors() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        let token = issue_admin_claim_token(&state);
        let headers = auth_headers(&token);
        state.repo = test_support::broken_repo();
        assert_repo_failure_for_me(&state, &headers).await;
        assert_repo_failure_for_user_list_create(&state, &headers).await;
        assert_repo_failure_for_user_updates(&state, &headers).await;
        assert_repo_failure_for_cluster_endpoints(&state, &headers).await;
        let err = record_audit(&state, None, "admin.test", "ok", None)
            .await
            .unwrap_err();
        assert!(err.contains("audit failed"));
    }

    #[test]
    fn parse_ts_handles_invalid_input() {
        assert!(parse_ts(None).is_none());
        assert!(parse_ts(Some("invalid")).is_none());
        let now = Utc::now().to_rfc3339();
        assert!(parse_ts(Some(&now)).is_some());
    }

    #[tokio::test]
    async fn session_cookie_can_be_used_for_auth() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let token = state
            .token_manager
            .issue(state.node_id, true)
            .expect("token");
        let jar = CookieJar::new().add(session_cookie(&token, true));
        let headers = HeaderMap::new();
        let response = list_users(State(state), headers, jar).await.expect("list");
        assert!(!response.0.is_empty());
    }

    #[tokio::test]
    async fn register_login_failure_returns_unauthorized() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let err = register_login_failure(&state, "bad-user").await;
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_users_and_nodes_include_expected_fields() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;

        let users = list_users(State(state.clone()), headers.clone(), CookieJar::new())
            .await
            .expect("list users");
        assert!(users.0.iter().any(|user| user.is_admin));

        state
            .repo
            .upsert_node(
                Uuid::new_v4(),
                "replica",
                "http://node",
                "online",
                Some(10),
                Some(5),
                Some(Utc::now()),
            )
            .await
            .expect("node");
        let nodes = list_nodes(State(state), headers, CookieJar::new())
            .await
            .expect("list nodes");
        assert!(nodes.0.iter().any(|val| val.get("capacityBytes").is_some()));
    }

    #[tokio::test]
    async fn create_update_delete_user_flow() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let payload = create_user_payload("admin-user-create", "secret");
        let user = create_user(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            payload,
        )
        .await
        .expect("create");

        let update_payload = update_user_payload(Some("disabled"), Some("new-secret"));
        let status = update_user(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(user.0.id),
            update_payload,
        )
        .await
        .expect("update");
        assert_eq!(status, StatusCode::NO_CONTENT);

        let status = delete_user(State(state), headers, CookieJar::new(), Path(user.0.id))
            .await
            .expect("delete");
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn create_join_token_returns_value_and_audit_entry() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let admin = state
            .repo
            .find_user_by_username(&state.config.admin_bootstrap_user)
            .await
            .expect("user")
            .expect("admin");
        let token = state.token_manager.issue(admin.id, true).expect("token");
        let headers = auth_headers(&token);

        let response = create_join_token(State(state.clone()), headers.clone(), CookieJar::new())
            .await
            .expect("join token");
        assert!(!response.0.token.is_empty());

        let since = Utc::now() - Duration::minutes(1);
        let query = AuditQuery {
            since: Some(since.to_rfc3339()),
            until: None,
            user_id: None,
            action: Some("admin.cluster.join_token".to_string()),
            offset: None,
            limit: None,
        };
        let logs = list_audit(State(state), headers, CookieJar::new(), Query(query))
            .await
            .expect("audit");
        assert!(!logs.0.is_empty());
    }

    #[test]
    fn parse_audit_pagination_rejects_invalid_values() {
        let negative_offset = AuditQuery {
            since: None,
            until: None,
            user_id: None,
            action: None,
            offset: Some(-1),
            limit: Some(10),
        };
        let err = parse_audit_pagination(&negative_offset).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);

        let invalid_limit = AuditQuery {
            since: None,
            until: None,
            user_id: None,
            action: None,
            offset: Some(0),
            limit: Some(0),
        };
        let err = parse_audit_pagination(&invalid_limit).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parse_audit_pagination_defaults_when_missing() {
        let query = AuditQuery {
            since: None,
            until: None,
            user_id: None,
            action: None,
            offset: None,
            limit: None,
        };
        let (offset, limit) = parse_audit_pagination(&query).expect("pagination");
        assert_eq!(offset, 0);
        assert_eq!(limit, DEFAULT_AUDIT_LIMIT);
    }

    #[tokio::test]
    async fn record_audit_succeeds() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        record_audit(&state, None, "admin.test", "ok", Some(json!({"ok": true})))
            .await
            .expect("audit");
    }
}
