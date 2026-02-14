use crate::api::auth::{extract_token, verify_claims};
use crate::api::AppState;
use crate::backup;
use crate::meta::backup_repos::{BackupPolicyCreate, BackupPolicyPatch};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

const DEFAULT_LIST_LIMIT: i64 = 50;
const MAX_LIST_LIMIT: i64 = 200;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateBucketWormRequest {
    is_worm: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpsertSnapshotPolicyRequest {
    bucket_name: String,
    trigger_kind: String,
    retention_count: i32,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSnapshotRequest {
    bucket_name: String,
    trigger_kind: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RestoreSnapshotRequest {
    bucket_name: String,
    owner_user_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateBackupPolicyRequest {
    name: String,
    scope: String,
    node_id: Option<Uuid>,
    source_bucket_name: String,
    backup_bucket_name: String,
    backup_type: String,
    schedule_kind: String,
    strategy: String,
    retention_count: i32,
    enabled: Option<bool>,
    external_targets: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateBackupPolicyRequest {
    name: Option<String>,
    backup_type: Option<String>,
    schedule_kind: Option<String>,
    strategy: Option<String>,
    retention_count: Option<i32>,
    enabled: Option<bool>,
    external_targets: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestBackupTargetRequest {
    target: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TestBackupTargetResponse {
    ok: bool,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReplicaModeRequest {
    sub_mode: String,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    offset: Option<i64>,
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ExportQuery {
    format: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplicaModeResponse {
    node_id: Uuid,
    sub_mode: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/admin/v1/storage/buckets/{bucket_name}/worm",
            patch(update_bucket_worm),
        )
        .route(
            "/admin/v1/storage/snapshot-policies",
            post(upsert_snapshot_policy).get(list_snapshot_policies),
        )
        .route("/admin/v1/storage/snapshots", post(create_snapshot))
        .route(
            "/admin/v1/storage/snapshots/{bucket_name}",
            get(list_snapshots),
        )
        .route(
            "/admin/v1/storage/snapshots/{snapshot_id}/restore",
            post(restore_snapshot),
        )
        .route(
            "/admin/v1/storage/backup-policies",
            post(create_backup_policy).get(list_backup_policies),
        )
        .route(
            "/admin/v1/storage/backup-targets/test",
            post(test_backup_target),
        )
        .route(
            "/admin/v1/storage/backup-policies/{policy_id}",
            patch(update_backup_policy),
        )
        .route(
            "/admin/v1/storage/backups/{policy_id}/run",
            post(run_backup_policy),
        )
        .route("/admin/v1/storage/backups/runs", get(list_backup_runs))
        .route(
            "/admin/v1/storage/backups/runs/{run_id}/export",
            get(export_backup_run),
        )
        .route(
            "/admin/v1/cluster/replicas/{node_id}/mode",
            patch(update_replica_mode),
        )
        .with_state(state)
}

fn unauthorized_error() -> (StatusCode, String) {
    (StatusCode::UNAUTHORIZED, "unauthorized".into())
}

fn forbidden_error() -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, "forbidden".into())
}

async fn require_admin(
    state: &AppState,
    headers: &HeaderMap,
    jar: &CookieJar,
) -> Result<Uuid, (StatusCode, String)> {
    let token = extract_token(headers, Some(jar)).ok_or_else(unauthorized_error)?;
    let claims = verify_claims(state, &token).map_err(|_| unauthorized_error())?;
    if !claims.is_admin {
        return Err(forbidden_error());
    }
    Ok(claims.user_id)
}

fn parse_list_query(query: &ListQuery) -> Result<(i64, i64), (StatusCode, String)> {
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(DEFAULT_LIST_LIMIT);
    if offset < 0 {
        return Err((StatusCode::BAD_REQUEST, "offset must be >= 0".into()));
    }
    if !(1..=MAX_LIST_LIMIT).contains(&limit) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("limit must be in 1..={MAX_LIST_LIMIT}"),
        ));
    }
    Ok((offset, limit))
}

async fn load_bucket_by_name(
    state: &AppState,
    name: &str,
) -> Result<crate::meta::models::Bucket, (StatusCode, String)> {
    state
        .repo
        .get_bucket(name)
        .await
        .map_err(internal_error)?
        .ok_or((StatusCode::NOT_FOUND, "bucket not found".into()))
}

fn internal_error(err: sqlx::Error) -> (StatusCode, String) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("internal error: {err}"),
    )
}

async fn update_bucket_worm(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(bucket_name): Path<String>,
    Json(payload): Json<UpdateBucketWormRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _ = require_admin(&state, &headers, &jar).await?;
    let bucket = load_bucket_by_name(&state, &bucket_name).await?;
    state
        .repo
        .update_bucket_worm(bucket.id, payload.is_worm)
        .await
        .map_err(internal_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn upsert_snapshot_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(payload): Json<UpsertSnapshotPolicyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let user_id = require_admin(&state, &headers, &jar).await?;
    if !backup::is_valid_snapshot_trigger(&payload.trigger_kind)
        || payload.trigger_kind == "on_demand"
    {
        return Err((StatusCode::BAD_REQUEST, "invalid snapshot trigger".into()));
    }
    if payload.retention_count < 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            "retentionCount must be >= 1".into(),
        ));
    }
    let bucket = load_bucket_by_name(&state, &payload.bucket_name).await?;
    let policy = state
        .repo
        .upsert_snapshot_policy(
            bucket.id,
            payload.trigger_kind.as_str(),
            payload.retention_count,
            payload.enabled,
            Some(user_id),
        )
        .await
        .map_err(internal_error)?;
    Ok(Json(json!(policy)))
}

async fn list_snapshot_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Json<Vec<crate::meta::models::BucketSnapshotPolicy>>, (StatusCode, String)> {
    let _ = require_admin(&state, &headers, &jar).await?;
    let policies = state
        .repo
        .list_snapshot_policies()
        .await
        .map_err(internal_error)?;
    Ok(Json(policies))
}

async fn create_snapshot(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(payload): Json<CreateSnapshotRequest>,
) -> Result<Json<crate::meta::models::BucketSnapshot>, (StatusCode, String)> {
    let user_id = require_admin(&state, &headers, &jar).await?;
    let trigger_kind = payload
        .trigger_kind
        .unwrap_or_else(|| "on_demand".to_string());
    if !backup::is_valid_snapshot_trigger(trigger_kind.as_str()) {
        return Err((StatusCode::BAD_REQUEST, "invalid snapshot trigger".into()));
    }
    let bucket = load_bucket_by_name(&state, &payload.bucket_name).await?;
    let snapshot = state
        .repo
        .create_bucket_snapshot(bucket.id, trigger_kind.as_str(), Some(user_id))
        .await
        .map_err(internal_error)?;
    Ok(Json(snapshot))
}

async fn list_snapshots(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(bucket_name): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<crate::meta::models::BucketSnapshot>>, (StatusCode, String)> {
    let _ = require_admin(&state, &headers, &jar).await?;
    let (offset, limit) = parse_list_query(&query)?;
    let bucket = load_bucket_by_name(&state, &bucket_name).await?;
    let snapshots = state
        .repo
        .list_bucket_snapshots(bucket.id, offset, limit)
        .await
        .map_err(internal_error)?;
    Ok(Json(snapshots))
}

async fn restore_snapshot(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(snapshot_id): Path<Uuid>,
    Json(payload): Json<RestoreSnapshotRequest>,
) -> Result<Json<crate::meta::models::Bucket>, (StatusCode, String)> {
    let _ = require_admin(&state, &headers, &jar).await?;
    let snapshot = state
        .repo
        .get_bucket_snapshot(snapshot_id)
        .await
        .map_err(internal_error)?
        .ok_or((StatusCode::NOT_FOUND, "snapshot not found".into()))?;
    let source_bucket = state
        .repo
        .get_bucket_by_id(snapshot.bucket_id)
        .await
        .map_err(internal_error)?
        .ok_or((StatusCode::NOT_FOUND, "source bucket not found".into()))?;
    let owner_user_id = payload.owner_user_id.unwrap_or(source_bucket.owner_user_id);
    let bucket = state
        .repo
        .create_bucket_from_snapshot(snapshot_id, payload.bucket_name.as_str(), owner_user_id)
        .await
        .map_err(internal_error)?;
    Ok(Json(bucket))
}

async fn create_backup_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(payload): Json<CreateBackupPolicyRequest>,
) -> Result<Json<crate::meta::models::BackupPolicy>, (StatusCode, String)> {
    let user_id = require_admin(&state, &headers, &jar).await?;
    validate_backup_policy_payload(&payload)?;
    validate_external_targets(payload.external_targets.as_ref())?;
    let source_bucket = load_bucket_by_name(&state, &payload.source_bucket_name).await?;
    let backup_bucket = load_bucket_by_name(&state, &payload.backup_bucket_name).await?;
    if !backup_bucket.is_worm {
        return Err((
            StatusCode::BAD_REQUEST,
            "backup bucket must be WORM-enabled".into(),
        ));
    }
    if let Some(node_id) = payload.node_id {
        let node = state.repo.get_node(node_id).await.map_err(internal_error)?;
        if node.is_none() {
            return Err((StatusCode::NOT_FOUND, "replica node not found".into()));
        }
    }
    let policy = state
        .repo
        .create_backup_policy(&BackupPolicyCreate {
            name: payload.name,
            scope: payload.scope,
            node_id: payload.node_id,
            source_bucket_id: source_bucket.id,
            backup_bucket_id: backup_bucket.id,
            backup_type: payload.backup_type,
            schedule_kind: payload.schedule_kind,
            strategy: payload.strategy,
            retention_count: payload.retention_count,
            enabled: payload.enabled.unwrap_or(true),
            external_targets_json: payload.external_targets.unwrap_or_else(|| json!([])),
            created_by_user_id: Some(user_id),
        })
        .await
        .map_err(internal_error)?;
    Ok(Json(policy))
}

fn validate_backup_policy_payload(
    payload: &CreateBackupPolicyRequest,
) -> Result<(), (StatusCode, String)> {
    if !backup::is_valid_backup_scope(payload.scope.as_str()) {
        return Err((StatusCode::BAD_REQUEST, "invalid backup scope".into()));
    }
    if !backup::is_valid_backup_type(payload.backup_type.as_str()) {
        return Err((StatusCode::BAD_REQUEST, "invalid backup type".into()));
    }
    if !backup::is_valid_backup_schedule(payload.schedule_kind.as_str()) {
        return Err((StatusCode::BAD_REQUEST, "invalid backup schedule".into()));
    }
    if !backup::is_valid_backup_strategy(payload.strategy.as_str()) {
        return Err((StatusCode::BAD_REQUEST, "invalid backup strategy".into()));
    }
    if payload.retention_count < 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            "retentionCount must be >= 1".into(),
        ));
    }
    if payload.scope == "replica" && payload.node_id.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "replica scope requires nodeId".into(),
        ));
    }
    Ok(())
}

async fn list_backup_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Json<Vec<crate::meta::models::BackupPolicy>>, (StatusCode, String)> {
    let _ = require_admin(&state, &headers, &jar).await?;
    let policies = state
        .repo
        .list_backup_policies()
        .await
        .map_err(internal_error)?;
    Ok(Json(policies))
}

async fn update_backup_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(policy_id): Path<Uuid>,
    Json(payload): Json<UpdateBackupPolicyRequest>,
) -> Result<Json<crate::meta::models::BackupPolicy>, (StatusCode, String)> {
    let _ = require_admin(&state, &headers, &jar).await?;
    validate_backup_policy_patch(&payload)?;
    validate_external_targets(payload.external_targets.as_ref())?;
    let patch = BackupPolicyPatch {
        name: payload.name,
        backup_type: payload.backup_type,
        schedule_kind: payload.schedule_kind,
        strategy: payload.strategy,
        retention_count: payload.retention_count,
        enabled: payload.enabled,
        external_targets_json: payload.external_targets,
        node_id: None,
    };
    let policy = state
        .repo
        .update_backup_policy(policy_id, &patch)
        .await
        .map_err(internal_error)?
        .ok_or((StatusCode::NOT_FOUND, "backup policy not found".into()))?;
    Ok(Json(policy))
}

fn validate_backup_policy_patch(
    payload: &UpdateBackupPolicyRequest,
) -> Result<(), (StatusCode, String)> {
    if payload
        .backup_type
        .as_ref()
        .is_some_and(|value| !backup::is_valid_backup_type(value))
    {
        return Err((StatusCode::BAD_REQUEST, "invalid backup type".into()));
    }
    if payload
        .schedule_kind
        .as_ref()
        .is_some_and(|value| !backup::is_valid_backup_schedule(value))
    {
        return Err((StatusCode::BAD_REQUEST, "invalid backup schedule".into()));
    }
    if payload
        .strategy
        .as_ref()
        .is_some_and(|value| !backup::is_valid_backup_strategy(value))
    {
        return Err((StatusCode::BAD_REQUEST, "invalid backup strategy".into()));
    }
    if payload.retention_count.is_some_and(|value| value < 1) {
        return Err((
            StatusCode::BAD_REQUEST,
            "retentionCount must be >= 1".into(),
        ));
    }
    Ok(())
}

fn validate_external_targets(raw: Option<&serde_json::Value>) -> Result<(), (StatusCode, String)> {
    let Some(targets) = raw else {
        return Ok(());
    };
    backup::parse_external_targets(targets)
        .map(|_| ())
        .map_err(|err| (StatusCode::BAD_REQUEST, err))
}

async fn run_backup_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(policy_id): Path<Uuid>,
) -> Result<Json<crate::meta::models::BackupRun>, (StatusCode, String)> {
    let _ = require_admin(&state, &headers, &jar).await?;
    let policy = state
        .repo
        .get_backup_policy(policy_id)
        .await
        .map_err(internal_error)?
        .ok_or((StatusCode::NOT_FOUND, "backup policy not found".into()))?;
    let run = backup::run_backup_policy_once(&state, &policy, "on_demand")
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err))?;
    Ok(Json(run))
}

async fn list_backup_runs(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<crate::meta::models::BackupRun>>, (StatusCode, String)> {
    let _ = require_admin(&state, &headers, &jar).await?;
    let (offset, limit) = parse_list_query(&query)?;
    let runs = state
        .repo
        .list_backup_runs(offset, limit)
        .await
        .map_err(internal_error)?;
    Ok(Json(runs))
}

async fn export_backup_run(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(run_id): Path<Uuid>,
    Query(query): Query<ExportQuery>,
) -> Result<Response, (StatusCode, String)> {
    let _ = require_admin(&state, &headers, &jar).await?;
    let run = state
        .repo
        .get_backup_run(run_id)
        .await
        .map_err(internal_error)?
        .ok_or((StatusCode::NOT_FOUND, "backup run not found".into()))?;
    let format = resolve_export_format(&run, query.format.as_deref())?;
    let bytes = backup::export_backup_run_archive(&state, &run, format)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err))?;
    let filename = format!("backup-{}.{}", run.id, format.as_str());
    build_export_response(bytes, format.content_type(), filename.as_str())
}

fn build_export_response(
    bytes: Vec<u8>,
    content_type: &str,
    filename: &str,
) -> Result<Response, (StatusCode, String)> {
    let mut response = bytes.into_response();
    *response.status_mut() = StatusCode::OK;
    let content_type = HeaderValue::from_str(content_type).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid content type".into(),
        )
    })?;
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid content disposition".into(),
            )
        })?;
    response.headers_mut().insert("Content-Type", content_type);
    response
        .headers_mut()
        .insert("Content-Disposition", disposition);
    Ok(response)
}

fn resolve_export_format(
    run: &crate::meta::models::BackupRun,
    requested: Option<&str>,
) -> Result<backup::ArchiveFormat, (StatusCode, String)> {
    if let Some(value) = requested {
        return backup::ArchiveFormat::parse(value)
            .ok_or((StatusCode::BAD_REQUEST, "invalid export format".into()));
    }
    backup::ArchiveFormat::parse(run.archive_format.as_str()).ok_or((
        StatusCode::BAD_REQUEST,
        "invalid stored backup format".into(),
    ))
}

async fn test_backup_target(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(payload): Json<TestBackupTargetRequest>,
) -> Result<Json<TestBackupTargetResponse>, (StatusCode, String)> {
    let _ = require_admin(&state, &headers, &jar).await?;
    let targets = backup::parse_external_targets(&json!([payload.target]))
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let target = &targets[0];
    let message = backup::test_external_target_connection(target)
        .await
        .map_err(|err| (StatusCode::BAD_GATEWAY, err))?;
    Ok(Json(TestBackupTargetResponse { ok: true, message }))
}

async fn update_replica_mode(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(node_id): Path<Uuid>,
    Json(payload): Json<ReplicaModeRequest>,
) -> Result<Json<ReplicaModeResponse>, (StatusCode, String)> {
    let user_id = require_admin(&state, &headers, &jar).await?;
    if !matches!(payload.sub_mode.as_str(), "delivery" | "backup") {
        return Err((StatusCode::BAD_REQUEST, "invalid replica sub mode".into()));
    }
    let mode = state
        .repo
        .set_replica_runtime_mode(node_id, payload.sub_mode.as_str(), Some(user_id))
        .await
        .map_err(internal_error)?;
    Ok(Json(ReplicaModeResponse {
        node_id: mode.node_id,
        sub_mode: mode.sub_mode,
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        build_export_response, create_backup_policy, create_snapshot, export_backup_run,
        list_backup_policies, list_backup_runs, list_snapshot_policies, list_snapshots,
        parse_list_query, require_admin, resolve_export_format, restore_snapshot,
        run_backup_policy, test_backup_target, update_backup_policy, update_bucket_worm,
        update_replica_mode, upsert_snapshot_policy, validate_backup_policy_patch,
        validate_backup_policy_payload, validate_external_targets, CreateBackupPolicyRequest,
        CreateSnapshotRequest, ExportQuery, ListQuery, ReplicaModeRequest, RestoreSnapshotRequest,
        TestBackupTargetRequest, UpdateBackupPolicyRequest, UpdateBucketWormRequest,
        UpsertSnapshotPolicyRequest,
    };
    use crate::test_support::{self, FailTriggerGuard, TableRenameGuard};
    use axum::extract::{Path, Query, State};
    use axum::http::HeaderMap;
    use axum::http::StatusCode;
    use axum::Json;
    use axum_extra::extract::cookie::CookieJar;
    use serde_json::json;
    use uuid::Uuid;

    fn auth_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {token}").parse().expect("header"),
        );
        headers
    }

    fn service_admin_headers(state: &crate::api::AppState) -> HeaderMap {
        let token = state
            .token_manager
            .issue(Uuid::new_v4(), true)
            .expect("token");
        auth_headers(token.as_str())
    }

    fn assert_error_status<T>(result: Result<T, (StatusCode, String)>, expected: StatusCode) {
        assert!(matches!(result, Err((status, _)) if status == expected));
    }

    async fn admin_headers(state: &crate::api::AppState) -> HeaderMap {
        let admin = state
            .repo
            .find_user_by_username(&state.config.admin_bootstrap_user)
            .await
            .expect("admin query")
            .expect("admin");
        let token = state.token_manager.issue(admin.id, true).expect("token");
        auth_headers(token.as_str())
    }

    async fn create_user(
        state: &crate::api::AppState,
        username: &str,
    ) -> crate::meta::models::User {
        let hash = crate::auth::password::hash_password("secret").expect("hash");
        state
            .repo
            .create_user(username, Some("Test User"), hash.as_str(), "active")
            .await
            .expect("create user")
    }

    async fn create_bucket(
        state: &crate::api::AppState,
        name: &str,
        owner_user_id: Uuid,
        is_worm: bool,
    ) -> crate::meta::models::Bucket {
        let bucket = state
            .repo
            .create_bucket(name, owner_user_id)
            .await
            .expect("bucket");
        state
            .repo
            .update_bucket_worm(bucket.id, is_worm)
            .await
            .expect("worm");
        state
            .repo
            .get_bucket(name)
            .await
            .expect("bucket")
            .expect("bucket")
    }

    async fn seed_object(state: &crate::api::AppState, bucket_id: Uuid, key: &str, bytes: &[u8]) {
        let (chunk_id, _) = state.replication.write_chunk(bytes).await.expect("chunk");
        state
            .repo
            .finalize_object_version(
                bucket_id,
                key,
                Uuid::new_v4().to_string().as_str(),
                bytes.len() as i64,
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

    fn create_policy_payload(source: &str, backup: &str) -> Json<CreateBackupPolicyRequest> {
        Json(CreateBackupPolicyRequest {
            name: "policy".to_string(),
            scope: "master".to_string(),
            node_id: None,
            source_bucket_name: source.to_string(),
            backup_bucket_name: backup.to_string(),
            backup_type: "full".to_string(),
            schedule_kind: "daily".to_string(),
            strategy: "3-2-1".to_string(),
            retention_count: 2,
            enabled: Some(true),
            external_targets: Some(json!([])),
        })
    }

    fn create_policy_input(
        source_bucket_id: Uuid,
        backup_bucket_id: Uuid,
    ) -> crate::meta::backup_repos::BackupPolicyCreate {
        crate::meta::backup_repos::BackupPolicyCreate {
            name: "policy".to_string(),
            scope: "master".to_string(),
            node_id: None,
            source_bucket_id,
            backup_bucket_id,
            backup_type: "full".to_string(),
            schedule_kind: "daily".to_string(),
            strategy: "3-2-1".to_string(),
            retention_count: 2,
            enabled: true,
            external_targets_json: json!([]),
            created_by_user_id: None,
        }
    }

    fn base_create_payload() -> CreateBackupPolicyRequest {
        CreateBackupPolicyRequest {
            name: "p".to_string(),
            scope: "master".to_string(),
            node_id: None,
            source_bucket_name: "src".to_string(),
            backup_bucket_name: "dst".to_string(),
            backup_type: "full".to_string(),
            schedule_kind: "daily".to_string(),
            strategy: "3-2-1".to_string(),
            retention_count: 1,
            enabled: Some(true),
            external_targets: Some(json!([])),
        }
    }

    fn update_backup_payload() -> UpdateBackupPolicyRequest {
        UpdateBackupPolicyRequest {
            name: None,
            backup_type: None,
            schedule_kind: None,
            strategy: None,
            retention_count: None,
            enabled: None,
            external_targets: None,
        }
    }

    async fn drop_bucket_snapshot_fk(pool: &sqlx::PgPool) {
        sqlx::query(
            "ALTER TABLE bucket_snapshots DROP CONSTRAINT IF EXISTS bucket_snapshots_bucket_id_fkey",
        )
            .execute(pool)
            .await
            .expect("drop fk");
    }

    async fn add_bucket_snapshot_fk(pool: &sqlx::PgPool) {
        sqlx::query(
            "ALTER TABLE bucket_snapshots ADD CONSTRAINT bucket_snapshots_bucket_id_fkey \
             FOREIGN KEY (bucket_id) REFERENCES buckets(id) ON DELETE CASCADE",
        )
        .execute(pool)
        .await
        .expect("add fk");
    }

    #[tokio::test]
    async fn admin_guard_enforces_auth_and_role() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let payload = Json(UpdateBucketWormRequest { is_worm: true });
        let err = update_bucket_worm(
            State(state.clone()),
            HeaderMap::new(),
            CookieJar::new(),
            Path("missing".to_string()),
            payload,
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let user = create_user(&state, "non-admin").await;
        let token = state.token_manager.issue(user.id, false).expect("token");
        let err = update_bucket_worm(
            State(state),
            auth_headers(token.as_str()),
            CookieJar::new(),
            Path("missing".to_string()),
            Json(UpdateBucketWormRequest { is_worm: true }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn snapshot_handlers_require_auth() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        assert_error_status(
            update_bucket_worm(
                State(state.clone()),
                HeaderMap::new(),
                CookieJar::new(),
                Path("missing".to_string()),
                Json(UpdateBucketWormRequest { is_worm: true }),
            )
            .await,
            StatusCode::UNAUTHORIZED,
        );
        assert_error_status(
            upsert_snapshot_policy(
                State(state.clone()),
                HeaderMap::new(),
                CookieJar::new(),
                Json(UpsertSnapshotPolicyRequest {
                    bucket_name: "missing".to_string(),
                    trigger_kind: "daily".to_string(),
                    retention_count: 1,
                    enabled: true,
                }),
            )
            .await,
            StatusCode::UNAUTHORIZED,
        );
        assert_error_status(
            list_snapshot_policies(State(state), HeaderMap::new(), CookieJar::new()).await,
            StatusCode::UNAUTHORIZED,
        );
    }

    #[tokio::test]
    async fn backup_and_replica_handlers_require_auth() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        assert_error_status(
            create_snapshot(
                State(state.clone()),
                HeaderMap::new(),
                CookieJar::new(),
                Json(CreateSnapshotRequest {
                    bucket_name: "missing".to_string(),
                    trigger_kind: None,
                }),
            )
            .await,
            StatusCode::UNAUTHORIZED,
        );
        assert_error_status(
            create_backup_policy(
                State(state.clone()),
                HeaderMap::new(),
                CookieJar::new(),
                Json(base_create_payload()),
            )
            .await,
            StatusCode::UNAUTHORIZED,
        );
        assert_error_status(
            update_replica_mode(
                State(state),
                HeaderMap::new(),
                CookieJar::new(),
                Path(Uuid::new_v4()),
                Json(ReplicaModeRequest {
                    sub_mode: "backup".to_string(),
                }),
            )
            .await,
            StatusCode::UNAUTHORIZED,
        );
    }

    #[tokio::test]
    async fn list_restore_and_policy_handlers_require_auth() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        assert_error_status(
            list_snapshots(
                State(state.clone()),
                HeaderMap::new(),
                CookieJar::new(),
                Path("missing".to_string()),
                Query(ListQuery {
                    offset: None,
                    limit: None,
                }),
            )
            .await,
            StatusCode::UNAUTHORIZED,
        );
        assert_error_status(
            restore_snapshot(
                State(state.clone()),
                HeaderMap::new(),
                CookieJar::new(),
                Path(Uuid::new_v4()),
                Json(RestoreSnapshotRequest {
                    bucket_name: "x".into(),
                    owner_user_id: None,
                }),
            )
            .await,
            StatusCode::UNAUTHORIZED,
        );
        assert_error_status(
            list_backup_policies(State(state), HeaderMap::new(), CookieJar::new()).await,
            StatusCode::UNAUTHORIZED,
        );
    }

    #[tokio::test]
    async fn run_export_and_target_handlers_require_auth() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        assert_error_status(
            run_backup_policy(
                State(state.clone()),
                HeaderMap::new(),
                CookieJar::new(),
                Path(Uuid::new_v4()),
            )
            .await,
            StatusCode::UNAUTHORIZED,
        );
        assert_error_status(
            list_backup_runs(
                State(state.clone()),
                HeaderMap::new(),
                CookieJar::new(),
                Query(ListQuery {
                    offset: None,
                    limit: None,
                }),
            )
            .await,
            StatusCode::UNAUTHORIZED,
        );
        assert_error_status(
            export_backup_run(
                State(state.clone()),
                HeaderMap::new(),
                CookieJar::new(),
                Path(Uuid::new_v4()),
                Query(ExportQuery { format: None }),
            )
            .await,
            StatusCode::UNAUTHORIZED,
        );
        assert_error_status(
            test_backup_target(
                State(state),
                HeaderMap::new(),
                CookieJar::new(),
                Json(TestBackupTargetRequest { target: json!({}) }),
            )
            .await,
            StatusCode::UNAUTHORIZED,
        );
    }

    #[tokio::test]
    async fn handlers_map_broken_repo_errors() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        let headers = service_admin_headers(&state);
        assert_broken_repo_snapshot_errors(&state, &headers).await;
        assert_broken_repo_backup_errors(&state, &headers).await;
        assert_broken_repo_replica_errors(&state, &headers).await;
    }

    async fn assert_broken_repo_snapshot_errors(state: &crate::api::AppState, headers: &HeaderMap) {
        assert_error_status(
            update_bucket_worm(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Path("missing".to_string()),
                Json(UpdateBucketWormRequest { is_worm: true }),
            )
            .await,
            StatusCode::INTERNAL_SERVER_ERROR,
        );
        assert_error_status(
            create_snapshot(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Json(CreateSnapshotRequest {
                    bucket_name: "missing".to_string(),
                    trigger_kind: None,
                }),
            )
            .await,
            StatusCode::INTERNAL_SERVER_ERROR,
        );
        assert_error_status(
            upsert_snapshot_policy(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Json(UpsertSnapshotPolicyRequest {
                    bucket_name: "missing".to_string(),
                    trigger_kind: "daily".to_string(),
                    retention_count: 1,
                    enabled: true,
                }),
            )
            .await,
            StatusCode::INTERNAL_SERVER_ERROR,
        );
        assert_error_status(
            list_snapshot_policies(State(state.clone()), headers.clone(), CookieJar::new()).await,
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    async fn assert_broken_repo_backup_errors(state: &crate::api::AppState, headers: &HeaderMap) {
        assert_error_status(
            create_backup_policy(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Json(base_create_payload()),
            )
            .await,
            StatusCode::INTERNAL_SERVER_ERROR,
        );
        assert_error_status(
            list_backup_policies(State(state.clone()), headers.clone(), CookieJar::new()).await,
            StatusCode::INTERNAL_SERVER_ERROR,
        );
        assert_error_status(
            update_backup_policy(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Path(Uuid::new_v4()),
                Json(UpdateBackupPolicyRequest {
                    name: None,
                    backup_type: None,
                    schedule_kind: None,
                    strategy: None,
                    retention_count: None,
                    enabled: None,
                    external_targets: None,
                }),
            )
            .await,
            StatusCode::INTERNAL_SERVER_ERROR,
        );
        assert_error_status(
            list_backup_runs(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Query(ListQuery {
                    offset: Some(0),
                    limit: Some(10),
                }),
            )
            .await,
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    async fn assert_broken_repo_replica_errors(state: &crate::api::AppState, headers: &HeaderMap) {
        assert_error_status(
            run_backup_policy(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Path(Uuid::new_v4()),
            )
            .await,
            StatusCode::INTERNAL_SERVER_ERROR,
        );
        assert_error_status(
            update_replica_mode(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Path(Uuid::new_v4()),
                Json(ReplicaModeRequest {
                    sub_mode: "backup".to_string(),
                }),
            )
            .await,
            StatusCode::INTERNAL_SERVER_ERROR,
        );
        assert_error_status(
            list_snapshots(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Path("missing".to_string()),
                Query(ListQuery {
                    offset: Some(0),
                    limit: Some(10),
                }),
            )
            .await,
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    #[tokio::test]
    async fn restore_and_export_return_not_found_for_missing_records() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        assert_error_status(
            restore_snapshot(
                State(state.clone()),
                headers.clone(),
                CookieJar::new(),
                Path(Uuid::new_v4()),
                Json(RestoreSnapshotRequest {
                    bucket_name: "restored-missing".to_string(),
                    owner_user_id: None,
                }),
            )
            .await,
            StatusCode::NOT_FOUND,
        );
        assert_error_status(
            export_backup_run(
                State(state),
                headers,
                CookieJar::new(),
                Path(Uuid::new_v4()),
                Query(ExportQuery { format: None }),
            )
            .await,
            StatusCode::NOT_FOUND,
        );
    }

    #[tokio::test]
    async fn snapshot_policy_snapshot_and_restore_flow() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, "owner-1").await;
        let source = create_bucket(&state, "src-a", owner.id, false).await;
        seed_object(&state, source.id, "a/file.txt", b"hello").await;

        let Json(policy) = upsert_snapshot_policy(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Json(UpsertSnapshotPolicyRequest {
                bucket_name: source.name.clone(),
                trigger_kind: "daily".to_string(),
                retention_count: 2,
                enabled: true,
            }),
        )
        .await
        .expect("policy");
        assert_eq!(policy["bucket_id"], json!(source.id));

        let Json(snapshot) = create_snapshot(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Json(CreateSnapshotRequest {
                bucket_name: source.name.clone(),
                trigger_kind: None,
            }),
        )
        .await
        .expect("snapshot");
        let Json(restored) = restore_snapshot(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(snapshot.id),
            Json(RestoreSnapshotRequest {
                bucket_name: "restored-a".to_string(),
                owner_user_id: None,
            }),
        )
        .await
        .expect("restore");
        assert_eq!(restored.name, "restored-a");

        let Json(policies) =
            list_snapshot_policies(State(state.clone()), headers.clone(), CookieJar::new())
                .await
                .expect("list policies");
        let Json(snapshots) = list_snapshots(
            State(state),
            headers,
            CookieJar::new(),
            Path(source.name),
            Query(ListQuery {
                offset: Some(0),
                limit: Some(10),
            }),
        )
        .await
        .expect("list snapshots");
        assert!(!policies.is_empty());
        assert_eq!(snapshots.len(), 1);
    }

    #[tokio::test]
    async fn backup_policy_run_and_export_flow() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, "owner-2").await;
        let source = create_bucket(&state, "src-b", owner.id, false).await;
        let backup_bucket = create_bucket(&state, "bak-b", owner.id, true).await;
        seed_object(&state, source.id, "obj.txt", b"payload").await;

        let Json(policy) = create_backup_policy(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            create_policy_payload(source.name.as_str(), backup_bucket.name.as_str()),
        )
        .await
        .expect("policy");
        let Json(run) = run_backup_policy(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(policy.id),
        )
        .await
        .expect("run");
        let Json(policies) =
            list_backup_policies(State(state.clone()), headers.clone(), CookieJar::new())
                .await
                .expect("list policies");
        let Json(runs) = list_backup_runs(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Query(ListQuery {
                offset: Some(0),
                limit: Some(10),
            }),
        )
        .await
        .expect("list runs");
        let response = export_backup_run(
            State(state),
            headers,
            CookieJar::new(),
            Path(run.id),
            Query(ExportQuery {
                format: Some("tar".to_string()),
            }),
        )
        .await
        .expect("export");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(policies.len(), 1);
        assert_eq!(runs.len(), 1);
    }

    #[tokio::test]
    async fn create_backup_policy_accepts_existing_replica_node_id() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, "owner-node-policy").await;
        let source = create_bucket(&state, "src-node-policy", owner.id, false).await;
        let backup_bucket = create_bucket(&state, "bak-node-policy", owner.id, true).await;
        let node_id = Uuid::new_v4();
        state
            .repo
            .upsert_node(
                node_id,
                "replica",
                "http://replica-node:9010",
                "online",
                None,
                None,
                None,
            )
            .await
            .expect("node");
        let mut payload =
            create_policy_payload(source.name.as_str(), backup_bucket.name.as_str()).0;
        payload.scope = "replica".to_string();
        payload.node_id = Some(node_id);
        let Json(policy) =
            create_backup_policy(State(state), headers, CookieJar::new(), Json(payload))
                .await
                .expect("policy");
        assert_eq!(policy.node_id, Some(node_id));
    }

    #[tokio::test]
    async fn policy_validation_target_test_and_replica_mode_flow() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, "owner-3").await;
        let source = create_bucket(&state, "src-c", owner.id, false).await;
        let non_worm_backup = create_bucket(&state, "bak-c", owner.id, false).await;
        let err = create_backup_policy(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            create_policy_payload(source.name.as_str(), non_worm_backup.name.as_str()),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);

        let Json(target) = test_backup_target(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Json(TestBackupTargetRequest {
                target: json!({
                    "name": "disabled",
                    "kind": "other",
                    "endpoint": "https://backup.example.com/archive",
                    "enabled": false
                }),
            }),
        )
        .await
        .expect("target");
        assert!(target.ok);

        let node_id = Uuid::new_v4();
        state
            .repo
            .upsert_node(
                node_id,
                "replica",
                "http://replica:9010",
                "online",
                None,
                None,
                None,
            )
            .await
            .expect("node");
        let err = update_replica_mode(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(node_id),
            Json(ReplicaModeRequest {
                sub_mode: "invalid".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let Json(mode) = update_replica_mode(
            State(state),
            headers,
            CookieJar::new(),
            Path(node_id),
            Json(ReplicaModeRequest {
                sub_mode: "backup".to_string(),
            }),
        )
        .await
        .expect("mode");
        assert_eq!(mode.sub_mode, "backup");
    }

    #[test]
    fn parse_list_query_validates_ranges() {
        let query = ListQuery {
            offset: Some(1),
            limit: Some(10),
        };
        assert_eq!(parse_list_query(&query).expect("query"), (1, 10));
        let invalid = ListQuery {
            offset: Some(-1),
            limit: Some(10),
        };
        assert!(parse_list_query(&invalid).is_err());
        let invalid_limit = ListQuery {
            offset: Some(0),
            limit: Some(500),
        };
        assert!(parse_list_query(&invalid_limit).is_err());
    }

    #[test]
    fn backup_payload_validation_rejects_invalid_values() {
        let mut payload = base_create_payload();
        payload.scope = "bad".to_string();
        assert!(validate_backup_policy_payload(&payload).is_err());
        payload.scope = "master".to_string();
        payload.backup_type = "bad".to_string();
        assert!(validate_backup_policy_payload(&payload).is_err());
        payload.backup_type = "full".to_string();
        payload.schedule_kind = "bad".to_string();
        assert!(validate_backup_policy_payload(&payload).is_err());
        payload.schedule_kind = "daily".to_string();
        payload.strategy = "bad".to_string();
        assert!(validate_backup_policy_payload(&payload).is_err());
        payload.strategy = "3-2-1".to_string();
        payload.retention_count = 0;
        assert!(validate_backup_policy_payload(&payload).is_err());
        payload.retention_count = 1;
        payload.scope = "replica".to_string();
        payload.node_id = None;
        assert!(validate_backup_policy_payload(&payload).is_err());
        let mut patch = UpdateBackupPolicyRequest {
            name: None,
            backup_type: Some("bad".to_string()),
            schedule_kind: None,
            strategy: None,
            retention_count: None,
            enabled: None,
            external_targets: None,
        };
        assert!(validate_backup_policy_patch(&patch).is_err());
        patch.backup_type = None;
        patch.schedule_kind = Some("bad".to_string());
        assert!(validate_backup_policy_patch(&patch).is_err());
        patch.schedule_kind = None;
        patch.strategy = Some("bad".to_string());
        assert!(validate_backup_policy_patch(&patch).is_err());
        patch.strategy = None;
        patch.retention_count = Some(0);
        assert!(validate_backup_policy_patch(&patch).is_err());
        patch.retention_count = None;
        assert!(validate_backup_policy_patch(&patch).is_ok());
    }

    #[test]
    fn validate_external_targets_rejects_invalid_endpoint() {
        let payload = json!([
            {
                "name": "remote-1",
                "kind": "s3",
                "endpoint": "ftp://invalid-endpoint"
            }
        ]);
        let err = validate_external_targets(Some(&payload)).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn internal_error_maps_sqlx_errors() {
        let err = super::internal_error(sqlx::Error::RowNotFound);
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn resolve_export_format_uses_request_or_stored_format() {
        let run = crate::meta::models::BackupRun {
            id: Uuid::new_v4(),
            policy_id: Uuid::new_v4(),
            snapshot_id: Some(Uuid::new_v4()),
            backup_type: "full".to_string(),
            changed_since: None,
            trigger_kind: "on_demand".to_string(),
            status: "success".to_string(),
            archive_format: "tar.gz".to_string(),
            archive_object_key: None,
            archive_size_bytes: None,
            error_text: None,
            started_at: chrono::Utc::now(),
            completed_at: None,
        };
        let query = ExportQuery {
            format: Some("tar".to_string()),
        };
        let format = resolve_export_format(&run, query.format.as_deref()).expect("format");
        assert_eq!(format.as_str(), "tar");
        let format = resolve_export_format(&run, None).expect("stored");
        assert_eq!(format.as_str(), "tar.gz");
    }

    #[test]
    fn export_helpers_handle_invalid_values() {
        let err = build_export_response(vec![1, 2, 3], "bad\nvalue", "backup.tar").unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        let err =
            build_export_response(vec![1, 2, 3], "application/x-tar", "bad\nfile").unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        let run = crate::meta::models::BackupRun {
            id: Uuid::new_v4(),
            policy_id: Uuid::new_v4(),
            snapshot_id: Some(Uuid::new_v4()),
            backup_type: "full".to_string(),
            changed_since: None,
            trigger_kind: "on_demand".to_string(),
            status: "success".to_string(),
            archive_format: "zip".to_string(),
            archive_object_key: None,
            archive_size_bytes: None,
            error_text: None,
            started_at: chrono::Utc::now(),
            completed_at: None,
        };
        assert!(resolve_export_format(&run, None).is_err());
    }

    #[tokio::test]
    async fn update_worm_and_snapshot_validation_paths() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, "owner-5").await;
        let bucket = create_bucket(&state, "src-e", owner.id, false).await;
        let status = update_bucket_worm(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(bucket.name.clone()),
            Json(UpdateBucketWormRequest { is_worm: true }),
        )
        .await
        .expect("worm");
        assert_eq!(status, StatusCode::NO_CONTENT);
        let err = upsert_snapshot_policy(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Json(UpsertSnapshotPolicyRequest {
                bucket_name: bucket.name.clone(),
                trigger_kind: "on_demand".to_string(),
                retention_count: 1,
                enabled: true,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let err = upsert_snapshot_policy(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Json(UpsertSnapshotPolicyRequest {
                bucket_name: bucket.name.clone(),
                trigger_kind: "daily".to_string(),
                retention_count: 0,
                enabled: true,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let err = create_snapshot(
            State(state),
            headers,
            CookieJar::new(),
            Json(CreateSnapshotRequest {
                bucket_name: bucket.name,
                trigger_kind: Some("invalid".to_string()),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_handlers_validate_invalid_query_ranges() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, "owner-query-range").await;
        let bucket = create_bucket(&state, "src-query-range", owner.id, false).await;
        let err = list_snapshots(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(bucket.name),
            Query(ListQuery {
                offset: Some(-1),
                limit: Some(10),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let err = list_backup_runs(
            State(state),
            headers,
            CookieJar::new(),
            Query(ListQuery {
                offset: Some(0),
                limit: Some(500),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn update_bucket_worm_maps_update_query_error() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, "owner-worm-fail").await;
        let bucket = create_bucket(&state, "worm-fail", owner.id, false).await;
        let trigger = FailTriggerGuard::create(&pool, "buckets", "AFTER", "UPDATE")
            .await
            .expect("trigger");
        let err = update_bucket_worm(
            State(state),
            headers,
            CookieJar::new(),
            Path(bucket.name),
            Json(UpdateBucketWormRequest { is_worm: true }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        trigger.remove().await.expect("remove trigger");
    }

    #[tokio::test]
    async fn list_snapshot_and_backup_policies_map_repo_errors() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let snapshot_rename = TableRenameGuard::rename(&pool, "bucket_snapshots")
            .await
            .expect("rename");
        let owner = create_user(&state, "owner-snap-list-fail").await;
        let bucket = create_bucket(&state, "snap-list-fail", owner.id, false).await;
        let err = list_snapshots(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(bucket.name),
            Query(ListQuery {
                offset: Some(0),
                limit: Some(10),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        snapshot_rename.restore().await.expect("restore");

        let policy_rename = TableRenameGuard::rename(&pool, "backup_policies")
            .await
            .expect("rename");
        let err = list_backup_policies(State(state), headers, CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        policy_rename.restore().await.expect("restore");
    }

    #[tokio::test]
    async fn restore_snapshot_maps_snapshot_and_bucket_repo_errors() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, "owner-restore-fail").await;
        let source = create_bucket(&state, "restore-fail-src", owner.id, false).await;
        seed_object(&state, source.id, "a.txt", b"a").await;
        let snapshot = state
            .repo
            .create_bucket_snapshot(source.id, "on_demand", None)
            .await
            .expect("snapshot");

        let snap_rename = TableRenameGuard::rename(&pool, "bucket_snapshots")
            .await
            .expect("rename");
        let err = restore_snapshot(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(snapshot.id),
            Json(RestoreSnapshotRequest {
                bucket_name: "restore-a".into(),
                owner_user_id: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        snap_rename.restore().await.expect("restore");

        let bucket_rename = TableRenameGuard::rename(&pool, "buckets")
            .await
            .expect("rename");
        let err = restore_snapshot(
            State(state),
            headers,
            CookieJar::new(),
            Path(snapshot.id),
            Json(RestoreSnapshotRequest {
                bucket_name: "restore-b".into(),
                owner_user_id: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        bucket_rename.restore().await.expect("restore");
    }

    #[tokio::test]
    async fn update_backup_policy_validates_payload_inside_handler() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let err = update_backup_policy(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(Uuid::new_v4()),
            Json(UpdateBackupPolicyRequest {
                name: None,
                backup_type: Some("invalid".to_string()),
                schedule_kind: None,
                strategy: None,
                retention_count: None,
                enabled: None,
                external_targets: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let err = update_backup_policy(
            State(state),
            headers,
            CookieJar::new(),
            Path(Uuid::new_v4()),
            Json(UpdateBackupPolicyRequest {
                name: None,
                backup_type: None,
                schedule_kind: None,
                strategy: None,
                retention_count: None,
                enabled: None,
                external_targets: Some(json!([{"name":"bad","kind":"s3","endpoint":"ftp://x"}])),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn run_backup_and_export_cover_not_found_and_invalid_format() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let err = run_backup_policy(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(Uuid::new_v4()),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);

        let owner = create_user(&state, "owner-run-export").await;
        let source = create_bucket(&state, "src-run-export", owner.id, false).await;
        let backup = create_bucket(&state, "bak-run-export", owner.id, true).await;
        let policy = state
            .repo
            .create_backup_policy(&create_policy_input(source.id, backup.id))
            .await
            .expect("policy");
        let run = state
            .repo
            .create_backup_run(policy.id, None, "full", None, "on_demand", "tar.gz")
            .await
            .expect("run");
        let err = export_backup_run(
            State(state),
            headers,
            CookieJar::new(),
            Path(run.id),
            Query(ExportQuery {
                format: Some("zip".to_string()),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_backup_policy_reports_missing_replica_node() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, "owner-6").await;
        let source = create_bucket(&state, "src-f", owner.id, false).await;
        let backup_bucket = create_bucket(&state, "bak-f", owner.id, true).await;
        let err = create_backup_policy(
            State(state),
            headers,
            CookieJar::new(),
            Json(CreateBackupPolicyRequest {
                name: "replica-policy".to_string(),
                scope: "replica".to_string(),
                node_id: Some(Uuid::new_v4()),
                source_bucket_name: source.name,
                backup_bucket_name: backup_bucket.name,
                backup_type: "full".to_string(),
                schedule_kind: "daily".to_string(),
                strategy: "3-2-1".to_string(),
                retention_count: 1,
                enabled: Some(true),
                external_targets: Some(json!([])),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn require_admin_rejects_invalid_token() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = auth_headers("invalid-token");
        let err = require_admin(&state, &headers, &CookieJar::new())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_backup_policy_defaults_external_targets_to_empty_array() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, "owner-default-targets").await;
        let source = create_bucket(&state, "src-default-targets", owner.id, false).await;
        let backup = create_bucket(&state, "bak-default-targets", owner.id, true).await;
        let Json(policy) = create_backup_policy(
            State(state),
            headers,
            CookieJar::new(),
            Json(CreateBackupPolicyRequest {
                external_targets: None,
                ..create_policy_payload(source.name.as_str(), backup.name.as_str()).0
            }),
        )
        .await
        .expect("policy");
        assert_eq!(policy.external_targets_json, json!([]));
    }

    async fn setup_backup_policy_error_state(
        suffix: &str,
    ) -> (
        crate::api::AppState,
        sqlx::PgPool,
        HeaderMap,
        crate::meta::models::Bucket,
        crate::meta::models::Bucket,
    ) {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, format!("owner-{suffix}").as_str()).await;
        let source = create_bucket(&state, format!("src-{suffix}").as_str(), owner.id, false).await;
        let backup = create_bucket(&state, format!("bak-{suffix}").as_str(), owner.id, true).await;
        (state, pool, headers, source, backup)
    }

    async fn assert_create_backup_policy_error(
        state: crate::api::AppState,
        headers: HeaderMap,
        payload: CreateBackupPolicyRequest,
        expected_status: StatusCode,
    ) {
        let err = create_backup_policy(State(state), headers, CookieJar::new(), Json(payload))
            .await
            .unwrap_err();
        assert_eq!(err.0, expected_status);
    }

    #[tokio::test]
    async fn upsert_snapshot_policy_maps_repo_write_error() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, "owner-upsert-fail").await;
        let bucket = create_bucket(&state, "upsert-fail", owner.id, false).await;

        let upsert_fail = FailTriggerGuard::create(
            &pool,
            "bucket_snapshot_policies",
            "BEFORE",
            "INSERT OR UPDATE",
        )
        .await
        .expect("upsert failpoint");
        let err = upsert_snapshot_policy(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Json(UpsertSnapshotPolicyRequest {
                bucket_name: bucket.name.clone(),
                trigger_kind: "daily".to_string(),
                retention_count: 1,
                enabled: true,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        upsert_fail.remove().await.expect("remove upsert failpoint");
    }

    #[tokio::test]
    async fn create_snapshot_maps_repo_insert_error() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, "owner-snapshot-fail").await;
        let bucket = create_bucket(&state, "snapshot-fail", owner.id, false).await;
        let snapshot_fail = FailTriggerGuard::create(&pool, "bucket_snapshots", "BEFORE", "INSERT")
            .await
            .expect("snapshot failpoint");
        let err = create_snapshot(
            State(state),
            headers,
            CookieJar::new(),
            Json(CreateSnapshotRequest {
                bucket_name: bucket.name,
                trigger_kind: Some("hourly".to_string()),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        snapshot_fail
            .remove()
            .await
            .expect("remove snapshot failpoint");
    }

    #[tokio::test]
    async fn restore_snapshot_reports_missing_source_bucket() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, "owner-restore-missing-source").await;
        let source = create_bucket(&state, "restore-source", owner.id, false).await;
        let snapshot = state
            .repo
            .create_bucket_snapshot(source.id, "on_demand", None)
            .await
            .expect("snapshot");

        drop_bucket_snapshot_fk(&pool).await;
        sqlx::query("DELETE FROM buckets WHERE id = $1")
            .bind(source.id)
            .execute(&pool)
            .await
            .expect("delete source");
        let err = restore_snapshot(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(snapshot.id),
            Json(RestoreSnapshotRequest {
                bucket_name: "restored-source-missing".to_string(),
                owner_user_id: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        sqlx::query("DELETE FROM bucket_snapshots WHERE id = $1")
            .bind(snapshot.id)
            .execute(&pool)
            .await
            .expect("delete snapshot");
        add_bucket_snapshot_fk(&pool).await;
    }

    #[tokio::test]
    async fn restore_snapshot_maps_create_bucket_from_snapshot_error() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, "owner-restore-insert-fail").await;
        let source = create_bucket(&state, "restore-source-insert-fail", owner.id, false).await;
        let snapshot = state
            .repo
            .create_bucket_snapshot(source.id, "on_demand", None)
            .await
            .expect("snapshot");
        let restore_fail = FailTriggerGuard::create(&pool, "buckets", "BEFORE", "INSERT")
            .await
            .expect("restore failpoint");
        let err = restore_snapshot(
            State(state),
            headers,
            CookieJar::new(),
            Path(snapshot.id),
            Json(RestoreSnapshotRequest {
                bucket_name: "restored-insert-fail".to_string(),
                owner_user_id: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        restore_fail
            .remove()
            .await
            .expect("remove restore failpoint");
    }

    #[tokio::test]
    async fn create_backup_policy_handler_validates_scope() {
        let (state, _pool, headers, source, backup) =
            setup_backup_policy_error_state("scope").await;
        let mut invalid_scope = base_create_payload();
        invalid_scope.scope = "invalid".to_string();
        invalid_scope.source_bucket_name = source.name;
        invalid_scope.backup_bucket_name = backup.name;
        assert_create_backup_policy_error(state, headers, invalid_scope, StatusCode::BAD_REQUEST)
            .await;
    }

    #[tokio::test]
    async fn create_backup_policy_handler_validates_external_targets() {
        let (state, _pool, headers, source, backup) =
            setup_backup_policy_error_state("targets").await;
        let mut invalid_target = base_create_payload();
        invalid_target.source_bucket_name = source.name;
        invalid_target.backup_bucket_name = backup.name;
        invalid_target.external_targets = Some(json!([{
            "name": "bad-target",
            "kind": "other",
            "endpoint": "ftp://invalid"
        }]));
        assert_create_backup_policy_error(state, headers, invalid_target, StatusCode::BAD_REQUEST)
            .await;
    }

    #[tokio::test]
    async fn create_backup_policy_handler_reports_missing_backup_bucket() {
        let (state, _pool, headers, source, _backup) =
            setup_backup_policy_error_state("missing").await;
        let mut missing_backup = base_create_payload();
        missing_backup.source_bucket_name = source.name;
        missing_backup.backup_bucket_name = "missing-bucket".to_string();
        assert_create_backup_policy_error(state, headers, missing_backup, StatusCode::NOT_FOUND)
            .await;
    }

    #[tokio::test]
    async fn create_backup_policy_maps_node_lookup_error() {
        let (state, pool, headers, source, backup) = setup_backup_policy_error_state("node").await;
        let mut node_error = base_create_payload();
        node_error.scope = "replica".to_string();
        node_error.source_bucket_name = source.name;
        node_error.backup_bucket_name = backup.name;
        node_error.node_id = Some(Uuid::new_v4());
        let nodes_rename = TableRenameGuard::rename(&pool, "nodes")
            .await
            .expect("rename nodes");
        assert_create_backup_policy_error(
            state,
            headers,
            node_error,
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
        nodes_rename.restore().await.expect("restore nodes");
    }

    #[tokio::test]
    async fn create_backup_policy_maps_insert_error() {
        let (state, pool, headers, source, backup) =
            setup_backup_policy_error_state("insert").await;
        let mut insert_error = base_create_payload();
        insert_error.source_bucket_name = source.name;
        insert_error.backup_bucket_name = backup.name;
        let policy_fail = FailTriggerGuard::create(&pool, "backup_policies", "BEFORE", "INSERT")
            .await
            .expect("policy failpoint");
        assert_create_backup_policy_error(
            state,
            headers,
            insert_error,
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
        policy_fail.remove().await.expect("remove policy failpoint");
    }

    #[tokio::test]
    async fn update_backup_policy_handler_requires_auth() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let err = update_backup_policy(
            State(state),
            HeaderMap::new(),
            CookieJar::new(),
            Path(Uuid::new_v4()),
            Json(update_backup_payload()),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn export_backup_run_maps_backup_lookup_error() {
        let (state, pool, headers, source, backup) =
            setup_backup_policy_error_state("export").await;
        let policy = state
            .repo
            .create_backup_policy(&create_policy_input(source.id, backup.id))
            .await
            .expect("policy");
        let run = state
            .repo
            .create_backup_run(policy.id, None, "full", None, "on_demand", "tar.gz")
            .await
            .expect("run");
        let runs_rename = TableRenameGuard::rename(&pool, "backup_runs")
            .await
            .expect("rename runs");
        let err = export_backup_run(
            State(state),
            headers,
            CookieJar::new(),
            Path(run.id),
            Query(ExportQuery { format: None }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        runs_rename.restore().await.expect("restore runs");
    }

    #[tokio::test]
    async fn run_backup_policy_maps_backup_execution_error() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, "owner-run-fail").await;
        let source = create_bucket(&state, "src-run-fail", owner.id, false).await;
        let backup = create_bucket(&state, "bak-run-fail", owner.id, false).await;
        let policy = state
            .repo
            .create_backup_policy(&create_policy_input(source.id, backup.id))
            .await
            .expect("policy");
        let err = run_backup_policy(State(state), headers, CookieJar::new(), Path(policy.id))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn export_backup_run_maps_archive_errors() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, "owner-export-fail").await;
        let source = create_bucket(&state, "src-export-fail", owner.id, false).await;
        let backup = create_bucket(&state, "bak-export-fail", owner.id, true).await;
        let policy = state
            .repo
            .create_backup_policy(&create_policy_input(source.id, backup.id))
            .await
            .expect("policy");
        let run = state
            .repo
            .create_backup_run(policy.id, None, "full", None, "on_demand", "tar.gz")
            .await
            .expect("run");
        let err = export_backup_run(
            State(state),
            headers,
            CookieJar::new(),
            Path(run.id),
            Query(ExportQuery { format: None }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_backup_target_maps_parse_and_connectivity_errors() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let invalid = test_backup_target(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Json(TestBackupTargetRequest {
                target: json!({"name":"bad","kind":"s3","endpoint":"not-url"}),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(invalid.0, StatusCode::BAD_REQUEST);
        let gateway = test_backup_target(
            State(state),
            headers,
            CookieJar::new(),
            Json(TestBackupTargetRequest {
                target: json!({"name":"down","kind":"s3","endpoint":"http://127.0.0.1:1/up"}),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(gateway.0, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn update_backup_policy_and_not_found_paths() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = admin_headers(&state).await;
        let owner = create_user(&state, "owner-4").await;
        let source = create_bucket(&state, "src-d", owner.id, false).await;
        let backup_bucket = create_bucket(&state, "bak-d", owner.id, true).await;
        let Json(policy) = create_backup_policy(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            create_policy_payload(source.name.as_str(), backup_bucket.name.as_str()),
        )
        .await
        .expect("policy");
        let Json(updated) = update_backup_policy(
            State(state.clone()),
            headers.clone(),
            CookieJar::new(),
            Path(policy.id),
            Json(UpdateBackupPolicyRequest {
                name: Some("policy-2".to_string()),
                backup_type: Some("incremental".to_string()),
                schedule_kind: None,
                strategy: None,
                retention_count: Some(3),
                enabled: Some(false),
                external_targets: Some(json!([])),
            }),
        )
        .await
        .expect("update");
        assert_eq!(updated.name, "policy-2");
        let err = update_backup_policy(
            State(state),
            headers,
            CookieJar::new(),
            Path(Uuid::new_v4()),
            Json(UpdateBackupPolicyRequest {
                name: None,
                backup_type: None,
                schedule_kind: None,
                strategy: None,
                retention_count: None,
                enabled: None,
                external_targets: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }
}
