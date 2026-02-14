use crate::api::AppState;
use crate::storage::checksum::parse_checksum;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinRequest {
    address_internal: String,
    capacity_bytes: i64,
    free_bytes: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct JoinResponse {
    node_id: Uuid,
    cluster_config: crate::storage::replication::ClusterConfig,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HeartbeatRequest {
    node_id: Uuid,
    free_bytes: i64,
    capacity_bytes: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplicaRuntimeResponse {
    node_id: Uuid,
    sub_mode: String,
}

pub fn master_router(state: AppState) -> Router {
    let body_limit = internal_body_limit_bytes(&state.config);
    Router::new()
        .route("/internal/v1/cluster/join", post(join_cluster))
        .route("/internal/v1/cluster/heartbeat", post(heartbeat))
        .route("/internal/v1/cluster/config", get(cluster_config))
        .route(
            "/internal/v1/cluster/replica-runtime/{node_id}",
            get(replica_runtime),
        )
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state)
}

pub fn replica_router(state: AppState) -> Router {
    let body_limit = internal_body_limit_bytes(&state.config);
    Router::new()
        .route(
            "/internal/v1/chunks/{chunk_id}",
            put(put_chunk)
                .get(get_chunk)
                .head(head_chunk)
                .delete(delete_chunk),
        )
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state)
}

fn internal_body_limit_bytes(config: &crate::util::config::Config) -> usize {
    let lower_bound = 128usize * 1024 * 1024;
    let chunk_max = usize::try_from(config.chunk_max_bytes).unwrap_or(usize::MAX);
    lower_bound.max(chunk_max)
}

async fn join_cluster(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<JoinRequest>,
) -> Result<Json<JoinResponse>, (StatusCode, String)> {
    let token = parse_join_token(&headers)?;
    consume_join_token(&state, token).await?;
    let node = load_or_create_replica_node(&state, &payload).await?;

    let response = JoinResponse {
        node_id: node.node_id,
        cluster_config: state.replication.cluster_config(state.chunk_size_bytes),
    };
    Ok(Json(response))
}

fn parse_join_token(headers: &HeaderMap) -> Result<&str, (StatusCode, String)> {
    let auth = headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !auth.starts_with("Bearer ") {
        return Err((StatusCode::UNAUTHORIZED, "missing token".into()));
    }
    Ok(auth.trim_start_matches("Bearer "))
}

async fn consume_join_token(state: &AppState, token: &str) -> Result<(), (StatusCode, String)> {
    let token_hash = format!("{:x}", sha2::Sha256::digest(token.as_bytes()));
    let join = state
        .repo
        .consume_join_token(&token_hash, chrono::Utc::now())
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "join token error".into()))?;
    if join.is_none() {
        return Err((StatusCode::UNAUTHORIZED, "invalid join token".into()));
    }
    Ok(())
}

async fn load_or_create_replica_node(
    state: &AppState,
    payload: &JoinRequest,
) -> Result<crate::meta::models::Node, (StatusCode, String)> {
    match state
        .repo
        .get_node_by_address(&payload.address_internal)
        .await
    {
        Ok(Some(node)) => Ok(node),
        _ => state
            .repo
            .upsert_node(
                Uuid::new_v4(),
                "replica",
                &payload.address_internal,
                "online",
                Some(payload.capacity_bytes),
                Some(payload.free_bytes),
                Some(chrono::Utc::now()),
            )
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "node create failed".into(),
                )
            }),
    }
}

async fn heartbeat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<HeartbeatRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !state.internal_auth.verify_headers(&headers) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }
    state
        .repo
        .update_node_heartbeat(
            payload.node_id,
            Some(payload.capacity_bytes),
            Some(payload.free_bytes),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "heartbeat failed".into()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn cluster_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<crate::storage::replication::ClusterConfig>, (StatusCode, String)> {
    if !state.internal_auth.verify_headers(&headers) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }
    Ok(Json(
        state.replication.cluster_config(state.chunk_size_bytes),
    ))
}

async fn replica_runtime(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(node_id): Path<Uuid>,
) -> Result<Json<ReplicaRuntimeResponse>, (StatusCode, String)> {
    if !state.internal_auth.verify_headers(&headers) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }
    let mode = state
        .repo
        .get_replica_runtime_mode(node_id)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "runtime config failed".into(),
            )
        })?;
    let sub_mode = mode
        .map(|value| value.sub_mode)
        .unwrap_or_else(|| "delivery".to_string());
    Ok(Json(ReplicaRuntimeResponse { node_id, sub_mode }))
}

async fn put_chunk(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chunk_id): Path<Uuid>,
    body: bytes::Bytes,
) -> Result<StatusCode, (StatusCode, String)> {
    if !state.internal_auth.verify_headers(&headers) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }
    let algo = headers
        .get("X-Checksum-Algo")
        .and_then(|value| value.to_str().ok())
        .ok_or((StatusCode::BAD_REQUEST, "missing checksum algo".into()))?;
    let value = headers
        .get("X-Checksum-Value")
        .and_then(|value| value.to_str().ok())
        .ok_or((StatusCode::BAD_REQUEST, "missing checksum value".into()))?;
    let checksum = parse_checksum(algo, value).map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    if !checksum.verify(&body) {
        return Err((StatusCode::BAD_REQUEST, "checksum mismatch".into()));
    }
    state
        .replication
        .chunk_store()
        .write_chunk(chunk_id, &body)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err))?;
    Ok(StatusCode::CREATED)
}

async fn get_chunk(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chunk_id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state.internal_auth.verify_headers(&headers) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }
    let range = headers
        .get("Range")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_range_header);
    let bytes = if let Some((start, end)) = range {
        state
            .replication
            .chunk_store()
            .read_chunk_range(chunk_id, start, end)
            .await
            .map_err(|err| (StatusCode::NOT_FOUND, err))?
    } else {
        state
            .replication
            .chunk_store()
            .read_chunk(chunk_id)
            .await
            .map_err(|err| (StatusCode::NOT_FOUND, err))?
    };
    Ok((StatusCode::OK, bytes))
}

async fn head_chunk(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chunk_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !state.internal_auth.verify_headers(&headers) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }
    if state.replication.chunk_store().chunk_exists(chunk_id).await {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::NOT_FOUND, "not found".into()))
    }
}

async fn delete_chunk(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chunk_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !state.internal_auth.verify_headers(&headers) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }
    state
        .replication
        .chunk_store()
        .delete_chunk(chunk_id)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err))?;
    Ok(StatusCode::NO_CONTENT)
}

fn parse_range_header(header: &str) -> Option<(usize, usize)> {
    if !header.starts_with("bytes=") {
        return None;
    }
    let range = header.trim_start_matches("bytes=");
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return None;
    }
    let start = parts[0].parse::<usize>().ok()?;
    let end = parts[1].parse::<usize>().ok()?;
    Some((start, end + 1))
}

#[cfg(test)]
mod tests {
    use super::{
        cluster_config, delete_chunk, get_chunk, head_chunk, heartbeat, internal_body_limit_bytes,
        join_cluster, master_router, parse_range_header, put_chunk, replica_router,
        replica_runtime, HeartbeatRequest, JoinRequest,
    };
    use crate::storage::checksum::Checksum;
    use crate::storage::chunkstore::failpoint_guard;
    use crate::test_support;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
    use axum::response::IntoResponse;
    use axum::Json;
    use sha2::Digest;
    use sqlx;
    use tower::ServiceExt;
    use uuid::Uuid;

    fn join_payload() -> Json<JoinRequest> {
        Json(JoinRequest {
            address_internal: "http://replica:9010".to_string(),
            capacity_bytes: 10,
            free_bytes: 5,
        })
    }

    fn bearer_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", token).parse().expect("auth"),
        );
        headers
    }

    fn internal_headers(state: &crate::api::AppState) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&state.internal_auth.header_value()).expect("auth"),
        );
        headers
    }

    async fn create_join_token(state: &crate::api::AppState, token: &str) {
        let token_hash = format!("{:x}", sha2::Sha256::digest(token.as_bytes()));
        state
            .repo
            .create_join_token(
                &token_hash,
                chrono::Utc::now() + chrono::Duration::minutes(5),
            )
            .await
            .expect("join token");
    }

    async fn call_put(
        state: &crate::api::AppState,
        headers: HeaderMap,
        chunk_id: Uuid,
        body: bytes::Bytes,
    ) -> Result<StatusCode, (StatusCode, String)> {
        put_chunk(
            State(state.clone()),
            headers,
            axum::extract::Path(chunk_id),
            body,
        )
        .await
    }

    async fn call_get(
        state: &crate::api::AppState,
        headers: HeaderMap,
        chunk_id: Uuid,
    ) -> Result<axum::response::Response, (StatusCode, String)> {
        get_chunk(State(state.clone()), headers, axum::extract::Path(chunk_id))
            .await
            .map(IntoResponse::into_response)
    }

    async fn call_head(
        state: &crate::api::AppState,
        headers: HeaderMap,
        chunk_id: Uuid,
    ) -> Result<StatusCode, (StatusCode, String)> {
        head_chunk(State(state.clone()), headers, axum::extract::Path(chunk_id)).await
    }

    async fn call_delete(
        state: &crate::api::AppState,
        headers: HeaderMap,
        chunk_id: Uuid,
    ) -> Result<StatusCode, (StatusCode, String)> {
        delete_chunk(State(state.clone()), headers, axum::extract::Path(chunk_id)).await
    }

    async fn assert_put_rejects_unauthorized(
        state: &crate::api::AppState,
        chunk_id: Uuid,
        body: bytes::Bytes,
    ) {
        let status = call_put(state, HeaderMap::new(), chunk_id, body)
            .await
            .err()
            .expect("expected error")
            .0;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    async fn assert_put_rejects_invalid_checksums(
        state: &crate::api::AppState,
        chunk_id: Uuid,
        body: bytes::Bytes,
    ) {
        let mut headers = internal_headers(state);
        let status = call_put(state, headers.clone(), chunk_id, body.clone())
            .await
            .err()
            .expect("expected error")
            .0;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        headers.insert("X-Checksum-Algo", "crc32c".parse().expect("algo"));
        headers.insert("X-Checksum-Value", "invalid".parse().expect("value"));
        let status = call_put(state, headers.clone(), chunk_id, body.clone())
            .await
            .err()
            .expect("expected error")
            .0;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_put_rejects_checksum_mismatch(state, headers, chunk_id, body).await;
    }

    async fn assert_put_rejects_checksum_mismatch(
        state: &crate::api::AppState,
        mut headers: HeaderMap,
        chunk_id: Uuid,
        body: bytes::Bytes,
    ) {
        let bad_checksum = Checksum::compute(state.config.checksum_algo, b"other");
        headers.insert(
            "X-Checksum-Value",
            bad_checksum.to_base64().parse().expect("value"),
        );
        let status = call_put(state, headers, chunk_id, body)
            .await
            .err()
            .expect("expected error")
            .0;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    async fn write_valid_chunk(state: &crate::api::AppState, chunk_id: Uuid, body: bytes::Bytes) {
        let mut headers = internal_headers(state);
        headers.insert("X-Checksum-Algo", "crc32c".parse().expect("algo"));
        let checksum = Checksum::compute(state.config.checksum_algo, &body);
        headers.insert(
            "X-Checksum-Value",
            checksum.to_base64().parse().expect("value"),
        );
        let status = call_put(state, headers, chunk_id, body).await.expect("put");
        assert_eq!(status, StatusCode::CREATED);
    }

    async fn assert_get_paths(state: &crate::api::AppState, chunk_id: Uuid) {
        let mut headers = internal_headers(state);
        let status = call_get(state, headers.clone(), chunk_id)
            .await
            .expect("get")
            .status();
        assert_eq!(status, StatusCode::OK);
        headers.insert("Range", "bytes=0-3".parse().expect("range"));
        let status = call_get(state, headers, chunk_id)
            .await
            .expect("range")
            .status();
        assert_eq!(status, StatusCode::OK);
    }

    async fn assert_head_delete_paths(state: &crate::api::AppState, chunk_id: Uuid) {
        let err = call_head(state, HeaderMap::new(), chunk_id)
            .await
            .err()
            .expect("expected error");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        let auth_headers = internal_headers(state);
        assert_eq!(
            call_head(state, auth_headers.clone(), chunk_id)
                .await
                .expect("head"),
            StatusCode::OK
        );
        assert_eq!(
            call_delete(state, auth_headers.clone(), chunk_id)
                .await
                .expect("delete"),
            StatusCode::NO_CONTENT
        );
        let err = call_head(state, auth_headers, chunk_id)
            .await
            .err()
            .expect("expected error");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    async fn assert_put_failpoint_paths(
        state: &crate::api::AppState,
        chunk_id: Uuid,
        body: bytes::Bytes,
    ) {
        let mut headers = internal_headers(state);
        headers.insert("X-Checksum-Algo", "crc32c".parse().expect("algo"));
        let status = call_put(state, headers.clone(), chunk_id, body.clone())
            .await
            .err()
            .expect("expected error")
            .0;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let checksum = Checksum::compute(state.config.checksum_algo, &body);
        headers.insert(
            "X-Checksum-Value",
            checksum.to_base64().parse().expect("value"),
        );
        let _fail_guard = failpoint_guard(2);
        let status = call_put(state, headers, chunk_id, body)
            .await
            .err()
            .expect("expected error")
            .0;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    async fn assert_get_failpoint_paths(state: &crate::api::AppState, chunk_id: Uuid) {
        let mut range_headers = internal_headers(state);
        range_headers.insert("Range", "bytes=0-1".parse().expect("range"));
        let _fail_guard = failpoint_guard(7);
        let status = call_get(state, range_headers.clone(), chunk_id)
            .await
            .err()
            .expect("expected error")
            .0;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let _fail_guard = failpoint_guard(7);
        let status = call_get(state, internal_headers(state), chunk_id)
            .await
            .err()
            .expect("expected error")
            .0;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    async fn assert_delete_failpoint_path(state: &crate::api::AppState, chunk_id: Uuid) {
        let _fail_guard = failpoint_guard(8);
        let status = call_delete(state, internal_headers(state), chunk_id)
            .await
            .err()
            .expect("expected error")
            .0;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    async fn assert_heartbeat_repo_error(state: &crate::api::AppState) {
        let payload = Json(HeartbeatRequest {
            node_id: state.node_id,
            free_bytes: 1,
            capacity_bytes: 2,
        });
        let err = heartbeat(State(state.clone()), internal_headers(state), payload)
            .await
            .err()
            .expect("expected error");
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    async fn assert_chunk_error_paths(state: &crate::api::AppState) {
        assert_chunk_put_failpoint_error(state).await;
        assert_missing_chunk_get_paths(state).await;
    }

    async fn assert_chunk_put_failpoint_error(state: &crate::api::AppState) {
        let mut headers = internal_headers(state);
        headers.insert("X-Checksum-Algo", "crc32c".parse().expect("algo"));
        let checksum = Checksum::compute(state.config.checksum_algo, b"payload");
        headers.insert(
            "X-Checksum-Value",
            checksum.to_base64().parse().expect("value"),
        );
        let _fail_guard = crate::storage::chunkstore::failpoint_guard(4);
        let status = call_put(
            state,
            headers,
            Uuid::new_v4(),
            bytes::Bytes::from_static(b"payload"),
        )
        .await
        .err()
        .expect("expected error")
        .0;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    async fn assert_missing_chunk_get_paths(state: &crate::api::AppState) {
        let missing_id = Uuid::new_v4();
        let status = call_get(state, internal_headers(state), missing_id)
            .await
            .err()
            .expect("expected error")
            .0;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let mut range_headers = internal_headers(state);
        range_headers.insert("Range", "bytes=0-1".parse().expect("range"));
        let status = call_get(state, range_headers, missing_id)
            .await
            .err()
            .expect("expected error")
            .0;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn join_cluster_rejects_missing_token() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = HeaderMap::new();
        let payload = Json(JoinRequest {
            address_internal: "http://replica:9010".to_string(),
            capacity_bytes: 10,
            free_bytes: 5,
        });
        let err = join_cluster(State(state), headers, payload)
            .await
            .err()
            .expect("expected error");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn join_cluster_accepts_token_and_returns_config() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        create_join_token(&state, "join-token").await;
        let response = join_cluster(
            State(state.clone()),
            bearer_headers("join-token"),
            join_payload(),
        )
        .await
        .expect("join");
        assert_eq!(
            response.0.cluster_config.replication_factor,
            state.config.replication_factor
        );

        create_join_token(&state, "second").await;
        let response = join_cluster(State(state), bearer_headers("second"), join_payload())
            .await
            .expect("join");
        assert_eq!(response.0.cluster_config.write_quorum, 1);
    }

    #[tokio::test]
    async fn join_cluster_rejects_invalid_token() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer invalid".parse().expect("auth"));
        let payload = Json(JoinRequest {
            address_internal: "http://replica:9010".to_string(),
            capacity_bytes: 10,
            free_bytes: 5,
        });
        let err = join_cluster(State(state), headers, payload)
            .await
            .err()
            .expect("expected error");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn heartbeat_requires_internal_auth() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = HeaderMap::new();
        let payload = Json(HeartbeatRequest {
            node_id: state.node_id,
            free_bytes: 1,
            capacity_bytes: 2,
        });
        let err = heartbeat(State(state.clone()), headers, payload)
            .await
            .err()
            .expect("expected error");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&state.internal_auth.header_value()).expect("auth"),
        );
        let payload = Json(HeartbeatRequest {
            node_id: state.node_id,
            free_bytes: 1,
            capacity_bytes: 2,
        });
        let status = heartbeat(State(state), headers, payload)
            .await
            .expect("heartbeat");
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn cluster_config_requires_auth() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let headers = HeaderMap::new();
        let err = cluster_config(State(state.clone()), headers)
            .await
            .err()
            .expect("expected error");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&state.internal_auth.header_value()).expect("auth"),
        );
        let response = cluster_config(State(state), headers).await.expect("config");
        assert_eq!(response.0.write_quorum, 1);
    }

    #[tokio::test]
    async fn replica_runtime_requires_auth_and_returns_values() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let node_id = state.node_id;
        assert_replica_runtime_requires_auth(&state, node_id).await;
        assert_replica_runtime_sub_mode(&state, node_id, "delivery").await;
        state
            .repo
            .set_replica_runtime_mode(node_id, "backup", None)
            .await
            .expect("set mode");
        assert_replica_runtime_sub_mode(&state, node_id, "backup").await;
    }

    #[tokio::test]
    async fn replica_runtime_reports_repo_error() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        let err = replica_runtime(
            State(state.clone()),
            internal_headers(&state),
            axum::extract::Path(state.node_id),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    async fn assert_replica_runtime_requires_auth(state: &crate::api::AppState, node_id: Uuid) {
        let err = replica_runtime(
            State(state.clone()),
            HeaderMap::new(),
            axum::extract::Path(node_id),
        )
        .await
        .err()
        .expect("expected error");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    async fn assert_replica_runtime_sub_mode(
        state: &crate::api::AppState,
        node_id: Uuid,
        expected_sub_mode: &str,
    ) {
        let response = replica_runtime(
            State(state.clone()),
            internal_headers(state),
            axum::extract::Path(node_id),
        )
        .await
        .expect("runtime");
        assert_eq!(response.0.sub_mode, expected_sub_mode);
    }

    #[tokio::test]
    async fn chunk_handlers_cover_error_and_success_paths() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let body = bytes::Bytes::from_static(b"payload");
        let chunk_id = uuid::Uuid::new_v4();
        assert_put_rejects_unauthorized(&state, chunk_id, body.clone()).await;
        assert_put_rejects_invalid_checksums(&state, chunk_id, body.clone()).await;
        write_valid_chunk(&state, chunk_id, body).await;
        assert_get_paths(&state, chunk_id).await;
        assert_head_delete_paths(&state, chunk_id).await;
    }

    #[tokio::test]
    async fn chunk_handlers_reject_missing_auth() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let chunk_id = uuid::Uuid::new_v4();

        let err = get_chunk(
            State(state.clone()),
            HeaderMap::new(),
            axum::extract::Path(chunk_id),
        )
        .await
        .err()
        .expect("expected unauthorized");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let err = delete_chunk(
            State(state),
            HeaderMap::new(),
            axum::extract::Path(chunk_id),
        )
        .await
        .err()
        .expect("expected error");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn chunk_handlers_cover_missing_checksum_and_failpoints() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let chunk_id = uuid::Uuid::new_v4();
        let body = bytes::Bytes::from_static(b"payload");
        assert_put_failpoint_paths(&state, chunk_id, body).await;
        let _ = state
            .replication
            .chunk_store()
            .write_chunk(chunk_id, b"payload")
            .await;
        assert_get_failpoint_paths(&state, chunk_id).await;
        assert_delete_failpoint_path(&state, chunk_id).await;
    }

    #[test]
    fn parse_range_header_accepts_valid_ranges() {
        assert_eq!(parse_range_header("bytes=1-2"), Some((1, 3)));
    }

    #[tokio::test]
    async fn join_cluster_reports_repo_and_node_errors() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        let err = join_cluster(State(state), bearer_headers("bad"), join_payload())
            .await
            .err()
            .expect("expected error");
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

        let (state, _pool, _dir) = test_support::build_state("master").await;
        create_join_token(&state, "join-token").await;
        sqlx::query("ALTER TABLE nodes RENAME TO nodes_backup")
            .execute(state.repo.pool())
            .await
            .expect("rename");
        let result = join_cluster(
            State(state.clone()),
            bearer_headers("join-token"),
            join_payload(),
        )
        .await;
        let _ = sqlx::query("ALTER TABLE nodes_backup RENAME TO nodes")
            .execute(state.repo.pool())
            .await;
        let err = result.err().expect("expected error");
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn heartbeat_and_chunk_errors_are_reported() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        assert_heartbeat_repo_error(&state).await;

        let (state, _pool, _dir) = test_support::build_state("master").await;
        assert_chunk_error_paths(&state).await;

        let chunk_id = Uuid::new_v4();
        state
            .replication
            .chunk_store()
            .write_chunk(chunk_id, b"data")
            .await
            .expect("write");
        assert_delete_failpoint_path(&state, chunk_id).await;
        let _ = state.replication.chunk_store().delete_chunk(chunk_id).await;
    }

    #[test]
    fn parse_range_header_variants() {
        assert_eq!(parse_range_header("bytes=0-9"), Some((0, 10)));
        assert!(parse_range_header("bytes=bad").is_none());
        assert!(parse_range_header("bytes=bad-1").is_none());
        assert!(parse_range_header("bytes=1-bad").is_none());
        assert!(parse_range_header("items=0-1").is_none());
    }

    #[tokio::test]
    async fn routers_are_constructed() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let _ = master_router(state.clone());
        let _ = replica_router(state);
    }

    #[tokio::test]
    async fn join_cluster_reports_repo_errors() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        create_join_token(&state, "join-token").await;
        assert_join_cluster_repo_error(
            &pool,
            "join_tokens",
            "join_tokens_backup",
            join_cluster(
                State(state.clone()),
                bearer_headers("join-token"),
                join_payload(),
            ),
        )
        .await;
        create_join_token(&state, "second").await;
        assert_join_cluster_repo_error(
            &pool,
            "nodes",
            "nodes_backup",
            join_cluster(State(state), bearer_headers("second"), join_payload()),
        )
        .await;
    }

    async fn assert_join_cluster_repo_error<F, T>(
        pool: &sqlx::PgPool,
        source_table: &str,
        backup_table: &str,
        join_call: F,
    ) where
        F: std::future::Future<Output = Result<T, (StatusCode, String)>>,
    {
        sqlx::query(&format!(
            "ALTER TABLE {} RENAME TO {}",
            source_table, backup_table
        ))
        .execute(pool)
        .await
        .expect("rename");
        let err = join_call.await.err().expect("expected error");
        let _ = sqlx::query(&format!(
            "ALTER TABLE {} RENAME TO {}",
            backup_table, source_table
        ))
        .execute(pool)
        .await;
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn heartbeat_reports_repo_error() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&state.internal_auth.header_value()).expect("auth"),
        );
        let payload = Json(HeartbeatRequest {
            node_id: state.node_id,
            free_bytes: 1,
            capacity_bytes: 2,
        });
        let err = heartbeat(State(state), headers, payload)
            .await
            .err()
            .expect("expected error");
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn put_chunk_requires_checksum_value() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let chunk_id = uuid::Uuid::new_v4();
        let body = bytes::Bytes::from_static(b"payload");
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&state.internal_auth.header_value()).expect("auth"),
        );
        headers.insert("X-Checksum-Algo", "crc32c".parse().expect("algo"));
        let err = put_chunk(State(state), headers, axum::extract::Path(chunk_id), body)
            .await
            .err()
            .expect("expected error");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn internal_body_limit_uses_lower_bound_and_chunk_max() {
        let mut config = test_support::base_config("master", std::env::temp_dir());
        config.chunk_max_bytes = 64 * 1024 * 1024;
        assert_eq!(internal_body_limit_bytes(&config), 128 * 1024 * 1024);
        config.chunk_max_bytes = 256 * 1024 * 1024;
        assert_eq!(internal_body_limit_bytes(&config), 256 * 1024 * 1024);
    }

    #[tokio::test]
    async fn replica_router_accepts_large_chunk_body() {
        let (state, _pool, _dir) = test_support::build_state("replica").await;
        let chunk_id = Uuid::new_v4();
        let payload = vec![7u8; 3 * 1024 * 1024 + 17];
        let checksum = Checksum::compute(state.config.checksum_algo, &payload);
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/internal/v1/chunks/{chunk_id}"))
            .header("Authorization", state.internal_auth.header_value())
            .header("X-Checksum-Algo", checksum.algo.as_str())
            .header("X-Checksum-Value", checksum.to_base64())
            .body(Body::from(payload.clone()))
            .expect("request");
        let response = replica_router(state.clone())
            .oneshot(request)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let stored = state
            .replication
            .chunk_store()
            .read_chunk(chunk_id)
            .await
            .expect("stored");
        assert_eq!(stored.len(), payload.len());
    }
}
