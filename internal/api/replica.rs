use crate::api::internal;
use crate::api::{refresh_node_heartbeat_metrics, AppState};
use crate::obs::MetricsLayer;
use crate::s3;
use crate::util::runtime::ReplicaSubMode;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{extract::State, Router};
use prometheus::{Encoder, TextEncoder};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

pub struct Servers {
    handles: Vec<JoinHandle<()>>,
}

impl Servers {
    pub async fn run_all(self) {
        for handle in self.handles {
            let _ = handle.await;
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct JoinRequest {
    address_internal: String,
    capacity_bytes: i64,
    free_bytes: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinResponse {
    node_id: Uuid,
    cluster_config: crate::storage::replication::ClusterConfig,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HeartbeatRequest {
    node_id: Uuid,
    free_bytes: i64,
    capacity_bytes: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReplicaRuntimeSyncResponse {
    sub_mode: String,
}

struct JoinContext {
    address: String,
    join_token: String,
    master: String,
}

pub async fn build_servers(state: AppState) -> Result<Servers, String> {
    join_cluster(&state).await?;
    spawn_heartbeat(state.clone());

    let mut handles = Vec::new();
    let s3_app =
        s3::router(state.clone()).layer(MetricsLayer::new(state.metrics.clone(), "replica-s3"));
    handles.push(spawn_server(&state.config.s3_listen, s3_app)?);

    let internal_app = internal::replica_router(state.clone())
        .layer(MetricsLayer::new(state.metrics.clone(), "replica-internal"));
    handles.push(spawn_server(&state.config.replica_listen, internal_app)?);

    let metrics_app = metrics_router(state.clone())
        .layer(MetricsLayer::new(state.metrics.clone(), "replica-metrics"));
    handles.push(spawn_server(&state.config.metrics_listen, metrics_app)?);

    Ok(Servers { handles })
}

async fn run_server(socket: SocketAddr, app: Router) {
    let listener = match TcpListener::bind(socket).await {
        Ok(val) => val,
        Err(_) => return,
    };
    let _ = axum::serve(listener, app).await;
}

fn spawn_server(addr: &str, app: Router) -> Result<JoinHandle<()>, String> {
    let socket: SocketAddr = addr
        .parse()
        .map_err(|_| format!("invalid listen addr {addr}"))?;
    let handle = tokio::spawn(run_server(socket, app));
    Ok(handle)
}

fn metrics_router(state: AppState) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(ready_handler))
        .with_state(state)
}

async fn metrics_handler(State(state): State<AppState>) -> String {
    refresh_node_heartbeat_metrics(&state).await;
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    let _ = encoder.encode(&state.metrics.gather(), &mut buffer);
    String::from_utf8_lossy(&buffer).to_string()
}

async fn ready_handler(State(state): State<AppState>) -> (StatusCode, &'static str) {
    if !check_data_dirs(&state).await {
        return (StatusCode::SERVICE_UNAVAILABLE, "data dirs not writable");
    }
    if !check_db_ready(&state).await {
        return (StatusCode::SERVICE_UNAVAILABLE, "db not ready");
    }
    if let Some(master) = state.config.master_url.as_ref() {
        let client = Client::new();
        let url = format!(
            "{}/internal/v1/cluster/config",
            master.trim_end_matches('/')
        );
        let resp = client
            .get(url)
            .header("Authorization", state.internal_auth.header_value())
            .send()
            .await;
        if resp.is_err() {
            return (StatusCode::SERVICE_UNAVAILABLE, "master not reachable");
        }
    }
    (StatusCode::OK, "ok")
}

async fn check_db_ready(state: &AppState) -> bool {
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        state.repo.pool().acquire(),
    )
    .await
    .is_ok_and(|result| result.is_ok())
}

async fn check_data_dirs(state: &AppState) -> bool {
    for dir in &state.config.data_dirs {
        let test_path = dir.join(".nss_ready_check");
        if tokio::fs::write(&test_path, b"ok").await.is_err() {
            return false;
        }
        let _ = tokio::fs::remove_file(&test_path).await;
    }
    true
}

async fn join_cluster(state: &AppState) -> Result<(), String> {
    let context = join_context(state)?;
    let join_response = send_join_request(&context).await?;
    log_cluster_config_mismatch(state, &join_response.cluster_config);
    tracing::info!(
        node_id = %join_response.node_id,
        "joined cluster"
    );
    Ok(())
}

fn join_context(state: &AppState) -> Result<JoinContext, String> {
    let master = state
        .config
        .master_url
        .clone()
        .ok_or_else(|| "NSS_MASTER_URL is required".to_string())?;
    let join_token = state
        .config
        .join_token
        .clone()
        .ok_or_else(|| "NSS_JOIN_TOKEN is required".to_string())?;
    let address = state
        .config
        .replica_advertise
        .clone()
        .unwrap_or_else(|| format!("http://localhost{}", state.config.replica_listen));
    Ok(JoinContext {
        address,
        join_token,
        master,
    })
}

async fn send_join_request(context: &JoinContext) -> Result<JoinResponse, String> {
    let request = JoinRequest {
        address_internal: context.address.clone(),
        capacity_bytes: 0,
        free_bytes: 0,
    };
    let url = format!(
        "{}/internal/v1/cluster/join",
        context.master.trim_end_matches('/')
    );
    let response = Client::new()
        .post(url)
        .header("Authorization", format!("Bearer {}", context.join_token))
        .json(&request)
        .send()
        .await
        .map_err(|err| format!("join request failed: {err}"))?;
    parse_join_response(response).await
}

async fn parse_join_response(response: reqwest::Response) -> Result<JoinResponse, String> {
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| format!("join response read failed: {err}"))?;
    if !status.is_success() {
        return Err(format!("join failed: {status} {body}"));
    }
    serde_json::from_str(&body).map_err(|err| format!("join response failed: {err} body={body}"))
}

fn log_cluster_config_mismatch(
    state: &AppState,
    cluster_config: &crate::storage::replication::ClusterConfig,
) {
    log_config_mismatch(
        "replication factor mismatch",
        state.config.replication_factor,
        cluster_config.replication_factor,
    );
    log_config_mismatch(
        "write quorum mismatch",
        state.config.write_quorum,
        cluster_config.write_quorum,
    );
    log_string_mismatch(
        "checksum algorithm mismatch",
        state.config.checksum_algo.as_str(),
        cluster_config.checksum_algo.as_str(),
    );
    log_config_mismatch(
        "chunk size mismatch",
        state.chunk_size_bytes,
        cluster_config.chunk_size_bytes,
    );
}

fn log_config_mismatch<T>(message: &str, local: T, remote: T)
where
    T: std::fmt::Display + PartialEq,
{
    if local != remote {
        tracing::warn!(local = %local, remote = %remote, "{message}");
    }
}

fn log_string_mismatch(message: &str, local: &str, remote: &str) {
    if local != remote {
        tracing::warn!(local = %local, remote = %remote, "{message}");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_servers, join_cluster, metrics_handler, metrics_router, ready_handler,
        spawn_heartbeat, spawn_server, sync_replica_mode, Servers,
    };
    use crate::api::AppState;
    use crate::obs::Metrics;
    use crate::storage::chunkstore::ChunkStore;
    use crate::test_support;
    use crate::util::runtime::ReplicaSubMode;
    use axum::http::Request;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::post;
    use axum::{Json, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::{oneshot, Notify};
    use tokio::task::JoinHandle;
    use tokio::time::{sleep, timeout};
    use tower::ServiceExt;
    use uuid::Uuid;

    fn join_success_router(attempts: Arc<AtomicUsize>) -> Router {
        Router::new().route(
            "/internal/v1/cluster/join",
            post(move || {
                let attempts = attempts.clone();
                async move {
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        return (StatusCode::BAD_REQUEST, "retry").into_response();
                    }
                    let response = Json(serde_json::json!({
                        "nodeId": Uuid::new_v4(),
                        "clusterConfig": {
                            "chunk_size_bytes": 1024,
                            "replication_factor": 1,
                            "write_quorum": 1,
                            "checksum_algo": "crc32c"
                        }
                    }));
                    (StatusCode::OK, response).into_response()
                }
            }),
        )
    }

    async fn join_with_retries(state: &AppState) -> Result<(), String> {
        for _ in 0..5 {
            let result = join_cluster(state).await;
            if result.is_ok() {
                return Ok(());
            }
            sleep(Duration::from_millis(50)).await;
        }
        Err("join failed".to_string())
    }

    async fn assert_join_parse_error(base_url: String) {
        let state = build_replica_state(Some(base_url), Some("token".to_string())).await;
        let err = join_cluster(&state).await.unwrap_err();
        assert!(err.contains("join response failed"));
    }

    async fn assert_join_read_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n12")
                .await;
        });
        sleep(Duration::from_millis(50)).await;
        let state =
            build_replica_state(Some(format!("http://{}", addr)), Some("token".to_string())).await;
        let err = join_cluster(&state).await.unwrap_err();
        assert!(err.contains("join response read failed"));
        let _ = handle.await;
    }

    struct ServerHandle {
        shutdown: Option<oneshot::Sender<()>>,
        join: JoinHandle<()>,
    }

    impl ServerHandle {
        async fn shutdown(mut self) {
            if let Some(tx) = self.shutdown.take() {
                let _ = tx.send(());
            }
            let _ = self.join.await;
        }
    }

    async fn spawn_app(app: Router) -> (String, ServerHandle) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });
        sleep(Duration::from_millis(50)).await;
        (
            format!("http://{}", addr),
            ServerHandle {
                shutdown: Some(shutdown_tx),
                join,
            },
        )
    }

    async fn build_replica_state(
        master_url: Option<String>,
        join_token: Option<String>,
    ) -> AppState {
        let pool = test_support::setup_pool().await;
        test_support::reset_db(&pool).await;
        let data_dir = test_support::new_temp_dir("replica").await;
        let mut config = test_support::base_config("replica", data_dir.clone());
        config.master_url = master_url;
        config.join_token = join_token;
        let metrics = Metrics::new();
        let chunk_store = ChunkStore::from_runtime(&config).expect("chunk store");
        AppState::new(config, pool, chunk_store, metrics)
            .await
            .expect("state")
    }

    #[tokio::test]
    async fn join_cluster_requires_master_and_token() {
        let state = build_replica_state(None, None).await;
        let err = join_cluster(&state).await.unwrap_err();
        assert!(err.contains("NSS_MASTER_URL"));
    }

    #[tokio::test]
    async fn build_servers_requires_master_url() {
        let state = build_replica_state(None, Some("token".to_string())).await;
        let err = build_servers(state).await.err().expect("err");
        assert!(err.contains("NSS_MASTER_URL"));
    }

    #[tokio::test]
    async fn build_servers_maps_invalid_s3_listen_without_join() {
        let mut state = build_replica_state(None, None).await;
        state.config.s3_listen = "invalid".to_string();
        state.config.replica_listen = "127.0.0.1:0".to_string();
        state.config.metrics_listen = "127.0.0.1:0".to_string();
        let err = build_servers(state).await.err().expect("invalid listen");
        assert!(err.contains("invalid listen addr") || err.contains("NSS_MASTER_URL"));
    }

    #[tokio::test]
    async fn join_cluster_requires_token() {
        let state = build_replica_state(Some("http://127.0.0.1:1".to_string()), None).await;
        let err = join_cluster(&state).await.unwrap_err();
        assert!(err.contains("NSS_JOIN_TOKEN"));
    }

    #[tokio::test]
    async fn join_cluster_handles_error_response() {
        let app = Router::new().route(
            "/internal/v1/cluster/join",
            post(|| async { (StatusCode::BAD_REQUEST, "bad") }),
        );
        let (base_url, server) = spawn_app(app).await;
        let state = build_replica_state(Some(base_url), Some("token".to_string())).await;
        let err = join_cluster(&state).await.unwrap_err();
        assert!(err.contains("join failed"));
        server.shutdown().await;
    }

    #[tokio::test]
    async fn join_cluster_success() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let app = join_success_router(attempts);
        let (base_url, server) = spawn_app(app).await;
        let state = build_replica_state(Some(base_url), Some("token".to_string())).await;
        join_with_retries(&state).await.expect("join");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn join_with_retries_reports_failure_after_exhaustion() {
        let state = build_replica_state(
            Some("http://127.0.0.1:1".to_string()),
            Some("token".to_string()),
        )
        .await;
        let err = join_with_retries(&state).await.unwrap_err();
        assert_eq!(err, "join failed");
    }

    #[tokio::test]
    async fn join_cluster_logs_mismatched_config() {
        let app = Router::new().route(
            "/internal/v1/cluster/join",
            post(|| async {
                let response = Json(serde_json::json!({
                    "nodeId": Uuid::new_v4(),
                    "clusterConfig": {
                        "chunk_size_bytes": 2048,
                        "replication_factor": 2,
                        "write_quorum": 2,
                        "checksum_algo": "sha256"
                    }
                }));
                (StatusCode::OK, response)
            }),
        );
        let (base_url, server) = spawn_app(app).await;
        let mut state = build_replica_state(Some(base_url), Some("token".to_string())).await;
        state.config.replication_factor = 1;
        state.config.write_quorum = 1;
        state.config.checksum_algo = crate::storage::checksum::ChecksumAlgo::Crc32c;
        let result = join_cluster(&state).await;
        assert!(result.is_ok());
        server.shutdown().await;
    }

    #[tokio::test]
    async fn sync_replica_mode_reports_status_and_payload_errors() {
        let state = build_replica_state(None, Some("token".to_string())).await;
        let client = reqwest::Client::new();

        let (status_url, status_server) = spawn_app(Router::new().route(
            "/internal/v1/cluster/replica-runtime/{id}",
            axum::routing::get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "bad") }),
        ))
        .await;
        let err = sync_replica_mode(&state, &client, status_url.as_str())
            .await
            .unwrap_err();
        assert!(err.contains("status"));
        status_server.shutdown().await;

        let (payload_url, payload_server) = spawn_app(Router::new().route(
            "/internal/v1/cluster/replica-runtime/{id}",
            axum::routing::get(|| async { (StatusCode::OK, "bad-json") }),
        ))
        .await;
        let err = sync_replica_mode(&state, &client, payload_url.as_str())
            .await
            .unwrap_err();
        assert!(err.contains("payload failed"));
        payload_server.shutdown().await;
    }

    #[tokio::test]
    async fn sync_replica_mode_reports_request_error() {
        let state = build_replica_state(None, Some("token".to_string())).await;
        let client = reqwest::Client::new();
        let err = sync_replica_mode(&state, &client, "http://127.0.0.1:1")
            .await
            .unwrap_err();
        assert!(err.contains("sync failed"));
    }

    #[tokio::test]
    async fn sync_replica_mode_updates_state_on_success() {
        let state = build_replica_state(None, Some("token".to_string())).await;
        let client = reqwest::Client::new();
        let (url, server) = spawn_app(Router::new().route(
            "/internal/v1/cluster/replica-runtime/{id}",
            axum::routing::get(|| async {
                (
                    StatusCode::OK,
                    Json(serde_json::json!({ "subMode": "backup" })),
                )
            }),
        ))
        .await;
        sync_replica_mode(&state, &client, url.as_str())
            .await
            .expect("sync");
        assert_eq!(
            state.replica_mode.get(),
            crate::util::runtime::ReplicaSubMode::Backup
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn sync_replica_mode_ignores_unknown_sub_mode() {
        let state = build_replica_state(None, Some("token".to_string())).await;
        state.replica_mode.set(ReplicaSubMode::Delivery);
        let client = reqwest::Client::new();
        let (url, server) = spawn_app(Router::new().route(
            "/internal/v1/cluster/replica-runtime/{id}",
            axum::routing::get(|| async {
                (
                    StatusCode::OK,
                    Json(serde_json::json!({ "subMode": "unknown" })),
                )
            }),
        ))
        .await;
        sync_replica_mode(&state, &client, url.as_str())
            .await
            .expect("sync");
        assert_eq!(state.replica_mode.get(), ReplicaSubMode::Delivery);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn ready_handler_detects_master_unreachable() {
        let mut state = build_replica_state(
            Some("http://127.0.0.1:1".to_string()),
            Some("token".to_string()),
        )
        .await;
        state.config.master_url = Some("http://127.0.0.1:1".to_string());
        let (status, _) = ready_handler(axum::extract::State(state)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn ready_handler_accepts_reachable_master() {
        let app = Router::new().route(
            "/internal/v1/cluster/config",
            axum::routing::get(|| async { StatusCode::OK }),
        );
        let (base_url, server) = spawn_app(app).await;
        let state = build_replica_state(Some(base_url), Some("token".to_string())).await;
        let (status, _) = ready_handler(axum::extract::State(state)).await;
        assert_eq!(status, StatusCode::OK);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn ready_handler_reports_ok_without_master() {
        let state = build_replica_state(None, None).await;
        let (status, message) = ready_handler(axum::extract::State(state)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(message, "ok");
    }

    #[tokio::test]
    async fn ready_handler_detects_data_dir_and_db_failure() {
        let mut state = build_replica_state(None, None).await;
        let file_path = test_support::new_temp_dir("replica-file")
            .await
            .join("not-a-dir");
        tokio::fs::write(&file_path, b"data").await.expect("write");
        state.config.data_dirs = vec![file_path];
        let (status, message) = ready_handler(axum::extract::State(state.clone())).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(message, "data dirs not writable");

        let mut state = build_replica_state(None, None).await;
        let pool = sqlx::PgPool::connect_lazy("postgres://nss:nss@127.0.0.1:1/nss?sslmode=disable")
            .expect("pool");
        state.repo = crate::meta::repos::Repo::new(pool);
        let (status, message) = ready_handler(axum::extract::State(state)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(message, "db not ready");
    }

    #[tokio::test]
    async fn build_servers_rejects_invalid_listen() {
        let app = Router::new().route(
            "/internal/v1/cluster/join",
            post(|| async {
                let response = Json(serde_json::json!({
                    "nodeId": Uuid::new_v4(),
                    "clusterConfig": {
                        "chunk_size_bytes": 1024,
                        "replication_factor": 1,
                        "write_quorum": 1,
                        "checksum_algo": "crc32c"
                    }
                }));
                (StatusCode::OK, response)
            }),
        );
        let (base_url, server) = spawn_app(app).await;
        let mut state = build_replica_state(Some(base_url), Some("token".to_string())).await;
        state.config.replica_listen = "invalid".to_string();
        let err = build_servers(state).await.err().expect("err");
        let has_invalid = err.contains("invalid listen addr");
        let has_join = err.contains("join");
        assert!(has_invalid | has_join);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn build_servers_rejects_invalid_s3_listen() {
        let app = Router::new().route(
            "/internal/v1/cluster/join",
            post(|| async {
                let response = Json(serde_json::json!({
                    "nodeId": Uuid::new_v4(),
                    "clusterConfig": {
                        "chunk_size_bytes": 1024,
                        "replication_factor": 1,
                        "write_quorum": 1,
                        "checksum_algo": "crc32c"
                    }
                }));
                (StatusCode::OK, response)
            }),
        );
        let (base_url, server) = spawn_app(app).await;
        let mut state = build_replica_state(Some(base_url), Some("token".to_string())).await;
        state.config.s3_listen = "invalid".to_string();
        let err = build_servers(state).await.err().expect("err");
        let has_invalid = err.contains("invalid listen addr");
        let has_join = err.contains("join");
        assert!(has_invalid | has_join);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn build_servers_rejects_invalid_metrics_listen() {
        let app = Router::new().route(
            "/internal/v1/cluster/join",
            post(|| async {
                let response = Json(serde_json::json!({
                    "nodeId": Uuid::new_v4(),
                    "clusterConfig": {
                        "chunk_size_bytes": 1024,
                        "replication_factor": 1,
                        "write_quorum": 1,
                        "checksum_algo": "crc32c"
                    }
                }));
                (StatusCode::OK, response)
            }),
        );
        let (base_url, server) = spawn_app(app).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut state = build_replica_state(Some(base_url), Some("token".to_string())).await;
        state.config.replica_listen = addr.to_string();
        state.config.metrics_listen = "invalid".to_string();
        let err = build_servers(state).await.err().expect("err");
        assert!(err.contains("invalid listen addr"));
        drop(listener);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn build_servers_succeeds_with_ephemeral_ports() {
        let app = Router::new().route(
            "/internal/v1/cluster/join",
            post(|| async {
                let response = Json(serde_json::json!({
                    "nodeId": Uuid::new_v4(),
                    "clusterConfig": {
                        "chunk_size_bytes": 1024,
                        "replication_factor": 1,
                        "write_quorum": 1,
                        "checksum_algo": "crc32c"
                    }
                }));
                (StatusCode::OK, response)
            }),
        );
        let (base_url, server) = spawn_app(app).await;
        let mut state = build_replica_state(Some(base_url), Some("token".to_string())).await;
        state.config.replica_listen = "127.0.0.1:0".to_string();
        state.config.metrics_listen = "127.0.0.1:0".to_string();
        state.config.s3_listen = "127.0.0.1:0".to_string();
        let servers = build_servers(state).await.expect("servers");
        assert_eq!(servers.handles.len(), 3);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn servers_run_all_waits_for_handles() {
        let handle = tokio::spawn(async move {});
        let servers = Servers {
            handles: vec![handle],
        };
        servers.run_all().await;
    }

    #[tokio::test]
    async fn server_handle_shutdown_handles_missing_sender() {
        let handle = tokio::spawn(async move {});
        let server = ServerHandle {
            shutdown: None,
            join: handle,
        };
        server.shutdown().await;
    }

    #[tokio::test]
    async fn metrics_router_healthz_returns_ok() {
        let state = build_replica_state(None, None).await;
        let app = metrics_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_handler_returns_payload() {
        let state = build_replica_state(None, None).await;
        let body = metrics_handler(axum::extract::State(state)).await;
        assert!(body.contains("nss_node_heartbeat_age_seconds"));
        assert!(body.contains("node_id="));
    }

    #[tokio::test]
    async fn heartbeat_background_task_sends_request() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = hits.clone();
        let notify = Arc::new(Notify::new());
        let notify_clone = notify.clone();
        let app = Router::new().route(
            "/internal/v1/cluster/heartbeat",
            post(move || {
                let hits = hits_clone.clone();
                let notify = notify_clone.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    notify.notify_one();
                    StatusCode::NO_CONTENT
                }
            }),
        );
        let (base_url, server) = spawn_app(app).await;
        let mut state =
            build_replica_state(Some(base_url.clone()), Some("token".to_string())).await;
        state.config.master_url = Some(base_url);
        spawn_heartbeat(state);
        let _ = timeout(Duration::from_secs(2), notify.notified())
            .await
            .expect("heartbeat");
        assert!(hits.load(Ordering::SeqCst) > 0);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn spawn_heartbeat_exits_without_master() {
        let state = build_replica_state(None, None).await;
        spawn_heartbeat(state);
        sleep(Duration::from_millis(10)).await;
    }

    #[tokio::test]
    async fn join_cluster_reports_request_and_parse_errors() {
        let state = build_replica_state(
            Some("http://127.0.0.1:1".to_string()),
            Some("token".to_string()),
        )
        .await;
        let err = join_cluster(&state).await.unwrap_err();
        assert!(err.contains("join request failed"));
        assert_join_read_error().await;

        let app = Router::new().route(
            "/internal/v1/cluster/join",
            post(|| async { (StatusCode::OK, "not-json") }),
        );
        let (base_url, server) = spawn_app(app).await;
        assert_join_parse_error(base_url).await;
        server.shutdown().await;
    }

    #[tokio::test]
    async fn spawn_server_binds_and_serves_requests() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        async fn ok() -> &'static str {
            "ok"
        }
        let app = Router::new().route("/healthz", axum::routing::get(ok));
        let handle = spawn_server(&addr.to_string(), app).expect("spawn");
        sleep(Duration::from_millis(50)).await;
        let response = reqwest::get(format!("http://{}/healthz", addr))
            .await
            .expect("request");
        assert_eq!(response.status(), StatusCode::OK);
        handle.abort();
    }

    #[tokio::test]
    async fn spawn_server_handles_bind_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        async fn ok() -> &'static str {
            "ok"
        }
        assert_eq!(ok().await, "ok");
        let app = Router::new().route("/healthz", axum::routing::get(ok));
        let handle = spawn_server(&addr.to_string(), app).expect("spawn");
        sleep(Duration::from_millis(20)).await;
        drop(listener);
        handle.abort();
    }
}

fn spawn_heartbeat(state: AppState) {
    tokio::spawn(async move {
        let master = match state.config.master_url.clone() {
            Some(val) => val,
            None => return,
        };
        let client = Client::new();
        loop {
            let _ = sync_replica_mode(&state, &client, master.as_str()).await;
            let url = format!(
                "{}/internal/v1/cluster/heartbeat",
                master.trim_end_matches('/')
            );
            let request = HeartbeatRequest {
                node_id: state.node_id,
                free_bytes: 0,
                capacity_bytes: 0,
            };
            let _ = client
                .post(url)
                .header("Authorization", state.internal_auth.header_value())
                .json(&request)
                .send()
                .await;
            sleep(Duration::from_secs(10)).await;
        }
    });
}

async fn sync_replica_mode(state: &AppState, client: &Client, master: &str) -> Result<(), String> {
    let url = format!(
        "{}/internal/v1/cluster/replica-runtime/{}",
        master.trim_end_matches('/'),
        state.node_id
    );
    let response = client
        .get(url)
        .header("Authorization", state.internal_auth.header_value())
        .send()
        .await
        .map_err(|err| format!("replica mode sync failed: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("replica mode sync status {}", response.status()));
    }
    let payload = response
        .json::<ReplicaRuntimeSyncResponse>()
        .await
        .map_err(|err| format!("replica mode payload failed: {err}"))?;
    if let Some(mode) = ReplicaSubMode::parse(payload.sub_mode.as_str()) {
        state.replica_mode.set(mode);
    }
    Ok(())
}
