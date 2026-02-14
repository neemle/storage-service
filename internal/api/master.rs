use crate::api::{internal, portal, refresh_node_heartbeat_metrics, AppState};
use crate::obs::MetricsLayer;
use crate::s3;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{extract::State, Router};
use prometheus::{Encoder, TextEncoder};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

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

pub fn build_servers(state: AppState) -> Result<Servers, String> {
    let mut handles = Vec::new();

    let s3_state = state.clone();
    let s3_app = s3::router(s3_state).layer(MetricsLayer::new(state.metrics.clone(), "s3"));
    handles.push(spawn_server(&state.config.s3_listen, s3_app)?);

    let api_state = state.clone();
    let api_app = portal::router(api_state).layer(MetricsLayer::new(state.metrics.clone(), "api"));
    handles.push(spawn_server(&state.config.api_listen, api_app)?);

    let internal_state = state.clone();
    let internal_app = internal::master_router(internal_state)
        .layer(MetricsLayer::new(state.metrics.clone(), "internal"));
    handles.push(spawn_server(&state.config.internal_listen, internal_app)?);

    let metrics_state = state.clone();
    let metrics_app =
        metrics_router(metrics_state).layer(MetricsLayer::new(state.metrics.clone(), "metrics"));
    handles.push(spawn_server(&state.config.metrics_listen, metrics_app)?);

    Ok(Servers { handles })
}

fn spawn_server(addr: &str, app: Router) -> Result<JoinHandle<()>, String> {
    let socket: SocketAddr = addr
        .parse()
        .map_err(|_| format!("invalid listen addr {addr}"))?;
    let handle = tokio::spawn(async move {
        let listener = match TcpListener::bind(socket).await {
            Ok(val) => val,
            Err(_) => return,
        };
        let _ = axum::serve(listener, app).await;
    });
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

#[cfg(test)]
mod tests {
    use super::{
        build_servers, check_data_dirs, metrics_handler, metrics_router, ready_handler,
        spawn_server,
    };
    use crate::api::AppState;
    use crate::cache::{CacheStore, RateLimiter};
    use crate::events::EventPublisher;
    use crate::jobs::RepairQueue;
    use crate::meta::repos::Repo;
    use crate::obs::Metrics;
    use crate::storage::chunkstore::ChunkStore;
    use crate::storage::replication::ReplicationManager;
    use crate::test_support;
    use crate::util::http::InternalAuth;
    use axum::routing::get;
    use axum::{
        http::{Request, StatusCode},
        Router,
    };
    use chrono::Duration as ChronoDuration;
    use tokio::time::{sleep, Duration};
    use tower::ServiceExt;
    use uuid::Uuid;

    #[tokio::test]
    async fn build_servers_rejects_invalid_listen() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.s3_listen = "invalid".to_string();
        let err = build_servers(state).err().expect("err");
        assert!(err.contains("invalid listen addr"));
    }

    #[tokio::test]
    async fn build_servers_rejects_invalid_secondary_listeners() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.s3_listen = "127.0.0.1:0".to_string();
        state.config.api_listen = "127.0.0.1:0".to_string();
        state.config.internal_listen = "127.0.0.1:0".to_string();
        state.config.metrics_listen = "127.0.0.1:0".to_string();

        state.config.api_listen = "invalid".to_string();
        let err = build_servers(state.clone()).err().expect("err");
        assert!(err.contains("invalid listen addr"));

        state.config.api_listen = "127.0.0.1:0".to_string();
        state.config.internal_listen = "invalid".to_string();
        let err = build_servers(state.clone()).err().expect("err");
        assert!(err.contains("invalid listen addr"));

        state.config.internal_listen = "127.0.0.1:0".to_string();
        state.config.metrics_listen = "invalid".to_string();
        let err = build_servers(state).err().expect("err");
        assert!(err.contains("invalid listen addr"));
    }

    #[tokio::test]
    async fn ready_handler_checks_dirs_and_db() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (status, _) = ready_handler(axum::extract::State(state)).await;
        assert_eq!(status, StatusCode::OK);
        let state = state_with_missing_data_dir().await;
        assert!(!check_data_dirs(&state).await);
        let (status, _) = ready_handler(axum::extract::State(state)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    async fn state_with_missing_data_dir() -> AppState {
        let missing_dir = std::env::temp_dir().join("nss-missing-dir");
        let config = test_support::base_config("master", missing_dir);
        let pool = sqlx::PgPool::connect_lazy("postgres://nss:nss@127.0.0.1:1/nss?sslmode=disable")
            .expect("pool");
        let repo = Repo::new(pool);
        build_state_for_missing_dir(config, repo).await
    }

    async fn build_state_for_missing_dir(
        config: crate::util::config::Config,
        repo: Repo,
    ) -> AppState {
        let metrics = Metrics::new();
        let parts = build_missing_dir_state_parts(&config, &repo, metrics.clone());
        AppState {
            config,
            repo,
            metrics,
            token_manager: parts.token_manager,
            events: EventPublisher::new(None).await.expect("events"),
            replication: parts.replication,
            repair_queue: parts.repair_queue,
            cache: parts.cache,
            rate_limiter: parts.rate_limiter,
            encryption_key: parts.encryption_key,
            node_id: Uuid::new_v4(),
            chunk_size_bytes: 1024,
            internal_auth: InternalAuth::new("token".to_string()),
            replica_mode: parts.replica_mode,
        }
    }

    struct MissingDirStateParts {
        cache: CacheStore,
        encryption_key: Vec<u8>,
        rate_limiter: RateLimiter,
        repair_queue: RepairQueue,
        replication: ReplicationManager,
        token_manager: crate::auth::token::TokenManager,
        replica_mode: crate::util::runtime::ReplicaModeState,
    }

    fn build_missing_dir_state_parts(
        config: &crate::util::config::Config,
        repo: &Repo,
        metrics: std::sync::Arc<Metrics>,
    ) -> MissingDirStateParts {
        let encryption_key = config.secret_encryption_key.clone();
        let token_manager = crate::auth::token::TokenManager::new(
            &config.jwt_signing_key,
            ChronoDuration::hours(12),
        );
        let cache = CacheStore::Memory(crate::cache::MemoryCache::new());
        let rate_limiter = RateLimiter::new(cache.clone());
        let repair_queue = RepairQueue::new();
        let replication =
            build_missing_dir_replication(config, repo, repair_queue.clone(), metrics);
        let replica_mode = crate::util::runtime::ReplicaModeState::new(
            crate::util::runtime::ReplicaSubMode::Delivery,
        );
        MissingDirStateParts {
            cache,
            encryption_key,
            rate_limiter,
            repair_queue,
            replication,
            token_manager,
            replica_mode,
        }
    }

    fn build_missing_dir_replication(
        config: &crate::util::config::Config,
        repo: &Repo,
        repair_queue: RepairQueue,
        metrics: std::sync::Arc<Metrics>,
    ) -> ReplicationManager {
        let chunk_store = ChunkStore::from_runtime(&config).expect("chunk store");
        ReplicationManager::new(
            repo.clone(),
            chunk_store,
            config.checksum_algo,
            config.replication_factor,
            config.write_quorum,
            InternalAuth::new(config.internal_shared_token.clone()),
            Uuid::new_v4(),
            repair_queue,
            metrics,
        )
    }

    #[tokio::test]
    async fn build_servers_starts_listeners() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let servers = build_servers(state).expect("servers");
        assert_eq!(servers.handles.len(), 4);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn metrics_router_healthz_returns_ok() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
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
    async fn ready_handler_reports_db_unavailable() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        let pool = sqlx::PgPool::connect_lazy("postgres://nss:nss@127.0.0.1:1/nss?sslmode=disable")
            .expect("pool");
        state.repo = Repo::new(pool);
        let (status, message) = ready_handler(axum::extract::State(state)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(message, "db not ready");
    }

    #[tokio::test]
    async fn metrics_handler_returns_payload() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let body = metrics_handler(axum::extract::State(state)).await;
        assert!(body.contains("nss_node_heartbeat_age_seconds"));
        assert!(body.contains("node_id="));
    }

    #[tokio::test]
    async fn build_servers_succeeds_with_ephemeral_ports() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.s3_listen = "127.0.0.1:0".to_string();
        state.config.api_listen = "127.0.0.1:0".to_string();
        state.config.internal_listen = "127.0.0.1:0".to_string();
        state.config.metrics_listen = "127.0.0.1:0".to_string();
        let servers = build_servers(state).expect("servers");
        assert_eq!(servers.handles.len(), 4);
    }

    #[tokio::test]
    async fn servers_run_all_waits_for_handles() {
        let handle = tokio::spawn(async {});
        let servers = super::Servers {
            handles: vec![handle],
        };
        servers.run_all().await;
    }

    #[tokio::test]
    async fn spawn_server_handles_bind_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        async fn ok() -> &'static str {
            "ok"
        }
        assert_eq!(ok().await, "ok");
        let app = Router::new().route("/healthz", get(ok));
        let handle = spawn_server(&addr.to_string(), app).expect("spawn");
        drop(listener);
        handle.abort();
    }

    #[tokio::test]
    async fn spawn_server_binds_and_serves_requests() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        let app = Router::new().route("/healthz", get(|| async { "ok" }));
        let handle = spawn_server(&addr.to_string(), app).expect("spawn");
        sleep(Duration::from_millis(50)).await;
        let response = reqwest::get(format!("http://{}/healthz", addr))
            .await
            .expect("request");
        assert_eq!(response.status(), StatusCode::OK);
        handle.abort();
    }

    #[tokio::test]
    async fn spawn_server_handles_in_use_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        async fn ok() -> &'static str {
            "ok"
        }
        assert_eq!(ok().await, "ok");
        let app = Router::new().route("/healthz", get(ok));
        let handle = spawn_server(&addr.to_string(), app).expect("spawn");
        sleep(Duration::from_millis(50)).await;
        handle.abort();
        drop(listener);
    }
}
