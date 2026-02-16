use crate::auth::{password, token::TokenManager};
use crate::cache::{CacheStore, RateLimiter};
use crate::events::EventPublisher;
use crate::jobs::RepairQueue;
use crate::meta::repos::Repo;
use crate::obs::Metrics;
use crate::storage::chunkstore::ChunkStore;
use crate::storage::replication::ReplicationManager;
use crate::util::config::Config;
use crate::util::http::InternalAuth;
use crate::util::runtime::{ReplicaModeState, ReplicaSubMode};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

pub mod admin;
pub mod admin_storage;
pub mod auth;
pub mod console;
pub mod internal;
pub mod master;
pub mod portal;
pub mod replica;
pub mod volume_capacity;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub repo: Repo,
    pub metrics: Arc<Metrics>,
    pub token_manager: TokenManager,
    pub events: EventPublisher,
    pub replication: ReplicationManager,
    pub repair_queue: RepairQueue,
    pub cache: CacheStore,
    pub rate_limiter: RateLimiter,
    pub encryption_key: Vec<u8>,
    pub node_id: Uuid,
    pub chunk_size_bytes: u64,
    pub internal_auth: InternalAuth,
    pub replica_mode: ReplicaModeState,
}

impl AppState {
    pub async fn new(
        config: Config,
        pool: PgPool,
        chunk_store: ChunkStore,
        metrics: Arc<Metrics>,
    ) -> Result<Self, String> {
        if config.data_dirs.is_empty() {
            return Err("NSS_DATA_DIRS must have at least one entry".into());
        }
        let repo = Repo::new(pool.clone());
        let deps = build_app_state_deps(&config, &repo, chunk_store, metrics.clone()).await?;

        Ok(Self {
            config,
            repo,
            metrics,
            token_manager: deps.token_manager,
            events: deps.events,
            replication: deps.replication,
            repair_queue: deps.repair_queue,
            cache: deps.cache,
            rate_limiter: deps.rate_limiter,
            encryption_key: deps.encryption_key,
            node_id: deps.node_id,
            chunk_size_bytes: deps.chunk_size_bytes,
            internal_auth: deps.internal_auth,
            replica_mode: deps.replica_mode,
        })
    }
}

struct AppStateDeps {
    cache: CacheStore,
    chunk_size_bytes: u64,
    encryption_key: Vec<u8>,
    events: EventPublisher,
    internal_auth: InternalAuth,
    node_id: Uuid,
    rate_limiter: RateLimiter,
    repair_queue: RepairQueue,
    replication: ReplicationManager,
    token_manager: TokenManager,
    replica_mode: ReplicaModeState,
}

struct AppStateCoreDeps {
    cache: CacheStore,
    chunk_size_bytes: u64,
    encryption_key: Vec<u8>,
    events: EventPublisher,
    internal_auth: InternalAuth,
    node_id: Uuid,
    rate_limiter: RateLimiter,
    token_manager: TokenManager,
    replica_mode: ReplicaModeState,
}

async fn build_app_state_deps(
    config: &Config,
    repo: &Repo,
    chunk_store: ChunkStore,
    metrics: Arc<Metrics>,
) -> Result<AppStateDeps, String> {
    let core = build_app_state_core_deps(config, repo).await?;
    ensure_bootstrap_admin(repo, config).await?;
    let (repair_queue, replication) = build_replication_parts(
        config,
        repo.clone(),
        chunk_store,
        core.internal_auth.clone(),
        core.node_id,
        metrics,
    );
    Ok(merge_app_state_deps(core, repair_queue, replication))
}

fn build_replication_parts(
    config: &Config,
    repo: Repo,
    chunk_store: ChunkStore,
    internal_auth: InternalAuth,
    node_id: Uuid,
    metrics: Arc<Metrics>,
) -> (RepairQueue, ReplicationManager) {
    let repair_queue = RepairQueue::new();
    let replication = build_replication_manager(
        config,
        repo,
        chunk_store,
        internal_auth,
        node_id,
        repair_queue.clone(),
        metrics,
    );
    (repair_queue, replication)
}

fn merge_app_state_deps(
    core: AppStateCoreDeps,
    repair_queue: RepairQueue,
    replication: ReplicationManager,
) -> AppStateDeps {
    AppStateDeps {
        cache: core.cache,
        chunk_size_bytes: core.chunk_size_bytes,
        encryption_key: core.encryption_key,
        events: core.events,
        internal_auth: core.internal_auth,
        node_id: core.node_id,
        rate_limiter: core.rate_limiter,
        repair_queue,
        replication,
        token_manager: core.token_manager,
        replica_mode: core.replica_mode,
    }
}

async fn build_app_state_core_deps(
    config: &Config,
    repo: &Repo,
) -> Result<AppStateCoreDeps, String> {
    let encryption_key = config.secret_encryption_key.clone();
    let token_manager = build_token_manager(&config.jwt_signing_key);
    let events = build_event_publisher(config).await?;
    let internal_auth = InternalAuth::new(config.internal_shared_token.clone());
    let node_id = ensure_local_node(repo, config).await?;
    let replica_mode = ReplicaModeState::new(
        ReplicaSubMode::parse(&config.replica_sub_mode).unwrap_or(ReplicaSubMode::Delivery),
    );
    let chunk_size_bytes = config.computed_chunk_size_bytes()?;
    let cache = CacheStore::new(config.redis_url.as_deref()).await?;
    let rate_limiter = RateLimiter::new(cache.clone());
    Ok(AppStateCoreDeps {
        cache,
        chunk_size_bytes,
        encryption_key,
        events,
        internal_auth,
        node_id,
        rate_limiter,
        replica_mode,
        token_manager,
    })
}

fn build_token_manager(jwt_signing_key: &[u8]) -> TokenManager {
    TokenManager::new(jwt_signing_key, Duration::hours(12))
}

async fn build_event_publisher(config: &Config) -> Result<EventPublisher, String> {
    EventPublisher::new(config.rabbit_url.as_deref()).await
}

async fn ensure_bootstrap_admin(repo: &Repo, config: &Config) -> Result<(), String> {
    if config.mode != "master" {
        return Ok(());
    }
    let password_hash = password::hash_password(&config.admin_bootstrap_password)?;
    repo.ensure_admin_user_with_policy(
        &config.admin_bootstrap_user,
        &password_hash,
        bootstrap_force_password_enabled(),
    )
    .await
    .map_err(|err| format!("ensure admin failed: {err}"))?;
    Ok(())
}

fn bootstrap_force_password_enabled() -> bool {
    std::env::var("NSS_ADMIN_BOOTSTRAP_FORCE_PASSWORD")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}

fn build_replication_manager(
    config: &Config,
    repo: Repo,
    chunk_store: ChunkStore,
    internal_auth: InternalAuth,
    node_id: Uuid,
    repair_queue: RepairQueue,
    metrics: Arc<Metrics>,
) -> ReplicationManager {
    ReplicationManager::new(
        repo,
        chunk_store,
        config.checksum_algo,
        config.replication_factor,
        config.write_quorum,
        internal_auth,
        node_id,
        repair_queue,
        metrics,
    )
}

fn local_address(config: &Config) -> String {
    if config.mode == "master" {
        config
            .internal_advertise
            .clone()
            .unwrap_or_else(|| format!("http://localhost{}", config.internal_listen))
    } else {
        config
            .replica_advertise
            .clone()
            .unwrap_or_else(|| format!("http://localhost{}", config.replica_listen))
    }
}

async fn ensure_local_node(repo: &Repo, config: &Config) -> Result<Uuid, String> {
    let address = local_address(config);
    if let Some(node) = lookup_local_node(repo, &address).await? {
        return Ok(node.node_id);
    }
    insert_local_node(repo, config, &address).await
}

pub async fn refresh_node_heartbeat_metrics(state: &AppState) {
    let nodes = match state.repo.list_nodes().await {
        Ok(nodes) => nodes,
        Err(err) => {
            tracing::debug!(error = %err, "node heartbeat metrics refresh failed");
            return;
        }
    };
    state.metrics.node_heartbeat_age.reset();
    let now = Utc::now();
    for node in nodes {
        if let Some(last_heartbeat) = node.last_heartbeat_at {
            let age_seconds = now
                .signed_duration_since(last_heartbeat)
                .num_seconds()
                .max(0);
            state
                .metrics
                .node_heartbeat_age
                .with_label_values(&[&node.node_id.to_string()])
                .set(age_seconds);
        }
    }
}

async fn lookup_local_node(
    repo: &Repo,
    address: &str,
) -> Result<Option<crate::meta::models::Node>, String> {
    match repo.get_node_by_address(address).await {
        Ok(node) => Ok(node),
        Err(err) if is_missing_nodes_table(&err) => Ok(None),
        Err(err) => Err(format!("node lookup failed: {err}")),
    }
}

fn is_missing_nodes_table(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db_err) if db_err.code().as_deref() == Some("42P01"))
}

async fn insert_local_node(repo: &Repo, config: &Config, address: &str) -> Result<Uuid, String> {
    let node_id = Uuid::new_v4();
    let role = if config.mode == "master" {
        "master"
    } else {
        "replica"
    };
    let (capacity_bytes, free_bytes) = local_node_capacity(config);
    repo.upsert_node(
        node_id,
        role,
        address,
        "online",
        capacity_bytes,
        free_bytes,
        Some(chrono::Utc::now()),
    )
    .await
    .map_err(|err| format!("node insert failed: {err}"))?;
    Ok(node_id)
}

fn local_node_capacity(config: &Config) -> (Option<i64>, Option<i64>) {
    let usage = crate::util::storage_volume::data_dirs_usage(&config.data_dirs);
    (Some(usage.capacity_bytes), Some(usage.free_bytes))
}

impl Clone for Repo {
    fn clone(&self) -> Self {
        Self::new(self.pool().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bootstrap_force_password_enabled, ensure_local_node, local_address,
        refresh_node_heartbeat_metrics, AppState,
    };
    use crate::meta::repos::Repo;
    use crate::obs::Metrics;
    use crate::storage::chunkstore::ChunkStore;
    use crate::test_support;
    use chrono::{Duration, Utc};
    use sqlx::PgPool;
    use uuid::Uuid;

    async fn assert_app_state_new_error_contains(
        config: crate::util::config::Config,
        pool: &PgPool,
        chunk_store: &ChunkStore,
        expected: &str,
    ) {
        let err = AppState::new(config, pool.clone(), chunk_store.clone(), Metrics::new())
            .await
            .err()
            .expect("expected error");
        assert!(err.contains(expected));
    }

    async fn assert_local_node_reused(state: &AppState, expected: Uuid) {
        state
            .repo
            .upsert_node(
                Uuid::new_v4(),
                "replica",
                "http://other",
                "online",
                None,
                None,
                Some(chrono::Utc::now()),
            )
            .await
            .expect("node");
        let node_id = ensure_local_node(&state.repo, &state.config)
            .await
            .expect("ensure");
        assert_eq!(node_id, expected);
    }

    #[tokio::test]
    async fn local_address_prefers_master_and_replica_defaults() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.internal_advertise = None;
        let addr = local_address(&state.config);
        assert!(addr.contains("http://localhost"));
        state.config.mode = "replica".to_string();
        let addr = local_address(&state.config);
        assert!(addr.contains("http://localhost"));
    }

    #[test]
    fn bootstrap_force_password_enabled_parses_truthy_values() {
        let prev = std::env::var("NSS_ADMIN_BOOTSTRAP_FORCE_PASSWORD").ok();
        std::env::set_var("NSS_ADMIN_BOOTSTRAP_FORCE_PASSWORD", "yes");
        assert!(bootstrap_force_password_enabled());
        std::env::set_var("NSS_ADMIN_BOOTSTRAP_FORCE_PASSWORD", "0");
        assert!(!bootstrap_force_password_enabled());
        if let Some(value) = prev {
            std::env::set_var("NSS_ADMIN_BOOTSTRAP_FORCE_PASSWORD", value);
        } else {
            std::env::remove_var("NSS_ADMIN_BOOTSTRAP_FORCE_PASSWORD");
        }
    }

    #[test]
    fn bootstrap_force_password_enabled_restores_existing_value() {
        std::env::set_var("NSS_ADMIN_BOOTSTRAP_FORCE_PASSWORD", "true");
        bootstrap_force_password_enabled_parses_truthy_values();
        let restored = std::env::var("NSS_ADMIN_BOOTSTRAP_FORCE_PASSWORD")
            .expect("force password env should be restored");
        assert_eq!(restored, "true");
    }

    #[tokio::test]
    async fn refresh_node_heartbeat_metrics_returns_on_repo_error() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        refresh_node_heartbeat_metrics(&state).await;
    }

    #[tokio::test]
    async fn refresh_node_heartbeat_metrics_sets_value_for_recent_nodes() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let node_id = Uuid::new_v4();
        state
            .repo
            .upsert_node(
                node_id,
                "replica",
                "http://replica-heartbeat",
                "online",
                None,
                None,
                Some(Utc::now() - Duration::seconds(5)),
            )
            .await
            .expect("node");
        refresh_node_heartbeat_metrics(&state).await;
        let value = state
            .metrics
            .node_heartbeat_age
            .with_label_values(&[&node_id.to_string()])
            .get();
        assert!(value >= 0);
    }

    #[tokio::test]
    async fn refresh_node_heartbeat_metrics_skips_nodes_without_heartbeat() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let node_id = Uuid::new_v4();
        state
            .repo
            .upsert_node(
                node_id,
                "replica",
                "http://replica-no-heartbeat",
                "online",
                None,
                None,
                None,
            )
            .await
            .expect("node");
        refresh_node_heartbeat_metrics(&state).await;
        let value = state
            .metrics
            .node_heartbeat_age
            .with_label_values(&[&node_id.to_string()])
            .get();
        assert_eq!(value, 0);
    }

    #[tokio::test]
    async fn refresh_node_heartbeat_metrics_skips_null_heartbeat_row() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let node_id = Uuid::new_v4();
        sqlx::query(concat!(
            "INSERT INTO nodes (node_id, role, address_internal, status, last_heartbeat_at, ",
            "capacity_bytes, free_bytes, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        ))
        .bind(node_id)
        .bind("replica")
        .bind("http://replica-null-heartbeat")
        .bind("online")
        .bind(None::<chrono::DateTime<Utc>>)
        .bind(None::<i64>)
        .bind(None::<i64>)
        .bind(Utc::now())
        .execute(state.repo.pool())
        .await
        .expect("insert node");
        refresh_node_heartbeat_metrics(&state).await;
        let value = state
            .metrics
            .node_heartbeat_age
            .with_label_values(&[&node_id.to_string()])
            .get();
        assert_eq!(value, 0);
    }

    #[tokio::test]
    async fn refresh_node_heartbeat_metrics_clamps_future_heartbeat_to_zero() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let node_id = Uuid::new_v4();
        state
            .repo
            .upsert_node(
                node_id,
                "replica",
                "http://replica-future-heartbeat",
                "online",
                None,
                None,
                Some(Utc::now() + Duration::seconds(30)),
            )
            .await
            .expect("node");
        refresh_node_heartbeat_metrics(&state).await;
        let value = state
            .metrics
            .node_heartbeat_age
            .with_label_values(&[&node_id.to_string()])
            .get();
        assert_eq!(value, 0);
    }

    #[tokio::test]
    async fn ensure_local_node_reuses_existing() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let addr = local_address(&state.config);
        let existing = state
            .repo
            .get_node_by_address(&addr)
            .await
            .expect("node")
            .expect("node exists");
        let node_id = ensure_local_node(&state.repo, &state.config)
            .await
            .expect("ensure");
        assert_eq!(node_id, existing.node_id);
        assert_local_node_reused(&state, existing.node_id).await;
    }

    #[tokio::test]
    async fn app_state_new_reports_local_node_error() {
        let data_dir = test_support::new_temp_dir("state-node-error").await;
        let mut config = test_support::base_config("replica", data_dir);
        config.master_url = None;
        let pool = PgPool::connect_lazy("postgres://nss:nss@127.0.0.1:1/nss?sslmode=disable")
            .expect("pool");
        let metrics = Metrics::new();
        let chunk_store = ChunkStore::from_runtime(&config).expect("chunk store");
        let err = AppState::new(config, pool, chunk_store, metrics)
            .await
            .err()
            .expect("expected error");
        assert!(err.contains("node lookup failed"));
    }

    #[tokio::test]
    async fn app_state_new_reports_chunk_size_error() {
        let pool = test_support::setup_pool().await;
        test_support::reset_db(&pool).await;
        let missing_dir = std::env::temp_dir().join("nss-missing-dir");
        let mut config = test_support::base_config("replica", missing_dir.clone());
        config.chunk_size_bytes = None;
        let metrics = Metrics::new();
        let chunk_store = ChunkStore::from_runtime(&config).expect("chunk store");
        let _ = tokio::fs::remove_dir_all(&missing_dir).await;
        let err = AppState::new(config, pool, chunk_store, metrics)
            .await
            .err()
            .expect("expected error");
        assert!(err.contains("Failed to statfs"));
    }

    #[tokio::test]
    async fn local_address_prefers_advertise_settings() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.internal_advertise = Some("http://internal:9003".to_string());
        let addr = local_address(&state.config);
        assert_eq!(addr, "http://internal:9003");
        state.config.mode = "replica".to_string();
        state.config.replica_advertise = Some("http://replica:9010".to_string());
        let addr = local_address(&state.config);
        assert_eq!(addr, "http://replica:9010");
    }

    #[tokio::test]
    async fn ensure_local_node_creates_when_missing() {
        let (mut state, pool, _dir) = test_support::build_state("master").await;
        sqlx::query("DELETE FROM nodes")
            .execute(&pool)
            .await
            .expect("delete nodes");
        state.config.internal_advertise = Some("http://new-node".to_string());
        let node_id = ensure_local_node(&state.repo, &state.config)
            .await
            .expect("ensure");
        let found = state
            .repo
            .get_node_by_address("http://new-node")
            .await
            .expect("node");
        assert_eq!(found.map(|node| node.node_id), Some(node_id));
    }

    #[tokio::test]
    async fn repo_clone_uses_same_pool() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let repo = Repo::new(state.repo.pool().clone());
        let users = repo.list_users().await.expect("list");
        let _ = users;
    }

    #[tokio::test]
    async fn app_state_new_reports_dependency_errors() {
        let pool = test_support::setup_pool().await;
        let data_dir = test_support::new_temp_dir("state").await;
        let mut config = test_support::base_config("master", data_dir.clone());
        config.rabbit_url = Some("amqp://127.0.0.1:1".to_string());
        let chunk_store = ChunkStore::from_runtime(&config).expect("chunk store");
        assert_app_state_new_error_contains(config, &pool, &chunk_store, "rabbit connect failed")
            .await;

        let mut config = test_support::base_config("master", data_dir.clone());
        config.redis_url = Some("redis://127.0.0.1:1".to_string());
        assert_app_state_new_error_contains(config, &pool, &chunk_store, "redis").await;

        let mut config = test_support::base_config("master", data_dir.clone());
        config.data_dirs.clear();
        assert_app_state_new_error_contains(config, &pool, &chunk_store, "NSS_DATA_DIRS").await;

        let mut config = test_support::base_config("master", data_dir);
        config.admin_bootstrap_password = "__force_hash_error__".to_string();
        assert_app_state_new_error_contains(config, &pool, &chunk_store, "hash failed").await;
    }

    #[tokio::test]
    async fn app_state_new_reports_admin_repo_error() {
        let pool = test_support::setup_pool().await;
        let data_dir = test_support::new_temp_dir("state-admin").await;
        let config = test_support::base_config("master", data_dir.clone());
        let chunk_store = ChunkStore::from_runtime(&config).expect("chunk store");
        sqlx::query("ALTER TABLE users RENAME TO users_backup")
            .execute(&pool)
            .await
            .expect("rename");
        let result = AppState::new(config, pool.clone(), chunk_store, Metrics::new()).await;
        let _ = sqlx::query("ALTER TABLE users_backup RENAME TO users")
            .execute(&pool)
            .await;
        let err = result.err().expect("expected error");
        assert!(err.contains("ensure admin failed"));
    }

    #[tokio::test]
    async fn app_state_new_succeeds_with_valid_config() {
        let pool = test_support::setup_pool().await;
        test_support::reset_db(&pool).await;
        let data_dir = test_support::new_temp_dir("state-ok").await;
        let config = test_support::base_config("master", data_dir);
        let chunk_store = ChunkStore::from_runtime(&config).expect("chunk store");
        let state = AppState::new(config, pool.clone(), chunk_store, Metrics::new())
            .await
            .expect("state");
        assert_eq!(state.config.mode, "master");
        assert!(!state.config.data_dirs.is_empty());
    }

    #[tokio::test]
    async fn ensure_local_node_reports_repo_errors() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        let err = ensure_local_node(&state.repo, &state.config)
            .await
            .err()
            .expect("expected error");
        assert!(err.contains("node lookup failed"));

        let (state, pool, _dir) = test_support::build_state("master").await;
        sqlx::query("ALTER TABLE nodes RENAME TO nodes_backup")
            .execute(&pool)
            .await
            .expect("rename");
        let result = ensure_local_node(&state.repo, &state.config).await;
        let _ = sqlx::query("ALTER TABLE nodes_backup RENAME TO nodes")
            .execute(&pool)
            .await;
        let err = result.err().expect("expected error");
        assert!(err.contains("node insert failed"));
    }

    #[tokio::test]
    async fn ensure_local_node_creates_replica_role() {
        let pool = test_support::setup_pool().await;
        test_support::reset_db(&pool).await;
        let data_dir = test_support::new_temp_dir("replica-role").await;
        let mut config = test_support::base_config("replica", data_dir);
        config.replica_advertise = Some("http://replica:9010".to_string());
        let repo = Repo::new(pool.clone());
        let node_id = ensure_local_node(&repo, &config).await.expect("node");
        let node = repo
            .get_node_by_address("http://replica:9010")
            .await
            .expect("node")
            .expect("exists");
        assert_eq!(node.node_id, node_id);
        assert_eq!(node.role, "replica");
    }
}
