use crate::api::AppState;
use crate::backup;
use crate::meta::models::Node;
use crate::storage::checksum::{Checksum, ChecksumAlgo};
use crate::util::runtime::ReplicaSubMode;
use chrono::Utc;
use dashmap::DashMap;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

#[cfg(test)]
static SCRUB_RUNS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static MULTIPART_CLEANUP_RUNS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static GC_RUNS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
pub struct RepairQueue {
    backlog: Arc<DashMap<Uuid, ()>>,
}

impl Default for RepairQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl RepairQueue {
    pub fn new() -> Self {
        Self {
            backlog: Arc::new(DashMap::new()),
        }
    }

    pub fn enqueue(&self, chunk_id: Uuid) {
        self.backlog.insert(chunk_id, ());
    }

    pub fn backlog_len(&self) -> usize {
        self.backlog.len()
    }

    pub fn take_one(&self) -> Option<Uuid> {
        let key = self.backlog.iter().next().map(|entry| *entry.key())?;
        self.backlog.remove(&key);
        Some(key)
    }
}

pub fn start_background_jobs(state: AppState) {
    start_backup_jobs(state.clone());
    start_repair_workers(state.clone());
    start_scrubber(state.clone());
    start_capacity_refresh(state.clone());
    start_lifecycle_jobs(state);
}

pub fn start_backup_jobs(state: AppState) {
    start_snapshot_scheduler(state.clone());
    start_backup_scheduler(state);
}

fn start_lifecycle_jobs(state: AppState) {
    start_multipart_cleanup(state.clone());
    start_gc(state);
}

fn start_snapshot_scheduler(state: AppState) {
    if state.config.mode != "master" {
        return;
    }
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(60)).await;
            run_snapshot_policies_once(&state).await;
        }
    });
}

fn start_backup_scheduler(state: AppState) {
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(60)).await;
            run_backup_policies_once(&state).await;
        }
    });
}

fn start_repair_workers(state: AppState) {
    let workers = state.config.repair_workers.max(1);
    for _ in 0..workers {
        let worker_state = state.clone();
        tokio::spawn(async move {
            loop {
                repair_worker_step(&worker_state).await;
            }
        });
    }
}

fn start_capacity_refresh(state: AppState) {
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(30)).await;
            refresh_capacity_once(&state).await;
        }
    });
}

async fn refresh_capacity_once(state: &AppState) {
    let usage = crate::util::storage_volume::data_dirs_usage(&state.config.data_dirs);
    if let Err(err) = state
        .repo
        .update_node_heartbeat(
            state.node_id,
            Some(usage.capacity_bytes),
            Some(usage.free_bytes),
        )
        .await
    {
        tracing::debug!(error = %err, "capacity refresh failed");
    }
}

fn start_scrubber(state: AppState) {
    tokio::spawn(async move {
        loop {
            sleep(state.config.scrub_interval).await;
            scrub_once(&state).await;
        }
    });
}

fn start_multipart_cleanup(state: AppState) {
    tokio::spawn(async move {
        loop {
            sleep(state.config.gc_interval).await;
            multipart_cleanup_once(&state).await;
        }
    });
}

fn start_gc(state: AppState) {
    tokio::spawn(async move {
        loop {
            sleep(state.config.gc_interval).await;
            gc_once(&state).await;
        }
    });
}

async fn repair_worker_step(state: &AppState) {
    if let Some(chunk_id) = state.repair_queue.take_one() {
        let result = repair_chunk(state, chunk_id).await;
        let label = if result.is_ok() { "ok" } else { "error" };
        state.metrics.repair_jobs.with_label_values(&[label]).inc();
    } else {
        sleep(Duration::from_secs(2)).await;
    }
    let backlog = state.repair_queue.backlog_len() as i64;
    state
        .metrics
        .repair_backlog
        .with_label_values(&["default"])
        .set(backlog);
}

async fn scrub_once(state: &AppState) {
    #[cfg(test)]
    SCRUB_RUNS.fetch_add(1, Ordering::Relaxed);
    let chunk_ids = match state.repo.list_chunk_ids(100).await {
        Ok(ids) => ids,
        Err(_) => return,
    };
    for chunk_id in chunk_ids {
        if let Ok(Some((algo, value))) = state.repo.get_chunk_checksum(chunk_id).await {
            let algo = ChecksumAlgo::parse(&algo).unwrap_or(state.config.checksum_algo);
            let checksum = Checksum { algo, value };
            if state
                .replication
                .read_chunk(chunk_id, &checksum)
                .await
                .is_err()
            {
                state.repair_queue.enqueue(chunk_id);
            }
        }
    }
    let backlog = state.repair_queue.backlog_len() as i64;
    state
        .metrics
        .repair_backlog
        .with_label_values(&["default"])
        .set(backlog);
}

async fn multipart_cleanup_once(state: &AppState) {
    #[cfg(test)]
    MULTIPART_CLEANUP_RUNS.fetch_add(1, Ordering::Relaxed);
    let cutoff =
        Utc::now() - chrono::Duration::seconds(state.config.multipart_ttl.as_secs() as i64);
    let uploads = match state.repo.list_stale_multipart_uploads(cutoff).await {
        Ok(list) => list,
        Err(_) => return,
    };
    for upload_id in uploads {
        let _ = state.repo.cleanup_multipart_upload(&upload_id).await;
    }
}

async fn gc_once(state: &AppState) {
    #[cfg(test)]
    GC_RUNS.fetch_add(1, Ordering::Relaxed);
    loop {
        let manifests = match state.repo.list_orphan_manifest_ids(100).await {
            Ok(list) => list,
            Err(_) => break,
        };
        if manifests.is_empty() {
            break;
        }
        for manifest_id in manifests {
            let _ = state.repo.delete_manifest(manifest_id).await;
        }
    }
    loop {
        let chunks = match state.repo.list_orphan_chunk_ids(100).await {
            Ok(list) => list,
            Err(_) => break,
        };
        if chunks.is_empty() {
            break;
        }
        for chunk_id in chunks {
            let _ = state.replication.delete_chunk_everywhere(chunk_id).await;
            let _ = state.repo.delete_chunk_metadata(chunk_id).await;
        }
    }
}

async fn run_snapshot_policies_once(state: &AppState) {
    let policies = match state.repo.list_enabled_snapshot_policies().await {
        Ok(policies) => policies,
        Err(_) => return,
    };
    for policy in policies {
        if should_run_snapshot_policy(state, &policy).await {
            execute_snapshot_policy(state, &policy).await;
        }
    }
}

async fn should_run_snapshot_policy(
    state: &AppState,
    policy: &crate::meta::models::BucketSnapshotPolicy,
) -> bool {
    if policy.trigger_kind == "on_create_change" {
        return state
            .repo
            .bucket_changed_after(policy.bucket_id, policy.last_snapshot_at)
            .await
            .unwrap_or(false);
    }
    backup::is_due(policy.last_snapshot_at, &policy.trigger_kind, Utc::now())
}

async fn execute_snapshot_policy(
    state: &AppState,
    policy: &crate::meta::models::BucketSnapshotPolicy,
) {
    let run = state
        .repo
        .create_bucket_snapshot(
            policy.bucket_id,
            policy.trigger_kind.as_str(),
            policy.created_by_user_id,
        )
        .await;
    if run.is_err() {
        return;
    }
    let now = Utc::now();
    let _ = state.repo.touch_snapshot_policy_run(policy.id, now).await;
    if policy.trigger_kind == "on_create_change" {
        let _ = state.repo.clear_bucket_changed(policy.bucket_id).await;
    }
    let _ = state
        .repo
        .prune_bucket_snapshots(policy.bucket_id, policy.retention_count)
        .await;
}

async fn run_backup_policies_once(state: &AppState) {
    if !backup_scheduler_enabled(state) {
        return;
    }
    let policies = match state.repo.list_enabled_backup_policies().await {
        Ok(policies) => policies,
        Err(_) => return,
    };
    for policy in policies {
        if !backup::backup_policy_matches_runner(&policy, state.config.mode.as_str(), state.node_id)
        {
            continue;
        }
        if !backup::is_due(
            policy.last_run_at,
            policy.schedule_kind.as_str(),
            Utc::now(),
        ) {
            continue;
        }
        let _ = backup::run_backup_policy_once(state, &policy, "schedule").await;
    }
}

fn backup_scheduler_enabled(state: &AppState) -> bool {
    if state.config.mode == "master" {
        return true;
    }
    if state.config.mode != "replica" {
        return false;
    }
    state.replica_mode.get() == ReplicaSubMode::Backup
}

async fn repair_chunk(state: &AppState, chunk_id: Uuid) -> Result<(), String> {
    let checksum = load_repair_checksum(state, chunk_id).await?;
    let mut present_nodes = load_present_nodes(state, chunk_id).await?;
    if has_required_replicas(state, present_nodes.len()) {
        return Ok(());
    }
    let data = fetch_repair_payload(state, chunk_id, &checksum, &present_nodes).await?;
    repair_to_missing_nodes(state, chunk_id, &checksum, &data, &mut present_nodes).await?;
    Ok(())
}

async fn load_repair_checksum(state: &AppState, chunk_id: Uuid) -> Result<Checksum, String> {
    state
        .repo
        .get_chunk_checksum(chunk_id)
        .await
        .map_err(|err| format!("checksum load failed: {err}"))?
        .map(|(algo, value)| {
            let algo = ChecksumAlgo::parse(&algo).unwrap_or(state.config.checksum_algo);
            Checksum { algo, value }
        })
        .ok_or_else(|| "chunk missing".to_string())
}

async fn load_present_nodes(state: &AppState, chunk_id: Uuid) -> Result<Vec<Node>, String> {
    let replicas = state
        .repo
        .list_chunk_replicas_with_nodes(chunk_id)
        .await
        .map_err(|err| format!("replica query failed: {err}"))?;
    Ok(replicas
        .into_iter()
        .filter_map(present_replica_node)
        .collect())
}

fn present_replica_node(replica: crate::meta::repos::ChunkReplicaNode) -> Option<Node> {
    if replica.status != "online" || replica.state != "present" {
        return None;
    }
    Some(Node {
        node_id: replica.node_id,
        role: replica.role,
        address_internal: replica.address_internal,
        status: replica.status,
        last_heartbeat_at: replica.last_heartbeat_at,
        capacity_bytes: replica.capacity_bytes,
        free_bytes: replica.free_bytes,
        created_at: replica.created_at,
    })
}

fn has_required_replicas(state: &AppState, current: usize) -> bool {
    current >= state.config.replication_factor as usize
}

async fn fetch_repair_payload(
    state: &AppState,
    chunk_id: Uuid,
    checksum: &Checksum,
    present_nodes: &[Node],
) -> Result<Vec<u8>, String> {
    let source = present_nodes
        .first()
        .ok_or_else(|| "no healthy source".to_string())?;
    let data = state
        .replication
        .fetch_chunk_from_node(source, chunk_id)
        .await
        .map_err(|err| format!("fetch source failed: {err}"))?;
    if !checksum.verify(&data) {
        return Err("checksum mismatch during repair".to_string());
    }
    Ok(data.to_vec())
}

async fn repair_to_missing_nodes(
    state: &AppState,
    chunk_id: Uuid,
    checksum: &Checksum,
    data: &[u8],
    present_nodes: &mut Vec<Node>,
) -> Result<(), String> {
    let nodes = state
        .repo
        .list_nodes()
        .await
        .map_err(|err| format!("list nodes failed: {err}"))?;
    for node in nodes {
        if should_skip_repair_target(present_nodes, &node) {
            continue;
        }
        store_repair_replica(state, chunk_id, checksum, data, present_nodes, node).await;
        if has_required_replicas(state, present_nodes.len()) {
            break;
        }
    }
    Ok(())
}

fn should_skip_repair_target(present_nodes: &[Node], node: &Node) -> bool {
    node.status != "online"
        || present_nodes
            .iter()
            .any(|item| item.node_id == node.node_id)
}

async fn store_repair_replica(
    state: &AppState,
    chunk_id: Uuid,
    checksum: &Checksum,
    data: &[u8],
    present_nodes: &mut Vec<Node>,
    node: Node,
) {
    if state
        .replication
        .store_chunk_on_node(&node, chunk_id, checksum, data)
        .await
        .is_ok()
    {
        let _ = state
            .repo
            .insert_chunk_replica(chunk_id, node.node_id, "present")
            .await;
        present_nodes.push(node);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        backup_scheduler_enabled, execute_snapshot_policy, gc_once, multipart_cleanup_once,
        refresh_capacity_once, repair_chunk, repair_worker_step, run_backup_policies_once,
        run_snapshot_policies_once, scrub_once, should_run_snapshot_policy,
        start_background_jobs, start_backup_scheduler, start_capacity_refresh,
        start_snapshot_scheduler, RepairQueue, GC_RUNS, MULTIPART_CLEANUP_RUNS, SCRUB_RUNS,
    };
    use crate::api::AppState;
    use crate::meta::backup_repos::BackupPolicyCreate;
    use crate::meta::repos::{checksum_none_guard, Repo};
    use crate::storage::checksum::{Checksum, ChecksumAlgo};
    use crate::test_support;
    use crate::test_support::TableRenameGuard;
    use crate::util::runtime::ReplicaSubMode;
    use axum::extract::Path;
    use axum::http::StatusCode;
    use axum::routing::{get, put};
    use axum::{body::Bytes as AxumBytes, Router};
    use chrono::Utc;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::{oneshot, Mutex, Notify};
    use tokio::task::JoinHandle;
    use tokio::time::{sleep, timeout};
    use uuid::Uuid;

    struct RunningChunkServer {
        address: String,
        shutdown: Option<oneshot::Sender<()>>,
        task: JoinHandle<()>,
    }

    impl RunningChunkServer {
        async fn shutdown(mut self) {
            if let Some(tx) = self.shutdown.take() {
                let _ = tx.send(());
            }
            let _ = self.task.await;
        }
    }

    #[tokio::test]
    async fn running_chunk_server_shutdown_handles_missing_sender() {
        let task = tokio::spawn(async move {});
        let server = RunningChunkServer {
            address: String::new(),
            shutdown: None,
            task,
        };
        server.shutdown().await;
    }

    #[tokio::test]
    async fn running_chunk_server_shutdown_sends_signal() {
        let (tx, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = rx.await;
        });
        let server = RunningChunkServer {
            address: String::new(),
            shutdown: Some(tx),
            task,
        };
        server.shutdown().await;
    }

    async fn start_chunk_server(app: Router) -> RunningChunkServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });
        sleep(Duration::from_millis(50)).await;
        RunningChunkServer {
            address: format!("http://{}", addr),
            shutdown: Some(shutdown_tx),
            task,
        }
    }

    fn put_chunk_router(status: StatusCode) -> Router {
        Router::new().route(
            "/internal/v1/chunks/{id}",
            put(move |Path(_): Path<Uuid>, _body: AxumBytes| async move { status }),
        )
    }

    async fn upsert_node(state: &AppState, node_id: Uuid, role: &str, address: &str, status: &str) {
        state
            .repo
            .upsert_node(node_id, role, address, status, None, None, Some(Utc::now()))
            .await
            .expect("node");
    }

    async fn insert_present_replica(state: &AppState, chunk_id: Uuid, node_id: Uuid) {
        state
            .repo
            .insert_chunk_replica(chunk_id, node_id, "present")
            .await
            .expect("replica");
    }

    async fn insert_chunk_metadata_with_checksum(
        state: &AppState,
        chunk_id: Uuid,
        checksum_payload: &[u8],
    ) -> Checksum {
        let checksum = Checksum::compute(state.config.checksum_algo, checksum_payload);
        state
            .repo
            .insert_chunk_metadata(
                chunk_id,
                checksum_payload.len() as i32,
                checksum.algo.as_str(),
                &checksum.value,
            )
            .await
            .expect("metadata");
        checksum
    }

    async fn seed_chunk_for_repair(
        state: &AppState,
        chunk_id: Uuid,
        stored_payload: &[u8],
        checksum_payload: &[u8],
    ) {
        state
            .replication
            .chunk_store()
            .write_chunk(chunk_id, stored_payload)
            .await
            .expect("write");
        let _ = insert_chunk_metadata_with_checksum(state, chunk_id, checksum_payload).await;
        insert_present_replica(state, chunk_id, state.node_id).await;
    }

    async fn create_backup_policy(
        state: &AppState,
        source_bucket_id: Uuid,
        backup_bucket_id: Uuid,
        scope: &str,
        schedule_kind: &str,
    ) -> crate::meta::models::BackupPolicy {
        state
            .repo
            .create_backup_policy(&BackupPolicyCreate {
                name: format!("policy-{scope}-{schedule_kind}"),
                scope: scope.to_string(),
                node_id: None,
                source_bucket_id,
                backup_bucket_id,
                backup_type: "full".to_string(),
                schedule_kind: schedule_kind.to_string(),
                strategy: "3-2-1".to_string(),
                retention_count: 2,
                enabled: true,
                external_targets_json: serde_json::json!([]),
                created_by_user_id: None,
            })
            .await
            .expect("backup policy")
    }

    async fn setup_backup_policy_runner_state() -> (AppState, Uuid) {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let user = state
            .repo
            .create_user("backup-policy-user", None, "hash", "active")
            .await
            .expect("user");
        let source = state
            .repo
            .create_bucket("backup-policy-source", user.id)
            .await
            .expect("source");
        let backup = state
            .repo
            .create_bucket("backup-policy-target", user.id)
            .await
            .expect("backup");
        state
            .repo
            .update_bucket_worm(backup.id, true)
            .await
            .expect("worm");
        let _ = create_backup_policy(&state, source.id, backup.id, "replica", "daily").await;
        let _ = create_backup_policy(&state, source.id, backup.id, "master", "on_demand").await;
        let run_policy =
            create_backup_policy(&state, source.id, backup.id, "master", "daily").await;
        (state, run_policy.id)
    }

    async fn setup_snapshot_policy_runner_state() -> (AppState, Uuid) {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let user = state
            .repo
            .create_user("snapshot-policy-user", None, "hash", "active")
            .await
            .expect("user");
        let bucket = state
            .repo
            .create_bucket("snapshot-policy-bucket", user.id)
            .await
            .expect("bucket");
        state
            .repo
            .upsert_snapshot_policy(bucket.id, "on_create_change", 1, true, Some(user.id))
            .await
            .expect("policy");
        state
            .repo
            .mark_bucket_changed(bucket.id)
            .await
            .expect("changed");
        (state, bucket.id)
    }

    fn reset_job_run_counters() {
        SCRUB_RUNS.store(0, Ordering::Relaxed);
        MULTIPART_CLEANUP_RUNS.store(0, Ordering::Relaxed);
        GC_RUNS.store(0, Ordering::Relaxed);
    }

    async fn wait_for_job_runs() {
        let wait_result = tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                sleep(Duration::from_millis(10)).await;
                if SCRUB_RUNS.load(Ordering::Relaxed) > 0
                    && MULTIPART_CLEANUP_RUNS.load(Ordering::Relaxed) > 0
                    && GC_RUNS.load(Ordering::Relaxed) > 0
                {
                    break;
                }
            }
        })
        .await;
        assert!(wait_result.is_ok());
    }

    async fn spawn_blocking_get_server(
        payload: AxumBytes,
    ) -> (RunningChunkServer, oneshot::Receiver<()>, Arc<Notify>) {
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let started_tx = Arc::new(Mutex::new(Some(started_tx)));
        let release = Arc::new(Notify::new());
        let release_clone = release.clone();
        let payload_clone = payload.clone();
        let app = Router::new().route(
            "/internal/v1/chunks/{id}",
            get(move |Path(_): Path<Uuid>| {
                let started_tx = started_tx.clone();
                let release = release_clone.clone();
                let payload = payload_clone.clone();
                async move {
                    let tx = started_tx.lock().await.take().expect("started sender");
                    let _ = tx.send(());
                    release.notified().await;
                    (StatusCode::OK, payload)
                }
            }),
        );
        let server = start_chunk_server(app).await;
        (server, started_rx, release)
    }

    #[tokio::test]
    async fn repair_queue_tracks_items() {
        let queue = RepairQueue::new();
        assert_eq!(queue.backlog_len(), 0);
        let id = Uuid::new_v4();
        queue.enqueue(id);
        assert_eq!(queue.backlog_len(), 1);
        let taken = queue.take_one().expect("take");
        assert_eq!(taken, id);
        assert_eq!(queue.backlog_len(), 0);
    }

    #[test]
    fn repair_queue_default_is_empty() {
        let queue = RepairQueue::default();
        assert_eq!(queue.backlog_len(), 0);
        assert!(queue.take_one().is_none());
    }

    #[tokio::test]
    async fn run_snapshot_policies_once_returns_on_repo_error() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        run_snapshot_policies_once(&state).await;
    }

    #[tokio::test]
    async fn run_snapshot_policies_once_handles_change_policy() {
        let (state, bucket_id) = setup_snapshot_policy_runner_state().await;
        run_snapshot_policies_once(&state).await;
        run_snapshot_policies_once(&state).await;
        let snapshots = state
            .repo
            .list_bucket_snapshots(bucket_id, 0, 100)
            .await
            .expect("snapshots");
        assert_eq!(snapshots.len(), 1);
    }

    #[tokio::test]
    async fn snapshot_policy_change_check_handles_repo_errors() {
        let (state, bucket_id) = setup_snapshot_policy_runner_state().await;
        let policy = state
            .repo
            .upsert_snapshot_policy(bucket_id, "on_create_change", 1, true, None)
            .await
            .expect("policy");
        let mut broken_state = state.clone();
        broken_state.repo = test_support::broken_repo();
        let should_run = should_run_snapshot_policy(&broken_state, &policy).await;
        assert!(!should_run);
    }

    #[tokio::test]
    async fn execute_snapshot_policy_handles_error_and_clear_paths() {
        let (state, bucket_id) = setup_snapshot_policy_runner_state().await;
        let policy = state
            .repo
            .upsert_snapshot_policy(bucket_id, "on_create_change", 1, true, None)
            .await
            .expect("policy");
        execute_snapshot_policy(&state, &policy).await;
        let changed = state
            .repo
            .bucket_changed_after(bucket_id, None)
            .await
            .expect("changed");
        assert!(!changed);
        let mut broken_state = state.clone();
        broken_state.repo = test_support::broken_repo();
        execute_snapshot_policy(&broken_state, &policy).await;
    }

    #[tokio::test]
    async fn execute_snapshot_policy_non_change_trigger_keeps_change_marker() {
        let (state, bucket_id) = setup_snapshot_policy_runner_state().await;
        let policy = state
            .repo
            .upsert_snapshot_policy(bucket_id, "daily", 1, true, None)
            .await
            .expect("policy");
        execute_snapshot_policy(&state, &policy).await;
        let changed = state
            .repo
            .bucket_changed_after(bucket_id, None)
            .await
            .expect("changed");
        assert!(changed);
    }

    #[tokio::test]
    async fn run_backup_policies_once_covers_filters_and_execution() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        run_backup_policies_once(&state).await;

        let (state, run_policy_id) = setup_backup_policy_runner_state().await;
        run_backup_policies_once(&state).await;
        let runs = state
            .repo
            .list_backup_runs_for_policy(run_policy_id)
            .await
            .expect("runs");
        assert!(!runs.is_empty());
    }

    #[tokio::test]
    async fn backup_scheduler_enabled_respects_mode_and_sub_mode() {
        let (master, _pool, _dir) = test_support::build_state("master").await;
        assert!(backup_scheduler_enabled(&master));

        let (replica, _pool, _dir) = test_support::build_state("replica").await;
        assert!(!backup_scheduler_enabled(&replica));

        replica.replica_mode.set(ReplicaSubMode::Backup);
        assert!(backup_scheduler_enabled(&replica));

        let (mut test_mode, _pool, _dir) = test_support::build_state("master").await;
        test_mode.config.mode = "test".to_string();
        assert!(!backup_scheduler_enabled(&test_mode));
    }

    #[tokio::test]
    async fn run_backup_policies_once_skips_non_backup_replica_mode() {
        let (state, _pool, _dir) = test_support::build_state("replica").await;
        let user = state
            .repo
            .create_user("replica-backup-mode-user", None, "hash", "active")
            .await
            .expect("user");
        let source = state
            .repo
            .create_bucket("replica-backup-mode-source", user.id)
            .await
            .expect("source");
        let backup = state
            .repo
            .create_bucket("replica-backup-mode-target", user.id)
            .await
            .expect("backup");
        state
            .repo
            .update_bucket_worm(backup.id, true)
            .await
            .expect("worm");
        let policy = create_backup_policy(&state, source.id, backup.id, "replica", "daily").await;

        run_backup_policies_once(&state).await;
        let before = state
            .repo
            .list_backup_runs_for_policy(policy.id)
            .await
            .expect("before");
        assert!(before.is_empty());

        state.replica_mode.set(ReplicaSubMode::Backup);
        run_backup_policies_once(&state).await;
        let after = state
            .repo
            .list_backup_runs_for_policy(policy.id)
            .await
            .expect("after");
        assert_eq!(after.len(), 1);
    }

    async fn scheduler_created_snapshot(state: &AppState, bucket_id: Uuid) -> bool {
        match state.repo.list_bucket_snapshots(bucket_id, 0, 10).await {
            Ok(rows) => !rows.is_empty(),
            Err(_) => false,
        }
    }

    async fn scheduler_created_backup_run(state: &AppState, policy_id: Uuid) -> bool {
        match state.repo.list_backup_runs_for_policy(policy_id).await {
            Ok(rows) => !rows.is_empty(),
            Err(_) => false,
        }
    }

    async fn assert_snapshot_scheduler_effect() {
        let (snapshot_state, bucket_id) = setup_snapshot_policy_runner_state().await;
        run_snapshot_policies_once(&snapshot_state).await;
        assert!(scheduler_created_snapshot(&snapshot_state, bucket_id).await);
    }

    async fn assert_backup_scheduler_effect() {
        let (backup_state, run_policy_id) = setup_backup_policy_runner_state().await;
        run_backup_policies_once(&backup_state).await;
        assert!(scheduler_created_backup_run(&backup_state, run_policy_id).await);
    }

    async fn assert_scheduler_effects() {
        assert_snapshot_scheduler_effect().await;
        assert_backup_scheduler_effect().await;
    }

    #[tokio::test]
    async fn schedulers_run_periodic_ticks() {
        assert_scheduler_effects().await;
    }

    #[tokio::test]
    async fn scheduler_loops_tick_when_repo_is_broken() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        tokio::time::pause();
        start_snapshot_scheduler(state.clone());
        start_backup_scheduler(state);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn capacity_refresh_ticks_periodically() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        tokio::time::pause();
        start_capacity_refresh(state);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(31)).await;
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn scheduler_created_helpers_return_false_on_repo_error() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        assert!(!scheduler_created_snapshot(&state, Uuid::new_v4()).await);
        assert!(!scheduler_created_backup_run(&state, Uuid::new_v4()).await);
    }

    #[tokio::test]
    async fn snapshot_scheduler_returns_immediately_for_replica_mode() {
        let (state, _pool, _dir) = test_support::build_state("replica").await;
        start_snapshot_scheduler(state);
    }

    #[tokio::test]
    async fn should_run_snapshot_policy_daily_uses_due_check() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let user = state
            .repo
            .create_user("daily-snapshot", None, "hash", "active")
            .await
            .expect("user");
        let bucket = state
            .repo
            .create_bucket("daily-snapshot-bucket", user.id)
            .await
            .expect("bucket");
        let policy = state
            .repo
            .upsert_snapshot_policy(bucket.id, "daily", 1, true, None)
            .await
            .expect("policy");
        assert!(should_run_snapshot_policy(&state, &policy).await);
    }

    #[tokio::test]
    async fn repair_chunk_missing_returns_error() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let err = repair_chunk(&state, Uuid::new_v4()).await.unwrap_err();
        assert_eq!(err, "chunk missing");
    }

    #[tokio::test]
    async fn repair_worker_step_handles_empty_queue() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        repair_worker_step(&state).await;
        assert_eq!(state.repair_queue.backlog_len(), 0);
    }

    #[tokio::test]
    async fn repair_worker_step_processes_queue_item() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let chunk_id = Uuid::new_v4();
        let checksum = Checksum::compute(state.config.checksum_algo, b"data");
        state
            .replication
            .chunk_store()
            .write_chunk(chunk_id, b"data")
            .await
            .expect("write");
        state
            .repo
            .insert_chunk_metadata(chunk_id, 4, checksum.algo.as_str(), &checksum.value)
            .await
            .expect("metadata");
        state
            .repo
            .insert_chunk_replica(chunk_id, state.node_id, "present")
            .await
            .expect("replica");
        state.repair_queue.enqueue(chunk_id);
        repair_worker_step(&state).await;
        assert_eq!(state.repair_queue.backlog_len(), 0);
    }

    #[tokio::test]
    async fn scrub_once_enqueues_missing_replica() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let repo = Repo::new(pool);
        let chunk_id = Uuid::new_v4();
        repo.insert_chunk_metadata(chunk_id, 4, "crc32c", b"abcd")
            .await
            .expect("insert chunk");
        let checksum = Checksum {
            algo: ChecksumAlgo::Crc32c,
            value: b"abcd".to_vec(),
        };
        let node_id = state.node_id;
        repo.insert_chunk_replica(chunk_id, node_id, "present")
            .await
            .expect("replica");
        let _ = state.replication.read_chunk(chunk_id, &checksum).await;
        scrub_once(&state).await;
        assert!(state.repair_queue.backlog_len() > 0);
    }

    #[tokio::test]
    async fn scrub_once_skips_when_chunk_healthy() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let repo = Repo::new(pool);
        let chunk_id = Uuid::new_v4();
        let payload = b"payload";
        let checksum = Checksum::compute(state.config.checksum_algo, payload);
        state
            .replication
            .chunk_store()
            .write_chunk(chunk_id, payload)
            .await
            .expect("write");
        repo.insert_chunk_metadata(
            chunk_id,
            payload.len() as i32,
            checksum.algo.as_str(),
            &checksum.value,
        )
        .await
        .expect("metadata");
        repo.insert_chunk_replica(chunk_id, state.node_id, "present")
            .await
            .expect("replica");
        scrub_once(&state).await;
        assert_eq!(state.repair_queue.backlog_len(), 0);
    }

    #[tokio::test]
    async fn scrub_once_returns_on_repo_error() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        scrub_once(&state).await;
    }

    #[tokio::test]
    async fn scrub_once_skips_when_checksum_missing() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let repo = Repo::new(pool);
        let chunk_id = Uuid::new_v4();
        let checksum = Checksum::compute(state.config.checksum_algo, b"payload");
        repo.insert_chunk_metadata(chunk_id, 7, checksum.algo.as_str(), &checksum.value)
            .await
            .expect("metadata");
        let _guard = checksum_none_guard();
        scrub_once(&state).await;
        assert_eq!(state.repair_queue.backlog_len(), 0);
    }

    #[tokio::test]
    async fn scrub_once_enqueues_when_chunk_missing() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let repo = Repo::new(pool);
        let chunk_id = Uuid::new_v4();
        let checksum = Checksum::compute(state.config.checksum_algo, b"payload");
        repo.insert_chunk_metadata(chunk_id, 7, checksum.algo.as_str(), &checksum.value)
            .await
            .expect("metadata");
        repo.upsert_node(
            state.node_id,
            "master",
            "http://127.0.0.1:0",
            "online",
            None,
            None,
            Some(Utc::now()),
        )
        .await
        .expect("node");
        repo.insert_chunk_replica(chunk_id, state.node_id, "present")
            .await
            .expect("replica");
        scrub_once(&state).await;
        assert!(state.repair_queue.backlog_len() > 0);
    }

    #[tokio::test]
    async fn multipart_cleanup_deletes_stale_uploads() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let repo = Repo::new(pool);
        let user = repo
            .create_user("cleanup-user", None, "hash", "active")
            .await
            .expect("user");
        let bucket = repo
            .create_bucket("cleanup-bucket", user.id)
            .await
            .expect("bucket");
        let upload = repo
            .create_multipart_upload(bucket.id, "object", "upload-1")
            .await
            .expect("upload");
        sqlx::query("UPDATE multipart_uploads SET initiated_at=$1 WHERE upload_id=$2")
            .bind(Utc::now() - chrono::Duration::hours(2))
            .bind(&upload.upload_id)
            .execute(repo.pool())
            .await
            .expect("update time");
        multipart_cleanup_once(&state).await;
        let uploads = repo.list_multipart_uploads(bucket.id).await.expect("list");
        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0].status, "aborted");
    }

    #[tokio::test]
    async fn multipart_cleanup_returns_on_repo_error() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        multipart_cleanup_once(&state).await;
    }

    #[tokio::test]
    async fn gc_once_cleans_orphan_records() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let repo = Repo::new(pool);
        let chunk_id = Uuid::new_v4();
        repo.insert_chunk_metadata(chunk_id, 4, "crc32c", b"abcd")
            .await
            .expect("chunk");
        repo.insert_chunk_replica(chunk_id, state.node_id, "present")
            .await
            .expect("replica");
        let manifest_id = Uuid::new_v4();
        sqlx::query("INSERT INTO manifests (id, total_size_bytes, created_at) VALUES ($1, $2, $3)")
            .bind(manifest_id)
            .bind(4i64)
            .bind(Utc::now())
            .execute(repo.pool())
            .await
            .expect("manifest");
        gc_once(&state).await;
        let orphans = repo.list_orphan_manifest_ids(10).await.expect("orphans");
        assert!(!orphans.contains(&manifest_id));
        let chunks = repo.list_orphan_chunk_ids(10).await.expect("chunks");
        assert!(!chunks.contains(&chunk_id));
    }

    #[tokio::test]
    async fn repair_chunk_branches_cover_sources_and_mismatch() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        let chunk_id = Uuid::new_v4();
        seed_chunk_for_repair(&state, chunk_id, b"bad", b"good").await;
        state.config.replication_factor = 2;
        let err = repair_chunk(&state, chunk_id).await.unwrap_err();
        assert_eq!(err, "checksum mismatch during repair");

        state
            .replication
            .chunk_store()
            .write_chunk(chunk_id, b"good")
            .await
            .expect("write");
        state.config.replication_factor = 1;
        let ok = repair_chunk(&state, chunk_id).await;
        assert!(ok.is_ok());
    }

    #[tokio::test]
    async fn repair_chunk_handles_missing_source() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let chunk_id = Uuid::new_v4();
        state
            .repo
            .insert_chunk_metadata(chunk_id, 4, "crc32c", b"abcd")
            .await
            .expect("metadata");
        let err = repair_chunk(&state, chunk_id).await.unwrap_err();
        assert_eq!(err, "no healthy source");
    }

    #[tokio::test]
    async fn repair_chunk_reports_replica_query_error() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let chunk_id = Uuid::new_v4();
        state
            .repo
            .insert_chunk_metadata(chunk_id, 4, "crc32c", b"abcd")
            .await
            .expect("metadata");
        let guard = TableRenameGuard::rename(&pool, "chunk_replicas")
            .await
            .expect("rename");
        let err = repair_chunk(&state, chunk_id).await.unwrap_err();
        assert!(err.contains("replica query failed"));
        guard.restore().await.expect("restore");
    }

    #[tokio::test]
    async fn repair_chunk_reports_fetch_source_error() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.replication_factor = 2;
        let chunk_id = Uuid::new_v4();
        let _ = insert_chunk_metadata_with_checksum(&state, chunk_id, b"abcd").await;
        let node_id = Uuid::new_v4();
        upsert_node(&state, node_id, "replica", "http://127.0.0.1:1", "online").await;
        insert_present_replica(&state, chunk_id, node_id).await;
        let err = repair_chunk(&state, chunk_id).await.unwrap_err();
        assert!(err.contains("fetch source failed"));
    }

    #[tokio::test]
    async fn repair_chunk_reports_list_nodes_error() {
        let (mut state, pool, _dir) = test_support::build_state("master").await;
        state.config.replication_factor = 2;
        let chunk_id = Uuid::new_v4();
        let payload = AxumBytes::from_static(b"payload");
        let _ = insert_chunk_metadata_with_checksum(&state, chunk_id, payload.as_ref()).await;
        let (server, started_rx, release) = spawn_blocking_get_server(payload).await;
        let node_id = Uuid::new_v4();
        upsert_node(&state, node_id, "replica", &server.address, "online").await;
        insert_present_replica(&state, chunk_id, node_id).await;
        let state_clone = state.clone();
        let handle = tokio::spawn(async move { repair_chunk(&state_clone, chunk_id).await });
        timeout(Duration::from_secs(2), started_rx)
            .await
            .expect("request")
            .expect("signal");
        let guard = TableRenameGuard::rename(&pool, "nodes")
            .await
            .expect("rename");
        release.notify_one();
        let err = handle.await.expect("join").unwrap_err();
        assert!(err.contains("list nodes failed"));
        guard.restore().await.expect("restore");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn repair_chunk_repairs_to_remote_node() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.replication_factor = 2;
        let chunk_id = Uuid::new_v4();
        seed_chunk_for_repair(&state, chunk_id, b"payload", b"payload").await;
        let server = start_chunk_server(put_chunk_router(StatusCode::CREATED)).await;
        let node_id = Uuid::new_v4();
        upsert_node(&state, node_id, "replica", &server.address, "online").await;
        let result = repair_chunk(&state, chunk_id).await;
        assert!(result.is_ok());
        let replicas = state
            .repo
            .list_chunk_replicas_with_nodes(chunk_id)
            .await
            .expect("replicas");
        assert!(replicas.iter().any(|replica| replica.node_id == node_id));
        server.shutdown().await;
    }

    #[tokio::test]
    async fn repair_chunk_adds_missing_replica() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.replication_factor = 2;
        let chunk_id = Uuid::new_v4();
        let payload = AxumBytes::from_static(b"payload");
        seed_chunk_for_repair(&state, chunk_id, payload.as_ref(), payload.as_ref()).await;
        upsert_node(
            &state,
            state.node_id,
            "master",
            "http://127.0.0.1:0",
            "online",
        )
        .await;
        let server = start_chunk_server(put_chunk_router(StatusCode::CREATED)).await;
        let node_id = Uuid::new_v4();
        upsert_node(&state, node_id, "replica", &server.address, "online").await;
        let result = repair_chunk(&state, chunk_id).await;
        assert!(result.is_ok());
        let replicas = state
            .repo
            .list_chunk_replicas_with_nodes(chunk_id)
            .await
            .expect("replicas");
        assert!(replicas.iter().any(|replica| replica.node_id == node_id));
        server.shutdown().await;
    }

    #[tokio::test]
    async fn repair_chunk_skips_offline_replica_and_breaks_on_quorum() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.replication_factor = 2;
        let chunk_id = Uuid::new_v4();
        let payload = AxumBytes::from_static(b"payload");
        seed_chunk_for_repair(&state, chunk_id, payload.as_ref(), payload.as_ref()).await;
        register_master_node(&state).await;
        seed_offline_replica(&state, chunk_id).await;
        let server = start_chunk_server(put_chunk_router(StatusCode::CREATED)).await;
        let node_id = Uuid::new_v4();
        upsert_node(&state, node_id, "replica", &server.address, "online").await;
        let result = repair_chunk(&state, chunk_id).await;
        assert!(result.is_ok());
        let replicas = state
            .repo
            .list_chunk_replicas_with_nodes(chunk_id)
            .await
            .expect("replicas");
        assert!(replicas.iter().any(|replica| replica.node_id == node_id));
        server.shutdown().await;
    }

    async fn register_master_node(state: &crate::api::AppState) {
        upsert_node(
            state,
            state.node_id,
            "master",
            "http://127.0.0.1:0",
            "online",
        )
        .await;
    }

    async fn seed_offline_replica(state: &crate::api::AppState, chunk_id: Uuid) {
        let offline_id = Uuid::new_v4();
        upsert_node(
            state,
            offline_id,
            "replica",
            "http://127.0.0.1:1",
            "offline",
        )
        .await;
        insert_present_replica(state, chunk_id, offline_id).await;
    }

    #[tokio::test]
    async fn repair_chunk_skips_failed_store_without_breaking() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.replication_factor = 2;
        let chunk_id = Uuid::new_v4();
        let payload = AxumBytes::from_static(b"payload");
        seed_chunk_for_repair(&state, chunk_id, payload.as_ref(), payload.as_ref()).await;
        upsert_node(
            &state,
            state.node_id,
            "master",
            "http://127.0.0.1:0",
            "online",
        )
        .await;
        let server = start_chunk_server(put_chunk_router(StatusCode::INTERNAL_SERVER_ERROR)).await;
        let node_id = Uuid::new_v4();
        upsert_node(&state, node_id, "replica", &server.address, "online").await;
        let result = repair_chunk(&state, chunk_id).await;
        assert!(result.is_ok());
        let replicas = state
            .repo
            .list_chunk_replicas_with_nodes(chunk_id)
            .await
            .expect("replicas");
        assert!(!replicas.iter().any(|replica| replica.node_id == node_id));
        server.shutdown().await;
    }

    #[tokio::test]
    async fn gc_once_handles_empty_orphans() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        gc_once(&state).await;
        assert_eq!(state.repair_queue.backlog_len(), 0);
    }

    #[tokio::test]
    async fn start_background_jobs_spawns_tasks() {
        reset_job_run_counters();
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.scrub_interval = Duration::from_secs(60);
        state.config.gc_interval = Duration::from_secs(60);
        state.config.multipart_ttl = Duration::from_secs(1);
        start_background_jobs(state.clone());
        let deadline = Instant::now() + Duration::from_millis(20);
        loop {
            if Instant::now() >= deadline {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }

        reset_job_run_counters();
        state.config.scrub_interval = Duration::from_millis(50);
        state.config.gc_interval = Duration::from_millis(50);
        start_background_jobs(state);
        wait_for_job_runs().await;
        assert!(SCRUB_RUNS.load(Ordering::Relaxed) > 0);
        assert!(MULTIPART_CLEANUP_RUNS.load(Ordering::Relaxed) > 0);
        assert!(GC_RUNS.load(Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn repair_worker_step_records_error_label() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let chunk_id = Uuid::new_v4();
        state.repair_queue.enqueue(chunk_id);
        repair_worker_step(&state).await;
    }

    #[tokio::test]
    async fn gc_once_returns_on_repo_error() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        gc_once(&state).await;
    }

    #[tokio::test]
    async fn repair_chunk_reports_repo_error() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        let err = repair_chunk(&state, Uuid::new_v4()).await.unwrap_err();
        assert!(err.contains("checksum load failed"));
    }

    #[tokio::test]
    async fn refresh_capacity_once_updates_node_free_bytes() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        sqlx::query("UPDATE nodes SET free_bytes = 0 WHERE node_id = $1")
            .bind(state.node_id)
            .execute(&pool)
            .await
            .expect("zero free");
        refresh_capacity_once(&state).await;
        let nodes = state.repo.list_nodes().await.expect("nodes");
        let node = nodes
            .iter()
            .find(|n| n.node_id == state.node_id)
            .expect("local node");
        assert!(node.free_bytes.unwrap_or(0) > 0);
    }

    #[tokio::test]
    async fn refresh_capacity_once_tolerates_broken_repo() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.repo = test_support::broken_repo();
        refresh_capacity_once(&state).await;
    }
}
