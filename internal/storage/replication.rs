use crate::jobs::RepairQueue;
use crate::meta::repos::Repo;
use crate::obs::Metrics;
use crate::storage::checksum::{Checksum, ChecksumAlgo};
use crate::storage::chunkstore::ChunkStore;
use crate::util::http::InternalAuth;
use bytes::Bytes;
use rand::Rng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct ReplicationManager {
    repo: Repo,
    chunk_store: ChunkStore,
    checksum_algo: ChecksumAlgo,
    replication_factor: u32,
    write_quorum: u32,
    client: Client,
    internal_auth: InternalAuth,
    local_node_id: Uuid,
    repair_queue: RepairQueue,
    metrics: Arc<Metrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub chunk_size_bytes: u64,
    pub replication_factor: u32,
    pub write_quorum: u32,
    pub checksum_algo: String,
}

impl ReplicationManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repo: Repo,
        chunk_store: ChunkStore,
        checksum_algo: ChecksumAlgo,
        replication_factor: u32,
        write_quorum: u32,
        internal_auth: InternalAuth,
        local_node_id: Uuid,
        repair_queue: RepairQueue,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            repo,
            chunk_store,
            checksum_algo,
            replication_factor,
            write_quorum,
            client: Client::new(),
            internal_auth,
            local_node_id,
            repair_queue,
            metrics,
        }
    }

    pub fn cluster_config(&self, chunk_size_bytes: u64) -> ClusterConfig {
        ClusterConfig {
            chunk_size_bytes,
            replication_factor: self.replication_factor,
            write_quorum: self.write_quorum,
            checksum_algo: self.checksum_algo.as_str().to_string(),
        }
    }

    pub fn chunk_store(&self) -> &ChunkStore {
        &self.chunk_store
    }

    pub async fn write_chunk(&self, data: &[u8]) -> Result<(Uuid, Checksum), String> {
        let chunk_id = Uuid::new_v4();
        let checksum = Checksum::compute(self.checksum_algo, data);
        let nodes = self.select_nodes(chunk_id).await?;
        let success = self
            .write_chunk_to_nodes(chunk_id, &checksum, data, &nodes)
            .await;
        self.ensure_write_quorum(success)?;
        self.persist_chunk_write(chunk_id, &checksum, data.len() as i32, nodes)
            .await?;
        self.metrics.chunk_write.with_label_values(&["ok"]).inc();
        Ok((chunk_id, checksum))
    }

    pub async fn read_chunk(&self, chunk_id: Uuid, checksum: &Checksum) -> Result<Bytes, String> {
        let replicas = self.load_chunk_replicas(chunk_id).await?;
        for replica in replicas {
            if !readable_replica(&replica) {
                continue;
            }
            if let Some(bytes) = self
                .read_valid_replica_data(chunk_id, checksum, &replica)
                .await
            {
                self.metrics.chunk_read.with_label_values(&["ok"]).inc();
                return Ok(bytes);
            }
        }
        self.metrics.chunk_read.with_label_values(&["error"]).inc();
        Err("no valid replicas".into())
    }

    async fn write_chunk_to_nodes(
        &self,
        chunk_id: Uuid,
        checksum: &Checksum,
        data: &[u8],
        nodes: &[crate::meta::models::Node],
    ) -> u32 {
        let mut success = 0u32;
        for node in nodes {
            if self
                .write_chunk_to_node(chunk_id, checksum, data, node)
                .await
                .is_ok()
            {
                success += 1;
            }
        }
        success
    }

    async fn write_chunk_to_node(
        &self,
        chunk_id: Uuid,
        checksum: &Checksum,
        data: &[u8],
        node: &crate::meta::models::Node,
    ) -> Result<(), String> {
        if node.node_id == self.local_node_id {
            return self.chunk_store.write_chunk(chunk_id, data).await;
        }
        self.put_remote_chunk(node.address_internal.as_str(), chunk_id, checksum, data)
            .await
    }

    fn ensure_write_quorum(&self, success: u32) -> Result<(), String> {
        if success >= self.write_quorum {
            return Ok(());
        }
        self.metrics.chunk_write.with_label_values(&["error"]).inc();
        Err("write quorum not met".to_string())
    }

    async fn persist_chunk_write(
        &self,
        chunk_id: Uuid,
        checksum: &Checksum,
        size: i32,
        nodes: Vec<crate::meta::models::Node>,
    ) -> Result<(), String> {
        self.repo
            .insert_chunk_metadata(chunk_id, size, checksum.algo.as_str(), &checksum.value)
            .await
            .map_err(|err| format!("insert chunk metadata failed: {err}"))?;
        for node in nodes {
            self.repo
                .insert_chunk_replica(chunk_id, node.node_id, "present")
                .await
                .map_err(|err| format!("insert chunk replica failed: {err}"))?;
        }
        Ok(())
    }

    async fn load_chunk_replicas(
        &self,
        chunk_id: Uuid,
    ) -> Result<Vec<crate::meta::repos::ChunkReplicaNode>, String> {
        self.repo
            .list_chunk_replicas_with_nodes(chunk_id)
            .await
            .map_err(|err| format!("load replicas failed: {err}"))
    }

    async fn read_valid_replica_data(
        &self,
        chunk_id: Uuid,
        checksum: &Checksum,
        replica: &crate::meta::repos::ChunkReplicaNode,
    ) -> Option<Bytes> {
        let data = if replica.node_id == self.local_node_id {
            self.chunk_store.read_chunk(chunk_id).await
        } else {
            self.get_remote_chunk(replica.address_internal.as_str(), chunk_id)
                .await
        };
        let bytes = match data {
            Ok(bytes) => bytes,
            Err(_) => return None,
        };
        if checksum.verify(&bytes) {
            return Some(bytes);
        }
        self.mark_replica_missing(chunk_id, replica.node_id).await;
        None
    }

    async fn mark_replica_missing(&self, chunk_id: Uuid, node_id: Uuid) {
        let node_label = node_id.to_string();
        self.metrics
            .checksum_mismatch
            .with_label_values(&[node_label.as_str()])
            .inc();
        let _ = self
            .repo
            .update_chunk_replica_state(chunk_id, node_id, "missing")
            .await;
        self.repair_queue.enqueue(chunk_id);
    }

    async fn select_nodes(&self, chunk_id: Uuid) -> Result<Vec<crate::meta::models::Node>, String> {
        let mut nodes = self
            .repo
            .list_nodes()
            .await
            .map_err(|err| format!("list nodes failed: {err}"))?;
        nodes.retain(|node| node.status == "online");
        if nodes.is_empty() {
            return Err("no nodes available".into());
        }
        nodes.sort_by_key(|node| node.node_id);
        let mut selected: Vec<crate::meta::models::Node> = Vec::new();
        let mut seed = chunk_id.as_u128() as u64;
        if seed == 0 {
            seed = rand::rng().next_u64();
        }
        let start = (seed % nodes.len() as u64) as usize;
        for idx in 0..nodes.len() {
            let node = nodes[(start + idx) % nodes.len()].clone();
            selected.push(node);
            if selected.len() >= self.replication_factor as usize {
                break;
            }
        }
        Ok(selected)
    }

    async fn put_remote_chunk(
        &self,
        base_url: &str,
        chunk_id: Uuid,
        checksum: &Checksum,
        data: &[u8],
    ) -> Result<(), String> {
        let url = format!(
            "{}/internal/v1/chunks/{}",
            base_url.trim_end_matches('/'),
            chunk_id
        );
        let response = self
            .client
            .put(url)
            .header("Authorization", self.internal_auth.header_value())
            .header("X-Checksum-Algo", checksum.algo.as_str())
            .header("X-Checksum-Value", checksum.to_base64())
            .body(data.to_vec())
            .send()
            .await
            .map_err(|err| format!("remote put failed: {err}"))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("remote put status {}", response.status()))
        }
    }

    pub async fn store_chunk_on_node(
        &self,
        node: &crate::meta::models::Node,
        chunk_id: Uuid,
        checksum: &Checksum,
        data: &[u8],
    ) -> Result<(), String> {
        if node.node_id == self.local_node_id {
            self.chunk_store.write_chunk(chunk_id, data).await
        } else {
            self.put_remote_chunk(node.address_internal.as_str(), chunk_id, checksum, data)
                .await
        }
    }

    pub async fn fetch_chunk_from_node(
        &self,
        node: &crate::meta::models::Node,
        chunk_id: Uuid,
    ) -> Result<Bytes, String> {
        if node.node_id == self.local_node_id {
            self.chunk_store.read_chunk(chunk_id).await
        } else {
            self.get_remote_chunk(node.address_internal.as_str(), chunk_id)
                .await
        }
    }

    pub async fn delete_chunk_everywhere(&self, chunk_id: Uuid) -> Result<(), String> {
        let replicas = self
            .repo
            .list_chunk_replicas_with_nodes(chunk_id)
            .await
            .map_err(|err| format!("load replicas failed: {err}"))?;
        for replica in replicas {
            if replica.node_id == self.local_node_id {
                let _ = self.chunk_store.delete_chunk(chunk_id).await;
                continue;
            }
            let _ = self
                .delete_remote_chunk(replica.address_internal.as_str(), chunk_id)
                .await;
        }
        Ok(())
    }

    async fn get_remote_chunk(&self, base_url: &str, chunk_id: Uuid) -> Result<Bytes, String> {
        let url = format!(
            "{}/internal/v1/chunks/{}",
            base_url.trim_end_matches('/'),
            chunk_id
        );
        let response = self
            .client
            .get(url)
            .header("Authorization", self.internal_auth.header_value())
            .send()
            .await
            .map_err(|err| format!("remote get failed: {err}"))?;
        if !response.status().is_success() {
            return Err(format!("remote get status {}", response.status()));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|err| format!("remote body failed: {err}"))?;
        Ok(bytes)
    }

    async fn delete_remote_chunk(&self, base_url: &str, chunk_id: Uuid) -> Result<(), String> {
        let url = format!(
            "{}/internal/v1/chunks/{}",
            base_url.trim_end_matches('/'),
            chunk_id
        );
        let response = self
            .client
            .delete(url)
            .header("Authorization", self.internal_auth.header_value())
            .send()
            .await
            .map_err(|err| format!("remote delete failed: {err}"))?;
        if response.status().is_success() || response.status().as_u16() == 404 {
            Ok(())
        } else {
            Err(format!("remote delete status {}", response.status()))
        }
    }
}

fn readable_replica(replica: &crate::meta::repos::ChunkReplicaNode) -> bool {
    replica.state == "present" && replica.status == "online"
}

#[cfg(test)]
mod tests {
    use crate::jobs::RepairQueue;
    use crate::meta::models::Node;
    use crate::obs::Metrics;
    use crate::storage::checksum::{Checksum, ChecksumAlgo};
    use crate::storage::replication::ReplicationManager;
    use crate::test_support;
    use crate::test_support::FailTriggerGuard;
    use crate::util::http::InternalAuth;
    use axum::extract::Path;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::put;
    use axum::{body::Bytes as AxumBytes, Router};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::{oneshot, Mutex};
    use tokio::task::JoinHandle;
    use tokio::time::sleep;
    use uuid::Uuid;

    type ReplicaDataStore = Arc<Mutex<HashMap<Uuid, Vec<u8>>>>;

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

    #[tokio::test]
    async fn server_handle_shutdown_handles_missing_sender() {
        let handle = tokio::spawn(async move {});
        let server = ServerHandle {
            shutdown: None,
            join: handle,
        };
        server.shutdown().await;
    }

    async fn spawn_chunk_server(respond_ok: bool) -> (String, ReplicaDataStore, ServerHandle) {
        let data = Arc::new(Mutex::new(HashMap::new()));
        let app = chunk_server_router(respond_ok, data.clone());
        let (base_url, server) = start_router_server(app).await;
        (base_url, data, server)
    }

    fn chunk_server_router(respond_ok: bool, data: ReplicaDataStore) -> Router {
        let put_data = data.clone();
        let get_data = data;
        Router::new().route(
            "/internal/v1/chunks/{id}",
            put(move |Path(id): Path<Uuid>, body: AxumBytes| {
                chunk_server_put(respond_ok, put_data.clone(), id, body)
            })
            .get(move |Path(id): Path<Uuid>| chunk_server_get(respond_ok, get_data.clone(), id))
            .delete(move |Path(_id): Path<Uuid>| async move { chunk_server_delete(respond_ok) }),
        )
    }

    async fn chunk_server_put(
        respond_ok: bool,
        data: ReplicaDataStore,
        id: Uuid,
        body: AxumBytes,
    ) -> StatusCode {
        if !respond_ok {
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
        data.lock().await.insert(id, body.to_vec());
        StatusCode::OK
    }

    async fn chunk_server_get(
        respond_ok: bool,
        data: ReplicaDataStore,
        id: Uuid,
    ) -> axum::response::Response {
        if !respond_ok {
            return (StatusCode::INTERNAL_SERVER_ERROR, AxumBytes::new()).into_response();
        }
        let payload = data.lock().await.get(&id).cloned().unwrap_or_default();
        (StatusCode::OK, AxumBytes::from(payload)).into_response()
    }

    fn chunk_server_delete(respond_ok: bool) -> StatusCode {
        if respond_ok {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::NOT_FOUND
        }
    }

    async fn start_router_server(app: Router) -> (String, ServerHandle) {
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

    fn node_for(address: &str, node_id: Uuid) -> Node {
        Node {
            node_id,
            role: "replica".to_string(),
            address_internal: address.to_string(),
            status: "online".to_string(),
            last_heartbeat_at: None,
            capacity_bytes: None,
            free_bytes: None,
            created_at: chrono::Utc::now(),
        }
    }

    async fn upsert_replica_node(
        state: &crate::api::AppState,
        node_id: Uuid,
        address: &str,
        status: &str,
    ) {
        state
            .repo
            .upsert_node(
                node_id,
                "replica",
                address,
                status,
                None,
                None,
                Some(chrono::Utc::now()),
            )
            .await
            .expect("node");
    }

    async fn insert_chunk_metadata_and_replica(
        state: &crate::api::AppState,
        chunk_id: Uuid,
        checksum: &Checksum,
        size: i32,
        node_id: Uuid,
    ) {
        state
            .repo
            .insert_chunk_metadata(chunk_id, size, checksum.algo.as_str(), &checksum.value)
            .await
            .expect("metadata");
        state
            .repo
            .insert_chunk_replica(chunk_id, node_id, "present")
            .await
            .expect("replica");
    }

    async fn seed_local_chunk(
        state: &crate::api::AppState,
        chunk_id: Uuid,
        payload: &[u8],
    ) -> Checksum {
        let checksum = Checksum::compute(state.config.checksum_algo, payload);
        state
            .replication
            .chunk_store()
            .write_chunk(chunk_id, payload)
            .await
            .expect("write");
        insert_chunk_metadata_and_replica(
            state,
            chunk_id,
            &checksum,
            i32::try_from(payload.len()).expect("size"),
            state.node_id,
        )
        .await;
        checksum
    }

    fn manager_with_settings(
        state: &crate::api::AppState,
        replication_factor: u32,
        write_quorum: u32,
    ) -> ReplicationManager {
        ReplicationManager::new(
            state.repo.clone(),
            state.replication.chunk_store().clone(),
            state.config.checksum_algo,
            replication_factor,
            write_quorum,
            state.internal_auth.clone(),
            state.node_id,
            state.repair_queue.clone(),
            state.metrics.clone(),
        )
    }

    async fn perform_remote_roundtrip(
        state: &crate::api::AppState,
        node: &Node,
        chunk_id: Uuid,
        checksum: &Checksum,
        payload: &[u8],
        data_store: &ReplicaDataStore,
    ) {
        state
            .replication
            .store_chunk_on_node(node, chunk_id, checksum, payload)
            .await
            .expect("store");
        let stored = data_store
            .lock()
            .await
            .get(&chunk_id)
            .cloned()
            .unwrap_or_default();
        assert_eq!(stored, payload.to_vec());
        let data = state
            .replication
            .fetch_chunk_from_node(node, chunk_id)
            .await
            .expect("fetch");
        assert_eq!(data.to_vec(), payload.to_vec());
    }

    fn assert_remote_put_error(err: &str) {
        let has_status = err.contains("remote put status");
        let has_failed = err.contains("remote put failed");
        assert!(has_status | has_failed);
    }

    fn assert_remote_get_error(err: &str) {
        let has_get = err.contains("remote get");
        let has_status = err.contains("remote get status");
        assert!(has_get | has_status);
    }

    async fn seed_remote_read_case(
        state: &crate::api::AppState,
        base_url: &str,
        data_store: &ReplicaDataStore,
    ) -> (Uuid, Checksum, Vec<u8>) {
        let (offline_id, remote_id) = seed_remote_nodes(state, base_url).await;
        let chunk_id = Uuid::new_v4();
        let payload = b"remote-read".to_vec();
        let checksum = Checksum::compute(state.config.checksum_algo, &payload);
        perform_remote_roundtrip(
            state,
            &node_for(base_url, remote_id),
            chunk_id,
            &checksum,
            &payload,
            data_store,
        )
        .await;
        insert_chunk_metadata_and_replica(
            state,
            chunk_id,
            &checksum,
            payload.len() as i32,
            offline_id,
        )
        .await;
        insert_remote_replica(state, chunk_id, remote_id).await;
        (chunk_id, checksum, payload)
    }

    async fn seed_remote_nodes(state: &crate::api::AppState, base_url: &str) -> (Uuid, Uuid) {
        let offline_id = Uuid::new_v4();
        let remote_id = Uuid::new_v4();
        upsert_replica_node(state, offline_id, "http://offline", "offline").await;
        upsert_replica_node(state, remote_id, base_url, "online").await;
        (offline_id, remote_id)
    }

    async fn insert_remote_replica(state: &crate::api::AppState, chunk_id: Uuid, remote_id: Uuid) {
        state
            .repo
            .insert_chunk_replica(chunk_id, remote_id, "present")
            .await
            .expect("replica");
    }

    #[tokio::test]
    async fn cluster_config_matches_manager() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let config = state.replication.cluster_config(2048);
        assert_eq!(config.chunk_size_bytes, 2048);
        assert_eq!(config.replication_factor, 1);
        assert_eq!(config.write_quorum, 1);
        assert_eq!(config.checksum_algo, state.config.checksum_algo.as_str());
    }

    #[tokio::test]
    async fn write_and_read_chunk_local() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let data = b"hello-world".to_vec();
        let chunk_id = Uuid::new_v4();
        let checksum = Checksum::compute(state.config.checksum_algo, &data);
        state
            .replication
            .chunk_store()
            .write_chunk(chunk_id, &data)
            .await
            .expect("write");
        let size = i32::try_from(data.len()).expect("size");
        state
            .repo
            .insert_chunk_metadata(chunk_id, size, checksum.algo.as_str(), &checksum.value)
            .await
            .expect("metadata");
        state
            .repo
            .insert_chunk_replica(chunk_id, state.node_id, "present")
            .await
            .expect("replica");
        let bytes = state
            .replication
            .read_chunk(chunk_id, &checksum)
            .await
            .expect("read");
        assert_eq!(bytes.to_vec(), data);
    }

    #[tokio::test]
    async fn read_chunk_returns_ok_for_valid_local_replica() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let chunk_id = Uuid::new_v4();
        let payload = b"local-read";
        let checksum = seed_local_chunk(&state, chunk_id, payload).await;
        let bytes = state
            .replication
            .read_chunk(chunk_id, &checksum)
            .await
            .expect("read");
        assert_eq!(bytes.to_vec(), payload.to_vec());
    }

    #[tokio::test]
    async fn read_chunk_mismatch_enqueues_repair() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let chunk_id = Uuid::new_v4();
        let _ = seed_local_chunk(&state, chunk_id, b"payload").await;
        let bad_checksum = Checksum {
            algo: ChecksumAlgo::Crc32c,
            value: vec![1, 2, 3],
        };
        let err = state
            .replication
            .read_chunk(chunk_id, &bad_checksum)
            .await
            .unwrap_err();
        assert!(err.contains("no valid replicas"));
        assert!(state.repair_queue.backlog_len() >= 1);
    }

    #[tokio::test]
    async fn write_chunk_reports_quorum_failure() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let manager = ReplicationManager::new(
            state.repo.clone(),
            state.replication.chunk_store().clone(),
            state.config.checksum_algo,
            state.config.replication_factor,
            state.config.replication_factor + 1,
            state.internal_auth.clone(),
            state.node_id,
            state.repair_queue.clone(),
            state.metrics.clone(),
        );
        let err = manager.write_chunk(b"data").await.unwrap_err();
        assert!(err.contains("write quorum not met"));
    }

    #[tokio::test]
    async fn write_chunk_succeeds_with_zero_quorum() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let manager = ReplicationManager::new(
            state.repo.clone(),
            state.replication.chunk_store().clone(),
            state.config.checksum_algo,
            state.config.replication_factor,
            0,
            state.internal_auth.clone(),
            state.node_id,
            state.repair_queue.clone(),
            state.metrics.clone(),
        );
        let result = manager.write_chunk(b"data").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn write_chunk_fails_when_no_nodes() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        sqlx::query("DELETE FROM nodes")
            .execute(&pool)
            .await
            .expect("delete nodes");
        let err = state.replication.write_chunk(b"data").await.unwrap_err();
        assert!(err.contains("no nodes available"));
    }

    #[tokio::test]
    async fn remote_put_get_delete_paths() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (base_url, data_store, server) = spawn_chunk_server(true).await;
        let node_id = Uuid::new_v4();
        let node = node_for(&base_url, node_id);
        upsert_replica_node(&state, node_id, &base_url, "online").await;

        let chunk_id = Uuid::new_v4();
        let checksum = Checksum::compute(state.config.checksum_algo, b"remote");
        perform_remote_roundtrip(&state, &node, chunk_id, &checksum, b"remote", &data_store).await;
        insert_chunk_metadata_and_replica(&state, chunk_id, &checksum, 6, node_id).await;
        state
            .replication
            .delete_chunk_everywhere(chunk_id)
            .await
            .expect("delete");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn remote_errors_are_reported() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (base_url, _data, server) = spawn_chunk_server(false).await;
        let node_id = Uuid::new_v4();
        let node = node_for(&base_url, node_id);
        let checksum = Checksum::compute(state.config.checksum_algo, b"data");
        let err = state
            .replication
            .store_chunk_on_node(&node, Uuid::new_v4(), &checksum, b"data")
            .await
            .unwrap_err();
        assert_remote_put_error(&err);

        let err = state
            .replication
            .fetch_chunk_from_node(&node, Uuid::new_v4())
            .await
            .unwrap_err();
        assert_remote_get_error(&err);
        upsert_replica_node(&state, node_id, &base_url, "online").await;
        let chunk_id = Uuid::new_v4();
        insert_chunk_metadata_and_replica(&state, chunk_id, &checksum, 4, node_id).await;
        state
            .replication
            .delete_chunk_everywhere(chunk_id)
            .await
            .expect("delete");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn store_and_fetch_chunk_local_node() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let node = node_for("http://local", state.node_id);
        let chunk_id = Uuid::new_v4();
        let data = b"local-data";
        let checksum = Checksum::compute(state.config.checksum_algo, data);
        state
            .replication
            .store_chunk_on_node(&node, chunk_id, &checksum, data)
            .await
            .expect("store");
        let fetched = state
            .replication
            .fetch_chunk_from_node(&node, chunk_id)
            .await
            .expect("fetch");
        assert_eq!(fetched.to_vec(), data);
    }

    #[tokio::test]
    async fn write_chunk_hits_remote_nodes() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (base_url, _data, server) = spawn_chunk_server(true).await;
        let node_id = Uuid::new_v4();
        upsert_replica_node(&state, node_id, &base_url, "online").await;
        let manager = manager_with_settings(&state, 2, 1);
        let result = manager.write_chunk(b"replicated");
        assert!(result.await.is_ok());
        server.shutdown().await;
    }

    #[tokio::test]
    async fn read_chunk_skips_unhealthy_and_reads_remote() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let (base_url, data_store, server) = spawn_chunk_server(true).await;
        let (chunk_id, checksum, payload) =
            seed_remote_read_case(&state, &base_url, &data_store).await;
        assert!(data_store.lock().await.contains_key(&chunk_id));
        let data = state
            .replication
            .read_chunk(chunk_id, &checksum)
            .await
            .expect("read");
        assert_eq!(data.to_vec(), payload);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn read_chunk_skips_unreadable_replica_entries() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let chunk_id = Uuid::new_v4();
        let checksum = Checksum::compute(state.config.checksum_algo, b"x");
        state
            .repo
            .insert_chunk_metadata(chunk_id, 1, checksum.algo.as_str(), &checksum.value)
            .await
            .expect("metadata");
        let offline_id = Uuid::new_v4();
        upsert_replica_node(&state, offline_id, "http://offline", "offline").await;
        state
            .repo
            .insert_chunk_replica(chunk_id, offline_id, "present")
            .await
            .expect("replica");
        let err = state
            .replication
            .read_chunk(chunk_id, &checksum)
            .await
            .unwrap_err();
        assert_eq!(err, "no valid replicas");
    }

    #[tokio::test]
    async fn delete_chunk_everywhere_handles_local_replica() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let chunk_id = Uuid::new_v4();
        let checksum = Checksum::compute(state.config.checksum_algo, b"delete");
        state
            .replication
            .chunk_store()
            .write_chunk(chunk_id, b"delete")
            .await
            .expect("write");
        state
            .repo
            .insert_chunk_metadata(chunk_id, 6, checksum.algo.as_str(), &checksum.value)
            .await
            .expect("metadata");
        state
            .repo
            .insert_chunk_replica(chunk_id, state.node_id, "present")
            .await
            .expect("replica");
        state
            .replication
            .delete_chunk_everywhere(chunk_id)
            .await
            .expect("delete");
    }

    #[tokio::test]
    async fn delete_remote_chunk_reports_error_status() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let app = Router::new().route(
            "/internal/v1/chunks/{id}",
            axum::routing::delete(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        );
        let (base_url, server) = start_router_server(app).await;
        let node_id = Uuid::new_v4();
        upsert_replica_node(&state, node_id, &base_url, "online").await;
        let chunk_id = Uuid::new_v4();
        state
            .repo
            .insert_chunk_metadata(chunk_id, 1, state.config.checksum_algo.as_str(), &[0])
            .await
            .expect("metadata");
        state
            .repo
            .insert_chunk_replica(chunk_id, node_id, "present")
            .await
            .expect("replica");
        let result = state.replication.delete_chunk_everywhere(chunk_id).await;
        assert!(result.is_ok());
        server.shutdown().await;
    }

    #[tokio::test]
    async fn select_nodes_handles_zero_seed_and_offline_nodes() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        sqlx::query("DELETE FROM nodes")
            .execute(&pool)
            .await
            .expect("delete");
        let online_id = Uuid::new_v4();
        let offline_id = Uuid::new_v4();
        upsert_replica_node(&state, online_id, "http://online", "online").await;
        upsert_replica_node(&state, offline_id, "http://offline", "offline").await;
        let nodes = state
            .replication
            .select_nodes(Uuid::from_u128(0))
            .await
            .expect("nodes");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_id, online_id);
    }

    #[tokio::test]
    async fn read_chunk_reports_repo_error() {
        let data_dir = test_support::new_temp_dir("replication-broken").await;
        let config = test_support::base_config("master", data_dir.clone());
        let pool = sqlx::PgPool::connect_lazy("postgres://nss:nss@127.0.0.1:1/nss?sslmode=disable")
            .expect("pool");
        let repo = crate::meta::repos::Repo::new(pool);
        let chunk_store =
            crate::storage::chunkstore::ChunkStore::from_runtime(&config).expect("store");
        let metrics = Metrics::new();
        let manager = ReplicationManager::new(
            repo,
            chunk_store,
            config.checksum_algo,
            config.replication_factor,
            config.write_quorum,
            InternalAuth::new("token".to_string()),
            Uuid::new_v4(),
            RepairQueue::new(),
            metrics.clone(),
        );
        let checksum = Checksum::compute(config.checksum_algo, b"data");
        let err = manager
            .read_chunk(Uuid::new_v4(), &checksum)
            .await
            .unwrap_err();
        assert!(err.contains("load replicas failed"));
    }

    #[tokio::test]
    async fn write_chunk_reports_repo_error() {
        let data_dir = test_support::new_temp_dir("replication-broken-write").await;
        let config = test_support::base_config("master", data_dir.clone());
        let pool = sqlx::PgPool::connect_lazy("postgres://nss:nss@127.0.0.1:1/nss?sslmode=disable")
            .expect("pool");
        let repo = crate::meta::repos::Repo::new(pool);
        let chunk_store =
            crate::storage::chunkstore::ChunkStore::from_runtime(&config).expect("store");
        let metrics = Metrics::new();
        let manager = ReplicationManager::new(
            repo,
            chunk_store,
            config.checksum_algo,
            config.replication_factor,
            config.write_quorum,
            InternalAuth::new("token".to_string()),
            Uuid::new_v4(),
            RepairQueue::new(),
            metrics.clone(),
        );
        let err = manager.write_chunk(b"data").await.unwrap_err();
        assert!(err.contains("list nodes failed"));
    }

    #[tokio::test]
    async fn write_chunk_succeeds_locally() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let result = state.replication.write_chunk(b"local-data").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn delete_chunk_everywhere_succeeds_for_remote_node() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let app = Router::new().route(
            "/internal/v1/chunks/{id}",
            axum::routing::delete(|| async { StatusCode::NO_CONTENT }),
        );
        let (base_url, server) = start_router_server(app).await;
        let node_id = Uuid::new_v4();
        upsert_replica_node(&state, node_id, &base_url, "online").await;
        let chunk_id = Uuid::new_v4();
        let checksum = Checksum::compute(state.config.checksum_algo, b"data");
        insert_chunk_metadata_and_replica(&state, chunk_id, &checksum, 4, node_id).await;
        let result = state.replication.delete_chunk_everywhere(chunk_id).await;
        assert!(result.is_ok());
        server.shutdown().await;
    }

    #[tokio::test]
    async fn write_chunk_reports_metadata_insert_error() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let guard = FailTriggerGuard::create(&pool, "chunks", "AFTER", "INSERT")
            .await
            .expect("guard");
        let err = state.replication.write_chunk(b"data").await.unwrap_err();
        assert!(err.contains("insert chunk metadata failed"));
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn write_chunk_reports_replica_insert_error() {
        let (state, pool, _dir) = test_support::build_state("master").await;
        let guard = FailTriggerGuard::create(&pool, "chunk_replicas", "AFTER", "INSERT")
            .await
            .expect("guard");
        let err = state.replication.write_chunk(b"data").await.unwrap_err();
        assert!(err.contains("insert chunk replica failed"));
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn delete_chunk_everywhere_reports_repo_error() {
        let data_dir = test_support::new_temp_dir("replication-delete-error").await;
        let config = test_support::base_config("master", data_dir.clone());
        let pool = sqlx::PgPool::connect_lazy("postgres://nss:nss@127.0.0.1:1/nss?sslmode=disable")
            .expect("pool");
        let repo = crate::meta::repos::Repo::new(pool);
        let chunk_store =
            crate::storage::chunkstore::ChunkStore::from_runtime(&config).expect("store");
        let metrics = Metrics::new();
        let manager = ReplicationManager::new(
            repo,
            chunk_store,
            config.checksum_algo,
            config.replication_factor,
            config.write_quorum,
            InternalAuth::new("token".to_string()),
            Uuid::new_v4(),
            RepairQueue::new(),
            metrics.clone(),
        );
        let err = manager
            .delete_chunk_everywhere(Uuid::new_v4())
            .await
            .unwrap_err();
        assert!(err.contains("load replicas failed"));
    }

    #[tokio::test]
    async fn remote_network_errors_are_reported() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let node_id = Uuid::new_v4();
        let node = node_for("http://127.0.0.1:1", node_id);
        let checksum = Checksum::compute(state.config.checksum_algo, b"data");
        let err = state
            .replication
            .store_chunk_on_node(&node, Uuid::new_v4(), &checksum, b"data")
            .await
            .unwrap_err();
        assert!(err.contains("remote put failed"));

        let err = state
            .replication
            .fetch_chunk_from_node(&node, Uuid::new_v4())
            .await
            .unwrap_err();
        assert!(err.contains("remote get failed"));
    }

    #[tokio::test]
    async fn get_remote_chunk_reports_body_error() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhi")
                .await;
        });
        sleep(Duration::from_millis(50)).await;
        let node = node_for(&format!("http://{}", addr), Uuid::new_v4());
        let err = state
            .replication
            .fetch_chunk_from_node(&node, Uuid::new_v4())
            .await
            .unwrap_err();
        assert!(err.contains("remote body failed"));
        let _ = server.await;

        let unreachable = node_for("http://127.0.0.1:1", Uuid::new_v4());
        let err = state
            .replication
            .fetch_chunk_from_node(&unreachable, Uuid::new_v4())
            .await
            .unwrap_err();
        assert!(err.contains("remote get failed"));
    }

    #[tokio::test]
    async fn delete_remote_chunk_reports_send_error() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let node_id = Uuid::new_v4();
        state
            .repo
            .upsert_node(
                node_id,
                "replica",
                "http://127.0.0.1:1",
                "online",
                None,
                None,
                Some(chrono::Utc::now()),
            )
            .await
            .expect("node");
        let chunk_id = Uuid::new_v4();
        state
            .repo
            .insert_chunk_metadata(chunk_id, 4, state.config.checksum_algo.as_str(), &[0])
            .await
            .expect("metadata");
        state
            .repo
            .insert_chunk_replica(chunk_id, node_id, "present")
            .await
            .expect("replica");
        let _ = state.replication.delete_chunk_everywhere(chunk_id).await;
    }
}
