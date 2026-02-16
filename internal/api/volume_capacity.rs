use crate::meta::models::{BucketVolumeBinding, Node, ReplicaRuntimeConfig};
use crate::meta::repos::Repo;
use std::collections::HashMap;
use uuid::Uuid;

pub struct VolumeCapacityContext {
    nodes_by_id: HashMap<Uuid, Node>,
    free_by_node: HashMap<Uuid, i64>,
    runtime_modes: HashMap<Uuid, String>,
    bindings_by_bucket: HashMap<Uuid, Vec<Uuid>>,
    default_node_ids: Vec<Uuid>,
}

impl VolumeCapacityContext {
    pub fn bound_node_ids(&self, bucket_id: Uuid) -> Vec<Uuid> {
        if let Some(bound) = self.bindings_by_bucket.get(&bucket_id) {
            return bound.clone();
        }
        self.default_node_ids.clone()
    }

    pub fn max_available_bytes(&self, bucket_id: Uuid, replication_factor: u32) -> i64 {
        let node_ids = self.bound_node_ids(bucket_id);
        self.max_available_bytes_for_nodes(&node_ids, replication_factor)
    }

    pub fn max_available_bytes_for_nodes(&self, node_ids: &[Uuid], replication_factor: u32) -> i64 {
        let mut total_free = 0i64;
        for node_id in node_ids {
            if !self.is_writable_volume_node_id(*node_id) {
                continue;
            }
            let free = self.free_by_node.get(node_id).copied().unwrap_or(0).max(0);
            total_free = total_free.saturating_add(free);
        }
        let factor = i64::from(replication_factor.max(1));
        total_free / factor
    }

    pub fn is_binding_eligible_node(&self, node_id: Uuid) -> bool {
        self.nodes_by_id
            .get(&node_id)
            .is_some_and(|node| is_binding_eligible(node, self.runtime_modes.get(&node_id)))
    }

    pub fn has_node(&self, node_id: Uuid) -> bool {
        self.nodes_by_id.contains_key(&node_id)
    }

    pub fn runtime_sub_mode(&self, node_id: Uuid) -> Option<&str> {
        self.runtime_modes.get(&node_id).map(String::as_str)
    }

    fn is_writable_volume_node_id(&self, node_id: Uuid) -> bool {
        self.nodes_by_id
            .get(&node_id)
            .is_some_and(|node| is_writable_volume_node(node, self.runtime_modes.get(&node_id)))
    }
}

pub async fn load_volume_capacity_context(
    repo: &Repo,
) -> Result<VolumeCapacityContext, sqlx::Error> {
    let nodes = repo.list_nodes().await?;
    let runtime_modes = runtime_mode_map(repo.list_replica_runtime_modes().await?);
    let bindings = repo.list_bucket_volume_bindings_all().await?;
    let bindings_by_bucket = bindings_map(bindings);
    let default_node_ids = default_writable_node_ids(&nodes, &runtime_modes);
    Ok(VolumeCapacityContext {
        nodes_by_id: nodes_map(&nodes),
        free_by_node: free_map(&nodes),
        runtime_modes,
        bindings_by_bucket,
        default_node_ids,
    })
}

fn nodes_map(nodes: &[Node]) -> HashMap<Uuid, Node> {
    let mut map = HashMap::new();
    for node in nodes {
        map.insert(node.node_id, node.clone());
    }
    map
}

fn free_map(nodes: &[Node]) -> HashMap<Uuid, i64> {
    let mut map = HashMap::new();
    for node in nodes {
        map.insert(node.node_id, node.free_bytes.unwrap_or(0));
    }
    map
}

fn runtime_mode_map(entries: Vec<ReplicaRuntimeConfig>) -> HashMap<Uuid, String> {
    let mut map = HashMap::new();
    for entry in entries {
        map.insert(entry.node_id, entry.sub_mode);
    }
    map
}

fn bindings_map(entries: Vec<BucketVolumeBinding>) -> HashMap<Uuid, Vec<Uuid>> {
    let mut map: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for entry in entries {
        map.entry(entry.bucket_id).or_default().push(entry.node_id);
    }
    for values in map.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    map
}

fn default_writable_node_ids(nodes: &[Node], modes: &HashMap<Uuid, String>) -> Vec<Uuid> {
    let mut ids = Vec::new();
    for node in nodes {
        if is_writable_volume_node(node, modes.get(&node.node_id)) {
            ids.push(node.node_id);
        }
    }
    ids.sort_unstable();
    ids
}

fn is_binding_eligible(node: &Node, mode: Option<&String>) -> bool {
    if node.role == "master" {
        return true;
    }
    node.role == "replica" && mode.is_some_and(|value| value == "volume")
}

fn is_writable_volume_node(node: &Node, mode: Option<&String>) -> bool {
    if node.status != "online" {
        return false;
    }
    is_binding_eligible(node, mode)
}

#[cfg(test)]
mod tests {
    use super::{
        bindings_map, is_binding_eligible, is_writable_volume_node, load_volume_capacity_context,
        nodes_map, runtime_mode_map, VolumeCapacityContext,
    };
    use crate::meta::models::{BucketVolumeBinding, Node};
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn node(role: &str, status: &str) -> Node {
        Node {
            node_id: Uuid::new_v4(),
            role: role.to_string(),
            address_internal: "http://node".to_string(),
            status: status.to_string(),
            last_heartbeat_at: None,
            capacity_bytes: Some(10),
            free_bytes: Some(5),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn bindings_map_groups_and_deduplicates() {
        let bucket_id = Uuid::new_v4();
        let node_id = Uuid::new_v4();
        let rows = vec![
            BucketVolumeBinding {
                bucket_id,
                node_id,
                created_at: Utc::now(),
            },
            BucketVolumeBinding {
                bucket_id,
                node_id,
                created_at: Utc::now(),
            },
        ];
        let map = bindings_map(rows);
        assert_eq!(map.get(&bucket_id).map(Vec::len), Some(1));
    }

    #[test]
    fn binding_eligibility_accepts_master_and_volume_replica_only() {
        let master = node("master", "online");
        assert!(is_binding_eligible(&master, None));
        let replica = node("replica", "online");
        assert!(is_binding_eligible(&replica, Some(&"volume".to_string())));
        assert!(!is_binding_eligible(&replica, Some(&"backup".to_string())));
    }

    #[test]
    fn writable_volume_requires_online_status() {
        let replica = node("replica", "offline");
        assert!(!is_writable_volume_node(
            &replica,
            Some(&"volume".to_string())
        ));
        let master = node("master", "online");
        assert!(is_writable_volume_node(&master, None));
    }

    #[test]
    fn binding_eligibility_rejects_non_volume_replica() {
        let replica = node("replica", "online");
        let mut modes = HashMap::new();
        modes.insert(replica.node_id, "backup".to_string());
        let mode = modes.get(&replica.node_id);
        assert!(!is_binding_eligible(&replica, mode));
    }

    #[test]
    fn bound_node_ids_uses_binding_or_defaults() {
        let bucket_id = Uuid::new_v4();
        let bound_node_id = Uuid::new_v4();
        let mut bindings = HashMap::new();
        bindings.insert(bucket_id, vec![bound_node_id]);
        let context = VolumeCapacityContext {
            nodes_by_id: HashMap::new(),
            free_by_node: HashMap::new(),
            runtime_modes: HashMap::new(),
            bindings_by_bucket: bindings,
            default_node_ids: vec![Uuid::new_v4()],
        };
        assert_eq!(context.bound_node_ids(bucket_id), vec![bound_node_id]);
        assert_eq!(context.bound_node_ids(Uuid::new_v4()).len(), 1);
    }

    #[test]
    fn max_available_bytes_uses_only_writable_nodes_and_replication_factor() {
        let bucket_id = Uuid::new_v4();
        let master = node("master", "online");
        let backup_replica = node("replica", "online");
        let mut nodes = HashMap::new();
        nodes.insert(master.node_id, master.clone());
        nodes.insert(backup_replica.node_id, backup_replica.clone());
        let mut free_by_node = HashMap::new();
        free_by_node.insert(master.node_id, 100);
        free_by_node.insert(backup_replica.node_id, 200);
        let mut runtime = HashMap::new();
        runtime.insert(backup_replica.node_id, "backup".to_string());
        let context = VolumeCapacityContext {
            nodes_by_id: nodes,
            free_by_node,
            runtime_modes: runtime,
            bindings_by_bucket: HashMap::new(),
            default_node_ids: vec![master.node_id, backup_replica.node_id],
        };
        assert_eq!(context.max_available_bytes(bucket_id, 2), 50);
        assert_eq!(
            context.max_available_bytes_for_nodes(&[master.node_id, backup_replica.node_id], 2),
            50
        );
    }

    #[tokio::test]
    async fn load_context_from_repo_supports_lookup_helpers() {
        let (state, _pool, _dir) = crate::test_support::build_state("master").await;
        let replica_node_id = Uuid::new_v4();
        state
            .repo
            .upsert_node(
                replica_node_id,
                "replica",
                "http://volume-capacity-node:9010",
                "online",
                Some(1000),
                Some(700),
                Some(Utc::now()),
            )
            .await
            .expect("node");
        state
            .repo
            .set_replica_runtime_mode(replica_node_id, "volume", None)
            .await
            .expect("mode");
        let owner = state
            .repo
            .find_user_by_username(&state.config.admin_bootstrap_user)
            .await
            .expect("admin")
            .expect("admin");
        let bucket = state
            .repo
            .create_bucket("vc-bound", owner.id)
            .await
            .expect("bucket");
        state
            .repo
            .replace_bucket_volume_bindings(bucket.id, &[replica_node_id])
            .await
            .expect("binding");
        let context = load_volume_capacity_context(&state.repo)
            .await
            .expect("context");
        assert!(context.has_node(replica_node_id));
        assert!(context.is_binding_eligible_node(replica_node_id));
        assert_eq!(context.runtime_sub_mode(replica_node_id), Some("volume"));
        assert_eq!(context.bound_node_ids(bucket.id), vec![replica_node_id]);
    }

    #[tokio::test]
    async fn load_context_from_repo_maps_lookup_errors() {
        let (state, pool, _dir) = crate::test_support::build_state("master").await;
        let nodes_guard = crate::test_support::TableRenameGuard::rename(&pool, "nodes")
            .await
            .expect("rename");
        assert!(load_volume_capacity_context(&state.repo).await.is_err());
        nodes_guard.restore().await.expect("restore");

        let runtime_guard =
            crate::test_support::TableRenameGuard::rename(&pool, "replica_runtime_config")
                .await
                .expect("rename");
        assert!(load_volume_capacity_context(&state.repo).await.is_err());
        runtime_guard.restore().await.expect("restore");

        let binding_guard =
            crate::test_support::TableRenameGuard::rename(&pool, "bucket_volume_bindings")
                .await
                .expect("rename");
        assert!(load_volume_capacity_context(&state.repo).await.is_err());
        binding_guard.restore().await.expect("restore");
    }

    #[test]
    fn helper_maps_keep_runtime_values() {
        let node = node("replica", "online");
        let nodes = vec![node.clone()];
        let runtime = runtime_mode_map(vec![crate::meta::models::ReplicaRuntimeConfig {
            node_id: node.node_id,
            sub_mode: "delivery".to_string(),
            updated_by_user_id: None,
            updated_at: Utc::now(),
        }]);
        let mapped = nodes_map(&nodes);
        assert!(mapped.contains_key(&node.node_id));
        assert_eq!(runtime.get(&node.node_id), Some(&"delivery".to_string()));
    }
}
