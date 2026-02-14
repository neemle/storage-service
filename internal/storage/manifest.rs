use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ManifestEntry {
    pub chunk_id: Uuid,
    pub size_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub total_size: u64,
    pub chunks: Vec<ManifestEntry>,
}
