use crate::storage::chunk_encryption::{load_chunk_encryption, ChunkEncryption};
use bytes::Bytes;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

#[cfg(test)]
use std::sync::atomic::{AtomicU8, Ordering};

#[cfg(test)]
static FAILPOINT: AtomicU8 = AtomicU8::new(0);

#[cfg(test)]
fn failpoint(step: u8) -> bool {
    if FAILPOINT.load(Ordering::SeqCst) == step {
        FAILPOINT.store(0, Ordering::SeqCst);
        true
    } else {
        false
    }
}

#[cfg(test)]
pub(crate) fn set_failpoint(step: u8) {
    FAILPOINT.store(step, Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) fn clear_failpoint() {
    FAILPOINT.store(0, Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) struct FailpointGuard;

#[cfg(test)]
impl Drop for FailpointGuard {
    fn drop(&mut self) {
        clear_failpoint();
    }
}

#[cfg(test)]
pub(crate) fn failpoint_guard(step: u8) -> FailpointGuard {
    set_failpoint(step);
    FailpointGuard
}

#[derive(Clone)]
pub struct ChunkStore {
    data_dirs: Vec<PathBuf>,
    encryption: Option<ChunkEncryption>,
}

impl ChunkStore {
    pub fn new(data_dirs: &[PathBuf]) -> Result<Self, String> {
        Self::with_encryption(data_dirs, None)
    }

    pub fn from_runtime(config: &crate::util::config::Config) -> Result<Self, String> {
        let encryption = load_chunk_encryption(config)?;
        Self::with_encryption(&config.data_dirs, encryption)
    }

    pub fn with_encryption(
        data_dirs: &[PathBuf],
        encryption: Option<ChunkEncryption>,
    ) -> Result<Self, String> {
        if data_dirs.is_empty() {
            return Err("data dirs empty".into());
        }
        Ok(Self {
            data_dirs: data_dirs.to_vec(),
            encryption,
        })
    }

    pub fn data_dirs(&self) -> &[PathBuf] {
        &self.data_dirs
    }

    pub fn chunk_path(&self, chunk_id: Uuid) -> PathBuf {
        let hex = chunk_id.simple().to_string();
        let shard_a = &hex[0..2];
        let shard_b = &hex[2..4];
        let dir = self.pick_dir(&hex);
        dir.join("chunks").join(shard_a).join(shard_b).join(hex)
    }

    fn pick_dir(&self, key: &str) -> &PathBuf {
        if self.data_dirs.len() == 1 {
            return &self.data_dirs[0];
        }
        let mut hash: u64 = 0;
        for byte in key.as_bytes() {
            hash = hash.wrapping_mul(31).wrapping_add(*byte as u64);
        }
        let idx = (hash % self.data_dirs.len() as u64) as usize;
        &self.data_dirs[idx]
    }

    pub async fn write_chunk(&self, chunk_id: Uuid, data: &[u8]) -> Result<(), String> {
        let payload = self.encode_payload(data)?;
        let path = self.chunk_path(chunk_id);
        let dir = validate_chunk_dir(&path)?;
        create_chunk_dir(dir).await?;
        let tmp_path = path.with_extension("tmp");
        let mut file = create_temp_file(&tmp_path).await?;
        write_chunk_data(&mut file, &payload).await?;
        sync_chunk_file(&mut file).await?;
        drop(file);
        rename_temp_file(&tmp_path, &path).await?;
        Ok(())
    }

    pub async fn read_chunk(&self, chunk_id: Uuid) -> Result<Bytes, String> {
        let path = self.chunk_path(chunk_id);
        let mut file = fs::File::open(&path)
            .await
            .map_err(|err| format!("open failed: {err}"))?;
        let mut buf = Vec::new();
        let read_result = {
            #[cfg(test)]
            {
                if failpoint(7) {
                    Err(std::io::Error::new(std::io::ErrorKind::Other, "failpoint"))
                } else {
                    file.read_to_end(&mut buf).await
                }
            }
            #[cfg(not(test))]
            {
                file.read_to_end(&mut buf).await
            }
        };
        read_result.map_err(|err| format!("read failed: {err}"))?;
        let payload = self.decode_payload(&buf)?;
        Ok(Bytes::from(payload))
    }

    pub async fn read_chunk_range(
        &self,
        chunk_id: Uuid,
        start: usize,
        end: usize,
    ) -> Result<Bytes, String> {
        let data = self.read_chunk(chunk_id).await?;
        if start >= data.len() {
            return Ok(Bytes::new());
        }
        let end = end.min(data.len());
        Ok(data.slice(start..end))
    }

    pub async fn chunk_exists(&self, chunk_id: Uuid) -> bool {
        let path = self.chunk_path(chunk_id);
        Path::new(&path).exists()
    }

    pub async fn delete_chunk(&self, chunk_id: Uuid) -> Result<(), String> {
        let path = self.chunk_path(chunk_id);
        if Path::new(&path).exists() {
            let delete_result = {
                #[cfg(test)]
                {
                    if failpoint(8) {
                        Err(std::io::Error::new(std::io::ErrorKind::Other, "failpoint"))
                    } else {
                        fs::remove_file(&path).await
                    }
                }
                #[cfg(not(test))]
                {
                    fs::remove_file(&path).await
                }
            };
            delete_result.map_err(|err| format!("delete failed: {err}"))?;
        }
        Ok(())
    }

    fn encode_payload(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(encryption) = &self.encryption {
            return encryption.encrypt(data);
        }
        Ok(data.to_vec())
    }

    fn decode_payload(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        if !ChunkEncryption::is_envelope(payload) {
            return self.decode_plaintext(payload);
        }
        let encryption = self
            .encryption
            .as_ref()
            .ok_or_else(|| "chunk payload is encrypted but encryption is disabled".to_string())?;
        encryption.decrypt(payload)
    }

    fn decode_plaintext(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(encryption) = &self.encryption {
            if !encryption.allow_plaintext_read() {
                return Err("plaintext chunk payload rejected by encryption policy".into());
            }
        }
        Ok(payload.to_vec())
    }
}

#[cfg(test)]
fn failpoint_io_error() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, "failpoint")
}

fn validate_chunk_dir(path: &Path) -> Result<&Path, String> {
    let parent = {
        #[cfg(test)]
        {
            if failpoint(1) {
                None
            } else {
                path.parent()
            }
        }
        #[cfg(not(test))]
        {
            path.parent()
        }
    };
    parent.ok_or_else(|| "invalid chunk path".to_string())
}

async fn create_chunk_dir(dir: &Path) -> Result<(), String> {
    let result = {
        #[cfg(test)]
        {
            if failpoint(2) {
                Err(failpoint_io_error())
            } else {
                fs::create_dir_all(dir).await
            }
        }
        #[cfg(not(test))]
        {
            fs::create_dir_all(dir).await
        }
    };
    result.map_err(|err| format!("create dir failed: {err}"))
}

async fn create_temp_file(tmp_path: &Path) -> Result<fs::File, String> {
    let result = {
        #[cfg(test)]
        {
            if failpoint(3) {
                Err(failpoint_io_error())
            } else {
                fs::File::create(tmp_path).await
            }
        }
        #[cfg(not(test))]
        {
            fs::File::create(tmp_path).await
        }
    };
    result.map_err(|err| format!("create temp failed: {err}"))
}

async fn write_chunk_data(file: &mut fs::File, data: &[u8]) -> Result<(), String> {
    let result = {
        #[cfg(test)]
        {
            if failpoint(4) {
                Err(failpoint_io_error())
            } else {
                file.write_all(data).await
            }
        }
        #[cfg(not(test))]
        {
            file.write_all(data).await
        }
    };
    result.map_err(|err| format!("write failed: {err}"))
}

async fn sync_chunk_file(file: &mut fs::File) -> Result<(), String> {
    let result = {
        #[cfg(test)]
        {
            if failpoint(5) {
                Err(failpoint_io_error())
            } else {
                file.sync_all().await
            }
        }
        #[cfg(not(test))]
        {
            file.sync_all().await
        }
    };
    result.map_err(|err| format!("sync failed: {err}"))
}

async fn rename_temp_file(tmp_path: &Path, path: &Path) -> Result<(), String> {
    let result = {
        #[cfg(test)]
        {
            if failpoint(6) {
                Err(failpoint_io_error())
            } else {
                fs::rename(tmp_path, path).await
            }
        }
        #[cfg(not(test))]
        {
            fs::rename(tmp_path, path).await
        }
    };
    result.map_err(|err| format!("rename failed: {err}"))
}

#[cfg(test)]
mod tests {
    use super::{clear_failpoint, set_failpoint, ChunkStore};
    use crate::storage::chunk_encryption::ChunkEncryption;
    use crate::test_support;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::env;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use tokio::fs;
    use uuid::Uuid;

    static FAILPOINT_LOCK: Mutex<()> = Mutex::new(());

    fn lock_failpoints() -> std::sync::MutexGuard<'static, ()> {
        let guard = FAILPOINT_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_failpoint();
        guard
    }

    struct FailGuard;

    impl FailGuard {
        fn new(step: u8) -> Self {
            set_failpoint(step);
            FailGuard
        }
    }

    impl Drop for FailGuard {
        fn drop(&mut self) {
            clear_failpoint();
        }
    }

    struct EnvVarGuard {
        key: String,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &str, value: &str) -> Self {
            let previous = env::var(key).ok();
            env::set_var(key, value);
            Self {
                key: key.to_string(),
                previous,
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = self.previous.as_ref() {
                env::set_var(&self.key, value);
            } else {
                env::remove_var(&self.key);
            }
        }
    }

    async fn new_temp_dir() -> PathBuf {
        let path = env::temp_dir().join(format!("nss-chunkstore-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).await.expect("create dir");
        path
    }

    #[test]
    fn env_var_guard_restores_existing_value() {
        let key = "NSS_TEST_CHUNKSTORE_GUARD";
        env::set_var(key, "before");
        {
            let _guard = EnvVarGuard::set(key, "after");
        }
        assert_eq!(env::var(key).ok().as_deref(), Some("before"));
        env::remove_var(key);
    }

    fn build_encryption(
        active_key_id: &str,
        keys: &[(&str, u8)],
        allow_plaintext_read: bool,
    ) -> ChunkEncryption {
        let mut keyring = HashMap::new();
        for (key_id, fill) in keys {
            keyring.insert((*key_id).to_string(), vec![*fill; 32]);
        }
        ChunkEncryption::new(active_key_id.to_string(), keyring, allow_plaintext_read)
            .expect("encryption")
    }

    #[tokio::test]
    async fn chunkstore_rejects_empty_dirs() {
        let _lock = lock_failpoints();
        let result = ChunkStore::new(&[]);
        assert!(result.is_err());
        let err = result.err().expect("err");
        assert_eq!(err, "data dirs empty");
    }

    #[tokio::test]
    async fn write_read_delete_chunk() {
        let _lock = lock_failpoints();
        let dir = new_temp_dir().await;
        let store = ChunkStore::new(&[dir.clone()]).expect("store");
        let chunk_id = Uuid::new_v4();
        let payload = b"hello world";

        store.write_chunk(chunk_id, payload).await.expect("write");
        assert!(store.chunk_exists(chunk_id).await);

        let bytes = store.read_chunk(chunk_id).await.expect("read");
        assert_eq!(bytes, Bytes::from_static(payload));

        let range = store.read_chunk_range(chunk_id, 0, 5).await.expect("range");
        assert_eq!(range, Bytes::from_static(b"hello"));

        let empty = store
            .read_chunk_range(chunk_id, payload.len() + 1, payload.len() + 10)
            .await
            .expect("range empty");
        assert!(empty.is_empty());

        let capped = store
            .read_chunk_range(chunk_id, 0, payload.len() + 10)
            .await
            .expect("range capped");
        assert_eq!(capped, Bytes::from_static(payload));

        store.delete_chunk(chunk_id).await.expect("delete");
        assert!(!store.chunk_exists(chunk_id).await);

        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn write_chunk_failpoints_report_errors() {
        let _lock = lock_failpoints();
        let dir = new_temp_dir().await;
        let store = ChunkStore::new(&[dir.clone()]).expect("store");
        let payload = b"data";
        let cases = [
            (1u8, "invalid chunk path"),
            (2u8, "create dir failed"),
            (3u8, "create temp failed"),
            (4u8, "write failed"),
            (5u8, "sync failed"),
            (6u8, "rename failed"),
        ];
        for (step, message) in cases {
            let _guard = FailGuard::new(step);
            let result = store.write_chunk(Uuid::new_v4(), payload).await;
            let err = result.unwrap_err();
            assert!(err.contains(message));
        }
        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn read_chunk_failpoint_reports_error() {
        let _lock = lock_failpoints();
        let dir = new_temp_dir().await;
        let store = ChunkStore::new(&[dir.clone()]).expect("store");
        let chunk_id = Uuid::new_v4();
        store
            .write_chunk(chunk_id, b"payload")
            .await
            .expect("write");

        let _guard = FailGuard::new(7);
        let err = store.read_chunk(chunk_id).await.unwrap_err();
        assert!(err.contains("read failed"));

        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn read_chunk_range_propagates_read_error() {
        let _lock = lock_failpoints();
        let dir = new_temp_dir().await;
        let store = ChunkStore::new(&[dir.clone()]).expect("store");
        let err = store
            .read_chunk_range(Uuid::new_v4(), 0, 10)
            .await
            .unwrap_err();
        assert!(err.contains("open failed"));
        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn delete_chunk_failpoint_reports_error() {
        let _lock = lock_failpoints();
        let dir = new_temp_dir().await;
        let store = ChunkStore::new(&[dir.clone()]).expect("store");
        let chunk_id = Uuid::new_v4();
        store
            .write_chunk(chunk_id, b"payload")
            .await
            .expect("write");

        let _guard = FailGuard::new(8);
        let err = store.delete_chunk(chunk_id).await.unwrap_err();
        assert!(err.contains("delete failed"));

        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn read_missing_chunk_returns_error() {
        let _lock = lock_failpoints();
        let dir = new_temp_dir().await;
        let store = ChunkStore::new(&[dir.clone()]).expect("store");
        let err = store.read_chunk(Uuid::new_v4()).await.unwrap_err();
        assert!(err.contains("open failed"));
        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn chunk_path_uses_one_of_multiple_dirs() {
        let _lock = lock_failpoints();
        let dir_a = new_temp_dir().await;
        let dir_b = new_temp_dir().await;
        let store = ChunkStore::new(&[dir_a.clone(), dir_b.clone()]).expect("store");
        let mut seen_a = false;
        let mut seen_b = false;
        for i in 0..1024u128 {
            let chunk_id = Uuid::from_u128(i);
            let path = store.chunk_path(chunk_id);
            let starts_a = path.starts_with(&dir_a);
            let starts_b = path.starts_with(&dir_b);
            assert!(starts_a ^ starts_b);
            seen_a |= starts_a;
            seen_b |= starts_b;
            if seen_a && seen_b {
                break;
            }
        }
        assert!(seen_a);
        assert!(seen_b);
        let _ = fs::remove_dir_all(&dir_a).await;
        let _ = fs::remove_dir_all(&dir_b).await;
    }

    #[tokio::test]
    async fn data_dirs_returns_configured_paths() {
        let _lock = lock_failpoints();
        let dir = new_temp_dir().await;
        let store = ChunkStore::new(&[dir.clone()]).expect("store");
        assert_eq!(store.data_dirs(), &[dir.clone()]);
        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn delete_chunk_ignores_missing_file() {
        let _lock = lock_failpoints();
        let dir = new_temp_dir().await;
        let store = ChunkStore::new(&[dir.clone()]).expect("store");
        store.delete_chunk(Uuid::new_v4()).await.expect("delete");
        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn write_chunk_with_encryption_stores_envelope() {
        let _lock = lock_failpoints();
        let dir = new_temp_dir().await;
        let encryption = build_encryption("v1", &[("v1", 7)], true);
        let store = ChunkStore::with_encryption(&[dir.clone()], Some(encryption)).expect("store");
        let chunk_id = Uuid::new_v4();

        store
            .write_chunk(chunk_id, b"plaintext payload")
            .await
            .expect("write");

        let raw = fs::read(store.chunk_path(chunk_id)).await.expect("raw");
        assert!(ChunkEncryption::is_envelope(&raw));
        assert!(!raw
            .windows(b"plaintext payload".len())
            .any(|win| win == b"plaintext payload"));

        let decoded = store.read_chunk(chunk_id).await.expect("read");
        assert_eq!(decoded, Bytes::from_static(b"plaintext payload"));
        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn encrypted_store_rejects_plaintext_when_disabled() {
        let _lock = lock_failpoints();
        let dir = new_temp_dir().await;
        let chunk_id = Uuid::new_v4();

        let plain_store = ChunkStore::new(&[dir.clone()]).expect("plain store");
        plain_store
            .write_chunk(chunk_id, b"legacy plain")
            .await
            .expect("write");

        let strict = build_encryption("v1", &[("v1", 9)], false);
        let strict_store =
            ChunkStore::with_encryption(&[dir.clone()], Some(strict)).expect("strict");
        let err = strict_store.read_chunk(chunk_id).await.unwrap_err();
        assert!(err.contains("plaintext chunk payload rejected"));

        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn encrypted_store_can_read_plaintext_when_allowed() {
        let _lock = lock_failpoints();
        let dir = new_temp_dir().await;
        let chunk_id = Uuid::new_v4();
        let plain_store = ChunkStore::new(&[dir.clone()]).expect("plain store");
        plain_store
            .write_chunk(chunk_id, b"legacy plain")
            .await
            .expect("write");
        let permissive = build_encryption("v1", &[("v1", 11)], true);
        let store = ChunkStore::with_encryption(&[dir.clone()], Some(permissive)).expect("store");
        let payload = store.read_chunk(chunk_id).await.expect("read");
        assert_eq!(payload, Bytes::from_static(b"legacy plain"));
        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn rotated_keyring_reads_old_chunks() {
        let _lock = lock_failpoints();
        let dir = new_temp_dir().await;
        let chunk_id_old = Uuid::new_v4();
        let chunk_id_new = Uuid::new_v4();

        let v1_only = build_encryption("v1", &[("v1", 1)], true);
        let store_v1 = ChunkStore::with_encryption(&[dir.clone()], Some(v1_only)).expect("v1");
        store_v1
            .write_chunk(chunk_id_old, b"old")
            .await
            .expect("write old");

        let rotated = build_encryption("v2", &[("v1", 1), ("v2", 2)], true);
        let store_rotated =
            ChunkStore::with_encryption(&[dir.clone()], Some(rotated)).expect("rotated");
        let old = store_rotated
            .read_chunk(chunk_id_old)
            .await
            .expect("read old");
        assert_eq!(old, Bytes::from_static(b"old"));

        store_rotated
            .write_chunk(chunk_id_new, b"new")
            .await
            .expect("write new");
        let new = store_rotated
            .read_chunk(chunk_id_new)
            .await
            .expect("read new");
        assert_eq!(new, Bytes::from_static(b"new"));

        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn from_runtime_uses_loaded_config() {
        let _lock = lock_failpoints();
        let dir = new_temp_dir().await;
        let config = test_support::base_config("test", dir.clone());
        let store = ChunkStore::from_runtime(&config).expect("store");
        assert_eq!(store.data_dirs(), &[dir.clone()]);
        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn encrypted_payload_requires_encryption_for_reads() {
        let _lock = lock_failpoints();
        let dir = new_temp_dir().await;
        let encrypted = build_encryption("v1", &[("v1", 15)], true);
        let writer = ChunkStore::with_encryption(&[dir.clone()], Some(encrypted)).expect("writer");
        let chunk_id = Uuid::new_v4();
        writer
            .write_chunk(chunk_id, b"secure")
            .await
            .expect("write");
        let plain_reader = ChunkStore::new(&[dir.clone()]).expect("reader");
        let err = plain_reader.read_chunk(chunk_id).await.unwrap_err();
        assert!(err.contains("chunk payload is encrypted but encryption is disabled"));
        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn from_runtime_reports_invalid_encryption_flag() {
        let _lock = lock_failpoints();
        let dir = new_temp_dir().await;
        let _env = EnvVarGuard::set("NSS_CHUNK_ENCRYPTION_ENABLED", "maybe");
        let config = test_support::base_config("test", dir.clone());
        let result = ChunkStore::from_runtime(&config);
        assert!(result.is_err());
        assert!(result
            .err()
            .is_some_and(|err| err.contains("NSS_CHUNK_ENCRYPTION_ENABLED must be true/false")));
        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn write_chunk_reports_encryption_failures() {
        let _lock = lock_failpoints();
        let dir = new_temp_dir().await;
        let _force_error = crate::util::crypto::force_encrypt_error_guard();
        let encryption = build_encryption("v1", &[("v1", 31)], true);
        let store = ChunkStore::with_encryption(&[dir.clone()], Some(encryption)).expect("store");
        let err = store
            .write_chunk(Uuid::new_v4(), b"payload")
            .await
            .unwrap_err();
        assert!(err.contains("encryption failed"));
        let _ = fs::remove_dir_all(&dir).await;
    }
}
