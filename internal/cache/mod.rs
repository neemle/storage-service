use dashmap::DashMap;
use redis::AsyncCommands;
#[cfg(test)]
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[cfg(test)]
static REDIS_FAILPOINT: AtomicU8 = AtomicU8::new(0);

#[cfg(test)]
fn redis_failpoint(step: u8) -> bool {
    if REDIS_FAILPOINT.load(Ordering::SeqCst) == step {
        REDIS_FAILPOINT.store(0, Ordering::SeqCst);
        true
    } else {
        false
    }
}

#[cfg(test)]
pub fn set_redis_failpoint(step: u8) {
    REDIS_FAILPOINT.store(step, Ordering::SeqCst);
}

#[cfg(test)]
pub fn clear_redis_failpoint() {
    REDIS_FAILPOINT.store(0, Ordering::SeqCst);
}

#[cfg(test)]
pub struct RedisFailpointGuard;

#[cfg(test)]
impl Drop for RedisFailpointGuard {
    fn drop(&mut self) {
        clear_redis_failpoint();
    }
}

#[cfg(test)]
pub fn redis_failpoint_guard(step: u8) -> RedisFailpointGuard {
    set_redis_failpoint(step);
    RedisFailpointGuard
}

#[derive(Clone)]
pub enum CacheStore {
    Memory(MemoryCache),
    Redis(RedisCache),
}

impl CacheStore {
    pub async fn new(redis_url: Option<&str>) -> Result<Self, String> {
        if let Some(url) = redis_url {
            let cache = RedisCache::new(url).await?;
            Ok(CacheStore::Redis(cache))
        } else {
            Ok(CacheStore::Memory(MemoryCache::new()))
        }
    }

    pub async fn get(&self, key: &str) -> Option<String> {
        match self {
            CacheStore::Memory(cache) => cache.get(key),
            CacheStore::Redis(cache) => cache.get(key).await,
        }
    }

    pub async fn set(&self, key: &str, value: &str, ttl_seconds: i64) -> Result<(), String> {
        match self {
            CacheStore::Memory(cache) => {
                cache.set(key, value, ttl_seconds);
                Ok(())
            }
            CacheStore::Redis(cache) => cache.set(key, value, ttl_seconds).await,
        }
    }

    pub async fn incr(&self, key: &str, ttl_seconds: i64) -> Result<i64, String> {
        match self {
            CacheStore::Memory(cache) => Ok(cache.incr(key, ttl_seconds)),
            CacheStore::Redis(cache) => cache.incr(key, ttl_seconds).await,
        }
    }
}

#[derive(Clone)]
pub struct MemoryCache {
    values: Arc<DashMap<String, MemoryEntry>>,
    counters: Arc<DashMap<String, CounterEntry>>,
}

#[derive(Clone)]
struct MemoryEntry {
    value: String,
    expires_at: Instant,
}

#[derive(Clone)]
struct CounterEntry {
    count: i64,
    expires_at: Instant,
}

impl Default for MemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryCache {
    pub fn new() -> Self {
        Self {
            values: Arc::new(DashMap::new()),
            counters: Arc::new(DashMap::new()),
        }
    }

    pub fn get(&self, key: &str) -> Option<String> {
        if let Some(entry) = self.values.get(key) {
            if Instant::now() <= entry.expires_at {
                return Some(entry.value.clone());
            }
        }
        self.values.remove(key);
        None
    }

    pub fn set(&self, key: &str, value: &str, ttl_seconds: i64) {
        let expires_at = Instant::now() + Duration::from_secs(ttl_seconds as u64);
        self.values.insert(
            key.to_string(),
            MemoryEntry {
                value: value.to_string(),
                expires_at,
            },
        );
    }

    pub fn incr(&self, key: &str, ttl_seconds: i64) -> i64 {
        let now = Instant::now();
        let expires_at = now + Duration::from_secs(ttl_seconds as u64);
        if let Some(mut entry) = self.counters.get_mut(key) {
            if now > entry.expires_at {
                entry.count = 1;
                entry.expires_at = expires_at;
                return entry.count;
            }
            entry.count += 1;
            return entry.count;
        }
        self.counters.insert(
            key.to_string(),
            CounterEntry {
                count: 1,
                expires_at,
            },
        );
        1
    }
}

#[derive(Clone)]
pub struct RedisCache {
    connection: Arc<Mutex<redis::aio::ConnectionManager>>,
}

impl RedisCache {
    pub async fn new(url: &str) -> Result<Self, String> {
        let client = redis::Client::open(url).map_err(|err| format!("redis error: {err}"))?;
        let manager = redis::aio::ConnectionManager::new(client)
            .await
            .map_err(|err| format!("redis connect failed: {err}"))?;
        Ok(Self {
            connection: Arc::new(Mutex::new(manager)),
        })
    }

    pub async fn get(&self, key: &str) -> Option<String> {
        let mut conn = self.connection.lock().await;
        conn.get(key).await.ok().flatten()
    }

    pub async fn set(&self, key: &str, value: &str, ttl_seconds: i64) -> Result<(), String> {
        let mut conn = self.connection.lock().await;
        let result = {
            #[cfg(test)]
            {
                if redis_failpoint(1) {
                    Err(redis::RedisError::from((redis::ErrorKind::Io, "failpoint")))
                } else {
                    conn.set_ex::<_, _, ()>(key, value, ttl_seconds as u64)
                        .await
                }
            }
            #[cfg(not(test))]
            {
                conn.set_ex::<_, _, ()>(key, value, ttl_seconds as u64)
                    .await
            }
        };
        result.map_err(|err| format!("redis set failed: {err}"))?;
        Ok(())
    }

    pub async fn incr(&self, key: &str, ttl_seconds: i64) -> Result<i64, String> {
        let mut conn = self.connection.lock().await;
        let count_result = {
            #[cfg(test)]
            {
                if redis_failpoint(2) {
                    Err(redis::RedisError::from((redis::ErrorKind::Io, "failpoint")))
                } else {
                    conn.incr(key, 1).await
                }
            }
            #[cfg(not(test))]
            {
                conn.incr(key, 1).await
            }
        };
        let count: i64 = count_result.map_err(|err| format!("redis incr failed: {err}"))?;
        let _: Result<(), _> = conn.expire(key, ttl_seconds).await;
        Ok(count)
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    cache: CacheStore,
}

impl RateLimiter {
    pub fn new(cache: CacheStore) -> Self {
        Self { cache }
    }

    pub async fn register_failure(
        &self,
        key: &str,
        limit: i64,
        window_seconds: i64,
    ) -> Result<bool, String> {
        let count = self.cache.incr(key, window_seconds).await?;
        Ok(count <= limit)
    }
}

#[cfg(test)]
mod tests {
    use super::{redis_failpoint_guard, CacheStore, MemoryCache, RateLimiter, RedisCache};
    use std::env;
    use std::sync::Mutex;
    use tokio::time::{sleep, Duration};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        entries: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn new() -> Self {
            Self {
                entries: Vec::new(),
            }
        }

        fn remove(&mut self, key: &str) {
            let prev = env::var(key).ok();
            self.entries.push((key.to_string(), prev));
            env::remove_var(key);
        }

        fn set(&mut self, key: &str, value: &str) {
            let prev = env::var(key).ok();
            self.entries.push((key.to_string(), prev));
            env::set_var(key, value);
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.entries.drain(..).rev() {
                if let Some(val) = value {
                    env::set_var(key, val);
                } else {
                    env::remove_var(key);
                }
            }
        }
    }

    fn redis_url() -> String {
        std::env::var("NSS_REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string())
    }
    #[tokio::test]
    async fn memory_cache_set_get_and_expire() {
        let cache = MemoryCache::new();
        assert!(cache.get("missing").is_none());
        cache.set("alpha", "one", 1);
        assert_eq!(cache.get("alpha"), Some("one".to_string()));
        sleep(Duration::from_secs(2)).await;
        assert!(cache.get("alpha").is_none());
    }

    #[tokio::test]
    async fn memory_cache_incr_resets_after_ttl() {
        let cache = MemoryCache::new();
        let first = cache.incr("counter", 1);
        let second = cache.incr("counter", 1);
        assert_eq!(first, 1);
        assert_eq!(second, 2);
        sleep(Duration::from_secs(2)).await;
        let reset = cache.incr("counter", 1);
        assert_eq!(reset, 1);
    }

    #[test]
    fn memory_cache_default_matches_new() {
        let cache = MemoryCache::default();
        assert!(cache.get("missing").is_none());
    }

    #[tokio::test]
    async fn cache_store_memory_paths() {
        let store = CacheStore::Memory(MemoryCache::new());
        assert!(store.get("alpha").await.is_none());
        store.set("alpha", "one", 1).await.expect("set");
        assert_eq!(store.get("alpha").await, Some("one".to_string()));
        let count = store.incr("failures", 1).await.expect("incr");
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn cache_store_redis_roundtrip() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        guard.remove("NSS_REDIS_URL");
        let url = redis_url();
        let store = CacheStore::new(Some(url.as_str()))
            .await
            .expect("redis store");
        store.set("store-key", "value", 30).await.expect("set");
        let value = store.get("store-key").await;
        assert_eq!(value, Some("value".to_string()));
        let count = store.incr("store-count", 30).await.expect("incr");
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn rate_limiter_blocks_after_limit() {
        let store = CacheStore::Memory(MemoryCache::new());
        let limiter = RateLimiter::new(store);
        let ok = limiter.register_failure("key", 2, 60).await.expect("limit");
        assert!(ok);
        let ok = limiter.register_failure("key", 2, 60).await.expect("limit");
        assert!(ok);
        let blocked = limiter.register_failure("key", 2, 60).await.expect("limit");
        assert!(!blocked);
    }

    #[tokio::test]
    async fn redis_cache_roundtrip() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        guard.remove("NSS_REDIS_URL");
        let url = redis_url();
        let cache = RedisCache::new(&url).await.expect("redis cache");
        cache.set("redis-key", "value", 60).await.expect("set");
        let value = cache.get("redis-key").await;
        assert_eq!(value, Some("value".to_string()));
        let first = cache.incr("redis-counter", 60).await.expect("incr");
        let second = cache.incr("redis-counter", 60).await.expect("incr");
        assert_eq!(first, 1);
        assert_eq!(second, 2);
    }

    #[tokio::test]
    async fn redis_cache_invalid_url_errors() {
        let result = RedisCache::new("redis://127.0.0.1:1").await;
        let err = result.err().expect("err");
        let has_connect = err.contains("redis connect failed");
        let has_error = err.contains("redis error");
        assert!(has_connect | has_error);
        let result = RedisCache::new("redis://127.0.0.1:bad").await;
        let err = result.err().expect("err");
        assert!(err.contains("redis error"));
    }

    #[tokio::test]
    async fn redis_cache_failpoints_report_errors() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        guard.remove("NSS_REDIS_URL");
        let url = redis_url();
        let cache = RedisCache::new(&url).await.expect("redis cache");

        let _guard = redis_failpoint_guard(1);
        let err = cache.set("fail-key", "value", 5).await.unwrap_err();
        assert!(err.contains("redis set failed"));

        let _guard = redis_failpoint_guard(2);
        let err = cache.incr("fail-count", 5).await.unwrap_err();
        assert!(err.contains("redis incr failed"));
    }

    #[tokio::test]
    async fn cache_store_redis_uses_env_override() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        guard.set("NSS_REDIS_URL", "redis://redis:6379");
        let url = redis_url();
        let store = CacheStore::new(Some(url.as_str()))
            .await
            .expect("redis store");
        let _ = store.get("env-key").await;
    }

    #[tokio::test]
    async fn rate_limiter_reports_cache_errors() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        guard.remove("NSS_REDIS_URL");
        let url = redis_url();
        let cache = RedisCache::new(&url).await.expect("redis cache");
        let limiter = RateLimiter::new(CacheStore::Redis(cache));
        let _guard = redis_failpoint_guard(2);
        let err = limiter
            .register_failure("limit-key", 1, 60)
            .await
            .unwrap_err();
        assert!(err.contains("redis incr failed"));
    }

    #[test]
    fn env_guard_removes_missing_var_on_drop() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let key = "NSS_TEST_REDIS_ENV";
        env::remove_var(key);
        {
            let mut guard = EnvGuard::new();
            guard.remove(key);
        }
        assert!(env::var(key).is_err());
    }

    #[test]
    fn redis_failpoint_consumes_step() {
        super::set_redis_failpoint(9);
        assert!(super::redis_failpoint(9));
        assert!(!super::redis_failpoint(9));
    }
}
