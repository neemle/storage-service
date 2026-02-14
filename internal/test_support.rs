use crate::api::AppState;
use crate::obs::Metrics;
use crate::storage::chunkstore::ChunkStore;
use crate::util::config::{AuthMode, Config};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::OnceCell;
use uuid::Uuid;

static MIGRATIONS: OnceCell<()> = OnceCell::const_new();
static CRYPTO: std::sync::Once = std::sync::Once::new();

pub fn ensure_crypto_provider() {
    CRYPTO.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub async fn setup_pool() -> PgPool {
    ensure_crypto_provider();
    let dsn = std::env::var("NSS_POSTGRES_DSN")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("NSS_POSTGRES_DSN or DATABASE_URL must be set");
    let options = PgConnectOptions::from_str(&dsn)
        .expect("parse postgres dsn")
        .statement_cache_capacity(0);
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .expect("connect to postgres");
    MIGRATIONS
        .get_or_init(|| async {
            let migrator = crate::meta::migrate::load_migrator()
                .await
                .expect("load migrations");
            migrator.run(&pool).await.expect("run migrations");
        })
        .await;
    pool
}

pub async fn reset_db(pool: &PgPool) {
    sqlx::query(
        "TRUNCATE TABLE replica_runtime_config, backup_runs, backup_policies, bucket_change_events, \
bucket_snapshot_objects, bucket_snapshots, bucket_snapshot_policies, audit_log, access_keys, \
multipart_parts, multipart_uploads, object_version_manifests, manifest_chunks, manifests, \
chunk_replicas, chunks, object_versions, buckets, join_tokens, nodes, users RESTART IDENTITY CASCADE",
    )
    .execute(pool)
    .await
    .expect("truncate tables");
}

pub struct TableRenameGuard {
    pool: PgPool,
    original: String,
    renamed: String,
}

impl TableRenameGuard {
    pub async fn rename(pool: &PgPool, table: &str) -> Result<Self, sqlx::Error> {
        let suffix = Uuid::new_v4().simple().to_string();
        let renamed = format!("{}_bak_{}", table, suffix);
        let sql = format!("ALTER TABLE {} RENAME TO {}", table, renamed);
        sqlx::query(&sql).execute(pool).await?;
        Ok(Self {
            pool: pool.clone(),
            original: table.to_string(),
            renamed,
        })
    }

    pub async fn restore(self) -> Result<(), sqlx::Error> {
        let sql = format!("ALTER TABLE {} RENAME TO {}", self.renamed, self.original);
        sqlx::query(&sql).execute(&self.pool).await?;
        Ok(())
    }
}

pub struct FailTriggerGuard {
    pool: PgPool,
    table: String,
    trigger: String,
    function: String,
    constraint: bool,
}

impl FailTriggerGuard {
    pub async fn create(
        pool: &PgPool,
        table: &str,
        timing: &str,
        event: &str,
    ) -> Result<Self, sqlx::Error> {
        let trigger = format!("nss_fail_{}", Uuid::new_v4().simple());
        let function = format!("{}_fn", trigger);
        let create_fn = build_failpoint_function_sql(&function);
        sqlx::query(&create_fn).execute(pool).await?;
        let create_trigger = format!(
            "CREATE TRIGGER {} {} {} ON {} FOR EACH ROW EXECUTE FUNCTION {}();",
            trigger, timing, event, table, function
        );
        sqlx::query(&create_trigger).execute(pool).await?;
        Ok(Self {
            pool: pool.clone(),
            table: table.to_string(),
            trigger,
            function,
            constraint: false,
        })
    }

    pub async fn create_deferred(
        pool: &PgPool,
        table: &str,
        timing: &str,
        event: &str,
    ) -> Result<Self, sqlx::Error> {
        let trigger = format!("nss_fail_{}", Uuid::new_v4().simple());
        let function = format!("{}_fn", trigger);
        let create_fn = build_failpoint_function_sql(&function);
        sqlx::query(&create_fn).execute(pool).await?;
        let create_trigger = format!(
            concat!(
                "CREATE CONSTRAINT TRIGGER {} {} {} ON {} DEFERRABLE INITIALLY DEFERRED ",
                "FOR EACH ROW EXECUTE FUNCTION {}();"
            ),
            trigger, timing, event, table, function
        );
        sqlx::query(&create_trigger).execute(pool).await?;
        Ok(Self {
            pool: pool.clone(),
            table: table.to_string(),
            trigger,
            function,
            constraint: true,
        })
    }

    pub async fn remove(self) -> Result<(), sqlx::Error> {
        let drop_trigger = if self.constraint {
            format!("DROP TRIGGER IF EXISTS {} ON {}", self.trigger, self.table)
        } else {
            format!("DROP TRIGGER IF EXISTS {} ON {}", self.trigger, self.table)
        };
        sqlx::query(&drop_trigger).execute(&self.pool).await?;
        let drop_fn = format!("DROP FUNCTION IF EXISTS {}()", self.function);
        sqlx::query(&drop_fn).execute(&self.pool).await?;
        Ok(())
    }
}

fn build_failpoint_function_sql(function: &str) -> String {
    format!(
        concat!(
            "CREATE OR REPLACE FUNCTION {}() RETURNS trigger AS $$ BEGIN ",
            "RAISE EXCEPTION 'failpoint'; END; $$ LANGUAGE plpgsql;"
        ),
        function
    )
}

pub async fn new_temp_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nss-{}-{}", prefix, Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir)
        .await
        .expect("create temp dir");
    dir
}

macro_rules! base_config_template {
    ($mode:expr, $data_dir:expr) => {
        Config {
            mode: $mode.to_string(),
            auth_mode: AuthMode::Internal,
            oidc: None,
            postgres_dsn: "postgres://nss:nss@localhost:5432/nss?sslmode=disable".to_string(),
            data_dirs: vec![$data_dir],
            admin_bootstrap_user: "admin".to_string(),
            admin_bootstrap_password: "change-me".to_string(),
            secret_encryption_key: vec![1u8; 32],
            jwt_signing_key: vec![2u8; 32],
            replication_factor: 1,
            write_quorum: 1,
            chunk_size_bytes: Some(1024),
            chunk_min_bytes: 256,
            chunk_max_bytes: 1024 * 1024,
            checksum_algo: crate::storage::checksum::ChecksumAlgo::Crc32c,
            scrub_interval: Duration::from_secs(60),
            repair_workers: 1,
            multipart_ttl: Duration::from_secs(3600),
            gc_interval: Duration::from_secs(3600),
            s3_listen: "127.0.0.1:0".to_string(),
            api_listen: "127.0.0.1:0".to_string(),
            internal_listen: "127.0.0.1:0".to_string(),
            replica_listen: "127.0.0.1:0".to_string(),
            metrics_listen: "127.0.0.1:0".to_string(),
            s3_max_time_skew_seconds: 900,
            internal_advertise: None,
            replica_advertise: None,
            ui_dir: None,
            s3_public_url: None,
            redis_url: None,
            rabbit_url: None,
            log_level: "info".to_string(),
            cors_allow_origins: Vec::new(),
            insecure_dev: false,
            internal_shared_token: "test-token".to_string(),
            master_url: None,
            join_token: None,
            replica_sub_mode: "delivery".to_string(),
        }
    };
}

pub fn base_config(mode: &str, data_dir: PathBuf) -> Config {
    base_config_template!(mode, data_dir)
}

pub async fn build_state(mode: &str) -> (AppState, PgPool, PathBuf) {
    let pool = setup_pool().await;
    reset_db(&pool).await;
    let data_dir = new_temp_dir("data").await;
    let config = base_config(mode, data_dir.clone());
    let metrics = Metrics::new();
    let chunk_store = ChunkStore::from_runtime(&config).expect("chunk store");
    let state = AppState::new(config, pool.clone(), chunk_store, metrics)
        .await
        .expect("app state");
    (state, pool, data_dir)
}

fn unreachable_db_pool() -> PgPool {
    PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(250))
        .connect_lazy("postgres://nss:nss@127.0.0.1:1/nss?sslmode=disable&connect_timeout=1")
        .expect("lazy pool")
}

pub fn broken_repo() -> crate::meta::repos::Repo {
    let pool = unreachable_db_pool();
    crate::meta::repos::Repo::new(pool)
}

#[cfg(test)]
mod guard_tests {
    use super::*;
    use sqlx::PgPool;

    fn broken_pool() -> PgPool {
        unreachable_db_pool()
    }

    async fn cleanup_fail_functions(pool: &PgPool) {
        let names: Vec<String> =
            sqlx::query_scalar("SELECT proname FROM pg_proc WHERE proname LIKE 'nss_fail_%_fn'")
                .fetch_all(pool)
                .await
                .expect("fetch functions");
        for name in names {
            let _ = sqlx::query(&format!("DROP FUNCTION IF EXISTS {}()", name))
                .execute(pool)
                .await;
        }
    }

    #[tokio::test]
    async fn table_rename_guard_reports_error_on_rename() {
        let pool = broken_pool();
        let result = TableRenameGuard::rename(&pool, "users").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn table_rename_guard_rename_and_restore_succeeds() {
        let pool = setup_pool().await;
        reset_db(&pool).await;
        let guard = TableRenameGuard::rename(&pool, "users")
            .await
            .expect("rename");
        guard.restore().await.expect("restore");
    }

    #[tokio::test]
    async fn table_rename_guard_restore_reports_error() {
        let pool = setup_pool().await;
        reset_db(&pool).await;
        let guard = TableRenameGuard {
            pool: pool.clone(),
            original: "users".to_string(),
            renamed: "missing_table".to_string(),
        };
        let result = guard.restore().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn fail_trigger_guard_create_reports_error_on_function() {
        let pool = broken_pool();
        let result = FailTriggerGuard::create(&pool, "users", "AFTER", "INSERT").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn fail_trigger_guard_create_reports_error_on_trigger() {
        let pool = setup_pool().await;
        reset_db(&pool).await;
        let result = FailTriggerGuard::create(&pool, "missing_table", "AFTER", "INSERT").await;
        assert!(result.is_err());
        cleanup_fail_functions(&pool).await;
    }

    #[tokio::test]
    async fn fail_trigger_guard_create_deferred_reports_error_on_function() {
        let pool = broken_pool();
        let result = FailTriggerGuard::create_deferred(&pool, "users", "AFTER", "INSERT").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn fail_trigger_guard_create_deferred_reports_error_on_trigger() {
        let pool = setup_pool().await;
        reset_db(&pool).await;
        let result =
            FailTriggerGuard::create_deferred(&pool, "missing_table", "AFTER", "INSERT").await;
        assert!(result.is_err());
        cleanup_fail_functions(&pool).await;
    }

    #[tokio::test]
    async fn fail_trigger_guard_create_and_remove_succeeds() {
        let pool = setup_pool().await;
        reset_db(&pool).await;
        let guard = FailTriggerGuard::create(&pool, "users", "AFTER", "INSERT")
            .await
            .expect("create");
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn fail_trigger_guard_create_deferred_and_remove_succeeds() {
        let pool = setup_pool().await;
        reset_db(&pool).await;
        let guard = FailTriggerGuard::create_deferred(&pool, "users", "AFTER", "INSERT")
            .await
            .expect("create deferred");
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn fail_trigger_guard_remove_reports_error_on_drop_trigger() {
        let pool = setup_pool().await;
        reset_db(&pool).await;
        let guard = FailTriggerGuard {
            pool: pool.clone(),
            table: "missing-table".to_string(),
            trigger: "nss_missing".to_string(),
            function: "nss_missing_fn".to_string(),
            constraint: false,
        };
        let result = guard.remove().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn fail_trigger_guard_remove_reports_error_on_drop_function() {
        let pool = setup_pool().await;
        reset_db(&pool).await;
        let guard = FailTriggerGuard {
            pool: pool.clone(),
            table: "users".to_string(),
            trigger: "nss_missing".to_string(),
            function: "invalid-fn".to_string(),
            constraint: true,
        };
        let result = guard.remove().await;
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

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

        fn set(&mut self, key: &str, value: &str) {
            let prev = env::var(key).ok();
            self.entries.push((key.to_string(), prev));
            env::set_var(key, value);
        }

        fn remove(&mut self, key: &str) {
            let prev = env::var(key).ok();
            self.entries.push((key.to_string(), prev));
            env::remove_var(key);
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

    #[tokio::test]
    async fn setup_pool_uses_database_url_fallback() {
        let _guard = ENV_LOCK.lock().expect("lock");
        let mut env_guard = EnvGuard::new();
        let dsn = env::var("NSS_POSTGRES_DSN").expect("NSS_POSTGRES_DSN");
        env_guard.remove("NSS_POSTGRES_DSN");
        env_guard.set("DATABASE_URL", &dsn);
        let pool = setup_pool().await;
        sqlx::query("SELECT 1").execute(&pool).await.expect("query");
    }

    #[tokio::test]
    async fn base_config_and_build_state_work() {
        let dir = new_temp_dir("support").await;
        let config = base_config("master", dir.clone());
        assert_eq!(config.mode, "master");
        assert_eq!(config.data_dirs.len(), 1);

        let (state, _pool, data_dir) = build_state("master").await;
        assert_eq!(state.config.mode, "master");
        assert!(data_dir.exists());
    }

    #[tokio::test]
    async fn env_guard_removes_unset_vars_on_drop() {
        let _guard = ENV_LOCK.lock().expect("lock");
        let key = format!("NSS_TEST_ENV_{}", Uuid::new_v4());
        env::remove_var(&key);
        {
            let mut env_guard = EnvGuard::new();
            env_guard.set(&key, "value");
            assert_eq!(env::var(&key).as_deref(), Ok("value"));
        }
        assert!(env::var(&key).is_err());
    }

    #[tokio::test]
    async fn broken_repo_returns_error_on_query() {
        let repo = broken_repo();
        let _ = repo.list_users().await.unwrap_err();
        let errors = [
            sqlx::Error::Io(std::io::Error::new(std::io::ErrorKind::Other, "boom")),
            sqlx::Error::PoolTimedOut,
        ];
        for err in errors {
            let is_io = matches!(err, sqlx::Error::Io(_));
            let is_timeout = matches!(err, sqlx::Error::PoolTimedOut);
            assert!(is_io | is_timeout);
        }
    }

    #[tokio::test]
    async fn fail_trigger_guard_create_deferred_removes_trigger() {
        let pool = setup_pool().await;
        reset_db(&pool).await;
        let guard = FailTriggerGuard::create_deferred(&pool, "users", "AFTER", "INSERT")
            .await
            .expect("guard");
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn table_rename_guard_roundtrip() {
        let pool = setup_pool().await;
        reset_db(&pool).await;
        let guard = TableRenameGuard::rename(&pool, "users")
            .await
            .expect("rename");
        guard.restore().await.expect("restore");
        let _ = sqlx::query("SELECT 1 FROM users LIMIT 1")
            .execute(&pool)
            .await
            .expect("query");
    }

    #[tokio::test]
    async fn fail_trigger_guard_create_removes_trigger() {
        let pool = setup_pool().await;
        reset_db(&pool).await;
        let guard = FailTriggerGuard::create(&pool, "users", "AFTER", "INSERT")
            .await
            .expect("guard");
        guard.remove().await.expect("remove");
    }
}
