use sqlx::migrate::{MigrateError, Migration, Migrator};
use sqlx::{PgPool, Postgres};
use std::path::PathBuf;
#[cfg(test)]
use std::sync::atomic::{AtomicU8, Ordering};

type PgConn = sqlx::pool::PoolConnection<Postgres>;

#[cfg(test)]
static MIGRATE_FAILPOINT: AtomicU8 = AtomicU8::new(0);

#[cfg(test)]
fn migrate_failpoint(step: u8) -> bool {
    if MIGRATE_FAILPOINT.load(Ordering::SeqCst) == step {
        MIGRATE_FAILPOINT.store(0, Ordering::SeqCst);
        true
    } else {
        false
    }
}

#[cfg(test)]
fn clear_migrate_failpoint() {
    MIGRATE_FAILPOINT.store(0, Ordering::SeqCst);
}

#[cfg(test)]
struct MigrateFailpointGuard;

#[cfg(test)]
impl Drop for MigrateFailpointGuard {
    fn drop(&mut self) {
        clear_migrate_failpoint();
    }
}

#[cfg(test)]
fn migrate_failpoint_guard(step: u8) -> MigrateFailpointGuard {
    MIGRATE_FAILPOINT.store(step, Ordering::SeqCst);
    MigrateFailpointGuard
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), MigrateError> {
    let migrator = load_migrator().await?;
    let mut conn = pool.acquire().await.map_err(MigrateError::Execute)?;
    match migrator.run_direct(&mut *conn).await {
        Ok(()) => Ok(()),
        Err(MigrateError::VersionMismatch(version)) => {
            repair_and_retry(&migrator, &mut conn, version).await
        }
        Err(err) => Err(err),
    }
}

fn migration_directory_candidates() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(raw) = std::env::var("NSS_MIGRATIONS_DIR") {
        if !raw.trim().is_empty() {
            paths.push(PathBuf::from(raw));
        }
    }
    paths.push(PathBuf::from("/app/migrations"));
    paths.push(PathBuf::from("internal/meta/migrations"));
    paths.push(PathBuf::from("meta/migrations"));
    paths
}

pub(crate) async fn load_migrator() -> Result<Migrator, MigrateError> {
    for path in migration_directory_candidates() {
        if path.is_dir() {
            return Migrator::new(path).await;
        }
    }
    let error = std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "migration directory not found",
    );
    Err(MigrateError::Source(Box::new(error)))
}

async fn repair_and_retry(
    migrator: &Migrator,
    conn: &mut PgConn,
    version: i64,
) -> Result<(), MigrateError> {
    if !is_auto_repair_enabled() || version != 4 {
        return Err(MigrateError::VersionMismatch(version));
    }
    release_advisory_locks(conn).await?;
    let migration =
        find_migration(migrator, version).ok_or(MigrateError::VersionNotPresent(version))?;
    tracing::warn!(version, "repairing SQLx migration mismatch");
    apply_migration_sql(conn, migration).await?;
    update_migration_checksum(conn, migration).await?;
    migrator.run_direct(&mut **conn).await
}

fn is_auto_repair_enabled() -> bool {
    std::env::var("NSS_MIGRATION_AUTO_REPAIR")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}

fn find_migration(migrator: &Migrator, version: i64) -> Option<&Migration> {
    migrator.iter().find(|migration| {
        migration.version == version && !migration.migration_type.is_down_migration()
    })
}

async fn release_advisory_locks(conn: &mut PgConn) -> Result<(), MigrateError> {
    #[cfg(test)]
    if migrate_failpoint(1) {
        return Err(MigrateError::Execute(sqlx::Error::Protocol(
            "forced advisory unlock failure".to_string(),
        )));
    }
    sqlx::query("SELECT pg_advisory_unlock_all()")
        .execute(&mut **conn)
        .await
        .map(|_| ())
        .map_err(MigrateError::Execute)
}

async fn apply_migration_sql(conn: &mut PgConn, migration: &Migration) -> Result<(), MigrateError> {
    #[cfg(test)]
    if migrate_failpoint(2) {
        return Err(MigrateError::Execute(sqlx::Error::Protocol(
            "forced apply migration failure".to_string(),
        )));
    }
    sqlx::raw_sql(migration.sql.as_ref())
        .execute(&mut **conn)
        .await
        .map(|_| ())
        .map_err(MigrateError::Execute)
}

async fn update_migration_checksum(
    conn: &mut PgConn,
    migration: &Migration,
) -> Result<(), MigrateError> {
    #[cfg(test)]
    if migrate_failpoint(3) {
        return Err(MigrateError::Execute(sqlx::Error::Protocol(
            "forced checksum update failure".to_string(),
        )));
    }
    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = $2")
        .bind(migration.checksum.as_ref())
        .bind(migration.version)
        .execute(&mut **conn)
        .await
        .map(|_| ())
        .map_err(MigrateError::Execute)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;
    use sqlx::postgres::PgPoolOptions;
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prev = env::var(key).ok();
            env::set_var(key, value);
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(prev) = &self.prev {
                env::set_var(self.key, prev);
            } else {
                env::remove_var(self.key);
            }
        }
    }

    struct CwdGuard {
        prev: PathBuf,
    }

    impl CwdGuard {
        fn set(path: &PathBuf) -> Self {
            let prev = env::current_dir().expect("cwd");
            env::set_current_dir(path).expect("set cwd");
            Self { prev }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            env::set_current_dir(&self.prev).expect("restore cwd");
        }
    }

    fn write_temp_migration(sql: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("nss-migrations-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("0001_bad.sql");
        fs::write(&path, sql).expect("migration");
        dir
    }

    fn write_versioned_migration(version: i64, name: &str, sql: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("nss-migrations-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("dir");
        let filename = format!("{version:04}_{name}.sql");
        fs::write(dir.join(filename), sql).expect("migration");
        dir
    }

    #[test]
    fn migration_directory_candidates_include_non_empty_env() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _env_guard = EnvGuard::set("NSS_MIGRATIONS_DIR", "custom/migrations");
        let candidates = migration_directory_candidates();
        assert!(candidates
            .iter()
            .any(|path| path == &PathBuf::from("custom/migrations")));
    }

    #[tokio::test]
    async fn load_migrator_reports_missing_directory() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _env_guard = EnvGuard::set("NSS_MIGRATIONS_DIR", "");
        let temp = env::temp_dir().join(format!("nss-empty-cwd-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp).expect("temp");
        let _cwd_guard = CwdGuard::set(&temp);
        let err = load_migrator().await.unwrap_err();
        let message = format!("{err:?}");
        assert!(message.starts_with("Source("));
    }

    #[tokio::test]
    async fn run_migrations_succeeds() {
        let pool = test_support::setup_pool().await;
        run_migrations(&pool).await.expect("migrations");
    }

    #[tokio::test]
    async fn run_migrations_fails_with_bad_pool() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://nss:nss@127.0.0.1:1/nss?sslmode=disable")
            .expect("lazy pool");
        let result = run_migrations(&pool).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_migrations_reports_missing_migration_directory() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _env_guard = EnvGuard::set("NSS_MIGRATIONS_DIR", "");
        let temp = env::temp_dir().join(format!("nss-empty-cwd-run-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp).expect("temp");
        let _cwd_guard = CwdGuard::set(&temp);
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://nss:nss@127.0.0.1:1/nss?sslmode=disable")
            .expect("lazy pool");
        let err = run_migrations(&pool).await.unwrap_err();
        assert!(format!("{err:?}").starts_with("Source("));
    }

    #[tokio::test]
    async fn run_migrations_repairs_version_mismatch_for_v4() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _env_guard = EnvGuard::set("NSS_MIGRATION_AUTO_REPAIR", "1");
        let pool = test_support::setup_pool().await;
        run_migrations(&pool).await.expect("migrations");

        sqlx::query(
            "UPDATE _sqlx_migrations SET checksum = decode(repeat('00', 48), 'hex') WHERE version = 4",
        )
            .execute(&pool)
            .await
            .expect("corrupt checksum");

        run_migrations(&pool).await.expect("repair mismatch");

        let migrator = load_migrator().await.expect("migrator");
        let expected = find_migration(&migrator, 4)
            .expect("migration 4")
            .checksum
            .as_ref()
            .to_vec();
        let checksum: Vec<u8> =
            sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = 4")
                .fetch_one(&pool)
                .await
                .expect("checksum");
        assert_eq!(checksum, expected);
    }

    #[tokio::test]
    async fn repair_and_retry_executes_repair_steps_for_v4() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _env_guard = EnvGuard::set("NSS_MIGRATION_AUTO_REPAIR", "true");
        let pool = test_support::setup_pool().await;
        run_migrations(&pool).await.expect("migrations");
        sqlx::query(
            "UPDATE _sqlx_migrations SET checksum = decode(repeat('00', 48), 'hex') WHERE version = 4",
        )
        .execute(&pool)
        .await
        .expect("corrupt checksum");
        let migrator = load_migrator().await.expect("migrator");
        let mut conn = pool.acquire().await.expect("conn");
        repair_and_retry(&migrator, &mut conn, 4)
            .await
            .expect("repair");
    }

    #[tokio::test]
    async fn repair_and_retry_reports_release_lock_error() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _env_guard = EnvGuard::set("NSS_MIGRATION_AUTO_REPAIR", "true");
        let pool = test_support::setup_pool().await;
        let migrator = load_migrator().await.expect("migrator");
        let mut conn = pool.acquire().await.expect("conn");
        let _failpoint = migrate_failpoint_guard(1);
        let err = repair_and_retry(&migrator, &mut conn, 4)
            .await
            .expect_err("release lock error");
        assert!(format!("{err:?}").starts_with("Execute("));
    }

    #[tokio::test]
    async fn repair_and_retry_reports_missing_v4_migration() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _env_guard = EnvGuard::set("NSS_MIGRATION_AUTO_REPAIR", "true");
        let dir = write_versioned_migration(1, "init", "SELECT 1;");
        let dir_guard = EnvGuard::set("NSS_MIGRATIONS_DIR", dir.to_string_lossy().as_ref());
        let pool = test_support::setup_pool().await;
        let migrator = load_migrator().await.expect("migrator");
        let mut conn = pool.acquire().await.expect("conn");
        let err = repair_and_retry(&migrator, &mut conn, 4).await.unwrap_err();
        assert_eq!(format!("{err:?}"), "VersionNotPresent(4)");
        drop(dir_guard);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn repair_and_retry_reports_apply_sql_error() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _env_guard = EnvGuard::set("NSS_MIGRATION_AUTO_REPAIR", "true");
        let pool = test_support::setup_pool().await;
        let migrator = load_migrator().await.expect("migrator");
        let mut conn = pool.acquire().await.expect("conn");
        let _failpoint = migrate_failpoint_guard(2);
        let err = repair_and_retry(&migrator, &mut conn, 4)
            .await
            .expect_err("apply sql error");
        assert!(format!("{err:?}").starts_with("Execute("));
    }

    #[tokio::test]
    async fn repair_and_retry_reports_checksum_update_error() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _env_guard = EnvGuard::set("NSS_MIGRATION_AUTO_REPAIR", "true");
        let pool = test_support::setup_pool().await;
        let migrator = load_migrator().await.expect("migrator");
        let mut conn = pool.acquire().await.expect("conn");
        let _failpoint = migrate_failpoint_guard(3);
        let err = repair_and_retry(&migrator, &mut conn, 4)
            .await
            .expect_err("checksum update error");
        assert!(format!("{err:?}").starts_with("Execute("));
    }

    #[tokio::test]
    async fn run_migrations_returns_non_version_mismatch_errors() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let dir = write_temp_migration("THIS IS INVALID SQL;");
        let dir_guard = EnvGuard::set("NSS_MIGRATIONS_DIR", dir.to_string_lossy().as_ref());
        let pool = test_support::setup_pool().await;
        let err = run_migrations(&pool).await.unwrap_err();
        assert!(!matches!(err, MigrateError::VersionMismatch(_)));
        drop(dir_guard);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn repair_and_retry_rejects_non_v4_versions() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let pool = test_support::setup_pool().await;
        let migrator = load_migrator().await.expect("migrator");
        let mut conn = pool.acquire().await.expect("conn");
        let err = repair_and_retry(&migrator, &mut conn, 7).await.unwrap_err();
        assert_eq!(format!("{err:?}"), "VersionMismatch(7)");
    }

    #[test]
    fn is_auto_repair_enabled_accepts_yes_value() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _env_guard = EnvGuard::set("NSS_MIGRATION_AUTO_REPAIR", "yes");
        assert!(is_auto_repair_enabled());
    }

    #[test]
    fn env_guard_restores_previous_value() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        env::set_var("NSS_MIGRATION_AUTO_REPAIR", "old");
        {
            let _env_guard = EnvGuard::set("NSS_MIGRATION_AUTO_REPAIR", "new");
            assert_eq!(env::var("NSS_MIGRATION_AUTO_REPAIR").expect("set"), "new");
        }
        assert_eq!(
            env::var("NSS_MIGRATION_AUTO_REPAIR").expect("restored"),
            "old"
        );
        env::remove_var("NSS_MIGRATION_AUTO_REPAIR");
    }
}
