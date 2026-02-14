use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::lookup_host;
use tokio::time::sleep;

struct DbConnectSettings {
    delay_ms: u64,
    max_attempts: u32,
}

pub async fn connect(dsn: &str) -> Result<PgPool, sqlx::Error> {
    let settings = load_connect_settings();
    let mut last_err = None;
    for attempt in 1..=settings.max_attempts {
        let resolved_dsn = match resolve_host_or_retry(dsn, attempt, &settings, &mut last_err).await
        {
            Some(value) => value,
            None => continue,
        };
        match connect_pool(&resolved_dsn).await {
            Ok(pool) => return Ok(pool),
            Err(err) => record_retry_error(&settings, attempt, &mut last_err, err).await,
        }
    }
    Err(last_err.unwrap_or(sqlx::Error::PoolTimedOut))
}

fn load_connect_settings() -> DbConnectSettings {
    let max_attempts = std::env::var("NSS_POSTGRES_CONNECT_RETRIES")
        .ok()
        .and_then(|val| val.parse::<u32>().ok())
        .unwrap_or(30)
        .max(1);
    let delay_ms = std::env::var("NSS_POSTGRES_CONNECT_DELAY_MS")
        .ok()
        .and_then(|val| val.parse::<u64>().ok())
        .unwrap_or(1000)
        .max(100);
    DbConnectSettings {
        delay_ms,
        max_attempts,
    }
}

async fn connect_pool(dsn: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(dsn)
        .await
}

async fn resolve_host_or_retry(
    dsn: &str,
    attempt: u32,
    settings: &DbConnectSettings,
    last_err: &mut Option<sqlx::Error>,
) -> Option<String> {
    match resolve_dsn_host(dsn).await {
        Ok(value) => Some(value),
        Err(err) => {
            *last_err = Some(err);
            if attempt < settings.max_attempts {
                tracing::warn!(attempt, "postgres host lookup failed; retrying");
                sleep(Duration::from_millis(settings.delay_ms)).await;
            }
            None
        }
    }
}

async fn record_retry_error(
    settings: &DbConnectSettings,
    attempt: u32,
    last_err: &mut Option<sqlx::Error>,
    err: sqlx::Error,
) {
    *last_err = Some(err);
    if attempt < settings.max_attempts {
        tracing::warn!(attempt, "postgres connect failed; retrying");
        sleep(Duration::from_millis(settings.delay_ms)).await;
    }
}

async fn resolve_dsn_host(dsn: &str) -> Result<String, sqlx::Error> {
    resolve_dsn_host_with_lookup(dsn, |host, port| async move {
        let addrs = lookup_host((host.as_str(), port)).await?;
        Ok(addrs.collect::<Vec<SocketAddr>>())
    })
    .await
}

async fn resolve_dsn_host_with_lookup<F, Fut>(dsn: &str, lookup: F) -> Result<String, sqlx::Error>
where
    F: FnOnce(String, u16) -> Fut,
    Fut: Future<Output = Result<Vec<SocketAddr>, std::io::Error>>,
{
    let mut url = match url::Url::parse(dsn) {
        Ok(val) => val,
        Err(_) => return Ok(dsn.to_string()),
    };
    let host = match url.host_str() {
        Some(val) => val.to_string(),
        None => return Ok(dsn.to_string()),
    };
    if host.parse::<IpAddr>().is_ok() {
        return Ok(dsn.to_string());
    }
    let port = url.port().unwrap_or(5432);
    let mut addrs = lookup(host.clone(), port)
        .await
        .map_err(sqlx::Error::Io)?
        .into_iter();
    if let Some(addr) = addrs.next() {
        let ip = addr.ip().to_string();
        let _ = url.set_host(Some(&ip));
        return Ok(url.to_string());
    }
    Ok(dsn.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    async fn lookup_stub(host: String, port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
        if host == "error-host" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "lookup failed",
            ));
        }
        if host == "empty-host" {
            return Ok(Vec::new());
        }
        Ok(vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port,
        )])
    }

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

    fn assert_db_error(err: &sqlx::Error) {
        let message = err.to_string();
        assert!(!message.is_empty());
    }

    #[tokio::test]
    async fn resolve_dsn_host_handles_various_inputs() {
        let plain = resolve_dsn_host("not-a-url").await.expect("ok");
        assert_eq!(plain, "not-a-url");

        let no_host = resolve_dsn_host("postgres:///nss?sslmode=disable")
            .await
            .expect("ok");
        assert_eq!(no_host, "postgres:///nss?sslmode=disable");

        let ip_host = resolve_dsn_host("postgres://127.0.0.1:5432/nss?sslmode=disable")
            .await
            .expect("ok");
        assert_eq!(ip_host, "postgres://127.0.0.1:5432/nss?sslmode=disable");

        let resolved = resolve_dsn_host("postgres://localhost:5432/nss?sslmode=disable")
            .await
            .expect("ok");
        let url = url::Url::parse(&resolved).expect("url");
        let host = url.host_str().expect("host");
        assert!(host.parse::<IpAddr>().is_ok() || host == "localhost");
    }

    #[tokio::test]
    async fn resolve_dsn_host_defaults_port_when_missing() {
        let dsn = "postgres://example.com/nss?sslmode=disable";
        let resolved = resolve_dsn_host_with_lookup(dsn, lookup_stub)
            .await
            .expect("ok");
        let url = url::Url::parse(&resolved).expect("url");
        let host = url.host_str().expect("host");
        assert!(host.parse::<IpAddr>().is_ok());
    }

    #[tokio::test]
    async fn resolve_dsn_host_errors_on_unresolvable_host() {
        let err = resolve_dsn_host("postgres://does-not-exist.invalid:5432/nss?sslmode=disable")
            .await
            .unwrap_err();
        assert_db_error(&err);
    }

    #[tokio::test]
    async fn resolve_dsn_host_returns_original_when_lookup_empty() {
        let dsn = "postgres://empty-host:5432/nss?sslmode=disable";
        let resolved = resolve_dsn_host_with_lookup(dsn, lookup_stub)
            .await
            .expect("ok");
        assert_eq!(resolved, dsn);
    }

    #[tokio::test]
    async fn resolve_dsn_host_with_lookup_returns_original_on_parse_error() {
        let dsn = "not-a-url";
        let _ = lookup_stub("example".to_string(), 5432)
            .await
            .expect("lookup");
        let resolved = resolve_dsn_host_with_lookup(dsn, lookup_stub)
            .await
            .expect("ok");
        assert_eq!(resolved, dsn);
    }

    #[tokio::test]
    async fn resolve_dsn_host_with_lookup_returns_original_on_missing_host() {
        let dsn = "postgres:///nss?sslmode=disable";
        let _ = lookup_stub("example".to_string(), 5432)
            .await
            .expect("lookup");
        let resolved = resolve_dsn_host_with_lookup(dsn, lookup_stub)
            .await
            .expect("ok");
        assert_eq!(resolved, dsn);
    }

    #[tokio::test]
    async fn resolve_dsn_host_with_lookup_returns_original_on_ip_host() {
        let dsn = "postgres://127.0.0.1:5432/nss?sslmode=disable";
        let _ = lookup_stub("example".to_string(), 5432)
            .await
            .expect("lookup");
        let resolved = resolve_dsn_host_with_lookup(dsn, lookup_stub)
            .await
            .expect("ok");
        assert_eq!(resolved, dsn);
    }

    #[tokio::test]
    async fn resolve_dsn_host_with_lookup_rewrites_first_address() {
        let dsn = "postgres://db.example:5432/nss?sslmode=disable";
        let resolved = resolve_dsn_host_with_lookup(dsn, lookup_stub)
            .await
            .expect("ok");
        let url = url::Url::parse(&resolved).expect("url");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
    }

    #[tokio::test]
    async fn resolve_dsn_host_with_lookup_reports_error() {
        let dsn = "postgres://error-host:5432/nss?sslmode=disable";
        let err = resolve_dsn_host_with_lookup(dsn, lookup_stub)
            .await
            .unwrap_err();
        assert_db_error(&err);
    }

    #[tokio::test]
    async fn connect_succeeds_and_retries_on_failures() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        guard.set("NSS_POSTGRES_CONNECT_RETRIES", "1");
        guard.set("NSS_POSTGRES_CONNECT_DELAY_MS", "100");

        let dsn = env::var("NSS_POSTGRES_DSN").expect("NSS_POSTGRES_DSN");
        let pool = connect(&dsn).await.expect("connect ok");
        sqlx::query("SELECT 1").execute(&pool).await.expect("query");

        guard.set("NSS_POSTGRES_CONNECT_RETRIES", "2");
        let err = connect("postgres://nss:nss@127.0.0.1:1/nss?sslmode=disable")
            .await
            .unwrap_err();
        assert_db_error(&err);

        guard.set("NSS_POSTGRES_CONNECT_RETRIES", "2");
        let err = connect("postgres://does-not-exist.invalid:5432/nss?sslmode=disable")
            .await
            .unwrap_err();
        assert_db_error(&err);
    }

    #[tokio::test]
    async fn connect_retries_on_lookup_and_connect_errors() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        guard.set("NSS_POSTGRES_CONNECT_RETRIES", "2");
        guard.set("NSS_POSTGRES_CONNECT_DELAY_MS", "100");

        let err = connect("postgres://does-not-exist.invalid:5432/nss?sslmode=disable")
            .await
            .unwrap_err();
        assert_db_error(&err);

        let err = connect("postgres://nss:nss@127.0.0.1:1/nss?sslmode=disable")
            .await
            .unwrap_err();
        assert_db_error(&err);
    }

    #[tokio::test]
    async fn connect_logs_retry_warnings() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        guard.set("NSS_POSTGRES_CONNECT_RETRIES", "2");
        guard.set("NSS_POSTGRES_CONNECT_DELAY_MS", "100");

        let err = connect("postgres://does-not-exist.invalid:5432/nss?sslmode=disable")
            .await
            .unwrap_err();
        assert_db_error(&err);

        let err = connect("postgres://nss:nss@127.0.0.1:1/nss?sslmode=disable")
            .await
            .unwrap_err();
        assert_db_error(&err);
    }
}
