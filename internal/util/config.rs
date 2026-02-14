use crate::storage::checksum::ChecksumAlgo;
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Internal,
    Oidc,
    Oauth2,
    Saml2,
}

impl AuthMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::Oidc => "oidc",
            Self::Oauth2 => "oauth2",
            Self::Saml2 => "saml2",
        }
    }

    pub fn uses_external_identity(self) -> bool {
        self != Self::Internal
    }
}

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_url: String,
    pub scopes: String,
    pub username_claim: String,
    pub display_name_claim: String,
    pub groups_claim: String,
    pub admin_groups: Vec<String>,
    pub audience: String,
}

#[derive(Clone)]
pub struct Config {
    pub mode: String,
    pub auth_mode: AuthMode,
    pub oidc: Option<OidcConfig>,
    pub postgres_dsn: String,
    pub data_dirs: Vec<PathBuf>,
    pub admin_bootstrap_user: String,
    pub admin_bootstrap_password: String,
    pub secret_encryption_key: Vec<u8>,
    pub jwt_signing_key: Vec<u8>,
    pub replication_factor: u32,
    pub write_quorum: u32,
    pub chunk_size_bytes: Option<u64>,
    pub chunk_min_bytes: u64,
    pub chunk_max_bytes: u64,
    pub checksum_algo: ChecksumAlgo,
    pub scrub_interval: Duration,
    pub repair_workers: usize,
    pub multipart_ttl: Duration,
    pub gc_interval: Duration,
    pub s3_listen: String,
    pub api_listen: String,
    pub internal_listen: String,
    pub replica_listen: String,
    pub metrics_listen: String,
    pub s3_max_time_skew_seconds: i64,
    pub internal_advertise: Option<String>,
    pub replica_advertise: Option<String>,
    pub ui_dir: Option<String>,
    pub s3_public_url: Option<String>,
    pub redis_url: Option<String>,
    pub rabbit_url: Option<String>,
    pub log_level: String,
    pub cors_allow_origins: Vec<String>,
    pub insecure_dev: bool,
    pub internal_shared_token: String,
    pub master_url: Option<String>,
    pub join_token: Option<String>,
    pub replica_sub_mode: String,
}

macro_rules! config_from_parts {
    ($req:expr, $storage:expr, $listen:expr, $runtime:expr, $auth:expr) => {
        Self {
            mode: $req.mode,
            auth_mode: $auth.mode,
            oidc: $auth.oidc,
            postgres_dsn: $req.postgres_dsn,
            data_dirs: $req.data_dirs,
            admin_bootstrap_user: $req.admin_bootstrap_user,
            admin_bootstrap_password: $req.admin_bootstrap_password,
            secret_encryption_key: $req.secret_encryption_key,
            jwt_signing_key: $req.jwt_signing_key,
            replication_factor: $storage.replication_factor,
            write_quorum: $storage.write_quorum,
            chunk_size_bytes: $storage.chunk_size_bytes,
            chunk_min_bytes: $storage.chunk_min_bytes,
            chunk_max_bytes: $storage.chunk_max_bytes,
            checksum_algo: $storage.checksum_algo,
            scrub_interval: $storage.scrub_interval,
            repair_workers: $storage.repair_workers,
            multipart_ttl: $storage.multipart_ttl,
            gc_interval: $storage.gc_interval,
            s3_listen: $listen.s3_listen,
            api_listen: $listen.api_listen,
            internal_listen: $listen.internal_listen,
            replica_listen: $listen.replica_listen,
            metrics_listen: $listen.metrics_listen,
            s3_max_time_skew_seconds: $listen.s3_max_time_skew_seconds,
            internal_advertise: $listen.internal_advertise,
            replica_advertise: $listen.replica_advertise,
            ui_dir: $listen.ui_dir,
            s3_public_url: $runtime.s3_public_url,
            redis_url: $runtime.redis_url,
            rabbit_url: $runtime.rabbit_url,
            log_level: $runtime.log_level,
            cors_allow_origins: $runtime.cors_allow_origins,
            insecure_dev: $runtime.insecure_dev,
            internal_shared_token: $req.internal_shared_token,
            master_url: $req.master_url,
            join_token: $req.join_token,
            replica_sub_mode: $runtime.replica_sub_mode,
        }
    };
}

impl Config {
    pub fn load() -> Result<Self, String> {
        let required = RequiredConfig::from_env()?;
        let storage = StorageConfig::from_env();
        let listen = ListenConfig::from_env();
        let runtime = RuntimeConfig::from_env();
        let auth = AuthConfig::from_env()?;
        let config = Self::from_parts(required, storage, listen, runtime, auth);
        config.validate_security()?;
        Ok(config)
    }

    fn from_parts(
        req: RequiredConfig,
        storage: StorageConfig,
        listen: ListenConfig,
        runtime: RuntimeConfig,
        auth: AuthConfig,
    ) -> Self {
        config_from_parts!(req, storage, listen, runtime, auth)
    }

    fn validate_security(&self) -> Result<(), String> {
        if !matches!(self.replica_sub_mode.as_str(), "delivery" | "backup") {
            return Err("NSS_REPLICA_SUB_MODE must be delivery or backup".into());
        }
        validate_external_auth_config(self.auth_mode, self.oidc.as_ref())?;
        if self.insecure_dev || self.mode == "test" {
            return Ok(());
        }
        validate_required_secret("NSS_INTERNAL_SHARED_TOKEN", &self.internal_shared_token)?;
        if self.mode == "master" {
            validate_required_secret(
                "NSS_ADMIN_BOOTSTRAP_PASSWORD",
                &self.admin_bootstrap_password,
            )?;
        }
        if self.cors_allow_origins.iter().any(|origin| origin == "*") {
            return Err(
                "NSS_CORS_ALLOW_ORIGINS cannot contain '*' unless NSS_INSECURE_DEV=true".into(),
            );
        }
        Ok(())
    }

    pub fn computed_chunk_size_bytes(&self) -> Result<u64, String> {
        if let Some(size) = self.chunk_size_bytes {
            return Ok(size);
        }
        let data_dir = self
            .data_dirs
            .first()
            .ok_or_else(|| "NSS_DATA_DIRS must have at least one entry".to_string())?;
        let block_size = block_size_for_path(data_dir)?;
        let mut chunk_size = block_size;
        while chunk_size < self.chunk_min_bytes {
            chunk_size *= 2;
        }
        if chunk_size > self.chunk_max_bytes {
            chunk_size = self.chunk_max_bytes;
        }
        Ok(chunk_size)
    }
}

struct RequiredConfig {
    mode: String,
    postgres_dsn: String,
    data_dirs: Vec<PathBuf>,
    admin_bootstrap_user: String,
    admin_bootstrap_password: String,
    secret_encryption_key: Vec<u8>,
    jwt_signing_key: Vec<u8>,
    internal_shared_token: String,
    master_url: Option<String>,
    join_token: Option<String>,
}

impl RequiredConfig {
    fn from_env() -> Result<Self, String> {
        let secret_encryption_key = load_secret_encryption_key()?;
        let jwt_signing_key = load_jwt_signing_key(&secret_encryption_key)?;
        Ok(Self {
            mode: required_env("NSS_MODE", "NSS_MODE is required")?,
            postgres_dsn: required_env("NSS_POSTGRES_DSN", "NSS_POSTGRES_DSN is required")?,
            data_dirs: load_data_dirs()?,
            admin_bootstrap_user: env_or_default("NSS_ADMIN_BOOTSTRAP_USER", "admin"),
            admin_bootstrap_password: env_or_default("NSS_ADMIN_BOOTSTRAP_PASSWORD", "change-me"),
            secret_encryption_key,
            jwt_signing_key,
            internal_shared_token: env_or_default("NSS_INTERNAL_SHARED_TOKEN", "change-me"),
            master_url: env::var("NSS_MASTER_URL").ok(),
            join_token: env::var("NSS_JOIN_TOKEN").ok(),
        })
    }
}

struct StorageConfig {
    replication_factor: u32,
    write_quorum: u32,
    chunk_size_bytes: Option<u64>,
    chunk_min_bytes: u64,
    chunk_max_bytes: u64,
    checksum_algo: ChecksumAlgo,
    scrub_interval: Duration,
    repair_workers: usize,
    multipart_ttl: Duration,
    gc_interval: Duration,
}

impl StorageConfig {
    fn from_env() -> Self {
        let replication_factor = parse_env("NSS_REPLICATION_FACTOR").unwrap_or(1);
        Self {
            replication_factor,
            write_quorum: parse_env("NSS_WRITE_QUORUM").unwrap_or(replication_factor),
            chunk_size_bytes: parse_env("NSS_CHUNK_SIZE_BYTES"),
            chunk_min_bytes: parse_env("NSS_CHUNK_MIN_BYTES").unwrap_or(4 * 1024 * 1024),
            chunk_max_bytes: parse_env("NSS_CHUNK_MAX_BYTES").unwrap_or(64 * 1024 * 1024),
            checksum_algo: env::var("NSS_CHECKSUM_ALGO")
                .ok()
                .and_then(|value| ChecksumAlgo::parse(&value))
                .unwrap_or(ChecksumAlgo::Crc32c),
            scrub_interval: Duration::from_secs(
                parse_env("NSS_SCRUB_INTERVAL_SECONDS").unwrap_or(3600),
            ),
            repair_workers: parse_env("NSS_REPAIR_WORKERS").unwrap_or(4),
            multipart_ttl: Duration::from_secs(
                parse_env("NSS_MULTIPART_TTL_SECONDS").unwrap_or(24 * 3600),
            ),
            gc_interval: Duration::from_secs(parse_env("NSS_GC_INTERVAL_SECONDS").unwrap_or(3600)),
        }
    }
}

struct ListenConfig {
    s3_listen: String,
    api_listen: String,
    internal_listen: String,
    replica_listen: String,
    metrics_listen: String,
    s3_max_time_skew_seconds: i64,
    internal_advertise: Option<String>,
    replica_advertise: Option<String>,
    ui_dir: Option<String>,
}

impl ListenConfig {
    fn from_env() -> Self {
        Self {
            s3_listen: normalize_listen_addr(env_or_default("NSS_S3_LISTEN", ":9000")),
            api_listen: resolve_api_listen(),
            internal_listen: normalize_listen_addr(env_or_default("NSS_INTERNAL_LISTEN", ":9003")),
            replica_listen: normalize_listen_addr(env_or_default("NSS_REPLICA_LISTEN", ":9010")),
            metrics_listen: normalize_listen_addr(env_or_default("NSS_METRICS_LISTEN", ":9100")),
            s3_max_time_skew_seconds: parse_env("NSS_S3_MAX_TIME_SKEW_SECONDS").unwrap_or(900),
            internal_advertise: env::var("NSS_INTERNAL_ADVERTISE").ok(),
            replica_advertise: env::var("NSS_REPLICA_ADVERTISE").ok(),
            ui_dir: resolve_ui_dir(),
        }
    }
}

struct RuntimeConfig {
    s3_public_url: Option<String>,
    redis_url: Option<String>,
    rabbit_url: Option<String>,
    log_level: String,
    cors_allow_origins: Vec<String>,
    insecure_dev: bool,
    replica_sub_mode: String,
}

impl RuntimeConfig {
    fn from_env() -> Self {
        let cors_allow_origins = env::var("NSS_CORS_ALLOW_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        Self {
            s3_public_url: env::var("NSS_S3_PUBLIC_URL").ok(),
            redis_url: env::var("NSS_REDIS_URL").ok(),
            rabbit_url: env::var("NSS_RABBIT_URL").ok(),
            log_level: env_or_default("NSS_LOG_LEVEL", "info"),
            cors_allow_origins,
            insecure_dev: env::var("NSS_INSECURE_DEV")
                .ok()
                .and_then(|value| parse_bool(&value))
                .unwrap_or(false),
            replica_sub_mode: env_or_default("NSS_REPLICA_SUB_MODE", "delivery").to_lowercase(),
        }
    }
}

struct AuthConfig {
    mode: AuthMode,
    oidc: Option<OidcConfig>,
}

impl AuthConfig {
    fn from_env() -> Result<Self, String> {
        let mode = parse_auth_mode()?;
        let oidc = if mode.uses_external_identity() {
            Some(load_oidc_config()?)
        } else {
            None
        };
        Ok(Self { mode, oidc })
    }
}

fn required_env(key: &str, missing_message: &str) -> Result<String, String> {
    env::var(key).map_err(|_| missing_message.to_string())
}

fn parse_auth_mode() -> Result<AuthMode, String> {
    let raw = env_or_default("NSS_AUTH_MODE", "internal");
    match raw.trim().to_ascii_lowercase().as_str() {
        "internal" => Ok(AuthMode::Internal),
        "oidc" => Ok(AuthMode::Oidc),
        "oauth2" => Ok(AuthMode::Oauth2),
        "saml2" => Ok(AuthMode::Saml2),
        _ => Err("NSS_AUTH_MODE must be internal, oidc, oauth2, or saml2".into()),
    }
}

fn load_oidc_config() -> Result<OidcConfig, String> {
    let issuer_url = required_oidc_env("NSS_OIDC_ISSUER_URL")?;
    let client_id = required_oidc_env("NSS_OIDC_CLIENT_ID")?;
    let redirect_url = required_oidc_env("NSS_OIDC_REDIRECT_URL")?;
    let client_secret = env::var("NSS_OIDC_CLIENT_SECRET")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let scopes = env_or_default("NSS_OIDC_SCOPES", "openid profile email");
    let username_claim = env_or_default("NSS_OIDC_USERNAME_CLAIM", "preferred_username");
    let display_name_claim = env_or_default("NSS_OIDC_DISPLAY_NAME_CLAIM", "name");
    let groups_claim = env_or_default("NSS_OIDC_GROUPS_CLAIM", "groups");
    let admin_groups = split_csv("NSS_OIDC_ADMIN_GROUPS");
    let audience = env::var("NSS_OIDC_AUDIENCE").unwrap_or_else(|_| client_id.clone());
    Ok(OidcConfig {
        issuer_url,
        client_id,
        client_secret,
        redirect_url,
        scopes,
        username_claim,
        display_name_claim,
        groups_claim,
        admin_groups,
        audience,
    })
}

fn required_oidc_env(key: &str) -> Result<String, String> {
    required_env(
        key,
        &format!("{} is required for oidc/oauth2/saml2 auth", key),
    )
}

fn validate_external_auth_config(
    auth_mode: AuthMode,
    oidc: Option<&OidcConfig>,
) -> Result<(), String> {
    if !auth_mode.uses_external_identity() {
        return Ok(());
    }
    let Some(oidc) = oidc else {
        return Err("OIDC-compatible config missing while NSS_AUTH_MODE is external".into());
    };
    if !oidc.issuer_url.starts_with("http://") && !oidc.issuer_url.starts_with("https://") {
        return Err("NSS_OIDC_ISSUER_URL must be an absolute http/https URL".into());
    }
    if !oidc.redirect_url.starts_with("http://") && !oidc.redirect_url.starts_with("https://") {
        return Err("NSS_OIDC_REDIRECT_URL must be an absolute http/https URL".into());
    }
    if oidc.audience.trim().is_empty() {
        return Err("NSS_OIDC_AUDIENCE must not be empty".into());
    }
    if oidc.admin_groups.is_empty() {
        return Err(
            "NSS_OIDC_ADMIN_GROUPS must contain at least one group in external auth mode".into(),
        );
    }
    Ok(())
}

fn env_or_default(key: &str, default_value: &str) -> String {
    env::var(key).unwrap_or_else(|_| default_value.to_string())
}

fn parse_env<T>(key: &str) -> Option<T>
where
    T: std::str::FromStr,
{
    env::var(key).ok().and_then(|value| value.parse().ok())
}

fn split_csv(key: &str) -> Vec<String> {
    env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.to_string())
        .collect()
}

fn load_data_dirs() -> Result<Vec<PathBuf>, String> {
    let raw = required_env("NSS_DATA_DIRS", "NSS_DATA_DIRS is required")?;
    let data_dirs = raw
        .split(',')
        .map(|entry| PathBuf::from(entry.trim()))
        .filter(|entry| !entry.as_os_str().is_empty())
        .collect::<Vec<_>>();
    if data_dirs.is_empty() {
        return Err("NSS_DATA_DIRS must contain at least one directory".into());
    }
    Ok(data_dirs)
}

fn load_secret_encryption_key() -> Result<Vec<u8>, String> {
    let key = required_env(
        "NSS_SECRET_ENCRYPTION_KEY_BASE64",
        "NSS_SECRET_ENCRYPTION_KEY_BASE64 is required",
    )?;
    parse_base64_key("NSS_SECRET_ENCRYPTION_KEY_BASE64", &key)
}

fn load_jwt_signing_key(secret_encryption_key: &[u8]) -> Result<Vec<u8>, String> {
    let maybe_key = env::var("NSS_JWT_SIGNING_KEY_BASE64").ok();
    if let Some(raw) = maybe_key {
        return parse_base64_key("NSS_JWT_SIGNING_KEY_BASE64", &raw);
    }
    Ok(derive_jwt_signing_key(secret_encryption_key))
}

fn parse_base64_key(env_name: &str, raw: &str) -> Result<Vec<u8>, String> {
    let decoded = Base64
        .decode(raw.as_bytes())
        .map_err(|_| format!("{env_name} must be valid base64"))?;
    if decoded.len() != 32 {
        return Err(format!("{env_name} must decode to 32 bytes"));
    }
    Ok(decoded)
}

fn derive_jwt_signing_key(secret_encryption_key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(secret_encryption_key);
    hasher.update(b"nss-jwt-signing-key-v1");
    hasher.finalize().to_vec()
}

fn validate_required_secret(env_name: &str, value: &str) -> Result<(), String> {
    if is_insecure_secret_value(value) {
        return Err(format!(
            "{env_name} must be changed from default when NSS_INSECURE_DEV=false"
        ));
    }
    Ok(())
}

fn is_insecure_secret_value(value: &str) -> bool {
    matches!(value.trim(), "" | "change-me")
}

fn resolve_api_listen() -> String {
    if let Ok(value) = env::var("NSS_API_LISTEN") {
        return normalize_listen_addr(value);
    }
    if let Ok(value) = env::var("NSS_CONSOLE_LISTEN") {
        return normalize_listen_addr(value);
    }
    if let Ok(value) = env::var("NSS_ADMIN_LISTEN") {
        return normalize_listen_addr(value);
    }
    normalize_listen_addr(":9001".to_string())
}

fn resolve_ui_dir() -> Option<String> {
    env::var("NSS_UI_DIR")
        .ok()
        .or_else(|| env::var("NSS_CONSOLE_UI_DIR").ok())
        .or_else(|| env::var("NSS_ADMIN_UI_DIR").ok())
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn normalize_listen_addr(value: String) -> String {
    if value.starts_with(':') {
        format!("0.0.0.0{}", value)
    } else {
        value
    }
}

#[cfg(unix)]
fn block_size_for_path(path: &Path) -> Result<u64, String> {
    use std::ffi::CString;
    let c_path = CString::new(path.to_string_lossy().as_bytes()).map_err(|_| "Invalid path")?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if res != 0 {
        return Err(format!("Failed to statfs {}", path.display()));
    }
    let block_size: u64 = stat.f_bsize;
    Ok(block_size)
}

#[cfg(not(unix))]
fn block_size_for_path(_path: &Path) -> Result<u64, String> {
    Ok(4096)
}

#[cfg(test)]
mod tests {
    use super::{block_size_for_path, normalize_listen_addr, parse_bool, AuthMode, Config};
    use crate::storage::checksum::ChecksumAlgo;
    use base64::engine::general_purpose::STANDARD as Base64;
    use base64::Engine;
    use std::env;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::Duration;
    use uuid::Uuid;

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

    macro_rules! test_base_config {
        ($data_dir:expr) => {
            Config {
                mode: "test".to_string(),
                auth_mode: AuthMode::Internal,
                oidc: None,
                postgres_dsn: "postgres://nss:nss@localhost:5432/nss?sslmode=disable".to_string(),
                data_dirs: vec![$data_dir],
                admin_bootstrap_user: "admin".to_string(),
                admin_bootstrap_password: "password".to_string(),
                secret_encryption_key: vec![1u8; 32],
                jwt_signing_key: vec![2u8; 32],
                replication_factor: 2,
                write_quorum: 2,
                chunk_size_bytes: None,
                chunk_min_bytes: 4 * 1024,
                chunk_max_bytes: 8 * 1024 * 1024,
                checksum_algo: ChecksumAlgo::Crc32c,
                scrub_interval: Duration::from_secs(3600),
                repair_workers: 1,
                multipart_ttl: Duration::from_secs(3600),
                gc_interval: Duration::from_secs(3600),
                s3_listen: "0.0.0.0:9000".to_string(),
                api_listen: "0.0.0.0:9001".to_string(),
                internal_listen: "0.0.0.0:9003".to_string(),
                replica_listen: "0.0.0.0:9010".to_string(),
                metrics_listen: "0.0.0.0:9100".to_string(),
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
                internal_shared_token: "change-me".to_string(),
                master_url: None,
                join_token: None,
                replica_sub_mode: "delivery".to_string(),
            }
        };
    }

    fn base_config(data_dir: PathBuf) -> Config {
        test_base_config!(data_dir)
    }

    fn set_minimum_env(env_guard: &mut EnvGuard, data_dir: &PathBuf, secret_b64: &str) {
        env_guard.set("NSS_MODE", "test");
        env_guard.set(
            "NSS_POSTGRES_DSN",
            "postgres://nss:nss@localhost:5432/nss?sslmode=disable",
        );
        env_guard.set("NSS_DATA_DIRS", data_dir.to_str().expect("data dir"));
        env_guard.set("NSS_SECRET_ENCRYPTION_KEY_BASE64", secret_b64);
    }

    fn set_oidc_env(env_guard: &mut EnvGuard) {
        env_guard.set("NSS_AUTH_MODE", "oidc");
        env_guard.set("NSS_OIDC_ISSUER_URL", "https://sso.example.com/realms/nss");
        env_guard.set("NSS_OIDC_CLIENT_ID", "nss-console");
        env_guard.set(
            "NSS_OIDC_REDIRECT_URL",
            "http://localhost:9001/console/v1/oidc/callback",
        );
        env_guard.set("NSS_OIDC_ADMIN_GROUPS", "nss-admin,storage-admin");
    }

    #[test]
    fn parse_bool_variants() {
        assert_eq!(parse_bool("1"), Some(true));
        assert_eq!(parse_bool("TRUE"), Some(true));
        assert_eq!(parse_bool("yes"), Some(true));
        assert_eq!(parse_bool("on"), Some(true));
        assert_eq!(parse_bool("0"), Some(false));
        assert_eq!(parse_bool("false"), Some(false));
        assert_eq!(parse_bool("No"), Some(false));
        assert_eq!(parse_bool("off"), Some(false));
        assert_eq!(parse_bool("maybe"), None);
    }

    #[test]
    fn normalize_listen_addr_handles_colon_prefix() {
        assert_eq!(normalize_listen_addr(":9000".to_string()), "0.0.0.0:9000");
        assert_eq!(
            normalize_listen_addr("127.0.0.1:9000".to_string()),
            "127.0.0.1:9000"
        );
    }

    #[test]
    fn block_size_for_path_returns_value() {
        let path = env::temp_dir();
        let size = block_size_for_path(&path).expect("block size");
        assert!(size > 0);
    }

    #[test]
    fn block_size_for_path_fails_for_missing_path() {
        let missing = env::temp_dir().join(format!("nss-missing-{}", Uuid::new_v4()));
        let err = block_size_for_path(&missing).unwrap_err();
        assert!(err.contains("Failed to statfs"));
    }

    #[test]
    #[cfg(unix)]
    fn block_size_for_path_rejects_invalid_path() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let mut bytes = b"/tmp/nss\0bad".to_vec();
        bytes.push(0);
        let os = OsString::from_vec(bytes);
        let path = PathBuf::from(os);
        let err = block_size_for_path(&path).unwrap_err();
        assert_eq!(err, "Invalid path");
    }

    #[test]
    fn computed_chunk_size_uses_override() {
        let config = Config {
            chunk_size_bytes: Some(1234),
            ..base_config(env::temp_dir())
        };
        let size = config.computed_chunk_size_bytes().expect("computed");
        assert_eq!(size, 1234);
    }

    #[test]
    fn computed_chunk_size_respects_min_and_max() {
        let data_dir = env::temp_dir();
        let block_size = block_size_for_path(&data_dir).expect("block size");
        let config = Config {
            chunk_size_bytes: None,
            chunk_min_bytes: block_size * 4,
            chunk_max_bytes: block_size * 4,
            ..base_config(data_dir)
        };
        let size = config.computed_chunk_size_bytes().expect("computed");
        assert_eq!(size, block_size * 4);
    }

    #[test]
    fn computed_chunk_size_caps_at_max() {
        let data_dir = env::temp_dir();
        let block_size = block_size_for_path(&data_dir).expect("block size");
        let max_bytes = (block_size / 2).max(1);
        let config = Config {
            chunk_size_bytes: None,
            chunk_min_bytes: 1,
            chunk_max_bytes: max_bytes,
            ..base_config(data_dir)
        };
        let size = config.computed_chunk_size_bytes().expect("computed");
        assert_eq!(size, max_bytes);
    }

    #[test]
    fn computed_chunk_size_errors_without_data_dir() {
        let config = Config {
            data_dirs: Vec::new(),
            ..base_config(env::temp_dir())
        };
        let err = config.computed_chunk_size_bytes().unwrap_err();
        assert_eq!(err, "NSS_DATA_DIRS must have at least one entry");
    }

    #[test]
    fn computed_chunk_size_errors_on_missing_path() {
        let missing = env::temp_dir().join(format!("nss-missing-{}", Uuid::new_v4()));
        let config = Config {
            data_dirs: vec![missing.clone()],
            ..base_config(env::temp_dir())
        };
        let err = config.computed_chunk_size_bytes().unwrap_err();
        assert!(err.contains("Failed to statfs"));
    }

    #[test]
    fn load_config_success() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let data_dirs = format!("{}, {}", data_dir.display(), data_dir.display());
        let secret_b64 = Base64.encode(vec![7u8; 32]);

        env_guard.set("NSS_MODE", "test");
        env_guard.set(
            "NSS_POSTGRES_DSN",
            "postgres://nss:nss@localhost:5432/nss?sslmode=disable",
        );
        env_guard.set("NSS_DATA_DIRS", &data_dirs);
        env_guard.set("NSS_SECRET_ENCRYPTION_KEY_BASE64", &secret_b64);
        env_guard.set("NSS_REPLICATION_FACTOR", "3");
        env_guard.set(
            "NSS_CORS_ALLOW_ORIGINS",
            "https://a.example, ,https://b.example",
        );
        env_guard.set("NSS_INSECURE_DEV", "yes");
        env_guard.set("NSS_S3_LISTEN", ":9000");

        let config = Config::load().expect("load");
        assert_eq!(config.mode, "test");
        assert_eq!(config.replication_factor, 3);
        assert_eq!(config.write_quorum, 3);
        assert!(config.insecure_dev);
        assert_eq!(config.cors_allow_origins.len(), 2);
        assert_eq!(config.s3_listen, "0.0.0.0:9000");
        assert_eq!(config.jwt_signing_key.len(), 32);
        assert_ne!(config.jwt_signing_key, config.secret_encryption_key);
    }

    #[test]
    fn load_config_defaults_to_internal_auth_mode() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);
        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);

        let config = Config::load().expect("load");
        assert_eq!(config.auth_mode, AuthMode::Internal);
        assert!(config.oidc.is_none());
    }

    #[test]
    fn load_config_rejects_invalid_auth_mode() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);
        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        env_guard.set("NSS_AUTH_MODE", "ldap");

        let err = Config::load().err().expect("expected error");
        assert_eq!(
            err,
            "NSS_AUTH_MODE must be internal, oidc, oauth2, or saml2"
        );
    }

    #[test]
    fn load_config_requires_oidc_values_when_mode_is_oidc() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);
        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        env_guard.set("NSS_AUTH_MODE", "oidc");
        env_guard.remove("NSS_OIDC_ISSUER_URL");

        let err = Config::load().err().expect("expected error");
        assert_eq!(
            err,
            "NSS_OIDC_ISSUER_URL is required for oidc/oauth2/saml2 auth"
        );
    }

    #[test]
    fn load_config_requires_oidc_client_and_redirect_in_external_mode() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);
        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        set_oidc_env(&mut env_guard);
        env_guard.remove("NSS_OIDC_CLIENT_ID");
        let err = Config::load().err().expect("expected error");
        assert_eq!(
            err,
            "NSS_OIDC_CLIENT_ID is required for oidc/oauth2/saml2 auth"
        );
        env_guard.set("NSS_OIDC_CLIENT_ID", "nss-console");
        env_guard.remove("NSS_OIDC_REDIRECT_URL");
        let err = Config::load().err().expect("expected error");
        assert_eq!(
            err,
            "NSS_OIDC_REDIRECT_URL is required for oidc/oauth2/saml2 auth"
        );
    }

    #[test]
    fn validate_external_auth_config_rejects_missing_struct() {
        let err = super::validate_external_auth_config(AuthMode::Oidc, None).unwrap_err();
        assert_eq!(
            err,
            "OIDC-compatible config missing while NSS_AUTH_MODE is external"
        );
    }

    #[test]
    fn load_config_parses_oidc_mode() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);
        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        set_oidc_env(&mut env_guard);

        let config = Config::load().expect("load");
        assert_eq!(config.auth_mode, AuthMode::Oidc);
        let oidc = config.oidc.expect("oidc config");
        assert_eq!(oidc.audience, "nss-console");
        assert_eq!(oidc.admin_groups.len(), 2);
        assert_eq!(oidc.groups_claim, "groups");
    }

    #[test]
    fn load_config_rejects_oidc_without_admin_groups() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);
        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        set_oidc_env(&mut env_guard);
        env_guard.set("NSS_OIDC_ADMIN_GROUPS", "   ");

        let err = Config::load().err().expect("expected error");
        assert_eq!(
            err,
            "NSS_OIDC_ADMIN_GROUPS must contain at least one group in external auth mode"
        );
    }

    #[test]
    fn load_config_parses_oauth2_and_saml2_modes_with_oidc_settings() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);
        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        set_oidc_env(&mut env_guard);

        env_guard.set("NSS_AUTH_MODE", "oauth2");
        let oauth2 = Config::load().expect("oauth2");
        assert_eq!(oauth2.auth_mode, AuthMode::Oauth2);
        assert!(oauth2.oidc.is_some());

        env_guard.set("NSS_AUTH_MODE", "saml2");
        let saml2 = Config::load().expect("saml2");
        assert_eq!(saml2.auth_mode, AuthMode::Saml2);
        assert!(saml2.oidc.is_some());
    }

    #[test]
    fn load_config_rejects_invalid_replica_sub_mode() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);

        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        env_guard.set("NSS_REPLICA_SUB_MODE", "invalid");

        let err = Config::load().err().expect("expected error");
        assert_eq!(err, "NSS_REPLICA_SUB_MODE must be delivery or backup");
    }

    #[test]
    fn load_config_uses_explicit_jwt_signing_key() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);
        let jwt_b64 = Base64.encode(vec![9u8; 32]);

        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        env_guard.set("NSS_JWT_SIGNING_KEY_BASE64", &jwt_b64);

        let config = Config::load().expect("load");
        assert_eq!(config.jwt_signing_key, vec![9u8; 32]);
    }

    #[test]
    fn load_config_rejects_invalid_jwt_signing_key() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);
        let jwt_b64 = Base64.encode(vec![9u8; 16]);

        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        env_guard.set("NSS_JWT_SIGNING_KEY_BASE64", &jwt_b64);

        let err = Config::load().err().expect("expected error");
        assert_eq!(err, "NSS_JWT_SIGNING_KEY_BASE64 must decode to 32 bytes");
    }

    #[test]
    fn load_config_prefers_api_listen_and_ui_dir() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);

        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        env_guard.set("NSS_API_LISTEN", ":9123");
        env_guard.set("NSS_UI_DIR", "/opt/ui");

        let config = Config::load().expect("load");
        assert_eq!(config.api_listen, "0.0.0.0:9123");
        assert_eq!(config.ui_dir, Some("/opt/ui".to_string()));
    }

    #[test]
    fn load_config_falls_back_to_console_listen_and_ui_dir() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);

        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        env_guard.set("NSS_CONSOLE_LISTEN", ":9444");
        env_guard.set("NSS_CONSOLE_UI_DIR", "/opt/console");

        let config = Config::load().expect("load");
        assert_eq!(config.api_listen, "0.0.0.0:9444");
        assert_eq!(config.ui_dir, Some("/opt/console".to_string()));
    }

    #[test]
    fn load_config_falls_back_to_admin_listen_and_ui_dir() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);

        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        env_guard.set("NSS_ADMIN_LISTEN", ":9555");
        env_guard.set("NSS_ADMIN_UI_DIR", "/opt/admin");

        let config = Config::load().expect("load");
        assert_eq!(config.api_listen, "0.0.0.0:9555");
        assert_eq!(config.ui_dir, Some("/opt/admin".to_string()));
    }

    #[test]
    fn load_config_requires_mode() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);

        env_guard.remove("NSS_MODE");
        env_guard.set(
            "NSS_POSTGRES_DSN",
            "postgres://nss:nss@localhost:5432/nss?sslmode=disable",
        );
        env_guard.set("NSS_DATA_DIRS", data_dir.to_str().expect("data dir"));
        env_guard.set("NSS_SECRET_ENCRYPTION_KEY_BASE64", &secret_b64);

        let result = Config::load();
        assert!(result.is_err());
        let err = result.err().expect("err");
        assert_eq!(err, "NSS_MODE is required");
    }

    #[test]
    fn load_config_requires_postgres_dsn() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);

        env_guard.set("NSS_MODE", "test");
        env_guard.remove("NSS_POSTGRES_DSN");
        env_guard.set("NSS_DATA_DIRS", data_dir.to_str().expect("data dir"));
        env_guard.set("NSS_SECRET_ENCRYPTION_KEY_BASE64", &secret_b64);

        let result = Config::load();
        assert!(result.is_err());
        let err = result.err().expect("err");
        assert_eq!(err, "NSS_POSTGRES_DSN is required");
    }

    #[test]
    fn load_config_requires_dirs_env() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let secret_b64 = Base64.encode(vec![7u8; 32]);

        env_guard.set("NSS_MODE", "test");
        env_guard.set(
            "NSS_POSTGRES_DSN",
            "postgres://nss:nss@localhost:5432/nss?sslmode=disable",
        );
        env_guard.remove("NSS_DATA_DIRS");
        env_guard.set("NSS_SECRET_ENCRYPTION_KEY_BASE64", &secret_b64);

        let result = Config::load();
        assert!(result.is_err());
        let err = result.err().expect("err");
        assert_eq!(err, "NSS_DATA_DIRS is required");
    }

    #[test]
    fn load_config_requires_secret_key() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();

        env_guard.set("NSS_MODE", "test");
        env_guard.set(
            "NSS_POSTGRES_DSN",
            "postgres://nss:nss@localhost:5432/nss?sslmode=disable",
        );
        env_guard.set("NSS_DATA_DIRS", data_dir.to_str().expect("data dir"));
        env_guard.remove("NSS_SECRET_ENCRYPTION_KEY_BASE64");

        let result = Config::load();
        assert!(result.is_err());
        let err = result.err().expect("err");
        assert_eq!(err, "NSS_SECRET_ENCRYPTION_KEY_BASE64 is required");
    }

    #[test]
    fn load_config_requires_data_dirs() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let secret_b64 = Base64.encode(vec![7u8; 32]);

        env_guard.set("NSS_MODE", "test");
        env_guard.set(
            "NSS_POSTGRES_DSN",
            "postgres://nss:nss@localhost:5432/nss?sslmode=disable",
        );
        env_guard.set("NSS_DATA_DIRS", ", ,");
        env_guard.set("NSS_SECRET_ENCRYPTION_KEY_BASE64", &secret_b64);

        let result = Config::load();
        assert!(result.is_err());
        let err = result.err().expect("err");
        assert_eq!(err, "NSS_DATA_DIRS must contain at least one directory");
    }

    #[test]
    fn load_config_rejects_invalid_base64() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();

        env_guard.set("NSS_MODE", "test");
        env_guard.set(
            "NSS_POSTGRES_DSN",
            "postgres://nss:nss@localhost:5432/nss?sslmode=disable",
        );
        env_guard.set("NSS_DATA_DIRS", data_dir.to_str().expect("data dir"));
        env_guard.set("NSS_SECRET_ENCRYPTION_KEY_BASE64", "not-base64");

        let result = Config::load();
        assert!(result.is_err());
        let err = result.err().expect("err");
        assert_eq!(err, "NSS_SECRET_ENCRYPTION_KEY_BASE64 must be valid base64");
    }

    #[test]
    fn load_config_rejects_invalid_key_length() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![1u8; 16]);

        env_guard.set("NSS_MODE", "test");
        env_guard.set(
            "NSS_POSTGRES_DSN",
            "postgres://nss:nss@localhost:5432/nss?sslmode=disable",
        );
        env_guard.set("NSS_DATA_DIRS", data_dir.to_str().expect("data dir"));
        env_guard.set("NSS_SECRET_ENCRYPTION_KEY_BASE64", &secret_b64);

        let result = Config::load();
        assert!(result.is_err());
        let err = result.err().expect("err");
        assert_eq!(
            err,
            "NSS_SECRET_ENCRYPTION_KEY_BASE64 must decode to 32 bytes"
        );
    }

    #[test]
    fn load_config_rejects_default_secrets_in_non_dev() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);

        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        env_guard.set("NSS_MODE", "master");
        env_guard.set("NSS_ADMIN_BOOTSTRAP_PASSWORD", "change-me");
        env_guard.set("NSS_INTERNAL_SHARED_TOKEN", "change-me");
        env_guard.remove("NSS_INSECURE_DEV");

        let err = Config::load().err().expect("expected error");
        assert_eq!(
            err,
            "NSS_INTERNAL_SHARED_TOKEN must be changed from default when NSS_INSECURE_DEV=false"
        );
    }

    #[test]
    fn load_config_rejects_default_admin_password_in_non_dev_master() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);
        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        env_guard.set("NSS_MODE", "master");
        env_guard.set("NSS_ADMIN_BOOTSTRAP_PASSWORD", "change-me");
        env_guard.set("NSS_INTERNAL_SHARED_TOKEN", "safe-token");
        env_guard.remove("NSS_INSECURE_DEV");
        let err = Config::load().err().expect("expected error");
        assert_eq!(
            err,
            "NSS_ADMIN_BOOTSTRAP_PASSWORD must be changed from default when NSS_INSECURE_DEV=false"
        );
    }

    #[test]
    fn load_config_rejects_wildcard_cors_in_non_dev() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);

        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        env_guard.set("NSS_MODE", "master");
        env_guard.set("NSS_ADMIN_BOOTSTRAP_PASSWORD", "safe-password");
        env_guard.set("NSS_INTERNAL_SHARED_TOKEN", "safe-token");
        env_guard.set("NSS_CORS_ALLOW_ORIGINS", "*");

        let err = Config::load().err().expect("expected error");
        assert_eq!(
            err,
            "NSS_CORS_ALLOW_ORIGINS cannot contain '*' unless NSS_INSECURE_DEV=true"
        );
    }

    #[test]
    fn load_config_accepts_secure_master_when_values_are_safe() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);
        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        env_guard.set("NSS_MODE", "master");
        env_guard.set("NSS_ADMIN_BOOTSTRAP_PASSWORD", "safe-password");
        env_guard.set("NSS_INTERNAL_SHARED_TOKEN", "safe-token");
        env_guard.set("NSS_CORS_ALLOW_ORIGINS", "http://localhost:4200");
        env_guard.remove("NSS_INSECURE_DEV");
        let config = Config::load().expect("load");
        assert_eq!(config.mode, "master");
    }

    #[test]
    fn validate_security_master_branch_executes_with_safe_values() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);
        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        env_guard.set("NSS_MODE", "master");
        env_guard.set("NSS_ADMIN_BOOTSTRAP_PASSWORD", "safe-password");
        env_guard.set("NSS_INTERNAL_SHARED_TOKEN", "safe-token");
        env_guard.remove("NSS_INSECURE_DEV");
        let config = Config::load().expect("load");
        config.validate_security().expect("validate");
    }

    #[test]
    fn validate_security_default_branch_allows_non_cluster_mode() {
        let config = base_config(env::temp_dir());
        config.validate_security().expect("validate");
    }

    #[test]
    fn validate_security_skips_master_password_check_for_non_master_mode() {
        let mut config = base_config(env::temp_dir());
        config.mode = "replica".to_string();
        config.internal_shared_token = "safe-token".to_string();
        config.validate_security().expect("validate");
    }

    #[test]
    fn load_config_trims_empty_optional_oidc_client_secret() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);
        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        set_oidc_env(&mut env_guard);
        env_guard.set("NSS_OIDC_CLIENT_SECRET", "   ");
        let config = Config::load().expect("load");
        assert!(config.oidc.expect("oidc").client_secret.is_none());
    }

    #[test]
    fn load_config_rejects_invalid_oidc_url_and_audience_values() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);
        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        set_oidc_env(&mut env_guard);
        env_guard.set("NSS_OIDC_ISSUER_URL", "issuer-without-scheme");
        let err = Config::load().err().expect("expected error");
        assert_eq!(
            err,
            "NSS_OIDC_ISSUER_URL must be an absolute http/https URL"
        );
        env_guard.set("NSS_OIDC_ISSUER_URL", "https://sso.example.com/realm");
        env_guard.set("NSS_OIDC_REDIRECT_URL", "callback-without-scheme");
        let err = Config::load().err().expect("expected error");
        assert_eq!(
            err,
            "NSS_OIDC_REDIRECT_URL must be an absolute http/https URL"
        );
        env_guard.set(
            "NSS_OIDC_REDIRECT_URL",
            "http://localhost:9001/console/v1/oidc/callback",
        );
        env_guard.set("NSS_OIDC_AUDIENCE", "   ");
        let err = Config::load().err().expect("expected error");
        assert_eq!(err, "NSS_OIDC_AUDIENCE must not be empty");
    }

    fn set_invalid_optional_values(env_guard: &mut EnvGuard) {
        env_guard.set("NSS_REPLICATION_FACTOR", "bad");
        env_guard.set("NSS_WRITE_QUORUM", "bad");
        env_guard.set("NSS_CHUNK_SIZE_BYTES", "bad");
        env_guard.set("NSS_CHUNK_MIN_BYTES", "bad");
        env_guard.set("NSS_CHUNK_MAX_BYTES", "bad");
        env_guard.set("NSS_CHECKSUM_ALGO", "bad");
        env_guard.set("NSS_SCRUB_INTERVAL_SECONDS", "bad");
        env_guard.set("NSS_REPAIR_WORKERS", "bad");
        env_guard.set("NSS_MULTIPART_TTL_SECONDS", "bad");
        env_guard.set("NSS_GC_INTERVAL_SECONDS", "bad");
        env_guard.set("NSS_S3_MAX_TIME_SKEW_SECONDS", "bad");
        env_guard.remove("NSS_S3_LISTEN");
        env_guard.remove("NSS_CORS_ALLOW_ORIGINS");
    }

    fn assert_optional_defaults(config: &Config) {
        assert_eq!(config.replication_factor, 1);
        assert_eq!(config.write_quorum, 1);
        assert!(config.chunk_size_bytes.is_none());
        assert_eq!(config.chunk_min_bytes, 4 * 1024 * 1024);
        assert_eq!(config.chunk_max_bytes, 64 * 1024 * 1024);
        assert_eq!(config.checksum_algo, ChecksumAlgo::Crc32c);
        assert_eq!(config.scrub_interval.as_secs(), 3600);
        assert_eq!(config.repair_workers, 4);
        assert_eq!(config.multipart_ttl.as_secs(), 24 * 3600);
        assert_eq!(config.gc_interval.as_secs(), 3600);
        assert_eq!(config.s3_max_time_skew_seconds, 900);
        assert_eq!(config.s3_listen, "0.0.0.0:9000");
        assert!(config.cors_allow_origins.is_empty());
    }

    #[test]
    fn load_config_defaults_for_invalid_optional_values() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let mut env_guard = EnvGuard::new();
        let data_dir = env::temp_dir();
        let secret_b64 = Base64.encode(vec![7u8; 32]);
        set_minimum_env(&mut env_guard, &data_dir, &secret_b64);
        set_invalid_optional_values(&mut env_guard);

        let config = Config::load().expect("load");
        assert_optional_defaults(&config);
    }

    #[test]
    fn env_guard_restores_previous_value() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        env::set_var("NSS_TEST_ENV", "original");
        {
            let mut guard = EnvGuard::new();
            guard.set("NSS_TEST_ENV", "updated");
            assert_eq!(env::var("NSS_TEST_ENV").expect("read"), "updated");
        }
        assert_eq!(env::var("NSS_TEST_ENV").expect("read"), "original");
        env::remove_var("NSS_TEST_ENV");
    }
}
