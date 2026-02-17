use crate::api::AppState;
use crate::meta::models::{BackupPolicy, BackupRun, Bucket, BucketSnapshot, BucketSnapshotObject};
use crate::storage::checksum::{Checksum, ChecksumAlgo};
use chrono::{DateTime, Duration, Utc};
use flate2::write::GzEncoder;
use flate2::Compression;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::collections::{BTreeMap, HashSet};
use std::io::{self, Write};
#[cfg(test)]
use std::sync::atomic::{AtomicU8, Ordering};
use tar::{Builder, Header};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration as TokioDuration};
use uuid::Uuid;

const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

#[cfg(test)]
static BACKUP_FAILPOINT: AtomicU8 = AtomicU8::new(0);
#[cfg(test)]
static MEMORY_WRITER_FAIL_MODE: AtomicU8 = AtomicU8::new(0);

#[cfg(test)]
fn backup_failpoint(step: u8) -> bool {
    if BACKUP_FAILPOINT.load(Ordering::SeqCst) == step {
        BACKUP_FAILPOINT.store(0, Ordering::SeqCst);
        true
    } else {
        false
    }
}

#[cfg(test)]
fn clear_backup_failpoint() {
    BACKUP_FAILPOINT.store(0, Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) struct BackupFailpointGuard;

#[cfg(test)]
impl Drop for BackupFailpointGuard {
    fn drop(&mut self) {
        clear_backup_failpoint();
    }
}

#[cfg(test)]
pub(crate) fn backup_failpoint_guard(step: u8) -> BackupFailpointGuard {
    BACKUP_FAILPOINT.store(step, Ordering::SeqCst);
    BackupFailpointGuard
}

#[cfg(test)]
fn clear_memory_writer_fail_mode() {
    MEMORY_WRITER_FAIL_MODE.store(0, Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) struct MemoryWriterFailGuard;

#[cfg(test)]
impl Drop for MemoryWriterFailGuard {
    fn drop(&mut self) {
        clear_memory_writer_fail_mode();
    }
}

#[cfg(test)]
pub(crate) fn memory_writer_fail_guard(mode: u8) -> MemoryWriterFailGuard {
    MEMORY_WRITER_FAIL_MODE.store(mode, Ordering::SeqCst);
    MemoryWriterFailGuard
}

#[derive(Debug, Default)]
struct MemoryWriter {
    bytes: Vec<u8>,
    flush_calls: u8,
}

impl MemoryWriter {
    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for MemoryWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        #[cfg(test)]
        if MEMORY_WRITER_FAIL_MODE.load(Ordering::SeqCst) == 1 {
            return Err(io::Error::other("memory-writer-write-failed"));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        #[cfg(test)]
        {
            let mode = MEMORY_WRITER_FAIL_MODE.load(Ordering::SeqCst);
            let fail_first_flush = mode == 2 && self.flush_calls == 0;
            let fail_second_flush = mode == 3 && self.flush_calls > 0;
            if fail_first_flush || fail_second_flush {
                return Err(io::Error::other("memory-writer-flush-failed"));
            }
        }
        self.flush_calls = self.flush_calls.saturating_add(1);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveFormat {
    Tar,
    TarGz,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExternalTargetKind {
    S3,
    Glacier,
    Sftp,
    Ssh,
    Other,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalBackupTarget {
    pub name: String,
    pub kind: ExternalTargetKind,
    pub endpoint: String,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub headers: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_access_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl ExternalBackupTarget {
    fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    fn timeout_seconds(&self) -> u64 {
        self.timeout_seconds.unwrap_or(5).clamp(1, 120)
    }
}

pub fn parse_external_targets(raw: &Value) -> Result<Vec<ExternalBackupTarget>, String> {
    let targets: Vec<ExternalBackupTarget> = serde_json::from_value(raw.clone())
        .map_err(|_| "external targets must be an array of objects".to_string())?;
    validate_external_targets(&targets)?;
    Ok(targets)
}

pub async fn test_external_target_connection(
    target: &ExternalBackupTarget,
) -> Result<String, String> {
    if !target.is_enabled() {
        return Ok(format!("target '{}' is disabled", target.name));
    }
    match target.kind {
        ExternalTargetKind::Sftp => {
            if target_uses_sftp_scheme(target)? {
                return test_sftp_target(target).await;
            }
            test_http_target(target).await
        }
        ExternalTargetKind::Ssh => {
            if target_uses_ssh_scheme(target)? {
                return test_ssh_target(target).await;
            }
            test_http_target(target).await
        }
        ExternalTargetKind::S3 | ExternalTargetKind::Glacier => test_s3_target(target).await,
        ExternalTargetKind::Other => test_http_target(target).await,
    }
}

fn validate_external_targets(targets: &[ExternalBackupTarget]) -> Result<(), String> {
    let mut names = HashSet::new();
    for target in targets {
        validate_external_target(target)?;
        let key = target.name.trim().to_ascii_lowercase();
        if !names.insert(key) {
            return Err(format!("duplicate external target name '{}'", target.name));
        }
    }
    Ok(())
}

fn validate_external_target(target: &ExternalBackupTarget) -> Result<(), String> {
    if target.name.trim().is_empty() {
        return Err("external target name is required".into());
    }
    let endpoint = parse_target_url(&target.endpoint)?;
    validate_target_scheme(target, &endpoint)?;
    validate_target_method(target)?;
    validate_target_timeout(target)?;
    validate_kind_specific_fields(target)?;
    Ok(())
}

fn validate_kind_specific_fields(target: &ExternalBackupTarget) -> Result<(), String> {
    match target.kind {
        ExternalTargetKind::S3 => {
            require_field(&target.access_key_id, "s3 target requires accessKeyId")?;
            require_field(
                &target.secret_access_key,
                "s3 target requires secretAccessKey",
            )?;
            require_field(&target.region, "s3 target requires region")?;
            require_field(&target.bucket_name, "s3 target requires bucketName")?;
        }
        ExternalTargetKind::Glacier => {
            require_field(&target.access_key_id, "glacier target requires accessKeyId")?;
            require_field(
                &target.secret_access_key,
                "glacier target requires secretAccessKey",
            )?;
            require_field(&target.region, "glacier target requires region")?;
            require_field(&target.vault_name, "glacier target requires vaultName")?;
        }
        ExternalTargetKind::Sftp | ExternalTargetKind::Ssh | ExternalTargetKind::Other => {}
    }
    Ok(())
}

fn require_field(value: &Option<String>, message: &str) -> Result<(), String> {
    match value {
        Some(v) if !v.trim().is_empty() => Ok(()),
        _ => Err(message.to_string()),
    }
}

fn validate_target_scheme(
    target: &ExternalBackupTarget,
    endpoint: &reqwest::Url,
) -> Result<(), String> {
    if target.kind == ExternalTargetKind::Sftp {
        if endpoint.scheme() == "sftp"
            || endpoint.scheme() == "http"
            || endpoint.scheme() == "https"
        {
            return Ok(());
        }
        return Err("sftp target endpoint must use sftp:// or http(s):// gateway scheme".into());
    }
    if target.kind == ExternalTargetKind::Ssh {
        if endpoint.scheme() == "ssh" || endpoint.scheme() == "http" || endpoint.scheme() == "https"
        {
            return Ok(());
        }
        return Err("ssh target endpoint must use ssh:// or http(s):// gateway scheme".into());
    }
    if endpoint.scheme() == "http" || endpoint.scheme() == "https" {
        return Ok(());
    }
    Err("remote target endpoint must use http:// or https://".into())
}

fn validate_target_method(target: &ExternalBackupTarget) -> Result<(), String> {
    if let Some(method) = target.method.as_ref() {
        let upper = method.trim().to_ascii_uppercase();
        if upper != "PUT" && upper != "POST" {
            return Err("remote target method must be PUT or POST".into());
        }
    }
    Ok(())
}

fn validate_target_timeout(target: &ExternalBackupTarget) -> Result<(), String> {
    if let Some(value) = target.timeout_seconds {
        if !(1..=120).contains(&value) {
            return Err("remote target timeoutSeconds must be in 1..=120".into());
        }
    }
    Ok(())
}

fn parse_target_url(raw: &str) -> Result<reqwest::Url, String> {
    reqwest::Url::parse(raw).map_err(|_| "invalid remote target endpoint URL".to_string())
}

async fn test_sftp_target(target: &ExternalBackupTarget) -> Result<String, String> {
    let endpoint = parse_target_url(&target.endpoint)?;
    let host = endpoint
        .host_str()
        .ok_or_else(|| "sftp target endpoint is missing host".to_string())?;
    let port = endpoint.port().unwrap_or(22);
    let address = format!("{host}:{port}");
    run_sftp_connect(target.timeout_seconds(), address).await?;
    Ok("sftp endpoint reachable".into())
}

async fn test_ssh_target(target: &ExternalBackupTarget) -> Result<String, String> {
    let endpoint = parse_target_url(&target.endpoint)?;
    let host = endpoint
        .host_str()
        .ok_or_else(|| "ssh target endpoint is missing host".to_string())?;
    let port = endpoint.port().unwrap_or(22);
    let address = format!("{host}:{port}");
    run_ssh_connect(target.timeout_seconds(), address).await?;
    Ok("ssh endpoint reachable".into())
}

fn s3_bucket_name(target: &ExternalBackupTarget) -> &str {
    match target.kind {
        ExternalTargetKind::Glacier => target.vault_name.as_deref().unwrap_or_default(),
        _ => target.bucket_name.as_deref().unwrap_or_default(),
    }
}

fn s3_service_name(target: &ExternalBackupTarget) -> &str {
    match target.kind {
        ExternalTargetKind::Glacier => "glacier",
        _ => "s3",
    }
}

fn parse_s3_url(url_str: &str) -> Result<(reqwest::Url, String, String), String> {
    let parsed = parse_target_url(url_str)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "s3 endpoint missing host".to_string())?
        .to_string();
    let uri_path = parsed.path().to_string();
    Ok((parsed, host, uri_path))
}

async fn test_s3_target(target: &ExternalBackupTarget) -> Result<String, String> {
    let bucket = s3_bucket_name(target);
    let base = target.endpoint.trim_end_matches('/');
    let (parsed, host, uri_path) = parse_s3_url(&format!("{base}/{bucket}/"))?;
    let now = Utc::now();
    let payload_hash = hex_sha256(b"");
    let auth = sign_s3_request(target, "HEAD", &uri_path, &host, "", &payload_hash, now);
    let date_stamp = now.format("%Y%m%dT%H%M%SZ").to_string();
    let client = build_http_client(target.timeout_seconds())?;
    let response = client
        .head(parsed)
        .header("Host", &host)
        .header("x-amz-date", &date_stamp)
        .header("x-amz-content-sha256", &payload_hash)
        .header("Authorization", &auth)
        .send()
        .await
        .map_err(|err| format!("s3 connectivity check failed: {err}"))?;
    if response.status().is_server_error() {
        return Err(format!("s3 server error status {}", response.status()));
    }
    Ok(format!(
        "s3 endpoint reachable (status {})",
        response.status()
    ))
}

async fn test_http_target(target: &ExternalBackupTarget) -> Result<String, String> {
    let endpoint = parse_target_url(&target.endpoint)?;
    let client = build_http_client(target.timeout_seconds())?;
    let mut request = client.head(endpoint);
    if let Some(headers) = target.headers.as_ref() {
        for (name, value) in headers {
            request = request.header(name, value);
        }
    }
    let response = request
        .send()
        .await
        .map_err(|err| format!("http connectivity check failed: {err}"))?;
    if response.status().is_server_error() {
        return Err(format!(
            "http endpoint returned server error status {}",
            response.status()
        ));
    }
    Ok(format!(
        "http endpoint reachable (status {})",
        response.status()
    ))
}

impl ArchiveFormat {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "tar" => Some(Self::Tar),
            "tar.gz" => Some(Self::TarGz),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tar => "tar",
            Self::TarGz => "tar.gz",
        }
    }

    pub fn content_type(self) -> &'static str {
        match self {
            Self::Tar => "application/x-tar",
            Self::TarGz => "application/gzip",
        }
    }
}

pub fn is_valid_snapshot_trigger(trigger_kind: &str) -> bool {
    matches!(
        trigger_kind,
        "hourly" | "daily" | "weekly" | "monthly" | "on_create_change" | "on_demand"
    )
}

pub fn is_valid_backup_type(value: &str) -> bool {
    matches!(value, "full" | "incremental" | "differential")
}

pub fn is_valid_backup_schedule(value: &str) -> bool {
    matches!(
        value,
        "hourly" | "daily" | "weekly" | "monthly" | "on_demand"
    )
}

pub fn is_valid_backup_strategy(value: &str) -> bool {
    matches!(value, "3-2-1" | "3-2-1-1-0" | "4-3-2")
}

pub fn normalize_backup_scope(value: &str) -> Option<&'static str> {
    match value {
        "master" => Some("master"),
        "replica" | "slave" => Some("replica"),
        _ => None,
    }
}

pub fn is_valid_backup_scope(value: &str) -> bool {
    normalize_backup_scope(value).is_some()
}

pub fn is_due(last_run: Option<DateTime<Utc>>, schedule_kind: &str, now: DateTime<Utc>) -> bool {
    let Some(last) = last_run else {
        return schedule_kind != "on_demand";
    };
    let threshold = match schedule_kind {
        "hourly" => Duration::hours(1),
        "daily" => Duration::days(1),
        "weekly" => Duration::weeks(1),
        "monthly" => Duration::days(30),
        _ => return false,
    };
    last + threshold <= now
}

pub fn backup_policy_matches_runner(policy: &BackupPolicy, mode: &str, node_id: Uuid) -> bool {
    let Some(normalized_mode) = normalize_backup_scope(mode) else {
        return false;
    };
    let Some(normalized_scope) = normalize_backup_scope(policy.scope.as_str()) else {
        return false;
    };
    if normalized_mode == "master" {
        return normalized_scope == "master";
    }
    if normalized_mode != "replica" || normalized_scope != "replica" {
        return false;
    }
    policy.node_id.is_none_or(|value| value == node_id)
}

pub async fn run_backup_policy_once(
    state: &AppState,
    policy: &BackupPolicy,
    trigger_kind: &str,
) -> Result<BackupRun, String> {
    let backup_bucket = load_backup_bucket(state, policy.backup_bucket_id).await?;
    if !backup_bucket.is_worm {
        return Err("backup bucket must be WORM-enabled".into());
    }
    let snapshot_trigger = snapshot_trigger_for_backup_type(&policy.backup_type)?;
    let snapshot = state
        .repo
        .create_bucket_snapshot(policy.source_bucket_id, snapshot_trigger, None)
        .await
        .map_err(|err| format!("snapshot failed: {err}"))?;
    let changed_since = backup_changed_since(state, policy).await?;
    let run = state
        .repo
        .create_backup_run(
            policy.id,
            Some(snapshot.id),
            policy.backup_type.as_str(),
            changed_since,
            trigger_kind,
            "tar.gz",
        )
        .await
        .map_err(|err| format!("run create failed: {err}"))?;
    execute_backup_run(state, policy, &snapshot, run).await
}

async fn backup_changed_since(
    state: &AppState,
    policy: &BackupPolicy,
) -> Result<Option<DateTime<Utc>>, String> {
    if policy.backup_type == "full" {
        return Ok(None);
    }
    let runs = state
        .repo
        .list_backup_runs_for_policy(policy.id)
        .await
        .map_err(|err| format!("run list failed: {err}"))?;
    let successful: Vec<BackupRun> = runs
        .into_iter()
        .filter(|run| run.status == "success")
        .collect();
    if successful.is_empty() {
        return Ok(None);
    }
    if policy.backup_type == "incremental" {
        return Ok(Some(successful[0].started_at));
    }
    if policy.backup_type == "differential" {
        return Ok(successful.last().map(|run| run.started_at));
    }
    Ok(None)
}

async fn load_backup_bucket(state: &AppState, backup_bucket_id: Uuid) -> Result<Bucket, String> {
    state
        .repo
        .get_bucket_by_id(backup_bucket_id)
        .await
        .map_err(|err| format!("bucket lookup failed: {err}"))?
        .ok_or_else(|| "backup bucket not found".to_string())
}

fn snapshot_trigger_for_backup_type(backup_type: &str) -> Result<&'static str, String> {
    match backup_type {
        "full" => Ok("backup_full"),
        "incremental" => Ok("backup_incremental"),
        "differential" => Ok("backup_differential"),
        _ => Err("unsupported backup type".into()),
    }
}

async fn execute_backup_run(
    state: &AppState,
    policy: &BackupPolicy,
    snapshot: &BucketSnapshot,
    run: BackupRun,
) -> Result<BackupRun, String> {
    let bytes = match build_backup_archive(state, snapshot, run.changed_since).await {
        Ok(bytes) => bytes,
        Err(err) => return fail_backup_run(state, run.id, err).await,
    };
    let object_key = backup_archive_key(policy.id, run.id, Utc::now());
    if let Err(err) = persist_backup_archive(
        state,
        policy,
        &object_key,
        &bytes,
        ArchiveFormat::TarGz.content_type(),
    )
    .await
    {
        return fail_backup_run(state, run.id, err).await;
    }
    complete_backup_run(state, policy, run.id, &object_key, bytes.len() as i64).await
}

async fn build_backup_archive(
    state: &AppState,
    snapshot: &BucketSnapshot,
    changed_since: Option<DateTime<Utc>>,
) -> Result<Vec<u8>, String> {
    build_snapshot_archive(state, snapshot, ArchiveFormat::TarGz, changed_since).await
}

async fn fail_backup_run(
    state: &AppState,
    run_id: Uuid,
    error_text: String,
) -> Result<BackupRun, String> {
    let _ = state
        .repo
        .complete_backup_run_failure(run_id, &error_text)
        .await;
    Err(error_text)
}

async fn persist_backup_archive(
    state: &AppState,
    policy: &BackupPolicy,
    object_key: &str,
    bytes: &[u8],
    content_type: &str,
) -> Result<(), String> {
    let store_result = store_backup_archive(
        state,
        policy.backup_bucket_id,
        object_key,
        bytes,
        content_type,
    )
    .await;
    store_result?;
    upload_external_targets(policy, object_key, bytes, content_type).await
}

async fn complete_backup_run(
    state: &AppState,
    policy: &BackupPolicy,
    run_id: Uuid,
    object_key: &str,
    size_bytes: i64,
) -> Result<BackupRun, String> {
    state
        .repo
        .complete_backup_run_success(run_id, object_key, size_bytes)
        .await
        .map_err(|err| format!("run complete failed: {err}"))?;
    state
        .repo
        .touch_backup_policy_run(policy.id, Utc::now())
        .await
        .map_err(|err| format!("policy touch failed: {err}"))?;
    apply_backup_retention(state, policy).await?;
    load_completed_backup_run(state, run_id).await
}

async fn load_completed_backup_run(state: &AppState, run_id: Uuid) -> Result<BackupRun, String> {
    #[cfg(test)]
    if backup_failpoint(4) {
        return Err(map_run_lookup_error(sqlx::Error::Protocol(
            "forced lookup failure".to_string(),
        )));
    }
    state
        .repo
        .get_backup_run(run_id)
        .await
        .map_err(map_run_lookup_error)?
        .ok_or("backup run not found".to_string())
}

fn backup_archive_key(policy_id: Uuid, run_id: Uuid, now: DateTime<Utc>) -> String {
    format!(
        "nss-backups/{}/{}/{}.tar.gz",
        policy_id,
        now.format("%Y%m%dT%H%M%SZ"),
        run_id
    )
}

async fn store_backup_archive(
    state: &AppState,
    backup_bucket_id: Uuid,
    object_key: &str,
    bytes: &[u8],
    content_type: &str,
) -> Result<(), String> {
    let chunk_id = write_backup_chunk(state, bytes).await?;
    let etag = backup_archive_etag(bytes);
    state
        .repo
        .finalize_object_version(
            backup_bucket_id,
            object_key,
            &Uuid::new_v4().to_string(),
            bytes.len() as i64,
            &etag,
            Some(content_type),
            &serde_json::json!({ "nss_backup": true }),
            &serde_json::json!({}),
            &[chunk_id],
            false,
        )
        .await
        .map_err(|err| format!("archive finalize failed: {err}"))
        .map(|_| ())
}

async fn write_backup_chunk(state: &AppState, bytes: &[u8]) -> Result<Uuid, String> {
    state
        .replication
        .write_chunk(bytes)
        .await
        .map_err(|err| format!("chunk write failed: {err}"))
        .map(|(chunk_id, _)| chunk_id)
}

fn backup_archive_etag(bytes: &[u8]) -> String {
    format!("{:x}", Md5::digest(bytes))
}

async fn upload_external_targets(
    policy: &BackupPolicy,
    object_key: &str,
    bytes: &[u8],
    content_type: &str,
) -> Result<(), String> {
    let targets = parse_external_targets(&policy.external_targets_json)?;
    for target in targets {
        if !target.is_enabled() {
            continue;
        }
        upload_external_target(&target, object_key, bytes, content_type)
            .await
            .map_err(|err| format!("external target '{}': {err}", target.name))?;
    }
    Ok(())
}

fn reject_direct_scheme(target: &ExternalBackupTarget) -> Result<(), String> {
    match target.kind {
        ExternalTargetKind::Sftp if target_uses_sftp_scheme(target)? => {
            Err("direct sftp push is not available; use an http(s) sftp gateway endpoint".into())
        }
        ExternalTargetKind::Ssh if target_uses_ssh_scheme(target)? => {
            Err("direct ssh push is not available; use an http(s) ssh gateway endpoint".into())
        }
        _ => Ok(()),
    }
}

async fn upload_external_target(
    target: &ExternalBackupTarget,
    object_key: &str,
    bytes: &[u8],
    content_type: &str,
) -> Result<(), String> {
    reject_direct_scheme(target)?;
    match target.kind {
        ExternalTargetKind::S3 | ExternalTargetKind::Glacier => {
            upload_s3_target(target, object_key, bytes, content_type).await
        }
        _ => upload_http_target(target, object_key, bytes, content_type).await,
    }
}

fn sign_s3_request(
    target: &ExternalBackupTarget,
    method: &str,
    uri_path: &str,
    host: &str,
    content_type: &str,
    payload_hash: &str,
    now: DateTime<Utc>,
) -> String {
    build_sigv4_authorization(
        method,
        uri_path,
        host,
        content_type,
        payload_hash,
        target.access_key_id.as_deref().unwrap_or_default(),
        target.secret_access_key.as_deref().unwrap_or_default(),
        target.region.as_deref().unwrap_or_default(),
        s3_service_name(target),
        now,
    )
}

fn build_signed_s3_put(
    target: &ExternalBackupTarget,
    url: reqwest::Url,
    host: &str,
    uri_path: &str,
    content_type: &str,
    bytes: &[u8],
) -> Result<reqwest::RequestBuilder, String> {
    let now = Utc::now();
    let hash = hex_sha256(bytes);
    let auth = sign_s3_request(target, "PUT", uri_path, host, content_type, &hash, now);
    let stamp = now.format("%Y%m%dT%H%M%SZ").to_string();
    let client = build_http_client(target.timeout_seconds())?;
    let mut req = client
        .put(url)
        .header("Host", host)
        .header("Content-Type", content_type)
        .header("x-amz-date", &stamp)
        .header("x-amz-content-sha256", &hash)
        .header("Authorization", &auth)
        .body(bytes.to_vec());
    if target.kind == ExternalTargetKind::Glacier {
        req = req.header("x-amz-storage-class", "GLACIER");
    }
    Ok(req)
}

async fn upload_s3_target(
    target: &ExternalBackupTarget,
    object_key: &str,
    bytes: &[u8],
    content_type: &str,
) -> Result<(), String> {
    let bucket = s3_bucket_name(target);
    let s3_url = build_s3_object_url(&target.endpoint, bucket, object_key)?;
    let (parsed, host, uri_path) = parse_s3_url(&s3_url)?;
    let req = build_signed_s3_put(target, parsed, &host, &uri_path, content_type, bytes)?;
    let resp = req
        .send()
        .await
        .map_err(|e| format!("s3 push failed: {e}"))?;
    if resp.status().is_success() {
        return Ok(());
    }
    Err(format!("s3 push returned status {}", resp.status()))
}

fn build_s3_object_url(endpoint: &str, bucket: &str, object_key: &str) -> Result<String, String> {
    let base = endpoint.trim_end_matches('/');
    let encoded_key = encode_object_key(object_key);
    Ok(format!("{base}/{bucket}/{encoded_key}"))
}

fn hex_sha256(data: &[u8]) -> String {
    use sha2::Digest as Sha2Digest;
    let hash = Sha256::digest(data);
    hex::encode(hash)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[allow(clippy::too_many_arguments)]
fn build_sigv4_authorization(
    method: &str,
    uri_path: &str,
    host: &str,
    content_type: &str,
    payload_hash: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    now: DateTime<Utc>,
) -> String {
    let ds = now.format("%Y%m%d").to_string();
    let ad = now.format("%Y%m%dT%H%M%SZ").to_string();
    let scope = format!("{ds}/{region}/{service}/aws4_request");
    let signed = "content-type;host;x-amz-content-sha256;x-amz-date";
    let hdr = format!(
        "content-type:{content_type}\nhost:{host}\n\
         x-amz-content-sha256:{payload_hash}\nx-amz-date:{ad}\n"
    );
    let cr = format!("{method}\n{uri_path}\n\n{hdr}\n{signed}\n{payload_hash}");
    let hash = hex_sha256(cr.as_bytes());
    let sts = format!("AWS4-HMAC-SHA256\n{ad}\n{scope}\n{hash}");
    let key = derive_signing_key(secret_key, &ds, region, service);
    let sig = hex::encode(hmac_sha256(&key, sts.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, \
         SignedHeaders={signed}, Signature={sig}"
    )
}

fn derive_signing_key(secret_key: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(
        format!("AWS4{secret_key}").as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

async fn upload_http_target(
    target: &ExternalBackupTarget,
    object_key: &str,
    bytes: &[u8],
    content_type: &str,
) -> Result<(), String> {
    let url = resolve_target_url(target, object_key)?;
    let method = parse_upload_method(target)?;
    let client = build_http_client(target.timeout_seconds())?;
    let mut request = client
        .request(method, url)
        .header("Content-Type", content_type)
        .header("X-NSS-Backup-Object-Key", object_key)
        .body(bytes.to_vec());
    request = apply_target_headers(request, target);
    let response = request
        .send()
        .await
        .map_err(|err| format!("http push failed: {err}"))?;
    if response.status().is_success() {
        return Ok(());
    }
    Err(format!("http push returned status {}", response.status()))
}

fn apply_target_headers(
    mut request: reqwest::RequestBuilder,
    target: &ExternalBackupTarget,
) -> reqwest::RequestBuilder {
    if let Some(headers) = target.headers.as_ref() {
        for (name, value) in headers {
            request = request.header(name, value);
        }
    }
    request
}

fn build_http_client(timeout_seconds: u64) -> Result<reqwest::Client, String> {
    #[cfg(test)]
    if backup_failpoint(1) {
        return Err("http client build failed: failpoint".to_string());
    }
    reqwest::Client::builder()
        .timeout(TokioDuration::from_secs(timeout_seconds))
        .build()
        .map_err(map_http_client_build_error)
}

fn map_http_client_build_error(err: reqwest::Error) -> String {
    format!("http client build failed: {err}")
}

async fn run_sftp_connect(timeout_seconds: u64, address: String) -> Result<(), String> {
    #[cfg(test)]
    let connect_future = async move {
        if backup_failpoint(2) {
            return std::future::pending::<Result<(), std::io::Error>>().await;
        }
        TcpStream::connect(address).await.map(|_| ())
    };
    #[cfg(not(test))]
    let connect_future = async move { TcpStream::connect(address).await.map(|_| ()) };

    timeout(TokioDuration::from_secs(timeout_seconds), connect_future)
        .await
        .map_err(map_sftp_timeout_error)?
        .map_err(map_sftp_connect_error)
}

fn map_sftp_timeout_error(_: tokio::time::error::Elapsed) -> String {
    "sftp connectivity check timed out".to_string()
}

fn map_sftp_connect_error(err: std::io::Error) -> String {
    format!("sftp connectivity check failed: {err}")
}

async fn run_ssh_connect(timeout_seconds: u64, address: String) -> Result<(), String> {
    #[cfg(test)]
    let connect_future = async move {
        if backup_failpoint(2) {
            return std::future::pending::<Result<(), std::io::Error>>().await;
        }
        TcpStream::connect(address).await.map(|_| ())
    };
    #[cfg(not(test))]
    let connect_future = async move { TcpStream::connect(address).await.map(|_| ()) };

    timeout(TokioDuration::from_secs(timeout_seconds), connect_future)
        .await
        .map_err(map_ssh_timeout_error)?
        .map_err(map_ssh_connect_error)
}

fn map_ssh_timeout_error(_: tokio::time::error::Elapsed) -> String {
    "ssh connectivity check timed out".to_string()
}

fn map_ssh_connect_error(err: std::io::Error) -> String {
    format!("ssh connectivity check failed: {err}")
}

fn map_run_lookup_error(err: sqlx::Error) -> String {
    format!("run lookup failed: {err}")
}

fn parse_upload_method(target: &ExternalBackupTarget) -> Result<reqwest::Method, String> {
    let method = target
        .method
        .as_deref()
        .unwrap_or("PUT")
        .trim()
        .to_ascii_uppercase();
    reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|_| "invalid upload method".to_string())
        .and_then(|parsed| {
            if parsed == reqwest::Method::PUT || parsed == reqwest::Method::POST {
                Ok(parsed)
            } else {
                Err("upload method must be PUT or POST".to_string())
            }
        })
}

fn resolve_target_url(
    target: &ExternalBackupTarget,
    object_key: &str,
) -> Result<reqwest::Url, String> {
    let encoded_key = encode_object_key(object_key);
    let contains_token = target.endpoint.contains("{objectKey}");
    let endpoint = target.endpoint.replace("{objectKey}", encoded_key.as_str());
    let mut url = parse_target_url(endpoint.as_str())?;
    if contains_token || !url.path().ends_with('/') {
        return Ok(url);
    }
    let base = url.path().trim_end_matches('/');
    let merged = format!("{base}/{}", encode_object_key(object_key));
    url.set_path(merged.as_str());
    Ok(url)
}

fn encode_object_key(object_key: &str) -> String {
    utf8_percent_encode(object_key, PATH_SEGMENT_ENCODE_SET).to_string()
}

fn target_uses_sftp_scheme(target: &ExternalBackupTarget) -> Result<bool, String> {
    let endpoint = parse_target_url(&target.endpoint)?;
    Ok(endpoint.scheme() == "sftp")
}

fn target_uses_ssh_scheme(target: &ExternalBackupTarget) -> Result<bool, String> {
    let endpoint = parse_target_url(&target.endpoint)?;
    Ok(endpoint.scheme() == "ssh")
}

pub async fn apply_backup_retention(state: &AppState, policy: &BackupPolicy) -> Result<(), String> {
    #[cfg(test)]
    if backup_failpoint(5) {
        return Err("retention failpoint".to_string());
    }
    let runs = state
        .repo
        .list_backup_runs_for_policy(policy.id)
        .await
        .map_err(|err| format!("run list failed: {err}"))?;
    if runs.len() <= policy.retention_count as usize {
        return Ok(());
    }
    for run in runs.into_iter().skip(policy.retention_count as usize) {
        prune_backup_run(state, policy.backup_bucket_id, &run).await?;
    }
    Ok(())
}

async fn prune_backup_run(
    state: &AppState,
    backup_bucket_id: Uuid,
    run: &BackupRun,
) -> Result<(), String> {
    if let Some(key) = run.archive_object_key.as_deref() {
        state
            .repo
            .delete_all_object_versions(backup_bucket_id, key)
            .await
            .map_err(|err| format!("archive delete failed: {err}"))?;
    }
    state
        .repo
        .delete_backup_run(run.id)
        .await
        .map_err(|err| format!("run delete failed: {err}"))?;
    Ok(())
}

pub async fn build_snapshot_archive(
    state: &AppState,
    snapshot: &BucketSnapshot,
    format: ArchiveFormat,
    changed_since: Option<DateTime<Utc>>,
) -> Result<Vec<u8>, String> {
    let bucket = state
        .repo
        .get_bucket_by_id(snapshot.bucket_id)
        .await
        .map_err(|err| format!("bucket lookup failed: {err}"))?
        .ok_or_else(|| "snapshot bucket not found".to_string())?;
    let objects = state
        .repo
        .list_snapshot_objects(snapshot.id)
        .await
        .map_err(|err| format!("snapshot object list failed: {err}"))?;
    let entries = load_archive_entries(state, &bucket, &objects, changed_since).await?;
    #[cfg(test)]
    let entries = if backup_failpoint(3) {
        vec![("bad\0path".to_string(), b"x".to_vec(), Utc::now())]
    } else {
        entries
    };
    let tar_bytes = render_tar_entries(entries)?;
    if format == ArchiveFormat::Tar {
        return Ok(tar_bytes);
    }
    compress_gzip(tar_bytes)
}

async fn load_archive_entries(
    state: &AppState,
    bucket: &Bucket,
    objects: &[BucketSnapshotObject],
    changed_since: Option<DateTime<Utc>>,
) -> Result<Vec<(String, Vec<u8>, DateTime<Utc>)>, String> {
    let mut entries = Vec::with_capacity(objects.len());
    for object in objects {
        if changed_since.is_some_and(|cutoff| object.object_created_at <= cutoff) {
            continue;
        }
        let path = sanitize_archive_path(&bucket.name, &object.object_key);
        let bytes = read_snapshot_object_payload(state, object).await?;
        entries.push((path, bytes, object.object_created_at));
    }
    Ok(entries)
}

async fn read_snapshot_object_payload(
    state: &AppState,
    object: &BucketSnapshotObject,
) -> Result<Vec<u8>, String> {
    let chunks = state
        .repo
        .get_manifest_chunks(object.manifest_id)
        .await
        .map_err(|err| format!("manifest load failed: {err}"))?;
    let mut out = Vec::new();
    for chunk in chunks {
        let checksum = load_chunk_checksum(state, chunk.chunk_id).await?;
        let bytes = state
            .replication
            .read_chunk(chunk.chunk_id, &checksum)
            .await
            .map_err(|err| format!("chunk read failed: {err}"))?;
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

async fn load_chunk_checksum(state: &AppState, chunk_id: Uuid) -> Result<Checksum, String> {
    let row = state
        .repo
        .get_chunk_checksum(chunk_id)
        .await
        .map_err(|err| format!("chunk checksum query failed: {err}"))?
        .ok_or_else(|| "chunk checksum missing".to_string())?;
    let algo = ChecksumAlgo::parse(&row.0).unwrap_or(state.config.checksum_algo);
    Ok(Checksum { algo, value: row.1 })
}

fn render_tar_entries(entries: Vec<(String, Vec<u8>, DateTime<Utc>)>) -> Result<Vec<u8>, String> {
    render_tar_entries_with_writer(MemoryWriter::default(), entries).map(MemoryWriter::into_inner)
}

fn render_tar_entries_with_writer<W: Write>(
    writer: W,
    entries: Vec<(String, Vec<u8>, DateTime<Utc>)>,
) -> Result<W, String> {
    let mut builder = Builder::new(writer);
    for (path, data, created_at) in entries {
        append_tar_entry(&mut builder, &path, &data, created_at)?;
    }
    let mut writer = builder.into_inner().map_err(map_tar_finalize_error)?;
    writer.flush().map_err(map_tar_finalize_error)?;
    Ok(writer)
}

fn append_tar_entry(
    builder: &mut Builder<impl Write>,
    path: &str,
    data: &[u8],
    created_at: DateTime<Utc>,
) -> Result<(), String> {
    let mut header = Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o600);
    header.set_mtime(created_at.timestamp() as u64);
    header.set_cksum();
    builder
        .append_data(&mut header, path, data)
        .map_err(map_tar_append_error)
}

fn compress_gzip(tar_bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    compress_gzip_with_writer(MemoryWriter::default(), &tar_bytes).map(MemoryWriter::into_inner)
}

fn compress_gzip_with_writer<W: Write>(writer: W, tar_bytes: &[u8]) -> Result<W, String> {
    let mut encoder = GzEncoder::new(writer, Compression::best());
    encoder.write_all(tar_bytes).map_err(map_gzip_write_error)?;
    let mut writer = encoder.finish().map_err(map_gzip_finish_error)?;
    writer.flush().map_err(map_gzip_finish_error)?;
    Ok(writer)
}

fn map_tar_append_error(err: std::io::Error) -> String {
    format!("tar append failed: {err}")
}

fn map_tar_finalize_error(err: std::io::Error) -> String {
    format!("tar finalize failed: {err}")
}

fn map_gzip_write_error(err: std::io::Error) -> String {
    format!("gzip write failed: {err}")
}

fn map_gzip_finish_error(err: std::io::Error) -> String {
    format!("gzip finish failed: {err}")
}

fn sanitize_archive_path(bucket_name: &str, object_key: &str) -> String {
    let clean = object_key
        .split('/')
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .collect::<Vec<_>>()
        .join("/");
    if clean.is_empty() {
        return format!("{bucket_name}/unnamed-object");
    }
    format!("{bucket_name}/{clean}")
}

pub async fn export_backup_run_archive(
    state: &AppState,
    run: &BackupRun,
    format: ArchiveFormat,
) -> Result<Vec<u8>, String> {
    let snapshot_id = run
        .snapshot_id
        .ok_or_else(|| "backup run has no snapshot source".to_string())?;
    let snapshot = state
        .repo
        .get_bucket_snapshot(snapshot_id)
        .await
        .map_err(|err| format!("snapshot lookup failed: {err}"))?
        .ok_or_else(|| "snapshot not found".to_string())?;
    build_snapshot_archive(state, &snapshot, format, run.changed_since).await
}

#[cfg(test)]
mod tests {
    use super::{
        apply_backup_retention, backup_archive_etag, backup_archive_key, backup_changed_since,
        backup_failpoint_guard, backup_policy_matches_runner, build_s3_object_url,
        build_sigv4_authorization, build_snapshot_archive, complete_backup_run, compress_gzip,
        compress_gzip_with_writer, derive_signing_key, execute_backup_run,
        export_backup_run_archive, fail_backup_run, hex_sha256, is_due, is_valid_backup_schedule,
        is_valid_backup_scope, is_valid_backup_strategy, is_valid_backup_type,
        is_valid_snapshot_trigger, load_backup_bucket, load_chunk_checksum,
        load_completed_backup_run, map_http_client_build_error, map_run_lookup_error,
        map_sftp_connect_error, map_sftp_timeout_error, map_ssh_connect_error,
        map_ssh_timeout_error, memory_writer_fail_guard, normalize_backup_scope,
        parse_external_targets, parse_upload_method, persist_backup_archive, prune_backup_run,
        read_snapshot_object_payload, render_tar_entries, render_tar_entries_with_writer,
        resolve_target_url, run_backup_policy_once, run_sftp_connect, run_ssh_connect,
        sanitize_archive_path, store_backup_archive, test_external_target_connection,
        test_http_target, test_sftp_target, test_ssh_target, upload_external_target,
        upload_external_targets, upload_http_target, write_backup_chunk, ArchiveFormat,
        ExternalBackupTarget, ExternalTargetKind, MemoryWriter,
    };
    use crate::test_support;
    use axum::http::StatusCode;
    use axum::routing::any;
    use axum::Router;
    use chrono::{Duration, Utc};
    use serde_json::json;
    use sqlx;
    use std::collections::BTreeMap;
    use std::io;
    use std::io::Write;
    use tokio::sync::oneshot;
    use uuid::Uuid;

    fn policy(scope: &str, node_id: Option<Uuid>) -> crate::meta::models::BackupPolicy {
        let now = Utc::now();
        crate::meta::models::BackupPolicy {
            id: Uuid::new_v4(),
            name: "p".to_string(),
            scope: scope.to_string(),
            node_id,
            source_bucket_id: Uuid::new_v4(),
            backup_bucket_id: Uuid::new_v4(),
            backup_type: "full".to_string(),
            schedule_kind: "daily".to_string(),
            strategy: "3-2-1".to_string(),
            retention_count: 3,
            enabled: true,
            external_targets_json: json!([]),
            last_run_at: None,
            created_by_user_id: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn target(
        kind: ExternalTargetKind,
        endpoint: &str,
        method: Option<&str>,
    ) -> ExternalBackupTarget {
        ExternalBackupTarget {
            name: "target".to_string(),
            kind,
            endpoint: endpoint.to_string(),
            enabled: Some(true),
            method: method.map(str::to_string),
            headers: None,
            timeout_seconds: Some(10),
            access_key_id: None,
            secret_access_key: None,
            region: None,
            bucket_name: None,
            vault_name: None,
            username: None,
            password: None,
        }
    }

    async fn create_user(
        state: &crate::api::AppState,
        username: &str,
    ) -> crate::meta::models::User {
        let hash = crate::auth::password::hash_password("secret").expect("hash");
        state
            .repo
            .create_user(username, Some("Backup User"), hash.as_str(), "active")
            .await
            .expect("user")
    }

    async fn create_bucket(
        state: &crate::api::AppState,
        name: &str,
        owner_user_id: Uuid,
        is_worm: bool,
    ) -> crate::meta::models::Bucket {
        let bucket = state
            .repo
            .create_bucket(name, owner_user_id)
            .await
            .expect("bucket");
        state
            .repo
            .update_bucket_worm(bucket.id, is_worm)
            .await
            .expect("worm");
        state
            .repo
            .get_bucket(name)
            .await
            .expect("load")
            .expect("bucket")
    }

    async fn seed_object(state: &crate::api::AppState, bucket_id: Uuid, key: &str, bytes: &[u8]) {
        let (chunk_id, _) = state.replication.write_chunk(bytes).await.expect("chunk");
        state
            .repo
            .finalize_object_version(
                bucket_id,
                key,
                Uuid::new_v4().to_string().as_str(),
                bytes.len() as i64,
                "etag",
                Some("text/plain"),
                &json!({}),
                &json!({}),
                &[chunk_id],
                false,
            )
            .await
            .expect("object");
    }

    async fn seed_object_with_chunk_id(
        state: &crate::api::AppState,
        bucket_id: Uuid,
        key: &str,
        bytes: &[u8],
    ) -> Uuid {
        let (chunk_id, _) = state.replication.write_chunk(bytes).await.expect("chunk");
        state
            .repo
            .finalize_object_version(
                bucket_id,
                key,
                Uuid::new_v4().to_string().as_str(),
                bytes.len() as i64,
                "etag",
                Some("text/plain"),
                &json!({}),
                &json!({}),
                &[chunk_id],
                false,
            )
            .await
            .expect("object");
        chunk_id
    }

    fn chunk_file_path(data_dir: &std::path::Path, chunk_id: Uuid) -> std::path::PathBuf {
        let hex = chunk_id.simple().to_string();
        data_dir
            .join("chunks")
            .join(&hex[0..2])
            .join(&hex[2..4])
            .join(hex)
    }

    fn policy_with(
        scope: &str,
        source_bucket_id: Uuid,
        backup_bucket_id: Uuid,
        backup_type: &str,
        retention: i32,
        external_targets_json: serde_json::Value,
    ) -> crate::meta::models::BackupPolicy {
        let now = Utc::now();
        crate::meta::models::BackupPolicy {
            id: Uuid::new_v4(),
            name: "p".to_string(),
            scope: scope.to_string(),
            node_id: None,
            source_bucket_id,
            backup_bucket_id,
            backup_type: backup_type.to_string(),
            schedule_kind: "daily".to_string(),
            strategy: "3-2-1".to_string(),
            retention_count: retention,
            enabled: true,
            external_targets_json,
            last_run_at: None,
            created_by_user_id: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn backup_policy_create_input(
        name: &str,
        source_bucket_id: Uuid,
        backup_bucket_id: Uuid,
        backup_type: &str,
    ) -> crate::meta::backup_repos::BackupPolicyCreate {
        crate::meta::backup_repos::BackupPolicyCreate {
            name: name.to_string(),
            scope: "master".to_string(),
            node_id: None,
            source_bucket_id,
            backup_bucket_id,
            backup_type: backup_type.to_string(),
            schedule_kind: "daily".to_string(),
            strategy: "3-2-1".to_string(),
            retention_count: 2,
            enabled: true,
            external_targets_json: json!([]),
            created_by_user_id: None,
        }
    }

    async fn create_repo_backup_policy(
        state: &crate::api::AppState,
        name: &str,
        source_bucket_id: Uuid,
        backup_bucket_id: Uuid,
        backup_type: &str,
    ) -> crate::meta::models::BackupPolicy {
        state
            .repo
            .create_backup_policy(&backup_policy_create_input(
                name,
                source_bucket_id,
                backup_bucket_id,
                backup_type,
            ))
            .await
            .expect("policy")
    }

    fn run_with_snapshot(snapshot_id: Uuid) -> crate::meta::models::BackupRun {
        crate::meta::models::BackupRun {
            id: Uuid::new_v4(),
            policy_id: Uuid::new_v4(),
            snapshot_id: Some(snapshot_id),
            backup_type: "full".to_string(),
            changed_since: None,
            trigger_kind: "on_demand".to_string(),
            status: "success".to_string(),
            archive_format: "tar.gz".to_string(),
            archive_object_key: Some("nss-backups/archive.tar.gz".to_string()),
            archive_size_bytes: Some(1),
            error_text: None,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
        }
    }

    async fn run_policy_and_restore(
        state: &crate::api::AppState,
        policy: &crate::meta::models::BackupPolicy,
        owner_user_id: Uuid,
        restored_bucket_name: &str,
    ) -> crate::meta::models::BackupRun {
        let run = run_backup_policy_once(state, policy, "on_demand")
            .await
            .expect("run");
        let snapshot_id = run.snapshot_id.expect("snapshot id");
        let restored = state
            .repo
            .create_bucket_from_snapshot(snapshot_id, restored_bucket_name, owner_user_id)
            .await
            .expect("restore");
        let objects = state
            .repo
            .list_objects_current(restored.id, None, None, 10)
            .await
            .expect("objects");
        assert!(!objects.is_empty());
        run
    }

    async fn assert_incremental_run_and_restore(
        state: &crate::api::AppState,
        owner_user_id: Uuid,
        source_bucket_id: Uuid,
        backup_bucket_id: Uuid,
    ) {
        let policy = create_repo_backup_policy(
            state,
            "policy-incremental",
            source_bucket_id,
            backup_bucket_id,
            "incremental",
        )
        .await;
        let baseline = run_policy_and_restore(state, &policy, owner_user_id, "restore-inc-1").await;
        seed_object(state, source_bucket_id, "inc/next.txt", b"next").await;
        let current = run_policy_and_restore(state, &policy, owner_user_id, "restore-inc-2").await;
        assert_eq!(current.changed_since, Some(baseline.started_at));
    }

    async fn assert_differential_run_and_restore(
        state: &crate::api::AppState,
        owner_user_id: Uuid,
        source_bucket_id: Uuid,
        backup_bucket_id: Uuid,
    ) {
        let policy = create_repo_backup_policy(
            state,
            "policy-differential",
            source_bucket_id,
            backup_bucket_id,
            "differential",
        )
        .await;
        let first = run_policy_and_restore(state, &policy, owner_user_id, "restore-diff-1").await;
        seed_object(state, source_bucket_id, "diff/one.txt", b"one").await;
        let _second = run_policy_and_restore(state, &policy, owner_user_id, "restore-diff-2").await;
        seed_object(state, source_bucket_id, "diff/two.txt", b"two").await;
        let third = run_policy_and_restore(state, &policy, owner_user_id, "restore-diff-3").await;
        assert_eq!(third.changed_since, Some(first.started_at));
    }

    async fn spawn_status_server(
        status: StatusCode,
    ) -> (String, tokio::task::JoinHandle<std::io::Result<()>>) {
        let app = Router::new().route("/{*path}", any(move || async move { status }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let _ = started_tx.send(());
        let handle = tokio::spawn(std::future::IntoFuture::into_future(axum::serve(
            listener, app,
        )));
        let _ = started_rx.await;
        (format!("http://{addr}/"), handle)
    }

    fn ensure_rustls_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn validates_backup_and_snapshot_enums() {
        assert!(is_valid_snapshot_trigger("on_create_change"));
        assert!(is_valid_backup_type("differential"));
        assert!(is_valid_backup_schedule("monthly"));
        assert!(is_valid_backup_strategy("3-2-1-1-0"));
        assert!(is_valid_backup_scope("replica"));
        assert!(is_valid_backup_scope("slave"));
        assert!(!is_valid_backup_scope("bad"));
    }

    #[test]
    fn normalize_backup_scope_accepts_aliases() {
        assert_eq!(normalize_backup_scope("master"), Some("master"));
        assert_eq!(normalize_backup_scope("replica"), Some("replica"));
        assert_eq!(normalize_backup_scope("slave"), Some("replica"));
        assert_eq!(normalize_backup_scope("unknown"), None);
    }

    #[test]
    fn schedule_due_checks_windows() {
        let now = Utc::now();
        assert!(is_due(None, "hourly", now));
        assert!(!is_due(None, "on_demand", now));
        assert!(is_due(Some(now - Duration::hours(2)), "hourly", now));
        assert!(!is_due(Some(now - Duration::minutes(10)), "hourly", now));
    }

    #[test]
    fn backup_policy_runner_matching_works() {
        let node_id = Uuid::new_v4();
        let master = policy("master", None);
        let replica = policy("replica", Some(node_id));
        let slave_alias = policy("slave", Some(node_id));
        let invalid_scope = policy("invalid", Some(node_id));
        assert!(backup_policy_matches_runner(&master, "master", node_id));
        assert!(!backup_policy_matches_runner(&master, "replica", node_id));
        assert!(backup_policy_matches_runner(&replica, "replica", node_id));
        assert!(backup_policy_matches_runner(&replica, "slave", node_id));
        assert!(backup_policy_matches_runner(
            &slave_alias,
            "replica",
            node_id
        ));
        assert!(!backup_policy_matches_runner(&master, "unknown", node_id));
        assert!(!backup_policy_matches_runner(
            &replica,
            "replica",
            Uuid::new_v4()
        ));
        assert!(!backup_policy_matches_runner(
            &invalid_scope,
            "replica",
            node_id
        ));
    }

    #[test]
    fn archive_format_parsing_and_metadata() {
        assert_eq!(ArchiveFormat::parse("tar"), Some(ArchiveFormat::Tar));
        assert_eq!(ArchiveFormat::parse("tar.gz"), Some(ArchiveFormat::TarGz));
        assert_eq!(ArchiveFormat::parse("zip"), None);
        assert_eq!(ArchiveFormat::Tar.content_type(), "application/x-tar");
    }

    #[test]
    fn parse_external_targets_accepts_valid_payload() {
        let parsed = parse_external_targets(&json!([
            {
                "name": "archive-s3",
                "kind": "s3",
                "endpoint": "https://s3.amazonaws.com",
                "timeoutSeconds": 10,
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "secretAccessKey": "wJalrXUtnFEMI/bPxRfiCYEXAMPLEKEY",
                "region": "us-east-1",
                "bucketName": "my-bucket"
            },
            {
                "name": "archive-sftp",
                "kind": "sftp",
                "endpoint": "sftp://backup.example.com:22/data"
            },
            {
                "name": "archive-sftp-gateway",
                "kind": "sftp",
                "endpoint": "https://gateway.example.com/sftp/upload/{objectKey}"
            },
            {
                "name": "archive-ssh",
                "kind": "ssh",
                "endpoint": "ssh://backup.example.com:22/data"
            }
        ]))
        .expect("targets");
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[0].kind, ExternalTargetKind::S3);
        assert_eq!(
            parsed[0].access_key_id.as_deref(),
            Some("AKIAIOSFODNN7EXAMPLE")
        );
        assert_eq!(parsed[0].region.as_deref(), Some("us-east-1"));
        assert_eq!(parsed[0].bucket_name.as_deref(), Some("my-bucket"));
        assert_eq!(parsed[1].kind, ExternalTargetKind::Sftp);
        assert_eq!(parsed[2].kind, ExternalTargetKind::Sftp);
        assert_eq!(parsed[3].kind, ExternalTargetKind::Ssh);
    }

    #[test]
    fn parse_external_targets_rejects_invalid_payload() {
        let err = parse_external_targets(&json!([
            {
                "name": "bad-target",
                "kind": "s3",
                "endpoint": "ftp://not-supported"
            }
        ]))
        .unwrap_err();
        assert!(err.contains("http:// or https://"));

        let err = parse_external_targets(&json!({ "not": "an-array" })).unwrap_err();
        assert!(err.contains("array of objects"));
    }

    #[test]
    fn parse_external_targets_rejects_duplicate_names() {
        let err = parse_external_targets(&json!([
            {
                "name": "dup",
                "kind": "other",
                "endpoint": "https://one.example.com"
            },
            {
                "name": "dup",
                "kind": "other",
                "endpoint": "https://two.example.com"
            }
        ]))
        .unwrap_err();
        assert!(err.contains("duplicate external target name"));
    }

    #[test]
    fn parse_external_targets_rejects_empty_name_sftp_and_ssh_scheme() {
        let empty_name = parse_external_targets(&json!([
            {
                "name": "   ",
                "kind": "other",
                "endpoint": "https://example.com"
            }
        ]))
        .unwrap_err();
        assert!(empty_name.contains("name is required"));

        let bad_sftp = parse_external_targets(&json!([
            {
                "name": "sftp",
                "kind": "sftp",
                "endpoint": "ftp://example.com"
            }
        ]))
        .unwrap_err();
        assert!(bad_sftp.contains("sftp:// or http(s)://"));
        let bad_ssh = parse_external_targets(&json!([
            {
                "name": "ssh",
                "kind": "ssh",
                "endpoint": "ftp://example.com"
            }
        ]))
        .unwrap_err();
        assert!(bad_ssh.contains("ssh:// or http(s)://"));
    }

    #[test]
    fn parse_external_targets_rejects_invalid_method_and_timeout() {
        let bad_method = parse_external_targets(&json!([
            {
                "name": "remote",
                "kind": "other",
                "endpoint": "https://backup.example.com/archive",
                "method": "PATCH"
            }
        ]))
        .unwrap_err();
        assert!(bad_method.contains("PUT or POST"));

        let bad_timeout = parse_external_targets(&json!([
            {
                "name": "remote-timeout",
                "kind": "other",
                "endpoint": "https://backup.example.com/archive",
                "timeoutSeconds": 0
            }
        ]))
        .unwrap_err();
        assert!(bad_timeout.contains("1..=120"));
    }

    #[test]
    fn parse_external_targets_rejects_s3_without_required_credentials() {
        let err = parse_external_targets(&json!([
            {
                "name": "s3-missing-creds",
                "kind": "s3",
                "endpoint": "https://s3.amazonaws.com"
            }
        ]))
        .unwrap_err();
        assert!(err.contains("s3 target requires accessKeyId"));
    }

    #[test]
    fn parse_external_targets_rejects_glacier_without_vault_name() {
        let err = parse_external_targets(&json!([
            {
                "name": "glacier-missing",
                "kind": "glacier",
                "endpoint": "https://glacier.amazonaws.com",
                "accessKeyId": "AKIA",
                "secretAccessKey": "secret",
                "region": "us-east-1"
            }
        ]))
        .unwrap_err();
        assert!(err.contains("glacier target requires vaultName"));
    }

    #[test]
    fn sigv4_signing_produces_expected_authorization_header() {
        let now = chrono::NaiveDate::from_ymd_opt(2026, 1, 15)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_utc();
        let payload_hash = hex_sha256(b"test-body");
        let auth = build_sigv4_authorization(
            "PUT",
            "/my-bucket/test.tar.gz",
            "s3.amazonaws.com",
            "application/gzip",
            &payload_hash,
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "s3",
            now,
        );
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"));
        assert!(auth.contains("20260115/us-east-1/s3/aws4_request"));
        assert!(auth.contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date"));
        assert!(auth.contains("Signature="));
    }

    #[test]
    fn build_s3_object_url_encodes_key_segments() {
        let url = build_s3_object_url(
            "https://s3.amazonaws.com",
            "my-bucket",
            "nss-backups/policy-1/run.tar.gz",
        )
        .expect("url");
        assert_eq!(
            url,
            "https://s3.amazonaws.com/my-bucket/nss-backups%2Fpolicy-1%2Frun.tar.gz"
        );
    }

    #[test]
    fn derive_signing_key_produces_deterministic_output() {
        let key1 = derive_signing_key("secret", "20260115", "us-east-1", "s3");
        let key2 = derive_signing_key("secret", "20260115", "us-east-1", "s3");
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn resolve_target_url_appends_object_key_when_endpoint_is_directory() {
        let parsed = resolve_target_url(
            &target(
                ExternalTargetKind::S3,
                "https://backup.example.com/archive/",
                None,
            ),
            "nss-backups/policy/run.tar.gz",
        )
        .expect("url");
        assert_eq!(
            parsed.as_str(),
            "https://backup.example.com/archive/nss-backups%2Fpolicy%2Frun.tar.gz"
        );
    }

    #[test]
    fn parse_upload_method_rejects_invalid_method() {
        let err = parse_upload_method(&target(
            ExternalTargetKind::Other,
            "https://backup.example.com/archive",
            Some("PATCH"),
        ))
        .unwrap_err();
        assert!(err.contains("PUT or POST"));

        let err = parse_upload_method(&target(
            ExternalTargetKind::Other,
            "https://backup.example.com/archive",
            Some("\n"),
        ))
        .unwrap_err();
        assert!(err.contains("invalid upload method"));
    }

    #[test]
    fn error_mapping_helpers_return_expected_messages() {
        let client_err = reqwest::Client::builder()
            .user_agent("\n")
            .build()
            .expect_err("client build error");
        let mapped = map_http_client_build_error(client_err);
        assert!(mapped.contains("http client build failed"));

        let connect_err = map_sftp_connect_error(io::Error::other("boom"));
        assert!(connect_err.contains("sftp connectivity check failed"));
        let ssh_connect_err = map_ssh_connect_error(io::Error::other("boom"));
        assert!(ssh_connect_err.contains("ssh connectivity check failed"));

        let lookup_err = map_run_lookup_error(sqlx::Error::RowNotFound);
        assert!(lookup_err.contains("run lookup failed"));
    }

    #[tokio::test]
    async fn sftp_timeout_error_mapper_returns_expected_message() {
        let sftp_elapsed = tokio::time::timeout(
            std::time::Duration::from_millis(1),
            std::future::pending::<()>(),
        )
        .await
        .err()
        .expect("elapsed");
        let mapped = map_sftp_timeout_error(sftp_elapsed);
        assert!(mapped.contains("timed out"));
        let ssh_elapsed = tokio::time::timeout(
            std::time::Duration::from_millis(1),
            std::future::pending::<()>(),
        )
        .await
        .err()
        .expect("elapsed");
        let ssh_mapped = map_ssh_timeout_error(ssh_elapsed);
        assert!(ssh_mapped.contains("timed out"));
    }

    #[test]
    fn resolve_target_url_replaces_object_key_placeholder() {
        let parsed = resolve_target_url(
            &target(
                ExternalTargetKind::Other,
                "https://backup.example.com/archive/{objectKey}",
                None,
            ),
            "a/b.txt",
        )
        .expect("url");
        assert_eq!(
            parsed.as_str(),
            "https://backup.example.com/archive/a%2Fb.txt"
        );
    }

    #[test]
    fn resolve_target_url_rejects_invalid_endpoint() {
        let err = resolve_target_url(
            &target(ExternalTargetKind::Other, "://invalid", None),
            "a.txt",
        )
        .unwrap_err();
        assert!(err.contains("invalid remote target endpoint URL"));
    }

    #[tokio::test]
    async fn external_target_connection_reports_parse_and_host_errors() {
        let invalid = test_external_target_connection(&target(
            ExternalTargetKind::Other,
            "://invalid-url",
            None,
        ))
        .await
        .unwrap_err();
        assert!(invalid.contains("invalid remote target endpoint URL"));

        let missing_host = test_external_target_connection(&target(
            ExternalTargetKind::Sftp,
            "sftp:///archive",
            None,
        ))
        .await
        .unwrap_err();
        assert!(missing_host.contains("missing host"));
        let ssh_missing_host = test_external_target_connection(&target(
            ExternalTargetKind::Ssh,
            "ssh:///archive",
            None,
        ))
        .await
        .unwrap_err();
        assert!(ssh_missing_host.contains("missing host"));

        let sftp_parse_error = upload_external_target(
            &target(ExternalTargetKind::Sftp, "://invalid", None),
            "archive",
            b"payload",
            "application/gzip",
        )
        .await
        .unwrap_err();
        assert!(sftp_parse_error.contains("invalid remote target endpoint URL"));
        let ssh_parse_error = upload_external_target(
            &target(ExternalTargetKind::Ssh, "://invalid", None),
            "archive",
            b"payload",
            "application/gzip",
        )
        .await
        .unwrap_err();
        assert!(ssh_parse_error.contains("invalid remote target endpoint URL"));
    }

    #[tokio::test]
    async fn upload_http_target_reports_url_and_method_errors() {
        let url_err = upload_http_target(
            &target(ExternalTargetKind::Other, "://invalid", None),
            "archive",
            b"payload",
            "application/gzip",
        )
        .await
        .unwrap_err();
        assert!(url_err.contains("invalid remote target endpoint URL"));

        let method_err = upload_http_target(
            &target(
                ExternalTargetKind::Other,
                "https://backup.example.com/archive",
                Some("\n"),
            ),
            "archive",
            b"payload",
            "application/gzip",
        )
        .await
        .unwrap_err();
        assert!(method_err.contains("invalid upload method"));
    }

    #[derive(Debug)]
    struct FailOnWrite;

    impl Write for FailOnWrite {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("write-failed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FailOnFlush;

    impl Write for FailOnFlush {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("flush-failed"))
        }
    }

    #[derive(Debug, Default)]
    struct FailOnSecondWrite {
        writes: usize,
    }

    impl Write for FailOnSecondWrite {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.writes > 0 {
                return Err(io::Error::other("second-write-failed"));
            }
            self.writes += 1;
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn tar_and_gzip_helpers_report_writer_errors() {
        let now = Utc::now();
        let tar_append_err = render_tar_entries_with_writer(
            Vec::new(),
            vec![("bad\0path".to_string(), b"x".to_vec(), now)],
        )
        .unwrap_err();
        assert!(tar_append_err.contains("tar append failed"));

        let tar_finish_err = render_tar_entries_with_writer(
            FailOnFlush,
            vec![("ok.txt".to_string(), b"x".to_vec(), now)],
        )
        .unwrap_err();
        assert!(tar_finish_err.contains("tar finalize failed"));
        let tar_finalize_err = render_tar_entries_with_writer(FailOnWrite, Vec::new()).unwrap_err();
        assert!(tar_finalize_err.contains("tar finalize failed"));

        let gzip_write_err = compress_gzip_with_writer(FailOnWrite, b"payload").unwrap_err();
        assert!(gzip_write_err.contains("gzip write failed"));
        let mut pass_flush = FailOnWrite;
        assert!(pass_flush.flush().is_ok());
        let mut second_flush = FailOnSecondWrite::default();
        assert!(second_flush.flush().is_ok());

        let gzip_finish_err = compress_gzip_with_writer(FailOnFlush, b"payload").unwrap_err();
        assert!(gzip_finish_err.contains("gzip finish failed"));
        let gzip_finish_err =
            compress_gzip_with_writer(FailOnSecondWrite::default(), b"payload").unwrap_err();
        assert!(gzip_finish_err.contains("gzip finish failed"));
    }

    #[test]
    fn render_tar_entries_with_fail_on_write_hits_append_path() {
        let now = Utc::now();
        let err = render_tar_entries_with_writer(
            FailOnWrite,
            vec![("ok.txt".to_string(), b"x".to_vec(), now)],
        )
        .unwrap_err();
        assert!(err.contains("tar append failed"));
    }

    #[test]
    fn in_memory_writer_fail_modes_cover_tar_paths() {
        let now = Utc::now();
        let _append_fail = memory_writer_fail_guard(1);
        let append_err =
            render_tar_entries(vec![("ok.txt".to_string(), b"x".to_vec(), now)]).unwrap_err();
        assert!(append_err.contains("tar append failed"));

        let _finalize_fail = memory_writer_fail_guard(1);
        let finalize_err = render_tar_entries(Vec::new()).unwrap_err();
        assert!(finalize_err.contains("tar finalize failed"));

        let _flush_fail = memory_writer_fail_guard(2);
        let flush_err =
            render_tar_entries(vec![("ok.txt".to_string(), b"x".to_vec(), now)]).unwrap_err();
        assert!(flush_err.contains("tar finalize failed"));
    }

    #[test]
    fn in_memory_writer_fail_modes_cover_gzip_paths() {
        let _write_fail = memory_writer_fail_guard(1);
        let write_err = compress_gzip(b"payload".to_vec()).unwrap_err();
        assert!(write_err.contains("gzip write failed"));

        let _finish_fail = memory_writer_fail_guard(1);
        let finish_err = compress_gzip(Vec::new()).unwrap_err();
        assert!(finish_err.contains("gzip finish failed"));

        let _flush_fail = memory_writer_fail_guard(2);
        let flush_err = compress_gzip(b"payload".to_vec()).unwrap_err();
        assert!(flush_err.contains("gzip finish failed"));
    }

    #[test]
    fn memory_writer_mode3_fails_after_first_flush() {
        let mut writer = MemoryWriter::default();
        writer.flush().expect("first flush");
        let _mode_three = memory_writer_fail_guard(3);
        let err = writer.flush().unwrap_err();
        assert!(err.to_string().contains("memory-writer-flush-failed"));
    }

    #[tokio::test]
    async fn connection_helpers_cover_sftp_ssh_parse_and_http_client_failpoints() {
        let invalid_sftp =
            test_external_target_connection(&target(ExternalTargetKind::Sftp, "://bad", None))
                .await
                .unwrap_err();
        assert!(invalid_sftp.contains("invalid remote target endpoint URL"));
        let invalid_ssh =
            test_external_target_connection(&target(ExternalTargetKind::Ssh, "://bad", None))
                .await
                .unwrap_err();
        assert!(invalid_ssh.contains("invalid remote target endpoint URL"));
        let invalid_direct = test_sftp_target(&target(ExternalTargetKind::Sftp, "://bad", None))
            .await
            .unwrap_err();
        assert!(invalid_direct.contains("invalid remote target endpoint URL"));
        let invalid_ssh_direct = test_ssh_target(&target(ExternalTargetKind::Ssh, "://bad", None))
            .await
            .unwrap_err();
        assert!(invalid_ssh_direct.contains("invalid remote target endpoint URL"));
        let _client_fail = backup_failpoint_guard(1);
        let err = test_http_target(&target(
            ExternalTargetKind::Other,
            "https://backup.example.com",
            None,
        ))
        .await
        .unwrap_err();
        assert!(err.contains("http client build failed"));
        let _client_fail = backup_failpoint_guard(1);
        let err = upload_http_target(
            &target(
                ExternalTargetKind::Other,
                "https://backup.example.com",
                None,
            ),
            "archive.tar.gz",
            b"payload",
            "application/gzip",
        )
        .await
        .unwrap_err();
        assert!(err.contains("http client build failed"));
    }

    #[tokio::test]
    async fn run_sftp_connect_timeout_failpoint_maps_timeout_error() {
        let _timeout_fail = backup_failpoint_guard(2);
        let err = run_sftp_connect(0, "127.0.0.1:1".to_string())
            .await
            .unwrap_err();
        assert!(err.contains("timed out"));
        let _timeout_fail = backup_failpoint_guard(2);
        let ssh_err = run_ssh_connect(0, "127.0.0.1:1".to_string())
            .await
            .unwrap_err();
        assert!(ssh_err.contains("timed out"));
    }

    #[tokio::test]
    async fn run_backup_policy_once_reports_missing_backup_bucket() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let owner = create_user(&state, "owner-missing-backup-bucket").await;
        let source = create_bucket(&state, "src-missing-backup-bucket", owner.id, false).await;
        let policy = policy_with("master", source.id, Uuid::new_v4(), "full", 1, json!([]));
        let err = run_backup_policy_once(&state, &policy, "on_demand")
            .await
            .unwrap_err();
        assert!(err.contains("backup bucket not found"));
    }

    async fn setup_persist_failpoint_policy(
        suffix: &str,
    ) -> (crate::api::AppState, crate::meta::models::BackupPolicy) {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let owner = create_user(&state, format!("owner-{suffix}").as_str()).await;
        let source = create_bucket(&state, format!("src-{suffix}").as_str(), owner.id, false).await;
        let backup_bucket =
            create_bucket(&state, format!("dst-{suffix}").as_str(), owner.id, true).await;
        let policy = create_repo_backup_policy(
            &state,
            format!("policy-{suffix}").as_str(),
            source.id,
            backup_bucket.id,
            "full",
        )
        .await;
        (state, policy)
    }

    #[tokio::test]
    async fn persist_backup_archive_maps_chunk_write_failpoint_error() {
        let (state, policy) = setup_persist_failpoint_policy("persist-failpoint").await;
        let _write_failpoint = crate::storage::chunkstore::failpoint_guard(2);
        let err = persist_backup_archive(
            &state,
            &policy,
            "archive.tar.gz",
            b"payload",
            "application/gzip",
        )
        .await
        .unwrap_err();
        assert!(err.contains("chunk write failed"));
    }

    #[tokio::test]
    async fn complete_backup_run_maps_lookup_failpoint_error() {
        let (state, policy) = setup_persist_failpoint_policy("lookup-failpoint").await;
        let run = state
            .repo
            .create_backup_run(policy.id, None, "full", None, "on_demand", "tar.gz")
            .await
            .expect("run");
        let _lookup_failpoint = backup_failpoint_guard(4);
        let err = complete_backup_run(&state, &policy, run.id, "archive.tar.gz", 1)
            .await
            .unwrap_err();
        assert!(err.contains("run lookup failed"));
    }

    #[tokio::test]
    async fn complete_backup_run_maps_retention_failure_with_failpoint() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let owner = create_user(&state, "owner-retention-failpoint").await;
        let source = create_bucket(&state, "src-retention-failpoint", owner.id, false).await;
        let backup_bucket = create_bucket(&state, "dst-retention-failpoint", owner.id, true).await;
        let policy = create_repo_backup_policy(
            &state,
            "policy-retention-failpoint",
            source.id,
            backup_bucket.id,
            "full",
        )
        .await;
        let run = state
            .repo
            .create_backup_run(policy.id, None, "full", None, "on_demand", "tar.gz")
            .await
            .expect("run");
        let _retention_failpoint = backup_failpoint_guard(5);
        let err = complete_backup_run(&state, &policy, run.id, "archive.tar.gz", 1)
            .await
            .unwrap_err();
        assert!(err.contains("retention failpoint"));
    }

    #[tokio::test]
    async fn apply_backup_retention_maps_prune_errors() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let owner = create_user(&state, "owner-retention-prune-error").await;
        let source = create_bucket(&state, "src-retention-prune-error", owner.id, false).await;
        let backup_bucket =
            create_bucket(&state, "dst-retention-prune-error", owner.id, true).await;
        let policy = create_retention_policy(&state, source.id, backup_bucket.id).await;
        seed_object(&state, backup_bucket.id, "archive-old.tar.gz", b"old").await;
        let run = create_successful_backup_run(&state, policy.id, "archive-old.tar.gz").await;
        let _next = create_successful_backup_run(&state, policy.id, "archive-new.tar.gz").await;
        let fail = crate::test_support::FailTriggerGuard::create(
            state.repo.pool(),
            "object_versions",
            "BEFORE",
            "DELETE",
        )
        .await
        .expect("failpoint");
        let persisted = state
            .repo
            .get_backup_run(run.id)
            .await
            .expect("run")
            .expect("run");
        let err = apply_backup_retention(&state, &policy).await.unwrap_err();
        assert!(err.contains("archive delete failed"));
        assert_eq!(
            persisted.archive_object_key.as_deref(),
            Some("archive-old.tar.gz")
        );
        fail.remove().await.expect("remove failpoint");
    }

    #[tokio::test]
    async fn build_snapshot_archive_maps_entry_and_render_errors() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let owner = create_user(&state, "owner-archive-build-errors").await;
        let source = create_bucket(&state, "src-archive-build-errors", owner.id, false).await;
        let chunk_id = seed_object_with_chunk_id(&state, source.id, "bad/chunk.txt", b"body").await;
        let snapshot = state
            .repo
            .create_bucket_snapshot(source.id, "on_demand", None)
            .await
            .expect("snapshot");
        let path = chunk_file_path(&state.config.data_dirs[0], chunk_id);
        tokio::fs::remove_file(path).await.expect("remove chunk");
        let err = build_snapshot_archive(&state, &snapshot, ArchiveFormat::Tar, None)
            .await
            .unwrap_err();
        assert!(err.contains("chunk read failed"));

        let empty = create_bucket(&state, "src-archive-render-error", owner.id, false).await;
        let snapshot = state
            .repo
            .create_bucket_snapshot(empty.id, "on_demand", None)
            .await
            .expect("snapshot");
        let _render_failpoint = backup_failpoint_guard(3);
        let err = build_snapshot_archive(&state, &snapshot, ArchiveFormat::Tar, None)
            .await
            .unwrap_err();
        assert!(err.contains("tar append failed"));
    }

    #[test]
    fn schedule_due_checks_daily_weekly_monthly_and_unknown() {
        let now = Utc::now();
        assert!(is_due(Some(now - Duration::days(2)), "daily", now));
        assert!(is_due(Some(now - Duration::weeks(2)), "weekly", now));
        assert!(is_due(Some(now - Duration::days(31)), "monthly", now));
        assert!(!is_due(Some(now - Duration::days(400)), "unknown", now));
    }

    #[tokio::test]
    async fn run_backup_policy_once_and_export_archive_succeeds() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let owner = create_user(&state, "owner-backup").await;
        let source = create_bucket(&state, "src-backup", owner.id, false).await;
        let backup_bucket = create_bucket(&state, "dst-backup", owner.id, true).await;
        seed_object(&state, source.id, "docs/a.txt", b"payload").await;
        let policy =
            create_repo_backup_policy(&state, "policy", source.id, backup_bucket.id, "full").await;
        let run = run_backup_policy_once(&state, &policy, "on_demand")
            .await
            .expect("run");
        let tar = export_backup_run_archive(&state, &run, ArchiveFormat::Tar)
            .await
            .expect("tar");
        let tgz = export_backup_run_archive(&state, &run, ArchiveFormat::TarGz)
            .await
            .expect("tar.gz");
        assert_eq!(run.status, "success");
        assert!(!tar.is_empty());
        assert!(!tgz.is_empty());
    }

    async fn assert_connection_helpers_cover_disabled_sftp_and_ssh() {
        let disabled = ExternalBackupTarget {
            enabled: Some(false),
            ..target(
                ExternalTargetKind::Other,
                "https://backup.example.com/archive",
                None,
            )
        };
        let msg = test_external_target_connection(&disabled)
            .await
            .expect("disabled");
        assert!(msg.contains("disabled"));

        let err = test_external_target_connection(&target(
            ExternalTargetKind::Sftp,
            "sftp://127.0.0.1:1/upload",
            None,
        ))
        .await
        .unwrap_err();
        let connectivity_error = err.contains("connectivity check failed");
        let timeout_error = err.contains("timed out");
        assert!(connectivity_error | timeout_error);
        let ssh_err = test_external_target_connection(&target(
            ExternalTargetKind::Ssh,
            "ssh://127.0.0.1:1/upload",
            None,
        ))
        .await
        .unwrap_err();
        let ssh_connectivity_error = ssh_err.contains("connectivity check failed");
        let ssh_timeout_error = ssh_err.contains("timed out");
        assert!(ssh_connectivity_error | ssh_timeout_error);
    }

    async fn assert_http_upload_server_error_path() {
        let (error_url, error_handle) =
            spawn_status_server(StatusCode::INTERNAL_SERVER_ERROR).await;
        let err = upload_http_target(
            &target(ExternalTargetKind::Other, error_url.as_str(), Some("PUT")),
            "archive.tar.gz",
            b"payload",
            "application/gzip",
        )
        .await
        .unwrap_err();
        assert!(err.contains("status"));
        error_handle.abort();
    }

    #[tokio::test]
    async fn target_connectivity_and_upload_helpers_cover_branches() {
        ensure_rustls_provider();
        assert_connection_helpers_cover_disabled_sftp_and_ssh().await;
        assert_http_upload_server_error_path().await;
    }

    #[tokio::test]
    async fn target_connectivity_covers_sftp_ssh_success_and_http_headers() {
        ensure_rustls_provider();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let sftp = target(
            ExternalTargetKind::Sftp,
            format!("sftp://{addr}/upload").as_str(),
            None,
        );
        let message = test_external_target_connection(&sftp).await.expect("sftp");
        assert!(message.contains("reachable"));
        let accept_result = tokio::time::timeout(std::time::Duration::from_secs(1), accept).await;
        assert!(accept_result.is_ok());
        let ssh_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let ssh_addr = ssh_listener.local_addr().expect("addr");
        let ssh_accept = tokio::spawn(async move {
            let _ = ssh_listener.accept().await;
        });
        let ssh = target(
            ExternalTargetKind::Ssh,
            format!("ssh://{ssh_addr}/upload").as_str(),
            None,
        );
        let ssh_message = test_external_target_connection(&ssh).await.expect("ssh");
        assert!(ssh_message.contains("reachable"));
        let ssh_accept_result =
            tokio::time::timeout(std::time::Duration::from_secs(1), ssh_accept).await;
        assert!(ssh_accept_result.is_ok());

        let (url, handle) = spawn_status_server(StatusCode::INTERNAL_SERVER_ERROR).await;
        let mut headers = BTreeMap::new();
        headers.insert("X-NSS-Test".to_string(), "1".to_string());
        let endpoint = format!("{url}/connectivity");
        let http = ExternalBackupTarget {
            headers: Some(headers),
            ..target(ExternalTargetKind::Other, endpoint.as_str(), None)
        };
        let err = test_external_target_connection(&http).await.unwrap_err();
        assert!(err.contains("server error status"));
        handle.abort();
    }

    #[tokio::test]
    async fn target_connectivity_sftp_kind_with_http_gateway_uses_http_probe() {
        ensure_rustls_provider();
        let (url, handle) = spawn_status_server(StatusCode::NO_CONTENT).await;
        let target = ExternalBackupTarget {
            kind: ExternalTargetKind::Sftp,
            ..target(
                ExternalTargetKind::Other,
                format!("{url}gateway").as_str(),
                None,
            )
        };
        let message = test_external_target_connection(&target)
            .await
            .expect("message");
        assert!(message.contains("http endpoint reachable"));
        handle.abort();
    }

    #[tokio::test]
    async fn target_connectivity_ssh_kind_with_http_gateway_uses_http_probe() {
        ensure_rustls_provider();
        let (url, handle) = spawn_status_server(StatusCode::NO_CONTENT).await;
        let target = ExternalBackupTarget {
            kind: ExternalTargetKind::Ssh,
            ..target(
                ExternalTargetKind::Other,
                format!("{url}gateway").as_str(),
                None,
            )
        };
        let message = test_external_target_connection(&target)
            .await
            .expect("message");
        assert!(message.contains("http endpoint reachable"));
        handle.abort();
    }

    fn policy_with_disabled_external_target() -> crate::meta::models::BackupPolicy {
        policy_with(
            "master",
            Uuid::new_v4(),
            Uuid::new_v4(),
            "full",
            1,
            json!([{
                "name": "disabled",
                "kind": "other",
                "endpoint": "https://backup.example.com/archive",
                "enabled": false
            }]),
        )
    }

    async fn assert_direct_sftp_upload_is_rejected() {
        let err = upload_external_target(
            &target(
                ExternalTargetKind::Sftp,
                "sftp://backup.example.com/upload",
                None,
            ),
            "archive",
            b"payload",
            "application/gzip",
        )
        .await
        .unwrap_err();
        assert!(err.contains("direct sftp push is not available"));
    }

    async fn assert_direct_ssh_upload_is_rejected() {
        let err = upload_external_target(
            &target(
                ExternalTargetKind::Ssh,
                "ssh://backup.example.com/upload",
                None,
            ),
            "archive",
            b"payload",
            "application/gzip",
        )
        .await
        .unwrap_err();
        assert!(err.contains("direct ssh push is not available"));
    }

    #[tokio::test]
    async fn upload_external_targets_skips_disabled_and_rejects_direct_transports() {
        let policy_disabled = policy_with_disabled_external_target();
        upload_external_targets(&policy_disabled, "archive", b"payload", "application/gzip")
            .await
            .expect("disabled");
        assert_direct_sftp_upload_is_rejected().await;
        assert_direct_ssh_upload_is_rejected().await;
    }

    #[tokio::test]
    async fn upload_external_targets_reports_invalid_target_json() {
        let policy = policy_with(
            "master",
            Uuid::new_v4(),
            Uuid::new_v4(),
            "full",
            1,
            json!({}),
        );
        let err = upload_external_targets(&policy, "archive", b"payload", "application/gzip")
            .await
            .unwrap_err();
        assert!(err.contains("external targets must be an array of objects"));
    }

    #[tokio::test]
    async fn upload_external_target_sftp_ssh_gateway_and_other_paths() {
        ensure_rustls_provider();
        let (url, handle) = spawn_status_server(StatusCode::NO_CONTENT).await;
        let mut headers = BTreeMap::new();
        headers.insert("X-Trace".to_string(), "gateway".to_string());
        let sftp_gateway = ExternalBackupTarget {
            kind: ExternalTargetKind::Sftp,
            endpoint: url.clone(),
            headers: Some(headers),
            ..target(
                ExternalTargetKind::Sftp,
                "https://unused.invalid",
                Some("POST"),
            )
        };
        upload_external_target(&sftp_gateway, "archive", b"payload", "application/gzip")
            .await
            .expect("gateway");
        let ssh_gateway = ExternalBackupTarget {
            kind: ExternalTargetKind::Ssh,
            endpoint: url.clone(),
            ..target(
                ExternalTargetKind::Ssh,
                "https://unused.invalid",
                Some("PUT"),
            )
        };
        upload_external_target(&ssh_gateway, "archive", b"payload", "application/gzip")
            .await
            .expect("ssh gateway");
        let other = target(ExternalTargetKind::Other, url.as_str(), Some("PUT"));
        upload_external_target(&other, "archive", b"payload", "application/gzip")
            .await
            .expect("other");
        handle.abort();
    }

    #[tokio::test]
    async fn run_backup_policy_once_rejects_non_worm_and_invalid_type() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let owner = create_user(&state, "owner-backup-2").await;
        let source = create_bucket(&state, "src-backup-2", owner.id, false).await;
        let backup_bucket = create_bucket(&state, "dst-backup-2", owner.id, false).await;
        let non_worm = policy_with("master", source.id, backup_bucket.id, "full", 1, json!([]));
        let err = run_backup_policy_once(&state, &non_worm, "on_demand")
            .await
            .unwrap_err();
        assert!(err.contains("WORM"));
        state
            .repo
            .update_bucket_worm(backup_bucket.id, true)
            .await
            .expect("worm");
        let unsupported = policy_with("master", source.id, backup_bucket.id, "delta", 1, json!([]));
        let err = run_backup_policy_once(&state, &unsupported, "on_demand")
            .await
            .unwrap_err();
        assert!(err.contains("unsupported backup type"));
    }

    #[tokio::test]
    async fn backup_lookup_helpers_report_repo_and_not_found_errors() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let missing = load_backup_bucket(&state, Uuid::new_v4())
            .await
            .unwrap_err();
        assert!(missing.contains("backup bucket not found"));

        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let policy = policy_with(
            "master",
            Uuid::new_v4(),
            Uuid::new_v4(),
            "incremental",
            1,
            json!([]),
        );
        let changed_err = backup_changed_since(&broken, &policy).await.unwrap_err();
        assert!(changed_err.contains("run list failed"));

        let retention_err = apply_backup_retention(&broken, &policy).await.unwrap_err();
        assert!(retention_err.contains("run list failed"));

        let snapshot = crate::meta::models::BucketSnapshot {
            id: Uuid::new_v4(),
            bucket_id: Uuid::new_v4(),
            trigger_kind: "on_demand".to_string(),
            created_by_user_id: None,
            object_count: 0,
            total_size_bytes: 0,
            created_at: Utc::now(),
        };
        let archive_err = build_snapshot_archive(&broken, &snapshot, ArchiveFormat::Tar, None)
            .await
            .unwrap_err();
        assert!(archive_err.contains("bucket lookup failed"));

        let run = run_with_snapshot(Uuid::new_v4());
        let lookup_err = export_backup_run_archive(&broken, &run, ArchiveFormat::Tar)
            .await
            .unwrap_err();
        assert!(lookup_err.contains("snapshot lookup failed"));

        let missing_snapshot_err = export_backup_run_archive(&state, &run, ArchiveFormat::Tar)
            .await
            .unwrap_err();
        assert!(missing_snapshot_err.contains("snapshot not found"));

        let lookup_err = load_backup_bucket(&broken, Uuid::new_v4())
            .await
            .unwrap_err();
        assert!(lookup_err.contains("bucket lookup failed"));
    }

    fn run_for_prune(archive_object_key: Option<&str>) -> crate::meta::models::BackupRun {
        crate::meta::models::BackupRun {
            id: Uuid::new_v4(),
            policy_id: Uuid::new_v4(),
            snapshot_id: None,
            backup_type: "full".to_string(),
            changed_since: None,
            trigger_kind: "on_demand".to_string(),
            status: "success".to_string(),
            archive_format: "tar.gz".to_string(),
            archive_object_key: archive_object_key.map(str::to_string),
            archive_size_bytes: Some(1),
            error_text: None,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
        }
    }

    #[tokio::test]
    async fn prune_backup_run_reports_delete_errors_with_broken_repo() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();

        let with_archive = run_for_prune(Some("archive.tar.gz"));
        let archive_err = prune_backup_run(&broken, Uuid::new_v4(), &with_archive)
            .await
            .unwrap_err();
        assert!(archive_err.contains("archive delete failed"));

        let without_archive = run_for_prune(None);
        let run_err = prune_backup_run(&broken, Uuid::new_v4(), &without_archive)
            .await
            .unwrap_err();
        assert!(run_err.contains("run delete failed"));
    }

    #[tokio::test]
    async fn archive_storage_and_checksum_helpers_report_error_paths() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();

        let finalize_err = store_backup_archive(
            &broken,
            Uuid::new_v4(),
            "archive.tar.gz",
            b"payload",
            "application/gzip",
        )
        .await
        .unwrap_err();
        assert!(finalize_err.contains("archive finalize failed"));

        let checksum_query_err = load_chunk_checksum(&broken, Uuid::new_v4())
            .await
            .unwrap_err();
        assert!(checksum_query_err.contains("chunk checksum query failed"));

        let checksum_missing_err = load_chunk_checksum(&state, Uuid::new_v4())
            .await
            .unwrap_err();
        assert!(checksum_missing_err.contains("chunk checksum missing"));
    }

    #[tokio::test]
    async fn write_chunk_and_snapshot_archive_helpers_cover_error_paths() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let _failpoint = crate::storage::chunkstore::failpoint_guard(2);
        let write_err = write_backup_chunk(&state, b"payload").await.unwrap_err();
        assert!(write_err.contains("chunk write failed"));

        let owner = create_user(&state, "owner-archive-errors").await;
        let source = create_bucket(&state, "src-archive-errors", owner.id, false).await;
        let _chunk = seed_object_with_chunk_id(&state, source.id, "a.txt", b"body").await;
        let snapshot = state
            .repo
            .create_bucket_snapshot(source.id, "on_demand", None)
            .await
            .expect("snapshot");
        let table = crate::test_support::TableRenameGuard::rename(
            state.repo.pool(),
            "bucket_snapshot_objects",
        )
        .await
        .expect("rename");
        let list_err = build_snapshot_archive(&state, &snapshot, ArchiveFormat::Tar, None)
            .await
            .unwrap_err();
        assert!(list_err.contains("snapshot object list failed"));
        table.restore().await.expect("restore");
    }

    #[tokio::test]
    async fn read_snapshot_object_payload_reports_manifest_and_chunk_errors() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let object = crate::meta::models::BucketSnapshotObject {
            snapshot_id: Uuid::new_v4(),
            object_key: "x.txt".to_string(),
            version_id: "v1".to_string(),
            manifest_id: Uuid::new_v4(),
            size_bytes: 1,
            content_type: Some("text/plain".to_string()),
            metadata_json: json!({}),
            tags_json: json!({}),
            object_created_at: Utc::now(),
        };
        let manifest_err = read_snapshot_object_payload(&broken, &object)
            .await
            .unwrap_err();
        assert!(manifest_err.contains("manifest load failed"));

        let owner = create_user(&state, "owner-chunk-errors").await;
        let source = create_bucket(&state, "src-chunk-errors", owner.id, false).await;
        let chunk_id = seed_object_with_chunk_id(&state, source.id, "b.txt", b"body").await;
        let snapshot = state
            .repo
            .create_bucket_snapshot(source.id, "on_demand", None)
            .await
            .expect("snapshot");
        let objects = state
            .repo
            .list_snapshot_objects(snapshot.id)
            .await
            .expect("objects");
        {
            let _checksum_none = crate::meta::repos::checksum_none_guard();
            let checksum_err = read_snapshot_object_payload(&state, &objects[0])
                .await
                .unwrap_err();
            assert!(checksum_err.contains("chunk checksum missing"));
        }
        let path = chunk_file_path(&state.config.data_dirs[0], chunk_id);
        tokio::fs::remove_file(path).await.expect("remove chunk");
        let chunk_err = read_snapshot_object_payload(&state, &objects[0])
            .await
            .unwrap_err();
        assert!(chunk_err.contains("chunk read failed"));
    }

    #[tokio::test]
    async fn run_backup_policy_once_maps_snapshot_and_run_create_errors() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let owner = create_user(&state, "owner-backup-run-errors").await;
        let source = create_bucket(&state, "src-backup-run-errors", owner.id, false).await;
        let backup_bucket = create_bucket(&state, "dst-backup-run-errors", owner.id, true).await;
        let policy = create_repo_backup_policy(
            &state,
            "policy-run-errors",
            source.id,
            backup_bucket.id,
            "full",
        )
        .await;
        assert_run_backup_policy_snapshot_insert_error(&state, &policy).await;
        assert_run_backup_policy_create_run_error(&state, &policy).await;
        assert_run_backup_policy_changed_since_error(&state, source.id, backup_bucket.id).await;
    }

    async fn assert_run_backup_policy_snapshot_insert_error(
        state: &crate::api::AppState,
        policy: &crate::meta::models::BackupPolicy,
    ) {
        let snapshot_fail = crate::test_support::FailTriggerGuard::create(
            state.repo.pool(),
            "bucket_snapshots",
            "AFTER",
            "INSERT",
        )
        .await
        .expect("snapshot fail trigger");
        let snapshot_err = run_backup_policy_once(&state, &policy, "on_demand")
            .await
            .unwrap_err();
        assert!(snapshot_err.contains("snapshot failed"));
        snapshot_fail
            .remove()
            .await
            .expect("remove snapshot trigger");
    }

    async fn assert_run_backup_policy_create_run_error(
        state: &crate::api::AppState,
        policy: &crate::meta::models::BackupPolicy,
    ) {
        let run_fail = crate::test_support::FailTriggerGuard::create(
            state.repo.pool(),
            "backup_runs",
            "BEFORE",
            "INSERT",
        )
        .await
        .expect("run fail trigger");
        let run_err = run_backup_policy_once(&state, &policy, "on_demand")
            .await
            .unwrap_err();
        assert!(run_err.contains("run create failed"));
        run_fail.remove().await.expect("remove run trigger");
    }

    async fn assert_run_backup_policy_changed_since_error(
        state: &crate::api::AppState,
        source_bucket_id: Uuid,
        backup_bucket_id: Uuid,
    ) {
        let policy = create_repo_backup_policy(
            state,
            "policy-run-errors-incremental",
            source_bucket_id,
            backup_bucket_id,
            "incremental",
        )
        .await;
        let backup_runs_table =
            crate::test_support::TableRenameGuard::rename(state.repo.pool(), "backup_runs")
                .await
                .expect("rename backup_runs");
        let run_err = run_backup_policy_once(state, &policy, "on_demand")
            .await
            .unwrap_err();
        assert!(run_err.contains("run list failed"));
        backup_runs_table
            .restore()
            .await
            .expect("restore backup_runs");
    }

    #[tokio::test]
    async fn complete_backup_run_reports_run_and_touch_errors() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let owner = create_user(&state, "owner-complete-errors").await;
        let source = create_bucket(&state, "src-complete-errors", owner.id, false).await;
        let backup_bucket = create_bucket(&state, "dst-complete-errors", owner.id, true).await;
        let policy = create_repo_backup_policy(
            &state,
            "policy-complete-errors",
            source.id,
            backup_bucket.id,
            "full",
        )
        .await;
        assert_complete_backup_run_reports_complete_error(&state, &policy).await;
        assert_complete_backup_run_reports_touch_error(&state, &policy).await;
        assert_complete_backup_run_reports_missing_run(&state, &policy).await;
    }

    #[tokio::test]
    async fn load_completed_backup_run_maps_lookup_error() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let err = load_completed_backup_run(&broken, Uuid::new_v4())
            .await
            .unwrap_err();
        assert!(err.contains("run lookup failed"));
    }

    async fn assert_complete_backup_run_reports_complete_error(
        state: &crate::api::AppState,
        policy: &crate::meta::models::BackupPolicy,
    ) {
        let run = state
            .repo
            .create_backup_run(policy.id, None, "full", None, "on_demand", "tar.gz")
            .await
            .expect("run");
        let runs_table =
            crate::test_support::TableRenameGuard::rename(state.repo.pool(), "backup_runs")
                .await
                .expect("rename backup_runs");
        let complete_err = complete_backup_run(&state, &policy, run.id, "archive.tar.gz", 5)
            .await
            .unwrap_err();
        assert!(complete_err.contains("run complete failed"));
        runs_table.restore().await.expect("restore backup_runs");
    }

    async fn assert_complete_backup_run_reports_touch_error(
        state: &crate::api::AppState,
        policy: &crate::meta::models::BackupPolicy,
    ) {
        let run = state
            .repo
            .create_backup_run(policy.id, None, "full", None, "on_demand", "tar.gz")
            .await
            .expect("run");
        let policies_table =
            crate::test_support::TableRenameGuard::rename(state.repo.pool(), "backup_policies")
                .await
                .expect("rename backup_policies");
        let touch_err = complete_backup_run(&state, &policy, run.id, "archive.tar.gz", 5)
            .await
            .unwrap_err();
        assert!(touch_err.contains("policy touch failed"));
        policies_table
            .restore()
            .await
            .expect("restore backup_policies");
    }

    async fn assert_complete_backup_run_reports_missing_run(
        state: &crate::api::AppState,
        policy: &crate::meta::models::BackupPolicy,
    ) {
        let missing_err = complete_backup_run(&state, &policy, Uuid::new_v4(), "archive.tar.gz", 5)
            .await
            .unwrap_err();
        assert!(missing_err.contains("backup run not found"));
    }

    #[tokio::test]
    async fn backup_types_support_restore_paths() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let owner = create_user(&state, "owner-backup-types").await;
        let source = create_bucket(&state, "src-backup-types", owner.id, false).await;
        let backup_bucket = create_bucket(&state, "dst-backup-types", owner.id, true).await;
        seed_object(&state, source.id, "seed/base.txt", b"base").await;

        let full_policy =
            create_repo_backup_policy(&state, "policy-full", source.id, backup_bucket.id, "full")
                .await;
        let full_run = run_policy_and_restore(&state, &full_policy, owner.id, "restore-full").await;
        assert!(full_run.changed_since.is_none());

        assert_incremental_run_and_restore(&state, owner.id, source.id, backup_bucket.id).await;
        assert_differential_run_and_restore(&state, owner.id, source.id, backup_bucket.id).await;
    }

    #[tokio::test]
    async fn retention_prunes_old_runs_and_helpers_cover_paths() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let owner = create_user(&state, "owner-retention").await;
        let source = create_bucket(&state, "src-retention", owner.id, false).await;
        let backup_bucket = create_bucket(&state, "dst-retention", owner.id, true).await;
        let created = create_retention_policy(&state, source.id, backup_bucket.id).await;
        let _first = create_successful_backup_run(&state, created.id, "archive-1.tar.gz").await;
        let second = create_successful_backup_run(&state, created.id, "archive-2.tar.gz").await;
        assert_retention_keeps_latest_run(&state, &created, second.id).await;
        assert!(backup_archive_key(created.id, second.id, Utc::now()).contains("nss-backups/"));
        assert_eq!(
            backup_archive_etag(b"abc"),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            sanitize_archive_path("bucket", "../../"),
            "bucket/unnamed-object"
        );
    }

    #[tokio::test]
    async fn backup_changed_since_and_prune_helpers_cover_remaining_paths() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let owner = create_user(&state, "owner-backup-diff").await;
        let source = create_bucket(&state, "src-backup-diff", owner.id, false).await;
        let backup_bucket = create_bucket(&state, "dst-backup-diff", owner.id, true).await;
        let policy = create_repo_backup_policy(
            &state,
            "policy-diff-since",
            source.id,
            backup_bucket.id,
            "differential",
        )
        .await;
        let run = create_successful_backup_run(&state, policy.id, "archive-diff.tar.gz").await;
        let changed = backup_changed_since(&state, &policy)
            .await
            .expect("changed");
        assert_eq!(changed, Some(run.started_at));

        let mut unknown = policy.clone();
        unknown.backup_type = "unknown".to_string();
        let changed = backup_changed_since(&state, &unknown)
            .await
            .expect("unknown");
        assert!(changed.is_none());

        let persisted = state
            .repo
            .get_backup_run(run.id)
            .await
            .expect("run")
            .expect("run");
        prune_backup_run(&state, backup_bucket.id, &persisted)
            .await
            .expect("prune");
    }

    #[tokio::test]
    async fn apply_backup_retention_handles_run_without_archive_key() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let owner = create_user(&state, "owner-retention-no-key").await;
        let source = create_bucket(&state, "src-retention-no-key", owner.id, false).await;
        let backup_bucket = create_bucket(&state, "dst-retention-no-key", owner.id, true).await;
        let policy = create_retention_policy(&state, source.id, backup_bucket.id).await;
        let run = state
            .repo
            .create_backup_run(policy.id, None, "full", None, "on_demand", "tar.gz")
            .await
            .expect("run");
        state
            .repo
            .complete_backup_run_success(run.id, "archive.tar.gz", 1)
            .await
            .expect("done");
        sqlx::query("UPDATE backup_runs SET archive_object_key = NULL WHERE id = $1")
            .bind(run.id)
            .execute(state.repo.pool())
            .await
            .expect("clear key");
        apply_backup_retention(&state, &policy)
            .await
            .expect("retention");
    }

    async fn create_retention_policy(
        state: &crate::api::AppState,
        source_bucket_id: Uuid,
        backup_bucket_id: Uuid,
    ) -> crate::meta::models::BackupPolicy {
        let mut input =
            backup_policy_create_input("retention", source_bucket_id, backup_bucket_id, "full");
        input.retention_count = 1;
        state
            .repo
            .create_backup_policy(&input)
            .await
            .expect("policy")
    }

    async fn create_successful_backup_run(
        state: &crate::api::AppState,
        policy_id: Uuid,
        object_key: &str,
    ) -> crate::meta::models::BackupRun {
        let run = state
            .repo
            .create_backup_run(policy_id, None, "full", None, "on_demand", "tar.gz")
            .await
            .expect("run");
        state
            .repo
            .complete_backup_run_success(run.id, object_key, 10)
            .await
            .expect("done");
        run
    }

    async fn assert_retention_keeps_latest_run(
        state: &crate::api::AppState,
        policy: &crate::meta::models::BackupPolicy,
        expected_run_id: Uuid,
    ) {
        apply_backup_retention(state, policy)
            .await
            .expect("retention");
        let runs = state
            .repo
            .list_backup_runs_for_policy(policy.id)
            .await
            .expect("runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].id, expected_run_id);
    }

    #[tokio::test]
    async fn external_target_upload_and_connection_paths_are_covered() {
        ensure_rustls_provider();
        let (ok_url, ok_handle) = spawn_status_server(StatusCode::NO_CONTENT).await;
        let ok_target = target(ExternalTargetKind::Other, ok_url.as_str(), Some("PUT"));
        let message = test_external_target_connection(&ok_target)
            .await
            .expect("ok");
        assert!(message.contains("reachable"));
        upload_http_target(
            &ok_target,
            "a/b.txt",
            b"payload",
            "application/octet-stream",
        )
        .await
        .expect("upload");
        let sftp = target(ExternalTargetKind::Sftp, "sftp://example.com/archive", None);
        let err = upload_external_target(&sftp, "a/b.txt", b"x", "text/plain")
            .await
            .unwrap_err();
        assert!(err.contains("direct sftp push"));
        let ssh = target(ExternalTargetKind::Ssh, "ssh://example.com/archive", None);
        let ssh_err = upload_external_target(&ssh, "a/b.txt", b"x", "text/plain")
            .await
            .unwrap_err();
        assert!(ssh_err.contains("direct ssh push"));
        ok_handle.abort();

        let (fail_url, fail_handle) = spawn_status_server(StatusCode::BAD_GATEWAY).await;
        let fail = target(ExternalTargetKind::Other, fail_url.as_str(), Some("POST"));
        let err = upload_http_target(&fail, "key", b"x", "text/plain")
            .await
            .unwrap_err();
        assert!(err.contains("status"));
        fail_handle.abort();
    }

    async fn create_execute_failure_inputs(
        state: &crate::api::AppState,
        source_bucket_id: Uuid,
        policy_id: Uuid,
    ) -> (
        crate::meta::models::BucketSnapshot,
        crate::meta::models::BackupRun,
    ) {
        let snapshot = state
            .repo
            .create_bucket_snapshot(source_bucket_id, "on_demand", None)
            .await
            .expect("snapshot");
        let run = state
            .repo
            .create_backup_run(
                policy_id,
                Some(snapshot.id),
                "full",
                None,
                "on_demand",
                "tar.gz",
            )
            .await
            .expect("run");
        (snapshot, run)
    }

    async fn assert_policy_run_failed(state: &crate::api::AppState, policy_id: Uuid) {
        let failed = state
            .repo
            .list_backup_runs_for_policy(policy_id)
            .await
            .expect("runs");
        assert_eq!(failed[0].status, "failed");
    }

    async fn run_execute_backup_with_failing_external_target(
        state: &crate::api::AppState,
        source_bucket_id: Uuid,
        backup_bucket_id: Uuid,
    ) -> Uuid {
        seed_object(state, source_bucket_id, "seed/failure.txt", b"payload").await;
        let mut policy = create_repo_backup_policy(
            state,
            "policy-failure",
            source_bucket_id,
            backup_bucket_id,
            "full",
        )
        .await;
        let (snapshot, run) =
            create_execute_failure_inputs(state, source_bucket_id, policy.id).await;
        policy.external_targets_json = json!([{
            "name": "remote",
            "kind": "other",
            "endpoint": "http://127.0.0.1:1/upload",
            "enabled": true
        }]);
        let err = execute_backup_run(state, &policy, &snapshot, run)
            .await
            .unwrap_err();
        assert!(err.contains("external target"));
        policy.id
    }

    async fn assert_fail_backup_run_returns_original_error(
        state: &crate::api::AppState,
        policy_id: Uuid,
    ) {
        let run = state
            .repo
            .create_backup_run(policy_id, None, "full", None, "on_demand", "tar.gz")
            .await
            .expect("run");
        let failed = fail_backup_run(state, run.id, "boom".to_string())
            .await
            .unwrap_err();
        assert_eq!(failed, "boom");
    }

    #[tokio::test]
    async fn execute_backup_run_failure_paths_are_recorded() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let owner = create_user(&state, "owner-backup-failure").await;
        let source = create_bucket(&state, "src-backup-failure", owner.id, false).await;
        let backup_bucket = create_bucket(&state, "dst-backup-failure", owner.id, true).await;
        let policy_id =
            run_execute_backup_with_failing_external_target(&state, source.id, backup_bucket.id)
                .await;
        assert_policy_run_failed(&state, policy_id).await;
        assert_fail_backup_run_returns_original_error(&state, policy_id).await;
    }

    #[tokio::test]
    async fn execute_backup_run_marks_failed_when_archive_build_fails() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let owner = create_user(&state, "owner-backup-build-failure").await;
        let source = create_bucket(&state, "src-build-failure", owner.id, false).await;
        let backup_bucket = create_bucket(&state, "dst-build-failure", owner.id, true).await;
        let policy = create_repo_backup_policy(
            &state,
            "policy-build-failure",
            source.id,
            backup_bucket.id,
            "full",
        )
        .await;
        let run = state
            .repo
            .create_backup_run(policy.id, None, "full", None, "on_demand", "tar.gz")
            .await
            .expect("run");
        let snapshot = crate::meta::models::BucketSnapshot {
            id: Uuid::new_v4(),
            bucket_id: Uuid::new_v4(),
            trigger_kind: "on_demand".to_string(),
            created_by_user_id: None,
            object_count: 0,
            total_size_bytes: 0,
            created_at: Utc::now(),
        };
        let err = execute_backup_run(&state, &policy, &snapshot, run)
            .await
            .unwrap_err();
        assert!(err.contains("snapshot bucket not found"));
    }

    #[tokio::test]
    async fn prune_backup_run_deletes_run_without_archive_object_key() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let owner = create_user(&state, "owner-prune-no-key").await;
        let source = create_bucket(&state, "src-prune-no-key", owner.id, false).await;
        let backup_bucket = create_bucket(&state, "dst-prune-no-key", owner.id, true).await;
        let policy = create_repo_backup_policy(
            &state,
            "policy-prune-no-key",
            source.id,
            backup_bucket.id,
            "full",
        )
        .await;
        let run = state
            .repo
            .create_backup_run(policy.id, None, "full", None, "on_demand", "tar.gz")
            .await
            .expect("run");
        let persisted = state
            .repo
            .get_backup_run(run.id)
            .await
            .expect("lookup")
            .expect("present");
        prune_backup_run(&state, backup_bucket.id, &persisted)
            .await
            .expect("prune");
    }
}
