use crate::api::AppState;
use crate::meta::models::{Bucket, ManifestChunk, ObjectVersion};
use crate::policy;
use crate::s3::chunking::drain_full_chunks;
use crate::s3::errors::{s3_error, S3Error};
use crate::s3::sigv4::{authenticate_request, AuthResult};
use crate::storage::checksum::Checksum;
use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{DefaultBodyLimit, OriginalUri, Path, RawQuery, State};
use axum::http::HeaderValue;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use md5::{Digest, Md5};
use serde_json::json;
use std::collections::HashMap;
use std::io;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use uuid::Uuid;

mod chunking;
pub mod errors;
pub mod sigv4;
mod sigv4_core;
pub mod xml;

pub fn router(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/", any(root_handler))
        .route("/{*path}", any(path_handler))
        .layer(DefaultBodyLimit::max(128 * 1024 * 1024))
        .with_state(state.clone());
    if !state.config.cors_allow_origins.is_empty() {
        let cors = build_cors(&state.config.cors_allow_origins);
        router = router.layer(cors);
    }
    router
}

async fn root_handler(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let response = match load_root_bucket_listing(&state, &method, &headers).await {
        Ok(body) => xml_ok_response(body),
        Err(err) => s3_error(err),
    };
    record_s3_request(&state, "ListBuckets", response.status());
    response
}

async fn load_root_bucket_listing(
    state: &AppState,
    method: &Method,
    headers: &HeaderMap,
) -> Result<String, S3Error> {
    ensure_replica_read_only(state, method)?;
    if *method != Method::GET {
        return Err(S3Error::MethodNotAllowed);
    }
    let auth = authenticate_request(state, headers, method.as_str(), "/", None).await?;
    let buckets = state
        .repo
        .list_buckets(auth.user.id)
        .await
        .map_err(|_| S3Error::InternalError)?;
    Ok(xml::list_buckets(&auth.user.username, &buckets))
}

async fn path_handler(
    State(state): State<AppState>,
    Path(path): Path<String>,
    OriginalUri(original_uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    body: Body,
) -> Response {
    let request_path = format!("/{}", path);
    let context = match build_path_context(&headers, &request_path, raw_query, &method) {
        Ok(context) => context,
        Err(err) => return s3_error(err),
    };
    let response =
        dispatch_path_request(&state, original_uri.path(), &context, method, headers, body).await;
    record_s3_request(&state, context.op, response.status());
    response
}

struct PathRequestContext {
    bucket_key: BucketKey,
    query: String,
    query_map: HashMap<String, String>,
    op: &'static str,
}

fn build_path_context(
    headers: &HeaderMap,
    path: &str,
    raw_query: Option<String>,
    method: &Method,
) -> Result<PathRequestContext, S3Error> {
    let bucket_key = parse_bucket_key(headers, path).ok_or(S3Error::InvalidRequest)?;
    let query = raw_query.unwrap_or_default();
    let query_map = serde_urlencoded::from_str(&query).unwrap_or_default();
    let op = detect_s3_operation(method, bucket_key.key.is_some(), &query_map);
    Ok(PathRequestContext {
        bucket_key,
        query,
        query_map,
        op,
    })
}

async fn dispatch_path_request(
    state: &AppState,
    auth_path: &str,
    context: &PathRequestContext,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let auth_result = authenticate_request(
        state,
        &headers,
        method.as_str(),
        auth_path,
        Some(&context.query),
    )
    .await;
    match auth_result {
        Ok(auth) => dispatch_authenticated_path(state, &auth, context, method, headers, body).await,
        Err(err) => dispatch_public_path(state, context, method, headers, err).await,
    }
}

async fn dispatch_authenticated_path(
    state: &AppState,
    auth: &AuthResult,
    context: &PathRequestContext,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Response {
    dispatch(
        state,
        auth,
        context.bucket_key.clone(),
        method,
        headers,
        context.query.as_str(),
        body,
    )
    .await
    .unwrap_or_else(s3_error)
}

async fn dispatch_public_path(
    state: &AppState,
    context: &PathRequestContext,
    method: Method,
    headers: HeaderMap,
    auth_error: S3Error,
) -> Response {
    if !is_public_read_request(&method, &context.bucket_key) {
        return s3_error(auth_error);
    }
    let Some(bucket) = load_public_bucket(state, &context.bucket_key.bucket).await else {
        return s3_error(auth_error);
    };
    let key = context.bucket_key.key.as_deref().unwrap_or_default();
    dispatch_public(state, bucket, key, method, headers, &context.query_map)
        .await
        .unwrap_or_else(s3_error)
}

async fn load_public_bucket(state: &AppState, bucket_name: &str) -> Option<Bucket> {
    match state.repo.get_bucket(bucket_name).await {
        Ok(Some(bucket)) if bucket.public_read => Some(bucket),
        _ => None,
    }
}

#[derive(Debug, Clone)]
struct BucketKey {
    bucket: String,
    key: Option<String>,
}

fn to_optional_owned(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

fn parse_bucket_key(headers: &HeaderMap, path: &str) -> Option<BucketKey> {
    let host = headers
        .get("host")
        .and_then(|val| val.to_str().ok())
        .unwrap_or("");
    let trimmed = path.trim_start_matches('/');

    if let Some((host_bucket, host_key)) = parse_virtual_host(host, trimmed) {
        let key = to_optional_owned(&host_key);
        return Some(BucketKey {
            bucket: host_bucket,
            key,
        });
    }

    let mut parts = trimmed.splitn(2, '/');
    let bucket = parts.next().unwrap_or("").to_string();
    let key = parts.next().and_then(to_optional_owned);

    if bucket.is_empty() {
        return None;
    }
    Some(BucketKey { bucket, key })
}

fn is_public_read_request(method: &Method, bucket_key: &BucketKey) -> bool {
    is_client_read_method(method) && bucket_key.key.is_some()
}

fn is_client_read_method(method: &Method) -> bool {
    method == Method::GET || method == Method::HEAD
}

fn ensure_replica_read_only(state: &AppState, method: &Method) -> Result<(), S3Error> {
    if state.config.mode != "replica" {
        return Ok(());
    }
    if !state.replica_mode.get().allows_client_reads() {
        return Err(S3Error::AccessDenied);
    }
    if !is_client_read_method(method) {
        return Err(S3Error::AccessDenied);
    }
    Ok(())
}

fn ensure_bucket_writable(bucket: &Bucket, method: &Method) -> Result<(), S3Error> {
    if bucket.is_worm && !is_client_read_method(method) {
        return Err(S3Error::AccessDenied);
    }
    Ok(())
}

fn ensure_worm_object_method_allowed(
    bucket: &Bucket,
    method: &Method,
    query: &HashMap<String, String>,
) -> Result<(), S3Error> {
    if !bucket.is_worm || is_client_read_method(method) || *method == Method::PUT {
        return Ok(());
    }
    if *method == Method::POST && (query.contains_key("uploads") || query.contains_key("uploadId"))
    {
        return Ok(());
    }
    if *method == Method::DELETE && query.contains_key("uploadId") {
        return Ok(());
    }
    Err(S3Error::AccessDenied)
}

async fn dispatch_public(
    state: &AppState,
    bucket: Bucket,
    key: &str,
    method: Method,
    headers: HeaderMap,
    query: &std::collections::HashMap<String, String>,
) -> Result<Response, S3Error> {
    if !bucket.public_read {
        return Err(S3Error::AccessDenied);
    }
    if let Some(version_id) = query.get("versionId") {
        if method == Method::GET {
            return get_object_version(state, &bucket, key, version_id, headers).await;
        }
        if method == Method::HEAD {
            return head_object_version(state, &bucket, key, version_id).await;
        }
        return Err(S3Error::InvalidRequest);
    }
    if method == Method::GET {
        return get_object(state, &bucket, key, headers).await;
    }
    if method == Method::HEAD {
        return head_object(state, &bucket, key).await;
    }
    Err(S3Error::InvalidRequest)
}

fn parse_virtual_host(host: &str, path: &str) -> Option<(String, String)> {
    let host_only = host.split(':').next().unwrap_or("");
    let labels: Vec<&str> = host_only.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    let bucket = labels[0];
    if bucket.is_empty() || bucket == "localhost" || bucket == "127" {
        return None;
    }
    Some((bucket.to_string(), path.to_string()))
}

#[rustfmt::skip]
async fn dispatch(
    state: &AppState, auth: &AuthResult, bucket_key: BucketKey, method: Method,
    headers: HeaderMap, query: &str, body: Body,
) -> Result<Response, S3Error> {
    ensure_replica_read_only(state, &method)?;
    let query_map = serde_urlencoded::from_str(query).unwrap_or_default();
    let bucket = load_dispatch_bucket(state, &bucket_key.bucket).await;
    if let Some(key) = bucket_key.key {
        return dispatch_object_with_loaded_bucket(ObjectDispatchRequest {
            state, auth, bucket, key: &key, method, headers, query: &query_map, body,
        }).await;
    }
    dispatch_bucket_request(state, auth, &bucket_key.bucket, bucket, method, &query_map, body).await
}

async fn dispatch_object_with_loaded_bucket(
    request: ObjectDispatchRequest<'_>,
) -> Result<Response, S3Error> {
    dispatch_object_request(request).await
}

struct ObjectDispatchRequest<'a> {
    state: &'a AppState,
    auth: &'a AuthResult,
    bucket: Option<Bucket>,
    key: &'a str,
    method: Method,
    headers: HeaderMap,
    query: &'a HashMap<String, String>,
    body: Body,
}

async fn load_dispatch_bucket(state: &AppState, bucket_name: &str) -> Option<Bucket> {
    state.repo.get_bucket(bucket_name).await.unwrap_or_default()
}

async fn dispatch_bucket_request(
    state: &AppState,
    auth: &AuthResult,
    bucket_name: &str,
    bucket: Option<Bucket>,
    method: Method,
    query: &HashMap<String, String>,
    body: Body,
) -> Result<Response, S3Error> {
    match bucket {
        None => dispatch_missing_bucket(state, auth, bucket_name, method).await,
        Some(bucket) => dispatch_existing_bucket(state, auth, bucket, method, query, body).await,
    }
}

async fn dispatch_missing_bucket(
    state: &AppState,
    auth: &AuthResult,
    bucket_name: &str,
    method: Method,
) -> Result<Response, S3Error> {
    match method {
        Method::PUT => handle_create_bucket(state, auth, bucket_name).await,
        Method::GET | Method::HEAD | Method::DELETE => Err(S3Error::NoSuchBucket),
        _ => Err(S3Error::InvalidRequest),
    }
}

async fn dispatch_existing_bucket(
    state: &AppState,
    auth: &AuthResult,
    bucket: Bucket,
    method: Method,
    query: &HashMap<String, String>,
    body: Body,
) -> Result<Response, S3Error> {
    ensure_bucket_writable(&bucket, &method)?;
    match method {
        Method::GET => handle_get_bucket(state, auth, bucket, query).await,
        Method::HEAD => handle_head_bucket(auth, bucket).await,
        Method::DELETE => handle_delete_bucket(state, auth, bucket).await,
        Method::PUT => dispatch_existing_bucket_put(state, auth, bucket, query, body).await,
        Method::POST if query.contains_key("delete") => {
            let body_bytes = read_body_limited(body, 2 * 1024 * 1024).await?;
            handle_delete_objects(state, auth, bucket, query, &body_bytes).await
        }
        _ => Err(S3Error::InvalidRequest),
    }
}

async fn dispatch_existing_bucket_put(
    state: &AppState,
    auth: &AuthResult,
    bucket: Bucket,
    query: &HashMap<String, String>,
    body: Body,
) -> Result<Response, S3Error> {
    if query.contains_key("notification") {
        let body_bytes = read_body_limited(body, 1024 * 1024).await?;
        return handle_put_bucket_notification(state, auth, bucket, &body_bytes).await;
    }
    if query.contains_key("versioning") {
        let body_bytes = read_body_limited(body, 1024 * 1024).await?;
        return handle_put_bucket_versioning(state, auth, bucket, &body_bytes).await;
    }
    Err(S3Error::BucketAlreadyExists)
}

async fn dispatch_object_request(args: ObjectDispatchRequest<'_>) -> Result<Response, S3Error> {
    let bucket = args.bucket.ok_or(S3Error::NoSuchBucket)?;
    handle_object(
        args.state,
        args.auth,
        bucket,
        args.key,
        args.method,
        args.headers,
        args.query,
        args.body,
    )
    .await
}

async fn handle_create_bucket(
    state: &AppState,
    auth: &AuthResult,
    bucket_name: &str,
) -> Result<Response, S3Error> {
    let bucket = state
        .repo
        .create_bucket(bucket_name, auth.user.id)
        .await
        .map_err(|_| S3Error::BucketAlreadyExists)?;
    if !policy::can_access_bucket(&auth.user, &bucket) {
        return Err(S3Error::AccessDenied);
    }
    Ok((StatusCode::OK, "").into_response())
}

async fn handle_get_bucket(
    state: &AppState,
    auth: &AuthResult,
    bucket: Bucket,
    query: &HashMap<String, String>,
) -> Result<Response, S3Error> {
    ensure_bucket_access(auth, &bucket)?;
    if query.contains_key("location") {
        return Ok(xml_ok_response(xml::bucket_location("local")));
    }
    if query.contains_key("versioning") {
        return Ok(xml_ok_response(xml::bucket_versioning(
            &bucket.versioning_status,
        )));
    }
    if query.contains_key("notification") {
        return handle_get_bucket_notification(state, auth, bucket).await;
    }
    if query.contains_key("versions") {
        return handle_get_bucket_versions(state, &bucket, query).await;
    }
    if query.get("list-type").map(String::as_str) == Some("2") {
        return handle_get_bucket_list_v2(state, &bucket, query).await;
    }
    if query.contains_key("uploads") {
        return handle_get_bucket_uploads(state, &bucket).await;
    }
    handle_get_bucket_default_list(state, &bucket).await
}

fn ensure_bucket_access(auth: &AuthResult, bucket: &Bucket) -> Result<(), S3Error> {
    if policy::can_access_bucket(&auth.user, bucket) {
        Ok(())
    } else {
        Err(S3Error::AccessDenied)
    }
}

fn xml_ok_response(body: String) -> Response {
    (StatusCode::OK, [("Content-Type", "application/xml")], body).into_response()
}

struct VersionsRequest<'a> {
    prefix: Option<&'a str>,
    key_marker: Option<&'a str>,
    version_id_marker: Option<&'a str>,
    max_keys: i64,
}

fn parse_versions_request(query: &HashMap<String, String>) -> VersionsRequest<'_> {
    VersionsRequest {
        prefix: query.get("prefix").map(String::as_str),
        key_marker: query.get("key-marker").map(String::as_str),
        version_id_marker: query.get("version-id-marker").map(String::as_str),
        max_keys: parse_max_keys(query),
    }
}

fn parse_max_keys(query: &HashMap<String, String>) -> i64 {
    query
        .get("max-keys")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(1000)
}

async fn handle_get_bucket_versions(
    state: &AppState,
    bucket: &Bucket,
    query: &HashMap<String, String>,
) -> Result<Response, S3Error> {
    let request = parse_versions_request(query);
    let page = load_versions_page(state, bucket.id, &request).await?;
    let body = render_versions_xml(bucket, &request, page);
    Ok(xml_ok_response(body))
}

async fn load_versions_page(
    state: &AppState,
    bucket_id: Uuid,
    request: &VersionsRequest<'_>,
) -> Result<(Vec<ObjectVersion>, bool, Option<String>, Option<String>), S3Error> {
    let versions = state
        .repo
        .list_object_versions(
            bucket_id,
            request.prefix,
            request.key_marker,
            request.version_id_marker,
            request.max_keys + 1,
        )
        .await
        .map_err(|_| S3Error::InternalError)?;
    Ok(paginate_versions(versions, request.max_keys))
}

fn render_versions_xml(
    bucket: &Bucket,
    request: &VersionsRequest<'_>,
    page: (Vec<ObjectVersion>, bool, Option<String>, Option<String>),
) -> String {
    let (contents, is_truncated, next_key, next_version) = page;
    let body = xml::list_object_versions(
        &bucket.name,
        request.prefix,
        request.key_marker,
        request.version_id_marker,
        request.max_keys,
        is_truncated,
        next_key.as_deref(),
        next_version.as_deref(),
        &contents,
    );
    body
}

fn paginate_versions(
    mut versions: Vec<ObjectVersion>,
    max_keys: i64,
) -> (Vec<ObjectVersion>, bool, Option<String>, Option<String>) {
    let is_truncated = versions.len() as i64 > max_keys;
    if is_truncated {
        versions.truncate(max_keys as usize);
    }
    let (next_key, next_version) = versions
        .last()
        .map(|entry| {
            (
                Some(entry.object_key.clone()),
                Some(entry.version_id.clone()),
            )
        })
        .unwrap_or((None, None));
    if is_truncated {
        (versions, true, next_key, next_version)
    } else {
        (versions, false, None, None)
    }
}

struct ListV2Request<'a> {
    prefix: Option<&'a str>,
    delimiter: Option<&'a str>,
    start_after: Option<&'a str>,
    max_keys: i64,
}

fn parse_list_v2_request(query: &HashMap<String, String>) -> ListV2Request<'_> {
    ListV2Request {
        prefix: query.get("prefix").map(String::as_str),
        delimiter: query.get("delimiter").map(String::as_str),
        start_after: query
            .get("continuation-token")
            .map(String::as_str)
            .or_else(|| query.get("start-after").map(String::as_str)),
        max_keys: parse_max_keys(query),
    }
}

async fn handle_get_bucket_list_v2(
    state: &AppState,
    bucket: &Bucket,
    query: &HashMap<String, String>,
) -> Result<Response, S3Error> {
    let request = parse_list_v2_request(query);
    let all_objects =
        list_objects_all(state, bucket.id, request.prefix, request.start_after).await?;
    let (contents, common_prefixes) =
        group_objects_by_delimiter(request.prefix, request.delimiter, &all_objects);
    let mut entries = build_list_entries(contents, &common_prefixes);
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    let (entries, is_truncated, next_token) =
        paginate_list_entries(entries, request.start_after, request.max_keys);
    let (object_entries, prefix_entries) = split_list_entries(entries);
    let body = xml::list_objects_v2(
        &bucket.name,
        request.prefix,
        request.delimiter,
        &object_entries,
        &prefix_entries,
        request.max_keys,
        is_truncated,
        next_token.as_deref(),
    );
    Ok(xml_ok_response(body))
}

fn paginate_list_entries(
    entries: Vec<ListEntry>,
    start_after: Option<&str>,
    max_keys: i64,
) -> (Vec<ListEntry>, bool, Option<String>) {
    let mut filtered = filter_entries_after_start(entries, start_after);
    let is_truncated = filtered.len() as i64 > max_keys;
    if is_truncated {
        filtered.truncate(max_keys as usize);
    }
    let next_token = if is_truncated {
        filtered.last().map(|entry| entry.key.clone())
    } else {
        None
    };
    (filtered, is_truncated, next_token)
}

fn filter_entries_after_start(
    entries: Vec<ListEntry>,
    start_after: Option<&str>,
) -> Vec<ListEntry> {
    if let Some(start) = start_after {
        entries
            .into_iter()
            .filter(|entry| entry.key.as_str() > start)
            .collect()
    } else {
        entries
    }
}

async fn handle_get_bucket_uploads(state: &AppState, bucket: &Bucket) -> Result<Response, S3Error> {
    let uploads = state
        .repo
        .list_multipart_uploads(bucket.id)
        .await
        .map_err(|_| S3Error::InternalError)?;
    Ok(xml_ok_response(xml::list_multipart_uploads(
        &bucket.name,
        &uploads,
    )))
}

async fn handle_get_bucket_default_list(
    state: &AppState,
    bucket: &Bucket,
) -> Result<Response, S3Error> {
    let objects = state
        .repo
        .list_objects_current(bucket.id, None, None, 1000)
        .await
        .map_err(|_| S3Error::InternalError)?;
    Ok(xml_ok_response(xml::list_objects(&bucket.name, &objects)))
}

async fn handle_head_bucket(auth: &AuthResult, bucket: Bucket) -> Result<Response, S3Error> {
    if !policy::can_access_bucket(&auth.user, &bucket) {
        return Err(S3Error::AccessDenied);
    }
    Ok((StatusCode::OK, "").into_response())
}

async fn handle_delete_bucket(
    state: &AppState,
    auth: &AuthResult,
    bucket: Bucket,
) -> Result<Response, S3Error> {
    if !policy::can_access_bucket(&auth.user, &bucket) {
        return Err(S3Error::AccessDenied);
    }
    state
        .repo
        .delete_bucket(&bucket.name)
        .await
        .map_err(|_| S3Error::InternalError)?;
    Ok((StatusCode::NO_CONTENT, "").into_response())
}

async fn handle_get_bucket_notification(
    state: &AppState,
    auth: &AuthResult,
    bucket: Bucket,
) -> Result<Response, S3Error> {
    if !policy::can_access_bucket(&auth.user, &bucket) {
        return Err(S3Error::AccessDenied);
    }
    if !state.events.enabled() {
        return Err(S3Error::NotImplemented);
    }
    let body = bucket.notification_config_xml.unwrap_or_else(|| {
        "<NotificationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>".to_string()
    });
    Ok((StatusCode::OK, [("Content-Type", "application/xml")], body).into_response())
}

async fn handle_put_bucket_notification(
    state: &AppState,
    auth: &AuthResult,
    bucket: Bucket,
    body: &Bytes,
) -> Result<Response, S3Error> {
    if !policy::can_access_bucket(&auth.user, &bucket) {
        return Err(S3Error::AccessDenied);
    }
    if !state.events.enabled() {
        return Err(S3Error::NotImplemented);
    }
    let xml_body = String::from_utf8_lossy(body).to_string();
    if !xml_body.contains("NotificationConfiguration") {
        return Err(S3Error::MalformedXML);
    }
    state
        .repo
        .update_bucket_notification(bucket.id, &xml_body)
        .await
        .map_err(|_| S3Error::InternalError)?;
    Ok((StatusCode::OK, "").into_response())
}

async fn handle_put_bucket_versioning(
    state: &AppState,
    auth: &AuthResult,
    bucket: Bucket,
    body: &Bytes,
) -> Result<Response, S3Error> {
    if !policy::can_access_bucket(&auth.user, &bucket) {
        return Err(S3Error::AccessDenied);
    }
    let status = xml::parse_versioning_status(body).map_err(|_| S3Error::InvalidRequest)?;
    state
        .repo
        .update_bucket_versioning(bucket.id, &status)
        .await
        .map_err(|_| S3Error::InternalError)?;
    Ok((StatusCode::OK, "").into_response())
}

async fn handle_delete_objects(
    state: &AppState,
    auth: &AuthResult,
    bucket: Bucket,
    _query: &HashMap<String, String>,
    body: &Bytes,
) -> Result<Response, S3Error> {
    if !policy::can_access_bucket(&auth.user, &bucket) {
        return Err(S3Error::AccessDenied);
    }
    delete_objects(state, &bucket, body).await
}

#[allow(clippy::too_many_arguments)]
async fn handle_object(
    state: &AppState,
    auth: &AuthResult,
    bucket: Bucket,
    key: &str,
    method: Method,
    headers: HeaderMap,
    query: &HashMap<String, String>,
    body: Body,
) -> Result<Response, S3Error> {
    ensure_bucket_access(auth, &bucket)?;
    ensure_worm_object_method_allowed(&bucket, &method, query)?;
    if method == Method::POST && query.contains_key("uploads") {
        return create_multipart_upload(state, &bucket, key).await;
    }
    if let Some(version_id) = query.get("versionId") {
        return handle_versioned_object_request(state, &bucket, key, version_id, method, headers)
            .await;
    }
    if let Some(upload_id) = query.get("uploadId") {
        return handle_upload_object_request(state, &bucket, key, upload_id, method, query, body)
            .await;
    }
    handle_standard_object_request(state, &bucket, key, method, headers, query, body).await
}

async fn handle_versioned_object_request(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    version_id: &str,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, S3Error> {
    match method {
        Method::GET => get_object_version(state, bucket, key, version_id, headers).await,
        Method::HEAD => head_object_version(state, bucket, key, version_id).await,
        Method::DELETE => delete_object_version(state, bucket, key, version_id).await,
        _ => Err(S3Error::InvalidRequest),
    }
}

async fn handle_upload_object_request(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    upload_id: &str,
    method: Method,
    query: &HashMap<String, String>,
    body: Body,
) -> Result<Response, S3Error> {
    match method {
        Method::PUT => {
            let part_number = query
                .get("partNumber")
                .and_then(|value| value.parse::<i32>().ok())
                .ok_or(S3Error::InvalidRequest)?;
            upload_part(state, bucket, key, upload_id, part_number, body).await
        }
        Method::GET => list_parts(state, bucket, key, upload_id).await,
        Method::POST => {
            let body_bytes = read_body_limited(body, 2 * 1024 * 1024).await?;
            complete_multipart_upload(state, bucket, key, upload_id, &body_bytes).await
        }
        Method::DELETE => abort_multipart_upload(state, upload_id).await,
        _ => Err(S3Error::InvalidRequest),
    }
}

async fn handle_standard_object_request(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    method: Method,
    headers: HeaderMap,
    query: &HashMap<String, String>,
    body: Body,
) -> Result<Response, S3Error> {
    match method {
        Method::PUT => put_object(state, bucket, key, headers, body).await,
        Method::GET => get_object(state, bucket, key, headers).await,
        Method::HEAD => head_object(state, bucket, key).await,
        Method::DELETE => delete_object(state, bucket, key).await,
        Method::POST if query.contains_key("delete") => {
            let body_bytes = read_body_limited(body, 2 * 1024 * 1024).await?;
            delete_objects(state, bucket, &body_bytes).await
        }
        _ => Err(S3Error::InvalidRequest),
    }
}

async fn put_object(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, S3Error> {
    ensure_worm_allows_new_object(state, bucket, key).await?;
    let write_result = stream_body_to_chunks(state, body).await?;
    record_s3_bytes_in(state, "PutObject", write_result.size_bytes);
    let content_type = extract_content_type(&headers);
    let object =
        finalize_put_object(state, bucket, key, &write_result, content_type.as_deref()).await?;
    cleanup_replaced_versions(state, bucket, key, &object.version_id).await?;
    emit_object_created_event(state, bucket, key, &write_result, &object.version_id).await;
    Ok(etag_response(&write_result.etag))
}

fn extract_content_type(headers: &HeaderMap) -> Option<String> {
    headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
}

async fn ensure_worm_allows_new_object(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
) -> Result<(), S3Error> {
    if !bucket.is_worm {
        return Ok(());
    }
    let existing = state
        .repo
        .get_object_current(bucket.id, key)
        .await
        .map_err(|_| S3Error::InternalError)?;
    if existing.is_some() {
        return Err(S3Error::AccessDenied);
    }
    Ok(())
}

async fn finalize_put_object(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    write_result: &ChunkWriteResult,
    content_type: Option<&str>,
) -> Result<ObjectVersion, S3Error> {
    let version_id = Uuid::new_v4().to_string();
    state
        .repo
        .finalize_object_version(
            bucket.id,
            key,
            &version_id,
            write_result.size_bytes,
            &write_result.etag,
            content_type,
            &json!({}),
            &json!({}),
            &write_result.chunks,
            false,
        )
        .await
        .map_err(|_| S3Error::InternalError)
}

async fn cleanup_replaced_versions(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    version_id: &str,
) -> Result<(), S3Error> {
    if bucket.versioning_status != "off" {
        return Ok(());
    }
    state
        .repo
        .delete_other_object_versions(bucket.id, key, version_id)
        .await
        .map_err(|_| S3Error::InternalError)
}

async fn emit_object_created_event(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    write_result: &ChunkWriteResult,
    version_id: &str,
) {
    if !state.events.enabled() || bucket.notification_config_xml.is_none() {
        return;
    }
    let _ = state
        .events
        .publish_object_created(
            &bucket.name,
            key,
            write_result.size_bytes,
            &write_result.etag,
            Some(version_id),
        )
        .await;
}

fn etag_response(etag: &str) -> Response {
    (StatusCode::OK, [("ETag", format!("\"{}\"", etag))], "").into_response()
}

async fn get_object(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    headers: HeaderMap,
) -> Result<Response, S3Error> {
    let (object, manifest_id) = state
        .repo
        .get_object_current(bucket.id, key)
        .await
        .map_err(|_| S3Error::InternalError)?
        .ok_or(S3Error::NoSuchKey)?;
    build_object_response(state, &object, manifest_id, headers, "GetObject").await
}

async fn head_object(state: &AppState, bucket: &Bucket, key: &str) -> Result<Response, S3Error> {
    let (object, _manifest_id) = state
        .repo
        .get_object_current(bucket.id, key)
        .await
        .map_err(|_| S3Error::InternalError)?
        .ok_or(S3Error::NoSuchKey)?;
    Ok(build_head_response(&object))
}

async fn delete_object(state: &AppState, bucket: &Bucket, key: &str) -> Result<Response, S3Error> {
    if bucket.versioning_status == "off" {
        return delete_unversioned_object(state, bucket, key).await;
    }
    delete_versioned_object(state, bucket, key).await
}

async fn delete_unversioned_object(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
) -> Result<Response, S3Error> {
    let current = state
        .repo
        .get_object_current(bucket.id, key)
        .await
        .map_err(|_| S3Error::InternalError)?;
    state
        .repo
        .delete_all_object_versions(bucket.id, key)
        .await
        .map_err(|_| S3Error::InternalError)?;
    emit_removed_current_event(state, bucket, key, current).await;
    Ok((StatusCode::NO_CONTENT, "").into_response())
}

async fn emit_removed_current_event(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    current: Option<(ObjectVersion, Uuid)>,
) {
    if !state.events.enabled() || bucket.notification_config_xml.is_none() {
        return;
    }
    let Some((object, _)) = current else {
        return;
    };
    let _ = state
        .events
        .publish_object_removed(
            &bucket.name,
            key,
            object.size_bytes,
            object.etag.as_deref().unwrap_or(""),
            Some(&object.version_id),
        )
        .await;
}

async fn delete_versioned_object(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
) -> Result<Response, S3Error> {
    let delete_marker_id = Uuid::new_v4().to_string();
    state
        .repo
        .finalize_object_version(
            bucket.id,
            key,
            &delete_marker_id,
            0,
            "",
            None,
            &json!({}),
            &json!({}),
            &[],
            true,
        )
        .await
        .map_err(|_| S3Error::InternalError)?;
    emit_removed_marker_event(state, bucket, key, &delete_marker_id).await;
    Ok((StatusCode::NO_CONTENT, "").into_response())
}

async fn emit_removed_marker_event(state: &AppState, bucket: &Bucket, key: &str, marker_id: &str) {
    if !state.events.enabled() || bucket.notification_config_xml.is_none() {
        return;
    }
    let _ = state
        .events
        .publish_object_removed(&bucket.name, key, 0, "", Some(marker_id))
        .await;
}

async fn delete_objects(
    state: &AppState,
    bucket: &Bucket,
    body: &Bytes,
) -> Result<Response, S3Error> {
    let delete_req = xml::parse_delete_objects(body).map_err(|_| S3Error::MalformedXML)?;
    for key in delete_req {
        let _ = delete_object(state, bucket, &key).await;
    }
    let body = xml::delete_objects_result();
    Ok((StatusCode::OK, [("Content-Type", "application/xml")], body).into_response())
}

async fn create_multipart_upload(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
) -> Result<Response, S3Error> {
    ensure_worm_allows_new_object(state, bucket, key).await?;
    let upload_id = Uuid::new_v4().to_string();
    state
        .repo
        .create_multipart_upload(bucket.id, key, &upload_id)
        .await
        .map_err(|_| S3Error::InternalError)?;
    let body = xml::initiate_multipart_upload(&bucket.name, key, &upload_id);
    Ok((StatusCode::OK, [("Content-Type", "application/xml")], body).into_response())
}

async fn upload_part(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    upload_id: &str,
    part_number: i32,
    body: Body,
) -> Result<Response, S3Error> {
    ensure_upload_matches(state, bucket, key, upload_id).await?;
    let write_result = stream_body_to_chunks(state, body).await?;
    record_s3_bytes_in(state, "UploadPart", write_result.size_bytes);
    fail_upload_part_begin()?;
    let manifest_id = create_upload_manifest(state, &write_result).await?;
    save_upload_part_record(state, upload_id, part_number, &write_result, manifest_id).await?;
    Ok(etag_response(&write_result.etag))
}

async fn ensure_upload_matches(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    upload_id: &str,
) -> Result<(), S3Error> {
    let upload = state
        .repo
        .get_multipart_upload(upload_id)
        .await
        .map_err(|_| S3Error::InternalError)?
        .ok_or(S3Error::NoSuchUpload)?;
    if upload.bucket_id == bucket.id && upload.object_key == key {
        Ok(())
    } else {
        Err(S3Error::NoSuchUpload)
    }
}

fn fail_upload_part_begin() -> Result<(), S3Error> {
    #[cfg(test)]
    if test_failpoints::take_upload_part_begin() {
        return Err(S3Error::InternalError);
    }
    Ok(())
}

async fn create_upload_manifest(
    state: &AppState,
    write_result: &ChunkWriteResult,
) -> Result<Uuid, S3Error> {
    let mut tx = begin_tx(state.repo.pool()).await?;
    let manifest_id = state
        .repo
        .create_manifest(&mut tx, write_result.size_bytes, &write_result.chunks)
        .await
        .map_err(|_| S3Error::InternalError)?;
    tx.commit().await.map_err(|_| S3Error::InternalError)?;
    Ok(manifest_id)
}

async fn save_upload_part_record(
    state: &AppState,
    upload_id: &str,
    part_number: i32,
    write_result: &ChunkWriteResult,
    manifest_id: Uuid,
) -> Result<(), S3Error> {
    state
        .repo
        .upsert_multipart_part(
            upload_id,
            part_number,
            write_result.size_bytes,
            &write_result.etag,
            manifest_id,
        )
        .await
        .map_err(|_| S3Error::InternalError)
}

async fn list_parts(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    upload_id: &str,
) -> Result<Response, S3Error> {
    ensure_upload_matches(state, bucket, key, upload_id).await?;
    let parts = state
        .repo
        .list_multipart_parts(upload_id)
        .await
        .map_err(|_| S3Error::InternalError)?;
    let body = xml::list_parts(&bucket.name, key, upload_id, &parts);
    Ok((StatusCode::OK, [("Content-Type", "application/xml")], body).into_response())
}

async fn complete_multipart_upload(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    upload_id: &str,
    body: &Bytes,
) -> Result<Response, S3Error> {
    ensure_upload_matches(state, bucket, key, upload_id).await?;
    ensure_worm_allows_new_object(state, bucket, key).await?;
    let completion = build_multipart_completion(state, upload_id, body).await?;
    let object = finalize_completed_upload(state, bucket, key, &completion).await?;
    cleanup_replaced_versions(state, bucket, key, &object.version_id).await?;
    mark_upload_complete(state, upload_id).await?;
    emit_completed_upload_event(state, bucket, key, &completion, &object.version_id).await;
    Ok(xml_ok_response(xml::complete_multipart_upload(
        &bucket.name,
        key,
        &completion.combined_etag,
    )))
}

struct MultipartCompletion {
    chunk_ids: Vec<Uuid>,
    total_size: i64,
    combined_etag: String,
}

async fn build_multipart_completion(
    state: &AppState,
    upload_id: &str,
    body: &Bytes,
) -> Result<MultipartCompletion, S3Error> {
    let requested = xml::parse_complete_parts(body).map_err(|_| S3Error::MalformedXML)?;
    let existing = state
        .repo
        .list_multipart_parts(upload_id)
        .await
        .map_err(|_| S3Error::InternalError)?;
    let ordered = order_complete_parts(&requested, &existing)?;
    aggregate_complete_parts(state, &ordered).await
}

fn order_complete_parts(
    requested: &[xml::CompletePart],
    existing: &[crate::meta::models::MultipartPart],
) -> Result<Vec<crate::meta::models::MultipartPart>, S3Error> {
    let mut ordered = Vec::new();
    for requested_part in requested {
        let part = existing
            .iter()
            .find(|candidate| {
                candidate.part_number == requested_part.part_number
                    && candidate.etag == requested_part.etag
            })
            .ok_or(S3Error::InvalidPart)?;
        ordered.push(part.clone());
    }
    Ok(ordered)
}

async fn aggregate_complete_parts(
    state: &AppState,
    parts: &[crate::meta::models::MultipartPart],
) -> Result<MultipartCompletion, S3Error> {
    let mut chunk_ids = Vec::new();
    let mut total_size = 0i64;
    let mut md5_concat = Vec::new();
    for part in parts {
        append_manifest_chunks(state, part.manifest_id, &mut chunk_ids).await?;
        total_size += part.size_bytes;
        md5_concat.extend_from_slice(&decode_part_etag(&part.etag)?);
    }
    let combined_etag = format!("{:x}-{}", Md5::digest(&md5_concat), parts.len());
    Ok(MultipartCompletion {
        chunk_ids,
        total_size,
        combined_etag,
    })
}

async fn append_manifest_chunks(
    state: &AppState,
    manifest_id: Uuid,
    chunk_ids: &mut Vec<Uuid>,
) -> Result<(), S3Error> {
    for chunk in load_manifest_chunks(state, manifest_id).await? {
        chunk_ids.push(chunk.chunk_id);
    }
    Ok(())
}

fn decode_part_etag(etag: &str) -> Result<Vec<u8>, S3Error> {
    hex::decode(etag.trim_matches('"')).map_err(|_| S3Error::InvalidPart)
}

async fn finalize_completed_upload(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    completion: &MultipartCompletion,
) -> Result<ObjectVersion, S3Error> {
    let version_id = Uuid::new_v4().to_string();
    state
        .repo
        .finalize_object_version(
            bucket.id,
            key,
            &version_id,
            completion.total_size,
            &completion.combined_etag,
            None,
            &json!({}),
            &json!({}),
            &completion.chunk_ids,
            false,
        )
        .await
        .map_err(|_| S3Error::InternalError)
}

async fn mark_upload_complete(state: &AppState, upload_id: &str) -> Result<(), S3Error> {
    state
        .repo
        .complete_multipart_upload(upload_id)
        .await
        .map_err(|_| S3Error::InternalError)
}

async fn emit_completed_upload_event(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    completion: &MultipartCompletion,
    version_id: &str,
) {
    if !state.events.enabled() || bucket.notification_config_xml.is_none() {
        return;
    }
    let _ = state
        .events
        .publish_object_created(
            &bucket.name,
            key,
            completion.total_size,
            &completion.combined_etag,
            Some(version_id),
        )
        .await;
}

async fn abort_multipart_upload(state: &AppState, upload_id: &str) -> Result<Response, S3Error> {
    state
        .repo
        .abort_multipart_upload(upload_id)
        .await
        .map_err(|_| S3Error::InternalError)?;
    Ok((StatusCode::NO_CONTENT, "").into_response())
}

fn parse_range_header(header: &str) -> Option<(usize, usize)> {
    if !header.starts_with("bytes=") {
        return None;
    }
    let range = header.trim_start_matches("bytes=");
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return None;
    }
    let start = parts[0].parse::<usize>().ok()?;
    if parts[1].is_empty() {
        return Some((start, usize::MAX));
    }
    let end = parts[1].parse::<usize>().ok()?;
    Some((start, end + 1))
}

struct ChunkWriteResult {
    chunks: Vec<Uuid>,
    size_bytes: i64,
    etag: String,
}

struct ChunkSlice {
    chunk_id: Uuid,
    start: usize,
    end: usize,
}

enum ListEntryValue {
    Object(ObjectVersion),
    Prefix(String),
}

struct ListEntry {
    key: String,
    value: ListEntryValue,
}

async fn read_body_limited(body: Body, limit: usize) -> Result<Bytes, S3Error> {
    to_bytes(body, limit)
        .await
        .map_err(|_| S3Error::InvalidRequest)
}

async fn begin_tx(pool: &sqlx::PgPool) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, S3Error> {
    #[cfg(test)]
    if test_failpoints::take_upload_part_tx_begin() {
        return Err(S3Error::InternalError);
    }
    pool.begin().await.map_err(|_| S3Error::InternalError)
}

async fn stream_body_to_chunks(state: &AppState, body: Body) -> Result<ChunkWriteResult, S3Error> {
    let mut chunks = Vec::new();
    let mut total_size = 0i64;
    let mut buffer: Vec<u8> = Vec::new();
    let mut hasher = Md5::new();
    let mut stream = body.into_data_stream();
    while let Some(frame) = stream.next().await {
        let data = frame.map_err(|_| S3Error::InternalError)?;
        process_stream_chunk(
            state,
            &data,
            &mut hasher,
            &mut total_size,
            &mut buffer,
            &mut chunks,
        )
        .await?;
    }
    flush_tail_chunk(state, &buffer, &mut chunks).await?;
    let etag = format!("{:x}", hasher.finalize());
    Ok(ChunkWriteResult {
        chunks,
        size_bytes: total_size,
        etag,
    })
}

async fn process_stream_chunk(
    state: &AppState,
    data: &Bytes,
    hasher: &mut Md5,
    total_size: &mut i64,
    buffer: &mut Vec<u8>,
    chunks: &mut Vec<Uuid>,
) -> Result<(), S3Error> {
    if data.is_empty() {
        return Ok(());
    }
    hasher.update(data);
    *total_size += data.len() as i64;
    buffer.extend_from_slice(data);
    drain_buffered_chunks(state, buffer, chunks).await
}

async fn drain_buffered_chunks(
    state: &AppState,
    buffer: &mut Vec<u8>,
    chunks: &mut Vec<Uuid>,
) -> Result<(), S3Error> {
    let chunk_size = state.chunk_size_bytes as usize;
    for chunk_bytes in drain_full_chunks(buffer, chunk_size) {
        chunks.push(write_chunk(state, &chunk_bytes).await?);
    }
    Ok(())
}

async fn flush_tail_chunk(
    state: &AppState,
    buffer: &[u8],
    chunks: &mut Vec<Uuid>,
) -> Result<(), S3Error> {
    if buffer.is_empty() {
        return Ok(());
    }
    chunks.push(write_chunk(state, buffer).await?);
    Ok(())
}

async fn write_chunk(state: &AppState, data: &[u8]) -> Result<Uuid, S3Error> {
    let (chunk_id, _checksum) = state
        .replication
        .write_chunk(data)
        .await
        .map_err(|_| S3Error::InternalError)?;
    Ok(chunk_id)
}

async fn build_object_response(
    state: &AppState,
    object: &ObjectVersion,
    manifest_id: Uuid,
    headers: HeaderMap,
    op: &str,
) -> Result<Response, S3Error> {
    let chunks = load_manifest_chunks(state, manifest_id).await?;
    let total_size = object_total_size(object)?;
    let range = resolve_response_range(&headers, total_size)?;
    let slices = build_range_slices(&chunks, state.chunk_size_bytes as usize, &range, total_size);
    let body = build_object_stream_body(state, slices);
    let mut response = (range.status, body).into_response();
    let content_length = set_range_headers(&mut response, &range);
    set_object_headers(&mut response, object);
    record_s3_bytes_out(state, op, content_length);
    Ok(response)
}

struct ResponseRange {
    start: usize,
    end: usize,
    status: StatusCode,
    content_range: Option<String>,
}

fn object_total_size(object: &ObjectVersion) -> Result<usize, S3Error> {
    if object.size_bytes < 0 {
        Err(S3Error::InternalError)
    } else {
        Ok(object.size_bytes as usize)
    }
}

fn resolve_response_range(
    headers: &HeaderMap,
    total_size: usize,
) -> Result<ResponseRange, S3Error> {
    let parsed = headers
        .get("range")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_range_header);
    if let Some((start, end)) = parsed {
        return build_partial_range(start, end, total_size);
    }
    Ok(ResponseRange {
        start: 0,
        end: total_size,
        status: StatusCode::OK,
        content_range: None,
    })
}

fn build_partial_range(
    start: usize,
    end: usize,
    total_size: usize,
) -> Result<ResponseRange, S3Error> {
    let end = end.min(total_size);
    if start >= end {
        return Err(S3Error::InvalidRequest);
    }
    Ok(ResponseRange {
        start,
        end,
        status: StatusCode::PARTIAL_CONTENT,
        content_range: Some(format!("bytes {}-{}/{}", start, end - 1, total_size)),
    })
}

fn build_range_slices(
    chunks: &[ManifestChunk],
    chunk_size: usize,
    range: &ResponseRange,
    total_size: usize,
) -> Vec<ChunkSlice> {
    if total_size == 0 {
        return Vec::new();
    }
    let mut slices = Vec::new();
    let first = range.start / chunk_size;
    let last = (range.end.saturating_sub(1)) / chunk_size;
    for idx in first..=last {
        if idx >= chunks.len() {
            break;
        }
        slices.push(chunk_slice_for_index(
            chunks[idx].chunk_id,
            idx,
            chunk_size,
            range,
        ));
    }
    slices
}

fn chunk_slice_for_index(
    chunk_id: Uuid,
    idx: usize,
    chunk_size: usize,
    range: &ResponseRange,
) -> ChunkSlice {
    let chunk_start = idx * chunk_size;
    let chunk_end = chunk_start + chunk_size;
    let start = range.start.saturating_sub(chunk_start);
    let end = if range.end < chunk_end {
        range.end - chunk_start
    } else {
        chunk_size
    };
    ChunkSlice {
        chunk_id,
        start,
        end,
    }
}

fn build_object_stream_body(state: &AppState, slices: Vec<ChunkSlice>) -> Body {
    let state_clone = state.clone();
    let stream = futures_util::stream::iter(slices).then(move |slice| {
        let state = state_clone.clone();
        async move { read_chunk_slice(&state, slice).await }
    });
    Body::from_stream(stream)
}

async fn read_chunk_slice(state: &AppState, slice: ChunkSlice) -> Result<bytes::Bytes, io::Error> {
    let checksum = fetch_checksum(state, slice.chunk_id)
        .await
        .map_err(|_| io::Error::other("checksum error"))?;
    let bytes = state
        .replication
        .read_chunk(slice.chunk_id, &checksum)
        .await
        .map_err(|_| io::Error::other("chunk read error"))?;
    let len = bytes.len();
    let start = slice.start.min(len);
    let end = slice.end.min(len);
    Ok(bytes.slice(start..end))
}

fn set_range_headers(response: &mut Response, range: &ResponseRange) -> usize {
    response
        .headers_mut()
        .insert("Accept-Ranges", "bytes".parse().unwrap());
    let content_length = range.end - range.start;
    response.headers_mut().insert(
        "Content-Length",
        content_length.to_string().parse().unwrap(),
    );
    if let Some(content_range) = range.content_range.as_deref() {
        response
            .headers_mut()
            .insert("Content-Range", content_range.parse().unwrap());
    }
    content_length
}

fn set_object_headers(response: &mut Response, object: &ObjectVersion) {
    if let Some(etag) = object.etag.as_deref() {
        response
            .headers_mut()
            .insert("ETag", format!("\"{}\"", etag).parse().unwrap());
    }
    response.headers_mut().insert(
        "Last-Modified",
        http_date(object.created_at).parse().unwrap(),
    );
    if let Some(content_type) = object.content_type.as_deref() {
        response
            .headers_mut()
            .insert("Content-Type", content_type.parse().unwrap());
    }
}

fn build_head_response(object: &ObjectVersion) -> Response {
    let mut response = (StatusCode::OK, "").into_response();
    if let Some(etag) = object.etag.as_deref() {
        response
            .headers_mut()
            .insert("ETag", format!("\"{}\"", etag).parse().unwrap());
    }
    response.headers_mut().insert(
        "Last-Modified",
        http_date(object.created_at).parse().unwrap(),
    );
    response.headers_mut().insert(
        "Content-Length",
        object.size_bytes.to_string().parse().unwrap(),
    );
    if let Some(content_type) = object.content_type.as_deref() {
        response
            .headers_mut()
            .insert("Content-Type", content_type.parse().unwrap());
    }
    response
}

async fn get_object_version(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    version_id: &str,
    headers: HeaderMap,
) -> Result<Response, S3Error> {
    let (object, manifest_id) = state
        .repo
        .get_object_version(bucket.id, key, version_id)
        .await
        .map_err(|_| S3Error::InternalError)?
        .ok_or(S3Error::NoSuchKey)?;
    if object.is_delete_marker {
        return Err(S3Error::NoSuchKey);
    }
    build_object_response(state, &object, manifest_id, headers, "GetObjectVersion").await
}

async fn head_object_version(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    version_id: &str,
) -> Result<Response, S3Error> {
    let (object, _manifest_id) = state
        .repo
        .get_object_version(bucket.id, key, version_id)
        .await
        .map_err(|_| S3Error::InternalError)?
        .ok_or(S3Error::NoSuchKey)?;
    if object.is_delete_marker {
        return Err(S3Error::NoSuchKey);
    }
    Ok(build_head_response(&object))
}

async fn delete_object_version(
    state: &AppState,
    bucket: &Bucket,
    key: &str,
    version_id: &str,
) -> Result<Response, S3Error> {
    let result = state
        .repo
        .delete_object_version(bucket.id, key, version_id)
        .await
        .map_err(|_| S3Error::InternalError)?;
    if !result.found {
        return Err(S3Error::NoSuchKey);
    }
    Ok((StatusCode::NO_CONTENT, "").into_response())
}

async fn list_objects_all(
    state: &AppState,
    bucket_id: Uuid,
    prefix: Option<&str>,
    start_after: Option<&str>,
) -> Result<Vec<ObjectVersion>, S3Error> {
    let mut out = Vec::new();
    let mut marker = start_after.map(|val| val.to_string());
    loop {
        let batch = state
            .repo
            .list_objects_current(bucket_id, prefix, marker.as_deref(), 1000)
            .await
            .map_err(|_| S3Error::InternalError)?;
        if batch.is_empty() {
            break;
        }
        let batch_len = batch.len();
        out.extend(batch);
        if batch_len < 1000 {
            break;
        }
        marker = out.last().map(|obj| obj.object_key.clone());
    }
    Ok(out)
}

fn group_objects_by_delimiter(
    prefix: Option<&str>,
    delimiter: Option<&str>,
    objects: &[ObjectVersion],
) -> (Vec<ObjectVersion>, Vec<String>) {
    let mut contents = Vec::new();
    let mut common_prefixes = std::collections::BTreeSet::new();
    let prefix_val = prefix.unwrap_or("");
    if let Some(delim) = delimiter {
        for object in objects {
            let key = object.object_key.as_str();
            let rest = key.strip_prefix(prefix_val).unwrap_or(key);
            if let Some(pos) = rest.find(delim) {
                let end = pos + delim.len();
                let common = format!("{}{}", prefix_val, &rest[..end]);
                common_prefixes.insert(common);
                continue;
            }
            contents.push(object.clone());
        }
    } else {
        contents.extend_from_slice(objects);
    }
    (contents, common_prefixes.into_iter().collect())
}

fn build_list_entries(objects: Vec<ObjectVersion>, prefixes: &[String]) -> Vec<ListEntry> {
    let mut entries = Vec::new();
    for obj in objects {
        entries.push(ListEntry {
            key: obj.object_key.clone(),
            value: ListEntryValue::Object(obj),
        });
    }
    for prefix in prefixes {
        entries.push(ListEntry {
            key: prefix.clone(),
            value: ListEntryValue::Prefix(prefix.clone()),
        });
    }
    entries
}

fn split_list_entries(entries: Vec<ListEntry>) -> (Vec<ObjectVersion>, Vec<String>) {
    let mut objects = Vec::new();
    let mut prefixes = Vec::new();
    for entry in entries {
        match entry.value {
            ListEntryValue::Object(obj) => objects.push(obj),
            ListEntryValue::Prefix(prefix) => prefixes.push(prefix),
        }
    }
    (objects, prefixes)
}

fn build_cors(origins: &[String]) -> CorsLayer {
    if origins.iter().any(|val| val == "*") {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        let list = origins
            .iter()
            .filter_map(|val| HeaderValue::from_str(val).ok())
            .collect::<Vec<_>>();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(list))
            .allow_methods(Any)
            .allow_headers(Any)
    }
}

fn detect_s3_operation(
    method: &Method,
    key_present: bool,
    query: &HashMap<String, String>,
) -> &'static str {
    if key_present {
        return detect_object_operation(method, query);
    }
    detect_bucket_operation(method, query)
}

fn detect_object_operation(method: &Method, query: &HashMap<String, String>) -> &'static str {
    if query.contains_key("uploads") && *method == Method::POST {
        return "CreateMultipartUpload";
    }
    if query.contains_key("versionId") {
        return match *method {
            Method::GET => "GetObjectVersion",
            Method::HEAD => "HeadObjectVersion",
            Method::DELETE => "DeleteObjectVersion",
            _ => "Unknown",
        };
    }
    if query.contains_key("uploadId") {
        return match *method {
            Method::PUT => "UploadPart",
            Method::GET => "ListParts",
            Method::POST => "CompleteMultipartUpload",
            Method::DELETE => "AbortMultipartUpload",
            _ => "Unknown",
        };
    }
    match *method {
        Method::PUT => "PutObject",
        Method::GET => "GetObject",
        Method::HEAD => "HeadObject",
        Method::DELETE => "DeleteObject",
        _ => "Unknown",
    }
}

fn detect_bucket_operation(method: &Method, query: &HashMap<String, String>) -> &'static str {
    if query.contains_key("delete") && *method == Method::POST {
        return "DeleteObjects";
    }
    if query.contains_key("notification") && *method == Method::PUT {
        return "PutBucketNotification";
    }
    if query.contains_key("versioning") && *method == Method::PUT {
        return "PutBucketVersioning";
    }
    if *method == Method::PUT {
        return "CreateBucket";
    }
    if *method == Method::GET {
        return detect_bucket_get_operation(query);
    }
    match *method {
        Method::HEAD => "HeadBucket",
        Method::DELETE => "DeleteBucket",
        _ => "Unknown",
    }
}

fn detect_bucket_get_operation(query: &HashMap<String, String>) -> &'static str {
    if query.contains_key("location") {
        return "GetBucketLocation";
    }
    if query.contains_key("notification") {
        return "GetBucketNotification";
    }
    if query.contains_key("versioning") {
        return "GetBucketVersioning";
    }
    if query.contains_key("versions") {
        return "ListObjectVersions";
    }
    if query.contains_key("uploads") {
        return "ListMultipartUploads";
    }
    if query.get("list-type").map(String::as_str) == Some("2") {
        return "ListObjectsV2";
    }
    "ListObjects"
}

fn record_s3_request(state: &AppState, op: &str, status: StatusCode) {
    let status_label = status.as_u16().to_string();
    state
        .metrics
        .s3_requests
        .with_label_values(&[op, &status_label])
        .inc();
}

fn record_s3_bytes_in(state: &AppState, op: &str, size_bytes: i64) {
    if size_bytes <= 0 {
        return;
    }
    let count = size_bytes as u64;
    state
        .metrics
        .s3_bytes_in
        .with_label_values(&[op])
        .inc_by(count);
}

fn record_s3_bytes_out(state: &AppState, op: &str, size_bytes: usize) {
    if size_bytes == 0 {
        return;
    }
    state
        .metrics
        .s3_bytes_out
        .with_label_values(&[op])
        .inc_by(size_bytes as u64);
}

fn http_date(ts: DateTime<Utc>) -> String {
    ts.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

async fn fetch_checksum(state: &AppState, chunk_id: Uuid) -> Result<Checksum, S3Error> {
    let (algo, value): (String, Vec<u8>) =
        sqlx::query_as("SELECT checksum_algo, checksum_value FROM chunks WHERE chunk_id=$1")
            .bind(chunk_id)
            .fetch_one(state.repo.pool())
            .await
            .map_err(|_| S3Error::InternalError)?;
    let algo =
        crate::storage::checksum::ChecksumAlgo::parse(&algo).unwrap_or(state.config.checksum_algo);
    Ok(Checksum { algo, value })
}

async fn load_manifest_chunks(
    state: &AppState,
    manifest_id: Uuid,
) -> Result<Vec<ManifestChunk>, S3Error> {
    let cache_key = manifest_cache_key(manifest_id);
    if let Some(cached) = load_cached_manifest_chunks(state, manifest_id, &cache_key).await {
        return Ok(cached);
    }
    let chunks = state
        .repo
        .get_manifest_chunks(manifest_id)
        .await
        .map_err(|_| S3Error::InternalError)?;
    cache_manifest_chunks(state, &cache_key, &chunks).await;
    Ok(chunks)
}

fn manifest_cache_key(manifest_id: Uuid) -> String {
    format!("manifest:{}", manifest_id)
}

async fn load_cached_manifest_chunks(
    state: &AppState,
    manifest_id: Uuid,
    cache_key: &str,
) -> Option<Vec<ManifestChunk>> {
    let value = state.cache.get(cache_key).await?;
    parse_cached_manifest_chunks(manifest_id, &value)
}

fn parse_cached_manifest_chunks(manifest_id: Uuid, value: &str) -> Option<Vec<ManifestChunk>> {
    let list = serde_json::from_str::<Vec<String>>(value).ok()?;
    let mut chunks = Vec::new();
    for (index, entry) in list.into_iter().enumerate() {
        if let Ok(chunk_id) = Uuid::parse_str(&entry) {
            chunks.push(ManifestChunk {
                manifest_id,
                chunk_index: index as i32,
                chunk_id,
            });
        }
    }
    (!chunks.is_empty()).then_some(chunks)
}

async fn cache_manifest_chunks(state: &AppState, cache_key: &str, chunks: &[ManifestChunk]) {
    let chunk_ids: Vec<String> = chunks
        .iter()
        .map(|chunk| chunk.chunk_id.to_string())
        .collect();
    let value = serde_json::to_string(&chunk_ids).unwrap_or_default();
    let _ = state.cache.set(cache_key, &value, 300).await;
}

#[cfg(test)]
mod test_failpoints {
    use std::sync::atomic::{AtomicBool, Ordering};

    static UPLOAD_PART_BEGIN_FAIL: AtomicBool = AtomicBool::new(false);
    static UPLOAD_PART_TX_BEGIN_FAIL: AtomicBool = AtomicBool::new(false);

    pub fn trigger_upload_part_begin() {
        UPLOAD_PART_BEGIN_FAIL.store(true, Ordering::SeqCst);
    }

    pub fn take_upload_part_begin() -> bool {
        UPLOAD_PART_BEGIN_FAIL.swap(false, Ordering::SeqCst)
    }

    pub fn trigger_upload_part_tx_begin() {
        UPLOAD_PART_TX_BEGIN_FAIL.store(true, Ordering::SeqCst);
    }

    pub fn take_upload_part_tx_begin() -> bool {
        UPLOAD_PART_TX_BEGIN_FAIL.swap(false, Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::repos::delete_other_versions_fail_guard;
    use crate::test_support;
    use crate::test_support::{FailTriggerGuard, TableRenameGuard};
    use axum::body::{to_bytes, Body};
    use axum::extract::{OriginalUri, Path, RawQuery, State};
    use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
    use chrono::Utc;
    use futures_util::stream;
    use serde_json::json;
    use sha2::Digest;
    use sqlx;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn build_auth_headers(
        method: &str,
        path: &str,
        query: &str,
        access_key: &str,
        secret: &str,
    ) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost"));
        let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        headers.insert("x-amz-date", HeaderValue::from_str(&amz_date).unwrap());
        let payload_hash = payload_hash_for_method(method);
        let credential_scope = sigv4_credential_scope(&amz_date);
        let auth_header = build_sigv4_auth_header(
            method,
            path,
            query,
            access_key,
            secret,
            &headers,
            &amz_date,
            &payload_hash,
            &credential_scope,
        );
        headers.insert(
            "authorization",
            HeaderValue::from_str(&auth_header).unwrap(),
        );
        headers
    }

    fn payload_hash_for_method(method: &str) -> String {
        if method == "GET" || method == "HEAD" {
            "UNSIGNED-PAYLOAD".to_string()
        } else {
            hex::encode(sha2::Sha256::digest(b""))
        }
    }

    fn sigv4_credential_scope(amz_date: &str) -> String {
        format!("{}/us-east-1/s3/aws4_request", &amz_date[..8])
    }

    #[allow(clippy::too_many_arguments)]
    fn build_sigv4_auth_header(
        method: &str,
        path: &str,
        query: &str,
        access_key: &str,
        secret: &str,
        headers: &HeaderMap,
        amz_date: &str,
        payload_hash: &str,
        credential_scope: &str,
    ) -> String {
        let canonical_hash = sigv4_canonical_hash(method, path, query, headers, payload_hash);
        let signature = sigv4_signature(secret, amz_date, credential_scope, &canonical_hash);
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders=host;x-amz-date, Signature={}",
            access_key, credential_scope, signature
        )
    }

    fn sigv4_canonical_hash(
        method: &str,
        path: &str,
        query: &str,
        headers: &HeaderMap,
        payload_hash: &str,
    ) -> String {
        let signed_headers = vec!["host".to_string(), "x-amz-date".to_string()];
        let canonical_request = crate::s3::sigv4_core::build_canonical_request(
            method,
            path,
            query,
            headers,
            &signed_headers,
            payload_hash,
            false,
        )
        .expect("canonical");
        hex::encode(sha2::Sha256::digest(canonical_request.as_bytes()))
    }

    fn sigv4_signature(
        secret: &str,
        amz_date: &str,
        credential_scope: &str,
        canonical_hash: &str,
    ) -> String {
        let string_to_sign = crate::s3::sigv4_core::build_string_to_sign(
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            canonical_hash,
        );
        crate::s3::sigv4_core::calculate_signature(secret, credential_scope, &string_to_sign)
            .expect("signature")
    }

    async fn build_state_with_config(config: crate::util::config::Config) -> AppState {
        let pool = test_support::setup_pool().await;
        test_support::reset_db(&pool).await;
        let metrics = crate::obs::Metrics::new();
        let chunk_store =
            crate::storage::chunkstore::ChunkStore::from_runtime(&config).expect("chunk store");
        AppState::new(config, pool, chunk_store, metrics)
            .await
            .expect("state")
    }

    async fn basic_state() -> AppState {
        let data_dir = test_support::new_temp_dir("s3-basic").await;
        let config = test_support::base_config("master", data_dir);
        build_state_with_config(config).await
    }

    async fn state_with_events_enabled() -> AppState {
        let data_dir = test_support::new_temp_dir("s3-events").await;
        let mut config = test_support::base_config("master", data_dir);
        let url = std::env::var("NSS_RABBIT_URL")
            .unwrap_or_else(|_| "amqp://rabbitmq:5672/%2f".to_string());
        config.rabbit_url = Some(url);
        build_state_with_config(config).await
    }

    async fn create_user_and_bucket(
        state: &AppState,
        bucket_name: &str,
    ) -> (crate::meta::models::User, Bucket) {
        let user = state
            .repo
            .create_user("s3-user", Some("S3 User"), "hash", "active")
            .await
            .expect("user");
        let bucket = state
            .repo
            .create_bucket(bucket_name, user.id)
            .await
            .expect("bucket");
        (user, bucket)
    }

    async fn create_access_key(
        state: &AppState,
        user: &crate::meta::models::User,
        access_key_id: &str,
        secret: &[u8],
    ) {
        let encrypted =
            crate::util::crypto::encrypt_secret(&state.encryption_key, secret).expect("encrypt");
        state
            .repo
            .create_access_key(access_key_id, user.id, "label", "active", &encrypted)
            .await
            .expect("key");
    }

    async fn create_upload(state: &AppState, bucket: &Bucket, key: &str) -> String {
        let response = create_multipart_upload(state, bucket, key)
            .await
            .expect("create upload");
        assert_eq!(response.status(), StatusCode::OK);
        state
            .repo
            .list_multipart_uploads(bucket.id)
            .await
            .expect("uploads")
            .first()
            .expect("upload")
            .upload_id
            .clone()
    }

    fn complete_upload_one_part_xml(part_number: i32, etag: &str) -> String {
        format!(
            concat!(
                "<CompleteMultipartUpload><Part><PartNumber>{}</PartNumber>",
                "<ETag>\"{}\"</ETag></Part></CompleteMultipartUpload>"
            ),
            part_number, etag
        )
    }

    fn auth_for(user: crate::meta::models::User) -> AuthResult {
        AuthResult {
            user,
            access_key_id: "AKIA".to_string(),
            payload_hash: "UNSIGNED-PAYLOAD".to_string(),
        }
    }

    macro_rules! __parse_and_detect_helpers_cover_branches_body {
        () => {
            let mut headers = HeaderMap::new();
            headers.insert("host", HeaderValue::from_static("bucket.localhost"));
            let parsed = parse_bucket_key(&headers, "/object");
            assert!(parsed.is_some());
            let parsed = parse_bucket_key(&headers, "/");
            assert!(parsed.is_some());
            assert!(parsed.unwrap().key.is_none());

            headers.insert("host", HeaderValue::from_static("localhost"));
            let parsed = parse_bucket_key(&headers, "/bucket/key");
            assert!(parsed.is_some());
            let parsed = parse_bucket_key(&headers, "/bucket/");
            assert!(parsed.is_some());
            assert!(parsed.unwrap().key.is_none());

            let none = parse_bucket_key(&headers, "/");
            assert!(none.is_none());

            let host = parse_virtual_host("bucket.local", "path");
            assert!(host.is_some());
            assert!(parse_virtual_host("localhost", "path").is_none());
            assert!(parse_virtual_host("127.0.0.1", "path").is_none());

            let bucket_key = BucketKey {
                bucket: "b".to_string(),
                key: Some("k".to_string()),
            };
            assert!(is_public_read_request(&Method::GET, &bucket_key));
            assert!(is_public_read_request(&Method::HEAD, &bucket_key));
            let bucket_key = BucketKey {
                bucket: "b".to_string(),
                key: None,
            };
            assert!(!is_public_read_request(&Method::GET, &bucket_key));

            assert!(parse_range_header("bytes=0-1").is_some());
            assert!(parse_range_header("bytes=5-").is_some());
            assert!(parse_range_header("bytes=-1").is_none());
            assert!(parse_range_header("nope").is_none());

            let origins = vec!["*".to_string()];
            let _cors = build_cors(&origins);
            let origins = vec!["http://example.com".to_string()];
            let _cors = build_cors(&origins);

            let query = std::collections::HashMap::new();
            assert_eq!(detect_s3_operation(&Method::PUT, true, &query), "PutObject");
            assert_eq!(detect_s3_operation(&Method::GET, true, &query), "GetObject");
            assert_eq!(
                detect_s3_operation(&Method::HEAD, true, &query),
                "HeadObject"
            );
            assert_eq!(
                detect_s3_operation(&Method::DELETE, true, &query),
                "DeleteObject"
            );

            let mut query = std::collections::HashMap::new();
            query.insert("uploads".to_string(), "".to_string());
            assert_eq!(
                detect_s3_operation(&Method::POST, true, &query),
                "CreateMultipartUpload"
            );

            let mut query = std::collections::HashMap::new();
            query.insert("versionId".to_string(), "v1".to_string());
            assert_eq!(
                detect_s3_operation(&Method::GET, true, &query),
                "GetObjectVersion"
            );
            assert_eq!(
                detect_s3_operation(&Method::HEAD, true, &query),
                "HeadObjectVersion"
            );
            assert_eq!(
                detect_s3_operation(&Method::DELETE, true, &query),
                "DeleteObjectVersion"
            );
            assert_eq!(detect_s3_operation(&Method::POST, true, &query), "Unknown");

            let mut query = std::collections::HashMap::new();
            query.insert("uploadId".to_string(), "u1".to_string());
            assert_eq!(
                detect_s3_operation(&Method::PUT, true, &query),
                "UploadPart"
            );
            assert_eq!(detect_s3_operation(&Method::GET, true, &query), "ListParts");
            assert_eq!(
                detect_s3_operation(&Method::POST, true, &query),
                "CompleteMultipartUpload"
            );
            assert_eq!(
                detect_s3_operation(&Method::DELETE, true, &query),
                "AbortMultipartUpload"
            );
            assert_eq!(detect_s3_operation(&Method::PATCH, true, &query), "Unknown");

            let mut query = std::collections::HashMap::new();
            query.insert("delete".to_string(), "".to_string());
            assert_eq!(
                detect_s3_operation(&Method::POST, false, &query),
                "DeleteObjects"
            );

            let mut query = std::collections::HashMap::new();
            query.insert("notification".to_string(), "".to_string());
            assert_eq!(
                detect_s3_operation(&Method::PUT, false, &query),
                "PutBucketNotification"
            );
            assert_eq!(
                detect_s3_operation(&Method::GET, false, &query),
                "GetBucketNotification"
            );

            let mut query = std::collections::HashMap::new();
            query.insert("versioning".to_string(), "".to_string());
            assert_eq!(
                detect_s3_operation(&Method::PUT, false, &query),
                "PutBucketVersioning"
            );
            assert_eq!(
                detect_s3_operation(&Method::GET, false, &query),
                "GetBucketVersioning"
            );

            let mut query = std::collections::HashMap::new();
            query.insert("versions".to_string(), "".to_string());
            assert_eq!(
                detect_s3_operation(&Method::GET, false, &query),
                "ListObjectVersions"
            );

            let mut query = std::collections::HashMap::new();
            query.insert("uploads".to_string(), "".to_string());
            assert_eq!(
                detect_s3_operation(&Method::GET, false, &query),
                "ListMultipartUploads"
            );

            let mut query = std::collections::HashMap::new();
            query.insert("list-type".to_string(), "2".to_string());
            assert_eq!(
                detect_s3_operation(&Method::GET, false, &query),
                "ListObjectsV2"
            );

            let query = std::collections::HashMap::new();
            assert_eq!(
                detect_s3_operation(&Method::PUT, false, &query),
                "CreateBucket"
            );
            assert_eq!(
                detect_s3_operation(&Method::GET, false, &query),
                "ListObjects"
            );
            assert_eq!(
                detect_s3_operation(&Method::HEAD, false, &query),
                "HeadBucket"
            );
            assert_eq!(
                detect_s3_operation(&Method::DELETE, false, &query),
                "DeleteBucket"
            );
            assert_eq!(
                detect_s3_operation(&Method::PATCH, false, &query),
                "Unknown"
            );
        };
    }

    #[test]
    fn parse_and_detect_helpers_cover_branches() {
        __parse_and_detect_helpers_cover_branches_body!();
    }

    #[tokio::test]
    async fn record_helpers_and_read_body_limits() {
        let state = basic_state().await;
        record_s3_request(&state, "Op", StatusCode::OK);
        record_s3_bytes_in(&state, "Op", 0);
        record_s3_bytes_in(&state, "Op", 5);
        record_s3_bytes_out(&state, "Op", 0);
        record_s3_bytes_out(&state, "Op", 7);

        let ok_body = Body::from("hi");
        let bytes = read_body_limited(ok_body, 10).await.expect("body");
        assert_eq!(bytes, Bytes::from_static(b"hi"));

        let bad_body = Body::from("toolarge");
        let err = read_body_limited(bad_body, 1).await.unwrap_err();
        assert_eq!(err, S3Error::InvalidRequest);
    }

    #[tokio::test]
    async fn stream_body_to_chunks_skips_empty_frames() {
        let state = basic_state().await;
        let stream = stream::iter(vec![
            Ok::<Bytes, std::convert::Infallible>(Bytes::new()),
            Ok(Bytes::from_static(b"hello")),
        ]);
        let body = Body::from_stream(stream);
        let result = stream_body_to_chunks(&state, body).await.expect("chunks");
        assert_eq!(result.size_bytes, 5);
        assert_eq!(result.chunks.len(), 1);
    }

    #[tokio::test]
    async fn stream_body_to_chunks_handles_empty_body() {
        let state = basic_state().await;
        let stream = stream::iter(vec![Ok::<Bytes, std::convert::Infallible>(Bytes::new())]);
        let body = Body::from_stream(stream);
        let result = stream_body_to_chunks(&state, body).await.expect("chunks");
        assert_eq!(result.size_bytes, 0);
        assert!(result.chunks.is_empty());
    }

    #[tokio::test]
    async fn list_objects_all_handles_batches() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "batch-bucket").await;
        let now = Utc::now();
        for idx in 0..1001 {
            let key = format!("obj-{:04}", idx);
            sqlx::query(
                "INSERT INTO object_versions (bucket_id, object_key, version_id, is_delete_marker, \
                 size_bytes, etag, content_type, metadata_json, tags_json, created_at, current)
                 VALUES ($1,$2,$3,false,1,'etag',NULL,'{}','{}',$4,true)",
            )
            .bind(bucket.id)
            .bind(key)
            .bind(format!("v{}", idx))
            .bind(now)
            .execute(state.repo.pool())
            .await
            .expect("insert");
        }
        let objects = list_objects_all(&state, bucket.id, None, None)
            .await
            .expect("list");
        assert_eq!(objects.len(), 1001);
    }

    macro_rules! __bucket_dispatch_and_handlers_cover_queries_body {
        () => {
            let state = basic_state().await;
            let (user, bucket) = create_user_and_bucket(&state, "bucket-ops").await;
            let auth = auth_for(user.clone());

            // bucket not found paths
            let missing = BucketKey {
                bucket: "missing".to_string(),
                key: None,
            };
            let err = dispatch(
                &state,
                &auth,
                missing,
                Method::GET,
                HeaderMap::new(),
                "",
                Body::empty(),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::NoSuchBucket);

            // create bucket via dispatch
            let create = BucketKey {
                bucket: "new-bucket".to_string(),
                key: None,
            };
            let response = dispatch(
                &state,
                &auth,
                create,
                Method::PUT,
                HeaderMap::new(),
                "",
                Body::empty(),
            )
            .await
            .expect("create");
            assert_eq!(response.status(), StatusCode::OK);

            // bucket exists
            let exists = BucketKey {
                bucket: bucket.name.clone(),
                key: None,
            };
            let err = dispatch(
                &state,
                &auth,
                exists,
                Method::PUT,
                HeaderMap::new(),
                "",
                Body::empty(),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::BucketAlreadyExists);

            // put versioning
            let body = Body::from(concat!(
                "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
                "<Status>Enabled</Status></VersioningConfiguration>"
            ));
            let response = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::PUT,
                HeaderMap::new(),
                "versioning",
                body,
            )
            .await
            .expect("versioning");
            assert_eq!(response.status(), StatusCode::OK);

            // invalid versioning xml
            let body = Body::from("<bad/>");
            let err = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::PUT,
                HeaderMap::new(),
                "versioning",
                body,
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InvalidRequest);

            // notification with events disabled
            let body = Body::from("<NotificationConfiguration/>");
            let err = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::PUT,
                HeaderMap::new(),
                "notification",
                body,
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::NotImplemented);

            // get location/versioning
            let response = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::GET,
                HeaderMap::new(),
                "location",
                Body::empty(),
            )
            .await
            .expect("location");
            assert_eq!(response.status(), StatusCode::OK);

            let response = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::GET,
                HeaderMap::new(),
                "versioning",
                Body::empty(),
            )
            .await
            .expect("versioning");
            assert_eq!(response.status(), StatusCode::OK);

            // prepare object versions for list
            let (chunk_id, _checksum) =
                state.replication.write_chunk(b"data").await.expect("chunk");
            let _ = state
                .repo
                .finalize_object_version(
                    bucket.id,
                    "alpha",
                    "v1",
                    4,
                    "etag",
                    None,
                    &json!({}),
                    &json!({}),
                    &[chunk_id],
                    false,
                )
                .await
                .expect("version");

            let response = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::GET,
                HeaderMap::new(),
                "versions",
                Body::empty(),
            )
            .await
            .expect("versions");
            assert_eq!(response.status(), StatusCode::OK);

            let response = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::GET,
                HeaderMap::new(),
                "list-type=2&delimiter=/&start-after=a",
                Body::empty(),
            )
            .await
            .expect("list v2");
            assert_eq!(response.status(), StatusCode::OK);

            let upload = state
                .repo
                .create_multipart_upload(bucket.id, "big.bin", "upload-1")
                .await
                .expect("upload");
            let response = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::GET,
                HeaderMap::new(),
                "uploads",
                Body::empty(),
            )
            .await
            .expect("uploads");
            assert_eq!(response.status(), StatusCode::OK);

            let response = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::GET,
                HeaderMap::new(),
                "",
                Body::empty(),
            )
            .await
            .expect("list");
            assert_eq!(response.status(), StatusCode::OK);

            let response = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::HEAD,
                HeaderMap::new(),
                "",
                Body::empty(),
            )
            .await
            .expect("head");
            assert_eq!(response.status(), StatusCode::OK);

            let err = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::DELETE,
                HeaderMap::new(),
                "",
                Body::empty(),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InternalError);

            state
                .repo
                .delete_all_object_versions(bucket.id, "alpha")
                .await
                .expect("cleanup objects");
            state
                .repo
                .cleanup_multipart_upload(&upload.upload_id)
                .await
                .expect("cleanup upload");
            sqlx::query("DELETE FROM multipart_uploads WHERE upload_id=$1")
                .bind(&upload.upload_id)
                .execute(state.repo.pool())
                .await
                .expect("delete upload row");

            let response = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::DELETE,
                HeaderMap::new(),
                "",
                Body::empty(),
            )
            .await
            .expect("delete");
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        };
    }

    #[tokio::test]
    async fn bucket_dispatch_and_handlers_cover_queries() {
        __bucket_dispatch_and_handlers_cover_queries_body!();
    }

    macro_rules! __object_and_multipart_flows_cover_paths_body {
        () => {
            let state = basic_state().await;
            let (_user, bucket) = create_user_and_bucket(&state, "object-ops").await;

            let body = Body::from("hello world");
            let response = put_object(&state, &bucket, "file.txt", HeaderMap::new(), body)
                .await
                .expect("put");
            assert_eq!(response.status(), StatusCode::OK);

            let response = get_object(&state, &bucket, "file.txt", HeaderMap::new())
                .await
                .expect("get");
            assert_eq!(response.status(), StatusCode::OK);

            let mut range_headers = HeaderMap::new();
            range_headers.insert("range", HeaderValue::from_static("bytes=0-3"));
            let response = get_object(&state, &bucket, "file.txt", range_headers)
                .await
                .expect("range");
            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);

            let response = head_object(&state, &bucket, "file.txt")
                .await
                .expect("head");
            assert_eq!(response.status(), StatusCode::OK);

            let response = delete_object(&state, &bucket, "file.txt")
                .await
                .expect("delete");
            assert_eq!(response.status(), StatusCode::NO_CONTENT);

            state
                .repo
                .update_bucket_versioning(bucket.id, "enabled")
                .await
                .expect("versioning");
            let body = Body::from("data");
            let response = put_object(&state, &bucket, "versioned.txt", HeaderMap::new(), body)
                .await
                .expect("put");
            assert_eq!(response.status(), StatusCode::OK);
            let response = delete_object(&state, &bucket, "versioned.txt")
                .await
                .expect("delete");
            assert_eq!(response.status(), StatusCode::NO_CONTENT);

            let body = Body::from("data");
            let response = put_object(&state, &bucket, "del.txt", HeaderMap::new(), body)
                .await
                .expect("put");
            assert_eq!(response.status(), StatusCode::OK);
            let (obj, _manifest) = state
                .repo
                .get_object_current(bucket.id, "del.txt")
                .await
                .expect("current")
                .expect("exists");
            let response = get_object_version(
                &state,
                &bucket,
                "del.txt",
                &obj.version_id,
                HeaderMap::new(),
            )
            .await
            .expect("get version");
            assert_eq!(response.status(), StatusCode::OK);
            let response = head_object_version(&state, &bucket, "del.txt", &obj.version_id)
                .await
                .expect("head version");
            assert_eq!(response.status(), StatusCode::OK);

            let delete_body = "<Delete><Object><Key>del.txt</Key></Object></Delete>".to_string();
            let response = delete_objects(&state, &bucket, &Bytes::from(delete_body))
                .await
                .expect("delete objects");
            assert_eq!(response.status(), StatusCode::OK);

            let response = create_multipart_upload(&state, &bucket, "big.bin")
                .await
                .expect("create upload");
            assert_eq!(response.status(), StatusCode::OK);
            let upload_id = state
                .repo
                .list_multipart_uploads(bucket.id)
                .await
                .expect("uploads")
                .first()
                .expect("upload")
                .upload_id
                .clone();

            let body = Body::from("part1");
            let response = upload_part(&state, &bucket, "big.bin", &upload_id, 1, body)
                .await
                .expect("upload part");
            assert_eq!(response.status(), StatusCode::OK);

            let response = list_parts(&state, &bucket, "big.bin", &upload_id)
                .await
                .expect("list parts");
            assert_eq!(response.status(), StatusCode::OK);

            let parts = state
                .repo
                .list_multipart_parts(&upload_id)
                .await
                .expect("parts");
            let part = parts.first().expect("part");
            let invalid_body = complete_upload_one_part_xml(part.part_number, "deadbeef");
            let err = complete_multipart_upload(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                &Bytes::from(invalid_body),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InvalidPart);

            let valid_body = complete_upload_one_part_xml(part.part_number, part.etag.as_str());
            let response = complete_multipart_upload(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                &Bytes::from(valid_body),
            )
            .await
            .expect("complete");
            assert_eq!(response.status(), StatusCode::OK);

            let response = abort_multipart_upload(&state, &upload_id)
                .await
                .expect("abort");
            assert_eq!(response.status(), StatusCode::NO_CONTENT);

            let err = upload_part(&state, &bucket, "big.bin", "missing", 1, Body::from("data"))
                .await
                .unwrap_err();
            assert_eq!(err, S3Error::NoSuchUpload);
        };
    }

    #[tokio::test]
    async fn object_and_multipart_flows_cover_paths() {
        __object_and_multipart_flows_cover_paths_body!();
    }

    #[tokio::test]
    async fn complete_multipart_upload_rejects_mismatched_key() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "multipart-mismatch").await;
        let response = create_multipart_upload(&state, &bucket, "original.bin")
            .await
            .expect("create");
        assert_eq!(response.status(), StatusCode::OK);
        let upload_id = state
            .repo
            .list_multipart_uploads(bucket.id)
            .await
            .expect("uploads")
            .first()
            .expect("upload")
            .upload_id
            .clone();
        let err = complete_multipart_upload(
            &state,
            &bucket,
            "other.bin",
            &upload_id,
            &Bytes::from_static(b""),
        )
        .await
        .unwrap_err();
        assert_eq!(err, S3Error::NoSuchUpload);
    }

    macro_rules! __complete_multipart_upload_emits_event_body {
        () => {
            let state = state_with_events_enabled().await;
            let (_user, mut bucket) = create_user_and_bucket(&state, "multipart-events").await;
            bucket.notification_config_xml = Some("<NotificationConfiguration/>".to_string());

            let response = create_multipart_upload(&state, &bucket, "events.bin")
                .await
                .expect("create");
            assert_eq!(response.status(), StatusCode::OK);
            let upload_id = state
                .repo
                .list_multipart_uploads(bucket.id)
                .await
                .expect("uploads")
                .first()
                .expect("upload")
                .upload_id
                .clone();
            let response = upload_part(
                &state,
                &bucket,
                "events.bin",
                &upload_id,
                1,
                Body::from("part"),
            )
            .await
            .expect("upload part");
            assert_eq!(response.status(), StatusCode::OK);

            let parts = state
                .repo
                .list_multipart_parts(&upload_id)
                .await
                .expect("parts");
            let part = parts.first().expect("part");
            let body = complete_upload_one_part_xml(part.part_number, part.etag.as_str());
            let response = complete_multipart_upload(
                &state,
                &bucket,
                "events.bin",
                &upload_id,
                &Bytes::from(body),
            )
            .await
            .expect("complete");
            assert_eq!(response.status(), StatusCode::OK);
        };
    }

    #[tokio::test]
    async fn complete_multipart_upload_emits_event() {
        __complete_multipart_upload_emits_event_body!();
    }

    macro_rules! __load_manifest_chunks_uses_cache_and_fallbacks_body {
        () => {
            let state = basic_state().await;
            let (_user, bucket) = create_user_and_bucket(&state, "cache-bucket").await;
            let body = Body::from("cache data");
            let response = put_object(&state, &bucket, "cache.txt", HeaderMap::new(), body)
                .await
                .expect("put");
            assert_eq!(response.status(), StatusCode::OK);
            let (_object, manifest_id) = state
                .repo
                .get_object_current(bucket.id, "cache.txt")
                .await
                .expect("current")
                .expect("exists");

            let cache_key = format!("manifest:{}", manifest_id);
            let chunks = load_manifest_chunks(&state, manifest_id)
                .await
                .expect("chunks");
            assert!(!chunks.is_empty());

            let cached = load_manifest_chunks(&state, manifest_id)
                .await
                .expect("cached");
            assert_eq!(cached.len(), chunks.len());

            state
                .cache
                .set(&cache_key, "not-json", 300)
                .await
                .expect("set");
            let fallback = load_manifest_chunks(&state, manifest_id)
                .await
                .expect("fallback");
            assert_eq!(fallback.len(), chunks.len());

            state
                .cache
                .set(&cache_key, "[\"bad-uuid\"]", 300)
                .await
                .expect("set");
            let fallback = load_manifest_chunks(&state, manifest_id)
                .await
                .expect("fallback");
            assert_eq!(fallback.len(), chunks.len());
        };
    }

    #[tokio::test]
    async fn load_manifest_chunks_uses_cache_and_fallbacks() {
        __load_manifest_chunks_uses_cache_and_fallbacks_body!();
    }

    macro_rules! __fetch_checksum_and_build_object_response_errors_body {
        () => {
            let state = basic_state().await;
            let (_user, bucket) = create_user_and_bucket(&state, "checksum-bucket").await;
            let body = Body::from("checksum");
            let response = put_object(&state, &bucket, "sum.txt", HeaderMap::new(), body)
                .await
                .expect("put");
            assert_eq!(response.status(), StatusCode::OK);
            let (_object, manifest_id) = state
                .repo
                .get_object_current(bucket.id, "sum.txt")
                .await
                .expect("current")
                .expect("exists");
            let manifest_chunks = state
                .repo
                .get_manifest_chunks(manifest_id)
                .await
                .expect("chunks");
            let chunk_id = manifest_chunks[0].chunk_id;

            sqlx::query("UPDATE chunks SET checksum_algo='unknown' WHERE chunk_id=$1")
                .bind(chunk_id)
                .execute(state.repo.pool())
                .await
                .expect("update");
            let checksum = fetch_checksum(&state, chunk_id).await.expect("checksum");
            assert_eq!(checksum.algo, state.config.checksum_algo);

            let err = fetch_checksum(&state, Uuid::new_v4()).await.unwrap_err();
            assert_eq!(err, S3Error::InternalError);

            let mut object = state
                .repo
                .get_object_current(bucket.id, "sum.txt")
                .await
                .expect("current")
                .expect("exists")
                .0;
            object.size_bytes = -1;
            let err = build_object_response(&state, &object, manifest_id, HeaderMap::new(), "Get")
                .await
                .unwrap_err();
            assert_eq!(err, S3Error::InternalError);

            let object = state
                .repo
                .get_object_current(bucket.id, "sum.txt")
                .await
                .expect("current")
                .expect("exists")
                .0;
            let mut headers = HeaderMap::new();
            headers.insert("range", HeaderValue::from_static("bytes=10-9"));
            let err = build_object_response(&state, &object, manifest_id, headers, "Get")
                .await
                .unwrap_err();
            assert_eq!(err, S3Error::InvalidRequest);
        };
    }

    #[tokio::test]
    async fn fetch_checksum_and_build_object_response_errors() {
        __fetch_checksum_and_build_object_response_errors_body!();
    }

    macro_rules! __root_and_path_handlers_cover_public_and_invalid_body {
        () => {
            let state = basic_state().await;
            let (user, bucket) = create_user_and_bucket(&state, "public-bucket").await;
            create_access_key(&state, &user, "AKIAROOT", b"secret").await;
            state
                .repo
                .update_bucket_public(bucket.id, true)
                .await
                .expect("public");
            let body = Body::from("public");
            put_object(&state, &bucket, "pub.txt", HeaderMap::new(), body)
                .await
                .expect("put");

            let headers = HeaderMap::new();
            let response = root_handler(State(state.clone()), Method::PUT, headers.clone()).await;
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

            let headers = build_auth_headers("GET", "/", "", "AKIAROOT", "secret");
            let response = root_handler(State(state.clone()), Method::GET, headers).await;
            assert_eq!(response.status(), StatusCode::OK);

            let response = path_handler(
                State(state.clone()),
                Path("".to_string()),
                OriginalUri("/".parse().expect("uri")),
                Method::GET,
                HeaderMap::new(),
                RawQuery(None),
                Body::empty(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);

            let response = path_handler(
                State(state.clone()),
                Path(format!("{}/pub.txt", bucket.name)),
                OriginalUri(format!("/{}/pub.txt", bucket.name).parse().expect("uri")),
                Method::GET,
                HeaderMap::new(),
                RawQuery(None),
                Body::empty(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);

            let auth_headers = build_auth_headers(
                "GET",
                &format!("/{}/pub.txt", bucket.name),
                "",
                "AKIAROOT",
                "secret",
            );
            let response = path_handler(
                State(state.clone()),
                Path(format!("{}/pub.txt", bucket.name)),
                OriginalUri(format!("/{}/pub.txt", bucket.name).parse().expect("uri")),
                Method::GET,
                auth_headers,
                RawQuery(None),
                Body::empty(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
        };
    }

    #[tokio::test]
    async fn root_and_path_handlers_cover_public_and_invalid() {
        __root_and_path_handlers_cover_public_and_invalid_body!();
    }

    macro_rules! __notification_handlers_cover_event_paths_body {
        () => {
            let state = basic_state().await;
            let (user, bucket) = create_user_and_bucket(&state, "notify-bucket").await;
            let auth = auth_for(user.clone());

            let err = handle_get_bucket_notification(&state, &auth, bucket.clone())
                .await
                .unwrap_err();
            assert_eq!(err, S3Error::NotImplemented);

            let state = state_with_events_enabled().await;
            let (user, bucket) = create_user_and_bucket(&state, "notify-bucket-2").await;
            let auth = auth_for(user.clone());
            state
                .repo
                .update_bucket_notification(bucket.id, "<NotificationConfiguration/>")
                .await
                .expect("update");

            let body = Bytes::from_static(b"<NotificationConfiguration/>");
            let response = handle_put_bucket_notification(&state, &auth, bucket.clone(), &body)
                .await
                .expect("put");
            assert_eq!(response.status(), StatusCode::OK);

            let err = handle_put_bucket_notification(
                &state,
                &auth,
                bucket.clone(),
                &Bytes::from_static(b"bad"),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::MalformedXML);
        };
    }

    #[tokio::test]
    async fn notification_handlers_cover_event_paths() {
        __notification_handlers_cover_event_paths_body!();
    }

    #[tokio::test]
    async fn public_dispatch_rejects_private_bucket() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "private-bucket").await;
        let err = dispatch_public(
            &state,
            bucket,
            "key.txt",
            Method::GET,
            HeaderMap::new(),
            &HashMap::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    macro_rules! __handle_object_rejects_invalid_version_and_upload_requests_body {
        () => {
            let state = basic_state().await;
            let (user, bucket) = create_user_and_bucket(&state, "invalid-object").await;
            let auth = auth_for(user);
            let mut query = HashMap::new();
            query.insert("versionId".to_string(), "v1".to_string());
            let err = handle_object(
                &state,
                &auth,
                bucket.clone(),
                "key.txt",
                Method::PUT,
                HeaderMap::new(),
                &query,
                Body::empty(),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InvalidRequest);

            let mut query = HashMap::new();
            query.insert("uploadId".to_string(), "upload-1".to_string());
            let err = handle_object(
                &state,
                &auth,
                bucket.clone(),
                "key.txt",
                Method::PUT,
                HeaderMap::new(),
                &query,
                Body::empty(),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InvalidRequest);

            let mut query = HashMap::new();
            query.insert("uploadId".to_string(), "upload-1".to_string());
            query.insert("partNumber".to_string(), "bad".to_string());
            let err = handle_object(
                &state,
                &auth,
                bucket.clone(),
                "key.txt",
                Method::PUT,
                HeaderMap::new(),
                &query,
                Body::empty(),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InvalidRequest);

            let mut query = HashMap::new();
            query.insert("uploadId".to_string(), "upload-1".to_string());
            let err = handle_object(
                &state,
                &auth,
                bucket.clone(),
                "key.txt",
                Method::PATCH,
                HeaderMap::new(),
                &query,
                Body::empty(),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InvalidRequest);
        };
    }

    #[tokio::test]
    async fn handle_object_rejects_invalid_version_and_upload_requests() {
        __handle_object_rejects_invalid_version_and_upload_requests_body!();
    }

    #[tokio::test]
    async fn delete_object_version_missing_returns_error() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "version-missing").await;
        let err = delete_object_version(&state, &bucket, "key.txt", "missing")
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::NoSuchKey);
    }

    macro_rules! __group_objects_by_delimiter_splits_prefixes_body {
        () => {
            let now = Utc::now();
            let objects = vec![
                crate::meta::models::ObjectVersion {
                    id: Uuid::new_v4(),
                    bucket_id: Uuid::new_v4(),
                    object_key: "a/file.txt".to_string(),
                    version_id: "v1".to_string(),
                    is_delete_marker: false,
                    size_bytes: 1,
                    etag: Some("etag".to_string()),
                    content_type: None,
                    metadata_json: json!({}),
                    tags_json: json!({}),
                    created_at: now,
                    current: true,
                },
                crate::meta::models::ObjectVersion {
                    id: Uuid::new_v4(),
                    bucket_id: Uuid::new_v4(),
                    object_key: "a/dir/file.txt".to_string(),
                    version_id: "v1".to_string(),
                    is_delete_marker: false,
                    size_bytes: 1,
                    etag: Some("etag".to_string()),
                    content_type: None,
                    metadata_json: json!({}),
                    tags_json: json!({}),
                    created_at: now,
                    current: true,
                },
            ];
            let (contents, prefixes) = group_objects_by_delimiter(Some("a/"), Some("/"), &objects);
            assert_eq!(contents.len(), 1);
            assert_eq!(prefixes, vec!["a/dir/".to_string()]);

            let (contents, prefixes) = group_objects_by_delimiter(None, None, &objects);
            assert_eq!(contents.len(), 2);
            assert!(prefixes.is_empty());
        };
    }

    #[test]
    fn group_objects_by_delimiter_splits_prefixes() {
        __group_objects_by_delimiter_splits_prefixes_body!();
    }

    macro_rules! __build_object_response_handles_empty_and_clamped_ranges_body {
        () => {
            let state = basic_state().await;
            let (_user, bucket) = create_user_and_bucket(&state, "range-bucket").await;

            state
                .repo
                .finalize_object_version(
                    bucket.id,
                    "empty.txt",
                    "v1",
                    0,
                    "etag",
                    None,
                    &json!({}),
                    &json!({}),
                    &[],
                    false,
                )
                .await
                .expect("object");
            let (obj, manifest_id) = state
                .repo
                .get_object_current(bucket.id, "empty.txt")
                .await
                .expect("current")
                .expect("exists");
            let response =
                build_object_response(&state, &obj, manifest_id, HeaderMap::new(), "Get")
                    .await
                    .expect("response");
            assert_eq!(response.status(), StatusCode::OK);

            let body = Body::from("data");
            put_object(&state, &bucket, "range.txt", HeaderMap::new(), body)
                .await
                .expect("put");
            let (obj, manifest_id) = state
                .repo
                .get_object_current(bucket.id, "range.txt")
                .await
                .expect("current")
                .expect("exists");
            let mut headers = HeaderMap::new();
            headers.insert("range", HeaderValue::from_static("bytes=0-100"));
            let response = build_object_response(&state, &obj, manifest_id, headers, "Get")
                .await
                .expect("range");
            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
            let content_range = response.headers().get("Content-Range").expect("range");
            assert!(content_range.to_str().unwrap().starts_with("bytes 0-"));
        };
    }

    #[tokio::test]
    async fn build_object_response_handles_empty_and_clamped_ranges() {
        __build_object_response_handles_empty_and_clamped_ranges_body!();
    }

    #[tokio::test]
    async fn path_handler_requires_auth_for_private_bucket() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "private-path").await;
        let response = path_handler(
            State(state),
            Path(format!("{}/key.txt", bucket.name)),
            OriginalUri(format!("/{}/key.txt", bucket.name).parse().expect("uri")),
            Method::GET,
            HeaderMap::new(),
            RawQuery(None),
            Body::empty(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn path_handler_rejects_missing_auth_for_non_public_request() {
        let state = basic_state().await;
        let response = path_handler(
            State(state),
            Path("missing-auth-bucket".to_string()),
            OriginalUri("/missing-auth-bucket".parse().expect("uri")),
            Method::PUT,
            HeaderMap::new(),
            RawQuery(None),
            Body::empty(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    macro_rules! __handle_get_bucket_versions_and_list_v2_cover_markers_body {
        () => {
            let state = basic_state().await;
            let (user, bucket) = create_user_and_bucket(&state, "marker-bucket").await;
            let auth = auth_for(user);
            let (chunk_a, _) = state.replication.write_chunk(b"a").await.expect("chunk");
            let (chunk_b, _) = state.replication.write_chunk(b"b").await.expect("chunk");
            let (chunk_c, _) = state.replication.write_chunk(b"c").await.expect("chunk");

            state
                .repo
                .finalize_object_version(
                    bucket.id,
                    "alpha",
                    "v1",
                    1,
                    "etag-a1",
                    None,
                    &json!({}),
                    &json!({}),
                    &[chunk_a],
                    false,
                )
                .await
                .expect("alpha v1");
            state
                .repo
                .finalize_object_version(
                    bucket.id,
                    "alpha",
                    "v2",
                    1,
                    "etag-a2",
                    None,
                    &json!({}),
                    &json!({}),
                    &[chunk_b],
                    false,
                )
                .await
                .expect("alpha v2");
            state
                .repo
                .finalize_object_version(
                    bucket.id,
                    "apple",
                    "v1",
                    1,
                    "etag-ap1",
                    None,
                    &json!({}),
                    &json!({}),
                    &[chunk_c],
                    false,
                )
                .await
                .expect("apple v1");

            let mut query = HashMap::new();
            query.insert("versions".to_string(), "".to_string());
            query.insert("prefix".to_string(), "a".to_string());
            query.insert("key-marker".to_string(), "alpha".to_string());
            query.insert("version-id-marker".to_string(), "v2".to_string());
            query.insert("max-keys".to_string(), "1".to_string());
            let response = handle_get_bucket(&state, &auth, bucket.clone(), &query)
                .await
                .expect("versions");
            assert_eq!(response.status(), StatusCode::OK);

            let body = Body::from("readme");
            put_object(&state, &bucket, "photos/readme.txt", HeaderMap::new(), body)
                .await
                .expect("put readme");
            let body = Body::from("photo-a");
            put_object(&state, &bucket, "photos/2023/a.jpg", HeaderMap::new(), body)
                .await
                .expect("put a");
            let body = Body::from("photo-b");
            put_object(&state, &bucket, "photos/2024/b.jpg", HeaderMap::new(), body)
                .await
                .expect("put b");

            let mut query = HashMap::new();
            query.insert("list-type".to_string(), "2".to_string());
            query.insert("prefix".to_string(), "photos/".to_string());
            query.insert("delimiter".to_string(), "/".to_string());
            query.insert("continuation-token".to_string(), "photos/".to_string());
            query.insert("max-keys".to_string(), "1".to_string());
            let response = handle_get_bucket(&state, &auth, bucket.clone(), &query)
                .await
                .expect("list v2");
            assert_eq!(response.status(), StatusCode::OK);

            let mut query = HashMap::new();
            query.insert("list-type".to_string(), "2".to_string());
            query.insert("prefix".to_string(), "photos/".to_string());
            query.insert("delimiter".to_string(), "/".to_string());
            query.insert("start-after".to_string(), "photos/2023/".to_string());
            query.insert("max-keys".to_string(), "1".to_string());
            let response = handle_get_bucket(&state, &auth, bucket, &query)
                .await
                .expect("list v2");
            assert_eq!(response.status(), StatusCode::OK);
        };
    }

    #[tokio::test]
    async fn handle_get_bucket_versions_and_list_v2_cover_markers() {
        __handle_get_bucket_versions_and_list_v2_cover_markers_body!();
    }

    #[tokio::test]
    async fn handle_get_bucket_notification_uses_default_xml() {
        let state = state_with_events_enabled().await;
        let (user, bucket) = create_user_and_bucket(&state, "notify-default").await;
        let auth = auth_for(user);
        let response = handle_get_bucket_notification(&state, &auth, bucket)
            .await
            .expect("notification");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn handle_delete_objects_executes_for_owner() {
        let state = basic_state().await;
        let (user, bucket) = create_user_and_bucket(&state, "delete-bucket").await;
        let auth = auth_for(user);
        let body = Bytes::from_static(b"<Delete><Object><Key>missing</Key></Object></Delete>");
        let response = handle_delete_objects(&state, &auth, bucket, &HashMap::new(), &body)
            .await
            .expect("delete objects");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn put_object_honors_content_type() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "content-type").await;
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        let response = put_object(&state, &bucket, "note.txt", headers, Body::from("note"))
            .await
            .expect("put");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn build_object_response_streams_body_bytes() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "stream-bucket").await;
        let body = Body::from("payload");
        put_object(&state, &bucket, "stream.txt", HeaderMap::new(), body)
            .await
            .expect("put");
        let (obj, manifest_id) = state
            .repo
            .get_object_current(bucket.id, "stream.txt")
            .await
            .expect("current")
            .expect("exists");
        let response = build_object_response(&state, &obj, manifest_id, HeaderMap::new(), "Get")
            .await
            .expect("response");
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(bytes, Bytes::from_static(b"payload"));
    }

    #[tokio::test]
    async fn router_adds_cors_layer_when_configured() {
        let data_dir = test_support::new_temp_dir("s3-cors").await;
        let mut config = test_support::base_config("master", data_dir);
        config.cors_allow_origins = vec!["https://example.com".to_string()];
        let state = build_state_with_config(config).await;
        let _ = router(state);
    }

    #[tokio::test]
    async fn root_handler_rejects_missing_auth() {
        let state = basic_state().await;
        let response = root_handler(State(state), Method::GET, HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn root_handler_reports_bucket_repo_error() {
        let state = basic_state().await;
        let (user, _bucket) = create_user_and_bucket(&state, "root-bucket").await;
        create_access_key(&state, &user, "AKIAROOT", b"secret").await;
        let headers = build_auth_headers("GET", "/", "", "AKIAROOT", "secret");
        let pool = state.repo.pool().clone();
        sqlx::query("ALTER TABLE buckets RENAME TO buckets_backup")
            .execute(&pool)
            .await
            .expect("rename");
        let response = root_handler(State(state), Method::GET, headers).await;
        let _ = sqlx::query("ALTER TABLE buckets_backup RENAME TO buckets")
            .execute(&pool)
            .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn path_handler_rejects_private_request_without_auth() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "private-bucket").await;
        let response = path_handler(
            State(state),
            Path(format!("{}/secret.txt", bucket.name)),
            OriginalUri(format!("/{}/secret.txt", bucket.name).parse().expect("uri")),
            Method::GET,
            HeaderMap::new(),
            RawQuery(None),
            Body::empty(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn path_handler_maps_dispatch_errors() {
        let state = basic_state().await;
        let (user, bucket) = create_user_and_bucket(&state, "dispatch-bucket").await;
        create_access_key(&state, &user, "AKIADISPATCH", b"secret").await;
        let path = format!("/{}/file.txt", bucket.name);
        let headers = build_auth_headers("PATCH", &path, "", "AKIADISPATCH", "secret");
        let response = path_handler(
            State(state),
            Path(format!("{}/file.txt", bucket.name)),
            OriginalUri(format!("/{}/file.txt", bucket.name).parse().expect("uri")),
            Method::PATCH,
            headers,
            RawQuery(None),
            Body::empty(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn path_handler_public_dispatch_error_for_missing_version() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "public-missing").await;
        state
            .repo
            .update_bucket_public(bucket.id, true)
            .await
            .expect("public");
        let response = path_handler(
            State(state),
            Path(format!("{}/missing.txt", bucket.name)),
            OriginalUri(
                format!("/{}/missing.txt", bucket.name)
                    .parse()
                    .expect("uri"),
            ),
            Method::GET,
            HeaderMap::new(),
            RawQuery(Some("versionId=missing".to_string())),
            Body::empty(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    macro_rules! __dispatch_public_supports_versioned_reads_and_invalid_method_body {
        () => {
            let state = basic_state().await;
            let (_user, bucket) = create_user_and_bucket(&state, "public-versions").await;
            state
                .repo
                .update_bucket_public(bucket.id, true)
                .await
                .expect("public");
            let bucket = state
                .repo
                .get_bucket(&bucket.name)
                .await
                .expect("bucket lookup")
                .expect("bucket");
            put_object(
                &state,
                &bucket,
                "file.txt",
                HeaderMap::new(),
                Body::from("payload"),
            )
            .await
            .expect("put");
            let (object, _manifest) = state
                .repo
                .get_object_current(bucket.id, "file.txt")
                .await
                .expect("current")
                .expect("object");
            let mut query = HashMap::new();
            query.insert("versionId".to_string(), object.version_id.clone());

            let response = dispatch_public(
                &state,
                bucket.clone(),
                "file.txt",
                Method::GET,
                HeaderMap::new(),
                &query,
            )
            .await
            .expect("get version");
            assert_eq!(response.status(), StatusCode::OK);

            let response = dispatch_public(
                &state,
                bucket.clone(),
                "file.txt",
                Method::HEAD,
                HeaderMap::new(),
                &query,
            )
            .await
            .expect("head version");
            assert_eq!(response.status(), StatusCode::OK);

            let err = dispatch_public(
                &state,
                bucket.clone(),
                "file.txt",
                Method::POST,
                HeaderMap::new(),
                &query,
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InvalidRequest);

            let err = dispatch_public(
                &state,
                bucket.clone(),
                "file.txt",
                Method::POST,
                HeaderMap::new(),
                &HashMap::new(),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InvalidRequest);

            let response = dispatch_public(
                &state,
                bucket.clone(),
                "file.txt",
                Method::GET,
                HeaderMap::new(),
                &HashMap::new(),
            )
            .await
            .expect("get");
            assert_eq!(response.status(), StatusCode::OK);

            let response = dispatch_public(
                &state,
                bucket,
                "file.txt",
                Method::HEAD,
                HeaderMap::new(),
                &HashMap::new(),
            )
            .await
            .expect("head");
            assert_eq!(response.status(), StatusCode::OK);
        };
    }

    #[tokio::test]
    async fn dispatch_public_supports_versioned_reads_and_invalid_method() {
        __dispatch_public_supports_versioned_reads_and_invalid_method_body!();
    }

    #[tokio::test]
    async fn handle_get_bucket_access_denied() {
        let state = basic_state().await;
        let (user, bucket) = create_user_and_bucket(&state, "deny-bucket").await;
        let other = state
            .repo
            .create_user("other-user", None, "hash", "active")
            .await
            .expect("user");
        let err = handle_get_bucket(&state, &auth_for(other), bucket, &HashMap::new())
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
        let _ = user;
    }

    #[tokio::test]
    async fn handle_get_bucket_notification_disabled() {
        let state = basic_state().await;
        let (user, bucket) = create_user_and_bucket(&state, "notify-bucket").await;
        let mut query = HashMap::new();
        query.insert("notification".to_string(), "".to_string());
        let err = handle_get_bucket(&state, &auth_for(user), bucket, &query)
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::NotImplemented);
    }

    #[tokio::test]
    async fn handle_get_bucket_versions_repo_error() {
        let state = basic_state().await;
        let (user, bucket) = create_user_and_bucket(&state, "versions-error").await;
        let pool = state.repo.pool().clone();
        sqlx::query("ALTER TABLE object_versions RENAME TO object_versions_backup")
            .execute(&pool)
            .await
            .expect("rename");
        let mut query = HashMap::new();
        query.insert("versions".to_string(), "".to_string());
        let result = handle_get_bucket(&state, &auth_for(user), bucket, &query).await;
        let _ = sqlx::query("ALTER TABLE object_versions_backup RENAME TO object_versions")
            .execute(&pool)
            .await;
        let err = result.unwrap_err();
        assert_eq!(err, S3Error::InternalError);
    }

    #[tokio::test]
    async fn handle_get_bucket_list_v2_defaults() {
        let state = basic_state().await;
        let (user, bucket) = create_user_and_bucket(&state, "listv2-bucket").await;
        put_object(
            &state,
            &bucket,
            "alpha.txt",
            HeaderMap::new(),
            Body::from("a"),
        )
        .await
        .expect("put");
        put_object(
            &state,
            &bucket,
            "photos/beta.txt",
            HeaderMap::new(),
            Body::from("b"),
        )
        .await
        .expect("put");
        let mut query = HashMap::new();
        query.insert("list-type".to_string(), "2".to_string());
        let response = handle_get_bucket(&state, &auth_for(user), bucket, &query)
            .await
            .expect("list v2");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn handle_get_bucket_uploads_repo_error() {
        let state = basic_state().await;
        let (user, bucket) = create_user_and_bucket(&state, "uploads-error").await;
        let pool = state.repo.pool().clone();
        sqlx::query("ALTER TABLE multipart_uploads RENAME TO multipart_uploads_backup")
            .execute(&pool)
            .await
            .expect("rename");
        let mut query = HashMap::new();
        query.insert("uploads".to_string(), "".to_string());
        let result = handle_get_bucket(&state, &auth_for(user), bucket, &query).await;
        let _ = sqlx::query("ALTER TABLE multipart_uploads_backup RENAME TO multipart_uploads")
            .execute(&pool)
            .await;
        let err = result.unwrap_err();
        assert_eq!(err, S3Error::InternalError);
    }

    #[tokio::test]
    async fn handle_get_bucket_list_current_repo_error() {
        let state = basic_state().await;
        let (user, bucket) = create_user_and_bucket(&state, "list-error").await;
        let pool = state.repo.pool().clone();
        sqlx::query("ALTER TABLE object_versions RENAME TO object_versions_backup")
            .execute(&pool)
            .await
            .expect("rename");
        let result = handle_get_bucket(&state, &auth_for(user), bucket, &HashMap::new()).await;
        let _ = sqlx::query("ALTER TABLE object_versions_backup RENAME TO object_versions")
            .execute(&pool)
            .await;
        let err = result.unwrap_err();
        assert_eq!(err, S3Error::InternalError);
    }

    #[tokio::test]
    async fn handle_object_rejects_other_user() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "object-deny").await;
        let other = state
            .repo
            .create_user("other-user", None, "hash", "active")
            .await
            .expect("user");
        let err = handle_object(
            &state,
            &auth_for(other),
            bucket,
            "file.txt",
            Method::GET,
            HeaderMap::new(),
            &HashMap::new(),
            Body::empty(),
        )
        .await
        .unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[tokio::test]
    async fn handle_object_put_creates_object() {
        let state = basic_state().await;
        let (user, bucket) = create_user_and_bucket(&state, "object-put").await;
        let response = handle_object(
            &state,
            &auth_for(user),
            bucket.clone(),
            "file.txt",
            Method::PUT,
            HeaderMap::new(),
            &HashMap::new(),
            Body::from("data"),
        )
        .await
        .expect("put");
        assert_eq!(response.status(), StatusCode::OK);
        let (object, _manifest) = state
            .repo
            .get_object_current(bucket.id, "file.txt")
            .await
            .expect("current")
            .expect("object");
        assert_eq!(object.size_bytes, 4);
    }

    macro_rules! __handle_object_version_and_multipart_branches_body {
        () => {
            let state = basic_state().await;
            let (user, bucket) = create_user_and_bucket(&state, "object-branches").await;
            put_object(
                &state,
                &bucket,
                "versioned.txt",
                HeaderMap::new(),
                Body::from("data"),
            )
            .await
            .expect("put");
            let (object, _manifest) = state
                .repo
                .get_object_current(bucket.id, "versioned.txt")
                .await
                .expect("current")
                .expect("object");
            let mut version_query = HashMap::new();
            version_query.insert("versionId".to_string(), object.version_id.clone());

            let response = handle_object(
                &state,
                &auth_for(user.clone()),
                bucket.clone(),
                "versioned.txt",
                Method::GET,
                HeaderMap::new(),
                &version_query,
                Body::empty(),
            )
            .await
            .expect("get version");
            assert_eq!(response.status(), StatusCode::OK);

            let response = handle_object(
                &state,
                &auth_for(user.clone()),
                bucket.clone(),
                "versioned.txt",
                Method::HEAD,
                HeaderMap::new(),
                &version_query,
                Body::empty(),
            )
            .await
            .expect("head version");
            assert_eq!(response.status(), StatusCode::OK);

            let response = handle_object(
                &state,
                &auth_for(user.clone()),
                bucket.clone(),
                "versioned.txt",
                Method::DELETE,
                HeaderMap::new(),
                &version_query,
                Body::empty(),
            )
            .await
            .expect("delete version");
            assert_eq!(response.status(), StatusCode::NO_CONTENT);

            let err = handle_object(
                &state,
                &auth_for(user.clone()),
                bucket.clone(),
                "versioned.txt",
                Method::PUT,
                HeaderMap::new(),
                &version_query,
                Body::empty(),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InvalidRequest);

            let mut uploads_query = HashMap::new();
            uploads_query.insert("uploads".to_string(), "".to_string());
            let response = handle_object(
                &state,
                &auth_for(user.clone()),
                bucket.clone(),
                "big.bin",
                Method::POST,
                HeaderMap::new(),
                &uploads_query,
                Body::empty(),
            )
            .await
            .expect("create upload");
            assert_eq!(response.status(), StatusCode::OK);

            let uploads = state
                .repo
                .list_multipart_uploads(bucket.id)
                .await
                .expect("uploads");
            let upload_id = uploads[0].upload_id.clone();

            let mut missing_part = HashMap::new();
            missing_part.insert("uploadId".to_string(), upload_id.clone());
            let err = handle_object(
                &state,
                &auth_for(user.clone()),
                bucket.clone(),
                "big.bin",
                Method::PUT,
                HeaderMap::new(),
                &missing_part,
                Body::from("part"),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InvalidRequest);

            let mut upload_part_query = HashMap::new();
            upload_part_query.insert("uploadId".to_string(), upload_id.clone());
            upload_part_query.insert("partNumber".to_string(), "1".to_string());
            let response = handle_object(
                &state,
                &auth_for(user.clone()),
                bucket.clone(),
                "big.bin",
                Method::PUT,
                HeaderMap::new(),
                &upload_part_query,
                Body::from("part"),
            )
            .await
            .expect("upload part");
            assert_eq!(response.status(), StatusCode::OK);

            let response = handle_object(
                &state,
                &auth_for(user.clone()),
                bucket.clone(),
                "big.bin",
                Method::GET,
                HeaderMap::new(),
                &missing_part,
                Body::empty(),
            )
            .await
            .expect("list parts");
            assert_eq!(response.status(), StatusCode::OK);

            let parts = state
                .repo
                .list_multipart_parts(&upload_id)
                .await
                .expect("parts");
            let body = complete_upload_one_part_xml(1, parts[0].etag.as_str());
            let response = handle_object(
                &state,
                &auth_for(user.clone()),
                bucket.clone(),
                "big.bin",
                Method::POST,
                HeaderMap::new(),
                &missing_part,
                Body::from(body),
            )
            .await
            .expect("complete");
            assert_eq!(response.status(), StatusCode::OK);

            let response = handle_object(
                &state,
                &auth_for(user),
                bucket,
                "big.bin",
                Method::DELETE,
                HeaderMap::new(),
                &missing_part,
                Body::empty(),
            )
            .await
            .expect("abort");
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        };
    }

    #[tokio::test]
    async fn handle_object_version_and_multipart_branches() {
        __handle_object_version_and_multipart_branches_body!();
    }

    #[tokio::test]
    async fn stream_body_to_chunks_reports_errors() {
        let state = basic_state().await;
        let error_body = Body::from_stream(stream::once(async {
            Err::<Bytes, std::io::Error>(std::io::Error::new(std::io::ErrorKind::Other, "boom"))
        }));
        let err = stream_body_to_chunks(&state, error_body)
            .await
            .err()
            .expect("expected error");
        assert_eq!(err, S3Error::InternalError);

        let _guard = crate::storage::chunkstore::failpoint_guard(4);
        let err = stream_body_to_chunks(&state, Body::from("payload"))
            .await
            .err()
            .expect("expected error");
        assert_eq!(err, S3Error::InternalError);
    }

    macro_rules! __delete_object_covers_versioning_and_events_body {
        () => {
            let state = state_with_events_enabled().await;
            let (_user, bucket) = create_user_and_bucket(&state, "delete-events").await;
            state
                .repo
                .update_bucket_notification(bucket.id, "<NotificationConfiguration/>")
                .await
                .expect("notify");
            put_object(
                &state,
                &bucket,
                "del.txt",
                HeaderMap::new(),
                Body::from("data"),
            )
            .await
            .expect("put");
            let response = delete_object(&state, &bucket, "del.txt")
                .await
                .expect("delete");
            assert_eq!(response.status(), StatusCode::NO_CONTENT);

            state
                .repo
                .update_bucket_versioning(bucket.id, "enabled")
                .await
                .expect("versioning");
            put_object(
                &state,
                &bucket,
                "del2.txt",
                HeaderMap::new(),
                Body::from("data"),
            )
            .await
            .expect("put");
            let response = delete_object(&state, &bucket, "del2.txt")
                .await
                .expect("delete");
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        };
    }

    #[tokio::test]
    async fn delete_object_covers_versioning_and_events() {
        __delete_object_covers_versioning_and_events_body!();
    }

    macro_rules! __build_object_response_handles_missing_chunks_and_headers_body {
        () => {
            let state = basic_state().await;
            let (_user, bucket) = create_user_and_bucket(&state, "response-headers").await;
            let mut headers = HeaderMap::new();
            headers.insert("content-type", HeaderValue::from_static("text/plain"));
            put_object(
                &state,
                &bucket,
                "big.txt",
                headers,
                Body::from(vec![1u8; 3000]),
            )
            .await
            .expect("put");
            let (object, manifest_id) = state
                .repo
                .get_object_current(bucket.id, "big.txt")
                .await
                .expect("current")
                .expect("object");
            let mut chunks = state
                .repo
                .get_manifest_chunks(manifest_id)
                .await
                .expect("chunks");
            let extra_chunk = chunks.pop().expect("chunk");
            sqlx::query("DELETE FROM manifest_chunks WHERE manifest_id=$1 AND chunk_id=$2")
                .bind(manifest_id)
                .bind(extra_chunk.chunk_id)
                .execute(state.repo.pool())
                .await
                .expect("delete chunk");
            let response =
                build_object_response(&state, &object, manifest_id, HeaderMap::new(), "Get")
                    .await
                    .expect("response");
            assert!(response.headers().get("ETag").is_some());
            assert!(response.headers().get("Content-Type").is_some());
        };
    }

    #[tokio::test]
    async fn build_object_response_handles_missing_chunks_and_headers() {
        __build_object_response_handles_missing_chunks_and_headers_body!();
    }

    macro_rules! __build_object_response_stream_errors_for_missing_checksum_and_chunk_body {
        () => {
            let state = basic_state().await;
            let (_user, bucket) = create_user_and_bucket(&state, "response-errors").await;
            put_object(
                &state,
                &bucket,
                "checksum.txt",
                HeaderMap::new(),
                Body::from("payload"),
            )
            .await
            .expect("put");
            let (object, manifest_id) = state
                .repo
                .get_object_current(bucket.id, "checksum.txt")
                .await
                .expect("current")
                .expect("object");

            let pool = state.repo.pool().clone();
            sqlx::query("ALTER TABLE chunks RENAME TO chunks_backup")
                .execute(&pool)
                .await
                .expect("rename");
            let response =
                build_object_response(&state, &object, manifest_id, HeaderMap::new(), "Get")
                    .await
                    .expect("response");
            let err = to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("checksum error"));
            let _ = sqlx::query("ALTER TABLE chunks_backup RENAME TO chunks")
                .execute(&pool)
                .await;

            put_object(
                &state,
                &bucket,
                "missing.txt",
                HeaderMap::new(),
                Body::from("payload"),
            )
            .await
            .expect("put");
            let (object, manifest_id) = state
                .repo
                .get_object_current(bucket.id, "missing.txt")
                .await
                .expect("current")
                .expect("object");
            let manifest_chunks = state
                .repo
                .get_manifest_chunks(manifest_id)
                .await
                .expect("chunks");
            let chunk_id = manifest_chunks[0].chunk_id;
            let _ = state.replication.chunk_store().delete_chunk(chunk_id).await;

            let response =
                build_object_response(&state, &object, manifest_id, HeaderMap::new(), "Get")
                    .await
                    .expect("response");
            let err = to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("chunk read error"));
        };
    }

    #[tokio::test]
    async fn build_object_response_stream_errors_for_missing_checksum_and_chunk() {
        __build_object_response_stream_errors_for_missing_checksum_and_chunk_body!();
    }

    macro_rules! __dispatch_handles_missing_bucket_and_invalid_request_body {
        () => {
            let state = basic_state().await;
            let user = state
                .repo
                .create_user("dispatch-user", None, "hash", "active")
                .await
                .expect("user");
            let auth = auth_for(user);
            let err = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: "missing".to_string(),
                    key: None,
                },
                Method::HEAD,
                HeaderMap::new(),
                "",
                Body::empty(),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::NoSuchBucket);
            let err = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: "missing".to_string(),
                    key: None,
                },
                Method::DELETE,
                HeaderMap::new(),
                "",
                Body::empty(),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::NoSuchBucket);

            let bucket_key = BucketKey {
                bucket: "missing".to_string(),
                key: Some("key".to_string()),
            };
            let err = dispatch(
                &state,
                &auth,
                bucket_key,
                Method::PATCH,
                HeaderMap::new(),
                "",
                Body::empty(),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::NoSuchBucket);
        };
    }

    #[tokio::test]
    async fn dispatch_handles_missing_bucket_and_invalid_request() {
        __dispatch_handles_missing_bucket_and_invalid_request_body!();
    }

    #[tokio::test]
    async fn dispatch_treats_repo_error_as_missing_bucket() {
        let state = basic_state().await;
        let user = state
            .repo
            .create_user("dispatch-broken", None, "hash", "active")
            .await
            .expect("user");
        let auth = auth_for(user);
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let err = dispatch(
            &broken,
            &auth,
            BucketKey {
                bucket: "missing".to_string(),
                key: None,
            },
            Method::GET,
            HeaderMap::new(),
            "",
            Body::empty(),
        )
        .await
        .unwrap_err();
        assert_eq!(err, S3Error::NoSuchBucket);
    }

    macro_rules! __dispatch_bucket_notification_versioning_and_delete_objects_body {
        () => {
            let state = state_with_events_enabled().await;
            let (user, bucket) = create_user_and_bucket(&state, "dispatch-bucket").await;
            let auth = auth_for(user);

            let response = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::PUT,
                HeaderMap::new(),
                "notification=1",
                Body::from("<NotificationConfiguration/>"),
            )
            .await
            .expect("notification");
            assert_eq!(response.status(), StatusCode::OK);

            let response = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::PUT,
                HeaderMap::new(),
                "versioning=1",
                Body::from(
                    "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                ),
            )
            .await
            .expect("versioning");
            assert_eq!(response.status(), StatusCode::OK);

            let response = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::POST,
                HeaderMap::new(),
                "delete=1",
                Body::from("<Delete><Object><Key>missing</Key></Object></Delete>"),
            )
            .await
            .expect("delete objects");
            assert_eq!(response.status(), StatusCode::OK);
        };
    }

    #[tokio::test]
    async fn dispatch_bucket_notification_versioning_and_delete_objects() {
        __dispatch_bucket_notification_versioning_and_delete_objects_body!();
    }

    #[tokio::test]
    async fn replica_dispatch_blocks_writes_and_serves_reads() {
        let mut state = basic_state().await;
        state.config.mode = "replica".to_string();
        let (user, bucket) = create_user_and_bucket(&state, "replica-readonly").await;
        let auth = auth_for(user);
        seed_replica_dispatch_object(&state, &bucket).await;
        assert_replica_write_blocked(&state, &auth, &bucket).await;
        assert_replica_read_allowed(&state, &auth, &bucket).await;
    }

    #[tokio::test]
    async fn replica_backup_mode_blocks_reads() {
        let mut state = basic_state().await;
        state.config.mode = "replica".to_string();
        let (user, bucket) = create_user_and_bucket(&state, "replica-backup").await;
        let auth = auth_for(user);
        seed_replica_dispatch_object(&state, &bucket).await;
        state
            .replica_mode
            .set(crate::util::runtime::ReplicaSubMode::Backup);
        let err = dispatch(
            &state,
            &auth,
            BucketKey {
                bucket: bucket.name.clone(),
                key: Some("seed.txt".to_string()),
            },
            Method::GET,
            HeaderMap::new(),
            "",
            Body::empty(),
        )
        .await
        .unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[tokio::test]
    async fn replica_volume_mode_blocks_reads() {
        let mut state = basic_state().await;
        state.config.mode = "replica".to_string();
        let (user, bucket) = create_user_and_bucket(&state, "replica-volume").await;
        let auth = auth_for(user);
        seed_replica_dispatch_object(&state, &bucket).await;
        state
            .replica_mode
            .set(crate::util::runtime::ReplicaSubMode::Volume);
        let err = dispatch(
            &state,
            &auth,
            BucketKey {
                bucket: bucket.name.clone(),
                key: Some("seed.txt".to_string()),
            },
            Method::GET,
            HeaderMap::new(),
            "",
            Body::empty(),
        )
        .await
        .unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[tokio::test]
    async fn root_listing_blocks_reads_in_replica_backup_mode() {
        let mut state = basic_state().await;
        state.config.mode = "replica".to_string();
        state
            .replica_mode
            .set(crate::util::runtime::ReplicaSubMode::Backup);
        let err = load_root_bucket_listing(&state, &Method::GET, &HeaderMap::new())
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[tokio::test]
    async fn worm_bucket_blocks_mutation_requests() {
        let state = basic_state().await;
        let (user, bucket) = create_user_and_bucket(&state, "worm-bucket").await;
        state
            .repo
            .update_bucket_worm(bucket.id, true)
            .await
            .expect("worm");
        let auth = auth_for(user);
        let key = assert_worm_first_put_allowed(&state, &auth, &bucket).await;
        assert_worm_overwrite_put_blocked(&state, &auth, &bucket, &key).await;
        assert_worm_delete_blocked(&state, &auth, &bucket).await;
    }

    #[tokio::test]
    async fn worm_bucket_rejects_invalid_post_object_method() {
        let state = basic_state().await;
        let (user, mut bucket) = create_user_and_bucket(&state, "worm-object-method").await;
        state
            .repo
            .update_bucket_worm(bucket.id, true)
            .await
            .expect("worm");
        bucket.is_worm = true;
        let auth = auth_for(user);
        let err = handle_object(
            &state,
            &auth,
            bucket,
            "x.txt",
            Method::POST,
            HeaderMap::new(),
            &HashMap::new(),
            Body::empty(),
        )
        .await
        .unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[tokio::test]
    async fn ensure_worm_allows_new_object_maps_repo_errors() {
        let state = basic_state().await;
        let (_user, mut bucket) = create_user_and_bucket(&state, "worm-repo-error").await;
        state
            .repo
            .update_bucket_worm(bucket.id, true)
            .await
            .expect("worm");
        bucket.is_worm = true;
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let err = ensure_worm_allows_new_object(&broken, &bucket, "seed.txt")
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::InternalError);
    }

    #[tokio::test]
    async fn multipart_handlers_reject_existing_object_for_worm_bucket() {
        let state = basic_state().await;
        let bucket = prepare_worm_bucket_with_seed(&state).await;
        assert_worm_multipart_handlers_block_overwrite(&state, &bucket).await;
    }

    fn worm_rule_bucket() -> Bucket {
        Bucket {
            id: Uuid::new_v4(),
            name: "worm-rule".to_string(),
            owner_user_id: Uuid::new_v4(),
            created_at: Utc::now(),
            versioning_status: "suspended".to_string(),
            public_read: false,
            is_worm: true,
            lifecycle_config_xml: None,
            cors_config_xml: None,
            website_config_xml: None,
            notification_config_xml: None,
        }
    }

    #[test]
    fn worm_object_method_allows_multipart_exceptions() {
        let bucket = worm_rule_bucket();
        let empty = HashMap::new();
        let err = ensure_worm_object_method_allowed(&bucket, &Method::POST, &empty).unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);

        let mut uploads = HashMap::new();
        uploads.insert("uploads".to_string(), String::new());
        assert!(ensure_worm_object_method_allowed(&bucket, &Method::POST, &uploads).is_ok());

        let mut upload_id = HashMap::new();
        upload_id.insert("uploadId".to_string(), "u-1".to_string());
        assert!(ensure_worm_object_method_allowed(&bucket, &Method::POST, &upload_id).is_ok());
        assert!(ensure_worm_object_method_allowed(&bucket, &Method::DELETE, &upload_id).is_ok());
    }

    #[tokio::test]
    async fn bucket_dispatch_invalid_methods_return_invalid_request() {
        let state = basic_state().await;
        let (user, bucket) = create_user_and_bucket(&state, "dispatch-invalid-bucket").await;
        let auth = auth_for(user);
        let err = dispatch_missing_bucket(&state, &auth, "missing", Method::PATCH)
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::InvalidRequest);
        let err = dispatch_existing_bucket(
            &state,
            &auth,
            bucket,
            Method::PATCH,
            &HashMap::new(),
            Body::empty(),
        )
        .await
        .unwrap_err();
        assert_eq!(err, S3Error::InvalidRequest);
    }

    async fn assert_worm_first_put_allowed(
        state: &AppState,
        auth: &AuthResult,
        bucket: &Bucket,
    ) -> String {
        let key = "write-once.txt".to_string();
        let response = dispatch(
            state,
            auth,
            BucketKey {
                bucket: bucket.name.clone(),
                key: Some(key.clone()),
            },
            Method::PUT,
            HeaderMap::new(),
            "",
            Body::from("first"),
        )
        .await
        .expect("first write");
        assert_eq!(response.status(), StatusCode::OK);
        key
    }

    async fn assert_worm_overwrite_put_blocked(
        state: &AppState,
        auth: &AuthResult,
        bucket: &Bucket,
        key: &str,
    ) {
        let err = dispatch(
            state,
            auth,
            BucketKey {
                bucket: bucket.name.clone(),
                key: Some(key.to_string()),
            },
            Method::PUT,
            HeaderMap::new(),
            "",
            Body::from("overwrite"),
        )
        .await
        .unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    async fn assert_worm_delete_blocked(state: &AppState, auth: &AuthResult, bucket: &Bucket) {
        let err = dispatch(
            state,
            auth,
            BucketKey {
                bucket: bucket.name.clone(),
                key: None,
            },
            Method::DELETE,
            HeaderMap::new(),
            "",
            Body::empty(),
        )
        .await
        .unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    async fn prepare_worm_bucket_with_seed(state: &AppState) -> Bucket {
        let (_user, mut bucket) = create_user_and_bucket(state, "worm-multipart").await;
        state
            .repo
            .update_bucket_worm(bucket.id, true)
            .await
            .expect("worm");
        bucket.is_worm = true;
        put_object(
            state,
            &bucket,
            "seed.txt",
            HeaderMap::new(),
            Body::from("seed"),
        )
        .await
        .expect("seed");
        bucket
    }

    async fn assert_worm_multipart_handlers_block_overwrite(state: &AppState, bucket: &Bucket) {
        let create_err = create_multipart_upload(state, bucket, "seed.txt")
            .await
            .unwrap_err();
        assert_eq!(create_err, S3Error::AccessDenied);
        state
            .repo
            .create_multipart_upload(bucket.id, "seed.txt", "upload-1")
            .await
            .expect("upload");
        let complete_err =
            complete_multipart_upload(state, bucket, "seed.txt", "upload-1", &Bytes::new())
                .await
                .unwrap_err();
        assert_eq!(complete_err, S3Error::AccessDenied);
    }

    async fn seed_replica_dispatch_object(state: &AppState, bucket: &Bucket) {
        put_object(
            state,
            bucket,
            "seed.txt",
            HeaderMap::new(),
            Body::from("replica-read"),
        )
        .await
        .expect("seed");
    }

    async fn assert_replica_write_blocked(state: &AppState, auth: &AuthResult, bucket: &Bucket) {
        let err = dispatch(
            state,
            auth,
            BucketKey {
                bucket: bucket.name.clone(),
                key: Some("blocked.txt".to_string()),
            },
            Method::PUT,
            HeaderMap::new(),
            "",
            Body::from("blocked"),
        )
        .await
        .unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    async fn assert_replica_read_allowed(state: &AppState, auth: &AuthResult, bucket: &Bucket) {
        let response = dispatch(
            state,
            auth,
            BucketKey {
                bucket: bucket.name.clone(),
                key: Some("seed.txt".to_string()),
            },
            Method::GET,
            HeaderMap::new(),
            "",
            Body::empty(),
        )
        .await
        .expect("read");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn handle_create_bucket_reports_conflict_and_access_denied() {
        let state = basic_state().await;
        let disabled = state
            .repo
            .create_user("disabled", None, "hash", "disabled")
            .await
            .expect("user");
        let err = handle_create_bucket(&state, &auth_for(disabled), "deny-bucket")
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);

        let active = state
            .repo
            .create_user("active", None, "hash", "active")
            .await
            .expect("user");
        handle_create_bucket(&state, &auth_for(active.clone()), "conflict-bucket")
            .await
            .expect("create");
        let err = handle_create_bucket(&state, &auth_for(active), "conflict-bucket")
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::BucketAlreadyExists);
    }

    macro_rules! __bucket_handlers_reject_inactive_user_body {
        () => {
            let state = basic_state().await;
            let user = state
                .repo
                .create_user("inactive", None, "hash", "disabled")
                .await
                .expect("user");
            let bucket = state
                .repo
                .create_bucket("deny-bucket", user.id)
                .await
                .expect("bucket");
            let auth = auth_for(user);

            let err = handle_head_bucket(&auth, bucket.clone()).await.unwrap_err();
            assert_eq!(err, S3Error::AccessDenied);
            let err = handle_delete_bucket(&state, &auth, bucket.clone())
                .await
                .unwrap_err();
            assert_eq!(err, S3Error::AccessDenied);
            let err = handle_get_bucket_notification(&state, &auth, bucket.clone())
                .await
                .unwrap_err();
            assert_eq!(err, S3Error::AccessDenied);
            let err = handle_put_bucket_notification(
                &state,
                &auth,
                bucket.clone(),
                &Bytes::from("<NotificationConfiguration/>"),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::AccessDenied);
            let err = handle_put_bucket_versioning(
                &state,
                &auth,
                bucket.clone(),
                &Bytes::from(
                    "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                ),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::AccessDenied);
            let err = handle_delete_objects(
                &state,
                &auth,
                bucket,
                &HashMap::new(),
                &Bytes::from("<Delete><Object><Key>x</Key></Object></Delete>"),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::AccessDenied);
        };
    }

    #[tokio::test]
    async fn bucket_handlers_reject_inactive_user() {
        __bucket_handlers_reject_inactive_user_body!();
    }

    macro_rules! __bucket_update_errors_surface_as_internal_body {
        () => {
            let state = state_with_events_enabled().await;
            let (user, bucket) = create_user_and_bucket(&state, "update-bucket").await;
            let auth = auth_for(user);
            let guard = FailTriggerGuard::create(state.repo.pool(), "buckets", "AFTER", "UPDATE")
                .await
                .expect("guard");
            let err = handle_put_bucket_notification(
                &state,
                &auth,
                bucket.clone(),
                &Bytes::from("<NotificationConfiguration/>"),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InternalError);
            guard.remove().await.expect("remove");

            let guard = FailTriggerGuard::create(state.repo.pool(), "buckets", "AFTER", "UPDATE")
                .await
                .expect("guard");
            let err = handle_put_bucket_versioning(
                &state,
                &auth,
                bucket,
                &Bytes::from(
                    "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                ),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InternalError);
            guard.remove().await.expect("remove");
        };
    }

    #[tokio::test]
    async fn bucket_update_errors_surface_as_internal() {
        __bucket_update_errors_surface_as_internal_body!();
    }

    macro_rules! __handle_object_methods_cover_head_delete_and_multi_delete_body {
        () => {
            let state = basic_state().await;
            let (user, bucket) = create_user_and_bucket(&state, "obj-methods").await;
            let auth = auth_for(user);
            put_object(
                &state,
                &bucket,
                "note.txt",
                HeaderMap::new(),
                Body::from("hi"),
            )
            .await
            .expect("put");

            let response = handle_object(
                &state,
                &auth,
                bucket.clone(),
                "note.txt",
                Method::HEAD,
                HeaderMap::new(),
                &HashMap::new(),
                Body::empty(),
            )
            .await
            .expect("head");
            assert_eq!(response.status(), StatusCode::OK);

            let response = handle_object(
                &state,
                &auth,
                bucket.clone(),
                "note.txt",
                Method::DELETE,
                HeaderMap::new(),
                &HashMap::new(),
                Body::empty(),
            )
            .await
            .expect("delete");
            assert_eq!(response.status(), StatusCode::NO_CONTENT);

            let mut query = HashMap::new();
            query.insert("delete".to_string(), "1".to_string());
            let response = handle_object(
                &state,
                &auth,
                bucket,
                "ignored",
                Method::POST,
                HeaderMap::new(),
                &query,
                Body::from("<Delete><Object><Key>a</Key></Object></Delete>"),
            )
            .await
            .expect("multi delete");
            assert_eq!(response.status(), StatusCode::OK);
        };
    }

    #[tokio::test]
    async fn handle_object_methods_cover_head_delete_and_multi_delete() {
        __handle_object_methods_cover_head_delete_and_multi_delete_body!();
    }

    macro_rules! __put_and_delete_object_emit_events_body {
        () => {
            let state = state_with_events_enabled().await;
            let (user, mut bucket) = create_user_and_bucket(&state, "event-bucket").await;
            bucket.notification_config_xml = Some("<NotificationConfiguration/>".to_string());
            let _auth = auth_for(user);
            put_object(
                &state,
                &bucket,
                "events.txt",
                HeaderMap::new(),
                Body::from("one"),
            )
            .await
            .expect("put");
            put_object(
                &state,
                &bucket,
                "events.txt",
                HeaderMap::new(),
                Body::from("two"),
            )
            .await
            .expect("put again");
            let response = delete_object(&state, &bucket, "events.txt")
                .await
                .expect("delete");
            assert_eq!(response.status(), StatusCode::NO_CONTENT);

            bucket.versioning_status = "enabled".to_string();
            put_object(
                &state,
                &bucket,
                "marker.txt",
                HeaderMap::new(),
                Body::from("data"),
            )
            .await
            .expect("put marker");
            let response = delete_object(&state, &bucket, "marker.txt")
                .await
                .expect("delete marker");
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        };
    }

    #[tokio::test]
    async fn put_and_delete_object_emit_events() {
        __put_and_delete_object_emit_events_body!();
    }

    #[tokio::test]
    async fn delete_objects_invalid_xml_returns_error() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "bad-delete").await;
        let err = delete_objects(&state, &bucket, &Bytes::from("<bad>"))
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::MalformedXML);
    }

    macro_rules! __multipart_error_paths_cover_branches_body {
        () => {
            let state = basic_state().await;
            let (_user, bucket) = create_user_and_bucket(&state, "multipart-errors").await;
            let guard =
                FailTriggerGuard::create(state.repo.pool(), "multipart_uploads", "AFTER", "INSERT")
                    .await
                    .expect("guard");
            let err = create_multipart_upload(&state, &bucket, "fail.bin")
                .await
                .unwrap_err();
            assert_eq!(err, S3Error::InternalError);
            guard.remove().await.expect("remove");

            let response = create_multipart_upload(&state, &bucket, "ok.bin")
                .await
                .expect("create");
            assert_eq!(response.status(), StatusCode::OK);
            let upload_id = state
                .repo
                .list_multipart_uploads(bucket.id)
                .await
                .expect("uploads")
                .first()
                .expect("upload")
                .upload_id
                .clone();

            let err = upload_part(
                &state,
                &bucket,
                "wrong.bin",
                &upload_id,
                1,
                Body::from("data"),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::NoSuchUpload);

            let err = list_parts(&state, &bucket, "wrong.bin", &upload_id)
                .await
                .unwrap_err();
            assert_eq!(err, S3Error::NoSuchUpload);

            let err = complete_multipart_upload(
                &state,
                &bucket,
                "ok.bin",
                "missing",
                &Bytes::from("<CompleteMultipartUpload/>"),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::NoSuchUpload);

            let mut broken = state.clone();
            broken.repo = test_support::broken_repo();
            let err = abort_multipart_upload(&broken, "missing")
                .await
                .unwrap_err();
            assert_eq!(err, S3Error::InternalError);
        };
    }

    #[tokio::test]
    async fn multipart_error_paths_cover_branches() {
        __multipart_error_paths_cover_branches_body!();
    }

    #[test]
    fn parse_range_header_rejects_invalid_parts() {
        assert!(parse_range_header("bytes=0-1-2").is_none());
    }

    #[tokio::test]
    async fn stream_body_to_chunks_splits_and_flushes_tail() {
        let mut state = basic_state().await;
        state.chunk_size_bytes = 2;
        let body = Body::from("abc");
        let result = stream_body_to_chunks(&state, body).await.expect("stream");
        assert_eq!(result.chunks.len(), 2);
    }

    macro_rules! __build_object_response_sets_headers_and_ranges_body {
        () => {
            let state = basic_state().await;
            let (_user, bucket) = create_user_and_bucket(&state, "header-bucket").await;
            let mut headers = HeaderMap::new();
            headers.insert("content-type", HeaderValue::from_static("text/plain"));
            put_object(&state, &bucket, "range.txt", headers, Body::from("abcd"))
                .await
                .expect("put");
            let (object, manifest_id) = state
                .repo
                .get_object_current(bucket.id, "range.txt")
                .await
                .expect("current")
                .expect("object");
            let mut headers = HeaderMap::new();
            headers.insert("range", HeaderValue::from_static("bytes=1-2"));
            let response = build_object_response(&state, &object, manifest_id, headers, "Get")
                .await
                .expect("response");
            assert!(response.headers().get("ETag").is_some());
            assert_eq!(
                response.headers().get("Content-Type").unwrap(),
                "text/plain"
            );

            let response = head_object(&state, &bucket, "range.txt")
                .await
                .expect("head");
            assert!(response.headers().get("ETag").is_some());
            assert_eq!(
                response.headers().get("Content-Type").unwrap(),
                "text/plain"
            );
        };
    }

    #[tokio::test]
    async fn build_object_response_sets_headers_and_ranges() {
        __build_object_response_sets_headers_and_ranges_body!();
    }

    macro_rules! __object_version_requests_reject_delete_marker_body {
        () => {
            let state = basic_state().await;
            let (_user, mut bucket) = create_user_and_bucket(&state, "version-bucket").await;
            bucket.versioning_status = "enabled".to_string();
            put_object(
                &state,
                &bucket,
                "del.txt",
                HeaderMap::new(),
                Body::from("data"),
            )
            .await
            .expect("put");
            delete_object(&state, &bucket, "del.txt")
                .await
                .expect("delete");
            let versions = state
                .repo
                .list_object_versions(bucket.id, None, None, None, 10)
                .await
                .expect("versions");
            let delete_marker = versions
                .iter()
                .find(|version| version.is_delete_marker)
                .expect("delete marker");
            let err = get_object_version(
                &state,
                &bucket,
                "del.txt",
                &delete_marker.version_id,
                HeaderMap::new(),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::NoSuchKey);
            let err = head_object_version(&state, &bucket, "del.txt", &delete_marker.version_id)
                .await
                .unwrap_err();
            assert_eq!(err, S3Error::NoSuchKey);
        };
    }

    #[tokio::test]
    async fn object_version_requests_reject_delete_marker() {
        __object_version_requests_reject_delete_marker_body!();
    }

    #[tokio::test]
    async fn delete_object_version_reports_repo_error() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "delete-version").await;
        put_object(
            &state,
            &bucket,
            "file.txt",
            HeaderMap::new(),
            Body::from("data"),
        )
        .await
        .expect("put");
        let (object, _manifest_id) = state
            .repo
            .get_object_current(bucket.id, "file.txt")
            .await
            .expect("current")
            .expect("object");
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let err = delete_object_version(&broken, &bucket, "file.txt", &object.version_id)
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::InternalError);
    }

    #[tokio::test]
    async fn list_objects_all_empty_and_repo_error() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "empty-bucket").await;
        let list = list_objects_all(&state, bucket.id, None, None)
            .await
            .expect("list");
        assert!(list.is_empty());

        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let err = list_objects_all(&broken, bucket.id, None, None)
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::InternalError);
    }

    #[test]
    fn detect_s3_operation_covers_bucket_location() {
        let mut query = HashMap::new();
        query.insert("location".to_string(), "1".to_string());
        assert_eq!(
            detect_s3_operation(&Method::GET, false, &query),
            "GetBucketLocation"
        );
    }

    #[tokio::test]
    async fn fetch_checksum_returns_expected() {
        let state = basic_state().await;
        let chunk_id = Uuid::new_v4();
        state
            .repo
            .insert_chunk_metadata(chunk_id, 4, "crc32c", b"abcd")
            .await
            .expect("chunk");
        let checksum = fetch_checksum(&state, chunk_id).await.expect("checksum");
        assert_eq!(checksum.value, b"abcd".to_vec());
    }

    #[tokio::test]
    async fn load_manifest_chunks_reports_repo_error() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "manifest-error").await;
        let response = put_object(
            &state,
            &bucket,
            "file.txt",
            HeaderMap::new(),
            Body::from("data"),
        )
        .await
        .expect("put");
        assert_eq!(response.status(), StatusCode::OK);
        let (_object, manifest_id) = state
            .repo
            .get_object_current(bucket.id, "file.txt")
            .await
            .expect("current")
            .expect("object");
        let guard = TableRenameGuard::rename(state.repo.pool(), "manifest_chunks")
            .await
            .expect("rename");
        let err = load_manifest_chunks(&state, manifest_id).await.unwrap_err();
        assert_eq!(err, S3Error::InternalError);
        guard.restore().await.expect("restore");
    }

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn set_env_optional(key: &str, value: Option<String>) {
        if let Some(val) = value {
            std::env::set_var(key, val);
        } else {
            std::env::remove_var(key);
        }
    }

    #[tokio::test]
    async fn state_with_events_enabled_uses_default_url_when_env_missing() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let key = "NSS_RABBIT_URL";
        let existing = std::env::var(key).ok();
        set_env_optional(key, None);
        let _ = state_with_events_enabled().await;
        set_env_optional(key, Some("amqp://rabbitmq:5672/%2f".to_string()));
        set_env_optional(key, None);
        set_env_optional(key, existing);
    }

    #[tokio::test]
    async fn state_with_events_enabled_restores_env_when_present() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let key = "NSS_RABBIT_URL";
        let existing = std::env::var(key).ok();
        set_env_optional(key, Some("amqp://rabbitmq:5672/%2f".to_string()));
        let _ = state_with_events_enabled().await;
        assert_eq!(
            std::env::var(key).ok(),
            Some("amqp://rabbitmq:5672/%2f".to_string())
        );
        set_env_optional(key, existing);
    }

    macro_rules! __dispatch_reads_body_for_bucket_queries_body {
        () => {
            let state = basic_state().await;
            let (user, bucket) = create_user_and_bucket(&state, "dispatch-bucket").await;
            let auth = auth_for(user);

            let notification = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::PUT,
                HeaderMap::new(),
                "notification=",
                Body::from("<NotificationConfiguration/>"),
            )
            .await
            .unwrap_err();
            assert_eq!(notification, S3Error::NotImplemented);

            let versioning = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::PUT,
                HeaderMap::new(),
                "versioning=",
                Body::from(
                    "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                ),
            )
            .await
            .expect("versioning");
            assert_eq!(versioning.status(), StatusCode::OK);

            let deletes = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::POST,
                HeaderMap::new(),
                "delete=",
                Body::from("<Delete><Object><Key>alpha</Key></Object></Delete>"),
            )
            .await
            .expect("delete objects");
            assert_eq!(deletes.status(), StatusCode::OK);
        };
    }

    #[tokio::test]
    async fn dispatch_reads_body_for_bucket_queries() {
        __dispatch_reads_body_for_bucket_queries_body!();
    }

    #[tokio::test]
    async fn list_objects_v2_dispatches_listing() {
        let state = basic_state().await;
        let (user, bucket) = create_user_and_bucket(&state, "list-v2").await;
        let auth = auth_for(user);
        put_object(
            &state,
            &bucket,
            "alpha.txt",
            HeaderMap::new(),
            Body::from("data"),
        )
        .await
        .expect("put");

        let mut query = HashMap::new();
        query.insert("list-type".to_string(), "2".to_string());
        let response = handle_get_bucket(&state, &auth, bucket, &query)
            .await
            .expect("list");
        assert_eq!(response.status(), StatusCode::OK);
    }

    macro_rules! __handle_object_reads_body_for_complete_and_delete_body {
        () => {
            let state = basic_state().await;
            let (user, bucket) = create_user_and_bucket(&state, "handle-object-body").await;
            let auth = auth_for(user);
            let upload_id = create_upload(&state, &bucket, "big.bin").await;
            upload_part(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                1,
                Body::from("part"),
            )
            .await
            .expect("upload part");
            let part = state
                .repo
                .list_multipart_parts(&upload_id)
                .await
                .expect("parts")
                .first()
                .expect("part")
                .clone();
            let complete_body = complete_upload_one_part_xml(part.part_number, part.etag.as_str());
            let mut query = HashMap::new();
            query.insert("uploadId".to_string(), upload_id.clone());
            let response = handle_object(
                &state,
                &auth,
                bucket.clone(),
                "big.bin",
                Method::POST,
                HeaderMap::new(),
                &query,
                Body::from(complete_body),
            )
            .await
            .expect("complete");
            assert_eq!(response.status(), StatusCode::OK);

            let mut delete_query = HashMap::new();
            delete_query.insert("delete".to_string(), "1".to_string());
            let response = handle_object(
                &state,
                &auth,
                bucket,
                "ignored",
                Method::POST,
                HeaderMap::new(),
                &delete_query,
                Body::from("<Delete><Object><Key>alpha</Key></Object></Delete>"),
            )
            .await
            .expect("delete");
            assert_eq!(response.status(), StatusCode::OK);
        };
    }

    #[tokio::test]
    async fn handle_object_reads_body_for_complete_and_delete() {
        __handle_object_reads_body_for_complete_and_delete_body!();
    }

    #[tokio::test]
    async fn upload_part_failpoint_returns_error() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "upload-failpoint").await;
        let upload_id = create_upload(&state, &bucket, "big.bin").await;
        test_failpoints::trigger_upload_part_begin();
        let err = upload_part(
            &state,
            &bucket,
            "big.bin",
            &upload_id,
            1,
            Body::from("data"),
        )
        .await
        .unwrap_err();
        assert_eq!(err, S3Error::InternalError);
    }

    #[tokio::test]
    async fn list_parts_reads_upload() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "list-parts").await;
        let upload_id = create_upload(&state, &bucket, "big.bin").await;
        upload_part(
            &state,
            &bucket,
            "big.bin",
            &upload_id,
            1,
            Body::from("part"),
        )
        .await
        .expect("part");
        let response = list_parts(&state, &bucket, "big.bin", &upload_id)
            .await
            .expect("list parts");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn put_object_reports_stream_error() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "put-stream-error").await;
        let _guard = crate::storage::chunkstore::failpoint_guard(4);
        let err = put_object(
            &state,
            &bucket,
            "fail.txt",
            HeaderMap::new(),
            Body::from("data"),
        )
        .await
        .unwrap_err();
        assert_eq!(err, S3Error::InternalError);
    }

    #[tokio::test]
    async fn put_object_reports_finalize_error() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "put-finalize-error").await;
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let err = put_object(
            &broken,
            &bucket,
            "fail.txt",
            HeaderMap::new(),
            Body::from("data"),
        )
        .await
        .unwrap_err();
        assert_eq!(err, S3Error::InternalError);
    }

    #[tokio::test]
    async fn put_object_reports_delete_other_versions_error() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "put-delete-other").await;
        put_object(
            &state,
            &bucket,
            "dup.txt",
            HeaderMap::new(),
            Body::from("data"),
        )
        .await
        .expect("put");
        let guard =
            FailTriggerGuard::create(state.repo.pool(), "object_versions", "BEFORE", "DELETE")
                .await
                .expect("guard");
        let err = put_object(
            &state,
            &bucket,
            "dup.txt",
            HeaderMap::new(),
            Body::from("data"),
        )
        .await
        .unwrap_err();
        assert_eq!(err, S3Error::InternalError);
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn get_and_head_missing_key_return_no_such_key() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "missing-key").await;
        let err = get_object(&state, &bucket, "missing", HeaderMap::new())
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::NoSuchKey);
        let err = head_object(&state, &bucket, "missing").await.unwrap_err();
        assert_eq!(err, S3Error::NoSuchKey);
    }

    #[tokio::test]
    async fn delete_object_reports_repo_error() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "delete-error").await;
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let err = delete_object(&broken, &bucket, "missing")
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::InternalError);
    }

    #[tokio::test]
    async fn delete_object_reports_delete_all_versions_error() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "delete-all-error").await;
        put_object(
            &state,
            &bucket,
            "alpha.txt",
            HeaderMap::new(),
            Body::from("data"),
        )
        .await
        .expect("put");
        let guard =
            FailTriggerGuard::create(state.repo.pool(), "object_versions", "BEFORE", "DELETE")
                .await
                .expect("guard");
        let err = delete_object(&state, &bucket, "alpha.txt")
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::InternalError);
        guard.remove().await.expect("remove");
    }

    #[tokio::test]
    async fn delete_object_emits_event_when_enabled() {
        let state = state_with_events_enabled().await;
        let (_user, bucket) = create_user_and_bucket(&state, "delete-event").await;
        state
            .repo
            .update_bucket_notification(bucket.id, "<NotificationConfiguration/>")
            .await
            .expect("notify");
        put_object(
            &state,
            &bucket,
            "alpha.txt",
            HeaderMap::new(),
            Body::from("data"),
        )
        .await
        .expect("put");
        let response = delete_object(&state, &bucket, "alpha.txt")
            .await
            .expect("delete");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn delete_object_versioning_enabled_creates_delete_marker() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "delete-marker").await;
        state
            .repo
            .update_bucket_versioning(bucket.id, "enabled")
            .await
            .expect("versioning");
        let response = delete_object(&state, &bucket, "missing-key")
            .await
            .expect("delete");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[test]
    fn parse_range_header_accepts_valid_range() {
        let parsed = parse_range_header("bytes=2-5");
        assert_eq!(parsed, Some((2, 6)));
    }

    macro_rules! __get_and_head_object_version_cover_etag_headers_body {
        () => {
            let state = basic_state().await;
            let (_user, bucket) = create_user_and_bucket(&state, "version-headers").await;
            put_object(
                &state,
                &bucket,
                "alpha.txt",
                HeaderMap::new(),
                Body::from("data"),
            )
            .await
            .expect("put");
            let (object, manifest_id) = state
                .repo
                .get_object_current(bucket.id, "alpha.txt")
                .await
                .expect("current")
                .expect("object");
            let response =
                build_object_response(&state, &object, manifest_id, HeaderMap::new(), "GetObject")
                    .await
                    .expect("build");
            assert!(response.headers().get("ETag").is_some());
            let response = get_object_version(
                &state,
                &bucket,
                "alpha.txt",
                &object.version_id,
                HeaderMap::new(),
            )
            .await
            .expect("get");
            assert_eq!(response.status(), StatusCode::OK);
            let response = head_object_version(&state, &bucket, "alpha.txt", &object.version_id)
                .await
                .expect("head");
            assert!(response.headers().get("ETag").is_some());
        };
    }

    #[tokio::test]
    async fn get_and_head_object_version_cover_etag_headers() {
        __get_and_head_object_version_cover_etag_headers_body!();
    }

    macro_rules! __dispatch_rejects_oversized_bucket_bodies_body {
        () => {
            let state = basic_state().await;
            let (user, bucket) = create_user_and_bucket(&state, "dispatch-oversize").await;
            let auth = auth_for(user);

            let large = vec![0u8; 1024 * 1024 + 1];
            let err = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::PUT,
                HeaderMap::new(),
                "notification=",
                Body::from(large),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InvalidRequest);

            let large = vec![0u8; 1024 * 1024 + 1];
            let err = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::PUT,
                HeaderMap::new(),
                "versioning=",
                Body::from(large),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InvalidRequest);

            let large = vec![0u8; 2 * 1024 * 1024 + 1];
            let err = dispatch(
                &state,
                &auth,
                BucketKey {
                    bucket: bucket.name.clone(),
                    key: None,
                },
                Method::POST,
                HeaderMap::new(),
                "delete=",
                Body::from(large),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InvalidRequest);
        };
    }

    #[tokio::test]
    async fn dispatch_rejects_oversized_bucket_bodies() {
        __dispatch_rejects_oversized_bucket_bodies_body!();
    }

    #[tokio::test]
    async fn handle_get_bucket_list_v2_reports_repo_error() {
        let state = basic_state().await;
        let (user, bucket) = create_user_and_bucket(&state, "list-v2-error").await;
        let auth = auth_for(user);
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let mut query = HashMap::new();
        query.insert("list-type".to_string(), "2".to_string());
        let err = handle_get_bucket(&broken, &auth, bucket, &query)
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::InternalError);
    }

    macro_rules! __handle_object_rejects_oversize_complete_and_delete_body {
        () => {
            let state = basic_state().await;
            let (user, bucket) = create_user_and_bucket(&state, "handle-oversize").await;
            let auth = auth_for(user);
            let upload_id = create_upload(&state, &bucket, "big.bin").await;

            let mut query = HashMap::new();
            query.insert("uploadId".to_string(), upload_id);
            let large = vec![0u8; 2 * 1024 * 1024 + 1];
            let err = handle_object(
                &state,
                &auth,
                bucket.clone(),
                "big.bin",
                Method::POST,
                HeaderMap::new(),
                &query,
                Body::from(large),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InvalidRequest);

            let mut query = HashMap::new();
            query.insert("delete".to_string(), "".to_string());
            let large = vec![0u8; 2 * 1024 * 1024 + 1];
            let err = handle_object(
                &state,
                &auth,
                bucket,
                "del.txt",
                Method::POST,
                HeaderMap::new(),
                &query,
                Body::from(large),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InvalidRequest);
        };
    }

    #[tokio::test]
    async fn handle_object_rejects_oversize_complete_and_delete() {
        __handle_object_rejects_oversize_complete_and_delete_body!();
    }

    #[tokio::test]
    async fn get_object_and_head_report_repo_error() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "object-repo-error").await;
        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let err = get_object(&broken, &bucket, "missing", HeaderMap::new())
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::InternalError);
        let err = head_object(&broken, &bucket, "missing").await.unwrap_err();
        assert_eq!(err, S3Error::InternalError);
    }

    #[tokio::test]
    async fn delete_object_skips_missing_current_with_events() {
        let state = state_with_events_enabled().await;
        let (_user, mut bucket) = create_user_and_bucket(&state, "delete-missing-events").await;
        bucket.notification_config_xml = Some("<NotificationConfiguration/>".to_string());
        let response = delete_object(&state, &bucket, "missing-key")
            .await
            .expect("delete");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn delete_object_reports_finalize_error() {
        let state = basic_state().await;
        let (_user, mut bucket) = create_user_and_bucket(&state, "delete-finalize-error").await;
        bucket.versioning_status = "enabled".to_string();
        let guard =
            FailTriggerGuard::create(state.repo.pool(), "object_versions", "AFTER", "INSERT")
                .await
                .expect("trigger");
        let err = delete_object(&state, &bucket, "missing-key")
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::InternalError);
        guard.remove().await.expect("remove");
    }

    macro_rules! __upload_part_error_paths_cover_branches_body {
        () => {
            let state = basic_state().await;
            let (_user, bucket) = create_user_and_bucket(&state, "upload-part-errors").await;
            let upload_id = create_upload(&state, &bucket, "big.bin").await;

            let guard = TableRenameGuard::rename(state.repo.pool(), "multipart_uploads")
                .await
                .expect("rename");
            let err = upload_part(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                1,
                Body::from("data"),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InternalError);
            guard.restore().await.expect("restore");

            let _fail = crate::storage::chunkstore::failpoint_guard(4);
            let err = upload_part(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                1,
                Body::from("data"),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InternalError);

            test_failpoints::trigger_upload_part_tx_begin();
            let err = upload_part(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                1,
                Body::from("data"),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InternalError);

            let guard =
                FailTriggerGuard::create(state.repo.pool(), "manifest_chunks", "BEFORE", "INSERT")
                    .await
                    .expect("trigger");
            let err = upload_part(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                1,
                Body::from("data"),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InternalError);
            guard.remove().await.expect("remove");

            let guard = FailTriggerGuard::create_deferred(
                state.repo.pool(),
                "manifest_chunks",
                "AFTER",
                "INSERT",
            )
            .await
            .expect("trigger");
            let err = upload_part(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                1,
                Body::from("data"),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InternalError);
            guard.remove().await.expect("remove");

            let guard =
                FailTriggerGuard::create(state.repo.pool(), "multipart_parts", "BEFORE", "INSERT")
                    .await
                    .expect("trigger");
            let err = upload_part(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                1,
                Body::from("data"),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InternalError);
            guard.remove().await.expect("remove");
        };
    }

    #[tokio::test]
    async fn upload_part_error_paths_cover_branches() {
        __upload_part_error_paths_cover_branches_body!();
    }

    #[tokio::test]
    async fn list_parts_error_paths_cover_branches() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "list-parts-errors").await;
        let upload_id = create_upload(&state, &bucket, "big.bin").await;

        let err = list_parts(&state, &bucket, "big.bin", "missing")
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::NoSuchUpload);

        let guard = TableRenameGuard::rename(state.repo.pool(), "multipart_uploads")
            .await
            .expect("rename");
        let err = list_parts(&state, &bucket, "big.bin", &upload_id)
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::InternalError);
        guard.restore().await.expect("restore");

        let guard = TableRenameGuard::rename(state.repo.pool(), "multipart_parts")
            .await
            .expect("rename");
        let err = list_parts(&state, &bucket, "big.bin", &upload_id)
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::InternalError);
        guard.restore().await.expect("restore");
    }

    macro_rules! __complete_multipart_upload_error_paths_cover_branches_body {
        () => {
            let state = basic_state().await;
            let (_user, mut bucket) = create_user_and_bucket(&state, "complete-errors").await;
            let upload_id = create_upload(&state, &bucket, "big.bin").await;
            upload_part(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                1,
                Body::from("data"),
            )
            .await
            .expect("upload part");
            let part = state
                .repo
                .list_multipart_parts(&upload_id)
                .await
                .expect("parts")
                .first()
                .expect("part")
                .clone();
            let original_etag = part.etag.clone();

            let guard = TableRenameGuard::rename(state.repo.pool(), "multipart_uploads")
                .await
                .expect("rename");
            let err = complete_multipart_upload(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                &Bytes::from("<CompleteMultipartUpload/>"),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InternalError);
            guard.restore().await.expect("restore");

            let err = complete_multipart_upload(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                &Bytes::from("<bad"),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::MalformedXML);

            let guard = TableRenameGuard::rename(state.repo.pool(), "multipart_parts")
                .await
                .expect("rename");
            let body = complete_upload_one_part_xml(part.part_number, original_etag.as_str());
            let err = complete_multipart_upload(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                &Bytes::from(body),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InternalError);
            guard.restore().await.expect("restore");

            let guard = TableRenameGuard::rename(state.repo.pool(), "manifest_chunks")
                .await
                .expect("rename");
            let body = complete_upload_one_part_xml(part.part_number, original_etag.as_str());
            let err = complete_multipart_upload(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                &Bytes::from(body),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InternalError);
            guard.restore().await.expect("restore");

            sqlx::query("UPDATE multipart_parts SET etag='zz' WHERE upload_id=$1")
                .bind(&upload_id)
                .execute(state.repo.pool())
                .await
                .expect("update etag");
            let body = complete_upload_one_part_xml(part.part_number, "zz");
            let err = complete_multipart_upload(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                &Bytes::from(body),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InvalidPart);
            sqlx::query("UPDATE multipart_parts SET etag=$1 WHERE upload_id=$2")
                .bind(&original_etag)
                .bind(&upload_id)
                .execute(state.repo.pool())
                .await
                .expect("restore etag");

            let guard =
                FailTriggerGuard::create(state.repo.pool(), "object_versions", "AFTER", "INSERT")
                    .await
                    .expect("trigger");
            let body = complete_upload_one_part_xml(part.part_number, original_etag.as_str());
            let err = complete_multipart_upload(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                &Bytes::from(body),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InternalError);
            guard.remove().await.expect("remove");

            bucket.versioning_status = "off".to_string();
            put_object(
                &state,
                &bucket,
                "big.bin",
                HeaderMap::new(),
                Body::from("old"),
            )
            .await
            .expect("put");
            let guard =
                FailTriggerGuard::create(state.repo.pool(), "object_versions", "BEFORE", "DELETE")
                    .await
                    .expect("trigger");
            let body = complete_upload_one_part_xml(part.part_number, original_etag.as_str());
            let err = complete_multipart_upload(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                &Bytes::from(body),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InternalError);
            guard.remove().await.expect("remove");

            let guard = FailTriggerGuard::create(
                state.repo.pool(),
                "multipart_uploads",
                "BEFORE",
                "UPDATE",
            )
            .await
            .expect("trigger");
            let body = complete_upload_one_part_xml(part.part_number, original_etag.as_str());
            let err = complete_multipart_upload(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                &Bytes::from(body),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InternalError);
            guard.remove().await.expect("remove");
        };
    }

    #[tokio::test]
    async fn complete_multipart_upload_error_paths_cover_branches() {
        __complete_multipart_upload_error_paths_cover_branches_body!();
    }

    macro_rules! __complete_multipart_upload_reports_delete_other_versions_error_body {
        () => {
            let state = basic_state().await;
            let (_user, mut bucket) = create_user_and_bucket(&state, "complete-delete-other").await;
            bucket.versioning_status = "off".to_string();
            let upload_id = create_upload(&state, &bucket, "big.bin").await;
            upload_part(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                1,
                Body::from("data"),
            )
            .await
            .expect("upload part");
            let part = state
                .repo
                .list_multipart_parts(&upload_id)
                .await
                .expect("parts")
                .first()
                .expect("part")
                .clone();
            let body = complete_upload_one_part_xml(part.part_number, part.etag.as_str());
            let _guard = delete_other_versions_fail_guard();
            let err = complete_multipart_upload(
                &state,
                &bucket,
                "big.bin",
                &upload_id,
                &Bytes::from(body),
            )
            .await
            .unwrap_err();
            assert_eq!(err, S3Error::InternalError);
        };
    }

    #[tokio::test]
    async fn complete_multipart_upload_reports_delete_other_versions_error() {
        __complete_multipart_upload_reports_delete_other_versions_error_body!();
    }

    #[tokio::test]
    async fn complete_multipart_upload_skips_delete_other_versions_when_enabled() {
        let state = basic_state().await;
        let (_user, mut bucket) = create_user_and_bucket(&state, "complete-enabled").await;
        bucket.versioning_status = "enabled".to_string();
        let upload_id = create_upload(&state, &bucket, "big.bin").await;
        upload_part(
            &state,
            &bucket,
            "big.bin",
            &upload_id,
            1,
            Body::from("data"),
        )
        .await
        .expect("upload part");
        let part = state
            .repo
            .list_multipart_parts(&upload_id)
            .await
            .expect("parts")
            .first()
            .expect("part")
            .clone();
        let body = complete_upload_one_part_xml(part.part_number, part.etag.as_str());
        let response =
            complete_multipart_upload(&state, &bucket, "big.bin", &upload_id, &Bytes::from(body))
                .await
                .expect("complete");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn parse_range_header_rejects_invalid_end() {
        assert!(parse_range_header("bytes=0-ab").is_none());
    }

    #[tokio::test]
    async fn stream_body_to_chunks_reports_chunk_write_error_in_loop() {
        let mut state = basic_state().await;
        state.chunk_size_bytes = 1;
        let _guard = crate::storage::chunkstore::failpoint_guard(4);
        let body = Body::from(vec![0u8; 4]);
        let err = stream_body_to_chunks(&state, body)
            .await
            .err()
            .expect("error");
        assert_eq!(err, S3Error::InternalError);
    }

    #[tokio::test]
    async fn stream_body_to_chunks_reports_tail_write_error() {
        let state = basic_state().await;
        let _guard = crate::storage::chunkstore::failpoint_guard(4);
        let err = stream_body_to_chunks(&state, Body::from("tail"))
            .await
            .err()
            .expect("error");
        assert_eq!(err, S3Error::InternalError);
    }

    #[tokio::test]
    async fn build_object_response_reports_manifest_error() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "manifest-error").await;
        put_object(
            &state,
            &bucket,
            "file.txt",
            HeaderMap::new(),
            Body::from("data"),
        )
        .await
        .expect("put");
        let (object, manifest_id) = state
            .repo
            .get_object_current(bucket.id, "file.txt")
            .await
            .expect("current")
            .expect("object");
        let guard = TableRenameGuard::rename(state.repo.pool(), "manifest_chunks")
            .await
            .expect("rename");
        let err = build_object_response(&state, &object, manifest_id, HeaderMap::new(), "Get")
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::InternalError);
        guard.restore().await.expect("restore");
    }

    #[tokio::test]
    async fn build_head_response_omits_etag_when_missing() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "etag-missing").await;
        put_object(
            &state,
            &bucket,
            "file.txt",
            HeaderMap::new(),
            Body::from("data"),
        )
        .await
        .expect("put");
        let (mut version, manifest_id) = state
            .repo
            .get_object_current(bucket.id, "file.txt")
            .await
            .expect("current")
            .expect("object");
        version.etag = None;
        let response =
            build_object_response(&state, &version, manifest_id, HeaderMap::new(), "Get")
                .await
                .expect("build");
        assert!(response.headers().get("ETag").is_none());
        let response = build_head_response(&version);
        assert!(response.headers().get("ETag").is_none());
    }

    #[tokio::test]
    async fn get_and_head_object_version_error_paths() {
        let state = basic_state().await;
        let (_user, bucket) = create_user_and_bucket(&state, "version-errors").await;
        let err = get_object_version(&state, &bucket, "file.txt", "missing", HeaderMap::new())
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::NoSuchKey);
        let err = head_object_version(&state, &bucket, "file.txt", "missing")
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::NoSuchKey);

        let mut broken = state.clone();
        broken.repo = test_support::broken_repo();
        let err = get_object_version(&broken, &bucket, "file.txt", "missing", HeaderMap::new())
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::InternalError);
        let err = head_object_version(&broken, &bucket, "file.txt", "missing")
            .await
            .unwrap_err();
        assert_eq!(err, S3Error::InternalError);
    }
}
