use crate::util::config::OidcConfig;
#[cfg(test)]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(test)]
use base64::Engine;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
pub struct OidcIdentity {
    pub subject: String,
    pub username: String,
    pub display_name: Option<String>,
    pub is_admin: bool,
}

#[derive(Debug, Deserialize)]
struct DiscoveryResponse {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: String,
}

pub fn generate_state_nonce() -> (String, String) {
    (Uuid::new_v4().to_string(), Uuid::new_v4().to_string())
}

pub async fn authorization_url(
    oidc: &OidcConfig,
    state: &str,
    nonce: &str,
) -> Result<String, String> {
    let client = build_client()?;
    let metadata = fetch_discovery(&client, oidc).await?;
    let mut url = Url::parse(&metadata.authorization_endpoint)
        .map_err(|_| "invalid authorization endpoint")?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", &oidc.client_id);
        query.append_pair("redirect_uri", &oidc.redirect_url);
        query.append_pair("scope", &oidc.scopes);
        query.append_pair("state", state);
        query.append_pair("nonce", nonce);
    }
    Ok(url.to_string())
}

pub async fn exchange_code_for_identity(
    oidc: &OidcConfig,
    code: &str,
    nonce: &str,
) -> Result<OidcIdentity, String> {
    #[cfg(test)]
    if let Some(identity) = load_test_identity_override()? {
        return Ok(identity);
    }
    let client = build_client()?;
    let metadata = fetch_discovery(&client, oidc).await?;
    let id_token = exchange_code_for_id_token(&client, &metadata, oidc, code).await?;
    verify_id_token(&client, &metadata, oidc, &id_token, nonce).await
}

#[cfg(test)]
fn load_test_identity_override() -> Result<Option<OidcIdentity>, String> {
    match std::env::var("NSS_TEST_OIDC_IDENTITY_JSON") {
        Ok(raw) => serde_json::from_str::<OidcIdentity>(&raw)
            .map(Some)
            .map_err(|_| "oidc test identity json invalid".to_string()),
        Err(_) => Ok(None),
    }
}

fn build_client() -> Result<reqwest::Client, String> {
    let builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10));
    #[cfg(test)]
    let builder = if should_force_client_error() {
        reqwest::Client::builder().user_agent("\n")
    } else {
        builder
    };
    match builder.build() {
        Ok(client) => Ok(client),
        Err(_) => Err("oidc client init failed".to_string()),
    }
}

#[cfg(test)]
fn should_force_client_error() -> bool {
    matches!(
        std::env::var("NSS_TEST_FORCE_OIDC_CLIENT_ERROR"),
        Ok(value) if value.trim().eq_ignore_ascii_case("1") || value.trim().eq_ignore_ascii_case("true")
    )
}

async fn fetch_discovery(
    client: &reqwest::Client,
    oidc: &OidcConfig,
) -> Result<DiscoveryResponse, String> {
    let url = discovery_url(&oidc.issuer_url);
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|_| "oidc discovery request failed".to_string())?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        return Err(format!("oidc discovery failed: {status}"));
    }
    match response.json::<DiscoveryResponse>().await {
        Ok(metadata) => Ok(metadata),
        Err(_) => Err("oidc discovery payload invalid".to_string()),
    }
}

fn discovery_url(issuer_url: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/')
    )
}

async fn exchange_code_for_id_token(
    client: &reqwest::Client,
    metadata: &DiscoveryResponse,
    oidc: &OidcConfig,
    code: &str,
) -> Result<String, String> {
    let response = request_token_exchange(client, metadata, oidc, code).await?;
    read_id_token_from_response(response).await
}

async fn verify_id_token(
    client: &reqwest::Client,
    metadata: &DiscoveryResponse,
    oidc: &OidcConfig,
    id_token: &str,
    nonce: &str,
) -> Result<OidcIdentity, String> {
    let header = parse_token_header(id_token)?;
    ensure_supported_signing_alg(header.alg)?;
    let claims = decode_id_token_claims(client, metadata, oidc, id_token, &header).await?;
    extract_identity(&claims, oidc, nonce)
}

fn token_exchange_form(oidc: &OidcConfig, code: &str) -> Vec<(&'static str, String)> {
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", oidc.redirect_url.clone()),
        ("client_id", oidc.client_id.clone()),
    ];
    if let Some(secret) = &oidc.client_secret {
        form.push(("client_secret", secret.clone()));
    }
    form
}

async fn request_token_exchange(
    client: &reqwest::Client,
    metadata: &DiscoveryResponse,
    oidc: &OidcConfig,
    code: &str,
) -> Result<reqwest::Response, String> {
    let form = token_exchange_form(oidc, code);
    let response = client
        .post(&metadata.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|_| "oidc token request failed".to_string())?;
    if response.status().is_success() {
        return Ok(response);
    }
    Err(format!(
        "oidc token exchange failed: {}",
        response.status().as_u16()
    ))
}

async fn read_id_token_from_response(response: reqwest::Response) -> Result<String, String> {
    let payload = response
        .json::<TokenResponse>()
        .await
        .map_err(|_| "oidc token payload invalid".to_string())?;
    if payload.id_token.trim().is_empty() {
        return Err("oidc token payload missing id_token".into());
    }
    Ok(payload.id_token)
}

fn parse_token_header(id_token: &str) -> Result<jsonwebtoken::Header, String> {
    decode_header(id_token).map_err(|_| "oidc token header invalid".to_string())
}

fn ensure_supported_signing_alg(alg: Algorithm) -> Result<(), String> {
    if is_supported_alg(alg) {
        return Ok(());
    }
    Err("unsupported oidc signing algorithm".into())
}

async fn decode_id_token_claims(
    client: &reqwest::Client,
    metadata: &DiscoveryResponse,
    oidc: &OidcConfig,
    id_token: &str,
    header: &jsonwebtoken::Header,
) -> Result<Value, String> {
    #[cfg(test)]
    if should_skip_signature_validation() {
        return decode_unverified_claims(id_token);
    }
    decode_signed_id_token_claims(client, metadata, oidc, id_token, header).await
}

async fn decode_signed_id_token_claims(
    client: &reqwest::Client,
    metadata: &DiscoveryResponse,
    oidc: &OidcConfig,
    id_token: &str,
    header: &jsonwebtoken::Header,
) -> Result<Value, String> {
    let jwks = fetch_jwks(client, &metadata.jwks_uri).await?;
    let jwk = select_jwk(&jwks.keys, header.kid.as_deref())?;
    let key = decoding_key_from_jwk(jwk)?;
    let validation = token_validation(header, metadata, oidc);
    decode::<Value>(id_token, &key, &validation)
        .map_err(|_| "oidc token validation failed".to_string())
        .map(|decoded| decoded.claims)
}

fn decoding_key_from_jwk(jwk: &Jwk) -> Result<DecodingKey, String> {
    DecodingKey::from_jwk(jwk).map_err(|_| "oidc key parse failed".to_string())
}

fn token_validation(
    header: &jsonwebtoken::Header,
    metadata: &DiscoveryResponse,
    oidc: &OidcConfig,
) -> Validation {
    let mut validation = Validation::new(header.alg);
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.set_issuer(&[metadata.issuer.as_str()]);
    validation.set_audience(&[oidc.audience.as_str()]);
    validation
}

#[cfg(test)]
fn should_skip_signature_validation() -> bool {
    matches!(
        std::env::var("NSS_TEST_SKIP_OIDC_SIGNATURE"),
        Ok(value) if value.trim().eq_ignore_ascii_case("1") || value.trim().eq_ignore_ascii_case("true")
    )
}

#[cfg(test)]
fn decode_unverified_claims(id_token: &str) -> Result<Value, String> {
    let payload = match id_token.split('.').nth(1) {
        Some(value) => value,
        None => return Err("oidc token validation failed".to_string()),
    };
    let decoded = match URL_SAFE_NO_PAD.decode(payload) {
        Ok(bytes) => bytes,
        Err(_) => return Err("oidc token validation failed".to_string()),
    };
    match serde_json::from_slice::<Value>(&decoded) {
        Ok(claims) => Ok(claims),
        Err(_) => Err("oidc token validation failed".to_string()),
    }
}

fn is_supported_alg(alg: Algorithm) -> bool {
    matches!(
        alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    )
}

async fn fetch_jwks(client: &reqwest::Client, jwks_uri: &str) -> Result<JwkSet, String> {
    let response = match client.get(jwks_uri).send().await {
        Ok(value) => value,
        Err(_) => return Err("oidc jwks request failed".to_string()),
    };
    if !response.status().is_success() {
        let status = response.status().as_u16();
        return Err(format!("oidc jwks fetch failed: {status}"));
    }
    match response.json::<JwkSet>().await {
        Ok(keys) => Ok(keys),
        Err(_) => Err("oidc jwks payload invalid".to_string()),
    }
}

fn select_jwk<'a>(keys: &'a [Jwk], kid: Option<&str>) -> Result<&'a Jwk, String> {
    if let Some(kid) = kid {
        for key in keys {
            if key.common.key_id.as_deref() == Some(kid) {
                return Ok(key);
            }
        }
        return Err("oidc jwks key id not found".to_string());
    }
    if keys.len() == 1 {
        return Ok(&keys[0]);
    }
    Err("oidc token missing key id".into())
}

fn extract_identity(
    claims: &Value,
    oidc: &OidcConfig,
    nonce: &str,
) -> Result<OidcIdentity, String> {
    ensure_nonce(claims, nonce)?;
    let subject = required_claim_string(claims, "sub")?;
    let username = resolve_username(claims, oidc, &subject);
    let display_name = match optional_claim_string(claims, &oidc.display_name_claim) {
        Some(value) => Some(value),
        None => optional_claim_string(claims, "name"),
    };
    let groups = claim_string_list(claims, &oidc.groups_claim);
    let is_admin = has_admin_group(&groups, &oidc.admin_groups);
    Ok(OidcIdentity {
        subject,
        username,
        display_name,
        is_admin,
    })
}

fn ensure_nonce(claims: &Value, expected: &str) -> Result<(), String> {
    let nonce = required_claim_string(claims, "nonce")?;
    if nonce == expected {
        return Ok(());
    }
    Err("oidc nonce mismatch".into())
}

fn required_claim_string(claims: &Value, key: &str) -> Result<String, String> {
    match optional_claim_string(claims, key) {
        Some(value) => Ok(value),
        None => Err(format!("oidc token missing {key} claim")),
    }
}

fn optional_claim_string(claims: &Value, key: &str) -> Option<String> {
    claim_value_by_path(claims, key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn resolve_username(claims: &Value, oidc: &OidcConfig, subject: &str) -> String {
    optional_claim_string(claims, &oidc.username_claim)
        .or_else(|| optional_claim_string(claims, "preferred_username"))
        .or_else(|| optional_claim_string(claims, "email"))
        .unwrap_or_else(|| subject.to_string())
}

fn claim_string_list(claims: &Value, key: &str) -> Vec<String> {
    let Some(value) = claim_value_by_path(claims, key) else {
        return Vec::new();
    };
    match value {
        Value::String(text) => vec![text.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(|entry| entry.to_string())
            .collect(),
        _ => Vec::new(),
    }
}

fn has_admin_group(groups: &[String], admin_groups: &[String]) -> bool {
    if admin_groups.is_empty() {
        return false;
    }
    groups
        .iter()
        .any(|group| admin_groups.iter().any(|admin| admin == group))
}

fn claim_value_by_path<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cursor = claims;
    for part in path.split('.') {
        let Value::Object(map) = cursor else {
            return None;
        };
        cursor = map.get(part)?;
    }
    Some(cursor)
}

#[cfg(test)]
mod tests {
    use super::{
        authorization_url, claim_string_list, claim_value_by_path, decode_unverified_claims,
        exchange_code_for_identity, extract_identity, fetch_jwks, generate_state_nonce,
        has_admin_group, is_supported_alg, resolve_username, select_jwk,
    };
    use crate::util::config::OidcConfig;
    use axum::http::StatusCode;
    use axum::routing::{get, post};
    use axum::Router;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use jsonwebtoken::Algorithm;
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::oneshot;

    const TEST_IDENTITY_ENV: &str = "NSS_TEST_OIDC_IDENTITY_JSON";

    struct TestEnvGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl TestEnvGuard {
        fn set(key: &'static str, value: String) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prev }
        }
    }

    impl Drop for TestEnvGuard {
        fn drop(&mut self) {
            if let Some(value) = self.prev.take() {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn oidc_config_with_issuer(issuer_url: &str) -> OidcConfig {
        OidcConfig {
            issuer_url: issuer_url.to_string(),
            client_id: "nss-console".to_string(),
            client_secret: None,
            redirect_url: "http://localhost:9001/console/v1/oidc/callback".to_string(),
            scopes: "openid profile email".to_string(),
            username_claim: "preferred_username".to_string(),
            display_name_claim: "name".to_string(),
            groups_claim: "realm_access.roles".to_string(),
            admin_groups: vec!["nss-admin".to_string()],
            audience: "nss-console".to_string(),
        }
    }

    fn oidc_config() -> OidcConfig {
        oidc_config_with_issuer("https://sso.example.com/realms/nss")
    }

    fn fake_rs256_token(kid: Option<&str>, claims: serde_json::Value) -> String {
        let mut header = json!({"alg":"RS256","typ":"JWT"});
        if let Some(value) = kid {
            header["kid"] = json!(value);
        }
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
        format!("{header}.{payload}.sig")
    }

    fn ensure_rustls_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    async fn spawn_oidc_server(
        token_status: StatusCode,
        token_body: serde_json::Value,
        jwks_status: StatusCode,
        jwks_body: serde_json::Value,
    ) -> (String, tokio::task::JoinHandle<std::io::Result<()>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let base_url = format!("http://{addr}");
        let discovery_payload = json!({
            "issuer": base_url,
            "authorization_endpoint": format!("{base_url}/authorize"),
            "token_endpoint": format!("{base_url}/token"),
            "jwks_uri": format!("{base_url}/jwks")
        });
        let discovery = Arc::new(discovery_payload);
        let token = Arc::new(token_body);
        let jwks = Arc::new(jwks_body);
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get({
                    let discovery = discovery.clone();
                    move || {
                        let discovery = discovery.clone();
                        async move { (StatusCode::OK, axum::Json((*discovery).clone())) }
                    }
                }),
            )
            .route(
                "/token",
                post({
                    let token = token.clone();
                    move || {
                        let token = token.clone();
                        async move { (token_status, axum::Json((*token).clone())) }
                    }
                }),
            )
            .route(
                "/jwks",
                get({
                    let jwks = jwks.clone();
                    move || {
                        let jwks = jwks.clone();
                        async move { (jwks_status, axum::Json((*jwks).clone())) }
                    }
                }),
            );
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let _ = started_tx.send(());
        let handle = tokio::spawn(std::future::IntoFuture::into_future(axum::serve(
            listener, app,
        )));
        let _ = started_rx.await;
        (base_url, handle)
    }

    async fn spawn_discovery_server(
        discovery_status: StatusCode,
        discovery_body: serde_json::Value,
    ) -> (String, tokio::task::JoinHandle<std::io::Result<()>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let app = Router::new().route(
            "/.well-known/openid-configuration",
            get(move || {
                let body = discovery_body.clone();
                async move { (discovery_status, axum::Json(body)) }
            }),
        );
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let _ = started_tx.send(());
        let handle = tokio::spawn(std::future::IntoFuture::into_future(axum::serve(
            listener, app,
        )));
        let _ = started_rx.await;
        (format!("http://{addr}"), handle)
    }

    #[test]
    fn state_and_nonce_are_distinct() {
        let (state, nonce) = generate_state_nonce();
        assert!(!state.is_empty());
        assert!(!nonce.is_empty());
        assert_ne!(state, nonce);
    }

    #[test]
    fn claim_path_supports_nested_values() {
        let claims = json!({
            "realm_access": {
                "roles": ["nss-admin"]
            }
        });
        assert!(claim_value_by_path(&claims, "realm_access.roles").is_some());
        assert!(claim_value_by_path(&claims, "realm_access.missing").is_none());
    }

    #[test]
    fn resolve_username_falls_back_to_subject() {
        let claims = json!({
            "sub": "sub-1",
            "nonce": "nonce-1",
            "aud": "nss-console",
            "iss": "https://sso.example.com/realms/nss",
            "exp": 9_999_999_999u64
        });
        let username = resolve_username(&claims, &oidc_config(), "sub-1");
        assert_eq!(username, "sub-1");
    }

    #[test]
    fn claim_string_list_reads_arrays() {
        let claims = json!({
            "realm_access": {
                "roles": ["nss-admin", "reader"]
            }
        });
        let groups = claim_string_list(&claims, "realm_access.roles");
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0], "nss-admin");
    }

    #[test]
    fn has_admin_group_matches_entries() {
        let groups = vec!["reader".to_string(), "nss-admin".to_string()];
        let admins = vec!["nss-admin".to_string()];
        assert!(has_admin_group(&groups, &admins));
        assert!(!has_admin_group(&groups, &[]));
    }

    #[test]
    fn supported_algorithms_exclude_hmac() {
        assert!(is_supported_alg(Algorithm::RS256));
        assert!(is_supported_alg(Algorithm::EdDSA));
        assert!(!is_supported_alg(Algorithm::HS256));
    }

    #[test]
    fn test_env_guard_restores_existing_value() {
        std::env::set_var(TEST_IDENTITY_ENV, "{\"subject\":\"before\"}");
        {
            let _guard =
                TestEnvGuard::set(TEST_IDENTITY_ENV, "{\"subject\":\"after\"}".to_string());
        }
        let restored = std::env::var(TEST_IDENTITY_ENV).expect("restored");
        assert_eq!(restored, "{\"subject\":\"before\"}");
        std::env::remove_var(TEST_IDENTITY_ENV);
    }

    #[test]
    fn extract_identity_reads_claims() {
        let claims = json!({
            "sub": "sub-1",
            "nonce": "nonce-1",
            "preferred_username": "alice",
            "name": "Alice",
            "realm_access": {
                "roles": ["nss-admin"]
            }
        });
        let identity = extract_identity(&claims, &oidc_config(), "nonce-1").expect("identity");
        assert_eq!(identity.subject, "sub-1");
        assert_eq!(identity.username, "alice");
        assert_eq!(identity.display_name.as_deref(), Some("Alice"));
        assert!(identity.is_admin);
    }

    #[tokio::test]
    async fn authorization_url_uses_discovery_metadata() {
        ensure_rustls_provider();
        let (issuer, handle) = spawn_oidc_server(
            StatusCode::OK,
            json!({ "id_token": "x" }),
            StatusCode::OK,
            json!({ "keys": [] }),
        )
        .await;
        let config = oidc_config_with_issuer(&issuer);
        let url = authorization_url(&config, "state-1", "nonce-1")
            .await
            .expect("url");
        assert!(url.contains("response_type=code"));
        assert!(url.contains("state=state-1"));
        assert!(url.contains("nonce=nonce-1"));
        handle.abort();
    }

    #[tokio::test]
    async fn authorization_url_reports_discovery_error() {
        ensure_rustls_provider();
        let config = oidc_config_with_issuer("http://127.0.0.1:1");
        let err = authorization_url(&config, "state-1", "nonce-1")
            .await
            .unwrap_err();
        assert!(err.contains("discovery"));
    }

    #[tokio::test]
    async fn authorization_url_rejects_invalid_authorization_endpoint() {
        ensure_rustls_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let issuer = format!("http://{addr}");
        let app = Router::new().route(
            "/.well-known/openid-configuration",
            get(move || {
                let issuer = issuer.clone();
                async move {
                    axum::Json(json!({
                        "issuer": issuer,
                        "authorization_endpoint": "::bad-url",
                        "token_endpoint": "http://localhost/token",
                        "jwks_uri": "http://localhost/jwks"
                    }))
                }
            }),
        );
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let _ = started_tx.send(());
        let handle = tokio::spawn(std::future::IntoFuture::into_future(axum::serve(
            listener, app,
        )));
        let _ = started_rx.await;
        let config = oidc_config_with_issuer(&format!("http://{addr}"));
        let err = authorization_url(&config, "state-1", "nonce-1")
            .await
            .unwrap_err();
        assert!(err.contains("invalid authorization endpoint"));
        handle.abort();
    }

    #[tokio::test]
    async fn authorization_url_reports_discovery_status_and_payload_errors() {
        ensure_rustls_provider();
        let (issuer, status_handle) =
            spawn_discovery_server(StatusCode::UNAUTHORIZED, json!({ "error": "unauthorized" }))
                .await;
        let config = oidc_config_with_issuer(&issuer);
        let err = authorization_url(&config, "state", "nonce")
            .await
            .unwrap_err();
        assert!(err.contains("discovery failed: 401"));
        status_handle.abort();

        let (issuer, payload_handle) =
            spawn_discovery_server(StatusCode::OK, json!({ "issuer": issuer_placeholder() })).await;
        let config = oidc_config_with_issuer(&issuer);
        let err = authorization_url(&config, "state", "nonce")
            .await
            .unwrap_err();
        assert!(err.contains("payload invalid"));
        payload_handle.abort();
    }

    fn issuer_placeholder() -> String {
        "http://localhost".to_string()
    }

    #[tokio::test]
    async fn exchange_code_reports_missing_id_token() {
        ensure_rustls_provider();
        let (issuer, handle) = spawn_oidc_server(
            StatusCode::OK,
            json!({ "id_token": "   " }),
            StatusCode::OK,
            json!({ "keys": [] }),
        )
        .await;
        let config = oidc_config_with_issuer(&issuer);
        let err = exchange_code_for_identity(&config, "code", "nonce-1")
            .await
            .unwrap_err();
        assert!(err.contains("missing id_token"));
        handle.abort();
    }

    #[tokio::test]
    async fn exchange_code_rejects_unsupported_signing_algorithm() {
        ensure_rustls_provider();
        let (issuer, handle) = spawn_oidc_server(
            StatusCode::OK,
            json!({
                "id_token": jsonwebtoken::encode(
                    &jsonwebtoken::Header::new(Algorithm::HS256),
                    &json!({
                        "sub": "u-1",
                        "nonce": "nonce-1",
                        "aud": "nss-console"
                    }),
                    &jsonwebtoken::EncodingKey::from_secret(b"secret")
                ).expect("token")
            }),
            StatusCode::OK,
            json!({ "keys": [] }),
        )
        .await;
        let config = oidc_config_with_issuer(&issuer);
        let err = exchange_code_for_identity(&config, "code", "nonce-1")
            .await
            .unwrap_err();
        assert!(err.contains("unsupported oidc signing algorithm"));
        handle.abort();
    }

    #[tokio::test]
    async fn exchange_code_reports_missing_jwk_kid() {
        ensure_rustls_provider();
        let (issuer, handle) = spawn_oidc_server(
            StatusCode::OK,
            json!({
                "id_token": fake_rs256_token(Some("missing-kid"), json!({ "sub": "u-1" }))
            }),
            StatusCode::OK,
            json!({ "keys": [] }),
        )
        .await;
        let config = oidc_config_with_issuer(&issuer);
        let err = exchange_code_for_identity(&config, "code", "nonce-1")
            .await
            .unwrap_err();
        assert!(err.contains("key id not found"));
        handle.abort();
    }

    #[tokio::test]
    async fn exchange_code_reports_token_exchange_status() {
        ensure_rustls_provider();
        let (issuer, handle) = spawn_oidc_server(
            StatusCode::UNAUTHORIZED,
            json!({ "id_token": "x" }),
            StatusCode::OK,
            json!({ "keys": [] }),
        )
        .await;
        let config = oidc_config_with_issuer(&issuer);
        let err = exchange_code_for_identity(&config, "code", "nonce-1")
            .await
            .unwrap_err();
        assert!(err.contains("token exchange failed: 401"));
        handle.abort();
    }

    async fn assert_exchange_reports_token_request_failed() {
        let (issuer, discovery_handle) = spawn_discovery_server(
            StatusCode::OK,
            json!({
                "issuer": "http://localhost",
                "authorization_endpoint": "http://localhost/authorize",
                "token_endpoint": "http://127.0.0.1:1/token",
                "jwks_uri": "http://localhost/jwks"
            }),
        )
        .await;
        let config = oidc_config_with_issuer(&issuer);
        let err = exchange_code_for_identity(&config, "code", "nonce")
            .await
            .unwrap_err();
        assert!(err.contains("token request failed"));
        discovery_handle.abort();
    }

    async fn assert_exchange_reports_token_payload_invalid() {
        let (issuer, payload_handle) = spawn_oidc_server(
            StatusCode::OK,
            json!("invalid-payload"),
            StatusCode::OK,
            json!({ "keys": [] }),
        )
        .await;
        let config = oidc_config_with_issuer(&issuer);
        let err = exchange_code_for_identity(&config, "code", "nonce")
            .await
            .unwrap_err();
        assert!(err.contains("token payload invalid"));
        payload_handle.abort();
    }

    async fn assert_exchange_reports_token_header_invalid() {
        let (issuer, header_handle) = spawn_oidc_server(
            StatusCode::OK,
            json!({ "id_token": "not-a-jwt-token" }),
            StatusCode::OK,
            json!({ "keys": [] }),
        )
        .await;
        let config = oidc_config_with_issuer(&issuer);
        let err = exchange_code_for_identity(&config, "code", "nonce")
            .await
            .unwrap_err();
        assert!(err.contains("token header invalid"));
        header_handle.abort();
    }

    #[tokio::test]
    async fn exchange_code_reports_request_payload_and_header_errors() {
        ensure_rustls_provider();
        assert_exchange_reports_token_request_failed().await;
        assert_exchange_reports_token_payload_invalid().await;
        assert_exchange_reports_token_header_invalid().await;
    }

    #[tokio::test]
    async fn exchange_code_with_secret_reaches_jwks_status_branch() {
        ensure_rustls_provider();
        let token = fake_rs256_token(None, json!({ "sub": "u-1" }));
        let (issuer, handle) = spawn_oidc_server(
            StatusCode::OK,
            json!({ "id_token": token }),
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "keys": [] }),
        )
        .await;
        let mut config = oidc_config_with_issuer(&issuer);
        config.client_secret = Some("secret".to_string());
        let err = exchange_code_for_identity(&config, "code", "nonce-1")
            .await
            .unwrap_err();
        assert!(err.contains("jwks fetch failed: 503"));
        handle.abort();
    }

    #[tokio::test]
    async fn exchange_code_reports_jwks_request_and_payload_errors() {
        ensure_rustls_provider();
        let client = reqwest::Client::new();
        let err = fetch_jwks(&client, "http://127.0.0.1:1/jwks")
            .await
            .unwrap_err();
        assert!(err.contains("jwks request failed"));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let app = Router::new().route(
            "/jwks",
            get(|| async { (StatusCode::OK, axum::Json(json!("bad-jwks-payload"))) }),
        );
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let _ = started_tx.send(());
        let handle = tokio::spawn(std::future::IntoFuture::into_future(axum::serve(
            listener, app,
        )));
        let _ = started_rx.await;
        let url = format!("http://{addr}/jwks");
        let err = fetch_jwks(&client, &url).await.unwrap_err();
        assert!(err.contains("jwks payload invalid"));
        handle.abort();
    }

    #[tokio::test]
    async fn authorization_url_reports_client_build_error_when_forced() {
        let _guard = TestEnvGuard::set("NSS_TEST_FORCE_OIDC_CLIENT_ERROR", "true".to_string());
        let config = oidc_config_with_issuer("http://127.0.0.1:1");
        let err = authorization_url(&config, "state", "nonce")
            .await
            .unwrap_err();
        assert!(err.contains("client init failed"));
    }

    #[tokio::test]
    async fn exchange_code_reports_client_build_error_when_forced() {
        let _guard = TestEnvGuard::set("NSS_TEST_FORCE_OIDC_CLIENT_ERROR", "true".to_string());
        let config = oidc_config_with_issuer("http://127.0.0.1:1");
        let err = exchange_code_for_identity(&config, "code", "nonce")
            .await
            .unwrap_err();
        assert!(err.contains("client init failed"));
    }

    #[tokio::test]
    async fn exchange_code_forced_signature_skip_extracts_identity() {
        let _guard = TestEnvGuard::set("NSS_TEST_SKIP_OIDC_SIGNATURE", "true".to_string());
        let (issuer, handle) = spawn_oidc_server(
            StatusCode::OK,
            json!({
                "id_token": fake_rs256_token(None, json!({
                    "sub": "forced-user",
                    "nonce": "nonce-1",
                    "aud": "nss-console",
                    "iss": "unused",
                    "exp": 9999999999u64,
                    "name": "Forced Name"
                }))
            }),
            StatusCode::OK,
            json!({ "keys": [] }),
        )
        .await;
        let mut config = oidc_config_with_issuer(&issuer);
        config.display_name_claim = "custom_display".to_string();
        let identity = exchange_code_for_identity(&config, "code", "nonce-1")
            .await
            .expect("identity");
        assert_eq!(identity.username, "forced-user");
        assert_eq!(identity.display_name.as_deref(), Some("Forced Name"));
        handle.abort();
    }

    #[tokio::test]
    async fn exchange_code_forced_signature_skip_rejects_malformed_payload() {
        let _guard = TestEnvGuard::set("NSS_TEST_SKIP_OIDC_SIGNATURE", "true".to_string());
        let malformed = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.bad-payload.sig";
        let (issuer, handle) = spawn_oidc_server(
            StatusCode::OK,
            json!({ "id_token": malformed }),
            StatusCode::OK,
            json!({ "keys": [] }),
        )
        .await;
        let config = oidc_config_with_issuer(&issuer);
        let err = exchange_code_for_identity(&config, "code", "nonce-1")
            .await
            .unwrap_err();
        assert!(err.contains("token validation failed"));
        handle.abort();
    }

    #[tokio::test]
    async fn exchange_code_reports_key_parse_error_for_matching_kid() {
        ensure_rustls_provider();
        let (issuer, handle) = spawn_oidc_server(
            StatusCode::OK,
            json!({
                "id_token": fake_rs256_token(Some("bad-rsa"), json!({
                    "sub": "u-1",
                    "nonce": "nonce-1",
                    "aud": "nss-console",
                    "iss": "http://example.invalid",
                    "exp": 9999999999u64
                }))
            }),
            StatusCode::OK,
            json!({
                "keys": [{
                    "kty": "RSA",
                    "kid": "bad-rsa",
                    "n": "!",
                    "e": "AQAB"
                }]
            }),
        )
        .await;
        let config = oidc_config_with_issuer(&issuer);
        let err = exchange_code_for_identity(&config, "code", "nonce-1")
            .await
            .unwrap_err();
        assert!(err.contains("key parse failed"));
        handle.abort();
    }

    #[test]
    fn select_jwk_without_kid_requires_single_key() {
        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(json!({
            "keys": [
                { "kty": "oct", "k": "AQAB" },
                { "kty": "oct", "k": "AQAB" }
            ]
        }))
        .expect("jwks");
        let err = select_jwk(&jwks.keys, None).unwrap_err();
        assert!(err.contains("missing key id"));
    }

    #[test]
    fn select_jwk_with_matching_kid_returns_key() {
        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(json!({
            "keys": [
                { "kty": "oct", "kid": "k-1", "k": "AQAB" },
                { "kty": "oct", "kid": "k-2", "k": "AQAB" }
            ]
        }))
        .expect("jwks");
        let key = select_jwk(&jwks.keys, Some("k-2")).expect("key");
        assert_eq!(key.common.key_id.as_deref(), Some("k-2"));
    }

    #[test]
    fn extract_identity_falls_back_to_name_claim() {
        let mut config = oidc_config();
        config.display_name_claim = "custom_display".to_string();
        let claims = json!({
            "sub": "sub-fallback",
            "nonce": "nonce-1",
            "name": "Fallback Name",
            "realm_access": { "roles": ["reader"] }
        });
        let identity = extract_identity(&claims, &config, "nonce-1").expect("identity");
        assert_eq!(identity.display_name.as_deref(), Some("Fallback Name"));
    }

    #[tokio::test]
    async fn exchange_code_without_kid_uses_single_jwk_then_fails_parse() {
        ensure_rustls_provider();
        let token = fake_rs256_token(None, json!({ "sub": "u-1" }));
        let (issuer, handle) = spawn_oidc_server(
            StatusCode::OK,
            json!({ "id_token": token }),
            StatusCode::OK,
            json!({ "keys": [{ "kty": "oct", "k": "AQAB" }] }),
        )
        .await;
        let config = oidc_config_with_issuer(&issuer);
        let err = exchange_code_for_identity(&config, "code", "nonce-1")
            .await
            .unwrap_err();
        assert!(err.contains("key parse failed") || err.contains("token validation failed"));
        handle.abort();
    }

    #[tokio::test]
    async fn exchange_code_uses_test_identity_override() {
        let _guard = TestEnvGuard::set(
            TEST_IDENTITY_ENV,
            json!({
                "subject": "sub-override",
                "username": "override-user",
                "display_name": "Override User",
                "is_admin": true
            })
            .to_string(),
        );
        let config = oidc_config_with_issuer("http://127.0.0.1:1");
        let identity = exchange_code_for_identity(&config, "code", "nonce")
            .await
            .expect("identity");
        assert_eq!(identity.subject, "sub-override");
        assert_eq!(identity.username, "override-user");
        assert_eq!(identity.display_name.as_deref(), Some("Override User"));
        assert!(identity.is_admin);
    }

    #[tokio::test]
    async fn exchange_code_reports_invalid_test_identity_json() {
        let _guard = TestEnvGuard::set(TEST_IDENTITY_ENV, "{bad-json}".to_string());
        let config = oidc_config_with_issuer("http://127.0.0.1:1");
        let err = exchange_code_for_identity(&config, "code", "nonce")
            .await
            .unwrap_err();
        assert!(err.contains("identity json invalid"));
    }

    #[test]
    fn claim_helpers_cover_string_scalar_and_non_object_paths() {
        let string_claims = json!({ "groups": "nss-admin" });
        let groups = claim_string_list(&string_claims, "groups");
        assert_eq!(groups, vec!["nss-admin".to_string()]);
        let scalar_claims = json!({ "groups": 42 });
        assert!(claim_string_list(&scalar_claims, "groups").is_empty());
        let invalid_path_claims = json!({ "realm_access": [] });
        assert!(claim_value_by_path(&invalid_path_claims, "realm_access.roles").is_none());
    }

    #[test]
    fn decode_unverified_claims_rejects_malformed_tokens() {
        let missing_payload = decode_unverified_claims("token-without-dots").unwrap_err();
        assert!(missing_payload.contains("oidc token validation failed"));

        let bad_base64 = decode_unverified_claims("a.@@.b").unwrap_err();
        assert!(bad_base64.contains("oidc token validation failed"));

        let payload = URL_SAFE_NO_PAD.encode("not-json");
        let invalid_json = decode_unverified_claims(&format!("a.{payload}.b")).unwrap_err();
        assert!(invalid_json.contains("oidc token validation failed"));
    }

    #[test]
    fn extract_identity_requires_matching_nonce() {
        let claims = json!({
            "sub": "sub-1",
            "nonce": "nonce-1",
            "preferred_username": "alice"
        });
        let err = extract_identity(&claims, &oidc_config(), "nonce-2").unwrap_err();
        assert!(err.contains("nonce mismatch"));
    }

    #[test]
    fn extract_identity_requires_nonce_claim() {
        let claims = json!({
            "sub": "sub-1",
            "preferred_username": "alice"
        });
        let err = extract_identity(&claims, &oidc_config(), "nonce-2").unwrap_err();
        assert!(err.contains("missing nonce claim"));
    }

    #[test]
    fn ensure_nonce_reports_missing_claim_directly() {
        let err = super::ensure_nonce(&json!({ "sub": "sub-1" }), "nonce-1").unwrap_err();
        assert!(err.contains("missing nonce claim"));
    }

    #[test]
    fn extract_identity_requires_subject_and_missing_groups_returns_empty() {
        let claims = json!({
            "nonce": "nonce-1",
            "preferred_username": "alice"
        });
        let err = extract_identity(&claims, &oidc_config(), "nonce-1").unwrap_err();
        assert!(err.contains("missing sub"));
        let groups = claim_string_list(&json!({}), "groups");
        assert!(groups.is_empty());
    }
}
