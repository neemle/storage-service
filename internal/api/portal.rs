use crate::api::{admin, admin_storage, console, AppState};
use axum::http::header::{
    HeaderName, ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use bytes::Bytes;
use include_dir::{include_dir, Dir};
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};

static EMBEDDED_UI: Dir = include_dir!("$CARGO_MANIFEST_DIR/embedded-ui");

pub fn router(state: AppState) -> Router {
    let mut router = admin::router(state.clone())
        .merge(admin_storage::router(state.clone()))
        .merge(console::router(state.clone()));

    if !state.config.cors_allow_origins.is_empty() {
        let cors = build_cors(&state.config.cors_allow_origins);
        router = router.layer(cors);
    }

    if let Some(dir) = state.config.ui_dir.as_ref() {
        let index_path = format!("{}/index.html", dir.trim_end_matches('/'));
        let service = ServeDir::new(dir)
            .precompressed_gzip()
            .fallback(ServeFile::new(index_path).precompressed_gzip());
        router = router.fallback_service(service);
    } else {
        router = router.fallback(embedded_ui);
    }

    router
}

fn build_cors(origins: &[String]) -> CorsLayer {
    let allow_headers = AllowHeaders::list(vec![
        CONTENT_TYPE,
        AUTHORIZATION,
        ACCEPT,
        HeaderName::from_static("x-requested-with"),
    ]);
    let allow_methods = AllowMethods::list(vec![
        Method::GET,
        Method::POST,
        Method::PATCH,
        Method::DELETE,
    ]);
    let cors = CorsLayer::new()
        .allow_methods(allow_methods)
        .allow_headers(allow_headers);

    if origins.iter().any(|val| val == "*") {
        return cors.allow_origin(Any);
    }
    let list = origins
        .iter()
        .filter_map(|val| HeaderValue::from_str(val).ok())
        .collect::<Vec<_>>();
    cors.allow_origin(AllowOrigin::list(list))
        .allow_credentials(true)
}

async fn embedded_ui(method: Method, uri: Uri, headers: HeaderMap) -> Response {
    embedded_ui_with_dir(&EMBEDDED_UI, method, uri, headers).await
}

async fn embedded_ui_with_dir(
    dir: &'static Dir<'static>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::NOT_FOUND.into_response();
    }

    let mut path = uri.path().trim_start_matches('/').to_string();
    if path.contains("..") {
        return StatusCode::NOT_FOUND.into_response();
    }
    if path.is_empty() {
        path = "index.html".to_string();
    }
    let allow_gzip = client_accepts_gzip(&headers);

    if let Some(asset) = get_embedded_asset(dir, &path, allow_gzip) {
        return response_with_content_type(asset.contents, asset.content_type, asset.gzipped);
    }

    if !path.contains('.') {
        if let Some(asset) = get_embedded_asset(dir, "index.html", allow_gzip) {
            return response_with_content_type(asset.contents, asset.content_type, asset.gzipped);
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

struct EmbeddedAsset {
    content_type: &'static str,
    contents: &'static [u8],
    gzipped: bool,
}

fn get_embedded_asset(
    dir: &'static Dir<'static>,
    path: &str,
    allow_gzip: bool,
) -> Option<EmbeddedAsset> {
    if allow_gzip {
        let gzip_path = format!("{path}.gz");
        if let Some(file) = dir.get_file(&gzip_path) {
            return Some(EmbeddedAsset {
                content_type: content_type_for(path),
                contents: file.contents(),
                gzipped: true,
            });
        }
    }

    dir.get_file(path).map(|file| EmbeddedAsset {
        content_type: content_type_for(path),
        contents: file.contents(),
        gzipped: false,
    })
}

fn response_with_content_type(
    contents: &'static [u8],
    content_type: &'static str,
    gzipped: bool,
) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    if gzipped {
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    }
    (headers, Bytes::from_static(contents)).into_response()
}

fn client_accepts_gzip(headers: &HeaderMap) -> bool {
    let Some(value) = headers.get(ACCEPT_ENCODING) else {
        return false;
    };
    let Ok(raw) = value.to_str() else {
        return false;
    };
    accepts_encoding(raw, "gzip")
}

fn accepts_encoding(raw: &str, target: &str) -> bool {
    raw.split(',').any(|part| encoding_allowed(part, target))
}

fn encoding_allowed(part: &str, target: &str) -> bool {
    let mut sections = part.split(';');
    let token = sections.next().unwrap_or("").trim();
    if !token.eq_ignore_ascii_case(target) {
        return false;
    }
    sections
        .find_map(parse_quality)
        .is_none_or(|quality| quality > 0.0)
}

fn parse_quality(section: &str) -> Option<f32> {
    let trimmed = section.trim();
    let (key, value) = trimmed.split_once('=')?;
    if !key.eq_ignore_ascii_case("q") {
        return None;
    }
    value.trim().parse::<f32>().ok()
}

fn content_type_for(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("");
    if ext.is_empty() {
        return "application/octet-stream";
    }
    match ext {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "eot" => "application/vnd.ms-fontobject",
        "ico" => "image/x-icon",
        "map" => "application/json; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        accepts_encoding, client_accepts_gzip, content_type_for, embedded_ui, embedded_ui_with_dir,
        get_embedded_asset, parse_quality, router,
    };
    use crate::test_support;
    use axum::body::Body;
    use axum::http::header::ACCEPT_ENCODING;
    use axum::http::{HeaderMap, HeaderValue, Method, Request};
    use include_dir::{include_dir, Dir};
    use tower::ServiceExt;

    static TEST_GZIP_UI: Dir = include_dir!("$CARGO_MANIFEST_DIR/tests/fixtures/portal-ui-gzip");

    #[tokio::test]
    async fn router_builds_with_defaults() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let _ = router(state);
    }

    #[tokio::test]
    async fn router_builds_with_cors_and_ui_dir() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        let ui_dir = test_support::new_temp_dir("portal-ui").await;
        tokio::fs::write(ui_dir.join("index.html"), "ok")
            .await
            .expect("write");
        state.config.ui_dir = Some(ui_dir.to_string_lossy().to_string());
        state.config.cors_allow_origins = vec!["*".to_string()];
        let _ = router(state);
    }

    #[tokio::test]
    async fn router_builds_with_specific_cors_origins() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.cors_allow_origins = vec!["https://example.com".to_string()];
        let _ = router(state);
    }

    #[tokio::test]
    async fn wildcard_cors_does_not_enable_credentials() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.cors_allow_origins = vec!["*".to_string()];
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/console/v1/me")
                    .header("origin", "https://example.com")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert!(response
            .headers()
            .get("access-control-allow-credentials")
            .is_none());
    }

    #[tokio::test]
    async fn explicit_origin_cors_enables_credentials() {
        let (mut state, _pool, _dir) = test_support::build_state("master").await;
        state.config.cors_allow_origins = vec!["https://example.com".to_string()];
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/console/v1/me")
                    .header("origin", "https://example.com")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let credentials = response
            .headers()
            .get("access-control-allow-credentials")
            .and_then(|value| value.to_str().ok());
        assert_eq!(credentials, Some("true"));
    }

    #[tokio::test]
    async fn embedded_ui_rejects_non_get_requests() {
        let response = embedded_ui(Method::POST, "/".parse().expect("uri"), HeaderMap::new()).await;
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn embedded_ui_serves_index_for_root_and_routes() {
        let root = embedded_ui(Method::GET, "/".parse().expect("uri"), HeaderMap::new()).await;
        assert_eq!(root.status(), axum::http::StatusCode::OK);

        let route = embedded_ui(
            Method::GET,
            "/app/buckets".parse().expect("uri"),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(route.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn embedded_ui_serves_gzip_when_client_requests_it() {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        let response = embedded_ui(Method::GET, "/".parse().expect("uri"), headers).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let encoding = response
            .headers()
            .get(axum::http::header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok());
        assert!(encoding.is_none() || encoding == Some("gzip"));
    }

    #[tokio::test]
    async fn embedded_ui_with_fixture_serves_precompressed_asset() {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        let response = embedded_ui_with_dir(
            &TEST_GZIP_UI,
            Method::GET,
            "/".parse().expect("uri"),
            headers,
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let encoding = response
            .headers()
            .get(axum::http::header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok());
        assert_eq!(encoding, Some("gzip"));
    }

    #[tokio::test]
    async fn embedded_ui_serves_index_for_route_without_extension() {
        let route = embedded_ui(
            Method::GET,
            "/console".parse().expect("uri"),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(route.status(), axum::http::StatusCode::OK);
        let content_type = route
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|val| val.to_str().ok());
        assert_eq!(content_type, Some("text/html; charset=utf-8"));
    }

    #[tokio::test]
    async fn embedded_ui_returns_not_found_for_missing_asset() {
        let response = embedded_ui(
            Method::GET,
            "/missing.css".parse().expect("uri"),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn embedded_ui_rejects_parent_traversal() {
        let response = embedded_ui(
            Method::GET,
            "/../secret".parse().expect("uri"),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn embedded_ui_allows_head_requests() {
        let response = embedded_ui(Method::HEAD, "/".parse().expect("uri"), HeaderMap::new()).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn embedded_ui_reports_missing_index() {
        let empty = Box::leak(Box::new(Dir::new("", &[])));
        let response = embedded_ui_with_dir(
            empty,
            Method::GET,
            "/console".parse().expect("uri"),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[test]
    fn client_accepts_gzip_when_header_allows_it() {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("br, gzip;q=0.8"));
        assert!(client_accepts_gzip(&headers));
    }

    #[test]
    fn client_rejects_gzip_when_quality_is_zero() {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip;q=0, br"));
        assert!(!client_accepts_gzip(&headers));
    }

    #[test]
    fn client_rejects_non_utf8_accept_encoding() {
        let mut headers = HeaderMap::new();
        let invalid = HeaderValue::from_bytes(&[0xFF]).expect("header");
        headers.insert(ACCEPT_ENCODING, invalid);
        assert!(!client_accepts_gzip(&headers));
    }

    #[test]
    fn accepts_encoding_matches_case_insensitive_tokens() {
        assert!(accepts_encoding("GZip, br", "gzip"));
        assert!(!accepts_encoding("br, deflate", "gzip"));
    }

    #[test]
    fn accepts_encoding_ignores_non_quality_parameters() {
        assert!(accepts_encoding("gzip;level=1", "gzip"));
    }

    #[test]
    fn parse_quality_rejects_sections_without_q_parameter() {
        assert_eq!(parse_quality("q"), None);
        assert_eq!(parse_quality("level=1"), None);
    }

    #[test]
    fn get_embedded_asset_returns_none_when_missing() {
        let empty = Box::leak(Box::new(Dir::new("", &[])));
        let asset = get_embedded_asset(empty, "missing.js", true);
        assert!(asset.is_none());
    }

    #[test]
    fn content_type_for_known_extensions() {
        assert_eq!(content_type_for("index.html"), "text/html; charset=utf-8");
        assert_eq!(content_type_for("app.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type_for("styles.css"), "text/css; charset=utf-8");
        assert_eq!(content_type_for("image.png"), "image/png");
    }

    #[test]
    fn content_type_for_additional_extensions_and_defaults() {
        assert_script_and_json_types();
        assert_image_types();
        assert_font_types();
        assert_default_types();
    }

    fn assert_script_and_json_types() {
        assert_eq!(
            content_type_for("bundle.mjs"),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            content_type_for("data.json"),
            "application/json; charset=utf-8"
        );
        assert_eq!(
            content_type_for("app.js.map"),
            "application/json; charset=utf-8"
        );
    }

    fn assert_image_types() {
        assert_eq!(content_type_for("icon.svg"), "image/svg+xml");
        assert_eq!(content_type_for("photo.jpg"), "image/jpeg");
        assert_eq!(content_type_for("photo.jpeg"), "image/jpeg");
        assert_eq!(content_type_for("anim.gif"), "image/gif");
        assert_eq!(content_type_for("image.webp"), "image/webp");
        assert_eq!(content_type_for("favicon.ico"), "image/x-icon");
    }

    fn assert_font_types() {
        assert_eq!(content_type_for("font.woff2"), "font/woff2");
        assert_eq!(content_type_for("font.woff"), "font/woff");
        assert_eq!(content_type_for("font.ttf"), "font/ttf");
        assert_eq!(
            content_type_for("font.eot"),
            "application/vnd.ms-fontobject"
        );
    }

    fn assert_default_types() {
        assert_eq!(
            content_type_for("asset.unknown"),
            "application/octet-stream"
        );
        assert_eq!(content_type_for("noext"), "application/octet-stream");
        assert_eq!(content_type_for(""), "application/octet-stream");
    }
}
