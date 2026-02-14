use crate::api::AppState;
use crate::auth::token::Claims;
use axum::http::HeaderMap;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use time::Duration;

pub fn extract_token(headers: &HeaderMap, jar: Option<&CookieJar>) -> Option<String> {
    if let Some(value) = headers.get("Authorization") {
        if let Ok(value_str) = value.to_str() {
            if let Some(token) = value_str.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }
    if let Some(jar) = jar {
        if let Some(cookie) = jar.get("nss_session") {
            return Some(cookie.value().to_string());
        }
    }
    None
}

pub fn verify_claims(state: &AppState, token: &str) -> Result<Claims, String> {
    state.token_manager.verify(token)
}

pub fn clear_session_cookie() -> Cookie<'static> {
    clear_cookie("nss_session")
}

pub fn session_cookie(token: &str, insecure: bool) -> Cookie<'static> {
    transient_cookie("nss_session", token, insecure)
}

pub fn clear_cookie(name: &str) -> Cookie<'static> {
    Cookie::build((name.to_string(), String::new()))
        .path("/")
        .http_only(true)
        .max_age(Duration::seconds(0))
        .build()
}

pub fn transient_cookie(name: &str, value: &str, insecure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::build((name.to_string(), value.to_string()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();
    if !insecure {
        cookie.set_secure(true);
    }
    cookie
}

#[cfg(test)]
mod tests {
    use super::{
        clear_cookie, clear_session_cookie, extract_token, session_cookie, transient_cookie,
        verify_claims,
    };
    use crate::test_support;
    use axum::http::{HeaderMap, HeaderValue};
    use axum_extra::extract::cookie::CookieJar;

    #[tokio::test]
    async fn extract_token_prefers_authorization_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            "Bearer header-token".parse().expect("header"),
        );
        let jar = CookieJar::new().add(session_cookie("cookie-token", true));
        let token = extract_token(&headers, Some(&jar)).expect("token");
        assert_eq!(token, "header-token");
    }

    #[tokio::test]
    async fn extract_token_reads_cookie_when_header_missing() {
        let headers = HeaderMap::new();
        let jar = CookieJar::new().add(session_cookie("cookie-token", true));
        let token = extract_token(&headers, Some(&jar)).expect("token");
        assert_eq!(token, "cookie-token");
        assert!(extract_token(&headers, None).is_none());
    }

    #[tokio::test]
    async fn extract_token_falls_back_when_header_not_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Basic abc".parse().expect("header"));
        let jar = CookieJar::new().add(session_cookie("cookie-token", true));
        let token = extract_token(&headers, Some(&jar)).expect("token");
        assert_eq!(token, "cookie-token");
    }

    #[tokio::test]
    async fn extract_token_falls_back_when_header_invalid() {
        let mut headers = HeaderMap::new();
        let raw = HeaderValue::from_bytes(b"\xff").expect("header");
        headers.insert("Authorization", raw);
        let jar = CookieJar::new().add(session_cookie("cookie-token", true));
        let token = extract_token(&headers, Some(&jar)).expect("token");
        assert_eq!(token, "cookie-token");
    }

    #[tokio::test]
    async fn session_cookie_sets_secure_flag() {
        let secure = session_cookie("token", false);
        assert!(secure.secure().unwrap_or(false));
        let insecure = session_cookie("token", true);
        assert!(insecure.secure().is_none());
        assert!(!insecure.secure().unwrap_or(false));
        let mut forced = session_cookie("token", true);
        forced.set_secure(false);
        assert!(forced.secure().is_some());
        assert!(!forced.secure().unwrap_or(false));
    }

    #[tokio::test]
    async fn clear_session_cookie_resets_value() {
        let cookie = clear_session_cookie();
        assert_eq!(cookie.name(), "nss_session");
        assert_eq!(cookie.value(), "");
    }

    #[tokio::test]
    async fn helper_cookies_use_requested_name() {
        let cookie = transient_cookie("nss_oidc_state", "state", true);
        assert_eq!(cookie.name(), "nss_oidc_state");
        assert_eq!(cookie.value(), "state");
        let cleared = clear_cookie("nss_oidc_state");
        assert_eq!(cleared.name(), "nss_oidc_state");
        assert_eq!(cleared.value(), "");
    }

    #[tokio::test]
    async fn verify_claims_accepts_valid_token() {
        let (state, _pool, _dir) = test_support::build_state("master").await;
        let token = state
            .token_manager
            .issue(state.node_id, true)
            .expect("token");
        let claims = verify_claims(&state, &token).expect("claims");
        assert!(claims.is_admin);
    }
}
