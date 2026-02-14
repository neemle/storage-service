use axum::http::HeaderMap;

#[derive(Clone)]
pub struct InternalAuth {
    token: String,
}

impl InternalAuth {
    pub fn new(token: String) -> Self {
        Self { token }
    }

    pub fn header_value(&self) -> String {
        format!("Bearer {}", self.token)
    }

    pub fn verify_headers(&self, headers: &HeaderMap) -> bool {
        let expected = self.header_value();
        headers
            .get("Authorization")
            .map(|value| constant_time_eq(value.as_bytes(), expected.as_bytes()))
            .unwrap_or(false)
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    let mut index = 0usize;
    while index < max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= (left_byte ^ right_byte) as usize;
        index += 1;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::InternalAuth;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn header_value_formats_bearer() {
        let auth = InternalAuth::new("token-123".to_string());
        assert_eq!(auth.header_value(), "Bearer token-123");
    }

    #[test]
    fn verify_headers_accepts_exact_match() {
        let auth = InternalAuth::new("token-123".to_string());
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&auth.header_value()).expect("value"),
        );
        assert!(auth.verify_headers(&headers));
    }

    #[test]
    fn verify_headers_rejects_missing_or_mismatch() {
        let auth = InternalAuth::new("token-123".to_string());
        let mut headers = HeaderMap::new();
        assert!(!auth.verify_headers(&headers));

        headers.insert("Authorization", HeaderValue::from_static("Bearer nope"));
        assert!(!auth.verify_headers(&headers));
    }
}
