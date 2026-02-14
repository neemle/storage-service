use crate::s3::errors::S3Error;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use url::form_urlencoded;

#[derive(Clone, Debug)]
pub(crate) struct SigV4Params {
    pub access_key: String,
    pub credential_scope: String,
    pub signed_headers: Vec<String>,
    pub signature: String,
    pub algorithm: String,
    pub amz_date: String,
    pub expires: Option<i64>,
    pub payload_hash: String,
    pub is_presigned: bool,
}

pub(crate) fn parse_authorization(
    headers: &axum::http::HeaderMap,
    method: &str,
) -> Result<SigV4Params, S3Error> {
    let auth_header = required_header(headers, "authorization")?;
    let (algorithm, params_str) = split_auth_header(&auth_header);
    let params = parse_auth_params(params_str);
    let (access_key, credential_scope) = parse_credential(required_param(&params, "Credential")?)?;
    let amz_date = required_header(headers, "x-amz-date")?;
    let payload_hash = resolve_payload_hash(headers, method);
    Ok(SigV4Params {
        access_key,
        credential_scope,
        signed_headers: split_signed_headers(required_param(&params, "SignedHeaders")?),
        signature: required_param(&params, "Signature")?.to_string(),
        algorithm,
        amz_date,
        expires: None,
        payload_hash,
        is_presigned: false,
    })
}

pub(crate) fn parse_presigned(query: &str) -> Result<SigV4Params, S3Error> {
    let params = parse_query_params(query);
    let (access_key, credential_scope) =
        parse_credential(required_param(&params, "X-Amz-Credential")?)?;
    let payload_hash = params
        .get("X-Amz-Content-Sha256")
        .cloned()
        .unwrap_or_else(|| "UNSIGNED-PAYLOAD".to_string());

    Ok(SigV4Params {
        access_key,
        credential_scope,
        signed_headers: split_signed_headers(required_param(&params, "X-Amz-SignedHeaders")?),
        signature: required_param(&params, "X-Amz-Signature")?.to_string(),
        algorithm: required_param(&params, "X-Amz-Algorithm")?.to_string(),
        amz_date: required_param(&params, "X-Amz-Date")?.to_string(),
        expires: parse_expires(&params),
        payload_hash,
        is_presigned: true,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn presign_url(
    method: &str,
    endpoint: &str,
    bucket: &str,
    key: &str,
    access_key: &str,
    secret: &str,
    expires_seconds: i64,
    region: &str,
) -> Result<String, String> {
    let method = method.to_uppercase();
    let now = Utc::now();
    let timestamps = PresignTimestamps::new(now, region);
    let (mut url, path, host) = build_presign_endpoint(endpoint, bucket, key)?;
    let mut params = build_presign_params(access_key, expires_seconds, &timestamps);
    params.sort();
    let canonical_query = encode_query_pairs(&params);
    let canonical_uri = canonical_uri(&path);
    let canonical_host_header = format!("host:{host}\n");
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, canonical_uri, canonical_query, canonical_host_header, "host", "UNSIGNED-PAYLOAD"
    );
    let signature = sign_presigned_request(secret, &timestamps, &canonical_request)?;
    params.push(("X-Amz-Signature".to_string(), signature));
    url.set_query(Some(&encode_query_pairs(&params)));
    Ok(url.to_string())
}

fn split_auth_header(auth_header: &str) -> (String, &str) {
    let mut parts = auth_header.splitn(2, ' ');
    let algorithm = parts.next().unwrap_or("").to_string();
    (algorithm, parts.next().unwrap_or(""))
}

fn parse_query_params(query: &str) -> HashMap<String, String> {
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect::<HashMap<String, String>>()
}

fn required_header(headers: &axum::http::HeaderMap, name: &str) -> Result<String, S3Error> {
    headers
        .get(name)
        .and_then(|val| val.to_str().ok())
        .map(|val| val.to_string())
        .ok_or(S3Error::AccessDenied)
}

fn required_param<'a>(params: &'a HashMap<String, String>, key: &str) -> Result<&'a str, S3Error> {
    params
        .get(key)
        .map(String::as_str)
        .ok_or(S3Error::AccessDenied)
}

fn parse_credential(credential: &str) -> Result<(String, String), S3Error> {
    let mut parts = credential.split('/');
    let access_key = parts.next().unwrap_or("");
    if access_key.is_empty() {
        return Err(S3Error::AccessDenied);
    }
    Ok((
        access_key.to_string(),
        parts.collect::<Vec<&str>>().join("/"),
    ))
}

fn split_signed_headers(headers: &str) -> Vec<String> {
    headers.split(';').map(|item| item.to_string()).collect()
}

fn resolve_payload_hash(headers: &axum::http::HeaderMap, method: &str) -> String {
    headers
        .get("x-amz-content-sha256")
        .and_then(|val| val.to_str().ok())
        .map(|val| val.to_string())
        .unwrap_or_else(|| unsigned_payload_hash(method))
}

fn unsigned_payload_hash(method: &str) -> String {
    if method == "GET" || method == "HEAD" {
        return "UNSIGNED-PAYLOAD".to_string();
    }
    hex::encode(Sha256::digest(b""))
}

fn parse_expires(params: &HashMap<String, String>) -> Option<i64> {
    params
        .get("X-Amz-Expires")
        .and_then(|val| val.parse::<i64>().ok())
}

struct PresignTimestamps {
    amz_date: String,
    credential_scope: String,
}

impl PresignTimestamps {
    fn new(now: DateTime<Utc>, region: &str) -> Self {
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let credential_scope = format!("{}/{}/s3/aws4_request", date_stamp, region);
        Self {
            amz_date,
            credential_scope,
        }
    }
}

fn build_presign_endpoint(
    endpoint: &str,
    bucket: &str,
    key: &str,
) -> Result<(url::Url, String, String), String> {
    let mut url = url::Url::parse(endpoint).map_err(|_| "invalid endpoint".to_string())?;
    let path = if key.is_empty() {
        format!("/{}", bucket)
    } else {
        format!("/{}/{}", bucket, key)
    };
    url.set_path(&path);
    let host = url
        .host_str()
        .ok_or_else(|| "invalid endpoint".to_string())?;
    let host = if let Some(port) = url.port() {
        format!("{}:{}", host, port)
    } else {
        host.to_string()
    };
    Ok((url, path, host))
}

fn build_presign_params(
    access_key: &str,
    expires_seconds: i64,
    timestamps: &PresignTimestamps,
) -> Vec<(String, String)> {
    vec![
        (
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
        (
            "X-Amz-Credential".to_string(),
            format!("{}/{}", access_key, timestamps.credential_scope),
        ),
        ("X-Amz-Date".to_string(), timestamps.amz_date.clone()),
        ("X-Amz-Expires".to_string(), expires_seconds.to_string()),
        ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
        (
            "X-Amz-Content-Sha256".to_string(),
            "UNSIGNED-PAYLOAD".to_string(),
        ),
    ]
}

fn encode_query_pairs(params: &[(String, String)]) -> String {
    params
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<String>>()
        .join("&")
}

fn sign_presigned_request(
    secret: &str,
    timestamps: &PresignTimestamps,
    canonical_request: &str,
) -> Result<String, String> {
    let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = build_string_to_sign(
        "AWS4-HMAC-SHA256",
        &timestamps.amz_date,
        &timestamps.credential_scope,
        &canonical_hash,
    );
    calculate_signature(secret, &timestamps.credential_scope, &string_to_sign)
        .map_err(|_| "signature failed".to_string())
}

fn parse_auth_params(params_str: &str) -> HashMap<String, String> {
    params_str
        .split(',')
        .filter_map(|kv| {
            let mut iter = kv.trim().splitn(2, '=');
            let key = iter.next().unwrap_or("").trim();
            let value = iter.next()?.trim();
            if key.is_empty() || value.is_empty() {
                return None;
            }
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

pub(crate) fn build_canonical_request(
    method: &str,
    path: &str,
    query: &str,
    headers: &axum::http::HeaderMap,
    signed_headers: &[String],
    payload_hash: &str,
    is_presigned: bool,
) -> Result<String, S3Error> {
    let canonical_uri = canonical_uri(path);
    let canonical_query = canonical_query(query, is_presigned);
    let canonical_headers = canonical_headers(headers, signed_headers)?;
    let signed_headers_str = signed_headers.join(";");
    Ok(format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, canonical_uri, canonical_query, canonical_headers, signed_headers_str, payload_hash
    ))
}

fn canonical_uri(path: &str) -> String {
    let segments = path.split('/').map(encode).collect::<Vec<String>>();
    let mut out = segments.join("/");
    if !out.starts_with('/') {
        out.insert(0, '/');
    }
    out
}

pub(crate) fn canonical_query(query: &str, is_presigned: bool) -> String {
    let mut pairs: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    if is_presigned {
        pairs.retain(|(k, _)| k != "X-Amz-Signature");
    }
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", encode(&k), encode(&v)))
        .collect::<Vec<String>>()
        .join("&")
}

pub(crate) fn canonical_headers(
    headers: &axum::http::HeaderMap,
    signed_headers: &[String],
) -> Result<String, S3Error> {
    let mut out = String::new();
    for name in signed_headers {
        let value = headers
            .get(name)
            .and_then(|val| val.to_str().ok())
            .ok_or(S3Error::AccessDenied)?;
        let normalized = value.split_whitespace().collect::<Vec<&str>>().join(" ");
        out.push_str(&format!("{}:{}\n", name.to_lowercase(), normalized));
    }
    Ok(out)
}

pub(crate) fn build_string_to_sign(
    algorithm: &str,
    amz_date: &str,
    scope: &str,
    canonical_hash: &str,
) -> String {
    format!("{}\n{}\n{}\n{}", algorithm, amz_date, scope, canonical_hash)
}

pub(crate) fn calculate_signature(
    secret: &str,
    credential_scope: &str,
    string_to_sign: &str,
) -> Result<String, S3Error> {
    let scope_parts: Vec<&str> = credential_scope.split('/').collect();
    if scope_parts.len() < 4 {
        return Err(S3Error::AccessDenied);
    }
    let date = scope_parts[0];
    let region = scope_parts[1];
    let service = scope_parts[2];
    if date.is_empty() || region.is_empty() || service.is_empty() {
        return Err(S3Error::AccessDenied);
    }

    let mut key = sign(format!("AWS4{}", secret).as_bytes(), date.as_bytes());
    key = sign(&key, region.as_bytes());
    key = sign(&key, service.as_bytes());
    key = sign(&key, b"aws4_request");

    let signature_bytes = sign(&key, string_to_sign.as_bytes());
    Ok(hex::encode(signature_bytes))
}

fn sign(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

pub(crate) fn parse_amz_date(value: &str) -> Result<DateTime<Utc>, S3Error> {
    let offset_formats = ["%Y%m%dT%H%M%S%z", "%Y%m%dT%H%M%S%.f%z"];
    for fmt in offset_formats {
        if let Ok(parsed) = DateTime::parse_from_str(value, fmt) {
            return Ok(parsed.with_timezone(&Utc));
        }
    }

    let naive_formats = ["%Y%m%dT%H%M%SZ", "%Y%m%dT%H%M%S%.fZ"];
    for fmt in naive_formats {
        if let Ok(parsed) = NaiveDateTime::parse_from_str(value, fmt) {
            return Ok(Utc.from_utc_datetime(&parsed));
        }
    }

    Err(S3Error::RequestTimeTooSkewed)
}

fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use std::collections::HashMap;

    const CANONICAL_UNSIGNED_GET: &str = concat!(
        "GET\n/test.txt\n\nhost:example.amazonaws.com\nx-amz-date:20130524T000000Z\n\n",
        "host;x-amz-date\nUNSIGNED-PAYLOAD"
    );
    const AUTH_HEADER_BASIC: &str = concat!(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request, ",
        "SignedHeaders=host;x-amz-date, Signature=deadbeef"
    );
    const AUTH_HEADER_WITH_SHA256: &str = concat!(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request, ",
        "SignedHeaders=host;x-amz-date;x-amz-content-sha256, Signature=deadbeef"
    );
    const AUTH_HEADER_EMPTY_KEY: &str = concat!(
        "AWS4-HMAC-SHA256 Credential=/20130524/us-east-1/s3/aws4_request, ",
        "SignedHeaders=host;x-amz-date, Signature=deadbeef"
    );
    const PRESIGNED_QUERY_FULL: &str = concat!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256",
        "&X-Amz-Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request",
        "&X-Amz-Date=20130524T000000Z",
        "&X-Amz-Expires=900",
        "&X-Amz-SignedHeaders=host",
        "&X-Amz-Signature=deadbeef"
    );
    const PRESIGNED_QUERY_NO_CREDENTIAL: &str = concat!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256",
        "&X-Amz-Date=20130524T000000Z",
        "&X-Amz-Expires=900",
        "&X-Amz-SignedHeaders=host",
        "&X-Amz-Signature=deadbeef"
    );
    const PRESIGNED_QUERY_NO_SIGNED_HEADERS: &str = concat!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256",
        "&X-Amz-Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request",
        "&X-Amz-Date=20130524T000000Z",
        "&X-Amz-Expires=900",
        "&X-Amz-Signature=deadbeef"
    );
    const PRESIGNED_QUERY_NO_SIGNATURE: &str = concat!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256",
        "&X-Amz-Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request",
        "&X-Amz-Date=20130524T000000Z",
        "&X-Amz-Expires=900",
        "&X-Amz-SignedHeaders=host"
    );
    const PRESIGNED_QUERY_NO_DATE: &str = concat!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256",
        "&X-Amz-Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request",
        "&X-Amz-Expires=900",
        "&X-Amz-SignedHeaders=host",
        "&X-Amz-Signature=deadbeef"
    );
    const PRESIGNED_QUERY_EMPTY_KEY: &str = concat!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256",
        "&X-Amz-Credential=/20130524/us-east-1/s3/aws4_request",
        "&X-Amz-Date=20130524T000000Z",
        "&X-Amz-Expires=900",
        "&X-Amz-SignedHeaders=host",
        "&X-Amz-Signature=deadbeef"
    );
    const PRESIGNED_QUERY_WITH_PAYLOAD_HASH: &str = concat!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256",
        "&X-Amz-Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request",
        "&X-Amz-Date=20130524T000000Z",
        "&X-Amz-Expires=900",
        "&X-Amz-SignedHeaders=host",
        "&X-Amz-Signature=deadbeef",
        "&X-Amz-Content-Sha256=custom"
    );
    const PRESIGNED_QUERY_NO_ALGORITHM: &str = concat!(
        "X-Amz-Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request",
        "&X-Amz-Date=20130524T000000Z",
        "&X-Amz-Expires=900",
        "&X-Amz-SignedHeaders=host",
        "&X-Amz-Signature=deadbeef"
    );
    const PRESIGNED_CANONICAL_EXPECTED: &str = concat!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256",
        "&X-Amz-Credential=AKIDEXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request",
        "&X-Amz-Date=20130524T000000Z",
        "&X-Amz-Expires=900",
        "&X-Amz-SignedHeaders=host"
    );

    #[test]
    fn canonical_request_for_unsigned_get_matches_expected() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "example.amazonaws.com".parse().unwrap());
        headers.insert("x-amz-date", "20130524T000000Z".parse().unwrap());
        let signed_headers = vec!["host".to_string(), "x-amz-date".to_string()];
        let canonical = build_canonical_request(
            "GET",
            "/test.txt",
            "",
            &headers,
            &signed_headers,
            "UNSIGNED-PAYLOAD",
            false,
        )
        .expect("canonical request");
        let expected = CANONICAL_UNSIGNED_GET;
        assert_eq!(canonical, expected);
    }

    #[test]
    fn build_canonical_request_errors_when_headers_missing() {
        let headers = HeaderMap::new();
        let signed_headers = vec!["host".to_string()];
        let err = build_canonical_request(
            "GET",
            "/test.txt",
            "",
            &headers,
            &signed_headers,
            "UNSIGNED-PAYLOAD",
            false,
        )
        .unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[test]
    fn calculate_signature_matches_known_vector() {
        let canonical_request = CANONICAL_UNSIGNED_GET;
        let canonical_hash = hex::encode(sha2::Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign = build_string_to_sign(
            "AWS4-HMAC-SHA256",
            "20130524T000000Z",
            "20130524/us-east-1/s3/aws4_request",
            &canonical_hash,
        );
        let signature = calculate_signature(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20130524/us-east-1/s3/aws4_request",
            &string_to_sign,
        )
        .expect("signature");
        assert_eq!(
            signature,
            "2f819a66faed8119d759825dd109febdded18c22d8003898d182e768c5e59366"
        );
    }

    #[test]
    fn parse_authorization_defaults_unsigned_payload_for_get() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", AUTH_HEADER_BASIC.parse().unwrap());
        headers.insert("x-amz-date", "20130524T000000Z".parse().unwrap());
        let params = parse_authorization(&headers, "GET").expect("params");
        assert_eq!(params.access_key, "AKIDEXAMPLE");
        assert_eq!(
            params.credential_scope,
            "20130524/us-east-1/s3/aws4_request"
        );
        assert_eq!(params.payload_hash, "UNSIGNED-PAYLOAD");
        assert_eq!(
            params.signed_headers,
            vec!["host".to_string(), "x-amz-date".to_string()]
        );
    }

    #[test]
    fn parse_authorization_defaults_empty_hash_for_put() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", AUTH_HEADER_BASIC.parse().unwrap());
        headers.insert("x-amz-date", "20130524T000000Z".parse().unwrap());
        let params = parse_authorization(&headers, "PUT").expect("params");
        assert_eq!(params.payload_hash, hex::encode(sha2::Sha256::digest(b"")));
    }

    #[test]
    fn parse_authorization_rejects_missing_signed_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request, Signature=deadbeef"
                .parse()
                .unwrap(),
        );
        headers.insert("x-amz-date", "20130524T000000Z".parse().unwrap());
        let err = parse_authorization(&headers, "GET").unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[test]
    fn parse_authorization_rejects_missing_signature() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date"
                .parse()
                .unwrap(),
        );
        headers.insert("x-amz-date", "20130524T000000Z".parse().unwrap());
        let err = parse_authorization(&headers, "GET").unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[test]
    fn parse_authorization_rejects_empty_access_key() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", AUTH_HEADER_EMPTY_KEY.parse().unwrap());
        headers.insert("x-amz-date", "20130524T000000Z".parse().unwrap());
        let err = parse_authorization(&headers, "GET").unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[test]
    fn parse_authorization_defaults_payload_hash_when_header_invalid() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", AUTH_HEADER_WITH_SHA256.parse().unwrap());
        headers.insert("x-amz-date", "20130524T000000Z".parse().unwrap());
        let invalid = HeaderValue::from_bytes(&[0x80]).expect("header value");
        headers.insert("x-amz-content-sha256", invalid);
        let params = parse_authorization(&headers, "GET").expect("params");
        assert_eq!(params.payload_hash, "UNSIGNED-PAYLOAD");
    }

    #[test]
    fn parse_authorization_honors_payload_hash_header() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", AUTH_HEADER_WITH_SHA256.parse().unwrap());
        headers.insert("x-amz-date", "20130524T000000Z".parse().unwrap());
        headers.insert("x-amz-content-sha256", "custom-hash".parse().unwrap());
        let params = parse_authorization(&headers, "PUT").expect("params");
        assert_eq!(params.payload_hash, "custom-hash");
    }

    #[test]
    fn parse_authorization_rejects_missing_headers() {
        let headers = HeaderMap::new();
        let err = parse_authorization(&headers, "GET").unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);

        let mut headers = HeaderMap::new();
        headers.insert("authorization", AUTH_HEADER_BASIC.parse().unwrap());
        let err = parse_authorization(&headers, "GET").unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[test]
    fn parse_authorization_rejects_missing_params() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=deadbeef"
                .parse()
                .unwrap(),
        );
        headers.insert("x-amz-date", "20130524T000000Z".parse().unwrap());
        let err = parse_authorization(&headers, "GET").unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[test]
    fn canonical_query_presigned_excludes_signature() {
        let query = PRESIGNED_QUERY_FULL;
        let canonical = canonical_query(query, true);
        assert_eq!(canonical, PRESIGNED_CANONICAL_EXPECTED);
    }

    #[test]
    fn canonical_query_sorts_params() {
        let query = "b=2&a=1";
        let canonical = canonical_query(query, false);
        assert_eq!(canonical, "a=1&b=2");
    }

    #[test]
    fn canonical_uri_encodes_and_normalizes() {
        assert_eq!(canonical_uri("test file.txt"), "/test%20file.txt");
        assert_eq!(canonical_uri("/a/b"), "/a/b");
    }

    #[test]
    fn canonical_headers_normalizes_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "example.amazonaws.com".parse().unwrap());
        headers.insert("x-amz-date", "20130524T000000Z".parse().unwrap());
        headers.insert("x-amz-meta", " spaced   out ".parse().unwrap());
        let signed_headers = vec![
            "host".to_string(),
            "x-amz-date".to_string(),
            "x-amz-meta".to_string(),
        ];
        let canonical = canonical_headers(&headers, &signed_headers).expect("canonical headers");
        assert_eq!(
            canonical,
            "host:example.amazonaws.com\nx-amz-date:20130524T000000Z\nx-amz-meta:spaced out\n"
        );
    }

    #[test]
    fn canonical_headers_errors_when_missing() {
        let headers = HeaderMap::new();
        let signed_headers = vec!["host".to_string()];
        let err = canonical_headers(&headers, &signed_headers).unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[test]
    fn build_string_to_sign_formats() {
        let out = build_string_to_sign("AWS4", "date", "scope", "hash");
        assert_eq!(out, "AWS4\ndate\nscope\nhash");
    }

    #[test]
    fn calculate_signature_rejects_invalid_scope() {
        let err = calculate_signature("secret", "too-short", "string");
        assert_eq!(err, Err(S3Error::AccessDenied));
    }

    #[test]
    fn parse_amz_date_accepts_offsets_and_z() {
        let offset = parse_amz_date("20130524T000000+0000").expect("offset parse");
        assert_eq!(offset.to_rfc3339(), "2013-05-24T00:00:00+00:00");
        let naive = parse_amz_date("20130524T000000Z").expect("z parse");
        assert_eq!(naive.to_rfc3339(), "2013-05-24T00:00:00+00:00");
    }

    #[test]
    fn parse_amz_date_rejects_invalid() {
        let err = parse_amz_date("bad").unwrap_err();
        assert_eq!(err, S3Error::RequestTimeTooSkewed);
    }

    #[test]
    fn encode_escapes_spaces() {
        assert_eq!(encode("a b"), "a%20b");
    }

    #[test]
    fn presign_url_encodes_unicode_paths() {
        let url = presign_url(
            "GET",
            "http://localhost:9000",
            "my-bucket",
            "folder/space name/über.txt",
            "AKIDEXAMPLE",
            "secret",
            60,
            "us-east-1",
        )
        .expect("presign");
        let parsed = url::Url::parse(&url).expect("parsed");
        assert_eq!(
            parsed.path(),
            "/my-bucket/folder/space%20name/%C3%BCber.txt"
        );
    }

    #[test]
    fn parse_presigned_extracts_fields() {
        let query = PRESIGNED_QUERY_FULL;
        let params = parse_presigned(query).expect("params");
        assert_eq!(params.access_key, "AKIDEXAMPLE");
        assert_eq!(
            params.credential_scope,
            "20130524/us-east-1/s3/aws4_request"
        );
        assert_eq!(params.signature, "deadbeef");
        assert_eq!(params.payload_hash, "UNSIGNED-PAYLOAD");
        assert!(params.is_presigned);
    }

    #[test]
    fn parse_presigned_rejects_missing_credential() {
        let query = PRESIGNED_QUERY_NO_CREDENTIAL;
        let err = parse_presigned(query).unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[test]
    fn parse_presigned_rejects_missing_signed_headers() {
        let query = PRESIGNED_QUERY_NO_SIGNED_HEADERS;
        let err = parse_presigned(query).unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[test]
    fn parse_presigned_rejects_missing_signature() {
        let query = PRESIGNED_QUERY_NO_SIGNATURE;
        let err = parse_presigned(query).unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[test]
    fn parse_presigned_rejects_missing_date() {
        let query = PRESIGNED_QUERY_NO_DATE;
        let err = parse_presigned(query).unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[test]
    fn parse_presigned_rejects_empty_access_key() {
        let query = PRESIGNED_QUERY_EMPTY_KEY;
        let err = parse_presigned(query).unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[test]
    fn parse_presigned_honors_payload_hash() {
        let query = PRESIGNED_QUERY_WITH_PAYLOAD_HASH;
        let params = parse_presigned(query).expect("params");
        assert_eq!(params.payload_hash, "custom");
    }

    #[test]
    fn parse_presigned_rejects_missing_fields() {
        let query = "X-Amz-Credential=missing";
        let err = parse_presigned(query).unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[test]
    fn parse_presigned_rejects_missing_algorithm() {
        let err = parse_presigned(PRESIGNED_QUERY_NO_ALGORITHM).unwrap_err();
        assert_eq!(err, S3Error::AccessDenied);
    }

    #[test]
    fn presign_url_includes_signature_and_host() {
        let url = presign_url(
            "GET",
            "http://example.amazonaws.com",
            "bucket",
            "key",
            "AKID",
            "secret",
            60,
            "us-east-1",
        )
        .expect("presign");
        let parsed = url::Url::parse(&url).expect("url parse");
        let query: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(parsed.path(), "/bucket/key");
        assert!(query.contains_key("X-Amz-Signature"));
        assert_eq!(
            query.get("X-Amz-SignedHeaders").map(String::as_str),
            Some("host")
        );
    }

    #[test]
    fn presign_url_bucket_only_uses_bucket_path() {
        let url = presign_url(
            "PUT",
            "http://example.amazonaws.com",
            "bucket",
            "",
            "AKID",
            "secret",
            60,
            "us-east-1",
        )
        .expect("presign");
        let parsed = url::Url::parse(&url).expect("url parse");
        assert_eq!(parsed.path(), "/bucket");
    }

    #[test]
    fn presign_url_supports_ports() {
        let url = presign_url(
            "PUT",
            "http://example.amazonaws.com:9000",
            "bucket",
            "key",
            "AKID",
            "secret",
            60,
            "us-east-1",
        )
        .expect("presign");
        let parsed = url::Url::parse(&url).expect("url parse");
        assert_eq!(parsed.port(), Some(9000));
    }

    #[test]
    fn presign_url_rejects_invalid_endpoint() {
        let err = presign_url(
            "GET",
            "http://[",
            "bucket",
            "key",
            "AKID",
            "secret",
            60,
            "us-east-1",
        )
        .unwrap_err();
        assert_eq!(err, "invalid endpoint");
    }

    #[test]
    fn presign_url_rejects_hostless_endpoint() {
        let err = presign_url(
            "GET",
            "file:///tmp/nss",
            "bucket",
            "key",
            "AKID",
            "secret",
            60,
            "us-east-1",
        )
        .unwrap_err();
        assert_eq!(err, "invalid endpoint");
    }

    #[test]
    fn presign_url_rejects_empty_region() {
        let err = presign_url(
            "GET",
            "http://example.amazonaws.com",
            "bucket",
            "key",
            "AKID",
            "secret",
            60,
            "",
        )
        .unwrap_err();
        assert_eq!(err, "signature failed");
    }

    #[test]
    fn parse_auth_params_handles_pairs() {
        let params = parse_auth_params("Key=Value, Invalid, Another=More");
        assert_eq!(params.get("Key").map(String::as_str), Some("Value"));
        assert_eq!(params.get("Another").map(String::as_str), Some("More"));
        assert!(!params.contains_key("Invalid"));
    }

    #[test]
    fn parse_auth_params_skips_empty_key_or_value() {
        let params = parse_auth_params("=Missing, Empty=, Key=Value");
        assert_eq!(params.get("Key").map(String::as_str), Some("Value"));
        assert_eq!(params.contains_key(""), false);
        assert_eq!(params.contains_key("Empty"), false);
    }
}
