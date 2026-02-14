use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3Error {
    AccessDenied,
    NoSuchBucket,
    NoSuchKey,
    BucketAlreadyExists,
    InvalidAccessKeyId,
    SignatureDoesNotMatch,
    RequestTimeTooSkewed,
    InvalidRequest,
    MethodNotAllowed,
    NotImplemented,
    TooManyRequests,
    InternalError,
    MalformedXML,
    NoSuchUpload,
    InvalidPart,
}

impl S3Error {
    pub fn code(&self) -> &'static str {
        match self {
            S3Error::AccessDenied => "AccessDenied",
            S3Error::NoSuchBucket => "NoSuchBucket",
            S3Error::NoSuchKey => "NoSuchKey",
            S3Error::BucketAlreadyExists => "BucketAlreadyExists",
            S3Error::InvalidAccessKeyId => "InvalidAccessKeyId",
            S3Error::SignatureDoesNotMatch => "SignatureDoesNotMatch",
            S3Error::RequestTimeTooSkewed => "RequestTimeTooSkewed",
            S3Error::InvalidRequest => "InvalidRequest",
            S3Error::MethodNotAllowed => "MethodNotAllowed",
            S3Error::NotImplemented => "NotImplemented",
            S3Error::TooManyRequests => "SlowDown",
            S3Error::InternalError => "InternalError",
            S3Error::MalformedXML => "MalformedXML",
            S3Error::NoSuchUpload => "NoSuchUpload",
            S3Error::InvalidPart => "InvalidPart",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            S3Error::AccessDenied => "Access Denied",
            S3Error::NoSuchBucket => "The specified bucket does not exist",
            S3Error::NoSuchKey => "The specified key does not exist",
            S3Error::BucketAlreadyExists => "Bucket already exists",
            S3Error::InvalidAccessKeyId => "The AWS access key Id you provided does not exist",
            S3Error::SignatureDoesNotMatch => {
                "The request signature we calculated does not match the signature you provided"
            }
            S3Error::RequestTimeTooSkewed => {
                "The difference between the request time and the server's time is too large"
            }
            S3Error::InvalidRequest => "Invalid Request",
            S3Error::MethodNotAllowed => "Method Not Allowed",
            S3Error::NotImplemented => "Not Implemented",
            S3Error::TooManyRequests => "Slow Down",
            S3Error::InternalError => "Internal Error",
            S3Error::MalformedXML => "The XML you provided was not well-formed",
            S3Error::NoSuchUpload => "The specified upload does not exist",
            S3Error::InvalidPart => "One or more of the specified parts could not be found",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            S3Error::AccessDenied => StatusCode::FORBIDDEN,
            S3Error::NoSuchBucket => StatusCode::NOT_FOUND,
            S3Error::NoSuchKey => StatusCode::NOT_FOUND,
            S3Error::BucketAlreadyExists => StatusCode::CONFLICT,
            S3Error::InvalidAccessKeyId => StatusCode::FORBIDDEN,
            S3Error::SignatureDoesNotMatch => StatusCode::FORBIDDEN,
            S3Error::RequestTimeTooSkewed => StatusCode::FORBIDDEN,
            S3Error::InvalidRequest => StatusCode::BAD_REQUEST,
            S3Error::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            S3Error::NotImplemented => StatusCode::NOT_IMPLEMENTED,
            S3Error::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            S3Error::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            S3Error::MalformedXML => StatusCode::BAD_REQUEST,
            S3Error::NoSuchUpload => StatusCode::NOT_FOUND,
            S3Error::InvalidPart => StatusCode::BAD_REQUEST,
        }
    }
}

pub fn s3_error(error: S3Error) -> Response {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{}</Code><Message>{}</Message></Error>",
        error.code(),
        error.message()
    );
    (error.status(), [("Content-Type", "application/xml")], body).into_response()
}

#[cfg(test)]
mod tests {
    use super::{s3_error, S3Error};
    use axum::body::to_bytes;
    use axum::http::StatusCode;

    const ERROR_CASES: &[(S3Error, &str, StatusCode)] = &[
        (S3Error::AccessDenied, "AccessDenied", StatusCode::FORBIDDEN),
        (S3Error::NoSuchBucket, "NoSuchBucket", StatusCode::NOT_FOUND),
        (S3Error::NoSuchKey, "NoSuchKey", StatusCode::NOT_FOUND),
        (
            S3Error::BucketAlreadyExists,
            "BucketAlreadyExists",
            StatusCode::CONFLICT,
        ),
        (
            S3Error::InvalidAccessKeyId,
            "InvalidAccessKeyId",
            StatusCode::FORBIDDEN,
        ),
        (
            S3Error::SignatureDoesNotMatch,
            "SignatureDoesNotMatch",
            StatusCode::FORBIDDEN,
        ),
        (
            S3Error::RequestTimeTooSkewed,
            "RequestTimeTooSkewed",
            StatusCode::FORBIDDEN,
        ),
        (
            S3Error::InvalidRequest,
            "InvalidRequest",
            StatusCode::BAD_REQUEST,
        ),
        (
            S3Error::MethodNotAllowed,
            "MethodNotAllowed",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            S3Error::NotImplemented,
            "NotImplemented",
            StatusCode::NOT_IMPLEMENTED,
        ),
        (
            S3Error::TooManyRequests,
            "SlowDown",
            StatusCode::TOO_MANY_REQUESTS,
        ),
        (
            S3Error::InternalError,
            "InternalError",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            S3Error::MalformedXML,
            "MalformedXML",
            StatusCode::BAD_REQUEST,
        ),
        (S3Error::NoSuchUpload, "NoSuchUpload", StatusCode::NOT_FOUND),
        (S3Error::InvalidPart, "InvalidPart", StatusCode::BAD_REQUEST),
    ];

    #[test]
    fn error_variants_map_to_codes_and_statuses() {
        for &(err, code, status) in ERROR_CASES {
            assert_eq!(err.code(), code);
            assert_eq!(err.status(), status);
            assert!(!err.message().is_empty());
        }
    }

    #[tokio::test]
    async fn s3_error_builds_xml_response() {
        let response = s3_error(S3Error::AccessDenied);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8(body.to_vec()).expect("utf8");
        assert!(text.contains("<Code>AccessDenied</Code>"));
        assert!(text.contains("<Message>Access Denied</Message>"));
    }
}
