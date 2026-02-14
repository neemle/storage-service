use crate::meta::models::{Bucket, MultipartPart, MultipartUpload, ObjectVersion};
use chrono::{DateTime, SecondsFormat, Utc};
use quick_xml::de::from_str;
use serde::Deserialize;

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn list_buckets(owner_name: &str, buckets: &[Bucket]) -> String {
    let mut body = String::new();
    body.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    body.push_str("<ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    body.push_str("<Owner><DisplayName>");
    body.push_str(&xml_escape(owner_name));
    body.push_str("</DisplayName></Owner>");
    body.push_str("<Buckets>");
    for bucket in buckets {
        body.push_str("<Bucket><Name>");
        body.push_str(&xml_escape(&bucket.name));
        body.push_str("</Name><CreationDate>");
        body.push_str(&s3_timestamp(bucket.created_at));
        body.push_str("</CreationDate></Bucket>");
    }
    body.push_str("</Buckets></ListAllMyBucketsResult>");
    body
}

pub fn bucket_location(location: &str) -> String {
    format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
            "{}",
            "</LocationConstraint>"
        ),
        xml_escape(location)
    )
}

pub fn list_objects(bucket: &str, objects: &[ObjectVersion]) -> String {
    let mut body = String::new();
    body.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    body.push_str("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    body.push_str("<Name>");
    body.push_str(&xml_escape(bucket));
    body.push_str("</Name>");
    for obj in objects {
        body.push_str("<Contents>");
        body.push_str("<Key>");
        body.push_str(&xml_escape(&obj.object_key));
        body.push_str("</Key>");
        body.push_str("<LastModified>");
        body.push_str(&s3_timestamp(obj.created_at));
        body.push_str("</LastModified>");
        body.push_str("<ETag>");
        let etag = obj.etag.as_deref().unwrap_or("");
        body.push_str(&xml_escape(&format!("\"{}\"", etag)));
        body.push_str("</ETag>");
        body.push_str("<Size>");
        body.push_str(&obj.size_bytes.to_string());
        body.push_str("</Size>");
        body.push_str("</Contents>");
    }
    body.push_str("</ListBucketResult>");
    body
}

#[allow(clippy::too_many_arguments)]
pub fn list_objects_v2(
    bucket: &str,
    prefix: Option<&str>,
    delimiter: Option<&str>,
    objects: &[ObjectVersion],
    common_prefixes: &[String],
    max_keys: i64,
    is_truncated: bool,
    next_token: Option<&str>,
) -> String {
    build_list_objects_v2(ListObjectsV2Args {
        bucket,
        prefix,
        delimiter,
        objects,
        common_prefixes,
        max_keys,
        is_truncated,
        next_token,
    })
}

struct ListObjectsV2Args<'a> {
    bucket: &'a str,
    prefix: Option<&'a str>,
    delimiter: Option<&'a str>,
    objects: &'a [ObjectVersion],
    common_prefixes: &'a [String],
    max_keys: i64,
    is_truncated: bool,
    next_token: Option<&'a str>,
}

fn build_list_objects_v2(args: ListObjectsV2Args<'_>) -> String {
    let mut body = String::new();
    append_list_objects_v2_header(
        &mut body,
        args.bucket,
        args.prefix,
        args.delimiter,
        args.objects,
        args.common_prefixes,
        args.max_keys,
        args.is_truncated,
        args.next_token,
    );
    for obj in args.objects {
        append_object_contents(&mut body, obj);
    }
    for prefix_val in args.common_prefixes {
        append_common_prefix(&mut body, prefix_val);
    }
    body.push_str("</ListBucketResult>");
    body
}

pub fn initiate_multipart_upload(bucket: &str, key: &str, upload_id: &str) -> String {
    format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
            "<Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId>",
            "</InitiateMultipartUploadResult>"
        ),
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(upload_id)
    )
}

pub fn list_multipart_uploads(bucket: &str, uploads: &[MultipartUpload]) -> String {
    let mut body = String::new();
    body.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    body.push_str("<ListMultipartUploadsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    body.push_str("<Bucket>");
    body.push_str(&xml_escape(bucket));
    body.push_str("</Bucket>");
    for upload in uploads {
        body.push_str("<Upload>");
        body.push_str("<Key>");
        body.push_str(&xml_escape(&upload.object_key));
        body.push_str("</Key>");
        body.push_str("<UploadId>");
        body.push_str(&xml_escape(&upload.upload_id));
        body.push_str("</UploadId>");
        body.push_str("<Initiated>");
        body.push_str(&s3_timestamp(upload.initiated_at));
        body.push_str("</Initiated>");
        body.push_str("</Upload>");
    }
    body.push_str("</ListMultipartUploadsResult>");
    body
}

pub fn list_parts(bucket: &str, key: &str, upload_id: &str, parts: &[MultipartPart]) -> String {
    let mut body = String::new();
    body.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    body.push_str("<ListPartsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    body.push_str("<Bucket>");
    body.push_str(&xml_escape(bucket));
    body.push_str("</Bucket>");
    body.push_str("<Key>");
    body.push_str(&xml_escape(key));
    body.push_str("</Key>");
    body.push_str("<UploadId>");
    body.push_str(&xml_escape(upload_id));
    body.push_str("</UploadId>");
    for part in parts {
        body.push_str("<Part>");
        body.push_str("<PartNumber>");
        body.push_str(&part.part_number.to_string());
        body.push_str("</PartNumber>");
        body.push_str("<ETag>");
        body.push_str(&xml_escape(&format!("\"{}\"", part.etag)));
        body.push_str("</ETag>");
        body.push_str("<Size>");
        body.push_str(&part.size_bytes.to_string());
        body.push_str("</Size>");
        body.push_str("</Part>");
    }
    body.push_str("</ListPartsResult>");
    body
}

fn s3_timestamp(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn complete_multipart_upload(bucket: &str, key: &str, etag: &str) -> String {
    format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
            "<Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag>",
            "</CompleteMultipartUploadResult>"
        ),
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(&format!("\"{}\"", etag))
    )
}

pub fn bucket_versioning(status: &str) -> String {
    if status == "off" {
        return concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
            "</VersioningConfiguration>"
        )
        .to_string();
    }
    let value = if status == "enabled" {
        "Enabled"
    } else {
        "Suspended"
    };
    format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
            "<Status>{}</Status></VersioningConfiguration>"
        ),
        value
    )
}

#[allow(clippy::too_many_arguments)]
pub fn list_object_versions(
    bucket: &str,
    prefix: Option<&str>,
    key_marker: Option<&str>,
    version_id_marker: Option<&str>,
    max_keys: i64,
    is_truncated: bool,
    next_key_marker: Option<&str>,
    next_version_id_marker: Option<&str>,
    versions: &[ObjectVersion],
) -> String {
    let mut body = String::new();
    append_list_object_versions_header(
        &mut body,
        bucket,
        prefix,
        key_marker,
        version_id_marker,
        max_keys,
        is_truncated,
        next_key_marker,
        next_version_id_marker,
    );
    for version in versions {
        append_version_entry(&mut body, version);
    }
    body.push_str("</ListVersionsResult>");
    body
}

#[allow(clippy::too_many_arguments)]
fn append_list_objects_v2_header(
    body: &mut String,
    bucket: &str,
    prefix: Option<&str>,
    delimiter: Option<&str>,
    objects: &[ObjectVersion],
    common_prefixes: &[String],
    max_keys: i64,
    is_truncated: bool,
    next_token: Option<&str>,
) {
    body.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    body.push_str("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    body.push_str("<Name>");
    body.push_str(&xml_escape(bucket));
    body.push_str("</Name>");
    push_xml_optional(body, "Prefix", prefix);
    push_xml_optional(body, "Delimiter", delimiter);
    push_xml_number(
        body,
        "KeyCount",
        (objects.len() + common_prefixes.len()) as i64,
    );
    push_xml_number(body, "MaxKeys", max_keys);
    push_xml_bool(body, "IsTruncated", is_truncated);
    push_xml_optional(body, "NextContinuationToken", next_token);
}

#[allow(clippy::too_many_arguments)]
fn append_list_object_versions_header(
    body: &mut String,
    bucket: &str,
    prefix: Option<&str>,
    key_marker: Option<&str>,
    version_id_marker: Option<&str>,
    max_keys: i64,
    is_truncated: bool,
    next_key_marker: Option<&str>,
    next_version_id_marker: Option<&str>,
) {
    body.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    body.push_str("<ListVersionsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    push_xml_field(body, "Name", bucket);
    push_xml_optional(body, "Prefix", prefix);
    push_xml_optional(body, "KeyMarker", key_marker);
    push_xml_optional(body, "VersionIdMarker", version_id_marker);
    push_xml_number(body, "MaxKeys", max_keys);
    push_xml_bool(body, "IsTruncated", is_truncated);
    push_xml_optional(body, "NextKeyMarker", next_key_marker);
    push_xml_optional(body, "NextVersionIdMarker", next_version_id_marker);
}

fn append_object_contents(body: &mut String, obj: &ObjectVersion) {
    body.push_str("<Contents>");
    push_xml_field(body, "Key", &obj.object_key);
    push_xml_field(body, "LastModified", &s3_timestamp(obj.created_at));
    push_xml_field(
        body,
        "ETag",
        &format!("\"{}\"", obj.etag.as_deref().unwrap_or("")),
    );
    push_xml_field(body, "Size", &obj.size_bytes.to_string());
    body.push_str("</Contents>");
}

fn append_common_prefix(body: &mut String, prefix: &str) {
    body.push_str("<CommonPrefixes>");
    push_xml_field(body, "Prefix", prefix);
    body.push_str("</CommonPrefixes>");
}

fn append_version_entry(body: &mut String, version: &ObjectVersion) {
    body.push_str(if version.is_delete_marker {
        "<DeleteMarker>"
    } else {
        "<Version>"
    });
    push_xml_field(body, "Key", &version.object_key);
    push_xml_field(body, "VersionId", &version.version_id);
    push_xml_bool(body, "IsLatest", version.current);
    push_xml_field(body, "LastModified", &s3_timestamp(version.created_at));
    if version.is_delete_marker {
        body.push_str("</DeleteMarker>");
        return;
    }
    push_xml_field(
        body,
        "ETag",
        &format!("\"{}\"", version.etag.as_deref().unwrap_or("")),
    );
    push_xml_field(body, "Size", &version.size_bytes.to_string());
    body.push_str("</Version>");
}

fn push_xml_field(body: &mut String, tag: &str, value: &str) {
    body.push_str(&format!("<{}>{}</{}>", tag, xml_escape(value), tag));
}

fn push_xml_optional(body: &mut String, tag: &str, value: Option<&str>) {
    if let Some(value) = value {
        push_xml_field(body, tag, value);
    }
}

fn push_xml_number(body: &mut String, tag: &str, value: i64) {
    body.push_str(&format!("<{}>{}</{}>", tag, value, tag));
}

fn push_xml_bool(body: &mut String, tag: &str, value: bool) {
    body.push_str(&format!(
        "<{}>{}</{}>",
        tag,
        if value { "true" } else { "false" },
        tag
    ));
}

#[derive(Debug, Deserialize)]
#[serde(rename = "VersioningConfiguration")]
struct VersioningConfigurationRequest {
    #[serde(rename = "Status")]
    status: Option<String>,
}

pub fn parse_versioning_status(body: &[u8]) -> Result<String, String> {
    let parsed: VersioningConfigurationRequest =
        from_str(&String::from_utf8_lossy(body)).map_err(|_| "invalid xml")?;
    let status = parsed.status.ok_or_else(|| "missing status".to_string())?;
    match status.as_str() {
        "Enabled" => Ok("enabled".to_string()),
        "Suspended" => Ok("suspended".to_string()),
        _ => Err("invalid status".to_string()),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Delete")]
struct DeleteObjectsRequest {
    #[serde(rename = "Object")]
    objects: Vec<DeleteObject>,
}

#[derive(Debug, Deserialize)]
struct DeleteObject {
    #[serde(rename = "Key")]
    key: String,
}

pub fn parse_delete_objects(body: &[u8]) -> Result<Vec<String>, String> {
    let parsed: DeleteObjectsRequest =
        from_str(&String::from_utf8_lossy(body)).map_err(|_| "invalid xml")?;
    Ok(parsed.objects.into_iter().map(|obj| obj.key).collect())
}

pub fn delete_objects_result() -> String {
    concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
        "</DeleteResult>"
    )
    .to_string()
}

#[derive(Debug, Deserialize)]
#[serde(rename = "CompleteMultipartUpload")]
struct CompleteMultipartRequest {
    #[serde(rename = "Part")]
    parts: Vec<CompletePart>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CompletePart {
    #[serde(rename = "PartNumber")]
    pub part_number: i32,
    #[serde(rename = "ETag")]
    pub etag: String,
}

pub fn parse_complete_parts(body: &[u8]) -> Result<Vec<CompletePart>, String> {
    let parsed: CompleteMultipartRequest =
        from_str(&String::from_utf8_lossy(body)).map_err(|_| "invalid xml")?;
    Ok(parsed
        .parts
        .into_iter()
        .map(|mut part| {
            part.etag = part.etag.trim_matches('\"').to_string();
            part
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::models::{Bucket, MultipartPart, MultipartUpload, ObjectVersion};
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;

    fn sample_bucket(name: &str) -> Bucket {
        Bucket {
            id: Uuid::new_v4(),
            name: name.to_string(),
            owner_user_id: Uuid::new_v4(),
            created_at: Utc::now(),
            versioning_status: "off".to_string(),
            public_read: false,
            is_worm: false,
            lifecycle_config_xml: None,
            cors_config_xml: None,
            website_config_xml: None,
            notification_config_xml: None,
        }
    }

    fn sample_object(key: &str, delete_marker: bool) -> ObjectVersion {
        ObjectVersion {
            id: Uuid::new_v4(),
            bucket_id: Uuid::new_v4(),
            object_key: key.to_string(),
            version_id: "v1".to_string(),
            is_delete_marker: delete_marker,
            size_bytes: 12,
            etag: Some("etag".to_string()),
            content_type: None,
            metadata_json: json!({}),
            tags_json: json!({}),
            created_at: Utc::now(),
            current: true,
        }
    }

    #[test]
    fn list_buckets_escapes_values() {
        let bucket = sample_bucket("a&b");
        let body = list_buckets("me<you>", &[bucket]);
        assert!(body.contains("me&lt;you&gt;"));
        assert!(body.contains("a&amp;b"));
    }

    #[test]
    fn list_objects_v2_includes_optional_fields() {
        let objects = vec![sample_object("key-1", false)];
        let body = list_objects_v2(
            "bucket",
            Some("pre/"),
            Some("/"),
            &objects,
            &["pre/child/".to_string()],
            100,
            true,
            Some("token"),
        );
        assert!(body.contains("<Prefix>pre/</Prefix>"));
        assert!(body.contains("<Delimiter>/</Delimiter>"));
        assert!(body.contains("<NextContinuationToken>token</NextContinuationToken>"));
        assert!(body.contains("<CommonPrefixes>"));
    }

    #[test]
    fn list_objects_v2_omits_optional_fields() {
        let objects = vec![sample_object("key-2", false)];
        let body = list_objects_v2("bucket", None, None, &objects, &[], 1, false, None);
        assert!(!body.contains("<Prefix>"));
        assert!(!body.contains("<Delimiter>"));
        assert!(!body.contains("<NextContinuationToken>"));
    }

    #[test]
    fn bucket_location_and_list_objects_emit_xml() {
        let location = bucket_location("us&west");
        assert!(location.contains("us&amp;west"));

        let objects = vec![sample_object("photo.jpg", false)];
        let body = list_objects("bucket", &objects);
        assert!(body.contains("<Key>photo.jpg</Key>"));
        assert!(body.contains("<ETag>&quot;etag&quot;</ETag>"));
    }

    #[test]
    fn list_object_versions_includes_delete_marker_and_version() {
        let versions = vec![sample_object("keep", false), sample_object("gone", true)];
        let body = list_object_versions(
            "bucket",
            Some("pref"),
            Some("key-marker"),
            Some("ver-marker"),
            10,
            false,
            Some("next-key"),
            Some("next-version"),
            &versions,
        );
        assert!(body.contains("<DeleteMarker>"));
        assert!(body.contains("<Version>"));
        assert!(body.contains("<KeyMarker>key-marker</KeyMarker>"));
        assert!(body.contains("<VersionIdMarker>ver-marker</VersionIdMarker>"));
        assert!(body.contains("<NextKeyMarker>next-key</NextKeyMarker>"));
        assert!(body.contains("<NextVersionIdMarker>next-version</NextVersionIdMarker>"));
    }

    #[test]
    fn list_object_versions_handles_truncated_and_non_current() {
        let mut version = sample_object("older", false);
        version.current = false;
        let body =
            list_object_versions("bucket", None, None, None, 1, true, None, None, &[version]);
        assert!(body.contains("<IsTruncated>true</IsTruncated>"));
        assert!(body.contains("<IsLatest>false</IsLatest>"));
        assert!(!body.contains("<Prefix>"));
        assert!(!body.contains("<KeyMarker>"));
        assert!(!body.contains("<VersionIdMarker>"));
        assert!(!body.contains("<NextKeyMarker>"));
        assert!(!body.contains("<NextVersionIdMarker>"));
    }

    #[test]
    fn bucket_versioning_formats_states() {
        let off = bucket_versioning("off");
        assert!(off.contains("VersioningConfiguration"));
        let enabled = bucket_versioning("enabled");
        assert!(enabled.contains("<Status>Enabled</Status>"));
        let suspended = bucket_versioning("suspended");
        assert!(suspended.contains("<Status>Suspended</Status>"));
    }

    #[test]
    fn multipart_and_delete_helpers_emit_xml() {
        let init = initiate_multipart_upload("b", "k", "upload");
        assert!(init.contains("<UploadId>upload</UploadId>"));
        let complete = complete_multipart_upload("b", "k", "etag");
        assert!(complete.contains("&quot;etag&quot;"));
        let delete_xml = delete_objects_result();
        assert!(delete_xml.contains("<DeleteResult"));

        let uploads = vec![MultipartUpload {
            id: Uuid::new_v4(),
            bucket_id: Uuid::new_v4(),
            object_key: "file".to_string(),
            upload_id: "u1".to_string(),
            initiated_at: Utc::now(),
            status: "active".to_string(),
        }];
        let uploads_xml = list_multipart_uploads("bucket", &uploads);
        assert!(uploads_xml.contains("<UploadId>u1</UploadId>"));

        let parts = vec![MultipartPart {
            upload_id: "u1".to_string(),
            part_number: 1,
            size_bytes: 10,
            etag: "etag".to_string(),
            manifest_id: Uuid::new_v4(),
        }];
        let parts_xml = list_parts("bucket", "key", "u1", &parts);
        assert!(parts_xml.contains("<PartNumber>1</PartNumber>"));
    }

    #[test]
    fn parse_versioning_status_variants() {
        let enabled = parse_versioning_status(
            b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
        )
        .expect("enabled");
        assert_eq!(enabled, "enabled");

        let suspended = parse_versioning_status(
            b"<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>",
        )
        .expect("suspended");
        assert_eq!(suspended, "suspended");

        let err = parse_versioning_status(b"<VersioningConfiguration></VersioningConfiguration>")
            .unwrap_err();
        assert_eq!(err, "missing status");

        let err = parse_versioning_status(
            b"<VersioningConfiguration><Status>Unknown</Status></VersioningConfiguration>",
        )
        .unwrap_err();
        assert_eq!(err, "invalid status");

        let err = parse_versioning_status(b"<bad>").unwrap_err();
        assert_eq!(err, "invalid xml");
    }

    #[test]
    fn parse_delete_objects_variants() {
        let xml = b"<Delete><Object><Key>a</Key></Object><Object><Key>b</Key></Object></Delete>";
        let keys = parse_delete_objects(xml).expect("keys");
        assert_eq!(keys, vec!["a".to_string(), "b".to_string()]);

        let err = parse_delete_objects(b"<Delete><Object></Delete>").unwrap_err();
        assert_eq!(err, "invalid xml");
    }

    #[test]
    fn parse_complete_parts_strips_quotes() {
        let xml = concat!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>",
            "<ETag>\"etag\"</ETag></Part></CompleteMultipartUpload>"
        )
        .as_bytes();
        let parts = parse_complete_parts(xml).expect("parts");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].part_number, 1);
        assert_eq!(parts[0].etag, "etag");

        let err = parse_complete_parts(b"<CompleteMultipartUpload>").unwrap_err();
        assert_eq!(err, "invalid xml");
    }
}
