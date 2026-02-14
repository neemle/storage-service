use chrono::Utc;
use lapin::{
    options::BasicPublishOptions, options::ExchangeDeclareOptions, types::FieldTable,
    BasicProperties, Channel, Connection, ConnectionProperties, ExchangeKind,
};
use serde::Serialize;
use std::future::Future;
#[cfg(test)]
use std::io;
#[cfg(test)]
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(test)]
static EVENT_FAILPOINT: AtomicU8 = AtomicU8::new(0);

#[cfg(test)]
fn event_failpoint(step: u8) -> bool {
    if EVENT_FAILPOINT.load(Ordering::SeqCst) == step {
        EVENT_FAILPOINT.store(0, Ordering::SeqCst);
        true
    } else {
        false
    }
}

#[cfg(test)]
pub fn set_event_failpoint(step: u8) {
    EVENT_FAILPOINT.store(step, Ordering::SeqCst);
}

#[cfg(test)]
pub fn clear_event_failpoint() {
    EVENT_FAILPOINT.store(0, Ordering::SeqCst);
}

#[cfg(test)]
pub struct EventFailpointGuard;

#[cfg(test)]
impl Drop for EventFailpointGuard {
    fn drop(&mut self) {
        clear_event_failpoint();
    }
}

#[cfg(test)]
pub fn event_failpoint_guard(step: u8) -> EventFailpointGuard {
    set_event_failpoint(step);
    EventFailpointGuard
}

#[derive(Clone)]
pub struct EventPublisher {
    channel: Option<Arc<Mutex<Channel>>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct S3EventRecord<'a> {
    event_name: &'a str,
    event_time: String,
    s3: S3Entity<'a>,
}

#[derive(Debug, Serialize)]
struct S3Entity<'a> {
    bucket: S3Bucket<'a>,
    object: S3Object<'a>,
}

#[derive(Debug, Serialize)]
struct S3Bucket<'a> {
    name: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct S3Object<'a> {
    key: &'a str,
    size: i64,
    e_tag: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_id: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct S3Event<'a> {
    #[serde(rename = "Records")]
    records: Vec<S3EventRecord<'a>>,
}

fn rabbit_connection_properties() -> ConnectionProperties {
    ConnectionProperties::default()
}

#[cfg(test)]
fn failpoint_error() -> lapin::Error {
    lapin::Error::from(io::Error::new(io::ErrorKind::Other, "failpoint"))
}

async fn connect_rabbit(url: &str) -> Result<Connection, String> {
    Connection::connect(url, rabbit_connection_properties())
        .await
        .map_err(|err| format!("rabbit connect failed: {err}"))
}

async fn create_channel(conn: &Connection) -> Result<Channel, String> {
    create_channel_with_failpoint(conn)
        .await
        .map_err(|err| format!("rabbit channel failed: {err}"))
}

async fn create_channel_with_failpoint(conn: &Connection) -> Result<Channel, lapin::Error> {
    #[cfg(test)]
    {
        if event_failpoint(1) {
            return Err(failpoint_error());
        }
    }
    conn.create_channel().await
}

async fn declare_exchange(channel: &Channel) -> Result<(), String> {
    declare_exchange_with_failpoint(channel)
        .await
        .map_err(|err| format!("rabbit exchange failed: {err}"))
}

async fn declare_exchange_with_failpoint(channel: &Channel) -> Result<(), lapin::Error> {
    #[cfg(test)]
    {
        if event_failpoint(2) {
            return Err(failpoint_error());
        }
    }
    channel
        .exchange_declare(
            "nss.events".into(),
            ExchangeKind::Topic,
            ExchangeDeclareOptions::default(),
            FieldTable::default(),
        )
        .await
}

#[derive(Debug)]
enum PublishError {
    Publish(lapin::Error),
    Confirm(lapin::Error),
}

fn maybe_fail_publish() -> Result<(), PublishError> {
    #[cfg(test)]
    if event_failpoint(4) {
        return Err(PublishError::Publish(failpoint_error()));
    }
    Ok(())
}

async fn wait_publish_confirm<F>(confirm: F) -> Result<(), PublishError>
where
    F: Future<Output = Result<lapin::Confirmation, lapin::Error>>,
{
    #[cfg(test)]
    if event_failpoint(5) {
        return Err(PublishError::Confirm(failpoint_error()));
    }
    #[cfg(test)]
    if event_failpoint(6) {
        return map_publish_confirm_result(Err(failpoint_error()));
    }
    map_publish_confirm_result(confirm.await)
}

fn map_publish_confirm_result(
    result: Result<lapin::Confirmation, lapin::Error>,
) -> Result<(), PublishError> {
    result.map(|_| ()).map_err(PublishError::Confirm)
}

fn build_event<'a>(
    event_name: &'a str,
    bucket: &'a str,
    key: &'a str,
    size: i64,
    etag: &'a str,
    version_id: Option<&'a str>,
) -> S3Event<'a> {
    S3Event {
        records: vec![S3EventRecord {
            event_name,
            event_time: Utc::now().to_rfc3339(),
            s3: S3Entity {
                bucket: S3Bucket { name: bucket },
                object: S3Object {
                    key,
                    size,
                    e_tag: etag,
                    version_id,
                },
            },
        }],
    }
}

fn serialize_event(event: &S3Event<'_>) -> Result<Vec<u8>, String> {
    serialize_event_payload(event).map_err(|err| format!("event serialize failed: {err}"))
}

fn serialize_event_payload(event: &S3Event<'_>) -> Result<Vec<u8>, serde_json::Error> {
    #[cfg(test)]
    if event_failpoint(3) {
        let err = std::io::Error::new(std::io::ErrorKind::Other, "failpoint");
        return Err(serde_json::Error::io(err));
    }
    serde_json::to_vec(event)
}

async fn publish_message(
    channel: &Channel,
    routing_key: &str,
    payload: &[u8],
) -> Result<(), String> {
    match publish_with_failpoint(channel, routing_key, payload).await {
        Ok(()) => Ok(()),
        Err(PublishError::Publish(err)) => Err(format!("event publish failed: {err}")),
        Err(PublishError::Confirm(err)) => Err(format!("event confirm failed: {err}")),
    }
}

async fn publish_with_failpoint(
    channel: &Channel,
    routing_key: &str,
    payload: &[u8],
) -> Result<(), PublishError> {
    maybe_fail_publish()?;
    let confirm = channel
        .basic_publish(
            "nss.events".into(),
            routing_key.into(),
            BasicPublishOptions::default(),
            payload,
            BasicProperties::default(),
        )
        .await
        .map_err(PublishError::Publish)?;
    wait_publish_confirm(confirm).await
}

impl EventPublisher {
    pub async fn new(rabbit_url: Option<&str>) -> Result<Self, String> {
        let Some(url) = rabbit_url else {
            return Ok(Self { channel: None });
        };

        let conn = connect_rabbit(url).await?;
        let channel = create_channel(&conn).await?;
        declare_exchange(&channel).await?;
        Ok(Self {
            channel: Some(Arc::new(Mutex::new(channel))),
        })
    }

    pub fn enabled(&self) -> bool {
        self.channel.is_some()
    }

    pub async fn publish_object_created(
        &self,
        bucket: &str,
        key: &str,
        size: i64,
        etag: &str,
        version_id: Option<&str>,
    ) -> Result<(), String> {
        self.publish_event(
            "s3.object.created",
            "ObjectCreated",
            bucket,
            key,
            size,
            etag,
            version_id,
        )
        .await
    }

    pub async fn publish_object_removed(
        &self,
        bucket: &str,
        key: &str,
        size: i64,
        etag: &str,
        version_id: Option<&str>,
    ) -> Result<(), String> {
        self.publish_event(
            "s3.object.removed",
            "ObjectRemoved",
            bucket,
            key,
            size,
            etag,
            version_id,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn publish_event(
        &self,
        routing_key: &str,
        event_name: &str,
        bucket: &str,
        key: &str,
        size: i64,
        etag: &str,
        version_id: Option<&str>,
    ) -> Result<(), String> {
        let Some(channel) = &self.channel else {
            return Ok(());
        };
        let event = build_event(event_name, bucket, key, size, etag, version_id);
        let payload = serialize_event(&event)?;
        let channel = channel.lock().await;
        publish_message(&channel, routing_key, &payload).await
    }
}

#[cfg(test)]
mod tests {
    use super::{event_failpoint_guard, EventPublisher};
    use std::env;
    use std::io;
    use std::sync::Mutex;

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

    fn rabbit_url() -> String {
        std::env::var("NSS_RABBIT_URL").unwrap_or_else(|_| "amqp://rabbitmq:5672/%2f".to_string())
    }

    async fn new_with_failpoint(url: &str, step: u8) -> String {
        let _guard = event_failpoint_guard(step);
        EventPublisher::new(Some(url))
            .await
            .err()
            .expect("expected error")
    }

    async fn publish_with_failpoint(publisher: &EventPublisher, step: u8) -> String {
        let _guard = event_failpoint_guard(step);
        publisher
            .publish_object_created("bucket", "key", 10, "etag", None)
            .await
            .err()
            .expect("expected error")
    }

    #[tokio::test]
    async fn disabled_publisher_noops() {
        let publisher = EventPublisher::new(None).await.expect("publisher");
        assert!(!publisher.enabled());
        publisher
            .publish_object_created("bucket", "key", 10, "etag", None)
            .await
            .expect("publish");
        publisher
            .publish_object_removed("bucket", "key", 10, "etag", Some("v1"))
            .await
            .expect("publish");
    }

    #[tokio::test]
    async fn invalid_rabbit_url_errors() {
        let result = EventPublisher::new(Some("amqp://127.0.0.1:1")).await;
        let err = result.err().expect("err");
        assert!(err.contains("rabbit connect failed"));
    }

    #[tokio::test]
    async fn publisher_sends_message_when_enabled() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        guard.remove("NSS_RABBIT_URL");
        let url = rabbit_url();
        let publisher = EventPublisher::new(Some(url.as_str()))
            .await
            .expect("publisher");
        assert!(publisher.enabled());
        let result = publisher
            .publish_object_created("bucket", "key", 10, "etag", None)
            .await;
        result.expect("publish");
    }

    #[tokio::test]
    async fn publisher_failpoints_cover_error_paths() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        guard.remove("NSS_RABBIT_URL");
        let url = rabbit_url();

        let err = new_with_failpoint(url.as_str(), 1).await;
        assert!(err.contains("rabbit channel failed"));

        let err = new_with_failpoint(url.as_str(), 2).await;
        assert!(err.contains("rabbit exchange failed"));

        let publisher = EventPublisher::new(Some(url.as_str()))
            .await
            .expect("publisher");
        let err = publish_with_failpoint(&publisher, 3).await;
        assert!(err.contains("event serialize failed"));

        let err = publish_with_failpoint(&publisher, 4).await;
        assert!(err.contains("event publish failed"));

        let err = publish_with_failpoint(&publisher, 5).await;
        assert!(err.contains("event confirm failed"));
        let err = publish_with_failpoint(&publisher, 6).await;
        assert!(err.contains("event confirm failed"));
    }

    #[tokio::test]
    async fn publisher_sends_removed_event_when_enabled() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        guard.remove("NSS_RABBIT_URL");
        let url = rabbit_url();
        let publisher = EventPublisher::new(Some(url.as_str()))
            .await
            .expect("publisher");
        let result = publisher
            .publish_object_removed("bucket", "key", 10, "etag", Some("v1"))
            .await;
        result.expect("publish");
    }

    #[test]
    fn env_guard_removes_missing_var_on_drop() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let key = "NSS_TEST_RABBIT_ENV";
        env::remove_var(key);
        {
            let mut guard = EnvGuard::new();
            guard.remove(key);
        }
        assert!(env::var(key).is_err());
    }

    #[test]
    fn event_failpoint_consumes_step() {
        super::set_event_failpoint(9);
        assert!(super::event_failpoint(9));
        assert!(!super::event_failpoint(9));
    }

    #[tokio::test]
    async fn wait_publish_confirm_maps_future_errors() {
        let result = super::wait_publish_confirm(async {
            Err(lapin::Error::from(io::Error::other("confirm-failed")))
        })
        .await
        .expect_err("confirm error");
        assert!(format!("{result:?}").starts_with("Confirm("));
    }

    #[tokio::test]
    async fn wait_publish_confirm_accepts_successful_confirmation() {
        let result =
            super::wait_publish_confirm(async { Ok(lapin::Confirmation::NotRequested) }).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn publish_with_failpoint_maps_publish_error_from_closed_channel() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        guard.remove("NSS_RABBIT_URL");
        let url = rabbit_url();
        let publisher = EventPublisher::new(Some(url.as_str()))
            .await
            .expect("publisher");
        let channel_lock = publisher.channel.as_ref().expect("channel");
        {
            let channel = channel_lock.lock().await;
            channel.close(200, "closing".into()).await.expect("close");
        }
        let channel = channel_lock.lock().await;
        let result = super::publish_with_failpoint(&channel, "s3.object.created", b"payload")
            .await
            .expect_err("publish error");
        assert!(format!("{result:?}").starts_with("Publish("));
    }

    #[tokio::test]
    async fn publish_with_failpoint_accepts_open_channel() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        guard.remove("NSS_RABBIT_URL");
        let url = rabbit_url();
        let publisher = EventPublisher::new(Some(url.as_str()))
            .await
            .expect("publisher");
        let channel_lock = publisher.channel.as_ref().expect("channel");
        let channel = channel_lock.lock().await;
        let result = super::publish_with_failpoint(&channel, "s3.object.created", b"payload").await;
        assert!(result.is_ok());
    }
}
