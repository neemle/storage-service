use axum::extract::MatchedPath;
use axum::http::Request;
use futures_util::future::BoxFuture;
use prometheus::core::Collector;
use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts, Registry};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tower::{Layer, Service};

#[derive(Clone)]
pub struct Metrics {
    registry: Registry,
    pub http_requests: IntCounterVec,
    pub http_duration: HistogramVec,
    pub s3_requests: IntCounterVec,
    pub s3_bytes_in: IntCounterVec,
    pub s3_bytes_out: IntCounterVec,
    pub chunk_write: IntCounterVec,
    pub chunk_read: IntCounterVec,
    pub checksum_mismatch: IntCounterVec,
    pub repair_jobs: IntCounterVec,
    pub repair_backlog: IntGaugeVec,
    pub node_heartbeat_age: IntGaugeVec,
}

struct MetricVectors {
    http_requests: IntCounterVec,
    http_duration: HistogramVec,
    s3_requests: IntCounterVec,
    s3_bytes_in: IntCounterVec,
    s3_bytes_out: IntCounterVec,
    chunk_write: IntCounterVec,
    chunk_read: IntCounterVec,
    checksum_mismatch: IntCounterVec,
    repair_jobs: IntCounterVec,
    repair_backlog: IntGaugeVec,
    node_heartbeat_age: IntGaugeVec,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        let registry = Registry::new();
        let vectors = build_metric_vectors();
        register_metric_vectors(&registry, &vectors);
        Arc::new(Self {
            registry,
            http_requests: vectors.http_requests,
            http_duration: vectors.http_duration,
            s3_requests: vectors.s3_requests,
            s3_bytes_in: vectors.s3_bytes_in,
            s3_bytes_out: vectors.s3_bytes_out,
            chunk_write: vectors.chunk_write,
            chunk_read: vectors.chunk_read,
            checksum_mismatch: vectors.checksum_mismatch,
            repair_jobs: vectors.repair_jobs,
            repair_backlog: vectors.repair_backlog,
            node_heartbeat_age: vectors.node_heartbeat_age,
        })
    }

    pub fn gather(&self) -> Vec<prometheus::proto::MetricFamily> {
        self.registry.gather()
    }
}

fn build_metric_vectors() -> MetricVectors {
    let (http_requests, http_duration) = build_http_vectors();
    let (s3_requests, s3_bytes_in, s3_bytes_out) = build_s3_vectors();
    let (chunk_write, chunk_read, checksum_mismatch) = build_chunk_vectors();
    let (repair_jobs, repair_backlog, node_heartbeat_age) = build_repair_vectors();
    MetricVectors {
        http_requests,
        http_duration,
        s3_requests,
        s3_bytes_in,
        s3_bytes_out,
        chunk_write,
        chunk_read,
        checksum_mismatch,
        repair_jobs,
        repair_backlog,
        node_heartbeat_age,
    }
}

fn build_http_vectors() -> (IntCounterVec, HistogramVec) {
    let http_requests = IntCounterVec::new(
        Opts::new("nss_http_requests_total", "HTTP requests"),
        &["service", "route", "method", "status"],
    )
    .expect("http_requests");
    let http_duration = HistogramVec::new(
        HistogramOpts::new("nss_http_request_duration_seconds", "HTTP request duration"),
        &["service", "route", "method"],
    )
    .expect("http_duration");
    (http_requests, http_duration)
}

fn build_s3_vectors() -> (IntCounterVec, IntCounterVec, IntCounterVec) {
    let s3_requests = IntCounterVec::new(
        Opts::new("nss_s3_requests_total", "S3 requests"),
        &["op", "status"],
    )
    .expect("s3_requests");
    let s3_bytes_in =
        IntCounterVec::new(Opts::new("nss_s3_bytes_in_total", "S3 bytes in"), &["op"])
            .expect("s3_bytes_in");
    let s3_bytes_out =
        IntCounterVec::new(Opts::new("nss_s3_bytes_out_total", "S3 bytes out"), &["op"])
            .expect("s3_bytes_out");
    (s3_requests, s3_bytes_in, s3_bytes_out)
}

fn build_chunk_vectors() -> (IntCounterVec, IntCounterVec, IntCounterVec) {
    let chunk_write = IntCounterVec::new(
        Opts::new("nss_chunk_write_total", "Chunk writes"),
        &["result"],
    )
    .expect("chunk_write");
    let chunk_read = IntCounterVec::new(
        Opts::new("nss_chunk_read_total", "Chunk reads"),
        &["result"],
    )
    .expect("chunk_read");
    let checksum_mismatch = IntCounterVec::new(
        Opts::new("nss_checksum_mismatch_total", "Checksum mismatches"),
        &["node"],
    )
    .expect("checksum_mismatch");
    (chunk_write, chunk_read, checksum_mismatch)
}

fn build_repair_vectors() -> (IntCounterVec, IntGaugeVec, IntGaugeVec) {
    let repair_jobs = IntCounterVec::new(
        Opts::new("nss_repair_jobs_total", "Repair jobs"),
        &["result"],
    )
    .expect("repair_jobs");
    let repair_backlog = IntGaugeVec::new(
        Opts::new("nss_repair_backlog", "Repair backlog"),
        &["queue"],
    )
    .expect("repair_backlog");
    let node_heartbeat_age = IntGaugeVec::new(
        Opts::new("nss_node_heartbeat_age_seconds", "Node heartbeat age"),
        &["node_id"],
    )
    .expect("node_heartbeat_age");
    (repair_jobs, repair_backlog, node_heartbeat_age)
}

fn register_metric_vectors(registry: &Registry, vectors: &MetricVectors) {
    register_collector(registry, &vectors.http_requests);
    #[cfg(test)]
    {
        if std::env::var("NSS_TEST_METRICS_DUP").ok().as_deref() == Some("1") {
            register_collector(registry, &vectors.http_requests);
        }
    }
    register_collector(registry, &vectors.http_duration);
    register_collector(registry, &vectors.s3_requests);
    register_collector(registry, &vectors.s3_bytes_in);
    register_collector(registry, &vectors.s3_bytes_out);
    register_collector(registry, &vectors.chunk_write);
    register_collector(registry, &vectors.chunk_read);
    register_collector(registry, &vectors.checksum_mismatch);
    register_collector(registry, &vectors.repair_jobs);
    register_collector(registry, &vectors.repair_backlog);
    register_collector(registry, &vectors.node_heartbeat_age);
}

fn register_collector<C>(registry: &Registry, collector: &C)
where
    C: Collector + Clone + 'static,
{
    registry.register(Box::new(collector.clone())).ok();
}

#[derive(Clone)]
pub struct MetricsLayer {
    metrics: Arc<Metrics>,
    service: &'static str,
}

impl MetricsLayer {
    pub fn new(metrics: Arc<Metrics>, service: &'static str) -> Self {
        Self { metrics, service }
    }
}

impl<S> Layer<S> for MetricsLayer {
    type Service = MetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MetricsService {
            inner,
            metrics: self.metrics.clone(),
            service: self.service,
        }
    }
}

#[derive(Clone)]
pub struct MetricsService<S> {
    inner: S,
    metrics: Arc<Metrics>,
    service: &'static str,
}

impl<S, B> Service<Request<B>> for MetricsService<S>
where
    S: Service<Request<B>, Response = axum::response::Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = axum::response::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let mut inner = self.inner.clone();
        let metrics = self.metrics.clone();
        let service = self.service;
        let method = req.method().clone();
        let path = request_path_label(&req);
        let start = Instant::now();
        Box::pin(async move {
            let response = inner.call(req).await?;
            let status = response.status();
            let status_label = status.as_u16().to_string();
            metrics
                .http_requests
                .with_label_values(&[service, &path, method.as_str(), &status_label])
                .inc();
            metrics
                .http_duration
                .with_label_values(&[service, &path, method.as_str()])
                .observe(start.elapsed().as_secs_f64());
            Ok(response)
        })
    }
}

fn request_path_label<B>(req: &Request<B>) -> String {
    if let Some(matched) = req.extensions().get::<MatchedPath>() {
        return matched.as_str().to_string();
    }
    req.uri().path().to_string()
}

#[cfg(test)]
mod tests {
    use super::{Metrics, MetricsLayer};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use axum::routing::get;
    use axum::Router;
    use std::io;
    use std::sync::Mutex;
    use std::task::{Context, Poll};
    use tower::{Layer, Service};

    static METRICS_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Copy)]
    enum TestOutcome {
        Ok,
        Err,
    }

    #[derive(Clone, Copy)]
    struct TestService {
        outcome: TestOutcome,
    }

    impl Service<Request<Body>> for TestService {
        type Response = Response;
        type Error = io::Error;
        type Future = futures_util::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<Body>) -> Self::Future {
            match self.outcome {
                TestOutcome::Ok => futures_util::future::ready(Ok(Response::new(Body::empty()))),
                TestOutcome::Err => {
                    futures_util::future::ready(Err(io::Error::new(io::ErrorKind::Other, "boom")))
                }
            }
        }
    }

    fn metrics_with_env(value: Option<&str>) -> std::sync::Arc<Metrics> {
        let _guard = METRICS_ENV_LOCK.lock().expect("lock");
        match value {
            Some(value) => std::env::set_var("NSS_TEST_METRICS_DUP", value),
            None => std::env::remove_var("NSS_TEST_METRICS_DUP"),
        }
        let metrics = Metrics::new();
        std::env::remove_var("NSS_TEST_METRICS_DUP");
        metrics
    }

    #[test]
    fn metrics_registry_exposes_known_metrics() {
        let metrics = metrics_with_env(None);
        metrics
            .http_requests
            .with_label_values(&["svc", "/path", "GET", "200"])
            .inc();
        metrics.chunk_read.with_label_values(&["ok"]).inc();
        let names: Vec<String> = metrics
            .gather()
            .into_iter()
            .map(|family| family.name().to_string())
            .collect();
        assert!(names.contains(&"nss_http_requests_total".to_string()));
        assert!(names.contains(&"nss_chunk_read_total".to_string()));
    }

    #[test]
    fn metrics_registry_handles_duplicate_registration() {
        let _metrics = metrics_with_env(Some("1"));
    }

    #[tokio::test]
    async fn metrics_layer_poll_ready_delegates() {
        let metrics = metrics_with_env(None);
        let layer = MetricsLayer::new(metrics, "svc");
        let mut wrapped = layer.layer(TestService {
            outcome: TestOutcome::Ok,
        });
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = Service::poll_ready(&mut wrapped, &mut cx);
    }

    #[tokio::test]
    async fn metrics_layer_records_http_request_with_matched_path() {
        let metrics = metrics_with_env(None);
        let layer = MetricsLayer::new(metrics.clone(), "svc");
        let mut app = Router::new()
            .route("/objects/{id}", get(|| async { "" }))
            .layer(layer);

        let req = Request::builder()
            .method("GET")
            .uri("/objects/123")
            .body(Body::empty())
            .expect("request");

        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = <Router as Service<Request<Body>>>::poll_ready(&mut app, &mut cx);
        let response = <Router as Service<Request<Body>>>::call(&mut app, req)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let count = metrics
            .http_requests
            .with_label_values(&["svc", "/objects/{id}", "GET", "200"])
            .get();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn metrics_layer_records_route_service_requests() {
        let metrics = metrics_with_env(None);
        let layer = MetricsLayer::new(metrics.clone(), "svc");
        let route = get(|| async { "" });
        let mut wrapped = layer.layer(route);

        let req = Request::builder()
            .method("GET")
            .uri("/route")
            .body(Body::empty())
            .expect("request");

        let response = Service::call(&mut wrapped, req).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let count = metrics
            .http_requests
            .with_label_values(&["svc", "/route", "GET", "200"])
            .get();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn metrics_layer_uses_fallback_path_without_matched_path() {
        let metrics = metrics_with_env(None);
        let layer = MetricsLayer::new(metrics.clone(), "svc");
        let mut wrapped = layer.layer(TestService {
            outcome: TestOutcome::Ok,
        });

        let req = Request::builder()
            .method("GET")
            .uri("/fallback")
            .body(Body::empty())
            .expect("request");

        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = Service::poll_ready(&mut wrapped, &mut cx);
        let response = Service::call(&mut wrapped, req).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let count = metrics
            .http_requests
            .with_label_values(&["svc", "/fallback", "GET", "200"])
            .get();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn metrics_layer_propagates_inner_errors() {
        let metrics = metrics_with_env(None);
        let layer = MetricsLayer::new(metrics.clone(), "svc");
        let mut wrapped = layer.layer(TestService {
            outcome: TestOutcome::Err,
        });

        let req = Request::builder()
            .method("GET")
            .uri("/error")
            .body(Body::empty())
            .expect("request");

        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = Service::poll_ready(&mut wrapped, &mut cx);
        let err = Service::call(&mut wrapped, req).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }
}
