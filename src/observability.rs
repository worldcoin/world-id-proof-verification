//! Request logs include extractor and router rejections as well as handler results.

use axum::{
    extract::{MatchedPath, Request, State},
    http::{HeaderValue, Request as HttpRequest},
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tracing::{field::Empty, Span};
use uuid::Uuid;

use crate::cfg::config::Config;
use crate::models::challenge_model::ChallengeType;

#[derive(Clone)]
pub struct RequestLogSpan(Span);

impl RequestLogSpan {
    pub fn record_challenge_type(&self, challenge_type: ChallengeType) {
        self.0.record("challenge_type", challenge_type.as_str());
    }
}

/// INFO keeps request fields available to the JSON formatter at RUST_LOG=info.
/// Do not capture raw paths, queries, headers, or bodies: they can contain secrets.
pub fn request_span(req: &HttpRequest<()>) -> Span {
    tracing::info_span!(
        "http_request",
        http.method = %req.method(),
        http.route = Empty,
        http.status_code = Empty,
        http.response.status_code = Empty,
        otel.name = Empty,
        otel.kind = "server",
        otel.status_code = Empty,
        service = Empty,
        env = Empty,
        version = Empty,
        request_id = Empty,
        auth.outcome = Empty,
        auth.error_kind = Empty,
        challenge_type = Empty,
    )
}

pub async fn log_request(State(cfg): State<Config>, mut request: Request, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("unmatched")
        .to_owned();
    // Generate our own ID; untrusted incoming IDs must not pollute logs.
    let request_id = Uuid::new_v4().to_string();
    let span = Span::current();
    request
        .extensions_mut()
        .insert(RequestLogSpan(span.clone()));
    span.record("http.route", &route);
    span.record("otel.name", format!("{} {route}", request.method()));
    span.record("request_id", &request_id);
    span.record("service", &cfg.srv_name);
    span.record("env", &cfg.srv_env);
    span.record("version", &cfg.srv_version);

    let start = Instant::now();
    let mut response = next.run(request).await;
    let status = response.status();
    span.record("http.status_code", status.as_u16());
    span.record("http.response.status_code", status.as_u16());
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    if status.is_server_error() {
        span.record("otel.status_code", "ERROR");
        tracing::error!(
            stage = "http_response",
            http.status_code = status.as_u16(),
            duration_ms,
            "request failed"
        );
    } else if status.is_client_error() {
        tracing::warn!(
            stage = "http_response",
            http.status_code = status.as_u16(),
            duration_ms,
            "request rejected"
        );
    } else if route != "/health" && route != "/ready" {
        tracing::info!(
            stage = "http_response",
            http.status_code = status.as_u16(),
            duration_ms,
            "request completed"
        );
    }
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id).expect("UUID is a valid header value"),
    );
    response
}
