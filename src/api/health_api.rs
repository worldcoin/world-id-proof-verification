use crate::cfg::config::Config;
use crate::services::nonce_store::DynNonceStore;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use tracing::error;

#[derive(Serialize)]
struct HealthResp {
    pub msg: String,
    pub app_name: String,
    pub app_version: String,
}

#[derive(Serialize)]
struct ReadyResp {
    redis: &'static str,
}

/// Handles GET requests to the `/health` endpoint.
///
/// The function takes a `Data<Config>` struct as input, which contains the configuration options for the proof verification service.
///
/// The function returns an `HttpResponse` with a JSON body containing the following fields:
///
/// * `msg`: A `String` indicating the status of the health check (always "check").
/// * `app_name`: A `String` representing the name of the service.
/// * `app_version`: A `String` representing the version of the service.
///
/// # Arguments
///
/// * `cfg`: A `State<Config>` struct containing the configuration options for the service.
pub async fn health_check(State(cfg): State<Config>) -> impl IntoResponse {
    Json(HealthResp {
        msg: "check".to_string(),
        app_name: cfg.srv_name.to_owned(),
        app_version: cfg.srv_version.to_owned(),
    })
}

/// Readiness probe: `200` when the nonce-store Redis answers a `PING`, `503`
/// otherwise. Kept separate from `/health` (liveness) so a dependency blip pulls
/// the pod from rotation without restarting it.
pub async fn ready_check(State(nonce_store): State<DynNonceStore>) -> impl IntoResponse {
    match nonce_store.ping().await {
        Ok(()) => (StatusCode::OK, Json(ReadyResp { redis: "up" })),
        Err(e) => {
            error!(stage = "readiness", error_kind = "redis_ping_failed", error = %e, "readiness check failed: redis unreachable");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ReadyResp { redis: "down" }),
            )
        }
    }
}
