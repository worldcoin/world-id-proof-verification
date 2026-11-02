use crate::api::bounded_json::LoggedJson;
use crate::{
    cfg::config::Config,
    models::verification_model::VerificationRequest,
    services::proof_verifier::{check_freshness, ChallengeFreshness, DynProofVerifier},
};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{Duration, Utc};
use semaphore_rs::protocol::ProofError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{Semaphore, TryAcquireError};
use tracing::{error, instrument, warn};

/// Allowance for clock skew between the client and this service. A challenge
/// timestamp up to this far in the future is still accepted as "now".
const CLOCK_SKEW_TOLERANCE_SECONDS: i64 = 2;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum VerificationMsg {
    #[serde(rename = "old_timestamp")]
    OldTimestamp,
    #[serde(rename = "timestamp_is_in_the_future")]
    FutureTimestamp,
    #[serde(rename = "proof_rejected")]
    ProofRejected,
    #[serde(rename = "wrong_timestamp_format")]
    WrongTimestampFormat,
    #[serde(rename = "proof_accepted")]
    ProofAccepted,
}

use VerificationMsg::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationResult {
    pub msg: VerificationMsg,
}

impl VerificationResult {
    fn new(vr: VerificationMsg) -> VerificationResult {
        VerificationResult { msg: vr }
    }
}

/// Maps a `VerificationResult` to its HTTP status and JSON body: `200` when
/// accepted, `400` for an unparseable timestamp, `401` otherwise.
impl IntoResponse for VerificationResult {
    fn into_response(self) -> axum::response::Response {
        let status = match self.msg {
            WrongTimestampFormat => StatusCode::BAD_REQUEST,
            ProofAccepted => StatusCode::OK,
            _ => StatusCode::UNAUTHORIZED,
        };
        (status, Json(self)).into_response()
    }
}

fn verification_unavailable() -> Response {
    error!(
        stage = "verification_queue",
        error_kind = "verification_pool_closed",
        "semaphore inclusion proof verification pool unavailable"
    );
    metrics::counter!(
        "semaphore.inclusion_proof.failure",
        "error" => "verification_pool_closed"
    )
    .increment(1);
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}

fn dependency_unavailable() -> Response {
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}

/// Classifies a verification-layer `ProofError` for metrics/log correlation.
///
/// `verify_proof` only reaches the deserialization variants below — the
/// verifying key is compiled in via the `depth_30` feature rather than read
/// at request time, so the proving-side variants (`CircuitKeyError`,
/// `WitnessError`) are unreachable here. Every reachable variant stems from
/// malformed proof/public-input data, not a dependency outage, so the HTTP
/// response stays `ProofRejected`; only the label changes.
fn proof_error_label(error: &ProofError) -> &'static str {
    match error {
        ProofError::CircuitKeyError(_) => "circuit_key_error",
        ProofError::WitnessError(_) => "witness_error",
        ProofError::SynthesisError(_) => "synthesis_error",
        ProofError::ToFieldError(_) => "to_field_error",
        ProofError::G1AffineError(_) => "g1_affine_error",
    }
}

#[instrument(skip_all)]
pub async fn verify_proof(
    State(cfg): State<Config>,
    State(verifier): State<DynProofVerifier>,
    State(verification_slots): State<Arc<Semaphore>>,
    LoggedJson(req): LoggedJson<VerificationRequest>,
) -> Response {
    let check = check_freshness(
        &req.challenge,
        Utc::now(),
        Duration::seconds(cfg.response_duration_seconds),
        Duration::seconds(CLOCK_SKEW_TOLERANCE_SECONDS),
    );

    // The age metric is recorded for exactly the timestamps that reach the age
    // check in the original flow: parseable and not rejected as in-future.
    if let Some(age) = check.age {
        metrics::histogram!(
            "semaphore.inclusion_proof.age_seconds",
            "histogram" => "distribution"
        )
        .record(age.num_milliseconds() as f64 / 1000.0);
    }

    match check.freshness {
        ChallengeFreshness::Unparseable => {
            warn!(
                stage = "challenge_freshness",
                error_kind = "wrong_timestamp_format",
                "wrong timestamp format"
            );
            VerificationResult::new(WrongTimestampFormat).into_response()
        }
        ChallengeFreshness::InFuture => {
            warn!(
                stage = "challenge_freshness",
                error_kind = "timestamp_is_in_the_future",
                "timestamp is in the future"
            );
            VerificationResult::new(FutureTimestamp).into_response()
        }
        ChallengeFreshness::Expired => {
            warn!(
                stage = "challenge_freshness",
                error_kind = "old_timestamp",
                "challenge timestamp expired"
            );
            VerificationResult::new(OldTimestamp).into_response()
        }
        ChallengeFreshness::Fresh => {
            let queue_wait_start = std::time::Instant::now();
            let permit = match Arc::clone(&verification_slots).try_acquire_owned() {
                Ok(permit) => permit,
                Err(TryAcquireError::NoPermits) => {
                    metrics::counter!("semaphore.inclusion_proof.verification_saturated")
                        .increment(1);

                    let Ok(acquired) = tokio::time::timeout(
                        cfg.verify_timeout,
                        Arc::clone(&verification_slots).acquire_owned(),
                    )
                    .await
                    else {
                        error!(
                            stage = "verification_queue", error_kind = "queue_wait_timeout",
                            timeout = ?cfg.verify_timeout,
                            "semaphore inclusion proof queue wait timed out"
                        );
                        metrics::counter!(
                            "semaphore.inclusion_proof.failure",
                            "error" => "queue_wait_timeout"
                        )
                        .increment(1);
                        return dependency_unavailable();
                    };

                    match acquired {
                        Ok(permit) => permit,
                        Err(error) => {
                            error!(stage = "verification_queue", error_kind = "verification_pool_closed", %error, "semaphore inclusion proof verification pool closed while waiting");
                            metrics::counter!(
                                "semaphore.inclusion_proof.failure",
                                "error" => "verification_pool_closed"
                            )
                            .increment(1);
                            return dependency_unavailable();
                        }
                    }
                }
                Err(TryAcquireError::Closed) => return verification_unavailable(),
            };
            metrics::histogram!(
                "semaphore.inclusion_proof.queue_wait_seconds",
                "histogram" => "distribution"
            )
            .record(queue_wait_start.elapsed().as_secs_f64());

            // A timed-out blocking task keeps running, so it must retain the
            // permit until verification actually finishes.
            let span = tracing::info_span!("proof_verification", stage = "proof_verification");
            let join_handle = tokio::task::spawn_blocking(move || {
                let _entered = span.enter();
                let _permit = permit;
                verifier.verify(&req)
            });

            let verification = match tokio::time::timeout(cfg.verify_timeout, join_handle).await {
                Err(_) => {
                    error!(stage = "proof_verification", error_kind = "verification_timeout", timeout = ?cfg.verify_timeout, "semaphore inclusion proof verification timed out");
                    metrics::counter!(
                        "semaphore.inclusion_proof.failure",
                        "error" => "verification_timeout"
                    )
                    .increment(1);
                    return dependency_unavailable();
                }
                Ok(Err(error)) => {
                    error!(stage = "proof_verification", error_kind = "verification_error", error = %error, "semaphore inclusion proof verification task failed");
                    metrics::counter!(
                        "semaphore.inclusion_proof.failure",
                        "error" => "verification_error"
                    )
                    .increment(1);
                    return dependency_unavailable();
                }
                Ok(Ok(verification)) => verification,
            };

            match verification {
                Ok(true) => {
                    metrics::counter!("semaphore.inclusion_proof.accepted").increment(1);
                    VerificationResult::new(ProofAccepted).into_response()
                }
                Ok(false) => {
                    warn!(
                        stage = "proof_verification",
                        error_kind = "invalid_proof",
                        "semaphore inclusion proof rejected: proof did not verify"
                    );
                    metrics::counter!(
                        "semaphore.inclusion_proof.rejected",
                        "error" => "invalid_proof"
                    )
                    .increment(1);
                    VerificationResult::new(ProofRejected).into_response()
                }
                Err(error) => {
                    let error_kind = proof_error_label(&error);
                    warn!(
                        stage = "proof_verification",
                        error = %error,
                        error_kind,
                        "semaphore inclusion proof rejected: malformed proof or input"
                    );
                    metrics::counter!(
                        "semaphore.inclusion_proof.rejected",
                        "error" => error_kind
                    )
                    .increment(1);
                    VerificationResult::new(ProofRejected).into_response()
                }
            }
        }
    }
}
