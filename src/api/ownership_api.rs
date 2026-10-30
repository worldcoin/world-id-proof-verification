use crate::api::bounded_json::BoundedJson;
use crate::cfg::config::Config;
use crate::models::challenge_model::ChallengeType;
use crate::models::ownership_model::{
    decode_proof, OwnershipVerificationMsg, OwnershipVerificationRequest,
    OwnershipVerificationResult, ProofDecodeError,
};
use crate::observability::RequestLogSpan;
use crate::services::gateway_service::GatewayService;
use crate::services::jwt_auth::AuthenticatedService;
use crate::services::nonce_store::DynNonceStore;
use crate::services::ownership_proof_verifier::DynOwnershipProofVerifier;
use axum::{
    extract::State, http::StatusCode, response::IntoResponse, response::Response, Extension, Json,
};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{Semaphore, TryAcquireError};
use tracing::{error, info, instrument, warn};
use world_id_primitives::FieldElement;
use world_id_proof::artifacts::embedded::EmbeddedZkArtifacts;
use world_id_proof::ProofError;

// Secondary cap on the decoded proof's two variable-length fields; a real
// staging proof is 570,464 bytes of CBOR combined, so 640 KiB bounds each.
const MAX_PROOF_COMPONENT_BYTES: usize = 640 * 1024;

#[derive(Clone)]
pub struct OwnershipVerificationState {
    pub(crate) cfg: Config,
    pub(crate) nonce_store: DynNonceStore,
    pub(crate) gateway: Arc<GatewayService>,
    pub(crate) verifier: DynOwnershipProofVerifier,
    pub(crate) verification_slots: Arc<Semaphore>,
}

fn verdict(status: StatusCode, msg: OwnershipVerificationMsg) -> Response {
    (status, Json(OwnershipVerificationResult { msg })).into_response()
}

fn accepted() -> Response {
    verdict(StatusCode::OK, OwnershipVerificationMsg::ProofAccepted)
}

fn rejected() -> Response {
    verdict(
        StatusCode::UNAUTHORIZED,
        OwnershipVerificationMsg::ProofRejected,
    )
}

// Redis/gateway faults, task panics, and verification timeouts are all
// equally retriable, so they share this 503 rather than a bare 500.
fn dependency_unavailable() -> Response {
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}

fn malformed_request() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "msg": "malformed_request" })),
    )
        .into_response()
}

fn malformed_proof(stage: &'static str) -> Response {
    warn!(
        stage = "proof_decode",
        error_kind = "malformed_proof",
        encoding = stage,
        "proof blob failed to decode"
    );
    metrics::counter!("ownership_proof.rejected", "error" => "malformed_proof").increment(1);
    malformed_request()
}

fn too_large(reason: &'static str) -> Response {
    warn!(
        stage = "proof_decode",
        error_kind = "proof_component_too_large",
        component = reason,
        "oversized proof component"
    );
    metrics::counter!("ownership_proof.rejected", "error" => "proof_component_too_large")
        .increment(1);
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(serde_json::json!({ "msg": "request_too_large" })),
    )
        .into_response()
}

fn verification_unavailable() -> Response {
    error!(
        stage = "verification_queue",
        error_kind = "verification_pool_closed",
        "verification pool unavailable"
    );
    metrics::counter!("ownership_proof.failure", "error" => "verification_pool_closed")
        .increment(1);
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}

#[instrument(skip_all, fields(challenge_id = %req.challenge_id))]
pub async fn verify_ownership(
    State(OwnershipVerificationState {
        cfg,
        nonce_store,
        gateway,
        verifier,
        verification_slots,
    }): State<OwnershipVerificationState>,
    Extension(request_log): Extension<RequestLogSpan>,
    // Gates the route: rejects before the body or any dependency is touched.
    _auth: AuthenticatedService,
    BoundedJson(req): BoundedJson<OwnershipVerificationRequest>,
) -> Response {
    // Destructured up front so the base64 blob is owned by `decode_proof` and
    // dropped there, rather than living in `req` until the handler returns.
    let OwnershipVerificationRequest {
        challenge_id,
        credential_sub,
        proof,
    } = req;

    let credential_sub = match FieldElement::from_str(&credential_sub) {
        Ok(value) => value,
        Err(_) => {
            warn!(
                stage = "request_decode",
                error_kind = "malformed_credential_sub",
                "credential_sub is not a canonical field element"
            );
            metrics::counter!("ownership_proof.rejected", "error" => "malformed_credential_sub")
                .increment(1);
            return malformed_request();
        }
    };

    let proof = match decode_proof(proof) {
        Ok(proof) => proof,
        Err(ProofDecodeError::Base64) => return malformed_proof("base64"),
        Err(ProofDecodeError::Cbor) => return malformed_proof("cbor"),
    };

    if proof.proof.narg_string.len() > MAX_PROOF_COMPONENT_BYTES {
        return too_large("narg_string");
    }
    if proof.proof.hints.len() > MAX_PROOF_COMPONENT_BYTES {
        return too_large("hints");
    }

    let nonce_object = match nonce_store.peek(&challenge_id).await {
        Ok(Some(obj)) => obj,
        Ok(None) => {
            warn!(
                stage = "nonce_peek",
                error_kind = "challenge_not_found",
                "challenge unknown, expired, or already used"
            );
            metrics::counter!("ownership_proof.rejected", "error" => "challenge_not_found")
                .increment(1);
            return rejected();
        }
        Err(e) => {
            error!(stage = "nonce_peek", error_kind = "nonce_peek_failed", error = %e, "nonce store peek failed");
            metrics::counter!("ownership_proof.failure", "error" => "nonce_peek_failed")
                .increment(1);
            return dependency_unavailable();
        }
    };
    request_log.record_challenge_type(nonce_object.challenge_type);

    // Only flows participating in the v4 shadow rollout may be verified.
    if !matches!(
        nonce_object.challenge_type,
        ChallengeType::Enrollment | ChallengeType::TEEDIMigration
    ) {
        warn!(
            stage = "challenge_validation", error_kind = "challenge_type_not_supported",
            stored = ?nonce_object.challenge_type,
            "challenge type is not supported for ownership verification"
        );
        metrics::counter!("ownership_proof.rejected", "error" => "challenge_type_not_supported")
            .increment(1);
        return rejected();
    }

    match gateway.is_valid_root(proof.merkle_root).await {
        Ok(true) => {}
        Ok(false) => {
            warn!(
                stage = "gateway_root_check",
                error_kind = "merkle_root_not_accepted",
                "merkle root not accepted"
            );
            metrics::counter!("ownership_proof.rejected", "error" => "merkle_root_not_accepted")
                .increment(1);
            return rejected();
        }
        Err(e) => {
            error!(stage = "gateway_root_check", error_kind = "merkle_root_check_failed", error = %e, "root-validity check failed");
            metrics::counter!("ownership_proof.failure", "error" => "merkle_root_check_failed")
                .increment(1);
            return dependency_unavailable();
        }
    }

    let nonce = nonce_object.nonce;
    let context =
        FieldElement::from_arbitrary_raw_bytes(nonce_object.challenge_type.as_str().as_bytes());

    let queue_wait_start = std::time::Instant::now();
    let permit = match Arc::clone(&verification_slots).try_acquire_owned() {
        Ok(permit) => permit,
        Err(TryAcquireError::NoPermits) => {
            metrics::counter!("ownership_proof.verification_saturated").increment(1);

            let Ok(acquired) = tokio::time::timeout(
                cfg.verify_timeout,
                Arc::clone(&verification_slots).acquire_owned(),
            )
            .await
            else {
                error!(
                    stage = "verification_queue", error_kind = "queue_wait_timeout",
                    timeout = ?cfg.verify_timeout,
                    "ownership verification queue wait timed out"
                );
                metrics::counter!("ownership_proof.failure", "error" => "queue_wait_timeout")
                    .increment(1);
                return dependency_unavailable();
            };

            match acquired {
                Ok(permit) => permit,
                Err(error) => {
                    error!(stage = "verification_queue", error_kind = "verification_pool_closed", %error, "ownership verification pool closed while waiting");
                    metrics::counter!("ownership_proof.failure", "error" => "verification_pool_closed")
                        .increment(1);
                    return dependency_unavailable();
                }
            }
        }
        Err(TryAcquireError::Closed) => return verification_unavailable(),
    };
    metrics::histogram!(
        "ownership_proof.queue_wait_seconds",
        "histogram" => "distribution"
    )
    .record(queue_wait_start.elapsed().as_secs_f64());

    // `spawn_blocking` can't be cancelled: a timeout below only stops this
    // caller from waiting, the OS thread still runs to completion and drops
    // `_permit` on its own schedule, so the slot is never leaked.
    let span = tracing::info_span!("proof_verification", stage = "proof_verification");
    let join_handle = tokio::task::spawn_blocking(move || {
        let _entered = span.enter();
        let _permit = permit;

        verifier.verify(&proof, nonce, credential_sub, context, &EmbeddedZkArtifacts)
    });

    let Ok(outcome) = tokio::time::timeout(cfg.verify_timeout, join_handle).await else {
        error!(stage = "proof_verification", error_kind = "verification_timeout", timeout = ?cfg.verify_timeout, "ownership verification timed out");
        metrics::counter!("ownership_proof.failure", "error" => "verification_timeout")
            .increment(1);
        return dependency_unavailable();
    };

    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(ProofError::Verification(reason))) => {
            warn!(stage = "proof_verification", error_kind = "invalid_proof", reason = %reason, "ownership proof rejected");
            metrics::counter!("ownership_proof.rejected", "error" => "invalid_proof").increment(1);
            return rejected();
        }
        Ok(Err(err)) => {
            error!(stage = "proof_verification", error_kind = "verifier_infra_error", error = %err, "ownership verification infrastructure failure");
            metrics::counter!("ownership_proof.failure", "error" => "verifier_infra_error")
                .increment(1);
            return dependency_unavailable();
        }
        Err(e) => {
            error!(stage = "proof_verification", error_kind = "verification_error", error = %e, "ownership verification task failed");
            metrics::counter!("ownership_proof.failure", "error" => "verification_error")
                .increment(1);
            return dependency_unavailable();
        }
    }

    // Consume nonce only after a successful verification
    match nonce_store.consume(&challenge_id).await {
        Ok(Some(_)) => {
            info!("ownership proof accepted");
            metrics::counter!("ownership_proof.accepted").increment(1);
            accepted()
        }
        Ok(None) => {
            warn!(
                stage = "nonce_consume",
                error_kind = "nonce_not_found_after_verification",
                "challenge gone at consume: concurrent winner or TTL expiry"
            );
            metrics::counter!("ownership_proof.rejected", "error" => "nonce_not_found_after_verification").increment(1);
            rejected()
        }
        Err(e) => {
            error!(stage = "nonce_consume", error_kind = "nonce_consume_failed", error = %e, "nonce store consume failed after verification");
            metrics::counter!("ownership_proof.failure", "error" => "nonce_consume_failed")
                .increment(1);
            dependency_unavailable()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ownership_model::OwnershipProof;
    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
    use world_id_primitives::FieldElement;
    use world_id_proof::WhirR1CSProof;

    fn sample_proof() -> OwnershipProof {
        OwnershipProof {
            proof: WhirR1CSProof {
                narg_string: vec![1, 2, 3, 4],
                hints: vec![9, 8, 7],
                // Debug-only field, skipped on serialize.
                #[cfg(debug_assertions)]
                pattern: Vec::new(),
            },
            merkle_root: FieldElement::from(42u64),
        }
    }

    fn encode_proof(proof: &OwnershipProof) -> String {
        let mut bytes = Vec::new();
        ciborium::into_writer(proof, &mut bytes).unwrap();
        BASE64_STANDARD.encode(bytes)
    }

    // Go `json.Marshal([]byte)` (go1.22) output over the CBOR bytes of
    // `sample_proof()`, quotes included — not a Rust re-encoding.
    const GO_JSON_PROOF: &str =
        "\"omVwcm9vZqJrbmFyZ19zdHJpbmdEAQIDBGVoaW50c0MJCAdrbWVya2xlX3Jvb3RYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAq\"";
    // Same, with a 5-byte `narg_string` so Go emits `==` padding.
    const GO_JSON_PROOF_PADDED: &str =
        "\"omVwcm9vZqJrbmFyZ19zdHJpbmdFAQIDBAVlaGludHNDCQgHa21lcmtsZV9yb290WCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKg==\"";

    #[test]
    fn go_json_marshal_output_decodes_to_the_sample_proof() {
        let proof = serde_json::from_str(GO_JSON_PROOF).unwrap();
        assert_eq!(decode_proof(proof).unwrap(), sample_proof());
    }

    #[test]
    fn padded_go_json_marshal_output_decodes() {
        let mut expected = sample_proof();
        expected.proof.narg_string = vec![1, 2, 3, 4, 5];

        let proof = serde_json::from_str(GO_JSON_PROOF_PADDED).unwrap();
        assert_eq!(decode_proof(proof).unwrap(), expected);
    }

    #[test]
    fn proof_blob_roundtrips_through_decode() {
        assert_eq!(
            decode_proof(encode_proof(&sample_proof())).unwrap(),
            sample_proof()
        );
    }

    #[test]
    fn unpadded_base64_is_rejected() {
        // Only the padded fixture has trailing `=` to strip.
        let proof = serde_json::from_str::<String>(GO_JSON_PROOF_PADDED)
            .unwrap()
            .trim_end_matches('=')
            .to_string();
        assert_eq!(decode_proof(proof), Err(ProofDecodeError::Base64));
    }

    #[test]
    fn non_base64_proof_is_a_base64_error() {
        assert_eq!(
            decode_proof("not/base64!!".to_string()),
            Err(ProofDecodeError::Base64)
        );
    }

    #[test]
    fn valid_base64_of_garbage_is_a_cbor_error() {
        let proof = BASE64_STANDARD.encode(b"definitely not cbor");
        assert_eq!(decode_proof(proof), Err(ProofDecodeError::Cbor));
    }
}
