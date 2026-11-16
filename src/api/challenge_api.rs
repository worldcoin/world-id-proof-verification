use std::sync::Arc;

use crate::cfg::config::Config;
use crate::models::challenge_model::{ChallengeBinding, ChallengeType, NonceObject};
use crate::observability::RequestLogSpan;
use crate::services::challenge_generator::DynChallengeGenerator;
use crate::services::nitro::binding::WebCapture;
use crate::services::nitro::document::{AttestationError, DynCaptureVerifier, MAX_DOCUMENT_BYTES};
use crate::services::nonce_store::{DynNonceStore, NonceStoreError};
use axum::{
    body::Body,
    extract::{rejection::PathRejection, Path, State},
    http::{header::RETRY_AFTER, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use tokio::sync::Semaphore;
use tracing::{error, info, instrument, warn};

/// Carries the capture enclave's attestation document, as standard padded base64.
pub const NITRO_ATTESTATION_HEADER: &str = "x-nitro-attestation";
/// Set by attested-proxy, and only for a request whose device attestation and
/// signature it verified. It strips any copy a client sends.
const ATTESTED_PLATFORM_HEADER: &str = "x-attested-platform";
const ATTESTED_KEY_THUMBPRINT_HEADER: &str = "x-attested-key-thumbprint";

/// Ceiling on a capture body. Three shares of up to 8 KiB dominate it.
pub const MAX_CAPTURE_BODY_BYTES: usize = 128 * 1024;

/// Recorded on challenges issued without a capture binding. A placeholder
/// until challenges are keyed on the authenticated caller identity.
const UNBOUND_ISSUER: &str = "challenge-endpoint";
const NITRO_ISSUER: &str = "nitro-capture";

/// What the enrollment challenge route needs to authenticate a web caller by
/// its Nitro capture evidence. Present only when the feature is enabled.
#[derive(Clone)]
pub struct NitroChallengeAuth {
    pub verifier: DynCaptureVerifier,
    /// Bounds concurrent attestation verifications, which are CPU-bound and
    /// reachable without any prior authentication.
    pub verification_slots: Arc<Semaphore>,
    /// Challenges one capture may obtain within a challenge lifetime.
    pub max_per_capture: u64,
}

/// The challenge route's dependencies, built from the shared application state.
#[derive(Clone)]
pub struct ChallengeState {
    pub(crate) cfg: Config,
    pub(crate) nonce_store: DynNonceStore,
    pub(crate) generator: DynChallengeGenerator,
    pub(crate) nitro: Option<NitroChallengeAuth>,
}

/// Why a web caller was not issued a challenge.
enum Rejection {
    /// Neither a verified device identity nor capture evidence was presented.
    MissingEvidence,
    Malformed,
    TooLarge,
    Attestation(AttestationError),
    RateLimited {
        retry_after_secs: u64,
    },
    Saturated,
    Unavailable,
}

impl Rejection {
    /// A stable, low-cardinality name for logs and the rejection metric.
    fn class(&self) -> &'static str {
        match self {
            Self::MissingEvidence => "missing_evidence",
            Self::Malformed => "malformed",
            Self::TooLarge => "too_large",
            Self::Attestation(error) => error.class(),
            Self::RateLimited { .. } => "rate_limited",
            Self::Saturated => "saturated",
            Self::Unavailable => "unavailable",
        }
    }

    fn into_response(self, request_log: &RequestLogSpan) -> Response {
        let class = self.class();
        metrics::counter!("challenge.nitro.rejected", "class" => class).increment(1);
        request_log.record_auth_rejected(class);

        let message = |status: StatusCode, msg: &'static str| {
            warn!(
                stage = "capture_authentication",
                error_kind = class,
                http.status_code = status.as_u16(),
                "challenge not issued: capture evidence rejected"
            );
            (status, Json(serde_json::json!({ "msg": msg }))).into_response()
        };
        match self {
            Self::MissingEvidence => message(StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Malformed => message(StatusCode::BAD_REQUEST, "malformed_request"),
            Self::TooLarge => message(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large"),
            // A stale document is the one failure a client can act on: it
            // must capture again. Every other attestation failure is coarse.
            Self::Attestation(AttestationError::Freshness) => {
                message(StatusCode::UNAUTHORIZED, "attestation_expired")
            }
            Self::Attestation(_) => message(StatusCode::UNAUTHORIZED, "attestation_rejected"),
            Self::RateLimited { retry_after_secs } => {
                let mut response =
                    message(StatusCode::TOO_MANY_REQUESTS, "challenge_limit_reached");
                response
                    .headers_mut()
                    .insert(RETRY_AFTER, retry_after_secs.into());
                response
            }
            // Ours, not the caller's, and retriable.
            Self::Saturated | Self::Unavailable => {
                error!(
                    stage = "capture_authentication",
                    error_kind = class,
                    "challenge not issued: capture authentication unavailable"
                );
                StatusCode::SERVICE_UNAVAILABLE.into_response()
            }
        }
    }
}

/// Issues a single-use challenge. An unknown `challenge_type` is logged and
/// returned as the `Path<ChallengeType>` extractor's `400` response.
///
/// With Nitro challenge authentication enabled, an enrollment challenge is
/// issued only to a caller attested-proxy verified, or to one presenting valid
/// Nitro capture evidence, in which case the challenge is bound to the attested
/// subject. There is no unauthenticated path. Other challenge types, and every
/// request while the feature is disabled, rely on attested-proxy alone.
#[instrument(skip_all)]
pub async fn issue_challenge(
    State(ChallengeState {
        cfg,
        nonce_store,
        generator,
        nitro,
    }): State<ChallengeState>,
    Extension(request_log): Extension<RequestLogSpan>,
    challenge_type: Result<Path<ChallengeType>, PathRejection>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let challenge_type = match challenge_type {
        Ok(Path(value)) => value,
        Err(rejection) => {
            warn!(
                stage = "request_decode",
                error_kind = "invalid_challenge_type",
                "challenge path rejected"
            );
            return rejection.into_response();
        }
    };
    request_log.record_challenge_type(challenge_type);

    let binding = match nitro {
        Some(nitro)
            if challenge_type == ChallengeType::Enrollment && !is_attested_device(&headers) =>
        {
            match authenticate_capture(&nitro, &cfg, &nonce_store, &headers, body).await {
                Ok(binding) => {
                    metrics::counter!("challenge.nitro.accepted").increment(1);
                    request_log.record_auth_accepted();
                    Some(binding)
                }
                Err(rejection) => return rejection.into_response(&request_log),
            }
        }
        _ => None,
    };

    let challenge = generator.generate();
    let ttl = cfg.challenge_ttl;
    let created_at = Utc::now();
    let expires_at = created_at + chrono::Duration::seconds(ttl.as_secs() as i64);
    let issuer = if binding.is_some() {
        NITRO_ISSUER
    } else {
        UNBOUND_ISSUER
    };
    let nonce_object = NonceObject {
        nonce: challenge.nonce,
        challenge_type,
        created_at,
        expires_at,
        issuer: issuer.to_string(),
        binding,
    };

    match nonce_store
        .put(&challenge.challenge_id, &nonce_object, ttl)
        .await
    {
        Ok(()) => {
            info!(challenge_id = %challenge.challenge_id, "challenge issued");
            metrics::counter!("challenge.issued").increment(1);
            (
                StatusCode::CREATED,
                Json(api_types::ChallengeResponse {
                    challenge_id: challenge.challenge_id,
                    nonce: challenge.nonce.to_string(),
                    challenge_type,
                    expires_at,
                }),
            )
                .into_response()
        }
        // Redis unreachable: fail closed, don't hand out a challenge the store
        // can't vouch for.
        Err(NonceStoreError::Backend(e)) => {
            error!(stage = "nonce_put", error_kind = "nonce_store_unavailable", error = %e, "nonce store unavailable; challenge not issued");
            metrics::counter!("challenge.failure", "error" => "nonce_store_unavailable")
                .increment(1);
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        // UUID collision or serialization fault: an internal anomaly, not a
        // dependency-availability problem.
        Err(e) => {
            error!(stage = "nonce_put", error_kind = "internal", error = %e, "challenge issuance failed");
            metrics::counter!("challenge.failure", "error" => "internal").increment(1);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Whether attested-proxy verified this request's device attestation. Sound
/// only because the service is reachable solely through the proxy, which
/// startup enforces whenever this check is in use.
fn is_attested_device(headers: &HeaderMap) -> bool {
    headers.contains_key(ATTESTED_PLATFORM_HEADER)
        && headers.contains_key(ATTESTED_KEY_THUMBPRINT_HEADER)
}

/// Authenticates a web caller by its capture evidence, cheapest checks first,
/// and returns what the challenge is to be bound to.
async fn authenticate_capture(
    nitro: &NitroChallengeAuth,
    cfg: &Config,
    nonce_store: &DynNonceStore,
    headers: &HeaderMap,
    body: Body,
) -> Result<ChallengeBinding, Rejection> {
    let document = attestation_document(headers)?;
    let body = axum::body::to_bytes(body, MAX_CAPTURE_BODY_BYTES)
        .await
        .map_err(|_| Rejection::TooLarge)?;
    let capture: WebCapture = serde_json::from_slice(&body).map_err(|_| Rejection::Malformed)?;
    let binding = capture.binding().map_err(|_| Rejection::Malformed)?;
    let sub = capture.subject().map_err(|_| Rejection::Malformed)?;

    // Shed rather than queue: verification is CPU-bound and this caller is
    // not yet authenticated.
    let permit = Arc::clone(&nitro.verification_slots)
        .try_acquire_owned()
        .map_err(|_| Rejection::Saturated)?;
    let verifier = Arc::clone(&nitro.verifier);
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verifier.verify(&document, &binding, Utc::now())
    })
    .await
    .map_err(|_| Rejection::Unavailable)?
    .map_err(Rejection::Attestation)?;

    // Counted only once the evidence is authentic, so junk requests cannot
    // exhaust a real capture's allowance. A legitimate retry needs a fresh
    // challenge, so the capture is limited rather than made single-use.
    let capture_digest = hex::encode(binding.nonce);
    let issued = nonce_store
        .count_issuance(&capture_digest, cfg.challenge_ttl)
        .await
        .map_err(|_| Rejection::Unavailable)?;
    if issued > nitro.max_per_capture {
        return Err(Rejection::RateLimited {
            retry_after_secs: cfg.challenge_ttl.as_secs(),
        });
    }
    Ok(ChallengeBinding {
        sub,
        capture_digest,
    })
}

/// Exactly one header holding canonical base64 of a non-empty document within
/// the size limit.
fn attestation_document(headers: &HeaderMap) -> Result<Vec<u8>, Rejection> {
    let mut values = headers.get_all(NITRO_ATTESTATION_HEADER).iter();
    let value = values.next().ok_or(Rejection::MissingEvidence)?;
    if values.next().is_some() {
        return Err(Rejection::Malformed);
    }
    let value = value.as_bytes();
    if value.len() > MAX_DOCUMENT_BYTES.div_ceil(3) * 4 {
        return Err(Rejection::Malformed);
    }
    STANDARD
        .decode(value)
        .ok()
        .filter(|document| {
            !document.is_empty()
                && document.len() <= MAX_DOCUMENT_BYTES
                && STANDARD.encode(document).as_bytes() == value
        })
        .ok_or(Rejection::Malformed)
}
