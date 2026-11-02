use crate::cfg::config::Config;
use crate::models::challenge_model::{ChallengeType, NonceObject};
use crate::observability::RequestLogSpan;
use crate::services::challenge_generator::DynChallengeGenerator;
use crate::services::nonce_store::{DynNonceStore, NonceStoreError};
use axum::{
    extract::{rejection::PathRejection, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use chrono::Utc;
use tracing::{error, info, instrument, warn};

/// Placeholder until the Auth-milestone task keys challenges on the
/// authenticated caller identity the rate limiter uses.
const ISSUER: &str = "challenge-endpoint";

/// Issues a single-use challenge. An unknown `challenge_type` is logged and
/// returned as the `Path<ChallengeType>` extractor's `400` response.
#[instrument(skip_all)]
pub async fn issue_challenge(
    State(cfg): State<Config>,
    State(nonce_store): State<DynNonceStore>,
    State(generator): State<DynChallengeGenerator>,
    Extension(request_log): Extension<RequestLogSpan>,
    challenge_type: Result<Path<ChallengeType>, PathRejection>,
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
    let challenge = generator.generate();
    let ttl = cfg.challenge_ttl;
    let created_at = Utc::now();
    let expires_at = created_at + chrono::Duration::seconds(ttl.as_secs() as i64);
    let nonce_object = NonceObject {
        nonce: challenge.nonce,
        challenge_type,
        created_at,
        expires_at,
        issuer: ISSUER.to_string(),
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
