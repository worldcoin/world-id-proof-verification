//! Wire types for the World ID 4.x proof verification HTTP API.
//!
//! The service and its client both use these structs, so a field added on one
//! side is the same field the other side serializes.

use std::fmt;

use axum::{Json, http::StatusCode, response::IntoResponse, response::Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The flow a challenge authorizes. New flows add variants; the wire form is the
/// snake_case name (for example, `"enrollment"` or `"teedi_migration"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    Enrollment,
    #[serde(rename = "teedi_migration")]
    TEEDIMigration,
}

impl ChallengeType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enrollment => "enrollment",
            Self::TEEDIMigration => "teedi_migration",
        }
    }
}

impl fmt::Display for ChallengeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// A challenge issued by `POST /api/v4/zkp/challenge/{challenge_type}`.
/// `expires_at` is advisory; the Redis key TTL is the authority on expiration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub challenge_id: uuid::Uuid,
    pub nonce: String,
    pub challenge_type: ChallengeType,
    pub expires_at: DateTime<Utc>,
}

/// Body of `POST /api/v4/verify`.
///
/// The freshness nonce and challenge type are not in this body. Both live in
/// the challenge stored under `challenge_id`. `proof` is standard padded
/// base64 of the wallet's ownership-proof CBOR.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationRequest {
    pub challenge_id: uuid::Uuid,
    pub credential_sub: String,
    pub proof: String,
}

/// `msg` on a verify response, including the auth extractor's rejection.
///
/// The verify handler returns `proof_accepted` or `proof_rejected`. A rejected
/// JWT uses the same body shape with `unauthorized`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationMsg {
    #[serde(rename = "proof_accepted")]
    ProofAccepted,
    #[serde(rename = "proof_rejected")]
    ProofRejected,
    #[serde(rename = "unauthorized")]
    Unauthorized,
}

/// JSON body `{"msg": ...}` returned by verify and by the verify auth layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    pub msg: VerificationMsg,
}

impl IntoResponse for crate::VerificationResult {
    fn into_response(self) -> Response {
        let status = match self.msg {
            VerificationMsg::ProofAccepted => StatusCode::OK,
            VerificationMsg::ProofRejected => StatusCode::UNAUTHORIZED,
            VerificationMsg::Unauthorized => StatusCode::UNAUTHORIZED,
        };
        (status, Json(self)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_msgs_use_the_service_wire_names() {
        assert_eq!(
            serde_json::to_string(&VerificationMsg::ProofAccepted).unwrap(),
            "\"proof_accepted\""
        );
        assert_eq!(
            serde_json::to_string(&VerificationMsg::ProofRejected).unwrap(),
            "\"proof_rejected\""
        );
        assert_eq!(
            serde_json::to_string(&VerificationMsg::Unauthorized).unwrap(),
            "\"unauthorized\""
        );
    }

    #[test]
    fn challenge_round_trips_with_canonical_field_encoding() {
        let challenge = ChallengeResponse {
            challenge_id: "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31".parse().unwrap(),
            nonce: world_id_primitives::FieldElement::ONE.to_string(),
            challenge_type: ChallengeType::TEEDIMigration,
            expires_at: DateTime::parse_from_rfc3339("2026-09-28T15:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        let json = serde_json::to_value(&challenge).unwrap();
        assert_eq!(json["challenge_type"], "teedi_migration");
        assert_eq!(json["nonce"], format!("0x{}1", "0".repeat(63)));
        let decoded: ChallengeResponse = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, challenge);
    }
}
