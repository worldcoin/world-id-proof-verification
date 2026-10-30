use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use world_id_primitives::FieldElement;

pub use api_types::ChallengeType;

/// A `nonce`: the public input to the World ID 4.x ownership ZK circuit.
///
/// This is exactly the protocol's [`FieldElement`] (the `BabyJubJub` base field
/// = BN254 scalar field). Reusing it means the unbiased CSPRNG sampling
/// ([`FieldElement::random`]), the canonical fixed-width encoding
/// (`Display` → `0x` + 64 lowercase hex, leading zeros preserved) and the
/// strict reject-if-`>=`-`p` parser (`FromStr`) all come from the protocol —
/// not re-derived here, where a subtle encoding/entropy bug would silently
/// break proof verification.
///
/// `0` is not excluded — matching `FieldElement`'s encoding layer; whether the
/// circuit forbids a zero nonce is a circuit-owner decision above this layer.
pub type Nonce = FieldElement;

/// An opaque, unguessable handle used as the Redis key for a challenge.
///
/// A v4 (random) UUID. It is drawn from a CSPRNG independently of the [`Nonce`]
/// (never derived from it) and, as a `Uuid`, can never be confused with a field
/// element. It serializes as its canonical hyphenated string.
pub type ChallengeId = uuid::Uuid;

/// The pair of values prepared for one challenge: the opaque `challenge_id`
/// (the Redis key) and the circuit-input `nonce`. They are produced from
/// independent CSPRNG draws, so the handle is never derivable from the nonce.
///
/// `nonce` serializes via [`FieldElement`]'s canonical string encoding;
/// `challenge_id` as its hyphenated UUID string.
#[derive(Clone, Debug, Serialize)]
pub struct Challenge {
    pub challenge_id: ChallengeId,
    pub nonce: Nonce,
}

/// The record stored under a [`ChallengeId`] and consumed once at verification.
///
/// The verify endpoint accepts enrollment and TEE DI migration challenges.
/// `expires_at` is advisory; the Redis key TTL is the authority on expiration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceObject {
    pub nonce: Nonce,
    pub challenge_type: ChallengeType,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub issuer: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// The nonce reuses `FieldElement`'s canonical encoding: a small value (`1`)
    /// renders as `0x` + 63 zeros + `1` (fixed-width, leading zeros preserved)
    /// and round-trips through the strict parser. This pins that we did not
    /// regress the leading-zero invariant by re-encoding the value ourselves.
    #[test]
    fn nonce_encoding_preserves_leading_zeros() {
        let one: Nonce = FieldElement::ONE;
        let s = one.to_string();
        assert_eq!(s, format!("0x{}1", "0".repeat(63)));
        assert_eq!(s.len(), 66); // "0x" + 64 hex digits
        assert_eq!(Nonce::from_str(&s).unwrap(), one);
    }

    /// `NonceObject` round-trips through JSON with the nonce in canonical string
    /// form — the encoding the store persists and reads back.
    #[test]
    fn nonce_object_json_roundtrips() {
        let obj = NonceObject {
            nonce: FieldElement::ONE,
            challenge_type: ChallengeType::Enrollment,
            created_at: DateTime::parse_from_rfc3339("2026-07-03T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            expires_at: DateTime::parse_from_rfc3339("2026-07-03T00:10:00Z")
                .unwrap()
                .with_timezone(&Utc),
            issuer: "challenge-endpoint".to_string(),
        };
        let json = serde_json::to_string(&obj).unwrap();
        // The nonce is stored as its canonical field-element string, not bytes.
        assert!(json.contains(&format!("0x{}1", "0".repeat(63))));
        let decoded: NonceObject = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, obj);
    }

    #[test]
    fn teedi_migration_wire_name_matches_proof_context() {
        let challenge_type = ChallengeType::TEEDIMigration;
        assert_eq!(challenge_type.as_str(), "teedi_migration");
        assert_eq!(
            serde_json::to_string(&challenge_type).unwrap(),
            "\"teedi_migration\""
        );
        assert_eq!(
            serde_json::from_str::<ChallengeType>("\"teedi_migration\"").unwrap(),
            challenge_type
        );
    }
}
