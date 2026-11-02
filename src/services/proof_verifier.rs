use crate::cfg::config::TREE_DEPTH;
use crate::models::verification_model::VerificationRequest;
use chrono::{DateTime, Duration, Utc};
use semaphore_rs::hash_to_field;
use semaphore_rs::protocol::authentication::verify_proof;
use semaphore_rs::protocol::ProofError;
use std::sync::Arc;
use tracing::{debug, instrument};

/// A trait port for cryptographically verifying a World ID inclusion proof.
///
/// The trait exists purely as an injection/mocking seam: handlers
/// depend on `dyn ProofVerifier`, so a test can substitute a deterministic
/// verifier without touching the (slow) cryptographic path.
pub trait ProofVerifier: Send + Sync {
    /// Verifies the inclusion proof carried by `req`.
    ///
    /// Returns `Ok(true)` for a valid proof, `Ok(false)` for a well-formed but
    /// invalid one, and `Err` if the protocol layer could not evaluate it.
    fn verify(&self, req: &VerificationRequest) -> Result<bool, ProofError>;
}

/// Shared, thread-safe handle to the active [`ProofVerifier`] implementation.
///
/// This is the type held in the axum application state and pulled into handlers
/// via `State<DynProofVerifier>`.
pub type DynProofVerifier = Arc<dyn ProofVerifier>;

/// The production [`ProofVerifier`], backed by `semaphore-rs`.
///
/// Stateless: it holds no fields and performs the same cryptographic check the
/// service has always performed, now behind the trait port.
#[derive(Clone, Copy, Debug, Default)]
pub struct SemaphoreVerifier;

impl ProofVerifier for SemaphoreVerifier {
    /// Verifies a proof of inclusion for a given id commitment, challenge and external nullifier.
    ///
    /// The input [`VerificationRequest`] carries:
    ///
    /// * `id_commitment`: A `Field` representing the commitment to the identity of the user.
    /// * `nullifier_hash`: A `Field` representing the hash of the nullifier for the user.
    /// * `challenge`: A `String` (an RFC 3339 timestamp) for which the proof is being verified.
    /// * `scope`: A `String` representing the external nullifier for the user.
    /// * `proof`: A `Proof` representing the proof of inclusion for the challenge and nullifier.
    ///
    /// It hashes the challenge and external nullifier to field elements with `hash_to_field`,
    /// then calls `verify_proof` with the configured tree depth, id commitment, nullifier hash,
    /// challenge hash, external nullifier hash, and proof. `verify_proof` returns a `bool`
    /// indicating whether the proof is valid.
    ///
    /// # Errors
    ///
    /// Returns a `ProofError` if the proof is invalid or if there is an error during verification.
    ///
    /// # Examples
    ///
    /// ```
    /// use world_id_proof_verification_service::models::verification_model::VerificationRequest;
    /// use world_id_proof_verification_service::services::proof_verifier::{ProofVerifier, SemaphoreVerifier};
    /// use semaphore_rs::hash_to_field;
    /// use serde_json::json;
    ///
    /// let proof:&'static str = r#"[
    ///     [
    ///         "0xb17dc446f8a1ad8c55b696ae6791bba36294bc55606cd6a80cd914951b5a169",
    ///         "0x60a527327b1eb335b5485dd2da15e232e8c33f3b57ab45ca9f2bf0dd7778f11"
    ///     ],
    ///     [
    ///         [
    ///             "0x212a70dcc09edeec28395055af7e833738fb75c29deab5064b9b9e37a31c8da8",
    ///             "0x78483f082d5322abd197f76caf5462085d0a9cfd8959b1c0580477369b14a80"
    ///         ],
    ///         [
    ///             "0x304ad6ab04c20d868deaa949196491cb25a3a6bdbcc0ca8c8ffe1af71f68d13b",
    ///             "0x14248ec88a16d87d7cfd65c9092a43bbbacb6b3280f2142247bb9714f553ef6f"
    ///         ]
    ///     ],
    ///     [
    ///         "0x2a2890f6aed38cc31a9426d7db515ee0097b013d66e15628f54298e379c88a3e",
    ///         "0x8eacd3b8507b795f987fe76fcc0df262021e719654426dcc87eca4eb8f5399b"
    ///     ]
    /// ]"#;
    ///
    /// let ver_req = VerificationRequest {
    ///     id_commitment: hash_to_field(b"0x1234567890abcdef"),
    ///     nullifier_hash: hash_to_field(b"0xabcdef1234567890"),
    ///     challenge: "Hello, world!".to_string(),
    ///     scope: "0x0987654321fedcba".to_string(),
    ///     proof: serde_json::from_str(proof).unwrap(),
    /// };
    /// let result = SemaphoreVerifier.verify(&ver_req);
    /// assert_eq!(result.unwrap(), false);
    /// ```
    #[instrument(skip_all)]
    fn verify(&self, req: &VerificationRequest) -> Result<bool, ProofError> {
        let challenge_hash = hash_to_field(req.challenge.as_bytes());
        let scope_hash = hash_to_field(req.scope.as_bytes());
        debug!("verifying proof");
        verify_proof(
            TREE_DEPTH,
            req.id_commitment,
            req.nullifier_hash,
            challenge_hash,
            scope_hash,
            &req.proof,
        )
    }
}

/// Classification of a challenge timestamp relative to "now".
///
/// This is the freshness *policy* for a verification request, kept separate from
/// the cryptographic check ([`ProofVerifier`]) and from HTTP/metrics concerns
/// (which stay in the handler). The handler maps each variant to its response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeFreshness {
    /// The challenge string is not a valid RFC 3339 timestamp.
    Unparseable,
    /// The timestamp is further in the future than the clock-skew tolerance allows.
    InFuture,
    /// The timestamp is older than the maximum accepted age.
    Expired,
    /// The timestamp is within the accepted window.
    Fresh,
}

/// Result of a freshness evaluation.
///
/// `age` is `Some` only when the timestamp parsed *and* was not rejected as
/// in-future — i.e. exactly the cases for which the caller records the age
/// metric. It can be slightly negative for timestamps within the skew tolerance.
#[derive(Clone, Copy, Debug)]
pub struct FreshnessCheck {
    pub freshness: ChallengeFreshness,
    pub age: Option<Duration>,
}

/// Evaluates whether a challenge timestamp is fresh enough to verify against.
///
/// Pure function: no clock reads, no metrics, no I/O — `now` is injected so the
/// policy is fully testable. Ordering of the checks (parse → future → age)
/// preserves the original handler behavior exactly.
pub fn check_freshness(
    challenge: &str,
    now: DateTime<Utc>,
    max_age: Duration,
    clock_skew_tolerance: Duration,
) -> FreshnessCheck {
    let parsed = match DateTime::parse_from_rfc3339(challenge) {
        Ok(dt) => dt.with_timezone(&Utc),
        Err(_) => {
            return FreshnessCheck {
                freshness: ChallengeFreshness::Unparseable,
                age: None,
            }
        }
    };

    if parsed > now + clock_skew_tolerance {
        return FreshnessCheck {
            freshness: ChallengeFreshness::InFuture,
            age: None,
        };
    }

    let age = now - parsed;
    let freshness = if age > max_age {
        ChallengeFreshness::Expired
    } else {
        ChallengeFreshness::Fresh
    };
    FreshnessCheck {
        freshness,
        age: Some(age),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn unparseable_timestamp_is_classified_and_carries_no_age() {
        let now = at("2024-01-01T00:00:00Z");
        let check = check_freshness(
            "not a timestamp",
            now,
            Duration::seconds(300),
            Duration::seconds(2),
        );
        assert_eq!(check.freshness, ChallengeFreshness::Unparseable);
        assert!(check.age.is_none());
    }

    #[test]
    fn future_beyond_skew_is_in_future_and_carries_no_age() {
        let now = at("2024-01-01T00:00:00Z");
        let check = check_freshness(
            "2024-01-01T00:00:10Z",
            now,
            Duration::seconds(300),
            Duration::seconds(2),
        );
        assert_eq!(check.freshness, ChallengeFreshness::InFuture);
        assert!(check.age.is_none());
    }

    #[test]
    fn future_within_skew_is_fresh_and_records_negative_age() {
        let now = at("2024-01-01T00:00:00Z");
        let check = check_freshness(
            "2024-01-01T00:00:01Z",
            now,
            Duration::seconds(300),
            Duration::seconds(2),
        );
        assert_eq!(check.freshness, ChallengeFreshness::Fresh);
        assert_eq!(check.age, Some(Duration::seconds(-1)));
    }

    #[test]
    fn old_timestamp_is_expired_and_records_age() {
        let now = at("2024-01-01T00:10:00Z");
        let check = check_freshness(
            "2024-01-01T00:00:00Z",
            now,
            Duration::seconds(300),
            Duration::seconds(2),
        );
        assert_eq!(check.freshness, ChallengeFreshness::Expired);
        assert_eq!(check.age, Some(Duration::seconds(600)));
    }

    #[test]
    fn recent_timestamp_is_fresh() {
        let now = at("2024-01-01T00:01:00Z");
        let check = check_freshness(
            "2024-01-01T00:00:00Z",
            now,
            Duration::seconds(300),
            Duration::seconds(2),
        );
        assert_eq!(check.freshness, ChallengeFreshness::Fresh);
        assert_eq!(check.age, Some(Duration::seconds(60)));
    }
}
