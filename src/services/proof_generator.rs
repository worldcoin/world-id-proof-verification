use crate::cfg::config::TREE_DEPTH;
use crate::models::generation_model::Generation;
use chrono::{DateTime, Utc};
use semaphore_rs::{
    hash_to_field,
    identity::Identity,
    protocol::{self, generate_nullifier_hash, Proof, ProofError},
    Field,
};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::instrument;

/// The outcome of one proof-generation attempt.
///
/// The cryptographic metadata (`nullifier_hash`, `id_commitment`,
/// `signal_timestamp`) is derived from the request regardless of whether proof
/// generation itself succeeds, so it sits alongside the fallible `proof`. Named
/// fields replace the previous positional 4-tuple, which forced callers to
/// remember the order.
#[derive(Debug)]
pub struct GeneratedProof {
    /// The generated inclusion proof, or the protocol error that prevented it.
    pub proof: Result<Proof, ProofError>,
    /// Hash of the nullifier for this identity + external nullifier.
    pub nullifier_hash: Field,
    /// The identity commitment derived from the secret.
    pub id_commitment: Field,
    /// The RFC 3339 timestamp used as the signal, echoed back as the challenge.
    pub signal_timestamp: String,
}

/// A trait port for generating a World ID inclusion proof from a [`Generation`]
/// request.
///
/// The trait exists as an injection/mocking seam so the (staging-only)
/// generation endpoint can be driven by a stub in tests
/// without running the real, slow proving path.
pub trait ProofGenerator: Send + Sync {
    /// Generates a proof of inclusion for the secret, signal and external
    /// nullifier carried by `req`.
    fn generate(&self, req: &Generation) -> GeneratedProof;
}

/// Shared, thread-safe handle to the active [`ProofGenerator`] implementation,
/// injected into the generation handler via an axum `Extension`.
pub type DynProofGenerator = Arc<dyn ProofGenerator>;

/// The production [`ProofGenerator`], backed by `semaphore-rs`. Stateless.
#[derive(Clone, Copy, Debug, Default)]
pub struct SemaphoreProofGenerator;

impl ProofGenerator for SemaphoreProofGenerator {
    /// Generates a proof of inclusion for a given secret, signal and external nullifier.
    ///
    /// The input [`Generation`] carries:
    ///
    /// * `secret`: A `String` representing a secret that should be only known to the user.
    /// * `external_nullifier`: A `String` representing the topic or scope.
    ///
    /// It derives the identity commitment, hashes the external nullifier, and uses `semaphore-rs`
    /// to generate the inclusion proof. The returned [`GeneratedProof`] always carries the
    /// nullifier hash, id commitment and signal timestamp; its `proof` field holds the proof on
    /// success or the `ProofError` on failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use world_id_proof_verification_service::models::generation_model::Generation;
    /// use world_id_proof_verification_service::services::proof_generator::{ProofGenerator, SemaphoreProofGenerator};
    ///
    /// let gen_req = Generation {
    ///     secret: "abcxyz".to_string(),
    ///     external_nullifier: "pii.deletion".to_string(),
    /// };
    /// let generated = SemaphoreProofGenerator.generate(&gen_req);
    /// assert_eq!(generated.nullifier_hash.to_string(), "17238294235436223690376387159136240851395037634179391499515409485191016529483");
    /// assert_eq!(generated.id_commitment.to_string(), "21248771108105435485385025812291755517742717832250258948001341434621332305558");
    /// ```
    #[instrument(skip_all)]
    fn generate(&self, req: &Generation) -> GeneratedProof {
        let mut secret = req.secret.clone().into_bytes();
        let id = Identity::from_secret(&mut secret, None);

        let (signal_hash, signal_timestamp) = current_signal();

        let external_nullifier_hash = hash_to_field(req.external_nullifier.as_bytes());

        let proof = protocol::authentication::generate_proof(
            TREE_DEPTH,
            &id,
            external_nullifier_hash,
            signal_hash,
        );
        let nullifier_hash = generate_nullifier_hash(&id, external_nullifier_hash);

        GeneratedProof {
            proof,
            nullifier_hash,
            id_commitment: id.commitment(),
            signal_timestamp,
        }
    }
}

/// Builds the signal from the current time: the RFC 3339 string (echoed back as
/// the challenge) and its field-hash (fed into the proof).
fn current_signal() -> (Field, String) {
    let now: DateTime<Utc> = SystemTime::now().into();
    let now = now.to_rfc3339();
    let signal_hash = hash_to_field(now.as_bytes());
    (signal_hash, now)
}
