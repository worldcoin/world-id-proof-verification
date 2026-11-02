use std::sync::Arc;

use crate::models::ownership_model::CredentialSub;
use crate::models::ownership_model::OwnershipProof;
use world_id_primitives::FieldElement;
use world_id_proof::artifacts::ZkArtifactSource;
use world_id_proof::ProofError;
/// Injection/mocking seam over `world_id_proof`'s `verify_ownership_proof`, whose
/// signature and `Result<(), ProofError>` contract it mirrors exactly.
pub trait OwnershipProofVerifier: Send + Sync {
    fn verify(
        &self,
        proof: &OwnershipProof,
        nonce: FieldElement,
        credential_sub: CredentialSub,
        context: FieldElement,
        artifacts: &dyn ZkArtifactSource,
    ) -> Result<(), ProofError>;
}

pub type DynOwnershipProofVerifier = Arc<dyn OwnershipProofVerifier>;
/// Production verifier, delegating to `world_id_proof` (`embed-ownership-verifier`).
#[derive(Clone, Copy, Debug, Default)]
pub struct WorldIdOwnershipVerifier;

impl OwnershipProofVerifier for WorldIdOwnershipVerifier {
    /// Runs the WHIR/ProveKit verifier inside a dedicated single-thread Rayon
    /// pool, scoped to this call only.
    ///
    /// The verifier fans out across Rayon's *process-wide default* pool
    /// internally (measured ~2.3 effective cores per call). A fresh pool per
    /// call — rather than `RAYON_NUM_THREADS=1` — keeps that limit local to
    /// this call: it doesn't affect the Groth16 verifier's own Rayon-capable
    /// path (`ark-groth16`/`ark-crypto-primitives`, `parallel` feature) or any
    /// future unrelated Rayon consumer in this process, and concurrent calls
    /// each get an exclusive pool instead of contending for one shared thread
    /// (which measurably worsened throughput under concurrency versus the
    /// process-wide env var).
    fn verify(
        &self,
        proof: &OwnershipProof,
        nonce: FieldElement,
        credential_sub: CredentialSub,
        context: FieldElement,
        artifacts: &dyn ZkArtifactSource,
    ) -> Result<(), ProofError> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .map_err(|error| {
                ProofError::InternalError(eyre::eyre!(
                    "failed to build single-threaded rayon pool for ownership proof verification: {error}"
                ))
            })?;
        // Rayon runs on a different OS thread too; retain request/stage context
        // for verifier diagnostics and the telemetry panic hook.
        let span = tracing::Span::current();
        pool.install(|| {
            let _entered = span.enter();
            world_id_proof::ownership_proof::verify_ownership_proof(
                proof,
                nonce,
                credential_sub,
                context,
                artifacts,
            )
        })
    }
}
