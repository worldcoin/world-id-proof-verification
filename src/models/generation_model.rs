use serde::{Deserialize, Serialize};

/// A struct representing a request to generate a proof of inclusion for a given secret and external nullifier.
///
/// The `Generation` struct contains the following fields:
///
/// * `secret`: A `String` representing the secret used to generate the identity commitment.
/// * `external_nullifier`: A `String` representing the external nullifier (scope); its hash is required to generate the semaphore proof.
///
/// # Examples
///
/// ```
/// use world_id_proof_verification_service::models::generation_model::Generation;
/// use serde_json::json;
///     
///
/// let gen = Generation {
///   secret: "d4f1c433-217a-434e-b044-2ca9c267591d".to_string(),
///   external_nullifier: "pii.deletion".to_string(),
/// };
/// assert_eq!(gen.secret, "d4f1c433-217a-434e-b044-2ca9c267591d");
/// assert_eq!(gen.external_nullifier, "pii.deletion");
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct Generation {
    pub secret: String,
    pub external_nullifier: String, // scope
}
