use semaphore_rs::protocol::Proof;
use semaphore_rs::Field;
use serde::{Deserialize, Serialize};

/// A struct representing a proof of inclusion for a given id commitment, challenge and external nullifier.
///
/// The `Verification` struct contains the following fields:
///
/// * `id_commitment`: A `Field` representing the commitment to the identity of the user.
/// * `nullifier_hash`: A `Field` representing the hash of the nullifier for the user.
/// * `challenge`: A `String` (an RFC 3339 timestamp) for which the proof is being verified.
/// * `scope`: A `String` representing the external nullifier for the user.
/// * `proof`: A `Proof` representing the proof of inclusion for the challenge and nullifier.
///
/// # Examples
///
/// ```
/// use world_id_proof_verification_service::models::verification_model::VerificationRequest;
/// use semaphore_rs::protocol::Proof;
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
///
/// let ver = VerificationRequest {
///     id_commitment: hash_to_field(b"0x1234567890abcdef"),
///     nullifier_hash: hash_to_field(b"0xabcdef1234567890"),
///     challenge: "Hello, world!".to_string(),
///     scope: "0x0987654321fedcba".to_string(),
///     proof: serde_json::from_str(proof).unwrap(),
/// };
/// assert_eq!(ver.challenge, "Hello, world!");
/// assert_eq!(ver.scope, "0x0987654321fedcba");
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationRequest {
    pub id_commitment: Field,
    pub nullifier_hash: Field,
    pub challenge: String,
    pub scope: String,
    pub proof: Proof,
}
