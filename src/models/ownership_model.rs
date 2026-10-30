pub use api_types::{
    VerificationMsg as OwnershipVerificationMsg,
    VerificationRequest as OwnershipVerificationRequest,
    VerificationResult as OwnershipVerificationResult,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use world_id_primitives::FieldElement;

/// The credential subject (`sub`), the circuit's `commitment` public input.
pub type CredentialSub = FieldElement;
// Re-exported, not re-modelled, so the decoded type is exactly what the verifier consumes.
pub use world_id_primitives::proof::OwnershipProof;
/// Internal failure class only; the response collapses both to one coarse 400.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofDecodeError {
    Base64,
    Cbor,
}

/// Takes the blob by value so the 760 KiB base64 `String` is freed before
/// `ciborium` allocates the decoded fields, keeping both the transient decode
/// peak and the per-request retention off the caller's memory budget.
pub fn decode_proof(blob: String) -> Result<OwnershipProof, ProofDecodeError> {
    let bytes = BASE64_STANDARD
        .decode(&blob)
        .map_err(|_| ProofDecodeError::Base64)?;
    drop(blob);
    ciborium::from_reader(bytes.as_slice()).map_err(|_| ProofDecodeError::Cbor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::challenge_model::ChallengeId;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
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

    // Mirrors walletkit's `OwnershipProof::encode()`.
    fn encode_proof(proof: &OwnershipProof) -> String {
        let mut bytes = Vec::new();
        ciborium::into_writer(proof, &mut bytes).unwrap();
        BASE64_STANDARD.encode(bytes)
    }

    fn sample_request() -> OwnershipVerificationRequest {
        OwnershipVerificationRequest {
            challenge_id: ChallengeId::from_u128(0x1234_5678_90ab_cdef_1234_5678_90ab_cdef),
            credential_sub: FieldElement::from(7u64).to_string(),
            proof: encode_proof(&sample_proof()),
        }
    }

    #[test]
    fn request_json_roundtrips() {
        let req = sample_request();
        let json = serde_json::to_string(&req).unwrap();
        let decoded: OwnershipVerificationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_has_expected_wire_shape() {
        let json = serde_json::to_value(sample_request()).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 3);
        assert_eq!(
            obj["challenge_id"],
            serde_json::json!("12345678-90ab-cdef-1234-567890abcdef")
        );
        assert_eq!(
            obj["credential_sub"],
            serde_json::json!(format!("0x{}7", "0".repeat(63)))
        );
        assert!(obj["proof"].is_string());
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
        let mut req = sample_request();
        req.proof = serde_json::from_str(GO_JSON_PROOF).unwrap();
        assert_eq!(decode_proof(req.proof).unwrap(), sample_proof());
    }

    #[test]
    fn padded_go_json_marshal_output_decodes() {
        let mut expected = sample_proof();
        expected.proof.narg_string = vec![1, 2, 3, 4, 5];

        let mut req = sample_request();
        req.proof = serde_json::from_str(GO_JSON_PROOF_PADDED).unwrap();
        assert_eq!(decode_proof(req.proof).unwrap(), expected);
    }

    #[test]
    fn proof_blob_roundtrips_through_decode() {
        let req = sample_request();
        assert_eq!(decode_proof(req.proof).unwrap(), sample_proof());
    }

    #[test]
    fn unpadded_base64_is_rejected() {
        let mut req = sample_request();
        // Only the padded fixture has trailing `=` to strip.
        req.proof = serde_json::from_str::<String>(GO_JSON_PROOF_PADDED)
            .unwrap()
            .trim_end_matches('=')
            .to_string();
        assert_eq!(decode_proof(req.proof), Err(ProofDecodeError::Base64));
    }

    #[test]
    fn non_base64_proof_is_a_base64_error() {
        let mut req = sample_request();
        req.proof = "not/base64!!".to_string();
        assert_eq!(decode_proof(req.proof), Err(ProofDecodeError::Base64));
    }

    #[test]
    fn valid_base64_of_garbage_is_a_cbor_error() {
        let mut req = sample_request();
        req.proof = BASE64_STANDARD.encode(b"definitely not cbor");
        assert_eq!(decode_proof(req.proof), Err(ProofDecodeError::Cbor));
    }

    #[test]
    fn response_serializes_to_coarse_strings() {
        let accepted = OwnershipVerificationResult {
            msg: OwnershipVerificationMsg::ProofAccepted,
        };
        let rejected = OwnershipVerificationResult {
            msg: OwnershipVerificationMsg::ProofRejected,
        };
        assert_eq!(
            serde_json::to_string(&accepted).unwrap(),
            r#"{"msg":"proof_accepted"}"#
        );
        assert_eq!(
            serde_json::to_string(&rejected).unwrap(),
            r#"{"msg":"proof_rejected"}"#
        );
    }

    #[test]
    fn response_deserializes_from_coarse_strings() {
        let decoded: OwnershipVerificationResult =
            serde_json::from_str(r#"{"msg":"proof_rejected"}"#).unwrap();
        assert_eq!(decoded.msg, OwnershipVerificationMsg::ProofRejected);
    }
}
