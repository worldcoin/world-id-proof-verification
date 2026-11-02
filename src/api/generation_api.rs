use crate::api::bounded_json::LoggedJson;
use crate::{models::generation_model::Generation, services::proof_generator::DynProofGenerator};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use semaphore_rs::protocol::Proof;
use semaphore_rs::Field;
use serde::{Deserialize, Serialize};
use tracing::{error, info, instrument};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum GenerationMsg {
    #[serde(rename = "proof generation error")]
    ProofGenerationError,
    #[serde(rename = "proof generated successfully")]
    ProofGenerated,
}

use GenerationMsg::*;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerationResult {
    pub msg: GenerationMsg,
    pub proof: ZKP,
    pub proof_base64: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZKP {
    proof: String,
    nullifier_hash: Field,
    challenge: String,
    external_nullifier: String,
    id_commitment: String,
}

impl GenerationResult {
    fn new(
        gr: GenerationMsg,
        p: Proof,
        nh: Field,
        challenge: String,
        external_nullifier: String,
        id_comm: Field,
    ) -> Result<GenerationResult, serde_json::Error> {
        let zkp = ZKP {
            proof: serde_json::to_string(&p)?,
            nullifier_hash: nh,
            challenge,
            external_nullifier,
            id_commitment: format!("{id_comm:#066x}"),
        };
        let json = serde_json::to_string_pretty(&zkp)?;
        Ok(GenerationResult {
            msg: gr,
            proof: zkp,
            proof_base64: data_encoding::BASE64.encode(json.as_bytes()),
        })
    }
}

/// Maps a `GenerationResult` to its HTTP status and JSON body: `200` when a proof
/// was generated, `400` otherwise.
impl IntoResponse for GenerationResult {
    fn into_response(self) -> Response {
        let status = match self.msg {
            ProofGenerated => StatusCode::OK,
            _ => StatusCode::BAD_REQUEST,
        };
        (status, Json(self)).into_response()
    }
}

#[instrument(skip_all)]
pub async fn gen_proof(
    Extension(generator): Extension<DynProofGenerator>,
    LoggedJson(req): LoggedJson<Generation>,
) -> Response {
    let generated = generator.generate(&req);

    let result = match generated.proof {
        Ok(proof) => {
            info!("semaphore inclusion proof generated");
            GenerationResult::new(
                ProofGenerated,
                proof,
                generated.nullifier_hash,
                generated.signal_timestamp,
                req.external_nullifier,
                generated.id_commitment,
            )
        }
        Err(e) => {
            error!(stage = "proof_generation", error_kind = "generation_failed", error = %e, "semaphore inclusion proof generation failed");
            // Placeholder proof returned alongside the error message so the
            // response shape stays consistent with the success case.
            let empty_proof: &'static str =
                r#"[["0x0","0x0"],[ ["0x0","0x0"],["0x0","0x0"]],["0x0","0x0"]]"#;
            let empty_proof: Proof = match serde_json::from_str(empty_proof) {
                Ok(proof) => proof,
                Err(e) => {
                    error!(stage = "response_encode", error_kind = "placeholder_proof_invalid", error = %e, "failed to parse placeholder proof");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };
            GenerationResult::new(
                ProofGenerationError,
                empty_proof,
                generated.nullifier_hash,
                generated.signal_timestamp,
                req.external_nullifier,
                generated.id_commitment,
            )
        }
    };

    match result {
        Ok(generation_result) => generation_result.into_response(),
        Err(e) => {
            error!(stage = "response_encode", error_kind = "serialization_failed", error = %e, "failed to serialize generation result");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::config::TREE_DEPTH;
    use axum::http::StatusCode;
    use semaphore_rs::{
        hash_to_field,
        identity::Identity,
        protocol::{self, generate_nullifier_hash},
    };

    // Must stay byte-for-byte identical to the placeholder string in `gen_proof`.
    const EMPTY_PROOF_JSON: &str =
        r#"[["0x0","0x0"],[ ["0x0","0x0"],["0x0","0x0"]],["0x0","0x0"]]"#;

    fn sample_proof() -> (Proof, Field, Field) {
        let mut secret = *b"error-handling test secret";
        let id = Identity::from_secret(&mut secret[..], None);
        let external_nullifier = hash_to_field(b"test.scope");
        let signal = hash_to_field(b"2024-01-01T00:00:00.000Z");
        let proof =
            protocol::authentication::generate_proof(TREE_DEPTH, &id, external_nullifier, signal)
                .unwrap();
        let nullifier_hash = generate_nullifier_hash(&id, external_nullifier);
        (proof, nullifier_hash, id.commitment())
    }

    /// The error branch of `gen_proof` parses this constant into a `Proof`; if it
    /// ever failed to parse, the handler would return 500. Pin that it parses, so
    /// that defensive branch stays unreachable.
    #[test]
    fn placeholder_proof_constant_parses() {
        let parsed: Result<Proof, _> = serde_json::from_str(EMPTY_PROOF_JSON);
        assert!(parsed.is_ok(), "placeholder proof must parse: {parsed:?}");
    }

    /// `new` returns `Ok` for valid inputs, and `proof_base64` round-trips back
    /// to the serialized ZKP JSON (exercising the success path of the fallible
    /// constructor end to end).
    #[test]
    fn generation_result_new_ok_and_base64_roundtrips() {
        let (proof, nullifier_hash, id_comm) = sample_proof();
        let gr = GenerationResult::new(
            ProofGenerated,
            proof,
            nullifier_hash,
            "2024-01-01T00:00:00.000Z".to_string(),
            "test.scope".to_string(),
            id_comm,
        )
        .expect("serialization of valid inputs should succeed");

        // id_commitment is 0x + 64 lowercase hex chars.
        assert_eq!(gr.proof.id_commitment.len(), 66);
        assert!(gr.proof.id_commitment.starts_with("0x"));

        // proof_base64 decodes back to the serialized ZKP.
        let decoded = data_encoding::BASE64
            .decode(gr.proof_base64.as_bytes())
            .expect("proof_base64 must be valid base64");
        let json: serde_json::Value =
            serde_json::from_slice(&decoded).expect("decoded base64 must be JSON");
        assert!(json.get("proof").is_some());
        assert_eq!(
            json["idCommitment"].as_str().unwrap(),
            gr.proof.id_commitment.as_str()
        );
    }

    /// Response mapping: a generated proof maps to HTTP 200.
    #[test]
    fn proof_generated_maps_to_ok() {
        let (proof, nullifier_hash, id_comm) = sample_proof();
        let gr = GenerationResult::new(
            ProofGenerated,
            proof,
            nullifier_hash,
            "ts".to_string(),
            "scope".to_string(),
            id_comm,
        )
        .unwrap();
        let resp = gr.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Response mapping: a generation error maps to HTTP 400.
    #[test]
    fn proof_generation_error_maps_to_bad_request() {
        let (proof, nullifier_hash, id_comm) = sample_proof();
        let gr = GenerationResult::new(
            ProofGenerationError,
            proof,
            nullifier_hash,
            "ts".to_string(),
            "scope".to_string(),
            id_comm,
        )
        .unwrap();
        let resp = gr.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
