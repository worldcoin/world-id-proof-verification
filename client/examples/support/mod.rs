//! Private credentials for the deliberately trusted stage CI issuer.

use std::time::{SystemTime, UNIX_EPOCH};

use attested_request::{profile::Platform, sign::Signer};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    ecdsa::{
        Signature, SigningKey,
        signature::{Signer as _, hazmat::PrehashSigner as _},
    },
    elliptic_curve::Generate,
    pkcs8::DecodePrivateKey,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("expected an unencrypted PKCS#8 PEM P-256 CI issuer private key")]
    InvalidPrivateKey,
    #[error("could not generate a request key using system randomness")]
    Randomness,
    #[error("system clock cannot represent the integrity token validity interval")]
    InvalidClock,
    #[error("P-256 signing failed")]
    Sign,
}

pub(crate) struct StagingCiCredentials {
    issuer_key: SigningKey,
    request_key: SigningKey,
}

impl StagingCiCredentials {
    pub(crate) fn new(pem: &str) -> Result<Self, SigningError> {
        Ok(Self {
            issuer_key: SigningKey::from_pkcs8_pem(pem)
                .map_err(|_| SigningError::InvalidPrivateKey)?,
            request_key: SigningKey::try_generate().map_err(|_| SigningError::Randomness)?,
        })
    }

    pub(crate) fn integrity_token(&self) -> Result<String, SigningError> {
        let issued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SigningError::InvalidClock)?
            .as_secs();
        let expires_at = issued_at
            .checked_add(300)
            .ok_or(SigningError::InvalidClock)?;
        let point = self.request_key.verifying_key().to_sec1_point(false);
        let bytes = point.as_bytes();
        let header = json!({"alg": "ES256", "typ": "JWT", "kid": "test-integrity-kid"});
        let claims = json!({
            "iss": "ci.attestation.worldcoin.dev",
            "aud": "app.stage.orb.worldcoin.org",
            "iat": issued_at,
            "exp": expires_at,
            "pass": true,
            "platform": "android",
            "cnf": {"jwk": {
                "kty": "EC", "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(&bytes[1..33]),
                "y": URL_SAFE_NO_PAD.encode(&bytes[33..65]),
            }},
        });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string()),
        );
        // JWTs sign the original input and encode raw R || S, unlike request signatures.
        let signature: Signature = self
            .issuer_key
            .try_sign(input.as_bytes())
            .map_err(|_| SigningError::Sign)?;
        Ok(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }
}

impl Signer for StagingCiCredentials {
    type Error = SigningError;

    fn platform(&self) -> Platform {
        Platform::Android
    }

    fn sign(&self, digest: &[u8; 32]) -> Result<Vec<u8>, SigningError> {
        // The canonical signing library already hashed the request; emit Android DER.
        let signature: Signature = self
            .request_key
            .sign_prehash(digest)
            .map_err(|_| SigningError::Sign)?;
        Ok(signature.to_der().as_bytes().to_vec())
    }
}
