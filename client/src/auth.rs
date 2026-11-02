//! Short-lived JWTs signed by AWS KMS for service-to-service authentication.
//!
//! Uses ES256 via `ECDSA_SHA_256` with a five-minute token lifetime.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use aws_sdk_kms::{
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use tokio::sync::Mutex;

const TOKEN_LIFETIME: Duration = Duration::from_secs(5 * 60);
/// Re-sign this long before `exp` so the server still accepts the token.
const REFRESH_SKEW: Duration = Duration::from_secs(30);
/// Bounds a KMS `Sign`, including retries. `token` holds the cache mutex across
/// that call, so the client passed to [`JwtAuthProvider::new`] is rebuilt with
/// this operation timeout.
const SIGN_TIMEOUT: Duration = Duration::from_secs(10);

#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn token(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>>;
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("KMS key ID must not be empty")]
    MissingKeyId,
    #[error("failed to encode JWT claims: {0}")]
    Encode(#[source] serde_json::Error),
    #[error("KMS sign failed: {0}")]
    KmsSign(String),
    #[error("KMS returned an empty signature")]
    EmptySignature,
    #[error("failed to parse DER signature")]
    InvalidDer,
}

#[async_trait]
trait JwtSigner: Send + Sync {
    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, AuthError>;
}

struct KmsSigner {
    client: aws_sdk_kms::Client,
    key_id: String,
}

#[async_trait]
impl JwtSigner for KmsSigner {
    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, AuthError> {
        let output = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(signing_input))
            .message_type(MessageType::Raw)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await
            .map_err(|error| AuthError::KmsSign(error.to_string()))?;
        output
            .signature
            .map(|signature| signature.into_inner())
            .ok_or(AuthError::EmptySignature)
    }
}

struct CachedToken {
    token: String,
    /// Sign again once `SystemTime::now()` reaches this instant.
    refresh_at: SystemTime,
}

/// Issues ES256 JWTs with `sub` and `exp`, signed by KMS.
///
/// A token is reused until [`REFRESH_SKEW`] before its `exp`, so a burst of
/// verify calls shares one KMS signature.
pub struct JwtAuthProvider {
    signer: Arc<dyn JwtSigner>,
    subject: String,
    lifetime: Duration,
    cache: Mutex<Option<CachedToken>>,
}

impl JwtAuthProvider {
    pub fn new(
        kms: aws_sdk_kms::Client,
        kms_key_id: impl Into<String>,
        subject: impl Into<String>,
    ) -> Result<Self, AuthError> {
        let kms_key_id = kms_key_id.into();
        if kms_key_id.is_empty() {
            return Err(AuthError::MissingKeyId);
        }
        Ok(Self {
            signer: Arc::new(KmsSigner {
                client: with_sign_timeout(kms),
                key_id: kms_key_id,
            }),
            subject: subject.into(),
            lifetime: TOKEN_LIFETIME,
            cache: Mutex::new(None),
        })
    }

    async fn generate_token(&self) -> Result<CachedToken, AuthError> {
        let now = SystemTime::now();
        let exp = now
            .checked_add(self.lifetime)
            .unwrap_or(now)
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let refresh_at = now
            .checked_add(self.lifetime)
            .and_then(|exp| exp.checked_sub(REFRESH_SKEW))
            .unwrap_or(now);

        #[derive(Serialize)]
        struct Header {
            alg: &'static str,
            typ: &'static str,
        }
        #[derive(Serialize)]
        struct Claims<'a> {
            sub: &'a str,
            exp: u64,
        }

        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Header {
            alg: "ES256",
            typ: "JWT",
        })?);
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Claims {
            sub: &self.subject,
            exp,
        })?);
        let signing_input = format!("{header}.{claims}");
        let der = self.signer.sign(signing_input.as_bytes()).await?;
        let signature = der_to_jws(&der)?;
        Ok(CachedToken {
            token: format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature)),
            refresh_at,
        })
    }
}

impl From<serde_json::Error> for AuthError {
    fn from(error: serde_json::Error) -> Self {
        Self::Encode(error)
    }
}

#[async_trait]
impl AuthProvider for JwtAuthProvider {
    async fn token(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let mut cache = self.cache.lock().await;
        if let Some(cached) = cache.as_ref()
            && SystemTime::now() < cached.refresh_at
        {
            return Ok(cached.token.clone());
        }
        let issued = self
            .generate_token()
            .await
            .map_err(|error| AuthError::KmsSign(error.to_string()))
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
        let token = issued.token.clone();
        *cache = Some(issued);
        Ok(token)
    }
}

fn with_sign_timeout(client: aws_sdk_kms::Client) -> aws_sdk_kms::Client {
    let timeout = aws_sdk_kms::config::timeout::TimeoutConfig::builder()
        .operation_timeout(SIGN_TIMEOUT)
        .operation_attempt_timeout(SIGN_TIMEOUT)
        .build();
    aws_sdk_kms::Client::from_conf(client.config().to_builder().timeout_config(timeout).build())
}

/// Converts a DER-encoded ECDSA signature to JWS `R || S` (64 bytes for P-256).
fn der_to_jws(der: &[u8]) -> Result<[u8; 64], AuthError> {
    let signature = p256::ecdsa::Signature::from_der(der).map_err(|_| AuthError::InvalidDer)?;
    Ok(signature.to_bytes().into())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct CountingSigner {
        der: Vec<u8>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl JwtSigner for CountingSigner {
        async fn sign(&self, _signing_input: &[u8]) -> Result<Vec<u8>, AuthError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.der.clone())
        }
    }

    fn provider(calls: Arc<AtomicUsize>, lifetime: Duration) -> JwtAuthProvider {
        JwtAuthProvider {
            signer: Arc::new(CountingSigner {
                der: der_r1_s1(),
                calls,
            }),
            subject: "example-client".to_owned(),
            lifetime,
            cache: Mutex::new(None),
        }
    }

    fn dummy_kms() -> aws_sdk_kms::Client {
        aws_sdk_kms::Client::from_conf(
            aws_sdk_kms::Config::builder()
                .region(aws_sdk_kms::config::Region::new("us-east-1"))
                .behavior_version(aws_sdk_kms::config::BehaviorVersion::latest())
                .credentials_provider(aws_sdk_kms::config::Credentials::new(
                    "test", "test", None, None, "test",
                ))
                .build(),
        )
    }

    fn der_r1_s1() -> Vec<u8> {
        // SEQUENCE { INTEGER 1, INTEGER 1 }
        vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]
    }

    #[test]
    fn der_to_jws_pads_r_and_s_to_32_bytes() {
        let jws = der_to_jws(&der_r1_s1()).unwrap();
        assert_eq!(jws.len(), 64);
        assert_eq!(&jws[..31], &[0; 31]);
        assert_eq!(jws[31], 1);
        assert_eq!(&jws[32..63], &[0; 31]);
        assert_eq!(jws[63], 1);
    }

    #[test]
    fn der_to_jws_strips_sign_padding() {
        // INTEGER 0x80 is encoded as 00 80.
        let der = vec![0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x00, 0x81];
        let jws = der_to_jws(&der).unwrap();
        assert_eq!(jws[31], 0x80);
        assert_eq!(jws[63], 0x81);
        assert_eq!(&jws[..31], &[0; 31]);
        assert_eq!(&jws[32..63], &[0; 31]);
    }

    #[test]
    fn der_to_jws_rejects_trailing_bytes() {
        let mut der = der_r1_s1();
        der.push(0x00);
        assert!(matches!(der_to_jws(&der), Err(AuthError::InvalidDer)));
    }

    #[test]
    fn new_rejects_an_empty_key_id() {
        assert!(matches!(
            JwtAuthProvider::new(dummy_kms(), "", "example-client"),
            Err(AuthError::MissingKeyId)
        ));
    }

    #[tokio::test]
    async fn token_is_an_es256_jwt_with_sub_and_exp() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        let token = AuthProvider::token(&provider(Arc::new(AtomicUsize::new(0)), TOKEN_LIFETIME))
            .await
            .unwrap();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;

        let parts: Vec<_> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");

        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["sub"], "example-client");
        let exp = claims["exp"].as_u64().unwrap();
        assert!(
            (before..=after).contains(&exp),
            "exp {exp} not in {before}..={after}"
        );

        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[tokio::test]
    async fn token_is_reused_until_refresh() {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = provider(Arc::clone(&calls), TOKEN_LIFETIME);
        let first = AuthProvider::token(&provider).await.unwrap();
        let second = AuthProvider::token(&provider).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn token_is_resigned_when_the_lifetime_is_inside_the_refresh_skew() {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = provider(Arc::clone(&calls), REFRESH_SKEW);
        AuthProvider::token(&provider).await.unwrap();
        AuthProvider::token(&provider).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn sign_timeout_is_set_on_the_kms_client() {
        let client = with_sign_timeout(dummy_kms());
        let timeout = client.config().timeout_config().unwrap();
        assert_eq!(timeout.operation_timeout(), Some(SIGN_TIMEOUT));
        assert_eq!(timeout.operation_attempt_timeout(), Some(SIGN_TIMEOUT));
    }
}
