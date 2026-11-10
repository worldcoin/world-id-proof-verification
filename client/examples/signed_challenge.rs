//! Fetches a signed stage challenge using the existing CI issuer private key.

mod support;

use std::{env, error::Error, fs, io, sync::Arc, time::Duration};

use api_types::ChallengeType;
use async_trait::async_trait;
use support::StagingCiCredentials;
use world_id_proof_verification_client::{AuthProvider, Client, Config};
use zeroize::Zeroizing;

type ExampleError = Box<dyn Error + Send + Sync>;

// Challenges do not use verify's service JWT provider.
struct ChallengeOnlyAuth;

#[async_trait]
impl AuthProvider for ChallengeOnlyAuth {
    async fn token(&self) -> Result<String, ExampleError> {
        Err(io::Error::other("verify authentication is not configured").into())
    }
}

#[tokio::main]
async fn main() -> Result<(), ExampleError> {
    let pem = Zeroizing::new(match env::var("CI_CANONICAL_REQUEST_SIGNING_PRIVATE_KEY") {
        Ok(pem) => pem,
        Err(env::VarError::NotPresent) => {
            let path = env::var_os("CI_CANONICAL_REQUEST_SIGNING_PRIVATE_KEY_PATH")
                .unwrap_or_else(|| ".keys/ag_priv.pem".into());
            fs::read_to_string(path).map_err(|error| {
                io::Error::other(format!("could not read CI issuer key: {error}"))
            })?
        }
        Err(env::VarError::NotUnicode(_)) => {
            return Err(io::Error::other("CI issuer key environment must be valid UTF-8").into());
        }
    });
    let credentials = Arc::new(StagingCiCredentials::new(&pem)?);
    let token = credentials.integrity_token()?;
    let client = Client::new(
        Config {
            host: "https://app.stage.orb.worldcoin.org".to_owned(),
            timeout: Duration::from_secs(10),
            pool_max_idle_per_host: 1,
        },
        Arc::new(ChallengeOnlyAuth),
    )?;
    let challenge = client
        .challenge(ChallengeType::Enrollment, &token, credentials)
        .await?;
    println!("challenge issued: {}", challenge.challenge_id);
    Ok(())
}
