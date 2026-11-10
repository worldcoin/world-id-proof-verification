use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use api_types::ChallengeType;
use async_trait::async_trait;
use attested_request::{
    Platform, Verifier,
    sign::Signer,
    test_util::{SoftwareSigner, TestClaims, TestIssuer, test_key},
    token::{IssuerKeys, TokenVerifier},
};
use attested_request_tower::AttestedRequestLayer;
use axum::{Json, Router, http::StatusCode, routing::post};
use serde_json::json;
use world_id_proof_verification_client::{AuthProvider, ChallengeError, Client, Config};

struct NoVerifyAuth;
#[async_trait]
impl AuthProvider for NoVerifyAuth {
    async fn token(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        panic!("challenge must not request a verification JWT")
    }
}

async fn server(
    router: impl FnOnce(&str) -> Router,
    timeout: Duration,
) -> (Client, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let router = router(&authority);
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = Client::new(
        Config {
            host: format!("http://{authority}"),
            timeout,
            pool_max_idle_per_host: 1,
        },
        Arc::new(NoVerifyAuth),
    )
    .unwrap();
    (client, task)
}

#[tokio::test]
async fn signed_challenges_pass_real_verifier() {
    let issuer = TestIssuer::new("issuer");
    let keys: Arc<dyn IssuerKeys> = Arc::new(issuer.keys());
    let tokens =
        TokenVerifier::new([("issuer".to_owned(), keys)], ["audience".to_owned()]).unwrap();
    let (client, task) = server(
        |authority| {
            let verifier = Verifier::builder(tokens, authority)
                .scheme("http")
                .build()
                .unwrap();
            Router::new()
                .route(
                    "/api/v4/zkp/challenge/enrollment",
                    post(|| async {
                        (
                            StatusCode::CREATED,
                            Json(json!({
                                "challenge_id": "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31",
                                "nonce": "nonce", "challenge_type": "enrollment",
                                "expires_at": "2030-01-01T00:00:00Z"
                            })),
                        )
                    }),
                )
                .layer(AttestedRequestLayer::new(Arc::new(verifier)))
        },
        Duration::from_secs(5),
    )
    .await;
    for platform in [Platform::Android, Platform::Ios] {
        let signer = Arc::new(SoftwareSigner::new(test_key("device"), platform));
        let token = issuer.mint(&TestClaims::valid(
            "audience",
            platform,
            signer.verifying_key(),
            SystemTime::now(),
        ));
        let response = client
            .challenge(ChallengeType::Enrollment, &token, signer)
            .await
            .unwrap();
        assert_eq!(response.nonce, "nonce");
        assert_eq!(response.challenge_type, ChallengeType::Enrollment);
    }
    assert!(matches!(
        client
            .challenge(ChallengeType::Enrollment, "token", Arc::new(FailingSigner))
            .await,
        Err(ChallengeError::Signing(_))
    ));
    task.abort();
}

struct FailingSigner;
impl Signer for FailingSigner {
    type Error = std::io::Error;
    fn platform(&self) -> Platform {
        Platform::Android
    }
    fn sign(&self, _: &[u8; 32]) -> Result<Vec<u8>, Self::Error> {
        Err(std::io::Error::other("device unavailable"))
    }
}
