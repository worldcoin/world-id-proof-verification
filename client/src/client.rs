use std::{sync::Arc, time::Duration};

use api_types::ChallengeType;
use api_types::{VerificationMsg, VerificationResult};
use async_trait::async_trait;
use reqwest::{StatusCode, Url};

use crate::auth::AuthProvider;

pub const VERIFY_PATH: &str = "/api/v4/verify";
const CHALLENGE_PATH_PREFIX: &str = "/api/v4/zkp/challenge/";

/// Why [`Client::new`] failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to build the HTTP client: {0}")]
    Build(#[source] reqwest::Error),
    #[error("{host} is not a valid proof verification service host")]
    InvalidHost { host: String },
    #[error("proof verification service timeout must be greater than zero")]
    InvalidTimeout,
}

/// Why [`Client::verify`] did not accept the proof.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("proof rejected")]
    Rejected,
    #[error("verification service rejected the auth token")]
    Unauthorized,
    #[error("failed to get auth token: {0}")]
    Auth(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("request to the proof verification service timed out: {0}")]
    Timeout(#[source] reqwest::Error),
    #[error("request to the proof verification service was canceled: {0}")]
    Canceled(#[source] reqwest::Error),
    #[error("request to the proof verification service failed: {0}")]
    Connection(#[source] reqwest::Error),
    #[error("world-id-proof-verification-service returned {status}")]
    UnexpectedStatus { status: StatusCode },
}

/// Implemented by [`Client`]; tests may substitute a stub.
#[async_trait]
pub trait ProofVerificationClient: Send + Sync {
    /// `Ok(())` means the verification service accepted the proof.
    async fn verify(&self, request: VerificationRequest) -> Result<(), VerificationError>;
}

pub use api_types::{ChallengeResponse, VerificationRequest};

pub struct Config {
    pub host: String,
    pub timeout: Duration,
    pub pool_max_idle_per_host: usize,
}

/// Why [`Client::challenge`] failed.
#[derive(Debug, thiserror::Error)]
pub enum ChallengeError {
    #[error("challenge type must be a single path segment")]
    InvalidChallengeType,
    #[error("request to the proof verification service timed out: {0}")]
    Timeout(#[source] reqwest::Error),
    #[error("request to the proof verification service was canceled: {0}")]
    Canceled(#[source] reqwest::Error),
    #[error("request to the proof verification service failed: {0}")]
    Connection(#[source] reqwest::Error),
    #[error("world-id-proof-verification-service returned {status}")]
    UnexpectedStatus { status: StatusCode },
    #[error("challenge response was not the expected JSON: {0}")]
    Decode(#[source] serde_json::Error),
}

pub struct Client {
    http: reqwest::Client,
    base_url: Url,
    auth_provider: Arc<dyn AuthProvider>,
}

impl Client {
    pub fn new(config: Config, auth_provider: Arc<dyn AuthProvider>) -> Result<Self, Error> {
        if config.timeout.is_zero() {
            return Err(Error::InvalidTimeout);
        }
        let pool_max_idle_per_host = config.pool_max_idle_per_host.max(1);
        let http = reqwest::Client::builder()
            .pool_max_idle_per_host(pool_max_idle_per_host)
            .timeout(config.timeout)
            .build()
            .map_err(Error::Build)?;
        let host = config.host.trim_end_matches('/').to_owned();
        let base_url = Url::parse(&host).map_err(|_| Error::InvalidHost { host: config.host })?;

        Ok(Self {
            http,
            base_url,
            auth_provider,
        })
    }

    /// Asks the service for a single-use challenge of `challenge_type`.
    ///
    /// The route is public: this call does not send the verify JWT. `Ok` is an
    /// HTTP 201 whose body decoded as a [`ChallengeResponse`].
    pub async fn challenge(
        &self,
        challenge_type: ChallengeType,
    ) -> Result<ChallengeResponse, ChallengeError> {
        let url = challenge_url(&self.base_url, challenge_type)?;
        let response = self
            .http
            .post(url)
            .send()
            .await
            .map_err(challenge_transport)?;
        let status = response.status();
        let body = response.bytes().await.map_err(challenge_transport)?;
        if status != StatusCode::CREATED {
            return Err(ChallengeError::UnexpectedStatus { status });
        }
        serde_json::from_slice(&body).map_err(ChallengeError::Decode)
    }

    /// `Ok(())` means the verification service accepted the proof.
    pub async fn verify(&self, request: VerificationRequest) -> Result<(), VerificationError> {
        let token = self
            .auth_provider
            .token()
            .await
            .map_err(VerificationError::Auth)?;
        let mut verify_url = self.base_url.clone();
        verify_url.set_path(VERIFY_PATH);
        let response = self
            .http
            .post(verify_url)
            .json(&request)
            .bearer_auth(token)
            .send()
            .await
            .map_err(transport_error)?;

        let status = response.status();
        // Drain in full so the connection can return to the pool. The body also
        // distinguishes a rejected proof from a rejected JWT, which share 401.
        let body = response.bytes().await.map_err(transport_error)?;
        classify_status(status, &body)
    }
}

fn classify_status(status: StatusCode, body: &[u8]) -> Result<(), VerificationError> {
    match status {
        StatusCode::OK => Ok(()),
        StatusCode::UNAUTHORIZED => match serde_json::from_slice::<VerificationResult>(body) {
            Ok(body) if body.msg == VerificationMsg::ProofRejected => {
                Err(VerificationError::Rejected)
            }
            Ok(body) if body.msg == VerificationMsg::Unauthorized => {
                Err(VerificationError::Unauthorized)
            }
            _ => Err(VerificationError::UnexpectedStatus { status }),
        },
        status => Err(VerificationError::UnexpectedStatus { status }),
    }
}

#[async_trait]
impl ProofVerificationClient for Client {
    async fn verify(&self, request: VerificationRequest) -> Result<(), VerificationError> {
        Self::verify(self, request).await
    }
}

fn challenge_url(base_url: &Url, challenge_type: ChallengeType) -> Result<Url, ChallengeError> {
    let mut url = base_url.clone();
    url.set_path(&format!(
        "{CHALLENGE_PATH_PREFIX}{}",
        challenge_type.as_str()
    ));
    Ok(url)
}

fn transport_error(error: reqwest::Error) -> VerificationError {
    match classify_transport(error) {
        Transport::Timeout(error) => VerificationError::Timeout(error),
        Transport::Canceled(error) => VerificationError::Canceled(error),
        Transport::Connection(error) => VerificationError::Connection(error),
    }
}

fn challenge_transport(error: reqwest::Error) -> ChallengeError {
    match classify_transport(error) {
        Transport::Timeout(error) => ChallengeError::Timeout(error),
        Transport::Canceled(error) => ChallengeError::Canceled(error),
        Transport::Connection(error) => ChallengeError::Connection(error),
    }
}

enum Transport {
    Timeout(reqwest::Error),
    Canceled(reqwest::Error),
    Connection(reqwest::Error),
}

fn classify_transport(error: reqwest::Error) -> Transport {
    if error.is_timeout() {
        return Transport::Timeout(error);
    }
    if is_canceled(&error) {
        return Transport::Canceled(error);
    }
    Transport::Connection(error)
}

fn is_canceled(error: &reqwest::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(err) = source {
        if let Some(io) = err.downcast_ref::<std::io::Error>()
            && io.kind() == std::io::ErrorKind::Interrupted
        {
            return true;
        }
        let message = err.to_string();
        if message.contains("canceled") || message.contains("cancelled") {
            return true;
        }
        source = err.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use api_types::ChallengeType;
    use async_trait::async_trait;
    use axum::{
        Router,
        extract::OriginalUri,
        http::{HeaderMap, StatusCode, header},
        routing::post,
    };

    use super::{
        ChallengeError, Client, Config, Error, VERIFY_PATH, VerificationError, VerificationRequest,
    };
    use crate::auth::AuthProvider;

    struct StubAuth {
        token: Result<String, &'static str>,
    }

    #[async_trait]
    impl AuthProvider for StubAuth {
        async fn token(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
            self.token
                .clone()
                .map_err(|message| Box::new(std::io::Error::other(message)).into())
        }
    }

    fn test_request() -> VerificationRequest {
        serde_json::from_value(serde_json::json!({
            "challenge_id": "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31",
            "credential_sub": format!("0x{}7", "0".repeat(63)),
            "proof": "0xa100ff00deadbeef",
        }))
        .unwrap()
    }

    async fn serve(router: Router) -> (reqwest::Url, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (url, server)
    }

    fn verify_route<H, T>(handler: H) -> Router
    where
        H: axum::handler::Handler<T, ()> + Send + 'static,
        T: 'static,
    {
        Router::new().route(VERIFY_PATH, post(handler))
    }

    fn stub_auth(token: Result<String, &'static str>) -> Arc<dyn AuthProvider> {
        Arc::new(StubAuth { token })
    }

    fn client(host: &reqwest::Url, timeout: Duration) -> Client {
        Client::new(
            Config {
                host: host.to_string(),
                timeout,
                pool_max_idle_per_host: 2,
            },
            stub_auth(Ok("test-token".to_owned())),
        )
        .unwrap()
    }

    #[test]
    fn new_rejects_a_zero_timeout() {
        let result = Client::new(
            Config {
                host: "http://127.0.0.1:18080".to_owned(),
                timeout: Duration::ZERO,
                pool_max_idle_per_host: 1,
            },
            stub_auth(Ok("test-token".to_owned())),
        );

        assert!(matches!(result, Err(Error::InvalidTimeout)));
    }

    #[tokio::test]
    async fn verify_classifies_responses() {
        for status in [
            StatusCode::OK,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::BAD_REQUEST,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let seen_path = Arc::new(Mutex::new(String::new()));
            let seen_content_type = Arc::new(Mutex::new(String::new()));
            let seen_body = Arc::new(Mutex::new(None));
            let (url, server) = {
                let calls = Arc::clone(&calls);
                let seen_path = Arc::clone(&seen_path);
                let seen_content_type = Arc::clone(&seen_content_type);
                let seen_body = Arc::clone(&seen_body);
                serve(verify_route(
                    move |uri: OriginalUri, headers: HeaderMap, body: String| {
                        let calls = Arc::clone(&calls);
                        let seen_path = Arc::clone(&seen_path);
                        let seen_content_type = Arc::clone(&seen_content_type);
                        let seen_body = Arc::clone(&seen_body);
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            *seen_path.lock().unwrap() = uri.path().to_owned();
                            *seen_content_type.lock().unwrap() = headers
                                .get(header::CONTENT_TYPE)
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or_default()
                                .to_owned();
                            *seen_body.lock().unwrap() =
                                Some(serde_json::from_str::<VerificationRequest>(&body).unwrap());
                            status
                        }
                    },
                ))
                .await
            };

            let request = test_request();
            let error = client(&url, Duration::from_secs(2))
                .verify(request.clone())
                .await;

            match status {
                StatusCode::OK => assert!(error.is_ok(), "{error:?}"),
                status => match error {
                    Err(VerificationError::UnexpectedStatus { status: got }) => {
                        assert_eq!(got, status);
                    }
                    other => panic!("unexpected {other:?}"),
                },
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(*seen_path.lock().unwrap(), VERIFY_PATH);
            assert!(
                seen_content_type
                    .lock()
                    .unwrap()
                    .starts_with("application/json"),
                "{}",
                seen_content_type.lock().unwrap()
            );
            assert_eq!(seen_body.lock().unwrap().as_ref(), Some(&request));
            server.abort();
        }
    }

    #[tokio::test]
    async fn verify_forwards_no_nonce() {
        let raw = Arc::new(Mutex::new(serde_json::Value::Null));
        let (url, server) = {
            let raw = Arc::clone(&raw);
            serve(verify_route(move |body: String| {
                let raw = Arc::clone(&raw);
                async move {
                    *raw.lock().unwrap() = serde_json::from_str(&body).unwrap();
                    StatusCode::OK
                }
            }))
            .await
        };

        client(&url, Duration::from_secs(1))
            .verify(test_request())
            .await
            .unwrap();

        let raw = raw.lock().unwrap();
        assert!(raw.get("nonce").is_none(), "{raw}");
        assert!(raw.get("challenge_type").is_none(), "{raw}");
        assert_eq!(raw["challenge_id"], "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31");
        server.abort();
    }

    #[tokio::test]
    async fn verify_distinguishes_rejection_from_an_unauthorized_token() {
        for (body, expect_rejected) in [
            (r#"{"msg":"proof_rejected"}"#, true),
            (r#"{"msg":"unauthorized"}"#, false),
            ("", false),
        ] {
            let (url, server) = serve(verify_route(move || async move {
                (
                    StatusCode::UNAUTHORIZED,
                    [(header::CONTENT_TYPE, "application/json")],
                    body,
                )
            }))
            .await;

            let error = client(&url, Duration::from_secs(1))
                .verify(test_request())
                .await;
            if expect_rejected {
                assert!(
                    matches!(error, Err(VerificationError::Rejected)),
                    "{body} {error:?}"
                );
            } else if body.is_empty() {
                assert!(
                    matches!(error, Err(VerificationError::UnexpectedStatus { .. })),
                    "{error:?}"
                );
            } else {
                assert!(
                    matches!(error, Err(VerificationError::Unauthorized)),
                    "{body} {error:?}"
                );
            }
            server.abort();
        }
    }

    #[tokio::test]
    async fn verify_classifies_timeout() {
        let (url, server) = serve(verify_route(|| async {
            std::future::pending::<()>().await;
            StatusCode::OK
        }))
        .await;

        let error = client(&url, Duration::from_millis(50))
            .verify(test_request())
            .await;
        assert!(
            matches!(error, Err(VerificationError::Timeout(_))),
            "{error:?}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn verify_classifies_unreachable_host() {
        let client = Client::new(
            Config {
                host: "http://127.0.0.1:1".to_owned(),
                timeout: Duration::from_secs(1),
                pool_max_idle_per_host: 1,
            },
            stub_auth(Ok("test-token".to_owned())),
        )
        .unwrap();
        let error = client.verify(test_request()).await;
        assert!(
            matches!(error, Err(VerificationError::Connection(_))),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn verify_sends_bearer_token_when_auth_provider_is_set() {
        let seen = Arc::new(Mutex::new(None));
        let (url, server) = {
            let seen = Arc::clone(&seen);
            serve(verify_route(move |headers: HeaderMap| {
                let seen = Arc::clone(&seen);
                async move {
                    *seen.lock().unwrap() = headers
                        .get(header::AUTHORIZATION)
                        .map(|value| value.to_str().unwrap().to_owned());
                    StatusCode::OK
                }
            }))
            .await
        };

        Client::new(
            Config {
                host: url.to_string(),
                timeout: Duration::from_secs(1),
                pool_max_idle_per_host: 1,
            },
            stub_auth(Ok("test-token".to_owned())),
        )
        .unwrap()
        .verify(test_request())
        .await
        .unwrap();

        assert_eq!(seen.lock().unwrap().as_deref(), Some("Bearer test-token"));
        server.abort();
    }

    #[tokio::test]
    async fn verify_classifies_auth_failure_without_calling_the_server() {
        let calls = Arc::new(AtomicUsize::new(0));
        let (url, server) = {
            let calls = Arc::clone(&calls);
            serve(verify_route(move || {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    StatusCode::OK
                }
            }))
            .await
        };

        let error = Client::new(
            Config {
                host: url.to_string(),
                timeout: Duration::from_secs(1),
                pool_max_idle_per_host: 1,
            },
            stub_auth(Err("kms unavailable")),
        )
        .unwrap()
        .verify(test_request())
        .await;

        assert!(
            matches!(error, Err(VerificationError::Auth(_))),
            "{error:?}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "an unsigned request must never reach the verification service"
        );
        server.abort();
    }

    #[tokio::test]
    async fn client_trims_trailing_slash_from_host() {
        let seen_path = Arc::new(Mutex::new(String::new()));
        let (url, server) = {
            let seen_path = Arc::clone(&seen_path);
            serve(verify_route(move |uri: OriginalUri| {
                let seen_path = Arc::clone(&seen_path);
                async move {
                    *seen_path.lock().unwrap() = uri.path().to_owned();
                    StatusCode::OK
                }
            }))
            .await
        };

        Client::new(
            Config {
                host: format!("{url}/"),
                timeout: Duration::from_secs(1),
                pool_max_idle_per_host: 1,
            },
            stub_auth(Ok("test-token".to_owned())),
        )
        .unwrap()
        .verify(test_request())
        .await
        .unwrap();

        assert_eq!(*seen_path.lock().unwrap(), VERIFY_PATH);
        server.abort();
    }

    #[tokio::test]
    async fn challenge_requests_the_type_and_parses_the_created_body() {
        let seen_auth = Arc::new(Mutex::new(None));
        let (url, server) = {
            let seen_auth = Arc::clone(&seen_auth);
            serve(Router::new().route(
                "/api/v4/zkp/challenge/{challenge_type}",
                post(move |uri: OriginalUri, headers: HeaderMap| {
                    let seen_auth = Arc::clone(&seen_auth);
                    async move {
                        *seen_auth.lock().unwrap() = headers
                            .get(header::AUTHORIZATION)
                            .map(|value| value.to_str().unwrap().to_owned());
                        assert_eq!(uri.path(), "/api/v4/zkp/challenge/teedi_migration");
                        (
                            StatusCode::CREATED,
                            [(header::CONTENT_TYPE, "application/json")],
                            format!(
                                r#"{{"challenge_id":"0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31","nonce":"0x{}1","challenge_type":"teedi_migration","expires_at":"2026-09-28T15:00:00Z"}}"#,
                                "0".repeat(63)
                            ),
                        )
                    }
                }),
            ))
            .await
        };

        let challenge = client(&url, Duration::from_secs(1))
            .challenge(ChallengeType::TEEDIMigration)
            .await
            .unwrap();

        assert_eq!(
            challenge,
            serde_json::from_value(serde_json::json!({
                "challenge_id": "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31",
                "nonce": format!("0x{}1", "0".repeat(63)),
                "challenge_type": "teedi_migration",
                "expires_at": "2026-09-28T15:00:00Z",
            }))
            .unwrap()
        );
        assert!(seen_auth.lock().unwrap().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn challenge_classifies_a_non_created_status() {
        let (url, server) = serve(Router::new().route(
            "/api/v4/zkp/challenge/{challenge_type}",
            post(|| async { StatusCode::BAD_REQUEST }),
        ))
        .await;

        let error = client(&url, Duration::from_secs(1))
            .challenge(ChallengeType::Enrollment)
            .await;
        assert!(
            matches!(
                error,
                Err(ChallengeError::UnexpectedStatus {
                    status: StatusCode::BAD_REQUEST
                })
            ),
            "{error:?}"
        );
        server.abort();
    }
}
