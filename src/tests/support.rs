//! In-memory fakes for the 4.x verify dependencies, plus a small oneshot harness
//! for driving the axum `Router` in-process.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use axum::{body::Body, http::Request, response::Response, Router};
use serde::{de::DeserializeOwned, Serialize};
use tower::ServiceExt;
use world_id_primitives::FieldElement;
use world_id_proof::artifacts::ZkArtifactSource;
use world_id_proof::ProofError;
use world_id_proof_verification_service::{
    app::AppDeps,
    cfg::config::Config,
    clients::gateway::{GatewayClient, GatewayError},
    models::{
        challenge_model::{ChallengeId, NonceObject},
        ownership_model::{CredentialSub, OwnershipProof},
    },
    services::{
        gateway_service::GatewayService,
        jwt_auth::JwtKeyStore,
        nonce_store::{DynNonceStore, NonceStore, NonceStoreError, RedisConfig, RedisNonceStore},
        ownership_proof_verifier::{DynOwnershipProofVerifier, OwnershipProofVerifier},
        proof_verifier::{DynProofVerifier, SemaphoreVerifier},
    },
};

/// [`NonceStore`] used for failing assumptions (we cannot cause an error with Redis in docker)
pub struct MockNonceStore {
    entries: Mutex<HashMap<ChallengeId, NonceObject>>,
    peek_calls: AtomicUsize,
    consume_calls: AtomicUsize,
    fail_put: bool,
    fail_peek: bool,
    fail_consume: bool,
    fail_ping: bool,
}

impl MockNonceStore {
    pub fn empty() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            peek_calls: AtomicUsize::new(0),
            consume_calls: AtomicUsize::new(0),
            fail_put: false,
            fail_peek: false,
            fail_consume: false,
            fail_ping: false,
        }
    }

    pub fn failing_put() -> Self {
        Self {
            fail_put: true,
            ..Self::empty()
        }
    }

    pub fn failing_ping() -> Self {
        Self {
            fail_ping: true,
            ..Self::empty()
        }
    }

    pub fn with(id: ChallengeId, obj: NonceObject) -> Self {
        let store = Self::empty();
        store.entries.lock().unwrap().insert(id, obj);
        store
    }

    pub fn failing_peek() -> Self {
        Self {
            fail_peek: true,
            ..Self::empty()
        }
    }

    pub fn with_failing_consume(id: ChallengeId, obj: NonceObject) -> Self {
        let store = Self::with(id, obj);
        Self {
            fail_consume: true,
            ..store
        }
    }

    pub fn peek_calls(&self) -> usize {
        self.peek_calls.load(Ordering::SeqCst)
    }

    pub fn consume_calls(&self) -> usize {
        self.consume_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl NonceStore for MockNonceStore {
    async fn put(
        &self,
        challenge_id: &ChallengeId,
        nonce: &NonceObject,
        _ttl: Duration,
    ) -> Result<(), NonceStoreError> {
        if self.fail_put {
            return Err(NonceStoreError::Backend("mock put failure".into()));
        }
        self.entries
            .lock()
            .unwrap()
            .insert(*challenge_id, nonce.clone());
        Ok(())
    }

    async fn peek(
        &self,
        challenge_id: &ChallengeId,
    ) -> Result<Option<NonceObject>, NonceStoreError> {
        self.peek_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_peek {
            return Err(NonceStoreError::Backend("mock peek failure".into()));
        }
        Ok(self.entries.lock().unwrap().get(challenge_id).cloned())
    }

    async fn consume(
        &self,
        challenge_id: &ChallengeId,
    ) -> Result<Option<NonceObject>, NonceStoreError> {
        self.consume_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_consume {
            return Err(NonceStoreError::Backend("mock consume failure".into()));
        }
        Ok(self.entries.lock().unwrap().remove(challenge_id))
    }

    async fn ping(&self) -> Result<(), NonceStoreError> {
        if self.fail_ping {
            return Err(NonceStoreError::Backend("mock ping failure".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub enum RootVerdict {
    Valid,
    Invalid,
    Error,
}

pub struct MockGatewayClient {
    verdict: RootVerdict,
}

impl MockGatewayClient {
    pub fn new(verdict: RootVerdict) -> Self {
        Self { verdict }
    }
}

#[async_trait]
impl GatewayClient for MockGatewayClient {
    async fn is_valid_root(&self, _root: FieldElement) -> Result<bool, GatewayError> {
        match self.verdict {
            RootVerdict::Valid => Ok(true),
            RootVerdict::Invalid => Ok(false),
            RootVerdict::Error => Err(GatewayError::Transport("mock gateway failure".into())),
        }
    }
}

pub struct MockOwnershipVerifier {
    accept: bool,
}

impl MockOwnershipVerifier {
    pub fn new(accept: bool) -> Self {
        Self { accept }
    }
}

impl OwnershipProofVerifier for MockOwnershipVerifier {
    fn verify(
        &self,
        _proof: &OwnershipProof,
        _nonce: FieldElement,
        _credential_sub: CredentialSub,
        _context: FieldElement,
        _artifacts: &dyn ZkArtifactSource,
    ) -> Result<(), ProofError> {
        if self.accept {
            Ok(())
        } else {
            Err(ProofError::Verification("mock rejection".into()))
        }
    }
}

/// Mirrors walletkit's `OwnershipProof::encode()`.
pub fn encode_proof(proof: &OwnershipProof) -> String {
    use base64::Engine as _;
    let mut bytes = Vec::new();
    ciborium::into_writer(proof, &mut bytes).expect("proof encodes as CBOR");
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Builds [`AppDeps`] around a caller-supplied nonce store (a real
/// `RedisNonceStore` for the endpoint tests, or a fault-injecting mock) with a
/// mock gateway and verifier.
pub fn deps_with(nonce_store: DynNonceStore, root: RootVerdict, accept_proof: bool) -> AppDeps {
    let gateway = Arc::new(GatewayService::new(Arc::new(MockGatewayClient::new(root))));
    let ownership_verifier: DynOwnershipProofVerifier =
        Arc::new(MockOwnershipVerifier::new(accept_proof));
    AppDeps {
        verifier: Arc::new(SemaphoreVerifier),
        nonce_store,
        gateway,
        ownership_verifier,
        jwt_keys: test_jwt_keys(),
    }
}

/// [`AppDeps`] with a caller-supplied ownership verifier.
pub fn deps_with_verifier(
    nonce_store: DynNonceStore,
    root: RootVerdict,
    ownership_verifier: DynOwnershipProofVerifier,
) -> AppDeps {
    let gateway = Arc::new(GatewayService::new(Arc::new(MockGatewayClient::new(root))));
    AppDeps {
        verifier: Arc::new(SemaphoreVerifier),
        nonce_store,
        gateway,
        ownership_verifier,
        jwt_keys: test_jwt_keys(),
    }
}

/// [`AppDeps`] with a caller-supplied v1 verifier.
pub fn deps_with_v1_verifier(
    nonce_store: DynNonceStore,
    root: RootVerdict,
    verifier: DynProofVerifier,
) -> AppDeps {
    let gateway = Arc::new(GatewayService::new(Arc::new(MockGatewayClient::new(root))));
    AppDeps {
        verifier,
        nonce_store,
        gateway,
        ownership_verifier: Arc::new(MockOwnershipVerifier::new(true)),
        jwt_keys: test_jwt_keys(),
    }
}

/// Deps for tests that don't touch `/api/v4/verify`: empty store, valid root, accepting.
pub fn mock_deps() -> AppDeps {
    deps_with(Arc::new(MockNonceStore::empty()), RootVerdict::Valid, true)
}

/// A populated `Config` for tests. Built directly rather than via
/// `Config::parse()`, which reads process args/env and now requires `gateway_url`.
pub fn test_config() -> Config {
    Config {
        srv_env: "test".to_string(),
        // Real package identity so version-sensitive tests (e.g. /health) match.
        srv_name: env!("CARGO_PKG_NAME").to_string(),
        srv_version: env!("CARGO_PKG_VERSION").to_string(),
        dd_agent_host: "127.0.0.1".to_string(),
        dd_agent_port: "8126".to_string(),
        dd_statsd_port: "8125".to_string(),
        response_duration_seconds: 300,
        verification_concurrency: NonZeroUsize::new(2).unwrap(),
        rust_log: "info".to_string(),
        enable_proof_gen_endpoint: false,
        redis_url: "redis://127.0.0.1:6380".to_string(),
        redis_command_timeout_ms: 2000,
        challenge_ttl: Duration::from_secs(600),
        gateway_url: "http://gateway.test".to_string(),
        gateway_timeout: Duration::from_secs(2),
        jwt_trusted_keys: test_jwt_trusted_keys_json(),
        max_body_bytes: bytesize::ByteSize::mib(1),
        verify_timeout: Duration::from_secs(5),
    }
}

/// POSTs `body` as JSON to `uri`, consuming `app` for a single request (the axum
/// analogue of actix's `test::call_service`).
pub async fn post_json<T: Serialize>(app: Router, uri: &str, body: &T) -> Response {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    app.oneshot(request).await.unwrap()
}

/// POSTs to `uri` with an empty body, for handlers that take no request body.
pub async fn post_empty(app: Router, uri: &str) -> Response {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    app.oneshot(request).await.unwrap()
}

/// GETs `uri`, consuming `app` for a single request.
pub async fn get(app: Router, uri: &str) -> Response {
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    app.oneshot(request).await.unwrap()
}

/// Collects a response body into a UTF-8 string.
pub async fn body_string(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Collects a response body and deserializes it as JSON.
pub async fn body_json<T: DeserializeOwned>(resp: Response) -> T {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// JWT auth fixtures. ES256 keypairs are generated at first use, never committed
// (a private key in the repo trips secret scanning). `test-service` gets a
// current + previous key; `service-b` a current key only; `attacker` is trusted
// by nothing.

pub const TEST_SVC: &str = "test-service";
pub const TEST_SVC_B: &str = "service-b";

struct TestKeypair {
    private_pem: String,
    public_pem: String,
}

fn generate_keypair() -> TestKeypair {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec).unwrap();
    TestKeypair {
        private_pem: String::from_utf8(pkey.private_key_to_pem_pkcs8().unwrap()).unwrap(),
        public_pem: String::from_utf8(pkey.public_key_to_pem().unwrap()).unwrap(),
    }
}

struct TestKeys {
    svc_a_current: TestKeypair,
    svc_a_previous: TestKeypair,
    svc_b_current: TestKeypair,
    attacker: TestKeypair,
}

fn keys() -> &'static TestKeys {
    static KEYS: OnceLock<TestKeys> = OnceLock::new();
    KEYS.get_or_init(|| TestKeys {
        svc_a_current: generate_keypair(),
        svc_a_previous: generate_keypair(),
        svc_b_current: generate_keypair(),
        attacker: generate_keypair(),
    })
}

pub fn svc_a_current_priv() -> &'static str {
    &keys().svc_a_current.private_pem
}
pub fn svc_a_previous_priv() -> &'static str {
    &keys().svc_a_previous.private_pem
}
pub fn svc_b_current_priv() -> &'static str {
    &keys().svc_b_current.private_pem
}
pub fn attacker_priv() -> &'static str {
    &keys().attacker.private_pem
}

#[derive(Serialize)]
struct TestClaims {
    sub: String,
    exp: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<usize>,
}

pub fn test_jwt_trusted_keys_json() -> String {
    let k = keys();
    let mut map = serde_json::Map::new();
    map.insert(
        TEST_SVC.to_string(),
        serde_json::json!({
            "current": k.svc_a_current.public_pem,
            "previous": k.svc_a_previous.public_pem,
        }),
    );
    map.insert(
        TEST_SVC_B.to_string(),
        serde_json::json!({ "current": k.svc_b_current.public_pem }),
    );
    serde_json::Value::Object(map).to_string()
}

pub fn test_jwt_keys() -> Arc<JwtKeyStore> {
    Arc::new(JwtKeyStore::from_json(&test_jwt_trusted_keys_json()).expect("valid test key config"))
}

/// Signs an ES256 token for `sub`; `exp_offset`/`nbf_offset` are seconds from now
/// (negative = past).
pub fn sign_token(sub: &str, priv_pem: &str, exp_offset: i64, nbf_offset: Option<i64>) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = TestClaims {
        sub: sub.to_string(),
        exp: (now + exp_offset).max(0) as usize,
        nbf: nbf_offset.map(|o| (now + o).max(0) as usize),
    };
    let key =
        jsonwebtoken::EncodingKey::from_ec_pem(priv_pem.as_bytes()).expect("valid EC private key");
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256),
        &claims,
        &key,
    )
    .expect("token encodes")
}

pub fn valid_bearer() -> String {
    format!(
        "Bearer {}",
        sign_token(TEST_SVC, svc_a_current_priv(), 3600, None)
    )
}

pub async fn post_json_authed<T: Serialize>(
    app: Router,
    uri: &str,
    body: &T,
    bearer: &str,
) -> Response {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", bearer)
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    app.oneshot(request).await.unwrap()
}

/// Authed POST with no content-type header (to reach the body extractor).
pub async fn post_json_without_type_header_authed<T: Serialize>(
    app: Router,
    uri: &str,
    body: &T,
    bearer: &str,
) -> Response {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", bearer)
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    app.oneshot(request).await.unwrap()
}

/// Authed POST of raw bytes, for exercising the body extractor with
/// deliberately oversized or malformed payloads that don't round-trip through
/// `Serialize`.
pub async fn post_raw_authed(app: Router, uri: &str, body: Vec<u8>, bearer: &str) -> Response {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", bearer)
        .body(Body::from(body))
        .unwrap();
    app.oneshot(request).await.unwrap()
}

/// Connects to the Docker Redis (port 6380) for integration tests.
pub async fn redis_store() -> Arc<RedisNonceStore> {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6380".to_string());
    let store = RedisNonceStore::connect(&RedisConfig {
        url,
        command_timeout: Duration::from_secs(2),
    })
    .await
    .expect("start Redis with `docker compose up -d redis`");
    Arc::new(store)
}
