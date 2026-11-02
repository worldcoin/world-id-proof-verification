use crate::api::challenge_api::issue_challenge;
use crate::api::generation_api::gen_proof;
use crate::api::health_api::{health_check, ready_check};
use crate::api::ownership_api::{verify_ownership, OwnershipVerificationState};
use crate::api::verification_api::verify_proof;
use crate::cfg::config::Config;
use crate::observability::{log_request, request_span};
use crate::services::challenge_generator::{DynChallengeGenerator, OsRngChallengeGenerator};
use crate::services::gateway_service::GatewayService;
use crate::services::jwt_auth::JwtKeyStore;
use crate::services::nonce_store::DynNonceStore;
use crate::services::ownership_proof_verifier::DynOwnershipProofVerifier;
use crate::services::proof_generator::{DynProofGenerator, SemaphoreProofGenerator};
use crate::services::proof_verifier::DynProofVerifier;
use axum::extract::FromRef;
use axum::routing::{get, post};
use axum::{Extension, Router};
use std::sync::Arc;
use telemetry_batteries::tracing::middleware::TraceLayer;
use tokio::sync::Semaphore;

/// Shared dependencies of the verify endpoints, built once in `main`.
/// Injectable so tests can substitute in-memory fakes.
#[derive(Clone)]
pub struct AppDeps {
    pub verifier: DynProofVerifier,
    pub nonce_store: DynNonceStore,
    pub gateway: Arc<GatewayService>,
    pub ownership_verifier: DynOwnershipProofVerifier,
    pub jwt_keys: Arc<JwtKeyStore>,
}

/// Shared application state cloned into each request by axum. Handlers pull the
/// individual pieces they need through `State<T>`, backed by the `FromRef` impls
/// below.
#[derive(Clone)]
pub struct AppState {
    cfg: Config,
    verifier: DynProofVerifier,
    nonce_store: DynNonceStore,
    challenge_generator: DynChallengeGenerator,
    gateway: Arc<GatewayService>,
    ownership_verifier: DynOwnershipProofVerifier,
    verification_slots: Arc<Semaphore>,
    jwt_keys: Arc<JwtKeyStore>,
}

impl FromRef<AppState> for Config {
    fn from_ref(state: &AppState) -> Self {
        state.cfg.clone()
    }
}

impl FromRef<AppState> for DynProofVerifier {
    fn from_ref(state: &AppState) -> Self {
        state.verifier.clone()
    }
}

impl FromRef<AppState> for DynNonceStore {
    fn from_ref(state: &AppState) -> Self {
        state.nonce_store.clone()
    }
}

impl FromRef<AppState> for DynChallengeGenerator {
    fn from_ref(state: &AppState) -> Self {
        state.challenge_generator.clone()
    }
}

impl FromRef<AppState> for Arc<GatewayService> {
    fn from_ref(state: &AppState) -> Self {
        state.gateway.clone()
    }
}

impl FromRef<AppState> for DynOwnershipProofVerifier {
    fn from_ref(state: &AppState) -> Self {
        state.ownership_verifier.clone()
    }
}

impl FromRef<AppState> for Arc<Semaphore> {
    fn from_ref(state: &AppState) -> Self {
        state.verification_slots.clone()
    }
}

impl FromRef<AppState> for Arc<JwtKeyStore> {
    fn from_ref(state: &AppState) -> Self {
        state.jwt_keys.clone()
    }
}

impl FromRef<AppState> for OwnershipVerificationState {
    fn from_ref(state: &AppState) -> Self {
        Self {
            cfg: state.cfg.clone(),
            nonce_store: state.nonce_store.clone(),
            gateway: state.gateway.clone(),
            verifier: state.ownership_verifier.clone(),
            verification_slots: state.verification_slots.clone(),
        }
    }
}

/// Builds the axum `Router` for the proof verification service, wiring the shared
/// dependencies via `State` and registering the routes:
///
/// * `POST /api/v1/verify` — verify a Semaphore inclusion proof against a challenge.
/// * `POST /api/v4/verify` — verify a 4.x ownership proof against a single-use
///   challenge. Requires a valid `Authorization: Bearer` ES256 JWT.
/// * `POST /api/v4/zkp/challenge/{challenge_type}` — issue a single-use challenge.
/// * `GET  /health` — liveness (service name and version).
/// * `GET  /ready` — readiness (nonce-store Redis `PING`).
/// * `POST /api/v1/gen` — optional, registered only when `enable_proof_gen_endpoint`.
///
/// The `TraceLayer` provides the per-request span and extracts Datadog trace
/// context from request headers. The inner logging middleware covers all
/// responses, including extractor rejections, and returns an `x-request-id`.
pub fn create_app(cfg: Config, deps: AppDeps) -> Router {
    let logging_config = cfg.clone();
    let enable_proof_gen_endpoint = cfg.enable_proof_gen_endpoint;
    let verification_slots = Arc::new(Semaphore::new(cfg.verification_concurrency.get()));
    let state = AppState {
        cfg,
        verifier: deps.verifier,
        nonce_store: deps.nonce_store,
        challenge_generator: Arc::new(OsRngChallengeGenerator),
        gateway: deps.gateway,
        ownership_verifier: deps.ownership_verifier,
        verification_slots,
        jwt_keys: deps.jwt_keys,
    };

    let mut app = Router::new()
        .route("/api/v1/verify", post(verify_proof))
        .route("/api/v4/verify", post(verify_ownership))
        .route(
            "/api/v4/zkp/challenge/{challenge_type}",
            post(issue_challenge),
        );

    if enable_proof_gen_endpoint {
        let generator: DynProofGenerator = Arc::new(SemaphoreProofGenerator);
        app = app
            .route("/api/v1/gen", post(gen_proof))
            .layer(Extension(generator));
    }

    app.route("/health", get(health_check))
        .route("/ready", get(ready_check))
        .layer(axum::middleware::from_fn_with_state(
            logging_config,
            log_request,
        ))
        .layer(TraceLayer::new().with_make_span(request_span))
        .with_state(state)
}
