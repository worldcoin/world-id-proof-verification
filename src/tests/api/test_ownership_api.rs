#[cfg(test)]
mod test_ownership_endpoint {
    use std::num::NonZeroUsize;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use axum::http::StatusCode;
    use axum::response::Response;
    use chrono::Utc;
    use world_id_primitives::FieldElement;
    use world_id_proof::artifacts::ZkArtifactSource;
    use world_id_proof::{ProofError, WhirR1CSProof};
    use world_id_proof_verification_service::{
        app::{create_app, AppDeps},
        models::{
            challenge_model::{ChallengeId, ChallengeType, NonceObject},
            ownership_model::{
                CredentialSub, OwnershipProof, OwnershipVerificationMsg,
                OwnershipVerificationRequest, OwnershipVerificationResult,
            },
        },
        services::{
            nonce_store::NonceStore,
            ownership_proof_verifier::{DynOwnershipProofVerifier, OwnershipProofVerifier},
        },
    };

    use crate::tests::support::{
        body_json, deps_with, deps_with_verifier, encode_proof, get, post_empty, post_json_authed,
        post_json_without_type_header_authed, post_raw_authed, redis_store, test_config,
        valid_bearer, MockNonceStore, RootVerdict,
    };

    const TTL: Duration = Duration::from_secs(60);

    fn sample_proof() -> OwnershipProof {
        OwnershipProof {
            proof: WhirR1CSProof {
                narg_string: vec![1, 2, 3, 4],
                hints: vec![9, 8, 7],
                #[cfg(debug_assertions)]
                pattern: Vec::new(),
            },
            merkle_root: FieldElement::from(42u64),
        }
    }

    fn sample_request(challenge_id: ChallengeId) -> OwnershipVerificationRequest {
        OwnershipVerificationRequest {
            challenge_id,
            credential_sub: FieldElement::from(7u64).to_string(),
            proof: encode_proof(&sample_proof()),
        }
    }

    fn nonce_object() -> NonceObject {
        let now = Utc::now();
        NonceObject {
            nonce: FieldElement::from(123u64),
            challenge_type: ChallengeType::Enrollment,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(600),
            issuer: "test".to_string(),
        }
    }

    async fn post(deps: AppDeps, id: ChallengeId) -> Response {
        let app = create_app(test_config(), deps);
        post_json_authed(app, "/api/v4/verify", &sample_request(id), &valid_bearer()).await
    }

    // End-to-end across both v4 endpoints: a challenge issued by
    // POST /api/v4/zkp/challenge/{type} is consumable by POST /api/v4/verify and
    // burned afterwards, sharing one app and one real Redis.
    #[tokio::test]
    async fn issue_then_verify_end_to_end() {
        let store = redis_store().await;
        let app = create_app(
            test_config(),
            deps_with(store.clone(), RootVerdict::Valid, true),
        );

        let issued = post_empty(app.clone(), "/api/v4/zkp/challenge/enrollment").await;
        assert_eq!(issued.status(), StatusCode::CREATED);
        let body: serde_json::Value = body_json(issued).await;
        let id: ChallengeId = serde_json::from_value(body["challenge_id"].clone()).unwrap();

        let resp = post_json_authed(
            app.clone(),
            "/api/v4/verify",
            &sample_request(id),
            &valid_bearer(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let result: OwnershipVerificationResult = body_json(resp).await;
        assert_eq!(result.msg, OwnershipVerificationMsg::ProofAccepted);

        assert_eq!(store.peek(&id).await.unwrap(), None);
    }

    struct MigrationContextVerifier;

    impl OwnershipProofVerifier for MigrationContextVerifier {
        fn verify(
            &self,
            _proof: &OwnershipProof,
            _nonce: FieldElement,
            _credential_sub: CredentialSub,
            context: FieldElement,
            _artifacts: &dyn ZkArtifactSource,
        ) -> Result<(), ProofError> {
            if context == FieldElement::from_arbitrary_raw_bytes(b"teedi_migration") {
                Ok(())
            } else {
                Err(ProofError::Verification("wrong challenge context".into()))
            }
        }
    }

    #[tokio::test]
    async fn teedi_migration_challenge_verifies_with_its_own_context() {
        let store = Arc::new(MockNonceStore::empty());
        let verifier: DynOwnershipProofVerifier = Arc::new(MigrationContextVerifier);
        let app = create_app(
            test_config(),
            deps_with_verifier(store.clone(), RootVerdict::Valid, verifier),
        );

        let issued = post_empty(app.clone(), "/api/v4/zkp/challenge/teedi_migration").await;
        assert_eq!(issued.status(), StatusCode::CREATED);
        let body: serde_json::Value = body_json(issued).await;
        assert_eq!(body["challenge_type"], "teedi_migration");
        let id: ChallengeId = serde_json::from_value(body["challenge_id"].clone()).unwrap();
        assert_eq!(
            store.peek(&id).await.unwrap().unwrap().challenge_type,
            ChallengeType::TEEDIMigration
        );

        let resp =
            post_json_authed(app, "/api/v4/verify", &sample_request(id), &valid_bearer()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(store.peek(&id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn accepts_valid_proof_and_burns_the_nonce() {
        let store = redis_store().await;
        let id = ChallengeId::new_v4();
        store.put(&id, &nonce_object(), TTL).await.unwrap();

        let resp = post(deps_with(store.clone(), RootVerdict::Valid, true), id).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: OwnershipVerificationResult = body_json(resp).await;
        assert_eq!(body.msg, OwnershipVerificationMsg::ProofAccepted);
        // GETDEL removed it from Redis.
        assert_eq!(store.peek(&id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn rejects_unknown_or_used_challenge() {
        let store = redis_store().await;
        // Never put — Redis has no such key.
        let id = ChallengeId::new_v4();

        let resp = post(deps_with(store.clone(), RootVerdict::Valid, true), id).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body: OwnershipVerificationResult = body_json(resp).await;
        assert_eq!(body.msg, OwnershipVerificationMsg::ProofRejected);
    }

    // Legacy callers may still send `challenge_type`; serde ignores it.
    #[tokio::test]
    async fn stray_challenge_type_field_is_ignored() {
        let store = redis_store().await;
        let id = ChallengeId::new_v4();
        store.put(&id, &nonce_object(), TTL).await.unwrap();

        let mut body = serde_json::to_value(sample_request(id)).unwrap();
        body["challenge_type"] = serde_json::json!("enrollment");
        let app = create_app(
            test_config(),
            deps_with(store.clone(), RootVerdict::Valid, true),
        );
        let resp = post_json_authed(app, "/api/v4/verify", &body, &valid_bearer()).await;

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn malformed_credential_sub_is_bad_request_without_touching_the_nonce_store() {
        let store = Arc::new(MockNonceStore::empty());
        let app = create_app(
            test_config(),
            deps_with(store.clone(), RootVerdict::Valid, true),
        );

        let mut req = sample_request(ChallengeId::new_v4());
        req.credential_sub = "0x01".to_string();
        let resp = post_json_authed(app, "/api/v4/verify", &req, &valid_bearer()).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(store.peek_calls(), 0);
    }

    #[tokio::test]
    async fn bad_base64_proof_is_bad_request_without_touching_the_nonce_store() {
        let store = Arc::new(MockNonceStore::empty());
        let app = create_app(
            test_config(),
            deps_with(store.clone(), RootVerdict::Valid, true),
        );

        let mut req = sample_request(ChallengeId::new_v4());
        req.proof = "!!!not-base64!!!".to_string();
        let resp = post_json_authed(app, "/api/v4/verify", &req, &valid_bearer()).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(store.peek_calls(), 0);
    }

    #[tokio::test]
    async fn bad_cbor_proof_is_bad_request_without_touching_the_nonce_store() {
        use base64::Engine as _;
        let store = Arc::new(MockNonceStore::empty());
        let app = create_app(
            test_config(),
            deps_with(store.clone(), RootVerdict::Valid, true),
        );

        let mut req = sample_request(ChallengeId::new_v4());
        req.proof = base64::engine::general_purpose::STANDARD.encode(b"not cbor at all");
        let resp = post_json_authed(app, "/api/v4/verify", &req, &valid_bearer()).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(store.peek_calls(), 0);
    }

    #[tokio::test]
    async fn request_without_content_header_is_rejected() {
        let store = redis_store().await;
        let id = ChallengeId::new_v4();
        store.put(&id, &nonce_object(), TTL).await.unwrap();

        let body = serde_json::to_value(sample_request(id)).unwrap();
        let app = create_app(
            test_config(),
            deps_with(store.clone(), RootVerdict::Valid, true),
        );
        let resp =
            post_json_without_type_header_authed(app, "/api/v4/verify", &body, &valid_bearer())
                .await;

        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert!(store.peek(&id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn rejects_unaccepted_root_without_burning() {
        let store = redis_store().await;
        let id = ChallengeId::new_v4();
        store.put(&id, &nonce_object(), TTL).await.unwrap();

        let resp = post(deps_with(store.clone(), RootVerdict::Invalid, true), id).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(store.peek(&id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn rejects_invalid_proof_without_burning() {
        let store = redis_store().await;
        let id = ChallengeId::new_v4();
        store.put(&id, &nonce_object(), TTL).await.unwrap();

        let resp = post(deps_with(store.clone(), RootVerdict::Valid, false), id).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body: OwnershipVerificationResult = body_json(resp).await;
        assert_eq!(body.msg, OwnershipVerificationMsg::ProofRejected);
        // A failed proof must leave the challenge intact for a retry.
        assert!(store.peek(&id).await.unwrap().is_some());
    }

    /// Always fails with a non-`Verification` `ProofError`.
    struct InternalErrorVerifier;

    impl OwnershipProofVerifier for InternalErrorVerifier {
        fn verify(
            &self,
            _proof: &OwnershipProof,
            _nonce: FieldElement,
            _credential_sub: CredentialSub,
            _context: FieldElement,
            _artifacts: &dyn ZkArtifactSource,
        ) -> Result<(), ProofError> {
            Err(ProofError::InternalError(eyre::eyre!(
                "failed to build single-threaded rayon pool"
            )))
        }
    }

    #[tokio::test]
    async fn verifier_internal_error_is_service_error_not_rejection() {
        let store = redis_store().await;
        let id = ChallengeId::new_v4();
        store.put(&id, &nonce_object(), TTL).await.unwrap();

        let verifier: DynOwnershipProofVerifier = Arc::new(InternalErrorVerifier);
        let resp = post(
            deps_with_verifier(store.clone(), RootVerdict::Valid, verifier),
            id,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(store.peek(&id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn gateway_error_is_service_error_and_preserves_the_nonce() {
        let store = redis_store().await;
        let id = ChallengeId::new_v4();
        store.put(&id, &nonce_object(), TTL).await.unwrap();

        let resp = post(deps_with(store.clone(), RootVerdict::Error, true), id).await;

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(store.peek(&id).await.unwrap().is_some());
    }

    // Two concurrent verifications of the same challenge: Redis GETDEL makes the
    // burn atomic, so exactly one succeeds regardless of interleaving.
    #[tokio::test]
    async fn concurrent_requests_yield_at_most_one_success() {
        let store = redis_store().await;
        let id = ChallengeId::new_v4();
        store.put(&id, &nonce_object(), TTL).await.unwrap();

        let app = create_app(
            test_config(),
            deps_with(store.clone(), RootVerdict::Valid, true),
        );
        // Bind each request so it outlives the borrow across the awaited call.
        let (req_a, req_b) = (sample_request(id), sample_request(id));
        let bearer = valid_bearer();
        let (a, b) = futures_util::join!(
            post_json_authed(app.clone(), "/api/v4/verify", &req_a, &bearer),
            post_json_authed(app.clone(), "/api/v4/verify", &req_b, &bearer),
        );

        let statuses = [a.status(), b.status()];
        assert!(
            statuses.contains(&StatusCode::OK),
            "one must succeed: {statuses:?}"
        );
        assert!(
            statuses.contains(&StatusCode::UNAUTHORIZED),
            "one must be rejected: {statuses:?}"
        );
        assert_eq!(store.peek(&id).await.unwrap(), None);
    }

    // Backend faults can't be provoked on a healthy Redis, so the 503 mapping is
    // exercised with a fault-injecting mock store.
    #[tokio::test]
    async fn peek_error_is_service_error_before_the_gateway() {
        let store = Arc::new(MockNonceStore::failing_peek());
        let deps = deps_with(store.clone(), RootVerdict::Valid, true);

        let resp = post(deps, ChallengeId::new_v4()).await;

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(store.consume_calls(), 0);
    }

    #[tokio::test]
    async fn consume_error_is_service_error() {
        let id = ChallengeId::new_v4();
        let store = Arc::new(MockNonceStore::with_failing_consume(id, nonce_object()));
        let deps = deps_with(store.clone(), RootVerdict::Valid, true);

        let resp = post(deps, id).await;

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(store.peek_calls(), 1);
        assert_eq!(store.consume_calls(), 1);
    }

    /// Records peak concurrent `verify` calls; holds each for `hold` to force overlap.
    struct CountingVerifier {
        current: AtomicUsize,
        peak: AtomicUsize,
        hold: Duration,
    }

    impl CountingVerifier {
        fn new(hold: Duration) -> Self {
            Self {
                current: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                hold,
            }
        }

        fn peak(&self) -> usize {
            self.peak.load(Ordering::SeqCst)
        }
    }

    impl OwnershipProofVerifier for CountingVerifier {
        fn verify(
            &self,
            _proof: &OwnershipProof,
            _nonce: FieldElement,
            _credential_sub: CredentialSub,
            _context: FieldElement,
            _artifacts: &dyn ZkArtifactSource,
        ) -> Result<(), ProofError> {
            let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(self.hold);
            self.current.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Blocks for `first_call_hold` on the first call only; later calls return immediately.
    struct SlowOnceVerifier {
        first_call_hold: Duration,
        calls: AtomicUsize,
    }

    impl SlowOnceVerifier {
        fn new(first_call_hold: Duration) -> Self {
            Self {
                first_call_hold,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl OwnershipProofVerifier for SlowOnceVerifier {
        fn verify(
            &self,
            _proof: &OwnershipProof,
            _nonce: FieldElement,
            _credential_sub: CredentialSub,
            _context: FieldElement,
            _artifacts: &dyn ZkArtifactSource,
        ) -> Result<(), ProofError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                std::thread::sleep(self.first_call_hold);
            }
            Ok(())
        }
    }

    // cap=2 keeps peak verifies at 2 and /health responsive under load.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn verification_is_bounded_and_isolates_health() {
        let store = Arc::new(MockNonceStore::empty());
        let mut ids = Vec::new();
        for _ in 0..10 {
            let id = ChallengeId::new_v4();
            store.put(&id, &nonce_object(), TTL).await.unwrap();
            ids.push(id);
        }

        let verifier = Arc::new(CountingVerifier::new(Duration::from_millis(50)));
        let mut cfg = test_config();
        cfg.verification_concurrency = NonZeroUsize::new(2).unwrap();
        let app = create_app(
            cfg,
            deps_with_verifier(store.clone(), RootVerdict::Valid, verifier.clone()),
        );

        let mut handles = Vec::new();
        for id in ids {
            let app = app.clone();
            let bearer = valid_bearer();
            handles.push(tokio::spawn(async move {
                let req = sample_request(id);
                post_json_authed(app, "/api/v4/verify", &req, &bearer)
                    .await
                    .status()
            }));
        }

        let health = get(app.clone(), "/health").await;
        assert_eq!(health.status(), StatusCode::OK);

        for handle in handles {
            assert_eq!(handle.await.unwrap(), StatusCode::OK);
        }

        let peak = verifier.peak();
        assert!(peak <= 2, "exceeded the configured concurrency cap: {peak}");
        assert_eq!(
            peak, 2,
            "expected two verifications to run at once, saw {peak}"
        );
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_with_413() {
        let store = Arc::new(MockNonceStore::empty());
        let mut cfg = test_config();
        cfg.max_body_bytes = bytesize::ByteSize::b(64);
        let app = create_app(cfg, deps_with(store, RootVerdict::Valid, true));

        let big_body = serde_json::to_vec(&sample_request(ChallengeId::new_v4())).unwrap();
        assert!(big_body.len() > 64);
        let resp = post_raw_authed(app, "/api/v4/verify", big_body, &valid_bearer()).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn content_length_over_the_cap_is_rejected_before_the_body_is_read() {
        let store = Arc::new(MockNonceStore::empty());
        let mut cfg = test_config();
        cfg.max_body_bytes = bytesize::ByteSize::b(64);
        let app = create_app(cfg, deps_with(store, RootVerdict::Valid, true));

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v4/verify")
            .header("content-type", "application/json")
            .header("authorization", valid_bearer())
            .header("content-length", "1000000")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, request).await.unwrap();

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn deeply_nested_body_is_rejected_with_413() {
        let store = Arc::new(MockNonceStore::empty());
        let app = create_app(test_config(), deps_with(store, RootVerdict::Valid, true));

        let mut body = vec![b'['; 40];
        body.extend(std::iter::repeat_n(b']', 40));
        let resp = post_raw_authed(app, "/api/v4/verify", body, &valid_bearer()).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn oversized_proof_component_is_rejected_before_touching_the_nonce_store() {
        let store = Arc::new(MockNonceStore::empty());
        let app = create_app(
            test_config(),
            deps_with(store.clone(), RootVerdict::Valid, true),
        );

        // 640 KiB + 1: kept in sync with `MAX_PROOF_COMPONENT_BYTES` in `api::ownership_api`.
        let id = ChallengeId::new_v4();
        let mut proof = sample_proof();
        proof.proof.narg_string = vec![0u8; 640 * 1024 + 1];
        let mut req = sample_request(id);
        req.proof = encode_proof(&proof);
        let resp = post_json_authed(app, "/api/v4/verify", &req, &valid_bearer()).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(store.peek_calls(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn verification_timeout_returns_503_and_the_pool_recovers() {
        let store = Arc::new(MockNonceStore::empty());
        let (id1, id2) = (ChallengeId::new_v4(), ChallengeId::new_v4());
        store.put(&id1, &nonce_object(), TTL).await.unwrap();
        store.put(&id2, &nonce_object(), TTL).await.unwrap();

        let verifier: DynOwnershipProofVerifier =
            Arc::new(SlowOnceVerifier::new(Duration::from_millis(150)));
        let mut cfg = test_config();
        cfg.verification_concurrency = NonZeroUsize::new(1).unwrap();
        cfg.verify_timeout = Duration::from_millis(20);
        let app = create_app(
            cfg,
            deps_with_verifier(store.clone(), RootVerdict::Valid, verifier),
        );

        let resp = post_json_authed(
            app.clone(),
            "/api/v4/verify",
            &sample_request(id1),
            &valid_bearer(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(store.peek(&id1).await.unwrap().is_some());

        tokio::time::sleep(Duration::from_millis(300)).await;

        let resp2 =
            post_json_authed(app, "/api/v4/verify", &sample_request(id2), &valid_bearer()).await;
        assert_eq!(
            resp2.status(),
            StatusCode::OK,
            "verification pool slot must recover after the blocking call finishes"
        );
    }

    // verify_timeout also bounds compute, so one waiter alone can't isolate
    // the queue-wait deadline -- a deep queue is needed instead.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn queue_wait_timeout_returns_503_and_the_pool_recovers() {
        let store = Arc::new(MockNonceStore::empty());

        // A + 4 waiters + Z, each needs its own unconsumed nonce.
        let id_a = ChallengeId::new_v4();
        let waiter_ids: Vec<ChallengeId> = (0..4).map(|_| ChallengeId::new_v4()).collect();
        let id_z = ChallengeId::new_v4();
        for id in std::iter::once(&id_a).chain(&waiter_ids).chain([&id_z]) {
            store.put(id, &nonce_object(), TTL).await.unwrap();
        }

        // 250ms of simulated compute per call.
        let verifier: DynOwnershipProofVerifier =
            Arc::new(CountingVerifier::new(Duration::from_millis(250)));
        let mut cfg = test_config();

        // One slot; verify_timeout bounds both a request's compute and its
        // queue wait. Wide margins on purpose: the winning waiter's window is
        // (verify_timeout - hold) and the losers' margin is (2*hold -
        // verify_timeout) -- both need slack against CI scheduler jitter.
        cfg.verification_concurrency = NonZeroUsize::new(1).unwrap();
        cfg.verify_timeout = Duration::from_millis(350);
        let app = create_app(
            cfg,
            deps_with_verifier(store.clone(), RootVerdict::Valid, verifier),
        );

        // A takes the only permit immediately (fast path, nothing else is running yet).
        let app_a = app.clone();
        let handle_a = tokio::spawn(async move {
            post_json_authed(
                app_a,
                "/api/v4/verify",
                &sample_request(id_a),
                &valid_bearer(),
            )
            .await
        });

        // In-memory checks precede this, so a short sleep is enough to know
        // A holds the permit before the waiters are issued.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Four requests queue behind A, each racing its own queue-wait deadline.
        let mut waiter_handles = Vec::new();
        for id in waiter_ids {
            let app = app.clone();
            waiter_handles.push(tokio::spawn(async move {
                tokio::time::timeout(
                    Duration::from_millis(1200),
                    post_json_authed(app, "/api/v4/verify", &sample_request(id), &valid_bearer()),
                )
                .await
                .expect("a queue-wait timeout must fail fast, not hang past verify_timeout")
            }));
        }

        // A got its permit instantly, so it only has to survive its own compute step.
        let resp_a = handle_a.await.unwrap();
        assert_eq!(
            resp_a.status(),
            StatusCode::OK,
            "the request that actually held the slot must still succeed"
        );

        // Only the first waiter in line gets A's freed slot in time; the rest
        // are still queued when their own deadline expires.
        let mut ok_count = 0;
        let mut unavailable_count = 0;
        for handle in waiter_handles {
            match handle.await.unwrap().status() {
                StatusCode::OK => ok_count += 1,
                StatusCode::SERVICE_UNAVAILABLE => unavailable_count += 1,
                other => panic!("unexpected status {other}"),
            }
        }
        assert_eq!(
            ok_count, 1,
            "exactly one queued waiter should win A's freed slot"
        );
        assert_eq!(
            unavailable_count, 3,
            "the rest must fail the queue-wait deadline rather than hang"
        );

        // Proves no permit leaked from the timed-out waiters.
        let resp_z = tokio::time::timeout(
            Duration::from_millis(800),
            post_json_authed(
                app,
                "/api/v4/verify",
                &sample_request(id_z),
                &valid_bearer(),
            ),
        )
        .await
        .expect("the pool must recover after the blocking calls finish");
        assert_eq!(
            resp_z.status(),
            StatusCode::OK,
            "verification pool slot must recover after queue-wait timeouts"
        );
    }
}
