#[cfg(test)]
mod test_verification_endpoint {
    use std::collections::HashSet;
    use std::num::NonZeroUsize;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::ThreadId;
    use std::time::Duration as StdDuration;

    use axum::http::StatusCode;
    use chrono::{Duration, Utc};
    use semaphore_rs::{
        hash_to_field,
        identity::Identity,
        protocol::{self, generate_nullifier_hash},
    };
    use std::env;
    use world_id_primitives::FieldElement;
    use world_id_proof::WhirR1CSProof;
    use world_id_proof_verification_service::{
        api::verification_api::{VerificationMsg, VerificationResult},
        app::create_app,
        models::{
            challenge_model::{ChallengeId, ChallengeType, NonceObject},
            ownership_model::{OwnershipProof, OwnershipVerificationRequest},
            verification_model::VerificationRequest,
        },
        services::proof_verifier::ProofVerifier,
    };

    use crate::tests::support::{
        body_json, deps_with_v1_verifier, encode_proof, get, mock_deps, post_json,
        post_json_authed, test_config, valid_bearer, MockNonceStore, RootVerdict,
    };

    struct CountingVerifier {
        current: AtomicUsize,
        peak: AtomicUsize,
        runtime_worker_calls: AtomicUsize,
        hold: StdDuration,
        runtime_worker_ids: Arc<HashSet<ThreadId>>,
    }

    impl CountingVerifier {
        fn new(hold: StdDuration, runtime_worker_ids: Arc<HashSet<ThreadId>>) -> Self {
            Self {
                current: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                runtime_worker_calls: AtomicUsize::new(0),
                hold,
                runtime_worker_ids,
            }
        }

        fn peak(&self) -> usize {
            self.peak.load(Ordering::SeqCst)
        }

        fn current(&self) -> usize {
            self.current.load(Ordering::SeqCst)
        }

        fn runtime_worker_calls(&self) -> usize {
            self.runtime_worker_calls.load(Ordering::SeqCst)
        }
    }

    impl ProofVerifier for CountingVerifier {
        fn verify(
            &self,
            _req: &VerificationRequest,
        ) -> Result<bool, semaphore_rs::protocol::ProofError> {
            if self
                .runtime_worker_ids
                .contains(&std::thread::current().id())
            {
                self.runtime_worker_calls.fetch_add(1, Ordering::SeqCst);
            }
            let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(self.hold);
            self.current.fetch_sub(1, Ordering::SeqCst);
            Ok(true)
        }
    }

    async fn runtime_worker_ids() -> Arc<HashSet<ThreadId>> {
        let ids = Arc::new(Mutex::new(HashSet::new()));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let ids = Arc::clone(&ids);
            handles.push(tokio::spawn(async move {
                ids.lock().unwrap().insert(std::thread::current().id());
                std::thread::sleep(StdDuration::from_millis(20));
            }));
        }
        tokio::time::timeout(StdDuration::from_secs(1), async {
            for handle in handles {
                handle.await.unwrap();
            }
        })
        .await
        .expect("runtime worker identification should complete");
        let ids = ids.lock().unwrap().clone();
        assert_eq!(
            ids.len(),
            4,
            "expected to sample all 4 runtime workers, saw {}; an under-sampled run would \
             silently weaken the assertion that verification never runs on a runtime worker",
            ids.len()
        );
        Arc::new(ids)
    }

    fn v4_request(challenge_id: ChallengeId) -> OwnershipVerificationRequest {
        let proof = OwnershipProof {
            proof: WhirR1CSProof {
                narg_string: vec![1, 2, 3, 4],
                hints: vec![9, 8, 7],
                #[cfg(debug_assertions)]
                pattern: Vec::new(),
            },
            merkle_root: FieldElement::from(42u64),
        };
        OwnershipVerificationRequest {
            challenge_id,
            credential_sub: FieldElement::from(7u64).to_string(),
            proof: encode_proof(&proof),
        }
    }

    fn nonce_object() -> NonceObject {
        let now = Utc::now();
        NonceObject {
            nonce: FieldElement::from(123u64),
            challenge_type: ChallengeType::Enrollment,
            created_at: now,
            expires_at: now + Duration::seconds(600),
            issuer: "test".to_string(),
        }
    }

    #[tokio::test]
    async fn test_wrong_challenge_format() {
        env::set_var("RUST_BACKTRACE", "1");

        let depth: usize = 30;
        // The secret is on the client side (World App)
        let mut secret = *b"my big secret";
        // The identity is stored on the client side (World App)
        let id = Identity::from_secret(&mut secret[..], None);
        let challenge = "Hello Worldcoin".to_string();
        let challenge_hash = hash_to_field(challenge.as_bytes());
        let scope = "pii.deletion".to_string();
        let scope_hash = hash_to_field(scope.as_bytes());
        let nullifier_hash = generate_nullifier_hash(&id, scope_hash);
        let id_commitment = id.commitment();

        let proof =
            protocol::authentication::generate_proof(depth, &id, scope_hash, challenge_hash)
                .unwrap();

        let valid_request_body = VerificationRequest {
            proof,
            challenge,
            nullifier_hash,
            scope,
            id_commitment,
        };

        let cfg = test_config();
        let app = create_app(cfg, mock_deps());
        let resp = post_json(app, "/api/v1/verify", &valid_request_body).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp_body: VerificationResult = body_json(resp).await;
        assert_eq!(resp_body.msg, VerificationMsg::WrongTimestampFormat);
    }

    #[tokio::test]
    async fn test_future_challenge() {
        env::set_var("RUST_BACKTRACE", "1");
        // env::set_var("RUST_LOG", "debug");
        // env_logger::init();

        let depth: usize = 30;
        // The secret is on the client side (World App)
        let mut secret = *b"my big secret";
        // The identity is stored on the client side (World App)
        let id = Identity::from_secret(&mut secret[..], None);
        let future_challenge = Utc::now() + Duration::seconds(120);
        let challenge = future_challenge.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let challenge_hash = hash_to_field(challenge.as_bytes());
        let scope = "pii.deletion".to_string();
        let scope_hash = hash_to_field(scope.as_bytes());
        let nullifier_hash = generate_nullifier_hash(&id, scope_hash);
        let id_commitment = id.commitment();

        let proof =
            protocol::authentication::generate_proof(depth, &id, scope_hash, challenge_hash)
                .unwrap();

        let valid_request_body = VerificationRequest {
            proof,
            challenge,
            nullifier_hash,
            scope,
            id_commitment,
        };

        let cfg = test_config();
        let app = create_app(cfg, mock_deps());
        let resp = post_json(app, "/api/v1/verify", &valid_request_body).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let resp_body: VerificationResult = body_json(resp).await;
        assert_eq!(resp_body.msg, VerificationMsg::FutureTimestamp);
    }

    #[tokio::test]
    async fn test_old_challenge() {
        env::set_var("RUST_BACKTRACE", "1");
        // env::set_var("RUST_LOG", "debug");
        // env_logger::init();

        let depth: usize = 30;
        // The secret is on the client side (World App)
        let mut secret = *b"my big secret";
        // The identity is stored on the client side (World App)
        let id = Identity::from_secret(&mut secret[..], None);
        let challenge = "2023-10-08T14:54:56.603Z".to_string();
        let challenge_hash = hash_to_field(b"another challenge");
        let scope = "pii.deletion".to_string();
        let scope_hash = hash_to_field(scope.as_bytes());
        let nullifier_hash = generate_nullifier_hash(&id, scope_hash);
        let id_commitment = id.commitment();

        let proof =
            protocol::authentication::generate_proof(depth, &id, scope_hash, challenge_hash)
                .unwrap();

        let valid_request_body = VerificationRequest {
            proof,
            challenge,
            nullifier_hash,
            scope,
            id_commitment,
        };

        let cfg = test_config();
        let app = create_app(cfg, mock_deps());
        let resp = post_json(app, "/api/v1/verify", &valid_request_body).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let resp_body: VerificationResult = body_json(resp).await;
        assert_eq!(resp_body.msg, VerificationMsg::OldTimestamp);
    }

    #[tokio::test]
    async fn test_rejected_proof() {
        // env::set_var("RUST_BACKTRACE", "1");
        // env::set_var("RUST_LOG", "debug");

        let depth: usize = 30;
        // The secret is on the client side (World App)
        let mut secret = *b"my big secret";
        // The identity is stored on the client side (World App)
        let id = Identity::from_secret(&mut secret[..], None);
        let challenge = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let challenge_hash = hash_to_field(b"another challenge");
        let scope = "pii.deletion".to_string();
        let scope_hash = hash_to_field(scope.as_bytes());
        let nullifier_hash = generate_nullifier_hash(&id, scope_hash);
        let id_commitment = id.commitment();

        let proof =
            protocol::authentication::generate_proof(depth, &id, scope_hash, challenge_hash)
                .unwrap();

        let valid_request_body = VerificationRequest {
            proof,
            challenge,
            nullifier_hash,
            scope,
            id_commitment,
        };

        let cfg = test_config();
        let app = create_app(cfg, mock_deps());
        let resp = post_json(app, "/api/v1/verify", &valid_request_body).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let resp_body: VerificationResult = body_json(resp).await;
        assert_eq!(resp_body.msg, VerificationMsg::ProofRejected);
    }

    /// A verifier double that always returns a `ProofError`, standing in for
    /// any deserialization failure on the proof or its public inputs.
    struct ErroringVerifier;

    impl ProofVerifier for ErroringVerifier {
        fn verify(
            &self,
            _req: &VerificationRequest,
        ) -> Result<bool, semaphore_rs::protocol::ProofError> {
            Err(semaphore_rs::protocol::ProofError::CircuitKeyError(
                std::io::Error::other("simulated for test"),
            ))
        }
    }

    #[tokio::test]
    async fn test_malformed_proof_is_rejected_not_service_unavailable() {
        let challenge = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut secret = *b"my big secret";
        let id = Identity::from_secret(&mut secret[..], None);
        let scope_hash = hash_to_field(b"pii.deletion");
        let nullifier_hash = generate_nullifier_hash(&id, scope_hash);

        // The request body's own contents don't matter here — `ErroringVerifier`
        // always returns `Err` regardless of input, so this just needs to reach
        // the verification step (a fresh, parseable challenge).
        let valid_request_body = VerificationRequest {
            proof: protocol::authentication::generate_proof(
                30,
                &id,
                scope_hash,
                hash_to_field(b"another challenge"),
            )
            .unwrap(),
            challenge,
            nullifier_hash,
            scope: "pii.deletion".to_string(),
            id_commitment: id.commitment(),
        };

        let cfg = test_config();
        let deps = deps_with_v1_verifier(
            Arc::new(MockNonceStore::empty()),
            RootVerdict::Valid,
            Arc::new(ErroringVerifier),
        );
        let app = create_app(cfg, deps);
        let resp = post_json(app, "/api/v1/verify", &valid_request_body).await;

        // A `ProofError` (malformed proof/public-input data) is a rejection,
        // not a dependency outage — verify_proof's verifying key is compiled
        // in, so there is no runtime dependency for this to signal is down.
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let resp_body: VerificationResult = body_json(resp).await;
        assert_eq!(resp_body.msg, VerificationMsg::ProofRejected);
    }

    #[tokio::test]
    async fn test_accepted_proof() {
        env::set_var("RUST_BACKTRACE", "1");
        // env::set_var("RUST_LOG", "debug");

        let depth: usize = 30;
        // The secret is on the client side (World App)
        let mut secret = *b"my big secret";
        // The identity is stored on the client side (World App)
        let id = Identity::from_secret(&mut secret[..], None);
        let challenge = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let challenge_hash = hash_to_field(challenge.as_bytes());
        let scope = "pii.deletion".to_string();
        let scope_hash = hash_to_field(scope.as_bytes());
        let nullifier_hash = generate_nullifier_hash(&id, scope_hash);
        let id_commitment = id.commitment();

        let proof =
            protocol::authentication::generate_proof(depth, &id, scope_hash, challenge_hash)
                .unwrap();

        let valid_request_body = VerificationRequest {
            proof,
            challenge,
            nullifier_hash,
            scope,
            id_commitment,
        };

        let cfg = test_config();
        let app = create_app(cfg, mock_deps());
        let resp = post_json(app, "/api/v1/verify", &valid_request_body).await;

        assert!(resp.status().is_success());
        let resp_body: VerificationResult = body_json(resp).await;
        assert_eq!(resp_body.msg, VerificationMsg::ProofAccepted);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn verification_is_bounded_and_isolates_health_and_v4() {
        let depth = 30;
        let mut secret = *b"my big secret";
        let identity = Identity::from_secret(&mut secret[..], None);
        let challenge = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let challenge_hash = hash_to_field(challenge.as_bytes());
        let scope = "pii.deletion".to_string();
        let scope_hash = hash_to_field(scope.as_bytes());
        let request = VerificationRequest {
            proof: protocol::authentication::generate_proof(
                depth,
                &identity,
                scope_hash,
                challenge_hash,
            )
            .unwrap(),
            challenge,
            nullifier_hash: generate_nullifier_hash(&identity, scope_hash),
            scope,
            id_commitment: identity.commitment(),
        };
        let request = serde_json::to_value(request).unwrap();

        let challenge_id = ChallengeId::new_v4();
        let store = Arc::new(MockNonceStore::with(challenge_id, nonce_object()));
        let verifier = Arc::new(CountingVerifier::new(
            StdDuration::from_millis(50),
            runtime_worker_ids().await,
        ));
        let mut cfg = test_config();
        cfg.verification_concurrency = NonZeroUsize::new(2).unwrap();
        let app = create_app(
            cfg,
            deps_with_v1_verifier(store, RootVerdict::Valid, verifier.clone()),
        );

        let mut handles = Vec::new();
        for _ in 0..10 {
            let app = app.clone();
            let request = request.clone();
            handles.push(tokio::spawn(async move {
                post_json(app, "/api/v1/verify", &request).await
            }));
        }

        tokio::time::timeout(StdDuration::from_secs(1), async {
            while verifier.current() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both verification slots should become occupied");

        let health =
            tokio::time::timeout(StdDuration::from_millis(100), get(app.clone(), "/health"))
                .await
                .expect("health should remain responsive during v1 verification load");
        assert_eq!(health.status(), StatusCode::OK);

        // The shared cap may queue v4 behind v1; this checks runtime isolation,
        // not independence from the deliberately shared verification slots.
        let v4 = tokio::time::timeout(
            StdDuration::from_secs(2),
            post_json_authed(
                app,
                "/api/v4/verify",
                &v4_request(challenge_id),
                &valid_bearer(),
            ),
        )
        .await
        .expect("v4 should complete while v1 load is in flight");
        assert_eq!(v4.status(), StatusCode::OK);

        for handle in handles {
            let response = handle.await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let result: VerificationResult = body_json(response).await;
            assert_eq!(result.msg, VerificationMsg::ProofAccepted);
        }

        let peak = verifier.peak();
        assert!(peak <= 2, "exceeded the configured concurrency cap: {peak}");
        assert_eq!(
            peak, 2,
            "expected two verifications to run at once, saw {peak}"
        );
        assert_eq!(
            verifier.runtime_worker_calls(),
            0,
            "v1 verification ran on a tokio worker; peak concurrency was {peak}"
        );
    }

    // verify_timeout also bounds compute, so one waiter alone can't isolate
    // the queue-wait deadline -- a deep queue is needed instead.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn queue_wait_timeout_returns_503_and_the_pool_recovers() {
        let depth = 30;
        let mut secret = *b"my big secret";
        let identity = Identity::from_secret(&mut secret[..], None);
        let challenge = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let challenge_hash = hash_to_field(challenge.as_bytes());
        let scope = "pii.deletion".to_string();
        let scope_hash = hash_to_field(scope.as_bytes());
        let request = VerificationRequest {
            proof: protocol::authentication::generate_proof(
                depth,
                &identity,
                scope_hash,
                challenge_hash,
            )
            .unwrap(),
            challenge,
            nullifier_hash: generate_nullifier_hash(&identity, scope_hash),
            scope,
            id_commitment: identity.commitment(),
        };
        let request = serde_json::to_value(request).unwrap();

        let store = Arc::new(MockNonceStore::empty());

        // 250ms of simulated compute per call, tracked via current()/peak().
        let verifier = Arc::new(CountingVerifier::new(
            StdDuration::from_millis(250),
            Arc::new(HashSet::new()),
        ));
        let mut cfg = test_config();

        // One slot; verify_timeout bounds both a request's compute and its
        // queue wait. Wide margins on purpose: the winning waiter's window is
        // (verify_timeout - hold) and the losers' margin is (2*hold -
        // verify_timeout) -- both need slack against CI scheduler jitter.
        cfg.verification_concurrency = NonZeroUsize::new(1).unwrap();
        cfg.verify_timeout = StdDuration::from_millis(350);
        let app = create_app(
            cfg,
            deps_with_v1_verifier(store, RootVerdict::Valid, verifier.clone()),
        );

        // A takes the only permit immediately (fast path, nothing else is running yet).
        let app_a = app.clone();
        let request_a = request.clone();
        let handle_a =
            tokio::spawn(async move { post_json(app_a, "/api/v1/verify", &request_a).await });

        // Don't fire the waiters until A actually holds the permit.
        tokio::time::timeout(StdDuration::from_secs(1), async {
            while verifier.current() < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the single verification slot should become occupied by A");

        // Four requests queue behind A, each racing its own queue-wait deadline.
        let mut waiter_handles = Vec::new();
        for _ in 0..4 {
            let app = app.clone();
            let request = request.clone();
            waiter_handles.push(tokio::spawn(async move {
                tokio::time::timeout(
                    StdDuration::from_millis(1200),
                    post_json(app, "/api/v1/verify", &request),
                )
                .await
                .expect("a queue-wait timeout must fail fast, not hang past verify_timeout")
            }));
        }

        // A got its permit instantly, so it only has to survive its own compute step.
        let response_a = handle_a.await.unwrap();
        assert_eq!(
            response_a.status(),
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
        let response_z = tokio::time::timeout(
            StdDuration::from_millis(800),
            post_json(app, "/api/v1/verify", &request),
        )
        .await
        .expect("the pool must recover after the blocking calls finish");
        assert_eq!(
            response_z.status(),
            StatusCode::OK,
            "verification pool slot must recover after queue-wait timeouts"
        );
    }

    // A challenge timestamp slightly in the future, but within the clock-skew
    // allowance, is treated as valid rather than rejected as a future timestamp.
    #[tokio::test]
    async fn test_future_challenge_within_skew_tolerance() {
        env::set_var("RUST_BACKTRACE", "1");

        let depth: usize = 30;
        let mut secret = *b"my big secret";
        let id = Identity::from_secret(&mut secret[..], None);
        // 1s ahead — inside the 2s tolerance.
        let future_challenge = Utc::now() + Duration::seconds(1);
        let challenge = future_challenge.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let challenge_hash = hash_to_field(challenge.as_bytes());
        let scope = "pii.deletion".to_string();
        let scope_hash = hash_to_field(scope.as_bytes());
        let nullifier_hash = generate_nullifier_hash(&id, scope_hash);
        let id_commitment = id.commitment();

        let proof =
            protocol::authentication::generate_proof(depth, &id, scope_hash, challenge_hash)
                .unwrap();

        let valid_request_body = VerificationRequest {
            proof,
            challenge,
            nullifier_hash,
            scope,
            id_commitment,
        };

        let cfg = test_config();
        let app = create_app(cfg, mock_deps());
        let resp = post_json(app, "/api/v1/verify", &valid_request_body).await;

        // Within tolerance, the future check is not tripped, so the proof is
        // verified normally and accepted.
        assert!(resp.status().is_success());
        let resp_body: VerificationResult = body_json(resp).await;
        assert_eq!(resp_body.msg, VerificationMsg::ProofAccepted);
    }

    // A challenge timestamp beyond the clock-skew allowance is rejected as a
    // future timestamp.
    #[tokio::test]
    async fn test_future_challenge_beyond_skew_tolerance() {
        env::set_var("RUST_BACKTRACE", "1");

        let depth: usize = 30;
        let mut secret = *b"my big secret";
        let id = Identity::from_secret(&mut secret[..], None);
        // 60s ahead — far beyond the 2s tolerance. The margin is deliberately
        // large: the challenge timestamp is captured before the (slow, cold)
        // proof generation runs, and under parallel test load that gap can be
        // several seconds, which would otherwise erode a tight margin.
        let future_challenge = Utc::now() + Duration::seconds(60);
        let challenge = future_challenge.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let challenge_hash = hash_to_field(challenge.as_bytes());
        let scope = "pii.deletion".to_string();
        let scope_hash = hash_to_field(scope.as_bytes());
        let nullifier_hash = generate_nullifier_hash(&id, scope_hash);
        let id_commitment = id.commitment();

        let proof =
            protocol::authentication::generate_proof(depth, &id, scope_hash, challenge_hash)
                .unwrap();

        let valid_request_body = VerificationRequest {
            proof,
            challenge,
            nullifier_hash,
            scope,
            id_commitment,
        };

        let cfg = test_config();
        let app = create_app(cfg, mock_deps());
        let resp = post_json(app, "/api/v1/verify", &valid_request_body).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let resp_body: VerificationResult = body_json(resp).await;
        assert_eq!(resp_body.msg, VerificationMsg::FutureTimestamp);
    }
}
