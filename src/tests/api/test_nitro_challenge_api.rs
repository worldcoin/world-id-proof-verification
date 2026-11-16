#[cfg(test)]
mod test_nitro_challenge {
    use std::num::NonZeroUsize;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use axum::Router;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use chrono::{DateTime, Utc};
    use tower::ServiceExt;
    use world_id_primitives::FieldElement;
    use world_id_proof_verification::{
        api::challenge_api::{MAX_CAPTURE_BODY_BYTES, NITRO_ATTESTATION_HEADER},
        app::{create_app, AppDeps},
        cfg::config::Config,
        models::challenge_model::{ChallengeBinding, ChallengeType},
        services::nitro::document::{
            AttestationError, CaptureBinding, CaptureEvidenceVerifier, MAX_DOCUMENT_BYTES,
        },
    };

    use crate::tests::support::{body_json, deps_with, test_config, MockNonceStore, RootVerdict};

    const ENROLLMENT: &str = "/api/v4/zkp/challenge/enrollment";
    const FIXTURE: &str = include_str!("../../services/nitro/testdata/enrollment-v2.json");
    const DOCUMENT: &[u8] = b"attestation document";
    const VERIFIED_DEVICE: [(&str, &str); 2] = [
        ("x-attested-platform", "ios"),
        ("x-attested-key-thumbprint", "thumbprint"),
    ];

    /// Stands in for the Nitro verifier; its real behaviour has its own tests.
    struct MockCaptureVerifier {
        outcome: Result<(), AttestationError>,
        hold: Duration,
        calls: AtomicUsize,
        seen: Mutex<Option<(Vec<u8>, CaptureBinding)>>,
    }

    impl MockCaptureVerifier {
        fn returning(outcome: Result<(), AttestationError>) -> Arc<Self> {
            Self::holding(outcome, Duration::ZERO)
        }

        fn holding(outcome: Result<(), AttestationError>, hold: Duration) -> Arc<Self> {
            Arc::new(Self {
                outcome,
                hold,
                calls: AtomicUsize::new(0),
                seen: Mutex::new(None),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl CaptureEvidenceVerifier for MockCaptureVerifier {
        fn verify(
            &self,
            document: &[u8],
            binding: &CaptureBinding,
            _now: DateTime<Utc>,
        ) -> Result<(), AttestationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.seen.lock().unwrap() = Some((document.to_vec(), *binding));
            std::thread::sleep(self.hold);
            self.outcome
        }
    }

    fn fixture() -> serde_json::Value {
        serde_json::from_str(FIXTURE).unwrap()
    }

    fn capture_with(change: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let mut fields = fixture()["fields"].clone();
        change(&mut fields);
        serde_json::to_vec(&fields).unwrap()
    }

    fn capture() -> Vec<u8> {
        capture_with(|_| {})
    }

    type Headers = Vec<(&'static str, String)>;

    fn evidence() -> Headers {
        vec![(NITRO_ATTESTATION_HEADER, STANDARD.encode(DOCUMENT))]
    }

    fn deps(store: Arc<MockNonceStore>, verifier: Option<Arc<MockCaptureVerifier>>) -> AppDeps {
        AppDeps {
            capture_verifier: verifier.map(|verifier| verifier as _),
            ..deps_with(store, RootVerdict::Valid, true)
        }
    }

    fn app(store: &Arc<MockNonceStore>, verifier: &Arc<MockCaptureVerifier>) -> Router {
        create_app(test_config(), deps(store.clone(), Some(verifier.clone())))
    }

    async fn post<V: AsRef<str>>(
        app: &Router,
        uri: &str,
        headers: &[(&str, V)],
        body: Vec<u8>,
    ) -> Response {
        let mut request = Request::builder().method("POST").uri(uri);
        for (name, value) in headers {
            request = request.header(*name, value.as_ref());
        }
        app.clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    async fn message(response: Response) -> String {
        let body: serde_json::Value = body_json(response).await;
        body["msg"].as_str().unwrap().to_owned()
    }

    #[tokio::test]
    async fn while_disabled_the_route_ignores_capture_evidence() {
        let store = Arc::new(MockNonceStore::empty());
        let app = create_app(test_config(), deps(store.clone(), None));

        let response = post(&app, ENROLLMENT, &evidence(), capture()).await;

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(store.only_entry().binding, None);
    }

    #[tokio::test]
    async fn a_verified_device_gets_an_unbound_challenge_without_capture_evidence() {
        let store = Arc::new(MockNonceStore::empty());
        // A rejecting verifier: reaching it would fail the request.
        let verifier = MockCaptureVerifier::returning(Err(AttestationError::Trust));

        let response = post(
            &app(&store, &verifier),
            ENROLLMENT,
            &VERIFIED_DEVICE,
            vec![],
        )
        .await;

        assert_eq!(response.status(), StatusCode::CREATED);
        let stored = store.only_entry();
        assert_eq!(stored.binding, None);
        assert_eq!(stored.issuer, "challenge-endpoint");
        assert_eq!(verifier.calls(), 0);
    }

    #[tokio::test]
    async fn a_caller_with_no_evidence_is_refused() {
        // One identity header alone is not a verified device.
        let partial_identity: &[(&str, &str)] = &VERIFIED_DEVICE[..1];
        for headers in [&[][..], partial_identity] {
            let store = Arc::new(MockNonceStore::empty());
            let verifier = MockCaptureVerifier::returning(Ok(()));

            let response = post(&app(&store, &verifier), ENROLLMENT, headers, vec![]).await;

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(message(response).await, "unauthorized");
            assert!(store.is_empty());
            assert_eq!(verifier.calls(), 0);
        }
    }

    #[tokio::test]
    async fn valid_capture_evidence_gets_a_challenge_bound_to_its_subject() {
        let store = Arc::new(MockNonceStore::empty());
        let verifier = MockCaptureVerifier::returning(Ok(()));
        let expected_digest = fixture()["nonce_hex"].as_str().unwrap().to_owned();

        let response = post(&app(&store, &verifier), ENROLLMENT, &evidence(), capture()).await;

        assert_eq!(response.status(), StatusCode::CREATED);
        let body: serde_json::Value = body_json(response).await;
        assert_eq!(body["challenge_type"], "enrollment");

        let stored = store.only_entry();
        assert_eq!(stored.challenge_type, ChallengeType::Enrollment);
        assert_eq!(stored.issuer, "nitro-capture");
        assert_eq!(
            stored.binding,
            Some(ChallengeBinding {
                sub: FieldElement::from(31u64),
                capture_digest: expected_digest.clone(),
            })
        );

        // The verifier received the decoded document and the recomputed binding.
        let (document, binding) = verifier.seen.lock().unwrap().clone().unwrap();
        assert_eq!(document, DOCUMENT);
        assert_eq!(hex::encode(binding.nonce), expected_digest);
        assert_eq!(binding.captured_at, 1_700_000_000);
    }

    #[tokio::test]
    async fn other_challenge_types_are_unaffected() {
        let store = Arc::new(MockNonceStore::empty());
        let verifier = MockCaptureVerifier::returning(Err(AttestationError::Trust));
        let no_headers: &[(&str, &str)] = &[];

        let response = post(
            &app(&store, &verifier),
            "/api/v4/zkp/challenge/teedi_migration",
            no_headers,
            vec![],
        )
        .await;

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(store.only_entry().binding, None);
        assert_eq!(verifier.calls(), 0);
    }

    #[tokio::test]
    async fn rejected_attestations_get_no_challenge() {
        for (error, expected) in [
            (AttestationError::Document, "attestation_rejected"),
            (AttestationError::Trust, "attestation_rejected"),
            (AttestationError::Release, "attestation_rejected"),
            (AttestationError::Binding, "attestation_rejected"),
            (AttestationError::Freshness, "attestation_expired"),
        ] {
            let store = Arc::new(MockNonceStore::empty());
            let verifier = MockCaptureVerifier::returning(Err(error));

            let response = post(&app(&store, &verifier), ENROLLMENT, &evidence(), capture()).await;

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{error:?}");
            assert_eq!(message(response).await, expected, "{error:?}");
            assert!(store.is_empty(), "{error:?}");
        }
    }

    #[tokio::test]
    async fn malformed_evidence_is_rejected_before_verification() {
        let header = |value: String| vec![(NITRO_ATTESTATION_HEADER, value)];
        let canonical = STANDARD.encode(DOCUMENT);
        let cases: Vec<(&str, Headers, Vec<u8>)> = vec![
            ("header not base64", header("not base64!".into()), capture()),
            (
                "unpadded header",
                header(canonical.trim_end_matches('=').into()),
                capture(),
            ),
            ("empty header", header(String::new()), capture()),
            (
                "document over the size limit",
                header(STANDARD.encode(vec![0; MAX_DOCUMENT_BYTES + 1])),
                capture(),
            ),
            (
                "two attestation headers",
                vec![
                    (NITRO_ATTESTATION_HEADER, canonical.clone()),
                    (NITRO_ATTESTATION_HEADER, canonical.clone()),
                ],
                capture(),
            ),
            ("empty body", evidence(), vec![]),
            ("body not JSON", evidence(), b"capture".to_vec()),
            (
                "unknown field",
                evidence(),
                capture_with(|fields| fields["idComm"] = "0x1".into()),
            ),
            (
                "missing field",
                evidence(),
                capture_with(|fields| {
                    fields.as_object_mut().unwrap().remove("pcp_version");
                }),
            ),
            (
                "non-canonical subject",
                evidence(),
                capture_with(|fields| fields["sub"] = "0x01f".into()),
            ),
            (
                "subject outside the field",
                evidence(),
                capture_with(|fields| fields["sub"] = format!("0x{}", "f".repeat(64)).into()),
            ),
        ];
        for (name, headers, body) in cases {
            let store = Arc::new(MockNonceStore::empty());
            let verifier = MockCaptureVerifier::returning(Ok(()));

            let response = post(&app(&store, &verifier), ENROLLMENT, &headers, body).await;

            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
            assert_eq!(message(response).await, "malformed_request", "{name}");
            assert!(store.is_empty(), "{name}");
            assert_eq!(verifier.calls(), 0, "{name}");
        }
    }

    #[tokio::test]
    async fn an_oversized_capture_body_is_rejected() {
        let store = Arc::new(MockNonceStore::empty());
        let verifier = MockCaptureVerifier::returning(Ok(()));

        let response = post(
            &app(&store, &verifier),
            ENROLLMENT,
            &evidence(),
            vec![b' '; MAX_CAPTURE_BODY_BYTES + 1],
        )
        .await;

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(message(response).await, "request_too_large");
        assert_eq!(verifier.calls(), 0);
    }

    #[tokio::test]
    async fn one_capture_can_obtain_only_a_limited_number_of_challenges() {
        let store = Arc::new(MockNonceStore::empty());
        let verifier = MockCaptureVerifier::returning(Ok(()));
        let app = create_app(
            Config {
                nitro_challenge_max_per_capture: 2,
                ..test_config()
            },
            deps(store.clone(), Some(verifier)),
        );

        // A retry needs a fresh challenge, so the same capture may come back.
        for _ in 0..2 {
            let response = post(&app, ENROLLMENT, &evidence(), capture()).await;
            assert_eq!(response.status(), StatusCode::CREATED);
        }
        let limited = post(&app, ENROLLMENT, &evidence(), capture()).await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(limited.headers()["retry-after"], "600");
        assert_eq!(message(limited).await, "challenge_limit_reached");

        // The limit is per capture, not global.
        let another = capture_with(|fields| fields["timestamp"] = "1700000001".into());
        let response = post(&app, ENROLLMENT, &evidence(), another).await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn rejected_evidence_does_not_spend_a_captures_allowance() {
        let store = Arc::new(MockNonceStore::empty());
        let config = || Config {
            nitro_challenge_max_per_capture: 1,
            ..test_config()
        };
        let rejecting = create_app(
            config(),
            deps(
                store.clone(),
                Some(MockCaptureVerifier::returning(Err(AttestationError::Trust))),
            ),
        );
        let accepting = create_app(
            config(),
            deps(store.clone(), Some(MockCaptureVerifier::returning(Ok(())))),
        );

        let response = post(&rejecting, ENROLLMENT, &evidence(), capture()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = post(&accepting, ENROLLMENT, &evidence(), capture()).await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn a_store_failure_while_counting_fails_closed() {
        let store = Arc::new(MockNonceStore::failing_count());
        let verifier = MockCaptureVerifier::returning(Ok(()));

        let response = post(&app(&store, &verifier), ENROLLMENT, &evidence(), capture()).await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(store.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verification_beyond_the_concurrency_limit_is_shed() {
        let store = Arc::new(MockNonceStore::empty());
        let verifier = MockCaptureVerifier::holding(Ok(()), Duration::from_millis(300));
        let app = create_app(
            Config {
                nitro_verify_concurrency: NonZeroUsize::new(1).unwrap(),
                ..test_config()
            },
            deps(store, Some(verifier.clone())),
        );

        let headers = evidence();
        let (first, second) = tokio::join!(
            post(&app, ENROLLMENT, &headers, capture()),
            post(&app, ENROLLMENT, &headers, capture()),
        );

        let mut statuses = [first.status(), second.status()];
        statuses.sort();
        assert_eq!(
            statuses,
            [StatusCode::CREATED, StatusCode::SERVICE_UNAVAILABLE]
        );
        assert_eq!(verifier.calls(), 1);
    }
}
