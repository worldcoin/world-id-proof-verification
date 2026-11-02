use std::{
    io,
    sync::{Arc, Mutex},
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Utc;
use serde_json::Value;
use telemetry_batteries::tracing::layers::datadog::DatadogFormat;
use tower::ServiceExt;
use tracing::instrument::WithSubscriber;
use tracing_subscriber::{fmt::MakeWriter, prelude::*, EnvFilter};
use world_id_proof_verification_service::app::create_app;
use world_id_proof_verification_service::models::challenge_model::{ChallengeType, NonceObject};

use super::support::{
    attacker_priv, body_json, deps_with, encode_proof, mock_deps, sign_token, svc_a_current_priv,
    svc_a_previous_priv, test_config, valid_bearer, MockNonceStore, RootVerdict, TEST_SVC,
};

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl io::Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogBuffer {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

impl LogBuffer {
    fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
        tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .event_format(DatadogFormat)
                .with_writer(self.clone())
                .with_filter(EnvFilter::new("info")),
        )
    }

    fn logs(&self) -> Vec<Value> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

#[tokio::test]
async fn request_outcome_logs_include_validated_challenge_type() {
    for challenge_type in ["enrollment", "teedi_migration"] {
        let buffer = LogBuffer::default();
        let response = create_app(test_config(), mock_deps())
            .oneshot(
                Request::post(format!("/api/v4/zkp/challenge/{challenge_type}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .with_subscriber(buffer.subscriber())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let logs = buffer.logs();
        assert!(logs
            .iter()
            .any(|log| log["stage"] == "http_response" && log["challenge_type"] == challenge_type));
    }

    let challenge_id = uuid::Uuid::new_v4();
    let now = Utc::now();
    let store = Arc::new(MockNonceStore::with(
        challenge_id,
        NonceObject {
            nonce: world_id_primitives::FieldElement::from(1u64),
            challenge_type: ChallengeType::TEEDIMigration,
            created_at: now,
            expires_at: now + chrono::Duration::minutes(10),
            issuer: "test".to_owned(),
        },
    ));
    let proof = encode_proof(
        &world_id_proof_verification_service::models::ownership_model::OwnershipProof {
            proof: world_id_proof::WhirR1CSProof {
                narg_string: vec![],
                hints: vec![],
                #[cfg(debug_assertions)]
                pattern: vec![],
            },
            merkle_root: world_id_primitives::FieldElement::from(42u64),
        },
    );
    let buffer = LogBuffer::default();
    let response = create_app(test_config(), deps_with(store, RootVerdict::Invalid, true))
        .oneshot(
            Request::post("/api/v4/verify")
                .header("authorization", valid_bearer())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "challenge_id": challenge_id,
                        "credential_sub": world_id_primitives::FieldElement::from(7u64),
                        "proof": proof,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .with_subscriber(buffer.subscriber())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let logs = buffer.logs();
    assert!(logs
        .iter()
        .any(|log| log["stage"] == "gateway_root_check"
            && log["challenge_type"] == "teedi_migration"));
    assert!(logs
        .iter()
        .any(|log| log["stage"] == "http_response" && log["challenge_type"] == "teedi_migration"));
}

#[tokio::test]
async fn datadog_json_includes_trace_ids_at_info() {
    use telemetry_batteries::opentelemetry::trace::TracerProvider;

    // An in-process provider needs no Agent or network exporter, while exercising
    // the same formatter and OpenTelemetry layer used by the Datadog preset.
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
    let buffer = LogBuffer::default();
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .event_format(DatadogFormat)
                .with_writer(buffer.clone())
                .with_filter(EnvFilter::new("info")),
        )
        .with(
            telemetry_batteries::tracing_opentelemetry::layer()
                .with_tracer(provider.tracer("observability-test")),
        );
    let response = create_app(test_config(), mock_deps())
        .oneshot(Request::post("/api/v4/verify").body(Body::empty()).unwrap())
        .with_subscriber(subscriber)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let logs = buffer.logs();
    assert_eq!(logs.len(), 2, "{logs:?}");
    for log in &logs {
        for field in ["dd.trace_id", "dd.span_id"] {
            assert_ne!(log[field].as_str().unwrap().parse::<u64>().unwrap(), 0);
        }
        assert_eq!(
            log["request_id"],
            response.headers()["x-request-id"].to_str().unwrap()
        );
        assert!(log["message"].is_string());
        assert!(
            log.get("fields").is_none(),
            "event fields must be flattened"
        );
    }
    assert_eq!(logs[0]["dd.trace_id"], logs[1]["dd.trace_id"]);
}

#[tokio::test]
async fn auth_failure_is_visible_at_info_and_correlated_without_secrets() {
    let buffer = LogBuffer::default();
    let app = create_app(test_config(), mock_deps());
    let request = Request::post("/api/v4/verify?token=secret-query-marker")
        .header("authorization", "Bearer secret-token-marker")
        .header("x-request-id", "untrusted-id-marker")
        .body(Body::from("secret-body-marker"))
        .unwrap();
    let response = app
        .oneshot(request)
        .with_subscriber(buffer.subscriber())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let id = response.headers()["x-request-id"].to_str().unwrap();
    assert!(uuid::Uuid::parse_str(id).is_ok());
    let logs = buffer.logs();
    let rejection = logs
        .iter()
        .find(|log| log["stage"] == "authentication")
        .unwrap();
    assert_eq!(rejection["level"], "WARN");
    assert_eq!(rejection["error_kind"], "malformed");
    assert_eq!(rejection["http.route"], "/api/v4/verify");
    assert_eq!(rejection["service"], env!("CARGO_PKG_NAME"));
    assert_eq!(rejection["env"], "test");
    let completion = logs
        .iter()
        .find(|log| log["stage"] == "http_response")
        .unwrap();
    assert_eq!(completion["http.status_code"], 401);
    assert!(completion["duration_ms"].is_number());
    for log in &logs {
        assert_eq!(log["request_id"], id);
        assert!(!log.to_string().contains("marker"));
    }
}

#[tokio::test]
async fn auth_rejection_reasons_survive_key_rotation_and_reach_outcome_logs() {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;

    let sign = |claims: Value, key: &str| {
        format!(
            "Bearer {}",
            encode(
                &Header::new(Algorithm::ES256),
                &claims,
                &EncodingKey::from_ec_pem(key.as_bytes()).unwrap()
            )
            .unwrap()
        )
    };
    let bearer = |sub, key, exp, nbf| format!("Bearer {}", sign_token(sub, key, exp, nbf));
    let header = data_encoding::BASE64URL_NOPAD.encode(br#"{"alg":"ES256"}"#);
    let bad_json = data_encoding::BASE64URL_NOPAD.encode(b"{secret-payload-marker");
    let unsigned_header = data_encoding::BASE64URL_NOPAD.encode(br#"{"alg":"none"}"#);
    let cases = [
        (None, "missing_token"),
        (Some("Bearer   ".into()), "missing_token"),
        (Some("Basic secret-token-marker".into()), "bad_scheme"),
        (Some("Bearer not.a.jwt".into()), "malformed"),
        (
            Some(format!("Bearer {header}.{bad_json}.signature")),
            "malformed",
        ),
        (Some(format!("Bearer {unsigned_header}.e30.")), "bad_alg"),
        (
            Some(sign(json!({"exp": 9999999999u64}), svc_a_current_priv())),
            "missing_sub",
        ),
        (
            Some(sign(
                json!({"sub": 123, "exp": 9999999999u64}),
                svc_a_current_priv(),
            )),
            "invalid_claims",
        ),
        (
            Some(sign(json!({"sub": TEST_SVC}), svc_a_current_priv())),
            "missing_or_invalid_exp",
        ),
        (
            Some(sign(json!({"sub": TEST_SVC}), svc_a_previous_priv())),
            "missing_or_invalid_exp",
        ),
        (
            Some(sign(
                json!({"sub": TEST_SVC, "exp": "secret-exp-marker"}),
                svc_a_current_priv(),
            )),
            "missing_or_invalid_exp",
        ),
        (
            Some(bearer(
                "unknown-sub-marker",
                svc_a_current_priv(),
                3600,
                None,
            )),
            "unknown_sub",
        ),
        (
            Some(bearer(TEST_SVC, attacker_priv(), 3600, None)),
            "bad_signature",
        ),
        (
            Some(bearer(TEST_SVC, svc_a_current_priv(), -120, None)),
            "expired",
        ),
        (
            Some(bearer(TEST_SVC, svc_a_previous_priv(), -120, None)),
            "expired",
        ),
        (
            Some(bearer(TEST_SVC, svc_a_current_priv(), 7200, Some(3600))),
            "not_yet_valid",
        ),
    ];

    for (authorization, expected_kind) in cases {
        let buffer = LogBuffer::default();
        let store = Arc::new(MockNonceStore::empty());
        let app = create_app(
            test_config(),
            deps_with(store.clone(), RootVerdict::Valid, true),
        );
        let mut request =
            Request::post("/api/v4/verify").header("content-type", "application/json");
        if let Some(ref token) = authorization {
            request = request.header("authorization", token);
        }
        let response = app
            .oneshot(request.body(Body::from("{secret-body-marker")).unwrap())
            .with_subscriber(buffer.subscriber())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let id = response.headers()["x-request-id"]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            body_json::<Value>(response).await,
            json!({"msg": "unauthorized"})
        );
        assert_eq!(store.peek_calls(), 0);
        assert_eq!(store.consume_calls(), 0);

        let logs = buffer.logs();
        assert_eq!(logs.len(), 2, "{logs:?}");
        let auth = logs
            .iter()
            .find(|log| log["event"] == "authentication_rejected")
            .unwrap();
        assert_eq!(auth["stage"], "authentication");
        assert_eq!(auth["error_kind"], expected_kind);
        assert_eq!(auth["http.status_code"], 401);
        assert!(!auth["reason"].as_str().unwrap().is_empty());
        for log in &logs {
            assert_eq!(log["level"], "WARN");
            assert_eq!(log["auth.outcome"], "rejected");
            assert_eq!(log["auth.error_kind"], expected_kind);
            assert_eq!(log["request_id"], id);
        }
        let text = serde_json::to_string(&logs).unwrap();
        assert!(!text.contains("marker"));
        if let Some(token) = authorization {
            assert!(!text.contains(&token));
        }
    }
}

#[tokio::test]
async fn proof_rejection_401_explicitly_records_successful_authentication() {
    use world_id_primitives::FieldElement;
    use world_id_proof::WhirR1CSProof;
    use world_id_proof_verification_service::models::ownership_model::{
        OwnershipProof, OwnershipVerificationRequest,
    };

    let proof = encode_proof(&OwnershipProof {
        proof: WhirR1CSProof {
            narg_string: vec![],
            hints: vec![],
            #[cfg(debug_assertions)]
            pattern: vec![],
        },
        merkle_root: FieldElement::from(42u64),
    });
    // Both configured keys must authenticate and reach the missing-nonce rejection.
    for key in [svc_a_current_priv(), svc_a_previous_priv()] {
        let buffer = LogBuffer::default();
        let request = Request::post("/api/v4/verify")
            .header(
                "authorization",
                format!("Bearer {}", sign_token(TEST_SVC, key, 3600, None)),
            )
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&OwnershipVerificationRequest {
                    challenge_id: uuid::Uuid::new_v4(),
                    credential_sub: FieldElement::from(7u64).to_string(),
                    proof: proof.clone(),
                })
                .unwrap(),
            ))
            .unwrap();
        let response = create_app(test_config(), mock_deps())
            .oneshot(request)
            .with_subscriber(buffer.subscriber())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json::<Value>(response).await["msg"], "proof_rejected");
        let logs = buffer.logs();
        let completion = logs
            .iter()
            .find(|log| log["stage"] == "http_response")
            .unwrap();
        assert_eq!(completion["auth.outcome"], "accepted");
        assert_eq!(completion["http.status_code"], 401);
        assert!(completion.get("auth.error_kind").is_none());
        assert!(!logs
            .iter()
            .any(|log| log["event"] == "authentication_rejected"));
    }
}

#[tokio::test]
async fn extractor_rejections_have_stage_and_keep_http_status() {
    for (path, body, content_type, expected, kind) in [
        ("/api/v1/verify", "{", true, 400, "invalid_json_syntax"),
        ("/api/v1/verify", "{}", true, 422, "invalid_json_shape"),
        (
            "/api/v1/verify",
            "{}",
            false,
            415,
            "missing_json_content_type",
        ),
        ("/api/v1/gen", "{", true, 400, "invalid_json_syntax"),
        ("/api/v4/verify", "{", true, 400, "invalid_json_syntax"),
        (
            "/api/v4/verify",
            "[[[[[[[[[[[[[[[[[",
            true,
            413,
            "json_nesting_too_deep",
        ),
        (
            "/api/v4/zkp/challenge/secret-path-marker",
            "",
            false,
            400,
            "invalid_challenge_type",
        ),
    ] {
        let buffer = LogBuffer::default();
        let mut cfg = test_config();
        cfg.enable_proof_gen_endpoint = true;
        let app = create_app(cfg, mock_deps());
        let mut request = Request::post(path).header("authorization", valid_bearer());
        if content_type {
            request = request.header("content-type", "application/json");
        }
        let response = app
            .oneshot(request.body(Body::from(body)).unwrap())
            .with_subscriber(buffer.subscriber())
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), expected, "{path}");
        let logs = buffer.logs();
        assert!(
            logs.iter()
                .any(|log| log["stage"] == "request_decode" && log["error_kind"] == kind),
            "{logs:?}"
        );
        assert!(logs
            .iter()
            .any(|log| log["stage"] == "http_response" && log["http.status_code"] == expected));
        if kind == "invalid_challenge_type" {
            assert!(logs.iter().all(|log| log.get("challenge_type").is_none()));
        }
        assert!(!serde_json::to_string(&logs)
            .unwrap()
            .contains("secret-path-marker"));
    }
}

#[tokio::test]
async fn infrastructure_failures_log_error_and_stage() {
    for (path, method, store, stage) in [
        (
            "/api/v4/zkp/challenge/enrollment",
            "POST",
            MockNonceStore::failing_put(),
            "nonce_put",
        ),
        ("/ready", "GET", MockNonceStore::failing_ping(), "readiness"),
    ] {
        let buffer = LogBuffer::default();
        let app = create_app(
            test_config(),
            deps_with(Arc::new(store), RootVerdict::Valid, true),
        );
        let request = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let response = app
            .oneshot(request)
            .with_subscriber(buffer.subscriber())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let logs = buffer.logs();
        let failure = logs.iter().find(|log| log["stage"] == stage).unwrap();
        assert_eq!(failure["level"], "ERROR");
        assert_eq!(
            failure["request_id"],
            response.headers()["x-request-id"].to_str().unwrap()
        );
        assert!(logs
            .iter()
            .any(|log| log["stage"] == "http_response" && log["http.status_code"] == 503));
    }
}

#[tokio::test]
async fn routing_failures_are_logged_and_successful_probes_are_quiet() {
    for (path, expected) in [
        ("/secret-path-marker", 404),
        ("/api/v4/verify", 405),
        ("/health", 200),
        ("/ready", 200),
    ] {
        let buffer = LogBuffer::default();
        let response = create_app(test_config(), mock_deps())
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .with_subscriber(buffer.subscriber())
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), expected);
        let logs = buffer.logs();
        if expected == 200 {
            assert!(logs.is_empty(), "{logs:?}");
        } else {
            assert!(
                logs.iter()
                    .any(|log| log["stage"] == "http_response"
                        && log["http.status_code"] == expected),
                "{logs:?}"
            );
            assert!(!serde_json::to_string(&logs)
                .unwrap()
                .contains("secret-path-marker"));
        }
    }
}
