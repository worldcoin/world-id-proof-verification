//! JWT auth on `POST /api/v4/verify`. Both auth failure and a passing
//! request over the empty mock store return `401`, so they are told apart by
//! body: `unauthorized` (rejected) vs `proof_rejected` (auth passed, handler ran).

#[cfg(test)]
mod verify_auth_endpoint {
    use std::sync::Arc;

    use axum::http::StatusCode;
    use axum::response::Response;
    use chrono::Utc;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde::Serialize;
    use world_id_primitives::FieldElement;
    use world_id_proof::WhirR1CSProof;
    use world_id_proof_verification_service::{
        app::create_app,
        models::{
            challenge_model::ChallengeId,
            ownership_model::{OwnershipProof, OwnershipVerificationRequest},
        },
    };

    use crate::tests::support::{
        attacker_priv, body_json, deps_with, encode_proof, get, mock_deps, post_empty, post_json,
        post_json_authed, sign_token, svc_a_current_priv, svc_a_previous_priv, svc_b_current_priv,
        test_config, valid_bearer, MockNonceStore, RootVerdict, TEST_SVC, TEST_SVC_B,
    };

    const VERIFY: &str = "/api/v4/verify";

    fn sample_request() -> OwnershipVerificationRequest {
        OwnershipVerificationRequest {
            challenge_id: ChallengeId::new_v4(),
            credential_sub: FieldElement::from(7u64).to_string(),
            proof: encode_proof(&OwnershipProof {
                proof: WhirR1CSProof {
                    narg_string: vec![1, 2, 3, 4],
                    hints: vec![9, 8, 7],
                    #[cfg(debug_assertions)]
                    pattern: Vec::new(),
                },
                merkle_root: FieldElement::from(42u64),
            }),
        }
    }

    fn app() -> axum::Router {
        create_app(test_config(), mock_deps())
    }

    async fn msg_of(resp: Response) -> String {
        let body: serde_json::Value = body_json(resp).await;
        body["msg"].as_str().unwrap_or_default().to_string()
    }

    fn bearer(sub: &str, priv_pem: &str) -> String {
        format!("Bearer {}", sign_token(sub, priv_pem, 3600, None))
    }

    #[tokio::test]
    async fn missing_token_is_unauthorized() {
        let resp = post_json(app(), VERIFY, &sample_request()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(msg_of(resp).await, "unauthorized");
    }

    #[tokio::test]
    async fn auth_rejection_wins_over_malformed_body() {
        let mut req = sample_request();
        req.proof = "!!!not-base64!!!".to_string();
        let resp = post_json(app(), VERIFY, &req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(msg_of(resp).await, "unauthorized");
    }

    #[tokio::test]
    async fn wrong_scheme_is_unauthorized() {
        let token = sign_token(TEST_SVC, svc_a_current_priv(), 3600, None);
        let resp =
            post_json_authed(app(), VERIFY, &sample_request(), &format!("Basic {token}")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(msg_of(resp).await, "unauthorized");
    }

    #[tokio::test]
    async fn malformed_token_is_unauthorized() {
        let resp = post_json_authed(app(), VERIFY, &sample_request(), "Bearer not.a.jwt").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(msg_of(resp).await, "unauthorized");
    }

    #[tokio::test]
    async fn wrong_algorithm_is_unauthorized() {
        #[derive(Serialize)]
        struct C {
            sub: String,
            exp: usize,
        }
        let claims = C {
            sub: TEST_SVC.to_string(),
            exp: (Utc::now().timestamp() + 3600) as usize,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"shared-secret"),
        )
        .unwrap();
        let resp =
            post_json_authed(app(), VERIFY, &sample_request(), &format!("Bearer {token}")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(msg_of(resp).await, "unauthorized");
    }

    #[tokio::test]
    async fn none_algorithm_is_unauthorized() {
        // Hand-crafted unsigned token: header {"alg":"none"}, empty signature.
        let header = data_encoding::BASE64URL_NOPAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = data_encoding::BASE64URL_NOPAD
            .encode(format!(r#"{{"sub":"{TEST_SVC}","exp":9999999999}}"#).as_bytes());
        let token = format!("{header}.{payload}.");
        let resp =
            post_json_authed(app(), VERIFY, &sample_request(), &format!("Bearer {token}")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(msg_of(resp).await, "unauthorized");
    }

    #[tokio::test]
    async fn unknown_sub_is_unauthorized() {
        let resp = post_json_authed(
            app(),
            VERIFY,
            &sample_request(),
            &bearer("ghost", svc_a_current_priv()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(msg_of(resp).await, "unauthorized");
    }

    #[tokio::test]
    async fn expired_token_is_unauthorized() {
        let token = format!(
            "Bearer {}",
            sign_token(TEST_SVC, svc_a_current_priv(), -120, None)
        );
        let resp = post_json_authed(app(), VERIFY, &sample_request(), &token).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(msg_of(resp).await, "unauthorized");
    }

    #[tokio::test]
    async fn not_yet_valid_token_is_unauthorized() {
        let token = format!(
            "Bearer {}",
            sign_token(TEST_SVC, svc_a_current_priv(), 7200, Some(3600))
        );
        let resp = post_json_authed(app(), VERIFY, &sample_request(), &token).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(msg_of(resp).await, "unauthorized");
    }

    #[tokio::test]
    async fn wrong_key_for_sub_is_unauthorized() {
        let resp = post_json_authed(
            app(),
            VERIFY,
            &sample_request(),
            &bearer(TEST_SVC, attacker_priv()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(msg_of(resp).await, "unauthorized");
    }

    #[tokio::test]
    async fn cross_sub_impersonation_is_unauthorized() {
        // sub=service-b but signed with test-service's key.
        let resp = post_json_authed(
            app(),
            VERIFY,
            &sample_request(),
            &bearer(TEST_SVC_B, svc_a_current_priv()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(msg_of(resp).await, "unauthorized");
    }

    #[tokio::test]
    async fn valid_current_key_token_passes_auth() {
        let resp = post_json_authed(app(), VERIFY, &sample_request(), &valid_bearer()).await;
        assert_eq!(msg_of(resp).await, "proof_rejected");
    }

    #[tokio::test]
    async fn previous_key_token_passes_auth() {
        let token = bearer(TEST_SVC, svc_a_previous_priv());
        let resp = post_json_authed(app(), VERIFY, &sample_request(), &token).await;
        assert_eq!(msg_of(resp).await, "proof_rejected");
    }

    #[tokio::test]
    async fn lowercase_bearer_scheme_passes_auth() {
        let token = format!(
            "bearer {}",
            sign_token(TEST_SVC, svc_a_current_priv(), 3600, None)
        );
        let resp = post_json_authed(app(), VERIFY, &sample_request(), &token).await;
        assert_eq!(msg_of(resp).await, "proof_rejected");
    }

    #[tokio::test]
    async fn service_b_current_key_token_passes_auth() {
        let token = bearer(TEST_SVC_B, svc_b_current_priv());
        let resp = post_json_authed(app(), VERIFY, &sample_request(), &token).await;
        assert_eq!(msg_of(resp).await, "proof_rejected");
    }

    #[tokio::test]
    async fn rejected_auth_never_touches_the_nonce_store() {
        let store = Arc::new(MockNonceStore::empty());
        let deps = deps_with(store.clone(), RootVerdict::Valid, true);
        let app = create_app(test_config(), deps);

        let resp = post_json(app, VERIFY, &sample_request()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(store.peek_calls(), 0);
        assert_eq!(store.consume_calls(), 0);
    }

    #[tokio::test]
    async fn challenge_route_is_open_without_a_token() {
        let issued = post_empty(app(), "/api/v4/zkp/challenge/enrollment").await;
        assert_eq!(issued.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn health_is_open_without_a_token() {
        let resp = get(app(), "/health").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rejection_body_is_uniform_across_classes() {
        let cases = [
            "Bearer not.a.jwt".to_string(),
            format!(
                "Bearer {}",
                sign_token(TEST_SVC, svc_a_current_priv(), -120, None)
            ),
            bearer(TEST_SVC, attacker_priv()),
            bearer("ghost", svc_a_current_priv()),
        ];
        for token in cases {
            let resp = post_json_authed(app(), VERIFY, &sample_request(), &token).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(msg_of(resp).await, "unauthorized");
        }
    }
}
