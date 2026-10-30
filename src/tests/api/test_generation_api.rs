#[cfg(test)]
mod test_generation_endpoint {
    use axum::http::StatusCode;
    use serde_json::Value;
    use world_id_proof_verification_service::{
        api::generation_api::GenerationMsg, api::generation_api::GenerationResult, app::create_app,
        cfg::config::Config, models::generation_model::Generation,
    };

    use crate::tests::support::{body_json, mock_deps, post_json};

    // Build a Config directly instead of `Config::parse()` reading process-global
    // env vars. cargo runs tests in parallel within a single process, so sharing
    // env (e.g. ENABLE_PROOF_GEN_ENDPOINT) races across tests; this keeps each
    // test hermetic.
    fn test_config(enable_proof_gen_endpoint: bool) -> Config {
        Config {
            srv_env: "test".to_string(),
            srv_name: "world-id-proof-verification-service".to_string(),
            srv_version: "0.0.0".to_string(),
            dd_agent_host: "127.0.0.1".to_string(),
            dd_agent_port: "8126".to_string(),
            dd_statsd_port: "8125".to_string(),
            response_duration_seconds: 300,
            verification_concurrency: std::num::NonZeroUsize::new(4).unwrap(),
            rust_log: "info".to_string(),
            enable_proof_gen_endpoint,
            redis_url: "redis://127.0.0.1:6379".to_string(),
            redis_command_timeout_ms: 2000,
            challenge_ttl: std::time::Duration::from_secs(600),
            gateway_url: "http://127.0.0.1:8080".to_string(),
            gateway_timeout: std::time::Duration::from_secs(2),
            jwt_trusted_keys: crate::tests::support::test_jwt_trusted_keys_json(),
            max_body_bytes: bytesize::ByteSize::kib(512),
            verify_timeout: std::time::Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn test_proof_generation_success() {
        let generation_request = Generation {
            secret: "my_test_secret".to_string(),
            external_nullifier: "pii.deletion".to_string(),
        };

        let cfg = test_config(true);
        let app = create_app(cfg, mock_deps());
        let resp = post_json(app, "/api/v1/gen", &generation_request).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body: GenerationResult = body_json(resp).await;
        assert_eq!(resp_body.msg, GenerationMsg::ProofGenerated);
    }

    #[tokio::test]
    async fn test_proof_generation_disabled() {
        let generation_request = Generation {
            secret: "my_test_secret".to_string(),
            external_nullifier: "pii.deletion".to_string(),
        };

        // Endpoint is gated off, so the route is not registered at all.
        let cfg = test_config(false);
        let app = create_app(cfg, mock_deps());
        let resp = post_json(app, "/api/v1/gen", &generation_request).await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_generated_fields_have_64_char_hex() {
        let generation_request = Generation {
            secret: "test_secret_for_hex_check".to_string(),
            external_nullifier: "test.scope".to_string(),
        };

        let cfg = test_config(true);
        let app = create_app(cfg, mock_deps());
        let resp = post_json(app, "/api/v1/gen", &generation_request).await;

        assert_eq!(resp.status(), StatusCode::OK);

        // Parse response as JSON to check hex field lengths
        let json: Value = body_json(resp).await;

        // Extract the proof object
        let proof = &json["proof"];
        let id_commitment = proof["idCommitment"].as_str().unwrap();

        // Verify idCommitment is exactly 66 characters (0x + 64 hex chars - bug fix verification)
        assert_eq!(
            id_commitment.len(),
            66,
            "idCommitment must be exactly 66 characters (0x + 64 hex), got {} chars: {}",
            id_commitment.len(),
            id_commitment
        );

        // Verify lowercase and has 0x prefix
        assert_eq!(id_commitment, id_commitment.to_lowercase());
        assert!(
            id_commitment.starts_with("0x"),
            "idCommitment should start with 0x"
        );
    }

    #[tokio::test]
    async fn test_multiple_generations_all_64_chars() {
        let test_secrets = vec!["secret1", "secret2", "worldcoin", "test"];

        let cfg = test_config(true);

        for secret in test_secrets {
            let app = create_app(cfg.clone(), mock_deps());

            let generation_request = Generation {
                secret: secret.to_string(),
                external_nullifier: "test.scope".to_string(),
            };

            let resp = post_json(app, "/api/v1/gen", &generation_request).await;

            assert_eq!(resp.status(), StatusCode::OK);

            let json: Value = body_json(resp).await;

            let proof = &json["proof"];
            let id_commitment = proof["idCommitment"].as_str().unwrap();

            assert_eq!(
                id_commitment.len(),
                66,
                "Failed for secret '{}': idCommitment length is {} (expected 66: 0x + 64 hex)",
                secret,
                id_commitment.len()
            );

            // Verify it starts with 0x
            assert!(
                id_commitment.starts_with("0x"),
                "idCommitment should start with 0x"
            );
        }
    }
}
