#[cfg(test)]
mod test_challenge_endpoint {
    use std::sync::Arc;
    use std::time::Duration;

    use axum::http::StatusCode;
    use chrono::{DateTime, Utc};
    use uuid::Uuid;
    use world_id_proof_verification_service::{
        app::create_app,
        cfg::config::Config,
        models::challenge_model::{ChallengeType, Nonce, NonceObject},
        services::nonce_store::NonceStore,
    };

    use crate::tests::support::{
        body_json, deps_with, post_empty, redis_store, test_config, MockNonceStore, RootVerdict,
    };

    // Mirrors the private `KEY_PREFIX` in `nonce_store`; the store trait exposes
    // no TTL getter, so the test checks the raw key directly.
    const KEY_PREFIX: &str = "nonce:";

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6380".to_string())
    }

    async fn redis_ttl(key: &str) -> i64 {
        let client = redis::Client::open(redis_url()).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        redis::cmd("TTL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .unwrap()
    }

    /// The core acceptance test: issue → documented body back, key present in
    /// Redis with a live TTL.
    #[tokio::test]
    async fn issue_persists_challenge_with_ttl() {
        let store = redis_store().await;
        let app = create_app(
            test_config(),
            deps_with(store.clone(), RootVerdict::Valid, true),
        );

        let before = Utc::now();
        let resp = post_empty(app, "/api/v4/zkp/challenge/enrollment").await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body: serde_json::Value = body_json(resp).await;
        let challenge_id = Uuid::parse_str(body["challenge_id"].as_str().unwrap()).unwrap();
        assert_eq!(body["challenge_type"], "enrollment");
        assert!(body["nonce"].as_str().unwrap().parse::<Nonce>().is_ok());
        let expires_at: DateTime<Utc> = body["expires_at"].as_str().unwrap().parse().unwrap();
        let delta = (expires_at - before).num_seconds();
        assert!(
            (595..=605).contains(&delta),
            "expires_at delta was {delta}s"
        );

        let stored: NonceObject = store.peek(&challenge_id).await.unwrap().unwrap();
        assert_eq!(stored.challenge_type, ChallengeType::Enrollment);
        let ttl = redis_ttl(&format!("{KEY_PREFIX}{challenge_id}")).await;
        assert!((1..=600).contains(&ttl), "redis TTL was {ttl}s");
    }

    #[tokio::test]
    async fn unknown_challenge_type_is_rejected() {
        let store = Arc::new(MockNonceStore::empty());
        let app = create_app(test_config(), deps_with(store, RootVerdict::Valid, true));
        let resp = post_empty(app, "/api/v4/zkp/challenge/not_a_real_type").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn redis_down_returns_503() {
        let store = Arc::new(MockNonceStore::failing_put());
        let app = create_app(test_config(), deps_with(store, RootVerdict::Valid, true));
        let resp = post_empty(app, "/api/v4/zkp/challenge/enrollment").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// TTL defaults to 10m and is overridable with a humantime string.
    #[test]
    fn challenge_ttl_is_configurable_default_10m() {
        use clap::Parser;
        // `--jwt-trusted-keys` is now a required arg; its value is not parsed here.
        let default = Config::parse_from([
            "svc",
            "--gateway-url",
            "http://gateway.test",
            "--jwt-trusted-keys",
            "{}",
        ]);
        assert_eq!(default.challenge_ttl, Duration::from_secs(600));

        let overridden = Config::parse_from([
            "svc",
            "--gateway-url",
            "http://gateway.test",
            "--jwt-trusted-keys",
            "{}",
            "--challenge-ttl",
            "42s",
        ]);
        assert_eq!(overridden.challenge_ttl, Duration::from_secs(42));
    }
}
