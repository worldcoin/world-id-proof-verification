#[cfg(test)]
mod test_readiness_endpoint {
    use std::sync::Arc;

    use axum::http::StatusCode;
    use world_id_proof_verification_service::app::create_app;

    use crate::tests::support::{
        body_string, deps_with, get, redis_store, test_config, MockNonceStore, RootVerdict,
    };

    #[tokio::test]
    async fn ready_when_redis_is_up() {
        let store = redis_store().await;
        let app = create_app(test_config(), deps_with(store, RootVerdict::Valid, true));
        let resp = get(app, "/ready").await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, r#"{"redis":"up"}"#);
    }

    #[tokio::test]
    async fn not_ready_when_redis_is_down() {
        let store = Arc::new(MockNonceStore::failing_ping());
        let app = create_app(test_config(), deps_with(store, RootVerdict::Valid, true));
        let resp = get(app, "/ready").await;

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body_string(resp).await, r#"{"redis":"down"}"#);
    }
}
