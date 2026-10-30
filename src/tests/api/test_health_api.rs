#[cfg(test)]
mod test_health_check {
    use axum::http::StatusCode;
    use world_id_proof_verification_service::app::create_app;

    use crate::tests::support::{body_string, get, mock_deps, test_config};

    #[tokio::test]
    async fn test() {
        let app = create_app(test_config(), mock_deps());
        let resp = get(app, "/health").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let expected_body = r#"{"msg":"check","app_name":"world-id-proof-verification-service","app_version":"1.0.0"}"#;
        assert_eq!(body_string(resp).await, expected_body);
    }
}
