//! HTTP client for the World ID gateway's `GET /is-valid-root?root=<hex>`
//! endpoint, which returns `{ "valid": bool }`.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::Url;
use thiserror::Error;
use tracing::{error, instrument};
use world_id_primitives::api_types::IsValidRootResponse;
use world_id_primitives::FieldElement;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("gateway transport error: {0}")]
    Transport(String),
    #[error("gateway returned status {0}")]
    UnexpectedStatus(u16),
    #[error("invalid gateway base url: {0}")]
    InvalidUrl(String),
}

/// Reads root validity from the gateway. Kept as a trait so the
/// [`GatewayService`](crate::services::gateway_service) policy is testable
/// without a live gateway.
#[async_trait]
pub trait GatewayClient: Send + Sync {
    async fn is_valid_root(&self, root: FieldElement) -> Result<bool, GatewayError>;
}

#[derive(Clone, Debug)]
pub struct GatewayClientConfig {
    pub base_url: String,
    /// Per-request deadline bounding the gateway call.
    pub request_timeout: Duration,
}

pub struct HttpGatewayClient {
    client: reqwest::Client,
    base_url: Url,
}

impl HttpGatewayClient {
    pub fn new(cfg: &GatewayClientConfig) -> Result<Self, GatewayError> {
        // Normalize to a directory base so relative joins keep any path prefix.
        let base_url = Url::parse(&format!("{}/", cfg.base_url.trim_end_matches('/')))
            .map_err(|e| GatewayError::InvalidUrl(e.to_string()))?;
        let client = reqwest::Client::builder()
            .timeout(cfg.request_timeout)
            .build()
            .map_err(|e| GatewayError::Transport(e.without_url().to_string()))?;
        Ok(Self { client, base_url })
    }

    fn endpoint(&self, path: &str) -> Result<Url, GatewayError> {
        self.base_url
            .join(path)
            .map_err(|e| GatewayError::InvalidUrl(e.to_string()))
    }
}

#[async_trait]
impl GatewayClient for HttpGatewayClient {
    #[instrument(skip(self), fields(dependency = "gateway", root = %root))]
    async fn is_valid_root(&self, root: FieldElement) -> Result<bool, GatewayError> {
        // FieldElement's Display is the 0x-prefixed 32-byte hex the gateway parses.
        let resp = self
            .client
            .get(self.endpoint("is-valid-root")?)
            .query(&[("root", root.to_string())])
            .send()
            .await
            .map_err(|e| {
                let e = e.without_url();
                error!(stage = "gateway_request", error_kind = "transport_error", error = %e, "gateway request failed");
                GatewayError::Transport(e.to_string())
            })?;

        let status = resp.status();
        if !status.is_success() {
            error!(
                stage = "gateway_response",
                error_kind = "unexpected_status",
                upstream_status = status.as_u16(),
                "gateway non-success status"
            );
            return Err(GatewayError::UnexpectedStatus(status.as_u16()));
        }

        let body: IsValidRootResponse = resp
            .json()
            .await
            .map_err(|e| {
                let e = e.without_url();
                error!(stage = "gateway_decode", error_kind = "invalid_gateway_response", error = %e, "gateway response decode failed");
                GatewayError::Transport(e.to_string())
            })?;
        Ok(body.valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_builds_is_valid_root_endpoint() {
        for base in ["http://gw:8080", "http://gw:8080/", "http://gw/prefix"] {
            let client = HttpGatewayClient::new(&GatewayClientConfig {
                base_url: base.to_string(),
                request_timeout: Duration::from_secs(2),
            })
            .unwrap();
            let url = client.endpoint("is-valid-root").unwrap();
            assert!(url.as_str().ends_with("/is-valid-root"), "url was {url}");
        }
    }

    #[test]
    fn new_rejects_malformed_url() {
        let result = HttpGatewayClient::new(&GatewayClientConfig {
            base_url: "not a url".to_string(),
            request_timeout: Duration::from_secs(2),
        });
        assert!(matches!(result, Err(GatewayError::InvalidUrl(_))));
    }
}
