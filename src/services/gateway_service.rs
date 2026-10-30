//! `GatewayService`: decides whether a proof's `merkle_root` is currently
//! accepted by asking the gateway. Caching/freshness is the gateway's
//! responsibility, so this is a thin, fail-closed pass-through.

use std::sync::Arc;

use thiserror::Error;
use world_id_primitives::FieldElement;

use crate::clients::gateway::{GatewayClient, GatewayError};

#[derive(Debug, Error)]
pub enum GatewayServiceError {
    #[error(transparent)]
    Gateway(#[from] GatewayError),
}

/// Answers "is this Merkle root accepted?" via the gateway. `Err` means the
/// verdict could not be established (gateway unreachable); callers fail closed
/// rather than mistaking "unknown" for "invalid".
pub struct GatewayService {
    gateway: Arc<dyn GatewayClient>,
}

impl GatewayService {
    pub fn new(gateway: Arc<dyn GatewayClient>) -> Self {
        Self { gateway }
    }

    pub async fn is_valid_root(&self, root: FieldElement) -> Result<bool, GatewayServiceError> {
        Ok(self.gateway.is_valid_root(root).await?)
    }
}
