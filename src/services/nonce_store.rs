//! Single-use nonce storage: `put` writes once (`SET .. NX EX`), `peek` reads
//! without consuming (`GET`), and `consume` reads-and-deletes atomically
//! (`GETDEL`) for at-most-once use. Backend failures fail closed via
//! [`NonceStoreError`] — the store never reports a success it cannot guarantee.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::{AsyncCommands, ExistenceCheck, SetExpiry, SetOptions};
use thiserror::Error;
use tracing::instrument;

use crate::models::challenge_model::{ChallengeId, NonceObject};

const KEY_PREFIX: &str = "nonce:";

/// Failure of a [`NonceStore`] operation. Callers treat every variant as
/// failure: issuance returns 503, consumption rejects.
#[derive(Debug, Error)]
pub enum NonceStoreError {
    #[error("nonce store backend error: {0}")]
    Backend(String),
    #[error("nonce store serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("challenge_id already exists")]
    AlreadyExists,
}

impl From<redis::RedisError> for NonceStoreError {
    fn from(e: redis::RedisError) -> Self {
        NonceStoreError::Backend(e.to_string())
    }
}

/// Single-use nonce storage port; used behind [`DynNonceStore`].
#[async_trait]
pub trait NonceStore: Send + Sync {
    async fn put(
        &self,
        challenge_id: &ChallengeId,
        nonce: &NonceObject,
        ttl: Duration,
    ) -> Result<(), NonceStoreError>;

    /// Reads a nonce without removing it. Use before a failable check so a
    /// rejection does not burn the challenge; a later `consume` still
    /// guarantees at-most-once success.
    async fn peek(
        &self,
        challenge_id: &ChallengeId,
    ) -> Result<Option<NonceObject>, NonceStoreError>;

    /// Atomically reads and removes a nonce (`GETDEL`): at most one concurrent
    /// caller gets `Some`, the rest get `None`.
    async fn consume(
        &self,
        challenge_id: &ChallengeId,
    ) -> Result<Option<NonceObject>, NonceStoreError>;

    /// Liveness probe for the backend (a Redis `PING`), for readiness checks.
    async fn ping(&self) -> Result<(), NonceStoreError>;
}

pub type DynNonceStore = Arc<dyn NonceStore>;

/// `url` carries scheme, host, optional AUTH and optional TLS:
/// `redis://host`, `redis://:password@host`, or `rediss://host`.
#[derive(Clone, Debug)]
pub struct RedisConfig {
    pub url: String,
    pub command_timeout: Duration,
}

#[derive(Clone)]
pub struct RedisNonceStore {
    conn: ConnectionManager,
}

impl RedisNonceStore {
    #[instrument(skip(cfg))]
    pub async fn connect(cfg: &RedisConfig) -> Result<Self, NonceStoreError> {
        let client = redis::Client::open(cfg.url.as_str())?;
        let manager_cfg = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(cfg.command_timeout))
            .set_response_timeout(Some(cfg.command_timeout));
        let conn = ConnectionManager::new_with_config(client, manager_cfg).await?;
        Ok(Self { conn })
    }

    fn key(challenge_id: &ChallengeId) -> String {
        format!("{KEY_PREFIX}{challenge_id}")
    }

    fn decode(raw: Option<String>) -> Result<Option<NonceObject>, NonceStoreError> {
        raw.map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(Into::into)
    }
}

#[async_trait]
impl NonceStore for RedisNonceStore {
    #[instrument(skip(self, nonce), fields(challenge_id = %challenge_id))]
    async fn put(
        &self,
        challenge_id: &ChallengeId,
        nonce: &NonceObject,
        ttl: Duration,
    ) -> Result<(), NonceStoreError> {
        let value = serde_json::to_string(nonce)?;
        let opts = SetOptions::default()
            .conditional_set(ExistenceCheck::NX)
            .with_expiration(SetExpiry::EX(ttl.as_secs()));
        let mut conn = self.conn.clone();
        let set: Option<String> = conn
            .set_options(Self::key(challenge_id), value, opts)
            .await?;
        match set {
            Some(_) => Ok(()),
            None => Err(NonceStoreError::AlreadyExists),
        }
    }

    #[instrument(skip(self), fields(challenge_id = %challenge_id))]
    async fn peek(
        &self,
        challenge_id: &ChallengeId,
    ) -> Result<Option<NonceObject>, NonceStoreError> {
        let mut conn = self.conn.clone();
        let raw: Option<String> = conn.get(Self::key(challenge_id)).await?;
        Self::decode(raw)
    }

    #[instrument(skip(self), fields(challenge_id = %challenge_id))]
    async fn consume(
        &self,
        challenge_id: &ChallengeId,
    ) -> Result<Option<NonceObject>, NonceStoreError> {
        let mut conn = self.conn.clone();
        let raw: Option<String> = conn.get_del(Self::key(challenge_id)).await?;
        Self::decode(raw)
    }

    #[instrument(skip(self))]
    async fn ping(&self) -> Result<(), NonceStoreError> {
        let mut conn = self.conn.clone();
        let _: String = redis::cmd("PING").query_async(&mut conn).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::challenge_model::{ChallengeType, Nonce};
    use chrono::Utc;

    async fn test_store() -> RedisNonceStore {
        let url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6380".to_string());
        RedisNonceStore::connect(&RedisConfig {
            url,
            command_timeout: Duration::from_secs(2),
        })
        .await
        .expect("start Redis with `docker compose up -d redis`")
    }

    fn sample_nonce_object() -> NonceObject {
        let now = Utc::now();
        NonceObject {
            nonce: Nonce::ONE,
            challenge_type: ChallengeType::Enrollment,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(600),
            issuer: "test".to_string(),
        }
    }

    #[test]
    fn key_is_namespaced() {
        assert_eq!(
            RedisNonceStore::key(&ChallengeId::nil()),
            "nonce:00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn redis_error_maps_to_backend() {
        let err = redis::Client::open("redis://127.0.0.1:1/")
            .unwrap()
            .get_connection()
            .err()
            .expect("connection to a closed port must fail");
        assert!(matches!(
            NonceStoreError::from(err),
            NonceStoreError::Backend(_)
        ));
    }

    #[tokio::test]
    async fn peek_reads_without_consuming() {
        let store = test_store().await;
        let id = ChallengeId::new_v4();
        let obj = sample_nonce_object();
        store.put(&id, &obj, Duration::from_secs(60)).await.unwrap();
        // Repeated peeks keep returning the value; it is not removed.
        assert_eq!(store.peek(&id).await.unwrap().as_ref(), Some(&obj));
        assert_eq!(store.peek(&id).await.unwrap().as_ref(), Some(&obj));
        // consume removes it; a later peek finds it gone.
        assert_eq!(store.consume(&id).await.unwrap().as_ref(), Some(&obj));
        assert_eq!(store.peek(&id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn consume_is_single_use() {
        let store = test_store().await;
        let id = ChallengeId::new_v4();
        let obj = sample_nonce_object();
        store.put(&id, &obj, Duration::from_secs(60)).await.unwrap();
        assert_eq!(store.consume(&id).await.unwrap().as_ref(), Some(&obj));
        assert_eq!(store.consume(&id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn missing_key_returns_none() {
        let store = test_store().await;
        let id = ChallengeId::new_v4();
        assert_eq!(store.peek(&id).await.unwrap(), None);
        assert_eq!(store.consume(&id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn put_is_nx_and_rejects_duplicate() {
        let store = test_store().await;
        let id = ChallengeId::new_v4();
        let obj = sample_nonce_object();
        store.put(&id, &obj, Duration::from_secs(60)).await.unwrap();
        assert!(matches!(
            store.put(&id, &obj, Duration::from_secs(60)).await,
            Err(NonceStoreError::AlreadyExists)
        ));
    }

    #[tokio::test]
    async fn concurrent_consumes_exactly_one_succeeds() {
        let store = test_store().await;
        let id = ChallengeId::new_v4();
        store
            .put(&id, &sample_nonce_object(), Duration::from_secs(60))
            .await
            .unwrap();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            handles.push(tokio::spawn(async move { store.consume(&id).await }));
        }
        let mut winners = 0;
        for h in handles {
            if h.await.unwrap().unwrap().is_some() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1);
    }
}
