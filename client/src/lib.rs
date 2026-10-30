//! World ID 4.x (WIP-103) client for world-id-proof-verification-service.
//!
//! [`Client::challenge`] requests a single-use challenge. [`Client::verify`]
//! submits an ownership proof for that challenge's id. The nonce is not sent
//! again on verify; the service loads it from the stored challenge.

mod auth;
mod client;

pub use auth::{AuthError, AuthProvider, JwtAuthProvider};
pub use client::{
    ChallengeError, ChallengeResponse, Client, Config, Error, ProofVerificationClient, VERIFY_PATH,
    VerificationError, VerificationRequest,
};
