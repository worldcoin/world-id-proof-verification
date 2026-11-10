//! World ID 4.x client for world-id-proof-verification.
//!
//! [`Client::challenge`] signs with the supplied integrity token and [`Signer`].
//! [`Client::verify`] authenticates using the service JWT provider.

mod auth;
mod client;

pub use attested_request::sign::Signer;
pub use auth::{AuthError, AuthProvider, JwtAuthProvider};
pub use client::{
    ChallengeError, ChallengeResponse, Client, Config, Error, ProofVerificationClient, VERIFY_PATH,
    VerificationError, VerificationRequest,
};
