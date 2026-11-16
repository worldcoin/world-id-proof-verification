//! Verification of Nitro enclave capture evidence.
//!
//! Nothing here is wired into a route yet. [`document::CaptureVerifier`]
//! authenticates an attestation document against a [`release_policy::ReleasePolicy`]
//! and a caller-supplied binding.

pub mod document;
pub mod release_policy;
