//! Verification of Nitro enclave capture evidence.
//!
//! Nothing here is wired into a route yet. [`binding::WebCapture`] recomputes
//! the digest an enclave attested for a capture, and
//! [`document::CaptureVerifier`] authenticates the attestation document against
//! a [`release_policy::ReleasePolicy`] and that digest.

pub mod binding;
pub mod document;
pub mod release_policy;
