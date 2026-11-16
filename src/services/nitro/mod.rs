//! Verification of Nitro enclave capture evidence.
//!
//! [`binding::WebCapture`] recomputes the digest an enclave attested for a
//! capture, and [`document::CaptureVerifier`] authenticates the attestation
//! document against a [`release_policy::ReleasePolicy`] and that digest.

use std::sync::Arc;

use eyre::{ensure, eyre, Context};

use crate::cfg::config::Config;

pub mod binding;
pub mod document;
pub mod release_policy;

/// Builds the verifier for Nitro-authenticated challenge issuance, or `None`
/// when the feature is disabled.
///
/// Enabling it is refused unless the service listens on loopback: the challenge
/// route then trusts attested-proxy's identity headers to recognize a verified
/// device, which is only sound when the proxy is the sole way in. It is also
/// refused without an approved release, so the feature cannot be enabled in a
/// state that rejects every caller or, worse, was meant to restrict them.
pub fn capture_verifier_from_config(
    cfg: &Config,
) -> eyre::Result<Option<document::DynCaptureVerifier>> {
    if !cfg.enable_nitro_challenge {
        return Ok(None);
    }
    ensure!(
        cfg.http_addr.ip().is_loopback(),
        "enable_nitro_challenge requires http_addr to be a loopback address behind attested-proxy, got {}",
        cfg.http_addr
    );
    let policy = release_policy::ReleasePolicy::parse(&cfg.nitro_release_policy)
        .wrap_err("invalid nitro_release_policy")?;
    ensure!(
        !policy.is_empty(),
        "enable_nitro_challenge requires at least one approved release in nitro_release_policy"
    );
    let verifier = document::CaptureVerifier::new(policy)
        .map_err(|error| eyre!("failed to build the Nitro capture verifier: {error}"))?;
    Ok(Some(Arc::new(verifier)))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    fn config(extra: &[&str]) -> Config {
        let base = [
            "svc",
            "--gateway-url",
            "http://gateway.test",
            "--jwt-trusted-keys",
            "{}",
        ];
        Config::try_parse_from(base.iter().chain(extra)).unwrap()
    }

    fn policy() -> String {
        let measurement = "ab".repeat(48);
        format!(
            r#"[{{"pcr0":"{measurement}","pcr1":"{measurement}","pcr2":"{measurement}","worker_sha384":"{measurement}"}}]"#
        )
    }

    #[test]
    fn the_feature_is_off_by_default_and_needs_no_policy() {
        assert!(capture_verifier_from_config(&config(&[]))
            .unwrap()
            .is_none());
    }

    #[test]
    fn enabling_requires_a_loopback_listener() {
        let policy = policy();
        let error = capture_verifier_from_config(&config(&[
            "--enable-nitro-challenge",
            "--nitro-release-policy",
            &policy,
        ]))
        .err()
        .expect("the default listener is not loopback");
        assert!(error.to_string().contains("loopback"), "{error}");
    }

    #[test]
    fn enabling_requires_an_approved_release() {
        for policy in ["", "[]", "not json"] {
            assert!(
                capture_verifier_from_config(&config(&[
                    "--enable-nitro-challenge",
                    "--http-addr",
                    "127.0.0.1:8000",
                    "--nitro-release-policy",
                    policy,
                ]))
                .is_err(),
                "{policy:?}"
            );
        }
    }

    #[test]
    fn a_loopback_listener_and_a_release_enable_the_feature() {
        let policy = policy();
        assert!(capture_verifier_from_config(&config(&[
            "--enable-nitro-challenge",
            "--http-addr",
            "127.0.0.1:8000",
            "--nitro-release-policy",
            &policy,
        ]))
        .unwrap()
        .is_some());
    }
}
