//! The allowlist of approved capture-enclave releases.

use serde::Deserialize;
use thiserror::Error;

/// Byte length of a Nitro PCR and of the worker's SHA-384 digest.
pub const MEASUREMENT_BYTES: usize = 48;

/// Upper bound on approved releases, matching the capture client's limit.
pub const MAX_RELEASES: usize = 8;

pub type Measurement = [u8; MEASUREMENT_BYTES];

/// One approved enclave release.
///
/// PCR0-2 measure the enclave image, its kernel and bootstrap, and its
/// applications. The worker executable is delivered after boot, so the PCRs do
/// not cover it; the enclave reports the worker's SHA-384 in the attestation's
/// signed `user_data` instead. A release is trusted only as a whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Release {
    pub pcr0: Measurement,
    pub pcr1: Measurement,
    pub pcr2: Measurement,
    pub worker_sha384: Measurement,
}

/// An allowlist of approved releases. The default approves nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReleasePolicy {
    releases: Vec<Release>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReleasePolicyError {
    #[error("releases must be a JSON array of {{pcr0, pcr1, pcr2, worker_sha384}} objects: {0}")]
    Json(String),
    #[error("at most {MAX_RELEASES} releases are allowed, got {0}")]
    TooMany(usize),
    #[error("release {index}: {field} must be 96 lowercase hex characters and not all zero")]
    Measurement { index: usize, field: &'static str },
    #[error("release {index} duplicates release {first}")]
    Duplicate { index: usize, first: usize },
}

/// The published release format, shared with the capture client so one entry
/// can be handed to every verifier unchanged. Unknown and duplicate keys are
/// errors: a misspelled field must not silently approve or drop a measurement.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRelease {
    pcr0: String,
    pcr1: String,
    pcr2: String,
    worker_sha384: String,
}

impl ReleasePolicy {
    /// Parses a JSON array such as
    /// `[{"pcr0":"…","pcr1":"…","pcr2":"…","worker_sha384":"…"}]`. Blank input
    /// yields an empty policy, which approves nothing.
    pub fn parse(raw: &str) -> Result<Self, ReleasePolicyError> {
        if raw.trim().is_empty() {
            return Ok(Self::default());
        }
        let entries: Vec<RawRelease> = serde_json::from_str(raw)
            .map_err(|error| ReleasePolicyError::Json(error.to_string()))?;
        if entries.len() > MAX_RELEASES {
            return Err(ReleasePolicyError::TooMany(entries.len()));
        }

        let mut releases = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            let measurement = |field, value| {
                parse_measurement(value).ok_or(ReleasePolicyError::Measurement { index, field })
            };
            let release = Release {
                pcr0: measurement("pcr0", &entry.pcr0)?,
                pcr1: measurement("pcr1", &entry.pcr1)?,
                pcr2: measurement("pcr2", &entry.pcr2)?,
                worker_sha384: measurement("worker_sha384", &entry.worker_sha384)?,
            };
            if let Some(first) = releases.iter().position(|approved| *approved == release) {
                return Err(ReleasePolicyError::Duplicate { index, first });
            }
            releases.push(release);
        }
        Ok(Self { releases })
    }

    pub fn len(&self) -> usize {
        self.releases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.releases.is_empty()
    }

    /// Whether a single approved release has exactly these measurements.
    /// Measurements from different releases never combine into a match.
    pub fn matches(&self, pcr0: &[u8], pcr1: &[u8], pcr2: &[u8], worker_sha384: &[u8]) -> bool {
        self.releases.iter().any(|release| {
            release.pcr0 == pcr0
                && release.pcr1 == pcr1
                && release.pcr2 == pcr2
                && release.worker_sha384 == worker_sha384
        })
    }
}

/// Lowercase only: the published format has one spelling per measurement.
/// All-zero is refused because debug-mode enclaves report all-zero PCRs.
fn parse_measurement(value: &str) -> Option<Measurement> {
    let lowercase_hex = value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    if value.len() != 2 * MEASUREMENT_BYTES || !lowercase_hex {
        return None;
    }
    let mut measurement = [0u8; MEASUREMENT_BYTES];
    hex::decode_to_slice(value, &mut measurement).ok()?;
    (measurement != [0u8; MEASUREMENT_BYTES]).then_some(measurement)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_of(byte: u8) -> String {
        hex::encode([byte; MEASUREMENT_BYTES])
    }

    fn release_json(pcr0: u8, pcr1: u8, pcr2: u8, worker: u8) -> String {
        format!(
            r#"{{"pcr0":"{}","pcr1":"{}","pcr2":"{}","worker_sha384":"{}"}}"#,
            hex_of(pcr0),
            hex_of(pcr1),
            hex_of(pcr2),
            hex_of(worker)
        )
    }

    #[test]
    fn blank_input_approves_nothing() {
        for raw in ["", "  \n"] {
            let policy = ReleasePolicy::parse(raw).unwrap();
            assert!(policy.is_empty());
            assert!(!policy.matches(&[1; 48], &[2; 48], &[3; 48], &[4; 48]));
        }
        assert!(ReleasePolicy::parse("[]").unwrap().is_empty());
    }

    #[test]
    fn a_release_matches_only_as_a_whole() {
        let raw = format!(
            "[{},{}]",
            release_json(1, 2, 3, 4),
            release_json(5, 6, 7, 8)
        );
        let policy = ReleasePolicy::parse(&raw).unwrap();
        assert_eq!(policy.len(), 2);
        assert!(policy.matches(&[1; 48], &[2; 48], &[3; 48], &[4; 48]));
        assert!(policy.matches(&[5; 48], &[6; 48], &[7; 48], &[8; 48]));
        // PCRs of the first release with the worker of the second.
        assert!(!policy.matches(&[1; 48], &[2; 48], &[3; 48], &[8; 48]));
        assert!(!policy.matches(&[1; 47], &[2; 48], &[3; 48], &[4; 48]));
    }

    #[test]
    fn malformed_measurements_are_rejected() {
        let good = hex_of(1);
        for (bad, why) in [
            (hex_of(0), "all zero"),
            (good.to_uppercase().replace('0', "A"), "uppercase"),
            (good[..94].to_string(), "short"),
            (format!("{good}00"), "long"),
            (format!("{}zz", &good[..94]), "not hex"),
        ] {
            let raw = format!(
                r#"[{{"pcr0":"{good}","pcr1":"{bad}","pcr2":"{good}","worker_sha384":"{good}"}}]"#
            );
            assert_eq!(
                ReleasePolicy::parse(&raw),
                Err(ReleasePolicyError::Measurement {
                    index: 0,
                    field: "pcr1"
                }),
                "{why}"
            );
        }
    }

    #[test]
    fn ambiguous_json_is_rejected() {
        let good = hex_of(1);
        let complete = release_json(1, 1, 1, 1);
        for (raw, why) in [
            ("null".to_string(), "not an array"),
            ("{}".to_string(), "object"),
            (format!("[{complete}] []"), "trailing data"),
            (
                format!(r#"[{{"pcr0":"{good}","pcr1":"{good}","pcr2":"{good}"}}]"#),
                "missing field",
            ),
            (
                format!(
                    r#"[{{"pcr0":"{good}","pcr1":"{good}","pcr2":"{good}","worker_sha384":"{good}","pcr3":"{good}"}}]"#
                ),
                "unknown field",
            ),
            (
                format!(
                    r#"[{{"pcr0":"{good}","pcr0":"{good}","pcr1":"{good}","pcr2":"{good}","worker_sha384":"{good}"}}]"#
                ),
                "duplicate field",
            ),
            (
                format!(
                    r#"[{{"PCR0":"{good}","pcr1":"{good}","pcr2":"{good}","worker_sha384":"{good}"}}]"#
                ),
                "wrong case",
            ),
        ] {
            assert!(
                matches!(ReleasePolicy::parse(&raw), Err(ReleasePolicyError::Json(_))),
                "{why}"
            );
        }
    }

    #[test]
    fn duplicate_and_excess_releases_are_rejected() {
        let duplicate = format!(
            "[{},{}]",
            release_json(1, 2, 3, 4),
            release_json(1, 2, 3, 4)
        );
        assert_eq!(
            ReleasePolicy::parse(&duplicate),
            Err(ReleasePolicyError::Duplicate { index: 1, first: 0 })
        );

        let many = (1..=9)
            .map(|byte| release_json(byte, 1, 1, 1))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            ReleasePolicy::parse(&format!("[{many}]")),
            Err(ReleasePolicyError::TooMany(9))
        );
    }
}
