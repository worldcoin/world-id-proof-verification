//! The web capture an enclave attests, and the digest that binds it.
//!
//! The field list, validation and digest follow the enclave's published
//! protocol (`worldcoin/biometrics-tee`, `selfie-enrollment/identity/protocol.md`,
//! contract version `2`). The digest is the attestation document's `nonce`, so
//! every byte hashed here must be exactly what the enclave hashed: values are
//! validated as canonical and never normalized.

use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use openssl::sha::Sha256;
use serde::Deserialize;
use thiserror::Error;
use world_id_primitives::FieldElement;

use super::document::CaptureBinding;

const DOMAIN: &[u8] = b"web-authenticator:face-enrollment:v2";
/// The request the enclave attested the capture for. These are the capture
/// submission's method and path, not this service's: the same evidence is
/// presented here to obtain a challenge and there to enroll.
const SUBMISSION_METHOD: &[u8] = b"PUT";
const SUBMISSION_PATH: &[u8] = b"/api/v2/identity";

const CONTRACT_VERSION: &str = "2";
/// Upper bound on each field, in bytes as received.
pub const MAX_FIELD_BYTES: usize = 8192;
/// A share is a sealed box, so it is at least the box's overhead.
const MIN_SHARE_BYTES: usize = 48;
const MAX_SUBJECT_HEX_DIGITS: usize = 64;
const HASH_HEX_DIGITS: usize = 64;

/// The capture could not be bound: a field is missing a canonical encoding the
/// contract requires. Deliberately carries no detail about which.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("invalid web capture")]
pub struct InvalidCapture;

/// The twelve attested capture fields, exactly as the enclave returned them.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebCapture {
    pub contract_version: String,
    pub sub: String,
    pub capture_id: String,
    pub timestamp: String,
    pub face_embedding_shares_0: String,
    pub face_embedding_shares_1: String,
    pub face_embedding_shares_2: String,
    pub face_embedding_version: String,
    pub face_embedding_type: String,
    pub face_embedding_inference_backend: String,
    pub pcp_version: String,
    pub associated_data_hash: String,
}

impl WebCapture {
    /// Validates the capture and recomputes what its attestation must cover:
    /// the binding digest and the capture time.
    pub fn binding(&self) -> Result<CaptureBinding, InvalidCapture> {
        let captured_at = self.validate()?;

        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        let mut write = |name: &[u8], value: &[u8]| {
            for part in [name, value] {
                // `validate` bounded every part far below `u32::MAX`.
                digest.update(&(part.len() as u32).to_be_bytes());
                digest.update(part);
            }
        };
        write(b"@method", SUBMISSION_METHOD);
        write(b"@path", SUBMISSION_PATH);
        for (name, value) in self.fields() {
            if name.starts_with(SHARE_FIELD_PREFIX) {
                // Shares are bound as ciphertext, not as their base64 text.
                write(name.as_bytes(), &decode_share(value)?);
            } else {
                write(name.as_bytes(), value.as_bytes());
            }
        }
        Ok(CaptureBinding {
            nonce: digest.finish(),
            captured_at,
        })
    }

    /// The attested subject as a field element, for comparison with the
    /// subject an ownership proof is later verified for.
    pub fn subject(&self) -> Result<FieldElement, InvalidCapture> {
        let digits = canonical_subject_digits(&self.sub).ok_or(InvalidCapture)?;
        FieldElement::from_str(&format!("0x{digits:0>MAX_SUBJECT_HEX_DIGITS$}"))
            .map_err(|_| InvalidCapture)
    }

    /// The fields in the order the contract hashes them.
    fn fields(&self) -> [(&'static str, &str); 12] {
        [
            ("contract_version", &self.contract_version),
            ("sub", &self.sub),
            ("capture_id", &self.capture_id),
            ("timestamp", &self.timestamp),
            ("face_embedding_shares_0", &self.face_embedding_shares_0),
            ("face_embedding_shares_1", &self.face_embedding_shares_1),
            ("face_embedding_shares_2", &self.face_embedding_shares_2),
            ("face_embedding_version", &self.face_embedding_version),
            ("face_embedding_type", &self.face_embedding_type),
            (
                "face_embedding_inference_backend",
                &self.face_embedding_inference_backend,
            ),
            ("pcp_version", &self.pcp_version),
            ("associated_data_hash", &self.associated_data_hash),
        ]
    }

    /// Returns the capture time in Unix seconds.
    fn validate(&self) -> Result<i64, InvalidCapture> {
        let within_bounds = self
            .fields()
            .iter()
            .all(|(_, value)| !value.is_empty() && value.len() <= MAX_FIELD_BYTES);
        let is_valid = within_bounds
            && self.contract_version == CONTRACT_VERSION
            && canonical_subject_digits(&self.sub).is_some()
            && is_canonical_uuid(&self.capture_id)
            && is_canonical_hash(&self.associated_data_hash);
        if !is_valid {
            return Err(InvalidCapture);
        }
        canonical_timestamp(&self.timestamp).ok_or(InvalidCapture)
    }
}

const SHARE_FIELD_PREFIX: &str = "face_embedding_shares_";

/// Strict, canonical standard base64 of at least a sealed box's overhead.
fn decode_share(value: &str) -> Result<Vec<u8>, InvalidCapture> {
    STANDARD
        .decode(value)
        .ok()
        .filter(|share| share.len() >= MIN_SHARE_BYTES && STANDARD.encode(share) == value)
        .ok_or(InvalidCapture)
}

/// The hex digits of a canonical subject: `0x`, then 1 to 64 lowercase hex
/// digits with no leading zero, which also excludes zero itself.
fn canonical_subject_digits(sub: &str) -> Option<&str> {
    let digits = sub.strip_prefix("0x")?;
    let is_canonical = (1..=MAX_SUBJECT_HEX_DIGITS).contains(&digits.len())
        && is_lowercase_hex(digits)
        && !digits.starts_with('0');
    is_canonical.then_some(digits)
}

/// A nonzero UUID in its lowercase hyphenated form.
fn is_canonical_uuid(value: &str) -> bool {
    uuid::Uuid::try_parse(value)
        .is_ok_and(|id| !id.is_nil() && id.hyphenated().to_string() == value)
}

/// Positive decimal Unix seconds with no sign, padding or leading zero.
fn canonical_timestamp(value: &str) -> Option<i64> {
    let seconds = value.parse::<i64>().ok()?;
    (seconds > 0 && seconds.to_string() == value).then_some(seconds)
}

/// `0x` followed by exactly 32 lowercase hex bytes.
fn is_canonical_hash(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|digits| digits.len() == HASH_HEX_DIGITS && is_lowercase_hex(digits))
}

fn is_lowercase_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The enclave's golden fixture, from `worldcoin/biometrics-tee`
    /// `selfie-enrollment/identity/tests/fixtures/enrollment-v2.json` at
    /// `abd17d5dfdcb00e94cd03fb20a4a1685241f851c`.
    const FIXTURE: &str = include_str!("testdata/enrollment-v2.json");

    #[derive(Deserialize)]
    struct Fixture {
        fields: WebCapture,
        nonce_hex: String,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(FIXTURE).unwrap()
    }

    fn capture() -> WebCapture {
        fixture().fields
    }

    /// Selects the field a test case changes.
    type Field = fn(&mut WebCapture) -> &mut String;

    #[test]
    fn the_digest_matches_the_enclave_fixture() {
        let fixture = fixture();
        let binding = fixture.fields.binding().unwrap();
        assert_eq!(hex::encode(binding.nonce), fixture.nonce_hex);
        assert_eq!(binding.captured_at, 1_700_000_000);
    }

    #[test]
    fn every_field_is_bound() {
        let original = capture().binding().unwrap().nonce;
        let share = |byte: u8| STANDARD.encode([byte; 80]);
        let changes: [(&str, Field, String); 11] = [
            ("sub", |c| &mut c.sub, "0x20".into()),
            (
                "capture_id",
                |c| &mut c.capture_id,
                "6f9619ff-8b86-4d01-b42d-00cf4fc964fe".into(),
            ),
            ("timestamp", |c| &mut c.timestamp, "1700000001".into()),
            ("share 0", |c| &mut c.face_embedding_shares_0, share(9)),
            ("share 1", |c| &mut c.face_embedding_shares_1, share(9)),
            ("share 2", |c| &mut c.face_embedding_shares_2, share(9)),
            (
                "embedding version",
                |c| &mut c.face_embedding_version,
                "2.0.1".into(),
            ),
            (
                "embedding type",
                |c| &mut c.face_embedding_type,
                "another".into(),
            ),
            (
                "inference backend",
                |c| &mut c.face_embedding_inference_backend,
                "another".into(),
            ),
            ("pcp version", |c| &mut c.pcp_version, "2".into()),
            (
                "associated data hash",
                |c| &mut c.associated_data_hash,
                format!("0x{}", "02".repeat(32)),
            ),
        ];
        for (name, field, value) in changes {
            let mut changed = capture();
            *field(&mut changed) = value;
            assert_ne!(changed.binding().unwrap().nonce, original, "{name}");
        }
    }

    /// Party slots are bound by name, so swapping two shares changes the digest.
    #[test]
    fn share_slots_are_not_interchangeable() {
        let mut swapped = capture();
        std::mem::swap(
            &mut swapped.face_embedding_shares_0,
            &mut swapped.face_embedding_shares_1,
        );
        assert_ne!(
            swapped.binding().unwrap().nonce,
            capture().binding().unwrap().nonce
        );
    }

    #[test]
    fn non_canonical_fields_are_rejected() {
        let canonical_share = capture().face_embedding_shares_0;
        let cases: Vec<(&str, Field, String)> = vec![
            (
                "another contract version",
                |c| &mut c.contract_version,
                "1".into(),
            ),
            (
                "empty contract version",
                |c| &mut c.contract_version,
                String::new(),
            ),
            ("empty subject", |c| &mut c.sub, String::new()),
            ("subject without digits", |c| &mut c.sub, "0x".into()),
            ("zero subject", |c| &mut c.sub, "0x0".into()),
            ("padded subject", |c| &mut c.sub, "0x01f".into()),
            ("uppercase subject", |c| &mut c.sub, "0x1F".into()),
            ("uppercase subject prefix", |c| &mut c.sub, "0X1f".into()),
            ("unprefixed subject", |c| &mut c.sub, "1f".into()),
            (
                "overlong subject",
                |c| &mut c.sub,
                format!("0x1{}", "0".repeat(64)),
            ),
            (
                "nil capture id",
                |c| &mut c.capture_id,
                uuid::Uuid::nil().to_string(),
            ),
            (
                "uppercase capture id",
                |c| &mut c.capture_id,
                "6F9619FF-8B86-4D01-B42D-00CF4FC964FF".into(),
            ),
            (
                "unhyphenated capture id",
                |c| &mut c.capture_id,
                "6f9619ff8b864d01b42d00cf4fc964ff".into(),
            ),
            (
                "braced capture id",
                |c| &mut c.capture_id,
                "{6f9619ff-8b86-4d01-b42d-00cf4fc964ff}".into(),
            ),
            ("zero timestamp", |c| &mut c.timestamp, "0".into()),
            ("negative timestamp", |c| &mut c.timestamp, "-1".into()),
            (
                "signed timestamp",
                |c| &mut c.timestamp,
                "+1700000000".into(),
            ),
            (
                "padded timestamp",
                |c| &mut c.timestamp,
                "01700000000".into(),
            ),
            (
                "fractional timestamp",
                |c| &mut c.timestamp,
                "1700000000.5".into(),
            ),
            (
                "timestamp beyond i64",
                |c| &mut c.timestamp,
                "9223372036854775808".into(),
            ),
            (
                "unprefixed hash",
                |c| &mut c.associated_data_hash,
                "01".repeat(33),
            ),
            (
                "short hash",
                |c| &mut c.associated_data_hash,
                format!("0x{}", "01".repeat(31)),
            ),
            (
                "uppercase hash",
                |c| &mut c.associated_data_hash,
                format!("0x{}", "AB".repeat(32)),
            ),
            (
                "non-hex hash",
                |c| &mut c.associated_data_hash,
                format!("0x{}", "zz".repeat(32)),
            ),
            (
                "empty metadata",
                |c| &mut c.face_embedding_type,
                String::new(),
            ),
            (
                "oversized metadata",
                |c| &mut c.pcp_version,
                "v".repeat(MAX_FIELD_BYTES + 1),
            ),
            (
                "share that is not base64",
                |c| &mut c.face_embedding_shares_1,
                "not base64!".into(),
            ),
            (
                "unpadded share",
                |c| &mut c.face_embedding_shares_1,
                canonical_share.trim_end_matches('=').into(),
            ),
            (
                "url-safe share",
                |c| &mut c.face_embedding_shares_1,
                base64::engine::general_purpose::URL_SAFE.encode([0xfb; 80]),
            ),
            (
                "share below the sealed-box overhead",
                |c| &mut c.face_embedding_shares_2,
                STANDARD.encode([1; MIN_SHARE_BYTES - 1]),
            ),
            (
                "share with non-canonical trailing bits",
                |c| &mut c.face_embedding_shares_2,
                // A final one-byte group must end in `Q==`; `R==` leaves stray bits set.
                format!("{}AR==", STANDARD.encode([1; 48])),
            ),
        ];
        for (name, field, value) in cases {
            let mut changed = capture();
            *field(&mut changed) = value;
            assert_eq!(changed.binding(), Err(InvalidCapture), "{name}");
        }
    }

    #[test]
    fn a_field_at_the_size_limit_is_accepted() {
        let mut changed = capture();
        changed.pcp_version = "v".repeat(MAX_FIELD_BYTES);
        assert!(changed.binding().is_ok());
    }

    #[test]
    fn the_subject_is_the_field_element_the_proof_is_verified_for() {
        assert_eq!(capture().subject(), Ok(FieldElement::from(31u64)));

        let mut padded = capture();
        padded.sub = "0x01f".into();
        assert_eq!(padded.subject(), Err(InvalidCapture));

        // Canonical text, but not an element of the field.
        let mut out_of_range = capture();
        out_of_range.sub = format!("0x{}", "f".repeat(64));
        assert!(out_of_range.binding().is_ok());
        assert_eq!(out_of_range.subject(), Err(InvalidCapture));
    }

    #[test]
    fn unknown_and_missing_fields_are_rejected_on_decode() {
        let mut fields =
            serde_json::from_str::<serde_json::Value>(FIXTURE).unwrap()["fields"].clone();

        fields["idComm"] = "0x1".into();
        assert!(serde_json::from_value::<WebCapture>(fields.clone()).is_err());

        let fields = fields.as_object_mut().unwrap();
        fields.remove("idComm");
        fields.remove("pcp_version");
        assert!(serde_json::from_value::<WebCapture>(fields.clone().into()).is_err());
    }
}
