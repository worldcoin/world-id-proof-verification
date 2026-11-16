//! Verification of a Nitro attestation document that authenticates one capture.
//!
//! The document is the enclave's `COSE_Sign1` evidence, as published in
//! `worldcoin/biometrics-tee` (`selfie-enrollment/identity/protocol.md`): the
//! `nonce` is the capture's binding digest, `user_data` is a version byte and
//! the worker's SHA-384, and `public_key` is absent.

use chrono::{DateTime, Utc};
use ciborium::value::Value;
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyParam;
use openssl::x509::{X509StoreContext, X509};
use thiserror::Error;

use super::release_policy::{ReleasePolicy, MEASUREMENT_BYTES};

/// The AWS commercial-partition Nitro root, SHA-256 fingerprint
/// `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`.
/// Source: <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>
const AWS_NITRO_ROOT_PEM: &[u8] = include_bytes!("aws-nitro-root-g1.pem");

/// Largest accepted binary document. Its base64 is 16,000 bytes, which keeps
/// the attestation header under the load balancer's single-header limit.
pub const MAX_DOCUMENT_BYTES: usize = 12_000;

/// Byte length of the capture binding digest carried in the document's nonce.
pub const NONCE_BYTES: usize = 32;

const MAX_DOCUMENT_AGE_MS: i64 = 5 * 60 * 1000;
const MAX_FUTURE_SKEW_MS: i64 = 30 * 1000;
const MAX_CAPTURE_SKEW_MS: i64 = 2 * 60 * 1000;

const COSE_SIGN1_TAG: u64 = 18;
const COSE_HEADER_ALG: i128 = 1;
const COSE_ALG_ES384: i128 = -35;
const P384_SCALAR_BYTES: usize = 48;
const USER_DATA_VERSION: u8 = 1;

const MAX_NESTING: usize = 16;
const MAX_COLLECTION_ITEMS: usize = 32;
const MAX_MODULE_ID_BYTES: usize = 256;
const MAX_CERTIFICATE_BYTES: usize = 1024;
const MAX_CABUNDLE_CERTIFICATES: usize = 10;
const MAX_PCR_INDEX: i128 = 31;

/// Why capture evidence was refused. Each variant is one rejection class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum AttestationError {
    /// The bytes are not a well-formed capture attestation.
    #[error("invalid Nitro capture attestation")]
    Document,
    /// The signature or its certificate chain does not lead to the AWS root.
    #[error("untrusted Nitro capture attestation")]
    Trust,
    /// The enclave's measurements are not an approved release.
    #[error("unapproved Nitro capture release")]
    Release,
    /// The document or the capture time is outside the accepted window.
    #[error("stale Nitro capture attestation")]
    Freshness,
    /// The document does not cover the presented capture.
    #[error("invalid Nitro capture binding")]
    Binding,
}

impl AttestationError {
    /// A stable, low-cardinality name for logs and metric labels.
    pub const fn class(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Trust => "trust",
            Self::Release => "release",
            Self::Freshness => "freshness",
            Self::Binding => "binding",
        }
    }
}

/// What the caller derived from the capture it received and expects the
/// document to cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureBinding {
    /// The capture's binding digest, recomputed from the received fields.
    pub nonce: [u8; NONCE_BYTES],
    /// The capture's own timestamp, in Unix seconds.
    pub captured_at: i64,
}

/// Authenticates Nitro capture evidence against a release policy and a
/// caller-supplied binding. It has no knowledge of the capture's field layout.
pub struct CaptureVerifier {
    policy: ReleasePolicy,
    root: X509,
}

impl CaptureVerifier {
    /// Trusts only the embedded AWS Nitro root and the supplied releases. An
    /// empty policy is refused, so a misconfiguration cannot approve everything
    /// or silently approve nothing.
    pub fn new(policy: ReleasePolicy) -> Result<Self, AttestationError> {
        let root = X509::from_pem(AWS_NITRO_ROOT_PEM).map_err(|_| AttestationError::Trust)?;
        Self::with_root(policy, root)
    }

    fn with_root(policy: ReleasePolicy, root: X509) -> Result<Self, AttestationError> {
        if policy.is_empty() {
            return Err(AttestationError::Release);
        }
        Ok(Self { policy, root })
    }

    /// Checks, in order: the document's shape, its signature and certificate
    /// chain, its freshness, the enclave release, and the capture binding.
    /// `now` must be this service's clock, never a value from the request.
    pub fn verify(
        &self,
        raw: &[u8],
        binding: &CaptureBinding,
        now: DateTime<Utc>,
    ) -> Result<(), AttestationError> {
        if raw.is_empty() || raw.len() > MAX_DOCUMENT_BYTES {
            return Err(AttestationError::Document);
        }
        let signed = CoseSign1::decode(raw)?;
        let document = Document::decode(&signed.payload)?;
        self.verify_signature(&signed, &document, now)?;

        let now_ms = now.timestamp_millis();
        if document.issued_at_ms < now_ms.saturating_sub(MAX_DOCUMENT_AGE_MS)
            || document.issued_at_ms > now_ms.saturating_add(MAX_FUTURE_SKEW_MS)
        {
            return Err(AttestationError::Freshness);
        }
        if binding.captured_at <= 0 {
            return Err(AttestationError::Binding);
        }
        let captured_at_ms = binding
            .captured_at
            .checked_mul(1000)
            .ok_or(AttestationError::Binding)?;
        if captured_at_ms < document.issued_at_ms.saturating_sub(MAX_CAPTURE_SKEW_MS)
            || captured_at_ms > document.issued_at_ms.saturating_add(MAX_CAPTURE_SKEW_MS)
        {
            return Err(AttestationError::Freshness);
        }

        let [pcr0, pcr1, pcr2] = &document.pcrs;
        if !self
            .policy
            .matches(pcr0, pcr1, pcr2, &document.user_data[1..])
        {
            return Err(AttestationError::Release);
        }
        // Both sides are `NONCE_BYTES` long: `Document::decode` enforced it.
        if !openssl::memcmp::eq(&binding.nonce, &document.nonce) {
            return Err(AttestationError::Binding);
        }
        Ok(())
    }

    /// Authenticates the AWS certificate chain and the COSE signature.
    ///
    /// The leaf must hold a P-384 key and chain to the pinned root at `now`.
    /// OpenSSL enforces that every issuer in the chain is a CA permitted to
    /// sign certificates. The leaf's own CA flag and key usage are not
    /// inspected: the bindings expose neither, and a certificate under this
    /// root is only ever issued by AWS.
    fn verify_signature(
        &self,
        signed: &CoseSign1,
        document: &Document,
        now: DateTime<Utc>,
    ) -> Result<(), AttestationError> {
        let trust = |_: ErrorStack| AttestationError::Trust;

        let leaf = parse_certificate(&document.certificate)?;
        let mut intermediates = Stack::new().map_err(trust)?;
        for certificate in &document.cabundle {
            // A root supplied by the document is only ever an untrusted
            // intermediate candidate here, never a trust anchor.
            intermediates
                .push(parse_certificate(certificate)?)
                .map_err(trust)?;
        }

        let mut param = X509VerifyParam::new().map_err(trust)?;
        // `time_t` is the platform's; the cast only names it.
        param.set_time(now.timestamp() as _);
        let mut store = X509StoreBuilder::new().map_err(trust)?;
        store.add_cert(self.root.clone()).map_err(trust)?;
        store.set_param(&param).map_err(trust)?;
        let store = store.build();
        let chain_is_valid = X509StoreContext::new()
            .map_err(trust)?
            .init(&store, &leaf, &intermediates, |context| {
                context.verify_cert()
            })
            .map_err(trust)?;
        if !chain_is_valid {
            return Err(AttestationError::Trust);
        }

        let key = leaf
            .public_key()
            .and_then(|key| key.ec_key())
            .map_err(trust)?;
        if key.group().curve_name() != Some(Nid::SECP384R1) {
            return Err(AttestationError::Trust);
        }

        let mut structure = Vec::new();
        ciborium::into_writer(
            &Value::Array(vec![
                Value::Text("Signature1".to_owned()),
                Value::Bytes(signed.protected.clone()),
                Value::Bytes(Vec::new()),
                Value::Bytes(signed.payload.clone()),
            ]),
            &mut structure,
        )
        .map_err(|_| AttestationError::Document)?;
        let digest = openssl::sha::sha384(&structure);

        let (r, s) = signed.signature.split_at(P384_SCALAR_BYTES);
        let signature = BigNum::from_slice(r)
            .and_then(|r| Ok((r, BigNum::from_slice(s)?)))
            .and_then(|(r, s)| EcdsaSig::from_private_components(r, s))
            .map_err(trust)?;
        match signature.verify(&digest, &key) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(AttestationError::Trust),
        }
    }
}

/// Parses one DER certificate, refusing trailing bytes.
fn parse_certificate(der: &[u8]) -> Result<X509, AttestationError> {
    let certificate = X509::from_der(der).map_err(|_| AttestationError::Trust)?;
    match certificate.to_der() {
        Ok(encoded) if encoded == der => Ok(certificate),
        _ => Err(AttestationError::Trust),
    }
}

/// The `COSE_Sign1` envelope: ES384 over an attestation document, with no
/// unprotected headers.
struct CoseSign1 {
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl CoseSign1 {
    fn decode(raw: &[u8]) -> Result<Self, AttestationError> {
        // The envelope may carry the COSE_Sign1 tag; no other tag is accepted
        // anywhere in the document.
        let envelope = match decode_exact(raw)? {
            Value::Tag(COSE_SIGN1_TAG, inner) => *inner,
            untagged => untagged,
        };
        require_plain(&envelope, 0)?;

        let Value::Array(parts) = envelope else {
            return Err(AttestationError::Document);
        };
        let Ok(
            [Value::Bytes(protected), Value::Map(unprotected), Value::Bytes(payload), Value::Bytes(signature)],
        ) = <[Value; 4]>::try_from(parts)
        else {
            return Err(AttestationError::Document);
        };
        if !unprotected.is_empty() || signature.len() != 2 * P384_SCALAR_BYTES {
            return Err(AttestationError::Document);
        }

        let headers = decode_exact(&protected)?;
        require_plain(&headers, 0)?;
        let is_es384_only = match &headers {
            Value::Map(entries) => match entries.as_slice() {
                [(Value::Integer(label), Value::Integer(algorithm))] => {
                    i128::from(*label) == COSE_HEADER_ALG
                        && i128::from(*algorithm) == COSE_ALG_ES384
                }
                _ => false,
            },
            _ => false,
        };
        if !is_es384_only {
            return Err(AttestationError::Document);
        }
        Ok(Self {
            protected,
            payload,
            signature,
        })
    }
}

/// The signed attestation document, reduced to what capture evidence needs.
struct Document {
    issued_at_ms: i64,
    pcrs: [Vec<u8>; 3],
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    /// `USER_DATA_VERSION` followed by the worker's SHA-384.
    user_data: Vec<u8>,
    nonce: Vec<u8>,
}

impl Document {
    fn decode(payload: &[u8]) -> Result<Self, AttestationError> {
        let value = decode_exact(payload)?;
        require_plain(&value, 0)?;
        let Value::Map(entries) = value else {
            return Err(AttestationError::Document);
        };

        let mut module_id = None;
        let mut digest = None;
        let mut timestamp = None;
        let mut pcrs = None;
        let mut certificate = None;
        let mut cabundle = None;
        let mut public_key = None;
        let mut user_data = None;
        let mut nonce = None;
        for (key, value) in entries {
            let Value::Text(key) = key else {
                return Err(AttestationError::Document);
            };
            let slot = match key.as_str() {
                "module_id" => &mut module_id,
                "digest" => &mut digest,
                "timestamp" => &mut timestamp,
                "pcrs" => &mut pcrs,
                "certificate" => &mut certificate,
                "cabundle" => &mut cabundle,
                "public_key" => &mut public_key,
                "user_data" => &mut user_data,
                "nonce" => &mut nonce,
                _ => return Err(AttestationError::Document),
            };
            if slot.replace(value).is_some() {
                return Err(AttestationError::Document);
            }
        }

        match module_id {
            Some(Value::Text(id)) if !id.is_empty() && id.len() <= MAX_MODULE_ID_BYTES => {}
            _ => return Err(AttestationError::Document),
        }
        if digest != Some(Value::Text("SHA384".to_owned())) {
            return Err(AttestationError::Document);
        }
        let issued_at_ms = match timestamp {
            Some(Value::Integer(timestamp)) => i64::try_from(i128::from(timestamp))
                .ok()
                .filter(|timestamp| *timestamp > 0),
            _ => None,
        }
        .ok_or(AttestationError::Document)?;
        // Capture evidence carries no channel key; a document that attests one
        // is a different kind of evidence and must not authorize a capture.
        match public_key {
            None | Some(Value::Null) => {}
            Some(Value::Bytes(key)) if key.is_empty() => {}
            Some(_) => return Err(AttestationError::Document),
        }
        let user_data = bytes(user_data)
            .filter(|data| data.len() == 1 + MEASUREMENT_BYTES && data[0] == USER_DATA_VERSION)
            .ok_or(AttestationError::Document)?;
        let nonce = bytes(nonce)
            .filter(|nonce| nonce.len() == NONCE_BYTES)
            .ok_or(AttestationError::Document)?;
        let certificate = bytes(certificate)
            .filter(|der| is_certificate_sized(der))
            .ok_or(AttestationError::Document)?;
        let cabundle = match cabundle {
            Some(Value::Array(certificates))
                if !certificates.is_empty() && certificates.len() <= MAX_CABUNDLE_CERTIFICATES =>
            {
                certificates
                    .into_iter()
                    .map(|der| bytes(Some(der)).filter(|der| is_certificate_sized(der)))
                    .collect::<Option<Vec<_>>>()
            }
            _ => None,
        }
        .ok_or(AttestationError::Document)?;

        Ok(Self {
            issued_at_ms,
            pcrs: decode_pcrs(pcrs)?,
            certificate,
            cabundle,
            user_data,
            nonce,
        })
    }
}

/// Every PCR present must be a SHA-384 measurement at a valid index, and PCR0-2
/// must be present. Returns PCR0-2.
fn decode_pcrs(pcrs: Option<Value>) -> Result<[Vec<u8>; 3], AttestationError> {
    let Some(Value::Map(entries)) = pcrs else {
        return Err(AttestationError::Document);
    };
    let mut seen = [false; MAX_PCR_INDEX as usize + 1];
    let mut first_three: [Option<Vec<u8>>; 3] = [None, None, None];
    for (index, measurement) in entries {
        let index = match index {
            Value::Integer(index) => usize::try_from(i128::from(index)).ok(),
            _ => None,
        }
        .filter(|index| *index < seen.len())
        .ok_or(AttestationError::Document)?;
        let measurement = bytes(Some(measurement))
            .filter(|measurement| measurement.len() == MEASUREMENT_BYTES)
            .ok_or(AttestationError::Document)?;
        if std::mem::replace(&mut seen[index], true) {
            return Err(AttestationError::Document);
        }
        if let Some(slot) = first_three.get_mut(index) {
            *slot = Some(measurement);
        }
    }
    match first_three {
        [Some(pcr0), Some(pcr1), Some(pcr2)] => Ok([pcr0, pcr1, pcr2]),
        _ => Err(AttestationError::Document),
    }
}

fn bytes(value: Option<Value>) -> Option<Vec<u8>> {
    match value {
        Some(Value::Bytes(bytes)) => Some(bytes),
        _ => None,
    }
}

fn is_certificate_sized(der: &[u8]) -> bool {
    !der.is_empty() && der.len() <= MAX_CERTIFICATE_BYTES
}

/// Decodes exactly one CBOR item, refusing trailing bytes.
fn decode_exact(bytes: &[u8]) -> Result<Value, AttestationError> {
    let mut remaining = bytes;
    let value = ciborium::from_reader(&mut remaining).map_err(|_| AttestationError::Document)?;
    if remaining.is_empty() {
        Ok(value)
    } else {
        Err(AttestationError::Document)
    }
}

/// Refuses tags and oversized or deeply nested collections anywhere in `value`.
fn require_plain(value: &Value, depth: usize) -> Result<(), AttestationError> {
    if depth > MAX_NESTING {
        return Err(AttestationError::Document);
    }
    match value {
        Value::Tag(..) => Err(AttestationError::Document),
        Value::Array(items) if items.len() > MAX_COLLECTION_ITEMS => {
            Err(AttestationError::Document)
        }
        Value::Map(entries) if entries.len() > MAX_COLLECTION_ITEMS => {
            Err(AttestationError::Document)
        }
        Value::Array(items) => items
            .iter()
            .try_for_each(|item| require_plain(item, depth + 1)),
        Value::Map(entries) => entries.iter().try_for_each(|(key, value)| {
            require_plain(key, depth + 1)?;
            require_plain(value, depth + 1)
        }),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests;
