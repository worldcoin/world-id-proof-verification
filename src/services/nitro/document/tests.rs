use chrono::TimeZone;
use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509Builder, X509NameBuilder};

use super::*;

const NOW_SECS: i64 = 1_793_728_518;
const HOUR: i64 = 3600;

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECS, 0).unwrap()
}

fn generate_key(curve: Nid) -> PKey<Private> {
    let group = EcGroup::from_curve_name(curve).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

struct CertificateSpec {
    ca: bool,
    can_sign_certificates: bool,
    /// Validity as offsets from `NOW_SECS`, in seconds.
    not_before: i64,
    not_after: i64,
}

impl CertificateSpec {
    fn authority() -> Self {
        Self {
            ca: true,
            can_sign_certificates: true,
            not_before: -HOUR,
            not_after: HOUR,
        }
    }

    fn leaf() -> Self {
        Self {
            ca: false,
            can_sign_certificates: false,
            ..Self::authority()
        }
    }
}

fn certificate(
    name: &str,
    subject_key: &PKey<Private>,
    issuer: Option<(&X509, &PKey<Private>)>,
    spec: &CertificateSpec,
) -> X509 {
    let mut subject = X509NameBuilder::new().unwrap();
    subject.append_entry_by_text("CN", name).unwrap();
    let subject = subject.build();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let serial = BigNum::from_u32(name.len() as u32).unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&subject).unwrap();
    builder
        .set_issuer_name(issuer.map_or(&subject, |(issuer, _)| issuer.subject_name()))
        .unwrap();
    builder.set_pubkey(subject_key).unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix(NOW_SECS + spec.not_before).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix(NOW_SECS + spec.not_after).unwrap())
        .unwrap();

    let mut constraints = BasicConstraints::new();
    constraints.critical();
    if spec.ca {
        constraints.ca();
    }
    builder
        .append_extension(constraints.build().unwrap())
        .unwrap();
    let mut usage = KeyUsage::new();
    usage.critical();
    if spec.can_sign_certificates {
        usage.key_cert_sign();
    } else {
        usage.digital_signature();
    }
    builder.append_extension(usage.build().unwrap()).unwrap();

    builder
        .sign(
            issuer.map_or(subject_key, |(_, key)| key),
            MessageDigest::sha384(),
        )
        .unwrap();
    builder.build()
}

/// How the test chain deviates from a valid root, intermediate and leaf.
struct ChainSpec {
    intermediate: CertificateSpec,
    leaf: CertificateSpec,
    include_intermediate: bool,
    /// The key certified by the leaf, when it is not the document signing key.
    certified_key: Option<PKey<Private>>,
}

impl Default for ChainSpec {
    fn default() -> Self {
        Self {
            intermediate: CertificateSpec::authority(),
            leaf: CertificateSpec::leaf(),
            include_intermediate: true,
            certified_key: None,
        }
    }
}

struct Fixture {
    verifier: CaptureVerifier,
    binding: CaptureBinding,
    document: TestDocument,
    signing_key: PKey<Private>,
}

impl Fixture {
    fn verify(&self, raw: &[u8]) -> Result<(), AttestationError> {
        self.verifier.verify(raw, &self.binding, now())
    }

    fn verify_document(&self, document: &TestDocument) -> Result<(), AttestationError> {
        self.verify(&encode(&cose(&document.payload(), &self.signing_key)))
    }
}

fn policy() -> ReleasePolicy {
    release(1, 2, 3, 4)
}

fn release(pcr0: u8, pcr1: u8, pcr2: u8, worker: u8) -> ReleasePolicy {
    let measurement = |byte| hex::encode([byte; MEASUREMENT_BYTES]);
    ReleasePolicy::parse(&format!(
        r#"[{{"pcr0":"{}","pcr1":"{}","pcr2":"{}","worker_sha384":"{}"}}]"#,
        measurement(pcr0),
        measurement(pcr1),
        measurement(pcr2),
        measurement(worker)
    ))
    .unwrap()
}

fn fixture() -> Fixture {
    fixture_with_chain(ChainSpec::default())
}

fn fixture_with_chain(chain: ChainSpec) -> Fixture {
    let root_key = generate_key(Nid::SECP384R1);
    let intermediate_key = generate_key(Nid::SECP384R1);
    let signing_key = generate_key(Nid::SECP384R1);

    let root = certificate("test root", &root_key, None, &CertificateSpec::authority());
    let intermediate = certificate(
        "test intermediate",
        &intermediate_key,
        Some((&root, &root_key)),
        &chain.intermediate,
    );
    let leaf = certificate(
        "test leaf",
        chain.certified_key.as_ref().unwrap_or(&signing_key),
        Some((&intermediate, &intermediate_key)),
        &chain.leaf,
    );

    // Real documents list the root first, then the intermediates.
    let mut cabundle = vec![root.to_der().unwrap()];
    if chain.include_intermediate {
        cabundle.push(intermediate.to_der().unwrap());
    }
    let nonce = vec![9; NONCE_BYTES];
    let mut user_data = vec![USER_DATA_VERSION];
    user_data.extend([4; MEASUREMENT_BYTES]);
    let pcr = |index: u8, byte: u8| {
        (
            Value::Integer(index.into()),
            Value::Bytes(vec![byte; MEASUREMENT_BYTES]),
        )
    };

    Fixture {
        verifier: CaptureVerifier::with_root(policy(), root).unwrap(),
        binding: CaptureBinding {
            nonce: nonce.clone().try_into().unwrap(),
            captured_at: NOW_SECS,
        },
        document: TestDocument {
            module_id: Value::Text("i-0123456789abcdef0-enc0123456789abcdef".to_owned()),
            digest: Value::Text("SHA384".to_owned()),
            timestamp: Value::Integer((NOW_SECS * 1000).into()),
            pcrs: vec![
                pcr(0, 1),
                pcr(1, 2),
                pcr(2, 3),
                pcr(3, 0),
                pcr(4, 7),
                pcr(8, 0),
            ],
            certificate: Value::Bytes(leaf.to_der().unwrap()),
            cabundle: cabundle.into_iter().map(Value::Bytes).collect(),
            public_key: Some(Value::Null),
            user_data: Some(Value::Bytes(user_data)),
            nonce: Value::Bytes(nonce),
            extra: Vec::new(),
        },
        signing_key,
    }
}

#[derive(Clone)]
struct TestDocument {
    module_id: Value,
    digest: Value,
    timestamp: Value,
    pcrs: Vec<(Value, Value)>,
    certificate: Value,
    cabundle: Vec<Value>,
    public_key: Option<Value>,
    user_data: Option<Value>,
    nonce: Value,
    extra: Vec<(Value, Value)>,
}

impl TestDocument {
    fn entries(&self) -> Vec<(Value, Value)> {
        let text = |name: &str| Value::Text(name.to_owned());
        let mut entries = vec![
            (text("module_id"), self.module_id.clone()),
            (text("digest"), self.digest.clone()),
            (text("timestamp"), self.timestamp.clone()),
            (text("pcrs"), Value::Map(self.pcrs.clone())),
            (text("certificate"), self.certificate.clone()),
            (text("cabundle"), Value::Array(self.cabundle.clone())),
            (text("nonce"), self.nonce.clone()),
        ];
        if let Some(public_key) = &self.public_key {
            entries.push((text("public_key"), public_key.clone()));
        }
        if let Some(user_data) = &self.user_data {
            entries.push((text("user_data"), user_data.clone()));
        }
        entries.extend(self.extra.clone());
        entries
    }

    fn payload(&self) -> Vec<u8> {
        encode(&Value::Map(self.entries()))
    }
}

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).unwrap();
    bytes
}

fn es384_headers() -> Vec<u8> {
    encode(&Value::Map(vec![(
        Value::Integer(1.into()),
        Value::Integer((-35).into()),
    )]))
}

/// An untagged, correctly signed `COSE_Sign1` over `payload`.
fn cose(payload: &[u8], key: &PKey<Private>) -> Value {
    let protected = es384_headers();
    let structure = encode(&Value::Array(vec![
        Value::Text("Signature1".to_owned()),
        Value::Bytes(protected.clone()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]));
    let signature =
        EcdsaSig::sign(&openssl::sha::sha384(&structure), &key.ec_key().unwrap()).unwrap();
    let mut raw_signature = signature.r().to_vec_padded(48).unwrap();
    raw_signature.extend(signature.s().to_vec_padded(48).unwrap());
    Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(Vec::new()),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(raw_signature),
    ])
}

fn with_part(envelope: Value, index: usize, part: Value) -> Value {
    let Value::Array(mut parts) = envelope else {
        panic!("a COSE_Sign1 envelope is an array");
    };
    parts[index] = part;
    Value::Array(parts)
}

#[test]
fn valid_capture_evidence_is_accepted_with_or_without_the_cose_tag() {
    let fixture = fixture();
    let envelope = cose(&fixture.document.payload(), &fixture.signing_key);
    assert_eq!(fixture.verify(&encode(&envelope)), Ok(()));
    let tagged = Value::Tag(COSE_SIGN1_TAG, Box::new(envelope));
    assert_eq!(fixture.verify(&encode(&tagged)), Ok(()));
}

/// The Nitro Secure Module emits its payload as an indefinite-length map.
#[test]
fn an_indefinite_length_payload_map_is_accepted() {
    let fixture = fixture();
    let mut payload = vec![0xbf];
    for (key, value) in fixture.document.entries() {
        payload.extend(encode(&key));
        payload.extend(encode(&value));
    }
    payload.push(0xff);
    assert_ne!(payload, fixture.document.payload());
    assert_eq!(
        fixture.verify(&encode(&cose(&payload, &fixture.signing_key))),
        Ok(())
    );
}

#[test]
fn an_absent_or_empty_public_key_is_accepted() {
    let fixture = fixture();
    for public_key in [None, Some(Value::Bytes(Vec::new()))] {
        let document = TestDocument {
            public_key,
            ..fixture.document.clone()
        };
        assert_eq!(fixture.verify_document(&document), Ok(()));
    }
}

#[test]
fn untrusted_chains_and_signatures_are_rejected() {
    let expired = |spec: CertificateSpec| CertificateSpec {
        not_after: -1,
        ..spec
    };
    let not_yet_valid = |spec: CertificateSpec| CertificateSpec {
        not_before: 1,
        ..spec
    };
    let cases: Vec<(&str, ChainSpec)> = vec![
        (
            "expired leaf",
            ChainSpec {
                leaf: expired(CertificateSpec::leaf()),
                ..ChainSpec::default()
            },
        ),
        (
            "future leaf",
            ChainSpec {
                leaf: not_yet_valid(CertificateSpec::leaf()),
                ..ChainSpec::default()
            },
        ),
        (
            "expired intermediate",
            ChainSpec {
                intermediate: expired(CertificateSpec::authority()),
                ..ChainSpec::default()
            },
        ),
        (
            "future intermediate",
            ChainSpec {
                intermediate: not_yet_valid(CertificateSpec::authority()),
                ..ChainSpec::default()
            },
        ),
        (
            "missing intermediate",
            ChainSpec {
                include_intermediate: false,
                ..ChainSpec::default()
            },
        ),
        (
            "intermediate is not a CA",
            ChainSpec {
                intermediate: CertificateSpec {
                    ca: false,
                    ..CertificateSpec::authority()
                },
                ..ChainSpec::default()
            },
        ),
        (
            "intermediate cannot sign certificates",
            ChainSpec {
                intermediate: CertificateSpec {
                    can_sign_certificates: false,
                    ..CertificateSpec::authority()
                },
                ..ChainSpec::default()
            },
        ),
        (
            "leaf certifies a P-256 key",
            ChainSpec {
                certified_key: Some(generate_key(Nid::X9_62_PRIME256V1)),
                ..ChainSpec::default()
            },
        ),
        (
            "leaf certifies another P-384 key",
            ChainSpec {
                certified_key: Some(generate_key(Nid::SECP384R1)),
                ..ChainSpec::default()
            },
        ),
    ];
    for (name, chain) in cases {
        let fixture = fixture_with_chain(chain);
        assert_eq!(
            fixture.verify_document(&fixture.document),
            Err(AttestationError::Trust),
            "{name}"
        );
    }
}

#[test]
fn a_signature_over_another_payload_is_rejected() {
    let fixture = fixture();
    let signed = cose(&fixture.document.payload(), &fixture.signing_key);
    let other = TestDocument {
        module_id: Value::Text("another-module".to_owned()),
        ..fixture.document.clone()
    };
    let forged = with_part(signed, 2, Value::Bytes(other.payload()));
    assert_eq!(
        fixture.verify(&encode(&forged)),
        Err(AttestationError::Trust)
    );
}

#[test]
fn a_chain_to_another_root_is_rejected() {
    let trusted = fixture();
    let other = fixture();
    // `other` carries its own root in the cabundle; that never makes it trusted.
    assert_eq!(
        trusted.verify(&encode(&cose(
            &other.document.payload(),
            &other.signing_key
        ))),
        Err(AttestationError::Trust)
    );
}

#[test]
fn certificates_with_trailing_bytes_are_rejected() {
    let fixture = fixture();
    let Value::Bytes(mut leaf) = fixture.document.certificate.clone() else {
        unreachable!()
    };
    leaf.push(0);
    let document = TestDocument {
        certificate: Value::Bytes(leaf),
        ..fixture.document.clone()
    };
    assert_eq!(
        fixture.verify_document(&document),
        Err(AttestationError::Trust)
    );
}

#[test]
fn the_production_verifier_trusts_only_the_aws_root() {
    let fixture = fixture();
    let production = CaptureVerifier::new(policy()).unwrap();
    assert_eq!(
        production.verify(
            &encode(&cose(&fixture.document.payload(), &fixture.signing_key)),
            &fixture.binding,
            now()
        ),
        Err(AttestationError::Trust)
    );
}

#[test]
fn the_embedded_root_is_the_published_aws_nitro_root() {
    let root = X509::from_pem(AWS_NITRO_ROOT_PEM).unwrap();
    assert_eq!(
        hex::encode(root.digest(MessageDigest::sha256()).unwrap()),
        "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
    );
}

#[test]
fn an_empty_release_policy_is_refused() {
    assert_eq!(
        CaptureVerifier::new(ReleasePolicy::default()).err(),
        Some(AttestationError::Release)
    );
}

#[test]
fn freshness_is_enforced_at_each_boundary() {
    // (name, document offset from now in ms, capture offset from issuance in ms, accepted)
    let cases = [
        ("age inside", -MAX_DOCUMENT_AGE_MS + 1, 0, true),
        ("age at limit", -MAX_DOCUMENT_AGE_MS, 0, true),
        ("age outside", -MAX_DOCUMENT_AGE_MS - 1, 0, false),
        ("future inside", MAX_FUTURE_SKEW_MS - 1, 0, true),
        ("future at limit", MAX_FUTURE_SKEW_MS, 0, true),
        ("future outside", MAX_FUTURE_SKEW_MS + 1, 0, false),
        ("capture past inside", 0, -MAX_CAPTURE_SKEW_MS + 1000, true),
        ("capture past at limit", 0, -MAX_CAPTURE_SKEW_MS, true),
        (
            "capture past outside",
            0,
            -MAX_CAPTURE_SKEW_MS - 1000,
            false,
        ),
        ("capture future inside", 0, MAX_CAPTURE_SKEW_MS - 1000, true),
        ("capture future at limit", 0, MAX_CAPTURE_SKEW_MS, true),
        (
            "capture future outside",
            0,
            MAX_CAPTURE_SKEW_MS + 1000,
            false,
        ),
    ];
    for (name, document_offset, capture_offset, accepted) in cases {
        let mut fixture = fixture();
        let issued_at_ms = NOW_SECS * 1000 + document_offset;
        fixture.document.timestamp = Value::Integer(issued_at_ms.into());
        // Capture timestamps are whole seconds.
        fixture.binding.captured_at = (issued_at_ms + capture_offset).div_euclid(1000);
        let expected = if accepted {
            Ok(())
        } else {
            Err(AttestationError::Freshness)
        };
        assert_eq!(
            fixture.verify_document(&fixture.document),
            expected,
            "{name}"
        );
    }
}

#[test]
fn only_approved_releases_are_accepted() {
    let mut fixture = fixture();
    let raw = encode(&cose(&fixture.document.payload(), &fixture.signing_key));

    for (name, unapproved) in [
        ("another image", release(9, 2, 3, 4)),
        ("another kernel", release(1, 9, 3, 4)),
        ("another application", release(1, 2, 9, 4)),
        ("another worker", release(1, 2, 3, 9)),
    ] {
        fixture.verifier.policy = unapproved;
        assert_eq!(
            fixture.verify(&raw),
            Err(AttestationError::Release),
            "{name}"
        );
    }

    // During a rotation both the outgoing and incoming releases are approved.
    let measurement = |byte| hex::encode([byte; MEASUREMENT_BYTES]);
    let entry = |pcr0, pcr1, pcr2, worker| {
        format!(
            r#"{{"pcr0":"{}","pcr1":"{}","pcr2":"{}","worker_sha384":"{}"}}"#,
            measurement(pcr0),
            measurement(pcr1),
            measurement(pcr2),
            measurement(worker)
        )
    };
    fixture.verifier.policy =
        ReleasePolicy::parse(&format!("[{},{}]", entry(5, 6, 7, 8), entry(1, 2, 3, 4))).unwrap();
    assert_eq!(fixture.verify(&raw), Ok(()));
}

#[test]
fn the_document_must_cover_the_presented_capture() {
    let mut fixture = fixture();
    let raw = encode(&cose(&fixture.document.payload(), &fixture.signing_key));

    fixture.binding.nonce[0] ^= 1;
    assert_eq!(fixture.verify(&raw), Err(AttestationError::Binding));
    fixture.binding.nonce[0] ^= 1;

    for captured_at in [0, -1, i64::MAX] {
        fixture.binding.captured_at = captured_at;
        assert_eq!(
            fixture.verify(&raw),
            Err(AttestationError::Binding),
            "{captured_at}"
        );
    }
}

#[test]
fn malformed_envelopes_are_rejected() {
    let fixture = fixture();
    let payload = fixture.document.payload();
    let envelope = cose(&payload, &fixture.signing_key);
    let valid = encode(&envelope);
    let Value::Array(parts) = envelope.clone() else {
        unreachable!()
    };
    let Value::Bytes(signature) = parts[3].clone() else {
        unreachable!()
    };

    let mut trailing = valid.clone();
    trailing.push(0);
    let headers = |entries: Vec<(i32, i32)>| {
        Value::Bytes(encode(&Value::Map(
            entries
                .into_iter()
                .map(|(label, value)| (Value::Integer(label.into()), Value::Integer(value.into())))
                .collect(),
        )))
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("oversized", vec![0; MAX_DOCUMENT_BYTES + 1]),
        ("trailing byte", trailing),
        ("not CBOR", b"not a document".to_vec()),
        (
            "another tag",
            encode(&Value::Tag(17, Box::new(envelope.clone()))),
        ),
        (
            "doubly tagged",
            encode(&Value::Tag(
                COSE_SIGN1_TAG,
                Box::new(Value::Tag(COSE_SIGN1_TAG, Box::new(envelope.clone()))),
            )),
        ),
        ("not an array", encode(&Value::Map(Vec::new()))),
        ("three parts", encode(&Value::Array(parts[..3].to_vec()))),
        (
            "unprotected header present",
            encode(&with_part(
                envelope.clone(),
                1,
                Value::Map(vec![(Value::Integer(4.into()), Value::Bytes(vec![1]))]),
            )),
        ),
        (
            "unprotected headers null",
            encode(&with_part(envelope.clone(), 1, Value::Null)),
        ),
        (
            "payload null",
            encode(&with_part(envelope.clone(), 2, Value::Null)),
        ),
        (
            "short signature",
            encode(&with_part(
                envelope.clone(),
                3,
                Value::Bytes(signature[..95].to_vec()),
            )),
        ),
        (
            "ES256 algorithm",
            encode(&with_part(envelope.clone(), 0, headers(vec![(1, -7)]))),
        ),
        (
            "extra protected header",
            encode(&with_part(
                envelope.clone(),
                0,
                headers(vec![(1, -35), (4, 0)]),
            )),
        ),
        (
            "no protected headers",
            encode(&with_part(envelope.clone(), 0, headers(Vec::new()))),
        ),
        (
            "protected headers not a map",
            encode(&with_part(
                envelope,
                0,
                Value::Bytes(encode(&Value::Array(Vec::new()))),
            )),
        ),
    ];
    for (name, raw) in cases {
        assert_eq!(
            fixture.verify(&raw),
            Err(AttestationError::Document),
            "{name}"
        );
    }
}

#[test]
fn malformed_documents_are_rejected() {
    let fixture = fixture();
    let valid = &fixture.document;
    let text = |value: &str| Value::Text(value.to_owned());
    let pcr =
        |index: i64, length: usize| (Value::Integer(index.into()), Value::Bytes(vec![1; length]));
    let with_pcrs = |pcrs: Vec<(Value, Value)>| TestDocument {
        pcrs,
        ..valid.clone()
    };
    let with_extra = |key: Value, value: Value| TestDocument {
        extra: vec![(key, value)],
        ..valid.clone()
    };
    let leaf = valid.certificate.clone();

    let cases: Vec<(&str, TestDocument)> = vec![
        ("unknown field", with_extra(text("extra"), Value::Null)),
        (
            "duplicate field",
            with_extra(text("nonce"), valid.nonce.clone()),
        ),
        (
            "non-text key",
            with_extra(Value::Integer(1.into()), Value::Null),
        ),
        (
            "tagged value",
            with_extra(text("extra"), Value::Tag(1, Box::new(Value::Null))),
        ),
        (
            "empty module id",
            TestDocument {
                module_id: text(""),
                ..valid.clone()
            },
        ),
        (
            "oversized module id",
            TestDocument {
                module_id: text(&"m".repeat(MAX_MODULE_ID_BYTES + 1)),
                ..valid.clone()
            },
        ),
        (
            "module id not text",
            TestDocument {
                module_id: Value::Bytes(vec![1]),
                ..valid.clone()
            },
        ),
        (
            "another digest",
            TestDocument {
                digest: text("SHA256"),
                ..valid.clone()
            },
        ),
        (
            "zero timestamp",
            TestDocument {
                timestamp: Value::Integer(0.into()),
                ..valid.clone()
            },
        ),
        (
            "negative timestamp",
            TestDocument {
                timestamp: Value::Integer((-1).into()),
                ..valid.clone()
            },
        ),
        (
            "timestamp beyond i64",
            TestDocument {
                timestamp: Value::Integer(u64::MAX.into()),
                ..valid.clone()
            },
        ),
        (
            "channel key attested",
            TestDocument {
                public_key: Some(Value::Bytes(vec![1; 32])),
                ..valid.clone()
            },
        ),
        (
            "missing user data",
            TestDocument {
                user_data: None,
                ..valid.clone()
            },
        ),
        (
            "null user data",
            TestDocument {
                user_data: Some(Value::Null),
                ..valid.clone()
            },
        ),
        (
            "user data without a version byte",
            TestDocument {
                user_data: Some(Value::Bytes(vec![4; MEASUREMENT_BYTES])),
                ..valid.clone()
            },
        ),
        (
            "another user data version",
            TestDocument {
                user_data: Some(Value::Bytes(
                    std::iter::once(2).chain([4; MEASUREMENT_BYTES]).collect(),
                )),
                ..valid.clone()
            },
        ),
        (
            "short nonce",
            TestDocument {
                nonce: Value::Bytes(vec![9; NONCE_BYTES - 1]),
                ..valid.clone()
            },
        ),
        (
            "null nonce",
            TestDocument {
                nonce: Value::Null,
                ..valid.clone()
            },
        ),
        (
            "missing PCR2",
            with_pcrs(vec![pcr(0, 48), pcr(1, 48), pcr(3, 48)]),
        ),
        (
            "short PCR",
            with_pcrs(vec![pcr(0, 48), pcr(1, 47), pcr(2, 48)]),
        ),
        (
            "short unused PCR",
            with_pcrs(vec![pcr(0, 48), pcr(1, 48), pcr(2, 48), pcr(5, 32)]),
        ),
        (
            "PCR index out of range",
            with_pcrs(vec![pcr(0, 48), pcr(1, 48), pcr(2, 48), pcr(32, 48)]),
        ),
        (
            "negative PCR index",
            with_pcrs(vec![pcr(0, 48), pcr(1, 48), pcr(2, 48), pcr(-1, 48)]),
        ),
        (
            "duplicate PCR",
            with_pcrs(vec![pcr(0, 48), pcr(1, 48), pcr(2, 48), pcr(0, 48)]),
        ),
        (
            "empty certificate",
            TestDocument {
                certificate: Value::Bytes(Vec::new()),
                ..valid.clone()
            },
        ),
        (
            "oversized certificate",
            TestDocument {
                certificate: Value::Bytes(vec![0x30; MAX_CERTIFICATE_BYTES + 1]),
                ..valid.clone()
            },
        ),
        (
            "empty cabundle",
            TestDocument {
                cabundle: Vec::new(),
                ..valid.clone()
            },
        ),
        (
            "oversized cabundle",
            TestDocument {
                cabundle: vec![leaf.clone(); MAX_CABUNDLE_CERTIFICATES + 1],
                ..valid.clone()
            },
        ),
        (
            "cabundle entry not bytes",
            TestDocument {
                cabundle: vec![text("certificate")],
                ..valid.clone()
            },
        ),
    ];
    for (name, document) in cases {
        assert_eq!(
            fixture.verify_document(&document),
            Err(AttestationError::Document),
            "{name}"
        );
    }

    let not_a_map = encode(&cose(
        &encode(&Value::Array(Vec::new())),
        &fixture.signing_key,
    ));
    assert_eq!(fixture.verify(&not_a_map), Err(AttestationError::Document));
}

#[test]
fn rejection_classes_are_stable() {
    let classes = [
        (AttestationError::Document, "document"),
        (AttestationError::Trust, "trust"),
        (AttestationError::Release, "release"),
        (AttestationError::Freshness, "freshness"),
        (AttestationError::Binding, "binding"),
    ];
    for (error, class) in classes {
        assert_eq!(error.class(), class);
    }
}
