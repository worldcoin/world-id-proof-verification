//! Offline CPU-time and wall-clock benchmark for the production proof-verification paths:
//! v1 Groth16/BN254 Semaphore authentication (`SemaphoreVerifier`) and v4 Noir/WHIR
//! (ProveKit) ownership (`WorldIdOwnershipVerifier`, including its dedicated
//! single-thread Rayon pool). Both fixtures are real cryptographic proofs generated
//! in-process from synthetic local data. There are zero network calls and no real
//! identity registration.
//!
//! Run with `cargo run --release --example verify_bench`.
//! For the pinned-thread comparison, run with
//! `RAYON_NUM_THREADS=1 cargo run --release --example verify_bench`.

use cpu_time::ProcessTime;
use semaphore_rs::{
    hash_to_field,
    identity::Identity,
    protocol::{self, Proof},
    Field,
};
use std::{
    any::Any,
    env, panic,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};
use world_id_primitives::{
    merkle::MerkleInclusionProof,
    poseidon::{self, ds},
    proof::OwnershipProof,
    AuthenticatorPublicKeySet, Credential, EdDSAPrivateKey, FieldElement, TREE_DEPTH,
};
use world_id_proof::artifacts::embedded::EmbeddedZkArtifacts;
use world_id_proof::artifacts::ZkArtifactSource;
use world_id_proof::{
    circuit_inputs::OwnershipProofCircuitInput, ownership_proof::generate_ownership_proof,
};
use world_id_proof_verification_service::models::challenge_model::ChallengeType;
use world_id_proof_verification_service::{
    cfg::config::TREE_DEPTH as SEMAPHORE_TREE_DEPTH,
    services::ownership_proof_verifier::{OwnershipProofVerifier, WorldIdOwnershipVerifier},
};

const ITERATIONS: usize = 20;
const WARMUP_ITERATIONS: usize = 3;
const CONCURRENCY_LEVELS: [usize; 4] = [1, 2, 4, 8];
const LEAF_INDEX: u64 = 1;

type VerifyCall = dyn Fn() -> Result<(), String> + Send + Sync;

struct V1Fixture {
    id_commitment: Field,
    nullifier_hash: Field,
    signal_hash: Field,
    external_nullifier_hash: Field,
    proof: Proof,
}

struct V4Fixture {
    proof: OwnershipProof,
    nonce: FieldElement,
    commitment: FieldElement,
}

#[derive(Clone, Copy)]
struct Sample {
    wall: Duration,
    cpu: Duration,
}

struct Statistics {
    mean_wall_ms: f64,
    mean_cpu_ms: f64,
    effective_cores: f64,
}

/// Vendored because the MIT-licensed upstream helper lives in the unpublished
/// (`publish = false`) `world-id-test-utils` crate and cannot be depended on here.
mod vendored_merkle {
    use ark_babyjubjub::Fq;
    use ark_ff::AdditiveGroup;
    use world_id_primitives::{FieldElement, TREE_DEPTH};

    pub fn first_leaf_merkle_path(leaf: Fq) -> ([FieldElement; TREE_DEPTH], FieldElement) {
        let mut siblings = [FieldElement::ZERO; TREE_DEPTH];
        let mut zero = Fq::ZERO;
        for sibling in siblings.iter_mut() {
            *sibling = zero.into();
            zero = poseidon2_compress(zero, zero);
        }
        let mut current = poseidon2_compress(*siblings[0], leaf);
        for sibling in &siblings[1..] {
            current = poseidon2_compress(current, **sibling);
        }
        (siblings, current.into())
    }

    fn poseidon2_compress(left: Fq, right: Fq) -> Fq {
        let mut state = poseidon2::bn254::t2::permutation(&[left, right]);
        state[0] += left;
        state[0]
    }
}

fn build_v1_fixture() -> Result<V1Fixture, String> {
    let mut secret = *b"bench secret seed";
    let identity = Identity::from_secret(&mut secret, None);
    let signal_hash: Field = hash_to_field(b"offline benchmark signal");
    let external_nullifier_hash: Field = hash_to_field(b"offline benchmark scope");
    let nullifier_hash: Field =
        protocol::generate_nullifier_hash(&identity, external_nullifier_hash);
    let id_commitment: Field = identity.commitment();
    let proof = protocol::authentication::generate_proof(
        SEMAPHORE_TREE_DEPTH,
        &identity,
        external_nullifier_hash,
        signal_hash,
    )
    .map_err(|error| format!("v1 proof generation failed: {error}"))?;

    Ok(V1Fixture {
        id_commitment,
        nullifier_hash,
        signal_hash,
        external_nullifier_hash,
        proof,
    })
}

fn verify_v1(fixture: &V1Fixture) -> Result<(), String> {
    match protocol::authentication::verify_proof(
        SEMAPHORE_TREE_DEPTH,
        fixture.id_commitment,
        fixture.nullifier_hash,
        fixture.signal_hash,
        fixture.external_nullifier_hash,
        &fixture.proof,
    ) {
        Ok(true) => Ok(()),
        Ok(false) => Err("v1 verification returned false".to_owned()),
        Err(error) => Err(format!("v1 verification failed: {error}")),
    }
}

fn build_v4_fixture() -> Result<V4Fixture, String> {
    let private_key = EdDSAPrivateKey::from_bytes([42u8; 32]);
    let public_key = private_key.public();
    let key_set = AuthenticatorPublicKeySet::new(vec![public_key])
        .map_err(|error| format!("v4 key-set construction failed: {error}"))?;
    let leaf: ark_babyjubjub::Fq = key_set.leaf_hash();
    let (siblings, root) = vendored_merkle::first_leaf_merkle_path(leaf);
    let inclusion_proof = MerkleInclusionProof::<TREE_DEPTH>::new(root, LEAF_INDEX, siblings);
    let nonce = FieldElement::from(1234567890u64);
    let context =
        FieldElement::from_arbitrary_raw_bytes(ChallengeType::Enrollment.as_str().as_bytes());
    let commitment_blinder = FieldElement::from(999u64);
    let commitment = Credential::compute_sub(LEAF_INDEX, commitment_blinder);

    // The circuit signs Poseidon2(WIP-103 domain separator, expected_commitment, nonce,
    // context) — see `world_id_proof::fixtures::ownership_proof_fixture` (the crate's own
    // canonical fixture) for the construction this must match.
    let message = poseidon::hash(ds::OWNERSHIP_PROOF, [commitment, nonce, context]);
    let signature = private_key.sign(*message);
    let circuit_input = OwnershipProofCircuitInput::<TREE_DEPTH> {
        key_index: 0,
        key_set,
        inclusion_proof,
        nonce,
        signature,
        commitment_blinder,
        expected_commitment: commitment,
        context,
    };

    let proof = generate_ownership_proof(circuit_input, &EmbeddedZkArtifacts)
        .map_err(|error| format!("v4 proof generation failed: {error}"))?;

    Ok(V4Fixture {
        proof,
        nonce,
        commitment,
    })
}

fn verify_v4(
    fixture: &V4Fixture,
    context: FieldElement,
    artifacts: &dyn ZkArtifactSource,
) -> Result<(), String> {
    WorldIdOwnershipVerifier
        .verify(
            &fixture.proof,
            fixture.nonce,
            fixture.commitment,
            context,
            artifacts,
        )
        .map_err(|error| format!("v4 verification failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_proof_roundtrip_and_public_input_binding() {
        let mut fixture = build_v4_fixture().expect("generate a real ownership proof");
        let context = FieldElement::from_arbitrary_raw_bytes(b"enrollment");
        // ProveKit's debug transcript requires interaction metadata that is
        // deliberately omitted from the wire format. Restore it for debug tests.
        #[cfg(debug_assertions)]
        let pattern = fixture.proof.proof.pattern.clone();
        let mut bytes = Vec::new();
        ciborium::into_writer(&fixture.proof, &mut bytes).unwrap();
        // A protocol upgrade must still fit the existing endpoint limits.
        assert!(fixture.proof.proof.narg_string.len() <= 640 * 1024);
        assert!(fixture.proof.proof.hints.len() <= 640 * 1024);
        use base64::Engine as _;
        let request = api_types::VerificationRequest {
            challenge_id: uuid::Uuid::nil(),
            credential_sub: fixture.commitment.to_string(),
            proof: base64::engine::general_purpose::STANDARD.encode(&bytes),
        };
        assert!(serde_json::to_vec(&request).unwrap().len() <= 1024 * 1024);
        fixture.proof = ciborium::from_reader(bytes.as_slice()).unwrap();
        #[cfg(debug_assertions)]
        {
            fixture.proof.proof.pattern = pattern;
        }
        verify_v4(&fixture, context, &EmbeddedZkArtifacts).expect("verify after CBOR roundtrip");

        let wrong_context = FieldElement::from_arbitrary_raw_bytes(b"teedi_migration");
        assert!(verify_v4(&fixture, wrong_context, &EmbeddedZkArtifacts).is_err());

        let nonce = fixture.nonce;
        fixture.nonce = FieldElement::from(1u64);
        assert!(verify_v4(&fixture, context, &EmbeddedZkArtifacts).is_err());
        fixture.nonce = nonce;

        let commitment = fixture.commitment;
        fixture.commitment = FieldElement::from(1u64);
        assert!(verify_v4(&fixture, context, &EmbeddedZkArtifacts).is_err());
        fixture.commitment = commitment;

        let root = fixture.proof.merkle_root;
        fixture.proof.merkle_root = FieldElement::from(1u64);
        assert!(verify_v4(&fixture, context, &EmbeddedZkArtifacts).is_err());
        fixture.proof.merkle_root = root;

        fixture.proof.proof.narg_string[0] ^= 1;
        assert!(verify_v4(&fixture, context, &EmbeddedZkArtifacts).is_err());
    }
}

fn measure_verify_series(verify: &VerifyCall) -> Result<Vec<Sample>, String> {
    let mut samples = Vec::with_capacity(ITERATIONS);
    for iteration in 0..ITERATIONS {
        let cpu_start = ProcessTime::now();
        let wall_start = Instant::now();
        verify().map_err(|error| {
            format!(
                "verification failed during timed iteration {}: {error}",
                iteration + 1
            )
        })?;
        let wall = wall_start.elapsed();
        let cpu = cpu_start.elapsed();
        samples.push(Sample { wall, cpu });
    }
    Ok(samples)
}

fn summarize_samples(samples: &[Sample]) -> Result<Statistics, String> {
    let measured = samples
        .get(WARMUP_ITERATIONS..)
        .ok_or_else(|| "warmup discard exceeds the available samples".to_owned())?;
    if measured.is_empty() {
        return Err("no samples remain after warmup discard".to_owned());
    }

    let sample_count = measured.len() as f64;
    let mean_wall_seconds = measured
        .iter()
        .map(|sample| sample.wall.as_secs_f64())
        .sum::<f64>()
        / sample_count;
    let mean_cpu_seconds = measured
        .iter()
        .map(|sample| sample.cpu.as_secs_f64())
        .sum::<f64>()
        / sample_count;
    if mean_wall_seconds == 0.0 {
        return Err("mean wall time is zero; effective-core ratio is undefined".to_owned());
    }

    // Process CPU time sums work across threads, so cpu/wall estimates effective cores used.
    let effective_cores = mean_cpu_seconds / mean_wall_seconds;
    Ok(Statistics {
        mean_wall_ms: mean_wall_seconds * 1_000.0,
        mean_cpu_ms: mean_cpu_seconds * 1_000.0,
        effective_cores,
    })
}

fn measure_concurrent_verify(
    concurrency: usize,
    verify: Arc<VerifyCall>,
) -> Result<Duration, String> {
    if concurrency == 0 {
        return Err("concurrency must be greater than zero".to_owned());
    }

    let barrier = Arc::new(Barrier::new(concurrency + 1));
    let mut workers = Vec::with_capacity(concurrency);
    for worker_index in 0..concurrency {
        let worker_barrier = Arc::clone(&barrier);
        let worker_verify = Arc::clone(&verify);
        workers.push(thread::spawn(move || {
            worker_barrier.wait();
            worker_verify().map_err(|error| {
                format!("worker {} verification failed: {error}", worker_index + 1)
            })
        }));
    }

    let wall_start = Instant::now();
    barrier.wait();
    let mut first_error: Option<String> = None;
    let mut first_panic: Option<Box<dyn Any + Send>> = None;
    for worker in workers {
        match worker.join() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            Err(payload) => {
                if first_panic.is_none() {
                    first_panic = Some(payload);
                }
            }
        }
    }
    let elapsed = wall_start.elapsed();

    if let Some(payload) = first_panic {
        panic::resume_unwind(payload);
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(elapsed)
}

fn rayon_thread_setting() -> String {
    // Rayon's global pool may already exist, so setting this in-process would be unreliable.
    match env::var("RAYON_NUM_THREADS") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => "unset (default Rayon pool)".to_owned(),
        Err(error) => format!("unreadable ({error})"),
    }
}

fn main() {
    let context =
        FieldElement::from_arbitrary_raw_bytes(ChallengeType::Enrollment.as_str().as_bytes());
    let available_parallelism = thread::available_parallelism()
        .map(|count| count.get().to_string())
        .unwrap_or_else(|error| format!("unavailable ({error})"));
    println!("Offline proof verification benchmark");
    println!("available parallelism : {available_parallelism}");
    println!("RAYON_NUM_THREADS     : {}", rayon_thread_setting());
    println!("iterations            : {ITERATIONS} ({WARMUP_ITERATIONS} warmup discarded)");
    println!("concurrency levels    : {:?}\n", CONCURRENCY_LEVELS);

    let v1_fixture = Arc::new(
        build_v1_fixture().unwrap_or_else(|error| panic!("v1 fixture setup failed: {error}")),
    );
    let v4_fixture = Arc::new(
        build_v4_fixture().unwrap_or_else(|error| panic!("v4 fixture setup failed: {error}")),
    );

    verify_v1(&v1_fixture)
        .unwrap_or_else(|error| panic!("v1 proof preflight verification failed: {error}"));

    verify_v4(&v4_fixture, context, &EmbeddedZkArtifacts)
        .unwrap_or_else(|error| panic!("v4 proof preflight verification failed: {error}"));

    let v1_verify: Arc<VerifyCall> = {
        let fixture = Arc::clone(&v1_fixture);
        Arc::new(move || verify_v1(&fixture))
    };
    let v4_verify: Arc<VerifyCall> = {
        let fixture = Arc::clone(&v4_fixture);
        Arc::new(move || verify_v4(&fixture, context, &EmbeddedZkArtifacts))
    };

    let v1_statistics = summarize_samples(
        &measure_verify_series(v1_verify.as_ref())
            .unwrap_or_else(|error| panic!("v1 timed verification failed: {error}")),
    )
    .unwrap_or_else(|error| panic!("v1 statistics failed: {error}"));
    let v4_statistics = summarize_samples(
        &measure_verify_series(v4_verify.as_ref())
            .unwrap_or_else(|error| panic!("v4 timed verification failed: {error}")),
    )
    .unwrap_or_else(|error| panic!("v4 statistics failed: {error}"));

    println!(
        "Latency and process CPU ({ITERATIONS} iterations, first {WARMUP_ITERATIONS} discarded)"
    );
    println!(
        "{:<8} {:>14} {:>14} {:>16}",
        "proof", "wall mean ms", "cpu mean ms", "effective cores"
    );
    println!(
        "{:<8} {:>14.3} {:>14.3} {:>16.2}",
        "v1", v1_statistics.mean_wall_ms, v1_statistics.mean_cpu_ms, v1_statistics.effective_cores
    );
    println!(
        "{:<8} {:>14.3} {:>14.3} {:>16.2}\n",
        "v4", v4_statistics.mean_wall_ms, v4_statistics.mean_cpu_ms, v4_statistics.effective_cores
    );

    println!("Concurrency scaling (one verification per OS thread)");
    println!("{:>8} {:>14} {:>14}", "threads", "v1 wall ms", "v4 wall ms");
    for concurrency in CONCURRENCY_LEVELS {
        let v1_wall = measure_concurrent_verify(concurrency, Arc::clone(&v1_verify))
            .unwrap_or_else(|error| panic!("v1 concurrency verification failed: {error}"));
        let v4_wall = measure_concurrent_verify(concurrency, Arc::clone(&v4_verify))
            .unwrap_or_else(|error| panic!("v4 concurrency verification failed: {error}"));
        println!(
            "{:>8} {:>14.3} {:>14.3}",
            concurrency,
            v1_wall.as_secs_f64() * 1_000.0,
            v4_wall.as_secs_f64() * 1_000.0
        );
    }
}
