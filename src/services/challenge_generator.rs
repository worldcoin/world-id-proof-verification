use std::sync::Arc;

use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use tracing::instrument;

use crate::models::challenge_model::{Challenge, ChallengeId, Nonce};

/// A trait port for preparing the `(challenge_id, nonce)` values for the World
/// ID 4.x ownership flow.
///
/// The trait is an injection seam: a test can supply a deterministic generator
/// in place of [`OsRngChallengeGenerator`].
pub trait ChallengeGenerator: Send + Sync {
    /// Generates a fresh challenge.
    fn generate(&self) -> Challenge;
}

pub type DynChallengeGenerator = Arc<dyn ChallengeGenerator>;

/// The production [`ChallengeGenerator`], drawing from the OS CSPRNG ([`OsRng`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRngChallengeGenerator;

impl ChallengeGenerator for OsRngChallengeGenerator {
    fn generate(&self) -> Challenge {
        generate_with(&mut OsRng)
    }
}

/// Generates a fresh challenge from an explicit CSPRNG.
///
/// The `R: CryptoRng` bound forbids passing a non-cryptographic PRNG.
/// `challenge_id` and `nonce` are drawn from two independent reads of `rng`, so
/// the opaque handle is never derivable from the public circuit input. Exposed
/// as a free function so callers (and tests) can pin the entropy source without
/// going through the trait.
#[instrument(skip_all)]
pub fn generate_with<R: RngCore + CryptoRng>(rng: &mut R) -> Challenge {
    let challenge_id = random_challenge_id(rng);
    let nonce = Nonce::random(rng);
    Challenge {
        challenge_id,
        nonce,
    }
}

/// Builds a v4 UUID from 16 CSPRNG bytes drawn from `rng`, so the handle's
/// randomness comes from the same cryptographically secure source as the nonce
/// rather than `uuid`'s internal global RNG.
fn random_challenge_id<R: RngCore + CryptoRng>(rng: &mut R) -> ChallengeId {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Compile-time guarantee that the generator only accepts a cryptographically
    /// secure RNG. This only type-checks because `OsRng: CryptoRng`; if the
    /// `CryptoRng` bound were dropped it would be a silent weakening, so we pin
    /// the property here.
    fn _assert_csprng<R: RngCore + CryptoRng>() {}

    #[test]
    fn rng_type_is_cryptographically_secure() {
        _assert_csprng::<OsRng>();
    }

    /// Every generated nonce is a valid, canonical field element: it round-trips
    /// through `FieldElement`'s strict reject-if-`>=`-`p` parser. `FieldElement`
    /// guarantees validity by construction, so a handful of CSPRNG draws is
    /// enough to exercise the path — not a statistical harness.
    #[test]
    fn generated_nonces_are_canonical_field_elements() {
        for _ in 0..256 {
            let challenge = OsRngChallengeGenerator.generate();
            let encoded = challenge.nonce.to_string();
            assert_eq!(Nonce::from_str(&encoded).unwrap(), challenge.nonce);
        }
    }

    /// `challenge_id` is a v4 (random) UUID, distinct from and not derivable from
    /// the nonce: different type/format, and its string is not parseable as a
    /// field element.
    #[test]
    fn challenge_id_is_v4_and_distinct_from_nonce() {
        let challenge = OsRngChallengeGenerator.generate();
        assert_eq!(
            challenge.challenge_id.get_version(),
            Some(uuid::Version::Random)
        );
        assert_ne!(
            challenge.challenge_id.to_string(),
            challenge.nonce.to_string()
        );
        assert!(Nonce::from_str(&challenge.challenge_id.to_string()).is_err());
    }

    /// Successive challenges differ in both fields (fresh entropy each call).
    #[test]
    fn successive_challenges_differ() {
        let a = OsRngChallengeGenerator.generate();
        let b = OsRngChallengeGenerator.generate();
        assert_ne!(a.challenge_id, b.challenge_id);
        assert_ne!(a.nonce, b.nonce);
    }
}
