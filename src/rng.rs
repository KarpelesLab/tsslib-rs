//! The entropy source behind every session's randomness.
//!
//! With the `std` feature (or on `wasm32-unknown-unknown`, where the host
//! supplies entropy) sessions draw from the operating system's CSPRNG and
//! nothing needs configuring. A bare-metal `no_std` build has no such source:
//! register one with [`set_entropy_source`] before starting any session, or
//! the first random draw panics.

use crate::prelude::*;
use crate::sync::Mutex;
use purecrypto::rng::{CryptoRng, CryptoRngCore, RngCore};

/// The registered generator. Any `purecrypto` RNG works — the same
/// `RngCore + CryptoRng` bound purecrypto's own APIs take.
type Source = Mutex<Box<dyn CryptoRngCore + Send>>;

static SOURCE: spin::Once<Source> = spin::Once::new();

/// Registers the CSPRNG used on targets without OS randomness, e.g. a
/// [`purecrypto::rng::HmacDrbg`] seeded from a hardware TRNG, or a wrapper
/// around the TRNG itself:
///
/// ```
/// use purecrypto::hash::Sha256;
/// use purecrypto::rng::HmacDrbg;
///
/// # let (seed, nonce) = ([7u8; 32], [9u8; 16]);
/// let drbg = HmacDrbg::<Sha256>::new(&seed, &nonce, b"tsslib");
/// tsslib::rng::set_entropy_source(Box::new(drbg));
/// ```
///
/// Every session draws from this one generator, serialized by a lock. The
/// first registration wins; returns `false` (dropping `rng`) if one was
/// already set. Ignored on targets that have OS randomness (see the
/// [module docs](self)), so a library may call it unconditionally.
pub fn set_entropy_source(rng: Box<dyn CryptoRngCore + Send>) -> bool {
    let mut rng = Some(rng);
    SOURCE.call_once(|| Mutex::new(rng.take().expect("call_once runs once")));
    rng.is_none()
}

/// The crate's RNG: OS entropy where available, else the registered
/// generator.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemRng;

impl RngCore for SystemRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill(dest)
    }
}

impl CryptoRng for SystemRng {}

#[cfg(any(
    feature = "std",
    test,
    all(target_arch = "wasm32", target_os = "unknown")
))]
fn fill(dest: &mut [u8]) {
    purecrypto::rng::OsRng.fill_bytes(dest)
}

#[cfg(not(any(
    feature = "std",
    test,
    all(target_arch = "wasm32", target_os = "unknown")
)))]
fn fill(dest: &mut [u8]) {
    match SOURCE.get() {
        Some(rng) => rng.lock().fill_bytes(dest),
        None => panic!(
            "tsslib: no entropy source on this target; call \
             tsslib::rng::set_entropy_source before starting a session"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Counter(u8);
    impl RngCore for Counter {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for b in dest {
                self.0 = self.0.wrapping_add(1);
                *b = self.0;
            }
        }
    }
    impl CryptoRng for Counter {}

    #[test]
    fn first_registration_wins_and_is_drawn_from() {
        assert!(set_entropy_source(Box::new(Counter(0))));
        assert!(!set_entropy_source(Box::new(Counter(100))));
        let mut buf = [0u8; 3];
        SOURCE.get().unwrap().lock().fill_bytes(&mut buf);
        assert_eq!(buf, [1, 2, 3]);
    }
}
