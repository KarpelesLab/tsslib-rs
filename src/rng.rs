//! The entropy source behind every session's randomness.
//!
//! With the `std` feature (or on `wasm32-unknown-unknown`, where the host
//! supplies entropy) sessions draw from the operating system's CSPRNG and
//! nothing needs configuring. A bare-metal `no_std` build has no such source:
//! register one with [`set_entropy_source`] before starting any session, or
//! the first random draw panics.

use purecrypto::rng::{CryptoRng, RngCore};

/// Fills the buffer with cryptographically secure random bytes. Must not
/// fail: an implementation that cannot produce entropy has to panic rather
/// than return a partly filled buffer.
pub type EntropySource = fn(&mut [u8]);

static SOURCE: spin::Once<EntropySource> = spin::Once::new();

/// Registers the CSPRNG used on targets without OS randomness.
///
/// The first registration wins; returns `false` (and keeps the existing
/// source) if one was already set. Ignored on targets that have OS randomness
/// (see the [module docs](self)), so a library may call it unconditionally.
pub fn set_entropy_source(source: EntropySource) -> bool {
    let mut installed = false;
    SOURCE.call_once(|| {
        installed = true;
        source
    });
    installed
}

/// The crate's RNG: OS entropy where available, else the registered
/// [`EntropySource`].
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
        Some(source) => source(dest),
        None => panic!(
            "tsslib: no entropy source on this target; call \
             tsslib::rng::set_entropy_source before starting a session"
        ),
    }
}
