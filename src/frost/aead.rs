//! X25519 + HKDF-SHA256 + ChaCha20-Poly1305 envelope for DKG/resharing P2P
//! shares. Port of tss-lib `crypto/frostenc`.
//!
//! Each participant samples a fresh ephemeral X25519 keypair per run and
//! broadcasts the public part. For round 2, sender and recipient derive a
//! per-pair shared secret via X25519; HKDF stretches it (with the associated
//! data as `info`) into a ChaCha20-Poly1305 key. The sealed payload is
//! `nonce(12) || ciphertext || tag(16)`.

use purecrypto::cipher::ChaCha20Poly1305;
use purecrypto::ec::x25519::x25519;
use purecrypto::hash::Sha256;
use purecrypto::kdf::hkdf;
use purecrypto::rng::RngCore;
use zeroize::Zeroizing;

/// Length of an X25519 private/public key.
pub const EPHEMERAL_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
/// HKDF `info` prefix; domain-separates this AEAD key from other uses.
const KEY_DERIVATION_INFO: &[u8] = b"frosttss/share-aead-v1";
const X25519_BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// An error sealing or opening a share envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AeadError {
    /// X25519 produced an all-zero shared secret (small-subgroup public key).
    SmallSubgroup,
    /// The ciphertext was shorter than `nonce || tag`.
    TooShort,
    /// The AEAD tag did not verify (tampered ciphertext or wrong AD).
    TagMismatch,
}

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let m = match self {
            AeadError::SmallSubgroup => "shared secret is all-zero (small-subgroup public key)",
            AeadError::TooShort => "ciphertext too short",
            AeadError::TagMismatch => "AEAD tag verification failed",
        };
        write!(f, "frostenc: {m}")
    }
}

impl std::error::Error for AeadError {}

/// Samples a fresh ephemeral X25519 keypair, returning `(private, public)`.
pub fn new_ephemeral_key(rng: &mut impl RngCore) -> ([u8; 32], [u8; 32]) {
    let mut priv_key = [0u8; 32];
    rng.fill_bytes(&mut priv_key);
    let pub_key = x25519(&priv_key, &X25519_BASEPOINT);
    (priv_key, pub_key)
}

/// Encrypts `plaintext` for `recipient_pub` under the `(sender_priv,
/// recipient_pub)` shared secret. Returns `nonce || ciphertext || tag`.
pub fn seal_share(
    rng: &mut impl RngCore,
    sender_priv: &[u8; 32],
    recipient_pub: &[u8; 32],
    ad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    // Zeroizing wipes the raw X25519 shared secret and the derived AEAD key
    // on every exit path (including early returns and unwinds).
    let shared = Zeroizing::new(shared_secret(sender_priv, recipient_pub)?);
    let key = Zeroizing::new(derive_key(&shared, ad));

    let mut nonce = [0u8; NONCE_BYTES];
    rng.fill_bytes(&mut nonce);

    // `buf` holds the plaintext only until the in-place encrypt below turns it
    // into ciphertext, so no plaintext copy outlives this function.
    let mut buf = plaintext.to_vec();
    let tag = ChaCha20Poly1305::new(&key).encrypt(&nonce, ad, &mut buf);

    let mut out = Vec::with_capacity(NONCE_BYTES + buf.len() + TAG_BYTES);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypts a payload produced by [`seal_share`] under the `(recipient_priv,
/// sender_pub)` shared secret. `ad` must match the value used at seal time.
pub fn open_share(
    recipient_priv: &[u8; 32],
    sender_pub: &[u8; 32],
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if ciphertext.len() < NONCE_BYTES + TAG_BYTES {
        return Err(AeadError::TooShort);
    }
    // Zeroizing wipes the raw X25519 shared secret and the derived AEAD key
    // on every exit path (including the tag-mismatch error return and unwinds).
    let shared = Zeroizing::new(shared_secret(recipient_priv, sender_pub)?);
    let key = Zeroizing::new(derive_key(&shared, ad));

    let nonce: [u8; NONCE_BYTES] = ciphertext[..NONCE_BYTES].try_into().unwrap();
    let tag: [u8; TAG_BYTES] = ciphertext[ciphertext.len() - TAG_BYTES..]
        .try_into()
        .unwrap();
    // Decryption happens in place: `buf` starts as a ciphertext copy and is
    // transformed into the plaintext, which is moved (not copied) to the
    // caller, so no intermediate plaintext copy is left behind. The returned
    // Vec itself is owned by the caller and intentionally not wrapped — doing
    // so would change the public API.
    let mut buf = ciphertext[NONCE_BYTES..ciphertext.len() - TAG_BYTES].to_vec();

    ChaCha20Poly1305::new(&key)
        .decrypt(&nonce, ad, &mut buf, &tag)
        .map_err(|_| AeadError::TagMismatch)?;
    Ok(buf)
}

/// X25519 shared secret, rejecting the all-zero (small-subgroup) result.
fn shared_secret(scalar: &[u8; 32], point: &[u8; 32]) -> Result<[u8; 32], AeadError> {
    let shared = x25519(scalar, point);
    if shared.iter().all(|&b| b == 0) {
        return Err(AeadError::SmallSubgroup);
    }
    Ok(shared)
}

/// HKDF-SHA256(salt="", ikm=shared, info=`KEY_DERIVATION_INFO || ad`) -> 32-byte key.
fn derive_key(shared: &[u8; 32], ad: &[u8]) -> [u8; 32] {
    let mut info = Vec::with_capacity(KEY_DERIVATION_INFO.len() + ad.len());
    info.extend_from_slice(KEY_DERIVATION_INFO);
    info.extend_from_slice(ad);
    let mut key = [0u8; 32];
    hkdf::<Sha256>(&[], shared, &info, &mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::rng::OsRng;

    #[test]
    fn seal_open_roundtrip() {
        let (a_priv, a_pub) = new_ephemeral_key(&mut OsRng);
        let (b_priv, b_pub) = new_ephemeral_key(&mut OsRng);
        let ad = b"frosttss/keygen/r2/v1|context";
        let msg = b"a secret share value";

        let ct = seal_share(&mut OsRng, &a_priv, &b_pub, ad, msg).unwrap();
        let pt = open_share(&b_priv, &a_pub, ad, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn wrong_ad_fails() {
        let (a_priv, a_pub) = new_ephemeral_key(&mut OsRng);
        let (b_priv, b_pub) = new_ephemeral_key(&mut OsRng);
        let ct = seal_share(&mut OsRng, &a_priv, &b_pub, b"ad1", b"x").unwrap();
        assert_eq!(
            open_share(&b_priv, &a_pub, b"ad2", &ct),
            Err(AeadError::TagMismatch)
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (a_priv, a_pub) = new_ephemeral_key(&mut OsRng);
        let (b_priv, b_pub) = new_ephemeral_key(&mut OsRng);
        let mut ct = seal_share(&mut OsRng, &a_priv, &b_pub, b"ad", b"hello").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert_eq!(
            open_share(&b_priv, &a_pub, b"ad", &ct),
            Err(AeadError::TagMismatch)
        );
    }

    #[test]
    fn shared_secret_is_symmetric() {
        let (a_priv, a_pub) = new_ephemeral_key(&mut OsRng);
        let (b_priv, b_pub) = new_ephemeral_key(&mut OsRng);
        assert_eq!(
            shared_secret(&a_priv, &b_pub),
            shared_secret(&b_priv, &a_pub)
        );
    }
}
