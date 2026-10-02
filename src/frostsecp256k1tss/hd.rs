//! BIP32 non-hardened derivation, Taproot output keys, and key import.
//!
//! Derivation is standard BIP32 `CKDpub` from the group key and the key's
//! chain code, so the group key plus chain code behaves like an account-level
//! xpub: wallets deriving from it get the same child keys. Hardened indices
//! need the whole private key and are rejected.

use super::Error;
use super::key::{Key, strip};
use super::signing::{SignOptions, Signing, SigningKey, TaprootTweak};
use super::suite::{Point, Scalar, encode_point, is_identity, mul_base};
use crate::prelude::*;
use crate::tss::bigint::BigUintDec;
use crate::tss::{Parameters, PartyId};
use purecrypto::hash::{HmacSha512, sha256};

/// BIP32 hardened-index boundary; path components `>= this` are rejected.
pub const HARDENED_KEY_START: u32 = 0x8000_0000;

const CHAINCODE_DOMAIN: &[u8] = b"FROST-secp256k1-TR-chaincode-v1";

/// The chain code a freshly generated key gets:
/// `SHA-256(domain || compressed(P))`. Deterministic, so every keygen party
/// agrees on it.
pub fn derive_chain_code(group_public_key: &Point) -> [u8; 32] {
    let enc = encode_point(group_public_key).unwrap_or([0; 33]);
    sha256(&[CHAINCODE_DOMAIN, &enc].concat())
}

impl Key {
    /// Walks a non-hardened BIP32 path, returning `(tweak, child_pub,
    /// child_chain_code)` with `child_pub = P + tweak·G`. Pass the tweak to
    /// [`SignOptions::tweak`] to sign for the child.
    pub fn derive_child(&self, path: &[u32]) -> Result<(Scalar, Point, [u8; 32]), Error> {
        if path.iter().any(|&i| i >= HARDENED_KEY_START) {
            return Err(Error::Validation(
                "hardened derivation needs the whole private key".into(),
            ));
        }
        let mut cur_pub = self.group_public_key;
        let mut cur_cc = self.chain_code;
        let mut tweak = Scalar::ZERO;
        for &index in path {
            let compressed = encode_point(&cur_pub)
                .ok_or_else(|| Error::Validation("cannot derive from the identity".into()))?;
            let i = HmacSha512::new(&cur_cc)
                .chain(&compressed)
                .chain(&index.to_be_bytes())
                .finalize();
            let il: [u8; 32] = i[..32].try_into().unwrap();
            let il = Scalar::from_bytes_be(&il).map_err(|_| {
                Error::Validation(format!("IL >= n at index {index}; use the next index"))
            })?;
            let next = cur_pub.add(&mul_base(&il));
            if is_identity(&next) {
                return Err(Error::Validation(format!(
                    "child key at index {index} is the identity; use the next index"
                )));
            }
            cur_pub = next;
            cur_cc.copy_from_slice(&i[32..]);
            tweak = tweak.add(&il);
        }
        Ok((tweak, cur_pub, cur_cc))
    }

    /// The 32-byte x-only key a signature made with `opts` verifies under
    /// (for a Taproot tweak, the output key that goes in the `scriptPubKey`
    /// as `OP_1 <key>`).
    pub fn signing_public_key(&self, opts: &SignOptions) -> Result<[u8; 32], Error> {
        Ok(SigningKey::new(&self.group_public_key, opts)?.q_x)
    }

    /// The BIP341 output key for this key as the internal key, with
    /// `merkle_root = None` for a key-path-only (BIP86) output.
    pub fn taproot_output_key(&self, merkle_root: Option<[u8; 32]>) -> Result<[u8; 32], Error> {
        self.signing_public_key(&SignOptions {
            tweak: None,
            taproot: Some(taproot_tweak(merkle_root)),
        })
    }

    /// Derives the child at `path` and starts signing for it, as a Taproot
    /// output key when `merkle_root` is given (`Some(None)` for key-path
    /// only). Returns the session and the x-only key it signs for.
    pub fn derive_and_sign(
        &self,
        path: &[u32],
        msg: Vec<u8>,
        params: Parameters,
        taproot: Option<Option<[u8; 32]>>,
    ) -> Result<(Signing, [u8; 32]), Error> {
        let (tweak, _, _) = self.derive_child(path)?;
        let opts = SignOptions {
            tweak: Some(tweak),
            taproot: taproot.map(taproot_tweak),
        };
        let q_x = self.signing_public_key(&opts)?;
        Ok((self.new_signing_with(msg, params, opts)?, q_x))
    }
}

fn taproot_tweak(merkle_root: Option<[u8; 32]>) -> TaprootTweak {
    match merkle_root {
        None => TaprootTweak::KeyPathOnly,
        Some(root) => TaprootTweak::ScriptTree(root),
    }
}

/// Wraps an existing secp256k1 private key as a 1-of-1 [`Key`] owned by
/// `party`, ready to be the sole old-committee input to a resharing. Pass the
/// key's BIP32 chain code to keep deriving the same child keys as before;
/// `None` derives one from the public key.
///
/// The party holds the whole secret until it reshares, so reshare right
/// after importing.
pub fn import_key(
    private: &Scalar,
    chain_code: Option<[u8; 32]>,
    party: &PartyId,
) -> Result<Key, Error> {
    if bool::from(private.is_zero()) {
        return Err(Error::Validation("import_key: private key is zero".into()));
    }
    let share_id = strip(&party.key);
    if share_id.is_empty() {
        return Err(Error::Validation(
            "import_key: party has an empty key".into(),
        ));
    }
    let pub_key = mul_base(private);
    let share_id = BigUintDec::from_be_bytes(share_id);
    let key = Key {
        xi: private.clone(),
        share_id: share_id.clone(),
        ks: vec![share_id],
        big_xj: vec![pub_key],
        group_public_key: pub_key,
        chain_code: chain_code.unwrap_or_else(|| derive_chain_code(&pub_key)),
    };
    key.validate_basic()?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frostsecp256k1tss::suite::{decode_scalar, x_only};

    /// BIP32 test vector 1: the non-hardened step m/0' -> m/0'/1 gives the
    /// published child public key, chain code and (parent + tweak) private key.
    #[test]
    fn bip32_ckdpub_matches_test_vector_1() {
        // m/0' (from BIP32 test vector 1).
        let parent_priv = decode_scalar(
            &hex::decode("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea")
                .unwrap(),
        )
        .unwrap();
        let parent_cc: [u8; 32] =
            hex::decode("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141")
                .unwrap()
                .try_into()
                .unwrap();
        let party = PartyId::new("1", "P1", vec![1]);
        let key = import_key(&parent_priv, Some(parent_cc), &party).unwrap();
        // m/0'/1
        let (tweak, child, cc) = key.derive_child(&[1]).unwrap();
        assert_eq!(
            hex::encode(encode_point(&child).unwrap()),
            "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"
        );
        assert_eq!(
            hex::encode(cc),
            "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"
        );
        assert_eq!(
            hex::encode(parent_priv.add(&tweak).to_bytes_be()),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );
    }

    #[test]
    fn import_rejects_zero_and_hardened_paths() {
        let party = PartyId::new("1", "P1", vec![1]);
        assert!(import_key(&Scalar::ZERO, None, &party).is_err());
        let key = import_key(&Scalar::ONE, None, &party).unwrap();
        assert!(key.derive_child(&[HARDENED_KEY_START]).is_err());
        let (t, p, cc) = key.derive_child(&[]).unwrap();
        assert!(bool::from(t.is_zero()));
        assert_eq!(x_only(&p), x_only(&key.group_public_key));
        assert_eq!(cc, key.chain_code);
    }

    /// BIP86 test vector: account 0, first receiving address
    /// (m/86'/0'/0'/0/0). The private key is decoded from the published xprv;
    /// the internal and output keys are published directly.
    #[test]
    fn taproot_output_key_matches_bip86() {
        let internal_priv = decode_scalar(
            &hex::decode("41f41d69260df4cf277826a9b65a3717e4eeddbeedf637f212ca096576479361")
                .unwrap(),
        )
        .unwrap();
        let party = PartyId::new("1", "P1", vec![1]);
        let key = import_key(&internal_priv, None, &party).unwrap();
        assert_eq!(
            hex::encode(key.x_only_public_key()),
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
        );
        assert_eq!(
            hex::encode(key.taproot_output_key(None).unwrap()),
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        );
    }
}
