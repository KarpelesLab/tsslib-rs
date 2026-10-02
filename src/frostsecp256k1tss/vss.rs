//! Dealer-side helpers for keygen and resharing: Feldman VSS over secp256k1,
//! a Schnorr proof of knowledge of the dealt secret, and a hash commitment
//! over a list of group elements.

use super::Error;
use super::suite::{
    ELEMENT_LEN, Point, Scalar, TR, decode_point, decode_scalar, encode_point, id_scalar,
    is_identity, mul_base, point_eq,
};
use crate::prelude::*;
use purecrypto::hash::sha256;
use purecrypto::rng::RngCore;

/// A uniformly random non-zero scalar.
pub(crate) fn random_scalar(rng: &mut impl RngCore) -> Scalar {
    loop {
        let mut b = [0u8; 48];
        rng.fill_bytes(&mut b);
        let s = super::suite::scalar_from_be_reduce(&b);
        zeroize::Zeroize::zeroize(&mut b);
        if !bool::from(s.is_zero()) {
            return s;
        }
    }
}

/// Rejects `threshold < 1`, fewer than `threshold + 1` identifiers, and any
/// identifier that is zero or a duplicate mod `n` (a zero identifier would be
/// dealt `f(0)`, the secret itself).
pub(crate) fn check_indexes(threshold: usize, ids: &[Vec<u8>]) -> Result<(), String> {
    if threshold < 1 {
        return Err("threshold must be at least 1".into());
    }
    check_old_committee(threshold, ids)
}

/// [`check_indexes`] for a committee handing its key on in a resharing,
/// which may also be a 1-of-1 (`threshold == 0`), e.g. an imported key.
pub(crate) fn check_old_committee(threshold: usize, ids: &[Vec<u8>]) -> Result<(), String> {
    if ids.len() <= threshold {
        return Err("fewer than threshold+1 identifiers".into());
    }
    let mut seen: Vec<Scalar> = Vec::with_capacity(ids.len());
    for id in ids {
        let x = id_scalar(id);
        if bool::from(x.is_zero()) {
            return Err("identifier is zero mod the group order".into());
        }
        if seen.iter().any(|y| bool::from(x.ct_eq(y))) {
            return Err("duplicate identifier mod the group order".into());
        }
        seen.push(x);
    }
    Ok(())
}

/// Shares `secret` with a random degree-`threshold` polynomial. Returns the
/// Feldman commitments `a_k·G` and one share `f(id)` per entry of `ids`.
/// Callers run [`check_indexes`] on `ids` first.
pub(crate) fn create(
    threshold: usize,
    secret: &Scalar,
    ids: &[Vec<u8>],
    rng: &mut impl RngCore,
) -> (Vec<Point>, Vec<Scalar>) {
    let mut poly: Vec<Scalar> = Vec::with_capacity(threshold + 1);
    poly.push(secret.clone());
    for _ in 0..threshold {
        poly.push(random_scalar(rng));
    }
    let commitments = poly.iter().map(mul_base).collect();
    let shares = ids.iter().map(|id| eval(&poly, &id_scalar(id))).collect();
    (commitments, shares)
}

/// `Σ_k id^k · commitments[k]`: the public image of the share for `id`.
pub(crate) fn share_image(id: &Scalar, commitments: &[Point]) -> Point {
    let mut acc = commitments[0];
    let mut xk = Scalar::ONE;
    for c in &commitments[1..] {
        xk = xk.mul(id);
        acc = acc.add(&c.mul(&xk));
    }
    acc
}

/// Whether `share` is the evaluation at `id` of the polynomial behind the
/// `threshold + 1` Feldman `commitments`.
pub(crate) fn verify(id: &[u8], share: &Scalar, threshold: usize, commitments: &[Point]) -> bool {
    commitments.len() == threshold + 1
        && point_eq(&mul_base(share), &share_image(&id_scalar(id), commitments))
}

fn eval(poly: &[Scalar], x: &Scalar) -> Scalar {
    poly.iter()
        .rev()
        .fold(Scalar::ZERO, |acc, a| acc.mul(x).add(a))
}

/// A Schnorr proof of knowledge of `x` with `X = x·G`, bound to a session
/// string. The challenge is `H(ctx, "pok", session || X || R)` with the
/// suite's hash-to-scalar.
pub(crate) struct ZkProof {
    r: Point,
    t: Scalar,
}

impl ZkProof {
    pub(crate) fn prove(session: &[u8], x: &Scalar, x_pub: &Point, rng: &mut impl RngCore) -> Self {
        let k = random_scalar(rng);
        let r = mul_base(&k);
        let c = challenge(session, x_pub, &r);
        ZkProof {
            r,
            t: k.add(&c.mul(x)),
        }
    }

    pub(crate) fn verify(&self, session: &[u8], x_pub: &Point) -> bool {
        !is_identity(&self.r)
            && point_eq(
                &mul_base(&self.t),
                &self.r.add(&x_pub.mul(&challenge(session, x_pub, &self.r))),
            )
    }

    /// `(R as 33-byte SEC1, t as 32-byte big-endian)`.
    pub(crate) fn to_wire(&self) -> (Vec<u8>, Vec<u8>) {
        (
            encode_point(&self.r)
                .map(|b| b.to_vec())
                .unwrap_or_default(),
            self.t.to_bytes_be().to_vec(),
        )
    }

    pub(crate) fn from_wire(r: &[u8], t: &[u8]) -> Result<Self, Error> {
        Ok(ZkProof {
            r: decode_point(r).ok_or_else(|| Error::Validation("invalid PoK R".into()))?,
            t: decode_scalar(t).ok_or_else(|| Error::Validation("invalid PoK t".into()))?,
        })
    }
}

fn challenge(session: &[u8], x_pub: &Point, r: &Point) -> Scalar {
    let mut buf = Vec::with_capacity(session.len() + 2 * ELEMENT_LEN);
    buf.extend_from_slice(session);
    buf.extend_from_slice(&encode_point(x_pub).unwrap_or([0; ELEMENT_LEN]));
    buf.extend_from_slice(&encode_point(r).unwrap_or([0; ELEMENT_LEN]));
    TR.hash_to_scalar(b"pok", &buf)
}

/// Commits to `elements` (none may be the identity): returns the commitment
/// `SHA-256(randomness || Encode(e_0) || …)` and the 32-byte randomness that
/// opens it together with the elements.
pub(crate) fn commit_elements(rng: &mut impl RngCore, elements: &[Point]) -> (Vec<u8>, [u8; 32]) {
    let mut randomness = [0u8; 32];
    rng.fill_bytes(&mut randomness);
    (element_digest(&randomness, elements).to_vec(), randomness)
}

/// Opens a [`commit_elements`] commitment: decodes `encoded` and checks the
/// digest. `None` on a bad encoding, a wrong count, or a digest mismatch.
pub(crate) fn open_elements(
    commitment: &[u8],
    randomness: &[u8],
    encoded: &[Vec<u8>],
    count: usize,
) -> Option<Vec<Point>> {
    let randomness: [u8; 32] = randomness.try_into().ok()?;
    if encoded.len() != count {
        return None;
    }
    let elements = encoded
        .iter()
        .map(|e| decode_point(e))
        .collect::<Option<Vec<_>>>()?;
    (element_digest(&randomness, &elements).as_slice() == commitment).then_some(elements)
}

fn element_digest(randomness: &[u8; 32], elements: &[Point]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + elements.len() * ELEMENT_LEN);
    buf.extend_from_slice(randomness);
    for e in elements {
        buf.extend_from_slice(&encode_point(e).unwrap_or([0; ELEMENT_LEN]));
    }
    sha256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SystemRng;

    fn ids(n: u8) -> Vec<Vec<u8>> {
        (1..=n).map(|i| vec![i]).collect()
    }

    #[test]
    fn shares_verify_and_reconstruct() {
        let secret = random_scalar(&mut SystemRng);
        let ids = ids(4);
        check_indexes(2, &ids).unwrap();
        let (vs, shares) = create(2, &secret, &ids, &mut SystemRng);
        for (id, sh) in ids.iter().zip(&shares) {
            assert!(verify(id, sh, 2, &vs));
            assert!(!verify(id, &sh.add(&Scalar::ONE), 2, &vs));
        }
        // Any 3 shares interpolate to the secret.
        let xs: Vec<Scalar> = ids[1..].iter().map(|i| id_scalar(i)).collect();
        let mut acc = Scalar::ZERO;
        for (x, sh) in xs.iter().zip(&shares[1..]) {
            let l = super::super::suite::lagrange_coefficient(x, &xs).unwrap();
            acc = acc.add(&l.mul(sh));
        }
        assert!(bool::from(acc.ct_eq(&secret)));
    }

    #[test]
    fn check_indexes_rejects_bad_committees() {
        assert!(check_indexes(0, &ids(3)).is_err());
        assert!(check_old_committee(0, &ids(1)).is_ok());
        assert!(check_old_committee(0, &[]).is_err());
        assert!(check_indexes(3, &ids(3)).is_err());
        assert!(check_indexes(1, &[vec![0], vec![1]]).is_err());
        let n_plus_1 =
            hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142")
                .unwrap();
        assert!(check_indexes(1, &[vec![1], n_plus_1]).is_err());
    }

    #[test]
    fn pok_roundtrip_and_binding() {
        let x = random_scalar(&mut SystemRng);
        let xp = mul_base(&x);
        let pf = ZkProof::prove(b"session", &x, &xp, &mut SystemRng);
        let (r, t) = pf.to_wire();
        let back = ZkProof::from_wire(&r, &t).unwrap();
        assert!(back.verify(b"session", &xp));
        assert!(!back.verify(b"other", &xp));
        assert!(!back.verify(b"session", &mul_base(&Scalar::ONE)));
    }

    #[test]
    fn element_commitment_opens_only_unmodified() {
        let els: Vec<Point> = (1u8..=3).map(|i| mul_base(&id_scalar(&[i]))).collect();
        let enc: Vec<Vec<u8>> = els
            .iter()
            .map(|e| encode_point(e).unwrap().to_vec())
            .collect();
        let (c, r) = commit_elements(&mut SystemRng, &els);
        assert!(open_elements(&c, &r, &enc, 3).is_some());
        assert!(open_elements(&c, &r, &enc, 2).is_none());
        let mut swapped = enc.clone();
        swapped.swap(0, 1);
        assert!(open_elements(&c, &r, &swapped, 3).is_none());
        let mut r2 = r;
        r2[0] ^= 1;
        assert!(open_elements(&c, &r2, &enc, 3).is_none());
    }
}
