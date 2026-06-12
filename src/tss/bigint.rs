//! Go `big.Int`-compatible JSON encoding.
//!
//! Go's `encoding/json` renders a `*big.Int` as a bare decimal JSON *number*
//! (e.g. `7237005577332262213973186563042994240857116359379907606001950938285454250989`),
//! not a string. The save formats this crate must interoperate with embed such
//! values (Shamir shares, participant identifiers, affine point coordinates), so
//! we reproduce that encoding exactly.
//!
//! [`BigUintDec`] holds a non-negative integer as its big-endian magnitude and
//! (de)serializes as a bare decimal number. It relies on serde_json's
//! `arbitrary_precision` feature so values beyond `2^53` round-trip losslessly.
//!
//! All values exchanged by these protocols are non-negative; a leading `-` on
//! input is rejected.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A non-negative big integer that (de)serializes as a bare decimal JSON number,
/// matching Go's `encoding/json` treatment of `*big.Int`.
///
/// The stored bytes are the big-endian magnitude with leading zeros stripped
/// (an empty vector denotes zero), mirroring Go's `big.Int.Bytes()`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BigUintDec(pub Vec<u8>);

impl BigUintDec {
    /// Wraps a big-endian magnitude, stripping leading zeros.
    pub fn from_be_bytes(be: &[u8]) -> Self {
        BigUintDec(strip_leading_zeros(be).to_vec())
    }

    /// Returns the big-endian magnitude (no leading zeros; empty for zero).
    pub fn as_be_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the big-endian magnitude left-padded (or truncated from the left)
    /// to exactly `n` bytes. Used to recover fixed-width encodings such as a
    /// 32-byte field coordinate.
    pub fn to_be_bytes_padded(&self, n: usize) -> Vec<u8> {
        let b = strip_leading_zeros(&self.0);
        if b.len() >= n {
            b[b.len() - n..].to_vec()
        } else {
            let mut out = vec![0u8; n];
            out[n - b.len()..].copy_from_slice(b);
            out
        }
    }
}

/// Converts a big-endian magnitude to its decimal string (`"0"` for zero).
pub fn be_to_decimal(be: &[u8]) -> String {
    let be = strip_leading_zeros(be);
    if be.is_empty() {
        return "0".to_string();
    }
    // Accumulate decimal digits little-endian: digits = digits * 256 + byte.
    let mut digits: Vec<u8> = vec![0];
    for &byte in be {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            let v = (*d as u32) * 256 + carry;
            *d = (v % 10) as u8;
            carry = v / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

/// Maximum number of decimal digits accepted by [`decimal_to_be`].
///
/// The base conversion below is O(n²) in the digit count, and the input comes
/// straight from attacker-controllable save-data JSON (serde_json's
/// `arbitrary_precision` feature preserves the full digit string), so an
/// unbounded input is a denial-of-service vector. The largest legitimate
/// values stored as [`BigUintDec`] anywhere in this crate are the 2048-bit
/// Paillier modulus `N` and its `lambda`/`phi` in the GG18 ecdsatss save data
/// (≈617 decimal digits; see `ecdsatss::key`), with the safe-prime `Ntilde`
/// preparams the same size. 8192 digits (≈27k bits) is more than 13× that —
/// and still over 4× a hypothetical 4096-bit modulus (≈1234 digits) — so no
/// real save data is ever rejected, while a multi-megabyte digit string is
/// refused in O(1).
pub const MAX_DECIMAL_DIGITS: usize = 8192;

/// Parses a non-negative decimal string into its big-endian magnitude (no
/// leading zeros; empty for zero). Returns an error on empty input, a leading
/// `-`, any non-digit character, or input longer than [`MAX_DECIMAL_DIGITS`].
pub fn decimal_to_be(s: &str) -> Result<Vec<u8>, DecimalError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(DecimalError("empty decimal string"));
    }
    if s.starts_with('-') {
        return Err(DecimalError("negative values are not supported"));
    }
    if s.len() > MAX_DECIMAL_DIGITS {
        return Err(DecimalError("decimal string too long"));
    }
    // Accumulate big-endian base-256: bytes = bytes * 10 + digit.
    let mut bytes: Vec<u8> = vec![0];
    for ch in s.chars() {
        let digit = ch.to_digit(10).ok_or(DecimalError("non-digit character"))?;
        let mut carry = digit;
        for b in bytes.iter_mut().rev() {
            let v = (*b as u32) * 10 + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    Ok(strip_leading_zeros(&bytes).to_vec())
}

/// Error parsing a decimal string into a [`BigUintDec`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecimalError(&'static str);

impl std::fmt::Display for DecimalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid decimal integer: {}", self.0)
    }
}

impl std::error::Error for DecimalError {}

fn strip_leading_zeros(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

impl Serialize for BigUintDec {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Build an arbitrary-precision JSON number from the decimal string; it
        // serializes verbatim as a bare number token under serde_json.
        let num = serde_json::Number::from_string_unchecked(be_to_decimal(&self.0));
        num.serialize(s)
    }
}

impl<'de> Deserialize<'de> for BigUintDec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let num = serde_json::Number::deserialize(d)?;
        let be = decimal_to_be(num.as_str()).map_err(D::Error::custom)?;
        Ok(BigUintDec(be))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_roundtrip_small() {
        for n in [0u64, 1, 9, 10, 255, 256, 65535, 1_000_000, u64::MAX] {
            let be = n.to_be_bytes();
            let dec = be_to_decimal(&be);
            assert_eq!(dec, n.to_string());
            let back = decimal_to_be(&dec).unwrap();
            assert_eq!(BigUintDec(back), BigUintDec::from_be_bytes(&be));
        }
    }

    #[test]
    fn decimal_large_beyond_u64() {
        // Ed25519 group order L.
        let l = "7237005577332262213973186563042994240857116359379907606001950938285454250989";
        let be = decimal_to_be(l).unwrap();
        assert_eq!(be_to_decimal(&be), l);
    }

    #[test]
    fn zero_is_canonical() {
        assert_eq!(be_to_decimal(&[]), "0");
        assert_eq!(be_to_decimal(&[0, 0, 0]), "0");
        assert_eq!(decimal_to_be("0").unwrap(), Vec::<u8>::new());
        assert_eq!(BigUintDec::from_be_bytes(&[0, 0, 5]).0, vec![5]);
    }

    #[test]
    fn json_is_a_bare_number() {
        let v = BigUintDec::from_be_bytes(&123456789u64.to_be_bytes());
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, "123456789");
        let back: BigUintDec = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn json_large_number_lossless() {
        let l = "7237005577332262213973186563042994240857116359379907606001950938285454250989";
        let v = BigUintDec(decimal_to_be(l).unwrap());
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, l);
        let back: BigUintDec = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn padded_width() {
        let v = BigUintDec::from_be_bytes(&[0xab, 0xcd]);
        assert_eq!(v.to_be_bytes_padded(4), vec![0, 0, 0xab, 0xcd]);
        assert_eq!(v.to_be_bytes_padded(2), vec![0xab, 0xcd]);
        assert_eq!(v.to_be_bytes_padded(1), vec![0xcd]);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(decimal_to_be("").is_err());
        assert!(decimal_to_be("-5").is_err());
        assert!(decimal_to_be("12a3").is_err());
    }

    #[test]
    fn rejects_oversized_decimal_but_accepts_paillier_sized() {
        // Just over the cap: rejected as an error (no panic, no O(n²) work).
        let too_long = "9".repeat(MAX_DECIMAL_DIGITS + 1);
        assert_eq!(
            decimal_to_be(&too_long),
            Err(DecimalError("decimal string too long"))
        );
        // Same via serde: a huge bare JSON number must fail deserialization.
        let json = format!("{{\"v\": {too_long}}}");
        #[derive(Deserialize)]
        struct Wrap {
            #[allow(dead_code)]
            v: BigUintDec,
        }
        assert!(serde_json::from_str::<Wrap>(&json).is_err());

        // A 617-digit value (the size of a 2048-bit Paillier modulus, the
        // largest legitimate BigUintDec in any save format) still parses and
        // round-trips unchanged.
        let mut paillier_sized = String::from("9");
        paillier_sized.push_str(&"7".repeat(616));
        assert_eq!(paillier_sized.len(), 617);
        let be = decimal_to_be(&paillier_sized).unwrap();
        assert_eq!(be_to_decimal(&be), paillier_sized);

        // Exactly at the cap is still accepted.
        let at_cap = "1".repeat(MAX_DECIMAL_DIGITS);
        assert!(decimal_to_be(&at_cap).is_ok());
    }
}
