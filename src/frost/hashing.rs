//! Byte-exact ports of the tss-lib `common` hash helpers used by the Schnorr
//! proof-of-knowledge challenge. Reproduced precisely so a PoK produced by the
//! Go library verifies here and vice versa.

use purecrypto::hash::sha512_256;

const DELIMITER: u8 = b'$';

/// Port of Go `common.SHA512_256(in...)`: a length-prefixed, delimited SHA-512/256
/// over the concatenation of `parts`.
///
/// Layout: `LE64(len(parts))` then, for each part, `part || '$' || LE64(len(part))`.
pub fn sha512_256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(&(parts.len() as u64).to_le_bytes());
    for p in parts {
        data.extend_from_slice(p);
        data.push(DELIMITER);
        data.extend_from_slice(&(p.len() as u64).to_le_bytes());
    }
    sha512_256(&data)
}

/// Port of Go `common.SHA512_256i_TAGGED(tag, in...)`: the tagged big-integer
/// hash used as the Schnorr challenge input. `operands` are the big-endian
/// magnitudes of non-negative integers (the affine point coordinates), in order.
///
/// Layout: `H = SHA512_256(tag)`; then SHA-512/256 over
/// `H || H || LE64(n) || (signbyte=0 || op || '$' || LE64(len(op)))*`.
/// Returns the 32-byte digest (big-endian integer).
pub fn sha512_256i_tagged(tag: &[u8], operands: &[&[u8]]) -> [u8; 32] {
    let tag_bz = sha512_256_parts(&[tag]);
    // state.write(tag_bz); state.write(tag_bz); state.write(operands_data)
    let data = operands_data(operands);
    let mut input = Vec::with_capacity(64 + data.len());
    input.extend_from_slice(&tag_bz);
    input.extend_from_slice(&tag_bz);
    input.extend_from_slice(&data);
    sha512_256(&input)
}

/// Port of Go `common.SHA512_256i(in...)`: the untagged big-integer hash used by
/// the hash-commitment scheme. `operands` are big-endian magnitudes of
/// non-negative integers. Returns the 32-byte digest (big-endian integer).
pub fn sha512_256i(operands: &[&[u8]]) -> [u8; 32] {
    sha512_256(&operands_data(operands))
}

/// The big-integer-list framing shared by `SHA512_256i` and its tagged variant:
/// `LE64(n) || (signbyte=0 || op || '$' || LE64(len(op)))*`.
fn operands_data(operands: &[&[u8]]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&(operands.len() as u64).to_le_bytes());
    for op in operands {
        data.push(0x00); // sign byte: all operands are non-negative
        data.extend_from_slice(op);
        data.push(DELIMITER);
        data.extend_from_slice(&(op.len() as u64).to_le_bytes());
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let a = sha512_256i_tagged(b"tag", &[&[1, 2, 3], &[4, 5]]);
        let b = sha512_256i_tagged(b"tag", &[&[1, 2, 3], &[4, 5]]);
        assert_eq!(a, b);
    }

    #[test]
    fn tag_and_operands_matter() {
        let base = sha512_256i_tagged(b"tag", &[&[1]]);
        assert_ne!(base, sha512_256i_tagged(b"other", &[&[1]]));
        assert_ne!(base, sha512_256i_tagged(b"tag", &[&[2]]));
        // Length-framing distinguishes split points.
        assert_ne!(
            sha512_256i_tagged(b"tag", &[&[1, 2], &[3]]),
            sha512_256i_tagged(b"tag", &[&[1], &[2, 3]])
        );
    }
}
