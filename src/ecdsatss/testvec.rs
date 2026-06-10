//! Loader for the Go-generated GG18 test vectors (`testdata/gg18.json`).
//!
//! Regenerate with `cd fixtures-gen && go run . > ../src/ecdsatss/testdata/gg18.json`.
//! Big integers are decimal strings in the fixture.

use super::bn;
use crate::tss::bigint::decimal_to_be;
use purecrypto::bignum::BoxedUint;
use serde_json::Value;

const FIXTURE: &str = include_str!("testdata/gg18.json");

/// The parsed fixture root object.
pub(crate) fn fixtures() -> Value {
    serde_json::from_str(FIXTURE).expect("gg18.json parses")
}

/// Parse a decimal-string big integer from the fixture into a `BoxedUint`.
pub(crate) fn dec(v: &Value) -> BoxedUint {
    let s = v.as_str().expect("decimal string");
    bn::from_be(&decimal_to_be(s).expect("valid decimal"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bn_gcd_matches_go() {
        let f = fixtures();
        for v in f["bn"]["gcd"].as_array().unwrap() {
            let a = dec(&v["a"]);
            let b = dec(&v["b"]);
            let g = dec(&v["g"]);
            assert_eq!(bn::to_be(&bn::gcd(&a, &b)), bn::to_be(&g));
        }
    }

    #[test]
    fn bn_jacobi_matches_go() {
        let f = fixtures();
        for v in f["bn"]["jacobi"].as_array().unwrap() {
            let a = dec(&v["a"]);
            let n = dec(&v["n"]);
            let j = v["j"].as_i64().unwrap() as i32;
            assert_eq!(bn::jacobi(&a, &n), j, "jacobi mismatch");
        }
    }
}
