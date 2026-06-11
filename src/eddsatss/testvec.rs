//! Test-vector loader for the Go-generated `eddsa.json` fixtures.

use serde_json::Value;

/// The parsed `eddsa.json` fixture document.
pub(crate) fn fixtures() -> Value {
    let raw = include_str!("testdata/eddsa.json");
    serde_json::from_str(raw).expect("valid eddsa.json fixture")
}

#[cfg(test)]
mod tests {
    use super::super::key::Key;
    use super::fixtures;

    #[test]
    fn go_keys_load_and_round_trip() {
        let f = fixtures();
        let keys: Vec<Key> = f["signing_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| serde_json::from_value(v.clone()).expect("load Go eddsatss key"))
            .collect();
        assert_eq!(keys.len(), 2);

        for k in &keys {
            k.validate_basic().unwrap();
            assert_eq!(k.ks.len(), 2);
            assert_eq!(k.eddsa_pub.curve, "ed25519");
        }
        // Both parties agree on the group public key.
        assert_eq!(keys[0].eddsa_pub.coords, keys[1].eddsa_pub.coords);

        // Re-serialize and reparse: values preserved.
        let json = keys[0].to_json().unwrap();
        let k2 = Key::from_json(&json).unwrap();
        assert_eq!(k2.xi, keys[0].xi);
        assert_eq!(k2.ks, keys[0].ks);
        assert_eq!(k2.big_xj[1].coords, keys[0].big_xj[1].coords);

        // Points decode on-curve; BigXj[i] = Xi_i · G is checked end-to-end in
        // the signing test. Here we just confirm the public key is recoverable.
        assert!(keys[0].eddsa_pub_point().is_some());
    }
}
