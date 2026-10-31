//! A sorted-`Vec` map for the small per-party maps the protocols keep.
//!
//! These maps hold one entry per committee member, so a `BTreeMap` buys
//! nothing at run time and costs a node layout, iterator machinery and (for
//! `collect`) a stable sort per key/value type. Lookups binary-search; inserts
//! shift, which is O(n) but n is a party count. Iteration is in key order,
//! like `BTreeMap`.

use crate::prelude::*;
use core::borrow::Borrow;

pub(crate) struct VecMap<K, V> {
    entries: Vec<(K, V)>,
}

impl<K: Ord, V> VecMap<K, V> {
    pub(crate) const fn new() -> Self {
        VecMap {
            entries: Vec::new(),
        }
    }

    fn find<Q: Ord + ?Sized>(&self, key: &Q) -> Result<usize, usize>
    where
        K: Borrow<Q>,
    {
        self.entries.binary_search_by(|(k, _)| k.borrow().cmp(key))
    }

    /// Inserts `value`, returning the value it replaced, if any.
    pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V> {
        match self.find(&key) {
            Ok(i) => Some(core::mem::replace(&mut self.entries[i].1, value)),
            Err(i) => {
                self.entries.insert(i, (key, value));
                None
            }
        }
    }

    /// Builds a map from entries in arbitrary order in O(n log n), with the
    /// same result as inserting them one by one: for a duplicate key the
    /// first key is kept and the last value wins.
    fn from_unsorted(mut entries: Vec<(K, V)>) -> Self {
        // Stable, so equal keys stay in arrival order for the merge below.
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut out: Vec<(K, V)> = Vec::with_capacity(entries.len());
        for (k, v) in entries {
            match out.last_mut() {
                Some(last) if last.0 == k => last.1 = v,
                _ => out.push((k, v)),
            }
        }
        VecMap { entries: out }
    }

    pub(crate) fn get<Q: Ord + ?Sized>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
    {
        self.find(key).ok().map(|i| &self.entries[i].1)
    }

    pub(crate) fn contains_key<Q: Ord + ?Sized>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
    {
        self.find(key).is_ok()
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter().map(|(_, v)| v)
    }

    pub(crate) fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.entries.iter_mut().map(|(_, v)| v)
    }
}

/// Panics if `key` is absent, like `BTreeMap`'s `Index`.
impl<K: Ord + Borrow<Q>, Q: Ord + ?Sized, V> core::ops::Index<&Q> for VecMap<K, V> {
    type Output = V;

    fn index(&self, key: &Q) -> &V {
        self.get(key).expect("key not in VecMap")
    }
}

impl<K: Ord, V> Default for VecMap<K, V> {
    fn default() -> Self {
        VecMap::new()
    }
}

impl<K: Clone, V: Clone> Clone for VecMap<K, V> {
    fn clone(&self) -> Self {
        VecMap {
            entries: self.entries.clone(),
        }
    }
}

impl<K: core::fmt::Debug, V: core::fmt::Debug> core::fmt::Debug for VecMap<K, V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_map()
            .entries(self.entries.iter().map(|(k, v)| (k, v)))
            .finish()
    }
}

/// Builds by repeated insertion (later duplicates win, as with `BTreeMap`),
/// which avoids instantiating a sort for each key/value type.
impl<K: Ord, V> FromIterator<(K, V)> for VecMap<K, V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut m = VecMap::new();
        for (k, v) in iter {
            m.insert(k, v);
        }
        m
    }
}

impl<K, V> IntoIterator for VecMap<K, V> {
    type Item = (K, V);
    type IntoIter = alloc::vec::IntoIter<(K, V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<'a, K, V> IntoIterator for &'a VecMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter =
        core::iter::Map<core::slice::Iter<'a, (K, V)>, fn(&'a (K, V)) -> (&'a K, &'a V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter().map(|(k, v)| (k, v))
    }
}

impl<K: serde::Serialize, V: serde::Serialize> serde::Serialize for VecMap<K, V> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_map(self.entries.iter().map(|(k, v)| (k, v)))
    }
}

impl<'de, K, V> serde::Deserialize<'de> for VecMap<K, V>
where
    K: Ord + serde::Deserialize<'de>,
    V: serde::Deserialize<'de>,
{
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor<K, V>(core::marker::PhantomData<(K, V)>);

        impl<'de, K, V> serde::de::Visitor<'de> for Visitor<K, V>
        where
            K: Ord + serde::Deserialize<'de>,
            V: serde::Deserialize<'de>,
        {
            type Value = VecMap<K, V>;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a map")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Self::Value, A::Error> {
                // Entries come from peers in any order; inserting one by one
                // would shift the tail each time (O(n²) for descending keys),
                // so collect, sort once and merge duplicates.
                let mut entries = Vec::new();
                while let Some(kv) = a.next_entry()? {
                    entries.push(kv);
                }
                Ok(VecMap::from_unsorted(entries))
            }
        }

        d.deserialize_map(Visitor(core::marker::PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behaves_like_a_sorted_map() {
        let mut m = VecMap::new();
        assert_eq!(m.insert("b".to_string(), 2), None);
        assert_eq!(m.insert("a".to_string(), 1), None);
        assert_eq!(m.insert("c".to_string(), 3), None);
        assert_eq!(m.insert("b".to_string(), 20), Some(2));
        assert_eq!(m.len(), 3);
        assert_eq!(m.get("b"), Some(&20));
        assert!(m.contains_key("a") && !m.contains_key("z"));
        assert_eq!(m["c"], 3);
        let keys: Vec<&str> = (&m).into_iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["a", "b", "c"]);
        m.values_mut().for_each(|v| *v += 1);
        assert_eq!(m.values().copied().collect::<Vec<_>>(), [2, 21, 4]);
        m.clear();
        assert!(m.is_empty());
    }

    /// Compares by the first field only, so we can see which of two equal
    /// keys is kept.
    #[derive(Debug, Clone, Copy)]
    struct Tagged(u32, u32);
    impl PartialEq for Tagged {
        fn eq(&self, o: &Self) -> bool {
            self.0 == o.0
        }
    }
    impl Eq for Tagged {}
    impl PartialOrd for Tagged {
        fn partial_cmp(&self, o: &Self) -> Option<core::cmp::Ordering> {
            Some(self.cmp(o))
        }
    }
    impl Ord for Tagged {
        fn cmp(&self, o: &Self) -> core::cmp::Ordering {
            self.0.cmp(&o.0)
        }
    }

    #[test]
    fn from_unsorted_matches_repeated_insert() {
        // Descending keys, each appearing about twice.
        let input: Vec<(Tagged, u32)> = (0..200u32)
            .map(|i| (Tagged(100 - (i % 101), i), i))
            .collect();
        let mut by_insert = VecMap::new();
        for &(k, v) in &input {
            by_insert.insert(k, v);
        }
        let sorted = VecMap::from_unsorted(input);
        let a: Vec<_> = by_insert.into_iter().map(|(k, v)| (k.0, k.1, v)).collect();
        let b: Vec<_> = sorted.into_iter().map(|(k, v)| (k.0, k.1, v)).collect();
        assert_eq!(a, b);
        assert_eq!(a.len(), 101);
    }

    #[test]
    fn wire_decode_unordered_with_duplicates() {
        // Map encoding = count, then (key, value) pairs: same as a Vec of tuples.
        let bytes =
            crate::wire::to_vec(&vec![(3u32, 1u8), (1, 2), (2, 3), (1, 4), (3, 5)]).unwrap();
        let m: VecMap<u32, u8> = crate::wire::from_slice(&bytes).unwrap();
        assert_eq!(m.into_iter().collect::<Vec<_>>(), [(1, 4), (2, 3), (3, 5)]);
    }

    #[cfg(feature = "json")]
    #[test]
    fn json_decode_unordered_keeps_last_duplicate() {
        let m: VecMap<String, u8> =
            serde_json::from_str(r#"{"c":1,"b":2,"a":3,"b":4,"c":5}"#).unwrap();
        let pairs: Vec<(String, u8)> = m.into_iter().collect();
        assert_eq!(pairs, [("a".into(), 3), ("b".into(), 4), ("c".into(), 5)]);
    }

    #[test]
    fn wire_decode_many_descending_keys_is_not_quadratic() {
        // Quadratic insertion of 100k descending keys took tens of seconds
        // in debug builds; the sort-based decoder takes a few milliseconds.
        const N: u32 = 100_000;
        let desc: Vec<(u32, ())> = (0..N).rev().map(|k| (k, ())).collect();
        let bytes = crate::wire::to_vec(&desc).unwrap();
        let t = std::time::Instant::now();
        let m: VecMap<u32, ()> = crate::wire::from_slice(&bytes).unwrap();
        assert!(t.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(m.len(), N as usize);
        assert!(m.into_iter().map(|(k, _)| k).eq(0..N));
    }

    #[cfg(feature = "json")]
    #[test]
    fn collect_keeps_last_duplicate_and_serde_round_trips() {
        let m: VecMap<u8, u8> = [(3, 30), (1, 10), (3, 31)].into_iter().collect();
        let pairs: Vec<(u8, u8)> = (&m).into_iter().map(|(k, v)| (*k, *v)).collect();
        assert_eq!(pairs, [(1, 10), (3, 31)]);
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, r#"{"1":10,"3":31}"#);
        let back: VecMap<u8, u8> = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.into_iter().collect::<Vec<_>>(),
            m.into_iter().collect::<Vec<_>>()
        );
    }
}
