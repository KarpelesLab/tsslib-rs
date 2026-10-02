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
                let mut m = VecMap::new();
                while let Some((k, v)) = a.next_entry()? {
                    m.insert(k, v);
                }
                Ok(m)
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
