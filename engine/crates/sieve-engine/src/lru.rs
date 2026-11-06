//! Least recently used, for what is bounded by count (the leaf cache, the
//! upstream verdict cache). `used` orders the keys by the tick of their last
//! use, so the oldest is its first entry.

use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

pub struct Lru<K, V> {
    capacity: usize,
    tick: u64,
    items: HashMap<K, (V, u64)>,
    used: BTreeMap<u64, K>,
}

impl<K: Eq + Hash + Clone, V: Clone> Lru<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self { capacity, tick: 0, items: HashMap::new(), used: BTreeMap::new() }
    }

    fn touch(&mut self, key: K, old_tick: u64) -> u64 {
        self.used.remove(&old_tick);
        self.tick += 1;
        self.used.insert(self.tick, key);
        self.tick
    }

    /// The value for `key` that `accept` takes, marked as just used.
    pub fn get<Q>(&mut self, key: &Q, accept: impl Fn(&V) -> bool) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ToOwned<Owned = K> + ?Sized,
    {
        let (value, old_tick) = self.items.get(key).map(|(v, t)| (v.clone(), *t))?;
        if !accept(&value) {
            return None;
        }
        let tick = self.touch(key.to_owned(), old_tick);
        self.items.insert(key.to_owned(), (value.clone(), tick));
        Some(value)
    }

    pub fn insert(&mut self, key: K, value: V) {
        let old_tick = self.items.get(&key).map_or(0, |(_, t)| *t);
        let tick = self.touch(key.clone(), old_tick);
        self.items.insert(key, (value, tick));
        while self.items.len() > self.capacity {
            let Some((_, oldest)) = self.used.pop_first() else { return };
            self.items.remove(&oldest);
        }
    }

    pub fn remove<Q>(&mut self, key: &Q)
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        if let Some((_, tick)) = self.items.remove(key) {
            self.used.remove(&tick);
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Both sides of the index, for a test of its bookkeeping.
    #[cfg(test)]
    pub fn index_len(&self) -> usize {
        self.used.len()
    }
}
