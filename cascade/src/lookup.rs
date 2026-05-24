// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Generic key/action lookup primitive.
//!
//! See [`Lookup`].

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

use crate::projection::Projection;

/// A read-only lookup from `&K` to `Option<&A>`.
///
/// The trait stays two-state and agnostic to what `A` means. Richer
/// outcome semantics (tombstones, partial-then-trap-to-software,
/// hardware-offload-pending, ...) live in the choice of `A` — e.g.
/// `Lookup<K, Option<Action>>` for explicit tombstones, or
/// `Lookup<K, OffloadOutcome>` for richer enums. The trait does not
/// have to grow.
///
/// Both `K` and `A` are trait type parameters (not associated) so a
/// single backend can serve many `(K, A)` instantiations:
/// `impl<K: Ord, V> Lookup<K, V> for BTreeMap<K, V>` covers every
/// concrete `BTreeMap` instantiation at once.
pub trait Lookup<K, A> {
    /// Look up `key`.
    fn lookup(&self, key: &K) -> Option<&A>;

    /// Project `source` to a key of type `K`, then look it up.
    ///
    /// `K` and the matching [`Projection`] impl are picked by type
    /// inference from `self`'s `Lookup<K, A>` instantiation.
    fn classify<S>(&self, source: S) -> Option<&A>
    where
        S: Projection<K>,
    {
        self.lookup(&source.project())
    }
}

impl<K: Ord, V> Lookup<K, V> for BTreeMap<K, V> {
    fn lookup(&self, key: &K) -> Option<&V> {
        BTreeMap::get(self, key)
    }
}

impl<K: Eq + Hash, V, S: std::hash::BuildHasher> Lookup<K, V> for HashMap<K, V, S> {
    fn lookup(&self, key: &K) -> Option<&V> {
        HashMap::get(self, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Pkt {
        src: u32,
        dst: u32,
        sport: u16,
        dport: u16,
    }

    impl Projection<(u32, u32)> for &Pkt {
        fn project(self) -> (u32, u32) {
            (self.src, self.dst)
        }
    }

    impl Projection<(u32, u32, u16, u16)> for &Pkt {
        fn project(self) -> (u32, u32, u16, u16) {
            (self.src, self.dst, self.sport, self.dport)
        }
    }

    impl<'a> Projection<(&'a u32, &'a u32)> for &'a Pkt {
        fn project(self) -> (&'a u32, &'a u32) {
            (&self.src, &self.dst)
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Action {
        Allow,
        Drop,
    }

    #[test]
    fn classify_picks_the_two_tuple_projection_from_the_table_type() {
        let mut table: BTreeMap<(u32, u32), Action> = BTreeMap::new();
        table.insert((10, 20), Action::Drop);
        let pkt = Pkt {
            src: 10,
            dst: 20,
            sport: 22,
            dport: 80,
        };

        // K = (u32, u32) inferred from `table`'s type; matching
        // `Projection<(u32, u32)>` impl on `&Pkt` is selected.
        assert_eq!(table.classify(&pkt), Some(&Action::Drop));
    }

    #[test]
    fn classify_picks_the_four_tuple_projection_from_the_table_type() {
        let mut table: BTreeMap<(u32, u32, u16, u16), Action> = BTreeMap::new();
        table.insert((10, 20, 22, 80), Action::Allow);
        let pkt = Pkt {
            src: 10,
            dst: 20,
            sport: 22,
            dport: 80,
        };

        // Same source, different K, different `Projection` impl.
        assert_eq!(table.classify(&pkt), Some(&Action::Allow));
    }

    #[test]
    fn borrowed_tuple_projection_threads_lifetime() {
        let pkt = Pkt {
            src: 10,
            dst: 20,
            sport: 0,
            dport: 0,
        };
        // The lifetime of the returned refs is the lifetime of the
        // receiver `&pkt`; no extra annotations needed.
        let (src, dst): (&u32, &u32) = (&pkt).project();
        assert_eq!(*src, 10);
        assert_eq!(*dst, 20);
    }

    #[test]
    fn miss_returns_none() {
        let table: BTreeMap<(u32, u32), Action> = BTreeMap::new();
        let pkt = Pkt {
            src: 1,
            dst: 2,
            sport: 3,
            dport: 4,
        };
        assert_eq!(table.classify(&pkt), None);
    }

    #[test]
    fn hashmap_backend_works_the_same_way() {
        let mut table: HashMap<(u32, u32), Action> = HashMap::new();
        table.insert((10, 20), Action::Drop);
        let pkt = Pkt {
            src: 10,
            dst: 20,
            sport: 0,
            dport: 0,
        };
        assert_eq!(table.classify(&pkt), Some(&Action::Drop));
    }
}
