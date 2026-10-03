//! Fast hash collections for repository-local analysis data.
//!
//! Bifrost analyzes trusted local repositories, not attacker-controlled request
//! keys, so the standard library's SipHash-based default is the wrong tradeoff
//! for hot analyzer indexes. Use these aliases for internal maps and sets.
//! Hash iteration order is intentionally unspecified; deterministic output must
//! be produced with `BTree*` collections or explicit sorting at boundaries.

#[cfg(not(feature = "randomized-hash"))]
pub type HashMap<K, V> = std::collections::HashMap<K, V, rustc_hash::FxBuildHasher>;
#[cfg(feature = "randomized-hash")]
pub type HashMap<K, V> = std::collections::HashMap<K, V>;

#[cfg(not(feature = "randomized-hash"))]
pub type HashSet<T> = std::collections::HashSet<T, rustc_hash::FxBuildHasher>;
#[cfg(feature = "randomized-hash")]
pub type HashSet<T> = std::collections::HashSet<T>;

pub fn map_with_capacity<K, V>(capacity: usize) -> HashMap<K, V> {
    HashMap::with_capacity_and_hasher(capacity, Default::default())
}

pub fn set_with_capacity<T>(capacity: usize) -> HashSet<T> {
    HashSet::with_capacity_and_hasher(capacity, Default::default())
}

/// The bytes one hash table's allocated slots occupy.
///
/// A table keeps the capacity it grew to, so a retained-byte estimate has to
/// charge slots and not live entries. The table stores one control byte per
/// slot beside the key and value.
pub fn map_slot_bytes<K, V, S>(map: &std::collections::HashMap<K, V, S>) -> usize {
    map.capacity().saturating_mul(
        size_of::<K>()
            .saturating_add(size_of::<V>())
            .saturating_add(1),
    )
}

/// The same for a set.
pub fn set_slot_bytes<T, S>(set: &std::collections::HashSet<T, S>) -> usize {
    set.capacity()
        .saturating_mul(size_of::<T>().saturating_add(1))
}

/// The same for a table of lists, adding each list's own allocation.
pub fn map_of_vec_slot_bytes<K, V, S>(map: &std::collections::HashMap<K, Vec<V>, S>) -> usize {
    map.values()
        .map(|values| vec_slot_bytes(values))
        .fold(map_slot_bytes(map), usize::saturating_add)
}

/// The bytes one vector's allocated slots occupy. This needs the vector and
/// not a slice: a slice cannot report the allocation behind it.
#[allow(clippy::ptr_arg)]
pub fn vec_slot_bytes<T>(values: &Vec<T>) -> usize {
    values.capacity().saturating_mul(size_of::<T>())
}

/// The bytes one ordered map's nodes occupy. A B-tree node holds up to eleven
/// entries plus its own links, so this charges one entry and one link each.
pub fn btree_map_slot_bytes<K, V>(map: &std::collections::BTreeMap<K, V>) -> usize {
    map.len().saturating_mul(
        size_of::<K>()
            .saturating_add(size_of::<V>())
            .saturating_add(size_of::<usize>()),
    )
}
