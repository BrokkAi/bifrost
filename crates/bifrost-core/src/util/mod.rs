use std::time::Instant;

use std::io;
use std::path::{Path, PathBuf};

/// Append an item only when it is absent, preserving insertion order.
pub fn push_if_absent<T: Eq>(items: &mut Vec<T>, item: T) {
    if !items.contains(&item) {
        items.push(item);
    }
}

pub fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Whether two half-open byte ranges overlap.
pub fn byte_ranges_overlap(
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
) -> bool {
    left_start < right_end && right_start < left_end
}

pub fn sorted_directory_entries(path: &Path) -> io::Result<Vec<PathBuf>> {
    let mut entries = std::fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    Ok(entries)
}

pub mod throttled_log;

#[cfg(test)]
mod interval_and_list_properties {
    use super::{byte_ranges_overlap, push_if_absent};
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    /// A non-empty half-open range `[start, end)`.
    fn range() -> impl Strategy<Value = (usize, usize)> {
        (0usize..14, 1usize..8).prop_map(|(start, length)| (start, start + length))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Two non-empty half-open ranges overlap exactly when they share a
        /// byte, so ranges that merely touch (one ends where the other begins)
        /// are disjoint. Empty ranges are covered by a separate test.
        #[test]
        fn overlap_means_sharing_a_byte(left in range(), right in range()) {
            let left_bytes: BTreeSet<usize> = (left.0..left.1).collect();
            let right_bytes: BTreeSet<usize> = (right.0..right.1).collect();
            let shares_a_byte = left_bytes.intersection(&right_bytes).next().is_some();
            prop_assert_eq!(byte_ranges_overlap(left.0, left.1, right.0, right.1), shares_a_byte);
            prop_assert_eq!(byte_ranges_overlap(right.0, right.1, left.0, left.1), shares_a_byte);
        }

        /// Pushing a sequence leaves the original contents (duplicates and all)
        /// in place, then adds each pushed item at its first occurrence only.
        #[test]
        fn push_if_absent_appends_first_occurrences_only(
            initial in proptest::collection::vec(0u8..8, 0..6),
            pushes in proptest::collection::vec(0u8..8, 0..16),
        ) {
            let mut items = initial.clone();
            for item in &pushes {
                push_if_absent(&mut items, *item);
            }

            let mut expected = initial.clone();
            for (index, item) in pushes.iter().enumerate() {
                let seen_before = initial.contains(item) || pushes[..index].contains(item);
                if !seen_before {
                    expected.push(*item);
                }
            }
            prop_assert_eq!(items, expected);
        }
    }
}
