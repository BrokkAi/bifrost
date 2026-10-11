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
