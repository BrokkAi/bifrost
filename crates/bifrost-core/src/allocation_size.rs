//! Allocation sizing for evictable retention caches.
use std::sync::OnceLock;

static ESTIMATOR: OnceLock<fn(usize) -> usize> = OnceLock::new();

/// Install the estimator for the process's global allocator before budgets open.
/// Only the executable declaring that allocator may call this function.
pub fn install_allocation_estimator(estimator: fn(usize) -> usize) {
    assert!(
        ESTIMATOR.set(estimator).is_ok(),
        "allocation estimator installed twice"
    );
}

/// Allocated payload allowance for one owned allocation, excluding inline data.
pub fn allocation_size(bytes: usize) -> usize {
    if bytes == 0 {
        return 0;
    }
    ESTIMATOR.get().map_or_else(
        || fallback_allocation_size(bytes),
        |estimate| {
            let allocated = estimate(bytes);
            // nallocx returns zero when no size class can represent the request.
            if allocated == 0 {
                usize::MAX
            } else {
                allocated
            }
        },
    )
}

/// Conservative fallback for executables that do not select an allocator.
/// Its coverage is checked against a counting System allocator in tests.
pub fn fallback_allocation_size(bytes: usize) -> usize {
    if bytes == 0 {
        return 0;
    }
    bytes.saturating_add(bytes.div_ceil(4).max(32))
}

#[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
#[doc(hidden)]
pub mod counting;
