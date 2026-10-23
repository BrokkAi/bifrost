#[cfg(test)]
use git2::Oid;

use super::*;

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct JavaInteriorSnapshot {
    #[doc(hidden)]
    pub blob_oid: Oid,
    #[doc(hidden)]
    pub interior_digest: [u8; 32],
    #[doc(hidden)]
    pub semantic_sites: u64,
    #[doc(hidden)]
    pub path_endpoint_headers: u64,
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod rust_root_test_support {
    use super::*;

    use std::sync::Arc;

    use std::sync::atomic::AtomicUsize;

    use std::sync::atomic::Ordering;

    #[doc(hidden)]
    pub fn parse_progress_counter() -> (Arc<AtomicUsize>, BuildProgress) {
        let count = Arc::new(AtomicUsize::new(0));
        let progress_count = Arc::clone(&count);
        let progress: BuildProgress = Arc::new(move |event| {
            if event.phase == BuildProgressPhase::Parse {
                progress_count.fetch_add(1, Ordering::Relaxed);
            }
        });
        (count, progress)
    }
}
