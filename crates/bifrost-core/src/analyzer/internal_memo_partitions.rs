//! Internal partition capture for memo read attribution.
//!
//! A partition is an unmodified backend receipt, not another journal. Only
//! memo selection and its attribution backend use this seam. Semantic keys,
//! source observations and request provenance remain owned by that backend.
use super::project_reads::{ErasedCapturedReads, ReadCapability};

/// Implemented by the existing attribution backend, using its deferred scope.
/// This is separate from authority capture: partitioning grants no authority.
#[doc(hidden)]
pub trait DeferredMemoAttribution: Send + Sync {
    /// Run once without forwarding into the immediate enclosing capture.
    /// The memo must forward all executed partitions exactly once, including
    /// unsuccessful builds. `forwarded_to` retains its backend meaning.
    /// Typed completion continues to route during the computation, separately
    /// from deferred channel marks, so failures still abort the same walk.
    fn capture_deferred(&self, build: &mut dyn FnMut()) -> ErasedCapturedReads;
}

/// Capture one direct memo partition without interpreting its opaque payload.
#[doc(hidden)]
pub fn capture<T>(
    capability: &ReadCapability,
    build: impl FnOnce() -> T,
) -> (T, ErasedCapturedReads) {
    let mut build = Some(build);
    let mut value = None;
    let reads = capability.0.capture_deferred(&mut || {
        value = Some(build.take().expect("one deferred memo build")());
    });
    (value.expect("deferred memo capture ran its build"), reads)
}

/// Build a transient selection recipe from immutable backend leaves. Equal
/// keys or channels do not establish equal proofs: only leaf identity dedups.
/// This neither forwards reads nor certifies that any capture forwarded them.
#[doc(hidden)]
pub fn recipe<'a>(
    partitions: impl IntoIterator<Item = &'a ErasedCapturedReads>,
) -> super::memo_attribution::CapturedMemoReads<super::project_reads::OpaqueReadReceipt> {
    use super::memo_attribution::{CapturedMemoReads, ReadChannels};
    let mut seen = crate::hash::HashSet::default();
    let mut keys = Vec::new();
    let mut channels = ReadChannels::default();
    let mut first_refusal = None;
    let mut first_execution_refusal = None;
    for partition in partitions {
        if !seen.insert(partition.receipt.allocation_identity()) {
            continue;
        }
        keys.push(partition.receipt.clone());
        let source = partition.channels;
        channels.unattributed_reads = channels
            .unattributed_reads
            .saturating_add(source.unattributed_reads);
        channels.execution_dependences = channels
            .execution_dependences
            .saturating_add(source.execution_dependences);
        channels.budget_dependences = channels
            .budget_dependences
            .saturating_add(source.budget_dependences);
        channels.request_pinned_dependences = channels
            .request_pinned_dependences
            .saturating_add(source.request_pinned_dependences);
        channels.persistence_refusals = channels
            .persistence_refusals
            .saturating_add(source.persistence_refusals);
        channels.reuse_refused |= source.reuse_refused;
        channels.store_failed |= source.store_failed;
        channels.explicit_verdict.join_in(source.explicit_verdict);
        first_refusal = first_refusal.or_else(|| partition.first_refusal.clone());
        first_execution_refusal =
            first_execution_refusal.or_else(|| partition.first_execution_refusal.clone());
    }
    CapturedMemoReads {
        runtime_cache_touched: false,
        keys: keys.into(),
        channels,
        first_refusal,
        first_execution_refusal,
    }
}

/// Shared graph accounting counts a leaf's payload once, even if several
/// captured node headers refer to it. Selection recipes do not own new payloads.
#[doc(hidden)]
pub fn retained_bytes<'a>(
    partitions: impl IntoIterator<Item = &'a std::sync::Arc<ErasedCapturedReads>>,
) -> usize {
    use crate::allocation_size::allocation_size;
    use std::mem::size_of;
    let mut headers = crate::hash::HashSet::default();
    let mut leaves = crate::hash::HashSet::default();
    let mut bytes = 0usize;
    for partition in partitions {
        if headers.insert(std::sync::Arc::as_ptr(partition) as usize) {
            bytes += allocation_size(size_of::<ErasedCapturedReads>() + 2 * size_of::<usize>());
            for refusal in [&partition.first_refusal, &partition.first_execution_refusal]
                .into_iter()
                .flatten()
            {
                bytes += allocation_size(refusal.reason.capacity());
            }
        }
        if leaves.insert(partition.receipt.allocation_identity()) {
            bytes += partition.receipt.retained_bytes();
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::super::project_reads::OpaqueReadReceipt;
    use super::*;
    use std::sync::Arc;

    fn partition(receipt: OpaqueReadReceipt) -> Arc<ErasedCapturedReads> {
        Arc::new(ErasedCapturedReads {
            receipt,
            channels: super::super::memo_attribution::ReadChannels {
                unattributed_reads: 3,
                ..Default::default()
            },
            first_refusal: None,
            first_execution_refusal: None,
            forwarded_to: None,
        })
    }

    #[test]
    fn equal_keys_and_channels_do_not_deduplicate_distinct_proof_owners() {
        let first = partition(OpaqueReadReceipt::new(Arc::new(17u8), 5000));
        let same = partition(first.receipt.clone());
        let different = partition(OpaqueReadReceipt::new(Arc::new(17u8), 5000));
        let selected = recipe([
            first.as_ref(),
            same.as_ref(),
            different.as_ref(),
            first.as_ref(),
        ]);
        assert_eq!(selected.keys.len(), 2);
        assert_eq!(selected.channels.unattributed_reads, 6);
        let one = retained_bytes([&first]);
        assert_eq!(retained_bytes([&first, &first]), one);
        let shared = retained_bytes([&first, &same]);
        let separate = retained_bytes([&first, &different]);
        assert_eq!(
            separate - shared,
            5000,
            "two headers share one opaque payload only when its identity agrees"
        );
    }
}
