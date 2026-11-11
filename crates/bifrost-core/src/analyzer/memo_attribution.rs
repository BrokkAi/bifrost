//! Memo access requires an explicit read-attribution capability.
use std::ops::Deref;
use std::sync::Arc;
use std::sync::Mutex;

/// Identity of one capture, independent of allocator address reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureIdentity(pub u64);

#[derive(Debug)]
pub struct CapturedMemoReads<K> {
    /// Transient eligibility evidence; never part of a persisted receipt.
    pub runtime_cache_touched: bool,
    pub keys: Arc<[K]>,
    pub channels: ReadChannels,
    pub first_refusal: Option<crate::profiling::ReadRefusal>,
    pub first_execution_refusal: Option<crate::profiling::ReadRefusal>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadChannels {
    pub unattributed_reads: usize,
    pub execution_dependences: usize,
    /// How many of the execution dependences were semantic budget refusals.
    /// Never more than `execution_dependences`; the rest are of another cause (a
    /// provider failure, a cancellation, and so on), which a rerun may not
    /// repeat. A merge that cannot keep the two counts together leaves this at
    /// zero, which reads as "not a budget refusal".
    pub budget_dependences: usize,
    pub reuse_refused: bool,
    pub persistence_refusals: usize,
}

/// Refuse retained reuse in the current consuming capture. This capability
/// certifies no source, model, profile, mount, or semantic identity.
pub trait ReadReuseRefusal: Send + Sync {
    fn refuse_read_reuse(&self);

    /// Certify the current consuming capture by the whole selected content of
    /// `language`: any change to that language's files invalidates it. A
    /// capability that cannot name that scope refuses reuse instead.
    fn record_language_scope_read(&self, _language: crate::analyzer::Language) {
        self.refuse_read_reuse();
    }
}

/// Supplied by the analysis layer; core does not know the key vocabulary.
pub trait MemoAttribution {
    type Key;
    fn is_capturing(&self) -> bool;
    fn capture_identity(&self) -> Option<CaptureIdentity>;
    #[track_caller]
    fn record_unattributed(&self);
    fn capture<T>(
        &self,
        build: impl FnOnce() -> T,
    ) -> (T, CapturedMemoReads<Self::Key>, Option<CaptureIdentity>);
    fn replay(&self, reads: &CapturedMemoReads<Self::Key>);
    fn capture_authority<T>(&self, build: impl FnOnce() -> T) -> (T, CapturedMemoReads<Self::Key>);
}

/// Only the analysis layer constructs capabilities. The source gate enforces
/// that boundary across crates; adapters receive a capability at their read.
pub struct MemoCapability<A: MemoAttribution> {
    attribution: A,
}
impl<A: MemoAttribution> MemoCapability<A> {
    pub const fn new(attribution: A) -> Self {
        Self { attribution }
    }
    pub fn is_capturing(&self) -> bool {
        self.attribution.is_capturing()
    }
    pub fn capture_identity(&self) -> Option<CaptureIdentity> {
        self.attribution.capture_identity()
    }
    #[track_caller]
    pub fn record_unattributed(&self) {
        self.attribution.record_unattributed();
    }
    fn capture<T>(
        &self,
        build: impl FnOnce() -> T,
    ) -> (T, CapturedMemoReads<A::Key>, Option<CaptureIdentity>) {
        self.attribution.capture(build)
    }
    fn replay(&self, reads: &CapturedMemoReads<A::Key>) {
        self.attribution.replay(reads);
    }
    fn record_detached_read(&self) {
        if self.is_capturing() && self.capture_identity().is_none() {
            self.record_unattributed();
        }
    }
    fn read_authority<F, I, R>(
        &self,
        family: &F,
        read: impl FnOnce() -> R,
        inputs: impl FnOnce(&R) -> I,
    ) -> R
    where
        A: AuthorityRecorder<F, I>,
    {
        self.record_detached_read();
        if !self.is_capturing() {
            return read();
        }
        let (answer, reads) = self.attribution.capture_authority(read);
        self.attribution
            .record_authority(family, inputs(&answer), reads);
        answer
    }
}

pub trait AuthorityRecorder<F, I>: MemoAttribution {
    fn record_authority(&self, family: &F, inputs: I, reads: CapturedMemoReads<Self::Key>);
}

/// An authority read records a covering certificate on both hits and misses.
#[derive(Clone, Debug, Default)]
pub struct WorkspaceAuthorityMemo<M, F> {
    family: F,
    memo: M,
}
impl<M, F> WorkspaceAuthorityMemo<M, F> {
    pub const fn new(family: F, memo: M) -> Self {
        Self { family, memo }
    }
    pub fn read<'a, A, R, I>(
        &'a self,
        attribution: &MemoCapability<A>,
        read: impl FnOnce(&'a M) -> R,
        inputs: impl FnOnce(&R) -> I,
    ) -> R
    where
        A: AuthorityRecorder<F, I>,
    {
        attribution.read_authority(&self.family, || read(&self.memo), inputs)
    }
    pub fn read_mut<A, R, I>(
        &mut self,
        attribution: &MemoCapability<A>,
        read: impl FnOnce(&mut M) -> R,
        inputs: impl FnOnce(&R) -> I,
    ) -> R
    where
        A: AuthorityRecorder<F, I>,
    {
        attribution.read_authority(&self.family, || read(&mut self.memo), inputs)
    }

    /// Byte/weight accounting only; this projection cannot return an answer.
    pub fn account(&self, account: impl FnOnce(&M) -> usize) -> usize {
        account(&self.memo)
    }
}

/// Unconverted memo reads refuse publication while a capture is attached.
#[derive(Clone, Debug, Default)]
pub struct PendingMemo<M> {
    memo: M,
}
impl<M> PendingMemo<M> {
    pub const fn new(memo: M) -> Self {
        Self { memo }
    }
    pub fn read<A: MemoAttribution, R>(
        &self,
        attribution: &MemoCapability<A>,
        read: impl FnOnce(&M) -> R,
    ) -> R {
        if attribution.is_capturing() {
            attribution.record_unattributed();
        }
        read(&self.memo)
    }
    pub fn read_mut<A: MemoAttribution, R>(
        &mut self,
        attribution: &MemoCapability<A>,
        read: impl FnOnce(&mut M) -> R,
    ) -> R {
        if attribution.is_capturing() {
            attribution.record_unattributed();
        }
        read(&mut self.memo)
    }

    /// Byte/weight accounting only; this projection cannot return an answer.
    pub fn account(&self, account: impl FnOnce(&M) -> usize) -> usize {
        account(&self.memo)
    }
}

/// A fresh memo whose answer-bearing accesses stay inside one capture.
/// Construction and accounting leave it unbound. Any access without a capture
/// taints it, even if the accessor happens to leave the memo empty: a generic
/// wrapper cannot prove that it recorded no inputs. Tainted memos refuse reuse.
#[derive(Debug, Default)]
pub struct CaptureScopedMemo<M> {
    binding: Mutex<CaptureBinding>,
    memo: M,
}
#[derive(Debug, Clone, Copy, Default)]
enum CaptureBinding {
    #[default]
    Unbound,
    Bound(CaptureIdentity),
    Tainted,
}
impl<M: Clone> Clone for CaptureScopedMemo<M> {
    fn clone(&self) -> Self {
        Self {
            binding: Mutex::new(*self.binding.lock().expect("capture binding poisoned")),
            memo: self.memo.clone(),
        }
    }
}
impl<M> CaptureScopedMemo<M> {
    /// Wrap a fresh memo, before any answer-bearing use of its contents.
    pub const fn new(memo: M) -> Self {
        Self {
            binding: Mutex::new(CaptureBinding::Unbound),
            memo,
        }
    }
    fn record_access<A: MemoAttribution>(&self, attribution: &MemoCapability<A>) {
        attribution.record_detached_read();
        let current = attribution
            .is_capturing()
            .then(|| attribution.capture_identity())
            .flatten();
        let mut binding = self.binding.lock().expect("capture binding poisoned");
        let previous = *binding;
        let (unattributed, wrong_capture) = match (previous, current) {
            (CaptureBinding::Unbound, Some(identity)) => {
                *binding = CaptureBinding::Bound(identity);
                (false, false)
            }
            (CaptureBinding::Bound(expected), Some(actual)) if expected == actual => (false, false),
            (CaptureBinding::Bound(_), Some(_)) => {
                // In release, a foreign capture may fill entries before returning.
                // Refuse subsequent reuse in the original capture as well.
                *binding = CaptureBinding::Tainted;
                (true, true)
            }
            (CaptureBinding::Tainted, Some(_)) => (true, false),
            (_, None) => {
                *binding = CaptureBinding::Tainted;
                (false, false)
            }
        };
        drop(binding);
        if unattributed {
            attribution.record_unattributed();
        }
        debug_assert!(
            !wrong_capture,
            "a capture-scoped memo cannot cross capture boundaries: {previous:?} -> {current:?}"
        );
    }
    pub fn read<'a, A: MemoAttribution, R>(
        &'a self,
        attribution: &MemoCapability<A>,
        read: impl FnOnce(&'a M) -> R,
    ) -> R {
        self.record_access(attribution);
        read(&self.memo)
    }
    pub fn read_mut<A: MemoAttribution, R>(
        &mut self,
        attribution: &MemoCapability<A>,
        read: impl FnOnce(&mut M) -> R,
    ) -> R {
        self.record_access(attribution);
        read(&mut self.memo)
    }
    /// Byte/weight accounting only. Accounting does not bind or taint a memo.
    pub fn account(&self, account: impl FnOnce(&M) -> usize) -> usize {
        account(&self.memo)
    }
}

#[derive(Debug)]
pub struct ReplayingMemoEntry<T, K> {
    value: T,
    reads: CapturedMemoReads<K>,
    value_bytes: usize,
    charge: crate::retention_budget::AllocationCharge,
}
impl<T, K> ReplayingMemoEntry<T, K> {
    /// Capture a value for a cache that performs its own admission and replay.
    pub fn capture<A: MemoAttribution<Key = K>>(
        attribution: &MemoCapability<A>,
        build: impl FnOnce() -> T,
    ) -> Self {
        let (value, reads, _) = attribution.capture(build);
        Self {
            value,
            reads,
            value_bytes: std::mem::size_of::<T>(),
            charge: Default::default(),
        }
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn into_parts(self) -> (T, CapturedMemoReads<K>) {
        (self.value, self.reads)
    }

    pub fn from_parts(value: T, reads: CapturedMemoReads<K>) -> Self {
        Self {
            value,
            reads,
            value_bytes: std::mem::size_of::<T>(),
            charge: Default::default(),
        }
    }

    /// `from_parts` for a heap-owned value whose weight the cache already
    /// knows, so `charge` covers the value as well as its receipt.
    pub fn from_parts_weighted(value: T, reads: CapturedMemoReads<K>, value_bytes: usize) -> Self {
        Self {
            value,
            reads,
            value_bytes,
            charge: Default::default(),
        }
    }

    pub fn replay<A: MemoAttribution<Key = K>>(&self, attribution: &MemoCapability<A>) {
        attribution.replay(&self.reads);
    }

    pub fn reuse_refused(&self) -> bool {
        self.reads.channels.reuse_refused
    }

    /// Whether the build that produced this entry depended on its execution:
    /// it recorded an execution dependence, refused reuse, or hit an execution
    /// refusal. Such an entry's value describes this run, not the recorded
    /// inputs, so a consumer must not treat a verdict inside it as content.
    pub fn execution_dependent(&self) -> bool {
        self.reads.channels.execution_dependences > 0
            || self.reads.channels.reuse_refused
            || self.reads.first_execution_refusal.is_some()
    }

    pub fn named_read_count(&self) -> usize {
        self.reads.keys.len()
    }

    /// Complete entry weight for the owning bounded cache. Heap-owned values
    /// use build_weighted; the key callback accounts for each key's heap data.
    pub fn retained_bytes(&self, key_heap_bytes: impl Fn(&K) -> usize) -> usize {
        self.value_bytes
            .saturating_add(self.retained_read_bytes(key_heap_bytes))
    }

    /// Add this to the owning cache's weight, including each key's heap data.
    pub fn retained_read_bytes(&self, key_heap_bytes: impl FnMut(&K) -> usize) -> usize {
        std::mem::size_of_val(self.reads.keys.as_ref())
            .saturating_add(self.reads.keys.iter().map(key_heap_bytes).sum::<usize>())
            .saturating_add(
                self.reads
                    .first_refusal
                    .as_ref()
                    .map_or(0, |refusal| refusal.reason.len()),
            )
            .saturating_add(
                self.reads
                    .first_execution_refusal
                    .as_ref()
                    .map_or(0, |refusal| refusal.reason.len()),
            )
    }

    /// Charge this entry's bytes to the owner's budget before it is shared, so
    /// every `Arc` of it, including the one a replayed hit holds, keeps them
    /// charged. An entry the budget cannot take stays uncharged and
    /// request-only.
    pub fn charge(
        &mut self,
        budget: &crate::retention_budget::RetentionBudget,
        key_heap_bytes: impl Fn(&K) -> usize,
    ) {
        let bytes = self.retained_bytes(key_heap_bytes);
        self.charge = crate::retention_budget::AllocationCharge::acquire(budget, bytes);
    }

    /// Drop an over-budget receipt while making future memo hits fail closed.
    /// The first build has already forwarded its reads to the active capture;
    /// later hits see the unattributed marker and cannot reuse the value.
    pub fn refuse_replay(&mut self) {
        self.reads.keys = Arc::from([]);
        self.reads.channels.unattributed_reads = self.reads.channels.unattributed_reads.max(1);
    }
}

impl<T, K> crate::retention_budget::SelfCharged for ReplayingMemoEntry<T, K> {
    fn allocation_charge(&self) -> &crate::retention_budget::AllocationCharge {
        &self.charge
    }
}

/// Build context valid only during one memo accessor. Capturing forwards the
/// build's reads already; identify its returned entry to avoid double-counting.
struct BuiltMemoReads<K> {
    reads: CapturedMemoReads<K>,
    forwarded_to: Option<CaptureIdentity>,
}

pub struct MemoReadCapture<'a, A: MemoAttribution> {
    attribution: &'a MemoCapability<A>,
    built: Mutex<Vec<BuiltMemoReads<A::Key>>>,
}
impl<A: MemoAttribution> MemoReadCapture<'_, A> {
    pub fn build<T>(&self, build: impl FnOnce() -> T) -> ReplayingMemoEntry<T, A::Key> {
        let (value, reads, forwarded_to) = self.attribution.capture(build);
        self.built
            .lock()
            .expect("memo build capture poisoned")
            .push(BuiltMemoReads {
                reads: CapturedMemoReads {
                    runtime_cache_touched: reads.runtime_cache_touched,
                    keys: Arc::clone(&reads.keys),
                    channels: reads.channels,
                    first_refusal: reads.first_refusal.clone(),
                    first_execution_refusal: reads.first_execution_refusal.clone(),
                },
                forwarded_to,
            });
        ReplayingMemoEntry {
            value,
            reads,
            value_bytes: std::mem::size_of::<T>(),
            charge: Default::default(),
        }
    }
    pub fn try_build<T, E>(
        &self,
        build: impl FnOnce() -> Result<T, E>,
    ) -> Result<ReplayingMemoEntry<T, A::Key>, E> {
        let entry = self.build(build);
        Ok(ReplayingMemoEntry {
            value: entry.value?,
            reads: entry.reads,
            value_bytes: std::mem::size_of::<T>(),
            charge: Default::default(),
        })
    }

    /// The builder returns the value and its existing cache weight together,
    /// without exposing a second accessor to the retained value.
    pub fn build_weighted<T>(
        &self,
        build: impl FnOnce() -> (T, usize),
    ) -> ReplayingMemoEntry<T, A::Key> {
        let entry = self.build(build);
        let (value, value_bytes) = entry.value;
        ReplayingMemoEntry {
            value,
            reads: entry.reads,
            value_bytes,
            charge: Default::default(),
        }
    }

    pub fn try_build_weighted<T, E>(
        &self,
        build: impl FnOnce() -> Result<(T, usize), E>,
    ) -> Result<ReplayingMemoEntry<T, A::Key>, E> {
        let entry = self.try_build(build)?;
        let (value, value_bytes) = entry.value;
        Ok(ReplayingMemoEntry {
            value,
            reads: entry.reads,
            value_bytes,
            charge: Default::default(),
        })
    }
}

/// Access handle retaining the chosen entry; its construction replays reads.
pub struct ReplayedMemoValue<T, K>(Arc<ReplayingMemoEntry<T, K>>);
impl<T, K> ReplayedMemoValue<T, K> {
    /// The entry, so a holder keeps its charge alive.
    pub fn into_entry(self) -> Arc<ReplayingMemoEntry<T, K>> {
        self.0
    }
}
impl<T, K> Deref for ReplayedMemoValue<T, K> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0.value
    }
}

#[derive(Clone, Debug, Default)]
pub struct ReplayingMemo<M> {
    memo: M,
}
impl<M> ReplayingMemo<M> {
    pub const fn new(memo: M) -> Self {
        Self { memo }
    }

    /// `read` selects an entry, using `capture.build` for any build. A losing
    /// concurrent build does not suppress replay of the entry actually chosen.
    pub fn read<A: MemoAttribution, T, E>(
        &self,
        attribution: &MemoCapability<A>,
        read: impl FnOnce(&M, &MemoReadCapture<'_, A>) -> Result<Arc<ReplayingMemoEntry<T, A::Key>>, E>,
    ) -> Result<ReplayedMemoValue<T, A::Key>, E> {
        attribution.record_detached_read();
        let capture = MemoReadCapture {
            attribution,
            built: Mutex::new(Vec::new()),
        };
        let entry = read(&self.memo, &capture)?;
        Ok(capture.finish(entry))
    }
    pub fn read_mut<A: MemoAttribution, T, E>(
        &mut self,
        attribution: &MemoCapability<A>,
        read: impl FnOnce(
            &mut M,
            &MemoReadCapture<'_, A>,
        ) -> Result<Arc<ReplayingMemoEntry<T, A::Key>>, E>,
    ) -> Result<ReplayedMemoValue<T, A::Key>, E> {
        attribution.record_detached_read();
        let capture = MemoReadCapture {
            attribution,
            built: Mutex::new(Vec::new()),
        };
        let entry = read(&mut self.memo, &capture)?;
        Ok(capture.finish(entry))
    }
    /// Byte/weight accounting only; this projection cannot return an answer.
    pub fn account(&self, account: impl FnOnce(&M) -> usize) -> usize {
        account(&self.memo)
    }
}

impl<A: MemoAttribution> MemoReadCapture<'_, A> {
    fn finish<T>(&self, entry: Arc<ReplayingMemoEntry<T, A::Key>>) -> ReplayedMemoValue<T, A::Key> {
        if self.attribution.is_capturing()
            && !self
                .built
                .lock()
                .expect("memo build capture poisoned")
                .iter()
                .any(|built| {
                    built.forwarded_to.is_some()
                        && built.forwarded_to == self.attribution.capture_identity()
                        && Arc::ptr_eq(&built.reads.keys, &entry.reads.keys)
                        && built.reads.channels == entry.reads.channels
                })
        {
            self.attribution.replay(&entry.reads);
        }
        ReplayedMemoValue(entry)
    }
}

impl MemoCapability<super::project_reads::ErasedMemoAttribution> {
    /// An erased capability can be adapted, never manufactured from a recorder.
    pub fn from_erased(capability: super::project_reads::ReadCapability) -> Self {
        Self {
            attribution: super::project_reads::ErasedMemoAttribution(capability),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    struct AttributionState {
        active: CaptureIdentity,
        delivered: Vec<(CaptureIdentity, ReadChannels)>,
    }

    #[derive(Clone)]
    struct TestAttribution(Arc<Mutex<AttributionState>>);

    impl MemoAttribution for TestAttribution {
        type Key = ();

        fn is_capturing(&self) -> bool {
            true
        }

        fn capture_identity(&self) -> Option<CaptureIdentity> {
            Some(self.0.lock().expect("attribution state poisoned").active)
        }

        fn record_unattributed(&self) {
            panic!("this test has no unattributed reads")
        }

        fn capture<T>(
            &self,
            build: impl FnOnce() -> T,
        ) -> (T, CapturedMemoReads<Self::Key>, Option<CaptureIdentity>) {
            let value = build();
            let identity = self.capture_identity().expect("active capture");
            let reads = CapturedMemoReads {
                runtime_cache_touched: false,
                keys: Arc::from([]),
                channels: ReadChannels {
                    reuse_refused: true,
                    ..Default::default()
                },
                first_refusal: None,
                first_execution_refusal: None,
            };
            self.replay(&reads);
            (value, reads, Some(identity))
        }

        fn replay(&self, reads: &CapturedMemoReads<Self::Key>) {
            let mut state = self.0.lock().expect("attribution state poisoned");
            let identity = state.active;
            state.delivered.push((identity, reads.channels));
        }

        fn capture_authority<T>(
            &self,
            _build: impl FnOnce() -> T,
        ) -> (T, CapturedMemoReads<Self::Key>) {
            unimplemented!("this test does not read authority")
        }
    }

    #[test]
    fn entry_is_execution_dependent_when_its_build_was() {
        let entry = |channels, first_execution_refusal| {
            ReplayingMemoEntry::from_parts(
                0u8,
                CapturedMemoReads::<()> {
                    keys: Arc::from([]),
                    channels,
                    first_refusal: None,
                    first_execution_refusal,
                    runtime_cache_touched: false,
                },
            )
        };
        assert!(!entry(ReadChannels::default(), None).execution_dependent());
        // Reads left unattributed or unpersistable are the consumer's to
        // refuse; they do not make the entry's value describe its execution.
        assert!(
            !entry(
                ReadChannels {
                    unattributed_reads: 1,
                    persistence_refusals: 1,
                    ..ReadChannels::default()
                },
                None
            )
            .execution_dependent()
        );
        assert!(
            entry(
                ReadChannels {
                    execution_dependences: 1,
                    ..ReadChannels::default()
                },
                None
            )
            .execution_dependent()
        );
        assert!(
            entry(
                ReadChannels {
                    reuse_refused: true,
                    ..ReadChannels::default()
                },
                None
            )
            .execution_dependent()
        );
        assert!(
            entry(
                ReadChannels::default(),
                Some(crate::profiling::ReadRefusal {
                    kind: "test",
                    reason: "execution".to_owned(),
                    origin: std::panic::Location::caller(),
                })
            )
            .execution_dependent()
        );
    }

    #[test]
    #[hardwon(
        "#9575: replayable memo must retain explicit refusal while deduplicating a cold build"
    )]
    fn replaying_memo_refusal_cold_forwarded_once_and_warm_replayed_to_other_capture() {
        let state = Arc::new(Mutex::new(AttributionState {
            active: CaptureIdentity(1),
            delivered: Vec::new(),
        }));
        let capability = MemoCapability::new(TestAttribution(Arc::clone(&state)));
        let memo = ReplayingMemo::new(Mutex::new(None::<Arc<ReplayingMemoEntry<u8, ()>>>));
        let cold = memo
            .read(&capability, |slot, capture| {
                let mut slot = slot.lock().expect("memo slot poisoned");
                Ok::<_, ()>(Arc::clone(
                    slot.get_or_insert_with(|| Arc::new(capture.build(|| 7))),
                ))
            })
            .expect("cold read");
        assert_eq!(*cold, 7);
        {
            let state = state.lock().expect("attribution state poisoned");
            assert_eq!(
                state.delivered.len(),
                1,
                "cold build already forwarded its receipt"
            );
            assert_eq!(state.delivered[0].0, CaptureIdentity(1));
            assert!(state.delivered[0].1.reuse_refused);
            assert_eq!(state.delivered[0].1.unattributed_reads, 0);
            assert_eq!(state.delivered[0].1.execution_dependences, 0);
        }
        state.lock().expect("attribution state poisoned").active = CaptureIdentity(2);
        let warm = memo
            .read(&capability, |slot, _| {
                Ok::<_, ()>(Arc::clone(
                    slot.lock()
                        .expect("memo slot poisoned")
                        .as_ref()
                        .expect("saved receipt"),
                ))
            })
            .expect("warm read");
        assert_eq!(*warm, 7);
        let state = state.lock().expect("attribution state poisoned");
        assert_eq!(state.delivered.len(), 2);
        assert_eq!(state.delivered[1].0, CaptureIdentity(2));
        assert!(state.delivered[1].1.reuse_refused);
        assert_eq!(state.delivered[1].1.unattributed_reads, 0);
        assert_eq!(state.delivered[1].1.execution_dependences, 0);
    }
}
