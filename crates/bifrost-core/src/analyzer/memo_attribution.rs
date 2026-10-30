//! Memo access requires an explicit read-attribution capability.
use std::ops::Deref;
use std::sync::Arc;
use std::sync::Mutex;

/// Identity of one capture, independent of allocator address reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureIdentity(pub u64);

#[derive(Debug)]
pub struct CapturedMemoReads<K> {
    pub keys: Arc<[K]>,
    pub unattributed_reads: usize,
    pub execution_dependences: usize,
}

/// Supplied by the analysis layer; core does not know the key vocabulary.
pub trait MemoAttribution {
    type Key;
    fn is_capturing(&self) -> bool;
    fn capture_identity(&self) -> Option<CaptureIdentity>;
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
}
impl<T, K> ReplayingMemoEntry<T, K> {
    /// Complete entry weight for the owning bounded cache. Heap-owned values
    /// use build_weighted; the key callback accounts for each key's heap data.
    pub fn retained_bytes(&self, key_heap_bytes: impl Fn(&K) -> usize) -> usize {
        self.value_bytes
            .saturating_add(self.retained_read_bytes(key_heap_bytes))
    }

    /// Add this to the owning cache's weight, including each key's heap data.
    pub fn retained_read_bytes(&self, key_heap_bytes: impl Fn(&K) -> usize) -> usize {
        std::mem::size_of_val(self.reads.keys.as_ref())
            .saturating_add(self.reads.keys.iter().map(key_heap_bytes).sum::<usize>())
    }

    /// Drop an over-budget receipt while making future memo hits fail closed.
    /// The first build has already forwarded its reads to the active capture;
    /// later hits see the unattributed marker and cannot reuse the value.
    pub fn refuse_replay(&mut self) {
        self.reads.keys = Arc::from([]);
        self.reads.unattributed_reads = self.reads.unattributed_reads.max(1);
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
                    keys: Arc::clone(&reads.keys),
                    unattributed_reads: reads.unattributed_reads,
                    execution_dependences: reads.execution_dependences,
                },
                forwarded_to,
            });
        ReplayingMemoEntry {
            value,
            reads,
            value_bytes: std::mem::size_of::<T>(),
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
        })
    }
}

/// Access handle retaining the chosen entry; its construction replays reads.
pub struct ReplayedMemoValue<T, K>(Arc<ReplayingMemoEntry<T, K>>);
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
                        && built.reads.unattributed_reads == entry.reads.unattributed_reads
                        && built.reads.execution_dependences == entry.reads.execution_dependences
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
