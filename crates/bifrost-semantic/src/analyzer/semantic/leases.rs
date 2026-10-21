//! Bounded strong leases for complete semantic artifact allocations.
//!
//! A lease is deliberately not an artifact cache. It preserves the exact
//! allocation that produced pointer-scoped semantic handles while ordinary
//! provider lookup continues to derive and validate the current artifact key.

use std::collections::HashMap;
use std::fmt;
use std::mem::size_of;
#[cfg(any(test, feature = "test-support"))]
use std::sync::MutexGuard;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use brokk_bifrost_core::analyzer::model::ProjectFile;

use crate::analyzer::semantic::ids::StableDigest;

use crate::analyzer::semantic::ir::SemanticArtifact;

use crate::analyzer::semantic::service::semantic_artifact_retained_bytes;

const ARC_HEADER_BYTES: usize = 2 * size_of::<usize>();
const ALLOCATION_HEADER_BYTES: usize = 2 * size_of::<usize>();
// One vector slot plus a conservatively sparse hash-map bucket and its index
// vector. Hashbrown's exact control layout is private, so reserve four extra
// machine words for control bytes and allocator slack.
const LEASE_INDEX_BYTES: usize = size_of::<SemanticArtifactLease>()
    + size_of::<StableDigest>()
    + size_of::<Vec<usize>>()
    + size_of::<usize>()
    + ALLOCATION_HEADER_BYTES
    + 4 * size_of::<usize>();
#[doc(hidden)]
pub const LEASE_STORAGE_BASE_BYTES: usize = ARC_HEADER_BYTES
    + size_of::<LeaseState>()
    + size_of::<Vec<SemanticArtifactLease>>()
    + size_of::<HashMap<StableDigest, Vec<usize>>>()
    + 2 * ALLOCATION_HEADER_BYTES;

/// One exact complete artifact allocation and its project-file identity.
///
/// Distinct allocations with equal semantic keys remain distinct leases:
/// semantic handles are allocation-scoped, so key equality cannot substitute
/// for pointer identity.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct SemanticArtifactLease {
    #[doc(hidden)]
    pub file: ProjectFile,
    #[doc(hidden)]
    pub artifact: Arc<SemanticArtifact>,
}

impl SemanticArtifactLease {
    #[doc(hidden)]
    pub fn new(file: ProjectFile, artifact: Arc<SemanticArtifact>) -> Self {
        Self { file, artifact }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub const fn file(&self) -> &ProjectFile {
        &self.file
    }

    #[doc(hidden)]
    pub const fn artifact(&self) -> &Arc<SemanticArtifact> {
        &self.artifact
    }

    fn retained_bytes(&self) -> Result<usize, SemanticArtifactLeaseError> {
        retained_artifact_bytes(&self.file, &self.artifact)
    }
}

#[doc(hidden)]
pub fn retained_artifact_bytes(
    file: &ProjectFile,
    artifact: &SemanticArtifact,
) -> Result<usize, SemanticArtifactLeaseError> {
    let retained = usize::try_from(semantic_artifact_retained_bytes(artifact))
        .map_err(|_| SemanticArtifactLeaseError::RetainedBytesOverflow)?;
    [
        file.retained_bytes(),
        2 * ALLOCATION_HEADER_BYTES,
        artifact.key().path().as_str().len(),
        artifact.key().adapter().name().len(),
        ARC_HEADER_BYTES,
        LEASE_INDEX_BYTES,
    ]
    .into_iter()
    .try_fold(retained, |total, bytes| {
        total
            .checked_add(bytes)
            .ok_or(SemanticArtifactLeaseError::RetainedBytesOverflow)
    })
}

#[derive(Debug, Clone, Default)]
#[doc(hidden)]
pub struct LeaseStorage {
    leases: Vec<SemanticArtifactLease>,
    indices_by_key: HashMap<StableDigest, Vec<usize>>,
    entry_retained_bytes: usize,
}

impl LeaseStorage {
    fn len(&self) -> usize {
        self.leases.len()
    }

    fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    fn contains_artifact(&self, artifact: &Arc<SemanticArtifact>) -> bool {
        self.indices_by_key
            .get(&artifact.key().fingerprint())
            .is_some_and(|indices| {
                indices.iter().any(|index| {
                    Arc::ptr_eq(
                        self.leases
                            .get(*index)
                            .expect("semantic lease key index is in bounds")
                            .artifact(),
                        artifact,
                    )
                })
            })
    }

    fn retained_bytes(&self) -> usize {
        reported_retained_bytes([self])
    }

    #[doc(hidden)]
    pub fn try_insert(
        &mut self,
        lease: SemanticArtifactLease,
    ) -> Result<bool, SemanticArtifactLeaseError> {
        if self.contains_artifact(lease.artifact()) {
            return Ok(false);
        }
        let entry_retained_bytes = lease.retained_bytes()?;
        let next_retained_bytes = self
            .entry_retained_bytes
            .checked_add(entry_retained_bytes)
            .ok_or(SemanticArtifactLeaseError::RetainedBytesOverflow)?;
        let key = lease.artifact().key().fingerprint();
        let index = self.leases.len();
        self.entry_retained_bytes = next_retained_bytes;
        self.leases.push(lease);
        self.indices_by_key.entry(key).or_default().push(index);
        Ok(true)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn take_file(&mut self, file: &ProjectFile) -> Vec<SemanticArtifactLease> {
        if self.is_empty() {
            return Vec::new();
        }
        let mut retained = Vec::with_capacity(self.leases.len());
        let mut taken = Vec::new();
        for lease in std::mem::take(&mut self.leases) {
            if lease.file() == file {
                taken.push(lease);
            } else {
                retained.push(lease);
            }
        }
        self.indices_by_key.clear();
        self.entry_retained_bytes = 0;
        for lease in retained {
            assert_eq!(
                self.try_insert(lease),
                Ok(true),
                "lease storage contained a duplicate pointer"
            );
        }
        taken
    }

    #[cfg(any(test, feature = "test-support"))]
    fn take_all(&mut self) -> Vec<SemanticArtifactLease> {
        self.indices_by_key.clear();
        self.entry_retained_bytes = 0;
        std::mem::take(&mut self.leases)
    }
}

fn checked_retained_bytes<'a>(
    storages: impl IntoIterator<Item = &'a LeaseStorage>,
) -> Result<usize, SemanticArtifactLeaseError> {
    let mut retained = 0usize;
    for storage in storages {
        if storage.is_empty() {
            continue;
        }
        retained = retained
            .checked_add(LEASE_STORAGE_BASE_BYTES)
            .and_then(|retained| retained.checked_add(storage.entry_retained_bytes))
            .ok_or(SemanticArtifactLeaseError::RetainedBytesOverflow)?;
    }
    Ok(retained)
}

fn reported_retained_bytes<'a>(storages: impl IntoIterator<Item = &'a LeaseStorage>) -> usize {
    let mut retained = 0usize;
    for storage in storages {
        if storage.is_empty() {
            continue;
        }
        retained = retained
            .saturating_add(LEASE_STORAGE_BASE_BYTES)
            .saturating_add(storage.entry_retained_bytes);
    }
    retained
}

fn checked_attempted_retained_bytes<'a>(
    storages: impl IntoIterator<Item = &'a LeaseStorage>,
    other_live_bytes: usize,
) -> Result<usize, SemanticArtifactLeaseError> {
    checked_retained_bytes(storages)?
        .checked_add(other_live_bytes)
        .ok_or(SemanticArtifactLeaseError::RetainedBytesOverflow)
}

fn check_retained_capacity<'a>(
    storages: impl IntoIterator<Item = &'a LeaseStorage>,
    other_live_bytes: usize,
    limit: usize,
) -> Result<(), SemanticArtifactLeaseError> {
    let attempted = checked_attempted_retained_bytes(storages, other_live_bytes)?;
    if attempted > limit {
        return Err(SemanticArtifactLeaseError::Capacity(
            SemanticArtifactLeaseCapacityExceeded { limit, attempted },
        ));
    }
    Ok(())
}

fn contains_exact_artifact<'a>(
    storages: impl IntoIterator<Item = &'a LeaseStorage>,
    artifact: &Arc<SemanticArtifact>,
) -> bool {
    storages
        .into_iter()
        .any(|storage| storage.contains_artifact(artifact))
}

#[derive(Debug)]
#[doc(hidden)]
pub struct SemanticArtifactLeaseScope;

#[derive(Debug, Clone, Default)]
#[doc(hidden)]
pub struct LeaseState {
    #[doc(hidden)]
    pub generation: u64,
    storage: LeaseStorage,
}

impl LeaseState {
    fn retained_bytes(&self) -> usize {
        self.storage.retained_bytes()
    }
}

/// A committed, bounded set of exact semantic artifact allocations.
///
/// The set is intentionally non-`Clone`: mutations advance one logical
/// generation. Cloneable snapshots are the only way to fork additions, and a
/// one-shot charge must reconcile against that exact generation.
#[derive(Debug)]
pub struct SemanticArtifactLeaseSet {
    max_retained_bytes: usize,
    #[doc(hidden)]
    pub scope: Arc<SemanticArtifactLeaseScope>,
    #[doc(hidden)]
    pub state: Arc<LeaseState>,
}

impl SemanticArtifactLeaseSet {
    pub fn new(max_retained_bytes: usize) -> Self {
        Self {
            max_retained_bytes,
            scope: Arc::new(SemanticArtifactLeaseScope),
            state: Arc::new(LeaseState::default()),
        }
    }

    pub const fn max_retained_bytes(&self) -> usize {
        self.max_retained_bytes
    }

    pub fn retained_bytes(&self) -> usize {
        self.state.retained_bytes()
    }

    pub fn len(&self) -> usize {
        self.state.storage.len()
    }

    pub fn is_empty(&self) -> bool {
        self.state.storage.is_empty()
    }

    /// Capture this exact committed generation in O(1) time.
    pub fn snapshot(&self) -> SemanticArtifactLeaseSnapshot {
        SemanticArtifactLeaseSnapshot {
            max_retained_bytes: self.max_retained_bytes,
            scope: Arc::clone(&self.scope),
            state: Arc::clone(&self.state),
        }
    }

    /// Atomically apply one additions-only child charge.
    ///
    /// `other_live_bytes` is caller-owned memory, such as the exact source
    /// snapshot that must coexist with the committed leases. It consumes the
    /// same physical authority without becoming part of the committed set.
    /// Every snapshot and sibling child from the expected generation must be
    /// consumed or dropped before apply; otherwise cloning their shared state
    /// would allocate lease metadata outside the fixed physical authority.
    pub fn try_apply_charge(
        &mut self,
        charge: SemanticArtifactLeaseCharge,
        other_live_bytes: usize,
    ) -> Result<(), SemanticArtifactLeaseError> {
        if !Arc::ptr_eq(&self.scope, &charge.scope) {
            return Err(SemanticArtifactLeaseError::WrongScope);
        }
        if self.state.generation != charge.expected_generation {
            return Err(SemanticArtifactLeaseError::StaleGeneration {
                expected: charge.expected_generation,
                actual: self.state.generation,
            });
        }
        if charge
            .additions
            .leases
            .iter()
            .any(|lease| self.state.storage.contains_artifact(lease.artifact()))
        {
            return Err(SemanticArtifactLeaseError::Overlap);
        }
        let attempted = checked_attempted_retained_bytes(
            [&self.state.storage, &charge.additions],
            other_live_bytes,
        )?;
        if attempted > self.max_retained_bytes {
            return Err(SemanticArtifactLeaseError::Capacity(
                SemanticArtifactLeaseCapacityExceeded {
                    limit: self.max_retained_bytes,
                    attempted,
                },
            ));
        }
        let Some(next_generation) = self.state.generation.checked_add(1) else {
            return Err(SemanticArtifactLeaseError::GenerationOverflow);
        };

        let state = Arc::get_mut(&mut self.state)
            .ok_or(SemanticArtifactLeaseError::OutstandingGeneration)?;
        state.generation = next_generation;
        for lease in charge.additions.leases {
            assert_eq!(
                state.storage.try_insert(lease),
                Ok(true),
                "prechecked semantic lease charge became overlapping"
            );
        }
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn state_identity(&self) -> usize {
        Arc::as_ptr(&self.state) as usize
    }
}

/// O(1) immutable view of one committed lease generation.
#[derive(Debug, Clone)]
pub struct SemanticArtifactLeaseSnapshot {
    max_retained_bytes: usize,
    scope: Arc<SemanticArtifactLeaseScope>,
    state: Arc<LeaseState>,
}

impl SemanticArtifactLeaseSnapshot {
    pub fn retained_bytes(&self) -> usize {
        self.state.retained_bytes()
    }

    /// Narrow this snapshot's physical authority for a bounded child query.
    ///
    /// The lease scope, generation, and exact retained allocations stay
    /// unchanged. If the existing allocation union already exceeds the
    /// narrower cap, the child's first window refuses before observing a new
    /// provider result.
    pub fn restrict_to(mut self, max_retained_bytes: usize) -> Self {
        self.max_retained_bytes = self.max_retained_bytes.min(max_retained_bytes);
        self
    }

    /// Whether this snapshot already retains this exact allocation.
    ///
    /// This is accounting-only membership: it performs a semantic-key bucket
    /// lookup and then pointer comparison, and never returns or serves an Arc.
    pub fn contains_exact(&self, artifact: &Arc<SemanticArtifact>) -> bool {
        self.state.storage.contains_artifact(artifact)
    }

    /// Consume this snapshot and stage additions in its logical scope.
    pub fn into_child(self) -> SemanticArtifactLeaseChild {
        SemanticArtifactLeaseChild {
            max_retained_bytes: self.max_retained_bytes,
            scope: self.scope,
            base: self.state,
            additions: Arc::new(LeaseStorage::default()),
            active_window: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Additions staged from one exact committed lease generation.
#[derive(Debug)]
pub struct SemanticArtifactLeaseChild {
    max_retained_bytes: usize,
    scope: Arc<SemanticArtifactLeaseScope>,
    base: Arc<LeaseState>,
    #[doc(hidden)]
    pub additions: Arc<LeaseStorage>,
    active_window: Arc<AtomicBool>,
}

impl SemanticArtifactLeaseChild {
    /// Start one discardable request/result window.
    pub fn begin_window(&mut self, other_live_bytes: usize) -> SemanticArtifactLeaseWindow {
        assert!(
            self.active_window
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "semantic artifact lease child already has a live window"
        );
        let overflow = check_retained_capacity(
            [&self.base.storage, self.additions.as_ref()],
            other_live_bytes,
            self.max_retained_bytes,
        )
        .err();
        SemanticArtifactLeaseWindow {
            state: Arc::new(Mutex::new(LeaseWindowState {
                max_retained_bytes: self.max_retained_bytes,
                other_live_bytes,
                scope: Some(Arc::clone(&self.scope)),
                base: Some(Arc::clone(&self.base)),
                promoted: Some(Arc::clone(&self.additions)),
                staged: LeaseStorage::default(),
                overflow,
                closed: false,
                active_live_reservations: 0,
                active_window: Arc::clone(&self.active_window),
            })),
        }
    }

    pub fn retained_bytes(&self) -> usize {
        reported_retained_bytes([&self.base.storage, self.additions.as_ref()])
    }

    /// Exact allocations retained by the inherited base and this child's
    /// committed additions.
    pub fn len(&self) -> usize {
        self.base.storage.len().saturating_add(self.additions.len())
    }

    /// Whether neither the inherited base nor this child's additions retain
    /// an artifact allocation.
    pub fn is_empty(&self) -> bool {
        self.base.storage.is_empty() && self.additions.is_empty()
    }

    /// Exact allocations first committed by this child.
    pub fn additions_len(&self) -> usize {
        self.additions.len()
    }

    /// Whether the base or additions already retain this exact allocation.
    pub fn contains_exact(&self, artifact: &Arc<SemanticArtifact>) -> bool {
        contains_exact_artifact([&self.base.storage, self.additions.as_ref()], artifact)
    }

    /// Finish this child as a one-shot, additions-only charge.
    pub fn into_charge(self) -> SemanticArtifactLeaseCharge {
        assert!(
            !self.active_window.load(Ordering::Acquire),
            "cannot finish a semantic artifact lease child with a live window"
        );
        let additions = Arc::try_unwrap(self.additions)
            .expect("a closed semantic lease window released its additions snapshot");
        SemanticArtifactLeaseCharge {
            scope: self.scope,
            expected_generation: self.base.generation,
            additions,
        }
    }
}

/// One discardable window whose collector can be cloned into staged requests.
#[derive(Debug)]
pub struct SemanticArtifactLeaseWindow {
    state: Arc<Mutex<LeaseWindowState>>,
}

impl SemanticArtifactLeaseWindow {
    pub fn collector(&self) -> SemanticArtifactCollector {
        SemanticArtifactCollector {
            state: SemanticArtifactCollectorState::Bounded(Arc::clone(&self.state)),
        }
    }

    pub fn overflow(&self) -> Option<SemanticArtifactLeaseError> {
        self.state
            .lock()
            .expect("semantic artifact lease window mutex poisoned")
            .overflow
    }

    pub fn retained_bytes(&self) -> usize {
        let state = self
            .state
            .lock()
            .expect("semantic artifact lease window mutex poisoned");
        let base = state
            .base
            .as_deref()
            .map(|state| &state.storage)
            .into_iter();
        let promoted = state.promoted.as_deref().into_iter();
        reported_retained_bytes(base.chain(promoted).chain([&state.staged]))
    }

    /// Reserve headroom for caller-owned memory before the caller allocates it.
    ///
    /// The returned guard rolls the reservation back unless the caller converts
    /// it to an exact retained charge. Collector observations and window commit
    /// include the reservation in the same physical authority, while
    /// [`Self::retained_bytes`] continues to report lease bytes only.
    pub fn reserve_other_live_bytes(
        &self,
        additional_bytes: usize,
    ) -> Result<SemanticArtifactLeaseLiveReservation, SemanticArtifactLeaseError> {
        let mut state = self
            .state
            .lock()
            .expect("semantic artifact lease window mutex poisoned");
        assert!(
            !state.closed,
            "cannot reserve caller-owned bytes on a closed semantic lease window"
        );
        if let Some(error) = state.overflow {
            return Err(error);
        }
        let next_other_live_bytes = match state.other_live_bytes.checked_add(additional_bytes) {
            Some(bytes) => bytes,
            None => {
                state.overflow = Some(SemanticArtifactLeaseError::RetainedBytesOverflow);
                return Err(SemanticArtifactLeaseError::RetainedBytesOverflow);
            }
        };
        let base = state.base.as_deref().expect("open lease window has a base");
        let promoted = state
            .promoted
            .as_deref()
            .expect("open lease window has promoted storage");
        if let Err(error) = check_retained_capacity(
            [&base.storage, promoted, &state.staged],
            next_other_live_bytes,
            state.max_retained_bytes,
        ) {
            state.overflow = Some(error);
            return Err(error);
        }
        let next_active_live_reservations = state
            .active_live_reservations
            .checked_add(1)
            .expect("semantic lease live-reservation count fits usize");
        state.other_live_bytes = next_other_live_bytes;
        state.active_live_reservations = next_active_live_reservations;
        drop(state);
        Ok(SemanticArtifactLeaseLiveReservation {
            state: Arc::clone(&self.state),
            reserved_bytes: additional_bytes,
            release_on_drop: true,
        })
    }

    /// Whether the inherited base, earlier child additions, or this staged
    /// window already retain this exact allocation. This is accounting-only:
    /// it never returns or serves the retained Arc.
    pub fn contains_exact(&self, artifact: &Arc<SemanticArtifact>) -> bool {
        let state = self
            .state
            .lock()
            .expect("semantic artifact lease window mutex poisoned");
        contains_exact_artifact(
            state
                .base
                .as_ref()
                .map(|base| &base.storage)
                .into_iter()
                .chain(state.promoted.as_deref())
                .chain(std::iter::once(&state.staged)),
            artifact,
        )
    }

    /// Promote this complete window into its originating child atomically.
    pub fn commit(
        self,
        child: &mut SemanticArtifactLeaseChild,
    ) -> Result<(), SemanticArtifactLeaseError> {
        let mut state = self
            .state
            .lock()
            .expect("semantic artifact lease window mutex poisoned");
        assert!(
            !state.closed,
            "semantic artifact lease window already closed"
        );
        if state.active_live_reservations != 0 {
            drop(state);
            panic!("cannot commit a semantic lease window with unresolved live-byte reservations");
        }
        if let Some(error) = state.overflow {
            state.close();
            return Err(error);
        }
        let same_scope = state
            .scope
            .as_ref()
            .is_some_and(|scope| Arc::ptr_eq(scope, &child.scope));
        let same_base = state
            .base
            .as_ref()
            .is_some_and(|base| Arc::ptr_eq(base, &child.base));
        let same_child = Arc::ptr_eq(&state.active_window, &child.active_window);
        if !same_scope || !same_base || !same_child {
            state.close();
            return Err(SemanticArtifactLeaseError::WrongScope);
        }

        let attempted = match checked_attempted_retained_bytes(
            [&child.base.storage, child.additions.as_ref(), &state.staged],
            state.other_live_bytes,
        ) {
            Ok(attempted) => attempted,
            Err(error) => {
                state.close();
                return Err(error);
            }
        };
        if attempted > child.max_retained_bytes {
            let exceeded = SemanticArtifactLeaseCapacityExceeded {
                limit: child.max_retained_bytes,
                attempted,
            };
            state.close();
            return Err(SemanticArtifactLeaseError::Capacity(exceeded));
        }

        let staged = std::mem::take(&mut state.staged);
        state.close();
        drop(state);
        let additions = Arc::get_mut(&mut child.additions)
            .expect("closed semantic lease window released its additions snapshot");
        for lease in staged.leases {
            if child.base.storage.contains_artifact(lease.artifact()) {
                continue;
            }
            assert_eq!(
                additions.try_insert(lease),
                Ok(true),
                "prechecked semantic lease window became overlapping"
            );
        }
        Ok(())
    }

    /// Drop all allocations staged by this window.
    pub fn discard(self) {
        let mut state = self
            .state
            .lock()
            .expect("semantic artifact lease window mutex poisoned");
        assert!(
            !state.closed,
            "semantic artifact lease window already closed"
        );
        state.close();
    }
}

/// Rollback-safe headroom for caller-owned memory in one lease window.
#[must_use = "dropping the reservation rolls its retained-byte headroom back"]
#[derive(Debug)]
pub struct SemanticArtifactLeaseLiveReservation {
    state: Arc<Mutex<LeaseWindowState>>,
    reserved_bytes: usize,
    release_on_drop: bool,
}

impl SemanticArtifactLeaseLiveReservation {
    /// Replace the conservative pre-allocation reservation with the caller's
    /// exact retained charge. The caller must have bounded the construction by
    /// the original reservation.
    pub fn retain_exact(mut self, retained_bytes: usize) {
        assert!(
            retained_bytes <= self.reserved_bytes,
            "retained caller-owned bytes exceed their semantic lease reservation"
        );
        let mut state = self
            .state
            .lock()
            .expect("semantic artifact lease window mutex poisoned");
        if state.closed {
            drop(state);
            panic!("cannot retain caller-owned bytes after closing their semantic lease window");
        }
        state.other_live_bytes = state
            .other_live_bytes
            .checked_sub(self.reserved_bytes)
            .and_then(|bytes| bytes.checked_add(retained_bytes))
            .expect("live semantic lease reservation is represented in window headroom");
        state.release_live_reservation();
        self.release_on_drop = false;
    }
}

impl Drop for SemanticArtifactLeaseLiveReservation {
    fn drop(&mut self) {
        if !self.release_on_drop {
            return;
        }
        let mut state = self
            .state
            .lock()
            .expect("semantic artifact lease window mutex poisoned while releasing reservation");
        state.other_live_bytes = state
            .other_live_bytes
            .checked_sub(self.reserved_bytes)
            .expect("live semantic lease reservation is represented in window headroom");
        state.release_live_reservation();
    }
}

impl Drop for SemanticArtifactLeaseWindow {
    fn drop(&mut self) {
        let mut state = self
            .state
            .lock()
            .expect("semantic artifact lease window mutex poisoned while dropping");
        if !state.closed {
            state.close();
        }
    }
}

#[derive(Debug)]
struct LeaseWindowState {
    max_retained_bytes: usize,
    other_live_bytes: usize,
    scope: Option<Arc<SemanticArtifactLeaseScope>>,
    base: Option<Arc<LeaseState>>,
    promoted: Option<Arc<LeaseStorage>>,
    staged: LeaseStorage,
    overflow: Option<SemanticArtifactLeaseError>,
    closed: bool,
    active_live_reservations: usize,
    active_window: Arc<AtomicBool>,
}

impl LeaseWindowState {
    fn release_live_reservation(&mut self) {
        self.active_live_reservations = self
            .active_live_reservations
            .checked_sub(1)
            .expect("live semantic lease reservation is registered with its window");
        if self.closed && self.active_live_reservations == 0 {
            self.active_window.store(false, Ordering::Release);
        }
    }

    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.scope = None;
        self.base = None;
        self.promoted = None;
        self.staged = LeaseStorage::default();
        // Publish the reusable child only after every window-owned snapshot and
        // live-byte reservation is gone. A concurrent `into_charge` pairs its
        // Acquire load with this Release and may therefore rely on unique
        // ownership of `additions`.
        if self.active_live_reservations == 0 {
            self.active_window.store(false, Ordering::Release);
        }
    }

    fn observe_complete(&mut self, file: &ProjectFile, artifact: &Arc<SemanticArtifact>) {
        if self.closed || self.overflow.is_some() {
            return;
        }
        let base = self.base.as_ref().expect("open lease window has base");
        let promoted = self
            .promoted
            .as_ref()
            .expect("open lease window has promoted storage");
        if base.storage.contains_artifact(artifact)
            || promoted.contains_artifact(artifact)
            || self.staged.contains_artifact(artifact)
        {
            return;
        }

        let candidate_bytes = match retained_artifact_bytes(file, artifact) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.overflow = Some(error);
                return;
            }
        };
        let retained = match checked_retained_bytes([
            &base.storage,
            promoted.as_ref(),
            &self.staged,
        ])
        .and_then(|retained| {
            retained
                .checked_add(if self.staged.is_empty() {
                    LEASE_STORAGE_BASE_BYTES
                } else {
                    0
                })
                .and_then(|retained| retained.checked_add(candidate_bytes))
                .ok_or(SemanticArtifactLeaseError::RetainedBytesOverflow)
        }) {
            Ok(retained) => retained,
            Err(error) => {
                self.overflow = Some(error);
                return;
            }
        };
        let attempted = match retained.checked_add(self.other_live_bytes) {
            Some(attempted) => attempted,
            None => {
                self.overflow = Some(SemanticArtifactLeaseError::RetainedBytesOverflow);
                return;
            }
        };
        if attempted > self.max_retained_bytes {
            self.overflow = Some(SemanticArtifactLeaseError::Capacity(
                SemanticArtifactLeaseCapacityExceeded {
                    limit: self.max_retained_bytes,
                    attempted,
                },
            ));
            return;
        }
        assert_eq!(
            self.staged.try_insert(SemanticArtifactLease::new(
                file.clone(),
                Arc::clone(artifact),
            )),
            Ok(true),
            "prechecked semantic lease candidate must fit"
        );
    }
}

/// One-shot additions produced by a child lease scope.
#[derive(Debug)]
pub struct SemanticArtifactLeaseCharge {
    #[doc(hidden)]
    pub scope: Arc<SemanticArtifactLeaseScope>,
    #[doc(hidden)]
    pub expected_generation: u64,
    #[doc(hidden)]
    pub additions: LeaseStorage,
}

impl SemanticArtifactLeaseCharge {
    pub fn len(&self) -> usize {
        self.additions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.additions.is_empty()
    }

    pub fn retained_bytes(&self) -> usize {
        self.additions.retained_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticArtifactLeaseCapacityExceeded {
    #[doc(hidden)]
    pub limit: usize,
    #[doc(hidden)]
    pub attempted: usize,
}

impl SemanticArtifactLeaseCapacityExceeded {
    pub const fn limit(self) -> usize {
        self.limit
    }

    pub const fn attempted(self) -> usize {
        self.attempted
    }
}

impl fmt::Display for SemanticArtifactLeaseCapacityExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "semantic artifact leases attempted {} retained bytes against limit {}",
            self.attempted, self.limit
        )
    }
}

impl std::error::Error for SemanticArtifactLeaseCapacityExceeded {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticArtifactLeaseError {
    Capacity(SemanticArtifactLeaseCapacityExceeded),
    WrongScope,
    StaleGeneration { expected: u64, actual: u64 },
    Overlap,
    OutstandingGeneration,
    RetainedBytesOverflow,
    GenerationOverflow,
}

impl fmt::Display for SemanticArtifactLeaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity(exceeded) => exceeded.fmt(formatter),
            Self::WrongScope => formatter.write_str("semantic artifact lease scope mismatch"),
            Self::StaleGeneration { expected, actual } => write!(
                formatter,
                "semantic artifact lease generation changed from {expected} to {actual}"
            ),
            Self::Overlap => formatter.write_str("semantic artifact lease charge overlaps parent"),
            Self::OutstandingGeneration => formatter.write_str(
                "semantic artifact lease generation still has outstanding snapshots or children",
            ),
            Self::RetainedBytesOverflow => {
                formatter.write_str("semantic artifact lease retained-byte arithmetic overflowed")
            }
            Self::GenerationOverflow => {
                formatter.write_str("semantic artifact lease generation overflowed")
            }
        }
    }
}

impl std::error::Error for SemanticArtifactLeaseError {}

/// Cloneable observer attached to semantic requests.
///
/// Production callers obtain this opaque handle only from
/// [`SemanticArtifactLeaseWindow::collector`]. The provider can observe
/// complete artifacts and callers can inspect overflow, but no public method
/// drains or serves the cap-accounted Arcs.
#[derive(Debug, Clone)]
pub struct SemanticArtifactCollector {
    state: SemanticArtifactCollectorState,
}

#[derive(Debug, Clone)]
enum SemanticArtifactCollectorState {
    #[cfg(any(test, feature = "test-support"))]
    Unbounded(Arc<Mutex<UnboundedCollectorState>>),
    Bounded(Arc<Mutex<LeaseWindowState>>),
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default)]
struct UnboundedCollectorState {
    storage: LeaseStorage,
    overflow: Option<SemanticArtifactLeaseError>,
}

impl SemanticArtifactCollector {
    /// Construct a caller-managed unbounded collector for internal adapters.
    ///
    /// Production continuations must obtain their collector from a bounded
    /// [`SemanticArtifactLeaseWindow`].
    // This internal test-support helper is public only across the crate boundary.
    #[allow(clippy::new_without_default)]
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn new() -> Self {
        Self {
            state: SemanticArtifactCollectorState::Unbounded(Arc::new(Mutex::new(
                UnboundedCollectorState::default(),
            ))),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn shares_state(&self, other: &Self) -> bool {
        match (&self.state, &other.state) {
            (
                SemanticArtifactCollectorState::Unbounded(left),
                SemanticArtifactCollectorState::Unbounded(right),
            ) => Arc::ptr_eq(left, right),
            (
                SemanticArtifactCollectorState::Bounded(left),
                SemanticArtifactCollectorState::Bounded(right),
            ) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn unbounded_state(&self) -> MutexGuard<'_, UnboundedCollectorState> {
        let SemanticArtifactCollectorState::Unbounded(state) = &self.state else {
            panic!("bounded semantic artifact collectors cannot drain leases");
        };
        state
            .lock()
            .expect("semantic artifact collector mutex poisoned")
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn take_complete(&self, file: &ProjectFile) -> Vec<SemanticArtifactLease> {
        self.unbounded_state().storage.take_file(file)
    }

    /// Atomically drain every complete artifact in this collector window.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn take_all_complete(&self) -> Vec<SemanticArtifactLease> {
        let mut complete = self.unbounded_state().storage.take_all();
        complete.sort_by(|left, right| left.file.cmp(&right.file));
        complete
    }

    /// Return the first bounded-window refusal, if any.
    pub fn overflow(&self) -> Option<SemanticArtifactLeaseError> {
        match &self.state {
            #[cfg(any(test, feature = "test-support"))]
            SemanticArtifactCollectorState::Unbounded(state) => {
                state
                    .lock()
                    .expect("semantic artifact collector mutex poisoned")
                    .overflow
            }
            SemanticArtifactCollectorState::Bounded(state) => {
                state
                    .lock()
                    .expect("semantic artifact lease window mutex poisoned")
                    .overflow
            }
        }
    }

    #[doc(hidden)]
    pub fn observe_complete(&self, file: &ProjectFile, artifact: &Arc<SemanticArtifact>) {
        match &self.state {
            #[cfg(any(test, feature = "test-support"))]
            SemanticArtifactCollectorState::Unbounded(state) => {
                let mut state = state
                    .lock()
                    .expect("semantic artifact collector mutex poisoned");
                if state.overflow.is_some() || state.storage.contains_artifact(artifact) {
                    return;
                }
                match state.storage.try_insert(SemanticArtifactLease::new(
                    file.clone(),
                    Arc::clone(artifact),
                )) {
                    Ok(true) => {}
                    Ok(false) => unreachable!("exact lease duplicate was prechecked"),
                    Err(error) => state.overflow = Some(error),
                }
            }
            SemanticArtifactCollectorState::Bounded(state) => state
                .lock()
                .expect("semantic artifact lease window mutex poisoned")
                .observe_complete(file, artifact),
        }
    }

    // This internal test-support helper is public only across the crate boundary.
    #[allow(clippy::len_without_is_empty)]
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn len(&self) -> usize {
        match &self.state {
            SemanticArtifactCollectorState::Unbounded(state) => state
                .lock()
                .expect("semantic artifact collector mutex poisoned")
                .storage
                .len(),
            SemanticArtifactCollectorState::Bounded(state) => state
                .lock()
                .expect("semantic artifact lease window mutex poisoned")
                .staged
                .len(),
        }
    }
}
