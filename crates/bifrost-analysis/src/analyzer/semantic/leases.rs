//! Bounded strong leases for complete semantic artifact allocations.
//!
//! A lease is deliberately not an artifact cache. It preserves the exact
//! allocation that produced pointer-scoped semantic handles while ordinary
//! provider lookup continues to derive and validate the current artifact key.

use std::collections::HashMap;
use std::fmt;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::analyzer::ProjectFile;

use super::ids::StableDigest;
use super::ir::SemanticArtifact;
use super::service::semantic_artifact_retained_bytes;

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
const LEASE_STORAGE_BASE_BYTES: usize = ARC_HEADER_BYTES
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
pub(crate) struct SemanticArtifactLease {
    file: ProjectFile,
    artifact: Arc<SemanticArtifact>,
}

impl SemanticArtifactLease {
    fn new(file: ProjectFile, artifact: Arc<SemanticArtifact>) -> Self {
        Self { file, artifact }
    }

    #[cfg(test)]
    pub(crate) const fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(crate) const fn artifact(&self) -> &Arc<SemanticArtifact> {
        &self.artifact
    }

    fn retained_bytes(&self) -> Result<usize, SemanticArtifactLeaseError> {
        retained_artifact_bytes(&self.file, &self.artifact)
    }
}

fn retained_artifact_bytes(
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
struct LeaseStorage {
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

    fn try_insert(
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

    #[cfg(test)]
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

    #[cfg(test)]
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

#[derive(Debug)]
struct SemanticArtifactLeaseScope;

#[derive(Debug, Clone, Default)]
struct LeaseState {
    generation: u64,
    storage: LeaseStorage,
}

/// A committed, bounded set of exact semantic artifact allocations.
///
/// The set is intentionally non-`Clone`: mutations advance one logical
/// generation. Cloneable snapshots are the only way to fork additions, and a
/// one-shot charge must reconcile against that exact generation.
#[derive(Debug)]
pub struct SemanticArtifactLeaseSet {
    max_retained_bytes: usize,
    scope: Arc<SemanticArtifactLeaseScope>,
    state: Arc<LeaseState>,
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
        self.state.storage.retained_bytes()
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

    #[cfg(test)]
    fn state_identity(&self) -> usize {
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
        self.state.storage.retained_bytes()
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
    additions: Arc<LeaseStorage>,
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
        let overflow = match checked_attempted_retained_bytes(
            [&self.base.storage, self.additions.as_ref()],
            other_live_bytes,
        ) {
            Ok(attempted) if attempted > self.max_retained_bytes => Some(
                SemanticArtifactLeaseError::Capacity(SemanticArtifactLeaseCapacityExceeded {
                    limit: self.max_retained_bytes,
                    attempted,
                }),
            ),
            Ok(_) => None,
            Err(error) => Some(error),
        };
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
        self.base.storage.contains_artifact(artifact) || self.additions.contains_artifact(artifact)
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
        let attempted = match checked_attempted_retained_bytes(
            [&base.storage, promoted, &state.staged],
            next_other_live_bytes,
        ) {
            Ok(attempted) => attempted,
            Err(error) => {
                state.overflow = Some(error);
                return Err(error);
            }
        };
        if attempted > state.max_retained_bytes {
            let error =
                SemanticArtifactLeaseError::Capacity(SemanticArtifactLeaseCapacityExceeded {
                    limit: state.max_retained_bytes,
                    attempted,
                });
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
        state
            .base
            .as_ref()
            .is_some_and(|base| base.storage.contains_artifact(artifact))
            || state
                .promoted
                .as_ref()
                .is_some_and(|promoted| promoted.contains_artifact(artifact))
            || state.staged.contains_artifact(artifact)
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
    scope: Arc<SemanticArtifactLeaseScope>,
    expected_generation: u64,
    additions: LeaseStorage,
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
    limit: usize,
    attempted: usize,
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
    #[cfg(test)]
    Unbounded(Arc<Mutex<UnboundedCollectorState>>),
    Bounded(Arc<Mutex<LeaseWindowState>>),
}

#[cfg(test)]
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
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self {
            state: SemanticArtifactCollectorState::Unbounded(Arc::new(Mutex::new(
                UnboundedCollectorState::default(),
            ))),
        }
    }

    #[cfg(test)]
    pub(crate) fn take_complete(&self, file: &ProjectFile) -> Vec<SemanticArtifactLease> {
        match &self.state {
            SemanticArtifactCollectorState::Unbounded(state) => state
                .lock()
                .expect("semantic artifact collector mutex poisoned")
                .storage
                .take_file(file),
            SemanticArtifactCollectorState::Bounded(_) => {
                panic!("bounded semantic artifact collectors cannot drain leases")
            }
        }
    }

    /// Atomically drain every complete artifact in this collector window.
    #[cfg(test)]
    pub(crate) fn take_all_complete(&self) -> Vec<SemanticArtifactLease> {
        let mut complete = match &self.state {
            SemanticArtifactCollectorState::Unbounded(state) => state
                .lock()
                .expect("semantic artifact collector mutex poisoned")
                .storage
                .take_all(),
            SemanticArtifactCollectorState::Bounded(_) => {
                panic!("bounded semantic artifact collectors cannot drain leases")
            }
        };
        complete.sort_by(|left, right| left.file.cmp(&right.file));
        complete
    }

    /// Return the first bounded-window refusal, if any.
    pub fn overflow(&self) -> Option<SemanticArtifactLeaseError> {
        match &self.state {
            #[cfg(test)]
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

    pub(crate) fn observe_complete(&self, file: &ProjectFile, artifact: &Arc<SemanticArtifact>) {
        match &self.state {
            #[cfg(test)]
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

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
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

    #[cfg(test)]
    pub(crate) fn shares_state(&self, other: &Self) -> bool {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::analyzer::semantic::{
        AdapterSemanticsVersion, ConfigurationFingerprint, ContentIdentity, DependencyFingerprint,
        SemanticArtifactKey, SemanticCapabilities, SemanticIrVersion, SemanticLanguage,
        SourceRevision, WorkspaceMountId, WorkspaceRelativePath,
    };

    fn file(path: &str) -> ProjectFile {
        ProjectFile::new(std::env::temp_dir(), path)
    }

    fn artifact(path: &str, source: &str) -> Arc<SemanticArtifact> {
        let key = SemanticArtifactKey::new(
            WorkspaceMountId::hash_bytes(b"semantic lease test mount"),
            WorkspaceRelativePath::new(path).expect("portable fixture path"),
            SemanticLanguage::Standard(Language::TypeScript),
            SourceRevision::Disk {
                content: ContentIdentity::hash_bytes(source.as_bytes()),
            },
            AdapterSemanticsVersion::hash_bytes("lease-test-typescript", b"adapter")
                .expect("non-empty adapter name"),
            SemanticIrVersion::hash_bytes(b"lease test IR"),
            ConfigurationFingerprint::hash_bytes(b"lease test configuration"),
            DependencyFingerprint::hash_bytes(b"lease test dependencies"),
        );
        Arc::new(
            SemanticArtifact::try_new(key, SemanticCapabilities::default(), Vec::new())
                .expect("empty complete fixture artifact"),
        )
    }

    fn observe(
        collector: &SemanticArtifactCollector,
        file: &ProjectFile,
        artifact: &Arc<SemanticArtifact>,
    ) {
        collector.observe_complete(file, artifact);
    }

    fn one_lease_retained_bytes(file: &ProjectFile, artifact: &Arc<SemanticArtifact>) -> usize {
        LEASE_STORAGE_BASE_BYTES
            .checked_add(
                retained_artifact_bytes(file, artifact).expect("fixture lease weight fits usize"),
            )
            .expect("fixture storage weight fits usize")
    }

    #[test]
    fn exact_artifact_allocation_is_retained_once() {
        let file = file("src/once.ts");
        let artifact = artifact("src/once.ts", "export const once = 1;\n");
        let mut leases = SemanticArtifactLeaseSet::new(usize::MAX);
        let mut child = leases.snapshot().into_child();
        let window = child.begin_window(0);
        let collector = window.collector();

        observe(&collector, &file, &artifact);
        observe(&collector, &file, &artifact);
        assert_eq!(collector.len(), 1);
        drop(collector);
        window.commit(&mut child).expect("one lease fits");
        let charge = child.into_charge();
        assert_eq!(charge.len(), 1);
        leases
            .try_apply_charge(charge, 0)
            .expect("one lease charge applies");
        assert_eq!(leases.len(), 1);
    }

    #[test]
    fn distinct_allocations_with_the_same_key_are_retained_separately() {
        let file = file("src/twins.ts");
        let first = artifact("src/twins.ts", "export const twins = 1;\n");
        let second = artifact("src/twins.ts", "export const twins = 1;\n");
        let third = artifact("src/twins.ts", "export const twins = 1;\n");
        assert_eq!(first.key(), second.key());
        assert!(!Arc::ptr_eq(&first, &second));

        let mut leases = SemanticArtifactLeaseSet::new(usize::MAX);
        let mut child = leases.snapshot().into_child();
        let window = child.begin_window(0);
        let collector = window.collector();
        observe(&collector, &file, &first);
        observe(&collector, &file, &second);
        drop(collector);
        window
            .commit(&mut child)
            .expect("both exact allocations fit");
        assert!(child.contains_exact(&first));
        assert!(child.contains_exact(&second));
        assert!(!child.contains_exact(&third));
        let charge = child.into_charge();
        assert_eq!(charge.len(), 2);
        leases
            .try_apply_charge(charge, 0)
            .expect("both exact allocations apply");
        assert_eq!(leases.len(), 2);
        let snapshot = leases.snapshot();
        assert!(snapshot.contains_exact(&first));
        assert!(snapshot.contains_exact(&second));
        assert!(!snapshot.contains_exact(&third));
    }

    #[test]
    fn apply_preflights_the_whole_batch_and_source_headroom_atomically() {
        let first_file = file("src/first.ts");
        let first = artifact("src/first.ts", "export const first = 1;\n");
        let second_file = file("src/second.ts");
        let second = artifact("src/second.ts", "export const second = 2;\n");
        let first_bytes = one_lease_retained_bytes(&first_file, &first);
        let second_bytes = retained_artifact_bytes(&second_file, &second)
            .expect("second fixture lease weight fits usize");
        let cap = first_bytes
            .checked_add(LEASE_STORAGE_BASE_BYTES)
            .and_then(|bytes| bytes.checked_add(second_bytes))
            .expect("two live lease storages fit usize");
        let mut leases = SemanticArtifactLeaseSet::new(cap);

        let mut first_child = leases.snapshot().into_child();
        let first_window = first_child.begin_window(0);
        let collector = first_window.collector();
        observe(&collector, &first_file, &first);
        drop(collector);
        first_window
            .commit(&mut first_child)
            .expect("first artifact fits");
        leases
            .try_apply_charge(first_child.into_charge(), 0)
            .expect("first artifact applies");
        let before_len = leases.len();
        let before_bytes = leases.retained_bytes();

        let mut second_child = leases.snapshot().into_child();
        assert_eq!(second_child.len(), 1);
        assert_eq!(second_child.additions_len(), 0);
        let second_window = second_child.begin_window(0);
        assert!(second_window.contains_exact(&first));
        assert!(!second_window.contains_exact(&second));
        let collector = second_window.collector();
        observe(&collector, &second_file, &second);
        assert!(second_window.contains_exact(&second));
        drop(collector);
        second_window
            .commit(&mut second_child)
            .expect("second artifact fits without a live source");
        assert_eq!(second_child.len(), 2);
        assert_eq!(second_child.additions_len(), 1);
        let error = leases
            .try_apply_charge(second_child.into_charge(), 1)
            .expect_err("one live source byte exceeds the shared physical cap");
        assert!(matches!(
            error,
            SemanticArtifactLeaseError::Capacity(
                SemanticArtifactLeaseCapacityExceeded { limit, attempted }
            ) if limit == cap && attempted == cap + 1
        ));
        assert_eq!(leases.len(), before_len);
        assert_eq!(leases.retained_bytes(), before_bytes);
    }

    #[test]
    fn windows_discard_or_promote_into_one_cumulative_child() {
        let first_file = file("src/first.ts");
        let first = artifact("src/first.ts", "export const first = 1;\n");
        let second_file = file("src/second.ts");
        let second = artifact("src/second.ts", "export const second = 2;\n");
        let mut leases = SemanticArtifactLeaseSet::new(usize::MAX);
        let mut child = leases.snapshot().into_child();

        let discarded = child.begin_window(0);
        let collector = discarded.collector();
        observe(&collector, &first_file, &first);
        drop(collector);
        discarded.discard();

        let first_window = child.begin_window(0);
        let collector = first_window.collector();
        observe(&collector, &first_file, &first);
        drop(collector);
        first_window
            .commit(&mut child)
            .expect("first positive window fits");

        let second_window = child.begin_window(0);
        let collector = second_window.collector();
        observe(&collector, &first_file, &first);
        observe(&collector, &second_file, &second);
        assert_eq!(collector.len(), 1, "the promoted first Arc is deduplicated");
        drop(collector);
        second_window
            .commit(&mut child)
            .expect("second positive window fits");

        let charge = child.into_charge();
        assert_eq!(charge.len(), 2);
        leases
            .try_apply_charge(charge, 0)
            .expect("cumulative positive windows apply");
        assert_eq!(leases.len(), 2);
    }

    #[test]
    fn charges_reject_wrong_scope_stale_replay_and_overlap() {
        let file = file("src/scope.ts");
        let artifact = artifact("src/scope.ts", "export const scope = 1;\n");
        let mut first_set = SemanticArtifactLeaseSet::new(usize::MAX);
        let mut unrelated = SemanticArtifactLeaseSet::new(usize::MAX);

        let wrong_scope = first_set.snapshot().into_child().into_charge();
        assert_eq!(
            unrelated.try_apply_charge(wrong_scope, 0),
            Err(SemanticArtifactLeaseError::WrongScope)
        );

        let shared_snapshot = first_set.snapshot();
        let first_charge = shared_snapshot.clone().into_child().into_charge();
        let replay = shared_snapshot.into_child().into_charge();
        first_set
            .try_apply_charge(first_charge, 0)
            .expect("first one-shot generation applies");
        assert_eq!(
            first_set.try_apply_charge(replay, 0),
            Err(SemanticArtifactLeaseError::StaleGeneration {
                expected: 0,
                actual: 1,
            })
        );

        let mut overlap = LeaseStorage::default();
        assert_eq!(
            overlap.try_insert(SemanticArtifactLease::new(
                file.clone(),
                Arc::clone(&artifact),
            )),
            Ok(true)
        );
        let current = SemanticArtifactLeaseCharge {
            scope: Arc::clone(&first_set.scope),
            expected_generation: first_set.state.generation,
            additions: overlap,
        };
        first_set
            .try_apply_charge(current, 0)
            .expect("first artifact is not yet in the committed set");

        let mut duplicate = LeaseStorage::default();
        assert_eq!(
            duplicate.try_insert(SemanticArtifactLease::new(file, artifact)),
            Ok(true)
        );
        let overlapping = SemanticArtifactLeaseCharge {
            scope: Arc::clone(&first_set.scope),
            expected_generation: first_set.state.generation,
            additions: duplicate,
        };
        assert_eq!(
            first_set.try_apply_charge(overlapping, 0),
            Err(SemanticArtifactLeaseError::Overlap)
        );
    }

    #[test]
    fn consumed_snapshot_allows_sequential_apply_without_state_cow() {
        let file = file("src/in_place.ts");
        let artifact = artifact("src/in_place.ts", "export const inPlace = 1;\n");
        let mut leases = SemanticArtifactLeaseSet::new(usize::MAX);
        let before = leases.state_identity();
        let mut child = leases.snapshot().into_child();
        let window = child.begin_window(0);
        let collector = window.collector();
        observe(&collector, &file, &artifact);
        drop(collector);
        window.commit(&mut child).expect("lease fits");
        let charge = child.into_charge();

        leases
            .try_apply_charge(charge, 0)
            .expect("consumed snapshot charge applies");
        assert_eq!(
            leases.state_identity(),
            before,
            "without a live snapshot the state allocation is updated in place"
        );
    }

    #[test]
    fn apply_rejects_an_outstanding_snapshot_without_cloning_state() {
        let file = file("src/outstanding.ts");
        let artifact = artifact("src/outstanding.ts", "export const outstanding = 1;\n");
        let mut leases = SemanticArtifactLeaseSet::new(usize::MAX);
        let mut initial_child = leases.snapshot().into_child();
        let window = initial_child.begin_window(0);
        let collector = window.collector();
        observe(&collector, &file, &artifact);
        drop(collector);
        window
            .commit(&mut initial_child)
            .expect("initial lease fits");
        leases
            .try_apply_charge(initial_child.into_charge(), 0)
            .expect("initial lease applies");

        let outstanding = leases.snapshot();
        let charge = outstanding.clone().into_child().into_charge();
        let before_generation = leases.state.generation;
        let before_len = leases.len();
        let before_bytes = leases.retained_bytes();
        let before_state = leases.state_identity();
        assert_eq!(
            leases.try_apply_charge(charge, 0),
            Err(SemanticArtifactLeaseError::OutstandingGeneration)
        );
        assert_eq!(leases.state.generation, before_generation);
        assert_eq!(leases.len(), before_len);
        assert_eq!(leases.retained_bytes(), before_bytes);
        assert_eq!(leases.state_identity(), before_state);

        drop(outstanding);
        let fresh_charge = leases.snapshot().into_child().into_charge();
        leases
            .try_apply_charge(fresh_charge, 0)
            .expect("a consumed fresh snapshot applies in place");
        assert_eq!(leases.state.generation, before_generation + 1);
        assert_eq!(leases.state_identity(), before_state);
    }

    #[test]
    fn charge_weight_accounts_for_long_project_file_storage() {
        let artifact = artifact("src/weight.ts", "export const weight = 1;\n");
        let short_file = file("src/weight.ts");
        let long_path = format!("src/{}/weight.ts", "nested/".repeat(128));
        let long_file = file(&long_path);
        let charge_for = |file: ProjectFile| {
            let mut additions = LeaseStorage::default();
            assert_eq!(
                additions.try_insert(SemanticArtifactLease::new(file, Arc::clone(&artifact),)),
                Ok(true)
            );
            SemanticArtifactLeaseCharge {
                scope: Arc::new(SemanticArtifactLeaseScope),
                expected_generation: 0,
                additions,
            }
        };

        let short = charge_for(short_file).retained_bytes();
        let long = charge_for(long_file).retained_bytes();
        assert!(
            long >= short.saturating_add(long_path.len() / 2),
            "lease charge weights must include owned ProjectFile paths"
        );
    }

    #[test]
    fn child_allows_only_one_live_window_and_seals_late_collectors() {
        let file = file("src/window.ts");
        let artifact = artifact("src/window.ts", "export const window = 1;\n");
        let leases = SemanticArtifactLeaseSet::new(usize::MAX);
        let mut child = leases.snapshot().into_child();
        let first = child.begin_window(0);
        let late_collector = first.collector();

        let second =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| child.begin_window(0)));
        assert!(second.is_err(), "one child cannot own concurrent windows");

        first.discard();
        assert_eq!(
            Arc::strong_count(&child.additions),
            1,
            "closing a window releases its promoted snapshot before publishing the child reusable"
        );
        observe(&late_collector, &file, &artifact);
        assert_eq!(late_collector.len(), 0, "sealed collectors retain nothing");
        drop(late_collector);

        let replacement = child.begin_window(0);
        replacement.discard();
        assert_eq!(child.into_charge().len(), 0);
    }

    #[test]
    fn window_rejects_a_different_child_from_the_same_snapshot() {
        let file = file("src/wrong_child.ts");
        let artifact = artifact("src/wrong_child.ts", "export const wrongChild = 1;\n");
        let leases = SemanticArtifactLeaseSet::new(usize::MAX);
        let snapshot = leases.snapshot();
        let mut first_child = snapshot.clone().into_child();
        let mut second_child = snapshot.into_child();
        let first_window = first_child.begin_window(0);
        let collector = first_window.collector();
        observe(&collector, &file, &artifact);
        drop(collector);
        let second_window = second_child.begin_window(0);

        assert_eq!(
            first_window.commit(&mut second_child),
            Err(SemanticArtifactLeaseError::WrongScope)
        );
        second_window.discard();
        assert_eq!(first_child.into_charge().len(), 0);
        assert_eq!(second_child.into_charge().len(), 0);
    }

    #[test]
    fn bounded_collector_latches_retained_byte_arithmetic_overflow() {
        let file = file("src/arithmetic.ts");
        let artifact = artifact("src/arithmetic.ts", "export const arithmetic = 1;\n");
        let leases = SemanticArtifactLeaseSet::new(usize::MAX);
        let mut child = leases.snapshot().into_child();
        let window = child.begin_window(usize::MAX);
        assert_eq!(window.overflow(), None, "source alone exactly fits usize");
        let collector = window.collector();

        observe(&collector, &file, &artifact);
        assert_eq!(
            collector.overflow(),
            Some(SemanticArtifactLeaseError::RetainedBytesOverflow)
        );
        assert_eq!(collector.len(), 0);
        drop(collector);
        assert_eq!(
            window.commit(&mut child),
            Err(SemanticArtifactLeaseError::RetainedBytesOverflow)
        );
        assert_eq!(child.into_charge().len(), 0);
    }

    #[test]
    fn bounded_collector_cannot_drain_cap_accounted_leases() {
        let file = file("src/no_drain.ts");
        let artifact = artifact("src/no_drain.ts", "export const noDrain = 1;\n");
        let mut leases = SemanticArtifactLeaseSet::new(usize::MAX);
        let mut child = leases.snapshot().into_child();
        let window = child.begin_window(0);
        let collector = window.collector();
        observe(&collector, &file, &artifact);

        let one_file = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            collector.take_complete(&file)
        }));
        assert!(
            one_file.is_err(),
            "bounded collectors cannot drain one file"
        );
        let all = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            collector.take_all_complete()
        }));
        assert!(all.is_err(), "bounded collectors cannot drain a window");
        assert_eq!(collector.len(), 1, "failed drains retain the staged lease");

        drop(collector);
        window
            .commit(&mut child)
            .expect("the still-accounted lease commits");
        leases
            .try_apply_charge(child.into_charge(), 0)
            .expect("the still-accounted lease applies");
        assert_eq!(leases.len(), 1);
    }

    #[test]
    fn caller_owned_window_reservations_shrink_or_rollback_atomically() {
        let file = file("src/reservation.ts");
        let artifact = artifact("src/reservation.ts", "export const reservation = 1;\n");
        let artifact_bytes = one_lease_retained_bytes(&file, &artifact);
        let cap = artifact_bytes + 8;

        let leases = SemanticArtifactLeaseSet::new(cap);
        let mut child = leases.snapshot().into_child();
        let rollback_window = child.begin_window(0);
        let collector = rollback_window.collector();
        observe(&collector, &file, &artifact);
        drop(collector);
        let rollback = rollback_window
            .reserve_other_live_bytes(8)
            .expect("the full caller-owned reservation fits");
        drop(rollback);
        rollback_window
            .commit(&mut child)
            .expect("dropping a reservation restores all headroom");

        let exact_window = child.begin_window(0);
        let exact = exact_window
            .reserve_other_live_bytes(8)
            .expect("the conservative caller-owned reservation fits");
        let retained = vec![0_u8; 3].into_boxed_slice();
        exact.retain_exact(retained.len());
        exact_window
            .commit(&mut child)
            .expect("shrinking retains only the exact caller-owned bytes");
        drop(retained);

        let overflow_window = child.begin_window(0);
        let error = overflow_window
            .reserve_other_live_bytes(9)
            .expect_err("one byte beyond the physical authority is refused");
        assert_eq!(
            error,
            SemanticArtifactLeaseError::Capacity(SemanticArtifactLeaseCapacityExceeded {
                limit: cap,
                attempted: cap + 1,
            })
        );
        assert_eq!(
            overflow_window.retained_bytes(),
            artifact_bytes,
            "a refused caller-owned reservation mutates no retained lease storage"
        );
        assert_eq!(overflow_window.commit(&mut child), Err(error));
        assert_eq!(child.len(), 1);

        let delayed_window = child.begin_window(0);
        let delayed = delayed_window
            .reserve_other_live_bytes(8)
            .expect("a final reservation fits");
        drop(delayed_window);
        let premature_reuse =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| child.begin_window(0)));
        assert!(
            premature_reuse.is_err(),
            "dropping a window cannot publish its child while a reservation remains live"
        );
        drop(delayed);
        child.begin_window(0).discard();
        assert_eq!(child.len(), 1);
    }

    #[test]
    fn caller_owned_window_reservations_participate_in_artifact_admission() {
        let file = file("src/reserved-admission.ts");
        let artifact = artifact(
            "src/reserved-admission.ts",
            "export const reservedAdmission = 1;\n",
        );
        let artifact_bytes = one_lease_retained_bytes(&file, &artifact);
        let caller_bytes = 8;
        let cap = artifact_bytes + caller_bytes - 1;

        let leases = SemanticArtifactLeaseSet::new(cap);
        let mut child = leases.snapshot().into_child();
        let window = child.begin_window(0);
        let reservation = window
            .reserve_other_live_bytes(caller_bytes)
            .expect("caller-owned bytes fit before artifact observation");
        let retained = vec![0_u8; caller_bytes].into_boxed_slice();
        reservation.retain_exact(retained.len());
        let collector = window.collector();
        let original_strong_count = Arc::strong_count(&artifact);

        observe(&collector, &file, &artifact);

        let error = collector
            .overflow()
            .expect("caller-owned bytes leave one byte too little for the artifact");
        assert_eq!(
            error,
            SemanticArtifactLeaseError::Capacity(SemanticArtifactLeaseCapacityExceeded {
                limit: cap,
                attempted: artifact_bytes + caller_bytes,
            })
        );
        assert_eq!(collector.len(), 0);
        assert_eq!(Arc::strong_count(&artifact), original_strong_count);
        drop(collector);
        assert_eq!(window.commit(&mut child), Err(error));
        drop(retained);
        assert_eq!(child.into_charge().len(), 0);
    }

    #[test]
    fn bounded_collector_latches_overflow_without_retaining_candidates() {
        let first_file = file("src/overflow.ts");
        let first = artifact("src/overflow.ts", "export const overflow = 1;\n");
        let second_file = file("src/later.ts");
        let second = artifact("src/later.ts", "export const later = 2;\n");
        let required = one_lease_retained_bytes(&first_file, &first);
        let leases = SemanticArtifactLeaseSet::new(required.saturating_sub(1));
        let mut child = leases.snapshot().into_child();
        let window = child.begin_window(0);
        let collector = window.collector();
        let first_count = Arc::strong_count(&first);
        let second_count = Arc::strong_count(&second);

        observe(&collector, &first_file, &first);
        let overflow = collector.overflow().expect("first candidate exceeds cap");
        let SemanticArtifactLeaseError::Capacity(exceeded) = overflow else {
            panic!("first candidate must report typed capacity exhaustion")
        };
        assert_eq!(exceeded.limit(), required - 1);
        assert_eq!(exceeded.attempted(), required);
        assert!(
            window.retained_bytes() < exceeded.attempted(),
            "the refused candidate's attempted charge is not a live retained peak"
        );
        assert_eq!(collector.len(), 0);
        assert_eq!(Arc::strong_count(&first), first_count);

        observe(&collector, &second_file, &second);
        assert_eq!(collector.len(), 0, "overflow refuses every later new Arc");
        assert_eq!(Arc::strong_count(&second), second_count);
        drop(collector);
        assert_eq!(window.commit(&mut child), Err(overflow));
        assert_eq!(child.into_charge().len(), 0);
    }
}
