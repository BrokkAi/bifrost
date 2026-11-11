//! Demand-driven, budgeted derivations with recorded input verification.
use std::any::Any;
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::model::Language;
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_core::retention_budget::{
    BudgetRegion, BudgetedValue, RequestOwned, Retained, RetainedBytes, RetentionBudget,
};
use serde::{Deserialize, Serialize};

use super::ids::StableDigest;
use super::read_ledger::{LookupKind, LookupQuestion, ReadKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DerivationKindId(pub &'static str);

/// A selected revision authority; overlays and staged selections cannot publish.
pub trait DerivationAuthority: Clone + Eq + Hash + Send + Sync + RetainedBytes + 'static {
    fn retention_refusal(&self) -> Option<NotReusableCause>;
}
/// Opaque proof of a selected reader and snapshot. Unestablished tokens cannot hit a verification memo.
pub trait DerivationRevision: Clone + Eq + Hash + Send + Sync + RetainedBytes + 'static {
    fn is_established(&self) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DerivationQuestion {
    pub language: Option<Language>,
    pub subject: Option<[u8; 32]>,
    pub rel_path: Option<Box<str>>,
    pub name: Option<Box<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputIdentity(pub StableDigest);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotReusableCause {
    Cancelled,
    LimitReached,
    UnattributedRead,
    ExecutionDependent,
    InvalidDependencyEvidence,
    ChildNotReusable,
    OverlayAuthority,
    UnprovedStage,
    UnestablishedBinding,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReuseValidity {
    Reusable,
    NotReusable(NotReusableCause),
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UnavailableCause {
    StratumViolation,
    ChildUnavailable,
    ValidationFailed,
    Cancelled,
    Failed(Arc<str>),
}

pub enum Handle<O> {
    Retained(RetainedValue<O>),
    RequestOwned(RequestOwned<Arc<O>>),
}
pub struct RetainedValue<O> {
    _entry: Retained<Entry>,
    value: Arc<O>,
}
impl<O> Deref for RetainedValue<O> {
    type Target = O;
    fn deref(&self) -> &O {
        &self.value
    }
}
impl<O> Deref for Handle<O> {
    type Target = O;
    fn deref(&self) -> &O {
        match self {
            Self::Retained(value) => value,
            Self::RequestOwned(value) => value,
        }
    }
}
pub enum Demanded<O> {
    Available {
        value: Handle<O>,
        identity: OutputIdentity,
        complete: bool,
        validity: ReuseValidity,
    },
    Unavailable(UnavailableCause),
}

/// The observable part of a demand made from a recorded question.
pub enum ReplayedDemand {
    Available {
        identity: OutputIdentity,
        complete: bool,
        retained: bool,
        validity: ReuseValidity,
    },
    Unavailable(UnavailableCause),
}

pub enum Computed<O> {
    Available {
        value: O,
        complete: bool,
        validity: ReuseValidity,
    },
    Unavailable(UnavailableCause),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    BaseInputs,
    Recompute,
}

pub trait DerivationKind: Send + Sync + 'static {
    type Key: Clone + Eq + Hash + Send + Sync + RetainedBytes + 'static;
    type Output: Send + Sync + RetainedBytes + 'static;
    const ID: DerivationKindId;
    const QUESTION_SHAPE: super::read_ledger::PersistedDerivationFamily =
        super::read_ledger::PersistedDerivationFamily::new(Self::ID, false, false, false, false);
    const STRATUM: u16;
    const VERIFY: Verification = Verification::BaseInputs;
    /// Every kind this computation may demand, with its declared stratum.
    const CHILDREN: &'static [(DerivationKindId, u16)];
    fn question(key: &Self::Key) -> DerivationQuestion;
    fn key_from_question(question: &DerivationQuestion) -> Option<Self::Key>;
    fn compute<R, A>(
        &self,
        frame: &mut DerivationFrame<'_, R, A>,
        key: &Self::Key,
    ) -> Computed<Self::Output>
    where
        R: DerivationRevision,
        A: DerivationAuthority;
    fn output_projection(value: &Self::Output, hash: &mut CanonicalHasher);
}

pub struct CaptureReceipt {
    pub reads: Vec<ReadKey>,
    pub unattributed: usize,
    pub execution_dependences: Vec<NotReusableCause>,
    pub reuse_refusals: Vec<NotReusableCause>,
    pub persistence_refusals: usize,
    pub stable_reasons: Vec<String>,
}
pub trait CaptureHook<R, A>: Send + Sync {
    /// Opens a non-forwarding capture around `work`.
    fn capture(&self, revision: &R, authority: &A, work: &mut dyn FnMut()) -> CaptureReceipt;
    fn report_unattributed(&self);
    fn report_execution_dependence(&self, cause: NotReusableCause);
    fn report_reuse_refusal(&self, cause: NotReusableCause);
    fn report_persistence_refusals(&self, count: usize);
    fn replay_reasons(&self, reasons: &[String]);
    fn record(&self, read: ReadKey);
    /// Whether the request running on this thread has been cancelled. A
    /// follower of an in-flight demand uses it to tell its own cancellation
    /// from the leader's.
    fn cancelled(&self) -> bool {
        false
    }
}
pub trait BaseInputs<R, A>: Send + Sync {
    /// Return false when evidence is missing or the selected input changed.
    fn unchanged(&self, read: &ReadKey, since: &R, at: &R, authority: &A) -> bool;
    /// Verify `read` from `at`'s main state alone, never consulting stage or TEMP state.
    /// This may return false more often than `unchanged`, but never true when it returns false.
    fn unchanged_without_stage(
        &self,
        _read: &ReadKey,
        _since: &R,
        _at: &R,
        _authority: &A,
    ) -> bool {
        false
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct EntryKey {
    kind: DerivationKindId,
    question: DerivationQuestion,
}
impl RetainedBytes for EntryKey {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.kind.0.len()
            + self.question.rel_path.as_ref().map_or(0, |v| v.len())
            + self.question.name.as_ref().map_or(0, |v| v.len())
    }
}
struct Entry {
    output: Arc<dyn Any + Send + Sync>,
    output_bytes: usize,
    identity: OutputIdentity,
    reads: Vec<ReadKey>,
    reasons: Vec<String>,
    persistence_refusals: usize,
    complete: bool,
    verified: Mutex<Box<dyn Any + Send + Sync>>,
    verified_bytes: usize,
}
impl RetainedBytes for Entry {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.verified_bytes
            + self.output_bytes
            + self.reads.capacity() * std::mem::size_of::<ReadKey>()
            + self
                .reads
                .iter()
                .map(|read| {
                    read.retained_bytes()
                        .saturating_sub(std::mem::size_of::<ReadKey>())
                })
                .sum::<usize>()
            + self.reasons.capacity() * std::mem::size_of::<String>()
            + self.reasons.iter().map(|s| s.capacity()).sum::<usize>()
    }
}

trait Registered<R, A>: Send + Sync {
    fn question_shape(&self) -> super::read_ledger::PersistedDerivationFamily;
    fn accepts_question(&self, question: &DerivationQuestion) -> bool;
    fn stratum(&self) -> u16;
    fn verification(&self) -> Verification;
    fn children(&self) -> &'static [(DerivationKindId, u16)];
    fn compute(
        &self,
        frame: &mut DerivationFrame<'_, R, A>,
        question: &DerivationQuestion,
    ) -> Result<ComputedEntry, UnavailableCause>;
}
struct Kind<D>(D);
struct ComputedEntry {
    output: Arc<dyn Any + Send + Sync>,
    bytes: usize,
    projection: [u8; 32],
    complete: bool,
    validity: ReuseValidity,
}
impl<D, R, A> Registered<R, A> for Kind<D>
where
    D: DerivationKind,
    R: DerivationRevision,
    A: DerivationAuthority,
{
    fn question_shape(&self) -> super::read_ledger::PersistedDerivationFamily {
        D::QUESTION_SHAPE
    }
    fn accepts_question(&self, question: &DerivationQuestion) -> bool {
        D::key_from_question(question).is_some()
    }
    fn stratum(&self) -> u16 {
        D::STRATUM
    }
    fn verification(&self) -> Verification {
        D::VERIFY
    }
    fn children(&self) -> &'static [(DerivationKindId, u16)] {
        D::CHILDREN
    }
    fn compute(
        &self,
        frame: &mut DerivationFrame<'_, R, A>,
        question: &DerivationQuestion,
    ) -> Result<ComputedEntry, UnavailableCause> {
        let key = D::key_from_question(question).ok_or(UnavailableCause::ValidationFailed)?;
        let (value, complete, validity) = match self.0.compute(frame, &key) {
            Computed::Available {
                value,
                complete,
                validity,
            } => (value, complete, validity),
            Computed::Unavailable(cause) => return Err(cause),
        };
        let mut hash = CanonicalHasher::new(b"bifrost-derivation-output:v1");
        D::output_projection(&value, &mut hash);
        let bytes = value.retained_bytes();
        Ok(ComputedEntry {
            output: Arc::new(value),
            bytes,
            projection: hash.finish(),
            complete,
            validity,
        })
    }
}

#[derive(Default, Debug, Clone)]
pub struct KindCounters {
    pub current_hits: u64,
    pub verified_unchanged: u64,
    pub recomputed: u64,
    pub equal_identity: u64,
    pub not_retainable: u64,
    pub not_retainable_by_cause: HashMap<NotReusableCause, u64>,
    pub unavailable: u64,
    pub unavailable_by_cause: HashMap<UnavailableCause, u64>,
    pub evicted: u64,
}
#[derive(Clone)]
struct FlightOutcome {
    answer: ErasedDemand,
    effects: FlightEffects,
}
#[derive(Clone, Default)]
struct FlightEffects {
    unattributed: usize,
    execution_dependences: Vec<NotReusableCause>,
    reuse_refusals: Vec<NotReusableCause>,
    persistence_refusals: usize,
    stable_reasons: Vec<String>,
}
impl FlightEffects {
    fn cause(&mut self, cause: NotReusableCause) {
        match cause {
            NotReusableCause::UnattributedRead => self.unattributed += 1,
            NotReusableCause::Cancelled
            | NotReusableCause::LimitReached
            | NotReusableCause::ExecutionDependent => self.execution_dependences.push(cause),
            _ => self.reuse_refusals.push(cause),
        }
    }
    fn replay<R, A>(&self, capture: &dyn CaptureHook<R, A>) {
        for _ in 0..self.unattributed {
            capture.report_unattributed();
        }
        for &cause in &self.execution_dependences {
            capture.report_execution_dependence(cause);
        }
        for &cause in &self.reuse_refusals {
            capture.report_reuse_refusal(cause);
        }
        capture.report_persistence_refusals(self.persistence_refusals);
        capture.replay_reasons(&self.stable_reasons);
    }
}
impl FlightOutcome {
    /// Whether the leader's request was cancelled while computing this
    /// answer, directly or through a child.
    fn cancelled(&self) -> bool {
        matches!(
            self.answer,
            ErasedDemand::Unavailable(UnavailableCause::Cancelled)
        ) || self
            .effects
            .execution_dependences
            .contains(&NotReusableCause::Cancelled)
    }
}
struct Flight {
    completed: Mutex<Option<FlightOutcome>>,
    wake: Condvar,
}
impl Flight {
    fn new() -> Self {
        Self {
            completed: Mutex::new(None),
            wake: Condvar::new(),
        }
    }
}
struct State<R, A> {
    flights: HashMap<(EntryKey, R, A), Arc<Flight>>,
    counters: HashMap<DerivationKindId, KindCounters>,
}
pub struct DerivationEngine<R, A> {
    region: BudgetRegion<EntryKey, Entry>,
    state: Mutex<State<R, A>>,
    kinds: Mutex<HashMap<DerivationKindId, Arc<dyn Registered<R, A>>>>,
    evictions: Mutex<HashMap<DerivationKindId, Arc<AtomicU64>>>,
    capture: Arc<dyn CaptureHook<R, A>>,
    base: Arc<dyn BaseInputs<R, A>>,
}
impl<R, A> DerivationEngine<R, A>
where
    R: DerivationRevision,
    A: DerivationAuthority,
{
    fn report_cause(&self, cause: NotReusableCause) {
        match cause {
            NotReusableCause::UnattributedRead => self.capture.report_unattributed(),
            NotReusableCause::Cancelled
            | NotReusableCause::LimitReached
            | NotReusableCause::ExecutionDependent => {
                self.capture.report_execution_dependence(cause)
            }
            NotReusableCause::InvalidDependencyEvidence
            | NotReusableCause::ChildNotReusable
            | NotReusableCause::OverlayAuthority
            | NotReusableCause::UnprovedStage
            | NotReusableCause::UnestablishedBinding => self.capture.report_reuse_refusal(cause),
        }
    }
    fn forward_capture_refusals(&self, receipt: &CaptureReceipt) {
        for _ in 0..receipt.unattributed {
            self.capture.report_unattributed();
        }
        for &cause in &receipt.execution_dependences {
            self.capture.report_execution_dependence(cause);
        }
        for &cause in &receipt.reuse_refusals {
            self.capture.report_reuse_refusal(cause);
        }
        self.capture
            .report_persistence_refusals(receipt.persistence_refusals);
    }
    pub fn new(
        budget: &RetentionBudget,
        capture: Arc<dyn CaptureHook<R, A>>,
        base: Arc<dyn BaseInputs<R, A>>,
    ) -> Self {
        Self {
            region: budget.region("semantic-derivations", None),
            state: Mutex::new(State {
                flights: HashMap::default(),
                counters: HashMap::default(),
            }),
            kinds: Mutex::new(HashMap::default()),
            evictions: Mutex::new(HashMap::default()),
            capture,
            base,
        }
    }
    pub fn registered_question_shapes(&self) -> Vec<super::read_ledger::PersistedDerivationFamily> {
        self.kinds
            .lock()
            .expect("kind registry poisoned")
            .values()
            .map(|kind| kind.question_shape())
            .collect()
    }
    pub fn register<D: DerivationKind>(&self, kind: D) {
        let mut kinds = self.kinds.lock().expect("kind registry poisoned");
        for &(child, declared_stratum) in D::CHILDREN {
            debug_assert!(
                declared_stratum < D::STRATUM,
                "derivation stratum violation"
            );
            debug_assert!(
                kinds
                    .get(&child)
                    .is_some_and(|registered| registered.stratum() == declared_stratum),
                "derivation child must be registered first at declared stratum"
            );
        }
        assert!(
            kinds.insert(D::ID, Arc::new(Kind(kind))).is_none(),
            "duplicate derivation kind"
        );
        self.evictions
            .lock()
            .expect("eviction counters poisoned")
            .insert(D::ID, Arc::new(AtomicU64::new(0)));
    }
    pub fn counters(&self, kind: DerivationKindId) -> KindCounters {
        let mut counters = self
            .state
            .lock()
            .expect("engine state poisoned")
            .counters
            .get(&kind)
            .cloned()
            .unwrap_or_default();
        counters.evicted = self
            .evictions
            .lock()
            .expect("eviction counters poisoned")
            .get(&kind)
            .map_or(0, |counter| counter.load(Ordering::Relaxed));
        counters
    }
    pub fn forget<D: DerivationKind>(&self, key: &D::Key) {
        self.region.invalidate(&EntryKey {
            kind: D::ID,
            question: D::question(key),
        });
    }
    pub fn demand<D: DerivationKind>(
        &self,
        key: &D::Key,
        revision: R,
        authority: A,
    ) -> Demanded<D::Output> {
        let question = D::question(key);
        let outcome = self.demand_erased(D::ID, question.clone(), revision, authority, None);
        self.record_demand(D::ID, question, &outcome.answer);
        outcome.answer.typed::<D::Output>()
    }
    pub fn replay(
        &self,
        kind: DerivationKindId,
        question: &DerivationQuestion,
        revision: R,
        authority: A,
    ) -> ReplayedDemand {
        let registered = self
            .kinds
            .lock()
            .expect("kind registry poisoned")
            .get(&kind)
            .cloned();
        if !registered.is_some_and(|registered| registered.accepts_question(question)) {
            return ReplayedDemand::Unavailable(UnavailableCause::ValidationFailed);
        }
        let outcome = self.demand_erased(kind, question.clone(), revision, authority, None);
        self.record_demand(kind, question.clone(), &outcome.answer);
        match outcome.answer {
            ErasedDemand::Retained(entry) => ReplayedDemand::Available {
                identity: entry.identity,
                complete: entry.complete,
                retained: true,
                validity: ReuseValidity::Reusable,
            },
            ErasedDemand::RequestOwned { entry, validity } => ReplayedDemand::Available {
                identity: entry.identity,
                complete: entry.complete,
                retained: false,
                validity,
            },
            ErasedDemand::Unavailable(cause) => ReplayedDemand::Unavailable(cause),
        }
    }
    pub fn try_reuse<D: DerivationKind>(
        &self,
        key: &D::Key,
        revision: R,
        authority: A,
    ) -> Option<Demanded<D::Output>> {
        let question = D::question(key);
        let answer = self.try_reuse_erased(D::ID, question.clone(), &revision, &authority, None)?;
        self.record_demand(D::ID, question, &answer);
        Some(answer.typed::<D::Output>())
    }
    fn try_reuse_erased(
        &self,
        kind: DerivationKindId,
        question: DerivationQuestion,
        revision: &R,
        authority: &A,
        parent: Option<(DerivationKindId, u16)>,
    ) -> Option<ErasedDemand> {
        let kinds = self.kinds.lock().expect("kind registry poisoned");
        let registered = kinds.get(&kind)?.clone();
        if let Some((parent_id, parent_stratum)) = parent {
            let declared = kinds
                .get(&parent_id)?
                .children()
                .iter()
                .any(|&(child, stratum)| child == kind && stratum == registered.stratum());
            if !declared || registered.stratum() >= parent_stratum {
                return None;
            }
        }
        drop(kinds);
        let key = EntryKey { kind, question };
        // Values live only in memory. Replay persists read keys and identity
        // digests, not values, so a cold process has nothing to reuse here.
        let entry = self.region.get(&key).or_else(|| self.region.revive(&key))?;
        let (since, old_authority) = entry
            .verified
            .lock()
            .expect("verification poisoned")
            .downcast_ref::<(R, A)>()?
            .clone();
        if !revision.is_established()
            || !since.is_established()
            || authority.retention_refusal().is_some()
            || old_authority != *authority
        {
            return None;
        }
        let current = since == *revision;
        if !current {
            if registered.verification() != Verification::BaseInputs {
                return None;
            }
            let mut unchanged = true;
            let _receipt = self.capture.capture(revision, authority, &mut || {
                for read in &entry.reads {
                    let valid = match read {
                        ReadKey::Lookup {
                            kind: LookupKind::Derivation(child),
                            question: LookupQuestion::Derivation(q),
                            digest,
                        } => self
                            .try_reuse_erased(
                                *child,
                                q.clone(),
                                revision,
                                authority,
                                Some((kind, registered.stratum())),
                            )
                            .is_some_and(|answer| match answer {
                                ErasedDemand::Retained(value) => value.identity.0 == *digest,
                                _ => false,
                            }),
                        _ => self
                            .base
                            .unchanged_without_stage(read, &since, revision, authority),
                    };
                    if !valid {
                        unchanged = false;
                        break;
                    }
                }
            });
            if !unchanged {
                return None;
            }
            let mut state = self.state.lock().expect("engine state poisoned");
            if revision
                .retained_bytes()
                .saturating_add(authority.retained_bytes())
                <= entry.verified_bytes
            {
                *entry.verified.lock().expect("verification poisoned") =
                    Box::new((revision.clone(), authority.clone()));
            }
            state.counters.entry(kind).or_default().verified_unchanged += 1;
        } else {
            self.state
                .lock()
                .expect("engine state poisoned")
                .counters
                .entry(kind)
                .or_default()
                .current_hits += 1;
        }
        // Replay what a lead hit replays: an entry's persistence refusals
        // travel with it, so a reused entry cannot make a ledger persistable
        // that the computing demand refused.
        self.capture.replay_reasons(&entry.reasons);
        self.capture
            .report_persistence_refusals(entry.persistence_refusals);
        Some(ErasedDemand::Retained(entry))
    }
    fn record_demand(
        &self,
        kind: DerivationKindId,
        question: DerivationQuestion,
        answer: &ErasedDemand,
    ) {
        let identity = match answer {
            ErasedDemand::Retained(entry) => entry.identity,
            ErasedDemand::RequestOwned { entry, .. } => entry.identity,
            ErasedDemand::Unavailable(_) => return,
        };
        self.capture.record(ReadKey::lookup(
            LookupKind::Derivation(kind),
            LookupQuestion::Derivation(question),
            identity.0,
        ));
    }
    fn demand_erased(
        &self,
        kind: DerivationKindId,
        question: DerivationQuestion,
        revision: R,
        authority: A,
        parent: Option<(DerivationKindId, u16)>,
    ) -> FlightOutcome {
        let registered = self
            .kinds
            .lock()
            .expect("kind registry poisoned")
            .get(&kind)
            .cloned();
        let Some(registered) = registered else {
            debug_assert!(false, "unregistered derivation kind");
            self.report_cause(NotReusableCause::InvalidDependencyEvidence);
            let mut effects = FlightEffects::default();
            effects.cause(NotReusableCause::InvalidDependencyEvidence);
            return FlightOutcome {
                answer: ErasedDemand::Unavailable(UnavailableCause::ValidationFailed),
                effects,
            };
        };
        let declared = parent.is_none_or(|(parent_id, _)| {
            self.kinds
                .lock()
                .expect("kind registry poisoned")
                .get(&parent_id)
                .is_some_and(|parent_kind| {
                    parent_kind
                        .children()
                        .iter()
                        .any(|&(child, stratum)| child == kind && stratum == registered.stratum())
                })
        });
        if !declared || parent.is_some_and(|(_, stratum)| registered.stratum() >= stratum) {
            let mut state = self.state.lock().expect("engine state poisoned");
            let counters = state.counters.entry(kind).or_default();
            counters.unavailable += 1;
            *counters
                .unavailable_by_cause
                .entry(UnavailableCause::StratumViolation)
                .or_default() += 1;
            drop(state);
            debug_assert!(
                false,
                "derivation stratum violation: kind={kind:?}, parent={parent:?}, declared={declared}"
            );
            self.report_cause(NotReusableCause::InvalidDependencyEvidence);
            let mut effects = FlightEffects::default();
            effects.cause(NotReusableCause::InvalidDependencyEvidence);
            return FlightOutcome {
                answer: ErasedDemand::Unavailable(UnavailableCause::StratumViolation),
                effects,
            };
        }
        let key = EntryKey { kind, question };
        let flight_key = (key.clone(), revision.clone(), authority.clone());
        loop {
            let (flight, leader) = {
                let mut state = self.state.lock().expect("engine state poisoned");
                if let Some(flight) = state.flights.get(&flight_key) {
                    (flight.clone(), false)
                } else {
                    let flight = Arc::new(Flight::new());
                    state.flights.insert(flight_key.clone(), flight.clone());
                    (flight, true)
                }
            };
            if !leader {
                let mut completed = flight.completed.lock().expect("flight poisoned");
                while completed.is_none() {
                    completed = flight.wake.wait(completed).expect("flight poisoned");
                }
                let outcome = completed.as_ref().expect("completed flight").clone();
                drop(completed);
                // The leader's cancellation says nothing about this request.
                // The leader retained nothing, so compute the answer here.
                if outcome.cancelled() && !self.capture.cancelled() {
                    continue;
                }
                outcome.effects.replay(self.capture.as_ref());
                return outcome;
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.lead(&key, &revision, &authority, registered.as_ref())
            }));
            let outcome = match &result {
                Ok(outcome) => outcome.clone(),
                Err(_) => {
                    let mut effects = FlightEffects::default();
                    effects.cause(NotReusableCause::InvalidDependencyEvidence);
                    FlightOutcome {
                        answer: ErasedDemand::Unavailable(UnavailableCause::Failed(Arc::from(
                            "derivation computation panicked",
                        ))),
                        effects,
                    }
                }
            };
            // Keep the flight discoverable until its result is visible to all followers.
            {
                let mut state = self.state.lock().expect("engine state poisoned");
                *flight.completed.lock().expect("flight poisoned") = Some(outcome.clone());
                flight.wake.notify_all();
                state.flights.remove(&flight_key);
            }
            if let Err(panic) = result {
                std::panic::resume_unwind(panic);
            }
            return outcome;
        }
    }
    fn lead(
        &self,
        key: &EntryKey,
        revision: &R,
        authority: &A,
        kind: &dyn Registered<R, A>,
    ) -> FlightOutcome {
        let mut effects = FlightEffects::default();
        let old = self.region.get(key).or_else(|| self.region.revive(key));
        if let Some(entry) = &old {
            let verified = entry
                .verified
                .lock()
                .expect("verification poisoned")
                .downcast_ref::<(R, A)>()
                .cloned();
            if let Some((since, old_authority)) = verified
                && revision.is_established()
                && since.is_established()
                && authority.retention_refusal().is_none()
            {
                if since == revision.clone() && old_authority == authority.clone() {
                    self.capture.replay_reasons(&entry.reasons);
                    self.capture
                        .report_persistence_refusals(entry.persistence_refusals);
                    effects.persistence_refusals = entry.persistence_refusals;
                    effects.stable_reasons = entry.reasons.clone();
                    let outcome = FlightOutcome {
                        answer: ErasedDemand::Retained(entry.clone()),
                        effects,
                    };
                    if matches!(outcome.answer, ErasedDemand::Retained(_)) {
                        self.state
                            .lock()
                            .expect("engine state poisoned")
                            .counters
                            .entry(key.kind)
                            .or_default()
                            .current_hits += 1;
                    }
                    return outcome;
                }
                let mut unchanged = old_authority == authority.clone()
                    && kind.verification() == Verification::BaseInputs;
                // Verification is provisional. Its child effects belong to neither a hit
                // nor the recomputation that follows a miss.
                if unchanged {
                    let _verification = self.capture.capture(revision, authority, &mut || {
                        // Verification is not the kind's compute; its reads need their own evidence.
                        // Worklist is explicit; nested derived checks descend through lower strata.
                        let mut pending = entry.reads.iter().rev().collect::<Vec<_>>();
                        while let Some(read) = pending.pop() {
                            match read {
                                ReadKey::Lookup {
                                    kind: LookupKind::Derivation(child),
                                    question: LookupQuestion::Derivation(q),
                                    digest,
                                } => {
                                    let child_outcome = self.demand_erased(
                                        *child,
                                        q.clone(),
                                        revision.clone(),
                                        authority.clone(),
                                        Some((key.kind, kind.stratum())),
                                    );
                                    match child_outcome.answer {
                                        ErasedDemand::Retained(value)
                                            if value.identity.0 == *digest => {}
                                        ErasedDemand::RequestOwned {
                                            entry,
                                            validity: ReuseValidity::Reusable,
                                        } if entry.identity.0 == *digest => {}
                                        _ => {
                                            unchanged = false;
                                            break;
                                        }
                                    }
                                }
                                _ => {
                                    if !self.base.unchanged(read, &since, revision, authority) {
                                        unchanged = false;
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
                if unchanged {
                    let mut state = self.state.lock().expect("engine state poisoned");
                    if revision.is_established()
                        && revision
                            .retained_bytes()
                            .saturating_add(authority.retained_bytes())
                            <= entry.verified_bytes
                    {
                        *entry.verified.lock().expect("verification poisoned") =
                            Box::new((revision.clone(), authority.clone()));
                    }
                    state
                        .counters
                        .entry(key.kind)
                        .or_default()
                        .verified_unchanged += 1;
                    drop(state);
                    self.capture.replay_reasons(&entry.reasons);
                    self.capture
                        .report_persistence_refusals(entry.persistence_refusals);
                    effects.persistence_refusals = entry.persistence_refusals;
                    effects.stable_reasons = entry.reasons.clone();
                    return FlightOutcome {
                        answer: ErasedDemand::Retained(entry.clone()),
                        effects,
                    };
                }
            }
        }
        let mut result = None;
        let mut frame = DerivationFrame {
            engine: self,
            revision: revision.clone(),
            authority: authority.clone(),
            stratum: kind.stratum(),
            kind_id: key.kind,
            child_validity: ReuseValidity::Reusable,
            child_unavailable: false,
            request_owned_child: false,
            marker: PhantomData,
        };
        let receipt = self.capture.capture(revision, authority, &mut || {
            result = Some(kind.compute(&mut frame, &key.question));
        });
        // Memory-only is transitive: an entry that read a key no persisted
        // read set may hold (a memory-only child's lookup) must not let its
        // own, persistable lookup stand in for it. It carries a persistence
        // refusal, which a miss forwards below and every hit replays.
        let mut receipt = receipt;
        if receipt.persistence_refusals == 0
            && receipt.reads.iter().any(|read| !read.is_persistable())
        {
            receipt.persistence_refusals = 1;
        }
        effects.unattributed = receipt.unattributed;
        effects.execution_dependences = receipt.execution_dependences.clone();
        effects.reuse_refusals = receipt.reuse_refusals.clone();
        effects.persistence_refusals = receipt.persistence_refusals;
        effects.stable_reasons = receipt.stable_reasons.clone();
        self.forward_capture_refusals(&receipt);
        self.capture.replay_reasons(&receipt.stable_reasons);
        let computed = match result.expect("capture hook must run the computation") {
            Ok(computed) => computed,
            Err(cause) => {
                let mut state = self.state.lock().expect("engine state poisoned");
                let counters = state.counters.entry(key.kind).or_default();
                counters.unavailable += 1;
                *counters
                    .unavailable_by_cause
                    .entry(cause.clone())
                    .or_default() += 1;
                drop(state);
                let refusal = match &cause {
                    UnavailableCause::Cancelled => NotReusableCause::Cancelled,
                    UnavailableCause::ChildUnavailable => NotReusableCause::ChildNotReusable,
                    _ => NotReusableCause::InvalidDependencyEvidence,
                };
                self.report_cause(refusal);
                effects.cause(refusal);
                return FlightOutcome {
                    answer: ErasedDemand::Unavailable(cause),
                    effects,
                };
            }
        };
        let mut validity = computed.validity;
        if let ReuseValidity::NotReusable(cause) = computed.validity {
            self.report_cause(cause);
            effects.cause(cause);
        }
        if receipt.unattributed > 0 {
            validity = ReuseValidity::NotReusable(NotReusableCause::UnattributedRead);
        } else if let Some(cause) = receipt.execution_dependences.first() {
            validity = ReuseValidity::NotReusable(*cause);
        } else if let Some(cause) = receipt.reuse_refusals.first() {
            validity = ReuseValidity::NotReusable(*cause);
        } else if frame.child_unavailable {
            validity = ReuseValidity::NotReusable(NotReusableCause::ChildNotReusable);
        } else if let ReuseValidity::NotReusable(cause) = frame.child_validity {
            validity = ReuseValidity::NotReusable(cause);
        }
        let mut reasons = receipt.stable_reasons;
        reasons.sort();
        reasons.dedup();
        let mut hash = CanonicalHasher::new(b"bifrost-derivation-identity:v1");
        hash.value(&computed.projection);
        hash.value(&[u8::from(computed.complete)]);
        hash.sequence("reasons", &reasons, |h, reason| h.value(reason.as_bytes()));
        let entry = Entry {
            output: computed.output,
            output_bytes: computed.bytes,
            identity: OutputIdentity(StableDigest::from_array(hash.finish())),
            reads: receipt.reads,
            reasons,
            persistence_refusals: receipt.persistence_refusals,
            complete: computed.complete,
            verified: Mutex::new(Box::new((revision.clone(), authority.clone()))),
            verified_bytes: revision
                .retained_bytes()
                .saturating_add(authority.retained_bytes()),
        };
        let mut state = self.state.lock().expect("engine state poisoned");
        let counters = state.counters.entry(key.kind).or_default();
        counters.recomputed += 1;
        if old
            .as_ref()
            .is_some_and(|old| old.identity == entry.identity)
        {
            counters.equal_identity += 1;
        }
        drop(old);
        if let Some(cause) = authority.retention_refusal() {
            validity = ReuseValidity::NotReusable(cause);
        } else if !revision.is_established() {
            validity = ReuseValidity::NotReusable(NotReusableCause::UnestablishedBinding);
        }
        // A result that cannot be retained says nothing about the retained
        // entry: that entry carries its own verified binding, and any demand at
        // another binding verifies it before use. Keep it, so an overlay or
        // unestablished demand does not wipe entries that main demands reuse.
        if let ReuseValidity::NotReusable(cause) = validity {
            let counters = state.counters.entry(key.kind).or_default();
            counters.not_retainable += 1;
            *counters.not_retainable_by_cause.entry(cause).or_default() += 1;
            drop(state);
            let forwarded = match cause {
                NotReusableCause::UnattributedRead => receipt.unattributed > 0,
                NotReusableCause::Cancelled
                | NotReusableCause::LimitReached
                | NotReusableCause::ExecutionDependent => {
                    receipt.execution_dependences.contains(&cause)
                }
                _ => receipt.reuse_refusals.contains(&cause),
            };
            if computed.validity != validity && !forwarded {
                self.report_cause(cause);
                effects.cause(cause);
            }
            return FlightOutcome {
                answer: ErasedDemand::RequestOwned {
                    entry: Arc::new(entry),
                    validity,
                },
                effects,
            };
        }
        if frame.request_owned_child {
            state.counters.entry(key.kind).or_default().not_retainable += 1;
            return FlightOutcome {
                answer: ErasedDemand::RequestOwned {
                    entry: Arc::new(entry),
                    validity,
                },
                effects,
            };
        }
        self.region.invalidate(key);
        let eviction_counter = self
            .evictions
            .lock()
            .expect("eviction counters poisoned")
            .get(&key.kind)
            .cloned()
            .expect("registered kind has eviction counter");
        let admitted = self.region.insert_with_eviction_callback(
            key.clone(),
            entry,
            Arc::new(move || {
                eviction_counter.fetch_add(1, Ordering::Relaxed);
            }),
        );
        drop(state);
        let answer = match admitted {
            BudgetedValue::Retained(value) => ErasedDemand::Retained(value),
            BudgetedValue::RequestOwned { value, .. } => ErasedDemand::RequestOwned {
                entry: Arc::new(Entry {
                    output: value.output.clone(),
                    output_bytes: value.output_bytes,
                    identity: value.identity,
                    reads: value.reads.clone(),
                    reasons: value.reasons.clone(),
                    persistence_refusals: value.persistence_refusals,
                    complete: value.complete,
                    verified: Mutex::new(Box::new((revision.clone(), authority.clone()))),
                    verified_bytes: revision
                        .retained_bytes()
                        .saturating_add(authority.retained_bytes()),
                }),
                validity,
            },
        };
        FlightOutcome { answer, effects }
    }
}

pub struct DerivationFrame<'a, R, A> {
    engine: &'a DerivationEngine<R, A>,
    revision: R,
    authority: A,
    stratum: u16,
    kind_id: DerivationKindId,
    child_validity: ReuseValidity,
    child_unavailable: bool,
    request_owned_child: bool,
    marker: PhantomData<&'a ()>,
}
impl<R, A> DerivationFrame<'_, R, A>
where
    R: DerivationRevision,
    A: DerivationAuthority,
{
    pub fn demand<D: DerivationKind>(&mut self, key: &D::Key) -> Demanded<D::Output> {
        let q = D::question(key);
        let outcome = self.engine.demand_erased(
            D::ID,
            q.clone(),
            self.revision.clone(),
            self.authority.clone(),
            Some((self.kind_id, self.stratum)),
        );
        let answer = outcome.answer;
        self.engine.record_demand(D::ID, q, &answer);
        match &answer {
            ErasedDemand::Retained(_) => {}
            ErasedDemand::RequestOwned { validity, .. } => {
                self.request_owned_child = true;
                if matches!(validity, ReuseValidity::NotReusable(_)) {
                    self.child_validity = *validity;
                }
            }
            ErasedDemand::Unavailable(_) => self.child_unavailable = true,
        }
        answer.typed::<D::Output>()
    }
}

#[derive(Clone)]
enum ErasedDemand {
    Retained(Retained<Entry>),
    RequestOwned {
        entry: Arc<Entry>,
        validity: ReuseValidity,
    },
    Unavailable(UnavailableCause),
}
impl ErasedDemand {
    fn typed<O: Send + Sync + 'static>(self) -> Demanded<O> {
        match self {
            Self::Retained(entry) => {
                let value = Arc::downcast::<O>(entry.output.clone())
                    .expect("registered derivation output type changed");
                let identity = entry.identity;
                let complete = entry.complete;
                Demanded::Available {
                    value: Handle::Retained(RetainedValue {
                        _entry: entry,
                        value,
                    }),
                    identity,
                    complete,
                    validity: ReuseValidity::Reusable,
                }
            }
            Self::RequestOwned { entry, validity } => {
                let value = Arc::downcast::<O>(entry.output.clone())
                    .expect("registered derivation output type changed");
                Demanded::Available {
                    value: Handle::RequestOwned(RequestOwned::new(value)),
                    identity: entry.identity,
                    complete: entry.complete,
                    validity,
                }
            }
            Self::Unavailable(cause) => Demanded::Unavailable(cause),
        }
    }
}

#[cfg(test)]
mod derivation_properties {
    use super::super::read_ledger::IndexFamily;
    use super::*;
    use brokk_bifrost_test_macros::hardwon;
    use proptest::prelude::*;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    type ToyCaptureFrame = (
        u64,
        Vec<ReadKey>,
        Vec<String>,
        Vec<NotReusableCause>,
        usize,
        Vec<NotReusableCause>,
        usize,
    );
    thread_local! {
        static STACK: RefCell<Vec<ToyCaptureFrame>> = const { RefCell::new(Vec::new()) };
        // Pauses this thread's next reason replay, so a test can act between a
        // follower's wake-up and the rest of its return path.
        static PAUSE_REPLAY: RefCell<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>> =
            const { RefCell::new(None) };
        // The request on this thread is cancelled: the leaf computes
        // Cancelled and the capture hook reports it.
        static CANCELLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    struct Key(u8);
    impl RetainedBytes for Key {
        fn retained_bytes(&self) -> usize {
            1
        }
    }
    struct Value(u8);
    impl RetainedBytes for Value {
        fn retained_bytes(&self) -> usize {
            if self.0 == 200 { 1_000_000 } else { 1 }
        }
    }
    fn question(key: &Key) -> DerivationQuestion {
        DerivationQuestion {
            language: None,
            subject: None,
            rel_path: None,
            name: Some(key.0.to_string().into_boxed_str()),
        }
    }
    fn from_question(q: &DerivationQuestion) -> Option<Key> {
        if q.language.is_some() || q.subject.is_some() || q.rel_path.is_some() {
            return None;
        }
        q.name.as_ref()?.parse().ok().map(Key)
    }
    struct ToyState {
        values: Mutex<HashMap<u64, [u8; 2]>>,
        routes: Mutex<HashMap<u64, [u8; 2]>>,
        validity: Mutex<HashMap<u64, ReuseValidity>>,
        unavailable: Mutex<HashMap<u64, UnavailableCause>>,
        incomplete: Mutex<HashMap<u64, bool>>,
        reasons: Mutex<HashMap<u64, String>>,
        unattributed: Mutex<HashMap<u64, bool>>,
        delay_ms: AtomicUsize,
        panic_after_gate: AtomicUsize,
        main_only_reject: AtomicUsize,
        gate: Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
    }
    impl ToyState {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                values: Mutex::new(HashMap::from_iter([(0, [1, 2])])),
                routes: Mutex::new(HashMap::default()),
                validity: Mutex::new(HashMap::default()),
                unavailable: Mutex::new(HashMap::default()),
                incomplete: Mutex::new(HashMap::default()),
                reasons: Mutex::new(HashMap::default()),
                unattributed: Mutex::new(HashMap::default()),
                delay_ms: AtomicUsize::new(0),
                panic_after_gate: AtomicUsize::new(0),
                main_only_reject: AtomicUsize::new(0),
                gate: Mutex::new(None),
            })
        }
        fn read(&self, key: Key) -> u8 {
            let revision = STACK.with(|s| s.borrow().last().expect("outside capture").0);
            let source = self
                .routes
                .lock()
                .unwrap()
                .get(&revision)
                .copied()
                .unwrap_or([0, 1])[usize::from(key.0)];
            let value = self.values.lock().unwrap()[&revision][usize::from(source)];
            STACK.with(|s| {
                s.borrow_mut().last_mut().unwrap().1.push(ReadKey::Index {
                    family: IndexFamily::DefinitionExact,
                    key: vec![2, key.0].into_boxed_slice(),
                })
            });
            STACK.with(|s| {
                s.borrow_mut().last_mut().unwrap().1.push(ReadKey::Index {
                    family: IndexFamily::DefinitionExact,
                    key: vec![source].into_boxed_slice(),
                })
            });
            if let Some(reason) = self.reasons.lock().unwrap().get(&revision) {
                STACK.with(|s| s.borrow_mut().last_mut().unwrap().2.push(reason.clone()));
            }
            if self
                .unattributed
                .lock()
                .unwrap()
                .get(&revision)
                .copied()
                .unwrap_or(false)
            {
                STACK.with(|s| s.borrow_mut().last_mut().unwrap().4 += 1);
            }
            value
        }
    }
    // Even authorities may retain, so tests can use two distinct ones that both do.
    impl DerivationAuthority for u64 {
        fn retention_refusal(&self) -> Option<NotReusableCause> {
            (!self.is_multiple_of(2)).then_some(NotReusableCause::OverlayAuthority)
        }
    }
    impl DerivationRevision for u64 {
        fn is_established(&self) -> bool {
            *self != u64::MAX
        }
    }
    struct ToyCapture;
    impl CaptureHook<u64, u64> for ToyCapture {
        fn capture(&self, revision: &u64, _: &u64, work: &mut dyn FnMut()) -> CaptureReceipt {
            STACK.with(|s| {
                s.borrow_mut().push((
                    *revision,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    0,
                    Vec::new(),
                    0,
                ))
            });
            work();
            let (
                _,
                reads,
                stable_reasons,
                reuse_refusals,
                unattributed,
                execution_dependences,
                persistence_refusals,
            ) = STACK.with(|s| s.borrow_mut().pop().unwrap());
            CaptureReceipt {
                reads,
                unattributed,
                execution_dependences,
                reuse_refusals,
                persistence_refusals,
                stable_reasons,
            }
        }
        fn report_unattributed(&self) {
            STACK.with(|s| {
                if let Some(top) = s.borrow_mut().last_mut() {
                    top.4 += 1;
                }
            });
        }
        fn report_execution_dependence(&self, cause: NotReusableCause) {
            STACK.with(|s| {
                if let Some(top) = s.borrow_mut().last_mut() {
                    top.5.push(cause);
                }
            });
        }
        fn report_reuse_refusal(&self, cause: NotReusableCause) {
            STACK.with(|s| {
                if let Some(top) = s.borrow_mut().last_mut() {
                    top.3.push(cause);
                }
            });
        }
        fn report_persistence_refusals(&self, count: usize) {
            STACK.with(|s| {
                if let Some(top) = s.borrow_mut().last_mut() {
                    top.6 += count;
                }
            });
        }
        fn replay_reasons(&self, reasons: &[String]) {
            if let Some((entered, release)) = PAUSE_REPLAY.with(|pause| pause.borrow_mut().take()) {
                entered.wait();
                release.wait();
            }
            STACK.with(|s| {
                if let Some(top) = s.borrow_mut().last_mut() {
                    top.2.extend_from_slice(reasons);
                }
            });
        }
        fn record(&self, read: ReadKey) {
            STACK.with(|s| {
                if let Some(top) = s.borrow_mut().last_mut() {
                    top.1.push(read);
                }
            });
        }
        fn cancelled(&self) -> bool {
            CANCELLED.with(|cancelled| cancelled.get())
        }
    }
    impl BaseInputs<u64, u64> for ToyState {
        fn unchanged_without_stage(
            &self,
            read: &ReadKey,
            since: &u64,
            at: &u64,
            authority: &u64,
        ) -> bool {
            self.main_only_reject.load(Ordering::SeqCst) == 0
                && self.unchanged(read, since, at, authority)
        }
        fn unchanged(&self, read: &ReadKey, since: &u64, at: &u64, _: &u64) -> bool {
            let ReadKey::Index { key, .. } = read else {
                return false;
            };
            let values = self.values.lock().unwrap();
            if key[0] == 2 {
                let routes = self.routes.lock().unwrap();
                let before = routes.get(since).copied().unwrap_or([0, 1]);
                let after = routes.get(at).copied().unwrap_or([0, 1]);
                return before[usize::from(key[1])] == after[usize::from(key[1])];
            }
            let index = usize::from(key[0]);
            values
                .get(since)
                .zip(values.get(at))
                .is_some_and(|(a, b)| a[index] == b[index])
        }
    }
    struct Leaf {
        state: Arc<ToyState>,
        calls: Arc<AtomicUsize>,
    }
    impl DerivationKind for Leaf {
        type Key = Key;
        type Output = Value;
        const ID: DerivationKindId = DerivationKindId("derivation:toy_leaf:v1");
        const STRATUM: u16 = 0;
        const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
        fn question(key: &Key) -> DerivationQuestion {
            question(key)
        }
        fn key_from_question(q: &DerivationQuestion) -> Option<Key> {
            from_question(q)
        }
        fn compute<R, A>(&self, _: &mut DerivationFrame<'_, R, A>, key: &Key) -> Computed<Value>
        where
            R: DerivationRevision,
            A: DerivationAuthority,
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let gate = self.state.gate.lock().unwrap().clone();
            if let Some((entered, release)) = gate {
                entered.wait();
                release.wait();
            }
            assert_eq!(self.state.panic_after_gate.load(Ordering::SeqCst), 0);
            let delay = self.state.delay_ms.load(Ordering::SeqCst);
            if delay > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay as u64));
            }
            let revision = STACK.with(|s| s.borrow().last().unwrap().0);
            if CANCELLED.with(|cancelled| cancelled.get()) {
                return Computed::Unavailable(UnavailableCause::Cancelled);
            }
            if let Some(cause) = self
                .state
                .unavailable
                .lock()
                .unwrap()
                .get(&revision)
                .cloned()
            {
                return Computed::Unavailable(cause);
            }
            let value = self.state.read(*key);
            let validity = self
                .state
                .validity
                .lock()
                .unwrap()
                .get(&revision)
                .copied()
                .unwrap_or(ReuseValidity::Reusable);
            Computed::Available {
                value: Value(value),
                complete: !self
                    .state
                    .incomplete
                    .lock()
                    .unwrap()
                    .get(&revision)
                    .copied()
                    .unwrap_or(false),
                validity,
            }
        }
        fn output_projection(value: &Value, hash: &mut CanonicalHasher) {
            hash.value(&[value.0]);
        }
    }
    struct Parent {
        calls: Arc<AtomicUsize>,
    }
    impl DerivationKind for Parent {
        type Key = Key;
        type Output = Value;
        const ID: DerivationKindId = DerivationKindId("derivation:toy_parent:v1");
        const STRATUM: u16 = 1;
        const CHILDREN: &'static [(DerivationKindId, u16)] = &[(Leaf::ID, Leaf::STRATUM)];
        fn question(key: &Key) -> DerivationQuestion {
            question(key)
        }
        fn key_from_question(q: &DerivationQuestion) -> Option<Key> {
            from_question(q)
        }
        fn compute<R, A>(&self, frame: &mut DerivationFrame<'_, R, A>, _: &Key) -> Computed<Value>
        where
            R: DerivationRevision,
            A: DerivationAuthority,
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let left = frame.demand::<Leaf>(&Key(0));
            let right = frame.demand::<Leaf>(&Key(1));
            let (Demanded::Available { value: a, .. }, Demanded::Available { value: b, .. }) =
                (left, right)
            else {
                panic!("toy child unavailable")
            };
            Computed::Available {
                value: Value(a.0.wrapping_add(b.0)),
                complete: true,
                validity: ReuseValidity::Reusable,
            }
        }
        fn output_projection(value: &Value, hash: &mut CanonicalHasher) {
            hash.value(&[value.0]);
        }
    }
    struct RecomputeLeaf(Leaf);
    impl DerivationKind for RecomputeLeaf {
        type Key = Key;
        type Output = Value;
        const ID: DerivationKindId = DerivationKindId("derivation:toy_recompute_leaf:v1");
        const STRATUM: u16 = 0;
        const VERIFY: Verification = Verification::Recompute;
        const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
        fn question(key: &Key) -> DerivationQuestion {
            question(key)
        }
        fn key_from_question(q: &DerivationQuestion) -> Option<Key> {
            from_question(q)
        }
        fn compute<R, A>(&self, frame: &mut DerivationFrame<'_, R, A>, key: &Key) -> Computed<Value>
        where
            R: DerivationRevision,
            A: DerivationAuthority,
        {
            self.0.compute(frame, key)
        }
        fn output_projection(value: &Value, hash: &mut CanonicalHasher) {
            Leaf::output_projection(value, hash);
        }
    }
    struct RecomputeParent {
        calls: Arc<AtomicUsize>,
    }
    impl DerivationKind for RecomputeParent {
        type Key = Key;
        type Output = Value;
        const ID: DerivationKindId = DerivationKindId("derivation:toy_recompute_parent:v1");
        const STRATUM: u16 = 1;
        const CHILDREN: &'static [(DerivationKindId, u16)] = &[(RecomputeLeaf::ID, 0)];
        fn question(key: &Key) -> DerivationQuestion {
            question(key)
        }
        fn key_from_question(q: &DerivationQuestion) -> Option<Key> {
            from_question(q)
        }
        fn compute<R, A>(&self, frame: &mut DerivationFrame<'_, R, A>, key: &Key) -> Computed<Value>
        where
            R: DerivationRevision,
            A: DerivationAuthority,
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match frame.demand::<RecomputeLeaf>(key) {
                Demanded::Available { value, .. } => Computed::Available {
                    value: Value(value.0),
                    complete: true,
                    validity: ReuseValidity::Reusable,
                },
                Demanded::Unavailable(cause) => Computed::Unavailable(cause),
            }
        }
        fn output_projection(value: &Value, hash: &mut CanonicalHasher) {
            Leaf::output_projection(value, hash);
        }
    }
    #[test]
    fn recompute_leaf_verifies_parent_by_output_identity() {
        let state = ToyState::new();
        state.values.lock().unwrap().insert(1, [1, 2]);
        state.values.lock().unwrap().insert(2, [4, 2]);
        let leaf_calls = Arc::new(AtomicUsize::new(0));
        let parent_calls = Arc::new(AtomicUsize::new(0));
        let engine = DerivationEngine::new(
            &RetentionBudget::new(1_000_000),
            Arc::new(ToyCapture),
            state.clone(),
        );
        engine.register(RecomputeLeaf(Leaf {
            state,
            calls: leaf_calls.clone(),
        }));
        engine.register(RecomputeParent {
            calls: parent_calls.clone(),
        });
        for (revision, expected_leaf, expected_parent) in [(0, 1, 1), (1, 2, 1), (2, 3, 2)] {
            assert!(matches!(
                engine.demand::<RecomputeParent>(&Key(0), revision, 0),
                Demanded::Available { .. }
            ));
            assert_eq!(leaf_calls.load(Ordering::SeqCst), expected_leaf);
            assert_eq!(parent_calls.load(Ordering::SeqCst), expected_parent);
        }
        assert!(matches!(
            engine.demand::<RecomputeLeaf>(&Key(0), 2, 0),
            Demanded::Available { .. }
        ));
        assert_eq!(leaf_calls.load(Ordering::SeqCst), 3);
    }
    fn engine(
        budget: u64,
        state: Arc<ToyState>,
        leaf_calls: Arc<AtomicUsize>,
        parent_calls: Arc<AtomicUsize>,
    ) -> DerivationEngine<u64, u64> {
        let engine = DerivationEngine::new(
            &RetentionBudget::new(budget),
            Arc::new(ToyCapture),
            state.clone(),
        );
        engine.register(Leaf {
            state,
            calls: leaf_calls,
        });
        engine.register(Parent {
            calls: parent_calls,
        });
        engine
    }
    fn answer(engine: &DerivationEngine<u64, u64>, revision: u64) -> u8 {
        let Demanded::Available { value, .. } = engine.demand::<Parent>(&Key(0), revision, 0)
        else {
            panic!("toy answer unavailable")
        };
        value.0
    }
    #[test]
    fn a_parent_of_an_unpersistable_child_carries_a_persistence_refusal() {
        // The toy kinds are outside the persisted codec, so the parent's
        // lookup of the leaf is a read no persisted read set may hold. The
        // parent must carry that refusal on its first demand and on a hit.
        let state = ToyState::new();
        state.values.lock().unwrap().insert(1, [1, 2]);
        let parent_calls = Arc::new(AtomicUsize::new(0));
        let engine = engine(
            1_000_000,
            state,
            Arc::new(AtomicUsize::new(0)),
            parent_calls.clone(),
        );
        for _ in 0..2 {
            let receipt = ToyCapture.capture(&0, &0, &mut || {
                assert!(matches!(
                    engine.demand::<Parent>(&Key(0), 0, 0),
                    Demanded::Available { .. }
                ));
            });
            assert_eq!(receipt.persistence_refusals, 1);
        }
        assert_eq!(parent_calls.load(Ordering::SeqCst), 1);
        let leaf_receipt = ToyCapture.capture(&0, &0, &mut || {
            assert!(matches!(
                engine.demand::<Leaf>(&Key(0), 0, 0),
                Demanded::Available { .. }
            ));
        });
        assert_eq!(leaf_receipt.persistence_refusals, 0);
    }
    #[test]
    fn try_reuse_current_and_verified_record_once() {
        let state = ToyState::new();
        state.values.lock().unwrap().insert(1, [1, 2]);
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = engine(
            1_000_000,
            state,
            calls.clone(),
            Arc::new(AtomicUsize::new(0)),
        );
        assert!(matches!(
            engine.demand::<Leaf>(&Key(0), 0, 0),
            Demanded::Available { .. }
        ));
        for revision in [0, 1] {
            let receipt = ToyCapture.capture(&revision, &0, &mut || {
                assert!(matches!(
                    engine.try_reuse::<Leaf>(&Key(0), revision, 0),
                    Some(Demanded::Available { .. })
                ));
            });
            assert_eq!(receipt.reads.len(), 1);
            assert!(matches!(
                &receipt.reads[0],
                ReadKey::Lookup {
                    kind: LookupKind::Derivation(Leaf::ID),
                    ..
                }
            ));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let counters = engine.counters(Leaf::ID);
        assert_eq!(
            (
                counters.current_hits,
                counters.verified_unchanged,
                counters.recomputed
            ),
            (1, 1, 1)
        );
    }

    #[test]
    fn try_reuse_refuses_stage_only_evidence_and_authority_change() {
        let state = ToyState::new();
        state.values.lock().unwrap().insert(1, [1, 2]);
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = engine(
            1_000_000,
            state.clone(),
            calls.clone(),
            Arc::new(AtomicUsize::new(0)),
        );
        assert!(matches!(
            engine.demand::<Leaf>(&Key(0), 0, 0),
            Demanded::Available { .. }
        ));
        state.main_only_reject.store(1, Ordering::SeqCst);
        let receipt = ToyCapture.capture(&1, &0, &mut || {
            assert!(engine.try_reuse::<Leaf>(&Key(0), 1, 0).is_none());
        });
        assert!(receipt.reads.is_empty());
        assert!(engine.try_reuse::<Leaf>(&Key(0), 0, 2).is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let counters = engine.counters(Leaf::ID);
        assert_eq!(
            (
                counters.current_hits,
                counters.verified_unchanged,
                counters.recomputed
            ),
            (0, 0, 1)
        );
    }

    #[test]
    fn try_reuse_missing_child_does_not_compute() {
        let state = ToyState::new();
        state.values.lock().unwrap().insert(1, [1, 2]);
        let leaf_calls = Arc::new(AtomicUsize::new(0));
        let parent_calls = Arc::new(AtomicUsize::new(0));
        let engine = engine(1_000_000, state, leaf_calls.clone(), parent_calls.clone());
        assert_eq!(answer(&engine, 0), 3);
        engine.forget::<Leaf>(&Key(0));
        let receipt = ToyCapture.capture(&1, &0, &mut || {
            assert!(engine.try_reuse::<Parent>(&Key(0), 1, 0).is_none());
        });
        assert!(receipt.reads.is_empty());
        assert_eq!(
            (
                leaf_calls.load(Ordering::SeqCst),
                parent_calls.load(Ordering::SeqCst)
            ),
            (2, 1)
        );
    }

    #[test]
    fn try_reuse_recompute_kind_requires_current_binding() {
        let state = ToyState::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = DerivationEngine::new(
            &RetentionBudget::new(1_000_000),
            Arc::new(ToyCapture),
            state.clone(),
        );
        engine.register(RecomputeLeaf(Leaf {
            state,
            calls: calls.clone(),
        }));
        assert!(matches!(
            engine.demand::<RecomputeLeaf>(&Key(0), 0, 0),
            Demanded::Available { .. }
        ));
        assert!(engine.try_reuse::<RecomputeLeaf>(&Key(0), 1, 0).is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    #[hardwon("#9737: top-level demands omitted the derivation lookup from an enclosing capture")]
    fn top_level_demand_records_output_identity_for_miss_and_hits() {
        let state = ToyState::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = engine(
            1_000_000,
            state.clone(),
            calls.clone(),
            Arc::new(AtomicUsize::new(0)),
        );
        for revision in [0, 0, 1] {
            if revision == 1 {
                state.values.lock().unwrap().insert(1, [1, 2]);
            }
            let mut identity = None;
            let receipt = ToyCapture.capture(&revision, &0, &mut || {
                let Demanded::Available {
                    identity: output, ..
                } = engine.demand::<Leaf>(&Key(0), revision, 0)
                else {
                    panic!("leaf unavailable")
                };
                identity = Some(output);
            });
            assert_eq!(
                receipt.reads,
                vec![ReadKey::lookup(
                    LookupKind::Derivation(Leaf::ID),
                    LookupQuestion::Derivation(question(&Key(0))),
                    identity.unwrap().0,
                )]
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(engine.counters(Leaf::ID).current_hits, 1);
        assert_eq!(engine.counters(Leaf::ID).verified_unchanged, 1);
    }

    #[test]
    #[hardwon("#9737: retained old entry blocked admission of its changed replacement")]
    fn changed_replacement_fits_one_entry_budget() {
        let state = ToyState::new();
        let probe = engine(
            1_000_000,
            state.clone(),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        );
        drop(probe.demand::<Leaf>(&Key(0), 0, 0));
        let one_entry = probe.region.stats().accounted_bytes;
        drop(probe);

        let calls = Arc::new(AtomicUsize::new(0));
        let engine = engine(
            one_entry,
            state.clone(),
            calls.clone(),
            Arc::new(AtomicUsize::new(0)),
        );
        drop(engine.demand::<Leaf>(&Key(0), 0, 0));
        state.values.lock().unwrap().insert(1, [4, 2]);
        let Demanded::Available { value, .. } = engine.demand::<Leaf>(&Key(0), 1, 0) else {
            panic!("replacement unavailable")
        };
        assert!(matches!(value, Handle::Retained(_)));
        assert_eq!(value.0, 4);
        drop(value);
        let Demanded::Available { value, .. } = engine.demand::<Leaf>(&Key(0), 1, 0) else {
            panic!("hit unavailable")
        };
        assert!(matches!(value, Handle::Retained(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(engine.counters(Leaf::ID).current_hits, 1);
    }
    #[test]
    fn cancelled_computation_is_not_kept() {
        let state = ToyState::new();
        state
            .validity
            .lock()
            .unwrap()
            .insert(0, ReuseValidity::NotReusable(NotReusableCause::Cancelled));
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = engine(
            1_000_000,
            state,
            calls.clone(),
            Arc::new(AtomicUsize::new(0)),
        );
        for _ in 0..2 {
            let Demanded::Available { validity, .. } = engine.demand::<Leaf>(&Key(0), 0, 0) else {
                panic!("unavailable")
            };
            assert_eq!(
                validity,
                ReuseValidity::NotReusable(NotReusableCause::Cancelled)
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn cancelled_unavailable_outcome_is_not_kept() {
        let state = ToyState::new();
        state
            .unavailable
            .lock()
            .unwrap()
            .insert(0, UnavailableCause::Cancelled);
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = engine(
            1_000_000,
            state,
            calls.clone(),
            Arc::new(AtomicUsize::new(0)),
        );
        for _ in 0..2 {
            assert!(matches!(
                engine.demand::<Leaf>(&Key(0), 0, 0),
                Demanded::Unavailable(UnavailableCause::Cancelled)
            ));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            engine.counters(Leaf::ID).unavailable_by_cause[&UnavailableCause::Cancelled],
            2
        );
    }

    #[test]
    fn unattributed_read_during_capture_refuses_retention() {
        let state = ToyState::new();
        state.unattributed.lock().unwrap().insert(0, true);
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = engine(
            1_000_000,
            state,
            calls.clone(),
            Arc::new(AtomicUsize::new(0)),
        );
        for _ in 0..2 {
            let Demanded::Available { validity, .. } = engine.demand::<Leaf>(&Key(0), 0, 0) else {
                panic!("unavailable")
            };
            assert_eq!(
                validity,
                ReuseValidity::NotReusable(NotReusableCause::UnattributedRead)
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn child_unattributed_read_reaches_parent_channel() {
        let state = ToyState::new();
        state.unattributed.lock().unwrap().insert(0, true);
        let engine = engine(
            1_000_000,
            state,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        );
        let Demanded::Available { validity, .. } = engine.demand::<Parent>(&Key(0), 0, 0) else {
            panic!("unavailable")
        };
        assert_eq!(
            validity,
            ReuseValidity::NotReusable(NotReusableCause::UnattributedRead)
        );
        assert_eq!(
            engine.counters(Parent::ID).not_retainable_by_cause
                [&NotReusableCause::UnattributedRead],
            1
        );
    }

    #[test]
    fn overlay_authority_does_not_publish() {
        let state = ToyState::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = engine(
            1_000_000,
            state,
            calls.clone(),
            Arc::new(AtomicUsize::new(0)),
        );
        for _ in 0..2 {
            let Demanded::Available { validity, .. } = engine.demand::<Leaf>(&Key(0), 0, 1) else {
                panic!("unavailable")
            };
            assert_eq!(
                validity,
                ReuseValidity::NotReusable(NotReusableCause::OverlayAuthority)
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn unestablished_reader_token_never_retains_or_verifies() {
        let state = ToyState::new();
        state.values.lock().unwrap().insert(u64::MAX, [1, 2]);
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = engine(
            1_000_000,
            state,
            calls.clone(),
            Arc::new(AtomicUsize::new(0)),
        );
        for _ in 0..2 {
            let Demanded::Available {
                value, validity, ..
            } = engine.demand::<Leaf>(&Key(0), u64::MAX, 0)
            else {
                panic!("unavailable")
            };
            assert!(matches!(value, Handle::RequestOwned(_)));
            assert_eq!(
                validity,
                ReuseValidity::NotReusable(NotReusableCause::UnestablishedBinding)
            );
        }
        let _ = engine.demand::<Leaf>(&Key(0), 0, 0);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(engine.counters(Leaf::ID).current_hits, 0);
        assert_eq!(engine.counters(Leaf::ID).verified_unchanged, 0);
    }

    #[test]
    fn rejected_child_with_equal_value_rejects_parent() {
        let state = ToyState::new();
        state.values.lock().unwrap().insert(0, [1, 1]);
        let leaves = Arc::new(AtomicUsize::new(0));
        let parents = Arc::new(AtomicUsize::new(0));
        let engine = engine(1_000_000, state.clone(), leaves, parents.clone());
        assert_eq!(answer(&engine, 0), 2);
        state.values.lock().unwrap().insert(1, [1, 1]);
        state.validity.lock().unwrap().insert(
            1,
            ReuseValidity::NotReusable(NotReusableCause::LimitReached),
        );
        // Force a base read to differ while preserving the selected output.
        state.routes.lock().unwrap().insert(1, [1, 0]);
        let Demanded::Available {
            value, validity, ..
        } = engine.demand::<Parent>(&Key(0), 1, 0)
        else {
            panic!("unavailable")
        };
        assert_eq!(value.0, 2);
        assert_eq!(
            validity,
            ReuseValidity::NotReusable(NotReusableCause::LimitReached)
        );
        let before = parents.load(Ordering::SeqCst);
        let _ = engine.demand::<Parent>(&Key(0), 1, 0);
        assert_eq!(parents.load(Ordering::SeqCst), before + 1);
    }

    #[test]
    fn refused_but_reusable_child_keeps_parent_valid() {
        let state = ToyState::new();
        state.values.lock().unwrap().insert(0, [200, 1]);
        state.values.lock().unwrap().insert(1, [200, 1]);
        let leaves = Arc::new(AtomicUsize::new(0));
        let parents = Arc::new(AtomicUsize::new(0));
        let engine = engine(8_000, state, leaves.clone(), parents.clone());
        let Demanded::Available {
            value,
            validity,
            complete,
            ..
        } = engine.demand::<Parent>(&Key(0), 0, 0)
        else {
            panic!("unavailable")
        };
        assert_eq!(value.0, 201);
        assert!(matches!(value, Handle::RequestOwned(_)));
        assert_eq!(validity, ReuseValidity::Reusable);
        assert!(complete);
        assert_eq!(answer(&engine, 0), 201);
        assert_eq!(parents.load(Ordering::SeqCst), 2);
        assert_eq!(answer(&engine, 1), 201);
        assert_eq!(parents.load(Ordering::SeqCst), 3);
        assert!(leaves.load(Ordering::SeqCst) > 2);
    }

    #[test]
    fn demanded_completeness_survives_retention_and_request_ownership() {
        let state = ToyState::new();
        state.incomplete.lock().unwrap().insert(0, true);
        let engine = engine(
            1_000_000,
            state,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        );
        for authority in [0, 0, 1] {
            let Demanded::Available {
                value, complete, ..
            } = engine.demand::<Leaf>(&Key(0), 0, authority)
            else {
                panic!("unavailable")
            };
            assert!(!complete);
            assert_eq!(matches!(value, Handle::Retained(_)), authority == 0);
        }
    }

    #[test]
    fn verification_effects_are_not_replayed_into_caller() {
        let state = ToyState::new();
        state.reasons.lock().unwrap().insert(0, "old".into());
        let engine = engine(
            1_000_000,
            state.clone(),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(answer(&engine, 0), 3);
        state.values.lock().unwrap().insert(1, [1, 2]);
        let hit = ToyCapture.capture(&1, &0, &mut || assert_eq!(answer(&engine, 1), 3));
        assert_eq!(hit.stable_reasons, ["old"]);
        assert!(hit.reuse_refusals.is_empty());

        state.values.lock().unwrap().insert(2, [3, 2]);
        state.reasons.lock().unwrap().insert(2, "new".into());
        let miss = ToyCapture.capture(&2, &0, &mut || assert_eq!(answer(&engine, 2), 5));
        // The changed child contributes "new"; the unchanged sibling still
        // contributes its retained "old" reason.
        assert_eq!(miss.stable_reasons, ["new", "old"]);
        assert!(miss.reuse_refusals.is_empty());
    }

    #[test]
    fn changed_reasons_with_equal_payload_change_identity() {
        let state = ToyState::new();
        state.values.lock().unwrap().insert(0, [1, 1]);
        let parents = Arc::new(AtomicUsize::new(0));
        let engine = engine(
            1_000_000,
            state.clone(),
            Arc::new(AtomicUsize::new(0)),
            parents.clone(),
        );
        assert_eq!(answer(&engine, 0), 2);
        state.values.lock().unwrap().insert(1, [1, 1]);
        state
            .reasons
            .lock()
            .unwrap()
            .insert(1, "new structural reason".into());
        // Force re-evaluation by moving the read source to an equal-valued input.
        state.routes.lock().unwrap().insert(1, [1, 0]);
        assert_eq!(answer(&engine, 1), 2);
        assert_eq!(parents.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn dependency_replacement_tracks_new_source_after_equal_output() {
        let state = ToyState::new();
        state.values.lock().unwrap().insert(0, [1, 1]);
        let parents = Arc::new(AtomicUsize::new(0));
        let engine = engine(
            1_000_000,
            state.clone(),
            Arc::new(AtomicUsize::new(0)),
            parents.clone(),
        );
        assert_eq!(answer(&engine, 0), 2);
        state.values.lock().unwrap().insert(1, [1, 1]);
        state.routes.lock().unwrap().insert(1, [1, 1]);
        assert_eq!(answer(&engine, 1), 2);
        assert_eq!(parents.load(Ordering::SeqCst), 1);
        state.values.lock().unwrap().insert(2, [2, 1]);
        state.routes.lock().unwrap().insert(2, [1, 1]);
        assert_eq!(answer(&engine, 2), 2);
        assert_eq!(parents.load(Ordering::SeqCst), 1);
        state.values.lock().unwrap().insert(3, [2, 2]);
        state.routes.lock().unwrap().insert(3, [1, 1]);
        assert_eq!(answer(&engine, 3), 4);
        assert_eq!(parents.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn single_flight_computes_once() {
        let state = ToyState::new();
        state.delay_ms.store(100, Ordering::SeqCst);
        let leaves = Arc::new(AtomicUsize::new(0));
        let engine = Arc::new(engine(
            1_000_000,
            state,
            leaves.clone(),
            Arc::new(AtomicUsize::new(0)),
        ));
        let start = Arc::new(std::sync::Barrier::new(9));
        let handles = (0..8)
            .map(|_| {
                let engine = engine.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    let Demanded::Available { value, .. } = engine.demand::<Leaf>(&Key(0), 0, 0)
                    else {
                        panic!("unavailable")
                    };
                    assert_eq!(value.0, 1);
                })
            })
            .collect::<Vec<_>>();
        start.wait();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(leaves.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[hardwon("#9737: a follower of a cancelled leader inherited the leader's Cancelled result")]
    fn follower_with_a_live_request_recomputes_after_leader_cancellation() {
        let state = ToyState::new();
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        *state.gate.lock().unwrap() = Some((entered.clone(), release.clone()));
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = Arc::new(engine(
            1_000_000,
            state.clone(),
            calls.clone(),
            Arc::new(AtomicUsize::new(0)),
        ));
        let leader_engine = engine.clone();
        let leader = std::thread::spawn(move || {
            CANCELLED.with(|cancelled| cancelled.set(true));
            matches!(
                leader_engine.demand::<Leaf>(&Key(0), 0, 0),
                Demanded::Unavailable(UnavailableCause::Cancelled)
            )
        });
        entered.wait();
        let follower_engine = engine.clone();
        let follower = std::thread::spawn(move || {
            matches!(
                follower_engine.demand::<Leaf>(&Key(0), 0, 0),
                Demanded::Available { .. }
            )
        });
        // The map owns one reference and the leader owns another. The third
        // proves the follower joined this flight before the computation ends.
        loop {
            let joined = {
                let state = engine.state.lock().unwrap();
                state
                    .flights
                    .values()
                    .next()
                    .is_some_and(|f| Arc::strong_count(f) >= 3)
            };
            if joined {
                break;
            }
            std::thread::yield_now();
        }
        // The follower's retry must not wait at the gate again.
        *state.gate.lock().unwrap() = None;
        release.wait();
        assert!(
            leader.join().unwrap(),
            "the cancelled leader is Unavailable"
        );
        assert!(
            follower.join().unwrap(),
            "the live follower computes its own answer"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn single_flight_follower_replays_receipt_into_own_capture() {
        let state = ToyState::new();
        state.reasons.lock().unwrap().insert(0, "partial".into());
        state.unattributed.lock().unwrap().insert(0, true);
        state.validity.lock().unwrap().insert(
            0,
            ReuseValidity::NotReusable(NotReusableCause::LimitReached),
        );
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        *state.gate.lock().unwrap() = Some((entered.clone(), release.clone()));
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = Arc::new(engine(
            1_000_000,
            state,
            calls.clone(),
            Arc::new(AtomicUsize::new(0)),
        ));
        let leader_engine = engine.clone();
        let leader = std::thread::spawn(move || {
            ToyCapture.capture(&0, &0, &mut || {
                let mut frame = DerivationFrame {
                    engine: &leader_engine,
                    revision: 0,
                    authority: 0,
                    stratum: Parent::STRATUM,
                    kind_id: Parent::ID,
                    child_validity: ReuseValidity::Reusable,
                    child_unavailable: false,
                    request_owned_child: false,
                    marker: PhantomData,
                };
                let _ = frame.demand::<Leaf>(&Key(0));
            })
        });
        entered.wait();
        let follower_engine = engine.clone();
        let follower = std::thread::spawn(move || {
            ToyCapture.capture(&0, &0, &mut || {
                let mut frame = DerivationFrame {
                    engine: &follower_engine,
                    revision: 0,
                    authority: 0,
                    stratum: Parent::STRATUM,
                    kind_id: Parent::ID,
                    child_validity: ReuseValidity::Reusable,
                    child_unavailable: false,
                    request_owned_child: false,
                    marker: PhantomData,
                };
                let _ = frame.demand::<Leaf>(&Key(0));
            })
        });
        // The map owns one reference and the leader owns another. The third
        // proves the follower joined this flight before the computation ends.
        loop {
            let joined = {
                let state = engine.state.lock().unwrap();
                state
                    .flights
                    .values()
                    .next()
                    .is_some_and(|f| Arc::strong_count(f) >= 3)
            };
            if joined {
                break;
            }
            std::thread::yield_now();
        }
        release.wait();
        let leader_receipt = leader.join().unwrap();
        let follower_receipt = follower.join().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            follower_receipt.stable_reasons,
            leader_receipt.stable_reasons
        );
        assert_eq!(follower_receipt.stable_reasons, ["partial"]);
        assert_eq!(follower_receipt.reads, leader_receipt.reads);
        assert!(matches!(
            follower_receipt.reads.as_slice(),
            [ReadKey::Lookup { .. }]
        ));
        assert_eq!(follower_receipt.unattributed, leader_receipt.unattributed);
        assert_eq!(
            follower_receipt.execution_dependences,
            leader_receipt.execution_dependences
        );
        assert_eq!(
            follower_receipt.reuse_refusals,
            leader_receipt.reuse_refusals
        );
    }

    #[test]
    #[hardwon(
        "#9737: a follower resuming after the engine advanced returned the leader's answer as reusable"
    )]
    fn follower_resuming_after_an_advance_refuses_reuse() {
        let state = ToyState::new();
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        *state.gate.lock().unwrap() = Some((entered.clone(), release.clone()));
        let engine = Arc::new(engine(
            1_000_000,
            state,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        ));
        let leader_engine = engine.clone();
        let leader = std::thread::spawn(move || leader_engine.demand::<Leaf>(&Key(0), 0, 0));
        entered.wait();
        let paused = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        let follower_engine = engine.clone();
        let (follower_paused, follower_resume) = (paused.clone(), resume.clone());
        let follower = std::thread::spawn(move || {
            PAUSE_REPLAY
                .with(|pause| *pause.borrow_mut() = Some((follower_paused, follower_resume)));
            let mut answer = None;
            let receipt = ToyCapture.capture(&0, &0, &mut || {
                answer = Some(follower_engine.demand::<Leaf>(&Key(0), 0, 0));
            });
            (answer.unwrap(), receipt)
        });
        loop {
            let joined = engine
                .state
                .lock()
                .unwrap()
                .flights
                .values()
                .next()
                .is_some_and(|flight| Arc::strong_count(flight) >= 3);
            if joined {
                break;
            }
            std::thread::yield_now();
        }
        release.wait();
        let Demanded::Available { validity, .. } = leader.join().unwrap() else {
            panic!("leader unavailable")
        };
        assert_eq!(
            validity,
            ReuseValidity::Reusable,
            "the leader retains its own binding"
        );
        // A same-binding follower remains reusable while other bindings are demanded.
        paused.wait();
        resume.wait();
        let (answer, receipt) = follower.join().unwrap();
        let Demanded::Available {
            value, validity, ..
        } = answer
        else {
            panic!("follower unavailable")
        };
        assert_eq!(validity, ReuseValidity::Reusable);
        assert!(matches!(value, Handle::Retained(_)));
        assert!(receipt.reuse_refusals.is_empty());
    }

    #[test]
    #[hardwon("#9737: panicking flight leader left follower capture without a refusal")]
    fn panicking_leader_reports_refusal_to_follower() {
        let state = ToyState::new();
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        *state.gate.lock().unwrap() = Some((entered.clone(), release.clone()));
        state.panic_after_gate.store(1, Ordering::SeqCst);
        let engine = Arc::new(engine(
            1_000_000,
            state,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        ));
        let leader_engine = engine.clone();
        let leader = std::thread::spawn(move || leader_engine.demand::<Leaf>(&Key(0), 0, 0));
        entered.wait();
        let follower_engine = engine.clone();
        let follower = std::thread::spawn(move || {
            let mut answer = None;
            let receipt = ToyCapture.capture(&0, &0, &mut || {
                answer = Some(follower_engine.demand::<Leaf>(&Key(0), 0, 0));
            });
            (answer.unwrap(), receipt)
        });
        loop {
            let joined = engine
                .state
                .lock()
                .unwrap()
                .flights
                .values()
                .next()
                .is_some_and(|flight| Arc::strong_count(flight) >= 3);
            if joined {
                break;
            }
            std::thread::yield_now();
        }
        release.wait();
        assert!(leader.join().is_err());
        let (answer, receipt) = follower.join().unwrap();
        assert!(matches!(
            answer,
            Demanded::Unavailable(UnavailableCause::Failed(_))
        ));
        assert_eq!(
            receipt.reuse_refusals,
            [NotReusableCause::InvalidDependencyEvidence]
        );
    }

    #[test]
    fn alternating_bindings_verify_unchanged_inputs_without_recomputing() {
        let state = ToyState::new();
        state.values.lock().unwrap().insert(1, [1, 2]);
        state.values.lock().unwrap().insert(2, [1, 2]);
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = engine(
            1_000_000,
            state,
            calls.clone(),
            Arc::new(AtomicUsize::new(0)),
        );
        let Demanded::Available {
            value: first,
            identity: first_identity,
            ..
        } = engine.demand::<Leaf>(&Key(0), 0, 0)
        else {
            panic!("first unavailable")
        };
        assert_eq!(first.0, 1);
        let Demanded::Available {
            value: second,
            identity: second_identity,
            ..
        } = engine.demand::<Leaf>(&Key(0), 1, 0)
        else {
            panic!("second unavailable")
        };
        assert_eq!(second.0, 1);
        assert_eq!(first_identity, second_identity);
        assert_eq!(engine.counters(Leaf::ID).verified_unchanged, 1);
        for revision in [1, 0, 1, 0] {
            let mut answer = None;
            let receipt = ToyCapture.capture(&revision, &0, &mut || {
                answer = Some(engine.demand::<Leaf>(&Key(0), revision, 0));
            });
            let Demanded::Available {
                value,
                validity,
                identity,
                ..
            } = answer.unwrap()
            else {
                panic!("verified hit unavailable")
            };
            assert_eq!(validity, ReuseValidity::Reusable);
            assert!(matches!(value, Handle::Retained(_)));
            assert_eq!(value.0, 1);
            assert_eq!(identity, first_identity);
            assert!(receipt.reuse_refusals.is_empty());
        }
        // Every new binding verifies unchanged inputs; only the first fill computes.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(engine.counters(Leaf::ID).recomputed, 1);
    }

    #[test]
    fn verification_requires_the_entry_authority() {
        let state = ToyState::new();
        for revision in [0, 1, 2] {
            state.values.lock().unwrap().insert(revision, [1, 2]);
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = engine(
            1_000_000,
            state,
            calls.clone(),
            Arc::new(AtomicUsize::new(0)),
        );
        let identity = |revision, authority| {
            let Demanded::Available {
                value, identity, ..
            } = engine.demand::<Leaf>(&Key(0), revision, authority)
            else {
                panic!("leaf unavailable")
            };
            assert!(matches!(value, Handle::Retained(_)));
            identity
        };
        let first = identity(0, 0);
        // The inputs are unchanged at revision 1, but the entry was computed
        // under authority 0. Authority 2 may retain too, yet it recomputes
        // instead of verifying an entry it did not compute.
        assert_eq!(identity(1, 2), first);
        assert_eq!(engine.counters(Leaf::ID).verified_unchanged, 0);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // Under its own authority the entry verifies at a new revision.
        assert_eq!(identity(2, 2), first);
        assert_eq!(engine.counters(Leaf::ID).verified_unchanged, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn replacement_during_verification_keeps_proof_on_checked_entry() {
        struct PausingInputs {
            state: Arc<ToyState>,
            entered: Arc<std::sync::Barrier>,
            release: Arc<std::sync::Barrier>,
            first: AtomicBool,
        }
        impl BaseInputs<u64, u64> for PausingInputs {
            fn unchanged(&self, read: &ReadKey, since: &u64, at: &u64, authority: &u64) -> bool {
                let unchanged = self.state.unchanged(read, since, at, authority);
                if *at == 1 && self.first.swap(false, Ordering::SeqCst) {
                    self.entered.wait();
                    self.release.wait();
                }
                unchanged
            }
        }
        let state = ToyState::new();
        state.values.lock().unwrap().insert(1, [1, 2]);
        state.values.lock().unwrap().insert(2, [4, 2]);
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let engine = Arc::new(DerivationEngine::new(
            &RetentionBudget::new(1_000_000),
            Arc::new(ToyCapture),
            Arc::new(PausingInputs {
                state: state.clone(),
                entered: entered.clone(),
                release: release.clone(),
                first: AtomicBool::new(true),
            }),
        ));
        engine.register(Leaf {
            state,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let Demanded::Available {
            identity: a_identity,
            ..
        } = engine.demand::<Leaf>(&Key(0), 0, 0)
        else {
            panic!("A unavailable")
        };
        let verifying = engine.clone();
        let a_again = std::thread::spawn(move || verifying.demand::<Leaf>(&Key(0), 1, 0));
        entered.wait();
        let Demanded::Available {
            value: b,
            identity: b_identity,
            ..
        } = engine.demand::<Leaf>(&Key(0), 2, 0)
        else {
            panic!("B unavailable")
        };
        assert_eq!(b.0, 4);
        assert_ne!(a_identity, b_identity);
        release.wait();
        let Demanded::Available {
            value: a,
            identity: verified_identity,
            ..
        } = a_again.join().unwrap()
        else {
            panic!("verified A unavailable")
        };
        assert_eq!(a.0, 1);
        assert_eq!(verified_identity, a_identity);
        // Verification stamped the old retained entry, never B's replacement.
        let current = engine
            .region
            .get(&EntryKey {
                kind: Leaf::ID,
                question: question(&Key(0)),
            })
            .unwrap();
        assert_eq!(current.identity, b_identity);
        let verified = current.verified.lock().unwrap();
        assert_eq!(verified.downcast_ref::<(u64, u64)>(), Some(&(2, 0)));
    }

    #[test]
    fn per_kind_eviction_counter_tracks_budget_evictions() {
        let state = ToyState::new();
        let probe = engine(
            1_000_000,
            state.clone(),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        );
        let _ = probe.demand::<Leaf>(&Key(0), 0, 0);
        let one_entry = probe.region.stats().accounted_bytes;
        assert!(one_entry > 0);
        drop(probe);
        let engine = engine(
            one_entry * 2 - 1,
            state,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        );
        for key in [Key(0), Key(1)] {
            let Demanded::Available {
                value, validity, ..
            } = engine.demand::<Leaf>(&key, 0, 0)
            else {
                panic!("unavailable")
            };
            assert!(matches!(value, Handle::Retained(_)));
            assert_eq!(validity, ReuseValidity::Reusable);
        }
        engine.region.run_pending_tasks();
        assert!(
            engine.counters(Leaf::ID).evicted >= 1,
            "{:?}",
            engine.region.stats()
        );
    }
    #[test]
    fn overlapping_revisions_do_not_join_and_retain_own_work() {
        let state = ToyState::new();
        state.values.lock().unwrap().insert(1, [4, 2]);
        state.delay_ms.store(200, Ordering::SeqCst);
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = Arc::new(engine(
            1_000_000,
            state.clone(),
            calls.clone(),
            Arc::new(AtomicUsize::new(0)),
        ));
        let old_engine = engine.clone();
        let old = std::thread::spawn(move || old_engine.demand::<Leaf>(&Key(0), 0, 0));
        while calls.load(Ordering::SeqCst) == 0 {
            std::thread::yield_now();
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        state.delay_ms.store(0, Ordering::SeqCst);
        let Demanded::Available {
            value,
            validity,
            identity: new_identity,
            ..
        } = engine.demand::<Leaf>(&Key(0), 1, 0)
        else {
            panic!("new unavailable")
        };
        assert_eq!(value.0, 4);
        assert_eq!(validity, ReuseValidity::Reusable);
        let Demanded::Available {
            value, validity, ..
        } = old.join().unwrap()
        else {
            panic!("old unavailable")
        };
        assert_eq!(value.0, 1);
        assert_eq!(validity, ReuseValidity::Reusable);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let Demanded::Available {
            value, identity, ..
        } = engine.demand::<Leaf>(&Key(0), 1, 0)
        else {
            panic!("new unavailable")
        };
        assert_eq!(value.0, 4);
        assert_eq!(identity, new_identity);
        assert_eq!(calls.load(Ordering::SeqCst), 3); // A replaced B; B must recompute.
    }

    struct BadLeaf;
    impl DerivationKind for BadLeaf {
        type Key = Key;
        type Output = Value;
        const ID: DerivationKindId = DerivationKindId("derivation:toy_bad:v1");
        const STRATUM: u16 = 0;
        const CHILDREN: &'static [(DerivationKindId, u16)] = &[(Parent::ID, Parent::STRATUM)];
        fn question(key: &Key) -> DerivationQuestion {
            question(key)
        }
        fn key_from_question(q: &DerivationQuestion) -> Option<Key> {
            from_question(q)
        }
        fn compute<R, A>(&self, frame: &mut DerivationFrame<'_, R, A>, _: &Key) -> Computed<Value>
        where
            R: DerivationRevision,
            A: DerivationAuthority,
        {
            let answer = frame.demand::<Parent>(&Key(0));
            assert!(matches!(
                answer,
                Demanded::Unavailable(UnavailableCause::StratumViolation)
            ));
            Computed::Available {
                value: Value(0),
                complete: true,
                validity: ReuseValidity::Reusable,
            }
        }
        fn output_projection(value: &Value, hash: &mut CanonicalHasher) {
            hash.value(&[value.0]);
        }
    }
    #[test]
    fn stratum_violation_is_refused() {
        let state = ToyState::new();
        let engine = engine(
            1_000_000,
            state,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        );
        if cfg!(debug_assertions) {
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                engine.register(BadLeaf);
            }));
            assert!(panic.is_err());
        } else {
            engine.register(BadLeaf);
            let _ = engine.demand::<BadLeaf>(&Key(0), 0, 0);
        }
    }
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]
        #[test]
        fn warm_equals_cold_and_unchanged_inputs_do_not_recompute(edits in prop::collection::vec((0u8..2, 0u8..8), 0..12)) {
            let state = ToyState::new();
            let leaf_calls = Arc::new(AtomicUsize::new(0));
            let parent_calls = Arc::new(AtomicUsize::new(0));
            let warm = engine(1_000_000, state.clone(), leaf_calls.clone(), parent_calls.clone());
            prop_assert_eq!(answer(&warm, 0), 3);
            let mut prior = [1u8, 2u8];
            for (step, (index, new_value)) in edits.into_iter().enumerate() {
                let revision = step as u64 + 1;
                let mut next = prior;
                next[usize::from(index)] = new_value;
                state.values.lock().unwrap().insert(revision, next);
                let before_leaf = leaf_calls.load(Ordering::SeqCst);
                let before_parent = parent_calls.load(Ordering::SeqCst);
                let actual = answer(&warm, revision);
                let cold = engine(1_000_000, state.clone(), Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
                prop_assert_eq!(actual, answer(&cold, revision));
                prop_assert_eq!(actual, next[0].wrapping_add(next[1]));
                let changed = usize::from(next[0] != prior[0]) + usize::from(next[1] != prior[1]);
                prop_assert_eq!(leaf_calls.load(Ordering::SeqCst) - before_leaf, changed);
                prop_assert_eq!(parent_calls.load(Ordering::SeqCst) - before_parent, usize::from(changed > 0));
                prior = next;
            }
        }
    }
}
