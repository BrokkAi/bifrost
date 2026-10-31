//! Provider outcomes, finite budgets, and the language-neutral adapter boundary.

use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::cancellation::CancellationToken;

use crate::analyzer::semantic::capabilities::SemanticCapabilities;

use crate::analyzer::semantic::capabilities::SemanticCapability;

use crate::analyzer::semantic::ids::ProcedureId;

use crate::analyzer::semantic::ids::SemanticArtifactKey;

use crate::analyzer::semantic::ids::StableDigest;

use crate::analyzer::semantic::ir::SemanticArtifact;

use crate::analyzer::semantic::ir::SemanticIrError;

use crate::analyzer::semantic::leases::SemanticArtifactCollector;

use crate::analyzer::semantic::partial_flow::ProcedurePartialFlows;

use brokk_bifrost_core::analyzer::work_budget::BudgetLedger;

use brokk_bifrost_core::analyzer::work_budget::WorkBudgetExceeded;

use brokk_bifrost_core::analyzer::work_budget::define_work_dimensions;

define_work_dimensions! {
    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum SemanticBudgetDimension;
    /// Work performed or limits applied while materializing semantic facts.
    ///
    /// Deserializable because a reused policy evaluation unit replays the
    /// exact semantic charge its own work made, and that charge outlives the
    /// process that measured it.
    #[derive(
        Debug, Default, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
    )]
    #[serde(deny_unknown_fields)]
    pub struct SemanticWork;
    all: pub [16];
    SourceBytes => source_bytes = 16 * 1024 * 1024,
    Procedures => procedures = 10_000,
    Blocks => blocks = 100_000,
    ProgramPoints => program_points = 1_000_000,
    Values => values = 1_000_000,
    Allocations => allocations = 100_000,
    CallSites => call_sites = 100_000,
    MemoryLocations => memory_locations = 250_000,
    Captures => captures = 100_000,
    SourceMappings => source_mappings = 1_000_000,
    Evidence => evidence = 250_000,
    Gaps => gaps = 100_000,
    Events => events = 4_000_000,
    ControlEdges => control_edges = 2_000_000,
    NestedEntries => nested_entries = 8_000_000,
    OwnedTextBytes => owned_text_bytes = 32 * 1024 * 1024,
}

/// Public semantic budget categories used by diagnostics and extension
/// results. Internal ledger dimensions intentionally project onto this small,
/// stable vocabulary.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SemanticBudgetLane {
    Source,
    Rows,
    RetainedBytes,
    Files,
}

impl SemanticBudgetLane {
    pub const LABELS: &'static [&'static str] = &["source", "rows", "retained_bytes", "files"];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Rows => "rows",
            Self::RetainedBytes => "retained_bytes",
            Self::Files => "files",
        }
    }
}

impl SemanticBudgetDimension {
    pub const fn public_lane(self) -> SemanticBudgetLane {
        match self {
            Self::SourceBytes => SemanticBudgetLane::Source,
            Self::Procedures
            | Self::Blocks
            | Self::ProgramPoints
            | Self::Values
            | Self::Allocations
            | Self::CallSites
            | Self::MemoryLocations
            | Self::Captures
            | Self::SourceMappings
            | Self::Evidence
            | Self::Gaps
            | Self::Events
            | Self::ControlEdges
            | Self::NestedEntries => SemanticBudgetLane::Rows,
            Self::OwnedTextBytes => SemanticBudgetLane::RetainedBytes,
        }
    }
}

impl SemanticWork {
    /// Add work conservatively, using a uniformly maximal sentinel if any
    /// dimension overflows.
    pub fn conservative_add(self, other: Self) -> Self {
        self.checked_add(other)
            .unwrap_or_else(|| Self::uniform(usize::MAX))
    }

    pub const fn component_max(self, other: Self) -> Self {
        Self {
            source_bytes: if self.source_bytes > other.source_bytes {
                self.source_bytes
            } else {
                other.source_bytes
            },
            procedures: if self.procedures > other.procedures {
                self.procedures
            } else {
                other.procedures
            },
            blocks: if self.blocks > other.blocks {
                self.blocks
            } else {
                other.blocks
            },
            program_points: if self.program_points > other.program_points {
                self.program_points
            } else {
                other.program_points
            },
            values: if self.values > other.values {
                self.values
            } else {
                other.values
            },
            allocations: if self.allocations > other.allocations {
                self.allocations
            } else {
                other.allocations
            },
            call_sites: if self.call_sites > other.call_sites {
                self.call_sites
            } else {
                other.call_sites
            },
            memory_locations: if self.memory_locations > other.memory_locations {
                self.memory_locations
            } else {
                other.memory_locations
            },
            captures: if self.captures > other.captures {
                self.captures
            } else {
                other.captures
            },
            source_mappings: if self.source_mappings > other.source_mappings {
                self.source_mappings
            } else {
                other.source_mappings
            },
            evidence: if self.evidence > other.evidence {
                self.evidence
            } else {
                other.evidence
            },
            gaps: if self.gaps > other.gaps {
                self.gaps
            } else {
                other.gaps
            },
            events: if self.events > other.events {
                self.events
            } else {
                other.events
            },
            control_edges: if self.control_edges > other.control_edges {
                self.control_edges
            } else {
                other.control_edges
            },
            nested_entries: if self.nested_entries > other.nested_entries {
                self.nested_entries
            } else {
                other.nested_entries
            },
            owned_text_bytes: if self.owned_text_bytes > other.owned_text_bytes {
                self.owned_text_bytes
            } else {
                other.owned_text_bytes
            },
        }
    }
}

/// Finite semantic bounds with cumulative work counters.
///
/// Admissions increase resident balances and cumulative counters; window release
/// and allocation expiry refund only residency. Work increases the current root
/// balance and cumulative counters, and is never refunded or refused. Resident
/// admissions alone consume these limits; solver steps and procedure discovery
/// have their own bounds. Work peaks remain observable on replay.
/// The weak admission registry does not retain executable artifacts. It is
/// scoped to one query and pruned at each mutation; window close clears it.
/// Paid identities preserve cumulative census credit across windows; the
/// weak registry separately identifies resident admissions.
///
/// Both registries use copy-on-write so staged charges can be discarded without
/// mutating the caller's accounting. Only live consumers spend the resident
/// allowance; complete-cache and prepared-pool pins are excluded even before
/// Moka physically reclaims an evicted entry.
#[derive(Debug, Clone)]
pub struct SemanticBudget {
    ledger: BudgetLedger<SemanticWork>,
    // Admitted plus worked per lane, so held-and-scanned bytes can count twice.
    // Cumulative accounting is telemetry, not a bound.
    cumulative: SemanticWork,
    /// Admissions that represent performed work plus non-refundable work.
    /// A retained source re-entering a new region's resident ledger is not a
    /// new read, so it advances residency and `cumulative`, but not this.
    performed: SemanticWork,
    root_work: SemanticWork,
    root_work_peak: SemanticWork,
    replay_observers: Vec<ReplayObserver>,
    lowering_work: Option<Arc<Mutex<SemanticWork>>>,
    resident_peak: SemanticWork,
    resident_artifacts: Arc<ResidentArtifacts>,
    resident_owners: Arc<ResidentOwners>,
    inherited_artifacts: Arc<ResidentArtifacts>,
    scope: Arc<SemanticBudgetScope>,
    charged_artifacts: Arc<HashSet<StableDigest>>,
    shared_summary_expansion_limit: Option<usize>,
    /// The first charge this ledger refused. Clones share it, so a refusal
    /// on a staging copy that is then discarded is still recorded; a child
    /// ledger has its own.
    first_refusal: Arc<std::sync::OnceLock<SemanticBudgetRefusal>>,
    // Timing-only query history. Lightweight scope identities never retain it.
    lowered: Arc<Mutex<HashSet<StableDigest>>>,
}

/// One charge a semantic budget refused, and the code that asked for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticBudgetRefusal {
    pub exceeded: SemanticBudgetExceeded,
    pub site: &'static std::panic::Location<'static>,
}

#[derive(Debug)]
struct SemanticBudgetScope;

/// Lightweight identity for one logical semantic-budget scope.
///
/// Unlike [`SemanticBudgetScopeSnapshot`], this token deliberately retains no
/// charged-artifact set. Long-lived optimizations can therefore validate
/// scope continuity without pinning copy-on-write accounting state.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct SemanticBudgetScopeIdentity {
    scope: Arc<SemanticBudgetScope>,
}

/// Artifact censuses already paid within one logical semantic-budget scope.
///
/// Scalar work alone is not a complete scope snapshot: a later cache hit in the same
/// scope must know which immutable artifact censuses the scope already paid so
/// it can charge only the repeat-lookup work. The snapshot is opaque because it
/// is accounting identity, not an artifact cache or a public result identity.
#[derive(Debug, Clone)]
pub struct SemanticBudgetScopeSnapshot {
    admitted_artifacts: Arc<ResidentArtifacts>,
    scope: Arc<SemanticBudgetScope>,
    charged_artifacts: Arc<HashSet<StableDigest>>,
    shared_summary_expansion_limit: Option<usize>,
    lowered: Arc<Mutex<HashSet<StableDigest>>>,
}

#[derive(Debug)]
pub struct SemanticBudgetCharge {
    resident: SemanticWork,
    resident_artifacts: Arc<ResidentArtifacts>,
    resident_owners: Arc<ResidentOwners>,
    scope: Arc<SemanticBudgetScope>,
    work: SemanticWork,
    performed: SemanticWork,
    resident_peak: SemanticWork,
    root_work_peak: SemanticWork,
    charged_artifacts: Arc<HashSet<StableDigest>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSemanticBudget {
    dimension: SemanticBudgetDimension,
}

impl InvalidSemanticBudget {
    pub const fn dimension(self) -> SemanticBudgetDimension {
        self.dimension
    }
}

impl fmt::Display for InvalidSemanticBudget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "semantic budget limit `{}` must be positive",
            self.dimension.public_lane().label()
        )
    }
}

impl std::error::Error for InvalidSemanticBudget {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SemanticBudgetExceeded {
    dimension: SemanticBudgetDimension,
    limit: usize,
    attempted: usize,
}

impl SemanticBudgetExceeded {
    /// Rebuild a recorded exceedance, as the semantic IR row decoder does for
    /// a stored budget gap or publication outcome.
    #[doc(hidden)]
    pub const fn new(dimension: SemanticBudgetDimension, limit: usize, attempted: usize) -> Self {
        Self {
            dimension,
            limit,
            attempted,
        }
    }

    pub const fn dimension(self) -> SemanticBudgetDimension {
        self.dimension
    }

    pub const fn limit(self) -> usize {
        self.limit
    }

    pub const fn attempted(self) -> usize {
        self.attempted
    }
}

impl fmt::Display for SemanticBudgetExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "semantic resident `{}` (`{}`) {} {} against limit {}",
            self.dimension.public_lane().label(),
            self.dimension.label(),
            if matches!(
                self.dimension,
                SemanticBudgetDimension::NestedEntries | SemanticBudgetDimension::OwnedTextBytes
            ) {
                "peak"
            } else {
                "attempted"
            },
            self.attempted,
            self.limit
        )
    }
}

impl std::error::Error for SemanticBudgetExceeded {}

impl From<WorkBudgetExceeded<SemanticBudgetDimension>> for SemanticBudgetExceeded {
    fn from(exceeded: WorkBudgetExceeded<SemanticBudgetDimension>) -> Self {
        Self {
            dimension: exceeded.dimension(),
            limit: exceeded.limit(),
            attempted: exceeded.attempted(),
        }
    }
}

fn summary_expansion_count(work: SemanticWork) -> usize {
    work.call_sites
        .saturating_add(work.memory_locations)
        .saturating_add(work.captures)
}

impl SemanticBudget {
    pub fn new(limits: SemanticWork) -> Result<Self, InvalidSemanticBudget> {
        for dimension in SemanticBudgetDimension::ALL {
            if limits.get(dimension) == 0 {
                return Err(InvalidSemanticBudget { dimension });
            }
        }
        Ok(Self {
            ledger: BudgetLedger::new(limits, SemanticWork::default()),
            cumulative: SemanticWork::default(),
            performed: SemanticWork::default(),
            root_work: SemanticWork::default(),
            root_work_peak: SemanticWork::default(),
            replay_observers: Vec::new(),
            lowering_work: None,
            resident_peak: SemanticWork::default(),
            resident_artifacts: Arc::default(),
            resident_owners: Arc::default(),
            inherited_artifacts: Arc::default(),
            scope: Arc::new(SemanticBudgetScope),
            charged_artifacts: Arc::new(HashSet::new()),
            shared_summary_expansion_limit: None,
            first_refusal: Arc::default(),
            lowered: Arc::default(),
        })
    }

    /// Share one cap across call-site, memory-location, and capture rows.
    #[doc(hidden)]
    pub fn with_shared_summary_expansion_limit(mut self, limit: usize) -> Self {
        assert!(limit > 0, "shared summary expansion limit must be positive");
        self.shared_summary_expansion_limit = Some(limit);
        self
    }

    pub fn uniform(limit: usize) -> Result<Self, InvalidSemanticBudget> {
        Self::new(SemanticWork::uniform(limit))
    }

    pub const fn limits(&self) -> SemanticWork {
        self.ledger.limits()
    }

    pub const fn used(&self) -> SemanticWork {
        self.cumulative
    }

    /// Cumulative performed work, excluding resident holds that only move an
    /// already-counted census into a later region's ledger.
    pub const fn performed(&self) -> SemanticWork {
        self.performed
    }

    /// Live admissions, excluding references owned only by materialization caches.
    pub fn resident(&self) -> SemanticWork {
        let mut used = self.ledger.used();
        for (artifact, work) in self.resident_artifacts.values() {
            if !artifact.has_consumer() {
                used = used.saturating_sub(*work);
            }
        }
        for (source, work) in self.resident_owners.values() {
            if source.strong_count() == 0 {
                used = used.saturating_sub(*work);
            }
        }
        used
    }

    pub const fn resident_peak(&self) -> SemanticWork {
        self.resident_peak
    }

    /// Release a closed file/root window without refunding performed work.
    pub fn release_resident(&mut self) {
        let used = SemanticWork::default();
        self.ledger = self.ledger.with_used(used);
        self.resident_artifacts = Arc::default();
        self.resident_owners = Arc::default();
        self.inherited_artifacts = Arc::default();
    }

    /// A returned root releases resolver sessions and other transient rows,
    /// while the owning file and live root/window consumers stay admitted.
    pub fn release_transient_residency(&mut self) {
        self.reconcile_residency();
        let retained = self
            .resident_artifacts
            .values()
            .fold(SemanticWork::default(), |total, (_, work)| {
                total.conservative_add(*work)
            });
        let retained = self
            .resident_owners
            .values()
            .fold(retained, |sum, (_, work)| sum.conservative_add(*work));
        self.ledger = self.ledger.with_used(retained);
    }

    /// A closed query window refunds only allocations it did not promote
    /// into the caller's bounded lease continuation.
    pub fn release_unleased_artifacts(&mut self, leases: &SemanticArtifactLeaseChild) {
        self.reconcile_residency();
        let mut used = self.ledger.used();
        Arc::make_mut(&mut self.resident_artifacts).retain(|_, (allocation, work)| {
            if allocation
                .upgrade()
                .is_some_and(|artifact| leases.contains_exact(&artifact))
            {
                return true;
            }
            assert!(
                SemanticBudgetDimension::ALL
                    .iter()
                    .all(|dimension| work.get(*dimension) <= used.get(*dimension))
            );
            used = used.saturating_sub(*work);
            false
        });
        // Prepared sessions and cached results have their own holders. A
        // pooled source has no active session token after return, so its
        // admission is refunded independently of pool occupancy.
        self.ledger = self.ledger.with_used(used);
    }

    /// Associate admitted census with its allocation without pinning it.
    #[doc(hidden)]
    pub fn track_resident_artifact(&mut self, artifact: &Arc<SemanticArtifact>) {
        Arc::make_mut(&mut self.resident_artifacts).insert(
            (artifact.key().fingerprint(), Arc::as_ptr(artifact) as usize),
            (ResidentArtifact::new(artifact), artifact.work()),
        );
    }

    /// Release a temporary source admission after lowering.
    pub fn release_admission(&mut self, work: SemanticWork) {
        if work == SemanticWork::default() {
            return;
        }
        self.reconcile_residency();
        let mut used = self.ledger.used();
        assert!(
            SemanticBudgetDimension::ALL
                .iter()
                .all(|dimension| work.get(*dimension) <= used.get(*dimension))
        );
        used = used.saturating_sub(work);
        self.ledger = self.ledger.with_used(used);
    }

    /// Run a derivation whose unowned admissions are scratch. Keep performed
    /// work, peaks and separately owned artifacts, and refund scratch on both
    /// success and error before the caller admits the returned value's census.
    pub fn with_temporary_admissions<T>(&mut self, derive: impl FnOnce(&mut Self) -> T) -> T {
        let before = self.raw_resident();
        let result = derive(self);
        let scratch = self.raw_resident().saturating_sub(before);
        self.release_admission(scratch);
        result
    }

    /// Bind retained prepared source to the session that owns it. Weak tokens
    /// follow the active session, not handoffs into the prepared-dispatch cache.
    #[track_caller]
    #[doc(hidden)]
    pub fn admit_source<T: Send + Sync + 'static>(
        &mut self,
        owner: &Arc<T>,
        bytes: usize,
    ) -> Result<(), SemanticBudgetExceeded> {
        let Some(work) = self.pending_source_admission(owner, bytes) else {
            return Ok(());
        };
        self.admit(work)?;
        self.record_source_owner(owner, work);
        Ok(())
    }

    /// Hold a source snapshot whose read and parse are charged as work
    /// separately. The hold advances residency and cumulative telemetry, but
    /// not the performed read/hash/parse lane.
    #[track_caller]
    #[doc(hidden)]
    pub fn hold_source<T: Send + Sync + 'static>(
        &mut self,
        owner: &Arc<T>,
        bytes: usize,
    ) -> Result<(), SemanticBudgetExceeded> {
        let Some(work) = self.pending_source_admission(owner, bytes) else {
            return Ok(());
        };
        self.admit_held(work)?;
        self.record_source_owner(owner, work);
        Ok(())
    }

    /// Re-admit a retained source snapshot into a new region's resident ledger.
    ///
    /// The snapshot was read and parsed once. A later region re-enters it into
    /// its own finite resident allowance, which is another admission for
    /// cumulative telemetry, but another read did not happen, so the transfer
    /// must not advance the performed read/hash/parse lane.
    #[track_caller]
    #[doc(hidden)]
    pub fn readmit_source<T: Send + Sync + 'static>(
        &mut self,
        owner: &Arc<T>,
        bytes: usize,
    ) -> Result<(), SemanticBudgetExceeded> {
        let Some(work) = self.pending_source_admission(owner, bytes) else {
            return Ok(());
        };
        self.admit_held(work)?;
        self.record_source_owner(owner, work);
        Ok(())
    }

    fn pending_source_admission<T: Send + Sync + 'static>(
        &self,
        owner: &Arc<T>,
        bytes: usize,
    ) -> Option<SemanticWork> {
        let key = Arc::as_ptr(owner) as usize;
        if self
            .resident_owners
            .get(&key)
            .is_some_and(|(owner, _)| owner.strong_count() > 0)
        {
            return None;
        }
        Some(SemanticWork {
            source_bytes: bytes,
            ..SemanticWork::default()
        })
    }

    fn record_source_owner<T: Send + Sync + 'static>(
        &mut self,
        owner: &Arc<T>,
        work: SemanticWork,
    ) {
        let key = Arc::as_ptr(owner) as usize;
        Arc::make_mut(&mut self.resident_owners).insert(key, (weak_resident_owner(owner), work));
    }

    fn reconcile_residency(&mut self) {
        // Consumer state can change when another policy takes a cached artifact.
        // Decide retention and refund together: a second observation could keep
        // an artifact whose census the first observation already refunded.
        let mut resident = self.ledger.used();
        refund_expired_residents(
            Arc::make_mut(&mut self.resident_owners),
            &mut resident,
            |owner| owner.strong_count() > 0,
        );
        refund_expired_residents(
            Arc::make_mut(&mut self.resident_artifacts),
            &mut resident,
            ResidentArtifact::has_consumer,
        );
        self.ledger = self.ledger.with_used(resident);
    }

    pub fn remaining(&self) -> SemanticWork {
        self.limits().saturating_sub(self.resident())
    }

    /// Check one atomic charge without mutating this budget.
    pub fn refusal_count(&self) -> usize {
        self.ledger.refusal_count()
    }

    pub fn check_admission(&self, work: SemanticWork) -> Result<(), SemanticBudgetExceeded> {
        self.ledger
            .with_used(self.resident())
            .check(work)
            .map_err(SemanticBudgetExceeded::from)?;
        let Some(limit) = self.shared_summary_expansion_limit else {
            return Ok(());
        };
        let attempted =
            summary_expansion_count(self.resident()).saturating_add(summary_expansion_count(work));
        if attempted <= limit {
            return Ok(());
        }
        let dimension = if work.call_sites > 0 {
            SemanticBudgetDimension::CallSites
        } else if work.memory_locations > 0 {
            SemanticBudgetDimension::MemoryLocations
        } else {
            assert!(work.captures > 0, "summary expansion charge is non-empty");
            SemanticBudgetDimension::Captures
        };
        self.ledger.record_refusal();
        Err(SemanticBudgetExceeded {
            dimension,
            limit,
            attempted,
        })
    }

    /// Admit retained rows or source; a failed admission leaves the budget unchanged
    /// apart from recording the first refusal and its caller.
    ///
    /// The resident ledger is the only part that can refuse. Performed work
    /// also advances the cumulative counters.
    #[track_caller]
    pub fn admit(&mut self, work: SemanticWork) -> Result<(), SemanticBudgetExceeded> {
        self.admit_held(work)?;
        self.performed = self.performed.saturating_add(work);
        Ok(())
    }

    /// Admit a census that is held but not performed: a source snapshot is
    /// retained for later calls, and its read and parse are charged as work
    /// where they happen. Holding it is cumulative telemetry, not another
    /// read.
    #[track_caller]
    fn admit_held(&mut self, work: SemanticWork) -> Result<(), SemanticBudgetExceeded> {
        self.admit_resident(work)?;
        self.cumulative = self.cumulative.saturating_add(work);
        Ok(())
    }

    /// Admit a resident census without advancing cumulative performed-work
    /// telemetry.
    ///
    /// A census that moves between ledgers was already counted where it was
    /// first admitted, and a repeat lookup of a paid identity holds its
    /// allocation until the consumer releases it. This charges the receiving
    /// ledger's residency so its finite bounds still hold, and leaves the
    /// cumulative counters alone.
    #[track_caller]
    fn admit_resident(&mut self, work: SemanticWork) -> Result<(), SemanticBudgetExceeded> {
        let site = std::panic::Location::caller();
        if let Err(exceeded) = self.check_admission(work) {
            self.first_refusal
                .get_or_init(|| SemanticBudgetRefusal { exceeded, site });
            return Err(exceeded);
        }
        self.reconcile_residency();
        self.ledger.charge(work).map_err(|exceeded| {
            let exceeded = SemanticBudgetExceeded::from(exceeded);
            self.first_refusal
                .get_or_init(|| SemanticBudgetRefusal { exceeded, site });
            exceeded
        })?;
        self.resident_peak = self.resident_peak.component_max(self.ledger.used());
        Ok(())
    }

    /// Record performed work as telemetry. Only retained admissions can refuse.
    pub fn charge_work(&mut self, work: SemanticWork) {
        self.root_work = self.root_work.saturating_add(work);
        self.cumulative = self.cumulative.saturating_add(work);
        self.performed = self.performed.saturating_add(work);
        self.root_work_peak = self.root_work_peak.component_max(self.root_work);
        self.observe_root_work();
    }

    pub const fn root_work_peak(&self) -> SemanticWork {
        self.root_work_peak
    }

    /// Record actual lowering traversal independently of publication rollback.
    /// Builder checks still use value ledgers; this recorder records performed
    /// steps only, never speculative census checks on staging copies.
    #[doc(hidden)]
    pub fn start_lowering_work(&mut self) {
        self.lowering_work = Some(Arc::new(Mutex::new(SemanticWork::default())));
    }

    #[doc(hidden)]
    pub fn note_lowering_work(&self, work: SemanticWork) {
        if let Some(recorded) = &self.lowering_work {
            let mut recorded = recorded.lock().expect("lowering work recorder");
            *recorded = recorded.conservative_add(work);
        }
    }

    #[doc(hidden)]
    pub fn finish_lowering_work(&mut self) {
        if let Some(recorded) = self.lowering_work.take() {
            let work = *recorded.lock().expect("lowering work recorder");
            self.charge_work(work);
        }
    }

    pub fn replay_snapshot(&mut self) -> SemanticBudgetReplaySnapshot {
        self.replay_observers
            .retain(|observer| observer.owner.strong_count() > 0);
        let owner = Arc::new(());
        self.replay_observers.push(ReplayObserver {
            owner: Arc::downgrade(&owner),
            base: self.root_work,
            peak: SemanticWork::default(),
        });
        SemanticBudgetReplaySnapshot {
            owner,
            cumulative: self.used(),
            performed: self.performed,
            artifacts: Arc::clone(&self.resident_artifacts),
            owners: Arc::clone(&self.resident_owners),
            raw_resident: self.raw_resident(),
        }
    }

    fn raw_resident(&self) -> SemanticWork {
        // The raw balance and registry describe the same admissions. Remove
        // every registered census once, without polling mutable consumer state.
        let mut raw = self.ledger.used();
        for (_, census) in self.resident_artifacts.values() {
            raw = raw.saturating_sub(*census);
        }
        for (_, census) in self.resident_owners.values() {
            raw = raw.saturating_sub(*census);
        }
        raw
    }

    /// Bind already-admitted result rows to the cache entry that now holds
    /// them. Artifact and source identities retain their own exact weak owners.
    pub fn bind_replay_holder<T: Send + Sync + 'static>(
        &mut self,
        owner: &Arc<T>,
        before: &SemanticBudgetReplaySnapshot,
    ) -> SemanticWork {
        let census = self.raw_resident().saturating_sub(before.raw_resident);
        let key = Arc::as_ptr(owner) as usize;
        if let Some((_, retained)) = Arc::make_mut(&mut self.resident_owners).get_mut(&key) {
            *retained = retained.conservative_add(census);
        } else {
            self.track_replay_holder(owner, census);
        }
        census
    }

    pub fn has_replay_holder<T: Send + Sync + 'static>(&self, owner: &Arc<T>) -> bool {
        self.resident_owners
            .get(&(Arc::as_ptr(owner) as usize))
            .is_some_and(|(allocation, _)| allocation.strong_count() > 0)
    }

    pub fn track_replay_holder<T: Send + Sync + 'static>(
        &mut self,
        owner: &Arc<T>,
        census: SemanticWork,
    ) {
        let key = Arc::as_ptr(owner) as usize;
        assert!(
            !self.resident_owners.contains_key(&key),
            "an entry is admitted once per ledger"
        );
        Arc::make_mut(&mut self.resident_owners).insert(key, (weak_resident_owner(owner), census));
    }

    pub fn replay_since(&self, before: &SemanticBudgetReplaySnapshot) -> SemanticBudgetReplay {
        let observer = self
            .replay_observers
            .iter()
            .find(|observer| observer.owner.ptr_eq(&Arc::downgrade(&before.owner)))
            .expect("the measurement interval belongs to this ledger");
        // A holder released during this interval cannot cancel a different
        // new admission of the same size. Compare identities, not net balances.
        let mut retained = self.raw_resident().saturating_sub(before.raw_resident);
        for (key, (owner, census)) in self.resident_artifacts.iter() {
            if owner.has_consumer() && !before.artifacts.contains_key(key) {
                retained = retained.conservative_add(*census);
            }
        }
        for (key, (owner, census)) in self.resident_owners.iter() {
            if owner.strong_count() > 0 && !before.owners.contains_key(key) {
                retained = retained.conservative_add(*census);
            }
        }
        SemanticBudgetReplay {
            cumulative: self.used().saturating_sub(before.cumulative),
            performed: self.performed.saturating_sub(before.performed),
            root_work_peak: observer.peak,
            retained,
        }
    }

    fn observe_root_work(&mut self) {
        let current = self.root_work;
        self.replay_observers.retain_mut(|observer| {
            observer.peak = observer
                .peak
                .component_max(current.saturating_sub(observer.base));
            observer.owner.strong_count() > 0
        });
    }

    fn observe_completed_root(&mut self, peak: SemanticWork) {
        self.replay_observers.retain_mut(|observer| {
            observer.peak = observer.peak.component_max(peak);
            observer.owner.strong_count() > 0
        });
    }

    /// A completed product may cover several independent roots. Import their
    /// work telemetry and admit only the census the replay actually retains.
    #[track_caller]
    pub fn replay_product(
        &mut self,
        replay: SemanticBudgetReplay,
    ) -> Result<(), SemanticBudgetExceeded> {
        let mut staged = self.clone();
        staged.admit(replay.retained)?;
        staged.cumulative = self.cumulative.saturating_add(replay.cumulative);
        staged.performed = self.performed.saturating_add(replay.performed);
        staged.root_work_peak = staged.root_work_peak.component_max(replay.root_work_peak);
        staged.observe_completed_root(replay.root_work_peak);
        *self = staged;
        Ok(())
    }

    /// A cached derivation continues the current root rather than completing
    /// independent roots; its original work also advances this root's telemetry.
    #[track_caller]
    pub fn replay_continuation(
        &mut self,
        replay: SemanticBudgetReplay,
    ) -> Result<(), SemanticBudgetExceeded> {
        let mut staged = self.clone();
        staged.charge_work(replay.root_work_peak);
        staged.replay_product(replay)?;
        staged.cumulative = self.cumulative.saturating_add(replay.cumulative);
        *self = staged;
        Ok(())
    }

    /// Preserve performed accounting when a projection discards its staged
    /// result. Its temporary admissions close, while accepted work and the
    /// observed high-water marks remain part of this same root.
    #[doc(hidden)]
    pub fn retain_performed_work(&mut self, staged: &Self) {
        assert!(Arc::ptr_eq(&self.scope, &staged.scope));
        self.root_work = self.root_work.component_max(staged.root_work);
        self.cumulative = self.cumulative.component_max(staged.cumulative);
        self.performed = self.performed.component_max(staged.performed);
        self.resident_peak = self.resident_peak.component_max(staged.resident_peak);
        self.root_work_peak = self.root_work_peak.component_max(staged.root_work_peak);
        self.observe_root_work();
    }

    /// Start another independent solver root while preserving query counters.
    pub fn begin_root(&mut self) {
        self.root_work = SemanticWork::default();
        for observer in &mut self.replay_observers {
            observer.base = SemanticWork::default();
        }
    }

    /// A finished root contributes counters and peaks, never another root's allowance.
    pub fn absorb_root_work(&mut self, child: Self) {
        assert!(
            Arc::ptr_eq(&self.scope, &child.scope),
            "root belongs to this semantic scope"
        );
        // Root-local artifact handles close with the solve, but prepared
        // source and cached result owners may survive in the query's bounded
        // caches. Transfer only those admissions that still have a holder.
        let cumulative = self.cumulative;
        let performed = self.performed;
        for (key, (owner, census)) in child.resident_owners.iter() {
            if owner.strong_count() > 0 && !self.resident_owners.contains_key(key) {
                self.admit(*census)
                    .expect("a root admitted its live owners against the parent's grant");
                Arc::make_mut(&mut self.resident_owners).insert(*key, (owner.clone(), *census));
            }
        }
        self.observe_completed_root(child.root_work_peak);
        self.cumulative = cumulative.saturating_add(child.cumulative);
        self.performed = performed.saturating_add(child.performed);
        self.resident_peak = self.resident_peak.component_max(child.resident_peak);
        self.root_work_peak = self.root_work_peak.component_max(child.root_work_peak);
    }

    /// The first charge this ledger, or a staging copy of it, refused.
    pub fn first_refusal(&self) -> Option<SemanticBudgetRefusal> {
        self.first_refusal.get().copied()
    }

    /// Snapshot this budget's logical scope and paid artifact identities.
    ///
    /// A child created from this snapshot starts with the same paid identities
    /// but an independent scalar ledger. It can therefore charge only repeat
    /// work for an overlapping complete artifact.
    pub fn scope_snapshot(&self) -> SemanticBudgetScopeSnapshot {
        let mut admitted_artifacts = Arc::clone(&self.inherited_artifacts);
        if admitted_artifacts.is_empty() {
            admitted_artifacts = Arc::clone(&self.resident_artifacts);
        } else if !self.resident_artifacts.is_empty() {
            Arc::make_mut(&mut admitted_artifacts).extend(
                self.resident_artifacts
                    .iter()
                    .map(|(key, value)| (*key, value.clone())),
            );
        }
        // Cache-only identities cannot grant a continuation free residency.
        // A later lookup creates a new consumer and must admit it in that
        // continuation rather than inherit a census no parent currently holds.
        if admitted_artifacts
            .values()
            .any(|(owner, _)| !owner.has_consumer())
        {
            Arc::make_mut(&mut admitted_artifacts).retain(|_, (owner, _)| owner.has_consumer());
        }
        SemanticBudgetScopeSnapshot {
            admitted_artifacts,
            scope: Arc::clone(&self.scope),
            charged_artifacts: Arc::clone(&self.charged_artifacts),
            shared_summary_expansion_limit: self
                .shared_summary_expansion_limit
                .map(|limit| limit.saturating_sub(summary_expansion_count(self.resident()))),
            lowered: Arc::clone(&self.lowered),
        }
    }

    /// Capture only this ledger's logical scope identity, without retaining
    /// its copy-on-write charged-artifact set.
    #[doc(hidden)]
    pub fn scope_identity(&self) -> SemanticBudgetScopeIdentity {
        SemanticBudgetScopeIdentity {
            scope: Arc::clone(&self.scope),
        }
    }

    /// Whether this ledger belongs to the same logical accounting scope as a
    /// previously captured identity. Cloned and child ledgers share a scope;
    /// a newly constructed budget does not.
    #[doc(hidden)]
    pub fn shares_scope_with(&self, identity: &SemanticBudgetScopeIdentity) -> bool {
        Arc::ptr_eq(&self.scope, &identity.scope)
    }

    /// Create an independently bounded child ledger in the same logical scope.
    ///
    /// The child starts with no scalar work, but inherits the artifact censuses
    /// its parent already paid. Source sessions have no artifact lease, so a
    /// continuation receives no source-identity credit from this snapshot.
    /// Only source admissions it actually holds transfer with its child charge.
    /// A root child below takes over the parent's live census and identities.
    pub fn new_child(limits: SemanticWork, parent: &SemanticBudgetScopeSnapshot) -> Self {
        Self {
            ledger: BudgetLedger::new(limits, SemanticWork::default()),
            cumulative: SemanticWork::default(),
            performed: SemanticWork::default(),
            root_work: SemanticWork::default(),
            root_work_peak: SemanticWork::default(),
            replay_observers: Vec::new(),
            lowering_work: None,
            resident_peak: SemanticWork::default(),
            resident_artifacts: Arc::default(),
            resident_owners: Arc::default(),
            inherited_artifacts: Arc::clone(&parent.admitted_artifacts),
            scope: Arc::clone(&parent.scope),
            charged_artifacts: Arc::clone(&parent.charged_artifacts),
            shared_summary_expansion_limit: parent.shared_summary_expansion_limit,
            first_refusal: Arc::default(),
            lowered: Arc::clone(&parent.lowered),
        }
    }

    /// A root's callee admissions coexist with the parent's current file.
    /// Unlike a child granted the parent's remaining allowance, this root
    /// receives the full cap and starts with the already resident census.
    pub fn new_root_child(parent: &Self) -> Self {
        let mut child = Self::new_child(parent.limits(), &parent.scope_snapshot());
        // Copy the raw balance with its raw weak registry, then refund once.
        // An effective balance with expired entries would refund them twice.
        child.ledger = parent.ledger.with_used(parent.ledger.used());
        child.shared_summary_expansion_limit = parent.shared_summary_expansion_limit;
        child.resident_artifacts = Arc::clone(&parent.resident_artifacts);
        child.resident_owners = Arc::clone(&parent.resident_owners);
        child.reconcile_residency();
        child.resident_peak = child.ledger.used();
        child
    }

    /// Atomically charge one child ledger's scalar work and import its exact
    /// artifact identities.
    ///
    /// The caller supplies the scalar charge because a coordinator may expose
    /// a different retained-memory measure than the provider's owned-text
    /// lane. Identities become paid only if that scalar charge succeeds.
    pub fn into_child_charge(mut self) -> SemanticBudgetCharge {
        self.reconcile_residency();
        let work = self.used();
        SemanticBudgetCharge {
            resident: self.ledger.used(),
            resident_artifacts: self.resident_artifacts,
            resident_owners: self.resident_owners,
            scope: self.scope,
            work,
            performed: self.performed,
            resident_peak: self.resident_peak,
            root_work_peak: self.root_work_peak,
            charged_artifacts: self.charged_artifacts,
        }
    }

    fn child_resident_addition(&self, charge: &SemanticBudgetCharge) -> SemanticWork {
        let mut resident = charge.resident;
        for (key, (owner, census)) in charge.resident_artifacts.iter() {
            if !owner.has_consumer() || self.resident_artifacts.contains_key(key) {
                resident = resident.saturating_sub(*census);
            }
        }
        for (key, (owner, census)) in charge.resident_owners.iter() {
            if owner.strong_count() == 0 || self.resident_owners.contains_key(key) {
                resident = resident.saturating_sub(*census);
            }
        }
        resident
    }

    #[track_caller]
    pub fn apply_child_charge(
        &mut self,
        work: SemanticWork,
        charge: SemanticBudgetCharge,
    ) -> Result<(), SemanticBudgetExceeded> {
        assert!(
            Arc::ptr_eq(&self.scope, &charge.scope),
            "semantic child charge belongs to a different logical scope"
        );
        let mut charge = charge;
        // A cache can evict between producing and importing this receipt.
        // Keep live allocations held until their admission registry commits.
        let mut artifact_holders = Vec::new();
        let mut cache_holders = Vec::new();
        let resident = &mut charge.resident;
        Arc::make_mut(&mut charge.resident_artifacts).retain(|_, (owner, census)| {
            if let Some(holder) = owner.consumer() {
                artifact_holders.push(holder);
                true
            } else {
                *resident = resident.saturating_sub(*census);
                false
            }
        });
        Arc::make_mut(&mut charge.resident_owners).retain(|_, (owner, census)| {
            if let Some(holder) = owner.upgrade() {
                cache_holders.push(holder);
                true
            } else {
                *resident = resident.saturating_sub(*census);
                false
            }
        });
        let mut staged = self.clone();
        let total = work.component_max(charge.work);
        let performed = charge.performed;
        let bounded = self
            .child_resident_addition(&charge)
            .conservative_add(work.saturating_sub(charge.work));
        staged.replay_product(SemanticBudgetReplay {
            cumulative: total,
            performed,
            root_work_peak: charge.root_work_peak,
            retained: bounded,
        })?;
        Arc::make_mut(&mut staged.resident_artifacts).extend(
            charge
                .resident_artifacts
                .iter()
                .map(|(key, value)| (*key, value.clone())),
        );
        Arc::make_mut(&mut staged.resident_owners).extend(
            charge
                .resident_owners
                .iter()
                .map(|(key, value)| (*key, value.clone())),
        );
        staged.resident_peak = staged.resident_peak.component_max(charge.resident_peak);
        if !Arc::ptr_eq(&staged.charged_artifacts, &charge.charged_artifacts) {
            let charged = Arc::make_mut(&mut staged.charged_artifacts);
            charged.extend(charge.charged_artifacts.iter().copied());
        }
        *self = staged;
        drop((artifact_holders, cache_holders));
        Ok(())
    }

    /// Check the conservative scalar charge required to import a child charge.
    ///
    /// A coordinator may price retained memory more conservatively than the
    /// provider's owned-text lane, but it may never import paid identities for
    /// less than the child ledger actually charged.
    pub fn check_child_charge(
        &self,
        work: SemanticWork,
        charge: &SemanticBudgetCharge,
    ) -> Result<(), SemanticBudgetExceeded> {
        assert!(
            Arc::ptr_eq(&self.scope, &charge.scope),
            "semantic child charge belongs to a different logical scope"
        );
        let bounded = self
            .child_resident_addition(charge)
            .conservative_add(work.saturating_sub(charge.work));
        self.check_admission(bounded)
    }

    #[doc(hidden)]
    pub fn record_lowering(&self, key: StableDigest) -> bool {
        !self
            .lowered
            .lock()
            .expect("lowering timing registry")
            .insert(key)
    }

    /// Whether this budget has already been charged one artifact's full
    /// retained-row census.
    pub fn has_charged_artifact(&self, artifact: StableDigest) -> bool {
        self.charged_artifacts.contains(&artifact)
    }

    pub(crate) fn has_charged_allocation(&self, artifact: &Arc<SemanticArtifact>) -> bool {
        let key = (artifact.key().fingerprint(), Arc::as_ptr(artifact) as usize);
        self.resident_artifacts
            .get(&key)
            .or_else(|| self.inherited_artifacts.get(&key))
            .is_some_and(|(allocation, _)| allocation.has_consumer())
    }

    #[track_caller]
    #[doc(hidden)]
    pub fn charge_complete_artifact(
        &mut self,
        artifact: &Arc<SemanticArtifact>,
    ) -> Result<(), SemanticBudgetExceeded> {
        let identity = artifact.key().fingerprint();
        if self.has_charged_allocation(artifact) {
            return self.charge_complete_artifact_hit(identity, artifact.work());
        }
        let census = artifact.work();
        if self.has_charged_artifact(identity) {
            // The scope already performed this census. The returned
            // allocation is live until its consumer releases it, so it spends
            // residency, but a repeat lookup is the only new work.
            self.admit_resident(census)?;
            self.track_resident_artifact(artifact);
            return self.charge_complete_artifact_hit(identity, census);
        }
        self.admit(census)?;
        self.record_charged_artifact(identity);
        self.track_resident_artifact(artifact);
        Ok(())
    }

    /// Record that this budget has paid one artifact's full retained-row
    /// census, so a later cache hit on the same artifact is charged as the
    /// lookup it is.
    pub fn record_charged_artifact(&mut self, artifact: StableDigest) {
        if self.charged_artifacts.contains(&artifact) {
            return;
        }
        Arc::make_mut(&mut self.charged_artifacts).insert(artifact);
    }

    /// A cached, handle-free index remembers a file window's census but holds
    /// no executable rows. Preserve its historical counter and cold admission
    /// guard without pretending the released artifact is still resident.
    #[track_caller]
    pub fn replay_released_artifact_census(
        &mut self,
        artifact: StableDigest,
        census: SemanticWork,
    ) -> Result<(), SemanticBudgetExceeded> {
        let mut staged = self.clone();
        staged.check_admission(census)?;
        let lookup = SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        };
        staged.charge_work(lookup);
        if !staged.has_charged_artifact(artifact) {
            staged.replay_product(SemanticBudgetReplay {
                cumulative: census,
                performed: census,
                root_work_peak: SemanticWork::default(),
                retained: SemanticWork::default(),
            })?;
            staged.record_charged_artifact(artifact);
        }
        *self = staged;
        Ok(())
    }

    /// Charge the canonical complete-artifact cache-hit cost atomically.
    #[doc(hidden)]
    #[track_caller]
    pub fn charge_complete_artifact_hit(
        &mut self,
        artifact: StableDigest,
        full_work: SemanticWork,
    ) -> Result<(), SemanticBudgetExceeded> {
        let mut staged = self.clone();
        if staged.has_charged_artifact(artifact) {
            // Looking up a live admission performs work without retaining
            // another row. Even an artifact at the resident limit can be read.
            staged.charge_work(SemanticWork {
                nested_entries: 1,
                ..SemanticWork::default()
            });
        } else {
            staged.admit(full_work)?;
            staged.record_charged_artifact(artifact);
        }
        *self = staged;
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn charged_artifact_count(&self) -> usize {
        self.charged_artifacts.len()
    }
}

impl Default for SemanticBudget {
    fn default() -> Self {
        Self::new(SemanticWork::default_limits()).expect("default semantic budgets are positive")
    }
}

/// Cross-provider accounting for distinct workspace files entered and traversal
/// steps performed while resolving them. Ordinary execution ledgers record
/// traversal as non-refusing telemetry; a dedicated fixpoint ledger also bounds it.
///
/// The shared ledger is deliberately request-scoped. Nested oracle requests
/// clone the handle, not the allowance, so dispatch cannot reset the caller's
/// file cap when it materializes candidate targets.
#[derive(Debug, Clone)]
pub struct SemanticExecutionBudget {
    state: Arc<Mutex<SemanticExecutionBudgetState>>,
}

#[derive(Debug)]
struct SemanticExecutionBudgetState {
    max_materialized_files: usize,
    max_traversal_steps: Option<usize>,

    materialized_files: Arc<BTreeSet<ProjectFile>>,
    externally_materialized_files: usize,
    traversal_steps: usize,
    exhausted: bool,
}

/// Exact in-process identity of the provider work already charged to one
/// request-scoped execution budget.
///
/// The materialized file identities are retained instead of being collapsed
/// to a count: files already admitted can be revisited without consuming
/// another slot, so two ledgers with equal remaining counts are not
/// behaviorally interchangeable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SemanticExecutionBudgetSnapshot {
    max_materialized_files: usize,
    max_traversal_steps: Option<usize>,

    materialized_files: Arc<BTreeSet<ProjectFile>>,
    externally_materialized_files: usize,
    traversal_steps: usize,
    exhausted: bool,
}

impl SemanticExecutionBudgetSnapshot {
    fn from_state(state: &SemanticExecutionBudgetState) -> Self {
        Self {
            max_materialized_files: state.max_materialized_files,
            max_traversal_steps: state.max_traversal_steps,

            materialized_files: Arc::clone(&state.materialized_files),
            externally_materialized_files: state.externally_materialized_files,
            traversal_steps: state.traversal_steps,
            exhausted: state.exhausted,
        }
    }

    pub fn retained_bytes(&self) -> usize {
        // The set owns B-tree nodes in addition to one cloned `ProjectFile`
        // handle per identity. Rust does not expose node allocations, so use a
        // deliberately sparse-tree upper estimate rather than the old flat
        // slice size; a COW snapshot can be the last owner of the old tree.
        const ARC_HEADER_BYTES: usize = 2 * std::mem::size_of::<usize>();
        const BTREE_NODE_BYTES_PER_FILE: usize = 32 * std::mem::size_of::<usize>();
        let container_bytes = std::mem::size_of::<Self>()
            .saturating_add(ARC_HEADER_BYTES)
            .saturating_add(std::mem::size_of::<BTreeSet<ProjectFile>>());
        self.materialized_files
            .iter()
            .fold(container_bytes, |bytes, file| {
                bytes
                    .saturating_add(BTREE_NODE_BYTES_PER_FILE)
                    .saturating_add(file.retained_bytes())
            })
    }

    pub fn contains_materialized_file(&self, file: &ProjectFile) -> bool {
        self.materialized_files.contains(file)
    }
}

/// Provider-execution work that an exact cached result must replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticExecutionBudgetCharge {
    materialized_files: Box<[ProjectFile]>,
    externally_materialized_files: usize,
    traversal_steps: usize,
    exhausted: bool,
}

impl SemanticExecutionBudgetCharge {
    pub fn retained_bytes(&self) -> usize {
        self.materialized_files
            .iter()
            .fold(std::mem::size_of::<Self>(), |bytes, file| {
                bytes.saturating_add(file.retained_bytes())
            })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SemanticExecutionWork {
    pub materialized_files: usize,
    pub traversal_steps: usize,
    pub exhausted: bool,
}

impl SemanticExecutionBudget {
    pub fn new(max_materialized_files: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(SemanticExecutionBudgetState {
                max_materialized_files,
                max_traversal_steps: None,

                materialized_files: Arc::new(BTreeSet::new()),
                externally_materialized_files: 0,
                traversal_steps: 0,
                exhausted: max_materialized_files == 0,
            })),
        }
    }

    /// A fresh per-fixpoint traversal allowance, independent of other solves.
    /// The caller's request retains its ordinary file accounting and also
    /// records the traversal work.
    pub fn for_fixpoint(max_traversal_steps: usize) -> Self {
        let execution = Self::new(usize::MAX);
        execution
            .state
            .lock()
            .expect("semantic execution budget lock")
            .max_traversal_steps = Some(max_traversal_steps);
        execution
    }

    pub fn work(&self) -> SemanticExecutionWork {
        let state = self.state.lock().expect("semantic execution budget lock");
        SemanticExecutionWork {
            materialized_files: state
                .externally_materialized_files
                .saturating_add(state.materialized_files.len()),
            traversal_steps: state.traversal_steps,
            exhausted: state.exhausted,
        }
    }

    pub fn snapshot(&self) -> SemanticExecutionBudgetSnapshot {
        let state = self.state.lock().expect("semantic execution budget lock");
        SemanticExecutionBudgetSnapshot::from_state(&state)
    }

    /// Fork an independently mutable child from one exact parent state.
    ///
    /// The snapshot and child are captured under the same lock. The child can
    /// revisit already-admitted files at zero new-file cost, and its exact
    /// delta can later be imported with [`Self::replay_charge`].
    pub fn fork(&self) -> (SemanticExecutionBudgetSnapshot, Self) {
        self.fork_with_materialized_file_limit(usize::MAX)
    }

    /// Fork an exact child whose new-file allowance is capped for one nested
    /// consumer. A dedicated fixpoint's traversal allowance is inherited.
    ///
    /// The pair is captured and the narrower maxima are derived under one
    /// parent lock, so callers cannot mismatch a snapshot and child. Reaching
    /// a narrower maximum remains complete; only a refused operation marks the
    /// child exhausted, which a replay records as performed incomplete work.
    pub fn fork_with_materialized_file_limit(
        &self,
        max_new_materialized_files: usize,
    ) -> (SemanticExecutionBudgetSnapshot, Self) {
        let state = self.state.lock().expect("semantic execution budget lock");
        let before = SemanticExecutionBudgetSnapshot::from_state(&state);
        let used_files = state
            .externally_materialized_files
            .saturating_add(state.materialized_files.len());
        let child = Self {
            state: Arc::new(Mutex::new(SemanticExecutionBudgetState {
                max_materialized_files: state
                    .max_materialized_files
                    .min(used_files.saturating_add(max_new_materialized_files)),
                max_traversal_steps: state.max_traversal_steps,
                materialized_files: Arc::clone(&state.materialized_files),
                externally_materialized_files: state.externally_materialized_files,
                traversal_steps: state.traversal_steps,
                exhausted: state.exhausted,
            })),
        };
        (before, child)
    }

    pub fn charge_since(
        &self,
        before: &SemanticExecutionBudgetSnapshot,
    ) -> Option<SemanticExecutionBudgetCharge> {
        let state = self.state.lock().expect("semantic execution budget lock");
        if state.max_materialized_files > before.max_materialized_files
            || state.max_traversal_steps != before.max_traversal_steps
            || state.externally_materialized_files < before.externally_materialized_files
            || state.traversal_steps < before.traversal_steps
            || before
                .materialized_files
                .iter()
                .any(|file| !state.materialized_files.contains(file))
        {
            return None;
        }
        let mut materialized_files =
            if Arc::ptr_eq(&state.materialized_files, &before.materialized_files) {
                Vec::new()
            } else {
                state
                    .materialized_files
                    .difference(&before.materialized_files)
                    .cloned()
                    .collect::<Vec<_>>()
            };
        materialized_files.sort_unstable_by(|left, right| {
            left.root()
                .cmp(right.root())
                .then_with(|| left.rel_path().cmp(right.rel_path()))
        });
        Some(SemanticExecutionBudgetCharge {
            materialized_files: materialized_files.into_boxed_slice(),
            externally_materialized_files: state
                .externally_materialized_files
                .saturating_sub(before.externally_materialized_files),
            traversal_steps: state.traversal_steps.saturating_sub(before.traversal_steps),
            exhausted: state.exhausted && !before.exhausted,
        })
    }

    fn replay_charge_totals(
        state: &SemanticExecutionBudgetState,
        expected_before: &SemanticExecutionBudgetSnapshot,
        charge: &SemanticExecutionBudgetCharge,
    ) -> Option<(usize, usize)> {
        if SemanticExecutionBudgetSnapshot::from_state(state) != *expected_before
            || charge
                .materialized_files
                .iter()
                .any(|file| state.materialized_files.contains(file))
        {
            return None;
        }
        let attempted_files = state
            .externally_materialized_files
            .checked_add(state.materialized_files.len())
            .and_then(|used| used.checked_add(charge.externally_materialized_files))
            .and_then(|used| used.checked_add(charge.materialized_files.len()))?;
        let attempted_traversal = state.traversal_steps.saturating_add(charge.traversal_steps);
        if attempted_files > state.max_materialized_files
            || state.max_traversal_steps.is_some_and(|limit| {
                charge.traversal_steps > limit.saturating_sub(state.traversal_steps)
            })
        {
            return None;
        }
        Some((attempted_files, attempted_traversal))
    }

    /// Whether [`Self::replay_charge`] can reproduce this exact child delta
    /// without mutating the execution ledger.
    pub fn can_replay_charge(
        &self,
        expected_before: &SemanticExecutionBudgetSnapshot,
        charge: &SemanticExecutionBudgetCharge,
    ) -> bool {
        let state = self.state.lock().expect("semantic execution budget lock");
        Self::replay_charge_totals(&state, expected_before, charge).is_some()
    }

    /// Atomically reproduce provider work from an exact cached solve.
    pub fn replay_charge(
        &self,
        expected_before: &SemanticExecutionBudgetSnapshot,
        charge: &SemanticExecutionBudgetCharge,
    ) -> bool {
        let mut state = self.state.lock().expect("semantic execution budget lock");
        let Some((_, attempted_traversal)) =
            Self::replay_charge_totals(&state, expected_before, charge)
        else {
            brokk_bifrost_core::analyzer::carried_context::mark_execution_dependent();
            return false;
        };
        if !charge.materialized_files.is_empty() {
            Arc::make_mut(&mut state.materialized_files)
                .extend(charge.materialized_files.iter().cloned());
        }
        state.externally_materialized_files += charge.externally_materialized_files;
        state.traversal_steps = attempted_traversal;
        state.exhausted |= charge.exhausted;
        true
    }

    pub fn remaining_materialized_files(&self) -> usize {
        let state = self.state.lock().expect("semantic execution budget lock");
        state.max_materialized_files.saturating_sub(
            state
                .externally_materialized_files
                .saturating_add(state.materialized_files.len()),
        )
    }

    pub fn admit_materialization(&self, file: &ProjectFile) -> bool {
        let mut state = self.state.lock().expect("semantic execution budget lock");
        if state.materialized_files.contains(file) {
            return true;
        }
        let used = state
            .externally_materialized_files
            .saturating_add(state.materialized_files.len());
        if used >= state.max_materialized_files {
            state.exhausted = true;
            brokk_bifrost_core::analyzer::carried_context::mark_execution_dependent();
            return false;
        }
        Arc::make_mut(&mut state.materialized_files).insert(file.clone());
        true
    }

    pub fn charge_external_query_work(
        &self,
        materialized_files: usize,
        traversal_steps: usize,
    ) -> bool {
        // CodeQuery currently reports only a count, not the identities, of
        // semantic materializations. Keep those slots anonymous: associating
        // them with final result paths would be unsound for branches that
        // materialize one file while producing evidence from another.
        self.charge_external_work(materialized_files, traversal_steps)
    }

    fn charge_external_work(&self, materialized_files: usize, traversal_steps: usize) -> bool {
        let mut state = self.state.lock().expect("semantic execution budget lock");
        let Some(attempted_files) = state
            .externally_materialized_files
            .checked_add(state.materialized_files.len())
            .and_then(|used| used.checked_add(materialized_files))
        else {
            state.exhausted = true;
            brokk_bifrost_core::analyzer::carried_context::mark_execution_dependent();
            return false;
        };
        let attempted_traversal = state.traversal_steps.saturating_add(traversal_steps);
        if attempted_files > state.max_materialized_files
            || state
                .max_traversal_steps
                .is_some_and(|limit| traversal_steps > limit.saturating_sub(state.traversal_steps))
        {
            state.exhausted = true;
            brokk_bifrost_core::analyzer::carried_context::mark_execution_dependent();
            return false;
        }
        state.externally_materialized_files += materialized_files;
        state.traversal_steps = attempted_traversal;
        true
    }

    pub fn charge_traversal(&self, steps: usize) -> bool {
        self.charge_external_work(0, steps)
    }
}

/// A semantic result whose uncertainty, partial value, and work remain explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticOutcome<T> {
    Complete {
        value: T,
        work: SemanticWork,
    },
    Ambiguous {
        candidates: T,
        work: SemanticWork,
    },
    Unknown {
        partial: Option<T>,
        work: SemanticWork,
    },
    Unsupported {
        capability: SemanticCapability,
        partial: Option<T>,
        work: SemanticWork,
    },
    Unproven {
        partial: T,
        work: SemanticWork,
    },
    ExceededBudget {
        partial: Option<T>,
        exceeded: SemanticBudgetExceeded,
        work: SemanticWork,
    },
    Cancelled {
        partial: Option<T>,
        work: SemanticWork,
    },
}

impl<T> SemanticOutcome<T> {
    /// Stable lowercase label for this outcome variant.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Complete { .. } => "complete",
            Self::Ambiguous { .. } => "ambiguous",
            Self::Unknown { .. } => "unknown",
            Self::Unsupported { .. } => "unsupported",
            Self::Unproven { .. } => "unproven",
            Self::ExceededBudget { .. } => "exceeded_budget",
            Self::Cancelled { .. } => "cancelled",
        }
    }

    pub const fn work(&self) -> SemanticWork {
        match self {
            Self::Complete { work, .. }
            | Self::Ambiguous { work, .. }
            | Self::Unknown { work, .. }
            | Self::Unsupported { work, .. }
            | Self::Unproven { work, .. }
            | Self::ExceededBudget { work, .. }
            | Self::Cancelled { work, .. } => *work,
        }
    }

    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }

    pub const fn budget_exceeded(&self) -> Option<SemanticBudgetExceeded> {
        match self {
            Self::ExceededBudget { exceeded, .. } => Some(*exceeded),
            Self::Complete { .. }
            | Self::Ambiguous { .. }
            | Self::Unknown { .. }
            | Self::Unsupported { .. }
            | Self::Unproven { .. }
            | Self::Cancelled { .. } => None,
        }
    }

    pub fn available_value(&self) -> Option<&T> {
        match self {
            Self::Complete { value, .. } => Some(value),
            Self::Ambiguous { candidates, .. } => Some(candidates),
            Self::Unknown { partial, .. }
            | Self::Unsupported { partial, .. }
            | Self::ExceededBudget { partial, .. }
            | Self::Cancelled { partial, .. } => partial.as_ref(),
            Self::Unproven { partial, .. } => Some(partial),
        }
    }

    /// Clone a finished provider verdict for zero-work replay.
    ///
    /// Budget exhaustion and cancellation describe the request, not the
    /// semantic input, so they cannot become cache entries. A value-less
    /// `Unknown` or `Unsupported` has no retained result worth replaying.
    pub fn completed_replay(&self) -> Option<Self>
    where
        T: Clone,
    {
        let work = SemanticWork::default();
        match self {
            Self::Complete { value, .. } => Some(Self::Complete {
                value: value.clone(),
                work,
            }),
            Self::Ambiguous { candidates, .. } => Some(Self::Ambiguous {
                candidates: candidates.clone(),
                work,
            }),
            Self::Unproven { partial, .. } => Some(Self::Unproven {
                partial: partial.clone(),
                work,
            }),
            Self::Unknown {
                partial: Some(partial),
                ..
            } => Some(Self::Unknown {
                partial: Some(partial.clone()),
                work,
            }),
            Self::Unsupported {
                capability,
                partial: Some(partial),
                ..
            } => Some(Self::Unsupported {
                capability: *capability,
                partial: Some(partial.clone()),
                work,
            }),
            Self::Unknown { partial: None, .. }
            | Self::Unsupported { partial: None, .. }
            | Self::ExceededBudget { .. }
            | Self::Cancelled { .. } => None,
        }
    }

    pub fn map<U>(self, mapper: impl FnOnce(T) -> U) -> SemanticOutcome<U> {
        match self.try_map(|value| Ok::<_, std::convert::Infallible>(mapper(value))) {
            Ok(outcome) => outcome,
            Err(never) => match never {},
        }
    }

    pub fn try_map<U, E>(
        self,
        mapper: impl FnOnce(T) -> Result<U, E>,
    ) -> Result<SemanticOutcome<U>, E> {
        Ok(match self {
            Self::Complete { value, work } => SemanticOutcome::Complete {
                value: mapper(value)?,
                work,
            },
            Self::Ambiguous { candidates, work } => SemanticOutcome::Ambiguous {
                candidates: mapper(candidates)?,
                work,
            },
            Self::Unknown { partial, work } => SemanticOutcome::Unknown {
                partial: partial.map(mapper).transpose()?,
                work,
            },
            Self::Unsupported {
                capability,
                partial,
                work,
            } => SemanticOutcome::Unsupported {
                capability,
                partial: partial.map(mapper).transpose()?,
                work,
            },
            Self::Unproven { partial, work } => SemanticOutcome::Unproven {
                partial: mapper(partial)?,
                work,
            },
            Self::ExceededBudget {
                partial,
                exceeded,
                work,
            } => SemanticOutcome::ExceededBudget {
                partial: partial.map(mapper).transpose()?,
                exceeded,
                work,
            },
            Self::Cancelled { partial, work } => SemanticOutcome::Cancelled {
                partial: partial.map(mapper).transpose()?,
                work,
            },
        })
    }
}

/// Request-local controls for one semantic materialization.
///
/// The provider borrows both values so cancellation and retained-payload
/// accounting remain owned by the caller rather than hidden in an adapter.
pub struct SemanticRequest<'a> {
    pub budget: &'a mut SemanticBudget,
    pub cancellation: &'a CancellationToken,
    execution: Option<SemanticExecutionBudget>,
    value_type_barrier_context: Option<&'a dyn crate::analyzer::semantic::ValueTypeBarrierContext>,
    #[doc(hidden)]
    pub artifact_collector: Option<SemanticArtifactCollector>,
}

impl<'a> SemanticRequest<'a> {
    pub fn new(budget: &'a mut SemanticBudget, cancellation: &'a CancellationToken) -> Self {
        Self {
            budget,
            cancellation,
            execution: None,
            artifact_collector: None,
            value_type_barrier_context: None,
        }
    }

    pub fn with_execution_budget(
        budget: &'a mut SemanticBudget,
        cancellation: &'a CancellationToken,
        execution: &SemanticExecutionBudget,
    ) -> Self {
        Self {
            budget,
            cancellation,
            execution: Some(execution.clone()),
            artifact_collector: None,
            value_type_barrier_context: None,
        }
    }

    /// Observe complete artifacts materialized by this request and its staged
    /// descendants.
    pub fn with_artifact_collector(mut self, collector: &SemanticArtifactCollector) -> Self {
        self.artifact_collector = Some(collector.clone());
        self
    }

    pub fn staged<'b>(&self, budget: &'b mut SemanticBudget) -> SemanticRequest<'b>
    where
        'a: 'b,
    {
        SemanticRequest {
            budget,
            cancellation: self.cancellation,
            execution: self.execution.clone(),
            artifact_collector: self.artifact_collector.clone(),
            value_type_barrier_context: self.value_type_barrier_context,
        }
    }

    /// Reborrow this request while replacing its execution ledger.
    ///
    /// Policy adapters use this form when one evaluation region owns a
    /// narrower execution budget. The scalar budget, cancellation token, and
    /// complete-artifact observer remain those of the surrounding request.
    pub fn staged_with_execution_budget<'b>(
        &'b mut self,
        execution: &SemanticExecutionBudget,
    ) -> SemanticRequest<'b>
    where
        'a: 'b,
    {
        SemanticRequest {
            budget: &mut *self.budget,
            cancellation: self.cancellation,
            execution: Some(execution.clone()),
            artifact_collector: self.artifact_collector.clone(),
            value_type_barrier_context: self.value_type_barrier_context,
        }
    }

    /// Borrow a native context whose operation and memos end with this request.
    pub fn with_value_type_barrier_context(
        mut self,
        context: &'a dyn crate::analyzer::semantic::ValueTypeBarrierContext,
    ) -> Self {
        self.value_type_barrier_context = Some(context);
        self
    }

    pub fn value_type_barrier_context(
        &self,
    ) -> Option<&'a dyn crate::analyzer::semantic::ValueTypeBarrierContext> {
        self.value_type_barrier_context
    }

    pub fn classify_value_type_barrier(
        &mut self,
        observation: &crate::analyzer::semantic::BarrierObservation,
        predicate: crate::analyzer::semantic::ValueTypePredicate,
    ) -> Result<
        crate::analyzer::semantic::ValueTypeBarrierDecision,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        let Some(context) = self.value_type_barrier_context() else {
            return Ok(
                crate::analyzer::semantic::ValueTypeBarrierDecision::Undecided(
                    crate::analyzer::semantic::ValueTypeBarrierReason::UnavailableObservation,
                ),
            );
        };
        context.classify(observation, predicate, self)
    }

    pub fn execution_budget(&self) -> Option<&SemanticExecutionBudget> {
        self.execution.as_ref()
    }

    #[doc(hidden)]
    pub fn artifact_collector(&self) -> Option<&SemanticArtifactCollector> {
        self.artifact_collector.as_ref()
    }

    pub(crate) fn observe_complete_artifact(
        &self,
        file: &ProjectFile,
        artifact: &Arc<SemanticArtifact>,
    ) {
        if let Some(collector) = &self.artifact_collector {
            collector.observe_complete(file, artifact);
        }
    }

    pub fn admit_materialization(&self, file: &ProjectFile) -> bool {
        self.execution
            .as_ref()
            .is_none_or(|execution| execution.admit_materialization(file))
    }

    pub fn charge_execution_traversal(&self, steps: usize) -> bool {
        self.execution
            .as_ref()
            .is_none_or(|execution| execution.charge_traversal(steps))
    }
}

/// Operational failure while a provider reads source, derives identity, or
/// validates a materialized artifact.  Semantic uncertainty remains in
/// [`SemanticOutcome`] and must not be used to disguise these failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticProviderError {
    SourceAccess(Box<str>),
    SourceAdmissionRefused {
        file: brokk_bifrost_core::analyzer::model::ProjectFile,
        reason: crate::analyzer::semantic::source_admission::SourceAdmissionRefusal,
    },
    InvalidIdentity(Box<str>),
    InvalidArtifact(SemanticIrError),
    Internal(Box<str>),
}

impl SemanticProviderError {
    pub fn invalid_artifact(error: SemanticIrError) -> Self {
        error.into()
    }

    pub fn source_admission_refused(
        file: brokk_bifrost_core::analyzer::model::ProjectFile,
        reason: crate::analyzer::semantic::source_admission::SourceAdmissionRefusal,
    ) -> Self {
        if !reason.is_intrinsic_source_rejection() {
            brokk_bifrost_core::analyzer::carried_context::mark_execution_dependent();
        }
        Self::SourceAdmissionRefused { file, reason }
    }

    pub fn is_intrinsic_source_rejection(&self) -> bool {
        matches!(self, Self::SourceAdmissionRefused { reason, .. } if reason.is_intrinsic_source_rejection())
    }

    pub fn source_access(detail: impl Into<String>) -> Self {
        brokk_bifrost_core::analyzer::carried_context::mark_execution_dependent();
        Self::SourceAccess(detail.into().into_boxed_str())
    }

    pub fn invalid_identity(detail: impl Into<String>) -> Self {
        brokk_bifrost_core::analyzer::carried_context::mark_execution_dependent();
        Self::InvalidIdentity(detail.into().into_boxed_str())
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        brokk_bifrost_core::analyzer::carried_context::mark_execution_dependent();
        Self::Internal(detail.into().into_boxed_str())
    }
}

impl From<SemanticIrError> for SemanticProviderError {
    fn from(error: SemanticIrError) -> Self {
        brokk_bifrost_core::analyzer::carried_context::mark_execution_dependent();
        Self::InvalidArtifact(error)
    }
}

impl fmt::Display for SemanticProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceAdmissionRefused { file, reason } => {
                write!(formatter, "{file}: {reason}")
            }
            Self::SourceAccess(detail) => {
                write!(formatter, "semantic source access failed: {detail}")
            }
            Self::InvalidIdentity(detail) => {
                write!(formatter, "semantic artifact identity is invalid: {detail}")
            }
            Self::InvalidArtifact(error) => write!(formatter, "{error}"),
            Self::Internal(detail) => write!(formatter, "semantic provider failed: {detail}"),
        }
    }
}

impl std::error::Error for SemanticProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidArtifact(error) => Some(error),
            Self::SourceAdmissionRefused { .. }
            | Self::SourceAccess(_)
            | Self::InvalidIdentity(_)
            | Self::Internal(_) => None,
        }
    }
}

/// One current source snapshot and the complete semantic artifact identity
/// derived from that same atomic project read.
///
/// This is not a materialized artifact and does not retain syntax or IR. It is
/// the source-bearing freshness proof used when a semantic handle crosses
/// provider calls and its exact source must be consumed by a downstream
/// resolver without a second, racing read.
#[derive(Debug, Clone)]
pub struct SemanticArtifactSourceSnapshot {
    key: SemanticArtifactKey,
    source: Arc<str>,
}

impl SemanticArtifactSourceSnapshot {
    pub fn new(key: SemanticArtifactKey, source: Arc<str>) -> Self {
        Self { key, source }
    }

    /// Complete artifact identity for this exact source snapshot.
    pub const fn key(&self) -> &SemanticArtifactKey {
        &self.key
    }

    /// Exact disk or overlay source used to derive [`Self::key`].
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn into_parts(self) -> (SemanticArtifactKey, Arc<str>) {
        (self.key, self.source)
    }
}

/// A standalone per-language adapter boundary for immutable semantic artifacts.
pub trait ProgramSemanticsProvider: Send + Sync {
    /// Stable procedure addresses, when the adapter supports inventory without IR.
    fn procedure_inventory(
        &self,
        _file: &ProjectFile,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<Option<SemanticProcedureInventory>, SemanticProviderError> {
        Ok(None)
    }

    /// Capabilities published by the semantic adapter selected for a file.
    /// This metadata is available before lowering so query planning can report
    /// unsupported relations even when the selected relation has no rows.
    fn capabilities(&self) -> SemanticCapabilities {
        SemanticCapabilities::default()
    }

    /// Capture the file's current atomic source snapshot and derive its complete
    /// semantic artifact identity without parsing or lowering procedures.
    ///
    /// `None` means the current snapshot exceeds `max_source_bytes`; source
    /// access and identity failures remain operational errors.
    fn current_artifact_source(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
    ) -> Result<Option<SemanticArtifactSourceSnapshot>, SemanticProviderError>;

    /// Exact physical storage namespace selected by this provider's adapter
    /// for `file`. This must come from the same adapter that owns the semantic
    /// source snapshot; coarse `Language` cannot distinguish dialect rows.
    fn storage_language_key_for_file(&self, _file: &ProjectFile) -> Option<StorageLanguageKey> {
        None
    }

    /// Derive the complete identity of the file's current atomic source
    /// snapshot without parsing, lowering procedures, or charging semantic
    /// work.
    ///
    /// This is the generation check for handles that cross provider calls. It
    /// uses the same adapter, IR, configuration, and dependency identity as
    /// [`Self::materialize`].
    /// `None` means the current snapshot exceeds `max_source_bytes`; source
    /// access and identity failures remain operational errors.
    fn current_artifact_key(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
    ) -> Result<Option<SemanticArtifactKey>, SemanticProviderError> {
        self.current_artifact_source(file, max_source_bytes)
            .map(|snapshot| snapshot.map(|snapshot| snapshot.key().clone()))
    }

    /// Prepare one exact file snapshot, derive its identity, and lower it as
    /// one linearized operation. Implementations cache only complete artifacts.
    fn materialize(
        &self,
        file: &ProjectFile,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError>;

    /// The stored partial flows of one procedure of the artifact `key`, from
    /// the file's complete publication. `None` when the language stores none
    /// or the publication does not carry this artifact.
    fn stored_partial_flows(
        &self,
        _file: &ProjectFile,
        _key: &SemanticArtifactKey,
        _procedure: ProcedureId,
    ) -> Result<Option<ProcedurePartialFlows>, SemanticProviderError> {
        Ok(None)
    }

    /// Whether the file's complete semantic IR rows carry the artifact `key`
    /// under the active producer epoch. `false` for a language that stores no
    /// rows, and for a file without a complete publication.
    fn has_complete_semantic_ir_rows(
        &self,
        _file: &ProjectFile,
        _key: &SemanticArtifactKey,
    ) -> Result<bool, SemanticProviderError> {
        Ok(false)
    }
}

/// A [`ProgramSemanticsProvider`] for languages whose lowering is not
/// implemented yet.
///
/// Every capability is reported as explicitly [`SemanticOutcome::Unsupported`]
/// rather than left absent, so callers can distinguish "this language cannot do
/// it" from "nothing was materialized". Zero-sized, so a language delegate can
/// hand out `&UNSUPPORTED_PROGRAM_SEMANTICS` without owning a value.
pub struct UnsupportedProgramSemantics;

/// The shared [`UnsupportedProgramSemantics`] instance.
pub static UNSUPPORTED_PROGRAM_SEMANTICS: UnsupportedProgramSemantics = UnsupportedProgramSemantics;

impl ProgramSemanticsProvider for UnsupportedProgramSemantics {
    fn current_artifact_source(
        &self,
        _file: &ProjectFile,
        _max_source_bytes: usize,
    ) -> Result<Option<SemanticArtifactSourceSnapshot>, SemanticProviderError> {
        Ok(None)
    }

    fn materialize(
        &self,
        _file: &ProjectFile,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
        Ok(SemanticOutcome::Unsupported {
            capability: SemanticCapability::Procedures,
            partial: None,
            work: SemanticWork::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::analyzer::semantic::provider::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#7421: a revived cached consumer kept an artifact after its census was refunded")]
    fn reconciliation_uses_one_observation_for_refund_and_retention() {
        let census = SemanticWork {
            program_points: 7,
            ..SemanticWork::default()
        };
        let mut entries = HashMap::from([(0, ((), census))]);
        let mut used = census;
        let mut observations = 0;
        refund_expired_residents(&mut entries, &mut used, |_| {
            observations += 1;
            // The first observation sees only cache pins. A concurrent policy
            // takes the artifact before a second observation would run.
            observations > 1
        });
        assert_eq!(observations, 1);
        assert!(entries.is_empty());
        assert_eq!(used, SemanticWork::default());
        // A later consumer has no retained admission and must pay again.
        entries.insert(0, ((), census));
        used = used.conservative_add(census);
        refund_expired_residents(&mut entries, &mut used, |_| true);
        assert_eq!(entries.len(), 1);
        assert_eq!(used, census);
        refund_expired_residents(&mut entries, &mut used, |_| false);
        assert_eq!(used, SemanticWork::default());
    }

    #[test]
    #[hardwon("#5113: failed refinement derivations left scratch admitted after return")]
    fn temporary_derivation_admissions_close_on_success_and_error() {
        let mut budget = SemanticBudget::uniform(100).expect("positive grant");
        let held = SemanticWork {
            nested_entries: 5,
            ..SemanticWork::default()
        };
        budget.admit(held).expect("outer held rows");
        for fail in [false, true] {
            let result = budget.with_temporary_admissions(|budget| {
                budget.admit(SemanticWork {
                    nested_entries: 20,
                    ..SemanticWork::default()
                })?;
                budget.charge_work(SemanticWork {
                    events: 10,
                    ..SemanticWork::default()
                });
                if fail {
                    budget.admit(SemanticWork {
                        nested_entries: 100,
                        ..SemanticWork::default()
                    })?;
                }
                Ok::<_, SemanticBudgetExceeded>(7)
            });
            assert_eq!(result.is_err(), fail);
            assert_eq!(budget.resident(), held);
        }
        assert_eq!(budget.resident_peak().nested_entries, 25);
        assert_eq!(budget.used().nested_entries, 45);
        assert_eq!(budget.root_work_peak().events, 20);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5113: mixed cached charges filled resident lanes and lost independent root allowances"
    )]
    fn budget_replay_keeps_independent_roots_and_never_refuses_work() {
        let events = |events| SemanticWork {
            events,
            ..SemanticWork::default()
        };
        let mut cold = SemanticBudget::uniform(10).unwrap();
        let before = cold.replay_snapshot();
        let mut first = SemanticBudget::new_root_child(&cold);
        first.admit(events(6)).unwrap();
        first.charge_work(events(7));
        assert_eq!(first.resident().events, 6);
        first.release_resident();
        cold.absorb_root_work(first);
        let mut second = SemanticBudget::new_root_child(&cold);
        second.charge_work(events(8));
        cold.absorb_root_work(second);
        let replay = cold.replay_since(&before);
        assert_eq!(replay.cumulative.events, 21);
        assert_eq!(replay.root_work_peak.events, 8);
        assert_eq!(replay.retained.events, 0);
        let mut warm = SemanticBudget::uniform(10).unwrap();
        warm.replay_product(replay).unwrap();
        assert_eq!(warm.used(), cold.used());
        assert_eq!(warm.root_work_peak(), cold.root_work_peak());
        assert_eq!(warm.resident().events, 0);
        let mut narrow = SemanticBudget::uniform(7).unwrap();
        narrow.replay_product(replay).unwrap();
        assert_eq!(narrow.used(), cold.used());
        assert_eq!(narrow.root_work_peak().events, 8);
        assert_eq!(narrow.resident(), SemanticWork::default());
        let mut interrupted = SemanticBudget::uniform(10).unwrap();
        let mut staged = interrupted.clone();
        staged.admit(events(6)).unwrap();
        staged.charge_work(events(7));
        interrupted.retain_performed_work(&staged);
        assert_eq!(interrupted.resident().events, 0);
        assert_eq!(interrupted.used().events, 13);
        assert_eq!(interrupted.root_work_peak().events, 7);
        interrupted.charge_work(events(4));
        assert_eq!(interrupted.root_work_peak().events, 11);
        assert!(interrupted.first_refusal().is_none());
        let mut query = SemanticBudget::uniform(10).unwrap();
        let before = query.replay_snapshot();
        for amount in [7, 8] {
            let mut child = SemanticBudget::new_child(query.remaining(), &query.scope_snapshot());
            child.charge_work(events(amount));
            query
                .apply_child_charge(SemanticWork::default(), child.into_child_charge())
                .unwrap();
        }
        let replay = query.replay_since(&before);
        assert_eq!(replay.cumulative.events, 15);
        assert_eq!(replay.root_work_peak.events, 8);
        let mut warm = SemanticBudget::uniform(10).unwrap();
        warm.replay_product(replay).unwrap();
        assert_eq!(query.used(), warm.used());
        assert_eq!(query.root_work_peak(), warm.root_work_peak());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5113: prepared source scans accumulated as resident debt after session release"
    )]
    fn source_admissions_transfer_only_with_their_actual_holder() {
        let mut parent = SemanticBudget::uniform(10).unwrap();
        let parent_source = Arc::new(());
        parent.admit_source(&parent_source, 8).unwrap();
        let mut root = SemanticBudget::new_root_child(&parent);
        root.admit_source(&parent_source, 8).unwrap();
        assert_eq!(root.resident().source_bytes, 8);
        assert_eq!(
            root.used().source_bytes,
            0,
            "the root took over a live admission"
        );
        drop(root);
        let scope = parent.scope_snapshot();
        let mut independent_work = SemanticBudget::new_child(parent.remaining(), &scope);
        independent_work.charge_work(SemanticWork {
            source_bytes: 9,
            ..Default::default()
        });
        assert_eq!(independent_work.root_work_peak().source_bytes, 9);
        let mut probe = SemanticBudget::new_child(parent.remaining(), &scope);
        assert!(
            probe.admit_source(&parent_source, 8).is_err(),
            "a continuation has no unowned source credit"
        );
        let mut child = SemanticBudget::new_child(parent.remaining(), &scope);
        let child_source = Arc::new(());
        child.admit_source(&child_source, 2).unwrap();
        child.charge_work(SemanticWork {
            source_bytes: 1,
            ..Default::default()
        });
        let charge = child.into_child_charge();
        parent
            .apply_child_charge(SemanticWork::default(), charge)
            .unwrap();
        assert_eq!(parent.resident().source_bytes, 10);
        drop(child_source);
        assert_eq!(parent.resident().source_bytes, 8);
        drop(parent_source);
        assert_eq!(parent.resident().source_bytes, 0);
        assert_eq!(
            parent.used().source_bytes,
            11,
            "holder release never refunds performed counters"
        );
        assert_eq!(parent.root_work_peak().source_bytes, 1);
        let old_source = Arc::new(());
        parent.admit_source(&old_source, 8).unwrap();
        let before = parent.replay_snapshot();
        drop(old_source);
        let replacement = Arc::new(());
        parent.admit_source(&replacement, 2).unwrap();
        assert_eq!(
            parent.replay_since(&before).retained.source_bytes,
            2,
            "a new holder is retained even when a larger old holder expired"
        );
        let cached_source = Arc::new(());
        let mut root = SemanticBudget::new_root_child(&parent);
        root.admit_source(&cached_source, 8).unwrap();
        parent.absorb_root_work(root);
        assert_eq!(parent.resident().source_bytes, 10);
        drop(cached_source);
        assert_eq!(parent.resident().source_bytes, 2);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5113: expired admission identities refunded live census twice during child handoff"
    )]
    fn expired_holders_do_not_erase_live_admissions_during_handoff() {
        let mut parent = SemanticBudget::uniform(10).unwrap();
        let expired = Arc::new(());
        let live = Arc::new(());
        parent.admit_source(&expired, 8).unwrap();
        parent.admit_source(&live, 2).unwrap();
        drop(expired);
        assert_eq!(parent.resident().source_bytes, 2);

        let mut root = SemanticBudget::new_root_child(&parent);
        assert_eq!(root.resident().source_bytes, 2);
        assert!(root.admit_source(&Arc::new(()), 9).is_err());
        drop(root);

        let mut child = SemanticBudget::new_child(parent.remaining(), &parent.scope_snapshot());
        let temporary = Arc::new(());
        child.admit_source(&live, 2).unwrap();
        child.admit_source(&temporary, 3).unwrap();
        drop(temporary);
        parent
            .apply_child_charge(SemanticWork::default(), child.into_child_charge())
            .unwrap();
        assert_eq!(parent.resident().source_bytes, 2);
        assert_eq!(parent.used().source_bytes, 15);

        // An independently bounded prepass can finish before its cached holder
        // is evicted. The handoff admits only what is still live at import.
        let mut parent = SemanticBudget::uniform(4).unwrap();
        let live = Arc::new(());
        parent.admit_source(&live, 2).unwrap();
        let mut prepass = SemanticBudget::new_child(parent.limits(), &parent.scope_snapshot());
        let temporary = Arc::new(());
        prepass.admit_source(&temporary, 3).unwrap();
        let charge = prepass.into_child_charge();
        drop(temporary);
        parent
            .check_child_charge(SemanticWork::default(), &charge)
            .expect("an evicted holder needs no admission");
        parent
            .apply_child_charge(SemanticWork::default(), charge)
            .unwrap();
        assert_eq!(parent.resident().source_bytes, 2);
        assert_eq!(parent.used().source_bytes, 5);
    }

    fn mock_file() -> ProjectFile {
        ProjectFile::new(std::env::temp_dir(), "src/mock.ts")
    }

    #[test]
    fn scope_identity_does_not_retain_the_charged_artifact_snapshot() {
        let mut budget = SemanticBudget::default();
        budget.record_charged_artifact(StableDigest::sha256(b"charged artifact"));
        let artifact_snapshot_owners = Arc::strong_count(&budget.charged_artifacts);
        let scope_owners = Arc::strong_count(&budget.scope);

        let identity = budget.scope_identity();

        assert_eq!(
            Arc::strong_count(&budget.charged_artifacts),
            artifact_snapshot_owners,
            "a logical-scope token must not pin copy-on-write artifact state"
        );
        assert_eq!(Arc::strong_count(&budget.scope), scope_owners + 1);
        drop(identity);
        assert_eq!(Arc::strong_count(&budget.scope), scope_owners);
    }

    #[test]
    fn complete_artifact_hit_replays_full_and_repeat_work_across_imported_paid_sets() {
        let already_paid = StableDigest::sha256(b"already paid");
        let sibling_paid = StableDigest::sha256(b"sibling paid");
        let newly_paid = StableDigest::sha256(b"newly paid");
        let full_work = SemanticWork {
            procedures: 2,
            blocks: 3,
            events: 5,
            ..SemanticWork::default()
        };

        let mut parent = SemanticBudget::uniform(32).expect("parent budget");
        parent.record_charged_artifact(already_paid);
        parent.record_charged_artifact(sibling_paid);
        let parent_scope = parent.scope_snapshot();
        let mut child = SemanticBudget::new_child(SemanticWork::uniform(32), &parent_scope);

        child
            .charge_complete_artifact_hit(newly_paid, full_work)
            .expect("an uncharged artifact pays its full census");
        child
            .charge_complete_artifact_hit(already_paid, full_work)
            .expect("an imported paid artifact pays one lookup");
        child
            .charge_complete_artifact_hit(sibling_paid, full_work)
            .expect("every imported paid identity uses the repeat price");

        assert_eq!(
            child.used(),
            SemanticWork {
                procedures: 2,
                blocks: 3,
                events: 5,
                nested_entries: 2,
                ..SemanticWork::default()
            }
        );
        assert!(child.has_charged_artifact(newly_paid));

        parent
            .apply_child_charge(SemanticWork::default(), child.into_child_charge())
            .expect("the child charge fits and imports its new paid identity");
        assert!(parent.has_charged_artifact(already_paid));
        assert!(parent.has_charged_artifact(sibling_paid));
        assert!(parent.has_charged_artifact(newly_paid));
        assert_eq!(parent.used().nested_entries, 2);

        let before = parent.clone();
        let oversized = SemanticWork {
            procedures: 33,
            ..SemanticWork::default()
        };
        assert!(
            parent
                .charge_complete_artifact_hit(StableDigest::sha256(b"over limit"), oversized)
                .is_err()
        );
        assert_eq!(parent.used(), before.used());
        assert_eq!(
            parent.charged_artifact_count(),
            before.charged_artifact_count(),
            "a refused full charge must not import the artifact identity"
        );
    }

    #[test]
    fn child_charge_import_is_scope_bound_conservative_and_atomic() {
        let mut parent = SemanticBudget::uniform(4).expect("parent budget");
        let parent_scope = parent.scope_snapshot();
        let artifact = StableDigest::sha256(b"child artifact");
        let child_charge = || {
            let mut child = SemanticBudget::new_child(SemanticWork::uniform(4), &parent_scope);
            child
                .admit(SemanticWork {
                    procedures: 2,
                    ..SemanticWork::default()
                })
                .expect("child work fits");
            child.record_charged_artifact(artifact);
            child.into_child_charge()
        };
        let checked_charge = child_charge();

        let before = parent.used();
        assert!(
            parent
                .check_child_charge(
                    SemanticWork {
                        procedures: 5,
                        ..SemanticWork::default()
                    },
                    &checked_charge,
                )
                .is_err()
        );
        assert_eq!(parent.used(), before);
        assert!(!parent.has_charged_artifact(artifact));
        assert!(
            parent
                .apply_child_charge(
                    SemanticWork {
                        procedures: 5,
                        ..SemanticWork::default()
                    },
                    checked_charge,
                )
                .is_err()
        );
        assert_eq!(parent.used(), before);
        assert!(!parent.has_charged_artifact(artifact));

        parent
            .apply_child_charge(SemanticWork::default(), child_charge())
            .expect("the exact child work fits");
        assert_eq!(parent.used().procedures, 2);
        assert!(parent.has_charged_artifact(artifact));

        let parent_scope = parent.scope_snapshot();
        let continuation = SemanticBudget::new_child(SemanticWork::uniform(4), &parent_scope);
        assert!(continuation.has_charged_artifact(artifact));
        assert_eq!(continuation.used(), SemanticWork::default());
    }

    #[test]
    #[should_panic(expected = "semantic child charge belongs to a different logical scope")]
    fn child_charge_import_rejects_an_unrelated_budget_scope() {
        let mut parent = SemanticBudget::uniform(1).expect("parent budget");
        let unrelated = SemanticBudget::uniform(1).expect("unrelated budget");
        let unrelated_scope = unrelated.scope_snapshot();
        let child = SemanticBudget::new_child(SemanticWork::uniform(1), &unrelated_scope);
        let _ = parent.apply_child_charge(SemanticWork::default(), child.into_child_charge());
    }

    #[test]
    fn execution_fork_preserves_overlap_and_replays_exact_child_work() {
        let first = mock_file();
        let second = ProjectFile::new(std::env::temp_dir(), "src/second.ts");
        let third = ProjectFile::new(std::env::temp_dir(), "src/third.ts");
        let execution = SemanticExecutionBudget::new(2);

        assert!(execution.admit_materialization(&first));
        assert!(execution.charge_traversal(1));
        let (before, child) = execution.fork_with_materialized_file_limit(1);
        assert!(before.contains_materialized_file(&first));
        assert!(!before.contains_materialized_file(&second));

        assert!(child.admit_materialization(&first));
        assert!(child.admit_materialization(&second));
        assert!(!child.admit_materialization(&third));
        assert!(child.charge_traversal(1));
        let charge = child
            .charge_since(&before)
            .expect("forked child extends its exact parent state");

        let work_before_preflight = execution.work();
        assert!(execution.can_replay_charge(&before, &charge));
        assert_eq!(
            execution.work(),
            work_before_preflight,
            "execution replay preflight is non-mutating"
        );
        assert!(execution.replay_charge(&before, &charge));
        assert_eq!(execution.work().materialized_files, 2);
        assert_eq!(execution.work().traversal_steps, 2);
        assert!(execution.work().exhausted);
        assert!(!execution.can_replay_charge(&before, &charge));
        assert!(!execution.replay_charge(&before, &charge));
    }

    #[test]
    fn execution_fork_with_zero_new_files_allows_only_known_file_revisits() {
        let known = mock_file();
        let new = ProjectFile::new(std::env::temp_dir(), "src/new.ts");
        let execution = SemanticExecutionBudget::new(2);
        assert!(execution.admit_materialization(&known));

        let (before, child) = execution.fork_with_materialized_file_limit(0);
        assert!(child.admit_materialization(&known));
        assert!(!child.admit_materialization(&new));
        let charge = child
            .charge_since(&before)
            .expect("forked child extends its exact parent state");

        assert!(execution.replay_charge(&before, &charge));
        assert_eq!(execution.work().materialized_files, 1);
        assert!(execution.work().exhausted);
    }

    #[test]
    fn execution_charge_retained_bytes_accounts_for_owned_file_paths() {
        let short_file = mock_file();
        let long_rel = format!("src/{}/subject.ts", "nested".repeat(128));
        let long_file = ProjectFile::new(std::env::temp_dir(), &long_rel);
        let charge_for = |file| SemanticExecutionBudgetCharge {
            materialized_files: vec![file].into_boxed_slice(),
            externally_materialized_files: 0,
            traversal_steps: 0,
            exhausted: false,
        };

        let short = charge_for(short_file).retained_bytes();
        let long = charge_for(long_file).retained_bytes();
        assert!(
            long >= short.saturating_add(long_rel.len() / 2),
            "cached execution charges must account for owned path storage"
        );
    }

    #[test]
    fn execution_budget_unifies_external_and_nested_provider_work() {
        let first = mock_file();
        let second = ProjectFile::new(std::env::temp_dir(), "src/second.ts");
        let third = ProjectFile::new(std::env::temp_dir(), "src/third.ts");
        let execution = SemanticExecutionBudget::new(3);
        assert!(execution.charge_external_query_work(1, 1));
        assert!(execution.admit_materialization(&first));
        assert!(execution.admit_materialization(&second));

        let mut budget = SemanticBudget::uniform(10).unwrap();
        let mut staged_budget = budget.clone();
        let cancellation = CancellationToken::default();
        let request =
            SemanticRequest::with_execution_budget(&mut budget, &cancellation, &execution);
        let staged = request.staged(&mut staged_budget);
        assert!(staged.charge_execution_traversal(2));
        assert!(!staged.admit_materialization(&third));

        assert_eq!(
            execution.work(),
            SemanticExecutionWork {
                materialized_files: 3,
                traversal_steps: 3,
                exhausted: true,
            }
        );
    }

    #[test]
    fn shared_summary_limit_caps_the_combined_summary_dimensions() {
        let mut parent = SemanticBudget::uniform(64)
            .unwrap()
            .with_shared_summary_expansion_limit(64);
        parent
            .admit(SemanticWork {
                call_sites: 19,
                ..SemanticWork::default()
            })
            .unwrap();
        let mut child =
            SemanticBudget::new_child(SemanticWork::uniform(64), &parent.scope_snapshot());
        child
            .admit(SemanticWork {
                memory_locations: 45,
                ..SemanticWork::default()
            })
            .unwrap();
        assert!(
            child
                .admit(SemanticWork {
                    captures: 1,
                    ..SemanticWork::default()
                })
                .is_err()
        );
        let child_charge = child.into_child_charge();
        parent
            .apply_child_charge(child_charge.work, child_charge)
            .unwrap();

        let used = parent.used();
        assert_eq!(summary_expansion_count(used), 64);
        let refusal = parent
            .admit(SemanticWork {
                captures: 1,
                ..SemanticWork::default()
            })
            .unwrap_err();
        assert_eq!(refusal.dimension(), SemanticBudgetDimension::Captures);
        assert_eq!(refusal.limit(), 64);
        assert_eq!(refusal.attempted(), 65);
        assert_eq!(parent.used(), used, "refused group charges are atomic");
    }

    #[test]
    fn public_budget_lanes_have_stable_labels_and_cover_every_dimension() {
        assert_eq!(
            SemanticBudgetLane::LABELS,
            &["source", "rows", "retained_bytes", "files"]
        );
        assert_eq!(SemanticBudgetLane::Source.label(), "source");
        assert_eq!(SemanticBudgetLane::Rows.label(), "rows");
        assert_eq!(SemanticBudgetLane::RetainedBytes.label(), "retained_bytes");
        assert_eq!(SemanticBudgetLane::Files.label(), "files");

        let expected = [
            (
                SemanticBudgetDimension::SourceBytes,
                SemanticBudgetLane::Source,
            ),
            (
                SemanticBudgetDimension::Procedures,
                SemanticBudgetLane::Rows,
            ),
            (SemanticBudgetDimension::Blocks, SemanticBudgetLane::Rows),
            (
                SemanticBudgetDimension::ProgramPoints,
                SemanticBudgetLane::Rows,
            ),
            (SemanticBudgetDimension::Values, SemanticBudgetLane::Rows),
            (
                SemanticBudgetDimension::Allocations,
                SemanticBudgetLane::Rows,
            ),
            (SemanticBudgetDimension::CallSites, SemanticBudgetLane::Rows),
            (
                SemanticBudgetDimension::MemoryLocations,
                SemanticBudgetLane::Rows,
            ),
            (SemanticBudgetDimension::Captures, SemanticBudgetLane::Rows),
            (
                SemanticBudgetDimension::SourceMappings,
                SemanticBudgetLane::Rows,
            ),
            (SemanticBudgetDimension::Evidence, SemanticBudgetLane::Rows),
            (SemanticBudgetDimension::Gaps, SemanticBudgetLane::Rows),
            (SemanticBudgetDimension::Events, SemanticBudgetLane::Rows),
            (
                SemanticBudgetDimension::ControlEdges,
                SemanticBudgetLane::Rows,
            ),
            (
                SemanticBudgetDimension::NestedEntries,
                SemanticBudgetLane::Rows,
            ),
            (
                SemanticBudgetDimension::OwnedTextBytes,
                SemanticBudgetLane::RetainedBytes,
            ),
        ];
        for (dimension, lane) in expected {
            assert_eq!(dimension.public_lane(), lane, "{}", dimension.label());
        }
    }

    #[test]
    fn budget_error_display_uses_public_lane_labels() {
        let mut limits = SemanticWork::default_limits();
        limits.owned_text_bytes = 0;
        let invalid = SemanticBudget::new(limits).unwrap_err();
        assert_eq!(
            invalid.to_string(),
            "semantic budget limit `retained_bytes` must be positive"
        );

        let mut budget = SemanticBudget::uniform(1).unwrap();
        let exceeded = budget
            .admit(SemanticWork {
                program_points: 2,
                ..SemanticWork::default()
            })
            .unwrap_err();
        assert_eq!(
            exceeded.to_string(),
            "semantic resident `rows` (`program_points`) attempted 2 against limit 1"
        );
        let refusal = budget
            .first_refusal()
            .expect("the refused charge is recorded");
        assert_eq!(refusal.exceeded, exceeded);
        assert_eq!(refusal.site.file(), file!());
    }

    #[test]
    fn total_payload_dimensions_are_charged_atomically() {
        let mut budget = SemanticBudget::uniform(10).unwrap();
        budget
            .admit(SemanticWork {
                events: 7,
                control_edges: 8,
                nested_entries: 9,
                owned_text_bytes: 10,
                ..SemanticWork::default()
            })
            .unwrap();

        let remaining = budget.remaining();
        assert_eq!(remaining.events, 3);
        assert_eq!(remaining.control_edges, 2);
        assert_eq!(remaining.nested_entries, 1);
        assert_eq!(remaining.owned_text_bytes, 0);

        let before = budget.used();
        let error = budget
            .admit(SemanticWork {
                owned_text_bytes: 1,
                ..SemanticWork::default()
            })
            .unwrap_err();
        assert_eq!(error.dimension(), SemanticBudgetDimension::OwnedTextBytes);
        assert_eq!(budget.used(), before);
    }

    #[test]
    fn failed_budget_charge_is_atomic_and_identifies_the_limit() {
        let mut budget = SemanticBudget::uniform(2).unwrap();
        budget
            .admit(SemanticWork {
                procedures: 2,
                ..SemanticWork::default()
            })
            .unwrap();
        let before = budget.used();
        let error = budget
            .admit(SemanticWork {
                procedures: 1,
                ..SemanticWork::default()
            })
            .unwrap_err();
        assert_eq!(error.dimension(), SemanticBudgetDimension::Procedures);
        assert_eq!(error.limit(), 2);
        assert_eq!(error.attempted(), 3);
        assert_eq!(budget.used(), before);
    }

    #[test]
    fn overflowing_budget_charge_is_rejected_even_at_the_maximum_limit() {
        let mut telemetry = SemanticBudget::uniform(1).unwrap();
        for _ in 0..2 {
            telemetry.charge_work(SemanticWork {
                procedures: usize::MAX,
                ..SemanticWork::default()
            });
        }
        assert_eq!(telemetry.used().procedures, usize::MAX);
        assert_eq!(telemetry.root_work_peak().procedures, usize::MAX);
        assert_eq!(telemetry.used().events, 0);
        assert!(telemetry.first_refusal().is_none());
        telemetry
            .admit(SemanticWork {
                events: 1,
                ..SemanticWork::default()
            })
            .unwrap();

        let mut budget = SemanticBudget::uniform(usize::MAX).unwrap();
        budget
            .admit(SemanticWork {
                procedures: usize::MAX,
                ..SemanticWork::default()
            })
            .unwrap();
        let before = budget.used();

        let error = budget
            .admit(SemanticWork {
                procedures: 1,
                ..SemanticWork::default()
            })
            .expect_err("overflow must be a budget error, not a panic");

        assert_eq!(error.dimension(), SemanticBudgetDimension::Procedures);
        assert_eq!(error.limit(), usize::MAX);
        assert_eq!(error.attempted(), usize::MAX);
        assert_eq!(budget.used(), before);
    }

    #[test]
    fn outcome_mapping_preserves_variant_partial_data_and_work() {
        let work = SemanticWork {
            program_points: 3,
            ..SemanticWork::default()
        };
        let outcomes = [
            SemanticOutcome::Complete { value: 1, work },
            SemanticOutcome::Ambiguous {
                candidates: 2,
                work,
            },
            SemanticOutcome::Unknown {
                partial: Some(3),
                work,
            },
            SemanticOutcome::Unsupported {
                capability: SemanticCapability::ExceptionalControlFlow,
                partial: Some(4),
                work,
            },
            SemanticOutcome::Unproven { partial: 5, work },
            SemanticOutcome::ExceededBudget {
                partial: Some(6),
                exceeded: SemanticBudgetExceeded {
                    dimension: SemanticBudgetDimension::ProgramPoints,
                    limit: 2,
                    attempted: 3,
                },
                work,
            },
            SemanticOutcome::Cancelled {
                partial: Some(7),
                work,
            },
        ];

        let mapped = outcomes.map(|outcome| outcome.map(|value| value.to_string()));
        for (index, outcome) in mapped.iter().enumerate() {
            let expected = (index + 1).to_string();
            assert_eq!(outcome.work(), work);
            assert_eq!(
                outcome.available_value().map(String::as_str),
                Some(expected.as_str())
            );
        }
        assert!(mapped[0].is_complete());
        assert!(!mapped[1].is_complete());
    }

    #[test]
    fn completed_replay_keeps_finished_payloads_and_rejects_request_interruptions() {
        let work = SemanticWork {
            program_points: 3,
            ..SemanticWork::default()
        };
        let complete = SemanticOutcome::Complete { value: 1_u32, work }
            .completed_replay()
            .expect("a completed payload is replayable");
        let partial = SemanticOutcome::Unknown {
            partial: Some(2_u32),
            work,
        }
        .completed_replay()
        .expect("a finished partial payload is replayable");
        assert_eq!(complete.available_value(), Some(&1));
        assert_eq!(partial.available_value(), Some(&2));
        assert_eq!(complete.work(), SemanticWork::default());
        assert_eq!(partial.work(), SemanticWork::default());

        assert!(
            SemanticOutcome::<u32>::Unknown {
                partial: None,
                work,
            }
            .completed_replay()
            .is_none()
        );
        assert!(
            SemanticOutcome::ExceededBudget {
                partial: Some(3_u32),
                exceeded: SemanticBudgetExceeded {
                    dimension: SemanticBudgetDimension::ProgramPoints,
                    limit: 2,
                    attempted: 3,
                },
                work,
            }
            .completed_replay()
            .is_none()
        );
        assert!(
            SemanticOutcome::Cancelled {
                partial: Some(4_u32),
                work,
            }
            .completed_replay()
            .is_none()
        );
    }

    #[test]
    fn exceeded_budget_mapping_preserves_full_measurement() {
        let exceeded = SemanticBudgetExceeded {
            dimension: SemanticBudgetDimension::NestedEntries,
            limit: 8,
            attempted: 13,
        };
        let work = SemanticWork {
            nested_entries: 8,
            ..SemanticWork::default()
        };
        let mapped = SemanticOutcome::ExceededBudget {
            partial: Some(21_u32),
            exceeded,
            work,
        }
        .map(|value| value.to_string());

        assert_eq!(mapped.budget_exceeded(), Some(exceeded));
        assert_eq!(mapped.work(), work);
        assert_eq!(mapped.available_value().map(String::as_str), Some("21"));
    }

    #[test]
    fn execution_budget_snapshot_replays_exact_file_and_traversal_work() {
        let first = mock_file();
        let second = ProjectFile::new(first.root(), "src/second.rs");
        let source = SemanticExecutionBudget::new(4);
        assert!(source.admit_materialization(&first));
        assert!(source.charge_external_work(1, 2));
        let before = source.snapshot();
        assert!(source.admit_materialization(&second));
        assert!(source.charge_external_work(1, 3));
        let after = source.snapshot();
        let charge = source.charge_since(&before).expect("monotonic charge");

        let replay = SemanticExecutionBudget::new(4);
        assert!(replay.admit_materialization(&first));
        assert!(replay.charge_external_work(1, 2));
        assert_eq!(replay.snapshot(), before);
        assert!(replay.replay_charge(&before, &charge));
        assert_eq!(replay.snapshot(), after);

        let already_replayed = replay.snapshot();
        assert!(!replay.replay_charge(&before, &charge));
        assert_eq!(replay.snapshot(), already_replayed);
    }
}

/// Portable accounting for a cached product. Each object remains SQL-readable
/// when persisted in a policy unit's JSONB product.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticBudgetReplay {
    /// Admitted plus worked per lane; held-and-scanned bytes can count twice.
    /// This cumulative telemetry is not a bound.
    pub cumulative: SemanticWork,
    /// Performed work only, without the resident holds that merely re-enter a
    /// later region's ledger. This is the read/hash/parse lane.
    #[serde(default)]
    pub performed: SemanticWork,
    pub root_work_peak: SemanticWork,
    pub retained: SemanticWork,
}

/// Query-local measurement interval. Dropping it retires its observer even
/// when a computation returns early; staging copies preserve value semantics.
#[derive(Debug)]
pub struct SemanticBudgetReplaySnapshot {
    owner: Arc<()>,
    cumulative: SemanticWork,
    performed: SemanticWork,
    artifacts: Arc<ResidentArtifacts>,
    owners: Arc<ResidentOwners>,
    raw_resident: SemanticWork,
}

#[derive(Debug, Clone)]
struct ReplayObserver {
    owner: Weak<()>,
    base: SemanticWork,
    peak: SemanticWork,
}

type ResidentOwner = dyn std::any::Any + Send + Sync;

type ResidentOwners = HashMap<usize, (Weak<ResidentOwner>, SemanticWork)>;

fn weak_resident_owner<T: Send + Sync + 'static>(owner: &Arc<T>) -> Weak<ResidentOwner> {
    let erased: Arc<ResidentOwner> = Arc::clone(owner) as Arc<ResidentOwner>;
    Arc::downgrade(&erased)
}

#[derive(Debug, Clone)]
struct ResidentArtifact {
    allocation: Weak<SemanticArtifact>,
    cache_pins: Arc<crate::analyzer::semantic::ir::ArtifactCachePins>,
}

impl ResidentArtifact {
    fn new(artifact: &Arc<SemanticArtifact>) -> Self {
        Self {
            allocation: Arc::downgrade(artifact),
            cache_pins: Arc::clone(&artifact.cache_pins),
        }
    }

    fn upgrade(&self) -> Option<Arc<SemanticArtifact>> {
        self.allocation.upgrade()
    }

    fn has_consumer(&self) -> bool {
        let pins = self.cache_pins.lock();
        self.allocation
            .upgrade()
            .is_some_and(|artifact| Arc::strong_count(&artifact) > *pins + 1)
    }

    fn consumer(&self) -> Option<Arc<SemanticArtifact>> {
        let pins = self.cache_pins.lock();
        let artifact = self.allocation.upgrade()?;
        if Arc::strong_count(&artifact) > *pins + 1 {
            Some(artifact)
        } else {
            // Drop the observation under the mutex, so another observer
            // cannot count it as a root pin after this lock is released.
            drop(artifact);
            None
        }
    }
}

/// Refund and remove using one liveness observation per admission.
fn refund_expired_residents<Key: Eq + std::hash::Hash, Owner>(
    entries: &mut HashMap<Key, (Owner, SemanticWork)>,
    used: &mut SemanticWork,
    mut is_live: impl FnMut(&Owner) -> bool,
) {
    entries.retain(|_, (owner, work)| {
        if is_live(owner) {
            true
        } else {
            *used = used.saturating_sub(*work);
            false
        }
    });
}

type ResidentArtifacts = HashMap<(StableDigest, usize), (ResidentArtifact, SemanticWork)>;

/// Artifact-free procedure identity and the source regions it does not own.
#[derive(Debug, Clone)]
pub struct SemanticProcedureInventoryEntry {
    pub locator: crate::analyzer::semantic::SemanticLocator,
    pub kind: crate::analyzer::semantic::ProcedureKind,
    pub source_range_holes: Vec<crate::analyzer::semantic::SourceSpan>,
}

/// The identity-only result of a language's procedure inventory.
pub type SemanticProcedureInventory = SemanticOutcome<Vec<SemanticProcedureInventoryEntry>>;

/// The exact physical language namespace used by the analyzer store. This is
/// intentionally distinct from semantic `Language`: adapters may publish more
/// than one physical projection for the same semantic language (for example
/// TypeScript/TSX and C/C++).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StorageLanguageKey(String);

impl StorageLanguageKey {
    /// Retain the exact key returned by a language adapter.
    pub fn from_adapter(key: &'static str) -> Self {
        Self(key.to_owned())
    }

    #[doc(hidden)]
    pub fn from_store(key: String) -> Self {
        Self(key)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

use std::collections::HashMap;

use std::sync::Weak;

use crate::analyzer::semantic::leases::SemanticArtifactLeaseChild;
