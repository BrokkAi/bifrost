//! Provider outcomes, finite budgets, and the language-neutral adapter boundary.

use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};

use brokk_bifrost_core::analyzer::model::ProjectFile;

use crate::analyzer::semantic::read_ledger::StoredSemanticIrPublicationAnswer;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::gitblob::ParseVariant;
use git2::Oid;

/// The authority and exact store key used by one publication observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSemanticIrSelection {
    pub rel_path: Box<str>,
    pub oid: Oid,
    pub storage_language: Box<str>,
    pub variant: ParseVariant,
}

/// A refusal cannot be represented as an absent publication.
#[derive(Debug)]
pub enum StoredSemanticIrRead {
    Refused,
    Observed(Box<StoredSemanticIrObservation>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredSemanticIrPublicationHead {
    NoHead,
    StaleEpoch,
    Present {
        active_epoch: Box<str>,
        row_digest: [u8; 32],
        content: [u8; 32],
        source_bytes: usize,
    },
}

pub fn classify(
    observation: &StoredSemanticIrObservation,
    subject: [u8; 32],
) -> StoredSemanticIrPublicationAnswer {
    match &observation.head {
        StoredSemanticIrPublicationHead::NoHead => StoredSemanticIrPublicationAnswer::NoHead,
        StoredSemanticIrPublicationHead::StaleEpoch => {
            StoredSemanticIrPublicationAnswer::StaleEpoch
        }
        StoredSemanticIrPublicationHead::Present {
            active_epoch,
            row_digest,
            content,
            ..
        } if *content == subject => StoredSemanticIrPublicationAnswer::Present {
            active_epoch: active_epoch.clone(),
            row_digest: *row_digest,
        },
        StoredSemanticIrPublicationHead::Present { .. } => {
            StoredSemanticIrPublicationAnswer::ContentMismatch
        }
    }
}

#[derive(Debug)]
pub struct StoredSemanticIrObservation {
    pub selection: StoredSemanticIrSelection,
    pub head: StoredSemanticIrPublicationHead,
    pub source_content: Option<[u8; 32]>,
    pub rows: Option<Vec<crate::analyzer::semantic::ProcedureSemanticsParts>>,
}

use crate::analyzer::semantic::capabilities::SemanticCapabilities;

use crate::analyzer::semantic::capabilities::SemanticCapability;

use crate::analyzer::semantic::ids::ProcedureId;

use crate::analyzer::semantic::ids::SemanticArtifactKey;

use crate::analyzer::semantic::ids::StableDigest;

use crate::analyzer::semantic::ir::ProcedureHandle;
use crate::analyzer::semantic::ir::SemanticArtifact;

use crate::analyzer::semantic::ir::SemanticIrError;

use crate::analyzer::semantic::leases::SemanticArtifactCollector;

use crate::analyzer::semantic::partial_flow::ProcedurePartialFlows;

use brokk_bifrost_core::analyzer::work_budget::BudgetLedger;

use brokk_bifrost_core::analyzer::work_budget::WorkBudgetExceeded;

use brokk_bifrost_core::analyzer::work_budget::define_work_dimensions;

/// A moment in a semantic budget's refusal count. See
/// [`SemanticBudget::refusal_mark`].
pub type SemanticBudgetRefusalMark = brokk_bifrost_core::analyzer::work_budget::RefusalMark;

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
    window_open: bool,
    window_default_limits: Option<SemanticWork>,
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
    /// What this ledger itself held at its peak, apart from rows it inherited
    /// from a parent (see [`ResidentInterval`]).
    own: ResidentInterval,
    resident_artifacts: Arc<ResidentArtifacts>,
    resident_owners: Arc<ResidentOwners>,
    reacquired: Arc<Vec<MemoDependencyGuard>>,
    inherited_artifacts: Arc<ResidentArtifacts>,
    scope: Arc<SemanticBudgetScope>,
    charged_artifacts: Arc<HashSet<StableDigest>>,
    shared_summary_expansion_limit: Option<usize>,
    /// The first charge this ledger refused. Clones share it, so a refusal
    /// on a staging copy that is then discarded is still recorded; a child
    /// ledger has its own.
    first_refusal: Arc<std::sync::OnceLock<SemanticBudgetRefusal>>,
    refusal_origins: Arc<Mutex<SemanticRefusalOrigins>>,
    unit_resident_lane: bool,
    // Timing-only query history. Lightweight scope identities never retain it.
    lowered: Arc<Mutex<HashSet<StableDigest>>>,
}

/// The admission authority that produced a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SemanticRefusalOrigin {
    UnitResident,
    Other,
}

/// Origins accumulated across staging copies and child roots of one unit.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SemanticRefusalOrigins {
    resident: bool,
    other: bool,
}

impl SemanticRefusalOrigins {
    pub fn resident_only(self) -> bool {
        self.resident && !self.other
    }
}

/// The unowned part of a ledger's resident balance at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScratchMark(SemanticWork);

/// The parts of a semantic ledger's resident balance, by holder kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResidentCensus {
    pub balance: SemanticWork,
    pub unowned: SemanticWork,
    pub live_artifacts: SemanticWork,
    pub live_owners: SemanticWork,
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
    refusal_origins: Arc<Mutex<SemanticRefusalOrigins>>,
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
    reacquired: Arc<Vec<MemoDependencyGuard>>,
    scope: Arc<SemanticBudgetScope>,
    work: SemanticWork,
    performed: SemanticWork,
    resident_peak: SemanticWork,
    /// The most rows the child itself held at once, apart from any it inherited.
    resident_transient_peak: SemanticWork,
    /// Whether the child was granted room beside its parent's holders, so its
    /// peak must fit on top of the parent's balance when the charge is applied.
    resident_coexists: bool,
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
            window_open: false,
            window_default_limits: None,
            cumulative: SemanticWork::default(),
            performed: SemanticWork::default(),
            root_work: SemanticWork::default(),
            root_work_peak: SemanticWork::default(),
            replay_observers: Vec::new(),
            lowering_work: None,
            resident_peak: SemanticWork::default(),
            own: ResidentInterval::independent(),
            resident_artifacts: Arc::default(),
            resident_owners: Arc::default(),
            reacquired: Arc::default(),
            inherited_artifacts: Arc::default(),
            scope: Arc::new(SemanticBudgetScope),
            charged_artifacts: Arc::new(HashSet::new()),
            shared_summary_expansion_limit: None,
            first_refusal: Arc::default(),
            refusal_origins: Arc::default(),
            unit_resident_lane: false,
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

    /// Open a window in which charged artifacts may expand row grants.
    pub fn start_artifact_window(&mut self, _file: &ProjectFile) {
        assert!(!self.window_open);
        self.window_open = true;
        self.window_default_limits = Some(self.ledger.limits());
    }

    /// Artifact rows are grant-neutral while a file window is open.
    fn grant_artifact_rows(&mut self, work: SemanticWork) {
        if !self.window_open {
            return;
        }
        let defaults = self.ledger.limits();
        let limits = SemanticWork {
            procedures: defaults.procedures.saturating_add(work.procedures),
            blocks: defaults.blocks.saturating_add(work.blocks),
            program_points: defaults.program_points.saturating_add(work.program_points),
            values: defaults.values.saturating_add(work.values),
            allocations: defaults.allocations.saturating_add(work.allocations),
            call_sites: defaults.call_sites.saturating_add(work.call_sites),
            memory_locations: defaults
                .memory_locations
                .saturating_add(work.memory_locations),
            captures: defaults.captures.saturating_add(work.captures),
            source_mappings: defaults
                .source_mappings
                .saturating_add(work.source_mappings),
            evidence: defaults.evidence.saturating_add(work.evidence),
            gaps: defaults.gaps.saturating_add(work.gaps),
            events: defaults.events.saturating_add(work.events),
            control_edges: defaults.control_edges.saturating_add(work.control_edges),
            ..defaults
        };
        self.ledger = self.ledger.with_limits(limits);
    }

    pub fn release_artifact_window(&mut self) {
        if let Some(defaults) = self.window_default_limits.take() {
            self.ledger = self.ledger.with_limits(defaults);
        }
        self.window_open = false;
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
        self.retire_expired_reacquisitions();
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

    /// What the resident balance is made of, without changing it. The
    /// balance equals the three parts below: rows no registered holder owns
    /// (scratch that was never closed, or rows of a returned value its caller
    /// keeps), the census of artifacts a consumer still holds, and the census
    /// of live cache or source owners.
    pub fn resident_census(&self) -> ResidentCensus {
        self.retire_expired_reacquisitions();
        let mut live_artifacts = SemanticWork::default();
        for (artifact, work) in self.resident_artifacts.values() {
            if artifact.has_consumer() {
                live_artifacts = live_artifacts.conservative_add(*work);
            }
        }
        let mut live_owners = SemanticWork::default();
        for (owner, work) in self.resident_owners.values() {
            if owner.strong_count() > 0 {
                live_owners = live_owners.conservative_add(*work);
            }
        }
        ResidentCensus {
            balance: self.resident(),
            unowned: self.raw_resident(),
            live_artifacts,
            live_owners,
        }
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
        self.reacquired = Arc::default();
        self.inherited_artifacts = Arc::default();
        // Nothing inherited is left to count on.
        self.own.base = SemanticWork::default();
        for observer in &mut self.replay_observers {
            observer.resident.base = SemanticWork::default();
        }
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
        let mut refunded_artifacts = SemanticWork::default();
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
            refunded_artifacts = refunded_artifacts.saturating_add(*work);
            false
        });
        // Prepared sessions and cached results have their own holders. A
        // pooled source has no active session token after return, so its
        // admission is refunded independently of pool occupancy.
        self.ledger = self.ledger.with_used(used);
        self.refund_artifact_grants(refunded_artifacts);
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
        let mark = self.scratch_mark();
        let result = derive(self);
        self.release_scratch_since(&mark);
        result
    }

    /// Remember the admissions that no registered holder owns, so a stretch of
    /// code that leaves nothing behind but scratch can refund exactly its own.
    /// Use this where the stretch has early exits that a closure cannot span;
    /// otherwise use [`Self::with_temporary_admissions`].
    pub fn scratch_mark(&self) -> ScratchMark {
        ScratchMark(self.raw_resident())
    }

    /// Refund the unowned admissions made since `mark`. Performed work,
    /// cumulative counters, peaks and the census of registered holders stay.
    pub fn release_scratch_since(&mut self, mark: &ScratchMark) {
        let scratch = self.raw_resident().saturating_sub(mark.0);
        self.release_admission(scratch);
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
            self.touch_owner(key);
            return None;
        }
        Some(SemanticWork {
            source_bytes: bytes,
            ..SemanticWork::default()
        })
    }

    /// Attach the exact source acquisition address after the normal admission.
    #[doc(hidden)]
    pub fn record_source_reacquisition<T: Send + Sync + 'static>(
        &mut self,
        owner: &Arc<T>,
        key: MemoSourceDependency,
    ) {
        if let Some((receipt, _)) =
            Arc::make_mut(&mut self.resident_owners).get_mut(&(Arc::as_ptr(owner) as usize))
        {
            receipt.source = Some(key);
        }
    }

    fn record_source_owner<T: Send + Sync + 'static>(
        &mut self,
        owner: &Arc<T>,
        work: SemanticWork,
    ) {
        let key = Arc::as_ptr(owner) as usize;
        Arc::make_mut(&mut self.resident_owners).insert(key, (weak_resident_owner(owner), work));
    }

    fn retire_expired_reacquisitions(&self) {
        for guard in self.reacquired.iter() {
            guard.retain_while_provider_lives();
        }
    }

    fn reconcile_residency(&mut self) {
        // A prepared source stops coexisting with the region when its cold
        // provider drops the sessions. Retire the real allocation before the
        // ordinary weak registry computes its refund.
        Arc::make_mut(&mut self.reacquired).retain(|guard| guard.retain_while_provider_lives());
        // Consumer state can change when another policy takes a cached artifact.
        // Decide retention and refund together: a second observation could keep
        // an artifact whose census the first observation already refunded.
        let mut resident = self.ledger.used();
        let mut expired_owners = Vec::new();
        refund_expired_residents_noting(
            Arc::make_mut(&mut self.resident_owners),
            &mut resident,
            |owner| owner.strong_count() > 0,
            |key, census| expired_owners.push((*key, *census)),
        );
        let mut expired_artifacts = Vec::new();
        let refunded_artifacts = refund_expired_residents_noting(
            Arc::make_mut(&mut self.resident_artifacts),
            &mut resident,
            ResidentArtifact::has_consumer,
            |key, census| expired_artifacts.push((*key, *census)),
        );
        self.ledger = self.ledger.with_used(resident);
        // Rows an interval inherited are no longer there to count on.
        for (key, census) in &expired_owners {
            self.own.owner_expired(key, *census);
            for observer in &mut self.replay_observers {
                observer.resident.owner_expired(key, *census);
            }
        }
        for (key, census) in &expired_artifacts {
            self.own.artifact_expired(key, *census);
            for observer in &mut self.replay_observers {
                observer.resident.artifact_expired(key, *census);
            }
        }
        self.refund_artifact_grants(refunded_artifacts);
    }

    fn refund_artifact_grants(&mut self, work: SemanticWork) {
        if self.window_open {
            let defaults = self
                .window_default_limits
                .expect("open window has defaults");
            let limits = self
                .ledger
                .limits()
                .saturating_sub(work)
                .component_max(defaults);
            self.ledger = self.ledger.with_limits(limits);
        }
    }

    pub fn remaining(&self) -> SemanticWork {
        self.limits().saturating_sub(self.resident())
    }

    /// Check one atomic charge without mutating this budget.
    pub fn refusal_origins(&self) -> SemanticRefusalOrigins {
        *self.refusal_origins.lock().expect("refusal origins lock")
    }

    fn note_refusal_origin(&self, origin: SemanticRefusalOrigin) {
        let mut origins = self.refusal_origins.lock().expect("refusal origins lock");
        if origin == SemanticRefusalOrigin::UnitResident && self.unit_resident_lane {
            origins.resident = true;
        } else {
            origins.other = true;
        }
    }

    pub fn refusal_count(&self) -> usize {
        self.ledger.refusal_count()
    }

    /// The refusals observed so far. A request built with
    /// [`SemanticRequest::observing_refusals_since`] treats a refusal before
    /// this mark as another unit's, not its own.
    pub fn refusal_mark(&self) -> SemanticBudgetRefusalMark {
        self.ledger.refusal_mark()
    }

    /// Refusals recorded since `mark`; all of this budget's refusals when the
    /// mark belongs to another logical budget.
    pub fn refusals_since(&self, mark: &SemanticBudgetRefusalMark) -> usize {
        self.ledger.refusals_since(mark)
    }

    /// Record a bounded proof's deadline as a budget stop without inventing
    /// retained rows. The first refusal remains the request's stop cause.
    #[doc(hidden)]
    #[track_caller]
    pub fn note_external_stop(&self, dimension: SemanticBudgetDimension) {
        let limit = match dimension {
            SemanticBudgetDimension::SourceBytes => self.limits().source_bytes,
            SemanticBudgetDimension::NestedEntries => self.limits().nested_entries,
            _ => unreachable!("only bounded source and structured proof scans use this stop"),
        };
        let exceeded = SemanticBudgetExceeded::new(dimension, limit, limit.saturating_add(1));
        self.note_refusal_origin(SemanticRefusalOrigin::Other);
        self.ledger.record_refusal();
        self.first_refusal.get_or_init(|| SemanticBudgetRefusal {
            exceeded,
            site: std::panic::Location::caller(),
        });
    }

    pub fn check_admission(&self, work: SemanticWork) -> Result<(), SemanticBudgetExceeded> {
        self.check_admission_without_recording(work)
            .inspect_err(|_| self.ledger.record_refusal())
    }

    fn check_admission_without_recording(
        &self,
        work: SemanticWork,
    ) -> Result<(), SemanticBudgetExceeded> {
        self.ledger
            .with_used(self.resident())
            .check_without_recording(work)
            .map_err(|error| {
                self.note_refusal_origin(SemanticRefusalOrigin::UnitResident);
                SemanticBudgetExceeded::from(error)
            })?;
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
        self.note_refusal_origin(SemanticRefusalOrigin::Other);
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

    /// Charge a complete artifact census and its matching window grant together.
    pub fn admit_artifact_rows(
        &mut self,
        work: SemanticWork,
    ) -> Result<(), SemanticBudgetExceeded> {
        let mut staged = self.clone();
        staged.grant_artifact_rows(work);
        staged.admit(work)?;
        *self = staged;
        Ok(())
    }

    fn admit_resident_artifact_rows(
        &mut self,
        work: SemanticWork,
    ) -> Result<(), SemanticBudgetExceeded> {
        let mut staged = self.clone();
        staged.grant_artifact_rows(work);
        staged.admit_resident(work)?;
        *self = staged;
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
        self.require_room(work)?;
        self.reconcile_residency();
        self.ledger.charge(work).map_err(|exceeded| {
            self.note_refusal_origin(SemanticRefusalOrigin::UnitResident);
            let exceeded = SemanticBudgetExceeded::from(exceeded);
            self.first_refusal
                .get_or_init(|| SemanticBudgetRefusal { exceeded, site });
            exceeded
        })?;
        let used = self.ledger.used();
        self.resident_peak = self.resident_peak.component_max(used);
        self.observe_resident(used);
        Ok(())
    }

    /// Refuse, and remember the refusing code, when `work` would not fit the
    /// resident balance. Nothing is admitted.
    #[track_caller]
    fn require_room(&self, work: SemanticWork) -> Result<(), SemanticBudgetExceeded> {
        let site = std::panic::Location::caller();
        self.check_admission(work).inspect_err(|exceeded| {
            let exceeded = *exceeded;
            self.first_refusal
                .get_or_init(|| SemanticBudgetRefusal { exceeded, site });
        })
    }

    /// Record the highest resident balance every open measurement interval saw,
    /// so a replay can later check the peak a computation needed, not only the
    /// rows it kept.
    fn observe_resident(&mut self, used: SemanticWork) {
        self.own.observe(used);
        for observer in &mut self.replay_observers {
            observer.resident.observe(used);
        }
    }

    /// Record performed work as telemetry. Only retained admissions can refuse.
    pub fn charge_work(&mut self, work: SemanticWork) {
        self.root_work = self.root_work.saturating_add(work);
        self.cumulative = self.cumulative.saturating_add(work);
        self.performed = self.performed.saturating_add(work);
        self.root_work_peak = self.root_work_peak.component_max(self.root_work);
        self.observe_root_work();
    }

    /// Record performed work that is not part of a solver root, such as
    /// preparing source before an artifact cache lookup.
    #[doc(hidden)]
    pub fn record_performed_work(&mut self, work: SemanticWork) {
        self.cumulative = self.cumulative.saturating_add(work);
        self.performed = self.performed.saturating_add(work);
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

    /// A fresh resident ledger for one Output unit of a batch, under this
    /// ledger's limits and logical scope.
    ///
    /// The ledger shares the paid artifact identities (so a repeat touch of an
    /// artifact is charged as a lookup in work) but inherits no live artifact
    /// credit: an artifact the unit touches is admitted into its own balance
    /// whether or not an earlier unit, or a cache that still pins it, already
    /// holds it. What a unit is charged therefore depends on the rows it holds
    /// itself, not on how many units ran before it. It has its own refusal
    /// count and first refusal. Fold it back with [`Self::absorb_unit`].
    pub fn unit_ledger(&self) -> Self {
        let mut unit = Self::new_child(self.limits(), &self.scope_snapshot());
        unit.refusal_origins = Arc::default();
        unit.unit_resident_lane = true;
        unit.inherited_artifacts = Arc::default();
        unit.shared_summary_expansion_limit = self.shared_summary_expansion_limit;
        unit
    }

    /// Fold a finished unit ledger into this one: cumulative and performed
    /// work, the largest work and resident peaks, and the paid artifact
    /// identities. A unit's resident rows die with the unit, so none are
    /// imported, and its refusals stay its own.
    pub fn absorb_unit(&mut self, unit: Self) {
        assert!(
            Arc::ptr_eq(&self.scope, &unit.scope),
            "unit belongs to this semantic scope"
        );
        self.cumulative = self.cumulative.saturating_add(unit.cumulative);
        self.performed = self.performed.saturating_add(unit.performed);
        self.root_work_peak = self.root_work_peak.component_max(unit.root_work_peak);
        self.resident_peak = self.resident_peak.component_max(unit.resident_peak);
        self.observe_completed_root(unit.root_work_peak);
        if !Arc::ptr_eq(&self.charged_artifacts, &unit.charged_artifacts) {
            Arc::make_mut(&mut self.charged_artifacts)
                .extend(unit.charged_artifacts.iter().copied());
        }
    }

    /// Replay a stored unit product the way a fresh unit leaves this ledger: on
    /// an empty unit ledger, which must have room for the unit's peak, with only
    /// its work and peaks folded in. Whether it fits depends on the product and
    /// the limits alone.
    pub fn replay_unit(
        &mut self,
        replay: SemanticBudgetReplay,
    ) -> Result<(), SemanticBudgetExceeded> {
        let mut unit = self.unit_ledger();
        unit.replay_product(replay)?;
        self.absorb_unit(unit);
        Ok(())
    }

    /// Whether [`Self::replay_unit`] would succeed, without changing anything.
    pub fn replay_unit_fits(&self, replay: SemanticBudgetReplay) -> bool {
        self.unit_ledger().replay_product_fits(replay)
    }

    pub fn replay_snapshot(&mut self) -> SemanticBudgetReplaySnapshot {
        self.replay_observers
            .retain(|observer| observer.owner.strong_count() > 0);
        self.reconcile_residency();
        let owner = Arc::new(Mutex::new(MemoDependencyTouches::default()));
        let resident = ResidentInterval::beginning(
            self.ledger.used(),
            &self.resident_owners,
            &self.resident_artifacts,
            false,
        );
        self.replay_observers.push(ReplayObserver {
            owner: Arc::downgrade(&owner),
            base: self.root_work,
            peak: SemanticWork::default(),
            resident,
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

    /// Capture the cold fill's live dependencies and its scratch bound.
    /// The returned holder pays its own census through the ordinary replay.
    pub fn memo_admission_since<T: Send + Sync + 'static>(
        &self,
        before: &SemanticBudgetReplaySnapshot,
        returned_holder: &Arc<T>,
    ) -> SemanticMemoAdmission {
        self.retire_expired_reacquisitions();
        let touched = before
            .owner
            .lock()
            .expect("memo dependency receipt poisoned");
        let mut owners = (*self.resident_owners).clone();
        owners.remove(&(Arc::as_ptr(returned_holder) as usize));
        owners.retain(|key, (owner, _)| {
            owner.strong_count() > 0
                && (!before.owners.contains_key(key) || touched.owners.contains(key))
        });
        let mut artifacts = (*self.resident_artifacts).clone();
        artifacts.retain(|key, (artifact, _)| {
            artifact.has_consumer()
                && (!before.artifacts.contains_key(key) || touched.artifacts.contains(key))
        });
        // An inherited dependency that expired inside the interval was part
        // of the cold fill too. Its census was excluded from the interval's
        // baseline-relative peak; conservatively restore it as transient room.
        let mut transient_peak = self.replay_since(before).resident_peak;
        for (key, (_, census)) in before.owners.iter() {
            if touched.owners.contains(key)
                && !owners.contains_key(key)
                && *key != Arc::as_ptr(returned_holder) as usize
            {
                transient_peak = transient_peak.conservative_add(*census);
            }
        }
        for (key, (_, census)) in before.artifacts.iter() {
            if touched.artifacts.contains(key) && !artifacts.contains_key(key) {
                transient_peak = transient_peak.conservative_add(*census);
            }
        }
        let acquired_owners = owners
            .keys()
            .filter(|key| !before.owners.contains_key(key))
            .copied()
            .collect();
        let acquired_artifacts = artifacts
            .keys()
            .filter(|key| !before.artifacts.contains_key(key))
            .copied()
            .collect();
        SemanticMemoAdmission {
            acquired_owners,
            acquired_artifacts,
            owners,
            artifacts,
            transient_peak,
        }
    }

    /// Speculative hit admission. A miss must recompute without recording a
    /// refusal: only that cold path can establish that the answer is incomplete.
    /// The caller evicts a rejected entry before recomputing, so cache-only
    /// holders cannot inflate the cold fill's balance. Live dependencies are
    /// restored transactionally; expired dependencies can use the active provider.
    /// Restoration imports residency only. The caller's replay owns cumulative
    /// work telemetry; this probe must not count the dependency's work again.
    #[track_caller]
    pub fn admit_memo_hit(
        &mut self,
        admission: &SemanticMemoAdmission,
    ) -> Result<(), SemanticMemoAdmissionMiss> {
        self.admit_memo_hit_with(admission, None)
    }

    /// Admit with the active provider's exact dependency acquisition paths.
    #[track_caller]
    pub fn admit_memo_hit_with(
        &mut self,
        admission: &SemanticMemoAdmission,
        reacquirer: Option<&dyn MemoDependencyReacquirer>,
    ) -> Result<(), SemanticMemoAdmissionMiss> {
        let site = std::panic::Location::caller();
        let mut probe = Self {
            refusal_origins: Arc::default(),
            ..self.clone()
        };
        probe.reconcile_residency();
        let mut acquired_owners = Vec::new();
        let mut acquired_artifacts = Vec::new();
        for (key, (owner, census)) in &admission.owners {
            if probe.resident_owners.contains_key(key) {
                continue;
            }
            let mut owner = owner.clone();
            if owner.upgrade().is_none() {
                let source = owner
                    .source
                    .as_ref()
                    .ok_or(SemanticMemoAdmissionMiss::MissingDependency)?;
                let guard = reacquirer.ok_or(SemanticMemoAdmissionMiss::MissingDependency)?;
                let guard = match source.acquisition {
                    MemoSourceAcquisition::Admit => {
                        guard.admit_source(source, probe.limits().source_bytes)
                    }
                    MemoSourceAcquisition::Hold => {
                        guard.hold_source(source, probe.limits().source_bytes)
                    }
                    MemoSourceAcquisition::Readmit => {
                        guard.readmit_source(source, probe.limits().source_bytes)
                    }
                }
                .map_err(|_| SemanticMemoAdmissionMiss::MissingDependency)?;
                if guard.census != *census {
                    return Err(SemanticMemoAdmissionMiss::MissingDependency);
                }
                let allocation = guard
                    .allocation()
                    .ok_or(SemanticMemoAdmissionMiss::MissingDependency)?;
                owner.allocation = Arc::downgrade(&allocation);
                probe.pin_reacquired(guard);
            }
            if admission.acquired_owners.contains(key) {
                acquired_owners.push((*key, owner.clone(), *census));
                continue;
            }
            probe
                .check_admission_without_recording(*census)
                .map_err(SemanticMemoAdmissionMiss::Residency)?;
            probe
                .admit_resident(*census)
                .expect("prechecked owner admission");
            Arc::make_mut(&mut probe.resident_owners).insert(*key, (owner.clone(), *census));
        }
        for (key, (artifact, census)) in &admission.artifacts {
            if probe.resident_artifacts.contains_key(key) {
                continue;
            }
            // The cold ledger also holds a weak registry entry. Restore it
            // only while a real consumer keeps the allocation resident. A
            // cache-only allocation needs cold acquisition to own its lifetime.
            let mut artifact = artifact.clone();
            if artifact.consumer().is_none() {
                let live = reacquirer
                    .ok_or(SemanticMemoAdmissionMiss::MissingDependency)?
                    .artifact(&artifact.key, &artifact.capabilities)
                    .map_err(|_| SemanticMemoAdmissionMiss::MissingDependency)?;
                if live.key() != &artifact.key
                    || live.capabilities() != &artifact.capabilities
                    || live.work() != *census
                {
                    return Err(SemanticMemoAdmissionMiss::MissingDependency);
                }
                artifact = ResidentArtifact::new(&live);
                probe.pin_reacquired(MemoDependencyGuard::new(live, *census, None));
            }
            if admission.acquired_artifacts.contains(key) {
                acquired_artifacts.push((*key, artifact.clone(), *census));
                continue;
            }
            probe
                .check_admission_without_recording(*census)
                .map_err(SemanticMemoAdmissionMiss::Residency)?;
            probe
                .admit_resident_artifact_rows(*census)
                .expect("prechecked artifact admission");
            Arc::make_mut(&mut probe.resident_artifacts).insert(*key, (artifact.clone(), *census));
        }
        probe
            .check_admission_without_recording(admission.transient_peak)
            .map_err(|exceeded| {
                brokk_bifrost_core::profiling::note_with(|| {
                    format!("semantic.memo_hit[{}].residency_miss", site)
                });
                SemanticMemoAdmissionMiss::Residency(exceeded)
            })?;
        let high = probe
            .ledger
            .used()
            .conservative_add(admission.transient_peak);
        for (key, owner, census) in acquired_owners {
            probe
                .admit_resident(census)
                .expect("retained owner fits measured peak");
            Arc::make_mut(&mut probe.resident_owners).insert(key, (owner, census));
        }
        for (key, artifact, census) in acquired_artifacts {
            probe
                .admit_resident_artifact_rows(census)
                .expect("retained artifact fits measured peak");
            Arc::make_mut(&mut probe.resident_artifacts).insert(key, (artifact, census));
        }
        brokk_bifrost_core::profiling::note_with(|| {
            format!("semantic.memo_hit[{}].admitted", site)
        });
        probe.refusal_origins = Arc::clone(&self.refusal_origins);
        *self = probe;
        for key in admission.owners.keys() {
            self.touch_owner(*key);
        }
        for key in admission.artifacts.keys() {
            self.touch_artifact(*key);
        }
        self.resident_peak = self.resident_peak.component_max(high);
        self.observe_resident(high);
        Ok(())
    }

    fn pin_reacquired(&mut self, guard: MemoDependencyGuard) {
        if !self
            .reacquired
            .iter()
            .any(|existing| Arc::ptr_eq(&existing.allocation, &guard.allocation))
        {
            Arc::make_mut(&mut self.reacquired).push(guard);
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

    /// The descriptor to replay for a cached derivation that `owner` holds.
    ///
    /// Call `admit_memo_hit` first to check the cold fill's transient room
    /// and dependencies. This descriptor then imports work and admits only
    /// returned rows; it does not repeat that peak check. An already-resident
    /// holder retains no additional rows. Returns whether the holder was
    /// already resident, so the caller registers it only once. Independent
    /// policy products use their full replay descriptor instead.
    pub fn replay_for_holder<T: Send + Sync + 'static>(
        &self,
        owner: &Arc<T>,
        mut replay: SemanticBudgetReplay,
    ) -> (SemanticBudgetReplay, bool) {
        let already_held = self.has_replay_holder(owner);
        replay.resident_peak = SemanticWork::default();
        if already_held {
            replay.retained = SemanticWork::default();
        }
        (replay, already_held)
    }

    fn touch_owner(&self, key: usize) {
        for observer in &self.replay_observers {
            if let Some(owner) = observer.owner.upgrade() {
                owner
                    .lock()
                    .expect("memo dependency receipt poisoned")
                    .owners
                    .insert(key);
            }
        }
    }

    fn touch_artifact(&self, key: (StableDigest, usize)) {
        for observer in &self.replay_observers {
            if let Some(owner) = observer.owner.upgrade() {
                owner
                    .lock()
                    .expect("memo dependency receipt poisoned")
                    .artifacts
                    .insert(key);
            }
        }
    }

    pub fn has_replay_holder<T: Send + Sync + 'static>(&self, owner: &Arc<T>) -> bool {
        let key = Arc::as_ptr(owner) as usize;
        let resident = self
            .resident_owners
            .get(&key)
            .is_some_and(|(allocation, _)| allocation.strong_count() > 0);
        if resident {
            self.touch_owner(key);
        }
        resident
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
            resident_peak: observer.resident.peak.component_max(retained),
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
        // Expired holders are not part of the balance this replay lands on.
        staged.reconcile_residency();
        // A fresh computation would have needed its peak, scratch included,
        // before it kept its retained rows, so a replay is refused where the
        // computation would have been (#10530).
        staged.require_room(replay.resident_peak)?;
        let high = staged.ledger.used().conservative_add(replay.resident_peak);
        staged.resident_peak = staged.resident_peak.component_max(high);
        staged.observe_resident(high);
        staged.admit(replay.retained)?;
        staged.cumulative = self.cumulative.saturating_add(replay.cumulative);
        staged.performed = self.performed.saturating_add(replay.performed);
        staged.root_work_peak = staged.root_work_peak.component_max(replay.root_work_peak);
        staged.observe_completed_root(replay.root_work_peak);
        *self = staged;
        Ok(())
    }

    /// Check replay's peak and retained admissions without changing budget or
    /// refusal state. The peak covers the retained rows.
    pub fn replay_product_fits(&self, replay: SemanticBudgetReplay) -> bool {
        self.check_admission_without_recording(replay.resident_peak.component_max(replay.retained))
            .is_ok()
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
        // The staged copy saw resident peaks of its own that this ledger never
        // admitted. Its own peak is what a parent is told this ledger needed,
        // and a measurement interval that both copies share keeps them too.
        self.own.peak = self.own.peak.component_max(staged.own.peak);
        for observer in &mut self.replay_observers {
            if let Some(seen) = staged
                .replay_observers
                .iter()
                .find(|seen| seen.owner.ptr_eq(&observer.owner))
            {
                observer.resident.peak = observer.resident.peak.component_max(seen.resident.peak);
            }
        }
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
        child.retire_expired_reacquisitions();
        assert!(
            Arc::ptr_eq(&self.scope, &child.scope),
            "root belongs to this semantic scope"
        );
        // Root-local artifact handles close with the solve, but prepared
        // source and cached result owners may survive in the query's bounded
        // caches. Transfer only those admissions that still have a holder.
        let cumulative = self.cumulative;
        let performed = self.performed;
        // A root child ran beside what this ledger held, so a measurement
        // interval open here saw the root's own peak on top of the balance that
        // is still here once expired holders are gone. The child's own peak
        // leaves out the rows it inherited, including any that expired while
        // it ran (#10530). A child under an allowance of its own is not bound
        // to fit beside this ledger, so it adds nothing to the interval.
        self.reconcile_residency();
        if child.own.coexists {
            let high = self.ledger.used().conservative_add(child.own.peak);
            self.resident_peak = self.resident_peak.component_max(high);
            self.observe_resident(high);
        }
        for (key, (owner, census)) in child.resident_owners.iter() {
            if owner.strong_count() > 0 && !self.resident_owners.contains_key(key) {
                self.admit(*census)
                    .expect("a root admitted its live owners against the parent's grant");
                Arc::make_mut(&mut self.resident_owners).insert(*key, (owner.clone(), *census));
            }
        }
        for guard in child.reacquired.iter() {
            if self.resident_owners.values().any(|(receipt, _)| {
                receipt.upgrade().is_some_and(|owner| {
                    guard
                        .allocation()
                        .is_some_and(|allocation| Arc::ptr_eq(&owner, &allocation))
                })
            }) {
                self.pin_reacquired(guard.clone());
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
            refusal_origins: Arc::clone(&self.refusal_origins),
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
            window_open: false,
            window_default_limits: None,
            cumulative: SemanticWork::default(),
            performed: SemanticWork::default(),
            root_work: SemanticWork::default(),
            root_work_peak: SemanticWork::default(),
            replay_observers: Vec::new(),
            lowering_work: None,
            resident_peak: SemanticWork::default(),
            own: ResidentInterval::independent(),
            resident_artifacts: Arc::default(),
            resident_owners: Arc::default(),
            reacquired: Arc::default(),
            inherited_artifacts: Arc::clone(&parent.admitted_artifacts),
            scope: Arc::clone(&parent.scope),
            charged_artifacts: Arc::clone(&parent.charged_artifacts),
            shared_summary_expansion_limit: parent.shared_summary_expansion_limit,
            first_refusal: Arc::default(),
            refusal_origins: Arc::clone(&parent.refusal_origins),
            unit_resident_lane: false,
            lowered: Arc::clone(&parent.lowered),
        }
    }

    /// A child carved from the allowance its parent had left, to run beside the
    /// parent's holders: unlike an independent child (a class-set root or a
    /// prepass under an allowance of its own), its peak must fit on top of the
    /// parent's balance when its charge is applied, and siblings carved from the
    /// same remainder that do not fit together are refused (#10530).
    pub fn new_carved_child(limits: SemanticWork, parent: &SemanticBudgetScopeSnapshot) -> Self {
        let mut child = Self::new_child(limits, parent);
        child.own.coexists = true;
        child
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
        child.reacquired = Arc::clone(&parent.reacquired);
        child.reconcile_residency();
        child.resident_peak = child.ledger.used();
        child.own = ResidentInterval::beginning(
            child.ledger.used(),
            &child.resident_owners,
            &child.resident_artifacts,
            true,
        );
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
            reacquired: self.reacquired,
            scope: self.scope,
            work,
            performed: self.performed,
            resident_peak: self.resident_peak,
            resident_transient_peak: self.own.peak,
            resident_coexists: self.own.coexists,
            root_work_peak: self.root_work_peak,
            charged_artifacts: self.charged_artifacts,
        }
    }

    fn child_resident_addition(&self, charge: &SemanticBudgetCharge) -> SemanticWork {
        for guard in charge.reacquired.iter() {
            guard.retain_while_provider_lives();
        }
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
        for guard in charge.reacquired.iter() {
            guard.retain_while_provider_lives();
        }
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
        for guard in charge.reacquired.iter() {
            staged.pin_reacquired(guard.clone());
        }
        staged.reconcile_residency();
        // The child ran beside what this ledger held, and siblings carved from
        // the same remaining allowance may not fit together. A live run that
        // went over must be refused here, or its replay would be refused where
        // the live run was not (#10530).
        if charge.resident_coexists {
            staged.require_room(charge.resident_transient_peak)?;
            let high = staged
                .ledger
                .used()
                .conservative_add(charge.resident_transient_peak);
            staged.resident_peak = staged.resident_peak.component_max(high);
            staged.observe_resident(high);
        }
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
            resident_peak: SemanticWork::default(),
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
        let peak = if charge.resident_coexists {
            charge.resident_transient_peak
        } else {
            SemanticWork::default()
        };
        self.check_admission(bounded.component_max(peak))
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
        let resident = self
            .resident_artifacts
            .get(&key)
            .or_else(|| self.inherited_artifacts.get(&key))
            .is_some_and(|(allocation, _)| allocation.has_consumer());
        if resident {
            self.touch_artifact(key);
        }
        resident
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
            self.admit_resident_artifact_rows(census)?;
            self.track_resident_artifact(artifact);
            return self.charge_complete_artifact_hit(identity, census);
        }
        self.admit_artifact_rows(census)?;
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
                resident_peak: SemanticWork::default(),
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
            staged.admit_artifact_rows(full_work)?;
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

impl SemanticBudget {
    /// Every semantic artifact is lowered under this budget, so its contents
    /// depend only on source content and producer identity. Parse-time and
    /// on-demand publication must use the same producer budget.
    pub fn producer() -> Self {
        Self::default()
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

    /// The one way to refuse a charge: the ledger becomes exhausted and the
    /// answer under construction is reported execution dependent, so it is
    /// never reused as content.
    fn refuse(state: &mut SemanticExecutionBudgetState) -> BudgetRefusal {
        state.exhausted = true;
        brokk_bifrost_core::analyzer::carried_context::mark_execution_dependent();
        BudgetRefusal(())
    }

    pub fn admit_materialization(&self, file: &ProjectFile) -> bool {
        self.try_admit_materialization(file).is_ok()
    }

    pub(crate) fn try_admit_materialization(
        &self,
        file: &ProjectFile,
    ) -> Result<(), BudgetRefusal> {
        let mut state = self.state.lock().expect("semantic execution budget lock");
        if state.materialized_files.contains(file) {
            return Ok(());
        }
        let used = state
            .externally_materialized_files
            .saturating_add(state.materialized_files.len());
        if used >= state.max_materialized_files {
            return Err(Self::refuse(&mut state));
        }
        Arc::make_mut(&mut state.materialized_files).insert(file.clone());
        Ok(())
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
            .is_ok()
    }

    pub fn external_query_work_fits(
        &self,
        materialized_files: usize,
        traversal_steps: usize,
    ) -> bool {
        let state = self.state.lock().expect("semantic execution budget lock");
        state
            .externally_materialized_files
            .checked_add(state.materialized_files.len())
            .and_then(|used| used.checked_add(materialized_files))
            .is_some_and(|attempted| attempted <= state.max_materialized_files)
            && state
                .max_traversal_steps
                .is_none_or(|limit| traversal_steps <= limit.saturating_sub(state.traversal_steps))
    }

    fn charge_external_work(
        &self,
        materialized_files: usize,
        traversal_steps: usize,
    ) -> Result<(), BudgetRefusal> {
        let mut state = self.state.lock().expect("semantic execution budget lock");
        let Some(attempted_files) = state
            .externally_materialized_files
            .checked_add(state.materialized_files.len())
            .and_then(|used| used.checked_add(materialized_files))
        else {
            return Err(Self::refuse(&mut state));
        };
        let attempted_traversal = state.traversal_steps.saturating_add(traversal_steps);
        if attempted_files > state.max_materialized_files
            || state
                .max_traversal_steps
                .is_some_and(|limit| traversal_steps > limit.saturating_sub(state.traversal_steps))
        {
            return Err(Self::refuse(&mut state));
        }
        state.externally_materialized_files += materialized_files;
        state.traversal_steps = attempted_traversal;
        Ok(())
    }

    pub fn charge_traversal(&self, steps: usize) -> bool {
        self.try_charge_traversal(steps).is_ok()
    }

    pub(crate) fn try_charge_traversal(&self, steps: usize) -> Result<(), BudgetRefusal> {
        self.charge_external_work(0, steps)
    }
}

/// A charge a [`SemanticExecutionBudget`] refused. Only the ledger's
/// `refuse` builds one, so holding a refusal proves the ledger is exhausted
/// and the answer was reported execution dependent.
#[must_use = "a refused execution-budget charge stops the work that asked for it"]
#[derive(Debug)]
pub(crate) struct BudgetRefusal(());

/// A semantic result whose uncertainty, partial value, and work remain explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticOutcome<T> {
    Complete {
        value: T,
        /// The work represented by the answer (recorded work for cached rows),
        /// not the charge to the caller's budget.
        work: SemanticWork,
    },
    Ambiguous {
        candidates: T,
        /// The work represented by the answer (recorded work for cached rows),
        /// not the charge to the caller's budget.
        work: SemanticWork,
    },
    Unknown {
        partial: Option<T>,
        /// The work represented by the answer (recorded work for cached rows),
        /// not the charge to the caller's budget.
        work: SemanticWork,
    },
    Unsupported {
        capability: SemanticCapability,
        partial: Option<T>,
        /// The work represented by the answer (recorded work for cached rows),
        /// not the charge to the caller's budget.
        work: SemanticWork,
    },
    Unproven {
        partial: T,
        /// The work represented by the answer (recorded work for cached rows),
        /// not the charge to the caller's budget.
        work: SemanticWork,
    },
    ExceededBudget {
        partial: Option<T>,
        exceeded: SemanticBudgetExceeded,
        /// The work represented by the answer (recorded work for cached rows),
        /// not the charge to the caller's budget.
        work: SemanticWork,
    },
    Cancelled {
        partial: Option<T>,
        /// The work represented by the answer (recorded work for cached rows),
        /// not the charge to the caller's budget.
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
    /// Where this request's own refusals start counting; `None` counts all of
    /// the budget's refusals.
    refusal_mark: Option<SemanticBudgetRefusalMark>,
}

impl<'a> SemanticRequest<'a> {
    pub fn new(budget: &'a mut SemanticBudget, cancellation: &'a CancellationToken) -> Self {
        Self {
            budget,
            cancellation,
            execution: None,
            artifact_collector: None,
            value_type_barrier_context: None,
            refusal_mark: None,
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
            refusal_mark: None,
        }
    }

    /// Count only the refusals recorded after `mark` as this request's own for
    /// [`Self::stop_observed`]. A caller that runs independent units on one
    /// ledger takes the mark when a unit starts, so a refusal that truncated an
    /// earlier unit is not read as a stop of this one. A request staged over a
    /// child budget, which counts from zero, sees all of that budget's refusals.
    pub fn observing_refusals_since(mut self, mark: SemanticBudgetRefusalMark) -> Self {
        self.refusal_mark = Some(mark);
        self
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
            refusal_mark: self.refusal_mark.clone(),
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
            refusal_mark: self.refusal_mark.clone(),
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

    /// A query-local proof stopped before it could establish complete data.
    /// Capture-scoped memos must not retain values produced under this state.
    pub fn stop_observed(&self) -> bool {
        self.cancellation.is_cancelled()
            || match &self.refusal_mark {
                Some(mark) => self.budget.refusals_since(mark) > 0,
                None => self.budget.refusal_count() > 0,
            }
            || self
                .execution
                .as_ref()
                .is_some_and(|budget| budget.work().exhausted)
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
        self.try_charge_execution_traversal(steps).is_ok()
    }

    pub(crate) fn try_charge_execution_traversal(&self, steps: usize) -> Result<(), BudgetRefusal> {
        self.execution
            .as_ref()
            .map_or(Ok(()), |execution| execution.try_charge_traversal(steps))
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FootprintAdmission {
    Admitted {
        call_target_obligations: Vec<crate::analyzer::semantic::CallTargetObligation>,
    },
    Refused(FootprintAdmissionRefusal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FootprintAdmissionRefusal {
    CoverageUnavailable,
    OldContract,
    UnknownCode,
    DuplicateClass,
    MissingClass,
    RefusedCoverage,
}

/// A standalone per-language adapter boundary for immutable semantic artifacts.
pub trait ProgramSemanticsProvider: Send + Sync {
    /// Identity of the active lowerer before any file is materialized.
    fn lowering_identity(
        &self,
    ) -> Option<crate::analyzer::semantic::service::SemanticAdapterIdentity> {
        None
    }
    /// Exercise the language lowerer before publication in cross-language tests.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    fn lower_with_budget_for_test(
        &self,
        _file: &ProjectFile,
        _budget: &SemanticBudget,
        _cancellation: &CancellationToken,
    ) -> Result<
        SemanticOutcome<Vec<crate::analyzer::semantic::ProcedureSemanticsParts>>,
        SemanticProviderError,
    > {
        unimplemented!("this provider has no direct language lowerer")
    }
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

    /// Observe the selected stored publication under one bounded authority check.
    fn stored_semantic_ir_publication_read(
        &self,
        _file: &ProjectFile,
        _subject: [u8; 32],
        _source_byte_cap: Option<usize>,
        _cancellation: &CancellationToken,
    ) -> Result<StoredSemanticIrRead, SemanticProviderError> {
        Ok(StoredSemanticIrRead::Refused)
    }

    /// Admission for an exact stored procedure footprint. Missing authority refuses.
    fn stored_footprint_coverage(
        &self,
        _procedure: &ProcedureHandle,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<crate::analyzer::semantic::FootprintAdmission, SemanticProviderError> {
        Ok(crate::analyzer::semantic::FootprintAdmission::Refused(
            crate::analyzer::semantic::FootprintAdmissionRefusal::CoverageUnavailable,
        ))
    }

    /// Admission for the selected procedure's scoped call/control coverage. Missing authority refuses.
    fn stored_call_control_coverage(
        &self,
        _procedure: &ProcedureHandle,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<crate::analyzer::semantic::FootprintAdmission, SemanticProviderError> {
        Ok(crate::analyzer::semantic::FootprintAdmission::Refused(
            crate::analyzer::semantic::FootprintAdmissionRefusal::CoverageUnavailable,
        ))
    }

    /// Decode one procedure from the artifact's complete stored IR rows.
    /// A provider without matching rows returns `None`.
    fn stored_semantic_ir_procedure(
        &self,
        _file: &ProjectFile,
        _key: &SemanticArtifactKey,
        _procedure: ProcedureId,
    ) -> Result<Option<crate::analyzer::semantic::ProcedureSemanticsParts>, SemanticProviderError>
    {
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
    fn provider_without_store_refuses_publication_read() {
        let file = ProjectFile::new(std::env::temp_dir(), "sample.rs");
        let result = UnsupportedProgramSemantics.stored_semantic_ir_publication_read(
            &file,
            [0; 32],
            None,
            &CancellationToken::default(),
        );
        assert!(matches!(result, Ok(StoredSemanticIrRead::Refused)));
    }

    #[test]
    #[hardwon("#10403: a refusal that truncated one unit cut every later unit on the ledger short")]
    fn refusal_mark_scopes_a_stop_to_the_unit_that_caused_it() {
        let cancellation = CancellationToken::default();
        let over = SemanticWork {
            program_points: 2,
            ..SemanticWork::default()
        };
        let mut budget = SemanticBudget::uniform(1).unwrap();
        // Unit one is refused.
        assert!(budget.admit(over).is_err());
        // Without a mark every later request on the ledger still sees the stop.
        assert!(SemanticRequest::new(&mut budget, &cancellation).stop_observed());
        // A request that starts after the refusal does not count it as its own.
        let mark = budget.refusal_mark();
        assert!(
            !SemanticRequest::new(&mut budget, &cancellation)
                .observing_refusals_since(mark.clone())
                .stop_observed()
        );
        // A refusal during the request is its own.
        assert!(budget.admit(over).is_err());
        assert!(
            SemanticRequest::new(&mut budget, &cancellation)
                .observing_refusals_since(mark.clone())
                .stop_observed()
        );
        assert_eq!(budget.refusals_since(&mark), 1);
        // A staged request keeps the mark; one over a child budget, which
        // counts from zero, sees all of its own refusals.
        let request =
            SemanticRequest::new(&mut budget, &cancellation).observing_refusals_since(mark.clone());
        let mut staged_copy = request.budget.clone();
        assert!(request.staged(&mut staged_copy).stop_observed());
        let mut child = SemanticBudget::uniform(1).unwrap();
        assert!(child.admit(over).is_err());
        let request =
            SemanticRequest::new(&mut budget, &cancellation).observing_refusals_since(mark.clone());
        assert!(request.staged(&mut child).stop_observed());
        assert_eq!(child.refusals_since(&mark), 1);
    }

    #[test]
    #[hardwon(
        "#10530: a replayed Output unit passed on its retained census while a fresh run is refused at the transient peak"
    )]
    fn replay_checks_the_transient_peak_not_only_the_retained_census() {
        let evidence = |rows: usize| SemanticWork {
            evidence: rows,
            ..SemanticWork::default()
        };
        let mut generous = SemanticBudget::uniform(100).unwrap();
        let before = generous.replay_snapshot();
        // A computation that needs 80 rows while it runs and keeps 10.
        generous.admit(evidence(80)).unwrap();
        generous.release_admission(evidence(70));
        let replay = generous.replay_since(&before);
        assert_eq!(replay.retained.evidence, 10);
        assert_eq!(replay.resident_peak.evidence, 80);

        // A tighter ledger fits the 10 retained rows but a fresh run would be
        // refused at 80, so the replay must be too, and must say so the same way.
        let mut tight = SemanticBudget::uniform(50).unwrap();
        assert!(tight.check_admission(replay.retained).is_ok());
        assert!(!tight.replay_product_fits(replay));
        assert!(tight.replay_product(replay).is_err());
        assert_eq!(
            tight.resident().evidence,
            0,
            "a refused replay admits nothing"
        );
        let mut fresh = SemanticBudget::uniform(50).unwrap();
        assert!(fresh.admit(evidence(80)).is_err());
        assert_eq!(
            tight
                .first_refusal()
                .map(|refusal| refusal.exceeded.dimension()),
            fresh
                .first_refusal()
                .map(|refusal| refusal.exceeded.dimension()),
            "the replay and the fresh run are refused on the same lane"
        );

        // A ledger with room for the peak replays it and keeps only the retained rows.
        let mut roomy = SemanticBudget::uniform(90).unwrap();
        assert!(roomy.replay_product_fits(replay));
        roomy.replay_product(replay).unwrap();
        assert_eq!(roomy.resident().evidence, 10);
        // A descriptor built without a measurement checks only what it retains.
        let unmeasured = SemanticBudgetReplay {
            retained: evidence(10),
            ..SemanticBudgetReplay::default()
        };
        assert!(
            SemanticBudget::uniform(10)
                .unwrap()
                .replay_product_fits(unmeasured)
        );
    }

    fn evidence_rows(rows: usize) -> SemanticWork {
        SemanticWork {
            evidence: rows,
            ..SemanticWork::default()
        }
    }

    #[test]
    #[hardwon(
        "#10530: a product computed through a root child was replayed without the peak its child needed"
    )]
    fn replay_checks_the_peak_of_an_absorbed_root_child() {
        // The parent already holds 10 rows when the measured computation starts.
        let mut parent = SemanticBudget::uniform(100).unwrap();
        parent.admit(evidence_rows(10)).unwrap();
        let before = parent.replay_snapshot();
        // The root runs beside those 10 rows: it needs 60 more while it runs
        // and keeps 10 behind a cache owner.
        let mut root = SemanticBudget::new_root_child(&parent);
        root.admit(evidence_rows(60)).unwrap();
        root.release_admission(evidence_rows(60));
        let kept = root.replay_snapshot();
        root.admit(evidence_rows(10)).unwrap();
        let owner = Arc::new(());
        root.bind_replay_holder(&owner, &kept);
        parent.absorb_root_work(root);
        let replay = parent.replay_since(&before);
        assert_eq!(replay.retained.evidence, 10);
        assert_eq!(replay.resident_peak.evidence, 60);

        // A fresh run on a ledger of 50 is refused when the root asks for its
        // 60 beside the parent's 10. The replay must be refused on the same lane.
        let mut fresh = SemanticBudget::uniform(50).unwrap();
        fresh.admit(evidence_rows(10)).unwrap();
        let mut fresh_root = SemanticBudget::new_root_child(&fresh);
        assert!(fresh_root.admit(evidence_rows(60)).is_err());
        let mut tight = SemanticBudget::uniform(50).unwrap();
        assert!(tight.check_admission(replay.retained).is_ok());
        assert!(!tight.replay_product_fits(replay));
        assert_eq!(
            tight
                .replay_product(replay)
                .map_err(|exceeded| exceeded.dimension()),
            Err(fresh_root.first_refusal().unwrap().exceeded.dimension())
        );
    }

    #[test]
    #[hardwon(
        "#10530: a product computed through an applied child charge was replayed without the peak its child needed"
    )]
    fn replay_checks_the_peak_of_an_applied_child_charge() {
        let mut parent = SemanticBudget::uniform(100).unwrap();
        parent.admit(evidence_rows(10)).unwrap();
        let before = parent.replay_snapshot();
        // An independent child carved from the remaining allowance needs 60 and
        // keeps 5.
        let mut child =
            SemanticBudget::new_carved_child(parent.remaining(), &parent.scope_snapshot());
        child.admit(evidence_rows(60)).unwrap();
        child.release_admission(evidence_rows(55));
        parent
            .apply_child_charge(SemanticWork::default(), child.into_child_charge())
            .unwrap();
        let replay = parent.replay_since(&before);
        assert_eq!(replay.retained.evidence, 5);
        assert_eq!(replay.resident_peak.evidence, 60);
        let mut tight = SemanticBudget::uniform(50).unwrap();
        assert!(tight.check_admission(replay.retained).is_ok());
        assert!(!tight.replay_product_fits(replay));
        assert!(tight.replay_product(replay).is_err());
    }

    #[test]
    #[hardwon("#10893: dropped policy source sessions prevented every warm summary hit")]
    fn expired_source_reacquisition_preserves_cold_peak_edges() {
        use crate::analyzer::semantic::service::{
            SemanticAdapterIdentity, semantic_artifact_key_from_content,
        };
        use crate::analyzer::semantic::{ContentIdentity, DependencyFingerprint, ProcedureId};
        struct Sources {
            lifetime: Option<Weak<()>>,
        }
        impl MemoDependencyReacquirer for Sources {
            fn hold_source(
                &self,
                _: &MemoSourceDependency,
                _: usize,
            ) -> Result<MemoDependencyGuard, MemoDependencyRefusal> {
                Ok(MemoDependencyGuard::new(
                    Arc::new(vec![0_u8; 20]),
                    SemanticWork {
                        source_bytes: 20,
                        ..Default::default()
                    },
                    self.lifetime.clone(),
                ))
            }
        }
        let sources = Sources { lifetime: None };
        let file = ProjectFile::new(std::env::temp_dir(), "reacquire.rs");
        let key = semantic_artifact_key_from_content(
            &file,
            brokk_bifrost_core::analyzer::model::LanguageDialect::Standard(
                brokk_bifrost_core::analyzer::model::Language::Rust,
            ),
            ContentIdentity::from_digest(StableDigest::sha256(b"source")),
            None,
            SemanticAdapterIdentity::for_adapter(
                "test",
                b"1",
                b"",
                DependencyFingerprint::from_digest(StableDigest::sha256(b"")),
            ),
        )
        .unwrap();
        let source = SemanticWork {
            source_bytes: 20,
            ..Default::default()
        };
        let scratch = SemanticWork {
            source_bytes: 80,
            ..Default::default()
        };
        for inherited in [false, true] {
            let owner = Arc::new(vec![0_u8; 20]);
            let mut fill = SemanticBudget::uniform(150).unwrap();
            if inherited {
                fill.hold_source(&owner, 20).unwrap();
            }
            let before = fill.replay_snapshot();
            fill.hold_source(&owner, 20).unwrap();
            fill.record_source_reacquisition(
                &owner,
                MemoSourceDependency {
                    procedure: (key.clone(), ProcedureId::new(0)),
                    acquisition: MemoSourceAcquisition::Hold,
                },
            );
            fill.admit(scratch).unwrap();
            fill.release_admission(scratch);
            let admission = fill.memo_admission_since(&before, &Arc::new(()));
            drop(owner);
            drop(fill);
            for limit in [99, 100] {
                let mut warm = SemanticBudget::uniform(limit).unwrap();
                let accepted = warm.admit_memo_hit_with(&admission, Some(&sources)).is_ok();
                let mut cold = SemanticBudget::uniform(limit).unwrap();
                let owner = Arc::new(vec![0_u8; 20]);
                cold.hold_source(&owner, 20).unwrap();
                assert_eq!(cold.admit(scratch).is_ok(), accepted);
                assert_eq!(accepted, limit == 100);
                assert_eq!(warm.refusal_count(), 0);
                assert_eq!(warm.refusal_origins(), SemanticRefusalOrigins::default());
                if accepted {
                    cold.release_admission(scratch);
                    assert_eq!(warm.resident(), source);
                    assert_eq!(warm.resident(), cold.resident());
                    assert_eq!(warm.resident_peak(), cold.resident_peak());
                    assert_eq!(warm.resident_owners.len(), cold.resident_owners.len());
                    let mut parent = SemanticBudget::uniform(limit).unwrap();
                    let mut child = SemanticBudget::new_root_child(&parent);
                    child
                        .admit_memo_hit_with(&admission, Some(&sources))
                        .unwrap();
                    parent.absorb_root_work(child);
                    assert_eq!(parent.resident(), source);
                    parent.release_resident();
                    assert!(parent.reacquired.is_empty());
                    let provider = Arc::new(());
                    let scoped = Sources {
                        lifetime: Some(Arc::downgrade(&provider)),
                    };
                    let mut region = SemanticBudget::uniform(limit).unwrap();
                    region
                        .admit_memo_hit_with(&admission, Some(&scoped))
                        .unwrap();
                    let staging = region.clone();
                    drop(provider);
                    assert_eq!(region.resident(), SemanticWork::default());
                    assert_eq!(staging.resident(), SemanticWork::default());
                } else {
                    assert_eq!(warm.resident(), SemanticWork::default());
                    assert!(warm.reacquired.is_empty());
                }
            }
        }
    }

    #[test]
    #[hardwon("#10893: a warm memo hit completed where a cold fill stopped on transient residency")]
    fn memo_admission_preserves_cold_transient_and_dependency_stops() {
        let mut fill = SemanticBudget::uniform(150).unwrap();
        let before = fill.replay_snapshot();
        fill.admit(evidence_rows(80)).unwrap();
        fill.release_admission(evidence_rows(80));
        fill.admit(evidence_rows(1)).unwrap();
        let result = Arc::new(());
        let admission = fill.memo_admission_since(&before, &result);
        for limit in [79, 80] {
            let mut warm = SemanticBudget::uniform(limit).unwrap();
            let accepted = warm.admit_memo_hit(&admission).is_ok();
            assert_eq!(accepted, limit == 80);
            assert_eq!(warm.refusal_count(), 0, "a speculative miss is not a stop");
            assert_eq!(warm.refusal_origins(), SemanticRefusalOrigins::default());
            assert_eq!(warm.resident(), SemanticWork::default());
            let mut cold = SemanticBudget::uniform(limit).unwrap();
            assert_eq!(cold.admit(evidence_rows(80)).is_ok(), accepted);
        }

        // Acquisitions inside the interval are already in its peak.
        let dependency = Arc::new(());
        let mut fill = SemanticBudget::uniform(150).unwrap();
        let before = fill.replay_snapshot();
        fill.admit_held(evidence_rows(20)).unwrap();
        fill.track_replay_holder(&dependency, evidence_rows(20));
        fill.admit(evidence_rows(80)).unwrap();
        fill.release_admission(evidence_rows(80));
        let admission = fill.memo_admission_since(&before, &Arc::new(()));
        for limit in [99, 100] {
            let mut warm = SemanticBudget::uniform(limit).unwrap();
            let accepted = warm.admit_memo_hit(&admission).is_ok();
            let mut cold = SemanticBudget::uniform(limit).unwrap();
            cold.admit_held(evidence_rows(20)).unwrap();
            cold.track_replay_holder(&dependency, evidence_rows(20));
            assert_eq!(cold.admit(evidence_rows(80)).is_ok(), accepted);
            assert_eq!(accepted, limit == 100);
            assert_eq!(warm.refusal_count(), 0);
            if accepted {
                cold.release_admission(evidence_rows(80));
                assert_eq!(warm.resident(), cold.resident());
            } else {
                assert_eq!(warm.resident(), SemanticWork::default());
            }
        }

        // A cache-only result must be evicted on a miss before the cold fill
        // starts. Otherwise its old 400 rows falsely refuse a 480-row fill.
        let mut cache = HashMap::new();
        let mut warm = SemanticBudget::uniform(600).unwrap();
        let before = warm.replay_snapshot();
        warm.admit(evidence_rows(480)).unwrap();
        warm.release_admission(evidence_rows(80));
        let holder = Arc::new(());
        warm.bind_replay_holder(&holder, &before);
        let admission = warm.memo_admission_since(&before, &holder);
        cache.insert(0, holder);
        assert!(warm.admit_memo_hit(&admission).is_err());
        assert_eq!(warm.refusal_count(), 0);
        drop(cache.remove(&0).unwrap());
        let before = warm.replay_snapshot();
        warm.admit(evidence_rows(480)).unwrap();
        warm.release_admission(evidence_rows(80));
        let holder = Arc::new(());
        warm.bind_replay_holder(&holder, &before);
        let mut cold = SemanticBudget::uniform(600).unwrap();
        cold.admit(evidence_rows(480)).unwrap();
        cold.release_admission(evidence_rows(80));
        assert_eq!(warm.resident(), cold.resident());
        assert_eq!(warm.refusal_count(), cold.refusal_count());

        // The fill inherited this dependency. Its interval peak alone omits it.
        let dependency = Arc::new(());
        let mut fill = SemanticBudget::uniform(150).unwrap();
        fill.admit(evidence_rows(100)).unwrap();
        fill.track_replay_holder(&dependency, evidence_rows(100));
        let untouched = Arc::new(());
        fill.admit_held(evidence_rows(20)).unwrap();
        fill.track_replay_holder(&untouched, evidence_rows(20));
        let before = fill.replay_snapshot();
        assert!(fill.has_replay_holder(&dependency));
        fill.admit(evidence_rows(1)).unwrap();
        let result = Arc::new(());
        let admission = fill.memo_admission_since(&before, &result);
        assert!(
            !admission
                .owners
                .contains_key(&(Arc::as_ptr(&untouched) as usize))
        );
        for limit in [100, 101] {
            let mut warm = SemanticBudget::uniform(limit).unwrap();
            let accepted = warm.admit_memo_hit(&admission).is_ok();
            assert_eq!(accepted, limit == 101);
            assert_eq!(warm.refusal_count(), 0);
            assert_eq!(warm.refusal_origins(), SemanticRefusalOrigins::default());
            let mut cold = SemanticBudget::uniform(limit).unwrap();
            cold.admit_held(evidence_rows(100)).unwrap();
            cold.track_replay_holder(&dependency, evidence_rows(100));
            assert_eq!(cold.check_admission(evidence_rows(1)).is_ok(), accepted);
            if accepted {
                assert_eq!(warm.resident(), cold.resident());
                assert_eq!(
                    warm.resident_owners.keys().collect::<Vec<_>>(),
                    cold.resident_owners.keys().collect::<Vec<_>>()
                );
            } else {
                assert_eq!(warm.resident(), SemanticWork::default());
            }
        }
        drop(dependency);
        let expired = Arc::new(());
        let mut fill = SemanticBudget::uniform(150).unwrap();
        fill.admit(evidence_rows(100)).unwrap();
        fill.track_replay_holder(&expired, evidence_rows(100));
        let before = fill.replay_snapshot();
        assert!(fill.has_replay_holder(&expired));
        drop(expired);
        fill.admit(evidence_rows(1)).unwrap();
        let expired_admission = fill.memo_admission_since(&before, &Arc::new(()));
        assert!(
            SemanticBudget::uniform(50)
                .unwrap()
                .admit_memo_hit(&expired_admission)
                .is_err()
        );
        let mut fresh = SemanticBudget::uniform(150).unwrap();
        assert!(matches!(
            fresh.admit_memo_hit(&admission),
            Err(SemanticMemoAdmissionMiss::MissingDependency)
        ));
    }

    #[test]
    #[hardwon(
        "#10530: a second lookup of a resident cached product was refused for scratch room it never allocates"
    )]
    fn a_repeat_lookup_of_a_resident_product_needs_no_transient_room() {
        // A refinement that kept 400 rows but needed 80 more while it was derived.
        let descriptor_with_scratch = || SemanticBudgetReplay {
            retained: evidence_rows(400),
            resident_peak: evidence_rows(480),
            ..SemanticBudgetReplay::default()
        };
        let mut budget = SemanticBudget::uniform(600).unwrap();
        // A 400-row refinement whose derivation held no more than it keeps.
        let before = budget.replay_snapshot();
        budget.admit(evidence_rows(400)).unwrap();
        let owner = Arc::new(());
        budget.bind_replay_holder(&owner, &before);
        let descriptor = budget.replay_since(&before);
        assert_eq!(descriptor.retained.evidence, 400);
        assert_eq!(descriptor.resident_peak.evidence, 400);
        // The product is resident, so the second lookup allocates nothing and
        // is not refused although 400 more rows would not fit under 600.
        let (replay, already_held) = budget.replay_for_holder(&owner, descriptor);
        assert!(already_held);
        assert_eq!(replay.retained, SemanticWork::default());
        assert_eq!(replay.resident_peak, SemanticWork::default());
        budget.replay_continuation(replay).unwrap();
        assert_eq!(budget.resident().evidence, 400);
        // A cached product that is not resident needs room for its returned
        // rows, but not for the scratch its derivation used.
        let stranger = Arc::new(());
        let (replay, already_held) = budget.replay_for_holder(&stranger, descriptor);
        assert!(!already_held);
        assert_eq!(replay.retained.evidence, 400);
        assert_eq!(replay.resident_peak, SemanticWork::default());
        assert!(
            !budget.replay_product_fits(replay),
            "400 more do not fit beside 400"
        );
        let mut roomy = SemanticBudget::uniform(450).unwrap();
        let (replay, _) = roomy.replay_for_holder(&stranger, descriptor_with_scratch());
        assert!(roomy.replay_product_fits(replay));
        roomy.replay_continuation(replay).unwrap();
    }

    #[test]
    #[hardwon(
        "#10530: an expired holder inflated the peak recorded for the interval that enclosed a replay"
    )]
    fn an_expired_holder_does_not_inflate_the_recorded_peak() {
        let inner = SemanticBudgetReplay {
            retained: evidence_rows(50),
            resident_peak: evidence_rows(50),
            ..SemanticBudgetReplay::default()
        };
        // The holder was admitted before the interval and expires inside it.
        let mut budget = SemanticBudget::uniform(100).unwrap();
        let before_holder = budget.replay_snapshot();
        budget.admit(evidence_rows(60)).unwrap();
        let holder = Arc::new(());
        budget.bind_replay_holder(&holder, &before_holder);
        drop(before_holder);
        let outer = budget.replay_snapshot();
        drop(holder);
        budget.replay_product(inner).unwrap();
        let enclosing = budget.replay_since(&outer);
        assert_eq!(enclosing.resident_peak.evidence, 50);
        assert!(
            SemanticBudget::uniform(100)
                .unwrap()
                .replay_product_fits(enclosing)
        );

        // The holder was admitted inside the interval and expires inside it.
        let mut budget = SemanticBudget::uniform(100).unwrap();
        let outer = budget.replay_snapshot();
        let before_holder = budget.replay_snapshot();
        budget.admit(evidence_rows(60)).unwrap();
        let holder = Arc::new(());
        budget.bind_replay_holder(&holder, &before_holder);
        drop(holder);
        budget.replay_product(inner).unwrap();
        let enclosing = budget.replay_since(&outer);
        // 60 while the holder lived, then 50 on its own: never 110.
        assert_eq!(enclosing.resident_peak.evidence, 60);
        assert!(
            SemanticBudget::uniform(100)
                .unwrap()
                .replay_product_fits(enclosing)
        );
    }

    #[test]
    #[hardwon(
        "#10530: a root's inherited holder expiring hid the rows the root then used, so its replay passed where recomputing refuses"
    )]
    fn a_root_reports_its_own_peak_when_an_inherited_holder_expires() {
        let mut parent = SemanticBudget::uniform(100).unwrap();
        let held = parent.replay_snapshot();
        parent.admit(evidence_rows(80)).unwrap();
        let inherited = Arc::new(());
        parent.bind_replay_holder(&inherited, &held);
        drop(held);
        let before = parent.replay_snapshot();
        let mut root = SemanticBudget::new_root_child(&parent);
        drop(inherited);
        // The inherited 80 are gone; the root needs 60 temporary rows of its own.
        root.admit(evidence_rows(60)).unwrap();
        root.release_admission(evidence_rows(60));
        parent.absorb_root_work(root);
        let replay = parent.replay_since(&before);
        assert_eq!(replay.resident_peak.evidence, 60);
        // Recomputing on a ledger of 50 refuses the root's 60; so must the replay.
        let mut fresh = SemanticBudget::uniform(50).unwrap();
        let mut fresh_root = SemanticBudget::new_root_child(&fresh);
        assert!(fresh_root.admit(evidence_rows(60)).is_err());
        assert!(fresh.replay_product(replay).is_err());
    }

    #[test]
    #[hardwon(
        "#10530: sibling children carved from the same allowance could together exceed the limit without a refusal, so their replay was refused where the live run was not"
    )]
    fn children_that_do_not_fit_together_are_refused_when_applied() {
        let mut parent = SemanticBudget::uniform(100).unwrap();
        parent.admit(evidence_rows(10)).unwrap();
        let before = parent.replay_snapshot();
        let scope = parent.scope_snapshot();
        // Both children are carved from the same 90 remaining rows.
        let mut first = SemanticBudget::new_carved_child(parent.remaining(), &scope);
        let mut second = SemanticBudget::new_carved_child(parent.remaining(), &scope);
        first.admit(evidence_rows(60)).unwrap();
        first.release_admission(evidence_rows(50));
        // The second child needs 90 at its peak and keeps only 5, so its
        // retained rows fit and only its peak does not.
        second.admit(evidence_rows(90)).unwrap();
        second.release_admission(evidence_rows(85));
        let first = first.into_child_charge();
        let second = second.into_child_charge();

        parent
            .apply_child_charge(SemanticWork::default(), first)
            .unwrap();
        assert_eq!(parent.resident().evidence, 20);
        // 20 held + the second child's 90 is 110 on a limit of 100.
        assert!(
            parent
                .check_child_charge(SemanticWork::default(), &second)
                .is_err()
        );
        assert!(
            parent
                .apply_child_charge(SemanticWork::default(), second)
                .is_err()
        );
        assert!(parent.first_refusal().is_some());
        assert_eq!(
            parent.resident().evidence,
            20,
            "a refused child admits nothing"
        );
        // The live run recorded only what it really held, and its replay agrees.
        let replay = parent.replay_since(&before);
        assert_eq!(replay.resident_peak.evidence, 60);
        assert!(
            SemanticBudget::uniform(80)
                .unwrap()
                .replay_product_fits(replay)
        );
        assert!(
            !SemanticBudget::uniform(50)
                .unwrap()
                .replay_product_fits(replay)
        );
    }

    #[test]
    #[hardwon(
        "#10530: a child under an allowance of its own was recorded beside its parent, so a stored product depended on the balance it was replayed on"
    )]
    fn an_independent_child_does_not_add_its_peak_beside_its_parent() {
        let mut parent = SemanticBudget::uniform(100).unwrap();
        parent.admit(evidence_rows(10)).unwrap();
        let before = parent.replay_snapshot();
        // An allowance of its own that happens to be within what the parent has
        // left, as a class-set root's engine allotment can be.
        let scope = parent.scope_snapshot();
        let mut applied = SemanticBudget::new_child(evidence_rows(60), &scope);
        applied.admit(evidence_rows(60)).unwrap();
        applied.release_admission(evidence_rows(55));
        parent.admit(evidence_rows(40)).unwrap();
        // 50 held + the child's 60 is over the limit, and that is not its concern.
        parent
            .apply_child_charge(SemanticWork::default(), applied.into_child_charge())
            .unwrap();
        let mut absorbed = SemanticBudget::new_child(evidence_rows(60), &scope);
        absorbed.admit(evidence_rows(60)).unwrap();
        absorbed.release_admission(evidence_rows(60));
        parent.absorb_root_work(absorbed);
        let replay = parent.replay_since(&before);
        // Only the parent's own 40 and the child's 5 kept rows are on the record.
        assert_eq!(replay.resident_peak.evidence, 45);
    }

    #[test]
    #[hardwon(
        "#10530: a child's discarded staged work kept its peak from the observers but not from the peak the child reports to its parent"
    )]
    fn a_childs_retained_staged_work_keeps_its_peak_for_the_parent() {
        let mut parent = SemanticBudget::uniform(100).unwrap();
        let before = parent.replay_snapshot();
        let mut root = SemanticBudget::new_root_child(&parent);
        // The staging copy admits 60 rows and is discarded, as the heap oracle
        // does when its publication is interrupted.
        let mut staged = root.clone();
        staged.admit(evidence_rows(60)).unwrap();
        root.retain_performed_work(&staged);
        parent.absorb_root_work(root);
        let replay = parent.replay_since(&before);
        assert_eq!(replay.resident_peak.evidence, 60);
        let mut fresh = SemanticBudget::uniform(50).unwrap();
        let fresh_root = SemanticBudget::new_root_child(&fresh);
        let mut fresh_staged = fresh_root.clone();
        assert!(fresh_staged.admit(evidence_rows(60)).is_err());
        assert!(fresh.replay_product(replay).is_err());
    }

    #[test]
    #[hardwon("#8389: refused replay preflight recorded a refusal on the live budget")]
    fn replay_fit_does_not_record_a_refusal() {
        let mut budget = SemanticBudget::uniform(2).unwrap();
        let replay = SemanticBudgetReplay {
            retained: SemanticWork {
                events: 3,
                ..SemanticWork::default()
            },
            ..SemanticBudgetReplay::default()
        };
        assert!(!budget.replay_product_fits(replay));
        assert_eq!(budget.refusal_count(), 0);
        assert!(budget.first_refusal().is_none());
        assert!(budget.replay_product(replay).is_err());
        assert_eq!(budget.refusal_count(), 1);
        assert!(budget.first_refusal().is_some());
    }

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
    fn sibling_conversion_census_charges_are_independent_of_batch_order() {
        let parent = SemanticBudget::uniform(4096).expect("parent");
        let snapshot = parent.scope_snapshot();
        let artifact = StableDigest::sha256(b"conversion file census");
        let full = SemanticWork {
            source_bytes: 800,
            nested_entries: 200,
            ..SemanticWork::default()
        };
        let run = |budget: &mut SemanticBudget| {
            budget
                .charge_complete_artifact_hit(artifact, full)
                .expect("first touch");
            budget
                .charge_complete_artifact_hit(artifact, full)
                .expect("repeat touch");
            budget.used()
        };
        let alone = run(&mut SemanticBudget::new_child(parent.limits(), &snapshot));
        for order in [[0, 1], [1, 0]] {
            let mut siblings = [
                SemanticBudget::new_child(parent.limits(), &snapshot),
                SemanticBudget::new_child(parent.limits(), &snapshot),
            ];
            for index in order {
                assert_eq!(run(&mut siblings[index]), alone);
            }
        }
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
        assert!(source.charge_external_work(1, 2).is_ok());
        let before = source.snapshot();
        assert!(source.admit_materialization(&second));
        assert!(source.charge_external_work(1, 3).is_ok());
        let after = source.snapshot();
        let charge = source.charge_since(&before).expect("monotonic charge");

        let replay = SemanticExecutionBudget::new(4);
        assert!(replay.admit_materialization(&first));
        assert!(replay.charge_external_work(1, 2).is_ok());
        assert_eq!(replay.snapshot(), before);
        assert!(replay.replay_charge(&before, &charge));
        assert_eq!(replay.snapshot(), after);

        let already_replayed = replay.snapshot();
        assert!(!replay.replay_charge(&before, &charge));
        assert_eq!(replay.snapshot(), already_replayed);
    }

    #[test]
    #[hardwon(
        "#10530: Output units shared one resident ledger, so a unit was charged and refused for the rows earlier units left"
    )]
    fn a_unit_ledger_starts_empty_and_refuses_on_its_own() {
        let mut batch = SemanticBudget::uniform(100).unwrap();
        batch.admit(evidence_rows(70)).unwrap();
        let mut unit = batch.unit_ledger();
        assert_eq!(unit.resident(), SemanticWork::default());
        assert_eq!(unit.limits(), batch.limits());

        // 80 rows do not fit beside the batch's 70 but fit a unit's own ledger.
        unit.admit(evidence_rows(80)).unwrap();
        assert!(unit.admit(evidence_rows(30)).is_err());
        assert!(unit.refusal_count() > 0);
        assert_eq!(
            batch.refusal_count(),
            0,
            "a unit's refusal is not the batch's"
        );
        assert!(batch.first_refusal().is_none());

        let unit_cumulative = unit.used();
        let batch_cumulative = batch.used();
        batch.absorb_unit(unit);
        assert_eq!(
            batch.resident().evidence,
            70,
            "a unit's resident rows die with the unit"
        );
        assert_eq!(batch.refusal_count(), 0);
        assert!(batch.first_refusal().is_none());
        assert_eq!(
            batch.used(),
            batch_cumulative.saturating_add(unit_cumulative),
            "the unit's work is the batch's work"
        );
    }

    #[test]
    #[hardwon(
        "#10530: a unit's rows were counted on the batch's own measurement as well, so the batch product charged them twice"
    )]
    fn absorbing_a_unit_adds_its_work_but_not_its_rows_to_an_open_measurement() {
        let mut batch = SemanticBudget::uniform(100).unwrap();
        batch.admit(evidence_rows(10)).unwrap();
        let before = batch.replay_snapshot();
        let mut unit = batch.unit_ledger();
        unit.admit(evidence_rows(80)).unwrap();
        unit.release_admission(evidence_rows(75));
        // The unit is measured on its own ledger.
        assert_eq!(unit.resident().evidence, 5);
        batch.absorb_unit(unit);
        // The batch's measurement sees the unit's work, which is performed, but
        // neither the 5 rows it kept nor the 80 it held: the unit was not
        // running beside the batch's rows.
        let replay = batch.replay_since(&before);
        assert_eq!(replay.cumulative.evidence, 80);
        assert_eq!(replay.retained.evidence, 0);
        assert_eq!(replay.resident_peak.evidence, 0);
    }

    #[test]
    #[hardwon(
        "#10530: whether a stored unit replayed depended on the rows earlier units held, so warm runs differed from cold ones"
    )]
    fn a_unit_replay_fits_by_its_own_product_not_by_the_batch_balance() {
        let mut measured = SemanticBudget::uniform(200).unwrap();
        let before = measured.replay_snapshot();
        measured.admit(evidence_rows(80)).unwrap();
        measured.release_admission(evidence_rows(60));
        let replay = measured.replay_since(&before);
        assert_eq!(replay.retained.evidence, 20);
        assert_eq!(replay.resident_peak.evidence, 80);

        // A batch that already holds 60 rows cannot take 80 more under 100, yet a
        // fresh unit would run on an empty ledger and fit, so the replay does.
        let mut batch = SemanticBudget::uniform(100).unwrap();
        batch.admit(evidence_rows(60)).unwrap();
        assert!(!batch.replay_product_fits(replay));
        assert!(batch.replay_unit_fits(replay));
        let cumulative = batch.used();
        batch.replay_unit(replay).unwrap();
        assert_eq!(
            batch.resident().evidence,
            60,
            "a replayed unit leaves no resident rows"
        );
        assert_eq!(
            batch.used().evidence,
            cumulative.evidence + replay.cumulative.evidence
        );

        // The limit still binds: a unit whose own peak exceeds it is refused,
        // and nothing changes.
        let mut small = SemanticBudget::uniform(50).unwrap();
        let used = small.used();
        assert!(!small.replay_unit_fits(replay));
        assert!(small.replay_unit(replay).is_err());
        assert_eq!(small.used(), used);
        assert_eq!(small.resident(), SemanticWork::default());
        assert_eq!(small.refusal_count(), 0, "a refused replay is the unit's");
    }

    #[test]
    fn a_unit_ledger_shares_paid_artifacts_with_the_batch() {
        let already_paid = StableDigest::sha256(b"paid before the unit");
        let paid_by_unit = StableDigest::sha256(b"paid by the unit");
        let full_work = SemanticWork {
            procedures: 2,
            blocks: 3,
            ..SemanticWork::default()
        };
        let mut batch = SemanticBudget::uniform(64).unwrap();
        batch.record_charged_artifact(already_paid);
        let mut unit = batch.unit_ledger();
        assert!(unit.has_charged_artifact(already_paid));
        unit.charge_complete_artifact_hit(paid_by_unit, full_work)
            .unwrap();
        assert!(unit.has_charged_artifact(paid_by_unit));
        assert!(!batch.has_charged_artifact(paid_by_unit));
        batch.absorb_unit(unit);
        assert!(
            batch.has_charged_artifact(paid_by_unit),
            "a later unit pays the repeat price"
        );
        let later = batch.unit_ledger();
        assert!(later.has_charged_artifact(paid_by_unit));
    }
}

/// Portable accounting for a cached product. Each object remains SQL-readable
/// when persisted in a policy unit's JSONB product.
///
/// The work counters (`cumulative`, `performed`, `root_work_peak`) are
/// execution-dependent telemetry (#10893). A memo hit charges no work, so a
/// product filled after its siblings warmed shared memos records less work than
/// the same product filled cold. They cannot change an answer: `charge_work`
/// never refuses, and `replay_product` admits on `resident_peak` and `retained`
/// only. Byte-equality tests of persisted products normalize these three
/// counters.
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
    /// The most resident rows the computation held above where it started, at
    /// any point and scratch included. A replay must fit this, not only the
    /// retained census, or it would pass where a fresh run is refused. Absent
    /// in a descriptor built without a measurement, which then checks only
    /// `retained`.
    #[serde(default)]
    pub resident_peak: SemanticWork,
}

/// In-memory admission receipt; no work telemetry or persisted fields.
#[derive(Debug, Clone)]
pub struct SemanticMemoAdmission {
    acquired_owners: HashSet<usize>,
    acquired_artifacts: HashSet<(StableDigest, usize)>,
    owners: ResidentOwners,
    artifacts: ResidentArtifacts,
    transient_peak: SemanticWork,
}

impl SemanticMemoAdmission {
    /// Payload capacity census for the descriptor's owned hash tables.
    pub fn retained_bytes(&self) -> usize {
        let identities = self
            .owners
            .values()
            .filter_map(|(owner, _)| owner.source.as_ref())
            .map(|source| source.procedure.0.path().as_str().len())
            .chain(
                self.artifacts
                    .values()
                    .map(|(artifact, _)| artifact.key.path().as_str().len()),
            )
            .fold(0usize, usize::saturating_add);
        identities
            .saturating_add(
                self.acquired_owners.capacity() * (std::mem::size_of::<usize>() + 1)
                    + self.acquired_artifacts.capacity()
                        * (std::mem::size_of::<(StableDigest, usize)>() + 1),
            )
            .saturating_add(self.owners.capacity().saturating_mul(
                std::mem::size_of::<(usize, (ResidentOwnerReceipt, SemanticWork))>() + 1,
            ))
            .saturating_add(self.artifacts.capacity().saturating_mul(
                std::mem::size_of::<((StableDigest, usize), (ResidentArtifact, SemanticWork))>()
                    + 1,
            ))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SemanticMemoAdmissionMiss {
    MissingDependency,
    Residency(SemanticBudgetExceeded),
}

#[derive(Debug, Default)]
struct MemoDependencyTouches {
    owners: HashSet<usize>,
    artifacts: HashSet<(StableDigest, usize)>,
}

/// Query-local measurement interval. Dropping it retires its observer even
/// when a computation returns early; staging copies preserve value semantics.
#[derive(Debug)]
pub struct SemanticBudgetReplaySnapshot {
    owner: Arc<Mutex<MemoDependencyTouches>>,
    cumulative: SemanticWork,
    performed: SemanticWork,
    artifacts: Arc<ResidentArtifacts>,
    owners: Arc<ResidentOwners>,
    raw_resident: SemanticWork,
}

#[derive(Debug, Clone)]
struct ReplayObserver {
    owner: Weak<Mutex<MemoDependencyTouches>>,
    base: SemanticWork,
    peak: SemanticWork,
    resident: ResidentInterval,
}

/// The most rows a computation held at once above what it inherited, scratch
/// included. `base` is the balance the interval began with that is still held:
/// when an inherited holder expires mid-interval the base drops by its census,
/// so the expiry is not mistaken for room the computation can count on, and a
/// later admission is measured against what is really still there.
#[derive(Debug, Clone)]
struct ResidentInterval {
    base: SemanticWork,
    peak: SemanticWork,
    /// Whether the interval ran beside its parent's holders (a root child) or
    /// under an allowance of its own.
    coexists: bool,
    inherited_owners: Arc<ResidentOwners>,
    inherited_artifacts: Arc<ResidentArtifacts>,
}

impl ResidentInterval {
    fn independent() -> Self {
        Self {
            base: SemanticWork::default(),
            peak: SemanticWork::default(),
            coexists: false,
            inherited_owners: Arc::default(),
            inherited_artifacts: Arc::default(),
        }
    }

    fn beginning(
        used: SemanticWork,
        owners: &Arc<ResidentOwners>,
        artifacts: &Arc<ResidentArtifacts>,
        coexists: bool,
    ) -> Self {
        Self {
            base: used,
            peak: SemanticWork::default(),
            coexists,
            inherited_owners: Arc::clone(owners),
            inherited_artifacts: Arc::clone(artifacts),
        }
    }

    fn observe(&mut self, used: SemanticWork) {
        self.peak = self.peak.component_max(used.saturating_sub(self.base));
    }

    fn owner_expired(&mut self, key: &usize, census: SemanticWork) {
        if self.inherited_owners.contains_key(key) {
            self.base = self.base.saturating_sub(census);
        }
    }

    fn artifact_expired(&mut self, key: &(StableDigest, usize), census: SemanticWork) {
        if self.inherited_artifacts.contains_key(key) {
            self.base = self.base.saturating_sub(census);
        }
    }
}

type ResidentOwner = dyn std::any::Any + Send + Sync;

type ResidentOwners = HashMap<usize, (ResidentOwnerReceipt, SemanticWork)>;

#[derive(Debug, Clone)]
struct ResidentOwnerReceipt {
    allocation: Weak<ResidentOwner>,
    source: Option<MemoSourceDependency>,
}

impl ResidentOwnerReceipt {
    fn strong_count(&self) -> usize {
        self.allocation.strong_count()
    }
    fn upgrade(&self) -> Option<Arc<ResidentOwner>> {
        self.allocation.upgrade()
    }
}

/// Exact source address; the artifact key includes the blob and adapter identity.
#[derive(Debug, Clone)]
pub struct MemoSourceDependency {
    pub procedure: (
        crate::analyzer::semantic::SemanticArtifactKey,
        crate::analyzer::semantic::ProcedureId,
    ),
    pub acquisition: MemoSourceAcquisition,
}

#[derive(Debug, Clone, Copy)]
pub enum MemoSourceAcquisition {
    Admit,
    Hold,
    Readmit,
}

/// A real allocation retained by the current region, never a residency marker.
#[derive(Clone)]
pub struct MemoDependencyGuard {
    // All staging clones share release, so no discarded probe can prolong a
    // provider's source lifetime after another clone reconciles its ledger.
    allocation: Arc<Mutex<Option<Arc<ResidentOwner>>>>,
    pub census: SemanticWork,
    provider_lifetime: Option<Weak<()>>,
}

impl MemoDependencyGuard {
    /// Source guards use the active provider's lifetime. Region-owned
    /// allocations may omit it; all staging clones share allocation release.
    pub fn new<T: Send + Sync + 'static>(
        allocation: Arc<T>,
        census: SemanticWork,
        provider_lifetime: Option<Weak<()>>,
    ) -> Self {
        Self {
            allocation: Arc::new(Mutex::new(Some(allocation))),
            census,
            provider_lifetime,
        }
    }

    fn allocation(&self) -> Option<Arc<ResidentOwner>> {
        self.allocation
            .lock()
            .expect("memo dependency allocation poisoned")
            .clone()
    }

    fn retain_while_provider_lives(&self) -> bool {
        if self
            .provider_lifetime
            .as_ref()
            .is_none_or(|owner| owner.strong_count() > 0)
        {
            return true;
        }
        self.allocation
            .lock()
            .expect("memo dependency allocation poisoned")
            .take();
        false
    }
}

impl fmt::Debug for MemoDependencyGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoDependencyGuard")
            .field("census", &self.census)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum MemoDependencyRefusal {
    MissingDependency,
    Provider(SemanticProviderError),
}

pub trait MemoDependencyReacquirer {
    fn hold_source(
        &self,
        key: &MemoSourceDependency,
        max_bytes: usize,
    ) -> Result<MemoDependencyGuard, MemoDependencyRefusal>;

    fn readmit_source(
        &self,
        key: &MemoSourceDependency,
        max_bytes: usize,
    ) -> Result<MemoDependencyGuard, MemoDependencyRefusal> {
        self.hold_source(key, max_bytes)
    }

    fn admit_source(
        &self,
        _key: &MemoSourceDependency,
        _max_bytes: usize,
    ) -> Result<MemoDependencyGuard, MemoDependencyRefusal> {
        Err(MemoDependencyRefusal::MissingDependency)
    }

    // A validity key alone does not select stored-publication provenance.
    // Providers without an exact cache acquisition path must retain the miss.
    fn artifact(
        &self,
        _key: &crate::analyzer::semantic::SemanticArtifactKey,
        _capabilities: &SemanticCapabilities,
    ) -> Result<Arc<SemanticArtifact>, MemoDependencyRefusal> {
        Err(MemoDependencyRefusal::MissingDependency)
    }
}

fn weak_resident_owner<T: Send + Sync + 'static>(owner: &Arc<T>) -> ResidentOwnerReceipt {
    let erased: Arc<ResidentOwner> = Arc::clone(owner) as Arc<ResidentOwner>;
    ResidentOwnerReceipt {
        allocation: Arc::downgrade(&erased),
        source: None,
    }
}

#[derive(Debug, Clone)]
struct ResidentArtifact {
    allocation: Weak<SemanticArtifact>,
    cache_pins: Arc<crate::analyzer::semantic::ir::ArtifactCachePins>,
    key: crate::analyzer::semantic::SemanticArtifactKey,
    capabilities: SemanticCapabilities,
}

impl ResidentArtifact {
    fn new(artifact: &Arc<SemanticArtifact>) -> Self {
        Self {
            allocation: Arc::downgrade(artifact),
            key: artifact.key().clone(),
            capabilities: artifact.capabilities().clone(),
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
#[cfg(test)]
fn refund_expired_residents<Key: Eq + std::hash::Hash, Owner>(
    entries: &mut HashMap<Key, (Owner, SemanticWork)>,
    used: &mut SemanticWork,
    is_live: impl FnMut(&Owner) -> bool,
) -> SemanticWork {
    refund_expired_residents_noting(entries, used, is_live, |_, _| {})
}

/// [`refund_expired_residents`] that also names each admission it removed.
fn refund_expired_residents_noting<Key: Eq + std::hash::Hash, Owner>(
    entries: &mut HashMap<Key, (Owner, SemanticWork)>,
    used: &mut SemanticWork,
    mut is_live: impl FnMut(&Owner) -> bool,
    mut expired: impl FnMut(&Key, &SemanticWork),
) -> SemanticWork {
    let mut refunded = SemanticWork::default();
    entries.retain(|key, (owner, work)| {
        if is_live(owner) {
            true
        } else {
            expired(key, work);
            *used = used.saturating_sub(*work);
            refunded = refunded.saturating_add(*work);
            false
        }
    });
    refunded
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
