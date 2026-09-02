//! Evaluation units: the smallest piece of policy work a run reuses.
//!
//! A unit is one policy evaluated over one partition of the workspace -- for
//! the match family, one seed file -- together with the exact set of inputs
//! that execution read (`.agents/plans/impact-sliced-diff-base.md`,
//! Milestone 2). Two runs over two workspaces may share a unit's product when
//! every one of those reads still denotes the same content, which is what
//! [`verify_read_set`] decides.
//!
//! Nothing here is per policy or per family beyond the key's own fields. The
//! same key, the same verification and the same store serve every policy: a
//! family differs only in how its execution is partitioned, which is a
//! property of the plan's structure that the RQL crate computes.
//!
//! [`verify_read_set`]: brokk_bifrost_analysis::analyzer::verify_read_set

use serde::Serialize;
use std::cell::RefCell;
use std::collections::HashMap;

use brokk_bifrost_analysis::analyzer::invalidation::{ArtifactVerdictLog, BudgetMode};
use brokk_bifrost_analysis::analyzer::read_ledger::read_set_digest;
use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
use brokk_bifrost_analysis::analyzer::store::policy_units::{
    PolicyUnitPartitionRow, PolicyUnitRow, PolicyUnitRowKey,
};
use brokk_bifrost_analysis::analyzer::{
    ChangedFacts, HeadInputs, Language, Oid, ReadKey, ReadSetDigest, WorkspaceAnalyzer,
    analysis_epoch_digest,
};
use brokk_bifrost_rql::structural::UnitExecutionResult;
use std::sync::Arc;

use super::definition::{PolicyAnalysisType, PolicyId};
use super::identity::PolicySemanticHash;
use super::resolved::LoadedPolicy;

/// The digest a unit key carries when no semantic models were active.
///
/// A fixed value rather than an absent field: "no models were active" is an
/// input like any other, and a unit produced without models must not match one
/// produced with them.
const NO_ACTIVE_MODELS: &str = "bifrost-policy-unit:no-active-models:v1";

/// Which partition of the workspace one unit covers.
///
/// A `Seed` unit is keyed by the file its seed enumeration walked and the blob
/// that path resolved to, because the same path holding different bytes is a
/// different unit even when nothing else moved. `Whole` is the whole policy,
/// which is what a widened evaluation publishes.
///
/// The assert-file and solver-root partitions the plan describes arrive with
/// the assertion and typestate families in later milestones.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UnitPartition {
    Seed {
        language: Language,
        rel_path: Box<str>,
        blob: Oid,
    },
    Whole,
}

impl UnitPartition {
    /// The stable label of this partition kind.
    pub const fn stable_label(&self) -> &'static str {
        match self {
            Self::Seed { .. } => "seed",
            Self::Whole => "whole",
        }
    }
}

/// Everything that decides whether two evaluations are the same question.
///
/// The policy's semantic hash and the family fix what is being asked, the
/// partition fixes over which content, and the three digests fix the engine
/// that would answer: the analyzer configuration folded into every content
/// identity, the active semantic-model set, and the analysis epoch every
/// persisted fact was derived under. A run that differs in any of them is
/// asking a different question and gets a different key rather than a wrong
/// answer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyUnitKey {
    pub policy: PolicySemanticHash,
    pub family: PolicyAnalysisType,
    pub partition: UnitPartition,
    pub configuration: StableDigest,
    pub models: StableDigest,
    pub epoch: StableDigest,
}

/// What one unit produced.
///
/// Rendered rows are the only product this milestone publishes: the match
/// family's product is the projection of its rendered rows, their evidence and
/// the execution's counters, which is exactly what the merge and the policy
/// adapter consume. Findings-shaped products arrive with the assertion and
/// typestate families.
#[derive(Debug, Clone)]
pub enum PolicyUnitProduct {
    Rows(UnitExecutionResult),
}

impl PolicyUnitProduct {
    /// The rendered rows this product carries.
    pub const fn rows(&self) -> &UnitExecutionResult {
        match self {
            Self::Rows(rows) => rows,
        }
    }

    /// The stable label of this product kind.
    pub const fn stable_label(&self) -> &'static str {
        match self {
            Self::Rows(_) => "rows",
        }
    }
}

/// One published unit: what it answered, and every input that answer depends
/// on.
///
/// `reads` is the ledger's own key set and `read_digest` is derived from it at
/// construction, so the two can never disagree about which reads a unit's
/// verification must cover.
#[derive(Debug, Clone)]
pub struct PolicyUnit {
    key: PolicyUnitKey,
    product: PolicyUnitProduct,
    reads: Vec<ReadKey>,
    read_digest: ReadSetDigest,
    budget_mode: BudgetMode,
}

impl PolicyUnit {
    /// Publish one unit's product under the reads that produced it.
    pub fn new(
        key: PolicyUnitKey,
        product: PolicyUnitProduct,
        reads: Vec<ReadKey>,
        budget_mode: BudgetMode,
    ) -> Self {
        let read_digest = read_set_digest(&reads);
        Self {
            key,
            product,
            reads,
            read_digest,
            budget_mode,
        }
    }

    pub const fn key(&self) -> &PolicyUnitKey {
        &self.key
    }

    pub const fn product(&self) -> &PolicyUnitProduct {
        &self.product
    }

    pub fn reads(&self) -> &[ReadKey] {
        &self.reads
    }

    pub const fn read_digest(&self) -> ReadSetDigest {
        self.read_digest
    }

    pub const fn budget_mode(&self) -> BudgetMode {
        self.budget_mode
    }
}

/// Where published units are looked up and published.
///
/// One evaluation batch owns one store. Milestone 3 adds the persisted
/// implementation behind the same two operations; nothing above this trait
/// knows which one it is holding.
pub trait PolicyUnitStore {
    /// Load every unit `keys` names, before the lookups start.
    ///
    /// One policy asks about every seed file of the workspace, so a store that
    /// answers each lookup on its own would pay a round trip per file before
    /// reading a single fact. An in-memory store already holds everything and
    /// does nothing here.
    ///
    /// `Err` is a store that could not answer -- a row that would not load,
    /// a database that would not read -- which is not the same as "nothing was
    /// published under this key". A policy whose store failed widens rather
    /// than treating a failure as an absence, because an absence is a claim
    /// about what was published and a failure is a claim about nothing.
    fn prefetch(&mut self, _keys: &[PolicyUnitKey]) -> Result<(), PolicyUnitStoreError> {
        Ok(())
    }

    fn lookup(&self, key: &PolicyUnitKey) -> Option<&PolicyUnit>;
    fn publish(&mut self, unit: PolicyUnit);
}

/// A store that could not answer.
///
/// Carried as prose because every one of these is reported and none is
/// recovered from: the policy widens, evaluates in full, and says the product
/// could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyUnitStoreError(String);

impl PolicyUnitStoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for PolicyUnitStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The units one batch published, for the lifetime of that batch.
#[derive(Debug, Default)]
pub struct InMemoryPolicyUnitStore {
    units: HashMap<PolicyUnitKey, PolicyUnit>,
}

impl InMemoryPolicyUnitStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many units this store holds.
    pub fn len(&self) -> usize {
        self.units.len()
    }

    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }
}

impl PolicyUnitStore for InMemoryPolicyUnitStore {
    fn lookup(&self, key: &PolicyUnitKey) -> Option<&PolicyUnit> {
        self.units.get(key)
    }

    fn publish(&mut self, unit: PolicyUnit) {
        self.units.insert(unit.key.clone(), unit);
    }
}

/// The units of one batch, backed by the repository's analyzer cache.
///
/// Everything a run derives from content lives in that cache, and a unit is
/// derived from content: the file it covers, the files and lookups it read,
/// the policy text, the configuration, the models, the epoch. Publishing units
/// there is what makes the second run of `--diff-base` on the same branch do
/// almost no work, and it is why this exists at all -- an in-memory store
/// serves one process and forgets.
///
/// Reads are prefetched per policy in one query and publications are buffered
/// until the caller flushes them, because a unit publication is one row plus
/// its read set and one transaction per policy is what keeps a widened policy
/// from leaving a half-published unit set behind.
pub struct PersistedPolicyUnitStore {
    store: Arc<AnalyzerStore>,
    loaded: HashMap<PolicyUnitKey, PolicyUnit>,
    pending: Vec<PolicyUnit>,
    published: usize,
}

impl PersistedPolicyUnitStore {
    pub fn new(store: Arc<AnalyzerStore>) -> Self {
        Self {
            store,
            loaded: HashMap::new(),
            pending: Vec::new(),
            published: 0,
        }
    }

    /// Write every buffered publication, in one transaction.
    ///
    /// The caller decides when: a cancelled or deadline-terminated run flushes
    /// nothing, because its units describe work that stopped early and nothing
    /// downstream can tell that from work that finished.
    pub fn flush(&mut self) -> Result<usize, PolicyUnitStoreError> {
        if self.pending.is_empty() {
            return Ok(0);
        }
        let rows = self
            .pending
            .drain(..)
            .map(|unit| unit_row(&unit))
            .collect::<Result<Vec<_>, _>>()?;
        let written = self
            .store
            .publish_policy_units(rows)
            .map_err(|error| PolicyUnitStoreError::new(format!("{error}")))?;
        self.published += written;
        Ok(written)
    }

    /// How many units this store has written.
    pub const fn published(&self) -> usize {
        self.published
    }

    /// The store these units are published to and read from.
    pub const fn store(&self) -> &Arc<AnalyzerStore> {
        &self.store
    }
}

impl PolicyUnitStore for PersistedPolicyUnitStore {
    fn prefetch(&mut self, keys: &[PolicyUnitKey]) -> Result<(), PolicyUnitStoreError> {
        let wanted = keys
            .iter()
            .filter(|key| !self.loaded.contains_key(key))
            .cloned()
            .collect::<Vec<_>>();
        if wanted.is_empty() {
            return Ok(());
        }
        let rows = wanted.iter().map(row_key).collect::<Vec<_>>();
        let answers = self
            .store
            .policy_units_for_keys(&rows)
            .map_err(|error| PolicyUnitStoreError::new(format!("{error}")))?;
        for (key, answer) in wanted.into_iter().zip(answers) {
            let Some(row) = answer else {
                continue;
            };
            self.loaded.insert(key.clone(), unit_of_row(key, row)?);
        }
        Ok(())
    }

    fn lookup(&self, key: &PolicyUnitKey) -> Option<&PolicyUnit> {
        self.loaded.get(key)
    }

    fn publish(&mut self, unit: PolicyUnit) {
        self.loaded.insert(unit.key.clone(), unit.clone());
        self.pending.push(unit);
    }
}

/// The store's spelling of one unit key.
///
/// Digests become lowercase hex and the family becomes its stable label,
/// because a persisted key is compared by SQL and must be one shape per value.
pub fn row_key(key: &PolicyUnitKey) -> PolicyUnitRowKey {
    PolicyUnitRowKey {
        policy_semantic_hash: StableDigest::from_array(*key.policy.as_bytes()).to_string(),
        family: key.family.label().to_string(),
        partition: match &key.partition {
            UnitPartition::Seed {
                language,
                rel_path,
                blob,
            } => PolicyUnitPartitionRow::Seed {
                rel_path: rel_path.to_string(),
                blob: *blob,
                language: *language,
            },
            UnitPartition::Whole => PolicyUnitPartitionRow::Whole,
        },
        configuration_fingerprint: key.configuration.to_string(),
        active_model_set_hash: key.models.to_string(),
        engine_epoch: key.epoch.to_string(),
    }
}

/// One unit as the row the store writes.
fn unit_row(unit: &PolicyUnit) -> Result<PolicyUnitRow, PolicyUnitStoreError> {
    assert_eq!(
        unit.budget_mode,
        BudgetMode::Exhaustive,
        "only an exhaustive unit is publishable, and the schema says so too"
    );
    let product = serde_json::to_string(unit.product.rows()).map_err(|error| {
        PolicyUnitStoreError::new(format!("a unit product could not be serialized: {error}"))
    })?;
    Ok(PolicyUnitRow {
        key: row_key(&unit.key),
        product_kind: unit.product.stable_label().to_string(),
        product,
        read_set_digest: *unit.read_digest.digest().as_bytes(),
        reads: unit.reads.clone(),
    })
}

/// The rendered rows one stored row carries.
///
/// This is all a replay of a completed evaluation needs: the products are that
/// evaluation's own answers, merged in the order it merged them. Reusing a
/// unit against a *different* workspace needs its read set too, which is what
/// [`unit_of_row`] rebuilds.
pub fn product_of_row(row: &PolicyUnitRow) -> Result<UnitExecutionResult, PolicyUnitStoreError> {
    if row.product_kind != "rows" {
        return Err(PolicyUnitStoreError::new(format!(
            "a published unit carries an unknown product kind `{}`",
            row.product_kind
        )));
    }
    serde_json::from_str(&row.product).map_err(|error| {
        PolicyUnitStoreError::new(format!(
            "a published unit product could not be read: {error}"
        ))
    })
}

/// One stored row as the unit an evaluation may reuse.
///
/// Every failure here is a load error rather than a malformed unit: a product
/// that will not parse, a read set whose digest does not match the reads that
/// came back with it. The caller widens and says so; nothing partially loaded
/// ever reaches a merge.
pub fn unit_of_row(
    key: PolicyUnitKey,
    row: PolicyUnitRow,
) -> Result<PolicyUnit, PolicyUnitStoreError> {
    let rows = product_of_row(&row)?;
    let unit = PolicyUnit::new(
        key,
        PolicyUnitProduct::Rows(rows),
        row.reads,
        BudgetMode::Exhaustive,
    );
    if unit.read_digest.digest().as_bytes() != &row.read_set_digest {
        return Err(PolicyUnitStoreError::new(
            "a published unit's read set does not digest to the identity it was published under"
                .to_string(),
        ));
    }
    Ok(unit)
}

/// The three non-source inputs every unit key and every verification carries.
///
/// Read once per evaluated workspace, because all three are properties of the
/// analyzer and the run's model activation rather than of any one policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceUnitInputs {
    configuration: StableDigest,
    models: StableDigest,
    epoch: StableDigest,
}

impl WorkspaceUnitInputs {
    /// The inputs `workspace` evaluates under, with `models` as the activation
    /// the run pinned.
    ///
    /// The configuration fingerprint is the one the analyzer folds into every
    /// content identity, spelled the same way (#2529): the `Debug` rendering
    /// of the configuration, with a workspace that carries none behaving as
    /// the defaults describe.
    pub fn of(workspace: &WorkspaceAnalyzer, models: Option<&ActiveSemanticModelSnapshot>) -> Self {
        let configuration = workspace.config().cloned().unwrap_or_default();
        Self {
            configuration: StableDigest::sha256(format!("{configuration:?}")),
            models: models.map_or_else(
                || StableDigest::sha256(NO_ACTIVE_MODELS),
                |models| StableDigest::sha256(models.active_models().active_model_set_hash()),
            ),
            epoch: analysis_epoch_digest(),
        }
    }

    pub const fn configuration(&self) -> StableDigest {
        self.configuration
    }

    pub const fn models(&self) -> StableDigest {
        self.models
    }

    pub const fn epoch(&self) -> StableDigest {
        self.epoch
    }

    /// The unit key one policy's `partition` is published under.
    pub fn unit_key(&self, policy: &LoadedPolicy, partition: UnitPartition) -> PolicyUnitKey {
        PolicyUnitKey {
            policy: policy.semantic_hash(),
            family: policy.definition().analysis.analysis_type(),
            partition,
            configuration: self.configuration,
            models: self.models,
            epoch: self.epoch,
        }
    }

    /// What verification compares one policy's recorded reads against.
    pub fn head_inputs(&self, policy: &LoadedPolicy) -> HeadInputs {
        HeadInputs {
            models: self.models,
            policy_semantic_hash: StableDigest::from_array(*policy.semantic_hash().as_bytes()),
            policy_source: StableDigest::from_array(*policy.source_hash().as_bytes()),
            configuration: self.configuration,
            epoch: self.epoch,
        }
    }
}

/// Everything one evaluation needs to reuse units instead of recomputing them.
///
/// Its presence is the whole condition: an evaluation that holds one has a
/// store to look units up in and a workspace to verify them against, and one
/// that does not executes exactly as it always has. There is no mode to set.
///
/// The base half of a `--diff-base` run holds one too. Its store starts empty,
/// so every unit is computed and published; its changed facts are the base
/// against itself, which is the honest statement that nothing moved between
/// the workspace its units were published against and the workspace they were
/// published from.
pub struct PolicyIncrementalContext<'a> {
    store: &'a RefCell<dyn PolicyUnitStore>,
    workspace: &'a WorkspaceAnalyzer,
    changed: &'a ChangedFacts,
    inputs: WorkspaceUnitInputs,
    base: IncrementalBaseState,
    verdicts: ArtifactVerdictLog,
    runs: RefCell<Vec<PolicyIncrementalRun>>,
    units: RefCell<Vec<(PolicyId, Vec<PolicyUnitKey>)>>,
}

impl<'a> PolicyIncrementalContext<'a> {
    pub fn new(
        store: &'a RefCell<dyn PolicyUnitStore>,
        workspace: &'a WorkspaceAnalyzer,
        changed: &'a ChangedFacts,
        inputs: WorkspaceUnitInputs,
        base: IncrementalBaseState,
    ) -> Self {
        Self {
            store,
            workspace,
            changed,
            inputs,
            base,
            verdicts: ArtifactVerdictLog::default(),
            runs: RefCell::new(Vec::new()),
            units: RefCell::new(Vec::new()),
        }
    }

    pub const fn store(&self) -> &'a RefCell<dyn PolicyUnitStore> {
        self.store
    }

    pub const fn workspace(&self) -> &'a WorkspaceAnalyzer {
        self.workspace
    }

    pub const fn changed(&self) -> &'a ChangedFacts {
        self.changed
    }

    pub const fn inputs(&self) -> WorkspaceUnitInputs {
        self.inputs
    }

    /// The reuse decisions this evaluation reached, in the typed vocabulary
    /// #2449 established.
    pub const fn verdicts(&self) -> &ArtifactVerdictLog {
        &self.verdicts
    }

    /// Record what one policy's evaluation did with its units.
    pub fn record_run(&self, run: PolicyIncrementalRun) {
        self.runs.borrow_mut().push(run);
    }

    /// Record the units one policy's product was merged from, in merge order.
    ///
    /// Recorded only when every one of them is published, because this is what
    /// a persisted evaluation replays: a partial list would replay a partial
    /// answer. The order is the seed order the run walked, which is the only
    /// order in which merging those units reproduces the vector a whole
    /// execution would have built.
    pub fn record_units(&self, policy_id: PolicyId, keys: Vec<PolicyUnitKey>) {
        self.units.borrow_mut().push((policy_id, keys));
    }

    /// The units each policy's product was merged from, in policy order.
    pub fn published_units(&self) -> Vec<(PolicyId, Vec<PolicyUnitKey>)> {
        self.units.borrow().clone()
    }

    /// The review of everything this evaluation reused, in policy order.
    pub fn review(&self) -> PolicyIncrementalReview {
        PolicyIncrementalReview {
            base: self.base,
            policies: self.runs.borrow().clone(),
        }
    }
}

/// How this run obtained the base revision's units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncrementalBaseState {
    /// The base revision was exported, built and evaluated by this run.
    Evaluated,
    /// An earlier run had already evaluated this exact base, so its units and
    /// its findings were replayed and the base was neither exported nor built.
    Reused,
}

impl IncrementalBaseState {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::Evaluated => "evaluated",
            Self::Reused => "reused",
        }
    }
}

/// Whether one policy was evaluated unit by unit or in full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncrementalMode {
    Sliced,
    Full,
}

impl IncrementalMode {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::Sliced => "sliced",
            Self::Full => "full",
        }
    }
}

/// Why one policy was evaluated in full instead of unit by unit.
///
/// Widening is always reported. A run that could not bound a unit exactly, or
/// could not merge its units into the bytes a whole evaluation would have
/// produced, evaluates the whole policy and says which of these was true --
/// never silently omits anything, and never claims a reuse it cannot prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WidenReason {
    /// The family has no per-partition product at all (taint and flow today,
    /// and every family this milestone has not sliced yet).
    WholePolicyFamily,
    /// The plan's rows are not the concatenation of its per-seed rows.
    PlanCrossesSeeds,
    /// A unit performed reads the ledger could not name.
    UnitUnbounded,
    /// A unit's own execution was truncated or ran under a bounded budget.
    UnitNotExhaustive,
    /// A unit reported a query diagnostic, which is not additive across
    /// partitions.
    UnitDiagnostics,
    /// The merged product reached a cap the whole execution enforces globally,
    /// so the whole execution might have truncated somewhere in its own order.
    MergedLimitReached,
    /// Verifying the recorded reads would have cost more than the evaluation
    /// it is trying to avoid.
    VerificationBudgetExceeded,
    /// The evidence a verification needs does not exist: an incomplete
    /// changed-fact set, or a lookup the head cannot answer.
    ReverseDependencyEvidenceMissing,
    /// A published product could not be loaded. Nothing mints this until
    /// Milestone 3 persists products outside the process.
    ProductLoadFailed,
}

impl WidenReason {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::WholePolicyFamily => "whole_policy_family",
            Self::PlanCrossesSeeds => "plan_crosses_seeds",
            Self::UnitUnbounded => "unit_unbounded",
            Self::UnitNotExhaustive => "unit_not_exhaustive",
            Self::UnitDiagnostics => "unit_diagnostics",
            Self::MergedLimitReached => "merged_limit_reached",
            Self::VerificationBudgetExceeded => "verification_budget_exceeded",
            Self::ReverseDependencyEvidenceMissing => "reverse_dependency_evidence_missing",
            Self::ProductLoadFailed => "product_load_failed",
        }
    }
}

/// What one policy's evaluation did with its units.
///
/// The counts describe the sliced attempt even when it widened, because "this
/// policy enumerated forty units and recomputed one before the merge reached a
/// cap" is the diagnosis a reader needs, and a widened policy that reported
/// zeros would hide it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyIncrementalRun {
    pub policy_id: PolicyId,
    pub mode: IncrementalMode,
    pub units_total: u64,
    pub units_reused: u64,
    pub units_recomputed: u64,
    pub units_unbounded: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub widen_reason: Option<WidenReason>,
}

impl PolicyIncrementalRun {
    /// One policy whose family has no per-partition product in this milestone.
    ///
    /// Taint and flow are whole by design, and the assertion and typestate
    /// families are sliced in later milestones. All of them are evaluated
    /// exactly as a run with no units evaluates them, and say so.
    pub const fn whole_family(policy_id: PolicyId) -> Self {
        Self {
            policy_id,
            mode: IncrementalMode::Full,
            units_total: 0,
            units_reused: 0,
            units_recomputed: 0,
            units_unbounded: 0,
            widen_reason: Some(WidenReason::WholePolicyFamily),
        }
    }
}

/// What one batch reused, per policy.
///
/// Carried beside the report rather than inside it: Milestone 3 adds the
/// report section, its retained-size accounting and its renderer. Until then
/// this is the structural evidence a test reads to prove that a byte-identical
/// report was produced by doing less work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyIncrementalReview {
    base: IncrementalBaseState,
    policies: Vec<PolicyIncrementalRun>,
}

/// The three review enums serialize as their stable labels, which are stated
/// once beside the variants rather than a second time in a serde attribute:
/// the label is the wire contract, and a rename that changed one and not the
/// other would ship two spellings of the same state.
impl Serialize for IncrementalBaseState {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.stable_label())
    }
}

impl Serialize for IncrementalMode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.stable_label())
    }
}

impl Serialize for WidenReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.stable_label())
    }
}

impl PolicyIncrementalReview {
    pub const fn base(&self) -> IncrementalBaseState {
        self.base
    }

    pub fn policies(&self) -> &[PolicyIncrementalRun] {
        &self.policies
    }

    /// How many units this batch reused instead of recomputing.
    pub fn reused_units(&self) -> u64 {
        self.policies
            .iter()
            .fold(0, |total, run| total.saturating_add(run.units_reused))
    }

    /// How many units this batch recomputed.
    pub fn recomputed_units(&self) -> u64 {
        self.policies
            .iter()
            .fold(0, |total, run| total.saturating_add(run.units_recomputed))
    }

    /// One policy's run, by identifier.
    pub fn policy(&self, policy_id: &PolicyId) -> Option<&PolicyIncrementalRun> {
        self.policies.iter().find(|run| &run.policy_id == policy_id)
    }
}
