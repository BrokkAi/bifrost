//! The family-agnostic unit path: how any policy's work is looked up, reused,
//! recomputed and published.
//!
//! Nothing here knows which family it is serving. A match policy's selector, an
//! assertion policy's subject selector and a relational binding's query are the
//! same question to this module -- a `CodeQuery` whose plan the RQL crate
//! classifies as partitionable -- and an assertion policy's per-file assert is
//! the same question again with a different partition and a different product.
//! What differs between families is what a unit *is* and what its product
//! means, which is the caller's business; what is the same is the algorithm
//! around it, which is this module's.
//!
//! The algorithm applied to one policy is: classify, enumerate, key, prefetch,
//! verify or recompute, check exhaustiveness, publish, merge, and check merged
//! limits. Every step that can refuse returns a typed [`WidenReason`], which
//! the caller reports beside a full evaluation rather than swallowing.
//!
//! Reuse follows one contract: publish a unit only with the read ledger that
//! licenses it, and verify every ledger entry against the head workspace before
//! reuse. A summary read identity excludes the workspace digest because the
//! unit's `File` and `Artifact` keys verify the precise workspace inputs. A
//! result-cache hit records no read set and cannot publish a unit. Shared budget
//! lanes remain request-wide: reused root products replay their solver,
//! semantic, execution, artifact-lease, and finding-lane charges, and reaching
//! a shared limit widens the policy with `MergedLimitReached`. A typestate root
//! key includes its compiled protocol and binding-plan hashes, so a product from
//! one compiled plan is not served under another. Adding an admitted partition
//! or product kind requires updating the `policy_units` check constraint.

use std::cell::Cell;
use std::sync::Arc;
use std::time::{Duration, Instant};

use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::common::language_for_file;
use brokk_bifrost_analysis::analyzer::invalidation::{
    ArtifactVerdict, BudgetMode, DerivedArtifactId, DerivedArtifactKind, InvalidationReason,
    RetentionReason,
};
use brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger;
use brokk_bifrost_analysis::analyzer::semantic::SemanticWork;
use brokk_bifrost_analysis::analyzer::usages::CallRelationLimits;
use brokk_bifrost_analysis::analyzer::{
    AnalyzerQueryScope, HeadInputs, IAnalyzer, Language, LookupMemo, LookupReplayLimits,
    NoSummaryAnswers, Oid, ProjectFile, ReadKey, ReadVerdict, WorkspaceAnalyzer,
    verify_read_set_for_artifact,
};
use brokk_bifrost_analysis::path_utils::rel_path_string;
use brokk_bifrost_rql::structural::search::{
    CodeQueryExecutionScope, MergedUnitRows, UnitExecutionResult, execute_code_query_unit,
    merge_unit_rows, plan_seed_files,
};
use brokk_bifrost_rql::structural::{CodeQuery, CodeQueryExecutionLimits};
use brokk_bifrost_rql::{PlanPartitioning, PlanWidenDetail};

use super::budget::PolicyBudget;
use super::definition::PolicyId;
use super::evaluator::SubjectQueryBatch;
use super::resolved::LoadedPolicy;
use super::units::{
    IncrementalMode, PolicyIncrementalContext, PolicyIncrementalRun, PolicyUnit, PolicyUnitKey,
    PolicyUnitProduct, UnitPartition, UnitPhaseMetrics, WidenReason,
};

/// What one policy's sliced attempt did, whether or not it widened.
///
/// The counts describe the attempt rather than the outcome: a policy that
/// enumerated forty units and recomputed one before the merge reached a cap
/// reports both numbers, because that is the diagnosis a reader needs and a
/// widened policy reporting zeros would hide it.
#[derive(Debug, Default)]
pub(crate) struct UnitAttempt {
    total: u64,
    reused: u64,
    recomputed: u64,
    unbounded: u64,
    widen_detail: Option<PlanWidenDetail>,
}

impl UnitAttempt {
    pub(crate) fn set_widen_detail(&mut self, detail: Option<PlanWidenDetail>) {
        self.widen_detail = detail;
    }
    /// Count `count` more units this attempt will decide about.
    pub(crate) fn enumerated(&mut self, count: usize) {
        self.total = self
            .total
            .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
    }

    pub(crate) fn reused(&mut self) {
        self.reused = self.reused.saturating_add(1);
    }

    pub(crate) fn recomputed(&mut self) {
        self.recomputed = self.recomputed.saturating_add(1);
    }

    /// How many units this attempt decided about.
    #[cfg(test)]
    pub(crate) const fn total(&self) -> u64 {
        self.total
    }

    pub(crate) fn unbounded(&mut self) {
        self.unbounded = self.unbounded.saturating_add(1);
    }

    /// The review entry this attempt became, with `widen_reason` set when the
    /// policy was evaluated whole after all.
    pub(crate) fn into_run(
        self,
        policy_id: PolicyId,
        widen_reason: Option<WidenReason>,
    ) -> PolicyIncrementalRun {
        PolicyIncrementalRun {
            policy_id,
            mode: match widen_reason {
                None => IncrementalMode::Sliced,
                Some(_) => IncrementalMode::Full,
            },
            units_total: self.total,
            units_reused: self.reused,
            units_recomputed: self.recomputed,
            units_unbounded: self.unbounded,
            lookups_replayed: 0,
            widen_reason,
            base_units_reused: 0,
            base_units_recomputed: 0,
            base_lookups_replayed: 0,
            base_widen_reason: None,
            widen_detail: self.widen_detail,
            base_widen_detail: None,
        }
    }
}

/// The reuse decision for one policy's units, and the state it amortizes.
///
/// One of these is built per policy and lives for the whole of its sliced
/// attempt: the head inputs every verification compares against, the limits a
/// replayed lookup re-runs under, and the memo that keeps one lookup from being
/// replayed once per unit. The memo is also the verification budget -- a pass
/// that needs more distinct answers than a whole evaluation would open files
/// has stopped being cheaper than the evaluation it avoids.
pub(crate) struct UnitReuse<'a> {
    incremental: &'a PolicyIncrementalContext<'a>,
    policy_id: &'a PolicyId,
    budget: &'a PolicyBudget,
    head_inputs: HeadInputs,
    replay_limits: LookupReplayLimits,
    limits: CodeQueryExecutionLimits,
    memo: LookupMemo,
    /// Where this attempt's time went, handed to the incremental context once
    /// when the attempt ends so the per-unit loop never takes its lock.
    phase: Cell<UnitPhaseMetrics>,
}

impl Drop for UnitReuse<'_> {
    fn drop(&mut self) {
        // While unwinding, a poisoned metrics mutex would turn this into a
        // second panic and abort the process; losing one attempt's metrics is
        // the cheaper outcome.
        if std::thread::panicking() {
            return;
        }
        let mut phase = self.phase.get();
        phase.lookup_replay = self.memo.replay_elapsed();
        phase.lookups_replayed =
            u64::try_from(self.memo.len()).expect("lookup replay count fits u64");
        self.incremental.add_unit_metrics(self.policy_id, phase);
    }
}

impl<'a> UnitReuse<'a> {
    pub(crate) fn new(
        policy: &'a LoadedPolicy,
        incremental: &'a PolicyIncrementalContext<'a>,
        budget: &'a PolicyBudget,
    ) -> Self {
        let limits = budget.query_limits();
        Self {
            incremental,
            policy_id: &policy.definition().metadata.id,
            budget,
            head_inputs: incremental.inputs().head_inputs(policy),
            replay_limits: lookup_replay_limits(&limits),
            limits,
            memo: LookupMemo::new(),
            phase: Cell::default(),
        }
    }

    /// The incremental context this reuse decides against.
    pub(crate) const fn incremental(&self) -> &'a PolicyIncrementalContext<'a> {
        self.incremental
    }

    /// Count `elapsed` as time one unit spent recomputing.
    pub(crate) fn record_recompute(&self, elapsed: Duration) {
        let mut phase = self.phase.get();
        phase.recompute += elapsed;
        self.phase.set(phase);
    }

    /// Load every key this policy will ask about, in one batch.
    ///
    /// A persisted store answers one query instead of one per partition. A
    /// store that cannot answer has said nothing about what was published, so
    /// the policy widens instead of reading its silence as absence.
    pub(crate) fn prefetch(&self, keys: &[PolicyUnitKey]) -> Result<(), WidenReason> {
        let started = Instant::now();
        let loaded = self
            .incremental
            .store()
            .lock()
            .expect("policy-unit store mutex poisoned")
            .prefetch(keys, self.budget);
        let mut phase = self.phase.get();
        phase.prefetch += started.elapsed();
        self.phase.set(phase);
        if let Err(error) = loaded {
            let policy_id = self.policy_id;
            brokk_bifrost_analysis::profiling::note_with(|| {
                format!("policy.units policy={policy_id} store_error={error}")
            });
            return Err(WidenReason::ProductLoadFailed);
        }
        Ok(())
    }

    /// The published product for `key`, when the head still reads what its unit
    /// read.
    ///
    /// `Ok(None)` means the unit must be recomputed: either nothing was
    /// published under its key, or a recorded read moved. `Err` means the whole
    /// policy must be evaluated, because a verification that cannot be
    /// completed is not a verification that failed.
    pub(crate) fn published(
        &mut self,
        key: &PolicyUnitKey,
    ) -> Result<Option<PolicyUnitProduct>, WidenReason> {
        let degraded_fills = self
            .incremental
            .workspace()
            .analyzer()
            .degraded_persistent_fills();
        if degraded_fills > 0 {
            brokk_bifrost_analysis::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=degraded_persistent_fill count={degraded_fills}",
                    file!(),
                    line!()
                )
            });
            return Err(WidenReason::UnitUnbounded);
        }
        let started = Instant::now();
        let replayed_before = self.memo.replay_elapsed();
        let result = self.published_inner(key);
        // Lookup replay runs inside verification; it is reported on its own,
        // so `verify` keeps only the rest of the decision and the two add up.
        let replay = self.memo.replay_elapsed() - replayed_before;
        let mut phase = self.phase.get();
        phase.verify += started.elapsed().saturating_sub(replay);
        self.phase.set(phase);
        result
    }

    fn published_inner(
        &mut self,
        key: &PolicyUnitKey,
    ) -> Result<Option<PolicyUnitProduct>, WidenReason> {
        let mut store = self
            .incremental
            .store()
            .lock()
            .expect("policy-unit store mutex poisoned");
        let Some(unit) = store.lookup(key) else {
            return Ok(None);
        };
        if unit.budget_mode() != BudgetMode::Exhaustive {
            return Err(WidenReason::UnitNotExhaustive);
        }
        // A whole evaluation of this policy may open `max_scanned_files` files,
        // and every replayed lookup opens at least one, so a verification pass
        // that needs more distinct answers than that has stopped being cheaper
        // than the evaluation it is avoiding.
        if self.memo.len() >= self.limits.max_scanned_files {
            return Err(WidenReason::VerificationBudgetExceeded);
        }
        let artifact = DerivedArtifactId::new(
            DerivedArtifactKind::PolicyEvaluationUnit,
            unit.read_digest().digest(),
        );
        // The store holds one unit per key, whichever run published it last:
        // a full scan of another revision, an earlier head of the same pull
        // request. Only its name-index reads are proved relative to a
        // snapshot; every other read is checked against this head itself. So
        // a unit without index reads is verified wherever it came from, and
        // one with index reads that holds on neither snapshot this comparison
        // is between is recomputed rather than verified against the wrong
        // difference.
        let (verified_on, changed) = match self.incremental.changed_since(unit.snapshots()) {
            Some((snapshot, changed)) => (Some(snapshot), changed),
            None if !unit.reads_name_index() => (None, self.incremental.changed()),
            None => {
                let policy_id = self.policy_id;
                brokk_bifrost_analysis::profiling::note_with(|| {
                    format!(
                        "policy.units policy={policy_id} partition={:?} foreign_snapshots={:?}",
                        key.partition,
                        unit.snapshots()
                    )
                });
                self.incremental
                    .verdicts()
                    .record(ArtifactVerdict::Invalidated(
                        InvalidationReason::InputContentChanged {
                            artifact,
                            before: unit.snapshots()[0],
                            after: self.incremental.snapshot(),
                        },
                    ));
                return Ok(None);
            }
        };
        match verify_read_set_for_artifact(
            artifact,
            self.incremental.workspace(),
            changed,
            &self.head_inputs,
            unit.reads(),
            self.replay_limits,
            // A typestate root unit's read set does name procedure
            // summaries, and this head answers none of them -- which is the
            // right answer, not a missing one. A head that has solved nothing
            // retains no summary under any identity, so the question cannot be
            // asked here at all; what carries the dependency is the closure
            // the recorder names beside each summary, one `Artifact` key per
            // member, which verification re-derives from the head's own bytes.
            &NoSummaryAnswers,
            &mut self.memo,
        ) {
            ReadVerdict::Unchanged => {
                self.incremental
                    .verdicts()
                    .record(ArtifactVerdict::Retained(
                        RetentionReason::InputsUnchanged { artifact },
                    ));
                let product = unit.product().clone();
                // Verification proved the unit's index answers on
                // `verified_on` are its answers on this head too, and on the
                // base when no probe names a moved name. Recording that is
                // what lets the next check in a chain, whose base is this
                // head, verify the unit again instead of recomputing it.
                if let Some(verified_on) = verified_on
                    && unit.reads_name_index()
                {
                    let attested = self
                        .incremental
                        .publication_snapshots(unit.reads())
                        .into_iter()
                        .filter(|snapshot| !unit.snapshots().contains(snapshot))
                        .collect::<Vec<_>>();
                    if !attested.is_empty() {
                        store.attest(key, verified_on, &attested);
                    }
                }
                Ok(Some(product))
            }
            ReadVerdict::Changed(changed) => {
                let missing = matches!(
                    changed.reason,
                    InvalidationReason::ReverseDependencyEvidenceMissing { .. }
                        | InvalidationReason::ContentIdentityEvidenceMissing { .. }
                );
                // Which read moved is the only diagnosis a reader of a
                // surprising recomputation can act on, and the counts cannot
                // carry it. Costs one relaxed load when timing is off.
                let policy_id = self.policy_id;
                brokk_bifrost_analysis::profiling::note_with(|| {
                    format!(
                        "policy.units policy={policy_id} partition={:?} read={:?} invalidated={:?}",
                        key.partition, changed.key, changed.reason
                    )
                });
                self.incremental
                    .verdicts()
                    .record(ArtifactVerdict::Invalidated(changed.reason));
                if missing {
                    return Err(WidenReason::ReverseDependencyEvidenceMissing);
                }
                Ok(None)
            }
        }
    }

    /// Stage one recomputed unit under the reads that produced it.
    ///
    /// The incremental context commits staged products only when the caller
    /// records the complete unit-key set for a successful sliced policy. A
    /// later widening therefore drops this product instead of exposing a
    /// partial unit set through the shared store.
    pub(crate) fn publish(
        &self,
        key: PolicyUnitKey,
        product: PolicyUnitProduct,
        reads: Vec<ReadKey>,
    ) {
        let snapshots = self.incremental.publication_snapshots(&reads);
        self.incremental.stage_unit(
            self.policy_id.clone(),
            PolicyUnit::new(key, product, reads, BudgetMode::Exhaustive, snapshots),
        );
    }
}

/// Run one unit's execution under a fresh ledger, and return its product with
/// the reads that licence publishing it.
///
/// The ledger is what makes a product reusable at all: it names every input the
/// execution read, in a form another workspace can be checked against. Absent
/// reads mean the ledger could not attribute every read, which makes the
/// product unbounded and therefore never publishable -- but the product itself
/// is still the answer this run computed, and the caller uses it.
pub(crate) fn recompute_unit<T>(
    analyzer: &dyn IAnalyzer,
    cancellation: Option<&CancellationToken>,
    run: impl FnOnce() -> T,
) -> (T, Option<Vec<ReadKey>>, Duration) {
    let ledger = Arc::new(ReadLedger::new());
    let generation_before = analyzer.project().analysis_generation();
    let product = {
        let started = Instant::now();
        let _reads = AnalyzerQueryScope::with_read_ledger(analyzer, Arc::clone(&ledger));
        let product = run();
        let degraded_fills = analyzer.degraded_persistent_fills();
        if degraded_fills > 0 {
            brokk_bifrost_analysis::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=degraded_persistent_fill count={degraded_fills}",
                    file!(),
                    line!()
                )
            });
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled)
            || analyzer
                .active_query_cancellation()
                .is_some_and(|token| token.is_cancelled())
            || analyzer.project().analysis_generation() != generation_before
            || _reads.store_error().is_some()
            || analyzer.degraded_persistent_fills() > 0
        {
            brokk_bifrost_analysis::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=unit_boundary cancelled={} snapshot={} store={}",
                    file!(),
                    line!(),
                    cancellation.is_some_and(CancellationToken::is_cancelled)
                        || analyzer
                            .active_query_cancellation()
                            .is_some_and(|token| token.is_cancelled()),
                    analyzer.project().analysis_generation() != generation_before,
                    _reads.store_error().is_some()
                )
            });
            ledger.mark_execution_dependent();
        }
        (product, started.elapsed())
    };
    let (product, elapsed) = product;
    let reads = ledger.is_bounded().then(|| ledger.keys());
    (product, reads, elapsed)
}

/// The limits a replayed lookup re-runs its funnel under.
///
/// The policy's own full lanes, not whatever a unit had left when it recorded
/// the answer: a complete answer replays identically under limits at least as
/// wide as the ones that produced it, and a narrower replay would report a
/// budget artifact as a change.
fn lookup_replay_limits(limits: &CodeQueryExecutionLimits) -> LookupReplayLimits {
    LookupReplayLimits {
        call_relations: CallRelationLimits {
            max_files: limits.max_scanned_files,
            max_source_bytes: limits.max_scanned_source_bytes,
            max_candidates: limits.max_pipeline_rows,
        },
        max_usage_files: limits.max_scanned_files,
        max_usages: limits.max_pipeline_rows,
        semantic: SemanticWork::default_limits(),
    }
}

/// What a query unit executes against.
///
/// The workspace file list is computed once per policy and handed to every
/// unit: the scanners that still need the whole enumeration get it without
/// re-deriving it, which is what keeps unit-wise execution linear in the file
/// count rather than quadratic.
pub(crate) struct UnitQueryExecution<'a> {
    pub(crate) analyzer: &'a dyn IAnalyzer,
    pub(crate) flow_state: brokk_bifrost_rql::SemanticFlowResources,
    /// The generation-bound workspace oracles, when this family's whole
    /// execution uses them. A unit that ran without them where the whole run
    /// had them would produce different rows, not fewer.
    pub(crate) workspace: Option<&'a WorkspaceAnalyzer>,
    pub(crate) cancellation: Option<&'a CancellationToken>,
    pub(crate) limits: CodeQueryExecutionLimits,
    pub(crate) workspace_files: &'a [ProjectFile],
    /// The policy batch whose other consumers of the same query a unit's
    /// execution is shared with. A unit it serves replays the reads of the
    /// execution that produced it, so it publishes under the same ledger.
    pub(crate) subject_batch: Option<&'a SubjectQueryBatch<'a>>,
}

/// The seed file one query unit covers, as a partition spelling needs it.
pub(crate) struct SeedPartition {
    pub(crate) language: Language,
    pub(crate) rel_path: String,
    pub(crate) blob: Oid,
}

impl SeedPartition {
    /// One unit per seed file, which is what a policy's own query uses.
    pub(crate) fn seed(self) -> UnitPartition {
        UnitPartition::Seed {
            language: self.language,
            rel_path: self.rel_path.into_boxed_str(),
            blob: self.blob,
        }
    }

    /// One unit per seed file of one named row binding, which is what a
    /// relational policy uses: it runs one query per binding over the same
    /// seeds, and two of them must not share a key.
    pub(crate) fn binding(self, binding: &str) -> UnitPartition {
        UnitPartition::Binding {
            binding: Box::from(binding),
            language: self.language,
            rel_path: self.rel_path.into_boxed_str(),
            blob: self.blob,
        }
    }
}

/// The rows one query produced, merged from its units, and the units it was
/// merged from.
///
/// The keys are carried out rather than recorded here because they are the
/// policy's statement of what its product was assembled from, and a policy may
/// assemble its product from more than one query.
pub(crate) struct SlicedQuery {
    pub(crate) merged: MergedUnitRows,
    pub(crate) keys: Vec<PolicyUnitKey>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct QuerySlicingWiden {
    pub(crate) reason: WidenReason,
    pub(crate) detail: PlanWidenDetail,
}

pub(crate) fn query_slicing_widen_reason(query: &CodeQuery) -> Option<QuerySlicingWiden> {
    if let Some(detail) = query.plan.requires_workspace_field_index() {
        Some(QuerySlicingWiden {
            reason: WidenReason::WorkspacePreparationRequired,
            detail,
        })
    } else {
        match PlanPartitioning::classify(&query.plan) {
            PlanPartitioning::Whole(detail) => Some(QuerySlicingWiden {
                reason: WidenReason::PlanCrossesSeeds,
                detail,
            }),
            _ => None,
        }
    }
}

/// Why the taint composition's frontier cannot evaluate `query` on one blob,
/// or `None` when it can.
///
/// The frontier reads one blob's rows and merges nothing, so it accepts what
/// [`query_slicing_widen_reason`] accepts plus an `except` over rows whose
/// identity names their file ([`PlanPartitioning::restricts_to_seed_file`]).
/// Unit reuse keeps the stricter rule: a unit's rows must merge into the whole
/// execution's rows in its order, so it also needs the except's minuend to
/// order its rows by seed ([`PlanPartitioning::classify`]). The
/// workspace field-index prepass would be repeated per blob either way. A plan
/// with a step that can move its rows out of the seed's file (a reverse or
/// forward relation, see `QueryStepOp::rows_may_leave_seed_file`) has rows
/// not at its seed's file, so one blob's slice does not hold the rows that lie in that
/// blob; the frontier evaluates it once over the workspace and indexes the
/// rows by where they lie.
pub(crate) fn frontier_slicing_widen_reason(query: &CodeQuery) -> Option<WidenReason> {
    if query.plan.requires_workspace_field_index().is_some() {
        Some(WidenReason::WorkspacePreparationRequired)
    } else if !PlanPartitioning::restricts_to_seed_file(&query.plan) {
        Some(WidenReason::PlanCrossesSeeds)
    } else {
        None
    }
}

/// Execute one query as the merge of one execution per seed file.
///
/// `Err` is the demand to evaluate the whole policy instead, with the reason
/// that demand exists. `Ok` is a row vector equal to the one a whole execution
/// would have produced: every unit was exhaustive, diagnostic-free and fully
/// attributed, and the merged counters proved that no cumulative cap the whole
/// execution enforces was reached.
///
/// `partition` spells how one seed file's unit is keyed, because a policy may
/// run more than one query over the same seeds and two queries of one policy
/// must not share a key.
pub(crate) fn sliced_query_units(
    policy: &LoadedPolicy,
    query: &CodeQuery,
    reuse: &mut UnitReuse<'_>,
    execution: &UnitQueryExecution<'_>,
    partition: impl Fn(SeedPartition) -> UnitPartition,
    attempt: &mut UnitAttempt,
) -> Result<SlicedQuery, WidenReason> {
    let incremental = reuse.incremental();
    if let Some(reason) = incremental.base_workspace_widen(&policy.definition().metadata.id) {
        return Err(reason);
    }
    if let Some(widen) = query_slicing_widen_reason(query) {
        attempt.set_widen_detail(Some(widen.detail));
        return Err(widen.reason);
    }
    // A changed-fact set that could not be completed is smaller than the truth,
    // and a smaller set would let a changed input pass verification.
    if !incremental.changed().is_complete() {
        return Err(WidenReason::ReverseDependencyEvidenceMissing);
    }

    let seed_files = plan_seed_files(&query.plan, execution.workspace_files);
    attempt.enumerated(seed_files.len());
    let shared = execution.subject_batch.and_then(|batch| {
        batch.query_units(
            query,
            execution.analyzer,
            execution.workspace,
            execution.limits,
        )
    });
    let inputs = incremental.inputs();

    let mut keys = Vec::with_capacity(seed_files.len());
    for file in &seed_files {
        let language = language_for_file(file);
        let rel_path = rel_path_string(file);
        let Some(blob) = incremental.changed().head_blob(language, &rel_path) else {
            // Without the blob this path resolves to there is no content
            // identity to key the unit by, which is missing evidence rather
            // than evidence of sameness.
            return Err(WidenReason::ReverseDependencyEvidenceMissing);
        };
        keys.push(inputs.unit_key(
            policy,
            partition(SeedPartition {
                language,
                rel_path,
                blob,
            }),
        ));
    }
    reuse.prefetch(&keys)?;

    let mut products = Vec::with_capacity(seed_files.len());
    for (file, key) in seed_files.iter().zip(keys.iter()) {
        let rows = match reuse.published(key)? {
            Some(product) => {
                attempt.reused();
                let Some(rows) = product.into_rows() else {
                    // One key names one product shape. A unit published under a
                    // query key that carries anything else is a store that
                    // answered a different question.
                    return Err(WidenReason::ProductLoadFailed);
                };
                check_exhaustive_rows(&rows)?;
                rows
            }
            None => {
                attempt.recomputed();
                let (rows, reads, elapsed) =
                    recompute_unit(execution.analyzer, execution.cancellation, || {
                        let execute = || {
                            let _timing = brokk_bifrost_analysis::profiling::scope_with(|| {
                                format!("policy.query_unit[{}]", rel_path_string(file))
                            });
                            execute_code_query_unit(
                                execution.analyzer,
                                execution.flow_state.clone(),
                                execution.workspace,
                                query,
                                execution.limits,
                                execution.cancellation,
                                CodeQueryExecutionScope::for_seed_files(
                                    std::slice::from_ref(file),
                                    execution.workspace_files,
                                ),
                            )
                        };
                        match &shared {
                            Some(shared) => shared.execute(
                                Some(file),
                                execution.analyzer,
                                execution.cancellation,
                                execute,
                            ),
                            None => execute(),
                        }
                    });
                reuse.record_recompute(elapsed);
                let Some(reads) = reads else {
                    attempt.unbounded();
                    return Err(WidenReason::UnitUnbounded);
                };
                check_exhaustive_rows(&rows)?;
                reuse.publish(key.clone(), PolicyUnitProduct::Rows(rows.clone()), reads);
                rows
            }
        };
        products.push(rows);
    }

    let merged = merge_unit_rows(query, products);
    if merged
        .reached_limit(&execution.limits, query.limit)
        .is_some()
    {
        return Err(WidenReason::MergedLimitReached);
    }
    Ok(SlicedQuery { merged, keys })
}

/// Truncation prevents a partition from representing its complete rows.
/// Diagnostics are additive; execution dependence is checked by its ledger.
pub(super) fn check_exhaustive_rows(rows: &UnitExecutionResult) -> Result<(), WidenReason> {
    if rows.truncated {
        return Err(WidenReason::UnitNotExhaustive);
    }
    if rows
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code.is_execution_state())
    {
        return Err(WidenReason::UnitDiagnostics);
    }
    Ok(())
}
