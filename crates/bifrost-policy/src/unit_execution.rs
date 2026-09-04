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
//! The algorithm is the plan's head algorithm
//! (`.agents/plans/impact-sliced-diff-base.md`, "The head algorithm") applied
//! to one policy: classify, enumerate, key, prefetch, verify-or-recompute,
//! check exhaustiveness, publish, merge, check the merged limits. Every step
//! that can refuse returns a typed [`WidenReason`], which the caller reports
//! beside a full evaluation rather than swallowing.

use std::sync::Arc;

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
    NoSummaryAnswers, Oid, ProjectFile, ReadKey, ReadVerdict, WorkspaceAnalyzer, verify_read_set,
};
use brokk_bifrost_analysis::path_utils::rel_path_string;
use brokk_bifrost_rql::PlanPartitioning;
use brokk_bifrost_rql::structural::search::{
    CodeQueryExecutionScope, MergedUnitRows, UnitExecutionResult, execute_code_query_unit,
    merge_unit_rows, plan_seed_files,
};
use brokk_bifrost_rql::structural::{CodeQuery, CodeQueryExecutionLimits};

use super::budget::PolicyBudget;
use super::definition::PolicyId;
use super::resolved::LoadedPolicy;
use super::units::{
    IncrementalMode, PolicyIncrementalContext, PolicyIncrementalRun, PolicyUnit, PolicyUnitKey,
    PolicyUnitProduct, UnitPartition, WidenReason,
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
}

impl UnitAttempt {
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
            widen_reason,
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
        }
    }

    /// The incremental context this reuse decides against.
    pub(crate) const fn incremental(&self) -> &'a PolicyIncrementalContext<'a> {
        self.incremental
    }

    /// Load every key this policy will ask about, in one batch.
    ///
    /// A persisted store answers one query instead of one per partition. A
    /// store that cannot answer has said nothing about what was published, so
    /// the policy widens instead of reading its silence as absence.
    pub(crate) fn prefetch(&self, keys: &[PolicyUnitKey]) -> Result<(), WidenReason> {
        if let Err(error) = self
            .incremental
            .store()
            .borrow_mut()
            .prefetch(keys, self.budget)
        {
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
        let store = self.incremental.store().borrow();
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
        match verify_read_set(
            self.incremental.workspace(),
            self.incremental.changed(),
            &self.head_inputs,
            unit.reads(),
            self.replay_limits,
            // A typestate root unit's read set does name procedure
            // summaries, and this head answers none of them -- which is the
            // right answer, not a missing one. A head that has solved nothing
            // retains no summary under any identity, so the question cannot be
            // asked here at all; what carries the dependency is the closure
            // the recorder names beside each summary, one `Artifact` key per
            // member, which verification re-derives from the head's own bytes
            // (`.agents/plans/impact-sliced-diff-base.md`, Decision Log (5b)).
            &NoSummaryAnswers,
            &mut self.memo,
        ) {
            ReadVerdict::Unchanged => {
                self.incremental
                    .verdicts()
                    .record(ArtifactVerdict::Retained(
                        RetentionReason::InputsUnchanged { artifact },
                    ));
                Ok(Some(unit.product().clone()))
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

    /// Publish one recomputed unit under the reads that produced it.
    pub(crate) fn publish(
        &self,
        key: PolicyUnitKey,
        product: PolicyUnitProduct,
        reads: Vec<ReadKey>,
    ) {
        self.incremental
            .store()
            .borrow_mut()
            .publish(PolicyUnit::new(key, product, reads, BudgetMode::Exhaustive));
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
    run: impl FnOnce() -> T,
) -> (T, Option<Vec<ReadKey>>) {
    let ledger = Arc::new(ReadLedger::new());
    let product = {
        let _reads = AnalyzerQueryScope::with_read_ledger(analyzer, Arc::clone(&ledger));
        run()
    };
    let reads = ledger.is_bounded().then(|| ledger.keys());
    (product, reads)
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
    /// The generation-bound workspace oracles, when this family's whole
    /// execution uses them. A unit that ran without them where the whole run
    /// had them would produce different rows, not fewer.
    pub(crate) workspace: Option<&'a WorkspaceAnalyzer>,
    pub(crate) cancellation: Option<&'a CancellationToken>,
    pub(crate) limits: CodeQueryExecutionLimits,
    pub(crate) workspace_files: &'a [ProjectFile],
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
    if !PlanPartitioning::classify(&query.plan).is_by_seed() {
        return Err(WidenReason::PlanCrossesSeeds);
    }
    // A changed-fact set that could not be completed is smaller than the truth,
    // and a smaller set would let a changed input pass verification.
    if !incremental.changed().is_complete() {
        return Err(WidenReason::ReverseDependencyEvidenceMissing);
    }

    let seed_files = plan_seed_files(&query.plan, execution.workspace_files);
    attempt.enumerated(seed_files.len());
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
                let (rows, reads) = recompute_unit(execution.analyzer, || {
                    execute_code_query_unit(
                        execution.analyzer,
                        execution.workspace,
                        query,
                        execution.limits,
                        execution.cancellation,
                        CodeQueryExecutionScope::for_seed_files(
                            std::slice::from_ref(file),
                            execution.workspace_files,
                        ),
                    )
                });
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

    let merged = merge_unit_rows(products);
    if merged
        .reached_limit(&execution.limits, query.limit)
        .is_some()
    {
        return Err(WidenReason::MergedLimitReached);
    }
    Ok(SlicedQuery { merged, keys })
}

/// Exhaustiveness is checked on the product rather than on how it was obtained:
/// a unit that truncated or raised a diagnostic is not a partition of a whole
/// execution, whichever run computed it.
fn check_exhaustive_rows(rows: &UnitExecutionResult) -> Result<(), WidenReason> {
    if rows.truncated {
        return Err(WidenReason::UnitNotExhaustive);
    }
    if !rows.diagnostics.is_empty() {
        return Err(WidenReason::UnitDiagnostics);
    }
    Ok(())
}
