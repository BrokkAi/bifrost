//! Workspace-level aggregation over per-root class-set solves.
//!
//! Every procedure of every language with a registered adapter is a root.
//! The report merges class sets across roots by union, keyed by the durable
//! site identity (file, span, member), deduplicates findings by (site,
//! class, member) keeping the first root's witness, and keeps a histogram of
//! Unknown reasons so a consumer can say why classification failed. An
//! Unknown is never read as an empty class set: merging preserves every
//! reason, and a site's status degrades to the weakest any root reported.

use crate::analyzer::semantic::{
    CancellationToken, SemanticBudget, SemanticRequest, SourceSpan, TypeFlowAdapter, UnknownReason,
    type_flow_adapter,
};
use crate::analyzer::{Language, ProjectFile, WorkspaceAnalyzer};
use crate::dataflow::{DataflowRequest, SolverBudget};
use crate::hash::HashMap;
use crate::value_flow::ClosureLimits;

use super::FieldSlotIndex;
use super::solve::{
    AbsentMemberFinding, ClassSetStatus, ReceiverClassSet, TypeFlowError, TypeFlowRootResult,
    solve_type_flow_for_root,
};

/// Durable identity of one member access: the file, the receiver span, and
/// the member name survive re-materialization; handles do not.
type SiteIdentity = (ProjectFile, SourceSpan, Box<str>);

/// The merged answer of [`solve_type_flow_workspace`].
#[derive(Debug, Default)]
pub struct TypeFlowReport {
    class_sets: Vec<ReceiverClassSet>,
    site_index: HashMap<SiteIdentity, usize>,
    findings: Vec<AbsentMemberFinding>,
    unknown_reasons: HashMap<UnknownReason, usize>,
    roots_analyzed: usize,
    roots_incomplete: usize,
}

impl TypeFlowReport {
    /// The merged class set for the member access at `span` in `file`, when
    /// any root reported one.
    pub fn class_set_at(
        &self,
        file: &ProjectFile,
        span: SourceSpan,
        member: &str,
    ) -> Option<&ReceiverClassSet> {
        let key = (file.clone(), span, member.into());
        self.site_index
            .get(&key)
            .map(|index| &self.class_sets[*index])
    }

    pub fn class_sets(&self) -> &[ReceiverClassSet] {
        &self.class_sets
    }

    pub fn findings(&self) -> &[AbsentMemberFinding] {
        &self.findings
    }

    pub fn unknown_reasons(&self) -> &HashMap<UnknownReason, usize> {
        &self.unknown_reasons
    }

    pub fn roots_analyzed(&self) -> usize {
        self.roots_analyzed
    }

    pub fn roots_incomplete(&self) -> usize {
        self.roots_incomplete
    }

    /// Merge one root's result. Class sets union per site; a reason is
    /// counted once per site that reports it; findings deduplicate by (site,
    /// class, member) with the first root keeping its witness.
    pub fn merge_root(&mut self, result: TypeFlowRootResult) {
        self.roots_analyzed += 1;
        if !result.complete {
            self.roots_incomplete += 1;
        }
        for set in result.class_sets {
            let key: SiteIdentity = (
                set.site.file.clone(),
                set.site.span,
                set.site.member.clone(),
            );
            match self.site_index.get(&key) {
                Some(index) => {
                    let reasons_before: Vec<UnknownReason> =
                        self.class_sets[*index].unknown.clone();
                    let existing = &mut self.class_sets[*index];
                    merge_class_set(existing, set);
                    for reason in existing
                        .unknown
                        .iter()
                        .filter(|reason| !reasons_before.contains(reason))
                    {
                        *self.unknown_reasons.entry(*reason).or_insert(0) += 1;
                    }
                }
                None => {
                    for reason in &set.unknown {
                        *self.unknown_reasons.entry(*reason).or_insert(0) += 1;
                    }
                    self.site_index.insert(key, self.class_sets.len());
                    self.class_sets.push(set);
                }
            }
        }
        for finding in result.findings {
            let duplicate = self.findings.iter().any(|existing| {
                existing.site.file == finding.site.file
                    && existing.site.span == finding.site.span
                    && existing.site.member == finding.site.member
                    && existing.class == finding.class
            });
            if !duplicate {
                self.findings.push(finding);
            }
        }
    }

    /// Account for one root whose own solve failed hard. Its sinks recorded
    /// nothing; the report says only that a root went unanalyzed.
    pub fn record_failed_root(&mut self) {
        self.roots_incomplete += 1;
    }
}

fn merge_class_set(existing: &mut ReceiverClassSet, incoming: ReceiverClassSet) {
    for (identity, origin) in incoming.classes {
        if !existing
            .classes
            .iter()
            .any(|(existing, _)| existing == &identity)
        {
            existing.classes.push((identity, origin));
        }
    }
    for reason in incoming.unknown {
        if !existing.unknown.contains(&reason) {
            existing.unknown.push(reason);
        }
    }
    existing.status = merge_status(existing.status, incoming.status);
}

/// The weakest status wins: an inconclusive root means the site was not fully
/// answered, a partial root means some value was unclassified, and a known
/// answer outranks only no information at all.
fn merge_status(left: ClassSetStatus, right: ClassSetStatus) -> ClassSetStatus {
    left.weakest(right)
}

/// Solve class-set propagation for every procedure of every language with a
/// registered adapter.
///
/// Budgets are per root: each root solves against a fresh clone of `budget`,
/// so a root that exhausts its solver budget reports its unreached sinks
/// `Unknown(SolverBudget)` through the incomplete-termination path and the
/// walk continues with the next root. Cancellation is checked between roots
/// and stops the walk.
pub fn solve_type_flow_workspace(
    workspace: &WorkspaceAnalyzer,
    limits: ClosureLimits,
    budget: SolverBudget,
    cancellation: &CancellationToken,
) -> Result<TypeFlowReport, TypeFlowError> {
    let provider = workspace.icfg_provider();
    let mut report = TypeFlowReport::default();
    for language in Language::ANALYZABLE {
        let Some(adapter) = type_flow_adapter(language) else {
            continue;
        };
        solve_language(
            workspace,
            adapter,
            limits,
            &budget,
            cancellation,
            &provider,
            &mut report,
        )?;
    }
    Ok(report)
}

fn solve_language<Provider: crate::analyzer::semantic::IcfgProvider + ?Sized>(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    limits: ClosureLimits,
    budget: &SolverBudget,
    cancellation: &CancellationToken,
    provider: &Provider,
    report: &mut TypeFlowReport,
) -> Result<(), TypeFlowError> {
    let mut field_slot_budget = SemanticBudget::default();
    let field_slots =
        FieldSlotIndex::build(workspace, adapter, &mut field_slot_budget, cancellation)?;
    let files = workspace
        .analyzer()
        .project()
        .analyzable_files(adapter.language())
        .map_err(TypeFlowError::Io)?;
    for file in files {
        if cancellation.is_cancelled() {
            return Err(TypeFlowError::Cancelled);
        }
        let mut materialize_budget = SemanticBudget::default();
        let outcome = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialize_budget, cancellation),
            )
            .map_err(super::plan::TypeFlowPlanError::Discovery)?;
        let Some(artifact) = outcome.available_value().cloned() else {
            continue;
        };
        for procedure in artifact.procedures() {
            if cancellation.is_cancelled() {
                return Err(TypeFlowError::Cancelled);
            }
            let root = artifact
                .procedure_handle(procedure.id())
                .expect("a live artifact owns each retained procedure");
            let mut semantic_budget = SemanticBudget::default();
            let mut solver_budget = budget.clone();
            let mut request = DataflowRequest::new(&mut solver_budget, cancellation);
            match solve_type_flow_for_root(
                workspace,
                adapter,
                &field_slots,
                &root,
                provider,
                limits,
                &mut semantic_budget,
                &mut request,
            ) {
                Ok(result) => report.merge_root(result),
                // A root that cannot plan or solve (a discovery provider
                // failure, a plan limit) is an incomplete root, not a reason
                // to abandon every other procedure in the workspace.
                Err(_) => report.record_failed_root(),
            }
        }
    }
    Ok(())
}
