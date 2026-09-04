//! Executor for the `class_set` and `absent_member` steps.
//!
//! Input rows are procedures. Each distinct input procedure roots at most one
//! whole-program class-set solve per query -- the result is cached by root and
//! provider behavior -- and the two steps project that one result: `class_set`
//! emits one row per (member access site, class atom), `absent_member` one row
//! per finding. Honest absence is preserved end to end: a row whose status is
//! not `known` carries no proof, and an unsupported language, an incomplete
//! solve, or a failed root is a diagnostic, never an empty answer that reads
//! as "no classes" or "no finding".

use std::sync::Arc;

use super::semantic::SemanticProcedureValue;
use super::witness_projection::saturating_u64;
use super::{
    CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact, CodeQueryTypeFlowWork,
    CodeQueryValueFlowLimits,
};
use crate::analyzer::common::language_for_file;
use crate::analyzer::semantic::{
    ClassIdentity, DeclarationSegmentKind, IcfgProvider, IcfgProviderBehaviorIdentity,
    LengthDelimitedDigest, ProcedureHandle, SemanticBudget, SemanticWork, SourceSpan, StableDigest,
    UnknownReason, WorkspaceIcfgProvider, type_flow_adapter,
};
use crate::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use crate::analyzer::{ProjectFile, Range, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
use brokk_bifrost_flow::dataflow::{DataflowRequest, SolverBudget};
use brokk_bifrost_flow::type_flow::{
    ClassSetStatus, FieldSlotIndex, TypeFlowError, TypeFlowPlanError, TypeFlowRootResult,
    solve_type_flow_for_root,
};
use brokk_bifrost_flow::value_flow::ClosureLimits;

/// Bound on the procedures one root's discovered closure may hold, matching
/// the engine's own integration-test budget.
const CLOSURE_LIMITS: ClosureLimits = ClosureLimits {
    max_procedures: 512,
};

fn field_slot_semantic_limits(caller: SemanticWork) -> SemanticWork {
    caller.component_max(SemanticWork::default_limits())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TypeFlowCacheKey {
    root: ProcedureHandle,
    /// Separates results if this cache is ever reused across provider builds.
    provider_behavior: IcfgProviderBehaviorIdentity,
    field_slots: StableDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FieldSlotCacheKey {
    language: crate::analyzer::Language,
    provider_behavior: IcfgProviderBehaviorIdentity,
}

#[derive(Debug, Clone)]
enum CachedTypeFlowAnalysis {
    Complete(Arc<TypeFlowRootResult>),
    Failed,
}

#[derive(Default)]
pub(super) struct TypeFlowQueryState {
    cache: HashMap<TypeFlowCacheKey, CachedTypeFlowAnalysis>,
    field_slots: HashMap<FieldSlotCacheKey, Option<Arc<FieldSlotIndex>>>,
    diagnostics: Vec<CodeQueryDiagnostic>,
    work: CodeQueryTypeFlowWork,
    semantic_budget_exhausted: bool,
}

/// One member access site's merged answer: the classes and Unknown reasons of
/// every sink sharing the site's durable identity, with the weakest status.
struct MergedClassSet {
    file: ProjectFile,
    span: SourceSpan,
    member: String,
    classes: Vec<ClassIdentity>,
    unknown: Vec<UnknownReason>,
    status: ClassSetStatus,
}

/// One projected (member access site, class atom) pair with its source anchor.
#[derive(Debug, Clone)]
pub(super) struct ClassSetRowValue {
    pub(super) id: String,
    pub(super) file: ProjectFile,
    pub(super) range: Range,
    pub(super) member: String,
    /// The qualified class name. Absent exactly for an `unknown:<reason>`
    /// origin, which names why the engine could not classify the value rather
    /// than naming a class.
    pub(super) class: Option<String>,
    pub(super) origin: String,
    pub(super) status: &'static str,
}

/// One absent-member finding with the site that introduced the class.
#[derive(Debug, Clone)]
pub(super) struct AbsentMemberFindingValue {
    pub(super) id: String,
    pub(super) file: ProjectFile,
    pub(super) range: Range,
    pub(super) member: String,
    pub(super) class: String,
    pub(super) origin_file: ProjectFile,
    pub(super) origin_range: Range,
    pub(super) caller: String,
    pub(super) witness_steps: usize,
}

impl ClassSetRowValue {
    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }
}

impl AbsentMemberFindingValue {
    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }
}

impl TypeFlowQueryState {
    pub(super) fn class_sets(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        procedure: &SemanticProcedureValue,
        semantic_budget: &mut SemanticBudget,
        limits: CodeQueryValueFlowLimits,
        cancellation: &CancellationToken,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Vec<ClassSetRowValue> {
        let Some(result) = self.solve(
            workspace,
            procedure,
            semantic_budget,
            limits,
            cancellation,
            active_semantic_model_snapshot,
        ) else {
            return Vec::new();
        };
        let root_procedure_id = super::semantic::procedure_wire_id(&result.root);
        // A call-shaped access `x.foo()` legitimately produces a Call sink and
        // a Load sink at the same durable identity (file, span, member). The
        // row surface answers one row per (member access site, atom), so the
        // projection merges those sinks the way the workspace report does:
        // classes and reasons union, the weakest status wins.
        let mut merged: Vec<MergedClassSet> = Vec::new();
        let mut site_index: HashMap<(ProjectFile, SourceSpan, &str), usize> = HashMap::default();
        for set in &result.class_sets {
            let key = (
                set.site.file.clone(),
                set.site.span,
                set.site.member.as_ref(),
            );
            let entry = match site_index.get(&key) {
                Some(index) => &mut merged[*index],
                None => {
                    site_index.insert(key, merged.len());
                    merged.push(MergedClassSet {
                        file: set.site.file.clone(),
                        span: set.site.span,
                        member: set.site.member.to_string(),
                        classes: Vec::new(),
                        unknown: Vec::new(),
                        status: set.status,
                    });
                    merged.last_mut().expect("the set was just pushed")
                }
            };
            for (identity, _) in &set.classes {
                if !entry.classes.contains(identity) {
                    entry.classes.push(identity.clone());
                }
            }
            for reason in &set.unknown {
                if !entry.unknown.contains(reason) {
                    entry.unknown.push(*reason);
                }
            }
            entry.status = entry.status.weakest(set.status);
        }
        let mut rows = Vec::new();
        for set in &merged {
            let range = source_range(set.span);
            for identity in &set.classes {
                let class = identity.qualified_name().to_string();
                let origin = match identity {
                    ClassIdentity::Workspace(_) => "workspace".to_string(),
                    ClassIdentity::External { .. } => "external".to_string(),
                };
                rows.push(ClassSetRowValue {
                    id: class_set_row_id(
                        &root_procedure_id,
                        &set.file,
                        set.span,
                        &set.member,
                        &class,
                        &origin,
                    ),
                    file: set.file.clone(),
                    range,
                    member: set.member.clone(),
                    class: Some(class),
                    origin,
                    status: set.status.label(),
                });
            }
            for reason in &set.unknown {
                let origin = format!("unknown:{}", reason.label());
                rows.push(ClassSetRowValue {
                    id: class_set_row_id(
                        &root_procedure_id,
                        &set.file,
                        set.span,
                        &set.member,
                        "",
                        &origin,
                    ),
                    file: set.file.clone(),
                    range,
                    member: set.member.clone(),
                    class: None,
                    origin,
                    status: set.status.label(),
                });
            }
        }
        self.work.class_set_rows = self
            .work
            .class_set_rows
            .saturating_add(saturating_u64(rows.len()));
        rows
    }

    pub(super) fn absent_member_findings(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        procedure: &SemanticProcedureValue,
        semantic_budget: &mut SemanticBudget,
        limits: CodeQueryValueFlowLimits,
        cancellation: &CancellationToken,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Vec<AbsentMemberFindingValue> {
        let Some(result) = self.solve(
            workspace,
            procedure,
            semantic_budget,
            limits,
            cancellation,
            active_semantic_model_snapshot,
        ) else {
            return Vec::new();
        };
        let root_procedure_id = super::semantic::procedure_wire_id(&result.root);
        let caller = procedure_name(&result.root);
        let mut rows = Vec::new();
        let mut seen = crate::hash::HashSet::default();
        for finding in &result.findings {
            // The duplicate Call/Load sinks of one call-shaped access report
            // the same finding twice; the first witness is kept, as in the
            // workspace report.
            if !seen.insert((
                finding.site.file.clone(),
                finding.site.span,
                finding.site.member.clone(),
                finding.class.qualified_name().to_string(),
            )) {
                continue;
            }
            rows.push(AbsentMemberFindingValue {
                id: absent_member_finding_id(
                    &root_procedure_id,
                    &finding.site.file,
                    finding.site.span,
                    &finding.site.member,
                    finding.class.qualified_name(),
                ),
                file: finding.site.file.clone(),
                range: source_range(finding.site.span),
                member: finding.site.member.to_string(),
                class: finding.class.qualified_name().to_string(),
                origin_file: finding.origin.file.clone(),
                origin_range: source_range(finding.origin.span),
                caller: caller.clone(),
                witness_steps: finding
                    .witness
                    .as_ref()
                    .map_or(0, |witness| witness.steps().len()),
            });
        }
        self.work.finding_rows = self
            .work
            .finding_rows
            .saturating_add(saturating_u64(rows.len()));
        rows
    }

    fn solve(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        procedure: &SemanticProcedureValue,
        semantic_budget: &mut SemanticBudget,
        limits: CodeQueryValueFlowLimits,
        cancellation: &CancellationToken,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Option<Arc<TypeFlowRootResult>> {
        let language = language_for_file(procedure.file());
        let Some(adapter) = type_flow_adapter(language) else {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::SemanticCapabilityUnsupported,
                format!(
                    "class-set propagation is unsupported for {}",
                    language.config_label()
                ),
            );
            return None;
        };
        let provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
            workspace,
            active_semantic_model_snapshot,
        );
        let provider_behavior = provider.behavior_identity();
        let field_slot_key = FieldSlotCacheKey {
            language,
            provider_behavior,
        };
        let field_slots = match self.field_slots.get(&field_slot_key).cloned() {
            Some(Some(index)) => index,
            Some(None) => return None,
            None => {
                self.work.field_slot_builds = self.work.field_slot_builds.saturating_add(1);
                let parent_scope = semantic_budget.scope_snapshot();
                // A field index is an explicit whole-workspace prepass, not
                // one root's semantic closure. The query's memory-shaped row
                // estimates can be lower than the finite workspace semantic
                // floors, so retain the caller's larger lanes while giving
                // this shared child enough headroom to visit the workspace
                // once. Root children below keep the caller's exact limits.
                let field_slot_limits = field_slot_semantic_limits(semantic_budget.limits());
                let mut field_slot_budget =
                    SemanticBudget::new_child(field_slot_limits, &parent_scope);
                let built =
                    FieldSlotIndex::build(workspace, adapter, &mut field_slot_budget, cancellation);
                if semantic_budget
                    .apply_child_charge(
                        SemanticWork::default(),
                        field_slot_budget.into_child_charge(),
                    )
                    .is_err()
                {
                    // Query-wide accounting only; later roots keep their own
                    // child budgets, matching the root-solve contract below.
                }
                match built {
                    Ok(index) => {
                        if index.semantic_budget_exhausted() {
                            self.semantic_budget_exhausted = true;
                            self.push_diagnostic(
                                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                                format!(
                                    "class-set field index exceeded its semantic budget: {}",
                                    index
                                        .semantic_budget_exhaustion()
                                        .expect("an exhausted field index records its ceiling")
                                ),
                            );
                        }
                        let index = Arc::new(index);
                        self.field_slots
                            .insert(field_slot_key, Some(Arc::clone(&index)));
                        index
                    }
                    Err(error) => {
                        let code = if matches!(error, TypeFlowPlanError::Cancelled) {
                            CodeQueryDiagnosticCode::Cancelled
                        } else {
                            CodeQueryDiagnosticCode::SemanticProviderFailed
                        };
                        self.push_diagnostic(
                            code,
                            format!("class-set field index failed: {error}"),
                        );
                        self.field_slots.insert(field_slot_key, None);
                        return None;
                    }
                }
            }
        };
        let cache_key = TypeFlowCacheKey {
            root: procedure.handle.clone(),
            provider_behavior,
            field_slots: field_slots.digest(),
        };
        match self.cache.get(&cache_key).cloned() {
            Some(CachedTypeFlowAnalysis::Complete(result)) => {
                self.work.cache_hits = self.work.cache_hits.saturating_add(1);
                Some(result)
            }
            Some(CachedTypeFlowAnalysis::Failed) => {
                self.work.cache_hits = self.work.cache_hits.saturating_add(1);
                None
            }
            None => {
                self.work.solves = self.work.solves.saturating_add(1);
                let mut solver_budget = SolverBudget::new(limits.solver_work);
                let mut request = DataflowRequest::new(&mut solver_budget, cancellation);
                // Each root solves against its own child of the query's
                // semantic budget: the child inherits the artifact identities
                // the query already paid but starts its scalar ledger at
                // zero, so one root cannot starve the next.
                let parent_scope = semantic_budget.scope_snapshot();
                let mut child_budget =
                    SemanticBudget::new_child(semantic_budget.limits(), &parent_scope);
                let outcome = solve_type_flow_for_root(
                    workspace,
                    adapter,
                    &field_slots,
                    &procedure.handle,
                    &provider,
                    CLOSURE_LIMITS,
                    &mut child_budget,
                    &mut request,
                );
                // Fold the root's spend back into the query-wide ledger so
                // later roots inherit the artifact identities this root paid
                // (the child's charge carries them) and the profile's work
                // counters keep measuring the query's real semantic spend.
                // When the per-query aggregate is already saturated the
                // apply is refused atomically: that ceiling is accounting
                // only, and must NOT become `semantic_budget_exhausted` --
                // the pipeline stops a step's remaining rows once that flag
                // is set, which is exactly the starvation this child ledger
                // exists to remove. A later root's child starts at zero
                // either way, and a genuine refusal of the query's own
                // direct spend is still reported by the shared budget's own
                // paths.
                if semantic_budget
                    .apply_child_charge(SemanticWork::default(), child_budget.into_child_charge())
                    .is_err()
                {
                    // Accounting-only ceiling saturated; see above.
                }
                match outcome {
                    Ok(result) => {
                        if result.semantic_budget_exhausted {
                            self.semantic_budget_exhausted = true;
                            self.push_diagnostic(
                                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                                "class-set semantic input exceeded its budget".to_string(),
                            );
                        }
                        if !result.complete {
                            self.work.incomplete_roots =
                                self.work.incomplete_roots.saturating_add(1);
                            self.push_diagnostic(
                                CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                                "class-set analysis retained incomplete semantic evidence"
                                    .to_string(),
                            );
                        }
                        let result = Arc::new(result);
                        self.cache.insert(
                            cache_key,
                            CachedTypeFlowAnalysis::Complete(Arc::clone(&result)),
                        );
                        Some(result)
                    }
                    Err(error) => {
                        self.work.failed_solves = self.work.failed_solves.saturating_add(1);
                        let code = match &error {
                            TypeFlowError::Cancelled => CodeQueryDiagnosticCode::Cancelled,
                            TypeFlowError::Plan(_)
                            | TypeFlowError::Solve(_)
                            | TypeFlowError::Io(_) => {
                                CodeQueryDiagnosticCode::SemanticProviderFailed
                            }
                        };
                        self.push_diagnostic(code, format!("class-set analysis failed: {error}"));
                        self.cache.insert(cache_key, CachedTypeFlowAnalysis::Failed);
                        None
                    }
                }
            }
        }
    }

    fn push_diagnostic(&mut self, code: CodeQueryDiagnosticCode, message: String) {
        if self
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == code && diagnostic.message == message)
        {
            return;
        }
        self.diagnostics.push(CodeQueryDiagnostic {
            code,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: "workspace",
            message,
        });
    }

    pub(super) fn take_diagnostics(&mut self) -> Vec<CodeQueryDiagnostic> {
        std::mem::take(&mut self.diagnostics)
    }

    pub(super) const fn work(&self) -> CodeQueryTypeFlowWork {
        self.work
    }

    pub(super) const fn semantic_budget_exhausted(&self) -> bool {
        self.semantic_budget_exhausted
    }
}

fn source_range(span: SourceSpan) -> Range {
    Range {
        start_byte: span.start_byte() as usize,
        end_byte: span.end_byte() as usize,
        start_line: span.start().line() as usize + 1,
        end_line: span.end().line() as usize + 1,
    }
}

/// The procedure's declaration path, rendered the way a reader spells it:
/// named segments joined, file segments dropped.
fn procedure_name(root: &ProcedureHandle) -> String {
    root.semantics()
        .locator()
        .declaration()
        .segments()
        .iter()
        .filter(|segment| segment.kind() != DeclarationSegmentKind::File)
        .map(|segment| segment.name().unwrap_or("<anonymous>").to_string())
        .collect::<Vec<_>>()
        .join(".")
}

fn class_set_row_id(
    root_procedure_id: &str,
    file: &ProjectFile,
    span: SourceSpan,
    member: &str,
    class: &str,
    origin: &str,
) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.class_set_row.v1");
    digest.push(root_procedure_id.as_bytes());
    digest.push(file.rel_path().display().to_string().as_bytes());
    digest.push(&span.start_byte().to_le_bytes());
    digest.push(&span.end_byte().to_le_bytes());
    digest.push(member.as_bytes());
    digest.push(class.as_bytes());
    digest.push(origin.as_bytes());
    digest.finish().to_string()
}

fn absent_member_finding_id(
    root_procedure_id: &str,
    file: &ProjectFile,
    span: SourceSpan,
    member: &str,
    class: &str,
) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.absent_member_finding.v1");
    digest.push(root_procedure_id.as_bytes());
    digest.push(file.rel_path().display().to_string().as_bytes());
    digest.push(&span.start_byte().to_le_bytes());
    digest.push(&span.end_byte().to_le_bytes());
    digest.push(member.as_bytes());
    digest.push(class.as_bytes());
    digest.finish().to_string()
}

#[cfg(test)]
mod tests {
    use super::field_slot_semantic_limits;
    use crate::analyzer::semantic::SemanticWork;

    #[test]
    fn field_slot_prepass_keeps_finite_workspace_floors_and_larger_caller_lanes() {
        assert_eq!(
            field_slot_semantic_limits(SemanticWork::uniform(1)),
            SemanticWork::default_limits()
        );

        let mut caller = SemanticWork::default_limits();
        caller.source_mappings = caller.source_mappings.saturating_mul(2);
        assert_eq!(
            field_slot_semantic_limits(caller).source_mappings,
            caller.source_mappings
        );
    }
}
