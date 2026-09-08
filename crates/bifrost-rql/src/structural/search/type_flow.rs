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
use super::witness_projection::{bounded_reason, saturating_u64};
use super::{
    CodeQueryAbsentMemberWitness, CodeQueryDiagnostic, CodeQueryDiagnosticCode,
    CodeQueryDiagnosticImpact, CodeQueryTypeFlowWork, CodeQueryValueFlowLimits,
};
use crate::analyzer::common::language_for_file;
use crate::analyzer::semantic::{
    ClassIdentity, DeclarationSegmentKind, IcfgProvider, IcfgProviderBehaviorIdentity,
    LengthDelimitedDigest, ProcedureHandle, SemanticBudget, SemanticBudgetDimension,
    SemanticIrVersion, SemanticWork, SourceSpan, StableDigest, TypeFlowAdapter, UnknownReason,
    WorkspaceIcfgProvider, WorkspaceRelativePath, type_flow_adapter,
};
use crate::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use crate::analyzer::{ProjectFile, Range, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
use crate::path_utils::rel_path_string;
use brokk_bifrost_analysis::analyzer::store::class_set_root_results::{
    ClassSetRootResultGenerationKey, ClassSetRootResultLookup, FindingFreeClassSetRootKey,
    FindingFreeClassSetRootResult, PersistedClassSetAtom, PersistedClassSetRootRow,
    PersistedClassSetStatus, PersistedClassSetUnknownReason,
};
use brokk_bifrost_flow::dataflow::{
    DataflowDirectionRequest, DataflowQueryPlanConfig, DataflowRequest, SolverBudget,
    SolverBudgetDimension, SummaryWitness, SummaryWitnessError,
};
use brokk_bifrost_flow::flow_state::procedure_public_digest;
use brokk_bifrost_flow::type_flow::{
    ClassSetStatus, FeedbackLimits, FieldSlotIndex, FieldSlotIndexAcquisitionKind,
    FieldSlotIndexMissReason, TypeFlowError, TypeFlowPlanError, TypeFlowRootPersistenceStatus,
    TypeFlowRootResult, active_semantic_model_pack_digest, solve_type_flow_for_root,
};
use brokk_bifrost_flow::value_flow::{ClosureLimits, ValueFlowCache, ValueFlowCacheStatsSnapshot};

/// Bound on the procedures one root's discovered closure may hold, matching
/// the engine's own integration-test budget.
const CLOSURE_LIMITS: ClosureLimits = ClosureLimits {
    max_procedures: 512,
};
const ROOT_RESULT_REPRESENTATION_VERSION: u32 = 2;

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
struct AbsentMemberWitnessProjectionKey {
    finding_id: String,
    root_procedure_id: String,
    witness_index: usize,
    max_steps: usize,
    max_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FieldSlotCacheKey {
    language: crate::analyzer::Language,
    provider_behavior: IcfgProviderBehaviorIdentity,
}

#[derive(Debug, Clone)]
enum CachedTypeFlowAnalysis {
    Live {
        result: Arc<TypeFlowRootResult>,
        projected_rows: Option<Arc<[ClassSetRowValue]>>,
    },
    FindingFreeRows(Arc<[ClassSetRowValue]>),
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootResultPublicationOutcome {
    Continued,
    Cancelled,
}

pub(super) struct TypeFlowQueryState {
    value_flow_cache: ValueFlowCache,
    summary_state: brokk_bifrost_flow::type_flow::TypeFlowSummaryState,
    provider_stats_baseline: ValueFlowCacheStatsSnapshot,
    cache: HashMap<TypeFlowCacheKey, CachedTypeFlowAnalysis>,
    field_slots: HashMap<FieldSlotCacheKey, Option<Arc<FieldSlotIndex>>>,
    witness_projection_cache:
        HashMap<AbsentMemberWitnessProjectionKey, Option<AbsentMemberWitnessValue>>,
    diagnostics: Vec<CodeQueryDiagnostic>,
    work: CodeQueryTypeFlowWork,
    semantic_budget_exhausted: bool,
    witness_render_cache: super::PipelineRenderCache,
}

impl Default for TypeFlowQueryState {
    fn default() -> Self {
        Self::new(ValueFlowCache::default(), Default::default())
    }
}

impl TypeFlowQueryState {
    pub(super) fn new(
        value_flow_cache: ValueFlowCache,
        summary_state: brokk_bifrost_flow::type_flow::TypeFlowSummaryState,
    ) -> Self {
        let value_flow_cache = value_flow_cache.with_fresh_stats();
        let provider_stats_baseline = value_flow_cache.stats();
        Self {
            value_flow_cache,
            summary_state,
            provider_stats_baseline,
            cache: HashMap::default(),
            field_slots: HashMap::default(),
            witness_projection_cache: HashMap::default(),
            diagnostics: Vec::new(),
            work: CodeQueryTypeFlowWork::default(),
            semantic_budget_exhausted: false,
            witness_render_cache: super::PipelineRenderCache::default(),
        }
    }
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
    span: SourceSpan,
    portable_path: Option<WorkspaceRelativePath>,
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
    /// Sorted by root identity, with one coherent evidence record per root.
    pub(super) roots: Vec<AbsentMemberRootEvidence>,
}

#[derive(Debug, Clone)]
pub(super) struct AbsentMemberRootEvidence {
    pub(super) root_procedure_id: String,
    pub(super) origin_file: ProjectFile,
    pub(super) origin_range: Range,
    pub(super) caller: String,
    pub(super) witness: Result<SummaryWitness, SummaryWitnessError>,
}

#[derive(Debug, Clone)]
pub(super) struct AbsentMemberWitnessValue {
    pub(super) public: CodeQueryAbsentMemberWitness,
    pub(super) file: ProjectFile,
    pub(super) byte_span: std::ops::Range<usize>,
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

    pub(super) fn representative(&self) -> &AbsentMemberRootEvidence {
        self.roots
            .iter()
            .find(|root| root.witness.is_ok())
            .unwrap_or_else(|| self.roots.first().expect("a finding has root evidence"))
    }

    pub(super) fn merge_evidence(&mut self, other: Self) {
        debug_assert_eq!(self.id, other.id);
        for root in other.roots {
            match self.roots.binary_search_by(|existing| {
                existing.root_procedure_id.cmp(&root.root_procedure_id)
            }) {
                Ok(index) => {
                    if self.roots[index].witness.is_err() && root.witness.is_ok() {
                        self.roots[index] = root;
                    }
                }
                Err(index) => self.roots.insert(index, root),
            }
        }
    }
}

impl AbsentMemberWitnessValue {
    pub(super) fn key(&self) -> &str {
        &self.public.id
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn byte_span(&self) -> std::ops::Range<usize> {
        self.byte_span.clone()
    }

    pub(super) fn public_ref(&self) -> super::CodeQueryResultRef {
        super::CodeQueryResultRef::AbsentMemberWitness {
            id: self.public.id.clone(),
            finding_id: self.public.finding_id.clone(),
            path: self.public.path.clone(),
            range: self.public.range,
        }
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
        let rows = match result {
            CachedTypeFlowAnalysis::Live {
                result,
                projected_rows,
            } => projected_rows.map_or_else(|| project_class_sets(&result), |rows| rows.to_vec()),
            CachedTypeFlowAnalysis::FindingFreeRows(rows) => rows.to_vec(),
            CachedTypeFlowAnalysis::Failed => {
                unreachable!("failed type-flow cache entries return None")
            }
        };
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
        let result = match result {
            CachedTypeFlowAnalysis::Live { result, .. } => result,
            CachedTypeFlowAnalysis::FindingFreeRows(_) => return Vec::new(),
            CachedTypeFlowAnalysis::Failed => {
                unreachable!("failed type-flow cache entries return None")
            }
        };
        let caller = procedure_name(&result.root);
        let mut rows: Vec<AbsentMemberFindingValue> = Vec::new();
        let mut seen: crate::hash::HashMap<_, usize> = crate::hash::HashMap::default();
        for finding in &result.findings {
            // The duplicate Call/Load sinks of one call-shaped access report
            // the same finding twice; the first witness is kept, as in the
            // workspace report.
            let key = (
                finding.site.file.clone(),
                finding.site.span,
                finding.site.member.clone(),
                finding.class.qualified_name().to_string(),
            );
            let value = AbsentMemberFindingValue {
                id: absent_member_finding_id(
                    &finding.site.file,
                    finding.site.span,
                    &finding.site.member,
                    finding.class.qualified_name(),
                ),
                file: finding.site.file.clone(),
                range: source_range(finding.site.span),
                member: finding.site.member.to_string(),
                class: finding.class.qualified_name().to_string(),
                roots: vec![AbsentMemberRootEvidence {
                    root_procedure_id: super::semantic::procedure_wire_id(&finding.root),
                    origin_file: finding.origin.file.clone(),
                    origin_range: source_range(finding.origin.span),
                    caller: caller.clone(),
                    witness: finding.witness.clone(),
                }],
            };
            if let Some(index) = seen.get(&key).copied() {
                rows[index].merge_evidence(value);
            } else {
                seen.insert(key, rows.len());
                rows.push(value);
            }
        }
        self.work.finding_rows = self
            .work
            .finding_rows
            .saturating_add(saturating_u64(rows.len()));
        rows
    }

    pub(super) fn absent_member_witnesses(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        finding: &AbsentMemberFindingValue,
        traversal: &brokk_bifrost_rql::WitnessTraversal,
        limits: CodeQueryValueFlowLimits,
    ) -> Vec<AbsentMemberWitnessValue> {
        let max_steps = traversal
            .max_steps
            .unwrap_or(limits.max_witness_steps)
            .min(limits.max_witness_steps);
        let max_bytes = traversal
            .max_bytes
            .unwrap_or(limits.max_witness_bytes)
            .min(limits.max_witness_bytes);
        let mut rows = Vec::new();
        for (witness_index, root) in finding.roots.iter().enumerate() {
            let key = AbsentMemberWitnessProjectionKey {
                finding_id: finding.id.clone(),
                root_procedure_id: root.root_procedure_id.clone(),
                witness_index,
                max_steps,
                max_bytes,
            };
            if let Some(cached) = self.witness_projection_cache.get(&key) {
                if let Some(row) = cached {
                    rows.push(row.clone());
                }
                continue;
            }

            let remaining_witnesses = limits
                .max_witnesses
                .saturating_sub(usize::try_from(self.work.witnesses).unwrap_or(usize::MAX));
            if remaining_witnesses == 0 {
                // Cache the omission as well as the row. A repeated pipeline
                // branch must not inflate the omitted count or diagnostics
                // after this aggregate cap has already been observed.
                self.record_witness_budget(1);
                self.witness_projection_cache.insert(key, None);
                continue;
            }
            let remaining_steps = limits
                .max_total_witness_steps
                .saturating_sub(usize::try_from(self.work.witness_steps).unwrap_or(usize::MAX));
            let remaining_bytes = limits
                .max_total_witness_bytes
                .saturating_sub(usize::try_from(self.work.witness_bytes).unwrap_or(usize::MAX));
            // This only projects already retained evidence. Do not charge old
            // reconstruction work again or spend an evidence-expansion budget.
            let public = super::witness_projection::public_absent_member_witness(
                workspace,
                finding,
                root,
                witness_index,
                max_steps.min(remaining_steps),
                max_bytes.min(remaining_bytes),
                &mut self.witness_render_cache,
            );
            if let Err(error) = &root.witness {
                self.record_witness_unavailable(error);
            }
            if public.truncated {
                self.record_witness_truncated(public.omitted_steps_lower_bound);
            }
            self.work.witnesses = self.work.witnesses.saturating_add(1);
            self.work.witness_steps = self
                .work
                .witness_steps
                .saturating_add(saturating_u64(public.steps.len()));
            self.work.witness_bytes = self
                .work
                .witness_bytes
                .saturating_add(saturating_u64(public.retained_bytes));
            let row = AbsentMemberWitnessValue {
                public,
                file: finding.file.clone(),
                byte_span: finding.range.start_byte..finding.range.end_byte,
            };
            self.witness_projection_cache.insert(key, Some(row.clone()));
            rows.push(row);
        }
        rows
    }

    fn record_witness_budget(&mut self, omitted_lower_bound: usize) {
        self.work.witness_truncated = true;
        self.work.omitted_witnesses = self
            .work
            .omitted_witnesses
            .saturating_add(saturating_u64(omitted_lower_bound));
        self.push_diagnostic(
            CodeQueryDiagnosticCode::TypeFlowWitnessTruncated,
            format!(
                "absent-member witness projection omitted at least {omitted_lower_bound} witness(es)"
            ),
        );
    }

    fn record_witness_truncated(&mut self, omitted_lower_bound: usize) {
        self.work.witness_truncated = true;
        self.push_diagnostic(
            CodeQueryDiagnosticCode::TypeFlowWitnessTruncated,
            format!(
                "absent-member witness projection omitted at least {omitted_lower_bound} step(s)"
            ),
        );
    }

    fn record_witness_unavailable(&mut self, error: &SummaryWitnessError) {
        self.push_diagnostic(
            CodeQueryDiagnosticCode::TypeFlowWitnessUnavailable,
            format!(
                "absent-member witness unavailable: {}",
                bounded_reason(&error.to_string())
            ),
        );
    }

    fn solve(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        procedure: &SemanticProcedureValue,
        semantic_budget: &mut SemanticBudget,
        limits: CodeQueryValueFlowLimits,
        cancellation: &CancellationToken,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Option<CachedTypeFlowAnalysis> {
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
            active_semantic_model_snapshot.clone(),
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
                let field_slot_cache = self.summary_state.field_slot_indexes();
                let acquired = FieldSlotIndex::acquire(
                    workspace,
                    adapter,
                    provider_behavior,
                    active_semantic_model_snapshot.clone(),
                    &field_slot_cache,
                    &mut field_slot_budget,
                    cancellation,
                );
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
                match acquired {
                    Ok(acquired) => {
                        match acquired.kind {
                            FieldSlotIndexAcquisitionKind::MemoryHit => {
                                self.work.field_slot_memory_hits =
                                    self.work.field_slot_memory_hits.saturating_add(1);
                            }
                            FieldSlotIndexAcquisitionKind::PersistentHit => {
                                self.work.field_slot_persistence_hits =
                                    self.work.field_slot_persistence_hits.saturating_add(1);
                            }
                            FieldSlotIndexAcquisitionKind::Built => {
                                self.work.field_slot_builds =
                                    self.work.field_slot_builds.saturating_add(1);
                                match acquired.miss_reason {
                                    Some(FieldSlotIndexMissReason::KeyMiss) => {
                                        self.work.field_slot_persistence_misses = self
                                            .work
                                            .field_slot_persistence_misses
                                            .saturating_add(1);
                                    }
                                    Some(
                                        FieldSlotIndexMissReason::PersistenceValidation
                                        | FieldSlotIndexMissReason::PersistenceReplayBudget,
                                    ) => {
                                        self.work.field_slot_persistence_rejections = self
                                            .work
                                            .field_slot_persistence_rejections
                                            .saturating_add(1);
                                    }
                                    Some(
                                        FieldSlotIndexMissReason::NoSemanticKey
                                        | FieldSlotIndexMissReason::NoPersistentStore
                                        | FieldSlotIndexMissReason::MemoryReplayBudget
                                        | FieldSlotIndexMissReason::StoreFailure,
                                    )
                                    | None => {}
                                }
                            }
                        }
                        if acquired.published {
                            self.work.field_slot_publications =
                                self.work.field_slot_publications.saturating_add(1);
                        }
                        let index = acquired.index;
                        if index.semantic_budget_exhausted() {
                            self.semantic_budget_exhausted = true;
                            let detail = index.semantic_budget_exhaustion().map_or_else(
                                || "bounded adapter class resolution".to_string(),
                                |exhaustion| exhaustion.to_string(),
                            );
                            self.push_diagnostic(
                                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                                format!(
                                    "class-set field index exceeded its semantic budget: {}",
                                    detail
                                ),
                            );
                        }
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
            Some(result @ CachedTypeFlowAnalysis::Live { .. })
            | Some(result @ CachedTypeFlowAnalysis::FindingFreeRows(_)) => {
                self.work.cache_hits = self.work.cache_hits.saturating_add(1);
                Some(result)
            }
            Some(CachedTypeFlowAnalysis::Failed) => {
                self.work.cache_hits = self.work.cache_hits.saturating_add(1);
                None
            }
            None => {
                let persistent_key = if field_slots.semantic_budget_exhausted() {
                    None
                } else {
                    root_result_persistence_key(
                        workspace,
                        adapter,
                        provider_behavior,
                        &field_slots,
                        &procedure.handle,
                        active_semantic_model_snapshot.as_deref(),
                        limits,
                        semantic_budget.limits(),
                    )
                };
                let mut persistent_store_failed = false;
                if let (Some(store), Some(persistent_key)) =
                    (workspace.store(), persistent_key.as_ref())
                {
                    match store.finding_free_class_set_root_result(
                        persistent_key,
                        limits.max_retained_relations,
                        limits.max_retained_bytes,
                        cancellation,
                    ) {
                        Ok(ClassSetRootResultLookup::Hit(persisted))
                            if persisted.rows.len() <= limits.max_retained_relations
                                && persisted.retained_bytes() <= limits.max_retained_bytes =>
                        {
                            let rows: Arc<[ClassSetRowValue]> =
                                persisted_class_set_rows(procedure.file(), *persisted).into();
                            self.work.root_result_persistence_hits =
                                self.work.root_result_persistence_hits.saturating_add(1);
                            let cached = CachedTypeFlowAnalysis::FindingFreeRows(rows);
                            self.cache.insert(cache_key, cached.clone());
                            return Some(cached);
                        }
                        Ok(
                            ClassSetRootResultLookup::Hit(_)
                            | ClassSetRootResultLookup::Rejected(_),
                        ) => {
                            self.work.root_result_persistence_rejections = self
                                .work
                                .root_result_persistence_rejections
                                .saturating_add(1);
                        }
                        Ok(ClassSetRootResultLookup::Miss) => {
                            self.work.root_result_persistence_misses =
                                self.work.root_result_persistence_misses.saturating_add(1);
                        }
                        Err(_) if cancellation.is_cancelled() => {
                            self.push_diagnostic(
                                CodeQueryDiagnosticCode::Cancelled,
                                "class-set root-result hydration was cancelled".to_string(),
                            );
                            self.cache.insert(cache_key, CachedTypeFlowAnalysis::Failed);
                            return None;
                        }
                        Err(_) => {
                            self.work.root_result_store_failures =
                                self.work.root_result_store_failures.saturating_add(1);
                            persistent_store_failed = true;
                        }
                    }
                }
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
                    active_semantic_model_snapshot,
                    CLOSURE_LIMITS,
                    FeedbackLimits::default(),
                    self.value_flow_cache.clone(),
                    self.summary_state.clone(),
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
                        self.work.summary_cache_hits = self
                            .work
                            .summary_cache_hits
                            .saturating_add(result.reusable_summary_hits as u64);
                        self.work.summary_cache_misses = self
                            .work
                            .summary_cache_misses
                            .saturating_add(result.reusable_summary_misses as u64);
                        self.work.root_summary_cache_hits = self
                            .work
                            .root_summary_cache_hits
                            .saturating_add(result.reusable_root_summary_hits as u64);
                        self.work.root_summary_observation_rejections = self
                            .work
                            .root_summary_observation_rejections
                            .saturating_add(
                                result.reusable_root_summary_observation_rejections as u64,
                            );
                        self.work.published_summaries = self
                            .work
                            .published_summaries
                            .saturating_add(result.published_summaries as u64);
                        self.work.summary_profile = self
                            .work
                            .summary_profile
                            .saturating_add(result.summary_profile);
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
                        let projected_rows = if !persistent_store_failed
                            && result.persistence_status == TypeFlowRootPersistenceStatus::Eligible
                            && result.findings.is_empty()
                            && let Some(persistent_key) = persistent_key.as_ref()
                        {
                            let projected: Arc<[ClassSetRowValue]> =
                                project_class_sets(&result).into();
                            let publication = self.publish_finding_free_root_result(
                                workspace,
                                persistent_key,
                                &result,
                                &projected,
                                limits,
                                cancellation,
                            );
                            if publication == RootResultPublicationOutcome::Cancelled {
                                self.push_diagnostic(
                                    CodeQueryDiagnosticCode::Cancelled,
                                    "class-set root-result publication was cancelled".to_string(),
                                );
                                self.cache.insert(cache_key, CachedTypeFlowAnalysis::Failed);
                                return None;
                            }
                            Some(projected)
                        } else {
                            None
                        };
                        let cached = CachedTypeFlowAnalysis::Live {
                            result: Arc::new(result),
                            projected_rows,
                        };
                        self.cache.insert(cache_key, cached.clone());
                        Some(cached)
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

    fn publish_finding_free_root_result(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        key: &FindingFreeClassSetRootKey,
        result: &TypeFlowRootResult,
        projected: &[ClassSetRowValue],
        limits: CodeQueryValueFlowLimits,
        cancellation: &CancellationToken,
    ) -> RootResultPublicationOutcome {
        if result.persistence_status != TypeFlowRootPersistenceStatus::Eligible
            || !result.findings.is_empty()
        {
            return RootResultPublicationOutcome::Continued;
        }
        let Some(store) = workspace.store() else {
            return RootResultPublicationOutcome::Continued;
        };
        let Some(current_workspace) = workspace.analyzer().workspace_content_identity() else {
            return RootResultPublicationOutcome::Continued;
        };
        if current_workspace.as_bytes() != &key.generation.workspace_content_digest {
            return RootResultPublicationOutcome::Continued;
        }
        let attachment =
            match workspace.semantic_artifact_store_attachment(result.root.artifact().key()) {
                Ok(Some(attachment)) => attachment,
                Ok(None) => return RootResultPublicationOutcome::Continued,
                Err(_) => {
                    self.work.root_result_store_failures =
                        self.work.root_result_store_failures.saturating_add(1);
                    return RootResultPublicationOutcome::Continued;
                }
            };
        if projected.len() > limits.max_retained_relations {
            return RootResultPublicationOutcome::Continued;
        }
        let persisted_rows = projected
            .iter()
            .enumerate()
            .map(|(ordinal, row)| persisted_class_set_row(ordinal, row))
            .collect::<Option<Vec<_>>>();
        let Some(persisted_rows) = persisted_rows else {
            return RootResultPublicationOutcome::Continued;
        };
        let persisted =
            match FindingFreeClassSetRootResult::try_new(key.clone(), attachment, persisted_rows) {
                Ok(persisted) if persisted.retained_bytes() <= limits.max_retained_bytes => {
                    persisted
                }
                Ok(_) | Err(_) => {
                    return RootResultPublicationOutcome::Continued;
                }
            };
        match store.publish_finding_free_class_set_root_result(persisted, cancellation) {
            Ok(true) => {
                self.work.root_result_publications =
                    self.work.root_result_publications.saturating_add(1);
                RootResultPublicationOutcome::Continued
            }
            Ok(false) => RootResultPublicationOutcome::Continued,
            Err(_) if cancellation.is_cancelled() => RootResultPublicationOutcome::Cancelled,
            Err(_) => {
                self.work.root_result_store_failures =
                    self.work.root_result_store_failures.saturating_add(1);
                RootResultPublicationOutcome::Continued
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

    pub(super) fn work(&self) -> CodeQueryTypeFlowWork {
        let provider = self
            .value_flow_cache
            .stats()
            .saturating_sub(self.provider_stats_baseline);
        CodeQueryTypeFlowWork {
            snapshot_cache_hits: provider.snapshot_hits,
            snapshot_cache_misses: provider.snapshot_misses,
            dispatch_cache_hits: provider.dispatch_hits,
            dispatch_cache_misses: provider.dispatch_misses,
            binding_cache_hits: provider.binding_hits,
            binding_cache_misses: provider.binding_misses,
            ..self.work
        }
    }

    pub(super) const fn semantic_budget_exhausted(&self) -> bool {
        self.semantic_budget_exhausted
    }
}

#[allow(clippy::too_many_arguments)]
fn root_result_persistence_key(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    provider_behavior: IcfgProviderBehaviorIdentity,
    field_slots: &FieldSlotIndex,
    root: &ProcedureHandle,
    active_semantic_model_snapshot: Option<&ActiveSemanticModelSnapshot>,
    limits: CodeQueryValueFlowLimits,
    semantic_limits: SemanticWork,
) -> Option<FindingFreeClassSetRootKey> {
    if workspace.store().is_none_or(|store| store.is_ephemeral()) {
        return None;
    }
    let workspace_content = workspace.analyzer().workspace_content_identity()?;
    let active_pack = active_semantic_model_pack_digest(active_semantic_model_snapshot);
    let semantics = root_result_semantics_digest(adapter, limits, semantic_limits);
    Some(FindingFreeClassSetRootKey {
        generation: ClassSetRootResultGenerationKey {
            language: adapter.language(),
            workspace_content_digest: *workspace_content.as_bytes(),
            provider_behavior_digest: *provider_behavior.digest().as_bytes(),
            active_pack_digest: *active_pack.as_bytes(),
            field_slots_digest: *field_slots.digest().as_bytes(),
            semantics_digest: *semantics.as_bytes(),
            representation_version: ROOT_RESULT_REPRESENTATION_VERSION,
        },
        root_public_digest: *procedure_public_digest(root).as_bytes(),
    })
}

fn root_result_semantics_digest(
    adapter: &dyn TypeFlowAdapter,
    limits: CodeQueryValueFlowLimits,
    semantic_limits: SemanticWork,
) -> StableDigest {
    let mut digest = LengthDelimitedDigest::new(b"bifrost-class-set-root-result-semantics-v1");
    let adapter_version = adapter.semantics_version();
    digest.push(adapter_version.name().as_bytes());
    digest.push(adapter_version.fingerprint().as_bytes());
    digest.push(SemanticIrVersion::current().as_bytes());
    digest.push(ROOT_RESULT_ALGORITHM_ID);
    digest.push(b"rql-class-set-projection-v1");
    digest.push(b"bifrost.code_query.class_set_row.v1");
    push_usize(&mut digest, CLOSURE_LIMITS.max_procedures);
    push_usize(&mut digest, FeedbackLimits::default().max_iterations());
    let plan_config = DataflowQueryPlanConfig::default();
    let direction = match plan_config.direction() {
        DataflowDirectionRequest::Auto => "auto",
        DataflowDirectionRequest::Forward => "forward",
        DataflowDirectionRequest::Backward => "backward",
    };
    digest.push(direction.as_bytes());
    digest.push(&[plan_config.minimum_backward_savings_percent()]);
    for dimension in SolverBudgetDimension::ALL {
        digest.push(dimension.label().as_bytes());
        push_usize(&mut digest, limits.solver_work.get(dimension));
    }
    for value in [
        limits.max_retained_relations,
        limits.max_retained_bytes,
        limits.max_endpoints,
        limits.max_witnesses,
        limits.max_witness_steps,
        limits.max_witness_expansions,
        limits.max_witness_bytes,
        limits.max_total_witness_steps,
        limits.max_total_witness_expansions,
        limits.max_total_witness_bytes,
    ] {
        push_usize(&mut digest, value);
    }
    for dimension in SemanticBudgetDimension::ALL {
        digest.push(dimension.label().as_bytes());
        push_usize(&mut digest, semantic_limits.get(dimension));
    }
    digest.finish()
}

const ROOT_RESULT_ALGORITHM_ID: &[u8] = b"type-flow-root-algorithm-v5";

fn push_usize(digest: &mut LengthDelimitedDigest, value: usize) {
    digest.push(
        &u64::try_from(value)
            .expect("bounded type-flow configuration fits in u64")
            .to_le_bytes(),
    );
}

fn project_class_sets(result: &TypeFlowRootResult) -> Vec<ClassSetRowValue> {
    let root_procedure_id = procedure_public_digest(&result.root).to_string();
    // A call-shaped access `x.foo()` legitimately produces a Call sink and a
    // Load sink at the same durable identity (file, span, member). The row
    // surface answers one row per (member access site, atom), so merge those
    // sinks exactly once before either live or durable projection.
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
        let portable_path = WorkspaceRelativePath::try_from_path(set.file.rel_path()).ok();
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
                    portable_path.as_ref(),
                    set.span,
                    &set.member,
                    &class,
                    &origin,
                ),
                file: set.file.clone(),
                range,
                span: set.span,
                portable_path: portable_path.clone(),
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
                    portable_path.as_ref(),
                    set.span,
                    &set.member,
                    "",
                    &origin,
                ),
                file: set.file.clone(),
                range,
                span: set.span,
                portable_path: portable_path.clone(),
                member: set.member.clone(),
                class: None,
                origin,
                status: set.status.label(),
            });
        }
    }
    let all_paths_portable = rows.iter().all(|row| row.portable_path.is_some());
    rows.sort_by(|left, right| {
        let path_order = if all_paths_portable {
            left.portable_path
                .as_ref()
                .expect("every projected path was checked above")
                .cmp(
                    right
                        .portable_path
                        .as_ref()
                        .expect("every projected path was checked above"),
                )
        } else {
            left.file.rel_path().cmp(right.file.rel_path())
        };
        path_order
            .then_with(|| left.span.cmp(&right.span))
            .then_with(|| left.member.cmp(&right.member))
            .then_with(|| class_set_row_atom_order(left).cmp(&class_set_row_atom_order(right)))
            .then_with(|| left.status.cmp(right.status))
    });
    rows.dedup_by(|left, right| {
        left.file == right.file
            && left.span == right.span
            && left.member == right.member
            && left.class == right.class
            && left.origin == right.origin
            && left.status == right.status
    });
    rows
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ClassSetRowAtomOrder<'a> {
    Workspace(&'a str),
    External(&'a str),
    Unknown(PersistedClassSetUnknownReason),
}

fn class_set_row_atom_order(row: &ClassSetRowValue) -> ClassSetRowAtomOrder<'_> {
    match (row.origin.as_str(), row.class.as_deref()) {
        ("workspace", Some(class)) => ClassSetRowAtomOrder::Workspace(class),
        ("external", Some(class)) => ClassSetRowAtomOrder::External(class),
        (origin, None) => ClassSetRowAtomOrder::Unknown(
            PersistedClassSetUnknownReason::from_label(
                origin
                    .strip_prefix("unknown:")
                    .expect("Unknown origins carry their typed reason label"),
            )
            .expect("the live and durable Unknown vocabularies stay aligned"),
        ),
        _ => unreachable!("live class-set projection preserves atom pairing"),
    }
}

fn persisted_class_set_row(
    ordinal: usize,
    row: &ClassSetRowValue,
) -> Option<PersistedClassSetRootRow> {
    let atom = persisted_class_set_atom(row);
    Some(PersistedClassSetRootRow {
        ordinal: u32::try_from(ordinal).ok()?,
        relative_path: row.portable_path.as_ref()?.as_path().to_path_buf(),
        span: row.span,
        member: row.member.clone().into_boxed_str(),
        atom,
        status: PersistedClassSetStatus::from_label(row.status)?,
    })
}

fn persisted_class_set_atom(row: &ClassSetRowValue) -> PersistedClassSetAtom {
    match (row.origin.as_str(), row.class.as_deref()) {
        ("workspace", Some(class)) => {
            PersistedClassSetAtom::WorkspaceClass(class.to_owned().into_boxed_str())
        }
        ("external", Some(class)) => {
            PersistedClassSetAtom::ExternalClass(class.to_owned().into_boxed_str())
        }
        (origin, None) => PersistedClassSetAtom::Unknown(
            PersistedClassSetUnknownReason::from_label(
                origin
                    .strip_prefix("unknown:")
                    .expect("Unknown origins carry their typed reason label"),
            )
            .expect("the live and durable Unknown vocabularies stay aligned"),
        ),
        _ => unreachable!("live class-set projection preserves atom pairing"),
    }
}

fn persisted_class_set_rows(
    root_file: &ProjectFile,
    persisted: FindingFreeClassSetRootResult,
) -> Vec<ClassSetRowValue> {
    let root_procedure_id = StableDigest::from_array(persisted.key.root_public_digest).to_string();
    persisted
        .rows
        .into_iter()
        .map(|row| {
            let portable_path = WorkspaceRelativePath::try_from_path(&row.relative_path)
                .expect("validated persisted rows carry portable relative paths");
            let file = root_file.with_rel_path(&row.relative_path);
            let (class, origin) = match row.atom {
                PersistedClassSetAtom::WorkspaceClass(class) => {
                    (Some(String::from(class)), "workspace".to_string())
                }
                PersistedClassSetAtom::ExternalClass(class) => {
                    (Some(String::from(class)), "external".to_string())
                }
                PersistedClassSetAtom::Unknown(reason) => {
                    (None, format!("unknown:{}", reason.label()))
                }
            };
            ClassSetRowValue {
                id: class_set_row_id(
                    &root_procedure_id,
                    &file,
                    Some(&portable_path),
                    row.span,
                    &row.member,
                    class.as_deref().unwrap_or(""),
                    &origin,
                ),
                file,
                range: source_range(row.span),
                span: row.span,
                portable_path: Some(portable_path),
                member: String::from(row.member),
                class,
                origin,
                status: row.status.label(),
            }
        })
        .collect()
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
    portable_path: Option<&WorkspaceRelativePath>,
    span: SourceSpan,
    member: &str,
    class: &str,
    origin: &str,
) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.class_set_row.v1");
    digest.push(root_procedure_id.as_bytes());
    let native_path;
    let path = match portable_path {
        Some(path) => path.as_str(),
        None => {
            native_path = file.rel_path().display().to_string();
            &native_path
        }
    };
    digest.push(path.as_bytes());
    digest.push(&span.start_byte().to_le_bytes());
    digest.push(&span.end_byte().to_le_bytes());
    digest.push(member.as_bytes());
    digest.push(class.as_bytes());
    digest.push(origin.as_bytes());
    digest.finish().to_string()
}

fn absent_member_finding_id(
    file: &ProjectFile,
    span: SourceSpan,
    member: &str,
    class: &str,
) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.absent_member_finding.v2");
    digest.push(rel_path_string(file).as_bytes());
    digest.push(&span.start_byte().to_le_bytes());
    digest.push(&span.end_byte().to_le_bytes());
    digest.push(member.as_bytes());
    digest.push(class.as_bytes());
    digest.finish().to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        AbsentMemberFindingValue, AbsentMemberRootEvidence, ROOT_RESULT_ALGORITHM_ID,
        TypeFlowQueryState, field_slot_semantic_limits, root_result_semantics_digest,
    };
    use crate::analyzer::semantic::{
        ProcedureHandle, SemanticBudget, SemanticRequest, SemanticWork, type_flow_adapter,
    };
    use crate::analyzer::{AnalyzerConfig, Language, Range, WorkspaceAnalyzer};
    use crate::cancellation::CancellationToken;
    use crate::structural::search::tests::inline_project::{
        BuiltInlineTestProject, InlineTestProject,
    };
    use crate::structural::search::{
        CodeQueryAbsentMemberWitnessStatus, CodeQueryDiagnosticCode, CodeQueryValueFlowLimits,
    };
    use brokk_bifrost_flow::dataflow::{
        DataflowEdge, DataflowOutput, DistributiveDataflowProblem, SolverBudget,
        SummaryDataflowResult, SummarySolveInput, SummaryWitness, SummaryWitnessError,
        WitnessReconstructionLimits, WitnessRetentionLimits, solve_with_summaries,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    enum WitnessFact {
        Zero,
        Seed,
        Extra,
    }

    struct WitnessProblem;

    impl WitnessProblem {
        fn emit(fact: WitnessFact, out: &mut dyn DataflowOutput<WitnessFact>) {
            if out.emit(fact) {
                let _ = out.emit(WitnessFact::Extra);
            }
        }
    }

    impl DistributiveDataflowProblem for WitnessProblem {
        type Fact = WitnessFact;

        fn zero_fact(&self) -> Self::Fact {
            WitnessFact::Zero
        }

        fn normal_flow(
            &self,
            _edge: DataflowEdge<'_, Self::Fact>,
            fact: Self::Fact,
            out: &mut dyn DataflowOutput<Self::Fact>,
        ) {
            Self::emit(fact, out);
        }

        fn call_flow(
            &self,
            _edge: DataflowEdge<'_, Self::Fact>,
            fact: Self::Fact,
            out: &mut dyn DataflowOutput<Self::Fact>,
        ) {
            Self::emit(fact, out);
        }

        fn return_flow(
            &self,
            _edge: DataflowEdge<'_, Self::Fact>,
            fact: Self::Fact,
            out: &mut dyn DataflowOutput<Self::Fact>,
        ) {
            Self::emit(fact, out);
        }

        fn call_to_return_flow(
            &self,
            _edge: DataflowEdge<'_, Self::Fact>,
            fact: Self::Fact,
            out: &mut dyn DataflowOutput<Self::Fact>,
        ) {
            Self::emit(fact, out);
        }

        fn exceptional_flow(
            &self,
            _edge: DataflowEdge<'_, Self::Fact>,
            fact: Self::Fact,
            out: &mut dyn DataflowOutput<Self::Fact>,
        ) {
            Self::emit(fact, out);
        }
    }

    fn witness_workspace() -> (BuiltInlineTestProject, WorkspaceAnalyzer, ProcedureHandle) {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "lib.rs",
                "pub fn root(value: i32) -> i32 {\n    value + 1\n}\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("lib.rs");
        let cancellation = CancellationToken::default();
        let mut semantic_budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
            )
            .expect("Rust witness fixture materializes")
            .available_value()
            .cloned()
            .expect("Rust witness fixture remains available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .iter()
                    .any(|segment| segment.name() == Some("root"))
            })
            .expect("Rust witness fixture contains root");
        let root = artifact
            .procedure_handle(procedure.id())
            .expect("root procedure handle");
        (project, workspace, root)
    }

    fn solve_witness(
        workspace: &WorkspaceAnalyzer,
        root: &ProcedureHandle,
        retention: WitnessRetentionLimits,
        witness_relations: usize,
    ) -> Result<SummaryWitness, SummaryWitnessError> {
        let provider = workspace.icfg_provider();
        let cancellation = CancellationToken::default();
        let mut solver_limits = SolverBudget::default().limits();
        solver_limits.witness_relations = witness_relations;
        let mut solver_budget = SolverBudget::new(solver_limits);
        let mut semantic_budget = SemanticBudget::default();
        let result: SummaryDataflowResult<WitnessFact> = solve_with_summaries(
            SummarySolveInput::new(root, &[WitnessFact::Seed]).with_witness_retention(retention),
            &provider,
            &WitnessProblem,
            &mut semantic_budget,
            &mut brokk_bifrost_flow::dataflow::DataflowRequest::new(
                &mut solver_budget,
                &cancellation,
            ),
        )
        .expect("bounded witness fixture solves");
        let exit = root
            .point_handle(root.semantics().normal_exit_point())
            .expect("root normal exit");
        let reached = result
            .reached_at(&exit)
            .find(|reached| result.fact(reached.fact()) == Some(&WitnessFact::Seed))
            .expect("seed reaches root exit");
        let quality = reached
            .path_qualities()
            .iter()
            .next()
            .expect("seed retains a path quality");
        result.witness_for_reached(reached, quality, WitnessReconstructionLimits::default())
    }

    fn absent_finding(
        project: &BuiltInlineTestProject,
        id: &str,
        witness: Result<SummaryWitness, SummaryWitnessError>,
    ) -> AbsentMemberFindingValue {
        let file = project.file("lib.rs");
        let range = Range {
            start_byte: 0,
            end_byte: 1,
            start_line: 0,
            end_line: 0,
        };
        AbsentMemberFindingValue {
            id: id.to_owned(),
            file: file.clone(),
            range,
            member: "missing".to_owned(),
            class: "app.Missing".to_owned(),
            roots: vec![AbsentMemberRootEvidence {
                root_procedure_id: "root".to_owned(),
                origin_file: file,
                origin_range: range,
                caller: "root".to_owned(),
                witness,
            }],
        }
    }

    fn assert_diagnostic(state: &mut TypeFlowQueryState, code: CodeQueryDiagnosticCode) {
        assert!(
            state
                .take_diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == code),
            "expected {code:?} diagnostic"
        );
    }

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

    #[test]
    fn root_result_semantics_rotates_with_solver_projection_and_semantic_limits() {
        assert_eq!(
            ROOT_RESULT_ALGORITHM_ID, b"type-flow-root-algorithm-v5",
            "class-preserving transfers must not reuse operand-dependency root results"
        );
        let adapter = type_flow_adapter(Language::Python).expect("Python supports type flow");
        let limits = CodeQueryValueFlowLimits::default();
        let semantic = SemanticWork::default_limits();
        let baseline = root_result_semantics_digest(adapter, limits, semantic);

        let mut solver = limits;
        solver.solver_work.interned_facts -= 1;
        assert_ne!(
            root_result_semantics_digest(adapter, solver, semantic),
            baseline
        );

        let mut projection = limits;
        projection.max_retained_relations -= 1;
        assert_ne!(
            root_result_semantics_digest(adapter, projection, semantic),
            baseline
        );

        let mut semantic = semantic;
        semantic.source_mappings -= 1;
        assert_ne!(
            root_result_semantics_digest(adapter, limits, semantic),
            baseline
        );
    }

    #[test]
    fn absent_member_witness_state_preserves_typed_retention_unavailability() {
        let (project, workspace, root) = witness_workspace();
        let unavailable = solve_witness(&workspace, &root, WitnessRetentionLimits::disabled(), 0);
        assert_eq!(unavailable, Err(SummaryWitnessError::RetentionDisabled));
        let finding = absent_finding(&project, "finding-unavailable", unavailable);

        let mut state = TypeFlowQueryState::default();
        let rows = state.absent_member_witnesses(
            &workspace,
            &finding,
            &crate::WitnessTraversal::default(),
            CodeQueryValueFlowLimits::default(),
        );
        assert_eq!(rows.len(), 1);
        let row = &rows[0].public;
        assert_eq!(
            row.witness_status,
            CodeQueryAbsentMemberWitnessStatus::Unavailable
        );
        assert!(row.steps.is_empty());
        assert_eq!(row.retained_bytes, 0);
        assert_eq!(
            row.quality.proof,
            crate::structural::search::CodeQuerySemanticProof::Unproven
        );
        assert_eq!(
            row.quality.completeness,
            crate::structural::search::CodeQuerySemanticCompleteness::Partial
        );
        assert!(row.unavailable_reason.is_some());
        assert_diagnostic(
            &mut state,
            CodeQueryDiagnosticCode::TypeFlowWitnessUnavailable,
        );
        assert_eq!(state.work().witness_expansions, 0);
    }

    #[test]
    fn absent_member_witness_state_distinguishes_retention_marker_from_unavailable() {
        let (project, workspace, root) = witness_workspace();
        let marker = solve_witness(
            &workspace,
            &root,
            WitnessRetentionLimits::best_effort(1, 1, 64 * 1024 * 1024)
                .expect("positive best-effort retention"),
            0,
        )
        .expect("best-effort retention returns a typed marker");
        assert!(marker.retention_truncated());
        assert!(marker.steps().is_empty());
        let finding = absent_finding(&project, "finding-marker", Ok(marker));

        let mut state = TypeFlowQueryState::default();
        let rows = state.absent_member_witnesses(
            &workspace,
            &finding,
            &crate::WitnessTraversal::default(),
            CodeQueryValueFlowLimits::default(),
        );
        assert_eq!(rows.len(), 1);
        let row = &rows[0].public;
        assert_eq!(
            row.witness_status,
            CodeQueryAbsentMemberWitnessStatus::Truncated
        );
        assert!(row.truncated);
        assert!(row.unavailable_reason.is_none());
        assert_eq!(row.steps.len(), 0);
        assert_eq!(
            row.quality.completeness,
            crate::structural::search::CodeQuerySemanticCompleteness::Partial
        );
        assert_diagnostic(
            &mut state,
            CodeQueryDiagnosticCode::TypeFlowWitnessTruncated,
        );
        assert_eq!(state.work().witness_expansions, 0);
    }

    #[test]
    fn absent_member_witness_state_honors_zero_traversal_limits() {
        let (project, workspace, root) = witness_workspace();
        let retained = solve_witness(
            &workspace,
            &root,
            WitnessRetentionLimits::new(8).expect("positive strict retention"),
            4096,
        )
        .expect("strict retention keeps the fixture witness");
        assert!(!retained.steps().is_empty());

        for traversal in [
            crate::WitnessTraversal {
                max_steps: Some(0),
                max_bytes: None,
            },
            crate::WitnessTraversal {
                max_steps: None,
                max_bytes: Some(0),
            },
        ] {
            let finding = absent_finding(&project, "finding-zero", Ok(retained.clone()));
            let mut state = TypeFlowQueryState::default();
            let rows = state.absent_member_witnesses(
                &workspace,
                &finding,
                &traversal,
                CodeQueryValueFlowLimits::default(),
            );
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows[0].public.witness_status,
                CodeQueryAbsentMemberWitnessStatus::Truncated
            );
            assert!(rows[0].public.truncated);
            assert!(rows[0].public.steps.is_empty());
            assert_eq!(rows[0].public.retained_bytes, 0);
            assert_diagnostic(
                &mut state,
                CodeQueryDiagnosticCode::TypeFlowWitnessTruncated,
            );
            assert_eq!(state.work().witness_expansions, 0);
        }
    }

    #[test]
    fn absent_member_witness_projection_cache_reuses_exact_requests_only() {
        let (project, workspace, root) = witness_workspace();
        let retained = solve_witness(
            &workspace,
            &root,
            WitnessRetentionLimits::new(8).expect("positive strict retention"),
            4096,
        )
        .expect("strict retention keeps the fixture witness");
        let limits = CodeQueryValueFlowLimits {
            max_witnesses: 1,
            ..CodeQueryValueFlowLimits::default()
        };
        let finding = absent_finding(&project, "finding-cached", Ok(retained.clone()));
        let mut state = TypeFlowQueryState::default();

        let first = state.absent_member_witnesses(
            &workspace,
            &finding,
            &crate::WitnessTraversal::default(),
            limits,
        );
        let second = state.absent_member_witnesses(
            &workspace,
            &finding,
            &crate::WitnessTraversal::default(),
            limits,
        );
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].public, second[0].public);
        assert_eq!(state.work().witnesses, 1);
        assert_eq!(
            state.work().witness_steps,
            first[0].public.steps.len() as u64
        );
        assert_eq!(
            state.work().witness_bytes,
            first[0].public.retained_bytes as u64
        );
        assert!(state.take_diagnostics().is_empty());

        let request_limits = CodeQueryValueFlowLimits {
            max_witnesses: 2,
            ..CodeQueryValueFlowLimits::default()
        };
        let request_finding = absent_finding(&project, "finding-request", Ok(retained.clone()));
        let mut request_state = TypeFlowQueryState::default();
        let zero_bytes = request_state.absent_member_witnesses(
            &workspace,
            &request_finding,
            &crate::WitnessTraversal {
                max_steps: None,
                max_bytes: Some(0),
            },
            request_limits,
        );
        let full_request = request_state.absent_member_witnesses(
            &workspace,
            &request_finding,
            &crate::WitnessTraversal::default(),
            request_limits,
        );
        assert_eq!(zero_bytes.len(), 1);
        assert!(zero_bytes[0].public.steps.is_empty());
        assert_eq!(full_request.len(), 1);
        assert!(!full_request[0].public.steps.is_empty());
        assert_eq!(request_state.work().witnesses, 2);
        let zero_bytes_again = request_state.absent_member_witnesses(
            &workspace,
            &request_finding,
            &crate::WitnessTraversal {
                max_steps: None,
                max_bytes: Some(0),
            },
            request_limits,
        );
        assert_eq!(zero_bytes_again[0].public, zero_bytes[0].public);
        assert_eq!(
            request_state
                .take_diagnostics()
                .into_iter()
                .filter(|diagnostic| {
                    diagnostic.code == CodeQueryDiagnosticCode::TypeFlowWitnessTruncated
                })
                .count(),
            1
        );

        let mut distinct_roots =
            absent_finding(&project, "finding-distinct-roots", Ok(retained.clone()));
        let mut second_root = distinct_roots.roots[0].clone();
        second_root.root_procedure_id = "other-root".to_owned();
        distinct_roots.roots.push(second_root);
        let mut distinct_state = TypeFlowQueryState::default();
        let distinct = distinct_state.absent_member_witnesses(
            &workspace,
            &distinct_roots,
            &crate::WitnessTraversal::default(),
            limits,
        );
        assert_eq!(distinct.len(), 1);
        assert_eq!(distinct_state.work().witnesses, 1);
        assert_eq!(distinct_state.work().omitted_witnesses, 1);
        assert_diagnostic(
            &mut distinct_state,
            CodeQueryDiagnosticCode::TypeFlowWitnessTruncated,
        );
        let repeated_distinct = distinct_state.absent_member_witnesses(
            &workspace,
            &distinct_roots,
            &crate::WitnessTraversal::default(),
            limits,
        );
        assert_eq!(repeated_distinct.len(), 1);
        assert_eq!(distinct_state.work().witnesses, 1);
        assert_eq!(distinct_state.work().omitted_witnesses, 1);
        assert!(distinct_state.take_diagnostics().is_empty());
    }

    #[test]
    fn absent_member_witness_state_caps_rows_steps_and_bytes_across_findings() {
        let (project, workspace, root) = witness_workspace();
        let retained = solve_witness(
            &workspace,
            &root,
            WitnessRetentionLimits::new(8).expect("positive strict retention"),
            4096,
        )
        .expect("strict retention keeps the fixture witness");
        assert!(retained.work().evidence_expansions() > 0);

        let probe = absent_finding(&project, "finding-probe", Ok(retained.clone()));
        let mut probe_state = TypeFlowQueryState::default();
        let probe_row = probe_state.absent_member_witnesses(
            &workspace,
            &probe,
            &crate::WitnessTraversal::default(),
            CodeQueryValueFlowLimits::default(),
        );
        let step_cap = probe_row[0].public.steps.len();
        let byte_cap = probe_row[0].public.retained_bytes;
        assert!(step_cap > 0);
        assert!(byte_cap > 0);

        let limits = CodeQueryValueFlowLimits {
            max_witnesses: 2,
            max_total_witness_steps: step_cap,
            max_total_witness_bytes: byte_cap,
            ..CodeQueryValueFlowLimits::default()
        };
        let mut state = TypeFlowQueryState::default();
        let first = absent_finding(&project, "finding-one", Ok(retained.clone()));
        let second = absent_finding(&project, "finding-two", Ok(retained.clone()));
        let third = absent_finding(&project, "finding-three", Ok(retained));
        assert_eq!(
            state
                .absent_member_witnesses(
                    &workspace,
                    &first,
                    &crate::WitnessTraversal::default(),
                    limits,
                )
                .len(),
            1
        );
        let second_rows = state.absent_member_witnesses(
            &workspace,
            &second,
            &crate::WitnessTraversal::default(),
            limits,
        );
        assert_eq!(second_rows.len(), 1);
        assert_eq!(
            second_rows[0].public.witness_status,
            CodeQueryAbsentMemberWitnessStatus::Truncated
        );
        assert!(
            state
                .absent_member_witnesses(
                    &workspace,
                    &third,
                    &crate::WitnessTraversal::default(),
                    limits,
                )
                .is_empty()
        );

        let work = state.work();
        assert_eq!(work.witnesses, 2);
        assert_eq!(work.witness_steps, step_cap as u64);
        assert_eq!(work.witness_bytes, byte_cap as u64);
        assert_eq!(work.omitted_witnesses, 1);
        assert!(work.witness_truncated);
        assert_eq!(work.witness_expansions, 0);
        assert_diagnostic(
            &mut state,
            CodeQueryDiagnosticCode::TypeFlowWitnessTruncated,
        );
    }
}
