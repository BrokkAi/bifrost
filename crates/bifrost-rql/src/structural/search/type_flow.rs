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

use super::{DerivationExecutionCause, Incompleteness};
use std::collections::HashSet;
use std::sync::Arc;

use super::semantic::SemanticProcedureValue;
use super::witness_projection::{bounded_reason, record_omitted_witnesses, saturating_u64};
use super::{
    CodeQueryAbsentMemberWitness, CodeQueryDiagnostic, CodeQueryDiagnosticCode,
    CodeQueryExhaustedCharge, CodeQueryExhaustedRoot, CodeQueryTypeFlowWork,
    CodeQueryValueFlowLimits, MAX_DIAGNOSTIC_LIST_MESSAGE_BYTES, incomplete_diagnostic,
    push_deduplicated_diagnostic, render_exhausted_roots,
};
use crate::analyzer::common::language_for_file;
use crate::analyzer::semantic::{
    CandidateCoverage, ClassIdentity, DeclarationSegmentKind, ExactResultProducer, IcfgProvider,
    IcfgProviderBehaviorIdentity, LengthDelimitedDigest, MemberAccessKind, MemberDeclaration,
    ProcedureHandle, SemanticBudget, SemanticBudgetDimension, SemanticIrVersion,
    SemanticProcedureReference, SemanticWork, SourceMappingKind, SourceSiteKind, SourceSpan,
    StableDigest, TypeFlowAdapter, UnknownReason, WorkspaceIcfgProvider, WorkspaceRelativePath,
    type_flow_adapter,
};
use crate::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use crate::analyzer::{ProjectFile, Range, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
use crate::path_utils::rel_path_string;
use brokk_bifrost_analysis::analyzer::store::cache_budget::{
    RetainedBytes, RetainedHeap, retained_read_key,
};
use brokk_bifrost_analysis::analyzer::store::class_set_root_results::{
    ClassSetRootResultGenerationKey, ClassSetRootResultLookup, FindingFreeClassSetRootKey,
    FindingFreeClassSetRootResult, PersistedClassSetAtom, PersistedClassSetRootRow,
    PersistedClassSetStatus,
};
use brokk_bifrost_analysis::analyzer::{
    ReadKey, capture_query_reads, capture_subsumed_query_reads,
};
use brokk_bifrost_core::complete_value_cache::{
    CompleteValueAcquisition, CompleteValueCache, CompleteValuePermit,
};
use brokk_bifrost_flow::dataflow::{
    DataflowDirectionRequest, DataflowQueryPlanConfig, DataflowRequest, SolverBudget,
    SolverBudgetDimension, SolverWork, SummaryWitnessError,
};
use brokk_bifrost_flow::flow_state::procedure_public_digest;
use brokk_bifrost_flow::type_flow::{
    AbsentMemberProof, ClassSetStatus, DynamicWriteEvidence, FeedbackLimits, FieldSlotIndex,
    FieldSlotIndexAcquisitionKind, FieldSlotIndexMissReason, ProcedureRefinements,
    RootExhaustedLane, RootIncompleteEvidence, TypeFlowError, TypeFlowPlanError,
    TypeFlowRootPersistenceRejection, TypeFlowRootPersistenceStatus, TypeFlowRootResult,
    TypeFlowSitePurpose, active_semantic_model_pack_digest,
    solve_type_flow_for_root_with_refinements, sort_unknown_reasons,
};
use brokk_bifrost_flow::value_flow::{ClosureLimits, ValueFlowCache, ValueFlowCacheStatsSnapshot};

/// Bound on the procedures one root's discovered closure may hold, matching
/// the engine's own integration-test budget.
const CLOSURE_LIMITS: ClosureLimits = ClosureLimits {
    max_procedures: 512,
};
const ROOT_RESULT_REPRESENTATION_VERSION: u32 = 5;

/// Engine-owned limits for every product shared by class-set root solves.
/// Selector continuations carry this value unchanged from their parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CodeQueryRootAllotment {
    solver: SolverWork,
    semantic: SemanticWork,
}

impl CodeQueryRootAllotment {
    /// Select the same shared products used by evaluation under this allotment.
    pub fn summary_state(
        &self,
        workspace: &WorkspaceAnalyzer,
        partitions: &brokk_bifrost_flow::type_flow::TypeFlowSummaryPartitions,
    ) -> brokk_bifrost_flow::type_flow::TypeFlowSummaryState {
        partitions.select(workspace, self.solver, self.semantic)
    }

    pub fn semantic_budget(&self) -> SemanticBudget {
        SemanticBudget::new(self.semantic).expect("root allotment has positive semantic limits")
    }

    /// Derive root limits once from the original query, before any continuation.
    pub fn from_execution_limits(limits: &super::CodeQueryExecutionLimits) -> Self {
        let solver = limits.value_flow.solver_work;
        let semantic = super::semantic::semantic_budget_limits(limits.semantic);
        fn round(query: usize, default: usize) -> usize {
            let limit = query.max(default);
            let rounded = limit.checked_next_power_of_two().unwrap_or(limit);
            assert!(rounded >= default && rounded >= query);
            rounded
        }
        Self {
            solver: solver.zip_with(SolverWork::default_limits(), round),
            semantic: semantic.zip_with(SemanticWork::default_limits(), round),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TypeFlowCacheKey {
    root: SemanticProcedureReference,
    /// Separates results if this cache is ever reused across provider builds.
    provider_behavior: IcfgProviderBehaviorIdentity,
    field_slots: StableDigest,
}

// Cold scans on 2026-10-26 retained 34.4 MiB for one product per unique root
// on pallets/flask and 2.0 MiB on axios. Eviction is safe under root allotments.
const ROOT_MEMO_RETAINED_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq, Hash)]
struct TypeFlowRootMemoKey {
    root: TypeFlowCacheKey,
    allotment: CodeQueryRootAllotment,
    active_pack: StableDigest,
    workspace_content: [u8; 32],
}

/// One policy run's bounded, single-flight memo. Never retain this in
/// FlowWorkspaceState: a service reuses that state across requests.
#[derive(Clone)]
pub struct TypeFlowRootMemo {
    products: CompleteValueCache<TypeFlowRootMemoKey, TypeFlowRootProduct>,
}

impl Default for TypeFlowRootMemo {
    fn default() -> Self {
        Self {
            products: CompleteValueCache::new(
                ROOT_MEMO_RETAINED_BYTES,
                |_, product: &Arc<TypeFlowRootProduct>| {
                    product.retained_bytes().min(u32::MAX as usize) as u32
                },
            ),
        }
    }
}

type RootMemoPermit = Box<CompleteValuePermit<TypeFlowRootMemoKey, TypeFlowRootProduct>>;

enum RootProductSource {
    Solved,
    Memo,
}

enum RootProductAcquisition {
    Solve(Option<RootMemoPermit>),
    Applied(Option<CachedTypeFlowAnalysis>),
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

/// A solve that returned an error is `Owned` with the product's `failure`
/// set, so the failure travels with the product. `Failed` records this
/// query's own outcome: its lookup or publication was cancelled, or its
/// admission of the product's census was refused.
#[derive(Debug, Clone)]
enum CachedTypeFlowAnalysis {
    Owned(QueryRootProduct),
    FindingFreeRows(Arc<[ClassSetRowValue]>),
    Failed,
}

/// A query's admission ends independently of any other owner of the output.
#[derive(Debug, Clone)]
struct QueryRootProduct {
    product: Arc<TypeFlowRootProduct>,
    _owner: Arc<()>,
}

/// Query-owned observations. No field contains a lowered artifact handle.
#[derive(Debug, Clone)]
pub(super) struct OwnedTypeFlowSite {
    pub(super) procedure: SemanticProcedureReference,
    pub(super) is_generator: bool,
    pub(super) call: Option<crate::analyzer::semantic::CallSiteId>,
    pub(super) call_span: Option<SourceSpan>,
    pub(super) file: ProjectFile,
    pub(super) span: SourceSpan,
    pub(super) member: Box<str>,
    pub(super) kind: MemberAccessKind,
    pub(super) purpose: TypeFlowSitePurpose,
}

#[derive(Debug, Clone)]
pub(super) struct OwnedReceiverClassSet {
    pub(super) site: OwnedTypeFlowSite,
    pub(super) classes: Vec<(ClassIdentity, crate::analyzer::semantic::SourceSite)>,
    pub(super) constructor_origin: Option<crate::analyzer::semantic::ConstructorResultOrigin>,
    pub(super) exact_result_receiver_proven: bool,
    pub(super) member_declarations:
        Vec<(ClassIdentity, crate::analyzer::semantic::MemberLookupHit)>,
    pub(super) flow_unknown: Vec<UnknownReason>,
    pub(super) unknown: Vec<UnknownReason>,
    pub(super) dynamic_writes: Vec<DynamicWriteEvidence>,
    pub(super) status: ClassSetStatus,
}

#[derive(Debug)]
struct TypeFlowRootProduct {
    root: SemanticProcedureReference,
    failure: Option<(CodeQueryDiagnosticCode, String)>,
    projected_rows: Vec<ClassSetRowValue>,
    class_sets: Vec<OwnedReceiverClassSet>,
    findings: Vec<AbsentMemberFindingValue>,
    complete: bool,
    semantic_budget_exhausted: bool,
    incomplete_evidence: RootIncompleteEvidence,
    persistence_status: TypeFlowRootPersistenceStatus,
    work: CodeQueryTypeFlowWork,
    solver_work: SolverWork,
    semantic_work: SemanticWork,
    reads: Vec<ReadKey>,
    unattributed_reads: usize,
    execution_dependences: usize,
}

impl TypeFlowRootProduct {
    fn work_for(result: &TypeFlowRootResult) -> CodeQueryTypeFlowWork {
        CodeQueryTypeFlowWork {
            solves: 1,
            summary_cache_hits: result.reusable_summary_hits as u64,
            summary_cache_misses: result.reusable_summary_misses as u64,
            root_summary_cache_hits: result.reusable_root_summary_hits as u64,
            root_summary_observation_rejections: result.reusable_root_summary_observation_rejections
                as u64,
            published_summaries: result.published_summaries as u64,
            summary_profile: result.summary_profile,
            solver_attempts: result.solver_attempts.len() as u64,
            incomplete_roots: u64::from(!result.complete),
            ..Default::default()
        }
    }

    fn new(
        workspace: &WorkspaceAnalyzer,
        procedure: &SemanticProcedureValue,
        result: TypeFlowRootResult,
        projected_rows: Vec<ClassSetRowValue>,
        semantic_work: SemanticWork,
    ) -> Self {
        let work = Self::work_for(&result);
        let solver_work = result
            .solver_attempts
            .iter()
            .fold(SolverWork::default(), |sum, attempt| {
                sum.saturating_add(attempt.work)
            });
        let findings = project_absent_members(workspace, procedure, &result);
        let class_sets = result
            .class_sets
            .into_iter()
            .map(|set| {
                let call_span = set.site.call.and_then(|id| {
                    let semantics = set.site.procedure.semantics();
                    let call = semantics.call_site(id)?;
                    let mapping = semantics.source_mapping(call.source)?;
                    (mapping.kind == SourceMappingKind::Exact)
                        .then(|| mapping.locator.anchor().span())
                });
                OwnedReceiverClassSet {
                    site: OwnedTypeFlowSite {
                        procedure: SemanticProcedureReference::of(&set.site.procedure),
                        is_generator: set.site.procedure.semantics().properties().is_generator,
                        call: set.site.call,
                        call_span,
                        file: set.site.file,
                        span: set.site.span,
                        member: set.site.member,
                        kind: set.site.kind,
                        purpose: set.site.purpose,
                    },
                    classes: set.classes,
                    constructor_origin: set.constructor_origin,
                    exact_result_receiver_proven: set.exact_result_receiver_proven,
                    member_declarations: set.member_declarations,
                    flow_unknown: set.flow_unknown,
                    unknown: set.unknown,
                    dynamic_writes: set.dynamic_writes,
                    status: set.status,
                }
            })
            .collect();
        Self {
            root: result.root,
            failure: None,
            projected_rows,
            class_sets,
            findings,
            complete: result.complete,
            semantic_budget_exhausted: result.semantic_budget_exhausted,
            incomplete_evidence: result.incomplete_evidence,
            persistence_status: result.persistence_status,
            work,
            solver_work,
            semantic_work,
            reads: Vec::new(),
            unattributed_reads: 0,
            execution_dependences: 0,
        }
    }
}

/// Type-specific walk over the shared retained-allocation census. Core file and
/// declaration handles are charged per handle, conservatively, because their
/// Arcs are private to core; RetainedHeap deduplicates exposed Arcs by address.
fn retained_text(heap: &mut RetainedHeap, value: &String) {
    heap.add(value.capacity());
    heap.add_entries(1);
}
fn retained_file(heap: &mut RetainedHeap, value: &ProjectFile) {
    heap.add(
        value
            .retained_bytes()
            .saturating_sub(std::mem::size_of_val(value)),
    );
    heap.add_entries(1);
}
fn retained_class(heap: &mut RetainedHeap, value: &ClassIdentity) {
    match value {
        ClassIdentity::Workspace(unit) => {
            heap.add(
                unit.retained_bytes()
                    .saturating_sub(std::mem::size_of_val(unit)),
            );
            heap.add_entries(1);
        }
        ClassIdentity::External {
            qualified_name,
            symbol_id,
        } => {
            heap.add(qualified_name.len().saturating_add(symbol_id.len()));
            heap.add_entries(2);
        }
        ClassIdentity::Intrinsic { qualified_name } => {
            heap.add(qualified_name.len());
            heap.add_entries(1);
        }
    }
}
fn retained_unknown(heap: &mut RetainedHeap, values: &Vec<UnknownReason>) {
    heap.vec(values);
    for value in values {
        if let UnknownReason::UnmodeledGuard { class } = value {
            heap.add(class.len());
            heap.add_entries(1);
        }
    }
}
fn retained_dynamic(heap: &mut RetainedHeap, values: &Vec<DynamicWriteEvidence>) {
    heap.vec(values);
    for value in values {
        retained_file(heap, &value.site.file);
        if let Some(UnknownReason::UnmodeledGuard { class }) = &value.reason {
            heap.add(class.len());
            heap.add_entries(1);
        }
    }
}
fn retained_reference(heap: &mut RetainedHeap, value: &SemanticProcedureReference) {
    heap.add(value.key.path().as_str().len());
    heap.add_entries(1);
    heap.add(value.locator.path().as_str().len());
    heap.add_entries(1);
    let segments = value.locator.declaration().segments();
    heap.add(std::mem::size_of_val(segments));
    heap.add_entries(segments.len());
    for segment in segments {
        if let Some(name) = segment.name() {
            heap.add(name.len());
            heap.add_entries(1);
        }
    }
}
fn retained_symbol(heap: &mut RetainedHeap, value: &super::CodeQueryFlowSymbolSite) {
    retained_text(heap, &value.id);
    retained_text(heap, &value.path);
    heap.vec(&value.declaration);
    for segment in &value.declaration {
        if let Some(name) = &segment.name {
            retained_text(heap, name);
        }
    }
}
fn retained_event(heap: &mut RetainedHeap, value: &super::CodeQueryFlowEvent) {
    retained_text(heap, &value.id);
    retained_text(heap, &value.path);
    retained_symbol(heap, &value.site);
    retained_carrier(heap, &value.carrier);
}
fn retained_carrier(heap: &mut RetainedHeap, value: &super::CodeQueryFlowCarrierSymbol) {
    use super::CodeQueryFlowCarrierSymbol as C;
    use super::CodeQueryFlowSelectorSymbol as S;
    // Carrier trees can be deeply nested. Walk boxed children iteratively.
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            C::Value { id, site, role, .. } => {
                retained_text(heap, id);
                retained_symbol(heap, site);
                retained_text(heap, role);
            }
            C::Port { id, procedure, .. } => {
                retained_text(heap, id);
                retained_symbol(heap, procedure);
            }
            C::Allocation { id, site } | C::ScopedRoot { id, site, .. } => {
                retained_text(heap, id);
                retained_symbol(heap, site);
            }
            C::CallResult {
                id,
                call,
                result,
                callee,
            } => {
                retained_text(heap, id);
                retained_symbol(heap, call);
                retained_symbol(heap, callee);
                heap.add(std::mem::size_of::<super::CodeQueryFlowCarrierSymbol>());
                heap.add_entries(1);
                pending.push(result);
            }
            C::Location {
                id,
                root,
                selectors,
                ..
            } => {
                retained_text(heap, id);
                heap.vec(selectors);
                heap.add(std::mem::size_of::<super::CodeQueryFlowCarrierSymbol>());
                heap.add_entries(1);
                pending.push(root);
                for selector in selectors {
                    match selector {
                        S::Field { field } => retained_symbol(heap, field),
                        S::Property { key } => retained_text(heap, key),
                        S::ConstantIndex { index } => retained_text(heap, index),
                        S::ExactIndex { index } => {
                            heap.add(std::mem::size_of::<super::CodeQueryFlowCarrierSymbol>());
                            heap.add_entries(1);
                            pending.push(index);
                        }
                        S::AnyIndex => {}
                    }
                }
            }
            C::RuntimeObject {
                id,
                runtime_profile_digest,
                realm,
                exposure_id,
                container_member,
                state_boundary,
                refinement_identity,
                active_model_set_hash,
                manifest_digest,
                shard_id,
                behavior_id,
                activation_source,
            } => {
                for text in [
                    id,
                    runtime_profile_digest,
                    realm,
                    exposure_id,
                    container_member,
                    state_boundary,
                    refinement_identity,
                    active_model_set_hash,
                    manifest_digest,
                    shard_id,
                    behavior_id,
                    activation_source,
                ] {
                    retained_text(heap, text);
                }
            }
        }
    }
}
fn retained_fact(heap: &mut RetainedHeap, value: &super::CodeQueryFlowFactSymbol) {
    use super::CodeQueryFlowFactSymbol as F;
    match value {
        F::Zero => {}
        F::Carrier {
            source, carrier, ..
        } => {
            heap.add(
                std::mem::size_of_val(source.as_ref()) + std::mem::size_of_val(carrier.as_ref()),
            );
            heap.add_entries(2);
            retained_event(heap, source);
            retained_carrier(heap, carrier);
        }
        F::Meeting { source, sink, .. } => {
            heap.add(2 * std::mem::size_of_val(source.as_ref()));
            heap.add_entries(2);
            retained_event(heap, source);
            retained_event(heap, sink);
        }
    }
}
fn retained_witness(
    heap: &mut RetainedHeap,
    value: &super::witness_projection::ProjectedSummaryWitness,
) {
    heap.vec(value.steps());
    for step in value.steps() {
        retained_text(heap, &step.source.path);
        for site in [&step.target, &step.origin].into_iter().flatten() {
            retained_text(heap, &site.path);
        }
        for symbol in [
            &step.source_symbol,
            &step.target_symbol,
            &step.origin_symbol,
        ]
        .into_iter()
        .flatten()
        {
            retained_symbol(heap, symbol);
        }
        if let Some(boundary) = &step.boundary {
            retained_text(heap, boundary);
        }
        for fact in [&step.input, &step.output].into_iter().flatten() {
            retained_fact(heap, fact);
        }
        if let Some(reason) = &step.evidence.reason {
            retained_text(heap, reason);
        }
    }
}

impl TypeFlowRootProduct {
    fn output_census(&self) -> RetainedHeap {
        let mut heap = RetainedHeap::default();
        heap.add(std::mem::size_of_val(self) + 2 * std::mem::size_of::<usize>());
        heap.add_entries(1);
        retained_reference(&mut heap, &self.root);
        if let Some((_, message)) = &self.failure {
            retained_text(&mut heap, message);
        }
        heap.vec(&self.projected_rows);
        for row in &self.projected_rows {
            retained_file(&mut heap, &row.file);
            for text in [&row.id, &row.member, &row.origin] {
                retained_text(&mut heap, text);
            }
            if let Some(class) = &row.class {
                retained_text(&mut heap, class);
            }
            if let Some(path) = &row.portable_path {
                heap.add(path.as_str().len());
                heap.add_entries(1);
            }
        }
        heap.vec(&self.class_sets);
        for set in &self.class_sets {
            retained_reference(&mut heap, &set.site.procedure);
            retained_file(&mut heap, &set.site.file);
            heap.add(set.site.member.len());
            heap.add_entries(1);
            heap.vec(&set.classes);
            for (class, site) in &set.classes {
                retained_class(&mut heap, class);
                retained_file(&mut heap, &site.file);
            }
            if let Some(origin) = &set.constructor_origin {
                heap.add(std::mem::size_of_val(origin.classes.as_ref()));
                heap.add_entries(origin.classes.len());
                for class in &origin.classes {
                    retained_class(&mut heap, class);
                }
                retained_file(&mut heap, &origin.source.file);
            }
            heap.vec(&set.member_declarations);
            for (class, hit) in &set.member_declarations {
                retained_class(&mut heap, class);
                match &hit.declaration {
                    MemberDeclaration::Workspace(unit) => {
                        heap.add(
                            unit.retained_bytes()
                                .saturating_sub(std::mem::size_of_val(unit)),
                        );
                        heap.add_entries(1);
                    }
                    MemberDeclaration::External(decl) => {
                        heap.add(std::mem::size_of_val(decl.symbol_ids()));
                        heap.add_entries(decl.symbol_ids().len());
                        for id in decl.symbol_ids() {
                            heap.add(id.len());
                            heap.add_entries(1);
                        }
                    }
                }
            }
            retained_unknown(&mut heap, &set.unknown);
            retained_unknown(&mut heap, &set.flow_unknown);
            retained_dynamic(&mut heap, &set.dynamic_writes);
        }
        heap.vec(&self.findings);
        for finding in &self.findings {
            retained_file(&mut heap, &finding.file);
            for text in [
                &finding.id,
                &finding.member,
                &finding.class,
                &finding.class_name,
            ] {
                retained_text(&mut heap, text);
            }
            if let AbsentMemberProof::Conditional {
                remainders,
                unbounded_dynamic_writes,
            } = &finding.proof
            {
                retained_unknown(&mut heap, remainders);
                retained_dynamic(&mut heap, unbounded_dynamic_writes);
            }
            heap.vec(&finding.roots);
            for root in &finding.roots {
                retained_text(&mut heap, &root.root_procedure_id);
                retained_text(&mut heap, &root.caller);
                retained_file(&mut heap, &root.origin_file);
                heap.vec(&root.also_fails_at);
                for (file, _) in &root.also_fails_at {
                    retained_file(&mut heap, file);
                }
                if let Ok(witness) = &root.witness {
                    retained_witness(&mut heap, witness);
                }
            }
        }
        heap.vec(&self.incomplete_evidence.lanes);
        heap
    }
    fn provenance_census(&self) -> RetainedHeap {
        let mut heap = RetainedHeap::default();
        heap.vec(&self.reads);
        for key in &self.reads {
            retained_read_key(&mut heap, key);
        }
        heap
    }
    fn census(&self) -> SemanticWork {
        // Read keys are dependency metadata. The query's ReadLedger receives the same
        // keys on replay without a semantic-lane charge, so admit only the output.
        let (bytes, entries) = self.output_census().totals();
        SemanticWork {
            owned_text_bytes: bytes,
            nested_entries: entries,
            ..Default::default()
        }
    }
}

impl brokk_bifrost_analysis::analyzer::store::cache_budget::RetainedBytes for TypeFlowRootProduct {
    fn retained_bytes(&self) -> usize {
        self.output_census()
            .total()
            .saturating_add(self.provenance_census().total())
    }
}

#[derive(Debug, Clone)]
pub(super) struct ExactReceiverDispatchProof {
    pub(super) targets: Vec<(ClassIdentity, MemberDeclaration)>,
    pub(super) member: String,
}

#[derive(Debug, Clone)]
pub(super) enum ReceiverDispatchAssessment {
    NotApplicable,
    Open,
    Closed(ExactReceiverDispatchProof),
}

pub(super) struct ReceiverDispatchQuery<'a> {
    pub(super) workspace: &'a WorkspaceAnalyzer,
    pub(super) procedure: &'a SemanticProcedureValue,
    pub(super) file: &'a ProjectFile,
    pub(super) range: Range,
    pub(super) semantic_budget: &'a mut SemanticBudget,
    pub(super) limits: CodeQueryValueFlowLimits,
    pub(super) cancellation: &'a CancellationToken,
    pub(super) active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
}

type QueryFieldSlotInputs = (
    &'static dyn TypeFlowAdapter,
    IcfgProviderBehaviorIdentity,
    Arc<FieldSlotIndex>,
);

#[derive(Clone)]
struct QueryFieldSlots {
    index: Arc<FieldSlotIndex>,
    unattributed_reads: usize,
    execution_dependences: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootResultPublicationOutcome {
    Continued,
    Cancelled,
}

pub(super) struct TypeFlowQueryState {
    value_flow_cache: ValueFlowCache,
    summary_partitions: brokk_bifrost_flow::type_flow::TypeFlowSummaryPartitions,
    summary_state: Option<brokk_bifrost_flow::type_flow::TypeFlowSummaryState>,
    allotment: CodeQueryRootAllotment,
    root_memo: Option<TypeFlowRootMemo>,
    /// Exact procedure-local derivations shared only by roots in this query.
    /// The query owns one pinned analyzer/model context and one diagnostics
    /// ledger, so reuse cannot cross policy, request, or snapshot boundaries.
    refinements: ProcedureRefinements,
    provider_stats_baseline: ValueFlowCacheStatsSnapshot,
    cache: HashMap<TypeFlowCacheKey, CachedTypeFlowAnalysis>,
    field_slots: HashMap<FieldSlotCacheKey, Option<QueryFieldSlots>>,
    witness_projection_cache: HashMap<
        AbsentMemberWitnessProjectionKey,
        (
            Option<AbsentMemberWitnessValue>,
            Arc<brokk_bifrost_analysis::analyzer::ReadLedger>,
        ),
    >,
    diagnostics: Vec<CodeQueryDiagnostic>,
    /// Roots whose solve stopped before a fixed point, and roots whose solve
    /// could not pay a semantic charge, each with the lane that stopped it.
    /// Held until the diagnostics are taken so one diagnostic per code can
    /// carry the complete attribution instead of one opaque line per root.
    incomplete_roots: Vec<CodeQueryExhaustedRoot>,
    incomplete_root_cause: Incompleteness,
    semantic_exhausted_roots: Vec<CodeQueryExhaustedRoot>,
    work: CodeQueryTypeFlowWork,
    semantic_budget_exhausted: bool,
    witness_render_cache: super::PipelineRenderCache,
}

impl Drop for TypeFlowQueryState {
    fn drop(&mut self) {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "type_flow.query.run_end value_flow_cached_artifact_bytes={}",
                self.value_flow_cache.artifact_bytes()
            )
        });
    }
}

impl Default for TypeFlowQueryState {
    fn default() -> Self {
        Self::new(
            ValueFlowCache::default(),
            Default::default(),
            CodeQueryRootAllotment::from_execution_limits(
                &super::CodeQueryExecutionLimits::default(),
            ),
        )
    }
}

impl TypeFlowQueryState {
    fn select_summary_partition(&mut self, workspace: &WorkspaceAnalyzer) {
        if self.summary_state.is_none() {
            self.summary_state = Some(self.summary_partitions.select(
                workspace,
                self.allotment.solver,
                self.allotment.semantic,
            ));
        }
    }

    pub(super) fn set_root_memo(&mut self, memo: Option<TypeFlowRootMemo>) {
        self.root_memo = memo;
    }

    pub(super) fn release_file_window(&mut self) {
        // Bound query-owned output and refund its holders at each window.
        // The products themselves do not depend on resident artifacts.
        self.cache.clear();
    }

    pub(super) fn new(
        value_flow_cache: ValueFlowCache,
        summary_partitions: brokk_bifrost_flow::type_flow::TypeFlowSummaryPartitions,
        allotment: CodeQueryRootAllotment,
    ) -> Self {
        let value_flow_cache = value_flow_cache.with_fresh_stats();
        let provider_stats_baseline = value_flow_cache.stats();
        Self {
            value_flow_cache,
            summary_partitions,
            summary_state: None,
            allotment,
            root_memo: None,
            refinements: ProcedureRefinements::default(),
            provider_stats_baseline,
            cache: HashMap::default(),
            field_slots: HashMap::default(),
            witness_projection_cache: HashMap::default(),
            diagnostics: Vec::new(),
            incomplete_roots: Vec::new(),
            incomplete_root_cause: Incompleteness::Content,
            semantic_exhausted_roots: Vec::new(),
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
    classes: Vec<(ClassIdentity, bool)>,
    unknown: Vec<UnknownReason>,
    dynamic_origins: Vec<String>,
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
    pub(super) guard_only: bool,
}

/// One absent-member finding with the site that introduced the class.
#[derive(Debug, Clone)]
pub(super) struct AbsentMemberFindingValue {
    pub(super) id: String,
    pub(super) file: ProjectFile,
    pub(super) range: Range,
    pub(super) member: String,
    pub(super) class: String,
    pub(super) class_name: String,
    /// The strongest tier any root established. `roots` holds only the roots
    /// that established this tier; a Conditional tier carries the sorted
    /// union of those roots' remainders.
    pub(super) proof: AbsentMemberProof,
    /// Sorted by root identity, with one coherent evidence record per root.
    pub(super) roots: Vec<AbsentMemberRootEvidence>,
}

#[derive(Debug, Clone)]
pub(super) struct AbsentMemberRootEvidence {
    pub(super) root_procedure_id: String,
    pub(super) origin_file: ProjectFile,
    pub(super) origin_range: Range,
    pub(super) origin_span: SourceSpan,
    pub(super) origin_kind: SourceSiteKind,
    pub(super) also_fails_at: Vec<(ProjectFile, SourceSpan)>,
    /// Whether a narrowing guard, rather than value-producing syntax,
    /// introduced the class.
    pub(super) origin_is_guard: bool,
    pub(super) caller: String,
    pub(super) witness:
        Result<super::witness_projection::ProjectedSummaryWitness, SummaryWitnessError>,
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

    pub(super) fn roots_in_source_order(&self) -> Vec<&AbsentMemberRootEvidence> {
        let mut roots = self.roots.iter().collect::<Vec<_>>();
        roots.sort_unstable_by_key(|root| {
            (&root.origin_file, root.origin_span, &root.root_procedure_id)
        });
        roots
    }

    pub(super) fn representative(&self) -> &AbsentMemberRootEvidence {
        let roots = self.roots_in_source_order();
        roots
            .iter()
            .copied()
            .find(|root| root.witness.is_ok())
            .or_else(|| roots.first().copied())
            .expect("a finding has root evidence")
    }

    /// Merge another root set's evidence for the same finding. A Proven tier
    /// replaces a Conditional one with its own evidence, a Conditional tier
    /// never weakens a Proven one, and two Conditional tiers union their
    /// remainders.
    pub(super) fn merge_evidence(&mut self, other: Self) {
        debug_assert_eq!(self.id, other.id);
        match (&mut self.proof, other.proof) {
            (AbsentMemberProof::Proven, AbsentMemberProof::Conditional { .. }) => return,
            (AbsentMemberProof::Conditional { .. }, AbsentMemberProof::Proven) => {
                self.proof = AbsentMemberProof::Proven;
                self.roots = other.roots;
                return;
            }
            (AbsentMemberProof::Proven, AbsentMemberProof::Proven) => {}
            (
                AbsentMemberProof::Conditional {
                    remainders,
                    unbounded_dynamic_writes,
                },
                AbsentMemberProof::Conditional {
                    remainders: other_remainders,
                    unbounded_dynamic_writes: other_dynamic_writes,
                },
            ) => {
                for reason in other_remainders {
                    if !remainders.contains(&reason) {
                        remainders.push(reason);
                    }
                }
                sort_unknown_reasons(remainders);
                merge_dynamic_write_evidence(unbounded_dynamic_writes, other_dynamic_writes);
            }
        }
        for root in other.roots {
            match self.roots.binary_search_by(|existing| {
                existing.root_procedure_id.cmp(&root.root_procedure_id)
            }) {
                Ok(index) => {
                    let existing = &mut self.roots[index];
                    if existing.origin_span == root.origin_span {
                        existing
                            .also_fails_at
                            .extend(root.also_fails_at.iter().cloned());
                        existing.also_fails_at.sort_unstable();
                        existing.also_fails_at.dedup();
                    }
                    if existing.witness.is_err() && root.witness.is_ok() {
                        let also_fails_at = std::mem::take(&mut existing.also_fails_at);
                        *existing = root;
                        existing.also_fails_at.extend(also_fails_at);
                        existing.also_fails_at.sort_unstable();
                        existing.also_fails_at.dedup();
                    }
                }
                Err(index) => self.roots.insert(index, root),
            }
        }
    }
}

fn merge_dynamic_write_evidence(
    evidence: &mut Vec<DynamicWriteEvidence>,
    additions: impl IntoIterator<Item = DynamicWriteEvidence>,
) {
    for addition in additions {
        if !evidence.contains(&addition) {
            evidence.push(addition);
        }
    }
    evidence.sort_unstable_by_key(DynamicWriteEvidence::origin);
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
            CachedTypeFlowAnalysis::Owned(result) => result.product.projected_rows.clone(),
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

    pub(super) fn receiver_dispatch_assessment(
        &mut self,
        query: ReceiverDispatchQuery<'_>,
    ) -> ReceiverDispatchAssessment {
        let ReceiverDispatchQuery {
            workspace,
            procedure,
            file,
            range,
            semantic_budget,
            limits,
            cancellation,
            active_semantic_model_snapshot,
        } = query;
        let Some(cached) = self.solve_live(
            workspace,
            procedure,
            semantic_budget,
            limits,
            cancellation,
            active_semantic_model_snapshot,
        ) else {
            return ReceiverDispatchAssessment::NotApplicable;
        };
        let CachedTypeFlowAnalysis::Owned(result) = cached else {
            unreachable!("solve_live returns only owned root products")
        };
        let result = result.product;
        if !result.complete || result.semantic_budget_exhausted {
            return ReceiverDispatchAssessment::NotApplicable;
        }
        let matching = result
            .class_sets
            .iter()
            .filter(|set| {
                set.site.file == *file
                    && set.site.kind == MemberAccessKind::Call
                    && set.site.purpose == TypeFlowSitePurpose::MemberAccess
                    && set.site.call_span.is_some_and(|span| {
                        span.start_byte() as usize == range.start_byte
                            && span.end_byte() as usize == range.end_byte
                    })
            })
            .collect::<Vec<_>>();
        let [set] = matching.as_slice() else {
            return if matching.iter().any(|set| {
                set.constructor_origin.is_some()
                    || set.classes.len() > 1
                    || !set.unknown.is_empty()
                    || !set.flow_unknown.is_empty()
            }) {
                ReceiverDispatchAssessment::Open
            } else {
                ReceiverDispatchAssessment::NotApplicable
            };
        };
        let Some(origin) = set.constructor_origin.as_ref() else {
            return if set.classes.len() > 1
                || !set.unknown.is_empty()
                || !set.flow_unknown.is_empty()
                || !set.dynamic_writes.is_empty()
            {
                ReceiverDispatchAssessment::Open
            } else {
                ReceiverDispatchAssessment::NotApplicable
            };
        };
        let open = || ReceiverDispatchAssessment::Open;
        if set.status != ClassSetStatus::Known
            || !set.unknown.is_empty()
            || !set.flow_unknown.is_empty()
            || !set.dynamic_writes.is_empty()
        {
            return open();
        }
        let Some(method_call) = set.site.call else {
            return open();
        };
        let separate_exact_producer = match &origin.producer {
            ExactResultProducer::Call(call) => {
                *call != method_call
                    && matches!(
                        origin.source.kind,
                        SourceSiteKind::ConstructorCall | SourceSiteKind::ExactCallResult
                    )
                    && (origin.source.kind != SourceSiteKind::ExactCallResult
                        || origin.source.file == *file)
            }
            ExactResultProducer::MemoryLoad { .. } => {
                origin.source.kind == SourceSiteKind::ExactAccessResult
                    && origin.source.file == *file
            }
        };
        let exact_access_result = matches!(
            origin.source.kind,
            SourceSiteKind::ExactCallResult | SourceSiteKind::ExactAccessResult
        );
        if !separate_exact_producer
            || (exact_access_result && !set.exact_result_receiver_proven)
            || origin.classes.len() != set.classes.len()
            || set.classes.is_empty()
        {
            return open();
        }
        let origin_classes = origin.classes.iter().collect::<HashSet<_>>();
        if origin_classes.len() != origin.classes.len()
            || set
                .classes
                .iter()
                .any(|(class, _)| !origin_classes.contains(class))
        {
            return open();
        }
        let mut targets = Vec::with_capacity(set.classes.len());
        for (class, _) in &set.classes {
            let declarations = set
                .member_declarations
                .iter()
                .filter(|(declared_class, _)| declared_class == class)
                .collect::<Vec<_>>();
            let [(_, hit)] = declarations.as_slice() else {
                return open();
            };
            if hit.dispatch_coverage != CandidateCoverage::Exhaustive {
                return open();
            }
            targets.push((class.clone(), hit.declaration.clone()));
        }
        if targets.len() != set.member_declarations.len() {
            return open();
        }
        ReceiverDispatchAssessment::Closed(ExactReceiverDispatchProof {
            targets,
            member: set.site.member.to_string(),
        })
    }

    pub(super) fn python_iterator_return_sets(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        procedure: &SemanticProcedureValue,
        semantic_budget: &mut SemanticBudget,
        limits: CodeQueryValueFlowLimits,
        cancellation: &CancellationToken,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Vec<OwnedReceiverClassSet> {
        if !is_python_iterator_method(procedure) {
            return Vec::new();
        }
        let Some(result) = self.solve_live(
            workspace,
            procedure,
            semantic_budget,
            limits,
            cancellation,
            active_semantic_model_snapshot,
        ) else {
            return Vec::new();
        };
        let CachedTypeFlowAnalysis::Owned(result) = result else {
            unreachable!("solve_live returns only owned root products")
        };
        let result = result.product;
        result
            .class_sets
            .iter()
            .filter(|set| {
                set.site.purpose == TypeFlowSitePurpose::PythonIteratorReturn
                    && set.site.procedure == SemanticProcedureReference::of(&procedure.handle)
            })
            .cloned()
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
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
            CachedTypeFlowAnalysis::Owned(result) => result.product,
            CachedTypeFlowAnalysis::FindingFreeRows(_) => return Vec::new(),
            CachedTypeFlowAnalysis::Failed => {
                unreachable!("failed type-flow cache entries return None")
            }
        };
        let rows = result.findings.clone();
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
        for (witness_index, root) in finding.roots_in_source_order().into_iter().enumerate() {
            let key = AbsentMemberWitnessProjectionKey {
                finding_id: finding.id.clone(),
                root_procedure_id: root.root_procedure_id.clone(),
                witness_index,
                max_steps,
                max_bytes,
            };
            if let Some((cached, reads)) = self.witness_projection_cache.get(&key) {
                crate::analyzer::i_analyzer::replay_query_reads(workspace.analyzer(), reads);
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
                self.witness_projection_cache
                    .insert(key, (None, Arc::default()));
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
            let (public, reads) = capture_query_reads(workspace.analyzer(), || {
                // Coordinate and indexed-source caches may both be warm.
                // Name the exact snapshot source even when neither loads it.
                if let Some(blob) = workspace.analyzer().indexed_blob_oid(&finding.file) {
                    workspace.analyzer().record_read(ReadKey::file(
                        language_for_file(&finding.file),
                        crate::path_utils::rel_path_string(&finding.file),
                        blob,
                    ));
                } else {
                    workspace.analyzer().record_unattributed_read();
                }
                super::witness_projection::public_absent_member_witness(
                    workspace,
                    finding,
                    root,
                    witness_index,
                    max_steps.min(remaining_steps),
                    max_bytes.min(remaining_bytes),
                    &mut self.witness_render_cache,
                )
            });
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
            self.witness_projection_cache
                .insert(key, (Some(row.clone()), reads));
            rows.push(row);
        }
        rows
    }

    fn record_witness_budget(&mut self, omitted_lower_bound: usize) {
        record_omitted_witnesses(
            &mut self.work.witness_truncated,
            &mut self.work.omitted_witnesses,
            omitted_lower_bound,
        );
        push_deduplicated_diagnostic(
            &mut self.diagnostics,
            CodeQueryDiagnosticCode::TypeFlowWitnessTruncated,
            Incompleteness::Operational(DerivationExecutionCause::Provider),
            format!(
                "absent-member witness projection omitted at least {omitted_lower_bound} witness(es)"
            ),
        );
    }

    fn record_witness_truncated(&mut self, omitted_lower_bound: usize) {
        self.work.witness_truncated = true;
        push_deduplicated_diagnostic(
            &mut self.diagnostics,
            CodeQueryDiagnosticCode::TypeFlowWitnessTruncated,
            Incompleteness::Operational(DerivationExecutionCause::Provider),
            format!(
                "absent-member witness projection omitted at least {omitted_lower_bound} step(s)"
            ),
        );
    }

    fn record_witness_unavailable(&mut self, error: &SummaryWitnessError) {
        push_deduplicated_diagnostic(
            &mut self.diagnostics,
            CodeQueryDiagnosticCode::TypeFlowWitnessUnavailable,
            Incompleteness::Operational(DerivationExecutionCause::Provider),
            format!(
                "absent-member witness unavailable: {}",
                bounded_reason(&error.to_string())
            ),
        );
    }

    /// This root's type-flow result: this query's cached result, the persisted
    /// finding-free projection of an earlier solve, or a new solve.
    ///
    /// The projection answers class-set rows exactly as a live result does,
    /// and nothing else. A consumer that reads the live receiver sets calls
    /// [`Self::solve_live`] instead, so that its answer cannot depend on
    /// whether an earlier query happened to publish this root.
    fn solve(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        procedure: &SemanticProcedureValue,
        semantic_budget: &mut SemanticBudget,
        limits: CodeQueryValueFlowLimits,
        cancellation: &CancellationToken,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Option<CachedTypeFlowAnalysis> {
        self.select_summary_partition(workspace);
        if is_python_iterator_method(procedure) {
            return self.solve_live(
                workspace,
                procedure,
                semantic_budget,
                limits,
                cancellation,
                active_semantic_model_snapshot,
            );
        }
        let (inputs, input_reads) = self.capture_root_inputs(
            workspace,
            procedure,
            semantic_budget,
            cancellation,
            active_semantic_model_snapshot.clone(),
        );
        let (adapter, provider_behavior, field_slots) = inputs?;
        let cache_key = TypeFlowCacheKey {
            root: SemanticProcedureReference::of(&procedure.handle),
            provider_behavior,
            field_slots: field_slots.digest(),
        };
        match self.cache.get(&cache_key).cloned() {
            Some(CachedTypeFlowAnalysis::Failed) => {
                workspace.analyzer().record_unattributed_read();
                self.work.cache_hits = self.work.cache_hits.saturating_add(1);
                return None;
            }
            Some(CachedTypeFlowAnalysis::Owned(result)) if result.product.failure.is_some() => {
                crate::analyzer::replay_query_read_receipt(
                    workspace.analyzer(),
                    result.product.reads.iter().cloned(),
                    result.product.unattributed_reads,
                    result.product.execution_dependences,
                );
                self.work.cache_hits = self.work.cache_hits.saturating_add(1);
                return None;
            }
            Some(result) => {
                if matches!(result, CachedTypeFlowAnalysis::FindingFreeRows(_)) {
                    // These legacy projections carry no read receipt. Refuse
                    // reuse rather than publish a capture without their inputs.
                    workspace.analyzer().record_unattributed_read();
                }
                if let CachedTypeFlowAnalysis::Owned(owned) = &result {
                    crate::analyzer::replay_query_read_receipt(
                        workspace.analyzer(),
                        owned.product.reads.iter().cloned(),
                        owned.product.unattributed_reads,
                        owned.product.execution_dependences,
                    );
                }
                self.work.cache_hits = self.work.cache_hits.saturating_add(1);
                return Some(result);
            }
            None => {}
        }
        let memo_permit = match self.acquire_root_memo(
            workspace,
            &cache_key,
            procedure,
            semantic_budget,
            cancellation,
            active_semantic_model_snapshot.as_deref(),
        ) {
            RootProductAcquisition::Applied(result) => return result,
            RootProductAcquisition::Solve(permit) => permit,
        };
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
                self.allotment,
            )
        };
        let mut persistent_store_failed = false;
        if let (Some(store), Some(persistent_key)) = (workspace.store(), persistent_key.as_ref()) {
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
                    // SQLite legacy projections have no derivation receipt,
                    // just like the later in-memory projection hit.
                    workspace.analyzer().record_unattributed_read();
                    let cached = CachedTypeFlowAnalysis::FindingFreeRows(rows);
                    self.cache.insert(cache_key, cached.clone());
                    return Some(cached);
                }
                Ok(ClassSetRootResultLookup::Hit(_) | ClassSetRootResultLookup::Rejected(_)) => {
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
                    push_deduplicated_diagnostic(
                        &mut self.diagnostics,
                        CodeQueryDiagnosticCode::Cancelled,
                        Incompleteness::Operational(DerivationExecutionCause::Cancelled),
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
        self.solve_root(
            workspace,
            adapter,
            field_slots,
            cache_key,
            procedure,
            persistent_key,
            persistent_store_failed,
            semantic_budget,
            limits,
            cancellation,
            active_semantic_model_snapshot,
            memo_permit,
            input_reads,
        )
    }

    /// This root's full owned type-flow product, never the finding-free projection.
    ///
    /// Receiver dispatch reads per-site class sets, constructor origins and
    /// member declarations that the projection does not carry. Answering it
    /// from a projection hit made one call's dispatch outcome depend on
    /// whether an earlier query in the process or cache had published the
    /// root (#6638).
    fn solve_live(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        procedure: &SemanticProcedureValue,
        semantic_budget: &mut SemanticBudget,
        limits: CodeQueryValueFlowLimits,
        cancellation: &CancellationToken,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Option<CachedTypeFlowAnalysis> {
        self.select_summary_partition(workspace);
        let (inputs, input_reads) = self.capture_root_inputs(
            workspace,
            procedure,
            semantic_budget,
            cancellation,
            active_semantic_model_snapshot.clone(),
        );
        let (adapter, provider_behavior, field_slots) = inputs?;
        let cache_key = TypeFlowCacheKey {
            root: SemanticProcedureReference::of(&procedure.handle),
            provider_behavior,
            field_slots: field_slots.digest(),
        };
        match self.cache.get(&cache_key).cloned() {
            Some(CachedTypeFlowAnalysis::Owned(result)) => {
                crate::analyzer::replay_query_read_receipt(
                    workspace.analyzer(),
                    result.product.reads.iter().cloned(),
                    result.product.unattributed_reads,
                    result.product.execution_dependences,
                );
                self.work.cache_hits = self.work.cache_hits.saturating_add(1);
                return result
                    .product
                    .failure
                    .is_none()
                    .then_some(CachedTypeFlowAnalysis::Owned(result));
            }
            Some(CachedTypeFlowAnalysis::Failed) => {
                workspace.analyzer().record_unattributed_read();
                self.work.cache_hits = self.work.cache_hits.saturating_add(1);
                return None;
            }
            Some(CachedTypeFlowAnalysis::FindingFreeRows(_)) | None => {}
        }
        // A live solve still publishes its projection for row consumers.
        let memo_permit = match self.acquire_root_memo(
            workspace,
            &cache_key,
            procedure,
            semantic_budget,
            cancellation,
            active_semantic_model_snapshot.as_deref(),
        ) {
            RootProductAcquisition::Applied(result) => return result,
            RootProductAcquisition::Solve(permit) => permit,
        };
        let persistent_key =
            if field_slots.semantic_budget_exhausted() || is_python_iterator_method(procedure) {
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
                    self.allotment,
                )
            };
        self.solve_root(
            workspace,
            adapter,
            field_slots,
            cache_key,
            procedure,
            persistent_key,
            false,
            semantic_budget,
            limits,
            cancellation,
            active_semantic_model_snapshot,
            memo_permit,
            input_reads,
        )
    }

    /// Capture the selected root artifact and the shared field-slot acquisition.
    fn capture_root_inputs(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        procedure: &SemanticProcedureValue,
        semantic_budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> (
        Option<QueryFieldSlotInputs>,
        Arc<brokk_bifrost_analysis::analyzer::ReadLedger>,
    ) {
        capture_query_reads(workspace.analyzer(), || {
            // Resolution selected this exact artifact before entering type flow.
            // Record that selection inside the root's dependency boundary.
            let artifact = procedure.handle.artifact();
            workspace
                .analyzer()
                .record_read(ReadKey::semantic_artifact(artifact.key()));
            self.query_field_slots(
                workspace,
                procedure,
                semantic_budget,
                cancellation,
                active_semantic_model_snapshot.clone(),
            )
        })
    }

    fn query_field_slots(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        procedure: &SemanticProcedureValue,
        semantic_budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Option<QueryFieldSlotInputs> {
        // Per-class field-slot keys cover the slots and survey a root reads.
        // They subsume acquisition's build keys, but not unattributed reads.
        let (inputs, _) = capture_subsumed_query_reads(workspace.analyzer(), || {
            let language = language_for_file(procedure.file());
            let Some(adapter) = type_flow_adapter(language) else {
                push_deduplicated_diagnostic(
                    &mut self.diagnostics,
                    CodeQueryDiagnosticCode::SemanticCapabilityUnsupported,
                    Incompleteness::Operational(DerivationExecutionCause::Provider),
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
            let query_field_slots = match self.field_slots.get(&field_slot_key).cloned() {
                Some(Some(index)) => {
                    crate::analyzer::replay_query_read_receipt(
                        workspace.analyzer(),
                        std::iter::empty(),
                        index.unattributed_reads,
                        index.execution_dependences,
                    );
                    index
                }
                Some(None) => {
                    workspace.analyzer().record_unattributed_read();
                    return None;
                }
                None => {
                    let parent_scope = semantic_budget.scope_snapshot();
                    // Shared field slots use the same engine-owned allotment as roots.
                    let mut field_slot_budget =
                        SemanticBudget::new_child(self.allotment.semantic, &parent_scope);
                    let field_slot_cache = self
                        .summary_state
                        .as_ref()
                        .expect("partition selected before field slots")
                        .field_slot_indexes();
                    let (acquired, receipt) =
                        brokk_bifrost_analysis::analyzer::capture_subsumed_query_read_receipt(
                            workspace.analyzer(),
                            || {
                                let _timing =
                                    crate::profiling::scope("type_flow.field_slot_acquire");
                                FieldSlotIndex::acquire(
                                    workspace,
                                    adapter,
                                    provider_behavior,
                                    active_semantic_model_snapshot.clone(),
                                    &field_slot_cache,
                                    self.value_flow_cache.clone(),
                                    &mut field_slot_budget,
                                    cancellation,
                                )
                            },
                        );
                    // The prepass has finished using its procedure handles. Keep
                    // cumulative work and peaks, but release its admissions before
                    // folding the independently bounded child into the query.
                    field_slot_budget.release_resident();
                    semantic_budget.absorb_root_work(field_slot_budget);
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
                            for refusal in index.source_refusals() {
                                push_deduplicated_diagnostic(
                                    &mut self.diagnostics,
                                    CodeQueryDiagnosticCode::SemanticProviderFailed,
                                    Incompleteness::Operational(DerivationExecutionCause::Provider),
                                    refusal.to_string(),
                                );
                            }
                            if index.semantic_budget_exhausted() {
                                self.semantic_budget_exhausted = true;
                                let detail = index.semantic_budget_exhaustion().map_or_else(
                                    || "bounded adapter class resolution".to_string(),
                                    |exhaustion| exhaustion.to_string(),
                                );
                                push_deduplicated_diagnostic(
                                    &mut self.diagnostics,
                                    CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                                    Incompleteness::Operational(DerivationExecutionCause::Budget),
                                    format!(
                                        "class-set field index exceeded its semantic budget: {}",
                                        detail
                                    ),
                                );
                            }
                            let cached = QueryFieldSlots {
                                index,
                                unattributed_reads: receipt.unattributed_reads,
                                execution_dependences: receipt.execution_dependences,
                            };
                            self.field_slots
                                .insert(field_slot_key.clone(), Some(cached.clone()));
                            cached
                        }
                        Err(error) => {
                            let code = if matches!(error, TypeFlowPlanError::Cancelled) {
                                CodeQueryDiagnosticCode::Cancelled
                            } else {
                                CodeQueryDiagnosticCode::SemanticProviderFailed
                            };
                            push_deduplicated_diagnostic(
                                &mut self.diagnostics,
                                code,
                                Incompleteness::Operational(DerivationExecutionCause::Provider),
                                format!("class-set field index failed: {error}"),
                            );
                            self.field_slots.insert(field_slot_key, None);
                            return None;
                        }
                    }
                }
            };
            Some((
                adapter,
                provider_behavior,
                Arc::clone(&query_field_slots.index),
            ))
        });
        inputs
    }

    #[allow(clippy::too_many_arguments)]
    fn solve_root(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        adapter: &'static dyn TypeFlowAdapter,
        field_slots: Arc<FieldSlotIndex>,
        cache_key: TypeFlowCacheKey,
        procedure: &SemanticProcedureValue,
        persistent_key: Option<FindingFreeClassSetRootKey>,
        persistent_store_failed: bool,
        semantic_budget: &mut SemanticBudget,
        limits: CodeQueryValueFlowLimits,
        cancellation: &CancellationToken,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
        memo_permit: Option<RootMemoPermit>,
        input_reads: Arc<brokk_bifrost_analysis::analyzer::ReadLedger>,
    ) -> Option<CachedTypeFlowAnalysis> {
        self.work.solves = self.work.solves.saturating_add(1);
        let mut solver_budget = SolverBudget::new(self.allotment.solver);
        // Each root gets a fresh ledger, independent of the parent's live census.
        let mut child_budget =
            SemanticBudget::new_child(self.allotment.semantic, &semantic_budget.scope_snapshot());
        let (product, reads) = capture_query_reads(workspace.analyzer(), || {
            crate::analyzer::i_analyzer::replay_query_reads(workspace.analyzer(), &input_reads);
            let mut request = DataflowRequest::new(&mut solver_budget, cancellation);
            let outcome = solve_type_flow_for_root_with_refinements(
                workspace,
                adapter,
                &field_slots,
                &procedure.handle,
                active_semantic_model_snapshot,
                CLOSURE_LIMITS,
                FeedbackLimits::default(),
                self.value_flow_cache.clone(),
                self.summary_state
                    .as_ref()
                    .expect("partition selected before root solve")
                    .clone(),
                &mut child_budget,
                &mut request,
                &mut self.refinements,
            );
            // Callee handles are local to the completed root solve.
            // Fold performed work and its peak into the parent without
            // importing those now-released resident admissions.
            match outcome {
                Ok(result) => {
                    let projected_rows = project_class_sets(&result);
                    if !persistent_store_failed
                    && result.persistence_status == TypeFlowRootPersistenceStatus::Eligible
                    && result.findings.is_empty()
                    // Constructor-origin evidence is request-local:
                    // the durable class-set projection does not carry
                    // the binding, escape, and member-closure proof
                    // that makes it usable by call_bindings.
                    && !(adapter.language() == crate::analyzer::Language::Python
                        && result
                            .class_sets
                            .iter()
                            .any(|set| set.constructor_origin.is_some()))
                    && let Some(persistent_key) = persistent_key.as_ref()
                    {
                        let publication = self.publish_finding_free_root_result(
                            workspace,
                            persistent_key,
                            &result,
                            &projected_rows,
                            limits,
                            cancellation,
                        );
                        if publication == RootResultPublicationOutcome::Cancelled {
                            self.work = self.work.saturating_add(CodeQueryTypeFlowWork {
                                solves: 0,
                                ..TypeFlowRootProduct::work_for(&result)
                            });
                            push_deduplicated_diagnostic(
                                &mut self.diagnostics,
                                CodeQueryDiagnosticCode::Cancelled,
                                Incompleteness::Operational(DerivationExecutionCause::Cancelled),
                                "class-set root-result publication was cancelled".to_string(),
                            );
                            child_budget.release_resident();
                            semantic_budget.absorb_root_work(child_budget);
                            self.cache
                                .insert(cache_key.clone(), CachedTypeFlowAnalysis::Failed);
                            return None;
                        }
                    }
                    let product = TypeFlowRootProduct::new(
                        workspace,
                        procedure,
                        result,
                        projected_rows,
                        child_budget.used(),
                    );
                    debug_assert_eq!(product.work.solves, 1);
                    debug_assert!(
                        product.persistence_status != TypeFlowRootPersistenceStatus::Eligible
                            || product.complete
                    );
                    child_budget.release_resident();
                    semantic_budget.absorb_root_work(child_budget);
                    Some(product)
                }
                Err(error) => {
                    let semantic_work = child_budget.used();
                    child_budget.release_resident();
                    semantic_budget.absorb_root_work(child_budget);
                    let code = match &error {
                        TypeFlowError::Cancelled => CodeQueryDiagnosticCode::Cancelled,
                        TypeFlowError::Plan(_) | TypeFlowError::Solve(_) | TypeFlowError::Io(_) => {
                            CodeQueryDiagnosticCode::SemanticProviderFailed
                        }
                    };
                    let product = TypeFlowRootProduct {
                        root: SemanticProcedureReference::of(&procedure.handle),
                        failure: Some((code, format!("class-set analysis failed: {error}"))),
                        projected_rows: Vec::new(),
                        class_sets: Vec::new(),
                        findings: Vec::new(),
                        complete: false,
                        semantic_budget_exhausted: false,
                        incomplete_evidence: RootIncompleteEvidence::default(),
                        persistence_status: TypeFlowRootPersistenceStatus::Ineligible(
                            if code == CodeQueryDiagnosticCode::Cancelled {
                                TypeFlowRootPersistenceRejection::SolverIncomplete
                            } else {
                                TypeFlowRootPersistenceRejection::ProviderFailure
                            },
                        ),
                        work: CodeQueryTypeFlowWork {
                            solves: 1,
                            failed_solves: 1,
                            ..Default::default()
                        },
                        solver_work: solver_budget.used(),
                        semantic_work,
                        reads: Vec::new(),
                        unattributed_reads: 0,
                        execution_dependences: 0,
                    };
                    Some(product)
                }
            }
        });
        let mut product = product?;
        product.reads = reads.keys();
        product.unattributed_reads = reads.unattributed_reads();
        product.execution_dependences = reads.execution_dependences();
        let product = Arc::new(product);
        // No memo reentry from the flow engine. A cancelled leader leaves its
        // permit unpublished so a live follower can retry as leader.
        if let Some(permit) = memo_permit
            && !cancellation.is_cancelled()
            && product
                .failure
                .as_ref()
                .is_none_or(|(code, _)| *code != CodeQueryDiagnosticCode::Cancelled)
            && !product
                .incomplete_evidence
                .lanes
                .contains(&RootExhaustedLane::Cancelled)
        {
            (*permit).publish_complete(Arc::clone(&product));
        }
        self.apply_product(
            workspace,
            cache_key,
            procedure,
            product,
            semantic_budget,
            RootProductSource::Solved,
        )
    }

    /// Apply the same immutable evidence and query-owned residency to every
    /// consumer, including the flight leader. Work attribution never decides completeness.
    fn apply_product(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        key: TypeFlowCacheKey,
        procedure: &SemanticProcedureValue,
        product: Arc<TypeFlowRootProduct>,
        budget: &mut SemanticBudget,
        source: RootProductSource,
    ) -> Option<CachedTypeFlowAnalysis> {
        match source {
            RootProductSource::Solved => {
                self.work = self.work.saturating_add(CodeQueryTypeFlowWork {
                    solves: 0,           // Counted before the solve, including cancelled publication.
                    incomplete_roots: 0, // Attributed below for every consumer.
                    ..product.work
                });
            }
            RootProductSource::Memo => {
                crate::analyzer::replay_query_read_receipt(
                    workspace.analyzer(),
                    product.reads.iter().cloned(),
                    product.unattributed_reads,
                    product.execution_dependences,
                );
                self.work.root_memo_hits = self.work.root_memo_hits.saturating_add(1);
                self.work.root_memo_solver_work = self
                    .work
                    .root_memo_solver_work
                    .saturating_add(product.solver_work);
                self.work.root_memo_semantic_work = self
                    .work
                    .root_memo_semantic_work
                    .saturating_add(product.semantic_work);
            }
        }
        if let Some((code, message)) = &product.failure {
            push_deduplicated_diagnostic(
                &mut self.diagnostics,
                *code,
                Incompleteness::Operational(DerivationExecutionCause::Provider),
                message.clone(),
            );
        } else {
            if product.semantic_budget_exhausted {
                self.semantic_budget_exhausted = true;
                self.record_semantic_exhausted_root(procedure, &product.incomplete_evidence);
            }
            if !product.complete {
                self.work.incomplete_roots = self.work.incomplete_roots.saturating_add(1);
                self.record_incomplete_root(procedure, &product.incomplete_evidence);
            }
        }
        let before = budget.replay_snapshot();
        let census = product.census();
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "type_flow.root_product root={} retained_bytes={} nested_entries={}",
                product.root.public_digest(),
                census.owned_text_bytes,
                census.nested_entries
            )
        });
        if let Err(exceeded) = budget.admit(census) {
            self.semantic_budget_exhausted = true;
            push_deduplicated_diagnostic(
                &mut self.diagnostics,
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                Incompleteness::Operational(DerivationExecutionCause::Budget),
                format!("class-set root product admission failed: {exceeded}"),
            );
            self.cache.insert(key, CachedTypeFlowAnalysis::Failed);
            return None;
        }
        let owner = Arc::new(());
        let bound = budget.bind_replay_holder(&owner, &before);
        debug_assert_eq!(
            bound, census,
            "a root product holder pays its returned census"
        );
        let failed = product.failure.is_some();
        let cached = CachedTypeFlowAnalysis::Owned(QueryRootProduct {
            product,
            _owner: owner,
        });
        self.cache.insert(key, cached.clone());
        (!failed).then_some(cached)
    }

    fn acquire_root_memo(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        key: &TypeFlowCacheKey,
        procedure: &SemanticProcedureValue,
        budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
        snapshot: Option<&ActiveSemanticModelSnapshot>,
    ) -> RootProductAcquisition {
        let Some(memo) = self.root_memo.as_ref() else {
            return RootProductAcquisition::Solve(None);
        };
        let Some(identity) = workspace.analyzer().workspace_content_identity() else {
            return RootProductAcquisition::Solve(None);
        };
        let memo_key = TypeFlowRootMemoKey {
            root: key.clone(),
            allotment: self.allotment,
            active_pack: active_semantic_model_pack_digest(snapshot),
            workspace_content: *identity.as_bytes(),
        };
        match memo.products.acquire(&memo_key, cancellation).0 {
            CompleteValueAcquisition::Cached { value } => {
                RootProductAcquisition::Applied(self.apply_product(
                    workspace,
                    key.clone(),
                    procedure,
                    value,
                    budget,
                    RootProductSource::Memo,
                ))
            }
            CompleteValueAcquisition::Leader { permit } => {
                RootProductAcquisition::Solve(Some(Box::new(permit)))
            }
            CompleteValueAcquisition::Cancelled => {
                push_deduplicated_diagnostic(
                    &mut self.diagnostics,
                    CodeQueryDiagnosticCode::Cancelled,
                    Incompleteness::Operational(DerivationExecutionCause::Cancelled),
                    "class-set root memo acquisition was cancelled".to_owned(),
                );
                RootProductAcquisition::Applied(None)
            }
            CompleteValueAcquisition::Rejected => {
                unreachable!("root memo leaders never reject a flight")
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
        let attachment = match workspace.semantic_artifact_store_attachment(&result.root.key) {
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

    /// Attribute one root's semantic-budget stop to its semantic lanes.
    fn record_semantic_exhausted_root(
        &mut self,
        procedure: &SemanticProcedureValue,
        evidence: &RootIncompleteEvidence,
    ) {
        let entries = exhausted_root_entries(
            procedure,
            evidence,
            evidence
                .lanes
                .iter()
                .filter(|lane| matches!(lane, RootExhaustedLane::Semantic { .. })),
        );
        extend_distinct(&mut self.semantic_exhausted_roots, entries);
    }

    /// Attribute one root that stopped before a fixed point to every lane
    /// that stopped it.
    fn record_incomplete_root(
        &mut self,
        procedure: &SemanticProcedureValue,
        evidence: &RootIncompleteEvidence,
    ) {
        for lane in &evidence.lanes {
            let cause = match lane {
                RootExhaustedLane::Cancelled => DerivationExecutionCause::Cancelled,
                RootExhaustedLane::Solver(_) | RootExhaustedLane::Semantic { .. } => {
                    DerivationExecutionCause::Budget
                }
            };
            self.incomplete_root_cause = self
                .incomplete_root_cause
                .combine(Incompleteness::Operational(cause));
        }
        let entries = exhausted_root_entries(procedure, evidence, evidence.lanes.iter());
        extend_distinct(&mut self.incomplete_roots, entries);
    }

    pub(super) fn take_diagnostics(&mut self) -> Vec<CodeQueryDiagnostic> {
        let semantic_roots = std::mem::take(&mut self.semantic_exhausted_roots);
        if !semantic_roots.is_empty() {
            let message = render_exhausted_roots(
                "class-set semantic input exceeded its budget",
                &semantic_roots,
                MAX_DIAGNOSTIC_LIST_MESSAGE_BYTES,
            );
            self.push_exhaustion_diagnostic(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                Incompleteness::Operational(DerivationExecutionCause::Budget),
                message,
                semantic_roots,
            );
        }
        let incomplete_roots = std::mem::take(&mut self.incomplete_roots);
        if !incomplete_roots.is_empty() {
            let message = render_exhausted_roots(
                "class-set analysis retained incomplete semantic evidence",
                &incomplete_roots,
                MAX_DIAGNOSTIC_LIST_MESSAGE_BYTES,
            );
            let incompleteness =
                std::mem::replace(&mut self.incomplete_root_cause, Incompleteness::Content);
            self.push_exhaustion_diagnostic(
                CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                incompleteness,
                message,
                incomplete_roots,
            );
        }
        std::mem::take(&mut self.diagnostics)
    }

    fn push_exhaustion_diagnostic(
        &mut self,
        code: CodeQueryDiagnosticCode,
        incompleteness: Incompleteness,
        message: String,
        exhausted_roots: Vec<CodeQueryExhaustedRoot>,
    ) {
        self.diagnostics.push(incomplete_diagnostic(
            code,
            incompleteness,
            "workspace",
            message,
            exhausted_roots,
        ));
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
    allotment: CodeQueryRootAllotment,
) -> Option<FindingFreeClassSetRootKey> {
    if workspace.store().is_none_or(|store| store.is_ephemeral()) {
        return None;
    }
    let owner_storage_language_key =
        workspace.semantic_artifact_storage_language_key(root.artifact().key())?;
    let workspace_content = workspace.analyzer().workspace_content_identity()?;
    let active_pack = active_semantic_model_pack_digest(active_semantic_model_snapshot);
    let semantics = root_result_semantics_digest(adapter, limits, allotment);
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
        owner_storage_language_key,
    })
}

fn root_result_semantics_digest(
    adapter: &dyn TypeFlowAdapter,
    limits: CodeQueryValueFlowLimits,
    allotment: CodeQueryRootAllotment,
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
        push_usize(&mut digest, allotment.solver.get(dimension));
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
        push_usize(&mut digest, allotment.semantic.get(dimension));
    }
    digest.finish()
}

const ROOT_RESULT_ALGORITHM_ID: &[u8] = b"type-flow-root-algorithm-v17";

fn push_usize(digest: &mut LengthDelimitedDigest, value: usize) {
    digest.push(
        &u64::try_from(value)
            .expect("bounded type-flow configuration fits in u64")
            .to_le_bytes(),
    );
}

fn project_class_sets(result: &TypeFlowRootResult) -> Vec<ClassSetRowValue> {
    let root_procedure_id = result.root.public_digest().to_string();
    // A call-shaped access `x.foo()` legitimately produces a Call sink and a
    // Load sink at the same durable identity (file, span, member). The row
    // surface answers one row per (member access site, atom), so merge those
    // sinks exactly once before either live or durable projection.
    let mut merged: Vec<MergedClassSet> = Vec::new();
    let mut site_index: HashMap<(ProjectFile, SourceSpan, &str), usize> = HashMap::default();
    for set in &result.class_sets {
        if set.site.purpose != TypeFlowSitePurpose::MemberAccess {
            continue;
        }
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
                    dynamic_origins: Vec::new(),
                    status: set.status,
                });
                merged.last_mut().expect("the set was just pushed")
            }
        };
        for (identity, source) in &set.classes {
            let guard_only = source.kind
                == brokk_bifrost_flow::type_flow::SourceSiteKind::ConditionalNarrowingGuard;
            if let Some((_, existing)) = entry
                .classes
                .iter_mut()
                .find(|(class, _)| class == identity)
            {
                *existing &= guard_only;
            } else {
                entry.classes.push((identity.clone(), guard_only));
            }
        }
        for reason in &set.unknown {
            if !entry.unknown.contains(reason) {
                entry.unknown.push(reason.clone());
            }
        }
        for evidence in &set.dynamic_writes {
            let origin = evidence.origin();
            if !entry.dynamic_origins.contains(&origin) {
                entry.dynamic_origins.push(origin);
            }
        }
        entry.status = entry.status.weakest(set.status);
    }
    let mut rows = Vec::new();
    for set in &merged {
        let range = source_range(set.span);
        let portable_path = WorkspaceRelativePath::try_from_path(set.file.rel_path()).ok();
        for (identity, guard_only) in &set.classes {
            let class = identity.qualified_name().to_string();
            let origin = match identity {
                ClassIdentity::Workspace(_) => "workspace".to_string(),
                ClassIdentity::External { .. } => "external".to_string(),
                ClassIdentity::Intrinsic { .. } => {
                    unreachable!("intrinsic language roots do not enter type inference")
                }
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
                guard_only: *guard_only,
                origin,
                status: set.status.label(),
            });
        }
        for origin in set
            .unknown
            .iter()
            .filter(|reason| **reason != UnknownReason::DynamicFieldWrite)
            .map(|reason| format!("unknown:{reason}"))
            .chain(set.dynamic_origins.iter().cloned())
        {
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
                guard_only: false,
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
            && left.guard_only == right.guard_only
    });
    rows
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ClassSetRowAtomOrder<'a> {
    Workspace(&'a str),
    External(&'a str),
    Unknown(UnknownReason),
    DynamicWrite(&'a str),
}

fn class_set_row_atom_order(row: &ClassSetRowValue) -> ClassSetRowAtomOrder<'_> {
    match (row.origin.as_str(), row.class.as_deref()) {
        ("workspace", Some(class)) => ClassSetRowAtomOrder::Workspace(class),
        ("external", Some(class)) => ClassSetRowAtomOrder::External(class),
        (origin, None) if origin.starts_with("unknown:dynamic_field_write:") => {
            ClassSetRowAtomOrder::DynamicWrite(origin)
        }
        (origin, None) => ClassSetRowAtomOrder::Unknown(
            UnknownReason::from_label(
                origin
                    .strip_prefix("unknown:")
                    .expect("Unknown origins carry their typed reason label"),
            )
            .expect("Unknown origins carry a live typed reason label"),
        ),
        _ => unreachable!("live class-set projection preserves atom pairing"),
    }
}

fn persisted_class_set_row(
    ordinal: usize,
    row: &ClassSetRowValue,
) -> Option<PersistedClassSetRootRow> {
    // Site-bearing dynamic survey evidence is request-local until its solver
    // work and source dependencies have a durable replay contract.
    if row.origin == "unknown:dynamic_field_write"
        || row.origin.starts_with("unknown:dynamic_field_write:")
    {
        return None;
    }
    let atom = persisted_class_set_atom(row);
    Some(PersistedClassSetRootRow {
        ordinal: u32::try_from(ordinal).ok()?,
        relative_path: row.portable_path.as_ref()?.as_path().to_path_buf(),
        span: row.span,
        member: row.member.clone().into_boxed_str(),
        atom,
        status: PersistedClassSetStatus::from_label(row.status)?,
        guard_only: row.guard_only,
    })
}

fn persisted_class_set_atom(row: &ClassSetRowValue) -> PersistedClassSetAtom {
    match class_set_row_atom_order(row) {
        ClassSetRowAtomOrder::Workspace(class) => {
            PersistedClassSetAtom::WorkspaceClass(class.to_owned().into_boxed_str())
        }
        ClassSetRowAtomOrder::External(class) => {
            PersistedClassSetAtom::ExternalClass(class.to_owned().into_boxed_str())
        }
        ClassSetRowAtomOrder::Unknown(reason) => PersistedClassSetAtom::Unknown(reason),
        ClassSetRowAtomOrder::DynamicWrite(_) => {
            unreachable!("dynamic field writes are filtered before persistence")
        }
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
                PersistedClassSetAtom::Unknown(reason) => (None, format!("unknown:{reason}")),
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
                guard_only: row.guard_only,
            }
        })
        .collect()
}

pub(super) fn source_range(span: SourceSpan) -> Range {
    Range {
        start_byte: span.start_byte() as usize,
        end_byte: span.end_byte() as usize,
        start_line: span.start().line() as usize + 1,
        end_line: span.end().line() as usize + 1,
    }
}

fn extend_distinct(
    destination: &mut Vec<CodeQueryExhaustedRoot>,
    entries: Vec<CodeQueryExhaustedRoot>,
) {
    for entry in entries {
        if !destination.contains(&entry) {
            destination.push(entry);
        }
    }
}

/// Project one root's typed exhaustion evidence onto the diagnostic wire:
/// the root's path and qualified name, the lane, the charge that did not fit,
/// and the feedback iteration that produced it.
fn exhausted_root_entries<'lane>(
    procedure: &SemanticProcedureValue,
    evidence: &RootIncompleteEvidence,
    lanes: impl Iterator<Item = &'lane RootExhaustedLane>,
) -> Vec<CodeQueryExhaustedRoot> {
    let path = rel_path_string(procedure.file());
    let name = procedure_name(&procedure.handle);
    lanes
        .map(|lane| {
            let (lane_label, stage, charge) = match lane {
                RootExhaustedLane::Solver(exceeded) => (
                    format!("solver/{}", exceeded.dimension().label()),
                    None,
                    Some(CodeQueryExhaustedCharge {
                        attempted: exceeded.attempted(),
                        limit: exceeded.limit(),
                    }),
                ),
                RootExhaustedLane::Cancelled => ("solver/cancelled".to_string(), None, None),
                RootExhaustedLane::Semantic { stage, exceeded } => (
                    exceeded.map_or_else(
                        || "semantic/unrecorded".to_string(),
                        |exceeded| format!("semantic/{}", exceeded.dimension().label()),
                    ),
                    Some(stage.label().to_string()),
                    exceeded.map(|exceeded| CodeQueryExhaustedCharge {
                        attempted: exceeded.attempted(),
                        limit: exceeded.limit(),
                    }),
                ),
            };
            CodeQueryExhaustedRoot {
                path: path.clone(),
                procedure: Some(name.clone()),
                lane: lane_label,
                stage,
                charge,
                feedback_iteration: Some(evidence.feedback_iteration),
            }
        })
        .collect()
}

/// The procedure's declaration path, rendered the way a reader spells it:
/// named segments joined, file segments dropped.
pub(super) fn procedure_name(root: &ProcedureHandle) -> String {
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

fn is_python_iterator_method(procedure: &SemanticProcedureValue) -> bool {
    language_for_file(procedure.file()) == crate::analyzer::Language::Python
        && procedure
            .handle
            .semantics()
            .locator()
            .declaration()
            .segments()
            .last()
            .and_then(|segment| segment.name())
            == Some("__iter__")
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

fn project_absent_members(
    workspace: &WorkspaceAnalyzer,
    procedure: &SemanticProcedureValue,
    result: &TypeFlowRootResult,
) -> Vec<AbsentMemberFindingValue> {
    let caller = procedure_name(&procedure.handle);
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
            class_name: match &finding.class {
                ClassIdentity::Workspace(unit) => unit.terminal_name().to_owned(),
                ClassIdentity::External { qualified_name, .. } => qualified_name.to_string(),
                ClassIdentity::Intrinsic { qualified_name } => qualified_name.to_string(),
            },
            proof: finding.proof.clone(),
            roots: vec![AbsentMemberRootEvidence {
                root_procedure_id: super::semantic::procedure_wire_id(&finding.root),
                origin_file: finding.origin.file.clone(),
                origin_range: source_range(finding.origin.span),
                origin_span: finding.origin.span,
                origin_kind: finding.origin.kind,
                also_fails_at: finding.also_fails_at.clone(),
                origin_is_guard: finding.origin.kind == SourceSiteKind::NarrowingGuard,
                caller: caller.clone(),
                witness: finding
                    .witness
                    .as_ref()
                    .map(|witness| {
                        super::witness_projection::ProjectedSummaryWitness::new(
                            workspace,
                            witness,
                            usize::MAX,
                            usize::MAX,
                        )
                    })
                    .map_err(Clone::clone),
            }],
        };
        if let Some(index) = seen.get(&key).copied() {
            rows[index].merge_evidence(value);
        } else {
            seen.insert(key, rows.len());
            rows.push(value);
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::{
        AbsentMemberFindingValue, AbsentMemberProof, AbsentMemberRootEvidence,
        CodeQueryRootAllotment, ROOT_RESULT_ALGORITHM_ID, SourceSiteKind, TypeFlowQueryState,
        capture_query_reads, root_result_semantics_digest,
    };
    use crate::analyzer::semantic::{
        ProcedureHandle, SemanticBudget, SemanticBudgetDimension, SemanticRequest, SemanticWork,
        SourcePosition, SourceSpan, type_flow_adapter,
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
        SolverBudgetDimension, SolverWork, SummaryDataflowResult, SummarySolveInput,
        SummaryWitness, SummaryWitnessError, WitnessReconstructionLimits, WitnessRetentionLimits,
        solve_with_summaries,
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
        workspace: &WorkspaceAnalyzer,
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
            class_name: "Missing".to_owned(),
            proof: AbsentMemberProof::Proven,
            roots: vec![AbsentMemberRootEvidence {
                root_procedure_id: "root".to_owned(),
                origin_file: file,
                origin_range: range,
                origin_span: SourceSpan::new(
                    SourcePosition::new(0, 0, 0),
                    SourcePosition::new(1, 0, 1),
                )
                .expect("ordered test span"),
                origin_kind: SourceSiteKind::Unknown,
                also_fails_at: Vec::new(),
                origin_is_guard: false,
                caller: "root".to_owned(),
                witness: witness.map(|witness| {
                    super::super::witness_projection::ProjectedSummaryWitness::new(
                        workspace,
                        &witness,
                        usize::MAX,
                        usize::MAX,
                    )
                }),
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

    // The oracle is an independent head solve, not a second read-ledger capture.
    // Kept beside the order test to exercise private products through solve_live.
    mod read_set_mutations {
        use super::super::{CachedTypeFlowAnalysis, TypeFlowRootMemo, TypeFlowRootProduct};
        use super::*;
        use crate::structural::search::semantic::SemanticQueryContext;
        use brokk_bifrost_analysis::analyzer::invalidation::{
            DerivedArtifactId, DerivedArtifactKind,
        };
        use brokk_bifrost_analysis::analyzer::read_ledger::read_set_digest;
        use brokk_bifrost_analysis::analyzer::{
            ChangedFacts, LookupMemo, LookupReplayLimits, ReadVerdict, verify_read_set_for_artifact,
        };
        use brokk_bifrost_analysis::analyzer::{FactSubject, LookupQuestion, WorkspaceFactFamily};
        use brokk_bifrost_test_macros::hardwon;
        use std::sync::Arc;

        const CLASSES: &str = "class Item:\n    def ping(self):\n        return self\n\nclass Other:\n    pass\n\nclass Box:\n    def __init__(self):\n        alias = self\n        alias.value = Item()\n";
        const CHILDREN: &str = "from classes import Item, Box, Other\n\nclass Child(Item):\n    pass\n\nclass ExistingChild(Item):\n    def ping(self):\n        return Other()\n\nclass SubBox(Box):\n    pass\n\ndef write_child():\n    box = SubBox()\n    box.value = Item()\n    return box.value.missing\n";
        const CALLEE: &str = "from classes import Item, Other\n\ndef make():\n    return Item()\n";
        const APP: &str = "from classes import Item, Box\nfrom children import Child, SubBox\nfrom callee import make\n\ndef dispatch():\n    value = Child()\n    return value.ping().missing\n\ndef base_dispatch():\n    value = Item()\n    return value.ping().missing\n\ndef alias_field():\n    box = Box()\n    alias = box\n    return alias.value.missing\n\ndef subclass_field():\n    box = SubBox()\n    return box.value.missing\n\ndef cross_file():\n    return make().missing\n\ndef independent():\n    return Item().missing\n";

        fn solve(
            workspace: &WorkspaceAnalyzer,
            state: &mut TypeFlowQueryState,
            root: &super::super::SemanticProcedureValue,
        ) -> Arc<TypeFlowRootProduct> {
            state.release_file_window();
            let result = state.solve_live(
                workspace,
                root,
                &mut SemanticBudget::default(),
                CodeQueryValueFlowLimits::default(),
                &CancellationToken::default(),
                workspace.analyzer().active_semantic_model_snapshot(),
            );
            let Some(CachedTypeFlowAnalysis::Owned(result)) = result else {
                panic!(
                    "expected owned root product: {:?}",
                    state.take_diagnostics()
                );
            };
            assert_eq!(
                result.product.unattributed_reads, 0,
                "every differential capture must name its inputs"
            );
            result.product
        }

        // Same semantic fields as the order oracle, split out to name each gap.
        fn observations(p: &TypeFlowRootProduct) -> Vec<(&'static str, String)> {
            vec![
                ("root", format!("{:?}", p.root)),
                ("failure", format!("{:?}", p.failure)),
                ("projected_rows", format!("{:?}", p.projected_rows)),
                ("class_sets", format!("{:?}", p.class_sets)),
                ("findings", format!("{:?}", p.findings)),
                ("complete", format!("{:?}", p.complete)),
                (
                    "semantic_budget_exhausted",
                    format!("{:?}", p.semantic_budget_exhausted),
                ),
                (
                    "incomplete_evidence",
                    format!("{:?}", p.incomplete_evidence),
                ),
                ("persistence_status", format!("{:?}", p.persistence_status)),
            ]
        }

        struct HeadFieldSlotAnswers(Arc<super::super::FieldSlotIndex>);

        impl brokk_bifrost_analysis::analyzer::SummaryAnswers for HeadFieldSlotAnswers {
            fn summary_content(
                &self,
                _identity: super::super::StableDigest,
            ) -> Option<super::super::StableDigest> {
                None
            }
            fn workspace_fact(
                &self,
                family: WorkspaceFactFamily,
                language: Language,
                subject: &FactSubject,
            ) -> Option<super::super::StableDigest> {
                match (family, language, subject) {
                    (WorkspaceFactFamily::FieldSlots, _, FactSubject::Class { class }) => {
                        Some(self.0.class_content(*class))
                    }
                    (WorkspaceFactFamily::FieldSlots, _, FactSubject::Whole) => {
                        Some(self.0.digest())
                    }
                    _ => None,
                }
            }
        }

        fn head_field_answers(
            workspace: &WorkspaceAnalyzer,
            root: &super::super::SemanticProcedureValue,
        ) -> HeadFieldSlotAnswers {
            let mut state = TypeFlowQueryState::default();
            state.select_summary_partition(workspace);
            let (_, _, index) = state
                .query_field_slots(
                    workspace,
                    root,
                    &mut SemanticBudget::default(),
                    &CancellationToken::default(),
                    workspace.analyzer().active_semantic_model_snapshot(),
                )
                .expect("head field-slot acquisition");
            HeadFieldSlotAnswers(index)
        }

        fn before_field_slot_reads(
            product: &TypeFlowRootProduct,
        ) -> Vec<brokk_bifrost_analysis::analyzer::ReadKey> {
            product
                .reads
                .iter()
                .filter(|key| {
                    !matches!(
                        key,
                        brokk_bifrost_analysis::analyzer::ReadKey::Lookup {
                            kind: brokk_bifrost_analysis::analyzer::LookupKind::WorkspaceFact,
                            question: LookupQuestion::WorkspaceFact {
                                family: WorkspaceFactFamily::FieldSlots,
                                ..
                            },
                            ..
                        }
                    )
                })
                .cloned()
                .collect()
        }

        fn check(case: &str, path: &str, replacement: &str) {
            let project = InlineTestProject::with_language(Language::Python)
                .with_git()
                .file("classes.py", CLASSES)
                .file("children.py", CHILDREN)
                .file("callee.py", CALLEE)
                .file("app.py", APP)
                .file(
                    "dynamic.py",
                    "from classes import Item\n\nsetattr(Item, 'dynamic', Item())\n",
                )
                .file("unrelated.py", "def unrelated():\n    return 1\n")
                .build();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let mut context = SemanticQueryContext::new(&base, None, Default::default());
            let mut state = TypeFlowQueryState::default();
            state.set_root_memo(Some(TypeFlowRootMemo::default()));
            let mut products = Vec::new();
            for path in [
                "app.py",
                "children.py",
                "classes.py",
                "callee.py",
                "dynamic.py",
                "unrelated.py",
            ] {
                for reference in context.procedure_references(&project.file(path)) {
                    let root = context
                        .resolve_procedure_reference(&reference)
                        .expect("base root");
                    products.push((reference, solve(&base, &mut state, &root)));
                }
            }
            assert!(products.len() >= 10, "must actually solve multiple roots");
            assert!(
                products.iter().any(|(_, p)| !p.class_sets.is_empty()),
                "must exercise class-set products"
            );
            project
                .file(path)
                .write(replacement)
                .expect("single-file mutation");
            let head = project.workspace_analyzer(AnalyzerConfig::default());
            let changed = ChangedFacts::between(&base, &head);
            assert!(
                changed.is_complete(),
                "incomplete difference: {:?}",
                changed.incompleteness()
            );
            assert_eq!(changed.changed_path_count(), 1);
            // Root capture has no policy wrapper. These fixed inputs must never
            // accidentally reject a product for an unrelated policy/config key.
            let inputs = brokk_bifrost_analysis::test_support::read_ledger_test_inputs();
            let head_root = named_root(&head, &project, "app.py", "independent");
            let answers = head_field_answers(&head, &head_root);
            let mut memo = LookupMemo::new();
            let mut head_context = SemanticQueryContext::new(&head, None, Default::default());
            let mut rejected = 0;
            let mut before_rejected = 0;
            let mut accepted = 0;
            let mut gaps = Vec::new();
            let mut rejected_roots = Vec::new();
            let mut empty_captures = 0;
            for (reference, product) in &products {
                let root_name = format!(
                    "{}::{:?}",
                    reference.public.path,
                    reference
                        .locator
                        .declaration()
                        .segments()
                        .iter()
                        .filter_map(|segment| segment.name())
                        .collect::<Vec<_>>()
                );
                empty_captures += usize::from(product.reads.is_empty());
                assert!(
                    !product.reads.iter().any(|key| matches!(
                        key,
                        brokk_bifrost_analysis::analyzer::ReadKey::Models(_)
                            | brokk_bifrost_analysis::analyzer::ReadKey::Policy { .. }
                            | brokk_bifrost_analysis::analyzer::ReadKey::Configuration(_)
                            | brokk_bifrost_analysis::analyzer::ReadKey::Epoch(_)
                    )),
                    "root unexpectedly captured policy wrapper inputs"
                );
                let artifact = DerivedArtifactId::new(
                    DerivedArtifactKind::PolicyEvaluationUnit,
                    read_set_digest(&product.reads).digest(),
                );
                let verdict = verify_read_set_for_artifact(
                    artifact,
                    &head,
                    &changed,
                    &inputs,
                    &product.reads,
                    LookupReplayLimits::default(),
                    &answers,
                    &mut memo,
                );
                let before = verify_read_set_for_artifact(
                    artifact,
                    &head,
                    &changed,
                    &inputs,
                    &before_field_slot_reads(product),
                    LookupReplayLimits::default(),
                    &answers,
                    &mut memo,
                );
                before_rejected += usize::from(before != ReadVerdict::Unchanged);
                assert!(
                    before == ReadVerdict::Unchanged || verdict != ReadVerdict::Unchanged,
                    "adding field-slot reads must not retain a previously rejected root"
                );
                eprintln!(
                    "{case} root={root_name} reads={:?} verdict={verdict:?}",
                    product.reads
                );
                if verdict != ReadVerdict::Unchanged {
                    rejected += 1;
                    rejected_roots.push(root_name);
                    continue;
                }
                accepted += 1;
                let head_reference = head_context
                    .procedure_references(&reference.file)
                    .into_iter()
                    .find(|candidate| candidate.locator == reference.locator);
                let Some(root) = head_reference
                    .as_ref()
                    .and_then(|reference| head_context.resolve_procedure_reference(reference))
                else {
                    gaps.push(format!(
                        "case={case} root={root_name} field=root_resolution"
                    ));
                    continue;
                };
                let mut fresh = TypeFlowQueryState::default();
                fresh.set_root_memo(Some(TypeFlowRootMemo::default()));
                let fresh = solve(&head, &mut fresh, &root);
                for ((field, before), (_, after)) in
                    observations(product).into_iter().zip(observations(&fresh))
                {
                    if before != after {
                        gaps.push(format!("case={case} root={root_name} field={field}\nbefore={before}\nafter={after}"));
                    }
                }
            }
            eprintln!(
                "M4A case={case} total={} rejected={rejected} accepted={accepted} differing_fields={}",
                products.len(),
                gaps.len()
            );
            eprintln!(
                "M4A case={case} before_rejected={before_rejected} after_rejected={rejected}"
            );
            eprintln!(
                "M4A case={case} empty_captures={empty_captures} rejected_roots={rejected_roots:?}"
            );
            assert!(accepted > 0, "verification must actually accept products");
            if case == "unrelated" {
                let expected = [
                    // Known false rejection, not a dependency on the edit: this
                    // product records receiver-hinted and unhinted ProcedureDispatch
                    // answers under one question, so it is always rejected.
                    // #7758 will remove this root from the expected set.
                    "app.py::[\"app.py\", \"base_dispatch\"]",
                    // The edit changes this root's own body.
                    "unrelated.py::[\"unrelated.py\", \"unrelated\"]",
                ];
                let mut actual = rejected_roots
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                actual.sort_unstable();
                assert_eq!(
                    actual, expected,
                    "unexpected unrelated-edit rejections: {rejected_roots:?}"
                );
            }
            if case == "add_override" {
                assert!(
                    rejected_roots
                        .iter()
                        .any(|name| name.contains("\"dispatch\"")),
                    "override must reject dispatching root: {rejected_roots:?}"
                );
            }
            assert!(
                gaps.is_empty(),
                "accepted stale products:\n{}",
                gaps.join("\n")
            );
        }

        fn named_root(
            workspace: &WorkspaceAnalyzer,
            project: &BuiltInlineTestProject,
            path: &str,
            name: &str,
        ) -> super::super::SemanticProcedureValue {
            let file = project.file(path);
            let declarations = workspace
                .analyzer()
                .declarations_named(&file, name)
                .into_iter()
                .filter(|unit| unit.is_function())
                .collect::<Vec<_>>();
            let [declaration] = declarations.as_slice() else {
                panic!("named fixture declaration {path}::{name}: {declarations:?}");
            };
            let ranges = workspace.analyzer().ranges_of(declaration);
            let [range] = ranges.as_slice() else {
                panic!("named fixture declaration ranges {path}::{name}: {ranges:?}");
            };
            let source = workspace
                .analyzer()
                .indexed_source(&file)
                .expect("fixture source");
            let mut context = SemanticQueryContext::new(workspace, None, Default::default());
            // Source/declaration lookup is shared by every language; the cheap
            // pre-lowering inventory hook is not implemented by every adapter.
            let procedures = context.procedure_of_source_range(
                &file,
                *range,
                crate::analyzer::semantic::ContentIdentity::hash_bytes(source.as_bytes()),
            );
            let mut matching = procedures
                .into_iter()
                .filter(|procedure| {
                    procedure
                        .handle
                        .semantics()
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .is_some_and(|segment| segment.name() == Some(name))
                })
                .collect::<Vec<_>>();
            assert_eq!(
                matching.len(),
                1,
                "named fixture root {path}::{name}: {matching:?}"
            );
            matching.remove(0)
        }

        fn names_path(key: &brokk_bifrost_analysis::analyzer::ReadKey, path: &str) -> bool {
            use brokk_bifrost_analysis::analyzer::LookupQuestion;
            use brokk_bifrost_analysis::analyzer::ReadKey;
            match key {
                ReadKey::File { rel_path, .. } | ReadKey::PathAbsent { rel_path, .. } => {
                    rel_path.as_ref() == path
                }
                ReadKey::Artifact { rel_path, .. } => rel_path.as_deref() == Some(path),
                ReadKey::Lookup { question, .. } => match question {
                    LookupQuestion::Declaration { rel_path, .. }
                    | LookupQuestion::File { rel_path }
                    | LookupQuestion::CallSite { rel_path, .. }
                    | LookupQuestion::ProcedureCallSite { rel_path, .. } => {
                        rel_path.as_ref() == path
                    }
                    LookupQuestion::Name { .. }
                    | LookupQuestion::Summary { .. }
                    | LookupQuestion::WorkspaceFact { .. } => false,
                },
                _ => false,
            }
        }

        // Compare even rejected roots here: the fresh solve also proves whether
        // the mutation changed the product, independently of the expected verdict.
        fn targeted_verdict(
            case: &str,
            project: &BuiltInlineTestProject,
            base: &WorkspaceAnalyzer,
            product: &TypeFlowRootProduct,
            root_path: &str,
            root_name: &str,
        ) -> (ReadVerdict, Vec<&'static str>) {
            let head = project.workspace_analyzer(AnalyzerConfig::default());
            let changed = ChangedFacts::between(base, &head);
            assert!(changed.is_complete(), "{:?}", changed.incompleteness());
            assert_eq!(changed.changed_path_count(), 1);
            let artifact = DerivedArtifactId::new(
                DerivedArtifactKind::PolicyEvaluationUnit,
                read_set_digest(&product.reads).digest(),
            );
            let root = named_root(&head, project, root_path, root_name);
            let answers = head_field_answers(&head, &root);
            let verdict = verify_read_set_for_artifact(
                artifact,
                &head,
                &changed,
                &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
                &product.reads,
                LookupReplayLimits::default(),
                &answers,
                &mut LookupMemo::new(),
            );
            let before = verify_read_set_for_artifact(
                artifact,
                &head,
                &changed,
                &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
                &before_field_slot_reads(product),
                LookupReplayLimits::default(),
                &answers,
                &mut LookupMemo::new(),
            );
            if let Some(family) = match case {
                "T8" => Some(WorkspaceFactFamily::PythonSavedDefaults),
                "T13" => Some(WorkspaceFactFamily::PythonModuleMemberMutation),
                _ => None,
            } {
                // Prove this family's certificate rejects independently of
                // field-slot coverage or any other named input in the product.
                let family_reads = before_field_slot_reads(product)
                    .into_iter()
                    .filter(|key| {
                        matches!(key,
                            brokk_bifrost_analysis::analyzer::ReadKey::Lookup {
                                question: LookupQuestion::WorkspaceFact { family: recorded, .. }, ..
                            } if *recorded == family
                        )
                    })
                    .collect::<Vec<_>>();
                assert!(
                    !family_reads.is_empty(),
                    "{case} must name {family:?}: {:?}",
                    product.reads
                );
                let family_verdict = verify_read_set_for_artifact(
                    artifact,
                    &head,
                    &changed,
                    &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
                    &family_reads,
                    LookupReplayLimits::default(),
                    &answers,
                    &mut LookupMemo::new(),
                );
                assert_ne!(
                    family_verdict,
                    ReadVerdict::Unchanged,
                    "{case} own Fact accepted: {family_reads:?}"
                );
                eprintln!("M4A {case} family_verdict={family_verdict:?}");
            }
            eprintln!("M4A {case} before_verdict={before:?} after_verdict={verdict:?}");
            assert!(before == ReadVerdict::Unchanged || verdict != ReadVerdict::Unchanged);
            if product.reads.iter().any(|key| {
                matches!(
                    key,
                    brokk_bifrost_analysis::analyzer::ReadKey::Lookup {
                        kind: brokk_bifrost_analysis::analyzer::LookupKind::WorkspaceFact,
                        question: LookupQuestion::WorkspaceFact {
                            family: WorkspaceFactFamily::FieldSlots,
                            ..
                        },
                        ..
                    }
                )
            }) {
                let unavailable = verify_read_set_for_artifact(
                    artifact,
                    &head,
                    &changed,
                    &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
                    &product.reads,
                    LookupReplayLimits::default(),
                    &brokk_bifrost_analysis::analyzer::NoSummaryAnswers,
                    &mut LookupMemo::new(),
                );
                assert!(
                    unavailable != ReadVerdict::Unchanged,
                    "unanswerable field reads must invalidate"
                );
            }
            let root = named_root(&head, project, root_path, root_name);
            let fresh = solve(&head, &mut TypeFlowQueryState::default(), &root);
            let mut differences = Vec::new();
            for ((field, before), (_, after)) in
                observations(product).into_iter().zip(observations(&fresh))
            {
                if before != after {
                    differences.push(field);
                    eprintln!("{case} field={field}\nbefore={before}\nafter={after}");
                }
            }
            eprintln!(
                "M4A {case} verdict={verdict:?} differing_fields={differences:?} reads={:?}",
                product.reads
            );
            (verdict, differences)
        }

        fn field_fixture() -> BuiltInlineTestProject {
            InlineTestProject::with_language(Language::Python).with_git()
                .file("c.py", "class Item:\n    pass\n\nclass Other:\n    pass\n\nclass C:\n    def __init__(self):\n        self.attr = Item()\n")
                .file("r.py", "from c import C\n\nclass Reader(C):\n    def R(self):\n        value = self.attr\n        return value.missing\n")
                .file("u.py", "marker = 0\n").build()
        }

        fn mutate_external_field(project: &BuiltInlineTestProject) {
            project
                .file("u.py")
                .write("from c import C, Other\n\nAlias = C\nAlias.attr = Other()\n")
                .expect("external alias field write");
        }

        #[test]
        #[hardwon(
            "#2445: external alias stores change field slots without invalidating root reads"
        )]
        fn read_set_mutation_external_field_slots() {
            let project = field_fixture();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let root = named_root(&base, &project, "r.py", "R");
            let mut state = TypeFlowQueryState::default();
            let product = solve(&base, &mut state, &root);
            assert_eq!(
                state.work().field_slot_builds,
                1,
                "T1 must build cold field slots"
            );
            assert!(
                !product.reads.iter().any(|key| names_path(key, "u.py")),
                "T1 requires u.py outside root reads: {:?}",
                product.reads
            );
            mutate_external_field(&project);
            let (verdict, differences) =
                targeted_verdict("T1", &project, &base, &product, "r.py", "R");
            assert_eq!(
                differences,
                vec!["projected_rows", "class_sets", "findings"],
                "mutation must change the slots consumed by R"
            );
            assert!(
                verdict != ReadVerdict::Unchanged,
                "external field-slot edit accepted; fresh differences={differences:?}"
            );
        }

        #[test]
        fn read_set_mutation_warm_value_flow() {
            let project = InlineTestProject::with_language(Language::Python).with_git()
                .file("c.py", "class Item:\n    pass\n\nclass Other:\n    pass\n")
                .file("f.py", "from c import Item, Other\n\ndef f():\n    return Item()\n")
                .file("r.py", "from f import f\n\ndef A():\n    return f().missing\n\ndef B():\n    return f().missing\n").build();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let mut state = TypeFlowQueryState::default();
            let a = named_root(&base, &project, "r.py", "A");
            let b = named_root(&base, &project, "r.py", "B");
            let before_a = state.value_flow_cache.stats();
            let _a = solve(&base, &mut state, &a);
            let after_a = state.value_flow_cache.stats();
            let product = solve(&base, &mut state, &b);
            let b_stats = state.value_flow_cache.stats().saturating_sub(after_a);
            eprintln!(
                "T2 A_stats={:?} B_stats={b_stats:?}",
                after_a.saturating_sub(before_a)
            );
            assert!(
                b_stats.snapshot_hits > 0,
                "B must hit warmed value-flow snapshots: {b_stats:?}"
            );
            let names_f_artifact = product.reads.iter().any(|key| matches!(key,
                brokk_bifrost_analysis::analyzer::ReadKey::Artifact { rel_path: Some(path), .. } if path.as_ref() == "f.py"));
            eprintln!("T2 B_names_f_artifact={names_f_artifact}");
            project
                .file("f.py")
                .write("from c import Item, Other\n\ndef f():\n    return Other()\n")
                .expect("callee mutation");
            let (verdict, differences) =
                targeted_verdict("T2", &project, &base, &product, "r.py", "B");
            assert!(
                verdict != ReadVerdict::Unchanged,
                "warm callee edit accepted; fresh differences={differences:?}"
            );
        }

        #[test]
        fn read_set_mutation_added_typescript_alias_target() {
            use brokk_bifrost_analysis::analyzer::ReadKey;
            let project = InlineTestProject::with_language(Language::TypeScript).with_git()
                .file("src/app.ts", "import { Owner } from '@/owner';\nfunction root(value: Owner) { return value.missing; }\n")
                .file("tsconfig.json", r#"{"compilerOptions":{"baseUrl":".","paths":{"@/*":["src/*"]}}}"#)
                .build();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let root = named_root(&base, &project, "src/app.ts", "root");
            let product = solve(&base, &mut TypeFlowQueryState::default(), &root);
            let negative_reads = product.reads.iter().filter(|key| matches!(key, ReadKey::PathAbsent { rel_path, .. } if rel_path.as_ref() == "src/owner.ts")).cloned().collect::<Vec<_>>();
            assert!(
                !negative_reads.is_empty(),
                "alias miss did not name its target: {:?}",
                product.reads
            );
            project
                .file("src/owner.ts")
                .write("export class Owner {}\n")
                .unwrap();
            let (verdict, differences) = targeted_verdict(
                "added_typescript_alias_target",
                &project,
                &base,
                &product,
                "src/app.ts",
                "root",
            );
            assert_ne!(verdict, ReadVerdict::Unchanged);
            assert!(
                !differences.is_empty(),
                "adding the imported class must change the fresh root product"
            );
            let head = project.workspace_analyzer(AnalyzerConfig::default());
            let changed = ChangedFacts::between(&base, &head);
            let artifact = DerivedArtifactId::new(
                DerivedArtifactKind::PolicyEvaluationUnit,
                read_set_digest(&negative_reads).digest(),
            );
            assert_ne!(
                verify_read_set_for_artifact(
                    artifact,
                    &head,
                    &changed,
                    &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
                    &negative_reads,
                    LookupReplayLimits::default(),
                    &brokk_bifrost_analysis::analyzer::NoSummaryAnswers,
                    &mut LookupMemo::new()
                ),
                ReadVerdict::Unchanged
            );
        }

        #[test]
        fn read_set_mutation_new_file_dispatch() {
            let project = InlineTestProject::with_language(Language::Python).with_git()
                .file("c.py", "class Item:\n    pass\n\nclass Other:\n    pass\n\nclass C:\n    def method(self):\n        return Item()\n")
                .file("r.py", "from c import C\n\ndef R(value: C):\n    return value.method().missing\n").build();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let root = named_root(&base, &project, "r.py", "R");
            let product = solve(&base, &mut TypeFlowQueryState::default(), &root);
            assert!(
                !product.reads.iter().any(|key| names_path(key, "s.py")),
                "new file must not have been probed"
            );
            project.file("s.py").write("from c import C, Other\n\nclass Sub(C):\n    def method(self):\n        return Other()\n\ninstance = Sub()\n").expect("new subclass file");
            let (verdict, differences) =
                targeted_verdict("T3", &project, &base, &product, "r.py", "R");
            assert!(
                verdict != ReadVerdict::Unchanged,
                "new dispatch subclass accepted; fresh differences={differences:?}"
            );
        }

        #[test]
        #[hardwon("#2445: memory-cached field slots replay no dependency keys into root capture")]
        fn read_set_mutation_field_slot_memory_hit() {
            let project = field_fixture();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let flow = brokk_bifrost_flow::FlowWorkspaceState::new();
            let root = named_root(&base, &project, "r.py", "R");
            let mut first = TypeFlowQueryState::new(
                flow.value_flow_cache(),
                flow.type_flow_summaries(),
                CodeQueryRootAllotment::from_execution_limits(
                    &crate::structural::CodeQueryExecutionLimits::default(),
                ),
            );
            let _first = solve(&base, &mut first, &root);
            let mut second = TypeFlowQueryState::new(
                flow.value_flow_cache(),
                flow.type_flow_summaries(),
                CodeQueryRootAllotment::from_execution_limits(
                    &crate::structural::CodeQueryExecutionLimits::default(),
                ),
            );
            let product = solve(&base, &mut second, &root);
            eprintln!(
                "T4 first_work={:?} second_work={:?}",
                first.work(),
                second.work()
            );
            assert_eq!(
                second.work().field_slot_memory_hits,
                1,
                "second query must acquire memory-cached field slots"
            );
            assert_eq!(second.work().field_slot_builds, 0);
            assert!(
                !product.reads.iter().any(|key| names_path(key, "u.py")),
                "T4 requires u.py outside root reads: {:?}",
                product.reads
            );
            mutate_external_field(&project);
            let (verdict, differences) =
                targeted_verdict("T4", &project, &base, &product, "r.py", "R");
            assert_eq!(
                differences,
                vec!["projected_rows", "class_sets", "findings"],
                "mutation must change the slots consumed by R"
            );
            assert!(
                verdict != ReadVerdict::Unchanged,
                "memory-hit field-slot edit accepted; fresh differences={differences:?}"
            );
        }

        #[test]
        #[hardwon(
            "#2445: external subclass-instance stores must invalidate inherited field-slot reads"
        )]
        fn read_set_mutation_external_subclass_field() {
            let project = field_fixture();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let root = named_root(&base, &project, "r.py", "R");
            let product = solve(&base, &mut TypeFlowQueryState::default(), &root);
            assert!(
                !product.reads.iter().any(|key| names_path(key, "u.py")),
                "external write file must not be read"
            );
            project.file("u.py").write("from c import C, Other\n\nclass Child(C):\n    pass\n\nobj = Child()\nalias = obj\nalias.attr = Other()\n").expect("subclass instance write");
            let (verdict, differences) =
                targeted_verdict("T5", &project, &base, &product, "r.py", "R");
            assert!(
                !differences.is_empty(),
                "subclass-instance mutation must change the fresh product"
            );
            assert!(
                verdict != ReadVerdict::Unchanged,
                "subclass-instance field write accepted: {differences:?}"
            );
        }

        #[test]
        fn read_set_mutation_first_external_field_write() {
            let project = InlineTestProject::with_language(Language::Python).with_git()
                .file("c.py", "class Other:\n    pass\n\nclass C:\n    pass\n")
                .file("r.py", "from c import C\n\nclass Reader(C):\n    def R(self):\n        return self.attr\n")
                .file("u.py", "marker = 0\n").build();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let root = named_root(&base, &project, "r.py", "R");
            let product = solve(&base, &mut TypeFlowQueryState::default(), &root);
            assert!(!product.reads.iter().any(|key| names_path(key, "u.py")));
            assert!(product.reads.iter().any(|key| matches!(key,
                brokk_bifrost_analysis::analyzer::ReadKey::Lookup {
                    kind: brokk_bifrost_analysis::analyzer::LookupKind::WorkspaceFact,
                            question: LookupQuestion::WorkspaceFact { family: WorkspaceFactFamily::FieldSlots, .. }, digest, ..
                } if *digest == brokk_bifrost_analysis::analyzer::read_ledger::absent_summary_digest()
            )), "the root must record a class with no slots: {:?}", product.reads);
            mutate_external_field(&project);
            let (verdict, differences) =
                targeted_verdict("T6", &project, &base, &product, "r.py", "R");
            assert!(!differences.is_empty());
            assert!(
                verdict != ReadVerdict::Unchanged,
                "first external write must reject an absent-slot read"
            );
        }

        #[test]
        fn read_set_mutation_warm_mro_change() {
            let project = InlineTestProject::with_language(Language::Python).with_git()
                .file("base.py", "class Item:\n    pass\n\nclass Other:\n    pass\n\nclass A:\n    def pick(self):\n        return Item()\n\nclass A2:\n    def pick(self):\n        return Other()\n")
                .file("mid.py", "from base import A, A2\n\nclass B(A):\n    pass\n")
                .file("r.py", "from mid import B\n\nclass Reader(B):\n    def R(self):\n        return self.pick().missing\n").build();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let _query = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(base.analyzer());
            let root = named_root(&base, &project, "r.py", "R");
            let mut state = TypeFlowQueryState::default();
            let _cold = solve(&base, &mut state, &root);
            let before = state.value_flow_cache.stats();
            let product = solve(&base, &mut state, &root);
            eprintln!(
                "T7 warm_stats={:?}",
                state.value_flow_cache.stats().saturating_sub(before)
            );
            assert!(
                state
                    .value_flow_cache
                    .stats()
                    .saturating_sub(before)
                    .dispatch_hits
                    > 0
            );
            project
                .file("mid.py")
                .write("from base import A, A2\n\nclass B(A2):\n    pass\n")
                .expect("base-class mutation without new method names");
            let (verdict, differences) =
                targeted_verdict("T7", &project, &base, &product, "r.py", "R");
            assert!(
                !differences.is_empty(),
                "inheritance edit must change dispatch's product"
            );
            assert!(
                verdict != ReadVerdict::Unchanged,
                "warm hierarchy edit accepted: {differences:?}"
            );
        }

        #[test]
        #[hardwon(
            "#2445: cached call bindings omit workspace Python default-mutation dependencies"
        )]
        fn read_set_mutation_warm_binding_default_metadata() {
            let project = InlineTestProject::with_language(Language::Python).with_git()
                .file("c.py", "class Item:\n    pass\n\nclass Other:\n    pass\n")
                .file("h.py", "from c import Item\n\ndef h(value=Item()):\n    return value\n")
                .file("f.py", "from h import h\n\ndef f():\n    return h()\n")
                .file("r.py", "from f import f\n\ndef A():\n    return f().missing\n\ndef B():\n    return f().missing\n")
                .file("u.py", "marker = 0\n").build();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let _query = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(base.analyzer());
            let mut state = TypeFlowQueryState::default();
            let a = named_root(&base, &project, "r.py", "A");
            let b = named_root(&base, &project, "r.py", "B");
            let _a = solve(&base, &mut state, &a);
            // Keep provider entries warm, but require full discovery of the
            // shared wrapper rather than cutting it with a class-set summary.
            state.summary_state = None;
            state.summary_partitions = Default::default();
            let before = state.value_flow_cache.stats();
            let product = solve(&base, &mut state, &b);
            let hits = state.value_flow_cache.stats().saturating_sub(before);
            eprintln!(
                "T8 B_stats={hits:?} complete={} persistence={:?}",
                product.complete, product.persistence_status
            );
            assert_eq!(
                product.unattributed_reads, 0,
                "the missing metadata dependency must not already be reported as unattributed"
            );
            assert!(
                hits.snapshot_hits > 0 && hits.binding_hits > 0,
                "must hit both value-flow caches"
            );
            assert!(
                !product.reads.iter().any(|key| names_path(key, "u.py")),
                "default mutation file must be outside the capture"
            );
            project
                .file("u.py")
                .write("from h import h\nfrom c import Other\n\nh.__defaults__ = (Other(),)\n")
                .expect("external callee-default mutation");
            let (verdict, differences) =
                targeted_verdict("T8", &project, &base, &product, "r.py", "B");
            assert!(
                !differences.is_empty(),
                "default metadata edit must affect binding precision"
            );
            assert!(
                verdict != ReadVerdict::Unchanged,
                "warm default metadata edit accepted: {differences:?}"
            );
        }

        #[test]
        #[hardwon("#2445: cached module-global seeds omit cross-file module mutation safety")]
        fn read_set_mutation_external_module_global() {
            let project = InlineTestProject::with_language(Language::Python)
                .with_git()
                .file(
                    "c.py",
                    "class Item:\n    pass\n\nvalue = Item()\n\ndef get():\n    return value\n",
                )
                .file(
                    "r.py",
                    "from c import get\n\ndef R():\n    return get().missing\n",
                )
                .file("u.py", "marker = 0\n")
                .build();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let root = named_root(&base, &project, "r.py", "R");
            let _query = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(base.analyzer());
            let mut state = TypeFlowQueryState::default();
            // Warm generation/query authorities and provider caches before the
            // measured capture; keep solving through the production root path.
            let _warm = solve(&base, &mut state, &root);
            state.summary_state = None;
            state.summary_partitions = Default::default();
            let product = solve(&base, &mut state, &root);
            assert_eq!(product.unattributed_reads, 0);
            assert_eq!(state.work().cache_hits, 0);
            assert_eq!(state.work().root_memo_hits, 0);
            assert!(
                !product.reads.iter().any(|key| names_path(key, "u.py")),
                "reads={:?}",
                product.reads
            );
            project
                .file("u.py")
                .write("import c\n\nc.value = None\n")
                .expect("external module global replacement");
            let (verdict, differences) =
                targeted_verdict("T13", &project, &base, &product, "r.py", "R");
            assert!(
                !differences.is_empty(),
                "module mutation must change the fresh product"
            );
            assert!(
                verdict != ReadVerdict::Unchanged,
                "external module global accepted: {differences:?}"
            );
        }

        #[test]
        #[hardwon("#2445: per-class field-slot content omits the dynamic store survey")]
        fn read_set_mutation_external_dynamic_survey() {
            let project = InlineTestProject::with_language(Language::Python)
                .with_git()
                .file("c.py", "class C:\n    pass\n")
                .file(
                    "r.py",
                    "from c import C\n\ndef R():\n    return C().missing\n",
                )
                .file("u.py", "marker = 0\n")
                .build();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let root = named_root(&base, &project, "r.py", "R");
            let _query = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(base.analyzer());
            let mut state = TypeFlowQueryState::default();
            // Warm generation/query authorities and provider caches before the
            // measured capture; keep solving through the production root path.
            let _warm = solve(&base, &mut state, &root);
            state.summary_state = None;
            state.summary_partitions = Default::default();
            let product = solve(&base, &mut state, &root);
            assert_eq!(product.unattributed_reads, 0);
            assert_eq!(state.work().cache_hits, 0);
            assert_eq!(state.work().root_memo_hits, 0);
            assert!(
                !product.reads.iter().any(|key| names_path(key, "u.py")),
                "reads={:?}",
                product.reads
            );
            assert!(
                product.reads.iter().any(|key| matches!(
                    key,
                    brokk_bifrost_analysis::analyzer::ReadKey::Lookup {
                        kind: brokk_bifrost_analysis::analyzer::LookupKind::WorkspaceFact,
                        question: LookupQuestion::WorkspaceFact {
                            family: WorkspaceFactFamily::FieldSlots,
                            ..
                        },
                        ..
                    }
                )),
                "the existing per-class key must actually be captured"
            );
            project.file("u.py").write("from c import C\n\ndef mutate(obj, name, value):\n    setattr(obj, name, value)\n\nmutate(C(), input(), None)\n")
                .expect("external dynamic write survey change");
            let (verdict, differences) =
                targeted_verdict("T14", &project, &base, &product, "r.py", "R");
            assert!(
                !differences.is_empty(),
                "dynamic survey must change the fresh product"
            );
            assert!(
                verdict != ReadVerdict::Unchanged,
                "external dynamic survey accepted: {differences:?}"
            );
        }

        #[test]
        #[hardwon("#2445: source-root module discovery omits package path-extension authority")]
        fn read_set_mutation_external_package_path_authority() {
            let project = InlineTestProject::with_language(Language::Python)
                .with_git()
                .file(
                    "pyproject.toml",
                    "[tool.setuptools.packages.find]\nwhere = ['.']\n",
                )
                .file("pkg/__init__.py", "marker = 0\n")
                .file("pkg/pkg/__init__.py", "")
                .file(
                    "pkg/pkg/mod.py",
                    "class Item:\n    pass\n\ndef get():\n    return Item()\n",
                )
                .file(
                    "r.py",
                    "from pkg.mod import get\n\ndef R():\n    return get().missing\n",
                )
                .build();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let root = named_root(&base, &project, "r.py", "R");
            let _query = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(base.analyzer());
            let mut state = TypeFlowQueryState::default();
            let _warm = solve(&base, &mut state, &root);
            state.summary_state = None;
            state.summary_partitions = Default::default();
            let product = solve(&base, &mut state, &root);
            assert_eq!(product.unattributed_reads, 0);
            assert_eq!(state.work().cache_hits, 0);
            assert_eq!(state.work().root_memo_hits, 0);
            assert!(
                !product
                    .reads
                    .iter()
                    .any(|key| names_path(key, "pkg/__init__.py")),
                "the marker must be outside the captured paths: {:?}",
                product.reads
            );
            project
                .file("pkg/__init__.py")
                .write(
                    "import os\n__path__.append(os.path.join(os.path.dirname(__file__), 'pkg'))\n",
                )
                .expect("package search path mutation");
            let (verdict, differences) =
                targeted_verdict("T15", &project, &base, &product, "r.py", "R");
            assert!(
                !differences.is_empty(),
                "package path authority must change the fresh product"
            );
            assert!(
                verdict != ReadVerdict::Unchanged,
                "package path authority accepted: {differences:?}"
            );
        }

        #[test]
        fn read_set_mutation_runtime_summary_transitive_callee() {
            let project = InlineTestProject::with_language(Language::Python).with_git()
                .file("c.py", "class Item:\n    pass\n\nclass Other:\n    pass\n")
                .file("leaf.py", "from c import Other\n\ndef leaf(value):\n    return value\n")
                .file("f.py", "from leaf import leaf\n\ndef f(value):\n    return leaf(value)\n")
                .file("r.py", "from c import Item\nfrom f import f\n\ndef A():\n    return f(Item()).missing\n\ndef B():\n    return f(Item()).missing\n").build();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let _query = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(base.analyzer());
            let mut state = TypeFlowQueryState::default();
            let a = named_root(&base, &project, "r.py", "A");
            let b = named_root(&base, &project, "r.py", "B");
            let a = solve(&base, &mut state, &a);
            assert!(
                a.work.published_summaries > 0,
                "A must publish runtime class-set summaries"
            );
            let product = solve(&base, &mut state, &b);
            eprintln!("T9 B_work={:?}", product.work);
            assert!(
                product.work.summary_cache_hits > product.work.root_summary_cache_hits,
                "B must use runtime summaries"
            );
            for path in ["f.py", "leaf.py"] {
                let artifact = product.reads.iter().any(|key| matches!(key,
                    brokk_bifrost_analysis::analyzer::ReadKey::Artifact { rel_path: Some(recorded), .. }
                    if recorded.as_ref() == path));
                eprintln!("T9 artifact({path})={artifact}");
                assert!(
                    artifact,
                    "runtime summary closure must record {path} artifact"
                );
            }
            project
                .file("leaf.py")
                .write("from c import Other\n\ndef leaf(value):\n    return Other()\n")
                .expect("transitive summary callee mutation");
            let (verdict, differences) =
                targeted_verdict("T9", &project, &base, &product, "r.py", "B");
            assert!(!differences.is_empty());
            assert!(
                verdict != ReadVerdict::Unchanged,
                "summary closure edit accepted: {differences:?}"
            );
        }

        #[test]
        fn read_set_mutation_same_query_refinement_hits() {
            let project = field_fixture();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let _query = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(base.analyzer());
            let root = named_root(&base, &project, "r.py", "R");
            let mut state = TypeFlowQueryState::default();
            let cold = solve(&base, &mut state, &root);
            let product = solve(&base, &mut state, &root);
            assert_eq!(observations(&cold), observations(&product));
            assert!(
                state.work().cache_hits == 0 && state.work().root_memo_hits == 0,
                "must solve again through shared ProcedureRefinements, not product memo"
            );
            mutate_external_field(&project);
            let (verdict, differences) =
                targeted_verdict("T10", &project, &base, &product, "r.py", "R");
            assert!(!differences.is_empty());
            assert!(
                verdict != ReadVerdict::Unchanged,
                "refinement-hit field edit accepted: {differences:?}"
            );
        }

        #[test]
        fn read_set_mutation_warm_subclass_reparenting() {
            let project = InlineTestProject::with_language(Language::Python).with_git()
                .file("base.py", "class Item:\n    pass\n\nclass Other:\n    pass\n\nclass A:\n    def method(self):\n        return Item()\n\nclass A2:\n    pass\n")
                .file("b.py", "from base import A, A2, Other\n\nclass B(A2):\n    def method(self):\n        return Other()\n")
                .file("r.py", "from base import A\n\ndef R(value: A):\n    return value.method().missing\n").build();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let _query = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(base.analyzer());
            let root = named_root(&base, &project, "r.py", "R");
            let mut state = TypeFlowQueryState::default();
            let _cold = solve(&base, &mut state, &root);
            let before = state.value_flow_cache.stats();
            let product = solve(&base, &mut state, &root);
            eprintln!(
                "T12 warm_stats={:?}",
                state.value_flow_cache.stats().saturating_sub(before)
            );
            assert!(
                state
                    .value_flow_cache
                    .stats()
                    .saturating_sub(before)
                    .dispatch_hits
                    > 0
            );
            eprintln!(
                "T12 names_b={}",
                product.reads.iter().any(|key| names_path(key, "b.py"))
            );
            project.file("b.py").write("from base import A, A2, Other\n\nclass B(A):\n    def method(self):\n        return Other()\n").expect("reparent existing override, preserving definition names");
            let (verdict, differences) =
                targeted_verdict("T12", &project, &base, &product, "r.py", "R");
            assert!(
                !differences.is_empty(),
                "reparenting must change dispatch's product"
            );
            assert!(
                verdict != ReadVerdict::Unchanged,
                "warm reparenting accepted: {differences:?}"
            );
        }

        #[test]
        fn read_set_mutation_add_override() {
            check(
                "add_override",
                "children.py",
                &CHILDREN.replace(
                    "class Child(Item):\n    pass",
                    "class Child(Item):\n    def ping(self):\n        return Other()",
                ),
            );
        }
        #[test]
        fn read_set_mutation_field_write() {
            check(
                "field_write",
                "classes.py",
                &CLASSES.replace("alias.value = Item()", "alias.value = Other()"),
            );
        }
        #[test]
        fn read_set_mutation_new_subclass() {
            check(
                "new_subclass",
                "children.py",
                &format!(
                    "{CHILDREN}\nclass NewChild(Item):\n    def ping(self):\n        return Other()\n"
                ),
            );
        }
        #[test]
        fn read_set_mutation_unrelated() {
            check(
                "unrelated",
                "unrelated.py",
                "def unrelated():\n    return 2\n",
            );
        }
        #[test]
        fn read_set_mutation_callee_same_behavior() {
            check(
                "callee_same_behavior",
                "callee.py",
                &CALLEE.replace("return Item()", "value = Item()\n    return value"),
            );
        }
        #[test]
        fn read_set_mutation_callee_return_class() {
            check(
                "callee_return_class",
                "callee.py",
                &CALLEE.replace("return Item()", "return Other()"),
            );
        }
    }

    mod cached_read_replay {
        use super::super::{
            CachedTypeFlowAnalysis, ClassSetRootResultLookup, FindingFreeClassSetRootResult,
            TypeFlowRootProduct, root_result_persistence_key,
        };
        use super::*;
        use crate::structural::search::semantic::SemanticQueryContext;
        use brokk_bifrost_analysis::analyzer::invalidation::{
            DerivedArtifactId, DerivedArtifactKind,
        };
        use brokk_bifrost_analysis::analyzer::read_ledger::read_set_digest;
        use brokk_bifrost_analysis::analyzer::{
            AnalyzerQueryScope, ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers,
            ReadKey, ReadVerdict, verify_read_set_for_artifact,
        };
        use brokk_bifrost_test_macros::hardwon;
        use std::sync::Arc;

        #[test]
        #[hardwon("#2445: a warm missing-source memo omitted its negative path input")]
        fn cached_missing_source_records_its_absent_path() {
            let project = InlineTestProject::with_language(Language::Python)
                .file("present.py", "class Present: pass\n")
                .build();
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let analyzer = workspace.analyzer();
            let missing = brokk_bifrost_analysis::analyzer::ProjectFile::new(
                analyzer.project().root(),
                "missing.py",
            );
            let _query = AnalyzerQueryScope::new(analyzer);
            assert!(analyzer.indexed_source(&missing).is_none());
            let (_, reads) =
                brokk_bifrost_analysis::analyzer::capture_query_reads(analyzer, || {
                    assert!(analyzer.indexed_source(&missing).is_none());
                });
            assert!(
                reads.keys().iter().any(|key| matches!(key,
                    ReadKey::PathAbsent { language: Language::Python, rel_path }
                        if rel_path.as_ref() == "missing.py"
                )),
                "warm source absence must retain its input: {:?}",
                reads.keys()
            );
        }

        fn root(
            workspace: &WorkspaceAnalyzer,
            project: &BuiltInlineTestProject,
            name: &str,
        ) -> super::super::SemanticProcedureValue {
            let mut context = SemanticQueryContext::new(workspace, None, Default::default());
            let reference = context
                .procedure_references(&project.file("roots.py"))
                .into_iter()
                .find(|reference| {
                    reference
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .is_some_and(|segment| segment.name() == Some(name))
                })
                .expect("named root");
            context
                .resolve_procedure_reference(&reference)
                .expect("root resolves")
        }

        fn solve(
            workspace: &WorkspaceAnalyzer,
            state: &mut TypeFlowQueryState,
            root: &super::super::SemanticProcedureValue,
        ) -> Arc<TypeFlowRootProduct> {
            state.release_file_window();
            let result = state.solve_live(
                workspace,
                root,
                &mut SemanticBudget::default(),
                CodeQueryValueFlowLimits::default(),
                &CancellationToken::default(),
                workspace.analyzer().active_semantic_model_snapshot(),
            );
            let Some(CachedTypeFlowAnalysis::Owned(result)) = result else {
                panic!("owned root: {:?}", state.take_diagnostics());
            };
            result.product
        }

        #[test]
        #[hardwon("#2445: later roots lost warm snapshot, binding and guard-refinement inputs")]
        fn shared_snapshots_bindings_and_refinements_replay_changed_callee_inputs() {
            for (callee, edited) in [
                (
                    "from classes import Item, Other\n\ndef make():\n    return Item()\n",
                    "from classes import Item, Other\n\ndef make():\n    return Other()\n",
                ),
                (
                    "from classes import Item, Other\n\ndef make():\n    value = Item()\n    if isinstance(value, Item):\n        return value\n    return Other()\n",
                    "from classes import Item, Other\n\ndef make():\n    value = Other()\n    if isinstance(value, Item):\n        return value\n    return Other()\n",
                ),
            ] {
                let project = InlineTestProject::with_language(Language::Python).with_git()
                .file("classes.py", "class Item:\n    pass\n\nclass Other:\n    pass\n")
                .file("callee.py", callee)
                .file("roots.py", "from callee import make\n\ndef first():\n    return make().missing\n\ndef second():\n    return make().missing\n")
                .build();
                let base = project.workspace_analyzer(AnalyzerConfig::default());
                let _query = AnalyzerQueryScope::new(base.analyzer());
                let mut state = TypeFlowQueryState::default();
                let a = root(&base, &project, "first");
                let b = root(&base, &project, "second");
                let first = solve(&base, &mut state, &a);
                // Force discovery while retaining value-flow and refinement entries.
                state.summary_state = None;
                state.summary_partitions = Default::default();
                let before = state.value_flow_cache.stats();
                let second = solve(&base, &mut state, &b);
                let hits = state.value_flow_cache.stats().saturating_sub(before);
                assert!(
                    hits.snapshot_hits > 0 && hits.binding_hits > 0,
                    "must consume shared derivations: {hits:?}"
                );
                let callee_inputs: Vec<_> = first.reads.iter().filter(|key| matches!(key,
                ReadKey::Artifact { rel_path: Some(path), .. } if path.as_ref() == "callee.py"
            )).collect();
                assert!(
                    !callee_inputs.is_empty(),
                    "root A must read the shared callee artifact"
                );
                assert!(
                    callee_inputs.iter().all(|key| second.reads.contains(key)),
                    "root B must inherit shared inputs"
                );
                project
                    .file("callee.py")
                    .write(edited)
                    .expect("edit shared input");
                let head = project.workspace_analyzer(AnalyzerConfig::default());
                let changed = ChangedFacts::between(&base, &head);
                assert!(changed.is_complete());
                let verdict = verify_read_set_for_artifact(
                    DerivedArtifactId::new(
                        DerivedArtifactKind::PolicyEvaluationUnit,
                        read_set_digest(&second.reads).digest(),
                    ),
                    &head,
                    &changed,
                    &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
                    &second.reads,
                    LookupReplayLimits::default(),
                    &NoSummaryAnswers,
                    &mut LookupMemo::new(),
                );
                assert_ne!(
                    verdict,
                    ReadVerdict::Unchanged,
                    "edited shared input must reject B"
                );
                let fresh = solve(
                    &head,
                    &mut TypeFlowQueryState::default(),
                    &root(&head, &project, "second"),
                );
                assert_ne!(
                    format!("{:?}", second.class_sets),
                    format!("{:?}", fresh.class_sets),
                    "fresh solve must change its semantic answer"
                );
            }
        }

        #[test]
        fn runtime_summary_replays_the_publishing_roots_inputs() {
            let project = InlineTestProject::with_language(Language::Python).with_git()
                .file("classes.py", "class Item:\n    pass\n\nclass Other:\n    pass\n")
                .file("leaf.py", "from classes import Other\n\ndef leaf(value):\n    return value\n")
                .file("helper.py", "from leaf import leaf\n\ndef relay(value):\n    return leaf(value)\n")
                .file("warm.py", "from classes import Item\nfrom helper import relay\n\ndef first():\n    return relay(Item()).missing\n")
                .file("roots.py", "from classes import Item\nfrom helper import relay\n\ndef second():\n    return relay(Item()).missing\n")
                .build();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let _query = AnalyzerQueryScope::new(base.analyzer());
            let mut context = SemanticQueryContext::new(&base, None, Default::default());
            let reference = context
                .procedure_references(&project.file("warm.py"))
                .into_iter()
                .find(|reference| {
                    reference
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .is_some_and(|segment| segment.name() == Some("first"))
                })
                .expect("publishing root");
            let a = context
                .resolve_procedure_reference(&reference)
                .expect("publishing root resolves");
            let b = root(&base, &project, "second");
            let mut state = TypeFlowQueryState::default();
            let first = solve(&base, &mut state, &a);
            assert!(
                first.work.published_summaries > 0,
                "A must publish runtime rows: {:?}",
                first.work
            );
            let second = solve(&base, &mut state, &b);
            assert!(
                second.work.summary_cache_hits > second.work.root_summary_cache_hits,
                "B must reuse runtime callee rows: {:?}",
                second.work
            );
            assert!(second.reads.iter().any(|key| matches!(key, ReadKey::Artifact { rel_path: Some(path), .. } if path.as_ref() == "warm.py")), "B must inherit A's own artifact as part of the publication superset: {:?}", second.reads);
            let leaf_input = first.reads.iter().find(|key| matches!(key, ReadKey::Artifact { rel_path: Some(path), .. } if path.as_ref() == "leaf.py")).expect("A reads the transitive leaf artifact");
            assert!(
                second.reads.contains(leaf_input),
                "B must inherit the summary's input"
            );
            project
                .file("leaf.py")
                .write("from classes import Other\n\ndef leaf(value):\n    return Other()\n")
                .expect("summary input edit");
            let head = project.workspace_analyzer(AnalyzerConfig::default());
            let verdict = verify_read_set_for_artifact(
                DerivedArtifactId::new(
                    DerivedArtifactKind::PolicyEvaluationUnit,
                    read_set_digest(&second.reads).digest(),
                ),
                &head,
                &ChangedFacts::between(&base, &head),
                &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
                &second.reads,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            );
            assert_ne!(
                verdict,
                ReadVerdict::Unchanged,
                "an edited summary input must reject B"
            );
            let fresh = solve(
                &head,
                &mut TypeFlowQueryState::default(),
                &root(&head, &project, "second"),
            );
            assert_ne!(
                format!("{:?}", second.class_sets),
                format!("{:?}", fresh.class_sets),
                "a fresh solve must observe the edited summary input"
            );
        }

        #[test]
        #[hardwon(
            "#2445: query root cache hits must replay inputs or refuse receipt-free projections"
        )]
        fn query_root_cache_replays_owned_products_and_refuses_unattributed_projections() {
            let project = InlineTestProject::with_language(Language::Python)
                .with_git()
                .file(
                    "roots.py",
                    "class Item:\n    pass\n\ndef first():\n    return Item().missing\n",
                )
                .build();
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let procedure = root(&workspace, &project, "first");
            let mut state = TypeFlowQueryState::default();
            let read = |state: &mut TypeFlowQueryState| {
                state.solve_live(
                    &workspace,
                    &procedure,
                    &mut SemanticBudget::default(),
                    CodeQueryValueFlowLimits::default(),
                    &CancellationToken::default(),
                    workspace.analyzer().active_semantic_model_snapshot(),
                )
            };
            let (first, fill) = capture_query_reads(workspace.analyzer(), || read(&mut state));
            let (second, hit) = capture_query_reads(workspace.analyzer(), || read(&mut state));
            let (
                Some(CachedTypeFlowAnalysis::Owned(first)),
                Some(CachedTypeFlowAnalysis::Owned(second)),
            ) = (first, second)
            else {
                panic!("the fixture must produce owned root products");
            };
            assert!(Arc::ptr_eq(&first.product, &second.product));
            assert_eq!(state.work().cache_hits, 1);
            let keys = hit.keys();
            assert!(!fill.keys().is_empty());
            assert!(fill.keys().iter().all(|key| keys.contains(key)));
            let key = state
                .cache
                .keys()
                .next()
                .expect("the root was memoized")
                .clone();
            state.cache.insert(
                key,
                CachedTypeFlowAnalysis::FindingFreeRows(Arc::from(
                    first.product.projected_rows.clone(),
                )),
            );
            let (projection, projection_reads) = capture_query_reads(workspace.analyzer(), || {
                state.solve(
                    &workspace,
                    &procedure,
                    &mut SemanticBudget::default(),
                    CodeQueryValueFlowLimits::default(),
                    &CancellationToken::default(),
                    workspace.analyzer().active_semantic_model_snapshot(),
                )
            });
            assert!(matches!(
                projection,
                Some(CachedTypeFlowAnalysis::FindingFreeRows(_))
            ));
            assert_eq!(state.work().cache_hits, 2);
            assert!(projection_reads.unattributed_reads() > 0);
        }

        #[test]
        #[hardwon("#2445: the first SQLite projection hit published a receipt-free product")]
        fn first_persisted_projection_hit_refuses_publication_under_a_fresh_capture() {
            let project = InlineTestProject::with_language(Language::Python)
                .with_git()
                .file("roots.py", "def first():\n    return 1\n")
                .build();
            let workspace = WorkspaceAnalyzer::build_persisted(
                project.project_dyn(),
                AnalyzerConfig::default(),
            )
            .unwrap();
            let procedure = root(&workspace, &project, "first");
            let cancellation = CancellationToken::default();
            let limits = CodeQueryValueFlowLimits::default();
            let models = workspace.analyzer().active_semantic_model_snapshot();
            let mut seed_state = TypeFlowQueryState::default();
            seed_state.select_summary_partition(&workspace);
            let (inputs, _) = seed_state.capture_root_inputs(
                &workspace,
                &procedure,
                &mut SemanticBudget::default(),
                &cancellation,
                models.clone(),
            );
            let (adapter, behavior, fields) = inputs.unwrap();
            let key = root_result_persistence_key(
                &workspace,
                adapter,
                behavior,
                &fields,
                &procedure.handle,
                models.as_deref(),
                limits,
                seed_state.allotment,
            )
            .unwrap();
            let attachment = workspace
                .semantic_artifact_store_attachment(procedure.handle.artifact().key())
                .unwrap()
                .unwrap();
            let persisted =
                FindingFreeClassSetRootResult::try_new(key.clone(), attachment, vec![]).unwrap();
            let store = workspace.store().unwrap();
            assert!(!store.is_ephemeral());
            assert!(
                store
                    .publish_finding_free_class_set_root_result(persisted, &cancellation)
                    .unwrap()
            );
            assert!(matches!(
                store
                    .finding_free_class_set_root_result(
                        &key,
                        limits.max_retained_relations,
                        limits.max_retained_bytes,
                        &cancellation
                    )
                    .unwrap(),
                ClassSetRootResultLookup::Hit(_)
            ));
            drop(seed_state);
            let mut hydrated = TypeFlowQueryState::default();
            assert!(hydrated.cache.is_empty());
            let (projection, reads) = capture_query_reads(workspace.analyzer(), || {
                hydrated.solve(
                    &workspace,
                    &procedure,
                    &mut SemanticBudget::default(),
                    limits,
                    &cancellation,
                    models,
                )
            });
            assert!(matches!(
                projection,
                Some(CachedTypeFlowAnalysis::FindingFreeRows(_))
            ));
            assert_eq!(hydrated.work().root_result_persistence_hits, 1);
            assert_eq!(hydrated.work().cache_hits, 0);
            assert_eq!(hydrated.work().solves, 0);
            assert!(reads.unattributed_reads() > 0);
            assert!(
                !reads.is_bounded(),
                "the hydrated legacy product must not license publication"
            );
        }

        #[test]
        fn subsumed_acquisition_preserves_unattributed_reads() {
            let project = InlineTestProject::with_language(Language::Python)
                .file("roots.py", "def first():\n    return 1\n")
                .build();
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let procedure = root(&workspace, &project, "first");
            let artifact_key = ReadKey::semantic_artifact(procedure.handle.artifact().key());
            let (_, reads) =
                brokk_bifrost_analysis::analyzer::capture_query_reads(workspace.analyzer(), || {
                    workspace.analyzer().record_read(artifact_key.clone());
                    let (_, unattributed) =
                        brokk_bifrost_analysis::analyzer::capture_subsumed_query_reads(
                            workspace.analyzer(),
                            || {
                                workspace.analyzer().record_read(ReadKey::Epoch(
                                    super::super::StableDigest::sha256(b"subsumed build"),
                                ));
                                workspace.analyzer().record_unattributed_read();
                                workspace.analyzer().record_unattributed_read();
                            },
                        );
                    assert_eq!(unattributed, 2);
                });
            assert_eq!(reads.keys(), vec![artifact_key]);
            assert_eq!(reads.unattributed_reads(), 2);
        }

        #[test]
        #[hardwon("#2445: a warm witness projection omitted its coordinate source dependency")]
        fn cached_witness_projection_replays_its_source_input() {
            let project = InlineTestProject::with_language(Language::Rust)
                .with_git()
                .file("lib.rs", "pub fn root() {}\n")
                .build();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let finding = absent_finding(
                &project,
                &base,
                "projection",
                Err(SummaryWitnessError::RetentionDisabled),
            );
            let mut state = TypeFlowQueryState::default();
            let traversal = crate::WitnessTraversal::default();
            let limits = CodeQueryValueFlowLimits::default();
            let (first, reads_a) =
                brokk_bifrost_analysis::analyzer::capture_query_reads(base.analyzer(), || {
                    state.absent_member_witnesses(&base, &finding, &traversal, limits)
                });
            let (second, reads_b) =
                brokk_bifrost_analysis::analyzer::capture_query_reads(base.analyzer(), || {
                    state.absent_member_witnesses(&base, &finding, &traversal, limits)
                });
            assert_eq!(first[0].public, second[0].public);
            assert_eq!(
                state.work().witnesses,
                1,
                "second consumer must hit the projection cache"
            );
            let keys = reads_b.keys();
            assert!(keys.iter().any(|key| matches!(key, ReadKey::File { rel_path, .. } if rel_path.as_ref() == "lib.rs")), "projection must name its actual source: {keys:?}");
            assert!(reads_a.keys().iter().all(|key| keys.contains(key)));
            project
                .file("lib.rs")
                .write("\npub fn root() {}\n")
                .expect("source coordinate edit");
            let head = project.workspace_analyzer(AnalyzerConfig::default());
            let verdict = verify_read_set_for_artifact(
                DerivedArtifactId::new(
                    DerivedArtifactKind::PolicyEvaluationUnit,
                    read_set_digest(&keys).digest(),
                ),
                &head,
                &ChangedFacts::between(&base, &head),
                &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
                &keys,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            );
            assert_ne!(verdict, ReadVerdict::Unchanged);
            let fresh_finding = absent_finding(
                &project,
                &head,
                "projection",
                Err(SummaryWitnessError::RetentionDisabled),
            );
            let fresh = TypeFlowQueryState::default().absent_member_witnesses(
                &head,
                &fresh_finding,
                &traversal,
                limits,
            );
            assert_ne!(
                second[0].public.range, fresh[0].public.range,
                "fresh projection must observe changed coordinates"
            );
        }
    }

    #[test]
    fn type_flow_root_memo_products_are_independent_of_root_order() {
        use super::super::semantic::SemanticQueryContext;
        use super::{CachedTypeFlowAnalysis, TypeFlowRootMemo, TypeFlowRootProduct};
        use std::sync::Arc;

        // Several entry roots share normalize and its precise constructor input,
        // exercising both summary and refinement history without a budget boundary.
        let project = InlineTestProject::with_language(Language::Python)
            .with_git()
            .file("app.py", "class Item:\n    pass\n\ndef normalize(x):\n    return x.missing\n\ndef first():\n    return normalize(Item())\n\ndef second():\n    return normalize(Item())\n\ndef third():\n    return first()\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        assert!(workspace.analyzer().workspace_content_identity().is_some());
        let mut context = SemanticQueryContext::new(&workspace, None, Default::default());
        let references = context.procedure_references(&project.file("app.py"));
        let mut roots = references
            .iter()
            .map(|reference| {
                context
                    .resolve_procedure_reference(reference)
                    .expect("fixture procedure")
            })
            .collect::<Vec<_>>();
        roots.sort_by_key(|root| root.handle.semantics().locator().clone());
        assert!(
            roots.len() >= 4,
            "fixture must exercise several roots: {roots:?}"
        );
        let cancellation = CancellationToken::default();
        let snapshot = workspace.analyzer().active_semantic_model_snapshot();
        let solve = |state: &mut TypeFlowQueryState, root: &super::SemanticProcedureValue| {
            state.release_file_window();
            let mut budget = SemanticBudget::default();
            let (result, captured) =
                brokk_bifrost_analysis::analyzer::capture_query_reads(workspace.analyzer(), || {
                    state.solve_live(
                        &workspace,
                        root,
                        &mut budget,
                        CodeQueryValueFlowLimits::default(),
                        &cancellation,
                        snapshot.clone(),
                    )
                });
            let Some(CachedTypeFlowAnalysis::Owned(result)) = result else {
                panic!(
                    "fixture root must produce owned evidence: {:?}",
                    state.take_diagnostics()
                );
            };
            let keys = captured.keys();
            assert!(!result.product.reads.is_empty());
            assert!(
                result.product.reads.iter().all(|key| keys.contains(key)),
                "each fresh capture, including a later memo hit, must inherit the fill keys: {keys:?}"
            );
            result.product
        };
        // Compare semantic observations, excluding work and captured dependency reads.
        let observations = |product: &TypeFlowRootProduct| {
            format!(
                "{:?}",
                (
                    &product.root,
                    &product.failure,
                    &product.projected_rows,
                    &product.class_sets,
                    &product.findings,
                    product.complete,
                    product.semantic_budget_exhausted,
                    &product.incomplete_evidence,
                    product.persistence_status,
                )
            )
        };
        let fresh = roots
            .iter()
            .map(|root| {
                let mut state = TypeFlowQueryState::default();
                state.set_root_memo(Some(TypeFlowRootMemo::default()));
                observations(&solve(&mut state, root))
            })
            .collect::<Vec<_>>();
        for order in [
            (0..roots.len()).collect::<Vec<_>>(),
            (0..roots.len()).rev().collect::<Vec<_>>(),
        ] {
            let memo = TypeFlowRootMemo::default();
            let mut state = TypeFlowQueryState::default();
            state.set_root_memo(Some(memo.clone()));
            let mut products = vec![None; roots.len()];
            for index in order {
                let (product, reads) =
                    capture_query_reads(workspace.analyzer(), || solve(&mut state, &roots[index]));
                assert!(product.reads.iter().all(|key| reads.keys().contains(key)));
                assert!(!product.reads.is_empty(), "the producer must name inputs");
                assert_eq!(
                    observations(&product),
                    fresh[index],
                    "producer root index={index}"
                );
                products[index] = Some(product);
            }
            assert_eq!(state.work.root_memo_hits, 0);
            assert_eq!(state.work.solves, roots.len() as u64);
            for (index, root) in roots.iter().enumerate() {
                let mut consumer = TypeFlowQueryState::default();
                consumer.set_root_memo(Some(memo.clone()));
                let (replay, replay_reads) =
                    capture_query_reads(workspace.analyzer(), || solve(&mut consumer, root));
                let produced = products[index].as_ref().unwrap();
                assert!(
                    produced
                        .reads
                        .iter()
                        .all(|key| replay_reads.keys().contains(key)),
                    "a later capture must inherit the fill's keys: {:?}",
                    replay_reads.keys()
                );
                assert!(replay_reads.unattributed_reads() >= produced.unattributed_reads);
                assert!(
                    Arc::ptr_eq(&replay, produced),
                    "consumer must read the memo product"
                );
                assert_eq!(
                    observations(&replay),
                    fresh[index],
                    "memo root index={index}"
                );
                assert_eq!(consumer.work.solves, 0);
                assert_eq!(consumer.work.root_memo_hits, 1);
                assert_eq!(consumer.work.root_memo_solver_work, produced.solver_work);
                assert_eq!(
                    consumer.work.root_memo_semantic_work,
                    produced.semantic_work
                );
                assert_eq!(
                    consumer.work.incomplete_roots,
                    u64::from(!produced.complete)
                );
            }
        }
    }

    #[test]
    fn absent_member_owned_witness_matches_consumer_capped_projection() {
        use super::super::witness_projection::{
            ProjectedSummaryWitness, public_absent_member_witness,
        };
        let (project, workspace, root) = witness_workspace();
        for retention in [
            WitnessRetentionLimits::new(8).expect("strict retention"),
            WitnessRetentionLimits::best_effort(1, 1, 64 * 1024 * 1024).expect("marker retention"),
        ] {
            let raw = solve_witness(&workspace, &root, retention, 4096).expect("fixture witness");
            let full = absent_finding(&project, &workspace, "projection-equality", Ok(raw.clone()));
            for steps in [0, 1, 2, usize::MAX] {
                for bytes in [0, 1, 512, 4096, usize::MAX] {
                    let mut old = full.clone();
                    old.roots[0].witness =
                        Ok(ProjectedSummaryWitness::new(&workspace, &raw, steps, bytes));
                    let mut old_cache = Default::default();
                    let mut new_cache = Default::default();
                    let old_row = public_absent_member_witness(
                        &workspace,
                        &old,
                        &old.roots[0],
                        0,
                        steps,
                        bytes,
                        &mut old_cache,
                    );
                    let new_row = public_absent_member_witness(
                        &workspace,
                        &full,
                        &full.roots[0],
                        0,
                        steps,
                        bytes,
                        &mut new_cache,
                    );
                    assert_eq!(
                        old_row, new_row,
                        "consumer limits steps={steps} bytes={bytes}"
                    );
                }
            }
        }
    }

    #[test]
    fn owned_root_product_residency_ends_with_its_cache_window() {
        use super::{
            CachedTypeFlowAnalysis, QueryRootProduct, RootIncompleteEvidence, TypeFlowCacheKey,
            TypeFlowRootPersistenceStatus, TypeFlowRootProduct,
        };
        use crate::analyzer::semantic::{IcfgProvider, SemanticProcedureReference, StableDigest};
        use brokk_bifrost_analysis::analyzer::store::cache_budget::RetainedBytes;
        use std::sync::Arc;
        let (project, workspace, root) = witness_workspace();
        let witness = solve_witness(
            &workspace,
            &root,
            WitnessRetentionLimits::new(8).unwrap(),
            4096,
        )
        .unwrap();
        assert!(!witness.steps().is_empty());
        let product = Arc::new(TypeFlowRootProduct {
            root: SemanticProcedureReference::of(&root),
            failure: None,
            projected_rows: Vec::new(),
            class_sets: Vec::new(),
            findings: vec![absent_finding(
                &project,
                &workspace,
                "owned-root",
                Ok(witness),
            )],
            complete: true,
            semantic_budget_exhausted: false,
            incomplete_evidence: RootIncompleteEvidence::default(),
            persistence_status: TypeFlowRootPersistenceStatus::Eligible,
            work: Default::default(),
            solver_work: Default::default(),
            semantic_work: Default::default(),
            reads: Vec::new(),
            unattributed_reads: 0,
            execution_dependences: 0,
        });
        let census = product.census();
        assert_eq!(census.owned_text_bytes, product.retained_bytes());
        assert!(census.nested_entries > 0);
        let mut refused_limits = SemanticWork::default_limits();
        refused_limits.owned_text_bytes = census.owned_text_bytes - 1;
        let mut refused = SemanticBudget::new(refused_limits).unwrap();
        assert!(refused.admit(census).is_err());
        assert!(
            product.complete,
            "consumer refusal does not weaken a product"
        );
        let mut budget = SemanticBudget::default();
        let owner = Arc::new(());
        let before = budget.replay_snapshot();
        budget.admit(census).unwrap();
        assert_eq!(budget.bind_replay_holder(&owner, &before), census);
        let key = TypeFlowCacheKey {
            root: product.root.clone(),
            provider_behavior: workspace.icfg_provider().behavior_identity(),
            field_slots: StableDigest::from_array([0; 32]),
        };
        let mut state = TypeFlowQueryState::default();
        state.cache.insert(
            key,
            CachedTypeFlowAnalysis::Owned(QueryRootProduct {
                product: Arc::clone(&product),
                _owner: owner,
            }),
        );
        assert_eq!(budget.resident().owned_text_bytes, census.owned_text_bytes);
        state.release_file_window();
        assert!(
            product.complete,
            "another consumer may still own the output"
        );
        assert_eq!(budget.resident().owned_text_bytes, 0);
        assert_eq!(budget.resident().nested_entries, 0);
    }

    #[test]
    fn root_result_semantics_rotates_with_solver_projection_and_semantic_limits() {
        assert_eq!(
            ROOT_RESULT_ALGORITHM_ID, b"type-flow-root-algorithm-v17",
            "a root cached as finding-free before the conditional absent-member tier may now carry a conditional finding"
        );
        let adapter = type_flow_adapter(Language::Python).expect("Python supports type flow");
        let limits = CodeQueryValueFlowLimits::default();
        let semantic = CodeQueryRootAllotment::from_execution_limits(
            &super::super::CodeQueryExecutionLimits::default(),
        );
        let baseline = root_result_semantics_digest(adapter, limits, semantic);

        let mut solver = semantic;
        solver.solver.interned_facts -= 1;
        assert_ne!(
            root_result_semantics_digest(adapter, limits, solver),
            baseline
        );

        let mut projection = limits;
        projection.max_retained_relations -= 1;
        assert_ne!(
            root_result_semantics_digest(adapter, projection, semantic),
            baseline
        );

        let mut semantic = semantic;
        semantic.semantic.source_mappings -= 1;
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
        let finding = absent_finding(&project, &workspace, "finding-unavailable", unavailable);

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
            row.evidence.proof,
            crate::structural::search::CodeQuerySemanticProof::Unproven
        );
        assert_eq!(
            row.evidence.completeness,
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
        let finding = absent_finding(&project, &workspace, "finding-marker", Ok(marker));

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
            row.evidence.completeness,
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
            let finding =
                absent_finding(&project, &workspace, "finding-zero", Ok(retained.clone()));
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
        let finding = absent_finding(&project, &workspace, "finding-cached", Ok(retained.clone()));
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
        let request_finding = absent_finding(
            &project,
            &workspace,
            "finding-request",
            Ok(retained.clone()),
        );
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

        let mut distinct_roots = absent_finding(
            &project,
            &workspace,
            "finding-distinct-roots",
            Ok(retained.clone()),
        );
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

        let probe = absent_finding(&project, &workspace, "finding-probe", Ok(retained.clone()));
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
        let first = absent_finding(&project, &workspace, "finding-one", Ok(retained.clone()));
        let second = absent_finding(&project, &workspace, "finding-two", Ok(retained.clone()));
        let third = absent_finding(&project, &workspace, "finding-three", Ok(retained));
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

    #[test]
    fn root_allotment_preserves_defaults_larger_queries_and_overflow() {
        let mut limits = super::super::CodeQueryExecutionLimits::default();
        limits.value_flow.solver_work = SolverWork::uniform(1);
        limits.value_flow.solver_work.interned_facts = usize::MAX;
        limits.semantic.max_rows_per_dimension = 2_000_001;
        limits.semantic.max_retained_bytes = usize::MAX;
        let solver = limits.value_flow.solver_work;
        let semantic = super::super::semantic::semantic_budget_limits(limits.semantic);
        let allotment = CodeQueryRootAllotment::from_execution_limits(&limits);
        for dimension in SolverBudgetDimension::ALL {
            assert!(allotment.solver.get(dimension) >= SolverWork::default_limits().get(dimension));
            assert!(allotment.solver.get(dimension) >= solver.get(dimension));
        }
        for dimension in SemanticBudgetDimension::ALL {
            assert!(
                allotment.semantic.get(dimension) >= SemanticWork::default_limits().get(dimension)
            );
            assert!(allotment.semantic.get(dimension) >= semantic.get(dimension));
        }
        assert_eq!(allotment.solver.interned_facts, usize::MAX);
        assert_eq!(allotment.semantic.source_mappings, 2_097_152);
    }
}
