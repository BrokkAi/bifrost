//! Pipeline execution for the `call_effects` and `procedure_effects` steps
//! (issue #2437, slice 2).
//!
//! Both steps consume the analyzer's existing answers and add no new call-graph
//! walker of their own:
//!
//! - the callee set of a call site is
//!   [`crate::structural::search::semantic::SemanticQueryContext::dispatch_at_source`],
//!   the exact answer the `dispatch_outcome` and `dispatch_target` rows
//!   publish, so an effect row's proof is copied rather than re-derived. The
//!   site's candidate coverage is copied too, with the one reinterpretation
//!   [`site_coverage`] states and justifies: the oracle spells "this callee has
//!   no workspace definition" and "I found a residual I could not name" with
//!   the same `Open`, and only the second is a missing callee;
//! - the call sites of a procedure are the facts arena's own call nodes inside
//!   the declaration's range, the same nodes `call_shape` derives from, so an
//!   effect row's `site_id` is literally a `call_shape` row id; and
//! - the effect declarations are the activated semantic-model set the analyzer
//!   already publishes ([`IAnalyzer::active_semantic_models`]), selected by the
//!   canonical `(language, owner, member, receiver, arity)` identity issue
//!   #1978 introduced for data-flow summaries.
//!
//! The algebra over those inputs — certainty meets, timing joins, coverage
//! degradation, the bounded fixpoint — lives in
//! [`crate::analyzer::usages::effects`] and is unit-tested without a workspace.

use super::*;

use crate::analyzer::semantic::{
    ArgumentDomain, CallArgumentExpansion, CallInvocationMode, CallSiteHandle,
    CallableReferenceKind, CallableTarget, CallableTargetResolution, CallerReceiverBinding,
    CaptureMode, CaptureSource, ContentIdentity, GuardPredicate, MemoryAccessKind,
    MemoryLocationKind, SemanticCapability, SemanticEffect, SemanticGapDischarge,
    SemanticGapImpact, SemanticGapSubject, SemanticLocator, SemanticValueKind, ValueFlowKind,
    ValueUseKind,
};
use crate::analyzer::semantic::{LengthDelimitedDigest, UnmaterializedExternalTarget};
use crate::analyzer::semantic_model::{
    CompiledConditionalIndirectWrite, CompiledConditionalResultRefinement,
    CompiledIndirectWriteTarget, CompiledNormalReturnRefinement, CompiledOperationPrecondition,
    CompiledPredicateProofEffect, CompiledResultContract, CompiledResultMemberContract,
    CompiledResultPredicate, CompiledSummaryInput, Completeness, ResolvedActiveSemanticModels,
    SemanticModelCallableKey, SemanticModelMatchDisposition, SemanticModelOverlay,
};
use crate::analyzer::usages::CallRelationLimits;
use crate::analyzer::usages::call_shape::{call_shape_for_call, call_shapes_in_file};
use crate::analyzer::usages::effects::{
    ArmLookup, BoundDeclaredEffect, CallEffectArm, CallEffectReport, CallEffectSiteStatus,
    EffectCertainty, EffectCoverage, EffectGraph, EffectGraphEdge, EffectGraphProcedure,
    EffectNodeBasis, EffectProof, EffectReason, ModeledCallApplication, ModeledCallTargetCoverage,
    ModeledCallTargetLookup, ModeledProcedureKey, ModeledProcedureName, ProcedureEffectBudget,
    ProcedureEffectReport, call_effect_report, modeled_call_targets_for_shapes,
    modeled_procedure_key_for_unit, summarize_procedure_effects,
};
use crate::structural::NormalizedKind;
use crate::structural::flow_state::{FlowStateIncompleteReason, GuardDominanceAnswer};
use brokk_bifrost_core::analyzer::model::CallableArity;
use brokk_bifrost_core::analyzer::structural::callable::{
    ArgumentListKind, CallKind, CallShapeCoverage,
};
use brokk_bifrost_core::analyzer::structural::flow_state::{
    FlowCertainty, FlowRelation, FlowStateAxis, StateEventClass,
};

/// How many call nodes one procedure body contributes to the reachable call
/// graph before the walk reports itself truncated.
const MAX_CALL_SITES_PER_PROCEDURE: usize = 512;

/// Wrapper composition is recursive only across this deliberately tiny,
/// request-local bound. This makes stack depth independent of repository call
/// graph depth while still covering ordinary package facade chains.
const MAX_CONDITIONAL_WRAPPER_DEPTH: usize = 8;

/// Domain separator for the graph identity of an external member the workspace
/// holds no declaration for. It is separate from `render::declaration_id`, so a
/// summarized external leaf can never collide with a workspace declaration row.
const EXTERNAL_EFFECT_PROCEDURE_ID_DOMAIN: &[u8] =
    b"bifrost.code_query.external_effect_procedure.v1";

/// One derived call-effect report, shared by every row of the site.
#[derive(Debug, Clone)]
pub(super) struct CallEffectValue {
    pub(super) report: Arc<CallEffectReport>,
    /// The workspace declaration behind each dispatch arm, keyed by the arm's
    /// target identity, so rendering never re-resolves a callee.
    pub(super) callees: Arc<BTreeMap<String, DeclarationValue>>,
    pub(super) index: usize,
}

const CALL_RESULT_CONTRACT_ID_DOMAIN: &[u8] = b"bifrost.code_query.call_result_contract.v1";
const RESULT_CONTRACT_USE_ID_DOMAIN: &[u8] = b"bifrost.code_query.result_contract_use.v1";
const RESULT_CONTRACT_FAILURE_USE_ID_DOMAIN: &[u8] =
    b"bifrost.code_query.result_contract_failure_use.v1";
const NILNESS_OPERATION_ID_DOMAIN: &[u8] = b"bifrost.code_query.nilness_operation.v1";
const SWITCH_COVERAGE_ID_DOMAIN: &[u8] = b"bifrost.code_query.switch_coverage.v1";
const DETACHED_TASK_TRANSFER_ID_DOMAIN: &[u8] = b"bifrost.code_query.detached_task_transfer.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ResultContractUseKind {
    Dereference,
    Field,
    Index,
    ReceiverCall,
    CallArgument,
}

impl ResultContractUseKind {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Dereference => "dereference",
            Self::Field => "field",
            Self::Index => "index",
            Self::ReceiverCall => "receiver_call",
            Self::CallArgument => "call_argument",
        }
    }
}

/// One structured operation whose pointer-like subject has a procedure-local
/// scalar nilness fact.
#[derive(Debug, Clone)]
pub(super) struct NilnessOperationValue {
    pub(super) file: ProjectFile,
    pub(super) range: Range,
    pub(super) ast_id: Option<String>,
    pub(super) id: String,
    pub(super) procedure_id: String,
    pub(super) operation_point_id: String,
    pub(super) subject_value_id: u64,
    pub(super) use_kind: ResultContractUseKind,
    pub(super) fact: brokk_bifrost_flow::scalar_state::ScalarFact,
    pub(super) origin: &'static str,
    pub(super) proof: &'static str,
    pub(super) coverage: EffectCoverage,
    pub(super) reason: Option<&'static str>,
}

impl NilnessOperationValue {
    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }
}

#[derive(Debug, Clone)]
pub(super) struct SwitchCoverageValue {
    pub(super) file: ProjectFile,
    pub(super) range: Range,
    pub(super) ast_id: Option<String>,
    pub(super) id: String,
    pub(super) procedure_id: String,
    pub(super) switch_fact_id: u32,
    pub(super) kind: &'static str,
    pub(super) selector_value_id: Option<u64>,
    pub(super) selector_domain: &'static str,
    pub(super) case_count: usize,
    pub(super) has_true_case: bool,
    pub(super) has_false_case: bool,
    pub(super) default_present: bool,
    pub(super) verdict: &'static str,
    pub(super) proof: &'static str,
    pub(super) reason: Option<&'static str>,
}

impl SwitchCoverageValue {
    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }
}

#[derive(Debug, Clone)]
pub(super) struct DetachedTaskTransferValue {
    pub(super) file: ProjectFile,
    pub(super) range: Range,
    pub(super) ast_id: Option<String>,
    pub(super) id: String,
    pub(super) procedure_id: String,
    pub(super) call_id: String,
    pub(super) call_point_id: String,
    pub(super) role: &'static str,
    pub(super) ordinal: Option<u32>,
    pub(super) value_id: String,
    pub(super) object_id: Option<String>,
    pub(super) object_cardinality: Option<&'static str>,
    pub(super) timing: &'static str,
    pub(super) proof: &'static str,
    pub(super) coverage: &'static str,
    pub(super) reason: Option<&'static str>,
}

impl DetachedTaskTransferValue {
    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ResultContractUseTiming {
    Direct,
    Deferred,
    Captured,
}

impl ResultContractUseTiming {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Deferred => "deferred",
            Self::Captured => "captured",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum OperationApplicability {
    Required,
    NotRequired,
    Unknown,
}

impl OperationApplicability {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::NotRequired => "not_required",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ResultUseGuardVerdict {
    Guarded,
    Unguarded,
    NotApplicable,
    Unknown,
}

impl ResultUseGuardVerdict {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Guarded => "guarded",
            Self::Unguarded => "unguarded",
            Self::NotApplicable => "not_applicable",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundResultContract {
    contract: CompiledResultContract,
    fresh_allocation: bool,
    pack_id: Option<String>,
    model_id: Option<String>,
    summary_id: Option<String>,
}

fn retain_common_result_contracts(
    common: &mut Vec<BoundResultContract>,
    contracts: &[BoundResultContract],
) {
    common.retain_mut(|candidate| {
        let Some(contract) = contracts
            .iter()
            .find(|contract| contract.contract == candidate.contract)
        else {
            return false;
        };
        candidate.fresh_allocation &= contract.fresh_allocation;
        if candidate.pack_id != contract.pack_id
            || candidate.model_id != contract.model_id
            || candidate.summary_id != contract.summary_id
        {
            candidate.pack_id = None;
            candidate.model_id = None;
            candidate.summary_id = None;
        }
        true
    });
}

/// One positive reviewed result contract, or the mandatory terminal row for a
/// call shape where no universally applicable contract was established.
#[derive(Debug, Clone)]
pub(super) struct CallResultContractValue {
    pub(super) file: ProjectFile,
    pub(super) range: Range,
    pub(super) id: String,
    pub(super) site_id: String,
    pub(super) site_ast_id: String,
    pub(super) target_id: Option<String>,
    /// Canonical modeled identity retained only when dispatch selected one
    /// exact arm. This is internal proof input; `callee_symbol` is display
    /// text and must never be reparsed to recover it.
    modeled_target: Option<ModeledProcedureKey>,
    pub(super) callee: Option<DeclarationValue>,
    pub(super) callee_symbol: Option<String>,
    pub(super) result_ordinal: Option<u32>,
    pub(super) condition_result_ordinal: Option<u32>,
    pub(super) predicate: Option<CompiledResultPredicate>,
    pub(super) result_success_predicate: Option<CompiledResultPredicate>,
    pub(super) proof: Option<EffectProof>,
    pub(super) coverage: EffectCoverage,
    pub(super) reason: Option<EffectReason>,
    pub(super) pack_id: Option<String>,
    pub(super) model_id: Option<String>,
    pub(super) summary_id: Option<String>,
    pub(super) arm_count: usize,
    pub(super) modeled_arm_count: usize,
    pub(super) terminal: bool,
    /// Exact when use-validation coverage is exhaustive; otherwise this is a
    /// lower bound over structured observations retained in the snapshot.
    pub(super) result_use_count: Option<usize>,
    /// Exact when use-validation coverage is exhaustive; otherwise this is a
    /// lower bound over observed uses proved unguarded in the retained CFG.
    pub(super) unguarded_result_use_count: Option<usize>,
    pub(super) use_validation: Option<&'static str>,
    pub(super) use_validation_coverage: Option<EffectCoverage>,
    /// Coverage of the exact success-guard relation. `None` is reserved for
    /// terminal rows, which carry no result contract.
    pub(super) success_guard_coverage: Option<EffectCoverage>,
    /// Exact normalized guards used by result-use validation.
    pub(super) success_guard_edges: Vec<crate::analyzer::semantic::ControlEdgeLocator>,
    /// Structured positive guard candidates retained when identity proof
    /// withholds an exact edge. Under exhaustive coverage these include the
    /// exact guards; under open coverage they are positioned partial evidence.
    pub(super) possible_success_guard_edges: Vec<crate::analyzer::semantic::ControlEdgeLocator>,
    pub(super) fresh_allocation: bool,
    pub(super) member_contracts: Vec<CompiledResultMemberContract>,
}

impl CallResultContractValue {
    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }
}

fn projected_result_contract(value: &CallResultContractValue) -> Option<CompiledResultContract> {
    let Some(result_ordinal) = value.result_ordinal else {
        debug_assert!(
            value.terminal
                && value.condition_result_ordinal.is_none()
                && value.predicate.is_none()
                && value.result_success_predicate.is_none(),
            "only terminal rows omit a result contract"
        );
        return None;
    };
    debug_assert!(
        !value.terminal,
        "positive result contracts are not terminal"
    );
    debug_assert_eq!(
        value.condition_result_ordinal.is_some(),
        value.predicate.is_some(),
        "result condition ordinal and predicate are present together"
    );
    debug_assert!(
        value.condition_result_ordinal.is_some() || value.result_success_predicate.is_some(),
        "direct result contracts carry a result-success predicate"
    );
    Some(CompiledResultContract {
        result_ordinal,
        condition_result_ordinal: value.condition_result_ordinal,
        predicate: value.predicate,
        result_success_predicate: value.result_success_predicate,
        member_contracts: value.member_contracts.clone(),
    })
}

/// One exact structured use of a protected call result.
///
/// The row is anchored at the operation, while the acquisition IDs retain the
/// reviewed result contract that made the use relevant. An unknown operation
/// applicability is deliberately a row with open coverage, never an inferred
/// receiver dereference.
#[derive(Debug, Clone)]
pub(super) struct ResultContractUseValue {
    pub(super) file: ProjectFile,
    pub(super) range: Range,
    pub(super) ast_id: Option<String>,
    pub(super) id: String,
    pub(super) acquisition_id: String,
    pub(super) acquisition_site_id: String,
    pub(super) acquisition_site_ast_id: String,
    pub(super) operation_point_id: String,
    operation_point: crate::analyzer::semantic::ProgramPointId,
    subject_value: crate::analyzer::semantic::ValueId,
    pub(super) operation_site_id: Option<String>,
    pub(super) operation_site_ast_id: Option<String>,
    pub(super) result_ordinal: u32,
    pub(super) condition_result_ordinal: Option<u32>,
    pub(super) acquisition_predicate: Option<CompiledResultPredicate>,
    pub(super) result_success_predicate: Option<CompiledResultPredicate>,
    pub(super) required_predicate: Option<CompiledResultPredicate>,
    pub(super) use_kind: ResultContractUseKind,
    pub(super) timing: ResultContractUseTiming,
    pub(super) applicability: OperationApplicability,
    pub(super) guard: ResultUseGuardVerdict,
    pub(super) coverage: EffectCoverage,
    pub(super) member: Option<String>,
    pub(super) parameter_count: Option<u32>,
    pub(super) parameter_ordinal: Option<u32>,
    pub(super) pack_id: Option<String>,
    pub(super) model_id: Option<String>,
    pub(super) summary_id: Option<String>,
}

impl ResultContractUseValue {
    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }
}

#[derive(Debug, Clone)]
pub(super) struct ResultContractFailureUseValue {
    pub(super) file: ProjectFile,
    pub(super) range: Range,
    pub(super) ast_id: Option<String>,
    pub(super) id: String,
    pub(super) acquisition_id: String,
    pub(super) acquisition_site_id: String,
    pub(super) acquisition_site_ast_id: String,
    pub(super) procedure_id: String,
    pub(super) condition_result_ordinal: u32,
    /// Present only when semantic materialization identified the exact
    /// condition-result value. An open row retains positioned consumer
    /// evidence even when that identity is unavailable.
    pub(super) condition_value_id: Option<u64>,
    /// Present only when guard derivation proved the exact failure edge. Open
    /// rows deliberately omit it instead of inventing an edge identity.
    pub(super) failure_edge_id: Option<String>,
    pub(super) consumer_point_id: String,
    pub(super) consumer_call_id: Option<String>,
    pub(super) consumer_site_id: Option<String>,
    pub(super) consumer_site_ast_id: Option<String>,
    pub(super) operand_value_id: u64,
    pub(super) binding_value_id: Option<u64>,
    pub(super) establishment_point_id: Option<String>,
    pub(super) establishment_value_id: Option<u64>,
    pub(super) provenance: crate::query::FailureUseProvenance,
    pub(super) consumer: crate::query::FailureUseConsumer,
    pub(super) argument_ordinal: Option<u32>,
    pub(super) proof: EffectProof,
    pub(super) coverage: EffectCoverage,
    pub(super) pack_id: Option<String>,
    pub(super) model_id: Option<String>,
    pub(super) summary_id: Option<String>,
}

impl ResultContractFailureUseValue {
    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }
}

impl CallEffectValue {
    pub(super) fn row(&self) -> &crate::analyzer::usages::effects::CallEffectRow {
        &self.report.rows[self.index]
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.report.file
    }

    pub(super) fn callee_declaration(&self) -> Option<&DeclarationValue> {
        self.callees.get(self.row().target_id.as_deref()?)
    }
}

/// One derived procedure-effect report, shared by every row of the procedure.
#[derive(Debug, Clone)]
pub(super) struct ProcedureEffectSubject {
    pub(super) declaration: DeclarationValue,
    pub(super) report: Arc<ProcedureEffectReport>,
}

/// One row of one procedure's effect summary.
#[derive(Debug, Clone)]
pub(super) struct ProcedureEffectValue {
    pub(super) subject: ProcedureEffectSubject,
    pub(super) index: usize,
}

impl ProcedureEffectValue {
    pub(super) fn row(&self) -> &crate::analyzer::usages::effects::ProcedureEffectRow {
        &self.subject.report.rows[self.index]
    }

    pub(super) fn file(&self) -> &ProjectFile {
        self.subject.declaration.unit.source()
    }
}

/// What the activated pack set says about one canonical procedure identity.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ModelAnswer {
    /// One unique activated summary names the identity. `complete` is that
    /// summary's own completeness claim, `covers_overrides` is the author's
    /// explicit claim that every implementation outside the workspace conforms
    /// to it (#2371), and `effects` is its declared list, which is empty for a
    /// summary that declares no effect.
    ///
    /// The three are kept apart because only their conjunction proves an
    /// absence: an empty list on a *complete* summary is the reviewed claim
    /// "this procedure performs no declared effect", while the same empty list
    /// on a partial summary says nothing at all.
    Modeled {
        complete: bool,
        covers_overrides: bool,
        effects: Vec<BoundDeclaredEffect>,
        result_contracts: Vec<BoundResultContract>,
        normal_return_refinements: Vec<CompiledNormalReturnRefinement>,
        conditional_result_refinements: Vec<CompiledConditionalResultRefinement>,
        conditional_indirect_writes: Vec<CompiledConditionalIndirectWrite>,
        preconditions: Option<Vec<CompiledOperationPrecondition>>,
    },
    Conflict,
    Empty,
}

/// Per-query state shared by every effect row a single query derives.
#[derive(Default)]
pub(super) struct EffectTraversalCache {
    models: Option<Option<Arc<ResolvedActiveSemanticModels>>>,
    keys: HashMap<CodeUnit, Option<ModeledProcedureKey>>,
    answers: HashMap<ModeledProcedureKey, ModelAnswer>,
    dispatch_answers: HashMap<(ProjectFile, Range), Arc<super::dispatch::DispatchSiteAnswer>>,
    result_contract_names: Option<ResultContractNameInventory>,
    reports: HashMap<String, Arc<ProcedureEffectReport>>,
    facts: HashMap<ProjectFile, Option<Arc<FileFacts>>>,
    result_member_call_shapes: Option<ResultMemberCallShapeWindow>,
    result_use_indexes: Option<ResultUseIndexWindow>,
    result_assignment_conversion_proofs:
        std::cell::RefCell<HashMap<ResultAssignmentConversionProofKey, bool>>,
    exact_sources: HashMap<ProjectFile, Option<Arc<str>>>,
    exact_source_identities: std::cell::RefCell<HashMap<ProjectFile, Option<ContentIdentity>>>,
    modeled_call_targets: Option<ModeledCallTargetWindow>,
    conditional_wrapper_answers: HashMap<CodeUnit, ConditionalProcedureSummaryAnswer>,
    conditional_wrapper_visiting: HashSet<CodeUnit>,
    result_contract_incomplete_diagnostics: HashSet<(ProjectFile, &'static str)>,
    /// Whether any derived row so far was not exhaustive, so the query's own
    /// completion can record the incompleteness once.
    pub(super) incomplete: bool,
    /// Whether a bound rather than a missing fact caused the incompleteness.
    pub(super) truncated: bool,
}

struct ModeledCallTargetWindow {
    file: ProjectFile,
    lookups: HashMap<String, ModeledCallTargetLookup>,
}

type ResultMemberCallShapesByRange =
    HashMap<Range, Option<crate::analyzer::usages::call_shape::CallShapeReport>>;

struct ResultMemberCallShapeWindow {
    file: ProjectFile,
    shapes: Option<Arc<ResultMemberCallShapesByRange>>,
}

struct ResultUseIndexWindow {
    file: ProjectFile,
    artifact: std::sync::Weak<crate::analyzer::semantic::SemanticArtifact>,
    indexes: HashMap<(crate::analyzer::semantic::ProcedureId, u64), Option<Arc<ResultUseIndex>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedIntrinsicUse {
    point: crate::analyzer::semantic::ProgramPointId,
    point_id: Box<str>,
    range: Range,
    source_exact: bool,
    /// Exact selector-identity uncertainty: an unresolved field location or a
    /// load that may instead denote a method value. One positive declaration
    /// proof for this same selector closes both lowering symptoms.
    classification_open: bool,
    kind: ResultContractUseKind,
    /// Grammar-backed selector member locator. Intrinsic classification uses
    /// its exact anchor; index and dereference operations carry no member.
    member: Option<SemanticLocator>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedCallArgumentUse {
    call: crate::analyzer::semantic::CallSiteId,
    /// Ordinal in the written argument list. This is not a formal-parameter
    /// ordinal until exact call-application evidence proves whether a receiver
    /// is bound separately from the written arguments.
    argument_ordinal: u32,
    /// Whole-call fallback. A public call-argument row uses the ordinal-joined
    /// structural argument range whenever that shape exists; a semantic value
    /// range is identity evidence only and never becomes the operation anchor.
    range: Range,
    semantic_range: Option<Range>,
    range_exact: bool,
    expansion_exact: bool,
}

#[derive(Default)]
struct ResultUseIndex {
    assignment_conversions:
        HashMap<crate::analyzer::semantic::ValueId, Vec<crate::analyzer::semantic::ValueId>>,
    assignment_conversion_sources_by_converted_value:
        HashMap<crate::analyzer::semantic::ValueId, Vec<crate::analyzer::semantic::ValueId>>,
    assignment_conversion_points_by_converted_value:
        HashMap<crate::analyzer::semantic::ValueId, Vec<crate::analyzer::semantic::ProgramPointId>>,
    assignment_value_flow_gap_at_procedure: bool,
    assignment_value_flow_gap_points: HashSet<crate::analyzer::semantic::ProgramPointId>,
    value_flow_gap_points_by_value: HashMap<
        crate::analyzer::semantic::ValueId,
        HashSet<crate::analyzer::semantic::ProgramPointId>,
    >,
    assigned_bindings_by_converted_value:
        HashMap<crate::analyzer::semantic::ValueId, Vec<crate::analyzer::semantic::ValueId>>,
    converted_values_by_binding:
        HashMap<crate::analyzer::semantic::ValueId, Vec<crate::analyzer::semantic::ValueId>>,
    establishment_events_by_value: HashMap<crate::analyzer::semantic::ValueId, Vec<usize>>,
    deferred_capture_sources:
        HashMap<crate::analyzer::semantic::ValueId, Option<crate::analyzer::semantic::ValueId>>,
    deferred_call_ids_by_source:
        HashMap<crate::analyzer::semantic::ValueId, Vec<crate::analyzer::semantic::CallSiteId>>,
    intrinsic_uses: HashMap<crate::analyzer::semantic::ValueId, Vec<IndexedIntrinsicUse>>,
    receiver_call_ids_by_value:
        HashMap<crate::analyzer::semantic::ValueId, Vec<crate::analyzer::semantic::CallSiteId>>,
    call_argument_uses_by_value:
        HashMap<crate::analyzer::semantic::ValueId, Vec<IndexedCallArgumentUse>>,
}

impl ResultUseIndex {
    fn exact_assignment_conversion_bindings(
        &self,
        source_value: crate::analyzer::semantic::ValueId,
        converted_values: &[crate::analyzer::semantic::ValueId],
    ) -> Option<
        Vec<(
            crate::analyzer::semantic::ValueId,
            crate::analyzer::semantic::ValueId,
        )>,
    > {
        converted_values
            .iter()
            .map(|converted| {
                let [source] = self
                    .assignment_conversion_sources_by_converted_value
                    .get(converted)?
                    .as_slice()
                else {
                    return None;
                };
                let [binding] = self
                    .assigned_bindings_by_converted_value
                    .get(converted)?
                    .as_slice()
                else {
                    return None;
                };
                (*source == source_value).then_some((*converted, *binding))
            })
            .collect()
    }

    fn has_relevant_assignment_value_flow_gap(
        &self,
        flow_values: &HashSet<crate::analyzer::semantic::ValueId>,
        boundary_bindings: &HashSet<crate::analyzer::semantic::ValueId>,
        boundary_points: &HashSet<crate::analyzer::semantic::ProgramPointId>,
    ) -> bool {
        self.assignment_value_flow_gap_at_procedure
            || flow_values
                .iter()
                .any(|value| self.value_flow_gap_points_by_value.contains_key(value))
            || boundary_bindings.iter().any(|binding| {
                self.value_flow_gap_points_by_value
                    .get(binding)
                    .is_some_and(|points| !points.is_disjoint(boundary_points))
            })
            || boundary_points
                .iter()
                .any(|point| self.assignment_value_flow_gap_points.contains(point))
    }

    fn converted_establishments_from(
        &self,
        source: crate::analyzer::semantic::ValueId,
    ) -> Vec<usize> {
        let mut events = self
            .assignment_conversions
            .get(&source)
            .into_iter()
            .flatten()
            .flat_map(|converted| {
                self.establishment_events_by_value
                    .get(converted)
                    .into_iter()
                    .flatten()
                    .copied()
            })
            .collect::<Vec<_>>();
        events.sort_unstable();
        events.dedup();
        events
    }

    fn exact_converted_establishments_from(
        &self,
        semantic: &mut SemanticQueryContext<'_>,
        procedure: &crate::analyzer::semantic::ProcedureHandle,
        derivation: &crate::structural::flow_state::FlowStateDerivation,
        source_value: crate::analyzer::semantic::ValueId,
        result_ordinal: u32,
        proof: Option<ResultAssignmentConversionProofContext<'_>>,
    ) -> ExactResultAssignmentConversion {
        // A Go assignment conversion is not an identity edge in general: a
        // nil pointer stored in an interface becomes a non-nil interface.
        // Promote its binding establishment only when the exact modeled
        // result type and the binding's explicit source type are identical.
        // The decision is all-or-none for this raw result. One extra source,
        // destination, missing establishment, or failed type proof keeps all
        // converted roots candidate-only so a partial lowering shape cannot
        // manufacture exact identity.
        let Some(converted_values) = self.assignment_conversions.get(&source_value) else {
            return ExactResultAssignmentConversion::default();
        };
        let Some(proof) = proof else {
            return ExactResultAssignmentConversion::open();
        };
        let identity_operation = "Go result assignment source identity";
        let cached_source_identity = proof.source_identities.borrow().get(proof.file).copied();
        let source_identity = match cached_source_identity {
            Some(identity) => {
                if !semantic.charge_consumer_traversal(proof.file, 0, identity_operation) {
                    return ExactResultAssignmentConversion::open();
                }
                identity
            }
            None => {
                let identity = if semantic.charge_consumer_traversal(
                    proof.file,
                    proof.source.len(),
                    identity_operation,
                ) {
                    let identity = ContentIdentity::hash_bytes(proof.source.as_bytes());
                    semantic
                        .charge_consumer_traversal(proof.file, 0, identity_operation)
                        .then_some(identity)
                } else {
                    None
                };
                proof
                    .source_identities
                    .borrow_mut()
                    .insert(proof.file.clone(), identity);
                identity
            }
        };
        let Some(source_identity) = source_identity else {
            return ExactResultAssignmentConversion::open();
        };
        if source_identity != procedure.artifact().key().revision().content() {
            return ExactResultAssignmentConversion::open();
        }
        let semantics = procedure.semantics();
        let target = SemanticModelCallableKey::new(
            &proof.modeled_target.language,
            &proof.modeled_target.owner,
            &proof.modeled_target.member,
            proof.modeled_target.has_receiver,
            proof.modeled_target.parameter_count,
        );
        let Some(converted_bindings) =
            self.exact_assignment_conversion_bindings(source_value, converted_values)
        else {
            return ExactResultAssignmentConversion::open();
        };
        if converted_bindings.iter().any(|(converted, binding)| {
            self.establishment_events_by_value
                .get(converted)
                .is_none_or(|events| {
                    events.is_empty()
                        || events.iter().any(|event| {
                            !matches!(
                                &derivation.event(*event).subject,
                                crate::structural::flow_state::FlowSubject::Binding { value }
                                    if value == binding
                            )
                        })
                })
        }) {
            return ExactResultAssignmentConversion::open();
        }
        let flow_values = std::iter::once(source_value)
            .chain(converted_bindings.iter().map(|(converted, _)| *converted))
            .collect::<HashSet<_>>();
        let boundary_bindings = converted_bindings
            .iter()
            .map(|(_, binding)| *binding)
            .collect::<HashSet<_>>();
        let boundary_points = converted_bindings
            .iter()
            .flat_map(|(converted, _)| {
                self.assignment_conversion_points_by_converted_value
                    .get(converted)
                    .into_iter()
                    .flatten()
                    .copied()
                    .chain(
                        self.establishment_events_by_value
                            .get(converted)
                            .into_iter()
                            .flatten()
                            .map(|event| derivation.event(*event).point),
                    )
            })
            .collect::<HashSet<_>>();
        if self.has_relevant_assignment_value_flow_gap(
            &flow_values,
            &boundary_bindings,
            &boundary_points,
        ) {
            return ExactResultAssignmentConversion::open();
        }
        let mut establishments = Vec::new();
        for (converted, binding) in converted_bindings {
            let Some(mapping) = semantics
                .value(binding)
                .and_then(|value| semantics.source_mapping(value.source))
                .filter(|mapping| {
                    mapping.kind == crate::analyzer::semantic::SourceMappingKind::Exact
                })
            else {
                return ExactResultAssignmentConversion::open();
            };
            let span = mapping.locator.anchor().span();
            let binding_declaration = Range {
                start_byte: span.start_byte() as usize,
                end_byte: span.end_byte() as usize,
                start_line: span.start().line() as usize + 1,
                end_line: span.end().line() as usize + 1,
            };
            let proof_key = ResultAssignmentConversionProofKey {
                file: proof.file.clone(),
                modeled_target: proof.modeled_target.clone(),
                result_ordinal,
                binding_declaration,
                source_identity,
            };
            let cached = proof.proofs.borrow().get(&proof_key).copied();
            let exact = if let Some(exact) = cached {
                exact
                    && semantic.charge_consumer_traversal(
                        proof.file,
                        0,
                        "Go result assignment type proof",
                    )
            } else {
                let charged = semantic.charge_consumer_traversal(
                    proof.file,
                    proof.work,
                    "Go result assignment type proof",
                );
                let exact = charged
                    && crate::analyzer::go_modeled_result_binding_type_identity_is_exact(
                        proof.analyzer,
                        proof.overlay,
                        proof.file,
                        proof.source,
                        binding_declaration,
                        target,
                        result_ordinal as usize,
                    )
                    && semantic.charge_consumer_traversal(
                        proof.file,
                        0,
                        "Go result assignment type proof",
                    );
                proof.proofs.borrow_mut().insert(proof_key, exact);
                exact
            };
            if !exact {
                return ExactResultAssignmentConversion::open();
            }
            let events = self
                .establishment_events_by_value
                .get(&converted)
                .expect("all converted values have validated establishment events");
            establishments.extend(events.iter().copied());
        }
        establishments.sort_unstable();
        establishments.dedup();
        ExactResultAssignmentConversion {
            establishments,
            proof_open: false,
        }
    }

    fn converted_establishments_for_bindings(
        &self,
        bindings: &HashSet<crate::analyzer::semantic::ValueId>,
    ) -> Vec<usize> {
        let mut events = bindings
            .iter()
            .flat_map(|binding| {
                self.converted_values_by_binding
                    .get(binding)
                    .into_iter()
                    .flatten()
            })
            .flat_map(|converted| {
                self.establishment_events_by_value
                    .get(converted)
                    .into_iter()
                    .flatten()
                    .copied()
            })
            .collect::<Vec<_>>();
        events.sort_unstable();
        events.dedup();
        events
    }
}

#[derive(Clone, Copy)]
struct ResultAssignmentConversionProofContext<'a> {
    analyzer: &'a dyn IAnalyzer,
    overlay: &'a SemanticModelOverlay,
    file: &'a ProjectFile,
    source: &'a str,
    source_identities: &'a std::cell::RefCell<HashMap<ProjectFile, Option<ContentIdentity>>>,
    modeled_target: &'a ModeledProcedureKey,
    proofs: &'a std::cell::RefCell<HashMap<ResultAssignmentConversionProofKey, bool>>,
    work: usize,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct ResultAssignmentConversionProofKey {
    file: ProjectFile,
    modeled_target: ModeledProcedureKey,
    result_ordinal: u32,
    binding_declaration: Range,
    source_identity: ContentIdentity,
}

#[allow(clippy::too_many_arguments)]
fn result_assignment_conversion_proof_context<'a>(
    analyzer: &'a dyn IAnalyzer,
    file: &'a ProjectFile,
    modeled_target: Option<&'a ModeledProcedureKey>,
    overlay: Option<&'a SemanticModelOverlay>,
    source: Option<&'a str>,
    source_identities: &'a std::cell::RefCell<HashMap<ProjectFile, Option<ContentIdentity>>>,
    proofs: &'a std::cell::RefCell<HashMap<ResultAssignmentConversionProofKey, bool>>,
    work: Option<usize>,
) -> Option<ResultAssignmentConversionProofContext<'a>> {
    modeled_target
        .filter(|target| target.language == "go")
        .zip(overlay)
        .zip(source)
        .zip(work)
        .map(
            |(((modeled_target, overlay), source), work)| ResultAssignmentConversionProofContext {
                analyzer,
                overlay,
                file,
                source,
                source_identities,
                modeled_target,
                proofs,
                work,
            },
        )
}

#[derive(Default)]
struct ExactResultAssignmentConversion {
    establishments: Vec<usize>,
    proof_open: bool,
}

impl ExactResultAssignmentConversion {
    fn open() -> Self {
        Self {
            establishments: Vec::new(),
            proof_open: true,
        }
    }
}

pub(super) fn is_go_assignment_conversion_target(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    target: crate::analyzer::semantic::ValueId,
) -> bool {
    semantics.value(target).is_some_and(|value| {
        matches!(
            &value.kind,
            SemanticValueKind::LanguageDefined(kind)
                if kind.as_ref() == "go.assignment_conversion"
        )
    })
}

fn build_result_use_index(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    derivation: &crate::structural::flow_state::FlowStateDerivation,
) -> ResultUseIndex {
    let semantics = procedure.semantics();
    let mut index = ResultUseIndex::default();
    let mut converted_values = HashSet::default();
    let mut assignments = Vec::new();
    let mut transparent_assignment_sources = HashMap::default();
    let selector_callees = semantics
        .call_sites()
        .iter()
        .filter(|call| call.receiver.is_some())
        .map(|call| call.callee)
        .collect::<HashSet<_>>();
    let mut callable_ambiguous_values = HashSet::default();
    let mut unresolved_field_locations = HashSet::default();
    for gap in semantics.gaps() {
        match (gap.capability, gap.subject) {
            (SemanticCapability::CallableReferences, SemanticGapSubject::Value(value)) => {
                callable_ambiguous_values.insert(value);
            }
            (SemanticCapability::FieldMemory, SemanticGapSubject::MemoryLocation(location)) => {
                unresolved_field_locations.insert(location);
            }
            _ => {}
        }
        if gap.impacts.contains(SemanticGapImpact::ValueFlow) {
            if let SemanticGapSubject::Value(value) = gap.subject {
                index
                    .value_flow_gap_points_by_value
                    .entry(value)
                    .or_default()
                    .insert(gap.point);
            }
            if gap.capability == SemanticCapability::Assignments {
                match gap.subject {
                    SemanticGapSubject::Procedure => {
                        index.assignment_value_flow_gap_at_procedure = true;
                    }
                    SemanticGapSubject::Point => {
                        index.assignment_value_flow_gap_points.insert(gap.point);
                    }
                    SemanticGapSubject::Value(_)
                    | SemanticGapSubject::MemoryLocation(_)
                    | SemanticGapSubject::CallSite(_)
                    | SemanticGapSubject::CallContinuation { .. }
                    | SemanticGapSubject::Capture(_)
                    | SemanticGapSubject::AsyncContinuation { .. } => {}
                }
            }
        }
    }

    for point in semantics.points() {
        // Go lowers a parenthesized expression as one otherwise-empty
        // assignment point from the exact inner value to a temporary whose
        // exact source range strictly contains it. Preserve that structured
        // identity through call application. Address-of uses an `Address`
        // target, while dereferences and type assertions carry additional
        // effects at their point, so neither can satisfy this proof.
        if let [event] = point.events.as_ref()
            && let SemanticEffect::Assignment { target, value } = event.effect
            && semantics
                .value(target)
                .is_some_and(|target| target.kind == SemanticValueKind::Temporary)
        {
            let exact_range = |value| {
                semantics
                    .value(value)
                    .and_then(|value| semantics.source_mapping(value.source))
                    .filter(|mapping| {
                        mapping.kind == crate::analyzer::semantic::SourceMappingKind::Exact
                    })
                    .map(|mapping| {
                        let span = mapping.locator.anchor().span();
                        Range {
                            start_byte: span.start_byte() as usize,
                            end_byte: span.end_byte() as usize,
                            start_line: span.start().line() as usize + 1,
                            end_line: span.end().line() as usize + 1,
                        }
                    })
            };
            if let (Some(target_range), Some(source_range)) =
                (exact_range(target), exact_range(value))
                && target_range != source_range
                && target_range.contains(&source_range)
            {
                assert!(
                    transparent_assignment_sources
                        .insert(target, (value, source_range))
                        .is_none(),
                    "one semantic temporary has one transparent assignment source"
                );
            }
        }
        for event in &point.events {
            match &event.effect {
                SemanticEffect::ValueFlow {
                    kind,
                    source,
                    target,
                } => {
                    let assignment_conversion =
                        is_go_assignment_conversion_target(semantics, *target);
                    if assignment_conversion {
                        index
                            .assignment_conversion_sources_by_converted_value
                            .entry(*target)
                            .or_default()
                            .push(*source);
                        index
                            .assignment_conversion_points_by_converted_value
                            .entry(*target)
                            .or_default()
                            .push(point.id);
                    }
                    if assignment_conversion && *kind == ValueFlowKind::LanguageDefined {
                        converted_values.insert(*target);
                        index
                            .assignment_conversions
                            .entry(*source)
                            .or_default()
                            .push(*target);
                    } else if *kind == ValueFlowKind::LanguageDefined
                        && semantics.value(*target).is_some_and(|value| {
                            matches!(
                                &value.kind,
                                SemanticValueKind::LanguageDefined(kind)
                                    if kind.as_ref() == "go.defer_capture"
                            )
                        })
                    {
                        index
                            .deferred_capture_sources
                            .entry(*target)
                            .and_modify(|existing| {
                                if existing.is_some_and(|existing| existing != *source) {
                                    *existing = None;
                                }
                            })
                            .or_insert(Some(*source));
                    }
                }
                SemanticEffect::Assignment { target, value } => {
                    assignments.push((*target, *value));
                }
                SemanticEffect::MemoryLoad {
                    kind,
                    location,
                    result,
                } => {
                    let (base, use_kind, member) =
                        match (kind, semantics.memory_location(*location)) {
                            (
                                MemoryAccessKind::Field,
                                Some(crate::analyzer::semantic::MemoryLocation {
                                    kind: MemoryLocationKind::Field { base, member },
                                    ..
                                }),
                            ) => (
                                Some(*base),
                                Some(ResultContractUseKind::Field),
                                Some(member.clone()),
                            ),
                            (
                                MemoryAccessKind::Index,
                                Some(crate::analyzer::semantic::MemoryLocation {
                                    kind: MemoryLocationKind::Index { base, .. },
                                    ..
                                }),
                            ) => (Some(*base), Some(ResultContractUseKind::Index), None),
                            _ => (None, None, None),
                        };
                    // A field load that produces a receiver-qualified call's
                    // callee is selector evaluation, not proof that evaluating
                    // the receiver itself dereferences it. Go permits nil
                    // pointer receivers. The operation is classified below
                    // from its exact call shape and reviewed member contract.
                    if !selector_callees.contains(result)
                        && let (Some(base), Some(use_kind)) = (base, use_kind)
                    {
                        let mapping = semantics
                            .source_mapping(event.source)
                            .expect("validated semantic event has a source mapping");
                        let span = mapping.locator.anchor().span();
                        let point_id = super::semantic::program_point_wire_id(
                            &procedure
                                .point_handle(point.id)
                                .expect("validated procedure owns its semantic event point"),
                        );
                        index
                            .intrinsic_uses
                            .entry(base)
                            .or_default()
                            .push(IndexedIntrinsicUse {
                                point: point.id,
                                point_id: point_id.into(),
                                range: Range {
                                    start_byte: span.start_byte() as usize,
                                    end_byte: span.end_byte() as usize,
                                    start_line: span.start().line() as usize + 1,
                                    end_line: span.end().line() as usize + 1,
                                },
                                source_exact: mapping.kind
                                    == crate::analyzer::semantic::SourceMappingKind::Exact,
                                classification_open: callable_ambiguous_values.contains(result)
                                    || (use_kind == ResultContractUseKind::Field
                                        && unresolved_field_locations.contains(location)),
                                kind: use_kind,
                                member,
                            });
                    }
                }
                SemanticEffect::MemoryStore { kind, location, .. } => {
                    let (base, use_kind, member) =
                        match (kind, semantics.memory_location(*location)) {
                            (
                                MemoryAccessKind::Field,
                                Some(crate::analyzer::semantic::MemoryLocation {
                                    kind: MemoryLocationKind::Field { base, member },
                                    ..
                                }),
                            ) => (
                                Some(*base),
                                Some(ResultContractUseKind::Field),
                                Some(member.clone()),
                            ),
                            (
                                MemoryAccessKind::Index,
                                Some(crate::analyzer::semantic::MemoryLocation {
                                    kind: MemoryLocationKind::Index { base, .. },
                                    ..
                                }),
                            ) => (Some(*base), Some(ResultContractUseKind::Index), None),
                            _ => (None, None, None),
                        };
                    if let (Some(base), Some(use_kind)) = (base, use_kind) {
                        let mapping = semantics
                            .source_mapping(event.source)
                            .expect("validated semantic event has a source mapping");
                        let span = mapping.locator.anchor().span();
                        let point_id = super::semantic::program_point_wire_id(
                            &procedure
                                .point_handle(point.id)
                                .expect("validated procedure owns its semantic event point"),
                        );
                        index
                            .intrinsic_uses
                            .entry(base)
                            .or_default()
                            .push(IndexedIntrinsicUse {
                                point: point.id,
                                point_id: point_id.into(),
                                range: Range {
                                    start_byte: span.start_byte() as usize,
                                    end_byte: span.end_byte() as usize,
                                    start_line: span.start().line() as usize + 1,
                                    end_line: span.end().line() as usize + 1,
                                },
                                source_exact: mapping.kind
                                    == crate::analyzer::semantic::SourceMappingKind::Exact,
                                classification_open: use_kind == ResultContractUseKind::Field
                                    && unresolved_field_locations.contains(location),
                                kind: use_kind,
                                member,
                            });
                    }
                }
                SemanticEffect::ValueUse {
                    kind: ValueUseKind::Dereference,
                    value,
                } => {
                    let mapping = semantics
                        .source_mapping(event.source)
                        .expect("validated semantic event has a source mapping");
                    let span = mapping.locator.anchor().span();
                    let point_id = super::semantic::program_point_wire_id(
                        &procedure
                            .point_handle(point.id)
                            .expect("validated procedure owns its semantic event point"),
                    );
                    index
                        .intrinsic_uses
                        .entry(*value)
                        .or_default()
                        .push(IndexedIntrinsicUse {
                            point: point.id,
                            point_id: point_id.into(),
                            range: Range {
                                start_byte: span.start_byte() as usize,
                                end_byte: span.end_byte() as usize,
                                start_line: span.start().line() as usize + 1,
                                end_line: span.end().line() as usize + 1,
                            },
                            source_exact: mapping.kind
                                == crate::analyzer::semantic::SourceMappingKind::Exact,
                            classification_open: false,
                            kind: ResultContractUseKind::Dereference,
                            member: None,
                        });
                }
                _ => {}
            }
        }
    }

    for (target, value) in assignments {
        if converted_values.contains(&value) {
            index
                .assigned_bindings_by_converted_value
                .entry(value)
                .or_default()
                .push(target);
            index
                .converted_values_by_binding
                .entry(target)
                .or_default()
                .push(value);
        }
    }
    for values in index.assignment_conversions.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in index
        .assignment_conversion_sources_by_converted_value
        .values_mut()
    {
        values.sort_unstable();
        values.dedup();
    }
    for points in index
        .assignment_conversion_points_by_converted_value
        .values_mut()
    {
        points.sort_unstable();
        points.dedup();
    }
    for values in index.assigned_bindings_by_converted_value.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in index.converted_values_by_binding.values_mut() {
        values.sort_unstable();
        values.dedup();
    }

    for call in semantics.call_sites() {
        if let Some(receiver) = call.receiver {
            index
                .receiver_call_ids_by_value
                .entry(receiver)
                .or_default()
                .push(call.id);
            if let Some(source) = index
                .deferred_capture_sources
                .get(&receiver)
                .copied()
                .flatten()
            {
                index
                    .deferred_call_ids_by_source
                    .entry(source)
                    .or_default()
                    .push(call.id);
            }
        }
        let fallback_range = semantic_call_range(semantics, call);
        for (argument_ordinal, argument) in call.arguments.iter().enumerate() {
            let argument_ordinal = u32::try_from(argument_ordinal)
                .expect("semantic call argument ordinals fit the portable u32 contract");
            let mapping = semantics
                .value(argument.value)
                .and_then(|value| semantics.source_mapping(value.source));
            let semantic_range = mapping.map(|mapping| {
                let span = mapping.locator.anchor().span();
                Range {
                    start_byte: span.start_byte() as usize,
                    end_byte: span.end_byte() as usize,
                    start_line: span.start().line() as usize + 1,
                    end_line: span.end().line() as usize + 1,
                }
            });
            let Some(range) = fallback_range else {
                continue;
            };
            let indexed = IndexedCallArgumentUse {
                call: call.id,
                argument_ordinal,
                range,
                semantic_range,
                range_exact: mapping.is_some_and(|mapping| {
                    mapping.kind == crate::analyzer::semantic::SourceMappingKind::Exact
                }),
                expansion_exact: matches!(
                    argument.expansion,
                    CallArgumentExpansion::Direct(ArgumentDomain::Positional)
                ),
            };
            index
                .call_argument_uses_by_value
                .entry(argument.value)
                .or_default()
                .push(indexed.clone());

            let mut transparent = argument.value;
            let mut visited = HashSet::default();
            while visited.insert(transparent)
                && let Some((source, source_range)) =
                    transparent_assignment_sources.get(&transparent).copied()
            {
                let mut inner = indexed.clone();
                inner.semantic_range = Some(source_range);
                index
                    .call_argument_uses_by_value
                    .entry(source)
                    .or_default()
                    .push(inner);
                transparent = source;
            }
        }
    }
    for uses in index.intrinsic_uses.values_mut() {
        uses.sort_unstable_by(|left, right| {
            (
                left.point.get(),
                left.range.start_byte,
                left.range.end_byte,
                left.kind.label(),
            )
                .cmp(&(
                    right.point.get(),
                    right.range.start_byte,
                    right.range.end_byte,
                    right.kind.label(),
                ))
        });
        uses.dedup();
    }
    for calls in index.receiver_call_ids_by_value.values_mut() {
        calls.sort_unstable();
        calls.dedup();
    }
    for uses in index.call_argument_uses_by_value.values_mut() {
        uses.sort_unstable_by_key(|use_| {
            (
                use_.call,
                use_.argument_ordinal,
                use_.range.start_byte,
                use_.range.end_byte,
            )
        });
        uses.dedup();
    }
    for calls in index.deferred_call_ids_by_source.values_mut() {
        calls.sort_unstable();
        calls.dedup();
    }
    for event in &derivation.events {
        if event.event_class == StateEventClass::Establish {
            index
                .establishment_events_by_value
                .entry(event.value)
                .or_default()
                .push(event.event);
        }
    }
    index
}

#[derive(Default)]
struct ResultContractNameInventory {
    exact: HashMap<ModeledProcedureName, ResultContractArities>,
    members: HashMap<(String, String, bool), ResultContractArities>,
}

#[derive(Default)]
struct ResultContractArities(Vec<CallableArity>);

impl ResultContractArities {
    fn insert(&mut self, arity: CallableArity) {
        if !self.0.contains(&arity) {
            self.0.push(arity);
        }
    }

    fn accepts(&self, actual_parameter_count: usize) -> bool {
        self.0
            .iter()
            .any(|arity| arity.accepts(actual_parameter_count))
    }
}

impl EffectTraversalCache {
    pub(super) fn with_active_semantic_models(
        models: Option<Arc<ResolvedActiveSemanticModels>>,
    ) -> Self {
        Self {
            models: Some(models),
            ..Self::default()
        }
    }

    fn models(&mut self, analyzer: &dyn IAnalyzer) -> Option<Arc<ResolvedActiveSemanticModels>> {
        self.models
            .get_or_insert_with(|| analyzer.active_semantic_models())
            .clone()
    }

    /// Reuse one typed dispatch answer across effect classifications of the
    /// same exact call. The projected answer owns no semantic handles, so it
    /// remains valid across this query's artifact windows while avoiding a
    /// second oracle traversal and a second retained-work charge.
    fn dispatch_at_source(
        &mut self,
        semantic: &mut SemanticQueryContext<'_>,
        file: &ProjectFile,
        range: Range,
    ) -> Arc<super::dispatch::DispatchSiteAnswer> {
        let key = (file.clone(), range);
        if let Some(answer) = self.dispatch_answers.get(&key) {
            return Arc::clone(answer);
        }
        let answer = Arc::new(semantic.dispatch_at_source(file, range));
        self.dispatch_answers.insert(key, Arc::clone(&answer));
        answer
    }

    /// The canonical identity of one workspace callable, cached per unit.
    ///
    /// `None` means no key could be built, which is a coverage gap and never a
    /// looser match: the owner must be a qualified prefix of the declaration's
    /// own fully-qualified name, the persisted signature contract must publish
    /// exactly one entry, and that entry must decide the receiver shape.
    fn key_for(
        &mut self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
    ) -> Option<ModeledProcedureKey> {
        if let Some(key) = self.keys.get(unit) {
            return key.clone();
        }
        let key = modeled_procedure_key_for_unit(analyzer, unit);
        self.keys.insert(unit.clone(), key.clone());
        key
    }

    fn answer_for(&mut self, analyzer: &dyn IAnalyzer, key: &ModeledProcedureKey) -> ModelAnswer {
        if let Some(answer) = self.answers.get(key) {
            return answer.clone();
        }
        let answer = lookup_declared_effects(self.models(analyzer).as_deref(), key);
        self.answers.insert(key.clone(), answer.clone());
        answer
    }

    fn result_contract_names(&mut self, analyzer: &dyn IAnalyzer) -> &ResultContractNameInventory {
        if self.result_contract_names.is_none() {
            let mut inventory = ResultContractNameInventory::default();
            if let Some(models) = self.models(analyzer) {
                for shard in models.shards() {
                    let Some(summaries) = shard.shard.payload().procedure_summaries() else {
                        continue;
                    };
                    for summary in summaries {
                        if summary.result_contracts.is_empty() {
                            continue;
                        }
                        let Some((owner, member)) =
                            crate::analyzer::semantic::authored_procedure_target_identity(
                                &summary.target.path,
                                &summary.target.symbol,
                            )
                        else {
                            continue;
                        };
                        let language = shard.manifest.language.clone();
                        let name = ModeledProcedureName {
                            language: language.clone(),
                            owner: owner.into_owned(),
                            member: member.to_owned(),
                            has_receiver: summary.target.has_receiver,
                        };
                        let arity = summary.target.callable_arity();
                        inventory.exact.entry(name).or_default().insert(arity);
                        inventory
                            .members
                            .entry((language, member.to_owned(), summary.target.has_receiver))
                            .or_default()
                            .insert(arity);
                    }
                }
            }
            self.result_contract_names = Some(inventory);
        }
        self.result_contract_names
            .as_ref()
            .expect("result-contract name inventory was initialized")
    }

    fn has_result_contract_name(
        &mut self,
        analyzer: &dyn IAnalyzer,
        name: &ModeledProcedureName,
        actual_parameter_count: usize,
        application: ModeledCallApplication,
    ) -> bool {
        let arities = self.result_contract_names(analyzer).exact.get(name);
        application_accepts_result_contract(
            application,
            &name.language,
            name.has_receiver,
            actual_parameter_count,
            |parameter_count| arities.is_some_and(|arities| arities.accepts(parameter_count)),
        )
    }

    fn may_name_result_contract(
        &mut self,
        analyzer: &dyn IAnalyzer,
        shape: &CallShapeValue,
        application: ModeledCallApplication,
    ) -> bool {
        let outcome = &shape.report.outcome;
        let Some(member) = outcome.callee_name.as_deref() else {
            return false;
        };
        let actual_parameter_count = shape.report.arguments.len();
        let language = crate::analyzer::common::language_for_file(&outcome.file)
            .config_label()
            .to_owned();
        let member = member.to_owned();
        let inventory = self.result_contract_names(analyzer);
        [false, true].into_iter().any(|has_receiver| {
            application_accepts_result_contract(
                application,
                &language,
                has_receiver,
                actual_parameter_count,
                |parameter_count| {
                    inventory
                        .members
                        .get(&(language.clone(), member.clone(), has_receiver))
                        .is_some_and(|arities| arities.accepts(parameter_count))
                },
            )
        })
    }

    fn exact_source(&mut self, analyzer: &dyn IAnalyzer, file: &ProjectFile) -> Option<Arc<str>> {
        if !self.exact_sources.contains_key(file) {
            // The identity is meaningful only for the exact bytes retained in
            // this file window. Invalidate it whenever a new source snapshot
            // is fetched, including after an explicit window preparation.
            self.exact_source_identities.get_mut().remove(file);
            self.exact_sources
                .insert(file.clone(), analyzer.indexed_source(file).map(Arc::from));
        }
        self.exact_sources
            .get(file)
            .expect("the exact source cache was initialized")
            .clone()
    }

    /// Derive exact structural call shapes once for the current result-contract
    /// file window. The structural snapshot's complete node-and-role work is
    /// charged before the scan, and an unavailable answer is cached so a
    /// cancelled or exhausted request cannot retry the same work per row.
    fn result_member_call_shapes(
        &mut self,
        semantic: &mut SemanticQueryContext<'_>,
        file: &ProjectFile,
        facts: Option<&FileFacts>,
    ) -> Option<Arc<ResultMemberCallShapesByRange>> {
        let operation = "result-member call-shape indexing";
        if self
            .result_member_call_shapes
            .as_ref()
            .is_some_and(|window| &window.file == file)
        {
            if !semantic.charge_consumer_traversal(file, 0, operation) {
                return None;
            }
            return self
                .result_member_call_shapes
                .as_ref()
                .and_then(|window| window.shapes.clone());
        }

        let shapes = facts.and_then(|facts| {
            if !semantic.charge_consumer_traversal(file, facts.work_item_count(), operation) {
                return None;
            }
            let mut shapes = ResultMemberCallShapesByRange::default();
            // One call site cannot outnumber the snapshot's nodes. This keeps
            // the structural helper explicitly bounded while preserving the
            // complete file inventory paid for above.
            for shape in call_shapes_in_file(facts, file, facts.nodes().len()) {
                shapes
                    .entry(shape.outcome.range)
                    .and_modify(|existing| *existing = None)
                    .or_insert(Some(shape));
            }
            // Cancellation can race with the synchronous structural walk.
            // Recheck it before publishing proof-bearing cached data.
            semantic
                .charge_consumer_traversal(file, 0, operation)
                .then(|| Arc::new(shapes))
        });
        self.result_member_call_shapes = Some(ResultMemberCallShapeWindow {
            file: file.clone(),
            shapes,
        });
        self.result_member_call_shapes
            .as_ref()
            .and_then(|window| window.shapes.clone())
    }

    /// Index the structured value and state rows used by result-contract
    /// consumers once per procedure derivation. An unavailable index is
    /// cached so cancellation or budget exhaustion cannot restart the same
    /// procedure-wide scan for every contract row.
    fn result_use_index(
        &mut self,
        semantic: &mut SemanticQueryContext<'_>,
        file: &ProjectFile,
        procedure: &crate::analyzer::semantic::ProcedureHandle,
        derivation: &crate::structural::flow_state::FlowStateDerivation,
    ) -> Option<Arc<ResultUseIndex>> {
        let operation = "result-use semantic indexing";
        let artifact = Arc::downgrade(procedure.artifact());
        let retains_artifact = self.result_use_indexes.as_ref().is_some_and(|window| {
            &window.file == file && std::sync::Weak::ptr_eq(&window.artifact, &artifact)
        });
        if !retains_artifact {
            self.result_use_indexes = Some(ResultUseIndexWindow {
                file: file.clone(),
                artifact,
                indexes: HashMap::default(),
            });
        }

        let key = (procedure.id(), derivation.generation);
        if self
            .result_use_indexes
            .as_ref()
            .is_some_and(|window| window.indexes.contains_key(&key))
        {
            if !semantic.charge_consumer_traversal(file, 0, operation) {
                return None;
            }
            return self
                .result_use_indexes
                .as_ref()
                .and_then(|window| window.indexes.get(&key))
                .cloned()
                .flatten();
        }

        let semantics = procedure.semantics();
        let available = (|| {
            // The builder scans semantic events once and then joins at most
            // one pending assignment per event. Charge that exact linear
            // upper bound before inspecting event contents.
            for point in semantics.points() {
                let steps = point.events.len().saturating_add(1).saturating_mul(2);
                if !semantic.charge_consumer_traversal(file, steps, operation) {
                    return None;
                }
            }
            let remaining_steps = semantics
                .call_sites()
                .len()
                .saturating_add(
                    semantics
                        .call_sites()
                        .iter()
                        .map(|call| call.arguments.len())
                        .sum::<usize>(),
                )
                .saturating_add(semantics.memory_locations().len())
                .saturating_add(semantics.gaps().len())
                .saturating_add(derivation.events.len());
            if !semantic.charge_consumer_traversal(file, remaining_steps, operation) {
                return None;
            }
            let index = Arc::new(build_result_use_index(procedure, derivation));
            // Cancellation can race with the synchronous structured walk.
            semantic
                .charge_consumer_traversal(file, 0, operation)
                .then_some(index)
        })();
        self.result_use_indexes
            .as_mut()
            .expect("result-use index window was initialized")
            .indexes
            .insert(key, available.clone());
        available
    }

    fn replace_modeled_call_target_window(
        &mut self,
        file: ProjectFile,
        lookups: HashMap<String, ModeledCallTargetLookup>,
    ) {
        self.modeled_call_targets = Some(ModeledCallTargetWindow { file, lookups });
    }

    /// Release the source snapshot retained by one artifact-independent file
    /// window while preserving activated-model and declaration-key caches.
    pub(super) fn release_file_window(&mut self) {
        self.exact_sources.clear();
        self.exact_source_identities.get_mut().clear();
        self.result_assignment_conversion_proofs.get_mut().clear();
        self.result_member_call_shapes = None;
        self.result_use_indexes = None;
        self.modeled_call_targets = None;
    }
}

fn application_accepts_result_contract(
    application: ModeledCallApplication,
    language: &str,
    has_receiver: bool,
    written_parameter_count: usize,
    mut accepts: impl FnMut(usize) -> bool,
) -> bool {
    match application {
        ModeledCallApplication::PackageFunction => {
            !has_receiver && accepts(written_parameter_count)
        }
        ModeledCallApplication::BoundReceiver => has_receiver && accepts(written_parameter_count),
        ModeledCallApplication::ReceiverBindingUnknown => {
            has_receiver
                && (accepts(written_parameter_count)
                    || (language == Language::Go.config_label()
                        && written_parameter_count
                            .checked_sub(1)
                            .is_some_and(&mut accepts)))
        }
        ModeledCallApplication::Unknown => {
            accepts(written_parameter_count)
                || (has_receiver
                    && language == Language::Go.config_label()
                    && written_parameter_count
                        .checked_sub(1)
                        .is_some_and(&mut accepts))
        }
    }
}

/// Select the activated summary for one canonical identity and project its
/// declarations.
///
/// The disposition is the runtime's own: `Conflict` means several activated
/// packs disagree, which fails closed rather than picking one.
fn lookup_declared_effects(
    models: Option<&ResolvedActiveSemanticModels>,
    key: &ModeledProcedureKey,
) -> ModelAnswer {
    let Some(models) = models else {
        return ModelAnswer::Empty;
    };
    let matched = models.procedure_summaries_for_member(
        crate::analyzer::semantic_model::ProcedureSummaryMemberKey::new(
            &key.language,
            &key.owner,
            &key.member,
            key.has_receiver,
            key.parameter_count,
        ),
    );
    match matched.disposition {
        SemanticModelMatchDisposition::Empty => ModelAnswer::Empty,
        SemanticModelMatchDisposition::Conflict => ModelAnswer::Conflict,
        SemanticModelMatchDisposition::Unique => {
            let Some(selected) = matched.records.first() else {
                return ModelAnswer::Empty;
            };
            let effects = selected
                .declared_effects()
                .iter()
                .map(|effect| {
                    BoundDeclaredEffect::new(
                        effect,
                        selected.shard.manifest.pack_id.clone(),
                        selected.record.model_id.clone(),
                        selected.record.id.clone(),
                    )
                })
                .collect::<Vec<_>>();
            let result_contracts = selected
                .result_contracts()
                .iter()
                .cloned()
                .map(|contract| BoundResultContract {
                    fresh_allocation: selected.record.effects.iter().any(|effect| {
                        matches!(
                            effect,
                            crate::analyzer::semantic_model::CompiledSummaryEffect::Allocation {
                                output: crate::analyzer::semantic_model::CompiledSummaryOutput::IndexedNormalReturn { ordinal },
                                ..
                            } if *ordinal == contract.result_ordinal
                        )
                    }),
                    contract,
                    pack_id: Some(selected.shard.manifest.pack_id.clone()),
                    model_id: Some(selected.record.model_id.clone()),
                    summary_id: Some(selected.record.id.clone()),
                })
                .collect();
            let normal_return_refinements = selected.normal_return_refinements().to_vec();
            let conditional_result_refinements = selected.conditional_result_refinements().to_vec();
            let conditional_indirect_writes = selected.conditional_indirect_writes().to_vec();
            let preconditions = selected
                .preconditions()
                .map(|preconditions| preconditions.to_vec());
            ModelAnswer::Modeled {
                complete: selected.record.completeness == Completeness::Complete,
                covers_overrides: selected.record.covers_overrides,
                effects,
                result_contracts,
                normal_return_refinements,
                conditional_result_refinements,
                conditional_indirect_writes,
                preconditions,
            }
        }
    }
}

/// The canonical identity of one fully-qualified callee the workspace does not
/// materialize, built from the resolver's own published facts (#1978).
///
/// The language label is the semantic-pack spelling the taint side already
/// binds authored summaries with, so TSX and TypeScript select the same pack
/// while an effect declaration and a data-flow summary use the same rule.
fn external_modeled_key(target: &UnmaterializedExternalTarget) -> ModeledProcedureKey {
    ModeledProcedureKey {
        language: target.language().semantic_pack_label().to_owned(),
        owner: target.owner_fqn().to_owned(),
        member: target.member().to_owned(),
        has_receiver: target.has_receiver(),
        parameter_count: target.arity(),
    }
}

/// The graph identity of an external member, minted from its canonical key so
/// two arms naming the same member share one leaf node.
fn external_procedure_identity(key: &ModeledProcedureKey) -> String {
    let mut digest = LengthDelimitedDigest::new(EXTERNAL_EFFECT_PROCEDURE_ID_DOMAIN);
    digest.push(key.language.as_bytes());
    digest.push(key.owner.as_bytes());
    digest.push(key.member.as_bytes());
    digest.push(&[u8::from(key.has_receiver)]);
    digest.push(&key.parameter_count.to_le_bytes());
    digest.finish().to_string()
}

/// Derive the direct effect rows of one already-derived call shape.
pub(super) fn call_effect_expansions(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    shape: &CallShapeValue,
) -> Vec<PipelineExpansion> {
    let outcome = &shape.report.outcome;
    let DispatchedArms {
        status,
        arms,
        call_contexts: _,
    } = dispatch_arms(analyzer, semantic, cache, &outcome.file, outcome.range);
    let report_arms = arms
        .iter()
        .map(|arm| arm.effect.clone())
        .collect::<Vec<_>>();
    let report = Arc::new(call_effect_report(
        &outcome.file,
        &outcome.site_id,
        &outcome.site_ast_id,
        outcome.range,
        status,
        &report_arms,
    ));
    let rendered_callees = Arc::new(
        arms.into_iter()
            .filter_map(|arm| {
                let unit = arm.callee?;
                let range = analyzer
                    .ranges_of(&unit)
                    .into_iter()
                    .min_by_key(primary_range_key)?;
                Some((arm.effect.target_id, DeclarationValue::new(unit, range)))
            })
            .collect::<BTreeMap<_, _>>(),
    );
    record_coverage(cache, diagnostics, &outcome.file, report.coverage);
    (0..report.rows.len())
        .map(|index| {
            pipeline_expansion(PipelineValue::CallEffect(Box::new(CallEffectValue {
                report: Arc::clone(&report),
                callees: Arc::clone(&rendered_callees),
                index,
            })))
        })
        .collect()
}

/// Retain a call shape only when every resolved arm positively selects the
/// same activated result contract. Unresolved or conclusively unmodeled calls
/// are ordinary non-matches: this is a candidate-discovery filter, not the
/// mandatory relation emitted by `call_result_contract_expansions`.
pub(super) fn result_contract_call_expansions(
    analyzer: &dyn IAnalyzer,
    cache: &mut EffectTraversalCache,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    shape: &CallShapeValue,
) -> Vec<PipelineExpansion> {
    let outcome = &shape.report.outcome;
    let Some(answer) = cache
        .modeled_call_targets
        .as_ref()
        .filter(|window| window.file == outcome.file)
        .and_then(|window| window.lookups.get(&outcome.site_id))
        .cloned()
    else {
        return Vec::new();
    };
    if !answer.adjudicable_workspace_names.is_empty() {
        let actual_parameter_count = shape.report.arguments.len();
        if answer.adjudicable_workspace_names.iter().all(|name| {
            cache.has_result_contract_name(
                analyzer,
                name,
                actual_parameter_count,
                answer.call_application,
            )
        }) {
            record_result_contract_dispatch_coverage(
                cache,
                diagnostics,
                &outcome.file,
                EffectCoverage::Open,
            );
        }
        // A name absent from the active result-contract inventory is one exact
        // non-modeled dispatch alternative and therefore disproves universal
        // contract applicability. When every name has an active target that
        // accepts the actual arity, the missing receiver/signature
        // evidence remains typed open. Neither case manufactures a positive
        // target arm.
        return Vec::new();
    }
    if answer.arms.is_empty() {
        if matches!(
            answer.coverage,
            ModeledCallTargetCoverage::Open
                | ModeledCallTargetCoverage::Truncated
                | ModeledCallTargetCoverage::Unsupported
                | ModeledCallTargetCoverage::Cancelled
        ) && cache.may_name_result_contract(analyzer, shape, answer.call_application)
        {
            record_result_contract_dispatch_coverage(
                cache,
                diagnostics,
                &outcome.file,
                modeled_call_target_coverage(answer.coverage),
            );
        }
        return Vec::new();
    }

    let mut common_contracts: Option<Vec<BoundResultContract>> = None;
    for arm in &answer.arms {
        let contracts = match cache.answer_for(analyzer, &arm.key) {
            ModelAnswer::Modeled {
                result_contracts, ..
            } if !result_contracts.is_empty() => result_contracts,
            ModelAnswer::Conflict => {
                record_result_contract_dispatch_coverage(
                    cache,
                    diagnostics,
                    &outcome.file,
                    EffectCoverage::Open,
                );
                return Vec::new();
            }
            ModelAnswer::Modeled { .. } | ModelAnswer::Empty => return Vec::new(),
        };
        match &mut common_contracts {
            None => common_contracts = Some(contracts),
            Some(common) => retain_common_result_contracts(common, &contracts),
        }
    }

    if common_contracts.as_ref().is_none_or(Vec::is_empty) {
        return Vec::new();
    }
    let coverage = modeled_call_target_coverage(answer.coverage);
    if coverage != EffectCoverage::Exhaustive {
        record_result_contract_dispatch_coverage(cache, diagnostics, &outcome.file, coverage);
        return Vec::new();
    }

    vec![pipeline_expansion(PipelineValue::CallShape(shape.clone()))]
}

const fn modeled_call_target_coverage(coverage: ModeledCallTargetCoverage) -> EffectCoverage {
    match coverage {
        ModeledCallTargetCoverage::Exhaustive => EffectCoverage::Exhaustive,
        ModeledCallTargetCoverage::Unmodeled => EffectCoverage::Exhaustive,
        ModeledCallTargetCoverage::Open | ModeledCallTargetCoverage::Cancelled => {
            EffectCoverage::Open
        }
        ModeledCallTargetCoverage::Truncated => EffectCoverage::Truncated,
        ModeledCallTargetCoverage::Unsupported => EffectCoverage::Unsupported,
    }
}

/// Resolve all result-contract candidate call targets in one file with one
/// exact-source parse and one definition-resolution batch. The retained
/// products are canonical model keys and typed coverage only; they own no
/// semantic artifact handles.
pub(super) fn prepare_result_contract_call_lookups(
    analyzer: &dyn IAnalyzer,
    cache: &mut EffectTraversalCache,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    shapes: &[&CallShapeValue],
) {
    let Some(first) = shapes.first() else {
        return;
    };
    let file = &first.report.outcome.file;
    debug_assert!(
        shapes
            .iter()
            .all(|shape| &shape.report.outcome.file == file)
    );
    let reports = shapes
        .iter()
        .map(|shape| shape.report.as_ref())
        .collect::<Vec<_>>();
    prepare_modeled_call_target_lookups(analyzer, cache, limits, cancellation, file, &reports);
    cache.exact_sources.remove(file);
    cache.exact_source_identities.get_mut().remove(file);
}

fn prepare_modeled_call_target_lookups(
    analyzer: &dyn IAnalyzer,
    cache: &mut EffectTraversalCache,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    file: &ProjectFile,
    shapes: &[&crate::analyzer::usages::call_shape::CallShapeReport],
) {
    let Some(exact_source) = cache.exact_source(analyzer, file) else {
        cache.replace_modeled_call_target_window(
            file.clone(),
            shapes
                .iter()
                .map(|shape| {
                    (
                        shape.outcome.site_id.clone(),
                        ModeledCallTargetLookup {
                            arms: Vec::new(),
                            adjudicable_workspace_names: Vec::new(),
                            call_application: ModeledCallApplication::Unknown,
                            coverage: ModeledCallTargetCoverage::Unsupported,
                        },
                    )
                })
                .collect(),
        );
        return;
    };
    let lookups = modeled_call_targets_for_shapes(
        analyzer,
        shapes,
        exact_source,
        CallRelationLimits {
            max_files: 1,
            max_source_bytes: limits.semantic.max_source_bytes,
            // Each input shape came from the structural-fact pipeline bounded
            // by this same limit. The dispatch limit itself is the separate
            // per-call target-arm cap, not a second batch-site counter.
            max_candidates: limits.max_fact_nodes,
        },
        cancellation,
    );
    cache.replace_modeled_call_target_window(
        file.clone(),
        shapes
            .iter()
            .zip(lookups)
            .map(|(shape, lookup)| (shape.outcome.site_id.clone(), lookup))
            .collect(),
    );
}

fn prepare_result_operation_call_lookups(
    analyzer: &dyn IAnalyzer,
    cache: &mut EffectTraversalCache,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    file: &ProjectFile,
    shapes_by_range: &ResultMemberCallShapesByRange,
) {
    let mut shapes = shapes_by_range
        .values()
        .filter_map(Option::as_ref)
        .collect::<Vec<_>>();
    shapes.sort_unstable_by_key(|shape| {
        (
            shape.outcome.range.start_byte,
            shape.outcome.range.end_byte,
            shape.outcome.site_id.as_str(),
        )
    });
    shapes.dedup_by(|left, right| left.outcome.site_id == right.outcome.site_id);
    if cache.modeled_call_targets.as_ref().is_some_and(|window| {
        &window.file == file
            && shapes
                .iter()
                .all(|shape| window.lookups.contains_key(&shape.outcome.site_id))
    }) {
        return;
    }
    prepare_modeled_call_target_lookups(analyzer, cache, limits, cancellation, file, &shapes);
}

/// Project the result-validity contracts that every possible dispatch arm
/// agrees on. A contract is applicable only when it is common to the whole arm
/// set; selecting one modeled arm out of a dynamic call would turn pack order
/// into semantics.
#[allow(clippy::too_many_arguments)]
pub(super) fn call_result_contract_expansions(
    analyzer: &dyn IAnalyzer,
    workspace: &WorkspaceAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    flow_state_cache: &mut FlowStateTraversalCache,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    shape: &CallShapeValue,
) -> Vec<PipelineExpansion> {
    let outcome = &shape.report.outcome;
    let answer = cache.dispatch_at_source(semantic, &outcome.file, outcome.range);
    let arm_count = answer.arms.len();
    let mut modeled_arm_count = 0usize;
    let mut model_conflict = false;
    let mut every_arm_closed = !answer.arms.is_empty();
    let mut every_arm_proven = !answer.arms.is_empty();
    let mut common_contracts: Option<Vec<BoundResultContract>> = None;
    let mut keys = Vec::with_capacity(arm_count);

    for arm in &answer.arms {
        every_arm_proven &= arm.proof == "proven";
        let key = match &arm.target_unit {
            Some(unit) => cache.key_for(analyzer, unit),
            None => arm.unmaterialized_target.as_ref().map(external_modeled_key),
        };
        let model = key
            .as_ref()
            .map(|key| cache.answer_for(analyzer, key))
            .unwrap_or(ModelAnswer::Empty);
        let (contracts, closes) = match model {
            ModelAnswer::Modeled {
                complete,
                covers_overrides,
                result_contracts,
                ..
            } => {
                modeled_arm_count = modeled_arm_count.saturating_add(1);
                let closes = key
                    .as_ref()
                    .is_some_and(|key| complete && (covers_overrides || !key.has_receiver));
                (result_contracts, closes)
            }
            ModelAnswer::Conflict => {
                model_conflict = true;
                (Vec::new(), false)
            }
            // An exact canonical arm with no active authored summary is a
            // conclusive non-applicability result for this relation. The
            // relation projects reviewed contracts from the active model set;
            // it does not claim that an unmodeled API has no behavioral
            // preconditions of its own.
            ModelAnswer::Empty => (Vec::new(), key.is_some()),
        };
        every_arm_closed &= closes;
        match &mut common_contracts {
            None => common_contracts = Some(contracts),
            Some(common) => retain_common_result_contracts(common, &contracts),
        }
        keys.push(key);
    }

    let mut coverage = coverage_for(answer.coverage);
    if answer.coverage == crate::analyzer::semantic::CandidateCoverage::Open
        && !answer.arms.is_empty()
    {
        let residual_discharged = match answer.unnamed_boundaries.as_slice() {
            [] => true,
            ["unresolved"] => every_arm_closed,
            _ => false,
        };
        if residual_discharged {
            coverage = EffectCoverage::Exhaustive;
        }
    }
    let mut reason = match answer.outcome {
        "unsupported" => {
            coverage = EffectCoverage::Unsupported;
            Some(EffectReason::DispatchUnsupported)
        }
        "cancelled" | "exceeded_budget" => {
            coverage = EffectCoverage::Open;
            Some(EffectReason::DispatchInterrupted)
        }
        _ if answer.arms.is_empty() => {
            coverage = EffectCoverage::Open;
            Some(EffectReason::DispatchUnresolved)
        }
        _ => None,
    };
    if model_conflict {
        coverage = coverage.meet(EffectCoverage::Open);
        reason = Some(EffectReason::ModelConflict);
    } else if coverage == EffectCoverage::Truncated {
        reason = Some(EffectReason::DispatchTruncated);
    } else if coverage == EffectCoverage::Open && reason.is_none() {
        reason = Some(EffectReason::DispatchUnresolved);
    }
    record_result_contract_dispatch_coverage(cache, diagnostics, &outcome.file, coverage);

    let single_arm = (answer.arms.len() == 1).then(|| &answer.arms[0]);
    let target_id = single_arm.map(|arm| arm.target_id.clone());
    let modeled_target = single_arm.and_then(|_| keys.first().cloned().flatten());
    let callee = single_arm
        .and_then(|arm| arm.target_unit.as_ref())
        .and_then(|unit| {
            analyzer
                .ranges_of(unit)
                .into_iter()
                .min_by_key(primary_range_key)
                .map(|range| DeclarationValue::new(unit.clone(), range))
        });
    let callee_symbol = keys
        .first()
        .and_then(Option::as_ref)
        .filter(|first| keys.iter().all(|key| key.as_ref() == Some(*first)))
        .map(ModeledProcedureKey::display);
    let proof = (!answer.arms.is_empty()).then_some(if every_arm_proven {
        EffectProof::Proven
    } else {
        EffectProof::Unproven
    });

    let contracts = common_contracts.unwrap_or_default();
    if contracts.is_empty() {
        return vec![pipeline_expansion(PipelineValue::CallResultContract(
            Box::new(CallResultContractValue {
                file: outcome.file.clone(),
                range: outcome.range,
                id: result_contract_row_id(&outcome.site_id, None),
                site_id: outcome.site_id.clone(),
                site_ast_id: outcome.site_ast_id.clone(),
                target_id,
                modeled_target,
                callee,
                callee_symbol,
                result_ordinal: None,
                condition_result_ordinal: None,
                predicate: None,
                result_success_predicate: None,
                proof,
                coverage,
                reason,
                pack_id: None,
                model_id: None,
                summary_id: None,
                arm_count,
                modeled_arm_count,
                terminal: true,
                result_use_count: None,
                unguarded_result_use_count: None,
                use_validation: None,
                use_validation_coverage: None,
                success_guard_coverage: None,
                success_guard_edges: Vec::new(),
                possible_success_guard_edges: Vec::new(),
                fresh_allocation: false,
                member_contracts: Vec::new(),
            }),
        ))];
    }

    contracts
        .into_iter()
        .map(|bound| {
            let guards = result_contract_success_guards(
                analyzer,
                workspace,
                semantic,
                cache,
                flow_state_cache,
                cancellation,
                &outcome.file,
                outcome.range,
                &outcome.site_id,
                &outcome.site_ast_id,
                modeled_target.as_ref(),
                &bound.contract,
            );
            if guards.coverage != EffectCoverage::Exhaustive {
                record_result_contract_guard_coverage(
                    cache,
                    diagnostics,
                    &outcome.file,
                    guards.coverage,
                );
            }
            pipeline_expansion(PipelineValue::CallResultContract(Box::new(
                CallResultContractValue {
                    file: outcome.file.clone(),
                    range: outcome.range,
                    id: result_contract_row_id(&outcome.site_id, Some(&bound.contract)),
                    site_id: outcome.site_id.clone(),
                    site_ast_id: outcome.site_ast_id.clone(),
                    target_id: target_id.clone(),
                    modeled_target: modeled_target.clone(),
                    callee: callee.clone(),
                    callee_symbol: callee_symbol.clone(),
                    result_ordinal: Some(bound.contract.result_ordinal),
                    condition_result_ordinal: bound.contract.condition_result_ordinal,
                    predicate: bound.contract.predicate,
                    result_success_predicate: bound.contract.result_success_predicate,
                    proof,
                    coverage,
                    reason,
                    pack_id: bound.pack_id,
                    model_id: bound.model_id,
                    summary_id: bound.summary_id,
                    arm_count,
                    modeled_arm_count,
                    terminal: false,
                    result_use_count: None,
                    unguarded_result_use_count: None,
                    use_validation: None,
                    use_validation_coverage: None,
                    success_guard_coverage: Some(guards.coverage),
                    success_guard_edges: guards
                        .edges
                        .iter()
                        .map(|edge| edge.durable_locator())
                        .collect(),
                    possible_success_guard_edges: guards
                        .possible_edges
                        .iter()
                        .map(|edge| edge.durable_locator())
                        .collect(),
                    fresh_allocation: bound.fresh_allocation,
                    member_contracts: bound.contract.member_contracts.clone(),
                },
            )))
        })
        .collect()
}

/// Add resource-use validation to one already projected result contract. The
/// contract row and its source identity are preserved; only the optional use
/// fields are populated. Model projection and lifecycle composition therefore
/// do not inherit incompleteness from a consumer they did not request.
#[allow(clippy::too_many_arguments)]
pub(super) fn result_contract_use_expansions(
    analyzer: &dyn IAnalyzer,
    workspace: &WorkspaceAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    flow_state_cache: &mut FlowStateTraversalCache,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    value: &CallResultContractValue,
) -> Vec<PipelineExpansion> {
    let Some(contract) = projected_result_contract(value) else {
        return vec![pipeline_expansion(PipelineValue::CallResultContract(
            Box::new(value.clone()),
        ))];
    };
    let validation = validate_result_contract_uses(
        analyzer,
        workspace,
        semantic,
        cache,
        flow_state_cache,
        limits,
        cancellation,
        &value.file,
        value.range,
        &value.site_id,
        &value.site_ast_id,
        value.modeled_target.as_ref(),
        &contract,
        value.coverage,
        &value.success_guard_edges,
    );
    if validation.coverage != EffectCoverage::Exhaustive {
        record_result_contract_use_coverage(cache, diagnostics, &value.file, validation.coverage);
    }
    let mut enriched = value.clone();
    enriched.result_use_count = Some(validation.use_count);
    enriched.unguarded_result_use_count = validation.unguarded_use_count;
    enriched.use_validation = Some(validation.status);
    enriched.use_validation_coverage = Some(validation.coverage);
    vec![pipeline_expansion(PipelineValue::CallResultContract(
        Box::new(enriched),
    ))]
}

/// Project one typed row per exact structured use of a protected result.
/// Unknown operation applicability remains visible with open coverage, while
/// reviewed no-precondition operations carry `not_required` and can never be
/// selected as an unguarded use.
#[allow(clippy::too_many_arguments)]
pub(super) fn result_contract_operation_use_expansions(
    analyzer: &dyn IAnalyzer,
    workspace: &WorkspaceAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    flow_state_cache: &mut FlowStateTraversalCache,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    value: &CallResultContractValue,
) -> Vec<PipelineExpansion> {
    let Some(contract) = projected_result_contract(value) else {
        return Vec::new();
    };
    let validation = validate_result_contract_uses(
        analyzer,
        workspace,
        semantic,
        cache,
        flow_state_cache,
        limits,
        cancellation,
        &value.file,
        value.range,
        &value.site_id,
        &value.site_ast_id,
        value.modeled_target.as_ref(),
        &contract,
        value.coverage,
        &value.success_guard_edges,
    );
    if validation.coverage != EffectCoverage::Exhaustive {
        record_result_contract_use_coverage(cache, diagnostics, &value.file, validation.coverage);
    }
    validation
        .uses
        .into_iter()
        .map(|validated| {
            let observed = validated.observed;
            let id = result_contract_use_row_id(&value.id, &observed);
            pipeline_expansion(PipelineValue::ResultContractUse(Box::new(
                ResultContractUseValue {
                    file: observed.file,
                    range: observed.range,
                    ast_id: observed.ast_id,
                    id,
                    acquisition_id: value.id.clone(),
                    acquisition_site_id: value.site_id.clone(),
                    acquisition_site_ast_id: value.site_ast_id.clone(),
                    operation_point_id: observed.point_id.to_string(),
                    operation_point: observed.guard_point,
                    subject_value: observed.subject_value,
                    operation_site_id: observed.operation_site_id,
                    operation_site_ast_id: observed.operation_site_ast_id,
                    result_ordinal: contract.result_ordinal,
                    condition_result_ordinal: value.condition_result_ordinal,
                    acquisition_predicate: value.predicate,
                    result_success_predicate: value.result_success_predicate,
                    required_predicate: observed.required_predicate,
                    use_kind: observed.use_kind,
                    timing: observed.timing,
                    applicability: observed.applicability,
                    guard: validated.guard,
                    coverage: validated.coverage,
                    member: observed.member,
                    parameter_count: observed.parameter_count,
                    parameter_ordinal: observed.parameter_ordinal,
                    pack_id: value.pack_id.clone(),
                    model_id: value.model_id.clone(),
                    summary_id: value.summary_id.clone(),
                },
            )))
        })
        .collect()
}

#[derive(Debug, Clone, Copy)]
struct NilnessOperationCandidate {
    point: crate::analyzer::semantic::ProgramPointId,
    subject: crate::analyzer::semantic::ValueId,
    use_kind: ResultContractUseKind,
    range: Range,
    fact: Option<brokk_bifrost_flow::scalar_state::ScalarFact>,
    origin: &'static str,
}

fn complete_modeled_call_facts(
    analyzer: &dyn IAnalyzer,
    cache: &mut EffectTraversalCache,
    shape: &crate::analyzer::usages::call_shape::CallShapeReport,
) -> Option<(
    Vec<CompiledConditionalIndirectWrite>,
    Option<Vec<CompiledOperationPrecondition>>,
)> {
    let answer = cache
        .modeled_call_targets
        .as_ref()
        .filter(|window| window.file == shape.outcome.file)?
        .lookups
        .get(&shape.outcome.site_id)?
        .clone();
    if answer.coverage != ModeledCallTargetCoverage::Exhaustive
        || !answer.adjudicable_workspace_names.is_empty()
        || answer.arms.is_empty()
    {
        return None;
    }
    let mut common_writes = None::<Vec<CompiledConditionalIndirectWrite>>;
    let mut common_preconditions = None::<Vec<CompiledOperationPrecondition>>;
    let mut preconditions_reviewed = true;
    for arm in &answer.arms {
        let ModelAnswer::Modeled {
            complete: true,
            conditional_indirect_writes,
            preconditions,
            ..
        } = cache.answer_for(analyzer, &arm.key)
        else {
            return None;
        };
        match &mut common_writes {
            None => common_writes = Some(conditional_indirect_writes),
            Some(common) => common.retain(|write| conditional_indirect_writes.contains(write)),
        }
        match (
            preconditions_reviewed,
            preconditions,
            &mut common_preconditions,
        ) {
            (true, Some(preconditions), None) => common_preconditions = Some(preconditions),
            (true, Some(preconditions), Some(common)) => {
                common.retain(|precondition| preconditions.contains(precondition));
            }
            (_, None, _) => preconditions_reviewed = false,
            (false, Some(_), _) => {}
        }
    }
    Some((
        common_writes.unwrap_or_default(),
        preconditions_reviewed.then(|| common_preconditions.unwrap_or_default()),
    ))
}

fn receiver_requires_non_null(preconditions: Option<&[CompiledOperationPrecondition]>) -> bool {
    let Some(preconditions) = preconditions else {
        return false;
    };
    let receiver = preconditions
        .iter()
        .filter(|precondition| matches!(precondition.input, CompiledSummaryInput::Receiver {}))
        .collect::<Vec<_>>();
    matches!(
        receiver.as_slice(),
        [precondition] if precondition.predicate == CompiledResultPredicate::NonNull
    )
}

fn modeled_call_proves_normal_continuation_absent(
    analyzer: &dyn IAnalyzer,
    cache: &mut EffectTraversalCache,
    shape: &crate::analyzer::usages::call_shape::CallShapeReport,
) -> bool {
    let Some(lookup) = cache
        .modeled_call_targets
        .as_ref()
        .filter(|window| window.file == shape.outcome.file)
        .and_then(|window| window.lookups.get(&shape.outcome.site_id))
        .cloned()
    else {
        return false;
    };
    if lookup.coverage != ModeledCallTargetCoverage::Exhaustive
        || !lookup.adjudicable_workspace_names.is_empty()
        || lookup.arms.is_empty()
    {
        return false;
    }
    let Some(models) = cache.models(analyzer) else {
        return false;
    };
    lookup.arms.iter().all(|arm| {
        models.proves_normal_continuation_absent(
            crate::analyzer::semantic_model::ProcedureSummaryMemberKey::new(
                &arm.key.language,
                &arm.key.owner,
                &arm.key.member,
                arm.key.has_receiver,
                arm.key.parameter_count,
            ),
        )
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn nilness_operation_expansions(
    analyzer: &dyn IAnalyzer,
    workspace: &WorkspaceAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    flow_state_cache: &mut FlowStateTraversalCache,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    procedure: &SemanticProcedureValue,
    facts: Option<&FileFacts>,
) -> Vec<PipelineExpansion> {
    use brokk_bifrost_flow::scalar_state::{
        ScalarCallEffects, ScalarEdgeWrite, ScalarFact, ScalarStateDerivation,
        unique_binding_origin,
    };

    let semantics = procedure.handle.semantics();
    if semantics.locator().language()
        != crate::analyzer::LanguageDialect::Standard(crate::analyzer::Language::Go)
    {
        return Vec::new();
    }
    let file = procedure.file();
    let shapes = cache.result_member_call_shapes(semantic, file, facts);
    if let Some(shapes) = shapes.as_deref() {
        prepare_result_operation_call_lookups(analyzer, cache, limits, cancellation, file, shapes);
    }
    let shape_for_call = |call: &crate::analyzer::semantic::SemanticCallSite| {
        exact_semantic_call_range(semantics, call)
            .and_then(|range| shapes.as_deref()?.get(&range)?.as_ref())
    };
    let mut modeled_address_calls = Vec::new();
    let mut edge_writes = Vec::new();
    let mut infeasible_edges = Vec::new();
    let mut candidates = Vec::new();
    for call in semantics.call_sites() {
        let Some(shape) = shape_for_call(call) else {
            continue;
        };
        if modeled_call_proves_normal_continuation_absent(analyzer, cache, shape)
            && let Some(normal) = call.normal_continuation.target()
        {
            let normal_edges = semantics
                .successor_edges(call.point)
                .filter_map(|(edge, control)| (control.target_point == normal).then_some(edge))
                .collect::<Vec<_>>();
            debug_assert!(
                !normal_edges.is_empty(),
                "a retained normal call continuation has at least one CFG edge"
            );
            infeasible_edges.extend(normal_edges);
        }
        let Some((conditional_writes, preconditions)) =
            complete_modeled_call_facts(analyzer, cache, shape)
        else {
            continue;
        };
        modeled_address_calls.push(call.id);
        for write in conditional_writes {
            if write.target != CompiledIndirectWriteTarget::Pointee {
                continue;
            }
            let Some(argument) = call.arguments.get(write.parameter_ordinal as usize) else {
                continue;
            };
            let Some(target) = unique_binding_origin(&procedure.handle, argument.value) else {
                continue;
            };
            let Some(result) = call.normal_result(write.result_ordinal as usize) else {
                continue;
            };
            let Some((true_edge, false_edge)) =
                direct_opaque_guard_edges(&procedure.handle, result)
            else {
                continue;
            };
            edge_writes.push(ScalarEdgeWrite {
                edge: if write.outcome {
                    true_edge.id()
                } else {
                    false_edge.id()
                },
                target,
                fact: ScalarFact::Unknown,
            });
        }
        let Some(receiver) = call.receiver else {
            continue;
        };
        if !receiver_requires_non_null(preconditions.as_deref())
            || shape.outcome.coverage != CallShapeCoverage::Exact
            || shape.outcome.call_kind != CallKind::Method
        {
            continue;
        }
        let Some(range) = shape.outcome.receiver_range else {
            continue;
        };
        candidates.push(NilnessOperationCandidate {
            point: call.point,
            subject: receiver,
            use_kind: ResultContractUseKind::ReceiverCall,
            range,
            fact: None,
            origin: "scalar_refinement",
        });
    }
    modeled_address_calls.sort_unstable();
    modeled_address_calls.dedup();
    edge_writes.sort_unstable_by_key(|write| (write.edge, write.target));
    edge_writes.dedup();
    infeasible_edges.sort_unstable();
    infeasible_edges.dedup();
    let scalar = ScalarStateDerivation::derive_with_call_effects(
        &procedure.handle,
        ScalarCallEffects {
            modeled_address_calls: &modeled_address_calls,
            edge_writes: &edge_writes,
            infeasible_edges: &infeasible_edges,
        },
    );
    let procedure_id = procedure.wire_id();
    for point in semantics.points() {
        for event in &point.events {
            let (subject, use_kind) = match event.effect {
                SemanticEffect::ValueUse {
                    kind: ValueUseKind::Dereference,
                    value,
                } => (value, ResultContractUseKind::Dereference),
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Field,
                    location,
                    result,
                } => {
                    if semantics
                        .call_sites()
                        .iter()
                        .any(|call| call.callee == result)
                    {
                        continue;
                    }
                    let Some(crate::analyzer::semantic::MemoryLocation {
                        kind: MemoryLocationKind::Field { base, .. },
                        ..
                    }) = semantics.memory_location(location)
                    else {
                        continue;
                    };
                    (*base, ResultContractUseKind::Field)
                }
                SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Field,
                    location,
                    ..
                } => {
                    let Some(crate::analyzer::semantic::MemoryLocation {
                        kind: MemoryLocationKind::Field { base, .. },
                        ..
                    }) = semantics.memory_location(location)
                    else {
                        continue;
                    };
                    (*base, ResultContractUseKind::Field)
                }
                _ => continue,
            };
            let Some(mapping) = semantics.source_mapping(event.source) else {
                continue;
            };
            let span = mapping.locator.anchor().span();
            let range = Range {
                start_byte: span.start_byte() as usize,
                end_byte: span.end_byte() as usize,
                start_line: span.start().line() as usize + 1,
                end_line: span.end().line() as usize + 1,
            };
            candidates.push(NilnessOperationCandidate {
                point: point.id,
                subject,
                use_kind,
                range,
                fact: None,
                origin: "scalar_refinement",
            });
        }
    }

    // Compose reviewed result/error contracts into the same scalar relation.
    // This reuses the contract validator instead of teaching nilness a second
    // interpretation of result provenance or success guards.
    let contract_shapes = semantics
        .call_sites()
        .iter()
        .filter_map(shape_for_call)
        .filter(|shape| shape.outcome.coverage == CallShapeCoverage::Exact)
        .map(|shape| CallShapeValue {
            report: Arc::new(shape.clone()),
        })
        .collect::<Vec<_>>();
    for shape in contract_shapes {
        if result_contract_call_expansions(analyzer, cache, diagnostics, &shape).is_empty() {
            continue;
        }
        for contract in call_result_contract_expansions(
            analyzer,
            workspace,
            semantic,
            cache,
            flow_state_cache,
            cancellation,
            diagnostics,
            &shape,
        ) {
            let PipelineValue::CallResultContract(contract) = contract.value else {
                unreachable!("result-contract expansion returned another row kind");
            };
            for operation in result_contract_operation_use_expansions(
                analyzer,
                workspace,
                semantic,
                cache,
                flow_state_cache,
                limits,
                cancellation,
                diagnostics,
                &contract,
            ) {
                let PipelineValue::ResultContractUse(operation) = operation.value else {
                    unreachable!("result-contract-use expansion returned another row kind");
                };
                if operation.applicability != OperationApplicability::Required
                    || operation.required_predicate != Some(CompiledResultPredicate::NonNull)
                    || operation.guard != ResultUseGuardVerdict::Unguarded
                    || operation.coverage != EffectCoverage::Exhaustive
                    || procedure
                        .handle
                        .point_handle(operation.operation_point)
                        .is_none()
                {
                    continue;
                }
                candidates.push(NilnessOperationCandidate {
                    point: operation.operation_point,
                    subject: operation.subject_value,
                    use_kind: operation.use_kind,
                    range: operation.range,
                    fact: Some(ScalarFact::MaybeNil),
                    origin: "result_contract",
                });
            }
        }
    }

    let mut candidates = candidates
        .into_iter()
        .map(|candidate| {
            let fact = candidate
                .fact
                .unwrap_or_else(|| scalar.fact_at(candidate.point, candidate.subject));
            (candidate, fact)
        })
        .collect::<Vec<_>>();
    candidates.sort_unstable_by_key(|(candidate, fact)| {
        let exact = !matches!(fact, ScalarFact::Unknown | ScalarFact::Unreachable);
        let priority = match (exact, candidate.origin) {
            (true, "scalar_refinement") => 3,
            (true, _) => 2,
            (false, "scalar_refinement") => 1,
            (false, _) => 0,
        };
        (
            candidate.point,
            candidate.subject,
            candidate.use_kind.label(),
            std::cmp::Reverse(priority),
        )
    });
    candidates.dedup_by(|(left, _), (right, _)| {
        left.point == right.point
            && left.subject == right.subject
            && left.use_kind == right.use_kind
    });

    let mut rows = Vec::with_capacity(candidates.len());
    for (candidate, fact) in candidates {
        let point_handle = procedure
            .handle
            .point_handle(candidate.point)
            .expect("validated nilness operation point resolves");
        let operation_point_id = super::semantic::program_point_wire_id(&point_handle);
        let mut digest = LengthDelimitedDigest::new(NILNESS_OPERATION_ID_DOMAIN);
        digest.push(procedure_id.as_bytes());
        digest.push(operation_point_id.as_bytes());
        digest.push(&candidate.subject.get().to_le_bytes());
        digest.push(candidate.use_kind.label().as_bytes());
        let exact = !matches!(fact, ScalarFact::Unknown | ScalarFact::Unreachable);
        rows.push(pipeline_expansion(PipelineValue::NilnessOperation(
            Box::new(NilnessOperationValue {
                file: procedure.file().clone(),
                range: candidate.range,
                ast_id: None,
                id: digest.finish().to_string(),
                procedure_id: procedure_id.clone(),
                operation_point_id,
                subject_value_id: candidate.subject.get().into(),
                use_kind: candidate.use_kind,
                fact,
                origin: candidate.origin,
                proof: if exact { "exact" } else { "unknown" },
                coverage: if exact {
                    EffectCoverage::Exhaustive
                } else {
                    EffectCoverage::Open
                },
                reason: (!exact).then_some("scalar_fact_unknown"),
            }),
        )));
    }
    rows
}

/// One typed coverage row for every structured switch fact emitted by the
/// language adapter. Closed boolean domains are the only non-default case set
/// that can prove exhaustiveness; open and type-switch domains stay explicit
/// unknowns instead of being guessed from source spelling.
pub(super) fn switch_coverage_expansions(
    procedure: &SemanticProcedureValue,
) -> Vec<PipelineExpansion> {
    use crate::analyzer::semantic::{SwitchFactKind, SwitchSelectorDomain};

    let semantics = procedure.handle.semantics();
    let procedure_id = procedure.wire_id();
    semantics
        .switch_facts()
        .iter()
        .map(|fact| {
            let mut has_true_case = false;
            let mut has_false_case = false;
            let boolean_cases_exact = fact.cases.iter().all(|case| {
                match semantics.value(case.value).map(|value| &value.kind) {
                    Some(SemanticValueKind::Boolean(true)) => {
                        has_true_case = true;
                        true
                    }
                    Some(SemanticValueKind::Boolean(false)) => {
                        has_false_case = true;
                        true
                    }
                    _ => false,
                }
            });
            let (verdict, proof, reason) = match fact.kind {
                SwitchFactKind::Type => ("unknown", "unknown", Some("type_switch")),
                _ if fact.default_present => ("exhaustive", "exact", None),
                SwitchFactKind::Expression
                    if fact.selector_domain == SwitchSelectorDomain::Boolean
                        && boolean_cases_exact =>
                {
                    if has_true_case && has_false_case {
                        ("exhaustive", "exact", None)
                    } else {
                        ("non_exhaustive", "exact", Some("boolean_case_missing"))
                    }
                }
                SwitchFactKind::Expression
                    if fact.selector_domain == SwitchSelectorDomain::Boolean =>
                {
                    ("unknown", "unknown", Some("case_domain_open"))
                }
                SwitchFactKind::Expression => ("unknown", "unknown", Some("selector_domain_open")),
                SwitchFactKind::Expressionless => {
                    ("unknown", "unknown", Some("expressionless_without_default"))
                }
            };
            let mapping = semantics
                .source_mapping(fact.source)
                .expect("validated switch fact source mapping resolves");
            let span = mapping.locator.anchor().span();
            let range = Range {
                start_byte: span.start_byte() as usize,
                end_byte: span.end_byte() as usize,
                start_line: span.start().line() as usize + 1,
                end_line: span.end().line() as usize + 1,
            };
            let mut digest = LengthDelimitedDigest::new(SWITCH_COVERAGE_ID_DOMAIN);
            digest.push(procedure_id.as_bytes());
            digest.push(&fact.id.get().to_le_bytes());
            pipeline_expansion(PipelineValue::SwitchCoverage(Box::new(
                SwitchCoverageValue {
                    file: procedure.file().clone(),
                    range,
                    ast_id: mapping.ast_identity.map(|identity| {
                        super::super::occurrence_rows::ast_id(
                            identity.content(),
                            identity.node_id(),
                        )
                    }),
                    id: digest.finish().to_string(),
                    procedure_id: procedure_id.clone(),
                    switch_fact_id: fact.id.get(),
                    kind: fact.kind.label(),
                    selector_value_id: fact.selector.map(|id| u64::from(id.get())),
                    selector_domain: fact.selector_domain.label(),
                    case_count: fact.cases.len(),
                    has_true_case,
                    has_false_case,
                    default_present: fact.default_present,
                    verdict,
                    proof,
                    reason,
                },
            )))
        })
        .collect()
}

pub(super) fn detached_task_transfer_expansions(
    semantic: &mut super::semantic::SemanticQueryContext<'_>,
    procedure: &SemanticProcedureValue,
) -> Vec<PipelineExpansion> {
    let semantics = procedure.handle.semantics();
    let procedure_id = procedure.wire_id();
    brokk_bifrost_flow::detached_task::detached_task_transfers(semantics)
        .into_iter()
        .map(|transfer| {
            let call = procedure
                .handle
                .call_site_handle(transfer.call_site)
                .expect("validated detached transfer call resolves");
            let point = procedure
                .handle
                .point_handle(transfer.point)
                .expect("validated detached transfer point resolves");
            let observation_point = procedure
                .handle
                .point_handle(transfer.observation_point)
                .expect("validated detached transfer observation point resolves");
            let value = procedure
                .handle
                .value_handle(transfer.value)
                .expect("validated detached transfer value resolves");
            let mapping = semantics
                .value(transfer.value)
                .and_then(|value| semantics.source_mapping(value.source))
                .expect("validated detached transfer value has a source mapping");
            let span = mapping.locator.anchor().span();
            let range = Range {
                start_byte: span.start_byte() as usize,
                end_byte: span.end_byte() as usize,
                start_line: span.start().line() as usize + 1,
                end_line: span.end().line() as usize + 1,
            };
            let value_id = super::semantic::semantic_value_wire_id(&value);
            let call_id = super::semantic::call_site_wire_id(&call);
            let call_point_id = super::semantic::program_point_wire_id(&point);
            let object = semantic.exact_object_identity(value, observation_point);
            let (object_id, object_cardinality, proof, coverage, reason) = match object {
                Ok(object) => (
                    Some(object.id),
                    Some(object.cardinality),
                    "exact",
                    "exhaustive",
                    None,
                ),
                Err(reason) => (None, None, "unknown", "open", Some(reason)),
            };
            let mut digest = LengthDelimitedDigest::new(DETACHED_TASK_TRANSFER_ID_DOMAIN);
            digest.push(procedure_id.as_bytes());
            digest.push(call_id.as_bytes());
            digest.push(transfer.role.label().as_bytes());
            digest.push(&transfer.ordinal.unwrap_or(u32::MAX).to_le_bytes());
            digest.push(value_id.as_bytes());
            pipeline_expansion(PipelineValue::DetachedTaskTransfer(Box::new(
                DetachedTaskTransferValue {
                    file: procedure.file().clone(),
                    range,
                    ast_id: mapping.ast_identity.map(|identity| {
                        super::super::occurrence_rows::ast_id(
                            identity.content(),
                            identity.node_id(),
                        )
                    }),
                    id: digest.finish().to_string(),
                    procedure_id: procedure_id.clone(),
                    call_id,
                    call_point_id,
                    role: transfer.role.label(),
                    ordinal: transfer.ordinal,
                    value_id,
                    object_id,
                    object_cardinality,
                    timing: "different_task",
                    proof,
                    coverage,
                    reason,
                },
            )))
        })
        .collect()
}

#[derive(Debug, Clone)]
struct FailureUseCandidate {
    point: crate::analyzer::semantic::ProgramPointId,
    operand: crate::analyzer::semantic::ValueId,
    consumer: crate::query::FailureUseConsumer,
    consumer_classification_closed: bool,
    consumer_identity_closed: bool,
    consumer_call_id: Option<String>,
    consumer_site_id: Option<String>,
    consumer_site_ast_id: Option<String>,
    argument_ordinal: Option<u32>,
}

#[derive(Debug, Default)]
struct FailureUseCandidates {
    values: Vec<FailureUseCandidate>,
    globally_open: bool,
    point_call_gaps: Vec<crate::analyzer::semantic::ProgramPointId>,
}

#[derive(Debug, Clone)]
struct FailureUseOrigin {
    range: Range,
    ast_id: Option<String>,
    binding: Option<crate::analyzer::semantic::ValueId>,
    establishment_point_id: Option<String>,
    establishment_value: Option<crate::analyzer::semantic::ValueId>,
    provenance: crate::query::FailureUseProvenance,
    closed: bool,
}

fn semantic_value_range(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    value: crate::analyzer::semantic::ValueId,
) -> Option<Range> {
    let mapping = semantics
        .value(value)
        .and_then(|value| semantics.source_mapping(value.source))?;
    let span = mapping.locator.anchor().span();
    Some(Range {
        start_byte: span.start_byte() as usize,
        end_byte: span.end_byte() as usize,
        start_line: span.start().line() as usize + 1,
        end_line: span.end().line() as usize + 1,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReturnedCallClassification {
    Returned,
    NotReturned,
    Open,
}

fn call_result_return_classification(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    derivation: Option<&crate::structural::flow_state::FlowStateDerivation>,
    call: &crate::analyzer::semantic::SemanticCallSite,
) -> ReturnedCallClassification {
    let semantics = procedure.semantics();
    let results = call
        .result
        .into_iter()
        .chain(call.normal_results.iter().copied())
        .collect::<Vec<_>>();
    if results.is_empty() {
        return ReturnedCallClassification::NotReturned;
    }
    // Active procedure completion can recover a panic and then implicitly
    // return named results, or mutate them before that return. Its local gap
    // subject does not identify every affected result, so keep the negative
    // classification procedure-wide open. A retained direct/aliased return
    // below still proves the positive `Returned` classification.
    let mut open = derivation.is_none()
        || semantics.gaps().iter().any(|gap| {
            gap.discharge == SemanticGapDischarge::ExitOnlyProcedureCompletion
                && gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
        });
    for result in results {
        let direct = semantics.points().iter().any(|point| {
            point.events.iter().any(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Return | ValueFlowKind::IndexedReturn { .. },
                        source,
                        ..
                    } if source == result
                )
            })
        });
        if direct {
            return ReturnedCallClassification::Returned;
        }
        let Some(derivation) = derivation else {
            continue;
        };
        let establishments = derivation
            .events
            .iter()
            .filter(|event| {
                event.event_class == StateEventClass::Establish && event.value == result
            })
            .map(|event| event.event)
            .collect::<Vec<_>>();
        if establishments.is_empty() {
            let call_span = semantics
                .source_mapping(call.source)
                .map(|mapping| mapping.locator.anchor().span());
            open |= semantics.gaps().iter().any(|gap| {
                let return_transfer_hole = gap.impacts.contains(SemanticGapImpact::ReturnTransfer);
                // Calls, callable-reference, and dynamic-dispatch gaps describe
                // callee target resolution. They do not make a retained caller-
                // side call occurrence possibly returned. Only a local value-
                // transfer hole can hide the alias/return edge used here.
                let local_value_transfer_hole = gap.impacts.contains(SemanticGapImpact::ValueFlow)
                    && !matches!(
                        gap.capability,
                        SemanticCapability::Calls
                            | SemanticCapability::CallableReferences
                            | SemanticCapability::DynamicDispatch
                    );
                if !return_transfer_hole && !local_value_transfer_hole {
                    return false;
                }
                if matches!(
                    gap.discharge,
                    SemanticGapDischarge::RetainedEvaluationOrder
                        | SemanticGapDischarge::RetainedControlTopology
                        | SemanticGapDischarge::NonRejoiningExceptionalExit
                ) {
                    return false;
                }
                match gap.subject {
                    SemanticGapSubject::Procedure => true,
                    SemanticGapSubject::Point => {
                        gap.point == call.point
                            || call.normal_continuation.target() == Some(gap.point)
                            || call_span.is_some_and(|call| {
                                semantics
                                    .source_mapping(gap.source)
                                    .map(|mapping| mapping.locator.anchor().span())
                                    .is_some_and(|gap| {
                                        gap.start_byte() <= call.start_byte()
                                            && call.end_byte() <= gap.end_byte()
                                    })
                            })
                    }
                    SemanticGapSubject::Value(value) => value == result,
                    SemanticGapSubject::CallSite(site) => site == call.id,
                    SemanticGapSubject::CallContinuation { call_site, .. } => call_site == call.id,
                    SemanticGapSubject::MemoryLocation(_)
                    | SemanticGapSubject::Capture(_)
                    | SemanticGapSubject::AsyncContinuation { .. } => false,
                }
            });
            open |= derivation.completeness.reasons().iter().any(|reason| {
                (reason.blocks(FlowStateAxis::BindingEvents)
                    || reason.blocks(FlowStateAxis::ReachingRelation))
                    && !matches!(
                        reason,
                        FlowStateIncompleteReason::LoweringGap { .. }
                            | FlowStateIncompleteReason::BindingWithoutEstablishment { .. }
                            | FlowStateIncompleteReason::PropertyBaseNotCanonical { .. }
                    )
            });
            continue;
        }
        let aliases = derivation.exact_local_value_alias_closure(procedure, &establishments);
        open |= aliases.proof_open
            || !aliases.uncertain_reads.is_empty()
            || !aliases.uncertain_transfers.is_empty()
            || !aliases.unclosed_transfers.is_empty();
        let read_values = aliases
            .reads
            .iter()
            .map(|event| derivation.event(*event).value)
            .collect::<HashSet<_>>();
        let returned = semantics.points().iter().any(|point| {
            point.events.iter().any(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Return | ValueFlowKind::IndexedReturn { .. },
                        source,
                        ..
                    } if read_values.contains(&source)
                )
            })
        });
        if returned {
            return ReturnedCallClassification::Returned;
        }
    }
    if open {
        ReturnedCallClassification::Open
    } else {
        ReturnedCallClassification::NotReturned
    }
}

fn failure_use_candidates(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    derivation: Option<&crate::structural::flow_state::FlowStateDerivation>,
    call_shapes_by_range: Option<&ResultMemberCallShapesByRange>,
) -> FailureUseCandidates {
    let semantics = procedure.semantics();
    let mut answer = FailureUseCandidates::default();
    // A procedure-scoped Calls gap may have omitted a caller-side occurrence
    // anywhere, and a ReturnFlow gap may have omitted a direct return
    // consumer. ReturnFlow remains request-wide because this inventory does
    // not distinguish an omitted return expression from an omitted exit
    // transfer; its point is not yet a typed consumer occurrence. A
    // point-scoped Calls gap is narrower: retain its exact program point so the
    // caller can decide whether that omitted occurrence belongs to the
    // particular reviewed failure edge being projected. A later or sibling
    // spawned call must not open an earlier failure arm. Call-site gaps instead
    // qualify retained calls and are handled by each candidate's own identity
    // axes.
    for gap in semantics.gaps().iter().filter(|gap| {
        !matches!(
            gap.discharge,
            SemanticGapDischarge::RetainedEvaluationOrder
                | SemanticGapDischarge::RetainedControlTopology
                | SemanticGapDischarge::NonRejoiningExceptionalExit
        )
    }) {
        match (gap.capability, gap.subject) {
            (SemanticCapability::ReturnFlow, _) => answer.globally_open = true,
            (SemanticCapability::Calls, SemanticGapSubject::Procedure) => {
                answer.globally_open = true;
            }
            (SemanticCapability::Calls, SemanticGapSubject::Point) => {
                answer.point_call_gaps.push(gap.point);
            }
            _ => {}
        }
    }
    answer.point_call_gaps.sort_unstable();
    answer.point_call_gaps.dedup();
    for point in semantics.points() {
        let returned_values = point
            .events
            .iter()
            .filter_map(|event| match event.effect {
                SemanticEffect::ProcedureReturn { value } => Some(value),
                _ => None,
            })
            .collect::<Vec<_>>();
        if returned_values.is_empty() {
            continue;
        }
        for flow in &point.events {
            let SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Return | ValueFlowKind::IndexedReturn { .. },
                source,
                target,
            } = flow.effect
            else {
                continue;
            };
            if !returned_values
                .iter()
                .any(|returned| returned.is_none_or(|returned| returned == target))
            {
                continue;
            }
            answer.values.push(FailureUseCandidate {
                point: point.id,
                operand: source,
                consumer: crate::query::FailureUseConsumer::Return,
                consumer_classification_closed: true,
                consumer_identity_closed: true,
                consumer_call_id: None,
                consumer_site_id: None,
                consumer_site_ast_id: None,
                argument_ordinal: None,
            });
        }
    }
    for call in semantics.call_sites() {
        let returned = call_result_return_classification(procedure, derivation, call);
        let consumer_call_range = exact_semantic_call_range(semantics, call);
        let consumer_call_id = procedure
            .call_site_handle(call.id)
            .map(|handle| super::semantic::call_site_wire_id(&handle));
        let shape = exact_result_member_call_shape(semantics, call, call_shapes_by_range);
        let consumer_site_id = shape.map(|shape| shape.outcome.site_id.clone());
        let consumer_site_ast_id = shape.map(|shape| shape.outcome.site_ast_id.clone());
        let structural_identity_closed =
            shape.is_some_and(|shape| shape.outcome.coverage == CallShapeCoverage::Exact);
        for (argument_ordinal, argument) in call.arguments.iter().enumerate() {
            let argument_identity_closed = matches!(
                argument.expansion,
                CallArgumentExpansion::Direct(ArgumentDomain::Positional)
            );
            answer.values.push(FailureUseCandidate {
                point: call.point,
                operand: argument.value,
                consumer: if returned != ReturnedCallClassification::NotReturned {
                    crate::query::FailureUseConsumer::ReturnedCallArgument
                } else {
                    crate::query::FailureUseConsumer::CallArgument
                },
                consumer_classification_closed: returned != ReturnedCallClassification::Open,
                consumer_identity_closed: argument_identity_closed
                    && consumer_call_id.is_some()
                    && consumer_call_range.is_some()
                    && structural_identity_closed,
                consumer_call_id: consumer_call_id.clone(),
                consumer_site_id: consumer_site_id.clone(),
                consumer_site_ast_id: consumer_site_ast_id.clone(),
                argument_ordinal: Some(
                    u32::try_from(argument_ordinal)
                        .expect("semantic argument ordinals fit the public u32 contract"),
                ),
            });
        }
    }
    answer
}

fn failure_use_call_shapes(
    workspace: &WorkspaceAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    file: &ProjectFile,
) -> Option<Arc<ResultMemberCallShapesByRange>> {
    let facts = cache
        .facts
        .entry(file.clone())
        .or_insert_with(|| {
            workspace
                .analyzer()
                .structural_fact_providers()
                .into_iter()
                .find_map(|provider| provider.structural_facts(file))
        })
        .clone();
    cache.result_member_call_shapes(semantic, file, facts.as_deref())
}

fn failure_use_origin(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    derivation: &crate::structural::flow_state::FlowStateDerivation,
    condition: crate::analyzer::semantic::ValueId,
    condition_aliases: &crate::structural::flow_state::ExactLocalValueAliasClosure,
    condition_bindings: &HashSet<crate::analyzer::semantic::ValueId>,
    candidate: &FailureUseCandidate,
    fallback_range: Range,
) -> FailureUseOrigin {
    let semantics = procedure.semantics();
    let mut reads = derivation
        .events
        .iter()
        .filter(|event| {
            event.event_class == StateEventClass::Read && event.value == candidate.operand
        })
        .collect::<Vec<_>>();
    reads.sort_unstable_by_key(|event| event.event);
    // Event completeness is scoped to this exact semantic operand. A global
    // FieldMemory gap at an unrelated selector (for example `file.Close`)
    // must not erase a retained local read, while a noncanonical property
    // load or binding flow for this operand must not become `independent`.
    let mut structured_origin_count = 0usize;
    let mut relevant_points = HashSet::default();
    relevant_points.insert(candidate.point);
    let mut relevant_values = HashSet::default();
    relevant_values.insert(candidate.operand);
    let mut relevant_locations = HashSet::default();
    for point in semantics.points() {
        for event in &point.events {
            match event.effect {
                SemanticEffect::ValueFlow { source, target, .. }
                    if target == candidate.operand
                        && semantics.value(source).is_some_and(|value| {
                            matches!(
                                value.kind,
                                SemanticValueKind::Local
                                    | SemanticValueKind::Parameter { .. }
                                    | SemanticValueKind::Receiver { .. }
                            )
                        }) =>
                {
                    structured_origin_count = structured_origin_count.saturating_add(1);
                    relevant_points.insert(point.id);
                    relevant_values.insert(source);
                }
                SemanticEffect::MemoryLoad {
                    location, result, ..
                } if result == candidate.operand => {
                    structured_origin_count = structured_origin_count.saturating_add(1);
                    relevant_points.insert(point.id);
                    relevant_locations.insert(location);
                }
                _ => {}
            }
        }
    }
    let hard_event_hole = derivation.completeness.reasons().iter().any(|reason| {
        (reason.blocks(FlowStateAxis::BindingEvents)
            || reason.blocks(FlowStateAxis::PropertyEvents))
            && !matches!(
                reason,
                FlowStateIncompleteReason::LoweringGap { .. }
                    | FlowStateIncompleteReason::BindingWithoutEstablishment { .. }
                    | FlowStateIncompleteReason::PropertyBaseNotCanonical { .. }
            )
    });
    let operand_span = semantics
        .value(candidate.operand)
        .and_then(|value| semantics.source_mapping(value.source))
        .map(|mapping| mapping.locator.anchor().span());
    let localized_event_gap = semantics.gaps().iter().any(|gap| {
        let blocks_origin_events = matches!(
            gap.capability,
            SemanticCapability::Assignments
                | SemanticCapability::Values
                | SemanticCapability::LocalFlow
                | SemanticCapability::ParameterFlow
                | SemanticCapability::ReceiverFlow
                | SemanticCapability::ReturnFlow
                | SemanticCapability::Allocations
                | SemanticCapability::FieldMemory
                | SemanticCapability::StaticMemory
                | SemanticCapability::IndexMemory
                | SemanticCapability::Captures
        );
        if !blocks_origin_events {
            return false;
        }
        match gap.subject {
            SemanticGapSubject::Procedure => true,
            SemanticGapSubject::Point => {
                relevant_points.contains(&gap.point)
                    || operand_span.is_some_and(|operand| {
                        semantics
                            .source_mapping(gap.source)
                            .map(|mapping| mapping.locator.anchor().span())
                            .is_some_and(|gap| {
                                gap.start_byte() <= operand.start_byte()
                                    && operand.end_byte() <= gap.end_byte()
                            })
                    })
            }
            SemanticGapSubject::Value(value) => relevant_values.contains(&value),
            SemanticGapSubject::MemoryLocation(location) => relevant_locations.contains(&location),
            SemanticGapSubject::Capture(_) => operand_span.is_some_and(|operand| {
                semantics
                    .source_mapping(gap.source)
                    .map(|mapping| mapping.locator.anchor().span())
                    .is_some_and(|gap| {
                        gap.start_byte() <= operand.start_byte()
                            && operand.end_byte() <= gap.end_byte()
                    })
            }),
            SemanticGapSubject::CallSite(_)
            | SemanticGapSubject::CallContinuation { .. }
            | SemanticGapSubject::AsyncContinuation { .. } => false,
        }
    });
    let origin_events_closed =
        !hard_event_hole && !localized_event_gap && structured_origin_count == reads.len();
    if reads.len() == 1 {
        let read = reads[0];
        let binding = match &read.subject {
            crate::structural::flow_state::FlowSubject::Binding { value } => *value,
            crate::structural::flow_state::FlowSubject::Property { .. } => {
                return FailureUseOrigin {
                    range: read.site.range,
                    ast_id: read.site.ast_id.clone(),
                    binding: None,
                    establishment_point_id: None,
                    establishment_value: None,
                    provenance: crate::query::FailureUseProvenance::Unknown,
                    closed: false,
                };
            }
        };
        let identity_closed = origin_events_closed
            && condition_aliases.reads.contains(&read.event)
            && derivation.exact_local_alias_read_identity_is_closed(
                procedure,
                condition_aliases,
                read.event,
            );
        if identity_closed {
            let reaching = derivation
                .relations
                .iter()
                .filter(|relation| {
                    relation.target_event == read.event
                        && relation.relation == FlowRelation::Reaching
                        && relation.certainty == FlowCertainty::Exact
                })
                .collect::<Vec<_>>();
            debug_assert_eq!(
                reaching.len(),
                1,
                "a closed exact alias read has one reaching establishment"
            );
            let establishment = reaching
                .first()
                .map(|relation| derivation.event(relation.source_event));
            return FailureUseOrigin {
                range: read.site.range,
                ast_id: read.site.ast_id.clone(),
                binding: Some(binding),
                establishment_point_id: establishment.map(|event| event.point_id.to_string()),
                establishment_value: establishment.map(|event| event.value),
                provenance: crate::query::FailureUseProvenance::ConditionResult,
                closed: true,
            };
        }
        let reaching = derivation
            .relations
            .iter()
            .filter(|relation| {
                relation.target_event == read.event && relation.relation == FlowRelation::Reaching
            })
            .collect::<Vec<_>>();
        let reaching_complete = origin_events_closed
            && reaching.len() == 1
            && reaching[0].certainty == FlowCertainty::Exact
            && {
                let aliases = derivation
                    .exact_local_value_alias_closure(procedure, &[reaching[0].source_event]);
                aliases.reads.contains(&read.event)
                    && derivation
                        .exact_local_alias_read_identity_is_closed(procedure, &aliases, read.event)
            };
        if reaching_complete {
            let establishment = derivation.event(reaching[0].source_event);
            let distinct_binding = !condition_bindings.contains(&binding);
            let zero = semantics.value(establishment.value).is_some_and(|value| {
                matches!(
                    &value.kind,
                    SemanticValueKind::LanguageDefined(kind) if kind.as_ref() == "go.zero_value"
                )
            });
            let provenance = if !distinct_binding {
                crate::query::FailureUseProvenance::Unknown
            } else if zero {
                crate::query::FailureUseProvenance::DistinctZeroBinding
            } else {
                crate::query::FailureUseProvenance::DistinctBinding
            };
            return FailureUseOrigin {
                range: read.site.range,
                ast_id: read.site.ast_id.clone(),
                binding: Some(binding),
                establishment_point_id: Some(establishment.point_id.to_string()),
                establishment_value: Some(establishment.value),
                provenance,
                closed: provenance != crate::query::FailureUseProvenance::Unknown,
            };
        }
        return FailureUseOrigin {
            range: read.site.range,
            ast_id: read.site.ast_id.clone(),
            binding: Some(binding),
            establishment_point_id: None,
            establishment_value: None,
            provenance: crate::query::FailureUseProvenance::Unknown,
            closed: false,
        };
    }

    let direct_condition = candidate.operand == condition;
    let closed = origin_events_closed && reads.is_empty() && !semantics.gaps().iter().any(|gap| {
        gap.impacts.contains(SemanticGapImpact::ValueFlow)
            && matches!(gap.subject, SemanticGapSubject::Value(value) if value == candidate.operand)
    });
    FailureUseOrigin {
        range: semantic_value_range(semantics, candidate.operand).unwrap_or(fallback_range),
        ast_id: None,
        binding: None,
        establishment_point_id: None,
        establishment_value: None,
        provenance: if direct_condition {
            crate::query::FailureUseProvenance::ConditionResult
        } else if closed {
            crate::query::FailureUseProvenance::Independent
        } else {
            crate::query::FailureUseProvenance::Unknown
        },
        closed,
    }
}

#[allow(clippy::too_many_arguments)]
fn result_contract_failure_use_row_id(
    acquisition_id: &str,
    failure_edge_id: Option<&str>,
    point_id: &str,
    consumer_call_id: Option<&str>,
    consumer_site_id: Option<&str>,
    operand: crate::analyzer::semantic::ValueId,
    consumer: crate::query::FailureUseConsumer,
    argument_ordinal: Option<u32>,
) -> String {
    let mut digest = LengthDelimitedDigest::new(RESULT_CONTRACT_FAILURE_USE_ID_DOMAIN);
    digest.push(acquisition_id.as_bytes());
    match failure_edge_id {
        Some(failure_edge_id) => digest.push(failure_edge_id.as_bytes()),
        None => digest.push(b"open.failure.edge"),
    }
    digest.push(point_id.as_bytes());
    match (consumer_call_id, consumer_site_id) {
        (Some(consumer_call_id), consumer_site_id) => {
            digest.push(b"consumer.call");
            digest.push(consumer_call_id.as_bytes());
            if let Some(consumer_site_id) = consumer_site_id {
                digest.push(b"consumer.shape");
                digest.push(consumer_site_id.as_bytes());
            }
        }
        (None, None) => digest.push(b"procedure.return"),
        (None, Some(_)) => unreachable!("a structural consumer site has a semantic call"),
    }
    digest.push(&operand.get().to_le_bytes());
    digest.push(consumer.label().as_bytes());
    if let Some(argument_ordinal) = argument_ordinal {
        digest.push(&argument_ordinal.to_le_bytes());
    }
    digest.finish().to_string()
}

#[allow(clippy::too_many_arguments)]
fn open_result_contract_failure_use_expansions(
    cache: &mut EffectTraversalCache,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    filter: &crate::query::ResultContractFailureUseFilter,
    value: &CallResultContractValue,
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    derivation: Option<&crate::structural::flow_state::FlowStateDerivation>,
    call_shapes_by_range: Option<&ResultMemberCallShapesByRange>,
    condition_result_ordinal: u32,
    condition_value: Option<crate::analyzer::semantic::ValueId>,
    message: &'static str,
) -> Vec<PipelineExpansion> {
    record_result_contract_incomplete(
        cache,
        diagnostics,
        &value.file,
        EffectCoverage::Open,
        message,
    );
    if !filter.accepts(
        crate::query::FailureUseProvenance::Unknown,
        crate::query::FailureUseConsumer::Return,
    ) && !filter.accepts(
        crate::query::FailureUseProvenance::Unknown,
        crate::query::FailureUseConsumer::ReturnedCallArgument,
    ) && !filter.accepts(
        crate::query::FailureUseProvenance::Unknown,
        crate::query::FailureUseConsumer::CallArgument,
    ) {
        return Vec::new();
    }

    let semantics = procedure.semantics();
    let procedure_id = super::semantic::procedure_wire_id(procedure);
    failure_use_candidates(procedure, derivation, call_shapes_by_range)
        .values
        .into_iter()
        .filter(|candidate| {
            filter.accepts(
                crate::query::FailureUseProvenance::Unknown,
                candidate.consumer,
            )
        })
        .map(|candidate| {
            let consumer_point_id = super::semantic::program_point_wire_id(
                &procedure
                    .point_handle(candidate.point)
                    .expect("a retained failure consumer belongs to its procedure"),
            );
            let id = result_contract_failure_use_row_id(
                &value.id,
                None,
                &consumer_point_id,
                candidate.consumer_call_id.as_deref(),
                candidate.consumer_site_id.as_deref(),
                candidate.operand,
                candidate.consumer,
                candidate.argument_ordinal,
            );
            pipeline_expansion(PipelineValue::ResultContractFailureUse(Box::new(
                ResultContractFailureUseValue {
                    file: value.file.clone(),
                    range: semantic_value_range(semantics, candidate.operand)
                        .unwrap_or(value.range),
                    ast_id: None,
                    id,
                    acquisition_id: value.id.clone(),
                    acquisition_site_id: value.site_id.clone(),
                    acquisition_site_ast_id: value.site_ast_id.clone(),
                    procedure_id: procedure_id.clone(),
                    condition_result_ordinal,
                    condition_value_id: condition_value.map(|value| u64::from(value.get())),
                    failure_edge_id: None,
                    consumer_point_id,
                    consumer_call_id: candidate.consumer_call_id,
                    consumer_site_id: candidate.consumer_site_id,
                    consumer_site_ast_id: candidate.consumer_site_ast_id,
                    operand_value_id: u64::from(candidate.operand.get()),
                    binding_value_id: None,
                    establishment_point_id: None,
                    establishment_value_id: None,
                    provenance: crate::query::FailureUseProvenance::Unknown,
                    consumer: candidate.consumer,
                    argument_ordinal: candidate.argument_ordinal,
                    proof: EffectProof::Unproven,
                    coverage: EffectCoverage::Open,
                    pack_id: value.pack_id.clone(),
                    model_id: value.model_id.clone(),
                    summary_id: value.summary_id.clone(),
                },
            )))
        })
        .collect()
}

/// Project structured return and call-argument values that execute inside the
/// exact failure arm of a reviewed conditional result contract.
#[allow(clippy::too_many_arguments)]
pub(super) fn result_contract_failure_use_expansions(
    analyzer: &dyn IAnalyzer,
    workspace: &WorkspaceAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    flow_state_cache: &mut FlowStateTraversalCache,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    filter: &crate::query::ResultContractFailureUseFilter,
    value: &CallResultContractValue,
) -> Vec<PipelineExpansion> {
    let Some(contract) = projected_result_contract(value) else {
        return Vec::new();
    };
    let (Some(condition_result_ordinal), Some(_)) =
        (contract.condition_result_ordinal, contract.predicate)
    else {
        return Vec::new();
    };
    let results = semantic.call_results_at_source(
        &value.file,
        value.range,
        &value.site_id,
        &value.site_ast_id,
    );
    let result = results
        .iter()
        .find(|result| result.ordinal == contract.result_ordinal as usize);
    let condition = results
        .iter()
        .find(|result| result.ordinal == condition_result_ordinal as usize);
    let procedure = condition
        .map(|condition| condition.handle.procedure())
        .or_else(|| result.map(|result| result.handle.procedure()));
    let Some(procedure) = procedure else {
        record_result_contract_incomplete(
            cache,
            diagnostics,
            &value.file,
            EffectCoverage::Open,
            "failure-arm projection did not identify a result procedure",
        );
        return Vec::new();
    };
    let condition_value = condition.map(|condition| condition.value);
    let call_shapes = failure_use_call_shapes(workspace, semantic, cache, &value.file);
    let (Some(result), Some(condition)) = (result, condition) else {
        return open_result_contract_failure_use_expansions(
            cache,
            diagnostics,
            filter,
            value,
            procedure,
            None,
            call_shapes.as_deref(),
            condition_result_ordinal,
            condition_value,
            "failure-arm projection did not identify both contract results",
        );
    };
    if result.handle != condition.handle {
        return open_result_contract_failure_use_expansions(
            cache,
            diagnostics,
            filter,
            value,
            procedure,
            None,
            call_shapes.as_deref(),
            condition_result_ordinal,
            condition_value,
            "failure-arm projection found contract results in different procedures",
        );
    }
    let procedure = condition.handle.procedure();
    let Some(materialized) = semantic.materialized_outcome(&value.file) else {
        return open_result_contract_failure_use_expansions(
            cache,
            diagnostics,
            filter,
            value,
            procedure,
            None,
            call_shapes.as_deref(),
            condition_result_ordinal,
            Some(condition.value),
            "failure-arm projection could not materialize semantic state",
        );
    };
    let file_state = flow_state_cache.for_materialized_procedure(
        workspace,
        &value.file,
        materialized,
        procedure,
        cancellation,
    );
    let Some(derivation) = file_state
        .procedures
        .iter()
        .find(|candidate| candidate.procedure == procedure.id())
    else {
        return open_result_contract_failure_use_expansions(
            cache,
            diagnostics,
            filter,
            value,
            procedure,
            None,
            call_shapes.as_deref(),
            condition_result_ordinal,
            Some(condition.value),
            "failure-arm projection could not derive flow state",
        );
    };
    let Some(result_use_index) =
        cache.result_use_index(semantic, &value.file, procedure, derivation)
    else {
        return open_result_contract_failure_use_expansions(
            cache,
            diagnostics,
            filter,
            value,
            procedure,
            Some(derivation),
            call_shapes.as_deref(),
            condition_result_ordinal,
            Some(condition.value),
            "failure-arm projection could not index structured result uses",
        );
    };
    let semantic_model_overlay = value
        .modeled_target
        .as_ref()
        .filter(|target| target.language == "go")
        .and_then(|_| semantic.semantic_model_overlay());
    let exact_source = semantic_model_overlay
        .as_ref()
        .and_then(|_| cache.exact_source(analyzer, &value.file));
    let assignment_conversion_proof_work = exact_source
        .as_deref()
        .and_then(crate::analyzer::go_modeled_result_binding_type_identity_proof_work);
    let assignment_conversion_proof = result_assignment_conversion_proof_context(
        analyzer,
        &value.file,
        value.modeled_target.as_ref(),
        semantic_model_overlay.as_deref(),
        exact_source.as_deref(),
        &cache.exact_source_identities,
        &cache.result_assignment_conversion_proofs,
        assignment_conversion_proof_work,
    );
    let guards = result_contract_success_guards_for_values(
        semantic,
        procedure,
        derivation,
        &result_use_index,
        Some(condition.value),
        result.value,
        &contract,
        None,
        assignment_conversion_proof,
    );
    if guards.condition_failure_edges.is_empty() {
        if guards.condition_failure_coverage == EffectCoverage::Exhaustive {
            return Vec::new();
        }
        return open_result_contract_failure_use_expansions(
            cache,
            diagnostics,
            filter,
            value,
            procedure,
            Some(derivation),
            call_shapes.as_deref(),
            condition_result_ordinal,
            Some(condition.value),
            "failure-arm projection did not establish an exact condition edge",
        );
    }

    let condition_conversion = result_use_index.exact_converted_establishments_from(
        semantic,
        procedure,
        derivation,
        condition.value,
        condition_result_ordinal,
        assignment_conversion_proof,
    );
    let mut condition_establishments = derivation
        .events
        .iter()
        .filter(|event| {
            event.event_class == StateEventClass::Establish && event.value == condition.value
        })
        .map(|event| event.event)
        .collect::<Vec<_>>();
    condition_establishments.extend(condition_conversion.establishments.iter().copied());
    condition_establishments.sort_unstable();
    condition_establishments.dedup();
    let mut condition_establishment_points = condition_establishments
        .iter()
        .map(|event| derivation.event(*event).point)
        .collect::<Vec<_>>();
    condition_establishment_points.sort_unstable();
    condition_establishment_points.dedup();
    let condition_aliases =
        derivation.exact_local_value_alias_closure(procedure, &condition_establishments);
    let condition_bindings = condition_aliases
        .establishments
        .iter()
        .filter_map(|event| match &derivation.event(*event).subject {
            crate::structural::flow_state::FlowSubject::Binding { value } => Some(*value),
            crate::structural::flow_state::FlowSubject::Property { .. } => None,
        })
        .collect::<HashSet<_>>();

    let candidates = failure_use_candidates(procedure, Some(derivation), call_shapes.as_deref());

    let procedure_id = super::semantic::procedure_wire_id(procedure);
    // Failure-arm provenance depends on the condition identity and its exact
    // opposite-predicate edge. Protected-result aliases after acquisition are
    // success-use evidence and must not downgrade this independent proof.
    let globally_closed = value.proof == Some(EffectProof::Proven)
        && value.coverage == EffectCoverage::Exhaustive
        && guards.condition_failure_coverage == EffectCoverage::Exhaustive
        && !condition_conversion.proof_open
        && !condition_aliases.proof_open
        && condition_aliases.uncertain_reads.is_empty()
        && condition_aliases.uncertain_transfers.is_empty()
        && condition_aliases.unclosed_transfers.is_empty();
    let mut expansions = Vec::new();
    let mut saw_open_candidate = candidates.globally_open || !globally_closed;
    for failure_edge in &guards.condition_failure_edges {
        let point_call_gaps_open = if candidates.point_call_gaps.is_empty() {
            false
        } else {
            derivation
                .any_guard_arm_dominates_result_uses(
                    procedure,
                    &condition_establishment_points,
                    std::slice::from_ref(failure_edge),
                    &candidates.point_call_gaps,
                )
                .is_none_or(|answers| {
                    answers
                        .iter()
                        .any(|answer| *answer != GuardDominanceAnswer::ClosedNegative)
                })
        };
        saw_open_candidate |= point_call_gaps_open;
        let failure_edge_id = super::semantic::control_edge_wire_id(failure_edge);
        for candidate in &candidates.values {
            let origin = failure_use_origin(
                procedure,
                derivation,
                condition.value,
                &condition_aliases,
                &condition_bindings,
                candidate,
                value.range,
            );
            let dominance = derivation.any_guard_arm_dominates_result_uses(
                procedure,
                &condition_establishment_points,
                std::slice::from_ref(failure_edge),
                &[candidate.point],
            );
            if dominance.as_deref() == Some([GuardDominanceAnswer::ClosedNegative].as_slice()) {
                continue;
            }
            let confined = dominance.as_deref() == Some([GuardDominanceAnswer::Proven].as_slice());
            let closed = confined
                && globally_closed
                && origin.closed
                && candidate.consumer_classification_closed
                && candidate.consumer_identity_closed;
            let provenance = if closed {
                origin.provenance
            } else {
                crate::query::FailureUseProvenance::Unknown
            };
            saw_open_candidate |= !closed;
            if !filter.accepts(provenance, candidate.consumer) {
                continue;
            }
            let consumer_point_id = super::semantic::program_point_wire_id(
                &procedure
                    .point_handle(candidate.point)
                    .expect("a derived failure consumer belongs to its procedure"),
            );
            let id = result_contract_failure_use_row_id(
                &value.id,
                Some(&failure_edge_id),
                &consumer_point_id,
                candidate.consumer_call_id.as_deref(),
                candidate.consumer_site_id.as_deref(),
                candidate.operand,
                candidate.consumer,
                candidate.argument_ordinal,
            );
            expansions.push(pipeline_expansion(PipelineValue::ResultContractFailureUse(
                Box::new(ResultContractFailureUseValue {
                    file: value.file.clone(),
                    range: origin.range,
                    ast_id: origin.ast_id,
                    id,
                    acquisition_id: value.id.clone(),
                    acquisition_site_id: value.site_id.clone(),
                    acquisition_site_ast_id: value.site_ast_id.clone(),
                    procedure_id: procedure_id.clone(),
                    condition_result_ordinal,
                    condition_value_id: Some(u64::from(condition.value.get())),
                    failure_edge_id: Some(failure_edge_id.clone()),
                    consumer_point_id,
                    consumer_call_id: candidate.consumer_call_id.clone(),
                    consumer_site_id: candidate.consumer_site_id.clone(),
                    consumer_site_ast_id: candidate.consumer_site_ast_id.clone(),
                    operand_value_id: u64::from(candidate.operand.get()),
                    binding_value_id: origin.binding.map(|value| u64::from(value.get())),
                    establishment_point_id: origin.establishment_point_id,
                    establishment_value_id: origin
                        .establishment_value
                        .map(|value| u64::from(value.get())),
                    provenance,
                    consumer: candidate.consumer,
                    argument_ordinal: candidate.argument_ordinal,
                    proof: if closed {
                        EffectProof::Proven
                    } else {
                        EffectProof::Unproven
                    },
                    coverage: if closed {
                        EffectCoverage::Exhaustive
                    } else {
                        EffectCoverage::Open
                    },
                    pack_id: value.pack_id.clone(),
                    model_id: value.model_id.clone(),
                    summary_id: value.summary_id.clone(),
                }),
            )));
        }
    }
    if saw_open_candidate {
        record_result_contract_incomplete(
            cache,
            diagnostics,
            &value.file,
            EffectCoverage::Open,
            "failure-arm value provenance remained open",
        );
    }
    expansions
}

struct ResultContractSuccessGuards {
    edges: Vec<crate::analyzer::semantic::ControlEdgeHandle>,
    possible_edges: Vec<crate::analyzer::semantic::ControlEdgeHandle>,
    condition_candidate_success_edges: Vec<crate::analyzer::semantic::ControlEdgeHandle>,
    condition_failure_edges: Vec<crate::analyzer::semantic::ControlEdgeHandle>,
    condition_values: HashSet<crate::analyzer::semantic::ValueId>,
    condition_candidate_values: HashSet<crate::analyzer::semantic::ValueId>,
    subject_reads: Vec<(usize, crate::analyzer::semantic::ProgramPointId)>,
    subject_reads_exhaustive: bool,
    condition_discarded: bool,
    condition_identity_open: bool,
    condition_failure_coverage: EffectCoverage,
    result_identity_open: bool,
    has_result_success_edge: bool,
    coverage: EffectCoverage,
}

impl ResultContractSuccessGuards {
    fn unknown() -> Self {
        Self {
            edges: Vec::new(),
            possible_edges: Vec::new(),
            condition_candidate_success_edges: Vec::new(),
            condition_failure_edges: Vec::new(),
            condition_values: HashSet::default(),
            condition_candidate_values: HashSet::default(),
            subject_reads: Vec::new(),
            subject_reads_exhaustive: false,
            condition_discarded: false,
            condition_identity_open: true,
            condition_failure_coverage: EffectCoverage::Open,
            result_identity_open: true,
            has_result_success_edge: false,
            coverage: EffectCoverage::Open,
        }
    }
}

struct ResultSuccessGuardSubject {
    edges: Vec<crate::analyzer::semantic::ControlEdgeHandle>,
    possible_edges: Vec<crate::analyzer::semantic::ControlEdgeHandle>,
    candidate_edges: Vec<crate::analyzer::semantic::ControlEdgeHandle>,
    failure_edges: Vec<crate::analyzer::semantic::ControlEdgeHandle>,
    read_values: HashSet<crate::analyzer::semantic::ValueId>,
    candidate_read_values: HashSet<crate::analyzer::semantic::ValueId>,
    reads: Vec<(usize, crate::analyzer::semantic::ProgramPointId)>,
    reads_exhaustive: bool,
    discarded: bool,
    identity_open: bool,
    failure_identity_open: bool,
    withheld_positive_edge: bool,
}

#[allow(clippy::too_many_arguments)]
fn result_contract_success_guards(
    analyzer: &dyn IAnalyzer,
    workspace: &WorkspaceAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    model_cache: &mut EffectTraversalCache,
    flow_state_cache: &mut FlowStateTraversalCache,
    cancellation: Option<&CancellationToken>,
    file: &ProjectFile,
    range: Range,
    site_id: &str,
    site_ast_id: &str,
    modeled_target: Option<&ModeledProcedureKey>,
    contract: &CompiledResultContract,
) -> ResultContractSuccessGuards {
    let results = semantic.call_results_at_source(file, range, site_id, site_ast_id);
    let Some(result) = results
        .iter()
        .find(|result| result.ordinal == contract.result_ordinal as usize)
    else {
        return ResultContractSuccessGuards::unknown();
    };
    let condition = if let Some(condition_result_ordinal) = contract.condition_result_ordinal {
        let Some(condition) = results
            .iter()
            .find(|result| result.ordinal == condition_result_ordinal as usize)
        else {
            return ResultContractSuccessGuards::unknown();
        };
        Some(condition)
    } else {
        None
    };
    if condition.is_some_and(|condition| result.handle != condition.handle) {
        return ResultContractSuccessGuards::unknown();
    }

    let procedure = result.handle.procedure();
    let Some(materialized) = semantic.materialized_outcome(file) else {
        return ResultContractSuccessGuards::unknown();
    };
    let file_state = flow_state_cache.for_materialized_procedure(
        workspace,
        file,
        materialized,
        procedure,
        cancellation,
    );
    let Some(derivation) = file_state
        .procedures
        .iter()
        .find(|candidate| candidate.procedure == procedure.id())
    else {
        return ResultContractSuccessGuards::unknown();
    };
    let Some(result_use_index) =
        model_cache.result_use_index(semantic, file, procedure, derivation)
    else {
        return ResultContractSuccessGuards::unknown();
    };
    let semantic_model_overlay = modeled_target
        .filter(|target| target.language == "go")
        .and_then(|_| semantic.semantic_model_overlay());
    let exact_source = semantic_model_overlay
        .as_ref()
        .and_then(|_| model_cache.exact_source(analyzer, file));
    let assignment_conversion_proof_work = exact_source
        .as_deref()
        .and_then(crate::analyzer::go_modeled_result_binding_type_identity_proof_work);
    let assignment_conversion_proof = result_assignment_conversion_proof_context(
        analyzer,
        file,
        modeled_target,
        semantic_model_overlay.as_deref(),
        exact_source.as_deref(),
        &model_cache.exact_source_identities,
        &model_cache.result_assignment_conversion_proofs,
        assignment_conversion_proof_work,
    );
    result_contract_success_guards_for_values(
        semantic,
        procedure,
        derivation,
        &result_use_index,
        condition.map(|condition| condition.value),
        result.value,
        contract,
        None,
        assignment_conversion_proof,
    )
}

#[allow(clippy::too_many_arguments)]
fn result_contract_success_guards_for_values(
    semantic: &mut SemanticQueryContext<'_>,
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    derivation: &crate::structural::flow_state::FlowStateDerivation,
    result_use_index: &ResultUseIndex,
    condition: Option<crate::analyzer::semantic::ValueId>,
    result: crate::analyzer::semantic::ValueId,
    contract: &CompiledResultContract,
    required_predicate: Option<CompiledResultPredicate>,
    assignment_conversion_proof: Option<ResultAssignmentConversionProofContext<'_>>,
) -> ResultContractSuccessGuards {
    // Contract projection asks for acquisition-success guards. Operation-use
    // validation instead asks for the operation's own precondition. The
    // contract's condition arm can establish that precondition only when the
    // reviewed result correlation says it does; an independently authored
    // guard on the result itself is always evaluated against the required
    // predicate.
    let condition = condition
        .zip(contract.predicate)
        .filter(|_| {
            required_predicate
                .is_none_or(|predicate| contract.result_success_predicate == Some(predicate))
        })
        .map(|(condition, predicate)| {
            result_success_guard_subject(
                semantic,
                procedure,
                derivation,
                result_use_index,
                condition,
                contract
                    .condition_result_ordinal
                    .expect("a condition value has a condition result ordinal"),
                predicate,
                assignment_conversion_proof,
            )
        });
    let result_predicate = required_predicate.or(contract.result_success_predicate);
    let result = result_predicate.map(|predicate| {
        result_success_guard_subject(
            semantic,
            procedure,
            derivation,
            result_use_index,
            result,
            contract.result_ordinal,
            predicate,
            assignment_conversion_proof,
        )
    });
    let has_result_success_edge = result
        .as_ref()
        .is_some_and(|subject| !subject.edges.is_empty());
    let result_identity_open = result.as_ref().is_some_and(|subject| subject.identity_open);
    let condition_identity_open = condition
        .as_ref()
        .is_some_and(|subject| subject.identity_open);
    let condition_failure_coverage = if condition
        .as_ref()
        .map(|subject| subject.failure_identity_open)
        .unwrap_or(true)
    {
        EffectCoverage::Open
    } else {
        EffectCoverage::Exhaustive
    };
    let withheld_positive_edge = condition
        .as_ref()
        .is_some_and(|subject| subject.withheld_positive_edge)
        || result
            .as_ref()
            .is_some_and(|subject| subject.withheld_positive_edge);
    let mut subject_reads = condition
        .as_ref()
        .map(|subject| subject.reads.clone())
        .unwrap_or_default();
    let subject_reads_exhaustive = condition
        .as_ref()
        .is_none_or(|subject| subject.reads_exhaustive)
        && result
            .as_ref()
            .is_none_or(|subject| subject.reads_exhaustive);
    let condition_success_edges = condition
        .as_ref()
        .map(|subject| subject.edges.clone())
        .unwrap_or_default();
    let condition_candidate_success_edges = condition
        .as_ref()
        .map(|subject| subject.candidate_edges.clone())
        .unwrap_or_default();
    let mut possible_edges = condition
        .as_ref()
        .map(|subject| subject.possible_edges.clone())
        .unwrap_or_default();
    let mut edges = condition_success_edges.clone();
    if let Some(result) = result {
        subject_reads.extend(result.reads);
        edges.extend(result.edges);
        possible_edges.extend(result.possible_edges);
    }
    subject_reads.sort_unstable_by_key(|(event, _)| *event);
    subject_reads.dedup_by_key(|(event, _)| *event);
    edges.sort_unstable_by_key(|edge| edge.id());
    edges.dedup_by_key(|edge| edge.id());
    possible_edges.sort_unstable_by_key(|edge| edge.id());
    possible_edges.dedup_by_key(|edge| edge.id());
    ResultContractSuccessGuards {
        edges,
        possible_edges,
        condition_candidate_success_edges,
        condition_failure_edges: condition
            .as_ref()
            .map(|subject| subject.failure_edges.clone())
            .unwrap_or_default(),
        condition_values: condition
            .as_ref()
            .map(|subject| subject.read_values.clone())
            .unwrap_or_default(),
        condition_candidate_values: condition
            .as_ref()
            .map(|subject| subject.candidate_read_values.clone())
            .unwrap_or_default(),
        subject_reads,
        subject_reads_exhaustive,
        condition_discarded: condition.as_ref().is_some_and(|subject| subject.discarded),
        condition_identity_open,
        condition_failure_coverage,
        result_identity_open,
        has_result_success_edge,
        // Withholding an otherwise matched edge makes the positive relation
        // open. Identity uncertainty can also hide an unpositioned guard, so
        // an empty candidate set is exhaustive only when both subjects are
        // closed.
        coverage: if withheld_positive_edge || condition_identity_open || result_identity_open {
            EffectCoverage::Open
        } else {
            EffectCoverage::Exhaustive
        },
    }
}

struct ReadIdentityClosure {
    by_event: HashMap<usize, bool>,
    every_event_by_value: HashMap<crate::analyzer::semantic::ValueId, bool>,
}

fn read_identity_closure(
    reads: impl IntoIterator<Item = (usize, crate::analyzer::semantic::ValueId, bool)>,
) -> ReadIdentityClosure {
    let mut by_event = HashMap::default();
    let mut every_event_by_value = HashMap::default();
    for (event, value, closed) in reads {
        by_event
            .entry(event)
            .and_modify(|existing| *existing &= closed)
            .or_insert(closed);
        every_event_by_value
            .entry(value)
            .and_modify(|existing| *existing &= closed)
            .or_insert(closed);
    }
    ReadIdentityClosure {
        by_event,
        every_event_by_value,
    }
}

fn uses_before_every_guard_subject_read(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    derivation: &crate::structural::flow_state::FlowStateDerivation,
    result_establishments: &[crate::analyzer::semantic::ProgramPointId],
    ordering_points: &[Option<crate::analyzer::semantic::ProgramPointId>],
    own_subject_read_events: &[Option<usize>],
    subject_reads: &[(usize, crate::analyzer::semantic::ProgramPointId)],
    subject_reads_exhaustive: bool,
) -> Box<[bool]> {
    debug_assert_eq!(ordering_points.len(), own_subject_read_events.len());
    if !subject_reads_exhaustive || subject_reads.is_empty() {
        return vec![false; ordering_points.len()].into_boxed_slice();
    }

    ordering_points
        .iter()
        .zip(own_subject_read_events)
        .map(|(ordering_point, own_subject_read_event)| {
            let Some(ordering_point) = ordering_point else {
                return false;
            };
            // A success edge or a modeled normal-return refinement can only
            // follow a read of the contract's condition/result subject. If
            // this use strictly dominates every other exhaustively enumerated
            // subject-read point, even omitted guard facts cannot guard it.
            // A direct operation's receiver read is evaluation of that same
            // operation, not a possible guard. Exclude only its exact event:
            // another subject read at the same point remains a frontier.
            let mut later_reads = subject_reads
                .iter()
                .filter_map(|(event, point)| {
                    (Some(*event) != *own_subject_read_event).then_some(*point)
                })
                .collect::<Vec<_>>();
            later_reads.sort_unstable();
            later_reads.dedup();
            if later_reads.contains(ordering_point) {
                return false;
            }
            later_reads.is_empty()
                || derivation
                    .any_candidate_dominates_result_uses(
                        procedure,
                        result_establishments,
                        &[*ordering_point],
                        &later_reads,
                    )
                    .is_some_and(|answers| answers.iter().all(|answer| *answer))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn result_success_guard_subject(
    semantic: &mut SemanticQueryContext<'_>,
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    derivation: &crate::structural::flow_state::FlowStateDerivation,
    result_use_index: &ResultUseIndex,
    value: crate::analyzer::semantic::ValueId,
    result_ordinal: u32,
    predicate: CompiledResultPredicate,
    assignment_conversion_proof: Option<ResultAssignmentConversionProofContext<'_>>,
) -> ResultSuccessGuardSubject {
    let semantics = procedure.semantics();
    let mut establishments = derivation
        .events
        .iter()
        .filter(|event| event.event_class == StateEventClass::Establish && event.value == value)
        .map(|event| event.event)
        .collect::<Vec<_>>();
    let converted = result_use_index.exact_converted_establishments_from(
        semantic,
        procedure,
        derivation,
        value,
        result_ordinal,
        assignment_conversion_proof,
    );
    establishments.extend(converted.establishments.iter().copied());
    establishments.sort_unstable();
    establishments.dedup();
    if establishments.is_empty() {
        let assignment_incomplete = semantics.gaps().iter().any(|gap| {
            gap.subject == SemanticGapSubject::Value(value)
                && gap.capability == SemanticCapability::Assignments
                && gap.impacts.contains(SemanticGapImpact::ValueFlow)
        });
        let identity_open = assignment_incomplete || converted.proof_open;
        let candidate_aliases = converted.proof_open.then(|| {
            derivation.exact_local_value_alias_closure(
                procedure,
                &result_use_index.converted_establishments_from(value),
            )
        });
        let candidate_reads = candidate_aliases
            .iter()
            .flat_map(|aliases| aliases.reads.iter().chain(&aliases.uncertain_reads))
            .map(|event| derivation.event(*event))
            .collect::<Vec<_>>();
        let candidate_read_values = candidate_reads
            .iter()
            .map(|event| event.value)
            .collect::<HashSet<_>>();
        let mut reads = candidate_reads
            .iter()
            .map(|event| (event.event, event.point))
            .collect::<Vec<_>>();
        reads.sort_unstable_by_key(|(event, _)| *event);
        reads.dedup_by_key(|(event, _)| *event);
        let possible_edges = if converted.proof_open {
            normalized_success_guard_edges(procedure, &candidate_read_values, predicate)
        } else {
            Vec::new()
        };
        let withheld_positive_edge = !possible_edges.is_empty();
        return ResultSuccessGuardSubject {
            edges: Vec::new(),
            possible_edges,
            candidate_edges: Vec::new(),
            failure_edges: Vec::new(),
            read_values: HashSet::default(),
            candidate_read_values,
            reads,
            reads_exhaustive: !identity_open,
            // An explicitly discarded port is a complete positive-projection
            // answer with no activation edge. A lowering gap instead keeps
            // identity open for the exhaustive validation wrapper. A direct
            // Go assignment conversion likewise preserves data flow without
            // proving that the destination retains this result identity.
            discarded: !identity_open,
            identity_open,
            failure_identity_open: identity_open,
            withheld_positive_edge,
        };
    }
    let aliases = derivation.exact_local_value_alias_closure(procedure, &establishments);
    let reads = aliases
        .reads
        .iter()
        .map(|event| derivation.event(*event))
        .collect::<Vec<_>>();
    let uncertain_reads = aliases
        .uncertain_reads
        .iter()
        .map(|event| derivation.event(*event))
        .collect::<Vec<_>>();
    let converted_candidate_aliases = converted.proof_open.then(|| {
        derivation.exact_local_value_alias_closure(
            procedure,
            &result_use_index.converted_establishments_from(value),
        )
    });
    let converted_candidate_reads = converted_candidate_aliases
        .iter()
        .flat_map(|aliases| aliases.reads.iter().chain(&aliases.uncertain_reads))
        .map(|event| derivation.event(*event))
        .collect::<Vec<_>>();
    let establishment_points = aliases
        .establishments
        .iter()
        .map(|event| derivation.event(*event).point)
        .collect::<Vec<_>>();
    // Exact and may-reaching reads are all structured uncertainty frontiers.
    // An unclosed transfer can hide later uses of the value, but it cannot
    // hide a guard before the read that feeds that transfer. Retain the point
    // even when identity beyond it is open so an earlier operation can still
    // be proved to precede every possible success check.
    let mut subject_reads = reads
        .iter()
        .chain(&uncertain_reads)
        .chain(&converted_candidate_reads)
        .map(|event| (event.event, event.point))
        .collect::<Vec<_>>();
    subject_reads.sort_unstable_by_key(|(event, _)| *event);
    subject_reads.dedup_by_key(|(event, _)| *event);
    let read_values = reads
        .iter()
        .map(|event| event.value)
        .collect::<HashSet<_>>();
    let read_identity = read_identity_closure(reads.iter().map(|read| {
        (
            read.event,
            read.value,
            derivation.exact_local_alias_read_identity_is_closed(procedure, &aliases, read.event),
        )
    }));
    let closed_read_values = read_identity
        .every_event_by_value
        .iter()
        .filter_map(|(value, closed)| closed.then_some(*value))
        .collect::<HashSet<_>>();
    let binding_subjects = aliases
        .establishments
        .iter()
        .map(|event| derivation.event(*event).subject.value())
        .collect::<HashSet<_>>();
    let mut relevant_values = binding_subjects;
    relevant_values.insert(value);
    relevant_values.extend(
        aliases
            .establishments
            .iter()
            .map(|event| derivation.event(*event).value),
    );
    relevant_values.extend(read_values.iter().copied());
    let relevant_value_list = relevant_values.iter().copied().collect::<Vec<_>>();
    let uncertain_read_values = uncertain_reads
        .iter()
        .chain(&converted_candidate_reads)
        .map(|event| event.value)
        .collect::<HashSet<_>>();
    let uncertain_edges =
        normalized_success_guard_edges(procedure, &uncertain_read_values, predicate);
    let mut edges = normalized_success_guard_edges(procedure, &read_values, predicate);
    let mut possible_edges = edges.clone();
    possible_edges.extend(uncertain_edges.iter().cloned());
    possible_edges.sort_unstable_by_key(|edge| edge.id());
    possible_edges.dedup_by_key(|edge| edge.id());
    let retained_edge_count = edges.len();
    // Publishing a positive result guard requires result identity to survive
    // the arm. Candidate confinement is a negative question: it needs the
    // exact authored edge for a closed condition read, then applies its own
    // per-use control-gap proof. Keep that edge before the global result-
    // identity filter so a later gap cannot erase the question itself.
    let candidate_edges = normalized_success_guard_edges(procedure, &closed_read_values, predicate);
    let closed_edges = candidate_edges
        .iter()
        .map(|edge| edge.id())
        .collect::<HashSet<_>>();
    edges.retain(|edge| closed_edges.contains(&edge.id()));
    let binding_identity_open = edges.len() != retained_edge_count;
    let identity_retained_edge_count = edges.len();
    edges.retain(|edge| {
        derivation.guard_arm_preserves_result_identity(
            procedure,
            &establishment_points,
            &relevant_value_list,
            edge,
        )
    });
    let control_identity_open = edges.len() != identity_retained_edge_count;
    let withheld_positive_edge = !uncertain_edges.is_empty()
        || ((binding_identity_open || control_identity_open) && retained_edge_count != 0);
    let failure_predicate = opposite_result_predicate(predicate);
    let failure_edges =
        normalized_success_guard_edges(procedure, &closed_read_values, failure_predicate);
    ResultSuccessGuardSubject {
        edges,
        possible_edges,
        candidate_edges,
        failure_edges,
        read_values: closed_read_values,
        candidate_read_values: read_values
            .iter()
            .copied()
            .chain(uncertain_read_values.iter().copied())
            .collect(),
        reads: subject_reads,
        // Candidate-scoped uncertainty is localized at the retained read
        // points above. Only a closure-wide proof gap leaves an unpositioned
        // read that ordering cannot reason about.
        reads_exhaustive: !aliases.proof_open && !converted.proof_open,
        discarded: false,
        identity_open: aliases.proof_open
            || converted.proof_open
            || !aliases.uncertain_reads.is_empty()
            || !aliases.uncertain_transfers.is_empty()
            || !aliases.unclosed_transfers.is_empty()
            || binding_identity_open
            || control_identity_open
            || !uncertain_edges.is_empty(),
        // Preserving the subject's identity after the authored guard matters
        // to positive result-use validation, but not to identifying which
        // opposite-predicate edge enters the failure arm.
        failure_identity_open: aliases.proof_open
            || converted.proof_open
            || !aliases.uncertain_reads.is_empty()
            || !aliases.uncertain_transfers.is_empty()
            || !aliases.unclosed_transfers.is_empty()
            || binding_identity_open
            || !uncertain_edges.is_empty(),
        withheld_positive_edge,
    }
}

struct ResultContractUseValidation {
    use_count: usize,
    unguarded_use_count: Option<usize>,
    status: &'static str,
    coverage: EffectCoverage,
    uses: Vec<ValidatedResultUse>,
}

#[derive(Debug, Clone)]
struct ValidatedResultUse {
    observed: ObservedResultUse,
    guard: ResultUseGuardVerdict,
    coverage: EffectCoverage,
}

impl ResultContractUseValidation {
    fn known(use_count: usize, unguarded_use_count: usize) -> Self {
        Self {
            use_count,
            unguarded_use_count: Some(unguarded_use_count),
            status: if use_count == 0 {
                "unused"
            } else if unguarded_use_count == 0 {
                "satisfied"
            } else {
                "violated"
            },
            coverage: EffectCoverage::Exhaustive,
            uses: Vec::new(),
        }
    }

    fn unknown(use_count: usize) -> Self {
        Self {
            use_count,
            unguarded_use_count: None,
            status: "unknown",
            coverage: EffectCoverage::Open,
            uses: Vec::new(),
        }
    }

    fn violated_open(use_count: usize, unguarded_use_count: usize) -> Self {
        debug_assert_ne!(unguarded_use_count, 0);
        debug_assert!(unguarded_use_count <= use_count);
        Self {
            use_count,
            unguarded_use_count: Some(unguarded_use_count),
            status: "violated",
            coverage: EffectCoverage::Open,
            uses: Vec::new(),
        }
    }
}

fn attach_observed_result_uses(
    mut validation: ResultContractUseValidation,
    observed: &[ObservedResultUse],
    required_uses: &[RequiredObservedResultUse],
    required_verdicts: &[ResultUseGuardVerdict],
) -> ResultContractUseValidation {
    debug_assert_eq!(required_uses.len(), required_verdicts.len());
    let verdict_by_index = required_uses
        .iter()
        .zip(required_verdicts)
        .map(|(required, verdict)| (required.observed_index, *verdict))
        .collect::<HashMap<_, _>>();
    validation.uses = observed
        .iter()
        .enumerate()
        .map(|(index, observed)| {
            let guard = match observed.applicability {
                OperationApplicability::Required => verdict_by_index
                    .get(&index)
                    .copied()
                    .unwrap_or(ResultUseGuardVerdict::Unknown),
                OperationApplicability::NotRequired => ResultUseGuardVerdict::NotApplicable,
                OperationApplicability::Unknown => ResultUseGuardVerdict::Unknown,
            };
            let coverage = if observed.applicability == OperationApplicability::Unknown
                || guard == ResultUseGuardVerdict::Unknown
                || (observed.identity_open
                    && observed.applicability == OperationApplicability::Required)
            {
                EffectCoverage::Open
            } else {
                EffectCoverage::Exhaustive
            };
            ValidatedResultUse {
                observed: observed.clone(),
                guard,
                coverage,
            }
        })
        .collect();
    // Preserve the aggregate relation's established meaning: this count is
    // every exact structured operation observed on the protected result, not
    // only the subset whose reviewed precondition requires a success guard.
    // The unguarded count remains the lower bound over required operations.
    validation.use_count = validation.uses.len();
    let unresolved_finding = validation.uses.iter().any(|result_use| {
        result_use.observed.applicability == OperationApplicability::Unknown
            || (result_use.observed.applicability == OperationApplicability::Required
                && result_use.guard == ResultUseGuardVerdict::Unknown)
    });
    if validation
        .uses
        .iter()
        .any(|result_use| result_use.coverage != EffectCoverage::Exhaustive)
    {
        validation.coverage = validation.coverage.meet(EffectCoverage::Open);
    }
    if unresolved_finding && validation.unguarded_use_count == Some(0) {
        validation.unguarded_use_count = None;
        validation.status = "unknown";
    } else if validation.coverage == EffectCoverage::Exhaustive
        && validation.unguarded_use_count == Some(0)
    {
        validation.status = if validation.uses.is_empty() {
            "unused"
        } else {
            "satisfied"
        };
    }
    validation
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OperationUseClassification {
    applicability: OperationApplicability,
    required_predicate: Option<CompiledResultPredicate>,
}

fn exact_go_unknown_selector_dual(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    call: &crate::analyzer::semantic::SemanticCallSite,
) -> bool {
    if call.declared_targets != CallableTargetResolution::Unknown {
        return false;
    }
    let Some(receiver) = call.receiver else {
        return false;
    };
    let Some(point) = semantics.point(call.point) else {
        return false;
    };
    let mut function = false;
    let mut bound_method = false;
    let mut alternatives = 0usize;
    for event in &point.events {
        let callable = match &event.effect {
            SemanticEffect::CallableReference { result, callable }
            | SemanticEffect::CallableCreation { result, callable }
                if *result == call.callee =>
            {
                callable
            }
            _ => continue,
        };
        alternatives = alternatives.saturating_add(1);
        if callable.targets != CallableTargetResolution::Unknown || callable.environment.is_some() {
            return false;
        }
        match (callable.kind, callable.bound_receiver) {
            (CallableReferenceKind::Function, None) if !function => function = true,
            (CallableReferenceKind::BoundMethod, Some(bound))
                if bound == receiver && !bound_method =>
            {
                bound_method = true;
            }
            _ => return false,
        }
    }
    alternatives == 2 && function && bound_method
}

fn classify_result_member_operation(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    shape: Option<&crate::analyzer::usages::call_shape::CallShapeReport>,
    call: &crate::analyzer::semantic::SemanticCallSite,
    member_contracts: &[CompiledResultMemberContract],
) -> OperationUseClassification {
    let unknown = OperationUseClassification {
        applicability: OperationApplicability::Unknown,
        required_predicate: None,
    };
    let Some(shape) = shape else {
        return unknown;
    };
    let Some(receiver) = call.receiver else {
        return unknown;
    };
    let receiver_binding_is_exact = matches!(
        semantics.proven_caller_receiver_binding(call.id),
        Some(CallerReceiverBinding::Bound(bound)) if bound == receiver
    ) || exact_go_unknown_selector_dual(semantics, call);
    if !receiver_binding_is_exact {
        return unknown;
    }
    if shape.outcome.coverage != CallShapeCoverage::Exact
        || shape.outcome.call_kind != CallKind::Method
        || shape.outcome.receiver_range.is_none()
        || shape
            .arguments
            .iter()
            .any(|argument| argument.name.is_some() || argument.spread)
        || call.arguments.iter().any(|argument| {
            !matches!(
                argument.expansion,
                CallArgumentExpansion::Direct(ArgumentDomain::Positional)
            )
        })
    {
        return unknown;
    }
    let [group] = shape.groups.as_slice() else {
        return unknown;
    };
    if group.kind != ArgumentListKind::Ordinary
        || group.argument_count != shape.arguments.len()
        || call.arguments.len() != shape.arguments.len()
    {
        return unknown;
    }
    let Some(member) = shape.outcome.callee_name.as_deref() else {
        return unknown;
    };
    let matching = member_contracts
        .iter()
        .filter(|contract| {
            contract.member == member
                && usize::try_from(contract.parameter_count).ok() == Some(shape.arguments.len())
        })
        .collect::<Vec<_>>();
    let [contract] = matching.as_slice() else {
        return unknown;
    };
    if contract.completeness != Completeness::Complete {
        return unknown;
    }
    let Some(preconditions) = contract.preconditions.as_ref() else {
        return unknown;
    };
    if preconditions.is_empty() {
        return OperationUseClassification {
            applicability: OperationApplicability::NotRequired,
            required_predicate: None,
        };
    }
    let receiver_preconditions = preconditions
        .iter()
        .filter(|precondition| matches!(&precondition.input, CompiledSummaryInput::Receiver {}))
        .collect::<Vec<_>>();
    let [receiver] = receiver_preconditions.as_slice() else {
        // Parameter-only operation requirements are not requirements on this
        // protected receiver. This first consumer intentionally stays open
        // until RQL has a typed parameter-use binding surface.
        return unknown;
    };
    if receiver.predicate != CompiledResultPredicate::NonNull {
        return unknown;
    }
    OperationUseClassification {
        applicability: OperationApplicability::Required,
        required_predicate: Some(receiver.predicate),
    }
}

fn exact_positional_call_argument<'a>(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    shape: Option<&'a crate::analyzer::usages::call_shape::CallShapeReport>,
    call: &crate::analyzer::semantic::SemanticCallSite,
    indexed: &IndexedCallArgumentUse,
) -> Option<&'a crate::analyzer::usages::call_shape::ArgumentRow> {
    let shape = shape?;
    if indexed.call != call.id
        || !indexed.range_exact
        || !indexed.expansion_exact
        || shape.outcome.coverage != CallShapeCoverage::Exact
        || exact_semantic_call_range(semantics, call) != Some(shape.outcome.range)
        || shape
            .arguments
            .iter()
            .any(|argument| argument.name.is_some() || argument.spread)
        || call.arguments.iter().any(|argument| {
            !matches!(
                argument.expansion,
                CallArgumentExpansion::Direct(ArgumentDomain::Positional)
            )
        })
    {
        return None;
    }
    let [group] = shape.groups.as_slice() else {
        return None;
    };
    if group.kind != ArgumentListKind::Ordinary
        || group.argument_count != shape.arguments.len()
        || call.arguments.len() != shape.arguments.len()
    {
        return None;
    }
    let argument = structured_call_argument(Some(shape), indexed)?;
    let semantic_range = indexed.semantic_range?;
    if semantic_range != argument.range
        && !(semantics.locator().language()
            == crate::analyzer::LanguageDialect::Standard(crate::analyzer::Language::Go)
            && argument.range.contains(&semantic_range))
    {
        return None;
    }
    Some(argument)
}

fn structured_call_argument<'a>(
    shape: Option<&'a crate::analyzer::usages::call_shape::CallShapeReport>,
    indexed: &IndexedCallArgumentUse,
) -> Option<&'a crate::analyzer::usages::call_shape::ArgumentRow> {
    let shape = shape?;
    let ordinal = usize::try_from(indexed.argument_ordinal).ok()?;
    let argument = shape.arguments.get(ordinal)?;
    (argument.argument_index == ordinal).then_some(argument)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CallArgumentOperationClassification {
    operation: OperationUseClassification,
    parameter_count: Option<u32>,
    parameter_ordinal: Option<u32>,
}

impl CallArgumentOperationClassification {
    const fn unknown() -> Self {
        Self {
            operation: OperationUseClassification {
                applicability: OperationApplicability::Unknown,
                required_predicate: None,
            },
            parameter_count: None,
            parameter_ordinal: None,
        }
    }

    const fn unknown_at(parameter_count: u32, parameter_ordinal: u32) -> Self {
        Self {
            operation: OperationUseClassification {
                applicability: OperationApplicability::Unknown,
                required_predicate: None,
            },
            parameter_count: Some(parameter_count),
            parameter_ordinal: Some(parameter_ordinal),
        }
    }
}

/// Map one written positional argument to a formal parameter only after both
/// structural target resolution and semantic callable evaluation agree on the
/// receiver application. In particular, a Go method expression writes its
/// receiver as argument zero; `ReceiverBindingUnknown` must not let that value
/// inherit formal parameter zero's precondition.
fn exact_call_argument_parameter(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    shape: &crate::analyzer::usages::call_shape::CallShapeReport,
    call: &crate::analyzer::semantic::SemanticCallSite,
    indexed: &IndexedCallArgumentUse,
    answer: &ModeledCallTargetLookup,
) -> Option<(u32, u32)> {
    let receiver_application_exact = match answer.call_application {
        ModeledCallApplication::PackageFunction => {
            call.receiver.is_none()
                && semantics.proven_caller_receiver_binding(call.id)
                    == Some(CallerReceiverBinding::Absent)
                && answer.arms.iter().all(|arm| !arm.key.has_receiver)
        }
        ModeledCallApplication::BoundReceiver => {
            let receiver = call.receiver?;
            shape.outcome.call_kind == CallKind::Method
                && shape.outcome.receiver_range.is_some()
                && (semantics.proven_caller_receiver_binding(call.id)
                    == Some(CallerReceiverBinding::Bound(receiver))
                    || exact_go_unknown_selector_dual(semantics, call))
                && answer.arms.iter().all(|arm| arm.key.has_receiver)
        }
        ModeledCallApplication::ReceiverBindingUnknown | ModeledCallApplication::Unknown => false,
    };
    if !receiver_application_exact {
        return None;
    }

    let parameter_count = answer.arms.first()?.key.parameter_count;
    if !answer
        .arms
        .iter()
        .all(|arm| arm.key.parameter_count == parameter_count)
        || indexed.argument_ordinal >= parameter_count
    {
        return None;
    }
    Some((parameter_count, indexed.argument_ordinal))
}

fn classify_call_argument_operation(
    analyzer: &dyn IAnalyzer,
    cache: &mut EffectTraversalCache,
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    shape: Option<&crate::analyzer::usages::call_shape::CallShapeReport>,
    call: &crate::analyzer::semantic::SemanticCallSite,
    indexed: &IndexedCallArgumentUse,
) -> CallArgumentOperationClassification {
    let unknown = CallArgumentOperationClassification::unknown();
    let Some(shape) = shape else {
        return unknown;
    };
    if exact_positional_call_argument(semantics, Some(shape), call, indexed).is_none() {
        return unknown;
    }
    let Some(answer) = cache
        .modeled_call_targets
        .as_ref()
        .filter(|window| window.file == shape.outcome.file)
        .and_then(|window| window.lookups.get(&shape.outcome.site_id))
        .cloned()
    else {
        return unknown;
    };
    let Some((parameter_count, parameter_ordinal)) =
        exact_call_argument_parameter(semantics, shape, call, indexed, &answer)
    else {
        return unknown;
    };
    let unknown =
        CallArgumentOperationClassification::unknown_at(parameter_count, parameter_ordinal);
    if answer.coverage != ModeledCallTargetCoverage::Exhaustive
        || !answer.adjudicable_workspace_names.is_empty()
        || answer.arms.is_empty()
    {
        return unknown;
    }

    let mut common = None;
    for arm in &answer.arms {
        let preconditions = match cache.answer_for(analyzer, &arm.key) {
            ModelAnswer::Modeled {
                complete: true,
                preconditions: Some(preconditions),
                ..
            } => preconditions,
            ModelAnswer::Modeled { .. } | ModelAnswer::Conflict | ModelAnswer::Empty => {
                return unknown;
            }
        };
        let matching = preconditions
            .iter()
            .filter(|precondition| {
                matches!(
                    &precondition.input,
                    CompiledSummaryInput::Parameter { ordinal }
                        if *ordinal == parameter_ordinal
                )
            })
            .collect::<Vec<_>>();
        let classification = match matching.as_slice() {
            [] => OperationUseClassification {
                applicability: OperationApplicability::NotRequired,
                required_predicate: None,
            },
            [precondition] if precondition.predicate == CompiledResultPredicate::NonNull => {
                OperationUseClassification {
                    applicability: OperationApplicability::Required,
                    required_predicate: Some(precondition.predicate),
                }
            }
            // Result-use guard validation currently derives the protected
            // result's successful non-null frontier. A reviewed null
            // precondition agrees at dispatch, but proving its opposite-arm
            // guard requires a predicate-specific validation group. Keep that
            // operation open instead of labeling a non-null success guard as
            // satisfying a null entry requirement.
            [_] => return unknown,
            _ => return unknown,
        };
        match common {
            None => common = Some(classification),
            Some(common) if common == classification => {}
            Some(_) => return unknown,
        }
    }
    CallArgumentOperationClassification {
        operation: common.expect("one exhaustive modeled target was classified"),
        parameter_count: Some(parameter_count),
        parameter_ordinal: Some(parameter_ordinal),
    }
}

#[derive(Debug, Clone)]
struct ObservedResultUse {
    file: ProjectFile,
    range: Range,
    ast_id: Option<String>,
    /// Point at which the operation's reviewed precondition must hold.
    guard_point: crate::analyzer::semantic::ProgramPointId,
    /// Exact semantic value on which this operation imposes its precondition.
    subject_value: crate::analyzer::semantic::ValueId,
    /// Conservative witness from which this operation must occur before any
    /// later guard frontier. An exact zero-argument receiver read qualifies
    /// because no intervening user expression can establish the predicate.
    /// Calls with arguments stay open because an argument can do so.
    ordering_point: Option<crate::analyzer::semantic::ProgramPointId>,
    /// Exact semantic invocation for a receiver call. Program points are not
    /// call identities: more than one call may be lowered at one point.
    target_call: Option<crate::analyzer::semantic::CallSiteId>,
    /// Exact result-subject read performed while evaluating this same direct
    /// operation. It cannot be a guard for the operation, but every other
    /// subject read remains a possible guard frontier.
    own_subject_read_event: Option<usize>,
    point_id: Box<str>,
    operation_site_id: Option<String>,
    operation_site_ast_id: Option<String>,
    use_kind: ResultContractUseKind,
    timing: ResultContractUseTiming,
    applicability: OperationApplicability,
    required_predicate: Option<CompiledResultPredicate>,
    member: Option<String>,
    parameter_count: Option<u32>,
    parameter_ordinal: Option<u32>,
    identity_open: bool,
}

#[derive(Debug, Clone, Copy)]
struct RequiredObservedResultUse {
    observed_index: usize,
    guard_point: crate::analyzer::semantic::ProgramPointId,
    ordering_point: Option<crate::analyzer::semantic::ProgramPointId>,
    target_call: Option<crate::analyzer::semantic::CallSiteId>,
    identity_open: bool,
    own_subject_read_event: Option<usize>,
}

fn unique_exact_intrinsic_subject_read<'a>(
    value: crate::analyzer::semantic::ValueId,
    reads: &[(&'a crate::structural::flow_state::StateEventRow, bool)],
    non_excludable_events: &HashSet<usize>,
) -> Option<&'a crate::structural::flow_state::StateEventRow> {
    let mut matching = reads
        .iter()
        .filter(|(read, _)| read.value == value)
        .map(|(read, _)| *read);
    let read = matching.next()?;
    if matching.next().is_some() || non_excludable_events.contains(&read.event) {
        return None;
    }
    Some(read)
}

#[derive(Clone, Copy)]
struct IntrinsicClassificationContext<'a> {
    modeled_target: Option<&'a ModeledProcedureKey>,
    result_ordinal: u32,
    semantic_model_overlay: Option<&'a SemanticModelOverlay>,
    exact_source: Option<&'a str>,
}

/// Whether positive declaration facts prove that this grammar-backed field
/// selection dereferences the pointer returned at the exact acquisition.
/// Missing or conflicting facts stay open because declaration packs may be
/// partial; a value-struct result also stays open because field access on it
/// does not carry the fallback non-null precondition.
fn modeled_pointer_result_field(
    intrinsic: &IndexedIntrinsicUse,
    file: &ProjectFile,
    context: IntrinsicClassificationContext<'_>,
) -> bool {
    if intrinsic.kind != ResultContractUseKind::Field {
        return false;
    }
    let Some(target) = context
        .modeled_target
        .filter(|target| target.language == "go")
    else {
        return false;
    };
    let Some(member) = intrinsic.member.as_ref().filter(|member| {
        member.language()
            == crate::analyzer::LanguageDialect::Standard(crate::analyzer::Language::Go)
            && member.path().as_path() == file.rel_path()
    }) else {
        return false;
    };
    let Some(source) = context.exact_source else {
        return false;
    };
    let span = member.anchor().span();
    let Some(field) = source.get(span.start_byte() as usize..span.end_byte() as usize) else {
        return false;
    };
    if field.is_empty() {
        return false;
    }
    crate::analyzer::modeled_go_callable_result_pointer_field(
        context.semantic_model_overlay,
        &target.owner,
        &target.member,
        target.has_receiver,
        target.parameter_count as usize,
        context.result_ordinal as usize,
        field,
    )
}

fn intrinsic_result_uses_for_reads(
    index: &ResultUseIndex,
    reads: &[(&crate::structural::flow_state::StateEventRow, bool)],
    non_excludable_events: &HashSet<usize>,
    timing: ResultContractUseTiming,
    classification: IntrinsicClassificationContext<'_>,
) -> Vec<ObservedResultUse> {
    let mut values = Vec::new();
    let mut seen_values = HashSet::default();
    for (read, _) in reads {
        if seen_values.insert(read.value) {
            values.push(read.value);
        }
    }

    let mut observed = Vec::new();
    for value in values {
        let candidates = reads
            .iter()
            .filter(|(read, _)| read.value == value)
            .collect::<Vec<_>>();
        for intrinsic in index.intrinsic_uses.get(&value).into_iter().flatten() {
            let fallback = *candidates[0];
            let classification_open = intrinsic.classification_open
                && !modeled_pointer_result_field(intrinsic, &fallback.0.site.file, classification);
            // The exact base ValueId is shared by the lexical operand read
            // and this intrinsic operation. Their program points deliberately
            // differ: Go evaluates the operand before the field load or
            // dereference. Join by that structured value identity, while
            // retaining ambiguity and candidate-local uncertainty as open.
            let own_subject_read_event =
                unique_exact_intrinsic_subject_read(value, reads, non_excludable_events)
                    .map(|read| read.event);
            observed.push(ObservedResultUse {
                file: fallback.0.site.file.clone(),
                range: intrinsic.range,
                ast_id: None,
                guard_point: intrinsic.point,
                subject_value: value,
                ordering_point: Some(intrinsic.point),
                target_call: None,
                own_subject_read_event,
                point_id: intrinsic.point_id.clone(),
                operation_site_id: None,
                operation_site_ast_id: None,
                use_kind: intrinsic.kind,
                timing,
                applicability: if classification_open {
                    OperationApplicability::Unknown
                } else {
                    OperationApplicability::Required
                },
                // Dereference, field, and index operations require a non-null
                // operand. `result_success_predicate` describes acquisition
                // correlation; it is not the operation's precondition and can
                // legitimately be `null` for a different API contract.
                required_predicate: (!classification_open)
                    .then_some(CompiledResultPredicate::NonNull),
                member: None,
                parameter_count: None,
                parameter_ordinal: None,
                identity_open: candidates.iter().any(|candidate| candidate.1)
                    || !intrinsic.source_exact
                    || own_subject_read_event.is_none(),
            });
        }
    }
    observed
}

fn exact_result_member_call_shape<'a>(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    call: &crate::analyzer::semantic::SemanticCallSite,
    call_shapes_by_range: Option<&'a ResultMemberCallShapesByRange>,
) -> Option<&'a crate::analyzer::usages::call_shape::CallShapeReport> {
    exact_semantic_call_range(semantics, call)
        .and_then(|range| call_shapes_by_range?.get(&range).and_then(Option::as_ref))
}

fn unique_exact_receiver_read<'a>(
    receiver: crate::analyzer::semantic::ValueId,
    file: &ProjectFile,
    receiver_range: Range,
    reads: &[&'a crate::structural::flow_state::StateEventRow],
) -> Option<&'a crate::structural::flow_state::StateEventRow> {
    let mut matching = reads.iter().copied().filter(|read| {
        read.value == receiver && &read.site.file == file && read.site.range == receiver_range
    });
    let read = matching.next()?;
    matching.next().is_none().then_some(read)
}

fn exact_result_member_receiver_read<'a>(
    call: &crate::analyzer::semantic::SemanticCallSite,
    shape: Option<&crate::analyzer::usages::call_shape::CallShapeReport>,
    reads: &[&'a crate::structural::flow_state::StateEventRow],
) -> Option<&'a crate::structural::flow_state::StateEventRow> {
    let shape = shape?;
    if shape.outcome.coverage != CallShapeCoverage::Exact
        || shape.outcome.call_kind != CallKind::Method
        || call.receiver.is_none()
    {
        return None;
    }
    unique_exact_receiver_read(
        call.receiver?,
        &shape.outcome.file,
        shape.outcome.receiver_range?,
        reads,
    )
}

fn result_member_use_for_call(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    call: &crate::analyzer::semantic::SemanticCallSite,
    call_shapes_by_range: Option<&ResultMemberCallShapesByRange>,
    member_contracts: &[CompiledResultMemberContract],
    fallback_site: &crate::structural::flow_state::StateEventSite,
    timing: ResultContractUseTiming,
    identity_open: bool,
) -> ObservedResultUse {
    let semantics = procedure.semantics();
    let exact_call_range = exact_semantic_call_range(semantics, call);
    let shape = exact_result_member_call_shape(semantics, call, call_shapes_by_range);
    let classification = classify_result_member_operation(semantics, shape, call, member_contracts);
    ObservedResultUse {
        file: fallback_site.file.clone(),
        range: shape.map_or_else(
            || exact_call_range.unwrap_or(fallback_site.range),
            |shape| shape.outcome.range,
        ),
        ast_id: match (shape, exact_call_range) {
            (Some(shape), _) => Some(shape.outcome.site_ast_id.clone()),
            (None, Some(_)) => None,
            (None, None) => fallback_site.ast_id.clone(),
        },
        guard_point: call.point,
        subject_value: call
            .receiver
            .expect("receiver result uses retain an exact semantic receiver"),
        ordering_point: Some(call.point),
        target_call: Some(call.id),
        own_subject_read_event: None,
        point_id: super::semantic::program_point_wire_id(
            &procedure
                .point_handle(call.point)
                .expect("validated procedure owns its semantic call point"),
        )
        .into(),
        operation_site_id: shape.map(|shape| shape.outcome.site_id.clone()),
        operation_site_ast_id: shape.map(|shape| shape.outcome.site_ast_id.clone()),
        use_kind: ResultContractUseKind::ReceiverCall,
        timing,
        applicability: classification.applicability,
        required_predicate: classification.required_predicate,
        member: shape.and_then(|shape| shape.outcome.callee_name.clone()),
        parameter_count: shape.and_then(|shape| u32::try_from(shape.arguments.len()).ok()),
        parameter_ordinal: None,
        identity_open,
    }
}

fn exact_result_call_argument_read<'a>(
    value: crate::analyzer::semantic::ValueId,
    file: &ProjectFile,
    range: Range,
    reads: &[&'a crate::structural::flow_state::StateEventRow],
) -> Option<&'a crate::structural::flow_state::StateEventRow> {
    let mut matching = reads
        .iter()
        .copied()
        .filter(|read| read.value == value && &read.site.file == file && read.site.range == range);
    let read = matching.next()?;
    matching.next().is_none().then_some(read)
}

#[allow(clippy::too_many_arguments)]
fn result_call_argument_use_for_call(
    analyzer: &dyn IAnalyzer,
    cache: &mut EffectTraversalCache,
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    call: &crate::analyzer::semantic::SemanticCallSite,
    indexed: &IndexedCallArgumentUse,
    call_shapes_by_range: Option<&ResultMemberCallShapesByRange>,
    fallback_site: &crate::structural::flow_state::StateEventSite,
    exact_read: Option<&crate::structural::flow_state::StateEventRow>,
    timing: ResultContractUseTiming,
    identity_open: bool,
) -> ObservedResultUse {
    let semantics = procedure.semantics();
    let shape = exact_result_member_call_shape(semantics, call, call_shapes_by_range);
    let structural_argument = structured_call_argument(shape, indexed);
    let classification =
        classify_call_argument_operation(analyzer, cache, semantics, shape, call, indexed);
    debug_assert_eq!(
        classification.operation.applicability == OperationApplicability::Required,
        classification.operation.required_predicate.is_some()
    );
    ObservedResultUse {
        file: shape.map_or_else(
            || fallback_site.file.clone(),
            |shape| shape.outcome.file.clone(),
        ),
        range: structural_argument.map_or(indexed.range, |argument| argument.range),
        ast_id: None,
        guard_point: call.point,
        subject_value: call.arguments[indexed.argument_ordinal as usize].value,
        ordering_point: exact_read.map(|read| read.point),
        target_call: Some(call.id),
        own_subject_read_event: exact_read.map(|read| read.event),
        point_id: super::semantic::program_point_wire_id(
            &procedure
                .point_handle(call.point)
                .expect("validated procedure owns its semantic call point"),
        )
        .into(),
        operation_site_id: shape.map(|shape| shape.outcome.site_id.clone()),
        operation_site_ast_id: shape.map(|shape| shape.outcome.site_ast_id.clone()),
        use_kind: ResultContractUseKind::CallArgument,
        timing,
        applicability: classification.operation.applicability,
        required_predicate: classification.operation.required_predicate,
        member: shape.and_then(|shape| shape.outcome.callee_name.clone()),
        parameter_count: classification.parameter_count,
        parameter_ordinal: classification.parameter_ordinal,
        identity_open,
    }
}

fn captured_callable_invocation_enumeration_is_open(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    callable: crate::analyzer::semantic::ValueId,
    target: crate::analyzer::semantic::ProcedureId,
) -> bool {
    let mut aliases = std::iter::once(callable).collect::<HashSet<_>>();
    loop {
        let mut changed = false;
        for point in semantics.points() {
            for event in &point.events {
                let (source, target) = match event.effect {
                    SemanticEffect::Assignment { target, value } => (value, target),
                    SemanticEffect::ValueFlow { source, target, .. } => (source, target),
                    _ => continue,
                };
                if aliases.contains(&source) {
                    changed |= aliases.insert(target);
                }
            }
        }
        if !changed {
            break;
        }
    }

    for call in semantics.call_sites() {
        let exact_target = matches!(
            &call.declared_targets,
            CallableTargetResolution::Proven(CallableTarget::Local(candidate))
                if *candidate == target
        );
        let may_target_callable = call
            .declared_targets
            .candidates()
            .iter()
            .any(|candidate| matches!(candidate, CallableTarget::Local(candidate) if *candidate == target));
        if (may_target_callable && !exact_target)
            || (aliases.contains(&call.callee) && !exact_target)
            || call.receiver.is_some_and(|value| aliases.contains(&value))
            || call
                .arguments
                .iter()
                .any(|argument| aliases.contains(&argument.value))
        {
            return true;
        }
    }

    if semantics.gaps().iter().any(|gap| {
        gap.impacts.contains(SemanticGapImpact::ValueFlow)
            && matches!(gap.subject, SemanticGapSubject::Value(value) if aliases.contains(&value))
    }) {
        return true;
    }

    semantics.points().iter().any(|point| {
        point.events.iter().any(|event| match event.effect {
            SemanticEffect::MemoryStore { value, .. } | SemanticEffect::ValueUse { value, .. } => {
                aliases.contains(&value)
            }
            SemanticEffect::ProcedureReturn { value } | SemanticEffect::Throw { value } => {
                value.is_some_and(|value| aliases.contains(&value))
            }
            SemanticEffect::AsyncSuspend { awaited, .. } => {
                awaited.is_some_and(|value| aliases.contains(&value))
            }
            SemanticEffect::CaptureBind { capture } => {
                semantics
                    .capture(capture)
                    .is_some_and(|capture| match capture.captured {
                        CaptureSource::Value(value) => aliases.contains(&value),
                        CaptureSource::Location(_) => false,
                    })
            }
            _ => false,
        })
    })
}

fn capture_observes_result_binding(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    captured: CaptureSource,
    mode: &CaptureMode,
    binding_subjects: &HashSet<crate::analyzer::semantic::ValueId>,
    storage_locations: &HashSet<crate::analyzer::semantic::MemoryLocationId>,
) -> bool {
    match captured {
        CaptureSource::Value(value) => {
            matches!(mode, CaptureMode::Value | CaptureMode::Move)
                && binding_subjects.contains(&value)
        }
        CaptureSource::Location(location) => {
            matches!(mode, CaptureMode::SharedCell | CaptureMode::MutableCell)
                && (storage_locations.contains(&location)
                    || semantics.memory_location(location).is_some_and(|location| {
                        binding_subjects
                            .iter()
                            .any(|subject| location.kind.uses_value(*subject))
                    }))
        }
    }
}

fn normalized_success_guard_edges(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    condition_read_values: &HashSet<crate::analyzer::semantic::ValueId>,
    predicate: CompiledResultPredicate,
) -> Vec<crate::analyzer::semantic::ControlEdgeHandle> {
    let mut edges = procedure
        .semantics()
        .guard_facts()
        .iter()
        .filter(|guard| {
            guard
                .subject
                .is_some_and(|value| condition_read_values.contains(&value))
        })
        .filter_map(|guard| {
            let take_true = match (predicate, guard.predicate) {
                (
                    CompiledResultPredicate::Null,
                    GuardPredicate::NullComparison { null_on_true },
                ) => null_on_true,
                (
                    CompiledResultPredicate::NonNull,
                    GuardPredicate::NullComparison { null_on_true },
                ) => !null_on_true,
                // An opaque predicate whose subject is the condition value is
                // still an exact direct Boolean decision: the typed control
                // edges retain which successor observes true and false. More
                // complex expressions name their own temporary value and do
                // not join the reviewed result identity above.
                (CompiledResultPredicate::True, GuardPredicate::Opaque { .. }) => true,
                (CompiledResultPredicate::False, GuardPredicate::Opaque { .. }) => false,
                (
                    CompiledResultPredicate::Null
                    | CompiledResultPredicate::NonNull
                    | CompiledResultPredicate::True
                    | CompiledResultPredicate::False,
                    GuardPredicate::ConstantBoolean { .. }
                    | GuardPredicate::ConstantEquality { .. }
                    | GuardPredicate::InstanceOf { .. }
                    | GuardPredicate::HasMember { .. }
                    | GuardPredicate::NullComparison { .. }
                    | GuardPredicate::Opaque { .. },
                ) => return None,
            };
            let edge = if take_true {
                guard.true_edge
            } else {
                guard.false_edge
            }?;
            procedure.control_edge_handle(edge)
        })
        .collect::<Vec<_>>();
    edges.sort_unstable_by_key(|edge| edge.id());
    edges.dedup_by_key(|edge| edge.id());
    edges
}

const fn opposite_result_predicate(predicate: CompiledResultPredicate) -> CompiledResultPredicate {
    match predicate {
        CompiledResultPredicate::Null => CompiledResultPredicate::NonNull,
        CompiledResultPredicate::NonNull => CompiledResultPredicate::Null,
        CompiledResultPredicate::True => CompiledResultPredicate::False,
        CompiledResultPredicate::False => CompiledResultPredicate::True,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConditionalProcedureSummaryAnswer {
    Complete(Vec<CompiledConditionalResultRefinement>),
    Open,
}

#[derive(Debug, Clone)]
enum ConditionalGuardArmEvidence {
    Positive(crate::analyzer::semantic::ControlEdgeHandle),
    ClosedNegative(crate::analyzer::semantic::ControlEdgeHandle),
    Open,
}

#[derive(Debug, Clone)]
enum ConditionalResultConsumption {
    DirectGuard {
        true_edge: crate::analyzer::semantic::ControlEdgeHandle,
        false_edge: crate::analyzer::semantic::ControlEdgeHandle,
    },
    ProvenDiscard,
    DetachedOnly {
        consumers: Box<[crate::analyzer::semantic::CallSiteId]>,
    },
    Open,
}

#[derive(Debug, Clone)]
struct ConditionalPredicateCall {
    call: crate::analyzer::semantic::CallSiteId,
    read_point: crate::analyzer::semantic::ProgramPointId,
    // Whether the modeled condition result cannot control each reviewed use.
    // A discarded result closes every use. A result consumed only by detached
    // work closes only those uses reached through the parent's exact linear
    // continuation before any control or synchronization boundary.
    caller_control_irrelevant_for_uses: Box<[bool]>,
    positive_edges: Box<[crate::analyzer::semantic::ControlEdgeHandle]>,
    closed_negative_for_uses: Box<[bool]>,
    success_arm_confines_for_uses: Box<[bool]>,
    failure_arm_confines_for_uses: Box<[bool]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConditionalPredicateUseAnswer {
    Positive,
    ClosedNegative,
    Irrelevant,
    Open,
}

fn semantic_call_range(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    call: &crate::analyzer::semantic::SemanticCallSite,
) -> Option<Range> {
    let mapping = semantics.source_mapping(call.source)?;
    let span = mapping.locator.anchor().span();
    Some(Range {
        start_byte: span.start_byte() as usize,
        end_byte: span.end_byte() as usize,
        start_line: span.start().line() as usize + 1,
        end_line: span.end().line() as usize + 1,
    })
}

fn exact_semantic_call_range(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    call: &crate::analyzer::semantic::SemanticCallSite,
) -> Option<Range> {
    let mapping = semantics.source_mapping(call.source)?;
    if mapping.kind != crate::analyzer::semantic::SourceMappingKind::Exact {
        return None;
    }
    semantic_call_range(semantics, call)
}

fn direct_conditional_summary(
    analyzer: &dyn IAnalyzer,
    cache: &mut EffectTraversalCache,
    key: &ModeledProcedureKey,
) -> ConditionalProcedureSummaryAnswer {
    match cache.answer_for(analyzer, key) {
        ModelAnswer::Modeled {
            complete: true,
            covers_overrides,
            conditional_result_refinements,
            ..
        } if covers_overrides || !key.has_receiver => {
            ConditionalProcedureSummaryAnswer::Complete(conditional_result_refinements)
        }
        ModelAnswer::Modeled { .. } | ModelAnswer::Conflict | ModelAnswer::Empty => {
            ConditionalProcedureSummaryAnswer::Open
        }
    }
}

fn common_conditional_refinements(
    common: &mut Vec<CompiledConditionalResultRefinement>,
    candidate: &[CompiledConditionalResultRefinement],
) {
    common.retain(|refinement| candidate.contains(refinement));
}

struct ExactConditionalWrapper {
    call: crate::analyzer::semantic::CallSiteId,
    inner_parameter_to_outer_parameter: Vec<u32>,
}

fn exact_conditional_wrapper_shape(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
) -> Option<ExactConditionalWrapper> {
    let semantics = procedure.semantics();
    let [call] = semantics.call_sites() else {
        return None;
    };
    if call.receiver.is_some()
        || call.normal_continuation.target().is_none()
        || call.exceptional_continuation.target().is_none()
        || !call.normal_results.is_empty()
        || call.result.is_none()
        || !semantics.guard_facts().is_empty()
        || !semantics.captures().is_empty()
        || !semantics.allocations().is_empty()
    {
        return None;
    }

    let mut parameters = semantics
        .values()
        .iter()
        .filter_map(|value| match &value.kind {
            SemanticValueKind::Parameter {
                ordinal,
                multiplicity,
                ..
            } if *multiplicity == crate::analyzer::semantic::FormalMultiplicity::One => {
                Some((*ordinal, value.id))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if semantics.values().iter().any(|value| {
        matches!(
            &value.kind,
            SemanticValueKind::Parameter {
                multiplicity: crate::analyzer::semantic::FormalMultiplicity::Rest(_),
                ..
            } | SemanticValueKind::Receiver { .. }
        )
    }) {
        return None;
    }
    parameters.sort_unstable_by_key(|(ordinal, _)| *ordinal);
    if parameters.len() != call.arguments.len()
        || parameters
            .iter()
            .enumerate()
            .any(|(index, (ordinal, _))| *ordinal as usize != index)
    {
        return None;
    }
    let parameter_by_value = parameters
        .iter()
        .map(|(ordinal, value)| (*value, *ordinal))
        .collect::<HashMap<_, _>>();
    let parameter_flows = semantics
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .filter_map(|event| match event.effect {
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Parameter,
                source,
                target,
            } => Some((source, target)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut inner_parameter_to_outer_parameter = Vec::with_capacity(call.arguments.len());
    let mut used_outer_parameters = HashSet::default();
    let mut used_parameter_flows = HashSet::default();
    for argument in &call.arguments {
        if !matches!(
            argument.expansion,
            CallArgumentExpansion::Direct(ArgumentDomain::Positional)
        ) {
            return None;
        }
        let direct_outer = parameter_by_value.get(&argument.value).copied();
        let flowed_outer = parameter_flows
            .iter()
            .filter(|(_, target)| *target == argument.value)
            .filter_map(|(source, target)| {
                parameter_by_value
                    .get(source)
                    .copied()
                    .map(|outer| (outer, (*source, *target)))
            })
            .collect::<Vec<_>>();
        let (outer, flow) = match (direct_outer, flowed_outer.as_slice()) {
            (Some(outer), []) => (outer, None),
            (None, [(outer, flow)]) => (*outer, Some(*flow)),
            _ => return None,
        };
        if !used_outer_parameters.insert(outer) {
            return None;
        }
        if let Some(flow) = flow {
            used_parameter_flows.insert(flow);
        }
        inner_parameter_to_outer_parameter.push(outer);
    }
    if used_outer_parameters.len() != parameters.len()
        || used_parameter_flows.len() != parameter_flows.len()
    {
        return None;
    }

    let returns = semantics
        .points()
        .iter()
        .flat_map(|point| {
            point
                .events
                .iter()
                .filter_map(move |event| match event.effect {
                    SemanticEffect::ProcedureReturn { value } => Some((point.id, value)),
                    _ => None,
                })
        })
        .collect::<Vec<_>>();
    let [(return_point, Some(return_value))] = returns.as_slice() else {
        return None;
    };
    let return_flows = semantics
        .points()
        .iter()
        .flat_map(|point| {
            point
                .events
                .iter()
                .filter_map(move |event| match event.effect {
                    SemanticEffect::ValueFlow {
                        kind,
                        source,
                        target,
                    } if matches!(
                        kind,
                        ValueFlowKind::Return | ValueFlowKind::IndexedReturn { .. }
                    ) =>
                    {
                        Some((point.id, kind, source, target))
                    }
                    _ => None,
                })
        })
        .collect::<Vec<_>>();
    let [(flow_point, ValueFlowKind::Return, source, target)] = return_flows.as_slice() else {
        return None;
    };
    if flow_point != return_point
        || *source != call.result?
        || target != return_value
        || !exact_tail_normal_path(semantics, call, *return_point)
    {
        return None;
    }

    let allowed_gaps = semantics
        .gaps()
        .iter()
        .filter(|gap| {
            (gap.capability == SemanticCapability::CallableReferences
                && gap.subject == SemanticGapSubject::Value(call.callee))
                || (gap.capability == SemanticCapability::Calls
                    && gap.subject == SemanticGapSubject::CallSite(call.id))
        })
        .map(|gap| gap.id)
        .collect::<HashSet<_>>();
    if allowed_gaps.len() != semantics.gaps().len() {
        return None;
    }
    let pure = semantics
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .all(|event| match &event.effect {
            SemanticEffect::Entry
            | SemanticEffect::NormalExit
            | SemanticEffect::ExceptionalExit => true,
            SemanticEffect::CallableReference { result, callable } => {
                *result == call.callee && callable.bound_receiver.is_none()
            }
            SemanticEffect::Invoke { call_site }
            | SemanticEffect::CallContinuation { call_site, .. } => *call_site == call.id,
            SemanticEffect::MemoryLoad {
                kind: MemoryAccessKind::Field,
                result,
                ..
            } => *result == call.callee,
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Return,
                source,
                target,
            } => {
                *source == call.result.expect("wrapper has one result") && *target == *return_value
            }
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Parameter,
                source,
                target,
            } => used_parameter_flows.contains(&(*source, *target)),
            SemanticEffect::ProcedureReturn { value } => *value == Some(*return_value),
            SemanticEffect::Gap { gap } => allowed_gaps.contains(gap),
            SemanticEffect::Assignment { .. }
            | SemanticEffect::ValueFlow { .. }
            | SemanticEffect::ValueUse { .. }
            | SemanticEffect::Allocation { .. }
            | SemanticEffect::MemoryLoad { .. }
            | SemanticEffect::MemoryStore { .. }
            | SemanticEffect::Synchronization { .. }
            | SemanticEffect::CallableCreation { .. }
            | SemanticEffect::CaptureBind { .. }
            | SemanticEffect::Throw { .. }
            | SemanticEffect::AsyncSuspend { .. }
            | SemanticEffect::AsyncResume { .. } => false,
        });
    if !pure
        || semantics.control_edges().iter().any(|edge| {
            !matches!(
                edge.kind,
                crate::analyzer::semantic::ControlEdgeKind::Normal
                    | crate::analyzer::semantic::ControlEdgeKind::Exceptional
            )
        })
    {
        return None;
    }

    Some(ExactConditionalWrapper {
        call: call.id,
        inner_parameter_to_outer_parameter,
    })
}

fn exact_tail_normal_path(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    call: &crate::analyzer::semantic::SemanticCallSite,
    return_point: crate::analyzer::semantic::ProgramPointId,
) -> bool {
    let Some(normal_point) = call.normal_continuation.target() else {
        return false;
    };
    if normal_point == return_point {
        return true;
    }
    let Some(point) = semantics.point(normal_point) else {
        return false;
    };
    let [event] = point.events.as_ref() else {
        return false;
    };
    if !matches!(
        event.effect,
        SemanticEffect::CallContinuation {
            call_site,
            kind: crate::analyzer::semantic::CallContinuationKind::Normal,
        } if call_site == call.id
    ) {
        return false;
    }
    let successors = semantics.successor_edges(normal_point).collect::<Vec<_>>();
    matches!(
        successors.as_slice(),
        [(_, edge)]
            if edge.kind == crate::analyzer::semantic::ControlEdgeKind::Normal
                && edge.target_point == return_point
    )
}

fn map_conditional_wrapper_refinements(
    refinements: Vec<CompiledConditionalResultRefinement>,
    wrapper: &ExactConditionalWrapper,
) -> Option<Vec<CompiledConditionalResultRefinement>> {
    let mut mapped = refinements
        .into_iter()
        .map(|refinement| {
            if refinement.result_ordinal != 0 {
                return None;
            }
            Some(CompiledConditionalResultRefinement {
                result_ordinal: 0,
                outcome: refinement.outcome,
                parameter_ordinal: *wrapper
                    .inner_parameter_to_outer_parameter
                    .get(refinement.parameter_ordinal as usize)?,
                predicate: refinement.predicate,
                proof_effect: refinement.proof_effect,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    mapped.sort();
    mapped.dedup();
    Some(mapped)
}

fn conditional_summary_for_workspace_procedure(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    unit: &CodeUnit,
    depth: usize,
) -> ConditionalProcedureSummaryAnswer {
    if let Some(answer) = cache.conditional_wrapper_answers.get(unit) {
        return answer.clone();
    }
    if depth >= MAX_CONDITIONAL_WRAPPER_DEPTH
        || !cache.conditional_wrapper_visiting.insert(unit.clone())
    {
        return ConditionalProcedureSummaryAnswer::Open;
    }
    let answer = (|| {
        let range = analyzer
            .ranges_of(unit)
            .into_iter()
            .min_by_key(primary_range_key)?;
        let declaration = DeclarationValue::new(unit.clone(), range);
        let procedure = semantic.unique_procedure_of_declaration(&declaration)?;
        let semantics = procedure.semantics();
        let traversal_steps = semantics
            .values()
            .len()
            .saturating_add(semantics.allocations().len())
            .saturating_add(semantics.memory_locations().len())
            .saturating_add(semantics.captures().len())
            .saturating_add(semantics.call_sites().len())
            .saturating_add(semantics.source_mappings().len())
            .saturating_add(semantics.gaps().len())
            .saturating_add(semantics.control_edges().len())
            .saturating_add(semantics.guard_facts().len())
            .saturating_add(semantics.points().len())
            .saturating_add(
                semantics
                    .points()
                    .iter()
                    .map(|point| point.events.len())
                    .sum::<usize>(),
            );
        if !semantic.charge_consumer_traversal(
            unit.source(),
            traversal_steps,
            "conditional wrapper composition",
        ) {
            return None;
        }
        let wrapper = exact_conditional_wrapper_shape(&procedure)?;
        let call = procedure.semantics().call_site(wrapper.call)?;
        let range = exact_semantic_call_range(procedure.semantics(), call)?;
        let inner = conditional_summary_for_call(
            analyzer,
            semantic,
            cache,
            unit.source(),
            range,
            depth.saturating_add(1),
        );
        let ConditionalProcedureSummaryAnswer::Complete(refinements) = inner else {
            return None;
        };
        map_conditional_wrapper_refinements(refinements, &wrapper)
            .map(ConditionalProcedureSummaryAnswer::Complete)
    })()
    .unwrap_or(ConditionalProcedureSummaryAnswer::Open);
    cache.conditional_wrapper_visiting.remove(unit);
    cache
        .conditional_wrapper_answers
        .insert(unit.clone(), answer.clone());
    answer
}

fn conditional_summary_for_call(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    file: &ProjectFile,
    range: Range,
    depth: usize,
) -> ConditionalProcedureSummaryAnswer {
    let answer = cache.dispatch_at_source(semantic, file, range);
    if answer.arms.is_empty()
        || matches!(
            answer.outcome,
            "ambiguous" | "cancelled" | "exceeded_budget" | "unsupported" | "unproven"
        )
    {
        return ConditionalProcedureSummaryAnswer::Open;
    }

    let mut common = None::<Vec<CompiledConditionalResultRefinement>>;
    let mut every_arm_closes_residual = true;
    for arm in &answer.arms {
        if arm.proof != "proven" {
            return ConditionalProcedureSummaryAnswer::Open;
        }
        let (arm_answer, closes_residual) = match &arm.target_unit {
            Some(unit) => {
                if arm.completeness != "complete" {
                    return ConditionalProcedureSummaryAnswer::Open;
                }
                (
                    match cache
                        .key_for(analyzer, unit)
                        .map(|key| cache.answer_for(analyzer, &key))
                    {
                        Some(ModelAnswer::Modeled {
                            complete: true,
                            conditional_result_refinements,
                            ..
                        }) => ConditionalProcedureSummaryAnswer::Complete(
                            conditional_result_refinements,
                        ),
                        Some(ModelAnswer::Empty) | None => {
                            conditional_summary_for_workspace_procedure(
                                analyzer, semantic, cache, unit, depth,
                            )
                        }
                        Some(ModelAnswer::Modeled { .. } | ModelAnswer::Conflict) => {
                            ConditionalProcedureSummaryAnswer::Open
                        }
                    },
                    false,
                )
            }
            None => {
                let Some(key) = arm.unmaterialized_target.as_ref().map(external_modeled_key) else {
                    return ConditionalProcedureSummaryAnswer::Open;
                };
                let answer = direct_conditional_summary(analyzer, cache, &key);
                let closes_residual = !key.has_receiver
                    && matches!(&answer, ConditionalProcedureSummaryAnswer::Complete(_));
                (answer, closes_residual)
            }
        };
        let ConditionalProcedureSummaryAnswer::Complete(refinements) = arm_answer else {
            return ConditionalProcedureSummaryAnswer::Open;
        };
        every_arm_closes_residual &= closes_residual;
        match &mut common {
            None => common = Some(refinements),
            Some(common) => common_conditional_refinements(common, &refinements),
        }
    }

    let exhaustive = answer.coverage == crate::analyzer::semantic::CandidateCoverage::Exhaustive
        || (answer.coverage == crate::analyzer::semantic::CandidateCoverage::Open
            && match answer.unnamed_boundaries.as_slice() {
                [] => true,
                ["unresolved"] => every_arm_closes_residual,
                _ => false,
            });
    if exhaustive {
        ConditionalProcedureSummaryAnswer::Complete(common.unwrap_or_default())
    } else {
        ConditionalProcedureSummaryAnswer::Open
    }
}

fn direct_opaque_guard_edges(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    result: crate::analyzer::semantic::ValueId,
) -> Option<(
    crate::analyzer::semantic::ControlEdgeHandle,
    crate::analyzer::semantic::ControlEdgeHandle,
)> {
    let guards = procedure
        .semantics()
        .guard_facts()
        .iter()
        .filter(|guard| guard.subject == Some(result))
        .filter(|guard| matches!(guard.predicate, GuardPredicate::Opaque { .. }))
        .collect::<Vec<_>>();
    let [guard] = guards.as_slice() else {
        return None;
    };
    let true_edge = procedure.control_edge_handle(guard.true_edge?)?;
    let false_edge = procedure.control_edge_handle(guard.false_edge?)?;
    Some((true_edge, false_edge))
}

fn conditional_result_consumption(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    derivation: &crate::structural::flow_state::FlowStateDerivation,
    call: &crate::analyzer::semantic::SemanticCallSite,
    result: crate::analyzer::semantic::ValueId,
) -> ConditionalResultConsumption {
    if let Some((true_edge, false_edge)) = direct_opaque_guard_edges(procedure, result) {
        return ConditionalResultConsumption::DirectGuard {
            true_edge,
            false_edge,
        };
    }

    let Some(_origin) = call.normal_continuation.target() else {
        return ConditionalResultConsumption::Open;
    };
    if !derivation.result_observation_account_is_available(procedure) {
        return ConditionalResultConsumption::Open;
    }

    let semantics = procedure.semantics();
    let Some(result_span) = semantics
        .value(result)
        .and_then(|value| semantics.source_mapping(value.source))
        .map(|mapping| mapping.locator.anchor().span())
    else {
        return ConditionalResultConsumption::Open;
    };
    let gap_encloses_result = |gap: &crate::analyzer::semantic::SemanticGap| {
        semantics.source_mapping(gap.source).is_none_or(|mapping| {
            let gap_span = mapping.locator.anchor().span();
            gap_span.start_byte() <= result_span.start_byte()
                && gap_span.end_byte() >= result_span.end_byte()
        })
    };
    let call_consumers = semantics
        .call_sites()
        .iter()
        .filter(|candidate| {
            candidate.callee == result
                || candidate.receiver == Some(result)
                || candidate
                    .arguments
                    .iter()
                    .any(|argument| argument.value == result)
        })
        .collect::<Vec<_>>();
    let guard_consumes = semantics
        .guard_facts()
        .iter()
        .any(|guard| guard.subject == Some(result));
    let capture_consumes = semantics.captures().iter().any(|capture| {
        capture.callable == result
            || match capture.captured {
                CaptureSource::Value(value) => value == result,
                CaptureSource::Location(location) => semantics
                    .memory_location(location)
                    .is_some_and(|location| location.kind.uses_value(result)),
            }
    });
    let effect_consumes = semantics.points().iter().any(|point| {
        point.events.iter().any(|event| match &event.effect {
            SemanticEffect::Assignment { value, .. }
            | SemanticEffect::ValueFlow { source: value, .. }
            | SemanticEffect::ValueUse { value, .. } => *value == result,
            SemanticEffect::MemoryStore {
                location, value, ..
            } => {
                *value == result
                    || semantics
                        .memory_location(*location)
                        .is_some_and(|location| location.kind.uses_value(result))
            }
            SemanticEffect::MemoryLoad { location, .. } => semantics
                .memory_location(*location)
                .is_some_and(|location| location.kind.uses_value(result)),
            SemanticEffect::Synchronization { subject, .. } => *subject == result,
            SemanticEffect::CallableCreation { callable, .. }
            | SemanticEffect::CallableReference { callable, .. } => {
                callable.bound_receiver == Some(result)
            }
            SemanticEffect::ProcedureReturn { value } | SemanticEffect::Throw { value } => {
                *value == Some(result)
            }
            SemanticEffect::AsyncSuspend { awaited, .. } => *awaited == Some(result),
            SemanticEffect::Entry
            | SemanticEffect::NormalExit
            | SemanticEffect::ExceptionalExit
            | SemanticEffect::Allocation { .. }
            | SemanticEffect::CaptureBind { .. }
            | SemanticEffect::Invoke { .. }
            | SemanticEffect::CallContinuation { .. }
            | SemanticEffect::AsyncResume { .. }
            | SemanticEffect::Gap { .. } => false,
        })
    });
    let gap_consumes = semantics.gaps().iter().any(|gap| {
        if !gap.impacts.contains(SemanticGapImpact::ValueFlow)
            || matches!(
                gap.discharge,
                SemanticGapDischarge::RetainedEvaluationOrder
                    | SemanticGapDischarge::RetainedControlTopology
                    | SemanticGapDischarge::NonRejoiningExceptionalExit
            )
        {
            return false;
        }
        match gap.subject {
            SemanticGapSubject::Value(value) => value == result,
            SemanticGapSubject::MemoryLocation(location) => semantics
                .memory_location(location)
                .is_some_and(|location| location.kind.uses_value(result)),
            SemanticGapSubject::Capture(capture) => {
                semantics
                    .capture(capture)
                    .is_some_and(|capture| match capture.captured {
                        CaptureSource::Value(value) => value == result,
                        CaptureSource::Location(location) => semantics
                            .memory_location(location)
                            .is_some_and(|location| location.kind.uses_value(result)),
                    })
            }
            // An unscoped gap can hide consumption of this ephemeral result
            // only inside the same structured source evaluation. A later
            // unrelated statement cannot recover an unbound value. Requiring
            // the exact result span to be nested in the gap keeps unsupported
            // parent expressions open without letting a later capture or
            // spawn contaminate an already-discarded boolean.
            SemanticGapSubject::Procedure | SemanticGapSubject::Point => gap_encloses_result(gap),
            SemanticGapSubject::CallSite(_)
            | SemanticGapSubject::CallContinuation { .. }
            | SemanticGapSubject::AsyncContinuation { .. } => false,
        }
    });
    if call_consumers
        .iter()
        .any(|consumer| consumer.invocation_mode == CallInvocationMode::Ordinary)
        || guard_consumes
        || capture_consumes
        || effect_consumes
        || gap_consumes
    {
        ConditionalResultConsumption::Open
    } else if !call_consumers.is_empty() {
        ConditionalResultConsumption::DetachedOnly {
            consumers: call_consumers
                .into_iter()
                .map(|consumer| consumer.id)
                .collect(),
        }
    } else {
        ConditionalResultConsumption::ProvenDiscard
    }
}

fn detached_consumers_are_irrelevant_for_uses(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    derivation: &crate::structural::flow_state::FlowStateDerivation,
    result_establishments: &[crate::analyzer::semantic::ProgramPointId],
    consumers: &[crate::analyzer::semantic::CallSiteId],
    use_points: &[Option<crate::analyzer::semantic::ProgramPointId>],
) -> Box<[bool]> {
    let mut consumers = consumers.to_vec();
    consumers.sort_unstable();
    consumers.dedup();
    let Some(handles) = consumers
        .iter()
        .copied()
        .map(|consumer| procedure.call_site_handle(consumer))
        .collect::<Option<Vec<_>>>()
    else {
        return vec![false; use_points.len()].into_boxed_slice();
    };
    let present = use_points
        .iter()
        .enumerate()
        .filter_map(|(index, point)| point.map(|point| (index, point)))
        .collect::<Vec<_>>();
    let points = present.iter().map(|(_, point)| *point).collect::<Vec<_>>();
    let Some(reached) = derivation.detached_consumers_cannot_gate_result_uses(
        procedure,
        result_establishments,
        &handles,
        &points,
    ) else {
        return vec![false; use_points.len()].into_boxed_slice();
    };
    let mut answers = vec![false; use_points.len()];
    for ((index, _), reached) in present.into_iter().zip(reached) {
        answers[index] = reached;
    }
    answers.into_boxed_slice()
}

fn conditional_guard_arm(
    call: &crate::analyzer::semantic::SemanticCallSite,
    refinements: &[CompiledConditionalResultRefinement],
    result_consumptions: &HashMap<crate::analyzer::semantic::ValueId, ConditionalResultConsumption>,
    exact_condition_values: &HashSet<crate::analyzer::semantic::ValueId>,
    predicate: CompiledResultPredicate,
    outcome: bool,
) -> ConditionalGuardArmEvidence {
    let applicable = refinements
        .iter()
        .filter(|refinement| refinement.outcome == outcome && refinement.predicate == predicate)
        .filter(|refinement| {
            call.arguments
                .get(refinement.parameter_ordinal as usize)
                .is_some_and(|argument| {
                    matches!(
                        argument.expansion,
                        CallArgumentExpansion::Direct(ArgumentDomain::Positional)
                    ) && exact_condition_values.contains(&argument.value)
                })
        })
        .collect::<Vec<_>>();
    let [refinement] = applicable.as_slice() else {
        return ConditionalGuardArmEvidence::Open;
    };
    let Some(result) = call.normal_result(refinement.result_ordinal as usize) else {
        return ConditionalGuardArmEvidence::Open;
    };
    let Some(ConditionalResultConsumption::DirectGuard {
        true_edge,
        false_edge,
    }) = result_consumptions.get(&result)
    else {
        return ConditionalGuardArmEvidence::Open;
    };
    let edge = if outcome {
        true_edge.clone()
    } else {
        false_edge.clone()
    };
    match refinement.proof_effect {
        CompiledPredicateProofEffect::Establishes => ConditionalGuardArmEvidence::Positive(edge),
        CompiledPredicateProofEffect::DoesNotEstablish => {
            ConditionalGuardArmEvidence::ClosedNegative(edge)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn conditional_predicate_calls(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    file: &ProjectFile,
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    derivation: &crate::structural::flow_state::FlowStateDerivation,
    result_establishments: &[crate::analyzer::semantic::ProgramPointId],
    use_points: &[crate::analyzer::semantic::ProgramPointId],
    use_ordering_points: &[Option<crate::analyzer::semantic::ProgramPointId>],
    condition_candidate_success_edges: &[crate::analyzer::semantic::ControlEdgeHandle],
    condition_failure_edges: &[crate::analyzer::semantic::ControlEdgeHandle],
    normal_return_calls: &[CallSiteHandle],
    candidate_condition_values: &HashSet<crate::analyzer::semantic::ValueId>,
    modelable_condition_values: &HashSet<crate::analyzer::semantic::ValueId>,
    predicate: CompiledResultPredicate,
) -> Vec<ConditionalPredicateCall> {
    let semantics = procedure.semantics();
    let mut candidates = Vec::new();
    // Raw exact reads enumerate every call that could validate the condition,
    // including void or otherwise unmodeled consumers. Only the independently
    // identity-closed subset can bind an authored refinement. This keeps an
    // address escape or another open consumer visible without globally
    // disqualifying a separate exact modeled call.
    for call in semantics.call_sites() {
        if !call
            .arguments
            .iter()
            .any(|argument| candidate_condition_values.contains(&argument.value))
        {
            continue;
        }
        let exact_condition_argument = call.arguments.iter().any(|argument| {
            matches!(
                argument.expansion,
                CallArgumentExpansion::Direct(ArgumentDomain::Positional)
            ) && candidate_condition_values.contains(&argument.value)
        });
        let exact_modelable_condition_argument = call.arguments.iter().any(|argument| {
            matches!(
                argument.expansion,
                CallArgumentExpansion::Direct(ArgumentDomain::Positional)
            ) && modelable_condition_values.contains(&argument.value)
        });
        // Detached completion cannot itself gate the parent, but the child may
        // communicate back through shared state. Close only uses reached by the
        // parent's exact linear continuation before any control or
        // synchronization boundary; every other use remains an open candidate.
        if call.invocation_mode != CallInvocationMode::Ordinary {
            candidates.push(ConditionalPredicateCall {
                call: call.id,
                read_point: call.point,
                caller_control_irrelevant_for_uses: detached_consumers_are_irrelevant_for_uses(
                    procedure,
                    derivation,
                    result_establishments,
                    &[call.id],
                    use_ordering_points,
                ),
                positive_edges: Box::new([]),
                closed_negative_for_uses: vec![false; use_points.len()].into_boxed_slice(),
                success_arm_confines_for_uses: vec![false; use_points.len()].into_boxed_slice(),
                failure_arm_confines_for_uses: vec![false; use_points.len()].into_boxed_slice(),
            });
            continue;
        }
        // An unmodeled consumer reached only through the contract's exact
        // failure arm cannot make that already-failing arm a success proof.
        // A consumer confined to the success arm is already redundant and
        // cannot validate a separate failure path after the arms rejoin.
        // Keep authored conditional and normal-return positives separate;
        // either can still satisfy a later use through its own control edge.
        let modeled_normal_return = normal_return_calls
            .iter()
            .any(|candidate| candidate.id() == call.id);
        let arm_confinement_for_uses =
            |edges: &[crate::analyzer::semantic::ControlEdgeHandle]| {
                if !exact_modelable_condition_argument || edges.is_empty() {
                    return vec![false; use_points.len()].into_boxed_slice();
                }
                derivation
                    .any_guard_arm_confines_candidate_for_result_uses(
                        procedure,
                        result_establishments,
                        edges,
                        call.point,
                        use_points,
                    )
                    .unwrap_or_else(|| vec![false; use_points.len()].into_boxed_slice())
            };
        let success_arm_confines_for_uses =
            arm_confinement_for_uses(condition_candidate_success_edges);
        // A modeled normal-return refinement on this exact call may combine
        // with the bypassing success arm even when neither continuation alone
        // dominates a joined use. We do not prove collective vertex cuts, so
        // keep that candidate open rather than failure-closing it.
        let failure_arm_confines_for_uses = if modeled_normal_return {
            vec![false; use_points.len()].into_boxed_slice()
        } else {
            arm_confinement_for_uses(condition_failure_edges)
        };
        let Some(range) = exact_semantic_call_range(semantics, call) else {
            candidates.push(ConditionalPredicateCall {
                call: call.id,
                read_point: call.point,
                caller_control_irrelevant_for_uses: vec![false; use_points.len()]
                    .into_boxed_slice(),
                positive_edges: Box::new([]),
                closed_negative_for_uses: vec![false; use_points.len()].into_boxed_slice(),
                success_arm_confines_for_uses,
                failure_arm_confines_for_uses,
            });
            continue;
        };
        let summary = if exact_condition_argument && call.receiver.is_none() {
            conditional_summary_for_call(analyzer, semantic, cache, file, range, 0)
        } else {
            ConditionalProcedureSummaryAnswer::Open
        };
        let (true_arm, false_arm) = match summary {
            ConditionalProcedureSummaryAnswer::Complete(refinements) => {
                let modeled_results = refinements
                    .iter()
                    .filter(|refinement| refinement.predicate == predicate)
                    .filter(|refinement| {
                        call.arguments
                            .get(refinement.parameter_ordinal as usize)
                            .is_some_and(|argument| {
                                matches!(
                                    argument.expansion,
                                    CallArgumentExpansion::Direct(ArgumentDomain::Positional)
                                ) && modelable_condition_values.contains(&argument.value)
                            })
                    })
                    .filter_map(|refinement| call.normal_result(refinement.result_ordinal as usize))
                    .collect::<HashSet<_>>();
                let result_consumptions = modeled_results
                    .iter()
                    .map(|result| {
                        (
                            *result,
                            conditional_result_consumption(procedure, derivation, call, *result),
                        )
                    })
                    .collect::<HashMap<_, _>>();
                let results_have_no_direct_caller_control = !modeled_results.is_empty()
                    && result_consumptions.values().all(|consumption| {
                        matches!(
                            consumption,
                            ConditionalResultConsumption::ProvenDiscard
                                | ConditionalResultConsumption::DetachedOnly { .. }
                        )
                    });
                if results_have_no_direct_caller_control {
                    let detached_consumers = result_consumptions
                        .values()
                        .filter_map(|consumption| match consumption {
                            ConditionalResultConsumption::DetachedOnly { consumers } => {
                                Some(consumers.as_ref())
                            }
                            ConditionalResultConsumption::DirectGuard { .. }
                            | ConditionalResultConsumption::ProvenDiscard
                            | ConditionalResultConsumption::Open => None,
                        })
                        .flatten()
                        .copied()
                        .collect::<Vec<_>>();
                    let caller_control_irrelevant_for_uses = if detached_consumers.is_empty() {
                        vec![true; use_points.len()].into_boxed_slice()
                    } else {
                        detached_consumers_are_irrelevant_for_uses(
                            procedure,
                            derivation,
                            result_establishments,
                            &detached_consumers,
                            use_ordering_points,
                        )
                    };
                    candidates.push(ConditionalPredicateCall {
                        call: call.id,
                        read_point: call.point,
                        caller_control_irrelevant_for_uses,
                        positive_edges: Box::new([]),
                        closed_negative_for_uses: vec![false; use_points.len()].into_boxed_slice(),
                        success_arm_confines_for_uses,
                        failure_arm_confines_for_uses,
                    });
                    continue;
                }
                (
                    conditional_guard_arm(
                        call,
                        &refinements,
                        &result_consumptions,
                        modelable_condition_values,
                        predicate,
                        true,
                    ),
                    conditional_guard_arm(
                        call,
                        &refinements,
                        &result_consumptions,
                        modelable_condition_values,
                        predicate,
                        false,
                    ),
                )
            }
            ConditionalProcedureSummaryAnswer::Open => (
                ConditionalGuardArmEvidence::Open,
                ConditionalGuardArmEvidence::Open,
            ),
        };
        let arms = [true_arm, false_arm];
        let positive_edges = arms
            .iter()
            .filter_map(|arm| match arm {
                ConditionalGuardArmEvidence::Positive(edge) => Some(edge.clone()),
                ConditionalGuardArmEvidence::ClosedNegative(_)
                | ConditionalGuardArmEvidence::Open => None,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let closed_negative_edges =
            arms.iter()
                .filter_map(|arm| match arm {
                    ConditionalGuardArmEvidence::ClosedNegative(edge) => Some(edge.clone()),
                    ConditionalGuardArmEvidence::Positive(_)
                    | ConditionalGuardArmEvidence::Open => None,
                })
                .collect::<Vec<_>>();
        let closed_negative_for_uses = if closed_negative_edges.is_empty() {
            vec![false; use_points.len()].into_boxed_slice()
        } else {
            derivation
                .any_guard_arm_confines_result_uses_for_negative_evidence(
                    procedure,
                    result_establishments,
                    &closed_negative_edges,
                    use_points,
                )
                .unwrap_or_else(|| vec![false; use_points.len()].into_boxed_slice())
        };
        candidates.push(ConditionalPredicateCall {
            call: call.id,
            read_point: call.point,
            caller_control_irrelevant_for_uses: vec![false; use_points.len()].into_boxed_slice(),
            positive_edges,
            closed_negative_for_uses,
            success_arm_confines_for_uses,
            failure_arm_confines_for_uses,
        });
    }
    candidates
}

fn conditional_predicate_use_answer(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    derivation: &crate::structural::flow_state::FlowStateDerivation,
    result_establishments: &[crate::analyzer::semantic::ProgramPointId],
    candidate: &ConditionalPredicateCall,
    use_index: usize,
    use_point: crate::analyzer::semantic::ProgramPointId,
    target_call: Option<crate::analyzer::semantic::CallSiteId>,
) -> ConditionalPredicateUseAnswer {
    debug_assert_eq!(
        candidate.success_arm_confines_for_uses.len(),
        candidate.failure_arm_confines_for_uses.len()
    );
    debug_assert_eq!(
        candidate.success_arm_confines_for_uses.len(),
        candidate.closed_negative_for_uses.len()
    );
    debug_assert_eq!(
        candidate.success_arm_confines_for_uses.len(),
        candidate.caller_control_irrelevant_for_uses.len()
    );
    debug_assert!(use_index < candidate.success_arm_confines_for_uses.len());
    if let (Some(target_call), Some(candidate_call)) = (
        target_call.and_then(|call| procedure.semantics().call_site(call)),
        procedure.semantics().call_site(candidate.call),
    ) && target_call.normal_result_is_argument_to(candidate_call)
    {
        return ConditionalPredicateUseAnswer::Irrelevant;
    }
    if candidate.caller_control_irrelevant_for_uses[use_index] {
        return ConditionalPredicateUseAnswer::Irrelevant;
    }
    let mut positive = false;
    let mut positive_open = false;
    for edge in &candidate.positive_edges {
        match derivation.any_guard_arm_dominates_result_uses(
            procedure,
            result_establishments,
            std::slice::from_ref(edge),
            &[use_point],
        ) {
            Some(answers) => match answers[0] {
                GuardDominanceAnswer::Proven => {
                    positive = true;
                    break;
                }
                GuardDominanceAnswer::ClosedNegative => {}
                GuardDominanceAnswer::Open => positive_open = true,
            },
            None => positive_open = true,
        }
    }
    let closed_negative = candidate.closed_negative_for_uses[use_index];
    if positive && closed_negative {
        return ConditionalPredicateUseAnswer::Open;
    }
    if positive {
        return ConditionalPredicateUseAnswer::Positive;
    }
    if positive_open && closed_negative {
        return ConditionalPredicateUseAnswer::Open;
    }
    if closed_negative {
        return ConditionalPredicateUseAnswer::ClosedNegative;
    }
    let strictly_precedes = use_point != candidate.read_point
        && derivation
            .any_candidate_dominates_targets(procedure, &[use_point], &[candidate.read_point])
            .is_some_and(|answers| answers[0]);
    if strictly_precedes || candidate.success_arm_confines_for_uses[use_index] {
        ConditionalPredicateUseAnswer::Irrelevant
    } else if positive_open {
        ConditionalPredicateUseAnswer::Open
    } else if candidate.failure_arm_confines_for_uses[use_index]
        && !candidate.positive_edges.is_empty()
    {
        // The bypassing success edge and this modeled positive outcome may
        // jointly cover the use even when neither edge dominates alone.
        ConditionalPredicateUseAnswer::Open
    } else if candidate.failure_arm_confines_for_uses[use_index] {
        ConditionalPredicateUseAnswer::ClosedNegative
    } else {
        ConditionalPredicateUseAnswer::Open
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_result_contract_uses(
    analyzer: &dyn IAnalyzer,
    workspace: &WorkspaceAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    model_cache: &mut EffectTraversalCache,
    flow_state_cache: &mut FlowStateTraversalCache,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    file: &ProjectFile,
    range: Range,
    site_id: &str,
    site_ast_id: &str,
    modeled_target: Option<&ModeledProcedureKey>,
    contract: &CompiledResultContract,
    acquisition_coverage: EffectCoverage,
    projected_success_guard_edges: &[crate::analyzer::semantic::ControlEdgeLocator],
) -> ResultContractUseValidation {
    let results = semantic.call_results_at_source(file, range, site_id, site_ast_id);
    let Some(result) = results
        .iter()
        .find(|result| result.ordinal == contract.result_ordinal as usize)
    else {
        return ResultContractUseValidation::unknown(0);
    };
    let condition = if let Some(condition_result_ordinal) = contract.condition_result_ordinal {
        let Some(condition) = results
            .iter()
            .find(|result| result.ordinal == condition_result_ordinal as usize)
        else {
            return ResultContractUseValidation::unknown(0);
        };
        Some(condition)
    } else {
        None
    };
    if condition.is_some_and(|condition| result.handle != condition.handle) {
        return ResultContractUseValidation::unknown(0);
    }

    let procedure = result.handle.procedure();
    let semantics = procedure.semantics();
    let Ok(projected_success_guard_handles) = projected_success_guard_edges
        .iter()
        .map(|edge| edge.resolve(procedure))
        .collect::<Result<Vec<_>, _>>()
    else {
        return ResultContractUseValidation::unknown(0);
    };
    let Some(materialized) = semantic.materialized_outcome(file) else {
        return ResultContractUseValidation::unknown(0);
    };
    // Every ordinary result-use proof is intraprocedural. Derive the parent
    // procedure first and pay for the complete file only if this exact result
    // is captured into a child below. Most reviewed result contracts have no
    // relevant capture, so deriving every sibling procedure here needlessly
    // broadens optional use validation after contract projection established
    // the parent at procedure scope.
    let procedure_state = flow_state_cache.for_materialized_procedure(
        workspace,
        file,
        materialized.clone(),
        procedure,
        cancellation,
    );
    let Some(derivation) = procedure_state
        .procedures
        .iter()
        .find(|candidate| candidate.procedure == procedure.id())
    else {
        return ResultContractUseValidation::unknown(0);
    };
    let Some(result_use_index) =
        model_cache.result_use_index(semantic, file, procedure, derivation)
    else {
        return ResultContractUseValidation::unknown(0);
    };
    let semantic_model_overlay = modeled_target
        .filter(|target| target.language == "go")
        .and_then(|_| semantic.semantic_model_overlay());
    let exact_source = semantic_model_overlay
        .as_ref()
        .and_then(|_| model_cache.exact_source(analyzer, file));
    let intrinsic_classification = IntrinsicClassificationContext {
        modeled_target,
        result_ordinal: contract.result_ordinal,
        semantic_model_overlay: semantic_model_overlay.as_deref(),
        exact_source: exact_source.as_deref(),
    };
    let assignment_conversion_proof_work = exact_source
        .as_deref()
        .and_then(crate::analyzer::go_modeled_result_binding_type_identity_proof_work);
    let assignment_conversion_proof = result_assignment_conversion_proof_context(
        analyzer,
        file,
        modeled_target,
        semantic_model_overlay.as_deref(),
        exact_source.as_deref(),
        &model_cache.exact_source_identities,
        &model_cache.result_assignment_conversion_proofs,
        assignment_conversion_proof_work,
    );
    let projected_success_guards = result_contract_success_guards_for_values(
        semantic,
        procedure,
        derivation,
        &result_use_index,
        condition.map(|condition| condition.value),
        result.value,
        contract,
        None,
        assignment_conversion_proof,
    );
    let projected_guard_ids = projected_success_guard_handles
        .iter()
        .map(|edge| edge.id())
        .collect::<Vec<_>>();
    let recomputed_guard_ids = projected_success_guards
        .edges
        .iter()
        .map(|edge| edge.id())
        .collect::<Vec<_>>();
    let guard_projection_matches = projected_guard_ids == recomputed_guard_ids;
    let success_guards = result_contract_success_guards_for_values(
        semantic,
        procedure,
        derivation,
        &result_use_index,
        condition.map(|condition| condition.value),
        result.value,
        contract,
        Some(CompiledResultPredicate::NonNull),
        assignment_conversion_proof,
    );

    let result_conversion = result_use_index.exact_converted_establishments_from(
        semantic,
        procedure,
        derivation,
        result.value,
        contract.result_ordinal,
        assignment_conversion_proof,
    );
    let mut result_establishments = derivation
        .events
        .iter()
        .filter(|event| {
            event.event_class == StateEventClass::Establish && event.value == result.value
        })
        .map(|event| event.event)
        .collect::<Vec<_>>();
    result_establishments.extend(result_conversion.establishments.iter().copied());
    result_establishments.sort_unstable();
    result_establishments.dedup();
    let result_aliases =
        derivation.exact_local_value_alias_closure(procedure, &result_establishments);
    let mut result_establishment_points = result_aliases
        .establishments
        .iter()
        .map(|event| derivation.event(*event).point)
        .collect::<Vec<_>>();
    if result_establishment_points.is_empty()
        && let Some(call) = semantics.call_site(result.handle.id())
    {
        // An explicitly discarded result still comes into existence at its
        // call. Use that structured origin so a later control/value gap cannot
        // turn an omitted assignment or read into a certified zero-use count.
        result_establishment_points.push(call.point);
    }
    result_establishment_points.sort_unstable();
    result_establishment_points.dedup();
    let result_binding_subjects = result_aliases
        .establishments
        .iter()
        .map(|event| derivation.event(*event).subject.value())
        .collect::<HashSet<_>>();
    let result_establishment_values = result_aliases
        .establishments
        .iter()
        .map(|event| derivation.event(*event).value)
        .collect::<HashSet<_>>();
    let converted_result_establishments = if result_conversion.proof_open {
        result_use_index.converted_establishments_from(result.value)
    } else {
        Vec::new()
    };
    let converted_result_aliases = (!converted_result_establishments.is_empty()).then(|| {
        derivation.exact_local_value_alias_closure(procedure, &converted_result_establishments)
    });
    let converted_result_read_events = converted_result_aliases
        .iter()
        .flat_map(|aliases| aliases.reads.iter().chain(&aliases.uncertain_reads))
        .copied()
        .collect::<HashSet<_>>();
    let mut capture_binding_subjects = result_binding_subjects.clone();
    if let Some(aliases) = &converted_result_aliases {
        capture_binding_subjects.extend(aliases.establishments.iter().filter_map(|event| {
            let event = derivation.event(*event);
            matches!(
                &event.subject,
                crate::structural::flow_state::FlowSubject::Binding { .. }
            )
            .then_some(event.subject.value())
        }));
        result_establishment_points.extend(
            aliases
                .establishments
                .iter()
                .map(|event| derivation.event(*event).point),
        );
        result_establishment_points.sort_unstable();
        result_establishment_points.dedup();
    }
    let mut converted_binding_establishments =
        result_use_index.converted_establishments_for_bindings(&result_binding_subjects);
    converted_binding_establishments
        .retain(|event| !result_conversion.establishments.contains(event));
    let converted_binding_aliases = (!converted_binding_establishments.is_empty()).then(|| {
        derivation.exact_local_value_alias_closure(procedure, &converted_binding_establishments)
    });
    let converted_binding_read_events = converted_binding_aliases
        .iter()
        .flat_map(|aliases| aliases.reads.iter().chain(&aliases.uncertain_reads))
        .copied()
        .collect::<HashSet<_>>();
    // A same-subject read is not necessarily a use of this call result: a
    // field can be read before this assignment or overwritten later. Keep
    // only reads for which this exact establishment is the sole reaching
    // definition. A `May` relation can include an infeasible retained-CFG path
    // (for example, the false arm of `if true`) and therefore cannot certify a
    // use or a violation.
    let result_read_events = &result_aliases.reads;
    let uncertain_result_read_events = &result_aliases.uncertain_reads;
    let result_reads = derivation
        .events
        .iter()
        .filter(|event| result_read_events.contains(&event.event))
        .collect::<Vec<_>>();
    let result_read_values = result_reads
        .iter()
        .map(|read| read.value)
        .collect::<HashSet<_>>();
    let converted_result_reads = derivation
        .events
        .iter()
        .filter(|event| {
            converted_result_read_events.contains(&event.event)
                && !result_read_events.contains(&event.event)
        })
        .collect::<Vec<_>>();
    let converted_result_read_values = converted_result_reads
        .iter()
        .map(|read| read.value)
        .collect::<HashSet<_>>();
    let mut capture_source_values = result_establishment_values.clone();
    capture_source_values.insert(result.value);
    capture_source_values.extend(result_read_values.iter().copied());
    capture_source_values.extend(converted_result_read_values.iter().copied());
    let result_storage_locations = semantics
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .filter_map(|event| match event.effect {
            SemanticEffect::MemoryStore {
                location, value, ..
            } if capture_source_values.contains(&value) => Some(location),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let read_identity = read_identity_closure(result_reads.iter().map(|read| {
        (
            read.event,
            read.value,
            derivation.exact_local_alias_read_identity_is_closed(
                procedure,
                &result_aliases,
                read.event,
            ),
        )
    }));
    let captured_result_may_be_used = semantics.captures().iter().any(|capture| {
        capture_observes_result_binding(
            semantics,
            capture.captured,
            &capture.mode,
            &capture_binding_subjects,
            &result_storage_locations,
        )
    });
    let direct_call_argument_may_be_used = result_read_values.iter().any(|value| {
        result_use_index
            .call_argument_uses_by_value
            .contains_key(value)
    }) || converted_result_read_values.iter().any(|value| {
        result_use_index
            .call_argument_uses_by_value
            .contains_key(value)
    });
    let needs_result_member_facts = result_read_values
        .iter()
        .flat_map(|source| {
            result_use_index
                .receiver_call_ids_by_value
                .get(source)
                .into_iter()
                .flatten()
                .chain(
                    result_use_index
                        .deferred_call_ids_by_source
                        .get(source)
                        .into_iter()
                        .flatten(),
                )
        })
        .next()
        .is_some()
        || converted_result_read_values.iter().any(|source| {
            result_use_index
                .receiver_call_ids_by_value
                .contains_key(source)
                || result_use_index
                    .deferred_call_ids_by_source
                    .contains_key(source)
        })
        || direct_call_argument_may_be_used
        || captured_result_may_be_used;
    let result_member_facts = needs_result_member_facts
        .then(|| {
            model_cache
                .facts
                .entry(file.clone())
                .or_insert_with(|| {
                    analyzer
                        .structural_fact_providers()
                        .into_iter()
                        .find_map(|provider| provider.structural_facts(file))
                })
                .clone()
        })
        .flatten();
    let result_member_call_shapes = needs_result_member_facts
        .then(|| {
            model_cache.result_member_call_shapes(semantic, file, result_member_facts.as_deref())
        })
        .flatten();
    if (direct_call_argument_may_be_used || captured_result_may_be_used)
        && let Some(shapes) = result_member_call_shapes.as_deref()
    {
        prepare_result_operation_call_lookups(
            analyzer,
            model_cache,
            limits,
            cancellation,
            file,
            shapes,
        );
    }
    let mut observed_uses = Vec::<ObservedResultUse>::new();
    let mut observed_direct_calls = HashSet::default();
    let mut observed_call_arguments = HashSet::default();
    let direct_intrinsic_reads = result_reads
        .iter()
        .map(|read| {
            let identity_open = !read_identity
                .every_event_by_value
                .get(&read.value)
                .copied()
                .unwrap_or(false)
                || converted_binding_read_events.contains(&read.event)
                || acquisition_coverage != EffectCoverage::Exhaustive;
            (*read, identity_open)
        })
        .collect::<Vec<_>>();
    // An unclosed transfer downstream of one exact read keeps observation
    // enumeration open, but it does not make that read ambiguous as the
    // operand of its own intrinsic operation. Retain the exact event so local
    // ordering can still prove that operation unguarded. May-reaching reads
    // remain non-excludable because they do not identify this result alone.
    let non_excludable_result_read_events = uncertain_result_read_events.clone();
    observed_uses.extend(intrinsic_result_uses_for_reads(
        &result_use_index,
        &direct_intrinsic_reads,
        &non_excludable_result_read_events,
        ResultContractUseTiming::Direct,
        intrinsic_classification,
    ));
    let mut direct_receiver_call_ids = result_read_values
        .iter()
        .flat_map(|value| {
            result_use_index
                .receiver_call_ids_by_value
                .get(value)
                .into_iter()
                .flatten()
        })
        .copied()
        .collect::<Vec<_>>();
    direct_receiver_call_ids.sort_unstable();
    direct_receiver_call_ids.dedup();
    for call_id in direct_receiver_call_ids {
        let Some(call) = semantics.call_site(call_id) else {
            continue;
        };
        let Some(receiver) = call.receiver else {
            continue;
        };
        let shape =
            exact_result_member_call_shape(semantics, call, result_member_call_shapes.as_deref());
        // A lowered value may be reused by later source reads. The exact call
        // shape names this operation's receiver syntax, so only its one exact
        // state-read site can use event-local identity. Missing or ambiguous
        // joins stay visible as operations but cannot carry a closed proof.
        let receiver_read = exact_result_member_receiver_read(call, shape, &result_reads);
        let fallback_read = result_reads
            .iter()
            .copied()
            .find(|read| read.value == receiver)
            .expect("receiver-call index key came from a retained result read");
        let identity_open = receiver_read.is_none_or(|read| {
            !read_identity
                .by_event
                .get(&read.event)
                .copied()
                .unwrap_or(false)
                || converted_binding_read_events.contains(&read.event)
        });
        let mut use_value = result_member_use_for_call(
            procedure,
            call,
            result_member_call_shapes.as_deref(),
            &contract.member_contracts,
            &fallback_read.site,
            ResultContractUseTiming::Direct,
            identity_open,
        );
        use_value.ordering_point = None;
        if let Some(receiver_read) = receiver_read
            && !uncertain_result_read_events.contains(&receiver_read.event)
            && !result_aliases
                .unclosed_transfers
                .contains(&receiver_read.event)
            && use_value.parameter_count == Some(0)
        {
            use_value.ordering_point = Some(receiver_read.point);
            use_value.own_subject_read_event = Some(receiver_read.event);
        }
        if acquisition_coverage != EffectCoverage::Exhaustive || identity_open {
            use_value.applicability = OperationApplicability::Unknown;
            use_value.required_predicate = None;
        }
        observed_direct_calls.insert(call_id);
        observed_uses.push(use_value);
    }
    let mut direct_call_arguments = result_read_values
        .iter()
        .flat_map(|value| {
            result_use_index
                .call_argument_uses_by_value
                .get(value)
                .into_iter()
                .flatten()
                .cloned()
                .map(|indexed| (*value, indexed))
        })
        .collect::<Vec<_>>();
    direct_call_arguments.sort_unstable_by_key(|(_, indexed)| {
        (
            indexed.call,
            indexed.argument_ordinal,
            indexed.range.start_byte,
            indexed.range.end_byte,
        )
    });
    direct_call_arguments.dedup_by(|left, right| {
        left.1.call == right.1.call && left.1.argument_ordinal == right.1.argument_ordinal
    });
    for (source, indexed) in direct_call_arguments {
        let Some(call) = semantics.call_site(indexed.call) else {
            continue;
        };
        let shape =
            exact_result_member_call_shape(semantics, call, result_member_call_shapes.as_deref());
        let exact_argument = exact_positional_call_argument(semantics, shape, call, &indexed);
        let exact_read = exact_argument.and_then(|_| {
            exact_result_call_argument_read(
                source,
                &shape
                    .expect("exact positional argument has a call shape")
                    .outcome
                    .file,
                indexed
                    .semantic_range
                    .expect("exact positional argument has an exact semantic range"),
                &result_reads,
            )
        });
        let fallback_read = result_reads
            .iter()
            .copied()
            .find(|read| read.value == source)
            .expect("call-argument index key came from a retained result read");
        let identity_open = exact_read.is_none_or(|read| {
            !read_identity
                .by_event
                .get(&read.event)
                .copied()
                .unwrap_or(false)
                || converted_binding_read_events.contains(&read.event)
                || uncertain_result_read_events.contains(&read.event)
                || result_aliases.unclosed_transfers.contains(&read.event)
        });
        let mut use_value = result_call_argument_use_for_call(
            analyzer,
            model_cache,
            procedure,
            call,
            &indexed,
            result_member_call_shapes.as_deref(),
            &fallback_read.site,
            exact_read,
            ResultContractUseTiming::Direct,
            identity_open,
        );
        if acquisition_coverage != EffectCoverage::Exhaustive || identity_open {
            use_value.applicability = OperationApplicability::Unknown;
            use_value.required_predicate = None;
        }
        observed_call_arguments.insert((indexed.call, indexed.argument_ordinal));
        observed_uses.push(use_value);
    }
    let converted_intrinsic_reads = converted_result_reads
        .iter()
        .map(|read| (*read, true))
        .collect::<Vec<_>>();
    observed_uses.extend(intrinsic_result_uses_for_reads(
        &result_use_index,
        &converted_intrinsic_reads,
        &converted_result_read_events,
        ResultContractUseTiming::Direct,
        intrinsic_classification,
    ));
    for read in &converted_result_reads {
        for call_id in result_use_index
            .receiver_call_ids_by_value
            .get(&read.value)
            .into_iter()
            .flatten()
        {
            if !observed_direct_calls.insert(*call_id) {
                continue;
            }
            let Some(call) = semantics.call_site(*call_id) else {
                continue;
            };
            let mut use_value = result_member_use_for_call(
                procedure,
                call,
                result_member_call_shapes.as_deref(),
                &contract.member_contracts,
                &read.site,
                ResultContractUseTiming::Direct,
                true,
            );
            use_value.applicability = OperationApplicability::Unknown;
            use_value.required_predicate = None;
            observed_uses.push(use_value);
        }
        for indexed in result_use_index
            .call_argument_uses_by_value
            .get(&read.value)
            .into_iter()
            .flatten()
        {
            if !observed_call_arguments.insert((indexed.call, indexed.argument_ordinal)) {
                continue;
            }
            let Some(call) = semantics.call_site(indexed.call) else {
                continue;
            };
            let mut use_value = result_call_argument_use_for_call(
                analyzer,
                model_cache,
                procedure,
                call,
                indexed,
                result_member_call_shapes.as_deref(),
                &read.site,
                None,
                ResultContractUseTiming::Direct,
                true,
            );
            use_value.applicability = OperationApplicability::Unknown;
            use_value.required_predicate = None;
            observed_uses.push(use_value);
        }
    }
    // Go evaluates and captures a deferred receiver at registration, then
    // invokes the call on a path-specialized cleanup route. The exact
    // language-defined value identity joins those two phases. Count each
    // invocation point, not the registration-time copy, so a success check
    // after `defer file.Close()` cannot guard the failure cleanup.
    let converted_binding_read_values = result_reads
        .iter()
        .filter(|read| converted_binding_read_events.contains(&read.event))
        .map(|read| read.value)
        .collect::<HashSet<_>>();
    let mut observed_deferred_calls = HashSet::default();
    for source in &result_read_values {
        let Some(source_read) = result_reads.iter().find(|read| read.value == *source) else {
            continue;
        };
        for call_id in result_use_index
            .deferred_call_ids_by_source
            .get(source)
            .into_iter()
            .flatten()
        {
            let Some(call) = semantics.call_site(*call_id) else {
                continue;
            };
            observed_deferred_calls.insert(call.id);
            let identity_open = !read_identity
                .every_event_by_value
                .get(source)
                .copied()
                .unwrap_or(false)
                || converted_binding_read_values.contains(source);
            let mut use_value = result_member_use_for_call(
                procedure,
                call,
                result_member_call_shapes.as_deref(),
                &contract.member_contracts,
                &source_read.site,
                ResultContractUseTiming::Deferred,
                identity_open,
            );
            if acquisition_coverage != EffectCoverage::Exhaustive || identity_open {
                use_value.applicability = OperationApplicability::Unknown;
                use_value.required_predicate = None;
            }
            observed_uses.push(use_value);
        }
    }
    for source in &converted_result_read_values {
        let Some(source_read) = converted_result_reads
            .iter()
            .find(|read| read.value == *source)
        else {
            continue;
        };
        for call_id in result_use_index
            .deferred_call_ids_by_source
            .get(source)
            .into_iter()
            .flatten()
        {
            if !observed_deferred_calls.insert(*call_id) {
                continue;
            }
            let Some(call) = semantics.call_site(*call_id) else {
                continue;
            };
            let mut use_value = result_member_use_for_call(
                procedure,
                call,
                result_member_call_shapes.as_deref(),
                &contract.member_contracts,
                &source_read.site,
                ResultContractUseTiming::Deferred,
                true,
            );
            use_value.applicability = OperationApplicability::Unknown;
            use_value.required_predicate = None;
            observed_uses.push(use_value);
        }
    }
    let uncertain_resource_use_count = derivation
        .events
        .iter()
        .filter(|event| uncertain_result_read_events.contains(&event.event))
        .filter(|event| {
            result_use_index.intrinsic_uses.contains_key(&event.value)
                || result_use_index
                    .receiver_call_ids_by_value
                    .contains_key(&event.value)
                || result_use_index
                    .deferred_call_ids_by_source
                    .contains_key(&event.value)
                || result_use_index
                    .call_argument_uses_by_value
                    .contains_key(&event.value)
        })
        .count();
    let mut capture_use_enumeration_open = false;
    let mut capture_file_state = None;
    for capture in semantics.captures() {
        if !capture_observes_result_binding(
            semantics,
            capture.captured,
            &capture.mode,
            &capture_binding_subjects,
            &result_storage_locations,
        ) {
            continue;
        }
        let Some(child_handle) = procedure.artifact().procedure_handle(capture.target) else {
            capture_use_enumeration_open = true;
            continue;
        };
        let child = child_handle.semantics();
        let mut capture_inputs = child
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Capture,
                    location,
                    result,
                } if location == capture.destination => Some(result),
                _ => None,
            })
            .collect::<HashSet<_>>();
        if let Some(binding) = child
            .memory_location(capture.destination)
            .and_then(|location| match location.kind {
                MemoryLocationKind::Capture { binding, .. } => binding,
                _ => None,
            })
        {
            capture_inputs.insert(binding);
        }
        if capture_inputs.is_empty() {
            capture_use_enumeration_open = true;
            continue;
        }
        let file_state = capture_file_state.get_or_insert_with(|| {
            flow_state_cache.for_materialized_file(
                workspace,
                file,
                materialized.clone(),
                cancellation,
            )
        });
        let Some(child_derivation) = file_state
            .procedures
            .iter()
            .find(|candidate| candidate.procedure == capture.target)
        else {
            capture_use_enumeration_open = true;
            continue;
        };
        let Some(child_use_index) =
            model_cache.result_use_index(semantic, file, &child_handle, child_derivation)
        else {
            capture_use_enumeration_open = true;
            continue;
        };
        let captured_reads = child_derivation
            .events
            .iter()
            .filter(|event| {
                event.event_class == StateEventClass::Read
                    && capture_inputs.contains(&event.subject.value())
            })
            .collect::<Vec<_>>();
        let mut child_relevant_values = capture_inputs.iter().copied().collect::<HashSet<_>>();
        child_relevant_values.extend(captured_reads.iter().map(|event| event.value));
        let child_observations_complete = child_derivation.result_observations_are_complete(
            &child_handle,
            &[child.entry_point()],
            &child_relevant_values.iter().copied().collect::<Vec<_>>(),
        );
        if !child_observations_complete {
            capture_use_enumeration_open = true;
        }

        let captured_intrinsic_reads = captured_reads
            .iter()
            .map(|read| (*read, true))
            .collect::<Vec<_>>();
        let captured_non_excludable_events = captured_reads
            .iter()
            .map(|read| read.event)
            .collect::<HashSet<_>>();
        let captured_intrinsic = intrinsic_result_uses_for_reads(
            &child_use_index,
            &captured_intrinsic_reads,
            &captured_non_excludable_events,
            ResultContractUseTiming::Captured,
            intrinsic_classification,
        );
        let mut captured_operation_count = captured_intrinsic.len();
        observed_uses.extend(captured_intrinsic);
        let mut captured_calls = HashSet::default();
        let mut captured_call_arguments = HashSet::default();
        for read in &captured_reads {
            for call_id in child_use_index
                .receiver_call_ids_by_value
                .get(&read.value)
                .into_iter()
                .flatten()
            {
                if !captured_calls.insert(*call_id) {
                    continue;
                }
                let Some(call) = child.call_site(*call_id) else {
                    continue;
                };
                let mut use_value = result_member_use_for_call(
                    &child_handle,
                    call,
                    result_member_call_shapes.as_deref(),
                    &contract.member_contracts,
                    &read.site,
                    ResultContractUseTiming::Captured,
                    true,
                );
                if acquisition_coverage != EffectCoverage::Exhaustive
                    || !child_observations_complete
                {
                    use_value.applicability = OperationApplicability::Unknown;
                    use_value.required_predicate = None;
                }
                captured_operation_count = captured_operation_count.saturating_add(1);
                observed_uses.push(use_value);
            }
            for call_id in child_use_index
                .deferred_call_ids_by_source
                .get(&read.value)
                .into_iter()
                .flatten()
            {
                if !captured_calls.insert(*call_id) {
                    continue;
                }
                let Some(call) = child.call_site(*call_id) else {
                    continue;
                };
                let mut use_value = result_member_use_for_call(
                    &child_handle,
                    call,
                    result_member_call_shapes.as_deref(),
                    &contract.member_contracts,
                    &read.site,
                    ResultContractUseTiming::Captured,
                    true,
                );
                if acquisition_coverage != EffectCoverage::Exhaustive
                    || !child_observations_complete
                {
                    use_value.applicability = OperationApplicability::Unknown;
                    use_value.required_predicate = None;
                }
                captured_operation_count = captured_operation_count.saturating_add(1);
                observed_uses.push(use_value);
            }
            for indexed in child_use_index
                .call_argument_uses_by_value
                .get(&read.value)
                .into_iter()
                .flatten()
            {
                if !captured_call_arguments.insert((indexed.call, indexed.argument_ordinal)) {
                    continue;
                }
                let Some(call) = child.call_site(indexed.call) else {
                    continue;
                };
                let shape = exact_result_member_call_shape(
                    child,
                    call,
                    result_member_call_shapes.as_deref(),
                );
                let exact_argument = exact_positional_call_argument(child, shape, call, indexed);
                let exact_read = exact_argument.and_then(|_| {
                    exact_result_call_argument_read(
                        read.value,
                        &shape
                            .expect("exact positional argument has a call shape")
                            .outcome
                            .file,
                        indexed
                            .semantic_range
                            .expect("exact positional argument has an exact semantic range"),
                        &captured_reads,
                    )
                });
                let mut use_value = result_call_argument_use_for_call(
                    analyzer,
                    model_cache,
                    &child_handle,
                    call,
                    indexed,
                    result_member_call_shapes.as_deref(),
                    &read.site,
                    exact_read,
                    ResultContractUseTiming::Captured,
                    true,
                );
                if acquisition_coverage != EffectCoverage::Exhaustive
                    || !child_observations_complete
                {
                    use_value.applicability = OperationApplicability::Unknown;
                    use_value.required_predicate = None;
                }
                captured_operation_count = captured_operation_count.saturating_add(1);
                observed_uses.push(use_value);
            }
        }
        if captured_operation_count == 0 {
            continue;
        }

        // The parent procedure cannot yet compose a condition captured by the
        // same child with that child's resource read. Even an exactly placed
        // invocation is therefore an observed use with unknown guard status,
        // never evidence of an unguarded use by itself.
        capture_use_enumeration_open |= captured_callable_invocation_enumeration_is_open(
            semantics,
            capture.callable,
            capture.target,
        );

        // A child read happens when the closure is invoked, never merely when
        // its environment is created. Only the call site's proven local target
        // establishes that exact invocation point. Raw callable-value equality
        // is insufficient for language-defined deferred copies, and an
        // ambiguous or unresolved target cannot place the child execution.
        let invocation_points = semantics
            .call_sites()
            .iter()
            .filter(|call| {
                matches!(
                    &call.declared_targets,
                    CallableTargetResolution::Proven(CallableTarget::Local(target))
                        if *target == capture.target
                )
            })
            .map(|call| call.point)
            .collect::<Vec<_>>();
        if invocation_points.is_empty() {
            capture_use_enumeration_open = true;
            continue;
        }
    }
    let mut required_uses = observed_uses
        .iter()
        .enumerate()
        .filter(|(_, result_use)| {
            result_use.applicability == OperationApplicability::Required
                && result_use.timing != ResultContractUseTiming::Captured
        })
        .map(|(observed_index, result_use)| RequiredObservedResultUse {
            observed_index,
            guard_point: result_use.guard_point,
            ordering_point: result_use.ordering_point,
            target_call: result_use.target_call,
            identity_open: result_use.identity_open,
            own_subject_read_event: result_use.own_subject_read_event,
        })
        .collect::<Vec<_>>();
    required_uses.sort_unstable_by_key(|required| required.observed_index);
    let use_guard_points = required_uses
        .iter()
        .map(|required| required.guard_point)
        .collect::<Vec<_>>();
    let use_ordering_points = required_uses
        .iter()
        .map(|required| required.ordering_point)
        .collect::<Vec<_>>();
    let use_target_calls = required_uses
        .iter()
        .map(|required| required.target_call)
        .collect::<Vec<_>>();
    let use_guard_classification_open = required_uses
        .iter()
        .map(|required| required.identity_open)
        .collect::<Vec<_>>();
    let own_subject_read_events = required_uses
        .iter()
        .map(|required| required.own_subject_read_event)
        .collect::<Vec<_>>();
    let mut result_relevant_values = result_binding_subjects.clone();
    result_relevant_values.insert(result.value);
    result_relevant_values.extend(result_establishment_values);
    result_relevant_values.extend(result_read_values.iter().copied());
    result_relevant_values.extend(converted_result_read_values.iter().copied());
    if let Some(aliases) = &converted_result_aliases {
        result_relevant_values.extend(aliases.establishments.iter().flat_map(|event| {
            let event = derivation.event(*event);
            [event.subject.value(), event.value]
        }));
    }
    let result_observations_complete = derivation.result_observation_enumeration_is_complete(
        procedure,
        &result_establishment_points,
        &result_relevant_values.iter().copied().collect::<Vec<_>>(),
    );
    let observed_use_count = use_guard_points.len();
    if !guard_projection_matches {
        return attach_observed_result_uses(
            ResultContractUseValidation::unknown(observed_use_count),
            &observed_uses,
            &required_uses,
            &vec![ResultUseGuardVerdict::Unknown; required_uses.len()],
        );
    }
    let observation_enumeration_open = uncertain_resource_use_count != 0
        || !result_aliases.uncertain_transfers.is_empty()
        || result_aliases.proof_open
        || !result_aliases.unclosed_transfers.is_empty()
        || converted_result_aliases.as_ref().is_some_and(|aliases| {
            aliases.proof_open
                || !aliases.uncertain_transfers.is_empty()
                || !aliases.unclosed_transfers.is_empty()
        })
        || converted_binding_aliases.as_ref().is_some_and(|aliases| {
            aliases.proof_open
                || !aliases.uncertain_transfers.is_empty()
                || !aliases.unclosed_transfers.is_empty()
        })
        || result_conversion.proof_open
        || capture_use_enumeration_open
        || observed_uses
            .iter()
            .any(|result_use| result_use.applicability == OperationApplicability::Unknown)
        || !result_observations_complete;
    let observed_guard_classification_open = use_guard_classification_open.iter().any(|open| *open);
    let ResultContractSuccessGuards {
        edges: success_guard_edges,
        possible_edges: _,
        condition_candidate_success_edges,
        condition_failure_edges,
        condition_values: condition_read_values,
        condition_candidate_values,
        subject_reads,
        subject_reads_exhaustive,
        condition_discarded,
        condition_identity_open,
        condition_failure_coverage: _,
        result_identity_open,
        has_result_success_edge,
        coverage: guard_projection_coverage,
    } = success_guards;
    let guard_evidence_open = condition_identity_open
        || result_identity_open
        || guard_projection_coverage != EffectCoverage::Exhaustive;
    let mut predicate_binding_values = derivation
        .events
        .iter()
        .filter(|event| {
            event.event_class == StateEventClass::Read
                && condition_read_values.contains(&event.value)
        })
        .map(|event| event.subject.value())
        .collect::<Vec<_>>();
    predicate_binding_values.sort_unstable();
    predicate_binding_values.dedup();
    let use_precedes_guard_subject_reads = uses_before_every_guard_subject_read(
        procedure,
        derivation,
        &result_establishment_points,
        &use_ordering_points,
        &own_subject_read_events,
        &subject_reads,
        subject_reads_exhaustive,
    );
    if condition_discarded && !has_result_success_edge && !result_identity_open {
        let unguarded = use_guard_classification_open
            .iter()
            .filter(|open| !**open)
            .count();
        let validation = if use_guard_points.is_empty() && observation_enumeration_open {
            ResultContractUseValidation::unknown(0)
        } else if unguarded != 0
            && (observation_enumeration_open || observed_guard_classification_open)
        {
            ResultContractUseValidation::violated_open(use_guard_points.len(), unguarded)
        } else if observed_guard_classification_open {
            ResultContractUseValidation::unknown(use_guard_points.len())
        } else if observation_enumeration_open {
            ResultContractUseValidation::violated_open(
                use_guard_points.len(),
                use_guard_points.len(),
            )
        } else {
            ResultContractUseValidation::known(use_guard_points.len(), use_guard_points.len())
        };
        let verdicts = use_guard_classification_open
            .iter()
            .map(|open| {
                if *open {
                    ResultUseGuardVerdict::Unknown
                } else {
                    ResultUseGuardVerdict::Unguarded
                }
            })
            .collect::<Vec<_>>();
        return attach_observed_result_uses(validation, &observed_uses, &required_uses, &verdicts);
    }
    if use_guard_points.is_empty() {
        let validation = if observation_enumeration_open || observed_guard_classification_open {
            ResultContractUseValidation::unknown(0)
        } else {
            ResultContractUseValidation::known(0, 0)
        };
        return attach_observed_result_uses(validation, &observed_uses, &required_uses, &[]);
    }

    // A direct guard that already protects every use is a complete proof. Do
    // not search the containing procedure for modeled validator calls after
    // that proof has been established: each such search performs semantic
    // dispatch, and unrelated calls cannot strengthen the answer.
    let guard_answers = if success_guard_edges.is_empty() {
        None
    } else {
        Some(derivation.any_guard_arm_dominates_result_uses(
            procedure,
            &result_establishment_points,
            &success_guard_edges,
            &use_guard_points,
        ))
    };
    if guard_answers
        .as_ref()
        .and_then(|answers| answers.as_ref())
        .is_some_and(|answers| {
            answers
                .iter()
                .all(|answer| *answer == GuardDominanceAnswer::Proven)
        })
    {
        let validation = if observation_enumeration_open {
            ResultContractUseValidation::unknown(use_guard_points.len())
        } else {
            ResultContractUseValidation::known(use_guard_points.len(), 0)
        };
        let verdicts = use_guard_classification_open
            .iter()
            .map(|open| {
                if *open {
                    ResultUseGuardVerdict::Unknown
                } else {
                    ResultUseGuardVerdict::Guarded
                }
            })
            .collect::<Vec<_>>();
        return attach_observed_result_uses(validation, &observed_uses, &required_uses, &verdicts);
    }

    let normal_return_calls = if condition_identity_open || condition_discarded {
        Vec::new()
    } else if let Some(predicate) = contract.predicate {
        normal_return_refinement_calls(
            analyzer,
            semantic,
            model_cache,
            file,
            procedure,
            &condition_read_values,
            predicate,
        )
    } else {
        Vec::new()
    };
    let conditional_calls = if condition_identity_open || condition_discarded {
        Vec::new()
    } else if let Some(predicate) = contract.predicate {
        conditional_predicate_calls(
            analyzer,
            semantic,
            model_cache,
            file,
            procedure,
            derivation,
            &result_establishment_points,
            &use_guard_points,
            &use_ordering_points,
            &condition_candidate_success_edges,
            &condition_failure_edges,
            &normal_return_calls,
            &condition_candidate_values,
            &condition_read_values,
            predicate,
        )
    } else {
        Vec::new()
    };
    // A dispatch budget failure while looking for modeled validators is not
    // evidence that no validator exists. The query as a whole is incomplete,
    // and this candidate must stay unknown so a positive relational finding
    // cannot turn the interrupted lookup into a claimed unguarded use.
    if semantic.work().budget_exhausted {
        let unguarded = use_precedes_guard_subject_reads
            .iter()
            .zip(&use_guard_classification_open)
            .filter(|(precedes, identity_open)| **precedes && !**identity_open)
            .count();
        let validation = if unguarded == 0 {
            ResultContractUseValidation::unknown(use_guard_points.len())
        } else {
            ResultContractUseValidation::violated_open(use_guard_points.len(), unguarded)
        };
        let verdicts = use_precedes_guard_subject_reads
            .iter()
            .zip(&use_guard_classification_open)
            .map(|(precedes, identity_open)| {
                if *precedes && !*identity_open {
                    ResultUseGuardVerdict::Unguarded
                } else {
                    ResultUseGuardVerdict::Unknown
                }
            })
            .collect::<Vec<_>>();
        return attach_observed_result_uses(validation, &observed_uses, &required_uses, &verdicts);
    }
    if success_guard_edges.is_empty()
        && normal_return_calls.is_empty()
        && conditional_calls.is_empty()
    {
        let guard_facts_complete = procedure
            .artifact()
            .capabilities()
            .is_complete(SemanticCapability::GuardFacts);
        if !guard_evidence_open && guard_facts_complete {
            let unguarded = use_guard_classification_open
                .iter()
                .filter(|open| !**open)
                .count();
            let validation = if unguarded != 0
                && (observation_enumeration_open || observed_guard_classification_open)
            {
                ResultContractUseValidation::violated_open(use_guard_points.len(), unguarded)
            } else if observation_enumeration_open || observed_guard_classification_open {
                ResultContractUseValidation::unknown(use_guard_points.len())
            } else {
                ResultContractUseValidation::known(use_guard_points.len(), use_guard_points.len())
            };
            let verdicts = use_guard_classification_open
                .iter()
                .map(|open| {
                    if *open {
                        ResultUseGuardVerdict::Unknown
                    } else {
                        ResultUseGuardVerdict::Unguarded
                    }
                })
                .collect::<Vec<_>>();
            return attach_observed_result_uses(
                validation,
                &observed_uses,
                &required_uses,
                &verdicts,
            );
        }
        let unguarded = use_precedes_guard_subject_reads
            .iter()
            .zip(&use_guard_classification_open)
            .filter(|(precedes, identity_open)| **precedes && !**identity_open)
            .count();
        if unguarded != 0 {
            let verdicts = use_precedes_guard_subject_reads
                .iter()
                .zip(&use_guard_classification_open)
                .map(|(precedes, identity_open)| {
                    if *precedes && !*identity_open {
                        ResultUseGuardVerdict::Unguarded
                    } else {
                        ResultUseGuardVerdict::Unknown
                    }
                })
                .collect::<Vec<_>>();
            let every_required_use_is_closed_unguarded = unguarded == use_guard_points.len()
                && !observation_enumeration_open
                && !observed_guard_classification_open;
            let validation = if every_required_use_is_closed_unguarded {
                ResultContractUseValidation::known(use_guard_points.len(), unguarded)
            } else {
                ResultContractUseValidation::violated_open(use_guard_points.len(), unguarded)
            };
            return attach_observed_result_uses(
                validation,
                &observed_uses,
                &required_uses,
                &verdicts,
            );
        }
        // Preserve candidate-local uncertainty on the row. The caller also
        // lowers run completion because a later relational filter can remove
        // this row and otherwise turn an unproved negative into a clean run.
        return attach_observed_result_uses(
            ResultContractUseValidation::unknown(use_guard_points.len()),
            &observed_uses,
            &required_uses,
            &vec![ResultUseGuardVerdict::Unknown; required_uses.len()],
        );
    }

    // Flow-state has already derived this procedure's dominator tree to mark
    // exact reaching definitions. Reuse that exact result: asking the control-
    // relation cache here would pay for the same tree a second time under an
    // unrelated ledger, once per positive procedure.
    // Keep normalized guard arms separate from modeled normal-return
    // continuations. A validated normal continuation can consume retained
    // control topology because every source-local normal successor remains in
    // the CFG. Retained evaluation order stays open unless flow-state proves
    // this exact validator result is an argument of the target invocation and
    // no intervening operand can replace or escape the predicate binding.
    let normal_return_answers = if normal_return_calls.is_empty() {
        None
    } else {
        Some(derivation.any_normal_return_dominates_result_uses(
            procedure,
            &result_establishment_points,
            &predicate_binding_values,
            &normal_return_calls,
            &use_guard_points,
            &use_target_calls,
        ))
    };
    let mut unguarded = 0usize;
    let mut guard_classification_open = false;
    let mut guard_verdicts = Vec::with_capacity(use_guard_points.len());
    for index in 0..use_guard_points.len() {
        let precedes_every_guard_subject_read = use_precedes_guard_subject_reads[index];
        let mut participating = false;
        let mut proven = false;
        let mut unknown = guard_evidence_open && !precedes_every_guard_subject_read;
        if let Some(answers) = &guard_answers {
            participating = true;
            match answers {
                Some(answers) => match answers[index] {
                    GuardDominanceAnswer::Proven => proven = true,
                    GuardDominanceAnswer::ClosedNegative => {}
                    GuardDominanceAnswer::Open => {
                        unknown |= !precedes_every_guard_subject_read;
                    }
                },
                None => unknown |= !precedes_every_guard_subject_read,
            }
        }
        if let Some(answers) = &normal_return_answers {
            participating = true;
            match answers {
                Some(answers) => proven |= answers[index],
                None => unknown |= !precedes_every_guard_subject_read,
            }
        }
        for candidate in &conditional_calls {
            participating = true;
            match conditional_predicate_use_answer(
                procedure,
                derivation,
                &result_establishment_points,
                candidate,
                index,
                use_guard_points[index],
                use_target_calls[index],
            ) {
                ConditionalPredicateUseAnswer::Positive => proven = true,
                ConditionalPredicateUseAnswer::ClosedNegative
                | ConditionalPredicateUseAnswer::Irrelevant => {}
                ConditionalPredicateUseAnswer::Open => {
                    unknown |= !precedes_every_guard_subject_read;
                }
            }
        }
        debug_assert!(participating, "a success candidate class is present");
        if proven {
            guard_verdicts.push(ResultUseGuardVerdict::Guarded);
            continue;
        }
        if use_guard_classification_open[index] {
            guard_classification_open = true;
            guard_verdicts.push(ResultUseGuardVerdict::Unknown);
            continue;
        }
        if unknown {
            guard_classification_open = true;
            guard_verdicts.push(ResultUseGuardVerdict::Unknown);
            continue;
        }
        unguarded += 1;
        guard_verdicts.push(ResultUseGuardVerdict::Unguarded);
    }
    let validation =
        if unguarded != 0 && (observation_enumeration_open || guard_classification_open) {
            ResultContractUseValidation::violated_open(use_guard_points.len(), unguarded)
        } else if observation_enumeration_open || guard_classification_open {
            ResultContractUseValidation::unknown(use_guard_points.len())
        } else {
            ResultContractUseValidation::known(use_guard_points.len(), unguarded)
        };
    attach_observed_result_uses(validation, &observed_uses, &required_uses, &guard_verdicts)
}

fn normal_return_refinement_calls(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    file: &ProjectFile,
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    condition_values: &HashSet<crate::analyzer::semantic::ValueId>,
    predicate: CompiledResultPredicate,
) -> Vec<CallSiteHandle> {
    let semantics = procedure.semantics();
    let mut candidates = Vec::new();
    for call in semantics.call_sites() {
        // A detached invocation only establishes that its task was scheduled.
        // Its callee has not returned on the parent continuation, so a modeled
        // normal-return refinement cannot guard a later parent operation.
        if call.invocation_mode != CallInvocationMode::Ordinary {
            continue;
        }
        if call.normal_continuation.target().is_none() {
            continue;
        }
        // A normal-return refinement can establish this exact condition only
        // when the condition value is passed directly to the refined
        // parameter. Filter on the structured semantic arguments before
        // dispatching: calls that cannot possibly refine this condition are
        // irrelevant, however many other calls the procedure contains.
        if !call.arguments.iter().any(|argument| {
            matches!(
                argument.expansion,
                CallArgumentExpansion::Direct(ArgumentDomain::Positional)
            ) && condition_values.contains(&argument.value)
        }) {
            continue;
        }
        let Some(range) = semantic_call_range(semantics, call) else {
            continue;
        };
        let answer = cache.dispatch_at_source(semantic, file, range);
        if answer.arms.is_empty() {
            continue;
        }
        let mut every_arm_closed = true;
        let mut common: Option<Vec<CompiledNormalReturnRefinement>> = None;
        for arm in &answer.arms {
            let key = match &arm.target_unit {
                Some(unit) => cache.key_for(analyzer, unit),
                None => arm.unmaterialized_target.as_ref().map(external_modeled_key),
            };
            let Some(key) = key else {
                common = Some(Vec::new());
                break;
            };
            let (refinements, closes) = match cache.answer_for(analyzer, &key) {
                ModelAnswer::Modeled {
                    complete,
                    covers_overrides,
                    normal_return_refinements,
                    ..
                } if !normal_return_refinements.is_empty() => (
                    normal_return_refinements,
                    complete && (covers_overrides || !key.has_receiver),
                ),
                ModelAnswer::Modeled { .. } | ModelAnswer::Conflict | ModelAnswer::Empty => {
                    common = Some(Vec::new());
                    break;
                }
            };
            every_arm_closed &= closes;
            match &mut common {
                None => common = Some(refinements),
                Some(common) => common.retain(|candidate| refinements.contains(candidate)),
            }
        }
        let exhaustive = answer.coverage
            == crate::analyzer::semantic::CandidateCoverage::Exhaustive
            || (answer.coverage == crate::analyzer::semantic::CandidateCoverage::Open
                && match answer.unnamed_boundaries.as_slice() {
                    [] => true,
                    ["unresolved"] => every_arm_closed,
                    _ => false,
                });
        if !exhaustive || !every_arm_closed {
            continue;
        }
        let establishes = common.unwrap_or_default().into_iter().any(|refinement| {
            refinement.predicate == predicate
                && call
                    .arguments
                    .get(refinement.parameter_ordinal as usize)
                    .is_some_and(|argument| {
                        matches!(
                            argument.expansion,
                            CallArgumentExpansion::Direct(ArgumentDomain::Positional)
                        ) && condition_values.contains(&argument.value)
                    })
        });
        if establishes {
            candidates.push(
                procedure
                    .call_site_handle(call.id)
                    .expect("validated semantic call has a scoped handle"),
            );
        }
    }
    candidates
}

fn result_contract_row_id(site_id: &str, contract: Option<&CompiledResultContract>) -> String {
    let mut digest = LengthDelimitedDigest::new(CALL_RESULT_CONTRACT_ID_DOMAIN);
    digest.push(site_id.as_bytes());
    if let Some(contract) = contract {
        digest.push(&contract.result_ordinal.to_le_bytes());
        if let (Some(condition_result_ordinal), Some(predicate)) =
            (contract.condition_result_ordinal, contract.predicate)
        {
            digest.push(&condition_result_ordinal.to_le_bytes());
            digest.push(result_predicate_label(predicate).as_bytes());
        } else {
            debug_assert!(
                contract.condition_result_ordinal.is_none() && contract.predicate.is_none(),
                "compiled result conditions are present or absent together"
            );
            debug_assert!(
                contract.result_success_predicate.is_some(),
                "direct result contracts carry a result-success predicate"
            );
            digest.push(b"direct-result-validity");
        }
        if let Some(predicate) = contract.result_success_predicate {
            digest.push(result_predicate_label(predicate).as_bytes());
        }
    } else {
        digest.push(b"terminal");
    }
    digest.finish().to_string()
}

fn result_contract_use_row_id(acquisition_id: &str, result_use: &ObservedResultUse) -> String {
    debug_assert!(
        result_use.parameter_ordinal.is_none()
            || result_use.use_kind == ResultContractUseKind::CallArgument,
        "only call-argument result uses may carry a parameter ordinal"
    );
    debug_assert!(
        result_use.use_kind != ResultContractUseKind::CallArgument
            || result_use.parameter_count.is_some() == result_use.parameter_ordinal.is_some(),
        "a call-argument formal count and ordinal are proved together"
    );
    let mut digest = LengthDelimitedDigest::new(RESULT_CONTRACT_USE_ID_DOMAIN);
    digest.push(acquisition_id.as_bytes());
    digest.push(result_use.point_id.as_bytes());
    digest.push(rel_path_string(&result_use.file).as_bytes());
    digest.push(&result_use.range.start_byte.to_le_bytes());
    digest.push(&result_use.range.end_byte.to_le_bytes());
    digest.push(result_use.use_kind.label().as_bytes());
    digest.push(result_use.timing.label().as_bytes());
    if let Some(ast_id) = &result_use.ast_id {
        digest.push(ast_id.as_bytes());
    }
    if let Some(site_id) = &result_use.operation_site_id {
        digest.push(site_id.as_bytes());
    }
    if let Some(parameter_ordinal) = result_use.parameter_ordinal {
        digest.push(&parameter_ordinal.to_le_bytes());
    }
    digest.finish().to_string()
}

pub(super) const fn result_predicate_label(predicate: CompiledResultPredicate) -> &'static str {
    match predicate {
        CompiledResultPredicate::Null => "null",
        CompiledResultPredicate::NonNull => "non_null",
        CompiledResultPredicate::True => "true",
        CompiledResultPredicate::False => "false",
    }
}

fn record_result_contract_dispatch_coverage(
    cache: &mut EffectTraversalCache,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    file: &ProjectFile,
    coverage: EffectCoverage,
) {
    record_result_contract_incomplete(
        cache,
        diagnostics,
        file,
        coverage,
        "dispatch did not establish one exhaustive result-contract answer",
    );
}

fn record_result_contract_guard_coverage(
    cache: &mut EffectTraversalCache,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    file: &ProjectFile,
    coverage: EffectCoverage,
) {
    record_result_contract_incomplete(
        cache,
        diagnostics,
        file,
        coverage,
        "success-guard projection did not establish one exhaustive result-contract answer",
    );
}

fn record_result_contract_use_coverage(
    cache: &mut EffectTraversalCache,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    file: &ProjectFile,
    coverage: EffectCoverage,
) {
    record_result_contract_incomplete(
        cache,
        diagnostics,
        file,
        coverage,
        "result-use validation did not establish one exhaustive success-guard answer",
    );
}

fn record_result_contract_incomplete(
    cache: &mut EffectTraversalCache,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    file: &ProjectFile,
    coverage: EffectCoverage,
    message: &'static str,
) {
    if coverage == EffectCoverage::Exhaustive {
        return;
    }
    cache.incomplete = true;
    cache.truncated |= coverage == EffectCoverage::Truncated;
    if !cache
        .result_contract_incomplete_diagnostics
        .insert((file.clone(), message))
    {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::ResultContractDerivationIncomplete,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: crate::analyzer::common::language_for_file(file).config_label(),
        message: format!("{message} in `{}`", rel_path_string(file)),
    });
}

/// Note a derivation's coverage on the query so the result's completion can
/// state the incompleteness once.
///
/// This is what keeps a non-exhaustive effect relation out of a clean absence
/// verdict: the relational evaluator reads the query's `CodeQueryCompletion`,
/// so a row that admits a missing effect must also make the query incomplete.
fn record_coverage(
    cache: &mut EffectTraversalCache,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    file: &ProjectFile,
    coverage: EffectCoverage,
) {
    let language = crate::analyzer::common::language_for_file(file).config_label();
    match coverage {
        EffectCoverage::Exhaustive => {}
        EffectCoverage::Truncated => {
            if !cache.truncated {
                cache.truncated = true;
                diagnostics.push(CodeQueryDiagnostic {
                    code: CodeQueryDiagnosticCode::EffectBudgetExhausted,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language,
                    message:
                        "effect derivation reached a bound; the retained effect set may be missing rows"
                            .to_owned(),
                });
            }
            cache.incomplete = true;
        }
        EffectCoverage::Open | EffectCoverage::Unsupported => {
            if !cache.incomplete {
                cache.incomplete = true;
                diagnostics.push(CodeQueryDiagnostic {
                    code: CodeQueryDiagnosticCode::EffectDerivationIncomplete,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language,
                    message:
                        "an unresolved or unmodeled callee leaves the effect set non-exhaustive"
                            .to_owned(),
                });
            }
        }
    }
}

/// One call site's dispatch answer, reduced to what both row families need.
struct DispatchedArms {
    status: CallEffectSiteStatus,
    arms: Vec<DispatchedArm>,
    call_contexts: Vec<super::dispatch::DispatchCallContext>,
}

/// One arm plus its exact semantic caller and optional graph target. Keeping
/// this association intact prevents a nested callable's source-contained call
/// from becoming an edge of its lexical parent.
struct DispatchedArm {
    effect: CallEffectArm,
    call_context: usize,
    callee: Option<CodeUnit>,
    external_callee: Option<ExternalEffectCallee>,
}

/// One external member an activated summary declares effects for: a leaf of the
/// effect graph, carrying those declarations and what establishes them.
#[derive(Debug, Clone)]
struct ExternalEffectCallee {
    key: ModeledProcedureKey,
    declared: Vec<BoundDeclaredEffect>,
    /// `CompleteSummary` when the summary is the member's whole effect set, so
    /// the leaf keeps its callers exhaustive. `Unestablished` when the pack
    /// declares effects the caller should still see but does not claim to state
    /// them all, so the leaf reports the same open coverage an unread body does.
    basis: EffectNodeBasis,
}

/// Classify one arm whose callee the workspace does not materialize, and mint
/// the graph leaf it contributes, if any.
///
/// Three answers are possible and the difference between them is the whole
/// honesty rule of this slice.
///
/// * A *complete* summary that also speaks for every implementation the
///   workspace cannot see is the arm's whole answer, so the arm closes. An
///   empty declared list under that condition is the reviewed claim "this
///   member performs no declared effect" -- the known-empty proof Milestone L
///   rests on -- and refusing to believe it is what made authored external
///   content inert here. "Speaks for every implementation" is #2371's rule
///   verbatim: an explicit `covers_overrides`, or a receiverless callee, which
///   has no overrides to cover and whose complete summary is therefore already
///   the whole statement.
/// * Any other summary still *declares* what it declares. Those effects reach
///   the caller, because a partial model of an external member is exactly how a
///   positive claim like "this writes to a stream" is authored, but the arm
///   does not close: an undeclared effect may still happen below it.
/// * A conflict between activated packs, and no summary at all, claim nothing.
fn external_arm_lookup(
    answer: ModelAnswer,
    key: &ModeledProcedureKey,
) -> (ArmLookup, Option<ExternalEffectCallee>) {
    let (complete, covers_overrides, effects) = match answer {
        ModelAnswer::Modeled {
            complete,
            covers_overrides,
            effects,
            ..
        } => (complete, covers_overrides, effects),
        ModelAnswer::Conflict => return (ArmLookup::Conflict, None),
        ModelAnswer::Empty => return (ArmLookup::Unmodeled { analyzable: false }, None),
    };
    let closes = complete && (covers_overrides || !key.has_receiver);
    if !closes && effects.is_empty() {
        return (ArmLookup::Unmodeled { analyzable: false }, None);
    }
    let leaf = ExternalEffectCallee {
        key: key.clone(),
        declared: effects.clone(),
        basis: if closes {
            EffectNodeBasis::CompleteSummary
        } else {
            EffectNodeBasis::Unestablished
        },
    };
    let lookup = if closes {
        ArmLookup::SummarizedExternal(effects)
    } else {
        ArmLookup::Declared(effects)
    };
    (lookup, Some(leaf))
}

/// Run dispatch at one call range and pair every arm with its pack answer.
fn dispatch_arms(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    file: &ProjectFile,
    range: Range,
) -> DispatchedArms {
    let answer = cache.dispatch_at_source(semantic, file, range);
    let mut arms = Vec::with_capacity(answer.arms.len());
    for arm in &answer.arms {
        let callee = arm.target_unit.clone();
        let mut external_callee = None;
        let proof = if arm.proof == "proven" {
            EffectProof::Proven
        } else {
            EffectProof::Unproven
        };
        let complete = arm.completeness == "complete";
        let (key, lookup, declaration_id) = match &arm.target_unit {
            Some(unit) => {
                let declaration_id = declaration_identity(analyzer, unit);
                match cache.key_for(analyzer, unit) {
                    Some(key) => {
                        let lookup = match cache.answer_for(analyzer, &key) {
                            ModelAnswer::Modeled { effects, .. } if !effects.is_empty() => {
                                ArmLookup::Declared(effects)
                            }
                            ModelAnswer::Conflict => ArmLookup::Conflict,
                            // The target is a workspace declaration with a
                            // readable body, so its own effects are reachable
                            // through propagation rather than missing. A
                            // summary that declares none therefore adds
                            // nothing, whatever its completeness claims.
                            ModelAnswer::Modeled { .. } | ModelAnswer::Empty => {
                                ArmLookup::Unmodeled { analyzable: true }
                            }
                        };
                        (Some(key), lookup, declaration_id)
                    }
                    None => (None, ArmLookup::Unkeyable, declaration_id),
                }
            }
            // The oracle named a target the workspace does not materialize, so
            // there is no declaration to key a lookup from. When the resolver
            // published the callee's canonical member identity, the activated
            // packs are asked for that identity directly -- the same lookup
            // #1978 binds a data-flow summary to an unmaterialized external
            // callee with. An arm the resolver could not name has no identity
            // at all and stays unmodeled, which is the #2579 family.
            None => match arm.unmaterialized_target.as_ref().map(external_modeled_key) {
                Some(key) => {
                    let (lookup, leaf) =
                        external_arm_lookup(cache.answer_for(analyzer, &key), &key);
                    external_callee = leaf;
                    (Some(key), lookup, None)
                }
                None => (None, ArmLookup::Unmodeled { analyzable: false }, None),
            },
        };
        arms.push(DispatchedArm {
            effect: CallEffectArm {
                target_id: arm.target_id.clone(),
                callee_declaration_id: declaration_id,
                key,
                proof,
                complete,
                execution_timing: arm.execution_timing,
                lookup,
            },
            call_context: arm.call_context,
            callee,
            external_callee,
        });
    }
    arms.sort_by(|left, right| {
        (&left.effect.target_id, left.call_context)
            .cmp(&(&right.effect.target_id, right.call_context))
    });
    // The site's coverage is read after the arms are classified: whether an
    // unresolved residual is discharged depends on what the activated packs
    // answered for the arms beside it.
    let coverage = site_coverage(&answer, &arms);
    let status = match answer.outcome {
        "resolved" | "ambiguous" => CallEffectSiteStatus::Answered { coverage },
        "unsupported" => CallEffectSiteStatus::Interrupted {
            reason: EffectReason::DispatchUnsupported,
        },
        "cancelled" | "exceeded_budget" => CallEffectSiteStatus::Interrupted {
            reason: EffectReason::DispatchInterrupted,
        },
        _ if arms.is_empty() => CallEffectSiteStatus::Interrupted {
            reason: EffectReason::DispatchUnresolved,
        },
        _ => CallEffectSiteStatus::Answered { coverage },
    };
    DispatchedArms {
        status,
        arms,
        call_contexts: answer.call_contexts.clone(),
    }
}

fn coverage_for(coverage: crate::analyzer::semantic::CandidateCoverage) -> EffectCoverage {
    use crate::analyzer::semantic::CandidateCoverage;
    match coverage {
        CandidateCoverage::Exhaustive => EffectCoverage::Exhaustive,
        CandidateCoverage::Open => EffectCoverage::Open,
        CandidateCoverage::Truncated => EffectCoverage::Truncated,
    }
}

/// The candidate coverage one site contributes to its effect rows: the dispatch
/// oracle's own answer, with two proof-carrying reinterpretations of `Open`.
///
/// `Open` is not one fact. `workspace_oracle::dispatch_coverage` publishes it
/// both when the callee simply has no workspace definition
/// (`DefinitionLookupStatus::NotFound` and its neighbours, which is every
/// external call) and when the oracle found a residual it could not name. Read
/// as "a callee may be missing", the first spelling makes an external call
/// permanently non-exhaustive no matter what a pack says about it, which is
/// what left authored external content unusable in this relation.
///
/// What actually says the arm set is incomplete is a residual boundary. Those
/// carry no locator, so they never become arms, and `unnamed_boundaries` is the
/// only place they are visible here. Two shapes upgrade:
///
/// * No residual at all, and at least one arm. Then the callee set is exactly
///   the arms, and whether the site is exhaustive is decided arm by arm by
///   `call_effect_report`: an unmodeled, unkeyable or conflicted arm still
///   opens it.
/// * Exactly one `unresolved` residual, at least one arm, and every arm closed
///   by an authored complete summary that speaks for the implementations the
///   workspace cannot see. This is #2371's external-residual discharge rule,
///   the same one `ValueFlowPlan::authored_arm_closure` applies to taint, held
///   to the same guards: a `truncated` residual, a second residual, an
///   `external` boundary that named nothing, and any arm the summary does not
///   close all refuse it.
///
/// The armless family of #2579 is untouched: those sites publish a residual and
/// no arm at all, so both shapes refuse them and no target-keyed content can
/// address them.
fn site_coverage(
    answer: &super::dispatch::DispatchSiteAnswer,
    arms: &[DispatchedArm],
) -> EffectCoverage {
    use crate::analyzer::semantic::CandidateCoverage;
    if answer.coverage != CandidateCoverage::Open || arms.is_empty() {
        return coverage_for(answer.coverage);
    }
    let residual_discharged = match answer.unnamed_boundaries.as_slice() {
        [] => true,
        ["unresolved"] => arms
            .iter()
            .all(|arm| arm.effect.lookup.is_closed_by_summary()),
        _ => false,
    };
    if residual_discharged {
        EffectCoverage::Exhaustive
    } else {
        EffectCoverage::Open
    }
}

/// The `declaration` domain's own identity for one workspace unit, so an
/// effect row joins a declaration row by id equality.
fn declaration_identity(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<String> {
    let range = analyzer
        .ranges_of(unit)
        .into_iter()
        .min_by_key(primary_range_key)?;
    let declaration = DeclarationValue::new(unit.clone(), range);
    Some(render::declaration_id(
        &rel_path_string(unit.source()),
        declaration.identity_kind_label(),
        &unit.fq_name(),
        range,
    ))
}

/// Derive the transitive effect summary of one declaration.
#[allow(clippy::too_many_arguments)]
pub(super) fn procedure_effect_expansions(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    cache_profile: &mut Option<QueryCacheProfile>,
    declaration: &DeclarationValue,
) -> Vec<PipelineExpansion> {
    let Some(identity) = declaration_identity(analyzer, &declaration.unit) else {
        return Vec::new();
    };
    let report = match cache.reports.get(&identity) {
        Some(report) => Arc::clone(report),
        None => {
            let graph = discover_effect_graph(
                analyzer,
                semantic,
                cache,
                budget,
                limits,
                cancellation,
                diagnostics,
                cache_profile,
                declaration,
                ProcedureEffectBudget::default(),
            );
            let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
            let mut selected = None;
            for report in reports {
                let report = Arc::new(report);
                if report.procedure_declaration_id == identity {
                    selected = Some(Arc::clone(&report));
                }
                cache
                    .reports
                    .insert(report.procedure_declaration_id.clone(), report);
            }
            match selected {
                Some(report) => report,
                None => return Vec::new(),
            }
        }
    };
    record_coverage(
        cache,
        diagnostics,
        declaration.unit.source(),
        report.coverage,
    );
    let subject = ProcedureEffectSubject {
        declaration: declaration.clone(),
        report,
    };
    (0..subject.report.rows.len())
        .map(|index| {
            pipeline_expansion(PipelineValue::ProcedureEffect(Box::new(
                ProcedureEffectValue {
                    subject: subject.clone(),
                    index,
                },
            )))
        })
        .collect()
}

/// Walk the reachable call graph of one declaration, breadth first, bounded.
///
/// A callee is either a workspace callable the dispatch answer named, which the
/// walk queues and reads the body of, or an external member a complete
/// activated summary models, which enters the graph as a leaf: its own callees
/// are outside the workspace and are not analyzable, so it has no outgoing
/// edge, and the summary is what establishes its effect set. Admitting the leaf
/// is what lets a positive declaration on an external member reach a workspace
/// caller's `procedure_effect` rows instead of only closing the call site's own
/// coverage.
///
/// A call whose target the workspace does not index and no pack models, an
/// ambiguous dispatch and an exhausted bound each become a typed gap on the
/// *calling* procedure, so the fixpoint can degrade that procedure's coverage
/// rather than losing the fact.
#[allow(clippy::too_many_arguments)]
fn discover_effect_graph(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    cache_profile: &mut Option<QueryCacheProfile>,
    root: &DeclarationValue,
    bounds: ProcedureEffectBudget,
) -> EffectGraph {
    let mut graph = EffectGraph::default();
    let mut index_by_unit: HashMap<CodeUnit, usize> = HashMap::default();
    // External leaves are keyed by their canonical member identity rather than
    // by a workspace unit, so two call sites naming the same external member
    // share one node and one edge target.
    let mut index_by_external: HashMap<ModeledProcedureKey, usize> = HashMap::default();
    let mut queue: Vec<(CodeUnit, usize)> = Vec::new();

    let push_node = |graph: &mut EffectGraph,
                     index_by_unit: &mut HashMap<CodeUnit, usize>,
                     cache: &mut EffectTraversalCache,
                     unit: &CodeUnit|
     -> Option<usize> {
        if let Some(index) = index_by_unit.get(unit) {
            return Some(*index);
        }
        if graph.procedures.len() >= bounds.max_procedures {
            graph.truncated = true;
            return None;
        }
        let identity = declaration_identity(analyzer, unit)?;
        let declared = match cache.key_for(analyzer, unit) {
            Some(key) => match cache.answer_for(analyzer, &key) {
                ModelAnswer::Modeled { effects, .. } => effects,
                ModelAnswer::Conflict | ModelAnswer::Empty => Vec::new(),
            },
            None => Vec::new(),
        };
        let index = graph.procedures.len();
        graph.procedures.push(EffectGraphProcedure {
            declaration_id: identity,
            display_name: unit.fq_name(),
            declared,
            basis: EffectNodeBasis::Unestablished,
            local_gaps: Vec::new(),
        });
        index_by_unit.insert(unit.clone(), index);
        Some(index)
    };

    // The leaf admission charges the same procedure bound a workspace node
    // does, so an authored external member cannot buy extra graph capacity.
    let push_external_node = |graph: &mut EffectGraph,
                              index_by_external: &mut HashMap<ModeledProcedureKey, usize>,
                              external: &ExternalEffectCallee|
     -> Option<usize> {
        if let Some(index) = index_by_external.get(&external.key) {
            return Some(*index);
        }
        if graph.procedures.len() >= bounds.max_procedures {
            graph.truncated = true;
            return None;
        }
        let index = graph.procedures.len();
        graph.procedures.push(EffectGraphProcedure {
            declaration_id: external_procedure_identity(&external.key),
            display_name: external.key.display(),
            declared: external.declared.clone(),
            basis: external.basis,
            local_gaps: Vec::new(),
        });
        index_by_external.insert(external.key.clone(), index);
        Some(index)
    };

    if push_node(&mut graph, &mut index_by_unit, cache, &root.unit).is_none() {
        return graph;
    }
    queue.push((root.unit.clone(), 0));

    let mut cursor = 0usize;
    while cursor < queue.len() {
        let (unit, depth) = queue[cursor].clone();
        cursor += 1;
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            graph.truncated = true;
            break;
        }
        let Some(node) = index_by_unit.get(&unit).copied() else {
            continue;
        };
        if depth > bounds.max_depth {
            graph.truncated = true;
            continue;
        }
        let file = unit.source().clone();
        let facts = match cache.facts.get(&file) {
            Some(facts) => facts.clone(),
            None => {
                let resolved = match receiver::receiver_facts_for_pipeline_row(
                    analyzer,
                    &[],
                    &file,
                    &mut HashMap::default(),
                    budget,
                    limits,
                    cancellation,
                    diagnostics,
                    cache_profile,
                ) {
                    PipelineReceiverFacts::Available(facts) => Some(facts),
                    PipelineReceiverFacts::Unavailable | PipelineReceiverFacts::Halted => None,
                };
                cache.facts.insert(file.clone(), resolved.clone());
                resolved
            }
        };
        let Some(facts) = facts else {
            continue;
        };
        let ranges = analyzer.ranges_of(&unit);
        let Some(span) = ranges.into_iter().min_by_key(primary_range_key) else {
            continue;
        };
        graph.procedures[node].basis = EffectNodeBasis::BodyRead;

        let mut call_nodes = facts
            .nodes()
            .iter()
            .enumerate()
            .filter(|(_, fact)| fact.kind == NormalizedKind::Call)
            .filter(|(_, fact)| {
                fact.range.start_byte >= span.start_byte && fact.range.end_byte <= span.end_byte
            })
            .map(|(id, fact)| (fact.range.start_byte, fact.range.end_byte, id))
            .collect::<Vec<_>>();
        call_nodes.sort_unstable();
        if call_nodes.len() > MAX_CALL_SITES_PER_PROCEDURE {
            call_nodes.truncate(MAX_CALL_SITES_PER_PROCEDURE);
            graph.truncated = true;
        }

        for (_, _, call_id) in call_nodes {
            if graph.edges.len() >= bounds.max_edges {
                graph.truncated = true;
                break;
            }
            let call_id = match u32::try_from(call_id) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let Some(shape) = call_shape_for_call(&facts, &file, call_id) else {
                continue;
            };
            // A curried sequence reports one site from any of its nodes, so
            // only the site whose own outcome range starts here contributes an
            // edge; the rest would be duplicates of it.
            if shape.outcome.range.start_byte != facts.node(call_id).range.start_byte {
                continue;
            }
            let DispatchedArms {
                status,
                arms,
                call_contexts,
            } = dispatch_arms(
                analyzer,
                semantic,
                cache,
                &shape.outcome.file,
                shape.outcome.range,
            );
            let matching_contexts = call_contexts
                .iter()
                .enumerate()
                .filter_map(|(index, context)| {
                    (context.caller_is_exact && context.caller.as_ref() == Some(&unit))
                        .then_some(index)
                })
                .collect::<HashSet<_>>();
            let unknown_caller = call_contexts.iter().any(|context| context.caller.is_none());
            if matching_contexts.is_empty() {
                if call_contexts.is_empty() || unknown_caller {
                    graph.procedures[node]
                        .local_gaps
                        .push(EffectReason::DispatchUnresolved);
                }
                // Every exact context belongs to another semantic procedure:
                // this is a source-contained call in a nested declaration,
                // not an edge of the procedure currently being summarized.
                continue;
            }
            if unknown_caller {
                graph.procedures[node]
                    .local_gaps
                    .push(EffectReason::DispatchUnresolved);
            }
            let arms = arms
                .into_iter()
                .filter(|arm| matching_contexts.contains(&arm.call_context))
                .collect::<Vec<_>>();
            let site_coverage = match status {
                CallEffectSiteStatus::Answered { coverage } => coverage,
                CallEffectSiteStatus::Interrupted { reason } => {
                    graph.procedures[node].local_gaps.push(reason);
                    EffectCoverage::Open
                }
            };
            if !site_coverage.is_exhaustive() {
                graph.procedures[node]
                    .local_gaps
                    .push(EffectReason::DispatchUnresolved);
            }
            let exact_site = site_coverage.is_exhaustive() && arms.len() == 1 && !unknown_caller;
            for arm in &arms {
                match &arm.effect.lookup {
                    ArmLookup::Unkeyable => {
                        graph.procedures[node]
                            .local_gaps
                            .push(EffectReason::CalleeUnkeyable);
                    }
                    ArmLookup::Conflict => {
                        graph.procedures[node]
                            .local_gaps
                            .push(EffectReason::ModelConflict);
                    }
                    ArmLookup::Unmodeled { analyzable: false } => {
                        graph.procedures[node]
                            .local_gaps
                            .push(EffectReason::CalleeUnmodeled);
                    }
                    ArmLookup::Declared(_)
                    | ArmLookup::SummarizedExternal(_)
                    | ArmLookup::Unmodeled { analyzable: true } => {}
                }
            }
            for arm in arms {
                let certainty = if exact_site {
                    EffectCertainty::Definite
                } else {
                    EffectCertainty::Possible
                };
                if let Some(callee_unit) = arm.callee {
                    let Some(callee) =
                        push_node(&mut graph, &mut index_by_unit, cache, &callee_unit)
                    else {
                        graph.procedures[node]
                            .local_gaps
                            .push(EffectReason::ProcedureBudgetExhausted);
                        continue;
                    };
                    graph.edges.push(EffectGraphEdge {
                        caller: node,
                        callee,
                        site_id: shape.outcome.site_id.clone(),
                        certainty,
                        execution_timing: arm.effect.execution_timing,
                    });
                    // A callee already queued is already going to be walked at
                    // a depth no greater than this one. The fixpoint below,
                    // rather than this walk, resolves cycles.
                    if queue.iter().all(|(queued, _)| queued != &callee_unit) {
                        queue.push((callee_unit, depth.saturating_add(1)));
                    }
                }
                // An external modeled member is a graph leaf: there is no
                // workspace body to queue, but the exact call timing still
                // composes with its declared effects.
                if let Some(external) = arm.external_callee {
                    let Some(callee) =
                        push_external_node(&mut graph, &mut index_by_external, &external)
                    else {
                        graph.procedures[node]
                            .local_gaps
                            .push(EffectReason::ProcedureBudgetExhausted);
                        continue;
                    };
                    graph.edges.push(EffectGraphEdge {
                        caller: node,
                        callee,
                        site_id: shape.outcome.site_id.clone(),
                        certainty,
                        execution_timing: arm.effect.execution_timing,
                    });
                }
            }
        }
        graph.procedures[node].local_gaps.sort_unstable();
        graph.procedures[node].local_gaps.dedup();
    }

    graph.edges.sort_by(|left, right| {
        (
            left.caller,
            left.callee,
            &left.site_id,
            left.execution_timing,
        )
            .cmp(&(
                right.caller,
                right.callee,
                &right.site_id,
                right.execution_timing,
            ))
    });
    graph.edges.dedup();
    graph
}

#[cfg(test)]
#[allow(clippy::duplicate_mod)]
#[path = "../../../../../test-support/inline_project.rs"]
mod inline_project;

#[cfg(test)]
mod modeled_call_target_window_tests {
    use super::inline_project::InlineTestProject;
    use super::*;
    use crate::analyzer::AnalyzerConfig;
    use crate::analyzer::semantic::{SemanticBudget, SemanticRequest};

    #[test]
    fn direct_boolean_result_predicates_select_the_typed_guard_arms() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "main.go",
                r#"package main
func observe() {}
func inspect(ok bool) {
    if ok { observe() } else { observe() }
}
"#,
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("main.go");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Go artifact materialization");
        let artifact = outcome
            .available_value()
            .expect("Go artifact remains available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("inspect")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("inspect procedure");
        let [guard] = procedure.semantics().guard_facts() else {
            panic!("one direct Boolean guard: {:#?}", procedure.semantics());
        };
        assert!(matches!(guard.predicate, GuardPredicate::Opaque { .. }));
        let subject = guard
            .subject
            .expect("a direct guard names its Boolean value");
        let subjects = [subject].into_iter().collect::<HashSet<_>>();
        let true_edges =
            normalized_success_guard_edges(&procedure, &subjects, CompiledResultPredicate::True);
        let false_edges =
            normalized_success_guard_edges(&procedure, &subjects, CompiledResultPredicate::False);

        assert_eq!(
            true_edges.iter().map(|edge| edge.id()).collect::<Vec<_>>(),
            [guard.true_edge.expect("the true arm is retained")]
        );
        assert_eq!(
            false_edges.iter().map(|edge| edge.id()).collect::<Vec<_>>(),
            [guard.false_edge.expect("the false arm is retained")]
        );
        assert_eq!(
            opposite_result_predicate(CompiledResultPredicate::True),
            CompiledResultPredicate::False
        );
        assert_eq!(
            opposite_result_predicate(CompiledResultPredicate::False),
            CompiledResultPredicate::True
        );
    }

    #[test]
    fn failure_use_identity_includes_the_consumer_call_site() {
        let operand = crate::analyzer::semantic::ValueId::new(7);
        let first = result_contract_failure_use_row_id(
            "acquisition",
            Some("failure-edge"),
            "point",
            Some("call-one"),
            Some("shape-one"),
            operand,
            crate::query::FailureUseConsumer::CallArgument,
            Some(0),
        );
        let second = result_contract_failure_use_row_id(
            "acquisition",
            Some("failure-edge"),
            "point",
            Some("call-two"),
            Some("shape-two"),
            operand,
            crate::query::FailureUseConsumer::CallArgument,
            Some(0),
        );
        let returned = result_contract_failure_use_row_id(
            "acquisition",
            Some("failure-edge"),
            "point",
            None,
            None,
            operand,
            crate::query::FailureUseConsumer::Return,
            None,
        );
        assert_ne!(first, second);
        assert_ne!(first, returned);
    }

    #[test]
    fn failure_candidate_inventory_scopes_omitted_calls_to_their_points() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "main.go",
                r#"package main
func inspect(value any) {
    switch value.(type) {
    case bool:
        return
    }
}
"#,
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("main.go");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Go artifact materialization");
        let artifact = outcome
            .available_value()
            .cloned()
            .expect("Go artifact remains available");
        let procedure = artifact
            .procedure_handle(artifact.procedures().first().expect("one procedure").id())
            .expect("procedure handle");

        let candidates = failure_use_candidates(&procedure, None, None);
        assert!(
            !candidates.globally_open,
            "a point-scoped omission must not poison every failure arm"
        );
        assert!(
            !candidates.point_call_gaps.is_empty(),
            "the omitted call remains attached to its exact CFG point"
        );
        assert!(
            procedure.semantics().gaps().iter().any(|gap| {
                gap.capability == SemanticCapability::Calls
                    && matches!(gap.subject, SemanticGapSubject::Point)
            }),
            "the regression must exercise an actual caller-side Calls gap"
        );
    }

    #[test]
    fn active_cleanup_completion_keeps_negative_return_classification_open() {
        const SOURCE: &str = r#"package main

type item struct { value int }

func acquire() int { return 1 }
func cleanup() { recover() }

func inspect(input *item) (result int) {
    defer cleanup()
    result = acquire()
    _ = input.value
    select {}
}
"#;
        let project = InlineTestProject::with_language(Language::Go)
            .file("main.go", SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("main.go");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Go artifact materialization");
        let artifact = outcome
            .available_value()
            .cloned()
            .expect("Go artifact remains available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("inspect")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("inspect procedure");
        assert!(procedure.semantics().gaps().iter().any(|gap| {
            gap.discharge == SemanticGapDischarge::ExitOnlyProcedureCompletion
                && gap.capability == SemanticCapability::ExceptionalControlFlow
                && gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
        }));
        let acquisition = procedure
            .semantics()
            .call_sites()
            .iter()
            .find(|call| {
                let mapping = procedure
                    .semantics()
                    .source_mapping(call.source)
                    .expect("a call has a source mapping");
                let span = mapping.locator.anchor().span();
                &SOURCE[span.start_byte() as usize..span.end_byte() as usize] == "acquire()"
            })
            .expect("acquire call");
        assert!(
            acquisition.result.is_some() || !acquisition.normal_results.is_empty(),
            "the regression requires a retained call result"
        );
        assert!(
            !procedure.semantics().points().iter().any(|point| {
                point.events.iter().any(|event| {
                    matches!(
                        event.effect,
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Return | ValueFlowKind::IndexedReturn { .. },
                            ..
                        }
                    )
                })
            }),
            "the marker, not a retained normal return, must keep classification open"
        );
        let mut flow_cache = super::super::flow_state::FlowStateTraversalCache::default();
        let state = flow_cache.for_materialized_procedure(
            &workspace,
            &file,
            outcome,
            &procedure,
            Some(&cancellation),
        );
        let derivation = state
            .procedures
            .iter()
            .find(|candidate| candidate.procedure == procedure.id())
            .expect("flow state for inspect");

        assert_eq!(
            call_result_return_classification(&procedure, Some(derivation), acquisition),
            ReturnedCallClassification::Open,
            "panic recovery can implicitly return the named result, so NotReturned is unsound"
        );
    }

    #[test]
    fn result_use_identity_keeps_event_local_and_universal_closure_separate() {
        let reused = crate::analyzer::semantic::ValueId::new(0);
        let closed = crate::analyzer::semantic::ValueId::new(1);
        let identities =
            read_identity_closure([(0, reused, true), (1, closed, true), (2, reused, false)]);

        assert_eq!(identities.by_event.get(&0), Some(&true));
        assert_eq!(identities.by_event.get(&2), Some(&false));
        assert_eq!(identities.every_event_by_value.get(&reused), Some(&false));
        assert_eq!(identities.every_event_by_value.get(&closed), Some(&true));
    }

    #[test]
    fn same_point_second_subject_read_is_not_excluded() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "main.go",
                "package main\nfunc identity(value int) int { return value }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("main.go");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Go artifact materialization");
        let artifact = outcome
            .available_value()
            .cloned()
            .expect("Go artifact remains available");
        let semantics = artifact.procedures().first().expect("one Go procedure");
        let procedure = artifact
            .procedure_handle(semantics.id())
            .expect("procedure handle");
        let mut flow_cache = super::super::flow_state::FlowStateTraversalCache::default();
        let state = flow_cache.for_materialized_procedure(
            &workspace,
            &file,
            outcome,
            &procedure,
            Some(&cancellation),
        );
        let derivation = state
            .procedures
            .iter()
            .find(|candidate| candidate.procedure == procedure.id())
            .expect("flow state for the selected procedure");
        let point = procedure.semantics().entry_point();

        assert_eq!(
            &*uses_before_every_guard_subject_read(
                &procedure,
                derivation,
                &[point],
                &[Some(point)],
                &[Some(7)],
                &[(7, point)],
                true,
            ),
            &[true],
            "the operation's own exact subject-read event is harmless"
        );
        assert_eq!(
            &*uses_before_every_guard_subject_read(
                &procedure,
                derivation,
                &[point],
                &[Some(point)],
                &[Some(7)],
                &[(7, point), (8, point)],
                true,
            ),
            &[false],
            "a distinct subject read at the same point remains a possible guard frontier"
        );
    }

    fn state_read(
        event: usize,
        value: crate::analyzer::semantic::ValueId,
        file: ProjectFile,
        range: Range,
    ) -> crate::structural::flow_state::StateEventRow {
        crate::structural::flow_state::StateEventRow {
            event,
            procedure: crate::analyzer::semantic::ProcedureId::new(0),
            event_class: StateEventClass::Read,
            subject: crate::structural::flow_state::FlowSubject::Binding { value },
            point: crate::analyzer::semantic::ProgramPointId::new(0),
            point_id: "point".into(),
            value,
            site: crate::structural::flow_state::StateEventSite {
                file,
                range,
                ast_id: None,
            },
            generation: 0,
        }
    }

    #[test]
    fn direct_receiver_read_join_requires_one_exact_site() {
        let root = std::env::temp_dir().join("bifrost-rql-result-receiver-read");
        let file = ProjectFile::new(&root, "main.go");
        let other_file = ProjectFile::new(&root, "other.go");
        let receiver = crate::analyzer::semantic::ValueId::new(0);
        let other_value = crate::analyzer::semantic::ValueId::new(1);
        let receiver_range = Range {
            start_byte: 17,
            end_byte: 21,
            start_line: 2,
            end_line: 2,
        };
        let other_range = Range {
            start_byte: 30,
            end_byte: 34,
            start_line: 3,
            end_line: 3,
        };
        let exact = state_read(0, receiver, file.clone(), receiver_range);
        let wrong_range = state_read(1, receiver, file.clone(), other_range);
        let wrong_value = state_read(2, other_value, file.clone(), receiver_range);
        let wrong_file = state_read(3, receiver, other_file, receiver_range);

        assert_eq!(
            unique_exact_receiver_read(
                receiver,
                &file,
                receiver_range,
                &[&exact, &wrong_range, &wrong_value, &wrong_file],
            )
            .map(|read| read.event),
            Some(0)
        );
        assert_eq!(
            unique_exact_receiver_read(receiver, &file, receiver_range, &[&wrong_range]),
            None
        );

        let duplicate = state_read(4, receiver, file.clone(), receiver_range);
        assert_eq!(
            unique_exact_receiver_read(receiver, &file, receiver_range, &[&exact, &duplicate]),
            None,
            "ambiguous read identity must fail open"
        );
    }

    #[test]
    fn intrinsic_subject_read_join_uses_value_identity_across_points() {
        let root = std::env::temp_dir().join("bifrost-rql-result-intrinsic-read");
        let file = ProjectFile::new(&root, "main.go");
        let value = crate::analyzer::semantic::ValueId::new(0);
        let other_value = crate::analyzer::semantic::ValueId::new(1);
        let range = Range {
            start_byte: 17,
            end_byte: 21,
            start_line: 2,
            end_line: 2,
        };
        let mut operand_read = state_read(0, value, file.clone(), range);
        operand_read.point = crate::analyzer::semantic::ProgramPointId::new(1);
        let intrinsic_operation_point = crate::analyzer::semantic::ProgramPointId::new(2);
        assert_ne!(
            operand_read.point, intrinsic_operation_point,
            "Go evaluates the operand before the intrinsic field load or dereference"
        );
        let other = state_read(1, other_value, file.clone(), range);
        let reads = [(&operand_read, false), (&other, false)];
        assert_eq!(
            unique_exact_intrinsic_subject_read(value, &reads, &HashSet::default())
                .map(|read| read.event),
            Some(0),
            "the exact operand ValueId joins across distinct evaluation points"
        );

        let duplicate = state_read(2, value, file, range);
        assert_eq!(
            unique_exact_intrinsic_subject_read(
                value,
                &[(&operand_read, false), (&duplicate, false)],
                &HashSet::default(),
            ),
            None,
            "ambiguous reads of one semantic value must stay open"
        );
        assert_eq!(
            unique_exact_intrinsic_subject_read(
                value,
                &[(&operand_read, false)],
                &std::iter::once(operand_read.event).collect(),
            ),
            None,
            "candidate-local uncertainty keeps the exact operation open"
        );
    }

    fn bound_contract(fresh_allocation: bool) -> BoundResultContract {
        BoundResultContract {
            contract: CompiledResultContract {
                result_ordinal: 0,
                condition_result_ordinal: Some(1),
                predicate: Some(CompiledResultPredicate::Null),
                result_success_predicate: None,
                member_contracts: Vec::new(),
            },
            fresh_allocation,
            pack_id: Some("pack".to_owned()),
            model_id: Some("model".to_owned()),
            summary_id: Some("summary".to_owned()),
        }
    }

    #[test]
    fn common_result_contract_requires_fresh_allocation_on_every_arm() {
        let mut common = vec![bound_contract(true)];

        retain_common_result_contracts(&mut common, &[bound_contract(false)]);

        assert_eq!(common.len(), 1);
        assert!(
            !common[0].fresh_allocation,
            "one non-fresh dispatch arm prevents a universal fresh-result claim"
        );
    }

    #[test]
    fn common_result_contract_omits_nonunanimous_provenance() {
        let mut common = vec![bound_contract(true)];
        let mut other = bound_contract(true);
        other.summary_id = Some("other-summary".to_owned());

        retain_common_result_contracts(&mut common, &[other]);

        assert_eq!(common.len(), 1);
        assert_eq!(common[0].pack_id, None);
        assert_eq!(common[0].model_id, None);
        assert_eq!(common[0].summary_id, None);
    }

    fn lookup() -> ModeledCallTargetLookup {
        ModeledCallTargetLookup {
            arms: Vec::new(),
            adjudicable_workspace_names: Vec::new(),
            call_application: ModeledCallApplication::Unknown,
            coverage: ModeledCallTargetCoverage::Unmodeled,
        }
    }

    #[test]
    fn assignment_conversion_join_is_all_or_none_for_one_raw_result() {
        let source = crate::analyzer::semantic::ValueId::new(0);
        let other_source = crate::analyzer::semantic::ValueId::new(1);
        let first_converted = crate::analyzer::semantic::ValueId::new(2);
        let second_converted = crate::analyzer::semantic::ValueId::new(3);
        let first_binding = crate::analyzer::semantic::ValueId::new(4);
        let second_binding = crate::analyzer::semantic::ValueId::new(5);
        let other_binding = crate::analyzer::semantic::ValueId::new(6);
        let converted = [first_converted, second_converted];
        let mut index = ResultUseIndex::default();
        index
            .assignment_conversion_sources_by_converted_value
            .insert(first_converted, vec![source]);
        index
            .assignment_conversion_sources_by_converted_value
            .insert(second_converted, vec![source]);
        index
            .assigned_bindings_by_converted_value
            .insert(first_converted, vec![first_binding]);
        index
            .assigned_bindings_by_converted_value
            .insert(second_converted, vec![second_binding]);

        assert_eq!(
            index.exact_assignment_conversion_bindings(source, &converted),
            Some(vec![
                (first_converted, first_binding),
                (second_converted, second_binding),
            ])
        );

        let boundary_point = crate::analyzer::semantic::ProgramPointId::new(0);
        let later_point = crate::analyzer::semantic::ProgramPointId::new(1);
        let flow_values = [source, first_converted, second_converted]
            .into_iter()
            .collect::<HashSet<_>>();
        let boundary_bindings = [first_binding, second_binding]
            .into_iter()
            .collect::<HashSet<_>>();
        let boundary_points = [boundary_point].into_iter().collect::<HashSet<_>>();
        assert!(!index.has_relevant_assignment_value_flow_gap(
            &flow_values,
            &boundary_bindings,
            &boundary_points,
        ));
        index
            .value_flow_gap_points_by_value
            .entry(source)
            .or_default()
            .insert(later_point);
        assert!(index.has_relevant_assignment_value_flow_gap(
            &flow_values,
            &boundary_bindings,
            &boundary_points,
        ));
        index.value_flow_gap_points_by_value.clear();
        index
            .assignment_value_flow_gap_points
            .insert(boundary_point);
        assert!(index.has_relevant_assignment_value_flow_gap(
            &flow_values,
            &boundary_bindings,
            &boundary_points,
        ));
        index.assignment_value_flow_gap_points.clear();
        index
            .value_flow_gap_points_by_value
            .entry(first_binding)
            .or_default()
            .insert(later_point);
        assert!(
            !index.has_relevant_assignment_value_flow_gap(
                &flow_values,
                &boundary_bindings,
                &boundary_points,
            ),
            "a later binding gap remains the alias closure's responsibility"
        );
        index
            .value_flow_gap_points_by_value
            .get_mut(&first_binding)
            .expect("first binding gap points")
            .insert(boundary_point);
        assert!(index.has_relevant_assignment_value_flow_gap(
            &flow_values,
            &boundary_bindings,
            &boundary_points,
        ));
        index.value_flow_gap_points_by_value.clear();

        index
            .assignment_conversion_sources_by_converted_value
            .get_mut(&second_converted)
            .expect("second conversion source")
            .push(other_source);
        assert_eq!(
            index.exact_assignment_conversion_bindings(source, &converted),
            None,
            "one multi-source conversion opens the complete raw result"
        );

        index
            .assignment_conversion_sources_by_converted_value
            .insert(second_converted, vec![source]);
        index
            .assigned_bindings_by_converted_value
            .get_mut(&second_converted)
            .expect("second conversion binding")
            .push(other_binding);
        assert_eq!(
            index.exact_assignment_conversion_bindings(source, &converted),
            None,
            "one multi-destination conversion opens the complete raw result"
        );
    }

    #[test]
    fn effect_file_window_releases_file_local_caches() {
        let root = std::env::temp_dir().join("bifrost-rql-modeled-target-window");
        let first = ProjectFile::new(&root, "first.go");
        let second = ProjectFile::new(&root, "second.go");
        let mut cache = EffectTraversalCache {
            result_member_call_shapes: Some(ResultMemberCallShapeWindow {
                file: first.clone(),
                shapes: Some(Arc::new(ResultMemberCallShapesByRange::default())),
            }),
            ..EffectTraversalCache::default()
        };
        cache.result_assignment_conversion_proofs.get_mut().insert(
            ResultAssignmentConversionProofKey {
                file: first.clone(),
                modeled_target: ModeledProcedureKey {
                    language: "go".to_owned(),
                    owner: "net".to_owned(),
                    member: "Listen".to_owned(),
                    has_receiver: false,
                    parameter_count: 2,
                },
                result_ordinal: 1,
                binding_declaration: Range {
                    start_byte: 0,
                    end_byte: 3,
                    start_line: 1,
                    end_line: 1,
                },
                source_identity: ContentIdentity::hash_bytes(b"var err error"),
            },
            true,
        );
        cache.exact_source_identities.get_mut().insert(
            first.clone(),
            Some(ContentIdentity::hash_bytes(b"var err error")),
        );
        cache.replace_modeled_call_target_window(
            first,
            [
                ("first-a".to_owned(), lookup()),
                ("first-b".to_owned(), lookup()),
            ]
            .into_iter()
            .collect(),
        );
        assert_eq!(
            cache
                .modeled_call_targets
                .as_ref()
                .expect("first file window")
                .lookups
                .len(),
            2
        );

        cache.replace_modeled_call_target_window(
            second.clone(),
            [("second".to_owned(), lookup())].into_iter().collect(),
        );
        let window = cache
            .modeled_call_targets
            .as_ref()
            .expect("replacement file window");
        assert_eq!(window.file, second);
        assert_eq!(window.lookups.len(), 1);
        assert!(window.lookups.contains_key("second"));

        cache.release_file_window();
        assert!(cache.result_member_call_shapes.is_none());
        assert!(cache.modeled_call_targets.is_none());
        assert!(
            cache
                .result_assignment_conversion_proofs
                .borrow()
                .is_empty()
        );
        assert!(cache.exact_source_identities.borrow().is_empty());
    }
}
