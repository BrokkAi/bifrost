//! Workspace-level execution of a structural query (`query_code`): scope by
//! path globs and languages, derive the planner's positive anchors and query
//! requirements, run the matcher over deterministic candidates until `limit+1`
//! global matches prove truncation (facts come from the per-analyzer cache,
//! extraction happens on miss from in-memory source), then render the first
//! `limit` matches with captures, enclosing symbols, and capability
//! diagnostics.

use super::execution::derived::{
    DerivedLayer, DerivedLayerAcquisition, DerivedLayerBuildMetrics, DerivedLayerLifecycle,
    DerivedLayerRequest, DirectImportTopology, DirectImportTopologyLimits,
    RequestLocalDirectImportGraph, build_direct_import_topology,
};
use super::execution::plan::{
    CodeQueryExplain, LogicalQueryOperator, LogicalQueryPlan, PhysicalQueryNodeId,
    PhysicalQueryOperator, PhysicalQueryPlan,
};
use super::execution::profile::{
    CodeQueryProfile, QueryAccessPathProfile, QueryAccessPathTermProfile, QueryCacheProfile,
    QueryExecutionProfile, QueryOperatorDisposition, QueryOperatorProfile,
    QueryOperatorTermination, QueryOperatorWorkProfile, QueryRetainedValueCensus,
    QueryRetainedValueKind,
};
use super::execution::scheduler::BoundedReadyScheduler;
use super::facts::{FileFacts, Span};
use super::index::{
    QueryStructuralIndexSession, STRUCTURAL_INDEX_REPRESENTATION_VERSION, SnapshotStructuralIndex,
    StructuralCandidateSet, StructuralIndexAcquisition, StructuralIndexBuildMetrics,
    StructuralIndexLifecycle,
};
use super::kinds::{NormalizedKind, Role};
use super::matcher::FactMatch;
use super::planner::{QueryPlan, SourceAnchorGroup};
use super::provider::{
    StructuralFactsCacheOutcome, StructuralFactsLimitedOutcome, StructuralSearchProvider,
    StructuralSourceLimitedOutcome,
};
use super::query::schema::{reference_kind_label, usage_proof_label};
use super::query::{
    CallInputSelector, CallSiteTraversalFilter, CallTraversalFilter, CodeQuery,
    CodeQueryExecutionMode, CodeQueryPlan, CodeQueryPlanSource, CodeQueryResultDetail,
    CodeQuerySeed, HierarchyTraversal, PathFilter, Pattern, QueryError, QueryStep,
    ReferenceTraversalFilter, SetOperator,
};
use crate::analyzer::reference_candidates::{
    ReferenceCandidateRanges, reference_candidate_ranges, reference_candidate_ranges_cancellable,
};
use crate::analyzer::structural::analysis_context::{
    ProtocolRef, ProtocolRegistrationSet, QueryAnalysisContext, QueryAnalysisContextError,
    QueryAnalysisValidationLimits, TaintResultRef, TaintResultRegistrationSet, ValueFlowPlanRef,
    ValueFlowPlanRegistrationSet,
};
use crate::analyzer::structural::capabilities::QueryFeature;
#[cfg(test)]
use crate::analyzer::usages::CallArgument;
use crate::analyzer::usages::get_definition::{
    CallSyntaxKind, DefinitionLookupOutcome, DefinitionLookupRequest, DefinitionLookupStatus,
    parse_tree_for_language, resolve_definition_batch_with_source,
    resolve_definition_batch_with_source_and_cancellation,
};
use crate::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisOutcome, ReceiverValue,
};
use crate::analyzer::usages::receiver_query::{
    ReceiverQueryAnalysis, ReceiverQueryError, ReceiverQueryInput, ReceiverQueryOperation,
    ReceiverQueryReport, ReceiverQueryService,
};
use crate::analyzer::usages::{
    CallBindingCache, CallBindingStatus, CallRelationDiagnostic, CallRelationDiagnosticCode,
    CallRelationLimits, CallRelationResult, CallRelationService, CallSite, DEFAULT_MAX_FILES,
    ExplicitCandidateProvider, FuzzyResult, ReferenceHit, ReferenceKind, UsageFinder, UsageHit,
    UsageHitKind, UsageProof, bind_call_site_arguments,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;
use crate::text_utils::{compute_line_starts, line_column_for_offset};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

mod call_shape;
mod edges;
mod environment;
mod execution;
pub(crate) mod expansions;
mod imports;
mod materialization;
mod occurrences;
use edges::{EdgeKey, EdgeTraversalCache, EdgeValue};
mod paths;
mod pipeline;
mod receiver;
mod relations;
mod render;
use environment::{
    BindingKey, BindingValue, CandidateKey, CandidateValue, EnvironmentTraversalCache, ScopeKey,
    ScopeValue,
};
use occurrences::{OccurrenceKey, OccurrenceTraversalCache, OccurrenceValue};
use paths::{
    PATH_QUERY_AXES, PathKey, PathTraversalCache, PathValue, RESOLVED_PATH_QUERY_AXES, SegmentKey,
    SegmentValue, public_path, public_segment,
};
mod results;
mod row_relations;
mod seeds;
mod semantic;
mod taint;
#[cfg(test)]
mod tests;
mod typestate;
mod value_flow;
mod witness_projection;

// `apply_pipeline_step` below (this engine's own per-step dispatch) reaches
// into `expansions` for its three graph-traversal entry points.
use execution::*;
use expansions::{
    call_declaration_expansions, inbound_reference_expansions, scan_outbound_reference_hits,
};
use imports::*;
use pipeline::*;
use receiver::*;
use relations::*;
use render::*;
use row_relations::*;
use seeds::*;
use semantic::{
    SemanticControlEdgeValue, SemanticProcedureValue, SemanticProgramPointValue,
    SemanticQueryContext,
};
use taint::SemanticTaintFindingValue;
use typestate::{SemanticTypestateFindingValue, SemanticTypestateWitnessValue};
pub(crate) use value_flow::public_witness_step;
use value_flow::{SemanticFlowEndpointValue, SemanticFlowWitnessValue};
pub use witness_projection::project_taint_finding_report;
pub(crate) use witness_projection::{BoundedTaintProjection, project_taint_finding_report_bounded};

// Internal wiring: hoist the handful of `expansions`-child items the moved
// test module (tests.rs) still reaches via a bare `super::name` path, exactly
// as it did when this was one flat file. This is private (not part of the
// external crate/pub surface below) and only referenced under `#[cfg(test)]`.
#[cfg(test)]
use expansions::{
    append_outbound_lookup_diagnostics, group_outbound_lookup_candidates, reference_hits_for_target,
};

// Re-export the exact previous public/pub(crate) surface of `search.rs` so
// that `crate::analyzer::structural::search::X` keeps resolving for every
// existing consumer path unchanged.
use super::lexical_environment::ReachingBindingOutcome;
use super::occurrence_rows::{OccurrenceRow, OccurrenceTarget};
use super::occurrences::{OccurrenceClass, OccurrenceRole};
use super::query::{
    BindingFilter, CandidateFilter, EdgeFilter, OccurrenceFilter, OccurrenceSeed, ScopeFilter,
};
use crate::analyzer::semantic::{ContentIdentity, LengthDelimitedDigest};
use crate::analyzer::usages::get_definition::TraceCandidateRef;
pub use results::ALL_DETAILED_CODE_QUERY_DOMAINS;
pub use results::CodeQueryBinding;
pub use results::CodeQueryCallArgument;
pub use results::CodeQueryCallArgumentGroup;
pub use results::CodeQueryCallShape;
pub use results::CodeQueryCallShapeArgument;
pub use results::CodeQueryCallSite;
pub use results::CodeQueryCandidateRef;
pub use results::CodeQueryCapture;
pub use results::CodeQueryCompletion;
pub use results::CodeQueryControlEdge;
pub use results::CodeQueryDeclaration;
pub use results::CodeQueryDeclarationState;
pub use results::CodeQueryDiagnostic;
pub use results::CodeQueryDiagnosticCode;
pub use results::CodeQueryDiagnosticImpact;
pub use results::CodeQueryExecutionLimits;
pub use results::CodeQueryExecutionWork;
pub use results::CodeQueryExport;
pub use results::CodeQueryExpressionSite;
pub use results::CodeQueryFile;
pub use results::CodeQueryFlowCarrierSymbol;
pub use results::CodeQueryFlowCertainty;
pub use results::CodeQueryFlowCompletion;
pub use results::CodeQueryFlowDeclarationSegment;
pub use results::CodeQueryFlowEndpoint;
pub use results::CodeQueryFlowEvent;
pub use results::CodeQueryFlowFactSymbol;
pub use results::CodeQueryFlowMustStatus;
pub use results::CodeQueryFlowPortSymbol;
pub use results::CodeQueryFlowReachability;
pub use results::CodeQueryFlowSelectorSymbol;
pub use results::CodeQueryFlowSolverTermination;
pub use results::CodeQueryFlowSymbolSite;
pub use results::CodeQueryFlowWitness;
pub use results::CodeQueryFlowWitnessStep;
pub use results::CodeQueryFlowWitnessStepKind;
pub use results::CodeQueryGenerationSite;
pub use results::CodeQueryImportBinder;
pub use results::CodeQueryLexicalScope;
pub use results::CodeQueryMatch;
pub use results::CodeQueryOccurrence;
pub use results::CodeQueryOccurrenceTarget;
pub use results::CodeQueryPathSegment;
pub use results::CodeQueryProcedure;
pub use results::CodeQueryProgramPoint;
pub use results::CodeQueryProgramPointBoundary;
pub use results::CodeQueryProgramPointRef;
pub use results::CodeQueryProvenance;
pub use results::CodeQueryProvenanceStep;
pub use results::CodeQueryQualifiedPath;
pub use results::CodeQueryRange;
pub use results::CodeQueryReceiverAnalysis;
pub use results::CodeQueryReceiverEvidence;
pub use results::CodeQueryReceiverOutcome;
pub use results::CodeQueryReceiverValue;
pub use results::CodeQueryReferenceEdge;
pub use results::CodeQueryReferenceSite;
pub use results::CodeQueryResolutionCandidate;
pub use results::CodeQueryResponse;
pub use results::CodeQueryResult;
pub use results::CodeQueryResultItem;
pub use results::CodeQueryResultRef;
pub use results::CodeQueryResultValue;
pub use results::CodeQueryRowField;
pub use results::CodeQueryRowFieldError;
pub use results::CodeQueryRowRef;
pub use results::CodeQueryRowScalarRef;
pub use results::CodeQueryRowScalarType;
pub use results::CodeQuerySemanticCompleteness;
pub use results::CodeQuerySemanticEvidence;
pub use results::CodeQuerySemanticLimits;
pub use results::CodeQuerySemanticProof;
pub use results::CodeQuerySemanticWork;
pub use results::CodeQuerySourceSite;
pub use results::CodeQueryStableOwnerCandidate;
pub use results::CodeQueryStableOwnerDerivation;
pub use results::CodeQueryTaintFinding;
pub use results::CodeQueryTaintLimits;
pub use results::CodeQueryTaintOrigin;
pub use results::CodeQueryTaintProjectionLimits;
pub use results::CodeQueryTaintWitness;
pub use results::CodeQueryTypestateCertainty;
pub use results::CodeQueryTypestateFinding;
pub use results::CodeQueryTypestateFindingKind;
pub use results::CodeQueryTypestateLimits;
pub use results::CodeQueryTypestateSubject;
pub use results::CodeQueryTypestateUncertainty;
pub use results::CodeQueryTypestateWitness;
pub use results::CodeQueryTypestateWitnessStep;
pub use results::CodeQueryTypestateWitnessStepKind;
pub use results::CodeQueryTypestateWork;
pub use results::CodeQueryValueFlowLimits;
pub use results::CodeQueryValueFlowWork;
pub use results::DetailedCodeQueryDomain;
pub use results::DetailedCodeQueryEvidence;
pub use results::DetailedCodeQueryIdentityCandidate;
pub use results::DetailedCodeQueryKey;
pub use results::DetailedCodeQueryProvenanceEvidence;
pub use results::DetailedCodeQueryProvenanceIdentities;
pub use results::DetailedCodeQueryProvenanceRefEvidence;
pub(crate) use results::DetailedCodeQueryProvenanceStepEvidence;
pub(crate) use results::DetailedCodeQueryResult;
pub(crate) use results::UnionExecutionStrategy;

/// Longest match/capture snippet reported inline; full content is always
/// reachable via the returned line range.
const SNIPPET_MAX_CHARS: usize = 160;
const MAX_SCANNED_FILES: usize = 20_000;
const MAX_SCANNED_SOURCE_BYTES: usize = 128 * 1024 * 1024;
const MAX_FACT_NODES: usize = 2_000_000;
const MAX_PIPELINE_ROWS: usize = 50_000;
const MAX_SEMANTIC_MATERIALIZED_FILES: usize = 256;
const MAX_SEMANTIC_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SEMANTIC_ROWS_PER_DIMENSION: usize = 1_000_000;
const MAX_SEMANTIC_RETAINED_BYTES: usize = 64 * 1024 * 1024;
const MAX_SEMANTIC_TRAVERSAL_STEPS: usize = 1_000_000;
const MAX_PROVENANCE_TRACES: usize = 16;
const BROAD_QUERY_SCANNED_FILE_HINT_THRESHOLD: usize = 100;
const CODE_QUERY_SCHEDULER_WORKERS: usize = 2;
const MIN_AUTO_STRUCTURAL_INDEX_FILES: usize = 8;
const BENCHMARK_ACCESS_MODE_ENV: &str = "BIFROST_QUERY_CODE_ACCESS_MODE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StructuralAccessMode {
    Auto,
    /// Auto's viability rules without its first-build deferral. For callers
    /// that will run a whole batch of queries against one snapshot (policy
    /// packs), reuse is guaranteed, so waiting for a second request before
    /// building the snapshot index only converts the first batch into a
    /// full-workspace scan.
    EagerAuto,
    ScanOnly,
    IndexedRequired,
    #[cfg(test)]
    DerivedAutoForTest,
}

impl StructuralAccessMode {
    const fn uses_auto_index_admission(self) -> bool {
        match self {
            Self::Auto | Self::EagerAuto => true,
            #[cfg(test)]
            Self::DerivedAutoForTest => true,
            Self::ScanOnly | Self::IndexedRequired => false,
        }
    }

    /// Whether the first viable request for a snapshot scans and merely
    /// records reuse interest instead of building the index.
    const fn defers_first_snapshot_build(self) -> bool {
        match self {
            Self::Auto => true,
            #[cfg(test)]
            Self::DerivedAutoForTest => true,
            Self::EagerAuto | Self::ScanOnly | Self::IndexedRequired => false,
        }
    }

    const fn permits_snapshot_import_topology(self) -> bool {
        match self {
            Self::IndexedRequired => true,
            #[cfg(test)]
            Self::DerivedAutoForTest => true,
            Self::Auto | Self::EagerAuto | Self::ScanOnly => false,
        }
    }

    const fn uses_snapshot_import_auto_admission(self) -> bool {
        match self {
            #[cfg(test)]
            Self::DerivedAutoForTest => true,
            Self::Auto | Self::EagerAuto | Self::ScanOnly | Self::IndexedRequired => false,
        }
    }
}

/// A match found before rendering, held until the rendering pass (which
/// truncates at `limit` and does enclosing-symbol lookups).
type PendingMatch = (Language, ProjectFile, Arc<FileFacts>, FactMatch);

#[derive(Debug)]
struct SeedMatch {
    language: Language,
    file: ProjectFile,
    facts: Arc<FileFacts>,
    fact_match: FactMatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DeclarationValue {
    unit: CodeUnit,
    range: Range,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReferenceSiteValue {
    file: ProjectFile,
    range: Range,
    target: DeclarationValue,
    enclosing: Option<DeclarationValue>,
    usage_kind: UsageHitKind,
    proof: UsageProof,
    reference_kind: Option<ReferenceKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CallSiteValue(CallSite, CallBindingStatus);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ExpressionInput {
    Receiver,
    Parameter { index: usize, name: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExpressionSiteValue {
    call_site: CallSiteValue,
    range: Range,
    input: ExpressionInput,
}

#[derive(Debug, Clone)]
struct ReceiverAnalysisValue {
    report: ReceiverQueryReport,
    capture: Option<String>,
    site_id: String,
    site_ast_id: Option<String>,
}

#[derive(Debug, Clone)]
struct ReceiverEvidenceValue {
    receiver: ReceiverAnalysisValue,
    id: String,
    parent_evidence_id: Option<String>,
    ordinal: usize,
    chain_hop: usize,
    value: ReceiverValue,
    factory: Option<CodeUnit>,
}

/// One derived call-shape report shared by its outcome, group, and argument
/// pipeline rows. Group and argument values index into the shared report
/// instead of cloning row data per pipeline expansion.
#[derive(Debug, Clone)]
struct CallShapeValue {
    report: Arc<crate::analyzer::usages::call_shape::CallShapeReport>,
}

#[derive(Debug, Clone)]
struct CallArgumentGroupValue {
    shape: CallShapeValue,
    group_index: usize,
}

#[derive(Debug, Clone)]
struct CallArgumentValue {
    shape: CallShapeValue,
    argument_index: usize,
}

#[derive(Default)]
struct IndexedDeclarations {
    by_file: HashMap<ProjectFile, BTreeSet<CodeUnit>>,
    by_unit: HashMap<CodeUnit, Option<DeclarationValue>>,
    owner_by_member: HashMap<CodeUnit, CodeUnit>,
}

impl IndexedDeclarations {
    fn get(&mut self, analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<DeclarationValue> {
        if let Some(value) = self.by_unit.get(unit) {
            return value.clone();
        }

        let value = if unit.is_synthetic() || unit.is_file_scope() {
            None
        } else {
            let declarations = self
                .by_file
                .entry(unit.source().clone())
                .or_insert_with(|| analyzer.declarations(unit.source()));
            declarations.contains(unit).then(|| {
                analyzer
                    .ranges_of(unit)
                    .into_iter()
                    .min_by_key(primary_range_key)
                    .map(|range| DeclarationValue {
                        unit: unit.clone(),
                        range,
                    })
            })?
        };
        self.by_unit.insert(unit.clone(), value.clone());
        value
    }

    fn record_owner(&mut self, member: &CodeUnit, owner: &CodeUnit) {
        self.owner_by_member
            .entry(member.clone())
            .or_insert_with(|| owner.clone());
    }

    fn owner_of(
        &mut self,
        analyzer: &dyn IAnalyzer,
        member: &CodeUnit,
        work: &mut usize,
        max_work: usize,
    ) -> (Option<DeclarationValue>, bool) {
        if let Some(owner) = self.owner_by_member.get(member).cloned() {
            if *work >= max_work {
                return (None, true);
            }
            *work += 1;
            return (self.get(analyzer, &owner), false);
        }

        let owner = {
            let declarations = self
                .by_file
                .entry(member.source().clone())
                .or_insert_with(|| analyzer.declarations(member.source()));
            let mut found = None;
            'owners: for candidate in declarations.iter() {
                if *work >= max_work {
                    return (None, true);
                }
                *work += 1;
                if !is_type_declaration(analyzer, candidate) {
                    continue;
                }
                for child in analyzer.direct_children(candidate) {
                    if *work >= max_work {
                        return (None, true);
                    }
                    *work += 1;
                    if &child == member {
                        found = Some(candidate.clone());
                        break 'owners;
                    }
                }
            }
            found
        };
        if let Some(owner) = owner {
            self.record_owner(member, &owner);
            return (self.get(analyzer, &owner), false);
        }
        (None, false)
    }
}

fn primary_range_key(range: &Range) -> (usize, usize, usize, usize) {
    (
        range.start_line,
        range.start_byte,
        range.end_line,
        range.end_byte,
    )
}

struct PipelineExpansion {
    value: PipelineValue,
    trace: Vec<(PipelineTraceValue, Option<PipelineVia>)>,
    budgeted: bool,
}

#[derive(Debug, Clone)]
enum PipelineValue {
    StructuralMatch(Arc<SeedMatch>),
    Declaration(DeclarationValue),
    Semantic(SemanticPipelineValue),
    File(ProjectFile),
    ReferenceSite(ReferenceSiteValue),
    CallSite(CallSiteValue),
    ExpressionSite(ExpressionSiteValue),
    ReceiverAnalysis(ReceiverAnalysisValue),
    ReceiverOutcome(ReceiverAnalysisValue),
    ReceiverEvidence(ReceiverEvidenceValue),
    CallShape(CallShapeValue),
    CallArgumentGroup(CallArgumentGroupValue),
    CallArgument(CallArgumentValue),
    Occurrence(OccurrenceValue),
    LexicalScope(ScopeValue),
    Binding(BindingValue),
    ResolutionCandidate(Box<CandidateValue>),
    GenerationSite(materialization::GenerationSiteValue),
    Export(materialization::ExportValue),
    DeclarationState(materialization::DeclarationStateValue),
    ReferenceEdge(Box<EdgeValue>),
    QualifiedPath(PathValue),
    PathSegment(SegmentValue),
}

#[derive(Debug, Clone)]
enum SemanticPipelineValue {
    Procedure(SemanticProcedureValue),
    ProgramPoint(SemanticProgramPointValue),
    ControlEdge(SemanticControlEdgeValue),
    TypestateFinding(SemanticTypestateFindingValue),
    TypestateWitness(SemanticTypestateWitnessValue),
    FlowEndpoint(Box<SemanticFlowEndpointValue>),
    FlowWitness(SemanticFlowWitnessValue),
    TaintFinding(Box<SemanticTaintFindingValue>),
}

struct DetailedSemanticProjection<'a> {
    domain: DetailedCodeQueryDomain,
    key: DetailedCodeQueryKey,
    file: &'a ProjectFile,
    byte_span: std::ops::Range<usize>,
    display_range: CodeQueryRange,
    language: &'static str,
    stable_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PipelineKey {
    StructuralMatch(ProjectFile, u32),
    Declaration(DeclarationValue),
    Semantic(SemanticPipelineKey),
    File(ProjectFile),
    ReferenceSite(ReferenceSiteValue),
    CallSite(CallSiteValue),
    ExpressionSite(ExpressionSiteValue),
    ReceiverAnalysis(ReceiverQueryOperation, ProjectFile, Range),
    ReceiverOutcome(String),
    ReceiverEvidence(String),
    CallShape(String),
    CallArgumentGroup(String),
    CallArgument(String),
    Occurrence(OccurrenceKey),
    LexicalScope(ScopeKey),
    Binding(BindingKey),
    ResolutionCandidate(CandidateKey),
    GenerationSite(materialization::GenerationSiteKey),
    Export(materialization::ExportKey),
    DeclarationState(materialization::DeclarationStateKey),
    ReferenceEdge(EdgeKey),
    QualifiedPath(PathKey),
    PathSegment(SegmentKey),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SemanticPipelineKey {
    Procedure(crate::analyzer::semantic::ProcedureHandle),
    ProgramPoint(crate::analyzer::semantic::ProgramPointHandle),
    ControlEdge(crate::analyzer::semantic::ControlEdgeHandle),
    TypestateFinding(String),
    TypestateWitness(String),
    FlowEndpoint(String),
    FlowWitness(String),
    TaintFinding(String),
}

impl PipelineValue {
    fn key(&self) -> PipelineKey {
        match self {
            Self::StructuralMatch(seed) => {
                PipelineKey::StructuralMatch(seed.file.clone(), seed.fact_match.node)
            }
            Self::Declaration(declaration) => PipelineKey::Declaration(declaration.clone()),
            Self::Semantic(value) => PipelineKey::Semantic(value.key()),
            Self::File(file) => PipelineKey::File(file.clone()),
            Self::ReferenceSite(site) => PipelineKey::ReferenceSite(site.clone()),
            Self::CallSite(site) => PipelineKey::CallSite(site.clone()),
            Self::ExpressionSite(site) => PipelineKey::ExpressionSite(site.clone()),
            Self::ReceiverAnalysis(value) => PipelineKey::ReceiverAnalysis(
                value.report.operation,
                value.report.site.file.clone(),
                value.report.site.range,
            ),
            Self::ReceiverOutcome(value) => PipelineKey::ReceiverOutcome(value.site_id.clone()),
            Self::ReceiverEvidence(value) => PipelineKey::ReceiverEvidence(value.id.clone()),
            Self::CallShape(value) => PipelineKey::CallShape(value.report.outcome.site_id.clone()),
            Self::CallArgumentGroup(value) => PipelineKey::CallArgumentGroup(
                value.shape.report.groups[value.group_index].id.clone(),
            ),
            Self::CallArgument(value) => PipelineKey::CallArgument(
                value.shape.report.arguments[value.argument_index]
                    .id
                    .clone(),
            ),
            Self::Occurrence(value) => PipelineKey::Occurrence(value.key()),
            Self::LexicalScope(value) => PipelineKey::LexicalScope(value.key()),
            Self::GenerationSite(value) => PipelineKey::GenerationSite(value.key()),
            Self::Export(value) => PipelineKey::Export(value.key()),
            Self::DeclarationState(value) => PipelineKey::DeclarationState(value.key()),
            Self::Binding(value) => PipelineKey::Binding(value.key()),
            Self::ResolutionCandidate(value) => PipelineKey::ResolutionCandidate(value.key()),
            Self::ReferenceEdge(value) => PipelineKey::ReferenceEdge(value.key()),
            Self::QualifiedPath(value) => PipelineKey::QualifiedPath(value.key()),
            Self::PathSegment(value) => PipelineKey::PathSegment(value.key()),
        }
    }
}

impl SemanticPipelineValue {
    fn key(&self) -> SemanticPipelineKey {
        match self {
            Self::Procedure(procedure) => SemanticPipelineKey::Procedure(procedure.handle.clone()),
            Self::ProgramPoint(point) => SemanticPipelineKey::ProgramPoint(point.handle.clone()),
            Self::ControlEdge(edge) => SemanticPipelineKey::ControlEdge(edge.handle.clone()),
            Self::TypestateFinding(finding) => {
                SemanticPipelineKey::TypestateFinding(finding.key().to_string())
            }
            Self::TypestateWitness(witness) => {
                SemanticPipelineKey::TypestateWitness(witness.key().to_string())
            }
            Self::FlowEndpoint(endpoint) => {
                SemanticPipelineKey::FlowEndpoint(endpoint.key().to_string())
            }
            Self::FlowWitness(witness) => {
                SemanticPipelineKey::FlowWitness(witness.key().to_string())
            }
            Self::TaintFinding(finding) => {
                SemanticPipelineKey::TaintFinding(finding.key().to_string())
            }
        }
    }

    fn file(&self) -> &ProjectFile {
        match self {
            Self::Procedure(value) => value.file(),
            Self::ProgramPoint(value) => value.file(),
            Self::ControlEdge(value) => value.file(),
            Self::TypestateFinding(value) => value.file(),
            Self::TypestateWitness(value) => value.file(),
            Self::FlowEndpoint(value) => value.file(),
            Self::FlowWitness(value) => value.file(),
            Self::TaintFinding(value) => value.file(),
        }
    }

    fn public_result(self) -> CodeQueryResultValue {
        match self {
            Self::Procedure(value) => CodeQueryResultValue::Procedure {
                value: value.public(),
            },
            Self::ProgramPoint(value) => CodeQueryResultValue::ProgramPoint {
                value: value.public(),
            },
            Self::ControlEdge(value) => CodeQueryResultValue::ControlEdge {
                value: Box::new(value.public()),
            },
            Self::TypestateFinding(value) => CodeQueryResultValue::TypestateFinding {
                value: Box::new(value.public),
            },
            Self::TypestateWitness(value) => CodeQueryResultValue::TypestateWitness {
                value: Box::new(value.public),
            },
            Self::FlowEndpoint(value) => CodeQueryResultValue::FlowEndpoint {
                value: Box::new(value.public),
            },
            Self::FlowWitness(value) => CodeQueryResultValue::FlowWitness {
                value: Box::new(value.public),
            },
            Self::TaintFinding(value) => CodeQueryResultValue::TaintFinding {
                value: Box::new(value.public),
            },
        }
    }

    fn public_ref(&self) -> CodeQueryResultRef {
        match self {
            Self::Procedure(value) => value.public_ref(),
            Self::ProgramPoint(value) => value.public_ref(),
            Self::ControlEdge(value) => value.public_ref(),
            Self::TypestateFinding(value) => value.public_ref(),
            Self::TypestateWitness(value) => value.public_ref(),
            Self::FlowEndpoint(value) => value.public_ref(),
            Self::FlowWitness(value) => value.public_ref(),
            Self::TaintFinding(value) => value.public_ref(),
        }
    }

    fn detailed_projection(&self) -> DetailedSemanticProjection<'_> {
        match self {
            Self::Procedure(value) => {
                let public = value.public();
                DetailedSemanticProjection {
                    domain: DetailedCodeQueryDomain::Procedure,
                    key: DetailedCodeQueryKey::Procedure {
                        id: public.id.clone(),
                    },
                    file: value.file(),
                    byte_span: value.byte_span(),
                    display_range: public.range,
                    language: public.language,
                    stable_id: public.id,
                }
            }
            Self::ProgramPoint(value) => {
                let public = value.public();
                DetailedSemanticProjection {
                    domain: DetailedCodeQueryDomain::ProgramPoint,
                    key: DetailedCodeQueryKey::ProgramPoint {
                        id: public.id.clone(),
                        procedure_id: public.procedure_id,
                    },
                    file: value.file(),
                    byte_span: value.byte_span(),
                    display_range: public.range,
                    language: public.language,
                    stable_id: public.id,
                }
            }
            Self::ControlEdge(value) => {
                let public = value.public();
                DetailedSemanticProjection {
                    domain: DetailedCodeQueryDomain::ControlEdge,
                    key: DetailedCodeQueryKey::ControlEdge {
                        id: public.id.clone(),
                        procedure_id: public.procedure_id,
                    },
                    file: value.file(),
                    byte_span: value.byte_span(),
                    display_range: public.range,
                    language: public.language,
                    stable_id: public.id,
                }
            }
            Self::TypestateFinding(value) => DetailedSemanticProjection {
                domain: DetailedCodeQueryDomain::TypestateFinding,
                key: DetailedCodeQueryKey::TypestateFinding {
                    id: value.public.id.clone(),
                },
                file: value.file(),
                byte_span: value.byte_span(),
                display_range: value.public.range,
                language: value.public.language,
                stable_id: value.public.id.clone(),
            },
            Self::TypestateWitness(value) => DetailedSemanticProjection {
                domain: DetailedCodeQueryDomain::TypestateWitness,
                key: DetailedCodeQueryKey::TypestateWitness {
                    id: value.public.id.clone(),
                    finding_id: value.public.finding_id.clone(),
                },
                file: value.file(),
                byte_span: value.byte_span(),
                display_range: value.public.range,
                language: value.public.language,
                stable_id: value.public.id.clone(),
            },
            Self::FlowEndpoint(value) => DetailedSemanticProjection {
                domain: DetailedCodeQueryDomain::FlowEndpoint,
                key: DetailedCodeQueryKey::FlowEndpoint {
                    id: value.public.id.clone(),
                },
                file: value.file(),
                byte_span: value.byte_span(),
                display_range: value.public.range,
                language: value.public.language,
                stable_id: value.public.id.clone(),
            },
            Self::FlowWitness(value) => DetailedSemanticProjection {
                domain: DetailedCodeQueryDomain::FlowWitness,
                key: DetailedCodeQueryKey::FlowWitness {
                    id: value.public.id.clone(),
                    endpoint_id: value.public.endpoint_id.clone(),
                },
                file: value.file(),
                byte_span: value.byte_span(),
                display_range: value.public.range,
                language: value.public.language,
                stable_id: value.public.id.clone(),
            },
            Self::TaintFinding(value) => DetailedSemanticProjection {
                domain: DetailedCodeQueryDomain::TaintFinding,
                key: DetailedCodeQueryKey::TaintFinding {
                    id: value.public.id.clone(),
                },
                file: value.file(),
                byte_span: value.byte_span(),
                display_range: value.public.range,
                language: value.public.language,
                stable_id: value.public.id.clone(),
            },
        }
    }
}

#[derive(Debug, Clone)]
struct PipelineTrace {
    branch: Vec<usize>,
    seed: Arc<SeedMatch>,
    steps: Vec<PipelineTraceStep>,
}

#[derive(Debug, Clone)]
struct PipelineTraceStep {
    op: QueryStep,
    value: PipelineTraceValue,
    via: Option<PipelineVia>,
}

#[derive(Debug, Clone)]
enum PipelineTraceValue {
    Declaration(DeclarationValue),
    Semantic(SemanticPipelineValue),
    File(ProjectFile),
    ReferenceSite(ReferenceSiteValue),
    CallSite(CallSiteValue),
    ExpressionSite(ExpressionSiteValue),
    ReceiverAnalysis(ReceiverAnalysisValue),
    ReceiverOutcome(ReceiverAnalysisValue),
    ReceiverEvidence(ReceiverEvidenceValue),
    CallShape(CallShapeValue),
    CallArgumentGroup(CallArgumentGroupValue),
    CallArgument(CallArgumentValue),
    Occurrence(OccurrenceValue),
    LexicalScope(ScopeValue),
    Binding(BindingValue),
    ResolutionCandidate(Box<CandidateValue>),
    GenerationSite(materialization::GenerationSiteValue),
    Export(materialization::ExportValue),
    DeclarationState(materialization::DeclarationStateValue),
    ReferenceEdge(Box<EdgeValue>),
    QualifiedPath(PathValue),
    PathSegment(SegmentValue),
}

#[derive(Debug, Clone)]
enum PipelineVia {
    ReferenceSite(ReferenceSiteValue),
    CallSite(CallSiteValue),
}

#[derive(Default)]
struct ReferenceTraversalCache {
    inbound: HashMap<CodeUnit, Vec<ReferenceHit>>,
    outbound: HashMap<ProjectFile, Vec<ReferenceHit>>,
    inbound_incomplete: HashSet<CodeUnit>,
    outbound_incomplete: HashSet<ProjectFile>,
    inbound_exhausted: HashSet<CodeUnit>,
    outbound_exhausted: HashSet<ProjectFile>,
    reported_inbound: HashSet<CodeUnit>,
}

#[derive(Default)]
struct CallTraversalCache {
    incoming: HashMap<CodeUnit, CallRelationResult>,
    outgoing: HashMap<CodeUnit, CallRelationResult>,
    reported_incoming: HashSet<CodeUnit>,
    reported_outgoing: HashSet<CodeUnit>,
    bindings: CallBindingCache,
}

#[derive(Debug, Clone)]
struct PipelineRow {
    value: PipelineValue,
    traces: Vec<PipelineTrace>,
    provenance_truncated: bool,
}

struct CachedSourceCoordinates {
    source: String,
    line_starts: Vec<usize>,
}

#[derive(Default)]
struct PipelineRenderCache {
    sources: HashMap<ProjectFile, Option<CachedSourceCoordinates>>,
    conflicting_sources: HashSet<ProjectFile>,
    declaration_ranges: HashMap<DeclarationValue, Option<CodeQueryRange>>,
    enclosing_units: HashMap<(ProjectFile, usize, usize), Option<CodeUnit>>,
    source_loads_sealed: bool,
}

impl PipelineRenderCache {
    fn retain_source_snapshot(&mut self, file: &ProjectFile, source: &str) -> bool {
        if self.conflicting_sources.contains(file) {
            return false;
        }
        if let Some(existing) = self.sources.get(file) {
            match existing {
                Some(coordinates) if coordinates.source == source => return true,
                Some(_) => {
                    // Conflicting snapshots cannot support exact evidence or
                    // rendering. Retain the negative cache entry so a later
                    // renderer cannot silently hydrate a third source version.
                    self.sources.insert(file.clone(), None);
                    self.conflicting_sources.insert(file.clone());
                    return false;
                }
                None => {
                    // A held fact snapshot has already been charged by seed
                    // execution and may safely replace an earlier negative
                    // hydration entry.
                    self.sources.remove(file);
                }
            }
        }
        self.sources.insert(
            file.clone(),
            Some(CachedSourceCoordinates {
                line_starts: compute_line_starts(source),
                source: source.to_string(),
            }),
        );
        true
    }

    fn coordinates_for<F>(
        &mut self,
        file: &ProjectFile,
        load: F,
    ) -> Option<&CachedSourceCoordinates>
    where
        F: FnOnce() -> Option<String>,
    {
        if self.source_loads_sealed && !self.sources.contains_key(file) {
            self.sources.insert(file.clone(), None);
        }
        self.sources
            .entry(file.clone())
            .or_insert_with(|| {
                load().map(|source| CachedSourceCoordinates {
                    line_starts: compute_line_starts(&source),
                    source,
                })
            })
            .as_ref()
    }

    fn retain_loaded_source(&mut self, file: &ProjectFile, source: Option<String>) {
        self.sources.entry(file.clone()).or_insert_with(|| {
            source.map(|source| CachedSourceCoordinates {
                line_starts: compute_line_starts(&source),
                source,
            })
        });
    }

    fn seal_source_loads(&mut self) {
        self.source_loads_sealed = true;
    }

    fn source_snapshot(&self, file: &ProjectFile) -> Option<&str> {
        self.sources
            .get(file)
            .and_then(Option::as_ref)
            .map(|coordinates| coordinates.source.as_str())
    }

    fn range_for_declaration(
        &mut self,
        analyzer: &dyn IAnalyzer,
        declaration: &DeclarationValue,
    ) -> Option<CodeQueryRange> {
        if let Some(range) = self.declaration_ranges.get(declaration) {
            return *range;
        }

        let file = declaration.unit.source();
        let range = {
            self.coordinates_for(file, || analyzer.indexed_source(file))
                .map(|coordinates| {
                    range_for_offsets(
                        &coordinates.source,
                        &coordinates.line_starts,
                        declaration.range.start_byte,
                        declaration.range.end_byte,
                    )
                })
        };
        self.declaration_ranges.insert(declaration.clone(), range);
        range
    }

    fn enclosing_unit_for_lines(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        self.enclosing_units
            .entry((file.clone(), start_line, end_line))
            .or_insert_with(|| analyzer.enclosing_code_unit_for_lines(file, start_line, end_line))
            .clone()
    }
}

/// Run `query` across every language provider the analyzer exposes.
pub fn execute(analyzer: &dyn IAnalyzer, query: &CodeQuery) -> CodeQueryResult {
    execute_with_limits(analyzer, query, CodeQueryExecutionLimits::default())
}

/// Run `query` with access to the generation-bound semantic-oracle facade.
/// Receiver traversal uses this entrypoint in product code; the analyzer-only
/// entrypoint remains available for callers that do not own a workspace.
pub fn execute_workspace(workspace: &WorkspaceAnalyzer, query: &CodeQuery) -> CodeQueryResult {
    execute_workspace_with_limits(workspace, query, CodeQueryExecutionLimits::default())
}

/// Honor the query's root execution mode through the public Rust surface.
/// Ordinary callers that always want rows may continue to use [`execute`].
pub fn execute_request(analyzer: &dyn IAnalyzer, query: &CodeQuery) -> CodeQueryResponse {
    execute_request_with_limits(analyzer, query, CodeQueryExecutionLimits::default())
}

pub fn execute_request_with_limits(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> CodeQueryResponse {
    execute_request_internal(analyzer, None, query, limits, None, None, None)
}

/// Honor the query's root execution mode with access to generation-bound
/// semantic oracles for receiver traversal.
pub fn execute_workspace_request(
    workspace: &WorkspaceAnalyzer,
    query: &CodeQuery,
) -> CodeQueryResponse {
    execute_workspace_request_with_limits(workspace, query, CodeQueryExecutionLimits::default())
}

pub fn execute_workspace_request_with_limits(
    workspace: &WorkspaceAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> CodeQueryResponse {
    execute_request_internal(
        workspace.analyzer(),
        Some(workspace),
        query,
        limits,
        None,
        None,
        None,
    )
}

/// Execute against an immutable host registration snapshot.
///
/// The generation must be the same value captured in each registration. A
/// query-local capability context is created only for results/profile modes;
/// explain remains planning-only.
pub fn execute_workspace_request_with_registrations(
    workspace: &WorkspaceAnalyzer,
    workspace_generation: u64,
    registrations: &ProtocolRegistrationSet,
    query: &CodeQuery,
) -> CodeQueryResponse {
    execute_workspace_request_with_registration_limits(
        workspace,
        workspace_generation,
        registrations,
        query,
        CodeQueryExecutionLimits::default(),
    )
}

pub fn execute_workspace_request_with_registration_limits(
    workspace: &WorkspaceAnalyzer,
    workspace_generation: u64,
    registrations: &ProtocolRegistrationSet,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> CodeQueryResponse {
    let value_flow_registrations = ValueFlowPlanRegistrationSet::default();
    let taint_registrations = TaintResultRegistrationSet::default();
    execute_request_internal(
        workspace.analyzer(),
        Some(workspace),
        query,
        limits,
        None,
        Some((
            workspace_generation,
            registrations,
            &value_flow_registrations,
            &taint_registrations,
        )),
        None,
    )
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct CodeQueryExecutionBudget {
    scanned_files: usize,
    scanned_source_bytes: usize,
    fact_nodes: usize,
    examined_references: usize,
    pipeline_rows: usize,
    provenance_steps: usize,
    import_files_resolved: usize,
    import_edges_resolved: usize,
}

impl CodeQueryExecutionBudget {
    fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            scanned_files: self.scanned_files.saturating_sub(earlier.scanned_files),
            scanned_source_bytes: self
                .scanned_source_bytes
                .saturating_sub(earlier.scanned_source_bytes),
            fact_nodes: self.fact_nodes.saturating_sub(earlier.fact_nodes),
            examined_references: self
                .examined_references
                .saturating_sub(earlier.examined_references),
            pipeline_rows: self.pipeline_rows.saturating_sub(earlier.pipeline_rows),
            provenance_steps: self
                .provenance_steps
                .saturating_sub(earlier.provenance_steps),
            import_files_resolved: self
                .import_files_resolved
                .saturating_sub(earlier.import_files_resolved),
            import_edges_resolved: self
                .import_edges_resolved
                .saturating_sub(earlier.import_edges_resolved),
        }
    }

    fn saturating_add(self, other: Self) -> Self {
        Self {
            scanned_files: self.scanned_files.saturating_add(other.scanned_files),
            scanned_source_bytes: self
                .scanned_source_bytes
                .saturating_add(other.scanned_source_bytes),
            fact_nodes: self.fact_nodes.saturating_add(other.fact_nodes),
            examined_references: self
                .examined_references
                .saturating_add(other.examined_references),
            pipeline_rows: self.pipeline_rows.saturating_add(other.pipeline_rows),
            provenance_steps: self.provenance_steps.saturating_add(other.provenance_steps),
            import_files_resolved: self
                .import_files_resolved
                .saturating_add(other.import_files_resolved),
            import_edges_resolved: self
                .import_edges_resolved
                .saturating_add(other.import_edges_resolved),
        }
    }

    fn fair_lanes(self) -> [usize; 4] {
        [
            self.scanned_files,
            self.scanned_source_bytes,
            self.fact_nodes.saturating_add(self.examined_references),
            self.pipeline_rows.max(self.provenance_steps),
        ]
    }
}

#[derive(Debug)]
struct FairSeedBudgetState {
    usage: Vec<CodeQueryExecutionBudget>,
    finished: Vec<bool>,
    failed: bool,
    ledger: SeedScanLedger,
}

/// Per-file charges already admitted against one query execution's budget.
///
/// Compatible union branches (same language and file scope, different match
/// predicates) revisit the same files; the source bytes are read and the
/// normalized facts extracted once, with every later visit served from the
/// provider memory cache. This ledger lets those later visits skip the
/// already-admitted per-file charges so one execution meters each file's
/// extraction once, while files a branch alone visits still pay full price.
/// Sequential execution keeps one ledger on `QueryExecutionState`; parallel
/// union branches share the one inside `FairSeedBudgetState`, where
/// check-admit-mark is atomic under the coordinator mutex.
#[derive(Debug, Default)]
struct SeedScanLedger {
    /// The file's `scanned_files` / `scanned_source_bytes` charge was
    /// admitted (either access mode).
    scanned: HashSet<(Language, ProjectFile)>,
    /// The file's complete fact-node count was admitted by a Scan-access
    /// seed. Indexed access never marks this: its candidate charges are
    /// branch-specific and stay per-branch.
    fully_charged: HashSet<(Language, ProjectFile)>,
}

#[derive(Debug)]
struct FairSeedBudgetCoordinator {
    base: CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    branch_count: usize,
    cancellation: Option<CancellationToken>,
    state: Mutex<FairSeedBudgetState>,
    changed: Condvar,
    wait_ns: AtomicU64,
    waiters: AtomicUsize,
}

#[derive(Debug, Clone)]
struct FairSeedBudgetLease {
    coordinator: Arc<FairSeedBudgetCoordinator>,
    branch: usize,
}

enum FairSeedBudgetAdmission {
    Admitted,
    Rejected(CodeQueryExecutionBudget),
    Cancelled,
}

/// Which per-file charge a shared admission covers in the [`SeedScanLedger`].
#[derive(Clone, Copy)]
enum SeedChargeLane {
    /// `scanned_files` / `scanned_source_bytes` for one file.
    Scanned,
    /// The complete fact-node count of one Scan-access file.
    FullFacts,
}

impl SeedChargeLane {
    fn set(self, ledger: &SeedScanLedger) -> &HashSet<(Language, ProjectFile)> {
        match self {
            Self::Scanned => &ledger.scanned,
            Self::FullFacts => &ledger.fully_charged,
        }
    }

    fn set_mut(self, ledger: &mut SeedScanLedger) -> &mut HashSet<(Language, ProjectFile)> {
        match self {
            Self::Scanned => &mut ledger.scanned,
            Self::FullFacts => &mut ledger.fully_charged,
        }
    }
}

enum FairSeedBudgetSharedAdmission {
    /// An earlier seed scan in this execution already admitted this file's
    /// charge; the caller must not raise its local budget.
    AlreadyCharged,
    Admitted,
    Rejected(CodeQueryExecutionBudget),
    Cancelled,
}

impl FairSeedBudgetCoordinator {
    fn new(
        base: CodeQueryExecutionBudget,
        limits: CodeQueryExecutionLimits,
        branch_count: usize,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<Self> {
        debug_assert!(branch_count >= 2);
        Arc::new(Self {
            base,
            limits,
            branch_count,
            cancellation: cancellation.cloned(),
            state: Mutex::new(FairSeedBudgetState {
                usage: vec![CodeQueryExecutionBudget::default(); branch_count],
                finished: vec![false; branch_count],
                failed: false,
                ledger: SeedScanLedger::default(),
            }),
            changed: Condvar::new(),
            wait_ns: AtomicU64::new(0),
            waiters: AtomicUsize::new(0),
        })
    }

    fn lease(self: &Arc<Self>, branch: usize) -> FairSeedBudgetLease {
        debug_assert!(branch < self.branch_count);
        FairSeedBudgetLease {
            coordinator: Arc::clone(self),
            branch,
        }
    }

    fn maximum_pipeline_rows(&self) -> usize {
        self.limits.max_pipeline_rows
    }

    fn limits_lanes(&self) -> [usize; 4] {
        [
            self.limits.max_scanned_files,
            self.limits.max_scanned_source_bytes,
            self.limits.max_fact_nodes,
            self.limits.max_pipeline_rows,
        ]
    }

    fn branch_allowance(&self, state: &FairSeedBudgetState, branch: usize) -> [usize; 4] {
        let base = self.base.fair_lanes();
        let limits = self.limits_lanes();
        let mut used = base;
        for earlier in 0..branch {
            let remaining = self.branch_count.saturating_sub(earlier).max(1);
            let earlier_allowance: [usize; 4] = std::array::from_fn(|lane| {
                limits[lane].saturating_sub(used[lane]).div_ceil(remaining)
            });
            let actual = state.usage[earlier].fair_lanes();
            for lane in 0..used.len() {
                used[lane] = used[lane].saturating_add(if state.finished[earlier] {
                    actual[lane]
                } else {
                    earlier_allowance[lane]
                });
            }
        }
        let remaining = self.branch_count.saturating_sub(branch).max(1);
        std::array::from_fn(|lane| limits[lane].saturating_sub(used[lane]).div_ceil(remaining))
    }

    fn global_projected(
        &self,
        state: &FairSeedBudgetState,
        branch: usize,
        local_delta: CodeQueryExecutionBudget,
    ) -> CodeQueryExecutionBudget {
        state.usage[..branch]
            .iter()
            .copied()
            .fold(self.base, CodeQueryExecutionBudget::saturating_add)
            .saturating_add(local_delta)
    }

    fn committed_budget(&self) -> CodeQueryExecutionBudget {
        let state = self.state.lock().expect("fair seed budget lock poisoned");
        state
            .usage
            .iter()
            .copied()
            .fold(self.base, CodeQueryExecutionBudget::saturating_add)
    }

    fn wait_ns(&self) -> u64 {
        self.wait_ns.load(Ordering::Acquire)
    }

    #[cfg(test)]
    fn waiting_branches(&self) -> usize {
        self.waiters.load(Ordering::Acquire)
    }

    fn fail(&self) {
        let mut state = self.state.lock().expect("fair seed budget lock poisoned");
        state.failed = true;
        self.changed.notify_all();
    }
}

impl FairSeedBudgetLease {
    fn budget_before_branch(&self) -> CodeQueryExecutionBudget {
        let state = self
            .coordinator
            .state
            .lock()
            .expect("fair seed budget lock poisoned");
        state.usage[..self.branch].iter().copied().fold(
            self.coordinator.base,
            CodeQueryExecutionBudget::saturating_add,
        )
    }

    fn admit(&self, projected_local: CodeQueryExecutionBudget) -> FairSeedBudgetAdmission {
        let local_delta = projected_local.saturating_sub(self.coordinator.base);
        let requested = local_delta.fair_lanes();
        let mut state = self
            .coordinator
            .state
            .lock()
            .expect("fair seed budget lock poisoned");
        loop {
            if state.failed {
                return FairSeedBudgetAdmission::Cancelled;
            }
            if self
                .coordinator
                .cancellation
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
            {
                return FairSeedBudgetAdmission::Cancelled;
            }
            let allowance = self.coordinator.branch_allowance(&state, self.branch);
            if requested
                .iter()
                .zip(allowance)
                .all(|(requested, allowance)| *requested <= allowance)
            {
                state.usage[self.branch] = local_delta;
                return FairSeedBudgetAdmission::Admitted;
            }
            if state.finished[..self.branch]
                .iter()
                .all(|finished| *finished)
            {
                return FairSeedBudgetAdmission::Rejected(self.coordinator.global_projected(
                    &state,
                    self.branch,
                    local_delta,
                ));
            }
            let wait_started = Instant::now();
            self.coordinator.waiters.fetch_add(1, Ordering::AcqRel);
            let (next_state, _) = self
                .coordinator
                .changed
                .wait_timeout(state, Duration::from_millis(2))
                .expect("fair seed budget lock poisoned while waiting");
            self.coordinator.waiters.fetch_sub(1, Ordering::AcqRel);
            self.coordinator
                .wait_ns
                .fetch_add(elapsed_ns(wait_started), Ordering::Relaxed);
            state = next_state;
        }
    }

    /// [`Self::admit`] for a per-file charge shared across branches: checks
    /// the coordinator ledger, admits, and marks atomically under the
    /// coordinator mutex so concurrent branches cannot both charge one file.
    fn admit_shared(
        &self,
        lane: SeedChargeLane,
        key: &(Language, ProjectFile),
        projected_local: CodeQueryExecutionBudget,
    ) -> FairSeedBudgetSharedAdmission {
        let local_delta = projected_local.saturating_sub(self.coordinator.base);
        let requested = local_delta.fair_lanes();
        let mut state = self
            .coordinator
            .state
            .lock()
            .expect("fair seed budget lock poisoned");
        loop {
            // Re-check on every wake: another branch may have charged this
            // file while this one waited for allowance.
            if lane.set(&state.ledger).contains(key) {
                return FairSeedBudgetSharedAdmission::AlreadyCharged;
            }
            if state.failed {
                return FairSeedBudgetSharedAdmission::Cancelled;
            }
            if self
                .coordinator
                .cancellation
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
            {
                return FairSeedBudgetSharedAdmission::Cancelled;
            }
            let allowance = self.coordinator.branch_allowance(&state, self.branch);
            if requested
                .iter()
                .zip(allowance)
                .all(|(requested, allowance)| *requested <= allowance)
            {
                state.usage[self.branch] = local_delta;
                lane.set_mut(&mut state.ledger).insert(key.clone());
                return FairSeedBudgetSharedAdmission::Admitted;
            }
            if state.finished[..self.branch]
                .iter()
                .all(|finished| *finished)
            {
                return FairSeedBudgetSharedAdmission::Rejected(self.coordinator.global_projected(
                    &state,
                    self.branch,
                    local_delta,
                ));
            }
            let wait_started = Instant::now();
            self.coordinator.waiters.fetch_add(1, Ordering::AcqRel);
            let (next_state, _) = self
                .coordinator
                .changed
                .wait_timeout(state, Duration::from_millis(2))
                .expect("fair seed budget lock poisoned while waiting");
            self.coordinator.waiters.fetch_sub(1, Ordering::AcqRel);
            self.coordinator
                .wait_ns
                .fetch_add(elapsed_ns(wait_started), Ordering::Relaxed);
            state = next_state;
        }
    }

    fn finish(&self, local_budget: CodeQueryExecutionBudget) {
        let mut state = self
            .coordinator
            .state
            .lock()
            .expect("fair seed budget lock poisoned");
        state.usage[self.branch] = local_budget.saturating_sub(self.coordinator.base);
        state.finished[self.branch] = true;
        self.coordinator.changed.notify_all();
    }
}

#[derive(Clone)]
struct CachedSeedExecution {
    rows: Vec<PipelineRow>,
    diagnostics: Vec<CodeQueryDiagnostic>,
    truncated: bool,
    /// Whether the cached rows exhaust the seed relation, independently of
    /// whether an enclosing limit can still return a semantically complete
    /// response from a terminal-cap probe.
    complete: Option<bool>,
}

struct QueryExecutionState<'a> {
    analyzer: &'a dyn IAnalyzer,
    workspace: Option<&'a WorkspaceAnalyzer>,
    cancellation: Option<&'a CancellationToken>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    budget: CodeQueryExecutionBudget,
    seed_cache: HashMap<String, CachedSeedExecution>,
    /// Per-file charges already admitted in this execution; parallel union
    /// branches use the coordinator's ledger through their lease instead.
    seed_scan_ledger: SeedScanLedger,
    indexed_declarations: IndexedDeclarations,
    reference_cache: ReferenceTraversalCache,
    call_cache: CallTraversalCache,
    occurrence_cache: OccurrenceTraversalCache,
    environment_cache: EnvironmentTraversalCache,
    materialization_cache: materialization::MaterializationTraversalCache,
    edge_cache: EdgeTraversalCache,
    path_cache: PathTraversalCache,
    receiver_facts: HashMap<ProjectFile, Arc<FileFacts>>,
    semantic: Option<SemanticQueryContext<'a>>,
    import_graph: Option<RequestLocalDirectImportGraph>,
    import_graph_generations: Option<Box<[u64]>>,
    direct_import_layer: Option<Arc<DerivedLayer>>,
    direct_import_layer_generations: Option<Box<[u64]>>,
    deferred_derived_builds: HashSet<DerivedLayerRequest>,
    cache_profile: Option<QueryCacheProfile>,
    profile: Option<QueryExecutionProfile>,
    retained_value_census: Option<QueryRetainedValueCensus>,
    structural_index_session: QueryStructuralIndexSession,
    access_mode: StructuralAccessMode,
    access_failure: Option<String>,
    parallel_seed_budget: Option<FairSeedBudgetLease>,
    scheduler_workers: usize,
}

#[derive(Clone, Copy)]
enum DirectImportAccess<'a> {
    RequestLocal(&'a RequestLocalDirectImportGraph),
    Snapshot(&'a DirectImportTopology),
}

impl DirectImportAccess<'_> {
    fn imports_of(&self, file: &ProjectFile) -> Option<Vec<ProjectFile>> {
        match self {
            Self::RequestLocal(graph) => {
                graph.supports_source(file).then(|| graph.imports_of(file))
            }
            Self::Snapshot(topology) => topology.imports_of(file),
        }
    }

    fn importers_of(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        match self {
            Self::RequestLocal(graph) => graph.importers_of(file),
            Self::Snapshot(topology) => topology.known_importers_of(file),
        }
    }

    fn unsupported_languages(&self) -> Vec<Language> {
        match self {
            Self::RequestLocal(graph) => graph.unsupported_languages(),
            Self::Snapshot(topology) => topology.unsupported_languages(),
        }
    }
}

struct PlanExecution {
    rows: Vec<PipelineRow>,
    truncated: bool,
    cancelled: bool,
    /// An intermediate authored pipeline step exhausted its budget, so the
    /// remaining steps in that same suffix must not run.
    pipeline_halted: bool,
}

struct ParallelSeedBranchResult {
    execution: PlanExecution,
    diagnostics: Vec<CodeQueryDiagnostic>,
    seed_cache: HashMap<String, CachedSeedExecution>,
    cache_profile: Option<QueryCacheProfile>,
    operators: Vec<QueryOperatorProfile>,
    access_path: QueryAccessPathProfile,
    access_failure: Option<String>,
}

struct ParallelUnionExecution {
    execution: PlanExecution,
    input_rows: usize,
    rows_visited: usize,
    rows_discarded: Option<usize>,
    temporary_capacity_bytes_lower_bound: u64,
    operator_truncated: bool,
    dependency_wait_ns: u64,
    scheduling_overhead_ns: u64,
    merge_ns: u64,
}

#[doc(hidden)]
pub fn execute_with_limits(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> CodeQueryResult {
    let mut result = execute_code_query_detailed(analyzer, query, limits, None).result;
    augment_public_result_with_semantic_overlay(analyzer, query, &mut result);
    result
}

#[doc(hidden)]
pub fn execute_workspace_with_limits(
    workspace: &WorkspaceAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> CodeQueryResult {
    let mut result = execute_internal_with_analysis(
        workspace.analyzer(),
        Some(workspace),
        None,
        0,
        query,
        limits,
        None,
        None,
        false,
    )
    .result;
    augment_public_result_with_semantic_overlay(workspace.analyzer(), query, &mut result);
    result
}

#[cfg(test)]
pub(crate) fn execute_with_cancellation(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: &CancellationToken,
) -> CodeQueryResult {
    execute_code_query_detailed(analyzer, query, limits, Some(cancellation)).result
}

/// Execute a mode-aware query with explicit limits and cooperative cancellation.
///
/// Unlike protocol surfaces that translate cancellation into their own error
/// response, a profiled Rust request returns its cancellation observations and
/// cancellation-safe partial result to the caller.
pub fn execute_request_with_cancellation(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: &CancellationToken,
) -> CodeQueryResponse {
    execute_request_internal(
        analyzer,
        None,
        query,
        limits,
        Some(cancellation),
        None,
        None,
    )
}

/// Execute a mode-aware workspace query with explicit limits and cooperative
/// cancellation. Explain mode remains planning-only and does not inspect the
/// workspace.
pub fn execute_workspace_request_with_cancellation(
    workspace: &WorkspaceAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: &CancellationToken,
) -> CodeQueryResponse {
    execute_request_internal(
        workspace.analyzer(),
        Some(workspace),
        query,
        limits,
        Some(cancellation),
        None,
        None,
    )
}

pub fn execute_workspace_request_with_registration_cancellation(
    workspace: &WorkspaceAnalyzer,
    workspace_generation: u64,
    registrations: &ProtocolRegistrationSet,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: &CancellationToken,
) -> CodeQueryResponse {
    let value_flow_registrations = ValueFlowPlanRegistrationSet::default();
    let taint_registrations = TaintResultRegistrationSet::default();
    execute_request_internal(
        workspace.analyzer(),
        Some(workspace),
        query,
        limits,
        Some(cancellation),
        Some((
            workspace_generation,
            registrations,
            &value_flow_registrations,
            &taint_registrations,
        )),
        None,
    )
}

/// Execute with a caller-owned generation-scoped typestate repository.
///
/// Long-lived hosts use this entry so separate JSON/RQL requests can share
/// exact production results without introducing process-global state.
pub fn execute_workspace_request_with_registration_lease(
    workspace: &WorkspaceAnalyzer,
    workspace_generation: u64,
    registrations: &ProtocolRegistrationSet,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    summary_lease: crate::analyzer::typestate::ProductionTypestateSummaryLease,
) -> CodeQueryResponse {
    let value_flow_registrations = ValueFlowPlanRegistrationSet::default();
    execute_workspace_request_with_analysis_registration_lease(
        workspace,
        workspace_generation,
        registrations,
        &value_flow_registrations,
        query,
        limits,
        cancellation,
        summary_lease,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execute_workspace_request_with_analysis_registration_lease(
    workspace: &WorkspaceAnalyzer,
    workspace_generation: u64,
    registrations: &ProtocolRegistrationSet,
    value_flow_registrations: &ValueFlowPlanRegistrationSet,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    summary_lease: crate::analyzer::typestate::ProductionTypestateSummaryLease,
) -> CodeQueryResponse {
    let taint_registrations = TaintResultRegistrationSet::default();
    execute_workspace_request_with_all_analysis_registration_lease(
        workspace,
        workspace_generation,
        registrations,
        value_flow_registrations,
        &taint_registrations,
        query,
        limits,
        cancellation,
        summary_lease,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execute_workspace_request_with_all_analysis_registration_lease(
    workspace: &WorkspaceAnalyzer,
    workspace_generation: u64,
    registrations: &ProtocolRegistrationSet,
    value_flow_registrations: &ValueFlowPlanRegistrationSet,
    taint_registrations: &TaintResultRegistrationSet,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    summary_lease: crate::analyzer::typestate::ProductionTypestateSummaryLease,
) -> CodeQueryResponse {
    execute_request_internal(
        workspace.analyzer(),
        Some(workspace),
        query,
        limits,
        cancellation,
        Some((
            workspace_generation,
            registrations,
            value_flow_registrations,
            taint_registrations,
        )),
        Some(summary_lease),
    )
}

fn execute_request_internal(
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    registrations: Option<(
        u64,
        &ProtocolRegistrationSet,
        &ValueFlowPlanRegistrationSet,
        &TaintResultRegistrationSet,
    )>,
    summary_lease: Option<crate::analyzer::typestate::ProductionTypestateSummaryLease>,
) -> CodeQueryResponse {
    if query_plan_requires_typestate(&query.plan) && !limits.typestate.is_valid() {
        return CodeQueryResponse::Results(invalid_plan_result(
            "typestate execution limits must be positive and no greater than their hard maxima",
        ));
    }
    if query_plan_requires_value_flow(&query.plan) && !limits.value_flow.is_valid() {
        return CodeQueryResponse::Results(invalid_plan_result(
            "value-flow execution limits must be positive and no greater than their hard maxima",
        ));
    }
    if query_plan_requires_taint(&query.plan) && !limits.taint.is_valid() {
        return CodeQueryResponse::Results(invalid_plan_result(
            "taint projection limits must be positive and no greater than their hard maxima",
        ));
    }
    let analysis_context = if query.execution_mode == CodeQueryExecutionMode::Explain {
        None
    } else if let (
        Some(workspace),
        Some((workspace_generation, registrations, value_flow_registrations, taint_registrations)),
    ) = (workspace, registrations)
    {
        let requested = requested_protocol_refs(&query.plan);
        let requested_value_flows = requested_value_flow_refs(&query.plan);
        let requested_taint_results = requested_taint_result_refs(&query.plan);
        let summary_lease = match summary_lease {
            Some(summary_lease) => summary_lease,
            None => {
                let summaries = Arc::new(
                    crate::analyzer::typestate::ProductionTypestateSummaryRepository::new(),
                );
                match summaries.lease(workspace_generation) {
                    Ok(summary_lease) => summary_lease,
                    Err(error) => {
                        return CodeQueryResponse::Results(invalid_plan_result(error.to_string()));
                    }
                }
            }
        };
        match QueryAnalysisContext::new_with_all_registrations_and_summaries(
            workspace,
            workspace_generation,
            registrations,
            &requested,
            value_flow_registrations,
            &requested_value_flows,
            taint_registrations,
            &requested_taint_results,
            QueryAnalysisValidationLimits::new(
                limits.semantic.max_materialized_files,
                limits.semantic.max_source_bytes,
            ),
            cancellation,
            summary_lease,
        ) {
            Ok(context) => Some(context),
            Err(error) => {
                return CodeQueryResponse::Results(query_analysis_context_error_result(error));
            }
        }
    } else {
        None
    };
    let workspace_generation = registrations.map_or(0, |(generation, _, _, _)| generation);
    match query.execution_mode {
        CodeQueryExecutionMode::Results => {
            let mut result = execute_internal_with_analysis(
                analyzer,
                workspace,
                analysis_context.as_ref(),
                workspace_generation,
                query,
                limits,
                cancellation,
                None,
                false,
            )
            .result;
            augment_public_result_with_semantic_overlay(analyzer, query, &mut result);
            CodeQueryResponse::Results(result)
        }
        CodeQueryExecutionMode::Explain => match select_physical_plan(
            query,
            UnionExecutionStrategy::Auto,
            CODE_QUERY_SCHEDULER_WORKERS,
        ) {
            Ok(physical_plan) => {
                // The measured production Auto policy is sequential. Explain
                // performs only lowering and physical selection: it does not
                // construct an analyzer query scope or touch workspace data.
                CodeQueryResponse::Explain(
                    physical_plan.public_explain(query, CODE_QUERY_SCHEDULER_WORKERS),
                )
            }
            Err(error) => CodeQueryResponse::Results(invalid_plan_result(error)),
        },
        CodeQueryExecutionMode::Profile => {
            let detailed = execute_internal_with_analysis(
                analyzer,
                workspace,
                analysis_context.as_ref(),
                workspace_generation,
                query,
                limits,
                cancellation,
                None,
                true,
            );
            let DetailedCodeQueryResult {
                mut result,
                profile,
                ..
            } = detailed;
            augment_public_result_with_semantic_overlay(analyzer, query, &mut result);
            match profile {
                Some(profile) => CodeQueryResponse::Profile(Box::new(
                    CodeQueryProfile::from_internal(query, result, profile),
                )),
                // Programmatically constructed invalid plans retain the
                // existing typed diagnostic instead of panicking while a
                // decoded request always reaches the profiled branch above.
                None => CodeQueryResponse::Results(result),
            }
        }
    }
}

pub fn execute_code_query_detailed(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
) -> DetailedCodeQueryResult {
    execute_internal_with_analysis(
        analyzer,
        None,
        None,
        0,
        query,
        limits,
        cancellation,
        None,
        false,
    )
}

/// `execute_code_query_detailed` for callers that will run a batch of queries
/// against the same snapshot: builds the snapshot structural index on first
/// use instead of deferring it to a later request.
pub fn execute_code_query_detailed_eager_index(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
) -> DetailedCodeQueryResult {
    let access_mode = match benchmark_structural_access_mode() {
        StructuralAccessMode::ScanOnly => StructuralAccessMode::ScanOnly,
        _ => StructuralAccessMode::EagerAuto,
    };
    execute_internal_with_analysis_strategy(
        analyzer,
        None,
        None,
        0,
        query,
        limits,
        cancellation,
        None,
        false,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
        access_mode,
        None,
    )
}

/// Internal opt-in profile entry point used by the M2 measurement harness.
/// Public query surfaces remain unchanged until the explicit M5 rollout.
#[cfg(test)]
pub(crate) fn execute_code_query_profiled(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> DetailedCodeQueryResult {
    execute_internal_with_analysis(analyzer, None, None, 0, query, limits, None, None, true)
}

/// M4 benchmark/test entry point. A forced strategy still passes through the
/// same semantic eligibility gate as production; unsafe shapes stay serial.
#[cfg(test)]
pub(crate) fn execute_code_query_with_union_strategy(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    strategy: UnionExecutionStrategy,
    capture_profile: bool,
) -> DetailedCodeQueryResult {
    execute_internal_with_analysis_strategy(
        analyzer,
        None,
        None,
        0,
        query,
        limits,
        None,
        None,
        capture_profile,
        strategy,
        CODE_QUERY_SCHEDULER_WORKERS,
        StructuralAccessMode::Auto,
        None,
    )
}

#[cfg(test)]
pub(crate) fn execute_code_query_with_access_mode(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    mode: StructuralAccessMode,
    capture_profile: bool,
) -> Result<DetailedCodeQueryResult, String> {
    let mut failure = None;
    let detailed = execute_internal_with_analysis_strategy(
        analyzer,
        None,
        None,
        0,
        query,
        limits,
        None,
        None,
        capture_profile,
        UnionExecutionStrategy::Sequential,
        CODE_QUERY_SCHEDULER_WORKERS,
        mode,
        Some(&mut failure),
    );
    match failure {
        Some(failure) => Err(failure),
        None => Ok(detailed),
    }
}

#[cfg(test)]
fn execute_with_receiver_budget_for_test(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    receiver_budget: ReceiverAnalysisBudget,
) -> CodeQueryResult {
    execute_internal_with_analysis(
        analyzer,
        None,
        None,
        0,
        query,
        CodeQueryExecutionLimits::default(),
        None,
        Some(receiver_budget),
        false,
    )
    .result
}

#[cfg(test)]
fn execute_internal(
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    capture_profile: bool,
) -> DetailedCodeQueryResult {
    execute_internal_with_analysis(
        analyzer,
        workspace,
        None,
        0,
        query,
        limits,
        cancellation,
        receiver_budget_override,
        capture_profile,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_internal_with_analysis(
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    analysis_context: Option<&QueryAnalysisContext>,
    workspace_generation: u64,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    capture_profile: bool,
) -> DetailedCodeQueryResult {
    execute_internal_with_analysis_strategy(
        analyzer,
        workspace,
        analysis_context,
        workspace_generation,
        query,
        limits,
        cancellation,
        receiver_budget_override,
        capture_profile,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
        benchmark_structural_access_mode(),
        None,
    )
}

fn benchmark_structural_access_mode() -> StructuralAccessMode {
    match std::env::var(BENCHMARK_ACCESS_MODE_ENV).as_deref() {
        Ok("scan_only") => StructuralAccessMode::ScanOnly,
        _ => StructuralAccessMode::Auto,
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn execute_internal_with_strategy(
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    capture_profile: bool,
    union_strategy: UnionExecutionStrategy,
    scheduler_workers: usize,
    access_mode: StructuralAccessMode,
    access_failure_out: Option<&mut Option<String>>,
) -> DetailedCodeQueryResult {
    execute_internal_with_analysis_strategy(
        analyzer,
        workspace,
        None,
        0,
        query,
        limits,
        cancellation,
        receiver_budget_override,
        capture_profile,
        union_strategy,
        scheduler_workers,
        access_mode,
        access_failure_out,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_internal_with_analysis_strategy(
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    analysis_context: Option<&QueryAnalysisContext>,
    workspace_generation: u64,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    capture_profile: bool,
    union_strategy: UnionExecutionStrategy,
    scheduler_workers: usize,
    access_mode: StructuralAccessMode,
    access_failure_out: Option<&mut Option<String>>,
) -> DetailedCodeQueryResult {
    // Keep repeated analyzer reads coherent and reusable even for direct API
    // callers that do not already own a wider request scope. Nested scopes are
    // supported and preserve an outer caller's store-error observation.
    let _query_scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
    let request_started = capture_profile.then(Instant::now);
    let planning_started = capture_profile.then(Instant::now);
    if !capture_profile && cancellation.is_some_and(CancellationToken::is_cancelled) {
        return detailed_result_without_evidence(
            cancelled_query_result(),
            CodeQueryExecutionBudget::default(),
        );
    }
    let physical_plan = match select_physical_plan(query, union_strategy, scheduler_workers) {
        Ok(plan) => plan,
        Err(error) => {
            return detailed_result_without_evidence(
                invalid_plan_result(error),
                CodeQueryExecutionBudget::default(),
            );
        }
    };
    let requires_semantic = query_plan_requires_semantic(&query.plan);
    if requires_semantic && !limits.semantic.all_positive() {
        return detailed_result_without_evidence(
            invalid_plan_result(
                "semantic execution limits must all be positive for a semantic query",
            ),
            CodeQueryExecutionBudget::default(),
        );
    }
    if query_plan_requires_typestate(&query.plan) && !limits.typestate.is_valid() {
        return detailed_result_without_evidence(
            invalid_plan_result(
                "typestate execution limits must be positive and no greater than their hard maxima",
            ),
            CodeQueryExecutionBudget::default(),
        );
    }
    if query_plan_requires_value_flow(&query.plan) && !limits.value_flow.is_valid() {
        return detailed_result_without_evidence(
            invalid_plan_result(
                "value-flow execution limits must be positive and no greater than their hard maxima",
            ),
            CodeQueryExecutionBudget::default(),
        );
    }
    let planning_ns = planning_started.map(elapsed_ns).unwrap_or(0);
    let mut diagnostics = Vec::new();
    let mut state = QueryExecutionState {
        analyzer,
        workspace,
        cancellation,
        receiver_budget_override,
        budget: CodeQueryExecutionBudget::default(),
        seed_cache: HashMap::default(),
        seed_scan_ledger: SeedScanLedger::default(),
        indexed_declarations: IndexedDeclarations::default(),
        reference_cache: ReferenceTraversalCache::default(),
        occurrence_cache: OccurrenceTraversalCache::default(),
        environment_cache: EnvironmentTraversalCache::default(),
        materialization_cache: materialization::MaterializationTraversalCache::default(),
        edge_cache: EdgeTraversalCache::default(),
        path_cache: PathTraversalCache::default(),
        call_cache: CallTraversalCache::default(),
        receiver_facts: HashMap::default(),
        semantic: workspace.filter(|_| requires_semantic).map(|workspace| {
            SemanticQueryContext::new_with_analysis(
                workspace,
                cancellation,
                limits.semantic,
                limits.typestate,
                limits.value_flow,
                limits.taint,
                workspace_generation,
                analysis_context,
            )
        }),
        import_graph: None,
        import_graph_generations: None,
        direct_import_layer: None,
        direct_import_layer_generations: None,
        deferred_derived_builds: HashSet::default(),
        cache_profile: capture_profile.then(QueryCacheProfile::default),
        profile: capture_profile
            .then(|| QueryExecutionProfile::new(&physical_plan, planning_ns, scheduler_workers)),
        retained_value_census: capture_profile.then(QueryRetainedValueCensus::default),
        structural_index_session: QueryStructuralIndexSession::default(),
        access_mode,
        access_failure: None,
        parallel_seed_budget: None,
        scheduler_workers,
    };
    let mut profile_branch = state.profile.as_ref().map(|_| Vec::new());
    let execution_started = capture_profile.then(Instant::now);
    let mut execution = execute_plan(
        &physical_plan,
        physical_plan.root(),
        &mut state,
        limits,
        None,
        &mut diagnostics,
        &mut profile_branch,
    );
    if !state
        .structural_index_session
        .selections_are_current(|generations| {
            state.analyzer.snapshot_generations_match(generations)
        })
    {
        execution.rows.clear();
        execution.truncated = true;
        state.access_failure.get_or_insert_with(|| {
            "structural source generation changed before result rendering".to_string()
        });
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: "workspace",
            message: "source generation changed after structural posting selection; retry the query for a coherent snapshot".to_string(),
        });
    }
    if let (Some(profile), Some(started)) = (&mut state.profile, execution_started) {
        profile.execution_ns = elapsed_ns(started);
    }
    let semantic_work = state
        .semantic
        .as_ref()
        .map_or_else(CodeQuerySemanticWork::default, SemanticQueryContext::work);
    let execution_work_profile =
        capture_profile.then(|| execution_work_snapshot(state.budget, semantic_work));
    let rendering_started = capture_profile.then(Instant::now);
    let mut cancelled = execution.cancelled;
    let mut truncated = execution.truncated;
    // Preserve the pre-composition response shape for a plain structural
    // query. Set plans retain their seed-only traces because the branch path
    // is meaningful provenance even when no semantic step follows the set.
    if query.seed().is_some() && query.plan.steps.is_empty() {
        for row in &mut execution.rows {
            row.traces.clear();
            row.provenance_truncated = false;
        }
    }
    if let Some(seed) = query.seed() {
        let plan = QueryPlan::for_query(seed);
        if should_report_broad_query(&plan, seed, &state.budget, truncated) {
            push_broad_query_diagnostic(&mut diagnostics, &state.budget);
        }
    }
    let mut render_cache = PipelineRenderCache::default();
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        cancelled = true;
        push_cancelled_diagnostic(&mut diagnostics);
    }
    let mut results = Vec::with_capacity(execution.rows.len());
    let mut evidence = Vec::with_capacity(execution.rows.len());
    for (result_index, row) in execution.rows.into_iter().enumerate() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            cancelled = true;
            truncated = true;
            push_cancelled_diagnostic(&mut diagnostics);
            break;
        }
        if retain_budgeted_pipeline_sources(
            analyzer,
            &row,
            &mut render_cache,
            &mut state.budget,
            limits,
            &mut diagnostics,
        ) {
            truncated = true;
        }
        render_cache.seal_source_loads();
        let terminal_source_file = terminal_source_file(&row.value);
        let retained_source =
            terminal_source_file.and_then(|file| render_cache.source_snapshot(file));
        let mut row_evidence =
            detailed_evidence_for_pipeline_value(result_index, &row.value, retained_source);
        row_evidence.provenance = detailed_provenance_for_row(&row, &render_cache);
        evidence.push(row_evidence);
        results.push(render_pipeline_item(
            analyzer,
            row,
            query.result_detail,
            &mut render_cache,
        ));
    }
    let structural_index_stale =
        !state
            .structural_index_session
            .selections_are_current(|generations| {
                state.analyzer.snapshot_generations_match(generations)
            });
    if structural_index_stale {
        results.clear();
        evidence.clear();
        truncated = true;
        state.access_failure.get_or_insert_with(|| {
            "structural source generation changed during result rendering".to_string()
        });
        if !diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::SemanticResultsOmitted
                && diagnostic.message.contains("structural posting")
        }) {
            diagnostics.push(CodeQueryDiagnostic {
                code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: "workspace",
                message: "source generation changed during structural posting replay; retry the query for a coherent snapshot".to_string(),
            });
        }
    }
    if !cancelled && !structural_index_stale {
        state.structural_index_session.publish_auto_observations();
    }
    let total_work = execution_work_snapshot(state.budget, semantic_work);
    let work = public_execution_work(total_work);
    if let Some(profile) = &mut state.profile {
        let execution_work = execution_work_profile.unwrap_or_default();
        profile.rendering_ns = rendering_started.map(elapsed_ns).unwrap_or(0);
        profile.total_elapsed_ns = request_started.map(elapsed_ns).unwrap_or(0);
        profile.execution_work = execution_work;
        profile.rendering_work = total_work.saturating_sub(execution_work);
        profile.work = total_work;
        profile.cache = state.cache_profile.unwrap_or_default();
    }
    let profile = state.profile;
    if let Some(out) = access_failure_out {
        *out = state.access_failure.take();
    }
    let detailed = DetailedCodeQueryResult {
        result: CodeQueryResult {
            results,
            truncated: truncated || cancelled,
            diagnostics,
        },
        work,
        evidence,
        profile,
    };
    detailed.assert_invariants();
    detailed
}

fn select_physical_plan(
    query: &CodeQuery,
    strategy: UnionExecutionStrategy,
    scheduler_workers: usize,
) -> Result<PhysicalQueryPlan, QueryError> {
    let logical_plan = LogicalQueryPlan::lower(query)?;
    let parallel_union = select_parallel_union(&logical_plan, strategy, scheduler_workers);
    Ok(PhysicalQueryPlan::select_with_parallel_union(
        logical_plan,
        parallel_union,
    ))
}

fn select_parallel_union(
    logical_plan: &LogicalQueryPlan,
    strategy: UnionExecutionStrategy,
    scheduler_workers: usize,
) -> Option<super::execution::plan::LogicalQueryNodeId> {
    if strategy == UnionExecutionStrategy::Sequential || scheduler_workers < 2 {
        return None;
    }
    let LogicalQueryOperator::Limit { input, .. } =
        logical_plan.node(logical_plan.root()).operator()
    else {
        return None;
    };
    let union = *input;
    let LogicalQueryOperator::Set {
        op: SetOperator::Union,
        inputs,
    } = logical_plan.node(union).operator()
    else {
        return None;
    };
    if inputs.len() != 2 || inputs[0] == inputs[1] {
        return None;
    }
    inputs
        .iter()
        .all(|&input| {
            matches!(
                logical_plan.node(input).operator(),
                LogicalQueryOperator::Seed(_)
            )
        })
        .then_some(())?;

    // The corrected M4 request-scoped, persistence-isolated A/B found no
    // stable cold-and-warm crossover, even at 1,001 analyzed files. Retain the
    // independently testable physical alternative, but keep production Auto
    // on the conservative sequential implementation until a later workload
    // supplies a measured selector with positive evidence.
    (strategy == UnionExecutionStrategy::Parallel).then_some(union)
}

fn detailed_result_without_evidence(
    result: CodeQueryResult,
    budget: CodeQueryExecutionBudget,
) -> DetailedCodeQueryResult {
    let detailed = DetailedCodeQueryResult {
        result,
        work: public_execution_work(execution_work_snapshot(
            budget,
            CodeQuerySemanticWork::default(),
        )),
        evidence: Vec::new(),
        profile: None,
    };
    detailed.assert_invariants();
    detailed
}

fn public_execution_work(work: QueryOperatorWorkProfile) -> CodeQueryExecutionWork {
    CodeQueryExecutionWork {
        scanned_files: work.scanned_files,
        scanned_source_bytes: work.scanned_source_bytes,
        fact_nodes: work.fact_nodes,
        pipeline_rows: work.pipeline_rows,
        examined_references: work.examined_references,
        semantic: work.semantic,
    }
}

fn execution_work_snapshot(
    budget: CodeQueryExecutionBudget,
    semantic: CodeQuerySemanticWork,
) -> QueryOperatorWorkProfile {
    let as_u64 = |value| u64::try_from(value).unwrap_or(u64::MAX);
    QueryOperatorWorkProfile {
        scanned_files: as_u64(budget.scanned_files),
        scanned_source_bytes: as_u64(budget.scanned_source_bytes),
        fact_nodes: as_u64(budget.fact_nodes),
        pipeline_rows: as_u64(budget.pipeline_rows),
        examined_references: as_u64(budget.examined_references),
        provenance_steps: as_u64(budget.provenance_steps),
        import_files_resolved: as_u64(budget.import_files_resolved),
        import_edges_resolved: as_u64(budget.import_edges_resolved),
        semantic,
    }
}

fn state_execution_work_snapshot(state: &QueryExecutionState<'_>) -> QueryOperatorWorkProfile {
    execution_work_snapshot(
        state.budget,
        state
            .semantic
            .as_ref()
            .map_or_else(CodeQuerySemanticWork::default, SemanticQueryContext::work),
    )
}

fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn detailed_evidence_for_pipeline_value(
    result_index: usize,
    value: &PipelineValue,
    retained_source: Option<&str>,
) -> DetailedCodeQueryEvidence {
    match value {
        PipelineValue::StructuralMatch(seed) => {
            let fact = seed.facts.node(seed.fact_match.node);
            let span = fact.span();
            let byte_span = span.start_byte..span.end_byte;
            let path = rel_path_string(&seed.file);
            let stable_owner_candidate = canonical_ast_candidate(seed);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::StructuralMatch,
                key: DetailedCodeQueryKey::StructuralMatch {
                    kind: fact.kind.label().to_string(),
                    analyzer_id: Some(match_id(&path, fact.kind.label(), span)),
                },
                file: seed.file.clone(),
                source_slice_sha256: source_slice_sha256(seed.facts.source(), &byte_span),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::Primary(
                    stable_owner_candidate.clone().map(|candidate| {
                        DetailedCodeQueryIdentityCandidate {
                            file: seed.file.clone(),
                            candidate,
                        }
                    }),
                ),
                stable_owner_candidate,
                provenance: Vec::new(),
            }
        }
        PipelineValue::Declaration(declaration) => {
            let file = declaration.unit.source().clone();
            let path = rel_path_string(&file);
            let kind = declaration.unit.kind().display_lowercase();
            let fq_name = declaration.unit.fq_name();
            let byte_span = range_byte_span(declaration.range);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::Declaration,
                key: DetailedCodeQueryKey::Declaration {
                    kind: kind.to_string(),
                    fq_name: fq_name.clone(),
                    analyzer_id: Some(declaration_id(&path, kind, &fq_name, declaration.range)),
                },
                file: file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::Primary(
                    detailed_identity_candidate_for_unit(&declaration.unit),
                ),
                stable_owner_candidate: stable_owner_candidate_for_unit(&file, &declaration.unit),
                provenance: Vec::new(),
            }
        }
        PipelineValue::Semantic(value) => {
            let projection = value.detailed_projection();
            detailed_semantic_evidence(
                result_index,
                projection.domain,
                projection.key,
                projection.file,
                projection.byte_span,
                projection.language,
                projection.stable_id,
                retained_source,
            )
        }
        PipelineValue::File(file) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::File,
            key: DetailedCodeQueryKey::File,
            file: file.clone(),
            byte_span: None,
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            source_slice_sha256: None,
            provenance: Vec::new(),
        },
        PipelineValue::ReferenceSite(site) => {
            let target_path = rel_path_string(site.target.unit.source());
            let target_kind = site.target.unit.kind().display_lowercase();
            let target_fq_name = site.target.unit.fq_name();
            let byte_span = range_byte_span(site.range);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ReferenceSite,
                key: DetailedCodeQueryKey::ReferenceSite {
                    target_id: Some(declaration_id(
                        &target_path,
                        target_kind,
                        &target_fq_name,
                        site.target.range,
                    )),
                    target_fq_name,
                },
                file: site.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::ReferenceTarget(
                    detailed_identity_candidate_for_unit(&site.target.unit),
                ),
                stable_owner_candidate: site.enclosing.as_ref().and_then(|declaration| {
                    stable_owner_candidate_for_unit(&site.file, &declaration.unit)
                }),
                provenance: Vec::new(),
            }
        }
        PipelineValue::CallSite(site) => {
            let file = &site.0.file;
            let byte_span = range_byte_span(site.0.range);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::CallSite,
                key: DetailedCodeQueryKey::CallSite {
                    caller_fq_name: site.0.caller.fq_name(),
                    callee_fq_name: site.0.callee.fq_name(),
                },
                file: file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::Call {
                    caller: detailed_identity_candidate_for_unit(&site.0.caller),
                    callee: detailed_identity_candidate_for_unit(&site.0.callee),
                },
                stable_owner_candidate: stable_owner_candidate_for_unit(file, &site.0.caller),
                provenance: Vec::new(),
            }
        }
        PipelineValue::ExpressionSite(site) => {
            let file = &site.call_site.0.file;
            let byte_span = range_byte_span(site.range);
            let (input_kind, parameter_index, parameter_name) = expression_input_parts(&site.input);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ExpressionSite,
                key: DetailedCodeQueryKey::ExpressionSite {
                    input_kind: input_kind.to_string(),
                    parameter_index: parameter_index.map(|index| {
                        u32::try_from(index).expect("query parameter indexes fit in u32")
                    }),
                    parameter_name,
                },
                file: file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: stable_owner_candidate_for_unit(
                    file,
                    &site.call_site.0.caller,
                ),
                provenance: Vec::new(),
            }
        }
        PipelineValue::ReceiverAnalysis(value) => {
            let site = &value.report.site;
            let byte_span = range_byte_span(site.range);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ReceiverAnalysis,
                key: DetailedCodeQueryKey::ReceiverAnalysis {
                    analysis_kind: value.report.operation.as_str().to_string(),
                    outcome: receiver_query_outcome_label(&value.report.analysis).to_string(),
                    capture: value.capture.clone(),
                },
                file: site.file.clone(),
                source_slice_sha256: None,
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
            }
        }
        PipelineValue::ReceiverOutcome(value) => {
            let site = &value.report.site;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ReceiverOutcome,
                key: DetailedCodeQueryKey::ReceiverOutcome {
                    id: value.site_id.clone(),
                    site_id: value.site_id.clone(),
                },
                file: site.file.clone(),
                source_slice_sha256: None,
                byte_span: Some(range_byte_span(site.range)),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
            }
        }
        PipelineValue::ReceiverEvidence(value) => {
            let site = &value.receiver.report.site;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ReceiverEvidence,
                key: DetailedCodeQueryKey::ReceiverEvidence {
                    id: value.id.clone(),
                    site_id: value.receiver.site_id.clone(),
                },
                file: site.file.clone(),
                source_slice_sha256: None,
                byte_span: Some(range_byte_span(site.range)),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
            }
        }
        PipelineValue::CallShape(value) => {
            let outcome = &value.report.outcome;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::CallShape,
                key: DetailedCodeQueryKey::CallShape {
                    id: outcome.id.clone(),
                    site_id: outcome.site_id.clone(),
                },
                file: outcome.file.clone(),
                source_slice_sha256: None,
                byte_span: Some(range_byte_span(outcome.range)),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
            }
        }
        PipelineValue::CallArgumentGroup(value) => {
            let outcome = &value.shape.report.outcome;
            let group = &value.shape.report.groups[value.group_index];
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::CallArgumentGroup,
                key: DetailedCodeQueryKey::CallArgumentGroup {
                    id: group.id.clone(),
                    site_id: group.site_id.clone(),
                },
                file: outcome.file.clone(),
                source_slice_sha256: None,
                byte_span: Some(range_byte_span(outcome.range)),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
            }
        }
        PipelineValue::CallArgument(value) => {
            let outcome = &value.shape.report.outcome;
            let argument = &value.shape.report.arguments[value.argument_index];
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::CallArgument,
                key: DetailedCodeQueryKey::CallArgument {
                    id: argument.id.clone(),
                    group_id: argument.group_id.clone(),
                },
                file: outcome.file.clone(),
                source_slice_sha256: None,
                byte_span: Some(range_byte_span(argument.range)),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
            }
        }
        PipelineValue::Occurrence(value) => {
            let row = &value.row;
            let byte_span = row.range.start_byte..row.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::Occurrence,
                key: DetailedCodeQueryKey::Occurrence {
                    id: row.id(),
                    ast_id: row.ast_id(),
                    role: row.role.label().to_string(),
                },
                file: row.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: row
                    .enclosing
                    .as_ref()
                    .and_then(|unit| stable_owner_candidate_for_unit(&row.file, unit)),
                provenance: Vec::new(),
            }
        }
        PipelineValue::LexicalScope(value) => {
            let row = value.row();
            let byte_span = row.range.start_byte..row.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::LexicalScope,
                key: DetailedCodeQueryKey::LexicalScope {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    index: row.index,
                },
                file: row.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
            }
        }
        PipelineValue::Binding(value) => {
            let row = value.row();
            let byte_span = row.range.start_byte..row.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::Binding,
                key: DetailedCodeQueryKey::Binding {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    name: row.name.clone(),
                },
                file: row.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
            }
        }
        PipelineValue::GenerationSite(value) => {
            let row = value.row();
            let byte_span = row.site.start_byte..row.site.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::GenerationSite,
                key: DetailedCodeQueryKey::GenerationSite {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    kind: row.kind.label().to_string(),
                },
                file: row.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
            }
        }
        PipelineValue::Export(value) => {
            let row = value.row();
            let byte_span = row.range.start_byte..row.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::Export,
                key: DetailedCodeQueryKey::Export {
                    id: value.id(),
                    form: row.form.label().to_string(),
                    exported_name: row.exported_name.clone(),
                },
                file: row.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
            }
        }
        PipelineValue::DeclarationState(value) => {
            let row = value.row();
            let byte_span = row
                .declaration
                .map(|declaration| declaration.start_byte..declaration.end_byte);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::DeclarationState,
                key: DetailedCodeQueryKey::DeclarationState {
                    id: value.id(),
                    fq_name: row.unit.fq_name().to_string(),
                    origin: row.origin.label().to_string(),
                },
                file: row.file.clone(),
                source_slice_sha256: byte_span.as_ref().and_then(|span| {
                    retained_source.and_then(|source| source_slice_sha256(source, span))
                }),
                byte_span,
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
            }
        }
        PipelineValue::ReferenceEdge(value) => {
            let row = &value.row;
            let byte_span = row.site.range.start_byte..row.site.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ReferenceEdge,
                key: DetailedCodeQueryKey::ReferenceEdge {
                    id: value.id(),
                    ast_id: row.site.ast_id.clone(),
                    target_fq_name: value.target.unit.fq_name(),
                    provenance: row.provenance.label().to_string(),
                },
                file: row.site.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: row
                    .site
                    .enclosing
                    .as_ref()
                    .and_then(|unit| stable_owner_candidate_for_unit(&row.site.file, unit)),
                provenance: Vec::new(),
            }
        }
        PipelineValue::ResolutionCandidate(value) => {
            let row = &value.occurrence;
            let byte_span = row.range.start_byte..row.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ResolutionCandidate,
                key: DetailedCodeQueryKey::ResolutionCandidate {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    ordinal: value.ordinal,
                },
                file: row.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: row
                    .enclosing
                    .as_ref()
                    .and_then(|unit| stable_owner_candidate_for_unit(&row.file, unit)),
                provenance: Vec::new(),
            }
        }
        PipelineValue::QualifiedPath(value) => {
            let row = value.row();
            let byte_span = row.range.start_byte..row.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::QualifiedPath,
                key: DetailedCodeQueryKey::QualifiedPath {
                    id: value.id(),
                    ast_id: row.ast_id(),
                },
                file: row.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
            }
        }
        PipelineValue::PathSegment(value) => {
            let row = value.row();
            let byte_span = row.range.start_byte..row.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::PathSegment,
                key: DetailedCodeQueryKey::PathSegment {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    ordinal: row.ordinal,
                },
                file: row.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn detailed_semantic_evidence(
    result_index: usize,
    domain: DetailedCodeQueryDomain,
    key: DetailedCodeQueryKey,
    file: &ProjectFile,
    byte_span: std::ops::Range<usize>,
    language: &str,
    wire_id: String,
    retained_source: Option<&str>,
) -> DetailedCodeQueryEvidence {
    let candidate = CodeQueryStableOwnerCandidate {
        namespace: language.to_string(),
        derivation: CodeQueryStableOwnerDerivation::SemanticWireId,
        semantic_key: wire_id,
    };
    DetailedCodeQueryEvidence {
        result_index,
        domain,
        key,
        file: file.clone(),
        source_slice_sha256: retained_source
            .and_then(|source| source_slice_sha256(source, &byte_span)),
        byte_span: Some(byte_span),
        identities: DetailedCodeQueryProvenanceIdentities::Primary(Some(
            DetailedCodeQueryIdentityCandidate {
                file: file.clone(),
                candidate: candidate.clone(),
            },
        )),
        stable_owner_candidate: Some(candidate),
        provenance: Vec::new(),
    }
}

fn range_byte_span(range: Range) -> std::ops::Range<usize> {
    range.start_byte..range.end_byte
}

fn source_slice_sha256(source: &str, byte_span: &std::ops::Range<usize>) -> Option<[u8; 32]> {
    source
        .as_bytes()
        .get(byte_span.clone())
        .map(|bytes| Sha256::digest(bytes).into())
}

fn terminal_source_file(value: &PipelineValue) -> Option<&ProjectFile> {
    match value {
        PipelineValue::StructuralMatch(seed) => Some(&seed.file),
        PipelineValue::Declaration(declaration) => Some(declaration.unit.source()),
        PipelineValue::Semantic(value) => Some(value.file()),
        PipelineValue::ReferenceSite(site) => Some(&site.file),
        PipelineValue::CallSite(site) => Some(&site.0.file),
        PipelineValue::ExpressionSite(site) => Some(&site.call_site.0.file),
        PipelineValue::CallShape(value) => Some(&value.report.outcome.file),
        PipelineValue::CallArgumentGroup(value) => Some(&value.shape.report.outcome.file),
        PipelineValue::CallArgument(value) => Some(&value.shape.report.outcome.file),
        PipelineValue::Occurrence(value) => Some(value.file()),
        PipelineValue::LexicalScope(value) => Some(value.file()),
        PipelineValue::QualifiedPath(value) => Some(value.file()),
        PipelineValue::PathSegment(value) => Some(value.file()),
        PipelineValue::Binding(value) => Some(value.file()),
        PipelineValue::ResolutionCandidate(value) => Some(value.file()),
        PipelineValue::GenerationSite(value) => Some(value.file()),
        PipelineValue::Export(value) => Some(value.file()),
        PipelineValue::DeclarationState(value) => Some(value.file()),
        PipelineValue::ReferenceEdge(value) => Some(value.file()),
        PipelineValue::ReceiverOutcome(value) => Some(&value.report.site.file),
        PipelineValue::ReceiverEvidence(value) => Some(&value.receiver.report.site.file),
        PipelineValue::File(_) | PipelineValue::ReceiverAnalysis(_) => None,
    }
}

/// Retain every source that full-detail terminal and provenance rendering can
/// consult, before rendering is sealed against untracked cache misses.
fn retain_budgeted_pipeline_sources(
    analyzer: &dyn IAnalyzer,
    row: &PipelineRow,
    cache: &mut PipelineRenderCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> bool {
    let mut files = BTreeSet::new();
    let mut exhausted = false;
    collect_pipeline_value_source_files(&row.value, &mut files);
    if let PipelineValue::StructuralMatch(seed) = &row.value {
        exhausted |= retain_held_source_snapshot(
            cache,
            &seed.file,
            seed.facts.source(),
            seed.language,
            Vec::new(),
            diagnostics,
        );
    }
    for trace in &row.traces {
        exhausted |= retain_held_source_snapshot(
            cache,
            &trace.seed.file,
            trace.seed.facts.source(),
            trace.seed.language,
            trace.branch.clone(),
            diagnostics,
        );
        for step in &trace.steps {
            collect_trace_value_source_files(&step.value, &mut files);
            if let Some(via) = &step.via {
                collect_via_source_files(via, &mut files);
            }
        }
    }

    for file in files {
        exhausted |=
            retain_budgeted_source_snapshot(analyzer, &file, cache, budget, limits, diagnostics);
    }
    exhausted
}

fn retain_held_source_snapshot(
    cache: &mut PipelineRenderCache,
    file: &ProjectFile,
    source: &str,
    language: Language,
    branch: Vec<usize>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> bool {
    let conflict_before = cache.conflicting_sources.contains(file);
    if cache.retain_source_snapshot(file, source) {
        return false;
    }
    if !conflict_before {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch,
            language: language.config_label(),
            message: format!(
                "conflicting analyzer-generation source snapshots for {} prevent exact result evidence",
                rel_path_string(file)
            ),
        });
    }
    true
}

fn collect_pipeline_value_source_files(value: &PipelineValue, files: &mut BTreeSet<ProjectFile>) {
    match value {
        PipelineValue::StructuralMatch(seed) => {
            files.insert(seed.file.clone());
        }
        PipelineValue::Declaration(declaration) => {
            files.insert(declaration.unit.source().clone());
        }
        PipelineValue::Semantic(value) => {
            files.insert(value.file().clone());
        }
        PipelineValue::File(_) => {}
        PipelineValue::ReferenceSite(site) => collect_reference_source_files(site, files),
        PipelineValue::CallSite(site) => collect_call_source_files(site, files),
        PipelineValue::ExpressionSite(site) => collect_call_source_files(&site.call_site, files),
        PipelineValue::ReceiverAnalysis(value) => collect_receiver_source_files(value, files),
        PipelineValue::ReceiverOutcome(value) => collect_receiver_source_files(value, files),
        PipelineValue::ReceiverEvidence(value) => {
            collect_receiver_source_files(&value.receiver, files)
        }
        PipelineValue::CallShape(value) => {
            files.insert(value.report.outcome.file.clone());
        }
        PipelineValue::CallArgumentGroup(value) => {
            files.insert(value.shape.report.outcome.file.clone());
        }
        PipelineValue::CallArgument(value) => {
            files.insert(value.shape.report.outcome.file.clone());
        }
        PipelineValue::Occurrence(value) => {
            files.insert(value.file().clone());
        }
        PipelineValue::LexicalScope(value) => {
            files.insert(value.file().clone());
        }
        PipelineValue::Binding(value) => {
            files.insert(value.file().clone());
        }
        PipelineValue::ResolutionCandidate(value) => {
            files.insert(value.file().clone());
        }
        PipelineValue::GenerationSite(value) => {
            files.insert(value.file().clone());
        }
        PipelineValue::Export(value) => {
            files.insert(value.file().clone());
        }
        PipelineValue::DeclarationState(value) => {
            files.insert(value.file().clone());
        }
        PipelineValue::ReferenceEdge(value) => collect_edge_source_files(value, files),
        PipelineValue::QualifiedPath(value) => {
            files.insert(value.file().clone());
        }
        PipelineValue::PathSegment(value) => {
            files.insert(value.file().clone());
        }
    }
}

fn collect_trace_value_source_files(value: &PipelineTraceValue, files: &mut BTreeSet<ProjectFile>) {
    match value {
        PipelineTraceValue::Declaration(declaration) => {
            files.insert(declaration.unit.source().clone());
        }
        PipelineTraceValue::Semantic(value) => {
            files.insert(value.file().clone());
        }
        PipelineTraceValue::File(_) => {}
        PipelineTraceValue::ReferenceSite(site) => collect_reference_source_files(site, files),
        PipelineTraceValue::CallSite(site) => collect_call_source_files(site, files),
        PipelineTraceValue::ExpressionSite(site) => {
            collect_call_source_files(&site.call_site, files);
        }
        PipelineTraceValue::ReceiverAnalysis(value) => collect_receiver_source_files(value, files),
        PipelineTraceValue::ReceiverOutcome(value) => collect_receiver_source_files(value, files),
        PipelineTraceValue::ReceiverEvidence(value) => {
            collect_receiver_source_files(&value.receiver, files)
        }
        PipelineTraceValue::CallShape(value) => {
            files.insert(value.report.outcome.file.clone());
        }
        PipelineTraceValue::CallArgumentGroup(value) => {
            files.insert(value.shape.report.outcome.file.clone());
        }
        PipelineTraceValue::CallArgument(value) => {
            files.insert(value.shape.report.outcome.file.clone());
        }
        PipelineTraceValue::Occurrence(value) => {
            files.insert(value.file().clone());
        }
        PipelineTraceValue::LexicalScope(value) => {
            files.insert(value.file().clone());
        }
        PipelineTraceValue::Binding(value) => {
            files.insert(value.file().clone());
        }
        PipelineTraceValue::ResolutionCandidate(value) => {
            files.insert(value.file().clone());
        }
        PipelineTraceValue::GenerationSite(value) => {
            files.insert(value.file().clone());
        }
        PipelineTraceValue::Export(value) => {
            files.insert(value.file().clone());
        }
        PipelineTraceValue::DeclarationState(value) => {
            files.insert(value.file().clone());
        }
        PipelineTraceValue::ReferenceEdge(value) => collect_edge_source_files(value, files),
        PipelineTraceValue::QualifiedPath(value) => {
            files.insert(value.file().clone());
        }
        PipelineTraceValue::PathSegment(value) => {
            files.insert(value.file().clone());
        }
    }
}

fn collect_edge_source_files(value: &EdgeValue, files: &mut BTreeSet<ProjectFile>) {
    files.insert(value.row.site.file.clone());
    files.insert(value.target.unit.source().clone());
    if let Some(enclosing) = &value.enclosing {
        files.insert(enclosing.unit.source().clone());
    }
}

fn collect_via_source_files(via: &PipelineVia, files: &mut BTreeSet<ProjectFile>) {
    match via {
        PipelineVia::ReferenceSite(site) => collect_reference_source_files(site, files),
        PipelineVia::CallSite(site) => collect_call_source_files(site, files),
    }
}

fn collect_reference_source_files(site: &ReferenceSiteValue, files: &mut BTreeSet<ProjectFile>) {
    files.insert(site.file.clone());
    files.insert(site.target.unit.source().clone());
    if let Some(enclosing) = &site.enclosing {
        files.insert(enclosing.unit.source().clone());
    }
}

fn collect_call_source_files(site: &CallSiteValue, files: &mut BTreeSet<ProjectFile>) {
    files.insert(site.0.file.clone());
    files.insert(site.0.caller.source().clone());
    files.insert(site.0.callee.source().clone());
}

fn collect_receiver_source_files(value: &ReceiverAnalysisValue, files: &mut BTreeSet<ProjectFile>) {
    files.insert(value.report.site.file.clone());
    match &value.report.analysis {
        ReceiverQueryAnalysis::Values(outcome) => {
            let mut stack = outcome.values().into_iter().flatten().collect::<Vec<_>>();
            while let Some(value) = stack.pop() {
                match value {
                    ReceiverValue::AllocationSite { ty, file, .. } => {
                        files.insert(ty.source().clone());
                        files.insert(file.clone());
                    }
                    ReceiverValue::InstanceType(unit)
                    | ReceiverValue::ClassOrStaticObject(unit)
                    | ReceiverValue::ModuleOrExportObject(unit)
                    | ReceiverValue::CurrentReceiver(unit) => {
                        files.insert(unit.source().clone());
                    }
                    ReceiverValue::FactoryReturn { factory, value } => {
                        files.insert(factory.source().clone());
                        stack.push(value);
                    }
                }
            }
        }
        ReceiverQueryAnalysis::MemberTargets(outcome) => {
            for unit in outcome.values().into_iter().flatten() {
                files.insert(unit.source().clone());
            }
        }
    }
}

/// Hydrate one source through the execution budget.
///
/// Returns `true` when a hard query limit prevented retaining the snapshot.
/// The cache receives a negative entry in that case so public full-detail
/// rendering cannot retry the same read outside the tracker.
fn retain_budgeted_source_snapshot(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    cache: &mut PipelineRenderCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> bool {
    if cache.sources.contains_key(file) {
        return false;
    }

    let mut projected = *budget;
    projected.scanned_files = projected.scanned_files.saturating_add(1);
    if projected.scanned_files > limits.max_scanned_files {
        cache.retain_loaded_source(file, None);
        push_budget_diagnostic(diagnostics, &projected);
        return true;
    }

    let source = analyzer.indexed_source(file);
    projected.scanned_source_bytes = projected
        .scanned_source_bytes
        .saturating_add(source.as_ref().map_or(0, String::len));
    if projected.scanned_source_bytes > limits.max_scanned_source_bytes {
        cache.retain_loaded_source(file, None);
        push_budget_diagnostic(diagnostics, &projected);
        return true;
    }

    budget.scanned_files = projected.scanned_files;
    budget.scanned_source_bytes = projected.scanned_source_bytes;
    cache.retain_loaded_source(file, source);
    false
}

fn detailed_provenance_for_row(
    row: &PipelineRow,
    cache: &PipelineRenderCache,
) -> Vec<DetailedCodeQueryProvenanceEvidence> {
    row.traces
        .iter()
        .map(|trace| DetailedCodeQueryProvenanceEvidence {
            branch: trace.branch.clone(),
            seed: detailed_seed_provenance_ref(&trace.seed),
            steps: trace
                .steps
                .iter()
                .map(|step| DetailedCodeQueryProvenanceStepEvidence {
                    op: step.op.label().to_string(),
                    result: detailed_trace_provenance_ref(&step.value, cache),
                    via: step
                        .via
                        .as_ref()
                        .map(|via| detailed_via_provenance_ref(via, cache)),
                })
                .collect(),
        })
        .collect()
}

fn detailed_seed_provenance_ref(seed: &SeedMatch) -> DetailedCodeQueryProvenanceRefEvidence {
    let fact = seed.facts.node(seed.fact_match.node);
    let span = fact.span();
    let byte_span = span.start_byte..span.end_byte;
    let path = rel_path_string(&seed.file);
    DetailedCodeQueryProvenanceRefEvidence {
        domain: DetailedCodeQueryDomain::StructuralMatch,
        key: DetailedCodeQueryKey::StructuralMatch {
            kind: fact.kind.label().to_string(),
            analyzer_id: Some(match_id(&path, fact.kind.label(), span)),
        },
        file: seed.file.clone(),
        source_slice_sha256: source_slice_sha256(seed.facts.source(), &byte_span),
        byte_span: Some(byte_span),
        display_range: Some(range_for_span(&seed.facts, fact.span())),
        identities: DetailedCodeQueryProvenanceIdentities::Primary(
            canonical_ast_candidate(seed).map(|candidate| DetailedCodeQueryIdentityCandidate {
                file: seed.file.clone(),
                candidate,
            }),
        ),
    }
}

fn detailed_trace_provenance_ref(
    value: &PipelineTraceValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    match value {
        PipelineTraceValue::Declaration(value) => detailed_declaration_provenance_ref(value, cache),
        PipelineTraceValue::Semantic(value) => {
            let projection = value.detailed_projection();
            detailed_semantic_provenance_ref(
                projection.domain,
                projection.key,
                projection.file,
                projection.byte_span,
                projection.display_range,
                projection.language,
                projection.stable_id,
                cache,
            )
        }
        PipelineTraceValue::File(file) => DetailedCodeQueryProvenanceRefEvidence {
            domain: DetailedCodeQueryDomain::File,
            key: DetailedCodeQueryKey::File,
            file: file.clone(),
            byte_span: None,
            display_range: None,
            identities: DetailedCodeQueryProvenanceIdentities::None,
            source_slice_sha256: None,
        },
        PipelineTraceValue::ReferenceSite(value) => detailed_reference_provenance_ref(value, cache),
        PipelineTraceValue::CallSite(value) => detailed_call_provenance_ref(value, cache),
        PipelineTraceValue::ExpressionSite(value) => {
            detailed_expression_provenance_ref(value, cache)
        }
        PipelineTraceValue::ReceiverAnalysis(value) => {
            detailed_receiver_provenance_ref(value, cache)
        }
        PipelineTraceValue::ReceiverOutcome(value) => {
            detailed_receiver_outcome_provenance_ref(value, cache)
        }
        PipelineTraceValue::ReceiverEvidence(value) => {
            detailed_receiver_evidence_provenance_ref(value, cache)
        }
        PipelineTraceValue::CallShape(value) => detailed_call_shape_provenance_ref(
            DetailedCodeQueryDomain::CallShape,
            DetailedCodeQueryKey::CallShape {
                id: value.report.outcome.id.clone(),
                site_id: value.report.outcome.site_id.clone(),
            },
            &value.report.outcome.file,
            value.report.outcome.range,
            cache,
        ),
        PipelineTraceValue::CallArgumentGroup(value) => {
            let group = &value.shape.report.groups[value.group_index];
            detailed_call_shape_provenance_ref(
                DetailedCodeQueryDomain::CallArgumentGroup,
                DetailedCodeQueryKey::CallArgumentGroup {
                    id: group.id.clone(),
                    site_id: group.site_id.clone(),
                },
                &value.shape.report.outcome.file,
                value.shape.report.outcome.range,
                cache,
            )
        }
        PipelineTraceValue::CallArgument(value) => {
            let argument = &value.shape.report.arguments[value.argument_index];
            detailed_call_shape_provenance_ref(
                DetailedCodeQueryDomain::CallArgument,
                DetailedCodeQueryKey::CallArgument {
                    id: argument.id.clone(),
                    group_id: argument.group_id.clone(),
                },
                &value.shape.report.outcome.file,
                argument.range,
                cache,
            )
        }
        PipelineTraceValue::Occurrence(value) => detailed_occurrence_provenance_ref(value, cache),
        PipelineTraceValue::GenerationSite(value) => {
            let row = value.row();
            detailed_environment_provenance_ref(
                DetailedCodeQueryDomain::GenerationSite,
                DetailedCodeQueryKey::GenerationSite {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    kind: row.kind.label().to_string(),
                },
                &row.file,
                row.site,
                cache,
            )
        }
        PipelineTraceValue::Export(value) => {
            let row = value.row();
            detailed_environment_provenance_ref(
                DetailedCodeQueryDomain::Export,
                DetailedCodeQueryKey::Export {
                    id: value.id(),
                    form: row.form.label().to_string(),
                    exported_name: row.exported_name.clone(),
                },
                &row.file,
                row.range,
                cache,
            )
        }
        PipelineTraceValue::DeclarationState(value) => {
            let row = value.row();
            detailed_environment_provenance_ref(
                DetailedCodeQueryDomain::DeclarationState,
                DetailedCodeQueryKey::DeclarationState {
                    id: value.id(),
                    fq_name: row.unit.fq_name().to_string(),
                    origin: row.origin.label().to_string(),
                },
                &row.file,
                row.declaration.unwrap_or(Range {
                    start_byte: 0,
                    end_byte: 0,
                    start_line: 1,
                    end_line: 1,
                }),
                cache,
            )
        }
        PipelineTraceValue::LexicalScope(value) => {
            let row = value.row();
            detailed_environment_provenance_ref(
                DetailedCodeQueryDomain::LexicalScope,
                DetailedCodeQueryKey::LexicalScope {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    index: row.index,
                },
                &row.file,
                row.range,
                cache,
            )
        }
        PipelineTraceValue::Binding(value) => {
            let row = value.row();
            detailed_environment_provenance_ref(
                DetailedCodeQueryDomain::Binding,
                DetailedCodeQueryKey::Binding {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    name: row.name.clone(),
                },
                &row.file,
                row.range,
                cache,
            )
        }
        PipelineTraceValue::ResolutionCandidate(value) => {
            let row = &value.occurrence;
            detailed_environment_provenance_ref(
                DetailedCodeQueryDomain::ResolutionCandidate,
                DetailedCodeQueryKey::ResolutionCandidate {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    ordinal: value.ordinal,
                },
                &row.file,
                row.range,
                cache,
            )
        }
        PipelineTraceValue::ReferenceEdge(value) => {
            let row = &value.row;
            detailed_environment_provenance_ref(
                DetailedCodeQueryDomain::ReferenceEdge,
                DetailedCodeQueryKey::ReferenceEdge {
                    id: value.id(),
                    ast_id: row.site.ast_id.clone(),
                    target_fq_name: value.target.unit.fq_name(),
                    provenance: row.provenance.label().to_string(),
                },
                &row.site.file,
                row.site.range,
                cache,
            )
        }
        PipelineTraceValue::QualifiedPath(value) => {
            let row = value.row();
            detailed_environment_provenance_ref(
                DetailedCodeQueryDomain::QualifiedPath,
                DetailedCodeQueryKey::QualifiedPath {
                    id: value.id(),
                    ast_id: row.ast_id(),
                },
                &row.file,
                row.range,
                cache,
            )
        }
        PipelineTraceValue::PathSegment(value) => {
            let row = value.row();
            detailed_environment_provenance_ref(
                DetailedCodeQueryDomain::PathSegment,
                DetailedCodeQueryKey::PathSegment {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    ordinal: row.ordinal,
                },
                &row.file,
                row.range,
                cache,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn detailed_semantic_provenance_ref(
    domain: DetailedCodeQueryDomain,
    key: DetailedCodeQueryKey,
    file: &ProjectFile,
    byte_span: std::ops::Range<usize>,
    display_range: CodeQueryRange,
    language: &str,
    wire_id: String,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let candidate = CodeQueryStableOwnerCandidate {
        namespace: language.to_string(),
        derivation: CodeQueryStableOwnerDerivation::SemanticWireId,
        semantic_key: wire_id,
    };
    DetailedCodeQueryProvenanceRefEvidence {
        domain,
        key,
        file: file.clone(),
        source_slice_sha256: cached_source_slice_sha256(cache, file, &byte_span),
        byte_span: Some(byte_span),
        display_range: Some(display_range),
        identities: DetailedCodeQueryProvenanceIdentities::Primary(Some(
            DetailedCodeQueryIdentityCandidate {
                file: file.clone(),
                candidate,
            },
        )),
    }
}

fn detailed_via_provenance_ref(
    value: &PipelineVia,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    match value {
        PipelineVia::ReferenceSite(value) => detailed_reference_provenance_ref(value, cache),
        PipelineVia::CallSite(value) => detailed_call_provenance_ref(value, cache),
    }
}

fn detailed_declaration_provenance_ref(
    declaration: &DeclarationValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let file = declaration.unit.source().clone();
    let path = rel_path_string(&file);
    let kind = declaration.unit.kind().display_lowercase();
    let fq_name = declaration.unit.fq_name();
    let byte_span = range_byte_span(declaration.range);
    DetailedCodeQueryProvenanceRefEvidence {
        domain: DetailedCodeQueryDomain::Declaration,
        key: DetailedCodeQueryKey::Declaration {
            kind: kind.to_string(),
            fq_name: fq_name.clone(),
            analyzer_id: Some(declaration_id(&path, kind, &fq_name, declaration.range)),
        },
        file: file.clone(),
        source_slice_sha256: cached_source_slice_sha256(cache, &file, &byte_span),
        byte_span: Some(byte_span),
        display_range: cached_display_range(cache, &file, declaration.range),
        identities: DetailedCodeQueryProvenanceIdentities::Primary(
            detailed_identity_candidate_for_unit(&declaration.unit),
        ),
    }
}

fn detailed_reference_provenance_ref(
    site: &ReferenceSiteValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let target_path = rel_path_string(site.target.unit.source());
    let target_kind = site.target.unit.kind().display_lowercase();
    let target_fq_name = site.target.unit.fq_name();
    let byte_span = range_byte_span(site.range);
    DetailedCodeQueryProvenanceRefEvidence {
        domain: DetailedCodeQueryDomain::ReferenceSite,
        key: DetailedCodeQueryKey::ReferenceSite {
            target_id: Some(declaration_id(
                &target_path,
                target_kind,
                &target_fq_name,
                site.target.range,
            )),
            target_fq_name,
        },
        file: site.file.clone(),
        source_slice_sha256: cached_source_slice_sha256(cache, &site.file, &byte_span),
        byte_span: Some(byte_span),
        display_range: cached_display_range(cache, &site.file, site.range),
        identities: DetailedCodeQueryProvenanceIdentities::ReferenceTarget(
            detailed_identity_candidate_for_unit(&site.target.unit),
        ),
    }
}

fn detailed_call_provenance_ref(
    site: &CallSiteValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let file = &site.0.file;
    let byte_span = range_byte_span(site.0.range);
    DetailedCodeQueryProvenanceRefEvidence {
        domain: DetailedCodeQueryDomain::CallSite,
        key: DetailedCodeQueryKey::CallSite {
            caller_fq_name: site.0.caller.fq_name(),
            callee_fq_name: site.0.callee.fq_name(),
        },
        file: file.clone(),
        source_slice_sha256: cached_source_slice_sha256(cache, file, &byte_span),
        byte_span: Some(byte_span),
        display_range: cached_display_range(cache, file, site.0.range),
        identities: DetailedCodeQueryProvenanceIdentities::Call {
            caller: detailed_identity_candidate_for_unit(&site.0.caller),
            callee: detailed_identity_candidate_for_unit(&site.0.callee),
        },
    }
}

fn detailed_expression_provenance_ref(
    site: &ExpressionSiteValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let file = &site.call_site.0.file;
    let byte_span = range_byte_span(site.range);
    let (input_kind, parameter_index, parameter_name) = expression_input_parts(&site.input);
    DetailedCodeQueryProvenanceRefEvidence {
        domain: DetailedCodeQueryDomain::ExpressionSite,
        key: DetailedCodeQueryKey::ExpressionSite {
            input_kind: input_kind.to_string(),
            parameter_index: parameter_index
                .map(|index| u32::try_from(index).expect("query parameter indexes fit in u32")),
            parameter_name,
        },
        file: file.clone(),
        source_slice_sha256: cached_source_slice_sha256(cache, file, &byte_span),
        byte_span: Some(byte_span),
        display_range: cached_display_range(cache, file, site.range),
        identities: DetailedCodeQueryProvenanceIdentities::None,
    }
}

fn detailed_receiver_provenance_ref(
    value: &ReceiverAnalysisValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let site = &value.report.site;
    let byte_span = range_byte_span(site.range);
    DetailedCodeQueryProvenanceRefEvidence {
        domain: DetailedCodeQueryDomain::ReceiverAnalysis,
        key: DetailedCodeQueryKey::ReceiverAnalysis {
            analysis_kind: value.report.operation.as_str().to_string(),
            outcome: receiver_query_outcome_label(&value.report.analysis).to_string(),
            capture: value.capture.clone(),
        },
        file: site.file.clone(),
        source_slice_sha256: cached_source_slice_sha256(cache, &site.file, &byte_span),
        byte_span: Some(byte_span),
        display_range: cached_display_range(cache, &site.file, site.range),
        identities: DetailedCodeQueryProvenanceIdentities::None,
    }
}

fn detailed_receiver_outcome_provenance_ref(
    value: &ReceiverAnalysisValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let site = &value.report.site;
    let byte_span = range_byte_span(site.range);
    DetailedCodeQueryProvenanceRefEvidence {
        domain: DetailedCodeQueryDomain::ReceiverOutcome,
        key: DetailedCodeQueryKey::ReceiverOutcome {
            id: value.site_id.clone(),
            site_id: value.site_id.clone(),
        },
        file: site.file.clone(),
        source_slice_sha256: cached_source_slice_sha256(cache, &site.file, &byte_span),
        byte_span: Some(byte_span),
        display_range: cached_display_range(cache, &site.file, site.range),
        identities: DetailedCodeQueryProvenanceIdentities::None,
    }
}

fn detailed_receiver_evidence_provenance_ref(
    value: &ReceiverEvidenceValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let site = &value.receiver.report.site;
    let byte_span = range_byte_span(site.range);
    DetailedCodeQueryProvenanceRefEvidence {
        domain: DetailedCodeQueryDomain::ReceiverEvidence,
        key: DetailedCodeQueryKey::ReceiverEvidence {
            id: value.id.clone(),
            site_id: value.receiver.site_id.clone(),
        },
        file: site.file.clone(),
        source_slice_sha256: cached_source_slice_sha256(cache, &site.file, &byte_span),
        byte_span: Some(byte_span),
        display_range: cached_display_range(cache, &site.file, site.range),
        identities: DetailedCodeQueryProvenanceIdentities::None,
    }
}

fn detailed_occurrence_provenance_ref(
    value: &OccurrenceValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let row = &value.row;
    let byte_span = range_byte_span(row.range);
    DetailedCodeQueryProvenanceRefEvidence {
        domain: DetailedCodeQueryDomain::Occurrence,
        key: DetailedCodeQueryKey::Occurrence {
            id: row.id(),
            ast_id: row.ast_id(),
            role: row.role.label().to_string(),
        },
        file: row.file.clone(),
        source_slice_sha256: cached_source_slice_sha256(cache, &row.file, &byte_span),
        byte_span: Some(byte_span),
        display_range: cached_display_range(cache, &row.file, row.range),
        identities: DetailedCodeQueryProvenanceIdentities::None,
    }
}

/// The provenance-ref evidence shape shared by the three call-shape row
/// families: a typed key, the owning file, and the exact source range.
fn detailed_call_shape_provenance_ref(
    domain: DetailedCodeQueryDomain,
    key: DetailedCodeQueryKey,
    file: &ProjectFile,
    range: Range,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    detailed_environment_provenance_ref(domain, key, file, range, cache)
}

/// The provenance-ref evidence shape shared by the three lexical-environment
/// row families, whose identity is a digest plus a byte span and nothing else.
fn detailed_environment_provenance_ref(
    domain: DetailedCodeQueryDomain,
    key: DetailedCodeQueryKey,
    file: &ProjectFile,
    range: Range,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let byte_span = range_byte_span(range);
    DetailedCodeQueryProvenanceRefEvidence {
        domain,
        key,
        file: file.clone(),
        source_slice_sha256: cached_source_slice_sha256(cache, file, &byte_span),
        byte_span: Some(byte_span),
        display_range: cached_display_range(cache, file, range),
        identities: DetailedCodeQueryProvenanceIdentities::None,
    }
}

fn cached_source_slice_sha256(
    cache: &PipelineRenderCache,
    file: &ProjectFile,
    byte_span: &std::ops::Range<usize>,
) -> Option<[u8; 32]> {
    cache
        .source_snapshot(file)
        .and_then(|source| source_slice_sha256(source, byte_span))
}

fn cached_display_range(
    cache: &PipelineRenderCache,
    file: &ProjectFile,
    range: Range,
) -> Option<CodeQueryRange> {
    let coordinates = cache.sources.get(file)?.as_ref()?;
    Some(range_for_offsets(
        &coordinates.source,
        &coordinates.line_starts,
        range.start_byte,
        range.end_byte,
    ))
}

fn detailed_identity_candidate_for_unit(
    unit: &CodeUnit,
) -> Option<DetailedCodeQueryIdentityCandidate> {
    stable_identity_candidate_for_unit(unit).map(|candidate| DetailedCodeQueryIdentityCandidate {
        file: unit.source().clone(),
        candidate,
    })
}

fn stable_owner_candidate_for_unit(
    evidence_file: &ProjectFile,
    unit: &CodeUnit,
) -> Option<CodeQueryStableOwnerCandidate> {
    if unit.source() != evidence_file {
        return None;
    }
    stable_identity_candidate_for_unit(unit)
}

fn stable_identity_candidate_for_unit(unit: &CodeUnit) -> Option<CodeQueryStableOwnerCandidate> {
    if unit.is_synthetic() || unit.is_file_scope() || unit.is_anonymous() {
        return None;
    }
    let kind = unit.kind().display_lowercase();
    let mut semantic_key = format!("{kind}:{}", unit.fq_name());
    if let Some(signature) = unit.signature() {
        semantic_key.push_str(signature);
    }
    Some(CodeQueryStableOwnerCandidate {
        namespace: crate::analyzer::common::language_for_file(unit.source())
            .config_label()
            .to_string(),
        derivation: CodeQueryStableOwnerDerivation::AnalyzerDeclarationId,
        semantic_key,
    })
}

/// Hard cap on a stable semantic key, mirrored from the policy finding
/// identity validator. Keys over this limit are rejected there, which would
/// downgrade the finding to a weak anchor and mark the whole policy run
/// inconclusive, so the producer must stay within it.
const MAX_CANONICAL_AST_KEY_BYTES: usize = 256;

fn canonical_ast_candidate(seed: &SeedMatch) -> Option<CodeQueryStableOwnerCandidate> {
    let mut segments = Vec::new();
    let mut current = Some(seed.fact_match.node);
    while let Some(node_id) = current {
        let node = seed.facts.node(node_id);
        segments.push((
            node.kind.label(),
            node.name.map(|name| name.text(seed.facts.source())),
        ));
        current = node.parent;
    }
    segments.reverse();
    let semantic_key = bounded_canonical_ast_key(&segments)?;
    Some(CodeQueryStableOwnerCandidate {
        namespace: seed.language.config_label().to_string(),
        derivation: CodeQueryStableOwnerDerivation::CanonicalAstIdentity,
        semantic_key,
    })
}

/// Serialize an ancestor chain into a canonical AST key that fits the stable
/// identity limit. Deeply nested matches (closures in closures, generated
/// code) can exceed it, so the middle of the chain is deterministically
/// replaced by a digest segment while the outermost and innermost context is
/// kept verbatim; the digest covers the full chain, so distinct chains keep
/// distinct keys.
fn bounded_canonical_ast_key(segments: &[(&str, Option<&str>)]) -> Option<String> {
    let full = serde_json::to_string(segments).ok()?;
    if full.len() <= MAX_CANONICAL_AST_KEY_BYTES {
        return Some(full);
    }
    let digest: [u8; 32] = Sha256::digest(full.as_bytes()).into();
    let mut elided_name = String::with_capacity(33);
    elided_name.push('h');
    for byte in &digest[..16] {
        use std::fmt::Write as _;
        write!(elided_name, "{byte:02x}").ok()?;
    }
    for keep in (0..=3usize).rev() {
        if segments.len() < keep.saturating_mul(2) {
            continue;
        }
        let mut compact: Vec<(&str, Option<&str>)> = Vec::with_capacity(keep * 2 + 1);
        compact.extend_from_slice(&segments[..keep]);
        compact.push(("elided", Some(elided_name.as_str())));
        compact.extend_from_slice(&segments[segments.len() - keep..]);
        let key = serde_json::to_string(&compact).ok()?;
        if key.len() <= MAX_CANONICAL_AST_KEY_BYTES {
            return Some(key);
        }
    }
    None
}

#[derive(Default)]
struct QueryStepInstrumentation {
    rows_visited: usize,
    relation_expansions: usize,
    temporary_capacity_bytes_lower_bound: u64,
}
fn pipeline_expansion(value: PipelineValue) -> PipelineExpansion {
    let trace_value =
        pipeline_trace_value(&value).expect("every semantic query step produces a semantic value");
    PipelineExpansion {
        value,
        trace: vec![(trace_value, None)],
        budgeted: false,
    }
}

fn budgeted_declaration_expansion(declaration: DeclarationValue) -> PipelineExpansion {
    PipelineExpansion {
        value: PipelineValue::Declaration(declaration.clone()),
        trace: vec![(PipelineTraceValue::Declaration(declaration), None)],
        budgeted: true,
    }
}

fn pipeline_trace_value(value: &PipelineValue) -> Option<PipelineTraceValue> {
    match value {
        PipelineValue::StructuralMatch(_) => None,
        PipelineValue::Declaration(declaration) => {
            Some(PipelineTraceValue::Declaration(declaration.clone()))
        }
        PipelineValue::Semantic(value) => Some(PipelineTraceValue::Semantic(value.clone())),
        PipelineValue::File(file) => Some(PipelineTraceValue::File(file.clone())),
        PipelineValue::ReferenceSite(site) => Some(PipelineTraceValue::ReferenceSite(site.clone())),
        PipelineValue::CallSite(site) => Some(PipelineTraceValue::CallSite(site.clone())),
        PipelineValue::ExpressionSite(site) => {
            Some(PipelineTraceValue::ExpressionSite(site.clone()))
        }
        PipelineValue::ReceiverAnalysis(value) => {
            Some(PipelineTraceValue::ReceiverAnalysis(value.clone()))
        }
        PipelineValue::ReceiverOutcome(value) => {
            Some(PipelineTraceValue::ReceiverOutcome(value.clone()))
        }
        PipelineValue::ReceiverEvidence(value) => {
            Some(PipelineTraceValue::ReceiverEvidence(value.clone()))
        }
        PipelineValue::CallShape(value) => Some(PipelineTraceValue::CallShape(value.clone())),
        PipelineValue::CallArgumentGroup(value) => {
            Some(PipelineTraceValue::CallArgumentGroup(value.clone()))
        }
        PipelineValue::CallArgument(value) => Some(PipelineTraceValue::CallArgument(value.clone())),
        PipelineValue::Occurrence(value) => Some(PipelineTraceValue::Occurrence(value.clone())),
        PipelineValue::LexicalScope(value) => Some(PipelineTraceValue::LexicalScope(value.clone())),
        PipelineValue::Binding(value) => Some(PipelineTraceValue::Binding(value.clone())),
        PipelineValue::ResolutionCandidate(value) => {
            Some(PipelineTraceValue::ResolutionCandidate(value.clone()))
        }
        PipelineValue::GenerationSite(value) => {
            Some(PipelineTraceValue::GenerationSite(value.clone()))
        }
        PipelineValue::Export(value) => Some(PipelineTraceValue::Export(value.clone())),
        PipelineValue::DeclarationState(value) => {
            Some(PipelineTraceValue::DeclarationState(value.clone()))
        }
        PipelineValue::ReferenceEdge(value) => {
            Some(PipelineTraceValue::ReferenceEdge(value.clone()))
        }
        PipelineValue::QualifiedPath(value) => {
            Some(PipelineTraceValue::QualifiedPath(value.clone()))
        }
        PipelineValue::PathSegment(value) => Some(PipelineTraceValue::PathSegment(value.clone())),
    }
}
