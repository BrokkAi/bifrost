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
    QueryOperatorTermination, QueryOperatorWorkProfile,
};
use super::execution::scheduler::BoundedReadyScheduler;
use super::facts::{FileFacts, Span};
use super::index::{
    STRUCTURAL_INDEX_REPRESENTATION_VERSION, SnapshotStructuralIndex, StructuralCandidateSet,
    StructuralIndexAcquisition, StructuralIndexBuildMetrics, StructuralIndexLifecycle,
};
use super::kinds::{NormalizedKind, Role};
use super::matcher::FactMatch;
use super::planner::QueryPlan;
use super::provider::{StructuralFactsCacheOutcome, StructuralSearchProvider};
use super::query::schema::{reference_kind_label, usage_proof_label};
use super::query::{
    CallInputSelector, CallSiteTraversalFilter, CallTraversalFilter, CodeQuery,
    CodeQueryExecutionMode, CodeQueryResultDetail, CodeQuerySeed, HierarchyTraversal, QueryError,
    QueryStep, ReferenceTraversalFilter, SetOperator,
};
use crate::analyzer::reference_candidates::{
    ReferenceCandidateRanges, reference_candidate_ranges, reference_candidate_ranges_cancellable,
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

mod expansions;
mod results;
#[cfg(test)]
mod tests;

// `apply_pipeline_step` below (this engine's own per-step dispatch) reaches
// into `expansions` for its three graph-traversal entry points.
use expansions::{
    call_declaration_expansions, inbound_reference_expansions, scan_outbound_reference_hits,
};

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
pub use results::CodeQueryCallArgument;
pub use results::CodeQueryCallSite;
pub use results::CodeQueryCapture;
pub use results::CodeQueryCompletion;
pub use results::CodeQueryDeclaration;
pub use results::CodeQueryDiagnostic;
pub use results::CodeQueryDiagnosticCode;
pub use results::CodeQueryDiagnosticImpact;
pub use results::CodeQueryExecutionLimits;
pub use results::CodeQueryExecutionWork;
pub use results::CodeQueryExpressionSite;
pub use results::CodeQueryFile;
pub use results::CodeQueryMatch;
pub use results::CodeQueryProvenance;
pub use results::CodeQueryProvenanceStep;
pub use results::CodeQueryRange;
pub use results::CodeQueryReceiverAnalysis;
pub use results::CodeQueryReceiverValue;
pub use results::CodeQueryReferenceSite;
pub use results::CodeQueryResponse;
pub use results::CodeQueryResult;
pub use results::CodeQueryResultItem;
pub use results::CodeQueryResultRef;
pub use results::CodeQueryResultValue;
pub use results::CodeQuerySourceSite;
pub(crate) use results::CodeQueryStableOwnerCandidate;
pub(crate) use results::CodeQueryStableOwnerDerivation;
pub(crate) use results::DetailedCodeQueryDomain;
pub(crate) use results::DetailedCodeQueryEvidence;
pub(crate) use results::DetailedCodeQueryIdentityCandidate;
pub(crate) use results::DetailedCodeQueryKey;
pub(crate) use results::DetailedCodeQueryProvenanceEvidence;
pub(crate) use results::DetailedCodeQueryProvenanceIdentities;
pub(crate) use results::DetailedCodeQueryProvenanceRefEvidence;
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
const MAX_PROVENANCE_TRACES: usize = 16;
const BROAD_QUERY_SCANNED_FILE_HINT_THRESHOLD: usize = 100;
const CODE_QUERY_SCHEDULER_WORKERS: usize = 2;
const MIN_AUTO_STRUCTURAL_INDEX_FILES: usize = 8;
const BENCHMARK_ACCESS_MODE_ENV: &str = "BIFROST_QUERY_CODE_ACCESS_MODE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StructuralAccessMode {
    Auto,
    ScanOnly,
    IndexedRequired,
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
    File(ProjectFile),
    ReferenceSite(ReferenceSiteValue),
    CallSite(CallSiteValue),
    ExpressionSite(ExpressionSiteValue),
    ReceiverAnalysis(ReceiverAnalysisValue),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PipelineKey {
    StructuralMatch(ProjectFile, u32),
    Declaration(DeclarationValue),
    File(ProjectFile),
    ReferenceSite(ReferenceSiteValue),
    CallSite(CallSiteValue),
    ExpressionSite(ExpressionSiteValue),
    ReceiverAnalysis(ReceiverQueryOperation, ProjectFile, Range),
}

impl PipelineValue {
    fn key(&self) -> PipelineKey {
        match self {
            Self::StructuralMatch(seed) => {
                PipelineKey::StructuralMatch(seed.file.clone(), seed.fact_match.node)
            }
            Self::Declaration(declaration) => PipelineKey::Declaration(declaration.clone()),
            Self::File(file) => PipelineKey::File(file.clone()),
            Self::ReferenceSite(site) => PipelineKey::ReferenceSite(site.clone()),
            Self::CallSite(site) => PipelineKey::CallSite(site.clone()),
            Self::ExpressionSite(site) => PipelineKey::ExpressionSite(site.clone()),
            Self::ReceiverAnalysis(value) => PipelineKey::ReceiverAnalysis(
                value.report.operation,
                value.report.site.file.clone(),
                value.report.site.range,
            ),
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
    File(ProjectFile),
    ReferenceSite(ReferenceSiteValue),
    CallSite(CallSiteValue),
    ExpressionSite(ExpressionSiteValue),
    ReceiverAnalysis(ReceiverAnalysisValue),
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
    execute_request_internal(analyzer, None, query, limits, None)
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
    execute_request_internal(workspace.analyzer(), Some(workspace), query, limits, None)
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
    indexed_declarations: IndexedDeclarations,
    reference_cache: ReferenceTraversalCache,
    call_cache: CallTraversalCache,
    import_graph: Option<RequestLocalDirectImportGraph>,
    direct_import_layer: Option<Arc<DerivedLayer>>,
    direct_import_layer_generation: Option<u64>,
    cache_profile: Option<QueryCacheProfile>,
    profile: Option<QueryExecutionProfile>,
    observed_structural_indexes: Option<Arc<Mutex<HashSet<usize>>>>,
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
            Self::Snapshot(topology) => topology.importers_of(file).unwrap_or_default(),
        }
    }

    fn unsupported_languages(&self) -> Vec<Language> {
        match self {
            Self::RequestLocal(graph) => graph.unsupported_languages(),
            Self::Snapshot(_) => Vec::new(),
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
    execute_code_query_detailed(analyzer, query, limits, None).result
}

#[doc(hidden)]
pub fn execute_workspace_with_limits(
    workspace: &WorkspaceAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> CodeQueryResult {
    execute_internal(
        workspace.analyzer(),
        Some(workspace),
        query,
        limits,
        None,
        None,
        false,
    )
    .result
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
    execute_request_internal(analyzer, None, query, limits, Some(cancellation))
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
    )
}

fn execute_request_internal(
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
) -> CodeQueryResponse {
    match query.execution_mode {
        CodeQueryExecutionMode::Results => CodeQueryResponse::Results(
            execute_internal(
                analyzer,
                workspace,
                query,
                limits,
                cancellation,
                None,
                false,
            )
            .result,
        ),
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
            let detailed =
                execute_internal(analyzer, workspace, query, limits, cancellation, None, true);
            let DetailedCodeQueryResult {
                result, profile, ..
            } = detailed;
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

pub(crate) fn execute_code_query_detailed(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
) -> DetailedCodeQueryResult {
    execute_internal(analyzer, None, query, limits, cancellation, None, false)
}

/// Internal opt-in profile entry point used by the M2 measurement harness.
/// Public query surfaces remain unchanged until the explicit M5 rollout.
#[cfg(test)]
pub(crate) fn execute_code_query_profiled(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> DetailedCodeQueryResult {
    execute_internal(analyzer, None, query, limits, None, None, true)
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
    execute_internal_with_strategy(
        analyzer,
        None,
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
    let detailed = execute_internal_with_strategy(
        analyzer,
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
    execute_internal(
        analyzer,
        None,
        query,
        CodeQueryExecutionLimits::default(),
        None,
        Some(receiver_budget),
        false,
    )
    .result
}

fn execute_internal(
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    capture_profile: bool,
) -> DetailedCodeQueryResult {
    execute_internal_with_strategy(
        analyzer,
        workspace,
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
    let planning_ns = planning_started.map(elapsed_ns).unwrap_or(0);
    let mut diagnostics = Vec::new();
    let mut state = QueryExecutionState {
        analyzer,
        workspace,
        cancellation,
        receiver_budget_override,
        budget: CodeQueryExecutionBudget::default(),
        seed_cache: HashMap::default(),
        indexed_declarations: IndexedDeclarations::default(),
        reference_cache: ReferenceTraversalCache::default(),
        call_cache: CallTraversalCache::default(),
        import_graph: None,
        direct_import_layer: None,
        direct_import_layer_generation: None,
        cache_profile: capture_profile.then(QueryCacheProfile::default),
        profile: capture_profile
            .then(|| QueryExecutionProfile::new(&physical_plan, planning_ns, scheduler_workers)),
        observed_structural_indexes: capture_profile
            .then(|| Arc::new(Mutex::new(HashSet::default()))),
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
    if let (Some(profile), Some(started)) = (&mut state.profile, execution_started) {
        profile.execution_ns = elapsed_ns(started);
    }
    let execution_work_profile = capture_profile.then(|| execution_work_snapshot(state.budget));
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
    let total_work = execution_work_snapshot(state.budget);
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
        work: public_execution_work(execution_work_snapshot(budget)),
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
    }
}

fn execution_work_snapshot(budget: CodeQueryExecutionBudget) -> QueryOperatorWorkProfile {
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
    }
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
        PipelineValue::ReferenceSite(site) => Some(&site.file),
        PipelineValue::CallSite(site) => Some(&site.0.file),
        PipelineValue::ExpressionSite(site) => Some(&site.call_site.0.file),
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
        PipelineValue::File(_) => {}
        PipelineValue::ReferenceSite(site) => collect_reference_source_files(site, files),
        PipelineValue::CallSite(site) => collect_call_source_files(site, files),
        PipelineValue::ExpressionSite(site) => collect_call_source_files(&site.call_site, files),
        PipelineValue::ReceiverAnalysis(value) => collect_receiver_source_files(value, files),
    }
}

fn collect_trace_value_source_files(value: &PipelineTraceValue, files: &mut BTreeSet<ProjectFile>) {
    match value {
        PipelineTraceValue::Declaration(declaration) => {
            files.insert(declaration.unit.source().clone());
        }
        PipelineTraceValue::File(_) => {}
        PipelineTraceValue::ReferenceSite(site) => collect_reference_source_files(site, files),
        PipelineTraceValue::CallSite(site) => collect_call_source_files(site, files),
        PipelineTraceValue::ExpressionSite(site) => {
            collect_call_source_files(&site.call_site, files);
        }
        PipelineTraceValue::ReceiverAnalysis(value) => collect_receiver_source_files(value, files),
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
    let semantic_key = serde_json::to_string(&segments).ok()?;
    Some(CodeQueryStableOwnerCandidate {
        namespace: seed.language.config_label().to_string(),
        derivation: CodeQueryStableOwnerDerivation::CanonicalAstIdentity,
        semantic_key,
    })
}

fn execute_plan(
    plan: &PhysicalQueryPlan,
    node_id: PhysicalQueryNodeId,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    terminal_cap: Option<usize>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    profile_branch: &mut Option<Vec<usize>>,
) -> PlanExecution {
    let profiling = state.profile.is_some();
    let invocation_started = profiling.then(Instant::now);
    let physical_node = plan.node(node_id);
    let physical_operator = physical_node.operator();
    let logical_operator = plan.logical_node(node_id).operator();
    let mut input_rows = 0;
    let mut rows_visited = 0;
    let mut relation_expansions = 0;
    let mut rows_discarded = None;
    let mut temporary_capacity_bytes_lower_bound = 0;
    let mut disposition = QueryOperatorDisposition::Completed;
    let mut self_truncated = false;
    let mut dependency_execution_ns = 0u64;
    let mut dependency_wait_ns = 0u64;
    let mut merge_ns = 0u64;
    let mut scheduling_overhead_ns = 0u64;
    let mut terminations = profiling.then(Vec::new);
    let mut work_started = profiling.then(|| execution_work_snapshot(state.budget));
    let mut cache_started = state.cache_profile;
    let mut own_diagnostic_start = diagnostics.len();

    let execution = match (physical_operator, logical_operator) {
        (PhysicalQueryOperator::SeedScan, LogicalQueryOperator::Seed(seed)) => {
            if state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
            {
                disposition = QueryOperatorDisposition::Skipped;
                push_operator_termination(
                    &mut terminations,
                    QueryOperatorTermination::CancellationBeforeWork,
                );
                cancelled_plan_execution()
            } else {
                let execution = execute_seed(seed, terminal_cap, state, limits, diagnostics);
                if terminal_cap.is_some_and(|cap| execution.rows.len() >= cap) {
                    push_operator_termination(
                        &mut terminations,
                        QueryOperatorTermination::TerminalCap,
                    );
                }
                self_truncated = execution.truncated;
                if execution.cancelled {
                    disposition = QueryOperatorDisposition::Cancelled;
                }
                execution
            }
        }
        (
            PhysicalQueryOperator::PipelineStep,
            LogicalQueryOperator::Step {
                step,
                final_in_authored_suffix,
                ..
            },
        ) => {
            let dependency = physical_node.dependencies()[0];
            let dependency_started = profiling.then(Instant::now);
            let child = execute_plan(
                plan,
                dependency,
                state,
                limits,
                None,
                diagnostics,
                profile_branch,
            );
            if let Some(started) = dependency_started {
                dependency_execution_ns =
                    dependency_execution_ns.saturating_add(elapsed_ns(started));
            }
            input_rows = child.rows.len();
            work_started = profiling.then(|| execution_work_snapshot(state.budget));
            cache_started = state.cache_profile;
            own_diagnostic_start = diagnostics.len();
            if child.cancelled {
                disposition = QueryOperatorDisposition::Skipped;
                push_operator_termination(
                    &mut terminations,
                    QueryOperatorTermination::DependencyCancelled,
                );
                child
            } else if child.pipeline_halted {
                disposition = QueryOperatorDisposition::Skipped;
                push_operator_termination(
                    &mut terminations,
                    QueryOperatorTermination::DependencyPipelineHalted,
                );
                PlanExecution {
                    pipeline_halted: !final_in_authored_suffix,
                    ..child
                }
            } else {
                let mut instrumentation = profiling.then(QueryStepInstrumentation::default);
                let mut stepped = apply_plan_step(
                    step,
                    physical_node.derived_layer_request(),
                    *final_in_authored_suffix,
                    child.rows,
                    state,
                    limits,
                    terminal_cap,
                    diagnostics,
                    instrumentation.as_mut(),
                );
                if let Some(instrumentation) = instrumentation {
                    rows_visited = instrumentation.rows_visited;
                    relation_expansions = instrumentation.relation_expansions;
                    temporary_capacity_bytes_lower_bound =
                        instrumentation.temporary_capacity_bytes_lower_bound;
                }
                if terminal_cap.is_some_and(|cap| stepped.rows.len() >= cap) {
                    push_operator_termination(
                        &mut terminations,
                        QueryOperatorTermination::TerminalCap,
                    );
                }
                self_truncated = stepped.truncated;
                if stepped.cancelled {
                    disposition = QueryOperatorDisposition::Cancelled;
                }
                stepped.truncated |= child.truncated;
                stepped
            }
        }
        (
            PhysicalQueryOperator::ParallelUnion,
            LogicalQueryOperator::Set {
                op: SetOperator::Union,
                ..
            },
        ) => {
            let parallel = execute_parallel_seed_union(
                plan,
                physical_node.dependencies(),
                state,
                limits,
                terminal_cap,
                diagnostics,
                profile_branch,
                profiling,
            );
            input_rows = parallel.input_rows;
            rows_visited = parallel.rows_visited;
            rows_discarded = parallel.rows_discarded;
            temporary_capacity_bytes_lower_bound = parallel.temporary_capacity_bytes_lower_bound;
            self_truncated = parallel.operator_truncated;
            dependency_wait_ns = parallel.dependency_wait_ns;
            scheduling_overhead_ns = parallel.scheduling_overhead_ns;
            merge_ns = parallel.merge_ns;
            if self_truncated {
                push_operator_termination(&mut terminations, QueryOperatorTermination::TerminalCap);
            }
            work_started = profiling.then(|| execution_work_snapshot(state.budget));
            cache_started = state.cache_profile;
            own_diagnostic_start = diagnostics.len();
            if parallel.execution.cancelled {
                disposition = QueryOperatorDisposition::Skipped;
                push_operator_termination(
                    &mut terminations,
                    QueryOperatorTermination::DependencyCancelled,
                );
            }
            parallel.execution
        }
        (
            PhysicalQueryOperator::SequentialUnion
            | PhysicalQueryOperator::SequentialIntersection
            | PhysicalQueryOperator::SequentialExcept,
            LogicalQueryOperator::Set { op, .. },
        ) => {
            if state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
            {
                disposition = QueryOperatorDisposition::Skipped;
                push_operator_termination(
                    &mut terminations,
                    QueryOperatorTermination::CancellationBeforeWork,
                );
                cancelled_plan_execution()
            } else {
                debug_assert_eq!(
                    physical_operator,
                    match op {
                        SetOperator::Union => PhysicalQueryOperator::SequentialUnion,
                        SetOperator::Intersect => PhysicalQueryOperator::SequentialIntersection,
                        SetOperator::Except => PhysicalQueryOperator::SequentialExcept,
                    }
                );
                let dependencies = physical_node.dependencies();
                let mut branch_rows = Vec::with_capacity(dependencies.len());
                let mut cancelled_child = None;
                let mut truncated = false;
                for (index, dependency) in dependencies.iter().copied().enumerate() {
                    let branch_limits = fair_branch_limits(
                        &state.budget,
                        limits,
                        dependencies.len().saturating_sub(index),
                    );
                    let diagnostic_start = diagnostics.len();
                    if let Some(branch) = profile_branch.as_mut() {
                        branch.push(index);
                    }
                    let dependency_started = profiling.then(Instant::now);
                    let mut child = execute_plan(
                        plan,
                        dependency,
                        state,
                        branch_limits,
                        None,
                        diagnostics,
                        profile_branch,
                    );
                    if let Some(started) = dependency_started {
                        dependency_execution_ns =
                            dependency_execution_ns.saturating_add(elapsed_ns(started));
                    }
                    if let Some(branch) = profile_branch.as_mut() {
                        let popped = branch.pop();
                        debug_assert_eq!(popped, Some(index));
                    }
                    input_rows = input_rows.saturating_add(child.rows.len());
                    let prefix_started = profiling.then(Instant::now);
                    prefix_branch_rows(&mut child.rows, index);
                    prefix_branch_diagnostics(&mut diagnostics[diagnostic_start..], index);
                    if let Some(started) = prefix_started {
                        merge_ns = merge_ns.saturating_add(elapsed_ns(started));
                    }
                    work_started = profiling.then(|| execution_work_snapshot(state.budget));
                    cache_started = state.cache_profile;
                    own_diagnostic_start = diagnostics.len();
                    truncated |= child.truncated;
                    if child.cancelled {
                        push_operator_termination(
                            &mut terminations,
                            QueryOperatorTermination::DependencyCancelled,
                        );
                        cancelled_child = Some(child);
                        break;
                    }
                    branch_rows.push(child.rows);
                }
                rows_visited = input_rows;
                if let Some(child) = cancelled_child {
                    disposition = QueryOperatorDisposition::Skipped;
                    child
                } else {
                    let merge_started = profiling.then(Instant::now);
                    let (mut rows, merge_measurement) =
                        combine_set_rows(*op, branch_rows, profiling);
                    if let Some(started) = merge_started {
                        merge_ns = merge_ns.saturating_add(elapsed_ns(started));
                    }
                    if let Some(merge_measurement) = merge_measurement {
                        rows_discarded = Some(merge_measurement.rows_discarded);
                        temporary_capacity_bytes_lower_bound =
                            merge_measurement.temporary_capacity_bytes_lower_bound;
                    }
                    if let Some(cap) = terminal_cap
                        && rows.len() > cap
                    {
                        self_truncated = true;
                        rows_discarded = Some(
                            rows_discarded
                                .unwrap_or_default()
                                .saturating_add(rows.len() - cap),
                        );
                        push_operator_termination(
                            &mut terminations,
                            QueryOperatorTermination::TerminalCap,
                        );
                        rows.truncate(cap);
                    }
                    PlanExecution {
                        rows,
                        truncated,
                        cancelled: false,
                        pipeline_halted: false,
                    }
                }
            }
        }
        (PhysicalQueryOperator::Limit, LogicalQueryOperator::Limit { count, .. }) => {
            let dependency = physical_node.dependencies()[0];
            let dependency_started = profiling.then(Instant::now);
            let mut child = execute_plan(
                plan,
                dependency,
                state,
                limits,
                Some(count.saturating_add(1)),
                diagnostics,
                profile_branch,
            );
            if let Some(started) = dependency_started {
                dependency_execution_ns =
                    dependency_execution_ns.saturating_add(elapsed_ns(started));
            }
            input_rows = child.rows.len();
            rows_visited = input_rows;
            rows_discarded = Some(0);
            work_started = profiling.then(|| execution_work_snapshot(state.budget));
            cache_started = state.cache_profile;
            own_diagnostic_start = diagnostics.len();
            let dependency_cancelled = child.cancelled;
            let token_cancelled = state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled);
            if dependency_cancelled || token_cancelled {
                push_operator_termination(
                    &mut terminations,
                    if dependency_cancelled {
                        QueryOperatorTermination::DependencyCancelled
                    } else {
                        QueryOperatorTermination::CancellationDuringWork
                    },
                );
                if dependency_cancelled {
                    disposition = QueryOperatorDisposition::Skipped;
                } else if token_cancelled {
                    disposition = QueryOperatorDisposition::Cancelled;
                }
                child.cancelled = true;
                child.truncated = true;
                push_cancelled_diagnostic(diagnostics);
            }
            if child.rows.len() > *count {
                self_truncated = true;
                rows_discarded = Some(child.rows.len() - *count);
                push_operator_termination(&mut terminations, QueryOperatorTermination::ResultLimit);
                push_truncation_diagnostic(diagnostics, &state.budget, *count);
                child.rows.truncate(*count);
                child.truncated = true;
            }
            child
        }
        _ => unreachable!("physical operator must implement its logical query node"),
    };

    if profiling {
        append_diagnostic_terminations(
            &mut terminations,
            &diagnostics[own_diagnostic_start.min(diagnostics.len())..],
        );
        if self_truncated
            && terminations
                .as_ref()
                .is_some_and(|terminations| terminations.is_empty())
        {
            push_operator_termination(
                &mut terminations,
                QueryOperatorTermination::AnalysisIncomplete,
            );
        }
        if execution.cancelled && disposition == QueryOperatorDisposition::Cancelled {
            push_operator_termination(
                &mut terminations,
                QueryOperatorTermination::CancellationDuringWork,
            );
        }
    }

    if let (Some(profile), Some(started)) = (&mut state.profile, invocation_started) {
        let total_elapsed_ns = elapsed_ns(started);
        let work =
            execution_work_snapshot(state.budget).saturating_sub(work_started.unwrap_or_default());
        let cache = state
            .cache_profile
            .unwrap_or_default()
            .saturating_sub(cache_started.unwrap_or_default());
        profile.record(QueryOperatorProfile {
            node: node_id,
            branch: profile_branch.as_deref().unwrap_or_default().to_vec(),
            operator: physical_operator,
            disposition,
            elapsed_ns: total_elapsed_ns
                .saturating_sub(dependency_execution_ns)
                .saturating_sub(dependency_wait_ns),
            total_elapsed_ns,
            dependency_execution_ns,
            dependency_wait_ns,
            merge_ns,
            scheduling_overhead_ns,
            input_rows,
            rows_visited,
            relation_expansions,
            rows_discarded,
            temporary_capacity_bytes_lower_bound,
            work,
            cache,
            terminations: terminations.unwrap_or_default(),
            output_rows: execution.rows.len(),
            operator_truncated: self_truncated,
            result_truncated: execution.truncated,
            result_cancelled: execution.cancelled,
        });
    }
    execution
}

#[allow(clippy::too_many_arguments)]
fn execute_parallel_seed_union(
    plan: &PhysicalQueryPlan,
    dependencies: &[PhysicalQueryNodeId],
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    terminal_cap: Option<usize>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    profile_branch: &Option<Vec<usize>>,
    profiling: bool,
) -> ParallelUnionExecution {
    debug_assert_eq!(dependencies.len(), 2);
    debug_assert!(dependencies.iter().all(|dependency| matches!(
        plan.node(*dependency).operator(),
        PhysicalQueryOperator::SeedScan
    )));
    debug_assert_ne!(dependencies[0], dependencies[1]);

    let coordinator = FairSeedBudgetCoordinator::new(
        state.budget,
        limits,
        dependencies.len(),
        state.cancellation,
    );
    let analyzer = state.analyzer;
    let cancellation = state.cancellation;
    let receiver_budget_override = state.receiver_budget_override;
    let access_mode = state.access_mode;
    let observed_structural_indexes = state.observed_structural_indexes.clone();
    let scheduler_workers = state.scheduler_workers;
    let base_budget = state.budget;
    let base_profile_branch = profile_branch.as_deref().unwrap_or_default().to_vec();
    let scheduled = BoundedReadyScheduler::new(scheduler_workers).run(
        dependencies.len(),
        cancellation,
        |branch| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let lease = coordinator.lease(branch);
                let mut branch_state = QueryExecutionState {
                    analyzer,
                    // Parallel union dependencies are seed scans only; receiver
                    // steps execute later against the parent workspace state.
                    workspace: None,
                    cancellation,
                    receiver_budget_override,
                    budget: base_budget,
                    seed_cache: HashMap::default(),
                    indexed_declarations: IndexedDeclarations::default(),
                    reference_cache: ReferenceTraversalCache::default(),
                    call_cache: CallTraversalCache::default(),
                    import_graph: None,
                    direct_import_layer: None,
                    direct_import_layer_generation: None,
                    cache_profile: profiling.then(QueryCacheProfile::default),
                    profile: profiling
                        .then(|| QueryExecutionProfile::new(plan, 0, scheduler_workers)),
                    observed_structural_indexes: observed_structural_indexes.clone(),
                    access_mode,
                    access_failure: None,
                    parallel_seed_budget: Some(lease.clone()),
                    scheduler_workers,
                };
                let mut branch_diagnostics = Vec::new();
                let mut branch_path = profiling.then(|| {
                    let mut path = base_profile_branch.clone();
                    path.push(branch);
                    path
                });
                let execution = execute_plan(
                    plan,
                    dependencies[branch],
                    &mut branch_state,
                    limits,
                    None,
                    &mut branch_diagnostics,
                    &mut branch_path,
                );
                lease.finish(branch_state.budget);
                debug_assert!(branch_state.import_graph.is_none());
                debug_assert!(branch_state.direct_import_layer.is_none());
                debug_assert!(branch_state.direct_import_layer_generation.is_none());
                debug_assert!(branch_state.reference_cache.inbound.is_empty());
                debug_assert!(branch_state.reference_cache.outbound.is_empty());
                debug_assert!(branch_state.call_cache.incoming.is_empty());
                debug_assert!(branch_state.call_cache.outgoing.is_empty());
                let (operators, access_path) = branch_state.profile.take().map_or_else(
                    || (Vec::new(), QueryAccessPathProfile::default()),
                    |profile| (profile.operators, profile.access_path),
                );
                ParallelSeedBranchResult {
                    execution,
                    diagnostics: branch_diagnostics,
                    seed_cache: branch_state.seed_cache,
                    cache_profile: branch_state.cache_profile,
                    operators,
                    access_path,
                    access_failure: branch_state.access_failure,
                }
            }));
            match result {
                Ok(result) => result,
                Err(payload) => {
                    coordinator.fail();
                    std::panic::resume_unwind(payload)
                }
            }
        },
    );

    let mut scheduler_profile = scheduled.profile;
    scheduler_profile.budget_wait_ns = coordinator.wait_ns();
    let dependency_wait_ns = scheduler_profile.coordinator_wait_ns;
    let scheduling_overhead_ns = scheduler_profile.dispatch_overhead_ns;
    if let Some(profile) = &mut state.profile {
        profile.record_scheduler_run(scheduler_profile);
    }

    let mut input_rows = 0usize;
    let mut branch_rows = Vec::with_capacity(dependencies.len());
    let mut truncated = false;
    let mut cancelled_child = None;
    let prefix_started = profiling.then(Instant::now);
    for (branch, mut result) in scheduled.results.into_iter().enumerate() {
        input_rows = input_rows.saturating_add(result.execution.rows.len());
        let contributes_to_public_prefix = cancelled_child.is_none();
        if contributes_to_public_prefix {
            prefix_branch_rows(&mut result.execution.rows, branch);
            prefix_branch_diagnostics(&mut result.diagnostics, branch);
            diagnostics.append(&mut result.diagnostics);
            truncated |= result.execution.truncated;
        }

        for (key, cached) in result.seed_cache {
            assert!(
                state.seed_cache.insert(key, cached).is_none(),
                "parallel union eligibility requires distinct seed cache keys"
            );
        }
        if let (Some(parent), Some(branch_cache)) = (&mut state.cache_profile, result.cache_profile)
        {
            *parent = parent.saturating_add(branch_cache);
        }
        if let Some(profile) = &mut state.profile {
            profile.operators.extend(result.operators);
            profile.access_path =
                std::mem::take(&mut profile.access_path).saturating_add(result.access_path);
        }
        if state.access_failure.is_none() {
            state.access_failure = result.access_failure;
        }
        if contributes_to_public_prefix {
            if result.execution.cancelled {
                cancelled_child = Some(result.execution);
            } else {
                branch_rows.push(result.execution.rows);
            }
        }
    }
    state.budget = coordinator.committed_budget();
    let mut merge_ns = prefix_started.map(elapsed_ns).unwrap_or(0);

    if let Some(child) = cancelled_child {
        return ParallelUnionExecution {
            execution: child,
            input_rows,
            rows_visited: input_rows,
            rows_discarded: None,
            temporary_capacity_bytes_lower_bound: 0,
            operator_truncated: false,
            dependency_wait_ns,
            scheduling_overhead_ns,
            merge_ns,
        };
    }

    let merge_started = profiling.then(Instant::now);
    let (mut rows, merge_measurement) =
        combine_set_rows(SetOperator::Union, branch_rows, profiling);
    if let Some(started) = merge_started {
        merge_ns = merge_ns.saturating_add(elapsed_ns(started));
    }
    let mut rows_discarded = merge_measurement
        .as_ref()
        .map(|measurement| measurement.rows_discarded);
    let temporary_capacity_bytes_lower_bound = merge_measurement
        .map(|measurement| measurement.temporary_capacity_bytes_lower_bound)
        .unwrap_or_default();
    let mut operator_truncated = false;
    if let Some(cap) = terminal_cap
        && rows.len() > cap
    {
        operator_truncated = true;
        rows_discarded = Some(
            rows_discarded
                .unwrap_or_default()
                .saturating_add(rows.len() - cap),
        );
        rows.truncate(cap);
    }
    ParallelUnionExecution {
        execution: PlanExecution {
            rows,
            truncated,
            cancelled: false,
            pipeline_halted: false,
        },
        input_rows,
        rows_visited: input_rows,
        rows_discarded,
        temporary_capacity_bytes_lower_bound,
        operator_truncated,
        dependency_wait_ns,
        scheduling_overhead_ns,
        merge_ns,
    }
}

fn push_operator_termination(
    terminations: &mut Option<Vec<QueryOperatorTermination>>,
    termination: QueryOperatorTermination,
) {
    if let Some(terminations) = terminations
        && !terminations.contains(&termination)
    {
        terminations.push(termination);
    }
}

fn append_diagnostic_terminations(
    terminations: &mut Option<Vec<QueryOperatorTermination>>,
    diagnostics: &[CodeQueryDiagnostic],
) {
    for diagnostic in diagnostics {
        let termination = match diagnostic.code {
            // Cancellation ownership is classified from the executor state
            // below. A diagnostic can be emitted or replayed by a parent that
            // only observed a cancelled dependency, so prose provenance is
            // not sufficient to call it operator-local work.
            CodeQueryDiagnosticCode::Cancelled => None,
            CodeQueryDiagnosticCode::ExecutionBudgetExhausted => {
                Some(QueryOperatorTermination::ExecutionBudget)
            }
            CodeQueryDiagnosticCode::PipelineBudgetExhausted => {
                Some(QueryOperatorTermination::PipelineBudget)
            }
            CodeQueryDiagnosticCode::ImportGraphBudgetExhausted => {
                Some(QueryOperatorTermination::ImportGraphBudget)
            }
            CodeQueryDiagnosticCode::ResultLimitReached => {
                Some(QueryOperatorTermination::ResultLimit)
            }
            CodeQueryDiagnosticCode::CallRelationBudgetExhausted
            | CodeQueryDiagnosticCode::CallRelationCandidateLimit
            | CodeQueryDiagnosticCode::ReferenceSourceBytesTruncated
            | CodeQueryDiagnosticCode::ReferenceCandidateFilesTruncated
            | CodeQueryDiagnosticCode::ReferenceCandidatesOmitted
            | CodeQueryDiagnosticCode::ReferenceCallsiteLimit
            | CodeQueryDiagnosticCode::UsesCandidateLimit
            | CodeQueryDiagnosticCode::UsesCandidatesOmitted => {
                Some(QueryOperatorTermination::AnalysisLimit)
            }
            CodeQueryDiagnosticCode::UnsupportedStructuralFeature
            | CodeQueryDiagnosticCode::MissingStructuralAdapter
            | CodeQueryDiagnosticCode::UnsupportedImportAnalysis
            | CodeQueryDiagnosticCode::UsesParserUnsupported => {
                Some(QueryOperatorTermination::UnsupportedAnalysis)
            }
            CodeQueryDiagnosticCode::SemanticResultsOmitted
            | CodeQueryDiagnosticCode::ReceiverAnalysisPartial
            | CodeQueryDiagnosticCode::ReceiverAnalysisFailed
            | CodeQueryDiagnosticCode::CallRelationParseFailed
            | CodeQueryDiagnosticCode::CallRelationCandidatesOmitted
            | CodeQueryDiagnosticCode::CallRelationAnalysisFailed
            | CodeQueryDiagnosticCode::ReferenceAnalysisFailed => {
                Some(QueryOperatorTermination::AnalysisIncomplete)
            }
            CodeQueryDiagnosticCode::InvalidPlan
            | CodeQueryDiagnosticCode::CallRelationTargetsAmbiguous
            | CodeQueryDiagnosticCode::ReferenceTargetsAmbiguous
            | CodeQueryDiagnosticCode::UsesTargetsAmbiguous
            | CodeQueryDiagnosticCode::BroadQuery => None,
        };
        if let Some(termination) = termination {
            push_operator_termination(terminations, termination);
        }
    }
}

fn cancelled_plan_execution() -> PlanExecution {
    PlanExecution {
        rows: Vec::new(),
        truncated: true,
        cancelled: true,
        pipeline_halted: false,
    }
}

#[derive(Clone)]
enum SeedStructuralAccess {
    Scan,
    Indexed {
        index: Arc<SnapshotStructuralIndex>,
        candidates: Arc<StructuralCandidateSet>,
    },
}

impl SeedStructuralAccess {
    fn index_file(&self, file: &ProjectFile) -> Option<&super::index::StructuralIndexFile> {
        match self {
            Self::Scan => None,
            Self::Indexed { index, .. } => index.file(file),
        }
    }

    fn candidate_facts(&self, file: &ProjectFile) -> Option<&[u32]> {
        match self {
            Self::Scan => None,
            Self::Indexed { candidates, .. } => Some(candidates.facts_for(file)),
        }
    }

    fn source_may_contain(&self, file: &ProjectFile, required_anchors: &[String]) -> Option<bool> {
        match self {
            Self::Scan => None,
            Self::Indexed { index, .. } => index.source_may_contain(file, required_anchors),
        }
    }
}

fn record_index_build_facts(
    profile: Option<&mut QueryCacheProfile>,
    build: StructuralIndexBuildMetrics,
) {
    let Some(profile) = profile else {
        return;
    };
    let facts = &mut profile.seed_structural_facts;
    facts.lookups = facts
        .lookups
        .saturating_add(build.memory_hits)
        .saturating_add(build.persisted_hydrations)
        .saturating_add(build.extractions)
        .saturating_add(build.unavailable)
        .saturating_add(build.unknown_outcomes);
    facts.memory_hits = facts.memory_hits.saturating_add(build.memory_hits);
    facts.persisted_hydrations = facts
        .persisted_hydrations
        .saturating_add(build.persisted_hydrations);
    facts.extractions = facts.extractions.saturating_add(build.extractions);
    facts.unavailable = facts.unavailable.saturating_add(build.unavailable);
    facts.unknown_outcomes = facts
        .unknown_outcomes
        .saturating_add(build.unknown_outcomes);
    facts.replayed_files = facts.replayed_files.saturating_add(build.memory_hits);
}

fn record_index_build_access(
    profile: Option<&mut QueryExecutionProfile>,
    build: StructuralIndexBuildMetrics,
) {
    let Some(profile) = profile else {
        return;
    };
    let access = &mut profile.access_path;
    access.index_build_files = access.index_build_files.saturating_add(build.files);
    access.index_build_source_bytes = access
        .index_build_source_bytes
        .saturating_add(build.source_bytes);
    access.index_build_fact_nodes = access
        .index_build_fact_nodes
        .saturating_add(build.fact_nodes);
    access.index_build_facts_bytes = access
        .index_build_facts_bytes
        .saturating_add(build.facts_bytes);
    access.index_build_ns = access.index_build_ns.saturating_add(build.elapsed_ns);
}

fn load_seed_facts(
    provider: &dyn StructuralSearchProvider,
    file: &ProjectFile,
    cache_profile: Option<&mut QueryCacheProfile>,
) -> Option<Arc<FileFacts>> {
    let Some(profile) = cache_profile else {
        return provider.structural_facts(file);
    };
    let (facts, outcome) = provider.structural_facts_with_outcome(file);
    match outcome {
        StructuralFactsCacheOutcome::MemoryHit => profile
            .seed_structural_facts
            .record_memory_hit(facts.is_some()),
        StructuralFactsCacheOutcome::PersistedHydration => {
            profile.seed_structural_facts.record_persisted_hydration()
        }
        StructuralFactsCacheOutcome::Extracted => {
            profile.seed_structural_facts.record_extraction();
        }
        StructuralFactsCacheOutcome::Unavailable => {
            profile.seed_structural_facts.record_unavailable();
        }
        StructuralFactsCacheOutcome::Unknown => {
            profile.seed_structural_facts.record_unknown();
        }
    }
    facts
}

fn scan_access(
    state: &mut QueryExecutionState<'_>,
    scoped_files: usize,
    fallback_reason: Option<&str>,
) -> SeedStructuralAccess {
    if let Some(profile) = &mut state.profile {
        profile
            .access_path
            .record_selected(super::planner::StructuralAccessPathKind::ScanOnly.label());
        profile.access_path.scoped_files = profile
            .access_path
            .scoped_files
            .saturating_add(u64::try_from(scoped_files).unwrap_or(u64::MAX));
        if fallback_reason.is_some() {
            profile.access_path.scan_fallbacks =
                profile.access_path.scan_fallbacks.saturating_add(1);
        }
    }
    if state.access_mode == StructuralAccessMode::IndexedRequired && state.access_failure.is_none()
    {
        state.access_failure = fallback_reason
            .map(str::to_string)
            .or_else(|| Some("query has no sound structural posting requirements".to_string()));
    }
    SeedStructuralAccess::Scan
}

fn prepare_seed_access(
    provider: &dyn StructuralSearchProvider,
    provider_file_count: usize,
    files: &[ProjectFile],
    plan: &QueryPlan,
    state: &mut QueryExecutionState<'_>,
) -> SeedStructuralAccess {
    if state.access_mode == StructuralAccessMode::ScanOnly {
        return scan_access(state, files.len(), None);
    }
    if plan.structural_access().terms().is_empty() {
        return scan_access(state, files.len(), None);
    }
    let Some(cache) = provider.snapshot_structural_index_cache() else {
        return scan_access(
            state,
            files.len(),
            Some("structural provider has no snapshot index cache"),
        );
    };

    let uncancelled = CancellationToken::default();
    let cancellation = state.cancellation.unwrap_or(&uncancelled);
    let source_generation = provider.structural_source_generation();
    let ready_index = cache.get_ready(source_generation, cancellation);
    let cache_ready_before_lookup = ready_index.is_some();
    let auto_build_is_viable = files.len() >= MIN_AUTO_STRUCTURAL_INDEX_FILES
        && files.len().saturating_mul(4) >= provider_file_count;
    if state.access_mode == StructuralAccessMode::Auto
        && ready_index.is_none()
        && (!auto_build_is_viable || !cache.observe_auto_reuse_opportunity(source_generation))
    {
        return scan_access(state, files.len(), None);
    }
    let acquisition = ready_index.map_or_else(
        || cache.acquire(provider, cancellation),
        |index| StructuralIndexAcquisition::Ready {
            index,
            lifecycle: StructuralIndexLifecycle::Hit,
            wait: Default::default(),
            build: StructuralIndexBuildMetrics::default(),
        },
    );
    if let Some(profile) = &mut state.profile {
        let access = &mut profile.access_path;
        access.representation_version = STRUCTURAL_INDEX_REPRESENTATION_VERSION;
        access.index_lookups = access.index_lookups.saturating_add(1);
        let wait = match &acquisition {
            StructuralIndexAcquisition::Ready { wait, .. }
            | StructuralIndexAcquisition::Unavailable { wait, .. }
            | StructuralIndexAcquisition::Cancelled { wait, .. } => *wait,
        };
        access.index_waits = access.index_waits.saturating_add(wait.waits);
        access.index_wait_ns = access.index_wait_ns.saturating_add(wait.wait_ns);
    }

    match acquisition {
        StructuralIndexAcquisition::Ready {
            index,
            lifecycle,
            build,
            ..
        } => {
            if index.source_generation() != provider.structural_source_generation() {
                return scan_access(
                    state,
                    files.len(),
                    Some("structural source generation changed before index selection"),
                );
            }
            record_index_build_facts(state.cache_profile.as_mut(), build);
            record_index_build_access(state.profile.as_mut(), build);
            if let Some(profile) = &mut state.profile {
                let access = &mut profile.access_path;
                match lifecycle {
                    StructuralIndexLifecycle::Hit => {
                        access.index_hits = access.index_hits.saturating_add(1)
                    }
                    StructuralIndexLifecycle::Built => {
                        access.index_misses = access.index_misses.saturating_add(1);
                        access.index_builds = access.index_builds.saturating_add(1);
                    }
                }
                let first_observation =
                    state
                        .observed_structural_indexes
                        .as_ref()
                        .is_some_and(|observed| {
                            observed
                                .lock()
                                .expect("observed structural index lock poisoned")
                                .insert(Arc::as_ptr(&index) as usize)
                        });
                if first_observation {
                    access.retained_bytes =
                        access.retained_bytes.saturating_add(index.retained_bytes());
                }
            }
            let selection = index.select(
                plan.structural_access(),
                files,
                plan.has_source_anchors(),
                cache_ready_before_lookup,
                cancellation,
            );
            if index.source_generation() != provider.structural_source_generation() {
                return scan_access(
                    state,
                    files.len(),
                    Some("structural source generation changed during index selection"),
                );
            }
            match selection {
                Ok(Some(candidates)) => {
                    if let Some(profile) = &mut state.profile {
                        let access = &mut profile.access_path;
                        access.record_selected(&format!(
                            "{}:{}",
                            candidates.estimate.kind.label(),
                            candidates.selected
                        ));
                        access.scoped_files = access
                            .scoped_files
                            .saturating_add(candidates.estimate.scoped_files);
                        access.estimated_provider_files = access
                            .estimated_provider_files
                            .saturating_add(candidates.estimate.provider_files);
                        access.scoped_fact_nodes = access
                            .scoped_fact_nodes
                            .saturating_add(candidates.estimate.scoped_fact_nodes);
                        access.candidate_files = access
                            .candidate_files
                            .saturating_add(candidates.estimate.candidate_files);
                        access.candidate_facts = access
                            .candidate_facts
                            .saturating_add(candidates.estimate.candidate_facts);
                        access.selected_terms.extend(
                            candidates.estimate.selected_terms.iter().map(|term| {
                                QueryAccessPathTermProfile {
                                    label: term.label.to_string(),
                                    candidate_facts: term.candidate_facts,
                                }
                            }),
                        );
                        access.source_verification_required |=
                            candidates.estimate.source_verification_required;
                        access.cache_ready_lookups = access.cache_ready_lookups.saturating_add(
                            u64::from(candidates.estimate.cache_ready_before_lookup),
                        );
                    }
                    SeedStructuralAccess::Indexed {
                        index,
                        candidates: Arc::new(candidates),
                    }
                }
                Ok(None) => scan_access(state, files.len(), None),
                Err(reason) => {
                    if reason.contains("cancelled")
                        && let Some(profile) = &mut state.profile
                    {
                        profile.access_path.index_cancelled =
                            profile.access_path.index_cancelled.saturating_add(1);
                    }
                    scan_access(state, files.len(), Some(reason))
                }
            }
        }
        StructuralIndexAcquisition::Unavailable { reason, build, .. } => {
            record_index_build_facts(state.cache_profile.as_mut(), build);
            record_index_build_access(state.profile.as_mut(), build);
            if let Some(profile) = &mut state.profile {
                let access = &mut profile.access_path;
                access.index_misses = access.index_misses.saturating_add(1);
                access.index_builds = access.index_builds.saturating_add(1);
                access.index_unavailable = access.index_unavailable.saturating_add(1);
                if reason.contains("limit") || reason.contains("retained-byte") {
                    access.index_over_budget = access.index_over_budget.saturating_add(1);
                }
            }
            scan_access(state, files.len(), Some(reason))
        }
        StructuralIndexAcquisition::Cancelled { build, .. } => {
            record_index_build_facts(state.cache_profile.as_mut(), build);
            record_index_build_access(state.profile.as_mut(), build);
            if let Some(profile) = &mut state.profile {
                let access = &mut profile.access_path;
                access.index_misses = access.index_misses.saturating_add(1);
                access.index_cancelled = access.index_cancelled.saturating_add(1);
                if build.elapsed_ns > 0 {
                    access.index_builds = access.index_builds.saturating_add(1);
                }
            }
            scan_access(
                state,
                files.len(),
                Some("structural index acquisition cancelled"),
            )
        }
    }
}

fn execute_seed(
    seed: &CodeQuerySeed,
    terminal_cap: Option<usize>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PlanExecution {
    let cache_key = seed.canonical_cache_key();
    let parallel_budget = state.parallel_seed_budget.clone();
    if parallel_budget.is_some() {
        debug_assert!(
            state.seed_cache.is_empty(),
            "parallel seed branches start with disjoint empty request caches"
        );
    }
    let pipeline_limit = parallel_budget
        .as_ref()
        .map_or(limits.max_pipeline_rows, |lease| {
            lease.coordinator.maximum_pipeline_rows()
        });
    let budget_cap = pipeline_limit.saturating_sub(state.budget.pipeline_rows);
    let desired_rows = terminal_cap.unwrap_or(budget_cap).min(budget_cap);
    let capped_by_budget = terminal_cap.is_none_or(|cap| budget_cap <= cap);
    if let Some(cached) = state.seed_cache.get(&cache_key).cloned() {
        if let Some(profile) = &mut state.cache_profile {
            profile
                .seed_result
                .record_hit(cached.complete, cached.rows.len());
        }
        diagnostics.extend(cached.diagnostics);
        let mut rows = cached.rows;
        let locally_capped = capped_by_budget && rows.len() > desired_rows;
        let truncated = cached.truncated || locally_capped;
        rows.truncate(desired_rows);
        state.budget.pipeline_rows = state.budget.pipeline_rows.saturating_add(rows.len());
        if locally_capped {
            push_pipeline_budget_diagnostic(diagnostics, &state.budget);
        }
        return PlanExecution {
            rows,
            truncated,
            cancelled: false,
            pipeline_halted: false,
        };
    }
    if let Some(profile) = &mut state.cache_profile {
        profile.seed_result.record_miss();
    }
    if desired_rows == 0 {
        push_pipeline_budget_diagnostic(diagnostics, &state.budget);
        return PlanExecution {
            rows: Vec::new(),
            truncated: true,
            cancelled: false,
            pipeline_halted: false,
        };
    }

    let diagnostic_start = diagnostics.len();
    let plan = QueryPlan::for_query(seed);
    let source_index = plan.build_source_index();
    let analyzer = state.analyzer;
    let mut providers = analyzer.structural_search_providers();
    providers.sort_by_key(|provider| provider.structural_language());
    providers.retain(|provider| {
        seed.languages.is_empty() || seed.languages.contains(&provider.structural_language())
    });

    let mut scoped_languages = BTreeSet::new();
    for file in state.analyzer.analyzed_files() {
        if state
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return PlanExecution {
                rows: Vec::new(),
                truncated: true,
                cancelled: true,
                pipeline_halted: false,
            };
        }
        let language = crate::analyzer::common::language_for_file(&file);
        let requested = seed.languages.is_empty() || seed.languages.contains(&language);
        if requested && file_matches_globs(&file, seed) {
            scoped_languages.insert(language);
        }
    }

    let mut supported = BTreeSet::new();
    let mut provider_scopes = Vec::new();
    for provider in providers {
        let language = provider.structural_language();
        supported.insert(language);
        let mut files = provider.structural_files();
        let provider_file_count = files.len();
        files.retain(|file| file_matches_globs(file, seed));
        files.sort();
        let explicitly_requested = seed.languages.contains(&language);
        if !files.is_empty() || explicitly_requested {
            diagnostics.extend(
                plan.features()
                    .unsupported_by(|feature| provider_supports_feature(provider, feature))
                    .into_diagnostics(language)
                    .into_iter()
                    .map(|diagnostic| CodeQueryDiagnostic {
                        code: CodeQueryDiagnosticCode::UnsupportedStructuralFeature,
                        impact: CodeQueryDiagnosticImpact::Incomplete,
                        branch: Vec::new(),
                        language: diagnostic.language().config_label(),
                        message: diagnostic.message(),
                    }),
            );
        }
        let access = if files.is_empty() {
            SeedStructuralAccess::Scan
        } else {
            prepare_seed_access(provider, provider_file_count, &files, &plan, state)
        };
        provider_scopes.push((language, provider, files, access));
    }
    for language in state.analyzer.languages() {
        let explicitly_requested = seed.languages.contains(&language);
        let requested = seed.languages.is_empty() || explicitly_requested;
        if requested
            && !supported.contains(&language)
            && (explicitly_requested || scoped_languages.contains(&language))
        {
            diagnostics.push(CodeQueryDiagnostic {
                code: CodeQueryDiagnosticCode::MissingStructuralAdapter,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "no structural adapter for {} yet; its files were not searched",
                    language.config_label()
                ),
            });
        }
    }

    let mut candidates = Vec::new();
    for (language, provider, files, access) in provider_scopes {
        candidates.extend(files.into_iter().map(|file| {
            (
                rel_path_string(&file),
                language,
                provider,
                file,
                access.clone(),
            )
        }));
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

    let probing_budget = capped_by_budget;
    let match_cap = desired_rows.saturating_add(usize::from(probing_budget));
    let mut pending: Vec<PendingMatch> = Vec::new();
    let mut truncated = false;
    let mut cache_complete = state.cache_profile.as_ref().map(|_| true);
    'candidates: for (_path, language, provider, file, access) in candidates {
        if state
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return PlanExecution {
                rows: Vec::new(),
                truncated: true,
                cancelled: true,
                pipeline_halted: false,
            };
        }
        let indexed_file = access.index_file(&file);
        let source_definitely_absent = source_index.requires_source()
            && access.source_may_contain(&file, source_index.required_anchors()) == Some(false);
        let source = if indexed_file.is_none()
            || (source_index.requires_source() && !source_definitely_absent)
        {
            let source = provider.structural_source(&file);
            if let (Some(source), Some(profile)) = (&source, &mut state.profile) {
                profile.access_path.inspected_source_bytes = profile
                    .access_path
                    .inspected_source_bytes
                    .saturating_add(u64::try_from(source.len()).unwrap_or(u64::MAX));
            }
            source
        } else {
            None
        };
        if source_index.requires_source() && !source_definitely_absent && source.is_none() {
            push_seed_provider_omission(diagnostics, language, &file, "indexed source snapshot");
            truncated = true;
            cache_complete = cache_complete.map(|_| false);
            continue;
        }
        let source_bytes = match (indexed_file, source.as_ref()) {
            (Some(indexed), _) => usize::try_from(indexed.source_bytes).unwrap_or(usize::MAX),
            (None, Some(source)) => source.len(),
            (None, None) => {
                push_seed_provider_omission(
                    diagnostics,
                    language,
                    &file,
                    "indexed source snapshot",
                );
                truncated = true;
                cache_complete = cache_complete.map(|_| false);
                continue;
            }
        };
        let mut projected = state.budget;
        projected.scanned_files = projected.scanned_files.saturating_add(1);
        projected.scanned_source_bytes =
            projected.scanned_source_bytes.saturating_add(source_bytes);
        if let Some(lease) = &parallel_budget {
            match lease.admit(projected) {
                FairSeedBudgetAdmission::Admitted => {}
                FairSeedBudgetAdmission::Rejected(global_projected) => {
                    push_budget_diagnostic(diagnostics, &global_projected);
                    truncated = true;
                    cache_complete = cache_complete.map(|_| false);
                    break;
                }
                FairSeedBudgetAdmission::Cancelled => {
                    return cancelled_plan_execution();
                }
            }
        } else if projected.scanned_files > limits.max_scanned_files
            || projected.scanned_source_bytes > limits.max_scanned_source_bytes
        {
            push_budget_diagnostic(diagnostics, &projected);
            truncated = true;
            cache_complete = cache_complete.map(|_| false);
            break;
        }
        state.budget.scanned_files = projected.scanned_files;
        state.budget.scanned_source_bytes = projected.scanned_source_bytes;
        if source_definitely_absent {
            continue;
        }
        if source
            .as_deref()
            .is_some_and(|source| !source_index.may_match(source))
        {
            continue;
        }
        let candidate_ids = access.candidate_facts(&file);
        let mut facts = None;
        let fact_nodes = if let Some(indexed) = indexed_file {
            usize::try_from(indexed.fact_nodes).unwrap_or(usize::MAX)
        } else {
            let loaded = load_seed_facts(provider, &file, state.cache_profile.as_mut());
            let Some(loaded) = loaded else {
                push_seed_provider_omission(
                    diagnostics,
                    language,
                    &file,
                    "normalized structural facts",
                );
                truncated = true;
                cache_complete = cache_complete.map(|_| false);
                continue;
            };
            let count = loaded.nodes().len();
            if let Some(profile) = &mut state.profile {
                profile.access_path.materialized_files =
                    profile.access_path.materialized_files.saturating_add(1);
                profile.access_path.materialized_fact_nodes = profile
                    .access_path
                    .materialized_fact_nodes
                    .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
            }
            facts = Some(loaded);
            if let Some(profile) = &mut state.profile {
                let access_profile = &mut profile.access_path;
                access_profile.candidate_files = access_profile.candidate_files.saturating_add(1);
                access_profile.candidate_facts = access_profile
                    .candidate_facts
                    .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
            }
            count
        };
        if let Some(profile) = &mut state.profile {
            profile.access_path.admitted_fact_nodes = profile
                .access_path
                .admitted_fact_nodes
                .saturating_add(u64::try_from(fact_nodes).unwrap_or(u64::MAX));
        }
        projected = state.budget;
        projected.fact_nodes = projected.fact_nodes.saturating_add(fact_nodes);
        if let Some(lease) = &parallel_budget {
            match lease.admit(projected) {
                FairSeedBudgetAdmission::Admitted => {}
                FairSeedBudgetAdmission::Rejected(global_projected) => {
                    push_budget_diagnostic(diagnostics, &global_projected);
                    truncated = true;
                    cache_complete = cache_complete.map(|_| false);
                    break;
                }
                FairSeedBudgetAdmission::Cancelled => {
                    return cancelled_plan_execution();
                }
            }
        } else if projected
            .fact_nodes
            .saturating_add(projected.examined_references)
            > limits.max_fact_nodes
        {
            push_budget_diagnostic(diagnostics, &projected);
            truncated = true;
            cache_complete = cache_complete.map(|_| false);
            break;
        }
        state.budget.fact_nodes = projected.fact_nodes;
        let selected_facts = candidate_ids.unwrap_or(&[]);
        if indexed_file.is_some() && selected_facts.is_empty() {
            continue;
        }
        let facts = match facts {
            Some(facts) => facts,
            None => {
                let loaded = load_seed_facts(provider, &file, state.cache_profile.as_mut());
                let Some(loaded) = loaded else {
                    push_seed_provider_omission(
                        diagnostics,
                        language,
                        &file,
                        "normalized structural facts",
                    );
                    truncated = true;
                    cache_complete = cache_complete.map(|_| false);
                    continue;
                };
                if loaded.nodes().len() != fact_nodes
                    || selected_facts
                        .last()
                        .is_some_and(|id| (*id as usize) >= loaded.nodes().len())
                {
                    state.access_failure.get_or_insert_with(|| {
                        format!(
                            "snapshot structural index metadata changed for {}",
                            rel_path_string(&file)
                        )
                    });
                    push_seed_provider_omission(
                        diagnostics,
                        language,
                        &file,
                        "fresh snapshot structural index metadata",
                    );
                    truncated = true;
                    cache_complete = cache_complete.map(|_| false);
                    continue;
                }
                if let Some(profile) = &mut state.profile {
                    profile.access_path.materialized_files =
                        profile.access_path.materialized_files.saturating_add(1);
                    profile.access_path.materialized_fact_nodes = profile
                        .access_path
                        .materialized_fact_nodes
                        .saturating_add(u64::try_from(loaded.nodes().len()).unwrap_or(u64::MAX));
                }
                loaded
            }
        };
        let remaining = match_cap.saturating_sub(pending.len());
        let matches = if indexed_file.is_some() {
            if let Some(profile) = &mut state.profile {
                profile.access_path.examined_fact_nodes = profile
                    .access_path
                    .examined_fact_nodes
                    .saturating_add(u64::try_from(selected_facts.len()).unwrap_or(u64::MAX));
            }
            super::matcher::match_query_candidates(
                seed,
                &facts,
                selected_facts.iter().copied(),
                remaining,
            )
        } else {
            if let Some(profile) = &mut state.profile {
                profile.access_path.examined_fact_nodes = profile
                    .access_path
                    .examined_fact_nodes
                    .saturating_add(u64::try_from(facts.nodes().len()).unwrap_or(u64::MAX));
            }
            super::matcher::match_query(seed, &facts, remaining)
        };
        if let Some(lease) = &parallel_budget {
            for fact_match in matches {
                let mut projected = state.budget;
                projected.pipeline_rows = projected.pipeline_rows.saturating_add(1);
                match lease.admit(projected) {
                    FairSeedBudgetAdmission::Admitted => {
                        state.budget.pipeline_rows = projected.pipeline_rows;
                        pending.push((language, file.clone(), Arc::clone(&facts), fact_match));
                    }
                    FairSeedBudgetAdmission::Rejected(_) => {
                        push_pipeline_budget_diagnostic(diagnostics, &lease.budget_before_branch());
                        truncated = true;
                        cache_complete = cache_complete.map(|_| false);
                        break 'candidates;
                    }
                    FairSeedBudgetAdmission::Cancelled => {
                        return cancelled_plan_execution();
                    }
                }
            }
        } else {
            pending.extend(
                matches
                    .into_iter()
                    .map(|fact_match| (language, file.clone(), Arc::clone(&facts), fact_match)),
            );
        }
        if parallel_budget.is_none() && pending.len() >= match_cap {
            // The cap stopped the scan before the remaining candidates were
            // examined. This can be enough for a root limit probe while still
            // being unsafe to advertise as a complete reusable seed layer.
            cache_complete = cache_complete.map(|_| false);
            break;
        }
    }
    if pending.len() > desired_rows {
        pending.truncate(desired_rows);
        cache_complete = cache_complete.map(|_| false);
        if capped_by_budget {
            truncated = true;
            push_pipeline_budget_diagnostic(diagnostics, &state.budget);
        }
    }
    let rows = pending
        .into_iter()
        .map(|(language, file, facts, fact_match)| {
            let seed = Arc::new(SeedMatch {
                language,
                file,
                facts,
                fact_match,
            });
            PipelineRow {
                value: PipelineValue::StructuralMatch(Arc::clone(&seed)),
                traces: vec![PipelineTrace {
                    branch: Vec::new(),
                    seed,
                    steps: Vec::new(),
                }],
                provenance_truncated: false,
            }
        })
        .collect::<Vec<_>>();
    let cache_complete = cache_complete.map(|complete| {
        complete
            && !truncated
            && !diagnostics[diagnostic_start..]
                .iter()
                .any(|diagnostic| diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete)
    });
    if parallel_budget.is_none() {
        state.budget.pipeline_rows = state.budget.pipeline_rows.saturating_add(rows.len());
    }
    state.seed_cache.insert(
        cache_key,
        CachedSeedExecution {
            rows: rows.clone(),
            diagnostics: diagnostics[diagnostic_start..].to_vec(),
            truncated,
            complete: cache_complete,
        },
    );
    if let Some(profile) = &mut state.cache_profile {
        profile.seed_result.record_build(cache_complete);
    }
    PlanExecution {
        rows,
        truncated,
        cancelled: false,
        pipeline_halted: false,
    }
}

#[derive(Default)]
struct QueryStepInstrumentation {
    rows_visited: usize,
    relation_expansions: usize,
    temporary_capacity_bytes_lower_bound: u64,
}

fn push_seed_provider_omission(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    language: Language,
    file: &ProjectFile,
    unavailable: &str,
) {
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: language.config_label(),
        message: format!(
            "structural seed omitted {} because its provider returned no {unavailable}",
            rel_path_string(file)
        ),
    });
}

fn acquire_direct_import_layer(
    state: &mut QueryExecutionState<'_>,
    request: DerivedLayerRequest,
    limits: CodeQueryExecutionLimits,
    build_if_missing: bool,
) -> Option<DerivedLayerLifecycle> {
    let Some(cache) = state.analyzer.snapshot_derived_layer_cache() else {
        if let Some(profile) = &mut state.cache_profile {
            let topology = &mut profile.direct_import_topology;
            topology.lookups = topology.lookups.saturating_add(1);
            topology.misses = topology.misses.saturating_add(1);
            topology.unavailable = topology.unavailable.saturating_add(1);
            topology.fallbacks = topology.fallbacks.saturating_add(1);
        }
        if build_if_missing && state.access_mode == StructuralAccessMode::IndexedRequired {
            state
                .access_failure
                .get_or_insert_with(|| "analyzer has no snapshot derived-layer cache".to_string());
        }
        return None;
    };
    let uncancelled = CancellationToken::default();
    let cancellation = state.cancellation.unwrap_or(&uncancelled);
    let source_generation = state.analyzer.project().analysis_generation();
    if state
        .direct_import_layer_generation
        .is_some_and(|generation| generation != source_generation)
    {
        state.direct_import_layer = None;
        state.direct_import_layer_generation = None;
    }
    let ready = cache.get_ready(request, source_generation, cancellation);
    let acquisition = match ready {
        Some(layer) if state.analyzer.project().analysis_generation() == source_generation => {
            DerivedLayerAcquisition::Ready {
                layer,
                lifecycle: DerivedLayerLifecycle::Hit,
                wait: Default::default(),
                build: DerivedLayerBuildMetrics::default(),
            }
        }
        Some(_) => DerivedLayerAcquisition::Unavailable {
            reason: "derived-layer source generation changed before reuse".to_string(),
            over_budget: false,
            wait: Default::default(),
            build: DerivedLayerBuildMetrics::default(),
        },
        None if !build_if_missing => {
            if let Some(profile) = &mut state.cache_profile {
                let topology = &mut profile.direct_import_topology;
                topology.lookups = topology.lookups.saturating_add(1);
                topology.misses = topology.misses.saturating_add(1);
                topology.fallbacks = topology.fallbacks.saturating_add(1);
            }
            return None;
        }
        None => cache.acquire(
            request,
            source_generation,
            cancellation,
            || {
                build_direct_import_topology(
                    state.analyzer,
                    cancellation,
                    DirectImportTopologyLimits {
                        max_files: limits.max_scanned_files,
                        max_edges: limits.max_pipeline_rows,
                        max_retained_bytes: cache.max_retained_bytes(),
                    },
                )
            },
            || state.analyzer.project().analysis_generation() == source_generation,
        ),
    };

    let (wait, build) = match &acquisition {
        DerivedLayerAcquisition::Ready { wait, build, .. }
        | DerivedLayerAcquisition::Cancelled { wait, build }
        | DerivedLayerAcquisition::Unavailable { wait, build, .. } => (*wait, *build),
    };
    state.budget.import_files_resolved = state
        .budget
        .import_files_resolved
        .saturating_add(usize::try_from(build.resolved_files).unwrap_or(usize::MAX));
    state.budget.import_edges_resolved = state
        .budget
        .import_edges_resolved
        .saturating_add(usize::try_from(build.resolved_edges).unwrap_or(usize::MAX));
    if let Some(profile) = &mut state.cache_profile {
        let topology = &mut profile.direct_import_topology;
        topology.lookups = topology.lookups.saturating_add(1);
        topology.waits = topology.waits.saturating_add(wait.waits);
        topology.wait_ns = topology.wait_ns.saturating_add(wait.wait_ns);
        topology.build_files = topology.build_files.saturating_add(build.resolved_files);
        topology.build_edges = topology.build_edges.saturating_add(build.resolved_edges);
        topology.build_ns = topology.build_ns.saturating_add(build.elapsed_ns);
    }

    match acquisition {
        DerivedLayerAcquisition::Ready { lifecycle, .. }
            if state.analyzer.project().analysis_generation() != source_generation =>
        {
            if let Some(profile) = &mut state.cache_profile {
                let topology = &mut profile.direct_import_topology;
                topology.misses = topology.misses.saturating_add(1);
                topology.unavailable = topology.unavailable.saturating_add(1);
                topology.fallbacks = topology.fallbacks.saturating_add(1);
                topology.builds = topology
                    .builds
                    .saturating_add(u64::from(lifecycle == DerivedLayerLifecycle::Built));
            }
            if build_if_missing && state.access_mode == StructuralAccessMode::IndexedRequired {
                state.access_failure.get_or_insert_with(|| {
                    "derived-layer source generation changed before selection".to_string()
                });
            }
            state.direct_import_layer = None;
            state.direct_import_layer_generation = None;
            None
        }
        DerivedLayerAcquisition::Ready {
            layer, lifecycle, ..
        } => {
            if let Some(profile) = &mut state.cache_profile {
                let topology = &mut profile.direct_import_topology;
                match lifecycle {
                    DerivedLayerLifecycle::Hit => {
                        topology.hits = topology.hits.saturating_add(1);
                        topology.complete_hits = topology.complete_hits.saturating_add(1);
                        topology.replayed_items = topology.replayed_items.saturating_add(
                            u64::try_from(layer.direct_import_topology().resolved_edges())
                                .unwrap_or(u64::MAX),
                        );
                    }
                    DerivedLayerLifecycle::Built => {
                        topology.misses = topology.misses.saturating_add(1);
                        topology.builds = topology.builds.saturating_add(1);
                        topology.complete_builds = topology.complete_builds.saturating_add(1);
                    }
                }
                let first_observation =
                    state
                        .observed_structural_indexes
                        .as_ref()
                        .is_some_and(|observed| {
                            observed
                                .lock()
                                .expect("observed snapshot values lock poisoned")
                                .insert(Arc::as_ptr(&layer) as usize)
                        });
                if first_observation {
                    topology.retained_bytes = topology
                        .retained_bytes
                        .saturating_add(layer.direct_import_topology().retained_bytes());
                }
            }
            state.direct_import_layer = Some(layer);
            state.direct_import_layer_generation = Some(source_generation);
            Some(lifecycle)
        }
        DerivedLayerAcquisition::Cancelled { .. } => {
            if let Some(profile) = &mut state.cache_profile {
                let topology = &mut profile.direct_import_topology;
                topology.misses = topology.misses.saturating_add(1);
                topology.cancelled = topology.cancelled.saturating_add(1);
                topology.fallbacks = topology.fallbacks.saturating_add(1);
                if build.elapsed_ns > 0 {
                    topology.builds = topology.builds.saturating_add(1);
                }
            }
            if build_if_missing && state.access_mode == StructuralAccessMode::IndexedRequired {
                state.access_failure.get_or_insert_with(|| {
                    "direct import topology acquisition cancelled".to_string()
                });
            }
            None
        }
        DerivedLayerAcquisition::Unavailable {
            reason,
            over_budget,
            ..
        } => {
            if let Some(profile) = &mut state.cache_profile {
                let topology = &mut profile.direct_import_topology;
                topology.misses = topology.misses.saturating_add(1);
                topology.unavailable = topology.unavailable.saturating_add(1);
                topology.over_budget = topology.over_budget.saturating_add(u64::from(over_budget));
                topology.fallbacks = topology.fallbacks.saturating_add(1);
                if build.elapsed_ns > 0 {
                    topology.builds = topology.builds.saturating_add(1);
                }
            }
            if build_if_missing && state.access_mode == StructuralAccessMode::IndexedRequired {
                state.access_failure.get_or_insert(reason);
            }
            None
        }
    }
}

fn discard_stale_direct_import_layer(state: &mut QueryExecutionState<'_>, required: bool) {
    let Some(layer_generation) = state.direct_import_layer_generation else {
        return;
    };
    if state.analyzer.project().analysis_generation() == layer_generation {
        return;
    }
    state.direct_import_layer = None;
    state.direct_import_layer_generation = None;
    if let Some(profile) = &mut state.cache_profile {
        let topology = &mut profile.direct_import_topology;
        topology.unavailable = topology.unavailable.saturating_add(1);
        topology.fallbacks = topology.fallbacks.saturating_add(1);
    }
    if required && state.access_mode == StructuralAccessMode::IndexedRequired {
        state
            .access_failure
            .get_or_insert_with(|| "direct import topology became stale before use".to_string());
    }
}

fn record_direct_import_fallback(
    state: &mut QueryExecutionState<'_>,
    reason: &str,
    required: bool,
) {
    if let Some(profile) = &mut state.cache_profile {
        profile.direct_import_topology.fallbacks =
            profile.direct_import_topology.fallbacks.saturating_add(1);
    }
    if required && state.access_mode == StructuralAccessMode::IndexedRequired {
        state
            .access_failure
            .get_or_insert_with(|| reason.to_string());
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_plan_step(
    step: &QueryStep,
    derived_layer_request: Option<DerivedLayerRequest>,
    final_in_authored_suffix: bool,
    rows: Vec<PipelineRow>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    terminal_cap: Option<usize>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    instrumentation: Option<&mut QueryStepInstrumentation>,
) -> PlanExecution {
    let mut truncated = false;
    if state
        .cancellation
        .is_some_and(CancellationToken::is_cancelled)
    {
        return PlanExecution {
            rows: Vec::new(),
            truncated: true,
            cancelled: true,
            pipeline_halted: false,
        };
    }
    let mut use_snapshot_imports = false;
    let mut snapshot_lifecycle = None;
    if !rows.is_empty() && matches!(step, QueryStep::ImportsOf | QueryStep::ImportersOf) {
        if state.access_mode != StructuralAccessMode::ScanOnly {
            let request = derived_layer_request
                .unwrap_or_else(DerivedLayerRequest::complete_direct_import_topology);
            let build_if_missing = derived_layer_request.is_some();
            snapshot_lifecycle =
                acquire_direct_import_layer(state, request, limits, build_if_missing);
        }
        discard_stale_direct_import_layer(state, derived_layer_request.is_some());
        if let Some(topology) = state
            .direct_import_layer
            .as_deref()
            .map(DerivedLayer::direct_import_topology)
        {
            let within_request_budget = topology.resolved_files() <= limits.max_scanned_files
                && topology.resolved_edges() <= limits.max_pipeline_rows;
            let relation_complete =
                step == &QueryStep::ImportsOf || topology.reverse_relation_complete();
            use_snapshot_imports = within_request_budget && relation_complete;
            if !use_snapshot_imports {
                record_direct_import_fallback(
                    state,
                    "complete direct import topology cannot satisfy this request",
                    derived_layer_request.is_some(),
                );
            }
        }

        if use_snapshot_imports {
            let topology = state
                .direct_import_layer
                .as_deref()
                .expect("snapshot import layer was selected")
                .direct_import_topology();
            let replayed_edges = rows
                .iter()
                .filter_map(|row| match &row.value {
                    PipelineValue::File(file) if step == &QueryStep::ImportersOf => {
                        topology.importer_count(file)
                    }
                    PipelineValue::File(file) => topology.imports_of(file).map(|edges| edges.len()),
                    PipelineValue::StructuralMatch(_)
                    | PipelineValue::Declaration(_)
                    | PipelineValue::ReferenceSite(_)
                    | PipelineValue::CallSite(_)
                    | PipelineValue::ExpressionSite(_)
                    | PipelineValue::ReceiverAnalysis(_) => None,
                })
                .sum();
            if let Some(profile) = &mut state.cache_profile {
                let relation = if step == &QueryStep::ImportersOf {
                    &mut profile.import_reverse
                } else {
                    &mut profile.import_forward
                };
                if snapshot_lifecycle == Some(DerivedLayerLifecycle::Built) {
                    relation.record_miss();
                    relation.record_build(Some(true));
                } else {
                    relation.record_hit(Some(true), replayed_edges);
                }
            }
        } else {
            let graph = state
                .import_graph
                .get_or_insert_with(|| RequestLocalDirectImportGraph::new(state.analyzer));
            let graph_exhausted = if step == &QueryStep::ImportersOf {
                let cache_observation = state
                    .cache_profile
                    .as_ref()
                    .map(|_| (graph.is_complete(), graph.reverse_relation_complete()));
                if let (Some(profile), Some((cache_hit, cache_complete))) =
                    (&mut state.cache_profile, cache_observation)
                {
                    if cache_hit {
                        let replayed_edges = rows
                            .iter()
                            .filter_map(|row| match &row.value {
                                PipelineValue::File(file) => Some(graph.importer_count(file)),
                                PipelineValue::StructuralMatch(_)
                                | PipelineValue::Declaration(_)
                                | PipelineValue::ReferenceSite(_)
                                | PipelineValue::CallSite(_)
                                | PipelineValue::ExpressionSite(_)
                                | PipelineValue::ReceiverAnalysis(_) => None,
                            })
                            .sum();
                        profile
                            .import_reverse
                            .record_hit(Some(cache_complete), replayed_edges);
                    } else {
                        profile.import_reverse.record_miss();
                    }
                }
                let resolved_files_before = graph.resolved_files();
                let resolved_edges_before = graph.resolved_edges();
                let exhausted = graph.ensure_complete(
                    state.analyzer,
                    limits.max_scanned_files,
                    limits.max_pipeline_rows,
                    state.cancellation,
                );
                state.budget.import_files_resolved = state
                    .budget
                    .import_files_resolved
                    .saturating_add(graph.resolved_files().saturating_sub(resolved_files_before));
                state.budget.import_edges_resolved = state
                    .budget
                    .import_edges_resolved
                    .saturating_add(graph.resolved_edges().saturating_sub(resolved_edges_before));
                if cache_observation.is_some_and(|(cache_hit, _)| !cache_hit)
                    && let Some(profile) = &mut state.cache_profile
                {
                    profile
                        .import_reverse
                        .record_build(Some(!exhausted && graph.reverse_relation_complete()));
                }
                exhausted
            } else {
                let mut frontier = rows
                    .iter()
                    .filter_map(|row| match &row.value {
                        PipelineValue::File(file) => Some(file.clone()),
                        PipelineValue::StructuralMatch(_)
                        | PipelineValue::Declaration(_)
                        | PipelineValue::ReferenceSite(_)
                        | PipelineValue::CallSite(_)
                        | PipelineValue::ExpressionSite(_)
                        | PipelineValue::ReceiverAnalysis(_) => None,
                    })
                    .collect::<Vec<_>>();
                frontier.sort_by_key(rel_path_string);
                frontier.dedup();
                let cache_observation = state.cache_profile.as_ref().map(|_| {
                    let cache_hit = frontier.iter().all(|file| graph.has_cached_forward(file));
                    let cache_complete = cache_hit && graph.forward_relation_complete(&frontier);
                    let replayed_edges = frontier
                        .iter()
                        .map(|file| graph.cached_forward_edge_count(file))
                        .sum();
                    (cache_hit, cache_complete, replayed_edges)
                });
                if let (Some(profile), Some((cache_hit, cache_complete, replayed_edges))) =
                    (&mut state.cache_profile, cache_observation)
                {
                    if cache_hit {
                        profile
                            .import_forward
                            .record_hit(Some(cache_complete), replayed_edges);
                    } else {
                        profile.import_forward.record_miss();
                    }
                }
                let resolved_files_before = graph.resolved_files();
                let resolved_edges_before = graph.resolved_edges();
                let exhausted = graph.ensure_forward(
                    state.analyzer,
                    &frontier,
                    limits.max_scanned_files,
                    limits.max_pipeline_rows,
                    state.cancellation,
                );
                state.budget.import_files_resolved = state
                    .budget
                    .import_files_resolved
                    .saturating_add(graph.resolved_files().saturating_sub(resolved_files_before));
                state.budget.import_edges_resolved = state
                    .budget
                    .import_edges_resolved
                    .saturating_add(graph.resolved_edges().saturating_sub(resolved_edges_before));
                if cache_observation.is_some_and(|(cache_hit, _, _)| !cache_hit)
                    && let Some(profile) = &mut state.cache_profile
                {
                    profile.import_forward.record_build(Some(
                        !exhausted && graph.forward_relation_complete(&frontier),
                    ));
                }
                exhausted
            };
            if state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
            {
                return cancelled_plan_execution();
            }
            if graph_exhausted {
                truncated = true;
                push_import_graph_budget_diagnostic(diagnostics, graph);
            }
        }
    }
    let max_step_outputs = if final_in_authored_suffix {
        terminal_cap.unwrap_or(limits.max_pipeline_rows)
    } else {
        limits.max_pipeline_rows
    };
    let import_access = if use_snapshot_imports {
        state
            .direct_import_layer
            .as_deref()
            .map(DerivedLayer::direct_import_topology)
            .map(DirectImportAccess::Snapshot)
    } else {
        state
            .import_graph
            .as_ref()
            .map(DirectImportAccess::RequestLocal)
    };
    let (mut rows, exhausted, step_truncated) = apply_pipeline_step(
        state.analyzer,
        state.workspace,
        step,
        rows,
        import_access,
        Some(&mut state.indexed_declarations),
        &mut state.reference_cache,
        &mut state.call_cache,
        &mut state.budget,
        limits,
        max_step_outputs,
        state.cancellation,
        diagnostics,
        state.receiver_budget_override,
        &mut state.cache_profile,
        instrumentation,
    );
    truncated |= step_truncated;
    if state
        .cancellation
        .is_some_and(CancellationToken::is_cancelled)
    {
        // A partially produced row is usable only after the final step:
        // before then its value belongs to an intermediate domain and
        // cannot satisfy the query's validated terminal contract.
        if !final_in_authored_suffix {
            rows.clear();
        }
        return PlanExecution {
            rows,
            truncated: true,
            cancelled: true,
            pipeline_halted: false,
        };
    }
    if exhausted {
        truncated = true;
        if state.budget.pipeline_rows >= limits.max_pipeline_rows
            || state.budget.provenance_steps >= limits.max_pipeline_rows
        {
            push_pipeline_budget_diagnostic(diagnostics, &state.budget);
        }
        if !final_in_authored_suffix {
            rows.clear();
        }
    }
    PlanExecution {
        rows,
        truncated,
        cancelled: false,
        pipeline_halted: exhausted && !final_in_authored_suffix,
    }
}

fn fair_branch_limits(
    budget: &CodeQueryExecutionBudget,
    parent: CodeQueryExecutionLimits,
    remaining_branches: usize,
) -> CodeQueryExecutionLimits {
    fn fair_cap(current: usize, maximum: usize, remaining: usize) -> usize {
        current.saturating_add(maximum.saturating_sub(current).div_ceil(remaining.max(1)))
    }
    CodeQueryExecutionLimits {
        max_scanned_files: fair_cap(
            budget.scanned_files,
            parent.max_scanned_files,
            remaining_branches,
        ),
        max_scanned_source_bytes: fair_cap(
            budget.scanned_source_bytes,
            parent.max_scanned_source_bytes,
            remaining_branches,
        ),
        max_fact_nodes: fair_cap(
            budget.fact_nodes.saturating_add(budget.examined_references),
            parent.max_fact_nodes,
            remaining_branches,
        ),
        max_pipeline_rows: fair_cap(
            budget.pipeline_rows.max(budget.provenance_steps),
            parent.max_pipeline_rows,
            remaining_branches,
        ),
    }
}

fn prefix_branch_rows(rows: &mut [PipelineRow], branch: usize) {
    for row in rows {
        for trace in &mut row.traces {
            trace.branch.insert(0, branch);
        }
    }
}

fn prefix_branch_diagnostics(diagnostics: &mut [CodeQueryDiagnostic], branch: usize) {
    for diagnostic in diagnostics {
        diagnostic.branch.insert(0, branch);
    }
}

struct SetMergeMeasurement {
    rows_discarded: usize,
    temporary_capacity_bytes_lower_bound: u64,
}

fn combine_set_rows(
    op: SetOperator,
    mut branches: Vec<Vec<PipelineRow>>,
    measure: bool,
) -> (Vec<PipelineRow>, Option<SetMergeMeasurement>) {
    let input_rows = if measure {
        branches.iter().map(Vec::len).sum::<usize>()
    } else {
        0
    };
    match op {
        SetOperator::Union => {
            let mut output = Vec::new();
            let mut indexes = HashMap::default();
            for branch in branches {
                for row in branch {
                    insert_pipeline_row(
                        &mut output,
                        &mut indexes,
                        row.value,
                        row.traces,
                        row.provenance_truncated,
                    );
                }
            }
            let measurement = measure.then(|| SetMergeMeasurement {
                rows_discarded: input_rows.saturating_sub(output.len()),
                temporary_capacity_bytes_lower_bound: hash_capacity_bytes_lower_bound::<
                    PipelineKey,
                    usize,
                >(indexes.capacity()),
            });
            (output, measurement)
        }
        SetOperator::Intersect => {
            let first = branches.remove(0);
            let mut later = branches
                .into_iter()
                .map(|branch| {
                    branch
                        .into_iter()
                        .map(|row| (row.value.key(), row))
                        .collect::<HashMap<_, _>>()
                })
                .collect::<Vec<_>>();
            let mut output = Vec::new();
            let mut indexes = HashMap::default();
            for mut row in first {
                let key = row.value.key();
                let mut contributions = Vec::with_capacity(later.len());
                let mut present = true;
                for branch in &mut later {
                    if let Some(contribution) = branch.remove(&key) {
                        contributions.push(contribution);
                    } else {
                        present = false;
                        break;
                    }
                }
                if present {
                    for contribution in contributions {
                        row.traces.extend(contribution.traces);
                        row.provenance_truncated |= contribution.provenance_truncated;
                    }
                    insert_pipeline_row(
                        &mut output,
                        &mut indexes,
                        row.value,
                        row.traces,
                        row.provenance_truncated,
                    );
                }
            }
            let measurement = measure.then(|| SetMergeMeasurement {
                rows_discarded: input_rows.saturating_sub(output.len()),
                temporary_capacity_bytes_lower_bound: later
                    .iter()
                    .map(|branch| {
                        hash_capacity_bytes_lower_bound::<PipelineKey, PipelineRow>(
                            branch.capacity(),
                        )
                    })
                    .fold(0u64, u64::saturating_add)
                    .saturating_add(hash_capacity_bytes_lower_bound::<PipelineKey, usize>(
                        indexes.capacity(),
                    )),
            });
            (output, measurement)
        }
        SetOperator::Except => {
            let first = branches.remove(0);
            let excluded = branches
                .into_iter()
                .flatten()
                .map(|row| row.value.key())
                .collect::<HashSet<_>>();
            let output = first
                .into_iter()
                .filter(|row| !excluded.contains(&row.value.key()))
                .collect::<Vec<_>>();
            let measurement = measure.then(|| SetMergeMeasurement {
                rows_discarded: input_rows.saturating_sub(output.len()),
                temporary_capacity_bytes_lower_bound: hash_capacity_bytes_lower_bound::<
                    PipelineKey,
                    (),
                >(excluded.capacity()),
            });
            (output, measurement)
        }
    }
}

fn hash_capacity_bytes_lower_bound<K, V>(capacity: usize) -> u64 {
    u64::try_from(
        capacity.saturating_mul(std::mem::size_of::<K>().saturating_add(std::mem::size_of::<V>())),
    )
    .unwrap_or(u64::MAX)
}

fn cancelled_query_result() -> CodeQueryResult {
    let mut diagnostics = Vec::new();
    push_cancelled_diagnostic(&mut diagnostics);
    CodeQueryResult {
        results: Vec::new(),
        truncated: true,
        diagnostics,
    }
}

fn invalid_plan_result(error: impl ToString) -> CodeQueryResult {
    CodeQueryResult {
        results: Vec::new(),
        truncated: false,
        diagnostics: vec![CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::InvalidPlan,
            impact: CodeQueryDiagnosticImpact::Invalid,
            branch: Vec::new(),
            language: "workspace",
            message: error.to_string(),
        }],
    }
}

fn push_cancelled_diagnostic(diagnostics: &mut Vec<CodeQueryDiagnostic>) {
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::Cancelled)
    {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::Cancelled,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: "query_code cancelled; any already-produced results are partial".to_string(),
    });
}

#[allow(clippy::too_many_arguments)]
fn apply_pipeline_step(
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    step: &QueryStep,
    rows: Vec<PipelineRow>,
    import_graph: Option<DirectImportAccess<'_>>,
    indexed_declarations: Option<&mut IndexedDeclarations>,
    reference_cache: &mut ReferenceTraversalCache,
    call_cache: &mut CallTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    max_step_outputs: usize,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    cache_profile: &mut Option<QueryCacheProfile>,
    instrumentation: Option<&mut QueryStepInstrumentation>,
) -> (Vec<PipelineRow>, bool, bool) {
    let max_pipeline_rows = limits.max_pipeline_rows;
    let mut output = Vec::new();
    let mut indexes: HashMap<PipelineKey, usize> = HashMap::default();
    let mut unsupported_languages = BTreeSet::new();
    let mut semantic_omissions: BTreeMap<(Language, &'static str), usize> = BTreeMap::new();
    let mut receiver_diagnostics = ReceiverDiagnostics::new();
    let mut enclosing_declarations: HashMap<ProjectFile, EnclosingDeclarationIndex> =
        HashMap::default();
    let mut exhausted = false;
    let mut receiver_truncated = false;
    let receiver_service = matches!(
        step,
        QueryStep::ReceiverTargets(_) | QueryStep::PointsTo(_) | QueryStep::MemberTargets(_)
    )
    .then(|| {
        workspace.map_or_else(
            || ReceiverQueryService::new(analyzer),
            ReceiverQueryService::from_workspace,
        )
    });
    let mut instrumentation = instrumentation;

    let mut indexed_declarations = indexed_declarations;
    'rows: for row in rows {
        if output.len() >= max_step_outputs {
            break;
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return (output, true, receiver_truncated);
        }
        if let Some(instrumentation) = instrumentation.as_deref_mut() {
            instrumentation.rows_visited = instrumentation.rows_visited.saturating_add(1);
        }
        let mut row_exhausted = false;
        if let (
            PipelineValue::StructuralMatch(_),
            QueryStep::ReceiverTargets(filter)
            | QueryStep::PointsTo(filter)
            | QueryStep::MemberTargets(filter),
        ) = (&row.value, step)
            && filter.capture.is_some()
        {
            let operation = receiver_operation(step);
            for trace in &row.traces {
                if output.len() >= max_step_outputs {
                    break;
                }
                let (ranges, input) =
                    structural_receiver_ranges(&trace.seed, operation, filter.capture.as_deref());
                let mut trace_exhausted = false;
                let expansions = receiver_analysis_expansions(
                    receiver_service
                        .as_ref()
                        .expect("receiver query service exists for receiver steps"),
                    operation,
                    &trace.seed.file,
                    ranges,
                    input,
                    filter.capture.clone(),
                    budget,
                    limits,
                    receiver_budget_override,
                    max_step_outputs.saturating_sub(output.len()),
                    cancellation,
                    &mut receiver_diagnostics,
                    &mut trace_exhausted,
                    &mut receiver_truncated,
                );
                if let Some(instrumentation) = instrumentation.as_deref_mut() {
                    instrumentation.relation_expansions = instrumentation
                        .relation_expansions
                        .saturating_add(expansions.len());
                }
                for expansion in expansions {
                    insert_pipeline_row(
                        &mut output,
                        &mut indexes,
                        expansion.value,
                        vec![advance_pipeline_trace(
                            trace.clone(),
                            step,
                            &expansion.trace,
                        )],
                        row.provenance_truncated,
                    );
                }
                if trace_exhausted {
                    exhausted = true;
                    break 'rows;
                }
            }
            continue;
        }
        let expansions = match (&row.value, step) {
            (PipelineValue::StructuralMatch(seed), QueryStep::EnclosingDecl) => {
                let (enclosing, projection_omitted) =
                    enclosing_declaration_value(analyzer, seed, &mut enclosing_declarations);
                if projection_omitted {
                    record_semantic_omission(
                        &mut semantic_omissions,
                        &CodeUnit::file_scope(seed.file.clone()),
                        "a real declaration in the seed file had no exact indexed range",
                    );
                    row_exhausted = true;
                }
                enclosing
                    .map(PipelineValue::Declaration)
                    .into_iter()
                    .map(pipeline_expansion)
                    .collect()
            }
            (PipelineValue::StructuralMatch(seed), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(seed.file.clone()))]
            }
            (PipelineValue::Declaration(declaration), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    declaration.unit.source().clone(),
                ))]
            }
            (PipelineValue::ReferenceSite(site), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(site.file.clone()))]
            }
            (PipelineValue::CallSite(site), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(site.0.file.clone()))]
            }
            (PipelineValue::ExpressionSite(site), QueryStep::FileOf) => vec![pipeline_expansion(
                PipelineValue::File(site.call_site.0.file.clone()),
            )],
            (PipelineValue::ReceiverAnalysis(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.report.site.file.clone(),
                ))]
            }
            (PipelineValue::File(file), QueryStep::ImportsOf) => {
                let graph = import_graph.expect("import graph exists for import steps");
                match graph.imports_of(file) {
                    Some(imports) => imports
                        .into_iter()
                        .map(PipelineValue::File)
                        .map(pipeline_expansion)
                        .collect(),
                    None => {
                        unsupported_languages
                            .insert(crate::analyzer::common::language_for_file(file));
                        Vec::new()
                    }
                }
            }
            (PipelineValue::File(file), QueryStep::ImportersOf) => import_graph
                .expect("import graph exists for import steps")
                .importers_of(file)
                .into_iter()
                .map(PipelineValue::File)
                .map(pipeline_expansion)
                .collect(),
            (
                PipelineValue::Declaration(declaration),
                QueryStep::Supertypes(traversal) | QueryStep::Subtypes(traversal),
            ) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let (expansions, hierarchy_exhausted) = expand_hierarchy(
                    analyzer,
                    declaration,
                    step,
                    *traversal,
                    indexed,
                    budget,
                    max_pipeline_rows,
                    &mut semantic_omissions,
                );
                row_exhausted = hierarchy_exhausted;
                expansions
            }
            (PipelineValue::Declaration(declaration), QueryStep::Members) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                if !is_type_declaration(analyzer, &declaration.unit) {
                    record_semantic_omission(
                        &mut semantic_omissions,
                        &declaration.unit,
                        "input is not a type declaration",
                    );
                    Vec::new()
                } else {
                    let (expansions, members_exhausted) = direct_member_expansions(
                        analyzer,
                        declaration,
                        analyzer.direct_children(&declaration.unit),
                        indexed,
                        budget,
                        max_pipeline_rows,
                        &mut semantic_omissions,
                    );
                    row_exhausted = members_exhausted;
                    expansions
                }
            }
            (PipelineValue::Declaration(declaration), QueryStep::Owner) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let (owner, owner_exhausted) = indexed.owner_of(
                    analyzer,
                    &declaration.unit,
                    &mut budget.pipeline_rows,
                    max_pipeline_rows,
                );
                row_exhausted = owner_exhausted;
                match owner {
                    Some(owner) => vec![budgeted_declaration_expansion(owner)],
                    None if !owner_exhausted => {
                        record_semantic_omission(
                            &mut semantic_omissions,
                            &declaration.unit,
                            "input is not a direct member declaration",
                        );
                        Vec::new()
                    }
                    None => Vec::new(),
                }
            }
            (
                PipelineValue::Declaration(declaration),
                QueryStep::ReferencesOf(filter) | QueryStep::UsedBy(filter),
            ) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let (expansions, reference_exhausted) = inbound_reference_expansions(
                    analyzer,
                    declaration,
                    step,
                    filter,
                    indexed,
                    reference_cache,
                    budget,
                    limits,
                    diagnostics,
                    max_pipeline_rows.saturating_sub(budget.pipeline_rows),
                    cancellation,
                    cache_profile,
                );
                row_exhausted = reference_exhausted;
                expansions
            }
            (PipelineValue::Declaration(declaration), QueryStep::Uses(filter)) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let (expansions, reference_exhausted) = outbound_reference_expansions(
                    analyzer,
                    declaration,
                    filter,
                    indexed,
                    reference_cache,
                    budget,
                    limits,
                    max_step_outputs,
                    cancellation,
                    diagnostics,
                    cache_profile,
                );
                row_exhausted = reference_exhausted;
                expansions
            }
            (
                PipelineValue::Declaration(declaration),
                QueryStep::Callers(filter) | QueryStep::Callees(filter),
            ) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let (expansions, call_exhausted) = call_declaration_expansions(
                    analyzer,
                    declaration,
                    step,
                    filter,
                    indexed,
                    call_cache,
                    budget,
                    limits,
                    max_step_outputs,
                    cancellation,
                    diagnostics,
                    cache_profile,
                );
                row_exhausted = call_exhausted;
                expansions
            }
            (
                PipelineValue::Declaration(declaration),
                QueryStep::CallSitesTo(filter) | QueryStep::CallSitesFrom(filter),
            ) => {
                let (expansions, call_exhausted) = call_site_expansions(
                    analyzer,
                    declaration,
                    step,
                    filter,
                    call_cache,
                    budget,
                    limits,
                    max_step_outputs,
                    cancellation,
                    diagnostics,
                    cache_profile,
                );
                row_exhausted = call_exhausted;
                expansions
            }
            (PipelineValue::CallSite(site), QueryStep::CallInput(selector)) => {
                let (expansions, binding_incomplete) = call_input_expansions(site, selector);
                if binding_incomplete {
                    record_semantic_omission(
                        &mut semantic_omissions,
                        &site.0.callee,
                        "a retained call site had no exact formal-parameter binding layout",
                    );
                    row_exhausted = true;
                }
                expansions
            }
            (
                PipelineValue::StructuralMatch(seed),
                QueryStep::ReceiverTargets(filter)
                | QueryStep::PointsTo(filter)
                | QueryStep::MemberTargets(filter),
            ) => {
                let operation = receiver_operation(step);
                let (ranges, input) =
                    structural_receiver_ranges(seed, operation, filter.capture.as_deref());
                receiver_analysis_expansions(
                    receiver_service
                        .as_ref()
                        .expect("receiver query service exists for receiver steps"),
                    operation,
                    &seed.file,
                    ranges,
                    input,
                    filter.capture.clone(),
                    budget,
                    limits,
                    receiver_budget_override,
                    max_step_outputs.saturating_sub(output.len()),
                    cancellation,
                    &mut receiver_diagnostics,
                    &mut row_exhausted,
                    &mut receiver_truncated,
                )
            }
            (
                PipelineValue::ReferenceSite(site),
                QueryStep::ReceiverTargets(_)
                | QueryStep::PointsTo(_)
                | QueryStep::MemberTargets(_),
            ) => receiver_analysis_expansions(
                receiver_service
                    .as_ref()
                    .expect("receiver query service exists for receiver steps"),
                receiver_operation(step),
                &site.file,
                vec![site.range],
                if matches!(step, QueryStep::PointsTo(_)) {
                    ReceiverQueryInput::Expression
                } else {
                    ReceiverQueryInput::ContainingSite
                },
                None,
                budget,
                limits,
                receiver_budget_override,
                max_step_outputs.saturating_sub(output.len()),
                cancellation,
                &mut receiver_diagnostics,
                &mut row_exhausted,
                &mut receiver_truncated,
            ),
            (PipelineValue::CallSite(site), QueryStep::ReceiverTargets(_)) => {
                receiver_analysis_expansions(
                    receiver_service
                        .as_ref()
                        .expect("receiver query service exists for receiver steps"),
                    ReceiverQueryOperation::ReceiverTargets,
                    &site.0.file,
                    vec![site.0.range],
                    ReceiverQueryInput::ContainingSite,
                    None,
                    budget,
                    limits,
                    receiver_budget_override,
                    max_step_outputs.saturating_sub(output.len()),
                    cancellation,
                    &mut receiver_diagnostics,
                    &mut row_exhausted,
                    &mut receiver_truncated,
                )
            }
            (
                PipelineValue::ExpressionSite(site),
                QueryStep::ReceiverTargets(_) | QueryStep::PointsTo(_),
            ) => receiver_analysis_expansions(
                receiver_service
                    .as_ref()
                    .expect("receiver query service exists for receiver steps"),
                receiver_operation(step),
                &site.call_site.0.file,
                vec![site.range],
                ReceiverQueryInput::Expression,
                None,
                budget,
                limits,
                receiver_budget_override,
                max_step_outputs.saturating_sub(output.len()),
                cancellation,
                &mut receiver_diagnostics,
                &mut row_exhausted,
                &mut receiver_truncated,
            ),
            _ => unreachable!("query step domains are validated before execution"),
        };

        if let Some(instrumentation) = instrumentation.as_deref_mut() {
            instrumentation.relation_expansions = instrumentation
                .relation_expansions
                .saturating_add(expansions.len());
        }

        for expansion in expansions {
            if !expansion.budgeted && budget.pipeline_rows >= max_pipeline_rows {
                exhausted = true;
                break 'rows;
            }
            if !expansion.budgeted {
                budget.pipeline_rows += 1;
            }
            let traces = row
                .traces
                .iter()
                .cloned()
                .map(|trace| advance_pipeline_trace(trace, step, &expansion.trace))
                .collect();
            insert_pipeline_row(
                &mut output,
                &mut indexes,
                expansion.value,
                traces,
                row.provenance_truncated,
            );
        }
        if row_exhausted {
            exhausted = true;
            break;
        }
    }

    if step == &QueryStep::ImportersOf
        && let Some(graph) = import_graph
    {
        unsupported_languages.extend(graph.unsupported_languages());
    }

    for language in unsupported_languages {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UnsupportedImportAnalysis,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "{} does not provide structured import analysis; {} omitted its affected files",
                language.config_label(),
                step.label()
            ),
        });
    }
    append_semantic_omission_diagnostics(diagnostics, step, semantic_omissions);
    for ((code, language, operation, reason), count) in receiver_diagnostics {
        let message = if code == CodeQueryDiagnosticCode::ReceiverAnalysisFailed {
            format!(
                "{operation} failed for {count} analysis input{}: {reason}",
                if count == 1 { "" } else { "s" }
            )
        } else {
            format!(
                "{operation} returned {count} analysis row{} with {reason}",
                if count == 1 { "" } else { "s" }
            )
        };
        diagnostics.push(CodeQueryDiagnostic {
            code,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message,
        });
    }
    if let Some(instrumentation) = instrumentation {
        let index_bytes = indexes.capacity().saturating_mul(
            std::mem::size_of::<PipelineKey>().saturating_add(std::mem::size_of::<usize>()),
        );
        instrumentation.temporary_capacity_bytes_lower_bound =
            u64::try_from(index_bytes).unwrap_or(u64::MAX);
    }
    (output, exhausted, receiver_truncated)
}

fn advance_pipeline_trace(
    mut trace: PipelineTrace,
    step: &QueryStep,
    expansion: &[(PipelineTraceValue, Option<PipelineVia>)],
) -> PipelineTrace {
    trace.steps.extend(
        expansion
            .iter()
            .cloned()
            .map(|(value, via)| PipelineTraceStep {
                op: step.clone(),
                value,
                via,
            }),
    );
    trace
}

fn receiver_operation(step: &QueryStep) -> ReceiverQueryOperation {
    match step {
        QueryStep::ReceiverTargets(_) => ReceiverQueryOperation::ReceiverTargets,
        QueryStep::PointsTo(_) => ReceiverQueryOperation::PointsTo,
        QueryStep::MemberTargets(_) => ReceiverQueryOperation::MemberTargets,
        _ => unreachable!("receiver operation requested for a non-receiver step"),
    }
}

type ReceiverDiagnostics =
    BTreeMap<(CodeQueryDiagnosticCode, Language, &'static str, String), usize>;

fn structural_receiver_ranges(
    seed: &SeedMatch,
    operation: ReceiverQueryOperation,
    capture: Option<&str>,
) -> (Vec<Range>, ReceiverQueryInput) {
    let (spans, input) = if let Some(capture) = capture {
        let spans = seed
            .fact_match
            .captures
            .iter()
            .filter(|binding| binding.name == capture)
            .map(|binding| binding.span)
            .collect::<Vec<_>>();
        (spans, ReceiverQueryInput::Expression)
    } else {
        let fact_id = seed.fact_match.node;
        let fact = seed.facts.node(fact_id);
        let normalized = match operation {
            ReceiverQueryOperation::PointsTo => seed
                .facts
                .role_targets(fact_id, Role::Right)
                .next()
                .map(|target| target.span),
            ReceiverQueryOperation::ReceiverTargets => match fact.kind {
                NormalizedKind::Call => seed
                    .facts
                    .role_targets(fact_id, Role::Receiver)
                    .next()
                    .map(|target| target.span),
                NormalizedKind::FieldAccess => seed
                    .facts
                    .role_targets(fact_id, Role::Object)
                    .next()
                    .map(|target| target.span),
                _ => None,
            },
            ReceiverQueryOperation::MemberTargets => None,
        };
        let input = match operation {
            ReceiverQueryOperation::PointsTo => ReceiverQueryInput::Expression,
            ReceiverQueryOperation::ReceiverTargets if normalized.is_some() => {
                ReceiverQueryInput::Expression
            }
            ReceiverQueryOperation::ReceiverTargets | ReceiverQueryOperation::MemberTargets => {
                ReceiverQueryInput::ContainingSite
            }
        };
        (vec![normalized.unwrap_or_else(|| fact.span())], input)
    };
    let mut seen = HashSet::default();
    let ranges = spans
        .into_iter()
        .filter(|span| seen.insert((span.start_byte, span.end_byte)))
        .map(|span| Range {
            start_byte: span.start_byte,
            end_byte: span.end_byte,
            start_line: seed.facts.line_of_byte(span.start_byte),
            end_line: seed.facts.line_of_byte(span.end_byte),
        })
        .collect();
    (ranges, input)
}

#[allow(clippy::too_many_arguments)]
fn receiver_analysis_expansions(
    service: &ReceiverQueryService<'_>,
    operation: ReceiverQueryOperation,
    file: &ProjectFile,
    mut ranges: Vec<Range>,
    input: ReceiverQueryInput,
    capture: Option<String>,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    max_outputs: usize,
    cancellation: Option<&CancellationToken>,
    receiver_diagnostics: &mut ReceiverDiagnostics,
    shared_budget_exhausted: &mut bool,
    receiver_truncated: &mut bool,
) -> Vec<PipelineExpansion> {
    ranges.sort_by_key(primary_range_key);
    ranges.dedup();
    ranges.truncate(max_outputs);
    let mut expansions = Vec::with_capacity(ranges.len());
    for range in ranges {
        let remaining_facts = limits
            .max_fact_nodes
            .saturating_sub(budget.fact_nodes.saturating_add(budget.examined_references));
        let remaining_rows = limits
            .max_pipeline_rows
            .saturating_sub(budget.pipeline_rows);
        let base = receiver_budget_override.unwrap_or_default();
        let receiver_budget = receiver_budget_for_remaining_work(
            base,
            remaining_facts,
            remaining_rows.saturating_sub(1),
        );
        let report =
            match service.analyze(operation, file, range, input, receiver_budget, cancellation) {
                Ok(report) => report,
                Err(ReceiverQueryError::Cancelled) => {
                    *shared_budget_exhausted = true;
                    break;
                }
                Err(ReceiverQueryError::SemanticProvider(error)) => {
                    *receiver_diagnostics
                        .entry((
                            CodeQueryDiagnosticCode::ReceiverAnalysisFailed,
                            crate::analyzer::common::language_for_file(file),
                            operation.as_str(),
                            error.to_string(),
                        ))
                        .or_default() += 1;
                    break;
                }
            };

        let candidate_count = receiver_candidate_count(&report);
        budget.fact_nodes = budget
            .fact_nodes
            .saturating_add(report.work.setup_nodes)
            .saturating_add(report.work.scope_nodes)
            .saturating_add(report.work.summary_expansions);
        budget.pipeline_rows = budget
            .pipeline_rows
            .saturating_add(1)
            .saturating_add(candidate_count);
        if budget.fact_nodes.saturating_add(budget.examined_references) > limits.max_fact_nodes
            || budget.pipeline_rows > limits.max_pipeline_rows
        {
            *shared_budget_exhausted = true;
        }

        let language = report.site.language;
        match &report.analysis {
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Unsupported { reason })
            | ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Unsupported {
                reason,
            }) => {
                *receiver_diagnostics
                    .entry((
                        CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
                        language,
                        operation.as_str(),
                        format!("unsupported provider or shape: {reason}"),
                    ))
                    .or_default() += 1;
            }
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::ExceededBudget { limit })
            | ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget {
                limit,
            }) => {
                *receiver_truncated = true;
                *receiver_diagnostics
                    .entry((
                        CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
                        language,
                        operation.as_str(),
                        format!("exceeded receiver limit {limit}"),
                    ))
                    .or_default() += 1;
            }
            ReceiverQueryAnalysis::Values(
                ReceiverAnalysisOutcome::Precise(_)
                | ReceiverAnalysisOutcome::Ambiguous(_)
                | ReceiverAnalysisOutcome::Unknown,
            )
            | ReceiverQueryAnalysis::MemberTargets(
                ReceiverAnalysisOutcome::Precise(_)
                | ReceiverAnalysisOutcome::Ambiguous(_)
                | ReceiverAnalysisOutcome::Unknown,
            ) => {}
        }
        if report.candidates_truncated {
            *receiver_truncated = true;
            *receiver_diagnostics
                .entry((
                    CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
                    language,
                    operation.as_str(),
                    "truncated candidates at max_targets".to_string(),
                ))
                .or_default() += 1;
        }
        let value = ReceiverAnalysisValue {
            report,
            capture: capture.clone(),
        };
        expansions.push(PipelineExpansion {
            value: PipelineValue::ReceiverAnalysis(value.clone()),
            trace: vec![(PipelineTraceValue::ReceiverAnalysis(value), None)],
            budgeted: true,
        });
    }
    expansions
}

fn receiver_budget_for_remaining_work(
    base: ReceiverAnalysisBudget,
    remaining_facts: usize,
    remaining_targets: usize,
) -> ReceiverAnalysisBudget {
    let desired_scope = base.max_scope_nodes.min(remaining_facts);
    let desired_summaries = base.max_summary_expansions.min(remaining_facts);
    if desired_scope.saturating_add(desired_summaries) <= remaining_facts {
        return ReceiverAnalysisBudget {
            context_depth: base.context_depth,
            max_targets: base.max_targets.min(remaining_targets),
            max_summary_expansions: desired_summaries,
            max_scope_nodes: desired_scope,
        };
    }

    // CodeQuery has one fact-node budget, while receiver analysis exposes
    // separate scope and summary caps. Reserve up to one quarter for summary
    // expansion, then give scope traversal the remainder; this prevents the
    // two dimensions from each spending the same scalar remainder in full.
    let summary_reserve = desired_summaries.min(remaining_facts / 4);
    let max_scope_nodes = desired_scope.min(remaining_facts - summary_reserve);
    let unallocated = remaining_facts - summary_reserve - max_scope_nodes;
    let max_summary_expansions =
        summary_reserve.saturating_add((desired_summaries - summary_reserve).min(unallocated));
    debug_assert!(max_scope_nodes.saturating_add(max_summary_expansions) <= remaining_facts);
    ReceiverAnalysisBudget {
        context_depth: base.context_depth,
        max_targets: base.max_targets.min(remaining_targets),
        max_summary_expansions,
        max_scope_nodes,
    }
}

fn receiver_candidate_count(report: &ReceiverQueryReport) -> usize {
    match &report.analysis {
        ReceiverQueryAnalysis::Values(outcome) => outcome.values().map_or(0, <[_]>::len),
        ReceiverQueryAnalysis::MemberTargets(outcome) => outcome.values().map_or(0, <[_]>::len),
    }
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

fn direct_member_expansions(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    mut children: Vec<CodeUnit>,
    indexed: &mut IndexedDeclarations,
    budget: &mut CodeQueryExecutionBudget,
    max_pipeline_rows: usize,
    omissions: &mut BTreeMap<(Language, &'static str), usize>,
) -> (Vec<PipelineExpansion>, bool) {
    children.sort();
    children.dedup();
    let mut expansions = Vec::new();
    let mut exhausted = false;
    for unit in children {
        if budget.pipeline_rows >= max_pipeline_rows {
            exhausted = true;
            break;
        }
        budget.pipeline_rows += 1;
        let Some(child) = indexed.get(analyzer, &unit) else {
            record_semantic_omission(
                omissions,
                &unit,
                "a direct member declaration had no exact indexed range",
            );
            exhausted = true;
            continue;
        };
        indexed.record_owner(&unit, &declaration.unit);
        expansions.push(budgeted_declaration_expansion(child));
    }
    (expansions, exhausted)
}

fn reference_expansion(value: PipelineValue, site: ReferenceSiteValue) -> PipelineExpansion {
    let trace_value =
        pipeline_trace_value(&value).expect("reference steps produce a semantic value");
    PipelineExpansion {
        value,
        trace: vec![(trace_value, Some(PipelineVia::ReferenceSite(site)))],
        budgeted: false,
    }
}

#[allow(clippy::too_many_arguments)]
fn call_site_expansions(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    step: &QueryStep,
    filter: &CallSiteTraversalFilter,
    cache: &mut CallTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    max_outputs: usize,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    cache_profile: &mut Option<QueryCacheProfile>,
) -> (Vec<PipelineExpansion>, bool) {
    let incoming = matches!(step, QueryStep::CallSitesTo(_));
    let result = cached_call_relation(
        analyzer,
        &declaration.unit,
        incoming,
        cache,
        budget,
        limits,
        cancellation,
        diagnostics,
        cache_profile,
    );
    let mut sites = result
        .sites
        .into_iter()
        .filter(|site| filter.proof.is_none_or(|proof| proof == site.proof))
        .collect::<Vec<_>>();
    let truncated = result.truncated || result.cancelled || sites.len() > max_outputs;
    sites.truncate(max_outputs);
    let expansions = sites
        .into_iter()
        .map(|mut site| {
            let binding = bind_call_site_arguments(analyzer, &mut site, &mut cache.bindings);
            pipeline_expansion(PipelineValue::CallSite(CallSiteValue(site, binding)))
        })
        .collect();
    (expansions, truncated)
}

#[allow(clippy::too_many_arguments)]
fn cached_call_relation(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    incoming: bool,
    cache: &mut CallTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    cache_profile: &mut Option<QueryCacheProfile>,
) -> CallRelationResult {
    let results = if incoming {
        &mut cache.incoming
    } else {
        &mut cache.outgoing
    };
    let layer = cache_profile.as_mut().map(|profile| {
        if incoming {
            &mut profile.incoming_call
        } else {
            &mut profile.outgoing_call
        }
    });
    let result = if let Some(result) = results.get(unit) {
        if let Some(layer) = layer {
            layer.record_hit(
                Some(call_relation_result_complete(result)),
                result.sites.len(),
            );
        }
        result.clone()
    } else {
        if let Some(layer) = layer {
            layer.record_miss();
        }
        let relation_limits = CallRelationLimits {
            max_files: limits
                .max_scanned_files
                .saturating_sub(budget.scanned_files)
                .min(DEFAULT_MAX_FILES),
            max_source_bytes: limits
                .max_scanned_source_bytes
                .saturating_sub(budget.scanned_source_bytes),
            max_candidates: limits
                .max_fact_nodes
                .saturating_sub(budget.fact_nodes.saturating_add(budget.examined_references)),
        };
        let result = if relation_limits.max_files == 0
            || relation_limits.max_source_bytes == 0
            || relation_limits.max_candidates == 0
        {
            push_budget_diagnostic(diagnostics, budget);
            CallRelationResult {
                truncated: true,
                ..CallRelationResult::default()
            }
        } else if incoming {
            CallRelationService::incoming_bounded(analyzer, unit, relation_limits, cancellation)
        } else {
            CallRelationService::outgoing_bounded(analyzer, unit, relation_limits, cancellation)
        };
        let budget_exhausted = charge_reference_scan(
            budget,
            limits,
            result.work.scanned_files,
            result.work.scanned_source_bytes,
            result.work.examined_candidates,
        );
        let mut result = result;
        result.truncated |= budget_exhausted;
        if budget_exhausted {
            push_budget_diagnostic(diagnostics, budget);
        }
        if let Some(profile) = cache_profile {
            let layer = if incoming {
                &mut profile.incoming_call
            } else {
                &mut profile.outgoing_call
            };
            layer.record_build(Some(call_relation_result_complete(&result)));
        }
        results.insert(unit.clone(), result.clone());
        result
    };
    let reported = if incoming {
        &mut cache.reported_incoming
    } else {
        &mut cache.reported_outgoing
    };
    if reported.insert(unit.clone()) {
        let language = crate::analyzer::common::language_for_file(unit.source()).config_label();
        diagnostics.extend(
            result
                .diagnostics
                .iter()
                .cloned()
                .map(|diagnostic| map_call_relation_diagnostic(language, diagnostic)),
        );
    }
    result
}

fn call_relation_result_complete(result: &CallRelationResult) -> bool {
    !result.truncated
        && !result.cancelled
        && result.diagnostics.iter().all(|diagnostic| {
            map_call_relation_diagnostic_code(diagnostic.code).1
                != CodeQueryDiagnosticImpact::Incomplete
        })
}

fn map_call_relation_diagnostic_code(
    code: CallRelationDiagnosticCode,
) -> (CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact) {
    match code {
        CallRelationDiagnosticCode::BudgetExhausted => (
            CodeQueryDiagnosticCode::CallRelationBudgetExhausted,
            CodeQueryDiagnosticImpact::Incomplete,
        ),
        CallRelationDiagnosticCode::ParseFailed => (
            CodeQueryDiagnosticCode::CallRelationParseFailed,
            CodeQueryDiagnosticImpact::Incomplete,
        ),
        CallRelationDiagnosticCode::CandidatesOmitted => (
            CodeQueryDiagnosticCode::CallRelationCandidatesOmitted,
            CodeQueryDiagnosticImpact::Incomplete,
        ),
        CallRelationDiagnosticCode::TargetsAmbiguous => (
            CodeQueryDiagnosticCode::CallRelationTargetsAmbiguous,
            CodeQueryDiagnosticImpact::Advisory,
        ),
        CallRelationDiagnosticCode::CandidateLimit => (
            CodeQueryDiagnosticCode::CallRelationCandidateLimit,
            CodeQueryDiagnosticImpact::Incomplete,
        ),
        CallRelationDiagnosticCode::AnalysisFailed => (
            CodeQueryDiagnosticCode::CallRelationAnalysisFailed,
            CodeQueryDiagnosticImpact::Incomplete,
        ),
    }
}

fn map_call_relation_diagnostic(
    language: &'static str,
    diagnostic: CallRelationDiagnostic,
) -> CodeQueryDiagnostic {
    debug_assert!(!diagnostic.context.is_empty());
    debug_assert_eq!(
        diagnostic.reason_kind.is_some(),
        diagnostic.code == CallRelationDiagnosticCode::AnalysisFailed
    );
    let (code, impact) = map_call_relation_diagnostic_code(diagnostic.code);
    CodeQueryDiagnostic {
        code,
        impact,
        branch: Vec::new(),
        language,
        message: diagnostic.message,
    }
}

fn call_input_expansions(
    site: &CallSiteValue,
    selector: &CallInputSelector,
) -> (Vec<PipelineExpansion>, bool) {
    let formal_binding_required =
        !matches!(selector, CallInputSelector::Receiver) && !site.0.arguments.is_empty();
    if formal_binding_required && site.1 == CallBindingStatus::Unavailable {
        return (Vec::new(), true);
    }
    let expressions = match selector {
        CallInputSelector::Receiver => site
            .0
            .receiver
            .map(|range| ExpressionSiteValue {
                call_site: site.clone(),
                range,
                input: ExpressionInput::Receiver,
            })
            .into_iter()
            .collect::<Vec<_>>(),
        CallInputSelector::ParameterIndex(index) => site
            .0
            .arguments
            .iter()
            .filter(|argument| argument.formal_index == Some(*index))
            .map(|argument| ExpressionSiteValue {
                call_site: site.clone(),
                range: argument.range,
                input: ExpressionInput::Parameter {
                    index: *index,
                    name: argument.formal_name.clone(),
                },
            })
            .collect(),
        CallInputSelector::ParameterName(name) => site
            .0
            .arguments
            .iter()
            .filter(|argument| argument.formal_name.as_deref() == Some(name))
            .filter_map(|argument| {
                Some(ExpressionSiteValue {
                    call_site: site.clone(),
                    range: argument.range,
                    input: ExpressionInput::Parameter {
                        index: argument.formal_index?,
                        name: argument.formal_name.clone(),
                    },
                })
            })
            .collect(),
    };
    let expansions = expressions
        .into_iter()
        .map(|expression| pipeline_expansion(PipelineValue::ExpressionSite(expression)))
        .collect();
    let spread_binding_incomplete =
        formal_binding_required && site.0.arguments.iter().any(|argument| argument.spread);
    (expansions, spread_binding_incomplete)
}

fn charge_reference_scan(
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    scanned_files: usize,
    scanned_source_bytes: usize,
    examined_references: usize,
) -> bool {
    budget.scanned_files = budget.scanned_files.saturating_add(scanned_files);
    budget.scanned_source_bytes = budget
        .scanned_source_bytes
        .saturating_add(scanned_source_bytes);
    budget.examined_references = budget
        .examined_references
        .saturating_add(examined_references);
    budget.scanned_files > limits.max_scanned_files
        || budget.scanned_source_bytes > limits.max_scanned_source_bytes
        || budget.fact_nodes.saturating_add(budget.examined_references) > limits.max_fact_nodes
}

fn reference_hit_matches(hit: &ReferenceHit, filter: &ReferenceTraversalFilter) -> bool {
    hit.usage_kind.included_in(filter.surface)
        && filter.proof.is_none_or(|proof| proof == hit.proof)
        && (filter.reference_kinds.is_empty()
            || hit
                .kind
                .is_some_and(|kind| filter.reference_kinds.contains(&kind)))
}

fn reference_site_value(
    analyzer: &dyn IAnalyzer,
    hit: &ReferenceHit,
    target: DeclarationValue,
    indexed: &mut IndexedDeclarations,
    known_enclosing: Option<&DeclarationValue>,
) -> (ReferenceSiteValue, bool) {
    let (enclosing, enclosing_projection_omitted) =
        if let Some(known) = known_enclosing.filter(|known| known.unit == hit.enclosing_unit) {
            (Some(known.clone()), false)
        } else if hit.enclosing_unit.is_synthetic() || hit.enclosing_unit.is_file_scope() {
            (None, false)
        } else {
            let enclosing = indexed.get(analyzer, &hit.enclosing_unit);
            let omitted = enclosing.is_none();
            (enclosing, omitted)
        };
    (
        ReferenceSiteValue {
            file: hit.file.clone(),
            range: hit.range,
            target,
            enclosing,
            usage_kind: hit.usage_kind,
            proof: hit.proof,
            reference_kind: hit.kind,
        },
        enclosing_projection_omitted,
    )
}

#[allow(clippy::too_many_arguments)]
fn outbound_reference_expansions(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    filter: &ReferenceTraversalFilter,
    indexed: &mut IndexedDeclarations,
    cache: &mut ReferenceTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    max_step_outputs: usize,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    cache_profile: &mut Option<QueryCacheProfile>,
) -> (Vec<PipelineExpansion>, bool) {
    let source_file = declaration.unit.source();
    let cache_hit = cache.outbound.contains_key(source_file);
    let mut exhausted = cache_hit && cache.outbound_exhausted.contains(source_file);
    if let Some(profile) = cache_profile {
        if cache_hit {
            profile.outbound_reference.record_hit(
                Some(!cache.outbound_incomplete.contains(source_file)),
                cache.outbound.get(source_file).map_or(0, Vec::len),
            );
        } else {
            profile.outbound_reference.record_miss();
        }
    }
    if !cache_hit {
        let diagnostic_start = diagnostics.len();
        let (hits, scan_exhausted) = scan_outbound_reference_hits(
            analyzer,
            declaration.unit.source(),
            budget,
            limits,
            max_step_outputs,
            cancellation,
            diagnostics,
        );
        exhausted = scan_exhausted;
        let cache_complete = cache_profile.as_ref().map(|_| {
            !scan_exhausted
                && !diagnostics[diagnostic_start..]
                    .iter()
                    .any(|diagnostic| diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete)
        });
        if cache_complete == Some(false) {
            cache.outbound_incomplete.insert(source_file.clone());
        }
        if scan_exhausted {
            cache.outbound_exhausted.insert(source_file.clone());
        }
        if let Some(profile) = cache_profile {
            profile.outbound_reference.record_build(cache_complete);
        }
        cache.outbound.insert(source_file.clone(), hits);
    }
    let mut sites = Vec::new();
    let mut omitted = 0usize;
    for hit in cache
        .outbound
        .get(declaration.unit.source())
        .into_iter()
        .flatten()
        .filter(|hit| hit.enclosing_unit == declaration.unit)
        .filter(|hit| reference_hit_matches(hit, filter))
    {
        let Some(target) = indexed.get(analyzer, &hit.resolved) else {
            omitted = omitted.saturating_add(1);
            continue;
        };
        let (site, enclosing_projection_omitted) =
            reference_site_value(analyzer, hit, target, indexed, Some(declaration));
        debug_assert!(
            !enclosing_projection_omitted,
            "outbound hits are filtered to the already projected input declaration"
        );
        sites.push(site);
    }
    if omitted > 0 {
        exhausted = true;
        diagnostics
            .retain(|diagnostic| diagnostic.code != CodeQueryDiagnosticCode::UsesTargetsAmbiguous);
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UsesCandidatesOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: crate::analyzer::common::language_for_file(declaration.unit.source())
                .config_label(),
            message: format!(
                "uses omitted {omitted} retained reference candidate{} from {} because the resolved target had no exact indexed range",
                if omitted == 1 { "" } else { "s" },
                declaration.unit.fq_name()
            ),
        });
    }
    sort_reference_sites(&mut sites);
    sites.dedup();
    let expansions = sites
        .into_iter()
        .map(|site| reference_expansion(PipelineValue::Declaration(site.target.clone()), site))
        .collect();
    (expansions, exhausted)
}

fn sort_reference_sites(sites: &mut [ReferenceSiteValue]) {
    sites.sort_by(|left, right| {
        rel_path_string(&left.file)
            .cmp(&rel_path_string(&right.file))
            .then_with(|| primary_range_key(&left.range).cmp(&primary_range_key(&right.range)))
            .then_with(|| left.target.unit.cmp(&right.target.unit))
            .then_with(|| {
                left.enclosing
                    .as_ref()
                    .map(|value| &value.unit)
                    .cmp(&right.enclosing.as_ref().map(|value| &value.unit))
            })
            .then_with(|| {
                left.usage_kind
                    .wire_label()
                    .cmp(right.usage_kind.wire_label())
            })
            .then_with(|| usage_proof_label(left.proof).cmp(usage_proof_label(right.proof)))
            .then_with(|| {
                left.reference_kind
                    .map(reference_kind_label)
                    .cmp(&right.reference_kind.map(reference_kind_label))
            })
    });
}

#[allow(clippy::too_many_arguments)]
fn expand_hierarchy(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    step: &QueryStep,
    traversal: HierarchyTraversal,
    indexed: &mut IndexedDeclarations,
    budget: &mut CodeQueryExecutionBudget,
    max_pipeline_rows: usize,
    omissions: &mut BTreeMap<(Language, &'static str), usize>,
) -> (Vec<PipelineExpansion>, bool) {
    let Some(provider) = analyzer.type_hierarchy_provider() else {
        record_semantic_omission(
            omissions,
            &declaration.unit,
            "its language does not provide type hierarchy analysis",
        );
        return (Vec::new(), false);
    };
    if !provider.supports_type_hierarchy(&declaration.unit) {
        record_semantic_omission(
            omissions,
            &declaration.unit,
            "input is not a supported type declaration",
        );
        return (Vec::new(), false);
    }

    let max_depth = match traversal {
        HierarchyTraversal::Direct => 1,
        HierarchyTraversal::Depth(depth) => depth.get(),
        HierarchyTraversal::Transitive => usize::MAX,
    };
    let mut queue = VecDeque::from([HierarchyWork {
        unit: declaration.unit.clone(),
        depth: 0,
        path_tail: None,
    }]);
    let mut paths = Vec::new();
    let mut expansions = Vec::new();
    let mut exhausted = false;

    while let Some(work) = queue.pop_front() {
        let mut related = match step {
            QueryStep::Supertypes(_) => provider.get_direct_ancestors(&work.unit),
            QueryStep::Subtypes(_) => provider
                .get_direct_descendants(&work.unit)
                .into_iter()
                .collect(),
            _ => unreachable!("hierarchy expansion requires a hierarchy step"),
        };
        related.sort();
        related.dedup();
        for unit in related {
            if budget.pipeline_rows >= max_pipeline_rows {
                return (expansions, true);
            }
            budget.pipeline_rows += 1;
            match hierarchy_path_contains(
                &paths,
                work.path_tail,
                &declaration.unit,
                &unit,
                &mut budget.provenance_steps,
                max_pipeline_rows,
            ) {
                Some(true) => continue,
                Some(false) => {}
                None => return (expansions, true),
            }
            let Some(value) =
                project_hierarchy_declaration(analyzer, &unit, indexed, omissions, &mut exhausted)
            else {
                continue;
            };
            let next_depth = work.depth + 1;
            if budget.provenance_steps.saturating_add(next_depth) > max_pipeline_rows {
                return (expansions, true);
            }
            budget.provenance_steps += next_depth;
            let path_tail = paths.len();
            paths.push(HierarchyPathNode {
                value: value.clone(),
                parent: work.path_tail,
            });
            expansions.push(PipelineExpansion {
                value: PipelineValue::Declaration(value),
                trace: hierarchy_trace_values(&paths, path_tail, next_depth)
                    .into_iter()
                    .map(|value| (value, None))
                    .collect(),
                budgeted: true,
            });

            if next_depth < max_depth {
                queue.push_back(HierarchyWork {
                    unit,
                    depth: next_depth,
                    path_tail: Some(path_tail),
                });
            }
        }
    }
    (expansions, exhausted)
}

fn project_hierarchy_declaration(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    indexed: &mut IndexedDeclarations,
    omissions: &mut BTreeMap<(Language, &'static str), usize>,
    exhausted: &mut bool,
) -> Option<DeclarationValue> {
    let value = indexed.get(analyzer, unit);
    if value.is_none() {
        record_semantic_omission(
            omissions,
            unit,
            "a related hierarchy declaration had no exact indexed range",
        );
        *exhausted = true;
    }
    value
}

struct HierarchyWork {
    unit: CodeUnit,
    depth: usize,
    path_tail: Option<usize>,
}

struct HierarchyPathNode {
    value: DeclarationValue,
    parent: Option<usize>,
}

fn hierarchy_path_contains(
    paths: &[HierarchyPathNode],
    mut tail: Option<usize>,
    root: &CodeUnit,
    candidate: &CodeUnit,
    work: &mut usize,
    max_work: usize,
) -> Option<bool> {
    if *work >= max_work {
        return None;
    }
    *work += 1;
    if candidate == root {
        return Some(true);
    }
    while let Some(index) = tail {
        if *work >= max_work {
            return None;
        }
        *work += 1;
        let node = &paths[index];
        if &node.value.unit == candidate {
            return Some(true);
        }
        tail = node.parent;
    }
    Some(false)
}

fn hierarchy_trace_values(
    paths: &[HierarchyPathNode],
    mut tail: usize,
    depth: usize,
) -> Vec<PipelineTraceValue> {
    let mut values = Vec::with_capacity(depth);
    loop {
        let node = &paths[tail];
        values.push(PipelineTraceValue::Declaration(node.value.clone()));
        let Some(parent) = node.parent else {
            break;
        };
        tail = parent;
    }
    values.reverse();
    values
}

fn is_type_declaration(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    unit.is_class()
        || analyzer
            .type_hierarchy_provider()
            .is_some_and(|provider| provider.supports_type_hierarchy(unit))
}

fn record_semantic_omission(
    omissions: &mut BTreeMap<(Language, &'static str), usize>,
    unit: &CodeUnit,
    reason: &'static str,
) {
    let language = crate::analyzer::common::language_for_file(unit.source());
    *omissions.entry((language, reason)).or_default() += 1;
}

fn append_semantic_omission_diagnostics(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    step: &QueryStep,
    omissions: BTreeMap<(Language, &'static str), usize>,
) {
    for ((language, reason), count) in omissions {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "{} omitted {count} input{} because {reason}",
                step.label(),
                if count == 1 { "" } else { "s" }
            ),
        });
    }
}

#[derive(Default)]
struct EnclosingDeclarationIndex {
    exact: Vec<DeclarationValue>,
    projection_omitted: bool,
}

impl EnclosingDeclarationIndex {
    fn retain(&mut self, unit: CodeUnit, ranges: impl IntoIterator<Item = Range>) {
        if unit.is_synthetic() || unit.is_file_scope() {
            return;
        }
        let mut retained = false;
        for range in ranges {
            retained = true;
            self.exact.push(DeclarationValue {
                unit: unit.clone(),
                range,
            });
        }
        if !retained {
            self.projection_omitted = true;
        }
    }

    fn sort(&mut self) {
        self.exact.sort_by(|left, right| {
            let left_span = left.range.end_byte.saturating_sub(left.range.start_byte);
            let right_span = right.range.end_byte.saturating_sub(right.range.start_byte);
            left_span
                .cmp(&right_span)
                .then_with(|| left.unit.cmp(&right.unit))
                .then_with(|| left.range.start_byte.cmp(&right.range.start_byte))
                .then_with(|| left.range.end_byte.cmp(&right.range.end_byte))
        });
    }

    fn enclosing(&self, seed_range: Range) -> Option<DeclarationValue> {
        self.exact
            .iter()
            .find(|declaration| {
                declaration.range.start_byte <= seed_range.start_byte
                    && declaration.range.end_byte >= seed_range.end_byte
            })
            .cloned()
    }
}

fn enclosing_declaration_value(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    declarations_by_file: &mut HashMap<ProjectFile, EnclosingDeclarationIndex>,
) -> (Option<DeclarationValue>, bool) {
    let fact = seed.facts.node(seed.fact_match.node);
    let span = fact.span();
    let seed_range = Range {
        start_byte: span.start_byte,
        end_byte: span.end_byte,
        start_line: fact.range.start_line,
        end_line: fact.range.end_line,
    };
    let declarations = declarations_by_file
        .entry(seed.file.clone())
        .or_insert_with(|| {
            let mut declarations = EnclosingDeclarationIndex::default();
            for unit in analyzer.get_declarations(&seed.file) {
                declarations.retain(unit.clone(), analyzer.ranges_of(&unit));
            }
            declarations.sort();
            declarations
        });
    (
        declarations.enclosing(seed_range),
        declarations.projection_omitted,
    )
}

fn pipeline_trace_value(value: &PipelineValue) -> Option<PipelineTraceValue> {
    match value {
        PipelineValue::StructuralMatch(_) => None,
        PipelineValue::Declaration(declaration) => {
            Some(PipelineTraceValue::Declaration(declaration.clone()))
        }
        PipelineValue::File(file) => Some(PipelineTraceValue::File(file.clone())),
        PipelineValue::ReferenceSite(site) => Some(PipelineTraceValue::ReferenceSite(site.clone())),
        PipelineValue::CallSite(site) => Some(PipelineTraceValue::CallSite(site.clone())),
        PipelineValue::ExpressionSite(site) => {
            Some(PipelineTraceValue::ExpressionSite(site.clone()))
        }
        PipelineValue::ReceiverAnalysis(value) => {
            Some(PipelineTraceValue::ReceiverAnalysis(value.clone()))
        }
    }
}

fn insert_pipeline_row(
    rows: &mut Vec<PipelineRow>,
    indexes: &mut HashMap<PipelineKey, usize>,
    value: PipelineValue,
    mut traces: Vec<PipelineTrace>,
    provenance_truncated: bool,
) {
    let key = value.key();
    if let Some(&index) = indexes.get(&key) {
        let row = &mut rows[index];
        let remaining = MAX_PROVENANCE_TRACES.saturating_sub(row.traces.len());
        if traces.len() > remaining {
            row.provenance_truncated = true;
        }
        row.traces.extend(traces.into_iter().take(remaining));
        row.provenance_truncated |= provenance_truncated;
        return;
    }

    let truncated = provenance_truncated || traces.len() > MAX_PROVENANCE_TRACES;
    traces.truncate(MAX_PROVENANCE_TRACES);
    indexes.insert(key, rows.len());
    rows.push(PipelineRow {
        value,
        traces,
        provenance_truncated: truncated,
    });
}

fn render_pipeline_item(
    analyzer: &dyn IAnalyzer,
    row: PipelineRow,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultItem {
    let provenance = row
        .traces
        .iter()
        .map(|trace| render_provenance(analyzer, trace, detail, cache))
        .collect();
    let value = match row.value {
        PipelineValue::StructuralMatch(seed) => CodeQueryResultValue::StructuralMatch {
            value: render_match(
                analyzer,
                seed.language,
                &seed.file,
                &seed.facts,
                &seed.fact_match,
                detail,
                cache,
            ),
        },
        PipelineValue::Declaration(declaration) => CodeQueryResultValue::Declaration {
            value: render_declaration(analyzer, &declaration, detail, cache),
        },
        PipelineValue::File(file) => CodeQueryResultValue::File {
            value: render_file(&file),
        },
        PipelineValue::ReferenceSite(site) => CodeQueryResultValue::ReferenceSite {
            value: Box::new(render_reference_site(analyzer, &site, detail, cache)),
        },
        PipelineValue::CallSite(site) => CodeQueryResultValue::CallSite {
            value: Box::new(render_call_site(analyzer, &site, detail, cache)),
        },
        PipelineValue::ExpressionSite(site) => CodeQueryResultValue::ExpressionSite {
            value: Box::new(render_expression_site(analyzer, &site, cache)),
        },
        PipelineValue::ReceiverAnalysis(value) => CodeQueryResultValue::ReceiverAnalysis {
            value: Box::new(render_receiver_analysis(analyzer, &value, detail, cache)),
        },
    };
    CodeQueryResultItem {
        value,
        provenance,
        provenance_truncated: row.provenance_truncated,
    }
}

fn render_provenance(
    analyzer: &dyn IAnalyzer,
    trace: &PipelineTrace,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryProvenance {
    CodeQueryProvenance {
        branch: trace.branch.clone(),
        seed: render_seed_ref(&trace.seed, detail),
        steps: trace
            .steps
            .iter()
            .map(|step| CodeQueryProvenanceStep {
                op: step.op.label(),
                result: match &step.value {
                    PipelineTraceValue::Declaration(declaration) => {
                        render_declaration_ref(analyzer, declaration, detail, cache)
                    }
                    PipelineTraceValue::File(file) => render_file_ref(file),
                    PipelineTraceValue::ReferenceSite(site) => {
                        render_reference_site_ref(analyzer, site, detail, cache)
                    }
                    PipelineTraceValue::CallSite(site) => {
                        render_call_site_ref(analyzer, site, cache)
                    }
                    PipelineTraceValue::ExpressionSite(site) => {
                        render_expression_site_ref(analyzer, site, cache)
                    }
                    PipelineTraceValue::ReceiverAnalysis(value) => {
                        render_receiver_analysis_ref(analyzer, value, cache)
                    }
                },
                via: step.via.as_ref().map(|via| match via {
                    PipelineVia::ReferenceSite(site) => {
                        render_reference_site_ref(analyzer, site, detail, cache)
                    }
                    PipelineVia::CallSite(site) => render_call_site_ref(analyzer, site, cache),
                }),
            })
            .collect(),
    }
}

fn render_seed_ref(seed: &SeedMatch, detail: CodeQueryResultDetail) -> CodeQueryResultRef {
    let fact = seed.facts.node(seed.fact_match.node);
    let full = !detail.is_compact();
    let path = rel_path_string(&seed.file);
    CodeQueryResultRef::StructuralMatch {
        id: full.then(|| match_id(&path, fact.kind.label(), fact.span())),
        path,
        kind: fact.kind.label(),
        start_line: fact.range.start_line,
        end_line: fact.range.end_line,
        node_range: full.then(|| range_for_span(&seed.facts, fact.span())),
    }
}

fn render_declaration_ref(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let path = rel_path_string(declaration.unit.source());
    let fq_name = declaration.unit.fq_name();
    let kind = declaration.unit.kind().display_lowercase();
    let full = !detail.is_compact();
    CodeQueryResultRef::Declaration {
        id: full.then(|| declaration_id(&path, kind, &fq_name, declaration.range)),
        path,
        kind,
        fq_name,
        start_line: declaration.range.start_line,
        end_line: declaration.range.end_line,
        node_range: full
            .then(|| cache.range_for_declaration(analyzer, declaration))
            .flatten(),
    }
}

fn render_file_ref(file: &ProjectFile) -> CodeQueryResultRef {
    CodeQueryResultRef::File {
        path: rel_path_string(file),
    }
}

fn render_reference_site_ref(
    analyzer: &dyn IAnalyzer,
    site: &ReferenceSiteValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let target_path = rel_path_string(site.target.unit.source());
    let target_fq_name = site.target.unit.fq_name();
    let target_kind = site.target.unit.kind().display_lowercase();
    CodeQueryResultRef::ReferenceSite {
        path: rel_path_string(&site.file),
        range: render_reference_range(analyzer, site, cache),
        target_id: (!detail.is_compact()).then(|| {
            declaration_id(
                &target_path,
                target_kind,
                &target_fq_name,
                site.target.range,
            )
        }),
        target_fq_name,
        usage_kind: (site.usage_kind != UsageHitKind::Reference)
            .then(|| site.usage_kind.wire_label()),
        proof: usage_proof_label(site.proof),
        reference_kind: site.reference_kind.map(reference_kind_label),
    }
}

fn render_call_site_ref(
    analyzer: &dyn IAnalyzer,
    site: &CallSiteValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    CodeQueryResultRef::CallSite {
        path: rel_path_string(&site.0.file),
        range: render_source_range(analyzer, &site.0.file, &site.0.range, cache),
        caller_fq_name: site.0.caller.fq_name(),
        callee_fq_name: site.0.callee.fq_name(),
        proof: usage_proof_label(site.0.proof),
    }
}

fn render_expression_site_ref(
    analyzer: &dyn IAnalyzer,
    site: &ExpressionSiteValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let (input_kind, parameter_index, parameter_name) = expression_input_parts(&site.input);
    CodeQueryResultRef::ExpressionSite {
        path: rel_path_string(&site.call_site.0.file),
        range: render_source_range(analyzer, &site.call_site.0.file, &site.range, cache),
        input_kind,
        parameter_index,
        parameter_name,
    }
}

fn render_receiver_analysis_ref(
    analyzer: &dyn IAnalyzer,
    value: &ReceiverAnalysisValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    CodeQueryResultRef::ReceiverAnalysis {
        path: rel_path_string(&value.report.site.file),
        range: render_source_range(
            analyzer,
            &value.report.site.file,
            &value.report.site.range,
            cache,
        ),
        analysis_kind: value.report.operation.as_str(),
        outcome: receiver_query_outcome_label(&value.report.analysis),
        capture: value.capture.clone(),
    }
}

fn render_declaration(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryDeclaration {
    let path = rel_path_string(declaration.unit.source());
    let fq_name = declaration.unit.fq_name();
    let kind = declaration.unit.kind().display_lowercase();
    let full = !detail.is_compact();
    let signature = declaration
        .unit
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.signatures_of(&declaration.unit).into_iter().next());
    CodeQueryDeclaration {
        id: full.then(|| declaration_id(&path, kind, &fq_name, declaration.range)),
        path,
        language: crate::analyzer::common::language_for_file(declaration.unit.source())
            .config_label(),
        kind,
        fq_name,
        start_line: declaration.range.start_line,
        end_line: declaration.range.end_line,
        signature,
        node_range: full
            .then(|| cache.range_for_declaration(analyzer, declaration))
            .flatten(),
    }
}

fn render_file(file: &ProjectFile) -> CodeQueryFile {
    CodeQueryFile {
        path: rel_path_string(file),
        language: crate::analyzer::common::language_for_file(file).config_label(),
    }
}

fn render_reference_site(
    analyzer: &dyn IAnalyzer,
    site: &ReferenceSiteValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryReferenceSite {
    CodeQueryReferenceSite {
        path: rel_path_string(&site.file),
        language: crate::analyzer::common::language_for_file(&site.file).config_label(),
        range: render_reference_range(analyzer, site, cache),
        target: render_declaration(analyzer, &site.target, detail, cache),
        enclosing_declaration: site
            .enclosing
            .as_ref()
            .map(|declaration| render_declaration(analyzer, declaration, detail, cache)),
        usage_kind: site.usage_kind.wire_label(),
        proof: usage_proof_label(site.proof),
        reference_kind: site.reference_kind.map(reference_kind_label),
    }
}

fn render_call_site(
    analyzer: &dyn IAnalyzer,
    site: &CallSiteValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryCallSite {
    let caller = declaration_value_for_unit(analyzer, &site.0.caller, site.0.range);
    let callee = declaration_value_for_unit(analyzer, &site.0.callee, site.0.callee_range);
    CodeQueryCallSite {
        path: rel_path_string(&site.0.file),
        language: crate::analyzer::common::language_for_file(&site.0.file).config_label(),
        range: render_source_range(analyzer, &site.0.file, &site.0.range, cache),
        callee_range: render_source_range(analyzer, &site.0.file, &site.0.callee_range, cache),
        caller: render_declaration(analyzer, &caller, detail, cache),
        callee: render_declaration(analyzer, &callee, detail, cache),
        call_kind: call_syntax_kind_label(site.0.kind),
        proof: usage_proof_label(site.0.proof),
        receiver: site
            .0
            .receiver
            .as_ref()
            .map(|range| render_source_range(analyzer, &site.0.file, range, cache)),
        arguments: site
            .0
            .arguments
            .iter()
            .map(|argument| CodeQueryCallArgument {
                range: render_source_range(analyzer, &site.0.file, &argument.range, cache),
                name: argument.name.clone(),
                position: argument.position,
                formal_index: argument.formal_index,
                formal_name: argument.formal_name.clone(),
                variadic: argument.variadic,
                spread: argument.spread,
            })
            .collect(),
    }
}

fn render_expression_site(
    analyzer: &dyn IAnalyzer,
    site: &ExpressionSiteValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryExpressionSite {
    let file = &site.call_site.0.file;
    let text = cache
        .coordinates_for(file, || analyzer.indexed_source(file))
        .and_then(|coordinates| {
            coordinates
                .source
                .get(site.range.start_byte..site.range.end_byte)
        })
        .map(snippet)
        .unwrap_or_default();
    let (input_kind, parameter_index, parameter_name) = expression_input_parts(&site.input);
    CodeQueryExpressionSite {
        path: rel_path_string(file),
        language: crate::analyzer::common::language_for_file(file).config_label(),
        range: render_source_range(analyzer, file, &site.range, cache),
        text,
        input_kind,
        parameter_index,
        parameter_name,
        caller_fq_name: site.call_site.0.caller.fq_name(),
        callee_fq_name: site.call_site.0.callee.fq_name(),
        call_range: render_source_range(analyzer, file, &site.call_site.0.range, cache),
    }
}

fn render_receiver_analysis(
    analyzer: &dyn IAnalyzer,
    value: &ReceiverAnalysisValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryReceiverAnalysis {
    let fallback = value.report.site.range;
    let (outcome, values, member_targets, reason, limit) = match &value.report.analysis {
        ReceiverQueryAnalysis::Values(outcome) => {
            let rendered = outcome
                .values()
                .into_iter()
                .flatten()
                .map(|value| render_receiver_value(analyzer, value, fallback, detail, cache))
                .collect();
            let (label, reason, limit) = receiver_outcome_metadata(outcome);
            (label, rendered, Vec::new(), reason, limit)
        }
        ReceiverQueryAnalysis::MemberTargets(outcome) => {
            let rendered = outcome
                .values()
                .into_iter()
                .flatten()
                .map(|unit| {
                    let declaration = declaration_value_for_unit(analyzer, unit, fallback);
                    render_declaration(analyzer, &declaration, detail, cache)
                })
                .collect();
            let (label, reason, limit) = receiver_outcome_metadata(outcome);
            (label, Vec::new(), rendered, reason, limit)
        }
    };
    CodeQueryReceiverAnalysis {
        analysis_kind: value.report.operation.as_str(),
        path: rel_path_string(&value.report.site.file),
        language: value.report.site.language.config_label(),
        range: render_source_range(
            analyzer,
            &value.report.site.file,
            &value.report.site.range,
            cache,
        ),
        text: snippet(&value.report.site.text),
        input_kind: value.report.site.syntax_kind.clone(),
        capture: value.capture.clone(),
        outcome,
        values,
        member_targets,
        reason,
        limit,
    }
}

fn render_receiver_value(
    analyzer: &dyn IAnalyzer,
    value: &ReceiverValue,
    fallback: Range,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryReceiverValue {
    let declaration = |unit: &CodeUnit, cache: &mut PipelineRenderCache| {
        let value = declaration_value_for_unit(analyzer, unit, fallback);
        render_declaration(analyzer, &value, detail, cache)
    };
    match value {
        ReceiverValue::AllocationSite { ty, file, range } => {
            CodeQueryReceiverValue::AllocationSite {
                type_declaration: declaration(ty, cache),
                allocation_site: CodeQuerySourceSite {
                    path: rel_path_string(file),
                    range: render_source_range(analyzer, file, range, cache),
                },
            }
        }
        ReceiverValue::InstanceType(unit) => CodeQueryReceiverValue::InstanceType {
            declaration: declaration(unit, cache),
        },
        ReceiverValue::ClassOrStaticObject(unit) => CodeQueryReceiverValue::ClassOrStaticObject {
            declaration: declaration(unit, cache),
        },
        ReceiverValue::ModuleOrExportObject(unit) => CodeQueryReceiverValue::ModuleOrExportObject {
            declaration: declaration(unit, cache),
        },
        ReceiverValue::CurrentReceiver(unit) => CodeQueryReceiverValue::CurrentReceiver {
            declaration: declaration(unit, cache),
        },
        ReceiverValue::FactoryReturn { factory, value } => CodeQueryReceiverValue::FactoryReturn {
            factory: declaration(factory, cache),
            returned_value: Box::new(render_receiver_value(
                analyzer, value, fallback, detail, cache,
            )),
        },
    }
}

fn receiver_query_outcome_label(analysis: &ReceiverQueryAnalysis) -> &'static str {
    match analysis {
        ReceiverQueryAnalysis::Values(outcome) => receiver_outcome_metadata(outcome).0,
        ReceiverQueryAnalysis::MemberTargets(outcome) => receiver_outcome_metadata(outcome).0,
    }
}

fn receiver_outcome_metadata<T>(
    outcome: &ReceiverAnalysisOutcome<T>,
) -> (&'static str, Option<&'static str>, Option<&'static str>) {
    match outcome {
        ReceiverAnalysisOutcome::Precise(_) => ("precise", None, None),
        ReceiverAnalysisOutcome::Ambiguous(_) => ("ambiguous", None, None),
        ReceiverAnalysisOutcome::Unknown => ("unknown", None, None),
        ReceiverAnalysisOutcome::Unsupported { reason } => ("unsupported", Some(*reason), None),
        ReceiverAnalysisOutcome::ExceededBudget { limit } => {
            ("exceeded_budget", None, Some(*limit))
        }
    }
}

fn expression_input_parts(
    input: &ExpressionInput,
) -> (&'static str, Option<usize>, Option<String>) {
    match input {
        ExpressionInput::Receiver => ("receiver", None, None),
        ExpressionInput::Parameter { index, name } => ("parameter", Some(*index), name.clone()),
    }
}

fn declaration_value_for_unit(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    fallback: Range,
) -> DeclarationValue {
    DeclarationValue {
        unit: unit.clone(),
        range: analyzer
            .ranges_of(unit)
            .into_iter()
            .min_by_key(primary_range_key)
            .unwrap_or(fallback),
    }
}

fn call_syntax_kind_label(kind: CallSyntaxKind) -> &'static str {
    match kind {
        CallSyntaxKind::Function => "function",
        CallSyntaxKind::Method => "method",
        CallSyntaxKind::Constructor => "constructor",
        CallSyntaxKind::Super => "super",
    }
}

fn render_reference_range(
    analyzer: &dyn IAnalyzer,
    site: &ReferenceSiteValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryRange {
    render_source_range(analyzer, &site.file, &site.range, cache)
}

fn render_source_range(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    range: &Range,
    cache: &mut PipelineRenderCache,
) -> CodeQueryRange {
    cache
        .coordinates_for(file, || analyzer.indexed_source(file))
        .map(|coordinates| {
            range_for_offsets(
                &coordinates.source,
                &coordinates.line_starts,
                range.start_byte,
                range.end_byte,
            )
        })
        .unwrap_or(CodeQueryRange {
            start_line: range.start_line,
            start_column: 1,
            end_line: range.end_line,
            end_column: 1,
        })
}

fn declaration_id(path: &str, kind: &str, fq_name: &str, range: Range) -> String {
    format!(
        "{path}:{kind}:{fq_name}:{}-{}",
        range.start_byte, range.end_byte
    )
}

fn range_for_offsets(
    source: &str,
    line_starts: &[usize],
    start_byte: usize,
    end_byte: usize,
) -> CodeQueryRange {
    let (start_line, start_column) = line_column_for_offset(source, line_starts, start_byte);
    let (end_line, end_column) = line_column_for_offset(source, line_starts, end_byte);
    CodeQueryRange {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

fn provider_supports_feature(
    provider: &dyn super::StructuralSearchProvider,
    feature: QueryFeature,
) -> bool {
    match feature {
        QueryFeature::Kind(kind) => provider.structural_supports_kind(kind),
        QueryFeature::Role(role) => provider.structural_supports_role(role),
    }
}

fn push_budget_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
) {
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::ExecutionBudgetExhausted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: format!(
            "query_code execution budget exhausted after scanning {} files, {} bytes, {} facts, and examining {} references; refine the query with where, languages, kind/name anchors, or a narrower pattern",
            budget.scanned_files,
            budget.scanned_source_bytes,
            budget.fact_nodes,
            budget.examined_references
        ),
    });
}

fn push_pipeline_budget_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
) {
    if diagnostics.iter().any(|diagnostic| {
        diagnostic.branch.is_empty()
            && diagnostic.code == CodeQueryDiagnosticCode::PipelineBudgetExhausted
    }) {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::PipelineBudgetExhausted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: format!(
            "query_code pipeline budget exhausted after producing {} seed and edge rows; refine the match, where, or languages filters",
            budget.pipeline_rows
        ),
    });
}

fn push_import_graph_budget_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    graph: &RequestLocalDirectImportGraph,
) {
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::ImportGraphBudgetExhausted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: format!(
            "query_code import graph budget exhausted after resolving {} files and {} direct edges; import traversal results are partial",
            graph.resolved_files(), graph.resolved_edges()
        ),
    });
}

fn push_truncation_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
    limit: usize,
) {
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::ResultLimitReached,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: format!(
            "query_code returned the first {limit} results after scanning {} files, {} bytes, {} facts, and examining {} references; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern",
            budget.scanned_files,
            budget.scanned_source_bytes,
            budget.fact_nodes,
            budget.examined_references
        ),
    });
}

fn should_report_broad_query(
    plan: &QueryPlan,
    query: &CodeQuerySeed,
    budget: &CodeQueryExecutionBudget,
    truncated: bool,
) -> bool {
    !plan.has_source_anchors()
        && query.where_globs.is_empty()
        && query.languages.is_empty()
        && (truncated || budget.scanned_files >= BROAD_QUERY_SCANNED_FILE_HINT_THRESHOLD)
}

fn push_broad_query_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
) {
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::BroadQuery,
        impact: CodeQueryDiagnosticImpact::Advisory,
        branch: Vec::new(),
        language: "workspace",
        message: format!(
            "broad unanchored query_code query scanned {} files, {} bytes, {} facts, and examined {} references; add where, languages, exact name predicates, or a more specific pattern to reduce work and output",
            budget.scanned_files,
            budget.scanned_source_bytes,
            budget.fact_nodes,
            budget.examined_references
        ),
    });
}

fn file_matches_globs(file: &ProjectFile, query: &CodeQuerySeed) -> bool {
    if query.where_globs.is_empty() {
        return true;
    }
    let rel_path = rel_path_string(file);
    query.where_globs.iter().any(|glob| glob.matches(&rel_path))
}

fn render_match(
    analyzer: &dyn IAnalyzer,
    language: Language,
    file: &ProjectFile,
    facts: &FileFacts,
    fact_match: &FactMatch,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryMatch {
    let fact = facts.node(fact_match.node);
    let full_detail = matches!(detail, CodeQueryResultDetail::Full);
    let path = rel_path_string(file);
    let captures = fact_match
        .captures
        .iter()
        .map(|capture| CodeQueryCapture {
            name: capture.name.clone(),
            text: snippet(capture.span.text(facts.source())),
            start_line: facts.line_of_byte(capture.span.start_byte),
            range: full_detail.then(|| range_for_span(facts, capture.span)),
            kind: if full_detail {
                capture.kind.map(|kind| kind.label())
            } else {
                None
            },
        })
        .collect();
    let node_range = full_detail.then(|| range_for_span(facts, fact.span()));
    let decorator_spans: Vec<_> = if full_detail {
        facts
            .role_targets(fact_match.node, Role::Decorator)
            .map(|target| target.span)
            .collect()
    } else {
        Vec::new()
    };
    let decorator_ranges = decorator_spans
        .iter()
        .map(|&span| range_for_span(facts, span))
        .collect::<Vec<_>>();
    let decorated_range = if full_detail && !decorator_spans.is_empty() {
        let mut decorated = fact.span();
        for span in decorator_spans {
            decorated.start_byte = decorated.start_byte.min(span.start_byte);
            decorated.end_byte = decorated.end_byte.max(span.end_byte);
        }
        Some(range_for_span(facts, decorated))
    } else {
        None
    };
    CodeQueryMatch {
        id: full_detail.then(|| match_id(&path, fact.kind.label(), fact.span())),
        path,
        language: language.config_label(),
        kind: fact.kind.label(),
        start_line: fact.range.start_line,
        end_line: fact.range.end_line,
        text: snippet(fact.span().text(facts.source())),
        node_range,
        decorated_range,
        decorator_ranges,
        captures,
        enclosing_symbol: cache
            .enclosing_unit_for_lines(analyzer, file, fact.range.start_line, fact.range.end_line)
            .map(|code_unit| code_unit.fq_name()),
    }
}

fn match_id(path: &str, kind: &str, span: Span) -> String {
    format!("{path}:{kind}:{}-{}", span.start_byte, span.end_byte)
}

fn range_for_span(facts: &FileFacts, span: Span) -> CodeQueryRange {
    let (start_line, start_column) = facts.line_column_of_byte(span.start_byte);
    let (end_line, end_column) = facts.line_column_of_byte(span.end_byte);
    CodeQueryRange {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

/// First line of `text`, truncated to [`SNIPPET_MAX_CHARS`] on a char
/// boundary, with an ellipsis when anything was dropped.
fn snippet(text: &str) -> String {
    let first_line = text.lines().next().unwrap_or("");
    let mut end = first_line.len().min(SNIPPET_MAX_CHARS);
    while !first_line.is_char_boundary(end) {
        end -= 1;
    }
    let mut result = first_line[..end].to_string();
    if end < text.len() {
        result.push('…');
    }
    result
}
