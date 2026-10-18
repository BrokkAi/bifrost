//! Analyzer-owned call relations shared by query traversal and LSP call hierarchy.

use std::sync::{Arc, Mutex};

/// One caller file's speculative native answers, keyed by the exact callee
/// byte range of each retained reverse site. The owning language's
/// `LanguageSupport::prefetch_reverse_call_targets` fills these before the
/// demanding walk asks, so this stays language-neutral.
type PrefetchedOutcome = (
    (usize, usize),
    CallTargetLookupOutcome,
    Option<CompletedExpansion>,
);

pub(crate) struct PrefetchedCallFile {
    pub(crate) source_identity: ContentIdentity,
    pub(crate) outcomes: Vec<PrefetchedOutcome>,
    pub(crate) work: CallRelationWork,
    pub(crate) native_execution_delta: usize,
}

use super::{
    FuzzyResult, UsageFinder, UsageHit, UsageHitKind, UsageProof, UsageProofAuthority,
    UsageQueryCompletion, proof_rank,
};
use crate::analyzer::common::language_for_file;
use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::languages::{
    ExternalCalleeFileEvidence, ExternalCalleeSite, language_support,
};
use crate::analyzer::lexical_definitions::{
    FormalParameterLayout, PythonMethodBinding, formal_parameter_slots,
};
use crate::analyzer::read_ledger::ReadLedger;
use crate::analyzer::semantic::{ContentIdentity, ResolverOwnedExternalCalleeIdentity};
use crate::analyzer::structural::FileFacts;
use crate::analyzer::structural::resolution::BoundaryStatus;
use crate::analyzer::usages::call_binding::{OrdinaryFormalSlots, canonical_parameter_name};
use crate::analyzer::usages::call_shape::call_shapes_in_file;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, CallApplicationKind, CallSiteSyntax, CallSyntaxKind,
    CallTargetLookupOutcome, DefinitionLookupOutcome, DefinitionLookupRequest,
    DefinitionLookupStatus, ExactCallReference, ExactCallReferenceGap, ExactExternalCallProof,
    GO_MODELED_PACKAGE_CALL_NOT_APPLICABLE_DIAGNOSTIC_KIND, GoTypedSelectorTarget,
    IMPORT_BINDINGS_TRUNCATED_DIAGNOSTIC, LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
    PARTIAL_IMPORT_BOUNDARY_DIAGNOSTIC, PARTIAL_IMPORT_UNRESOLVED_DIAGNOSTIC,
    call_reference_ranges_in_tree, call_reference_requires_point_lookup,
    call_site_syntax_for_reference, exact_call_reference_for_call, go_typed_selector_target,
    is_adjudicated_answer_diagnostic_kind, parse_tree_for_language, range_is_call_keyword_label,
    resolve_call_target_batch_with_source, resolve_definition_batch_with_source,
};
use crate::analyzer::usages::python_class_hierarchy::PythonHierarchyOutcome;
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, DispatchExtensibility, IAnalyzer, Language, ProjectFile,
    QueryScope, Range, capture_query_reads, replay_query_reads,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::query_token::QueryToken;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallArgument {
    pub range: Range,
    pub name: Option<String>,
    pub position: Option<usize>,
    pub formal_index: Option<usize>,
    pub formal_name: Option<String>,
    pub variadic: bool,
    pub spread: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallSite {
    pub file: ProjectFile,
    pub range: Range,
    pub callee_range: Range,
    pub caller: CodeUnit,
    pub callee: CodeUnit,
    pub kind: CallSyntaxKind,
    pub proof: UsageProof,
    pub receiver: Option<Range>,
    pub arguments: Vec<CallArgument>,
}

/// One exact source-backed call expression. The range covers the complete
/// call expression; the dispatch service derives the precise callee reference
/// through tree-sitter before invoking definition resolution.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg(test)]
pub(crate) struct ExactCallLocation {
    pub(crate) file: ProjectFile,
    pub(crate) call_span: Range,
}

/// One workspace definition retained by exact call-site dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CallDispatchTarget {
    pub(crate) definition: CodeUnit,
    pub(crate) proof: UsageProof,
    /// The unique incomplete Java source candidate came from the selected
    /// native operation itself. This provenance permits candidate-local
    /// argument rows while the dispatch frontier remains open.
    pub(crate) native_incomplete_source_reason: Option<Box<str>>,
}

/// Keep exact source identity after location-first dispatch. C/C++ declaration
/// and body candidates are related by the structured include graph in the
/// definition resolver; external linkage alone is not a workspace-global
/// identity because one workspace can contain several independently linked
/// binaries or modules.
pub(crate) fn call_dispatch_equivalence_source(
    _analyzer: &dyn IAnalyzer,
    definition: &CodeUnit,
) -> Option<ProjectFile> {
    Some(definition.source().clone())
}

/// A dispatch arm that has no workspace procedure target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CallDispatchBoundaryKind {
    /// Resolution proved that the referenced declaration crosses the indexed
    /// workspace boundary, but cannot name an external body. The dotted callee
    /// text is retained when the resolver produced one, so a fully-qualified
    /// unmaterialized external callee can still bind an activated summary (#1978).
    External {
        callee_text: Option<Box<str>>,
        /// Canonical Java owner proven by the definition resolver to be the
        /// call's type qualifier rather than a runtime receiver. Other
        /// languages and value receivers leave this absent.
        normalized_static_owner: Option<Box<str>>,
        /// Resolver-owned external owner/member identity. This is weaker than
        /// an exact call-shape proof and never mints a semantic target.
        external_callee_identity: Option<ResolverOwnedExternalCalleeIdentity>,
    },
    /// The exact resolver status is retained rather than collapsed into an
    /// empty target list.
    Unresolved(DefinitionLookupStatus),
    /// Resolution remains unproven, but the same structured resolver outcome
    /// retained a canonical callee identity that semantic lowering may be able
    /// to address with an authored model. This never upgrades the status: if
    /// the semantic call shape cannot mint the canonical target, lowering
    /// falls back to the ordinary targetless unresolved boundary.
    UnresolvedWithTarget {
        status: DefinitionLookupStatus,
        callee_text: Box<str>,
        normalized_static_owner: Option<Box<str>>,
    },
    /// A source-backed Go receiver proves an interface selector, but neither
    /// the module census nor an unclosed external interface is exhaustive.
    UnresolvedReason(Box<str>),
    /// Structured declaration/body evidence exists, but no build graph proves
    /// that the retained C/C++ body belongs to this call's link unit.
    UnprovenTargetIdentity,
    /// A candidate set was retained only up to the supplied target bound.
    Truncated,
}

/// Typed result of resolving one exact call expression.
///
/// `cancelled`, `budget_exhausted`, and `truncated` are deliberately
/// independent. A request can, for example, retain a truncated candidate set
/// because its target budget was exhausted without being cancelled.
#[derive(Debug, Clone, Default)]
pub(crate) struct CallDispatchLookup {
    pub(crate) status: Option<DefinitionLookupStatus>,
    /// The refined external-root evidence for a
    /// [`DefinitionLookupStatus::UnresolvableImportBoundary`] status, shared
    /// with the resolution trace (#1474). `None` for every other status.
    pub(crate) boundary: Option<BoundaryStatus>,
    pub(crate) targets: Vec<CallDispatchTarget>,
    pub(crate) boundaries: Vec<CallDispatchBoundaryKind>,
    /// The exact resolver proved that a no-definition answer is intentional
    /// (for example a local binder), rather than failing to reach a target.
    pub(crate) adjudicated_no_target: bool,
    /// The exact resolver proved this call expression is not an applicable
    /// call at all: its callee names a declaration an activated Go model
    /// publishes, and positive declaration facts rule out a callable with
    /// this argument list. In Go that is a conversion to a modeled type
    /// (`http.HandlerFunc(f)`), so the call expression has no callee and
    /// dispatch is a complete empty target set, not an unreached one.
    pub(crate) adjudicated_non_callable: bool,
    /// Receiver-application evidence produced by the same exact language
    /// resolution that populated the dispatch boundaries.
    pub(crate) call_application: CallApplicationKind,
    /// Exact call-site dispatch extensibility retained from that same
    /// resolution pass. A language can derive it from the selected declaration
    /// or a nonvirtual receiver origin. Absence is unknown, never implicitly
    /// open or closed.
    pub(crate) dispatch_extensibility: Option<DispatchExtensibility>,
    /// Resolver-owned external identity and applicable call shape. Consumers
    /// that mint an external model key must use this proof rather than combine
    /// the boundary spelling with independently lowered receiver or arity
    /// facts.
    pub(crate) exact_external_call: Option<ExactExternalCallProof>,
    /// The exact Go receiver type fact identifies an interface. A later
    /// workspace-oracle points-to query may close this receiver over its
    /// exhaustive concrete allocation set.
    pub(crate) go_interface_receiver: bool,
    pub(crate) go_selector_member: Option<String>,
    pub(crate) truncated: bool,
    pub(crate) cancelled: bool,
    pub(crate) budget_exhausted: bool,
    pub(crate) diagnostics: Vec<String>,
    pub(crate) work: CallRelationWork,
}

/// One external callable selected by exact call-site dispatch, including the
/// call shape that the language resolver proved for it.
///
/// This is the cross-crate view used by structural selectors. It can only be
/// produced when dispatch has one named external boundary and an exact
/// resolver-owned call proof; incomplete or ambiguous lookups remain absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverOwnedExternalCallDispatch {
    identity: ResolverOwnedExternalCalleeIdentity,
    parameter_count: u32,
    has_receiver: bool,
}

impl ResolverOwnedExternalCallDispatch {
    pub fn identity(&self) -> &ResolverOwnedExternalCalleeIdentity {
        &self.identity
    }

    pub const fn parameter_count(&self) -> u32 {
        self.parameter_count
    }

    pub const fn has_receiver(&self) -> bool {
        self.has_receiver
    }
}

impl CallDispatchLookup {
    fn resolver_owned_external_call(&self) -> Option<ResolverOwnedExternalCallDispatch> {
        if self.status != Some(DefinitionLookupStatus::Resolved)
            || !self.targets.is_empty()
            || self.boundaries.len() != 1
            || self.cancelled
            || self.truncated
            || self.budget_exhausted
        {
            return None;
        }
        let [
            CallDispatchBoundaryKind::External {
                external_callee_identity: Some(identity),
                ..
            },
        ] = self.boundaries.as_slice()
        else {
            return None;
        };
        let proof = self.exact_external_call.as_ref()?;
        Some(ResolverOwnedExternalCallDispatch {
            identity: identity.clone(),
            parameter_count: proof.parameter_count(),
            has_receiver: proof.has_receiver(),
        })
    }
}

/// Inputs for a language-owned exact-call dispatch extension. The framework
/// supplies the parsed source call; the registered language adapter decides
/// whether it has a structured special case before generic reference lookup.
pub(crate) struct CallDispatchLanguageRequest<'a> {
    pub(crate) analyzer: &'a dyn IAnalyzer,
    pub(crate) token: QueryToken<'a>,
    pub(crate) file: &'a ProjectFile,
    pub(crate) source: &'a str,
    pub(crate) tree: &'a tree_sitter::Tree,
    pub(crate) call_span: &'a Range,
    pub(crate) cancellation: Option<&'a CancellationToken>,
    pub(crate) work: CallRelationWork,
}

use brokk_bifrost_core::analyzer::structural::spec::{EmbeddedSyntaxForest, EmbeddedSyntaxStop};

/// File-local syntax authority shared by serial and batched exact dispatch.
struct CallDispatchSyntax {
    primary: tree_sitter::Tree,
    forest: EmbeddedSyntaxForest,
}

impl CallDispatchSyntax {
    fn parse(
        file: &ProjectFile,
        language: Language,
        source: &str,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Option<Self>, EmbeddedSyntaxStop> {
        let Some(primary) = parse_tree_for_language(file, language, source) else {
            return Ok(None);
        };
        let spec = crate::analyzer::structural_spec_for(language)
            .expect("a parsed language has a structural specification");
        let forest =
            EmbeddedSyntaxForest::parse(spec, primary.root_node(), source, 200_000, cancellation)?;
        Ok(Some(Self { primary, forest }))
    }

    fn tree(&self, range: &Range) -> &tree_sitter::Tree {
        self.forest
            .tree_for_range(&self.primary, range.start_byte, range.end_byte)
    }
}

fn stopped_dispatch_syntax(
    stop: &EmbeddedSyntaxStop,
    work: CallRelationWork,
) -> CallDispatchLookup {
    CallDispatchLookup {
        cancelled: matches!(stop, EmbeddedSyntaxStop::Cancelled),
        budget_exhausted: matches!(stop, EmbeddedSyntaxStop::Exceeded),
        diagnostics: vec![format!(
            "exact call dispatch syntax preparation stopped: {stop:?}"
        )],
        work,
        ..CallDispatchLookup::default()
    }
}

enum CallDispatchParse {
    Uninitialized,
    Ready(Result<Option<CallDispatchSyntax>, EmbeddedSyntaxStop>),
}

pub(crate) type CompletedExpansion =
    Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)>;

/// A serial exact-dispatch session for one immutable source snapshot.
///
/// Parsing is lazy, so merely opening a file window performs no semantic
/// work. The first call that is actually requested pays the source scan and
/// parse; later calls reuse that tree and pay only their own definition
/// lookup. Definition resolution itself stays one-call-at-a-time so
/// cancellation and budget outcomes keep request order.
pub(crate) struct CallDispatchSession {
    file: ProjectFile,
    exact_source: Arc<str>,
    language: Language,
    parse: CallDispatchParse,
    /// Shared with the parse, and for the same reason: the file-wide owner
    /// proofs classification needs are the same for every call in this window.
    file_evidence: ExternalCalleeFileEvidence,
    /// C/C++ dispatch is requested one source range at a time by the
    /// semantic source projection. Resolve a bounded set of exact call spans
    /// together, then serve the individual projections from this query-local
    /// cache. The cache is deliberately owned by the file session rather than
    /// the analyzer, so it cannot grow with the workspace or cross queries.
    cpp_dispatch_cache: HashMap<(usize, usize), CallDispatchLookup>,
    cpp_dispatch_prefetched: bool,
    /// Whole-call spans the caller announced it will dispatch through this
    /// session. The next call that reaches the definition resolver resolves
    /// their callee ranges in its own batch (see [`Self::expect_calls`]).
    expected_calls: Vec<Range>,
    /// Definition-resolver outcomes by callee byte range, filled by such a
    /// batch for the calls that did not trigger it. Like the C/C++ cache it
    /// is owned by the file session, so it is bounded by the calls one query
    /// announced in one file.
    callee_outcomes: HashMap<(usize, usize), CallTargetLookupOutcome>,
    /// Speculative native answers only. They can be removed without losing
    /// any answer the sequential session itself resolved.
    prefetched_callees: HashSet<(usize, usize)>,
    /// Only completed source-checked worker expansions; absence is explicit.
    prefetched_expansions: HashMap<(usize, usize), CompletedExpansion>,
}

const MAX_CPP_DISPATCH_PREFETCH_SITES: usize = 1024;

#[derive(Debug, Clone, Copy)]
pub struct CallRelationLimits {
    pub max_files: usize,
    pub max_source_bytes: usize,
    /// Maximum retained dispatch targets for each exact call. In the batched
    /// exact-call API this remains a per-call arm cap; the caller separately
    /// bounds the number of submitted call sites.
    pub max_candidates: usize,
}

fn unbounded_call_relation_limits(max_files: usize, max_candidates: usize) -> CallRelationLimits {
    CallRelationLimits {
        max_files,
        max_source_bytes: usize::MAX,
        max_candidates,
    }
}

pub(crate) fn request_for_callee_range(
    file: &ProjectFile,
    range: Range,
) -> DefinitionLookupRequest {
    DefinitionLookupRequest {
        file: file.clone(),
        line: None,
        column: None,
        start_byte: Some(range.start_byte),
        end_byte: Some(range.end_byte),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CallRelationWork {
    pub scanned_files: usize,
    pub scanned_source_bytes: usize,
    pub examined_candidates: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CallRelationDiagnosticCode {
    BudgetExhausted,
    ParseFailed,
    CandidatesOmitted,
    TargetsAmbiguous,
    CandidateLimit,
    AnalysisFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CallRelationDiagnostic {
    pub code: CallRelationDiagnosticCode,
    pub message: String,
    /// Stable producer context for debugging without parsing the message.
    pub context: String,
    /// Structured usage-analysis reason when this originated below the call
    /// relation layer.
    pub reason_kind: Option<String>,
}

impl CallRelationDiagnostic {
    fn new(code: CallRelationDiagnosticCode, message: String, context: String) -> Self {
        Self {
            code,
            message,
            context,
            reason_kind: None,
        }
    }

    pub(crate) fn analysis_failed(message: String, context: String, reason_kind: String) -> Self {
        Self {
            code: CallRelationDiagnosticCode::AnalysisFailed,
            message,
            context,
            reason_kind: Some(reason_kind),
        }
    }
}

impl CallRelationWork {
    fn add(&mut self, other: Self) {
        self.scanned_files = self.scanned_files.saturating_add(other.scanned_files);
        self.scanned_source_bytes = self
            .scanned_source_bytes
            .saturating_add(other.scanned_source_bytes);
        self.examined_candidates = self
            .examined_candidates
            .saturating_add(other.examined_candidates);
    }
}

#[derive(Debug, Clone, Default)]
pub struct CallRelationResult {
    pub sites: Vec<CallSite>,
    pub truncated: bool,
    pub cancelled: bool,
    pub diagnostics: Vec<CallRelationDiagnostic>,
    /// The authority of the producer that answered, so a consumer can tell an
    /// incompleteness diagnostic that reports a gap in a certified inventory
    /// from one a legacy resolver has always reported alongside a usable list.
    /// The engine below answers as [`UsageProofAuthority::Legacy`]; a
    /// registered provider's answer is stamped with that provider's authority.
    pub proof_authority: UsageProofAuthority,
    pub work: CallRelationWork,
}

/// A language-owned call relation authority. Once registered, both directions
/// use this provider exclusively, including incomplete and terminal outcomes.
pub(crate) trait CallRelationProvider: Send + Sync {
    /// Whether this provider's proof tiers are authoritative. Every answer it
    /// returns is stamped with this value, so no construction site inside a
    /// provider can forget it.
    fn proof_authority(&self) -> UsageProofAuthority;

    fn incoming(
        &self,
        analyzer: &dyn IAnalyzer,
        target: &CodeUnit,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> CallRelationResult;

    fn outgoing(
        &self,
        analyzer: &dyn IAnalyzer,
        caller: &CodeUnit,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> CallRelationResult;

    /// Resolve a language-specific exact call shape before the framework's
    /// ordinary callee-reference route. `None` leaves generic dispatch in
    /// charge; `Some` is the language adapter's complete answer.
    fn dispatch_special_call_site(
        &self,
        _request: CallDispatchLanguageRequest<'_>,
    ) -> Option<CallDispatchLookup> {
        None
    }
}

/// Domain for the digest of one call-relation answer.
const CALL_RELATION_ANSWER_DOMAIN: &[u8] = b"bifrost-read-ledger:call-relation-answer:v1";

/// Record the callers or callees answer for one declaration.
///
/// This is the funnel behind the `callers` and `callees` steps and behind
/// every other consumer of the call relation, so recording here covers the
/// request-scoped memo above it too: a memo hit means the funnel was crossed
/// earlier in the same request, which already recorded the key.
///
/// The two directions record two kinds -- [`LookupKind::Callers`] and
/// [`LookupKind::Callees`] -- because verification replays the funnel a kind
/// names, and a kind that named both this relation and the usage finder could
/// never be replayed: the two answer the same subject with different digests.
fn record_call_relation_read(
    analyzer: &dyn IAnalyzer,
    kind: crate::analyzer::read_ledger::LookupKind,
    subject: &CodeUnit,
    result: &CallRelationResult,
) {
    if !analyzer.read_ledger_attached() {
        return;
    }
    analyzer.record_read(crate::analyzer::read_ledger::ReadKey::lookup(
        kind,
        crate::analyzer::read_ledger::LookupQuestion::declaration(subject),
        call_relation_answer_digest(result),
    ));
}

/// The canonical digest of one call-relation answer.
///
/// Public to the crate because verification replays the same funnel against
/// the head workspace and must compute the answer digest with this function
/// rather than a second copy of it.
pub(crate) fn call_relation_answer_digest(
    result: &CallRelationResult,
) -> crate::analyzer::semantic::ids::StableDigest {
    let mut sites = result
        .sites
        .iter()
        .map(|site| {
            (
                crate::path_utils::rel_path_string(&site.file),
                site.range.start_byte,
                site.range.end_byte,
                site.caller.fq_name(),
                site.callee.fq_name(),
            )
        })
        .collect::<Vec<_>>();
    sites.sort();
    sites.dedup();
    let mut hasher =
        crate::analyzer::canonical_hash::CanonicalHasher::new(CALL_RELATION_ANSWER_DOMAIN);
    // A truncated or cancelled answer is a different fact about the workspace
    // from a complete one that happens to hold the same sites.
    hasher.field("truncated", &[u8::from(result.truncated)]);
    hasher.field("cancelled", &[u8::from(result.cancelled)]);
    let mut diagnostics = result.diagnostics.iter().collect::<Vec<_>>();
    diagnostics.sort();
    for diagnostic in diagnostics {
        hasher.field("diagnostic", format!("{diagnostic:?}").as_bytes());
    }
    for (path, start, end, caller, callee) in sites {
        hasher.field(&path, &(start as u64).to_be_bytes());
        hasher.value(&(end as u64).to_be_bytes());
        hasher.field("caller", caller.as_bytes());
        hasher.field("callee", callee.as_bytes());
    }
    crate::analyzer::semantic::ids::StableDigest::from_array(hasher.finish())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CallTargetOutcomeAuthority {
    workspace: WorkspaceContentIdentity,
    analysis_generation: u64,
    active_model_set_hash: Option<String>,
}

#[derive(Debug, Clone)]
struct SharedRustCallTargetPrefetch {
    targets: HashMap<Range, CallTargetLookupOutcome>,
    reads: Vec<Arc<ReadLedger>>,
}

/// One selected file batch, retained only by the requesting query.
pub(crate) struct PrefetchedCallTargets {
    pub(crate) targets: Vec<(Range, CallTargetLookupOutcome)>,
    pub(crate) reads: Arc<ReadLedger>,
}

/// Exact Rust call-target answers shared only by one policy compilation.
///
/// The cache namespace captures the analyzed content, selected-resolution
/// generation, and active model set. It is request-owned and never persisted.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct CallTargetOutcomeCache {
    authority: CallTargetOutcomeAuthority,
    prefetches: Arc<Mutex<HashMap<ProjectFile, Arc<SharedRustCallTargetPrefetch>>>>,
}

impl CallTargetOutcomeCache {
    /// Create the cache only when this analyzer can attest the workspace
    /// snapshot its call-target answers will describe.
    #[doc(hidden)]
    pub fn for_policy_compilation(analyzer: &dyn IAnalyzer) -> Option<Self> {
        let workspace = analyzer.workspace_content_identity()?;
        let active_model_set_hash = analyzer
            .active_semantic_models()
            .map(|models| models.active_model_set_hash().to_owned());
        Some(Self {
            authority: CallTargetOutcomeAuthority {
                workspace,
                analysis_generation: analyzer.project().analysis_generation(),
                active_model_set_hash,
            },
            prefetches: Arc::new(Mutex::new(HashMap::default())),
        })
    }

    #[doc(hidden)]
    pub fn matches_current(
        &self,
        analyzer: &dyn IAnalyzer,
        active_models: Option<&crate::analyzer::semantic_model::ResolvedActiveSemanticModels>,
    ) -> bool {
        analyzer
            .workspace_content_identity()
            .is_some_and(|workspace| {
                self.authority.workspace == workspace
                    && self.authority.analysis_generation
                        == analyzer.project().analysis_generation()
            })
            && self.authority.active_model_set_hash.as_deref()
                == active_models.map(|models| models.active_model_set_hash())
    }

    fn get_prefetch(&self, file: &ProjectFile) -> Option<Arc<SharedRustCallTargetPrefetch>> {
        self.prefetches
            .lock()
            .expect("call-target outcome cache lock poisoned")
            .get(file)
            .cloned()
    }

    fn insert_prefetch(
        &self,
        file: &ProjectFile,
        targets: HashMap<Range, CallTargetLookupOutcome>,
        reads: Arc<ReadLedger>,
    ) {
        let mut prefetches = self
            .prefetches
            .lock()
            .expect("call-target outcome cache lock poisoned");
        let prefetch = Arc::make_mut(prefetches.entry(file.clone()).or_insert_with(|| {
            Arc::new(SharedRustCallTargetPrefetch {
                targets: HashMap::default(),
                reads: Vec::new(),
            })
        }));
        prefetch.targets.extend(targets);
        prefetch.reads.push(reads);
    }
}

#[derive(Default)]
pub struct CallBindingCache {
    conversions: super::call_conversion::CallConversionCache,
    formals: HashMap<(CodeUnit, usize), Option<FormalParameterLayout>>,
    python_receiver_is_class: HashMap<(ProjectFile, usize, usize), Option<bool>>,
    /// Exact callee ranges demanded by this query, including narrow on-demand
    /// misses after a candidate batch. No entry promises whole-file coverage.
    call_targets: HashMap<(ProjectFile, Range), CallTargetLookupOutcome>,
    /// Exact per-file call-dispatch sessions used by structural selectors.
    /// Each session owns one source snapshot and parser tree only for this
    /// query, so retained state is bounded by the active query's file set.
    call_dispatch_sessions: HashMap<ProjectFile, CallDispatchSession>,
    /// Exact external call-site dispatch answers already requested by this
    /// query, keyed by the immutable file and whole-call range.
    call_dispatches: HashMap<(ProjectFile, Range), Option<ResolverOwnedExternalCallDispatch>>,
    shared_call_targets: Option<CallTargetOutcomeCache>,
}

impl CallBindingCache {
    /// Attach compilation-local Rust call-target outcomes, when available.
    #[doc(hidden)]
    pub fn with_shared_call_target_outcomes(
        mut self,
        outcomes: Option<CallTargetOutcomeCache>,
    ) -> Self {
        self.shared_call_targets = outcomes;
        self
    }

    /// Select the one structured model overload proven applicable to this
    /// exact written application, using the conversion cache's source index.
    pub fn select_model_signature(
        &mut self,
        analyzer: &dyn IAnalyzer,
        shape: &super::call_shape::CallShapeReport,
        caller_source: Option<(&ProjectFile, &str)>,
        candidates: &[(String, crate::analyzer::semantic_model::Signature)],
    ) -> Result<
        Option<(String, crate::analyzer::semantic_model::Signature)>,
        crate::analyzer::usages::call_conversion::ConversionUnknown,
    > {
        self.conversions
            .select_model_signature(analyzer, shape, caller_source, candidates)
    }

    /// Populate the adjacent shared conversion relation using this query's
    /// source cache and the already-selected signature.
    pub fn populate_conversions(
        &mut self,
        analyzer: &dyn IAnalyzer,
        report: &mut super::call_binding::CallBindingReport,
        signature: Option<&str>,
        model_signature: Option<(&str, &str, &crate::analyzer::semantic_model::Signature)>,
    ) {
        match model_signature {
            Some((model_target_id, model_signature_id, signature)) => {
                self.conversions.populate_model_signature(
                    analyzer,
                    report,
                    model_target_id,
                    model_signature_id,
                    signature,
                )
            }
            None => self.conversions.populate(analyzer, report, signature),
        }
    }

    /// The callable's syntax-derived formal parameter layout, read once per
    /// declaration. Shared with the `call_binding` row producer so both read
    /// one cache entry rather than re-parsing the declaring file twice.
    pub fn formal_layout(
        &mut self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        actual_count: usize,
    ) -> Option<FormalParameterLayout> {
        self.formals
            .entry((unit.clone(), actual_count))
            .or_insert_with(|| formal_slots_for_unit(analyzer, unit, actual_count))
            .clone()
    }

    /// Resolve this exact callee range. Pipeline consumers batch their selected
    /// candidates first; other consumers and late misses demand only this site.
    pub fn resolved_call_target(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        callee_range: Range,
        cancellation: Option<&CancellationToken>,
    ) -> Option<CallTargetLookupOutcome> {
        if !self
            .call_targets
            .contains_key(&(file.clone(), callee_range))
        {
            self.load_shared_call_targets(analyzer, file, cancellation);
        }
        if !self
            .call_targets
            .contains_key(&(file.clone(), callee_range))
        {
            self.prefetch_call_targets_uncached(analyzer, file, vec![callee_range], cancellation);
        }
        self.call_targets
            .get(&(file.clone(), callee_range))
            .cloned()
    }

    /// The exact external callee proved by the production resolver for this
    /// call site's callee token, when one is available.
    pub fn resolved_exact_external_callee(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        callee_range: Range,
        cancellation: Option<&CancellationToken>,
    ) -> Option<String> {
        self.resolved_call_target(analyzer, file, callee_range, cancellation)?
            .exact_external_call
            .map(|proof| proof.canonical_callee().to_owned())
    }

    /// Resolve a whole call through the shared exact-dispatch path and return
    /// its one resolver-owned external identity with the proven formal arity.
    /// The per-file session keeps parsing and Rust's macro visibility walk
    /// query-local while reusing the exact source snapshot across call sites.
    pub fn resolved_external_call_dispatch(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        call_span: Range,
        cancellation: Option<&CancellationToken>,
    ) -> Option<ResolverOwnedExternalCallDispatch> {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return None;
        }
        let key = (file.clone(), call_span);
        if let Some(dispatch) = self.call_dispatches.get(&key) {
            return dispatch.clone();
        }
        let source = Arc::<str>::from(analyzer.indexed_source(file)?);
        let session = self
            .call_dispatch_sessions
            .entry(file.clone())
            .or_insert_with(|| {
                CallRelationService::dispatch_session(file.clone(), Arc::clone(&source))
            });
        assert_eq!(
            session.exact_source.as_ref(),
            source.as_ref(),
            "one call-binding query retains one exact source snapshot per file"
        );
        let query_scope = AnalyzerQueryScope::new(analyzer);
        let dispatch = session
            .dispatch_at_bounded(analyzer, query_scope.token(), &call_span, 100, cancellation)
            .resolver_owned_external_call();
        if !cancellation.is_some_and(CancellationToken::is_cancelled) {
            self.call_dispatches.insert(key, dispatch.clone());
        }
        dispatch
    }

    fn load_shared_call_targets(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        cancellation: Option<&CancellationToken>,
    ) {
        if language_for_file(file) == Language::Rust
            && !cancellation.is_some_and(CancellationToken::is_cancelled)
            && let Some(prefetch) = self
                .shared_call_targets
                .as_ref()
                .and_then(|cache| cache.get_prefetch(file))
        {
            for reads in &prefetch.reads {
                replay_query_reads(analyzer, reads);
            }
            self.call_targets.extend(
                prefetch
                    .targets
                    .iter()
                    .map(|(range, outcome)| ((file.clone(), *range), outcome.clone())),
            );
        }
    }

    fn retain_call_targets(
        &mut self,
        file: &ProjectFile,
        targets: Vec<(Range, CallTargetLookupOutcome)>,
        reads: Arc<ReadLedger>,
        cancellation: Option<&CancellationToken>,
    ) {
        if language_for_file(file) == Language::Rust
            && !cancellation.is_some_and(CancellationToken::is_cancelled)
            && targets
                .iter()
                .all(|(_, outcome)| outcome.outcome.status != DefinitionLookupStatus::Cancelled)
            && let Some(shared) = &self.shared_call_targets
        {
            shared.insert_prefetch(file, targets.iter().cloned().collect(), reads);
        }
        self.call_targets.extend(
            targets
                .into_iter()
                .map(|(range, outcome)| ((file.clone(), range), outcome)),
        );
    }

    /// Resolve exactly the callee rows selected by the requesting pipeline.
    /// File groups share resolver setup, without speculating about other calls.
    /// All retained groups and outcomes die with this query or policy compile.
    pub fn prefetch_selected_call_targets(
        &mut self,
        workspace: &crate::analyzer::WorkspaceAnalyzer,
        candidates: impl IntoIterator<Item = (ProjectFile, Range)>,
        cancellation: Option<&CancellationToken>,
    ) -> crate::analyzer::store::Result<()> {
        let analyzer = workspace.analyzer();
        let mut files = Vec::<(ProjectFile, Vec<Range>)>::new();
        let mut indices = HashMap::default();
        for (file, range) in candidates {
            let next = files.len();
            let index = *indices.entry(file.clone()).or_insert_with(|| {
                self.load_shared_call_targets(analyzer, &file, cancellation);
                files.push((file, Vec::new()));
                next
            });
            if !self
                .call_targets
                .contains_key(&(files[index].0.clone(), range))
            {
                files[index].1.push(range);
            }
        }
        for (_, ranges) in &mut files {
            ranges.sort();
            ranges.dedup();
        }
        files.retain(|(_, ranges)| !ranges.is_empty());
        let uncancelled = CancellationToken::default();
        let token = cancellation.unwrap_or(&uncancelled);
        let snapshot = analyzer.active_semantic_model_snapshot();
        let mut languages = HashSet::default();
        for (file, _) in &files {
            if languages.insert(file.language())
                && let Some(support) = language_support(file.language())
                && let Some(result) = support.prefetch_selected_call_targets(
                    workspace,
                    &files,
                    token,
                    snapshot.clone(),
                )
            {
                for (file, answer) in result? {
                    self.retain_call_targets(&file, answer.targets, answer.reads, cancellation);
                }
            }
        }
        // Unsupported languages and single-connection stores retain the same
        // serial resolver. A late or unattempted range never widens the batch.
        for (file, ranges) in files {
            let missing = ranges
                .into_iter()
                .filter(|range| !self.call_targets.contains_key(&(file.clone(), *range)))
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                self.prefetch_call_targets_uncached(analyzer, &file, missing, cancellation);
            }
        }
        Ok(())
    }

    fn prefetch_call_targets_uncached(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        ranges: Vec<Range>,
        cancellation: Option<&CancellationToken>,
    ) {
        let (targets, reads) = capture_query_reads(analyzer, || {
            let Some(source) = analyzer.indexed_source(file).map(Arc::<str>::from) else {
                return Vec::new();
            };
            let requests = ranges
                .iter()
                .map(|range| request_for_callee_range(file, *range))
                .collect();
            let scope = AnalyzerQueryScope::new(analyzer);
            let mut outcomes = resolve_call_target_batch_with_source(
                analyzer,
                scope.token(),
                requests,
                file.clone(),
                Arc::clone(&source),
                cancellation,
            );
            if language_for_file(file) == Language::Python
                && let Some(tree) = parse_tree_for_language(file, Language::Python, &source)
            {
                let file_evidence = ExternalCalleeFileEvidence::default();
                for (range, outcome) in ranges.iter().zip(&mut outcomes) {
                    *outcome = expand_python_call_target_identity(
                        analyzer,
                        file,
                        &source,
                        &tree,
                        *range,
                        &file_evidence,
                        outcome.clone(),
                    );
                }
            }
            assert_eq!(outcomes.len(), ranges.len());
            ranges.into_iter().zip(outcomes).collect()
        });
        // Cancelled ranges retain their explicit terminal outcomes locally;
        // they are never published to a later selector's shared cache.
        self.retain_call_targets(file, targets, reads, cancellation);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallBindingStatus {
    Complete,
    Unavailable,
}

#[derive(Default)]
struct CallSyntaxCache {
    files: HashMap<ProjectFile, Option<Arc<FileFacts>>>,
}

impl CallSyntaxCache {
    fn facts(&mut self, analyzer: &dyn IAnalyzer, file: &ProjectFile) -> Option<&Arc<FileFacts>> {
        self.files
            .entry(file.clone())
            .or_insert_with(|| {
                analyzer
                    .structural_fact_providers()
                    .into_iter()
                    .find_map(|provider| provider.structural_facts(file))
            })
            .as_ref()
    }

    fn syntax_for_range(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
    ) -> Option<CallSiteSyntax> {
        call_site_syntax_for_reference(self.facts(analyzer, file)?, start_byte, end_byte)
    }

    fn range_is_keyword_label(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
    ) -> bool {
        self.facts(analyzer, file)
            .is_some_and(|facts| range_is_call_keyword_label(facts, start_byte, end_byte))
    }
}

pub struct CallRelationService;

struct OutgoingCallCandidate {
    proof: Option<UsageProof>,
    callees: Vec<CodeUnit>,
    omitted: usize,
    ambiguous: bool,
    fully_retained: bool,
}

fn resolve_outgoing_call_candidate(
    analyzer: &dyn IAnalyzer,
    status: DefinitionLookupStatus,
    definitions: Vec<CodeUnit>,
) -> OutgoingCallCandidate {
    let (proof, ambiguous) = match status {
        DefinitionLookupStatus::Resolved => (Some(UsageProof::Proven), false),
        DefinitionLookupStatus::Ambiguous => (Some(UsageProof::Unproven), true),
        _ => {
            return OutgoingCallCandidate {
                proof: None,
                callees: Vec::new(),
                omitted: 1,
                ambiguous: false,
                fully_retained: false,
            };
        }
    };

    let mut callees = Vec::new();
    let mut omitted = 0usize;
    for definition in definitions {
        if let Some(callee) = nearest_call_relation_unit(analyzer, definition) {
            callees.push(callee);
        } else {
            omitted = omitted.saturating_add(1);
        }
    }
    if callees.is_empty() && omitted == 0 {
        // A resolved/ambiguous outcome promises at least one candidate site.
        // An empty definition set therefore omits one lower-bound candidate.
        omitted = 1;
    }
    let fully_retained = omitted == 0 && !callees.is_empty();
    OutgoingCallCandidate {
        proof,
        callees,
        omitted,
        ambiguous,
        fully_retained,
    }
}

fn append_outgoing_candidate_diagnostics(
    diagnostics: &mut Vec<CallRelationDiagnostic>,
    caller: &CodeUnit,
    ambiguous: usize,
    retained_ambiguous: usize,
    omitted: usize,
) {
    // Ambiguity is advisory only when every alternative survived the
    // definition-to-callable projection. Otherwise the omission diagnostic is
    // the completeness-bearing outcome and we must not claim all candidates
    // were emitted as unproven.
    if ambiguous > 0 && retained_ambiguous == ambiguous {
        diagnostics.push(CallRelationDiagnostic::new(
            CallRelationDiagnosticCode::TargetsAmbiguous,
            format!(
                "call targets for {} were ambiguous at {ambiguous} candidate site{}; all candidates are unproven",
                caller.fq_name(),
                if ambiguous == 1 { "" } else { "s" }
            ),
            caller.fq_name().to_string(),
        ));
    }
    if omitted > 0 {
        diagnostics.push(CallRelationDiagnostic::new(
            CallRelationDiagnosticCode::CandidatesOmitted,
            format!(
                "omitted {omitted} unresolved call candidate{} for {}",
                if omitted == 1 { "" } else { "s" },
                caller.fq_name()
            ),
            caller.fq_name().to_string(),
        ));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IncomingCallOmission {
    CallerUnavailable,
    SyntaxUnavailable,
    /// The hit is a named argument's label. It references the callee's
    /// parameter without being a call site, so dropping it costs the call
    /// relation nothing.
    KeywordLabel,
}

fn project_incoming_call_hit(
    analyzer: &dyn IAnalyzer,
    syntax_cache: &mut CallSyntaxCache,
    target: &CodeUnit,
    hit: UsageHit,
    proof: UsageProof,
) -> Result<CallSite, IncomingCallOmission> {
    let caller = nearest_call_relation_unit(analyzer, hit.enclosing.clone())
        .ok_or(IncomingCallOmission::CallerUnavailable)?;
    let Some(syntax) =
        syntax_cache.syntax_for_range(analyzer, &hit.file, hit.start_offset, hit.end_offset)
    else {
        // A hit inside the target itself that has no call syntax is the
        // target's own declaration name, which is not a call candidate at
        // all: every function declaration produces exactly this hit, and
        // counting it as an unresolved candidate would fail every strict
        // incoming scan over a resolvable call.
        if caller == *target {
            return Err(IncomingCallOmission::KeywordLabel);
        }
        return Err(
            if syntax_cache.range_is_keyword_label(
                analyzer,
                &hit.file,
                hit.start_offset,
                hit.end_offset,
            ) {
                IncomingCallOmission::KeywordLabel
            } else {
                IncomingCallOmission::SyntaxUnavailable
            },
        );
    };
    Ok(raw_call_site(
        hit.file,
        caller,
        target.clone(),
        syntax,
        proof,
    ))
}

fn append_incoming_projection_omission(
    diagnostics: &mut Vec<CallRelationDiagnostic>,
    target: &CodeUnit,
    omitted: usize,
) {
    if omitted == 0 {
        return;
    }
    // The ambiguity producer claims every returned candidate is available as
    // an unproven edge. Once projection drops one, incompleteness replaces
    // that advisory for this incoming scan.
    diagnostics
        .retain(|diagnostic| diagnostic.code != CallRelationDiagnosticCode::TargetsAmbiguous);
    diagnostics.push(CallRelationDiagnostic::new(
        CallRelationDiagnosticCode::CandidatesOmitted,
        format!(
            "omitted {omitted} incoming call candidate{} for {} because exact caller or call syntax was unavailable",
            if omitted == 1 { "" } else { "s" },
            target.fq_name()
        ),
        target.fq_name().to_string(),
    ));
}

impl CallDispatchSession {
    pub(crate) fn install_prefetched(&mut self, prefetched: PrefetchedCallFile) {
        if prefetched.source_identity != ContentIdentity::hash_bytes(self.exact_source.as_bytes()) {
            return;
        }
        debug_assert_eq!(
            prefetched.work.scanned_source_bytes,
            self.exact_source.len()
        );
        debug_assert_eq!(prefetched.native_execution_delta, 0);
        for (key, outcome, expansion) in prefetched.outcomes {
            if let std::collections::hash_map::Entry::Vacant(entry) =
                self.callee_outcomes.entry(key)
            {
                entry.insert(outcome);
                self.prefetched_callees.insert(key);
                if let Some(expansion) = expansion {
                    self.prefetched_expansions.insert(key, expansion);
                }
            }
        }
    }

    pub(crate) fn discard_prefetched(&mut self) {
        self.prefetched_expansions.clear();
        for key in self.prefetched_callees.drain() {
            self.callee_outcomes.remove(&key);
        }
    }

    /// Conservative live source, tree, and project-path footprint while this
    /// session owns its exact snapshot. The shared syntax estimator also
    /// budgets entries retained by the analyzer's prepared-syntax store.
    pub(crate) fn retained_bytes(&self) -> usize {
        crate::analyzer::tree_sitter_analyzer::prepared_syntax_retained_bytes(
            self.exact_source.len(),
        )
        .saturating_add(self.file.retained_bytes())
    }

    /// Batch the first C/C++ dispatch window against the same exact source
    /// snapshot used by this session. The current call is always included,
    /// even when the structural fact arena has already reached the prefetch
    /// cap. A missing or stale facts snapshot simply leaves the ordinary
    /// single-call path in charge.
    fn prefetch_cpp_dispatches(
        &mut self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        current_span: &Range,
        max_candidates: usize,
        cancellation: Option<&CancellationToken>,
    ) -> Option<CallDispatchLookup> {
        self.cpp_dispatch_prefetched = true;
        let facts = analyzer
            .structural_fact_providers()
            .into_iter()
            .find_map(|provider| provider.structural_facts(&self.file))?;
        if facts.source_identity() != ContentIdentity::hash_bytes(self.exact_source.as_bytes()) {
            return None;
        }

        let current_key = (current_span.start_byte, current_span.end_byte);
        let mut spans = call_shapes_in_file(
            &facts,
            &self.file,
            MAX_CPP_DISPATCH_PREFETCH_SITES.saturating_sub(1),
        )
        .into_iter()
        .map(|shape| (shape.outcome.range.start_byte, shape.outcome.range.end_byte))
        .collect::<Vec<_>>();
        spans.push(current_key);
        spans.sort_unstable();
        spans.dedup();
        if spans.len() <= 1 {
            return None;
        }

        let ranges = spans
            .iter()
            .map(|&(start_byte, end_byte)| Range {
                start_byte,
                end_byte,
                start_line: 0,
                end_line: 0,
            })
            .collect::<Vec<_>>();
        let lookups = CallRelationService::dispatch_many_at_bounded(
            analyzer,
            token,
            &self.file,
            &ranges,
            Arc::clone(&self.exact_source),
            CallRelationLimits {
                max_files: 1,
                max_source_bytes: usize::MAX,
                max_candidates,
            },
            cancellation,
        );
        for (key, mut lookup) in spans.into_iter().zip(lookups) {
            // The batch shares one parse/source scan. The triggering call
            // owns that first source charge; later projections retain only
            // their per-call resolver work, matching the serial session.
            if key != current_key {
                lookup.work.scanned_files = 0;
                lookup.work.scanned_source_bytes = 0;
            }
            self.cpp_dispatch_cache.insert(key, lookup);
        }
        self.cpp_dispatch_cache.get(&current_key).cloned()
    }

    /// Announce whole-call spans this session will be asked to dispatch.
    ///
    /// Nothing is resolved here. The next call whose dispatch reaches the
    /// definition resolver resolves its own callee range together with the
    /// announced calls' callee ranges in one batch, and the announced calls
    /// later read their outcome from the session. One batch pays the
    /// per-batch resolver setup (for Rust, the definition operation factory
    /// and its macro frontiers) once instead of once per call.
    pub(crate) fn expect_calls(&mut self, call_spans: impl IntoIterator<Item = Range>) {
        self.expected_calls.extend(call_spans);
    }

    pub(crate) fn dispatch_at_bounded(
        &mut self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        call_span: &Range,
        max_candidates: usize,
        cancellation: Option<&CancellationToken>,
    ) -> CallDispatchLookup {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return CallDispatchLookup {
                cancelled: true,
                ..CallDispatchLookup::default()
            };
        }
        let call_key = (call_span.start_byte, call_span.end_byte);
        if let Some(lookup) = self.cpp_dispatch_cache.get(&call_key) {
            return lookup.clone();
        }
        if max_candidates == 0 {
            return CallDispatchLookup {
                budget_exhausted: true,
                diagnostics: vec![format!(
                    "exact call dispatch candidate budget omitted {}",
                    self.file
                )],
                ..CallDispatchLookup::default()
            };
        }

        let parse_was_uninitialized = matches!(self.parse, CallDispatchParse::Uninitialized);
        let mut work = CallRelationWork {
            examined_candidates: 1,
            ..CallRelationWork::default()
        };
        if matches!(self.parse, CallDispatchParse::Uninitialized) {
            work.scanned_files = 1;
            work.scanned_source_bytes = self.exact_source.len();
            let tree = if self.language == Language::None {
                Ok(None)
            } else {
                CallDispatchSyntax::parse(
                    &self.file,
                    self.language,
                    &self.exact_source,
                    cancellation,
                )
            };
            self.parse = CallDispatchParse::Ready(tree);
        }
        if self.language == Language::None {
            return unresolved_dispatch_lookup(
                DefinitionLookupStatus::UnsupportedLanguage,
                "exact call dispatch does not support this file language".to_string(),
                work,
            );
        }
        if let CallDispatchParse::Ready(Err(stop)) = &self.parse {
            return stopped_dispatch_syntax(stop, work);
        }
        if !matches!(self.parse, CallDispatchParse::Ready(Ok(Some(_)))) {
            return unresolved_dispatch_lookup(
                DefinitionLookupStatus::NotFound,
                format!("failed to parse {} for exact call dispatch", self.file),
                work,
            );
        };
        if self.language == Language::Cpp
            && !self.cpp_dispatch_prefetched
            && let Some(lookup) = self.prefetch_cpp_dispatches(
                analyzer,
                token,
                call_span,
                max_candidates,
                cancellation,
            )
        {
            return lookup;
        }
        let CallDispatchParse::Ready(Ok(Some(syntax))) = &self.parse else {
            unreachable!("a parsed C/C++ dispatch session retains its syntax tree");
        };
        let tree = syntax.tree(call_span);
        let language_request = CallDispatchLanguageRequest {
            analyzer,
            token,
            file: &self.file,
            source: &self.exact_source,
            tree,
            call_span,
            cancellation,
            work,
        };
        if let Some(lookup) = language_support(self.language)
            .and_then(|support| support.call_relation_provider())
            .and_then(|provider| provider.dispatch_special_call_site(language_request))
        {
            return lookup;
        }
        let callee_range = match exact_call_reference_for_call(tree, self.language, call_span) {
            Some(ExactCallReference::Resolvable(range)) => range,
            Some(ExactCallReference::Unsupported(ExactCallReferenceGap::RubyCallableObject)) => {
                return unresolved_dispatch_lookup(
                    DefinitionLookupStatus::NoDefinition,
                    "unsupported_ruby_callable_object_dispatch: resolving `receiver.(...)` requires value/heap callable-target information"
                        .to_string(),
                    work,
                );
            }
            Some(ExactCallReference::Unsupported(ExactCallReferenceGap::CallOfValue)) => {
                return unresolved_dispatch_lookup(
                    DefinitionLookupStatus::NoDefinition,
                    "unsupported_call_of_value: callee expression does not name a declaration; dispatch requires callable-value information".to_string(),
                    work,
                );
            }
            None => {
                return unresolved_dispatch_lookup(
                    DefinitionLookupStatus::InvalidLocation,
                    format!(
                        "range [{}, {}) is not one exact supported call expression in {}",
                        call_span.start_byte, call_span.end_byte, self.file
                    ),
                    work,
                );
            }
        };
        // Batched resolution gives each callee range the outcome a batch of
        // that range alone gives: the per-file prefetch of `CallBindingCache`
        // (#2765) and the C/C++ dispatch prefetch above rest on the same
        // property of `resolve_call_target_batch_with_source`. So an outcome
        // an earlier batch resolved for an announced call answers that call,
        // and only the post-resolution steps below run per call.
        let callee_key = (callee_range.start_byte, callee_range.end_byte);
        let (outcome, cancelled) = if let Some(outcome) = self.callee_outcomes.get(&callee_key) {
            if self.prefetched_callees.contains(&callee_key) {
                // Speculation does not pay source/call work. This lookup runs
                // the same parse and scalar charge as a sequential demand.
                let sequential_work = CallRelationWork {
                    scanned_files: usize::from(parse_was_uninitialized),
                    scanned_source_bytes: if parse_was_uninitialized {
                        self.exact_source.len()
                    } else {
                        0
                    },
                    examined_candidates: 1,
                };
                debug_assert_eq!(
                    work, sequential_work,
                    "prefetch preserves staged scalar dispatch work"
                );
            }
            (
                Some(outcome.clone()),
                cancellation.is_some_and(CancellationToken::is_cancelled),
            )
        } else {
            let mut references = vec![callee_range];
            let mut batched = HashSet::from_iter([callee_key]);
            for call_span in std::mem::take(&mut self.expected_calls) {
                if let Some(ExactCallReference::Resolvable(range)) = exact_call_reference_for_call(
                    syntax.tree(&call_span),
                    self.language,
                    &call_span,
                ) {
                    let key = (range.start_byte, range.end_byte);
                    if !self.callee_outcomes.contains_key(&key) && batched.insert(key) {
                        references.push(range);
                    }
                }
            }
            if crate::profiling::enabled() {
                crate::profiling::note(format!(
                    "call_dispatch.batch file={} requests={}",
                    self.file,
                    references.len()
                ));
            }
            let batch = resolve_call_references_with_source(
                analyzer,
                token,
                &self.file,
                Arc::clone(&self.exact_source),
                tree,
                &references,
                cancellation,
            );
            let cancelled =
                batch.cancelled || cancellation.is_some_and(CancellationToken::is_cancelled);
            let mut own = None;
            for (range, outcome) in batch.resolved {
                let key = (range.start_byte, range.end_byte);
                if key == callee_key {
                    own = Some(outcome);
                } else if !cancelled {
                    // A cancelled batch may hold cancelled outcomes; the
                    // announced calls then resolve on their own.
                    self.callee_outcomes.insert(key, outcome);
                }
            }
            (own, cancelled)
        };
        let Some(outcome) = outcome else {
            return if cancelled {
                CallDispatchLookup {
                    cancelled: true,
                    work,
                    ..CallDispatchLookup::default()
                }
            } else {
                unresolved_dispatch_lookup(
                    DefinitionLookupStatus::NotFound,
                    "definition resolver returned no outcome for the exact call reference"
                        .to_string(),
                    work,
                )
            };
        };
        let mut lookup = CallDispatchLookup {
            cancelled,
            work,
            ..CallDispatchLookup::default()
        };
        if outcome.outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary {
            lookup.boundary = Some(call_target_boundary_evidence(
                analyzer, &self.file, &outcome,
            ));
        }
        let site = ExternalCalleeSite {
            source: &self.exact_source,
            tree,
            callee_start_byte: callee_range.start_byte,
            file_evidence: &self.file_evidence,
        };
        apply_call_target_outcome(
            Some(analyzer),
            &mut lookup,
            expand_imported_external_callee_with_prefetched(
                analyzer,
                &self.file,
                outcome,
                Some(&site),
                self.prefetched_expansions.get(&callee_key),
            ),
            max_candidates,
            self.language,
            Some(&site),
        );
        refine_resolved_call_target_proofs(
            &mut lookup,
            self.language,
            analyzer,
            token,
            &self.file,
            &site,
        );
        apply_go_typed_selector_target_at_call(
            &mut lookup,
            analyzer,
            token,
            &self.file,
            &self.exact_source,
            tree,
            &callee_range,
            cancellation,
        );
        lookup
    }
}

fn go_selector_call_parts<'tree>(
    tree: &'tree tree_sitter::Tree,
    callee_range: &Range,
    source: &str,
) -> Option<(tree_sitter::Node<'tree>, tree_sitter::Node<'tree>, String)> {
    let root = tree.root_node();
    let mut node =
        root.descendant_for_byte_range(callee_range.start_byte, callee_range.end_byte)?;
    let (selector, member) = loop {
        if node.kind() == "selector_expression"
            && let Some(field) = node.child_by_field_name("field")
            && callee_range.start_byte <= field.start_byte()
            && field.end_byte() <= callee_range.end_byte
        {
            break (node, field);
        }
        node = node.parent()?;
    };
    let call = selector.parent()?;
    if call.kind() != "call_expression"
        || !call
            .child_by_field_name("function")
            .is_some_and(|function| function.id() == selector.id())
    {
        return None;
    }
    let receiver = selector.child_by_field_name("operand")?;
    let member_name = source.get(member.byte_range())?.to_owned();
    Some((receiver, selector, member_name))
}

#[allow(clippy::too_many_arguments)]
fn apply_go_typed_selector_target_at_call(
    lookup: &mut CallDispatchLookup,
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: &tree_sitter::Tree,
    callee_range: &Range,
    cancellation: Option<&CancellationToken>,
) {
    let Some((receiver, callable, member)) = go_selector_call_parts(tree, callee_range, source)
    else {
        return;
    };
    match go_typed_selector_target(
        analyzer,
        token,
        file,
        source,
        tree.root_node(),
        receiver,
        callable,
        &member,
        receiver.start_byte(),
        crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget::default(),
        cancellation,
    ) {
        BoundedResolution::Complete {
            value: Some(target),
            work: receiver_work,
        } => {
            lookup.work.examined_candidates = lookup
                .work
                .examined_candidates
                .saturating_add(receiver_work.setup_nodes)
                .saturating_add(receiver_work.scope_nodes)
                .saturating_add(receiver_work.summary_expansions);
            apply_go_typed_selector_target(lookup, target);
        }
        BoundedResolution::Complete {
            value: None,
            work: receiver_work,
        }
        | BoundedResolution::Exceeded {
            work: receiver_work,
            ..
        } => {
            lookup.work.examined_candidates = lookup
                .work
                .examined_candidates
                .saturating_add(receiver_work.setup_nodes)
                .saturating_add(receiver_work.scope_nodes)
                .saturating_add(receiver_work.summary_expansions);
        }
        BoundedResolution::Cancelled { .. } => lookup.cancelled = true,
    }
}

fn apply_go_typed_selector_target(lookup: &mut CallDispatchLookup, target: GoTypedSelectorTarget) {
    lookup.targets.clear();
    lookup.boundaries.clear();
    lookup.adjudicated_no_target = false;
    lookup.adjudicated_non_callable = false;
    lookup.truncated = false;
    lookup.budget_exhausted = false;
    lookup.exact_external_call = None;
    lookup.boundary = None;
    lookup.dispatch_extensibility = None;
    lookup.go_interface_receiver = target.receiver_is_interface;
    lookup.go_selector_member = Some(target.member.clone());
    if !target.workspace_methods.is_empty() {
        let ambiguous = target.workspace_methods.len() > 1;
        lookup
            .targets
            .extend(
                target
                    .workspace_methods
                    .into_iter()
                    .map(|method| CallDispatchTarget {
                        definition: method,
                        proof: if ambiguous {
                            UsageProof::Unproven
                        } else {
                            UsageProof::Proven
                        },
                        native_incomplete_source_reason: None,
                    }),
            );
        lookup.status = Some(if ambiguous {
            DefinitionLookupStatus::Ambiguous
        } else {
            DefinitionLookupStatus::Resolved
        });
        lookup.call_application = CallApplicationKind::BoundReceiver;
        if ambiguous {
            lookup
                .boundaries
                .push(CallDispatchBoundaryKind::UnresolvedReason(
                    "Go method selection retains multiple promoted declarations".into(),
                ));
        }
        if target.receiver_is_interface {
            lookup
                .boundaries
                .push(CallDispatchBoundaryKind::UnresolvedReason(
                    "Go interface implementations are not closed by the analyzed module".into(),
                ));
        }
        return;
    }
    let Some(callee) = target.external_callee else {
        return;
    };
    let Some(external_call) = target.external_call else {
        return;
    };
    lookup.status = Some(DefinitionLookupStatus::UnresolvableImportBoundary);
    lookup.boundary = Some(BoundaryStatus::ExternalIndexed);
    lookup.call_application = external_call.call_application();
    lookup.dispatch_extensibility = external_call.dispatch_extensibility();
    lookup.exact_external_call = Some(external_call);
    lookup.boundaries.push(CallDispatchBoundaryKind::External {
        callee_text: Some(callee.into_boxed_str()),
        normalized_static_owner: None,
        external_callee_identity: target.external_concrete_owner_fqn.map(|owner| {
            ResolverOwnedExternalCalleeIdentity::new(Language::Go, owner, target.member.clone())
        }),
    });
    if target.receiver_is_interface {
        lookup
            .boundaries
            .push(CallDispatchBoundaryKind::UnresolvedReason(
                "Go interface implementations are not closed by the analyzed module".into(),
            ));
    }
}

impl CallRelationService {
    pub(crate) fn dispatch_session(
        file: ProjectFile,
        exact_source: Arc<str>,
    ) -> CallDispatchSession {
        CallDispatchSession {
            language: language_for_file(&file),
            file,
            exact_source,
            parse: CallDispatchParse::Uninitialized,
            file_evidence: ExternalCalleeFileEvidence::default(),
            cpp_dispatch_cache: HashMap::default(),
            cpp_dispatch_prefetched: false,
            expected_calls: Vec::new(),
            callee_outcomes: HashMap::default(),
            prefetched_callees: HashSet::default(),
            prefetched_expansions: HashMap::default(),
        }
    }

    /// Resolve one exact whole-call span against one exact source snapshot.
    ///
    /// The caller supplies the source owned by the semantic artifact's
    /// revision. This method never rereads the file, so its byte span cannot
    /// race a newer disk or overlay snapshot. The same batched definition
    /// resolution core is used by legacy outgoing call relations below.
    #[cfg(test)]
    pub(crate) fn dispatch_at_bounded(
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        location: &ExactCallLocation,
        exact_source: Arc<str>,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> CallDispatchLookup {
        Self::dispatch_many_at_bounded(
            analyzer,
            token,
            &location.file,
            std::slice::from_ref(&location.call_span),
            exact_source,
            limits,
            cancellation,
        )
        .pop()
        .expect("one exact call location produces one dispatch lookup")
    }

    /// Resolve several exact call spans in one source snapshot with one parse
    /// and one definition-resolution batch.
    ///
    /// This is crate-visible only so analyzer-owned projections can reject
    /// broad structural candidates before semantic lowering without exposing
    /// low-level dispatch boundaries as public API. `max_candidates` applies
    /// independently to each call's target set, not to `call_spans` itself.
    pub(crate) fn dispatch_many_at_bounded(
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        file: &ProjectFile,
        call_spans: &[Range],
        exact_source: Arc<str>,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> Vec<CallDispatchLookup> {
        let repeated = |lookup: CallDispatchLookup| vec![lookup; call_spans.len()];
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return repeated(CallDispatchLookup {
                cancelled: true,
                ..CallDispatchLookup::default()
            });
        }
        if limits.max_files == 0 || limits.max_source_bytes == 0 || limits.max_candidates == 0 {
            return repeated(CallDispatchLookup {
                budget_exhausted: true,
                diagnostics: vec![format!("exact call dispatch budget omitted {file}")],
                ..CallDispatchLookup::default()
            });
        }
        if exact_source.len() > limits.max_source_bytes {
            return repeated(CallDispatchLookup {
                budget_exhausted: true,
                diagnostics: vec![format!("exact call dispatch source budget omitted {file}")],
                ..CallDispatchLookup::default()
            });
        }

        let work = CallRelationWork {
            scanned_files: 1,
            scanned_source_bytes: exact_source.len(),
            examined_candidates: 1,
        };
        let language = language_for_file(file);
        if language == Language::None {
            return repeated(unresolved_dispatch_lookup(
                DefinitionLookupStatus::UnsupportedLanguage,
                "exact call dispatch does not support this file language".to_string(),
                work,
            ));
        }
        let syntax = match CallDispatchSyntax::parse(file, language, &exact_source, cancellation) {
            Ok(syntax) => syntax,
            Err(stop) => return repeated(stopped_dispatch_syntax(&stop, work)),
        };
        let Some(syntax) = syntax else {
            return repeated(unresolved_dispatch_lookup(
                DefinitionLookupStatus::NotFound,
                format!("failed to parse {file} for exact call dispatch"),
                work,
            ));
        };
        let mut lookups = vec![None; call_spans.len()];
        let mut resolvable = Vec::with_capacity(call_spans.len());
        for (index, call_span) in call_spans.iter().enumerate() {
            let tree = syntax.tree(call_span);
            if let Some(lookup) = language_support(language)
                .and_then(|support| support.call_relation_provider())
                .and_then(|provider| {
                    provider.dispatch_special_call_site(CallDispatchLanguageRequest {
                        analyzer,
                        token,
                        file,
                        source: &exact_source,
                        tree,
                        call_span,
                        cancellation,
                        work,
                    })
                })
            {
                lookups[index] = Some(lookup);
                continue;
            }
            match exact_call_reference_for_call(tree, language, call_span) {
                Some(ExactCallReference::Resolvable(range)) => resolvable.push((index, range)),
                Some(ExactCallReference::Unsupported(
                    ExactCallReferenceGap::RubyCallableObject,
                )) => {
                    lookups[index] = Some(unresolved_dispatch_lookup(
                        DefinitionLookupStatus::NoDefinition,
                        "unsupported_ruby_callable_object_dispatch: resolving `receiver.(...)` requires value/heap callable-target information"
                            .to_string(),
                        work,
                    ));
                }
                Some(ExactCallReference::Unsupported(ExactCallReferenceGap::CallOfValue)) => {
                    lookups[index] = Some(unresolved_dispatch_lookup(
                        DefinitionLookupStatus::NoDefinition,
                        "unsupported_call_of_value: callee expression does not name a declaration; dispatch requires callable-value information".to_string(),
                        work,
                    ));
                }
                None => {
                    lookups[index] = Some(unresolved_dispatch_lookup(
                        DefinitionLookupStatus::InvalidLocation,
                        format!(
                            "range [{}, {}) is not one exact supported call expression in {file}",
                            call_span.start_byte, call_span.end_byte
                        ),
                        work,
                    ));
                }
            }
        }
        let references = resolvable
            .iter()
            .map(|(_, range)| *range)
            .collect::<Vec<_>>();
        let batch = resolve_call_references_with_source(
            analyzer,
            token,
            file,
            Arc::clone(&exact_source),
            &syntax.primary,
            &references,
            cancellation,
        );
        // One memo for the whole file: every site below classifies its callee
        // against the same exact source and admitted syntax forest.
        let file_evidence = ExternalCalleeFileEvidence::default();
        for ((index, callee_range), (_, outcome)) in resolvable.iter().zip(batch.resolved) {
            let tree = syntax.tree(&call_spans[*index]);
            let mut lookup = CallDispatchLookup {
                cancelled: batch.cancelled,
                work,
                ..CallDispatchLookup::default()
            };
            if outcome.outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary {
                lookup.boundary = Some(call_target_boundary_evidence(analyzer, file, &outcome));
            }
            let site = ExternalCalleeSite {
                source: &exact_source,
                tree,
                callee_start_byte: callee_range.start_byte,
                file_evidence: &file_evidence,
            };
            apply_call_target_outcome(
                Some(analyzer),
                &mut lookup,
                expand_imported_external_callee(analyzer, file, outcome, Some(&site)),
                limits.max_candidates,
                language,
                Some(&site),
            );
            refine_resolved_call_target_proofs(&mut lookup, language, analyzer, token, file, &site);
            if language == Language::Go {
                apply_go_typed_selector_target_at_call(
                    &mut lookup,
                    analyzer,
                    token,
                    file,
                    &exact_source,
                    tree,
                    callee_range,
                    cancellation,
                );
            }
            lookups[*index] = Some(lookup);
        }
        let cancelled =
            batch.cancelled || cancellation.is_some_and(CancellationToken::is_cancelled);
        lookups
            .into_iter()
            .map(|lookup| {
                let mut lookup = lookup.unwrap_or_else(|| {
                    if cancelled {
                        CallDispatchLookup {
                            cancelled: true,
                            work,
                            ..CallDispatchLookup::default()
                        }
                    } else {
                        unresolved_dispatch_lookup(
                            DefinitionLookupStatus::NotFound,
                            "definition resolver returned no outcome for the exact call reference"
                                .to_string(),
                            work,
                        )
                    }
                });
                lookup.cancelled |= cancelled;
                lookup
            })
            .collect()
    }

    pub fn incoming(
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        target: &CodeUnit,
        max_files: usize,
        max_sites: usize,
    ) -> CallRelationResult {
        Self::incoming_bounded(
            analyzer,
            token,
            target,
            unbounded_call_relation_limits(max_files, max_sites),
            None,
        )
    }

    pub fn incoming_bounded(
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        target: &CodeUnit,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> CallRelationResult {
        let result = Self::incoming_bounded_inner(analyzer, token, target, limits, cancellation);
        record_call_relation_read(
            analyzer,
            crate::analyzer::read_ledger::LookupKind::Callers,
            target,
            &result,
        );
        result
    }

    fn incoming_bounded_inner(
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        target: &CodeUnit,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> CallRelationResult {
        if !is_call_relation_unit(target) {
            return CallRelationResult::default();
        }
        if limits.max_files == 0 || limits.max_source_bytes == 0 || limits.max_candidates == 0 {
            let context = target.fq_name().to_string();
            return CallRelationResult {
                truncated: true,
                diagnostics: vec![CallRelationDiagnostic::new(
                    CallRelationDiagnosticCode::BudgetExhausted,
                    format!("call relation budget omitted {}", target.fq_name()),
                    context,
                )],
                ..CallRelationResult::default()
            };
        }
        if let Some(provider) = language_support(language_for_file(target.source()))
            .and_then(|support| support.call_relation_provider())
        {
            let mut answer = provider.incoming(analyzer, target, limits, cancellation);
            answer.proof_authority = provider.proof_authority();
            return answer;
        }
        let mut finder = UsageFinder::new();
        if let Some(cancellation) = cancellation {
            finder = finder.with_cancellation(cancellation.clone());
        }
        let query = finder.query_with_source_budget(
            analyzer,
            std::slice::from_ref(target),
            limits.max_files,
            limits.max_candidates,
            limits.max_source_bytes,
        );
        let mut work = CallRelationWork {
            scanned_files: query.candidate_files.len(),
            scanned_source_bytes: query.scanned_source_bytes,
            examined_candidates: 0,
        };
        let query_cancelled = query.completion == UsageQueryCompletion::Cancelled;
        let (mut hits, mut truncated, mut diagnostics) = call_hits(query.result, target);
        if query.source_bytes_truncated {
            diagnostics.push(CallRelationDiagnostic::new(
                CallRelationDiagnosticCode::BudgetExhausted,
                format!(
                    "call relation source-byte budget truncated candidate files for {}",
                    target.fq_name()
                ),
                target.fq_name().to_string(),
            ));
        }
        if query.candidate_files_truncated {
            diagnostics.push(CallRelationDiagnostic::new(
                CallRelationDiagnosticCode::BudgetExhausted,
                format!(
                    "call relation file budget truncated candidate files for {}",
                    target.fq_name()
                ),
                target.fq_name().to_string(),
            ));
        }
        truncated |= query.candidate_files_truncated || query.source_bytes_truncated;
        let mut syntax_cache = CallSyntaxCache::default();
        let mut sites = Vec::new();
        let mut cancelled = query_cancelled;
        truncated |= query_cancelled;
        let mut omitted = 0usize;
        // call_hits flattens HashMaps, so its order varies between runs. Sort
        // before the cap so the retained candidates are the same on every run.
        // Proven hits sort first, so the cap does not drop a proven caller in
        // favor of an unproven one from an earlier file.
        hits.sort_by(|(left, left_proof), (right, right_proof)| {
            proof_rank(*left_proof)
                .cmp(&proof_rank(*right_proof))
                .then_with(|| left.file.cmp(&right.file))
                .then_with(|| left.start_offset.cmp(&right.start_offset))
                .then_with(|| left.end_offset.cmp(&right.end_offset))
                .then_with(|| left.enclosing.cmp(&right.enclosing))
                .then_with(|| left.kind.cmp(&right.kind))
        });
        if hits.len() > limits.max_candidates {
            truncated = true;
            diagnostics.push(CallRelationDiagnostic::new(
                CallRelationDiagnosticCode::CandidateLimit,
                format!(
                    "call relation retained the first {} call candidates for {}",
                    limits.max_candidates,
                    target.fq_name()
                ),
                target.fq_name().to_string(),
            ));
        }
        hits.truncate(limits.max_candidates);
        for (hit, proof) in hits {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                cancelled = true;
                truncated = true;
                break;
            }
            if !matches!(
                hit.kind,
                UsageHitKind::Reference | UsageHitKind::SelfReceiver
            ) {
                continue;
            }
            work.examined_candidates = work.examined_candidates.saturating_add(1);
            match project_incoming_call_hit(analyzer, &mut syntax_cache, target, hit, proof) {
                Ok(site) => sites.push(site),
                Err(IncomingCallOmission::KeywordLabel) => {}
                Err(
                    IncomingCallOmission::CallerUnavailable
                    | IncomingCallOmission::SyntaxUnavailable,
                ) => {
                    omitted = omitted.saturating_add(1);
                }
            }
        }
        if omitted > 0 {
            truncated = true;
            append_incoming_projection_omission(&mut diagnostics, target, omitted);
        }

        // Usage graphs intentionally suppress references enclosed by the target
        // itself. Recover those exact recursive edges from the target's own
        // outgoing relation so incoming and outgoing traversal stay symmetric.
        if !cancelled {
            let recursive = Self::outgoing_bounded(
                analyzer,
                token,
                target,
                CallRelationLimits {
                    max_files: limits.max_files.saturating_sub(work.scanned_files),
                    max_source_bytes: limits
                        .max_source_bytes
                        .saturating_sub(work.scanned_source_bytes),
                    max_candidates: limits
                        .max_candidates
                        .saturating_sub(work.examined_candidates),
                },
                cancellation,
            );
            work.add(recursive.work);
            truncated |= recursive.truncated;
            cancelled |= recursive.cancelled;
            diagnostics.extend(recursive.diagnostics);
            sites.extend(
                recursive
                    .sites
                    .into_iter()
                    .filter(|site| site.caller == *target && site.callee == *target),
            );
        }

        sort_and_dedup_sites(&mut sites);
        if sites.len() > limits.max_candidates {
            sites.truncate(limits.max_candidates);
            truncated = true;
            diagnostics.push(CallRelationDiagnostic::new(
                CallRelationDiagnosticCode::CandidateLimit,
                format!(
                    "call relation retained the first {} call candidates for {}",
                    limits.max_candidates,
                    target.fq_name()
                ),
                target.fq_name().to_string(),
            ));
        }
        diagnostics.sort();
        diagnostics.dedup();
        CallRelationResult {
            sites,
            truncated,
            cancelled,
            diagnostics,
            proof_authority: UsageProofAuthority::Legacy,
            work,
        }
    }

    pub fn outgoing(
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        caller: &CodeUnit,
        max_sites: usize,
    ) -> CallRelationResult {
        Self::outgoing_bounded(
            analyzer,
            token,
            caller,
            unbounded_call_relation_limits(1, max_sites),
            None,
        )
    }

    pub fn outgoing_bounded(
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        caller: &CodeUnit,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> CallRelationResult {
        let result = Self::outgoing_bounded_inner(analyzer, token, caller, limits, cancellation);
        record_call_relation_read(
            analyzer,
            crate::analyzer::read_ledger::LookupKind::Callees,
            caller,
            &result,
        );
        result
    }

    fn outgoing_bounded_inner(
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        caller: &CodeUnit,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> CallRelationResult {
        if !is_call_relation_unit(caller) {
            return CallRelationResult::default();
        }
        if let Some(provider) = language_support(language_for_file(caller.source()))
            .and_then(|support| support.call_relation_provider())
        {
            let mut answer = provider.outgoing(analyzer, caller, limits, cancellation);
            answer.proof_authority = provider.proof_authority();
            return answer;
        }
        if limits.max_files == 0 || limits.max_source_bytes == 0 || limits.max_candidates == 0 {
            let context = caller.fq_name().to_string();
            return CallRelationResult {
                truncated: true,
                diagnostics: vec![CallRelationDiagnostic::new(
                    CallRelationDiagnosticCode::BudgetExhausted,
                    format!("call relation budget omitted {}", caller.fq_name()),
                    context,
                )],
                ..CallRelationResult::default()
            };
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return CallRelationResult {
                truncated: true,
                cancelled: true,
                ..CallRelationResult::default()
            };
        }
        let Some(source) = analyzer
            .indexed_source(caller.source())
            .map(Arc::<str>::from)
        else {
            return CallRelationResult {
                diagnostics: vec![CallRelationDiagnostic::analysis_failed(
                    format!("indexed source is unavailable for {}", caller.source()),
                    caller.fq_name().to_string(),
                    "indexed_source_unavailable".to_string(),
                )],
                ..CallRelationResult::default()
            };
        };
        if source.len() > limits.max_source_bytes || limits.max_files == 0 {
            let context = caller.source().to_string();
            return CallRelationResult {
                truncated: true,
                diagnostics: vec![CallRelationDiagnostic::new(
                    CallRelationDiagnosticCode::BudgetExhausted,
                    format!("call relation budget omitted {}", caller.source()),
                    context,
                )],
                ..CallRelationResult::default()
            };
        }
        let language = language_for_file(caller.source());
        let Some(tree) = parse_tree_for_language(caller.source(), language, &source) else {
            return CallRelationResult {
                diagnostics: vec![CallRelationDiagnostic::new(
                    CallRelationDiagnosticCode::ParseFailed,
                    format!("failed to parse {}", caller.source()),
                    caller.source().to_string(),
                )],
                ..CallRelationResult::default()
            };
        };
        let Some(caller_range) = analyzer.ranges_of(caller).into_iter().min_by_key(range_key)
        else {
            return CallRelationResult {
                diagnostics: vec![CallRelationDiagnostic::analysis_failed(
                    format!("declaration range is unavailable for {}", caller.fq_name()),
                    caller.fq_name().to_string(),
                    "declaration_range_unavailable".to_string(),
                )],
                ..CallRelationResult::default()
            };
        };
        let candidate_limit = limits.max_candidates.saturating_add(1);
        let candidates =
            call_reference_ranges_in_tree(&tree, language, &caller_range, candidate_limit);
        let mut truncated = candidates.len() > limits.max_candidates;
        let mut diagnostics = truncated
            .then(|| {
                CallRelationDiagnostic::new(
                    CallRelationDiagnosticCode::CandidateLimit,
                    format!(
                        "call relation retained the first {} call candidates for {}",
                        limits.max_candidates,
                        caller.fq_name()
                    ),
                    caller.fq_name().to_string(),
                )
            })
            .into_iter()
            .collect::<Vec<_>>();
        let candidates = candidates
            .into_iter()
            .take(limits.max_candidates)
            .collect::<Vec<_>>();
        let batch = resolve_call_references_with_source(
            analyzer,
            token,
            caller.source(),
            Arc::clone(&source),
            &tree,
            &candidates,
            cancellation,
        );
        let mut sites = Vec::new();
        let mut syntax_cache = CallSyntaxCache::default();
        let mut ambiguous = 0usize;
        let mut retained_ambiguous = 0usize;
        let mut omitted = 0usize;
        let mut navigation_truncated = false;
        for (candidate, outcome) in batch.resolved {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                break;
            }
            if outcome.exact_external_call.is_some() {
                // The resolver has named a callable outside the indexed
                // workspace. It is a complete boundary leaf for this
                // declaration traversal, even though it has no CodeUnit to
                // publish as a workspace callee. Counting it as an omitted
                // candidate makes a caller relation incomplete for a call
                // whose identity is already proven structurally. Rust publishes
                // the resolver-owned identity with the proof; Go's native
                // adapter publishes the proof alone, and neither is read here.
                assert!(
                    outcome.outcome.definitions.is_empty(),
                    "an exact external call cannot also have workspace definitions"
                );
                continue;
            }
            let uncertain_identity = outcome.structure_unavailable || outcome.unproven_link_unit;
            if outcome.truncated {
                navigation_truncated = true;
                truncated = true;
                omitted = omitted.saturating_add(1);
            }
            let mut resolution = resolve_outgoing_call_candidate(
                analyzer,
                outcome.outcome.status,
                outcome.outcome.definitions,
            );
            if uncertain_identity && resolution.proof.is_some() {
                resolution.proof = Some(UsageProof::Unproven);
            }
            let Some(proof) = resolution.proof else {
                omitted = omitted.saturating_add(resolution.omitted);
                continue;
            };
            ambiguous = ambiguous.saturating_add(usize::from(resolution.ambiguous));
            let Some(syntax) = syntax_cache.syntax_for_range(
                analyzer,
                caller.source(),
                candidate.start_byte,
                candidate.end_byte,
            ) else {
                omitted = omitted.saturating_add(1);
                continue;
            };
            omitted = omitted.saturating_add(resolution.omitted);
            if resolution.ambiguous && resolution.fully_retained && !outcome.truncated {
                retained_ambiguous = retained_ambiguous.saturating_add(1);
            }
            for callee in resolution.callees {
                sites.push(raw_call_site(
                    caller.source().clone(),
                    caller.clone(),
                    callee,
                    syntax.clone(),
                    proof,
                ));
            }
        }
        if navigation_truncated
            && !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CallRelationDiagnosticCode::CandidateLimit)
        {
            diagnostics.push(CallRelationDiagnostic::new(
                CallRelationDiagnosticCode::CandidateLimit,
                format!(
                    "call relation target navigation was truncated for {}",
                    caller.fq_name()
                ),
                caller.fq_name().to_string(),
            ));
        }
        append_outgoing_candidate_diagnostics(
            &mut diagnostics,
            caller,
            ambiguous,
            retained_ambiguous,
            omitted,
        );
        sort_and_dedup_sites(&mut sites);
        CallRelationResult {
            sites,
            truncated,
            cancelled: batch.cancelled,
            diagnostics,
            proof_authority: UsageProofAuthority::Legacy,
            work: CallRelationWork {
                scanned_files: 1,
                scanned_source_bytes: source.len(),
                examined_candidates: candidates.len(),
            },
        }
    }
}

struct CallReferenceResolutionBatch {
    resolved: Vec<(Range, CallTargetLookupOutcome)>,
    cancelled: bool,
}

fn call_target_boundary_evidence(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    outcome: &CallTargetLookupOutcome,
) -> BoundaryStatus {
    let resolved_target = outcome
        .outcome
        .resolved_reference_target()
        .unwrap_or_default();
    if let Some(exact_target) = outcome.exact_external_call.as_ref() {
        debug_assert_eq!(
            exact_target.canonical_callee(),
            resolved_target,
            "exact external call proof must name the returned boundary"
        );
        if exact_target.canonical_callee() == resolved_target {
            return BoundaryStatus::ExternalIndexed;
        }
    }
    if language_for_file(file) == Language::Go
        && outcome.outcome.diagnostics.iter().any(|diagnostic| {
            diagnostic.claim.as_ref().is_some_and(|claim| {
                claim.kind == super::get_definition::UnindexedClaimKind::ExternalBoundary
                    && claim.role == super::get_definition::ClaimSubjectRole::Module
                    && claim.subjects.iter().any(|subject| {
                        super::get_definition::trace::boundary_evidence(analyzer, file, subject).0
                            == BoundaryStatus::ExternalIndexed
                    })
            })
        })
    {
        return BoundaryStatus::ExternalIndexed;
    }
    super::get_definition::trace::call_target_boundary_evidence(analyzer, file, resolved_target).0
}

/// Resolve already-structured call reference ranges in one shared batch.
/// Exact semantic dispatch supplies one range; outgoing call relations supply
/// every range in the caller. Cancellation may shorten the lower-level result
/// vector, so pairing is retained explicitly rather than silently assuming
/// one outcome per request.
fn resolve_call_references_with_source(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: Arc<str>,
    tree: &tree_sitter::Tree,
    references: &[Range],
    cancellation: Option<&CancellationToken>,
) -> CallReferenceResolutionBatch {
    let requests = references
        .iter()
        .map(|range| DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(range.start_byte),
            end_byte: (!call_reference_requires_point_lookup(tree, language_for_file(file), range))
                .then_some(range.end_byte),
        })
        .collect();
    let outcomes = resolve_call_target_batch_with_source(
        analyzer,
        token,
        requests,
        file.clone(),
        source,
        cancellation,
    );
    let resolved = references.iter().copied().zip(outcomes).collect::<Vec<_>>();
    CallReferenceResolutionBatch {
        resolved,
        cancelled: cancellation.is_some_and(CancellationToken::is_cancelled),
    }
}

pub(crate) fn unresolved_dispatch_lookup(
    status: DefinitionLookupStatus,
    diagnostic: String,
    work: CallRelationWork,
) -> CallDispatchLookup {
    CallDispatchLookup {
        status: Some(status),
        boundaries: vec![CallDispatchBoundaryKind::Unresolved(status)],
        diagnostics: vec![diagnostic],
        work,
        ..CallDispatchLookup::default()
    }
}

fn unresolved_call_boundary(
    status: DefinitionLookupStatus,
    callee_text: Option<Box<str>>,
    normalized_static_owner: Option<Box<str>>,
) -> CallDispatchBoundaryKind {
    match callee_text {
        Some(callee_text) => CallDispatchBoundaryKind::UnresolvedWithTarget {
            status,
            callee_text,
            normalized_static_owner,
        },
        None => CallDispatchBoundaryKind::Unresolved(status),
    }
}

#[cfg(test)]
/// The test-facing entry point, which has no parsed file behind it. A call
/// site with no file evidence can never admit a single-segment external owner;
/// that decision belongs to [`apply_call_target_outcome`], which the production
/// path uses.
fn apply_dispatch_outcome(
    lookup: &mut CallDispatchLookup,
    outcome: DefinitionLookupOutcome,
    max_targets: usize,
    language: Language,
) {
    apply_dispatch_outcome_with_flags(
        lookup,
        outcome,
        max_targets,
        language,
        super::get_definition::DefinitionResolutionAuthority::Incumbent,
        None,
        None,
        None,
        false,
        false,
        false,
        false,
        None,
        None,
    );
}

/// Give the owning language a chance to expand an imported callee spelling to
/// the external identity that semantic models publish.
///
/// Both statuses that can publish an external boundary carrying a callee text
/// are offered the expansion. Java's import-qualified callees land on
/// `NoDefinition` (#2364); Rust's land on `UnresolvableImportBoundary`, because
/// its resolver followed the `use` out of the workspace before giving up
/// (#2596). Gating on only one of the two would have made the expansion dead
/// for one of the two languages that implement it.
///
/// The returned bit is provenance, not a convenience flag. Kotlin's dotted
/// source spelling can be a receiver-expression chain, so that language may
/// publish the expanded text only when its external declaration resolver
/// produced it.
fn expand_imported_external_callee(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    outcome: CallTargetLookupOutcome,
    site: Option<&ExternalCalleeSite<'_>>,
) -> ExpandedExternalCallee {
    expand_imported_external_callee_with_prefetched(analyzer, file, outcome, site, None)
}

fn expand_imported_external_callee_with_prefetched(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    mut outcome: CallTargetLookupOutcome,
    site: Option<&ExternalCalleeSite<'_>>,
    prefetched: Option<&CompletedExpansion>,
) -> ExpandedExternalCallee {
    if matches!(language_for_file(file), Language::Java | Language::Go)
        && matches!(
            outcome.authority,
            super::get_definition::DefinitionResolutionAuthority::NativeJavaSelected
                | super::get_definition::DefinitionResolutionAuthority::NativeGoSelected
        )
    {
        return ExpandedExternalCallee {
            resolver_proven_identity: outcome.exact_external_call.is_some()
                || outcome.external_callee_identity.is_some(),
            outcome,
        };
    }
    let language = language_for_file(file);
    let python_resolved_call =
        language == Language::Python && outcome.outcome.status == DefinitionLookupStatus::Resolved;
    let kotlin_import_resolved_without_target = language == Language::Kotlin
        && outcome.outcome.status == DefinitionLookupStatus::Resolved
        && outcome.outcome.definitions.is_empty();
    if !kotlin_import_resolved_without_target
        && !python_resolved_call
        && !matches!(
            outcome.outcome.status,
            DefinitionLookupStatus::NoDefinition
                | DefinitionLookupStatus::UnresolvableImportBoundary
        )
    {
        return ExpandedExternalCallee::unproven(outcome);
    }
    let structured_kotlin_callee = kotlin_import_resolved_without_target
        .then(|| site.and_then(kotlin_callee_text))
        .flatten();
    let structured_python_callee = (language == Language::Python)
        .then(|| site.and_then(python_callee_text))
        .flatten();
    let Some(text) = structured_kotlin_callee
        .or_else(|| outcome.outcome.resolved_reference_target())
        .or(structured_python_callee)
    else {
        return ExpandedExternalCallee::unproven(outcome);
    };
    let expanded = match prefetched {
        Some(answer) => answer.as_ref().map(|(proof, identity)| {
            crate::analyzer::languages::ImportedExternalCallee::proven(
                proof.clone(),
                identity.clone(),
            )
        }),
        None => language_support(language_for_file(file)).and_then(|support| {
            support.expand_imported_external_callee(analyzer, file, text, site)
        }),
    };
    let Some(expanded) = expanded else {
        return ExpandedExternalCallee::unproven(outcome);
    };
    if let Some(reference) = outcome.outcome.reference.as_mut() {
        reference.text = expanded.canonical_callee;
    }
    // A language that selected the callable itself carries its exact proof and
    // owner/member identity into the common dispatch path, where they replace
    // the spelling-derived identity the boundary would otherwise mint from
    // text. The proof also states how the selected callable takes its
    // receiver, which is the same fact the written-out route records beside
    // its proof, so the call shape and the declaration it describes stay one
    // answer. An expansion that only translated a spelling leaves whatever the
    // resolver already proved exactly as it was.
    if let Some(proof) = expanded.exact_external_call {
        outcome.call_application = proof.call_application();
        outcome.dispatch_extensibility = proof.dispatch_extensibility();
        outcome.exact_external_call = Some(proof);
        outcome.external_callee_identity = expanded.external_callee_identity;
        if language == Language::Python
            && outcome.outcome.status == DefinitionLookupStatus::Resolved
        {
            // The Python adapter's exact import or ctypes proof identifies a
            // package callable behind the resolved local binding. Preserve
            // that external boundary instead of also publishing the
            // intermediate import/handle assignment as a callable target.
            outcome.outcome.status = DefinitionLookupStatus::UnresolvableImportBoundary;
            outcome.outcome.modeled_definitions.clear();
            outcome.outcome.definitions.clear();
            outcome.outcome.lexical_definition = None;
        }
    }
    // Kotlin can resolve the local import binding while still having no
    // workspace definition for the imported member. Once the external-member
    // resolver proves that member, preserve the import cut as an external
    // boundary instead of reporting a targetless `Resolved` outcome.
    if kotlin_import_resolved_without_target {
        outcome.outcome.status = DefinitionLookupStatus::UnresolvableImportBoundary;
    }
    ExpandedExternalCallee {
        outcome,
        resolver_proven_identity: true,
    }
}

/// Apply the same Python identity adapter used by exact call dispatch to the
/// resolver-backed call-target cache. RQL call-shape consumers share this
/// cache and otherwise bypassed the adapter entirely.
fn expand_python_call_target_identity(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &tree_sitter::Tree,
    callee_range: Range,
    file_evidence: &ExternalCalleeFileEvidence,
    outcome: CallTargetLookupOutcome,
) -> CallTargetLookupOutcome {
    let site = ExternalCalleeSite {
        source,
        tree,
        callee_start_byte: callee_range.start_byte,
        file_evidence,
    };
    expand_imported_external_callee(analyzer, file, outcome, Some(&site)).outcome
}

fn python_callee_text<'a>(site: &ExternalCalleeSite<'a>) -> Option<&'a str> {
    let start = site.callee_start_byte;
    let mut callee = site
        .tree
        .root_node()
        .named_descendant_for_byte_range(start, start.checked_add(1)?)?;
    loop {
        let parent = callee.parent()?;
        if parent.kind() == "attribute" && parent.child_by_field_name("attribute") == Some(callee) {
            callee = parent;
            continue;
        }
        if parent.kind() == "call" && parent.child_by_field_name("function") == Some(callee) {
            return site.source.get(callee.byte_range());
        }
        return None;
    }
}

fn kotlin_callee_text<'a>(site: &'a ExternalCalleeSite<'_>) -> Option<&'a str> {
    let mut node = site.tree.root_node().named_descendant_for_byte_range(
        site.callee_start_byte,
        site.callee_start_byte.saturating_add(1),
    )?;
    while node.kind() != "call_expression" {
        node = node.parent()?;
    }
    let callee = language_support(Language::Kotlin)?.call_callee_node(node)?;
    site.source.get(callee.byte_range())
}

struct ExpandedExternalCallee {
    outcome: CallTargetLookupOutcome,
    resolver_proven_identity: bool,
}

impl ExpandedExternalCallee {
    fn unproven(outcome: CallTargetLookupOutcome) -> Self {
        Self {
            outcome,
            resolver_proven_identity: false,
        }
    }
}

fn apply_call_target_outcome(
    analyzer: Option<&dyn IAnalyzer>,
    lookup: &mut CallDispatchLookup,
    expanded: ExpandedExternalCallee,
    max_targets: usize,
    language: Language,
    site: Option<&ExternalCalleeSite<'_>>,
) {
    let ExpandedExternalCallee {
        outcome,
        resolver_proven_identity,
    } = expanded;
    let native_incomplete_source_reason = outcome
        .unique_incomplete_native_source_candidate()
        .map(|(_, reason)| Box::<str>::from(reason));
    let CallTargetLookupOutcome {
        outcome,
        authority,
        call_application,
        dispatch_extensibility,
        exact_external_call,
        external_callee_identity,
        structure_unavailable,
        unproven_link_unit,
        truncated,
    } = outcome;
    let exact_external_callee = exact_external_call
        .as_ref()
        .map(|proof| Box::<str>::from(proof.canonical_callee()));
    let normalized_static_owner = csharp_normalized_static_owner(
        analyzer,
        language,
        exact_external_callee
            .as_deref()
            .or_else(|| outcome.resolved_reference_target()),
    );
    if let Some(proof) = &exact_external_call {
        debug_assert_eq!(proof.call_application(), call_application);
        debug_assert_eq!(proof.dispatch_extensibility(), dispatch_extensibility);
        debug_assert_eq!(
            proof.canonical_callee(),
            outcome.resolved_reference_target().unwrap_or_default(),
            "exact external proof and returned boundary must retain one identity"
        );
    }
    lookup.call_application = exact_external_call
        .as_ref()
        .map_or(call_application, ExactExternalCallProof::call_application);
    lookup.dispatch_extensibility = exact_external_call.as_ref().map_or(
        dispatch_extensibility,
        ExactExternalCallProof::dispatch_extensibility,
    );
    lookup.exact_external_call = exact_external_call;
    if let Some(identity) = &external_callee_identity {
        debug_assert_eq!(identity.language(), language);
        if let Some(proof) = &lookup.exact_external_call {
            // The proof's text and the identity are two spellings of one
            // callee: the text keeps the language's own separator
            // (`std::net::TcpStream::connect`), while the identity is the
            // structured owner/member pair authored summaries and
            // unmaterialized external targets are indexed under. Cutting the
            // text with the same shared splitter the summary minting side uses
            // compares the two spellings structurally instead of assuming the
            // owner is dot-joined in the text (#3484).
            debug_assert_eq!(
                crate::analyzer::semantic::split_canonical_qualified_callee(
                    proof.canonical_callee(),
                    language,
                ),
                Some((
                    identity.owner_fqn().to_owned(),
                    identity.member().to_owned()
                )),
                "external identity and exact proof must describe one callee"
            );
        }
    }
    apply_dispatch_outcome_with_flags(
        lookup,
        outcome,
        max_targets,
        language,
        authority,
        exact_external_callee,
        external_callee_identity,
        site,
        resolver_proven_identity,
        structure_unavailable,
        unproven_link_unit,
        truncated,
        native_incomplete_source_reason,
        normalized_static_owner,
    );
}

/// The arguments are the outcome plus the four independent facts the caller
/// already proved about it; a struct would only rename them.
#[allow(clippy::too_many_arguments)]
fn apply_dispatch_outcome_with_flags(
    lookup: &mut CallDispatchLookup,
    outcome: DefinitionLookupOutcome,
    max_targets: usize,
    language: Language,
    authority: super::get_definition::DefinitionResolutionAuthority,
    exact_external_callee: Option<Box<str>>,
    external_callee_identity: Option<ResolverOwnedExternalCalleeIdentity>,
    site: Option<&ExternalCalleeSite<'_>>,
    resolver_proven_external_identity: bool,
    structure_unavailable: bool,
    unproven_link_unit: bool,
    navigation_targets_truncated: bool,
    native_incomplete_source_reason: Option<Box<str>>,
    normalized_static_owner: Option<Box<str>>,
) {
    let DefinitionLookupOutcome {
        modeled_definitions,
        status,
        mut definitions,
        lexical_definition,
        diagnostics,
        reference,
    } = outcome;
    let native_java_ambiguity_is_complete = diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "ambiguous_definition")
        && !diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "incomplete_binding");
    // A resolver-owned exact proof is already canonical and outranks syntax
    // classification; this is how an imported single-segment Python owner such
    // as `subprocess` crosses the boundary without making every
    // `subprocess.run` spelling globally trusted. Otherwise the syntactic
    // callee text (`java.net.URLDecoder.decode`) is the only identity an
    // unmaterialized external callee leaves behind, so canonicalize it once
    // here and retain either one bindable identity or none (#1978, #2598).
    // Kotlin's dotted syntax additionally requires the external-member
    // resolver provenance carried alongside the lookup (#2781).
    let external_callee_text: Option<Box<str>> = exact_external_callee.or_else(|| {
        reference
            .as_ref()
            .and_then(|reference| {
                canonical_external_callee(
                    &reference.text,
                    language,
                    site,
                    resolver_proven_external_identity,
                )
            })
            .map(Box::<str>::from)
    });
    let normalized_static_owner = normalized_static_owner.or_else(|| {
        external_callee_text
            .as_deref()
            .and_then(|callee_text| java_normalized_static_owner(callee_text, language, site))
    });
    let unproven_target_identity = structure_unavailable || unproven_link_unit;
    let partial_external_boundary = diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == PARTIAL_IMPORT_BOUNDARY_DIAGNOSTIC);
    let partial_unresolved_import = diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == PARTIAL_IMPORT_UNRESOLVED_DIAGNOSTIC);
    let import_bindings_truncated = diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == IMPORT_BINDINGS_TRUNCATED_DIAGNOSTIC);
    lookup.adjudicated_no_target |= lexical_definition.is_some()
        || diagnostics
            .iter()
            .any(|diagnostic| is_adjudicated_answer_diagnostic_kind(&diagnostic.kind));
    lookup.adjudicated_non_callable |= diagnostics.iter().any(|diagnostic| {
        diagnostic.kind == GO_MODELED_PACKAGE_CALL_NOT_APPLICABLE_DIAGNOSTIC_KIND
    });
    if lookup.adjudicated_non_callable {
        debug_assert!(
            definitions.is_empty(),
            "a non-callable package member answer never retains a definition"
        );
    }
    lookup.status = Some(status);
    lookup.diagnostics.extend(
        diagnostics
            .into_iter()
            .map(|diagnostic| format!("{}: {}", diagnostic.kind, diagnostic.message)),
    );
    if navigation_targets_truncated {
        lookup.truncated = true;
        lookup.budget_exhausted = true;
        lookup.boundaries.push(CallDispatchBoundaryKind::Truncated);
    }
    if partial_external_boundary {
        lookup.boundaries.push(CallDispatchBoundaryKind::External {
            callee_text: external_callee_text.clone(),
            normalized_static_owner: normalized_static_owner.clone(),
            external_callee_identity: external_callee_identity.clone(),
        });
    }
    if partial_unresolved_import {
        lookup.boundaries.push(unresolved_call_boundary(
            DefinitionLookupStatus::NoDefinition,
            external_callee_text.clone(),
            normalized_static_owner.clone(),
        ));
    }
    if import_bindings_truncated {
        lookup.truncated = true;
        lookup.budget_exhausted = true;
        if !lookup
            .boundaries
            .contains(&CallDispatchBoundaryKind::Truncated)
        {
            lookup.boundaries.push(CallDispatchBoundaryKind::Truncated);
        }
    }

    definitions.sort();
    definitions.dedup();
    let targets_truncated = definitions.len() > max_targets;
    if targets_truncated {
        definitions.truncate(max_targets);
        lookup.truncated = true;
        lookup.budget_exhausted = true;
        if !lookup
            .boundaries
            .contains(&CallDispatchBoundaryKind::Truncated)
        {
            lookup.boundaries.push(CallDispatchBoundaryKind::Truncated);
        }
    }
    let native_java_complete_candidate_set = language == Language::Java
        && authority == super::get_definition::DefinitionResolutionAuthority::NativeJavaSelected
        && status == DefinitionLookupStatus::Ambiguous
        && modeled_definitions.is_empty()
        && lexical_definition.is_none()
        && !structure_unavailable
        && !unproven_link_unit
        && !navigation_targets_truncated
        && !targets_truncated
        && definitions.len() > 1
        && native_incomplete_source_reason.is_none()
        && native_java_ambiguity_is_complete;
    let proof = if (status == DefinitionLookupStatus::Resolved
        || native_java_complete_candidate_set)
        && !unproven_target_identity
    {
        UsageProof::Proven
    } else {
        UsageProof::Unproven
    };
    debug_assert!(
        native_incomplete_source_reason.is_none()
            || (matches!(language, Language::Java | Language::Go)
                && status == DefinitionLookupStatus::Incomplete
                && modeled_definitions.is_empty()
                && lexical_definition.is_none()
                && !structure_unavailable
                && !unproven_link_unit
                && !navigation_targets_truncated
                && definitions.len() == 1),
        "candidate-local binding requires one incomplete selected-native source declaration"
    );
    lookup.targets.extend(
        definitions
            .into_iter()
            .map(|definition| CallDispatchTarget {
                definition,
                proof,
                native_incomplete_source_reason: native_incomplete_source_reason.clone(),
            }),
    );
    if unproven_target_identity {
        lookup
            .boundaries
            .push(CallDispatchBoundaryKind::UnprovenTargetIdentity);
    }

    match status {
        DefinitionLookupStatus::Resolved | DefinitionLookupStatus::Ambiguous
            if lookup.targets.is_empty() =>
        {
            lookup.boundaries.push(unresolved_call_boundary(
                status,
                external_callee_text,
                normalized_static_owner,
            ));
        }
        DefinitionLookupStatus::Resolved | DefinitionLookupStatus::Ambiguous => {}
        DefinitionLookupStatus::UnresolvableImportBoundary => {
            lookup.boundaries.push(CallDispatchBoundaryKind::External {
                callee_text: external_callee_text,
                normalized_static_owner,
                external_callee_identity,
            })
        }
        // #1978: a fully-qualified callee with no workspace or classpath
        // definition (`java.net.URLDecoder.decode`) is external, not merely
        // unresolvable. Java classifies it `NoDefinition` rather than
        // `UnresolvableImportBoundary`, so route only that fully-qualified subset
        // to the external boundary that can carry an activated summary. Every
        // other `NoDefinition` -- an unqualified or single-segment callee -- keeps
        // its unresolved boundary, so the classification blast radius is limited
        // to callees that name a bindable external identity.
        // Go's resolver uses `UnresolvableImportBoundary` after it has proven
        // and canonicalized an imported package qualifier. A `NoDefinition`
        // selector such as `missing.Open` therefore has no package-binding
        // proof: its dotted spelling alone must not mint an exact external
        // identity or turn an applicable modeled member into a clean miss.
        //
        // An adjudicated non-callable model member is the one Go no-definition
        // answer with no unresolved arm to retain: `http.HandlerFunc(f)` is a
        // conversion, so the call expression names no callee at all and its
        // empty target set is complete by the same facts that ruled the
        // function out.
        DefinitionLookupStatus::NoDefinition
            if language == Language::Go && lookup.adjudicated_non_callable => {}
        DefinitionLookupStatus::NoDefinition if language == Language::Go => lookup
            .boundaries
            .push(CallDispatchBoundaryKind::Unresolved(status)),
        DefinitionLookupStatus::NoDefinition => match external_callee_text {
            Some(text) => lookup.boundaries.push(CallDispatchBoundaryKind::External {
                callee_text: Some(text),
                normalized_static_owner,
                external_callee_identity,
            }),
            None => lookup.boundaries.push(unresolved_call_boundary(
                status,
                None,
                normalized_static_owner,
            )),
        },
        DefinitionLookupStatus::UnsupportedLanguage
        | DefinitionLookupStatus::Unavailable
        | DefinitionLookupStatus::Incomplete
        | DefinitionLookupStatus::Cancelled
        | DefinitionLookupStatus::ExceededBudget(_)
        | DefinitionLookupStatus::InvalidLocation
        | DefinitionLookupStatus::NotFound => lookup.boundaries.push(unresolved_call_boundary(
            status,
            external_callee_text,
            normalized_static_owner,
        )),
    }
}

/// Let the language that owns a resolved call refine target proof from its
/// structured receiver evidence.
fn refine_resolved_call_target_proofs(
    lookup: &mut CallDispatchLookup,
    language: Language,
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    site: &ExternalCalleeSite<'_>,
) {
    if lookup.status != Some(DefinitionLookupStatus::Resolved) || lookup.targets.is_empty() {
        return;
    }
    language_support(language)
        .expect("every resolved call language has registered support")
        .refine_resolved_call_targets(analyzer, token, file, site, &mut lookup.targets);
}

/// The canonical owner of a Java method-invocation object that the definition
/// resolver proved to be a type qualifier.
///
/// `callee_text` is already the resolver's canonical external identity. Java
/// publishes that text only after its structured receiver/type ladder has
/// rejected lexical value shadowing and resolved imports. Comparing the exact
/// AST object with that resolved owner distinguishes `URLDecoder.decode` and
/// `java.net.URLDecoder.decode` from an instance receiver such as `s.trim`
/// without reimplementing Java name resolution here.
fn java_normalized_static_owner(
    callee_text: &str,
    language: Language,
    site: Option<&ExternalCalleeSite<'_>>,
) -> Option<Box<str>> {
    if language != Language::Java {
        return None;
    }
    let site = site?;
    let (owner, member) =
        crate::analyzer::semantic::split_canonical_qualified_callee(callee_text, language)?;
    let mut node = site.tree.root_node().named_descendant_for_byte_range(
        site.callee_start_byte,
        site.callee_start_byte.saturating_add(1),
    )?;
    while node.kind() != "method_invocation" {
        node = node.parent()?;
    }
    let name = node.child_by_field_name("name")?;
    if site.source.get(name.byte_range())? != member {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    let object_text = site.source.get(object.byte_range())?;
    let owner_matches = object_text == owner
        || owner
            .strip_suffix(object_text)
            .is_some_and(|prefix| prefix.ends_with('.'));
    owner_matches.then(|| owner.into_boxed_str())
}

/// The canonical owner of a C# static member the external declaration surface
/// proved. C# member-access syntax gives static calls the same receiver-shaped
/// form as instance calls, so the target shape comes from the exact activated
/// declaration fact rather than from source text or the member name.
fn csharp_normalized_static_owner(
    analyzer: Option<&dyn IAnalyzer>,
    language: Language,
    callee_text: Option<&str>,
) -> Option<Box<str>> {
    if language != Language::CSharp {
        return None;
    }
    let callee_text = callee_text?;
    let analyzer = analyzer?;
    let (owner, member) =
        crate::analyzer::semantic::split_canonical_qualified_callee(callee_text, language)?;
    let is_static = language_support(language)?.external_member_is_static(
        analyzer,
        analyzer.semantic_model_overlay(),
        &owner,
        &member,
    );
    is_static
        .is_some_and(|is_static| is_static)
        .then(|| owner.into_boxed_str())
}

/// The external identity `callee_text` names, or `None` when it names none.
///
/// A multi-segment owner present verbatim in the spelling the source wrote
/// (`java.net.URLDecoder.decode`, `std::str::from_utf8`) is an identity on its
/// own evidence and is returned unchanged (#1978, #2596): the cut follows the
/// language's own separator, and the owner is compared in its canonical
/// dot-joined form, so one rule serves both spellings. The text is returned as
/// written rather than dot-joined, because the minting side re-cuts it with the
/// same separator.
///
/// An unqualified callee (`trim`) names nothing here; resolving it needs type
/// information this cut does not have. A single-segment owner
/// (`URLDecoder.decode`, `Path::new`, `JSON.parse`) is offered to the language
/// (#2598), which is the only party that can say whether such an owner is an
/// identity in its surface and, if so, which one. A language that can prove an
/// import expansion instead performs it upstream in
/// [`expand_imported_external_callee`], so a callee it handles arrives here
/// already multi-segment.
///
/// Constraint (#2596): an implicit-prelude spelling stays excluded. Rust's
/// `String::from(x)` has no `use` declaration for the import binder to read, so
/// admitting it would need a checked-in prelude table -- reviewed content
/// rather than resolution -- which Bifrost does not carry. Such a call keeps
/// the boundary it already had and binds no authored summary.
///
/// Go's exact resolver is an additional structured route: it has already
/// replaced the source qualifier with the canonical import path before this
/// function runs. A one-segment Go standard-library path such as `os` is thus
/// an identity, while a shadowed local receiver never reaches this boundary as
/// that canonical unresolved import.
fn canonical_external_callee(
    callee_text: &str,
    language: Language,
    site: Option<&ExternalCalleeSite<'_>>,
    resolver_proven_external_identity: bool,
) -> Option<String> {
    // Kotlin writes package paths and receiver-expression chains with the same
    // separator. PHP's reference range can likewise span an argument-unpack or
    // concatenation expression. A source spelling proves no package or
    // namespace root for either language; only resolver-owned evidence may
    // publish an external identity (#2781, #2793). Rust's `::`-joined path is
    // the same shape of claim: a multi-segment spelling such as
    // `std::net::TcpStream::connect` names the standard-library API only when
    // the resolver proved the leading segment names no workspace declaration,
    // so an unresolved member under a workspace `std` must stay open rather
    // than borrow a summary from its spelling (#3484).
    if matches!(language, Language::Kotlin | Language::Php | Language::Rust)
        && !resolver_proven_external_identity
    {
        return None;
    }
    let (owner, member) =
        crate::analyzer::semantic::split_canonical_qualified_callee(callee_text, language)?;
    if owner.contains('.') {
        return Some(callee_text.to_owned());
    }
    if language == Language::Go {
        return Some(callee_text.to_owned());
    }
    let support = language_support(language)?;
    if !support.publishes_single_segment_external_owners() {
        return None;
    }
    // Without the call site's own file evidence there is nothing to decide a
    // single-segment owner on, and guessing one is exactly what #2598 forbids.
    let canonical_owner = support.single_segment_external_owner(&owner, &member, site?)?;
    Some(format!(
        "{canonical_owner}{}{member}",
        support.qualified_call_separator()
    ))
}

fn call_hits(
    result: FuzzyResult,
    target: &CodeUnit,
) -> (
    Vec<(UsageHit, UsageProof)>,
    bool,
    Vec<CallRelationDiagnostic>,
) {
    let semantic_diagnostics = match &result {
        FuzzyResult::Incomplete { diagnostics, .. } => {
            vec![CallRelationDiagnostic::analysis_failed(
                format!("Usage analysis is incomplete: {diagnostics:?}"),
                target.fq_name().to_string(),
                "semantic_incomplete".to_string(),
            )]
        }
        _ => Vec::new(),
    };
    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            unproven_total_by_overload,
        }
        | FuzzyResult::Incomplete {
            hits_by_overload,
            unproven_by_overload,
            unproven_total_by_overload,
            ..
        } => {
            let proven = hits_by_overload
                .into_values()
                .flatten()
                .map(|hit| (hit, UsageProof::Proven));
            let unproven = unproven_by_overload
                .into_values()
                .flatten()
                .map(|hit| (hit, UsageProof::Unproven));
            let retained_unproven = unproven_total_by_overload.values().sum::<usize>();
            let hits = proven.chain(unproven).collect::<Vec<_>>();
            let omitted = retained_unproven.saturating_sub(
                hits.iter()
                    .filter(|(_, proof)| *proof == UsageProof::Unproven)
                    .count(),
            );
            let diagnostics = (omitted > 0)
                .then(|| {
                    CallRelationDiagnostic::new(
                        CallRelationDiagnosticCode::CandidatesOmitted,
                        format!(
                            "omitted {omitted} unproven call candidates for {}",
                            target.fq_name()
                        ),
                        target.fq_name().to_string(),
                    )
                })
                .into_iter()
                .chain(semantic_diagnostics)
                .collect();
            (hits, false, diagnostics)
        }
        FuzzyResult::Ambiguous {
            hits_by_overload, ..
        } => (
            hits_by_overload
                .into_values()
                .flatten()
                .map(|hit| (hit, UsageProof::Unproven))
                .collect(),
            false,
            vec![CallRelationDiagnostic::new(
                CallRelationDiagnosticCode::TargetsAmbiguous,
                format!(
                    "call targets for {} are ambiguous; candidates are unproven",
                    target.fq_name()
                ),
                target.fq_name().to_string(),
            )],
        ),
        FuzzyResult::TooManyCallsites {
            total_callsites,
            limit,
            sample_hits,
            ..
        } => (
            sample_hits
                .into_iter()
                .take(limit)
                .map(|hit| (hit, UsageProof::Proven))
                .collect(),
            true,
            vec![CallRelationDiagnostic::new(
                CallRelationDiagnosticCode::CandidateLimit,
                format!(
                    "found {total_callsites} call candidates for {}, retaining the first {limit}",
                    target.fq_name()
                ),
                target.fq_name().to_string(),
            )],
        ),
        FuzzyResult::Failure {
            reason_kind,
            reason,
            ..
        } => (
            Vec::new(),
            false,
            vec![CallRelationDiagnostic::analysis_failed(
                reason,
                target.fq_name().to_string(),
                reason_kind,
            )],
        ),
    }
}

pub(crate) fn raw_call_site(
    file: ProjectFile,
    caller: CodeUnit,
    callee: CodeUnit,
    syntax: CallSiteSyntax,
    proof: UsageProof,
) -> CallSite {
    let kind = if callee.is_class() || callee.kind().display_lowercase() == "constructor" {
        CallSyntaxKind::Constructor
    } else {
        syntax.kind
    };
    let arguments = syntax
        .arguments
        .into_iter()
        .map(|argument| CallArgument {
            range: argument.range,
            name: argument.name,
            position: argument.position,
            formal_index: None,
            formal_name: None,
            variadic: false,
            spread: argument.spread,
        })
        .collect();
    CallSite {
        file,
        range: syntax.range,
        callee_range: syntax.callee_range,
        caller,
        callee,
        kind,
        proof,
        receiver: syntax.receiver,
        arguments,
    }
}

pub fn bind_call_site_arguments(
    analyzer: &dyn IAnalyzer,
    site: &mut CallSite,
    cache: &mut CallBindingCache,
) -> CallBindingStatus {
    let Some((formal_owner, constructor_binding)) = formal_owner_for_callee(analyzer, &site.callee)
    else {
        return CallBindingStatus::Unavailable;
    };
    let Some(layout) = cache.formal_layout(analyzer, &formal_owner, site.arguments.len()) else {
        return CallBindingStatus::Unavailable;
    };
    let Some(bind_first) = python_first_formal_is_bound(
        analyzer,
        &site.file,
        site.receiver,
        &formal_owner,
        &layout,
        cache,
        constructor_binding,
    ) else {
        return CallBindingStatus::Unavailable;
    };
    // The matching rule itself lives beside the `call_binding` rows so the
    // production binding and the published rows can never be two computations
    // that drift apart (issue #2438).
    let ordinary_slots = OrdinaryFormalSlots::of(&layout, bind_first);

    for argument in &mut site.arguments {
        let slot =
            ordinary_slots.slot_for(argument.name.as_deref(), argument.position, argument.spread);
        argument.formal_index = slot.map(|(index, _)| index);
        argument.formal_name = slot
            .and_then(|(_, slot)| slot.names.first())
            .map(|name| canonical_parameter_name(name));
        argument.variadic = slot.is_some_and(|(_, slot)| slot.variadic.is_some());
    }
    CallBindingStatus::Complete
}

/// The callable whose formal list one resolved callee's arguments bind, and
/// whether the language binds its first declared formal to the constructed
/// object.
///
/// A callee that is already a callable owns its own formals. A *class* callee
/// names the language's indexed constructor child when that convention is
/// structured and unique. Python's allocation additionally binds `self`; a
/// JavaScript or TypeScript constructor declares only its written parameters.
/// Shared with the `call_binding` row producer so both answer from one rule
/// (issue #2499).
pub fn formal_owner_for_callee(
    analyzer: &dyn IAnalyzer,
    callee: &CodeUnit,
) -> Option<(CodeUnit, bool)> {
    if !callee.is_class() {
        return Some((callee.clone(), false));
    }
    let language = language_for_file(callee.source());
    if language == Language::Python {
        let mut children = analyzer.direct_children(callee);
        children.sort();
        children.dedup();

        let direct_initializers = children
            .iter()
            .filter(|unit| unit.identifier() == "__init__")
            .collect::<Vec<_>>();
        match direct_initializers.as_slice() {
            [initializer] if initializer.is_callable() => {
                return Some(((**initializer).clone(), true));
            }
            [] => {}
            _ => return None,
        }

        if let Some(provider) = analyzer.python_class_hierarchy_provider_for(callee) {
            let answer = provider.mro_members(callee, None);
            if answer.hierarchy.outcome != PythonHierarchyOutcome::Complete {
                return None;
            }
            if let Some(initializer) = answer
                .members
                .iter()
                .find(|member| member.name == "__init__")
            {
                return initializer
                    .member
                    .is_callable()
                    .then(|| (initializer.member.clone(), true));
            }
            // A retained __new__ does not establish absence of __init__ on
            // an unknown external member surface earlier in the full MRO.
            if answer.outcome != PythonHierarchyOutcome::Complete {
                return None;
            }
            if let Some(allocation) = answer
                .members
                .iter()
                .find(|member| member.name == "__new__")
            {
                return allocation
                    .member
                    .is_callable()
                    .then(|| (allocation.member.clone(), true));
            }
            return None;
        }

        let direct_allocators = children
            .into_iter()
            .filter(|unit| unit.is_callable() && unit.identifier() == "__new__")
            .collect::<Vec<_>>();
        return match direct_allocators.as_slice() {
            [allocator] => Some(((*allocator).clone(), true)),
            _ => None,
        };
    }

    let constructor_names = match language {
        Language::JavaScript | Language::TypeScript => ["constructor", ""],
        Language::Kotlin => [callee.identifier(), ""],
        _ => return None,
    };
    let mut children = analyzer
        .direct_children(callee)
        .into_iter()
        .filter(|unit| unit.is_callable())
        .collect::<Vec<_>>();
    children.sort();
    children.dedup();
    for constructor_name in constructor_names {
        let mut constructors = children
            .iter()
            .filter(|unit| unit.identifier() == constructor_name)
            .cloned()
            .collect::<Vec<_>>();
        if constructors.len() == 1 {
            return Some((constructors.remove(0), language == Language::Python));
        }
        if !constructors.is_empty() {
            return None;
        }
    }
    None
}

/// Whether the callee's first declared formal is consumed by the call's
/// receiver rather than by a written actual.
///
/// This is Python's whole receiver discipline: `self` and `cls` occupy declared
/// slots, so what the receiver expression resolves to decides which slot the
/// first written actual reaches. `None` means the receiver's own resolution
/// failed, which is undecidable rather than "not bound" -- a caller that
/// guessed here would report every actual one slot off.
pub fn python_first_formal_is_bound(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    receiver: Option<Range>,
    formal_owner: &CodeUnit,
    layout: &FormalParameterLayout,
    cache: &mut CallBindingCache,
    constructor_binding: bool,
) -> Option<bool> {
    if constructor_binding {
        return Some(true);
    }
    if language_for_file(formal_owner.source()) != Language::Python
        || !analyzer
            .parent_of(formal_owner)
            .is_some_and(|owner| owner.is_class())
    {
        return Some(false);
    }
    match layout.python_binding {
        Some(PythonMethodBinding::Static) | None => Some(false),
        Some(PythonMethodBinding::Class) => Some(receiver.is_some()),
        Some(PythonMethodBinding::Instance) => {
            let Some(receiver) = receiver else {
                return Some(false);
            };
            python_receiver_resolves_to_class(analyzer, file, receiver, cache)
                .map(|is_class| !is_class)
        }
    }
}

fn python_receiver_resolves_to_class(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    receiver: Range,
    cache: &mut CallBindingCache,
) -> Option<bool> {
    let key = (file.clone(), receiver.start_byte, receiver.end_byte);
    if let Some(is_class) = cache.python_receiver_is_class.get(&key) {
        return *is_class;
    }
    let source = analyzer.indexed_source(file).map(Arc::<str>::from);
    let is_class = source
        .clone()
        .and_then(|source| {
            resolve_definition_batch_with_source(
                analyzer,
                vec![DefinitionLookupRequest {
                    file: file.clone(),
                    line: None,
                    column: None,
                    start_byte: Some(receiver.start_byte),
                    end_byte: Some(receiver.end_byte),
                }],
                file.clone(),
                source,
            )
            .into_iter()
            .next()
        })
        .and_then(|outcome| match outcome.status {
            DefinitionLookupStatus::Resolved => {
                Some(outcome.definitions.iter().any(CodeUnit::is_class))
            }
            // The resolver identified what the name binds to and answered that
            // it is a local binder no analyzer publishes as a CodeUnit -- a
            // parameter, or a variable assigned in this body. That is an
            // adjudicated answer, not a miss, and a local binder is not the
            // class-reference spelling `Class.method(instance)` needs. The
            // known boundary is a local that holds a class object, such as
            // `alias = Store` followed by `alias.put(store, key)`; deciding
            // that needs value flow, and nothing here pretends to have it.
            DefinitionLookupStatus::NoDefinition
                if outcome.diagnostics.iter().any(|diagnostic| {
                    diagnostic.kind == LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND
                }) =>
            {
                Some(false)
            }
            _ => None,
        })
        .or_else(|| {
            // The resolver adjudicates names. A receiver that is not a name --
            // a call expression such as `make_store().put(key)` -- has no
            // definition to look up, but its own syntax is the answer: a
            // call's value is the callable's return value, an instance, never
            // the class-reference spelling `Class.method(instance)` needs.
            // Reaching this binding at all means the production resolver
            // already attributed the member through that receiver's proven
            // return type (#2495). The known boundary is a callable returning
            // a class object, which is the same value-flow boundary as a
            // local holding one.
            python_receiver_is_call_expression(file, receiver, source.as_deref()).then_some(false)
        });
    cache.python_receiver_is_class.insert(key, is_class);
    is_class
}

/// Whether the receiver span is a call expression (possibly parenthesized) in
/// the file's own tree. Answered from tree-sitter structure, never from text.
fn python_receiver_is_call_expression(
    file: &ProjectFile,
    receiver: Range,
    source: Option<&str>,
) -> bool {
    let Some(source) = source else {
        return false;
    };
    let Some(tree) = parse_tree_for_language(file, Language::Python, source) else {
        return false;
    };
    // Iterative descent to the smallest named node covering the receiver span.
    let mut node = tree.root_node();
    let mut smallest = None;
    loop {
        if node.is_named()
            && node.start_byte() == receiver.start_byte
            && node.end_byte() == receiver.end_byte
        {
            smallest = Some(node);
        }
        let mut descended = false;
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.start_byte() <= receiver.start_byte && receiver.end_byte <= child.end_byte() {
                node = child;
                descended = true;
                break;
            }
        }
        if !descended {
            break;
        }
    }
    let Some(mut node) = smallest else {
        return false;
    };
    while node.kind() == "parenthesized_expression" {
        let Some(inner) = node.named_child(0) else {
            return false;
        };
        node = inner;
    }
    node.kind() == "call"
}

/// Locate the source body belonging to the same persisted signature selection
/// used by call bindings. Overloads sharing a CodeUnit must not inherit the
/// first declaration's formals or semantic body.
pub fn selected_callable_range(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    actual_count: usize,
) -> Option<Range> {
    selected_callable_layout(analyzer, unit, actual_count).map(|(range, _)| range)
}

fn selected_callable_layout(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    actual_count: usize,
) -> Option<(Range, FormalParameterLayout)> {
    use super::callable_signature::{callable_signature_reports, signature_choice};
    if unit.is_class() {
        return None;
    }
    let ranges = analyzer.ranges_of(unit);
    let entries = analyzer.signature_metadata(unit);
    let reports = callable_signature_reports("selection-only", unit, &entries);
    let selection = signature_choice(&reports, actual_count);
    if selection.ambiguous {
        return None;
    }
    let source = analyzer.indexed_source(unit.source())?;
    let language = language_for_file(unit.source());
    let tree = parse_tree_for_language(unit.source(), language, &source)?;
    if let [range] = ranges.as_slice() {
        return formal_parameter_slots(language, tree.root_node(), &source, range)
            .map(|layout| (*range, layout));
    }
    let arity = entries.get(selection.ordinal?)?.callable_arity()?;
    // ParameterMetadata offsets are signature-relative in some adapters and
    // file-relative in others. Read each declaration's AST-owned layout instead.
    // The shared selector has already refused different accepting signatures;
    // several matching ranges here are equivalent declarations of that signature.
    ranges
        .into_iter()
        .filter_map(|range| {
            let layout = formal_parameter_slots(language, tree.root_node(), &source, &range)?;
            let ordinary = layout
                .slots
                .iter()
                .filter(|slot| !slot.receiver)
                .collect::<Vec<_>>();
            let required = ordinary
                .iter()
                .filter(|slot| slot.default_range.is_none() && slot.variadic.is_none())
                .count();
            let repeated = ordinary.iter().any(|slot| slot.variadic.is_some());
            (crate::analyzer::CallableArity::new(required, ordinary.len(), repeated) == arity)
                .then_some((range, layout))
        })
        .min_by_key(|(range, _)| range_key(range))
}

fn formal_slots_for_unit(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    actual_count: usize,
) -> Option<FormalParameterLayout> {
    selected_callable_layout(analyzer, unit, actual_count).map(|(_, layout)| layout)
}

pub fn nearest_call_relation_unit(
    analyzer: &dyn IAnalyzer,
    mut unit: CodeUnit,
) -> Option<CodeUnit> {
    loop {
        if is_call_relation_unit(&unit) {
            return Some(unit);
        }
        unit = analyzer.parent_of(&unit)?;
    }
}

pub fn is_call_relation_unit(unit: &CodeUnit) -> bool {
    (unit.is_callable() || unit.is_class()) && !unit.is_synthetic()
}

fn range_key(range: &Range) -> (usize, usize, usize, usize) {
    (
        range.start_line,
        range.start_byte,
        range.end_line,
        range.end_byte,
    )
}

fn sort_and_dedup_sites(sites: &mut Vec<CallSite>) {
    sites.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| range_key(&left.range).cmp(&range_key(&right.range)))
            .then_with(|| left.caller.cmp(&right.caller))
            .then_with(|| left.callee.cmp(&right.callee))
            .then_with(|| proof_rank(left.proof).cmp(&proof_rank(right.proof)))
    });
    let mut seen = HashSet::default();
    sites.retain(|site| seen.insert(site.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::CodeUnitIndex;
    use crate::analyzer::usages::get_definition::{
        DefinitionLookupDiagnostic, DefinitionLookupOutcome,
        GO_MODELED_PACKAGE_CALL_NOT_APPLICABLE_DIAGNOSTIC_KIND,
        GO_MODELED_PACKAGE_CALL_UNPROVEN_DIAGNOSTIC_KIND,
    };
    use crate::analyzer::{AnalyzerConfig, AnalyzerQueryScope, QueryScope, WorkspaceAnalyzer};
    use crate::analyzer::{
        CodeUnitType, Language, PythonAnalyzer, TestProject, TypescriptAnalyzer,
    };
    use crate::test_support::AnalyzerFixture;
    use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;
    use std::collections::BTreeSet;

    #[test]
    fn incomplete_call_hits_preserve_proof_and_semantic_diagnostics() {
        let file = ProjectFile::new(std::env::temp_dir(), "incomplete_calls.rs");
        let target = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
        let proven = UsageHit::new(file.clone(), 1, 0, 6, target.clone(), 1.0, "target");
        let unproven = UsageHit::new(file, 2, 10, 16, target.clone(), 0.5, "target");
        let result = FuzzyResult::Incomplete {
            hits_by_overload: [(target.clone(), BTreeSet::from([proven.clone()]))]
                .into_iter()
                .collect(),
            unproven_by_overload: [(target.clone(), BTreeSet::from([unproven.clone()]))]
                .into_iter()
                .collect(),
            unproven_total_by_overload: [(target.clone(), 1)].into_iter().collect(),
            diagnostics: vec![crate::analyzer::usages::UsageAnalysisDiagnostic {
                fq_name: target.fq_name().to_string(),
                strategy: "native".to_string(),
                reason_kind: "unsupported_reference".to_string(),
                reason: "Another call cannot be resolved".to_string(),
            }],
        };
        let (hits, truncated, diagnostics) = call_hits(result, &target);
        assert_eq!(
            hits,
            vec![
                (proven, UsageProof::Proven),
                (unproven, UsageProof::Unproven)
            ]
        );
        assert!(
            !truncated,
            "semantic incompleteness is not a callsite budget"
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            CallRelationDiagnosticCode::AnalysisFailed
        );
        assert!(diagnostics[0].message.contains("unsupported_reference"));
    }

    fn call_span(source: &str, call: &str) -> Range {
        crate::analyzer::usages::test_support::byte_range(source, call)
    }

    fn generous_limits() -> CallRelationLimits {
        CallRelationLimits {
            max_files: 1,
            max_source_bytes: usize::MAX,
            max_candidates: 100,
        }
    }

    fn activate_go_declaration_payload(
        fixture: &AnalyzerFixture,
        pack_id: &str,
        import_path: &str,
        package_name: &str,
        mut types: Vec<serde_json::Value>,
        members: Vec<serde_json::Value>,
    ) {
        use crate::analyzer::semantic_model::{
            CatalogCoordinate, SemanticModelActivationControl, SemanticModelActivationEvidence,
            SemanticModelActivationRequest, SemanticModelControlAction, SemanticModelControlScope,
            SemanticModelPackSelector, SemanticModelRuntimeLimits,
        };

        let id_namespace = pack_id.replace('-', ".");
        let module_id = format!("type.{id_namespace}.module");
        types.insert(
            0,
            serde_json::json!({
                "id": module_id,
                "name": import_path,
                "type_kind": "module",
                "visibility": "package",
                "aliases": [package_name],
                "locator": {
                    "kind": "artifact",
                    "path": "fixture.go",
                    "symbol": import_path
                }
            }),
        );
        let source = serde_json::to_vec(&serde_json::json!({
            "schema_version": 2,
            "pack_id": pack_id,
            "version": "1.0.0",
            "producer": { "name": "go-dispatch-fixture", "version": "1.0.0" },
            "language": "go",
            "ecosystem": "go",
            "compatibility": { "bifrost": "*", "toolchains": [] },
            "provenance": { "source": "fixture" },
            "license": "NOASSERTION",
            "completeness": "partial",
            "safety": { "generated_code_only": false, "review_required": false },
            "shards": [{
                "id": format!("declarations.{pack_id}"),
                "activation": [{}],
                "payload": {
                    "kind": "declaration_facts",
                    "types": types,
                    "members": members,
                    "relations": []
                }
            }]
        }))
        .expect("serialize Go declaration fixture");
        let request = SemanticModelActivationRequest {
            bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
                .expect("crate version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "go".to_owned(),
                ecosystem: "go".to_owned(),
                package: Some(CatalogCoordinate {
                    name: import_path.to_owned(),
                    version: None,
                }),
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: vec![SemanticModelActivationControl {
                scope: SemanticModelControlScope::Workspace,
                action: SemanticModelControlAction::Enable,
                selector: SemanticModelPackSelector {
                    pack_id: pack_id.to_owned(),
                    version: None,
                    manifest_digest: None,
                },
            }],
            limits: SemanticModelRuntimeLimits::default(),
        };
        crate::analyzer::usages::test_support::activate_semantic_pack(
            fixture.analyzer.analyzer(),
            pack_id,
            &source,
            &request,
        );
    }

    fn activate_go_function_declaration(
        fixture: &AnalyzerFixture,
        pack_id: &str,
        import_path: &str,
        package_name: &str,
        member: &str,
    ) {
        let id_namespace = pack_id.replace('-', ".");
        let module_id = format!("type.{id_namespace}.module");
        activate_go_declaration_payload(
            fixture,
            pack_id,
            import_path,
            package_name,
            Vec::new(),
            vec![serde_json::json!({
                "id": format!("member.{id_namespace}.{}", member.to_ascii_lowercase()),
                "owner": module_id,
                "name": member,
                "member_kind": "function",
                "visibility": "public",
                "is_static": true,
                "signature": { "parameters": [] },
                "locator": {
                    "kind": "artifact",
                    "path": "fixture.go",
                    "symbol": format!("{import_path}.{member}")
                }
            })],
        );
    }

    #[test]
    fn exact_dispatch_resolves_one_nested_call_without_resolving_its_neighbor() {
        let source = "function outer(value: number) { return value; }\nfunction inner() { return 1; }\nfunction caller() { return outer(inner()); }\n";
        let fixture =
            AnalyzerFixture::new_for_language(Language::TypeScript, &[("nested.ts", source)]);
        let file = ProjectFile::new(fixture.project_root(), "nested.ts");
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &ExactCallLocation {
                file,
                call_span: call_span(source, "inner()"),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert_eq!(lookup.status, Some(DefinitionLookupStatus::Resolved));
        assert_eq!(lookup.targets.len(), 1, "{lookup:#?}");
        assert_eq!(lookup.targets[0].definition.fq_name(), "inner");
        assert_eq!(lookup.targets[0].proof, UsageProof::Proven);
        assert!(lookup.boundaries.is_empty(), "{lookup:#?}");
        assert!(!lookup.cancelled);
        assert!(!lookup.budget_exhausted);
        assert!(!lookup.truncated);
    }

    /// #2495: Python and TypeScript publish the same exact declaration
    /// identities for the ordinary statically knowable call forms. This is the
    /// source-owned pin beneath the policy fixtures: it asks the normalized
    /// dispatch relation directly, so no rendered callee spelling can stand in
    /// for target proof.
    #[brokk_bifrost_test_macros::hardwon(
        "#2725: Cross-language analyzer fixtures compare Python and TypeScript static dispatch proofs and preserve their language-specific target identities"
    )]
    #[test]
    fn exact_dispatch_proves_python_and_typescript_static_targets() {
        const PYTHON: &str = r#"from typing import final

def module_function() -> None:
    pass

@final
class Store:
    def __init__(self, tag: str) -> None:
        self.tag = tag

    def put(self, value: str) -> None:
        pass

    def self_call(self) -> None:
        self.put("self")

@final
class Cache:
    def __init__(self, tag: str) -> None:
        self.tag = tag

    def put(self, value: str) -> None:
        pass

def caller() -> None:
    module_function()
    Store("direct")
    store = Store("local")
    cache = Cache("local")
    store.put("store")
    cache.put("cache")
"#;
        const TYPESCRIPT: &str = r#"export function moduleFunction(): void {}

export class Store {
  private constructor(public tag: string) {}
  put(value: string): void {}
  selfCall(): void { this.put("this"); }
  static direct(): Store { return new Store("direct"); }
  static local(): void {
    const store = new Store("local");
    const cache = Cache.create("local");
    store.put("store");
    cache.put("cache");
  }
}

export class Cache {
  private constructor(public tag: string) {}
  put(value: string): void {}
  static create(tag: string): Cache { return new Cache(tag); }
}

export function caller(): void { moduleFunction(); }
"#;

        let cases = [
            (
                Language::Python,
                "static_targets.py",
                PYTHON,
                vec![
                    ("module_function()", "module_function", None),
                    ("Store(\"direct\")", "Store", None),
                    ("store.put(\"store\")", "put", Some("Store")),
                    ("cache.put(\"cache\")", "put", Some("Cache")),
                    ("self.put(\"self\")", "put", Some("Store")),
                ],
            ),
            (
                Language::TypeScript,
                "static_targets.ts",
                TYPESCRIPT,
                vec![
                    ("moduleFunction()", "moduleFunction", None),
                    ("new Store(\"direct\")", "Store", None),
                    ("store.put(\"store\")", "put", Some("Store")),
                    ("cache.put(\"cache\")", "put", Some("Cache")),
                    ("this.put(\"this\")", "put", Some("Store")),
                ],
            ),
        ];

        for (language, path, source, calls) in cases {
            let fixture = AnalyzerFixture::new_for_language(language, &[(path, source)]);
            let analyzer = fixture.analyzer.analyzer();
            for (call, identifier, owner) in calls {
                let scope = AnalyzerQueryScope::new(analyzer);
                let lookup = CallRelationService::dispatch_at_bounded(
                    analyzer,
                    scope.token(),
                    &ExactCallLocation {
                        file: ProjectFile::new(fixture.project_root(), path),
                        call_span: call_span(source, call),
                    },
                    Arc::from(source),
                    generous_limits(),
                    None,
                );

                assert_eq!(
                    lookup.status,
                    Some(DefinitionLookupStatus::Resolved),
                    "{language:?} {call}: {lookup:#?}"
                );
                assert_eq!(lookup.targets.len(), 1, "{language:?} {call}: {lookup:#?}");
                let target = &lookup.targets[0];
                assert_eq!(
                    target.proof,
                    UsageProof::Proven,
                    "{language:?} {call}: {lookup:#?}"
                );
                assert_eq!(
                    target.definition.identifier(),
                    identifier,
                    "{language:?} {call}: {lookup:#?}"
                );
                if let Some(owner) = owner {
                    assert!(
                        target.definition.fq_name().contains(owner),
                        "{language:?} {call} resolved to the wrong same-named owner: {lookup:#?}"
                    );
                }
                assert!(
                    lookup.boundaries.is_empty(),
                    "{language:?} {call}: {lookup:#?}"
                );
            }
        }
    }

    #[test]
    fn exact_dispatch_preserves_canonical_go_external_package_member() {
        for (import, call) in [
            ("\"os\"", "os.Open(\"book.xlsx\")"),
            ("files \"os\"", "files.Open(\"book.xlsx\")"),
        ] {
            let source =
                format!("package main\n\nimport {import}\n\nfunc caller() {{ _, _ = {call} }}\n");
            let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", &source)]);
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
            let lookup = CallRelationService::dispatch_at_bounded(
                fixture.analyzer.analyzer(),
                scope.token(),
                &ExactCallLocation {
                    file,
                    call_span: call_span(&source, call),
                },
                Arc::from(source),
                generous_limits(),
                None,
            );

            assert_eq!(
                lookup.status,
                Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                "{lookup:#?}"
            );
            assert_eq!(lookup.go_selector_member.as_deref(), None, "{lookup:#?}");
            assert!(lookup.targets.is_empty(), "{lookup:#?}");
            assert_eq!(
                lookup.boundaries,
                vec![CallDispatchBoundaryKind::External {
                    callee_text: Some("os.Open".into()),
                    normalized_static_owner: None,
                    external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
                        Language::Go,
                        "os",
                        "Open",
                    )),
                }],
                "{lookup:#?}"
            );
        }
    }

    #[test]
    fn exact_go_selector_dispatch_uses_receiver_method_sets_and_embedding() {
        let source = r#"package main

type receiver struct{}
func (receiver) Value() {}
func (*receiver) Pointer() {}

type embedded struct { receiver }
type shadow struct { receiver }
func (shadow) Value() {}

func caller() {
	var r receiver
	r.Value()
	r.Pointer()
	var e embedded
	e.Value()
	var s shadow
	s.Value()
}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[("go.mod", "module example.com/app\n"), ("main.go", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        for (call, expected) in [
            ("r.Value()", "example.com/app.receiver.Value"),
            ("r.Pointer()", "example.com/app.receiver.Pointer"),
            ("e.Value()", "example.com/app.receiver.Value"),
            ("s.Value()", "example.com/app.shadow.Value"),
        ] {
            let lookup = CallRelationService::dispatch_at_bounded(
                fixture.analyzer.analyzer(),
                scope.token(),
                &ExactCallLocation {
                    file: file.clone(),
                    call_span: call_span(source, call),
                },
                Arc::from(source),
                generous_limits(),
                None,
            );
            assert_eq!(
                lookup.status,
                Some(DefinitionLookupStatus::Resolved),
                "{lookup:#?}"
            );
            assert_eq!(lookup.targets.len(), 1, "{lookup:#?}");
            assert_eq!(
                lookup.targets[0].definition.fq_name(),
                expected,
                "{lookup:#?}"
            );
            assert_eq!(lookup.targets[0].proof, UsageProof::Proven);
            assert!(lookup.boundaries.is_empty(), "{lookup:#?}");
        }
    }

    #[test]
    fn exact_go_external_receiver_dispatch_preserves_reviewed_and_unmodeled_identity() {
        for model_level in 1..=2 {
            let modeled = model_level == 2;
            let source = r#"package main

import "time"

func caller(idleTicker *time.Ticker) { idleTicker.Stop() }
"#;
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[("go.mod", "module example.com/app\n"), ("main.go", source)],
            );
            let mut methods = Vec::new();
            if modeled {
                methods.push(serde_json::json!({
                    "id": "fixture.go.time-ticker.stop",
                    "owner": "fixture.go.time-ticker.type",
                    "name": "Stop",
                    "member_kind": "method",
                    "visibility": "public",
                    "is_static": false,
                    "receiver": {"pointer": true},
                    "signature": {"parameters": []},
                    "locator": {
                        "kind": "artifact",
                        "path": "time/sleep.go",
                        "symbol": "time.Ticker.Stop"
                    }
                }));
            }
            activate_go_declaration_payload(
                &fixture,
                "fixture.go.time-ticker",
                "time",
                "time",
                vec![serde_json::json!({
                    "id": "fixture.go.time-ticker.type",
                    "name": "time.Ticker",
                    "type_kind": "struct",
                    "visibility": "public",
                    "locator": {
                        "kind": "artifact",
                        "path": "time/tick.go",
                        "symbol": "time.Ticker"
                    }
                })],
                methods,
            );
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
            let mut session = CallRelationService::dispatch_session(file, Arc::from(source));
            let lookup = session.dispatch_at_bounded(
                fixture.analyzer.analyzer(),
                scope.token(),
                &call_span(source, "idleTicker.Stop()"),
                generous_limits().max_candidates,
                None,
            );

            assert_eq!(
                lookup.status,
                Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                "{lookup:#?}"
            );
            assert!(lookup.targets.is_empty(), "{lookup:#?}");
            assert!(
                lookup.boundaries.iter().any(|boundary| matches!(
                    boundary,
                    CallDispatchBoundaryKind::External {
                        callee_text: Some(callee), ..
                    } if callee.as_ref() == "time.Ticker.Stop"
                )),
                "{lookup:#?}"
            );
            let identity = lookup
                .boundaries
                .iter()
                .find_map(|boundary| match boundary {
                    CallDispatchBoundaryKind::External {
                        external_callee_identity,
                        ..
                    } => external_callee_identity.as_ref(),
                    _ => None,
                });
            assert_eq!(
                identity.map(|identity| {
                    (identity.language(), identity.owner_fqn(), identity.member())
                }),
                (model_level > 0).then_some((Language::Go, "time.Ticker", "Stop")),
                "only a structured external concrete type declaration proves a model key: {lookup:#?}"
            );
            let proof = lookup
                .exact_external_call
                .as_ref()
                .expect("structured external receiver retains its canonical identity");
            assert_eq!(proof.canonical_callee(), "time.Ticker.Stop");
            assert_eq!(
                proof.dispatch_extensibility(),
                modeled.then_some(DispatchExtensibility::Closed),
                "{lookup:#?}"
            );
        }
    }

    #[test]
    fn exact_dispatch_keeps_model_proof_external_and_canonical() {
        for (
            pack_id,
            import_path,
            package_name,
            import,
            call,
            expected_target,
            expected_owner,
            expected_member,
        ) in [
            (
                "fixture.go.os",
                "os",
                "os",
                "\"os\"",
                "os.Open()",
                "os.Open",
                "os",
                "Open",
            ),
            (
                "fixture.go.os-alias",
                "os",
                "os",
                "files \"os\"",
                "files.Open()",
                "os.Open",
                "os",
                "Open",
            ),
            (
                "fixture.go.declared-name",
                "example.com/m/postgres",
                "pg",
                "\"example.com/m/postgres\"",
                "pg.Open()",
                "example.com/m/postgres.Open",
                "example.com/m/postgres",
                "Open",
            ),
            (
                "fixture.go.dot-import",
                "os",
                "os",
                ". \"os\"",
                "Open()",
                "os.Open",
                "os",
                "Open",
            ),
        ] {
            let source =
                format!("package main\n\nimport {import}\n\nfunc caller() {{ _, _ = {call} }}\n");
            let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", &source)]);
            activate_go_function_declaration(&fixture, pack_id, import_path, package_name, "Open");
            let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
            let lookup = CallRelationService::dispatch_at_bounded(
                fixture.analyzer.analyzer(),
                scope.token(),
                &ExactCallLocation {
                    file: ProjectFile::new(fixture.project_root(), "main.go"),
                    call_span: call_span(&source, call),
                },
                Arc::from(source),
                generous_limits(),
                None,
            );

            assert_eq!(
                lookup.status,
                Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                "{lookup:#?}"
            );
            assert_eq!(lookup.boundary, Some(BoundaryStatus::ExternalIndexed));
            assert_eq!(
                lookup.boundaries,
                vec![CallDispatchBoundaryKind::External {
                    callee_text: Some(expected_target.into()),
                    normalized_static_owner: None,
                    external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
                        Language::Go,
                        expected_owner,
                        expected_member,
                    )),
                }],
                "{lookup:#?}"
            );
            assert_eq!(
                lookup.call_application,
                CallApplicationKind::PackageFunction,
                "{lookup:#?}"
            );
            assert_eq!(lookup.dispatch_extensibility, None, "{lookup:#?}");
        }
    }

    #[test]
    fn dot_imported_model_function_conflicts_with_package_scope_and_stays_identityless() {
        let source = r#"package main

import . "example.com/model"

func Open() {}
func caller() { Open() }
"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[("go.mod", "module example.com/app\n"), ("main.go", source)],
        );
        activate_go_function_declaration(
            &fixture,
            "fixture.go.dot-shadow",
            "example.com/model",
            "model",
            "Open",
        );
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            AnalyzerQueryScope::new(fixture.analyzer.analyzer()).token(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "main.go"),
                call_span: call_span(source, "Open()"),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );
        assert_eq!(
            lookup.status,
            Some(DefinitionLookupStatus::UnresolvableImportBoundary),
            "{lookup:#?}"
        );
        assert!(lookup.targets.is_empty(), "{lookup:#?}");
        assert_eq!(lookup.boundary, Some(BoundaryStatus::ExternalIndexed));
        assert_eq!(
            lookup.call_application,
            CallApplicationKind::PackageFunction
        );
        assert_eq!(
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::External {
                callee_text: None,
                normalized_static_owner: None,
                external_callee_identity: None,
            }],
            "{lookup:#?}"
        );

        let ambiguous_source = r#"package main

import (
    . "example.com/a"
    . "example.com/b"
)

func caller() { Open() }
"#;
        let ambiguous = AnalyzerFixture::new_for_language(
            Language::Go,
            &[
                ("go.mod", "module example.com/app\n"),
                ("main.go", ambiguous_source),
            ],
        );
        for (pack_id, import_path, package_name) in [
            ("fixture.go.dot-a", "example.com/a", "a"),
            ("fixture.go.dot-b", "example.com/b", "b"),
        ] {
            activate_go_function_declaration(
                &ambiguous,
                pack_id,
                import_path,
                package_name,
                "Open",
            );
        }
        let lookup = CallRelationService::dispatch_at_bounded(
            ambiguous.analyzer.analyzer(),
            AnalyzerQueryScope::new(ambiguous.analyzer.analyzer()).token(),
            &ExactCallLocation {
                file: ProjectFile::new(ambiguous.project_root(), "main.go"),
                call_span: call_span(ambiguous_source, "Open()"),
            },
            Arc::from(ambiguous_source),
            generous_limits(),
            None,
        );
        assert_eq!(
            lookup.status,
            Some(DefinitionLookupStatus::UnresolvableImportBoundary),
            "{lookup:#?}"
        );
        assert!(lookup.targets.is_empty(), "{lookup:#?}");
        assert!(
            lookup.boundaries.iter().all(|boundary| match boundary {
                CallDispatchBoundaryKind::External {
                    callee_text,
                    external_callee_identity,
                    ..
                } => callee_text.is_none() && external_callee_identity.is_none(),
                _ => true,
            }),
            "{lookup:#?}"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#2808+911caaf2b65b: Go external dispatch identity requires proven workspace-package absence"
    )]
    #[test]
    fn go_external_identity_requires_proven_absent_workspace_package() {
        let workspace_source = r#"package main

import "example.com/app/library"

func caller() { library.Open() }
"#;
        let workspace = AnalyzerFixture::new_for_language(
            Language::Go,
            &[
                ("go.mod", "module example.com/app\n"),
                ("library/library.go", "package library\n\nfunc Open() {}\n"),
                ("main.go", workspace_source),
            ],
        );
        let workspace_lookup = CallRelationService::dispatch_at_bounded(
            workspace.analyzer.analyzer(),
            AnalyzerQueryScope::new(workspace.analyzer.analyzer()).token(),
            &ExactCallLocation {
                file: ProjectFile::new(workspace.project_root(), "main.go"),
                call_span: call_span(workspace_source, "library.Open()"),
            },
            Arc::from(workspace_source),
            generous_limits(),
            None,
        );
        assert_eq!(
            workspace_lookup.status,
            Some(DefinitionLookupStatus::Resolved),
            "{workspace_lookup:#?}"
        );
        assert_eq!(workspace_lookup.targets.len(), 1, "{workspace_lookup:#?}");
        assert!(
            workspace_lookup.boundaries.is_empty(),
            "{workspace_lookup:#?}"
        );

        let incomplete_source = r#"package main

import "os"

func caller() { _, _ = os.Open("book.xlsx") }
"#;
        let incomplete = AnalyzerFixture::new_for_language(
            Language::Go,
            &[
                ("go.mod", "module example.com/app\n"),
                ("main.go", incomplete_source),
            ],
        );
        let go = crate::analyzer::resolve_analyzer::<crate::analyzer::GoAnalyzer>(
            incomplete.analyzer.analyzer(),
        )
        .expect("fixture Go analyzer");
        let overlay = Arc::new(crate::analyzer::OverlayProject::new(Arc::new(
            incomplete.test_project().clone(),
        )));
        let incomplete_file = ProjectFile::new(incomplete.project_root(), "main.go");
        assert!(overlay.set(
            incomplete_file.abs_path().to_path_buf(),
            incomplete_source.to_owned(),
        ));
        let request_snapshot = go.clone_with_project(overlay as Arc<dyn crate::analyzer::Project>);
        let incomplete_lookup = CallRelationService::dispatch_at_bounded(
            &request_snapshot,
            AnalyzerQueryScope::new(&request_snapshot).token(),
            &ExactCallLocation {
                file: incomplete_file,
                call_span: call_span(incomplete_source, "os.Open(\"book.xlsx\")"),
            },
            Arc::from(incomplete_source),
            generous_limits(),
            None,
        );
        assert_ne!(
            incomplete_lookup.status,
            Some(DefinitionLookupStatus::UnresolvableImportBoundary),
            "an incomplete package inventory cannot prove absence: {incomplete_lookup:#?}"
        );
        assert!(
            incomplete_lookup
                .boundaries
                .iter()
                .all(|boundary| match boundary {
                    CallDispatchBoundaryKind::External {
                        external_callee_identity,
                        ..
                    } => external_callee_identity.is_none(),
                    _ => true,
                }),
            "an incomplete package inventory must not mint external identity: {incomplete_lookup:#?}"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "5c5d4e214494: Go model proof requires one public exact callable and applicable arity"
    )]
    #[test]
    fn modeled_go_package_calls_require_one_public_exact_function() {
        let import_path = "example.com/model";
        let pack_id = "fixture.go.package-calls";
        let id_namespace = pack_id.replace('-', ".");
        let module_id = format!("type.{id_namespace}.module");
        let function =
            |id: &str, name: &str, visibility: &str, parameters: Vec<serde_json::Value>| {
                serde_json::json!({
                    "id": id,
                    "owner": module_id,
                    "name": name,
                    "member_kind": "function",
                    "visibility": visibility,
                    "is_static": true,
                    "signature": { "parameters": parameters },
                    "locator": {
                        "kind": "artifact",
                        "path": "fixture.go",
                        "symbol": format!("{import_path}.{name}")
                    }
                })
            };
        let result_function =
            |id: &str, name: &str, returns: serde_json::Value| -> serde_json::Value {
                let mut declaration = function(id, name, "public", Vec::new());
                declaration["signature"]["returns"] = returns;
                declaration
            };
        let source = r#"package main

import model "example.com/model"

func pair() (int, int) { return 1, 2 }

func caller() {
    values := []int{1, 2}
    model.Open()
    model.Open(1)
    model.Open(model.One())
    model.Open(model.Pair())
    model.Binary(model.Pair())
    model.Zero()
    model.NoResult()
    model.Zero(model.NoResult())
    model.Duration(1)
    model.Vector(1)
    model.Open[int](1)
    model.Variadic()
    model.Variadic(1)
    model.Variadic(1, 2)
    model.Variadic(model.Pair())
    model.Variadic(pair())
    model.Variadic((pair()))
    model.Variadic(values...)
    model.Flag()
    model.Conflict()
    model.Hidden()
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        activate_go_declaration_payload(
            &fixture,
            pack_id,
            import_path,
            "model",
            vec![
                serde_json::json!({
                    "id": format!("type.{id_namespace}.duration"),
                    "name": format!("{import_path}.Duration"),
                    "type_kind": "struct",
                    "visibility": "public",
                    "locator": {
                        "kind": "artifact",
                        "path": "fixture.go",
                        "symbol": format!("{import_path}.Duration")
                    }
                }),
                serde_json::json!({
                    "id": format!("type.{id_namespace}.vector"),
                    "name": format!("{import_path}.Vector"),
                    "type_kind": "struct",
                    "visibility": "public",
                    "locator": {
                        "kind": "artifact",
                        "path": "fixture.go",
                        "symbol": format!("{import_path}.Vector")
                    }
                }),
            ],
            vec![
                function(
                    "member.fixture.open",
                    "Open",
                    "public",
                    vec![serde_json::json!({
                        "name": "value",
                        "type": { "kind": "named", "name": "int" }
                    })],
                ),
                function(
                    "member.fixture.variadic",
                    "Variadic",
                    "public",
                    vec![serde_json::json!({
                        "name": "values",
                        "type": { "kind": "named", "name": "int" },
                        "variadic": true
                    })],
                ),
                function(
                    "member.fixture.binary",
                    "Binary",
                    "public",
                    vec![
                        serde_json::json!({
                            "name": "left",
                            "type": { "kind": "named", "name": "int" }
                        }),
                        serde_json::json!({
                            "name": "right",
                            "type": { "kind": "named", "name": "int" }
                        }),
                    ],
                ),
                function("member.fixture.zero", "Zero", "public", Vec::new()),
                function("member.fixture.no-result", "NoResult", "public", Vec::new()),
                result_function(
                    "member.fixture.one",
                    "One",
                    serde_json::json!({
                        "kind": "named",
                        "name": "int"
                    }),
                ),
                result_function(
                    "member.fixture.pair",
                    "Pair",
                    serde_json::json!({
                        "kind": "tuple",
                        "elements": [
                            { "kind": "named", "name": "int" },
                            { "kind": "named", "name": "int" }
                        ]
                    }),
                ),
                serde_json::json!({
                    "id": "member.fixture.flag",
                    "owner": module_id,
                    "name": "Flag",
                    "member_kind": "constant",
                    "visibility": "public",
                    "is_static": true,
                    "locator": {
                        "kind": "artifact",
                        "path": "fixture.go",
                        "symbol": format!("{import_path}.Flag")
                    }
                }),
                function(
                    "member.fixture.conflict.first",
                    "Conflict",
                    "public",
                    Vec::new(),
                ),
                function(
                    "member.fixture.conflict.second",
                    "Conflict",
                    "public",
                    Vec::new(),
                ),
                function("member.fixture.hidden", "Hidden", "private", Vec::new()),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let lookup = |call: &str| {
            CallRelationService::dispatch_at_bounded(
                fixture.analyzer.analyzer(),
                scope.token(),
                &ExactCallLocation {
                    file: file.clone(),
                    call_span: call_span(source, call),
                },
                Arc::from(source),
                generous_limits(),
                None,
            )
        };

        for (call, canonical, member, effective_parameter_count) in [
            ("model.Open(1)", "example.com/model.Open", "Open", 1),
            (
                "model.Open(model.One())",
                "example.com/model.Open",
                "Open",
                1,
            ),
            (
                "model.Binary(model.Pair())",
                "example.com/model.Binary",
                "Binary",
                2,
            ),
            ("model.One()", "example.com/model.One", "One", 0),
            ("model.Pair()", "example.com/model.Pair", "Pair", 0),
            ("model.Zero()", "example.com/model.Zero", "Zero", 0),
            (
                "model.NoResult()",
                "example.com/model.NoResult",
                "NoResult",
                0,
            ),
            (
                "model.Variadic()",
                "example.com/model.Variadic",
                "Variadic",
                0,
            ),
            (
                "model.Variadic(1)",
                "example.com/model.Variadic",
                "Variadic",
                1,
            ),
            (
                "model.Variadic(1, 2)",
                "example.com/model.Variadic",
                "Variadic",
                2,
            ),
            (
                "model.Variadic(model.Pair())",
                "example.com/model.Variadic",
                "Variadic",
                2,
            ),
        ] {
            let exact = lookup(call);
            assert!(
                scope.store_error().is_none(),
                "modeled call store error: {:?}",
                scope.store_error()
            );
            assert_eq!(
                exact.status,
                Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                "{call}: {exact:#?}; parse errors: {:?}",
                fixture.analyzer.analyzer().parse_errors(&file)
            );
            assert_eq!(
                exact.boundaries,
                vec![CallDispatchBoundaryKind::External {
                    callee_text: Some(canonical.into()),
                    normalized_static_owner: None,
                    external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
                        Language::Go,
                        import_path,
                        member,
                    )),
                }],
                "{call}: {exact:#?}"
            );
            let proof = exact
                .exact_external_call
                .as_ref()
                .unwrap_or_else(|| panic!("{call}: exact external proof: {exact:#?}"));
            assert_eq!(proof.canonical_callee(), canonical, "{call}: {exact:#?}");
            assert_eq!(
                proof.call_application(),
                CallApplicationKind::PackageFunction,
                "{call}: {exact:#?}"
            );
            assert_eq!(
                proof.parameter_count(),
                effective_parameter_count,
                "{call}: {exact:#?}"
            );
        }

        for (call, adjudicated_no_target) in [
            ("model.Open()", true),
            ("model.Duration(1)", true),
            ("model.Vector(1)", true),
            ("model.Open(model.Pair())", true),
            ("model.Zero(model.NoResult())", false),
            ("model.Variadic(pair())", false),
            ("model.Variadic((pair()))", false),
            ("model.Variadic(values...)", false),
            ("model.Flag()", true),
            ("model.Conflict()", false),
            ("model.Hidden()", true),
        ] {
            let rejected = lookup(call);
            assert_eq!(
                rejected.status,
                Some(DefinitionLookupStatus::NoDefinition),
                "{call}: {rejected:#?}"
            );
            assert_eq!(
                rejected.dispatch_extensibility, None,
                "{call}: {rejected:#?}"
            );
            assert!(
                rejected.exact_external_call.is_none(),
                "{call}: rejected calls retain no partial external identity: {rejected:#?}"
            );
            assert_eq!(
                rejected.adjudicated_no_target, adjudicated_no_target,
                "{call}: {rejected:#?}"
            );
            let expected_diagnostic = if adjudicated_no_target {
                GO_MODELED_PACKAGE_CALL_NOT_APPLICABLE_DIAGNOSTIC_KIND
            } else {
                GO_MODELED_PACKAGE_CALL_UNPROVEN_DIAGNOSTIC_KIND
            };
            assert!(
                rejected
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.starts_with(expected_diagnostic)),
                "{call}: {rejected:#?}"
            );
            assert!(
                rejected
                    .boundaries
                    .iter()
                    .all(|boundary| !matches!(boundary, CallDispatchBoundaryKind::External { .. })),
                "{call}: {rejected:#?}"
            );
        }

        let generic = lookup("model.Open[int](1)");
        assert_eq!(
            generic.status,
            Some(DefinitionLookupStatus::InvalidLocation),
            "{generic:#?}"
        );
        assert!(!generic.adjudicated_no_target, "{generic:#?}");
        assert!(
            generic
                .boundaries
                .iter()
                .all(|boundary| !matches!(boundary, CallDispatchBoundaryKind::External { .. })),
            "{generic:#?}"
        );
    }

    #[test]
    fn a_model_cannot_turn_a_workspace_go_package_miss_external() {
        for (pack_id, import_path, package_name, workspace_file) in [
            (
                "fixture.go.workspace-collision",
                "example.com/app/service",
                "service",
                "service/service.go",
            ),
            (
                "fixture.go.vendor-collision",
                "example.com/dep/pkg",
                "pkg",
                "vendor/example.com/dep/pkg/pkg.go",
            ),
        ] {
            let call = format!("{package_name}.Open()");
            let source =
                format!("package main\n\nimport \"{import_path}\"\n\nfunc caller() {{ {call} }}\n");
            let workspace_source = format!("package {package_name}\n");
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[
                    ("go.mod", "module example.com/app\n"),
                    (workspace_file, &workspace_source),
                    ("main.go", &source),
                ],
            );
            activate_go_function_declaration(&fixture, pack_id, import_path, package_name, "Open");
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let tree = crate::analyzer::usages::get_definition::parse_tree_for_language(
                &file,
                Language::Go,
                &source,
            )
            .expect("Go tree");
            let focus_start_byte = source.find("Open").expect("Open reference");
            let focus_end_byte = focus_start_byte + "Open".len();
            let focus_line = source[..focus_start_byte]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count()
                + 1;
            let site = ResolvedReferenceSite {
                path: crate::path_utils::rel_path_string(&file),
                text: "Open".to_owned(),
                range: Range {
                    start_byte: focus_start_byte,
                    end_byte: focus_end_byte,
                    start_line: focus_line,
                    end_line: focus_line,
                },
                focus_start_byte,
                focus_end_byte,
            };
            let go = crate::analyzer::resolve_analyzer::<crate::analyzer::GoAnalyzer>(
                fixture.analyzer.analyzer(),
            )
            .expect("fixture Go analyzer");
            let index_builds_before = go.workspace_path_index_build_count_for_test();
            assert_eq!(
                index_builds_before, 0,
                "the bounded regression must exercise a cold workspace path index"
            );
            let bounded = crate::analyzer::usages::get_definition::resolve_go_bounded(
                fixture.analyzer.analyzer(),
                &file,
                &source,
                Some(&tree),
                &site,
                brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget::default(
                ),
                None,
            );
            let crate::analyzer::usages::get_definition::BoundedResolution::Complete {
                value: bounded,
                ..
            } = bounded
            else {
                panic!(
                    "bounded Go lookup should complete without scanning the workspace: {bounded:#?}"
                );
            };
            assert_eq!(bounded.status, DefinitionLookupStatus::NoDefinition);
            assert!(bounded.reference.is_none(), "{bounded:#?}");
            assert_eq!(
                go.workspace_path_index_build_count_for_test(),
                index_builds_before,
                "bounded resolution must not initialize the whole-workspace path index"
            );

            let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
            let lookup = CallRelationService::dispatch_at_bounded(
                fixture.analyzer.analyzer(),
                scope.token(),
                &ExactCallLocation {
                    file,
                    call_span: call_span(&source, &call),
                },
                Arc::from(source),
                generous_limits(),
                None,
            );

            assert_eq!(
                lookup.status,
                Some(DefinitionLookupStatus::NoDefinition),
                "{import_path}: {lookup:#?}"
            );
            assert!(
                lookup
                    .boundaries
                    .iter()
                    .all(|boundary| !matches!(boundary, CallDispatchBoundaryKind::External { .. })),
                "{import_path}: {lookup:#?}"
            );
            assert_eq!(
                go.workspace_path_index_build_count_for_test(),
                index_builds_before,
                "bounded exact dispatch must not initialize the whole-workspace path index"
            );
        }
    }

    #[test]
    fn local_go_value_named_like_package_is_not_an_external_member() {
        let source = r#"package main

type opener struct{}
func (opener) Open(string) {}

func caller(os opener) { os.Open("book.xlsx") }
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &ExactCallLocation {
                file,
                call_span: call_span(source, "os.Open(\"book.xlsx\")"),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert!(
            !lookup.boundaries.iter().any(|boundary| matches!(
                boundary,
                CallDispatchBoundaryKind::External {
                    callee_text: Some(target),
                    ..
                } if target.as_ref() == "os.Open"
            )),
            "{lookup:#?}"
        );
    }

    #[test]
    fn exact_dispatch_retains_python_imported_callable_proof() {
        let source = "import subprocess\ndef caller(command):\n    return subprocess.run(command, shell=True)\n";
        let fixture =
            AnalyzerFixture::new_for_language(Language::Python, &[("external.py", source)]);
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            AnalyzerQueryScope::new(fixture.analyzer.analyzer()).token(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "external.py"),
                call_span: call_span(source, "subprocess.run(command, shell=True)"),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert_eq!(
            lookup.status,
            Some(DefinitionLookupStatus::UnresolvableImportBoundary),
            "{lookup:#?}"
        );
        assert_eq!(lookup.boundary, Some(BoundaryStatus::ExternalIndexed));
        assert_eq!(
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::External {
                callee_text: Some("subprocess.run".into()),
                normalized_static_owner: None,
                external_callee_identity: None,
            }]
        );
        let proof = lookup
            .exact_external_call
            .as_ref()
            .expect("Python import proof");
        assert_eq!(proof.canonical_callee(), "subprocess.run");
        assert_eq!(
            proof.call_application(),
            CallApplicationKind::PackageFunction
        );
        assert_eq!(proof.parameter_count(), 2);
    }

    #[test]
    fn exact_dispatch_resolves_cpp_template_operator_and_destructor_names() {
        let source = r#"
namespace ns {
template <typename T> void make(T) {}
template <typename T> struct Box { Box() {} };
struct Widget {
  template <typename T> void run(T) {}
  Widget& operator+(int) { return *this; }
  ~Widget() {}
};
}
void caller(ns::Widget& receiver) {
  ns::make<int>(1);
  new ns::Box<int>();
  receiver.run<int>(1);
  receiver.operator+(1);
  receiver.~Widget();
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Cpp, &[("calls.cpp", source)]);

        for (call, identifier) in [
            ("ns::make<int>(1)", "make"),
            ("new ns::Box<int>()", "Box"),
            ("receiver.run<int>(1)", "run"),
            ("receiver.operator+(1)", "operator+"),
            ("receiver.~Widget()", "~Widget"),
        ] {
            let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
            let token = scope.token();
            let lookup = CallRelationService::dispatch_at_bounded(
                fixture.analyzer.analyzer(),
                token,
                &ExactCallLocation {
                    file: ProjectFile::new(fixture.project_root(), "calls.cpp"),
                    call_span: call_span(source, call),
                },
                Arc::from(source),
                generous_limits(),
                None,
            );

            assert_eq!(
                lookup.status,
                Some(DefinitionLookupStatus::Resolved),
                "{call}: {lookup:#?}"
            );
            assert_eq!(lookup.targets.len(), 1, "{call}: {lookup:#?}");
            assert_eq!(lookup.targets[0].definition.identifier(), identifier);
            assert!(lookup.boundaries.is_empty(), "{call}: {lookup:#?}");
        }
    }

    #[test]
    fn exact_dispatch_keeps_cpp_function_pointer_calls_as_a_typed_boundary() {
        let source = r#"
void target() {}
void caller() {
  void (*callable)() = &target;
  callable();
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Cpp, &[("calls.cpp", source)]);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "calls.cpp"),
                call_span: call_span(source, "callable()"),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert_eq!(lookup.status, Some(DefinitionLookupStatus::NoDefinition));
        assert!(lookup.targets.is_empty(), "{lookup:#?}");
        assert_eq!(
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::Unresolved(
                DefinitionLookupStatus::NoDefinition
            )]
        );
        assert!(
            lookup
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("no_indexed_definition")),
            "{lookup:#?}"
        );
    }

    #[test]
    fn exact_dispatch_publishes_c_header_proof_and_identity() {
        use crate::analyzer::semantic_model::{
            CatalogOptions, DependencyPackLimits, SemanticModelActivationControl,
            SemanticModelActivationRequest, SemanticModelControlAction, SemanticModelControlScope,
            SemanticModelPackSelector, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
            SemanticPackCatalog,
        };
        use crate::analyzer::workspace::{DependencyPackEcosystem, DependencyPackWorkspaceContext};

        let source = "#include <stdlib.h>\nvoid caller(void) { system(getenv(\"X\")); }\n";
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical temp root");
        let app = root.join("app");
        std::fs::create_dir_all(&app).expect("app directory");
        ProjectFile::new(app.clone(), "probe.c")
            .write(source)
            .expect("source");
        ProjectFile::new(root, "stubs/include/stdlib.h")
            .write("char *getenv(const char *name);\nint system(const char *command);\n")
            .expect("header");
        ProjectFile::new(app.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"probe.c","arguments":["clang","-I","../stubs/include","-c","probe.c"]}]"#)
            .expect("compile database");
        let analyzer = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(app.clone(), Language::Cpp)),
            AnalyzerConfig::default(),
        )
        .expect("C analyzer");
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("semantic-pack catalog");
        let cancellation = CancellationToken::new();
        let activation = SemanticModelActivationRequest {
            bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
                .expect("crate version"),
            evidence: Vec::new(),
            controls: vec![SemanticModelActivationControl {
                scope: SemanticModelControlScope::Workspace,
                action: SemanticModelControlAction::Enable,
                selector: SemanticModelPackSelector {
                    pack_id: "bifrost.external.cpp-headers".to_owned(),
                    version: None,
                    manifest_digest: None,
                },
            }],
            limits: SemanticModelRuntimeLimits::default(),
        };
        let activation_outcome = analyzer.activate_dependency_packs(
            &AnalyzerConfig::default(),
            &[DependencyPackEcosystem::Cpp],
            DependencyPackWorkspaceContext {
                catalog: &catalog,
                persistence: None,
                activation: &activation,
                limits: DependencyPackLimits::default(),
                cancellation: &cancellation,
            },
        );
        assert!(activation_outcome.complete(), "{activation_outcome:#?}");
        assert!(matches!(
            activation_outcome.runtime,
            Some(SemanticModelRuntimeOutcome::Ready { .. })
        ));
        let file = ProjectFile::new(app, "probe.c");
        let scope = AnalyzerQueryScope::new(analyzer.analyzer());

        for (call, member, arity) in [
            ("getenv(\"X\")", "getenv", 1),
            ("system(getenv(\"X\"))", "system", 1),
        ] {
            let lookup = CallRelationService::dispatch_at_bounded(
                analyzer.analyzer(),
                scope.token(),
                &ExactCallLocation {
                    file: file.clone(),
                    call_span: call_span(source, call),
                },
                Arc::from(source),
                generous_limits(),
                None,
            );

            assert_eq!(
                lookup.status,
                Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                "{call}: {lookup:#?}"
            );
            assert!(lookup.targets.is_empty(), "{call}: {lookup:#?}");
            let proof = lookup.exact_external_call.as_ref().unwrap_or_else(|| {
                panic!("{call} must carry its exact C header proof: {lookup:#?}")
            });
            assert_eq!(proof.canonical_callee(), format!("stdlib::{member}"));
            assert_eq!(proof.parameter_count(), arity);
            assert!(
                !proof.has_receiver(),
                "C header functions are receiverless: {lookup:#?}"
            );
            assert_eq!(
                lookup.boundaries,
                vec![CallDispatchBoundaryKind::External {
                    callee_text: Some(proof.canonical_callee().into()),
                    normalized_static_owner: None,
                    external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
                        Language::Cpp,
                        "stdlib",
                        member,
                    )),
                }],
                "{call}: resolver-owned proof and identity must survive call dispatch",
            );
        }
    }

    #[test]
    fn exact_dispatch_keeps_cpp_internal_linkage_in_its_translation_unit() {
        let caller_source = r#"
static int local_target(int value) { return value + 1; }
int caller() { return local_target(1); }
"#;
        let unrelated_source = "static int local_target(int value) { return value + 2; }\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Cpp,
            &[
                ("caller.c", caller_source),
                ("unrelated.c", unrelated_source),
            ],
        );
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "caller.c"),
                call_span: call_span(caller_source, "local_target(1)"),
            },
            Arc::from(caller_source),
            generous_limits(),
            None,
        );

        assert_eq!(lookup.status, Some(DefinitionLookupStatus::Resolved));
        assert_eq!(lookup.targets.len(), 1, "{lookup:#?}");
        assert_eq!(
            lookup.targets[0].definition.source().rel_path(),
            std::path::Path::new("caller.c")
        );
        assert!(lookup.boundaries.is_empty(), "{lookup:#?}");
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#1372: C++ header/body integration fixture checks a unique implementation body is selected with proven identity"
    )]
    #[test]
    fn exact_dispatch_projects_cpp_header_declarations_to_the_unique_body() {
        let header_source = "int relay(int value);\n";
        let body_source = "#include \"relay.h\"\nint relay(int value) { return value; }\n";
        let caller_source =
            "#include \"relay.h\"\nint caller(int value) { return relay(value); }\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Cpp,
            &[
                ("relay.h", header_source),
                ("relay.cpp", body_source),
                ("caller.cpp", caller_source),
            ],
        );

        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "caller.cpp"),
                call_span: call_span(caller_source, "relay(value)"),
            },
            Arc::from(caller_source),
            generous_limits(),
            None,
        );

        assert_eq!(lookup.status, Some(DefinitionLookupStatus::Resolved));
        assert_eq!(lookup.targets.len(), 1, "{lookup:#?}");
        assert_eq!(
            lookup.targets[0].definition.source().rel_path(),
            std::path::Path::new("relay.cpp")
        );
        assert_eq!(lookup.targets[0].proof, UsageProof::Proven);
        assert!(lookup.boundaries.is_empty(), "{lookup:#?}");
    }

    #[brokk_bifrost_test_macros::hardwon(
        "65290303b8a6: C++ navigation uncertainty used to discard candidate call targets instead of retaining them as unproven"
    )]
    #[test]
    fn exact_dispatch_preserves_cpp_navigation_uncertainty() {
        let definition = CodeUnit::new(
            ProjectFile::new(std::env::temp_dir(), "relay.cpp"),
            CodeUnitType::Function,
            "",
            "relay",
        );
        let outcome = |status, structure_unavailable, truncated| CallTargetLookupOutcome {
            outcome: DefinitionLookupOutcome {
                modeled_definitions: Vec::new(),
                status,
                reference: None,
                definitions: vec![definition.clone()],
                lexical_definition: None,
                diagnostics: Vec::new(),
            },
            authority:
                crate::analyzer::usages::get_definition::DefinitionResolutionAuthority::Incumbent,
            call_application: CallApplicationKind::Unknown,
            dispatch_extensibility: None,
            exact_external_call: None,
            external_callee_identity: None,
            structure_unavailable,
            unproven_link_unit: false,
            truncated,
        };

        let mut unavailable = CallDispatchLookup::default();
        apply_call_target_outcome(
            None,
            &mut unavailable,
            ExpandedExternalCallee::unproven(outcome(
                DefinitionLookupStatus::Resolved,
                true,
                false,
            )),
            8,
            Language::Cpp,
            None,
        );
        assert_eq!(unavailable.targets.len(), 1, "{unavailable:#?}");
        assert_eq!(unavailable.targets[0].proof, UsageProof::Unproven);
        assert!(
            unavailable
                .boundaries
                .contains(&CallDispatchBoundaryKind::UnprovenTargetIdentity),
            "{unavailable:#?}"
        );

        // Since #1440 an ambiguous lookup surfaces its candidate definitions as
        // Unproven targets instead of dropping them; the truncation flags and
        // boundary still record that navigation gave up early.
        let mut truncated = CallDispatchLookup::default();
        apply_call_target_outcome(
            None,
            &mut truncated,
            ExpandedExternalCallee::unproven(outcome(
                DefinitionLookupStatus::Ambiguous,
                false,
                true,
            )),
            8,
            Language::Cpp,
            None,
        );
        assert_eq!(truncated.targets.len(), 1, "{truncated:#?}");
        assert_eq!(truncated.targets[0].proof, UsageProof::Unproven);
        assert!(truncated.truncated, "{truncated:#?}");
        assert!(truncated.budget_exhausted, "{truncated:#?}");
        assert!(
            truncated
                .boundaries
                .contains(&CallDispatchBoundaryKind::Truncated),
            "{truncated:#?}"
        );
        assert!(
            !truncated
                .boundaries
                .contains(&CallDispatchBoundaryKind::Unresolved(
                    DefinitionLookupStatus::Ambiguous
                )),
            "{truncated:#?}"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#1372: Checks multiple candidate C++ bodies remain ambiguous and unproven instead of choosing one"
    )]
    #[test]
    fn exact_dispatch_keeps_multiple_cpp_bodies_unproven() {
        let header_source = "int relay(int value);\n";
        let first_body = "#include \"relay.h\"\nint relay(int value) { return value + 1; }\n";
        let second_body = "#include \"relay.h\"\nint relay(int value) { return value + 2; }\n";
        let caller_source =
            "#include \"relay.h\"\nint caller(int value) { return relay(value); }\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Cpp,
            &[
                ("relay.h", header_source),
                ("first.cpp", first_body),
                ("second.cpp", second_body),
                ("caller.cpp", caller_source),
            ],
        );

        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "caller.cpp"),
                call_span: call_span(caller_source, "relay(value)"),
            },
            Arc::from(caller_source),
            generous_limits(),
            None,
        );

        // Since #1440 the two candidate bodies survive as Unproven targets;
        // ambiguity is expressed by the status and the per-target proof, and the
        // Unresolved(Ambiguous) boundary is reserved for lookups that surface no
        // targets at all.
        assert_eq!(lookup.status, Some(DefinitionLookupStatus::Ambiguous));
        let mut target_paths: Vec<_> = lookup
            .targets
            .iter()
            .map(|target| target.definition.source().rel_path().to_path_buf())
            .collect();
        target_paths.sort();
        assert_eq!(
            target_paths,
            vec![
                std::path::PathBuf::from("first.cpp"),
                std::path::PathBuf::from("second.cpp"),
            ],
            "{lookup:#?}"
        );
        assert!(
            lookup
                .targets
                .iter()
                .all(|target| target.proof == UsageProof::Unproven),
            "{lookup:#?}"
        );
        assert!(
            lookup
                .boundaries
                .contains(&CallDispatchBoundaryKind::UnprovenTargetIdentity),
            "{lookup:#?}"
        );
        assert!(
            !lookup
                .boundaries
                .contains(&CallDispatchBoundaryKind::Unresolved(
                    DefinitionLookupStatus::Ambiguous
                )),
            "{lookup:#?}"
        );
    }

    #[test]
    fn exact_dispatch_resolves_ruby_safe_navigation_calls_with_blocks() {
        let source = r#"class Service
  def run(value)
  end
end

class Caller
  def call
    service = Service.new
    service&.run(1) { |value| value }
  end
end
"#;
        let call = "service&.run(1) { |value| value }";
        let fixture = AnalyzerFixture::new_for_language(Language::Ruby, &[("example.rb", source)]);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "example.rb"),
                call_span: call_span(source, call),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert_eq!(lookup.status, Some(DefinitionLookupStatus::Resolved));
        assert_eq!(lookup.targets.len(), 1, "{lookup:#?}");
        assert_eq!(lookup.targets[0].definition.fq_name(), "Service.run");
        assert_eq!(lookup.targets[0].proof, UsageProof::Proven);
        assert!(lookup.boundaries.is_empty(), "{lookup:#?}");
    }

    #[test]
    fn exact_dispatch_keeps_ruby_dynamic_send_as_an_unresolved_boundary() {
        let source = r#"class Example
  def target
  end

  def caller
    public_send(:target)
  end
end
"#;
        let call = "public_send(:target)";
        let fixture = AnalyzerFixture::new_for_language(Language::Ruby, &[("example.rb", source)]);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "example.rb"),
                call_span: call_span(source, call),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert_eq!(lookup.status, Some(DefinitionLookupStatus::NoDefinition));
        assert!(lookup.targets.is_empty(), "{lookup:#?}");
        assert_eq!(
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::Unresolved(
                DefinitionLookupStatus::NoDefinition
            )]
        );
        assert!(
            lookup
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("unsupported_ruby_dynamic_dispatch")),
            "{lookup:#?}"
        );
    }

    #[test]
    fn exact_dispatch_resolves_ruby_operator_methods_from_the_operator_token() {
        let source = r#"class Example
  def +(value)
    value
  end

  def [](index)
    index
  end

  def caller
    self.+(1)
    self.[](2)
  end
end
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Ruby, &[("example.rb", source)]);

        for (call, target) in [("self.+(1)", "Example.+"), ("self.[](2)", "Example.[]")] {
            let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
            let token = scope.token();
            let lookup = CallRelationService::dispatch_at_bounded(
                fixture.analyzer.analyzer(),
                token,
                &ExactCallLocation {
                    file: ProjectFile::new(fixture.project_root(), "example.rb"),
                    call_span: call_span(source, call),
                },
                Arc::from(source),
                generous_limits(),
                None,
            );

            assert_eq!(lookup.status, Some(DefinitionLookupStatus::Resolved));
            assert_eq!(lookup.targets.len(), 1, "{call}: {lookup:#?}");
            assert_eq!(lookup.targets[0].definition.fq_name(), target);
            assert_eq!(lookup.targets[0].proof, UsageProof::Proven);
            assert!(lookup.boundaries.is_empty(), "{call}: {lookup:#?}");
        }
    }

    #[test]
    fn exact_dispatch_keeps_ruby_callable_objects_as_a_typed_unresolved_boundary() {
        let source = r#"class Example
  def caller(callable)
    callable.(1)
  end
end
"#;
        let call = "callable.(1)";
        let fixture = AnalyzerFixture::new_for_language(Language::Ruby, &[("example.rb", source)]);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "example.rb"),
                call_span: call_span(source, call),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert_eq!(lookup.status, Some(DefinitionLookupStatus::NoDefinition));
        assert!(lookup.targets.is_empty(), "{lookup:#?}");
        assert_eq!(
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::Unresolved(
                DefinitionLookupStatus::NoDefinition
            )]
        );
        assert!(
            lookup
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("unsupported_ruby_callable_object_dispatch")),
            "{lookup:#?}"
        );
    }

    #[test]
    fn ruby_outgoing_relations_keep_attached_block_calls_separate() {
        let source = r#"class Example
  def target
  end

  def nested
  end

  def direct
  end

  def caller
    target() do
      nested()
    end
    direct()
  end
end
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Ruby, &[("example.rb", source)]);
        let analyzer = fixture.analyzer.analyzer();
        let caller = analyzer
            .definitions("Example.caller")
            .next()
            .expect("Ruby caller");

        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let relation = CallRelationService::outgoing_bounded(
            analyzer,
            token,
            &caller,
            generous_limits(),
            None,
        );
        let callees = relation
            .sites
            .iter()
            .map(|site| site.callee.fq_name())
            .collect::<Vec<_>>();

        assert_eq!(
            callees,
            vec!["Example.target".to_string(), "Example.direct".to_string()],
            "{relation:#?}"
        );
    }

    #[test]
    fn scala_outgoing_relations_keep_nested_partial_function_and_given_calls_separate() {
        let source = r#"
package example

object Calls {
  def nestedCall(): Int = 1
  def matchCall(): Int = 2
  def directCall(): Int = 3

  def outer(value: Int): Int = {
    val partial: PartialFunction[Int, Int] = { case _ => nestedCall() }
    given generated: Int = nestedCall()
    val matched = value match { case _ => matchCall() }
    directCall()
  }
}
"#;
        let fixture =
            AnalyzerFixture::new_for_language(Language::Scala, &[("Calls.scala", source)]);
        let analyzer = fixture.analyzer.analyzer();
        let caller = analyzer
            .definitions("example.Calls$.outer")
            .next()
            .expect("Scala caller");

        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let relation = CallRelationService::outgoing_bounded(
            analyzer,
            token,
            &caller,
            generous_limits(),
            None,
        );
        let callees = relation
            .sites
            .iter()
            .map(|site| site.callee.fq_name())
            .collect::<Vec<_>>();

        assert_eq!(
            callees,
            vec![
                "example.Calls$.matchCall".to_string(),
                "example.Calls$.directCall".to_string(),
            ],
            "{relation:#?}"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "bc14f106eeaa: exact dispatch reuses parsed syntax without changing requested call order"
    )]
    #[test]
    fn exact_dispatch_session_charges_one_parse_and_preserves_reverse_call_order() {
        let source: Arc<str> = Arc::from(
            "function first() {}\nfunction second() {}\nfunction caller() { first(); second(); }\n",
        );
        let fixture =
            AnalyzerFixture::new_for_language(Language::TypeScript, &[("sample.ts", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "sample.ts");
        let spans = [
            call_span(&source, "first()"),
            call_span(&source, "second()"),
        ];
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let mut session = CallRelationService::dispatch_session(file.clone(), Arc::clone(&source));
        assert_eq!(
            session.retained_bytes(),
            crate::analyzer::tree_sitter_analyzer::prepared_syntax_retained_bytes(source.len())
                .saturating_add(file.retained_bytes()),
            "the retained session owns both its parsed source and exact project path"
        );
        let second = session.dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &spans[1],
            generous_limits().max_candidates,
            None,
        );
        let first = session.dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &spans[0],
            generous_limits().max_candidates,
            None,
        );

        assert_eq!(second.work.scanned_files, 1);
        assert_eq!(second.work.scanned_source_bytes, source.len());
        assert_eq!(second.work.examined_candidates, 1);
        assert_eq!(first.work.scanned_files, 0);
        assert_eq!(first.work.scanned_source_bytes, 0);
        assert_eq!(first.work.examined_candidates, 1);
        assert_eq!(first.targets[0].definition.fq_name(), "first");
        assert_eq!(second.targets[0].definition.fq_name(), "second");

        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let single = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &ExactCallLocation {
                file,
                call_span: spans[1],
            },
            source,
            generous_limits(),
            None,
        );
        assert_eq!(single.work.scanned_files, 1);
        assert_eq!(
            single.work.scanned_source_bytes,
            second.work.scanned_source_bytes
        );
        assert_eq!(single.work.examined_candidates, 1);
        assert_eq!(single.status, second.status);
        assert_eq!(single.targets, second.targets);
        assert_eq!(single.boundaries, second.boundaries);
    }

    #[test]
    fn exact_dispatch_session_cancellation_does_not_reclassify_prior_calls() {
        let source: Arc<str> = Arc::from(
            "function first() {}\nfunction second() {}\nfunction caller() { first(); second(); }\n",
        );
        let fixture =
            AnalyzerFixture::new_for_language(Language::TypeScript, &[("sample.ts", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "sample.ts");
        let spans = [
            call_span(&source, "first()"),
            call_span(&source, "second()"),
        ];
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let cancellation = CancellationToken::default();
        let source_len = source.len();
        let mut session = CallRelationService::dispatch_session(file, source);

        let first = session.dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &spans[0],
            generous_limits().max_candidates,
            Some(&cancellation),
        );
        cancellation.cancel();
        let second = session.dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &spans[1],
            generous_limits().max_candidates,
            Some(&cancellation),
        );

        assert!(!first.cancelled);
        assert_eq!(first.work.scanned_source_bytes, source_len);
        assert!(second.cancelled);
        assert_eq!(second.work.scanned_files, 0);
        assert_eq!(second.work.scanned_source_bytes, 0);
        assert_eq!(second.work.examined_candidates, 0);
    }

    #[brokk_bifrost_test_macros::hardwon(
        "adf896b7d160: ambiguous TypeScript dispatch dropped candidate declarations and empty-boundary status evidence"
    )]
    #[test]
    fn dispatch_mapping_preserves_ambiguous_targets_and_empty_boundary() {
        let root = std::env::temp_dir();
        let file = ProjectFile::new(&root, "dispatch.ts");
        let first = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "first");
        let second = CodeUnit::new(file, CodeUnitType::Function, "", "second");
        let mut ambiguous = CallDispatchLookup::default();
        apply_dispatch_outcome(
            &mut ambiguous,
            DefinitionLookupOutcome {
                modeled_definitions: Vec::new(),
                status: DefinitionLookupStatus::Ambiguous,
                reference: None,
                definitions: vec![second, first],
                lexical_definition: None,
                diagnostics: vec![DefinitionLookupDiagnostic {
                    claim: None,
                    kind: "ambiguous_definition".to_string(),
                    message: "two candidates".to_string(),
                }],
            },
            2,
            Language::TypeScript,
        );
        assert_eq!(ambiguous.status, Some(DefinitionLookupStatus::Ambiguous));
        assert_eq!(
            ambiguous
                .targets
                .iter()
                .map(|target| (target.definition.fq_name(), target.proof))
                .collect::<Vec<_>>(),
            vec![
                ("first".to_string(), UsageProof::Unproven),
                ("second".to_string(), UsageProof::Unproven),
            ]
        );
        assert!(!ambiguous.truncated);
        assert!(!ambiguous.budget_exhausted);
        assert!(ambiguous.boundaries.is_empty());

        let retained = CodeUnit::new(
            ProjectFile::new(root, "partial.ts"),
            CodeUnitType::Function,
            "",
            "retained",
        );
        let mut partial_ambiguous = CallDispatchLookup::default();
        apply_dispatch_outcome(
            &mut partial_ambiguous,
            DefinitionLookupOutcome {
                modeled_definitions: Vec::new(),
                status: DefinitionLookupStatus::Ambiguous,
                reference: None,
                definitions: vec![retained],
                lexical_definition: None,
                diagnostics: vec![
                    DefinitionLookupDiagnostic {
                        claim: None,
                        kind: PARTIAL_IMPORT_BOUNDARY_DIAGNOSTIC.to_string(),
                        message: "one candidate is external".to_string(),
                    },
                    DefinitionLookupDiagnostic {
                        claim: None,
                        kind: PARTIAL_IMPORT_UNRESOLVED_DIAGNOSTIC.to_string(),
                        message: "one candidate is unresolved".to_string(),
                    },
                ],
            },
            2,
            Language::TypeScript,
        );
        assert_eq!(partial_ambiguous.targets.len(), 1);
        assert_eq!(
            partial_ambiguous.boundaries,
            vec![
                CallDispatchBoundaryKind::External {
                    callee_text: None,
                    normalized_static_owner: None,
                    external_callee_identity: None,
                },
                CallDispatchBoundaryKind::Unresolved(DefinitionLookupStatus::NoDefinition),
            ]
        );

        let mut empty_ambiguous = CallDispatchLookup::default();
        apply_dispatch_outcome(
            &mut empty_ambiguous,
            DefinitionLookupOutcome {
                modeled_definitions: Vec::new(),
                status: DefinitionLookupStatus::Ambiguous,
                reference: None,
                definitions: Vec::new(),
                lexical_definition: None,
                diagnostics: vec![DefinitionLookupDiagnostic {
                    claim: None,
                    kind: "ambiguous_definition".to_string(),
                    message: "ambiguous without retainable candidates".to_string(),
                }],
            },
            1,
            Language::TypeScript,
        );
        assert_eq!(
            empty_ambiguous.boundaries,
            vec![CallDispatchBoundaryKind::Unresolved(
                DefinitionLookupStatus::Ambiguous
            )]
        );

        let mut external = CallDispatchLookup::default();
        apply_dispatch_outcome(
            &mut external,
            DefinitionLookupOutcome {
                modeled_definitions: Vec::new(),
                status: DefinitionLookupStatus::UnresolvableImportBoundary,
                reference: None,
                definitions: Vec::new(),
                lexical_definition: None,
                diagnostics: Vec::new(),
            },
            1,
            Language::TypeScript,
        );
        assert_eq!(
            external.boundaries,
            vec![CallDispatchBoundaryKind::External {
                callee_text: None,
                normalized_static_owner: None,
                external_callee_identity: None,
            }]
        );

        for status in [
            DefinitionLookupStatus::NoDefinition,
            DefinitionLookupStatus::UnsupportedLanguage,
            DefinitionLookupStatus::InvalidLocation,
            DefinitionLookupStatus::NotFound,
        ] {
            let mut unresolved = CallDispatchLookup::default();
            apply_dispatch_outcome(
                &mut unresolved,
                DefinitionLookupOutcome {
                    modeled_definitions: Vec::new(),
                    status,
                    reference: None,
                    definitions: Vec::new(),
                    lexical_definition: None,
                    diagnostics: Vec::new(),
                },
                1,
                Language::TypeScript,
            );
            assert_eq!(unresolved.status, Some(status));
            assert_eq!(
                unresolved.boundaries,
                vec![CallDispatchBoundaryKind::Unresolved(status)]
            );
        }
    }

    #[test]
    fn go_no_definition_does_not_fabricate_an_external_package_identity() {
        let reference = ResolvedReferenceSite {
            path: "main.go".to_owned(),
            text: "missing.Open".to_owned(),
            range: Range {
                start_byte: 0,
                end_byte: 12,
                start_line: 1,
                end_line: 1,
            },
            focus_start_byte: 8,
            focus_end_byte: 12,
        };
        let outcome = |status| DefinitionLookupOutcome {
            modeled_definitions: Vec::new(),
            status,
            reference: Some(reference.clone()),
            definitions: Vec::new(),
            lexical_definition: None,
            diagnostics: Vec::new(),
        };

        let mut unresolved = CallDispatchLookup::default();
        apply_dispatch_outcome(
            &mut unresolved,
            outcome(DefinitionLookupStatus::NoDefinition),
            1,
            Language::Go,
        );
        assert_eq!(
            unresolved.boundaries,
            vec![CallDispatchBoundaryKind::Unresolved(
                DefinitionLookupStatus::NoDefinition
            )],
            "dotted spelling without an import-binding proof stays unresolved"
        );

        let mut imported = CallDispatchLookup::default();
        apply_dispatch_outcome(
            &mut imported,
            outcome(DefinitionLookupStatus::UnresolvableImportBoundary),
            1,
            Language::Go,
        );
        assert!(
            matches!(
                imported.boundaries.as_slice(),
                [CallDispatchBoundaryKind::External { .. }]
            ),
            "the resolver's proven imported-package boundary remains external: {imported:#?}"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#2579: unresolved residuals lost a structured target needed to bind modeled effects"
    )]
    #[test]
    fn unresolved_outcome_retains_only_a_structured_canonical_callee_target() {
        let canonical_reference = ResolvedReferenceSite {
            path: "Caller.java".to_owned(),
            text: "com.example.Missing.run".to_owned(),
            range: Range {
                start_byte: 0,
                end_byte: 23,
                start_line: 1,
                end_line: 1,
            },
            focus_start_byte: 20,
            focus_end_byte: 23,
        };
        let mut named = CallDispatchLookup::default();
        apply_dispatch_outcome(
            &mut named,
            DefinitionLookupOutcome {
                modeled_definitions: Vec::new(),
                status: DefinitionLookupStatus::NotFound,
                reference: Some(canonical_reference),
                definitions: Vec::new(),
                lexical_definition: None,
                diagnostics: Vec::new(),
            },
            1,
            Language::Java,
        );
        assert!(matches!(
            named.boundaries.as_slice(),
            [CallDispatchBoundaryKind::UnresolvedWithTarget {
                status: DefinitionLookupStatus::NotFound,
                callee_text,
                ..
            }] if callee_text.as_ref() == "com.example.Missing.run"
        ));

        let mut unnamed = CallDispatchLookup::default();
        apply_dispatch_outcome(
            &mut unnamed,
            DefinitionLookupOutcome {
                modeled_definitions: Vec::new(),
                status: DefinitionLookupStatus::NotFound,
                reference: None,
                definitions: Vec::new(),
                lexical_definition: None,
                diagnostics: Vec::new(),
            },
            1,
            Language::Java,
        );
        assert_eq!(
            unnamed.boundaries,
            vec![CallDispatchBoundaryKind::Unresolved(
                DefinitionLookupStatus::NotFound
            )],
            "an unnamed residual must remain targetless"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "2b11cc505fc4: a Kotlin receiver expression could be mistaken for a package-rooted external identity"
    )]
    #[test]
    fn kotlin_external_identity_requires_resolver_proven_package_root() {
        assert_eq!(
            canonical_external_callee("com.example.ext.Ext.wrap", Language::Kotlin, None, true,),
            Some("com.example.ext.Ext.wrap".to_owned()),
            "the Kotlin external-member resolver may publish its canonical identity"
        );
        for expression_spelling in [
            "value.value.toString",
            "this.kotlin.notRegisteredMessage",
            "type.upperBounds.first",
        ] {
            assert_eq!(
                canonical_external_callee(expression_spelling, Language::Kotlin, None, false,),
                None,
                "a receiver-expression spelling is not a package-rooted identity"
            );
        }
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#3017: PHP integration ensures external identity derives from resolver output rather than the textual receiver expression"
    )]
    #[test]
    fn php_external_identity_comes_from_the_resolver_not_expression_text() {
        let source = r#"<?php
namespace App;

function caller(string $input): string {
    return PHP_EOL . substr(...[$input, 0, 1]);
}
"#;
        let call = "substr(...[$input, 0, 1])";
        let fixture = AnalyzerFixture::new_for_language(Language::Php, &[("App.php", source)]);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "App.php"),
                call_span: call_span(source, call),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert!(lookup.targets.is_empty(), "{lookup:#?}");
        assert_eq!(
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::External {
                callee_text: None,
                normalized_static_owner: None,
                external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
                    Language::Php,
                    crate::analyzer::php::PHP_GLOBAL_NAMESPACE,
                    "substr",
                )),
            }],
            "the resolver-owned global identity must replace expression text without minting a target: {lookup:#?}"
        );
        assert_eq!(
            canonical_external_callee(".PHP_EOL.substr", Language::Php, None, false),
            None,
            "a PHP expression spelling is never a bindable identity"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#2823: Kotlin unknown receiver chain stays without an external identity when structured receiver resolution is incomplete"
    )]
    #[test]
    fn kotlin_unknown_receiver_chain_stays_identityless() {
        let source = r#"package app

class Holder(val value: MissingType)

fun caller(holder: Holder): String = holder.value.toString()
"#;
        let call = "holder.value.toString()";
        let fixture = AnalyzerFixture::new_for_language(Language::Kotlin, &[("App.kt", source)]);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "App.kt"),
                call_span: call_span(source, call),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert!(lookup.targets.is_empty(), "{lookup:#?}");
        assert!(
            lookup.boundaries.iter().all(|boundary| !matches!(
                boundary,
                CallDispatchBoundaryKind::External {
                    callee_text: Some(_),
                    ..
                }
            )),
            "an unknown Kotlin receiver chain must not become bindable: {lookup:#?}"
        );
    }

    /// A Kotlin workspace whose only external evidence is one activated
    /// declaration-facts pack. Discovery is explicitly disabled so the
    /// resolver-proven identity can come only from the pack's declaration.
    struct KotlinExternalMemberFixture {
        _temp: tempfile::TempDir,
        analyzer: crate::analyzer::WorkspaceAnalyzer,
        root: std::path::PathBuf,
    }

    impl KotlinExternalMemberFixture {
        fn new(source: &str) -> Self {
            use crate::analyzer::semantic_model::{
                CatalogOptions, CompilerOptions, SemanticModelActivationControl,
                SemanticModelActivationEvidence, SemanticModelActivationRequest,
                SemanticModelControlAction, SemanticModelControlScope, SemanticModelPackSelector,
                SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome, SemanticPackCatalog,
                SessionPackSource, SessionPackSourceKind, SourceFormat,
                acquire_active_semantic_models_with_evidence, compile_source,
            };
            use crate::analyzer::{
                AnalyzerConfig, JvmAnalyzerConfig, JvmDependencyDiscoveryConfig,
                JvmDependencyDiscoveryMode, JvmStandardLibraryDiscoveryConfig, WorkspaceAnalyzer,
            };

            let temp = tempfile::tempdir().expect("temp dir");
            let root = temp.path().canonicalize().expect("canonical temp dir");
            ProjectFile::new(root.clone(), "App.kt")
                .write(source)
                .expect("write Kotlin fixture");

            let type_id = "fixture.kotlin.external.ext";
            let pack = serde_json::json!({
                "schema_version": 2,
                "pack_id": "fixture.kotlin-external",
                "version": "1.0.0",
                "producer": { "name": "kotlin-dispatch-fixture", "version": "1.0.0" },
                "language": "kotlin",
                "ecosystem": "maven",
                "compatibility": { "bifrost": "*", "toolchains": [] },
                "provenance": { "source": "fixture" },
                "license": "NOASSERTION",
                "completeness": "partial",
                "safety": { "generated_code_only": false, "review_required": false },
                "shards": [{
                    "id": "declarations.fixture.kotlin-external",
                    "activation": [{ "package": { "name": "com.example.ext" } }],
                    "payload": {
                        "kind": "declaration_facts",
                        "types": [{
                            "id": type_id,
                            "name": "com.example.ext.Ext",
                            "type_kind": "class",
                            "visibility": "public",
                            "hierarchy": [],
                            "locator": {
                                "kind": "artifact",
                                "path": "fixture-source",
                                "symbol": "com.example.ext.Ext"
                            }
                        }],
                        "members": [{
                            "id": "fixture.kotlin.external.ext.wrap",
                            "owner": type_id,
                            "name": "wrap",
                            "member_kind": "method",
                            "visibility": "public",
                            "is_static": false,
                            "signature": {
                                "type_parameters": [],
                                "parameters": [{
                                    "name": "value",
                                    "type": {
                                        "kind": "named",
                                        "name": "kotlin.String",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                }],
                                "returns": {
                                    "kind": "named",
                                    "name": "kotlin.String",
                                    "arguments": [],
                                    "nullable": false
                                }
                            },
                            "locator": {
                                "kind": "artifact",
                                "path": "fixture-source",
                                "symbol": "com.example.ext.Ext.wrap"
                            }
                        }],
                        "relations": []
                    }
                }]
            });
            let pack = compile_source(
                SourceFormat::Json,
                &serde_json::to_vec(&pack).expect("serialize Kotlin declaration fixture"),
                &CompilerOptions::default(),
            )
            .unwrap_or_else(|diagnostics| {
                panic!("Kotlin declaration fixture must compile: {diagnostics:#?}")
            });
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
                .expect("open ephemeral semantic-pack catalog");
            catalog
                .register_session_pack(
                    &pack,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::Embedded,
                        source_id: "fixture.kotlin-external".to_owned(),
                    },
                )
                .expect("register Kotlin declaration fixture");

            let project = TestProject::new(root.clone(), Language::Kotlin);
            let config = AnalyzerConfig {
                jvm: JvmAnalyzerConfig {
                    dependency_discovery: JvmDependencyDiscoveryConfig {
                        mode: JvmDependencyDiscoveryMode::Disabled,
                        ..JvmDependencyDiscoveryConfig::default()
                    },
                    standard_library_discovery: JvmStandardLibraryDiscoveryConfig {
                        discover_java_home: false,
                        ..JvmStandardLibraryDiscoveryConfig::default()
                    },
                    ..JvmAnalyzerConfig::default()
                },
                ..AnalyzerConfig::default()
            };
            let analyzer = WorkspaceAnalyzer::build_ephemeral_footgun(Arc::new(project), config)
                .expect("build ephemeral Kotlin workspace");

            let request = SemanticModelActivationRequest {
                bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
                    .expect("crate version parses"),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "kotlin".to_owned(),
                    ecosystem: "maven".to_owned(),
                    package: Some(crate::analyzer::semantic_model::CatalogCoordinate {
                        name: "com.example.ext".to_owned(),
                        version: None,
                    }),
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                }],
                controls: vec![SemanticModelActivationControl {
                    scope: SemanticModelControlScope::Workspace,
                    action: SemanticModelControlAction::Enable,
                    selector: SemanticModelPackSelector {
                        pack_id: "fixture.kotlin-external".to_owned(),
                        version: None,
                        manifest_digest: None,
                    },
                }],
                limits: SemanticModelRuntimeLimits::default(),
            };
            let SemanticModelRuntimeOutcome::Ready { .. } =
                acquire_active_semantic_models_with_evidence(
                    analyzer.analyzer(),
                    &catalog,
                    None,
                    &request,
                    None,
                    &CancellationToken::new(),
                )
            else {
                panic!("Kotlin declaration fixture must activate");
            };
            assert!(analyzer.analyzer().semantic_model_overlay().is_some());

            Self {
                _temp: temp,
                analyzer,
                root,
            }
        }
    }

    fn dispatch_kotlin_call(source: &str, call: &str) -> CallDispatchLookup {
        let fixture = KotlinExternalMemberFixture::new(source);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.root, "App.kt"),
                call_span: call_span(source, call),
            },
            Arc::from(source),
            generous_limits(),
            None,
        )
    }

    fn dispatch_kotlin_external_member(callee: &str) {
        let imported = callee == "Ext.wrap";
        let import = imported.then_some("import com.example.ext.Ext\n\n");
        let call = format!("{callee}(value)");
        let source = format!(
            "package app\n\n{}fun caller(value: String): String = {call}\n",
            import.unwrap_or_default(),
        );
        let lookup = dispatch_kotlin_call(&source, &call);

        assert!(
            lookup.targets.is_empty(),
            "an external declaration is not a workspace target: {lookup:#?}"
        );
        assert_eq!(
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::External {
                callee_text: Some("com.example.ext.Ext.wrap".into()),
                normalized_static_owner: None,
                external_callee_identity: None,
            }],
            "the resolver-proven external member must retain its package-rooted identity: {lookup:#?}"
        );
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[brokk_bifrost_test_macros::hardwon(
        "#2823: An imported Kotlin external member resolves through an activated declaration pack and publishes the canonical package identity"
    )]
    #[test]
    fn kotlin_imported_external_member_publishes_resolver_proven_identity() {
        dispatch_kotlin_external_member("Ext.wrap");
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#2823: A fully qualified Kotlin external member resolves to the same pack-backed identity without an import binder"
    )]
    #[test]
    fn kotlin_fully_qualified_external_member_publishes_resolver_proven_identity() {
        dispatch_kotlin_external_member("com.example.ext.Ext.wrap");
    }

    #[test]
    fn kotlin_concrete_receiver_local_binding_publishes_external_identity() {
        let source = "package app\n\nimport com.example.ext.Ext\n\nfun caller(value: String): String {\n    val ext = Ext(value)\n    return ext.wrap(value)\n}\n";
        let call = "ext.wrap(value)";
        let lookup = dispatch_kotlin_call(source, call);

        assert!(
            lookup.targets.is_empty(),
            "an external declaration is not a workspace target: {lookup:#?}"
        );
        assert_eq!(
            lookup.status,
            Some(DefinitionLookupStatus::UnresolvableImportBoundary),
            "the external receiver must report the import-boundary status: {lookup:#?}"
        );
        assert_eq!(
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::External {
                callee_text: Some("com.example.ext.Ext.wrap".into()),
                normalized_static_owner: None,
                external_callee_identity: None,
            }],
            "a caller-local value constructed from the imported external type must keep its package-rooted identity: {lookup:#?}"
        );
    }

    fn empty_typescript_analyzer() -> (tempfile::TempDir, TypescriptAnalyzer, ProjectFile) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
        let file = ProjectFile::new(root, "src/app.ts");
        (temp, analyzer, file)
    }

    #[test]
    fn binding_status_distinguishes_missing_layout_from_known_empty_layout() {
        let (_temp, analyzer, missing_file) = empty_typescript_analyzer();
        let missing = CodeUnit::new(missing_file.clone(), CodeUnitType::Function, "", "missing");
        let range = Range {
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            end_line: 1,
        };
        let mut missing_site = CallSite {
            file: missing_file,
            range,
            callee_range: range,
            caller: missing.clone(),
            callee: missing,
            kind: CallSyntaxKind::Function,
            proof: UsageProof::Proven,
            receiver: None,
            arguments: Vec::new(),
        };
        assert_eq!(
            bind_call_site_arguments(
                &analyzer,
                &mut missing_site,
                &mut CallBindingCache::default(),
            ),
            CallBindingStatus::Unavailable
        );

        let source = "export function noArgs() {}\n";
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "src/app.ts");
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let no_args = analyzer
            .all_declarations()
            .find(|unit| unit.short_name() == "noArgs")
            .expect("known callable");
        let mut known_site = CallSite {
            file,
            range,
            callee_range: range,
            caller: no_args.clone(),
            callee: no_args,
            kind: CallSyntaxKind::Function,
            proof: UsageProof::Proven,
            receiver: None,
            arguments: Vec::new(),
        };
        assert_eq!(
            bind_call_site_arguments(&analyzer, &mut known_site, &mut CallBindingCache::default(),),
            CallBindingStatus::Complete
        );
    }

    #[test]
    fn unresolved_python_receiver_does_not_claim_a_complete_formal_binding() {
        let source = "class Service:\n    def run(self, payload):\n        pass\n";
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let service_file = ProjectFile::new(root.clone(), "service.py");
        service_file.write(source).expect("write source");
        let analyzer =
            PythonAnalyzer::from_project(TestProject::new(root.clone(), Language::Python));
        let callee = analyzer
            .search_definitions("run", false)
            .into_iter()
            .find(CodeUnit::is_callable)
            .expect("instance method");
        let call_file = ProjectFile::new(root, "missing_caller.py");
        let caller = CodeUnit::new(call_file.clone(), CodeUnitType::Function, "", "caller");
        let range = Range {
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            end_line: 1,
        };
        let mut site = CallSite {
            file: call_file,
            range,
            callee_range: range,
            caller,
            callee,
            kind: CallSyntaxKind::Method,
            proof: UsageProof::Proven,
            receiver: Some(range),
            arguments: vec![CallArgument {
                range,
                name: None,
                position: Some(0),
                formal_index: None,
                formal_name: None,
                variadic: false,
                spread: false,
            }],
        };

        let status =
            bind_call_site_arguments(&analyzer, &mut site, &mut CallBindingCache::default());

        assert_eq!(status, CallBindingStatus::Unavailable);
        assert_eq!(site.arguments[0].formal_index, None);
    }

    #[test]
    fn incoming_projection_reports_an_unmappable_enclosing_unit() {
        let (_temp, analyzer, file) = empty_typescript_analyzer();
        let target = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
        let enclosing = CodeUnit::new(file.clone(), CodeUnitType::Field, "", "value");
        let hit = UsageHit::new(file, 1, 0, 6, enclosing, 1.0, "target()");

        assert_eq!(
            project_incoming_call_hit(
                &analyzer,
                &mut CallSyntaxCache::default(),
                &target,
                hit,
                UsageProof::Proven,
            ),
            Err(IncomingCallOmission::CallerUnavailable)
        );
    }

    #[test]
    fn incoming_projection_reports_unavailable_structured_call_syntax() {
        let (_temp, analyzer, file) = empty_typescript_analyzer();
        let target = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
        let caller = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
        let hit = UsageHit::new(file, 1, 0, 6, caller, 1.0, "target()");

        assert_eq!(
            project_incoming_call_hit(
                &analyzer,
                &mut CallSyntaxCache::default(),
                &target,
                hit,
                UsageProof::Proven,
            ),
            Err(IncomingCallOmission::SyntaxUnavailable)
        );
    }

    #[test]
    fn incoming_projection_omission_replaces_ambiguity_advisory() {
        let (_temp, _analyzer, file) = empty_typescript_analyzer();
        let target = CodeUnit::new(file, CodeUnitType::Function, "", "target");
        let mut diagnostics = vec![CallRelationDiagnostic::new(
            CallRelationDiagnosticCode::TargetsAmbiguous,
            "ambiguous".to_string(),
            target.fq_name().to_string(),
        )];

        append_incoming_projection_omission(&mut diagnostics, &target, 1);

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            CallRelationDiagnosticCode::CandidatesOmitted
        );
        assert_eq!(diagnostics[0].context, target.fq_name());
    }

    #[test]
    fn ambiguous_outgoing_targets_count_empty_and_unmappable_definitions_as_omitted() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
        let file = ProjectFile::new(root, "src/app.ts");
        let callable = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
        let non_callable = CodeUnit::new(file, CodeUnitType::Field, "", "value");

        let empty = resolve_outgoing_call_candidate(
            &analyzer,
            DefinitionLookupStatus::Ambiguous,
            Vec::new(),
        );
        assert_eq!(empty.omitted, 1);
        assert!(empty.callees.is_empty());
        assert!(!empty.fully_retained);

        let partial = resolve_outgoing_call_candidate(
            &analyzer,
            DefinitionLookupStatus::Ambiguous,
            vec![callable, non_callable],
        );
        assert_eq!(partial.callees.len(), 1);
        assert_eq!(partial.omitted, 1);
        assert!(!partial.fully_retained);
    }

    #[test]
    fn ambiguous_outgoing_advisory_requires_every_candidate_to_survive() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root, "src/app.ts");
        let caller = CodeUnit::new(file, CodeUnitType::Function, "", "caller");
        let mut diagnostics = Vec::new();

        append_outgoing_candidate_diagnostics(&mut diagnostics, &caller, 1, 0, 1);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            CallRelationDiagnosticCode::CandidatesOmitted
        );

        diagnostics.clear();
        append_outgoing_candidate_diagnostics(&mut diagnostics, &caller, 1, 1, 0);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            CallRelationDiagnosticCode::TargetsAmbiguous
        );
    }

    /// The reviewed Rust declaration surface for
    /// `std::net::TcpStream::connect`: the crate root, its two owner paths,
    /// and one receiverless callable of the written arity. It mirrors the
    /// shipped web-network pack, which is what an authored network summary is
    /// keyed by.
    fn activate_rust_connect_declaration_pack(fixture: &AnalyzerFixture) {
        let pack_id = "fixture.rust-std-connect-declarations";
        let pack_json = serde_json::json!({
            "schema_version": 2,
            "pack_id": pack_id,
            "version": "1.0.0",
            "producer": { "name": "rust-dispatch-fixture", "version": "1.0.0" },
            "language": "rust",
            "ecosystem": "cargo",
            "compatibility": { "bifrost": "*", "toolchains": [] },
            "provenance": { "source": "fixture" },
            "license": "NOASSERTION",
            "completeness": "complete",
            "safety": { "generated_code_only": false, "review_required": false },
            "shards": [{
                "id": "declarations.rust-fixture",
                "activation": [{}],
                "payload": {
                    "kind": "declaration_facts",
                    "types": [
                        {
                            "id": "type.rust-fixture.std",
                            "name": "std",
                            "type_kind": "module",
                            "visibility": "public",
                            "locator": {
                                "kind": "artifact",
                                "path": "library/std/src/lib.rs",
                                "symbol": "std"
                            }
                        },
                        {
                            "id": "type.rust-fixture.std-net",
                            "name": "std.net",
                            "type_kind": "module",
                            "visibility": "public",
                            "locator": {
                                "kind": "artifact",
                                "path": "library/std/src/net/mod.rs",
                                "symbol": "std.net"
                            }
                        },
                        {
                            "id": "type.rust-fixture.std-net-tcpstream",
                            "name": "std.net.TcpStream",
                            "type_kind": "struct",
                            "visibility": "public",
                            "locator": {
                                "kind": "artifact",
                                "path": "library/std/src/net/tcp.rs",
                                "symbol": "std.net.TcpStream"
                            }
                        }
                    ],
                    "members": [{
                        "id": "member.rust-fixture.std-net-tcpstream.connect",
                        "owner": "type.rust-fixture.std-net-tcpstream",
                        "name": "connect",
                        "member_kind": "method",
                        "visibility": "public",
                        "is_static": true,
                        "callable_family_complete": true,
                        "signature": {
                            "parameters": [{
                                "name": "addr",
                                "type": { "kind": "named", "name": "untyped" }
                            }]
                        },
                        "locator": {
                            "kind": "artifact",
                            "path": "library/std/src/net/tcp.rs",
                            "symbol": "std.net.TcpStream.connect"
                        }
                    }],
                    "relations": []
                }
            }]
        });
        crate::test_support::activate_rust_declaration_pack(
            fixture.analyzer.analyzer(),
            pack_id,
            &pack_json,
        );
    }

    /// #3484: the imported spelling (`use std::net::TcpStream;` then
    /// `TcpStream::connect(addr)`) publishes the same evidence pair the
    /// written-out `std::net::TcpStream::connect(addr)` route publishes. The
    /// exact callable proof and the resolver-owned owner/member identity
    /// travel together through `resolve_call_target_batch_with_source` and the
    /// common dispatch path, because a matching summary is behavior attached
    /// to a callable rather than to the spelling that named it. An expansion
    /// that only translated a name would leave both fields empty and the
    /// reviewed summary unbound.
    #[test]
    fn rust_imported_external_member_publishes_exact_proof_and_identity() {
        let source = "use std::net::TcpStream;\n\npub fn total() {\n    let _connection = \
                      TcpStream::connect(\"127.0.0.1:9\");\n}\n";
        let call = "TcpStream::connect(\"127.0.0.1:9\")";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        activate_rust_connect_declaration_pack(&fixture);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "lib.rs"),
                call_span: call_span(source, call),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert!(
            lookup.targets.is_empty(),
            "an external declaration is not a workspace target: {lookup:#?}"
        );
        let proof = lookup
            .exact_external_call
            .as_ref()
            .unwrap_or_else(|| panic!("the imported call must carry its exact proof: {lookup:#?}"));
        assert_eq!(proof.canonical_callee(), "std::net::TcpStream::connect");
        assert_eq!(proof.parameter_count(), 1);
        assert!(
            !proof.has_receiver(),
            "an associated function of the owner takes no receiver: {proof:#?}"
        );
        assert_eq!(
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::External {
                callee_text: Some("std::net::TcpStream::connect".into()),
                normalized_static_owner: None,
                external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
                    Language::Rust,
                    "std.net.TcpStream",
                    "connect",
                )),
            }],
            "the imported spelling and the written spelling publish one identity: {lookup:#?}"
        );
    }
}
