//! Analyzer-owned call relations shared by query traversal and LSP call hierarchy.

use std::sync::Arc;

use crate::analyzer::common::language_for_file;
use crate::analyzer::languages::{ExternalCalleeSite, language_support};
use crate::analyzer::lexical_definitions::{
    FormalParameterLayout, PythonMethodBinding, formal_parameter_slots,
};
use crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity;
use crate::analyzer::structural::FileFacts;
use crate::analyzer::structural::resolution::BoundaryStatus;
use crate::analyzer::usages::call_binding::{OrdinaryFormalSlots, canonical_parameter_name};
use crate::analyzer::usages::call_shape::call_shapes_in_file;
use crate::analyzer::usages::get_definition::{
    CallApplicationKind, CallSiteSyntax, CallSyntaxKind, CallTargetLookupOutcome,
    DefinitionLookupOutcome, DefinitionLookupRequest, DefinitionLookupStatus, ExactCallReference,
    ExactCallReferenceGap, ExactExternalCallProof, IMPORT_BINDINGS_TRUNCATED_DIAGNOSTIC,
    LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND, PARTIAL_IMPORT_BOUNDARY_DIAGNOSTIC,
    PARTIAL_IMPORT_UNRESOLVED_DIAGNOSTIC, call_reference_ranges_in_tree,
    call_reference_requires_point_lookup, call_site_syntax_for_reference,
    exact_call_reference_for_call, is_adjudicated_answer_diagnostic_kind, parse_tree_for_language,
    range_is_call_keyword_label, resolve_call_target_batch_with_source,
    resolve_definition_batch_with_source,
};
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, DispatchExtensibility, IAnalyzer, Language, ProjectFile,
    QueryScope, Range,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::query_token::QueryToken;

use super::{FuzzyResult, UsageFinder, UsageHit, UsageHitKind, UsageProof, UsageQueryCompletion};

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
#[allow(dead_code)] // Retained for the aggregate one-call accounting facade below.
pub(crate) struct ExactCallLocation {
    pub(crate) file: ProjectFile,
    pub(crate) call_span: Range,
}

/// One workspace definition retained by exact call-site dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CallDispatchTarget {
    pub(crate) definition: CodeUnit,
    pub(crate) proof: UsageProof,
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
    /// Receiver-application evidence produced by the same exact language
    /// resolution that populated the dispatch boundaries.
    pub(crate) call_application: CallApplicationKind,
    /// Exact declaration-side dispatch extensibility retained from that same
    /// resolution pass. Absence is unknown, never implicitly open or closed.
    pub(crate) dispatch_extensibility: Option<DispatchExtensibility>,
    /// Resolver-owned external identity and applicable call shape. Consumers
    /// that mint an external model key must use this proof rather than combine
    /// the boundary spelling with independently lowered receiver or arity
    /// facts.
    pub(crate) exact_external_call: Option<ExactExternalCallProof>,
    pub(crate) truncated: bool,
    pub(crate) cancelled: bool,
    pub(crate) budget_exhausted: bool,
    pub(crate) diagnostics: Vec<String>,
    pub(crate) work: CallRelationWork,
}

enum CallDispatchParse {
    Uninitialized,
    Ready(Option<tree_sitter::Tree>),
}

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
}

#[derive(Debug, Clone, Copy)]
pub struct CallRelationLimits {
    pub max_files: usize,
    pub max_source_bytes: usize,
    /// Maximum retained dispatch targets for each exact call. In the batched
    /// exact-call API this remains a per-call arm cap; the caller separately
    /// bounds the number of submitted call sites.
    pub max_candidates: usize,
}

#[derive(Debug, Clone, Copy, Default)]
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

    fn analysis_failed(message: String, context: String, reason_kind: String) -> Self {
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
    pub work: CallRelationWork,
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
    for (path, start, end, caller, callee) in sites {
        hasher.field(&path, &(start as u64).to_be_bytes());
        hasher.value(&(end as u64).to_be_bytes());
        hasher.field("caller", caller.as_bytes());
        hasher.field("callee", callee.as_bytes());
    }
    crate::analyzer::semantic::ids::StableDigest::from_array(hasher.finish())
}

#[derive(Default)]
pub struct CallBindingCache {
    formals: HashMap<CodeUnit, Option<FormalParameterLayout>>,
    python_receiver_is_class: HashMap<(ProjectFile, usize, usize), Option<bool>>,
    /// One batch-resolved outcome per call site's callee range, keyed by
    /// file and filled by [`Self::resolved_call_target`]'s one-shot per-file
    /// prefetch (issue #2765). The per-site resolver path paid a fresh
    /// `DefinitionBatchContext` -- sources, trees, line starts, per-language
    /// import/alias contexts -- at every call site even though every site in
    /// one file shares the same one; batching every callee range of a file
    /// into one `resolve_call_target_batch_with_source` call derives that
    /// context once per file instead.
    call_targets: HashMap<(ProjectFile, Range), CallTargetLookupOutcome>,
    /// Files whose call-target prefetch already ran. A file with zero call
    /// sites is recorded too, so a later miss never re-scans it.
    call_target_prefetched: HashSet<ProjectFile>,
}

impl CallBindingCache {
    /// The callable's syntax-derived formal parameter layout, read once per
    /// declaration. Shared with the `call_binding` row producer so both read
    /// one cache entry rather than re-parsing the declaring file twice.
    pub fn formal_layout(
        &mut self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
    ) -> Option<FormalParameterLayout> {
        self.formals
            .entry(unit.clone())
            .or_insert_with(|| formal_slots_for_unit(analyzer, unit))
            .clone()
    }

    /// The production definition resolver's outcome for one call site's
    /// callee token (issue #2765).
    ///
    /// The first request for a file resolves every call shape's callee range
    /// that file's facts arena reports, in one
    /// `resolve_call_target_batch_with_source` invocation, and caches each
    /// outcome by its exact callee range. A later request for the same file
    /// is served from that prefetch. A callee range the prefetch's call-shape
    /// enumeration did not cover -- the pipeline's single-snapshot contract
    /// does not admit this, but nothing here assumes it -- still resolves
    /// through a single-request fallback; the fallback outcome is returned,
    /// not cached, because caching it would let this method silently answer
    /// for a range the prefetch never actually promised to cover.
    pub fn resolved_call_target(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        callee_range: Range,
        cancellation: Option<&CancellationToken>,
    ) -> Option<CallTargetLookupOutcome> {
        if self.call_target_prefetched.insert(file.clone()) {
            self.prefetch_call_targets(analyzer, file, cancellation);
        }
        if let Some(outcome) = self.call_targets.get(&(file.clone(), callee_range)) {
            return Some(outcome.clone());
        }
        let source = analyzer.indexed_source(file).map(Arc::<str>::from)?;
        let scope = AnalyzerQueryScope::new(analyzer);
        resolve_call_target_batch_with_source(
            analyzer,
            scope.token(),
            vec![DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(callee_range.start_byte),
                end_byte: Some(callee_range.end_byte),
            }],
            file.clone(),
            source,
            cancellation,
        )
        .into_iter()
        .next()
    }

    /// Batch-resolve every call site's callee range that `file`'s facts
    /// arena reports, in source byte-range order, and cache each outcome by
    /// its exact callee range.
    fn prefetch_call_targets(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        cancellation: Option<&CancellationToken>,
    ) {
        let Some(source) = analyzer.indexed_source(file).map(Arc::<str>::from) else {
            return;
        };
        let Some(facts) = analyzer
            .structural_fact_providers()
            .into_iter()
            .find_map(|provider| provider.structural_facts(file))
        else {
            return;
        };
        let mut ranges: Vec<Range> = call_shapes_in_file(&facts, file, facts.nodes().len())
            .into_iter()
            .filter_map(|shape| shape.outcome.callee_range)
            .collect();
        // Deterministic request order, independent of arena traversal order:
        // several call shapes sharing one callee range is degenerate but not
        // impossible, so dedup keeps the batch one request per distinct
        // range.
        ranges.sort();
        ranges.dedup();
        if ranges.is_empty() {
            return;
        }
        let requests = ranges
            .iter()
            .map(|range| DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(range.start_byte),
                end_byte: Some(range.end_byte),
            })
            .collect();
        let scope = AnalyzerQueryScope::new(analyzer);
        let outcomes = resolve_call_target_batch_with_source(
            analyzer,
            scope.token(),
            requests,
            file.clone(),
            source,
            cancellation,
        );
        // A cancelled batch answers a prefix of `ranges`, shorter than the
        // request list it was handed (`resolve_definition_requests_traced`
        // stops at the first cancelled poll): `zip` caches exactly that
        // prefix, and every range past it stays a cache miss that
        // `resolved_call_target`'s fallback resolves (and, with the same
        // cancellation token already tripped, answers unresolved) on its own.
        self.call_targets.extend(
            ranges
                .into_iter()
                .zip(outcomes)
                .map(|(range, outcome)| ((file.clone(), range), outcome)),
        );
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
    /// Conservative live source, tree, and project-path footprint while this
    /// session owns its exact snapshot. The shared syntax estimator also
    /// budgets entries retained by the analyzer's prepared-syntax store.
    pub(crate) fn retained_bytes(&self) -> usize {
        crate::analyzer::tree_sitter_analyzer::prepared_syntax_retained_bytes(
            self.exact_source.len(),
        )
        .saturating_add(self.file.retained_bytes())
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

        let mut work = CallRelationWork {
            examined_candidates: 1,
            ..CallRelationWork::default()
        };
        if matches!(self.parse, CallDispatchParse::Uninitialized) {
            work.scanned_files = 1;
            work.scanned_source_bytes = self.exact_source.len();
            let tree = (self.language != Language::None)
                .then(|| parse_tree_for_language(&self.file, self.language, &self.exact_source))
                .flatten();
            self.parse = CallDispatchParse::Ready(tree);
        }
        if self.language == Language::None {
            return unresolved_dispatch_lookup(
                DefinitionLookupStatus::UnsupportedLanguage,
                "exact call dispatch does not support this file language".to_string(),
                work,
            );
        }
        let CallDispatchParse::Ready(Some(tree)) = &self.parse else {
            return unresolved_dispatch_lookup(
                DefinitionLookupStatus::NotFound,
                format!("failed to parse {} for exact call dispatch", self.file),
                work,
            );
        };
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
        let batch = resolve_call_references_with_source(
            analyzer,
            token,
            &self.file,
            Arc::clone(&self.exact_source),
            tree,
            std::slice::from_ref(&callee_range),
            cancellation,
        );
        let cancelled =
            batch.cancelled || cancellation.is_some_and(CancellationToken::is_cancelled);
        let Some((_, outcome)) = batch.resolved.into_iter().next() else {
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
        };
        apply_call_target_outcome(
            &mut lookup,
            expand_imported_external_callee(analyzer, &self.file, outcome, Some(&site)),
            max_candidates,
            self.language,
            Some(&site),
        );
        lookup
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
        }
    }

    /// Resolve one exact whole-call span against one exact source snapshot.
    ///
    /// The caller supplies the source owned by the semantic artifact's
    /// revision. This method never rereads the file, so its byte span cannot
    /// race a newer disk or overlay snapshot. The same batched definition
    /// resolution core is used by legacy outgoing call relations below.
    #[allow(dead_code)] // The serial session is production; this facade pins one-call accounting.
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
        let Some(tree) = parse_tree_for_language(file, language, &exact_source) else {
            return repeated(unresolved_dispatch_lookup(
                DefinitionLookupStatus::NotFound,
                format!("failed to parse {file} for exact call dispatch"),
                work,
            ));
        };
        let mut lookups = vec![None; call_spans.len()];
        let mut resolvable = Vec::with_capacity(call_spans.len());
        for (index, call_span) in call_spans.iter().enumerate() {
            match exact_call_reference_for_call(&tree, language, call_span) {
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
            &tree,
            &references,
            cancellation,
        );
        for ((index, callee_range), (_, outcome)) in resolvable.iter().zip(batch.resolved) {
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
                tree: &tree,
                callee_start_byte: callee_range.start_byte,
            };
            apply_call_target_outcome(
                &mut lookup,
                expand_imported_external_callee(analyzer, file, outcome, Some(&site)),
                limits.max_candidates,
                language,
                Some(&site),
            );
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
            CallRelationLimits {
                max_files,
                max_source_bytes: usize::MAX,
                max_candidates: max_sites,
            },
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
        let (hits, mut truncated, mut diagnostics) = call_hits(query.result, target);
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
        for (hit, proof) in hits.into_iter().take(limits.max_candidates) {
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
            CallRelationLimits {
                max_files: 1,
                max_source_bytes: usize::MAX,
                max_candidates: max_sites,
            },
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
    super::get_definition::trace::boundary_evidence(analyzer, file, resolved_target).0
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

fn unresolved_dispatch_lookup(
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
        None,
        None,
        None,
        false,
        false,
        false,
        false,
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
    mut outcome: CallTargetLookupOutcome,
    site: Option<&ExternalCalleeSite<'_>>,
) -> ExpandedExternalCallee {
    let kotlin_import_resolved_without_target = language_for_file(file) == Language::Kotlin
        && outcome.outcome.status == DefinitionLookupStatus::Resolved
        && outcome.outcome.definitions.is_empty();
    if !kotlin_import_resolved_without_target
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
    let Some(text) =
        structured_kotlin_callee.or_else(|| outcome.outcome.resolved_reference_target())
    else {
        return ExpandedExternalCallee::unproven(outcome);
    };
    let Some(expanded) = language_support(language_for_file(file))
        .and_then(|support| support.expand_imported_external_callee(analyzer, file, text))
    else {
        return ExpandedExternalCallee::unproven(outcome);
    };
    if let Some(reference) = outcome.outcome.reference.as_mut() {
        reference.text = expanded;
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
    let CallTargetLookupOutcome {
        outcome,
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
            debug_assert_eq!(
                format!("{}.{}", identity.owner_fqn(), identity.member()),
                proof.canonical_callee(),
                "external identity and exact proof must describe one callee"
            );
        }
    }
    apply_dispatch_outcome_with_flags(
        lookup,
        outcome,
        max_targets,
        language,
        exact_external_callee,
        external_callee_identity,
        site,
        resolver_proven_identity,
        structure_unavailable,
        unproven_link_unit,
        truncated,
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
    exact_external_callee: Option<Box<str>>,
    external_callee_identity: Option<ResolverOwnedExternalCalleeIdentity>,
    site: Option<&ExternalCalleeSite<'_>>,
    resolver_proven_external_identity: bool,
    structure_unavailable: bool,
    unproven_link_unit: bool,
    navigation_targets_truncated: bool,
) {
    let DefinitionLookupOutcome {
        status,
        mut definitions,
        lexical_definition,
        diagnostics,
        reference,
    } = outcome;
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
    let normalized_static_owner = external_callee_text
        .as_deref()
        .and_then(|callee_text| java_normalized_static_owner(callee_text, language, site));
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
    if definitions.len() > max_targets {
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
    let proof = if status == DefinitionLookupStatus::Resolved && !unproven_target_identity {
        UsageProof::Proven
    } else {
        UsageProof::Unproven
    };
    lookup.targets.extend(
        definitions
            .into_iter()
            .map(|definition| CallDispatchTarget { definition, proof }),
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
        DefinitionLookupStatus::NoDefinition if language == Language::Go => lookup
            .boundaries
            .push(CallDispatchBoundaryKind::Unresolved(status)),
        DefinitionLookupStatus::NoDefinition => match external_callee_text {
            Some(text) => lookup.boundaries.push(CallDispatchBoundaryKind::External {
                callee_text: Some(text),
                normalized_static_owner,
                external_callee_identity: None,
            }),
            None => lookup.boundaries.push(unresolved_call_boundary(
                status,
                None,
                normalized_static_owner,
            )),
        },
        DefinitionLookupStatus::UnsupportedLanguage
        | DefinitionLookupStatus::InvalidLocation
        | DefinitionLookupStatus::NotFound => lookup.boundaries.push(unresolved_call_boundary(
            status,
            external_callee_text,
            normalized_static_owner,
        )),
    }
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
    // separator. A dotted source spelling proves no package root on its own;
    // only the language resolver's external-member expansion may publish one
    // as a bindable boundary identity (#2781).
    if language == Language::Kotlin && !resolver_proven_external_identity {
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
    let canonical_owner = support.single_segment_external_owner(&owner, site?)?;
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
    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            unproven_total_by_overload,
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

fn raw_call_site(
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
    let Some(layout) = cache.formal_layout(analyzer, &formal_owner) else {
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
    let (constructor_name, allocation_binds_first_formal) = match language_for_file(callee.source())
    {
        Language::Python => ("__init__", true),
        Language::JavaScript | Language::TypeScript => ("constructor", false),
        _ => return None,
    };
    let mut constructors = analyzer
        .direct_children(callee)
        .into_iter()
        .filter(|unit| unit.is_callable() && unit.identifier() == constructor_name)
        .collect::<Vec<_>>();
    constructors.sort();
    constructors.dedup();
    (constructors.len() == 1).then(|| (constructors.remove(0), allocation_binds_first_formal))
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

fn formal_slots_for_unit(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
) -> Option<FormalParameterLayout> {
    if unit.is_class() {
        return None;
    }
    let source = analyzer.indexed_source(unit.source())?;
    let language = language_for_file(unit.source());
    let tree = parse_tree_for_language(unit.source(), language, &source)?;
    let range = analyzer.ranges_of(unit).into_iter().min_by_key(range_key)?;
    formal_parameter_slots(language, tree.root_node(), &source, &range)
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

fn proof_rank(proof: UsageProof) -> u8 {
    match proof {
        UsageProof::Proven => 0,
        UsageProof::Unproven => 1,
    }
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
    use crate::analyzer::{AnalyzerQueryScope, QueryScope};
    use crate::analyzer::{
        CodeUnitType, Language, PythonAnalyzer, TestProject, TypescriptAnalyzer,
    };
    use crate::test_support::AnalyzerFixture;
    use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

    fn call_span(source: &str, call: &str) -> Range {
        let start_byte = source.rfind(call).expect("call exists");
        Range {
            start_byte,
            end_byte: start_byte + call.len(),
            start_line: 0,
            end_line: 0,
        }
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
            CatalogCoordinate, CatalogOptions, CompilerOptions, SemanticModelActivationControl,
            SemanticModelActivationEvidence, SemanticModelActivationRequest,
            SemanticModelControlAction, SemanticModelControlScope, SemanticModelPackSelector,
            SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome, SemanticPackCatalog,
            SessionPackSource, SessionPackSourceKind, SourceFormat,
            acquire_active_semantic_models_with_evidence, compile_source,
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
        let pack = compile_source(SourceFormat::Json, &source, &CompilerOptions::default())
            .unwrap_or_else(|diagnostics| {
                panic!("Go declaration fixture must compile: {diagnostics:#?}")
            });
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral catalog");
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: pack_id.to_owned(),
                },
            )
            .expect("register Go declaration fixture");
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
        let SemanticModelRuntimeOutcome::Ready { .. } =
            acquire_active_semantic_models_with_evidence(
                fixture.analyzer.analyzer(),
                &catalog,
                None,
                &request,
                None,
                &CancellationToken::new(),
            )
        else {
            panic!("Go declaration fixture must activate");
        };
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
    fn exact_dispatch_resolves_java_methods_at_the_call_span() {
        let source = "class Example { static void helper() {} static void caller() { helper(); } }";
        let fixture =
            AnalyzerFixture::new_for_language(Language::Java, &[("Example.java", source)]);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "Example.java"),
                call_span: call_span(source, "helper()"),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert_eq!(lookup.status, Some(DefinitionLookupStatus::Resolved));
        assert_eq!(lookup.targets.len(), 1, "{lookup:#?}");
        assert_eq!(lookup.targets[0].definition.fq_name(), "Example.helper");
        assert_eq!(lookup.targets[0].proof, UsageProof::Proven);
        assert!(lookup.boundaries.is_empty(), "{lookup:#?}");
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
    fn exact_dispatch_keeps_model_proof_external_and_canonical() {
        for (pack_id, import_path, package_name, import, call, expected_target) in [
            (
                "fixture.go.os",
                "os",
                "os",
                "\"os\"",
                "os.Open()",
                "os.Open",
            ),
            (
                "fixture.go.os-alias",
                "os",
                "os",
                "files \"os\"",
                "files.Open()",
                "os.Open",
            ),
            (
                "fixture.go.declared-name",
                "example.com/m/postgres",
                "pg",
                "\"example.com/m/postgres\"",
                "pg.Open()",
                "example.com/m/postgres.Open",
            ),
            (
                "fixture.go.dot-import",
                "os",
                "os",
                ". \"os\"",
                "Open()",
                "os.Open",
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
                    external_callee_identity: None,
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
    fn dot_imported_model_function_shadows_package_scope_and_conflicts_stay_identityless() {
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
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::External {
                callee_text: Some("example.com/model.Open".into()),
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

        for (call, canonical, effective_parameter_count) in [
            ("model.Open(1)", "example.com/model.Open", 1),
            ("model.Open(model.One())", "example.com/model.Open", 1),
            ("model.Binary(model.Pair())", "example.com/model.Binary", 2),
            ("model.One()", "example.com/model.One", 0),
            ("model.Pair()", "example.com/model.Pair", 0),
            ("model.Zero()", "example.com/model.Zero", 0),
            ("model.NoResult()", "example.com/model.NoResult", 0),
            ("model.Variadic()", "example.com/model.Variadic", 0),
            ("model.Variadic(1)", "example.com/model.Variadic", 1),
            ("model.Variadic(1, 2)", "example.com/model.Variadic", 2),
            (
                "model.Variadic(model.Pair())",
                "example.com/model.Variadic",
                2,
            ),
        ] {
            let exact = lookup(call);
            assert_eq!(
                exact.status,
                Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                "{call}: {exact:#?}"
            );
            assert_eq!(
                exact.boundaries,
                vec![CallDispatchBoundaryKind::External {
                    callee_text: Some(canonical.into()),
                    normalized_static_owner: None,
                    external_callee_identity: None,
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
    fn exact_go_package_call_keeps_declared_package_identity_static() {
        let source = r#"package main
import "example.com/driver"
func caller() { db.Open() }
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        activate_go_function_declaration(
            &fixture,
            "fixture.go.declared-package-name",
            "example.com/driver",
            "db",
            "Open",
        );
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            AnalyzerQueryScope::new(fixture.analyzer.analyzer()).token(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "main.go"),
                call_span: call_span(source, "db.Open()"),
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
        let proof = lookup
            .exact_external_call
            .as_ref()
            .unwrap_or_else(|| panic!("declared package call must retain its proof: {lookup:#?}"));
        assert_eq!(proof.canonical_callee(), "example.com/driver.Open");
        assert_eq!(
            proof.call_application(),
            CallApplicationKind::PackageFunction
        );
        assert_eq!(proof.parameter_count(), 0);
        assert!(!proof.has_receiver());
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

    /// #1599/#2799: a boundary status carries its refined external evidence so
    /// the dispatch oracle can classify quality from it. The named import
    /// proves the exact external callable even though nothing declares or
    /// indexes `third-party`; open dispatch remains a separate fact.
    #[test]
    fn exact_dispatch_refines_an_external_boundary_status() {
        let source = "import { work } from \"third-party\";\nexport function caller(): number { return work(); }\n";
        let fixture =
            AnalyzerFixture::new_for_language(Language::TypeScript, &[("external.ts", source)]);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "external.ts"),
                call_span: call_span(source, "work()"),
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
        assert_eq!(
            lookup.boundary,
            Some(BoundaryStatus::ExternalIndexed),
            "{lookup:#?}"
        );
        // The payload is the resolver-proven package plus imported symbol,
        // never the source-local bare callee spelling.
        assert_eq!(
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::External {
                callee_text: Some("third-party.work".into()),
                normalized_static_owner: None,
                external_callee_identity: None,
            }],
            "{lookup:#?}"
        );
        let proof = lookup
            .exact_external_call
            .as_ref()
            .unwrap_or_else(|| panic!("named import must retain exact proof: {lookup:#?}"));
        assert_eq!(proof.canonical_callee(), "third-party.work");
        assert_eq!(
            proof.call_application(),
            CallApplicationKind::PackageFunction
        );
        assert_eq!(proof.parameter_count(), 0);
        assert!(!proof.has_receiver());
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
                status,
                reference: None,
                definitions: vec![definition.clone()],
                lexical_definition: None,
                diagnostics: Vec::new(),
            },
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
    fn exact_dispatch_resolves_ruby_bare_calls_at_the_identifier_span() {
        let source = r#"class Example
  def target
  end

  def caller
    target
  end
end
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Ruby, &[("example.rb", source)]);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "example.rb"),
                call_span: call_span(source, "target"),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert_eq!(lookup.status, Some(DefinitionLookupStatus::Resolved));
        assert_eq!(lookup.targets.len(), 1, "{lookup:#?}");
        assert_eq!(lookup.targets[0].definition.fq_name(), "Example.target");
        assert_eq!(lookup.targets[0].proof, UsageProof::Proven);
        assert!(lookup.boundaries.is_empty(), "{lookup:#?}");
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

    #[test]
    fn exact_dispatch_keeps_cancellation_budget_and_truncation_independent() {
        let source: Arc<str> = Arc::from("function target() {}\ntarget();\n");
        let fixture =
            AnalyzerFixture::new_for_language(Language::TypeScript, &[("sample.ts", &source)]);
        let location = ExactCallLocation {
            file: ProjectFile::new(fixture.project_root(), "sample.ts"),
            call_span: call_span(&source, "target()"),
        };
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let cancelled = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &location,
            Arc::clone(&source),
            generous_limits(),
            Some(&cancellation),
        );
        assert!(cancelled.cancelled);
        assert!(!cancelled.budget_exhausted);
        assert!(!cancelled.truncated);

        let exhausted = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &location,
            source,
            CallRelationLimits {
                max_files: 0,
                max_source_bytes: usize::MAX,
                max_candidates: 100,
            },
            None,
        );
        assert!(!exhausted.cancelled);
        assert!(exhausted.budget_exhausted);
        assert!(!exhausted.truncated);
    }

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
                status: DefinitionLookupStatus::Ambiguous,
                reference: None,
                definitions: vec![second, first],
                lexical_definition: None,
                diagnostics: vec![DefinitionLookupDiagnostic {
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
                status: DefinitionLookupStatus::Ambiguous,
                reference: None,
                definitions: vec![retained],
                lexical_definition: None,
                diagnostics: vec![
                    DefinitionLookupDiagnostic {
                        kind: PARTIAL_IMPORT_BOUNDARY_DIAGNOSTIC.to_string(),
                        message: "one candidate is external".to_string(),
                    },
                    DefinitionLookupDiagnostic {
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
                status: DefinitionLookupStatus::Ambiguous,
                reference: None,
                definitions: Vec::new(),
                lexical_definition: None,
                diagnostics: vec![DefinitionLookupDiagnostic {
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

    fn dispatch_kotlin_external_member(callee: &str) {
        let imported = callee == "Ext.wrap";
        let import = imported.then_some("import com.example.ext.Ext\n\n");
        let call = format!("{callee}(value)");
        let source = format!(
            "package app\n\n{}fun caller(value: String): String = {call}\n",
            import.unwrap_or_default(),
        );
        let fixture = KotlinExternalMemberFixture::new(&source);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.root.clone(), "App.kt"),
                call_span: call_span(&source, &call),
            },
            Arc::from(source.as_str()),
            generous_limits(),
            None,
        );

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
    #[test]
    fn kotlin_imported_external_member_publishes_resolver_proven_identity() {
        dispatch_kotlin_external_member("Ext.wrap");
    }

    #[test]
    fn kotlin_fully_qualified_external_member_publishes_resolver_proven_identity() {
        dispatch_kotlin_external_member("com.example.ext.Ext.wrap");
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
}
