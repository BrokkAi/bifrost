//! Analyzer-owned call relations shared by query traversal and LSP call hierarchy.

use std::sync::Arc;

use crate::analyzer::common::language_for_file;
use crate::analyzer::languages::{ExternalCalleeSite, language_support};
use crate::analyzer::lexical_definitions::{
    FormalParameterLayout, PythonMethodBinding, formal_parameter_slots,
};
use crate::analyzer::structural::FileFacts;
use crate::analyzer::structural::resolution::BoundaryStatus;
use crate::analyzer::usages::call_binding::{OrdinaryFormalSlots, canonical_parameter_name};
use crate::analyzer::usages::get_definition::{
    CallSiteSyntax, CallSyntaxKind, CallTargetLookupOutcome, DefinitionLookupOutcome,
    DefinitionLookupRequest, DefinitionLookupStatus, ExactCallReference, ExactCallReferenceGap,
    IMPORT_BINDINGS_TRUNCATED_DIAGNOSTIC, LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
    PARTIAL_IMPORT_BOUNDARY_DIAGNOSTIC, PARTIAL_IMPORT_UNRESOLVED_DIAGNOSTIC,
    call_reference_ranges_in_tree, call_reference_requires_point_lookup,
    call_site_syntax_for_reference, exact_call_reference_for_call, parse_tree_for_language,
    range_is_call_keyword_label, resolve_call_target_batch_with_source,
    resolve_definition_batch_with_source,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range};
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
    External(Option<Box<str>>),
    /// The exact resolver status is retained rather than collapsed into an
    /// empty target list.
    Unresolved(DefinitionLookupStatus),
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
    pub(crate) truncated: bool,
    pub(crate) cancelled: bool,
    pub(crate) budget_exhausted: bool,
    pub(crate) diagnostics: Vec<String>,
    pub(crate) work: CallRelationWork,
}

#[derive(Debug, Clone, Copy)]
pub struct CallRelationLimits {
    pub max_files: usize,
    pub max_source_bytes: usize,
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

#[derive(Default)]
pub struct CallBindingCache {
    formals: HashMap<CodeUnit, Option<FormalParameterLayout>>,
    python_receiver_is_class: HashMap<(ProjectFile, usize, usize), Option<bool>>,
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

impl CallRelationService {
    /// Resolve one exact whole-call span against one exact source snapshot.
    ///
    /// The caller supplies the source owned by the semantic artifact's
    /// revision. This method never rereads the file, so its byte span cannot
    /// race a newer disk or overlay snapshot. The same batched definition
    /// resolution core is used by legacy outgoing call relations below.
    pub(crate) fn dispatch_at_bounded(
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        location: &ExactCallLocation,
        exact_source: Arc<str>,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> CallDispatchLookup {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return CallDispatchLookup {
                cancelled: true,
                ..CallDispatchLookup::default()
            };
        }
        if limits.max_files == 0 || limits.max_source_bytes == 0 || limits.max_candidates == 0 {
            return CallDispatchLookup {
                budget_exhausted: true,
                diagnostics: vec![format!(
                    "exact call dispatch budget omitted {}",
                    location.file
                )],
                ..CallDispatchLookup::default()
            };
        }
        if exact_source.len() > limits.max_source_bytes {
            return CallDispatchLookup {
                budget_exhausted: true,
                diagnostics: vec![format!(
                    "exact call dispatch source budget omitted {}",
                    location.file
                )],
                ..CallDispatchLookup::default()
            };
        }

        let work = CallRelationWork {
            scanned_files: 1,
            scanned_source_bytes: exact_source.len(),
            examined_candidates: 1,
        };
        let language = language_for_file(&location.file);
        if language == Language::None {
            return unresolved_dispatch_lookup(
                DefinitionLookupStatus::UnsupportedLanguage,
                "exact call dispatch does not support this file language".to_string(),
                work,
            );
        }
        let Some(tree) = parse_tree_for_language(&location.file, language, &exact_source) else {
            return unresolved_dispatch_lookup(
                DefinitionLookupStatus::NotFound,
                format!("failed to parse {} for exact call dispatch", location.file),
                work,
            );
        };
        let Some(reference) = exact_call_reference_for_call(&tree, language, &location.call_span)
        else {
            return unresolved_dispatch_lookup(
                DefinitionLookupStatus::InvalidLocation,
                format!(
                    "range [{}, {}) is not one exact supported call expression in {}",
                    location.call_span.start_byte, location.call_span.end_byte, location.file
                ),
                work,
            );
        };
        let callee_range = match reference {
            ExactCallReference::Resolvable(range) => range,
            ExactCallReference::Unsupported(ExactCallReferenceGap::RubyCallableObject) => {
                return unresolved_dispatch_lookup(
                    DefinitionLookupStatus::NoDefinition,
                    "unsupported_ruby_callable_object_dispatch: resolving `receiver.(...)` requires value/heap callable-target information"
                        .to_string(),
                    work,
                );
            }
        };
        let batch = resolve_call_references_with_source(
            analyzer,
            token,
            &location.file,
            Arc::clone(&exact_source),
            &tree,
            std::slice::from_ref(&callee_range),
            cancellation,
        );
        let mut lookup = CallDispatchLookup {
            cancelled: batch.cancelled,
            work,
            ..CallDispatchLookup::default()
        };
        let Some((_, outcome)) = batch.resolved.into_iter().next() else {
            if !lookup.cancelled {
                lookup.status = Some(DefinitionLookupStatus::NotFound);
                lookup.boundaries.push(CallDispatchBoundaryKind::Unresolved(
                    DefinitionLookupStatus::NotFound,
                ));
                lookup.diagnostics.push(
                    "definition resolver returned no outcome for the exact call reference"
                        .to_string(),
                );
            }
            return lookup;
        };
        if outcome.outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary {
            let name = outcome
                .outcome
                .resolved_reference_target()
                .unwrap_or_default();
            let (boundary, _) =
                super::get_definition::trace::boundary_evidence(analyzer, &location.file, name);
            lookup.boundary = Some(boundary);
        }
        apply_call_target_outcome(
            &mut lookup,
            expand_imported_external_callee(analyzer, &location.file, outcome),
            limits.max_candidates,
            language,
            Some(&ExternalCalleeSite {
                source: &exact_source,
                tree: &tree,
                callee_start_byte: callee_range.start_byte,
            }),
        );
        lookup.cancelled |= cancellation.is_some_and(CancellationToken::is_cancelled);
        lookup
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
fn expand_imported_external_callee(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    mut outcome: CallTargetLookupOutcome,
) -> CallTargetLookupOutcome {
    if !matches!(
        outcome.outcome.status,
        DefinitionLookupStatus::NoDefinition | DefinitionLookupStatus::UnresolvableImportBoundary
    ) {
        return outcome;
    }
    let Some(text) = outcome.outcome.resolved_reference_target() else {
        return outcome;
    };
    let Some(expanded) = language_support(language_for_file(file))
        .and_then(|support| support.expand_imported_external_callee(analyzer, file, text))
    else {
        return outcome;
    };
    if let Some(reference) = outcome.outcome.reference.as_mut() {
        reference.text = expanded;
    }
    outcome
}

fn apply_call_target_outcome(
    lookup: &mut CallDispatchLookup,
    outcome: CallTargetLookupOutcome,
    max_targets: usize,
    language: Language,
    site: Option<&ExternalCalleeSite<'_>>,
) {
    apply_dispatch_outcome_with_flags(
        lookup,
        outcome.outcome,
        max_targets,
        language,
        site,
        outcome.structure_unavailable,
        outcome.unproven_link_unit,
        outcome.truncated,
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
    site: Option<&ExternalCalleeSite<'_>>,
    structure_unavailable: bool,
    unproven_link_unit: bool,
    navigation_targets_truncated: bool,
) {
    let DefinitionLookupOutcome {
        status,
        mut definitions,
        lexical_definition: _,
        diagnostics,
        reference,
    } = outcome;
    // The syntactic callee text (`java.net.URLDecoder.decode`) is the only
    // identity an unmaterialized external callee leaves behind, so retain it on
    // the external boundary instead of dropping it (#1978). Canonicalizing it
    // once here is what makes every external route below carry an identity that
    // is bindable, or none at all (#2598).
    let external_callee_text: Option<Box<str>> = reference
        .as_ref()
        .and_then(|reference| canonical_external_callee(&reference.text, language, site))
        .map(Box::<str>::from);
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
        lookup.boundaries.push(CallDispatchBoundaryKind::External(
            external_callee_text.clone(),
        ));
    }
    if partial_unresolved_import {
        lookup.boundaries.push(CallDispatchBoundaryKind::Unresolved(
            DefinitionLookupStatus::NoDefinition,
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
            lookup
                .boundaries
                .push(CallDispatchBoundaryKind::Unresolved(status));
        }
        DefinitionLookupStatus::Resolved | DefinitionLookupStatus::Ambiguous => {}
        DefinitionLookupStatus::UnresolvableImportBoundary => lookup
            .boundaries
            .push(CallDispatchBoundaryKind::External(external_callee_text)),
        // #1978: a fully-qualified callee with no workspace or classpath
        // definition (`java.net.URLDecoder.decode`) is external, not merely
        // unresolvable. Java classifies it `NoDefinition` rather than
        // `UnresolvableImportBoundary`, so route only that fully-qualified subset
        // to the external boundary that can carry an activated summary. Every
        // other `NoDefinition` -- an unqualified or single-segment callee -- keeps
        // its unresolved boundary, so the classification blast radius is limited
        // to callees that name a bindable external identity.
        DefinitionLookupStatus::NoDefinition => match external_callee_text {
            Some(text) => lookup
                .boundaries
                .push(CallDispatchBoundaryKind::External(Some(text))),
            None => lookup
                .boundaries
                .push(CallDispatchBoundaryKind::Unresolved(status)),
        },
        DefinitionLookupStatus::UnsupportedLanguage
        | DefinitionLookupStatus::InvalidLocation
        | DefinitionLookupStatus::NotFound => lookup
            .boundaries
            .push(CallDispatchBoundaryKind::Unresolved(status)),
    }
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
fn canonical_external_callee(
    callee_text: &str,
    language: Language,
    site: Option<&ExternalCalleeSite<'_>>,
) -> Option<String> {
    let (owner, member) =
        crate::analyzer::semantic::split_canonical_qualified_callee(callee_text, language)?;
    if owner.contains('.') {
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
/// is a Python constructor call, whose formals are `__init__`'s and whose
/// `self` the allocation binds; a class in any other language names no
/// parameter list this seam can read. Shared with the `call_binding` row
/// producer so both answer from one rule (issue #2499).
pub fn formal_owner_for_callee(
    analyzer: &dyn IAnalyzer,
    callee: &CodeUnit,
) -> Option<(CodeUnit, bool)> {
    if !callee.is_class() {
        return Some((callee.clone(), false));
    }
    if language_for_file(callee.source()) != Language::Python {
        return None;
    }
    let mut constructors = analyzer
        .direct_children(callee)
        .into_iter()
        .filter(|unit| unit.is_callable() && unit.identifier() == "__init__")
        .collect::<Vec<_>>();
    constructors.sort();
    constructors.dedup();
    (constructors.len() == 1).then(|| (constructors.remove(0), true))
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
    };
    use crate::analyzer::{AnalyzerQueryScope, QueryScope};
    use crate::analyzer::{
        CodeUnitType, Language, PythonAnalyzer, TestProject, TypescriptAnalyzer,
    };
    use crate::test_support::AnalyzerFixture;

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

    /// #1599: a boundary status carries its refined external evidence so the
    /// dispatch oracle can classify quality from it. Nothing declares or
    /// indexes `third-party` here, so the refinement is `external_unknown`.
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
            Some(BoundaryStatus::ExternalUnknown),
            "{lookup:#?}"
        );
        // The payload of an external boundary is the canonical external
        // identity, not the raw callee text (#2598). `work` names no owner at
        // all, so it identifies nothing an authored summary could be keyed
        // under, and the boundary says so instead of carrying a spelling the
        // minting side would discard anyway. The refined status above is what
        // this test is about and is unchanged.
        assert_eq!(
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::External(None)],
            "{lookup:#?}"
        );
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
            structure_unavailable,
            unproven_link_unit: false,
            truncated,
        };

        let mut unavailable = CallDispatchLookup::default();
        apply_call_target_outcome(
            &mut unavailable,
            outcome(DefinitionLookupStatus::Resolved, true, false),
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
            outcome(DefinitionLookupStatus::Ambiguous, false, true),
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
                CallDispatchBoundaryKind::External(None),
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
            vec![CallDispatchBoundaryKind::External(None)]
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
