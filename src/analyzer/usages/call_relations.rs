//! Analyzer-owned call relations shared by query traversal and LSP call hierarchy.

use std::sync::Arc;

use crate::analyzer::common::language_for_file;
use crate::analyzer::lexical_definitions::{
    FormalParameterLayout, PythonMethodBinding, formal_parameter_slots,
};
use crate::analyzer::structural::FileFacts;
use crate::analyzer::usages::get_definition::{
    CPP_UNPROVEN_LINK_UNIT_DIAGNOSTIC, CallSiteSyntax, CallSyntaxKind, DefinitionLookupOutcome,
    DefinitionLookupRequest, DefinitionLookupStatus, ExactCallReference, ExactCallReferenceGap,
    call_reference_ranges_in_tree, call_reference_requires_point_lookup,
    call_site_syntax_for_reference, exact_call_reference_for_call, parse_tree_for_language,
    resolve_definition_batch_with_source, resolve_definition_batch_with_source_and_cancellation,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};

use super::{FuzzyResult, UsageFinder, UsageHit, UsageHitKind, UsageProof};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CallArgument {
    pub(crate) range: Range,
    pub(crate) name: Option<String>,
    pub(crate) position: Option<usize>,
    pub(crate) formal_index: Option<usize>,
    pub(crate) formal_name: Option<String>,
    pub(crate) variadic: bool,
    pub(crate) spread: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CallSite {
    pub(crate) file: ProjectFile,
    pub(crate) range: Range,
    pub(crate) callee_range: Range,
    pub(crate) caller: CodeUnit,
    pub(crate) callee: CodeUnit,
    pub(crate) kind: CallSyntaxKind,
    pub(crate) proof: UsageProof,
    pub(crate) receiver: Option<Range>,
    pub(crate) arguments: Vec<CallArgument>,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallDispatchBoundaryKind {
    /// Resolution proved that the referenced declaration crosses the indexed
    /// workspace boundary, but cannot name an external body.
    External,
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
    pub(crate) targets: Vec<CallDispatchTarget>,
    pub(crate) boundaries: Vec<CallDispatchBoundaryKind>,
    pub(crate) truncated: bool,
    pub(crate) cancelled: bool,
    pub(crate) budget_exhausted: bool,
    pub(crate) diagnostics: Vec<String>,
    pub(crate) work: CallRelationWork,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CallRelationLimits {
    pub(crate) max_files: usize,
    pub(crate) max_source_bytes: usize,
    pub(crate) max_candidates: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CallRelationWork {
    pub(crate) scanned_files: usize,
    pub(crate) scanned_source_bytes: usize,
    pub(crate) examined_candidates: usize,
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
pub(crate) struct CallRelationResult {
    pub(crate) sites: Vec<CallSite>,
    pub(crate) truncated: bool,
    pub(crate) cancelled: bool,
    pub(crate) diagnostics: Vec<String>,
    pub(crate) work: CallRelationWork,
}

#[derive(Default)]
pub(crate) struct CallBindingCache {
    formals: HashMap<CodeUnit, FormalParameterLayout>,
    python_receiver_is_class: HashMap<(ProjectFile, usize, usize), bool>,
}

#[derive(Default)]
struct CallSyntaxCache {
    files: HashMap<ProjectFile, Option<Arc<FileFacts>>>,
}

impl CallSyntaxCache {
    fn syntax_for_range(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
    ) -> Option<CallSiteSyntax> {
        let facts = self.files.entry(file.clone()).or_insert_with(|| {
            analyzer
                .structural_search_providers()
                .into_iter()
                .find_map(|provider| provider.structural_facts(file))
        });
        call_site_syntax_for_reference(facts.as_ref()?, start_byte, end_byte)
    }
}

pub(crate) struct CallRelationService;

impl CallRelationService {
    /// Resolve one exact whole-call span against one exact source snapshot.
    ///
    /// The caller supplies the source owned by the semantic artifact's
    /// revision. This method never rereads the file, so its byte span cannot
    /// race a newer disk or overlay snapshot. The same batched definition
    /// resolution core is used by legacy outgoing call relations below.
    pub(crate) fn dispatch_at_bounded(
        analyzer: &dyn IAnalyzer,
        location: &ExactCallLocation,
        exact_source: Arc<String>,
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
        apply_dispatch_outcome(&mut lookup, outcome, limits.max_candidates);
        lookup.cancelled |= cancellation.is_some_and(CancellationToken::is_cancelled);
        lookup
    }

    pub(crate) fn incoming(
        analyzer: &dyn IAnalyzer,
        target: &CodeUnit,
        max_files: usize,
        max_sites: usize,
    ) -> CallRelationResult {
        Self::incoming_bounded(
            analyzer,
            target,
            CallRelationLimits {
                max_files,
                max_source_bytes: usize::MAX,
                max_candidates: max_sites,
            },
            None,
        )
    }

    pub(crate) fn incoming_bounded(
        analyzer: &dyn IAnalyzer,
        target: &CodeUnit,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> CallRelationResult {
        if !is_call_relation_unit(target) {
            return CallRelationResult::default();
        }
        if limits.max_files == 0 || limits.max_source_bytes == 0 || limits.max_candidates == 0 {
            return CallRelationResult {
                truncated: true,
                diagnostics: vec![format!("call relation budget omitted {}", target.fq_name())],
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
        let (hits, mut truncated, mut diagnostics) = call_hits(query.result, target);
        truncated |= query.candidate_files_truncated || query.source_bytes_truncated;
        let mut syntax_cache = CallSyntaxCache::default();
        let mut sites = Vec::new();
        let mut cancelled = false;
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
            let Some(caller) = nearest_call_relation_unit(analyzer, hit.enclosing.clone()) else {
                continue;
            };
            let Some(syntax) = syntax_cache.syntax_for_range(
                analyzer,
                &hit.file,
                hit.start_offset,
                hit.end_offset,
            ) else {
                continue;
            };
            sites.push(raw_call_site(
                hit.file,
                caller,
                target.clone(),
                syntax,
                proof,
            ));
        }

        // Usage graphs intentionally suppress references enclosed by the target
        // itself. Recover those exact recursive edges from the target's own
        // outgoing relation so incoming and outgoing traversal stay symmetric.
        if !cancelled {
            let recursive = Self::outgoing_bounded(
                analyzer,
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

    pub(crate) fn outgoing(
        analyzer: &dyn IAnalyzer,
        caller: &CodeUnit,
        max_sites: usize,
    ) -> CallRelationResult {
        Self::outgoing_bounded(
            analyzer,
            caller,
            CallRelationLimits {
                max_files: 1,
                max_source_bytes: usize::MAX,
                max_candidates: max_sites,
            },
            None,
        )
    }

    pub(crate) fn outgoing_bounded(
        analyzer: &dyn IAnalyzer,
        caller: &CodeUnit,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> CallRelationResult {
        if !is_call_relation_unit(caller) {
            return CallRelationResult::default();
        }
        if limits.max_files == 0 || limits.max_source_bytes == 0 || limits.max_candidates == 0 {
            return CallRelationResult {
                truncated: true,
                diagnostics: vec![format!("call relation budget omitted {}", caller.fq_name())],
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
        let Some(source) = analyzer.indexed_source(caller.source()).map(Arc::new) else {
            return CallRelationResult::default();
        };
        if source.len() > limits.max_source_bytes || limits.max_files == 0 {
            return CallRelationResult {
                truncated: true,
                diagnostics: vec![format!("call relation budget omitted {}", caller.source())],
                ..CallRelationResult::default()
            };
        }
        let language = language_for_file(caller.source());
        let Some(tree) = parse_tree_for_language(caller.source(), language, &source) else {
            return CallRelationResult {
                diagnostics: vec![format!("failed to parse {}", caller.source())],
                ..CallRelationResult::default()
            };
        };
        let Some(caller_range) = analyzer.ranges_of(caller).into_iter().min_by_key(range_key)
        else {
            return CallRelationResult::default();
        };
        let candidate_limit = limits.max_candidates.saturating_add(1);
        let candidates =
            call_reference_ranges_in_tree(&tree, language, &caller_range, candidate_limit);
        let truncated = candidates.len() > limits.max_candidates;
        let candidates = candidates
            .into_iter()
            .take(limits.max_candidates)
            .collect::<Vec<_>>();
        let batch = resolve_call_references_with_source(
            analyzer,
            caller.source(),
            Arc::clone(&source),
            &tree,
            &candidates,
            cancellation,
        );
        let mut sites = Vec::new();
        let mut syntax_cache = CallSyntaxCache::default();
        for (candidate, outcome) in batch.resolved {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                break;
            }
            let proof = match outcome.status {
                DefinitionLookupStatus::Resolved => UsageProof::Proven,
                DefinitionLookupStatus::Ambiguous => UsageProof::Unproven,
                _ => continue,
            };
            let Some(syntax) = syntax_cache.syntax_for_range(
                analyzer,
                caller.source(),
                candidate.start_byte,
                candidate.end_byte,
            ) else {
                continue;
            };
            for definition in outcome.definitions {
                let Some(callee) = nearest_call_relation_unit(analyzer, definition) else {
                    continue;
                };
                sites.push(raw_call_site(
                    caller.source().clone(),
                    caller.clone(),
                    callee,
                    syntax.clone(),
                    proof,
                ));
            }
        }
        sort_and_dedup_sites(&mut sites);
        CallRelationResult {
            sites,
            truncated,
            cancelled: batch.cancelled,
            diagnostics: Vec::new(),
            work: CallRelationWork {
                scanned_files: 1,
                scanned_source_bytes: source.len(),
                examined_candidates: candidates.len(),
            },
        }
    }
}

struct CallReferenceResolutionBatch {
    resolved: Vec<(Range, DefinitionLookupOutcome)>,
    cancelled: bool,
}

/// Resolve already-structured call reference ranges in one shared batch.
/// Exact semantic dispatch supplies one range; outgoing call relations supply
/// every range in the caller. Cancellation may shorten the lower-level result
/// vector, so pairing is retained explicitly rather than silently assuming
/// one outcome per request.
fn resolve_call_references_with_source(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: Arc<String>,
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
    let outcomes = match cancellation {
        Some(cancellation) => resolve_definition_batch_with_source_and_cancellation(
            analyzer,
            requests,
            file.clone(),
            source,
            cancellation,
        ),
        None => resolve_definition_batch_with_source(analyzer, requests, file.clone(), source),
    };
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

fn apply_dispatch_outcome(
    lookup: &mut CallDispatchLookup,
    outcome: DefinitionLookupOutcome,
    max_targets: usize,
) {
    let DefinitionLookupOutcome {
        status,
        mut definitions,
        lexical_definition: _,
        diagnostics,
        reference: _,
    } = outcome;
    let unproven_target_identity = diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == CPP_UNPROVEN_LINK_UNIT_DIAGNOSTIC);
    lookup.status = Some(status);
    lookup.diagnostics.extend(
        diagnostics
            .into_iter()
            .map(|diagnostic| format!("{}: {}", diagnostic.kind, diagnostic.message)),
    );

    definitions.sort();
    definitions.dedup();
    if definitions.len() > max_targets {
        definitions.truncate(max_targets);
        lookup.truncated = true;
        lookup.budget_exhausted = true;
        lookup.boundaries.push(CallDispatchBoundaryKind::Truncated);
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
        DefinitionLookupStatus::UnresolvableImportBoundary => {
            lookup.boundaries.push(CallDispatchBoundaryKind::External)
        }
        DefinitionLookupStatus::NoDefinition
        | DefinitionLookupStatus::UnsupportedLanguage
        | DefinitionLookupStatus::InvalidLocation
        | DefinitionLookupStatus::NotFound => lookup
            .boundaries
            .push(CallDispatchBoundaryKind::Unresolved(status)),
    }
}

fn call_hits(
    result: FuzzyResult,
    target: &CodeUnit,
) -> (Vec<(UsageHit, UsageProof)>, bool, Vec<String>) {
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
                    format!(
                        "omitted {omitted} unproven call candidates for {}",
                        target.fq_name()
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
            vec![format!(
                "call targets for {} are ambiguous; candidates are unproven",
                target.fq_name()
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
            vec![format!(
                "found {total_callsites} call candidates for {}, retaining the first {limit}",
                target.fq_name()
            )],
        ),
        FuzzyResult::Failure { reason, .. } => (Vec::new(), false, vec![reason]),
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

pub(crate) fn bind_call_site_arguments(
    analyzer: &dyn IAnalyzer,
    site: &mut CallSite,
    cache: &mut CallBindingCache,
) {
    let Some((formal_owner, constructor_binding)) = formal_owner_for_site(analyzer, site) else {
        return;
    };
    let layout = cache
        .formals
        .entry(formal_owner.clone())
        .or_insert_with(|| formal_slots_for_unit(analyzer, &formal_owner))
        .clone();
    let bind_first = constructor_binding
        || python_first_formal_is_bound(analyzer, site, &formal_owner, &layout, cache);
    let mut ordinary_slots = layout
        .slots
        .iter()
        .filter(|slot| !slot.receiver)
        .collect::<Vec<_>>();
    if bind_first && !ordinary_slots.is_empty() {
        ordinary_slots.remove(0);
    }
    let ordinary_slots = ordinary_slots.into_iter().enumerate().collect::<Vec<_>>();

    for argument in &mut site.arguments {
        let slot =
            if argument.spread {
                None
            } else if let Some(name) = &argument.name {
                ordinary_slots
                    .iter()
                    .copied()
                    .find(|(_, slot)| {
                        slot.names
                            .iter()
                            .any(|candidate| names_match(candidate, name))
                    })
                    .or_else(|| {
                        ordinary_slots.iter().copied().rev().find(|(_, slot)| {
                            slot.variadic.is_some_and(|kind| kind.accepts_keyword())
                        })
                    })
            } else {
                argument.position.and_then(|position| {
                    ordinary_slots.get(position).copied().or_else(|| {
                        ordinary_slots.iter().copied().rev().find(|(_, slot)| {
                            slot.variadic.is_some_and(|kind| kind.accepts_positional())
                        })
                    })
                })
            };
        argument.formal_index = slot.map(|(index, _)| index);
        argument.formal_name = slot
            .and_then(|(_, slot)| slot.names.first())
            .map(|name| canonical_parameter_name(name));
        argument.variadic = slot.is_some_and(|(_, slot)| slot.variadic.is_some());
    }
}

fn formal_owner_for_site(analyzer: &dyn IAnalyzer, site: &CallSite) -> Option<(CodeUnit, bool)> {
    if !site.callee.is_class() {
        return Some((site.callee.clone(), false));
    }
    if language_for_file(site.callee.source()) != Language::Python {
        return None;
    }
    let mut constructors = analyzer
        .direct_children(&site.callee)
        .into_iter()
        .filter(|unit| unit.is_callable() && unit.identifier() == "__init__")
        .collect::<Vec<_>>();
    constructors.sort();
    constructors.dedup();
    (constructors.len() == 1).then(|| (constructors.remove(0), true))
}

fn python_first_formal_is_bound(
    analyzer: &dyn IAnalyzer,
    site: &CallSite,
    formal_owner: &CodeUnit,
    layout: &FormalParameterLayout,
    cache: &mut CallBindingCache,
) -> bool {
    if language_for_file(formal_owner.source()) != Language::Python
        || !analyzer
            .parent_of(formal_owner)
            .is_some_and(|owner| owner.is_class())
    {
        return false;
    }
    match layout.python_binding {
        Some(PythonMethodBinding::Static) | None => false,
        Some(PythonMethodBinding::Class) => site.receiver.is_some(),
        Some(PythonMethodBinding::Instance) => {
            let Some(receiver) = site.receiver else {
                return false;
            };
            !python_receiver_resolves_to_class(analyzer, site, receiver, cache)
        }
    }
}

fn python_receiver_resolves_to_class(
    analyzer: &dyn IAnalyzer,
    site: &CallSite,
    receiver: Range,
    cache: &mut CallBindingCache,
) -> bool {
    let key = (site.file.clone(), receiver.start_byte, receiver.end_byte);
    if let Some(is_class) = cache.python_receiver_is_class.get(&key) {
        return *is_class;
    }
    let is_class = analyzer
        .indexed_source(&site.file)
        .map(Arc::new)
        .and_then(|source| {
            resolve_definition_batch_with_source(
                analyzer,
                vec![DefinitionLookupRequest {
                    file: site.file.clone(),
                    line: None,
                    column: None,
                    start_byte: Some(receiver.start_byte),
                    end_byte: Some(receiver.end_byte),
                }],
                site.file.clone(),
                source,
            )
            .into_iter()
            .next()
        })
        .is_some_and(|outcome| {
            outcome.status == DefinitionLookupStatus::Resolved
                && outcome.definitions.iter().any(CodeUnit::is_class)
        });
    cache.python_receiver_is_class.insert(key, is_class);
    is_class
}

fn formal_slots_for_unit(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> FormalParameterLayout {
    if unit.is_class() {
        return FormalParameterLayout::default();
    }
    let Some(source) = analyzer.indexed_source(unit.source()) else {
        return FormalParameterLayout::default();
    };
    let language = language_for_file(unit.source());
    let Some(tree) = parse_tree_for_language(unit.source(), language, &source) else {
        return FormalParameterLayout::default();
    };
    let Some(range) = analyzer.ranges_of(unit).into_iter().min_by_key(range_key) else {
        return FormalParameterLayout::default();
    };
    formal_parameter_slots(language, tree.root_node(), &source, &range)
}

fn names_match(formal: &str, argument: &str) -> bool {
    formal == argument
        || formal.strip_prefix('$') == Some(argument)
        || argument.strip_prefix('$') == Some(formal)
}

fn canonical_parameter_name(name: &str) -> String {
    name.strip_prefix('$').unwrap_or(name).to_owned()
}

pub(crate) fn nearest_call_relation_unit(
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

pub(crate) fn is_call_relation_unit(unit: &CodeUnit) -> bool {
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
    use crate::analyzer::usages::get_definition::{
        DefinitionLookupDiagnostic, DefinitionLookupOutcome,
    };
    use crate::analyzer::{CodeUnitType, Language};
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
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            &ExactCallLocation {
                file,
                call_span: call_span(source, "inner()"),
            },
            Arc::new(source.to_string()),
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
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "Example.java"),
                call_span: call_span(source, "helper()"),
            },
            Arc::new(source.to_string()),
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
            let lookup = CallRelationService::dispatch_at_bounded(
                fixture.analyzer.analyzer(),
                &ExactCallLocation {
                    file: ProjectFile::new(fixture.project_root(), "calls.cpp"),
                    call_span: call_span(source, call),
                },
                Arc::new(source.to_string()),
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
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "calls.cpp"),
                call_span: call_span(source, "callable()"),
            },
            Arc::new(source.to_string()),
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
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "caller.c"),
                call_span: call_span(caller_source, "local_target(1)"),
            },
            Arc::new(caller_source.to_string()),
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
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "example.rb"),
                call_span: call_span(source, "target"),
            },
            Arc::new(source.to_string()),
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
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "example.rb"),
                call_span: call_span(source, call),
            },
            Arc::new(source.to_string()),
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
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "example.rb"),
                call_span: call_span(source, call),
            },
            Arc::new(source.to_string()),
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
            let lookup = CallRelationService::dispatch_at_bounded(
                fixture.analyzer.analyzer(),
                &ExactCallLocation {
                    file: ProjectFile::new(fixture.project_root(), "example.rb"),
                    call_span: call_span(source, call),
                },
                Arc::new(source.to_string()),
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
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "example.rb"),
                call_span: call_span(source, call),
            },
            Arc::new(source.to_string()),
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

        let relation =
            CallRelationService::outgoing_bounded(analyzer, &caller, generous_limits(), None);
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

        let relation =
            CallRelationService::outgoing_bounded(analyzer, &caller, generous_limits(), None);
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
        let source = Arc::new("function target() {}\ntarget();\n".to_string());
        let fixture = AnalyzerFixture::new_for_language(
            Language::TypeScript,
            &[("sample.ts", source.as_str())],
        );
        let location = ExactCallLocation {
            file: ProjectFile::new(fixture.project_root(), "sample.ts"),
            call_span: call_span(&source, "target()"),
        };
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let cancelled = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
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
    fn dispatch_mapping_preserves_status_boundaries_and_partial_candidates() {
        let root = std::env::temp_dir();
        let file = ProjectFile::new(root, "dispatch.ts");
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
            1,
        );
        assert_eq!(ambiguous.status, Some(DefinitionLookupStatus::Ambiguous));
        assert_eq!(ambiguous.targets.len(), 1);
        assert_eq!(ambiguous.targets[0].proof, UsageProof::Unproven);
        assert!(ambiguous.truncated);
        assert!(ambiguous.budget_exhausted);
        assert!(
            ambiguous
                .boundaries
                .contains(&CallDispatchBoundaryKind::Truncated)
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
        );
        assert_eq!(
            external.boundaries,
            vec![CallDispatchBoundaryKind::External]
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
            );
            assert_eq!(unresolved.status, Some(status));
            assert_eq!(
                unresolved.boundaries,
                vec![CallDispatchBoundaryKind::Unresolved(status)]
            );
        }
    }
}
