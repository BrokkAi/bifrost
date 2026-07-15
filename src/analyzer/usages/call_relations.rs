//! Analyzer-owned call relations shared by query traversal and LSP call hierarchy.

use std::sync::Arc;

use crate::analyzer::common::language_for_file;
use crate::analyzer::lexical_definitions::{
    FormalParameterLayout, PythonMethodBinding, formal_parameter_slots,
};
use crate::analyzer::structural::FileFacts;
use crate::analyzer::usages::get_definition::{
    CallSiteSyntax, CallSyntaxKind, DefinitionLookupRequest, DefinitionLookupStatus,
    call_reference_ranges_in_tree, call_site_syntax_for_reference, parse_tree_for_language,
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
        let requests = candidates
            .iter()
            .map(|range| DefinitionLookupRequest {
                file: caller.source().clone(),
                line: None,
                column: None,
                start_byte: Some(range.start_byte),
                end_byte: Some(range.end_byte),
            })
            .collect();
        let outcomes = match cancellation {
            Some(cancellation) => resolve_definition_batch_with_source_and_cancellation(
                analyzer,
                requests,
                caller.source().clone(),
                Arc::clone(&source),
                cancellation,
            ),
            None => resolve_definition_batch_with_source(
                analyzer,
                requests,
                caller.source().clone(),
                Arc::clone(&source),
            ),
        };
        let mut sites = Vec::new();
        let mut syntax_cache = CallSyntaxCache::default();
        for (candidate, outcome) in candidates.iter().copied().zip(outcomes) {
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
            cancelled: cancellation.is_some_and(CancellationToken::is_cancelled),
            diagnostics: Vec::new(),
            work: CallRelationWork {
                scanned_files: 1,
                scanned_source_bytes: source.len(),
                examined_candidates: candidates.len(),
            },
        }
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
