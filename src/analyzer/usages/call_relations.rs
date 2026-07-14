//! Analyzer-owned call relations shared by query traversal and LSP call hierarchy.

use std::sync::Arc;

use crate::analyzer::common::language_for_file;
use crate::analyzer::lexical_definitions::{
    FormalParameterLayout, FormalParameterSlot, formal_parameter_slots,
};
use crate::analyzer::usages::get_definition::{
    CallSiteSyntax, CallSyntaxKind, DefinitionLookupRequest, DefinitionLookupStatus,
    call_reference_ranges, call_site_syntax_for_reference, parse_tree_for_language,
    resolve_definition_batch_with_source,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range};
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

#[derive(Debug, Clone, Default)]
pub(crate) struct CallRelationResult {
    pub(crate) sites: Vec<CallSite>,
    pub(crate) truncated: bool,
    pub(crate) diagnostics: Vec<String>,
}

pub(crate) struct CallRelationService;

impl CallRelationService {
    pub(crate) fn incoming(
        analyzer: &dyn IAnalyzer,
        target: &CodeUnit,
        max_files: usize,
        max_sites: usize,
    ) -> CallRelationResult {
        if !is_call_relation_unit(target) {
            return CallRelationResult::default();
        }
        let result = UsageFinder::new().find_usages(
            analyzer,
            std::slice::from_ref(target),
            max_files,
            max_sites,
        );
        let (hits, mut truncated, mut diagnostics) = call_hits(result, target);
        let mut outgoing_by_caller: HashMap<CodeUnit, CallRelationResult> = HashMap::default();
        let mut sites = Vec::new();
        for (hit, proof) in hits {
            if !matches!(
                hit.kind,
                UsageHitKind::Reference | UsageHitKind::SelfReceiver
            ) {
                continue;
            }
            let Some(caller) = nearest_call_relation_unit(analyzer, hit.enclosing.clone()) else {
                continue;
            };
            let outgoing = outgoing_by_caller
                .entry(caller.clone())
                .or_insert_with(|| Self::outgoing(analyzer, &caller, max_sites));
            truncated |= outgoing.truncated;
            diagnostics.extend(outgoing.diagnostics.iter().cloned());
            sites.extend(
                outgoing
                    .sites
                    .iter()
                    .filter(|site| {
                        site.callee == *target
                            && site.file == hit.file
                            && site.callee_range.start_byte == hit.start_offset
                            && site.callee_range.end_byte == hit.end_offset
                    })
                    .cloned()
                    .map(|mut site| {
                        if proof == UsageProof::Unproven {
                            site.proof = UsageProof::Unproven;
                        }
                        site
                    }),
            );
        }
        sort_and_dedup_sites(&mut sites);
        diagnostics.sort();
        diagnostics.dedup();
        CallRelationResult {
            sites,
            truncated,
            diagnostics,
        }
    }

    pub(crate) fn outgoing(
        analyzer: &dyn IAnalyzer,
        caller: &CodeUnit,
        max_sites: usize,
    ) -> CallRelationResult {
        if !is_call_relation_unit(caller) {
            return CallRelationResult::default();
        }
        let Some(source) = analyzer.indexed_source(caller.source()).map(Arc::new) else {
            return CallRelationResult::default();
        };
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
        let candidate_limit = max_sites.saturating_add(1);
        let candidates =
            call_reference_ranges(caller.source(), &source, &caller_range, candidate_limit);
        let truncated = candidates.len() > max_sites;
        let candidates = candidates.into_iter().take(max_sites).collect::<Vec<_>>();
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
        let outcomes = resolve_definition_batch_with_source(
            analyzer,
            requests,
            caller.source().clone(),
            Arc::clone(&source),
        );
        let mut formal_cache = HashMap::default();
        let mut sites = Vec::new();
        for (candidate, outcome) in candidates.into_iter().zip(outcomes) {
            let proof = match outcome.status {
                DefinitionLookupStatus::Resolved => UsageProof::Proven,
                DefinitionLookupStatus::Ambiguous => UsageProof::Unproven,
                _ => continue,
            };
            let Some(syntax) = call_site_syntax_for_reference(
                &tree,
                language,
                &source,
                candidate.start_byte,
                candidate.end_byte,
            ) else {
                continue;
            };
            for definition in outcome.definitions {
                let Some(callee) = nearest_call_relation_unit(analyzer, definition) else {
                    continue;
                };
                sites.push(build_call_site(
                    analyzer,
                    caller.source().clone(),
                    caller.clone(),
                    callee,
                    syntax.clone(),
                    proof,
                    &mut formal_cache,
                ));
            }
        }
        sort_and_dedup_sites(&mut sites);
        CallRelationResult {
            sites,
            truncated,
            diagnostics: Vec::new(),
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
            ..
        } => (
            Vec::new(),
            true,
            vec![format!(
                "found {total_callsites} call candidates for {}, exceeding limit {limit}",
                target.fq_name()
            )],
        ),
        FuzzyResult::Failure { reason, .. } => (Vec::new(), false, vec![reason]),
    }
}

fn build_call_site(
    analyzer: &dyn IAnalyzer,
    file: ProjectFile,
    caller: CodeUnit,
    callee: CodeUnit,
    syntax: CallSiteSyntax,
    proof: UsageProof,
    formal_cache: &mut HashMap<CodeUnit, FormalParameterLayout>,
) -> CallSite {
    let kind = if callee.is_class() {
        CallSyntaxKind::Constructor
    } else {
        syntax.kind
    };
    let slots = formal_cache
        .entry(callee.clone())
        .or_insert_with(|| formal_slots_for_unit(analyzer, &callee));
    let ordinary_slots = effective_ordinary_slots(
        analyzer,
        &callee,
        syntax.receiver.is_some(),
        &slots.slots,
        slots.receiver_bound_first,
    );
    let arguments = syntax
        .arguments
        .into_iter()
        .map(|argument| {
            let slot = if argument.spread {
                None
            } else if let Some(name) = &argument.name {
                ordinary_slots.iter().copied().find(|(_, slot)| {
                    slot.names
                        .iter()
                        .any(|candidate| names_match(candidate, name))
                })
            } else {
                argument.position.and_then(|position| {
                    ordinary_slots.get(position).copied().or_else(|| {
                        ordinary_slots
                            .last()
                            .copied()
                            .filter(|(_, slot)| slot.variadic)
                    })
                })
            };
            CallArgument {
                range: argument.range,
                name: argument.name,
                position: argument.position,
                formal_index: slot.map(|(index, _)| index),
                formal_name: slot
                    .and_then(|(_, slot)| slot.names.first())
                    .map(|name| canonical_parameter_name(name)),
                variadic: slot.is_some_and(|(_, slot)| slot.variadic),
                spread: argument.spread,
            }
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

fn formal_slots_for_unit(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> FormalParameterLayout {
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

fn effective_ordinary_slots<'a>(
    analyzer: &dyn IAnalyzer,
    callee: &CodeUnit,
    has_receiver: bool,
    slots: &'a [FormalParameterSlot],
    receiver_bound_first: bool,
) -> Vec<(usize, &'a FormalParameterSlot)> {
    let mut ordinary = slots
        .iter()
        .filter(|slot| !slot.receiver)
        .collect::<Vec<_>>();
    if has_receiver
        && language_for_file(callee.source()) == Language::Python
        && analyzer
            .parent_of(callee)
            .is_some_and(|owner| owner.is_class())
        && receiver_bound_first
        && !ordinary.is_empty()
    {
        ordinary.remove(0);
    }
    ordinary.into_iter().enumerate().collect()
}

fn names_match(formal: &str, argument: &str) -> bool {
    formal == argument
        || formal.strip_prefix('$') == Some(argument)
        || argument.strip_prefix('$') == Some(formal)
}

fn canonical_parameter_name(name: &str) -> String {
    name.strip_prefix('$').unwrap_or(name).to_owned()
}

fn nearest_call_relation_unit(analyzer: &dyn IAnalyzer, mut unit: CodeUnit) -> Option<CodeUnit> {
    loop {
        if is_call_relation_unit(&unit) {
            return Some(unit);
        }
        unit = analyzer.parent_of(&unit)?;
    }
}

fn is_call_relation_unit(unit: &CodeUnit) -> bool {
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
