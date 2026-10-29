// Node identity, node text, fqn prefix walking, and hit recording and
// reclassification need nothing but a node, a string, or the hit set, so they
// moved to `brokk-bifrost-core` and are re-exported here at the paths their
// callers already use. What stays needs an `IAnalyzer` or a `Language`.
pub(crate) use brokk_bifrost_core::analyzer::usages::common::{
    classify_recursive_hit, namespace_prefixes,
};

use crate::analyzer::declaration_range::DeclarationNameRangeContext;
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{
    CodeUnit, CodeUnitIndex, IAnalyzer, Language, ProjectFile, Range, SignatureMetadata,
};
use std::collections::BTreeSet;

#[doc(hidden)]
pub fn build_reference_site(
    path: String,
    text: String,
    range: Range,
    focus_start_byte: usize,
    focus_end_byte: usize,
) -> crate::analyzer::usages::reference_site::ResolvedReferenceSite {
    crate::analyzer::usages::reference_site::ResolvedReferenceSite {
        path,
        text,
        range,
        focus_start_byte,
        focus_end_byte,
    }
}

// Graph strategy selection uses source language, not declaration naming.
// An unclaimed extension may be eligible for C++ include inference without
// supplying a C++ graph surface.
#[doc(hidden)]
pub fn language_for_target(target: &CodeUnit) -> Language {
    language_for_file(target.source())
}

pub(crate) fn is_constructor_metadata(metadata: &[SignatureMetadata]) -> bool {
    metadata
        .iter()
        .any(SignatureMetadata::callable_is_constructor)
}

/// Apply [`classify_recursive_hit`] to a proven hit set: a recursive call into
/// a callable target is kept and classified `SelfReceiver` (#1638), and every
/// other enclosing-equals-target hit stays dropped unless it reads a field
/// initializer value.
///
/// The target's own declared name is refused first. A scan records a
/// declaration's name token like any other occurrence -- Rust's `fn is_unpin<T>
/// () {}` yields an `is_unpin` identifier enclosed by, and equal in identity
/// to, the declaration it names. Dropping every enclosing-equals-target hit
/// used to hide that; the name is now excluded on its own structural terms,
/// through the analyzer's declaration name ranges rather than any source-text
/// comparison.
///
/// Both the declaration name ranges and the file read behind them are computed
/// only when some hit is a candidate, so the ordinary query pays nothing.
#[doc(hidden)]
pub fn classify_recursive_hits(
    analyzer: &dyn IAnalyzer,
    hits: BTreeSet<UsageHit>,
    target: &CodeUnit,
) -> BTreeSet<UsageHit> {
    if !hits.iter().any(|hit| &hit.enclosing == target) {
        return hits;
    }
    let context = analyzer
        .indexed_source(target.source())
        .map(|content| DeclarationNameRangeContext::new(target.source(), content));
    let name_ranges = context
        .as_ref()
        .map(|context| context.name_ranges(analyzer, target))
        .unwrap_or_default();
    let knowledge = crate::analyzer::languages::language_knowledge(language_for_target(target))
        .expect("a usage target has a supported language");
    hits.into_iter()
        .filter(|hit| {
            &hit.enclosing != target
                || hit.file != *target.source()
                || !name_ranges.iter().any(|range| {
                    hit.start_offset >= range.start_byte && hit.end_offset <= range.end_byte
                })
        })
        .filter_map(|hit| {
            let site = context
                .as_ref()
                .filter(|_| target.is_field() && hit.enclosing == *target)
                .and_then(|context| context.root_node())
                .and_then(|root| root.descendant_for_byte_range(hit.start_offset, hit.end_offset));
            classify_recursive_hit(hit, target, site, knowledge)
        })
        .collect()
}

pub(super) use crate::analyzer::common::language_for_file;

#[doc(hidden)]
pub fn analyzed_files_for_language(
    analyzer: &dyn CodeUnitIndex,
    language: Language,
) -> Vec<ProjectFile> {
    analyzer.analyzed_files_for_language(language)
}

#[doc(hidden)]
pub fn analyzable_usage_graph_files(
    analyzer: &dyn IAnalyzer,
    language: Language,
) -> Option<Vec<ProjectFile>> {
    Some(
        analyzer
            .project()
            .analyzable_files(language)
            .ok()?
            .into_iter()
            .collect(),
    )
}

#[doc(hidden)]
pub fn select_usage_graph_files(
    files: &[ProjectFile],
    keep_file: impl Fn(&ProjectFile) -> bool,
) -> Vec<ProjectFile> {
    files
        .iter()
        .filter(|file| keep_file(file))
        .cloned()
        .collect()
}

#[doc(hidden)]
pub fn with_relational_frontier<R>(
    analyzer: &dyn IAnalyzer,
    language: &str,
    mut visit: impl FnMut(&dyn brokk_bifrost_core::analyzer::RelationalDefinitionFrontier) -> R,
) -> R {
    let cancellation = crate::CancellationToken::new();
    match crate::analyzer::relational_frontier::resolve_relational_frontier(
        analyzer,
        &cancellation,
        |frontier| visit(frontier),
    ) {
        crate::analyzer::RelationalFrontierOutcome::Complete(result) => result,
        crate::analyzer::RelationalFrontierOutcome::Cancelled => {
            unreachable!("an uncancelled {language} helper frontier cannot cancel")
        }
        crate::analyzer::RelationalFrontierOutcome::Failed(error) => {
            panic!("{language} relational helper frontier failed: {error:?}")
        }
    }
}

pub(crate) use brokk_bifrost_core::analyzer::usages::common::enclosing_owner_chain;
