// Node identity, node text, fqn prefix walking, and hit recording and
// reclassification need nothing but a node, a string, or the hit set, so they
// moved to `brokk-bifrost-core` and are re-exported here at the paths their
// callers already use. What stays needs an `IAnalyzer` or a `Language`.
pub(super) use brokk_bifrost_core::analyzer::usages::common::{
    SNIPPET_CONTEXT_LINES, reclassify_import_hit_at, same_node, usage_hit,
};
pub(crate) use brokk_bifrost_core::analyzer::usages::common::{
    classify_recursive_hit, external_usage_hit_count, namespace_prefixes,
};

use crate::analyzer::common as analyzer_common;
use crate::analyzer::declaration_range::DeclarationNameRangeContext;
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{CodeUnit, CodeUnitIndex, IAnalyzer, Language, ProjectFile};
use std::collections::BTreeSet;

pub(crate) fn language_for_target(target: &CodeUnit) -> Language {
    language_for_file(target.source())
}

/// Apply [`classify_recursive_hit`] to a proven hit set: a recursive call into
/// a callable target is kept and classified `SelfReceiver` (#1638), and every
/// other enclosing-equals-target hit stays dropped.
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
pub(crate) fn classify_recursive_hits(
    analyzer: &dyn IAnalyzer,
    hits: BTreeSet<UsageHit>,
    target: &CodeUnit,
) -> BTreeSet<UsageHit> {
    if !hits.iter().any(|hit| &hit.enclosing == target) {
        return hits;
    }
    let name_ranges = target_declaration_name_ranges(analyzer, target);
    hits.into_iter()
        .filter(|hit| {
            &hit.enclosing != target
                || hit.file != *target.source()
                || !name_ranges.iter().any(|range| {
                    hit.start_offset >= range.start_byte && hit.end_offset <= range.end_byte
                })
        })
        .filter_map(|hit| classify_recursive_hit(hit, target))
        .collect()
}

fn target_declaration_name_ranges(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
) -> Vec<crate::analyzer::Range> {
    // The hits' offsets come from scanning the analyzed snapshot, so the name
    // ranges must be computed against that same snapshot, not the file on
    // disk. A file the analyzer has not indexed produced no hits, so an empty
    // answer is exact there.
    let Some(content) = analyzer.indexed_source(target.source()) else {
        return Vec::new();
    };
    DeclarationNameRangeContext::new(target.source(), content).name_ranges(analyzer, target)
}

pub(super) fn language_for_file(file: &ProjectFile) -> Language {
    analyzer_common::language_for_file(file)
}

pub(crate) fn analyzed_files_for_language(
    analyzer: &dyn CodeUnitIndex,
    language: Language,
) -> Vec<ProjectFile> {
    let mut files: Vec<ProjectFile> = analyzer
        .analyzed_files()
        .into_iter()
        .filter(|file| language_for_file(file) == language)
        .collect();
    files.sort();
    files
}

pub(crate) use brokk_bifrost_core::analyzer::usages::common::enclosing_owner_chain;
