// Node identity, node text, fqn prefix walking, and hit recording and
// reclassification need nothing but a node, a string, or the hit set, so they
// moved to `brokk-bifrost-core` and are re-exported here at the paths their
// callers already use. What stays needs an `IAnalyzer` or a `Language`.
pub(crate) use brokk_bifrost_core::analyzer::usages::common::namespace_prefixes;
pub(super) use brokk_bifrost_core::analyzer::usages::common::{
    SNIPPET_CONTEXT_LINES, node_text, reclassify_import_hit_at,
    reclassify_override_declaration_hit_at, reclassify_self_receiver_hit_at, same_node, usage_hit,
};

use crate::analyzer::common as analyzer_common;
use crate::analyzer::usages::model::{UsageHit, UsageHitSurface};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use std::collections::BTreeSet;

/// Count the proven hits that are visible to agent/search consumers. Binding,
/// definition, and same-owner sites remain available to editor consumers but
/// must not consume the external-usage budget.
pub(crate) fn external_usage_hit_count(hits: &BTreeSet<UsageHit>) -> usize {
    hits.iter()
        .filter(|hit| hit.kind.included_in(UsageHitSurface::ExternalUsages))
        .count()
}

pub(crate) fn language_for_target(target: &CodeUnit) -> Language {
    language_for_file(target.source())
}

pub(super) fn language_for_target_filtered(
    target: &CodeUnit,
    filter: impl FnOnce(Language) -> bool,
) -> Language {
    let language = language_for_target(target);
    if filter(language) {
        language
    } else {
        Language::None
    }
}

pub(super) fn language_for_file(file: &ProjectFile) -> Language {
    analyzer_common::language_for_file(file)
}

pub(crate) fn analyzed_files_for_language(
    analyzer: &dyn IAnalyzer,
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
