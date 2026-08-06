// Node identity, node text, fqn prefix walking, and hit recording and
// reclassification need nothing but a node, a string, or the hit set, so they
// moved to `brokk-bifrost-core` and are re-exported here at the paths their
// callers already use. What stays needs an `IAnalyzer` or a `Language`.
pub(super) use brokk_bifrost_core::analyzer::usages::common::{
    SNIPPET_CONTEXT_LINES, reclassify_import_hit_at, same_node, usage_hit,
};
pub(crate) use brokk_bifrost_core::analyzer::usages::common::{
    external_usage_hit_count, namespace_prefixes,
};

use crate::analyzer::common as analyzer_common;
use crate::analyzer::{CodeUnit, CodeUnitIndex, Language, ProjectFile};

pub(crate) fn language_for_target(target: &CodeUnit) -> Language {
    language_for_file(target.source())
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
