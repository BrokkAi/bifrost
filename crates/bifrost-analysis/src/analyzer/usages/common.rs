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

/// Lazily walks a [`CodeUnit`]'s enclosing-owner chain outward, starting at
/// `start` itself and stepping via caller-supplied `step` on every
/// subsequent pull. `step` is ordinarily a direct or budget-charging wrapper
/// over `analyzer.parent_of` (dynamic dispatch, so per-language overrides —
/// e.g. rust's and scala's opposite structural-vs-fqn precedence — apply
/// automatically); the walk never reimplements the fqn-split default itself.
///
/// This is the shared shape behind ~10 per-language "find/collect enclosing
/// owners" copies that differ only in what happens once a candidate is in
/// hand:
/// - `.find(accept)` — the innermost owner `accept` approves (java's/csharp's
///   enclosing-class lookup, python's/php's self-receiver owner).
/// - `.take_while(accept).collect()` — the contiguous run of approved owners
///   from `start` outward, stopping at the first rejection (cpp's enclosing
///   class chain).
/// - `.filter(accept).collect()` — every approved owner anywhere in the
///   chain, walking all the way to the root regardless of what's skipped in
///   between (cpp's indexed enclosing components; scala's template-owner
///   walk over non-CodeUnit intermediate scopes).
///
/// Deliberately lazy: `step` is called only when a consumer actually pulls
/// the next item (never speculatively), so a `.find`/`.take_while` that
/// stops after `k` accepted owners calls `step` exactly `k` times — the same
/// number of `parent_of` hops the hand-written `while` loops it replaces
/// would have charged.
pub(crate) fn enclosing_owner_chain<S>(start: CodeUnit, step: S) -> EnclosingOwnerChain<S>
where
    S: FnMut(&CodeUnit) -> Option<CodeUnit>,
{
    EnclosingOwnerChain {
        last: Some(start),
        step,
        started: false,
    }
}

pub(crate) struct EnclosingOwnerChain<S> {
    last: Option<CodeUnit>,
    step: S,
    started: bool,
}

impl<S> Iterator for EnclosingOwnerChain<S>
where
    S: FnMut(&CodeUnit) -> Option<CodeUnit>,
{
    type Item = CodeUnit;

    fn next(&mut self) -> Option<CodeUnit> {
        if self.started {
            let previous = self.last.as_ref()?;
            self.last = (self.step)(previous);
        } else {
            self.started = true;
        }
        self.last.clone()
    }
}
