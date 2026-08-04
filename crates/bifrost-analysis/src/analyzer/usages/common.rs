// Node identity, node text, and fqn prefix walking need nothing but a node or a
// string, so they moved to `brokk-bifrost-core` and are re-exported here at the
// paths their callers already use. What stays needs a hit set or an `IAnalyzer`.
pub(crate) use brokk_bifrost_core::analyzer::usages::common::namespace_prefixes;
pub(super) use brokk_bifrost_core::analyzer::usages::common::{node_text, same_node};

use crate::analyzer::common as analyzer_common;
use crate::analyzer::usages::model::{UsageHit, UsageHitSurface};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use std::collections::BTreeSet;

/// Graph-strategy hits land at maximum confidence.
pub(super) const GRAPH_HIT_CONFIDENCE: f64 = 1.0;
/// Lines of context to include before/after a match in [`UsageHit::snippet`].
pub(super) const SNIPPET_CONTEXT_LINES: usize = 1;

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

pub(super) fn reclassify_import_hit_at(
    hits: &mut BTreeSet<UsageHit>,
    file: &ProjectFile,
    start: usize,
    end: usize,
) {
    reclassify_hit_at(hits, file, start, end, UsageHit::into_import);
}

pub(super) fn reclassify_override_declaration_hit_at(
    hits: &mut BTreeSet<UsageHit>,
    file: &ProjectFile,
    start: usize,
    end: usize,
) {
    reclassify_hit_at(hits, file, start, end, UsageHit::into_override_declaration);
}

/// Reclassify an already-recorded proven hit at `[start, end)` as a same-owner
/// self/this receiver hit. Used by the per-language extractors (#1014 facet B)
/// so a call whose receiver is the current instance / own type is counted as a
/// same-owner site and excluded from the external usage surface, uniformly with
/// Rust/C++/JS-TS.
pub(super) fn reclassify_self_receiver_hit_at(
    hits: &mut BTreeSet<UsageHit>,
    file: &ProjectFile,
    start: usize,
    end: usize,
) {
    reclassify_hit_at(hits, file, start, end, UsageHit::into_self_receiver);
}

fn reclassify_hit_at(
    hits: &mut BTreeSet<UsageHit>,
    file: &ProjectFile,
    start: usize,
    end: usize,
    reclassify: impl FnOnce(UsageHit) -> UsageHit,
) {
    if let Some(hit) = hits
        .iter()
        .find(|hit| hit.file == *file && hit.start_offset == start && hit.end_offset == end)
        .cloned()
    {
        hits.remove(&hit);
        hits.insert(reclassify(hit));
    }
}

pub(super) fn usage_hit(
    file: &ProjectFile,
    line_idx: usize,
    start_offset: usize,
    end_offset: usize,
    enclosing: CodeUnit,
    snippet: impl Into<String>,
) -> UsageHit {
    UsageHit::new(
        file.clone(),
        line_idx + 1,
        start_offset,
        end_offset,
        enclosing,
        GRAPH_HIT_CONFIDENCE,
        snippet,
    )
}
