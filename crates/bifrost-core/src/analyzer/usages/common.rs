//! The language-blind half of the usage resolvers' shared helpers.
//!
//! Node identity, node text, fqn prefix walking, and hit recording and
//! reclassification: each is decided by a tree-sitter node, a string, or the hit
//! set, so none of it needs an analyzer handle. What is left of `usages::common`
//! -- the enclosing-owner chain, `analyzed_files_for_language`,
//! `language_for_target` -- names `IAnalyzer` or `Language` and stays in
//! `brokk-bifrost-analysis`, which re-exports these at their original paths.

use crate::analyzer::language_knowledge::LanguageKnowledge;
use crate::analyzer::usages::model::{UsageHit, UsageHitSurface};
use crate::analyzer::{CodeUnit, ProjectFile, Range};
use crate::text_utils::{find_line_index_for_offset, trimmed_snippet_around_line};
use std::collections::BTreeSet;
use tree_sitter::Node;

/// Graph-strategy hits land at maximum confidence.
pub const GRAPH_HIT_CONFIDENCE: f64 = 1.0;
/// Lines of context to include before/after a match in [`UsageHit::snippet`].
pub const SNIPPET_CONTEXT_LINES: usize = 1;

/// Count the proven hits that are visible to agent/search consumers. Binding,
/// definition, and same-owner sites remain available to editor consumers but
/// must not consume the external-usage budget.
pub fn external_usage_hit_count(hits: &BTreeSet<UsageHit>) -> usize {
    hits.iter()
        .filter(|hit| hit.kind.included_in(UsageHitSurface::ExternalUsages))
        .count()
}

pub fn insert_import_hit(hits: &mut BTreeSet<UsageHit>, hit: Option<UsageHit>) {
    if let Some(hit) = hit {
        hits.insert(hit.into_import());
    }
}

pub fn insert_unproven_hit(hits: &mut BTreeSet<UsageHit>, hit: Option<UsageHit>) {
    if let Some(hit) = hit {
        hits.insert(hit.into_unproven());
    }
}

pub fn reclassify_import_hit_at(
    hits: &mut BTreeSet<UsageHit>,
    file: &ProjectFile,
    start: usize,
    end: usize,
) {
    reclassify_hit_at(hits, file, start, end, UsageHit::into_import);
}

pub fn reclassify_override_declaration_hit_at(
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
pub fn reclassify_self_receiver_hit_at(
    hits: &mut BTreeSet<UsageHit>,
    file: &ProjectFile,
    start: usize,
    end: usize,
) {
    reclassify_hit_at(hits, file, start, end, UsageHit::into_self_receiver);
}

/// Decide what a proven hit whose enclosing declaration *is* the target means
/// (#1638). `None` drops the hit.
///
/// For a callable target the site is a recursive call. The forward occurrence
/// resolver states that edge and calls it a `self_reference`, so the inverse
/// listing must state it too, and `SelfReceiver` says both halves of the truth:
/// editor find-references lists the site, and the external usage surface omits
/// it, so dead-code evidence and the callsite budget still count only calls
/// from elsewhere.
///
/// A field initializer declares its target but reads its value, even when
/// that value names the field itself (#7289). The language supplies the target
/// and value nodes; shared code distinguishes the two by containment. Other
/// non-callable self sites remain excluded. Missing syntax cannot prove a read.
pub fn classify_recursive_hit(
    hit: UsageHit,
    target: &CodeUnit,
    site: Option<Node<'_>>,
    knowledge: &dyn LanguageKnowledge,
) -> Option<UsageHit> {
    if hit.enclosing != *target {
        return Some(hit);
    }
    if target.is_function() {
        return Some(hit.into_self_receiver());
    }
    if target.is_field() {
        let mut ancestor = site;
        while let Some(node) = ancestor {
            if let Some((binding, value)) = knowledge.field_initializer(node) {
                let contains_hit = |part: Node<'_>| {
                    part.start_byte() <= hit.start_offset && hit.end_offset <= part.end_byte()
                };
                return (contains_hit(value) && !contains_hit(binding)).then_some(hit);
            }
            ancestor = node.parent();
        }
    }
    None
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

pub fn usage_hit(
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

/// Build a usage hit for a syntax node with the caller's enclosing-unit policy.
pub fn usage_hit_for_node(
    node: Node<'_>,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    enclosing_code_unit: impl FnOnce(&Range) -> Option<CodeUnit>,
) -> Option<UsageHit> {
    let start_byte = node.start_byte();
    let end_byte = node.end_byte();
    if start_byte >= end_byte {
        return None;
    }

    let line_idx = find_line_index_for_offset(line_starts, start_byte);
    let snippet = trimmed_snippet_around_line(source, line_starts, line_idx, SNIPPET_CONTEXT_LINES);
    let range = Range {
        start_byte,
        end_byte,
        start_line: line_idx,
        end_line: line_idx,
    };
    let enclosing = enclosing_code_unit(&range)?;
    Some(usage_hit(
        file, line_idx, start_byte, end_byte, enclosing, snippet,
    ))
}

/// Yields `fqn`, then each progressively shorter dot-truncated prefix down to
/// (and including) the last single segment -- `"a.b.c"` -> `"a.b.c"`, `"a.b"`,
/// `"a"` -- never descending to the bare empty string unless `fqn` itself is
/// empty. Mirrors the `rfind('.') / truncate` idiom duplicated by every
/// "try the nearest enclosing scope, then its parent scope, ..." qualified-
/// name resolver (csharp's enclosing-namespace search, the shared
/// enclosing-scope resolver); callers that must skip the bare top level
/// entirely (see `resolve_in_enclosing_scopes`'s doc comment) add their own
/// `.take_while(|prefix| !prefix.is_empty())`.
pub fn namespace_prefixes(fqn: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(fqn), |scope| scope.rfind('.').map(|idx| &scope[..idx]))
}

/// Whether `left` and `right` are the same syntax node, by tree-sitter node
/// identity. Exact where a byte-range comparison can collide a unit/wrapper node
/// with its sole child (which share an identical span); both nodes must come from
/// the same tree for the ids to be comparable.
pub fn same_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.id() == right.id()
}

/// The trimmed source text spanned by `node`, or `""` if the byte range is not a
/// valid `str` boundary. Shared by the per-language usage resolvers that key on a
/// node's identifier/type text.
pub use crate::analyzer::common::node_source_text_trimmed as node_text;

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
pub fn enclosing_owner_chain<S>(start: CodeUnit, step: S) -> EnclosingOwnerChain<S>
where
    S: FnMut(&CodeUnit) -> Option<CodeUnit>,
{
    EnclosingOwnerChain {
        last: Some(start),
        step,
        started: false,
    }
}

/// The starting owner followed by its contiguous enclosing class owners.
pub fn enclosing_class_chain<S>(innermost: CodeUnit, step: S) -> impl Iterator<Item = CodeUnit>
where
    S: FnMut(&CodeUnit) -> Option<CodeUnit>,
{
    let parents = enclosing_owner_chain(innermost.clone(), step)
        .skip(1)
        .take_while(CodeUnit::is_class);
    std::iter::once(innermost).chain(parents)
}

pub struct EnclosingOwnerChain<S> {
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
