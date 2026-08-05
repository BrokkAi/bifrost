//! The language-blind half of the usage resolvers' shared helpers.
//!
//! Node identity, node text, fqn prefix walking, and hit recording and
//! reclassification: each is decided by a tree-sitter node, a string, or the hit
//! set, so none of it needs an analyzer handle. What is left of `usages::common`
//! -- the enclosing-owner chain, `analyzed_files_for_language`,
//! `language_for_target` -- names `IAnalyzer` or `Language` and stays in
//! `brokk-bifrost-analysis`, which re-exports these at their original paths.

use crate::analyzer::common::node_source_text_trimmed;
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{CodeUnit, ProjectFile};
use std::collections::BTreeSet;
use tree_sitter::Node;

/// Graph-strategy hits land at maximum confidence.
pub const GRAPH_HIT_CONFIDENCE: f64 = 1.0;
/// Lines of context to include before/after a match in [`UsageHit::snippet`].
pub const SNIPPET_CONTEXT_LINES: usize = 1;

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
pub fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node_source_text_trimmed(node, source)
}
