//! The language-blind half of the usage resolvers' shared helpers.
//!
//! Node identity, node text, and fqn prefix walking: each is decided by a
//! tree-sitter node or a string, so none of it needs an analyzer handle. The
//! rest of `usages::common` -- hit reclassification, the enclosing-owner chain,
//! `analyzed_files_for_language` -- names `IAnalyzer` or the hit set and stays
//! in `brokk-bifrost-analysis`, which re-exports these at their original paths.

use crate::analyzer::common::node_source_text_trimmed;
use tree_sitter::Node;

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
