//! The language-blind half of the analyzer's tree-sitter traversal helpers.
//!
//! Stack-based (non-recursive) preorder and enter/exit walks plus the two
//! byte-range readers that every language adapter needs and none of them can
//! specialize: the leading-comment expansion behind chunk text, and the
//! parse-error collector.
//! Nothing here needs a grammar, an analyzer handle, or a store -- the budgeted
//! walk charges its own counter against a caller-supplied limit and reads this
//! crate's own cancellation token, so it belongs here too. The traversal helpers
//! that do need those -- the per-language extractors -- stay in
//! `brokk-bifrost-analysis`, which re-exports these at their original paths.

use crate::analyzer::model::{Language, ParseError, ParseErrorKind, Range};
use crate::cancellation::CancellationToken;
#[cfg(any(test, feature = "test-support"))]
use std::cell::Cell;
use tree_sitter::Node;

/// The byte and 1-based line span a node covers. Language-blind: every adapter
/// that records a range for a node reads it exactly this way.
pub fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkControl {
    Continue,
    SkipChildren,
    Break,
}

pub fn walk_tree_preorder<'tree>(
    root: Node<'tree>,
    include_root: bool,
    mut visit: impl FnMut(Node<'tree>) -> WalkControl,
) {
    let mut cursor = root.walk();
    let mut is_root = true;

    loop {
        let node = cursor.node();
        let should_descend = if include_root || !is_root {
            match visit(node) {
                WalkControl::Continue => true,
                WalkControl::SkipChildren => false,
                WalkControl::Break => return,
            }
        } else {
            true
        };

        if should_descend && cursor.goto_first_child() {
            is_root = false;
            continue;
        }

        loop {
            if cursor.goto_next_sibling() {
                is_root = false;
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

pub fn walk_named_tree_preorder<'tree>(
    root: Node<'tree>,
    include_root: bool,
    mut visit: impl FnMut(Node<'tree>) -> WalkControl,
) {
    let result: Result<(), std::convert::Infallible> =
        try_walk_named_tree_preorder(root, include_root, |node| Ok(visit(node)));
    match result {
        Ok(()) => {}
        Err(error) => match error {},
    }
}

/// Fallible counterpart to [`walk_named_tree_preorder`]. Both helpers retain
/// source-order preorder traversal while allowing visitors to prune or stop.
pub fn try_walk_named_tree_preorder<'tree, Error>(
    root: Node<'tree>,
    include_root: bool,
    mut visit: impl FnMut(Node<'tree>) -> Result<WalkControl, Error>,
) -> Result<(), Error> {
    let mut cursor = root.walk();
    let mut is_root = true;

    loop {
        let node = cursor.node();
        let should_descend = if node.is_named() && (include_root || !is_root) {
            match visit(node)? {
                WalkControl::Continue => true,
                WalkControl::SkipChildren => false,
                WalkControl::Break => return Ok(()),
            }
        } else {
            true
        };

        if should_descend && cursor.goto_first_child() {
            is_root = false;
            continue;
        }

        loop {
            if cursor.goto_next_sibling() {
                is_root = false;
                break;
            }
            if !cursor.goto_parent() {
                return Ok(());
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedNamedTreeWalk {
    Complete { visited: usize },
    Exceeded { visited: usize },
    Cancelled,
}

/// Visit named nodes in source-order preorder while applying the shared
/// receiver/setup traversal budget and cancellation policy.
pub fn walk_named_tree_preorder_bounded<'tree>(
    root: Node<'tree>,
    include_root: bool,
    max_named_nodes: usize,
    cancellation: Option<&CancellationToken>,
    mut visit: impl FnMut(Node<'tree>),
) -> BoundedNamedTreeWalk {
    enum Stop {
        Exceeded,
        Cancelled,
    }

    let mut visited = 0usize;
    let result = try_walk_named_tree_preorder(root, include_root, |node| {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(Stop::Cancelled);
        }
        visited = visited.saturating_add(1);
        if visited > max_named_nodes {
            return Err(Stop::Exceeded);
        }
        visit(node);
        Ok(WalkControl::Continue)
    });
    match result {
        Ok(()) => BoundedNamedTreeWalk::Complete { visited },
        Err(Stop::Exceeded) => BoundedNamedTreeWalk::Exceeded { visited },
        Err(Stop::Cancelled) => BoundedNamedTreeWalk::Cancelled,
    }
}

/// Expand `start_byte` upward to include the declaration's own leading comment
/// block (its docstring / JSDoc / Rust attributes).
///
/// Only a comment block *contiguously attached* to the declaration counts: a
/// blank line terminates the walk. This is what keeps a file-level license
/// header -- separated from the first declaration by a blank line -- from being
/// misattributed as that declaration's docstring, which previously made chunk
/// `text` start at the file header while `start_line`/`end_line` still pointed
/// at the declaration body.
///
/// `language` decides what a leading `#` means, which is not a detail the walk
/// can guess: in Python, Ruby, and PHP it opens a line comment, while in C and
/// C++ it opens a preprocessor directive (see [`hash_starts_line_comment`]).
pub fn expanded_comment_start(language: Language, source: &str, start_byte: usize) -> usize {
    // Tree-sitter can report a byte offset inside a UTF-8 code point for a
    // malformed or generated source file. The caller's later `str::get` already
    // rejects that range, so do not panic while trying to add comments. This
    // occurred while prewarming Envoy's generated C++ sources.
    if start_byte > source.len() || !source.is_char_boundary(start_byte) {
        return start_byte.min(source.len());
    }

    // Walk backward from the declaration instead of building a line index for
    // the whole file. Semantic indexing asks for every function body in a
    // file; rescanning a multi-megabyte generated file once per function made
    // that extraction path effectively quadratic.
    let bytes = source.as_bytes();
    let mut next_line_start = bytes[..start_byte]
        .iter()
        .rposition(|byte| matches!(byte, b'\n' | b'\r'))
        .map_or(0, |separator| separator + 1);

    let mut comment_start = start_byte;
    while next_line_start > 0 {
        let mut line_end = next_line_start;
        if bytes[line_end - 1] == b'\n' {
            line_end -= 1;
            if line_end > 0 && bytes[line_end - 1] == b'\r' {
                line_end -= 1;
            }
        } else {
            debug_assert_eq!(bytes[line_end - 1], b'\r');
            line_end -= 1;
        }
        let line_start = bytes[..line_end]
            .iter()
            .rposition(|byte| matches!(byte, b'\n' | b'\r'))
            .map_or(0, |separator| separator + 1);
        let line = &source[line_start..line_end];
        let trimmed = line.trim_start();
        next_line_start = line_start;

        // A blank line separates the declaration (or its attached comment block)
        // from whatever precedes it; stop rather than reaching across the gap.
        if trimmed.trim().is_empty() {
            break;
        }

        if is_comment_like(trimmed, language) {
            comment_start = line_start;
            continue;
        }

        if let Some(offset) = first_comment_offset(line, language) {
            comment_start = line_start + offset;
        }
        break;
    }

    comment_start
}

/// Whether a leading `#` opens a line comment in `language`.
///
/// The three that say yes are the analyzable languages whose `#` runs to end
/// of line. Everywhere else `#` is either a preprocessor directive (C, C++,
/// C#) or not a comment at all, and a `#`-prefixed line only continues a
/// comment block when what follows the `#` is itself comment text -- which is
/// what [`is_comment_like`] then requires.
///
/// Boost's preprocessor limit headers are why this is a language decision and
/// not a spelling one (#1775). They write their license preamble as null
/// directives (`# /* Copyright ... */`, then a bare `#`) and their bodies as
/// spaced directives (`# define BOOST_PP_BOOL_176 1`). Reading every `# `
/// line as a comment made the backward walk run from any one macro through
/// every preceding `# define` and `# ifndef` up to line 1, so
/// `get_symbol_sources` answered a one-line macro with the whole 193-line
/// preamble.
fn hash_starts_line_comment(language: Language) -> bool {
    match language {
        Language::Python | Language::Ruby | Language::Php => true,
        Language::None
        | Language::Java
        | Language::Go
        | Language::Cpp
        | Language::JavaScript
        | Language::TypeScript
        | Language::Rust
        | Language::Scala
        | Language::CSharp
        | Language::Kotlin => false,
    }
}

fn is_comment_like(trimmed_line: &str, language: Language) -> bool {
    if trimmed_line.starts_with("/**")
        || trimmed_line.starts_with("/*")
        || trimmed_line.starts_with("*/")
        || trimmed_line.starts_with('*')
        || trimmed_line.starts_with("//")
        || trimmed_line.starts_with("#[")
    {
        return true;
    }
    let Some(rest) = trimmed_line.strip_prefix('#') else {
        return false;
    };
    if hash_starts_line_comment(language) {
        return rest.is_empty() || rest.chars().next().is_some_and(char::is_whitespace);
    }
    // A directive line continues an attached comment block only when the
    // directive itself is null and carries nothing but comment text: boost's
    // `# /* Revised by Paul Mensonides (2002) */` and its bare `#` spacers
    // stay attached, while `# define` and `# ifndef` terminate the walk.
    let rest = rest.trim_start();
    rest.is_empty()
        || rest.starts_with("/*")
        || rest.starts_with("*/")
        || rest.starts_with('*')
        || rest.starts_with("//")
}

fn first_comment_offset(line: &str, language: Language) -> Option<usize> {
    let markers = ["/**", "/*", "//", "#["]
        .into_iter()
        .filter_map(|marker| line.find(marker));
    if hash_starts_line_comment(language) {
        markers.chain(line.find("# ")).min()
    } else {
        markers.min()
    }
}

/// The direct named children of `node`, in source order.
pub fn named_children<'tree>(node: Node<'tree>) -> Vec<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

/// The first direct named child of `node` whose kind is `kind`.
///
/// Distinct from a bare "first named child": this selects by kind, which is how
/// declaration walks reach a specific grammar slot (a `class_body`, a
/// `type_identifier`) without assuming child order.
pub fn first_named_child_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

/// Whether `node` has an anonymous (token) child spelled `token`.
///
/// Restricted to anonymous children on purpose: grammars can spell the same
/// text as either a keyword token or a named node, and callers asking this
/// question want the keyword.
pub fn has_token_child(node: Node<'_>, token: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| !child.is_named() && child.kind() == token)
}

/// Whether the subtree rooted at `node` (including `node` itself) contains a
/// descendant matching `predicate`, short-circuiting on the first match. Iterative
/// (explicit stack) depth-first search; visit order does not affect the result.
pub fn subtree_contains(node: Node<'_>, predicate: impl Fn(Node<'_>) -> bool) -> bool {
    let mut stack = vec![node];
    while let Some(candidate) = stack.pop() {
        if predicate(candidate) {
            return true;
        }
        let mut cursor = candidate.walk();
        stack.extend(candidate.named_children(&mut cursor));
    }
    false
}

/// Find the node whose byte span exactly equals `range`. When several nested
/// nodes share that exact span, return the deepest one. The shallow wrapper
/// often carries no `name` field, so returning it would defeat declaration-name
/// resolution.
pub fn node_for_exact_range<'tree>(root: Node<'tree>, range: &Range) -> Option<Node<'tree>> {
    let mut best: Option<Node<'tree>> = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() > range.start_byte || node.end_byte() < range.end_byte {
            continue;
        }
        if node.start_byte() == range.start_byte && node.end_byte() == range.end_byte {
            // Exact-span nodes form a nested chain; overwriting keeps the
            // deepest node encountered so far.
            best = Some(node);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.start_byte() <= range.start_byte && child.end_byte() >= range.end_byte {
                stack.push(child);
            }
        }
    }
    best
}

/// Walk `node` and append every `ERROR` / `MISSING` span into `out`. Does NOT
/// recurse into `ERROR` nodes: every descendant would also report as errored
/// and the diagnostic list would explode. Used both by `analyze_file` (to
/// populate the per-file cache) and by `lsp::handlers::diagnostic` (for the
/// fallback path when the analyzer has no cached state), so the two paths
/// share one source of truth for the walk semantics and the
/// `end_byte.max(start_byte)` clamp.
pub fn collect_parse_errors(node: Node, out: &mut Vec<ParseError>) {
    walk_tree_preorder(node, true, |node| {
        if node.is_error() || node.is_missing() {
            let range = Range {
                start_byte: node.start_byte(),
                end_byte: node.end_byte().max(node.start_byte()),
                start_line: node.start_position().row,
                end_line: node.end_position().row,
            };
            let kind = if node.is_missing() {
                ParseErrorKind::Missing(node.kind().to_string())
            } else {
                ParseErrorKind::Error
            };
            out.push(ParseError { range, kind });
            if node.is_error() {
                return WalkControl::SkipChildren;
            }
        }
        WalkControl::Continue
    });
}

/// What [`walk_tree_iterative`] should do after visiting a node on entry.
pub enum TreeWalkAction {
    /// Descend into the node's named children; do not call `exit` for this node.
    Descend,
    /// Descend into the node's named children, then call `exit` once all
    /// descendants have been visited.
    DescendWithExit,
    /// Do not descend into this node's children.
    Skip,
    /// Stop the entire traversal immediately without firing pending exits.
    Stop,
}

enum TreeWalkFrame<'tree> {
    Enter(Node<'tree>),
    Exit,
}

/// Iterative (stack-based) enter/exit tree-sitter walk over `root`'s named
/// descendants (root included). `enter` is called on the way down and decides
/// whether to descend and whether an `exit` callback should fire on the way back
/// up (`DescendWithExit`) once all of that node's descendants have been visited.
///
/// Children are visited in source order; `exit` calls nest correctly with
/// `enter`/`exit` pairs from descendants firing before their ancestor's `exit`.
pub fn walk_tree_iterative<State>(
    root: Node<'_>,
    state: &mut State,
    mut enter: impl FnMut(Node<'_>, &mut State) -> TreeWalkAction,
    mut exit: impl FnMut(&mut State),
) {
    let mut stack = vec![TreeWalkFrame::Enter(root)];
    while let Some(frame) = stack.pop() {
        match frame {
            TreeWalkFrame::Enter(node) => match enter(node, state) {
                TreeWalkAction::Descend => push_named_children(node, &mut stack),
                TreeWalkAction::DescendWithExit => {
                    stack.push(TreeWalkFrame::Exit);
                    push_named_children(node, &mut stack);
                }
                TreeWalkAction::Skip => {}
                TreeWalkAction::Stop => break,
            },
            TreeWalkFrame::Exit => exit(state),
        }
    }
}

/// Push `node`'s named children so the walk pops them in source order.
///
/// Collected through a cursor rather than by `named_child(index)`: tree-sitter
/// resolves a child by index by stepping a fresh cursor from the first child, so
/// an index loop over `k` children costs `O(k^2)`. A generated source file whose
/// program node holds tens of thousands of statements pays that once per level
/// (#2369). The cursor walks each child exactly once instead, and the reversal
/// of the freshly pushed span keeps the original visit order.
fn push_named_children<'tree>(node: Node<'tree>, stack: &mut Vec<TreeWalkFrame<'tree>>) {
    let mut cursor = node.walk();
    let first_pushed = stack.len();
    stack.extend(node.named_children(&mut cursor).map(TreeWalkFrame::Enter));
    stack[first_pushed..].reverse();
}

/// The parent of every node in one tree, recorded by a single downward pass.
///
/// A tree-sitter node carries no parent pointer. `ts_node_parent` recovers one
/// by re-descending from the root, scanning each level's children until it finds
/// the one that contains the node, so a single call costs the node's position in
/// the tree. A file whose translation unit holds thousands of siblings therefore
/// makes one parent question cost thousands of steps, and asking it once per
/// declaration is quadratic in the file (#2361, and #2369 for the same shape in
/// JavaScript).
///
/// The relation the question asks about is fixed for the tree, so one preorder
/// pass records all of it and every later question is a hash lookup.
/// [`Self::parent`] answers exactly what [`Node::parent`] answers -- it is built
/// from the same visible-child relation `ts_node_parent` descends through -- so
/// substituting it cannot change a walk's result.
///
/// The index owns one entry per node, so it costs memory proportional to the
/// tree. Build it for the tree a walk is about to traverse and drop it with the
/// walk.
pub struct ParentIndex<'tree> {
    parents: crate::hash::HashMap<usize, Node<'tree>>,
    #[cfg(any(test, feature = "test-support"))]
    parent_queries: Cell<usize>,
}

impl<'tree> ParentIndex<'tree> {
    /// Record the parent of every node beneath `root`.
    pub fn new(root: Node<'tree>) -> Self {
        let mut parents = crate::hash::HashMap::default();
        let mut cursor = root.walk();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            // Visible children, named and anonymous alike: that is the relation
            // `ts_node_parent` walks, so an index built from anything narrower
            // would answer a different question for an anonymous node.
            cursor.reset(node);
            let before = stack.len();
            stack.extend(node.children(&mut cursor));
            for child in &stack[before..] {
                parents.insert(child.id(), node);
            }
        }
        Self {
            parents,
            #[cfg(any(test, feature = "test-support"))]
            parent_queries: Cell::new(0),
        }
    }

    /// An index that records nothing, so every question is answered by
    /// [`Node::parent`] itself.
    ///
    /// This is what a caller outside a traversal passes: it asks a bounded
    /// number of parent questions about a tree it does not otherwise walk, so
    /// indexing the tree would cost more than the questions do. It allocates
    /// nothing. A per-node caller inside a walk must pass a real index instead
    /// -- that is the shape this type exists to remove.
    pub fn unindexed() -> Self {
        Self {
            parents: crate::hash::HashMap::default(),
            #[cfg(any(test, feature = "test-support"))]
            parent_queries: Cell::new(0),
        }
    }

    /// The parent of `node`, or `None` for the root.
    ///
    /// A node the index does not hold -- the indexed root, a node of another
    /// tree, or any node at all when the index is [`Self::unindexed`] -- falls
    /// back to [`Node::parent`], which answers the same question and pays the
    /// walk this index exists to avoid.
    pub fn parent(&self, node: Node<'tree>) -> Option<Node<'tree>> {
        #[cfg(any(test, feature = "test-support"))]
        self.parent_queries
            .set(self.parent_queries.get().saturating_add(1));
        match self.parents.get(&node.id()) {
            Some(parent) => Some(*parent),
            None => node.parent(),
        }
    }

    /// Reset the number of parent questions answered by this index.
    #[cfg(any(test, feature = "test-support"))]
    pub fn reset_parent_query_count_for_test(&self) {
        self.parent_queries.set(0);
    }

    /// Return the number of parent questions answered since construction or reset.
    #[cfg(any(test, feature = "test-support"))]
    pub fn parent_query_count_for_test(&self) -> usize {
        self.parent_queries.get()
    }
}

#[cfg(test)]
mod tests {
    use super::expanded_comment_start;
    use crate::analyzer::model::Language;

    /// The boost preprocessor limit-header shape from #1775.
    const BOOST_SHAPE: &str = "\
# /* Copyright (C) 2001
#  * Housemarque Oy
#  */
#
# ifndef GUARD_HPP
# define GUARD_HPP
#
# define BOOST_PP_BOOL_0 0
# define BOOST_PP_BOOL_1 1
";

    #[test]
    fn cpp_spaced_directive_lines_terminate_the_walk() {
        let declaration = BOOST_SHAPE.find("# define BOOST_PP_BOOL_1 1").unwrap();

        assert_eq!(
            expanded_comment_start(Language::Cpp, BOOST_SHAPE, declaration),
            declaration,
            "`# define`/`# ifndef` are directives, so the macro has no attached comment"
        );
    }

    #[test]
    fn hash_comment_languages_still_attach_every_hash_line() {
        // The same bytes read as a hash-comment language: every `# ` line is a
        // comment, so the whole block above the declaration attaches.
        let declaration = BOOST_SHAPE.find("# define BOOST_PP_BOOL_1 1").unwrap();

        for language in [Language::Python, Language::Ruby, Language::Php] {
            assert_eq!(
                expanded_comment_start(language, BOOST_SHAPE, declaration),
                0,
                "{language:?} spells a line comment with `#`"
            );
        }
    }

    #[test]
    fn cpp_null_directives_carrying_comment_text_stay_attached() {
        let source = "\
# /* Fast path toggle.
#  * Second line.
#  */
#
# define FAST 1
";
        let declaration = source.find("# define FAST 1").unwrap();

        assert_eq!(
            expanded_comment_start(Language::Cpp, source, declaration),
            0,
            "a null directive whose payload is comment text is the macro's docstring"
        );
    }

    #[test]
    fn cpp_directive_after_a_block_comment_keeps_the_comment() {
        let source = "/** Fast path toggle. */\n# define FAST 1\n";
        let declaration = source.find("# define FAST 1").unwrap();

        assert_eq!(
            expanded_comment_start(Language::Cpp, source, declaration),
            0
        );
    }

    #[test]
    fn python_inline_comment_boundary_survives_the_language_gate() {
        // The `# ` fallback on a terminating code line is a hash-comment-only
        // rule: it must not fire for a C++ line that merely contains `# `.
        let python = "value = 1  # nearby\ndef work():\n";
        let declaration = python.find("def work").unwrap();
        assert_eq!(
            expanded_comment_start(Language::Python, python, declaration),
            python.find("# nearby").unwrap()
        );

        let cpp = "int value = 1;  # not a comment\nvoid work() {}\n";
        let declaration = cpp.find("void work").unwrap();
        assert_eq!(
            expanded_comment_start(Language::Cpp, cpp, declaration),
            declaration
        );
    }
}
