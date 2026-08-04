//! The language-blind half of the analyzer's tree-sitter traversal helpers.
//!
//! Stack-based (non-recursive) preorder walks plus the two byte-range readers
//! that every language adapter needs and none of them can specialize: the
//! leading-comment expansion behind chunk text, and the parse-error collector.
//! Nothing here needs a grammar, an analyzer handle, or a store. The traversal
//! helpers that do -- the budgeted walk with its cancellation token, and the
//! per-language extractors -- stay in `brokk-bifrost-analysis`, which re-exports
//! these at their original paths.

use crate::analyzer::model::{ParseError, ParseErrorKind, Range};
use tree_sitter::Node;

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
    enum Frame<'tree> {
        Enter(Node<'tree>, bool),
        NextChild(Node<'tree>, usize),
    }

    let mut stack = vec![Frame::Enter(root, true)];
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Enter(node, is_root) => {
                if node.is_named() && (include_root || !is_root) {
                    match visit(node)? {
                        WalkControl::Continue => {}
                        WalkControl::SkipChildren => continue,
                        WalkControl::Break => return Ok(()),
                    }
                }
                stack.push(Frame::NextChild(node, 0));
            }
            Frame::NextChild(node, index) => {
                if index >= node.named_child_count() {
                    continue;
                }
                stack.push(Frame::NextChild(node, index + 1));
                if let Some(child) = node.named_child(index) {
                    stack.push(Frame::Enter(child, false));
                }
            }
        }
    }
    Ok(())
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
pub fn expanded_comment_start(source: &str, start_byte: usize) -> usize {
    assert!(start_byte <= source.len() && source.is_char_boundary(start_byte));

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

        if is_comment_like(trimmed) {
            comment_start = line_start;
            continue;
        }

        if let Some(offset) = first_comment_offset(line) {
            comment_start = line_start + offset;
        }
        break;
    }

    comment_start
}

fn is_comment_like(trimmed_line: &str) -> bool {
    trimmed_line.starts_with("/**")
        || trimmed_line.starts_with("/*")
        || trimmed_line.starts_with("*/")
        || trimmed_line.starts_with('*')
        || trimmed_line.starts_with("//")
        || trimmed_line.strip_prefix('#').is_some_and(|rest| {
            rest.is_empty() || rest.chars().next().is_some_and(char::is_whitespace)
        })
        || trimmed_line.starts_with("#[")
}

fn first_comment_offset(line: &str) -> Option<usize> {
    ["/**", "/*", "//", "#["]
        .into_iter()
        .filter_map(|marker| line.find(marker))
        .chain(line.find("# "))
        .min()
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
