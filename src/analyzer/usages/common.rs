use crate::analyzer::common as analyzer_common;
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{CodeUnit, Language, ProjectFile};
use tree_sitter::Node;

/// Graph-strategy hits land at maximum confidence.
pub(super) const GRAPH_HIT_CONFIDENCE: f64 = 1.0;
/// Lines of context to include before/after a match in [`UsageHit::snippet`].
pub(super) const SNIPPET_CONTEXT_LINES: usize = 1;

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

/// Whether `left` and `right` are the same syntax node, by tree-sitter node
/// identity. Exact where a byte-range comparison can collide a unit/wrapper node
/// with its sole child (which share an identical span); both nodes must come from
/// the same tree for the ids to be comparable.
pub(super) fn same_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.id() == right.id()
}

/// The trimmed source text spanned by `node`, or `""` if the byte range is not a
/// valid `str` boundary. Shared by the per-language usage resolvers that key on a
/// node's identifier/type text.
pub(super) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
        .trim()
}

pub(super) enum TreeWalkAction {
    Descend,
    DescendWithExit,
    Skip,
}

pub(super) fn walk_tree_iterative<State>(
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
            },
            TreeWalkFrame::Exit => exit(state),
        }
    }
}

enum TreeWalkFrame<'tree> {
    Enter(Node<'tree>),
    Exit,
}

fn push_named_children<'tree>(node: Node<'tree>, stack: &mut Vec<TreeWalkFrame<'tree>>) {
    for index in (0..node.named_child_count()).rev() {
        if let Some(child) = node.named_child(index) {
            stack.push(TreeWalkFrame::Enter(child));
        }
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
