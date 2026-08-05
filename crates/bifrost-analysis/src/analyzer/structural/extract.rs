//! Fact extraction: parse one file and normalize it through a language spec.
//!
//! The tree is parsed from the in-memory source, walked iteratively (explicit
//! stack, per the repo's no-recursive-tree-walk rule), and dropped before
//! returning — only the flat fact arena survives, mirroring how the usage
//! inverted-edge builders treat their per-file trees.

use super::facts::{FileFacts, NormalizedNode};
use super::occurrences::OccurrenceRole;
use super::spec::{CompiledKinds, RoleSink, RoleSinkStop, StructuralSpec};
use crate::cancellation::CancellationToken;
use crate::compact_graph::CompactRowsBuilder;
use crate::hash::HashMap;
use crate::text_utils::compute_line_starts;
use tree_sitter::{Language as TsLanguage, Node, ParseOptions, Parser};

#[derive(Debug)]
pub(crate) enum LimitedFileFacts {
    Complete(FileFacts),
    Exceeded { minimum_fact_nodes: usize },
    Cancelled,
    Unavailable,
}

fn node_range(node: Node<'_>) -> crate::analyzer::Range {
    crate::analyzer::Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    }
}

/// Parse `source` with `grammar` and extract normalized facts through `spec`.
/// Returns `None` only when the parser cannot be constructed; an empty source
/// yields an empty fact set (#1459), and parse *errors* still yield facts for
/// the recoverable parts of the tree (tree-sitter trees are total).
pub(crate) fn extract_file_facts(
    spec: &dyn StructuralSpec,
    grammar: &TsLanguage,
    source: &str,
) -> Option<FileFacts> {
    match extract_file_facts_limited(spec, grammar, source, usize::MAX, None) {
        LimitedFileFacts::Complete(facts) => Some(facts),
        LimitedFileFacts::Exceeded { .. }
        | LimitedFileFacts::Cancelled
        | LimitedFileFacts::Unavailable => None,
    }
}

/// Extract normalized facts while refusing to materialize more than
/// `max_fact_nodes` normalized nodes plus semantic role edges. The source-byte
/// admission gate remains the bound on parser and raw-syntax work; this
/// function makes both normalized arenas cancellable and bounded before
/// allocation can run past the shared CodeQuery budget.
pub(crate) fn extract_file_facts_limited(
    spec: &dyn StructuralSpec,
    grammar: &TsLanguage,
    source: &str,
    max_fact_nodes: usize,
    cancellation: Option<&CancellationToken>,
) -> LimitedFileFacts {
    // An empty source is a legitimate file with zero facts (empty __init__.py
    // and placeholder .ts fixtures are real workspace members). Rejecting it
    // as Unavailable made one empty file abort the whole provider index and
    // demote its language slice to scan mode for the session (#1459); the
    // general extraction path below handles it as an empty tree.
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return LimitedFileFacts::Cancelled;
    }
    if max_fact_nodes == 0 {
        return LimitedFileFacts::Exceeded {
            minimum_fact_nodes: 1,
        };
    }
    let mut parser = Parser::new();
    if parser.set_language(grammar).is_err() {
        return LimitedFileFacts::Unavailable;
    }
    let tree = if let Some(cancellation) = cancellation {
        let mut read = |offset: usize, _| &source.as_bytes()[offset..];
        let mut progress = |_: &tree_sitter::ParseState| cancellation.is_cancelled();
        parser.parse_with_options(
            &mut read,
            None,
            Some(ParseOptions::new().progress_callback(&mut progress)),
        )
    } else {
        parser.parse(source, None)
    };
    let Some(tree) = tree else {
        return if cancellation.is_some_and(CancellationToken::is_cancelled) {
            LimitedFileFacts::Cancelled
        } else {
            LimitedFileFacts::Unavailable
        };
    };
    let compiled = CompiledKinds::compile(grammar, spec.kind_table());

    // Pass 1: create facts in pre-order with parent links, and remember which
    // tree-sitter node produced each fact so pass 2 can resolve role targets.
    let mut nodes: Vec<NormalizedNode> = Vec::new();
    let mut fact_by_ts_node: HashMap<usize, u32> = HashMap::default();
    let mut fact_sources: Vec<(Node<'_>, u32)> = Vec::new();

    enum ExtractionFrame<'tree> {
        Enter(Node<'tree>, Option<u32>),
        NextChild(Node<'tree>, Option<u32>, usize),
    }

    let mut stack = vec![ExtractionFrame::Enter(tree.root_node(), None)];
    while let Some(frame) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return LimitedFileFacts::Cancelled;
        }
        match frame {
            ExtractionFrame::Enter(node, enclosing) => {
                let mut parent_for_children = enclosing;
                if node.is_named()
                    && let Some(kind) = compiled.kind_of(&node)
                    && spec.should_extract(node, kind)
                {
                    if nodes.len() == max_fact_nodes {
                        return LimitedFileFacts::Exceeded {
                            minimum_fact_nodes: max_fact_nodes.saturating_add(1),
                        };
                    }
                    let kind = spec.refine_kind(
                        node,
                        kind,
                        enclosing.map(|id| nodes[id as usize].kind),
                        source,
                    );
                    let fact_id = nodes.len() as u32;
                    nodes.push(NormalizedNode {
                        kind,
                        construct: spec.generator_construct(node, kind).map(str::to_owned),
                        range: node_range(node),
                        parent: enclosing,
                        name: None,
                        subtree_end: fact_id + 1,
                    });
                    fact_by_ts_node.insert(node.id(), fact_id);
                    fact_sources.push((node, fact_id));
                    parent_for_children = Some(fact_id);
                }
                stack.push(ExtractionFrame::NextChild(node, parent_for_children, 0));
            }
            ExtractionFrame::NextChild(node, enclosing, index) => {
                if index >= node.named_child_count() {
                    continue;
                }
                stack.push(ExtractionFrame::NextChild(node, enclosing, index + 1));
                if let Some(child) = node.named_child(index) {
                    stack.push(ExtractionFrame::Enter(child, enclosing));
                }
            }
        }
    }

    for fact_id in (0..nodes.len()).rev() {
        if let Some(parent) = nodes[fact_id].parent {
            let subtree_end = nodes[fact_id].subtree_end;
            let parent = &mut nodes[parent as usize];
            parent.subtree_end = parent.subtree_end.max(subtree_end);
        }
    }

    // Pass 2: role extraction, now that every normalized node has a fact id.
    // Nodes and roles share one admission limit because both are durable facts
    // scanned by later CodeQuery steps.
    let max_roles = max_fact_nodes.saturating_sub(nodes.len());
    let mut roles = CompactRowsBuilder::with_capacity(nodes.len(), 0);
    // Occurrence roles are addressed by the classified node, which is not
    // necessarily the fact currently being extracted, so they are gathered flat
    // and bucketed below. They are bounded by the node arena rather than by
    // `max_roles`: an adapter classifies nodes, never synthesizes them.
    let mut occurrence_roles: Vec<(u32, OccurrenceRole)> = Vec::new();
    for (node, fact_id) in fact_sources {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return LimitedFileFacts::Cancelled;
        }
        debug_assert_eq!(fact_id as usize, roles.rows());
        let kind = nodes[fact_id as usize].kind;
        let mut sink = RoleSink::new(
            &fact_by_ts_node,
            roles.values_mut(),
            &mut occurrence_roles,
            max_roles,
            cancellation,
        );
        spec.extract(node, kind, &mut sink);
        let (name, stop) = sink.into_parts();
        match stop {
            Some(RoleSinkStop::Exceeded) => {
                return LimitedFileFacts::Exceeded {
                    minimum_fact_nodes: max_fact_nodes.saturating_add(1),
                };
            }
            Some(RoleSinkStop::Cancelled) => return LimitedFileFacts::Cancelled,
            None => {}
        }
        nodes[fact_id as usize].name = name;
        roles.finish_row();
    }

    // Bucket the flat classifications into one row per node. Adapters classify
    // a node from its own extraction call in the common case, so this is
    // already sorted and the sort is near-free; a parent classifying a child is
    // equally admissible and lands in the right row either way.
    occurrence_roles.sort_unstable();
    occurrence_roles.dedup();
    let mut occurrence_rows =
        CompactRowsBuilder::with_capacity(nodes.len(), occurrence_roles.len());
    let mut next = 0usize;
    for fact_id in 0..nodes.len() as u32 {
        while occurrence_roles
            .get(next)
            .is_some_and(|&(node, _)| node == fact_id)
        {
            occurrence_rows.values_mut().push(occurrence_roles[next].1);
            next += 1;
        }
        occurrence_rows.finish_row();
    }
    debug_assert_eq!(next, occurrence_roles.len());

    let line_starts = compute_line_starts(source);
    LimitedFileFacts::Complete(FileFacts::new(
        source.to_string(),
        line_starts,
        nodes,
        roles.finish(),
        occurrence_rows.finish(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #1459: an empty file is a legitimate workspace member with zero facts
    /// (empty `__init__.py`, placeholder `.ts` fixtures). It must extract as
    /// an empty fact set, not `Unavailable` -- the all-or-nothing index build
    /// aborts the whole provider slice on any unavailable file.
    #[test]
    fn empty_source_extracts_zero_facts() {
        let spec = &crate::analyzer::python::structural::PYTHON_STRUCTURAL_SPEC;
        let grammar = tree_sitter_python::LANGUAGE.into();
        let facts = extract_file_facts(spec, &grammar, "").expect("empty source yields facts");
        assert_eq!(facts.work_item_count(), 0);
        assert_eq!(facts.source(), "");
        let payload = facts
            .encode_snapshot()
            .expect("empty facts round-trip through the snapshot codec");
        let decoded =
            FileFacts::decode_snapshot(String::new(), &payload).expect("empty snapshot decodes");
        assert_eq!(decoded.work_item_count(), 0);
    }

    /// An adapter that declares no occurrence roles must emit none: a table and
    /// an extraction pass that disagree would turn "we cannot classify this"
    /// into a clean, empty, and wrong answer (#1473).
    #[test]
    fn adapters_declaring_no_occurrence_roles_emit_none() {
        let spec = &crate::analyzer::scala::structural::SCALA_STRUCTURAL_SPEC;
        assert!(spec.occurrence_role_support().is_empty());

        let grammar = tree_sitter_scala::LANGUAGE.into();
        let source = "class Widget(label: String) {\n  def render(): String = label\n}\n";
        let facts =
            extract_file_facts(spec, &grammar, source).expect("scala fixture extracts facts");
        assert!(facts.nodes().len() > 1, "fixture should produce facts");
        assert_eq!(facts.occurrence_role_count(), 0);
    }

    /// Occurrence roles survive the snapshot codec with their node addressing
    /// intact, which is the property the `(content identity, fact id)` join in
    /// later milestones depends on.
    #[test]
    fn extracted_occurrence_roles_round_trip_through_the_snapshot_codec() {
        let spec = &crate::analyzer::python::structural::PYTHON_STRUCTURAL_SPEC;
        let grammar = tree_sitter_python::LANGUAGE.into();
        let source = "def render(label):\n    return label\n";
        let facts = extract_file_facts(spec, &grammar, source).expect("python fixture extracts");
        assert!(facts.occurrence_role_count() > 0);

        let payload = facts.encode_snapshot().expect("facts encode");
        let decoded =
            FileFacts::decode_snapshot(source.to_owned(), &payload).expect("facts decode");
        for id in 0..facts.nodes().len() as u32 {
            assert_eq!(decoded.occurrence_roles(id), facts.occurrence_roles(id));
        }
    }
}
