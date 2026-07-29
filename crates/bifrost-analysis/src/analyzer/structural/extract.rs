//! Fact extraction: parse one file and normalize it through a language spec.
//!
//! The tree is parsed from the in-memory source, walked iteratively (explicit
//! stack, per the repo's no-recursive-tree-walk rule), and dropped before
//! returning — only the flat fact arena survives, mirroring how the usage
//! inverted-edge builders treat their per-file trees.

use super::facts::{FileFacts, NormalizedNode};
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
/// Returns `None` when the source is empty or the parser cannot be
/// constructed; parse *errors* still yield facts for the recoverable parts of
/// the tree (tree-sitter trees are total).
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
    if source.is_empty() {
        return LimitedFileFacts::Unavailable;
    }
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
    for (node, fact_id) in fact_sources {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return LimitedFileFacts::Cancelled;
        }
        debug_assert_eq!(fact_id as usize, roles.rows());
        let kind = nodes[fact_id as usize].kind;
        let mut sink = RoleSink::new(
            &fact_by_ts_node,
            roles.values_mut(),
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

    let line_starts = compute_line_starts(source);
    LimitedFileFacts::Complete(FileFacts::new(
        source.to_string(),
        line_starts,
        nodes,
        roles.finish(),
    ))
}
