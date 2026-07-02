//! Fact extraction: parse one file and normalize it through a language spec.
//!
//! The tree is parsed from the in-memory source, walked iteratively (explicit
//! stack, per the repo's no-recursive-tree-walk rule), and dropped before
//! returning — only the flat fact arena survives, mirroring how the usage
//! inverted-edge builders treat their per-file trees.

use super::facts::{FileFacts, NormalizedNode};
use super::spec::{CompiledKinds, RoleSink, StructuralSpec};
use crate::hash::HashMap;
use crate::text_utils::compute_line_starts;
use tree_sitter::{Language as TsLanguage, Node, Parser};

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
    if source.is_empty() {
        return None;
    }
    let mut parser = Parser::new();
    parser.set_language(grammar).ok()?;
    let tree = parser.parse(source, None)?;
    let compiled = CompiledKinds::compile(grammar, spec.kind_table());

    // Pass 1: create facts in pre-order with parent links, and remember which
    // tree-sitter node produced each fact so pass 2 can resolve role targets.
    let mut nodes: Vec<NormalizedNode> = Vec::new();
    let mut fact_by_ts_node: HashMap<usize, u32> = HashMap::default();
    let mut fact_sources: Vec<(Node<'_>, u32)> = Vec::new();

    let mut stack: Vec<(Node<'_>, Option<u32>)> = vec![(tree.root_node(), None)];
    while let Some((node, enclosing)) = stack.pop() {
        let mut parent_for_children = enclosing;
        if node.is_named()
            && let Some(kind) = compiled.kind_of(&node)
        {
            let kind = spec.refine_kind(node, kind, enclosing.map(|id| nodes[id as usize].kind));
            let fact_id = nodes.len() as u32;
            nodes.push(NormalizedNode {
                kind,
                range: node_range(node),
                parent: enclosing,
                name: None,
                roles: Vec::new(),
            });
            fact_by_ts_node.insert(node.id(), fact_id);
            fact_sources.push((node, fact_id));
            parent_for_children = Some(fact_id);
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push((child, parent_for_children));
            }
        }
    }

    // Pass 2: role extraction, now that every normalized node has a fact id.
    for (node, fact_id) in fact_sources {
        let kind = nodes[fact_id as usize].kind;
        let mut sink = RoleSink::new(&fact_by_ts_node);
        spec.extract(node, kind, &mut sink);
        let (name, roles) = sink.into_parts();
        let fact = &mut nodes[fact_id as usize];
        fact.name = name;
        fact.roles = roles;
    }

    let line_starts = compute_line_starts(source);
    Some(FileFacts::new(source.to_string(), line_starts, nodes))
}
