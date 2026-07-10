use std::sync::Arc;

use tree_sitter::{Node, Tree};

use crate::analyzer::common::language_for_file;
use crate::analyzer::usages::get_definition::parse_tree_for_language;
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, Range};

pub(crate) struct DeclarationNameRangeContext {
    content: Arc<String>,
    tree: Option<Tree>,
}

impl DeclarationNameRangeContext {
    pub(crate) fn new(file: &ProjectFile, content: String) -> Self {
        let language = language_for_file(file);
        let content = Arc::new(content);
        let tree = parse_tree_for_language(file, language, content.as_str());
        Self { content, tree }
    }

    pub(crate) fn content(&self) -> &str {
        &self.content
    }

    pub(crate) fn shared_content(&self) -> Arc<String> {
        Arc::clone(&self.content)
    }

    pub(crate) fn root_node(&self) -> Option<Node<'_>> {
        self.tree.as_ref().map(Tree::root_node)
    }

    pub(crate) fn name_range(
        &self,
        analyzer: &dyn IAnalyzer,
        code_unit: &CodeUnit,
    ) -> Option<Range> {
        self.name_ranges(analyzer, code_unit).into_iter().next()
    }

    pub(crate) fn name_ranges(&self, analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> Vec<Range> {
        let Some(root) = self.root_node() else {
            return Vec::new();
        };
        code_unit_declaration_name_ranges_in_tree(analyzer, &self.content, root, code_unit)
    }
}

pub(crate) fn code_unit_declaration_name_range(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    content: &str,
    code_unit: &CodeUnit,
) -> Option<Range> {
    let language = language_for_file(file);
    let tree = parse_tree_for_language(file, language, content)?;
    code_unit_declaration_name_range_in_tree(analyzer, content, tree.root_node(), code_unit)
}

fn code_unit_declaration_name_range_in_tree(
    analyzer: &dyn IAnalyzer,
    content: &str,
    root: Node<'_>,
    code_unit: &CodeUnit,
) -> Option<Range> {
    code_unit_declaration_name_ranges_in_tree(analyzer, content, root, code_unit)
        .into_iter()
        .next()
}

fn code_unit_declaration_name_ranges_in_tree(
    analyzer: &dyn IAnalyzer,
    content: &str,
    root: Node<'_>,
    code_unit: &CodeUnit,
) -> Vec<Range> {
    let mut declaration_ranges = analyzer.ranges(code_unit).to_vec();
    declaration_ranges.sort_unstable();
    declaration_ranges.dedup();

    declaration_ranges
        .into_iter()
        .filter_map(|declaration_range| {
            code_unit_declaration_name_range_for_range(content, root, code_unit, declaration_range)
        })
        .collect()
}

fn code_unit_declaration_name_range_for_range(
    content: &str,
    root: Node<'_>,
    code_unit: &CodeUnit,
    declaration_range: Range,
) -> Option<Range> {
    let declaration_node = node_for_exact_range(root, &declaration_range)
        .or_else(|| node_for_smallest_containing_range(root, &declaration_range))?;
    let name_node = declaration_name_node(declaration_node, code_unit.identifier(), content)?;
    Some(node_byte_range(name_node))
}

/// Find the node whose byte span exactly equals `range`. When several nested
/// nodes share that exact span, return the deepest one. The shallow wrapper
/// often carries no `name` field, so returning it would defeat declaration-name
/// resolution.
fn node_for_exact_range<'tree>(root: Node<'tree>, range: &Range) -> Option<Node<'tree>> {
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

fn node_for_smallest_containing_range<'tree>(
    root: Node<'tree>,
    range: &Range,
) -> Option<Node<'tree>> {
    let mut best: Option<Node<'tree>> = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() > range.start_byte || node.end_byte() < range.end_byte {
            continue;
        }
        if best.is_none_or(|current| {
            node.end_byte().saturating_sub(node.start_byte())
                < current.end_byte().saturating_sub(current.start_byte())
        }) {
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

fn declaration_name_node<'tree>(
    declaration_node: Node<'tree>,
    identifier: &str,
    content: &str,
) -> Option<Node<'tree>> {
    let mut stack = vec![declaration_node];
    while let Some(node) = stack.pop() {
        if let Some(name) = node.child_by_field_name("name")
            && let Some(identifier_node) = matching_identifier_node(name, identifier, content)
        {
            return Some(identifier_node);
        }
        for field in ["declarator", "declaration", "definition"] {
            if let Some(child) = node.child_by_field_name(field) {
                stack.push(child);
            }
        }
    }
    matching_identifier_node(declaration_node, identifier, content)
}

fn matching_identifier_node<'tree>(
    root: Node<'tree>,
    identifier: &str,
    content: &str,
) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.utf8_text(content.as_bytes()).ok()? == identifier {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    None
}

fn node_byte_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    }
}
