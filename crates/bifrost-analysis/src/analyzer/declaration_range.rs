use std::sync::{Arc, OnceLock};

use tree_sitter::{Node, Tree};

use crate::analyzer::common::{
    language_for_file, language_for_target, source_identifier_for_target,
};
use crate::analyzer::languages::LanguageSupport;
use crate::analyzer::tree_walk::node_for_exact_range;
use crate::analyzer::usages::get_definition::parse_tree_for_language;
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, Range};
use crate::text_utils::compute_line_starts;

pub struct DeclarationNameRangeContext {
    content: Arc<str>,
    line_starts: OnceLock<Vec<usize>>,
    tree: Option<Tree>,
}

impl DeclarationNameRangeContext {
    pub fn new(file: &ProjectFile, content: String) -> Self {
        let language = language_for_file(file);
        let content = Arc::<str>::from(content);
        let tree = parse_tree_for_language(file, language, content.as_ref());
        Self {
            content,
            line_starts: OnceLock::new(),
            tree,
        }
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub fn line_starts(&self) -> &[usize] {
        self.line_starts
            .get_or_init(|| compute_line_starts(self.content.as_ref()))
    }

    pub fn shared_content(&self) -> Arc<str> {
        Arc::clone(&self.content)
    }

    pub fn root_node(&self) -> Option<Node<'_>> {
        self.tree.as_ref().map(Tree::root_node)
    }

    pub fn name_range(&self, analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> Option<Range> {
        self.name_ranges(analyzer, code_unit).into_iter().next()
    }

    pub fn name_range_for_declaration(
        &self,
        code_unit: &CodeUnit,
        declaration_range: Range,
    ) -> Option<Range> {
        let root = self.root_node()?;
        code_unit_declaration_name_range_for_range(
            &self.content,
            root,
            code_unit,
            declaration_range,
        )
    }

    pub fn name_ranges(&self, analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> Vec<Range> {
        self.name_ranges_from_ranges(analyzer.ranges_of(code_unit), code_unit)
    }

    pub fn location_name_ranges(
        &self,
        analyzer: &dyn IAnalyzer,
        code_unit: &CodeUnit,
    ) -> Vec<Range> {
        self.name_ranges_from_ranges(analyzer.location_ranges(code_unit), code_unit)
    }

    fn name_ranges_from_ranges(
        &self,
        declaration_ranges: Vec<Range>,
        code_unit: &CodeUnit,
    ) -> Vec<Range> {
        let Some(root) = self.root_node() else {
            return Vec::new();
        };
        code_unit_declaration_name_ranges_in_tree(
            &self.content,
            root,
            code_unit,
            declaration_ranges,
        )
    }
}

pub fn code_unit_declaration_name_range(
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
    code_unit_declaration_name_ranges_in_tree(
        content,
        root,
        code_unit,
        analyzer.ranges_of(code_unit),
    )
    .into_iter()
    .next()
}

fn code_unit_declaration_name_ranges_in_tree(
    content: &str,
    root: Node<'_>,
    code_unit: &CodeUnit,
    mut declaration_ranges: Vec<Range>,
) -> Vec<Range> {
    declaration_ranges.sort_unstable();
    declaration_ranges.dedup();

    declaration_ranges
        .into_iter()
        .filter_map(|declaration_range| {
            code_unit_declaration_name_range_for_range(content, root, code_unit, declaration_range)
        })
        .collect()
}

pub(crate) fn code_unit_declaration_name_range_for_range(
    content: &str,
    root: Node<'_>,
    code_unit: &CodeUnit,
    declaration_range: Range,
) -> Option<Range> {
    let identifier = declaration_source_identifier(code_unit);
    let support = crate::analyzer::languages::language_support(language_for_target(code_unit));
    let name_node = node_for_exact_range(root, &declaration_range)
        .or_else(|| node_for_smallest_containing_range(root, &declaration_range))
        .and_then(|declaration_node| {
            declaration_name_node(declaration_node, identifier, content, support)
        })
        .or_else(|| {
            // Persisted ranges can have byte offsets from a different line
            // ending representation than the current source. Line spans are
            // stable across LF and CRLF, so use the current AST to recover the
            // declaration name when byte containment cannot do so.
            declaration_name_node_for_line_range(
                root,
                &declaration_range,
                identifier,
                content,
                support,
            )
        })?;
    Some(support.map_or_else(
        || node_byte_range(name_node),
        |support| support.declaration_name_range(name_node, content),
    ))
}

/// TypeScript uses a `$static` suffix in its internal member names to keep
/// static and instance members distinct. That suffix is not part of the
/// declaration token in source, which is what this module selects.
fn declaration_source_identifier(code_unit: &CodeUnit) -> &str {
    source_identifier_for_target(code_unit)
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

fn declaration_name_node_for_line_range<'tree>(
    root: Node<'tree>,
    range: &Range,
    identifier: &str,
    content: &str,
    support: Option<&'static dyn crate::analyzer::languages::LanguageSupport>,
) -> Option<Node<'tree>> {
    let mut best: Option<(usize, usize, usize, Node<'tree>)> = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if let Some(name_node) =
            declaration_name_node_from_fields(node, identifier, content, support)
        {
            let line_distance = declaration_line_distance(node, range);
            let span = node.end_byte().saturating_sub(node.start_byte());
            let start_byte = node.start_byte();
            let candidate = (line_distance, span, start_byte, name_node);
            if best.is_none_or(|current| {
                (candidate.0, candidate.1, candidate.2) < (current.0, current.1, current.2)
            }) {
                best = Some(candidate);
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    best.map(|(_, _, _, name_node)| name_node)
}

fn declaration_line_distance(node: Node<'_>, range: &Range) -> usize {
    let start = node.start_position().row;
    let end = node.end_position().row;
    [
        line_interval_distance(start, end, range.start_line, range.end_line),
        line_interval_distance(start + 1, end + 1, range.start_line, range.end_line),
    ]
    .into_iter()
    .min()
    .expect("line distance candidates are non-empty")
}

fn line_interval_distance(
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
) -> usize {
    if left_end < right_start {
        right_start.saturating_sub(left_end)
    } else if right_end < left_start {
        left_start.saturating_sub(right_end)
    } else {
        0
    }
}

fn declaration_name_node_from_fields<'tree>(
    declaration_node: Node<'tree>,
    identifier: &str,
    content: &str,
    support: Option<&'static dyn LanguageSupport>,
) -> Option<Node<'tree>> {
    let mut stack = vec![declaration_node];
    while let Some(node) = stack.pop() {
        for field in ["name", "left", "pattern"] {
            if let Some(binding) = node.child_by_field_name(field)
                && let Some(identifier_node) =
                    matching_identifier_node(binding, identifier, content, support)
            {
                return Some(identifier_node);
            }
        }
        for field in ["declarator", "declaration", "definition"] {
            if let Some(child) = node.child_by_field_name(field) {
                stack.push(child);
            }
        }
        // Some grammars wrap an assignment declaration in a fieldless
        // statement node. Descend through that unambiguous wrapper so the
        // assignment's structured `left` field wins over text matching.
        if node.named_child_count() == 1
            && let Some(child) = node.named_child(0)
        {
            stack.push(child);
        }
    }
    None
}

fn declaration_name_node<'tree>(
    declaration_node: Node<'tree>,
    identifier: &str,
    content: &str,
    support: Option<&'static dyn LanguageSupport>,
) -> Option<Node<'tree>> {
    declaration_name_node_from_fields(declaration_node, identifier, content, support)
        .or_else(|| matching_identifier_node(declaration_node, identifier, content, support))
}

fn matching_identifier_node<'tree>(
    root: Node<'tree>,
    identifier: &str,
    content: &str,
    support: Option<&'static dyn LanguageSupport>,
) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if support
            .and_then(|support| support.symbol_literal_name(node, content))
            .as_deref()
            == Some(identifier)
        {
            return Some(node);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::get_definition::parse_tree_for_language;
    use crate::analyzer::{Language, ProjectFile};

    fn first_node_of_kind<'tree>(root: Node<'tree>, kind: &str) -> Node<'tree> {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == kind {
                return node;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        panic!("missing {kind} node");
    }

    #[test]
    fn repeated_assignment_name_uses_structured_binding_target() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let cases = [
            (
                Language::Python,
                "value.py",
                "x = x\n",
                "expression_statement",
            ),
            (
                Language::Scala,
                "Value.scala",
                "val x = x\n",
                "val_definition",
            ),
            (Language::Ruby, "value.rb", "X = X\n", "assignment"),
        ];

        for (language, path, source, declaration_kind) in cases {
            let file = ProjectFile::new(&root, path);
            let tree = parse_tree_for_language(&file, language, source)
                .unwrap_or_else(|| panic!("failed to parse {language:?}"));
            let declaration = first_node_of_kind(tree.root_node(), declaration_kind);
            let identifier = if language == Language::Ruby { "X" } else { "x" };
            let support = crate::analyzer::languages::language_support(language);
            let name = declaration_name_node(declaration, identifier, source, support)
                .unwrap_or_else(|| panic!("missing declaration name for {language:?}"));

            assert_eq!(name.start_byte(), source.find(identifier).unwrap());
        }
    }

    #[test]
    fn declaration_name_recovers_when_persisted_bytes_use_lf() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(&root, "A.java");
        let lf_source =
            "public class A {\n    String method2() {\n        return \"ok\";\n    }\n}\n";
        let source = lf_source.replace('\n', "\r\n");
        let tree = parse_tree_for_language(&file, Language::Java, &source).expect("java tree");
        let unit = CodeUnit::new(file, crate::analyzer::CodeUnitType::Function, "", "method2");
        let start_byte = lf_source.find("String method2").expect("method start");
        let end_byte = lf_source.find("}\n}\n").expect("method end") + 2;
        let name = code_unit_declaration_name_range_for_range(
            &source,
            tree.root_node(),
            &unit,
            Range {
                // Model a persisted range whose byte offsets no longer fit
                // the current source representation.
                start_byte: source.len() + start_byte,
                end_byte: source.len() + end_byte,
                start_line: 2,
                end_line: 4,
            },
        )
        .expect("declaration name");

        assert_eq!(&source[name.start_byte..name.end_byte], "method2");
    }
}
