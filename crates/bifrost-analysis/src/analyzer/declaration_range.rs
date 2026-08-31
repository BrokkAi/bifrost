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
    // Ranked by line distance, then structural before spelling, then span and
    // start. A structural answer -- the language's positional reader naming the
    // node -- identifies the declaration the stale range belonged to, while a
    // spelling answer only says some token inside the range shares the name.
    // The distinction decides when the true name token cannot compete as a
    // spelling candidate on its own: the anonymous `default` keyword of
    // `export default ...` is invisible to the named-node walk, so every
    // in-body `{ default: x }` key ties the statement on line distance and
    // would win on span (#2733).
    let mut best: Option<(usize, bool, usize, usize, Node<'tree>)> = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if let Some((name_node, structural)) =
            declaration_name_node_from_fields(node, identifier, content, support)
        {
            let line_distance = declaration_line_distance(node, range);
            let span = node.end_byte().saturating_sub(node.start_byte());
            let start_byte = node.start_byte();
            let candidate = (line_distance, structural, span, start_byte, name_node);
            if best.is_none_or(|current| {
                (candidate.0, !candidate.1, candidate.2, candidate.3)
                    < (current.0, !current.1, current.2, current.3)
            }) {
                best = Some(candidate);
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    best.map(|(_, _, _, _, name_node)| name_node)
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

/// The node naming `identifier` inside `declaration_node`, paired with whether
/// the language's positional reader answered it (`true`) or a field binding or
/// leaf spelling did (`false`). The line-range fallback ranks structural
/// answers ahead of spelling coincidences; every other caller ignores the flag.
fn declaration_name_node_from_fields<'tree>(
    declaration_node: Node<'tree>,
    identifier: &str,
    content: &str,
    support: Option<&'static dyn LanguageSupport>,
) -> Option<(Node<'tree>, bool)> {
    let mut stack = vec![declaration_node];
    while let Some(node) = stack.pop() {
        // Some grammars name no declaration identifier by field at all, so the
        // language reads it positionally instead. Kotlin is one (#2712), and
        // the anonymous `default` keyword of a JS/TS `export default ...` is
        // another (#2733).
        if let Some(language_support) = support
            && let Some(name_node) = language_support.declaration_name_node(node)
            && node_names_identifier(name_node, identifier, content, support)
        {
            return Some((name_node, true));
        }
        // A declarator chain bottoms out at the declared name itself. C/C++
        // spell `void target(int)` as `function_definition.declarator ->
        // function_declarator.declarator -> identifier`, with no `name` field
        // anywhere on the way, so without this the chain runs out and the
        // caller falls back to a text search across the whole declaration --
        // which then answers with whatever occurrence of the name the body
        // happens to contain, such as a recursive call (#1638).
        if node.named_child_count() == 0
            && let Some(identifier_node) =
                matching_identifier_node(node, identifier, content, support)
        {
            return Some((identifier_node, false));
        }
        for field in ["name", "left", "pattern"] {
            if let Some(binding) = node.child_by_field_name(field)
                && let Some(identifier_node) =
                    matching_identifier_node(binding, identifier, content, support)
            {
                return Some((identifier_node, false));
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
        .map(|(name_node, _)| name_node)
        .or_else(|| matching_identifier_node(declaration_node, identifier, content, support))
}

/// Whether `node` is spelled exactly `identifier` at its declaration site.
fn node_names_identifier(
    node: Node<'_>,
    identifier: &str,
    content: &str,
    support: Option<&'static dyn LanguageSupport>,
) -> bool {
    if support
        .and_then(|support| support.symbol_literal_name(node, content))
        .as_deref()
        == Some(identifier)
    {
        return true;
    }
    node.utf8_text(content.as_bytes()).ok() == Some(identifier)
}

/// The first node spelled `identifier` in document order.
///
/// Document order is what makes this a usable best-effort: a declaration writes
/// its name before its body in every supported language, so the earliest
/// occurrence inside a declaration is its header token. Visiting children in
/// reverse instead answered with whatever the body happened to mention last,
/// such as the `offset` in `this.offset = n` inside `fun offset` (#2712).
fn matching_identifier_node<'tree>(
    root: Node<'tree>,
    identifier: &str,
    content: &str,
    support: Option<&'static dyn LanguageSupport>,
) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node_names_identifier(node, identifier, content, support) {
            return Some(node);
        }
        // Pushed in reverse so that `pop` yields the first child first.
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
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

    /// #2712: the Kotlin grammar names no declaration identifier by field, so
    /// name selection reaches the text search. A builder method whose body
    /// assigns the same-named property must still resolve to the header token.
    #[test]
    fn kotlin_function_name_is_not_hijacked_by_body_self_assignment() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(&root, "QueryBuilder.kt");
        // The blank line keeps the property off the function's neighbouring
        // line: the line-distance fallback tolerates a one-line skew, so an
        // adjacent same-named property would tie with the function and win on
        // span, which is a property of that ranking and not of name selection.
        let source = "class QueryBuilder {\n    var offset: Int = 0\n\n    fun offset(n: Int): QueryBuilder { this.offset = n; return this }\n}\n";
        let tree = parse_tree_for_language(&file, Language::Kotlin, source).expect("kotlin tree");
        let declaration = first_node_of_kind(tree.root_node(), "function_declaration");
        let unit = CodeUnit::new(file, crate::analyzer::CodeUnitType::Function, "", "offset");
        let expected_start = source.find("fun offset").expect("header") + "fun ".len();

        let exact = code_unit_declaration_name_range_for_range(
            source,
            tree.root_node(),
            &unit,
            node_byte_range(declaration),
        )
        .expect("declaration name");
        assert_eq!(exact.start_byte, expected_start);
        assert_eq!(&source[exact.start_byte..exact.end_byte], "offset");

        // A persisted range whose byte offsets no longer fit the current source
        // takes the line-distance fallback, which must agree.
        let shifted = code_unit_declaration_name_range_for_range(
            source,
            tree.root_node(),
            &unit,
            Range {
                start_byte: source.len() + declaration.start_byte(),
                end_byte: source.len() + declaration.end_byte(),
                start_line: declaration.start_position().row,
                end_line: declaration.end_position().row,
            },
        )
        .expect("declaration name from line range");
        assert_eq!(shifted.start_byte, expected_start);
    }

    /// The class header token wins over every same-named occurrence in the body.
    #[test]
    fn kotlin_class_name_is_not_hijacked_by_body_occurrences() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(&root, "Offset.kt");
        let source = "class Offset {\n    fun make(): Offset {\n        val x: Offset = Offset()\n        return x\n    }\n}\n";
        let tree = parse_tree_for_language(&file, Language::Kotlin, source).expect("kotlin tree");
        let declaration = first_node_of_kind(tree.root_node(), "class_declaration");
        let unit = CodeUnit::new(file, crate::analyzer::CodeUnitType::Class, "", "Offset");
        let expected_start = source.find("class Offset").expect("header") + "class ".len();

        let name = code_unit_declaration_name_range_for_range(
            source,
            tree.root_node(),
            &unit,
            node_byte_range(declaration),
        )
        .expect("declaration name");

        assert_eq!(name.start_byte, expected_start);
        assert_eq!(name.start_line, 0);
    }

    /// #2733: the `default` keyword of `export default ...` is an anonymous
    /// token in both tree-sitter-javascript and tree-sitter-typescript, so the
    /// named-children text search cannot see it. An anonymous default export
    /// whose body mentions `default` by name must still bind the keyword.
    #[test]
    fn js_anonymous_default_export_class_name_is_the_default_keyword() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(&root, "bar_chart.js");
        // Every named `default` shape from the report: a destructuring key, an
        // object key, and a member. Each sits on its own line so the binding
        // line identifies which token name selection answered with.
        let source = "export default class extends HTMLElement {\n    async connectedCallback() {\n        const { default: Chart } = await import('chart.js/auto');\n        this.chart = new Chart(this, { default: true });\n        this.chart.options.default = true;\n    }\n}\n";
        let tree = parse_tree_for_language(&file, Language::JavaScript, source).expect("js tree");
        let declaration = first_node_of_kind(tree.root_node(), "export_statement");
        let unit = CodeUnit::new(file, crate::analyzer::CodeUnitType::Class, "", "default");
        let expected_start = source.find("export default").expect("header") + "export ".len();

        let exact = code_unit_declaration_name_range_for_range(
            source,
            tree.root_node(),
            &unit,
            node_byte_range(declaration),
        )
        .expect("declaration name");
        assert_eq!(exact.start_byte, expected_start);
        assert_eq!(exact.start_line, 0);
        assert_eq!(&source[exact.start_byte..exact.end_byte], "default");

        // A persisted range whose byte offsets no longer fit the current source
        // takes the line-distance fallback, which must agree.
        let shifted = code_unit_declaration_name_range_for_range(
            source,
            tree.root_node(),
            &unit,
            Range {
                start_byte: source.len() + declaration.start_byte(),
                end_byte: source.len() + declaration.end_byte(),
                start_line: declaration.start_position().row,
                end_line: declaration.end_position().row,
            },
        )
        .expect("declaration name from line range");
        assert_eq!(shifted.start_byte, expected_start);
    }

    /// The function form, in TypeScript: same anonymous keyword, same hazard.
    #[test]
    fn ts_anonymous_default_export_function_name_is_the_default_keyword() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(&root, "render.ts");
        let source = "export default function () {\n    const { default: helper } = imports;\n    return helper;\n}\n";
        let tree = parse_tree_for_language(&file, Language::TypeScript, source).expect("ts tree");
        let declaration = first_node_of_kind(tree.root_node(), "export_statement");
        let unit = CodeUnit::new(file, crate::analyzer::CodeUnitType::Function, "", "default");
        let expected_start = source.find("export default").expect("header") + "export ".len();

        let name = code_unit_declaration_name_range_for_range(
            source,
            tree.root_node(),
            &unit,
            node_byte_range(declaration),
        )
        .expect("declaration name");

        assert_eq!(name.start_byte, expected_start);
        assert_eq!(name.start_line, 0);
    }

    /// `export default <expression>` gives the synthetic `default` field the
    /// whole statement as its declaration; the keyword still wins over an
    /// object key spelled `default` in the expression.
    #[test]
    fn js_default_export_expression_name_is_the_default_keyword() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(&root, "config.js");
        let source = "export default { default: 1 };\n";
        let tree = parse_tree_for_language(&file, Language::JavaScript, source).expect("js tree");
        let declaration = first_node_of_kind(tree.root_node(), "export_statement");
        let unit = CodeUnit::new(file, crate::analyzer::CodeUnitType::Field, "", "default");
        let expected_start = source.find("export default").expect("header") + "export ".len();

        let name = code_unit_declaration_name_range_for_range(
            source,
            tree.root_node(),
            &unit,
            node_byte_range(declaration),
        )
        .expect("declaration name");

        assert_eq!(name.start_byte, expected_start);
    }

    /// A named default export keeps its own name: the keyword is spelled
    /// `default`, not `chart`, so name selection must fall through to the
    /// declaration's `name` field even though the declaration range covers the
    /// whole `export_statement`.
    #[test]
    fn js_named_default_export_name_is_the_declaration_name() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(&root, "chart.js");
        let source = "export default function chart() {\n    return chart;\n}\n";
        let tree = parse_tree_for_language(&file, Language::JavaScript, source).expect("js tree");
        let declaration = first_node_of_kind(tree.root_node(), "export_statement");
        let unit = CodeUnit::new(file, crate::analyzer::CodeUnitType::Function, "", "chart");
        let expected_start = source.find("function chart").expect("header") + "function ".len();

        let name = code_unit_declaration_name_range_for_range(
            source,
            tree.root_node(),
            &unit,
            node_byte_range(declaration),
        )
        .expect("declaration name");

        assert_eq!(name.start_byte, expected_start);
        assert_eq!(&source[name.start_byte..name.end_byte], "chart");
    }

    /// Outside an `export_statement` nothing changes: a plain class keeps
    /// binding its `name` field.
    #[test]
    fn js_plain_class_name_is_unaffected_by_default_export_selection() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(&root, "widget.js");
        let source = "class Widget {\n    render() {\n        const { default: icon } = icons;\n        return icon;\n    }\n}\n";
        let tree = parse_tree_for_language(&file, Language::JavaScript, source).expect("js tree");
        let declaration = first_node_of_kind(tree.root_node(), "class_declaration");
        let unit = CodeUnit::new(file, crate::analyzer::CodeUnitType::Class, "", "Widget");
        let expected_start = source.find("class Widget").expect("header") + "class ".len();

        let name = code_unit_declaration_name_range_for_range(
            source,
            tree.root_node(),
            &unit,
            node_byte_range(declaration),
        )
        .expect("declaration name");

        assert_eq!(name.start_byte, expected_start);
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
