use std::sync::{Arc, OnceLock};

use tree_sitter::{Node, Tree};

use crate::analyzer::common::{
    language_for_file, language_for_target, source_identifier_for_target,
};
use crate::analyzer::languages::LanguageSupport;
use crate::analyzer::tree_walk::{node_for_exact_range, push_named_children_reversed};
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

    /// `name_range_for_declaration` for many declarations of this file in one
    /// pass. Locating one declaration walks each node's child list on the way
    /// down, which is linear in the file's widest node per declaration: on a
    /// single-header amalgamation (simdjson.h, one `namespace` with tens of
    /// thousands of children) 2,386 search hits cost 188 s that way. Here the
    /// requests are sorted by start byte and partitioned down the tree
    /// together, so every child list on the way is read once for all the
    /// requests it contains, and each declaration's search starts at its
    /// deepest containing node.
    pub fn name_ranges_for_declarations(
        &self,
        requests: &[(&CodeUnit, Range)],
    ) -> Vec<Option<Range>> {
        let Some(root) = self.root_node() else {
            return vec![None; requests.len()];
        };
        let mut order: Vec<usize> = (0..requests.len()).collect();
        order.sort_by_key(|&index| {
            let range = &requests[index].1;
            (range.start_byte, range.end_byte)
        });
        let mut answers = vec![None; requests.len()];
        let mut answer = |index: usize, scope: Node<'_>| {
            let (code_unit, range) = requests[index];
            answers[index] = code_unit_declaration_name_range_scoped(
                &self.content,
                root,
                scope,
                code_unit,
                range,
            );
        };
        // (node, lo, hi): the requests order[lo..hi] all lie within `node`.
        let mut stack: Vec<(Node<'_>, usize, usize)> = vec![(root, 0, order.len())];
        let mut cursor = root.walk();
        while let Some((node, lo, hi)) = stack.pop() {
            let mut next = lo;
            cursor.reset(node);
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if child.is_named() {
                        // Children are disjoint and in source order and the
                        // requests are sorted by start, so the requests a
                        // child contains are one contiguous run, and a request
                        // starting before the child that no earlier child
                        // contained belongs to `node` itself.
                        while next < hi && requests[order[next]].1.start_byte < child.start_byte() {
                            answer(order[next], node);
                            next += 1;
                        }
                        let first = next;
                        while next < hi && requests[order[next]].1.end_byte <= child.end_byte() {
                            next += 1;
                        }
                        if next > first {
                            stack.push((child, first, next));
                        }
                        // A request starting inside the child but running past
                        // it is contained by no child.
                        while next < hi && requests[order[next]].1.start_byte < child.end_byte() {
                            answer(order[next], node);
                            next += 1;
                        }
                        if next >= hi {
                            break;
                        }
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
            while next < hi {
                answer(order[next], node);
                next += 1;
            }
        }
        answers
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
    code_unit_declaration_name_range_scoped(content, root, root, code_unit, declaration_range)
}

/// [`code_unit_declaration_name_range_for_range`] with the declaration's
/// search started at `scope`: the root's child containing
/// `declaration_range` when the caller located one, else the root itself
/// (a persisted range can also lie outside the tree, e.g. after a line-ending
/// change, and then only the line-based fallback can answer). That fallback
/// still searches from the root: a declaration's lines can run past the scope.
fn code_unit_declaration_name_range_scoped<'tree>(
    content: &str,
    root: Node<'tree>,
    scope: Node<'tree>,
    code_unit: &CodeUnit,
    declaration_range: Range,
) -> Option<Range> {
    let identifier = declaration_source_identifier(code_unit);
    let support = crate::analyzer::languages::language_support(language_for_target(code_unit));
    let name_node = node_for_exact_range(scope, &declaration_range)
        .or_else(|| node_for_smallest_containing_range(scope, &declaration_range))
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

/// The declaration a persisted `range` names, located by the lines it carries
/// rather than by its byte offsets.
///
/// The search is bounded to the nodes that span those lines, which is the case
/// this recovery exists for: the offsets come from another representation of
/// the same text, where a line span survives and a byte offset does not. The
/// bound is exact, because a node's line interval contains every descendant's,
/// so a subtree that misses the range holds nothing that meets it. Reading the
/// whole file instead answered with whatever token elsewhere in it happened to
/// share the name, and cost a walk of every named node per request: 113 s of a
/// 204 s `search_symbols` query over the 7.7 MB amalgamated `simdjson.h`, whose
/// unparsed region holds no candidate at all, so nothing bounded that walk and
/// every request paid for the whole file (#3214).
fn declaration_name_node_for_line_range<'tree>(
    root: Node<'tree>,
    range: &Range,
    identifier: &str,
    content: &str,
    support: Option<&'static dyn crate::analyzer::languages::LanguageSupport>,
) -> Option<Node<'tree>> {
    if !node_lines_meet_range(root, range) {
        return None;
    }
    // Ranked structural before spelling, then span and start. A structural
    // answer -- the language's positional reader naming the node -- identifies
    // the declaration the stale range belonged to, while a spelling answer only
    // says some token inside the range shares the name. The distinction decides
    // when the true name token cannot compete as a spelling candidate on its
    // own: the anonymous `default` keyword of `export default ...` is invisible
    // to the named-node walk, so every in-body `{ default: x }` key shares the
    // statement's lines and would win on span (#2733).
    let mut best: Option<(bool, usize, usize, Node<'tree>)> = None;
    let mut stack = vec![root];
    // One cursor for the whole descent. `Node::walk` allocates, so a cursor per
    // visited node was a malloc per node (#3097).
    let mut cursor = root.walk();
    while let Some(node) = stack.pop() {
        if let Some((name_node, structural)) =
            declaration_name_node_from_fields(node, identifier, content, support)
        {
            let span = node.end_byte().saturating_sub(node.start_byte());
            let candidate = (structural, span, node.start_byte(), name_node);
            if best.is_none_or(|current| {
                (!candidate.0, candidate.1, candidate.2) < (!current.0, current.1, current.2)
            }) {
                best = Some(candidate);
            }
        }
        cursor.reset(node);
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                // Children are in source order, so once one starts past the
                // range's last line no later sibling meets the range either.
                if child.start_position().row > range.end_line {
                    break;
                }
                if child.is_named() && node_lines_meet_range(child, range) {
                    stack.push(child);
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    best.map(|(_, _, _, name_node)| name_node)
}

/// Whether `node` spans a line of `range`, under either line convention.
/// Declaration ranges number lines from one and tree-sitter rows from zero, and
/// a persisted range can carry either, so a node one line ahead still meets it.
fn node_lines_meet_range(node: Node<'_>, range: &Range) -> bool {
    let start = node.start_position().row;
    let end = node.end_position().row;
    line_intervals_meet(start, end, range.start_line, range.end_line)
        || line_intervals_meet(start + 1, end + 1, range.start_line, range.end_line)
}

fn line_intervals_meet(
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
) -> bool {
    left_start <= right_end && right_start <= left_end
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
    // `child_by_field_name` resolves the field id by comparing the name against
    // the grammar's field table on every call, and this walk asks six of them
    // per node. The ids are fixed for the grammar, so settle them once (#3097).
    let language = declaration_node.language();
    let name_fields = ["name", "left", "pattern"].map(|field| language.field_id_for_name(field));
    let descend_fields =
        ["declarator", "declaration", "definition"].map(|field| language.field_id_for_name(field));

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
        for field in name_fields.iter().flatten() {
            if let Some(binding) = node.child_by_field_id(field.get())
                && let Some(identifier_node) =
                    matching_identifier_node(binding, identifier, content, support)
            {
                return Some((identifier_node, false));
            }
        }
        for field in descend_fields.iter().flatten() {
            if let Some(child) = node.child_by_field_id(field.get()) {
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
        push_named_children_reversed(node, &mut stack);
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

    /// #3214: the line recovery exists for a persisted range whose byte offsets
    /// came from another representation of the same text, where the line span
    /// still identifies the declaration. Lines that hold no candidate identify
    /// nothing, and must answer nothing rather than the nearest token elsewhere
    /// in the file that shares the name, which is what the whole-file walk
    /// answered with for hits inside `simdjson.h`'s unparsed region.
    #[test]
    fn declaration_name_ignores_candidates_off_the_persisted_lines() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(&root, "document.cpp");
        let source = "class Document {\n  int size;\n};\n\nint main() {\n  return 0;\n}\n";
        let tree = parse_tree_for_language(&file, Language::Cpp, source).expect("cpp tree");
        let unit = CodeUnit::new(file, crate::analyzer::CodeUnitType::Class, "", "Document");
        // Byte offsets past the end of the current source, as a range persisted
        // from a different line-ending representation carries.
        let stale_bytes = (source.len(), source.len() + 3);

        let recovered = code_unit_declaration_name_range_for_range(
            source,
            tree.root_node(),
            &unit,
            Range {
                start_byte: stale_bytes.0,
                end_byte: stale_bytes.1,
                start_line: 1,
                end_line: 3,
            },
        )
        .expect("declaration name from line range");
        assert_eq!(
            &source[recovered.start_byte..recovered.end_byte],
            "Document"
        );

        let off_the_declaration = code_unit_declaration_name_range_for_range(
            source,
            tree.root_node(),
            &unit,
            Range {
                start_byte: stale_bytes.0,
                end_byte: stale_bytes.1,
                start_line: 6,
                end_line: 7,
            },
        );
        assert_eq!(
            off_the_declaration, None,
            "lines holding no declaration of this name must not answer with one elsewhere"
        );
    }

    /// #3214: the recovery walked every named node of the file for each request
    /// that reached it. One `search_symbols` query over the 7.7 MB amalgamated
    /// `simdjson.h` spent 113 s that way, because the region its hits live in
    /// holds no candidate at all and so nothing bounded the walk.
    #[test]
    fn line_recovery_cost_does_not_scale_with_the_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(&root, "amalgamated.cpp");
        let mut source = String::new();
        for index in 0..8_000 {
            source.push_str(&format!(
                "int filler_{index}(int value) {{ return value; }}\n"
            ));
        }
        let context = DeclarationNameRangeContext::new(&file, source.clone());
        let unit = CodeUnit::new(file, crate::analyzer::CodeUnitType::Class, "", "Document");
        let requests: Vec<(&CodeUnit, Range)> = (0..100)
            .map(|index| {
                (
                    &unit,
                    Range {
                        start_byte: source.len() + index,
                        end_byte: source.len() + index + 4,
                        start_line: index * 70 + 1,
                        end_line: index * 70 + 1,
                    },
                )
            })
            .collect();

        let started = std::time::Instant::now();
        let answers = context.name_ranges_for_declarations(&requests);
        let elapsed = started.elapsed();

        assert!(
            answers.iter().all(Option::is_none),
            "no filler declaration names Document: {answers:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "line recovery over {} requests took {elapsed:?}; expected a walk bounded to each request's lines",
            requests.len()
        );
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
