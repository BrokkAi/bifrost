use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::analyzer::common::node_source_text as node_text;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::HashSet;
use tree_sitter::{Node, Tree};

/// The operands of a Python conditional expression (`value if test else
/// alternative`).
///
/// The grammar leaves `conditional_expression` without fields, so its operands
/// can only be selected positionally. Skipping extras is required: a backslash
/// line continuation before `else` otherwise appears as a fourth named child
/// and trips the operand-count check (#4797).
pub(crate) fn python_conditional_expression_operands(node: Node<'_>) -> Option<[Node<'_>; 3]> {
    assert_eq!(node.kind(), "conditional_expression");
    let mut cursor = node.walk();
    let operands: Vec<Node<'_>> = node
        .named_children(&mut cursor)
        .filter(|child| !child.is_extra())
        .collect();
    operands.try_into().ok()
}

pub(crate) fn python_parameter_name(node: Node<'_>, source: &str) -> Option<String> {
    python_parameter_name_bounded(node, source, || true)
        .expect("unbounded parameter name lookup completes")
}

pub(crate) fn python_parameter_name_bounded(
    node: Node<'_>,
    source: &str,
    scope_step: impl FnMut() -> bool,
) -> Option<Option<String>> {
    python_parameter_node_bounded(node, scope_step).map(|node| {
        node.and_then(|node| {
            let name = node_text(node, source).trim();
            (!name.is_empty()).then(|| name.to_owned())
        })
    })
}

/// The exact binder token, shared by signature and native lexical production.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn python_parameter_node(node: Node<'_>) -> Option<Node<'_>> {
    python_parameter_node_bounded(node, || true).expect("unbounded parameter token lookup")
}

fn python_parameter_node_bounded(
    mut node: Node<'_>,
    mut scope_step: impl FnMut() -> bool,
) -> Option<Option<Node<'_>>> {
    loop {
        if !scope_step() {
            return None;
        }
        match node.kind() {
            "identifier" => return Some((!node.is_missing()).then_some(node)),
            "typed_parameter"
            | "typed_default_parameter"
            | "default_parameter"
            | "list_splat_pattern"
            | "dictionary_splat_pattern" => {
                if let Some(name) = node.child_by_field_name("name") {
                    node = name;
                    continue;
                }
                let mut selected = None;
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if !scope_step() {
                        return None;
                    }
                    if matches!(
                        child.kind(),
                        "identifier" | "list_splat_pattern" | "dictionary_splat_pattern"
                    ) {
                        selected = Some(child);
                        break;
                    }
                }
                let Some(name) = selected else {
                    return Some(None);
                };
                node = name;
            }
            _ => return Some(None),
        }
    }
}

pub fn leftmost_identifier(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "identifier" => return Some(node),
            "attribute" => node = node.child_by_field_name("object")?,
            _ => return None,
        }
    }
}

pub(crate) fn attribute_chain<'tree>(node: Node<'tree>) -> Option<(Node<'tree>, Vec<Node<'tree>>)> {
    let mut attributes = Vec::new();
    let mut current = node;
    loop {
        if current.kind() != "attribute" {
            return None;
        }
        attributes.push(current.child_by_field_name("attribute")?);
        current = current.child_by_field_name("object")?;
        if current.kind() == "identifier" {
            attributes.reverse();
            return Some((current, attributes));
        }
    }
}

pub fn python_reference_is_deferred_function_body(node: Node<'_>) -> bool {
    python_reference_is_deferred_function_body_bounded(node, || true)
        .expect("unbounded deferred-context lookup completes")
}

/// Body containment under the caller's sticky traversal budget.
pub fn python_reference_is_deferred_function_body_bounded(
    node: Node<'_>,
    mut scope_step: impl FnMut() -> bool,
) -> Option<bool> {
    let site_start = node.start_byte();
    let site_end = node.end_byte();
    let mut current = node;
    while let Some(parent) = current.parent() {
        if !scope_step() {
            return None;
        }
        if matches!(parent.kind(), "function_definition" | "lambda")
            && parent
                .child_by_field_name("body")
                .is_some_and(|body| body.start_byte() <= site_start && site_end <= body.end_byte())
        {
            return Some(true);
        }
        current = parent;
    }
    Some(false)
}

/// The identifier nodes in one static Python value path, from root to leaf.
///
/// Dynamic receivers and subscripts have no static path. Keeping the nodes
/// lets callers combine the parser shape with lexical/import binding facts
/// without reparsing a dotted source spelling.
pub fn python_static_attribute_path<'tree>(node: Node<'tree>) -> Option<Vec<Node<'tree>>> {
    python_static_value_path_with(node, || true, |_| None)
        .expect("unbounded static path lookup completes")
}

/// The strict static attribute path proof, charging traversal and reversal.
/// Parentheses remain outside this API's admitted grammar.
pub fn python_static_attribute_path_bounded<'tree>(
    node: Node<'tree>,
    scope_step: impl FnMut() -> bool,
) -> Option<Vec<Node<'tree>>> {
    python_static_value_path_with(node, scope_step, |_| None).flatten()
}

/// A metered static value path, including transparent parentheses. The outer
/// `None` means exhaustion; `Some(None)` means the receiver is not static.
pub fn python_static_value_path_bounded<'tree>(
    node: Node<'tree>,
    scope_step: impl FnMut() -> bool,
) -> Option<Option<Vec<Node<'tree>>>> {
    python_static_value_path_with(
        node,
        scope_step,
        crate::structural::python_parenthesized_expression_child,
    )
}

fn python_static_value_path_with<'tree>(
    mut node: Node<'tree>,
    mut scope_step: impl FnMut() -> bool,
    mut parenthesized_child: impl FnMut(Node<'tree>) -> Option<Node<'tree>>,
) -> Option<Option<Vec<Node<'tree>>>> {
    let mut path = Vec::new();
    loop {
        if !scope_step() {
            return None;
        }
        match node.kind() {
            "identifier" => {
                path.push(node);
                break;
            }
            "attribute" => {
                let Some(object) = push_static_attribute_segment(node, &mut path) else {
                    return Some(None);
                };
                node = object;
            }
            "parenthesized_expression" => {
                // The shared grammar helper skips comments. Charge all of its
                // immediate inputs before it inspects them.
                for _ in brokk_bifrost_core::analyzer::tree_walk::named_children_iter(node) {
                    if !scope_step() {
                        return None;
                    }
                }
                let Some(child) = parenthesized_child(node) else {
                    return Some(None);
                };
                node = child;
            }
            _ => return Some(None),
        }
    }
    for _ in 0..path.len() {
        if !scope_step() {
            return None;
        }
    }
    path.reverse();
    Some(Some(path))
}

/// The identifier nodes in one static Python annotation name, root to leaf.
/// Wrappers and generic arguments are ignored while the named generic origin
/// remains part of the path.
pub fn python_static_type_path<'tree>(mut node: Node<'tree>) -> Option<Vec<Node<'tree>>> {
    let mut path = Vec::new();
    loop {
        match node.kind() {
            "identifier" => {
                path.push(node);
                break;
            }
            "type" | "generic_type" | "subscript" => node = node.named_child(0)?,
            "attribute" => {
                node = push_static_attribute_segment(node, &mut path)?;
            }
            "member_type" => {
                let mut cursor = node.walk();
                let mut children = node.named_children(&mut cursor);
                let qualifier = children.next()?;
                let member = children.next()?;
                if member.kind() != "identifier" || children.next().is_some() {
                    return None;
                }
                path.push(member);
                node = qualifier;
            }
            _ => return None,
        }
    }
    path.reverse();
    Some(path)
}

fn push_static_attribute_segment<'tree>(
    node: Node<'tree>,
    path: &mut Vec<Node<'tree>>,
) -> Option<Node<'tree>> {
    let attribute = node.child_by_field_name("attribute")?;
    if attribute.kind() != "identifier" {
        return None;
    }
    path.push(attribute);
    node.child_by_field_name("object")
}

/// The text one plain string literal denotes.
///
/// Prefixed strings, interpolations, escapes, implicit concatenations, and
/// malformed shapes return `None`. The returned slice is always the exact
/// `string_content` AST span, never text recovered by delimiter parsing.
pub fn python_plain_string_literal<'source>(
    node: Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    if node.kind() != "string"
        || node
            .parent()
            .is_some_and(|parent| parent.kind() == "concatenated_string")
    {
        return None;
    }
    let mut content = None;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "string_start" | "string_end" => {
                let delimiter = child.utf8_text(source.as_bytes()).ok()?;
                if delimiter
                    .chars()
                    .any(|character| character != '"' && character != '\'')
                {
                    return None;
                }
            }
            "string_content" if child.named_child_count() == 0 && content.is_none() => {
                content = Some(child);
            }
            _ => return None,
        }
    }
    Some(content.map_or("", |child| {
        child
            .utf8_text(source.as_bytes())
            .expect("a tree-sitter node range is valid UTF-8 source")
    }))
}

#[derive(Debug, Default)]
pub struct PythonOverloadDecoratorBindings {
    direct: HashSet<String>,
    namespaces: HashSet<String>,
}

#[derive(Debug)]
pub(crate) enum PythonOverloadDecoratorName {
    Direct(String),
    Namespace(String),
}

impl PythonOverloadDecoratorBindings {
    /// Capture typing bindings from the import interpretation already owned by
    /// the primary producer. Only module-level leaves reach this collector.
    pub(crate) fn collect_import(
        &mut self,
        import: &brokk_bifrost_core::analyzer::model::ImportInfo,
    ) {
        use brokk_bifrost_core::analyzer::model::StructuredImportPathKind;
        let Some(path) = &import.path else { return };
        match (path.kind, path.segments.as_slice()) {
            (Some(StructuredImportPathKind::Namespace), [module]) if is_typing_module(module) => {
                self.namespaces
                    .insert(import.alias.as_ref().unwrap_or(module).clone());
            }
            (Some(StructuredImportPathKind::ImportFrom), [module, name])
                if is_typing_module(module) && name == "overload" =>
            {
                self.direct
                    .insert(import.alias.as_ref().unwrap_or(name).clone());
            }
            _ => {}
        }
    }

    /// Return the exact decorator binding shapes used by one function. The
    /// names are captured during the primary walk; the import binding set is
    /// resolved after the walk so a later typing import is handled exactly as
    /// the historical whole-file predicate did.
    pub(crate) fn overload_decorator_names(
        function: Node<'_>,
        source: &str,
    ) -> Vec<PythonOverloadDecoratorName> {
        let Some(parent) = function
            .parent()
            .filter(|node| node.kind() == "decorated_definition")
        else {
            return Vec::new();
        };
        let mut cursor = parent.walk();
        parent
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "decorator")
            .filter_map(decorator_callee)
            .filter_map(|callee| match callee.kind() {
                "identifier" => Some(PythonOverloadDecoratorName::Direct(
                    node_text(callee, source).trim().to_string(),
                )),
                "attribute" => {
                    let attribute = callee.child_by_field_name("attribute")?;
                    if node_text(attribute, source).trim() != "overload" {
                        return None;
                    }
                    let object = callee.child_by_field_name("object")?;
                    (object.kind() == "identifier").then(|| {
                        PythonOverloadDecoratorName::Namespace(
                            node_text(object, source).trim().to_string(),
                        )
                    })
                }
                _ => None,
            })
            .collect()
    }

    pub(crate) fn matches_overload_binding(&self, name: &PythonOverloadDecoratorName) -> bool {
        match name {
            PythonOverloadDecoratorName::Direct(name) => self.direct.contains(name),
            PythonOverloadDecoratorName::Namespace(name) => self.namespaces.contains(name),
        }
    }
}

fn is_typing_module(module: &str) -> bool {
    matches!(module, "typing" | "typing_extensions")
}

/// Return the name-bearing node of a Python expression using tree-sitter fields.
pub fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression;
    loop {
        match current.kind() {
            "identifier" => return Some(current),
            "attribute" => current = current.child_by_field_name("attribute")?,
            "call" => current = current.child_by_field_name("function")?,
            _ => return None,
        }
    }
}

/// Whether `node` is the label of a keyword argument: the `x` in `f(x=1)`.
///
/// The label names a parameter or member at the CALLEE, selected by the call's
/// target, not by anything bound where the label is written. That is why the
/// occurrence-role adapter in `structural.rs` classifies it `LabelOrKey`, whose
/// occurrence class is `NonReference`, and it is the rule the reference census
/// reads to decide that the label is not a forward-reference probe (#2054).
pub fn python_keyword_argument_label(node: Node<'_>) -> bool {
    node.kind() == "identifier"
        && node.parent().is_some_and(|parent| {
            parent.kind() == "keyword_argument" && parent.child_by_field_name("name") == Some(node)
        })
}

/// Return a decorator's callable expression, peeling an optional invocation.
pub fn decorator_callee<'tree>(decorator: Node<'tree>) -> Option<Node<'tree>> {
    if decorator.kind() != "decorator" {
        return None;
    }
    // The grammar can interleave a `line_continuation` extra before the
    // decorated expression; skip extras so `@\`-continued names resolve.
    let mut cursor = decorator.walk();
    let mut expression = decorator
        .named_children(&mut cursor)
        .find(|child| !child.is_extra())?;
    while expression.kind() == "call" {
        expression = expression.child_by_field_name("function")?;
    }
    Some(expression)
}

/// Whether `node` is contained by a parser field that Python evaluates as an
/// annotation rather than as an ordinary expression.
pub fn python_node_is_in_annotation(node: Node<'_>) -> bool {
    let start = node.start_byte();
    let end = node.end_byte();
    let mut current = node;
    while let Some(parent) = current.parent() {
        let annotation = match parent.kind() {
            "function_definition" => parent.child_by_field_name("return_type"),
            "typed_parameter" | "typed_default_parameter" | "assignment" => {
                parent.child_by_field_name("type")
            }
            _ => None,
        };
        if let Some(annotation) = annotation
            && annotation.start_byte() <= start
            && end <= annotation.end_byte()
        {
            return true;
        }
        current = parent;
    }
    false
}

/// Parse one exactly mapped deferred annotation and return its identifier ranges.
pub fn python_deferred_annotation_identifier_ranges(
    string: Node<'_>,
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Option<Vec<Range>> {
    let tree = python_deferred_annotation_tree(string, source, cancellation)?;

    let mut ranges = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(current) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return None;
        }
        if current.kind() == "identifier" {
            ranges.push(Range {
                start_byte: current.start_byte(),
                end_byte: current.end_byte(),
                start_line: current.start_position().row + 1,
                end_line: current.end_position().row + 1,
            });
        }
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
    Some(ranges)
}

/// Parse one quoted annotation expression while preserving its original source
/// byte coordinates. Literal string values and arbitrary strings are rejected
/// by the same structured gate used by inverse membership.
pub fn python_deferred_annotation_tree(
    string: Node<'_>,
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Option<Tree> {
    if string.kind() != "string"
        || string
            .parent()
            .is_some_and(|parent| parent.kind() == "concatenated_string")
        || !python_node_is_in_annotation(string)
        || python_string_is_literal_value(string, source)
    {
        return None;
    }

    let mut content = None;
    for index in 0..string.named_child_count() {
        let child = string.named_child(index)?;
        match child.kind() {
            "string_start" | "string_end" => {}
            "string_content" if content.is_none() => content = Some(child),
            _ => return None,
        }
    }
    let content = content?;
    let language = tree_sitter_python::LANGUAGE.into();
    let tree = brokk_bifrost_core::analyzer::common::parse_source_range_with_cancellation(
        &language,
        source,
        content.range(),
        cancellation,
    )?;
    if tree.root_node().has_error() {
        return None;
    }
    Some(tree)
}

/// Whether `string` is a value argument of `Literal[...]`, rather than a
/// deferred type expression merely because the whole subscript is an
/// annotation.
fn python_string_is_literal_value(string: Node<'_>, source: &str) -> bool {
    let start = string.start_byte();
    let end = string.end_byte();
    let mut current = string;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "subscript" => {
                let Some(value) = parent.child_by_field_name("value") else {
                    return false;
                };
                if value.start_byte() <= start && end <= value.end_byte() {
                    return false;
                }
                return python_literal_annotation_base(value, source);
            }
            "generic_type" => {
                let Some(value) = parent.named_child(0) else {
                    return false;
                };
                return python_literal_annotation_base(value, source);
            }
            _ => current = parent,
        }
    }
    false
}

fn python_literal_annotation_base(value: Node<'_>, source: &str) -> bool {
    match value.kind() {
        "identifier" => node_text(value, source) == "Literal",
        "attribute" => {
            let (Some(object), Some(attribute)) = (
                value.child_by_field_name("object"),
                value.child_by_field_name("attribute"),
            ) else {
                return false;
            };
            object.kind() == "identifier"
                && matches!(node_text(object, source), "typing" | "typing_extensions")
                && attribute.kind() == "identifier"
                && node_text(attribute, source) == "Literal"
        }
        "member_type" => {
            let mut identifiers = Vec::new();
            let mut stack = vec![value];
            while let Some(node) = stack.pop() {
                if node.kind() == "identifier" {
                    identifiers.push(node_text(node, source));
                    continue;
                }
                for index in (0..node.named_child_count()).rev() {
                    if let Some(child) = node.named_child(index) {
                        stack.push(child);
                    }
                }
            }
            matches!(
                identifiers.as_slice(),
                ["typing", "Literal"] | ["typing_extensions", "Literal"]
            )
        }
        _ => false,
    }
}

/// A structurally selected subtree mentioning the module export identifier.
/// Used by both legacy recovery and native export-operation classification.
pub(crate) fn python_contains_all_identifier(node: Node<'_>, source: &str) -> bool {
    use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
    let mut found = false;
    walk_named_tree_preorder(node, true, |node| {
        if node.kind() == "identifier" && &source[node.byte_range()] == "__all__" {
            found = true;
            WalkControl::Break
        } else {
            WalkControl::Continue
        }
    });
    found
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn qs6_python_syntax_field_boundary() {
        use super::*;
        for (source, expected) in [
            ("sys.argv[1]", Some("sys.argv")),
            ("obj.member[key]", Some("obj.member")),
            ("obj.nested.member[key]", None),
            ("values[key]", None),
            ("obj.member", None),
        ] {
            let tree = crate::declarations::parse_python_tree(source).unwrap();
            assert!(!tree.root_node().has_error());
            let expression = tree
                .root_node()
                .named_child(0)
                .unwrap()
                .named_child(0)
                .unwrap();
            let seed = crate::runtime_values::python_runtime_keyed_access_seed(expression);
            assert_eq!(seed.map(|node| &source[node.byte_range()]), expected);
            if let Some(seed) = seed {
                assert_eq!(seed.kind(), "attribute");
                assert_eq!(
                    expression.child_by_field_name("value").unwrap().id(),
                    seed.id()
                );
                assert_eq!(seed.child_by_field_name("object").unwrap().start_byte(), 0);
                assert_eq!(seed.start_byte(), 0);
                assert_eq!(seed.end_byte(), expected.unwrap().len());
            }
        }
        for (annotation, names) in [
            ("pkg.Type", vec!["pkg", "Type"]),
            ("pkg.Outer.Inner[int]", vec!["pkg", "Outer", "Inner"]),
            ("Outer[T].Inner", vec!["Outer", "Inner"]),
        ] {
            let source = format!("def f() -> {annotation}: pass\n");
            let tree = crate::declarations::parse_python_tree(&source).unwrap();
            assert!(!tree.root_node().has_error());
            let annotation_node = tree
                .root_node()
                .named_child(0)
                .unwrap()
                .child_by_field_name("return_type")
                .unwrap();
            let path = python_static_type_path(annotation_node).unwrap();
            assert_eq!(
                path.iter()
                    .map(|node| &source[node.byte_range()])
                    .collect::<Vec<_>>(),
                names
            );
            for node in path {
                assert_eq!(node.kind(), "identifier");
                assert!(node.start_byte() >= annotation_node.start_byte());
                assert!(node.end_byte() <= annotation_node.end_byte());
            }
        }
        let source = "@factory()()\ndef f(): pass\n";
        let tree = crate::declarations::parse_python_tree(source).unwrap();
        let decorator = tree
            .root_node()
            .named_child(0)
            .unwrap()
            .named_child(0)
            .unwrap();
        assert_eq!(decorator.kind(), "decorator");
        let call = decorator.named_child(0).unwrap();
        assert_eq!(call.kind(), "call");
        assert_eq!(call.child_by_field_name("function").unwrap().kind(), "call");
        let callee = decorator_callee(decorator).unwrap();
        assert_eq!(callee.kind(), "identifier");
        assert_eq!(callee.byte_range(), 1..8);
        assert_eq!(&source[callee.byte_range()], "factory");
    }

    #[test]
    fn qs6_deferred_annotation_live_token_ranges() {
        use super::*;
        let source = "# \u{e9}\ndef f(x: \"pkg.Type[Other]\") -> \"Result\": pass\nordinary = \"text\"\ny: Literal[\"value\"]\n";
        let tree = crate::declarations::parse_python_tree(source).unwrap();
        assert!(!tree.root_node().has_error());
        let fresh = CancellationToken::new();
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let mut pending = vec![tree.root_node()];
        let mut strings = Vec::new();
        while let Some(node) = pending.pop() {
            if node.kind() == "string" {
                strings.push(node);
            }
            for index in (0..node.named_child_count()).rev() {
                pending.push(node.named_child(index).unwrap());
            }
        }
        assert_eq!(strings.len(), 4);
        let mut names = Vec::new();
        for string in strings {
            let no_token = python_deferred_annotation_identifier_ranges(string, source, None);
            assert_eq!(
                python_deferred_annotation_identifier_ranges(string, source, Some(&fresh)),
                no_token
            );
            assert!(
                python_deferred_annotation_identifier_ranges(string, source, Some(&cancelled))
                    .is_none()
            );
            if let Some(ranges) = no_token {
                for range in ranges {
                    assert!(range.start_byte > string.start_byte());
                    assert!(range.end_byte < string.end_byte());
                    assert_eq!(range.start_line, 2);
                    assert_eq!(range.end_line, 2);
                    names.push(&source[range.start_byte..range.end_byte]);
                }
            }
        }
        assert_eq!(names, ["pkg", "Type", "Other", "Result"]);
    }

    #[test]
    #[hardwon("#5044: commented parentheses must preserve import identity and budget exhaustion")]
    fn static_paths_keep_parentheses_comments_and_exhaustion_distinct() {
        let source = "(  # receiver\n    module).function\n";
        let tree = crate::declarations::parse_python_tree(source).unwrap();
        let expression = tree
            .root_node()
            .named_child(0)
            .unwrap()
            .named_child(0)
            .unwrap();
        // Preserve the producer-facing helper's existing admission contract.
        assert!(super::python_static_attribute_path(expression).is_none());
        assert!(super::python_static_value_path_bounded(expression, || false).is_none());
        let path = super::python_static_value_path_bounded(expression, || true)
            .unwrap()
            .unwrap();
        assert_eq!(
            path.iter()
                .map(|node| node.utf8_text(source.as_bytes()).unwrap())
                .collect::<Vec<_>>(),
            ["module", "function"]
        );
        let dynamic = crate::declarations::parse_python_tree("factory().function\n").unwrap();
        let expression = dynamic
            .root_node()
            .named_child(0)
            .unwrap()
            .named_child(0)
            .unwrap();
        assert!(matches!(
            super::python_static_value_path_bounded(expression, || true),
            Some(None)
        ));
    }
}
