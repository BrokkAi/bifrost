use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::HashSet;
use tree_sitter::{Node, Tree};

/// The identifier nodes in one static Python value path, from root to leaf.
///
/// Dynamic receivers and subscripts have no static path. Keeping the nodes
/// lets callers combine the parser shape with lexical/import binding facts
/// without reparsing a dotted source spelling.
pub fn python_static_attribute_path<'tree>(mut node: Node<'tree>) -> Option<Vec<Node<'tree>>> {
    if !matches!(node.kind(), "identifier" | "attribute") {
        return None;
    }
    let mut path = Vec::new();
    loop {
        match node.kind() {
            "identifier" => {
                path.push(node);
                break;
            }
            "attribute" => {
                let attribute = node.child_by_field_name("attribute")?;
                if attribute.kind() != "identifier" {
                    return None;
                }
                path.push(attribute);
                node = node.child_by_field_name("object")?;
            }
            _ => return None,
        }
    }
    path.reverse();
    Some(path)
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
                let attribute = node.child_by_field_name("attribute")?;
                if attribute.kind() != "identifier" {
                    return None;
                }
                path.push(attribute);
                node = node.child_by_field_name("object")?;
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

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    brokk_bifrost_core::analyzer::common::node_source_text(node, source)
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
    let mut expression = decorator.named_child(0)?;
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
