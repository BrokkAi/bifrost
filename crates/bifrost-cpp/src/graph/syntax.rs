use crate::declarations::node_text;
use crate::graph::resolver::{
    cpp_name_component_nodes, cpp_type_name_components, is_globally_qualified_cpp_name,
    is_nested_type_node, qualified_owner_components,
};
use brokk_bifrost_core::analyzer::tree_walk::push_named_children_reversed;
use std::ops::Range;
use tree_sitter::{Node, Parser};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacroReplacementTypeReference {
    pub components: Vec<String>,
    pub component_ranges: Vec<Range<usize>>,
    pub global: bool,
}

/// Whether an identifier is a callable declaration name retained beneath C++
/// error recovery.
///
/// A C prototype using the traditional `__P((...))` wrapper can be parsed as a
/// pointer declarator whose first child is `ERROR(identifier)` and whose
/// declarator is a function declarator for the macro invocation. The identifier
/// is still a real declaration reference to the callable's later definition,
/// even though the ordinary census intentionally excludes the whole ERROR
/// subtree. Keep this predicate limited to that declaration-shaped CST so
/// arbitrary recovery leaves do not enter inverse membership.
pub fn is_cpp_recovered_callable_declaration_reference(node: Node<'_>) -> bool {
    if !matches!(node.kind(), "identifier" | "field_identifier") {
        return false;
    }
    let Some(error) = node.parent().filter(|parent| parent.is_error()) else {
        return false;
    };
    let Some(pointer) = error.parent().filter(|parent| {
        parent.kind() == "pointer_declarator"
            && parent.named_child(0) == Some(error)
            && parent
                .child_by_field_name("declarator")
                .is_some_and(|declarator| declarator.kind() == "function_declarator")
    }) else {
        return false;
    };
    pointer.parent().is_some_and(|declaration| {
        declaration.kind() == "declaration"
            && declaration.child_by_field_name("declarator") == Some(pointer)
    })
}

/// One direct field declaration recovered from an object-like macro
/// replacement. The replacement is parsed as the body of a synthetic struct,
/// so the name and declaration text come from C/C++ grammar nodes rather than
/// from a textual macro expansion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacroReplacementField {
    pub name: String,
    pub declaration: String,
}

/// The structured content of one object-like field-list macro replacement:
/// the members it declares itself, and the names of the field-list macros it
/// composes in turn. Composition is kept as names rather than resolved here
/// because a nested name's active replacement is a property of the
/// preprocessor environment at the invocation, not of this replacement.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectMacroReplacement {
    pub fields: Vec<MacroReplacementField>,
    pub nested: Vec<String>,
}

impl ObjectMacroReplacement {
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.nested.is_empty()
    }

    /// The members and nested names both replacements declare identically.
    ///
    /// An include closure can carry mutually exclusive definitions of one
    /// field-list macro (libuv defines `UV_HANDLE_PRIVATE_FIELDS` in both
    /// `uv/unix.h` and `uv/win.h`). Whichever header the compilation actually
    /// took, every member in this intersection is present, and every member
    /// that depends on the branch is left unproven.
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            fields: self
                .fields
                .iter()
                .filter(|field| other.fields.contains(field))
                .cloned()
                .collect(),
            nested: self
                .nested
                .iter()
                .filter(|name| other.nested.contains(name))
                .cloned()
                .collect(),
        }
    }
}

/// Recover direct fields hidden in an object-like macro replacement.
///
/// A field-list macro is valid in more than one owner, so this helper returns
/// only the declaration-shaped children of the synthetic field list. Nested
/// aggregate promotion remains the owner's normal structured aggregate logic;
/// treating nested members as direct fields here would leak them across owners.
///
/// A replacement that ends in another field-list macro's name is reported as
/// composition rather than refused: the grammar has no member rule for a bare
/// identifier, so tree-sitter marks it as one `type_identifier` with a MISSING
/// `;`. Every other malformed region still refuses the whole replacement, so an
/// unsupported spelling stays unproven instead of donating partial members.
pub fn object_macro_replacement(replacement: &str) -> ObjectMacroReplacement {
    if replacement.trim().is_empty() {
        return ObjectMacroReplacement::default();
    }
    let normalized_replacement = normalize_macro_continuations(replacement);
    const PREFIX: &str = "struct __bifrost_macro_fields { ";
    let synthetic = format!("{PREFIX}{normalized_replacement} }};");
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .is_err()
    {
        return ObjectMacroReplacement::default();
    }
    let Some(tree) = parser.parse(&synthetic, None) else {
        return ObjectMacroReplacement::default();
    };
    let mut stack = vec![tree.root_node()];
    let body = loop {
        let Some(current) = stack.pop() else {
            return ObjectMacroReplacement::default();
        };
        if current.kind() == "struct_specifier"
            && let Some(body) = current.child_by_field_name("body")
        {
            break body;
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    };
    let mut recovered = ObjectMacroReplacement::default();
    let mut composed_terminators = Vec::new();
    let mut cursor = body.walk();
    for declaration in body.named_children(&mut cursor) {
        if !matches!(declaration.kind(), "declaration" | "field_declaration") {
            continue;
        }
        if let Some((name, terminator)) = nested_object_macro_invocation(declaration, &synthetic) {
            recovered.nested.push(name);
            composed_terminators.push(terminator.id());
            continue;
        }
        let Some(declarator) = declaration
            .child_by_field_name("declarator")
            .or_else(|| declaration.named_child(1))
        else {
            continue;
        };
        let Some(name) = macro_replacement_declarator_name(declarator, &synthetic) else {
            continue;
        };
        let Some(declaration_text) =
            declaration_text_without_synthetic_prefix(declaration, replacement, PREFIX.len())
        else {
            continue;
        };
        recovered.fields.push(MacroReplacementField {
            name,
            declaration: declaration_text,
        });
    }
    if !malformed_regions_are_composition(tree.root_node(), &composed_terminators) {
        return ObjectMacroReplacement::default();
    }
    recovered
}

/// The name a nested field-list macro invocation contributes, with the MISSING
/// `;` tree-sitter inserted for it. A member list holding only another macro's
/// name has no grammar rule, so the invocation reaches the tree as exactly one
/// `type_identifier` followed by that missing terminator.
fn nested_object_macro_invocation<'tree>(
    declaration: Node<'tree>,
    source: &str,
) -> Option<(String, Node<'tree>)> {
    if declaration.kind() != "field_declaration" {
        return None;
    }
    let mut cursor = declaration.walk();
    let children = declaration.children(&mut cursor).collect::<Vec<_>>();
    let [name, terminator] = children.as_slice() else {
        return None;
    };
    if name.kind() != "type_identifier" || terminator.kind() != ";" || !terminator.is_missing() {
        return None;
    }
    let text = node_text(*name, source).trim();
    (!text.is_empty()).then(|| (text.to_string(), *terminator))
}

/// Whether every malformed region of a reparsed replacement is one of the
/// MISSING terminators nested composition already accounts for. Any other
/// error means the replacement is not a structured member list, and the whole
/// replacement is refused rather than donating the members that did parse.
fn malformed_regions_are_composition(root: Node<'_>, composed_terminators: &[usize]) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !node.has_error() && !node.is_missing() {
            continue;
        }
        if (node.is_error() || node.is_missing()) && !composed_terminators.contains(&node.id()) {
            return false;
        }
        let mut cursor = node.walk();
        let children = node.children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children);
    }
    true
}

/// One member declaration recovered from an aggregate region tree-sitter could
/// not place. `range` is the member's own byte range in the original source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredAggregateField {
    pub name: String,
    pub declaration: String,
    pub range: Range<usize>,
}

/// Recover the direct members of an aggregate body region the ordinary parse
/// could not place.
///
/// An object-like field-list macro invocation inside a member list has no
/// grammar rule, so tree-sitter collapses the aggregate's head and body into
/// one `ERROR` container and the members after the invocation lose their
/// declaration shape. Reparsing the exact byte slice that follows the
/// invocation as a synthetic aggregate body restores that shape from the
/// grammar, and every returned range maps back to the original source.
pub fn recovered_aggregate_fields(
    source: &str,
    span: Range<usize>,
) -> Vec<RecoveredAggregateField> {
    let Some(region) = source.get(span.clone()) else {
        return Vec::new();
    };
    if region.trim().is_empty() {
        return Vec::new();
    }
    const PREFIX: &str = "struct __bifrost_recovered_members { ";
    let synthetic = format!("{PREFIX}{region} }};");
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(&synthetic, None) else {
        return Vec::new();
    };
    if tree.root_node().has_error() {
        return Vec::new();
    }
    let mut stack = vec![tree.root_node()];
    let body = loop {
        let Some(current) = stack.pop() else {
            return Vec::new();
        };
        if current.kind() == "struct_specifier"
            && let Some(body) = current.child_by_field_name("body")
        {
            break body;
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    };
    let mut fields = Vec::new();
    let mut cursor = body.walk();
    for declaration in body.named_children(&mut cursor) {
        if !matches!(declaration.kind(), "declaration" | "field_declaration") {
            continue;
        }
        let Some(declarator) = declaration
            .child_by_field_name("declarator")
            .or_else(|| declaration.named_child(1))
        else {
            continue;
        };
        let Some(name) = macro_replacement_declarator_name(declarator, &synthetic) else {
            continue;
        };
        let Some(declaration_text) =
            declaration_text_without_synthetic_prefix(declaration, region, PREFIX.len())
        else {
            continue;
        };
        let start = span.start + declaration.start_byte() - PREFIX.len();
        let end = span.start + declaration.end_byte() - PREFIX.len();
        fields.push(RecoveredAggregateField {
            name,
            declaration: declaration_text,
            range: start..end,
        });
    }
    fields
}

/// The complete replacement list of an object-like `#define`.
///
/// tree-sitter-cpp lexes a comment inside a replacement as an extra, which
/// ends the `preproc_arg` token and the `preproc_def` node with it: libuv's
/// `UV_HANDLE_FIELDS` reports `void* data;` as its whole replacement and loses
/// the eight members that follow the next comment. A replacement list is one
/// preprocessing logical line (C17 5.1.1.2), so its extent is the directive's
/// own line-continuation run, which the grammar's token boundaries do not
/// describe. The AST supplies the start; the returned slice is then parsed by
/// tree-sitter like any other replacement.
pub fn object_macro_replacement_span(node: Node<'_>, source: &str) -> Option<Range<usize>> {
    if node.kind() != "preproc_def" {
        return None;
    }
    let start = node.child_by_field_name("name")?.end_byte();
    (start <= source.len()).then(|| start..logical_line_end(start, source))
}

/// The complete logical-line replacement list of a function-like `#define`.
///
/// Comments are tokenized as extras by tree-sitter-cpp and can truncate the
/// `preproc_arg` value. Start immediately after the parameter list so a
/// replacement that begins with a comment remains source backed even when it
/// has no value node. Follow the preprocessing continuation run to recover the
/// bytes that belong to the replacement. The returned span includes the
/// original backslash/newline bytes so callers can retain source coordinates.
pub fn function_macro_replacement_span(node: Node<'_>, source: &str) -> Option<Range<usize>> {
    let parameters = match node.kind() {
        "preproc_function_def" => node.child_by_field_name("parameters"),
        "preproc_def" => {
            // A comment-truncated function macro can recover as an object
            // directive whose ERROR child still owns the parameter list.
            let mut stack = vec![node];
            let mut parameters = None;
            while let Some(part) = stack.pop() {
                if part.kind() == "preproc_params" {
                    parameters = Some(part);
                    break;
                }
                if part == node || part.is_error() {
                    push_named_children_reversed(part, &mut stack);
                }
            }
            parameters
        }
        _ => None,
    }?;
    let start = parameters.end_byte();
    (start <= source.len()).then(|| start..logical_line_end(start, source))
}

/// Return the end of the preprocessing logical line beginning at `start`.
/// A physical newline belongs to the replacement while it is preceded by a
/// continuation backslash (with an optional CR before the newline).
fn logical_line_end(start: usize, source: &str) -> usize {
    let bytes = source.as_bytes();
    let mut index = start;
    while index < bytes.len() {
        if bytes[index] != b'\n' {
            index += 1;
            continue;
        }
        let mut previous = index;
        if previous > start && bytes[previous - 1] == b'\r' {
            previous -= 1;
        }
        if previous > start && bytes[previous - 1] == b'\\' {
            index += 1;
            continue;
        }
        break;
    }
    index
}

/// Keep preprocessor line continuations as byte-preserving whitespace before
/// reparsing an opaque replacement. The parser's replacement node includes
/// the backslash/newline pair, while C's preprocessing phase treats it as one
/// logical line. Replacing both bytes (and CRLF's three bytes) keeps every
/// tree-sitter byte range mapped directly to the original replacement.
pub(crate) fn normalize_macro_continuations(replacement: &str) -> String {
    let source = replacement.as_bytes();
    let mut normalized = source.to_vec();
    let mut index = 0;
    while index + 1 < source.len() {
        if source[index] == b'\\' && source[index + 1] == b'\n' {
            normalized[index] = b' ';
            normalized[index + 1] = b' ';
            index += 2;
        } else if index + 2 < source.len()
            && source[index] == b'\\'
            && source[index + 1] == b'\r'
            && source[index + 2] == b'\n'
        {
            normalized[index] = b' ';
            normalized[index + 1] = b' ';
            normalized[index + 2] = b' ';
            index += 3;
        } else {
            index += 1;
        }
    }
    String::from_utf8(normalized).expect("source text must remain valid UTF-8")
}

fn macro_replacement_declarator_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" | "type_identifier" | "qualified_identifier" => {
            let name = node_text(node, source).trim();
            (!name.is_empty()).then(|| name.to_string())
        }
        "function_declarator" => None,
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .and_then(|child| macro_replacement_declarator_name(child, source)),
    }
}

fn declaration_text_without_synthetic_prefix(
    node: Node<'_>,
    source: &str,
    prefix_len: usize,
) -> Option<String> {
    let start = node.start_byte().checked_sub(prefix_len)?;
    let end = node.end_byte().checked_sub(prefix_len)?;
    (end <= source.len()).then(|| source[start..end].to_string())
}

/// Recover type-bearing syntax hidden inside an object-like macro replacement.
///
/// Tree-sitter deliberately keeps the replacement of `#define NAME value` as
/// one opaque `preproc_arg`. Reparse that exact byte slice as a C++ expression
/// and return only references proven by the resulting tree: ordinary type
/// nodes and the owner prefixes of qualified values such as `Owner::member`.
/// Every returned range is mapped back to the original file.
pub fn object_macro_replacement_type_references(
    node: Node<'_>,
    source: &str,
) -> Vec<MacroReplacementTypeReference> {
    if node.kind() != "preproc_arg"
        || !node.parent().is_some_and(|parent| {
            parent.kind() == "preproc_def"
                && parent
                    .child_by_field_name("value")
                    .is_some_and(|value| value == node)
        })
    {
        return Vec::new();
    }
    let Some(replacement) = source.get(node.start_byte()..node.end_byte()) else {
        return Vec::new();
    };
    const PREFIX: &str = "void __bifrost_macro_reference() { ";
    let synthetic = format!("{PREFIX}{replacement}; }}");
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(&synthetic, None) else {
        return Vec::new();
    };
    if tree.root_node().has_error() {
        return Vec::new();
    }

    let mut references = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(current) = stack.pop() {
        let structured = if matches!(
            current.kind(),
            "type_identifier" | "scoped_type_identifier" | "template_type"
        ) && !is_nested_type_node(current)
        {
            cpp_type_name_components(current, &synthetic)
                .zip(cpp_name_component_nodes(current))
                .map(|(components, nodes)| {
                    (components, nodes, is_globally_qualified_cpp_name(current))
                })
        } else if current.kind() == "qualified_identifier"
            && !current.parent().is_some_and(|parent| {
                matches!(
                    parent.kind(),
                    "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier"
                )
            })
        {
            qualified_owner_components(current, &synthetic)
                .map(|owner| (owner.names, owner.nodes, owner.global))
        } else {
            None
        };
        if let Some((components, component_nodes, global)) = structured {
            let component_ranges = component_nodes
                .into_iter()
                .map(|component| {
                    let start = component.start_byte().checked_sub(PREFIX.len())?;
                    let end = component.end_byte().checked_sub(PREFIX.len())?;
                    (end <= replacement.len())
                        .then_some(node.start_byte() + start..node.start_byte() + end)
                })
                .collect::<Option<Vec<_>>>();
            if let Some(component_ranges) = component_ranges
                && component_ranges.len() == components.len()
            {
                let reference = MacroReplacementTypeReference {
                    components,
                    component_ranges,
                    global,
                };
                if !references.contains(&reference) {
                    references.push(reference);
                }
            }
        }
        push_named_children_reversed(current, &mut stack);
    }
    references
}

#[derive(Clone)]
pub struct QualifiedCallableValue<'tree> {
    pub qualified: Node<'tree>,
    pub global: bool,
    pub owner_components: Vec<Node<'tree>>,
    pub member: Node<'tree>,
}

/// Recognize an explicit address-of qualified callable value such as
/// `&Owner::method` or `&namespace::Owner::method`.
///
/// The returned nodes come exclusively from the C++ grammar's named fields. In
/// particular, a nested namespace/type owner remains a structured subtree rather
/// than being reconstructed from source text.
pub fn explicit_qualified_callable_value(node: Node<'_>) -> Option<QualifiedCallableValue<'_>> {
    if node.kind() != "pointer_expression" || node.child_by_field_name("operator")?.kind() != "&" {
        return None;
    }
    let qualified = node.child_by_field_name("argument")?;
    qualified_callable_value_from_node(qualified)
}

/// Recognize a qualified callable used as an expression value.
///
/// Calls use their own arity-aware path. Address-of expressions use the
/// explicit path above. This arm covers structured values such as
/// `bind(Owner::method)` and `callback = namespace::function`.
pub fn qualified_callable_value(node: Node<'_>) -> Option<QualifiedCallableValue<'_>> {
    if let Some(value) = explicit_qualified_callable_value(node) {
        return Some(value);
    }
    if node.kind() != "qualified_identifier" {
        return None;
    }
    if crate::graph::resolver::is_declaration_name(node) {
        return None;
    }
    if node.parent().is_some_and(|parent| {
        parent.child_by_field_name("type") == Some(node)
            || (parent.kind() == "call_expression"
                && parent.child_by_field_name("function") == Some(node))
            || (parent.kind() == "pointer_expression"
                && parent.child_by_field_name("argument") == Some(node))
            || matches!(
                parent.kind(),
                "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier"
            )
    }) {
        return None;
    }
    qualified_callable_value_from_node(node)
}

fn qualified_callable_value_from_node(qualified: Node<'_>) -> Option<QualifiedCallableValue<'_>> {
    if qualified.kind() != "qualified_identifier" {
        return None;
    }
    let mut components = Vec::new();
    let global = qualified.child_by_field_name("scope").is_none()
        && qualified.child(0).is_some_and(|child| child.kind() == "::");
    append_qualified_components(qualified, &mut components)?;
    let member = components.pop()?;
    if components.is_empty() {
        return None;
    }
    Some(QualifiedCallableValue {
        qualified,
        global,
        owner_components: components,
        member,
    })
}

fn append_qualified_components<'tree>(node: Node<'tree>, out: &mut Vec<Node<'tree>>) -> Option<()> {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            "identifier" | "namespace_identifier" | "type_identifier" | "operator_name" => {
                out.push(current)
            }
            "qualified_identifier" | "scoped_identifier" => {
                stack.push(current.child_by_field_name("name")?);
                if let Some(scope) = current.child_by_field_name("scope") {
                    stack.push(scope);
                } else if current.child(0).is_none_or(|child| child.kind() != "::") {
                    return None;
                }
            }
            "template_type" | "template_function" => {
                stack.push(current.child_by_field_name("name")?);
            }
            "nested_namespace_specifier" => {
                for index in (0..current.named_child_count()).rev() {
                    stack.push(current.named_child(index)?);
                }
            }
            _ => return None,
        }
    }
    Some(())
}

/// Hide grammar-owned comments inside function-like replacements from the
/// primary parser. Otherwise tree-sitter can terminate `preproc_arg` at the
/// comment and read the rest of the directive as surrounding C/C++ code.
/// Replacement analysis still reads the original source and reparses the full
/// logical span; included ranges preserve every original byte coordinate.
pub fn function_macro_included_ranges(source: &str) -> Option<Vec<tree_sitter::Range>> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(source, None)?;
    let mut replacements = Vec::new();
    let mut comments = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if let Some(span) = function_macro_replacement_span(node, source) {
            replacements.push(span);
        }
        if node.kind() == "comment" {
            comments.push(node.range());
        }
        push_named_children_reversed(node, &mut stack);
    }
    comments.retain(|comment| {
        replacements
            .iter()
            .any(|span| span.start <= comment.start_byte && span.end >= comment.end_byte)
    });
    if comments.is_empty() {
        return None;
    }
    comments.sort_by_key(|range| range.start_byte);
    let mut included = Vec::new();
    let mut start_byte = 0;
    let mut start_point = tree_sitter::Point::new(0, 0);
    for comment in comments {
        if start_byte < comment.start_byte {
            included.push(tree_sitter::Range {
                start_byte,
                end_byte: comment.start_byte,
                start_point,
                end_point: comment.start_point,
            });
        }
        start_byte = comment.end_byte;
        start_point = comment.end_point;
    }
    if start_byte < source.len() {
        included.push(tree_sitter::Range {
            start_byte,
            end_byte: source.len(),
            start_point,
            end_point: tree.root_node().end_position(),
        });
    }
    Some(included)
}

#[cfg(test)]
mod tests {
    #[test]
    fn issue_3089_macro_comments_do_not_consume_caller_function() {
        let source = "#define PROCESS(handle, block) \\\ndo { /* comment */ \\\n  int event; \\\n  if (handle) block \\\n} while (0)\nstatic void caller(int handle) { PROCESS(handle, { event; }); }\n";
        let ranges = super::function_macro_included_ranges(source).expect("macro comments");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        parser.set_included_ranges(&ranges).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut stack = vec![tree.root_node()];
        let mut functions = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "function_definition" {
                functions.push(node);
            }
            super::push_named_children_reversed(node, &mut stack);
        }
        assert_eq!(functions.len(), 1, "{}", tree.root_node().to_sexp());
        assert_eq!(
            super::node_text(
                functions[0]
                    .child_by_field_name("declarator")
                    .unwrap()
                    .child_by_field_name("declarator")
                    .unwrap(),
                source
            ),
            "caller"
        );
    }
    use super::*;

    fn references(source: &str) -> Vec<MacroReplacementTypeReference> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("macro fixture tree");
        let value = tree
            .root_node()
            .named_child(0)
            .and_then(|definition| definition.child_by_field_name("value"))
            .expect("macro replacement");
        object_macro_replacement_type_references(value, source)
    }

    #[test]
    fn object_macro_replacement_reparse_preserves_type_ranges() {
        let source = "#define SETTINGS (*api::SettingsImpl::GetInstance())\n";
        let references = references(source);
        let reference = references
            .iter()
            .find(|reference| reference.components == ["api", "SettingsImpl"])
            .expect("qualified callable owner");
        let rendered = reference
            .component_ranges
            .iter()
            .map(|range| &source[range.clone()])
            .collect::<Vec<_>>();
        assert_eq!(rendered, ["api", "SettingsImpl"]);
    }

    #[test]
    fn object_macro_replacement_fields_are_structured_and_direct_only() {
        let replacement = object_macro_replacement(
            r#"int public_value; \
             union { int nested_value; }; \
             unsigned private_value;"#,
        );
        assert_eq!(
            replacement.fields,
            vec![
                MacroReplacementField {
                    name: "public_value".to_string(),
                    declaration: "int public_value;".to_string(),
                },
                MacroReplacementField {
                    name: "private_value".to_string(),
                    declaration: "unsigned private_value;".to_string(),
                },
            ]
        );
        assert!(replacement.nested.is_empty());
        assert!(object_macro_replacement("not a declaration").is_empty());
    }

    /// libuv's `UV_HANDLE_FIELDS` interleaves `/* public */`-style comments
    /// with its members and ends by composing `UV_HANDLE_PRIVATE_FIELDS`
    /// (issue #2985). tree-sitter ends the `preproc_arg` token, and the
    /// `preproc_def` node with it, at the first of those comments.
    #[test]
    fn comment_split_replacement_keeps_every_member_and_its_composition() {
        let source = "#define UV_HANDLE_FIELDS                    \\\n\
                      \x20 /* public */                            \\\n\
                      \x20 void* data;                             \\\n\
                      \x20 /* read-only */                         \\\n\
                      \x20 uv_loop_t* loop;                        \\\n\
                      \x20 UV_HANDLE_PRIVATE_FIELDS                \\\n\
                      \nstruct uv_handle_s { UV_HANDLE_FIELDS };\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("macro fixture tree");
        let mut stack = vec![tree.root_node()];
        let definition = loop {
            let current = stack.pop().expect("the fixture defines one object macro");
            if current.kind() == "preproc_def" {
                break current;
            }
            let mut cursor = current.walk();
            for child in current.named_children(&mut cursor) {
                stack.push(child);
            }
        };
        let value = definition
            .child_by_field_name("value")
            .expect("truncated replacement token");
        assert_eq!(
            source[value.byte_range()]
                .trim_end()
                .trim_end_matches('\\')
                .trim_end(),
            "void* data;"
        );

        let span = object_macro_replacement_span(definition, source).expect("replacement span");
        let replacement = object_macro_replacement(&source[span]);
        assert_eq!(
            replacement
                .fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            ["data", "loop"]
        );
        assert_eq!(replacement.nested, ["UV_HANDLE_PRIVATE_FIELDS"]);
    }

    #[test]
    fn malformed_replacement_regions_still_refuse_the_whole_replacement() {
        assert!(object_macro_replacement("int ok; struct {").is_empty());
    }

    #[test]
    fn conflicting_replacements_keep_only_the_members_both_declare() {
        let unix = object_macro_replacement("uv_handle_t* next_closing; unsigned int flags;");
        let windows = object_macro_replacement("uv_handle_t* endgame_next; unsigned int flags;");
        assert_eq!(
            unix.intersect(&windows).fields,
            vec![MacroReplacementField {
                name: "flags".to_string(),
                declaration: "unsigned int flags;".to_string(),
            }]
        );
    }

    #[test]
    fn collapsed_aggregate_members_recover_their_names_and_ranges() {
        let source = "struct uv_signal_s {\n  UV_HANDLE_FIELDS\n  uv_signal_cb signal_cb;\n};";
        let span = source.find("uv_signal_cb").expect("member start")
            ..source.find("signal_cb;").expect("member end") + "signal_cb;".len();
        let fields = recovered_aggregate_fields(source, span);
        assert_eq!(
            fields
                .iter()
                .map(|field| (field.name.as_str(), field.declaration.as_str()))
                .collect::<Vec<_>>(),
            [("signal_cb", "uv_signal_cb signal_cb;")]
        );
        assert_eq!(&source[fields[0].range.clone()], "uv_signal_cb signal_cb;");
    }

    #[test]
    fn macro_reparse_ignores_function_like_and_non_code_text() {
        let function_like = "#define SETTINGS(Type) (*Type::GetInstance())\n";
        assert!(references(function_like).is_empty());

        let text = "#define SETTINGS \"SettingsImpl::GetInstance()\"\n";
        assert!(references(text).is_empty());
    }
}
