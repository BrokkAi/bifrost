use crate::analyzer::tree_sitter_analyzer::{ParsedFile, WalkControl, walk_named_tree_preorder};
use crate::analyzer::{CodeUnit, CodeUnitType, ProjectFile};
use tree_sitter::Node;

pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    crate::analyzer::common::node_source_text(node, source)
}

pub(crate) fn module_code_unit(file: &ProjectFile) -> CodeUnit {
    CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Module,
        "",
        file.rel_path()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("module"),
    )
}

pub(crate) fn trim_statement(text: &str) -> String {
    text.trim().trim_end_matches(';').trim().to_string()
}

// The helpers below are shared verbatim between the JavaScript and TypeScript
// adapters (`javascript/mod.rs` / `typescript/mod.rs`): each language used to
// carry a byte-identical private copy under a `js_`/`ts_` prefix. None of them
// touch dialect-specific grammar (no TSX/type-annotation handling lives here),
// so there is no per-language hole to parameterize — they are pure duplicates,
// not twins. See `.agents/docs/cross-language-duplication-survey.md` (CPD
// family #3) for the survey that identified them.

/// Adds a synthetic `default` CodeUnit for an anonymous `export default ...`
/// declaration (function/class/object literal with no name of its own).
pub(crate) fn add_default_export_unit(
    file: &ProjectFile,
    source: &str,
    export: Node<'_>,
    kind: CodeUnitType,
    parsed: &mut ParsedFile,
) -> CodeUnit {
    let code_unit = CodeUnit::new(file.clone(), kind, "", "default");
    parsed.add_code_unit(
        code_unit.clone(),
        export,
        source,
        None,
        Some(code_unit.clone()),
    );
    code_unit
}

/// If `node` is a `this.<property>` member expression with a nameable
/// property, returns the property node (used to detect constructor-assigned
/// instance fields).
pub(crate) fn this_member_property<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    if node.kind() != "member_expression" {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    if object.kind() != "this" {
        return None;
    }
    let property = node.child_by_field_name("property")?;
    property_name_text(property, source)
        .is_some()
        .then_some(property)
}

/// Renders a property-name-shaped node (bare identifier or quoted string key)
/// to its text, or `None` if the node doesn't denote a nameable property.
pub(crate) fn property_name_text(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier"
        | "property_identifier"
        | "shorthand_property_identifier"
        | "shorthand_property_identifier_pattern" => {
            let text = node_text(node, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        "string" => {
            let text = node_text(node, source)
                .trim()
                .trim_matches('"')
                .trim_matches('\'');
            (!text.is_empty()).then(|| text.to_string())
        }
        _ => None,
    }
}

/// Renders the `<keyword> <left-hand-side>` header of a variable declarator
/// (e.g. `const foo`), stripping any `= value` initializer text.
pub(crate) fn variable_header(
    statement: Node<'_>,
    declarator: Node<'_>,
    source: &str,
    exported: bool,
) -> String {
    let keyword = statement
        .child(0)
        .map(|node| node_text(node, source).trim().to_string())
        .unwrap_or_else(|| "const".to_string());
    let declarator_text = trim_statement(node_text(declarator, source));
    let left = declarator_text
        .split('=')
        .next()
        .map(trim_statement)
        .unwrap_or(declarator_text);
    let export_prefix = if exported { "export " } else { "" };
    format!("{export_prefix}{keyword} {left}")
}

/// Qualifies a module-scope field's short name with its file's base name
/// (`<file>.<name>`), used when a top-level binding has no enclosing class.
pub(crate) fn file_scoped_field_name(file: &ProjectFile, name: &str) -> String {
    format!(
        "{}.{}",
        file.rel_path()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("module"),
        name
    )
}

/// Whether `code_unit` is a module-scope field whose short name was qualified
/// by `file_scoped_field_name` (and therefore needs the file-scope parent
/// fallback in `parent_of`, rather than the ordinary structural parent).
pub(crate) fn module_scoped_field_uses_file_name(code_unit: &CodeUnit) -> bool {
    if !code_unit.is_field() {
        return false;
    }
    let Some(file_name) = code_unit
        .source()
        .rel_path()
        .file_name()
        .and_then(|name| name.to_str())
    else {
        return false;
    };
    code_unit.short_name().starts_with(&format!("{file_name}."))
}

/// Walks up to the outermost ancestor of `node` (the parse tree root).
pub(crate) fn root_node(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        node = parent;
    }
    node
}

/// Collects every function-declaration or function-valued variable-declarator
/// named `function_name` reachable from `node`, without descending into a
/// matched function's own body (each match is a separate candidate source).
pub(crate) fn collect_function_nodes<'tree>(
    node: Node<'tree>,
    source: &str,
    function_name: &str,
    out: &mut Vec<Node<'tree>>,
) {
    walk_named_tree_preorder(node, true, |node| {
        if node.kind() == "function_declaration"
            && node
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source).trim() == function_name)
        {
            out.push(node);
            return WalkControl::SkipChildren;
        }
        if node.kind() == "variable_declarator"
            && node
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source).trim() == function_name)
            && let Some(value) = node.child_by_field_name("value")
            && matches!(value.kind(), "arrow_function" | "function_expression")
        {
            out.push(value);
            return WalkControl::SkipChildren;
        }
        WalkControl::Continue
    });
}

/// The callee's bare or member-property name, if the call target is a simple
/// identifier or `a.b(...)`-shaped member access (not a computed/dynamic call).
pub(crate) fn call_identifier_name(call: Node<'_>, source: &str) -> Option<String> {
    let function = call.child_by_field_name("function")?;
    matches!(function.kind(), "identifier" | "property_identifier")
        .then(|| node_text(function, source).trim().to_string())
        .filter(|name| !name.is_empty())
}

/// Heuristic: does the callee's name look like a factory/builder conventionally
/// used to construct a shape-preserving object (`define(...)`, `defineX(...)`,
/// `object(...)`)? Used only as a last-resort fallback when the call's actual
/// source function couldn't be found to check its return shape directly.
pub(crate) fn call_has_likely_surface_factory_name(call: Node<'_>, source: &str) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let name = match function.kind() {
        "identifier" | "property_identifier" => node_text(function, source).trim(),
        "member_expression" => function
            .child_by_field_name("property")
            .map(|property| node_text(property, source).trim())
            .unwrap_or(""),
        _ => "",
    };
    name == "define" || name.starts_with("define") || name == "object"
}
