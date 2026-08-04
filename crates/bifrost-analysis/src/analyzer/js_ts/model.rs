use crate::analyzer::fq_name::{FqName, SegmentId, SegmentKind, segment_interner};
use crate::analyzer::tree_sitter_analyzer::{ParsedFile, WalkControl, walk_named_tree_preorder};
use crate::analyzer::{CodeUnit, CodeUnitType, ProjectFile};
use tree_sitter::Node;

pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    crate::analyzer::common::node_source_text(node, source)
}

/// Intern one qualified-name segment in the process-global interner. Shared by
/// the JavaScript and TypeScript adapters (both build `FqName`s the same way:
/// `package_name` is always empty, so every chain starts fresh from either a
/// parent's own `fq` or one of the synthetic file-scope prefixes below).
pub(crate) fn js_ts_segment(text: &str, kind: SegmentKind) -> SegmentId {
    segment_interner().intern(text, kind)
}

/// The file's own base name (with extension) as a single [`SegmentKind::Path`]
/// segment. Its text may itself contain literal dots (`utils.test.js`), which
/// is exactly what `Path` is for; this is never further split into directory
/// components because js/ts short names are never qualified by directory path,
/// only (optionally) by this bare file-name marker (see
/// `file_scoped_field_name` below).
fn file_name_path_segment(file: &ProjectFile) -> SegmentId {
    let name = file
        .rel_path()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("module");
    js_ts_segment(name, SegmentKind::Path)
}

pub(crate) fn module_code_unit(file: &ProjectFile) -> CodeUnit {
    let fq = FqName::new().with_pushed(file_name_path_segment(file));
    CodeUnit::new_fq(
        file.clone(),
        crate::analyzer::CodeUnitType::Module,
        "",
        file.rel_path()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("module"),
        fq,
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
    // The synthetic `default` name is a Type segment for a default-exported
    // class, a Member segment for a default-exported function/object (mirrors
    // how every other class-vs-member site in this module tags its own name).
    let segment_kind = if kind == CodeUnitType::Class {
        SegmentKind::Type
    } else {
        SegmentKind::Member
    };
    let fq = FqName::new().with_pushed(js_ts_segment("default", segment_kind));
    let code_unit = CodeUnit::new_fq(file.clone(), kind, "", "default", fq);
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

/// Structured counterpart to [`file_scoped_field_name`]: the same file-name
/// `Path` prefix followed by the field's own `Member` segment.
pub(crate) fn file_scoped_field_fq(file: &ProjectFile, name: &str) -> FqName {
    FqName::new()
        .with_pushed(file_name_path_segment(file))
        .with_pushed(js_ts_segment(name, SegmentKind::Member))
}

/// Indexes each binder of a destructured `variable_declarator` name pattern
/// (`const { alpha, beta: renamed } = ...`, `const [first] = ...`) as its own
/// Field code unit. Without this, the whole pattern would become a single unit
/// literally named after the pattern text, and the individual binders could
/// never be resolution targets (#1568).
pub(crate) fn add_destructured_binder_units(
    file: &ProjectFile,
    source: &str,
    pattern: Node<'_>,
    range_node: Node<'_>,
    parent: Option<&CodeUnit>,
    signature: &str,
    parsed: &mut ParsedFile,
) {
    for binder in crate::analyzer::js_ts::syntax::pattern_binder_identifiers(pattern) {
        let name = node_text(binder, source).trim();
        if name.is_empty() {
            continue;
        }
        let (short_name, fq) = match parent {
            Some(parent) => (
                format!("{}.{}", parent.short_name(), name),
                parent
                    .fq()
                    .clone()
                    .with_pushed(js_ts_segment(name, SegmentKind::Member)),
            ),
            None => (
                file_scoped_field_name(file, name),
                file_scoped_field_fq(file, name),
            ),
        };
        let code_unit = CodeUnit::new_fq(file.clone(), CodeUnitType::Field, "", short_name, fq);
        let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
        parsed.add_code_unit(
            code_unit.clone(),
            range_node,
            source,
            parent.cloned(),
            Some(top_level),
        );
        parsed.add_signature(code_unit, signature.to_string());
    }
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

/// Recognizes a schema-builder call whose first object-literal argument defines the value's
/// navigable shape, e.g. zod's `z.object({ ... })`. Schema libraries (zod, yup, valibot,
/// superstruct, ...) universally expose this via an `object(...)` builder, so we match the
/// `object` member-name convention rather than a specific import alias — `z` is only a
/// conventional name and breaks under `import * as zod` or aliased imports. Shared by both
/// dialects (see issue #1167): this is pure tree-sitter node-shape matching with no
/// language-specific grammar involved.
pub(crate) fn call_is_schema_object_builder(call: Node<'_>, source: &str) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    if function.kind() != "member_expression" {
        return false;
    }
    let Some(property) = function.child_by_field_name("property") else {
        return false;
    };
    node_text(property, source).trim() == "object"
}
