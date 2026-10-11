use crate::primary::JsTsParsedFile;
use brokk_bifrost_core::analyzer::common::node_source_text;
use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentId, SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::model::CodeUnitType;
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::analyzer::structural::materialization::{
    ExportForm, MaterializationRecord,
};
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, node_range, walk_named_tree_preorder};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use tree_sitter::Node;

pub use brokk_bifrost_core::analyzer::common::node_source_text as node_text;
pub use brokk_bifrost_core::analyzer::tree_walk::root_node;

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
    segment_interner().intern(name, SegmentKind::Path)
}

pub fn module_code_unit(file: &ProjectFile) -> CodeUnit {
    let fq = FqName::new().with_pushed(file_name_path_segment(file));
    CodeUnit::new_fq(
        file.clone(),
        brokk_bifrost_core::analyzer::model::CodeUnitType::Module,
        "",
        file.rel_path()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("module"),
        fq,
    )
}

pub fn trim_statement(text: &str) -> String {
    text.trim().trim_end_matches(';').trim().to_string()
}

pub(crate) fn export_is_default(node: Node<'_>, source: &str) -> bool {
    (0..node.child_count()).any(|index| {
        node.child(index)
            .is_some_and(|child| child.kind() == "default" || node_text(child, source) == "default")
    })
}

pub(crate) fn object_literal_property_kind(node: Node<'_>) -> CodeUnitType {
    if node.kind() == "method_definition"
        || node
            .child_by_field_name("value")
            .is_some_and(|value| matches!(value.kind(), "arrow_function" | "function_expression"))
    {
        CodeUnitType::Function
    } else {
        CodeUnitType::Field
    }
}

pub(crate) fn is_simple_js_ts_initializer(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "string"
            | "number"
            | "true"
            | "false"
            | "null"
            | "undefined"
            | "regex"
            | "template_string"
            | "unary_expression"
            | "binary_expression"
            | "identifier"
            | "member_expression"
    )
}

pub(crate) fn collect_return_object_literals<'tree>(
    node: Node<'tree>,
    root_id: usize,
    out: &mut Vec<Node<'tree>>,
    mut is_nested_boundary: impl FnMut(Node<'tree>) -> bool,
    mut object_literal_value: impl FnMut(Node<'tree>) -> Option<Node<'tree>>,
) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.id() != root_id && is_nested_boundary(node) {
            continue;
        }

        if node.kind() == "return_statement" {
            let mut cursor = node.walk();
            if let Some(object) = node
                .named_children(&mut cursor)
                .find_map(&mut object_literal_value)
            {
                out.push(object);
            }
            continue;
        }

        if node.kind() == "arrow_function"
            && let Some(body) = node.child_by_field_name("body")
            && let Some(object) = object_literal_value(body)
        {
            out.push(object);
        }

        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
}

// The helpers below are shared verbatim between the JavaScript and TypeScript
// adapters (`javascript/mod.rs` / `typescript/mod.rs`): each language used to
// carry a byte-identical private copy under a `js_`/`ts_` prefix. None of them
// touch dialect-specific grammar (no TSX/type-annotation handling lives here),
// so there is no per-language hole to parameterize -- they are pure duplicates,
// not twins.

/// Adds a synthetic `default` CodeUnit for an anonymous `export default ...`
/// declaration (function/class/object literal with no name of its own).
pub(crate) fn add_default_export_unit(
    file: &ProjectFile,
    source: &str,
    export: Node<'_>,
    kind: CodeUnitType,
    parsed: &mut JsTsParsedFile<'_>,
) -> CodeUnit {
    // The synthetic `default` name is a Type segment for a default-exported
    // class, a Member segment for a default-exported function/object (mirrors
    // how every other class-vs-member site in this module tags its own name).
    let segment_kind = if kind == CodeUnitType::Class {
        SegmentKind::Type
    } else {
        SegmentKind::Member
    };
    let fq = FqName::new().with_pushed(segment_interner().intern("default", segment_kind));
    let code_unit = CodeUnit::new_fq(file.clone(), kind, "", "default", fq);
    parsed.add_code_unit(
        code_unit.clone(),
        export,
        source,
        None,
        Some(code_unit.clone()),
    );
    record_export_row(
        parsed,
        export,
        ExportForm::DefaultAnonymous,
        "default".to_string(),
        Some(code_unit.clone()),
    );
    code_unit
}

/// Records the export row for a named exported declaration (`export class X`,
/// `export function f`, `export interface I`, `export default function f()`):
/// the declaration keeps its own name, so the row states the form and name
/// without re-deriving the declared unit. `is_default` is the dialect's own
/// default-clause check.
pub fn record_named_export(
    source: &str,
    export: Node<'_>,
    declaration: Node<'_>,
    is_default: bool,
    parsed: &mut ParsedFile,
) {
    let Some(name) = declaration.child_by_field_name("name") else {
        return;
    };
    record_export_row(
        parsed,
        export,
        if is_default {
            ExportForm::DefaultNamed
        } else {
            ExportForm::Named
        },
        if is_default {
            "default".to_string()
        } else {
            node_source_text(name, source).trim().to_string()
        },
        None,
    );
}

/// Records one export row per binder of each declarator of an exported
/// `let`/`const`/`var` statement (issue #1659). A plainly named declarator is
/// one binder; a destructuring pattern (`export const { a, b: renamed } = ...`)
/// contributes one row per bound identifier, enumerated through the same
/// pattern walk that [`add_destructured_binder_units`] uses. The walk is total
/// over the grammar's declarator name shapes, so an empty pattern (`{}`)
/// legitimately exports nothing.
pub fn record_named_declarator_exports(
    source: &str,
    export: Node<'_>,
    declaration: Node<'_>,
    parsed: &mut ParsedFile,
) {
    for index in 0..declaration.named_child_count() {
        let Some(declarator) = declaration.named_child(index) else {
            continue;
        };
        if declarator.kind() != "variable_declarator" {
            continue;
        }
        let Some(name) = declarator.child_by_field_name("name") else {
            continue;
        };
        for binder in crate::syntax::pattern_binder_identifiers(name) {
            let exported_name = node_source_text(binder, source).trim().to_string();
            if exported_name.is_empty() {
                continue;
            }
            record_export_row(parsed, export, ExportForm::Named, exported_name, None);
        }
    }
}

/// Records the `export default name` re-export row: it points at an existing
/// binding, so it materializes no declaration but is still an export fact.
pub fn record_default_reexport(export: Node<'_>, parsed: &mut ParsedFile) {
    record_export_row(
        parsed,
        export,
        ExportForm::DefaultNamed,
        "default".to_string(),
        None,
    );
}

fn record_export_row(
    parsed: &mut ParsedFile,
    export: Node<'_>,
    form: ExportForm,
    exported_name: String,
    target: Option<CodeUnit>,
) {
    parsed.record_materialization(MaterializationRecord::Export {
        range: node_range(export),
        form,
        exported_name,
        target,
    });
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn visit_default_export_value<'export, 'value, 'source>(
    file: &ProjectFile,
    source: &str,
    export: Node<'export>,
    value: Node<'value>,
    parsed: &mut JsTsParsedFile<'source>,
    mut visit_function: impl FnMut(
        &ProjectFile,
        &str,
        Node<'export>,
        Node<'value>,
        &mut JsTsParsedFile<'source>,
    ),
    mut visit_class: impl FnMut(
        &ProjectFile,
        &str,
        Node<'export>,
        Node<'value>,
        &mut JsTsParsedFile<'source>,
    ),
    mut visit_object_properties: impl FnMut(
        &ProjectFile,
        &str,
        Node<'value>,
        &CodeUnit,
        &CodeUnit,
        &mut JsTsParsedFile<'source>,
    ),
) {
    match value.kind() {
        "arrow_function" | "function_expression" | "generator_function" => {
            visit_function(file, source, export, value, parsed);
        }
        "class" => visit_class(file, source, export, value, parsed),
        "object" => {
            let code_unit =
                add_default_export_unit(file, source, export, CodeUnitType::Field, parsed);
            parsed.add_signature(code_unit.clone(), trim_statement(node_text(export, source)));
            visit_object_properties(file, source, value, &code_unit, &code_unit, parsed);
        }
        // `export default name` and `export default object.member` point at an
        // existing binding. Every other expression creates an anonymous default
        // value that needs its own source-backed declaration (#2301).
        "identifier" | "member_expression" => record_default_reexport(export, parsed),
        _ => {
            let code_unit =
                add_default_export_unit(file, source, export, CodeUnitType::Field, parsed);
            parsed.add_signature(code_unit, trim_statement(node_text(export, source)));
        }
    }
}

/// If `node` is a `this.<property>` member expression with a nameable
/// property, returns the property node (used to detect constructor-assigned
/// instance fields).
pub fn this_member_property<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
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
pub fn property_name_text(node: Node<'_>, source: &str) -> Option<String> {
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
pub fn variable_header(
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
pub fn file_scoped_field_name(file: &ProjectFile, name: &str) -> String {
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
pub fn file_scoped_field_fq(file: &ProjectFile, name: &str) -> FqName {
    FqName::new()
        .with_pushed(file_name_path_segment(file))
        .with_pushed(segment_interner().intern(name, SegmentKind::Member))
}

/// The structured identity of a file-scoped *type* declaration: the same
/// file-name `Path` prefix [`file_scoped_field_fq`] uses, followed by the
/// declaration's own [`SegmentKind::Type`] segment.
///
/// A `type` alias renders exactly like a same-named module-scope `const`
/// (`Type` and `Member` both join with `.`), so only the segment kind keeps the
/// two identities apart -- which is the whole of #2911.
pub fn file_scoped_type_fq(file: &ProjectFile, name: &str) -> FqName {
    FqName::new()
        .with_pushed(file_name_path_segment(file))
        .with_pushed(segment_interner().intern(name, SegmentKind::Type))
}

pub type TopLevelFieldIdentity = fn(&ProjectFile, &str) -> (String, FqName);

pub fn file_scoped_field_identity(file: &ProjectFile, name: &str) -> (String, FqName) {
    (
        file_scoped_field_name(file, name),
        file_scoped_field_fq(file, name),
    )
}

pub fn program_scoped_field_identity(_file: &ProjectFile, name: &str) -> (String, FqName) {
    (
        name.to_owned(),
        FqName::new().with_pushed(segment_interner().intern(name, SegmentKind::Member)),
    )
}

/// Indexes each binder of a destructured `variable_declarator` name pattern
/// (`const { alpha, beta: renamed } = ...`, `const [first] = ...`) as its own
/// Field code unit. Without this, the whole pattern would become a single unit
/// literally named after the pattern text, and the individual binders could
/// never be resolution targets (#1568). The caller supplies the top-level
/// identity because script values use the shared program scope, while module
/// values use the file scope (#1862).
#[allow(clippy::too_many_arguments)]
pub(crate) fn add_destructured_binder_units(
    file: &ProjectFile,
    source: &str,
    pattern: Node<'_>,
    range_node: Node<'_>,
    parent: Option<&CodeUnit>,
    signature: &str,
    parsed: &mut JsTsParsedFile<'_>,
    top_level_identity: TopLevelFieldIdentity,
) {
    for binder in crate::syntax::pattern_binder_identifiers(pattern) {
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
                    .with_pushed(segment_interner().intern(name, SegmentKind::Member)),
            ),
            None => top_level_identity(file, name),
        };
        let code_unit = CodeUnit::new_fq(file.clone(), CodeUnitType::Field, "", short_name, fq);
        let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
        parsed.add_named_code_unit(
            code_unit.clone(),
            range_node,
            binder,
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
pub fn module_scoped_field_uses_file_name(code_unit: &CodeUnit) -> bool {
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

/// Collects every function-declaration or function-valued variable-declarator
/// named `function_name` reachable from `node`, without descending into a
/// matched function's own body (each match is a separate candidate source).
pub fn collect_function_nodes<'tree>(
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
pub fn call_identifier_name(call: Node<'_>, source: &str) -> Option<String> {
    let function = call.child_by_field_name("function")?;
    matches!(function.kind(), "identifier" | "property_identifier")
        .then(|| node_text(function, source).trim().to_string())
        .filter(|name| !name.is_empty())
}

/// Heuristic: does the callee's name look like a factory/builder conventionally
/// used to construct a shape-preserving object (`define(...)`, `defineX(...)`,
/// `object(...)`)? Used only as a last-resort fallback when the call's actual
/// source function couldn't be found to check its return shape directly.
pub fn call_has_likely_surface_factory_name(call: Node<'_>, source: &str) -> bool {
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
pub fn call_is_schema_object_builder(call: Node<'_>, source: &str) -> bool {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShapePreservation {
    Preserves,
    DoesNotPreserve,
    Unknown,
}

pub(crate) fn call_preserves_object_argument_shape(
    call: Node<'_>,
    source: &str,
    argument_index: usize,
    preservation: ShapePreservation,
) -> bool {
    (argument_index == 0 && call_is_schema_object_builder(call, source))
        || preservation == ShapePreservation::Preserves
}

pub(crate) fn surface_call_preserves_object_argument_shape(
    call: Node<'_>,
    source: &str,
    argument_index: usize,
    preservation: ShapePreservation,
) -> bool {
    if argument_index == 0 && call_is_schema_object_builder(call, source) {
        return true;
    }
    match preservation {
        ShapePreservation::Preserves => true,
        ShapePreservation::DoesNotPreserve => false,
        ShapePreservation::Unknown => call_has_likely_surface_factory_name(call, source),
    }
}
