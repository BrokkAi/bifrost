use crate::primary::JsTsParsedFile;
use brokk_bifrost_core::analyzer::common::node_source_text;
use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentId, SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::model::CodeUnitType;
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::analyzer::structural::materialization::{
    ExportForm, MaterializationRecord,
};
use brokk_bifrost_core::analyzer::tree_walk::node_range;
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
            let value = crate::syntax::js_ts_string_literal_code_units(node, source)?;
            let name = String::from_utf16(&value).ok()?;
            (!name.is_empty()).then_some(name)
        }
        _ => None,
    }
}

/// A declaration's header before its own initializer assignment token. An
/// arrow in a type and defaults nested inside a binding are different nodes.
pub(crate) fn declaration_initializer_header<'source>(
    node: Node<'_>,
    source: &'source str,
) -> &'source str {
    let assignment = node
        .children(&mut node.walk())
        .find(|child| child.kind() == "=");
    debug_assert!(
        node.child_by_field_name("value").is_none() || assignment.is_some(),
        "initialized declaration has an assignment token: {}",
        node.to_sexp()
    );
    let end = assignment.map_or(node.end_byte(), |operator| operator.start_byte());
    &source[node.start_byte()..end]
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
    let left = trim_statement(declaration_initializer_header(declarator, source));
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

/// Classify only functions bound at this source location. The lexical index and
/// its declaration-token ranges live for this single lookup, never a workspace.
pub(crate) fn source_function_shape_preservation(
    anchor: Node<'_>,
    source: &str,
    name: &str,
    mut preserves: impl FnMut(Node<'_>) -> bool,
) -> ShapePreservation {
    let root = root_node(anchor);
    let bindings = crate::syntax::JsTsLexicalBindingIndex::build(root, source);
    let ranges = bindings.binding_identifier_ranges_at(name, anchor.start_byte());
    if ranges.is_empty() {
        return ShapePreservation::Unknown;
    }
    if bindings.is_binding_reassigned_before_at(name, anchor.start_byte()) {
        return ShapePreservation::Unknown;
    }
    let declarations: Vec<_> = ranges
        .into_iter()
        .map(|range| {
            root.named_descendant_for_byte_range(range.start_byte, range.end_byte)
                .expect("indexed declaration token is in the source tree")
                .parent()
                .expect("declaration binder has a parent")
        })
        .collect();
    let implementation = last_hoisted_function_implementation(&declarations);
    let mut functions = Vec::new();
    for declaration in implementation.into_iter().chain(
        declarations
            .into_iter()
            .filter(|_| implementation.is_none()),
    ) {
        match declaration.kind() {
            "function_declaration" => functions.push(declaration),
            "variable_declarator" => match declaration.child_by_field_name("value") {
                Some(value) if matches!(value.kind(), "arrow_function" | "function_expression") => {
                    functions.push(value)
                }
                _ => return ShapePreservation::DoesNotPreserve,
            },
            "class_declaration" | "abstract_class_declaration" => {
                return ShapePreservation::DoesNotPreserve;
            }
            // Imports and externally supplied values have no local body.
            _ => return ShapePreservation::Unknown,
        }
    }
    let preserving = functions.into_iter().all(&mut preserves);
    if preserving {
        ShapePreservation::Preserves
    } else {
        ShapePreservation::DoesNotPreserve
    }
}

/// Hoisting selects the last function declaration in one scope. Variable
/// declarations and assignments do not obey this rule, even when callable.
/// TypeScript overload signatures belong to the same binding and have no body.
pub(crate) fn last_hoisted_function_implementation<'tree>(
    nodes: &[Node<'tree>],
) -> Option<Node<'tree>> {
    fn scope(node: Node<'_>) -> Option<usize> {
        let parent = node.parent()?;
        if parent.kind() == "export_statement" {
            parent.parent().map(|n| n.id())
        } else {
            Some(parent.id())
        }
    }
    let first = *nodes.first()?;
    if nodes.iter().any(|node| {
        !matches!(node.kind(), "function_declaration" | "function_signature")
            || scope(*node) != scope(first)
    }) {
        return None;
    }
    nodes
        .iter()
        .copied()
        .filter(|node| node.child_by_field_name("body").is_some())
        .max_by_key(Node::start_byte)
}

/// The header ends at the grammar's body field, even when a parameter or a
/// heritage expression itself contains braces. Keep an export wrapper's prefix.
pub(crate) fn declaration_header<'source>(node: Node<'_>, source: &'source str) -> &'source str {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration")
            .or_else(|| node.child_by_field_name("value"))
            .expect("declaration export has a declaration or value")
    } else {
        node
    };
    let end = definition
        .child_by_field_name("body")
        .map_or(definition.end_byte(), |body| body.start_byte());
    &source[node.start_byte()..end]
}

pub(crate) fn is_async_callable(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| child.kind() == "async")
}

/// The callee's bare identifier name. Member calls require receiver resolution
/// and must not be inferred from a property spelling alone.
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

#[cfg(test)]
mod signature_regression_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "4ed755aac3c5: quicksilver round 7 on brokk-bifrost-js-ts: function type arrows truncated variable signatures"
    )]
    fn variable_header_uses_grammar_initializer_boundary() {
        let source = "const fn: (x:number)=>number = external;";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let statement = tree.root_node().named_child(0).unwrap();
        let declaration = statement.named_child(0).unwrap();
        assert_eq!(
            variable_header(statement, declaration, source, false),
            "const fn: (x:number)=>number"
        );
    }
}

#[cfg(test)]
mod export_boundary_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    fn parse(source: &str, language: brokk_bifrost_core::analyzer::Language) -> ParsedFile {
        let file = ProjectFile::new(
            std::env::temp_dir(),
            if language == brokk_bifrost_core::analyzer::Language::JavaScript {
                "exports.js"
            } else {
                "exports.ts"
            },
        );
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&crate::parse::tree_sitter_language_for(language).unwrap())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        if language == brokk_bifrost_core::analyzer::Language::JavaScript {
            crate::javascript::parse_javascript_file(&file, source, &tree)
        } else {
            crate::typescript::parse_typescript_file(&file, source, &tree)
        }
    }

    #[test]
    fn export_entries_agree_with_bound_names_and_default_declaration_identity() {
        for language in [
            brokk_bifrost_core::analyzer::Language::JavaScript,
            brokk_bifrost_core::analyzer::Language::TypeScript,
        ] {
            for (source, names, form, segment) in [
                (
                    "export const {x:renamed, y}=source;",
                    vec!["renamed", "y"],
                    ExportForm::Named,
                    None,
                ),
                (
                    "const owner={member:1}; export default owner.member;",
                    vec!["default"],
                    ExportForm::DefaultNamed,
                    None,
                ),
                (
                    "export default {run(){}};",
                    vec!["default"],
                    ExportForm::DefaultAnonymous,
                    Some(SegmentKind::Member),
                ),
                (
                    "export default ()=>1;",
                    vec!["default"],
                    ExportForm::DefaultAnonymous,
                    Some(SegmentKind::Member),
                ),
                (
                    "export default class {};",
                    vec!["default"],
                    ExportForm::DefaultAnonymous,
                    Some(SegmentKind::Type),
                ),
            ] {
                let parsed = parse(source, language);
                let exports: Vec<_> = parsed
                    .materialization_records
                    .iter()
                    .filter_map(|record| match record {
                        MaterializationRecord::Export {
                            form,
                            exported_name,
                            ..
                        } => Some((*form, exported_name.as_str())),
                        _ => None,
                    })
                    .collect();
                assert_eq!(
                    exports,
                    names.iter().map(|name| (form, *name)).collect::<Vec<_>>(),
                    "{source}"
                );
                let default = parsed
                    .ranges
                    .keys()
                    .find(|unit| unit.identifier() == "default");
                assert_eq!(
                    default.map(|unit| unit.fq().resolved_segments().last().unwrap().1),
                    segment,
                    "{source}"
                );
            }
            let parsed = parse(
                "import {defineConfig} from 'external'; export const api=defineConfig({run(){return 1;}}); const owner={member:1}; export const alias=owner.member;",
                language,
            );
            assert!(
                parsed.ranges.keys().any(
                    |unit| unit.identifier() == "run" && unit.owner_identifier() == Some("api")
                )
            );
            assert!(
                parsed
                    .signatures
                    .values()
                    .flatten()
                    .any(|signature| signature.contains("alias = owner.member"))
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_module_path_keeps_the_documented_fallback_identity() {
        use std::os::unix::ffi::OsStringExt;
        let file = ProjectFile::new(
            std::env::temp_dir(),
            std::path::PathBuf::from(std::ffi::OsString::from_vec(vec![
                b'm', 0xff, b'.', b'j', b's',
            ])),
        );
        let unit = module_code_unit(&file);
        assert_eq!(unit.short_name(), "module");
        assert_eq!(unit.fq().resolved_segments().last().unwrap().0, "module");
    }
    #[test]
    #[hardwon("#7218: review: known non-callable factory binding invented object members")]
    fn non_callable_factory_has_no_surface() {
        for binding in ["class defineConfig {}", "const defineConfig = 0;"] {
            let source = format!("{binding} export const api = defineConfig({{ghost() {{}}}});");
            let parsed = parse(&source, brokk_bifrost_core::analyzer::Language::TypeScript);
            assert!(
                !parsed
                    .ranges
                    .keys()
                    .any(|unit| unit.identifier() == "ghost"
                        && unit.owner_identifier() == Some("api")),
                "{binding}"
            );
        }
    }

    #[test]
    #[hardwon("#7218: review: duplicate hoisted factory used all bodies instead of last")]
    fn hoisted_factory_uses_last_body() {
        let parsed = parse(
            "function defineConfig(x) {return 0;} function defineConfig(x) {return x;} export const api = defineConfig({ghost() {}});",
            brokk_bifrost_core::analyzer::Language::JavaScript,
        );
        assert!(
            parsed
                .ranges
                .keys()
                .any(|unit| unit.identifier() == "ghost" && unit.owner_identifier() == Some("api"))
        );
    }

    #[test]
    #[hardwon(
        "4ed755aac3c5: quicksilver round 7 on brokk-bifrost-js-ts: unrelated nested identity created a fictitious factory surface"
    )]
    fn unrelated_nested_identity_does_not_preserve_a_nonpreserving_factory() {
        let source = "function identity(value){return 0;} function elsewhere(){function identity(value){return value;}} export const api=identity({run(){return 1;}});";
        for language in [
            brokk_bifrost_core::analyzer::Language::JavaScript,
            brokk_bifrost_core::analyzer::Language::TypeScript,
        ] {
            let parsed = parse(source, language);
            assert!(
                !parsed.ranges.keys().any(
                    |unit| unit.identifier() == "run" && unit.owner_identifier() == Some("api")
                ),
                "{language:?}"
            );
        }
    }

    #[test]
    #[hardwon(
        "4ed755aac3c5: quicksilver round 7 on brokk-bifrost-js-ts: class field function type signature was truncated at its arrow"
    )]
    fn class_field_function_type_keeps_its_arrow() {
        let parsed = parse(
            "class C { field: (x:number)=>number = ()=>1; }",
            brokk_bifrost_core::analyzer::Language::TypeScript,
        );
        let signatures: Vec<_> = parsed
            .signatures
            .iter()
            .filter(|(unit, _)| unit.identifier() == "field")
            .flat_map(|(_, signatures)| signatures)
            .collect();
        assert!(!signatures.is_empty());
        assert!(
            signatures
                .iter()
                .all(|signature| signature.contains("=>number")),
            "{signatures:?}"
        );
    }
}
