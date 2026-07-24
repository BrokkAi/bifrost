use super::*;
use crate::analyzer::model::StructuredTypeIdentityBuilder;
use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use crate::analyzer::{
    CallableArity, CallableLinkage, CppTemplateAliasTargetMetadata, CppTemplateExpression,
    CppTemplateMetadata, CppTemplateParameterKind, CppTemplateParameterMetadata, CppTemplateTerm,
    DispatchExtensibility, ParameterMetadata, Range, SignatureMetadata, StructuredTypeIdentity,
    StructuredTypeName,
};
use regex::Regex;
use tree_sitter::{Node, Parser, Tree};

#[derive(Clone)]
pub(super) struct ScopeInfo {
    package_name: String,
    module: Option<CodeUnit>,
    class_unit: Option<CodeUnit>,
    template_signature: Option<String>,
    template_metadata: Option<CppTemplateMetadata>,
    declarations_are_fields: bool,
    recovered_specialization_member_scope: bool,
    /// Namespace targets of every `using namespace X;` directive lexically
    /// visible at this point in the file (declaration order), threaded
    /// forward sibling-by-sibling by the sequential container walk (see
    /// `CppWork::Siblings`). An out-of-line member definition written as a
    /// bare `Class::method` at file/namespace scope with no enclosing
    /// `namespace {}` block (issue #1093, e.g. log4cxx's
    /// `using namespace LOG4CXX_NS; ... LogString HTMLLayout::getContentType()
    /// const { ... }`) has no other structural signal for which namespace
    /// actually owns `Class`; this is the best-effort candidate list used to
    /// recover it so the definition's indexed identity matches its header
    /// declaration's.
    visible_using_namespaces: Vec<String>,
}

struct CppContainer<'tree> {
    node: Node<'tree>,
    scope: ScopeInfo,
}

struct CppNodeWork<'tree> {
    node: Node<'tree>,
    scope: ScopeInfo,
}

/// Cursor over one container's remaining named children, processed one at a
/// time (rather than all at once) so a `using namespace X;` sibling can
/// update `scope.visible_using_namespaces` for the siblings that follow it,
/// matching real C++ using-directive semantics. Nested container work is
/// still pushed and fully drained before the cursor resumes (stack LIFO
/// order), preserving the original left-to-right visitation order.
struct CppSiblingsWork<'tree> {
    parent: Node<'tree>,
    next_index: usize,
    scope: ScopeInfo,
}

enum CppWork<'tree> {
    Container(CppContainer<'tree>),
    Node(CppNodeWork<'tree>),
    Siblings(CppSiblingsWork<'tree>),
}

fn class_like_name(node: Node<'_>, source: &str) -> Option<String> {
    let best = class_like_name_from_children(node, source);
    if let Some(parent) = node.parent()
        && matches!(
            parent.kind(),
            "declaration" | "field_declaration" | "function_definition"
        )
        && node
            .child_by_field_name("name")
            .map(|name_node| {
                cpp_export_macro_token(&normalize_cpp_whitespace(node_text(name_node, source)))
            })
            .unwrap_or(false)
        && let Some(recovered) = exported_class_name_from_node(parent, source)
        && best.as_deref() != Some(recovered.as_str())
    {
        return Some(recovered);
    }
    best.or_else(|| {
        node.child_by_field_name("name")
            .map(|name_node| normalize_cpp_whitespace(node_text(name_node, source)))
            .filter(|name| !name.is_empty() && !cpp_export_macro_token(name))
    })
}

fn class_like_name_from_children(node: Node<'_>, source: &str) -> Option<String> {
    let mut grammar_name = None;
    if let Some(name_node) = node.child_by_field_name("name") {
        let name = normalize_cpp_whitespace(node_text(name_node, source));
        if name.is_empty() {
            return None;
        }
        if !cpp_export_macro_token(&name) {
            return Some(name);
        }
        grammar_name = Some(name);
    }

    let mut best = None;
    let mut cursor = node.walk();
    let mut stack = Vec::new();
    for child in node.named_children(&mut cursor).collect::<Vec<_>>() {
        if matches!(
            child.kind(),
            "field_declaration_list" | "base_class_clause" | "declaration_list" | "enumerator_list"
        ) {
            break;
        }
        stack.push(child);
    }

    while let Some(current) = stack.pop() {
        if matches!(current.kind(), "type_identifier" | "identifier") {
            let name = normalize_cpp_whitespace(node_text(current, source));
            if !name.is_empty() && !cpp_export_macro_token(&name) {
                best = Some(name);
            }
            continue;
        }

        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
    best.or(grammar_name)
}

fn cpp_export_macro_token(token: &str) -> bool {
    token
        .chars()
        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

struct RecoveredExportedClass<'tree> {
    declaration_node: Node<'tree>,
    name: String,
    body: Option<Node<'tree>>,
    raw_supertypes: Option<Vec<String>>,
    uses_initializer_body: bool,
    /// Present only for the fragmented multiple-base export shape (issue #938).
    /// Carries the true class-body byte region -- the members tree-sitter scattered
    /// out of the recovered node -- so they can be reparsed and re-owned as members
    /// rather than lost inside the truncated `initializer_list` stand-in.
    fragmented_body: Option<FragmentedExportBody>,
}

/// The recovered class-body geometry for a fragmented multiple-base export class.
/// `[reparse_start, reparse_end)` is the interior between the class braces, kept
/// verbatim for a padded reparse (issue #941 machinery) so every recovered member
/// keeps its exact original byte/line position. `class_range` is the full class
/// navigation range spanning to the displaced closing brace.
struct FragmentedExportBody {
    reparse_start: usize,
    reparse_end: usize,
    class_range: Range,
}

fn recover_exported_class_declaration<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<RecoveredExportedClass<'tree>> {
    if let Some(recovered) = recover_malformed_exported_multiple_base_class(node, source) {
        return Some(recovered);
    }

    let class_node = first_class_like_child(node)?;
    if let Some(name_node) = class_node.child_by_field_name("name") {
        let class_name = normalize_cpp_whitespace(node_text(name_node, source));
        if cpp_export_macro_token(&class_name) {
            // Tree-sitter can parse `class EXPORT Name` as an EXPORT class plus a
            // Name declarator. Only a bare declarator can be the displaced class name;
            // wrappers describe an object whose type merely happens to look macro-like.
            let mut cursor = node.walk();
            if node
                .children_by_field_name("declarator", &mut cursor)
                .any(|declarator| !matches!(declarator.kind(), "identifier" | "type_identifier"))
            {
                return None;
            }
        } else if has_direct_cpp_declarator(node) {
            return None;
        }
    }
    let name = exported_class_name_from_node(class_node, source)?;
    Some(RecoveredExportedClass {
        declaration_node: class_node,
        name,
        body: cpp_body_node(class_node),
        raw_supertypes: matches!(class_node.kind(), "class_specifier" | "struct_specifier")
            .then(|| extract_cpp_supertypes(class_node, source)),
        uses_initializer_body: false,
        fragmented_body: None,
    })
}

fn recover_malformed_exported_multiple_base_class<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<RecoveredExportedClass<'tree>> {
    if node.kind() != "declaration" {
        return None;
    }
    let class_node = node.child_by_field_name("type")?;
    if class_node.kind() != "class_specifier" || cpp_body_node(class_node).is_some() {
        return None;
    }
    let macro_name = class_node
        .child_by_field_name("name")
        .and_then(|name| direct_identifier_name(name, source))?;
    if !cpp_export_macro_token(&macro_name) {
        return None;
    }

    let mut named_cursor = node.walk();
    let mut named = node.named_children(&mut named_cursor);
    if named
        .next()
        .is_none_or(|child| !same_node(child, class_node))
    {
        return None;
    }
    let displaced = named.next()?;
    if displaced.kind() != "ERROR" {
        return None;
    }
    let name = displaced_exported_class_name(displaced, source)?;

    let remaining = named.collect::<Vec<_>>();
    let init = *remaining.last()?;
    if init.kind() != "init_declarator" {
        return None;
    }
    let final_base = init
        .child_by_field_name("declarator")
        .and_then(|base| recovered_malformed_base_name(base, source))?;
    let body = init.child_by_field_name("value")?;
    // A complete reduction has a real closing brace here. In Chromium's Widget
    // declaration, tree-sitter instead emits the same direct `}` slot as a
    // zero-width missing node where the first body macro truncates the prefix.
    if body.kind() != "initializer_list" || !has_direct_token(body, "}") {
        return None;
    }

    let mut declarator_cursor = node.walk();
    let direct_declarators = node.children_by_field_name("declarator", &mut declarator_cursor);
    if direct_declarators.count() < 2 {
        return None;
    }
    if remaining[..remaining.len() - 1]
        .iter()
        .any(|child| match child.kind() {
            "qualified_identifier"
            | "scoped_type_identifier"
            | "type_identifier"
            | "identifier" => false,
            "ERROR" => !is_malformed_inheritance_access(*child, source),
            _ => true,
        })
    {
        return None;
    }

    let mut raw_supertypes = Vec::new();
    for base in &remaining[..remaining.len() - 1] {
        if base.kind() == "ERROR" {
            continue;
        }
        raw_supertypes.push(recovered_malformed_base_name(*base, source)?);
    }
    raw_supertypes.push(final_base);

    Some(RecoveredExportedClass {
        declaration_node: node,
        name,
        body: Some(body),
        raw_supertypes: Some(raw_supertypes),
        uses_initializer_body: true,
        fragmented_body: fragmented_export_body_region(node, body, source),
    })
}

/// Locate the true class-body region for a fragmented multiple-base export class.
///
/// `node` is the outer `declaration`; `body` is the `initializer_list` tree-sitter
/// emits in place of the real class body. Tree-sitter reduces that body in one of
/// two shapes, both of which lose the members from the recovered node:
///
/// * Complete inline body (one-liner / empty class): the `initializer_list` carries
///   a real closing brace and holds the whole body text inline. The interior between
///   the braces reparses to the members directly.
/// * Truncated body (the QGIS/Chromium shape): the `initializer_list` ends at the
///   first member with a zero-width MISSING `}`; every later member -- and the real
///   closing `}` (a lone-`}` `ERROR`) -- scatters to the declaration's following
///   siblings. The interior runs from the opening brace to that displaced `}`.
///
/// Returns the interior byte range to reparse plus the full class navigation range.
fn fragmented_export_body_region(
    node: Node<'_>,
    body: Node<'_>,
    source: &str,
) -> Option<FragmentedExportBody> {
    let reparse_start = body.start_byte() + 1;
    let close = direct_close_brace(body)?;
    if close.end_byte() > close.start_byte() {
        return Some(FragmentedExportBody {
            reparse_start,
            reparse_end: close.start_byte(),
            class_range: cpp_declaration_range(node),
        });
    }
    // The closing brace was displaced past the recovered node. A balanced nested
    // class keeps its own braces, so the first lone-`}` sibling is this class's.
    let mut sibling = node.next_named_sibling();
    let displaced_close = loop {
        let current = sibling?;
        if cpp_is_stray_close_brace(current, source) {
            break current;
        }
        sibling = current.next_named_sibling();
    };
    Some(FragmentedExportBody {
        reparse_start,
        reparse_end: displaced_close.start_byte(),
        class_range: Range {
            start_byte: node.start_byte(),
            end_byte: displaced_close.end_byte(),
            start_line: node.start_position().row + 1,
            end_line: displaced_close.end_position().row + 1,
        },
    })
}

/// The direct `}` child of a node, real or MISSING (a MISSING brace is zero-width).
fn direct_close_brace(node: Node<'_>) -> Option<Node<'_>> {
    (0..node.child_count())
        .filter_map(|index| node.child(index))
        .find(|child| !child.is_named() && child.kind() == "}")
}

/// A displaced lone closing brace: the class close that the fragmented multiple-base
/// mis-parse split off past the recovered declaration as a bare `}` `ERROR`.
fn cpp_is_stray_close_brace(node: Node<'_>, source: &str) -> bool {
    node.kind() == "ERROR" && node_text(node, source).trim() == "}"
}

fn displaced_exported_class_name(node: Node<'_>, source: &str) -> Option<String> {
    let mut name = None;
    let mut colon_count = 0;
    let mut access_count = 0;
    for index in 0..node.child_count() {
        let child = node.child(index)?;
        match child.kind() {
            "identifier" | "type_identifier" if child.is_named() => {
                if name.is_some() {
                    return None;
                }
                let candidate = normalize_cpp_whitespace(node_text(child, source));
                if candidate.is_empty() || cpp_export_macro_token(&candidate) {
                    return None;
                }
                name = Some(candidate);
            }
            ":" if !child.is_named() => colon_count += 1,
            "public" | "protected" | "private" if !child.is_named() => access_count += 1,
            _ => return None,
        }
    }
    (colon_count == 1 && access_count == 1)
        .then_some(name)
        .flatten()
}

fn is_malformed_inheritance_access(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "ERROR" || node.named_child_count() != 1 {
        return false;
    }
    node.named_child(0)
        .and_then(|child| direct_identifier_name(child, source))
        .is_some_and(|name| matches!(name.as_str(), "public" | "protected" | "private"))
}

fn has_direct_token(node: Node<'_>, expected_kind: &str) -> bool {
    (0..node.child_count()).any(|index| {
        node.child(index)
            .is_some_and(|child| !child.is_named() && child.kind() == expected_kind)
    })
}

fn recovered_malformed_base_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "type_identifier" | "identifier" | "namespace_identifier" => {
            recovered_base_atom(node, source)
        }
        "template_type" | "template_function" => node
            .child_by_field_name("name")
            .and_then(|name| recovered_malformed_base_name(name, source)),
        "ERROR" => None,
        "qualified_identifier" | "scoped_type_identifier" => {
            let suffix = node
                .child_by_field_name("name")
                .and_then(|name| recovered_malformed_base_name(name, source))?;
            let scope = node
                .child_by_field_name("scope")
                .and_then(|scope| recovered_malformed_base_name(scope, source))?;
            let prefix = if matches!(scope.as_str(), "public" | "protected" | "private") {
                malformed_qualified_prefix(node, source)?
            } else {
                if malformed_qualified_prefix(node, source).is_some() {
                    return None;
                }
                scope
            };
            Some(format!("{prefix}::{suffix}"))
        }
        _ => None,
    }
}

fn recovered_base_atom(node: Node<'_>, source: &str) -> Option<String> {
    if !matches!(
        node.kind(),
        "identifier" | "type_identifier" | "namespace_identifier"
    ) {
        return None;
    }
    let name = normalize_cpp_whitespace(node_text(node, source));
    (!name.is_empty()).then_some(name)
}

fn malformed_qualified_prefix(node: Node<'_>, source: &str) -> Option<String> {
    let mut prefix = None;
    let mut cursor = node.walk();
    for error in node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "ERROR")
    {
        if error.named_child_count() != 1 || prefix.is_some() {
            return None;
        }
        prefix = error
            .named_child(0)
            .and_then(|child| recovered_base_atom(child, source));
        prefix.as_ref()?;
    }
    prefix
}

fn recover_exported_class_function_definition<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, String)> {
    if node.kind() != "function_definition" {
        return None;
    }
    let type_node = node.child_by_field_name("type")?;
    let declarator = node.child_by_field_name("declarator")?;

    if matches!(
        type_node.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier"
    ) {
        if type_node
            .child_by_field_name("name")
            .and_then(|name| direct_identifier_name(name, source))
            .is_some_and(|name| cpp_export_macro_token(&name))
        {
            let mut cursor = node.walk();
            let errors_before_declarator = node
                .named_children(&mut cursor)
                .filter(|child| {
                    child.kind() == "ERROR"
                        && child.start_byte() >= type_node.end_byte()
                        && child.end_byte() <= declarator.start_byte()
                })
                .collect::<Vec<_>>();
            if let Some(name) = errors_before_declarator
                .iter()
                .find_map(|error| displaced_exported_class_name(*error, source))
            {
                return Some((node, name));
            }
            if errors_before_declarator
                .iter()
                .any(|error| malformed_inheritance_syntax(*error))
            {
                return None;
            }
        }
        if let Some(name) = direct_identifier_name(declarator, source)
            && !cpp_export_macro_token(&name)
        {
            return Some((node, name));
        }
        if declarator.kind() == "parenthesized_declarator"
            && type_node
                .child_by_field_name("name")
                .and_then(|name| direct_identifier_name(name, source))
                .is_some_and(|name| cpp_export_macro_token(&name))
        {
            let body_start = node
                .child_by_field_name("body")
                .map(|body| body.start_byte())
                .unwrap_or(node.end_byte());
            let mut cursor = node.walk();
            if let Some(name) = node
                .named_children(&mut cursor)
                .filter(|child| {
                    child.kind() == "ERROR"
                        && child.start_byte() >= declarator.end_byte()
                        && child.end_byte() <= body_start
                })
                .find_map(|error| declarator_name_from_node(error, source))
            {
                return Some((node, name));
            }
        }
    }

    let declarator_text = direct_identifier_name(declarator, source)?;
    if !matches!(declarator_text.as_str(), "class" | "struct" | "union") {
        return None;
    }
    class_identifier_before_body(node, source).map(|name| (node, name))
}

fn malformed_inheritance_syntax(node: Node<'_>) -> bool {
    (0..node.child_count()).any(|index| {
        node.child(index)
            .is_some_and(|child| matches!(child.kind(), ":" | "public" | "protected" | "private"))
    })
}

pub(crate) fn is_recovered_exported_class_container(node: Node<'_>, source: &str) -> bool {
    recover_exported_class_function_definition(node, source).is_some()
}

fn preserves_declaration_scope_through_wrapper(kind: &str, in_class_scope: bool) -> bool {
    matches!(
        kind,
        "ERROR"
            | "preproc_if"
            | "preproc_ifdef"
            | "preproc_ifndef"
            | "preproc_else"
            | "preproc_elif"
    ) || (kind == "labeled_statement" && in_class_scope)
}

pub(crate) fn is_direct_recovered_exported_class_field_declaration(
    node: Node<'_>,
    source: &str,
) -> bool {
    if node.kind() != "declaration" {
        return false;
    }
    let mut ancestor = node.parent();
    while let Some(container) = ancestor {
        match container.kind() {
            "compound_statement" => {
                return container.parent().is_some_and(|class_container| {
                    is_recovered_exported_class_container(class_container, source)
                });
            }
            // These containers preserve ScopeInfo in visit_node. declaration_list is
            // the body container selected for a linkage specification.
            "template_declaration" | "linkage_specification" | "declaration_list" => {}
            kind if preserves_declaration_scope_through_wrapper(kind, true) => {}
            _ => return false,
        }
        ancestor = container.parent();
    }
    false
}

pub(crate) fn recovered_exported_class_has_body(
    node: Node<'_>,
    source: &str,
    expected_name: &str,
) -> Option<bool> {
    match node.kind() {
        "function_definition" => {
            let (class_node, name) = recover_exported_class_function_definition(node, source)?;
            (name == expected_name).then(|| cpp_body_node(class_node).is_some())
        }
        "declaration" | "field_declaration" => {
            let recovered = recover_exported_class_declaration(node, source)?;
            (recovered.name == expected_name).then(|| recovered.body.is_some())
        }
        _ => None,
    }
}

fn class_identifier_before_body(node: Node<'_>, source: &str) -> Option<String> {
    let body_start = node
        .child_by_field_name("body")
        .map(|body| body.start_byte())
        .unwrap_or(node.end_byte());
    let mut stack = Vec::new();
    for index in (0..node.named_child_count()).rev() {
        let Some(child) = node.named_child(index) else {
            continue;
        };
        if child.start_byte() >= body_start {
            continue;
        }
        stack.push(child);
    }

    let mut best = None;
    while let Some(current) = stack.pop() {
        if matches!(current.kind(), "identifier" | "type_identifier") {
            let name = normalize_cpp_whitespace(node_text(current, source));
            if !name.is_empty()
                && !cpp_export_macro_token(&name)
                && !matches!(name.as_str(), "class" | "struct" | "union")
            {
                best = Some(name);
            }
            continue;
        }

        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index)
                && child.start_byte() < body_start
            {
                stack.push(child);
            }
        }
    }
    best
}

fn exported_class_name_from_node(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() == "declaration"
        && node
            .child_by_field_name("type")
            .or_else(|| first_class_like_child(node))
            .is_some_and(|type_node| {
                matches!(
                    type_node.kind(),
                    "class_specifier" | "struct_specifier" | "union_specifier"
                )
            })
        && let Some(name) = node
            .child_by_field_name("declarator")
            .and_then(|declarator| declarator_name_from_node(declarator, source))
        && !cpp_export_macro_token(&name)
    {
        return Some(name);
    }

    if node.kind() == "function_definition"
        && node.child_by_field_name("type").is_some_and(|type_node| {
            matches!(
                type_node.kind(),
                "class_specifier" | "struct_specifier" | "union_specifier"
            )
        })
        && let Some(name) = node
            .child_by_field_name("declarator")
            .and_then(|declarator| direct_identifier_name(declarator, source))
        && !cpp_export_macro_token(&name)
    {
        return Some(name);
    }

    let class_node = if matches!(
        node.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier"
    ) {
        node
    } else {
        first_class_like_child(node)?
    };
    class_like_name_from_children(class_node, source)
}

fn direct_identifier_name(node: Node<'_>, source: &str) -> Option<String> {
    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "type_identifier"
    ) {
        return None;
    }
    let name = normalize_cpp_whitespace(node_text(node, source));
    (!name.is_empty()).then_some(name)
}

fn declarator_name_from_node(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" | "type_identifier" => {
            let name = normalize_cpp_whitespace(node_text(node, source));
            (!name.is_empty()).then_some(name)
        }
        _ => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(|child| declarator_name_from_node(child, source))
        }
    }
}

fn first_class_like_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        )
    })
}

/// Push a container's children as a `Siblings` cursor rather than snapshotting
/// them all with one shared scope: children are visited one at a time so a
/// `using namespace X;` sibling can affect the scope threaded to the siblings
/// that textually follow it (issue #1093).
fn push_cpp_container_work<'tree>(
    node: Node<'tree>,
    scope: ScopeInfo,
    stack: &mut Vec<CppWork<'tree>>,
) {
    stack.push(CppWork::Siblings(CppSiblingsWork {
        parent: node,
        next_index: 0,
        scope,
    }));
}

/// Advance a `Siblings` cursor by one child: dispatch the current child under
/// the scope accumulated from its *earlier* siblings, then push a
/// continuation for the remaining siblings carrying the scope updated for
/// *this* child (only `using namespace X;` directives change it). Pushing the
/// continuation before the current child's own node work means the current
/// child's subtree fully drains (LIFO) before the next sibling is visited,
/// preserving left-to-right order.
fn advance_cpp_siblings<'tree>(
    siblings: CppSiblingsWork<'tree>,
    source: &str,
    stack: &mut Vec<CppWork<'tree>>,
) {
    let Some(child) = siblings.parent.named_child(siblings.next_index) else {
        return;
    };
    let current_scope = siblings.scope.clone();
    let mut next_scope = siblings.scope;
    if let Some(namespace) = cpp_using_namespace_target(child, source) {
        next_scope.visible_using_namespaces.push(namespace);
    }
    stack.push(CppWork::Siblings(CppSiblingsWork {
        parent: siblings.parent,
        next_index: siblings.next_index + 1,
        scope: next_scope,
    }));
    stack.push(CppWork::Node(CppNodeWork {
        node: child,
        scope: current_scope,
    }));
}

/// The namespace target of a `using namespace X;` directive, or `None` for
/// any other `using_declaration` shape (`using X;`, `using X::Y;`) or node
/// kind. Distinguished structurally by the presence of the grammar's literal
/// `namespace` keyword token among the node's children -- not by inspecting
/// source text -- so it never misreads a member-importing using-declaration
/// as a namespace directive.
fn cpp_using_namespace_target(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "using_declaration" {
        return None;
    }
    let mut cursor = node.walk();
    let is_namespace_directive = node
        .children(&mut cursor)
        .any(|child| child.kind() == "namespace");
    if !is_namespace_directive {
        return None;
    }
    let target = node.named_child(0)?;
    let text = normalize_cpp_whitespace(node_text(target, source));
    (!text.is_empty()).then_some(text)
}

/// Every `using namespace X;` directive target in a file, in source order, for
/// resolution-time consumers that need the file's using-directives without the
/// per-position scope threading extraction does. Parses `source` fresh and
/// walks the tree structurally, reusing `cpp_using_namespace_target` (which
/// keys on the grammar's `namespace` keyword token, not source text), so it
/// never misreads a member-importing `using X::Y;` as a namespace directive.
///
/// This is a whole-file over-approximation of what is in scope at any one point
/// (a directive nested inside a `namespace {}` block or a function body is still
/// reported), which is exactly what the #1134 identity reconciler wants: extra
/// candidate namespaces that no visible class confirms are harmless, and two
/// that both confirm are treated as a genuine ambiguity by the reconciler.
pub(crate) fn cpp_file_using_namespaces(source: &str) -> Vec<String> {
    let mut parser = Parser::new();
    if parser.set_language(&tree_sitter_cpp::LANGUAGE.into()).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let mut namespaces = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if let Some(namespace) = cpp_using_namespace_target(node, source)
            && seen.insert(namespace.clone())
        {
            namespaces.push(namespace);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    namespaces
}

pub(super) struct CppVisitor<'a> {
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) parsed: &'a mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
    pub(super) recovered_class_sibling_scopes: HashMap<usize, ScopeInfo>,
    /// Byte regions whose contents were re-owned by a fragmented export-class
    /// recovery (#938): the scattered members between the fragmented
    /// declaration and its displaced closing brace are indexed as members of
    /// the recovered class by the region reparse, so the ordinary sibling walk
    /// must not ALSO index them as top-level declarations (that double-indexing
    /// made a scattered nested class ambiguous between `Inner` and
    /// `Widget$Inner`). Regions are rare (one per fragmented recovery), so a
    /// linear scan at visit time is fine.
    pub(super) consumed_fragment_regions: Vec<(usize, usize)>,
}

impl<'a> CppVisitor<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn visit_container(
        &mut self,
        node: Node<'_>,
        package_name: &str,
        module: Option<CodeUnit>,
        class_unit: Option<CodeUnit>,
        template_signature: Option<String>,
        visible_using_namespaces: Vec<String>,
    ) {
        let scope = ScopeInfo {
            package_name: package_name.to_string(),
            module,
            class_unit,
            template_signature,
            template_metadata: None,
            declarations_are_fields: false,
            recovered_specialization_member_scope: false,
            visible_using_namespaces,
        };
        self.run_container_work(node, scope);
    }

    /// Whether a work node lies entirely inside a byte region consumed by a
    /// fragmented export-class recovery (#938); such nodes were already indexed
    /// as members of the recovered class by the region reparse.
    fn node_is_inside_consumed_fragment(&self, node: Node<'_>) -> bool {
        self.consumed_fragment_regions
            .iter()
            .any(|&(start, end)| node.start_byte() >= start && node.end_byte() <= end)
    }

    /// Drive the container work loop from an explicit seed scope to completion. The
    /// loop is self-contained so a locally-owned reparsed tree (issue #938/#941)
    /// stays alive for the whole traversal.
    fn run_container_work<'tree>(&mut self, node: Node<'tree>, scope: ScopeInfo) {
        let mut stack = vec![CppWork::Container(CppContainer { node, scope })];
        while let Some(work) = stack.pop() {
            match work {
                CppWork::Container(container) => {
                    push_cpp_container_work(container.node, container.scope, &mut stack);
                }
                CppWork::Siblings(siblings) => {
                    advance_cpp_siblings(siblings, self.source, &mut stack);
                }
                CppWork::Node(work) => {
                    if self.node_is_inside_consumed_fragment(work.node) {
                        continue;
                    }
                    self.visit_node(work.node, &work.scope, &mut stack);
                }
            }
        }
    }

    /// Reparse the fragmented multiple-base export class body (issue #938) and index
    /// its contents as members of `class_unit`. The interior is reparsed in a padded
    /// copy (issue #941's `cpp_reparse_region_items`) so every member keeps its exact
    /// original byte/line position; the reparse is admitted only when it is entirely
    /// member-shaped, so a well-formed body is the sole thing re-owned this way.
    fn visit_fragmented_export_class_members(
        &mut self,
        fragmented: &FragmentedExportBody,
        class_unit: CodeUnit,
        scope: &ScopeInfo,
    ) {
        if fragmented.reparse_start >= fragmented.reparse_end {
            return;
        }
        let Some((_padded, tree)) = cpp_reparse_region_items(
            self.source,
            fragmented.reparse_start,
            fragmented.reparse_end,
        ) else {
            return;
        };
        let root = tree.root_node();
        if !cpp_reparsed_members_are_indexable(root, self.source) {
            return;
        }
        let member_scope = ScopeInfo {
            package_name: scope.package_name.clone(),
            module: scope.module.clone(),
            class_unit: Some(class_unit),
            template_signature: scope.template_signature.clone(),
            template_metadata: None,
            declarations_are_fields: true,
            recovered_specialization_member_scope: false,
            visible_using_namespaces: scope.visible_using_namespaces.clone(),
        };
        self.run_container_work(root, member_scope);
    }

    fn visit_node<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        if let Some(recovered_scope) = self.recovered_class_sibling_scopes.remove(&node.id()) {
            self.visit_node(node, &recovered_scope, stack);
            return;
        }
        match node.kind() {
            "template_declaration" => {
                for index in (0..node.named_child_count()).rev() {
                    let Some(child) = node.named_child(index) else {
                        continue;
                    };
                    if matches!(
                        child.kind(),
                        "class_specifier"
                            | "struct_specifier"
                            | "union_specifier"
                            | "enum_specifier"
                            | "function_definition"
                            | "declaration"
                            | "field_declaration"
                            | "alias_declaration"
                            | "namespace_definition"
                    ) {
                        let mut template_scope = scope.clone();
                        template_scope.template_signature =
                            cpp_template_signature(node, child, self.source);
                        template_scope.template_metadata =
                            cpp_template_metadata(node, child, self.source);
                        if let Some(recovered) =
                            recover_fragmented_partial_specialization(node, child, self.source)
                        {
                            let code_unit = self.visit_named_class_like_shape(
                                recovered.declaration_node,
                                recovered.name,
                                None,
                                true,
                                Some(recovered.range),
                                None,
                                &template_scope,
                                stack,
                            );
                            let mut member_scope = template_scope.clone();
                            member_scope.class_unit = Some(code_unit);
                            member_scope.declarations_are_fields = true;
                            member_scope.recovered_specialization_member_scope = true;
                            for prefix_member in recovered.prefix_members.into_iter().rev() {
                                stack.push(CppWork::Node(CppNodeWork {
                                    node: prefix_member,
                                    scope: member_scope.clone(),
                                }));
                            }
                            for sibling in recovered.member_siblings {
                                self.recovered_class_sibling_scopes
                                    .insert(sibling.id(), member_scope.clone());
                            }
                            for following in recovered.following_declarations.into_iter().rev() {
                                stack.push(CppWork::Node(CppNodeWork {
                                    node: following,
                                    scope: scope.clone(),
                                }));
                            }
                            return;
                        }
                        stack.push(CppWork::Node(CppNodeWork {
                            node: child,
                            scope: template_scope,
                        }));
                    }
                }
            }
            "namespace_definition" => self.visit_namespace(node, scope, stack),
            "linkage_specification" => {
                if let Some(body) = cpp_body_node(node) {
                    stack.push(CppWork::Container(CppContainer {
                        node: body,
                        scope: scope.clone(),
                    }));
                } else {
                    stack.push(CppWork::Container(CppContainer {
                        node,
                        scope: scope.clone(),
                    }));
                }
            }
            "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier" => {
                self.visit_class_like(node, scope, stack)
            }
            "function_definition" => self.visit_function_definition(node, scope, stack),
            "declaration" => {
                if scope.class_unit.is_some()
                    && scope.declarations_are_fields
                    && scope.recovered_specialization_member_scope
                    && let Some(alias_name) =
                        recovered_using_declaration_alias_name(node, self.source)
                {
                    self.add_type_aliases(node, scope, vec![alias_name]);
                } else {
                    self.visit_declaration(node, scope, scope.declarations_are_fields, stack)
                }
            }
            "field_declaration" => self.visit_declaration(node, scope, true, stack),
            "type_definition" | "alias_declaration" => {
                self.visit_type_declaration(node, scope, stack)
            }
            "preproc_def" | "preproc_function_def" => self.visit_macro(node),
            "preproc_include" => self.visit_include(node),
            kind if preserves_declaration_scope_through_wrapper(
                kind,
                scope.class_unit.is_some(),
            ) =>
            {
                stack.push(CppWork::Container(CppContainer {
                    node,
                    scope: scope.clone(),
                }))
            }
            _ => {}
        }
    }

    fn visit_namespace<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        let name_node = node.child_by_field_name("name");
        let Some(name_node) = name_node else {
            if let Some(body) = cpp_body_node(node) {
                stack.push(CppWork::Container(CppContainer {
                    node: body,
                    scope: scope.clone(),
                }));
            }
            return;
        };
        let name = normalize_cpp_whitespace(node_text(name_node, self.source));
        if name.is_empty() {
            return;
        }
        let full_name = if scope.package_name.is_empty() {
            name
        } else {
            format!("{}::{}", scope.package_name, name)
        };
        let module = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Module,
            "",
            full_name.clone(),
        );
        if !self.parsed.contains_declaration(&module) {
            self.parsed
                .add_code_unit(module.clone(), node, self.source, None, None);
        }

        let namespace_scope = ScopeInfo {
            package_name: full_name,
            module: Some(module),
            class_unit: scope.class_unit.clone(),
            template_signature: scope.template_signature.clone(),
            template_metadata: scope.template_metadata.clone(),
            declarations_are_fields: false,
            recovered_specialization_member_scope: false,
            visible_using_namespaces: scope.visible_using_namespaces.clone(),
        };
        let container = cpp_body_node(node).unwrap_or(node);
        stack.push(CppWork::Container(CppContainer {
            node: container,
            scope: namespace_scope,
        }));
    }

    fn visit_class_like<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        let Some(name) = class_like_name(node, self.source) else {
            return;
        };
        self.visit_named_class_like(node, name, scope, stack);
    }

    fn visit_named_class_like<'tree>(
        &mut self,
        node: Node<'tree>,
        name: String,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        let body = cpp_body_node(node);
        let definition_body_present = body.is_some();
        let raw_supertypes = matches!(node.kind(), "class_specifier" | "struct_specifier")
            .then(|| extract_cpp_supertypes(node, self.source));
        self.visit_named_class_like_shape(
            node,
            name,
            body,
            definition_body_present,
            None,
            raw_supertypes,
            scope,
            stack,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn visit_named_class_like_shape<'tree>(
        &mut self,
        declaration_node: Node<'tree>,
        name: String,
        body: Option<Node<'tree>>,
        definition_body_present: bool,
        explicit_range: Option<Range>,
        raw_supertypes: Option<Vec<String>>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
    ) -> CodeUnit {
        let short_name = if let Some(parent) = &scope.class_unit {
            format!("{}${name}", parent.short_name())
        } else {
            name
        };
        let code_unit = CodeUnit::with_signature(
            self.file.clone(),
            CodeUnitType::Class,
            scope.package_name.clone(),
            short_name,
            scope.template_signature.clone(),
            false,
        );
        let has_body = definition_body_present;
        if !has_body && self.parsed.contains_declaration(&code_unit) {
            self.parsed.record_navigation_range(
                code_unit.clone(),
                explicit_range.unwrap_or_else(|| cpp_declaration_range(declaration_node)),
            );
            return code_unit;
        }
        if has_body {
            if let Some(range) = explicit_range {
                self.parsed
                    .replace_code_unit_with_range(code_unit.clone(), range, None, None);
            } else {
                self.parsed.replace_code_unit(
                    code_unit.clone(),
                    declaration_node,
                    self.source,
                    None,
                    None,
                );
            }
        } else {
            self.parsed
                .add_code_unit(code_unit.clone(), declaration_node, self.source, None, None);
        }
        if let Some(raw_supertypes) = raw_supertypes {
            self.parsed
                .set_raw_supertypes(code_unit.clone(), raw_supertypes);
        }
        self.parsed.add_signature(
            code_unit.clone(),
            render_cpp_type_signature(
                declaration_node,
                self.source,
                scope.template_signature.as_deref(),
            ),
        );
        if let Some(metadata) = &scope.template_metadata {
            let primary_short_name = if let Some(parent) = &scope.class_unit {
                format!("{}${}", parent.short_name(), metadata.primary_name)
            } else {
                metadata.primary_name.clone()
            };
            let primary_fq_name = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Class,
                scope.package_name.clone(),
                primary_short_name,
            )
            .fq_name();
            let mut metadata = metadata.clone();
            metadata.primary_fq_name = primary_fq_name;
            self.parsed
                .set_cpp_template_metadata(code_unit.clone(), metadata);
        }
        if let Some(parent) = &scope.class_unit {
            self.parsed.add_child(parent.clone(), code_unit.clone());
        } else if let Some(module) = &scope.module {
            self.parsed.add_child(module.clone(), code_unit.clone());
        }

        if let Some(body) = body {
            let mut nested_scope = scope.clone();
            nested_scope.class_unit = Some(code_unit.clone());
            nested_scope.template_signature = scope.template_signature.clone();
            // Template metadata describes the class just created. It must not
            // leak into ordinary nested declarations in that class's body.
            // Recovered export-macro specializations carry a separate scope bit
            // for their declaration-shaped body members.
            nested_scope.template_metadata = None;
            // Export-macro class bodies recovered from a function_definition use
            // compound_statement children, whose direct fields are declarations.
            nested_scope.recovered_specialization_member_scope =
                scope.template_metadata.as_ref().is_some_and(|metadata| {
                    declaration_node.kind() == "function_definition"
                        && !metadata.specialization_arguments.is_empty()
                });
            nested_scope.declarations_are_fields =
                is_recovered_exported_class_container(declaration_node, self.source)
                    || nested_scope.recovered_specialization_member_scope;
            stack.push(CppWork::Container(CppContainer {
                node: body,
                scope: nested_scope,
            }));
        }
        if declaration_node.kind() == "enum_specifier" {
            self.visit_enum_enumerators(declaration_node, scope, &code_unit);
            if !self.has_enum_enumerator_units(&code_unit) {
                self.visit_enum_enumerators_from_text(declaration_node, scope, &code_unit);
            }
        }
        code_unit
    }

    fn has_enum_enumerator_units(&self, parent: &CodeUnit) -> bool {
        let prefix = format!("{}.", parent.short_name());
        self.parsed.declarations().iter().any(|unit| {
            unit.kind() == CodeUnitType::Field
                && unit.source() == parent.source()
                && unit.package_name() == parent.package_name()
                && unit.short_name().starts_with(&prefix)
        })
    }

    fn visit_enum_enumerators(&mut self, node: Node<'_>, scope: &ScopeInfo, parent: &CodeUnit) {
        walk_named_tree_preorder(node, false, |child| {
            if child.kind() != "enumerator" {
                return WalkControl::Continue;
            }
            let Some(name_node) = child.child_by_field_name("name") else {
                return WalkControl::Continue;
            };
            let name = normalize_cpp_whitespace(node_text(name_node, self.source));
            if name.is_empty() {
                return WalkControl::Continue;
            }
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), name),
            );
            if self.parsed.contains_declaration(&code_unit) {
                return WalkControl::Continue;
            }
            self.parsed
                .add_code_unit(code_unit.clone(), child, self.source, None, None);
            self.parsed.add_signature(
                code_unit.clone(),
                normalize_cpp_whitespace(node_text(child, self.source)),
            );
            self.parsed.add_child(parent.clone(), code_unit);
            WalkControl::Continue
        });
    }

    fn visit_enum_enumerators_from_text(
        &mut self,
        node: Node<'_>,
        scope: &ScopeInfo,
        parent: &CodeUnit,
    ) {
        let text = node_text(node, self.source);
        let Some((_, body)) = text.split_once('{') else {
            return;
        };
        let Some((body, _)) = body.rsplit_once('}') else {
            return;
        };
        for entry in body.split(',') {
            let trimmed = entry.trim();
            let name = trimmed
                .split('=')
                .next()
                .unwrap_or("")
                .split_whitespace()
                .next()
                .unwrap_or("");
            if name.is_empty() {
                continue;
            }
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), name),
            );
            if self.parsed.contains_declaration(&code_unit) {
                continue;
            }
            self.parsed
                .add_code_unit(code_unit.clone(), node, self.source, None, None);
            self.parsed
                .add_signature(code_unit.clone(), trimmed.to_string());
            self.parsed.add_child(parent.clone(), code_unit);
        }
    }

    fn visit_function_definition<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        // A file-scope object-like macro sentinel the parser cannot see (issue
        // #941, e.g. `BEGIN_NS`/`END_NS`) makes tree-sitter recover the region it
        // prefixes as a bogus `function_definition` that swallows real namespaces,
        // classes, and members. Reparse the swallowed interior as C++ items so the
        // ordinary declaration visitors index it with byte/line-exact ownership.
        if self.visit_sentinel_macro_region(node, scope) {
            return;
        }
        if let Some((class_node, name)) =
            recover_exported_class_function_definition(node, self.source)
        {
            let mut stack = Vec::new();
            self.visit_named_class_like(class_node, name, scope, &mut stack);
            while let Some(work) = stack.pop() {
                match work {
                    CppWork::Container(container) => {
                        push_cpp_container_work(container.node, container.scope, &mut stack);
                    }
                    CppWork::Siblings(siblings) => {
                        advance_cpp_siblings(siblings, self.source, &mut stack);
                    }
                    CppWork::Node(work) => self.visit_node(work.node, &work.scope, &mut stack),
                }
            }
            return;
        }
        let Some(declarator) = node.child_by_field_name("declarator") else {
            self.visit_malformed_function_definition_container(node, scope, stack);
            return;
        };
        let Some(function_declarator) = extract_function_declarator(declarator) else {
            self.visit_malformed_function_definition_container(node, scope, stack);
            return;
        };
        let Some(function) = extract_function_info(function_declarator, self.source, scope) else {
            self.visit_malformed_function_definition_container(node, scope, stack);
            return;
        };
        let code_unit = function.code_unit(self.file.clone());
        // Keep an earlier same-file prototype as another physical occurrence
        // of this callable. `CodeUnit` already identifies the role-neutral
        // overload, while ranges and signature metadata describe its
        // declaration/definition occurrences.
        self.parsed
            .add_code_unit(code_unit.clone(), node, self.source, None, None);
        let signature = render_cpp_function_display_signature_from_node(
            node,
            self.source,
            scope.template_signature.as_deref(),
            true,
        );
        self.parsed.add_signature_with_metadata(
            code_unit.clone(),
            cpp_signature_metadata(signature, function_declarator, self.source)
                .with_declaration_only(false)
                .with_callable_linkage(cpp_callable_linkage(node, self.source)),
        );
        if let Some(parent) = &scope.class_unit {
            self.parsed.add_child(parent.clone(), code_unit);
        } else if let Some(module) = &scope.module {
            self.parsed.add_child(module.clone(), code_unit);
        }
    }

    fn visit_malformed_function_definition_container<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        let Some(body) = cpp_body_node(node) else {
            return;
        };
        if !cpp_contains_namespace_definition(body) {
            return;
        }
        stack.push(CppWork::Container(CppContainer {
            node: body,
            scope: scope.clone(),
        }));
    }

    /// Recover the declarations swallowed by a bare begin/end macro-sentinel pair
    /// (issue #941). When `node` is the bogus `function_definition` tree-sitter
    /// emits for a sentinel-prefixed region, reparse the interior after the
    /// sentinel identifier as real C++ items -- in a padded copy of the file so
    /// every reparsed node keeps its original byte/line position -- and run the
    /// ordinary container visitation over the result. Returns `true` when it fired
    /// (the caller must then skip normal function processing). Nested sentinel
    /// regions recover recursively: the reparsed interior is walked through the
    /// same `visit_function_definition` path, so a sentinel inside the region hits
    /// this recovery again.
    fn visit_sentinel_macro_region(&mut self, node: Node<'_>, scope: &ScopeInfo) -> bool {
        let Some((start, end)) = cpp_sentinel_macro_region(node, self.source) else {
            return false;
        };
        let Some((_padded, tree)) = cpp_reparse_region_items(self.source, start, end) else {
            return false;
        };
        let root = tree.root_node();
        if !cpp_reparsed_items_are_indexable(root, self.source) {
            return false;
        }
        self.visit_container(
            root,
            &scope.package_name,
            scope.module.clone(),
            scope.class_unit.clone(),
            scope.template_signature.clone(),
            scope.visible_using_namespaces.clone(),
        );
        true
    }

    fn visit_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        in_class_body: bool,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        let recovered_alias_names = recovered_type_alias_names(node, self.source);
        if !recovered_alias_names.is_empty() {
            self.add_type_aliases(node, scope, recovered_alias_names);
            return;
        }

        if let Some(recovered) = recover_exported_class_declaration(node, self.source) {
            if let Some(fragmented) = recovered.fragmented_body {
                // Issue #938: the members tree-sitter scattered out of the fragmented
                // multiple-base export node are reparsed from their true body region
                // and re-owned as members of the recovered class, with an explicit
                // navigation range spanning to the displaced closing brace.
                let code_unit = self.visit_named_class_like_shape(
                    recovered.declaration_node,
                    recovered.name,
                    None,
                    true,
                    Some(fragmented.class_range),
                    recovered.raw_supertypes,
                    scope,
                    stack,
                );
                let consumed_region = (
                    recovered.declaration_node.end_byte(),
                    fragmented.class_range.end_byte,
                );
                self.visit_fragmented_export_class_members(&fragmented, code_unit, scope);
                // Everything between the fragmented declaration and its displaced
                // closing brace now belongs to the recovered class; keep the
                // ordinary walk from re-indexing those scattered siblings at top
                // level. Registered AFTER the member reparse above because the
                // padded reparse's nodes deliberately carry their original byte
                // offsets (inside this very region) and must not be suppressed;
                // the outer tree's sibling work items are visited later, so the
                // ordering still shields them.
                self.consumed_fragment_regions.push(consumed_region);
                return;
            }
            let uses_initializer_body = recovered.uses_initializer_body;
            let definition_body_present = recovered.body.is_some();
            self.visit_named_class_like_shape(
                recovered.declaration_node,
                recovered.name,
                recovered.body,
                definition_body_present,
                None,
                recovered.raw_supertypes,
                scope,
                stack,
            );
            if uses_initializer_body {
                return;
            }
        }

        let mut handled_function = false;
        let mut handled_declarator = false;
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if matches!(
                child.kind(),
                "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
            ) {
                if in_class_body && !has_direct_cpp_declarator(node) {
                    self.visit_class_like(child, scope, stack);
                }
                continue;
            }
        }

        let mut cursor = node.walk();
        for child in node.children_by_field_name("declarator", &mut cursor) {
            if super::structural::is_recovered_designator_init_declarator(child) {
                handled_declarator = true;
                continue;
            }
            if let Some(kind) = classify_declarator(child) {
                handled_declarator = true;
                match kind {
                    DeclaratorKind::Function(function_declarator) => {
                        handled_function = true;
                        self.visit_function_declaration(node, function_declarator, scope);
                    }
                    DeclaratorKind::Variable(variable_declarator) => {
                        self.visit_variable_declaration(
                            node,
                            variable_declarator,
                            scope,
                            in_class_body,
                        );
                    }
                }
            }
        }

        if !handled_declarator {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if super::structural::is_recovered_designator_init_declarator(child) {
                    handled_declarator = true;
                    continue;
                }
                if !is_unfielded_declarator_candidate(child) {
                    continue;
                }
                let Some(kind) = classify_declarator(child) else {
                    continue;
                };
                handled_declarator = true;
                match kind {
                    DeclaratorKind::Function(function_declarator) => {
                        handled_function = true;
                        self.visit_function_declaration(node, function_declarator, scope);
                    }
                    DeclaratorKind::Variable(variable_declarator) => {
                        self.visit_variable_declaration(
                            node,
                            variable_declarator,
                            scope,
                            in_class_body,
                        );
                    }
                }
            }
        }

        if handled_function {
            return;
        }

        if !handled_declarator {
            if in_class_body {
                self.visit_class_members_from_declaration(node, scope);
            } else {
                self.visit_global_variables_from_declaration(node, scope);
            }
        }
    }

    fn visit_function_declaration(
        &mut self,
        declaration_node: Node<'_>,
        declarator: Node<'_>,
        scope: &ScopeInfo,
    ) {
        let Some(function) = extract_function_info(declarator, self.source, scope) else {
            return;
        };
        let code_unit =
            function.code_unit_with_synthetic(self.file.clone(), scope.class_unit.is_some());
        if self.parsed.contains_declaration(&code_unit) {
            self.parsed
                .record_navigation_range(code_unit, cpp_declaration_range(declaration_node));
            return;
        }
        self.parsed
            .add_code_unit(code_unit.clone(), declaration_node, self.source, None, None);
        let signature = render_cpp_function_display_signature_from_node(
            declaration_node,
            self.source,
            scope.template_signature.as_deref(),
            false,
        );
        self.parsed.add_signature_with_metadata(
            code_unit.clone(),
            cpp_signature_metadata(signature, declarator, self.source)
                .with_declaration_only(true)
                .with_callable_linkage(cpp_callable_linkage(declaration_node, self.source)),
        );
        if let Some(parent) = &scope.class_unit {
            self.parsed.add_child(parent.clone(), code_unit);
        } else if let Some(module) = &scope.module {
            self.parsed.add_child(module.clone(), code_unit);
        }
    }

    fn visit_variable_declaration(
        &mut self,
        declaration_node: Node<'_>,
        declarator: Node<'_>,
        scope: &ScopeInfo,
        in_class_body: bool,
    ) {
        let Some(name) = extract_variable_name(declarator, self.source) else {
            return;
        };
        let short_name = if in_class_body {
            let Some(parent) = &scope.class_unit else {
                return;
            };
            format!("{}.{}", parent.short_name(), name)
        } else {
            name
        };
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Field,
            scope.package_name.clone(),
            short_name,
        );
        if self.parsed.contains_declaration(&code_unit) {
            return;
        }
        self.parsed
            .add_code_unit(code_unit.clone(), declaration_node, self.source, None, None);
        self.parsed.add_signature(
            code_unit.clone(),
            render_cpp_field_signature(declaration_node, declarator, self.source),
        );
        if let Some(parent) = &scope.class_unit {
            self.parsed.add_child(parent.clone(), code_unit);
        } else if let Some(module) = &scope.module {
            self.parsed.add_child(module.clone(), code_unit);
        }
    }

    fn visit_class_members_from_declaration(&mut self, node: Node<'_>, scope: &ScopeInfo) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "init_declarator"
                && let Some(inner) = child.child_by_field_name("declarator")
            {
                self.visit_variable_declaration(node, inner, scope, true);
            } else if matches!(
                child.kind(),
                "identifier"
                    | "field_identifier"
                    | "pointer_declarator"
                    | "reference_declarator"
                    | "array_declarator"
                    | "parenthesized_declarator"
            ) {
                self.visit_variable_declaration(node, child, scope, true);
            }
        }
    }

    fn visit_global_variables_from_declaration(&mut self, node: Node<'_>, scope: &ScopeInfo) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "init_declarator"
                && let Some(inner) = child.child_by_field_name("declarator")
            {
                self.visit_variable_declaration(node, inner, scope, false);
            } else if matches!(
                child.kind(),
                "identifier"
                    | "field_identifier"
                    | "pointer_declarator"
                    | "reference_declarator"
                    | "array_declarator"
                    | "parenthesized_declarator"
            ) {
                self.visit_variable_declaration(node, child, scope, false);
            }
        }
    }

    fn visit_include(&mut self, node: Node<'_>) {
        let raw = normalize_cpp_whitespace(node_text(node, self.source));
        self.parsed.import_statements.push(raw.clone());
        self.parsed.imports.push(ImportInfo {
            raw_snippet: raw,
            is_wildcard: false,
            identifier: None,
            alias: None,
            path: None,
        });
    }

    fn visit_type_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        if let Some(type_node) = node.child_by_field_name("type")
            && matches!(
                type_node.kind(),
                "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
            )
        {
            self.visit_class_like(type_node, scope, stack);
        }

        let alias_names = match node.kind() {
            "alias_declaration" => extract_alias_declaration_name(node, self.source)
                .into_iter()
                .collect::<Vec<_>>(),
            "type_definition" => extract_typedef_alias_names(node, self.source),
            _ => Vec::new(),
        };
        self.add_type_aliases(node, scope, alias_names);
    }

    fn add_type_aliases(&mut self, node: Node<'_>, scope: &ScopeInfo, alias_names: Vec<String>) {
        let signature = normalize_cpp_whitespace(node_text(node, self.source));
        if signature.is_empty() {
            return;
        }
        let type_name = node
            .child_by_field_name("type")
            .and_then(|type_node| type_node.child_by_field_name("name"))
            .map(|name_node| normalize_cpp_whitespace(node_text(name_node, self.source)));
        for alias_name in alias_names {
            if alias_name.is_empty() || type_name.as_deref() == Some(alias_name.as_str()) {
                continue;
            }
            let short_name = if let Some(parent) = &scope.class_unit {
                format!("{}${alias_name}", parent.short_name())
            } else {
                alias_name
            };
            let code_unit = CodeUnit::with_signature(
                self.file.clone(),
                CodeUnitType::Class,
                scope.package_name.clone(),
                short_name,
                Some(signature.clone()),
                false,
            );
            if self.parsed.contains_declaration_identity(&code_unit) {
                continue;
            }
            self.parsed
                .add_code_unit(code_unit.clone(), node, self.source, None, None);
            self.parsed
                .add_signature(code_unit.clone(), signature.clone());
            if let Some(metadata) = &scope.template_metadata {
                let mut metadata = metadata.clone();
                metadata.primary_fq_name = code_unit.fq_name();
                self.parsed
                    .set_cpp_template_metadata(code_unit.clone(), metadata);
            }
            if let Some(parent) = &scope.class_unit {
                self.parsed.add_child(parent.clone(), code_unit.clone());
            } else if let Some(module) = &scope.module {
                self.parsed.add_child(module.clone(), code_unit.clone());
            }
            self.parsed.mark_type_alias(code_unit);
        }
    }

    fn visit_macro(&mut self, node: Node<'_>) {
        let Some(name) = extract_macro_name(node, self.source) else {
            return;
        };
        let signature = node_text(node, self.source).trim_end().to_string();
        if signature.is_empty() {
            return;
        }
        let code_unit = CodeUnit::new(self.file.clone(), CodeUnitType::Macro, "", name);
        if self.parsed.contains_declaration_identity(&code_unit) {
            return;
        }
        self.parsed
            .add_code_unit(code_unit.clone(), node, self.source, None, None);
        self.parsed.add_signature(code_unit, signature);
    }
}

fn cpp_declaration_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    }
}

pub(crate) fn recover_quoted_includes(
    source: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let mut in_block_comment = false;
    for line in source.lines() {
        let stripped = strip_cpp_comments_from_line(line, &mut in_block_comment);
        let trimmed = stripped.trim();
        if !looks_like_quoted_include_line(trimmed) {
            continue;
        }

        let raw = normalize_cpp_whitespace(trimmed);
        if parsed.import_statements.contains(&raw) {
            continue;
        }

        parsed.import_statements.push(raw.clone());
        parsed.imports.push(ImportInfo {
            raw_snippet: raw,
            is_wildcard: false,
            identifier: None,
            alias: None,
            path: None,
        });
    }
}

fn looks_like_quoted_include_line(line: &str) -> bool {
    let Some(rest) = line.trim_start().strip_prefix('#') else {
        return false;
    };
    let Some(rest) = rest.trim_start().strip_prefix("include") else {
        return false;
    };
    rest.trim_start().starts_with('"')
}

fn extract_cpp_supertypes(node: Node<'_>, source: &str) -> Vec<String> {
    let mut raw = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "base_class_clause" {
            collect_cpp_base_nodes(child, source, &mut raw);
        }
    }
    raw
}

fn collect_cpp_base_nodes(node: Node<'_>, source: &str, raw: &mut Vec<String>) {
    walk_named_tree_preorder(node, false, |child| match child.kind() {
        "type_identifier" | "qualified_identifier" | "template_type" => {
            let text = normalize_cpp_whitespace(node_text(child, source));
            if !text.is_empty() {
                raw.push(text);
            }
            WalkControl::SkipChildren
        }
        _ => WalkControl::Continue,
    });
}

fn strip_cpp_comments_from_line(line: &str, in_block_comment: &mut bool) -> String {
    let mut out = String::new();
    let chars: Vec<char> = line.chars().collect();
    let mut index = 0;
    let mut in_string = false;
    let mut in_char = false;
    let mut escape = false;

    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();

        if *in_block_comment {
            if ch == '*' && next == Some('/') {
                *in_block_comment = false;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }

        if in_string {
            out.push(ch);
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }

        if in_char {
            out.push(ch);
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '\'' {
                in_char = false;
            }
            index += 1;
            continue;
        }

        if ch == '/' && next == Some('/') {
            break;
        }
        if ch == '/' && next == Some('*') {
            *in_block_comment = true;
            index += 2;
            continue;
        }
        if ch == '"' {
            in_string = true;
            out.push(ch);
            index += 1;
            continue;
        }
        if ch == '\'' {
            in_char = true;
            out.push(ch);
            index += 1;
            continue;
        }

        out.push(ch);
        index += 1;
    }

    out
}

#[derive(Clone)]
struct FunctionInfo {
    package_name: String,
    owner_path: Option<String>,
    name: String,
    signature: String,
}

enum DeclaratorKind<'a> {
    Function(Node<'a>),
    Variable(Node<'a>),
}

impl FunctionInfo {
    fn code_unit(&self, file: ProjectFile) -> CodeUnit {
        self.code_unit_with_synthetic(file, false)
    }

    fn code_unit_with_synthetic(&self, file: ProjectFile, synthetic: bool) -> CodeUnit {
        let short_name = if let Some(owner) = &self.owner_path {
            format!("{owner}.{}", self.name)
        } else {
            self.name.clone()
        };
        CodeUnit::with_signature(
            file,
            CodeUnitType::Function,
            self.package_name.clone(),
            short_name,
            Some(self.signature.clone()),
            synthetic,
        )
    }
}

fn extract_function_info(
    declarator: Node<'_>,
    source: &str,
    scope: &ScopeInfo,
) -> Option<FunctionInfo> {
    let parameters_node = declarator.child_by_field_name("parameters")?;
    let parameters_text = cpp_parameter_signature(parameters_node, source);
    let declarator_name_node = declarator
        .child_by_field_name("declarator")
        .or_else(|| last_named_child(declarator))?;
    let (owner_path, name, package_name) = if let Some(parts) =
        split_structured_templated_cpp_name(declarator_name_node, source, scope)
    {
        parts
    } else {
        let raw_name =
            normalize_cpp_whitespace(&extract_declarator_name(declarator_name_node, source));
        if raw_name.is_empty() {
            return None;
        }
        split_cpp_name(&raw_name, scope)
    };
    let full_text = normalize_cpp_whitespace(node_text(declarator, source));
    let suffix = full_text
        .split_once(node_text(parameters_node, source))
        .map(|(_, tail)| normalize_cpp_qualifier_suffix(tail))
        .unwrap_or_default();
    let mut signature = if suffix.is_empty() {
        parameters_text
    } else {
        format!("{parameters_text} {suffix}")
    };
    if let Some(template_signature) = &scope.template_signature {
        signature = format!("{template_signature}{signature}");
    }

    Some(FunctionInfo {
        package_name,
        owner_path,
        name,
        signature,
    })
}

fn extract_function_declarator(node: Node<'_>) -> Option<Node<'_>> {
    match classify_declarator(node)? {
        DeclaratorKind::Function(function_declarator) => Some(function_declarator),
        DeclaratorKind::Variable(_) => None,
    }
}

fn classify_declarator(node: Node<'_>) -> Option<DeclaratorKind<'_>> {
    match node.kind() {
        "function_declarator" => {
            let inner = node
                .child_by_field_name("declarator")
                .or_else(|| node.child_by_field_name("name"))
                .or_else(|| last_named_child(node));
            if inner.is_some_and(is_function_pointer_like_inner_declarator) {
                Some(DeclaratorKind::Variable(node))
            } else {
                Some(DeclaratorKind::Function(node))
            }
        }
        "init_declarator"
        | "pointer_declarator"
        | "reference_declarator"
        | "parenthesized_declarator"
        | "array_declarator"
        | "attributed_declarator"
        | "template_function" => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| last_named_child(node))
            .and_then(classify_declarator),
        "identifier" | "field_identifier" | "qualified_identifier" => {
            Some(DeclaratorKind::Variable(node))
        }
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| last_named_child(node))
            .and_then(classify_declarator),
    }
}

fn is_unfielded_declarator_candidate(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_declarator"
            | "init_declarator"
            | "pointer_declarator"
            | "reference_declarator"
            | "parenthesized_declarator"
            | "array_declarator"
            | "attributed_declarator"
            | "template_function"
            | "identifier"
            | "field_identifier"
            | "qualified_identifier"
    )
}

fn has_direct_cpp_declarator(node: Node<'_>) -> bool {
    let class_like = first_class_like_child(node);
    let mut cursor = node.walk();
    node.named_children(&mut cursor).any(|child| {
        matches!(
            child.kind(),
            "init_declarator"
                | "pointer_declarator"
                | "reference_declarator"
                | "array_declarator"
                | "function_declarator"
                | "parenthesized_declarator"
                | "attributed_declarator"
        ) || matches!(
            child.kind(),
            "identifier" | "field_identifier" | "qualified_identifier"
        ) && class_like.is_none_or(|class_node| {
            child.start_byte() < class_node.start_byte() || child.end_byte() > class_node.end_byte()
        })
    })
}

fn is_function_pointer_like_inner_declarator(node: Node<'_>) -> bool {
    match node.kind() {
        "pointer_declarator" | "reference_declarator" | "array_declarator" => true,
        "parenthesized_declarator" => node
            .child_by_field_name("declarator")
            .or_else(|| last_named_child(node))
            .is_some_and(is_pointer_wrapper_declarator),
        "template_function" => node
            .child_by_field_name("name")
            .is_some_and(is_function_pointer_like_inner_declarator),
        _ => false,
    }
}

fn is_pointer_wrapper_declarator(node: Node<'_>) -> bool {
    match node.kind() {
        "pointer_declarator" | "reference_declarator" | "array_declarator" => true,
        "parenthesized_declarator" => node
            .child_by_field_name("declarator")
            .or_else(|| last_named_child(node))
            .is_some_and(is_pointer_wrapper_declarator),
        _ => false,
    }
}

fn split_cpp_name(raw_name: &str, scope: &ScopeInfo) -> (Option<String>, String, String) {
    let cleaned = raw_name.trim_start_matches("template ").trim();
    let parts: Vec<_> = cleaned.split("::").collect();
    if parts.len() > 1 {
        let name = parts.last().unwrap_or(&cleaned).to_string();
        let owner_parts = &parts[..parts.len() - 1];
        if let Some(class_unit) = &scope.class_unit {
            // Lexically inside a class body: the owner is that class, whatever
            // the declarator re-qualifies it as.
            return (
                Some(class_unit.short_name().to_string()),
                name,
                scope.package_name.clone(),
            );
        }
        if !scope.package_name.is_empty() {
            // Out-of-line member definition written *inside* an enclosing
            // `namespace {}` block (scope package is that namespace). Every
            // owner segment before the terminal member is a class-nesting step
            // -- an out-of-line nested-class member `Outer::Inner::method` in
            // Bifrost's `Outer$Inner` short-name convention (#1121) -- not a
            // namespace path: `using namespace` never brings nested-class
            // access into unqualified scope, so C++ always writes the full
            // `Outer::Inner::` qualifier here. The only wrinkle is a definition
            // that redundantly re-states the enclosing namespace it already
            // sits in (`namespace log4cxx { void log4cxx::Foo::method() {} }`);
            // strip that re-qualifying prefix (which duplicates a suffix of the
            // enclosing package path) before treating what remains as the
            // nested-class chain, so the redundant spelling still lands on the
            // same `log4cxx.Foo.method` identity as its header declaration.
            let nested = strip_redundant_namespace_prefix(owner_parts, &scope.package_name);
            let owner_path = (!nested.is_empty()).then(|| nested.join("$"));
            return (owner_path, name, scope.package_name.clone());
        }
        // File scope (no enclosing `namespace {}` block, scope package empty).
        let (owner_path, package_name) = if owner_parts.len() > 1 {
            // A multi-segment qualifier at file scope with no enclosing
            // namespace: treat all but the last owner segment as the namespace
            // path and the last as the owning class (`ns1::ns2::Class::method`
            // -> package `ns1::ns2`, owner `Class`). Whether a leading segment
            // is really a namespace or an outer class cannot be told from the
            // declarator text alone here, and no enclosing namespace or
            // in-index owner is available at per-file extraction to confirm the
            // class reading, so the far-more-common namespace interpretation is
            // kept rather than guessed away (the nested-class-at-file-scope and
            // using-directive-qualified nested-class shapes remain on this
            // behavior; see #1121).
            (
                Some(owner_parts.last().unwrap_or(&"").to_string()),
                owner_parts[..owner_parts.len() - 1].join("::"),
            )
        } else {
            // A bare `Class::member` qualifier at file scope carries no
            // namespace segment of its own. The declarator alone cannot say
            // which namespace owns `Class` -- but a `using namespace X;`
            // directive already in effect at this point in the file (#1093,
            // e.g. log4cxx's `using namespace LOG4CXX_NS;` followed by
            // out-of-line `LogString HTMLLayout::getContentType() const {...}`)
            // is the remaining structural signal for it, so fall back to it
            // rather than leaving the definition's package empty while its
            // header declaration (parsed inside the `namespace {}` block) keeps
            // the real one -- an identity split that made the same member
            // unresolvable under its own displayed spelling.
            (
                Some(owner_parts[0].to_string()),
                cpp_using_directive_namespace_for_bare_owner(scope),
            )
        };
        return (owner_path, name, package_name);
    }

    let package_name = scope.package_name.clone();
    let owner_path = scope
        .class_unit
        .as_ref()
        .map(|parent| parent.short_name().to_string());
    (owner_path, cleaned.to_string(), package_name)
}

/// Drop the leading owner segments of an out-of-line member qualifier that
/// merely re-state the enclosing namespace the definition already sits in, so
/// what remains is the pure class-nesting chain. Inside `namespace a::b`, a
/// definition may redundantly write `a::b::Outer::Inner::method` (or the
/// partial `b::Outer::Inner::method`); the leading segments that duplicate a
/// suffix of the enclosing package path (`a::b`, then `b`) are re-qualification
/// noise, not class-nesting steps. Returns the owner segments with the longest
/// such re-qualifying prefix removed (possibly all of them, when the qualifier
/// names only the enclosing namespace before the terminal member -- a
/// re-qualified free function). `package_name` is the enclosing namespace path
/// in its stored `::`-joined form; both sides are split on the same delimiter
/// the namespace walker joined them with, so this compares namespace *segments*
/// rather than scanning text.
fn strip_redundant_namespace_prefix<'a>(
    owner_parts: &'a [&'a str],
    package_name: &str,
) -> &'a [&'a str] {
    if package_name.is_empty() {
        return owner_parts;
    }
    let package_segments: Vec<&str> = package_name.split("::").collect();
    let max_prefix = owner_parts.len().min(package_segments.len());
    for prefix_len in (1..=max_prefix).rev() {
        let package_suffix = &package_segments[package_segments.len() - prefix_len..];
        if &owner_parts[..prefix_len] == package_suffix {
            return &owner_parts[prefix_len..];
        }
    }
    owner_parts
}

/// Best-effort package-name recovery for a bare (unqualified-by-itself) owner
/// class name at file/namespace scope, from the `using namespace` directives
/// visible at this point in the file. Several may be in scope at once (a
/// primary `using namespace NS;` alongside deeper conveniences like `using
/// namespace NS::helpers;`); since the declarator gives no way to tell which
/// one actually declares the owner class, prefer the shallowest (fewest
/// `::`-separated segments) as the file's most likely "home" namespace,
/// breaking ties by declaration order. Returns an empty string (leaving the
/// caller's package unqualified, as before) when no using-namespace directive
/// is in scope.
fn cpp_using_directive_namespace_for_bare_owner(scope: &ScopeInfo) -> String {
    scope
        .visible_using_namespaces
        .iter()
        .min_by_key(|namespace| namespace.split("::").count())
        .cloned()
        .unwrap_or_default()
}

struct CppQualifiedNameComponent {
    name: String,
    is_template_id: bool,
}

fn split_structured_templated_cpp_name(
    declarator_name: Node<'_>,
    source: &str,
    scope: &ScopeInfo,
) -> Option<(Option<String>, String, String)> {
    if declarator_name.kind() != "qualified_identifier" {
        return None;
    }

    let mut components = Vec::new();
    let mut current = declarator_name;
    let mut explicitly_global = false;
    loop {
        if current.kind() == "qualified_identifier" {
            if let Some(component) = current.child_by_field_name("scope") {
                components.push(canonical_cpp_qualified_component(component, source)?);
            } else if components.is_empty() {
                explicitly_global = true;
            } else {
                return None;
            }
            current = current.child_by_field_name("name")?;
        } else {
            components.push(canonical_cpp_qualified_component(current, source)?);
            break;
        }
    }

    let terminal = components.pop()?;
    let owner_start = components
        .iter()
        .position(|component| component.is_template_id)?;
    let explicit_package = components[..owner_start]
        .iter()
        .map(|component| component.name.as_str())
        .collect::<Vec<_>>()
        .join("::");
    let explicit_package_is_empty = explicit_package.is_empty();
    let package_name = match (
        explicitly_global,
        scope.package_name.is_empty(),
        explicit_package_is_empty,
    ) {
        (true, _, _) => explicit_package,
        (false, _, true) => scope.package_name.clone(),
        (false, true, false) => explicit_package,
        (false, false, false) => format!("{}::{explicit_package}", scope.package_name),
    };
    // Same identity-split fallback as `split_cpp_name` (#1093): a template
    // specialization's owner class named with no namespace segment of its own
    // (`explicit_package` empty) at file scope (`explicitly_global` false)
    // with nothing enclosing (`package_name` still empty) has no structural
    // signal for its namespace besides an in-scope `using namespace X;`.
    let package_name = if package_name.is_empty() && !explicitly_global && explicit_package_is_empty
    {
        cpp_using_directive_namespace_for_bare_owner(scope)
    } else {
        package_name
    };
    let owner_path = components[owner_start..]
        .iter()
        .map(|component| component.name.as_str())
        .collect::<Vec<_>>()
        .join("$");
    if owner_path.is_empty() || terminal.name.is_empty() {
        return None;
    }

    Some((Some(owner_path), terminal.name, package_name))
}

fn canonical_cpp_qualified_component(
    mut component: Node<'_>,
    source: &str,
) -> Option<CppQualifiedNameComponent> {
    let mut is_template_id = false;
    loop {
        match component.kind() {
            "template_type" => {
                is_template_id = true;
                component = component.child_by_field_name("name")?;
            }
            "dependent_name" => component = component.named_child(0)?,
            "identifier"
            | "field_identifier"
            | "namespace_identifier"
            | "type_identifier"
            | "operator_name"
            | "destructor_name" => {
                let name = normalize_cpp_whitespace(node_text(component, source));
                return (!name.is_empty()).then_some(CppQualifiedNameComponent {
                    name,
                    is_template_id,
                });
            }
            _ => component = component.child_by_field_name("name")?,
        }
    }
}

fn extract_declarator_name(node: Node<'_>, source: &str) -> String {
    match node.kind() {
        "identifier"
        | "field_identifier"
        | "type_identifier"
        | "operator_name"
        | "destructor_name"
        | "qualified_identifier" => node_text(node, source).to_string(),
        "function_declarator"
        | "pointer_declarator"
        | "reference_declarator"
        | "parenthesized_declarator"
        | "array_declarator"
        | "template_function" => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| last_named_child(node))
            .map(|child| extract_declarator_name(child, source))
            .unwrap_or_else(|| node_text(node, source).to_string()),
        _ => node
            .child_by_field_name("name")
            .map(|child| extract_declarator_name(child, source))
            .unwrap_or_else(|| node_text(node, source).to_string()),
    }
}

fn extract_variable_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" | "type_identifier" | "qualified_identifier" => {
            let name = node_text(node, source).trim().to_string();
            (!name.is_empty()).then_some(name)
        }
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| last_named_child(node))
            .and_then(|child| extract_variable_name(child, source)),
    }
}

fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let count = node.named_child_count();
    if count == 0 {
        None
    } else {
        node.named_child(count - 1)
    }
}

fn extract_alias_declaration_name(node: Node<'_>, source: &str) -> Option<String> {
    let name_node = node.child_by_field_name("name")?;
    let name = normalize_cpp_whitespace(node_text(name_node, source));
    (!name.is_empty()).then_some(name)
}

fn recovered_type_alias_names(node: Node<'_>, source: &str) -> Vec<String> {
    if node.kind() != "declaration" {
        return Vec::new();
    }
    let Some(keyword) = node.child_by_field_name("type").filter(|node| {
        node.kind() == "type_identifier" && matches!(node_text(*node, source), "using" | "typedef")
    }) else {
        return Vec::new();
    };
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return Vec::new();
    };
    if node_text(keyword, source) == "using"
        && (declarator.kind() != "init_declarator"
            || declarator.child_by_field_name("value").is_none())
    {
        return Vec::new();
    }
    extract_typedef_declarator_name(declarator, source)
        .into_iter()
        .collect()
}

fn extract_typedef_alias_names(node: Node<'_>, source: &str) -> Vec<String> {
    let type_node = node.child_by_field_name("type");
    let mut names = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if type_node.is_some_and(|type_node| same_node(child, type_node)) {
            continue;
        }
        if let Some(name) = extract_typedef_declarator_name(child, source)
            && !names.contains(&name)
        {
            names.push(name);
        }
    }
    names
}

fn extract_typedef_declarator_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" | "type_identifier" => {
            let name = normalize_cpp_whitespace(node_text(node, source));
            (!name.is_empty()).then_some(name)
        }
        "qualified_identifier" => node
            .child_by_field_name("name")
            .and_then(|name| extract_typedef_declarator_name(name, source)),
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| last_named_child(node))
            .and_then(|child| extract_typedef_declarator_name(child, source)),
    }
}

fn extract_macro_name(node: Node<'_>, source: &str) -> Option<String> {
    let name = node
        .child_by_field_name("name")
        .map(|name_node| normalize_cpp_whitespace(node_text(name_node, source)))
        .or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| {
                    matches!(
                        child.kind(),
                        "identifier" | "field_identifier" | "type_identifier"
                    )
                })
                .map(|name_node| normalize_cpp_whitespace(node_text(name_node, source)))
        })?;
    (!name.is_empty()).then_some(name)
}

fn same_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.id() == right.id()
}

fn render_cpp_type_signature(
    node: Node<'_>,
    source: &str,
    template_signature: Option<&str>,
) -> String {
    let text = normalize_cpp_whitespace(node_text(node, source));
    let head = text.split('{').next().unwrap_or(text.as_str()).trim();
    let rendered = if head.ends_with(';') {
        head.to_string()
    } else {
        format!("{head} {{")
    };
    if let Some(template_signature) = template_signature {
        format!("template {template_signature} {rendered}")
    } else {
        rendered
    }
}

fn render_cpp_field_signature(node: Node<'_>, declarator: Node<'_>, source: &str) -> String {
    let declaration_text = normalize_cpp_whitespace(node_text(node, source));
    let prefix = cpp_declaration_prefix(node, source);
    let name = extract_variable_name(declarator, source).unwrap_or_default();
    let raw_suffix = cpp_declarator_suffix_without_name(declarator, source);
    let suffix = if (prefix.ends_with('*') && raw_suffix == "*")
        || (prefix.ends_with('&') && raw_suffix == "&")
    {
        String::new()
    } else {
        raw_suffix
    };

    let mut rendered = if suffix.is_empty() {
        format!("{prefix} {name}")
    } else if suffix.starts_with('*') || suffix.starts_with('&') {
        format!("{prefix}{suffix} {name}")
    } else if suffix.starts_with('[') || suffix.starts_with('(') {
        format!("{prefix} {name}{suffix}")
    } else {
        format!("{prefix} {suffix}{name}")
    };
    rendered = collapse_cpp_whitespace(&rendered);

    if let Some(initializer) = cpp_preserved_initializer(node, declarator, source) {
        format!("{rendered} = {initializer};")
    } else if declaration_text.ends_with(';') {
        format!("{rendered};")
    } else {
        rendered
    }
}

fn cpp_declaration_prefix(node: Node<'_>, source: &str) -> String {
    let text = node_text(node, source);
    let mut cursor = node.walk();
    let first_declarator = node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "init_declarator"
                | "identifier"
                | "field_identifier"
                | "pointer_declarator"
                | "reference_declarator"
                | "array_declarator"
                | "function_declarator"
        )
    });
    let prefix = if let Some(first_declarator) = first_declarator {
        let end = first_declarator
            .start_byte()
            .saturating_sub(node.start_byte());
        let mut prefix = text.get(..end).unwrap_or(text).to_string();
        let declarator_suffix = match first_declarator.kind() {
            "init_declarator" => first_declarator
                .child_by_field_name("declarator")
                .map(|inner| cpp_declarator_suffix_without_name(inner, source))
                .unwrap_or_default(),
            _ => cpp_declarator_suffix_without_name(first_declarator, source),
        };
        if declarator_suffix.starts_with('*') || declarator_suffix.starts_with('&') {
            prefix.push_str(&declarator_suffix);
        }
        return collapse_cpp_whitespace(&prefix)
            .trim_end_matches(',')
            .trim_end_matches(';')
            .trim()
            .to_string();
    } else {
        text
    };
    collapse_cpp_whitespace(prefix)
        .trim_end_matches(',')
        .trim_end_matches(';')
        .trim()
        .to_string()
}

fn cpp_preserved_initializer(
    declaration_node: Node<'_>,
    declarator: Node<'_>,
    source: &str,
) -> Option<String> {
    let name = extract_variable_name(declarator, source)?;
    let mut cursor = declaration_node.walk();
    for child in declaration_node.named_children(&mut cursor) {
        if child.kind() != "init_declarator" {
            continue;
        }
        let Some(inner) = child.child_by_field_name("declarator") else {
            continue;
        };
        if extract_variable_name(inner, source).as_deref() != Some(name.as_str()) {
            continue;
        }
        let value = child.child_by_field_name("value")?;
        let kind = value.kind();
        if matches!(
            kind,
            "number_literal" | "float_literal" | "char_literal" | "true" | "false"
        ) {
            return Some(normalize_cpp_whitespace(node_text(value, source)));
        }
        break;
    }
    let declaration_text = normalize_cpp_whitespace(node_text(declaration_node, source));
    let pattern = format!(
        r"\b{}\s*=\s*([-+]?[0-9]+(?:\.[0-9]+)?)",
        regex::escape(&name)
    );
    Regex::new(&pattern)
        .ok()
        .and_then(|regex| regex.captures(&declaration_text))
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn render_cpp_function_display_signature_from_node(
    node: Node<'_>,
    source: &str,
    template_signature: Option<&str>,
    has_body: bool,
) -> String {
    let root = enclosing_cpp_declaration_node(node).unwrap_or(node);
    let parent_text = node_text(root, source);
    let body_local_start = root
        .child_by_field_name("body")
        .map(|body| body.start_byte().saturating_sub(root.start_byte()))
        .unwrap_or(parent_text.len());
    let display = parent_text
        .get(..body_local_start)
        .unwrap_or(parent_text)
        .trim()
        .trim();
    let display = if let Some(template_signature) = template_signature {
        if display.starts_with("template ") {
            display.to_string()
        } else {
            format!("template {template_signature} {display}")
        }
    } else {
        display.to_string()
    };
    let display = collapse_cpp_whitespace(display.trim_end_matches(';'));
    if has_body {
        format!("{display} {{...}}")
    } else {
        format!("{display};")
    }
}

fn cpp_template_signature(
    template_node: Node<'_>,
    declaration_child: Node<'_>,
    source: &str,
) -> Option<String> {
    let text = source
        .get(template_node.start_byte()..declaration_child.start_byte())
        .unwrap_or("");
    let text = normalize_cpp_whitespace(text);
    let start = text.find('<')?;
    let end = text.rfind('>')?;
    if end < start {
        return None;
    }
    Some(text[start..=end].to_string())
}

struct RecoveredFragmentedPartialSpecialization<'tree> {
    declaration_node: Node<'tree>,
    name: String,
    range: Range,
    prefix_members: Vec<Node<'tree>>,
    member_siblings: Vec<Node<'tree>>,
    following_declarations: Vec<Node<'tree>>,
}

fn recover_fragmented_partial_specialization<'tree>(
    template_node: Node<'tree>,
    declaration_child: Node<'tree>,
    source: &str,
) -> Option<RecoveredFragmentedPartialSpecialization<'tree>> {
    if declaration_child.kind() != "function_definition" {
        return None;
    }
    let class_node = declaration_child.child_by_field_name("type")?;
    if !matches!(
        class_node.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier"
    ) || !class_node
        .child_by_field_name("name")
        .and_then(|name| direct_identifier_name(name, source))
        .is_some_and(|name| cpp_export_macro_token(&name))
    {
        return None;
    }
    let declarator = declaration_child.child_by_field_name("declarator")?;
    if declarator.kind() != "template_function" {
        return None;
    }
    let metadata = cpp_template_metadata(template_node, declaration_child, source)?;
    if metadata.specialization_arguments.is_empty() {
        return None;
    }
    let body = declaration_child.child_by_field_name("body")?;
    if body.kind() != "compound_statement" {
        return None;
    }
    let complete_prefix = body.named_child(0).filter(|first| {
        first.kind() == "labeled_statement"
            && first.has_error()
            && first
                .named_child(first.named_child_count().saturating_sub(1))
                .is_some_and(recovered_declaration_has_class_terminator)
    });
    let complete_body = complete_prefix.is_some();
    let mut prefix_members = Vec::new();
    if let Some(prefix) = complete_prefix {
        prefix_members.push(prefix);
    } else {
        let mut body_cursor = body.walk();
        for child in body.named_children(&mut body_cursor) {
            if !is_structurally_valid_fragmented_class_prefix_member(child) {
                break;
            }
            prefix_members.push(child);
        }
    }
    let containing_declarations = template_node.parent()?;
    if !matches!(
        containing_declarations.kind(),
        "declaration_list" | "compound_statement"
    ) {
        return None;
    }
    let mut member_siblings = Vec::new();
    let mut following_declarations = Vec::new();
    let terminator;
    if complete_body {
        terminator = complete_prefix?;
        let mut cursor = body.walk();
        let mut after_prefix = false;
        for child in body.named_children(&mut cursor) {
            if complete_prefix.is_some_and(|prefix| same_node(child, prefix)) {
                after_prefix = true;
            } else if after_prefix {
                following_declarations.push(child);
            }
        }
    } else {
        let mut found_template = false;
        let mut cursor = containing_declarations.walk();
        let mut class_terminator = None;
        for child in containing_declarations.children(&mut cursor) {
            if same_node(child, template_node) {
                found_template = true;
                continue;
            }
            if found_template && child.kind() == "}" {
                class_terminator = Some(child);
                break;
            }
            if found_template && child.is_named() {
                member_siblings.push(child);
            }
        }
        terminator = class_terminator?;
    }
    let name = format!(
        "{}<{}>",
        metadata.primary_name,
        metadata
            .specialization_arguments
            .iter()
            .map(|argument| argument.text.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Some(RecoveredFragmentedPartialSpecialization {
        declaration_node: declaration_child,
        name,
        range: Range {
            start_byte: declaration_child.start_byte(),
            end_byte: terminator.end_byte(),
            start_line: declaration_child.start_position().row + 1,
            end_line: terminator.end_position().row + 1,
        },
        prefix_members,
        member_siblings,
        following_declarations,
    })
}

fn recovered_declaration_has_class_terminator(declaration: Node<'_>) -> bool {
    if declaration.kind() != "declaration" {
        return false;
    }
    // With an export macro between `class` and its name, tree-sitter folds a
    // complete class body into a function-shaped declaration. The class's own
    // `};` remains structurally identifiable as a direct ERROR child holding
    // `}`, immediately followed by the declaration's direct `;` child.
    (0..declaration.child_count().saturating_sub(1)).any(|index| {
        let Some(error) = declaration.child(index) else {
            return false;
        };
        error.kind() == "ERROR"
            && error.child_count() == 1
            && error.child(0).is_some_and(|child| child.kind() == "}")
            && declaration
                .child(index + 1)
                .is_some_and(|child| child.kind() == ";")
    })
}

fn is_structurally_valid_fragmented_class_prefix_member(node: Node<'_>) -> bool {
    if node.has_error() {
        return false;
    }
    match node.kind() {
        "declaration"
        | "field_declaration"
        | "alias_declaration"
        | "type_definition"
        | "static_assert_declaration" => true,
        "labeled_statement" => node
            .named_child(node.named_child_count().saturating_sub(1))
            .is_some_and(is_structurally_valid_fragmented_class_prefix_member),
        "template_declaration" => node.named_children(&mut node.walk()).any(|child| {
            matches!(
                child.kind(),
                "declaration"
                    | "field_declaration"
                    | "alias_declaration"
                    | "type_definition"
                    | "function_definition"
            )
        }),
        _ => false,
    }
}

fn recovered_using_declaration_alias_name(node: Node<'_>, source: &str) -> Option<String> {
    (node.kind() == "declaration" && node.child(0)?.kind() == "using")
        .then(|| node.child_by_field_name("declarator"))
        .flatten()
        .and_then(|declarator| extract_variable_name(declarator, source))
}

fn cpp_template_metadata(
    template_node: Node<'_>,
    declaration_child: Node<'_>,
    source: &str,
) -> Option<CppTemplateMetadata> {
    let parameters_node = template_node.child_by_field_name("parameters")?;
    let name_node = cpp_templated_class_name_node(declaration_child)?;
    let primary_node = match name_node.kind() {
        "template_type" | "template_function" => name_node.child_by_field_name("name")?,
        _ => name_node,
    };
    let primary_name = normalize_cpp_whitespace(node_text(primary_node, source));
    if primary_name.is_empty() || cpp_export_macro_token(&primary_name) {
        return None;
    }

    let mut parameter_nodes = Vec::new();
    let mut parameter_names = Vec::new();
    let mut cursor = parameters_node.walk();
    for parameter in parameters_node.named_children(&mut cursor) {
        let Some(name) = cpp_template_parameter_name(parameter, source) else {
            continue;
        };
        parameter_names.push(name);
        parameter_nodes.push(parameter);
    }
    let parameters = parameter_nodes
        .into_iter()
        .zip(parameter_names.iter().cloned())
        .map(|(parameter, name)| CppTemplateParameterMetadata {
            name,
            kind: cpp_template_parameter_kind(parameter),
            default: cpp_template_parameter_default_expression(parameter, source, &parameter_names),
        })
        .collect();
    let specialization_arguments = if declaration_child.kind() == "alias_declaration" {
        Vec::new()
    } else {
        cpp_template_argument_expressions(name_node, source, &parameter_names).unwrap_or_default()
    };
    let alias_target = (declaration_child.kind() == "alias_declaration")
        .then(|| cpp_template_alias_target(declaration_child, source, &parameter_names))
        .flatten();
    Some(CppTemplateMetadata {
        primary_name,
        primary_fq_name: String::new(),
        parameters,
        specialization_arguments,
        alias_target,
    })
}

fn cpp_templated_class_name_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "class_specifier" | "struct_specifier" | "union_specifier" => {
            node.child_by_field_name("name")
        }
        "function_definition" => {
            let declarator = node.child_by_field_name("declarator")?;
            if matches!(declarator.kind(), "identifier" | "template_function") {
                Some(declarator)
            } else {
                None
            }
        }
        "alias_declaration" => node.child_by_field_name("name"),
        _ => None,
    }
}

fn cpp_template_alias_target(
    alias: Node<'_>,
    source: &str,
    parameter_names: &[String],
) -> Option<CppTemplateAliasTargetMetadata> {
    let mut type_node = alias.child_by_field_name("type")?;
    while type_node.kind() == "type_descriptor" {
        type_node = type_node.child_by_field_name("type")?;
    }
    let global = type_node.child_by_field_name("scope").is_none()
        && type_node.child(0).is_some_and(|child| child.kind() == "::");
    let mut components = Vec::new();
    cpp_template_target_components(type_node, source, &mut components)?;
    let arguments = cpp_template_argument_expressions(type_node, source, parameter_names);
    (!components.is_empty()).then_some(CppTemplateAliasTargetMetadata {
        components,
        global,
        arguments,
    })
}

fn cpp_template_target_components(
    node: Node<'_>,
    source: &str,
    out: &mut Vec<String>,
) -> Option<()> {
    match node.kind() {
        "identifier" | "namespace_identifier" | "type_identifier" => {
            out.push(node_text(node, source).to_string());
            Some(())
        }
        "template_type" => {
            cpp_template_target_components(node.child_by_field_name("name")?, source, out)
        }
        "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier" => {
            if let Some(scope) = node.child_by_field_name("scope") {
                cpp_template_target_components(scope, source, out)?;
            }
            cpp_template_target_components(node.child_by_field_name("name")?, source, out)
        }
        _ => None,
    }
}

fn cpp_template_argument_expressions(
    mut node: Node<'_>,
    source: &str,
    parameter_names: &[String],
) -> Option<Vec<CppTemplateExpression>> {
    loop {
        match node.kind() {
            "template_type" | "template_function" => {
                let arguments = node.child_by_field_name("arguments")?;
                let mut cursor = arguments.walk();
                return Some(
                    arguments
                        .named_children(&mut cursor)
                        .filter(|argument| !argument.is_extra() && argument.kind() != "comment")
                        .map(|argument| cpp_template_expression(argument, source, parameter_names))
                        .collect(),
                );
            }
            "qualified_identifier" | "scoped_type_identifier" | "type_descriptor" => {
                node = node
                    .child_by_field_name("name")
                    .or_else(|| node.child_by_field_name("type"))?;
            }
            _ => return None,
        }
    }
}

fn cpp_template_parameter_name(node: Node<'_>, source: &str) -> Option<String> {
    let candidate = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("declarator"))
        .or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor).find(|child| {
                matches!(
                    child.kind(),
                    "identifier" | "type_identifier" | "field_identifier"
                )
            })
        })?;
    let name = normalize_cpp_whitespace(&extract_declarator_name(candidate, source));
    (!name.is_empty()).then_some(name)
}

fn cpp_template_parameter_kind(node: Node<'_>) -> CppTemplateParameterKind {
    match node.kind() {
        "type_parameter_declaration"
        | "optional_type_parameter_declaration"
        | "variadic_type_parameter_declaration" => CppTemplateParameterKind::Type,
        "template_template_parameter_declaration" => CppTemplateParameterKind::Template,
        _ => CppTemplateParameterKind::Value,
    }
}

fn cpp_template_parameter_default(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("default_type")
        .or_else(|| node.child_by_field_name("default_value"))
}

fn cpp_template_parameter_default_expression(
    parameter: Node<'_>,
    source: &str,
    parameter_names: &[String],
) -> Option<CppTemplateExpression> {
    let default = cpp_template_parameter_default(parameter)?;
    let base = cpp_template_expression(default, source, parameter_names);
    let Some(pointer_error) = parameter.next_named_sibling() else {
        return Some(base);
    };
    let Some(pointer_declarator) =
        recovered_abstract_pointer_declarator_term(pointer_error, source)
    else {
        return Some(base);
    };
    Some(CppTemplateExpression {
        text: format!(
            "{}{}",
            base.text,
            normalize_cpp_whitespace(node_text(pointer_error, source))
        ),
        term: CppTemplateTerm::Node {
            kind: "type_descriptor".to_string(),
            children: vec![base.term, pointer_declarator],
        },
    })
}

fn recovered_abstract_pointer_declarator_term(
    node: Node<'_>,
    source: &str,
) -> Option<CppTemplateTerm> {
    if node.kind() != "ERROR" || node.child_count() == 0 {
        return None;
    }
    let mut children = Vec::new();
    for index in 0..node.child_count() {
        let child = node.child(index)?;
        if child.kind() != "*" {
            return None;
        }
        children.push(CppTemplateTerm::Atom {
            kind: "*".to_string(),
            text: normalize_cpp_whitespace(node_text(child, source)),
        });
    }
    Some(CppTemplateTerm::Node {
        kind: "abstract_pointer_declarator".to_string(),
        children,
    })
}

fn cpp_template_expression(
    node: Node<'_>,
    source: &str,
    parameter_names: &[String],
) -> CppTemplateExpression {
    let text = normalize_cpp_whitespace(node_text(node, source));
    CppTemplateExpression {
        text,
        term: cpp_template_term(node, source, parameter_names),
    }
}

pub(crate) fn cpp_template_term(
    node: Node<'_>,
    source: &str,
    parameter_names: &[String],
) -> CppTemplateTerm {
    enum Work<'tree> {
        Visit(Node<'tree>),
        Build { kind: String, child_count: usize },
    }

    let mut work = vec![Work::Visit(node)];
    let mut terms = Vec::new();
    while let Some(next) = work.pop() {
        match next {
            Work::Visit(current) => {
                let text = normalize_cpp_whitespace(node_text(current, source));
                if parameter_names.contains(&text) {
                    terms.push(CppTemplateTerm::Parameter(text));
                    continue;
                }
                if matches!(current.kind(), "type_descriptor" | "dependent_type") {
                    let mut cursor = current.walk();
                    let named = current
                        .named_children(&mut cursor)
                        .filter(|child| !child.is_extra() && child.kind() != "comment")
                        .collect::<Vec<_>>();
                    if let [child] = named.as_slice() {
                        work.push(Work::Visit(*child));
                        continue;
                    }
                }
                if current.child_count() == 0 {
                    terms.push(CppTemplateTerm::Atom {
                        kind: if matches!(
                            current.kind(),
                            "identifier"
                                | "type_identifier"
                                | "field_identifier"
                                | "namespace_identifier"
                        ) {
                            "identifier".to_string()
                        } else {
                            current.kind().to_string()
                        },
                        text,
                    });
                    continue;
                }
                let children = (0..current.child_count())
                    .filter_map(|index| current.child(index))
                    .filter(|child| !child.is_extra() && child.kind() != "comment")
                    .collect::<Vec<_>>();
                work.push(Work::Build {
                    kind: current.kind().to_string(),
                    child_count: children.len(),
                });
                work.extend(children.into_iter().rev().map(Work::Visit));
            }
            Work::Build { kind, child_count } => {
                let children = terms.split_off(terms.len() - child_count);
                terms.push(CppTemplateTerm::Node { kind, children });
            }
        }
    }
    terms.pop().expect("template term traversal emits one root")
}

fn enclosing_cpp_declaration_node(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "declaration"
            | "function_declaration"
            | "field_declaration"
            | "function_definition" => return Some(node),
            _ => node = node.parent()?,
        }
    }
}

fn cpp_parameter_signature(parameters_node: Node<'_>, source: &str) -> String {
    let mut params = Vec::new();
    let mut cursor = parameters_node.walk();
    for child in parameters_node.children(&mut cursor) {
        match child.kind() {
            "parameter_declaration" | "optional_parameter_declaration" => {
                params.push(cpp_parameter_type(child, source));
            }
            "variadic_parameter_declaration" => {
                params.push(cpp_parameter_type(child, source));
            }
            "variadic_parameter" | "..." => params.push("...".to_string()),
            _ => {}
        }
    }

    if params.is_empty() {
        "()".to_string()
    } else {
        format!("({})", params.join(", "))
    }
}

fn cpp_signature_metadata(
    signature: String,
    function_declarator: Node<'_>,
    source: &str,
) -> SignatureMetadata {
    let dispatch = cpp_callable_dispatch_extensibility(function_declarator);
    let enrich = |metadata: SignatureMetadata| metadata.with_dispatch_extensibility(dispatch);
    let return_type_text = cpp_callable_return_type_text(function_declarator, source);
    let return_type_identity = cpp_callable_return_type_identity(function_declarator, source);
    let Some(parameters_node) = function_declarator.child_by_field_name("parameters") else {
        return enrich(
            SignatureMetadata::new(signature, Vec::new())
                .with_return_type_text(return_type_text)
                .with_return_type_identity(return_type_identity),
        );
    };
    let callable_arity = cpp_callable_arity(parameters_node, source);
    let parameter_text = normalize_cpp_whitespace(node_text(parameters_node, source));
    let search_from = cpp_signature_search_start(&signature, function_declarator, source);
    let Some(relative_start) = signature
        .get(search_from..)
        .and_then(|suffix| suffix.find(&parameter_text))
    else {
        return enrich(
            SignatureMetadata::new(signature, Vec::new())
                .with_callable_arity(callable_arity)
                .with_return_type_text(return_type_text)
                .with_return_type_identity(return_type_identity),
        );
    };
    let parameters_start = search_from + relative_start;
    let parameters_end = parameters_start + parameter_text.len();
    let mut search_start = parameters_start;
    let parameters = cpp_parameter_label_nodes(parameters_node)
        .into_iter()
        .filter_map(|label_node| {
            let label = normalize_cpp_whitespace(node_text(label_node, source));
            if label.is_empty() || search_start > parameters_end {
                return None;
            }
            let haystack = signature.get(search_start..parameters_end)?;
            let relative_start = haystack.find(&label)?;
            let start_byte = search_start + relative_start;
            let end_byte = start_byte + label.len();
            search_start = end_byte;
            Some(ParameterMetadata::new(label, start_byte, end_byte))
        })
        .collect();
    enrich(
        SignatureMetadata::new(signature, parameters)
            .with_callable_arity(callable_arity)
            .with_return_type_text(return_type_text)
            .with_return_type_identity(return_type_identity),
    )
}

fn cpp_callable_return_type_identity(
    function_declarator: Node<'_>,
    source: &str,
) -> Option<StructuredTypeIdentity> {
    let lexical_scope = cpp_callable_lexical_scope(function_declarator, source);
    let mut cursor = function_declarator.walk();
    if let Some(trailing) = function_declarator
        .named_children(&mut cursor)
        .find(|child| child.kind() == "trailing_return_type")
        && let Some(type_descriptor) = trailing.named_child(0)
    {
        return cpp_structured_type_identity(type_descriptor, source, &lexical_scope);
    }

    let mut current = function_declarator;
    let mut wrappers = Vec::new();
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "function_definition" | "declaration" | "field_declaration"
        ) {
            let type_node = parent.child_by_field_name("type")?;
            if cpp_export_macro_token(node_text(type_node, source))
                && (0..parent.named_child_count()).any(|index| {
                    parent
                        .named_child(index)
                        .is_some_and(|child| child.kind() == "ERROR")
                })
            {
                return None;
            }
            let mut identity = cpp_structured_type_identity(type_node, source, &lexical_scope)?;
            for wrapper in wrappers.into_iter().rev() {
                identity = cpp_wrap_structured_type(identity, wrapper)?;
            }
            return Some(identity);
        }
        let wraps_current_declarator = parent.child_by_field_name("declarator") == Some(current)
            || (matches!(
                parent.kind(),
                "pointer_declarator"
                    | "reference_declarator"
                    | "array_declarator"
                    | "parenthesized_declarator"
            ) && parent.named_child_count() == 1
                && parent.named_child(0) == Some(current));
        if !wraps_current_declarator {
            return None;
        }
        match parent.kind() {
            "pointer_declarator" => wrappers.push(CppStructuredTypeWrapper::Pointer),
            "reference_declarator" => wrappers.push(CppStructuredTypeWrapper::Reference),
            "array_declarator" => wrappers.push(CppStructuredTypeWrapper::Array),
            "init_declarator" | "parenthesized_declarator" | "attributed_declarator" => {}
            _ => return None,
        }
        current = parent;
    }
    None
}

fn cpp_structured_type_identity(
    node: Node<'_>,
    source: &str,
    lexical_scope: &[String],
) -> Option<StructuredTypeIdentity> {
    enum Work<'tree> {
        Visit(Node<'tree>),
        Wrap(CppStructuredTypeWrapper),
        ApplyWrappers(Vec<CppStructuredTypeWrapper>),
        BuildGeneric { argument_count: usize },
    }

    let mut work = vec![Work::Visit(node)];
    let mut values = Vec::new();
    let mut builder = StructuredTypeIdentityBuilder::default();
    while let Some(next) = work.pop() {
        match next {
            Work::Visit(current) => match current.kind() {
                "type_descriptor" => {
                    let type_node = current
                        .child_by_field_name("type")
                        .or_else(|| current.named_child(0))?;
                    let mut wrappers = Vec::new();
                    let mut cursor = current.walk();
                    for child in current.named_children(&mut cursor) {
                        if child.id() != type_node.id() {
                            wrappers.extend(cpp_structured_declarator_wrappers(child));
                        }
                    }
                    work.push(Work::ApplyWrappers(wrappers));
                    work.push(Work::Visit(type_node));
                }
                "pointer_declarator" | "abstract_pointer_declarator" => {
                    let child = current
                        .child_by_field_name("declarator")
                        .or_else(|| current.named_child(0))?;
                    work.push(Work::Wrap(CppStructuredTypeWrapper::Pointer));
                    work.push(Work::Visit(child));
                }
                "reference_declarator" => {
                    let child = current
                        .child_by_field_name("declarator")
                        .or_else(|| current.named_child(0))?;
                    work.push(Work::Wrap(CppStructuredTypeWrapper::Reference));
                    work.push(Work::Visit(child));
                }
                "array_declarator" | "abstract_array_declarator" => {
                    let child = current
                        .child_by_field_name("declarator")
                        .or_else(|| current.named_child(0))?;
                    work.push(Work::Wrap(CppStructuredTypeWrapper::Array));
                    work.push(Work::Visit(child));
                }
                "template_type" => {
                    let name_node = current.child_by_field_name("name")?;
                    let arguments = current
                        .child_by_field_name("arguments")
                        .map(|arguments_node| {
                            let mut cursor = arguments_node.walk();
                            arguments_node
                                .named_children(&mut cursor)
                                .filter(|child| !child.is_extra() && child.kind() != "comment")
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    work.push(Work::BuildGeneric {
                        argument_count: arguments.len(),
                    });
                    work.extend(arguments.into_iter().rev().map(Work::Visit));
                    work.push(Work::Visit(name_node));
                }
                "qualified_identifier"
                | "scoped_identifier"
                | "scoped_type_identifier"
                | "type_identifier"
                | "identifier"
                | "namespace_identifier"
                | "primitive_type" => {
                    values.push(builder.named(cpp_structured_named_type(
                        current,
                        source,
                        lexical_scope,
                    )?)?);
                }
                _ => {
                    let child = current.child_by_field_name("type").or_else(|| {
                        (current.named_child_count() == 1)
                            .then(|| current.named_child(0))
                            .flatten()
                    })?;
                    work.push(Work::Visit(child));
                }
            },
            Work::Wrap(wrapper) => {
                let root = values.pop()?;
                values.push(cpp_wrap_structured_type_node(&mut builder, root, wrapper)?);
            }
            Work::ApplyWrappers(wrappers) => {
                let mut root = values.pop()?;
                for wrapper in wrappers.into_iter().rev() {
                    root = cpp_wrap_structured_type_node(&mut builder, root, wrapper)?;
                }
                values.push(root);
            }
            Work::BuildGeneric { argument_count } => {
                let value_count = argument_count.checked_add(1)?;
                let start = values.len().checked_sub(value_count)?;
                let mut built = values.split_off(start);
                let base = built.remove(0);
                values.push(builder.generic(base, built)?);
            }
        }
    }
    (values.len() == 1)
        .then(|| values.pop())
        .flatten()
        .and_then(|root| builder.finish(root))
}

fn cpp_structured_named_type(
    node: Node<'_>,
    source: &str,
    lexical_scope: &[String],
) -> Option<StructuredTypeName> {
    let path = cpp_structured_type_path(node, source)?;
    let absolute = node.child_by_field_name("scope").is_none()
        && node.child(0).is_some_and(|child| child.kind() == "::");
    StructuredTypeName::new(path, lexical_scope.to_vec(), absolute)
}

#[derive(Clone, Copy)]
enum CppStructuredTypeWrapper {
    Pointer,
    Reference,
    Array,
}

fn cpp_structured_declarator_wrappers(node: Node<'_>) -> Vec<CppStructuredTypeWrapper> {
    let mut wrappers = Vec::new();
    let mut current = node;
    loop {
        match current.kind() {
            "pointer_declarator" | "abstract_pointer_declarator" => {
                wrappers.push(CppStructuredTypeWrapper::Pointer)
            }
            "reference_declarator" => wrappers.push(CppStructuredTypeWrapper::Reference),
            "array_declarator" | "abstract_array_declarator" => {
                wrappers.push(CppStructuredTypeWrapper::Array)
            }
            _ => break,
        }
        let Some(child) = current
            .child_by_field_name("declarator")
            .or_else(|| current.named_child(0))
        else {
            break;
        };
        current = child;
    }
    wrappers
}

fn cpp_wrap_structured_type(
    identity: StructuredTypeIdentity,
    wrapper: CppStructuredTypeWrapper,
) -> Option<StructuredTypeIdentity> {
    match wrapper {
        CppStructuredTypeWrapper::Pointer => identity.wrap_pointer(),
        CppStructuredTypeWrapper::Reference => identity.wrap_reference(),
        CppStructuredTypeWrapper::Array => identity.wrap_array(),
    }
}

fn cpp_wrap_structured_type_node(
    builder: &mut StructuredTypeIdentityBuilder,
    inner: crate::analyzer::model::StructuredTypeNodeId,
    wrapper: CppStructuredTypeWrapper,
) -> Option<crate::analyzer::model::StructuredTypeNodeId> {
    match wrapper {
        CppStructuredTypeWrapper::Pointer => builder.pointer(inner),
        CppStructuredTypeWrapper::Reference => builder.reference(inner),
        CppStructuredTypeWrapper::Array => builder.array(inner),
    }
}

fn cpp_structured_type_path(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut path = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            "identifier" | "namespace_identifier" | "type_identifier" | "primitive_type" => {
                let component = node_text(current, source).to_string();
                if component.is_empty() {
                    return None;
                }
                path.push(component);
            }
            "template_type" | "dependent_type" => {
                stack.push(current.child_by_field_name("name")?);
            }
            "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier" => {
                stack.push(current.child_by_field_name("name")?);
                if let Some(scope) = current.child_by_field_name("scope") {
                    stack.push(scope);
                }
            }
            _ => return None,
        }
    }
    (!path.is_empty()).then_some(path)
}

fn cpp_callable_lexical_scope(node: Node<'_>, source: &str) -> Vec<String> {
    let mut groups = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "namespace_definition" | "class_specifier" | "struct_specifier" | "union_specifier"
        ) && let Some(name_node) = parent.child_by_field_name("name")
            && let Some(components) = cpp_structured_type_path(name_node, source)
            && !components.is_empty()
        {
            groups.push(components);
        }
        current = parent.parent();
    }
    groups.reverse();
    groups.into_iter().flatten().collect()
}

fn cpp_callable_dispatch_extensibility(function_declarator: Node<'_>) -> DispatchExtensibility {
    let mut declaration = None;
    let mut current = Some(function_declarator);
    while let Some(node) = current {
        match node.kind() {
            "template_declaration"
            | "preproc_if"
            | "preproc_ifdef"
            | "preproc_else"
            | "preproc_elif"
            | "preproc_call"
            | "ERROR" => return DispatchExtensibility::Open,
            "declaration" | "field_declaration" | "function_definition" => {
                declaration.get_or_insert(node);
            }
            "translation_unit" => break,
            _ => {}
        }
        current = node.parent();
    }
    let Some(declaration) = declaration else {
        return DispatchExtensibility::Open;
    };

    let mut saw_virtual_boundary = false;
    let mut stack = vec![declaration];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "compound_statement" | "field_declaration_list" => continue,
            "final" | "final_specifier" => return DispatchExtensibility::Closed,
            "virtual"
            | "override"
            | "virtual_specifier"
            | "pure_virtual_clause"
            | "template_parameter_list"
            | "template_method"
            | "template_function"
            | "ERROR" => saw_virtual_boundary = true,
            _ => {}
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }

    if saw_virtual_boundary {
        DispatchExtensibility::Open
    } else {
        DispatchExtensibility::Closed
    }
}

fn cpp_callable_linkage(declaration: Node<'_>, source: &str) -> CallableLinkage {
    let mut enclosed_by_class = false;
    let mut current = declaration.parent();
    while let Some(node) = current {
        if node.kind() == "namespace_definition"
            && node
                .child_by_field_name("name")
                .is_none_or(|name| normalize_cpp_whitespace(node_text(name, source)).is_empty())
        {
            return CallableLinkage::Internal;
        }
        if matches!(
            node.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) {
            if node
                .child_by_field_name("name")
                .is_none_or(|name| normalize_cpp_whitespace(node_text(name, source)).is_empty())
            {
                return CallableLinkage::Internal;
            }
            enclosed_by_class = true;
        }
        if matches!(node.kind(), "function_definition" | "lambda_expression") {
            return CallableLinkage::Internal;
        }
        current = node.parent();
    }

    if enclosed_by_class {
        return CallableLinkage::External;
    }

    let mut cursor = declaration.walk();
    if declaration.named_children(&mut cursor).any(|child| {
        child.kind() == "storage_class_specifier"
            && normalize_cpp_whitespace(node_text(child, source)) == "static"
    }) {
        CallableLinkage::Internal
    } else {
        CallableLinkage::External
    }
}

fn cpp_callable_return_type_text(function_declarator: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = function_declarator.walk();
    if let Some(trailing) = function_declarator
        .named_children(&mut cursor)
        .find(|child| child.kind() == "trailing_return_type")
        && let Some(type_descriptor) = trailing.named_child(0)
    {
        let text = normalize_cpp_whitespace(node_text(type_descriptor, source));
        if !text.is_empty() {
            return Some(text);
        }
    }

    let mut current = function_declarator;
    let mut indirection = String::new();
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "function_definition" | "declaration" | "field_declaration"
        ) {
            let type_node = parent.child_by_field_name("type")?;
            if cpp_export_macro_token(node_text(type_node, source))
                && (0..parent.named_child_count()).any(|index| {
                    parent
                        .named_child(index)
                        .is_some_and(|child| child.kind() == "ERROR")
                })
            {
                // Export/decorator macros commonly occupy the grammar's `type`
                // field and leave the semantic return type in an ERROR sibling.
                // Do not persist the macro token as a return type. The malformed
                // declaration does not carry enough structured evidence here.
                return None;
            }
            let base = normalize_cpp_whitespace(node_text(type_node, source));
            return (!base.is_empty()).then(|| format!("{base}{indirection}"));
        }
        let wraps_current_declarator = parent.child_by_field_name("declarator") == Some(current)
            || (matches!(parent.kind(), "pointer_declarator" | "reference_declarator")
                && parent.named_child_count() == 1
                && parent.named_child(0) == Some(current));
        if wraps_current_declarator {
            match parent.kind() {
                "pointer_declarator" => indirection.push('*'),
                "reference_declarator" => {
                    let reference = parent
                        .children(&mut parent.walk())
                        .find(|child| !child.is_named())
                        .map(|child| node_text(child, source))
                        .unwrap_or("&");
                    indirection.push_str(reference);
                }
                "init_declarator" | "parenthesized_declarator" => {}
                _ => return None,
            }
            current = parent;
            continue;
        }
        return None;
    }
    None
}

fn cpp_callable_arity(parameters_node: Node<'_>, source: &str) -> CallableArity {
    let mut required = 0;
    let mut total = 0;
    let mut repeated = false;
    let mut cursor = parameters_node.walk();
    for child in parameters_node.children(&mut cursor) {
        match child.kind() {
            "parameter_declaration" => {
                if child.child_by_field_name("declarator").is_none()
                    && child
                        .child_by_field_name("type")
                        .is_some_and(|type_node| node_text(type_node, source).trim() == "void")
                {
                    continue;
                }
                required += 1;
                total += 1;
            }
            "optional_parameter_declaration" => total += 1,
            "variadic_parameter" | "variadic_parameter_declaration" | "..." => {
                repeated = true;
            }
            _ => {}
        }
    }
    CallableArity::new(required, total, repeated)
}

fn cpp_parameter_label_nodes(parameters_node: Node<'_>) -> Vec<Node<'_>> {
    let mut labels = Vec::new();
    let mut cursor = parameters_node.walk();
    for child in parameters_node.children(&mut cursor) {
        match child.kind() {
            "parameter_declaration" | "optional_parameter_declaration" => {
                if let Some(name_node) = child
                    .child_by_field_name("declarator")
                    .and_then(cpp_declarator_label_node)
                {
                    labels.push(name_node);
                } else {
                    labels.push(child);
                }
            }
            "variadic_parameter" | "variadic_parameter_declaration" | "..." => {
                labels.push(child);
            }
            _ => {}
        }
    }
    labels
}

fn cpp_signature_search_start(
    signature: &str,
    function_declarator: Node<'_>,
    source: &str,
) -> usize {
    let Some(enclosing) = enclosing_cpp_declaration_node(function_declarator) else {
        return 0;
    };
    let raw = node_text(enclosing, source);
    let leading_trim_bytes = raw.len().saturating_sub(raw.trim_start().len());
    let offset = function_declarator
        .start_byte()
        .saturating_sub(enclosing.start_byte())
        .saturating_sub(leading_trim_bytes);
    offset.min(signature.len())
}

fn cpp_declarator_label_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier" | "field_identifier" => Some(node),
        "pointer_declarator" | "reference_declarator" | "parenthesized_declarator" => node
            .child_by_field_name("declarator")
            .or_else(|| last_named_child(node))
            .and_then(cpp_declarator_label_node),
        "array_declarator" => node
            .child_by_field_name("declarator")
            .and_then(cpp_declarator_label_node),
        "function_declarator" => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| last_named_child(node))
            .and_then(cpp_declarator_label_node),
        _ => None,
    }
}

fn cpp_parameter_type(parameter: Node<'_>, source: &str) -> String {
    let base_type = parameter
        .child_by_field_name("type")
        .map(|node| normalize_cpp_whitespace(node_text(node, source)))
        .unwrap_or_default();
    let mut cursor = parameter.walk();
    let qualifiers = parameter
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "type_qualifier")
        .map(|child| normalize_cpp_whitespace(node_text(child, source)))
        .collect::<Vec<_>>()
        .join(" ");
    let type_text = match (qualifiers.is_empty(), base_type.is_empty()) {
        (true, _) => base_type,
        (_, true) => qualifiers,
        (false, false) => format!("{qualifiers} {base_type}"),
    };
    let declarator_suffix = cpp_parameter_declarator(parameter)
        .map(|node| cpp_declarator_suffix_without_name(node, source))
        .unwrap_or_default();

    let combined = if type_text.is_empty() {
        declarator_suffix
    } else if declarator_suffix.is_empty() {
        type_text
    } else {
        format!("{type_text} {declarator_suffix}")
    };
    normalize_cpp_type_text(&combined)
}

fn cpp_parameter_declarator(parameter: Node<'_>) -> Option<Node<'_>> {
    parameter.child_by_field_name("declarator").or_else(|| {
        // Some unnamed prototype parameters expose their abstract declarator
        // as a direct named child without the grammar's `declarator` field.
        // Recover only the structured abstract-declarator node; the parameter's
        // type and qualifiers are distinct children and must not be guessed from
        // source text.
        let mut cursor = parameter.walk();
        parameter
            .named_children(&mut cursor)
            .find(|child| is_cpp_abstract_declarator(child.kind()))
    })
}

fn is_cpp_abstract_declarator(kind: &str) -> bool {
    matches!(
        kind,
        "abstract_pointer_declarator"
            | "abstract_reference_declarator"
            | "abstract_array_declarator"
            | "abstract_function_declarator"
            | "abstract_parenthesized_declarator"
    )
}

fn cpp_nested_declarator(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("declarator").or_else(|| {
        if is_cpp_abstract_declarator(node.kind()) {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| is_cpp_abstract_declarator(child.kind()))
        } else {
            // Named declarators historically use their last named child when
            // tree-sitter omits the field. Keep that broad fallback for
            // attributed, variadic, and recovered named shapes.
            last_named_child(node)
        }
    })
}

fn cpp_declarator_suffix_without_name(node: Node<'_>, source: &str) -> String {
    match node.kind() {
        "identifier" | "field_identifier" => String::new(),
        "pointer_declarator" | "abstract_pointer_declarator" => {
            let inner = cpp_nested_declarator(node)
                .map(|child| cpp_declarator_suffix_without_name(child, source))
                .unwrap_or_default();
            format!("*{inner}")
        }
        "reference_declarator" | "abstract_reference_declarator" => {
            let inner = cpp_nested_declarator(node)
                .map(|child| cpp_declarator_suffix_without_name(child, source))
                .unwrap_or_default();
            let reference = node
                .children(&mut node.walk())
                .find(|child| matches!(child.kind(), "&" | "&&"))
                .map(|child| node_text(child, source))
                .unwrap_or("&");
            format!("{reference}{inner}")
        }
        "array_declarator" | "abstract_array_declarator" => {
            let inner = cpp_nested_declarator(node)
                .map(|child| cpp_declarator_suffix_without_name(child, source))
                .unwrap_or_default();
            let size = node
                .child_by_field_name("size")
                .map(|child| normalize_cpp_whitespace(node_text(child, source)))
                .unwrap_or_default();
            format!("{inner}[{size}]")
        }
        "parenthesized_declarator" | "abstract_parenthesized_declarator" => {
            let inner = cpp_nested_declarator(node);
            inner
                .map(|child| format!("({})", cpp_declarator_suffix_without_name(child, source)))
                .unwrap_or_default()
        }
        "function_declarator" | "abstract_function_declarator" => {
            let inner = cpp_nested_declarator(node)
                .map(|child| cpp_declarator_suffix_without_name(child, source))
                .unwrap_or_default();
            let params = node
                .child_by_field_name("parameters")
                .map(|child| cpp_parameter_signature(child, source))
                .unwrap_or_else(|| "()".to_string());
            format!("{inner}{params}")
        }
        _ => {
            let text = normalize_cpp_whitespace(node_text(node, source));
            let name = extract_declarator_name(node, source);
            if name.is_empty() {
                text
            } else {
                text.replace(&name, "").trim().to_string()
            }
        }
    }
}

fn normalize_cpp_qualifier_suffix(suffix: &str) -> String {
    collapse_cpp_whitespace(
        suffix
            .trim()
            .trim_start_matches("->")
            .trim_start_matches('{')
            .trim_end_matches(';'),
    )
}

pub(crate) fn normalize_cpp_whitespace(value: &str) -> String {
    collapse_cpp_whitespace(value)
}

fn normalize_cpp_type_text(value: &str) -> String {
    collapse_cpp_whitespace(value)
        .replace(", ", ",")
        .replace(" <", "<")
        .replace("< ", "<")
        .replace(" >", ">")
}

fn collapse_cpp_whitespace(value: &str) -> String {
    let mut result = String::new();
    let mut prev_space = false;
    for ch in value.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                result.push(' ');
            }
            prev_space = true;
        } else {
            result.push(ch);
            prev_space = false;
        }
    }
    result.trim().to_string()
}

pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

pub(super) fn collect_cpp_identifiers(
    node: Node<'_>,
    source: &str,
    identifiers: &mut HashSet<String>,
) {
    walk_named_tree_preorder(node, true, |node| {
        match node.kind() {
            "type_identifier" | "identifier" | "qualified_identifier" => {
                let text = node_text(node, source).trim();
                if !text.is_empty() {
                    identifiers.insert(text.to_string());
                }
            }
            _ => {}
        }
        WalkControl::Continue
    });
}

fn cpp_body_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).find(|child| {
            matches!(
                child.kind(),
                "declaration_list" | "field_declaration_list" | "enumerator_list"
            )
        })
    })
}

fn cpp_contains_namespace_definition(node: Node<'_>) -> bool {
    if node.kind() == "namespace_definition" {
        return true;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(cpp_contains_namespace_definition)
}

/// Detect the bogus `function_definition` that tree-sitter recovers for a region
/// prefixed by an object-like macro sentinel the parser cannot see (issue #941),
/// and return the byte range `[start, end)` of the swallowed interior to reparse.
///
/// The measured shape (`BEGIN_NS\nnamespace X { struct A { void m(); }; }`) is a
/// `function_definition` whose first named child is the sentinel mis-read as the
/// return `type` (a bare all-caps `type_identifier`), followed by the mis-lexed
/// item keyword, an `ERROR`, and a `compound_statement` holding the real items.
/// `start` is the end of the sentinel identifier -- everything after it is the
/// genuine source. `end` is the node's end, extended across any trailing empty
/// `;` statement the mis-parse displaced past the node (the class/struct closing
/// semicolon), so the reparse sees a complete, brace-balanced item.
///
/// False-positive guard: the candidate must itself carry an `ERROR`/`MISSING`
/// node (`has_error`). A well-formed function definition never does -- not even
/// one whose return type is an all-caps typedef like `DWORD foo() { ... }` -- so
/// real callables are never reparsed as items. The clean-reparse-to-items gate in
/// `cpp_reparsed_items_are_indexable` is the final arbiter.
fn cpp_sentinel_macro_region(node: Node<'_>, source: &str) -> Option<(usize, usize)> {
    if node.kind() != "function_definition" || !node.has_error() {
        return None;
    }
    let first = node.named_child(0)?;
    if first.kind() != "type_identifier" {
        return None;
    }
    let sentinel = normalize_cpp_whitespace(node_text(first, source));
    if sentinel.is_empty() || !cpp_export_macro_token(&sentinel) {
        return None;
    }
    // Consecutive begin/end sentinels stack: `END_NS BEGIN_NS namespace two {...}`
    // makes the trailing sentinel of one region and the leading sentinel of the
    // next both land as bare macro-token identifiers ahead of the real content.
    // Advance past every leading macro-token identifier so the reparse begins at
    // genuine source rather than another sentinel that would re-form the bogus
    // shape and fail the reparse gate.
    let mut start = first.end_byte();
    let mut index = 1;
    while let Some(child) = node.named_child(index) {
        if matches!(child.kind(), "identifier" | "type_identifier")
            && cpp_export_macro_token(&normalize_cpp_whitespace(node_text(child, source)))
        {
            start = child.end_byte();
            index += 1;
        } else {
            break;
        }
    }
    let mut end = node.end_byte();
    let mut sibling = node.next_named_sibling();
    while let Some(current) = sibling {
        if !cpp_is_stray_semicolon(current, source) {
            break;
        }
        end = current.end_byte();
        sibling = current.next_named_sibling();
    }
    (start < end).then_some((start, end))
}

/// An empty `;` statement: the displaced closing semicolon of a struct/class that
/// the sentinel mis-parse split off past the bogus function node.
fn cpp_is_stray_semicolon(node: Node<'_>, source: &str) -> bool {
    node.kind() == "expression_statement"
        && node.named_child_count() == 0
        && node_text(node, source).trim() == ";"
}

/// Reparse the region `[start, end)` of `source` as C++ inside a padded copy: the
/// prefix `[0, start)` is replaced byte-for-byte with spaces (newlines preserved)
/// so every reparsed node keeps its original byte offset and line number. The
/// existing visitors read node text from the original source, which is identical
/// to the padded interior, so ranges and ownership stay byte/line-exact. Mirrors
/// the Rust #1015 `rust_reparse_macro_items` technique.
fn cpp_reparse_region_items(source: &str, start: usize, end: usize) -> Option<(String, Tree)> {
    let bytes = source.as_bytes();
    let prefix = bytes.get(..start)?;
    let interior = bytes.get(start..end)?;
    let mut padded = Vec::with_capacity(end);
    padded.extend(
        prefix
            .iter()
            .map(|&b| if b == b'\n' { b'\n' } else { b' ' }),
    );
    padded.extend_from_slice(interior);
    let padded = String::from_utf8(padded).ok()?;
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(&padded, None)?;
    Some((padded, tree))
}

/// Robustness gate adapting #1015's `rust_reparsed_items_are_indexable`: the
/// reparsed interior is indexed only when every top-level named node is a
/// well-formed C++ item (or a comment) and at least one real item is present.
/// Expression/statement soup surfaces as a top-level `ERROR` or
/// `expression_statement`, neither of which is an item kind, so it is rejected.
///
/// Unlike the Rust gate, this does NOT reject on `root.has_error()`: a nested
/// begin/end sentinel inside the region (e.g. `namespace outer { BEGIN_NS ...`
/// swallowed by a preceding dangling sentinel) reparses to a real
/// `namespace_definition` whose body still holds a bogus `function_definition`,
/// so the subtree legitimately carries an error. Container items are admitted
/// even with an internal error; the inner bogus function is recovered recursively
/// when `visit_function_definition` walks it. Each recursion strips at least one
/// leading sentinel, so the region strictly shrinks and recovery terminates.
///
/// A top-level `function_definition` is the one place we stay strict: it is
/// admitted only when it is clean or is itself a sentinel candidate. A function
/// that has an error and is not a sentinel is a real callable with a broken body,
/// so we refuse the whole reparse and let the ordinary path handle it (preserving
/// its real return type rather than re-deriving an implicit one).
fn cpp_reparsed_items_are_indexable(root: Node<'_>, source: &str) -> bool {
    let mut cursor = root.walk();
    let mut saw_item = false;
    for child in root.named_children(&mut cursor) {
        match child.kind() {
            "comment" => {}
            "function_definition" => {
                if child.has_error() && cpp_sentinel_macro_region(child, source).is_none() {
                    return false;
                }
                saw_item = true;
            }
            kind if cpp_is_indexable_item_kind(kind) => saw_item = true,
            _ => return false,
        }
    }
    saw_item
}

/// Robustness gate for a reparsed fragmented multiple-base export class body
/// (issue #938). Adapts `cpp_reparsed_items_are_indexable` to the member-shaped
/// kinds a class body produces when reparsed at translation-unit scope: the
/// access-specifier label preceding the first member surfaces as a
/// `labeled_statement` wrapping that member, and members surface as
/// `declaration`/`field_declaration`/`function_definition`/nested type specifiers.
/// Statement or expression soup surfaces as other top-level kinds and is rejected,
/// so only a genuinely member-shaped body is ever re-owned as members; anything
/// ambiguous falls back to indexing the class alone.
fn cpp_reparsed_members_are_indexable(root: Node<'_>, source: &str) -> bool {
    let mut cursor = root.walk();
    let mut saw_member = false;
    for child in root.named_children(&mut cursor) {
        match child.kind() {
            "comment" => {}
            "labeled_statement" => saw_member = true,
            "function_definition" => {
                if child.has_error() && cpp_sentinel_macro_region(child, source).is_none() {
                    return false;
                }
                saw_member = true;
            }
            kind if cpp_is_indexable_item_kind(kind) => saw_member = true,
            _ => return false,
        }
    }
    saw_member
}

fn cpp_is_indexable_item_kind(kind: &str) -> bool {
    matches!(
        kind,
        "namespace_definition"
            | "class_specifier"
            | "struct_specifier"
            | "union_specifier"
            | "enum_specifier"
            | "function_definition"
            | "template_declaration"
            | "declaration"
            | "field_declaration"
            | "alias_declaration"
            | "type_definition"
            | "using_declaration"
            | "linkage_specification"
            | "preproc_def"
            | "preproc_function_def"
            | "preproc_include"
            | "preproc_if"
            | "preproc_ifdef"
            | "preproc_call"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::LanguageAdapter;
    use crate::analyzer::cpp::adapter::CppAdapter;
    use crate::analyzer::tree_sitter_analyzer::{
        finish_declaration_identity_comparison_probe, start_declaration_identity_comparison_probe,
    };
    use std::fmt::Write;

    fn member_function_linkage(source: &str) -> CallableLinkage {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "function_definition" {
                let mut current = node.parent();
                while let Some(parent) = current {
                    if matches!(
                        parent.kind(),
                        "class_specifier" | "struct_specifier" | "union_specifier"
                    ) {
                        return cpp_callable_linkage(node, source);
                    }
                    current = parent.parent();
                }
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        panic!("fixture has no member function definition");
    }

    #[test]
    fn cpp_member_linkage_source_scopes_local_and_unnamed_types() {
        assert_eq!(
            member_function_linkage("struct Named { int method() { return 1; } };"),
            CallableLinkage::External
        );
        assert_eq!(
            member_function_linkage(
                "int outer() { struct Local { int method() { return 1; } }; return 0; }"
            ),
            CallableLinkage::Internal
        );
        assert_eq!(
            member_function_linkage("struct { int method() { return 1; } } instance;"),
            CallableLinkage::Internal
        );
    }

    #[test]
    fn exported_single_base_recovery_uses_displaced_class_name() {
        let source = r#"
class CORE_EXPORT QgsPoint : public AbstractGeometry
{
    Q_GADGET

    Q_PROPERTY( double x READ x WRITE setX )
    Q_PROPERTY( double y READ y WRITE setY )
    Q_PROPERTY( double z READ z WRITE setZ )
    Q_PROPERTY( double m READ m WRITE setM )

  public:
#ifndef SIP_RUN
    QgsPoint(
      double x = std::numeric_limits<double>::quiet_NaN(),
      double y = std::numeric_limits<double>::quiet_NaN(),
      double z = std::numeric_limits<double>::quiet_NaN(),
      double m = std::numeric_limits<double>::quiet_NaN(),
      Qgis::WkbType wkbType = Qgis::WkbType::Unknown
    );
#else
    QgsPoint( SIP_PYOBJECT x SIP_TYPEHINT( Optional[Union[QgsPoint, QPointF, float]] ) = Py_None, SIP_PYOBJECT y SIP_TYPEHINT( Optional[float] ) = Py_None, SIP_PYOBJECT z SIP_TYPEHINT( Optional[float] ) = Py_None, SIP_PYOBJECT m SIP_TYPEHINT( Optional[float] ) = Py_None, SIP_PYOBJECT wkbType SIP_TYPEHINT( Optional[int] ) = Py_None ) [( double x = 0.0, double y = 0.0, double z = 0.0, double m = 0.0, Qgis::WkbType wkbType = Qgis::WkbType::Unknown )];
    % MethodCode
    if ( sipCanConvertToType( a0, sipType_QgsPointXY, SIP_NOT_NONE ) && a1 == Py_None && a2 == Py_None && a3 == Py_None && a4 == Py_None )
    {
      int state;
      sipIsErr = 0;
      QgsPointXY *p = reinterpret_cast<QgsPointXY *>( sipConvertToType( a0, sipType_QgsPointXY, 0, SIP_NOT_NONE, &state, &sipIsErr ) );
      if ( !sipIsErr )
      {
        sipCpp = new sipQgsPoint( QgsPoint( *p ) );
      }
      sipReleaseType( p, sipType_QgsPointXY, state );
    }
    else if ( sipCanConvertToType( a0, sipType_QPointF, SIP_NOT_NONE ) && a1 == Py_None && a2 == Py_None && a3 == Py_None && a4 == Py_None )
    {
      int state;
      sipIsErr = 0;

      QPointF *p = reinterpret_cast<QPointF *>( sipConvertToType( a0, sipType_QPointF, 0, SIP_NOT_NONE, &state, &sipIsErr ) );
      if ( !sipIsErr )
      {
        sipCpp = new sipQgsPoint( QgsPoint( *p ) );
      }
      sipReleaseType( p, sipType_QPointF, state );
    }
    else if (
      ( a0 == Py_None || PyFloat_AsDouble( a0 ) != -1.0 || !PyErr_Occurred() ) &&
      ( a1 == Py_None || PyFloat_AsDouble( a1 ) != -1.0 || !PyErr_Occurred() ) &&
      ( a2 == Py_None || PyFloat_AsDouble( a2 ) != -1.0 || !PyErr_Occurred() ) &&
      ( a3 == Py_None || PyFloat_AsDouble( a3 ) != -1.0 || !PyErr_Occurred() ) )
    {
      double x = a0 == Py_None ? std::numeric_limits<double>::quiet_NaN() : PyFloat_AsDouble( a0 );
      double y = a1 == Py_None ? std::numeric_limits<double>::quiet_NaN() : PyFloat_AsDouble( a1 );
      double z = a2 == Py_None ? std::numeric_limits<double>::quiet_NaN() : PyFloat_AsDouble( a2 );
      double m = a3 == Py_None ? std::numeric_limits<double>::quiet_NaN() : PyFloat_AsDouble( a3 );
      Qgis::WkbType wkbType = a4 == Py_None ? Qgis::WkbType::Unknown : static_cast<Qgis::WkbType>( sipConvertToEnum( a4, sipType_Qgis_WkbType ) );
      sipCpp = new sipQgsPoint( QgsPoint( x, y, z, m, wkbType ) );
    }
    else // Invalid ctor arguments
    {
      PyErr_SetString( PyExc_TypeError, u"Invalid type in constructor arguments."_s.toUtf8().constData() );
      sipIsErr = 1;
    }
    % End
#endif

    explicit QgsPoint( const QgsPointXY &p ) SIP_SKIP;
    explicit QgsPoint( QPointF p ) SIP_SKIP;
    explicit QgsPoint(
      Qgis::WkbType wkbType,
      double x = std::numeric_limits<double>::quiet_NaN(),
      double y = std::numeric_limits<double>::quiet_NaN(),
      double z = std::numeric_limits<double>::quiet_NaN(),
      double m = std::numeric_limits<double>::quiet_NaN()
    ) SIP_SKIP;
    explicit QgsPoint( const QVector3D &vect, double m = std::numeric_limits<double>::quiet_NaN() ) SIP_SKIP;
    explicit QgsPoint( const QVector4D &vect ) SIP_SKIP;
    explicit QgsPoint( const QgsVector3D &vect, double m = std::numeric_limits<double>::quiet_NaN() ) SIP_SKIP;
#ifndef SIP_RUN
  private:
    bool fuzzyHelper(
      double epsilon,
      const AbstractGeometry &other,
      bool is3DFlag,
      bool isMeasureFlag
    ) const
    {
      return is3DFlag && isMeasureFlag && epsilon > 0 && &other;
    }
#endif
};
class Ordinary : public Base { public: Ordinary(); };
class API_EXPORT Plain { public: Plain(); };
class API_EXPORT : public Base {};
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let file = ProjectFile::new(std::env::temp_dir(), "exported-single-base.cpp");
        let parsed = CppAdapter.parse_file(&file, source, &tree);
        let declarations = parsed.declarations();

        for expected in ["QgsPoint", "Ordinary", "Plain"] {
            assert!(
                declarations
                    .iter()
                    .any(|unit| unit.is_class() && unit.fq_name() == expected),
                "missing recovered class {expected}: {declarations:#?}"
            );
        }
        assert!(
            declarations.iter().any(|unit| {
                unit.is_function()
                    && unit.fq_name() == "QgsPoint.QgsPoint"
                    && unit.signature() == Some("(double, double, double, double, Qgis::WkbType)")
            }),
            "the conditional default donor must retain the recovered QgsPoint owner: {declarations:#?}"
        );
        assert!(
            declarations.iter().all(|unit| {
                !unit.is_class() || !matches!(unit.fq_name().as_str(), "AbstractGeometry" | "Base")
            }),
            "base declarators and an export macro without a displaced identifier must not become class identities: {declarations:#?}"
        );
    }

    #[test]
    fn cpp_alias_and_macro_dedup_comparison_count_is_linear() {
        const DISTINCT_PER_KIND: usize = 64;
        let mut source = String::new();
        for index in 0..DISTINCT_PER_KIND {
            writeln!(source, "typedef int Alias{index};").unwrap();
        }
        writeln!(source, "typedef long Alias0;").unwrap();
        for index in 0..DISTINCT_PER_KIND {
            writeln!(source, "#define MACRO_{index} {index}").unwrap();
        }
        writeln!(source, "#define MACRO_0 duplicate").unwrap();
        source.push_str("void overloaded(int value);\nvoid overloaded(double value);\n");

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&source, None).unwrap();
        let file = ProjectFile::new(std::env::temp_dir(), "dedup.cpp");

        start_declaration_identity_comparison_probe();
        let parsed = CppAdapter.parse_file(&file, &source, &tree);
        let comparisons = finish_declaration_identity_comparison_probe();

        assert_eq!(
            DISTINCT_PER_KIND,
            parsed
                .declarations()
                .iter()
                .filter(|unit| unit.is_class() && unit.short_name().starts_with("Alias"))
                .count(),
            "typedef aliases should retain semantic-identity deduplication"
        );
        assert_eq!(
            DISTINCT_PER_KIND,
            parsed
                .declarations()
                .iter()
                .filter(|unit| {
                    unit.kind() == CodeUnitType::Macro && unit.short_name().starts_with("MACRO_")
                })
                .count(),
            "macros should retain semantic-identity deduplication"
        );
        assert_eq!(
            2,
            parsed
                .declarations()
                .iter()
                .filter(|unit| {
                    unit.kind() == CodeUnitType::Function && unit.short_name() == "overloaded"
                })
                .count(),
            "function overloads must remain distinct"
        );

        let dedup_inputs = DISTINCT_PER_KIND * 2 + 2;
        assert!(
            comparisons <= dedup_inputs * 4,
            "semantic-identity dedup should perform O(inputs) comparisons; got {comparisons} comparisons for {dedup_inputs} alias/macro inputs"
        );
    }
}
