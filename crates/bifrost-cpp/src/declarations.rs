//! The C++ declaration walk, including the macro-sentinel error recovery.
//!
//! Every function here is a pure function of a parsed tree and its source text.
//! `analyzer/cpp/adapter.rs` in `brokk-bifrost-analysis` drives
//! [`CppVisitor`] out of `LanguageAdapter::parse_file`.

use brokk_bifrost_core::analyzer::common::{node_source_text, parse_source_region};
use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentId, SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::model::{
    CallableArity, CallableLinkage, CodeUnitType, CppTemplateAliasTargetMetadata,
    CppTemplateExpression, CppTemplateMetadata, CppTemplateParameterKind,
    CppTemplateParameterMetadata, CppTemplateTerm, DispatchExtensibility, ImportInfo,
    ParameterMetadata, Range, SignatureMetadata, StructuredTypeIdentity,
    StructuredTypeIdentityBuilder, StructuredTypeName, StructuredTypeNodeId,
};
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::analyzer::structural::materialization::{
    GenerationKind, MaterializationRecord,
};
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use regex::Regex;
use tree_sitter::{Node, Parser, Tree};

/// Intern one qualified-name segment in the process-global interner.
fn cpp_segment(text: &str, kind: SegmentKind) -> SegmentId {
    segment_interner().intern(text, kind)
}

/// Push per-component [`SegmentKind::Package`] segments for a C++ namespace
/// path stored in its legacy `::`-joined form (`cutlass::gemm::warp`). The
/// `::` head is exactly the mixed-separator store issue #1163 is about; the
/// structured form records each namespace component, and the equivalence check
/// renders it natively (with `::` between adjacent Package segments) so it
/// round-trips to the legacy string. Splitting the already-joined string here is
/// the M1 bridge — the legacy strings stay authoritative until M3.
fn cpp_push_package(fq: &mut FqName, package_name: &str) {
    for component in package_name.split("::").filter(|c| !c.is_empty()) {
        fq.push(cpp_segment(component, SegmentKind::Package));
    }
}

/// Push per-class segments for a nested-class chain stored in Bifrost's legacy
/// `$`-joined `short_name` form (`Outer$Inner`, issue #1121). The outermost
/// class is a plain [`SegmentKind::Type`]; every subsequently nested class is
/// [`SegmentKind::Nested`], which renders its `$` join unconditionally (the
/// same mechanism python/php/ruby's `$`-joined nesting already uses) — so no
/// cpp-specific native rendering rule is needed for this chain.
fn cpp_push_type_chain(fq: &mut FqName, chain: &str) {
    let mut first = true;
    // fqname-M4: sanctioned M1 construction bridge — this BUILDS the FqName's Type/Nested
    // segments from the legacy `$`-joined nested-class chain at emission; it is the interning
    // entry point, not re-inference of an already-structured name.
    for component in chain.split('$').filter(|c| !c.is_empty()) {
        let kind = if first {
            SegmentKind::Type
        } else {
            SegmentKind::Nested
        };
        fq.push(cpp_segment(component, kind));
        first = false;
    }
}

/// Structured name for a C++ namespace module: every `::`-separated component is
/// a [`SegmentKind::Package`] segment (the legacy unit stores the whole path in
/// `short_name` with an empty `package_name`).
fn cpp_namespace_fq(full_name: &str) -> FqName {
    let mut fq = FqName::new();
    cpp_push_package(&mut fq, full_name);
    fq
}

/// Return the named namespace path that structurally encloses `node`.
///
/// This intentionally follows namespace AST ancestors rather than inspecting
/// source text. Anonymous namespaces are not representable in the legacy C++
/// package field, so a path containing one fails closed.
fn cpp_lexical_namespace_name(node: Node<'_>, source: &str) -> Option<String> {
    let mut components = Vec::new();
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if current.kind() == "namespace_definition" {
            let name_node = current.child_by_field_name("name")?;
            let name = normalize_cpp_whitespace(node_text(name_node, source));
            if name.is_empty() {
                return None;
            }
            components.push(name);
        }
        ancestor = current.parent();
    }
    if components.is_empty() {
        return None;
    }
    components.reverse();
    Some(components.join("::"))
}

/// Structured name for a class-like unit: the enclosing namespace's `Package`
/// segments followed by the `$`-joined nested-class `Type` chain in `short_name`.
fn cpp_class_fq(package_name: &str, short_name: &str) -> FqName {
    let mut fq = FqName::new();
    cpp_push_package(&mut fq, package_name);
    cpp_push_type_chain(&mut fq, short_name);
    fq
}

/// Structured name for a member unit (function, field, enumerator). The
/// `short_name` is the owning `$`-joined nested-class `Type` chain followed, when
/// the member has an owner, by `.member`; free functions and globals have no
/// owner and no `.`, so the whole `short_name` is the terminal [`SegmentKind::Member`].
/// C++ member names never contain a literal `.`, so the single `.` (if any)
/// separates the owner chain from the member.
pub fn cpp_member_fq(package_name: &str, short_name: &str) -> FqName {
    let mut fq = FqName::new();
    cpp_push_package(&mut fq, package_name);
    match short_name.rsplit_once('.') {
        Some((owner_chain, member)) => {
            cpp_push_type_chain(&mut fq, owner_chain);
            fq.push(cpp_segment(member, SegmentKind::Member));
        }
        None => fq.push(cpp_segment(short_name, SegmentKind::Member)),
    }
    fq
}

#[derive(Clone)]
pub struct ScopeInfo {
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
    /// Named-child index to stop before (`usize::MAX` = drain the parent).
    /// Bounded ranges re-own a swallowed region's head and tail with
    /// different scopes (issue #1524).
    end_index: usize,
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

pub fn cpp_export_macro_token(token: &str) -> bool {
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
/// verbatim for a region reparse (issue #941 machinery) so every recovered member
/// keeps its exact original byte/line position. `class_range` is the full class
/// navigation range spanning to the displaced closing brace.
struct FragmentedExportBody {
    reparse_start: usize,
    reparse_end: usize,
    class_range: Range,
}

/// Result of validating a reparsed fragmented class body.  A complete tree can
/// safely consume the whole region.  A partial tree may contain only the exact
/// class-named constructor that tree-sitter merged into an access label; its
/// remaining siblings must stay on the ordinary outer walk.
enum FragmentedExportMembers {
    Complete(Tree),
    ConditionalConstructor(Tree),
}

#[derive(Clone, Copy)]
struct DisplacedMacroClassTail {
    split_index: usize,
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
        let Some(current) = sibling else {
            break displaced_fragment_close_at_namespace_boundary(node, body, source)?;
        };
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

/// Locate the true class-body region for the export-macro class shape that
/// tree-sitter promotes to a `function_definition`.
///
/// In this shape the synthetic function body closes at the first inline
/// method, while the class's real members continue as root-level siblings until
/// a stray `}` followed by the displaced class `;`. Reparse the complete
/// interior so those siblings are visited with the recovered class scope.
fn fragmented_export_function_body_region(
    node: Node<'_>,
    body: Node<'_>,
    source: &str,
) -> Option<FragmentedExportBody> {
    let reparse_start = body.start_byte().checked_add(1)?;
    let siblings = cpp_following_named_siblings(node, source);
    let boundary = fragmented_export_sibling_class_boundary(node, source);
    let boundary_index = boundary.and_then(|boundary| {
        siblings
            .iter()
            .position(|candidate| same_node(*candidate, boundary))
    });
    let siblings = &siblings[..boundary_index.unwrap_or(siblings.len())];
    let mut sibling_index = 0;
    // A complete recovered class's synthetic wrapper is immediately followed
    // by its displaced semicolon (comments may sit between the body and that
    // semicolon). Only scan for a later stray close when real member siblings
    // intervene; otherwise every earlier complete class would borrow the next
    // malformed class's close and claim its members.
    while let Some(current) = siblings.get(sibling_index).copied() {
        if current.kind() == "comment" {
            sibling_index += 1;
            continue;
        }
        if cpp_is_stray_semicolon(current, source) {
            return None;
        }
        break;
    }
    while let Some(current) = siblings.get(sibling_index).copied() {
        let next = siblings.get(sibling_index + 1).copied();
        if cpp_is_stray_close_brace(current, source)
            && next.is_some_and(|next| cpp_is_stray_semicolon(next, source))
        {
            let semicolon = next.expect("checked above");
            return Some(FragmentedExportBody {
                reparse_start,
                reparse_end: current.start_byte(),
                class_range: Range {
                    start_byte: node.start_byte(),
                    end_byte: semicolon.end_byte(),
                    start_line: node.start_position().row + 1,
                    end_line: semicolon.end_position().row + 1,
                },
            });
        }
        // When the final access label keeps the class close in its malformed
        // declaration body, tree-sitter nests the lone `}` ERROR below the
        // label instead of exposing it as a direct sibling. Search only the
        // scattered siblings after the synthetic wrapper. The first such
        // close is the class terminator because nested class bodies retain
        // their own balanced class_specifier nodes.
        if current.start_byte() >= body.end_byte()
            && let Some(close) = cpp_nested_stray_close_brace(current, source)
        {
            return Some(FragmentedExportBody {
                reparse_start,
                reparse_end: close.start_byte(),
                class_range: Range {
                    start_byte: node.start_byte(),
                    end_byte: current.end_byte(),
                    start_line: node.start_position().row + 1,
                    end_line: current.end_position().row + 1,
                },
            });
        }
        sibling_index += 1;
    }
    boundary.map(|boundary| FragmentedExportBody {
        reparse_start,
        reparse_end: boundary.start_byte(),
        class_range: Range {
            start_byte: node.start_byte(),
            end_byte: boundary.start_byte(),
            start_line: node.start_position().row + 1,
            end_line: boundary.start_position().row + 1,
        },
    })
}

/// Find a later macro-export class that tree-sitter lifted through an enclosing
/// preprocessor container. A class that is still a direct sibling can be a
/// nested member of the current fragmented class, so only a changed parent is
/// a proven boundary between the two recovered class envelopes.
fn fragmented_export_sibling_class_boundary<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let node_parent = node.parent()?;
    cpp_following_named_siblings(node, source)
        .into_iter()
        .find(|candidate| {
            recover_exported_class_function_definition(*candidate, source).is_some()
                && candidate
                    .parent()
                    .is_none_or(|candidate_parent| !same_node(node_parent, candidate_parent))
        })
}

/// Find a lone closing-brace ERROR below a scattered sibling.  A malformed
/// export-class wrapper can place the class close inside an access-label node,
/// so direct-sibling checks alone miss the boundary.  Walk named CST children
/// only; the helper does not inspect source text beyond the existing structured
/// stray-brace predicate.
fn cpp_nested_stray_close_brace<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if cpp_is_stray_close_brace(current, source) {
            return Some(current);
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    None
}

/// Return named siblings that follow `node`, including siblings that tree-sitter
/// attached to an enclosing container after malformed recovery split the local
/// declaration list. Stop at the first structurally visible class close so a
/// later namespace or exported class cannot supply the recovery boundary.
fn cpp_following_named_siblings<'tree>(node: Node<'tree>, source: &str) -> Vec<Node<'tree>> {
    let mut siblings = Vec::new();
    let mut anchor = node;
    while let Some(parent) = anchor.parent() {
        let at_translation_unit = parent.kind() == "translation_unit";
        let mut sibling = anchor.next_named_sibling();
        while let Some(current) = sibling {
            if at_translation_unit
                && (current.kind() == "namespace_definition"
                    || (current.kind() == "function_definition"
                        && first_class_like_child(current).is_some()))
            {
                return siblings;
            }
            siblings.push(current);
            if cpp_is_stray_close_brace(current, source) {
                if let Some(semicolon) = current
                    .next_named_sibling()
                    .filter(|candidate| cpp_is_stray_semicolon(*candidate, source))
                {
                    siblings.push(semicolon);
                }
                return siblings;
            }
            if current.start_byte() >= node.end_byte()
                && matches!(current.kind(), "ERROR" | "labeled_statement")
                && cpp_nested_stray_close_brace(current, source).is_some()
            {
                return siblings;
            }
            sibling = current.next_named_sibling();
        }
        anchor = parent;
    }
    siblings
}

fn cpp_fragment_sibling_is_class_member(node: Node<'_>, class_end: usize, source: &str) -> bool {
    if node.start_byte() >= class_end {
        return false;
    }
    node.end_byte() <= class_end
        || cpp_nested_stray_close_brace(node, source)
            .is_some_and(|close| close.start_byte() == class_end)
}

/// Recover a plain class whose opening prefix is retained in one ERROR node
/// while one or more nested class closes and the outer close are displaced to
/// sibling `}`/`;` nodes. This is the non-export counterpart to the fragmented
/// export-class recovery above. All boundaries come from tree-sitter nodes: the
/// direct class tokens establish nesting depth and the displaced close nodes
/// terminate it.
fn fragmented_plain_class_body(
    node: Node<'_>,
    source: &str,
) -> Option<(String, FragmentedExportBody)> {
    if node.kind() != "ERROR" {
        return None;
    }
    let mut cursor = node.walk();
    let children = node.children(&mut cursor).collect::<Vec<_>>();
    let keyword = children.first()?;
    if !matches!(keyword.kind(), "class" | "struct" | "union") {
        return None;
    }
    let name_node = children
        .iter()
        .copied()
        .skip(1)
        .find(|child| child.is_named())?;
    if !matches!(name_node.kind(), "type_identifier" | "identifier") {
        return None;
    }
    let name = normalize_cpp_whitespace(node_text(name_node, source));
    if name.is_empty() || cpp_export_macro_token(&name) {
        return None;
    }
    let open_index = children.iter().position(|child| child.kind() == "{")?;
    let open = children[open_index];
    let nested_class_opens = children[open_index + 1..]
        .iter()
        .filter(|child| matches!(child.kind(), "class" | "struct" | "union"))
        .count();
    let mut closes_remaining = 1 + nested_class_opens;
    let mut sibling = node.next_named_sibling();
    while let Some(candidate) = sibling {
        let next = candidate.next_named_sibling();
        if cpp_is_stray_close_brace(candidate, source) {
            closes_remaining -= 1;
            if closes_remaining == 0 {
                let semicolon = next.filter(|node| cpp_is_stray_semicolon(*node, source))?;
                if open.end_byte() >= candidate.start_byte() {
                    return None;
                }
                return Some((
                    name,
                    FragmentedExportBody {
                        reparse_start: open.end_byte(),
                        reparse_end: candidate.start_byte(),
                        class_range: Range {
                            start_byte: node.start_byte(),
                            end_byte: semicolon.end_byte(),
                            start_line: node.start_position().row + 1,
                            end_line: semicolon.end_position().row + 1,
                        },
                    },
                ));
            }
        }
        sibling = next;
    }
    None
}

fn displaced_fragment_close_at_namespace_boundary<'tree>(
    declaration: Node<'tree>,
    body: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let declaration_list = declaration.parent()?;
    if declaration_list.kind() != "declaration_list" {
        return None;
    }
    let namespace = declaration_list.parent()?;
    if namespace.kind() != "namespace_definition"
        || namespace.child_by_field_name("body") != Some(declaration_list)
    {
        return None;
    }
    let class_close = direct_close_brace(declaration_list)?;
    let trailing_semicolon = namespace.next_named_sibling()?;
    if trailing_semicolon.kind() != "expression_statement"
        || trailing_semicolon.named_child_count() != 0
    {
        return None;
    }
    let displaced_namespace_close = trailing_semicolon.next_named_sibling()?;
    if !cpp_is_stray_close_brace(displaced_namespace_close, source) {
        return None;
    }
    let reparse_start = body.start_byte() + 1;
    let tree = cpp_reparse_region_items(source, reparse_start, class_close.start_byte())?;
    cpp_reparsed_members_are_indexable(tree.root_node(), source).then_some(class_close)
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

/// Byte offset of the `}` matching the `{` at `open_byte`, scanning the source
/// text while skipping line/block comments and string/char literals. The
/// exported-class recovery needs this when tree-sitter's bogus
/// `function_definition` body runs past the class's true closing brace and
/// swallows following siblings (issue #1524): the grammar tree carries no
/// usable close node (the body ends in a zero-width `MISSING "}"`), so the
/// close is located textually. Returns `None` when the text is unbalanced or
/// contains a construct the scanner deliberately does not interpret (raw
/// strings) -- callers treat that as "cannot partition" and keep the
/// un-split recovery.
fn cpp_matching_close_brace(source: &str, open_byte: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(open_byte) != Some(&b'{') {
        return None;
    }
    let mut depth = 0usize;
    let mut i = open_byte;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = i.checked_add(2).filter(|&end| end <= bytes.len())?;
                continue;
            }
            quote @ (b'"' | b'\'') => {
                // Raw strings (R"(...)") can hold unescaped quotes and braces;
                // bail out rather than mis-count.
                if quote == b'"' && i > 0 && bytes[i - 1] == b'R' {
                    return None;
                }
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                if i >= bytes.len() {
                    return None;
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
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
) -> Option<(Node<'tree>, String, Option<Vec<String>>)> {
    if node.kind() != "function_definition" {
        return None;
    }
    let type_node = node.child_by_field_name("type")?;
    let declarator = node.child_by_field_name("declarator")?;

    if matches!(
        type_node.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier"
    ) {
        let type_name = type_node
            .child_by_field_name("name")
            .and_then(|name| direct_identifier_name(name, source));
        let exported_macro_type = type_name
            .as_ref()
            .is_some_and(|name| cpp_export_macro_token(name));
        if exported_macro_type {
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
                let raw_supertypes = errors_before_declarator
                    .iter()
                    .any(|error| malformed_inheritance_syntax(*error))
                    .then(|| recovered_malformed_base_name(declarator, source))
                    .flatten()
                    .map(|base| vec![base]);
                return Some((node, name, raw_supertypes));
            }
            if errors_before_declarator
                .iter()
                .any(|error| malformed_inheritance_syntax(*error))
            {
                return None;
            }
        }
        if !exported_macro_type
            && let Some(name) = type_name
            && !cpp_export_macro_token(&name)
            && let Some(base) =
                recovered_postfix_export_macro_base(node, type_node, declarator, source)
        {
            return Some((node, name, Some(vec![base])));
        }
        if let Some(name) = direct_identifier_name(declarator, source)
            && exported_macro_type
            && !cpp_export_macro_token(&name)
        {
            let raw_supertypes = exported_macro_type
                .then(|| recovered_single_base_after_declarator(node, declarator, source))
                .flatten()
                .map(|base| vec![base]);
            return Some((node, name, raw_supertypes));
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
                return Some((node, name, None));
            }
        }
    }

    let declarator_text = direct_identifier_name(declarator, source)?;
    if !matches!(declarator_text.as_str(), "class" | "struct" | "union") {
        return None;
    }
    class_identifier_before_body(node, source).map(|name| (node, name, None))
}

/// Recover the class item from a region reparse that still carries the
/// sentinel's synthetic function envelope.  An unknown class attribute can
/// make tree-sitter parse `class ATTR Span { ... }` as a function whose type
/// is `class ATTR` and whose declarator is `Span`.  The parser's class node is
/// then nested below that function, so direct class-child lookup is not enough.
struct CppSentinelReparsedClass<'tree> {
    declaration_node: Node<'tree>,
    name: String,
    body: Node<'tree>,
    raw_supertypes: Option<Vec<String>>,
}

fn cpp_sentinel_reparsed_leading_template(root: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = root.walk();
    root.named_children(&mut cursor)
        .find(|child| child.kind() != "comment")
        .filter(|child| child.kind() == "template_declaration")
}

fn cpp_sentinel_reparsed_class<'tree>(
    root: Node<'tree>,
    template_node: Option<Node<'tree>>,
    source: &str,
) -> Option<CppSentinelReparsedClass<'tree>> {
    let container = template_node.unwrap_or(root);
    let mut cursor = container.walk();
    for child in container.named_children(&mut cursor) {
        if matches!(
            child.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) {
            let name = class_like_name(child, source)?;
            let body = cpp_body_node(child)?;
            let raw_supertypes = matches!(child.kind(), "class_specifier" | "struct_specifier")
                .then(|| extract_cpp_supertypes(child, source));
            return Some(CppSentinelReparsedClass {
                declaration_node: child,
                name,
                body,
                raw_supertypes,
            });
        }
        if child.kind() == "declaration"
            && let Some(class_node) = first_class_like_child(child)
        {
            let name = class_like_name(class_node, source)?;
            let body = cpp_body_node(class_node)?;
            let raw_supertypes =
                matches!(class_node.kind(), "class_specifier" | "struct_specifier")
                    .then(|| extract_cpp_supertypes(class_node, source));
            return Some(CppSentinelReparsedClass {
                declaration_node: class_node,
                name,
                body,
                raw_supertypes,
            });
        }
        // Only when the nested class item carries its own body. A bodyless
        // `class ATTR` -- the type half of `class ATTR Span { ... }` reduced to
        // a function definition -- is the export-macro shape recovered by the
        // next arm, and must fall through to it rather than abort the search.
        if child.kind() == "function_definition"
            && let Some(class_node) = first_class_like_child(child)
            && let Some(body) = cpp_body_node(class_node)
            && let Some(name) = class_like_name(class_node, source)
        {
            let raw_supertypes =
                matches!(class_node.kind(), "class_specifier" | "struct_specifier")
                    .then(|| extract_cpp_supertypes(class_node, source));
            return Some(CppSentinelReparsedClass {
                declaration_node: class_node,
                name,
                body,
                raw_supertypes,
            });
        }
        if child.kind() == "function_definition"
            && let Some((_, name, raw_supertypes)) =
                recover_exported_class_function_definition(child, source)
        {
            let body = cpp_body_node(child)?;
            return Some(CppSentinelReparsedClass {
                declaration_node: child,
                name,
                body,
                raw_supertypes,
            });
        }
    }
    None
}

fn recovered_postfix_export_macro_base(
    node: Node<'_>,
    type_node: Node<'_>,
    declarator: Node<'_>,
    source: &str,
) -> Option<String> {
    let mut cursor = node.walk();
    let mut malformed_clauses = node.named_children(&mut cursor).filter(|child| {
        child.kind() == "ERROR"
            && child.start_byte() >= type_node.end_byte()
            && child.end_byte() <= declarator.start_byte()
            && postfix_export_macro_inheritance(*child, source)
    });
    malformed_clauses.next()?;
    if malformed_clauses.next().is_some() {
        return None;
    }
    recovered_malformed_base_name(declarator, source)
}

fn postfix_export_macro_inheritance(node: Node<'_>, source: &str) -> bool {
    let mut macro_count = 0;
    let mut colon_count = 0;
    let mut access_count = 0;
    for index in 0..node.child_count() {
        let Some(child) = node.child(index) else {
            return false;
        };
        match child.kind() {
            "identifier" | "type_identifier" if child.is_named() => {
                let candidate = normalize_cpp_whitespace(node_text(child, source));
                if !cpp_export_macro_token(&candidate) {
                    return false;
                }
                macro_count += 1;
            }
            ":" if !child.is_named() => colon_count += 1,
            "public" | "protected" | "private" if !child.is_named() => access_count += 1,
            _ => return false,
        }
    }
    macro_count == 1 && colon_count == 1 && access_count == 1
}

fn recovered_single_base_after_declarator(
    node: Node<'_>,
    declarator: Node<'_>,
    source: &str,
) -> Option<String> {
    let body_start = node
        .child_by_field_name("body")
        .map(|body| body.start_byte())
        .unwrap_or(node.end_byte());
    let mut cursor = node.walk();
    let mut bases = node
        .named_children(&mut cursor)
        .filter(|child| {
            child.kind() == "ERROR"
                && child.start_byte() >= declarator.end_byte()
                && child.end_byte() <= body_start
        })
        .filter_map(|error| displaced_exported_class_name(error, source));
    let base = bases.next()?;
    bases.next().is_none().then_some(base)
}

fn malformed_inheritance_syntax(node: Node<'_>) -> bool {
    (0..node.child_count()).any(|index| {
        node.child(index)
            .is_some_and(|child| matches!(child.kind(), ":" | "public" | "protected" | "private"))
    })
}

pub fn is_recovered_exported_class_container(node: Node<'_>, source: &str) -> bool {
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

pub fn is_direct_recovered_exported_class_field_declaration(node: Node<'_>, source: &str) -> bool {
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

pub fn recovered_exported_class_has_body(
    node: Node<'_>,
    source: &str,
    expected_name: &str,
) -> Option<bool> {
    match node.kind() {
        "function_definition" => {
            let (class_node, name, _) = recover_exported_class_function_definition(node, source)?;
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
        end_index: usize::MAX,
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
    if siblings.next_index >= siblings.end_index {
        return;
    }
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
        end_index: siblings.end_index,
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
pub fn cpp_file_using_namespaces(source: &str) -> Vec<String> {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .is_err()
    {
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

pub struct CppVisitor<'a> {
    pub file: &'a ProjectFile,
    pub source: &'a str,
    pub parsed: &'a mut ParsedFile,
    pub recovered_class_sibling_scopes: HashMap<usize, ScopeInfo>,
    /// Byte regions whose contents were re-owned by a fragmented export-class
    /// recovery (#938): the scattered members between the fragmented
    /// declaration and its displaced closing brace are indexed as members of
    /// the recovered class by the region reparse, so the ordinary sibling walk
    /// must not ALSO index them as top-level declarations (that double-indexing
    /// made a scattered nested class ambiguous between `Inner` and
    /// `Widget$Inner`). Regions are rare (one per fragmented recovery), so a
    /// linear scan at visit time is fine.
    pub consumed_fragment_regions: Vec<(usize, usize)>,
}

impl<'a> CppVisitor<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn visit_container(
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

    /// Reparse a fragmented multiple-base export class body (issue #938), admitting
    /// it only when the entire region is member-shaped. This validation must happen
    /// before registering the recovered class because a rejected speculative range
    /// must not leak into the ordinary recovery path.
    fn reparse_fragmented_export_class_members(
        &self,
        fragmented: &FragmentedExportBody,
        class_name: &str,
    ) -> Option<FragmentedExportMembers> {
        if fragmented.reparse_start >= fragmented.reparse_end {
            return None;
        }
        let tree = cpp_reparse_fragmented_class_body(
            self.source,
            fragmented.reparse_start,
            fragmented.reparse_end,
        )?;
        if cpp_reparsed_members_are_indexable(tree.root_node(), self.source) {
            return Some(FragmentedExportMembers::Complete(tree));
        }
        let has_conditional_constructor = {
            let root = tree.root_node();
            let mut cursor = root.walk();
            root.named_children(&mut cursor).any(|child| {
                cpp_reparsed_preprocessor_constructor(child, class_name, self.source).is_some()
            })
        };
        has_conditional_constructor.then_some(FragmentedExportMembers::ConditionalConstructor(tree))
    }

    /// Index an already validated fragmented body as members of `class_unit`. The
    /// region reparse keeps each member's exact original byte and line positions.
    fn visit_fragmented_export_class_members(
        &mut self,
        outcome: FragmentedExportMembers,
        class_unit: CodeUnit,
        scope: &ScopeInfo,
    ) -> bool {
        let (tree, complete) = match outcome {
            FragmentedExportMembers::Complete(tree) => (tree, true),
            FragmentedExportMembers::ConditionalConstructor(tree) => (tree, false),
        };
        let root = tree.root_node();
        let class_name = class_unit.identifier().to_string();
        let member_scope = ScopeInfo {
            // A recovered export-macro class may borrow its namespace from an
            // earlier forward declaration even when the malformed node itself
            // sits at file scope. Use the recovered class identity as the
            // authoritative package for reparsed members as well.
            package_name: class_unit.package_name().to_string(),
            module: scope.module.clone(),
            class_unit: Some(class_unit),
            template_signature: scope.template_signature.clone(),
            template_metadata: None,
            declarations_are_fields: true,
            recovered_specialization_member_scope: false,
            visible_using_namespaces: scope.visible_using_namespaces.clone(),
        };
        if !complete {
            // A conditional beginning immediately after an access label can
            // fragment one constructor declaration while leaving the rest of
            // the class body as unsafe statement soup. Recover only that
            // structurally proven constructor and leave the outer-tree
            // siblings unconsumed for their ordinary walk.
            let mut cursor = root.walk();
            let constructors = root
                .named_children(&mut cursor)
                .filter_map(|child| {
                    cpp_reparsed_preprocessor_constructor(child, &class_name, self.source)
                })
                .collect::<Vec<_>>();
            for constructor in constructors {
                let mut stack = Vec::new();
                self.visit_node(constructor, &member_scope, &mut stack);
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
            }
            return false;
        }
        self.run_container_work(root, member_scope);
        true
    }

    fn visit_recovered_fragment_constructor(
        &mut self,
        range: std::ops::Range<usize>,
        constructor_body: Node<'_>,
        class_declaration: Node<'_>,
        class_unit: &CodeUnit,
        scope: &ScopeInfo,
    ) {
        let Some(tree) = cpp_reparse_region_items(self.source, range.start, range.end) else {
            return;
        };
        let Some(function_declarator) = cpp_reparsed_exact_constructor_declarator(
            tree.root_node(),
            range.start,
            class_unit.identifier(),
            self.source,
        ) else {
            return;
        };
        let member_scope = ScopeInfo {
            package_name: class_unit.package_name().to_string(),
            module: scope.module.clone(),
            class_unit: Some(class_unit.clone()),
            template_signature: scope.template_signature.clone(),
            template_metadata: None,
            declarations_are_fields: true,
            recovered_specialization_member_scope: false,
            visible_using_namespaces: scope.visible_using_namespaces.clone(),
        };
        let Some(function) = extract_function_info(function_declarator, self.source, &member_scope)
        else {
            return;
        };
        debug_assert_eq!(function.name, class_unit.identifier());
        let code_unit = function.code_unit(self.file.clone());
        self.parsed.add_code_unit_with_range(
            code_unit.clone(),
            Range {
                start_byte: function_declarator.start_byte(),
                end_byte: constructor_body.end_byte(),
                start_line: function_declarator.start_position().row + 1,
                end_line: constructor_body.end_position().row + 1,
            },
            None,
            None,
        );
        self.parsed.add_signature_with_metadata(
            code_unit.clone(),
            cpp_signature_metadata(
                normalize_cpp_whitespace(node_text(function_declarator, self.source)),
                function_declarator,
                self.source,
            )
            .with_declaration_only(false)
            .with_callable_linkage(cpp_callable_linkage(class_declaration, self.source)),
        );
        self.parsed.add_child(class_unit.clone(), code_unit);
    }

    fn visit_recovered_fragment_prefix_members(
        &mut self,
        root: Node<'_>,
        constructor_start: usize,
        class_unit: &CodeUnit,
        scope: &ScopeInfo,
    ) {
        let member_scope = ScopeInfo {
            package_name: class_unit.package_name().to_string(),
            module: scope.module.clone(),
            class_unit: Some(class_unit.clone()),
            template_signature: scope.template_signature.clone(),
            template_metadata: None,
            declarations_are_fields: true,
            recovered_specialization_member_scope: false,
            visible_using_namespaces: scope.visible_using_namespaces.clone(),
        };
        let mut stack = vec![root];
        while let Some(current) = stack.pop() {
            if current.kind() == "comment" || current.start_byte() >= constructor_start {
                continue;
            }
            if current.end_byte() <= constructor_start
                && current.kind() != "translation_unit"
                && current.kind() != "labeled_statement"
                && current.kind() != "ERROR"
            {
                let mut work_stack = Vec::new();
                self.visit_node(current, &member_scope, &mut work_stack);
                while let Some(work) = work_stack.pop() {
                    match work {
                        CppWork::Container(container) => {
                            push_cpp_container_work(
                                container.node,
                                container.scope,
                                &mut work_stack,
                            );
                        }
                        CppWork::Siblings(siblings) => {
                            advance_cpp_siblings(siblings, self.source, &mut work_stack);
                        }
                        CppWork::Node(work) => {
                            self.visit_node(work.node, &work.scope, &mut work_stack)
                        }
                    }
                }
                continue;
            }
            if matches!(
                current.kind(),
                "translation_unit" | "labeled_statement" | "ERROR"
            ) {
                let mut cursor = current.walk();
                stack.extend(current.named_children(&mut cursor));
            }
        }
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
        if let Some((name, fragmented)) = fragmented_plain_class_body(node, self.source) {
            let outcome = self.reparse_fragmented_export_class_members(&fragmented, &name);
            let mut class_stack = Vec::new();
            let class_unit = self.visit_named_class_like_shape(
                node,
                name,
                None,
                true,
                Some(fragmented.class_range),
                Some(extract_cpp_supertypes(node, self.source)),
                scope,
                &mut class_stack,
            );
            let member_scope = ScopeInfo {
                package_name: class_unit.package_name().to_string(),
                module: scope.module.clone(),
                class_unit: Some(class_unit.clone()),
                template_signature: scope.template_signature.clone(),
                template_metadata: None,
                declarations_are_fields: true,
                recovered_specialization_member_scope: false,
                visible_using_namespaces: scope.visible_using_namespaces.clone(),
            };
            let complete = outcome.is_some_and(|outcome| {
                self.visit_fragmented_export_class_members(outcome, class_unit, scope)
            });
            if complete {
                self.consumed_fragment_regions
                    .push((node.start_byte(), fragmented.class_range.end_byte));
            } else {
                // A macro-constrained member can make the full body reparse
                // unsafe while tree-sitter still exposes later class members
                // as bounded siblings up to the displaced `}`/`;`. Keep the
                // structurally proven class/base declaration and re-own those
                // sibling nodes under it. They retain their original parser
                // nodes and exact ranges; the close boundary comes solely from
                // `fragmented_plain_class_body`.
                let mut sibling = node.next_named_sibling();
                while let Some(candidate) = sibling {
                    if candidate.start_byte() >= fragmented.reparse_end {
                        break;
                    }
                    if cpp_fragment_sibling_is_class_member(
                        candidate,
                        fragmented.reparse_end,
                        self.source,
                    ) {
                        self.recovered_class_sibling_scopes
                            .insert(candidate.id(), member_scope.clone());
                    }
                    sibling = candidate.next_named_sibling();
                }
            }
            stack.extend(class_stack);
            return;
        }
        match node.kind() {
            "template_declaration" => {
                if let Some(recovered) = recover_fragmented_preprocessor_class(node, self.source) {
                    let mut template_scope = scope.clone();
                    template_scope.template_signature =
                        cpp_template_signature(node, recovered.declaration_node, self.source);
                    template_scope.template_metadata =
                        cpp_template_metadata(node, recovered.class_node, self.source);
                    let raw_supertypes =
                        Some(extract_cpp_supertypes(recovered.class_node, self.source));
                    let mut class_stack = Vec::new();
                    let class_unit = self.visit_named_class_like_shape(
                        recovered.class_node,
                        recovered.name,
                        Some(recovered.body),
                        true,
                        Some(recovered.range),
                        raw_supertypes,
                        &template_scope,
                        &mut class_stack,
                    );
                    self.parsed.record_materialization(
                        MaterializationRecord::RecoveredDeclaration {
                            recovery: recovered.range,
                            unit: class_unit.clone(),
                        },
                    );
                    let member_scope = ScopeInfo {
                        package_name: template_scope.package_name.clone(),
                        module: template_scope.module.clone(),
                        class_unit: Some(class_unit.clone()),
                        template_signature: template_scope.template_signature.clone(),
                        template_metadata: None,
                        declarations_are_fields: true,
                        recovered_specialization_member_scope: recovered
                            .class_node
                            .child_by_field_name("name")
                            .is_some_and(|name| name.kind() == "template_type"),
                        visible_using_namespaces: template_scope.visible_using_namespaces.clone(),
                    };
                    for tail_member in recovered.tail_members.into_iter().rev() {
                        stack.push(CppWork::Node(CppNodeWork {
                            node: tail_member,
                            scope: member_scope.clone(),
                        }));
                    }
                    stack.extend(class_stack);
                    for sibling in recovered.member_siblings {
                        self.recovered_class_sibling_scopes
                            .insert(sibling.id(), member_scope.clone());
                    }
                    return;
                }
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
            // A bare namespace-begin sentinel can make tree-sitter promote the
            // wrapped declaration to an ERROR node instead of the usual bogus
            // function_definition envelope. Keep the recovery entry point on
            // the same structured path for both shapes; ordinary ERROR nodes
            // retain their declaration-preserving wrapper traversal when the
            // sentinel predicate does not match.
            "ERROR" => {
                if !self.visit_sentinel_macro_region(node, scope) {
                    stack.push(CppWork::Container(CppContainer {
                        node,
                        scope: scope.clone(),
                    }));
                }
            }
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
                // A preprocessor conditional gates every declaration inside it
                // on a configuration this analyzer never evaluates; record the
                // interval so declaration state can say so (issue #1476). The
                // else/elif branches are children of the `preproc_if` node, so
                // recording the openers covers every branch.
                if matches!(kind, "preproc_if" | "preproc_ifdef" | "preproc_ifndef") {
                    self.parsed.record_materialization(
                        MaterializationRecord::ConfigurationConditional {
                            range: cpp_declaration_range(node),
                        },
                    );
                }
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
        // Diagnostic corpora contain deliberately ill-formed global namespace
        // definitions such as `namespace ::outer::inner {}`. Tree-sitter keeps
        // the leading global `::` as the first anonymous child. Honor that AST
        // boundary instead of appending the name to the lexical namespace;
        // appending produced legacy names such as `outer::::outer::inner`, which
        // could not round-trip through the structured FqName boundary.
        let explicitly_global = name_node
            .child(0)
            .is_some_and(|child| !child.is_named() && child.kind() == "::");
        let name = if explicitly_global {
            let marker = name_node.child(0).expect("checked global namespace marker");
            normalize_cpp_whitespace(
                self.source
                    .get(marker.end_byte()..name_node.end_byte())
                    .expect("namespace marker and name share one source range"),
            )
        } else {
            normalize_cpp_whitespace(node_text(name_node, self.source))
        };
        if name.is_empty() {
            return;
        }
        let full_name = if explicitly_global || scope.package_name.is_empty() {
            name
        } else {
            format!("{}::{}", scope.package_name, name)
        };
        let module = CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Module,
            "",
            full_name.clone(),
            cpp_namespace_fq(&full_name),
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
        let displaced_macro_tail = if explicit_range.is_none() {
            body.and_then(|body| displaced_macro_class_tail(declaration_node, body, self.source))
        } else {
            None
        };
        let explicit_range = explicit_range.or(displaced_macro_tail.map(|tail| tail.class_range));
        let recovered_scope = self.scope_for_recovered_exported_class(
            declaration_node,
            &name,
            definition_body_present,
            scope,
        );
        let scope = &recovered_scope;
        let short_name = if let Some(parent) = &scope.class_unit {
            format!("{}${name}", parent.short_name())
        } else {
            name
        };
        let fq = cpp_class_fq(&scope.package_name, &short_name);
        let code_unit = CodeUnit::with_signature_and_fq(
            self.file.clone(),
            CodeUnitType::Class,
            scope.package_name.clone(),
            short_name,
            scope.template_signature.clone(),
            false,
            fq,
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
            if let Some(displaced) = displaced_macro_tail {
                // A macro-shaped field without a source semicolon can make
                // tree-sitter consume the real class terminator as an ERROR
                // inside that field, then retain following namespace items as
                // later field-list children. Drain the proven class prefix
                // first and re-own only the structured tail with the outer
                // scope. The tail is pushed first because the work stack is
                // LIFO.
                stack.push(CppWork::Siblings(CppSiblingsWork {
                    parent: body,
                    next_index: displaced.split_index,
                    end_index: usize::MAX,
                    scope: scope.clone(),
                }));
                stack.push(CppWork::Siblings(CppSiblingsWork {
                    parent: body,
                    next_index: 0,
                    end_index: displaced.split_index,
                    scope: nested_scope,
                }));
            } else {
                stack.push(CppWork::Container(CppContainer {
                    node: body,
                    scope: nested_scope,
                }));
            }
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
            let code_unit = CodeUnit::new_fq(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), name),
                parent
                    .fq()
                    .clone()
                    .with_pushed(cpp_segment(&name, SegmentKind::Member)),
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
            let code_unit = CodeUnit::new_fq(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), name),
                parent
                    .fq()
                    .clone()
                    .with_pushed(cpp_segment(name, SegmentKind::Member)),
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
        if let Some((class_node, name, raw_supertypes)) =
            recover_exported_class_function_definition(node, self.source)
        {
            let body = cpp_body_node(class_node);
            let fragmented = cpp_body_node(node)
                .and_then(|body| fragmented_export_function_body_region(node, body, self.source));
            // The recovery tuple's first node is the class-like type when the
            // parser exposes one, but the synthetic wrapper owns the compound
            // statement that contains the truncated class body. Use the
            // wrapper body for fragmented-member detection; retain the
            // class-node body for the ordinary (non-fragmented) path below.
            if let Some(fragmented) = fragmented {
                // The lifted sibling no longer sits below the parser-visible
                // namespace node. Restore the current parent scope when the
                // ordinary work walk reaches that class.
                if let Some(boundary) = fragmented_export_sibling_class_boundary(node, self.source)
                    .filter(|boundary| boundary.start_byte() == fragmented.reparse_end)
                {
                    let mut boundary_scope = scope.clone();
                    for sibling in cpp_following_named_siblings(node, self.source) {
                        if sibling.start_byte() >= boundary.start_byte() {
                            break;
                        }
                        if let Some(namespace) = cpp_using_namespace_target(sibling, self.source) {
                            boundary_scope.visible_using_namespaces.push(namespace);
                        }
                    }
                    self.recovered_class_sibling_scopes
                        .insert(boundary.id(), boundary_scope);
                }
                let mut recovered_constructor = None;
                let mut recovered_prefix_tree = None;
                let outcome = match self.reparse_fragmented_export_class_members(&fragmented, &name)
                {
                    Some(FragmentedExportMembers::Complete(tree)) => {
                        if let Some(body) = body
                            && let Some(range) =
                                cpp_reparsed_synthetic_initializer_constructor_range(
                                    tree.root_node(),
                                    &name,
                                    self.source,
                                    body.end_byte(),
                                )
                        {
                            recovered_constructor = Some(range);
                            recovered_prefix_tree = Some(tree);
                            None
                        } else {
                            Some(FragmentedExportMembers::Complete(tree))
                        }
                    }
                    outcome => outcome,
                };
                let mut class_stack = Vec::new();
                let class_unit = self.visit_named_class_like_shape(
                    class_node,
                    name,
                    None,
                    true,
                    Some(fragmented.class_range),
                    raw_supertypes,
                    scope,
                    &mut class_stack,
                );
                self.parsed
                    .record_materialization(MaterializationRecord::RecoveredDeclaration {
                        recovery: fragmented.class_range,
                        unit: class_unit.clone(),
                    });
                let complete = outcome.is_some_and(|outcome| {
                    self.visit_fragmented_export_class_members(outcome, class_unit.clone(), scope)
                });
                if complete {
                    self.consumed_fragment_regions
                        .push((node.start_byte(), fragmented.class_range.end_byte));
                } else {
                    // The reparse can fail when the first constructor or a
                    // method body is split into statement-shaped siblings.
                    // Keep the recovered class envelope, but do not visit the
                    // synthetic wrapper body: its initializer expressions can
                    // look like same-named member functions (for example
                    // `Token.location(loc)`). Re-own only the original sibling
                    // nodes that fall inside the proven class range. Their CST
                    // shapes retain the real field/function kinds and ranges.
                    let member_scope = ScopeInfo {
                        package_name: class_unit.package_name().to_string(),
                        module: scope.module.clone(),
                        class_unit: Some(class_unit.clone()),
                        template_signature: scope.template_signature.clone(),
                        template_metadata: None,
                        declarations_are_fields: true,
                        recovered_specialization_member_scope: false,
                        visible_using_namespaces: scope.visible_using_namespaces.clone(),
                    };
                    for candidate in cpp_following_named_siblings(node, self.source) {
                        if candidate.start_byte() >= fragmented.reparse_end {
                            break;
                        }
                        if cpp_fragment_sibling_is_class_member(
                            candidate,
                            fragmented.reparse_end,
                            self.source,
                        ) {
                            self.recovered_class_sibling_scopes
                                .insert(candidate.id(), member_scope.clone());
                        }
                    }
                    if let Some(range) = recovered_constructor
                        && let (Some(prefix_tree), Some(body)) = (recovered_prefix_tree, body)
                    {
                        self.visit_recovered_fragment_prefix_members(
                            prefix_tree.root_node(),
                            range.start,
                            &class_unit,
                            scope,
                        );
                        self.visit_recovered_fragment_constructor(
                            range,
                            body,
                            class_node,
                            &class_unit,
                            scope,
                        );
                    }
                }
                stack.extend(class_stack);
                return;
            }
            let mut stack = Vec::new();
            let class_unit = self.visit_named_class_like_shape(
                class_node,
                name,
                body,
                body.is_some(),
                None,
                raw_supertypes,
                scope,
                &mut stack,
            );
            self.parsed
                .record_materialization(MaterializationRecord::RecoveredDeclaration {
                    recovery: cpp_declaration_range(node),
                    unit: class_unit,
                });
            // Issue #1524: the bogus `function_definition` body can run past
            // the class's true closing brace (the parse ends it with a
            // zero-width `MISSING "}"`), swallowing following namespace-scope
            // siblings -- they would index as members of the recovered class.
            // When the body's text-balanced close lands before the body's own
            // end, re-own the swallowed tail with the outer scope instead.
            if let Some(body) = body
                && let Some(class_close) = cpp_matching_close_brace(self.source, body.start_byte())
                && class_close < body.end_byte()
            {
                let split = {
                    let mut cursor = body.walk();
                    body.named_children(&mut cursor)
                        .position(|child| child.start_byte() > class_close)
                };
                if let Some(split) = split {
                    // The seeded work is a single Container over the whole
                    // body with the class scope; replace it with the bounded
                    // head (class scope) plus the swallowed tail (outer
                    // scope). Push tail first so the head drains first.
                    let seeded = stack.pop();
                    match seeded {
                        Some(CppWork::Container(container)) => {
                            stack.push(CppWork::Siblings(CppSiblingsWork {
                                parent: body,
                                next_index: split,
                                end_index: usize::MAX,
                                scope: scope.clone(),
                            }));
                            stack.push(CppWork::Siblings(CppSiblingsWork {
                                parent: body,
                                next_index: 0,
                                end_index: split,
                                scope: container.scope,
                            }));
                        }
                        // visit_named_class_like_shape always seeds exactly
                        // one Container when a body is present.
                        _ => unreachable!("exported-class seed is always one Container"),
                    }
                }
            }
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
        let recovered_constraint_constructor =
            cpp_recovered_template_macro_constructor(node, self.source);
        let declarator = recovered_constraint_constructor
            .map(|(declarator, _)| declarator)
            .or_else(|| node.child_by_field_name("declarator"));
        let Some(declarator) = declarator else {
            self.visit_malformed_function_definition_container(node, scope, stack);
            return;
        };
        let Some(function_declarator) = extract_function_declarator(declarator) else {
            self.visit_malformed_function_definition_container(node, scope, stack);
            return;
        };
        let Some(mut function) = extract_function_info(function_declarator, self.source, scope)
        else {
            self.visit_malformed_function_definition_container(node, scope, stack);
            return;
        };
        if let Some((_, template_parameter)) = recovered_constraint_constructor {
            function.signature = format!(
                "template <{}>{}",
                normalize_cpp_whitespace(node_text(template_parameter, self.source)),
                function.signature
            );
        }
        let code_unit = function.code_unit(self.file.clone());
        // Keep an earlier same-file prototype as another physical occurrence
        // of this callable. `CodeUnit` already identifies the role-neutral
        // overload, while ranges and signature metadata describe its
        // declaration/definition occurrences.
        self.parsed
            .add_code_unit(code_unit.clone(), node, self.source, None, None);
        let signature = if recovered_constraint_constructor.is_some() {
            normalize_cpp_whitespace(node_text(function_declarator, self.source))
        } else {
            render_cpp_function_display_signature_from_node(
                node,
                self.source,
                scope.template_signature.as_deref(),
                true,
            )
        };
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

    /// Recover the namespace lost when tree-sitter promotes an export-macro
    /// class definition to a root-level `function_definition`.  Only a
    /// body-bearing, top-level recovery may borrow a namespace, and only when
    /// one earlier namespace-scope forward declaration proves the identity.
    fn scope_for_recovered_exported_class(
        &self,
        node: Node<'_>,
        name: &str,
        definition_body_present: bool,
        scope: &ScopeInfo,
    ) -> ScopeInfo {
        if !definition_body_present
            || !scope.package_name.is_empty()
            || scope.class_unit.is_some()
            || !(is_recovered_exported_class_container(node, self.source)
                || matches!(node.kind(), "declaration" | "field_declaration")
                    && recover_exported_class_declaration(node, self.source).is_some()
                || matches!(
                    node.kind(),
                    "class_specifier" | "struct_specifier" | "union_specifier"
                ) && (node.child_by_field_name("name").is_some_and(|name_node| {
                    cpp_export_macro_token(&normalize_cpp_whitespace(node_text(
                        name_node,
                        self.source,
                    )))
                }) || node.parent().is_some_and(|parent| {
                    matches!(parent.kind(), "declaration" | "field_declaration")
                        && recover_exported_class_declaration(parent, self.source).is_some()
                        || is_recovered_exported_class_container(parent, self.source)
                })) && class_like_name(node, self.source).as_deref() == Some(name))
        {
            return scope.clone();
        }
        let Some(package_name) = unique_earlier_cpp_namespace_forward(node, name, self.source)
        else {
            return scope.clone();
        };

        let module = CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Module,
            "",
            package_name.clone(),
            cpp_namespace_fq(&package_name),
        );
        let mut recovered = scope.clone();
        recovered.package_name = package_name;
        recovered.module = Some(module);
        recovered
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
    /// sentinel identifier as real C++ items -- confined to the region so
    /// every reparsed node keeps its original byte/line position -- and run the
    /// ordinary container visitation over the result. Returns `true` when it fired
    /// (the caller must then skip normal function processing). Nested sentinel
    /// regions recover recursively: the reparsed interior is walked through the
    /// same `visit_function_definition` path, so a sentinel inside the region hits
    /// this recovery again.
    fn visit_sentinel_macro_region(&mut self, node: Node<'_>, scope: &ScopeInfo) -> bool {
        if self.visit_nested_namespace_sentinel(node, scope) {
            return true;
        }
        if let Some((
            reparse_start,
            class_start,
            body_start,
            class_close_start,
            class_close_end,
            class_close_line,
        )) = cpp_sentinel_macro_class_region(node, self.source)
        {
            let Some(class_tree) =
                cpp_reparse_region_items(self.source, reparse_start, class_close_end)
            else {
                return false;
            };
            let class_root = class_tree.root_node();
            let template_node = cpp_sentinel_reparsed_leading_template(class_root);
            let Some(reparsed_class) =
                cpp_sentinel_reparsed_class(class_root, template_node, self.source)
            else {
                return false;
            };
            let class_node = reparsed_class.declaration_node;
            let name = reparsed_class.name;
            let mut class_scope = scope.clone();
            if let Some(template_node) = template_node {
                class_scope.template_signature =
                    cpp_template_signature(template_node, class_node, self.source);
                class_scope.template_metadata =
                    cpp_template_metadata(template_node, class_node, self.source);
            }
            let Some(body_tree) =
                cpp_reparse_region_items(self.source, body_start, class_close_start)
            else {
                return false;
            };
            let raw_supertypes = reparsed_class.raw_supertypes;
            let class_range = Range {
                start_byte: class_start,
                end_byte: class_close_end,
                start_line: class_node.start_position().row + 1,
                end_line: class_close_line,
            };
            let class_scope =
                self.scope_for_recovered_exported_class(class_node, &name, true, &class_scope);
            let mut class_stack = Vec::new();
            let class_unit = self.visit_named_class_like_shape(
                class_node,
                name,
                None,
                true,
                Some(class_range),
                raw_supertypes,
                &class_scope,
                &mut class_stack,
            );
            let member_scope = ScopeInfo {
                package_name: class_scope.package_name.clone(),
                module: class_scope.module.clone(),
                class_unit: Some(class_unit),
                template_signature: class_scope.template_signature.clone(),
                template_metadata: None,
                declarations_are_fields: true,
                recovered_specialization_member_scope: false,
                visible_using_namespaces: class_scope.visible_using_namespaces.clone(),
            };
            self.run_container_work(body_tree.root_node(), member_scope);
            // Register only after the padded body reparse: its nodes deliberately
            // retain offsets inside the consumed region and must be visited first.
            self.consumed_fragment_regions
                .push((node.start_byte(), class_close_end));
            return true;
        }
        let Some((start, end)) = cpp_sentinel_macro_region(node, self.source) else {
            return false;
        };
        let Some(tree) = cpp_reparse_region_items(self.source, start, end) else {
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
        if end > node.end_byte() {
            self.consumed_fragment_regions
                .push((node.start_byte(), end));
        }
        true
    }

    /// Re-own complete class declarations from the structured Abseil
    /// namespace-sentinel shape.  The malformed root `ERROR` is not reparsed:
    /// its direct CST children already prove both namespace components and the
    /// class bodies, so the ordinary class/member visitor can retain ownership
    /// and exact source ranges without admitting unrelated callable bodies.
    fn visit_nested_namespace_sentinel(&mut self, node: Node<'_>, scope: &ScopeInfo) -> bool {
        let Some(recovered) = cpp_nested_namespace_sentinel(node, self.source) else {
            return false;
        };

        let mut package_name = scope.package_name.clone();
        let mut module = scope.module.clone();
        for component in recovered.namespace_components {
            package_name = if package_name.is_empty() {
                component
            } else {
                format!("{package_name}::{component}")
            };
            let namespace_module = CodeUnit::new_fq(
                self.file.clone(),
                CodeUnitType::Module,
                "",
                package_name.clone(),
                cpp_namespace_fq(&package_name),
            );
            if !self.parsed.contains_declaration(&namespace_module) {
                self.parsed.add_code_unit(
                    namespace_module.clone(),
                    recovered.function,
                    self.source,
                    None,
                    None,
                );
            }
            module = Some(namespace_module);
        }

        let recovered_scope = ScopeInfo {
            package_name,
            module,
            class_unit: scope.class_unit.clone(),
            template_signature: scope.template_signature.clone(),
            template_metadata: scope.template_metadata.clone(),
            declarations_are_fields: false,
            recovered_specialization_member_scope: false,
            visible_using_namespaces: scope.visible_using_namespaces.clone(),
        };
        if let Some(fragmented) =
            cpp_sentinel_fragmented_class_tail(recovered.function, recovered.body, self.source)
        {
            let mut class_scope = recovered_scope.clone();
            if let Some(template_node) = fragmented.template_node {
                class_scope.template_signature =
                    cpp_template_signature(template_node, fragmented.class_node, self.source);
                class_scope.template_metadata =
                    cpp_template_metadata(template_node, fragmented.class_node, self.source);
            }
            let raw_supertypes = matches!(
                fragmented.class_node.kind(),
                "class_specifier" | "struct_specifier"
            )
            .then(|| extract_cpp_supertypes(fragmented.class_node, self.source));
            if let Some(outcome) = self
                .reparse_fragmented_export_class_members(&fragmented.fragmented, &fragmented.name)
            {
                let mut class_stack = Vec::new();
                let class_unit = self.visit_named_class_like_shape(
                    fragmented.class_node,
                    fragmented.name.clone(),
                    None,
                    true,
                    Some(fragmented.fragmented.class_range),
                    raw_supertypes,
                    &class_scope,
                    &mut class_stack,
                );
                if self.visit_fragmented_export_class_members(outcome, class_unit, &class_scope) {
                    self.consumed_fragment_regions.push((
                        fragmented.consumed_start,
                        fragmented.fragmented.class_range.end_byte,
                    ));
                }
            }
        }
        // The class requirement above is the admission gate; once admitted,
        // traverse the whole proven inner namespace body so sibling aliases,
        // functions, and variables are not silently discarded.
        self.run_container_work(recovered.body, recovered_scope);
        true
    }

    fn visit_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        in_class_body: bool,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        if self.visit_sentinel_macro_region(node, scope) {
            return;
        }
        if recovered_macro_return_type_node(node, self.source).is_some_and(|declarator| {
            !cpp_active_template_type_parameter(
                node,
                node_text(declarator, self.source),
                self.source,
            )
        }) {
            return;
        }
        if in_class_body
            && let Some(call) = recovered_macro_qualified_function_call(node, self.source)
        {
            self.visit_recovered_macro_qualified_function_declaration(node, call, scope);
            return;
        }
        if in_class_body
            && let Some(declarators) =
                recovered_macro_qualified_field_declarators(node, self.source)
        {
            for declarator in declarators {
                self.visit_variable_declaration(node, declarator, scope, true);
            }
            return;
        }
        let recovered_alias_names = recovered_type_alias_names(node, self.source);
        if !recovered_alias_names.is_empty() {
            self.add_type_aliases(node, scope, recovered_alias_names);
            return;
        }

        if let Some(recovered) = recover_exported_class_declaration(node, self.source) {
            if let Some(fragmented) = recovered.fragmented_body.as_ref() {
                // Issue #938: the members tree-sitter scattered out of the fragmented
                // multiple-base export node are reparsed from their true body region
                // and re-owned as members of the recovered class, with an explicit
                // navigation range spanning to the displaced closing brace.
                if let Some(outcome) =
                    self.reparse_fragmented_export_class_members(fragmented, &recovered.name)
                {
                    let consumed_region = (
                        recovered.declaration_node.end_byte(),
                        fragmented.class_range.end_byte,
                    );
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
                    let consume_fragment =
                        self.visit_fragmented_export_class_members(outcome, code_unit, scope);
                    // Everything between the fragmented declaration and its displaced
                    // closing brace now belongs to the recovered class; keep the
                    // ordinary walk from re-indexing those scattered siblings at top
                    // level. Register the consumed region only after indexing because
                    // the reparsed nodes retain byte offsets inside that same region.
                    if consume_fragment {
                        self.consumed_fragment_regions.push(consumed_region);
                    }
                    return;
                }
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
                // A named class-like definition remains a declaration even when
                // the same statement also declares an object, for example
                // `enum Kind { A } kind;`.  Tree-sitter exposes the enum as the
                // declaration's type and `kind` as its declarator.  Dropping the
                // type here loses both its nested owner and every later lexical
                // reference to it.  A body is the structured proof that this is
                // a definition rather than an elaborated type use such as
                // `class Kind value;`.
                if cpp_body_node(child).is_some() {
                    self.visit_class_like(child, scope, stack);
                }
                continue;
            }
        }

        let mut cursor = node.walk();
        for child in node.children_by_field_name("declarator", &mut cursor) {
            if crate::structural::is_recovered_designator_init_declarator(child) {
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
                if crate::structural::is_recovered_designator_init_declarator(child) {
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

    fn visit_recovered_macro_qualified_function_declaration(
        &mut self,
        declaration_node: Node<'_>,
        call: Node<'_>,
        scope: &ScopeInfo,
    ) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(name_node) = call.child_by_field_name("function") else {
            return;
        };
        let Some(arguments) = call.child_by_field_name("arguments") else {
            return;
        };
        let Some((signature, parameter_labels)) =
            recovered_macro_qualified_function_parameters(arguments, self.source)
        else {
            return;
        };
        let arity = parameter_labels.len();
        let function = FunctionInfo {
            package_name: scope.package_name.clone(),
            owner_path: Some(parent.short_name().to_string()),
            name: normalize_cpp_whitespace(node_text(name_node, self.source)),
            signature,
        };
        if function.name.is_empty() {
            return;
        }
        let code_unit = function.code_unit_with_synthetic(self.file.clone(), true);
        if self.parsed.contains_declaration(&code_unit) {
            self.parsed
                .record_navigation_range(code_unit, cpp_declaration_range(declaration_node));
            return;
        }
        self.parsed
            .add_code_unit(code_unit.clone(), declaration_node, self.source, None, None);
        let signature_label = render_cpp_function_display_signature_from_node(
            declaration_node,
            self.source,
            scope.template_signature.as_deref(),
            false,
        );
        let metadata = SignatureMetadata::with_parameter_labels(signature_label, parameter_labels)
            .with_declaration_only(true)
            .with_callable_arity(CallableArity::exact(arity))
            .with_callable_linkage(cpp_callable_linkage(declaration_node, self.source));
        self.parsed
            .add_signature_with_metadata(code_unit.clone(), metadata);
        self.parsed.add_child(parent.clone(), code_unit);
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
        let fq = cpp_member_fq(&scope.package_name, &short_name);
        let code_unit = CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Field,
            scope.package_name.clone(),
            short_name,
            fq,
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
            binder_span: None,
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

        if let Some(recovered) = recovered_macro_typedef_alias(node, self.source) {
            let range = Range {
                start_byte: node.start_byte(),
                end_byte: recovered.end_node.end_byte(),
                start_line: node.start_position().row + 1,
                end_line: recovered.end_node.end_position().row + 1,
            };
            let signature = self
                .source
                .get(range.start_byte..range.end_byte)
                .map(normalize_cpp_whitespace)
                .unwrap_or_default();
            self.record_type_aliases(node, scope, vec![recovered.name], signature, range);
            return;
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
        self.record_type_aliases(
            node,
            scope,
            alias_names,
            signature,
            cpp_declaration_range(node),
        );
    }

    fn record_type_aliases(
        &mut self,
        node: Node<'_>,
        scope: &ScopeInfo,
        alias_names: Vec<String>,
        signature: String,
        range: Range,
    ) {
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
            let fq = cpp_class_fq(&scope.package_name, &short_name);
            let code_unit = CodeUnit::with_signature_and_fq(
                self.file.clone(),
                CodeUnitType::Class,
                scope.package_name.clone(),
                short_name,
                Some(signature.clone()),
                false,
                fq,
            );
            // Declaration identity does not include the alias signature. Keep
            // each physical range so conditional aliases retain their guards.
            self.parsed
                .add_code_unit_with_range(code_unit.clone(), range, None, None);
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
        let fq = cpp_member_fq("", &name);
        let code_unit = CodeUnit::new_fq(self.file.clone(), CodeUnitType::Macro, "", name, fq);
        if self.parsed.contains_declaration_identity(&code_unit) {
            return;
        }
        self.parsed
            .add_code_unit(code_unit.clone(), node, self.source, None, None);
        let name_range = node
            .child_by_field_name("name")
            .map(cpp_declaration_range)
            .unwrap_or_else(|| cpp_declaration_range(node));
        self.parsed
            .record_materialization(MaterializationRecord::GeneratedDeclaration {
                site: cpp_declaration_range(node),
                argument: name_range,
                kind: GenerationKind::PreprocessorDefinition,
                unit: code_unit.clone(),
            });
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

pub fn recover_quoted_includes(source: &str, parsed: &mut ParsedFile) {
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
            binder_span: None,
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
        let fq = cpp_member_fq(&self.package_name, &short_name);
        CodeUnit::with_signature_and_fq(
            file,
            CodeUnitType::Function,
            self.package_name.clone(),
            short_name,
            Some(self.signature.clone()),
            synthetic,
            fq,
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
        .or_else(|| parameters_node.prev_named_sibling())?;
    let recovered_specialization_member = scope
        .recovered_specialization_member_scope
        .then(|| {
            let terminal = declarator_name_node
                .child_by_field_name("name")
                .unwrap_or(declarator_name_node);
            let name = canonical_cpp_qualified_component(terminal, source)?.name;
            let owner = scope.class_unit.as_ref()?;
            Some((
                Some(owner.short_name().to_string()),
                name,
                scope.package_name.clone(),
            ))
        })
        .flatten();
    let (owner_path, name, package_name) = if let Some(parts) = recovered_specialization_member {
        parts
    } else if let Some(parts) =
        split_structured_templated_cpp_name(declarator_name_node, source, scope)
    {
        parts
    } else {
        let raw_name = normalize_cpp_whitespace(&extract_callable_declarator_name(
            declarator_name_node,
            source,
        )?);
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

/// Find the unique namespace-scope forward declaration that precedes a
/// recovered export-macro class definition.  Tree-sitter can close a malformed
/// class at the enclosing namespace's closing brace, leaving the later class
/// definitions as root-level recovered `function_definition` nodes.  A
/// preceding `class Name;` in the same namespace is the only structured identity
/// signal available in that shape.
///
/// The search is deliberately conservative: it only accepts a body-less class
/// specifier whose declaration has no declarator and is not nested in a function
/// or class body.  More than one matching namespace forward declaration is
/// ambiguous and returns `None` rather than guessing.
fn unique_earlier_cpp_namespace_forward(
    recovered_node: Node<'_>,
    name: &str,
    source: &str,
) -> Option<String> {
    let mut root = recovered_node;
    while let Some(parent) = root.parent() {
        root = parent;
    }

    let mut candidates = Vec::new();
    let mut stack = vec![root];
    while let Some(current) = stack.pop() {
        if current.start_byte() < recovered_node.start_byte()
            && matches!(
                current.kind(),
                "class_specifier" | "struct_specifier" | "union_specifier"
            )
            && cpp_body_node(current).is_none()
            && current.parent().is_some_and(|parent| {
                parent.kind() == "declaration_list"
                    || parent.kind() == "declaration" && !has_direct_cpp_declarator(parent)
            })
            && class_like_name(current, source).as_deref() == Some(name)
            && cpp_namespace_definition_for_forward(current).is_some_and(|namespace| {
                // Borrowing is only justified by the parser-recovery shape we
                // are repairing: the namespace that held the forward must
                // itself contain a syntax error and must have closed before
                // the root-level recovered class. A clean, unrelated
                // namespace forward is not an identity proof.
                namespace.has_error()
                    && namespace.end_byte() < recovered_node.start_byte()
                    && malformed_namespace_is_nearest_recovery_region(namespace, recovered_node)
            })
            && let Some(package_name) = cpp_namespace_name_for_forward(current, source)
        {
            candidates.push(package_name);
        }

        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            if child.start_byte() < recovered_node.start_byte() {
                stack.push(child);
            }
        }
    }

    if candidates.len() == 1 {
        candidates.pop()
    } else {
        None
    }
}

fn malformed_namespace_is_nearest_recovery_region(
    namespace: Node<'_>,
    recovered_node: Node<'_>,
) -> bool {
    let mut root = recovered_node;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let mut cursor = root.walk();
    root.named_children(&mut cursor)
        .filter(|sibling| {
            namespace.end_byte() <= sibling.start_byte()
                && sibling.end_byte() <= recovered_node.start_byte()
        })
        .all(is_malformed_namespace_recovery_trivia)
}

fn is_malformed_namespace_recovery_trivia(node: Node<'_>) -> bool {
    matches!(node.kind(), "ERROR" | "comment")
        || node.kind().starts_with("preproc_")
        || node.kind() == "expression_statement" && node.named_child_count() == 0
}

/// Return the namespace path for a forward class only when the declaration is
/// at namespace scope.  A declaration nested in a function/class body may share
/// the same namespace ancestor but cannot identify a top-level class definition.
fn cpp_namespace_name_for_forward(node: Node<'_>, source: &str) -> Option<String> {
    cpp_namespace_definition_for_forward(node)?;
    cpp_lexical_namespace_name(node, source)
}

fn cpp_namespace_definition_for_forward(node: Node<'_>) -> Option<Node<'_>> {
    let declaration = node.parent()?;
    let mut ancestor = declaration.parent();
    while let Some(current) = ancestor {
        if matches!(
            current.kind(),
            "compound_statement"
                | "field_declaration_list"
                | "class_specifier"
                | "struct_specifier"
                | "union_specifier"
                | "function_definition"
                | "lambda_expression"
        ) {
            return None;
        }
        if current.kind() == "namespace_definition" {
            return Some(current);
        }
        ancestor = current.parent();
    }
    None
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
    // A leading `::` is the explicit-global marker, not an empty owner segment.
    // Error recovery can leave a definition spelled `::X(...)` (e.g. an
    // erroneous macro envelope swallowing the first identifier of an
    // out-of-line `X::X` constructor, chromium #1573); without this strip the
    // split below yields owner_parts `[""]`, constructing a unit with an empty
    // owner chain (`short ".X"`) that the FqName boundary assert rejects.
    let cleaned = cleaned.trim_start_matches("::");
    // Parser recovery can preserve two adjacent scope operators around a
    // missing component (for example `X::/**/::method` in compiler diagnostic
    // fixtures). Empty components are syntax-recovery artifacts, never C++
    // owners. Keeping one as the final owner constructed `short_name=".method"`
    // and violated the structured package/short boundary during a large LLVM
    // workspace build. This is the same legacy-string-to-FqName bridge as the
    // ordinary split above; discard only components that the delimiter itself
    // proves empty.
    let parts: Vec<_> = cleaned
        .split("::")
        .filter(|component| !component.is_empty())
        .collect();
    if parts.is_empty() {
        return (None, cleaned.to_string(), scope.package_name.clone());
    }
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

/// Extract a callable identity only through declaration-shaped AST nodes.
/// Error recovery around trailing `decltype((object.*f)(...))` expressions can
/// expose the call's parameter list as a false function declarator; accepting
/// arbitrary node text there emitted bogus names such as `.*f`.
fn extract_callable_declarator_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier"
        | "field_identifier"
        | "type_identifier"
        | "operator_name"
        | "destructor_name"
        | "qualified_identifier" => Some(node_text(node, source).to_string()),
        "function_declarator"
        | "pointer_declarator"
        | "reference_declarator"
        | "parenthesized_declarator"
        | "array_declarator"
        | "template_function" => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .and_then(|child| extract_callable_declarator_name(child, source)),
        _ => None,
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
    if node_text(keyword, source) == "typedef"
        && let Some(alias_name) = recovered_typedef_error_alias_name(node, declarator, source)
    {
        return vec![alias_name];
    }
    extract_typedef_declarator_name(declarator, source)
        .into_iter()
        .collect()
}

fn recovered_typedef_error_alias_name(
    declaration: Node<'_>,
    declarator: Node<'_>,
    source: &str,
) -> Option<String> {
    // An export macro between `class` and its name can make tree-sitter parse
    // the recovered class body as a function body. In that shape,
    //
    //     typedef spi::Filter BASE_CLASS;
    //
    // becomes a declaration whose `declarator` is the underlying qualified
    // type (`spi::Filter`) and whose actual alias name is displaced into the
    // following ERROR node. Do not publish the terminal underlying type
    // (`Filter`) as a false class-owned alias.
    if declarator.kind() != "qualified_identifier" {
        return None;
    }
    let mut cursor = declaration.walk();
    let mut errors = declaration
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "ERROR" && child.start_byte() >= declarator.end_byte());
    let error = errors.next()?;
    if errors.next().is_some() || error.named_child_count() != 1 {
        return None;
    }
    let name = error.named_child(0)?;
    if !matches!(
        name.kind(),
        "identifier" | "field_identifier" | "type_identifier"
    ) {
        return None;
    }
    let name = normalize_cpp_whitespace(node_text(name, source));
    (!name.is_empty()).then_some(name)
}

fn extract_typedef_alias_names(node: Node<'_>, source: &str) -> Vec<String> {
    // A function-like token in the type position can make tree-sitter expose
    // its argument as a parenthesized declarator. Do not publish that argument
    // as an alias. The macro-specific recovery below handles the proven shape.
    if fragmented_parenthesized_typedef_type(node).is_some() {
        return Vec::new();
    }
    let has_function_like_macro_type = node
        .child_by_field_name("type")
        .filter(|type_node| type_node.kind() == "type_identifier")
        .is_some_and(|type_node| {
            cpp_export_macro_token(&normalize_cpp_whitespace(node_text(type_node, source)))
        });
    let mut names = Vec::new();
    let mut cursor = node.walk();
    for declarator in node.children_by_field_name("declarator", &mut cursor) {
        if has_function_like_macro_type && declarator.kind() == "parenthesized_declarator" {
            continue;
        }
        if let Some(name) = extract_typedef_declarator_name(declarator, source)
            && !names.contains(&name)
        {
            names.push(name);
        }
    }
    names
}

struct RecoveredMacroTypedefAlias<'tree> {
    name: String,
    end_node: Node<'tree>,
}

/// Recover `typedef MACRO(type) alias;` when tree-sitter splits the final alias
/// into an identifier expression statement. The uppercase macro token, missing
/// typedef terminator, and complete sibling terminator prove this exact shape.
fn recovered_macro_typedef_alias<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<RecoveredMacroTypedefAlias<'tree>> {
    let type_node = fragmented_parenthesized_typedef_type(node)?;
    if type_node.kind() != "type_identifier"
        || !cpp_export_macro_token(&normalize_cpp_whitespace(node_text(type_node, source)))
    {
        return None;
    }

    let end_node = node.next_named_sibling()?;
    if end_node.kind() != "expression_statement" || end_node.named_child_count() != 1 {
        return None;
    }
    let name_node = end_node.named_child(0)?;
    if name_node.kind() != "identifier" {
        return None;
    }
    let has_terminator = (0..end_node.child_count()).any(|index| {
        end_node
            .child(index)
            .is_some_and(|child| child.kind() == ";" && !child.is_missing())
    });
    if !has_terminator {
        return None;
    }
    let name = normalize_cpp_whitespace(node_text(name_node, source));
    (!name.is_empty()).then_some(RecoveredMacroTypedefAlias { name, end_node })
}

fn fragmented_parenthesized_typedef_type(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "type_definition" {
        return None;
    }
    let mut declarator_cursor = node.walk();
    let mut declarators = node.children_by_field_name("declarator", &mut declarator_cursor);
    if declarators.next()?.kind() != "parenthesized_declarator" || declarators.next().is_some() {
        return None;
    }
    let has_missing_terminator = (0..node.child_count()).any(|index| {
        node.child(index)
            .is_some_and(|child| child.kind() == ";" && child.is_missing())
    });
    if !has_missing_terminator {
        return None;
    }
    node.child_by_field_name("type")
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
    if let Some(signature) =
        render_recovered_macro_qualified_field_signature(node, declarator, source)
    {
        return signature;
    }
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

fn render_recovered_macro_qualified_field_signature(
    node: Node<'_>,
    declarator: Node<'_>,
    source: &str,
) -> Option<String> {
    let recovered = recovered_macro_qualified_field_declarators(node, source)?;
    if !recovered
        .iter()
        .any(|candidate| same_node(*candidate, declarator))
    {
        return None;
    }
    let pseudo_declarator = node.child_by_field_name("declarator")?;
    let mut cursor = node.walk();
    let clause = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "bitfield_clause")?;
    let mut cursor = clause.walk();
    let error = clause
        .named_children(&mut cursor)
        .find(|child| child.kind() == "ERROR")?;
    let qualified_type =
        normalize_cpp_whitespace(source.get(pseudo_declarator.start_byte()..error.end_byte())?);
    let prefix = cpp_declaration_prefix(node, source);
    let name = extract_variable_name(declarator, source)?;
    let suffix = cpp_recovered_expression_declarator_suffix(declarator, source);
    let mut rendered = if suffix.is_empty() {
        format!("{prefix} {qualified_type} {name}")
    } else {
        format!("{prefix} {qualified_type} {suffix} {name}")
    };
    rendered = collapse_cpp_whitespace(&rendered);

    if let Some(initializer) = recovered_macro_qualified_field_initializer(clause, declarator) {
        Some(format!(
            "{rendered} = {};",
            normalize_cpp_whitespace(node_text(initializer, source))
        ))
    } else if let Some(initializer) = cpp_preserved_initializer(node, declarator, source) {
        Some(format!("{rendered} = {initializer};"))
    } else {
        Some(format!("{rendered};"))
    }
}

fn cpp_recovered_expression_declarator_suffix(node: Node<'_>, source: &str) -> String {
    match node.kind() {
        "pointer_expression" => {
            let operator = node
                .child_by_field_name("operator")
                .or_else(|| node.child(0))
                .map(|operator| node_text(operator, source))
                .unwrap_or("*");
            let argument = node
                .child_by_field_name("argument")
                .map(|argument| cpp_recovered_expression_declarator_suffix(argument, source))
                .unwrap_or_default();
            format!("{operator}{argument}")
        }
        "unary_expression" => {
            let operator = node
                .child_by_field_name("operator")
                .or_else(|| node.child(0))
                .map(|operator| node_text(operator, source))
                .unwrap_or_default();
            let argument = node
                .child_by_field_name("argument")
                .map(|argument| cpp_recovered_expression_declarator_suffix(argument, source))
                .unwrap_or_default();
            format!("{operator}{argument}")
        }
        "identifier" | "field_identifier" => String::new(),
        _ => cpp_declarator_suffix_without_name(node, source),
    }
}

fn recovered_macro_qualified_field_initializer<'tree>(
    clause: Node<'tree>,
    declarator: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut stack = vec![clause];
    while let Some(current) = stack.pop() {
        if current.kind() == "assignment_expression"
            && current
                .child_by_field_name("left")
                .is_some_and(|left| same_node(left, declarator))
        {
            return current.child_by_field_name("right");
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    None
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

struct RecoveredFragmentedPreprocessorClass<'tree> {
    declaration_node: Node<'tree>,
    class_node: Node<'tree>,
    body: Node<'tree>,
    name: String,
    range: Range,
    tail_members: Vec<Node<'tree>>,
    member_siblings: Vec<Node<'tree>>,
}

/// Recover a class whose preprocessor-fragmented parse closes at an early
/// member body and publishes the remaining in-class declarations as siblings
/// of the surrounding alternative. Primary classes are admitted only when an
/// earlier branch contains the matching bodyless declaration and the class
/// node retains the displaced `#endif`. Partial specializations instead carry
/// their identity structurally in the `template_type` name and template
/// metadata. Retain the original AST nodes and re-own only the siblings through
/// the displaced structural `};` terminator.
fn recover_fragmented_preprocessor_class<'tree>(
    template_node: Node<'tree>,
    source: &str,
) -> Option<RecoveredFragmentedPreprocessorClass<'tree>> {
    let alternative = template_node.parent()?;
    if alternative.kind() != "preproc_else" {
        return None;
    }
    let conditional = alternative.parent()?;
    if conditional.kind() != "preproc_if" {
        return None;
    }
    let declaration_node = template_node
        .named_children(&mut template_node.walk())
        .find(|child| matches!(child.kind(), "declaration" | "function_definition"))?;
    let class_node = declaration_node
        .named_children(&mut declaration_node.walk())
        .find(|child| matches!(child.kind(), "class_specifier" | "struct_specifier"))?;
    let body = cpp_body_node(class_node)?;
    if class_node.end_byte() >= declaration_node.end_byte() {
        return None;
    }
    let name = class_like_name(class_node, source)?;
    let is_partial_specialization = class_node
        .child_by_field_name("name")
        .is_some_and(|class_name| class_name.kind() == "template_type");
    if is_partial_specialization {
        let metadata = cpp_template_metadata(template_node, class_node, source)?;
        if metadata.specialization_arguments.is_empty() || !class_node.has_error() {
            return None;
        }
    } else {
        if !class_has_displaced_preprocessor_terminator(class_node) {
            return None;
        }
        let matching_other_branch = conditional
            .named_children(&mut conditional.walk())
            .take_while(|child| !same_node(*child, alternative))
            .filter(|child| child.kind() == "template_declaration")
            .filter_map(first_class_like_child)
            .any(|candidate| {
                cpp_body_node(candidate).is_none()
                    && class_like_name(candidate, source).as_deref() == Some(name.as_str())
            });
        if !matching_other_branch {
            return None;
        }
    }

    let mut tail_members = Vec::new();
    let mut saw_class = false;
    let mut declaration_cursor = declaration_node.walk();
    for child in declaration_node.named_children(&mut declaration_cursor) {
        if same_node(child, class_node) {
            saw_class = true;
        } else if saw_class {
            tail_members.push(child);
        }
    }

    let mut member_siblings = Vec::new();
    let mut saw_template = false;
    let mut terminator = None;
    for index in 0..alternative.child_count() {
        let Some(child) = alternative.child(index) else {
            continue;
        };
        if same_node(child, template_node) {
            saw_template = true;
            continue;
        }
        if !saw_template {
            continue;
        }
        if displaced_fragmented_class_terminator(alternative, index) {
            terminator = alternative.child(index + 1);
            break;
        }
        if child.is_named() {
            member_siblings.push(child);
        }
    }
    let terminator = terminator?;
    Some(RecoveredFragmentedPreprocessorClass {
        declaration_node,
        class_node,
        body,
        name,
        range: Range {
            start_byte: class_node.start_byte(),
            end_byte: terminator.end_byte(),
            start_line: class_node.start_position().row + 1,
            end_line: terminator.end_position().row + 1,
        },
        tail_members,
        member_siblings,
    })
}

fn class_has_displaced_preprocessor_terminator(class_node: Node<'_>) -> bool {
    (0..class_node.child_count()).any(|index| {
        class_node.child(index).is_some_and(|child| {
            child.kind() == "ERROR"
                && (0..child.child_count()).any(|error_index| {
                    child
                        .child(error_index)
                        .is_some_and(|token| token.kind() == "#endif")
                })
        })
    })
}

fn displaced_fragmented_class_terminator(parent: Node<'_>, error_index: usize) -> bool {
    let Some(error) = parent.child(error_index) else {
        return false;
    };
    if error.kind() != "ERROR"
        || error.child_count() != 1
        || error.child(0).is_none_or(|child| child.kind() != "}")
    {
        return false;
    }
    let Some(semicolon) = parent.child(error_index + 1) else {
        return false;
    };
    semicolon.kind() == "expression_statement"
        && semicolon.child_count() == 1
        && semicolon.child(0).is_some_and(|child| child.kind() == ";")
}

/// Locate the real end of a class-like declaration when a macro invocation
/// without a source semicolon absorbs the class's `};` into its parsed field.
/// The grammar then keeps following namespace declarations as later children
/// of the same field list. The direct ERROR-plus-semicolon pair proves the
/// boundary structurally; no source-text delimiter scan is needed.
fn displaced_macro_class_tail(
    declaration_node: Node<'_>,
    body: Node<'_>,
    source: &str,
) -> Option<DisplacedMacroClassTail> {
    if !matches!(
        declaration_node.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier"
    ) || body.kind() != "field_declaration_list"
    {
        return None;
    }

    let child_count = body.named_child_count();
    for index in 0..child_count {
        let child = body.named_child(index)?;
        let Some(terminator) = displaced_macro_field_terminator(child, source) else {
            continue;
        };
        let split_index = index + 1;
        if split_index >= child_count {
            return None;
        }
        let mut cursor = body.walk();
        if !body
            .named_children(&mut cursor)
            .skip(split_index)
            .any(|tail| cpp_is_indexable_item_kind(tail.kind()))
        {
            return None;
        }
        return Some(DisplacedMacroClassTail {
            split_index,
            class_range: Range {
                start_byte: declaration_node.start_byte(),
                end_byte: terminator.end_byte(),
                start_line: declaration_node.start_position().row + 1,
                end_line: terminator.end_position().row + 1,
            },
        });
    }
    None
}

fn displaced_macro_field_terminator<'tree>(
    field: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    if field.kind() != "field_declaration" {
        return None;
    }
    let macro_type = field.child_by_field_name("type")?;
    if macro_type.kind() != "type_identifier"
        || !cpp_export_macro_token(&normalize_cpp_whitespace(node_text(macro_type, source)))
        || field.child_by_field_name("declarator")?.kind() != "parenthesized_declarator"
    {
        return None;
    }
    for index in 0..field.child_count() {
        let error = field.child(index)?;
        if error.kind() != "ERROR"
            || error.child_count() != 1
            || error.child(0).is_none_or(|child| child.kind() != "}")
        {
            continue;
        }
        let semicolon = field.child(index + 1)?;
        if semicolon.kind() == ";" {
            return Some(semicolon);
        }
    }
    None
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
            variadic: matches!(
                parameter.kind(),
                "variadic_type_parameter_declaration" | "variadic_parameter_declaration"
            ),
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

pub fn cpp_template_term(
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

fn cpp_callable_is_structural_constructor(function_declarator: Node<'_>, source: &str) -> bool {
    let Some(name_node) = function_declarator
        .child_by_field_name("declarator")
        .or_else(|| function_declarator.child_by_field_name("name"))
        .or_else(|| last_named_child(function_declarator))
    else {
        return false;
    };
    let Some(callable_name) = direct_identifier_name(name_node, source) else {
        return false;
    };

    let mut current = function_declarator.parent();
    while let Some(ancestor) = current {
        let owner_name = match ancestor.kind() {
            "class_specifier" | "struct_specifier" | "union_specifier" => {
                class_like_name(ancestor, source)
            }
            "ERROR" => malformed_class_error_owner_name(ancestor, source),
            _ => None,
        };
        if owner_name.is_some_and(|owner_name| owner_name == callable_name) {
            return true;
        }
        current = ancestor.parent();
    }
    false
}

/// Recover the owner name from the direct grammar shape retained when a later
/// member macro makes tree-sitter reduce an otherwise ordinary class body to an
/// `ERROR` node:
///
/// `ERROR(class, type_identifier, base_class_clause?, "{", members...)`
///
/// Direct-child checks keep this distinct from an unrelated nested class inside
/// a broader error region. The closing brace may be displaced past the error
/// node, so the opening body token is the available structural boundary.
fn malformed_class_error_owner_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "ERROR" {
        return None;
    }
    let keyword = node.child(0)?;
    if !matches!(keyword.kind(), "class" | "struct" | "union") {
        return None;
    }
    let name_node = node.child(1)?;
    let name = direct_identifier_name(name_node, source)?;
    let has_body = (2..node.child_count())
        .filter_map(|index| node.child(index))
        .any(|child| child.kind() == "{");
    has_body.then_some(name)
}

fn cpp_callable_return_type_identity(
    function_declarator: Node<'_>,
    source: &str,
) -> Option<StructuredTypeIdentity> {
    if cpp_callable_is_structural_constructor(function_declarator, source) {
        return None;
    }
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
    inner: StructuredTypeNodeId,
    wrapper: CppStructuredTypeWrapper,
) -> Option<StructuredTypeNodeId> {
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
    if cpp_callable_is_structural_constructor(function_declarator, source) {
        return None;
    }
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

pub fn normalize_cpp_whitespace(value: &str) -> String {
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

pub fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node_source_text(node, source)
}

pub fn collect_cpp_identifiers(node: Node<'_>, source: &str, identifiers: &mut HashSet<String>) {
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

/// Return a class body's actual closing brace when the parser supplied one.
///
/// A malformed namespace sentinel can leave a class node carrying unrelated
/// parser errors even though its own class body is complete.  `has_error()` is
/// therefore too coarse an admission predicate for sentinel ownership.  The
/// body list, however, exposes the opening and closing punctuation directly;
/// a real (non-missing) final `}` proves that the class did not borrow the
/// enclosing namespace's close.  Requiring the body to end before its parent
/// container also rejects a recovered node whose body swallowed that outer
/// boundary.
fn cpp_complete_class_body_close(node: Node<'_>) -> Option<Node<'_>> {
    if !matches!(
        node.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier"
    ) {
        return None;
    }
    let body = cpp_body_node(node)?;
    if !matches!(body.kind(), "declaration_list" | "field_declaration_list") {
        return None;
    }
    let open = body.child(0)?;
    let close = body.child(body.child_count().checked_sub(1)?)?;
    if open.kind() != "{"
        || open.is_missing()
        || close.kind() != "}"
        || close.is_missing()
        || close.end_byte() != body.end_byte()
        || body.end_byte() > node.end_byte()
        || node
            .parent()
            .is_some_and(|parent| body.end_byte() >= parent.end_byte())
    {
        return None;
    }
    Some(close)
}

fn cpp_contains_namespace_definition(node: Node<'_>) -> bool {
    if node.kind() == "namespace_definition" {
        return true;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(cpp_contains_namespace_definition)
}

struct CppNestedNamespaceSentinel<'tree> {
    function: Node<'tree>,
    body: Node<'tree>,
    namespace_components: Vec<String>,
}

/// Owned structural recovery metadata for a namespace-sentinel region.
///
/// Tree-sitter puts an `ABSL_NAMESPACE_BEGIN` region in a bogus function body
/// instead of the namespace/class scopes that the declaration visitor restores.
/// The inverted usage walk has the original CST, so it needs the same ownership
/// evidence without borrowing parser nodes across its file scan.  Keep this
/// descriptor deliberately source-range based: callers can match a reference
/// node by containment and then resolve its structured type spelling in the
/// recovered class scope.
#[derive(Debug, Clone)]
pub struct CppSentinelRecoveredOwner {
    pub range: Range,
    /// Start of the qualified owner name (`btree<P>::method`).  A leading
    /// return type before this byte is looked up from the namespace; parameters,
    /// trailing returns, and the body use the member owner scope.
    pub owner_name_start_byte: usize,
    /// Number of leading components belonging to the namespace rather than
    /// the qualified class owner.  A leading return type is looked up before
    /// every owner component, not merely before the innermost class.
    pub namespace_component_count: usize,
    pub scope_components: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CppSentinelRecoveredClass {
    pub namespace_range: Range,
    pub namespace_scope_components: Vec<String>,
    pub class_range: Range,
    /// Full namespace + class path, e.g. `absl,container_internal,btree`.
    pub scope_components: Vec<String>,
    /// Qualified out-of-line member definitions owned by this class.  Their
    /// ranges may extend beyond `class_range` when the malformed sentinel
    /// swallowed the namespace close and left definitions as function siblings.
    pub owner_ranges: Vec<CppSentinelRecoveredOwner>,
}

/// Resolve the lexical scope restored for a node in a malformed
/// namespace-sentinel region.  Owner spans (out-of-line member definitions)
/// outrank class spans, which in turn outrank the surviving namespace body.
/// The class ancestor suffix is recovered from the original CST so nested
/// members keep their complete `Outer::Inner` owner chain.
pub fn cpp_sentinel_recovered_scope_for_node(
    node: Node<'_>,
    source: &str,
    recovered_classes: &[CppSentinelRecoveredClass],
) -> Option<Vec<String>> {
    let contains =
        |range: Range| range.start_byte <= node.start_byte() && range.end_byte >= node.end_byte();
    let mut best_owner: Option<&CppSentinelRecoveredOwner> = None;
    for recovered in recovered_classes {
        for owner in recovered
            .owner_ranges
            .iter()
            .filter(|owner| contains(owner.range))
        {
            let replace = best_owner.is_none_or(|existing| {
                owner.range.end_byte.saturating_sub(owner.range.start_byte)
                    < existing
                        .range
                        .end_byte
                        .saturating_sub(existing.range.start_byte)
            });
            if replace {
                best_owner = Some(owner);
            }
        }
    }
    if let Some(owner) = best_owner {
        let mut scope = owner.scope_components.clone();
        if node.start_byte() < owner.owner_name_start_byte {
            scope.truncate(owner.namespace_component_count);
        }
        return Some(scope);
    }

    let class = recovered_classes
        .iter()
        .filter(|recovered| contains(recovered.class_range))
        .min_by_key(|recovered| {
            recovered
                .class_range
                .end_byte
                .saturating_sub(recovered.class_range.start_byte)
        });
    let class_scope = class.is_some();
    let mut scope = if let Some(class) = class {
        class.scope_components.clone()
    } else {
        let namespace = recovered_classes
            .iter()
            .filter(|recovered| contains(recovered.namespace_range))
            .min_by_key(|recovered| {
                recovered
                    .namespace_range
                    .end_byte
                    .saturating_sub(recovered.namespace_range.start_byte)
            })?;
        let mut scope = namespace.namespace_scope_components.clone();
        let parser_namespace = cpp_sentinel_recovered_namespace_components(node, &[], source);
        let common_prefix = scope
            .iter()
            .zip(&parser_namespace)
            .take_while(|(recovered, parser)| recovered == parser)
            .count();
        scope.extend(parser_namespace.into_iter().skip(common_prefix));
        scope
    };
    if class_scope {
        let mut ancestor_components = Vec::new();
        let mut ancestor = node.parent();
        while let Some(current) = ancestor {
            if matches!(
                current.kind(),
                "class_specifier" | "struct_specifier" | "union_specifier"
            ) && let Some(name) = current.child_by_field_name("name")
                && let Some(name_components) = cpp_name_components(name, source)
            {
                ancestor_components.push(
                    name_components
                        .into_iter()
                        .map(|component| component.name)
                        .collect::<Vec<_>>(),
                );
            }
            ancestor = current.parent();
        }
        ancestor_components.reverse();
        let base_len = scope.len();
        for component in ancestor_components.into_iter().flatten() {
            if scope.len() >= base_len && scope.last() == Some(&component) {
                continue;
            }
            scope.push(component);
        }
    }
    Some(scope)
}

struct CppSentinelFragmentedClassTail<'tree> {
    class_node: Node<'tree>,
    template_node: Option<Node<'tree>>,
    name: String,
    fragmented: FragmentedExportBody,
    consumed_start: usize,
}

struct CppSentinelDirectBodyClassRegion {
    namespace_components: Vec<String>,
    class_start: usize,
    class_start_line: usize,
    class_close_end: usize,
    class_close_line: usize,
    name: String,
}

fn cpp_sentinel_body_class_candidate<'tree>(
    child: Node<'tree>,
) -> Option<(Node<'tree>, Option<Node<'tree>>)> {
    if matches!(
        child.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier"
    ) {
        return Some((child, None));
    }
    if child.kind() != "template_declaration" {
        if child.kind() == "declaration" {
            return Some((first_class_like_child(child)?, None));
        }
        return None;
    }
    let mut cursor = child.walk();
    let class_node = child.named_children(&mut cursor).find_map(|candidate| {
        if matches!(
            candidate.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) {
            Some(candidate)
        } else if candidate.kind() == "declaration" {
            first_class_like_child(candidate)
        } else {
            None
        }
    })?;
    Some((class_node, Some(child)))
}

fn cpp_sentinel_direct_body_class_candidate<'tree>(
    child: Node<'tree>,
) -> Option<(Node<'tree>, Option<Node<'tree>>)> {
    if let Some(candidate) = cpp_sentinel_body_class_candidate(child) {
        return Some(candidate);
    }
    if child.kind() != "template_declaration" {
        return None;
    }
    let mut cursor = child.walk();
    let wrapper = child
        .named_children(&mut cursor)
        .find(|candidate| candidate.kind() == "function_definition" && candidate.has_error())?;
    Some((first_class_like_child(wrapper)?, Some(child)))
}

fn cpp_sentinel_direct_namespace_components(
    function: Node<'_>,
    body: Node<'_>,
    source: &str,
) -> Option<Vec<String>> {
    let mut cursor = function.walk();
    let children = function
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment" && child.end_byte() <= body.start_byte())
        .collect::<Vec<_>>();
    let sentinel_index = children.iter().rposition(|child| {
        direct_identifier_name(*child, source)
            .is_some_and(|name| cpp_export_macro_token(&name) && name.ends_with("NAMESPACE_BEGIN"))
    })?;
    let mut identifiers = Vec::new();
    let mut stack = children[sentinel_index + 1..]
        .iter()
        .rev()
        .copied()
        .collect::<Vec<_>>();
    while let Some(current) = stack.pop() {
        if let Some(name) = direct_identifier_name(current, source) {
            identifiers.push(name);
            continue;
        }
        let mut cursor = current.walk();
        let children = current.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    let [keyword, namespace] = identifiers.as_slice() else {
        return None;
    };
    (keyword == "namespace" && !namespace.is_empty() && !cpp_export_macro_token(namespace))
        .then(|| vec![namespace.clone()])
}

fn cpp_sentinel_namespace_close_follows_class(class_semicolon: Node<'_>, source: &str) -> bool {
    let mut sibling = class_semicolon.next_named_sibling();
    let namespace_close = loop {
        let Some(current) = sibling else {
            return false;
        };
        sibling = current.next_named_sibling();
        if current.kind() != "comment" {
            break current;
        }
    };
    if !cpp_is_stray_close_brace(namespace_close, source) {
        return false;
    }
    loop {
        let Some(current) = sibling else {
            return false;
        };
        sibling = current.next_named_sibling();
        if current.kind() == "comment" {
            continue;
        }
        return direct_identifier_name(current, source)
            .is_some_and(|name| name.ends_with("NAMESPACE_END"));
    }
}

fn cpp_sentinel_macro_body_class_region(
    node: Node<'_>,
    source: &str,
) -> Option<CppSentinelDirectBodyClassRegion> {
    let (_, None) = cpp_sentinel_macro_parts(node, source)? else {
        return None;
    };
    if node.kind() != "function_definition" || !node.has_error() {
        return None;
    }
    let body = cpp_body_node(node).filter(|body| body.kind() == "compound_statement")?;
    let namespace_components = cpp_sentinel_direct_namespace_components(node, body, source)?;
    let mut cursor = body.walk();
    let candidates = body
        .named_children(&mut cursor)
        .filter_map(cpp_sentinel_direct_body_class_candidate)
        .filter(|(class_node, _)| class_node.has_error() && cpp_body_node(*class_node).is_some())
        .collect::<Vec<_>>();
    let [(class_node, template_node)] = candidates.as_slice() else {
        return None;
    };
    let original_body = cpp_body_node(*class_node)?;
    let name = class_like_name(*class_node, source)?;
    if name.is_empty() || cpp_export_macro_token(&name) {
        return None;
    }

    let mut sibling = node.next_named_sibling();
    let (class_close_start, class_close_end, class_close_line) = loop {
        let current = sibling?;
        let next = current.next_named_sibling();
        if cpp_is_stray_close_brace(current, source)
            && next.is_some_and(|next| cpp_is_stray_semicolon(next, source))
        {
            let semicolon = next.expect("checked above");
            if !cpp_sentinel_namespace_close_follows_class(semicolon, source) {
                return None;
            }
            break (
                current.start_byte(),
                semicolon.end_byte(),
                semicolon.end_position().row + 1,
            );
        }
        sibling = next;
    };
    let reparse_start = template_node.map_or(class_node.start_byte(), |node| node.start_byte());
    let tree = cpp_reparse_region_items(source, reparse_start, class_close_end)?;
    let root = tree.root_node();
    let reparsed_template = cpp_sentinel_reparsed_leading_template(root);
    let reparsed = cpp_sentinel_reparsed_class(root, reparsed_template, source)?;
    if reparsed.name != name
        || reparsed.declaration_node.start_byte() != class_node.start_byte()
        || reparsed.body.start_byte() != original_body.start_byte()
        || class_close_start <= reparsed.body.end_byte()
        || class_close_end <= class_node.end_byte()
    {
        return None;
    }
    Some(CppSentinelDirectBodyClassRegion {
        namespace_components,
        class_start: reparse_start,
        class_start_line: template_node.map_or(class_node.start_position().row + 1, |node| {
            node.start_position().row + 1
        }),
        class_close_end,
        class_close_line,
        name,
    })
}

/// Recognize the one malformed namespace-sentinel shape emitted for Abseil's
/// `namespace absl { ABSL_NAMESPACE_BEGIN namespace log_internal { ... }`.
///
/// The parser puts the namespace opener and the malformed function in one root
/// `ERROR` node.  This branch intentionally stays tied to that CST geometry:
/// the root's direct tokens must end in `namespace`, an identifier, and `{`;
/// the malformed function must begin with an all-caps type, then an ERROR whose
/// sole identifier is `namespace`, followed by the inner namespace identifier
/// and a compound body; and that body must contain complete named class
/// specifiers.  A text reparse cannot prove any of those ownership boundaries.
fn cpp_nested_namespace_sentinel<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<CppNestedNamespaceSentinel<'tree>> {
    if !node.has_error() {
        return None;
    }

    let (function, mut namespace_components) = if node.kind() == "ERROR" {
        let mut cursor = node.walk();
        let functions = node
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "function_definition")
            .collect::<Vec<_>>();
        let [function] = functions.as_slice() else {
            return None;
        };
        if !function.has_error() {
            return None;
        }
        let mut cursor = node.walk();
        let children = node.children(&mut cursor).collect::<Vec<_>>();
        let function_index = children
            .iter()
            .position(|child| same_node(*child, *function))?;
        let [outer_keyword, outer_name, outer_open] =
            children.get(function_index.checked_sub(3)?..function_index)?
        else {
            return None;
        };
        if outer_keyword.kind() != "namespace"
            || !matches!(outer_name.kind(), "identifier" | "namespace_identifier")
            || outer_open.kind() != "{"
        {
            return None;
        }
        (
            *function,
            vec![canonical_cpp_qualified_component(*outer_name, source)?.name],
        )
    } else if node.kind() == "function_definition" {
        let declaration_list = node.parent()?;
        let namespace = declaration_list.parent()?;
        if declaration_list.kind() != "declaration_list"
            || namespace.kind() != "namespace_definition"
            || namespace.child_by_field_name("body") != Some(declaration_list)
        {
            return None;
        }
        (node, Vec::new())
    } else {
        return None;
    };

    let mut cursor = function.walk();
    let named = function
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
        .collect::<Vec<_>>();
    let [first_type, inner_error, inner_name, body] = named.as_slice() else {
        return None;
    };
    if first_type.kind() != "type_identifier" {
        return None;
    }
    let sentinel = normalize_cpp_whitespace(node_text(*first_type, source));
    if sentinel.is_empty() || !cpp_export_macro_token(&sentinel) {
        return None;
    }
    if inner_error.kind() != "ERROR" || inner_error.named_child_count() != 1 {
        return None;
    }
    let inner_keyword = inner_error.named_child(0)?;
    if direct_identifier_name(inner_keyword, source).as_deref() != Some("namespace") {
        return None;
    }
    if !matches!(inner_name.kind(), "identifier" | "namespace_identifier") {
        return None;
    }
    let inner_name = canonical_cpp_qualified_component(*inner_name, source)?.name;
    if inner_name.is_empty() || body.kind() != "compound_statement" {
        return None;
    }
    namespace_components.push(inner_name);

    let mut cursor = body.walk();
    let classes = body
        .named_children(&mut cursor)
        .filter_map(cpp_sentinel_body_class_candidate)
        .filter(|(child, _)| {
            cpp_body_node(*child).is_some()
                && class_like_name(*child, source)
                    .is_some_and(|name| !name.is_empty() && !cpp_export_macro_token(&name))
        })
        .collect::<Vec<_>>();
    if classes.is_empty() {
        return None;
    }

    Some(CppNestedNamespaceSentinel {
        function,
        body: *body,
        namespace_components,
    })
}

/// Recover one fragmented class tail that tree-sitter leaves as siblings of the
/// malformed namespace-sentinel function.  The recovery is deliberately
/// structural: the class must be a direct body item, its own class node must be
/// erroneous and end before a unique anonymous `}` in the enclosing
/// declaration-list, and that namespace's next sibling must be a standalone
/// `;`.  The complete interior must pass the existing member-shaped reparse
/// gate. This avoids source brace scans and does not borrow a close from an
/// unrelated later declaration.
fn cpp_sentinel_fragmented_class_tail<'tree>(
    function: Node<'tree>,
    body: Node<'tree>,
    source: &str,
) -> Option<CppSentinelFragmentedClassTail<'tree>> {
    let mut cursor = body.walk();
    let candidates = body
        .named_children(&mut cursor)
        .filter_map(cpp_sentinel_body_class_candidate)
        .filter(|(class_node, _)| cpp_body_node(*class_node).is_some() && class_node.has_error())
        .collect::<Vec<_>>();
    let [(class_node, template_node)] = candidates.as_slice() else {
        return None;
    };
    let name = class_like_name(*class_node, source)?;
    if name.is_empty() || cpp_export_macro_token(&name) {
        return None;
    }
    let class_body = cpp_body_node(*class_node)?;

    let (close, semicolon) =
        cpp_sentinel_fragment_boundary(function, *class_node, class_body, source)?;

    let reparse_start = class_body.start_byte().checked_add(1)?;
    let reparse_end = close.start_byte();
    if reparse_start >= reparse_end {
        return None;
    }
    let tree = cpp_reparse_region_items(source, reparse_start, reparse_end)?;
    if !cpp_reparsed_members_are_indexable(tree.root_node(), source) {
        return None;
    }
    let class_range = Range {
        start_byte: template_node.map_or(class_node.start_byte(), |node| node.start_byte()),
        end_byte: semicolon.end_byte(),
        start_line: template_node.map_or(class_node.start_position().row, |node| {
            node.start_position().row
        }) + 1,
        end_line: semicolon.end_position().row + 1,
    };
    Some(CppSentinelFragmentedClassTail {
        class_node: *class_node,
        template_node: *template_node,
        name,
        fragmented: FragmentedExportBody {
            reparse_start,
            reparse_end,
            class_range,
        },
        consumed_start: template_node.map_or(class_node.start_byte(), |node| node.start_byte()),
    })
}

/// Recover the class and out-of-line owner scopes from every malformed
/// namespace-sentinel region in `root`.
///
/// This is the shared structural counterpart to
/// [`CppDeclarationVisitor::visit_nested_namespace_sentinel`].  It intentionally
/// reuses the visitor's sentinel/class admission predicates instead of parsing
/// source text a second time.  The returned values own only ranges and names, so
/// they can be retained by an inverted usage scan after the tree borrow ends.
pub fn cpp_sentinel_recovered_classes(
    root: Node<'_>,
    source: &str,
) -> Vec<CppSentinelRecoveredClass> {
    if !root.has_error() {
        return Vec::new();
    }
    let mut recovered_classes: Vec<CppSentinelRecoveredClass> = Vec::new();
    let mut stack = vec![root];
    while let Some(current) = stack.pop() {
        if let Some(recovered) = cpp_nested_namespace_sentinel(current, source) {
            let namespace_components = cpp_sentinel_recovered_namespace_components(
                recovered.function,
                &recovered.namespace_components,
                source,
            );
            let fragmented =
                cpp_sentinel_fragmented_class_tail(recovered.function, recovered.body, source);
            let mut class_candidates = Vec::new();
            let mut cursor = recovered.body.walk();
            for (class_node, template_node) in recovered
                .body
                .named_children(&mut cursor)
                .filter_map(cpp_sentinel_body_class_candidate)
            {
                let Some(name) = class_like_name(class_node, source) else {
                    continue;
                };
                if name.is_empty() || cpp_export_macro_token(&name) {
                    continue;
                }
                let is_fragmented = fragmented
                    .as_ref()
                    .is_some_and(|tail| same_node(tail.class_node, class_node));
                if !is_fragmented && cpp_complete_class_body_close(class_node).is_none() {
                    continue;
                }
                let class_range = if is_fragmented {
                    fragmented
                        .as_ref()
                        .map(|tail| tail.fragmented.class_range)
                        .expect("fragmented class range is present when class matches")
                } else {
                    cpp_declaration_range(template_node.unwrap_or(class_node))
                };
                class_candidates.push((class_range, name));
            }

            let mut owner_ranges =
                cpp_sentinel_recovered_owner_ranges(recovered.body, &namespace_components, source);
            cpp_sentinel_extend_unique_owner_ranges(
                &mut owner_ranges,
                cpp_sentinel_recovered_sibling_owner_ranges(
                    recovered.function,
                    &namespace_components,
                    source,
                ),
            );
            for (class_range, name) in class_candidates {
                push_cpp_sentinel_recovered_class(
                    &mut recovered_classes,
                    cpp_declaration_range(recovered.body),
                    &namespace_components,
                    class_range,
                    name,
                    &owner_ranges,
                );
            }

            if let Some(declaration_list) = recovered
                .function
                .parent()
                .filter(|parent| parent.kind() == "declaration_list")
            {
                let outer_namespace =
                    cpp_sentinel_recovered_namespace_components(recovered.function, &[], source);
                push_cpp_sentinel_sibling_classes(
                    &mut recovered_classes,
                    declaration_list,
                    recovered.function,
                    &outer_namespace,
                    source,
                );
            }
        } else if let Some(region) = cpp_sentinel_macro_body_class_region(current, source) {
            let namespace_components = cpp_sentinel_recovered_namespace_components(
                current,
                &region.namespace_components,
                source,
            );
            let owner_container = current
                .parent()
                .filter(|parent| parent.kind() == "declaration_list")
                .unwrap_or(current);
            let owner_ranges =
                cpp_sentinel_recovered_owner_ranges(owner_container, &namespace_components, source);
            push_cpp_sentinel_recovered_class(
                &mut recovered_classes,
                cpp_declaration_range(owner_container),
                &namespace_components,
                Range {
                    start_byte: region.class_start,
                    end_byte: region.class_close_end,
                    start_line: region.class_start_line,
                    end_line: region.class_close_line,
                },
                region.name,
                &owner_ranges,
            );
        } else if let Some(region) = cpp_sentinel_macro_class_region(current, source) {
            // A generic sentinel-prefixed class can be reduced as a malformed
            // function/ERROR without the explicit `namespace X` token pair.
            // Reuse the declaration visitor's bounded reparse and retain only
            // the recovered class identity/range here.
            let (reparse_start, class_start, _body_start, _close_start, close_end, _close_line) =
                region;
            let Some(tree) = cpp_reparse_region_items(source, reparse_start, close_end) else {
                continue;
            };
            let root = tree.root_node();
            let template_node = cpp_sentinel_reparsed_leading_template(root);
            let Some(reparsed_class) = cpp_sentinel_reparsed_class(root, template_node, source)
            else {
                continue;
            };
            let class_node = reparsed_class.declaration_node;
            let name = reparsed_class.name;
            let namespace_components =
                cpp_sentinel_recovered_namespace_components(current, &[], source);
            let owner_container = current
                .parent()
                .filter(|parent| parent.kind() == "declaration_list")
                .unwrap_or(current);
            let mut owner_ranges =
                cpp_sentinel_recovered_owner_ranges(owner_container, &namespace_components, source);
            cpp_sentinel_extend_unique_owner_ranges(
                &mut owner_ranges,
                cpp_sentinel_recovered_sibling_owner_ranges(current, &namespace_components, source),
            );
            push_cpp_sentinel_recovered_class(
                &mut recovered_classes,
                cpp_declaration_range(owner_container),
                &namespace_components,
                Range {
                    start_byte: class_start,
                    end_byte: close_end,
                    start_line: class_node.start_position().row + 1,
                    end_line: class_node.end_position().row + 1,
                },
                name,
                &owner_ranges,
            );
            if owner_container.kind() == "declaration_list" {
                push_cpp_sentinel_sibling_classes(
                    &mut recovered_classes,
                    owner_container,
                    current,
                    &namespace_components,
                    source,
                );
            }
        }

        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    // A shallower sentinel can expose nested classes as apparent namespace
    // siblings even after a deeper sentinel proves that a containing class
    // owns their ranges. Drop those shadow descriptors; scope recovery starts
    // from the proven containing class and appends parser-visible class
    // ancestors, preserving the full `Outer::Inner` chain.
    let shadowed = recovered_classes
        .iter()
        .map(|candidate| {
            recovered_classes.iter().any(|container| {
                container.class_range.start_byte <= candidate.class_range.start_byte
                    && container.class_range.end_byte >= candidate.class_range.end_byte
                    && container.class_range != candidate.class_range
                    && container.namespace_scope_components.len()
                        > candidate.namespace_scope_components.len()
                    && container
                        .namespace_scope_components
                        .starts_with(&candidate.namespace_scope_components)
            })
        })
        .collect::<Vec<_>>();
    let mut index = 0usize;
    recovered_classes.retain(|_| {
        let keep = !shadowed[index];
        index += 1;
        keep
    });
    recovered_classes
}

/// A flat sentinel can swallow the first class while leaving later classes and
/// their out-of-line definitions as ordinary declaration-list siblings.  Once
/// the malformed class proves the sentinel envelope, retain those structurally
/// complete sibling classes under the same surviving namespace so every member
/// owner in the region uses one recovery contract.
fn push_cpp_sentinel_sibling_classes(
    recovered_classes: &mut Vec<CppSentinelRecoveredClass>,
    declaration_list: Node<'_>,
    sentinel_node: Node<'_>,
    namespace_components: &[String],
    source: &str,
) {
    let owner_ranges =
        cpp_sentinel_recovered_owner_ranges(declaration_list, namespace_components, source);
    let namespace_range = cpp_declaration_range(declaration_list);
    let mut cursor = declaration_list.walk();
    for (class_node, template_node) in declaration_list
        .named_children(&mut cursor)
        .filter(|child| !same_node(*child, sentinel_node))
        .filter_map(cpp_sentinel_body_class_candidate)
    {
        let Some(name) = class_like_name(class_node, source) else {
            continue;
        };
        if name.is_empty()
            || cpp_export_macro_token(&name)
            || cpp_complete_class_body_close(class_node).is_none()
        {
            continue;
        }
        push_cpp_sentinel_recovered_class(
            recovered_classes,
            namespace_range,
            namespace_components,
            cpp_declaration_range(template_node.unwrap_or(class_node)),
            name,
            &owner_ranges,
        );
    }
}

fn push_cpp_sentinel_recovered_class(
    recovered_classes: &mut Vec<CppSentinelRecoveredClass>,
    namespace_range: Range,
    namespace_components: &[String],
    class_range: Range,
    name: String,
    owner_ranges: &[CppSentinelRecoveredOwner],
) {
    let mut scope_components = namespace_components.to_vec();
    scope_components.push(name);
    let owner_ranges = owner_ranges
        .iter()
        .filter(|owner| owner.scope_components.starts_with(&scope_components))
        .cloned()
        .collect::<Vec<_>>();
    if recovered_classes.iter().any(|existing| {
        existing.class_range == class_range && existing.scope_components == scope_components
    }) {
        return;
    }
    recovered_classes.push(CppSentinelRecoveredClass {
        namespace_range,
        namespace_scope_components: namespace_components.to_vec(),
        class_range,
        scope_components,
        owner_ranges,
    });
}

fn cpp_sentinel_recovered_namespace_components(
    function: Node<'_>,
    recovered_components: &[String],
    source: &str,
) -> Vec<String> {
    let mut ancestor_components = Vec::new();
    let mut ancestor = function.parent();
    while let Some(current) = ancestor {
        if current.kind() == "namespace_definition"
            && let Some(name_node) = current.child_by_field_name("name")
            && let Some(components) = cpp_name_components(name_node, source)
        {
            ancestor_components.push(
                components
                    .into_iter()
                    .map(|component| component.name)
                    .collect::<Vec<_>>(),
            );
        }
        ancestor = current.parent();
    }
    ancestor_components.reverse();
    let mut ancestors = ancestor_components
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    let overlap = (0..=ancestors.len().min(recovered_components.len()))
        .rev()
        .find(|length| {
            ancestors[ancestors.len().saturating_sub(*length)..] == recovered_components[..*length]
        })
        .unwrap_or(0);
    ancestors.extend(recovered_components.iter().skip(overlap).cloned());
    ancestors
}

fn cpp_sentinel_recovered_owner_ranges(
    body: Node<'_>,
    namespace_components: &[String],
    source: &str,
) -> Vec<CppSentinelRecoveredOwner> {
    let mut owners = Vec::new();
    walk_named_tree_preorder(body, true, |node| {
        cpp_sentinel_collect_owner_range(node, namespace_components, source, &mut owners)
    });
    owners
}

fn cpp_sentinel_collect_owner_range(
    node: Node<'_>,
    namespace_components: &[String],
    source: &str,
    owners: &mut Vec<CppSentinelRecoveredOwner>,
) -> WalkControl {
    if node.kind() != "function_definition" {
        return WalkControl::Continue;
    }
    let Some(function_declarator) = extract_function_declarator(node) else {
        return WalkControl::Continue;
    };
    let Some(name_node) = cpp_function_declarator_name_node(function_declarator) else {
        return WalkControl::Continue;
    };
    let Some(mut components) = cpp_name_components(name_node, source) else {
        return WalkControl::Continue;
    };
    if components.len() <= 1 {
        return WalkControl::Continue;
    }
    components.pop();
    let mut owner_components = components
        .into_iter()
        .map(|component| component.name)
        .collect::<Vec<_>>();
    let overlap = (0..=namespace_components.len().min(owner_components.len()))
        .rev()
        .find(|length| {
            owner_components[..*length]
                == namespace_components[namespace_components.len().saturating_sub(*length)..]
        })
        .unwrap_or(0);
    let mut scope_components = namespace_components.to_vec();
    scope_components.extend(owner_components.drain(overlap..));
    if scope_components.len() <= namespace_components.len() {
        return WalkControl::Continue;
    }
    let range = cpp_declaration_range(node);
    if !owners.iter().any(|existing: &CppSentinelRecoveredOwner| {
        existing.range == range && existing.scope_components == scope_components
    }) {
        owners.push(CppSentinelRecoveredOwner {
            range,
            owner_name_start_byte: name_node.start_byte(),
            namespace_component_count: namespace_components.len(),
            scope_components,
        });
    }
    WalkControl::Continue
}

fn cpp_sentinel_extend_unique_owner_ranges(
    owners: &mut Vec<CppSentinelRecoveredOwner>,
    additional: Vec<CppSentinelRecoveredOwner>,
) {
    for owner in additional {
        if !owners.iter().any(|existing| {
            existing.range == owner.range && existing.scope_components == owner.scope_components
        }) {
            owners.push(owner);
        }
    }
}

fn cpp_sentinel_namespace_end(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "ERROR" || node.named_child_count() != 1 {
        return false;
    }
    let Some(end_name) = node.named_child(0) else {
        return false;
    };
    if direct_identifier_name(end_name, source).as_deref() != Some("ABSL_NAMESPACE_END") {
        return false;
    }
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| child.kind() == "}" && !child.is_named() && !child.is_missing())
}

/// Collect owner definitions that the malformed sentinel left as later
/// declaration-list siblings. Parser-visible namespace siblings are a hard
/// boundary: their declarations must keep their own lexical namespace.
fn cpp_sentinel_recovered_owner_ranges_after_declaration_siblings(
    parent: Node<'_>,
    sentinel_node: Node<'_>,
    namespace_components: &[String],
    source: &str,
) -> Vec<CppSentinelRecoveredOwner> {
    let mut owners = Vec::new();
    let mut after_sentinel = false;
    let mut cursor = parent.walk();
    for child in parent.named_children(&mut cursor) {
        if !after_sentinel {
            if same_node(child, sentinel_node) {
                after_sentinel = true;
            }
            continue;
        }
        walk_named_tree_preorder(child, true, |node| {
            if node.kind() == "namespace_definition" {
                return WalkControl::SkipChildren;
            }
            cpp_sentinel_collect_owner_range(node, namespace_components, source, &mut owners)
        });
    }
    owners
}

/// Collect owner definitions after a malformed namespace, stopping only at
/// its structural `ABSL_NAMESPACE_END` error marker. Without that marker the
/// enclosing container is not trusted to belong to the recovered namespace.
fn cpp_sentinel_recovered_owner_ranges_after_namespace_siblings(
    parent: Node<'_>,
    sentinel_node: Node<'_>,
    namespace_components: &[String],
    source: &str,
) -> Option<Vec<CppSentinelRecoveredOwner>> {
    let mut owners = Vec::new();
    let mut after_namespace = false;
    let mut cursor = parent.walk();
    for child in parent.named_children(&mut cursor) {
        if !after_namespace {
            if same_node(child, sentinel_node) {
                after_namespace = true;
            }
            continue;
        }
        if cpp_sentinel_namespace_end(child, source) {
            return Some(owners);
        }
        walk_named_tree_preorder(child, true, |node| {
            if node.kind() == "namespace_definition" {
                return WalkControl::SkipChildren;
            }
            cpp_sentinel_collect_owner_range(node, namespace_components, source, &mut owners)
        });
    }
    None
}

fn cpp_sentinel_recovered_sibling_owner_ranges(
    sentinel_node: Node<'_>,
    namespace_components: &[String],
    source: &str,
) -> Vec<CppSentinelRecoveredOwner> {
    let Some(declaration_list) = sentinel_node
        .parent()
        .filter(|parent| parent.kind() == "declaration_list")
    else {
        return Vec::new();
    };
    let mut owners = cpp_sentinel_recovered_owner_ranges_after_declaration_siblings(
        declaration_list,
        sentinel_node,
        namespace_components,
        source,
    );

    let Some(namespace) = declaration_list
        .parent()
        .filter(|parent| parent.kind() == "namespace_definition")
    else {
        return owners;
    };
    let Some(outer_parent) = namespace.parent() else {
        return owners;
    };
    if let Some(additional) = cpp_sentinel_recovered_owner_ranges_after_namespace_siblings(
        outer_parent,
        namespace,
        namespace_components,
        source,
    ) {
        cpp_sentinel_extend_unique_owner_ranges(&mut owners, additional);
    }
    owners
}

fn cpp_function_declarator_name_node(function_declarator: Node<'_>) -> Option<Node<'_>> {
    let mut current = function_declarator.child_by_field_name("declarator")?;
    loop {
        if matches!(
            current.kind(),
            "qualified_identifier"
                | "scoped_identifier"
                | "scoped_type_identifier"
                | "identifier"
                | "field_identifier"
                | "operator_name"
                | "destructor_name"
                | "literal_operator_name"
        ) {
            return Some(current);
        }
        current = current
            .child_by_field_name("declarator")
            .or_else(|| current.child_by_field_name("name"))
            .or_else(|| last_named_child(current))?;
    }
}

fn cpp_name_components(node: Node<'_>, source: &str) -> Option<Vec<CppQualifiedNameComponent>> {
    match node.kind() {
        "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier" => {
            let mut components = match node.child_by_field_name("scope") {
                Some(scope) => cpp_name_components(scope, source)?,
                None => Vec::new(),
            };
            let name = node.child_by_field_name("name")?;
            components.push(canonical_cpp_qualified_component(name, source)?);
            Some(components)
        }
        _ => Some(vec![canonical_cpp_qualified_component(node, source)?]),
    }
}

fn cpp_sentinel_fragment_boundary<'tree>(
    function: Node<'tree>,
    class_node: Node<'tree>,
    class_body: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, Node<'tree>)> {
    let declaration_list = function.parent()?;
    if function.kind() != "function_definition" || declaration_list.kind() != "declaration_list" {
        return None;
    }
    let namespace = declaration_list.parent()?;
    if namespace.kind() != "namespace_definition"
        || namespace.child_by_field_name("body") != Some(declaration_list)
    {
        return None;
    }
    let mut cursor = declaration_list.walk();
    let closes = declaration_list
        .children(&mut cursor)
        .filter(|child| {
            !child.is_named()
                && child.kind() == "}"
                && child.start_byte() >= function.end_byte()
                && child.start_byte() > class_node.end_byte()
                && child.start_byte() > class_body.start_byte()
        })
        .collect::<Vec<_>>();
    let [close] = closes.as_slice() else {
        return None;
    };
    let semicolon = namespace.next_named_sibling()?;
    if !cpp_is_stray_semicolon(semicolon, source)
        || close.end_byte() != namespace.end_byte()
        || semicolon.start_byte() < namespace.end_byte()
    {
        return None;
    }
    Some((*close, semicolon))
}

/// Detect the bogus declaration/function tree that tree-sitter recovers for a
/// region prefixed by an object-like macro sentinel the parser cannot see
/// (issue #941), and return the byte range `[start, end)` of the swallowed
/// declaration interior to reparse.
///
/// The measured shape (`BEGIN_NS\nnamespace X { struct A { void m(); }; }`) is a
/// `function_definition` whose first non-comment named child is the sentinel
/// mis-read as the return `type` (a bare all-caps `type_identifier`), followed
/// by the mis-lexed item keyword, an `ERROR`, and a `compound_statement` holding
/// the real items.
/// `start` is the end of the sentinel identifier -- everything after it is the
/// genuine source. `end` is the node's end, extended across any trailing empty
/// `;` statement the mis-parse displaced past the node (the class/struct closing
/// semicolon), so the reparse sees a complete, brace-balanced item.
///
/// False-positive guards: the candidate must itself carry an `ERROR`/`MISSING`
/// node (`has_error`). Unknown annotation/export macros can make a real callable
/// error-recovered even though tree-sitter still preserves its declarator, so a
/// preserved callable is admitted only when a displaced class keyword precedes
/// that declarator. The clean-reparse-to-items gate in
/// `cpp_reparsed_items_are_indexable` is the final arbiter.
/// Return the reparse start and, when present, the structurally recovered class
/// keyword for a malformed sentinel-prefixed node.  The class keyword is kept
/// separately from the reparse start because an opaque template-declaration
/// macro may precede it.
fn cpp_sentinel_macro_parts(node: Node<'_>, source: &str) -> Option<(usize, Option<usize>)> {
    if !matches!(node.kind(), "function_definition" | "declaration" | "ERROR") || !node.has_error()
    {
        return None;
    }
    // OpenJDK's generated `EXPORT void f(struct Value value) { ... }` functions
    // retain a valid function declarator despite the unknown export macro making
    // the outer node erroneous. Remember that declarator for the ordering gate
    // below: a `struct` parameter lies inside it, while a sentinel-swallowed
    // class keyword precedes a spurious callable assembled from a later member.
    let mut declarator_cursor = node.walk();
    let preserved_callable = node
        .children_by_field_name("declarator", &mut declarator_cursor)
        .find_map(extract_function_declarator);
    // Leading documentation comments are attached to the malformed
    // `function_definition` as named children.  They are not part of the
    // sentinel prefix, so select the first non-comment child structurally
    // rather than requiring the sentinel to be child zero.  This is the shape
    // emitted for nlohmann/json's `basic_json`: its class documentation comment
    // precedes `NLOHMANN_BASIC_JSON_TPL_DECLARATION`, and the malformed node's
    // envelope otherwise ends at the first nested union.
    let mut cursor = node.walk();
    let first = node
        .named_children(&mut cursor)
        .find(|child| child.kind() != "comment")?;
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
    let mut after_first = false;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !after_first {
            if same_node(child, first) {
                after_first = true;
            }
            continue;
        }
        if matches!(child.kind(), "identifier" | "type_identifier")
            && cpp_export_macro_token(&normalize_cpp_whitespace(node_text(child, source)))
        {
            start = child.end_byte();
        } else {
            break;
        }
    }
    // An additional opaque template-declaration macro before a class can be
    // folded into the bogus function's qualified declarator.  In that shape
    // the macro is not a direct sibling we can skip above; tree-sitter exposes
    // the displaced `class`/`struct` keyword as an identifier inside an ERROR.
    // Reparse from that keyword (or a real preceding `template` keyword) so the
    // ordinary class visitor owns the body.  Only inspect the declarator prefix:
    // a class nested in a genuine sentinel-wrapped namespace lies after the
    // body opening and must not change the established region start.
    let prefix_end = cpp_body_node(node).map_or(node.end_byte(), |body| body.start_byte());
    let mut class_start = None;
    let mut template_start = None;
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.start_byte() >= prefix_end {
            continue;
        }
        if matches!(
            current.kind(),
            "identifier" | "type_identifier" | "class" | "struct" | "union" | "enum" | "template"
        ) {
            match normalize_cpp_whitespace(node_text(current, source)).as_str() {
                "class" | "struct" | "union" | "enum" => {
                    class_start = Some(class_start.map_or(current.start_byte(), |seen: usize| {
                        seen.min(current.start_byte())
                    }));
                }
                "template" => {
                    template_start =
                        Some(template_start.map_or(current.start_byte(), |seen: usize| {
                            seen.min(current.start_byte())
                        }));
                }
                _ => {}
            }
        }
        let mut cursor = current.walk();
        stack.extend(current.children(&mut cursor));
    }
    if preserved_callable.is_some_and(|callable| {
        class_start.is_none_or(|class_start| class_start >= callable.start_byte())
    }) {
        return None;
    }
    if let Some(class_start) = class_start {
        start = template_start
            .filter(|template_start| *template_start < class_start)
            .unwrap_or(class_start);
    }
    Some((start, class_start))
}

/// Locate a sentinel-prefixed class whose malformed declaration was split across
/// root-level siblings. The true class close is represented structurally as a
/// lone `}` error followed by the class's displaced `;`; nested method/body
/// errors are not direct siblings of the sentinel node and therefore cannot
/// satisfy this pair.
fn cpp_sentinel_macro_class_region(
    node: Node<'_>,
    source: &str,
) -> Option<(usize, usize, usize, usize, usize, usize)> {
    let (reparse_start, Some(class_start)) = cpp_sentinel_macro_parts(node, source)? else {
        return None;
    };
    let body_open_start = cpp_sentinel_macro_class_body_open(node, class_start)
        .or_else(|| cpp_body_node(node).map(|body| body.start_byte()))
        .or_else(|| cpp_sentinel_macro_displaced_class_body(node).map(|body| body.start_byte()))?;
    if class_start >= body_open_start {
        return None;
    }
    let sibling_close = {
        let mut sibling = node.next_named_sibling();
        let mut found = None;
        while let Some(current) = sibling {
            let next = current.next_named_sibling();
            if cpp_is_stray_close_brace(current, source)
                && next.is_some_and(|next| cpp_is_stray_semicolon(next, source))
            {
                let semicolon = next.expect("checked above");
                found = Some((
                    current.start_byte(),
                    semicolon.end_byte(),
                    semicolon.end_position().row + 1,
                ));
                break;
            }
            sibling = next;
        }
        found
    };
    let (class_close_start, class_close_end, class_close_line) =
        if let Some((class_close_start, class_close_end, class_close_line)) = sibling_close {
            (class_close_start, class_close_end, class_close_line)
        } else {
            // When the malformed envelope itself is an ERROR, tree-sitter can
            // leave the class's balanced close in the source while promoting
            // all following members to siblings. Reparse the complete suffix
            // and use the first body-bearing class node's own field range as
            // the partition boundary. This keeps balancing in tree-sitter and
            // preserves the source's original byte offsets.
            let tree = cpp_reparse_region_items(source, reparse_start, source.len())?;
            let template_node = cpp_sentinel_reparsed_leading_template(tree.root_node());
            let reparsed_class =
                cpp_sentinel_reparsed_class(tree.root_node(), template_node, source)?;
            let body = reparsed_class.body;
            let class_close_end = body.end_byte();
            let class_close_start = class_close_end.checked_sub(1)?;
            let class_close_line = body.end_position().row + 1;
            (class_close_start, class_close_end, class_close_line)
        };
    if class_close_start <= class_start {
        return None;
    }

    // Reparse only far enough to expose the class body opening. This is a
    // structured check that the candidate really begins with a body-bearing
    // class-like item; the original malformed tree cannot provide that node.
    let tree = cpp_reparse_region_items(source, reparse_start, class_close_end)?;
    let class_root = tree.root_node();
    let template_node = cpp_sentinel_reparsed_leading_template(class_root);
    let reparsed_class = cpp_sentinel_reparsed_class(class_root, template_node, source)?;
    let body = reparsed_class.body;
    // The class body opening must agree with the malformed wrapper's structured
    // body field. This rejects an inner nested class while permitting later
    // members to remain fragmented as root-level siblings in the bounded parse.
    if body.start_byte() != body_open_start {
        return None;
    }
    let body_start = body.start_byte().checked_add(1)?;
    (body_start < class_close_start).then_some((
        reparse_start,
        class_start,
        body_start,
        class_close_start,
        class_close_end,
        class_close_line,
    ))
}

/// Find the `{` token immediately following the class/struct/union/enum token
/// at `class_start` in the malformed tree. The token is anonymous in the C++
/// grammar, so this deliberately walks all children (not only named children)
/// and relies on sibling structure rather than source-text searching.
fn cpp_sentinel_macro_class_body_open(node: Node<'_>, class_start: usize) -> Option<usize> {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.start_byte() == class_start
            && matches!(current.kind(), "class" | "struct" | "union" | "enum")
        {
            let mut sibling = current.next_sibling();
            while let Some(candidate) = sibling {
                if candidate.kind() == "{" {
                    return Some(candidate.start_byte());
                }
                sibling = candidate.next_sibling();
            }
        }
        let mut cursor = current.walk();
        stack.extend(current.children(&mut cursor));
    }
    None
}

/// The class body that tree-sitter displaced out of a sentinel-prefixed
/// declaration and left as the malformed node's next sibling.
///
/// When the sentinel envelope reduces to a bare `ERROR` -- `ABSL_NAMESPACE_BEGIN
/// template <typename T> class ABSL_ATTRIBUTE_VIEW Span` -- the class token is
/// the last child of that `ERROR` and its `{` opens a sibling
/// `compound_statement` instead. The body is still the malformed tree's own
/// structured token, which is what the caller's `body.start_byte() !=
/// body_open_start` agreement check needs; it just is not reachable by walking
/// forward from the class token inside the node.
fn cpp_sentinel_macro_displaced_class_body(node: Node<'_>) -> Option<Node<'_>> {
    node.next_named_sibling()
        .filter(|sibling| sibling.kind() == "compound_statement")
}

fn cpp_sentinel_macro_region(node: Node<'_>, source: &str) -> Option<(usize, usize)> {
    let (start, class_start) = cpp_sentinel_macro_parts(node, source)?;
    let mut end = if class_start.is_some() {
        cpp_macro_prefixed_class_end(source, start)?
    } else {
        node.end_byte()
    };
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

/// Parse the source suffix beginning at a structurally recovered class/template
/// keyword and return the end of its first body-bearing class item.  The parser,
/// rather than a brace scanner, owns nested-body balancing.  This is needed when
/// the original error tree truncates the class and scatters later members as
/// top-level siblings.
fn cpp_macro_prefixed_class_end(source: &str, start: usize) -> Option<usize> {
    let tree = cpp_reparse_region_items(source, start, source.len())?;
    let root = tree.root_node();
    let mut cursor = root.walk();
    for item in root.named_children(&mut cursor) {
        if item.end_byte() <= start || item.kind() == "comment" {
            continue;
        }
        let mut stack = vec![item];
        while let Some(current) = stack.pop() {
            if matches!(
                current.kind(),
                "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
            ) && cpp_body_node(current).is_some()
            {
                return Some(current.end_byte());
            }
            let mut cursor = current.walk();
            stack.extend(current.named_children(&mut cursor));
        }
        // The recovered prefix is required to begin with the class item.  If
        // the first real item is something else, fail closed rather than skip
        // arbitrary source looking for a later class.
        return None;
    }
    None
}

/// An empty `;` statement: the displaced closing semicolon of a struct/class that
/// the sentinel mis-parse split off past the bogus function node.
fn cpp_is_stray_semicolon(node: Node<'_>, source: &str) -> bool {
    node.kind() == "expression_statement"
        && node.named_child_count() == 0
        && node_text(node, source).trim() == ";"
}

/// Recover the real field name when a leading object-like annotation macro
/// displaces a qualified type into tree-sitter's bit-field recovery shape.
///
/// `static API constexpr std::size_t npos = ...;` is parsed as `API` in the
/// type field, `std` as the field declarator, and `::size_t npos = ...` as a
/// `bitfield_clause` containing an error plus an assignment.  The assignment's
/// left field is the only structured declaration name in that malformed tail.
/// A real bit-field is excluded by the all-caps macro type and required error.
fn recovered_macro_qualified_field_declarators<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<Vec<Node<'tree>>> {
    if node.kind() != "field_declaration" {
        return None;
    }
    let macro_type = node.child_by_field_name("type")?;
    if macro_type.kind() != "type_identifier"
        || !cpp_export_macro_token(&normalize_cpp_whitespace(node_text(macro_type, source)))
    {
        return None;
    }
    let pseudo_declarator = node.child_by_field_name("declarator")?;
    if pseudo_declarator.kind() != "field_identifier" {
        return None;
    }
    let mut cursor = node.walk();
    let clause = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "bitfield_clause")?;
    if !(0..clause.named_child_count()).any(|index| {
        clause
            .named_child(index)
            .is_some_and(|child| child.kind() == "ERROR")
    }) {
        return None;
    }
    let mut recovered = Vec::new();
    let mut stack = vec![clause];
    while let Some(current) = stack.pop() {
        if current.kind() == "assignment_expression"
            && let Some(left) = current.child_by_field_name("left")
            && extract_variable_name(left, source).is_some()
        {
            recovered.push(left);
            break;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    if recovered.is_empty() {
        return None;
    }
    let mut cursor = node.walk();
    recovered.extend(
        node.children_by_field_name("declarator", &mut cursor)
            .filter(|declarator| !same_node(*declarator, pseudo_declarator)),
    );
    Some(recovered)
}

/// Recover a macro-qualified member function declaration that tree-sitter
/// represents as a pseudo-field. An object-like export macro before a qualified
/// return type can displace the namespace and type into an ERROR/bitfield
/// recovery, leaving the callable as a structured `call_expression`.
///
/// The caller must route this shape before ordinary declarator classification;
/// otherwise the displaced namespace identifier is published as a field.
fn recovered_macro_qualified_function_call<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    if node.kind() != "field_declaration" {
        return None;
    }
    let macro_type = node.child_by_field_name("type")?;
    if macro_type.kind() != "type_identifier"
        || !cpp_export_macro_token(&normalize_cpp_whitespace(node_text(macro_type, source)))
    {
        return None;
    }
    let declarator = node.child_by_field_name("declarator")?;
    if declarator.kind() != "field_identifier" {
        return None;
    }
    let mut cursor = node.walk();
    let named = node.named_children(&mut cursor).collect::<Vec<_>>();
    if !named.iter().any(|child| {
        child.kind() == "storage_class_specifier"
            && normalize_cpp_whitespace(node_text(*child, source)) == "static"
    }) {
        return None;
    }
    let bitfield = named
        .iter()
        .find(|child| child.kind() == "bitfield_clause")?;
    let mut bitfield_cursor = bitfield.walk();
    let payload = bitfield
        .named_children(&mut bitfield_cursor)
        .collect::<Vec<_>>();
    let [displaced_error, call] = payload.as_slice() else {
        return None;
    };
    if displaced_error.kind() != "ERROR"
        || displaced_error.named_child_count() != 1
        || displaced_error
            .named_child(0)
            .is_none_or(|child| child.kind() != "identifier")
        || call.kind() != "call_expression"
        || call
            .child_by_field_name("function")
            .is_none_or(|function| !matches!(function.kind(), "identifier" | "field_identifier"))
        || call
            .child_by_field_name("arguments")
            .is_none_or(|arguments| arguments.kind() != "argument_list")
    {
        return None;
    }
    Some(*call)
}

fn recovered_macro_qualified_function_parameters(
    arguments: Node<'_>,
    source: &str,
) -> Option<(String, Vec<String>)> {
    if arguments.kind() != "argument_list" {
        return None;
    }
    let mut cursor = arguments.walk();
    let named = arguments.named_children(&mut cursor).collect::<Vec<_>>();
    if named.is_empty() {
        return Some(("()".to_string(), Vec::new()));
    }
    let mut types = Vec::new();
    let mut labels = Vec::new();
    let mut index = 0;
    while index < named.len() {
        let parameter_type = named[index];
        let parameter_name = named.get(index + 1).copied()?;
        if !matches!(
            parameter_type.kind(),
            "identifier" | "type_identifier" | "qualified_identifier" | "template_type"
        ) || parameter_name.kind() != "ERROR"
            || parameter_name.named_child_count() != 1
            || parameter_name
                .named_child(0)
                .is_none_or(|child| !matches!(child.kind(), "identifier" | "field_identifier"))
        {
            return None;
        }
        let parameter_name = parameter_name.named_child(0)?;
        types.push(normalize_cpp_whitespace(node_text(parameter_type, source)));
        labels.push(normalize_cpp_whitespace(node_text(parameter_name, source)));
        index += 2;
    }
    Some((format!("({})", types.join(", ")), labels))
}

/// Recognize the phantom field tree-sitter emits for a macro-qualified
/// function return type.  For example,
/// `static API result_type ThresholdForSmallA() { ... }` can become a
/// `field_declaration` (`API` as the type and `result_type` as a field name)
/// followed by a clean `function_definition` for `ThresholdForSmallA`.
///
/// Keep this predicate entirely tied to the CST envelope: the type must be an
/// all-caps macro token, the pseudo-declarator must be a bare field identifier,
/// the declaration must carry a missing semicolon rather than a real one, and
/// the immediate named sibling must expose a function declarator.  A real
/// macro-decorated field with an explicit semicolon therefore remains a field.
pub fn recovered_macro_return_type_node<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    if node.kind() != "field_declaration" {
        return None;
    }
    let macro_type = node.child_by_field_name("type")?;
    if macro_type.kind() != "type_identifier"
        || !cpp_export_macro_token(&normalize_cpp_whitespace(node_text(macro_type, source)))
    {
        return None;
    }
    let declarator = node.child_by_field_name("declarator")?;
    if declarator.kind() != "field_identifier" || node_text(declarator, source).trim().is_empty() {
        return None;
    }
    let mut has_missing_semicolon = false;
    let mut has_real_semicolon = false;
    for index in 0..node.child_count() {
        let Some(child) = node.child(index) else {
            continue;
        };
        if child.kind() != ";" {
            continue;
        }
        if child.is_missing() {
            has_missing_semicolon = true;
        } else {
            has_real_semicolon = true;
        }
    }
    if !has_missing_semicolon || has_real_semicolon {
        return None;
    }
    let mut next = node.next_named_sibling();
    while next.is_some_and(|sibling| sibling.kind() == "comment") {
        next = next.and_then(|sibling| sibling.next_named_sibling());
    }
    let next = next?;
    if next.kind() != "function_definition" || next.child_by_field_name("type").is_some() {
        return None;
    }
    let function_declarator = next.child_by_field_name("declarator")?;
    extract_function_declarator(function_declarator).map(|_| declarator)
}

/// Whether `name` is a type parameter of a template declaration that lexically
/// encloses `node`. The malformed macro-return field uses the parameter name as
/// its pseudo-declarator; preserving that field is necessary to publish a
/// definition for dependent calls such as `OperandLayout::packed`. Walk the AST
/// ancestors instead of interpreting source text so nested templates and
/// parser-recovered regions retain their real lexical scopes.
fn cpp_active_template_type_parameter(node: Node<'_>, name: &str, source: &str) -> bool {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if current.kind() == "template_declaration"
            && let Some(parameters) = current.child_by_field_name("parameters")
        {
            let mut cursor = parameters.walk();
            if parameters.named_children(&mut cursor).any(|parameter| {
                cpp_template_parameter_kind(parameter) == CppTemplateParameterKind::Type
                    && cpp_template_parameter_name(parameter, source)
                        .is_some_and(|parameter_name| parameter_name == name)
            }) {
                return true;
            }
        }
        ancestor = current.parent();
    }
    false
}

/// Reparse the region `[start, end)` of `source` as C++, confined to the region
/// via included ranges so every reparsed node keeps its original byte offset and
/// line number. The existing visitors read node text from the original source,
/// so ranges and ownership stay byte/line-exact. Mirrors the Rust #1015
/// `parse_rust_region_tree` technique.
fn cpp_reparse_region_items(source: &str, start: usize, end: usize) -> Option<Tree> {
    parse_source_region(&tree_sitter_cpp::LANGUAGE.into(), source, start, end)
}

/// Reparse a fragmented class-body interior while preserving its original byte
/// and line offsets. Unlike an included-range translation-unit parse, a padded
/// prefix keeps C++ preprocessor directives after an access label in the same
/// recovery shape tree-sitter produces for a complete class body.
fn cpp_reparse_fragmented_class_body(source: &str, start: usize, end: usize) -> Option<Tree> {
    let bytes = source.as_bytes();
    let prefix = bytes.get(..start)?;
    let interior = bytes.get(start..end)?;
    let mut padded = Vec::with_capacity(end);
    padded.extend(
        prefix
            .iter()
            .map(|&byte| if byte == b'\n' { b'\n' } else { b' ' }),
    );
    padded.extend_from_slice(interior);
    let padded = String::from_utf8(padded).ok()?;
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .ok()?;
    parser.parse(&padded, None)
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
fn cpp_reparsed_member_error_is_indexable(node: Node<'_>) -> bool {
    if node.kind() != "ERROR" {
        return false;
    }
    let mut stack = Vec::new();
    let mut saw_function_declarator = false;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        stack.push(child);
    }
    while let Some(current) = stack.pop() {
        match current.kind() {
            // Tree-sitter may wrap adjacent copy-control declarations in a
            // nested ERROR. Keep descending only through ERROR wrappers; the
            // actual declaration payload must be a function_declarator.
            "ERROR" => {
                let mut cursor = current.walk();
                stack.extend(current.named_children(&mut cursor));
            }
            "function_declarator" => saw_function_declarator = true,
            _ => return false,
        }
    }
    saw_function_declarator
}

fn cpp_reparsed_adjacent_copy_control_error(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "ERROR" {
        return false;
    }
    let mut cursor = node.walk();
    let named = node.named_children(&mut cursor).collect::<Vec<_>>();
    let [explicit, constructor_error, destructor] = named.as_slice() else {
        return false;
    };
    let Some(constructor) = constructor_error.named_child(0) else {
        return false;
    };
    let Some(constructor_name) =
        extract_function_declarator(constructor).and_then(cpp_function_declarator_name_node)
    else {
        return false;
    };
    let Some(destructor_name) =
        extract_function_declarator(*destructor).and_then(cpp_function_declarator_name_node)
    else {
        return false;
    };
    let Some(destroyed_type) = destructor_name.named_child(0) else {
        return false;
    };
    explicit.kind() == "explicit_function_specifier"
        && constructor_error.kind() == "ERROR"
        && constructor_error.named_child_count() == 1
        && constructor.kind() == "function_declarator"
        && constructor_name.kind() == "identifier"
        && destructor.kind() == "function_declarator"
        && destructor_name.kind() == "destructor_name"
        && destroyed_type.kind() == "identifier"
        && node_text(constructor_name, source) == node_text(destroyed_type, source)
}

fn cpp_reparsed_constructor_body_is_indexable(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "compound_statement" {
        return false;
    }
    let Some(prefix) = cpp_prev_non_comment_named_sibling(node) else {
        return false;
    };
    if prefix.kind() == "labeled_statement"
        && prefix.named_child(0).is_some_and(|label| {
            matches!(
                node_text(label, source).trim(),
                "public" | "private" | "protected"
            )
        })
    {
        return prefix.named_children(&mut prefix.walk()).any(|child| {
            child.kind() == "declaration"
                && child.has_error()
                && child
                    .named_children(&mut child.walk())
                    .any(cpp_reparsed_member_error_is_indexable)
        });
    }
    // A malformed constructor initializer can be split into a declaration
    // followed by its compound body when the class prefix already contains
    // realistic members. Keep this admission tied to that exact structured
    // declaration/error/body chain rather than accepting arbitrary blocks.
    prefix.kind() == "declaration"
        && prefix.has_error()
        && prefix
            .named_children(&mut prefix.walk())
            .any(|child| child.kind() == "ERROR" && cpp_reparsed_member_error_is_indexable(child))
}

fn cpp_reparsed_member_error_with_preprocessed_body(node: Node<'_>) -> bool {
    if !cpp_reparsed_member_error_is_indexable(node) {
        return false;
    }
    let Some(preproc) = node.next_named_sibling() else {
        return false;
    };
    preproc.kind() == "preproc_if"
        && preproc.has_error()
        && preproc
            .named_children(&mut preproc.walk())
            .any(|child| child.kind() == "expression_statement" && child.has_error())
        && preproc
            .next_named_sibling()
            .is_some_and(|body| body.kind() == "compound_statement")
}

/// Return a function body whose braces and ownership are explicit in the
/// reparsed class-member tree. An error below a real function envelope is
/// recoverable by the ordinary function visitor; a missing/deferred body is
/// not, because accepting it would let statement soup masquerade as a member.
fn cpp_reparsed_member_function_body(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "function_definition" {
        return None;
    }
    let body = node.child_by_field_name("body")?;
    if body.kind() != "compound_statement" {
        return None;
    }
    let open = body.child(0)?;
    let close = body.child(body.child_count().checked_sub(1)?)?;
    if open.kind() != "{"
        || open.is_missing()
        || close.kind() != "}"
        || close.is_missing()
        || close.end_byte() != body.end_byte()
        || body.end_byte() != node.end_byte()
    {
        return None;
    }
    Some(body)
}

fn cpp_reparsed_member_function_errors_are_in_body(
    node: Node<'_>,
    body: Node<'_>,
    source: &str,
) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).all(|child| {
        same_node(child, body)
            || cpp_reparsed_member_attribute_error(child, source)
            || cpp_reparsed_member_signature_identifier_errors(child)
            || (!child.has_error() && !child.is_error() && !child.is_missing())
    })
}

/// A complete callable can still carry parser errors in its signature when a
/// project annotation is not part of the C++ grammar (`nonneg int`,
/// `RET_NONNULL`, or a constraint macro argument). Such annotations surface as
/// empty ERROR nodes or ERROR nodes containing identifiers. Admit only those
/// leaves inside the already-proven callable envelope; structured statements,
/// literals, missing tokens, and other malformed signature payload remain
/// rejected.
fn cpp_reparsed_member_signature_identifier_errors(node: Node<'_>) -> bool {
    if !node.has_error() && !node.is_error() && !node.is_missing() {
        return false;
    }
    let mut stack = vec![node];
    let mut saw_error = false;
    while let Some(current) = stack.pop() {
        if current.is_missing() {
            return false;
        }
        if current.kind() == "ERROR" {
            saw_error = true;
            let mut cursor = current.walk();
            let children = current.named_children(&mut cursor).collect::<Vec<_>>();
            if children
                .iter()
                .any(|child| !matches!(child.kind(), "ERROR" | "identifier"))
            {
                return false;
            }
            stack.extend(children);
            continue;
        }
        let mut cursor = current.walk();
        stack.extend(current.children(&mut cursor));
    }
    saw_error
}

fn cpp_reparsed_member_attribute_error(node: Node<'_>, source: &str) -> bool {
    node.kind() == "ERROR"
        && node.named_child_count() == 1
        && node.named_child(0).is_some_and(|attribute| {
            attribute.kind() == "identifier"
                && cpp_export_macro_token(&normalize_cpp_whitespace(node_text(attribute, source)))
        })
}

/// A C++ attribute placed between a member's declarator and body can make
/// tree-sitter expose the callable as
/// `type ERROR(init_declarator(name, argument_list)) ATTRIBUTE { ... }`.
/// Keep this admission tied to that exact node geometry. In particular, an
/// arbitrary ERROR or identifier before a compound statement is not enough.
fn cpp_reparsed_attribute_member_function(node: Node<'_>, source: &str) -> bool {
    let Some(body) = cpp_reparsed_member_function_body(node) else {
        return false;
    };
    let mut cursor = node.walk();
    let named = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
        .collect::<Vec<_>>();
    let [type_node, error, attribute, body_node] = named.as_slice() else {
        return false;
    };
    if !same_node(*body_node, body)
        || !cpp_reparsed_member_return_type_is_indexable(*type_node, source)
        || attribute.kind() != "identifier"
        || !cpp_export_macro_token(&normalize_cpp_whitespace(node_text(*attribute, source)))
        || error.kind() != "ERROR"
        || error.named_child_count() != 1
    {
        return false;
    }
    error
        .named_child(0)
        .is_some_and(cpp_reparsed_attribute_callable_declarator)
}

fn cpp_reparsed_member_return_type_is_indexable(node: Node<'_>, source: &str) -> bool {
    cpp_structured_type_path(node, source).is_some()
        && !cpp_export_macro_token(&normalize_cpp_whitespace(node_text(node, source)))
}

fn cpp_reparsed_friend_function_is_indexable(node: Node<'_>, source: &str) -> bool {
    let Some(body) = cpp_reparsed_member_function_body(node) else {
        return false;
    };
    let mut cursor = node.walk();
    let named = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
        .collect::<Vec<_>>();
    let [friend, return_error, declarator, body_node] = named.as_slice() else {
        return false;
    };
    let Some(return_type) = return_error.named_child(0) else {
        return false;
    };
    same_node(*body_node, body)
        && friend.kind() == "type_identifier"
        && node_text(*friend, source) == "friend"
        && return_error.kind() == "ERROR"
        && return_error.named_child_count() == 1
        && cpp_reparsed_member_return_type_is_indexable(return_type, source)
        && extract_function_declarator(*declarator)
            .and_then(cpp_function_declarator_name_node)
            .is_some()
}

fn cpp_reparsed_prefix_attribute_function_is_indexable(node: Node<'_>, source: &str) -> bool {
    let Some(body) = cpp_reparsed_member_function_body(node) else {
        return false;
    };
    let mut cursor = node.walk();
    let named = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
        .collect::<Vec<_>>();
    let [prefix @ .., attribute, return_error, declarator, body_node] = named.as_slice() else {
        return false;
    };
    let Some(return_type) = return_error.named_child(0) else {
        return false;
    };
    same_node(*body_node, body)
        && prefix
            .iter()
            .all(|node| matches!(node.kind(), "storage_class_specifier" | "type_qualifier"))
        && attribute.kind() == "type_identifier"
        && cpp_export_macro_token(&normalize_cpp_whitespace(node_text(*attribute, source)))
        && return_error.kind() == "ERROR"
        && return_error.named_child_count() == 1
        && cpp_reparsed_member_return_type_is_indexable(return_type, source)
        && extract_function_declarator(*declarator)
            .and_then(cpp_function_declarator_name_node)
            .is_some()
}

/// An included-range reparse that begins inside a malformed class can merge an
/// access label and following template member. Tree-sitter then emits the label
/// as the `template_type` name, the template parameter list as its arguments,
/// an ERROR-wrapped return type, the callable declarator, and its complete
/// body. Admit only that exact structured displacement.
fn cpp_reparsed_access_template_function_is_indexable(node: Node<'_>, source: &str) -> bool {
    let Some(body) = cpp_reparsed_member_function_body(node) else {
        return false;
    };
    let mut cursor = node.walk();
    let named = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
        .collect::<Vec<_>>();
    let [template_type, return_error, declarator, body_node] = named.as_slice() else {
        return false;
    };
    let Some(template_name) = template_type.child_by_field_name("name") else {
        return false;
    };
    let Some(arguments) = template_type.child_by_field_name("arguments") else {
        return false;
    };
    let Some(return_type) = return_error.named_child(0) else {
        return false;
    };
    let mut cursor = template_type.walk();
    let template_errors = template_type
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "ERROR")
        .collect::<Vec<_>>();
    let [comment_error] = template_errors.as_slice() else {
        return false;
    };
    let mut cursor = comment_error.walk();
    let error_children = comment_error.children(&mut cursor).collect::<Vec<_>>();
    let [colon, comments @ .., template_keyword] = error_children.as_slice() else {
        return false;
    };
    same_node(*body_node, body)
        && template_type.kind() == "template_type"
        && template_name.kind() == "type_identifier"
        && matches!(
            node_text(template_name, source).trim(),
            "public" | "private" | "protected"
        )
        && arguments.kind() == "template_argument_list"
        && arguments.named_child_count() > 0
        && !arguments.has_error()
        && !colon.is_named()
        && colon.kind() == ":"
        && comments.iter().all(|child| child.kind() == "comment")
        && !template_keyword.is_named()
        && template_keyword.kind() == "template"
        && return_error.kind() == "ERROR"
        && return_error.named_child_count() == 1
        && cpp_reparsed_member_return_type_is_indexable(return_type, source)
        && extract_function_declarator(*declarator)
            .and_then(cpp_function_declarator_name_node)
            .is_some()
}

/// Return the constructor declaration tree-sitter can merge into an access
/// label when a class-body reparse begins immediately before `#if`, `#ifdef`,
/// or `#ifndef`. The conditional token and macro name become an ERROR plus the
/// declaration's apparent type; the callable name must still exactly match the
/// recovered class, so unrelated labeled statements are never re-owned.
fn cpp_reparsed_preprocessor_constructor<'tree>(
    node: Node<'tree>,
    class_name: &str,
    source: &str,
) -> Option<Node<'tree>> {
    if node.kind() != "labeled_statement" {
        return None;
    }
    let mut cursor = node.walk();
    let named = node.named_children(&mut cursor).collect::<Vec<_>>();
    let [label, directive_error, declaration] = named.as_slice() else {
        return None;
    };
    if label.kind() != "statement_identifier"
        || !matches!(
            node_text(*label, source),
            "public" | "private" | "protected"
        )
        || directive_error.kind() != "ERROR"
        || directive_error.child_count() != 1
        || directive_error
            .child(0)
            .is_none_or(|directive| !matches!(directive.kind(), "#if" | "#ifdef" | "#ifndef"))
        || declaration.kind() != "declaration"
        || declaration.named_child_count() != 2
    {
        return None;
    }
    let apparent_type = declaration.child_by_field_name("type")?;
    if apparent_type.kind() != "type_identifier"
        || !cpp_export_macro_token(&normalize_cpp_whitespace(node_text(apparent_type, source)))
    {
        return None;
    }
    let declarator = declaration.child_by_field_name("declarator")?;
    let function = extract_function_declarator(declarator)?;
    let name = cpp_function_declarator_name_node(function)?;
    (node_text(name, source) == class_name).then_some(*declaration)
}

fn cpp_reparsed_attribute_callable_declarator(node: Node<'_>) -> bool {
    if extract_function_declarator(node)
        .and_then(cpp_function_declarator_name_node)
        .is_some()
    {
        return true;
    }
    node.kind() == "init_declarator"
        && node
            .child_by_field_name("declarator")
            .is_some_and(|declarator| declarator.kind() == "identifier")
        && node
            .child_by_field_name("value")
            .is_some_and(|value| value.kind() == "argument_list" && value.named_child_count() == 0)
}

/// Return true for the constrained/attribute form that tree-sitter splits into
/// an ERROR declaration, a preprocessor `requires` clause, and a following
/// compound statement. The three nodes must remain immediate named siblings;
/// this deliberately does not search source text or skip unrelated statements.
fn cpp_reparsed_attribute_requires_error(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "ERROR" || node.named_child_count() != 3 {
        return false;
    }
    let mut cursor = node.walk();
    let named = node.named_children(&mut cursor).collect::<Vec<_>>();
    let [type_node, function_declarator, attribute] = named.as_slice() else {
        return false;
    };
    if !cpp_reparsed_member_return_type_is_indexable(*type_node, source)
        || !cpp_reparsed_attribute_callable_declarator(*function_declarator)
        || attribute.kind() != "identifier"
        || !cpp_export_macro_token(&normalize_cpp_whitespace(node_text(*attribute, source)))
    {
        return false;
    }
    let Some(preproc) =
        cpp_next_non_comment_named_sibling(node).filter(|sibling| sibling.kind() == "preproc_if")
    else {
        return false;
    };
    let Some(body) = cpp_next_non_comment_named_sibling(preproc)
        .filter(|sibling| sibling.kind() == "compound_statement")
    else {
        return false;
    };
    let Some(open) = body.child(0) else {
        return false;
    };
    let Some(close) = body.child(body.child_count().saturating_sub(1)) else {
        return false;
    };
    let Some(condition) = preproc.child_by_field_name("condition") else {
        return false;
    };
    let mut cursor = preproc.walk();
    let payload = preproc
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment" && !same_node(*child, condition))
        .collect::<Vec<_>>();
    let [requires_statement] = payload.as_slice() else {
        return false;
    };
    let requires_clause = requires_statement.named_child(0);

    open.kind() == "{"
        && !open.is_missing()
        && close.kind() == "}"
        && !close.is_missing()
        && close.end_byte() == body.end_byte()
        && requires_statement.kind() == "expression_statement"
        && requires_statement.named_child_count() == 1
        && requires_clause.is_some_and(|clause| clause.kind() == "requires_clause")
}

fn cpp_next_non_comment_named_sibling(node: Node<'_>) -> Option<Node<'_>> {
    let mut sibling = node.next_named_sibling();
    while sibling.is_some_and(|candidate| candidate.kind() == "comment") {
        sibling = sibling.and_then(|candidate| candidate.next_named_sibling());
    }
    sibling
}

fn cpp_prev_non_comment_named_sibling(node: Node<'_>) -> Option<Node<'_>> {
    let mut sibling = node.prev_named_sibling();
    while sibling.is_some_and(|candidate| candidate.kind() == "comment") {
        sibling = sibling.and_then(|candidate| candidate.prev_named_sibling());
    }
    sibling
}

fn cpp_reparsed_attribute_requires_body(node: Node<'_>, source: &str) -> bool {
    let Some(preproc) =
        cpp_prev_non_comment_named_sibling(node).filter(|sibling| sibling.kind() == "preproc_if")
    else {
        return false;
    };
    let Some(error) =
        cpp_prev_non_comment_named_sibling(preproc).filter(|sibling| sibling.kind() == "ERROR")
    else {
        return false;
    };
    cpp_reparsed_attribute_requires_error(error, source)
}

fn cpp_reparsed_template_macro_prefix_parameter<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    if node.kind() != "ERROR" {
        return None;
    }
    let mut cursor = node.walk();
    let named = node.named_children(&mut cursor).collect::<Vec<_>>();
    let [parameter, macro_name, message] = named.as_slice() else {
        return None;
    };
    let parameter_name = parameter.named_child(0)?;
    (parameter.kind() == "type_parameter_declaration"
        && parameter_name.kind() == "type_identifier"
        && macro_name.kind() == "type_identifier"
        && cpp_export_macro_token(&normalize_cpp_whitespace(node_text(*macro_name, source)))
        && message.kind() == "string_literal")
        .then_some(parameter_name)
}

fn cpp_reparsed_template_macro_companion_is_indexable(
    node: Node<'_>,
    parameter_name: Node<'_>,
    source: &str,
) -> bool {
    let Some(body) = cpp_reparsed_member_function_body(node) else {
        return false;
    };
    let mut cursor = node.walk();
    let named = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
        .collect::<Vec<_>>();
    let [
        constraint,
        close_error,
        storage,
        return_error,
        declarator,
        body_node,
    ] = named.as_slice()
    else {
        return false;
    };
    let Some(constraint_scope) = constraint.child_by_field_name("scope") else {
        return false;
    };
    let Some(constraint_template) = constraint.child_by_field_name("name") else {
        return false;
    };
    let Some(constraint_arguments) = constraint_template.child_by_field_name("arguments") else {
        return false;
    };
    let Some(return_type) = return_error.named_child(0) else {
        return false;
    };
    let mut cursor = constraint_arguments.walk();
    let constraint_types = constraint_arguments
        .named_children(&mut cursor)
        .collect::<Vec<_>>();
    same_node(*body_node, body)
        && constraint.kind() == "qualified_identifier"
        && constraint_scope.kind() == "namespace_identifier"
        && constraint_template.kind() == "template_type"
        && matches!(constraint_types.as_slice(), [left, right]
            if left.kind() == "type_descriptor" && right.kind() == "type_descriptor")
        && !constraint_arguments.has_error()
        && close_error.kind() == "ERROR"
        && close_error.named_child_count() == 0
        && storage.kind() == "storage_class_specifier"
        && return_error.kind() == "ERROR"
        && return_error.named_child_count() == 1
        && return_type.kind() == "identifier"
        && node_text(return_type, source) == node_text(parameter_name, source)
        && extract_function_declarator(*declarator)
            .and_then(cpp_function_declarator_name_node)
            .is_some()
}

fn cpp_reparsed_template_macro_constructor_declarator<'tree>(
    node: Node<'tree>,
    parameter_name: Node<'_>,
    source: &str,
) -> Option<Node<'tree>> {
    let body = cpp_reparsed_member_function_body(node)?;
    let constraint = node.child_by_field_name("type")?;
    let constraint_template = constraint.child_by_field_name("name")?;
    let constraint_arguments = constraint_template.child_by_field_name("arguments")?;
    let mut argument_cursor = constraint_arguments.walk();
    let constraint_types = constraint_arguments
        .named_children(&mut argument_cursor)
        .collect::<Vec<_>>();
    if constraint.kind() != "qualified_identifier"
        || constraint_template.kind() != "template_type"
        || !matches!(constraint_types.as_slice(), [left, right]
            if left.kind() == "type_descriptor" && right.kind() == "type_descriptor")
        || constraint_arguments.has_error()
        || node
            .child_by_field_name("body")
            .is_none_or(|candidate| !same_node(candidate, body))
    {
        return None;
    }

    let mut cursor = node.walk();
    let recovery_errors = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "ERROR")
        .collect::<Vec<_>>();
    if !recovery_errors
        .iter()
        .any(|error| cpp_reparsed_constraint_macro_error(*error, source))
        || !recovery_errors.iter().all(|error| {
            error.named_child_count() == 0
                || cpp_reparsed_constraint_macro_error(*error, source)
                || (error.named_child_count() == 1
                    && error
                        .named_child(0)
                        .is_some_and(|child| child.kind() == "function_declarator"))
        })
    {
        return None;
    }

    let parameter_text = node_text(parameter_name, source);
    let mut declarators = node
        .child_by_field_name("declarator")
        .and_then(extract_function_declarator)
        .into_iter()
        .collect::<Vec<_>>();
    for error in recovery_errors {
        let mut stack = vec![error];
        while let Some(current) = stack.pop() {
            if current.kind() == "function_declarator" {
                declarators.push(current);
            }
            let mut cursor = current.walk();
            stack.extend(current.named_children(&mut cursor));
        }
    }
    declarators.into_iter().find(|declarator| {
        cpp_function_declarator_name_node(*declarator)
            .is_some_and(|name| name.kind() == "identifier")
            && declarator
                .child_by_field_name("parameters")
                .is_some_and(|parameters| {
                    parameters
                        .named_children(&mut parameters.walk())
                        .filter_map(|parameter| parameter.child_by_field_name("type"))
                        .any(|parameter_type| node_text(parameter_type, source) == parameter_text)
                })
    })
}

fn cpp_reparsed_template_macro_constructor_companion_is_indexable(
    node: Node<'_>,
    parameter_name: Node<'_>,
    source: &str,
) -> bool {
    cpp_reparsed_template_macro_constructor_declarator(node, parameter_name, source).is_some()
}

fn cpp_reparsed_constraint_macro_error(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "ERROR" {
        return false;
    }
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        let macro_shape = match current.kind() {
            "call_expression" => current
                .child_by_field_name("function")
                .zip(current.child_by_field_name("arguments")),
            "init_declarator" => current
                .child_by_field_name("declarator")
                .zip(current.child_by_field_name("value")),
            _ => None,
        };
        if let Some((name, arguments)) = macro_shape
            && name.kind() == "identifier"
            && arguments.kind() == "argument_list"
            && arguments.named_child_count() >= 2
            && cpp_export_macro_token(&normalize_cpp_whitespace(node_text(name, source)))
        {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn cpp_recovered_template_macro_constructor<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, Node<'tree>)> {
    let mut prefix = node.prev_named_sibling()?;
    while prefix.kind() == "comment" {
        prefix = prefix.prev_named_sibling()?;
    }
    let parameter_name = cpp_reparsed_template_macro_prefix_parameter(prefix, source)?;
    let parameter = parameter_name
        .parent()
        .filter(|parent| parent.kind() == "type_parameter_declaration")?;
    let declarator =
        cpp_reparsed_template_macro_constructor_declarator(node, parameter_name, source)?;
    Some((declarator, parameter))
}

fn cpp_reparsed_template_macro_prefix_is_indexable(node: Node<'_>, source: &str) -> bool {
    let Some(parameter_name) = cpp_reparsed_template_macro_prefix_parameter(node, source) else {
        return false;
    };
    cpp_next_non_comment_named_sibling(node).is_some_and(|function| {
        cpp_reparsed_template_macro_companion_is_indexable(function, parameter_name, source)
            || cpp_reparsed_template_macro_constructor_companion_is_indexable(
                function,
                parameter_name,
                source,
            )
    })
}

fn cpp_reparsed_member_function_is_indexable(node: Node<'_>, source: &str) -> bool {
    let function_name = node
        .child_by_field_name("declarator")
        .and_then(extract_function_declarator)
        .and_then(cpp_function_declarator_name_node);
    if let Some(body) = cpp_reparsed_member_function_body(node)
        && function_name.is_some()
        && cpp_reparsed_member_function_errors_are_in_body(node, body, source)
    {
        return true;
    }
    cpp_reparsed_attribute_member_function(node, source)
        || cpp_reparsed_friend_function_is_indexable(node, source)
        || cpp_reparsed_prefix_attribute_function_is_indexable(node, source)
        || cpp_reparsed_access_template_function_is_indexable(node, source)
        || cpp_recovered_template_macro_constructor(node, source).is_some()
}

fn cpp_reparsed_members_are_indexable(root: Node<'_>, source: &str) -> bool {
    let mut cursor = root.walk();
    let children = root.named_children(&mut cursor).collect::<Vec<_>>();
    let mut saw_member = false;
    let mut index = 0;
    while index < children.len() {
        let child = children[index];
        if let Some((_, fragmented)) = fragmented_plain_class_body(child, source) {
            let Some(tree) = cpp_reparse_fragmented_class_body(
                source,
                fragmented.reparse_start,
                fragmented.reparse_end,
            ) else {
                return false;
            };
            if !cpp_reparsed_members_are_indexable(tree.root_node(), source) {
                return false;
            }
            saw_member = true;
            index += 1;
            while index < children.len()
                && children[index].end_byte() <= fragmented.class_range.end_byte
            {
                index += 1;
            }
            continue;
        }
        match child.kind() {
            "comment" => {}
            "labeled_statement" => saw_member = true,
            "function_definition" => {
                if child.has_error()
                    && !cpp_reparsed_member_function_is_indexable(child, source)
                    && cpp_sentinel_macro_region(child, source).is_none()
                {
                    return false;
                }
                saw_member = true;
            }
            "ERROR"
                if (cpp_reparsed_member_error_is_indexable(child)
                    || cpp_reparsed_adjacent_copy_control_error(child, source))
                    && (child
                        .next_named_sibling()
                        .is_some_and(|sibling| cpp_is_stray_semicolon(sibling, source))
                        || cpp_reparsed_member_error_with_preprocessed_body(child)) =>
            {
                saw_member = true;
            }
            "ERROR" if cpp_reparsed_attribute_requires_error(child, source) => {
                saw_member = true;
            }
            "ERROR" if cpp_reparsed_template_macro_prefix_is_indexable(child, source) => {
                saw_member = true;
            }
            "expression_statement"
                if cpp_is_stray_semicolon(child, source)
                    && child.prev_named_sibling().is_some_and(|error| {
                        cpp_reparsed_member_error_is_indexable(error)
                            || cpp_reparsed_adjacent_copy_control_error(error, source)
                    }) =>
            {
                saw_member = true;
            }
            "compound_statement"
                if cpp_reparsed_constructor_body_is_indexable(child, source)
                    || cpp_reparsed_attribute_requires_body(child, source) =>
            {
                saw_member = true;
            }
            kind if cpp_is_indexable_item_kind(kind) => saw_member = true,
            _ => return false,
        }
        index += 1;
    }
    saw_member
}

/// Detect the malformed constructor shape that tree-sitter exposes as an
/// access-label statement followed by initializer-looking declarations. The
/// declarations are not class members: visiting their `location(loc)` and
/// `string(s)` function declarators would publish synthetic functions. The
/// export-class fallback keeps the original sibling nodes and therefore avoids
/// this parser artifact. The returned range identifies the real constructor
/// header, which can be reparsed independently as a structured declarator.
fn cpp_reparsed_synthetic_initializer_constructor_range(
    root: Node<'_>,
    class_name: &str,
    source: &str,
    constructor_end: usize,
) -> Option<std::ops::Range<usize>> {
    let mut stack = {
        let mut cursor = root.walk();
        root.named_children(&mut cursor).collect::<Vec<_>>()
    };
    while let Some(current) = stack.pop() {
        if let Some(range) = cpp_reparsed_synthetic_initializer_constructor(
            current,
            class_name,
            source,
            constructor_end,
        ) {
            return Some(range);
        }
        if current.kind() == "ERROR" {
            let mut cursor = current.walk();
            stack.extend(current.named_children(&mut cursor));
        }
    }
    None
}

fn cpp_reparsed_synthetic_initializer_constructor(
    node: Node<'_>,
    class_name: &str,
    source: &str,
    constructor_end: usize,
) -> Option<std::ops::Range<usize>> {
    if node.kind() != "labeled_statement" {
        return None;
    }
    let mut cursor = node.walk();
    let named = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
        .collect::<Vec<_>>();
    let label = named.first()?;
    if label.kind() != "statement_identifier"
        || !matches!(
            node_text(*label, source).trim(),
            "public" | "private" | "protected"
        )
    {
        return None;
    }
    let call_error_index = named.iter().position(|child| {
        if child.kind() != "ERROR" {
            return false;
        }
        let mut stack = vec![*child];
        while let Some(current) = stack.pop() {
            if current.kind() == "call_expression"
                && current
                    .child_by_field_name("function")
                    .is_some_and(|function| {
                        function.kind() == "identifier"
                            && node_text(function, source).trim() == class_name
                    })
            {
                return true;
            }
            let mut cursor = current.walk();
            stack.extend(current.named_children(&mut cursor));
        }
        false
    })?;
    let constructor_call = {
        let mut stack = vec![named[call_error_index]];
        let mut found = None;
        while let Some(current) = stack.pop() {
            if current.kind() == "call_expression"
                && current
                    .child_by_field_name("function")
                    .is_some_and(|function| {
                        function.kind() == "identifier"
                            && node_text(function, source).trim() == class_name
                    })
            {
                found = Some(current);
                break;
            }
            let mut cursor = current.walk();
            stack.extend(current.named_children(&mut cursor));
        }
        found
    };
    let constructor_call = constructor_call?;
    named.iter().skip(call_error_index + 1).find(|child| {
        child.kind() == "declaration" && child.has_error() && {
            let mut cursor = child.walk();
            child.named_children(&mut cursor).any(|declarator| {
                declarator.kind() == "init_declarator"
                    && declarator
                        .child_by_field_name("declarator")
                        .is_some_and(|declarator| declarator.kind() == "function_declarator")
                    && declarator
                        .child_by_field_name("value")
                        .is_some_and(|value| value.kind() == "initializer_list")
            })
        }
    })?;
    Some(constructor_call.start_byte()..constructor_end)
}

fn cpp_reparsed_exact_constructor_declarator<'tree>(
    root: Node<'tree>,
    start: usize,
    class_name: &str,
    source: &str,
) -> Option<Node<'tree>> {
    let mut candidate = None;
    let mut stack = vec![root];
    while let Some(current) = stack.pop() {
        if current.kind() == "function_declarator"
            && current.start_byte() == start
            && cpp_function_declarator_name_node(current)
                .is_some_and(|name| node_text(name, source).trim() == class_name)
        {
            if candidate.is_some() {
                return None;
            }
            candidate = Some(current);
            continue;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    candidate
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
            | "static_assert_declaration"
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
    use crate::adapter::parse_cpp_file;
    use brokk_bifrost_core::analyzer::parsed_file::{
        finish_declaration_identity_comparison_probe, start_declaration_identity_comparison_probe,
    };
    use std::fmt::Write;

    fn parse_cpp_declarations(source: &str, name: &str) -> ParsedFile {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let file = ProjectFile::new(std::env::temp_dir(), name);
        parse_cpp_file(&file, source, &tree)
    }

    #[test]
    fn macro_decorated_template_class_keeps_member_scope_without_forward_declaration() {
        let source = r#"namespace control {
template <typename T>
class AnySpan;
template <typename T>
class ABSL_ATTRIBUTE_VIEW AnySpan {
 public:
  int begin() const;
};
}

namespace absl {
ABSL_NAMESPACE_BEGIN
template <typename T>
class ABSL_ATTRIBUTE_VIEW Span {
 public:
  int begin() const;
  int back() const;
};

int begin();
int back();
}
"#;
        let parsed = parse_cpp_declarations(source, "cpp-sentinel-span.cpp");
        let declarations = parsed.declarations();
        assert!(
            declarations
                .iter()
                .any(|unit| unit.is_class() && unit.fq_name() == "absl.Span")
        );
        for method in ["begin", "back"] {
            assert!(declarations.iter().any(|unit| {
                unit.is_function() && unit.fq_name() == format!("absl.Span.{method}")
            }));
            assert!(
                declarations.iter().any(|unit| {
                    unit.is_function() && unit.fq_name() == format!("absl.{method}")
                })
            );
        }
        assert!(
            declarations
                .iter()
                .any(|unit| unit.is_class() && unit.fq_name() == "control.AnySpan")
        );
        assert!(
            declarations
                .iter()
                .any(|unit| { unit.is_function() && unit.fq_name() == "control.AnySpan.begin" })
        );
        assert!(
            declarations
                .iter()
                .all(|unit| unit.fq_name() != "absl.ABSL_ATTRIBUTE_VIEW")
        );
    }

    #[test]
    fn explicit_global_member_definition_has_canonical_package_boundary() {
        let source = r#"
namespace arangodb::aql {
class ExecutionPlan {
 public:
  template<class... Args> Node* createNode(Args&&... args);
};
}

template<class... Args>
Node* ::arangodb::aql::ExecutionPlan::createNode(Args&&... args) { return nullptr; }
"#;
        let parsed = parse_cpp_declarations(source, "global-member.cpp");

        assert!(parsed.declarations().iter().any(|unit| {
            unit.is_function()
                && unit.package_name() == "arangodb::aql"
                && unit.short_name() == "ExecutionPlan.createNode"
                && unit.fq_name() == "arangodb::aql.ExecutionPlan.createNode"
        }));
    }

    #[test]
    fn consecutive_macro_export_classes_keep_namespace_sibling_ownership() {
        let source = r#"
#ifndef TINYXML2_INCLUDED
#define TINYXML2_INCLUDED
namespace tinyxml2 {
class TINYXML2_LIB XMLUtil {
 public:
  static const char* SkipWhiteSpace(const char* p) {
    while (*p) {
      if (*p == ' ') {
        ++p;
      }
    }
    return p;
  }
  static bool StringEqual(const char* p, const char* q) {
    return p == q;
  }
  class TINYXML2_LIB Helper {
   public:
    void Touch();
  };
  static void ToStr(int value, char* buffer);
 private:
  static const char* writeBoolTrue;
};

class TINYXML2_LIB XMLNode {
 public:
  virtual XMLNode* ShallowClone() const = 0;
  virtual bool ShallowEqual(const XMLNode* compare) const = 0;
};
}
#endif
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut boundary_found = false;
        walk_named_tree_preorder(tree.root_node(), true, |node| {
            if let Some((_, name, _)) = recover_exported_class_function_definition(node, source)
                && name == "XMLUtil"
            {
                boundary_found = fragmented_export_sibling_class_boundary(node, source)
                    .and_then(|boundary| {
                        recover_exported_class_function_definition(boundary, source)
                    })
                    .is_some_and(|(_, name, _)| name == "XMLNode");
            }
            WalkControl::Continue
        });
        assert!(
            boundary_found,
            "fixture must exercise the recovered sibling boundary"
        );

        let parsed = parse_cpp_declarations(source, "macro-sibling-classes.cpp");
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| unit.fq_name() == "tinyxml2.XMLNode"),
            "{:#?}",
            parsed.declarations()
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .all(|unit| unit.fq_name() != "tinyxml2.XMLUtil$XMLNode"),
            "{:#?}",
            parsed.declarations()
        );
        assert!(parsed.declarations().iter().any(|unit| {
            unit.fq_name() == "tinyxml2.XMLNode.ShallowEqual" && unit.is_function()
        }));
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| { unit.fq_name() == "tinyxml2.XMLUtil.ToStr" && unit.is_function() })
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| { unit.fq_name() == "tinyxml2.XMLUtil$Helper" && unit.is_class() })
        );
    }

    #[test]
    fn explicit_global_namespace_recovery_does_not_duplicate_lexical_scope() {
        // Clang's diagnostic suite intentionally contains this ill-formed
        // spelling. The analyzer must retain the parser's explicit-global AST
        // boundary instead of constructing `cwg311::::cwg311::X`.
        let parsed = parse_cpp_declarations(
            r#"
namespace cwg311 {
namespace X { namespace Y {} }
namespace ::cwg311::X {}
}
"#,
            "explicit-global-namespace.cpp",
        );

        assert!(parsed.declarations().iter().any(|unit| {
            unit.kind() == CodeUnitType::Module
                && unit.short_name() == "cwg311::X"
                && unit.fq_name() == "cwg311::X"
        }));
        assert!(
            parsed
                .declarations()
                .iter()
                .all(|unit| !unit.short_name().contains("::::")),
            "recovered namespace names must not retain empty scope components: {:#?}",
            parsed.declarations()
        );
    }

    #[test]
    fn repeated_scope_separator_does_not_create_empty_function_owner() {
        let scope = ScopeInfo {
            package_name: "X".to_string(),
            module: None,
            class_unit: None,
            template_signature: None,
            template_metadata: None,
            declarations_are_fields: false,
            recovered_specialization_member_scope: false,
            visible_using_namespaces: Vec::new(),
        };

        let (owner, name, package) = split_cpp_name("X::::doit", &scope);

        assert_eq!(owner, None);
        assert_eq!(name, "doit");
        assert_eq!(package, "X");
    }

    #[test]
    fn trailing_decltype_expression_is_not_a_function_declarator() {
        let source = r#"
namespace boost { namespace detail {
#if ! defined(BOOST_NO_SFINAE_EXPR) && \
    ! defined(BOOST_NO_CXX11_DECLTYPE) && \
    ! defined(BOOST_NO_CXX11_TRAILING_RESULT_TYPES)
#define BOOST_THREAD_PROVIDES_INVOKE
#if ! defined(BOOST_NO_CXX11_VARIADIC_TEMPLATES)
template <class Fp, class A0, class ...Args>
inline auto
invoke(BOOST_THREAD_RV_REF(Fp) f, BOOST_THREAD_RV_REF(A0) a0,
       BOOST_THREAD_RV_REF(Args) ...args)
    -> decltype((boost::forward<A0>(a0).*f)(boost::forward<Args>(args)...))
{
    return (boost::forward<A0>(a0).*f)(boost::forward<Args>(args)...);
}
#endif
#endif
}}
"#;
        let parsed = parse_cpp_declarations(source, "trailing-decltype.hpp");

        assert!(
            parsed
                .declarations()
                .iter()
                .all(|unit| unit.short_name() != ".*f")
        );
    }

    fn find_class_named<'tree>(
        root: Node<'tree>,
        source: &str,
        expected_name: &str,
    ) -> Option<Node<'tree>> {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "class_specifier"
                && node
                    .child_by_field_name("name")
                    .is_some_and(|name| node_text(name, source) == expected_name)
            {
                return Some(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        None
    }

    #[test]
    fn sentinel_candidate_rejects_macro_qualified_callables_before_reparse() {
        let source = r#"EXPORT void definition(struct Value value) {}
EXPORT void prototype(struct Value value);
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        let mut cursor = root.walk();
        let callables = root
            .named_children(&mut cursor)
            .filter(|node| matches!(node.kind(), "function_definition" | "declaration"))
            .collect::<Vec<_>>();

        assert_eq!(callables.len(), 2, "unexpected fixture shape: {root}");
        for callable in callables {
            assert!(callable.has_error(), "fixture must exercise error recovery");
            assert!(
                cpp_sentinel_macro_parts(callable, source).is_none(),
                "macro-qualified callable must be rejected before sentinel region discovery: {callable}"
            );
        }
    }

    #[test]
    fn sentinel_candidate_keeps_class_before_recovered_member_callable() {
        let source = r#"namespace absl {
ABSL_NAMESPACE_BEGIN
// Generate a floating-point variate conforming to a Beta distribution:
template <typename RealType = double>
class beta_distribution {
 public:
  using result_type = RealType;


  beta_distribution() : beta_distribution(1) {}

  explicit beta_distribution(result_type alpha, result_type beta = 1)
      : param_(alpha, beta) {}

  explicit beta_distribution(const param_type& p) : param_(p) {}

  void reset() {}

  // Generating functions
  template <typename URBG>
  result_type operator()(URBG& g) {  // NOLINT(runtime/references)
    return (*this)(g, param_);
  }

};
ABSL_NAMESPACE_END
}  // namespace absl
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let namespace = tree.root_node().named_child(0).expect("fixture namespace");
        let body = namespace
            .child_by_field_name("body")
            .expect("fixture namespace body");
        let sentinel = body.named_child(0).expect("sentinel envelope");
        let callable = sentinel
            .child_by_field_name("declarator")
            .and_then(extract_function_declarator)
            .and_then(cpp_function_declarator_name_node)
            .expect("preserved callable name");

        assert_eq!(sentinel.kind(), "function_definition");
        assert_eq!(callable.kind(), "operator_name");
        assert!(
            cpp_sentinel_macro_parts(sentinel, source).is_some(),
            "a class preceding its recovered member callable remains a sentinel: {sentinel}"
        );
    }

    #[test]
    fn sentinel_candidate_keeps_class_before_recovered_constructor_callable() {
        let source = r#"namespace absl {
ABSL_NAMESPACE_BEGIN
// absl::discrete_distribution
//
// A discrete distribution produces random integers i, where 0 <= i < n
template <typename IntType = int>
class discrete_distribution {
 public:
  using result_type = IntType;
  class param_type {
   public:
    param_type() { init(); }
    template <typename InputIterator>
    explicit param_type(InputIterator begin, InputIterator end)
        : p_(begin, end) {
      init();
    }
  };
  discrete_distribution() : param_() {}
  explicit discrete_distribution(const param_type& p) : param_(p) {}
};
ABSL_NAMESPACE_END
}  // namespace absl
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let namespace = tree.root_node().named_child(0).expect("fixture namespace");
        let body = namespace
            .child_by_field_name("body")
            .expect("fixture namespace body");
        let sentinel = body.named_child(0).expect("sentinel envelope");
        let callable = sentinel
            .child_by_field_name("declarator")
            .and_then(extract_function_declarator)
            .and_then(cpp_function_declarator_name_node)
            .expect("preserved callable name");

        assert_eq!(sentinel.kind(), "function_definition");
        assert_eq!(callable.kind(), "identifier");
        assert!(
            cpp_sentinel_macro_parts(sentinel, source).is_some(),
            "a class preceding its recovered constructor remains a sentinel: {sentinel}"
        );
    }

    #[test]
    fn macro_qualified_member_function_does_not_publish_namespace_as_field() {
        let source = r#"
#define CPPCHECKLIB
class Library {
    struct Container {
        CPPCHECKLIB static std::string toString(Yield yield);
        CPPCHECKLIB static std::string toString(Action action);
    };
};
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let file = ProjectFile::new(std::env::temp_dir(), "macro-qualified-function.hpp");
        let parsed = parse_cpp_file(&file, source, &tree);
        assert!(
            parsed
                .declarations()
                .iter()
                .all(|unit| unit.fq_name() != "Library$Container.std"),
            "the qualified return-type namespace must not become a field: {:#?}",
            parsed.declarations()
        );
        for expected in ["(Yield)", "(Action)"] {
            assert!(
                parsed.declarations().iter().any(|unit| {
                    unit.is_function()
                        && unit.fq_name() == "Library$Container.toString"
                        && unit.signature() == Some(expected)
                }),
                "recovered toString overload {expected} is missing: {:#?}",
                parsed.declarations()
            );
        }
    }

    #[test]
    fn fragmented_export_constructor_keeps_initializer_names_as_fields() {
        let source = r#"
#define SIMPLECPP_LIB
namespace simplecpp {
using TokenString = std::string;
struct Location { int line{}; };
class SIMPLECPP_LIB Token {
  TokenString prefix;
  void prefix_method() {}
 public:
  Token(const TokenString &s, const Location &loc, bool wsahead = false) :
      whitespaceahead(wsahead), location(loc), string(s)
      // The comment must not hide the constructor body from recovery.
      {
      flags();
  }
  TokenString string;
  bool whitespaceahead;
  Location location;
  Token *previous{};
 private:
  void flags() {
      whitespaceahead = true;
  }
};
}
"#;
        let parsed = parse_cpp_declarations(source, "fragmented-export-constructor.hpp");

        let location_fields = parsed
            .declarations()
            .iter()
            .filter(|unit| unit.fq_name() == "simplecpp.Token.location")
            .collect::<Vec<_>>();
        assert_eq!(
            location_fields.len(),
            1,
            "location should have one class-owned declaration: {:#?}",
            parsed.declarations()
        );
        assert!(
            location_fields[0].is_field(),
            "location has wrong kind: {:#?}",
            parsed.declarations()
        );
        assert!(
            parsed.declarations().iter().all(|unit| {
                !(unit.is_function() && unit.fq_name() == "simplecpp.Token.location")
            })
        );
        assert!(
            parsed.declarations().iter().all(|unit| {
                !(unit.is_function() && unit.fq_name() == "simplecpp.Token.string")
            })
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| unit.is_function() && unit.fq_name() == "simplecpp.Token.flags")
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| unit.is_function() && unit.fq_name() == "simplecpp.Token.Token"),
            "the recovered class must retain its constructor: {:#?}",
            parsed.declarations()
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| unit.is_field() && unit.fq_name() == "simplecpp.Token.prefix")
        );
        assert!(parsed.declarations().iter().any(|unit| {
            unit.is_function() && unit.fq_name() == "simplecpp.Token.prefix_method"
        }));
        let constructor = parsed
            .declarations()
            .iter()
            .find(|unit| unit.is_function() && unit.fq_name() == "simplecpp.Token.Token")
            .expect("recovered constructor");
        let constructor_start = source.find("Token(const").expect("constructor start");
        let constructor_end = source
            .get(
                ..source
                    .find("  TokenString string;")
                    .expect("constructor end"),
            )
            .expect("constructor slice")
            .trim_end()
            .len();
        assert!(
            parsed
                .navigation_ranges
                .get(constructor)
                .is_some_and(|ranges| {
                    ranges.iter().any(|range| {
                        range.start_byte == constructor_start && range.end_byte == constructor_end
                    })
                }),
            "constructor navigation must span the full body: {:#?}",
            parsed.navigation_ranges
        );
        assert_eq!(
            parsed
                .signature_metadata
                .get(constructor)
                .and_then(|metadata| metadata.first())
                .and_then(SignatureMetadata::callable_linkage),
            Some(CallableLinkage::External)
        );
        let token_class = parsed
            .declarations()
            .iter()
            .find(|unit| unit.is_class() && unit.fq_name() == "simplecpp.Token")
            .expect("recovered Token class");
        let class_end = source.rfind("};\n}").expect("class terminator") + 2;
        assert!(
            parsed
                .navigation_ranges
                .get(token_class)
                .is_some_and(|ranges| ranges.iter().any(|range| range.end_byte == class_end)),
            "class navigation must include the terminating semicolon: {:#?}",
            parsed.navigation_ranges
        );
    }

    #[test]
    fn simplecpp_token_fragmented_export_keeps_location_and_string_fields() {
        let source = r#"
#define SIMPLECPP_LIB
namespace simplecpp {
using TokenString = std::string;
class Macro;
struct Location {
  unsigned int fileIndex{};
  unsigned int line{};
  unsigned int col{};
};
struct Output {
  int type;
};
class SIMPLECPP_LIB Token {
 public:
  Token(const TokenString &s, const Location &loc, bool wsahead = false) :
      whitespaceahead(wsahead), location(loc), string(s) {
      flags();
  }
  Token(const Token &tok) :
      macro(tok.macro), op(tok.op), comment(tok.comment), name(tok.name),
      number(tok.number), whitespaceahead(tok.whitespaceahead), location(tok.location),
      string(tok.string), mExpandedFrom(tok.mExpandedFrom) {}
  Token &operator=(const Token &tok) = delete;
  const TokenString& str() const { return string; }
  void setstr(const std::string &s) { string = s; flags(); }
  bool isOneOf(const char ops[]) const;
  TokenString macro;
  char op;
  bool comment;
  bool name;
  bool number;
  bool whitespaceahead;
  Location location;
  Token *previous{};
  Token *next{};
 private:
  void flags() {
      name = !string.empty();
      comment = false;
      number = false;
      op = 0;
  }
  TokenString string;
};
}
struct Following {
  int type;
};
class SIMPLECPP_LIB Later {
 public:
  Later(int value) : value(value) {}
  int value;
};
"#;
        let parsed = parse_cpp_declarations(source, "simplecpp-token.hpp");
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| { unit.is_field() && unit.fq_name() == "simplecpp.Token.location" })
        );
        assert!(
            !parsed
                .declarations()
                .iter()
                .any(|unit| { unit.is_function() && unit.fq_name() == "simplecpp.Token.location" })
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| unit.is_field() && unit.fq_name() == "simplecpp.Token.string")
        );
        assert!(
            !parsed
                .declarations()
                .iter()
                .any(|unit| unit.is_function() && unit.fq_name() == "simplecpp.Token.string")
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| unit.is_class() && unit.fq_name() == "simplecpp.Output")
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| unit.is_field() && unit.fq_name() == "simplecpp.Output.type")
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| unit.is_class() && unit.fq_name() == "Following")
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| unit.is_field() && unit.fq_name() == "Following.type")
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| unit.is_class() && unit.fq_name() == "Later")
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| unit.is_field() && unit.fq_name() == "Later.value")
        );
        assert!(parsed.declarations().iter().all(|unit| {
            !matches!(
                unit.fq_name().as_str(),
                "simplecpp.Token.Following" | "simplecpp.Token.Later"
            )
        }));
        assert!(
            !parsed
                .declarations()
                .iter()
                .any(|unit| unit.fq_name() == "simplecpp.Token.Output"),
            "the following struct must remain outside the recovered Token class"
        );
    }

    #[test]
    fn fragmented_export_constructor_in_anonymous_namespace_has_internal_linkage() {
        let source = r#"
#define SIMPLECPP_LIB
namespace {
namespace simplecpp {
using TokenString = std::string;
struct Location { int line{}; };
class SIMPLECPP_LIB HiddenToken {
 public:
  HiddenToken(const TokenString &s, const Location &loc) :
      location(loc), string(s) {
      flags();
  }
  TokenString string;
  Location location;
  HiddenToken *previous{};
 private:
  void flags() {}
};
}
}
"#;
        let parsed = parse_cpp_declarations(source, "fragmented-anonymous-constructor.hpp");
        let constructor = parsed
            .declarations()
            .iter()
            .find(|unit| unit.is_function() && unit.identifier() == "HiddenToken")
            .expect("recovered anonymous-namespace constructor");
        assert_eq!(
            parsed
                .signature_metadata
                .get(constructor)
                .and_then(|metadata| metadata.first())
                .and_then(SignatureMetadata::callable_linkage),
            Some(CallableLinkage::Internal)
        );
    }

    #[test]
    fn macro_qualified_static_field_keeps_real_declarator() {
        let source = r#"#define JSON_INLINE_VARIABLE
struct Reader {
static JSON_INLINE_VARIABLE constexpr std::size_t npos = 1, other = 2;
static JSON_INLINE_VARIABLE constexpr std::size_t *pointer = nullptr;
static JSON_INLINE_VARIABLE constexpr std::size_t &reference = other;
};"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let file = ProjectFile::new(std::env::temp_dir(), "macro-static-field.hpp");
        let parsed = parse_cpp_file(&file, source, &tree);
        for expected in [
            "Reader.npos",
            "Reader.other",
            "Reader.pointer",
            "Reader.reference",
        ] {
            assert!(
                parsed
                    .declarations()
                    .iter()
                    .any(|unit| unit.is_field() && unit.fq_name() == expected),
                "real macro-decorated field {expected} is missing: {:#?}",
                parsed.declarations()
            );
        }
        assert!(
            parsed
                .declarations()
                .iter()
                .all(|unit| unit.fq_name() != "Reader.std"),
            "qualified type prefix became a pseudo-field: {:#?}",
            parsed.declarations()
        );
        let root = tree.root_node();
        let mut stack = vec![root];
        let mut signatures = Vec::new();
        while let Some(current) = stack.pop() {
            if let Some(declarators) = recovered_macro_qualified_field_declarators(current, source)
            {
                signatures.extend(
                    declarators
                        .into_iter()
                        .map(|declarator| render_cpp_field_signature(current, declarator, source)),
                );
            }
            let mut cursor = current.walk();
            stack.extend(current.named_children(&mut cursor));
        }
        signatures.sort();
        assert_eq!(
            signatures,
            [
                "static JSON_INLINE_VARIABLE constexpr std::size_t & reference = other;",
                "static JSON_INLINE_VARIABLE constexpr std::size_t * pointer = nullptr;",
                "static JSON_INLINE_VARIABLE constexpr std::size_t npos = 1;",
                "static JSON_INLINE_VARIABLE constexpr std::size_t other = 2;",
            ]
        );
    }

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
        assert_eq!(
            member_function_linkage("namespace { struct Named { int method() { return 1; } }; }"),
            CallableLinkage::Internal
        );
    }

    #[test]
    fn malformed_class_macro_constructors_have_no_decorator_return_type() {
        let source = r#"
#ifndef PROTON_VALUE_HPP
#define PROTON_VALUE_HPP
namespace proton {
namespace internal {
class value_base {
  protected:
    internal::data& data();
    internal::data data_;
  friend class codec::encoder;
  friend class codec::decoder;
};
}
class value : public internal::value_base, private internal::comparable<value> {
  private:
    template<class T, class U=void> struct assignable :
        public std::enable_if<codec::is_encodable<T>::value, U> {};
    template<class U> struct assignable<value, U> {};
  public:
    PN_CPP_EXTERN value();
    PN_CPP_EXTERN value(const value&);
    PN_CPP_EXTERN value& operator=(const value&);
    PN_CPP_EXTERN value(value&&);
    PN_CPP_EXTERN value& operator=(value&&);
    template <class T> value(const T& x, typename assignable<T>::type* = 0) { *this = x; }
    template <class T> typename assignable<T, value&>::type operator=(const T& x) {
        codec::encoder e(*this);
        e << x;
        return *this;
    }
    PN_CPP_EXTERN type_id type() const;
    PN_CPP_EXTERN bool empty() const;
    PN_CPP_EXTERN void clear();
    template<class T> PN_CPP_DEPRECATED("Use 'proton::get'") void get(T &t) const;
    template<class T> PN_CPP_DEPRECATED("Use 'proton::get'") T get() const;
  friend PN_CPP_EXTERN void swap(value&, value&);
  friend PN_CPP_EXTERN bool operator==(const value& x, const value& y);
  friend PN_CPP_EXTERN bool operator<(const value& x, const value& y);
  friend PN_CPP_EXTERN std::ostream& operator<<(std::ostream&, const value&);
    value(pn_data_t* d);
    void reset(pn_data_t* d = 0);
};
}
#endif
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let file = ProjectFile::new(std::env::temp_dir(), "qpid-value.hpp");
        let parsed = parse_cpp_file(&file, source, &tree);
        let macro_constructors = parsed
            .signature_metadata
            .iter()
            .filter(|(unit, _)| unit.is_function() && unit.fq_name() == "proton.value")
            .flat_map(|(_, metadata)| metadata)
            .filter(|metadata| metadata.label().starts_with("PN_CPP_EXTERN value("))
            .collect::<Vec<_>>();

        assert_eq!(
            macro_constructors.len(),
            3,
            "fixture must retain the three macro-decorated constructor declarations: {:#?}",
            parsed.declarations()
        );
        assert!(
            macro_constructors.iter().all(|metadata| {
                metadata.return_type_text().is_none() && metadata.return_type_identity().is_none()
            }),
            "the export decorator is not a semantic constructor return type or identity: {macro_constructors:#?}"
        );
    }

    #[test]
    fn recovered_export_class_typedef_uses_displaced_alias_name() {
        let source = r#"
namespace spi {
class Filter {
public:
    enum FilterDecision { DENY, NEUTRAL, ACCEPT };
};
}
namespace filter {
class LOG4CXX_EXPORT LevelRangeFilter : public spi::Filter
{
public:
    typedef spi::Filter BASE_CLASS;
    DECLARE_LOG4CXX_OBJECT(LevelRangeFilter)
    BEGIN_LOG4CXX_CAST_MAP()
    LOG4CXX_CAST_ENTRY(LevelRangeFilter)
    LOG4CXX_CAST_ENTRY_CHAIN(BASE_CLASS)
    END_LOG4CXX_CAST_MAP()
    FilterDecision decide() const;
};
}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let file = ProjectFile::new(std::env::temp_dir(), "log4cxx-typedef.cpp");
        let parsed = parse_cpp_file(&file, source, &tree);
        assert!(
            parsed.declarations().iter().any(|unit| {
                unit.is_class()
                    && unit.fq_name() == "filter.LevelRangeFilter$BASE_CLASS"
                    && unit.signature() == Some("typedef spi::Filter BASE_CLASS;")
            }),
            "the displaced typedef alias must retain its declared name: {:#?}",
            parsed.declarations()
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .all(|unit| unit.fq_name() != "filter.LevelRangeFilter$Filter"),
            "the qualified underlying type must not become a false nested alias: {:#?}",
            parsed.declarations()
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
class
PN_CPP_CLASS_EXTERN Sender : public Link {
    Sender();
};
class thread_ctx_t {};
class ctx_t ZMQ_FINAL : public thread_ctx_t {
    bool start();
};
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let file = ProjectFile::new(std::env::temp_dir(), "exported-single-base.cpp");
        let parsed = parse_cpp_file(&file, source, &tree);
        let declarations = parsed.declarations();

        for expected in ["QgsPoint", "Ordinary", "Plain", "Sender", "ctx_t"] {
            assert!(
                declarations
                    .iter()
                    .any(|unit| unit.is_class() && unit.fq_name() == expected),
                "missing recovered class {expected}: {declarations:#?}"
            );
        }
        let qgs_point = declarations
            .iter()
            .find(|unit| unit.is_class() && unit.fq_name() == "QgsPoint")
            .expect("recovered QgsPoint class");
        assert_eq!(
            parsed.raw_supertypes.get(qgs_point),
            Some(&vec!["AbstractGeometry".to_string()]),
            "single-base export recovery must retain its displaced base"
        );
        let ordinary_start = source.find("class Ordinary").expect("ordinary sibling");
        assert!(
            parsed
                .navigation_ranges
                .get(qgs_point)
                .is_some_and(|ranges| {
                    !ranges.is_empty()
                        && ranges.iter().all(|range| range.end_byte <= ordinary_start)
                }),
            "a rejected fragmented-body candidate must not leak a range across sibling classes: {:#?}",
            parsed.navigation_ranges.get(qgs_point)
        );
        let sender = declarations
            .iter()
            .find(|unit| unit.is_class() && unit.fq_name() == "Sender")
            .expect("recovered Sender class");
        assert_eq!(
            parsed.raw_supertypes.get(sender),
            Some(&vec!["Link".to_string()]),
            "post-declarator export recovery must retain its displaced base"
        );
        let ctx = declarations
            .iter()
            .find(|unit| unit.is_class() && unit.fq_name() == "ctx_t")
            .expect("recovered ctx_t class");
        assert_eq!(
            parsed.raw_supertypes.get(ctx),
            Some(&vec!["thread_ctx_t".to_string()]),
            "postfix export-macro recovery must retain its displaced base"
        );
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
    fn cpp_reparsed_members_gate_handles_copy_control_error_only_with_semicolon() {
        let positive_source =
            "private:\n  virtual ~XMLElement();\n  XMLElement( const XMLElement& )\n  ;\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let positive_tree = parser.parse(positive_source, None).unwrap();
        assert!(cpp_reparsed_members_are_indexable(
            positive_tree.root_node(),
            positive_source
        ));

        let negative_source = "XMLElement( const XMLElement& )\n++ 0;\n";
        let negative_tree = parser.parse(negative_source, None).unwrap();
        assert!(!cpp_reparsed_members_are_indexable(
            negative_tree.root_node(),
            negative_source
        ));
    }

    #[test]
    fn cpp_reparsed_members_gate_accepts_cppcheck_copy_control_and_constraint_macros() {
        let copy_control_source = r#"
public:
    Token(const TokenList& tokenlist, std::shared_ptr<State> state);
    explicit Token(const Token* tok);
    ~Token();
    Token* astOperand1() { return nullptr; }
"#;
        let constraint_source = r#"
private:
    template<class T, REQUIRES("T must be a Token class", std::is_convertible<T*, const Token*> )>
    static T *tokAtImpl(T *tok, int index) {
        return tok;
    }

    template<class T, REQUIRES("T must be a Token class", std::is_convertible<T*, const Token*> )>
    static T *linkAtImpl(T *tok, int index) {
        return tok;
    }

public:
    int late() const { return 1; }
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let copy_control_tree = parser
            .parse(copy_control_source, None)
            .expect("parse copy-control fixture");
        assert!(
            copy_control_tree.root_node().has_error(),
            "fixture must exercise adjacent copy-control recovery"
        );
        assert!(
            cpp_reparsed_members_are_indexable(copy_control_tree.root_node(), copy_control_source),
            "a complete late getter must remain recoverable after adjacent copy-control declarations"
        );
        let mut cursor = copy_control_tree.root_node().walk();
        assert!(
            copy_control_tree
                .root_node()
                .named_children(&mut cursor)
                .any(|child| cpp_reparsed_adjacent_copy_control_error(child, copy_control_source)),
            "fixture must retain the exact explicit-constructor/destructor error geometry: {}",
            copy_control_tree.root_node().to_sexp()
        );
        let constraint_tree = parser
            .parse(constraint_source, None)
            .expect("parse constraint-macro fixture");
        assert!(constraint_tree.root_node().has_error());
        assert!(
            cpp_reparsed_members_are_indexable(constraint_tree.root_node(), constraint_source),
            "complete constraint-macro members must not hide a later ordinary member"
        );
        let mut cursor = constraint_tree.root_node().walk();
        assert!(
            constraint_tree
                .root_node()
                .named_children(&mut cursor)
                .any(|child| cpp_reparsed_template_macro_prefix_is_indexable(
                    child,
                    constraint_source
                )),
            "fixture must retain the split constraint-macro prefix/function geometry"
        );
    }

    #[test]
    fn fragmented_plain_class_recovers_nested_constrained_constructor_owner() {
        let source = r#"
struct Analyzer {
    struct Action {
        Action() = default;
        Action(const Action&) = default;
        Action& operator=(const Action& rhs) & = default;

        template<class T,
                 REQUIRES("T must be convertible to unsigned int", std::is_convertible<T, unsigned int> ),
                 REQUIRES("T must not be a bool", !std::is_same<T, bool> )>
        // NOLINTNEXTLINE(google-explicit-constructor)
        Action(T f) : mFlag(f) // cppcheck-suppress noExplicitConstructor
        {}

        enum : std::uint16_t { None = 0, Read = (1 << 0) };
        bool get(unsigned int f) const { return ((mFlag & f) != 0); }

    private:
        unsigned int mFlag{};
    };

    enum class Direction : unsigned char { Forward, Reverse };
    virtual Action analyze(Direction d) const = 0;
};
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(tree.root_node().has_error());
        let root = tree.root_node();
        let outer = root
            .named_children(&mut root.walk())
            .find(|child| child.kind() == "ERROR")
            .expect("fragmented Analyzer prefix");
        let (outer_name, outer_fragment) = fragmented_plain_class_body(outer, source)
            .expect("structured Analyzer fragment boundary");
        assert_eq!(outer_name, "Analyzer");
        let outer_tree = cpp_reparse_fragmented_class_body(
            source,
            outer_fragment.reparse_start,
            outer_fragment.reparse_end,
        )
        .expect("reparse Analyzer body");
        let outer_root = outer_tree.root_node();
        let action_prefix = outer_root
            .named_children(&mut outer_root.walk())
            .find(|child| child.kind() == "ERROR")
            .expect("fragmented Action prefix");
        let (action_name, action_fragment) = fragmented_plain_class_body(action_prefix, source)
            .expect("structured Action fragment boundary");
        assert_eq!(action_name, "Action");
        let action_tree = cpp_reparse_fragmented_class_body(
            source,
            action_fragment.reparse_start,
            action_fragment.reparse_end,
        )
        .expect("reparse Action body");
        let action_root = action_tree.root_node();
        let macro_prefix = action_root
            .named_children(&mut action_root.walk())
            .find(|child| child.kind() == "ERROR")
            .expect("constraint macro prefix");
        let macro_parameter = cpp_reparsed_template_macro_prefix_parameter(macro_prefix, source)
            .expect("structured template macro prefix");
        let macro_companion =
            cpp_next_non_comment_named_sibling(macro_prefix).expect("constraint macro companion");
        assert!(
            cpp_reparsed_template_macro_constructor_companion_is_indexable(
                macro_companion,
                macro_parameter,
                source,
            ),
            "split constrained constructor must be admitted: {}",
            macro_companion.to_sexp()
        );
        assert!(
            cpp_reparsed_members_are_indexable(action_root, source),
            "complete Action body must pass the recovery gate: {}",
            action_tree.root_node().to_sexp()
        );
        assert!(
            cpp_reparsed_members_are_indexable(outer_root, source),
            "complete Analyzer body must pass the recovery gate: {}",
            outer_tree.root_node().to_sexp()
        );
        let file = ProjectFile::new(std::env::temp_dir(), "fragmented-analyzer.hpp");
        let parsed = parse_cpp_file(&file, source, &tree);
        for expected in ["Analyzer", "Analyzer$Action", "Analyzer$Action.get"] {
            assert!(
                parsed
                    .declarations()
                    .iter()
                    .any(|unit| unit.fq_name() == expected),
                "missing recovered declaration {expected}: {:#?}",
                parsed.declarations()
            );
        }
        assert!(
            parsed
                .declarations()
                .iter()
                .all(|unit| unit.fq_name() != "Action" && unit.fq_name() != "get"),
            "nested members must not remain flattened: {:#?}",
            parsed.declarations()
        );
    }

    #[test]
    fn cpp_reparsed_members_gate_accepts_complete_errorful_member_functions() {
        let source = r#"
raw_hash_set& operator=(raw_hash_set&& that) {
  return move_assign(
      std::move(that),
      typename AllocTraits::propagate_on_container_move_assignment());
}

iterator begin() ABSL_ATTRIBUTE_LIFETIME_BOUND {
  return {};
}

void reset() ABSL_ATTRIBUTE_LIFETIME_BOUND {}

iterator insert(const_iterator hint, value_type&& value)
    ABSL_ATTRIBUTE_LIFETIME_BOUND {
  return {};
}

friend bool operator==(const raw_hash_set& left, const raw_hash_set& right) {
  return left.size() == right.size();
}

static ABSL_ATTRIBUTE_ALWAYS_INLINE slot_type* to_slot(void* buffer) {
  return static_cast<slot_type*>(buffer);
}

protected:
// Included-range recovery can attach this comment to the template prefix.
template <class K>
void AssertOnFind([[maybe_unused]] const K& key) {
  Check(key);
}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(
            tree.root_node().has_error(),
            "the fixture must exercise tree-sitter's errorful member shapes"
        );
        assert!(cpp_reparsed_members_are_indexable(tree.root_node(), source));

        let incomplete_source = "iterator begin() ABSL_ATTRIBUTE_LIFETIME_BOUND { return {};\n";
        let incomplete_tree = parser.parse(incomplete_source, None).unwrap();
        assert!(!cpp_reparsed_members_are_indexable(
            incomplete_tree.root_node(),
            incomplete_source
        ));

        let outside_error_source = "int foo() stray_attribute {}\n";
        let outside_error_tree = parser.parse(outside_error_source, None).unwrap();
        assert!(outside_error_tree.root_node().has_error());
        assert!(!cpp_reparsed_members_are_indexable(
            outside_error_tree.root_node(),
            outside_error_source
        ));

        let variable_initializer_source = "int value(1) ABSL_ATTRIBUTE_LIFETIME_BOUND { bad; }\n";
        let variable_initializer_tree = parser.parse(variable_initializer_source, None).unwrap();
        assert!(!cpp_reparsed_members_are_indexable(
            variable_initializer_tree.root_node(),
            variable_initializer_source
        ));
    }

    #[test]
    fn cpp_reparsed_members_gate_accepts_paired_attribute_requires_body() {
        let positive_source = r#"
std::pair<iterator, bool> insert(init_type&& value)
    ABSL_ATTRIBUTE_LIFETIME_BOUND
#if ABSL_INTERNAL_CPLUSPLUS_LANG >= 202002L
  requires(!IsLifetimeBoundAssignmentFrom<init_type>::value)
#endif
{
  return emplace(std::move(value));
}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let positive_tree = parser.parse(positive_source, None).unwrap();
        assert!(
            positive_tree.root_node().has_error(),
            "the fixture must exercise the split attribute/requires shape"
        );
        assert!(cpp_reparsed_members_are_indexable(
            positive_tree.root_node(),
            positive_source
        ));

        let template_return_source = r#"
pair<int> insert(init_type&& value)
    ABSL_ATTRIBUTE_LIFETIME_BOUND
#if LANGUAGE_LEVEL >= 202002L
  requires(!Predicate<init_type>::value)
#endif
// Attributes and the function body may be separated by comments.
{
  return {};
}
"#;
        let template_return_tree = parser.parse(template_return_source, None).unwrap();
        assert!(
            cpp_reparsed_members_are_indexable(
                template_return_tree.root_node(),
                template_return_source
            ),
            "template-return attribute/requires tree: {}",
            template_return_tree.root_node().to_sexp()
        );

        let no_body_source = r#"
std::pair<iterator, bool> insert(init_type&& value)
    ABSL_ATTRIBUTE_LIFETIME_BOUND
#if ABSL_INTERNAL_CPLUSPLUS_LANG >= 202002L
  requires(!IsLifetimeBoundAssignmentFrom<init_type>::value)
#endif
+ 0;
"#;
        let no_body_tree = parser.parse(no_body_source, None).unwrap();
        assert!(!cpp_reparsed_members_are_indexable(
            no_body_tree.root_node(),
            no_body_source
        ));

        let extra_payload_source = r#"
pair<int> insert(init_type&& value)
    ABSL_ATTRIBUTE_LIFETIME_BOUND
#if LANGUAGE_LEVEL >= 202002L
  int unrelated;
  requires(Predicate<init_type>::value)
#endif
{
  return {};
}
"#;
        let extra_payload_tree = parser.parse(extra_payload_source, None).unwrap();
        assert!(!cpp_reparsed_members_are_indexable(
            extra_payload_tree.root_node(),
            extra_payload_source
        ));

        let variable_initializer_source = r#"
int value(1) ABSL_ATTRIBUTE_LIFETIME_BOUND
#if LANGUAGE_LEVEL >= 202002L
  requires(true)
#endif
{
  bad;
}
"#;
        let variable_initializer_tree = parser.parse(variable_initializer_source, None).unwrap();
        assert!(!cpp_reparsed_members_are_indexable(
            variable_initializer_tree.root_node(),
            variable_initializer_source
        ));
    }

    #[test]
    fn sentinel_scope_prefers_deeper_fragmented_class_over_outer_shadow() {
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/cpp_macro_sentinel_raw_hash_set.h"
        ));
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let field = "    raw_hash_set& s;";
        let start = source.find(field).expect("InsertSlot field") + 4;
        let node = tree
            .root_node()
            .descendant_for_byte_range(start, start + "raw_hash_set".len())
            .expect("raw_hash_set type node");
        let recovered = cpp_sentinel_recovered_classes(tree.root_node(), source);

        assert_eq!(
            cpp_sentinel_recovered_scope_for_node(node, source, &recovered),
            Some(vec![
                "absl".to_string(),
                "container_internal".to_string(),
                "raw_hash_set".to_string(),
                "InsertSlot".to_string(),
            ])
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
        let parsed = parse_cpp_file(&file, &source, &tree);
        let comparisons = finish_declaration_identity_comparison_probe();

        assert_eq!(
            DISTINCT_PER_KIND + 1,
            parsed
                .declarations()
                .iter()
                .filter(|unit| unit.is_class() && unit.short_name().starts_with("Alias"))
                .count(),
            "every physical typedef alias declaration must be retained so \
             conditional branch guards stay available to the resolver"
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

    #[test]
    fn sentinel_recovery_admits_errorful_class_with_real_body_close() {
        let source = r#"namespace absl {
ABSL_NAMESPACE_BEGIN namespace container_internal {
template <typename T>
class broken {
 public:
  using value_type = T;
  T operator->() const { return &operator*(); }
  using alias = value_type;
};
}
}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let broken = find_class_named(tree.root_node(), source, "broken")
            .expect("the positive fixture must expose the broken class node");
        assert!(
            broken.has_error(),
            "the positive fixture must retain an internal parser error"
        );
        assert!(
            cpp_complete_class_body_close(broken).is_some(),
            "the positive fixture must expose a real class body close"
        );
        let recovered = cpp_sentinel_recovered_classes(tree.root_node(), source);
        assert!(
            recovered.iter().any(|class| {
                class.scope_components == ["absl", "container_internal", "broken"]
            }),
            "a complete class body must be recovered despite an internal parser error: {recovered:#?}"
        );
    }

    #[test]
    fn sentinel_recovery_keeps_members_after_nested_body_close() {
        let source = r#"NLOHMANN_JSON_NAMESPACE_BEGIN
NLOHMANN_BASIC_JSON_TPL_DECLARATION
class basic_json {
 private:
  union storage {
    int value;
  } data;
 public:
  using late_alias = int;
  late_alias value() const;
};
NLOHMANN_JSON_NAMESPACE_END
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let recovered = cpp_sentinel_recovered_classes(tree.root_node(), source);
        let basic_json = recovered
            .iter()
            .find(|class| {
                class
                    .scope_components
                    .last()
                    .is_some_and(|name| name == "basic_json")
            })
            .unwrap_or_else(|| panic!("the fragmented class must be recovered: {recovered:#?}"));
        let late_alias = source
            .find("late_alias value")
            .expect("late alias reference");
        assert!(
            basic_json.class_range.start_byte < late_alias
                && late_alias < basic_json.class_range.end_byte,
            "the recovered class range must include members after a nested close: {basic_json:#?}"
        );
    }

    #[test]
    fn sentinel_recovery_rejects_class_that_borrows_outer_close() {
        let source = r#"namespace absl {
ABSL_NAMESPACE_BEGIN namespace container_internal {
template <typename T>
class broken {
 public:
  using value_type = T;
  T operator->() const { return &operator*(); }
}
}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let broken = find_class_named(tree.root_node(), source, "broken")
            .expect("the negative fixture must expose the malformed class node");
        assert!(
            broken.has_error(),
            "the negative fixture must retain a parser error"
        );
        assert!(
            cpp_complete_class_body_close(broken).is_none(),
            "the malformed class must not expose a real body close"
        );
        let recovered = cpp_sentinel_recovered_classes(tree.root_node(), source);
        assert!(
            recovered
                .iter()
                .all(|class| class.scope_components != ["absl", "container_internal", "broken"]),
            "an incomplete class must not borrow the namespace close: {recovered:#?}"
        );
    }

    #[test]
    fn sentinel_recovery_collects_guarded_sibling_owner_without_crossing_namespace_sibling() {
        let source = r#"namespace absl {
ABSL_NAMESPACE_BEGIN namespace container_internal {
template <typename T>
struct broken {
  using value_type = T;
};
}

#ifdef OWNER_DEF
template <typename T>
typename broken<T>::value_type broken<T>::method() {
  value_type value{};
  return value;
}
#endif

namespace sibling {
template <typename T>
typename broken<T>::value_type broken<T>::other() {
  value_type value{};
  return value;
}
}

ABSL_NAMESPACE_END
}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let recovered = cpp_sentinel_recovered_classes(tree.root_node(), source);
        let broken = recovered
            .iter()
            .find(|class| class.scope_components == ["absl", "container_internal", "broken"])
            .expect("the sentinel class must be recovered");
        let method_start = source
            .find("typename broken<T>::value_type broken<T>::method()")
            .expect("guarded sibling owner");
        let method_end = source[method_start..]
            .find("\n}")
            .map(|offset| method_start + offset + 2)
            .expect("guarded sibling owner close");
        assert!(
            broken
                .owner_ranges
                .iter()
                .any(|owner| owner.range.start_byte <= method_start
                    && method_end <= owner.range.end_byte),
            "guarded sibling owner must be attached to the recovered class: {broken:#?}"
        );
        let sibling_start = source
            .find("typename broken<T>::value_type broken<T>::other()")
            .expect("nested namespace sibling owner");
        assert!(
            broken
                .owner_ranges
                .iter()
                .all(|owner| owner.range.start_byte > sibling_start
                    || owner.range.end_byte <= sibling_start),
            "a parser-visible namespace sibling must not inherit the recovered class scope: {broken:#?}"
        );
    }

    #[test]
    fn sentinel_recovery_discards_outer_siblings_without_namespace_end_marker() {
        let source = r#"#ifdef OUTER
namespace absl {
ABSL_NAMESPACE_BEGIN namespace container_internal {
template <typename T>
struct broken {
  using value_type = T;
};
}
}

#ifdef OWNER_DEF
template <typename T>
typename broken<T>::value_type broken<T>::method() {
  value_type value{};
  return value;
}
#endif
#endif
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let recovered = cpp_sentinel_recovered_classes(tree.root_node(), source);
        let broken = recovered
            .iter()
            .find(|class| class.scope_components == ["absl", "container_internal", "broken"])
            .expect("the sentinel class must be recovered");
        let method_start = source
            .find("typename broken<T>::value_type broken<T>::method()")
            .expect("outer sibling owner");
        assert!(
            broken
                .owner_ranges
                .iter()
                .all(|owner| owner.range.start_byte > method_start
                    || owner.range.end_byte <= method_start),
            "missing ABSL_NAMESPACE_END must not attach outer sibling owners: {broken:#?}"
        );
    }
}
