//! The C++ declaration walk, including the macro-sentinel error recovery.
//!
//! Every function here is a pure function of a parsed tree and its source text.
//! `analyzer/cpp/adapter.rs` in `brokk-bifrost-analysis` drives
//! [`CppVisitor`] out of `LanguageAdapter::parse_file`.

use crate::graph::resolver::OrphanedNamespaceScopeIndex;
use brokk_bifrost_core::analyzer::common::{
    node_source_text, parse_source_ranges_with_cancellation, parse_source_region,
};
use brokk_bifrost_core::analyzer::fq_name::{
    FqName, SegmentId, SegmentKind, joined_segments, normalize_joined, segment_interner,
};
use brokk_bifrost_core::analyzer::model::{
    CallableArity, CallableLinkage, CodeUnitType, CppFieldLinkage, CppTemplateAliasTargetMetadata,
    CppTemplateExpression, CppTemplateMetadata, CppTemplateParameterKind,
    CppTemplateParameterMetadata, CppTemplateTerm, DispatchExtensibility, ImportInfo,
    ParameterMetadata, Range, SignatureMetadata, StructuredTypeIdentity,
    StructuredTypeIdentityBuilder, StructuredTypeName, StructuredTypeNodeId,
};
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::analyzer::structural::materialization::{
    GenerationKind, MaterializationRecord,
};
use brokk_bifrost_core::analyzer::tree_walk::{ParentIndex, WalkControl, walk_named_tree_preorder};
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
    for component in joined_segments(package_name, CPP_PACKAGE_SEPARATOR) {
        fq.push(cpp_segment(component, SegmentKind::Package));
    }
}

/// C++ namespace paths are stored `::`-joined in `package_name` (issue #1163).
const CPP_PACKAGE_SEPARATOR: &str = "::";

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

/// The per-level namespace components a `namespace_definition`'s `name` field
/// declares.
///
/// A C++17 nested definition (`namespace a::b::c`) parses as a
/// `nested_namespace_specifier` whose named children are the per-level
/// `namespace_identifier`s plus, for three or more levels, a further
/// `nested_namespace_specifier`; the `::` separators, the optional per-level
/// `inline`, and the leading global `::` are all anonymous tokens the walk
/// skips. Reading those nodes keeps the shorthand on the same one-level-per-
/// segment path as the expanded `namespace a { namespace b { } }` form.
///
/// A shape outside that grammar is the deliberately ill-formed source the
/// diagnostic corpora carry. Those keep their historical single-component
/// reading of the raw name text, which the caller still joins to the lexical
/// namespace exactly as before.
fn cpp_namespace_name_components(node: Node<'_>, source: &str) -> Vec<String> {
    let mut components = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            "namespace_identifier" | "identifier" => {
                components.push(normalize_cpp_whitespace(node_text(current, source)));
            }
            "nested_namespace_specifier" => {
                for index in (0..current.named_child_count()).rev() {
                    stack.push(
                        current
                            .named_child(index)
                            .expect("index below the node's own named child count"),
                    );
                }
            }
            _ => return cpp_raw_namespace_name_components(node, source),
        }
    }
    if components.iter().any(String::is_empty) {
        return cpp_raw_namespace_name_components(node, source);
    }
    components
}

/// The historical reading of a namespace name node: its whole source text as
/// one component, with a leading global `::` marker dropped so the caller's
/// global-scope handling stays the AST boundary rather than a text prefix.
///
/// This is the recovery path for source outside the C++ grammar, so the text it
/// returns can carry a separator that names nothing. react-native-windows
/// templates its C++/WinRT namespaces as `namespace winrt::{{ namespaceCpp }}`,
/// and tree-sitter stops the name node at the `{{`, leaving `winrt::` -- a
/// trailing separator with no tail. The caller stores this component in
/// `short_name` and derives the fq by splitting it back apart, so an empty tail
/// desyncs the two and aborts the whole build. [`normalize_joined`] drops it
/// here, at the one place the malformed text enters, rather than leaving each
/// consumer to guard (#2353, a variant of #1878).
fn cpp_raw_namespace_name_components(node: Node<'_>, source: &str) -> Vec<String> {
    let start = node
        .child(0)
        .filter(|child| !child.is_named() && child.kind() == "::")
        .map_or(node.start_byte(), |marker| marker.end_byte());
    let text = normalize_cpp_whitespace(
        source
            .get(start..node.end_byte())
            .expect("namespace name node covers one source range"),
    );
    let text = normalize_joined(&text, CPP_PACKAGE_SEPARATOR).into_owned();
    if text.is_empty() {
        return Vec::new();
    }
    vec![text]
}

/// Return the named namespace path that structurally encloses `node`.
///
/// This intentionally follows namespace AST ancestors rather than inspecting
/// source text. Anonymous namespaces are not representable in the legacy C++
/// package field, so a path containing one fails closed.
fn cpp_lexical_namespace_name<'tree>(
    node: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> Option<String> {
    let mut components = Vec::new();
    let mut ancestor = ancestry.parent(node);
    while let Some(current) = ancestor {
        if current.kind() == "namespace_definition" {
            let name_node = current.child_by_field_name("name")?;
            let name = normalize_cpp_whitespace(node_text(name_node, source));
            if name.is_empty() {
                return None;
            }
            components.push(name);
        }
        ancestor = ancestry.parent(current);
    }
    if components.is_empty() {
        return None;
    }
    components.reverse();
    // Same shared empty-component decision as `cpp_push_package`, which splits
    // this string back apart: an enclosing namespace whose own name node is
    // malformed contributes a component carrying its own separator (#2353).
    Some(
        normalize_joined(
            &components.join(CPP_PACKAGE_SEPARATOR),
            CPP_PACKAGE_SEPARATOR,
        )
        .into_owned(),
    )
}

/// Nested-class `$` join for short names. An anonymous parent class (empty
/// short_name) contributes no segment: the FqName bridge drops empty
/// components, so a bare `parent$child` join would desync `short_name` from
/// the fq and trip the package/short boundary assert in
/// `CodeUnit::with_signature_and_fq` (#2140).
fn cpp_join_nested_short(parent_short: &str, name: &str) -> String {
    if parent_short.is_empty() {
        name.to_string()
    } else {
        format!("{parent_short}${name}")
    }
}

/// Member `.` join for short names; same anonymous-parent guard as
/// [`cpp_join_nested_short`] (#2140).
fn cpp_join_member_short(parent_short: &str, name: &str) -> String {
    if parent_short.is_empty() {
        name.to_string()
    } else {
        format!("{parent_short}.{name}")
    }
}

/// Structural fq for a leaf declaration: the parent unit's fq plus this
/// declaration's own name as one segment (or the package segments plus the
/// name when parentless). Never re-splits the legacy `$`/`.`-joined short
/// chain, so a literal `$` inside a source identifier (Cython template
/// substitution points, gcc `$`-identifiers) survives instead of corrupting
/// the chain and tripping the package/short boundary assert (#2140).
fn cpp_leaf_fq(
    package_name: &str,
    parent: Option<&CodeUnit>,
    name: &str,
    kind_if_nested: SegmentKind,
    kind_if_top: SegmentKind,
) -> FqName {
    if let Some(parent) = parent {
        parent
            .fq()
            .clone()
            .with_pushed(cpp_segment(name, kind_if_nested))
    } else {
        let mut fq = FqName::new();
        cpp_push_package(&mut fq, package_name);
        fq.push(cpp_segment(name, kind_if_top));
        fq
    }
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
    children: std::vec::IntoIter<Node<'tree>>,
    scope: ScopeInfo,
}

enum CppWork<'tree> {
    Container(CppContainer<'tree>),
    Node(CppNodeWork<'tree>),
    Siblings(CppSiblingsWork<'tree>),
}

fn class_like_name<'tree>(
    node: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> Option<String> {
    let best = class_like_name_from_children(node, source);
    if let Some(parent) = ancestry.parent(node)
        && matches!(
            parent.kind(),
            "declaration" | "field_declaration" | "function_definition"
        )
        // A class_specifier carrying its own body proves the grammar name is
        // the real class name: a sibling declarator then declares an object
        // (`class X {} x;`), never a displaced class name. The gate matters
        // when the class name is itself an all-caps token (`X`, `API`) --
        // without it the export-macro re-read below steals the object
        // declarator's name for the class (#2283). The genuine export-macro
        // shapes leave the class_specifier bodyless, the same invariant
        // recover_malformed_exported_multiple_base_class already gates on.
        && cpp_body_node(node).is_none()
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

struct RecoveredFunctionLikeExportClassPair {
    name: String,
    range: Range,
    raw_supertypes: Option<Vec<String>>,
    fragmented_body: FragmentedExportBody,
}

struct RecoveredEmbeddedFunctionLikeExportClass {
    name: String,
    range: Range,
    raw_supertypes: Vec<String>,
    fragmented_body: FragmentedExportBody,
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

fn recovered_fragmented_export_body(
    body: Node<'_>,
    class_range: Range,
) -> Option<FragmentedExportBody> {
    let open = body.child(0).filter(|child| child.kind() == "{")?;
    let close = body
        .child(body.child_count().saturating_sub(1))
        .filter(|child| child.kind() == "}" && !child.is_missing());
    Some(FragmentedExportBody {
        reparse_start: open.end_byte(),
        // A zero-width missing `}` contributes no source byte. Keep the whole
        // body range in that case; subtracting one byte would discard the last
        // member's semicolon and make the otherwise valid region unsafe to
        // index. A real close token is excluded by its structured start.
        reparse_end: close.map_or(body.end_byte(), |close| close.start_byte()),
        class_range,
    })
}

struct DisplacedFragmentNamespaceBoundary<'tree> {
    class_close: Node<'tree>,
    class_semicolon: Node<'tree>,
    namespace_items: Vec<Node<'tree>>,
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
    if let Some(recovered) = recover_malformed_exported_base_class(node, source) {
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

fn recover_malformed_exported_base_class<'tree>(
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
    let displaced = named.find(|child| child.kind() != "attribute_declaration")?;
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
            break displaced_fragment_namespace_boundary(node, body, source)?.class_close;
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
    displaced_namespace: Option<&DisplacedFragmentNamespaceBoundary<'_>>,
) -> Option<FragmentedExportBody> {
    let reparse_start = body.start_byte().checked_add(1)?;
    if let Some(boundary) = displaced_namespace {
        return Some(FragmentedExportBody {
            reparse_start,
            reparse_end: boundary.class_close.start_byte(),
            class_range: Range {
                start_byte: node.start_byte(),
                end_byte: boundary.class_semicolon.end_byte(),
                start_line: node.start_position().row + 1,
                end_line: boundary.class_semicolon.end_position().row + 1,
            },
        });
    }
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
    // by its displaced semicolon (comments and a trailing attribute macro --
    // `} GTEST_ATTRIBUTE_UNUSED_;`, a bare-identifier expression statement --
    // may sit between the body and that semicolon). Only scan for a later
    // stray close when real member siblings intervene; otherwise every earlier
    // complete class would borrow the next malformed class's close and claim
    // its members. The trailing-attribute case is the gtest shape: the scan
    // borrowed a close ~1900 lines later and re-owned a following
    // `namespace testing { namespace internal {` block as class members,
    // doubling the package path ("testing::internal::testing::internal") and
    // mis-nesting DeathTest under ScopedTrace, tripping the package/short
    // boundary assert (#2297).
    while let Some(current) = siblings.get(sibling_index).copied() {
        if current.kind() == "comment" {
            sibling_index += 1;
            continue;
        }
        if is_trailing_attribute_macro_sibling(current) {
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

/// A trailing attribute macro after a recovered class's closing brace, spelled
/// as a bare-identifier expression statement (`GTEST_ATTRIBUTE_UNUSED_`). A
/// bare identifier is never a class member (members need a type), so this
/// sibling can only be the class's own tail (#2297).
fn is_trailing_attribute_macro_sibling(node: Node<'_>) -> bool {
    if node.kind() != "expression_statement" {
        return false;
    }
    let mut cursor = node.walk();
    let mut children = node.named_children(&mut cursor);
    children
        .next()
        .is_some_and(|child| child.kind() == "identifier")
        && children.next().is_none()
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
fn fragmented_plain_class_body<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, String, FragmentedExportBody)> {
    if let Some(recovered) = fragmented_plain_class_declaration_body(node, source) {
        return Some(recovered);
    }
    let supported_container = node.kind() == "ERROR"
        || matches!(node.kind(), "function_definition" | "labeled_statement") && node.has_error();
    if !supported_container {
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
                    node,
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

pub(crate) fn recovered_fragmented_plain_class_has_body(
    node: Node<'_>,
    source: &str,
    expected_name: &str,
    expected_range: &Range,
) -> bool {
    fragmented_plain_class_body(node, source).is_some_and(|(_, name, fragmented)| {
        name == expected_name
            && fragmented.class_range.start_byte == expected_range.start_byte
            && fragmented.class_range.end_byte == expected_range.end_byte
    })
}

/// Recover a plain class whose parser-visible body ends inside a malformed
/// inline member. Tree-sitter then attaches either the next real member
/// declarator or the unfinished `else` branch directly to the outer function
/// definition and leaves the class's actual `};` among later siblings. Those
/// structured continuations and the close/semicolon siblings establish the
/// complete body envelope without interpreting source text.
fn fragmented_plain_class_declaration_body<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, String, FragmentedExportBody)> {
    if !matches!(node.kind(), "declaration" | "function_definition") || !node.has_error() {
        return None;
    }
    let class_node = node.child_by_field_name("type")?;
    if !matches!(
        class_node.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier"
    ) {
        return None;
    }
    let name_node = class_node.child_by_field_name("name")?;
    let name = normalize_cpp_whitespace(node_text(name_node, source));
    if name.is_empty() || cpp_export_macro_token(&name) {
        return None;
    }
    let body = cpp_body_node(class_node)?;
    if body.kind() != "field_declaration_list" {
        return None;
    }
    let displaced_member = if let Some(declarator) = extract_function_declarator(node) {
        if declarator.start_byte() < class_node.end_byte() {
            return None;
        }
        let mut cursor = node.walk();
        node.named_children(&mut cursor).any(|child| {
            if child.kind() != "ERROR"
                || child.start_byte() < class_node.end_byte()
                || child.end_byte() > declarator.start_byte()
            {
                return false;
            }
            let mut cursor = child.walk();
            let components = child.named_children(&mut cursor).collect::<Vec<_>>();
            let Some((return_type, attributes)) = components.split_last() else {
                return false;
            };
            matches!(
                return_type.kind(),
                "identifier"
                    | "type_identifier"
                    | "primitive_type"
                    | "decltype"
                    | "placeholder_type_specifier"
            ) && !cpp_export_macro_token(&normalize_cpp_whitespace(node_text(*return_type, source)))
                && attributes.iter().all(|attribute| {
                    matches!(attribute.kind(), "identifier" | "type_identifier")
                        && cpp_export_macro_token(&normalize_cpp_whitespace(node_text(
                            *attribute, source,
                        )))
                })
        })
    } else {
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        matches!(children.as_slice(), [candidate_class, continuation, continuation_body]
            if same_node(*candidate_class, class_node)
                && continuation.kind() == "identifier"
                && node_text(*continuation, source) == "else"
                && continuation_body.kind() == "compound_statement"
                && continuation_body.child(0).is_some_and(|open| open.kind() == "{")
                && continuation_body
                    .child(continuation_body.child_count().saturating_sub(1))
                    .is_some_and(|close| close.kind() == "}" && !close.is_missing()))
    };
    if !displaced_member {
        return None;
    }
    let open = body
        .children(&mut body.walk())
        .find(|child| child.kind() == "{")?;
    let siblings = cpp_following_named_siblings(node, source);
    let ordinary_boundary =
        siblings
            .iter()
            .copied()
            .enumerate()
            .find_map(|(close_index, close)| {
                cpp_is_stray_close_brace(close, source)
                    .then(|| {
                        siblings
                            .get(close_index + 1)
                            .copied()
                            .filter(|semicolon| cpp_is_stray_semicolon(*semicolon, source))
                            .map(|semicolon| (close, semicolon))
                    })
                    .flatten()
            });
    let (close, semicolon) =
        if let Some(boundary) = displaced_fragment_namespace_geometry(node, source) {
            (boundary.class_close, boundary.class_semicolon)
        } else {
            ordinary_boundary?
        };
    if open.end_byte() >= close.start_byte() {
        return None;
    }
    Some((
        class_node,
        name,
        FragmentedExportBody {
            reparse_start: open.end_byte(),
            reparse_end: close.start_byte(),
            class_range: Range {
                start_byte: class_node.start_byte(),
                end_byte: semicolon.end_byte(),
                start_line: class_node.start_position().row + 1,
                end_line: semicolon.end_position().row + 1,
            },
        },
    ))
}

fn displaced_export_function_namespace_shape<'tree>(
    declaration: Node<'tree>,
    source: &str,
) -> Option<DisplacedFragmentNamespaceBoundary<'tree>> {
    let mut nested = Vec::new();
    for index in (0..declaration.named_child_count()).rev() {
        nested.push(declaration.named_child(index)?);
    }
    while let Some(current) = nested.pop() {
        // A recovered export class nested in this class can consume the first
        // parser-visible namespace close itself. In that shape the existing
        // later-class boundary logic already distinguishes the nested and
        // namespace-sibling owners; do not mistake the nested close for this
        // class's terminator.
        if recover_exported_class_function_definition(current, source).is_some() {
            return None;
        }
        for index in (0..current.named_child_count()).rev() {
            nested.push(current.named_child(index)?);
        }
    }
    let mut same_envelope_sibling = declaration.next_named_sibling();
    while let Some(current) = same_envelope_sibling {
        if recover_exported_class_function_definition(current, source).is_some() {
            return None;
        }
        same_envelope_sibling = current.next_named_sibling();
    }
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
    // A chain of malformed export classes can consume one parser-visible
    // namespace close per class. Walk through the enclosing sibling levels so
    // the later real namespace close remains the structural boundary; a
    // direct next-sibling walk stops at the first collapsed namespace and
    // incorrectly makes its intervening items members of this class.
    let siblings = cpp_following_named_siblings(namespace, source);
    let trailing_index = siblings
        .iter()
        .position(|candidate| same_node(*candidate, trailing_semicolon))?;
    if siblings.get(trailing_index + 1).is_some_and(|candidate| {
        recover_exported_class_function_definition(*candidate, source).is_some()
    }) {
        // Consecutive recovered classes already have an exact sibling-class
        // boundary. Preserve that established path, including nested export
        // classes, instead of interpreting the first class close as a
        // collapsed namespace boundary.
        return None;
    }
    let mut namespace_items = Vec::new();
    let mut nested_fragment_end = 0;
    for current in siblings.into_iter().skip(trailing_index + 1) {
        if current.start_byte() >= nested_fragment_end && cpp_is_stray_close_brace(current, source)
        {
            return Some(DisplacedFragmentNamespaceBoundary {
                class_close,
                class_semicolon: trailing_semicolon,
                namespace_items,
            });
        }
        if current.start_byte() >= nested_fragment_end
            && let Some((_, _, fragmented)) = fragmented_plain_class_body(current, source)
        {
            nested_fragment_end = fragmented.class_range.end_byte;
        } else if current.start_byte() >= nested_fragment_end
            && recover_exported_class_function_definition(current, source).is_some()
            && let Some(body) = cpp_body_node(current)
            && let Some(fragmented) =
                fragmented_export_function_body_region(current, body, source, None)
        {
            nested_fragment_end = fragmented.class_range.end_byte;
        }
        namespace_items.push(current);
    }
    None
}

fn displaced_fragment_namespace_boundary<'tree>(
    declaration: Node<'tree>,
    body: Node<'tree>,
    source: &str,
) -> Option<DisplacedFragmentNamespaceBoundary<'tree>> {
    let boundary = displaced_fragment_namespace_geometry(declaration, source)?;
    let reparse_start = body.start_byte() + 1;
    let tree = cpp_reparse_region_items(source, reparse_start, boundary.class_close.start_byte())?;
    cpp_reparsed_members_are_indexable(tree.root_node(), source).then_some(boundary)
}

/// Recover the class/namespace brace geometry for a declaration whose class
/// close tree-sitter consumed as the enclosing namespace close. This proof is
/// independent of whether every member in the class body can be reparsed: the
/// ordinary-tree fallback can still re-own bounded sibling declarations when
/// an unknown macro makes the complete body reparse unsafe.
fn displaced_fragment_namespace_geometry<'tree>(
    declaration: Node<'tree>,
    source: &str,
) -> Option<DisplacedFragmentNamespaceBoundary<'tree>> {
    // A templated class's malformed function wrapper remains beneath the
    // template node even though its later members have escaped to the
    // enclosing declaration list. Lift only that exact declaration child.
    let envelope = declaration
        .parent()
        .filter(|parent| {
            parent.kind() == "template_declaration"
                && last_named_child(*parent).is_some_and(|child| same_node(child, declaration))
        })
        .unwrap_or(declaration);
    let declaration_list = envelope.parent()?;
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
    let mut namespace_items = Vec::new();
    let mut sibling = trailing_semicolon.next_named_sibling();
    let mut nested_fragment_end = 0;
    loop {
        let current = sibling?;
        if current.start_byte() >= nested_fragment_end && cpp_is_stray_close_brace(current, source)
        {
            break;
        }
        if current.start_byte() >= nested_fragment_end
            && let Some((_, _, fragmented)) = fragmented_plain_class_body(current, source)
        {
            nested_fragment_end = fragmented.class_range.end_byte;
        }
        namespace_items.push(current);
        sibling = current.next_named_sibling();
    }
    Some(DisplacedFragmentNamespaceBoundary {
        class_close,
        class_semicolon: trailing_semicolon,
        namespace_items,
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
            "template_function" | "template_type" if child.is_named() => {
                if name.is_some() {
                    return None;
                }
                let candidate = child
                    .child_by_field_name("name")
                    .and_then(|name| direct_identifier_name(name, source))?;
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
        "type_identifier" | "identifier" | "namespace_identifier" | "field_identifier" => {
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
        "identifier" | "type_identifier" | "namespace_identifier" | "field_identifier"
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

/// One declaration an attribute-like macro invocation swallowed into a
/// declaration-scope `ERROR`, with the byte range that spells it.
/// What [`stranded_declaration_run`] read out of one node.
struct StrandedRun<'tree> {
    declarations: Vec<MacroWrappedDeclaration<'tree>>,
    /// Whether every part of the node read as part of a declaration. False when
    /// a part the reader does not understand ended it early, or when the last
    /// parts were types with no declarator after them. Callers that index what
    /// was found keep the declarations either way; a caller deciding whether a
    /// whole region is safe to index requires this.
    complete: bool,
}

struct MacroWrappedDeclaration<'tree> {
    declarator: Node<'tree>,
    range: Range,
    /// Whether the recovered declaration spells `static`. The envelope hides
    /// that keyword from the ordinary linkage reader, which looks for it among
    /// a declaration node's own children, and internal linkage is what decides
    /// whether a header declaration and a body in another file are one symbol.
    is_static: bool,
}

/// Whether `node` stands where declarations live: directly in the translation
/// unit, or in a `namespace` or `extern "C"` body.
fn is_declaration_scope_position(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    match parent.kind() {
        "translation_unit" => true,
        "declaration_list" => parent.parent().is_some_and(|grandparent| {
            matches!(
                grandparent.kind(),
                "namespace_definition" | "linkage_specification"
            )
        }),
        _ => false,
    }
}

/// Whether `node` is an `ERROR` the parser produced where declarations live.
fn is_declaration_scope_error(node: Node<'_>) -> bool {
    node.kind() == "ERROR" && is_declaration_scope_position(node)
}

/// Whether `node` can only be part of what precedes a declarator -- a type, a
/// specifier, or a word of the attribute macro's own text that the lexer left
/// as a bare identifier -- so a run of these followed by a declarator is one
/// declaration the parser failed to group.
fn is_recovered_declaration_type_part(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier"
            | "type_identifier"
            | "primitive_type"
            | "sized_type_specifier"
            | "struct_specifier"
            | "union_specifier"
            | "enum_specifier"
            | "type_qualifier"
            | "storage_class_specifier"
            | "explicit_function_specifier"
            | "virtual_function_specifier"
            | "qualified_identifier"
            | "template_type"
            | "dependent_type"
            | "placeholder_type_specifier"
    )
}

/// Whether `node` is the `ERROR` tree-sitter leaves for a macro argument that
/// is not a declaration -- the hint string of `DEPRECATED(decl, "hint")`, whose
/// words the lexer reports as bare identifiers. Anything else in such an
/// `ERROR` stops the recovery, so a macro argument that carries structure this
/// recovery does not understand is never guessed at.
fn is_macro_argument_error(node: Node<'_>) -> bool {
    if node.kind() != "ERROR" {
        return false;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor).all(|child| {
        matches!(
            child.kind(),
            "identifier" | "number_literal" | "char_literal" | "string_literal" | "comment"
        )
    })
}

/// The end of a recovered declaration: the declarator's end, extended across
/// the `;` the grammar left beside it inside the envelope.
///
/// The envelope's own end is the hard boundary. The parser hands the last
/// declaration's `;` to the sibling statement it recovered with, outside the
/// envelope, and a range that reached it would no longer lie inside one node --
/// which is how every reader (including the resolver's climb from a range to
/// the node that declares it) finds a recovered declaration again.
fn recovered_declaration_end(declarator: Node<'_>) -> usize {
    declarator
        .next_sibling()
        .filter(|sibling| sibling.kind() == ";" && !sibling.is_missing())
        .map_or_else(|| declarator.end_byte(), |semicolon| semicolon.end_byte())
}

/// The declarations `node` holds after an attribute-like macro cost the parser
/// their grouping, in source order.
///
/// The parser packs the parts into whichever slots it has left. In whisper's
/// `DEPRECATED(LLAMA_API T * f(a), "hint");` the wrapped declaration's `type`
/// field takes the export macro, the real return type and the *next*
/// declaration's declarator both end up inside one sibling `ERROR`, and the
/// `declarator` field takes whatever declaration the recovery reached last. In
/// Botan's `BOTAN_DEPRECATED("text") explicit Ctor(T);` the string's words
/// arrive as bare identifiers and the attributed member and the member after it
/// share one declarator node.
///
/// Both are the same failure, so both get the same reading: flatten the node's
/// parts -- splicing each nested `ERROR`'s own children in place, since an
/// `ERROR` here is only a grouping failure -- and read the flat run as what it
/// spells, a run of type-and-specifier tokens followed by a declarator, over
/// and over.
///
/// Fails closed. A part that is neither a declarator nor something that can
/// only precede one ends the recovery there, and the declarations before it are
/// kept.
fn stranded_declaration_run<'tree>(node: Node<'tree>, source: &str) -> StrandedRun<'tree> {
    let mut parts = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "ERROR" {
            let mut error_cursor = child.walk();
            parts.extend(child.named_children(&mut error_cursor));
        } else {
            parts.push(child);
        }
    }

    let mut declarations = Vec::new();
    let mut start = None;
    let mut is_static = false;
    let mut complete = true;
    for part in parts {
        if part.kind() == "comment" {
            continue;
        }
        if let Some(declarator) = extract_function_declarator(part) {
            let start_byte = start.take().unwrap_or_else(|| part.start_byte());
            declarations.push(MacroWrappedDeclaration {
                declarator,
                range: cpp_recovery_window(source, start_byte, recovered_declaration_end(part)),
                is_static,
            });
            is_static = false;
            continue;
        }
        if !is_recovered_declaration_type_part(part) {
            complete = false;
            break;
        }
        is_static |= part.kind() == "storage_class_specifier"
            && normalize_cpp_whitespace(node_text(part, source)) == "static";
        start.get_or_insert(part.start_byte());
    }
    StrandedRun {
        declarations,
        complete: complete && start.is_none(),
    }
}

/// The declarations an attribute-like macro invocation swallowed into a
/// declaration-scope `ERROR`, in source order.
///
/// whisper.cpp's bundled `llama.h` deprecates a function by wrapping the whole
/// declaration in a macro call:
///
/// ```text
/// DEPRECATED(LLAMA_API struct llama_context * llama_new_context_with_model(
///                  struct llama_model * model,
///           struct llama_context_params   params),
///         "use llama_init_from_model instead");
/// LLAMA_API int32_t llama_tokenize(const struct llama_vocab * vocab, ...);
/// ```
///
/// tree-sitter cannot know `DEPRECATED` is a macro, so it emits one `ERROR`
/// holding the macro name, the wrapped declaration as a
/// `parameter_declaration`, the hint string as another `ERROR`, and then every
/// following declaration as a further `parameter_declaration` until it
/// recovers. That is what removed `llama_tokenize` from the index and left the
/// seven-argument call in `talk-llama.cpp` with only that file's own
/// three-parameter `static` overload to choose from (#2552, and the
/// `LLAMA_API` half of #2551).
///
/// Every part of every swallowed declaration is still a real node; only their
/// grouping is lost. This rebuilds the grouping and reads the nodes.
fn macro_wrapped_declarations<'tree>(
    envelope: Node<'tree>,
    source: &str,
) -> Vec<MacroWrappedDeclaration<'tree>> {
    let mut declarations = Vec::new();
    if !is_declaration_scope_error(envelope) {
        return declarations;
    }
    let mut cursor = envelope.walk();
    let children = envelope.named_children(&mut cursor).collect::<Vec<_>>();
    let [macro_name, arguments @ ..] = children.as_slice() else {
        return declarations;
    };
    if macro_name.kind() != "identifier" {
        return declarations;
    }
    let mut wrapped_declaration_seen = false;
    for argument in arguments {
        match argument.kind() {
            "comment" => {}
            "parameter_declaration" => {
                let recovered = stranded_declaration_run(*argument, source).declarations;
                if recovered.is_empty() {
                    break;
                }
                wrapped_declaration_seen = true;
                declarations.extend(recovered);
            }
            // The hint string, and only that: an argument the recovery cannot
            // read as a declaration is admitted before the wrapped declaration
            // is found, so a macro whose first argument is not a declaration
            // recovers nothing.
            "ERROR" if wrapped_declaration_seen && is_macro_argument_error(*argument) => {}
            _ => break,
        }
    }
    declarations
}

/// What one macro invocation swallowed when it collapsed a whole run of
/// declarations into a single node.
struct CollapsedMacroDeclarationRun {
    /// The byte just past the `;` that closes the invocation, which is where
    /// the declarations it swallowed begin.
    invocation_end: usize,
}

/// The macro invocation at the head of `node` when it swallowed the
/// declarations written after it, or `None` when `node` is not that shape.
///
/// whisper.cpp's bundled `llama.h` writes
///
/// ```text
/// DEPRECATED(LLAMA_API struct llama_model * llama_load_model_from_file(
///                          const char * path_model,
///           struct llama_model_params   params),
///         "use llama_model_load_from_file instead");
/// ```
///
/// The wrapped declaration's own parameter list spans lines, and that alone is
/// enough -- no stack of such items, no `extern "C"` block -- for the parser to
/// read `DEPRECATED(` as a function declarator whose close it never finds. It
/// then consumes every declaration written after it: in the real header, 57 KB
/// from line 481 to line 1535, `llama_tokenize` included, which is the
/// `LLAMA_API` half of #2551. A `MACRO(decl, "hint");` whose wrapped
/// declaration fits on its line collapses nothing; the parser leaves the
/// declaration-scope `ERROR` that [`macro_wrapped_declarations`] reads.
///
/// The envelope is a `function_definition` when a brace block falls in the
/// swallowed tail -- the parser borrows it for the body the bogus definition
/// needs -- and an `ERROR` when none does. That says nothing about the
/// construct, so both are accepted. Neither is the shape
/// [`macro_wrapped_declarations`] reads, whose first named child is the bare
/// macro-name `identifier` with no declarator around it.
///
/// Fails closed. The first argument must be a declaration and the argument
/// after it must be the one the parser handed the invocation's own `)` and `;`,
/// so a macro call whose end this cannot name is left to the ordinary readers.
fn collapsed_macro_declaration_run(
    node: Node<'_>,
    source: &str,
) -> Option<CollapsedMacroDeclarationRun> {
    if !matches!(node.kind(), "function_definition" | "ERROR")
        || !is_declaration_scope_position(node)
    {
        return None;
    }
    let head = if node.kind() == "function_definition" {
        // A real definition names its return type here. The envelope has none:
        // the macro name took the declarator slot and nothing precedes it.
        if node.child_by_field_name("type").is_some() {
            return None;
        }
        node.child_by_field_name("declarator")?
    } else {
        node.named_child(0)?
    };
    let mut invocation = extract_function_declarator(head)?;
    if invocation.start_byte() != node.start_byte() {
        return None;
    }
    // Each declaration the invocation swallowed wraps another
    // `function_declarator` around the one before it, so the macro's own
    // invocation is the innermost.
    while let Some(inner) = invocation
        .child_by_field_name("declarator")
        .filter(|inner| inner.kind() == "function_declarator")
    {
        invocation = inner;
    }
    let name = invocation.child_by_field_name("declarator")?;
    if name.kind() != "identifier"
        || !cpp_export_macro_token(&normalize_cpp_whitespace(node_text(name, source)))
    {
        return None;
    }
    let arguments = invocation.child_by_field_name("parameters")?;
    let mut cursor = arguments.walk();
    let mut children = arguments
        .children(&mut cursor)
        .filter(|child| child.kind() != "comment");
    if children.next()?.kind() != "(" || children.next()?.kind() != "parameter_declaration" {
        return None;
    }
    // The argument after the wrapped declaration is where the parser put the
    // invocation's own `)` and `;`. Their adjacency inside that argument is
    // where the invocation ends; whatever follows them there, or after the
    // argument, is what the invocation swallowed. A `)` the lexer left inside
    // the hint text is not followed by a `;`, so the pair names the end and
    // nothing else does.
    let hint = children.find(|child| child.kind() != ",")?;
    if hint.kind() != "ERROR" {
        return None;
    }
    let mut hint_cursor = hint.walk();
    let parts = hint.children(&mut hint_cursor).collect::<Vec<_>>();
    let invocation_end = parts.windows(2).find_map(|pair| {
        let [close, semicolon] = pair else {
            return None;
        };
        (close.kind() == ")"
            && !close.is_missing()
            && semicolon.kind() == ";"
            && !semicolon.is_missing())
        .then(|| semicolon.end_byte())
    })?;
    // An invocation that ends where the node does swallowed nothing after it.
    (invocation_end < node.end_byte()).then_some(CollapsedMacroDeclarationRun { invocation_end })
}

/// `MACRO("text") <member-declaration>` as tree-sitter parses it inside an
/// ordinary class body, and the members it swallowed.
///
/// Botan deprecates members that way:
///
/// ```text
/// BOTAN_DEPRECATED("Use DL_Group::from_name") explicit DL_Group(std::string_view name);
/// DL_Group(std::span<const uint8_t> der, DL_Group_Format format);
/// ```
///
/// The parser reads the macro name as the member's type and its argument list
/// as a parenthesized declarator, which then swallows the attributed member
/// *and* the member written after it: a `field_declaration` whose `type` is a
/// lone `type_identifier` and whose `declarator` is a `parenthesized_declarator`
/// opening with an `ERROR` whose first part is a bare identifier -- the first
/// word of the string, which the lexer could not keep together.
///
/// The macro's spelling is not the criterion; that structural shape is. The
/// returned declarations are in source order, the first being the attributed
/// member and the rest the members the declarator swallowed after it.
fn string_attribute_macro_member_declarators<'tree>(
    field: Node<'tree>,
    source: &str,
) -> Option<Vec<MacroWrappedDeclaration<'tree>>> {
    if field.kind() != "field_declaration"
        || field
            .child_by_field_name("type")
            .is_none_or(|type_node| type_node.kind() != "type_identifier")
    {
        return None;
    }
    let declarator = field.child_by_field_name("declarator")?;
    if declarator.kind() != "parenthesized_declarator" {
        return None;
    }
    let opening = declarator.named_child(0)?;
    if opening.kind() != "ERROR"
        || opening
            .named_child(0)
            .is_none_or(|word| word.kind() != "identifier")
    {
        return None;
    }
    let declarations = stranded_declaration_run(declarator, source).declarations;
    (!declarations.is_empty()).then_some(declarations)
}

/// Whether `node` is the `MACRO("text")` invocation the region reparse of an
/// export-macro class body leaves in front of the members that macro decorated.
///
/// The reparse reads the class body as statements, so the attribute becomes a
/// call statement of its own -- with the `;` the grammar had to invent -- and
/// the members after it are stranded in the `ERROR` that follows.
fn is_string_attribute_macro_statement(node: Node<'_>) -> bool {
    let Some(call) = (node.kind() == "expression_statement")
        .then(|| node.named_child(0))
        .flatten()
        .filter(|child| child.kind() == "call_expression")
    else {
        return false;
    };
    call.child_by_field_name("function")
        .is_some_and(|function| function.kind() == "identifier")
        && call
            .child_by_field_name("arguments")
            .is_some_and(|arguments| {
                let mut cursor = arguments.walk();
                arguments.named_child_count() > 0
                    && arguments
                        .named_children(&mut cursor)
                        .all(|argument| argument.kind() == "string_literal")
            })
}

/// The start byte of the call the region reparse left where an access-labeled
/// constructor was written.
///
/// A constructor is a member only inside a class body. The export-macro class
/// recovery reparses the body as statements, so `Ctor(params);` becomes a call
/// statement and `Ctor(params) : m_a(a), m_b(b) {}` collapses into one
/// comma-expression under `private:`, with no declarator left in the tree. It
/// is still spelled in the source, though, starting at the one call under the
/// label whose callee is the class's own name. Botan's private six-parameter
/// `XMSS_Parameters` constructor is the witness (#2552). More than one such
/// call is an ambiguity this declines, and so is a reparse from that byte that
/// does not yield exactly one constructor declarator there.
fn cpp_access_label_constructor_call_start(
    node: Node<'_>,
    class_name: &str,
    source: &str,
) -> Option<usize> {
    if node.kind() != "labeled_statement" {
        return None;
    }
    let label = node.named_child(0)?;
    if label.kind() != "statement_identifier"
        || !matches!(
            node_text(label, source).trim(),
            "public" | "private" | "protected"
        )
    {
        return None;
    }
    let mut starts = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "call_expression"
            && current
                .child_by_field_name("function")
                .is_some_and(|function| {
                    function.kind() == "identifier"
                        && node_text(function, source).trim() == class_name
                })
        {
            starts.push(current.start_byte());
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    let [start] = starts.as_slice() else {
        return None;
    };
    Some(*start)
}

/// The `function_definition` that gives `declarator` a body, following only the
/// declarator chain, so a recovered callable knows whether it is a declaration
/// or a definition without anyone having to say.
fn cpp_declarator_function_definition<'tree>(
    declarator: Node<'tree>,
    ancestry: &ParentIndex<'tree>,
) -> Option<Node<'tree>> {
    let mut current = declarator;
    while let Some(parent) = ancestry.parent(current) {
        match parent.kind() {
            "function_definition" if parent.child_by_field_name("body").is_some() => {
                return Some(parent);
            }
            "pointer_declarator"
            | "reference_declarator"
            | "parenthesized_declarator"
            | "array_declarator" => current = parent,
            _ => return None,
        }
    }
    None
}

/// Whether `node` lies in the body of a `namespace_definition` the ordinary
/// declaration walk still reaches, so a recovery that runs ahead of that walk
/// would name what it finds without the namespace.
fn cpp_is_inside_namespace_body<'tree>(node: Node<'tree>, ancestry: &ParentIndex<'tree>) -> bool {
    let mut current = node;
    while let Some(parent) = ancestry.parent(current) {
        if parent.kind() == "namespace_definition"
            && parent.child_by_field_name("body") == Some(current)
        {
            return true;
        }
        current = parent;
    }
    false
}

/// Whether the source a recovered callable's byte range spells is a definition
/// (a declarator with a body) rather than a declaration.
///
/// A callable recovered from a mangled region owns no node of its own in the
/// file's tree, so the occurrence-role scan that climbs from the range to the
/// node containing it lands on whatever container the parser left and answers
/// for that instead -- which called Botan's inline `XMSS_Parameters` private
/// constructor a declaration and left its call site with nothing to navigate to
/// (#2552). Reparse the range on its own, the same offset-preserving reparse
/// extraction used, and read the answer from the one declaration it spells.
///
/// `None` when the range is not one recovered declaration on its own, which is
/// the case for every ordinary declaration, so callers keep their own answer.
pub fn recovered_callable_body_at(source: &str, range: &Range) -> Option<bool> {
    let tree = cpp_reparse_region_items(source, range.start_byte, range.end_byte)?;
    let root = tree.root_node();
    let mut cursor = root.walk();
    let items = root
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
        .collect::<Vec<_>>();
    let [item] = items.as_slice() else {
        return None;
    };
    if item.start_byte() != range.start_byte || item.end_byte() != range.end_byte {
        return None;
    }
    match item.kind() {
        "function_definition" => Some(item.child_by_field_name("body").is_some()),
        "declaration" | "field_declaration" => Some(false),
        _ => None,
    }
}

/// Whether `node` is an envelope an attribute-like macro invocation left where
/// declarations were written: the declaration-scope `ERROR`
/// [`macro_wrapped_declarations`] reads, or the collapsed run
/// [`collapsed_macro_declaration_run`] reads.
///
/// Extraction and resolution must read one definition of this shape. The
/// resolver climbs from a declaration's recorded byte range to the node that
/// declares it, and a recovered declaration's range lies inside one of these
/// envelopes rather than inside a `declaration` node, so the climb stops here
/// (the same role `is_recovered_exported_class_container` plays for a recovered
/// class).
pub fn is_macro_wrapped_declaration_envelope(node: Node<'_>, source: &str) -> bool {
    !macro_wrapped_declarations(node, source).is_empty()
        || collapsed_macro_declaration_run(node, source).is_some()
}

fn recover_exported_class_function_definition<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, String, Option<Vec<String>>)> {
    if node.kind() != "function_definition" {
        return None;
    }
    if let Some(prefix) = node.prev_named_sibling()
        && let Some(recovered) = recover_function_like_export_class_pair(prefix, source)
        && recovered.range.end_byte == node.end_byte()
    {
        return Some((node, recovered.name, recovered.raw_supertypes));
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
            if let Some((name, base)) =
                recovered_function_like_export_class_owner(declarator, source)
            {
                return Some((node, name, Some(vec![base])));
            }
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

fn recovered_function_like_export_class_owner(
    declarator: Node<'_>,
    source: &str,
) -> Option<(String, String)> {
    if declarator.kind() != "parenthesized_declarator" {
        return None;
    }
    let mut cursor = declarator.walk();
    let children = declarator.named_children(&mut cursor).collect::<Vec<_>>();
    let [prefix, base] = children.as_slice() else {
        return None;
    };
    if prefix.kind() != "ERROR"
        || !matches!(
            base.kind(),
            "identifier" | "type_identifier" | "qualified_identifier" | "scoped_type_identifier"
        )
    {
        return None;
    }
    let mut identifiers = Vec::new();
    let mut prefix_cursor = prefix.walk();
    for child in prefix.named_children(&mut prefix_cursor) {
        match child.kind() {
            "number_literal" | "string_literal" | "char_literal" => {}
            "identifier" | "type_identifier" => {
                identifiers.push(normalize_cpp_whitespace(node_text(child, source)));
            }
            _ => return None,
        }
    }
    let name = match identifiers.as_slice() {
        [name] => name.clone(),
        [name, final_token] if final_token == "final" => name.clone(),
        _ => return None,
    };
    if name.is_empty() || cpp_export_macro_token(&name) {
        return None;
    }
    let base = recovered_malformed_base_name(*base, source)?;
    Some((name, base))
}

/// Collect the base names tree-sitter scattered across the recovered head of a
/// function-like export-macro class. `skip` names the structural children that
/// are not bases, such as the class name and the body. A base arrives either as
/// a direct sibling identifier or inside the `ERROR` node the grammar produced
/// for a `: public Base` fragment. The grammar leaves the `final` specifier and
/// the access specifiers in the same position as the bases, so drop them.
/// The bases a recovered function-like export-macro class head names between
/// `after` (the end of the class name, or of the access specifier that stands
/// in for it) and `before` (the start of the body, or of the `init_declarator`
/// that carries it). Bases arrive as bare declarator fields and inside `ERROR`
/// fragments, and one fragment can also hold the class name and `final`
/// (`M1 M2 Name final : public A`), so each part is bounded by position rather
/// than by the fragment that holds it.
fn recovered_export_head_bases(
    node: Node<'_>,
    after: usize,
    before: usize,
    source: &str,
) -> Vec<String> {
    let within = |part: &Node<'_>| part.start_byte() >= after && part.end_byte() <= before;
    let mut bases = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "ERROR" {
            let mut error_cursor = child.walk();
            bases.extend(
                child
                    .named_children(&mut error_cursor)
                    .filter(within)
                    .filter_map(|part| recovered_malformed_base_name(part, source)),
            );
        } else if within(&child)
            && let Some(base) = recovered_malformed_base_name(child, source)
        {
            bases.push(base);
        }
    }
    bases.retain(|base| !matches!(base.as_str(), "final" | "public" | "protected" | "private"));
    bases
}

/// Whether `token` is the `final` that closes a recovered class head. The
/// grammar keeps it as the `final` keyword when it recognised the head
/// (`M1 M2 Name final : public A`) and as an `identifier` spelled `final` when
/// it did not (`Name final {`, `OTHER_MACRO Name final : public A`).
fn recovered_export_head_final(token: Node<'_>, source: &str) -> bool {
    if token.is_named() {
        token.kind() == "identifier" && node_text(token, source) == "final"
    } else {
        token.kind() == "final"
    }
}

/// The class name of a recovered function-like export-macro class head, read by
/// position rather than spelling (#2557). `node` is the sibling tree-sitter
/// built from the head after `class MACRO(2, 0)`, and `tail` the child that
/// carries the body. The head's tokens, in source order with `ERROR` fragments
/// flattened, read `macros... name [final] [: bases...]`: the name is the last
/// identifier before the head ends, and the head ends at `final`, at the base
/// clause `:`, or at `tail`. Every identifier before the name is decoration
/// (`class MACRO(2, 0) OTHER_MACRO Name`), and a class named in capitals
/// (`X509_CA`) is a class name like any other.
///
/// A `MISSING` identifier is a zero-width node tree-sitter invented to close a
/// rule, not a token of the source, so it is never the name.
fn recovered_export_head_name<'tree>(
    node: Node<'tree>,
    tail: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let mut tokens = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.start_byte() >= tail.start_byte() {
            break;
        }
        if child.kind() == "ERROR" {
            let mut fragment_cursor = child.walk();
            tokens.extend(child.children(&mut fragment_cursor));
        } else {
            tokens.push(child);
        }
    }
    let mut name = None;
    for token in tokens {
        if recovered_export_head_final(token, source) || (!token.is_named() && token.kind() == ":")
        {
            break;
        }
        if token.is_named()
            && !token.is_missing()
            && matches!(
                token.kind(),
                "identifier" | "type_identifier" | "field_identifier"
            )
        {
            name = Some(token);
        }
    }
    name
}

/// The `init_declarator` whose `value` carries the class body when the grammar
/// keeps a function-like export-macro class head as one `declaration`.
fn recovered_export_init_declarator(declaration: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = declaration.walk();
    declaration
        .named_children(&mut cursor)
        .find(|child| child.kind() == "init_declarator")
}

/// Read the bases and the initializer-list body of a `declaration`-shaped tail
/// of a function-like export-macro class head. The grammar splits a base list
/// across bare declarator fields, `ERROR` fragments, and one trailing
/// `init_declarator` whose `value` is the class body. `head_end` is where the
/// class identity ends and the bases can begin: the end of the access specifier
/// when the class name went to a statement label, and the end of the class name
/// itself otherwise.
fn recovered_export_declaration_tail<'tree>(
    declaration: Node<'tree>,
    head_end: usize,
    source: &str,
) -> Option<(Vec<String>, Node<'tree>)> {
    let init = recovered_export_init_declarator(declaration)?;
    let body = init.child_by_field_name("value")?;
    if body.kind() != "initializer_list" {
        return None;
    }
    let mut bases = recovered_export_head_bases(declaration, head_end, init.start_byte(), source);
    bases.extend(recovered_export_head_bases(
        init,
        init.start_byte(),
        body.start_byte(),
        source,
    ));
    Some((bases, body))
}

fn recover_function_like_export_class_pair(
    node: Node<'_>,
    source: &str,
) -> Option<RecoveredFunctionLikeExportClassPair> {
    if node.kind() != "ERROR" {
        return None;
    }
    let class_node = first_class_like_child(node)?;
    if class_node.kind() != "class_specifier" || cpp_body_node(class_node).is_some() {
        return None;
    }
    // The identifier tree-sitter took for the class name is the export macro,
    // a function-like invocation when the `(` of its argument list follows it
    // directly inside the error. Spelling plays no part (#2557).
    class_node
        .child_by_field_name("name")
        .and_then(|name| direct_identifier_name(name, source))?;
    let invocation = class_node.next_sibling()?;
    if invocation.is_named() || invocation.kind() != "(" {
        return None;
    }
    let sibling = node.next_named_sibling()?;
    let (name, raw_supertypes, body) = match sibling.kind() {
        // At translation-unit scope tree-sitter can leave the malformed class
        // head in one ERROR node and parse its body as the adjacent compound
        // statement. The head still carries the export invocation, displaced
        // class name, and optional `final` token in source order, so recover
        // the name by the same positional rule as the other shapes.
        "compound_statement" => (
            recovered_export_head_name(node, sibling, source)
                .map(|name| normalize_cpp_whitespace(node_text(name, source)))?,
            None,
            sibling,
        ),
        "expression_statement" => {
            let compound = sibling.named_child(0)?;
            if compound.kind() != "compound_literal_expression" {
                return None;
            }
            let body = compound.child_by_field_name("value")?;
            if body.kind() != "initializer_list" {
                return None;
            }
            (
                compound
                    .child_by_field_name("type")
                    .and_then(|name| direct_identifier_name(name, source))?,
                None,
                body,
            )
        }
        "labeled_statement" => {
            let label = sibling.child_by_field_name("label")?;
            if label.kind() != "statement_identifier" {
                return None;
            }
            let name = normalize_cpp_whitespace(node_text(label, source));
            let declaration = sibling
                .named_children(&mut sibling.walk())
                .find(|child| child.kind() == "declaration")?;
            let access = declaration.child_by_field_name("type")?;
            if !matches!(
                node_text(access, source),
                "public" | "protected" | "private"
            ) {
                return None;
            }
            let (bases, body) =
                recovered_export_declaration_tail(declaration, access.end_byte(), source)?;
            (name, (!bases.is_empty()).then_some(bases), body)
        }
        // `class MACRO(2, 0) Name final { ... };`,
        // `class MACRO(2, 0) Name final : public Base { ... };`, and
        // `class MACRO(2, 0) OTHER_MACRO Name { ... };`. The head's identifiers
        // spread over the `type` field, the declarator field, and `ERROR`
        // fragments beside them; the name is the last one before the head ends.
        "function_definition" => {
            let body = sibling.child_by_field_name("body")?;
            if body.kind() != "compound_statement" {
                return None;
            }
            let name_node = recovered_export_head_name(sibling, body, source)?;
            let bases = recovered_export_head_bases(
                sibling,
                name_node.end_byte(),
                body.start_byte(),
                source,
            );
            (
                normalize_cpp_whitespace(node_text(name_node, source)),
                (!bases.is_empty()).then_some(bases),
                body,
            )
        }
        // `class MACRO(2, 0) Name final : public A, public B { ... };`. The
        // comma-separated base list makes the grammar keep the whole tail as one
        // declaration whose trailing `init_declarator` carries the body.
        "declaration" => {
            let init = recovered_export_init_declarator(sibling)?;
            let name_node = recovered_export_head_name(sibling, init, source)?;
            let (bases, body) =
                recovered_export_declaration_tail(sibling, name_node.end_byte(), source)?;
            (
                normalize_cpp_whitespace(node_text(name_node, source)),
                (!bases.is_empty()).then_some(bases),
                body,
            )
        }
        _ => return None,
    };
    debug_assert!(
        !name.is_empty(),
        "a recovered class head names its class by an identifier token"
    );
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: sibling.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: sibling.end_position().row + 1,
    };
    Some(RecoveredFunctionLikeExportClassPair {
        name,
        raw_supertypes,
        range,
        fragmented_body: recovered_fragmented_export_body(body, range)?,
    })
}

/// Recover a function-like export-macro class that tree-sitter embedded in a
/// larger error after an earlier malformed class body. The grammar still
/// preserves every part of the class head: the `class` token, export macro
/// identifier and argument list, displaced class identifier, access specifier,
/// base field, and initializer-list-shaped body. Match only that complete
/// structured sequence and keep each recovered class's exact byte envelope.
fn recover_embedded_function_like_export_classes(
    node: Node<'_>,
    source: &str,
) -> Vec<RecoveredEmbeddedFunctionLikeExportClass> {
    if node.kind() != "ERROR" {
        return Vec::new();
    }

    let mut nodes = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        nodes.push(current);
        for index in (0..current.child_count()).rev() {
            stack.push(
                current
                    .child(index)
                    .expect("index below the node's own child count"),
            );
        }
    }
    nodes.sort_unstable_by_key(|child| (child.start_byte(), child.end_byte()));

    let mut recovered = Vec::new();
    for class_token in nodes
        .iter()
        .copied()
        .filter(|child| !child.is_named() && child.kind() == "class")
    {
        let row = class_token.start_position().row;
        // The head after the `class` token reads `MACRO(args) macros... name
        // [final] : bases`. The macro is the first identifier, a function-like
        // invocation when its argument list is the next thing after it, and the
        // name is the last identifier before the head ends at `final` or at the
        // base clause `:`. Spelling plays no part (#2557).
        let is_identifier = |candidate: &Node<'_>| {
            !candidate.is_missing()
                && matches!(
                    candidate.kind(),
                    "identifier" | "type_identifier" | "field_identifier"
                )
        };
        let Some(macro_name) = nodes.iter().copied().find(|candidate| {
            candidate.start_byte() >= class_token.end_byte()
                && candidate.start_position().row == row
                && is_identifier(candidate)
        }) else {
            continue;
        };
        let Some(arguments) = nodes.iter().copied().find(|candidate| {
            candidate.kind() == "argument_list"
                && candidate.start_byte() >= macro_name.end_byte()
                && candidate.start_position().row == row
        }) else {
            continue;
        };
        if nodes.iter().any(|candidate| {
            is_identifier(candidate)
                && candidate.start_byte() >= macro_name.end_byte()
                && candidate.end_byte() <= arguments.start_byte()
        }) {
            continue;
        }
        let Some(head_end) = nodes.iter().copied().find(|candidate| {
            candidate.start_byte() >= arguments.end_byte()
                && (recovered_export_head_final(*candidate, source)
                    || (!candidate.is_named() && candidate.kind() == ":"))
        }) else {
            continue;
        };
        let Some(name_node) = nodes.iter().copied().rfind(|candidate| {
            is_identifier(candidate)
                && candidate.start_byte() >= arguments.end_byte()
                && candidate.end_byte() <= head_end.start_byte()
                && candidate.start_position().row == row
        }) else {
            continue;
        };
        let name = normalize_cpp_whitespace(node_text(name_node, source));
        let Some(base_initializer) = nodes.iter().copied().find(|candidate| {
            candidate.kind() == "field_initializer"
                && candidate.start_byte() >= name_node.end_byte()
                && candidate
                    .child_by_field_name("field")
                    .or_else(|| candidate.named_child(0))
                    .is_some()
                && candidate
                    .child_by_field_name("value")
                    .or_else(|| {
                        let mut cursor = candidate.walk();
                        candidate
                            .named_children(&mut cursor)
                            .find(|child| child.kind() == "initializer_list")
                    })
                    .is_some_and(|value| value.kind() == "initializer_list")
        }) else {
            continue;
        };
        let has_access = nodes.iter().copied().any(|candidate| {
            candidate.start_byte() >= name_node.end_byte()
                && candidate.end_byte() <= base_initializer.start_byte()
                && matches!(
                    normalize_cpp_whitespace(node_text(candidate, source)).as_str(),
                    "public" | "protected" | "private"
                )
        });
        if !has_access {
            continue;
        }
        let Some(base_node) = base_initializer
            .child_by_field_name("field")
            .or_else(|| base_initializer.named_child(0))
        else {
            continue;
        };
        let Some(base) = recovered_malformed_base_name(base_node, source) else {
            continue;
        };
        let body = base_initializer
            .child_by_field_name("value")
            .or_else(|| {
                let mut cursor = base_initializer.walk();
                base_initializer
                    .named_children(&mut cursor)
                    .find(|child| child.kind() == "initializer_list")
            })
            .expect("initializer-list value checked above");
        let range = Range {
            start_byte: class_token.start_byte(),
            end_byte: body.end_byte(),
            start_line: class_token.start_position().row + 1,
            end_line: body.end_position().row + 1,
        };
        if recovered
            .iter()
            .any(|existing: &RecoveredEmbeddedFunctionLikeExportClass| {
                existing.name == name && existing.range == range
            })
        {
            continue;
        }
        recovered.push(RecoveredEmbeddedFunctionLikeExportClass {
            name,
            range,
            raw_supertypes: vec![base],
            fragmented_body: match recovered_fragmented_export_body(body, range) {
                Some(fragmented) => fragmented,
                None => continue,
            },
        });
    }
    recovered
}

fn lifted_function_like_export_class_namespace<'tree>(
    node: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> Option<String> {
    // A long malformed body can embed the next exported class several levels
    // below a bogus top-level function_definition. Compare namespace evidence
    // against that top-level envelope, not only the recovered ERROR's direct
    // parent. The source tree still proves the same boundary: one earlier
    // malformed namespace and one later standalone closing brace.
    let mut anchor = node;
    let parent = loop {
        let parent = ancestry.parent(anchor)?;
        if parent.kind() == "translation_unit" || parent.kind().starts_with("preproc_") {
            break parent;
        }
        anchor = parent;
    };
    let has_later_close = parent.named_children(&mut parent.walk()).any(|sibling| {
        sibling.start_byte() > anchor.end_byte()
            && sibling.kind() == "ERROR"
            && sibling.named_child_count() == 0
            && normalize_cpp_whitespace(node_text(sibling, source)) == "}"
    });
    if !has_later_close {
        return None;
    }
    let candidates = parent
        .named_children(&mut parent.walk())
        .filter(|sibling| {
            sibling.kind() == "namespace_definition"
                && sibling.has_error()
                && sibling.end_byte() < anchor.start_byte()
        })
        .filter_map(|namespace| {
            namespace
                .child_by_field_name("name")
                .map(|name| normalize_cpp_whitespace(node_text(name, source)))
                .filter(|name| !name.is_empty() && !cpp_export_macro_token(name))
        })
        .collect::<Vec<_>>();
    let [namespace] = candidates.as_slice() else {
        return None;
    };
    Some(namespace.clone())
}

pub(crate) fn recovered_function_like_export_class_pair_has_body(
    node: Node<'_>,
    source: &str,
    identifier: &str,
    range: &Range,
) -> bool {
    recover_function_like_export_class_pair(node, source).is_some_and(|recovered| {
        recovered.name == identifier
            && recovered.range.start_byte == range.start_byte
            && recovered.range.end_byte == range.end_byte
    })
}

/// One file's embedded export-macro class recovery, resolved once and keyed by
/// the `ERROR` node that mints each set.
///
/// [`recover_embedded_function_like_export_classes`] collects and sorts an
/// `ERROR` node's whole subtree, and the declaration-strength question asks it
/// once per class-like unit in the file. On a translation unit the parser could
/// not recover -- Catch2's 449 KB `extras/catch_amalgamated.cpp`, whose `ERROR`
/// node spans most of the file -- that is one full subtree pass per class,
/// quadratic in the file's size, and it was 78% of that file's inverse scan
/// (#1496).
///
/// Keyed by byte span rather than node identity, so one analyzer generation's
/// re-parses of the same content share the index. A nested `ERROR` that shares
/// its parent's span recovers the same classes: the only node the parent adds
/// is the `ERROR` itself, and no part of a recovered class is an `ERROR`.
#[derive(Default)]
pub struct CppRecoveredExportClassIndex {
    by_error_node: HashMap<(usize, usize), Vec<RecoveredEmbeddedFunctionLikeExportClass>>,
}

impl CppRecoveredExportClassIndex {
    pub fn build(root: Node<'_>, source: &str) -> Self {
        let mut by_error_node: HashMap<
            (usize, usize),
            Vec<RecoveredEmbeddedFunctionLikeExportClass>,
        > = HashMap::default();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "ERROR" {
                let recovered = recover_embedded_function_like_export_classes(node, source);
                if !recovered.is_empty() {
                    by_error_node.insert((node.start_byte(), node.end_byte()), recovered);
                }
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        Self { by_error_node }
    }

    /// The bytes this index holds, for the analyzer cache's weight.
    pub fn approximate_size(&self) -> usize {
        self.by_error_node
            .values()
            .fold(0usize, |total, recovered| {
                recovered.iter().fold(
                    total.saturating_add(std::mem::size_of::<(usize, usize)>()),
                    |acc, class| {
                        acc.saturating_add(std::mem::size_of::<
                            RecoveredEmbeddedFunctionLikeExportClass,
                        >())
                        .saturating_add(class.name.len())
                        .saturating_add(class.raw_supertypes.iter().map(String::len).sum::<usize>())
                    },
                )
            })
    }

    fn claims(&self, node: Node<'_>, identifier: &str, range: &Range) -> bool {
        self.by_error_node
            .get(&(node.start_byte(), node.end_byte()))
            .is_some_and(|recovered| {
                recovered.iter().any(|class| {
                    class.name == identifier
                        && class.range.start_byte == range.start_byte
                        && class.range.end_byte == range.end_byte
                })
            })
    }
}

// #1496: `recovered_class_body_node_visits_for_test` counts every AST node
// `recovered_class_body_at` pops while deciding whether a recovered class shape
// claims one declaration range. The count is deterministic for a given source,
// so `recovered_class_body_lookup_cost_does_not_grow_with_the_rest_of_the_file`
// pins it directly instead of timing the walk, the way #2358 pinned the
// `remove_code_unit` scan.
#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static RECOVERED_CLASS_BODY_NODE_VISITS_FOR_TEST: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// Test-only count of the AST nodes [`recovered_class_body_at`] has visited on
/// the calling thread since the last
/// [`reset_recovered_class_body_node_visits_for_test`]. See #1496.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn recovered_class_body_node_visits_for_test() -> usize {
    RECOVERED_CLASS_BODY_NODE_VISITS_FOR_TEST.with(std::cell::Cell::get)
}

/// Resets the counter read by [`recovered_class_body_node_visits_for_test`].
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn reset_recovered_class_body_node_visits_for_test() {
    RECOVERED_CLASS_BODY_NODE_VISITS_FOR_TEST.with(|cell| cell.set(0));
}

#[cfg(any(test, feature = "test-support"))]
fn record_recovered_class_body_visit() {
    RECOVERED_CLASS_BODY_NODE_VISITS_FOR_TEST.with(|cell| cell.set(cell.get() + 1));
}

#[cfg(not(any(test, feature = "test-support")))]
fn record_recovered_class_body_visit() {}

/// Whether a recovered class shape named `identifier` owns `range`, and if so
/// whether that shape has a body.
///
/// `Some(true)` is a complete recovered definition, `Some(false)` a recovered
/// forward declaration, and `None` means no recovered shape claims the range,
/// so the caller reads the plain `class_specifier` family instead. This is the
/// single definition of "does a recovered class have a body": the resolver's
/// declaration-strength answer and the navigation occurrence role both read it,
/// so an export-macro class is a definition on both paths.
///
/// The walk follows only the nodes whose span covers `range.start_byte`, which
/// is every node that can answer. Each recovered shape reports a range that
/// starts at the node's own start byte (the function-like export pair, whose
/// range is `node.start_byte()..sibling.end_byte()`, and the fragmented plain
/// class, which the caller gates on an equal start) or at a token inside the
/// node (the embedded export class, keyed on its `class` token, and the
/// exported class wrapper, gated on containment here), and every one of them is
/// accepted only on an exact match with `range`. Descending everywhere instead
/// made one declaration-strength question cost a full pass over the file, so
/// asking it once per reference was quadratic in file size: 80% of the 385 s
/// inverse scan of Catch2's 449 KB `extras/catch_amalgamated.cpp` was this walk
/// (#1496).
pub(crate) fn recovered_class_body_at(
    recovered_export_classes: &CppRecoveredExportClassIndex,
    root: Node<'_>,
    source: &str,
    identifier: &str,
    range: &Range,
) -> Option<bool> {
    let covers_range_start = |node: &Node<'_>| {
        node.start_byte() <= range.start_byte
            && (range.start_byte < node.end_byte() || node.start_byte() == range.start_byte)
    };
    let mut stack = vec![root];
    let mut saw_forward = false;
    while let Some(node) = stack.pop() {
        record_recovered_class_body_visit();
        // The pair's recovered range is `node.start_byte()..sibling.end_byte()`,
        // so an unequal start settles it before the recovery reads the node's
        // children at all.
        if (node.start_byte() == range.start_byte
            && recovered_function_like_export_class_pair_has_body(node, source, identifier, range))
            || recovered_export_classes.claims(node, identifier, range)
            || (node.start_byte() == range.start_byte
                && recovered_fragmented_plain_class_has_body(node, source, identifier, range))
        {
            return Some(true);
        }
        // Macro-decorated exported classes are recovered from a malformed
        // function_definition/declaration wrapper. Their indexed class range starts at
        // the displaced class name, while the wrapper starts at `class EXPORT`; recovery
        // may also extend the indexed range beyond the wrapper through trailing class
        // fragments. Match the structured container that owns the range start by its
        // recovered name instead of requiring identical boundaries.
        if node.start_byte() <= range.start_byte
            && range.start_byte < node.end_byte()
            && let Some(has_body) = recovered_exported_class_has_body(node, source, identifier)
        {
            if has_body {
                return Some(true);
            }
            saw_forward = true;
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor).filter(covers_range_start));
    }
    saw_forward.then_some(false)
}

/// Whether `node` is the base type displaced into the declarator field of an
/// export-macro class that tree-sitter represented as a declaration or
/// function definition.
///
/// Declaration extraction already recovers this exact malformed envelope as a
/// class and records the declarator as its base. Reference extraction must use
/// the same structural fact instead of treating the node as a function name.
pub fn is_recovered_exported_class_base_type_node(node: Node<'_>, source: &str) -> bool {
    if !matches!(
        node.kind(),
        "qualified_identifier" | "scoped_type_identifier" | "template_type"
    ) {
        return false;
    }
    if let Some(function) = node.parent().filter(|parent| {
        parent.kind() == "function_definition"
            && parent
                .child_by_field_name("declarator")
                .is_some_and(|declarator| same_node(declarator, node))
    }) {
        return recover_exported_class_function_definition(function, source)
            .is_some_and(|(_, _, raw_supertypes)| raw_supertypes.is_some());
    }
    let Some(initializer) = node.parent().filter(|parent| {
        parent.kind() == "init_declarator"
            && parent
                .child_by_field_name("declarator")
                .is_some_and(|declarator| same_node(declarator, node))
    }) else {
        return false;
    };
    initializer
        .parent()
        .filter(|parent| parent.kind() == "declaration")
        .and_then(|declaration| recover_exported_class_declaration(declaration, source))
        .is_some_and(|recovered| recovered.raw_supertypes.is_some())
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
    ancestry: &ParentIndex<'tree>,
) -> Option<CppSentinelReparsedClass<'tree>> {
    let container = template_node.unwrap_or(root);
    let mut cursor = container.walk();
    for child in container.named_children(&mut cursor) {
        if matches!(
            child.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) {
            let name = class_like_name(child, source, ancestry)?;
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
            let name = class_like_name(class_node, source, ancestry)?;
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
            && let Some(name) = class_like_name(class_node, source, ancestry)
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
    push_cpp_sibling_range(node, 0, usize::MAX, scope, stack);
}

/// Materialize one selected named-child range with a tree-sitter cursor. The
/// cursor advances linearly across the parent's concrete children; repeatedly
/// asking for `named_child(index)` is quadratic on very wide generated nodes.
fn push_cpp_sibling_range<'tree>(
    parent: Node<'tree>,
    start_index: usize,
    end_index: usize,
    scope: ScopeInfo,
    stack: &mut Vec<CppWork<'tree>>,
) {
    let mut cursor = parent.walk();
    let children = parent
        .named_children(&mut cursor)
        .skip(start_index)
        .take(end_index.saturating_sub(start_index))
        .collect::<Vec<_>>()
        .into_iter();
    stack.push(CppWork::Siblings(CppSiblingsWork { children, scope }));
}

/// Advance a `Siblings` cursor by one child: dispatch the current child under
/// the scope accumulated from its *earlier* siblings, then push a
/// continuation for the remaining siblings carrying the scope updated for
/// *this* child (only `using namespace X;` directives change it). Pushing the
/// continuation before the current child's own node work means the current
/// child's subtree fully drains (LIFO) before the next sibling is visited,
/// preserving left-to-right order.
fn advance_cpp_siblings<'tree>(
    mut siblings: CppSiblingsWork<'tree>,
    source: &str,
    stack: &mut Vec<CppWork<'tree>>,
) {
    let Some(child) = siblings.children.next() else {
        return;
    };
    let current_scope = siblings.scope.clone();
    if let Some(namespace) = cpp_using_namespace_target(child, source) {
        siblings.scope.visible_using_namespaces.push(namespace);
    }
    if !siblings.children.as_slice().is_empty() {
        stack.push(CppWork::Siblings(siblings));
    }
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
    // A leading `::` is the explicit-global marker, not part of the namespace
    // path (`using namespace ::std::chrono;`). Drop that AST token before
    // reading the target text, the same boundary `cpp_raw_namespace_name_components`
    // keeps: storing the marker verbatim desynced the legacy package string from
    // the FqName bridge, which splits on `::` and drops the empty leading
    // component, tripping the package/short boundary assert when a bare-owner
    // out-of-line definition borrowed the directive's namespace (#1093 path).
    let start = target
        .child(0)
        .filter(|child| !child.is_named() && child.kind() == "::")
        .map_or(target.start_byte(), |marker| marker.end_byte());
    let text = normalize_cpp_whitespace(
        source
            .get(start..target.end_byte())
            .expect("using-directive target covers one source range"),
    );
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
    /// Whether this translation unit is compiled as C -- the `CppC` dialect of
    /// `LanguageDialect`, i.e. an exact lowercase `.c` extension.
    ///
    /// C has no nested tag scope: a struct/union/enum tag declared inside
    /// another aggregate's member list has the scope of the outer declaration
    /// itself (C17 6.2.1, 6.7.2.3). `struct outer { struct inner { int v; } i; };`
    /// therefore declares a file-scope `inner` that a later file-scope
    /// `struct inner *p;` legitimately references, where C++ would make the
    /// same shape a nested class `outer::inner`. Headers carry no compilation
    /// language of their own and keep the conservative C++ interpretation.
    pub c_tag_semantics: bool,
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
    /// The namespaces tree-sitter's error recovery closed early, by the byte
    /// regions of the declarations it left outside them (issue #1537). The
    /// container walk reads a declaration's package from its parsed ancestors,
    /// which for those declarations stop short; see
    /// [`CppVisitor::recovered_namespace_scope`].
    pub orphaned_namespaces: OrphanedNamespaceScopeIndex,
    /// The namespace forward declarations already folded out of each tree this
    /// walk has asked [`CppVisitor::unique_earlier_namespace_forward`] about.
    /// Empty until the first question, which the overwhelming majority of files
    /// never ask.
    pub namespace_forward_scans: HashMap<CppTreeIdentity, CppNamespaceForwardScan>,
    /// Which owners already have field declarations in the parse product, as
    /// [`CppVisitor::has_enum_enumerator_units`] needs to know. `None` until
    /// the first enum asks, which most files never do (#2786).
    pub field_owners: Option<CppFieldOwnerIndex>,
    /// What each open [`CppVisitor::record_recovered_declarations`] has watched
    /// happen to the declaration set, innermost last. Empty outside a recovery
    /// reparse, which is almost always (#2787).
    pub recovery_captures: Vec<CppRecoveryCapture>,
}

impl<'a> CppVisitor<'a> {
    /// Records `code_unit` with the answers the walk carries forward, then adds
    /// it to the parse product.
    ///
    /// Every declaration this walk publishes goes through this family, so the
    /// carried-forward answers see each one exactly once: the field ownership
    /// index behind [`Self::has_enum_enumerator_units`] (#2786) and the minted
    /// set every open [`Self::record_recovered_declarations`] reports (#2787).
    fn add_declaration(
        &mut self,
        code_unit: CodeUnit,
        node: Node<'_>,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        self.note_declaration(&code_unit);
        let source = self.source;
        self.parsed
            .add_code_unit(code_unit, node, source, parent, top_level);
    }

    /// Range-based form of [`Self::add_declaration`].
    fn add_declaration_with_range(
        &mut self,
        code_unit: CodeUnit,
        range: Range,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        self.note_declaration(&code_unit);
        self.parsed
            .add_code_unit_with_range(code_unit, range, parent, top_level);
    }

    /// Deferred-replacement form of [`Self::add_declaration`].
    fn replace_declaration_deferred(
        &mut self,
        code_unit: CodeUnit,
        node: Node<'_>,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        self.note_replaced_declaration(&code_unit);
        let source = self.source;
        self.parsed
            .replace_code_unit_deferred(code_unit, node, source, parent, top_level);
    }

    /// Range-based form of [`Self::replace_declaration_deferred`].
    fn replace_declaration_with_range_deferred(
        &mut self,
        code_unit: CodeUnit,
        range: Range,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        self.note_replaced_declaration(&code_unit);
        self.parsed
            .replace_code_unit_with_range_deferred(code_unit, range, parent, top_level);
    }

    /// Notes one declaration about to enter the parse product.
    ///
    /// A declaration the product already holds is not a creation, so an open
    /// recovery capture ignores it -- which is the membership test the set
    /// difference it replaces performed. A creation inside a nested recovery
    /// belongs to the recoveries around it too, so every open capture takes it.
    fn note_declaration(&mut self, code_unit: &CodeUnit) {
        if !self.recovery_captures.is_empty() && !self.parsed.contains_declaration(code_unit) {
            for capture in &mut self.recovery_captures {
                if capture.removed_pre_existing.contains(code_unit) {
                    continue;
                }
                if capture.created_units.insert(code_unit.clone()) {
                    capture.created.push(code_unit.clone());
                }
            }
        }
        if let Some(field_owners) = self.field_owners.as_mut() {
            field_owners.record(code_unit, self.file);
        }
    }

    /// Notes one declaration about to replace an existing one.
    ///
    /// A deferred replacement of a declaration that already owns children
    /// removes those children (`ParsedFile::prepare_deferred_replacement`), and
    /// a removal is the one thing the field index cannot absorb by addition.
    /// Drop it; the next question rebuilds it from the declarations that
    /// survive. A replacement of a unit with no children, and a "replacement"
    /// of a unit that is not there at all, remove nothing.
    fn note_replaced_declaration(&mut self, code_unit: &CodeUnit) {
        let removes_children = self.parsed.contains_declaration(code_unit)
            && self
                .parsed
                .children
                .get(code_unit)
                .is_some_and(|children| !children.is_empty());
        if removes_children {
            if !self.recovery_captures.is_empty() {
                let removed = self.declarations_a_replacement_removes(code_unit);
                for capture in &mut self.recovery_captures {
                    for unit in &removed {
                        // A declaration this capture watched being created is
                        // its own; one it did not is a declaration that was
                        // already there when the capture opened, so creating it
                        // again is a restoration and not a mint.
                        if !capture.created_units.contains(unit) {
                            capture.removed_pre_existing.insert(unit.clone());
                        }
                    }
                }
            }
            self.field_owners = None;
        }
        self.note_declaration(code_unit);
    }

    /// The declarations `ParsedFile::prepare_deferred_replacement` will remove
    /// when `code_unit` is replaced: its children, transitively.
    fn declarations_a_replacement_removes(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        let mut removed = Vec::new();
        let mut seen = HashSet::default();
        let mut pending: Vec<CodeUnit> = self
            .parsed
            .children
            .get(code_unit)
            .cloned()
            .unwrap_or_default();
        while let Some(unit) = pending.pop() {
            if !seen.insert(unit.clone()) {
                continue;
            }
            if let Some(children) = self.parsed.children.get(&unit) {
                pending.extend(children.iter().cloned());
            }
            removed.push(unit);
        }
        removed
    }

    fn visit_function_like_export_class_pair<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
        ancestry: &ParentIndex<'tree>,
    ) -> bool {
        let Some(recovered) = recover_function_like_export_class_pair(node, self.source) else {
            return false;
        };
        let member_outcome = self
            .reparse_fragmented_export_class_members(&recovered.fragmented_body, &recovered.name);
        // A malformed class body can escape into several following siblings
        // before the next export-macro class head appears. Inspect siblings in
        // order and stop at the first envelope that contains such a head. One
        // envelope can contain several following classes, all recovered in a
        // single bounded traversal.
        let mut displaced = node.next_named_sibling();
        while let Some(candidate) = displaced {
            if self.visit_embedded_function_like_export_classes(candidate, scope, stack, ancestry) {
                break;
            }
            displaced = candidate.next_named_sibling();
        }
        let class_unit = self.visit_named_class_like_shape(
            node,
            recovered.name,
            // The adjacent initializer_list proves the class body envelope,
            // but its children are expression-shaped rather than declaration-
            // preserving. Index the class identity here; callable definitions
            // remain available from their ordinary out-of-line declarations.
            None,
            true,
            Some(recovered.range),
            recovered.raw_supertypes,
            scope,
            stack,
            ancestry,
        );
        self.parsed
            .record_materialization(MaterializationRecord::RecoveredDeclaration {
                recovery: recovered.range,
                unit: class_unit.clone(),
            });
        if let Some(FragmentedExportMembers::Complete(tree)) = member_outcome.as_ref()
            && let Some((range, body)) = cpp_reparsed_merged_inline_constructor(
                tree.root_node(),
                class_unit.identifier(),
                self.source,
            )
        {
            self.visit_recovered_fragment_constructor(
                range,
                body,
                node,
                &class_unit,
                scope,
                ancestry,
            );
        }
        if let Some(outcome) = member_outcome {
            self.visit_fragmented_export_class_members(outcome, class_unit, scope);
        }
        self.consumed_fragment_regions
            .push((node.start_byte(), recovered.range.end_byte));
        true
    }

    fn visit_embedded_function_like_export_classes<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
        ancestry: &ParentIndex<'tree>,
    ) -> bool {
        let recovered_classes = recover_embedded_function_like_export_classes(node, self.source);
        let found = !recovered_classes.is_empty();
        for recovered in recovered_classes {
            let member_outcome = self.reparse_fragmented_export_class_members(
                &recovered.fragmented_body,
                &recovered.name,
            );
            let class_unit = self.visit_named_class_like_shape(
                node,
                recovered.name,
                None,
                true,
                Some(recovered.range),
                Some(recovered.raw_supertypes),
                scope,
                stack,
                ancestry,
            );
            self.parsed
                .record_materialization(MaterializationRecord::RecoveredDeclaration {
                    recovery: recovered.range,
                    unit: class_unit.clone(),
                });
            if let Some(FragmentedExportMembers::Complete(tree)) = member_outcome.as_ref()
                && let Some((range, body)) = cpp_reparsed_merged_inline_constructor(
                    tree.root_node(),
                    class_unit.identifier(),
                    self.source,
                )
            {
                self.visit_recovered_fragment_constructor(
                    range,
                    body,
                    node,
                    &class_unit,
                    scope,
                    ancestry,
                );
            }
            if let Some(outcome) = member_outcome {
                self.visit_fragmented_export_class_members(outcome, class_unit, scope);
            }
        }
        found
    }

    /// Walk `node`'s container, answering every ancestor question from
    /// `ancestry`.
    ///
    /// `ancestry` must index the tree `node` belongs to. The caller owns it
    /// because one tree can be walked more than once -- a header's C and C++
    /// readings are the same tree under different tag semantics -- and the
    /// parent relation is a property of the tree, not of the reading.
    #[allow(clippy::too_many_arguments)]
    pub fn visit_container<'tree>(
        &mut self,
        node: Node<'tree>,
        ancestry: &ParentIndex<'tree>,
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
        self.run_container_work(node, scope, ancestry);
    }

    /// Whether a work node lies entirely inside a byte region consumed by a
    /// fragmented export-class recovery (#938); such nodes were already indexed
    /// as members of the recovered class by the region reparse.
    fn node_is_inside_consumed_fragment(&self, node: Node<'_>) -> bool {
        self.byte_range_is_inside_consumed_fragment(node.start_byte(), node.end_byte())
    }

    /// Byte-range form of [`Self::node_is_inside_consumed_fragment`], for a
    /// candidate a recovery is about to reparse but has not yet turned into a
    /// node -- e.g. a prototype-macro candidate (#2932) already claimed by a
    /// prior structured recovery.
    fn byte_range_is_inside_consumed_fragment(&self, start: usize, end: usize) -> bool {
        self.consumed_fragment_regions
            .iter()
            .any(|&(region_start, region_end)| start >= region_start && end <= region_end)
    }

    /// Drive the container work loop from an explicit seed scope to completion. The
    /// loop is self-contained so a locally-owned reparsed tree (issue #938/#941)
    /// stays alive for the whole traversal.
    ///
    /// Every ancestor question this walk asks is answered from `ancestry`, which
    /// must index the tree `node` belongs to. Asking tree-sitter itself costs the
    /// node's position in the tree, which made a generated header with thousands
    /// of top-level declarations quadratic (#2361). The index is the caller's
    /// because it outlives any one walk: the file's tree is walked twice when a
    /// header has both a C and a C++ reading, and a region reparse (#938/#941)
    /// builds its own index for its own tree.
    fn run_container_work<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: ScopeInfo,
        ancestry: &ParentIndex<'tree>,
    ) {
        self.drain_cpp_work(
            vec![CppWork::Container(CppContainer { node, scope })],
            ancestry,
        );
    }

    /// The work loop itself, from whatever seed the caller built.
    ///
    /// [`Self::run_container_work`] seeds it with a whole container. A recovery
    /// that must walk only part of a reparsed tree seeds it with the sibling
    /// range it may walk instead, which keeps the `using namespace X;` scope
    /// accumulation `advance_cpp_siblings` performs.
    fn drain_cpp_work<'tree>(
        &mut self,
        mut stack: Vec<CppWork<'tree>>,
        ancestry: &ParentIndex<'tree>,
    ) {
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
                    self.visit_node(work.node, &work.scope, &mut stack, ancestry);
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
            // The reparsed region is its own tree, so this drain walks it with
            // its own parent index.
            let reparsed_ancestry = ParentIndex::new(root);
            for constructor in constructors {
                let mut stack = Vec::new();
                self.visit_node(constructor, &member_scope, &mut stack, &reparsed_ancestry);
                while let Some(work) = stack.pop() {
                    match work {
                        CppWork::Container(container) => {
                            push_cpp_container_work(container.node, container.scope, &mut stack);
                        }
                        CppWork::Siblings(siblings) => {
                            advance_cpp_siblings(siblings, self.source, &mut stack);
                        }
                        CppWork::Node(work) => {
                            self.visit_node(work.node, &work.scope, &mut stack, &reparsed_ancestry)
                        }
                    }
                }
            }
            return false;
        }
        // The reparsed region is its own tree, so this walk indexes it itself.
        self.run_container_work(root, member_scope, &ParentIndex::new(root));
        true
    }

    fn visit_recovered_fragment_constructor<'tree>(
        &mut self,
        range: std::ops::Range<usize>,
        constructor_body: Node<'tree>,
        class_declaration: Node<'tree>,
        class_unit: &CodeUnit,
        scope: &ScopeInfo,
        ancestry: &ParentIndex<'tree>,
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
        self.add_declaration_with_range(
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
                ancestry,
            )
            .with_declaration_only(false)
            .with_callable_linkage(cpp_callable_linkage(
                class_declaration,
                self.source,
                ancestry,
            )),
        );
        self.parsed.add_child(class_unit.clone(), code_unit);
    }

    fn visit_recovered_fragment_prefix_members<'tree>(
        &mut self,
        root: Node<'tree>,
        constructor_start: usize,
        class_unit: &CodeUnit,
        scope: &ScopeInfo,
        ancestry: &ParentIndex<'tree>,
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
                self.visit_node(current, &member_scope, &mut work_stack, ancestry);
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
                            self.visit_node(work.node, &work.scope, &mut work_stack, ancestry)
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
        ancestry: &ParentIndex<'tree>,
    ) {
        if let Some(recovered_scope) = self.recovered_class_sibling_scopes.remove(&node.id()) {
            self.visit_node(node, &recovered_scope, stack, ancestry);
            return;
        }
        if let Some(recovered_scope) = self.recovered_namespace_scope(node, scope) {
            self.visit_node(node, &recovered_scope, stack, ancestry);
            return;
        }
        // Fragmented-class recovery below may consume a malformed function
        // envelope before the ordinary kind dispatch runs. Recover any
        // export-macro class embedded in that envelope first; the strict class
        // head/base/body predicate is independent of which later recovery owns
        // the surrounding parser fragment.
        if node.kind() == "function_definition" && node.has_error() {
            self.visit_embedded_function_like_export_classes(node, scope, stack, ancestry);
        }
        if let Some((class_node, name, fragmented)) = fragmented_plain_class_body(node, self.source)
        {
            let displaced_namespace_items =
                displaced_fragment_namespace_geometry(node, self.source)
                    .map(|boundary| boundary.namespace_items)
                    .unwrap_or_default();
            let outcome = self.reparse_fragmented_export_class_members(&fragmented, &name);
            let mut class_stack = Vec::new();
            // When the full body cannot be safely reparsed, the original class
            // node still proves ownership for its parser-visible prefix.
            let parser_visible_body =
                (!matches!(&outcome, Some(FragmentedExportMembers::Complete(_))))
                    .then(|| cpp_body_node(class_node))
                    .flatten();
            let class_unit = self.visit_named_class_like_shape(
                class_node,
                name,
                parser_visible_body,
                true,
                Some(fragmented.class_range),
                Some(extract_cpp_supertypes(class_node, self.source)),
                scope,
                &mut class_stack,
                ancestry,
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
                // Template wrappers put the escaped members beside the
                // template rather than beside its malformed declaration.
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
            }
            for item in displaced_namespace_items {
                self.recovered_class_sibling_scopes
                    .insert(item.id(), scope.clone());
            }
            stack.extend(class_stack);
            return;
        }
        match node.kind() {
            "template_declaration" => {
                if let Some(recovered) =
                    recover_fragmented_preprocessor_class(node, self.source, ancestry)
                {
                    let mut template_scope = scope.clone();
                    template_scope.template_signature =
                        cpp_template_signature(node, recovered.declaration_node, self.source);
                    template_scope.template_metadata =
                        cpp_template_metadata(node, recovered.class_node, self.source, ancestry);
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
                        ancestry,
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
                            cpp_template_metadata(node, child, self.source, ancestry);
                        if let Some(recovered) = recover_fragmented_partial_specialization(
                            node,
                            child,
                            self.source,
                            ancestry,
                        ) {
                            let code_unit = self.visit_named_class_like_shape(
                                recovered.declaration_node,
                                recovered.name,
                                None,
                                true,
                                Some(recovered.range),
                                None,
                                &template_scope,
                                stack,
                                ancestry,
                            );
                            self.parsed.record_materialization(
                                MaterializationRecord::RecoveredDeclaration {
                                    recovery: recovered.range,
                                    unit: code_unit.clone(),
                                },
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
            "namespace_definition" => self.visit_namespace(node, scope, stack, ancestry),
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
                self.visit_class_like(node, scope, stack, ancestry)
            }
            "function_definition" => self.visit_function_definition(node, scope, stack, ancestry),
            // A bare namespace-begin sentinel can make tree-sitter promote the
            // wrapped declaration to an ERROR node instead of the usual bogus
            // function_definition envelope. Keep the recovery entry point on
            // the same structured path for both shapes; ordinary ERROR nodes
            // retain their declaration-preserving wrapper traversal when the
            // sentinel predicate does not match.
            "ERROR" => {
                if !self.visit_function_like_export_class_pair(node, scope, stack, ancestry) {
                    self.visit_embedded_function_like_export_classes(node, scope, stack, ancestry);
                    if self.visit_collapsed_macro_declaration_run(node, scope) {
                        return;
                    }
                    if self.visit_sentinel_macro_region(node, scope, stack, ancestry) {
                        return;
                    }
                    self.visit_macro_swallowed_function_declarations(node, scope);
                    self.visit_macro_wrapped_declarations(node, scope, ancestry);
                    self.visit_stranded_class_members(node, scope, ancestry);
                    stack.push(CppWork::Container(CppContainer {
                        node,
                        scope: scope.clone(),
                    }));
                }
            }
            "declaration" => {
                if node.has_error() {
                    self.visit_prototype_macro_declarations(node, scope);
                    if self.node_is_inside_consumed_fragment(node) {
                        // The whole declaration was a recovered K&R
                        // prototype macro invocation (issue #2932); the
                        // reparse above already indexed its Function.
                        // Falling through to the ordinary declaration
                        // visitor would additionally mint the swapped-field
                        // wreckage this recovery exists to replace.
                        return;
                    }
                }
                if scope.class_unit.is_some()
                    && scope.declarations_are_fields
                    && scope.recovered_specialization_member_scope
                    && let Some(alias_name) =
                        recovered_using_declaration_alias_name(node, self.source)
                {
                    self.add_type_aliases(node, scope, vec![alias_name], ancestry);
                } else {
                    self.visit_declaration(
                        node,
                        scope,
                        scope.declarations_are_fields,
                        stack,
                        ancestry,
                    )
                }
            }
            // A K&R prototype macro invocation with a pointer return type and a
            // simple argument list parses with no ERROR node at all: tree-sitter
            // reads `T *name _(( args ));` as a multiplication of a type by a
            // call (`T * name_(...)`), wrapped in an `expression_statement`
            // that `has_error()` only because of a `MISSING "::"` inside it
            // (issue #2932). Nothing else mints a declaration from an
            // `expression_statement` at declaration scope today, so there is
            // no existing behavior to preserve here if this node is not the
            // K&R shape; the admission gate inside
            // `visit_prototype_macro_declarations` (exactly one clean function
            // prototype spanning the recovered run) is what keeps this arm
            // safe on an ordinary errorful expression statement that happens
            // to contain nested parentheses.
            "expression_statement" => {
                if node.has_error() {
                    self.visit_prototype_macro_declarations(node, scope);
                }
            }
            "field_declaration" => self.visit_declaration(node, scope, true, stack, ancestry),
            "type_definition" | "alias_declaration" => {
                self.visit_type_declaration(node, scope, stack, ancestry)
            }
            "preproc_def" | "preproc_function_def" => self.visit_macro(node),
            // `#include` is collected by `collect_cpp_includes` before the
            // walk, so a directive the container walk never reaches -- inside
            // a class body (Eigen's `EIGEN_DENSEBASE_PLUGIN`) or a switch
            // statement (llama.cpp's `sycl/info/aspects.def`) -- is still an
            // include claim.
            "preproc_include" => {}
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
                if kind == "labeled_statement" {
                    self.visit_access_label_constructor(node, scope);
                }
                if matches!(kind, "preproc_if" | "preproc_ifdef" | "preproc_ifndef") {
                    let mut range = cpp_declaration_range(node);
                    if let Some(boundary) = cpp_displaced_preprocessor_boundary(node) {
                        range.end_byte = boundary.end_byte;
                        range.end_line = boundary.end_line;
                    }
                    self.parsed.record_materialization(
                        MaterializationRecord::ConfigurationConditional { range },
                    );
                    if node.has_error() {
                        // A malformed export-macro class can close the namespace
                        // node early while the enclosing include guard still owns
                        // the remaining class-head/body pairs. The ordinary walk
                        // cannot carry the lost namespace through those promoted
                        // siblings. Scan only structured ERROR nodes in this
                        // already-malformed conditional; the pair recovery's
                        // exact class/macro/body predicate remains the admission
                        // gate, and its namespace lifting restores the owner.
                        let mut candidates = vec![node];
                        while let Some(candidate) = candidates.pop() {
                            // An `ERROR` still inside a namespace body is one
                            // the ordinary walk reaches with that namespace in
                            // scope. Claiming it here registers the recovered
                            // class at file scope and the consumed region then
                            // suppresses the walk that would have named it
                            // correctly -- which is why Botan's `DL_Group` was
                            // `DL_Group` and not `Botan.DL_Group` in the real
                            // header, where an include guard wraps the
                            // namespace, and was right in a fixture without one
                            // (#2552).
                            if candidate.kind() == "ERROR"
                                && !cpp_is_inside_namespace_body(candidate, ancestry)
                                && self.visit_function_like_export_class_pair(
                                    candidate, scope, stack, ancestry,
                                )
                            {
                                continue;
                            }
                            for index in (0..candidate.named_child_count()).rev() {
                                candidates.push(
                                    candidate
                                        .named_child(index)
                                        .expect("index below the node's own named child count"),
                                );
                            }
                        }
                    }
                }
                stack.push(CppWork::Container(CppContainer {
                    node,
                    scope: scope.clone(),
                }))
            }
            _ => {}
        }
    }

    fn visit_macro_swallowed_function_declarations<'tree>(
        &mut self,
        envelope: Node<'tree>,
        scope: &ScopeInfo,
    ) {
        if !cpp_macro_swallowed_declaration_envelope(envelope, self.source)
            || envelope.kind() == "ERROR"
                && envelope
                    .parent()
                    .is_some_and(|parent| parent.kind() == "ERROR")
        {
            return;
        }
        let mut stack = (0..envelope.named_child_count())
            .filter_map(|index| envelope.named_child(index))
            .collect::<Vec<_>>();
        while let Some(node) = stack.pop() {
            if node.kind() == "function_declarator" {
                self.visit_error_swallowed_function_declaration(node, scope);
            }
            for index in 0..node.named_child_count() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }
    }

    /// Index the declarations an attribute-like macro invocation swallowed into
    /// a declaration-scope `ERROR` node. See [`macro_wrapped_declarations`] for
    /// the shape and why the parser produces it.
    fn visit_macro_wrapped_declarations<'tree>(
        &mut self,
        envelope: Node<'tree>,
        scope: &ScopeInfo,
        ancestry: &ParentIndex<'tree>,
    ) {
        let recovered = macro_wrapped_declarations(envelope, self.source);
        if recovered.is_empty() {
            return;
        }
        let recovery = cpp_recovery_window(self.source, envelope.start_byte(), envelope.end_byte());
        self.record_recovered_declarations(recovery, |visitor| {
            for declaration in recovered {
                visitor.add_macro_wrapped_declaration(declaration, scope, ancestry);
            }
        });
    }

    /// Index the declarations a macro invocation collapsed into one envelope.
    /// See [`collapsed_macro_declaration_run`] for the shape and why the parser
    /// produces it. Returns whether it claimed `envelope`.
    ///
    /// The envelope's own nodes cannot be read the way the swallowed tail of
    /// the one-line shape can. Of the 214 declarations whisper's `llama.h`
    /// hides in it, 57 are shredded to bare identifier and punctuation tokens
    /// with no declarator left at all, and the declarators that do survive on
    /// the envelope's declarator spine pair one declaration's name with the
    /// *next* declaration's parameter list. Reading those would be a guess.
    ///
    /// The bytes are still ordinary declarations, though, and the collapse is
    /// the parser carrying the failure forward from one macro invocation. So
    /// reparse the envelope's region, walk the items the parser makes of it,
    /// and when one item is itself a collapsed run, recover that invocation
    /// from its own bytes and resume the scan just past it. Each pass starts
    /// later than the last, so the scan is a loop over the invocations that
    /// collapse, not over the declarations: the real header needs three passes
    /// for 214 declarations.
    fn visit_collapsed_macro_declaration_run(
        &mut self,
        envelope: Node<'_>,
        scope: &ScopeInfo,
    ) -> bool {
        if collapsed_macro_declaration_run(envelope, self.source).is_none() {
            return false;
        }
        let start = envelope.start_byte();
        let end = envelope.end_byte();
        let recovery = cpp_recovery_window(self.source, start, end);
        self.record_recovered_declarations(recovery, |visitor| {
            let mut position = start;
            while position < end {
                let Some(tree) = cpp_reparse_region_items(visitor.source, position, end) else {
                    return;
                };
                let root = tree.root_node();
                // A region reparse is its own tree and needs its own parent
                // index; the caller's answers nothing about these nodes.
                let ancestry = ParentIndex::new(root);
                let mut cursor = root.walk();
                let collapsed =
                    root.named_children(&mut cursor)
                        .enumerate()
                        .find_map(|(index, item)| {
                            collapsed_macro_declaration_run(item, visitor.source)
                                .map(|run| (index, item, run))
                        });
                // Walk only the items before the collapsed one. It swallowed
                // the rest of the region, so handing it to the ordinary walk
                // would re-enter this recovery on a region that starts where
                // this one did.
                let mut stack = Vec::new();
                push_cpp_sibling_range(
                    root,
                    0,
                    collapsed.as_ref().map_or(usize::MAX, |(index, ..)| *index),
                    scope.clone(),
                    &mut stack,
                );
                visitor.drain_cpp_work(stack, &ancestry);
                let Some((_, item, run)) = collapsed else {
                    return;
                };
                // On its own bytes the invocation is the declaration-scope
                // shape `macro_wrapped_declarations` reads, so its wrapped
                // declaration needs no reader of its own here.
                if let Some(head) =
                    cpp_reparse_region_items(visitor.source, item.start_byte(), run.invocation_end)
                {
                    let head_root = head.root_node();
                    visitor.run_container_work(
                        head_root,
                        scope.clone(),
                        &ParentIndex::new(head_root),
                    );
                }
                assert!(
                    run.invocation_end > position,
                    "a collapsed run at {position} must end after the byte the scan resumed \
                     from, but ended at {}",
                    run.invocation_end
                );
                position = run.invocation_end;
            }
        });
        true
    }

    /// Index the members a string-argument attribute macro stranded in an
    /// `ERROR` inside a class body.
    ///
    /// `BOTAN_DEPRECATED("text") explicit Ctor(T);` costs the parser the
    /// grouping of the attributed member and of every member written after it
    /// until it recovers. The members are still whole `function_declarator`
    /// nodes; [`stranded_declaration_run`] regroups them. Without this, an
    /// export-macro class such as Botan's `DL_Group` was indexed with no
    /// members at all (#2552).
    fn visit_stranded_class_members<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        ancestry: &ParentIndex<'tree>,
    ) {
        if scope.class_unit.is_none() || !scope.declarations_are_fields {
            return;
        }
        for member in stranded_declaration_run(node, self.source).declarations {
            self.add_macro_wrapped_declaration(member, scope, ancestry);
        }
    }

    /// Index the constructor an access label swallowed in a reparsed class
    /// body. See [`cpp_access_label_constructor_call_start`] for the shape.
    ///
    /// The declarator is recovered by reparsing from that call to the end of
    /// the label's own statement, which is the same offset-preserving region
    /// reparse every other recovery here uses, so the recovered nodes carry
    /// their true source positions.
    fn visit_access_label_constructor(&mut self, node: Node<'_>, scope: &ScopeInfo) {
        let Some(class_unit) = scope.class_unit.clone() else {
            return;
        };
        if !scope.declarations_are_fields {
            return;
        }
        let class_name = class_unit.identifier().to_string();
        let Some(start) = cpp_access_label_constructor_call_start(node, &class_name, self.source)
        else {
            return;
        };
        let Some(tree) = cpp_reparse_region_items(self.source, start, node.end_byte()) else {
            return;
        };
        let root = tree.root_node();
        let Some(declarator) =
            cpp_reparsed_exact_constructor_declarator(root, start, &class_name, self.source)
        else {
            return;
        };
        let reparsed_ancestry = ParentIndex::new(root);
        let definition = cpp_declarator_function_definition(declarator, &reparsed_ancestry);
        let range = cpp_declaration_range(definition.unwrap_or(declarator));
        let recovery = cpp_recovery_window(self.source, start, node.end_byte());
        self.record_recovered_declarations(recovery, |visitor| {
            visitor.add_macro_wrapped_declaration(
                MacroWrappedDeclaration {
                    declarator,
                    range,
                    is_static: false,
                },
                scope,
                &reparsed_ancestry,
            );
        });
    }

    fn add_macro_wrapped_declaration<'tree>(
        &mut self,
        declaration: MacroWrappedDeclaration<'tree>,
        scope: &ScopeInfo,
        ancestry: &ParentIndex<'tree>,
    ) {
        let Some(function) = extract_function_info(declaration.declarator, self.source, scope)
        else {
            return;
        };
        let code_unit =
            function.code_unit_with_synthetic(self.file.clone(), scope.class_unit.is_some());
        if self.parsed.contains_declaration(&code_unit) {
            self.parsed
                .record_navigation_range(code_unit, declaration.range);
            return;
        }
        self.add_declaration_with_range(code_unit.clone(), declaration.range, None, None);
        let signature = normalize_cpp_whitespace(
            self.source
                .get(declaration.range.start_byte..declaration.range.end_byte)
                .expect("a recovered declaration range covers one source range"),
        );
        let linkage = if declaration.is_static {
            CallableLinkage::Internal
        } else {
            cpp_callable_linkage(declaration.declarator, self.source, ancestry)
        };
        // Whether this is a definition is a property of the recovered node, not
        // of the caller: a declarator that a `function_definition` gives a body
        // is a definition wherever the recovery found it.
        let declaration_only =
            cpp_declarator_function_definition(declaration.declarator, ancestry).is_none();
        self.parsed.add_signature_with_metadata(
            code_unit.clone(),
            cpp_signature_metadata(signature, declaration.declarator, self.source, ancestry)
                .with_declaration_only(declaration_only)
                .with_callable_linkage(linkage),
        );
        if let Some(parent) = &scope.class_unit {
            self.parsed.add_child(parent.clone(), code_unit);
        } else if let Some(module) = &scope.module {
            self.parsed.add_child(module.clone(), code_unit);
        }
    }

    fn visit_error_swallowed_function_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
    ) -> bool {
        let Some((start, end)) = cpp_error_swallowed_function_declaration_range(node) else {
            return false;
        };
        let Some(tree) = cpp_reparse_region_items(self.source, start, end) else {
            return false;
        };
        let root = tree.root_node();
        let mut cursor = root.walk();
        let declarations = root
            .named_children(&mut cursor)
            .filter(|child| child.kind() != "comment")
            .collect::<Vec<_>>();
        let [declaration] = declarations.as_slice() else {
            return false;
        };
        if declaration.kind() != "declaration"
            || declaration.has_error()
            || declaration.start_byte() != start
            || declaration.end_byte() != end
        {
            return false;
        }
        let recovery = cpp_recovery_window(self.source, start, end);
        // The reparsed region is its own tree, so this walk indexes it itself.
        let reparsed_ancestry = ParentIndex::new(root);
        self.record_recovered_declarations(recovery, |visitor| {
            visitor.run_container_work(root, scope.clone(), &reparsed_ancestry);
        });
        true
    }

    /// Recover a K&R-compatibility prototype macro invocation such as
    /// ruby.h's `RET name _(( args ));` (issue #2932). The `_` macro --
    /// spelled `__P`, `OF`, or `PROTO` in other pre-ANSI-C codebases -- is
    /// defined only in headers outside this workspace (ruby's own
    /// `ruby/defines.h`), so tree-sitter-cpp has no grammar production for
    /// `name _((args))` and turns each such line into a malformed
    /// `declaration` or pointer-expression statement. Before this
    /// recovery, the ordinary declaration visitor read that wreckage as a
    /// field with the type and name swapped (e.g. a field literally named
    /// `VALUE`) and indexed no prototype for the real name at all.
    ///
    /// [`cpp_prototype_macro_candidates`] admits only parser-owned shapes that
    /// preserve the declared name, a known one-argument compatibility macro,
    /// the nested argument list, and a live terminator. It rejects arbitrary
    /// identifiers and bare `ERROR` envelopes that flattened those relations;
    /// guessing there previously turned malformed non-macro declarations into
    /// invented functions. For each proven candidate this reparses the range
    /// before the macro token, the inner parenthesized argument node, and the
    /// terminating `;` as one included-range parse. That is the parser-native
    /// equivalent of expanding `#define _(args) args` while retaining original
    /// byte offsets. The result is admitted only when it is exactly one clean
    /// function prototype spanning the recovered run.
    fn visit_prototype_macro_declarations(&mut self, node: Node<'_>, scope: &ScopeInfo) {
        for candidate in cpp_prototype_macro_candidates(node, self.source) {
            let start = candidate.run_start;
            let end = candidate.semicolon_end;
            if self.byte_range_is_inside_consumed_fragment(start, end) {
                continue;
            }
            let Some(tree) = parse_source_ranges_with_cancellation(
                &tree_sitter_cpp::LANGUAGE.into(),
                self.source,
                &candidate.ranges(),
                None,
            ) else {
                continue;
            };
            let root = tree.root_node();
            let mut cursor = root.walk();
            let declarations = root
                .named_children(&mut cursor)
                .filter(|child| child.kind() != "comment")
                .collect::<Vec<_>>();
            let [declaration] = declarations.as_slice() else {
                continue;
            };
            if declaration.kind() != "declaration"
                || declaration.has_error()
                || declaration.start_byte() != start
                || declaration.end_byte() != end
                || declaration
                    .child_by_field_name("declarator")
                    .and_then(extract_function_declarator)
                    .is_none()
            {
                continue;
            }
            let recovery = cpp_recovery_window(self.source, start, end);
            // The reparsed region is its own tree, so this walk indexes it
            // itself.
            let reparsed_ancestry = ParentIndex::new(root);
            self.record_recovered_declarations(recovery, |visitor| {
                visitor.run_container_work(root, scope.clone(), &reparsed_ancestry);
            });
            self.consumed_fragment_regions.push((start, end));
        }
    }

    /// Declare one Module per namespace level of `components` under
    /// `package_name`, and return the innermost level's package name and
    /// Module. A level an earlier definition already declared is reused.
    fn declare_namespace_levels(
        &mut self,
        mut package_name: String,
        components: Vec<String>,
        node: Node<'_>,
    ) -> (String, Option<CodeUnit>) {
        let mut module = None;
        for component in components {
            let full_name = if package_name.is_empty() {
                component
            } else {
                format!("{package_name}{CPP_PACKAGE_SEPARATOR}{component}")
            };
            let level = CodeUnit::new_fq(
                self.file.clone(),
                CodeUnitType::Module,
                "",
                full_name.clone(),
                cpp_namespace_fq(&full_name),
            );
            if !self.parsed.contains_declaration(&level) {
                self.add_declaration(level.clone(), node, None, None);
            }
            package_name = full_name;
            module = Some(level);
        }
        (package_name, module)
    }

    /// The scope for a node that C++ parse recovery displaced out of the
    /// namespaces enclosing it (issue #1537). When tree-sitter closes a
    /// damaged namespace early, the rest of its body and possibly the rest of
    /// the file lose the `namespace_definition` ancestors this walk reads a
    /// package from; the recovered region names the complete enclosing path.
    /// `None` when the walk's scope already names every enclosing namespace,
    /// or names a path another recovery established that this one does not
    /// extend.
    fn recovered_namespace_scope(
        &mut self,
        node: Node<'_>,
        scope: &ScopeInfo,
    ) -> Option<ScopeInfo> {
        let components = self
            .orphaned_namespaces
            .region_at(node.start_byte())?
            .components
            .clone();
        let package_name = components.join(CPP_PACKAGE_SEPARATOR);
        let extends = package_name.len() > scope.package_name.len()
            && package_name.starts_with(scope.package_name.as_str())
            && (scope.package_name.is_empty()
                || package_name[scope.package_name.len()..].starts_with(CPP_PACKAGE_SEPARATOR));
        if !extends {
            return None;
        }
        let (package_name, module) = self.declare_namespace_levels(String::new(), components, node);
        Some(ScopeInfo {
            package_name,
            module,
            ..scope.clone()
        })
    }

    fn visit_namespace<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
        ancestry: &ParentIndex<'tree>,
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
        let components = cpp_namespace_name_components(name_node, self.source);
        if components.is_empty() {
            return;
        }
        // One Module per namespace level. C++17's `namespace a::b { ... }` is
        // DEFINED to mean `namespace a { namespace b { ... } }`, so the
        // shorthand must declare `a` as well as `a::b` -- extracting only the
        // innermost level left the enclosing namespace undeclared and made the
        // two spellings of one construct disagree (issue #1878).
        let package_name = if explicitly_global {
            String::new()
        } else {
            scope.package_name.clone()
        };
        let (package_name, module) = self.declare_namespace_levels(package_name, components, node);

        let namespace_scope = ScopeInfo {
            package_name,
            module,
            // C++ never nests a namespace inside a class, so a surviving
            // class_unit here is always recovery bleed: a malformed-region
            // boundary upstream mis-scoped this namespace block. Keeping the
            // owner would mint the namespace's declarations as class members
            // under a re-appended package, desyncing the fq boundary assert
            // (#2306). Dropping it is identity-neutral for valid code, where
            // class_unit is always empty at a namespace definition.
            class_unit: None,
            template_signature: scope.template_signature.clone(),
            template_metadata: scope.template_metadata.clone(),
            declarations_are_fields: false,
            recovered_specialization_member_scope: false,
            visible_using_namespaces: scope.visible_using_namespaces.clone(),
        };
        let container = cpp_body_node(node).unwrap_or(node);
        // A malformed export-macro class body may turn the following class
        // into a descendant of a bogus function/labeled/error envelope. Those
        // descendants are not declaration containers and the ordinary walk
        // intentionally does not descend into them. Scan the namespace tree
        // once for the strict embedded class geometry before scheduling its
        // normal declarations. When one envelope matches, its helper recovers
        // every embedded class and the walk need not inspect its descendants.
        let mut candidates = vec![container];
        while let Some(candidate) = candidates.pop() {
            if matches!(
                candidate.kind(),
                "ERROR" | "function_definition" | "labeled_statement"
            ) && self.visit_embedded_function_like_export_classes(
                candidate,
                &namespace_scope,
                stack,
                ancestry,
            ) {
                continue;
            }
            for index in (0..candidate.named_child_count()).rev() {
                candidates.push(
                    candidate
                        .named_child(index)
                        .expect("index below the node's own named child count"),
                );
            }
        }
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
        ancestry: &ParentIndex<'tree>,
    ) {
        let Some(name) = class_like_name(node, self.source, ancestry) else {
            return;
        };
        let name = qualified_class_name_chain(node, self.source, scope)
            .map(|chain| chain.join("$"))
            .unwrap_or(name);
        self.visit_named_class_like(node, name, scope, stack, ancestry);
    }

    fn visit_named_class_like<'tree>(
        &mut self,
        node: Node<'tree>,
        name: String,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
        ancestry: &ParentIndex<'tree>,
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
            ancestry,
        );
    }

    /// Whether this class-like declaration is a C tag that belongs to the
    /// enclosing non-aggregate scope rather than to the aggregate it is
    /// lexically written inside.
    ///
    /// `class_specifier` is deliberately excluded: `class` is not C, so text
    /// that spells one in a `.c` file is not C code and keeps the C++ reading
    /// rather than getting a half-C identity.
    fn mints_tag_at_enclosing_c_scope(
        &self,
        declaration_node: Node<'_>,
        scope: &ScopeInfo,
        ancestry: &ParentIndex<'_>,
    ) -> bool {
        self.c_tag_semantics
            && scope.class_unit.is_some()
            && class_like_name(declaration_node, self.source, ancestry).is_some()
            && matches!(
                declaration_node.kind(),
                "struct_specifier" | "union_specifier" | "enum_specifier"
            )
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
        ancestry: &ParentIndex<'tree>,
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
            ancestry,
        );
        // C tag scope (C17 6.2.1, 6.7.2.3): a tag declared inside another
        // aggregate's member list is declared at the enclosing non-aggregate
        // scope, not nested inside the aggregate. `scope.class_unit` is the
        // only aggregate carrier in this walk, so dropping it puts the tag at
        // the nearest enclosing non-aggregate scope -- the module at file or
        // namespace scope, and the same block-scope representation a
        // function-local aggregate already gets. The tag's own body scope
        // below still owns its members, so fields and enumerators are
        // unaffected.
        let c_tag_scope;
        let scope =
            if self.mints_tag_at_enclosing_c_scope(declaration_node, &recovered_scope, ancestry) {
                c_tag_scope = ScopeInfo {
                    class_unit: None,
                    ..recovered_scope.clone()
                };
                &c_tag_scope
            } else {
                &recovered_scope
            };
        let short_name = if let Some(parent) = &scope.class_unit {
            cpp_join_nested_short(parent.short_name(), &name)
        } else {
            name.clone()
        };
        // A top-level out-of-line qualified class definition (`struct
        // Outer::Inner { ... }` inside its namespace, #2246) carries its
        // nesting chain as the `$`-joined display name; push one Type/Nested
        // segment per class so segment-pop owner navigation keeps working.
        // Every other leaf name stays opaque so a literal `$` in a source
        // identifier never crosses the split/join boundary (#2140).
        let qualified_chain = if scope.class_unit.is_none() {
            qualified_class_name_chain(declaration_node, self.source, scope)
                .filter(|chain| chain.join("$") == name)
        } else {
            None
        };
        let fq = if let Some(chain) = qualified_chain {
            let mut fq = FqName::new();
            cpp_push_package(&mut fq, &scope.package_name);
            let mut first = true;
            for component in chain {
                let kind = if first {
                    SegmentKind::Type
                } else {
                    SegmentKind::Nested
                };
                fq.push(cpp_segment(&component, kind));
                first = false;
            }
            fq
        } else {
            cpp_leaf_fq(
                &scope.package_name,
                scope.class_unit.as_ref(),
                &name,
                SegmentKind::Nested,
                SegmentKind::Type,
            )
        };
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
                self.replace_declaration_with_range_deferred(code_unit.clone(), range, None, None);
            } else {
                self.replace_declaration_deferred(code_unit.clone(), declaration_node, None, None);
            }
        } else {
            self.add_declaration(code_unit.clone(), declaration_node, None, None);
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
                cpp_join_nested_short(parent.short_name(), &metadata.primary_name)
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
                    declaration_node.kind() == "function_definition" && metadata.is_specialization()
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
                push_cpp_sibling_range(
                    body,
                    displaced.split_index,
                    usize::MAX,
                    scope.clone(),
                    stack,
                );
                push_cpp_sibling_range(body, 0, displaced.split_index, nested_scope, stack);
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

    /// Whether the parse product already holds enumerator fields for `parent`,
    /// answered from the walk's carried-forward field ownership index.
    ///
    /// Built on the first enum's question and advanced by every declaration
    /// recorded after it, so a file that declares no enum -- most files -- pays
    /// nothing, and one that declares thousands pays a single pass instead of
    /// one per enum (#2786).
    fn has_enum_enumerator_units(&mut self, parent: &CodeUnit) -> bool {
        if self.field_owners.is_none() {
            self.field_owners = Some(CppFieldOwnerIndex::of(
                self.parsed.declarations().iter(),
                self.file,
            ));
        }
        debug_assert_eq!(
            parent.source(),
            self.file,
            "the walk's declarations are declarations of the file it is walking"
        );
        let carried = self
            .field_owners
            .as_ref()
            .expect("the index was just ensured")
            .owns_fields(parent.package_name(), parent.short_name());

        #[cfg(debug_assertions)]
        assert_eq!(
            carried,
            cpp_declarations_hold_owned_fields(
                self.parsed.declarations(),
                self.file,
                parent.package_name(),
                parent.short_name()
            ),
            "the carried-forward field index must answer what a fresh declaration scan \
             answers for {}",
            parent.fq_name()
        );

        carried
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
                cpp_join_member_short(parent.short_name(), &name),
                parent
                    .fq()
                    .clone()
                    .with_pushed(cpp_segment(&name, SegmentKind::Member)),
            );
            if self.parsed.contains_declaration(&code_unit) {
                return WalkControl::Continue;
            }
            self.add_declaration(code_unit.clone(), child, Some(parent.clone()), None);
            self.parsed.add_signature(
                code_unit,
                normalize_cpp_whitespace(node_text(child, self.source)),
            );
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
                cpp_join_member_short(parent.short_name(), name),
                parent
                    .fq()
                    .clone()
                    .with_pushed(cpp_segment(name, SegmentKind::Member)),
            );
            if self.parsed.contains_declaration(&code_unit) {
                continue;
            }
            self.add_declaration(code_unit.clone(), node, Some(parent.clone()), None);
            self.parsed.add_signature(code_unit, trimmed.to_string());
        }
    }

    fn visit_function_definition<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
        ancestry: &ParentIndex<'tree>,
    ) {
        // An attribute-like macro invocation whose argument is a declaration can
        // swallow every declaration written after it into one bogus
        // `function_definition` (#2551). This owns the whole region, so it runs
        // ahead of `visit_macro_swallowed_function_declarations` below, which
        // admits the same envelope by its head macro token and reads single
        // declarators out of nodes this recovery reparses properly.
        if self.visit_collapsed_macro_declaration_run(node, scope) {
            return;
        }
        // A file-scope object-like macro sentinel the parser cannot see (issue
        // #941, e.g. `BEGIN_NS`/`END_NS`) makes tree-sitter recover the region it
        // prefixes as a bogus `function_definition` that swallows real namespaces,
        // classes, and members. Reparse the swallowed interior as C++ items so the
        // ordinary declaration visitors index it with byte/line-exact ownership.
        if self.visit_sentinel_macro_region(node, scope, stack, ancestry) {
            return;
        }
        if node.has_error() {
            self.visit_macro_swallowed_function_declarations(node, scope);
        }
        if let Some((class_node, name, raw_supertypes)) =
            recover_exported_class_function_definition(node, self.source)
        {
            let body = cpp_body_node(class_node);
            let displaced_namespace = cpp_body_node(node)
                .and_then(|_| displaced_export_function_namespace_shape(node, self.source));
            let fragmented = cpp_body_node(node).and_then(|body| {
                fragmented_export_function_body_region(
                    node,
                    body,
                    self.source,
                    displaced_namespace.as_ref(),
                )
            });
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
                    ancestry,
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
                            ancestry,
                        );
                        self.visit_recovered_fragment_constructor(
                            range,
                            body,
                            class_node,
                            &class_unit,
                            scope,
                            ancestry,
                        );
                    }
                }
                if let Some(boundary) = displaced_namespace {
                    for item in boundary.namespace_items {
                        self.recovered_class_sibling_scopes
                            .insert(item.id(), scope.clone());
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
                ancestry,
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
                            push_cpp_sibling_range(
                                body,
                                split,
                                usize::MAX,
                                scope.clone(),
                                &mut stack,
                            );
                            push_cpp_sibling_range(body, 0, split, container.scope, &mut stack);
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
                    CppWork::Node(work) => {
                        self.visit_node(work.node, &work.scope, &mut stack, ancestry)
                    }
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
        let function = if let Some((_, callable_name)) =
            cpp_macro_displaced_callable_parts(function_declarator, self.source, ancestry)
        {
            extract_function_info_from_name(function_declarator, callable_name, self.source, scope)
        } else {
            extract_function_info(function_declarator, self.source, scope)
        };
        let Some(mut function) = function else {
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
        self.add_declaration(code_unit.clone(), node, None, None);
        let signature = if recovered_constraint_constructor.is_some() {
            normalize_cpp_whitespace(node_text(function_declarator, self.source))
        } else {
            render_cpp_function_display_signature_from_node(
                node,
                self.source,
                scope.template_signature.as_deref(),
                true,
                ancestry,
            )
        };
        self.parsed.add_signature_with_metadata(
            code_unit.clone(),
            cpp_signature_metadata(signature, function_declarator, self.source, ancestry)
                .with_declaration_only(false)
                .with_callable_linkage(cpp_callable_linkage(node, self.source, ancestry)),
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
    fn scope_for_recovered_exported_class<'tree>(
        &mut self,
        node: Node<'tree>,
        name: &str,
        definition_body_present: bool,
        scope: &ScopeInfo,
        ancestry: &ParentIndex<'tree>,
    ) -> ScopeInfo {
        if !definition_body_present
            || !scope.package_name.is_empty()
            || scope.class_unit.is_some()
            || !(is_recovered_exported_class_container(node, self.source)
                || recover_function_like_export_class_pair(node, self.source).is_some()
                || recover_embedded_function_like_export_classes(node, self.source)
                    .iter()
                    .any(|recovered| recovered.name == name)
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
                }) || ancestry.parent(node).is_some_and(|parent| {
                    matches!(parent.kind(), "declaration" | "field_declaration")
                        && recover_exported_class_declaration(parent, self.source).is_some()
                        || is_recovered_exported_class_container(parent, self.source)
                })) && class_like_name(node, self.source, ancestry).as_deref() == Some(name))
        {
            return scope.clone();
        }
        let borrowed_namespace = self.unique_earlier_namespace_forward(node, name, ancestry);
        let Some(package_name) = borrowed_namespace
            .or_else(|| lifted_function_like_export_class_namespace(node, self.source, ancestry))
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

    /// The unique namespace-scope forward declaration of `name` that precedes
    /// `recovered_node`, answered from the walk's carried-forward scan of the
    /// tree `recovered_node` belongs to.
    ///
    /// The scan is built on the first question and advanced by each later one,
    /// so a file that never reaches this path -- almost every file -- pays
    /// nothing, and one that reaches it thousands of times pays a single pass
    /// (#2754).
    fn unique_earlier_namespace_forward<'tree>(
        &mut self,
        recovered_node: Node<'tree>,
        name: &str,
        ancestry: &ParentIndex<'tree>,
    ) -> Option<String> {
        let mut root = recovered_node;
        while let Some(parent) = ancestry.parent(root) {
            root = parent;
        }
        let source = self.source;
        let scan = self
            .namespace_forward_scans
            .entry(CppTreeIdentity::of(root))
            .or_default();
        scan.advance_to(root, recovered_node.start_byte(), source, ancestry);
        let borrowed = scan.unique_earlier_forward(name, recovered_node);

        #[cfg(debug_assertions)]
        assert_eq!(
            borrowed,
            unique_earlier_cpp_namespace_forward(recovered_node, name, source, ancestry),
            "the carried-forward namespace scan must answer what a fresh prefix scan answers \
             for {name} at byte {}",
            recovered_node.start_byte()
        );

        borrowed
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
    /// Runs `reparse_walk` and records every declaration it mints as a
    /// [`MaterializationRecord::RecoveredDeclaration`] interpreting
    /// `recovery` (issue #1657). A reparsed sentinel region has no single
    /// recovered envelope unit: the ordinary visitors mint namespaces,
    /// classes, and members directly from the reparsed tree, so the walk's
    /// declaration delta is the recovered set. Records are ordered by
    /// declaration start byte so the parse product stays deterministic.
    fn record_recovered_declarations(
        &mut self,
        recovery: Range,
        reparse_walk: impl FnOnce(&mut Self),
    ) {
        // The set difference this used to be, kept as the oracle every answer
        // is asserted against (#2787).
        #[cfg(any(debug_assertions, test))]
        let before = self.parsed.declarations().clone();

        self.recovery_captures.push(CppRecoveryCapture::default());
        reparse_walk(self);
        let captured = self
            .recovery_captures
            .pop()
            .expect("the capture this call pushed is the one it pops");

        // The capture holds every declaration created while it was open, once
        // each and in creation order, so the recovered set costs what the
        // recovery made rather than everything the file has declared so far.
        // One filter is left to apply: a created declaration that a later
        // deferred replacement removed is not in the parse product to report.
        let mut minted: Vec<CodeUnit> = captured
            .created
            .into_iter()
            .filter(|unit| self.parsed.contains_declaration(unit))
            .collect();
        minted.sort_by_cached_key(|unit| self.recovered_declaration_order(unit));

        #[cfg(any(debug_assertions, test))]
        {
            let mut rediscovered: Vec<CodeUnit> = self
                .parsed
                .declarations()
                .iter()
                .filter(|unit| !before.contains(*unit))
                .cloned()
                .collect();
            rediscovered.sort_by_cached_key(|unit| self.recovered_declaration_order(unit));
            assert_eq!(
                minted, rediscovered,
                "the captured recovered set must be the declaration delta of the reparse \
                 walk over {recovery:?}"
            );
        }

        for unit in minted {
            self.parsed
                .record_materialization(MaterializationRecord::RecoveredDeclaration {
                    recovery,
                    unit,
                });
        }
    }

    /// Where one recovered declaration sorts: by start byte, then by name, so
    /// the parse product stays deterministic.
    fn recovered_declaration_order(&self, unit: &CodeUnit) -> (usize, String) {
        let start = self
            .parsed
            .declaration_ranges(unit)
            .first()
            .map(|range| range.start_byte)
            .unwrap_or(usize::MAX);
        (start, unit.fq_name().to_string())
    }

    fn visit_sentinel_macro_region<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
        ancestry: &ParentIndex<'tree>,
    ) -> bool {
        if self.visit_nested_namespace_sentinel(node, scope, ancestry) {
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
            // A region reparse is its own tree and needs its own parent index.
            let class_ancestry = ParentIndex::new(class_root);
            let Some(reparsed_class) = cpp_sentinel_reparsed_class(
                class_root,
                template_node,
                self.source,
                &class_ancestry,
            ) else {
                return false;
            };
            let class_node = reparsed_class.declaration_node;
            let name = reparsed_class.name;
            let mut class_scope = scope.clone();
            if let Some(template_node) = template_node {
                class_scope.template_signature =
                    cpp_template_signature(template_node, class_node, self.source);
                class_scope.template_metadata =
                    cpp_template_metadata(template_node, class_node, self.source, ancestry);
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
            let class_scope = self.scope_for_recovered_exported_class(
                class_node,
                &name,
                true,
                &class_scope,
                ancestry,
            );
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
                ancestry,
            );
            self.parsed
                .record_materialization(MaterializationRecord::RecoveredDeclaration {
                    recovery: class_range,
                    unit: class_unit.clone(),
                });
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
            // The padded body reparse is its own tree, so it indexes itself.
            let body_root = body_tree.root_node();
            self.run_container_work(body_root, member_scope, &ParentIndex::new(body_root));
            // Register only after the padded body reparse: its nodes deliberately
            // retain offsets inside the consumed region and must be visited first.
            self.consumed_fragment_regions
                .push((node.start_byte(), class_close_end));
            // An ERROR envelope can hold real sibling declarations after the
            // recovered class's close (the suffix-reparse boundary in
            // `cpp_sentinel_macro_class_region` partitions, it does not
            // consume). Walk the envelope's remaining children normally; the
            // consumed region above keeps the recovered class from being
            // indexed twice.
            if node.kind() == "ERROR" && node.end_byte() > class_close_end {
                stack.push(CppWork::Container(CppContainer {
                    node,
                    scope: scope.clone(),
                }));
            }
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
        let recovery = cpp_recovery_window(self.source, start, end);
        // The reparsed region is its own tree, so this walk indexes it itself.
        let reparsed_ancestry = ParentIndex::new(root);
        self.record_recovered_declarations(recovery, |visitor| {
            visitor.visit_container(
                root,
                &reparsed_ancestry,
                &scope.package_name,
                scope.module.clone(),
                scope.class_unit.clone(),
                scope.template_signature.clone(),
                scope.visible_using_namespaces.clone(),
            );
        });
        if end > node.end_byte() {
            self.consumed_fragment_regions
                .push((node.start_byte(), end));
        } else if node.kind() == "ERROR" && node.end_byte() > end {
            // The sentinel region ended at the first recovered class-like item
            // but the ERROR envelope keeps real sibling declarations after it
            // (fmt's color.h: `enum class color` under stacked FMT_BEGIN
            // sentinels, followed by `terminal_color`, `rgb`, ...). Walk the
            // envelope's remaining children normally; the consumed region
            // keeps the reparsed prefix from being indexed twice.
            self.consumed_fragment_regions
                .push((node.start_byte(), end));
            stack.push(CppWork::Container(CppContainer {
                node,
                scope: scope.clone(),
            }));
        }
        true
    }

    /// Re-own complete class declarations from the structured Abseil
    /// namespace-sentinel shape.  The malformed root `ERROR` is not reparsed:
    /// its direct CST children already prove both namespace components and the
    /// class bodies, so the ordinary class/member visitor can retain ownership
    /// and exact source ranges without admitting unrelated callable bodies.
    fn visit_nested_namespace_sentinel<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        ancestry: &ParentIndex<'tree>,
    ) -> bool {
        let Some(recovered) = cpp_nested_namespace_sentinel(node, self.source, ancestry) else {
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
                self.add_declaration(namespace_module.clone(), recovered.function, None, None);
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
        if let Some(fragmented) = cpp_sentinel_fragmented_class_tail(
            recovered.function,
            recovered.body,
            self.source,
            ancestry,
        ) {
            let mut class_scope = recovered_scope.clone();
            if let Some(template_node) = fragmented.template_node {
                class_scope.template_signature =
                    cpp_template_signature(template_node, fragmented.class_node, self.source);
                class_scope.template_metadata = cpp_template_metadata(
                    template_node,
                    fragmented.class_node,
                    self.source,
                    ancestry,
                );
            }
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
                    fragmented.raw_supertypes.clone(),
                    &class_scope,
                    &mut class_stack,
                    ancestry,
                );
                self.parsed
                    .record_materialization(MaterializationRecord::RecoveredDeclaration {
                        recovery: fragmented.fragmented.class_range,
                        unit: class_unit.clone(),
                    });
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
        // functions, and variables are not silently discarded. The body is a
        // node of the tree being walked, so it reuses that tree's index.
        self.run_container_work(recovered.body, recovered_scope, ancestry);
        true
    }

    fn visit_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        in_class_body: bool,
        stack: &mut Vec<CppWork<'tree>>,
        ancestry: &ParentIndex<'tree>,
    ) {
        if self.visit_sentinel_macro_region(node, scope, stack, ancestry) {
            return;
        }
        if recovered_macro_return_type_node(node, self.source).is_some_and(|declarator| {
            !cpp_active_template_type_parameter(
                node,
                node_text(declarator, self.source),
                self.source,
                ancestry,
            )
        }) {
            return;
        }
        if in_class_body
            && let Some(parent) = scope.class_unit.as_ref()
            && let Some(call) =
                recovered_macro_qualified_constructor_call(node, parent.identifier(), self.source)
        {
            self.visit_recovered_macro_qualified_constructor_definition(
                node, call, scope, ancestry,
            );
            return;
        }
        if in_class_body
            && let Some(call) = recovered_macro_qualified_function_call(node, self.source)
        {
            self.visit_recovered_macro_qualified_function_declaration(node, call, scope, ancestry);
            return;
        }
        if in_class_body
            && let Some(members) = string_attribute_macro_member_declarators(node, self.source)
        {
            for member in members {
                self.add_macro_wrapped_declaration(member, scope, ancestry);
            }
            return;
        }
        if in_class_body
            && let Some(declarators) =
                recovered_macro_qualified_field_declarators(node, self.source)
        {
            for declarator in declarators {
                self.visit_variable_declaration(node, declarator, scope, true, ancestry);
            }
            return;
        }
        let recovered_alias_names = recovered_type_alias_names(node, self.source);
        if !recovered_alias_names.is_empty() {
            self.add_type_aliases(node, scope, recovered_alias_names, ancestry);
            return;
        }
        if self.visit_c_anonymous_aggregate_declaration(node, scope, in_class_body, stack, ancestry)
        {
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
                        ancestry,
                    );
                    self.parsed.record_materialization(
                        MaterializationRecord::RecoveredDeclaration {
                            recovery: fragmented.class_range,
                            unit: code_unit.clone(),
                        },
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
            let class_unit = self.visit_named_class_like_shape(
                recovered.declaration_node,
                recovered.name,
                recovered.body,
                definition_body_present,
                None,
                recovered.raw_supertypes,
                scope,
                stack,
                ancestry,
            );
            self.parsed
                .record_materialization(MaterializationRecord::RecoveredDeclaration {
                    recovery: cpp_declaration_range(node),
                    unit: class_unit,
                });
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
                    self.visit_class_like(child, scope, stack, ancestry);
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
                        self.visit_function_declaration(node, function_declarator, scope, ancestry);
                    }
                    DeclaratorKind::Variable(variable_declarator) => {
                        self.visit_variable_declaration(
                            node,
                            variable_declarator,
                            scope,
                            in_class_body,
                            ancestry,
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
                        self.visit_function_declaration(node, function_declarator, scope, ancestry);
                    }
                    DeclaratorKind::Variable(variable_declarator) => {
                        self.visit_variable_declaration(
                            node,
                            variable_declarator,
                            scope,
                            in_class_body,
                            ancestry,
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
                self.visit_class_members_from_declaration(node, scope, ancestry);
            } else {
                self.visit_global_variables_from_declaration(node, scope, ancestry);
            }
        }
    }

    /// Preserve the member structure of an anonymous C aggregate.
    ///
    /// An anonymous union with no declarator promotes its fields into the
    /// containing aggregate. An anonymous struct/union followed by a named
    /// declarator, such as `struct { T *ops; } sock`, declares both the field
    /// `sock` and an otherwise unnamed receiver type. Give that receiver type
    /// the declarator's structured nested identity so a later `value.sock.ops`
    /// chain can traverse it without parsing a type spelling (#2407).
    fn visit_c_anonymous_aggregate_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        in_class_body: bool,
        stack: &mut Vec<CppWork<'tree>>,
        ancestry: &ParentIndex<'tree>,
    ) -> bool {
        if !self.c_tag_semantics || !in_class_body || scope.class_unit.is_none() {
            return false;
        }
        let Some(aggregate) = node.child_by_field_name("type") else {
            return false;
        };
        if !matches!(aggregate.kind(), "struct_specifier" | "union_specifier")
            || aggregate.child_by_field_name("name").is_some()
        {
            return false;
        }
        let Some(body) = cpp_body_node(aggregate) else {
            return false;
        };

        let mut cursor = node.walk();
        let declarators = node
            .children_by_field_name("declarator", &mut cursor)
            .filter_map(|declarator| match classify_declarator(declarator) {
                Some(DeclaratorKind::Variable(variable)) => Some(variable),
                Some(DeclaratorKind::Function(_)) | None => None,
            })
            .collect::<Vec<_>>();
        if declarators.is_empty() {
            stack.push(CppWork::Container(CppContainer {
                node: body,
                scope: scope.clone(),
            }));
            return true;
        }

        for declarator in declarators {
            let Some(name) = extract_variable_name(declarator, self.source) else {
                continue;
            };
            self.visit_variable_declaration(node, declarator, scope, true, ancestry);
            self.visit_named_class_like_shape(
                aggregate,
                name,
                Some(body),
                true,
                None,
                None,
                scope,
                stack,
                ancestry,
            );
        }
        true
    }

    fn visit_function_declaration<'tree>(
        &mut self,
        declaration_node: Node<'tree>,
        declarator: Node<'tree>,
        scope: &ScopeInfo,
        ancestry: &ParentIndex<'tree>,
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
        self.add_declaration(code_unit.clone(), declaration_node, None, None);
        let signature = render_cpp_function_display_signature_from_node(
            declaration_node,
            self.source,
            scope.template_signature.as_deref(),
            false,
            ancestry,
        );
        self.parsed.add_signature_with_metadata(
            code_unit.clone(),
            cpp_signature_metadata(signature, declarator, self.source, ancestry)
                .with_declaration_only(true)
                .with_callable_linkage(cpp_callable_linkage(
                    declaration_node,
                    self.source,
                    ancestry,
                )),
        );
        if let Some(parent) = &scope.class_unit {
            self.parsed.add_child(parent.clone(), code_unit);
        } else if let Some(module) = &scope.module {
            self.parsed.add_child(module.clone(), code_unit);
        }
    }

    fn visit_recovered_macro_qualified_function_declaration<'tree>(
        &mut self,
        declaration_node: Node<'tree>,
        call: Node<'tree>,
        scope: &ScopeInfo,
        ancestry: &ParentIndex<'tree>,
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
            owner: Some(CppMemberOwner::Unit(parent.clone())),
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
        self.add_declaration(code_unit.clone(), declaration_node, None, None);
        let signature_label = render_cpp_function_display_signature_from_node(
            declaration_node,
            self.source,
            scope.template_signature.as_deref(),
            false,
            ancestry,
        );
        let metadata = SignatureMetadata::with_parameter_labels(signature_label, parameter_labels)
            .with_declaration_only(true)
            .with_callable_arity(CallableArity::exact(arity))
            .with_callable_linkage(cpp_callable_linkage(
                declaration_node,
                self.source,
                ancestry,
            ));
        self.parsed
            .add_signature_with_metadata(code_unit.clone(), metadata);
        self.parsed.add_child(parent.clone(), code_unit);
    }

    fn visit_recovered_macro_qualified_constructor_definition<'tree>(
        &mut self,
        declaration_node: Node<'tree>,
        call: Node<'tree>,
        scope: &ScopeInfo,
        ancestry: &ParentIndex<'tree>,
    ) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(arguments) = call.child_by_field_name("arguments") else {
            return;
        };
        let Some((mut signature, parameter_labels)) =
            recovered_macro_qualified_function_parameters(arguments, self.source)
        else {
            return;
        };
        if let Some(template_signature) = &scope.template_signature {
            signature = format!("{template_signature}{signature}");
        }
        let arity = parameter_labels.len();
        let function = FunctionInfo {
            package_name: scope.package_name.clone(),
            owner: Some(CppMemberOwner::Unit(parent.clone())),
            name: parent.identifier().to_string(),
            signature,
        };
        let code_unit = function.code_unit_with_synthetic(self.file.clone(), true);
        self.add_declaration(code_unit.clone(), declaration_node, None, None);
        let signature_label = normalize_cpp_whitespace(node_text(declaration_node, self.source));
        let metadata = SignatureMetadata::with_parameter_labels(signature_label, parameter_labels)
            .with_declaration_only(false)
            .with_callable_arity(CallableArity::exact(arity))
            .with_callable_linkage(cpp_callable_linkage(
                declaration_node,
                self.source,
                ancestry,
            ));
        self.parsed
            .add_signature_with_metadata(code_unit.clone(), metadata);
        self.parsed.add_child(parent.clone(), code_unit);
    }

    fn visit_variable_declaration<'tree>(
        &mut self,
        declaration_node: Node<'tree>,
        declarator: Node<'tree>,
        scope: &ScopeInfo,
        in_class_body: bool,
        ancestry: &ParentIndex<'tree>,
    ) {
        let Some(name) = extract_variable_name(declarator, self.source) else {
            return;
        };
        let parent = if in_class_body {
            let Some(parent) = &scope.class_unit else {
                return;
            };
            Some(parent)
        } else {
            None
        };
        let short_name = match parent {
            Some(parent) => cpp_join_member_short(parent.short_name(), &name),
            None => name.clone(),
        };
        let fq = cpp_leaf_fq(
            &scope.package_name,
            parent,
            &name,
            SegmentKind::Member,
            SegmentKind::Member,
        );
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
        self.add_declaration(code_unit.clone(), declaration_node, None, None);
        self.parsed.add_signature_with_metadata(
            code_unit.clone(),
            SignatureMetadata::new(
                render_cpp_field_signature(declaration_node, declarator, self.source),
                Vec::new(),
            )
            .with_cpp_field_linkage(cpp_field_declaration_linkage(
                declaration_node,
                self.source,
                ancestry,
            )),
        );
        if let Some(parent) = &scope.class_unit {
            self.parsed.add_child(parent.clone(), code_unit);
        } else if let Some(module) = &scope.module {
            self.parsed.add_child(module.clone(), code_unit);
        }
    }

    fn visit_class_members_from_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        ancestry: &ParentIndex<'tree>,
    ) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "init_declarator"
                && let Some(inner) = child.child_by_field_name("declarator")
            {
                self.visit_variable_declaration(node, inner, scope, true, ancestry);
            } else if matches!(
                child.kind(),
                "identifier"
                    | "field_identifier"
                    | "pointer_declarator"
                    | "reference_declarator"
                    | "array_declarator"
                    | "parenthesized_declarator"
            ) {
                self.visit_variable_declaration(node, child, scope, true, ancestry);
            }
        }
    }

    fn visit_global_variables_from_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        ancestry: &ParentIndex<'tree>,
    ) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "init_declarator"
                && let Some(inner) = child.child_by_field_name("declarator")
            {
                self.visit_variable_declaration(node, inner, scope, false, ancestry);
            } else if matches!(
                child.kind(),
                "identifier"
                    | "field_identifier"
                    | "pointer_declarator"
                    | "reference_declarator"
                    | "array_declarator"
                    | "parenthesized_declarator"
            ) {
                self.visit_variable_declaration(node, child, scope, false, ancestry);
            }
        }
    }

    fn visit_type_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
        ancestry: &ParentIndex<'tree>,
    ) {
        let type_node = node.child_by_field_name("type");
        if let Some(type_node) = type_node
            && matches!(
                type_node.kind(),
                "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
            )
        {
            self.visit_class_like(type_node, scope, stack, ancestry);
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
            self.record_type_aliases(
                node,
                scope,
                vec![recovered.name],
                signature,
                range,
                ancestry,
            );
            return;
        }

        let alias_names = match node.kind() {
            "alias_declaration" => extract_alias_declaration_name(node, self.source)
                .into_iter()
                .collect::<Vec<_>>(),
            "type_definition" => extract_typedef_alias_names(node, self.source),
            _ => Vec::new(),
        };
        let anonymous_aggregate = if let (Some(type_node), [alias_name]) =
            (type_node, alias_names.as_slice())
            && matches!(type_node.kind(), "struct_specifier" | "union_specifier")
            && type_node.child_by_field_name("name").is_none()
        {
            cpp_body_node(type_node).map(|body| (body, alias_name.clone()))
        } else {
            None
        };
        self.add_type_aliases(node, scope, alias_names, ancestry);
        if let Some((body, alias_name)) = anonymous_aggregate {
            // The typedef alias is also the only user-visible identity of an
            // anonymous aggregate. Reuse it as the member owner instead of
            // minting a second signatureless class with the same FQN. The
            // latter makes forward lookup ambiguous when conditional aliases
            // coexist and returns duplicate definitions even without guards.
            let signature = normalize_cpp_whitespace(node_text(node, self.source));
            let alias_unit = self.type_alias_unit(scope, alias_name, signature);
            debug_assert!(self.parsed.contains_declaration(&alias_unit));
            let mut nested_scope = scope.clone();
            nested_scope.class_unit = Some(alias_unit);
            nested_scope.template_signature = scope.template_signature.clone();
            nested_scope.template_metadata = None;
            nested_scope.declarations_are_fields = false;
            nested_scope.recovered_specialization_member_scope = false;
            stack.push(CppWork::Container(CppContainer {
                node: body,
                scope: nested_scope,
            }));
        }
    }

    fn add_type_aliases(
        &mut self,
        node: Node<'_>,
        scope: &ScopeInfo,
        alias_names: Vec<String>,
        ancestry: &ParentIndex<'_>,
    ) {
        let signature = normalize_cpp_whitespace(node_text(node, self.source));
        self.record_type_aliases(
            node,
            scope,
            alias_names,
            signature,
            cpp_declaration_range(node),
            ancestry,
        );
    }

    fn record_type_aliases(
        &mut self,
        node: Node<'_>,
        scope: &ScopeInfo,
        alias_names: Vec<String>,
        signature: String,
        range: Range,
        ancestry: &ParentIndex<'_>,
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
            let code_unit = self.type_alias_unit(scope, alias_name, signature.clone());
            // Declaration identity does not include the alias signature. Keep
            // each physical range so conditional aliases retain their guards.
            self.add_declaration_with_range(code_unit.clone(), range, None, None);
            let lexical_scope = cpp_callable_lexical_scope(node, self.source, ancestry);
            let underlying_type_identity = node.child_by_field_name("type").and_then(|type_node| {
                cpp_structured_type_identity(type_node, self.source, &lexical_scope)
            });
            self.parsed.add_signature_with_metadata(
                code_unit.clone(),
                SignatureMetadata::new(signature.clone(), Vec::new())
                    .with_underlying_type_identity(underlying_type_identity),
            );
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

    fn type_alias_unit(
        &self,
        scope: &ScopeInfo,
        alias_name: String,
        signature: String,
    ) -> CodeUnit {
        let short_name = if let Some(parent) = &scope.class_unit {
            cpp_join_nested_short(parent.short_name(), &alias_name)
        } else {
            alias_name.clone()
        };
        let fq = cpp_leaf_fq(
            &scope.package_name,
            scope.class_unit.as_ref(),
            &alias_name,
            SegmentKind::Nested,
            SegmentKind::Type,
        );
        CodeUnit::with_signature_and_fq(
            self.file.clone(),
            CodeUnitType::Class,
            scope.package_name.clone(),
            short_name,
            Some(signature),
            false,
            fq,
        )
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
        // A macro can be undefined and redefined later in the same file. Its
        // structured directive is part of the declaration identity so the
        // temporal environment can navigate to the definition active at a
        // reference instead of collapsing every spelling to the first range.
        // The same physical directive parsed through another C/C++ reading
        // still produces the same unit and remains deduplicated.
        let code_unit = CodeUnit::with_signature_and_fq(
            self.file.clone(),
            CodeUnitType::Macro,
            "",
            name,
            Some(signature.clone()),
            false,
            fq,
        );
        if self.parsed.contains_declaration(&code_unit) {
            return;
        }
        self.add_declaration(code_unit.clone(), node, None, None);
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

/// Classify a C++ field while its declaration syntax is already available.
///
/// The persisted result lets later visibility queries avoid reparsing the
/// complete source file only to recover linkage.
pub fn cpp_field_declaration_linkage<'tree>(
    declaration: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> CppFieldLinkage {
    let mut current = ancestry.parent(declaration);
    let mut enclosed_by_class = false;
    while let Some(node) = current {
        if node.kind() == "namespace_definition"
            && node
                .child_by_field_name("name")
                .is_none_or(|name| normalize_cpp_whitespace(node_text(name, source)).is_empty())
        {
            return CppFieldLinkage::Internal;
        }
        if matches!(
            node.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) && node
            .child_by_field_name("name")
            .is_none_or(|name| normalize_cpp_whitespace(node_text(name, source)).is_empty())
        {
            return CppFieldLinkage::Internal;
        }
        if matches!(
            node.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) {
            enclosed_by_class = true;
        }
        if matches!(node.kind(), "function_definition" | "lambda_expression") {
            return CppFieldLinkage::Internal;
        }
        current = ancestry.parent(node);
    }
    if enclosed_by_class {
        return CppFieldLinkage::External;
    }
    let mut cursor = declaration.walk();
    let mut has_static = false;
    let mut has_extern = false;
    let mut has_inline = false;
    let mut has_const = false;
    let mut has_constexpr = false;
    for child in declaration.named_children(&mut cursor) {
        let text = normalize_cpp_whitespace(node_text(child, source));
        match (child.kind(), text.as_str()) {
            ("storage_class_specifier", "static") => has_static = true,
            ("storage_class_specifier", "extern") => has_extern = true,
            ("storage_class_specifier", "inline") => has_inline = true,
            ("storage_class_specifier", "constexpr") => has_constexpr = true,
            ("type_qualifier", "const") => has_const = true,
            ("type_qualifier", "constexpr") => has_constexpr = true,
            _ => {}
        }
    }
    if has_static {
        CppFieldLinkage::Internal
    } else if has_extern || has_inline {
        CppFieldLinkage::External
    } else if has_const || has_constexpr {
        CppFieldLinkage::InternalUnlessExternalPeer
    } else {
        CppFieldLinkage::External
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

/// A recovery interval as a [`Range`], for materialization records whose
/// window is a byte region rather than one parser node (the sentinel-macro
/// region reparses, issue #941/#1657).
fn cpp_recovery_window(source: &str, start_byte: usize, end_byte: usize) -> Range {
    let line_at = |byte: usize| {
        source.as_bytes()[..byte]
            .iter()
            .filter(|&&b| b == b'\n')
            .count()
            + 1
    };
    Range {
        start_byte,
        end_byte,
        start_line: line_at(start_byte),
        end_line: line_at(end_byte),
    }
}

/// Every `#include` directive the tree holds, in source order.
///
/// A preorder sweep rather than a step of the declaration walk: the container
/// walk descends only through declaration scopes, so an include written inside
/// a class body or a function body would otherwise never be seen, and an
/// include is an include wherever it is written.
pub fn collect_cpp_includes(root: Node<'_>, source: &str, parsed: &mut ParsedFile) {
    walk_named_tree_preorder(root, true, |node| {
        if node.kind() == "preproc_include" {
            let raw = normalize_cpp_whitespace(node_text(node, source));
            if !raw.is_empty() {
                parsed.imports.push(ImportInfo {
                    raw_snippet: raw,
                    is_wildcard: false,
                    is_global: false,
                    identifier: None,
                    alias: None,
                    path: None,
                    binder_span: None,
                });
            }
            return WalkControl::SkipChildren;
        }
        WalkControl::Continue
    });
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
        // The tree-sitter walk already recorded every `#include` it could see;
        // this line scan only recovers the ones a parse error hid, so skip a
        // snippet that is already an import binding.
        if parsed
            .imports
            .iter()
            .any(|import| import.raw_snippet == raw)
        {
            continue;
        }

        parsed.imports.push(ImportInfo {
            raw_snippet: raw,
            is_wildcard: false,
            is_global: false,
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
    owner: Option<CppMemberOwner>,
    name: String,
    signature: String,
}

/// Owner of a member function, kept structured so a literal `$` inside a
/// source-level class name never crosses a join/split boundary: the legacy
/// `$`-joined owner string was re-split at fq construction, dropping a leading
/// `$` (`$262Object` became `262Object` in the fq while short_name kept it)
/// and tripping the package/short boundary assert -- the #2140 corruption one
/// level up (#2362).
#[derive(Clone)]
enum CppMemberOwner {
    /// Source-level owner class chain from a qualified declarator-id, one
    /// class name per component (`Outer::Inner::method` -> `["Outer",
    /// "Inner"]`); each component may itself contain a literal `$`.
    Chain(Vec<String>),
    /// The lexically enclosing or recovered class unit; the member fq extends
    /// its fq directly instead of re-splitting its `$`-joined short chain.
    Unit(CodeUnit),
}

impl CppMemberOwner {
    /// The legacy `$`-joined owner chain used in the member's short name.
    fn short_chain(&self) -> String {
        match self {
            Self::Chain(chain) => chain.join("$"),
            Self::Unit(parent) => parent.short_name().to_string(),
        }
    }
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
        let short_name = match &self.owner {
            Some(owner) => cpp_join_member_short(&owner.short_chain(), &self.name),
            None => self.name.clone(),
        };
        let fq = match &self.owner {
            Some(CppMemberOwner::Chain(chain)) => {
                debug_assert!(
                    !chain.is_empty(),
                    "an empty owner chain is no owner; producers return None instead"
                );
                let mut fq = FqName::new();
                cpp_push_package(&mut fq, &self.package_name);
                let mut first = true;
                for component in chain {
                    let kind = if first {
                        SegmentKind::Type
                    } else {
                        SegmentKind::Nested
                    };
                    fq.push(cpp_segment(component, kind));
                    first = false;
                }
                fq.push(cpp_segment(&self.name, SegmentKind::Member));
                fq
            }
            Some(CppMemberOwner::Unit(parent)) if !parent.short_name().is_empty() => parent
                .fq()
                .clone()
                .with_pushed(cpp_segment(&self.name, SegmentKind::Member)),
            // An anonymous parent (empty short chain) contributes no owner
            // segment -- the same guard as cpp_join_member_short above.
            Some(CppMemberOwner::Unit(_)) | None => {
                let mut fq = FqName::new();
                cpp_push_package(&mut fq, &self.package_name);
                fq.push(cpp_segment(&self.name, SegmentKind::Member));
                fq
            }
        };
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
    let declarator_name_node = declarator
        .child_by_field_name("declarator")
        .or_else(|| parameters_node.prev_named_sibling())?;
    extract_function_info_from_name(declarator, declarator_name_node, source, scope)
}

fn extract_function_info_from_name(
    declarator: Node<'_>,
    declarator_name_node: Node<'_>,
    source: &str,
    scope: &ScopeInfo,
) -> Option<FunctionInfo> {
    let parameters_node = declarator.child_by_field_name("parameters")?;
    let parameters_text = cpp_parameter_signature(parameters_node, source);
    let recovered_specialization_member = scope
        .recovered_specialization_member_scope
        .then(|| {
            let terminal = declarator_name_node
                .child_by_field_name("name")
                .unwrap_or(declarator_name_node);
            let name = canonical_cpp_qualified_component(terminal, source)?.name;
            let owner = scope.class_unit.as_ref()?;
            Some((
                Some(CppMemberOwner::Unit(owner.clone())),
                name,
                scope.package_name.clone(),
            ))
        })
        .flatten();
    let (owner, name, package_name) = if let Some(parts) = recovered_specialization_member {
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
    let suffix = cpp_declarator_identity_suffix(declarator, parameters_node, source);
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
        owner,
        name,
        signature,
    })
}

/// Recover the semantic return type and callable name when a declaration macro
/// occupies a function definition's `type` field. Tree-sitter either exposes a
/// scalar return as the declarator's apparent name and the callable as the sole
/// identifier in an `ERROR`, or joins a template return and callable into a
/// qualified identifier with a missing `::`. Both shapes retain the complete
/// parameter list and body; a concrete separator remains an out-of-line member.
fn cpp_macro_displaced_callable_parts<'tree>(
    function_declarator: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> Option<(Node<'tree>, Node<'tree>)> {
    let definition = ancestry.parent(function_declarator)?;
    if definition.kind() != "function_definition"
        || definition.child_by_field_name("declarator") != Some(function_declarator)
        || definition
            .child_by_field_name("body")
            .is_none_or(|body| body.kind() != "compound_statement")
    {
        return None;
    }
    let macro_type = definition.child_by_field_name("type")?;
    if macro_type.kind() != "type_identifier"
        || !cpp_export_macro_token(&normalize_cpp_whitespace(node_text(macro_type, source)))
    {
        return None;
    }

    let apparent_return_type = function_declarator.child_by_field_name("declarator")?;
    if apparent_return_type.kind() == "qualified_identifier"
        && let (Some(return_type), Some(callable_name)) = (
            apparent_return_type.child_by_field_name("scope"),
            apparent_return_type.child_by_field_name("name"),
        )
        && return_type.kind() == "template_type"
        && matches!(callable_name.kind(), "identifier" | "field_identifier")
        && (0..apparent_return_type.child_count())
            .filter_map(|index| apparent_return_type.child(index))
            .any(|child| child.kind() == "::" && child.is_missing())
        && !normalize_cpp_whitespace(node_text(return_type, source)).is_empty()
        && !normalize_cpp_whitespace(node_text(callable_name, source)).is_empty()
    {
        return Some((return_type, callable_name));
    }
    if !matches!(
        apparent_return_type.kind(),
        "identifier" | "field_identifier" | "type_identifier"
    ) || normalize_cpp_whitespace(node_text(apparent_return_type, source)).is_empty()
    {
        return None;
    }
    let parameters = function_declarator.child_by_field_name("parameters")?;
    let mut cursor = function_declarator.walk();
    let between = function_declarator
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
        .filter(|child| {
            child.start_byte() >= apparent_return_type.end_byte()
                && child.end_byte() <= parameters.start_byte()
                && !same_node(*child, apparent_return_type)
                && !same_node(*child, parameters)
        })
        .collect::<Vec<_>>();
    let [name_error] = between.as_slice() else {
        return None;
    };
    if name_error.kind() != "ERROR" || name_error.named_child_count() != 1 {
        return None;
    }
    let callable_name = name_error.named_child(0)?;
    if !matches!(callable_name.kind(), "identifier" | "field_identifier")
        || normalize_cpp_whitespace(node_text(callable_name, source)).is_empty()
    {
        return None;
    }
    Some((apparent_return_type, callable_name))
}

/// The part of a `function_declarator` after its parameter list that belongs to
/// the callable's identity: the cv-qualifiers, the ref-qualifier, the exception
/// specification, a trailing return type and a trailing requires-clause.
///
/// The grammar makes each of these a distinct sibling of the `parameters`
/// field, so they are read from the tree. Splitting the declarator's text on
/// the parameter list instead silently dropped every qualifier whenever the
/// parameter list was spelled with whitespace that normalization rewrote - a
/// line break or a double space was enough to make a `const` member definition
/// a different logical symbol from its declaration (#1827).
///
/// Attributes, `asm` blocks and the virtual specifiers (`override`, `final`)
/// are deliberately excluded. C++ does not make them part of the signature and
/// an out-of-line definition never repeats them, so including them would split
/// a declaration from its own definition.
fn cpp_declarator_identity_suffix(
    declarator: Node<'_>,
    parameters_node: Node<'_>,
    source: &str,
) -> String {
    let mut cursor = declarator.walk();
    let parts = declarator
        .named_children(&mut cursor)
        .filter(|child| child.start_byte() >= parameters_node.end_byte())
        .filter(|child| {
            matches!(
                child.kind(),
                "type_qualifier"
                    | "ref_qualifier"
                    | "noexcept"
                    | "throw_specifier"
                    | "trailing_return_type"
                    | "requires_clause"
            )
        })
        .map(|child| normalize_cpp_whitespace(node_text(child, source)))
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>();
    normalize_cpp_qualifier_suffix(&parts.join(" "))
}

/// The identity suffix of one callable declarator, for a consumer that holds
/// the declarator rather than the declaration walk's parts.
///
/// The persisted signature concatenates the parameter spelling and this suffix,
/// so a comparison that must agree on the suffix alone recomputes it here
/// instead of splitting the stored string.
pub(crate) fn cpp_callable_identity_suffix(
    function_declarator: Node<'_>,
    source: &str,
) -> Option<String> {
    let parameters_node = function_declarator.child_by_field_name("parameters")?;
    Some(cpp_declarator_identity_suffix(
        function_declarator,
        parameters_node,
        source,
    ))
}

pub(crate) fn extract_function_declarator(node: Node<'_>) -> Option<Node<'_>> {
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

/// One namespace-scope forward class declaration that a recovered export-macro
/// class definition may borrow its identity from.  Tree-sitter can close a
/// malformed class at the enclosing namespace's closing brace, leaving the later
/// class definitions as root-level recovered `function_definition` nodes.  A
/// preceding `class Name;` in the same namespace is the only structured identity
/// signal available in that shape.
///
/// Everything recorded here is a property of the forward declaration alone.
/// What depends on the node doing the asking -- that the forward and its
/// namespace both close before it, with nothing but recovery trivia between --
/// stays in [`cpp_namespace_forward_matches_recovery`], so one fold over the
/// tree answers every later question about it.
struct CppNamespaceForward {
    name: String,
    start_byte: usize,
    /// Where the malformed namespace that held the forward ended.  No query
    /// asks anything else about that node.
    namespace_end_byte: usize,
    package_name: String,
}

/// Read `node` as a borrowable namespace forward declaration.
///
/// The admission is deliberately conservative: only a body-less class specifier
/// whose declaration has no declarator, at namespace scope rather than inside a
/// function or class body, in a namespace that itself failed to parse.
fn cpp_namespace_forward_entry<'tree>(
    node: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> Option<CppNamespaceForward> {
    if !matches!(
        node.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier"
    ) || cpp_body_node(node).is_some()
    {
        return None;
    }
    let parent = node.parent()?;
    if !(parent.kind() == "declaration_list"
        || parent.kind() == "declaration" && !has_direct_cpp_declarator(parent))
    {
        return None;
    }
    let namespace = cpp_namespace_definition_for_forward(node, ancestry)?;
    // Borrowing is only justified by the parser-recovery shape we are
    // repairing: the namespace that held the forward must itself contain a
    // syntax error. A clean, unrelated namespace forward is not an identity
    // proof.
    if !namespace.has_error() {
        return None;
    }
    Some(CppNamespaceForward {
        name: class_like_name(node, source, ancestry)?,
        start_byte: node.start_byte(),
        namespace_end_byte: namespace.end_byte(),
        package_name: cpp_namespace_name_for_forward(node, source, ancestry)?,
    })
}

/// Whether `forward` stands in the recovery relation to the node asking about
/// it: it and its malformed namespace both closed before the recovered class,
/// and nothing but recovery trivia separates the two.
fn cpp_namespace_forward_matches_recovery(
    forward: &CppNamespaceForward,
    recovered_node: Node<'_>,
) -> bool {
    forward.start_byte < recovered_node.start_byte()
        && forward.namespace_end_byte < recovered_node.start_byte()
        && malformed_namespace_is_nearest_recovery_region(
            forward.namespace_end_byte,
            recovered_node,
        )
}

/// What one open [`CppVisitor::record_recovered_declarations`] has watched
/// happen to the declaration set.
///
/// The recovered set used to be a difference against a clone of the whole
/// declaration set, taken once per recovery: O(recoveries x declarations) on
/// exactly the error-recovered files that already walk slowest (#2787). The
/// walk knows which declarations it creates, so the capture collects them as
/// they are made and the difference is never needed.
///
/// `removed_pre_existing` is what makes that equal to the difference. A
/// deferred replacement removes the replaced declaration's children
/// (`ParsedFile::prepare_deferred_replacement`), and the reparse walk then
/// re-creates them. Creation alone cannot tell that apart from a first mint, so
/// a removal of a declaration this capture did not create records that it was
/// already there when the capture opened.
#[derive(Debug, Default)]
pub struct CppRecoveryCapture {
    /// Declarations created while this capture was open, in creation order.
    created: Vec<CodeUnit>,
    /// Membership for `created`.
    created_units: HashSet<CodeUnit>,
    /// Declarations that predate this capture and have been removed during it.
    removed_pre_existing: HashSet<CodeUnit>,
}

/// Which owners the parse product already holds field declarations for, folded
/// in as the walk records them.
///
/// [`CppVisitor::has_enum_enumerator_units`] asks that question once per enum
/// and used to answer it by scanning every declaration accumulated so far:
/// O(enums x declarations) on exactly the generated headers that declare many
/// of both (#2786). The answer only grows by declaration, so the walk carries
/// it. A field's short name names its owner chain, `Owner.member`, so one field
/// answers for every dotted prefix of its own short name; an anonymous enum's
/// or union's enumerators carry bare short names instead (#2140), which is what
/// an empty owner short name asks about.
#[derive(Debug, Default)]
pub struct CppFieldOwnerIndex {
    /// Package name -> the owner short names its fields name.
    owners: HashMap<String, HashSet<String>>,
    /// Packages holding at least one field that names no owner.
    ownerless_packages: HashSet<String>,
}

impl CppFieldOwnerIndex {
    /// The index of the declarations recorded so far, built when the first
    /// question arrives.
    fn of<'unit>(
        declarations: impl IntoIterator<Item = &'unit CodeUnit>,
        file: &ProjectFile,
    ) -> Self {
        let mut index = Self::default();
        for declaration in declarations {
            index.record(declaration, file);
        }
        index
    }

    fn record(&mut self, code_unit: &CodeUnit, file: &ProjectFile) {
        if code_unit.kind() != CodeUnitType::Field || code_unit.source() != file {
            return;
        }
        let short_name = code_unit.short_name();
        let package_name = code_unit.package_name();
        if !short_name.contains(['.', '$']) && !self.ownerless_packages.contains(package_name) {
            self.ownerless_packages.insert(package_name.to_string());
        }
        if !short_name.contains('.') {
            return;
        }
        if !self.owners.contains_key(package_name) {
            self.owners
                .insert(package_name.to_string(), HashSet::default());
        }
        let owners = self
            .owners
            .get_mut(package_name)
            .expect("the package entry was just ensured");
        for (offset, _) in short_name.match_indices('.') {
            let owner = &short_name[..offset];
            if !owners.contains(owner) {
                owners.insert(owner.to_string());
            }
        }
    }

    /// Whether a field declaration in `package_name` names `owner_short_name`
    /// as its owner. An empty owner asks about ownerless fields instead.
    fn owns_fields(&self, package_name: &str, owner_short_name: &str) -> bool {
        if owner_short_name.is_empty() {
            self.ownerless_packages.contains(package_name)
        } else {
            self.owners
                .get(package_name)
                .is_some_and(|owners| owners.contains(owner_short_name))
        }
    }
}

/// The declaration scan [`CppFieldOwnerIndex`] replaces, kept as the oracle a
/// debug build asserts every carried answer against and as the release-mode
/// parity tests' reference (#2786).
#[cfg(any(debug_assertions, test))]
fn cpp_declarations_hold_owned_fields<'unit>(
    declarations: impl IntoIterator<Item = &'unit CodeUnit>,
    file: &ProjectFile,
    package_name: &str,
    owner_short_name: &str,
) -> bool {
    let prefix = format!("{owner_short_name}.");
    declarations.into_iter().any(|unit| {
        unit.kind() == CodeUnitType::Field
            && unit.source() == file
            && unit.package_name() == package_name
            && if owner_short_name.is_empty() {
                // Anonymous enum/union parent: its enumerators carry bare
                // short names (#2140), so presence means any ownerless
                // field in this file.
                !unit.short_name().contains(['.', '$'])
            } else {
                unit.short_name().starts_with(&prefix)
            }
    })
}

/// Which tree a [`CppNamespaceForwardScan`] was folded out of.
///
/// A region reparse is its own tree and is dropped while the walk that made it
/// continues, so a later parse can be allocated at the same address and hand out
/// the same node ids.  The root's span and shape pin the identity its address
/// alone does not: two roots agreeing on all of this are the same parse of the
/// same bytes, and a scan of one is a scan of the other.
#[derive(PartialEq, Eq, Hash)]
pub struct CppTreeIdentity {
    root_id: usize,
    start_byte: usize,
    end_byte: usize,
    kind_id: u16,
    child_count: usize,
}

impl CppTreeIdentity {
    fn of(root: Node<'_>) -> Self {
        Self {
            root_id: root.id(),
            start_byte: root.start_byte(),
            end_byte: root.end_byte(),
            kind_id: root.kind_id(),
            child_count: root.child_count(),
        }
    }
}

/// The namespace forward declarations one tree's prefix holds, folded in as the
/// walk asks about them.
///
/// `scope_for_recovered_exported_class` asks the same question once per
/// recovered class, and the answer depends only on the part of the tree that
/// starts before the asking node.  Rescanning that prefix per question is
/// quadratic in the file, and a generated header whose parse recovery leaves
/// thousands of class-like declarations at file scope pays all of it: 1,904
/// questions over 1.13 billion node visits on one 7.25 MB Vulkan header
/// (#2754).  This carries the scan forward instead.  Each question advances the
/// traversal from wherever the last one stopped to the asking node's start byte,
/// so a whole walk pays at most one pass over the prefix its furthest question
/// reaches, and each question then costs a name lookup.
#[derive(Default)]
pub struct CppNamespaceForwardScan {
    /// Every named node starting before this byte has been folded in.
    scanned_through: usize,
    forwards: HashMap<String, Vec<CppNamespaceForward>>,
}

impl CppNamespaceForwardScan {
    /// Fold in every named node of `root` that starts at or after the fold
    /// watermark and before `cutoff`.
    ///
    /// Preorder over a tree is nondecreasing in start byte, so the nodes this
    /// pass owes are exactly the ones no earlier pass reached, and a question
    /// about an earlier byte than one already answered costs nothing.
    fn advance_to<'tree>(
        &mut self,
        root: Node<'tree>,
        cutoff: usize,
        source: &str,
        ancestry: &ParentIndex<'tree>,
    ) {
        if cutoff <= self.scanned_through {
            return;
        }
        let folded_through = self.scanned_through;
        let mut cursor = root.walk();
        let mut stack = vec![root];
        while let Some(current) = stack.pop() {
            if (folded_through..cutoff).contains(&current.start_byte())
                && let Some(forward) = cpp_namespace_forward_entry(current, source, ancestry)
            {
                self.forwards
                    .entry(forward.name.clone())
                    .or_default()
                    .push(forward);
            }
            // A subtree ending before the watermark holds only nodes an earlier
            // pass already folded, and one starting at or after the cutoff is
            // outside the prefix being asked about. Skipping both is what keeps
            // the total traversal to one pass.
            for child in current.named_children(&mut cursor) {
                if child.start_byte() < cutoff && child.end_byte() >= folded_through {
                    stack.push(child);
                }
            }
        }
        self.scanned_through = cutoff;
    }

    /// The one namespace `name` was forward declared in before `recovered_node`.
    /// More than one matching forward declaration is ambiguous and answers
    /// nothing rather than guessing.
    fn unique_earlier_forward(&self, name: &str, recovered_node: Node<'_>) -> Option<String> {
        let mut matching = self
            .forwards
            .get(name)
            .into_iter()
            .flatten()
            .filter(|forward| cpp_namespace_forward_matches_recovery(forward, recovered_node));
        let first = matching.next()?;
        matching
            .next()
            .is_none()
            .then(|| first.package_name.clone())
    }
}

/// The prefix scan [`CppNamespaceForwardScan`] replaces, kept as the oracle a
/// debug build checks every answer against (and the one the parity tests drive
/// directly).  It walks the whole prefix per question, which is exactly the cost
/// #2754 removed from the release path.
#[cfg(any(debug_assertions, test))]
fn unique_earlier_cpp_namespace_forward<'tree>(
    recovered_node: Node<'tree>,
    name: &str,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> Option<String> {
    let mut root = recovered_node;
    while let Some(parent) = ancestry.parent(root) {
        root = parent;
    }

    let mut candidates = Vec::new();
    let mut stack = vec![root];
    while let Some(current) = stack.pop() {
        if current.start_byte() < recovered_node.start_byte()
            && let Some(forward) = cpp_namespace_forward_entry(current, source, ancestry)
            && forward.name == name
            && cpp_namespace_forward_matches_recovery(&forward, recovered_node)
        {
            candidates.push(forward.package_name);
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
    namespace_end_byte: usize,
    recovered_node: Node<'_>,
) -> bool {
    let mut root = recovered_node;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let mut cursor = root.walk();
    root.named_children(&mut cursor)
        .filter(|sibling| {
            namespace_end_byte <= sibling.start_byte()
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
fn cpp_namespace_name_for_forward<'tree>(
    node: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> Option<String> {
    cpp_namespace_definition_for_forward(node, ancestry)?;
    cpp_lexical_namespace_name(node, source, ancestry)
}

fn cpp_namespace_definition_for_forward<'tree>(
    node: Node<'tree>,
    ancestry: &ParentIndex<'tree>,
) -> Option<Node<'tree>> {
    let declaration = ancestry.parent(node)?;
    let mut ancestor = ancestry.parent(declaration);
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
        ancestor = ancestry.parent(current);
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

fn split_cpp_name(raw_name: &str, scope: &ScopeInfo) -> (Option<CppMemberOwner>, String, String) {
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
                Some(CppMemberOwner::Unit(class_unit.clone())),
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
            let owner = (!nested.is_empty()).then(|| {
                CppMemberOwner::Chain(nested.iter().map(|name| name.to_string()).collect())
            });
            return (owner, name, scope.package_name.clone());
        }
        // File scope (no enclosing `namespace {}` block, scope package empty).
        let (owner, package_name) = if owner_parts.len() > 1 {
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
                Some(CppMemberOwner::Chain(vec![
                    owner_parts.last().unwrap_or(&"").to_string(),
                ])),
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
                Some(CppMemberOwner::Chain(vec![owner_parts[0].to_string()])),
                cpp_using_directive_namespace_for_bare_owner(scope),
            )
        };
        return (owner, name, package_name);
    }

    let package_name = scope.package_name.clone();
    let owner = scope
        .class_unit
        .as_ref()
        .map(|parent| CppMemberOwner::Unit(parent.clone()));
    (owner, cleaned.to_string(), package_name)
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

/// Canonical nested-class chain for an out-of-line class definition written
/// inside its namespace, such as `struct Outer::Inner { ... }`, as one
/// component per class (`["Outer", "Inner"]`).
///
/// The enclosing namespace fixes the namespace/class boundary: after an
/// optional redundant spelling of that namespace, every component belongs to
/// the class chain. File-scope qualified class names remain untouched because
/// syntax alone cannot distinguish `namespace::Class` from `Outer::Inner`.
///
/// The components stay structured (rather than being `$`-joined here) so the
/// fq construction can push one Type/Nested segment per class; the `$`-joined
/// short-name display form is derived at the call sites that need it.
fn qualified_class_name_chain(
    class_node: Node<'_>,
    source: &str,
    scope: &ScopeInfo,
) -> Option<Vec<String>> {
    if scope.package_name.is_empty() || scope.class_unit.is_some() {
        return None;
    }
    let name = class_node.child_by_field_name("name")?;
    let (components, explicitly_global) = structured_cpp_qualified_components(name, source)?;
    if explicitly_global
        || components.len() < 2
        || components.iter().any(|component| component.is_template_id)
    {
        return None;
    }
    let names = components
        .iter()
        .map(|component| component.name.as_str())
        .collect::<Vec<_>>();
    let class_chain = strip_redundant_namespace_prefix(&names, &scope.package_name);
    if class_chain.is_empty() {
        return None;
    }
    Some(class_chain.iter().map(|name| name.to_string()).collect())
}

fn structured_cpp_qualified_components(
    qualified_name: Node<'_>,
    source: &str,
) -> Option<(Vec<CppQualifiedNameComponent>, bool)> {
    if qualified_name.kind() != "qualified_identifier" {
        return None;
    }

    let mut components = Vec::new();
    let mut current = qualified_name;
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
    Some((components, explicitly_global))
}

fn split_structured_templated_cpp_name(
    declarator_name: Node<'_>,
    source: &str,
    scope: &ScopeInfo,
) -> Option<(Option<CppMemberOwner>, String, String)> {
    let (mut components, explicitly_global) =
        structured_cpp_qualified_components(declarator_name, source)?;

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
    let owner_chain = components[owner_start..]
        .iter()
        .map(|component| component.name.clone())
        .collect::<Vec<_>>();
    if owner_chain.is_empty() || terminal.name.is_empty() {
        return None;
    }

    Some((
        Some(CppMemberOwner::Chain(owner_chain)),
        terminal.name,
        package_name,
    ))
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
    if let Some(name) = macro_decorated_unqualified_name(node) {
        return extract_declarator_name(name, source);
    }
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
    if let Some(name) = macro_decorated_unqualified_name(node) {
        return extract_callable_declarator_name(name, source);
    }
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

fn render_cpp_function_display_signature_from_node<'tree>(
    node: Node<'tree>,
    source: &str,
    template_signature: Option<&str>,
    has_body: bool,
    ancestry: &ParentIndex<'tree>,
) -> String {
    let root = enclosing_cpp_declaration_node(node, ancestry).unwrap_or(node);
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
    ancestry: &ParentIndex<'tree>,
) -> Option<RecoveredFragmentedPreprocessorClass<'tree>> {
    let alternative = ancestry.parent(template_node)?;
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
    let name = class_like_name(class_node, source, ancestry)?;
    let is_partial_specialization = class_node
        .child_by_field_name("name")
        .is_some_and(|class_name| class_name.kind() == "template_type");
    if is_partial_specialization {
        let metadata = cpp_template_metadata(template_node, class_node, source, ancestry)?;
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
                    && class_like_name(candidate, source, ancestry).as_deref()
                        == Some(name.as_str())
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

/// The real `#endif` that tree-sitter consumed inside an error subtree.
///
/// A preprocessor directive inside a malformed array bound can cause later
/// declarations to remain children of the conditional. The non-missing token
/// still gives the exact structured boundary. Ignore nested conditionals and
/// select the last error-owned token. Tree-sitter can pair a later outer
/// `#endif` with this conditional, so the direct terminator is not necessarily
/// missing.
pub fn cpp_displaced_preprocessor_terminator<'tree>(
    conditional: Node<'tree>,
) -> Option<Node<'tree>> {
    if !conditional.has_error() {
        return None;
    }
    let has_concrete_direct_terminator = conditional
        .child_count()
        .checked_sub(1)
        .and_then(|index| conditional.child(index))
        .is_some_and(|child| child.kind() == "#endif" && !child.is_missing());
    if has_concrete_direct_terminator && conditional.child_by_field_name("alternative").is_some() {
        // A structured alternative proves that the direct `#endif` closes
        // this family. An error-owned terminator inside either branch belongs
        // to a damaged nested conditional, not to this one.
        return None;
    }
    let mut displaced = None;
    let mut stack = (0..conditional.child_count())
        .filter_map(|index| conditional.child(index))
        .map(|child| (child, false))
        .collect::<Vec<_>>();
    while let Some((node, inside_error)) = stack.pop() {
        if !inside_error && node.kind() != "ERROR" && !node.has_error() {
            continue;
        }
        if node.kind() == "#endif" && !node.is_missing() && inside_error {
            if displaced.is_none_or(|current: Node<'_>| node.end_byte() > current.end_byte()) {
                displaced = Some(node);
            }
            continue;
        }
        if node != conditional
            && matches!(
                node.kind(),
                "preproc_if" | "preproc_ifdef" | "preproc_ifndef" | "preproc_elif"
            )
        {
            continue;
        }
        let inside_error = inside_error || node.kind() == "ERROR";
        for index in 0..node.child_count() {
            if let Some(child) = node.child(index) {
                stack.push((child, inside_error));
            }
        }
    }
    displaced
}

/// The effective end of a conditional whose real terminator tree-sitter
/// displaced into declaration recovery.
///
/// Most damaged conditionals retain a concrete `#endif` token below an
/// `ERROR`; [`cpp_displaced_preprocessor_terminator`] supplies that exact
/// boundary. A preprocessor family that selects the middle of a declaration
/// can lose the directive tokens entirely. In that shape tree-sitter leaves
/// the declaration's `typedef` token as the sole child of the immediately
/// preceding top-level `ERROR`, and puts a multiline `ERROR` plus the trailing
/// declarator name inside the conditional's first declaration. The declaration
/// end is then the smallest structured boundary that contains the whole split
/// declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CppDisplacedPreprocessorBoundary {
    pub end_byte: usize,
    pub end_line: usize,
}

pub fn cpp_displaced_preprocessor_boundary(
    conditional: Node<'_>,
) -> Option<CppDisplacedPreprocessorBoundary> {
    if let Some(terminator) = displaced_declaration_prefix_terminator(conditional) {
        return Some(CppDisplacedPreprocessorBoundary {
            end_byte: terminator.end_byte(),
            end_line: terminator.end_position().row + 1,
        });
    }
    if let Some(declaration) = displaced_split_declaration(conditional) {
        return Some(CppDisplacedPreprocessorBoundary {
            end_byte: declaration.end_byte(),
            end_line: declaration.end_position().row + 1,
        });
    }
    if let Some(terminator) = displaced_nested_conditional_terminator(conditional) {
        return Some(CppDisplacedPreprocessorBoundary {
            end_byte: terminator.end_byte(),
            end_line: terminator.end_position().row + 1,
        });
    }
    if let Some(terminator) = cpp_displaced_preprocessor_terminator(conditional) {
        return Some(CppDisplacedPreprocessorBoundary {
            end_byte: terminator.end_byte(),
            end_line: terminator.end_position().row + 1,
        });
    }
    None
}

/// Recover an outer terminator that tree-sitter assigned to a damaged nested
/// conditional. This occurs when a split construct such as `extern "C"`
/// consumes the nested `#endif` inside an error node: the nested conditional's
/// direct terminator is then the outer conditional's real terminator, while
/// the outer node ends with a missing token and absorbs later declarations.
fn displaced_nested_conditional_terminator<'tree>(conditional: Node<'tree>) -> Option<Node<'tree>> {
    if !conditional.has_error()
        || conditional.child_by_field_name("alternative").is_some()
        || conditional
            .child(conditional.child_count().saturating_sub(1))
            .is_none_or(|child| child.kind() != "#endif" || !child.is_missing())
    {
        return None;
    }
    let mut recovered = None;
    for index in 0..conditional.named_child_count() {
        let Some(nested) = conditional.named_child(index) else {
            continue;
        };
        if !matches!(
            nested.kind(),
            "preproc_if" | "preproc_ifdef" | "preproc_ifndef"
        ) || nested.child_by_field_name("alternative").is_some()
        {
            continue;
        }
        let Some(direct) = nested.child(nested.child_count().saturating_sub(1)) else {
            continue;
        };
        if direct.kind() != "#endif" || direct.is_missing() {
            continue;
        }
        let Some(displaced) = cpp_displaced_preprocessor_terminator(nested) else {
            continue;
        };
        if displaced.end_byte() >= direct.start_byte() {
            continue;
        }
        if recovered.is_none_or(|current: Node<'_>| direct.end_byte() > current.end_byte()) {
            recovered = Some(direct);
        }
    }
    recovered
}

fn displaced_declaration_prefix_terminator<'tree>(conditional: Node<'tree>) -> Option<Node<'tree>> {
    if !conditional.has_error() || conditional.child_by_field_name("alternative").is_some() {
        return None;
    }
    let mut cursor = conditional.walk();
    let declarations = conditional
        .named_children(&mut cursor)
        .filter(|child| matches!(child.kind(), "declaration" | "function_definition"))
        .collect::<Vec<_>>();
    let declaration = *declarations.first()?;
    if declaration.end_byte() >= conditional.end_byte() || declarations.len() < 2 {
        return None;
    }
    let declarator_start = declaration.child_by_field_name("declarator")?.start_byte();
    let mut terminator = None;
    let mut stack = (0..declaration.child_count())
        .filter_map(|index| declaration.child(index))
        .filter(|child| child.start_byte() < declarator_start)
        .map(|child| (child, false))
        .collect::<Vec<_>>();
    while let Some((node, inside_error)) = stack.pop() {
        let inside_error = inside_error || node.kind() == "ERROR";
        if inside_error && node.kind() == "#endif" && !node.is_missing() {
            terminator = Some(node);
            continue;
        }
        for index in 0..node.child_count() {
            if let Some(child) = node.child(index)
                && child.start_byte() < declarator_start
            {
                stack.push((child, inside_error));
            }
        }
    }
    terminator
}

fn displaced_split_declaration<'tree>(conditional: Node<'tree>) -> Option<Node<'tree>> {
    if !conditional.has_error()
        || conditional.child_by_field_name("alternative").is_some()
        || conditional
            .prev_named_sibling()
            .filter(|sibling| {
                sibling.kind() == "ERROR"
                    && sibling.child_count() == 1
                    && sibling
                        .child(0)
                        .is_some_and(|child| child.kind() == "typedef")
            })
            .filter(|sibling| sibling.end_position().row + 1 == conditional.start_position().row)
            .is_none()
    {
        return None;
    }
    let mut cursor = conditional.walk();
    let children = conditional.named_children(&mut cursor).collect::<Vec<_>>();
    let declaration_index = children
        .iter()
        .position(|child| child.kind() == "declaration" && child.has_error())?;
    let declaration = children[declaration_index];
    if !children
        .iter()
        .skip(declaration_index + 1)
        .any(|child| child.end_byte() > declaration.end_byte())
    {
        return None;
    }
    let declarator = declaration.child_by_field_name("declarator")?;
    let mut error_end = None;
    let mut names = Vec::new();
    let mut stack = vec![declarator];
    while let Some(node) = stack.pop() {
        if node.kind() == "ERROR" && node.end_position().row > node.start_position().row {
            error_end =
                Some(error_end.map_or(node.end_byte(), |end: usize| end.max(node.end_byte())));
            continue;
        }
        if matches!(node.kind(), "identifier" | "type_identifier") {
            names.push(node.start_byte());
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    let error_end = error_end?;
    names
        .into_iter()
        .any(|start| start >= error_end)
        .then_some(declaration)
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
    ancestry: &ParentIndex<'tree>,
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
    let metadata = cpp_template_metadata(template_node, declaration_child, source, ancestry)?;
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
            // A namespace can never be a class member: reaching one before the
            // terminator proves the class's true close was swallowed upstream
            // and this scan has crossed into the enclosing scope, so the
            // recovery cannot be bounded -- continuing re-owns the namespace
            // block (and its template specializations) as class members under
            // a re-appended package, desyncing the fq boundary (#2306).
            if found_template && child.kind() == "namespace_definition" {
                return None;
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

fn cpp_template_metadata<'tree>(
    template_node: Node<'tree>,
    declaration_child: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
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
        if !matches!(
            parameter.kind(),
            "type_parameter_declaration"
                | "optional_type_parameter_declaration"
                | "variadic_type_parameter_declaration"
                | "template_template_parameter_declaration"
                | "parameter_declaration"
                | "optional_parameter_declaration"
                | "variadic_parameter_declaration"
        ) {
            continue;
        }
        let index = parameter_nodes.len();
        // An unnamed parameter still contributes template arity and kind. Use
        // an impossible C++ identifier so positional reconciliation can bind
        // it without making source expressions refer to a name that was not
        // written.
        let name = cpp_template_parameter_name(parameter, source)
            .unwrap_or_else(|| format!("<anonymous:{index}>"));
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
            default: cpp_template_parameter_default_expression(
                parameter,
                source,
                &parameter_names,
                ancestry,
            ),
        })
        .collect();
    let specialization_arguments = if declaration_child.kind() == "alias_declaration" {
        Vec::new()
    } else {
        cpp_template_argument_expressions(name_node, source, &parameter_names, ancestry)
            .unwrap_or_default()
    };
    let alias_target = (declaration_child.kind() == "alias_declaration")
        .then(|| cpp_template_alias_target(declaration_child, source, &parameter_names, ancestry))
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

fn cpp_template_alias_target<'tree>(
    alias: Node<'tree>,
    source: &str,
    parameter_names: &[String],
    ancestry: &ParentIndex<'tree>,
) -> Option<CppTemplateAliasTargetMetadata> {
    let mut type_node = alias.child_by_field_name("type")?;
    while type_node.kind() == "type_descriptor" {
        type_node = type_node.child_by_field_name("type")?;
    }
    let global = type_node.child_by_field_name("scope").is_none()
        && type_node.child(0).is_some_and(|child| child.kind() == "::");
    let mut components = Vec::new();
    cpp_template_target_components(type_node, source, &mut components)?;
    let arguments = cpp_template_argument_expressions(type_node, source, parameter_names, ancestry);
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

fn cpp_template_argument_expressions<'tree>(
    mut node: Node<'tree>,
    source: &str,
    parameter_names: &[String],
    ancestry: &ParentIndex<'tree>,
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
                        .map(|argument| {
                            cpp_template_expression(argument, source, parameter_names, ancestry)
                        })
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

fn cpp_template_parameter_default_expression<'tree>(
    parameter: Node<'tree>,
    source: &str,
    parameter_names: &[String],
    ancestry: &ParentIndex<'tree>,
) -> Option<CppTemplateExpression> {
    let default = cpp_template_parameter_default(parameter)?;
    let base = cpp_template_expression(default, source, parameter_names, ancestry);
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

fn cpp_template_expression<'tree>(
    node: Node<'tree>,
    source: &str,
    parameter_names: &[String],
    ancestry: &ParentIndex<'tree>,
) -> CppTemplateExpression {
    let text = normalize_cpp_whitespace(node_text(node, source));
    CppTemplateExpression {
        text,
        term: cpp_template_term(node, source, parameter_names, ancestry),
    }
}

pub fn cpp_template_term<'tree>(
    node: Node<'tree>,
    source: &str,
    parameter_names: &[String],
    ancestry: &ParentIndex<'tree>,
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
                if cpp_template_term_leaf_is_parameter(current, &text, parameter_names, ancestry) {
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

fn cpp_template_term_leaf_is_parameter<'tree>(
    node: Node<'tree>,
    text: &str,
    parameter_names: &[String],
    ancestry: &ParentIndex<'tree>,
) -> bool {
    if !parameter_names.iter().any(|parameter| parameter == text) {
        return false;
    }
    !ancestry.parent(node).is_some_and(|parent| {
        matches!(
            parent.kind(),
            "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier"
        ) && parent.child_by_field_name("scope").is_some()
            && parent.child_by_field_name("name") == Some(node)
    })
}

fn enclosing_cpp_declaration_node<'tree>(
    mut node: Node<'tree>,
    ancestry: &ParentIndex<'tree>,
) -> Option<Node<'tree>> {
    loop {
        match node.kind() {
            "declaration"
            | "function_declaration"
            | "field_declaration"
            | "function_definition" => return Some(node),
            _ => node = ancestry.parent(node)?,
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

fn cpp_signature_metadata<'tree>(
    signature: String,
    function_declarator: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> SignatureMetadata {
    let dispatch = cpp_callable_dispatch_extensibility(function_declarator, ancestry);
    let enrich = |metadata: SignatureMetadata| metadata.with_dispatch_extensibility(dispatch);
    let return_type_text = cpp_callable_return_type_text(function_declarator, source, ancestry);
    let return_type_identity =
        cpp_callable_return_type_identity(function_declarator, source, ancestry);
    let Some(parameters_node) = function_declarator.child_by_field_name("parameters") else {
        return enrich(
            SignatureMetadata::new(signature, Vec::new())
                .with_return_type_text(return_type_text)
                .with_return_type_identity(return_type_identity),
        );
    };
    let callable_arity = cpp_callable_arity(parameters_node, source);
    let callable_parameter_types = cpp_callable_parameter_types(parameters_node, source);
    let parameter_text = normalize_cpp_whitespace(node_text(parameters_node, source));
    let search_from = cpp_signature_search_start(&signature, function_declarator, source, ancestry);
    let Some(relative_start) = signature
        .get(search_from..)
        .and_then(|suffix| suffix.find(&parameter_text))
    else {
        return enrich(
            SignatureMetadata::new(signature, Vec::new())
                .with_callable_arity(callable_arity)
                .with_callable_parameter_types(callable_parameter_types)
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
            .with_callable_parameter_types(callable_parameter_types)
            .with_return_type_text(return_type_text)
            .with_return_type_identity(return_type_identity),
    )
}

fn cpp_callable_is_structural_constructor<'tree>(
    function_declarator: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> bool {
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

    let mut current = ancestry.parent(function_declarator);
    while let Some(ancestor) = current {
        let owner_name = match ancestor.kind() {
            "class_specifier" | "struct_specifier" | "union_specifier" => {
                class_like_name(ancestor, source, ancestry)
            }
            "ERROR" => malformed_class_error_owner_name(ancestor, source),
            _ => None,
        };
        if owner_name.is_some_and(|owner_name| owner_name == callable_name) {
            return true;
        }
        current = ancestry.parent(ancestor);
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

/// The parser-derived return type of one callable declaration.
///
/// This accepts the enclosing declaration node so consumers do not need to
/// duplicate the declarator-unwrapping rules before asking for the structured
/// identity.
pub fn cpp_callable_declaration_return_type_identity<'tree>(
    callable: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> Option<StructuredTypeIdentity> {
    let declarator = callable
        .child_by_field_name("declarator")
        .and_then(extract_function_declarator)?;
    cpp_callable_return_type_identity(declarator, source, ancestry)
}

pub(crate) fn cpp_callable_return_type_identity<'tree>(
    function_declarator: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> Option<StructuredTypeIdentity> {
    if cpp_callable_is_structural_constructor(function_declarator, source, ancestry) {
        return None;
    }
    let lexical_scope = cpp_callable_lexical_scope(function_declarator, source, ancestry);
    if let Some((return_type, _)) =
        cpp_macro_displaced_callable_parts(function_declarator, source, ancestry)
    {
        return cpp_structured_type_identity(return_type, source, &lexical_scope);
    }
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
    while let Some(parent) = ancestry.parent(current) {
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
            "reference_declarator" => wrappers.push(cpp_reference_wrapper(parent)?),
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
                            wrappers.extend(cpp_structured_declarator_wrappers(child)?);
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
                    work.push(Work::Wrap(cpp_reference_wrapper(current)?));
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
                | "field_identifier"
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
    LvalueReference,
    RvalueReference,
    Array,
}

fn cpp_structured_declarator_wrappers(node: Node<'_>) -> Option<Vec<CppStructuredTypeWrapper>> {
    let mut wrappers = Vec::new();
    let mut current = node;
    loop {
        match current.kind() {
            "pointer_declarator" | "abstract_pointer_declarator" => {
                wrappers.push(CppStructuredTypeWrapper::Pointer)
            }
            "reference_declarator" | "abstract_reference_declarator" => {
                wrappers.push(cpp_reference_wrapper(current)?);
            }
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
    Some(wrappers)
}

fn cpp_reference_wrapper(node: Node<'_>) -> Option<CppStructuredTypeWrapper> {
    node.children(&mut node.walk())
        .find_map(|child| match child.kind() {
            "&" => Some(CppStructuredTypeWrapper::LvalueReference),
            "&&" => Some(CppStructuredTypeWrapper::RvalueReference),
            _ => None,
        })
}

fn cpp_wrap_structured_type(
    identity: StructuredTypeIdentity,
    wrapper: CppStructuredTypeWrapper,
) -> Option<StructuredTypeIdentity> {
    match wrapper {
        CppStructuredTypeWrapper::Pointer => identity.wrap_pointer(),
        CppStructuredTypeWrapper::LvalueReference => identity.wrap_reference(),
        CppStructuredTypeWrapper::RvalueReference => identity.wrap_rvalue_reference(),
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
        CppStructuredTypeWrapper::LvalueReference => builder.reference(inner),
        CppStructuredTypeWrapper::RvalueReference => builder.rvalue_reference(inner),
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

fn cpp_callable_lexical_scope<'tree>(
    node: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> Vec<String> {
    let mut groups = Vec::new();
    let mut current = ancestry.parent(node);
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
        current = ancestry.parent(parent);
    }
    groups.reverse();
    groups.into_iter().flatten().collect()
}

fn cpp_callable_dispatch_extensibility<'tree>(
    function_declarator: Node<'tree>,
    ancestry: &ParentIndex<'tree>,
) -> DispatchExtensibility {
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
        current = ancestry.parent(node);
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

fn cpp_callable_linkage<'tree>(
    declaration: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> CallableLinkage {
    let mut enclosed_by_class = false;
    let mut current = ancestry.parent(declaration);
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
        // An export macro between `class` and the class name can make
        // tree-sitter parse the entire class as a function definition. The
        // structured recovery proves that this container is a named class
        // scope, not a local callable scope.
        if node.kind() == "lambda_expression"
            || node.kind() == "function_definition"
                && !is_recovered_exported_class_container(node, source)
        {
            return CallableLinkage::Internal;
        }
        current = ancestry.parent(node);
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

fn cpp_callable_return_type_text<'tree>(
    function_declarator: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> Option<String> {
    if cpp_callable_is_structural_constructor(function_declarator, source, ancestry) {
        return None;
    }
    if let Some((return_type, _)) =
        cpp_macro_displaced_callable_parts(function_declarator, source, ancestry)
    {
        let text = normalize_cpp_whitespace(node_text(return_type, source));
        return (!text.is_empty()).then_some(text);
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
    while let Some(parent) = ancestry.parent(current) {
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
                if cpp_parameter_is_explicit_object(child, source) {
                    continue;
                }
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

fn cpp_parameter_is_explicit_object(parameter: Node<'_>, source: &str) -> bool {
    parameter
        .child_by_field_name("type")
        .filter(|type_node| type_node.kind() == "placeholder_type_specifier")
        .and_then(|type_node| type_node.child_by_field_name("constraint"))
        .is_some_and(|constraint| {
            constraint.kind() == "type_identifier" && node_text(constraint, source).trim() == "this"
        })
}

/// One entry of a callable's invocation parameter list.
///
/// The list excludes an explicit object parameter and a lone `void`, so its
/// length is the callable's invocation arity. Every derivation of a parameter
/// type - the rendered spelling used for overload discrimination and the
/// structured identity used by dependency-pack production - starts from this
/// same sequence, so the two can never disagree about which parameters exist.
#[derive(Clone, Copy)]
enum CppParameterSlot<'tree> {
    Declared(Node<'tree>),
    Ellipsis,
}

fn cpp_callable_parameter_slots<'tree>(
    parameters_node: Node<'tree>,
    source: &str,
) -> Vec<CppParameterSlot<'tree>> {
    let mut slots = Vec::new();
    let mut cursor = parameters_node.walk();
    for parameter in parameters_node.children(&mut cursor) {
        match parameter.kind() {
            "parameter_declaration" | "optional_parameter_declaration" => {
                if cpp_parameter_is_explicit_object(parameter, source)
                    || (parameter.child_by_field_name("declarator").is_none()
                        && parameter
                            .child_by_field_name("type")
                            .is_some_and(|type_node| node_text(type_node, source).trim() == "void"))
                {
                    continue;
                }
                slots.push(CppParameterSlot::Declared(parameter));
            }
            "variadic_parameter" | "variadic_parameter_declaration" | "..." => {
                slots.push(CppParameterSlot::Ellipsis);
            }
            _ => {}
        }
    }
    slots
}

fn cpp_callable_parameter_types(parameters_node: Node<'_>, source: &str) -> Vec<String> {
    cpp_callable_parameter_slots(parameters_node, source)
        .into_iter()
        .map(|slot| match slot {
            CppParameterSlot::Declared(parameter) => cpp_parameter_type(parameter, source),
            CppParameterSlot::Ellipsis => "...".to_string(),
        })
        .collect()
}

/// One callable parameter's parser-derived type.
///
/// A rendered spelling such as `const T&` is a source text, not a type name. A
/// consumer that must publish a type into a structured model - a semantic-pack
/// type reference, for example - reads this instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CppParameterType {
    /// The written type reduced to a structured identity. C++ cv-qualifiers
    /// have no place in that model and are not represented.
    Structured(StructuredTypeIdentity),
    /// A `...` pack, which declares no parameter type at all.
    Ellipsis,
    /// A written type with no structured reduction, such as a macro-obscured,
    /// `decltype`-computed, or function-pointer parameter.
    Unstructured,
}

/// The structured type of each invocation parameter, in declaration order.
///
/// The result is index-parallel with the rendered
/// [`SignatureMetadata::callable_parameter_types`] spellings of the same
/// callable.
pub fn cpp_callable_parameter_type_identities<'tree>(
    function_declarator: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> Vec<CppParameterType> {
    let Some(parameters_node) = function_declarator.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let lexical_scope = cpp_callable_lexical_scope(function_declarator, source, ancestry);
    cpp_callable_parameter_slots(parameters_node, source)
        .into_iter()
        .map(|slot| match slot {
            CppParameterSlot::Ellipsis => CppParameterType::Ellipsis,
            CppParameterSlot::Declared(parameter) => {
                cpp_parameter_type_identity(parameter, source, &lexical_scope)
                    .map_or(CppParameterType::Unstructured, CppParameterType::Structured)
            }
        })
        .collect()
}

/// The parser-derived type of one declared object or parameter.
///
/// The declaration owns the base `type` field while the individual declarator
/// owns pointer, reference, and array wrappers. Keeping both nodes explicit
/// lets callers distinguish several declarators in one declaration without
/// reparsing a rendered signature.
pub fn cpp_declaration_type_identity<'tree>(
    declaration: Node<'tree>,
    declarator: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> Option<StructuredTypeIdentity> {
    let lexical_scope = cpp_callable_lexical_scope(declarator, source, ancestry);
    cpp_declaration_type_identity_in_scope(declaration, Some(declarator), source, &lexical_scope)
}

fn cpp_parameter_type_identity(
    parameter: Node<'_>,
    source: &str,
    lexical_scope: &[String],
) -> Option<StructuredTypeIdentity> {
    cpp_declaration_type_identity_in_scope(
        parameter,
        cpp_parameter_declarator(parameter),
        source,
        lexical_scope,
    )
}

fn cpp_declaration_type_identity_in_scope(
    declaration: Node<'_>,
    declarator: Option<Node<'_>>,
    source: &str,
    lexical_scope: &[String],
) -> Option<StructuredTypeIdentity> {
    let type_node = declaration.child_by_field_name("type")?;
    let mut identity = cpp_structured_type_identity(type_node, source, lexical_scope)?;
    if let Some(declarator) = declarator {
        for wrapper in cpp_structured_declarator_wrappers(declarator)?
            .into_iter()
            .rev()
        {
            identity = cpp_wrap_structured_type(identity, wrapper)?;
        }
    }
    Some(identity)
}

/// One callable parameter's comparable shape.
///
/// [`CppParameterType`] above answers "which type is written here" for a
/// structured model and deliberately records no cv-qualifiers, so it reports
/// the same value for `f(char *)` and `f(const char *)`. Deciding whether two
/// callable declarations declare one function needs the opposite trade: every
/// cv-qualifier that C++ counts as part of the parameter type must survive,
/// while the two declarations may spell the same type through different
/// qualifications. This slot carries that comparand.
///
/// The result is index-parallel with [`cpp_callable_parameter_type_identities`]
/// and with the rendered parameter spellings of the same callable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CppComparableSlot {
    /// A declared parameter reduced to its comparable shape.
    Shape(CppComparableParameter),
    /// A `...` pack, which declares no parameter type at all.
    Ellipsis,
    /// A parameter with no comparable reduction, such as a macro-obscured,
    /// `decltype`-computed, or function-pointer parameter.
    Unstructured,
}

/// A parameter type as a flat arena of nodes plus a root index.
///
/// The arena carries the same rationale as [`StructuredTypeIdentity`]: source
/// can nest types very deeply, and cloning, comparing or dropping the value
/// must not consume the Rust call stack. Nodes are appended in post-order, so
/// every child index is smaller than its parent's and the last appended node is
/// the root.
///
/// That post-order append is also what makes the derived `PartialEq` a correct
/// structural equality: the builder below is deterministic, so one type shape
/// has exactly one arena layout no matter which spelling produced it. Two
/// shapes are equal as values iff they are equal as type trees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppComparableParameter {
    nodes: Vec<CppComparableNode>,
    root: usize,
}

/// One node of a [`CppComparableParameter`] arena.
///
/// `Reference` and `Array` carry no qualifiers because the grammar writes none
/// on them: a reference cannot be cv-qualified in C++, and an array's
/// qualifiers belong to its element type. A cv-qualifier written on a generic
/// type (`const std::vector<int>`) is recorded on the generic's base leaf,
/// which is the only Named node the whole spelling produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CppComparableNode {
    Named {
        name: StructuredTypeName,
        primitive: bool,
        konst: bool,
        volatil: bool,
    },
    Pointer {
        inner: usize,
        konst: bool,
        volatil: bool,
    },
    Reference {
        inner: usize,
    },
    Array {
        inner: usize,
    },
    Generic {
        base: usize,
        arguments: Vec<usize>,
    },
}

impl CppComparableParameter {
    pub fn root(&self) -> usize {
        self.root
    }

    pub fn node(&self, index: usize) -> &CppComparableNode {
        &self.nodes[index]
    }

    /// Apply the [dcl.fct]/5 parameter-type adjustments, which hold at the
    /// parameter's top level only.
    ///
    /// A top-level cv-qualifier is discarded, so `f(const int)` and `f(int)`
    /// declare one function, and a top-level array type becomes a pointer to
    /// its element type, so `f(int[3])` and `f(int *)` do too. The outermost
    /// type constructor is this arena's root, which is why both adjustments
    /// are one match on it: cv on an inner pointer level, on a pointee, or on
    /// an array element keeps distinguishing the type, and an array behind a
    /// pointer or reference is not a top-level array.
    fn adjust_parameter_top_level(&mut self) {
        let root = self.root;
        match &mut self.nodes[root] {
            CppComparableNode::Named { konst, volatil, .. }
            | CppComparableNode::Pointer { konst, volatil, .. } => {
                *konst = false;
                *volatil = false;
            }
            CppComparableNode::Array { inner } => {
                let inner = *inner;
                self.nodes[root] = CppComparableNode::Pointer {
                    inner,
                    konst: false,
                    volatil: false,
                };
            }
            CppComparableNode::Generic { base, .. } => {
                let base = *base;
                let CppComparableNode::Named { konst, volatil, .. } = &mut self.nodes[base] else {
                    unreachable!("a comparable generic's base is always a named leaf");
                };
                *konst = false;
                *volatil = false;
            }
            CppComparableNode::Reference { .. } => {}
        }
    }
}

/// The comparable shape of each invocation parameter, in declaration order.
///
/// The result is index-parallel with
/// [`cpp_callable_parameter_type_identities`]; a parameter that admits no
/// comparable shape is [`CppComparableSlot::Unstructured`], which a comparison
/// must treat as evidence of nothing rather than as agreement.
pub fn cpp_comparable_parameter_shapes<'tree>(
    function_declarator: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> Vec<CppComparableSlot> {
    let Some(parameters_node) = function_declarator.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let lexical_scope = cpp_callable_lexical_scope(function_declarator, source, ancestry);
    cpp_callable_parameter_slots(parameters_node, source)
        .into_iter()
        .map(|slot| match slot {
            CppParameterSlot::Ellipsis => CppComparableSlot::Ellipsis,
            CppParameterSlot::Declared(parameter) => {
                cpp_comparable_parameter(parameter, source, &lexical_scope)
                    .map_or(CppComparableSlot::Unstructured, CppComparableSlot::Shape)
            }
        })
        .collect()
}

fn cpp_comparable_parameter(
    parameter: Node<'_>,
    source: &str,
    lexical_scope: &[String],
) -> Option<CppComparableParameter> {
    let type_node = parameter.child_by_field_name("type")?;
    let levels = match cpp_parameter_declarator(parameter) {
        Some(declarator) => cpp_comparable_declarator_levels(declarator, source)?,
        None => Vec::new(),
    };
    let mut shape = cpp_comparable_type_shape(
        type_node,
        cpp_cv_qualifiers(parameter, source),
        levels,
        source,
        lexical_scope,
    )?;
    shape.adjust_parameter_top_level();
    Some(shape)
}

/// The `const` and `volatile` qualifiers written as direct named children of
/// `node`.
///
/// The grammar exposes `type_qualifier` as a non-field named child in exactly
/// the three places a parameter's qualifiers can be written: on the
/// `parameter_declaration` itself (the base type), on a `type_descriptor`
/// (inside a template argument list), and on each `pointer_declarator` level
/// (the pointer object). Every other qualifier the grammar admits - `restrict`
/// and friends - takes no part in C++ type identity, the same filter
/// `cpp_parameter_type` applies to the rendered spelling (#1827).
fn cpp_cv_qualifiers(node: Node<'_>, source: &str) -> CppCvQualifiers {
    let mut qualifiers = CppCvQualifiers::default();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "type_qualifier" {
            continue;
        }
        match node_text(child, source) {
            "const" => qualifiers.konst = true,
            "volatile" => qualifiers.volatil = true,
            _ => {}
        }
    }
    qualifiers
}

#[derive(Clone, Copy, Default)]
struct CppCvQualifiers {
    konst: bool,
    volatil: bool,
}

impl CppCvQualifiers {
    fn union(self, other: Self) -> Self {
        Self {
            konst: self.konst || other.konst,
            volatil: self.volatil || other.volatil,
        }
    }
}

/// One pointer, reference or array level a declarator chain adds.
#[derive(Clone, Copy)]
enum CppComparableLevel {
    Pointer { konst: bool, volatil: bool },
    Reference,
    Array,
}

/// The levels `declarator` adds, outermost written level first.
///
/// C++ declarator syntax binds inside out: the level written closest to the
/// declared name is the outermost type constructor, and tree-sitter nests it
/// deepest. `int *a[3]` therefore yields `[Pointer, Array]`, which the builder
/// applies in order to reach "array of pointer to int", and the qualifier of
/// `int * const *p` is read on the level it was written next to, the inner
/// pointer of the resulting type.
///
/// A declarator chain that names a function type - a function-pointer
/// parameter - has no comparable shape and reports `None`, matching the
/// structured identity channel.
fn cpp_comparable_declarator_levels(
    declarator: Node<'_>,
    source: &str,
) -> Option<Vec<CppComparableLevel>> {
    let mut levels = Vec::new();
    let mut current = declarator;
    loop {
        match current.kind() {
            "pointer_declarator" | "abstract_pointer_declarator" => {
                let qualifiers = cpp_cv_qualifiers(current, source);
                levels.push(CppComparableLevel::Pointer {
                    konst: qualifiers.konst,
                    volatil: qualifiers.volatil,
                });
            }
            "reference_declarator" | "abstract_reference_declarator" => {
                levels.push(CppComparableLevel::Reference);
            }
            "array_declarator" | "abstract_array_declarator" => {
                levels.push(CppComparableLevel::Array);
            }
            "parenthesized_declarator" | "abstract_parenthesized_declarator" => {}
            "identifier" | "field_identifier" | "type_identifier" => return Some(levels),
            _ => return None,
        }
        let Some(next) = cpp_nested_declarator(current) else {
            return Some(levels);
        };
        current = next;
    }
}

/// Reduce one written type to a comparable arena.
///
/// The walk is the work-stack shape `cpp_structured_type_identity` uses, with
/// two additions: each visited type node carries the cv-qualifiers written on
/// it, and declarator levels arrive as a prepared list rather than being
/// rediscovered inside the walk.
fn cpp_comparable_type_shape(
    type_node: Node<'_>,
    qualifiers: CppCvQualifiers,
    levels: Vec<CppComparableLevel>,
    source: &str,
    lexical_scope: &[String],
) -> Option<CppComparableParameter> {
    enum Work<'tree> {
        Visit {
            node: Node<'tree>,
            qualifiers: CppCvQualifiers,
        },
        ApplyLevels(Vec<CppComparableLevel>),
        BuildGeneric {
            argument_count: usize,
        },
    }

    let mut nodes: Vec<CppComparableNode> = Vec::new();
    let mut values: Vec<usize> = Vec::new();
    let mut work = vec![
        Work::ApplyLevels(levels),
        Work::Visit {
            node: type_node,
            qualifiers,
        },
    ];
    while let Some(next) = work.pop() {
        match next {
            Work::Visit { node, qualifiers } => match node.kind() {
                "type_descriptor" => {
                    let inner_type = node
                        .child_by_field_name("type")
                        .or_else(|| node.named_child(0))?;
                    let mut cursor = node.walk();
                    let declarator = node.child_by_field_name("declarator").or_else(|| {
                        node.named_children(&mut cursor).find(|child| {
                            child.id() != inner_type.id() && child.kind() != "type_qualifier"
                        })
                    });
                    let levels = match declarator {
                        Some(declarator) => cpp_comparable_declarator_levels(declarator, source)?,
                        None => Vec::new(),
                    };
                    work.push(Work::ApplyLevels(levels));
                    work.push(Work::Visit {
                        node: inner_type,
                        qualifiers: qualifiers.union(cpp_cv_qualifiers(node, source)),
                    });
                }
                "sized_type_specifier" => {
                    // `unsigned char` is one primitive type whose components are
                    // partly unnamed tokens, so the whole specifier is its own
                    // name component. Reducing it to the `type` child would make
                    // `f(unsigned char)` and `f(char)` compare equal.
                    let name = StructuredTypeName::new(
                        vec![normalize_cpp_whitespace(node_text(node, source))],
                        lexical_scope.to_vec(),
                        false,
                    )?;
                    values.push(cpp_push_comparable_node(
                        &mut nodes,
                        CppComparableNode::Named {
                            name,
                            primitive: true,
                            konst: qualifiers.konst,
                            volatil: qualifiers.volatil,
                        },
                    ));
                }
                "qualified_identifier"
                | "scoped_identifier"
                | "scoped_type_identifier"
                | "type_identifier"
                | "field_identifier"
                | "identifier"
                | "namespace_identifier"
                | "primitive_type"
                | "template_type" => {
                    let name = cpp_structured_named_type(node, source, lexical_scope)?;
                    values.push(cpp_push_comparable_node(
                        &mut nodes,
                        CppComparableNode::Named {
                            name,
                            primitive: node.kind() == "primitive_type",
                            konst: qualifiers.konst,
                            volatil: qualifiers.volatil,
                        },
                    ));
                    if let Some(arguments_node) = cpp_comparable_template_arguments(node) {
                        let mut cursor = arguments_node.walk();
                        let arguments = arguments_node
                            .named_children(&mut cursor)
                            .filter(|child| !child.is_extra() && child.kind() != "comment")
                            .collect::<Vec<_>>();
                        work.push(Work::BuildGeneric {
                            argument_count: arguments.len(),
                        });
                        work.extend(arguments.into_iter().rev().map(|argument| Work::Visit {
                            node: argument,
                            qualifiers: CppCvQualifiers::default(),
                        }));
                    }
                }
                _ => {
                    let inner = node.child_by_field_name("type").or_else(|| {
                        (node.named_child_count() == 1)
                            .then(|| node.named_child(0))
                            .flatten()
                    })?;
                    work.push(Work::Visit {
                        node: inner,
                        qualifiers,
                    });
                }
            },
            Work::ApplyLevels(levels) => {
                let mut root = values.pop()?;
                for level in levels {
                    let node = match level {
                        CppComparableLevel::Pointer { konst, volatil } => {
                            CppComparableNode::Pointer {
                                inner: root,
                                konst,
                                volatil,
                            }
                        }
                        CppComparableLevel::Reference => {
                            CppComparableNode::Reference { inner: root }
                        }
                        CppComparableLevel::Array => CppComparableNode::Array { inner: root },
                    };
                    root = cpp_push_comparable_node(&mut nodes, node);
                }
                values.push(root);
            }
            Work::BuildGeneric { argument_count } => {
                let value_count = argument_count.checked_add(1)?;
                let start = values.len().checked_sub(value_count)?;
                let mut built = values.split_off(start);
                let base = built.remove(0);
                values.push(cpp_push_comparable_node(
                    &mut nodes,
                    CppComparableNode::Generic {
                        base,
                        arguments: built,
                    },
                ));
            }
        }
    }
    let root = (values.len() == 1).then(|| values.pop()).flatten()?;
    debug_assert_eq!(
        root,
        nodes.len().saturating_sub(1),
        "comparable nodes are appended in post-order, so the root is the last one"
    );
    Some(CppComparableParameter { nodes, root })
}

fn cpp_push_comparable_node(nodes: &mut Vec<CppComparableNode>, node: CppComparableNode) -> usize {
    nodes.push(node);
    nodes.len() - 1
}

/// The template argument list of the name `node` terminates in, if any.
///
/// `std::vector<int>` writes its arguments on the `name` of a qualified
/// identifier, so a walk that stopped at the qualified node would reduce
/// `std::vector<const int *>` and `std::vector<int *>` to the same name.
fn cpp_comparable_template_arguments(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    loop {
        match current.kind() {
            "template_type" => return current.child_by_field_name("arguments"),
            "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier" => {
                current = current.child_by_field_name("name")?;
            }
            _ => return None,
        }
    }
}

/// The callable declarator of the declaration that covers `start_byte`.
///
/// A consumer that holds a declaration's recorded byte position rather than its
/// syntax node - external header extraction, for instance - uses this to reach
/// the same `function_declarator` the declaration walk read.
pub fn cpp_function_declarator_at(root: Node<'_>, start_byte: usize) -> Option<Node<'_>> {
    let mut current = root.descendant_for_byte_range(start_byte, start_byte)?;
    loop {
        if matches!(
            current.kind(),
            "declaration" | "field_declaration" | "function_definition"
        ) && let Some(declarator) = current
            .child_by_field_name("declarator")
            .and_then(extract_function_declarator)
        {
            return Some(declarator);
        }
        current = current.parent()?;
    }
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

fn cpp_signature_search_start<'tree>(
    signature: &str,
    function_declarator: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> usize {
    let Some(enclosing) = enclosing_cpp_declaration_node(function_declarator, ancestry) else {
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
    let declarator = cpp_parameter_declarator(parameter);
    // [dcl.fct]/5: after parameter-type adjustment the top-level cv-qualifiers
    // are discarded, so `f(const int)` and `f(int)` declare one function. A
    // qualifier written next to the parameter's type is only top-level when
    // the declarator adds no indirection; behind a pointer, reference or array
    // declarator the same qualifier belongs to the pointee, referent or
    // element and keeps distinguishing the type (#1827).
    let keeps_top_level_cv = declarator.is_some_and(cpp_declarator_adds_indirection);
    let mut cursor = parameter.walk();
    let qualifiers = parameter
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "type_qualifier")
        .map(|child| normalize_cpp_whitespace(node_text(child, source)))
        .filter(|text| keeps_top_level_cv || !matches!(text.as_str(), "const" | "volatile"))
        .collect::<Vec<_>>()
        .join(" ");
    let type_text = match (qualifiers.is_empty(), base_type.is_empty()) {
        (true, _) => base_type,
        (_, true) => qualifiers,
        (false, false) => format!("{qualifiers} {base_type}"),
    };
    let declarator_suffix = declarator
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

/// Whether a parameter's declarator chain adds indirection - a pointer,
/// reference, array or function declarator - to the parameter's written type.
pub(crate) fn cpp_declarator_adds_indirection(declarator: Node<'_>) -> bool {
    let mut current = Some(declarator);
    while let Some(node) = current {
        if matches!(
            node.kind(),
            "pointer_declarator"
                | "abstract_pointer_declarator"
                | "reference_declarator"
                | "abstract_reference_declarator"
                | "array_declarator"
                | "abstract_array_declarator"
                | "function_declarator"
                | "abstract_function_declarator"
        ) {
            return true;
        }
        current = cpp_nested_declarator(node);
    }
    false
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
    raw_supertypes: Option<Vec<String>>,
    fragmented: FragmentedExportBody,
    consumed_start: usize,
}

struct CppSentinelFragmentedClassErrorPrefix<'tree> {
    name: String,
    open: Node<'tree>,
    raw_supertypes: Option<Vec<String>>,
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

/// Recognize the direct `ERROR(class, name, "{", members...)` prefix left in a
/// namespace-sentinel body when a later member macro ends the bogus sentinel
/// function before the real class close. The anonymous class/open tokens and
/// direct identifier are the structural proof; a retained direct close would
/// be an ordinary malformed class rather than the fragmented tail handled here.
fn cpp_sentinel_fragmented_class_error_prefix<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<CppSentinelFragmentedClassErrorPrefix<'tree>> {
    let name = malformed_class_error_owner_name(node, source)?;
    let mut cursor = node.walk();
    let children = node.children(&mut cursor).collect::<Vec<_>>();
    let keyword = children.first()?;
    let open_index = children.iter().position(|child| child.kind() == "{")?;
    if children[open_index + 1..]
        .iter()
        .any(|child| child.kind() == "}")
    {
        return None;
    }
    let raw_supertypes =
        matches!(keyword.kind(), "class" | "struct").then(|| extract_cpp_supertypes(node, source));
    Some(CppSentinelFragmentedClassErrorPrefix {
        name,
        open: children[open_index],
        raw_supertypes,
    })
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

fn cpp_sentinel_macro_body_class_region<'tree>(
    node: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
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
    let name = class_like_name(*class_node, source, ancestry)?;
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
    // The region reparse is its own tree, so it needs its own parent index;
    // the caller's index answers nothing about these nodes.
    let reparsed_ancestry = ParentIndex::new(root);
    let reparsed =
        cpp_sentinel_reparsed_class(root, reparsed_template, source, &reparsed_ancestry)?;
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
/// and a compound body; and that body must contain a complete named class or a
/// structurally fragmented class prefix. A text reparse cannot prove any of
/// those ownership boundaries.
fn cpp_nested_namespace_sentinel<'tree>(
    node: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
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
    let has_complete_class = body.named_children(&mut cursor).any(|child| {
        cpp_sentinel_body_class_candidate(child).is_some_and(|(class_node, _)| {
            cpp_body_node(class_node).is_some()
                && class_like_name(class_node, source, ancestry)
                    .is_some_and(|name| !name.is_empty() && !cpp_export_macro_token(&name))
        })
    });
    if !has_complete_class
        && cpp_sentinel_fragmented_class_tail(function, *body, source, ancestry).is_none()
    {
        return None;
    }

    Some(CppNestedNamespaceSentinel {
        function,
        body: *body,
        namespace_components,
    })
}

/// Recognize a namespace-begin sentinel directly beneath the translation unit.
///
/// Tree-sitter reduces `BEGIN_NS namespace a::b { ... }` to a malformed
/// function whose type is the sentinel, whose declarator is the structured
/// qualified name `namespace::a::b`, and whose body contains the namespace
/// items. Declaration indexing already reparses this bounded region. The
/// inverse scanner retains the original tree, so recover the same namespace
/// components from the declarator fields for its lexical-scope metadata.
fn cpp_root_namespace_sentinel<'tree>(
    node: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> Option<CppNestedNamespaceSentinel<'tree>> {
    if node.kind() != "function_definition"
        || !node.has_error()
        || node.parent()?.kind() != "translation_unit"
    {
        return None;
    }
    let first_type = node.child_by_field_name("type")?;
    let sentinel = normalize_cpp_whitespace(node_text(first_type, source));
    if first_type.kind() != "type_identifier"
        || sentinel.is_empty()
        || !cpp_export_macro_token(&sentinel)
    {
        return None;
    }
    let declarator = node.child_by_field_name("declarator")?;
    let body = node.child_by_field_name("body")?;
    if declarator.kind() != "qualified_identifier" || body.kind() != "compound_statement" {
        return None;
    }
    let mut cursor = node.walk();
    let named = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
        .collect::<Vec<_>>();
    let [named_type, named_declarator, named_body] = named.as_slice() else {
        return None;
    };
    if !same_node(*named_type, first_type)
        || !same_node(*named_declarator, declarator)
        || !same_node(*named_body, body)
    {
        return None;
    }
    let mut declarator_components = Vec::new();
    let mut valid_components = true;
    walk_named_tree_preorder(declarator, true, |component| {
        if !matches!(
            component.kind(),
            "identifier" | "namespace_identifier" | "type_identifier"
        ) {
            return WalkControl::Continue;
        }
        let Some(component) = canonical_cpp_qualified_component(component, source) else {
            valid_components = false;
            return WalkControl::Break;
        };
        declarator_components.push(component.name);
        WalkControl::SkipChildren
    });
    if !valid_components || declarator_components.first().map(String::as_str) != Some("namespace") {
        return None;
    }
    declarator_components.remove(0);
    let namespace_components = declarator_components;
    if namespace_components.is_empty()
        || namespace_components
            .iter()
            .any(|component| component.is_empty() || cpp_export_macro_token(component))
    {
        return None;
    }

    let mut cursor = body.walk();
    let has_complete_class = body.named_children(&mut cursor).any(|child| {
        cpp_sentinel_body_class_candidate(child).is_some_and(|(class_node, _)| {
            cpp_body_node(class_node).is_some()
                && class_like_name(class_node, source, ancestry)
                    .is_some_and(|name| !name.is_empty() && !cpp_export_macro_token(&name))
        })
    });
    if !has_complete_class
        && cpp_sentinel_fragmented_class_tail(node, body, source, ancestry).is_none()
    {
        return None;
    }

    Some(CppNestedNamespaceSentinel {
        function: node,
        body,
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
    ancestry: &ParentIndex<'tree>,
) -> Option<CppSentinelFragmentedClassTail<'tree>> {
    let mut cursor = body.walk();
    let candidates = body
        .named_children(&mut cursor)
        .filter_map(|child| {
            if let Some((class_node, template_node)) = cpp_sentinel_body_class_candidate(child) {
                let class_body = cpp_body_node(class_node)?;
                if !class_node.has_error() {
                    return None;
                }
                let name = class_like_name(class_node, source, ancestry)?;
                let raw_supertypes =
                    matches!(class_node.kind(), "class_specifier" | "struct_specifier")
                        .then(|| extract_cpp_supertypes(class_node, source));
                return Some((
                    class_node,
                    template_node,
                    name,
                    class_body,
                    class_body.start_byte().checked_add(1)?,
                    raw_supertypes,
                ));
            }
            let prefix = cpp_sentinel_fragmented_class_error_prefix(child, source)?;
            Some((
                child,
                None,
                prefix.name,
                prefix.open,
                prefix.open.end_byte(),
                prefix.raw_supertypes,
            ))
        })
        .collect::<Vec<_>>();
    let [(class_node, template_node, name, class_body, reparse_start, raw_supertypes)] =
        candidates.as_slice()
    else {
        return None;
    };
    if name.is_empty() || cpp_export_macro_token(name) {
        return None;
    }

    let (close, semicolon) =
        cpp_sentinel_fragment_boundary(function, *class_node, *class_body, source)?;

    let reparse_end = close.start_byte();
    if *reparse_start >= reparse_end {
        return None;
    }
    let tree = cpp_reparse_region_items(source, *reparse_start, reparse_end)?;
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
        name: name.clone(),
        raw_supertypes: raw_supertypes.clone(),
        fragmented: FragmentedExportBody {
            reparse_start: *reparse_start,
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
    // This scan owns its walk of `root`, so it owns the parent index that walk
    // asks its ancestor questions through. Built after the error gate: a clean
    // tree returns without paying for one.
    let ancestry = ParentIndex::new(root);
    let mut recovered_classes: Vec<CppSentinelRecoveredClass> = Vec::new();
    let mut stack = vec![root];
    while let Some(current) = stack.pop() {
        if let Some(recovered) = cpp_nested_namespace_sentinel(current, source, &ancestry)
            .or_else(|| cpp_root_namespace_sentinel(current, source, &ancestry))
        {
            let namespace_components = cpp_sentinel_recovered_namespace_components(
                recovered.function,
                &recovered.namespace_components,
                source,
            );
            let fragmented = cpp_sentinel_fragmented_class_tail(
                recovered.function,
                recovered.body,
                source,
                &ancestry,
            );
            let mut class_candidates = Vec::new();
            let mut cursor = recovered.body.walk();
            for (class_node, template_node) in recovered
                .body
                .named_children(&mut cursor)
                .filter_map(cpp_sentinel_body_class_candidate)
            {
                let Some(name) = class_like_name(class_node, source, &ancestry) else {
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
            if let Some(fragmented) = fragmented
                .as_ref()
                .filter(|tail| tail.class_node.kind() == "ERROR")
            {
                class_candidates.push((fragmented.fragmented.class_range, fragmented.name.clone()));
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
                    &ancestry,
                );
            }
        } else if let Some(region) =
            cpp_sentinel_macro_body_class_region(current, source, &ancestry)
        {
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
            // A region reparse is its own tree and needs its own parent index.
            let reparsed_ancestry = ParentIndex::new(root);
            let Some(reparsed_class) =
                cpp_sentinel_reparsed_class(root, template_node, source, &reparsed_ancestry)
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
                    &ancestry,
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
fn push_cpp_sentinel_sibling_classes<'tree>(
    recovered_classes: &mut Vec<CppSentinelRecoveredClass>,
    declaration_list: Node<'tree>,
    sentinel_node: Node<'tree>,
    namespace_components: &[String],
    source: &str,
    ancestry: &ParentIndex<'tree>,
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
        let Some(name) = class_like_name(class_node, source, ancestry) else {
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
        if let Some(name) = macro_decorated_unqualified_name(current) {
            current = name;
            continue;
        }
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

/// A `qualified_identifier` the grammar produced for `MACRO Name` with no
/// `::` between the halves. The scope is an attribute-like macro token, not
/// a namespace; `Name` is the declared name.
///
/// `explicit BOTAN_FN_ISA_AVX2 SIMD_4x26(__m256i v)` is the witness (#2552):
/// tree-sitter joins the attribute macro and the constructor name into one
/// `qualified_identifier` and marks the separator it had to invent as MISSING.
/// That flag is the grammar's own record that no separator is in the source,
/// so read it instead of looking for `::` in the node text. A genuine
/// `Outer::Inner` keeps a present separator and is declined here, and so is
/// the explicit-global `::name`, whose `::` is present and whose scope is
/// absent.
fn macro_decorated_unqualified_name(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "qualified_identifier" || node.child_by_field_name("scope").is_none() {
        return None;
    }
    let mut cursor = node.walk();
    if node
        .children(&mut cursor)
        .any(|child| child.kind() == "::" && !child.is_missing())
    {
        return None;
    }
    node.child_by_field_name("name")
}

fn cpp_name_components(node: Node<'_>, source: &str) -> Option<Vec<CppQualifiedNameComponent>> {
    if let Some(name) = macro_decorated_unqualified_name(node) {
        return cpp_name_components(name, source);
    }
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
fn cpp_sentinel_macro_class_region<'tree>(
    node: Node<'tree>,
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
    // A stray `};` sibling is this class's close only when the bounded reparse
    // agrees the first body-bearing class ENDS there. When the malformed
    // envelope swallowed the class's true close, the scan can promote a much
    // later scope's close instead -- in protobuf-generated headers
    // (wazuh__wazuh's *.pb.h) the `PROTOBUF_NAMESPACE_CLOSE` sentinel before
    // `struct TableStruct_*` paired with the first message class's `};`, making
    // the recovered "class body" span whole `namespace {}` blocks and minting
    // namespace-scope classes as nested members of the recovered class, which
    // tripped the package/short boundary assert in CodeUnit::with_signature_and_fq
    // (#2275). On disagreement, fall through to the suffix-reparse boundary
    // below, which derives the close from the class node's own balanced body
    // range.
    let sibling_close = sibling_close.filter(|&(close_start, close_end, _)| {
        let Some(tree) = cpp_reparse_region_items(source, reparse_start, close_end) else {
            return false;
        };
        let template_node = cpp_sentinel_reparsed_leading_template(tree.root_node());
        // A region reparse is its own tree and needs its own parent index.
        let reparsed_ancestry = ParentIndex::new(tree.root_node());
        let Some(reparsed_class) = cpp_sentinel_reparsed_class(
            tree.root_node(),
            template_node,
            source,
            &reparsed_ancestry,
        ) else {
            return false;
        };
        let body = reparsed_class.body;
        body.start_byte() == body_open_start && body.end_byte() == close_start + 1
    });
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
            // A region reparse is its own tree and needs its own parent index.
            let reparsed_ancestry = ParentIndex::new(tree.root_node());
            let reparsed_class = cpp_sentinel_reparsed_class(
                tree.root_node(),
                template_node,
                source,
                &reparsed_ancestry,
            )?;
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
    // A region reparse is its own tree and needs its own parent index.
    let reparsed_ancestry = ParentIndex::new(class_root);
    let reparsed_class =
        cpp_sentinel_reparsed_class(class_root, template_node, source, &reparsed_ancestry)?;
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
    if class_start.is_none()
        && let Some(namespace_end) = cpp_sentinel_following_namespace_end(node, source)
    {
        end = end.max(namespace_end);
    }
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

/// Extend a sentinel reparse through a following namespace that tree-sitter
/// flattened into the sentinel node's sibling list.
///
/// Fmt places `FMT_END_EXPORT` immediately before `namespace detail`. The
/// unknown macro becomes a false function return type and consumes the first
/// namespace body. A second `namespace detail` then loses its enclosing node:
/// tree-sitter retains the `namespace`, name, and `{` as direct siblings, but
/// attaches its declarations to the surrounding error tree. Reparse from that
/// structured keyword so tree-sitter, rather than a source-text brace scan,
/// supplies the complete namespace boundary.
fn cpp_sentinel_following_namespace_end(node: Node<'_>, source: &str) -> Option<usize> {
    let mut sibling = node.next_sibling();
    let keyword = loop {
        let candidate = sibling?;
        sibling = candidate.next_sibling();
        if candidate.kind() != "comment" {
            break candidate;
        }
    };
    if keyword.kind() != "namespace" {
        return None;
    }
    let name = loop {
        let candidate = sibling?;
        sibling = candidate.next_sibling();
        if candidate.kind() != "comment" {
            break candidate;
        }
    };
    if cpp_namespace_name_components(name, source).is_empty() {
        return None;
    }
    let open = loop {
        let candidate = sibling?;
        sibling = candidate.next_sibling();
        if candidate.kind() != "comment" {
            break candidate;
        }
    };
    if open.kind() != "{" {
        return None;
    }

    let tree = cpp_reparse_region_items(source, keyword.start_byte(), source.len())?;
    let root = tree.root_node();
    let mut cursor = root.walk();
    let namespace = root
        .named_children(&mut cursor)
        .find(|candidate| candidate.kind() != "comment")?;
    (namespace.kind() == "namespace_definition"
        && namespace.start_byte() == keyword.start_byte()
        && namespace.child_by_field_name("body").is_some())
    .then_some(namespace.end_byte())
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

/// Recover a macro-qualified constructor that tree-sitter represents as one
/// field declaration. The constructor call remains inside the direct recovery
/// error, while each member initializer becomes a false function declarator.
/// The class owner proves the constructor name and lets the caller ignore those
/// initializer declarators.
fn recovered_macro_qualified_constructor_call<'tree>(
    node: Node<'tree>,
    class_name: &str,
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
    let mut cursor = node.walk();
    let bitfield = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "bitfield_clause")?;
    let error = bitfield
        .named_child(0)
        .filter(|child| child.kind() == "ERROR")?;
    let mut stack = vec![error];
    while let Some(current) = stack.pop() {
        if current.kind() == "call_expression"
            && current
                .child_by_field_name("function")
                .is_some_and(|function| node_text(function, source) == class_name)
            && current
                .child_by_field_name("arguments")
                .is_some_and(|arguments| arguments.kind() == "argument_list")
        {
            return Some(current);
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    None
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
pub(crate) fn cpp_active_template_type_parameter<'tree>(
    node: Node<'tree>,
    name: &str,
    source: &str,
    ancestry: &ParentIndex<'tree>,
) -> bool {
    let mut ancestor = ancestry.parent(node);
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
        ancestor = ancestry.parent(current);
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

fn cpp_error_swallowed_function_declaration_range(node: Node<'_>) -> Option<(usize, usize)> {
    if node.kind() != "function_declarator" || node.parent()?.kind() != "ERROR" {
        return None;
    }
    let semicolon = node.next_sibling()?;
    if semicolon.kind() != ";" || semicolon.is_missing() {
        return None;
    }
    let row = node.start_position().row;
    let mut start = node.start_byte();
    let mut sibling = node.prev_sibling();
    while let Some(previous) = sibling.filter(|previous| previous.start_position().row == row) {
        if previous.kind() == ";" {
            break;
        }
        start = previous.start_byte();
        sibling = previous.prev_sibling();
    }
    (start < node.start_byte()).then_some((start, semicolon.end_byte()))
}

/// One `RET name _(( args ));`-style K&R prototype-macro invocation
/// recognized by [`cpp_prototype_macro_candidates`] (issue #2932): the three
/// byte spans a clean reparse needs, in original-source order.
struct PrototypeMacroCandidate {
    /// Where the return type and declared name begin.
    run_start: usize,
    /// Byte where the macro token identifier (`_`, `__P`, ...) begins: the
    /// exclusive end of the first reparse span.
    identifier_start: usize,
    /// The inner `(`'s start byte: the start of the second reparse span.
    /// This paren is kept so the reparse sees exactly one parameter-list
    /// paren pair.
    inner_open_start: usize,
    /// Byte just past the inner `)`: the end of the second reparse span.
    inner_close_end: usize,
    /// Byte just past the outer `)`: the start of the third reparse span.
    outer_close_end: usize,
    /// Byte just past the terminating `;`: the end of the third reparse
    /// span, and of the whole candidate.
    semicolon_end: usize,
}

impl PrototypeMacroCandidate {
    /// The three spans [`parse_source_ranges_with_cancellation`] parses as
    /// one included-range tree: the return type and name, the parenthesized
    /// argument list, and the terminating `;`. The macro token and its outer
    /// wrapping parenthesis are omitted -- deleting them is exactly what the
    /// (absent) preprocessor macro expansion would do.
    fn ranges(&self) -> [(usize, usize); 3] {
        [
            (self.run_start, self.identifier_start),
            (self.inner_open_start, self.inner_close_end),
            (self.outer_close_end, self.semicolon_end),
        ]
    }
}

/// A live terminating semicolon owned directly by `node`.
fn cpp_direct_semicolon(node: Node<'_>) -> Option<Node<'_>> {
    node.child(node.child_count().checked_sub(1)?)
        .filter(|child| child.kind() == ";" && !child.is_missing())
}

/// The known pre-ANSI prototype macros whose expansion is exactly their one
/// argument. The malformed CST cannot prove that an arbitrary identifier has
/// that definition, so unknown spellings fail closed rather than turning an
/// ordinary broken declaration into a Function (issue #2932).
fn cpp_is_prototype_macro_identifier(node: Node<'_>, source: &str) -> bool {
    matches!(
        node.kind(),
        "identifier" | "type_identifier" | "field_identifier" | "namespace_identifier"
    ) && matches!(
        normalize_cpp_whitespace(node_text(node, source)).as_str(),
        "_" | "__P" | "OF" | "PROTO"
    )
}

/// Read tree-sitter's recovery for `declared_name MACRO`: a
/// `qualified_identifier` whose separator is MISSING, whose `scope` is the
/// declared name, and whose `name` is a known prototype macro.
fn cpp_prototype_macro_qualified_parts<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, Node<'tree>)> {
    if node.kind() != "qualified_identifier" {
        return None;
    }
    let declared_name = node
        .child_by_field_name("scope")
        .filter(|scope| matches!(scope.kind(), "namespace_identifier" | "identifier"))?;
    let macro_name = macro_decorated_unqualified_name(node)?;
    cpp_is_prototype_macro_identifier(macro_name, source).then_some((declared_name, macro_name))
}

/// The inner parenthesized node of tree-sitter's structured
/// `MACRO((parameters))` argument list. Keeping this node's exact range drops
/// the macro invocation's outer parentheses while retaining the one pair an
/// ordinary function declarator needs. No delimiter search is involved: both
/// pairs and their ownership come from the CST.
fn cpp_prototype_macro_inner_arguments(arguments: Node<'_>) -> Option<Node<'_>> {
    if arguments.kind() != "argument_list"
        || arguments.named_child_count() != 1
        || arguments.child_count() != 3
        || arguments
            .child(0)
            .is_none_or(|open| open.kind() != "(" || open.is_missing())
        || arguments
            .child(2)
            .is_none_or(|close| close.kind() != ")" || close.is_missing())
    {
        return None;
    }
    let inner = arguments.named_child(0)?;
    let close_index = match inner.kind() {
        "parenthesized_expression" => inner.child_count().checked_sub(1)?,
        // tree-sitter completes the C++ cast production with a zero-width
        // value after the live close parenthesis.
        "cast_expression" => inner.child_count().checked_sub(2)?,
        _ => return None,
    };
    (inner
        .child(0)
        .is_some_and(|open| open.kind() == "(" && !open.is_missing())
        && inner
            .child(close_index)
            .is_some_and(|close| close.kind() == ")" && !close.is_missing()))
    .then_some(inner)
}

fn cpp_prototype_macro_candidate_from_init_declaration(
    declaration: Node<'_>,
    source: &str,
) -> Option<PrototypeMacroCandidate> {
    let init = declaration
        .child_by_field_name("declarator")
        .filter(|declarator| declarator.kind() == "init_declarator")?;
    let malformed_declarator = init.child_by_field_name("declarator")?;
    let (declared_name, macro_name) = if malformed_declarator.kind() == "qualified_identifier" {
        cpp_prototype_macro_qualified_parts(malformed_declarator, source)?
    } else {
        if !cpp_is_prototype_macro_identifier(malformed_declarator, source) {
            return None;
        }
        let declared_name_error = init
            .prev_named_sibling()
            .filter(|previous| previous.kind() == "ERROR" && previous.named_child_count() == 1)?;
        let declared_name = declared_name_error
            .named_child(0)
            .filter(|name| matches!(name.kind(), "identifier" | "field_identifier"))?;
        (declared_name, malformed_declarator)
    };
    let arguments = init
        .child_by_field_name("value")
        .filter(|value| value.kind() == "argument_list")?;
    let inner = cpp_prototype_macro_inner_arguments(arguments)?;
    let semicolon = cpp_direct_semicolon(declaration)?;
    let return_type = declaration.child_by_field_name("type")?;
    if return_type.end_byte() > declared_name.start_byte()
        || declared_name.end_byte() > macro_name.start_byte()
        || macro_name.end_byte() > arguments.start_byte()
        || arguments.end_byte() > semicolon.start_byte()
    {
        return None;
    }
    Some(PrototypeMacroCandidate {
        run_start: declaration.start_byte(),
        identifier_start: macro_name.start_byte(),
        inner_open_start: inner.start_byte(),
        inner_close_end: inner.end_byte(),
        outer_close_end: arguments.end_byte(),
        semicolon_end: semicolon.end_byte(),
    })
}

fn cpp_prototype_macro_candidate_from_qualified_declaration(
    declaration: Node<'_>,
    source: &str,
) -> Option<PrototypeMacroCandidate> {
    let qualified = declaration
        .child_by_field_name("declarator")
        .filter(|declarator| declarator.kind() == "qualified_identifier")?;
    let (_, macro_name) = cpp_prototype_macro_qualified_parts(qualified, source)?;
    let open_error = qualified
        .next_named_sibling()
        .filter(|next| next.kind() == "ERROR")?;
    let close_error = last_named_child(declaration)
        .filter(|last| last.kind() == "ERROR" && !same_node(*last, open_error))?;
    if open_error.child_count() < 3
        || open_error
            .child(0)
            .is_none_or(|open| open.kind() != "(" || open.is_missing())
        || open_error
            .child(1)
            .is_none_or(|open| open.kind() != "(" || open.is_missing())
        || close_error.child_count() != 2
        || close_error
            .child(0)
            .is_none_or(|close| close.kind() != ")" || close.is_missing())
        || close_error
            .child(1)
            .is_none_or(|close| close.kind() != ")" || close.is_missing())
    {
        return None;
    }
    let inner_open = open_error.child(1)?;
    let inner_close = close_error.child(0)?;
    let outer_close = close_error.child(1)?;
    let semicolon = cpp_direct_semicolon(declaration)?;
    let return_type = declaration.child_by_field_name("type")?;
    if return_type.end_byte() > qualified.start_byte()
        || macro_name.end_byte() > open_error.start_byte()
        || inner_open.start_byte() > inner_close.end_byte()
        || inner_close.end_byte() > outer_close.start_byte()
        || outer_close.end_byte() > semicolon.start_byte()
    {
        return None;
    }
    Some(PrototypeMacroCandidate {
        run_start: declaration.start_byte(),
        identifier_start: macro_name.start_byte(),
        inner_open_start: inner_open.start_byte(),
        inner_close_end: inner_close.end_byte(),
        outer_close_end: outer_close.end_byte(),
        semicolon_end: semicolon.end_byte(),
    })
}

fn cpp_prototype_macro_candidate_from_pointer_expression(
    statement: Node<'_>,
    source: &str,
) -> Option<PrototypeMacroCandidate> {
    if statement.kind() != "expression_statement"
        || statement.named_child_count() != 1
        || !statement.has_error()
    {
        return None;
    }
    let expansion = statement
        .named_child(0)
        .filter(|child| child.kind() == "parameter_pack_expansion")?;
    let binary = expansion
        .child_by_field_name("pattern")
        .filter(|pattern| pattern.kind() == "binary_expression")?;
    if binary.child_count() != 3
        || binary
            .child(1)
            .is_none_or(|operator| operator.kind() != "*" || operator.is_missing())
        || expansion
            .child(expansion.child_count().checked_sub(1)?)
            .is_none_or(|ellipsis| ellipsis.kind() != "..." || !ellipsis.is_missing())
    {
        return None;
    }
    let return_type = binary.child_by_field_name("left")?;
    let call = binary
        .child_by_field_name("right")
        .filter(|right| right.kind() == "call_expression")?;
    let qualified = call.child_by_field_name("function")?;
    let (declared_name, macro_name) = cpp_prototype_macro_qualified_parts(qualified, source)?;
    let arguments = call
        .child_by_field_name("arguments")
        .filter(|arguments| arguments.kind() == "argument_list")?;
    let inner = cpp_prototype_macro_inner_arguments(arguments)?;
    let semicolon = cpp_direct_semicolon(statement)?;
    if return_type.end_byte() > declared_name.start_byte()
        || macro_name.end_byte() > arguments.start_byte()
        || arguments.end_byte() > semicolon.start_byte()
    {
        return None;
    }
    Some(PrototypeMacroCandidate {
        run_start: statement.start_byte(),
        identifier_start: macro_name.start_byte(),
        inner_open_start: inner.start_byte(),
        inner_close_end: inner.end_byte(),
        outer_close_end: arguments.end_byte(),
        semicolon_end: semicolon.end_byte(),
    })
}

/// Recover only CST shapes whose fields preserve the declaration name, macro
/// invocation, nested argument list, and terminator. Arbitrary flattened
/// `ERROR` wreckage stays unsupported rather than being interpreted through a
/// token or delimiter scan (issue #2932).
fn cpp_prototype_macro_candidates(node: Node<'_>, source: &str) -> Vec<PrototypeMacroCandidate> {
    let candidate = match node.kind() {
        "declaration" if node.has_error() => {
            cpp_prototype_macro_candidate_from_init_declaration(node, source)
                .or_else(|| cpp_prototype_macro_candidate_from_qualified_declaration(node, source))
        }
        "expression_statement" => {
            cpp_prototype_macro_candidate_from_pointer_expression(node, source)
        }
        _ => None,
    };
    candidate.into_iter().collect()
}

fn cpp_macro_swallowed_declaration_envelope(node: Node<'_>, source: &str) -> bool {
    if !node.has_error() || !matches!(node.kind(), "ERROR" | "function_definition") {
        return false;
    }
    if node.kind() == "function_definition" && node.child_by_field_name("type").is_some() {
        return false;
    }
    let Some(declarator) = (if node.kind() == "function_definition" {
        node.child_by_field_name("declarator")
            .and_then(extract_function_declarator)
    } else {
        node.named_child(0)
            .filter(|child| child.kind() == "function_declarator")
    }) else {
        return false;
    };
    let Some(name) = cpp_function_declarator_name_node(declarator) else {
        return false;
    };
    declarator.start_byte() == node.start_byte()
        && name.kind() == "identifier"
        && cpp_export_macro_token(&normalize_cpp_whitespace(node_text(name, source)))
}

/// Reparse a fragmented class-body interior while preserving its original byte
/// and line offsets, confined to the region by tree-sitter included ranges.
///
/// This used to materialize the region's whole file prefix as whitespace and
/// make the lexer walk it, the technique #1309 replaced on the other reparse
/// path: O(file) per fragmented-class recovery, on files that are already
/// error-recovered and already slow (#2788). Included ranges give the parser
/// the same view -- the region's bytes, at their original offsets and
/// line/column positions -- without materializing or lexing anything before it.
///
/// The equality of the two views is the claim, so a debug build parses both and
/// asserts the trees agree node for node.
fn cpp_reparse_fragmented_class_body(source: &str, start: usize, end: usize) -> Option<Tree> {
    let region = cpp_reparse_region_items(source, start, end);

    #[cfg(debug_assertions)]
    assert_eq!(
        region.as_ref().map(cpp_tree_shape),
        cpp_reparse_padded_class_body(source, start, end)
            .as_ref()
            .map(cpp_tree_shape),
        "the region reparse of [{start}, {end}) must be the parse a whitespace-padded \
         prefix produces"
    );

    region
}

/// The whitespace-padded reparse [`cpp_reparse_fragmented_class_body`]
/// replaces, kept as the oracle a debug build asserts every region reparse
/// against and as the release-mode parity tests' reference (#2788).
#[cfg(any(debug_assertions, test))]
fn cpp_reparse_padded_class_body(source: &str, start: usize, end: usize) -> Option<Tree> {
    if start >= end {
        // The included-range parser refuses an empty region; the padded one
        // returned a tree holding nothing, which every caller read as "no
        // members here".
        return None;
    }
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

/// Every node of `tree` in preorder, by kind, span and position, which is what
/// two reparses of one region have to agree on for their callers to read the
/// same declarations out of either (#2788).
#[cfg(any(debug_assertions, test))]
fn cpp_tree_shape(tree: &Tree) -> Vec<(&'static str, usize, usize, usize, usize, bool, bool)> {
    let mut shape = Vec::new();
    let mut cursor = tree.root_node().walk();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        shape.push((
            node.kind(),
            node.start_byte(),
            node.end_byte(),
            node.start_position().row,
            node.start_position().column,
            node.is_named(),
            node.is_missing(),
        ));
        let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    shape
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

/// Recognize the alternate constraint-macro prefix where tree-sitter retains
/// the complete qualified constraint as a fourth child instead of moving it
/// into the following function. Keep the gate tied to a two-type template
/// constraint that names the declared type parameter.
fn cpp_reparsed_template_macro_constraint_prefix_parameter<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    if node.kind() != "ERROR" {
        return None;
    }
    let mut cursor = node.walk();
    let named = node.named_children(&mut cursor).collect::<Vec<_>>();
    let [parameter, macro_name, message, constraint] = named.as_slice() else {
        return None;
    };
    let parameter_name = parameter.named_child(0)?;
    let constraint_scope = constraint.child_by_field_name("scope")?;
    let constraint_template = constraint.child_by_field_name("name")?;
    let constraint_arguments = constraint_template.child_by_field_name("arguments")?;
    let mut argument_cursor = constraint_arguments.walk();
    let constraint_types = constraint_arguments
        .named_children(&mut argument_cursor)
        .collect::<Vec<_>>();
    if parameter.kind() != "type_parameter_declaration"
        || parameter_name.kind() != "type_identifier"
        || macro_name.kind() != "type_identifier"
        || !cpp_export_macro_token(&normalize_cpp_whitespace(node_text(*macro_name, source)))
        || message.kind() != "string_literal"
        || constraint.kind() != "qualified_identifier"
        || constraint_scope.kind() != "namespace_identifier"
        || !matches!(
            constraint_template.kind(),
            "template_function" | "template_type"
        )
        || !matches!(constraint_types.as_slice(), [left, right]
            if left.kind() == "type_descriptor" && right.kind() == "type_descriptor")
        || constraint_arguments.has_error()
    {
        return None;
    }
    let parameter_text = node_text(parameter_name, source);
    let mut stack = constraint_types;
    while let Some(current) = stack.pop() {
        if current.kind() == "type_identifier" && node_text(current, source) == parameter_text {
            return Some(parameter_name);
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    None
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

fn cpp_reparsed_template_macro_function_companion_is_indexable(
    node: Node<'_>,
    parameter_name: Node<'_>,
    source: &str,
) -> bool {
    if node.has_error() || cpp_reparsed_member_function_body(node).is_none() {
        return false;
    }
    let Some(return_type) = node.child_by_field_name("type") else {
        return false;
    };
    let Some(function_declarator) = node
        .child_by_field_name("declarator")
        .and_then(extract_function_declarator)
    else {
        return false;
    };
    if cpp_function_declarator_name_node(function_declarator).is_none()
        || !cpp_reparsed_member_return_type_is_indexable(return_type, source)
    {
        return false;
    }
    let Some(parameters) = function_declarator.child_by_field_name("parameters") else {
        return false;
    };
    let parameter_text = node_text(parameter_name, source);
    parameters
        .named_children(&mut parameters.walk())
        .any(|parameter| {
            parameter
                .child_by_field_name("type")
                .is_some_and(|parameter_type| node_text(parameter_type, source) == parameter_text)
        })
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
    if let Some(parameter_name) = cpp_reparsed_template_macro_prefix_parameter(node, source) {
        return cpp_next_non_comment_named_sibling(node).is_some_and(|function| {
            cpp_reparsed_template_macro_companion_is_indexable(function, parameter_name, source)
                || cpp_reparsed_template_macro_constructor_companion_is_indexable(
                    function,
                    parameter_name,
                    source,
                )
        });
    }
    let Some(parameter_name) =
        cpp_reparsed_template_macro_constraint_prefix_parameter(node, source)
    else {
        return false;
    };
    cpp_next_non_comment_named_sibling(node).is_some_and(|function| {
        cpp_reparsed_template_macro_function_companion_is_indexable(
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

/// Recognize the three top-level nodes produced when an unknown attribute
/// macro separates an inline member's declarator from its body in a reparsed
/// class interior: an errorful declaration with a missing semicolon, the macro
/// call expression, and the complete compound body. Their adjacency and exact
/// structured shapes prove one recoverable member envelope; arbitrary calls or
/// blocks do not pass this gate.
fn cpp_reparsed_macro_attribute_member_sequence(
    children: &[Node<'_>],
    index: usize,
    source: &str,
) -> bool {
    let Some(prefix) = children.get(index).copied() else {
        return false;
    };
    let declaration = if prefix.kind() == "labeled_statement" {
        prefix
            .named_child(prefix.named_child_count().saturating_sub(1))
            .filter(|child| child.kind() == "declaration")
    } else {
        (prefix.kind() == "declaration").then_some(prefix)
    };
    let Some(declaration) = declaration else {
        return false;
    };
    if !declaration.has_error()
        || declaration
            .child_by_field_name("declarator")
            .and_then(extract_function_declarator)
            .and_then(cpp_function_declarator_name_node)
            .is_none()
    {
        return false;
    }
    let Some(attribute_statement) = children.get(index + 1).copied() else {
        return false;
    };
    let Some(attribute_call) = (attribute_statement.kind() == "expression_statement")
        .then(|| attribute_statement.named_child(0))
        .flatten()
        .filter(|child| child.kind() == "call_expression")
    else {
        return false;
    };
    let Some(attribute_name) = attribute_call
        .child_by_field_name("function")
        .filter(|function| function.kind() == "identifier")
        .map(|function| normalize_cpp_whitespace(node_text(function, source)))
    else {
        return false;
    };
    if !cpp_export_macro_token(&attribute_name) {
        return false;
    }
    let Some(body) = children.get(index + 2).copied() else {
        return false;
    };
    body.kind() == "compound_statement"
        && body.child(0).is_some_and(|open| open.kind() == "{")
        && body
            .child(body.child_count().saturating_sub(1))
            .is_some_and(|close| close.kind() == "}" && !close.is_missing())
        && declaration.end_byte() <= attribute_statement.start_byte()
        && attribute_statement.end_byte() <= body.start_byte()
}

/// Whether a reparsed `ERROR` holds nothing but member declarations: a run of
/// types and specifiers followed by a declarator, over and over, with nothing
/// left over. A string-argument attribute macro is what strands them there, and
/// the walk indexes exactly what this reads, so admitting the region is safe
/// (#2552). Without it Botan's `DL_Group` was indexed with no members at all,
/// because one `BOTAN_DEPRECATED("...") explicit DL_Group(...)` member rejected
/// the whole class body.
fn cpp_reparsed_stranded_member_error(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "ERROR" {
        return false;
    }
    let run = stranded_declaration_run(node, source);
    run.complete && !run.declarations.is_empty()
}

fn cpp_reparsed_members_are_indexable(root: Node<'_>, source: &str) -> bool {
    let mut cursor = root.walk();
    let children = root.named_children(&mut cursor).collect::<Vec<_>>();
    let mut saw_member = false;
    let mut index = 0;
    while index < children.len() {
        let child = children[index];
        if cpp_reparsed_macro_attribute_member_sequence(&children, index, source) {
            saw_member = true;
            index += 3;
            continue;
        }
        if let Some((_, _, fragmented)) = fragmented_plain_class_body(child, source) {
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
            // The attribute a string-argument macro leaves as a call statement
            // of its own. It declares nothing; the member it decorated is the
            // sibling after it, checked on its own turn.
            "expression_statement" if is_string_attribute_macro_statement(child) => {}
            "ERROR"
                if (cpp_reparsed_member_error_is_indexable(child)
                    || cpp_reparsed_adjacent_copy_control_error(child, source)
                    || cpp_reparsed_stranded_member_error(child, source))
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
                            || cpp_reparsed_stranded_member_error(error, source)
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

/// Recover an inline constructor that a function-like export macro makes
/// tree-sitter merge with the following overload. In the reparsed class-body
/// region, the access label wraps one declaration whose ERROR contains the
/// constructor declarator and its base-initializer/body, while the declaration's
/// ordinary declarator is the following overload. Every boundary below comes
/// from that CST; no source syntax is reparsed by hand.
fn cpp_reparsed_merged_inline_constructor<'tree>(
    root: Node<'tree>,
    class_name: &str,
    source: &str,
) -> Option<(std::ops::Range<usize>, Node<'tree>)> {
    let mut stack = vec![root];
    while let Some(current) = stack.pop() {
        if current.kind() != "labeled_statement" {
            let mut cursor = current.walk();
            stack.extend(current.named_children(&mut cursor));
            continue;
        }
        let declaration = current
            .named_children(&mut current.walk())
            .find(|child| child.kind() == "declaration")?;
        if declaration
            .child_by_field_name("type")
            .is_none_or(|kind| node_text(kind, source).trim() != "explicit")
        {
            continue;
        }
        let following = declaration
            .child_by_field_name("declarator")
            .and_then(extract_function_declarator)
            .and_then(cpp_function_declarator_name_node);
        if following.is_none_or(|name| node_text(name, source).trim() != class_name) {
            continue;
        }
        let mut declaration_cursor = declaration.walk();
        let Some(error) = declaration
            .named_children(&mut declaration_cursor)
            .find(|child| child.kind() == "ERROR")
        else {
            continue;
        };
        let mut error_cursor = error.walk();
        let error_children = error.named_children(&mut error_cursor).collect::<Vec<_>>();
        let Some(constructor) = error_children.iter().copied().find(|child| {
            child.kind() == "function_declarator"
                && cpp_function_declarator_name_node(*child)
                    .is_some_and(|name| node_text(name, source).trim() == class_name)
        }) else {
            continue;
        };
        let Some(body) = error_children.iter().copied().find_map(|child| {
            (child.kind() == "init_declarator")
                .then(|| child.child_by_field_name("value"))
                .flatten()
                .filter(|value| value.kind() == "initializer_list")
        }) else {
            continue;
        };
        if constructor.end_byte() > body.start_byte() {
            continue;
        }
        return Some((constructor.start_byte()..body.end_byte(), body));
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
        finish_code_unit_removal_scan_probe, finish_declaration_identity_comparison_probe,
        start_code_unit_removal_scan_probe, start_declaration_identity_comparison_probe,
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
    fn macro_redefinitions_keep_distinct_structured_declaration_identities() {
        let source = "#define VALUE 1\n#undef VALUE\n#define VALUE 2\n";
        let parsed = parse_cpp_declarations(source, "macro-redefinition.c");
        let mut macros = parsed
            .declarations()
            .iter()
            .filter(|unit| unit.is_macro() && unit.identifier() == "VALUE")
            .collect::<Vec<_>>();
        macros.sort_by_key(|unit| parsed.declaration_ranges(unit)[0].start_byte);

        assert_eq!(macros.len(), 2, "{macros:#?}");
        assert_eq!(macros[0].signature(), Some("#define VALUE 1"));
        assert_eq!(macros[1].signature(), Some("#define VALUE 2"));
        assert_eq!(parsed.declaration_ranges(macros[0])[0].start_byte, 0);
        assert_eq!(
            parsed.declaration_ranges(macros[1])[0].start_byte,
            source.rfind("#define VALUE 2").expect("second definition")
        );
    }

    #[test]
    fn identifies_export_macro_class_base_displaced_into_declarator() {
        let source = r#"#define PROJECT_API_
namespace project {
namespace internal {
template <typename T>
class Base {};
}
template <typename T>
class Wrapper;
template <>
class PROJECT_API_ [[nodiscard]] Wrapper<int> : public internal::Base<int> {};
}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let start = source.find("internal::Base<int>").expect("base");
        let mut base = tree
            .root_node()
            .descendant_for_byte_range(start, start + 8)
            .expect("base syntax");
        while base.kind() != "qualified_identifier" {
            base = base.parent().expect("qualified base ancestor");
        }
        assert!(
            is_recovered_exported_class_base_type_node(base, source),
            "{}",
            tree.root_node().to_sexp()
        );
    }

    fn function_identities(parsed: &ParsedFile) -> Vec<(String, String)> {
        let mut identities = parsed
            .declarations()
            .iter()
            .filter(|unit| unit.is_function())
            .map(|unit| {
                (
                    unit.fq_name(),
                    unit.signature().unwrap_or_default().to_string(),
                )
            })
            .collect::<Vec<_>>();
        identities.sort();
        identities
    }

    /// #2932. Recover the parser-owned declaration shapes for known pre-ANSI
    /// prototype macros. Each case is parsed independently so a preceding
    /// malformed line cannot flatten the next declaration's fields into one
    /// cascading `ERROR`; that shape has no structural proof and must fail
    /// closed rather than fall back to a token scan. Parameter names are
    /// dropped from signatures just as they are for ordinary C prototypes.
    #[test]
    fn c_prototype_macro_recovers_parser_owned_declaration_shapes() {
        let cases = [
            (
                "VALUE pg_typemap_fit_to_result _(( VALUE, VALUE ));",
                "pg_typemap_fit_to_result",
                "(VALUE, VALUE)",
            ),
            (
                "VALUE pg_typemap_result_value _(( t_typemap *, VALUE, int, int ));",
                "pg_typemap_result_value",
                "(t_typemap *, VALUE, int, int)",
            ),
            (
                "void pg_typemap_mark _(( void * ));",
                "pg_typemap_mark",
                "(void *)",
            ),
            (
                "void init_pg_type_map _(( void ));",
                "init_pg_type_map",
                "(void)",
            ),
            ("static VALUE pg_static _(( void ));", "pg_static", "(void)"),
            (
                "extern VALUE pg_extern _(( VALUE, VALUE ));",
                "pg_extern",
                "(VALUE, VALUE)",
            ),
            (
                "size_t pg_typemap_memsize _(( const void * ));",
                "pg_typemap_memsize",
                "(const void *)",
            ),
            (
                "VALUE pg_wrap_socket_io _(( int sd, VALUE self, VALUE *p_socket_io, int *p_ruby_sd ));",
                "pg_wrap_socket_io",
                "(int, VALUE, VALUE *, int *)",
            ),
            ("VALUE pg_dunder __P(( VALUE ));", "pg_dunder", "(VALUE)"),
            ("VALUE pg_of OF(( VALUE ));", "pg_of", "(VALUE)"),
            ("VALUE pg_proto PROTO(( VALUE ));", "pg_proto", "(VALUE)"),
        ];

        for (index, (source, name, signature)) in cases.into_iter().enumerate() {
            let parsed = parse_cpp_declarations(source, &format!("prototype_{index}.h"));
            assert_eq!(
                function_identities(&parsed),
                vec![(name.to_string(), signature.to_string())],
                "{source}: {:#?}",
                parsed.declarations()
            );
            assert!(
                parsed.declarations().iter().all(|unit| !unit.is_field()),
                "{source} must not retain the malformed field: {:#?}",
                parsed.declarations()
            );
        }
    }

    /// #2932. `T *name _(( args ));` with a pointer return type and a simple
    /// argument list parses with no `ERROR` node at all -- tree-sitter reads
    /// it as a multiplication of a type by a call
    /// (`identifier "T" '*' call_expression{qualified_identifier{...}}`),
    /// wrapped in an `expression_statement` that `has_error()` only because
    /// of the `MISSING "::"` inside the `qualified_identifier`. Reproduced
    /// here with a clean preceding field so the prototype remains the
    /// parser-owned `expression_statement` this recovery requires.
    #[test]
    fn c_prototype_macro_recovers_pointer_return_expression_statements() {
        let cases = [
            (
                "PGconn *pg_get_pgconn _(( VALUE ));",
                "pg_get_pgconn",
                "(VALUE)",
            ),
            (
                "PGresult* pgresult_get _(( VALUE ));",
                "pgresult_get",
                "(VALUE)",
            ),
        ];
        for (index, (prototype, name, signature)) in cases.into_iter().enumerate() {
            let source = format!("extern VALUE rb_mPG;\n{prototype}\n");
            let parsed = parse_cpp_declarations(&source, &format!("pointer_{index}.h"));
            assert_eq!(
                function_identities(&parsed),
                vec![(name.to_string(), signature.to_string())],
                "{source}: {:#?}",
                parsed.declarations()
            );
            assert_eq!(
                parsed
                    .declarations()
                    .iter()
                    .filter(|unit| unit.is_field())
                    .map(|unit| unit.fq_name())
                    .collect::<Vec<_>>(),
                vec!["rb_mPG".to_string()],
                "{source}: {:#?}",
                parsed.declarations()
            );
        }
    }

    /// #2932 acceptance. Keep the exact issue witness inside the surrounding
    /// `ext/pg.h` block, where tree-sitter's cascading recovery produces both
    /// field-preserving declaration shapes and ambiguous flattened `ERROR`
    /// regions. The witnessed declaration must still become a Function and
    /// its type must not survive as the name of a bogus Field. This test does
    /// not claim that structurally flattened neighboring prototypes are safe
    /// to recover.
    #[test]
    fn c_prototype_macro_recovers_the_issue_witness_inside_the_real_ruby_pg_header_block() {
        let source = r#"VALUE pg_typemap_fit_to_result                         _(( VALUE, VALUE ));
VALUE pg_typemap_fit_to_query                          _(( VALUE, VALUE ));
int pg_typemap_fit_to_copy_get                         _(( VALUE ));
VALUE pg_typemap_result_value                          _(( t_typemap *, VALUE, int, int ));
t_pg_coder *pg_typemap_typecast_query_param            _(( t_typemap *, VALUE, int ));
VALUE pg_typemap_typecast_copy_get                     _(( t_typemap *, VALUE, int, int, int ));
void pg_typemap_mark                                   _(( void * ));
size_t pg_typemap_memsize                              _(( const void * ));
void pg_typemap_compact                                _(( void * ));

PGconn *pg_get_pgconn                                  _(( VALUE ));
t_pg_connection *pg_get_connection                     _(( VALUE ));
VALUE pgconn_block                                     _(( int, VALUE *, VALUE ));
#ifdef __GNUC__
__attribute__((format(printf, 3, 4)))
#endif
NORETURN(void pg_raise_conn_error                      _(( VALUE klass, VALUE self, const char *format, ...)));
VALUE pg_wrap_socket_io                                _(( int sd, VALUE self, VALUE *p_socket_io, int *p_ruby_sd ));
void pg_unwrap_socket_io                               _(( VALUE self, VALUE *p_socket_io, int ruby_sd ));


VALUE pg_new_result                                    _(( PGresult *, VALUE ));
VALUE pg_new_result_autoclear                          _(( PGresult *, VALUE ));
PGresult* pgresult_get                                 _(( VALUE ));
VALUE pg_result_check                                  _(( VALUE ));
VALUE pg_result_clear                                  _(( VALUE ));
VALUE pg_tuple_new                                     _(( VALUE, int ));

/*
 * Fetch the data pointer for the result object
 */
static inline t_pg_result *
pgresult_get_this( VALUE self )
{
	return RTYPEDDATA_DATA(self);
}


rb_encoding * pg_get_pg_encname_as_rb_encoding         _(( const char * ));
const char * pg_get_rb_encoding_as_pg_encoding         _(( rb_encoding * ));
rb_encoding *pg_conn_enc_get                           _(( PGconn * ));

"#;
        let parsed = parse_cpp_declarations(source, "pg.h");
        assert!(
            function_identities(&parsed)
                .iter()
                .any(|(name, signature)| name == "pg_typemap_result_value"
                    && signature == "(t_typemap *, VALUE, int, int)"),
            "the real issue witness must be a Function with its C signature: {:#?}",
            parsed.declarations()
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .all(|unit| !(unit.is_field() && unit.identifier() == "VALUE")),
            "the issue witness must not leave its return type as a Field name: {:#?}",
            parsed.declarations()
        );
    }

    /// #2552 shape 1. Tree-sitter glues an attribute-like macro that stands
    /// between `explicit` and a constructor name onto the name, producing a
    /// `qualified_identifier` whose `::` it had to invent. The declared member
    /// is the constructor, not `MACRO Ctor`. The second constructor, with the
    /// macro in type position, was already recovered and is the control that
    /// both spellings agree.
    #[test]
    fn a_macro_decorated_constructor_is_named_for_the_constructor() {
        let source = r#"class SIMD_4x26 final {
   public:
      explicit BOTAN_FN_ISA_AVX2 SIMD_4x26(int v) : m_v(v) {}
      BOTAN_FN_ISA_AVX2 SIMD_4x26() : m_v(0) {}
      int m_v;
};
"#;
        let parsed = parse_cpp_declarations(source, "simd_4x26.h");
        assert_eq!(
            function_identities(&parsed),
            vec![
                ("SIMD_4x26.SIMD_4x26".to_string(), "()".to_string()),
                ("SIMD_4x26.SIMD_4x26".to_string(), "(int)".to_string()),
            ],
            "{:#?}",
            parsed.declarations()
        );
    }

    /// #2552 shape 2. `DEPRECATED(decl, "hint");` makes tree-sitter emit one
    /// `ERROR` holding the wrapped declaration and every declaration after it
    /// until the parser recovers. All of them must be indexed, each with the
    /// byte range that spells it.
    #[test]
    fn a_macro_wrapped_declaration_and_the_declarations_it_swallowed_are_indexed() {
        let source = r#"#include <cstdint>
struct llama_vocab; struct llama_model; struct llama_context; struct llama_context_params {};
    DEPRECATED(LLAMA_API struct llama_context * llama_new_context_with_model(
                     struct llama_model * model,
              struct llama_context_params   params),
            "use llama_init_from_model instead");
    LLAMA_API int32_t llama_tokenize(
        const struct llama_vocab * vocab,
                      const char * text,
                            bool   parse_special);
    LLAMA_API int32_t llama_other(int a);
"#;
        let parsed = parse_cpp_declarations(source, "llama.h");
        assert_eq!(
            function_identities(&parsed),
            vec![
                (
                    "llama_new_context_with_model".to_string(),
                    "(struct llama_model *, struct llama_context_params)".to_string()
                ),
                ("llama_other".to_string(), "(int)".to_string()),
                (
                    "llama_tokenize".to_string(),
                    "(const struct llama_vocab *, const char *, bool)".to_string()
                ),
            ],
            "{:#?}",
            parsed.declarations()
        );

        // Each recovered declaration owns the source that spells it, so
        // navigation lands on the declaration and not on the macro envelope.
        for (name, expected) in [
            (
                "llama_new_context_with_model",
                "LLAMA_API struct llama_context * llama_new_context_with_model(",
            ),
            ("llama_tokenize", "LLAMA_API int32_t llama_tokenize("),
            ("llama_other", "LLAMA_API int32_t llama_other(int a)"),
        ] {
            let unit = parsed
                .declarations()
                .iter()
                .find(|unit| unit.is_function() && unit.fq_name() == name)
                .unwrap_or_else(|| panic!("missing recovered declaration {name}"));
            let [range] = parsed.declaration_ranges(unit) else {
                panic!("{name} must have exactly one range");
            };
            let text = &source[range.start_byte..range.end_byte];
            assert!(
                text.starts_with(expected),
                "{name} range is {text:?}, expected it to start with {expected:?}"
            );
            assert!(
                text.ends_with(')') || text.ends_with(';'),
                "{name}: {text:?}"
            );
        }
    }

    /// Negative controls for the same recovery: a macro invocation whose
    /// arguments are not a declaration recovers nothing, whether the parser
    /// keeps it clean, reads the arguments as a type, or reads them as a bare
    /// declarator.
    #[test]
    fn a_macro_call_without_a_wrapped_declaration_recovers_nothing() {
        for source in [
            "int before;\nFOO(1, 2);\nint after;\n",
            "int before;\nMACRO(struct Foo, \"hint\");\nint after;\n",
            "int before;\nMACRO(int a, int b);\nint after;\n",
            "DECLARE_HANDLE(HWND);\nint after;\n",
        ] {
            let parsed = parse_cpp_declarations(source, "macro-call.h");
            assert_eq!(
                function_identities(&parsed),
                Vec::new(),
                "{source:?} must declare no function: {:#?}",
                parsed.declarations()
            );
        }
    }

    /// #2552 shape 3, plain class. `BOTAN_DEPRECATED("text") explicit Ctor(T);`
    /// makes tree-sitter read the macro as the member's type and its argument
    /// list as a parenthesized declarator, which then swallows the attributed
    /// member and the member written after it. Both are members.
    #[test]
    fn a_string_attribute_macro_member_keeps_itself_and_the_member_after_it() {
        let source = r#"#include <string_view>
namespace Botan {
class DL_Group final {
   public:
      DL_Group() = default;
      BOTAN_DEPRECATED("Use DL_Group::from_name") explicit DL_Group(std::string_view name);
      DL_Group(std::string_view pem, int format);
      size_t get_p() const;
};
}
"#;
        let parsed = parse_cpp_declarations(source, "dl_group.h");
        assert_eq!(
            function_identities(&parsed),
            vec![
                ("Botan.DL_Group.DL_Group".to_string(), "()".to_string()),
                (
                    "Botan.DL_Group.DL_Group".to_string(),
                    "(std::string_view)".to_string()
                ),
                (
                    "Botan.DL_Group.DL_Group".to_string(),
                    "(std::string_view, int)".to_string()
                ),
                ("Botan.DL_Group.get_p".to_string(), "() const".to_string()),
            ],
            "{:#?}",
            parsed.declarations()
        );
    }

    /// #2552 shape 3, export-macro class. The class head macro makes the body a
    /// `compound_statement`, so members come from the region reparse, and one
    /// string-attribute member used to make that reparse unindexable -- which
    /// left the class with no members at all.
    #[test]
    fn an_export_macro_class_keeps_its_string_attribute_members() {
        let source = r#"#include <string_view>
namespace Botan {
class BOTAN_PUBLIC_API(2, 0) DL_Group final {
   public:
      BOTAN_DEPRECATED("Use DL_Group::from_name") explicit DL_Group(std::string_view name);
      DL_Group(std::string_view pem, int format);
      size_t get_p() const;
};
}
"#;
        let parsed = parse_cpp_declarations(source, "dl_group.h");
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| unit.is_class() && unit.fq_name() == "Botan.DL_Group"),
            "{:#?}",
            parsed.declarations()
        );
        assert_eq!(
            function_identities(&parsed),
            vec![
                (
                    "Botan.DL_Group.DL_Group".to_string(),
                    "(std::string_view)".to_string()
                ),
                (
                    "Botan.DL_Group.DL_Group".to_string(),
                    "(std::string_view, int)".to_string()
                ),
                ("Botan.DL_Group.get_p".to_string(), "() const".to_string()),
            ],
            "{:#?}",
            parsed.declarations()
        );
    }

    /// #2552 shape 3, the `= default` variant plus the access-label
    /// constructor. The attributed defaulted constructor separates cleanly, but
    /// it strands the next member in a bare `ERROR`, and a constructor written
    /// with a member-initializer list under `private:` dissolves into
    /// expression soup that the reparse recovers from its own source range.
    #[test]
    fn an_export_macro_class_keeps_stranded_and_access_labeled_constructors() {
        let source = r#"namespace Botan {
class BOTAN_PUBLIC_API(2, 0) XMSS_Parameters final {
   public:
      BOTAN_DEPRECATED("Deprecated no replacement") XMSS_Parameters() = default;
      XMSS_Parameters(int oid, int len);
      size_t len() const;

   private:
      XMSS_Parameters(int oid, int wots_oid, size_t hash_len, size_t tree_height) :
            m_oid(oid), m_wots_oid(wots_oid), m_element_size(hash_len), m_tree_height(tree_height) {}

      int m_oid;
      int m_wots_oid;
      size_t m_element_size;
      size_t m_tree_height;
};
}
"#;
        let parsed = parse_cpp_declarations(source, "xmss_parameters.h");
        let constructors = function_identities(&parsed)
            .into_iter()
            .filter(|(name, _)| name == "Botan.XMSS_Parameters.XMSS_Parameters")
            .map(|(_, signature)| signature)
            .collect::<Vec<_>>();
        assert_eq!(
            constructors,
            vec![
                "()".to_string(),
                "(int, int)".to_string(),
                "(int, int, size_t, size_t)".to_string(),
            ],
            "{:#?}",
            parsed.declarations()
        );
    }

    /// Negative control for the same rule: a real qualified name spells its
    /// `::` in the source, so the separator is present rather than MISSING and
    /// the out-of-line definition keeps its owner.
    #[test]
    fn a_genuine_qualified_out_of_line_definition_keeps_its_scope() {
        let source = r#"namespace shell {
struct Outer {
   struct Inner {
      Inner(int v);
      void run(int v);
   };
};
Outer::Inner::Inner(int v) {}
void Outer::Inner::run(int v) {}
}
"#;
        let parsed = parse_cpp_declarations(source, "outer.cpp");
        let names = function_identities(&parsed)
            .into_iter()
            .map(|(fq_name, _)| fq_name)
            .collect::<Vec<_>>();
        assert!(
            names
                .iter()
                .all(|name| name.starts_with("shell.Outer$Inner.")),
            "{names:#?}"
        );
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

        assert!(owner.is_none());
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
        let ancestry = ParentIndex::new(tree.root_node());
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "function_definition" {
                let mut current = node.parent();
                while let Some(parent) = current {
                    if matches!(
                        parent.kind(),
                        "class_specifier" | "struct_specifier" | "union_specifier"
                    ) {
                        return cpp_callable_linkage(node, source, &ancestry);
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
    struct impl;
    struct impl& get_impl() const;
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
        let recovered_member = declarations
            .iter()
            .find(|unit| unit.is_function() && unit.fq_name() == "Sender.get_impl")
            .unwrap_or_else(|| panic!("missing recovered Sender member: {declarations:#?}"));
        assert_eq!(
            parsed
                .signature_metadata
                .get(recovered_member)
                .and_then(|metadata| metadata.first())
                .and_then(SignatureMetadata::callable_linkage),
            Some(CallableLinkage::External),
            "a named recovered class's members have external linkage"
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
    fn function_like_export_macro_classes_keep_names_and_base_edges() {
        // Every sibling shape tree-sitter produces after the `class MACRO(2, 0)`
        // error: a plain body, a single base, `final` without a base, `final`
        // with one base, and `final` with a comma-separated base list.
        let source = r#"
namespace api {
class PROJECT_PUBLIC_API(2, 0) Prelude {
  public:
    Prelude();
};
class PROJECT_PUBLIC_API(2, 0) Base {
  public:
    Base(int value);
};
class PROJECT_PUBLIC_API(2, 0) Mixin {
  public:
    Mixin();
};
class PROJECT_PUBLIC_API(2, 0) Adopted : public Base {
  public:
    Adopted(int value);
};
class PROJECT_PUBLIC_API(2, 0) Derived final : public Base {
  public:
    Derived(int value);
};
class PROJECT_PUBLIC_API(2, 0) Solo final {
  public:
    Solo();
};
class PROJECT_PUBLIC_API(2, 0) Blended final : public Base, public Mixin {
  public:
    Blended(int value);
};
class PROJECT_PUBLIC_API(2, 0) Woven : public Base, public Mixin {
  public:
    Woven(int value);
};
} // namespace api
"#;
        let parsed = parse_cpp_declarations(source, "function-like-export.hpp");
        let declarations = parsed.declarations();
        let class_named = |name: &str| {
            declarations
                .iter()
                .find(|unit| unit.is_class() && unit.fq_name() == name)
                .unwrap_or_else(|| {
                    panic!("missing function-like export macro class {name}: {declarations:#?}")
                })
        };
        let base = class_named("api.Base");
        class_named("api.Prelude");
        class_named("api.Mixin");

        assert_eq!(
            parsed.raw_supertypes.get(class_named("api.Adopted")),
            Some(&vec!["Base".to_string()])
        );
        assert_eq!(
            parsed.raw_supertypes.get(class_named("api.Derived")),
            Some(&vec!["Base".to_string()])
        );
        assert_eq!(
            parsed.raw_supertypes.get(class_named("api.Solo")),
            None,
            "a final class without a base list must not invent a supertype"
        );
        assert_eq!(
            parsed.raw_supertypes.get(class_named("api.Blended")),
            Some(&vec!["Base".to_string(), "Mixin".to_string()])
        );
        assert_eq!(
            parsed.raw_supertypes.get(class_named("api.Woven")),
            Some(&vec!["Base".to_string(), "Mixin".to_string()])
        );
        assert!(
            declarations
                .iter()
                .all(|unit| unit.identifier() != "PROJECT_PUBLIC_API"),
            "the export macro must not become a declaration: {declarations:#?}"
        );
        assert!(
            declarations.iter().all(|unit| !matches!(
                unit.identifier(),
                "final" | "public" | "protected" | "private"
            )),
            "the head specifiers must not become declarations: {declarations:#?}"
        );
        assert!(
            parsed
                .navigation_ranges
                .get(base)
                .is_some_and(|ranges| !ranges.is_empty()),
            "the recovered base must retain a navigable declaration range"
        );
    }

    #[test]
    fn function_like_export_macro_classes_are_named_by_position_not_spelling() {
        // #2557: the class name is the last identifier before the head ends
        // (`final`, the base clause `:`, or the body), whatever its spelling.
        // A class named in capitals (`X509_CA`) is a class, and an object-like
        // macro before the name (`OTHER_MACRO Name`) is decoration. `Name` is
        // the control whose spelling never mattered.
        let source = r#"
namespace api {
class PROJECT_PUBLIC_API(2, 0) Base {
  public:
    Base();
};
class PROJECT_PUBLIC_API(2, 0) Mixin {
  public:
    Mixin();
};
class PROJECT_PUBLIC_API(2, 0) Name {
  public:
    Name();
};
class PROJECT_PUBLIC_API(2, 0) X509_CA final {
  public:
    X509_CA();
};
class PROJECT_PUBLIC_API(2, 0) HSS_LMS_KEY final : public Base, public Mixin {
  public:
    HSS_LMS_KEY();
};
class PROJECT_PUBLIC_API(2, 0) GOST_3410 : public Base {
  public:
    GOST_3410();
};
class PROJECT_PUBLIC_API(2, 0) PKCS11_RSA {
  public:
    PKCS11_RSA();
};
class PROJECT_PUBLIC_API(2, 0) OTHER_MACRO Plain {
  public:
    Plain();
};
class PROJECT_PUBLIC_API(2, 0) OTHER_MACRO Decorated final : public Base {
  public:
    Decorated();
};
class PROJECT_PUBLIC_API(2, 0) FIRST_MACRO SECOND_MACRO Layered final : public Base, public Mixin {
  public:
    Layered();
};
} // namespace api
"#;
        let parsed = parse_cpp_declarations(source, "positional-export.hpp");
        let declarations = parsed.declarations();
        let class_named = |name: &str| {
            declarations
                .iter()
                .find(|unit| unit.is_class() && unit.fq_name() == name)
                .unwrap_or_else(|| {
                    panic!("missing function-like export macro class {name}: {declarations:#?}")
                })
        };
        for (name, bases) in [
            ("api.Name", None),
            ("api.X509_CA", None),
            ("api.HSS_LMS_KEY", Some(vec!["Base", "Mixin"])),
            ("api.GOST_3410", Some(vec!["Base"])),
            ("api.PKCS11_RSA", None),
            ("api.Plain", None),
            ("api.Decorated", Some(vec!["Base"])),
            ("api.Layered", Some(vec!["Base", "Mixin"])),
        ] {
            let expected =
                bases.map(|bases| bases.into_iter().map(str::to_string).collect::<Vec<_>>());
            assert_eq!(
                parsed.raw_supertypes.get(class_named(name)),
                expected.as_ref(),
                "{name}"
            );
        }
        assert!(
            declarations.iter().all(|unit| !matches!(
                unit.identifier(),
                "PROJECT_PUBLIC_API"
                    | "OTHER_MACRO"
                    | "FIRST_MACRO"
                    | "SECOND_MACRO"
                    | "final"
                    | "public"
            )),
            "macros and head specifiers must not become declarations: {declarations:#?}"
        );
    }

    #[test]
    fn embedded_function_like_export_class_is_named_by_position_not_spelling() {
        // The class embedded in a preceding malformed body follows the same
        // rule (#2557): `X509_CA` is the class, `OTHER_MACRO` is decoration.
        let fixture = |head: &str, name: &str| {
            format!(
                r#"
namespace api {{
class PROJECT_PUBLIC_API(2, 0) Exception : public std::exception {{
   public:
      /** Return a descriptive string. */
      const char* what() const noexcept override {{ return m_msg.c_str(); }}

      /** Return the type of error. */
      virtual ErrorType error_type() const noexcept {{ return ErrorType::Unknown; }}

      /** Return an associated error code. */
      virtual int error_code() const noexcept {{ return 0; }}

      /** Avoid throwing the base directly. */
      explicit Exception(std::string_view msg);

      /** Avoid throwing the base directly. */
      Exception(const char* prefix, std::string_view msg);

      /** Avoid throwing the base directly. */
      Exception(std::string_view msg, const std::exception& e);

   private:
      std::string m_msg;
}};

class PROJECT_PUBLIC_API(2, 0) {head} : public Exception {{
   public:
      explicit {name}(std::string_view msg);

      explicit {name}(std::string_view msg, std::string_view where);

      {name}(std::string_view msg, const std::exception& e);

      ErrorType error_type() const noexcept override {{ return ErrorType::InvalidArgument; }}
}};
}} // namespace api
"#
            )
        };
        for (head, name) in [("X509_CA", "X509_CA"), ("OTHER_MACRO Verdict", "Verdict")] {
            let source = fixture(head, name);
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_cpp::LANGUAGE.into())
                .expect("set C++ grammar");
            let tree = parser.parse(&source, None).expect("parse fixture");
            let mut embedded = Vec::new();
            let mut stack = vec![tree.root_node()];
            while let Some(node) = stack.pop() {
                embedded.extend(
                    recover_embedded_function_like_export_classes(node, &source)
                        .into_iter()
                        .map(|recovered| (recovered.name, recovered.raw_supertypes)),
                );
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
            assert!(
                embedded.contains(&(name.to_string(), vec!["Exception".to_string()])),
                "{head}: embedded recovery must name the class by position: {embedded:#?}\n{}",
                tree.root_node().to_sexp()
            );
            assert!(
                embedded
                    .iter()
                    .all(|(recovered, _)| recovered != "OTHER_MACRO"),
                "{head}: the object-like macro is not a class: {embedded:#?}"
            );

            let parsed = parse_cpp_declarations(&source, "embedded-positional-export.hpp");
            let declarations = parsed.declarations();
            let class = declarations
                .iter()
                .find(|unit| unit.is_class() && unit.fq_name() == format!("api.{name}"))
                .unwrap_or_else(|| panic!("{head}: missing embedded class: {declarations:#?}"));
            assert_eq!(
                parsed.raw_supertypes.get(class),
                Some(&vec!["Exception".to_string()]),
                "{head}"
            );
            assert!(
                declarations
                    .iter()
                    .all(|unit| unit.identifier() != "OTHER_MACRO"),
                "{head}: the object-like macro must not become a declaration: {declarations:#?}"
            );
        }
    }

    #[test]
    fn function_like_export_class_head_with_virtual_qualified_bases_does_not_invent_a_name() {
        // Botan's TPM2 keys (`tpm2_ecc.h`, `tpm2_rsa.h`). The grammar swallows
        // the whole head into the `class MACRO(3, 6)` error, keeps the first
        // base as the `type` of the following declaration, and closes that
        // declaration with a zero-width `MISSING identifier`. Reading the head
        // by position must not take that missing node for the class name: an
        // empty name panics at `FqName` construction, which took the Botan
        // corpus replay down (#2557). The class itself stays unrecovered here,
        // and the bodyless `class PROJECT_PUBLIC_API` specifier still surfaces
        // the way it did before this change.
        let source = r#"
namespace api {
class PROJECT_PUBLIC_API(3, 6) EC_PublicKey final : public virtual Botan::TPM2::PublicKey,
                                                    public virtual Botan::EC_PublicKey {
   public:
      std::string algo_name() const override { return "ECDSA"; }
};
} // namespace api
"#;
        let parsed = parse_cpp_declarations(source, "virtual-qualified-bases.hpp");
        let declarations = parsed.declarations();
        assert!(
            declarations
                .iter()
                .all(|unit| !unit.identifier().is_empty()),
            "no declaration may carry an empty name: {declarations:#?}"
        );
        assert!(
            declarations
                .iter()
                .all(|unit| !matches!(unit.identifier(), "final" | "public" | "virtual")),
            "macros and head specifiers must not become declarations: {declarations:#?}"
        );
    }

    #[test]
    fn function_like_export_class_survives_a_preceding_malformed_body() {
        let source = r#"
namespace api {
class PROJECT_PUBLIC_API(2, 0) Exception : public std::exception {
   public:
      /** Return a descriptive string. */
      const char* what() const noexcept override { return m_msg.c_str(); }

      /** Return the type of error. */
      virtual ErrorType error_type() const noexcept { return ErrorType::Unknown; }

      /** Return an associated error code. */
      virtual int error_code() const noexcept { return 0; }

      /** Avoid throwing the base directly. */
      explicit Exception(std::string_view msg);

      /** Avoid throwing the base directly. */
      Exception(const char* prefix, std::string_view msg);

      /** Avoid throwing the base directly. */
      Exception(std::string_view msg, const std::exception& e);

   private:
      std::string m_msg;
};

class PROJECT_PUBLIC_API(2, 0) Invalid_Argument : public Exception {
   public:
      explicit Invalid_Argument(std::string_view msg);

      explicit Invalid_Argument(std::string_view msg, std::string_view where);

      Invalid_Argument(std::string_view msg, const std::exception& e);

      ErrorType error_type() const noexcept override { return ErrorType::InvalidArgument; }
};
} // namespace api
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("set C++ grammar");
        let tree = parser.parse(source, None).expect("parse fixture");
        let mut stack = vec![tree.root_node()];
        let mut saw_embedded_shape = false;
        while let Some(node) = stack.pop() {
            saw_embedded_shape |= recover_embedded_function_like_export_classes(node, source)
                .iter()
                .any(|recovered| recovered.name == "Invalid_Argument");
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        assert!(
            saw_embedded_shape,
            "fixture must retain the embedded error geometry: {}",
            tree.root_node().to_sexp()
        );

        let parsed = parse_cpp_file(
            &ProjectFile::new(std::env::temp_dir(), "embedded-function-like-export.hpp"),
            source,
            &tree,
        );
        let declarations = parsed.declarations();
        let exception = declarations
            .iter()
            .find(|unit| unit.is_class() && unit.fq_name() == "api.Exception")
            .expect("qualified-base export class");
        let invalid = declarations
            .iter()
            .find(|unit| unit.is_class() && unit.fq_name() == "api.Invalid_Argument")
            .expect("class embedded in the preceding malformed body");

        assert_eq!(
            parsed.raw_supertypes.get(exception),
            Some(&vec!["std::exception".to_string()])
        );
        assert_eq!(
            parsed.raw_supertypes.get(invalid),
            Some(&vec!["Exception".to_string()])
        );
        assert!(
            parsed.materialization_records.iter().any(|record| matches!(
                record,
                MaterializationRecord::RecoveredDeclaration { unit, .. }
                    if unit == invalid
            )),
            "the embedded class must retain recovery provenance: {:#?}",
            parsed.materialization_records
        );
    }

    #[test]
    fn function_like_export_class_recovers_a_merged_inline_constructor_shape() {
        let source = r#"
public:
   explicit Lookup_Error(std::string_view err) : Exception(err) {}

   Lookup_Error(std::string_view type, std::string_view algo, std::string_view provider = "");
"#;
        let tree = cpp_reparse_fragmented_class_body(source, 0, source.len())
            .expect("reparse merged constructor body");
        let (range, body) =
            cpp_reparsed_merged_inline_constructor(tree.root_node(), "Lookup_Error", source)
                .unwrap_or_else(|| {
                    panic!(
                        "the merged constructor must retain its structured declarator/body: {}",
                        tree.root_node().to_sexp()
                    )
                });
        assert_eq!(
            source.get(range).expect("constructor range"),
            "Lookup_Error(std::string_view err) : Exception(err) {}"
        );
        assert_eq!(node_text(body, source), "{}");
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
        let (_, outer_name, outer_fragment) = fragmented_plain_class_body(outer, source)
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
        let (_, action_name, action_fragment) = fragmented_plain_class_body(action_prefix, source)
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
        let source = r#"namespace absl {
ABSL_NAMESPACE_BEGIN namespace container_internal {

class raw_hash_set : public Base {
 public:
  using value_type = int;

  template <class U,
            REQUIRES("U must be convertible to int", std::is_convertible<U, int>)>
  void insert(U value) { (void)value; }

  struct InsertSlot {
    raw_hash_set& s;
  };
};

}
ABSL_NAMESPACE_END
}"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        let outer_namespace = root
            .named_children(&mut root.walk())
            .find(|child| child.kind() == "namespace_definition")
            .expect("outer absl namespace");
        let declaration_list = outer_namespace
            .child_by_field_name("body")
            .expect("outer namespace body");
        let sentinel_function = declaration_list
            .named_children(&mut declaration_list.walk())
            .find(|child| child.kind() == "function_definition")
            .expect("malformed namespace sentinel function");
        let ancestry = ParentIndex::new(root);
        let sentinel = cpp_nested_namespace_sentinel(sentinel_function, source, &ancestry)
            .expect("structured nested namespace sentinel");
        let fragmented =
            cpp_sentinel_fragmented_class_tail(sentinel.function, sentinel.body, source, &ancestry)
                .expect("fragmented raw_hash_set class");
        assert_eq!(fragmented.class_node.kind(), "ERROR");
        assert_eq!(fragmented.name, "raw_hash_set");
        assert_eq!(fragmented.raw_supertypes, Some(vec!["Base".to_string()]));

        let outer_scope =
            cpp_sentinel_recovered_namespace_components(sentinel.function, &[], source);
        let mut outer_siblings = Vec::new();
        push_cpp_sentinel_sibling_classes(
            &mut outer_siblings,
            declaration_list,
            sentinel.function,
            &outer_scope,
            source,
            &ancestry,
        );
        let [outer_shadow] = outer_siblings.as_slice() else {
            panic!("expected exactly one apparent outer sibling: {outer_siblings:#?}");
        };
        assert_eq!(outer_shadow.namespace_scope_components, vec!["absl"]);
        assert_eq!(outer_shadow.scope_components, vec!["absl", "InsertSlot"]);

        let field = "    raw_hash_set& s;";
        let start = source.find(field).expect("InsertSlot field") + 4;
        let node = root
            .descendant_for_byte_range(start, start + "raw_hash_set".len())
            .expect("raw_hash_set type node");
        let recovered = cpp_sentinel_recovered_classes(root, source);
        let [deep_class] = recovered.as_slice() else {
            panic!("outer shadow must be removed in favor of one deep class: {recovered:#?}");
        };
        assert_eq!(
            deep_class.namespace_scope_components,
            vec!["absl", "container_internal"]
        );
        assert_eq!(
            deep_class.scope_components,
            vec!["absl", "container_internal", "raw_hash_set"]
        );
        assert!(
            deep_class.class_range.start_byte <= outer_shadow.class_range.start_byte
                && deep_class.class_range.end_byte >= outer_shadow.class_range.end_byte
        );

        assert_eq!(
            cpp_sentinel_recovered_scope_for_node(node, source, &recovered),
            Some(vec![
                "absl".to_string(),
                "container_internal".to_string(),
                "raw_hash_set".to_string(),
                "InsertSlot".to_string(),
            ])
        );

        let file = ProjectFile::new(std::env::temp_dir(), "raw-hash-set-sentinel.h");
        let parsed = parse_cpp_file(&file, source, &tree);
        let raw_hash_set = parsed
            .declarations()
            .iter()
            .find(|unit| unit.is_class() && unit.short_name() == "raw_hash_set")
            .expect("recovered raw_hash_set class");
        assert_eq!(
            raw_hash_set.fq_name(),
            "absl::container_internal.raw_hash_set",
            "the recovered declaration must publish under the deeper sentinel namespace"
        );
        assert_eq!(
            parsed.raw_supertypes.get(raw_hash_set),
            Some(&vec!["Base".to_string()]),
            "the structured base clause on the fragmented ERROR prefix must survive publication"
        );
        assert!(
            parsed.materialization_records.iter().any(|record| matches!(
                record,
                MaterializationRecord::RecoveredDeclaration { recovery, unit }
                    if unit == raw_hash_set && *recovery == deep_class.class_range
            )),
            "the reconstructed class must publish recovered-declaration provenance: {:#?}",
            parsed.materialization_records
        );
    }

    /// Issue #2358: recording an aggregate definition must not walk the whole
    /// file.
    ///
    /// `visit_named_class_like_shape` calls `replace_code_unit` for every
    /// class-like shape that has a body, so the removal step runs once per
    /// aggregate. It used to `retain` over `top_level_declarations` and over
    /// *every* child list in the file on each of those calls, comparing whole
    /// `CodeUnit`s (which compare their `ProjectFile` first). A generated
    /// kernel-type header is nothing but aggregates -- pwru's 2.5MB
    /// `vmlinux-x86.h` yields 75,899 declarations -- so the file paid that scan
    /// tens of thousands of times over and the C forward differential never
    /// finished.
    ///
    /// A definition the file has not already declared removes nothing, so the
    /// honest cost is zero regardless of how many other aggregates surround it.
    /// Two sizes an order of magnitude apart pin that the count is not merely
    /// small but independent of the file.
    ///
    /// The declaration walk answers every ancestor question from a
    /// [`ParentIndex`] instead of asking tree-sitter, which re-descends from
    /// the root for each one (#2361). Substituting the index is only safe
    /// because it answers the identical question, so pin that on the shapes
    /// this file's recovery paths care about: anonymous and named aggregates,
    /// nested namespaces, templates, macro-displaced declarations and the
    /// `ERROR` regions a sentinel macro produces. Anonymous nodes are compared
    /// too -- `Node::parent` walks the visible tree, not the named one.
    #[test]
    fn the_parent_index_answers_what_tree_sitter_answers() {
        const SHAPES: [&str; 5] = [
            "namespace outer { namespace inner { struct Tag { int field; }; } }",
            "namespace { static int hidden(); }\nstruct { int anonymous_member; } value;",
            "template <typename T>\nclass PROJECT_API Wrapper : public Base<T> {\n  T get() const;\n};",
            "#define BEGIN_NS namespace project {\nBEGIN_NS\nclass Widget { void run(); };\n}\n",
            "class API Broken : public First, public Second {\n  void member();\n",
        ];
        for source in SHAPES {
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_cpp::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(source, None).unwrap();
            let root = tree.root_node();
            let ancestry = ParentIndex::new(root);
            let mut nodes = 0usize;
            let mut stack = vec![root];
            while let Some(node) = stack.pop() {
                nodes += 1;
                assert_eq!(
                    node.parent().map(|parent| parent.id()),
                    ancestry.parent(node).map(|parent| parent.id()),
                    "the index disagreed with tree-sitter about the parent of {node:?} in {source:?}"
                );
                let mut cursor = node.walk();
                stack.extend(node.children(&mut cursor));
            }
            assert!(nodes > 1, "{source:?} produced no tree to compare");
        }
    }

    /// Issue #2361: the callable metadata helpers must ask the per-tree parent
    /// index for every ancestor edge. Asking tree-sitter directly makes each
    /// edge re-descend from the root, turning declaration extraction on a
    /// deeply nested generated header from quadratic output work into a cubic
    /// tree walk. Exact query counts pin the route without a machine-dependent
    /// wall-clock ceiling.
    #[test]
    fn deeply_nested_callable_ancestor_questions_use_the_parent_index() {
        const DEPTH: usize = 64;
        let mut source = String::new();
        for level in 0..DEPTH {
            writeln!(source, "namespace n{level} {{").unwrap();
        }
        source.push_str("int deepest(int value);\n");
        for _ in 0..DEPTH {
            source.push_str("}\n");
        }

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&source, None).unwrap();
        let root = tree.root_node();
        let ancestry = ParentIndex::new(root);
        let mut function_declarator = None;
        walk_named_tree_preorder(root, true, |node| {
            if node.kind() == "function_declarator" {
                function_declarator = Some(node);
                WalkControl::Break
            } else {
                WalkControl::Continue
            }
        });
        let function_declarator = function_declarator.expect("deepest function declarator");
        let ancestor_count =
            std::iter::successors(function_declarator.parent(), |node| node.parent()).count();

        ancestry.reset_parent_query_count_for_test();
        let lexical_scope = cpp_callable_lexical_scope(function_declarator, &source, &ancestry);
        assert_eq!(DEPTH, lexical_scope.len());
        assert_eq!(
            ancestor_count + 1,
            ancestry.parent_query_count_for_test(),
            "lexical-scope ancestry bypassed the parent index"
        );

        ancestry.reset_parent_query_count_for_test();
        assert_eq!(
            DispatchExtensibility::Closed,
            cpp_callable_dispatch_extensibility(function_declarator, &ancestry)
        );
        assert_eq!(
            ancestor_count,
            ancestry.parent_query_count_for_test(),
            "dispatch ancestry bypassed the parent index"
        );

        ancestry.reset_parent_query_count_for_test();
        assert_eq!(
            CallableLinkage::External,
            cpp_callable_linkage(function_declarator, &source, &ancestry)
        );
        assert_eq!(
            ancestor_count + 1,
            ancestry.parent_query_count_for_test(),
            "linkage ancestry bypassed the parent index"
        );

        ancestry.reset_parent_query_count_for_test();
        assert!(!cpp_callable_is_structural_constructor(
            function_declarator,
            &source,
            &ancestry
        ));
        assert_eq!(
            ancestor_count + 1,
            ancestry.parent_query_count_for_test(),
            "constructor ancestry bypassed the parent index"
        );
    }

    /// Forward declarations followed by definitions are compacted as one
    /// batch, without rescanning the shared namespace/top-level lists for each
    /// tag. Definitions are intentionally visited in reverse order so the
    /// assertion also pins eager remove-and-reappend ordering.
    #[test]
    fn forward_declared_aggregates_are_replaced_without_sibling_scans() {
        for aggregates in [64usize, 512] {
            let mut source =
                String::from("typedef unsigned long long u64;\nnamespace generated {\n");
            for index in 0..aggregates {
                writeln!(source, "struct tag{index};").unwrap();
            }
            for index in (0..aggregates).rev() {
                writeln!(
                    source,
                    "struct tag{index} {{\n\tu64 first;\n\tint second;\n}};"
                )
                .unwrap();
            }
            source.push_str("}\n");

            start_code_unit_removal_scan_probe();
            let parsed = parse_cpp_declarations(&source, "vmlinux.h");
            let scanned = finish_code_unit_removal_scan_probe();

            let expected_names: Vec<String> = (0..aggregates)
                .rev()
                .map(|index| format!("tag{index}"))
                .collect();
            let top_level_names: Vec<String> = parsed
                .top_level_declarations
                .iter()
                .filter(|unit| unit.is_class() && unit.short_name().starts_with("tag"))
                .map(|unit| unit.short_name().to_string())
                .collect();
            let namespace = parsed
                .declarations()
                .iter()
                .find(|unit| {
                    unit.kind() == CodeUnitType::Module && unit.short_name() == "generated"
                })
                .expect("generated namespace should be declared");
            let child_names: Vec<String> = parsed.children[namespace]
                .iter()
                .filter(|unit| unit.is_class() && unit.short_name().starts_with("tag"))
                .map(|unit| unit.short_name().to_string())
                .collect();
            assert_eq!(
                aggregates,
                parsed
                    .declarations()
                    .iter()
                    .filter(|unit| unit.is_class() && unit.short_name().starts_with("tag"))
                    .count(),
                "every aggregate must still be declared at {aggregates} aggregates"
            );
            assert_eq!(expected_names, top_level_names);
            assert_eq!(expected_names, child_names);
            assert_eq!(
                0, scanned,
                "replacing {aggregates} forward declarations must compact their shared lists once"
            );
        }
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
            DISTINCT_PER_KIND + 1,
            parsed
                .declarations()
                .iter()
                .filter(|unit| {
                    unit.kind() == CodeUnitType::Macro && unit.short_name().starts_with("MACRO_")
                })
                .count(),
            "distinct macro redefinitions must remain available to temporal lookup"
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

    /// Every identity signature emitted for `fq_name`, deduplicated, sorted.
    fn identity_signatures(parsed: &ParsedFile, fq_name: &str) -> Vec<String> {
        let mut signatures = parsed
            .declarations()
            .iter()
            .filter(|unit| unit.is_function() && unit.fq_name() == fq_name)
            .filter_map(|unit| unit.signature().map(str::to_string))
            .collect::<Vec<_>>();
        signatures.sort();
        signatures.dedup();
        signatures
    }

    #[test]
    fn callable_parameter_types_come_from_the_ast_parameter_list() {
        let source = r#"
template <typename T, ENABLE_BYTES(T)>
Vec256<T> DupOdd(Vec256<T> value) { return value; }

struct Visitor {
  void fail(this auto const& self) {}
};
"#;
        let parsed = parse_cpp_declarations(source, "structured-parameter-types.cpp");
        let dup_odd = parsed
            .declarations()
            .iter()
            .find(|unit| unit.is_function() && unit.fq_name() == "DupOdd")
            .expect("DupOdd declaration");
        assert_eq!(
            dup_odd.signature(),
            Some("<typename T, ENABLE_BYTES(T)>(Vec256<T>)")
        );
        assert_eq!(
            parsed
                .signature_metadata
                .get(dup_odd)
                .and_then(|metadata| metadata.first())
                .and_then(SignatureMetadata::callable_parameter_types),
            Some(["Vec256<T>".to_string()].as_slice())
        );

        let fail = parsed
            .declarations()
            .iter()
            .find(|unit| unit.is_function() && unit.fq_name() == "Visitor.fail")
            .expect("explicit-object member");
        assert_eq!(fail.signature(), Some("(const this auto &)"));
        let metadata = parsed
            .signature_metadata
            .get(fail)
            .and_then(|metadata| metadata.first())
            .expect("explicit-object signature metadata");
        assert_eq!(metadata.callable_parameter_types(), Some([].as_slice()));
        assert!(
            metadata
                .callable_arity()
                .is_some_and(|arity| arity.accepts(0))
        );
    }

    #[test]
    fn trailing_qualifiers_survive_parameter_list_whitespace() {
        // #1827: the trailing `const`/`noexcept`/ref-qualifier belongs to the
        // declarator's structure, so an out-of-line definition that spells its
        // parameter list with different whitespace than the declaration must
        // still carry it.
        let source = r#"
struct Widget {
  bool multiline(int settings, int supprs) const;
  bool doublespace(int settings, int supprs) const;
  bool noexcept_multiline(int settings, int supprs) noexcept;
  bool ref_multiline(int settings, int supprs) &&;
};
bool
Widget::multiline (int settings,
                   int supprs) const
{ return settings + supprs > 0; }
bool Widget::doublespace(int settings,  int supprs) const { return true; }
bool Widget::noexcept_multiline(int settings,
                                int supprs) noexcept { return true; }
bool Widget::ref_multiline(int settings,
                           int supprs) && { return true; }
"#;
        let parsed = parse_cpp_declarations(source, "trailing-qualifiers.cpp");
        assert_eq!(
            vec!["(int, int) const".to_string()],
            identity_signatures(&parsed, "Widget.multiline")
        );
        assert_eq!(
            vec!["(int, int) const".to_string()],
            identity_signatures(&parsed, "Widget.doublespace")
        );
        assert_eq!(
            vec!["(int, int) noexcept".to_string()],
            identity_signatures(&parsed, "Widget.noexcept_multiline")
        );
        assert_eq!(
            vec!["(int, int) &&".to_string()],
            identity_signatures(&parsed, "Widget.ref_multiline")
        );
    }

    #[test]
    fn macro_fragmented_plain_class_keeps_following_member_signature() {
        let source = r#"
struct CString {};
class CMessage {
public:
  CString GetParams(unsigned int index, unsigned int length = -1) const
      ZNC_MSG_DEPRECATED("Use GetParamsColon() instead") {
    return GetParamsColon(index, length);
  }
  CString GetParamsColon(unsigned int index, unsigned int length = -1) const;
};
CString CMessage::GetParamsColon(unsigned int index, unsigned int length) const {
  return {};
}
"#;
        let parsed = parse_cpp_declarations(source, "macro-fragmented-signature.cpp");
        assert_eq!(
            vec!["(unsigned int, unsigned int) const".to_string()],
            identity_signatures(&parsed, "CMessage.GetParamsColon")
        );
    }

    #[test]
    fn namespaced_macro_fragment_keeps_prefix_members_and_following_classes() {
        let source = r#"
#pragma once
#define DEMO_DEPRECATED(message)
namespace demo {
struct Base {
    static int aligned(int value) { return value; }
    int legacy(int value) const
        DEMO_DEPRECATED("use replacement()") { return value; }
    int replacement() const;
    void run(int value);
};
struct OtherBase {
    void run(int value);
    static int aligned(int value) { return value; }
};
struct Derived : Base {};
struct Override : Base {
    void run(int value);
    static int aligned(int value) { return value; }
};
struct RecoveredOverride : Base {
    int legacy(int value) const
        DEMO_DEPRECATED("use replacement()") { return value; }
    void run(int value);
};
struct Hidden : Base {
    void run(int first, int second);
    static int aligned(int first, int second) { return first + second; }
};
struct Ambiguous : Base, OtherBase {};
}
struct Global {};
"#;
        let parsed = parse_cpp_declarations(source, "namespaced-macro-fragment.cpp");
        let declarations = parsed.declarations();
        let fq_names = declarations
            .iter()
            .map(|unit| unit.fq_name())
            .collect::<std::collections::BTreeSet<_>>();

        for expected in [
            "demo.Base",
            "demo.Base.aligned",
            "demo.Base.legacy",
            "demo.Base.replacement",
            "demo.Base.run",
            "demo.Derived",
            "demo.OtherBase",
            "demo.Override",
            "demo.RecoveredOverride",
            "demo.Hidden",
            "demo.Ambiguous",
            "Global",
        ] {
            assert!(
                fq_names.contains(expected),
                "missing {expected} from namespaced macro fragment: {declarations:#?}"
            );
        }
        assert!(
            !fq_names.contains("Derived"),
            "following class escaped its namespace: {declarations:#?}"
        );
        assert!(
            !fq_names.contains("demo.Global"),
            "global class crossed the recovered namespace boundary: {declarations:#?}"
        );
    }

    #[test]
    fn trailing_qualifiers_still_separate_genuine_overloads() {
        // The qualifier must keep distinguishing the real C++ overload sets it
        // exists for: a const and a non-const accessor, and a `&`/`&&` pair.
        let source = r#"
struct Widget {
  int* slot(int index);
  const int* slot(int index) const;
  int log(int severity) &;
  int log(int severity) &&;
};
"#;
        let parsed = parse_cpp_declarations(source, "qualifier-overloads.cpp");
        assert_eq!(
            vec!["(int)".to_string(), "(int) const".to_string()],
            identity_signatures(&parsed, "Widget.slot")
        );
        assert_eq!(
            vec!["(int) &".to_string(), "(int) &&".to_string()],
            identity_signatures(&parsed, "Widget.log")
        );
    }

    #[test]
    fn virtual_specifier_is_not_part_of_the_identity_signature() {
        // `override` never appears on the out-of-line definition, and C++ does
        // not make it part of the signature, so it must not split the identity.
        let source = r#"
struct Base {
  virtual void run(int value) const;
};
struct Widget : Base {
  void run(int value) const override;
};
void Widget::run(int value) const {}
"#;
        let parsed = parse_cpp_declarations(source, "virtual-specifier.cpp");
        assert_eq!(
            vec!["(int) const".to_string()],
            identity_signatures(&parsed, "Widget.run")
        );
    }

    #[test]
    fn top_level_parameter_cv_qualifiers_do_not_split_identity() {
        // [dcl.fct]/5: top-level cv-qualifiers on a parameter are not part of
        // the function type, so a declaration that spells `const int` and a
        // definition that spells `int` are one entity.
        let source = r#"
struct Widget {
  bool value_params(const int settings, const int supprs);
  void pointee_const(const int* p);
  void pointer_const(int* const p);
  void both_const(const int* const p);
  void reference_const(const int& p);
  void array_const(const int values[4]);
};
bool Widget::value_params(int settings, int supprs) { return true; }
void Widget::pointer_const(int* p) {}
void Widget::both_const(const int* p) {}
"#;
        let parsed = parse_cpp_declarations(source, "top-level-const.cpp");
        assert_eq!(
            vec!["(int, int)".to_string()],
            identity_signatures(&parsed, "Widget.value_params")
        );
        assert_eq!(
            vec!["(int *)".to_string()],
            identity_signatures(&parsed, "Widget.pointer_const")
        );
        assert_eq!(
            vec!["(const int *)".to_string()],
            identity_signatures(&parsed, "Widget.both_const")
        );
        // The const that is not top-level still distinguishes the type.
        assert_eq!(
            vec!["(const int *)".to_string()],
            identity_signatures(&parsed, "Widget.pointee_const")
        );
        assert_eq!(
            vec!["(const int &)".to_string()],
            identity_signatures(&parsed, "Widget.reference_const")
        );
        assert_eq!(
            vec!["(const int [4])".to_string()],
            identity_signatures(&parsed, "Widget.array_const")
        );
    }

    #[test]
    fn top_level_parameter_const_still_separates_pointee_overloads() {
        let source = r#"
struct Widget {
  void take(const int* p);
  void take(int* p);
};
"#;
        let parsed = parse_cpp_declarations(source, "pointee-overloads.cpp");
        assert_eq!(
            vec!["(const int *)".to_string(), "(int *)".to_string()],
            identity_signatures(&parsed, "Widget.take")
        );
    }

    fn comparable_shapes(source: &str, callable_name: &str) -> Vec<CppComparableSlot> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let start = source.find(callable_name).expect("callable declaration");
        let declarator =
            cpp_function_declarator_at(tree.root_node(), start).expect("function declarator");
        cpp_comparable_parameter_shapes(declarator, source, &ParentIndex::unindexed())
    }

    fn sole_comparable_shape(source: &str, callable_name: &str) -> CppComparableParameter {
        let mut shapes = comparable_shapes(source, callable_name);
        assert_eq!(1, shapes.len(), "{shapes:?}");
        match shapes.remove(0) {
            CppComparableSlot::Shape(shape) => shape,
            other => panic!("expected a comparable shape, got {other:?}"),
        }
    }

    fn comparable_named_leaf(shape: &CppComparableParameter) -> &CppComparableNode {
        let mut current = shape.root();
        loop {
            match shape.node(current) {
                CppComparableNode::Named { .. } => return shape.node(current),
                CppComparableNode::Pointer { inner, .. }
                | CppComparableNode::Reference { inner }
                | CppComparableNode::Array { inner } => current = *inner,
                CppComparableNode::Generic { base, .. } => current = *base,
            }
        }
    }

    #[test]
    fn comparable_shape_keeps_pointee_const() {
        assert_ne!(
            sole_comparable_shape("void f(const char* p);", "f("),
            sole_comparable_shape("void f(char* p);", "f(")
        );
    }

    #[test]
    fn comparable_shape_keeps_inner_pointer_const() {
        assert_ne!(
            sole_comparable_shape("void f(int** p);", "f("),
            sole_comparable_shape("void f(int* const* p);", "f(")
        );
    }

    #[test]
    fn comparable_shape_drops_top_level_pointer_const() {
        assert_eq!(
            sole_comparable_shape("void f(int* const p);", "f("),
            sole_comparable_shape("void f(int* p);", "f(")
        );
    }

    #[test]
    fn comparable_shape_drops_top_level_base_const() {
        assert_eq!(
            sole_comparable_shape("void f(const int p);", "f("),
            sole_comparable_shape("void f(int p);", "f(")
        );
    }

    #[test]
    fn comparable_shape_decays_top_level_array_to_pointer() {
        assert_eq!(
            sole_comparable_shape("void f(int a[3]);", "f("),
            sole_comparable_shape("void f(int* a);", "f(")
        );
        assert_eq!(
            sole_comparable_shape("void f(int* a[3]);", "f("),
            sole_comparable_shape("void f(int** a);", "f(")
        );
    }

    #[test]
    fn comparable_shape_keeps_array_behind_pointer() {
        assert_ne!(
            sole_comparable_shape("struct S { void f(int (*a)[3]); };", "f("),
            sole_comparable_shape("struct S { void f(int** a); };", "f(")
        );
    }

    #[test]
    fn comparable_shape_records_written_name_and_lexical_scope() {
        let declared =
            sole_comparable_shape("namespace ns { struct S { void g(Msg* m); }; }", "g(");
        let defined = sole_comparable_shape("void ns::S::g(ns::Msg* m) {}", "g(");
        let CppComparableNode::Named { name, .. } = comparable_named_leaf(&declared) else {
            panic!("named leaf");
        };
        assert_eq!(["Msg".to_string()].as_slice(), name.path());
        assert_eq!(
            ["ns".to_string(), "S".to_string()].as_slice(),
            name.lexical_scope()
        );
        let CppComparableNode::Named { name, .. } = comparable_named_leaf(&defined) else {
            panic!("named leaf");
        };
        assert_eq!(
            ["ns".to_string(), "Msg".to_string()].as_slice(),
            name.path()
        );
        assert!(name.lexical_scope().is_empty());
        assert_ne!(declared, defined);
    }

    #[test]
    fn comparable_shape_marks_sized_primitive_leaf() {
        let shape = sole_comparable_shape("void f(unsigned char c);", "f(");
        let CppComparableNode::Named {
            name, primitive, ..
        } = comparable_named_leaf(&shape)
        else {
            panic!("named leaf");
        };
        assert!(primitive);
        assert_eq!(["unsigned char".to_string()].as_slice(), name.path());
        assert_ne!(shape, sole_comparable_shape("void f(char c);", "f("));
    }

    #[test]
    fn comparable_shape_reports_function_pointer_parameter_as_unstructured() {
        assert_eq!(
            vec![CppComparableSlot::Unstructured],
            comparable_shapes("void f(void (*cb)(int));", "f(")
        );
    }

    #[test]
    fn comparable_shape_reports_ellipsis_slot() {
        let shapes = comparable_shapes("void f(int a, ...);", "f(");
        assert_eq!(2, shapes.len(), "{shapes:?}");
        assert_eq!(CppComparableSlot::Ellipsis, shapes[1]);
    }

    #[test]
    fn comparable_shape_keeps_template_argument_const() {
        assert_ne!(
            sole_comparable_shape("void f(std::vector<const int*> v);", "f("),
            sole_comparable_shape("void f(std::vector<int*> v);", "f(")
        );
    }

    /// The issue #1970 fixture: C has no nested tag scope, so `inner` is a
    /// file-scope tag that a later `struct inner *` at file scope may name.
    #[test]
    fn c_file_mints_aggregate_member_tag_at_file_scope() {
        let source = "struct outer {\n  struct inner { int value; } item;\n};\n";
        let parsed = parse_cpp_declarations(source, "x.c");
        let declarations = parsed.declarations();

        assert!(
            declarations
                .iter()
                .any(|unit| unit.is_class() && unit.fq_name() == "inner"),
            "expected a file-scope inner tag, got {declarations:?}"
        );
        assert!(
            declarations
                .iter()
                .all(|unit| unit.fq_name() != "outer$inner"),
            "expected no nested identity, got {declarations:?}"
        );
        assert!(
            declarations
                .iter()
                .any(|unit| unit.is_class() && unit.fq_name() == "outer")
        );
        // Members still belong to their own aggregate.
        assert!(
            declarations
                .iter()
                .any(|unit| unit.fq_name() == "inner.value")
        );
        assert!(
            declarations
                .iter()
                .any(|unit| unit.fq_name() == "outer.item")
        );

        let outer = declarations
            .iter()
            .find(|unit| unit.is_class() && unit.fq_name() == "outer")
            .expect("outer");
        assert!(
            parsed
                .children
                .get(outer)
                .into_iter()
                .flatten()
                .all(|child| child.fq_name() != "inner"),
            "the tag must not hang off the aggregate it is written inside: {:?}",
            parsed.children
        );
    }

    /// A header carries no compilation language of its own, and a `.cpp`
    /// translation unit really does declare a nested class. Both keep exactly
    /// the C++ extraction they had before the C dialect existed.
    #[test]
    fn header_and_cpp_files_keep_nested_tag_identity() {
        let source = "struct outer {\n  struct inner { int value; } item;\n};\n";
        for name in ["x.h", "x.cpp", "x.cc", "x.cxx"] {
            let parsed = parse_cpp_declarations(source, name);
            let declarations = parsed.declarations();
            assert!(
                declarations
                    .iter()
                    .any(|unit| unit.is_class() && unit.fq_name() == "outer$inner"),
                "{name} must keep the nested identity, got {declarations:?}"
            );
            assert!(
                declarations.iter().all(|unit| unit.fq_name() != "inner"),
                "{name} must not mint a file-scope tag, got {declarations:?}"
            );
            assert!(
                declarations
                    .iter()
                    .any(|unit| unit.fq_name() == "outer$inner.value")
            );
        }
    }

    /// Uppercase `.C` conventionally means C++, so it keeps C++ scoping.
    #[test]
    fn uppercase_c_extension_keeps_cpp_tag_scope() {
        let source = "struct outer {\n  struct inner { int value; } item;\n};\n";
        let parsed = parse_cpp_declarations(source, "x.C");
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| unit.is_class() && unit.fq_name() == "outer$inner")
        );
    }

    /// There is no such thing as a partially nested tag in C: every level of a
    /// nested aggregate chain lands at the same enclosing scope.
    #[test]
    fn c_file_mints_every_nesting_level_at_file_scope() {
        let source = "struct a { struct b { struct c { int v; } cc; } bb; };\n";
        let parsed = parse_cpp_declarations(source, "z.c");
        let declarations = parsed.declarations();

        for tag in ["a", "b", "c"] {
            assert!(
                declarations
                    .iter()
                    .any(|unit| unit.is_class() && unit.fq_name() == tag),
                "expected a file-scope {tag}, got {declarations:?}"
            );
        }
        assert!(
            declarations
                .iter()
                .all(|unit| !unit.fq_name().contains('$')),
            "no level may keep a nested identity, got {declarations:?}"
        );
        // Each member still belongs to the aggregate that declares it.
        assert!(declarations.iter().any(|unit| unit.fq_name() == "a.bb"));
        assert!(declarations.iter().any(|unit| unit.fq_name() == "b.cc"));
        assert!(declarations.iter().any(|unit| unit.fq_name() == "c.v"));
    }

    /// An enum tag is a tag; its enumerators stay members of the enum, which is
    /// what makes them ordinary identifiers at the enum's own (file) scope.
    #[test]
    fn c_file_mints_member_list_enum_at_file_scope_with_its_enumerators() {
        let source = "struct outer { enum color { RED, GREEN } c; };\n";
        let parsed = parse_cpp_declarations(source, "e.c");
        let declarations = parsed.declarations();

        let color = declarations
            .iter()
            .find(|unit| unit.is_class() && unit.fq_name() == "color")
            .unwrap_or_else(|| panic!("expected a file-scope color enum, got {declarations:?}"));
        assert!(
            declarations
                .iter()
                .all(|unit| unit.fq_name() != "outer$color")
        );
        for enumerator in ["color.RED", "color.GREEN"] {
            assert!(
                declarations.iter().any(|unit| unit.fq_name() == enumerator),
                "expected {enumerator}, got {declarations:?}"
            );
        }
        let children = parsed
            .children
            .get(color)
            .unwrap_or_else(|| panic!("expected child edges for {color:?}"));
        assert!(
            ["color.RED", "color.GREEN"]
                .iter()
                .all(|name| children.iter().any(|child| child.fq_name() == *name)),
            "enumerators must hang off their enum: {children:?}"
        );
    }

    #[test]
    fn c_file_mints_member_list_union_at_file_scope() {
        let source = "struct outer { union inner { int a; float b; } item; };\n";
        let parsed = parse_cpp_declarations(source, "u.c");
        let declarations = parsed.declarations();
        assert!(
            declarations
                .iter()
                .any(|unit| unit.is_class() && unit.fq_name() == "inner"),
            "expected a file-scope inner union, got {declarations:?}"
        );
        assert!(
            declarations
                .iter()
                .all(|unit| unit.fq_name() != "outer$inner")
        );
        assert!(declarations.iter().any(|unit| unit.fq_name() == "inner.a"));
        assert!(declarations.iter().any(|unit| unit.fq_name() == "inner.b"));
    }

    /// A tag declared in a namespace member list is not a file-scope tag: the
    /// nearest enclosing non-aggregate scope is the namespace.
    #[test]
    fn c_file_member_list_tag_lands_in_the_enclosing_namespace() {
        let source = "namespace ns { struct outer { struct inner { int v; } i; }; }\n";
        let parsed = parse_cpp_declarations(source, "n.c");
        let declarations = parsed.declarations();
        let inner = declarations
            .iter()
            .find(|unit| unit.is_class() && unit.fq_name() == "ns.inner")
            .unwrap_or_else(|| panic!("expected ns.inner, got {declarations:?}"));
        assert_eq!(inner.package_name(), "ns");
        assert!(
            declarations
                .iter()
                .all(|unit| unit.fq_name() != "ns.outer$inner")
        );
    }

    /// Pins today's treatment of a tag declared inside a function body: the
    /// declaration walk does not descend into statement bodies, so no unit is
    /// minted for it in either dialect. C block scope is out of scope for the
    /// dialect change, and this test proves the change did not disturb it.
    #[test]
    fn function_local_tags_are_unchanged_in_both_dialects() {
        let source =
            "void run(void) {\n  struct localtag { struct deeper { int v; } d; } item;\n}\n";
        for name in ["y.c", "y.cpp"] {
            let parsed = parse_cpp_declarations(source, name);
            let declarations = parsed.declarations();
            assert!(
                declarations
                    .iter()
                    .any(|unit| unit.is_function() && unit.fq_name() == "run"),
                "{name}: {declarations:?}"
            );
            for tag in ["localtag", "deeper", "localtag$deeper"] {
                assert!(
                    declarations.iter().all(|unit| unit.fq_name() != tag),
                    "{name} must not mint {tag}, got {declarations:?}"
                );
            }
        }
    }

    /// An anonymous aggregate declares no tag, so the C dialect has nothing to
    /// re-scope: the typedef name is identical in both dialects.
    #[test]
    fn anonymous_typedef_struct_is_identical_in_both_dialects() {
        let source = "typedef struct { int v; } T;\n";
        for name in ["t.c", "t.cpp"] {
            let parsed = parse_cpp_declarations(source, name);
            let declarations = parsed.declarations();
            assert!(
                declarations
                    .iter()
                    .any(|unit| unit.is_class() && unit.fq_name() == "T"),
                "{name}: {declarations:?}"
            );
        }
    }

    #[test]
    fn c_anonymous_aggregate_members_keep_promoted_and_named_receiver_shapes() {
        let source = "typedef struct { union { struct { struct socket_ops *ops; } sock; int other; }; } *PAL_HANDLE;\n";
        let parsed = parse_cpp_declarations(source, "socket.c");
        let declarations = parsed.declarations();
        assert_eq!(
            declarations
                .iter()
                .filter(|unit| unit.fq_name() == "PAL_HANDLE")
                .count(),
            1,
            "the typedef alias is the anonymous aggregate owner: {declarations:#?}"
        );
        for expected in [
            "PAL_HANDLE",
            "PAL_HANDLE.sock",
            "PAL_HANDLE$sock",
            "PAL_HANDLE$sock.ops",
        ] {
            assert!(
                declarations.iter().any(|unit| unit.fq_name() == expected),
                "expected {expected}, got {declarations:?}"
            );
        }
    }

    /// `class` is not C. Source that spells one in a `.c` file is not C code,
    /// so it keeps the C++ reading rather than acquiring a half-C identity.
    #[test]
    fn class_specifier_in_a_c_file_keeps_cpp_nesting() {
        let source = "class outer { class inner { int v; }; };\n";
        let c_parsed = parse_cpp_declarations(source, "k.c");
        let cpp_parsed = parse_cpp_declarations(source, "k.cpp");
        let c_declarations = c_parsed.declarations();
        let cpp_declarations = cpp_parsed.declarations();
        assert!(
            c_declarations
                .iter()
                .any(|unit| unit.is_class() && unit.fq_name() == "outer$inner"),
            "{c_declarations:?}"
        );
        assert_eq!(
            c_declarations
                .iter()
                .map(|unit| unit.fq_name())
                .collect::<std::collections::BTreeSet<_>>(),
            cpp_declarations
                .iter()
                .map(|unit| unit.fq_name())
                .collect::<std::collections::BTreeSet<_>>()
        );
    }

    /// Drive [`CppNamespaceForwardScan`] and the prefix scan it replaced over
    /// every (node, class-like name) pair a tree offers, and require the same
    /// answer from both.
    ///
    /// The release build has no `debug_assertions` agreement check, so this is
    /// what pins the two together there.  Both query orders are exercised:
    /// document order is what the walk does, and reverse order proves that a
    /// question about an earlier byte than one already answered is still
    /// filtered back to its own prefix rather than answered from the wider
    /// fold.
    ///
    /// Returns how many questions were answered with a namespace, so a fixture
    /// can assert it actually reached the path (#2754).
    fn namespace_forward_scan_agreement(source: &str) -> usize {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        let ancestry = ParentIndex::new(root);

        let mut nodes = Vec::new();
        let mut names = std::collections::BTreeSet::new();
        let mut cursor = root.walk();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if matches!(
                node.kind(),
                "class_specifier" | "struct_specifier" | "union_specifier"
            ) && let Some(name) = class_like_name(node, source, &ancestry)
            {
                names.insert(name);
            }
            nodes.push(node);
            stack.extend(node.named_children(&mut cursor));
        }
        nodes.sort_by_key(|node| (node.start_byte(), node.end_byte()));
        assert!(!names.is_empty(), "fixture declares no class-like name");

        let mut answered = 0usize;
        for reversed in [false, true] {
            let mut scan = CppNamespaceForwardScan::default();
            let ordered: Vec<_> = if reversed {
                nodes.iter().rev().copied().collect()
            } else {
                nodes.clone()
            };
            answered = 0;
            for node in ordered {
                for name in &names {
                    scan.advance_to(root, node.start_byte(), source, &ancestry);
                    let carried = scan.unique_earlier_forward(name, node);
                    assert_eq!(
                        carried,
                        unique_earlier_cpp_namespace_forward(node, name, source, &ancestry),
                        "carried-forward scan and prefix scan disagree about {name} at \
                         {} node starting at byte {} (reversed order: {reversed})",
                        node.kind(),
                        node.start_byte()
                    );
                    answered += usize::from(carried.is_some());
                }
            }
        }
        answered
    }

    /// A malformed namespace whose forward declarations are the only identity
    /// signal left for the class definitions tree-sitter pushed out to file
    /// scope.  Both recovered classes open the guard; only the first one is
    /// separated from the namespace by nothing but recovery trivia, so only the
    /// first one borrows.  The carried-forward scan has to reproduce both
    /// answers.
    const MALFORMED_NAMESPACE_WITH_TWO_RECOVERED_CLASSES: &str = r#"#define API
namespace ns {
class Widget;
class Gadget;
int x = ;
}
class API Widget {
public:
    void first();
};
class API Gadget {
public:
    void second();
};
"#;

    #[test]
    fn carried_forward_namespace_scan_answers_what_the_prefix_scan_answers() {
        assert!(
            namespace_forward_scan_agreement(MALFORMED_NAMESPACE_WITH_TWO_RECOVERED_CLASSES) > 0,
            "the fixture must actually reach the namespace-borrow path"
        );

        // Nothing here may be answered, and the two paths have to agree about
        // that too: a clean namespace is not an identity proof, two forwards of
        // one name are ambiguous rather than a guess, and a forward inside a
        // function body is not at namespace scope.
        for source in [
            "namespace clean {\nclass Widget;\n}\nclass API Widget {\npublic:\n    void method();\n};\n",
            r#"#define API
namespace ns {
class Widget;
class Widget;
int x = ;
}
class API Widget {
public:
    void method();
};
"#,
            r#"#define API
namespace ns {
void host() {
    class Widget;
}
int x = ;
}
class API Widget {
public:
    void method();
};
"#,
        ] {
            assert_eq!(
                namespace_forward_scan_agreement(source),
                0,
                "no borrow is justified here: {source}"
            );
        }
    }

    /// The fold is incremental, so a walk that asks about steadily later bytes
    /// must never re-fold a node an earlier question already folded, and must
    /// never skip one that lies between two questions.
    #[test]
    fn carried_forward_namespace_scan_folds_each_node_once() {
        let source = MALFORMED_NAMESPACE_WITH_TWO_RECOVERED_CLASSES;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        let ancestry = ParentIndex::new(root);

        let mut incremental = CppNamespaceForwardScan::default();
        for cutoff in 0..=source.len() {
            incremental.advance_to(root, cutoff, source, &ancestry);
        }
        let mut whole = CppNamespaceForwardScan::default();
        whole.advance_to(root, source.len(), source, &ancestry);

        let mut incremental_shape: Vec<_> = incremental
            .forwards
            .iter()
            .map(|(name, forwards)| {
                (
                    name.clone(),
                    forwards
                        .iter()
                        .map(|forward| (forward.start_byte, forward.package_name.clone()))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        let mut whole_shape: Vec<_> = whole
            .forwards
            .iter()
            .map(|(name, forwards)| {
                (
                    name.clone(),
                    forwards
                        .iter()
                        .map(|forward| (forward.start_byte, forward.package_name.clone()))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        incremental_shape.sort();
        whole_shape.sort();
        for (_, forwards) in &mut incremental_shape {
            forwards.sort();
        }
        for (_, forwards) in &mut whole_shape {
            forwards.sort();
        }

        assert!(!whole_shape.is_empty(), "fixture folds no forward");
        assert_eq!(
            incremental_shape, whole_shape,
            "one byte at a time must fold exactly what one whole pass folds"
        );
    }

    /// Drive the region reparse and the whitespace-padded reparse it replaced
    /// over the same region and require identical trees.
    ///
    /// The release build has no `debug_assertions` agreement check, so this is
    /// what pins the two together there. Each body is reparsed at its own
    /// offset and again after a long prefix, because the prefix is the whole
    /// difference between the two techniques: the padded parse lexes it as
    /// whitespace, the included-range parse never sees it, and the tree has to
    /// come out the same either way (#2788).
    fn fragmented_class_reparse_agreement(body: &str) {
        for prefix in [
            String::new(),
            "// leading comment\n".to_string(),
            // A body starts just after its class head's `{`, which is normally
            // mid-line: the padded parse then has spaces before the region on
            // the region's own line, and the included-range parse has nothing
            // at all before it.
            "class Widget : public Base { ".to_string(),
            "namespace filler {\n".to_string()
                + &"struct Filler { int member; };\n".repeat(200)
                + "}\n",
            "namespace filler {\n".to_string()
                + &"struct Filler { int member; };\n".repeat(200)
                + "}\nclass Widget : public Base { ",
        ] {
            let source = format!("{prefix}{body}");
            let start = prefix.len();
            let end = source.len();
            let region = cpp_reparse_fragmented_class_body(&source, start, end)
                .expect("the region reparse must produce a tree");
            let padded = cpp_reparse_padded_class_body(&source, start, end)
                .expect("the padded reparse must produce a tree");
            assert_eq!(
                cpp_tree_shape(&region),
                cpp_tree_shape(&padded),
                "region and padded reparse disagree at offset {start} of {end} bytes"
            );
            assert_eq!(
                region.root_node().start_byte(),
                start,
                "the reparsed region keeps its original offsets"
            );
        }
    }

    #[test]
    fn the_region_reparse_of_a_fragmented_class_body_is_the_padded_reparse() {
        // A conditional immediately after an access label: the shape the padded
        // technique was kept for, because the directive and its macro name
        // become an ERROR plus the following declaration's apparent type.
        fragmented_class_reparse_agreement(
            "public:\n#ifdef HAS_FEATURE\n   Widget(int value);\n#endif\n   void method();\n",
        );
        fragmented_class_reparse_agreement(
            "public:\n#if defined(A) || defined(B)\n   Widget();\n#else\n   Widget(int);\n#endif\n",
        );
        // The merged inline constructor and the nested fragmented bodies the
        // #938 recovery reads out of a reparse.
        fragmented_class_reparse_agreement(
            "public:\n   explicit Lookup_Error(std::string_view err) : Exception(err) {}\n\n                Lookup_Error(std::string_view type, std::string_view algo);\n",
        );
        fragmented_class_reparse_agreement(
            "public:\n   void first();\nclass Action {\npublic:\n   void second();\n",
        );
        // A body that is not member-shaped at all still has to reparse the same
        // way, because the admission gate reads the tree to reject it.
        fragmented_class_reparse_agreement("public:\n   value + other;\n   return value;\n");
    }

    /// A header shaped like the generated ones this walk is slow on: many
    /// enums, classes whose members share the enums' names, nested enums, an
    /// ownerless enumerator, and namespaced repeats of all of it.
    fn many_enums_and_mixed_declarations() -> String {
        let mut source = String::from("#define API\nenum Empty {};\nenum API Loose { KEPT, };\n");
        for index in 0..40 {
            let _ = write!(
                source,
                "enum Color{index} {{ RED{index}, GREEN{index} }};\n\
                 struct Holder{index} {{ int Color{index}; enum Inner{index} {{ A{index} }}; }};\n\
                 class Color{index}Like {{ public: int member{index}; }};\n"
            );
        }
        source.push_str("namespace outer {\n");
        for index in 0..20 {
            let _ = write!(
                source,
                "enum Shade{index} {{ DARK{index} }};\n\
                 struct Shade{index}Holder {{ int field{index}; }};\n"
            );
        }
        source.push_str("}\n");
        source
    }

    /// Drive [`CppFieldOwnerIndex`] and the declaration scan it replaced over
    /// every question a fixture's declarations can ask, and require the same
    /// answer from both.
    ///
    /// The release build has no `debug_assertions` agreement check, so this is
    /// what pins the two together there. The index is fed one declaration at a
    /// time and every question is re-asked after each one, which is what proves
    /// the incremental record agrees -- a whole-set rebuild would pass a weaker
    /// test. Each of the fixture's own fields is also fed in restated as a
    /// declaration of another file: the scan ignores those because it asks
    /// about the asking unit's own source, and the index has to ignore them for
    /// the same reason.
    ///
    /// Returns how many questions the fixture answered `true`, so a caller can
    /// assert that it actually reached the path (#2786).
    fn field_owner_index_agreement(source: &str, name: &str) -> usize {
        let parsed = parse_cpp_declarations(source, name);
        let file = ProjectFile::new(std::env::temp_dir(), name);
        let elsewhere = ProjectFile::new(std::env::temp_dir(), "elsewhere.hpp");

        let mut declarations: Vec<CodeUnit> = parsed.declarations().iter().cloned().collect();
        declarations.sort_by_key(|unit| (unit.fq_name(), unit.kind()));

        let foreign: Vec<CodeUnit> = declarations
            .iter()
            .filter(|unit| unit.kind() == CodeUnitType::Field)
            .map(|unit| {
                CodeUnit::new_fq(
                    elsewhere.clone(),
                    unit.kind(),
                    unit.package_name().to_string(),
                    unit.short_name().to_string(),
                    unit.fq().clone(),
                )
            })
            .collect();

        // One owner chain deeper than any C++ short name reaches today
        // (`cpp_member_fq`: at most one `.`, separating the owner chain from
        // the member). The scan asks `starts_with("owner.")`, so a field like
        // this answers for every owner in its chain, and the index has to
        // record every one of them rather than only the innermost.
        let mut packages: Vec<String> = declarations
            .iter()
            .map(|unit| unit.package_name().to_string())
            .collect();
        packages.push(String::new());
        packages.sort();
        packages.dedup();
        let deeper: Vec<CodeUnit> = packages
            .iter()
            .map(|package_name| {
                CodeUnit::new_fq(
                    file.clone(),
                    CodeUnitType::Field,
                    package_name.clone(),
                    "SynthOwner.middle.leaf".to_string(),
                    cpp_member_fq(package_name, "SynthOwner.middle.leaf"),
                )
            })
            .collect();

        // Every (package, owner) pair anything could ask about: each unit's own
        // short name, each dotted prefix of it, and the empty owner an
        // anonymous enum asks with (#2140).
        let mut questions: Vec<(String, String)> = Vec::new();
        for unit in declarations.iter().chain(deeper.iter()) {
            let package_name = unit.package_name().to_string();
            let short_name = unit.short_name();
            questions.push((package_name.clone(), short_name.to_string()));
            questions.push((package_name.clone(), String::new()));
            for (offset, _) in short_name.match_indices('.') {
                questions.push((package_name.clone(), short_name[..offset].to_string()));
            }
        }
        questions.sort();
        questions.dedup();

        let mut index = CppFieldOwnerIndex::default();
        let mut recorded: Vec<&CodeUnit> = Vec::new();
        let mut answered = 0usize;
        for unit in foreign
            .iter()
            .chain(declarations.iter())
            .chain(deeper.iter())
        {
            index.record(unit, &file);
            recorded.push(unit);
            for (package_name, owner_short_name) in &questions {
                let carried = index.owns_fields(package_name, owner_short_name);
                assert_eq!(
                    carried,
                    cpp_declarations_hold_owned_fields(
                        recorded.iter().copied(),
                        &file,
                        package_name,
                        owner_short_name
                    ),
                    "the carried field index and the declaration scan disagree about \
                     {package_name:?}/{owner_short_name:?} after recording {}",
                    unit.fq_name()
                );
                answered += usize::from(carried);
            }
        }

        // The whole-set build the first question performs must land on the same
        // index the incremental record built.
        let rebuilt = CppFieldOwnerIndex::of(
            foreign
                .iter()
                .chain(declarations.iter())
                .chain(deeper.iter()),
            &file,
        );
        for (package_name, owner_short_name) in &questions {
            assert_eq!(
                rebuilt.owns_fields(package_name, owner_short_name),
                index.owns_fields(package_name, owner_short_name),
                "a rebuilt index must answer what the incremental one answers for \
                 {package_name:?}/{owner_short_name:?}"
            );
        }
        answered
    }

    /// The one thing the field index cannot absorb by addition: a deferred
    /// replacement of a declaration that owns children removes those children.
    ///
    /// The first enum builds the index, the struct records `Color.RED` into it,
    /// the body-less second `Color` replaces the first and takes `Color.RED`
    /// with it, and the last enum then asks about owner `Color`. An index that
    /// survived that removal answers `true` where the declarations say `false`,
    /// which is exactly what the in-walk agreement assertion catches (#2786).
    #[test]
    fn a_replacement_that_removes_children_drops_the_field_index() {
        let source =
            "enum First { A };\nstruct Color { int RED; };\nstruct Color {};\nenum Color {};\n";
        let parsed = parse_cpp_declarations(source, "replaced-owner.hpp");
        let mut names: Vec<_> = parsed
            .declarations()
            .iter()
            .map(|unit| unit.fq_name())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "Color".to_string(),
                "First".to_string(),
                "First.A".to_string()
            ],
            "the replaced Color owns no field any more"
        );
    }

    /// A recovery that re-declares what the file already declared mints
    /// nothing.
    ///
    /// The reparse walk replaces the outer `Widget`, which removes its method,
    /// and then re-creates that method from the region. Creation alone would
    /// call the method recovered; it was there before the recovery opened, so
    /// the recovered set is empty and only the region's own reparse window is
    /// recorded (#2787).
    #[test]
    fn a_recovery_that_restores_an_existing_declaration_mints_nothing() {
        let source = "namespace demo { struct Widget { void doWork(); }; }\n\
                      BEGIN_NS\n\
                      namespace demo { struct Widget { void doWork(); }; }\n\
                      END_NS\n";
        let parsed = parse_cpp_declarations(source, "restored.cpp");
        let recovered: Vec<String> = parsed
            .materialization_records
            .iter()
            .filter_map(|record| match record {
                MaterializationRecord::RecoveredDeclaration { unit, .. } => Some(unit.fq_name()),
                _ => None,
            })
            .collect();
        assert!(
            recovered.is_empty(),
            "the region declares nothing the file did not already declare: {recovered:?}"
        );
        let mut names: Vec<String> = parsed
            .declarations()
            .iter()
            .map(|unit| unit.fq_name())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "demo".to_string(),
                "demo.Widget".to_string(),
                "demo.Widget.doWork".to_string(),
            ]
        );
    }

    /// Four macro-sentinel recoveries in one file (#941). Each one must record
    /// exactly the declarations it minted -- not the ones an earlier recovery
    /// minted, and not the file's other declarations -- in start-byte order,
    /// and each record must carry its own reparse window (#2787).
    #[test]
    fn repeated_sentinel_recoveries_record_only_what_each_one_minted() {
        let mut source = String::new();
        for index in 0..4 {
            let _ = write!(
                source,
                "BEGIN_NS\nnamespace demo{index} {{ struct Widget{index}                  {{ void doWork{index}(); }}; }}\nEND_NS\n"
            );
        }
        source.push_str("void outside() {}\n");
        let parsed = parse_cpp_declarations(&source, "repeated-sentinels.cpp");

        let recovered: Vec<(String, (usize, usize))> = parsed
            .materialization_records
            .iter()
            .filter_map(|record| match record {
                MaterializationRecord::RecoveredDeclaration { recovery, unit } => {
                    Some((unit.fq_name(), (recovery.start_byte, recovery.end_byte)))
                }
                _ => None,
            })
            .collect();

        let mut expected: Vec<(String, (usize, usize))> = Vec::new();
        for index in 0..4 {
            // The window the reparse covers: everything after the opening
            // sentinel token up to the newline before the closing one.
            let region = format!("namespace demo{index}");
            let region_start = source.find(&region).expect("each region is in the source");
            let start = source[..region_start]
                .rfind("BEGIN_NS")
                .expect("each region opens with a sentinel")
                + "BEGIN_NS".len();
            let end = start
                + source[start..]
                    .find("END_NS")
                    .expect("each region closes with a sentinel")
                - 1;
            let window = (start, end);
            for name in [
                format!("demo{index}"),
                format!("demo{index}.Widget{index}"),
                format!("demo{index}.Widget{index}.doWork{index}"),
            ] {
                expected.push((name, window));
            }
        }
        assert_eq!(
            recovered, expected,
            "each recovery records its own minted declarations, in order"
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| unit.fq_name() == "outside"),
            "the declaration outside every region stays parsed and unrecovered"
        );
    }

    #[test]
    fn carried_forward_field_index_answers_what_the_declaration_scan_answers() {
        assert!(
            field_owner_index_agreement(&many_enums_and_mixed_declarations(), "many-enums.hpp") > 0,
            "the fixture must actually own fields"
        );

        // The shapes that make the two implementations diverge if the index
        // records the wrong keys: a nested enum's owner is its whole dotted
        // chain, a class named like an enum owns fields under that same name, a
        // `$` in a short name is an owner separator the dotted prefix rule must
        // not split on, and the same enum name in two namespaces is two owners.
        for (source, name) in [
            ("struct S { enum E { V }; };\n", "nested.hpp"),
            (
                "enum Color { RED };\nstruct Color { int RED; };\n",
                "class-like.c",
            ),
            ("struct Outer { struct Inner { int V; }; };\n", "sigil.hpp"),
            (
                "enum E { V };\nnamespace ns { enum E { V }; }\n",
                "repeated.hpp",
            ),
            ("#define API\nenum API Loose { KEPT, };\n", "ownerless.hpp"),
        ] {
            field_owner_index_agreement(source, name);
        }
    }

    /// `blocks` copies of one plain class-with-methods template. The class the
    /// question is about is always the first one, so the only thing that
    /// changes between two of these sources is how much unrelated tree
    /// surrounds it.
    fn repeated_class_blocks(blocks: usize) -> String {
        let mut source = String::from("namespace demo {\n");
        for index in 0..blocks {
            let _ = write!(
                source,
                "\nclass Widget{index} {{\npublic:\n    int translate() const {{ return {index}; }}\n    int helper(const Widget{index}& other) const {{ return other.translate(); }}\nprivate:\n    int field = {index};\n}};\n"
            );
        }
        source.push_str("\n}\n");
        source
    }

    /// #1496: asking whether a recovered class shape claims one range must cost
    /// the path to that range, not a pass over the whole translation unit.
    ///
    /// The C++ inverse scan asks this once per candidate type reference, so a
    /// whole-tree walk makes one file's scan quadratic in its own size. Both
    /// sources here answer `None` -- these are plain classes that no recovery
    /// shape claims -- which is exactly the case that used to pay full price.
    #[test]
    fn recovered_class_body_lookup_cost_does_not_grow_with_the_rest_of_the_file() {
        let mut answers = Vec::new();
        let mut visits = Vec::new();
        let mut node_counts = Vec::new();
        for blocks in [200usize, 400] {
            let source = repeated_class_blocks(blocks);
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_cpp::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(&source, None).unwrap();
            let start_byte = source.find("class Widget0 ").expect("first class");
            let end_byte = start_byte
                + source[start_byte..]
                    .find("};")
                    .expect("first class terminator")
                + "};".len();
            let range = Range {
                start_byte,
                end_byte,
                start_line: 0,
                end_line: 0,
            };
            reset_recovered_class_body_node_visits_for_test();
            let recovered_export_classes =
                CppRecoveredExportClassIndex::build(tree.root_node(), &source);
            answers.push(recovered_class_body_at(
                &recovered_export_classes,
                tree.root_node(),
                &source,
                "Widget0",
                &range,
            ));
            visits.push(recovered_class_body_node_visits_for_test());
            let mut nodes = 0usize;
            let mut stack = vec![tree.root_node()];
            while let Some(node) = stack.pop() {
                nodes += 1;
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
            node_counts.push(nodes);
        }

        assert_eq!(
            answers,
            vec![None, None],
            "no recovered shape claims a plain class"
        );
        assert_eq!(
            visits[0], visits[1],
            "the walk must follow the range's own path, so doubling the unrelated \
             classes must not change the node count: {visits:?} over trees of \
             {node_counts:?} nodes"
        );
        assert!(
            visits[1] * 20 < node_counts[1],
            "the walk must stay far below one pass over the tree: {visits:?} over \
             trees of {node_counts:?} nodes"
        );
    }
}
