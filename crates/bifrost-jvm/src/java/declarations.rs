use brokk_bifrost_core::analyzer::fq_name::{
    FqName, SegmentId, SegmentKind, joined_segments, normalize_joined, segment_interner,
};
use brokk_bifrost_core::analyzer::model::{CallableArity, SignatureMetadata};
use brokk_bifrost_core::analyzer::model::{DeclarationInfo, DeclarationKind};
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::HashSet;
use tree_sitter::{Node, Parser, Tree};

use crate::java::graph_support::{java_declared_type_parameters, java_type_parameter_name};
use crate::java::imports::parse_import_info;

/// Intern one qualified-name segment in the process-global interner.
fn java_segment(text: &str, kind: SegmentKind) -> SegmentId {
    segment_interner().intern(text, kind)
}

/// Java's package path is stored `.`-joined in `package_name`.
const JAVA_PACKAGE_SEPARATOR: &str = ".";

/// Build the structured package-path prefix for a Java declaration.
///
/// `package_name` (from `determine_package_name`) is already the `.`-joined
/// dotted package (`com.example.pkg`, empty for the unnamed package). Each
/// component becomes one [`SegmentKind::Package`] segment — mirroring python's
/// `python_module_fq` (`Package`-`Package` renders `.` by default, which is
/// exactly this convention; unlike go's `/`-joined import path, java's package
/// has no `Path` component).
///
/// [`joined_segments`] is the split half of the shared empty-component
/// decision; `determine_package_name` applies [`normalize_joined`], its join
/// half, to the string it returns. A Java identifier cannot contain a literal
/// `.`, but a declaration can still be written with a doubled or dangling one
/// -- intellij-community's inspection fixtures carry `package com..foo;` -- and
/// the two spellings must not disagree about it (#2375).
pub(crate) fn java_package_fq(package_name: &str) -> FqName {
    let mut fq = FqName::new();
    for component in joined_segments(package_name, JAVA_PACKAGE_SEPARATOR) {
        fq.push(java_segment(component, SegmentKind::Package));
    }
    fq
}

pub fn determine_package_name(root: Node<'_>, source: &str) -> String {
    for index in 0..root.named_child_count() {
        let Some(child) = root.named_child(index) else {
            continue;
        };

        if child.kind() == "package_declaration" {
            let declared = node_text(child, source)
                .trim()
                .strip_prefix("package ")
                .unwrap_or("")
                .strip_suffix(';')
                .unwrap_or("")
                .trim()
                .to_string();
            // Share the empty-component decision with `java_package_fq`, which
            // splits this string back apart (#2375).
            return normalize_joined(&declared, JAVA_PACKAGE_SEPARATOR).into_owned();
        }

        if is_class_like_declaration_kind(child.kind()) {
            break;
        }
    }

    String::new()
}

fn strip_generic_type_arguments(input: &str) -> String {
    let mut depth = 0usize;
    let mut out = String::with_capacity(input.len());

    for ch in input.chars() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }

    out
}

pub fn normalize_java_full_name(fq_name: &str) -> String {
    let mut normalized = strip_generic_type_arguments(fq_name);

    if normalized.contains("$anon$") {
        let mut out = String::with_capacity(normalized.len());
        let mut chars = normalized.char_indices();

        while let Some((index, ch)) = chars.next() {
            if normalized[index..].starts_with("$anon$") {
                out.push_str("$anon$");
                for _ in 0.."anon$".len() {
                    chars.next();
                }
                continue;
            }

            out.push(if ch == '$' { '.' } else { ch });
        }

        return out;
    }

    normalized = strip_trailing_numeric_suffix(&normalized);
    normalized = strip_location_suffix(&normalized);
    normalized.replace('$', ".")
}

/// Canonicalize an extracted Java identity one semantic segment at a time.
/// Nested-owner joins are represented by `SegmentKind`, so the canonical form
/// changes the join kind instead of replacing `$` in a rendered full name.
/// Bytecode-only suffixes can still occur inside one segment; the existing
/// segment-text normalizer handles exactly that local vocabulary.
pub fn normalize_java_fq_name(fq_name: &FqName) -> FqName {
    let interner = segment_interner();
    let mut normalized = FqName::new();
    for &segment_id in fq_name.segments() {
        let (text, kind) = interner.resolve(segment_id);
        let text = normalize_java_full_name(text);
        if text.is_empty() {
            continue;
        }
        let kind = match kind {
            SegmentKind::Nested | SegmentKind::Companion => SegmentKind::Type,
            other => other,
        };
        normalized.push(interner.intern(&text, kind));
    }
    if normalized.is_empty() {
        fq_name.clone()
    } else {
        normalized
    }
}

fn strip_trailing_numeric_suffix(input: &str) -> String {
    let colon_split = input.rsplit_once(':');
    let candidate = colon_split.map(|(head, _)| head).unwrap_or(input);
    // fqname-M4: parses a JVM bytecode-derived synthetic name (anonymous `$<digits>` suffix),
    // not a CodeUnit's structured short_name — the `$anon`/binary-name subsystem, not fq inference.
    let Some((prefix, suffix)) = candidate.rsplit_once('$') else {
        return input.to_string();
    };

    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return input.to_string();
    }

    if let Some((_, location)) = colon_split {
        format!("{prefix}:{location}")
    } else {
        prefix.to_string()
    }
}

fn strip_location_suffix(input: &str) -> String {
    let Some((head, tail)) = input.rsplit_once(':') else {
        return input.to_string();
    };
    if !tail.bytes().all(|byte| byte.is_ascii_digit()) {
        return input.to_string();
    }

    if let Some((grand_head, middle)) = head.rsplit_once(':')
        && middle.bytes().all(|byte| byte.is_ascii_digit())
    {
        return grand_head.to_string();
    }

    head.to_string()
}

pub fn extract_java_call_receiver(reference: &str) -> Option<String> {
    let trimmed = reference.trim();
    if trimmed.is_empty() || !trimmed.is_ascii() {
        return None;
    }

    let before_args = trimmed
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(trimmed)
        .trim();
    let (receiver, method_name) = before_args.rsplit_once('.')?;
    if receiver.is_empty() || method_name.is_empty() || receiver.contains('$') {
        return None;
    }

    if !looks_like_java_method_name(method_name) {
        return None;
    }

    let segments: Vec<_> = receiver.split('.').collect();
    let last = *segments.last()?;
    if !looks_like_pascal_identifier(last) {
        return None;
    }

    for segment in &segments {
        if segment.is_empty()
            || !segment
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            return None;
        }

        let first = segment.as_bytes()[0] as char;
        if !first.is_ascii_lowercase() && !first.is_ascii_uppercase() {
            return None;
        }
    }

    Some(receiver.to_string())
}

fn looks_like_java_method_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    first.is_ascii_lowercase() && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn looks_like_pascal_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    first.is_ascii_uppercase() && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

pub fn is_java_anonymous_structure(fq_name: &str) -> bool {
    fq_name.contains("$anon$")
        || fq_name
            // fqname-M4: classifies a JVM bytecode-derived anonymous-structure name, not a CodeUnit fq
            .rsplit_once('$')
            .map(|(_, suffix)| suffix.chars().all(|ch| ch.is_ascii_digit()))
            .unwrap_or(false)
}

pub fn collect_type_identifiers(node: Node<'_>, source: &str, identifiers: &mut HashSet<String>) {
    walk_named_tree_preorder(node, true, |node| {
        match node.kind() {
            "type_identifier" | "scoped_type_identifier" => {
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

/// The `type_identifiers` fact family persisted for one Java blob: every name
/// the file spells that could bind a type declared in another workspace file.
///
/// Two readings share this one set, so it must be a superset of both. The
/// reverse-reference prefilter needs written type names and qualified type
/// paths (`java.util.List`). The file dependency graph's same-package tier
/// needs the terminal names Java binds implicitly, and a class used as a
/// static or value qualifier (`Owner.INSTANCE`) spells `Owner` as a plain
/// `identifier`, not a `type_identifier` -- so capitalized identifiers are
/// retained as structured type-like evidence too.
///
/// Both readings are conservative: an extra name costs a candidate that a
/// later exact check discards, while a missing name silently loses an edge.
///
/// A declaration's own name is excluded. It is a definition, not a reference,
/// and the same-package reading has no later check that would discard it: a
/// file that recorded the classes it declares would report itself as one of
/// its own referencing files.
fn collect_persisted_type_identifiers(
    node: Node<'_>,
    source: &str,
    identifiers: &mut HashSet<String>,
) {
    walk_named_tree_preorder(node, true, |node| {
        let text = node_text(node, source).trim();
        if !text.is_empty()
            && (matches!(node.kind(), "type_identifier" | "scoped_type_identifier")
                || (node.kind() == "identifier"
                    && looks_like_pascal_identifier(text)
                    && !is_declared_name(node)))
        {
            identifiers.insert(text.to_string());
        }
        WalkControl::Continue
    });
}

/// Whether `node` is the `name` field of the declaration that encloses it.
fn is_declared_name(node: Node<'_>) -> bool {
    node.parent()
        .and_then(|parent| parent.child_by_field_name("name"))
        == Some(node)
}

/// One class-like scope waiting on the extraction stack.
///
/// A written declaration and an anonymous `new Base(...) { ... }` body differ
/// only in where their name, header, and supertype come from. Everything after
/// that -- members, nested types, signature metadata -- is the same walk, so
/// both ride the one explicit stack rather than a second traversal (#2045).
enum JavaClassScope<'tree> {
    Declared(Node<'tree>),
    Anonymous {
        creation: Node<'tree>,
        body: Node<'tree>,
    },
    EnumConstantBody {
        constant: Node<'tree>,
        body: Node<'tree>,
    },
}

/// A pending scope together with the owner it hangs off and the file's
/// top-level owner: `(scope, parent, top level)`.
type PendingClassScope<'tree> = (JavaClassScope<'tree>, Option<CodeUnit>, Option<CodeUnit>);

/// What the extraction loop needs from one class-like scope, whichever form
/// introduced it.
struct JavaClassScopeFacts<'tree> {
    unit: CodeUnit,
    /// The node whose range anchors the declaration. The loop also reads its
    /// kind: only a `record_declaration` has components and a compact
    /// constructor.
    anchor: Node<'tree>,
    body: Option<Node<'tree>>,
    raw_supertypes: Vec<String>,
    signature: String,
    is_interface: bool,
    is_static: bool,
}

pub fn visit_class_like<'tree>(
    file: &ProjectFile,
    source: &str,
    node: Node<'tree>,
    package_name: &str,
    parent: Option<&CodeUnit>,
    top_level_owner: Option<&CodeUnit>,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
) -> Option<CodeUnit> {
    let mut first = None;
    let mut stack: Vec<PendingClassScope<'tree>> = vec![(
        JavaClassScope::Declared(node),
        parent.cloned(),
        top_level_owner.cloned(),
    )];
    while let Some((scope, parent, top_level_owner)) = stack.pop() {
        let facts = match scope {
            JavaClassScope::Declared(node) => {
                let Some(facts) =
                    declared_class_scope(file, source, node, package_name, parent.as_ref())
                else {
                    continue;
                };
                facts
            }
            JavaClassScope::Anonymous { creation, body } => {
                let owner = parent.as_ref().expect(
                    "an anonymous class body is always written inside an enclosing declaration",
                );
                anonymous_class_scope(file, source, creation, body, package_name, owner)
            }
            JavaClassScope::EnumConstantBody { constant, body } => {
                let owner = parent
                    .as_ref()
                    .expect("an enum-constant-specific body is always owned by its declaring enum");
                enum_constant_class_scope(file, source, constant, body, package_name, owner)
            }
        };

        let code_unit = facts.unit;
        if first.is_none() {
            first = Some(code_unit.clone());
        }

        let top_level = top_level_owner.unwrap_or_else(|| code_unit.clone());
        parsed.add_code_unit(
            code_unit.clone(),
            facts.anchor,
            source,
            parent.clone(),
            Some(top_level.clone()),
        );
        parsed.set_raw_supertypes(code_unit.clone(), facts.raw_supertypes);
        // The declaration node's own kind is what separates an interface from a
        // class; recording it here is what lets a family edge state `implements`
        // rather than `overrides` without re-reading the owner's source. A Java
        // annotation type is an interface -- `@interface Marker` declares
        // `interface Marker extends java.lang.annotation.Annotation` -- so a
        // class that names one in its `implements` clause implements it.
        parsed.add_signature_with_metadata(
            code_unit.clone(),
            SignatureMetadata::new(facts.signature, Vec::new())
                .with_class_like_interface(facts.is_interface)
                .with_class_like_static(facts.is_static)
                // The arity of the written parameter list, so a class that
                // writes none is a recorded zero rather than an unread list.
                // An anonymous body and an enum-constant body write no list at
                // all, which is the same recorded zero.
                .with_recorded_type_parameters(
                    java_declared_type_parameters(facts.anchor)
                        .into_iter()
                        .filter_map(|parameter| java_type_parameter_name(parameter, source))
                        .map(str::to_string)
                        .collect(),
                ),
        );

        if facts.anchor.kind() == "record_declaration" {
            visit_record_components(
                file,
                source,
                facts.anchor,
                package_name,
                &code_unit,
                &top_level,
                parsed,
            );
        }

        let Some(body) = facts.body else {
            continue;
        };
        for child in class_like_body_children_rev(body) {
            match child.kind() {
                kind if is_class_like_declaration_kind(kind) => {
                    stack.push((
                        JavaClassScope::Declared(child),
                        Some(code_unit.clone()),
                        Some(top_level.clone()),
                    ));
                }
                "method_declaration" | "constructor_declaration" => {
                    visit_callable(
                        file,
                        source,
                        child,
                        package_name,
                        &code_unit,
                        &top_level,
                        parsed,
                        &mut stack,
                    );
                }
                "compact_constructor_declaration"
                    if facts.anchor.kind() == "record_declaration" =>
                {
                    visit_compact_constructor(
                        file,
                        source,
                        child,
                        facts.anchor,
                        package_name,
                        &code_unit,
                        &top_level,
                        parsed,
                        &mut stack,
                    );
                }
                "field_declaration" | "constant_declaration" => {
                    visit_field_declaration(
                        file,
                        source,
                        child,
                        package_name,
                        &code_unit,
                        &top_level,
                        parsed,
                        &mut stack,
                    );
                }
                "enum_constant" => {
                    visit_enum_constant(
                        file,
                        source,
                        child,
                        package_name,
                        &code_unit,
                        &top_level,
                        parsed,
                    );
                    if let Some(body) = enum_constant_class_body(child) {
                        stack.push((
                            JavaClassScope::EnumConstantBody {
                                constant: child,
                                body,
                            },
                            Some(code_unit.clone()),
                            Some(top_level.clone()),
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    first
}

/// Build the stable identity for a written class-like declaration without
/// walking its members. The dependency-only parser uses this to retain the
/// type names needed by Java import resolution.
pub fn class_like_code_unit(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: Option<&CodeUnit>,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let simple_name = node_text(name_node, source).trim();
    if simple_name.is_empty() {
        return None;
    }
    let local_coordinate = parent.filter(|parent| parent.is_function()).map(|_| {
        format!(
            "local${}:{}",
            node.start_position().row,
            node.start_position().column
        )
    });
    let short_name = parent
        .map(|parent| match &local_coordinate {
            Some(coordinate) => format!("{}${coordinate}.{simple_name}", parent.short_name()),
            None => format!("{}.{}", parent.short_name(), simple_name),
        })
        .unwrap_or_else(|| simple_name.to_string());
    let fq = match parent {
        Some(parent) => {
            let mut fq = parent.fq().clone();
            if let Some(coordinate) = &local_coordinate {
                fq.push(java_segment(coordinate, SegmentKind::Nested));
            }
            fq.with_pushed(java_segment(simple_name, SegmentKind::Type))
        }
        None => {
            java_package_fq(package_name).with_pushed(java_segment(simple_name, SegmentKind::Type))
        }
    };
    Some(CodeUnit::new_fq(
        file.clone(),
        brokk_bifrost_core::analyzer::model::CodeUnitType::Class,
        package_name.to_string(),
        short_name,
        fq,
    ))
}

/// The scope a written `class`/`interface`/`enum`/`record`/`@interface`
/// declaration introduces, wherever it is written: a top-level type, a nested
/// member type, or a class local to one method body.
fn declared_class_scope<'tree>(
    file: &ProjectFile,
    source: &str,
    node: Node<'tree>,
    package_name: &str,
    parent: Option<&CodeUnit>,
) -> Option<JavaClassScopeFacts<'tree>> {
    let unit = class_like_code_unit(file, source, node, package_name, parent)?;

    Some(JavaClassScopeFacts {
        unit,
        anchor: node,
        body: node.child_by_field_name("body"),
        raw_supertypes: extract_raw_supertypes(node, source),
        signature: class_signature(node, source),
        is_interface: matches!(
            node.kind(),
            "interface_declaration" | "annotation_type_declaration"
        ),
        is_static: java_class_like_is_static(node, parent),
    })
}

/// The scope an anonymous `new Base(...) { ... }` body introduces.
///
/// The unit takes the same `$anon$line:column` marker the lambda units use, so
/// no source spelling can name it and it stays synthetic. The written `Base`
/// becomes its one raw supertype, which is what lets a member the body
/// inherits resolve exactly as a named subclass's would. The range anchors on
/// the body, not on the whole expression: the constructor arguments are
/// written in the enclosing scope and must keep resolving there.
fn anonymous_class_scope<'tree>(
    file: &ProjectFile,
    source: &str,
    creation: Node<'tree>,
    body: Node<'tree>,
    package_name: &str,
    parent: &CodeUnit,
) -> JavaClassScopeFacts<'tree> {
    let (short_name, fq) = java_anonymous_scope_identity(parent, creation);
    let mut raw_supertypes = Vec::new();
    if let Some(supertype) = creation.child_by_field_name("type") {
        collect_supertype_nodes(supertype, source, &mut raw_supertypes);
    }
    let header = source
        .get(creation.start_byte()..body.start_byte())
        .unwrap_or("")
        .trim_end();

    JavaClassScopeFacts {
        unit: CodeUnit::with_signature_and_fq(
            file.clone(),
            brokk_bifrost_core::analyzer::model::CodeUnitType::Class,
            package_name.to_string(),
            short_name,
            None,
            true,
            fq,
        ),
        anchor: body,
        body: Some(body),
        raw_supertypes,
        signature: format!("{} {{", normalize_whitespace(header)),
        is_interface: false,
        is_static: false,
    }
}

/// The class scope introduced by an enum constant with its own body.
///
/// JLS 8.9.1 makes this an anonymous direct subclass of the declaring enum.
/// It is distinct for every constant, inherits the enum's methods and
/// interfaces, and owns any methods or nested anonymous classes written in the
/// body (#2272, #2273).
fn enum_constant_class_scope<'tree>(
    file: &ProjectFile,
    source: &str,
    constant: Node<'tree>,
    body: Node<'tree>,
    package_name: &str,
    declaring_enum: &CodeUnit,
) -> JavaClassScopeFacts<'tree> {
    let line = constant.start_position().row;
    let column = constant.start_position().column;
    let anon = java_segment(&format!("anon${line}:{column}"), SegmentKind::Nested);
    let short_name = format!("{}$anon${line}:{column}", declaring_enum.short_name());
    let fq = declaring_enum.fq().clone().with_pushed(anon);
    let header = source
        .get(constant.start_byte()..body.start_byte())
        .unwrap_or("")
        .trim_end();

    JavaClassScopeFacts {
        unit: CodeUnit::with_signature_and_fq(
            file.clone(),
            brokk_bifrost_core::analyzer::model::CodeUnitType::Class,
            package_name.to_string(),
            short_name,
            None,
            true,
            fq,
        ),
        anchor: body,
        body: Some(body),
        raw_supertypes: vec![declaring_enum.identifier().to_string()],
        signature: format!("{} {{", normalize_whitespace(header)),
        is_interface: false,
        is_static: false,
    }
}

#[allow(clippy::too_many_arguments)]
fn visit_callable<'tree>(
    file: &ProjectFile,
    source: &str,
    node: Node<'tree>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    pending: &mut Vec<PendingClassScope<'tree>>,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };

    let name = node_text(name_node, source).trim();
    if name.is_empty() {
        return;
    }

    let signature = node
        .child_by_field_name("parameters")
        .map(|parameters| canonical_parameters_signature(parameters, source));
    let short_name = format!("{}.{}", parent.short_name(), name);
    let callable_sig = callable_signature(node, source);
    let parameter_labels = node
        .child_by_field_name("parameters")
        .map(|parameters| parameter_labels(parameters, source))
        .unwrap_or_default();
    let fq = parent
        .fq()
        .clone()
        .with_pushed(java_segment(name, SegmentKind::Member));
    let code_unit = CodeUnit::with_signature_and_fq(
        file.clone(),
        brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
        package_name.to_string(),
        short_name,
        signature.clone(),
        false,
        fq,
    );

    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    let modifiers = java_callable_modifiers(node);
    parsed.add_signature_with_metadata(
        code_unit.clone(),
        SignatureMetadata::with_parameter_labels(callable_sig, parameter_labels)
            .with_callable_arity(
                node.child_by_field_name("parameters")
                    .map(callable_arity_for_parameters)
                    .unwrap_or_else(|| CallableArity::exact(0)),
            )
            .with_callable_modifiers(
                modifiers.is_static,
                node.kind() == "constructor_declaration",
                modifiers.visibility,
            )
            .with_callable_parameter_types(
                node.child_by_field_name("parameters")
                    .map(|parameters| canonical_parameter_type_texts(parameters, source))
                    .unwrap_or_default(),
            )
            .with_callable_native(modifiers.is_native),
    );

    if let Some(body) = node.child_by_field_name("body") {
        collect_body_scopes(
            file,
            source,
            body,
            package_name,
            &code_unit,
            top_level,
            parsed,
            pending,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn visit_compact_constructor<'tree>(
    file: &ProjectFile,
    source: &str,
    node: Node<'tree>,
    record: Node<'tree>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    pending: &mut Vec<PendingClassScope<'tree>>,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some(parameters) = record.child_by_field_name("parameters") else {
        return;
    };
    let name = node_text(name_node, source).trim();
    if name.is_empty() {
        return;
    }

    let signature = canonical_parameters_signature(parameters, source);
    let short_name = format!("{}.{}", parent.short_name(), name);
    let declaration_header = callable_signature(node, source);
    let callable_sig = format!("{declaration_header}{signature}");
    let fq = parent
        .fq()
        .clone()
        .with_pushed(java_segment(name, SegmentKind::Member));
    let code_unit = CodeUnit::with_signature_and_fq(
        file.clone(),
        brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
        package_name.to_string(),
        short_name,
        Some(signature),
        false,
        fq,
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    parsed.add_signature_with_metadata(
        code_unit.clone(),
        SignatureMetadata::with_parameter_labels(
            callable_sig,
            parameter_labels(parameters, source),
        )
        .with_callable_arity(callable_arity_for_parameters(parameters))
        .with_callable_modifiers(false, true, java_callable_modifiers(node).visibility)
        .with_callable_parameter_types(canonical_parameter_type_texts(parameters, source)),
    );

    if let Some(body) = node.child_by_field_name("body") {
        collect_body_scopes(
            file,
            source,
            body,
            package_name,
            &code_unit,
            top_level,
            parsed,
            pending,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn visit_field_declaration<'tree>(
    file: &ProjectFile,
    source: &str,
    node: Node<'tree>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    pending: &mut Vec<PendingClassScope<'tree>>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }

        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };

        let name = node_text(name_node, source).trim();
        if name.is_empty() {
            continue;
        }

        let fq = parent
            .fq()
            .clone()
            .with_pushed(java_segment(name, SegmentKind::Member));
        let code_unit = CodeUnit::new_fq(
            file.clone(),
            brokk_bifrost_core::analyzer::model::CodeUnitType::Field,
            package_name.to_string(),
            format!("{}.{}", parent.short_name(), name),
            fq,
        );
        parsed.add_code_unit(
            code_unit.clone(),
            node,
            source,
            Some(parent.clone()),
            Some(top_level.clone()),
        );
        let signature = field_signature(node, child, source);
        let field_type = node
            .child_by_field_name("type")
            .map(|type_node| normalize_whitespace(node_text(type_node, source)));
        let (is_static, is_final) = java_field_modifiers(node);
        let has_initializer = child.child_by_field_name("value").is_some();
        parsed.add_signature_with_metadata(
            code_unit,
            SignatureMetadata::new(signature, Vec::new())
                .with_return_type_text(field_type)
                .with_field_modifiers(is_static, is_final)
                .with_field_initializer(has_initializer),
        );

        if let Some(value) = child.child_by_field_name("value") {
            collect_body_scopes(
                file,
                source,
                value,
                package_name,
                parent,
                top_level,
                parsed,
                pending,
            );
        }
    }
}

fn java_field_modifiers(field: Node<'_>) -> (bool, bool) {
    let modifiers = (0..field.named_child_count())
        .filter_map(|index| field.named_child(index))
        .find(|child| child.kind() == "modifiers");
    let mut is_static = false;
    let mut is_final = false;
    if let Some(modifiers) = modifiers {
        for index in 0..modifiers.child_count() {
            let Some(modifier) = modifiers.child(index) else {
                continue;
            };
            match modifier.kind() {
                "static" => is_static = true,
                "final" => is_final = true,
                _ => {}
            }
        }
    }

    let mut ancestor = field.parent();
    let mut implicit_static_final = false;
    while let Some(current) = ancestor {
        if is_class_like_declaration_kind(current.kind()) {
            implicit_static_final = matches!(
                current.kind(),
                "interface_declaration" | "annotation_type_declaration"
            );
            break;
        }
        ancestor = current.parent();
    }
    is_static |= implicit_static_final;
    is_final |= implicit_static_final;
    (is_static, is_final)
}

fn visit_record_components(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
) {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return;
    };

    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if child.kind() != "formal_parameter" {
            continue;
        }

        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };

        let name = node_text(name_node, source).trim();
        if name.is_empty() {
            continue;
        }

        let fq = parent
            .fq()
            .clone()
            .with_pushed(java_segment(name, SegmentKind::Member));
        let code_unit = CodeUnit::new_fq(
            file.clone(),
            brokk_bifrost_core::analyzer::model::CodeUnitType::Field,
            package_name.to_string(),
            format!("{}.{}", parent.short_name(), name),
            fq,
        );
        parsed.add_code_unit(
            code_unit.clone(),
            child,
            source,
            Some(parent.clone()),
            Some(top_level.clone()),
        );
        parsed.add_signature(code_unit, normalize_whitespace(node_text(child, source)));
    }
}

fn visit_enum_constant(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };

    let name = node_text(name_node, source).trim();
    if name.is_empty() {
        return;
    }

    let fq = parent
        .fq()
        .clone()
        .with_pushed(java_segment(name, SegmentKind::Member));
    let code_unit = CodeUnit::new_fq(
        file.clone(),
        brokk_bifrost_core::analyzer::model::CodeUnitType::Field,
        package_name.to_string(),
        format!("{}.{}", parent.short_name(), name),
        fq,
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    parsed.add_signature_with_metadata(
        code_unit,
        SignatureMetadata::new(enum_constant_signature(node, source), Vec::new())
            .with_field_modifiers(true, true),
    );
}

/// Walk one executable body and record the scopes written inside it.
///
/// Three scope forms can appear in a method, constructor, or initializer: a
/// lambda, a class declared local to the body, and an anonymous class body.
/// The lambda gets its unit here. The two class-like forms are handed to the
/// caller's own extraction stack, which already knows how to index a class
/// body and everything under it, and this walk does not descend into them
/// (#2045). Nothing recurses: the walk keeps its own explicit stack and the
/// class-like forms leave it entirely.
#[allow(clippy::too_many_arguments)]
fn collect_body_scopes<'tree>(
    file: &ProjectFile,
    source: &str,
    node: Node<'tree>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    pending: &mut Vec<PendingClassScope<'tree>>,
) {
    let mut stack = vec![(node, parent.clone())];
    while let Some((node, parent)) = stack.pop() {
        if is_class_like_declaration_kind(node.kind()) {
            pending.push((
                JavaClassScope::Declared(node),
                Some(parent),
                Some(top_level.clone()),
            ));
            continue;
        }

        // `new Base(arg) { ... }` splits in two: the class body is its own
        // scope, while the type arguments and the constructor arguments are
        // written in this scope and keep being walked here.
        let anonymous_body = java_anonymous_class_body(node);
        if let Some(body) = anonymous_body {
            pending.push((
                JavaClassScope::Anonymous {
                    creation: node,
                    body,
                },
                Some(parent.clone()),
                Some(top_level.clone()),
            ));
        }

        let next_parent = if node.kind() == "lambda_expression" {
            let lambda = lambda_code_unit(file, package_name, &parent, node);
            parsed.add_code_unit(
                lambda.clone(),
                node,
                source,
                Some(parent),
                Some(top_level.clone()),
            );
            lambda
        } else {
            parent
        };
        let mut cursor = node.walk();
        let children = node
            .named_children(&mut cursor)
            .filter(|child| Some(*child) != anonymous_body)
            .collect::<Vec<_>>();
        stack.extend(
            children
                .into_iter()
                .rev()
                .map(|child| (child, next_parent.clone())),
        );
    }
}

/// The `class_body` an `object_creation_expression` carries when it declares
/// an anonymous class rather than only calling a constructor.
fn java_anonymous_class_body<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    if node.kind() != "object_creation_expression" {
        return None;
    }
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .find(|child| child.kind() == "class_body")
}

fn enum_constant_class_body<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    if node.kind() != "enum_constant" {
        return None;
    }
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .find(|child| child.kind() == "class_body")
}

fn lambda_code_unit(
    file: &ProjectFile,
    package_name: &str,
    parent: &CodeUnit,
    node: Node<'_>,
) -> CodeUnit {
    let (short_name, fq) = java_anonymous_scope_identity(parent, node);
    CodeUnit::with_signature_and_fq(
        file.clone(),
        brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
        package_name.to_string(),
        short_name,
        None,
        true,
        fq,
    )
}

/// The `$anon$line:column` short name and structured path a scope written at
/// `node` hangs off `parent`.
///
/// The synthetic marker is a single `$anon$line:column` segment whose OWN text
/// embeds a literal `$` between "anon" and the coordinate
/// (`SegmentKind::Nested` renders one more `$` before it, regardless of the
/// preceding segment's kind, and segment text is free-form, so the embedded
/// `$` round-trips untouched). A lambda and an anonymous class body share this
/// identity because no source spelling names either one, and no two of them
/// can start at the same coordinate.
///
/// Where the marker hangs depends on what encloses it. A scope written in a
/// callable body -- a method, a constructor, or another lambda -- and a scope
/// written in an anonymous class body hang the marker straight off that
/// owner's own `fq`. A scope written in a *named* class's field or
/// class-level initializer runs in that class's implicit initializer, whose
/// name is the class's own name, so the marker hangs off a repeat of the
/// class's last segment (`F.F$anon$1:47`).
///
/// An anonymous owner has no written name to repeat, and repeating its marker
/// segment was the #2161 regression: the short name joined the repeat with `.`
/// while the structured name rendered the repeated `Nested` segment with `$`,
/// so the two disagreed (`...$anon$140:43.anon$140:43$anon$146:51` against
/// `...$anon$140:43$anon$140:43$anon$146:51`) and the construction-point
/// boundary check in `CodeUnit::with_signature_and_fq` panicked the workspace
/// build.
fn java_anonymous_scope_identity(parent: &CodeUnit, node: Node<'_>) -> (String, FqName) {
    let line = node.start_position().row;
    let column = node.start_position().column;
    let anon = java_segment(&format!("anon${line}:{column}"), SegmentKind::Nested);

    if parent.is_function() || parent.is_synthetic() {
        let short_name = format!("{}$anon${line}:{column}", parent.short_name());
        return (short_name, parent.fq().clone().with_pushed(anon));
    }

    let short_name = format!(
        "{}.{}$anon${line}:{column}",
        parent.short_name(),
        parent.identifier()
    );
    let mut fq = parent.fq().clone();
    fq.push(
        parent
            .fq()
            .last()
            .expect("a CodeUnit qualified name always has a terminal segment"),
    );
    (short_name, fq.with_pushed(anon))
}

pub fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    brokk_bifrost_core::analyzer::common::node_source_text(node, source)
}

pub fn normalize_whitespace(text: &str) -> String {
    brokk_bifrost_core::analyzer::common::collapse_whitespace(text)
}

pub fn parse_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .expect("failed to load java parser");
    parser.parse(source, None)
}

pub fn is_comment_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "line_comment" | "block_comment")
}

pub fn is_declaration_parent(kind: &str) -> bool {
    matches!(
        kind,
        "method_declaration"
            | "field_declaration"
            | "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "variable_declarator"
            | "formal_parameter"
            | "catch_formal_parameter"
            | "enhanced_for_statement"
            | "resource"
    )
}

pub fn is_class_like_declaration_kind(kind: &str) -> bool {
    matches!(
        kind,
        "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration"
    )
}

/// The member declarations one class-like body holds, reversed so a stack pops
/// them in source order.
///
/// A Java `enum_body` is not a flat member list. Its constants come first, and
/// every ordinary member -- field, method, constructor, nested type -- sits
/// under one `enum_body_declarations` wrapper introduced by the `;` that ends
/// the constant list. Splicing that wrapper's own children in place is what
/// makes an enum's members reach the same dispatch a class body's members
/// reach; without it they are silently dropped (#2045).
pub fn class_like_body_children_rev<'tree>(body: Node<'tree>) -> Vec<Node<'tree>> {
    let mut children = Vec::new();
    for index in (0..body.named_child_count()).rev() {
        let Some(child) = body.named_child(index) else {
            continue;
        };
        if child.kind() == "enum_body_declarations" {
            for inner in (0..child.named_child_count()).rev() {
                let Some(inner) = child.named_child(inner) else {
                    continue;
                };
                children.push(inner);
            }
            continue;
        }
        children.push(child);
    }
    children
}

pub fn find_nearest_declaration_from_node(
    start_node: Node<'_>,
    identifier: &str,
    source: &str,
) -> Option<DeclarationInfo> {
    let mut current = Some(start_node);

    while let Some(node) = current {
        match node.kind() {
            "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration" => {
                if let Some(found) = check_formal_parameters(node, identifier, source) {
                    return Some(found);
                }
            }
            "enhanced_for_statement" => {
                if let Some(found) = match_named_field(
                    node,
                    "name",
                    identifier,
                    source,
                    DeclarationKind::EnhancedForVariable,
                ) {
                    return Some(found);
                }
            }
            "catch_clause" => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if child.kind() == "catch_formal_parameter"
                        && let Some(found) = match_named_field(
                            child,
                            "name",
                            identifier,
                            source,
                            DeclarationKind::CatchParameter,
                        )
                    {
                        return Some(found);
                    }
                }
            }
            "try_with_resources_statement" => {
                if let Some(resources) = node.child_by_field_name("resources") {
                    let mut cursor = resources.walk();
                    for child in resources.named_children(&mut cursor) {
                        if child.kind() == "resource"
                            && let Some(found) = match_named_field(
                                child,
                                "name",
                                identifier,
                                source,
                                DeclarationKind::ResourceVariable,
                            )
                        {
                            return Some(found);
                        }
                    }
                }
            }
            "lambda_expression" => {
                if let Some(parameters) = node.child_by_field_name("parameters") {
                    if parameters.kind() == "identifier" {
                        if node_text(parameters, source).trim() == identifier {
                            return Some(declaration_info(
                                identifier,
                                DeclarationKind::LambdaParameter,
                                parameters,
                            ));
                        }
                    } else {
                        let mut cursor = parameters.walk();
                        for child in parameters.named_children(&mut cursor) {
                            if child.kind() == "identifier"
                                && node_text(child, source).trim() == identifier
                            {
                                return Some(declaration_info(
                                    identifier,
                                    DeclarationKind::LambdaParameter,
                                    child,
                                ));
                            }
                            if child.kind() == "formal_parameter"
                                && let Some(found) = match_named_field(
                                    child,
                                    "name",
                                    identifier,
                                    source,
                                    DeclarationKind::LambdaParameter,
                                )
                            {
                                return Some(found);
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        if let Some(found) = check_preceding_local_variables(node, identifier, source) {
            return Some(found);
        }

        current = node.parent();
    }

    None
}

fn check_formal_parameters(
    node: Node<'_>,
    identifier: &str,
    source: &str,
) -> Option<DeclarationInfo> {
    let params = node.child_by_field_name("parameters")?;
    let mut cursor = params.walk();
    for child in params.named_children(&mut cursor) {
        if child.kind() == "formal_parameter"
            && let Some(found) = match_named_field(
                child,
                "name",
                identifier,
                source,
                DeclarationKind::Parameter,
            )
        {
            return Some(found);
        }
    }
    None
}

fn check_preceding_local_variables(
    current: Node<'_>,
    identifier: &str,
    source: &str,
) -> Option<DeclarationInfo> {
    let parent = current.parent()?;
    let mut cursor = parent.walk();
    for sibling in parent.named_children(&mut cursor) {
        if sibling.end_byte() > current.start_byte() {
            break;
        }
        if sibling.kind() != "local_variable_declaration" {
            continue;
        }
        let mut local_cursor = sibling.walk();
        for child in sibling.named_children(&mut local_cursor) {
            if child.kind() == "variable_declarator"
                && let Some(found) = match_named_field(
                    child,
                    "name",
                    identifier,
                    source,
                    DeclarationKind::LocalVariable,
                )
            {
                return Some(found);
            }
        }
    }
    None
}

fn match_named_field(
    node: Node<'_>,
    field_name: &str,
    identifier: &str,
    source: &str,
    kind: DeclarationKind,
) -> Option<DeclarationInfo> {
    let name_node = node.child_by_field_name(field_name)?;
    if node_text(name_node, source).trim() == identifier {
        Some(declaration_info(identifier, kind, name_node))
    } else {
        None
    }
}

fn declaration_info(identifier: &str, kind: DeclarationKind, node: Node<'_>) -> DeclarationInfo {
    DeclarationInfo {
        identifier: identifier.to_string(),
        kind,
        range: brokk_bifrost_core::analyzer::Range {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            start_line: node.start_position().row + 1,
            end_line: node.end_position().row + 1,
        },
    }
}

fn class_signature(node: Node<'_>, source: &str) -> String {
    let body_start = node
        .child_by_field_name("body")
        .map(|body| body.start_byte())
        .unwrap_or(node.end_byte());
    let header = source
        .get(node.start_byte()..body_start)
        .unwrap_or("")
        .trim_end();
    format!("{} {{", normalize_whitespace(header))
}

fn java_class_like_is_static(node: Node<'_>, parent: Option<&CodeUnit>) -> bool {
    if parent.is_none() {
        return false;
    }
    if matches!(
        node.kind(),
        "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration"
    ) || java_callable_modifiers(node).is_static
    {
        return true;
    }

    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if is_class_like_declaration_kind(current.kind()) {
            return matches!(
                current.kind(),
                "interface_declaration" | "annotation_type_declaration"
            );
        }
        ancestor = current.parent();
    }
    false
}

fn callable_signature(node: Node<'_>, source: &str) -> String {
    let end = node
        .child_by_field_name("body")
        .map(|body| body.start_byte())
        .unwrap_or(node.end_byte());
    normalize_whitespace(source.get(node.start_byte()..end).unwrap_or("").trim_end())
}

fn canonical_parameters_signature(parameters: Node<'_>, source: &str) -> String {
    format!(
        "({})",
        canonical_parameter_type_texts(parameters, source).join(", ")
    )
}

/// The declared type of each parameter, in order, read from the parameter's own
/// `type` node (plus its array dimensions or varargs marker).
///
/// This is the strongest per-parameter fact the Java declaration walk holds: a
/// source spelling, not a resolved or erased type. It is recorded so that
/// consumers can discriminate overloads structurally instead of splitting a
/// rendered signature string.
fn canonical_parameter_type_texts(parameters: Node<'_>, source: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        match child.kind() {
            "formal_parameter" => {
                if let Some(type_node) = child.child_by_field_name("type") {
                    let mut ty = normalize_whitespace(node_text(type_node, source));
                    if let Some(dimensions) = child.child_by_field_name("dimensions") {
                        ty.push_str(node_text(dimensions, source).trim());
                    }
                    parts.push(ty);
                }
            }
            "spread_parameter" => {
                if let Some(type_node) = spread_parameter_type_node(child) {
                    parts.push(format!(
                        "{}[]",
                        normalize_whitespace(node_text(type_node, source))
                    ));
                }
            }
            "ERROR" => {
                if let Some(type_node) = malformed_spread_parameter_type_node(child) {
                    parts.push(format!(
                        "{}[]",
                        normalize_whitespace(node_text(type_node, source))
                    ));
                }
            }
            "receiver_parameter" => {
                if let Some(type_node) = child.child_by_field_name("type") {
                    parts.push(normalize_whitespace(node_text(type_node, source)));
                }
            }
            _ => {}
        }
    }

    parts
}

/// The modifier facts a Java callable declares, read from its `modifiers`
/// node rather than from its rendered header text.
struct JavaCallableModifiers {
    is_static: bool,
    /// The declaration is implemented outside every source the workspace can
    /// read. A consumer that must not guess past a body-less callee needs this
    /// to tell `native` from `abstract`.
    is_native: bool,
    visibility: DeclaredVisibility,
}

fn java_callable_modifiers(node: Node<'_>) -> JavaCallableModifiers {
    // Java's default when no access modifier is written is package-private.
    // Interface members are implicitly public, but that is an inheritance rule
    // the consumer applies from the owner's kind; the declaration itself still
    // states nothing here, and inventing `Public` would be a claim the source
    // never made.
    let mut modifiers = JavaCallableModifiers {
        is_static: false,
        is_native: false,
        visibility: DeclaredVisibility::PackagePrivate,
    };
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "modifiers" {
            continue;
        }
        let mut inner = child.walk();
        for modifier in child.children(&mut inner) {
            match modifier.kind() {
                "static" => modifiers.is_static = true,
                "native" => modifiers.is_native = true,
                "public" => modifiers.visibility = DeclaredVisibility::Public,
                "protected" => modifiers.visibility = DeclaredVisibility::Protected,
                "private" => modifiers.visibility = DeclaredVisibility::Private,
                _ => {}
            }
        }
    }
    modifiers
}

fn parameter_labels(parameters: Node<'_>, source: &str) -> Vec<String> {
    let mut labels = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        let name = match child.kind() {
            "formal_parameter" => child.child_by_field_name("name"),
            "spread_parameter" => spread_parameter_name(child),
            "ERROR" => malformed_spread_parameter_name(child),
            _ => None,
        };
        if let Some(name) = name {
            let label = node_text(name, source).trim();
            if !label.is_empty() {
                labels.push(label.to_string());
            }
        }
    }
    labels
}

fn callable_arity_for_parameters(parameters: Node<'_>) -> CallableArity {
    let mut total = 0usize;
    let mut repeated = false;
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        match child.kind() {
            "formal_parameter" => total += 1,
            "spread_parameter" => {
                total += 1;
                repeated = true;
            }
            "ERROR" if malformed_spread_parameter_name(child).is_some() => {
                total += 1;
                repeated = true;
            }
            _ => {}
        }
    }
    let required = total.saturating_sub(usize::from(repeated));
    CallableArity::new(required, total, repeated)
}

fn spread_parameter_type_node(parameter: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = parameter.walk();
    parameter.named_children(&mut cursor).find(|child| {
        !matches!(
            child.kind(),
            "variable_declarator" | "modifiers" | "annotation" | "marker_annotation"
        )
    })
}

fn spread_parameter_name(parameter: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = parameter.walk();
    for child in parameter.named_children(&mut cursor) {
        if child.kind() == "variable_declarator" {
            return child.child_by_field_name("name");
        }
    }
    None
}

fn malformed_spread_parameter_type_node(parameter: Node<'_>) -> Option<Node<'_>> {
    if parameter.kind() != "ERROR" {
        return None;
    }
    let mut cursor = parameter.walk();
    parameter
        .named_children(&mut cursor)
        .find(|child| is_malformed_spread_parameter_type_node(child.kind()))
}

fn malformed_spread_parameter_name(parameter: Node<'_>) -> Option<Node<'_>> {
    let type_end = malformed_spread_parameter_type_node(parameter)?.end_byte();
    let mut stack = vec![parameter];
    let mut last = None;
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier" && node.start_byte() > type_end {
            last = Some(node);
        }
        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    last
}

fn is_malformed_spread_parameter_type_node(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "type_identifier"
            | "scoped_identifier"
            | "scoped_type_identifier"
            | "generic_type"
            | "annotated_type"
            | "array_type"
    )
}

fn field_signature(field_node: Node<'_>, declarator: Node<'_>, source: &str) -> String {
    let Some(type_node) = field_node.child_by_field_name("type") else {
        return normalize_whitespace(node_text(field_node, source));
    };
    let Some(name_node) = declarator.child_by_field_name("name") else {
        return normalize_whitespace(node_text(field_node, source));
    };

    let prefix = normalize_whitespace(
        source
            .get(field_node.start_byte()..type_node.start_byte())
            .unwrap_or(""),
    );
    let type_text = normalize_whitespace(node_text(type_node, source));
    let name_text = node_text(name_node, source).trim();

    let mut signature = String::new();
    for part in [prefix.as_str(), type_text.as_str(), name_text] {
        if part.is_empty() {
            continue;
        }
        if !signature.is_empty() {
            signature.push(' ');
        }
        signature.push_str(part);
    }

    let suffix = declarator
        .child_by_field_name("value")
        .and_then(|value| literal_field_initializer(value, source))
        .map(|value| format!(" = {value};"))
        .unwrap_or_else(|| ";".to_string());
    signature.push_str(&suffix);
    signature
}

fn literal_field_initializer<'a>(value: Node<'_>, source: &'a str) -> Option<&'a str> {
    let kind = value.kind();
    if kind.ends_with("_literal") || matches!(kind, "true" | "false" | "null_literal" | "null") {
        Some(node_text(value, source).trim())
    } else {
        None
    }
}

fn enum_constant_signature(node: Node<'_>, source: &str) -> String {
    let mut text = node_text(node, source).trim().to_string();
    if node.next_named_sibling().is_some() {
        text.push(',');
    }
    text
}

pub fn module_code_unit(file: &ProjectFile, package_name: &str) -> CodeUnit {
    let fq = java_package_fq(package_name);
    match package_name.rsplit_once('.') {
        Some((parent, leaf)) => CodeUnit::new_fq(
            file.clone(),
            brokk_bifrost_core::analyzer::model::CodeUnitType::Module,
            parent.to_string(),
            leaf.to_string(),
            fq,
        ),
        None => CodeUnit::new_fq(
            file.clone(),
            brokk_bifrost_core::analyzer::model::CodeUnitType::Module,
            String::new(),
            package_name.to_string(),
            fq,
        ),
    }
}

pub fn extract_raw_supertypes(node: Node<'_>, source: &str) -> Vec<String> {
    let mut raw = Vec::new();

    if let Some(superclass) = node.child_by_field_name("superclass") {
        collect_supertype_nodes(superclass, source, &mut raw);
    }
    if let Some(interfaces) = node.child_by_field_name("interfaces") {
        collect_supertype_nodes(interfaces, source, &mut raw);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "extends_interfaces" {
            collect_supertype_nodes(child, source, &mut raw);
        }
    }

    raw
}

fn collect_supertype_nodes(node: Node<'_>, source: &str, raw: &mut Vec<String>) {
    walk_named_tree_preorder(node, true, |node| {
        match node.kind() {
            // A type argument is not a supertype: `extends ArrayList<String>`
            // makes the class a list, not a string. Recording the argument left
            // the hierarchy free to link a class to its own element type, and
            // left an unresolvable type parameter (`extends SetView<E>`) looking
            // like a supertype outside the workspace (#2161).
            "type_arguments" => return WalkControl::SkipChildren,
            "type_identifier" | "scoped_type_identifier" => {
                let text = node_text(node, source).trim();
                if !text.is_empty() {
                    raw.push(text.to_string());
                }
            }
            _ => {}
        }
        WalkControl::Continue
    });
}

/// The whole-file declaration walk behind `JavaAdapter::parse_file`: the
/// package module unit, the import facts, and every top-level class-like
/// declaration with its members.
pub fn parse_java_file(file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
    let root = tree.root_node();
    let package_name = determine_package_name(root, source);
    let mut parsed = ParsedFile::new(package_name.clone());
    collect_persisted_type_identifiers(root, source, &mut parsed.type_identifiers);
    let package_module_code_unit =
        (!package_name.is_empty()).then(|| module_code_unit(file, &package_name));

    for index in 0..root.named_child_count() {
        let Some(child) = root.named_child(index) else {
            continue;
        };

        match child.kind() {
            "package_declaration" => {
                if let Some(module) = &package_module_code_unit {
                    parsed.add_code_unit(module.clone(), child, source, None, Some(module.clone()));
                    parsed.add_signature(module.clone(), format!("package {};", package_name));
                }
            }
            "import_declaration" => {
                let raw = node_text(child, source).trim().to_string();
                parsed.imports.push(parse_import_info(child, source, raw));
            }
            "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration" => {
                let class_code_unit =
                    visit_class_like(file, source, child, &package_name, None, None, &mut parsed);
                if let (Some(module), Some(class_code_unit)) =
                    (&package_module_code_unit, class_code_unit)
                {
                    parsed.add_child(module.clone(), class_code_unit);
                }
            }
            _ => {}
        }
    }

    parsed
}

#[cfg(test)]
mod relational_name_tests {
    use super::*;
    use brokk_bifrost_core::analyzer::Language;

    #[test]
    fn structured_lookup_canonicalization_matches_the_legacy_spelling() {
        let interner = segment_interner();
        let mut name = FqName::new();
        name.push(interner.intern("com", SegmentKind::Package));
        name.push(interner.intern("Outer", SegmentKind::Type));
        name.push(interner.intern("Inner<T>", SegmentKind::Nested));
        let exact = name.display_native(Language::Java, interner);
        let structured = normalize_java_fq_name(&name).display_native(Language::Java, interner);
        assert_eq!(structured, normalize_java_full_name(&exact));
        assert_eq!(structured, "com.Outer.Inner");
    }
}

#[cfg(test)]
mod same_package_identifier_tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("java grammar");
        parser.parse(source, None).expect("java tree")
    }

    /// The `type_identifiers` family the coarse file graph reads for Java's
    /// same-package tier. A class named only as a static or value qualifier
    /// (`SamePackageOwner.INSTANCE`) is spelled as a plain `identifier`, not a
    /// `type_identifier`, so the walk has to keep capitalized identifiers --
    /// but not a declaration's own name, which is a definition rather than a
    /// reference.
    #[test]
    fn type_identifiers_keep_referenced_names_and_drop_declared_ones() {
        let source = r#"package sample;
import sample.explicit.Target;
class Outer {
    class Inner { void nestedMethod() {} }
    Target field;
    void method(Target value) {
        NotAType local = null;
        SamePackageOwner.INSTANCE.use();
    }
}
"#;
        let file = ProjectFile::new(
            std::env::current_dir().expect("test working directory must be available"),
            "src/Outer.java",
        );
        let tree = parse(source);
        let parsed = parse_java_file(&file, source, &tree);

        assert!(parsed.type_identifiers.contains("Target"));
        assert!(parsed.type_identifiers.contains("NotAType"));
        assert!(parsed.type_identifiers.contains("SamePackageOwner"));
        assert!(
            !parsed.type_identifiers.contains("Outer"),
            "a declaration's own name is a definition, not a reference: {:?}",
            parsed.type_identifiers
        );
    }
}

#[cfg(test)]
mod type_parameter_metadata_tests {
    use super::*;
    use tree_sitter::Parser;

    /// A Java class-like declaration records its own type-parameter list, so a
    /// nongeneric class is a proven zero rather than the unread list an empty
    /// `type_parameters` used to mean (#1651).
    #[test]
    fn java_class_like_declarations_record_their_type_parameters() {
        let source = r#"package example;

public class Foo {
    public interface Inner<T> {}
    public record Pair<K, V>(K key, V value) {}
    public enum Colour { RED }
    public <T> T identity(T value) { return value; }
}
"#;
        let file = ProjectFile::new(
            std::env::current_dir().expect("test working directory must be available"),
            "src/example/Foo.java",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("Java grammar");
        let tree = parser.parse(source, None).expect("Java tree");
        let parsed = parse_java_file(&file, source, &tree);

        let mut recorded = parsed
            .signature_metadata
            .iter()
            .flat_map(|(unit, metadata)| {
                metadata
                    .iter()
                    .filter(|entry| entry.type_parameters_recorded())
                    .map(|entry| (unit.short_name().to_string(), entry.type_parameters().len()))
            })
            .collect::<Vec<_>>();
        recorded.sort();
        assert_eq!(
            recorded,
            vec![
                ("Foo".to_string(), 0),
                ("Foo.Colour".to_string(), 0),
                ("Foo.Inner".to_string(), 1),
                ("Foo.Pair".to_string(), 2),
            ],
            "a generic method's own parameters stay a callable fact, unrecorded here"
        );
    }
}
