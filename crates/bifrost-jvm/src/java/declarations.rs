use brokk_bifrost_core::analyzer::fq_name::{
    FqName, SegmentId, SegmentKind, joined_segments, segment_interner,
};
use brokk_bifrost_core::analyzer::java_facts::JavaTypeConstructorShape;
use brokk_bifrost_core::analyzer::model::{CallableArity, SignatureMetadata};
use brokk_bifrost_core::analyzer::model::{DeclarationInfo, DeclarationKind};
use brokk_bifrost_core::analyzer::parsed_file::{
    ParsedFile, ParsedNativeSource, ParsedSourceFacts, SourceDeclarationMetadataLink,
    SourceImportFact,
};
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceDeclarationVisibilityFact,
    SourceImportId,
};
use brokk_bifrost_core::analyzer::structural::collector::StructuralFactCollector;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_core::analyzer::structural::spec::{CompiledKinds, StructuralSpec};
use brokk_bifrost_core::analyzer::tree_walk::{
    ParentIndex, TreeWalkAction, WalkControl, walk_named_tree_preorder,
};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::{Node, Parser, Tree};

use crate::java::graph_support::{java_declared_type_parameters, java_type_parameter_name};
use crate::java::imports::{
    JavaImportSyntax, JavaPackageSyntax, parse_import_syntax, parse_package_syntax,
};
use crate::java::resolution::{JavaResolutionBuilder, JavaResolutionExtraction};
use crate::java::source_types::is_java_synthetic_class_body;
use crate::java::structural::{JAVA_KIND_TABLE, JAVA_STRUCTURAL_SPEC};

/// Intern one qualified-name segment in the process-global interner.
fn java_segment(text: &str, kind: SegmentKind) -> SegmentId {
    segment_interner().intern(text, kind)
}

/// Java's package path is stored `.`-joined in `package_name`.
const JAVA_PACKAGE_SEPARATOR: &str = ".";

/// Build the structured package-path prefix for a Java declaration.
///
/// `package_name` is the `.`-joined dotted package (`com.example.pkg`, empty
/// for the unnamed package). Each component becomes one
/// [`SegmentKind::Package`] segment - mirroring python's `python_module_fq`
/// (`Package`-`Package` renders `.` by default, which is exactly this
/// convention; unlike go's `/`-joined import path, java's package has no
/// `Path` component).
pub(crate) fn java_package_fq(package_name: &str) -> FqName {
    let mut fq = FqName::new();
    for component in joined_segments(package_name, JAVA_PACKAGE_SEPARATOR) {
        fq.push(java_segment(component, SegmentKind::Package));
    }
    fq
}

struct JavaTopLevelPackageSyntaxes<'tree, 'source> {
    syntaxes: Vec<JavaPackageSyntax<'tree, 'source>>,
    display_index: Option<usize>,
}

impl<'tree, 'source> JavaTopLevelPackageSyntaxes<'tree, 'source> {
    fn display(&self) -> Option<&JavaPackageSyntax<'tree, 'source>> {
        self.display_index.map(|index| &self.syntaxes[index])
    }
}

/// Interpret every top-level package node once for the primary walk. The
/// display candidate deliberately keeps the historical first-package-before-
/// class boundary, while the full record list lets native lowering reuse the
/// same syntax for late package nodes and retain its independent admission
/// gaps.
fn collect_top_level_package_syntaxes<'tree, 'source>(
    root: Node<'tree>,
    source: &'source str,
) -> JavaTopLevelPackageSyntaxes<'tree, 'source> {
    let mut syntaxes = Vec::new();
    let mut display_index = None;
    let mut display_prefix = true;
    for index in 0..root.named_child_count() {
        let Some(child) = root.named_child(index) else {
            continue;
        };
        if child.kind() == "package_declaration" {
            let syntax = parse_package_syntax(child, source);
            if display_prefix && display_index.is_none() {
                display_index = Some(syntaxes.len());
            }
            syntaxes.push(syntax);
        }
        if is_class_like_declaration_kind(child.kind()) {
            display_prefix = false;
        }
    }
    JavaTopLevelPackageSyntaxes {
        syntaxes,
        display_index,
    }
}

fn package_name_from_syntax(syntax: Option<&JavaPackageSyntax<'_, '_>>) -> String {
    let Some(segments) = syntax.and_then(|syntax| syntax.segments.as_ref()) else {
        return String::new();
    };
    segments
        .iter()
        .map(|(_, spelling)| *spelling)
        .collect::<Vec<_>>()
        .join(JAVA_PACKAGE_SEPARATOR)
}

pub fn determine_package_name(root: Node<'_>, source: &str) -> String {
    let packages = collect_top_level_package_syntaxes(root, source);
    package_name_from_syntax(packages.display())
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

pub(super) fn looks_like_pascal_identifier(name: &str) -> bool {
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

/// Whether `node` is the `name` field of the declaration that encloses it.
pub(super) fn is_declared_name(node: Node<'_>) -> bool {
    node.parent()
        .and_then(|parent| parent.child_by_field_name("name"))
        == Some(node)
}

/// Facts needed to publish one class-like scope, whichever form introduced it.
#[derive(Debug, Clone, Copy)]
pub(super) struct JavaTypeShape {
    pub(super) is_static: bool,
    pub(super) constructor_shape: Option<JavaTypeConstructorShape>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct JavaFieldShape {
    pub(super) is_static: bool,
    pub(super) is_final: bool,
}

#[derive(Debug, Clone)]
pub(super) struct JavaCallableShape {
    properties: JavaCallableProperties,
    parameter_repetition: HashMap<usize, bool>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct JavaCallableProperties {
    pub(super) is_static: bool,
    pub(super) is_constructor: bool,
    pub(super) arity: CallableArity,
}

impl JavaCallableShape {
    pub(super) fn properties(&self) -> JavaCallableProperties {
        self.properties
    }

    pub(super) fn repeated_for(&self, node_id: usize) -> Option<bool> {
        self.parameter_repetition.get(&node_id).copied()
    }
}

struct JavaClassScopeFacts<'tree> {
    unit: CodeUnit,
    /// The node whose range anchors the declaration. The loop also reads its
    /// kind: only a `record_declaration` has components and a compact
    /// constructor.
    anchor: Node<'tree>,
    raw_supertypes: Vec<String>,
    signature: String,
    is_interface: bool,
    is_static: bool,
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
    type_shape: JavaTypeShape,
) -> Option<JavaClassScopeFacts<'tree>> {
    let unit = class_like_code_unit(file, source, node, package_name, parent)?;

    Some(JavaClassScopeFacts {
        unit,
        anchor: node,
        raw_supertypes: extract_raw_supertypes(node, source),
        signature: class_signature(node, source),
        is_interface: matches!(
            node.kind(),
            "interface_declaration" | "annotation_type_declaration"
        ),
        is_static: type_shape.is_static,
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
        raw_supertypes: vec![declaring_enum.identifier().to_string()],
        signature: format!("{} {{", normalize_whitespace(header)),
        is_interface: false,
        is_static: false,
    }
}

fn record_source_declaration(
    collector: &mut PrimarySourceFactCollector<'_>,
    links: &mut Vec<(SourceDeclarationId, CodeUnit)>,
    node: Node<'_>,
    unit: &CodeUnit,
) -> SourceDeclarationId {
    let occurrence = collector.intern_node(node);
    let name = node
        .child_by_field_name("name")
        .map(|name| collector.intern_node(name));
    let declaration = collector.declare(occurrence, name);
    links.push((declaration, unit.clone()));
    declaration
}

fn add_source_metadata(
    parsed: &mut ParsedFile,
    links: &mut Vec<SourceDeclarationMetadataLink>,
    declaration: SourceDeclarationId,
    unit: &CodeUnit,
    metadata: SignatureMetadata,
) {
    let metadata_ordinal = parsed.add_signature_with_metadata_ordinal(unit.clone(), metadata);
    links.push(SourceDeclarationMetadataLink {
        declaration,
        unit: unit.clone(),
        metadata_ordinal,
    });
}

impl<'tree, 'source, 'parsed> JavaPrimaryParseState<'tree, 'source, 'parsed> {
    fn visit_callable(
        &mut self,
        node: Node,
        parent: &CodeUnit,
        top_level: &CodeUnit,
        visibility: DeclaredVisibility,
        modifiers: JavaDeclarationModifiers,
        properties: JavaCallableProperties,
    ) -> Option<CodeUnit> {
        let file = &self.file;
        let source = self.source;
        let package_name = &self.package_name;
        let parsed = &mut *self.parsed;
        let collector = self.resolution.source_collector_mut();
        let links = &mut self.source_declaration_units;
        let metadata_links = &mut self.source_declaration_metadata;

        let name_node = node.child_by_field_name("name")?;

        let name = node_text(name_node, source).trim();
        if name.is_empty() {
            return None;
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
        let declaration = record_source_declaration(collector, links, node, &code_unit);
        add_source_metadata(
            parsed,
            metadata_links,
            declaration,
            &code_unit,
            SignatureMetadata::with_parameter_labels(callable_sig, parameter_labels)
                .with_callable_arity(properties.arity)
                .with_callable_modifiers(
                    properties.is_static,
                    properties.is_constructor,
                    visibility,
                )
                .with_callable_parameter_types(
                    node.child_by_field_name("parameters")
                        .map(|parameters| canonical_parameter_type_texts(parameters, source))
                        .unwrap_or_default(),
                )
                .with_callable_native(modifiers.is_native),
        );

        Some(code_unit)
    }

    fn visit_compact_constructor(
        &mut self,
        node: Node,
        record: Node,
        parent: &CodeUnit,
        top_level: &CodeUnit,
        visibility: DeclaredVisibility,
        properties: JavaCallableProperties,
    ) -> Option<CodeUnit> {
        let file = &self.file;
        let source = self.source;
        let package_name = &self.package_name;
        let parsed = &mut *self.parsed;
        let collector = self.resolution.source_collector_mut();
        let links = &mut self.source_declaration_units;
        let metadata_links = &mut self.source_declaration_metadata;

        let name_node = node.child_by_field_name("name")?;
        let parameters = record.child_by_field_name("parameters")?;
        let name = node_text(name_node, source).trim();
        if name.is_empty() {
            return None;
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
        let declaration = record_source_declaration(collector, links, node, &code_unit);
        add_source_metadata(
            parsed,
            metadata_links,
            declaration,
            &code_unit,
            SignatureMetadata::with_parameter_labels(
                callable_sig,
                parameter_labels(parameters, source),
            )
            .with_callable_arity(properties.arity)
            .with_callable_modifiers(properties.is_static, properties.is_constructor, visibility)
            .with_callable_parameter_types(canonical_parameter_type_texts(parameters, source)),
        );

        Some(code_unit)
    }

    fn visit_field_declaration(
        &mut self,
        node: Node,
        parent: &CodeUnit,
        top_level: &CodeUnit,
        shape: JavaFieldShape,
    ) {
        let file = &self.file;
        let source = self.source;
        let package_name = &self.package_name;
        let parsed = &mut *self.parsed;
        let collector = self.resolution.source_collector_mut();
        let links = &mut self.source_declaration_units;
        let metadata_links = &mut self.source_declaration_metadata;

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
            let declaration = record_source_declaration(collector, links, child, &code_unit);
            let signature = field_signature(node, child, source);
            let field_type = node
                .child_by_field_name("type")
                .map(|type_node| normalize_whitespace(node_text(type_node, source)));
            let has_initializer = child.child_by_field_name("value").is_some();
            add_source_metadata(
                parsed,
                metadata_links,
                declaration,
                &code_unit,
                SignatureMetadata::new(signature, Vec::new())
                    .with_return_type_text(field_type)
                    .with_field_modifiers(shape.is_static, shape.is_final)
                    .with_field_initializer(has_initializer),
            );
        }
    }
}

impl<'tree, 'source, 'parsed> JavaPrimaryParseState<'tree, 'source, 'parsed> {
    fn visit_record_components(&mut self, node: Node<'_>, parent: &CodeUnit, top_level: &CodeUnit) {
        let file = &self.file;
        let source = self.source;
        let package_name = &self.package_name;
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
            self.parsed.add_code_unit(
                code_unit.clone(),
                child,
                source,
                Some(parent.clone()),
                Some(top_level.clone()),
            );
            record_source_declaration(
                self.resolution.source_collector_mut(),
                &mut self.source_declaration_units,
                child,
                &code_unit,
            );
            self.parsed
                .add_signature(code_unit, normalize_whitespace(node_text(child, source)));
        }
    }

    fn visit_enum_constant(&mut self, node: Node<'_>, parent: &CodeUnit, top_level: &CodeUnit) {
        let file = &self.file;
        let source = self.source;
        let package_name = &self.package_name;
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
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            source,
            Some(parent.clone()),
            Some(top_level.clone()),
        );
        let declaration = record_source_declaration(
            self.resolution.source_collector_mut(),
            &mut self.source_declaration_units,
            node,
            &code_unit,
        );
        add_source_metadata(
            self.parsed,
            &mut self.source_declaration_metadata,
            declaration,
            &code_unit,
            SignatureMetadata::new(enum_constant_signature(node, source), Vec::new())
                .with_field_modifiers(true, true),
        );
    }
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

/// The modifier facts one Java declaration states, read from its structured
/// `modifiers` child rather than from its rendered header text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct JavaDeclarationModifiers {
    pub(super) is_abstract: bool,
    pub(super) is_static: bool,
    pub(super) is_final: bool,
    /// The declaration is implemented outside every source the workspace can
    /// read. A consumer that must not guess past a body-less callee needs this
    /// to tell `native` from `abstract`.
    pub(super) is_native: bool,
    /// `None` means that Java's owner-aware default applies. Keeping the
    /// written modifier distinct from its effective visibility lets the
    /// resolution producer apply interface and annotation implicit-public
    /// semantics without changing ordinary class-member metadata.
    pub(super) explicit_visibility: Option<DeclaredVisibility>,
}

pub(super) fn java_declaration_modifiers(node: Node<'_>) -> JavaDeclarationModifiers {
    let mut modifiers = JavaDeclarationModifiers::default();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "modifiers" {
            continue;
        }
        let mut inner = child.walk();
        for modifier in child.children(&mut inner) {
            match modifier.kind() {
                "abstract" => modifiers.is_abstract = true,
                "static" => modifiers.is_static = true,
                "final" => modifiers.is_final = true,
                "native" => modifiers.is_native = true,
                "public" => {
                    modifiers.explicit_visibility = Some(DeclaredVisibility::Public);
                }
                "protected" => {
                    modifiers.explicit_visibility = Some(DeclaredVisibility::Protected);
                }
                "private" => {
                    modifiers.explicit_visibility = Some(DeclaredVisibility::Private);
                }
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

fn java_callable_shape(
    parameters: Option<Node<'_>>,
    modifiers: JavaDeclarationModifiers,
    is_constructor: bool,
) -> JavaCallableShape {
    let (arity, parameter_repetition) = parameters
        .map(|parameters| {
            let mut total = 0usize;
            let mut repeated_any = false;
            let mut parameter_repetition = HashMap::default();
            let mut cursor = parameters.walk();
            for child in parameters.named_children(&mut cursor) {
                let repeated = match child.kind() {
                    "formal_parameter" => {
                        total += 1;
                        false
                    }
                    "spread_parameter" => {
                        total += 1;
                        repeated_any = true;
                        true
                    }
                    "ERROR" if malformed_spread_parameter_name(child).is_some() => {
                        total += 1;
                        repeated_any = true;
                        true
                    }
                    _ => continue,
                };
                assert!(
                    parameter_repetition.insert(child.id(), repeated).is_none(),
                    "one Java callable parameter shape per source node"
                );
            }
            (
                CallableArity::new(
                    total.saturating_sub(usize::from(repeated_any)),
                    total,
                    repeated_any,
                ),
                parameter_repetition,
            )
        })
        .unwrap_or_else(|| (CallableArity::exact(0), HashMap::default()));
    JavaCallableShape {
        properties: JavaCallableProperties {
            is_static: modifiers.is_static,
            is_constructor,
            arity,
        },
        parameter_repetition,
    }
}

fn java_type_constructor_shape(node: Node<'_>) -> Option<JavaTypeConstructorShape> {
    match node.kind() {
        "class_declaration" => {
            let body = node.child_by_field_name("body")?;
            let has_explicit_constructor = {
                let mut cursor = body.walk();
                body.named_children(&mut cursor)
                    .any(|child| child.kind() == "constructor_declaration")
            };
            Some(if has_explicit_constructor {
                JavaTypeConstructorShape::NoImplicit
            } else {
                JavaTypeConstructorShape::Default
            })
        }
        "record_declaration" => Some(JavaTypeConstructorShape::RecordCanonical(
            callable_arity_for_parameters(node.child_by_field_name("parameters")?),
        )),
        "interface_declaration" | "enum_declaration" | "annotation_type_declaration" => {
            Some(JavaTypeConstructorShape::NoImplicit)
        }
        kind => panic!("unsupported Java type constructor shape node kind {kind}"),
    }
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

#[derive(Clone)]
struct JavaDeclarationContext {
    unit: CodeUnit,
    top_level: CodeUnit,
    is_record: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JavaSourceOwnerKind {
    Class,
    Interface,
    Enum,
    Record,
    Annotation,
}

#[derive(Debug, Clone, Copy)]
struct JavaSourceOwner {
    kind: JavaSourceOwnerKind,
    body_id: usize,
}

impl JavaSourceOwner {
    fn from_declaration(node: Node<'_>) -> Option<Self> {
        let kind = match node.kind() {
            "class_declaration" => JavaSourceOwnerKind::Class,
            "interface_declaration" => JavaSourceOwnerKind::Interface,
            "enum_declaration" => JavaSourceOwnerKind::Enum,
            "record_declaration" => JavaSourceOwnerKind::Record,
            "annotation_type_declaration" => JavaSourceOwnerKind::Annotation,
            _ => return None,
        };
        Some(Self {
            kind,
            body_id: node
                .child_by_field_name("body")
                .map(|body| body.id())
                .unwrap_or(node.id()),
        })
    }

    fn synthetic_class(body: Node<'_>) -> Self {
        assert_eq!(body.kind(), "class_body");
        Self {
            kind: JavaSourceOwnerKind::Class,
            body_id: body.id(),
        }
    }
}

struct JavaPrimaryParseState<'tree, 'source, 'parsed> {
    file: ProjectFile,
    source: &'source str,
    package_name: String,
    package_module: Option<CodeUnit>,
    package_syntaxes: HashMap<usize, JavaPackageSyntax<'tree, 'source>>,
    root_id: usize,
    parsed: &'parsed mut ParsedFile,
    resolution: JavaResolutionBuilder<'source>,
    structural: StructuralFactCollector<'source>,
    structural_kinds: &'source CompiledKinds,
    call_site_context: &'source brokk_bifrost_core::analyzer::structural::callable::CallSiteContext,
    structural_parents: Vec<Option<u32>>,
    declaration_contexts: Vec<JavaDeclarationContext>,
    declaration_exits: Vec<bool>,
    source_visibility_owners: Vec<JavaSourceOwner>,
    source_visibility_exits: Vec<bool>,
    source_declaration_visibilities: Vec<SourceDeclarationVisibilityFact>,
    source_declaration_units: Vec<(SourceDeclarationId, CodeUnit)>,
    source_declaration_by_node: HashMap<usize, SourceDeclarationId>,
    source_declaration_metadata: Vec<SourceDeclarationMetadataLink>,
    source_imports: Vec<SourceImportFact>,
    generic_imports: Vec<SourceImportId>,
}

impl<'tree, 'source, 'parsed> JavaPrimaryParseState<'tree, 'source, 'parsed> {
    fn new(
        file: &ProjectFile,
        source: &'source str,
        package_syntaxes: JavaTopLevelPackageSyntaxes<'tree, 'source>,
        parsed: &'parsed mut ParsedFile,
        root: Node<'tree>,
        structural_kinds: &'source CompiledKinds,
        call_site_context: &'source brokk_bifrost_core::analyzer::structural::callable::CallSiteContext,
    ) -> Self {
        let package_name = package_name_from_syntax(package_syntaxes.display());
        let package_module =
            (!package_name.is_empty()).then(|| module_code_unit(file, &package_name));
        let package_syntaxes = package_syntaxes
            .syntaxes
            .into_iter()
            .map(|syntax| (syntax.node.id(), syntax))
            .collect::<HashMap<_, _>>();
        let resolution = JavaResolutionBuilder::new(root, source);
        let structural = StructuralFactCollector::new(
            &JAVA_STRUCTURAL_SPEC,
            source,
            call_site_context,
            usize::MAX,
            None,
        );
        Self {
            file: file.clone(),
            source,
            package_name,
            package_module,
            package_syntaxes,
            root_id: root.id(),
            parsed,
            resolution,
            structural,
            structural_kinds,
            call_site_context,
            structural_parents: vec![None],
            declaration_contexts: Vec::new(),
            declaration_exits: Vec::new(),
            source_visibility_owners: Vec::new(),
            source_visibility_exits: Vec::new(),
            source_declaration_visibilities: Vec::new(),
            source_declaration_units: Vec::new(),
            source_declaration_by_node: HashMap::default(),
            source_declaration_metadata: Vec::new(),
            source_imports: Vec::new(),
            generic_imports: Vec::new(),
        }
    }

    fn current_owner(&self) -> Option<&CodeUnit> {
        self.declaration_contexts
            .last()
            .map(|context| &context.unit)
    }

    fn current_top_level(&self) -> Option<CodeUnit> {
        self.declaration_contexts
            .last()
            .map(|context| context.top_level.clone())
    }

    fn intern_source_declaration(&mut self, node: Node<'_>) -> SourceDeclarationId {
        let collector = self.resolution.source_collector_mut();
        let occurrence = collector.intern_node(node);
        let name = node
            .child_by_field_name("name")
            .map(|name| collector.intern_node(name));
        collector.declare(occurrence, name)
    }

    fn direct_member_of_current_type(&self, node: Node<'_>) -> bool {
        let Some(owner) = self.source_visibility_owners.last() else {
            return false;
        };
        let Some(parent) = node.parent() else {
            return false;
        };
        if parent.id() == owner.body_id {
            return true;
        }
        owner.kind == JavaSourceOwnerKind::Enum
            && parent.kind() == "enum_body_declarations"
            && parent
                .parent()
                .is_some_and(|body| body.id() == owner.body_id)
    }

    fn source_type_shape(
        &self,
        node: Node<'_>,
        modifiers: JavaDeclarationModifiers,
    ) -> JavaTypeShape {
        let has_parent = self.current_owner().is_some();
        let implicit_static = matches!(
            node.kind(),
            "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration"
        ) || (self.direct_member_of_current_type(node)
            && matches!(
                self.source_visibility_owners.last().map(|owner| owner.kind),
                Some(JavaSourceOwnerKind::Interface | JavaSourceOwnerKind::Annotation)
            ));
        JavaTypeShape {
            is_static: has_parent && (modifiers.is_static || implicit_static),
            constructor_shape: java_type_constructor_shape(node),
        }
    }

    fn source_field_shape(
        &self,
        node: Node<'_>,
        modifiers: JavaDeclarationModifiers,
    ) -> JavaFieldShape {
        let implicit_static_final = self.direct_member_of_current_type(node)
            && matches!(
                self.source_visibility_owners.last().map(|owner| owner.kind),
                Some(JavaSourceOwnerKind::Interface | JavaSourceOwnerKind::Annotation)
            );
        JavaFieldShape {
            is_static: modifiers.is_static || implicit_static_final,
            is_final: modifiers.is_final || implicit_static_final,
        }
    }

    fn source_callable_parameters(node: Node<'tree>) -> Option<Node<'tree>> {
        if node.kind() == "compact_constructor_declaration" {
            node.parent()
                .and_then(|body| body.parent())
                .filter(|record| record.kind() == "record_declaration")
                .and_then(|record| record.child_by_field_name("parameters"))
        } else {
            node.child_by_field_name("parameters")
        }
    }

    fn source_visibility_for(&self, node: Node<'_>) -> DeclaredVisibility {
        let explicit = self
            .resolution
            .source_modifiers_for(node)
            .explicit_visibility;
        if let Some(explicit) = explicit {
            return explicit;
        }

        match node.kind() {
            kind if is_class_like_declaration_kind(kind) => {
                if node
                    .parent()
                    .is_some_and(|parent| parent.id() == self.root_id)
                {
                    DeclaredVisibility::PackagePrivate
                } else if self.direct_member_of_current_type(node) {
                    match self.source_visibility_owners.last().map(|owner| owner.kind) {
                        Some(JavaSourceOwnerKind::Interface | JavaSourceOwnerKind::Annotation) => {
                            DeclaredVisibility::Public
                        }
                        _ => DeclaredVisibility::PackagePrivate,
                    }
                } else {
                    DeclaredVisibility::Unknown
                }
            }
            "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration"
            | "annotation_type_element_declaration" => {
                let constructor = matches!(
                    node.kind(),
                    "constructor_declaration" | "compact_constructor_declaration"
                );
                if constructor
                    && self.source_visibility_owners.last().map(|owner| owner.kind)
                        == Some(JavaSourceOwnerKind::Enum)
                {
                    DeclaredVisibility::Private
                } else if self.direct_member_of_current_type(node)
                    && matches!(
                        self.source_visibility_owners.last().map(|owner| owner.kind),
                        Some(JavaSourceOwnerKind::Interface | JavaSourceOwnerKind::Annotation)
                    )
                {
                    DeclaredVisibility::Public
                } else {
                    DeclaredVisibility::PackagePrivate
                }
            }
            "field_declaration" | "constant_declaration" => {
                if self.direct_member_of_current_type(node)
                    && matches!(
                        self.source_visibility_owners.last().map(|owner| owner.kind),
                        Some(JavaSourceOwnerKind::Interface | JavaSourceOwnerKind::Annotation)
                    )
                {
                    DeclaredVisibility::Public
                } else {
                    DeclaredVisibility::PackagePrivate
                }
            }
            "enum_constant" => DeclaredVisibility::Public,
            kind => panic!("unsupported Java source visibility node kind {kind}"),
        }
    }

    fn capture_source_visibility(
        &mut self,
        node: Node<'tree>,
        declaration: SourceDeclarationId,
        visibility: DeclaredVisibility,
    ) {
        self.source_declaration_visibilities
            .push(SourceDeclarationVisibilityFact {
                declaration,
                visibility,
            });
        self.resolution
            .set_source_declaration_visibility(node, declaration, visibility);
    }

    fn capture_source_properties(&mut self, node: Node<'tree>) {
        let mut pushed_owner = false;
        let is_modifier_owner = is_class_like_declaration_kind(node.kind())
            || matches!(
                node.kind(),
                "method_declaration"
                    | "constructor_declaration"
                    | "compact_constructor_declaration"
                    | "field_declaration"
                    | "constant_declaration"
                    | "enum_constant"
                    | "annotation_type_element_declaration"
            );
        if is_modifier_owner {
            let modifiers = java_declaration_modifiers(node);
            self.resolution
                .set_source_declaration_modifiers(node, modifiers);
            if is_class_like_declaration_kind(node.kind()) {
                let shape = self.source_type_shape(node, modifiers);
                self.resolution.set_source_type_shape(node, shape);
            } else if matches!(
                node.kind(),
                "method_declaration"
                    | "constructor_declaration"
                    | "compact_constructor_declaration"
                    | "annotation_type_element_declaration"
            ) {
                let parameters = Self::source_callable_parameters(node);
                let shape = java_callable_shape(
                    parameters,
                    modifiers,
                    matches!(
                        node.kind(),
                        "constructor_declaration" | "compact_constructor_declaration"
                    ),
                );
                self.resolution.set_source_callable_shape(node, shape);
            } else if matches!(node.kind(), "field_declaration" | "constant_declaration") {
                let shape = self.source_field_shape(node, modifiers);
                self.resolution.set_source_field_shape(node, shape);
            }
        }

        match node.kind() {
            kind if is_class_like_declaration_kind(kind) => {
                let declaration = self.intern_source_declaration(node);
                let visibility = self.source_visibility_for(node);
                self.capture_source_visibility(node, declaration, visibility);
                if node.kind() == "record_declaration"
                    && let Some(parameters) = node.child_by_field_name("parameters")
                {
                    let mut cursor = parameters.walk();
                    for component in parameters.named_children(&mut cursor) {
                        if component.kind() != "formal_parameter"
                            || component.child_by_field_name("name").is_none()
                        {
                            continue;
                        }
                        let declaration = self.intern_source_declaration(component);
                        self.capture_source_visibility(
                            component,
                            declaration,
                            DeclaredVisibility::Private,
                        );
                    }
                }
                if let Some(owner) = JavaSourceOwner::from_declaration(node) {
                    self.source_visibility_owners.push(owner);
                    pushed_owner = true;
                }
            }
            "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration"
            | "annotation_type_element_declaration" => {
                if node.child_by_field_name("name").is_some() {
                    let declaration = self.intern_source_declaration(node);
                    let visibility = self.source_visibility_for(node);
                    self.capture_source_visibility(node, declaration, visibility);
                }
            }
            "field_declaration" | "constant_declaration" => {
                let visibility = self.source_visibility_for(node);
                let mut cursor = node.walk();
                for declarator in node.named_children(&mut cursor) {
                    if declarator.kind() != "variable_declarator"
                        || declarator.child_by_field_name("name").is_none()
                    {
                        continue;
                    }
                    let declaration = self.intern_source_declaration(declarator);
                    self.capture_source_visibility(declarator, declaration, visibility);
                }
            }
            "enum_constant" if node.child_by_field_name("name").is_some() => {
                let declaration = self.intern_source_declaration(node);
                let visibility = self.source_visibility_for(node);
                self.capture_source_visibility(node, declaration, visibility);
            }
            "class_body" if is_java_synthetic_class_body(node) => {
                self.source_visibility_owners
                    .push(JavaSourceOwner::synthetic_class(node));
                pushed_owner = true;
            }
            _ => {}
        }
        self.source_visibility_exits.push(pushed_owner);
    }

    fn source_visibility(&self, node: Node<'_>) -> DeclaredVisibility {
        self.resolution.source_visibility_for(node)
    }

    fn field_visibility(&self, node: Node<'_>) -> Option<DeclaredVisibility> {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| {
                child.kind() == "variable_declarator" && child.child_by_field_name("name").is_some()
            })
            .map(|declarator| self.source_visibility(declarator))
    }

    fn record_unit_source(&mut self, node: Node<'_>, unit: &CodeUnit) -> SourceDeclarationId {
        record_source_declaration(
            self.resolution.source_collector_mut(),
            &mut self.source_declaration_units,
            node,
            unit,
        )
    }

    /// Capture the source-owned type family before native or display admission.
    fn capture_source_type_facts(&mut self, node: Node<'tree>) {
        let is_callable = matches!(
            node.kind(),
            "method_declaration" | "constructor_declaration" | "compact_constructor_declaration"
        );
        let is_class = is_class_like_declaration_kind(node.kind());
        if !is_callable && !is_class {
            return;
        }
        if !is_class && node.child_by_field_name("name").is_none() {
            return;
        }
        let declaration = self.intern_source_declaration(node);
        self.source_declaration_by_node
            .insert(node.id(), declaration);
        if let Some(owner) = self.source_declaration_owner(node) {
            self.resolution
                .record_source_declaration_owner(declaration, owner);
        }
        if is_class {
            self.resolution
                .record_source_type_parameters(node, declaration);
            self.resolution.record_source_local_type(node, declaration);
        } else {
            self.resolution.record_source_callable(node, declaration);
        }
    }

    fn source_declaration_owner(&self, node: Node<'tree>) -> Option<SourceDeclarationId> {
        let mut current = node.parent();
        while let Some(ancestor) = current {
            if is_java_synthetic_class_body(ancestor) {
                return None;
            }
            if is_class_like_declaration_kind(ancestor.kind())
                || matches!(
                    ancestor.kind(),
                    "method_declaration"
                        | "constructor_declaration"
                        | "compact_constructor_declaration"
                )
            {
                return self.source_declaration_by_node.get(&ancestor.id()).copied();
            }
            current = ancestor.parent();
        }
        None
    }

    fn add_class_scope(&mut self, node: Node<'_>) -> bool {
        let parent = self.current_owner().cloned();
        let is_root = parent.is_none();
        let type_shape = self.resolution.source_type_shape_for(node);
        let Some(facts) = declared_class_scope(
            &self.file,
            self.source,
            node,
            &self.package_name,
            parent.as_ref(),
            type_shape,
        ) else {
            return false;
        };
        let unit = facts.unit.clone();
        let top_level = self.current_top_level().unwrap_or_else(|| unit.clone());
        self.parsed.add_code_unit(
            unit.clone(),
            facts.anchor,
            self.source,
            parent,
            Some(top_level.clone()),
        );
        self.parsed
            .set_raw_supertypes(unit.clone(), facts.raw_supertypes);
        let declaration = self.record_unit_source(node, &unit);
        let metadata = SignatureMetadata::new(facts.signature, Vec::new())
            .with_class_like_interface(facts.is_interface)
            .with_class_like_static(facts.is_static)
            .with_recorded_type_parameters(
                java_declared_type_parameters(node)
                    .into_iter()
                    .filter_map(|parameter| java_type_parameter_name(parameter, self.source))
                    .map(str::to_string)
                    .collect(),
            );
        add_source_metadata(
            self.parsed,
            &mut self.source_declaration_metadata,
            declaration,
            &unit,
            metadata,
        );
        if facts.anchor.kind() == "record_declaration" {
            self.visit_record_components(facts.anchor, &unit, &top_level);
        }
        if is_root && let Some(module) = self.package_module.clone() {
            self.parsed.add_child(module, unit.clone());
        }
        self.declaration_contexts.push(JavaDeclarationContext {
            unit,
            top_level,
            is_record: facts.anchor.kind() == "record_declaration",
        });
        true
    }

    fn add_synthetic_class_scope(&mut self, node: Node<'_>) -> bool {
        let Some(parent) = self.current_owner().cloned() else {
            return false;
        };
        let Some(parent_node) = node.parent() else {
            return false;
        };
        let facts = match parent_node.kind() {
            "object_creation_expression" => anonymous_class_scope(
                &self.file,
                self.source,
                parent_node,
                node,
                &self.package_name,
                &parent,
            ),
            "enum_constant" => enum_constant_class_scope(
                &self.file,
                self.source,
                parent_node,
                node,
                &self.package_name,
                &parent,
            ),
            _ => return false,
        };
        let unit = facts.unit;
        let top_level = self.current_top_level().unwrap_or_else(|| unit.clone());
        self.parsed.add_code_unit(
            unit.clone(),
            facts.anchor,
            self.source,
            Some(parent),
            Some(top_level.clone()),
        );
        self.parsed
            .set_raw_supertypes(unit.clone(), facts.raw_supertypes);
        self.parsed.add_signature_with_metadata(
            unit.clone(),
            SignatureMetadata::new(facts.signature, Vec::new())
                .with_class_like_interface(facts.is_interface)
                .with_class_like_static(facts.is_static),
        );
        self.declaration_contexts.push(JavaDeclarationContext {
            unit,
            top_level,
            is_record: false,
        });
        true
    }

    fn enter_declaration(&mut self, node: Node<'_>, active: bool) {
        let mut pushed = false;
        if active {
            match node.kind() {
                "package_declaration" => {
                    if let Some(module) = self.package_module.clone() {
                        self.parsed.add_code_unit(
                            module.clone(),
                            node,
                            self.source,
                            None,
                            Some(module.clone()),
                        );
                        self.parsed.add_signature(
                            module.clone(),
                            format!("package {};", self.package_name),
                        );
                        self.record_unit_source(node, &module);
                    }
                }
                kind if is_class_like_declaration_kind(kind) => {
                    pushed = self.add_class_scope(node);
                }
                "method_declaration" | "constructor_declaration"
                    if self.current_owner().is_some() =>
                {
                    let parent = self.current_owner().cloned().expect("callable owner");
                    let top_level = self.current_top_level().expect("callable top level");
                    let visibility = self.source_visibility(node);
                    let modifiers = self.resolution.source_modifiers_for(node);
                    let properties = self.resolution.source_callable_shape_for(node).properties();
                    if let Some(unit) = self.visit_callable(
                        node, &parent, &top_level, visibility, modifiers, properties,
                    ) {
                        self.declaration_contexts.push(JavaDeclarationContext {
                            unit,
                            top_level,
                            is_record: false,
                        });
                        pushed = true;
                    }
                }
                "compact_constructor_declaration"
                    if self.current_owner().is_some()
                        && self
                            .declaration_contexts
                            .last()
                            .is_some_and(|context| context.is_record) =>
                {
                    let parent = self.current_owner().cloned().expect("record owner");
                    let top_level = self.current_top_level().expect("record top level");
                    let record = node
                        .parent()
                        .and_then(|body| body.parent())
                        .filter(|record| record.kind() == "record_declaration");
                    let visibility = self.source_visibility(node);
                    let properties = self.resolution.source_callable_shape_for(node).properties();
                    if let Some(record) = record
                        && let Some(unit) = self.visit_compact_constructor(
                            node, record, &parent, &top_level, visibility, properties,
                        )
                    {
                        self.declaration_contexts.push(JavaDeclarationContext {
                            unit,
                            top_level,
                            is_record: false,
                        });
                        pushed = true;
                    }
                }
                "field_declaration" | "constant_declaration" if self.current_owner().is_some() => {
                    let parent = self.current_owner().cloned().expect("field owner");
                    let top_level = self.current_top_level().expect("field top level");
                    if self.field_visibility(node).is_some() {
                        let shape = self.resolution.source_field_shape_for(node);
                        self.visit_field_declaration(node, &parent, &top_level, shape);
                    }
                }
                "enum_constant" if self.current_owner().is_some() => {
                    let parent = self.current_owner().cloned().expect("enum owner");
                    let top_level = self.current_top_level().expect("enum top level");
                    self.visit_enum_constant(node, &parent, &top_level);
                }
                "class_body" => {
                    pushed = self.add_synthetic_class_scope(node);
                }
                "lambda_expression" if self.current_owner().is_some() => {
                    let parent = self.current_owner().cloned().expect("lambda owner");
                    let top_level = self.current_top_level().expect("lambda top level");
                    let unit = lambda_code_unit(&self.file, &self.package_name, &parent, node);
                    self.parsed.add_code_unit(
                        unit.clone(),
                        node,
                        self.source,
                        Some(parent),
                        Some(top_level.clone()),
                    );
                    self.declaration_contexts.push(JavaDeclarationContext {
                        unit,
                        top_level,
                        is_record: false,
                    });
                    pushed = true;
                }
                _ => {}
            }
        }
        self.declaration_exits.push(pushed);
    }

    fn enter_import(&mut self, node: Node<'tree>, syntax: &JavaImportSyntax<'tree, 'source>) {
        assert_eq!(node.kind(), "import_declaration");
        let raw = node_text(node, self.source).trim().to_string();
        let import = syntax.to_import_info(node, raw);
        let declaration = self.resolution.source_collector_mut().intern_node(node);
        let target = if syntax.is_wildcard {
            None
        } else {
            syntax
                .segments
                .as_ref()
                .and_then(|segments| segments.last().map(|(segment, _)| *segment))
                .map(|target| self.resolution.source_collector_mut().intern_node(target))
        };
        let source_import_id = SourceImportId::try_from_index(self.source_imports.len())
            .expect("Java source import count exceeds u32");
        self.source_imports.push(SourceImportFact::from_import(
            import,
            declaration,
            target,
            None,
            Vec::new(),
        ));
        self.generic_imports.push(source_import_id);
    }

    fn take_package_syntax(&mut self, node: Node<'tree>) -> JavaPackageSyntax<'tree, 'source> {
        assert_eq!(node.kind(), "package_declaration");
        if let Some(syntax) = self.package_syntaxes.remove(&node.id()) {
            return syntax;
        }
        assert_ne!(
            node.parent().map(|parent| parent.id()),
            Some(self.root_id),
            "every top-level Java package syntax must be precollected"
        );
        parse_package_syntax(node, self.source)
    }

    fn enter(
        &mut self,
        node: Node<'tree>,
        declaration_active: bool,
        native_active: bool,
        parents: &ParentIndex<'tree>,
    ) -> (bool, TreeWalkAction) {
        // Capture source-owned declaration properties before either projection
        // applies its own admission or suppression rules.
        self.capture_source_type_facts(node);
        self.capture_source_properties(node);
        let enclosing = *self
            .structural_parents
            .last()
            .expect("Java structural traversal has a root frame");
        let mut structural_parent = enclosing;
        if node.is_named()
            && let Some(kind) = self.structural_kinds.kind_of(&node)
            && JAVA_STRUCTURAL_SPEC.should_extract(node, kind)
        {
            let kind = JAVA_STRUCTURAL_SPEC.refine_kind(
                node,
                kind,
                enclosing.map(|id| self.structural.normalized_kind(id)),
                self.source,
                self.call_site_context,
            );
            let fact_id = self
                .structural
                .enter(
                    node,
                    kind,
                    enclosing,
                    self.resolution.source_collector_mut(),
                )
                .expect("complete Java preparation has no structural admission limit");
            let mut sink = self
                .structural
                .role_sink(self.resolution.source_collector_mut(), parents);
            JAVA_STRUCTURAL_SPEC.extract(node, kind, &mut sink);
            self.structural
                .accept_roles(fact_id, sink)
                .expect("complete Java preparation has no structural admission limit");
            structural_parent = Some(fact_id);
        }
        self.structural_parents.push(structural_parent);
        let package_syntax = (native_active && node.kind() == "package_declaration")
            .then(|| self.take_package_syntax(node));
        let import_syntax =
            (node.kind() == "import_declaration").then(|| parse_import_syntax(node, self.source));
        if let Some(syntax) = import_syntax.as_ref() {
            self.enter_import(node, syntax);
        }
        let native_action = if !node.is_named() {
            // The Java resolution lowerer historically receives named nodes;
            // keep punctuation transparent while the coordinated driver lets
            // structural collection observe the complete parser tree.
            TreeWalkAction::Descend
        } else if native_active {
            if let Some(syntax) = package_syntax.as_ref() {
                self.resolution.enter_package(node, syntax)
            } else if let Some(syntax) = import_syntax.as_ref() {
                self.resolution.enter_import(node, syntax)
            } else {
                self.resolution.enter(node)
            }
        } else {
            self.resolution.record_type_identifier(node);
            TreeWalkAction::Skip
        };
        self.enter_declaration(node, declaration_active);
        (true, native_action)
    }

    fn exit(&mut self, native_exit: bool) {
        assert!(self.structural_parents.pop().is_some());
        if self
            .source_visibility_exits
            .pop()
            .expect("every Java primary node has a source-property exit")
        {
            self.source_visibility_owners
                .pop()
                .expect("Java source-property owner exit must balance");
        }
        if self
            .declaration_exits
            .pop()
            .expect("every Java primary node has a declaration exit")
        {
            self.declaration_contexts
                .pop()
                .expect("Java declaration context exit must balance");
        }
        if native_exit {
            self.resolution.exit_scope();
        }
    }

    fn finish(mut self) {
        assert_eq!(self.structural_parents, [None]);
        assert!(self.declaration_contexts.is_empty());
        assert!(self.declaration_exits.is_empty());
        assert!(self.source_visibility_owners.is_empty());
        assert!(self.source_visibility_exits.is_empty());
        let structural = self
            .structural
            .finish()
            .expect("complete Java preparation has no structural admission limit");
        let native: JavaResolutionExtraction = self.resolution.finish();
        let source_imports = std::mem::take(&mut self.source_imports);
        let generic_imports = std::mem::take(&mut self.generic_imports);
        self.parsed.imports = generic_imports
            .iter()
            .map(|id| {
                source_imports
                    .get(id.index())
                    .expect("Java generic import projection references a source import")
                    .import_info(&native.source_facts)
            })
            .collect();
        self.parsed.type_identifiers = native.type_identifiers;
        let java_source_facts = native.java_source_facts;
        let source_facts = ParsedSourceFacts {
            java: Some(java_source_facts),
            source_bytes: self.source.len(),
            occurrences: native.source_facts,
            structural,
            native_site_occurrences: native.site_occurrences,
            native_declaration_sources: native.declaration_sources,
            declaration_visibilities: Some(std::mem::take(
                &mut self.source_declaration_visibilities,
            )),
            imports: source_imports,
            generic_imports,
            source_declaration_units: std::mem::take(&mut self.source_declaration_units),
            source_declaration_metadata: std::mem::take(&mut self.source_declaration_metadata),
        };
        assert_eq!(
            self.parsed.imports.len(),
            source_facts.generic_imports.len()
        );
        self.parsed.native_source = Some(ParsedNativeSource::new(
            native.facts,
            source_facts,
            self.parsed,
        ));
    }
}

enum JavaPrimaryFrame<'tree> {
    Enter {
        node: Node<'tree>,
        declaration_active: bool,
        native_active: bool,
    },
    Exit {
        native_exit: bool,
    },
}

fn walk_java_primary_tree<'tree>(
    root: Node<'tree>,
    state: &mut JavaPrimaryParseState<'tree, '_, '_>,
    parents: &ParentIndex<'tree>,
) {
    let mut stack = vec![JavaPrimaryFrame::Enter {
        node: root,
        declaration_active: true,
        native_active: true,
    }];
    while let Some(frame) = stack.pop() {
        match frame {
            JavaPrimaryFrame::Enter {
                node,
                declaration_active,
                native_active,
            } => {
                let (declaration_descend, native_action) =
                    state.enter(node, declaration_active, native_active, parents);
                let native_descend = native_active
                    && matches!(
                        &native_action,
                        TreeWalkAction::Descend | TreeWalkAction::DescendWithExit
                    );
                let native_exit =
                    native_active && matches!(&native_action, TreeWalkAction::DescendWithExit);
                stack.push(JavaPrimaryFrame::Exit { native_exit });
                let mut cursor = node.walk();
                let mut children = node.children(&mut cursor).collect::<Vec<_>>();
                children.reverse();
                stack.extend(children.into_iter().map(|child| JavaPrimaryFrame::Enter {
                    node: child,
                    declaration_active: declaration_active && declaration_descend,
                    native_active: native_descend,
                }));
            }
            JavaPrimaryFrame::Exit { native_exit } => state.exit(native_exit),
        }
    }
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
    let package_syntaxes = collect_top_level_package_syntaxes(root, source);
    let package_name = package_name_from_syntax(package_syntaxes.display());
    let mut parsed = ParsedFile::new(package_name.clone());
    let grammar = tree_sitter_java::LANGUAGE.into();
    let structural_kinds = CompiledKinds::compile(&grammar, JAVA_KIND_TABLE);
    let call_site_context = JAVA_STRUCTURAL_SPEC.call_site_context(root, source);
    let parents = ParentIndex::new(root);
    let mut state = JavaPrimaryParseState::new(
        file,
        source,
        package_syntaxes,
        &mut parsed,
        root,
        &structural_kinds,
        &call_site_context,
    );
    walk_java_primary_tree(root, &mut state, &parents);
    state.finish();
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
mod source_shape_tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse(source: &str) -> ParsedFile {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("java grammar");
        let tree = parser.parse(source, None).expect("java tree");
        let file = ProjectFile::new(
            std::env::temp_dir().join("java-source-shape"),
            "src/Fixture.java",
        );
        parse_java_file(&file, source, &tree)
    }

    fn metadata<'a>(parsed: &'a ParsedFile, prefix: &str) -> &'a SignatureMetadata {
        parsed
            .signature_metadata
            .values()
            .flat_map(|rows| rows.iter())
            .find(|metadata| metadata.label().starts_with(prefix))
            .unwrap_or_else(|| panic!("missing Java metadata beginning with {prefix:?}"))
    }

    #[test]
    fn source_shapes_feed_metadata_and_native_staticness_without_ancestor_reinterpretation() {
        let parsed = parse(
            "class Outer { class Inner {} class Explicit { Explicit() {} } void local() { class OuterLocal {} } static void shape(String first, String... rest) {} Runnable anonymous = new Runnable() { int anonymousField; }; } \
             interface I { int field; Runnable interfaceAnonymous = new Runnable() { int bodyField; }; class Nested {} void method() { class InterfaceLocal {} } } \
             enum E { ONE { int enumField; } } record R(int value) {}",
        );

        assert!(metadata(&parsed, "static void shape").callable_is_static());
        assert_eq!(
            metadata(&parsed, "static void shape").callable_arity(),
            Some(CallableArity::new(1, 2, true))
        );
        assert!(metadata(&parsed, "int field").field_is_static());
        assert!(metadata(&parsed, "class Nested {").class_like_is_static());
        assert!(!metadata(&parsed, "class InterfaceLocal {").class_like_is_static());
        for field in ["int anonymousField", "int bodyField", "int enumField"] {
            assert!(!metadata(&parsed, field).field_is_static());
            assert!(!metadata(&parsed, field).field_is_final());
        }
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
