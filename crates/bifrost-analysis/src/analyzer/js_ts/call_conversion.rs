//! Bounded TypeScript actual-to-formal conversion proofs.
//!
//! This adapter answers a deliberately small question: does the syntax and
//! resolver evidence prove that one actual can be passed to one selected
//! formal? It does not choose declarations, infer overloads, or approximate the
//! TypeScript checker from rendered type text. Named types are resolved to one
//! indexed declaration identity, and structural comparison is limited to flat
//! property declarations whose member types are themselves proved.

use std::collections::HashSet;

use crate::analyzer::AnalyzerDefinitionLookup;
use crate::analyzer::IAnalyzer;
use crate::analyzer::Language;
use crate::analyzer::ProjectFile;
use crate::analyzer::js_ts::providers::resolve_js_ts_source;
use crate::analyzer::lexical_definitions::{LexicalBindingResolution, resolve_lexical_binding};
use crate::analyzer::usages::call_conversion::{
    ArgumentTypeConversion, CallArgumentConversionProver, ConversionKind, ConversionUnknown,
    ResolvedConversionType, TypeScriptPrimitive,
};
use brokk_bifrost_js_ts::providers::JsTsSource;
use brokk_bifrost_js_ts::syntax::{
    JsTsImportBinder, compute_import_binder, compute_import_binder_for_root, parse_js_ts_tree,
    static_property_name,
};
use brokk_bifrost_js_ts::ts_owners::{ts_named_type_candidates, ts_nodes_for_code_unit};
use tree_sitter::{Node, Tree};

const MAX_TYPE_DEPTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
enum TypeScriptType {
    Primitive(TypeScriptPrimitive),
    Declaration(crate::analyzer::CodeUnit),
}

impl TypeScriptType {
    fn resolved(&self) -> ResolvedConversionType {
        match self {
            Self::Primitive(primitive) => ResolvedConversionType::TypeScriptPrimitive(*primitive),
            Self::Declaration(unit) => ResolvedConversionType::Declaration(unit.clone()),
        }
    }
}

#[derive(Debug, Clone)]
struct ShapeField {
    name: String,
    ty: TypeScriptType,
}

#[derive(Debug, Clone, Default)]
struct ObjectShape {
    fields: Vec<ShapeField>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Assignability {
    Yes,
    No,
    Unknown,
}

/// Prove one TypeScript actual/formal pair from their source ASTs.
pub(super) fn prove_argument(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    actual: Node<'_>,
    source: &str,
    formal_file: &ProjectFile,
    formal: Node<'_>,
    formal_source: &str,
) -> Result<ArgumentTypeConversion, ConversionUnknown> {
    let actual_root = node_root(actual);
    let actual_imports = compute_import_binder_for_root(source, actual_root);
    let formal_imports = compute_import_binder_for_root(formal_source, node_root(formal));

    let Some(host) = resolve_js_ts_source(analyzer, Language::TypeScript) else {
        return Err(ConversionUnknown::UnresolvedSourceType);
    };
    let support = AnalyzerDefinitionLookup::new(analyzer, Language::TypeScript);
    let aliases = host.alias_resolver().as_ref();

    let source_type = actual_type(
        analyzer,
        host,
        &support,
        file,
        source,
        &actual_imports,
        aliases,
        actual,
    )?;
    let target_type = formal_type(
        analyzer,
        host,
        &support,
        formal_file,
        formal_source,
        &formal_imports,
        aliases,
        formal,
    )?;

    let mut seen = HashSet::new();
    let relation = assignable(analyzer, &source_type, &target_type, 0, &mut seen);
    let kind = match relation {
        Assignability::Yes if same_type_identity(&source_type, &target_type) => {
            ConversionKind::TypeScriptIdentity
        }
        Assignability::Yes => ConversionKind::TypeScriptStructuralAssignability,
        Assignability::No | Assignability::Unknown => {
            return Err(ConversionUnknown::UnsupportedConversion);
        }
    };
    Ok(ArgumentTypeConversion {
        source: source_type.resolved(),
        target: target_type.resolved(),
        kind,
    })
}

pub(crate) static CALL_ARGUMENT_CONVERSION_PROVER: TypescriptCallArgumentConversionProver =
    TypescriptCallArgumentConversionProver;

pub(crate) struct TypescriptCallArgumentConversionProver;

impl CallArgumentConversionProver for TypescriptCallArgumentConversionProver {
    fn validate_owner(&self, owner: Node<'_>) -> Result<(), ConversionUnknown> {
        let Some(parameters) = owner.child_by_field_name("parameters") else {
            return Ok(());
        };
        let mut cursor = parameters.walk();
        if parameters.named_children(&mut cursor).any(|parameter| {
            parameter
                .child_by_field_name("pattern")
                .is_some_and(|pattern| pattern.kind() == "this")
        }) {
            // An explicit compile-time receiver adds an applicability
            // constraint that ordinary actual/formal typing cannot prove.
            return Err(ConversionUnknown::SignatureApplicability);
        }
        Ok(())
    }

    fn prove_argument(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        actual: Node<'_>,
        source: &str,
        formal_file: &ProjectFile,
        formal: Node<'_>,
        formal_source: &str,
    ) -> Result<ArgumentTypeConversion, ConversionUnknown> {
        prove_argument(
            analyzer,
            file,
            actual,
            source,
            formal_file,
            formal,
            formal_source,
        )
    }
}

fn same_type_identity(source: &TypeScriptType, target: &TypeScriptType) -> bool {
    match (source, target) {
        (TypeScriptType::Primitive(left), TypeScriptType::Primitive(right)) => left == right,
        (TypeScriptType::Declaration(left), TypeScriptType::Declaration(right)) => {
            left.declaration_id() == right.declaration_id()
        }
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn actual_type(
    analyzer: &dyn IAnalyzer,
    host: &dyn JsTsSource,
    support: &AnalyzerDefinitionLookup<'_>,
    file: &ProjectFile,
    source: &str,
    imports: &JsTsImportBinder,
    aliases: &crate::analyzer::AliasResolver,
    mut actual: Node<'_>,
) -> Result<TypeScriptType, ConversionUnknown> {
    while actual.kind() == "parenthesized_expression" {
        actual = actual
            .named_child(0)
            .ok_or(ConversionUnknown::UnsupportedExpression)?;
    }
    let root = node_root(actual);
    if matches!(
        actual.kind(),
        "as_expression" | "satisfies_expression" | "type_assertion" | "non_null_expression"
    ) {
        return Err(ConversionUnknown::UnsupportedExpression);
    }
    match actual.kind() {
        "identifier" | "shorthand_property_identifier" => {
            let name = source
                .get(actual.byte_range())
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .ok_or(ConversionUnknown::UnresolvedSourceType)?;
            let Some(binding) = resolve_lexical_binding(
                Language::TypeScript,
                root,
                source,
                actual.start_byte(),
                actual.end_byte(),
                name,
            ) else {
                return Err(ConversionUnknown::UnresolvedSourceType);
            };
            let declaration = match binding {
                LexicalBindingResolution::Parameter(definition)
                | LexicalBindingResolution::OtherLocal(definition) => root
                    .named_descendant_for_byte_range(
                        definition.declaration_range.start_byte,
                        definition.declaration_range.end_byte,
                    )
                    .filter(|node| {
                        node.start_byte() == definition.declaration_range.start_byte
                            && node.end_byte() == definition.declaration_range.end_byte
                    })
                    .ok_or(ConversionUnknown::UnresolvedSourceType)?,
            };
            if has_anonymous_child(declaration, "?") {
                return Err(ConversionUnknown::UnsupportedConversion);
            }
            if let Some(type_node) = declaration.child_by_field_name("type") {
                return type_from_node(
                    analyzer, host, support, file, source, imports, aliases, type_node,
                );
            }
            // An unannotated local may be reassigned after this declaration;
            // its initializer is not a stable static type fact at the call.
            Err(ConversionUnknown::UnresolvedSourceType)
        }
        _ => Err(ConversionUnknown::UnsupportedExpression),
    }
}

#[allow(clippy::too_many_arguments)]
fn formal_type(
    analyzer: &dyn IAnalyzer,
    host: &dyn JsTsSource,
    support: &AnalyzerDefinitionLookup<'_>,
    file: &ProjectFile,
    source: &str,
    imports: &JsTsImportBinder,
    aliases: &crate::analyzer::AliasResolver,
    formal: Node<'_>,
) -> Result<TypeScriptType, ConversionUnknown> {
    if has_anonymous_child(formal, "?") {
        return Err(ConversionUnknown::UnsupportedConversion);
    }
    let type_node = formal
        .child_by_field_name("type")
        .ok_or(ConversionUnknown::UnresolvedTargetType)?;
    type_from_node(
        analyzer, host, support, file, source, imports, aliases, type_node,
    )
}

#[allow(clippy::too_many_arguments)]
fn type_from_node(
    analyzer: &dyn IAnalyzer,
    host: &dyn JsTsSource,
    support: &AnalyzerDefinitionLookup<'_>,
    file: &ProjectFile,
    source: &str,
    imports: &JsTsImportBinder,
    aliases: &crate::analyzer::AliasResolver,
    node: Node<'_>,
) -> Result<TypeScriptType, ConversionUnknown> {
    let node = unwrap_type_node(node).ok_or(ConversionUnknown::UnresolvedTargetType)?;
    if let Some(primitive) = primitive_annotation(node) {
        return Ok(TypeScriptType::Primitive(primitive));
    }
    if matches!(
        node.kind(),
        "generic_type"
            | "union_type"
            | "intersection_type"
            | "object_type"
            | "function_type"
            | "constructor_type"
            | "indexed_access_type"
            | "lookup_type"
            | "type_query"
            | "literal_type"
            | "predefined_type"
    ) {
        return Err(ConversionUnknown::UnsupportedConversion);
    }
    if !matches!(
        node.kind(),
        "type_identifier" | "nested_type_identifier" | "identifier"
    ) {
        return Err(ConversionUnknown::UnsupportedConversion);
    }
    let mut enclosing = node.parent();
    while let Some(owner) = enclosing {
        if owner.child_by_field_name("type_parameters").is_some() {
            return Err(ConversionUnknown::GenericSubstitution);
        }
        enclosing = owner.parent();
    }
    let candidates =
        ts_named_type_candidates(host, support, file, source, imports, aliases, node, false);
    let unit = unique_declaration(candidates).ok_or(ConversionUnknown::UnresolvedTargetType)?;
    match declaration_has_type_parameters(analyzer, &unit) {
        Some(false) => {}
        Some(true) => return Err(ConversionUnknown::GenericSubstitution),
        None => return Err(ConversionUnknown::UnresolvedTargetType),
    }
    Ok(TypeScriptType::Declaration(unit))
}

fn unwrap_type_node(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "type_annotation" | "parenthesized_type" | "readonly_type" => {
                node = node.named_child(0)?;
            }
            _ => return Some(node),
        }
    }
}

fn primitive_annotation(node: Node<'_>) -> Option<TypeScriptPrimitive> {
    if node.kind() != "predefined_type" {
        return None;
    }
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .filter(|child| !child.is_named())
        .find_map(|child| match child.kind() {
            "boolean" => Some(TypeScriptPrimitive::Boolean),
            "number" => Some(TypeScriptPrimitive::Number),
            "string" => Some(TypeScriptPrimitive::String),
            "bigint" => Some(TypeScriptPrimitive::BigInt),
            "symbol" => Some(TypeScriptPrimitive::Symbol),
            _ => None,
        })
}

fn unique_declaration(units: Vec<crate::analyzer::CodeUnit>) -> Option<crate::analyzer::CodeUnit> {
    let mut unique = Vec::new();
    for unit in units {
        if unique.iter().any(|existing: &crate::analyzer::CodeUnit| {
            existing.declaration_id() == unit.declaration_id()
        }) {
            continue;
        }
        unique.push(unit);
    }
    let [unit] = unique.as_slice() else {
        return None;
    };
    Some(unit.clone())
}

fn assignable(
    analyzer: &dyn IAnalyzer,
    source: &TypeScriptType,
    target: &TypeScriptType,
    depth: usize,
    seen: &mut HashSet<(String, String)>,
) -> Assignability {
    if same_type_identity(source, target) {
        return Assignability::Yes;
    }
    match (source, target) {
        (TypeScriptType::Primitive(_), TypeScriptType::Primitive(_)) => Assignability::No,
        (TypeScriptType::Primitive(_), TypeScriptType::Declaration(_))
        | (TypeScriptType::Declaration(_), TypeScriptType::Primitive(_)) => Assignability::No,
        (TypeScriptType::Declaration(source), TypeScriptType::Declaration(target)) => {
            if depth >= MAX_TYPE_DEPTH {
                return Assignability::Unknown;
            }
            let key = (
                source.declaration_id().to_string(),
                target.declaration_id().to_string(),
            );
            if !seen.insert(key.clone()) {
                return Assignability::Unknown;
            }
            let Some(source_shape) = declaration_shape(analyzer, source) else {
                return Assignability::Unknown;
            };
            let Some(target_shape) = declaration_shape(analyzer, target) else {
                return Assignability::Unknown;
            };
            let result = shape_assignable(analyzer, &source_shape, &target_shape, depth + 1, seen);
            seen.remove(&key);
            result
        }
    }
}

fn shape_assignable(
    analyzer: &dyn IAnalyzer,
    source: &ObjectShape,
    target: &ObjectShape,
    depth: usize,
    seen: &mut HashSet<(String, String)>,
) -> Assignability {
    for target_field in &target.fields {
        let Some(source_field) = source
            .fields
            .iter()
            .find(|field| field.name == target_field.name)
        else {
            return Assignability::Unknown;
        };
        match assignable(analyzer, &source_field.ty, &target_field.ty, depth, seen) {
            Assignability::Yes => {}
            Assignability::No => return Assignability::No,
            Assignability::Unknown => return Assignability::Unknown,
        }
    }
    Assignability::Yes
}

fn declaration_shape(
    analyzer: &dyn IAnalyzer,
    unit: &crate::analyzer::CodeUnit,
) -> Option<ObjectShape> {
    let source = analyzer.indexed_source(unit.source())?;
    let tree = parse_js_ts_tree(unit.source(), &source, Language::TypeScript)?;
    let nodes = ts_nodes_for_code_unit(analyzer, unit, tree.root_node());
    let [node] = nodes.as_slice() else {
        return None;
    };
    let declaration = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration")?
    } else {
        *node
    };
    if declaration.has_error() || declaration.is_missing() {
        return None;
    }
    let container = match declaration.kind() {
        "interface_declaration" => declaration.child_by_field_name("body")?,
        "type_alias_declaration" => declaration
            .child_by_field_name("value")
            .filter(|value| value.kind() == "object_type")?,
        _ => return None,
    };
    let mut shape = ObjectShape::default();
    let mut declaration_cursor = declaration.walk();
    if declaration
        .named_children(&mut declaration_cursor)
        .any(|child| child.kind() == "extends_type_clause")
    {
        return None;
    }
    let mut cursor = container.walk();
    for member in container.named_children(&mut cursor) {
        let property = match member.kind() {
            "property_signature" | "public_field_definition" => member,
            "method_signature"
            | "call_signature"
            | "construct_signature"
            | "abstract_method_signature"
            | "index_signature"
            | "method_definition" => {
                return None;
            }
            "comment" => continue,
            _ => return None,
        };
        if has_accessibility(property, "private")
            || has_accessibility(property, "protected")
            || has_anonymous_child(property, "static")
            || has_anonymous_child(property, "?")
        {
            return None;
        }
        let name = property
            .child_by_field_name("name")
            .and_then(|name| static_property_name(name, &source))
            .map(|(_, name)| name);
        let name = name?;
        if shape.fields.iter().any(|field| field.name == name) {
            return None;
        }
        let ty = property.child_by_field_name("type").and_then(|node| {
            type_from_node_for_shape(analyzer, unit.source(), &source, &tree, node)
        })?;
        shape.fields.push(ShapeField { name, ty });
    }
    Some(shape)
}

fn type_from_node_for_shape(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    node: Node<'_>,
) -> Option<TypeScriptType> {
    let imports = compute_import_binder(source, tree);
    let host = resolve_js_ts_source(analyzer, Language::TypeScript)?;
    let support = AnalyzerDefinitionLookup::new(analyzer, Language::TypeScript);
    let aliases = host.alias_resolver().as_ref();
    type_from_node(
        analyzer, host, &support, file, source, &imports, aliases, node,
    )
    .ok()
}

fn node_root(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        node = parent;
    }
    node
}

fn declaration_has_type_parameters(
    analyzer: &dyn IAnalyzer,
    unit: &crate::analyzer::CodeUnit,
) -> Option<bool> {
    let source = analyzer.indexed_source(unit.source())?;
    let tree = parse_js_ts_tree(unit.source(), &source, Language::TypeScript)?;
    let nodes = ts_nodes_for_code_unit(analyzer, unit, tree.root_node());
    let [node] = nodes.as_slice() else {
        return None;
    };
    let declaration = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration")?
    } else {
        *node
    };
    if declaration.has_error() || declaration.is_missing() {
        return None;
    }
    if declaration.kind() == "type_alias_declaration"
        && !declaration
            .child_by_field_name("value")
            .is_some_and(|value| value.kind() == "object_type")
    {
        return None;
    }
    Some(declaration.child_by_field_name("type_parameters").is_some())
}

fn has_anonymous_child(node: Node<'_>, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| !child.is_named() && child.kind() == kind)
}

fn has_accessibility(node: Node<'_>, expected: &str) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).any(|child| {
        child.kind() == "accessibility_modifier" && has_anonymous_child(child, expected)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_tree(source: &str) -> Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("TypeScript grammar");
        parser
            .parse(source, None)
            .expect("TypeScript source parses")
    }

    #[test]
    fn explicit_this_parameter_is_an_owner_applicability_constraint() {
        let tree = parse_tree("function take(this: string, value: string): void {}");
        let owner = tree.root_node().named_child(0).expect("function owner");
        assert_eq!(
            CALL_ARGUMENT_CONVERSION_PROVER.validate_owner(owner),
            Err(ConversionUnknown::SignatureApplicability)
        );
    }

    #[test]
    fn ordinary_typescript_owner_has_no_extra_applicability_constraint() {
        let tree = parse_tree("function take(value: string): void {}");
        let owner = tree.root_node().named_child(0).expect("function owner");
        assert_eq!(
            CALL_ARGUMENT_CONVERSION_PROVER.validate_owner(owner),
            Ok(())
        );
    }
}
