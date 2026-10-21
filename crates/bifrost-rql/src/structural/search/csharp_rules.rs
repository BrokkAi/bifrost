// Closed C# structural relations used by the CodeQL parity lane.
//
// These relations select AST nodes first and use persisted declaration
// metadata for member modifiers and type shape. Source text is read only for
// values of already-selected identifiers, literals, and type nodes; syntax
// selection stays in tree-sitter nodes and fields.

use crate::analyzer::common::language_for_file;
use crate::analyzer::usages::get_definition::parse_tree_for_language;
use crate::analyzer::{IAnalyzer, Language, ProjectFile, Range};
use crate::query::CSharpRule;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    csharp_integer_literal_value, declarator_initializer,
};
use brokk_bifrost_core::analyzer::structural::facts::IntegerLiteralValue;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use tree_sitter::{Node, Tree};

use super::field_metadata::{field_sites, FieldSite};
use super::language_rules::{LanguageRuleMatches, UndecidedSite};

/// Return the exact structural spans selected by one closed C# relation.
pub(super) fn matches_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    rule: CSharpRule,
) -> LanguageRuleMatches {
    if language_for_file(file) != Language::CSharp {
        return LanguageRuleMatches::default();
    }
    let Some(tree) = parse_tree_for_language(file, Language::CSharp, source) else {
        return LanguageRuleMatches::default();
    };
    let fields = field_sites(analyzer, file);
    let mut undecided = Vec::new();
    let ranges = match rule {
        CSharpRule::StaticArray => static_array_fields(&tree, source, &fields, &mut undecided),
        CSharpRule::UseNumberConstant => {
            number_constant_uses(&tree, source, &fields, &mut undecided)
        }
    };
    LanguageRuleMatches::decided(
        ranges,
        undecided,
        Language::CSharp.config_label(),
        rule.label(),
        file,
    )
}

fn static_array_fields(
    tree: &Tree,
    source: &str,
    fields: &[FieldSite],
    undecided: &mut Vec<UndecidedSite>,
) -> Vec<Range> {
    let mut matches = Vec::new();
    for node in descendants(tree.root_node()) {
        if node.kind() != "field_declaration" {
            continue;
        }
        for declarator in field_declarators(node) {
            let Some(site) = field_site_for(fields, declarator) else {
                continue;
            };
            if site.metadata.callable_declared_visibility() != Some(DeclaredVisibility::Public)
                || !site.metadata.field_is_static()
                || !site.metadata.field_is_final()
            {
                continue;
            }
            let Some(identity) = site.metadata.return_type_identity() else {
                undecided.push(UndecidedSite::at(
                    node_range(declarator),
                    "the declared field type is not recorded",
                ));
                continue;
            };
            if !identity.is_array() {
                continue;
            }
            if initializer_shape(declarator, source) != InitializerShape::Empty {
                matches.push(node_range(declarator));
            }
        }
    }
    matches
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InitializerShape {
    Empty,
    NonEmpty,
    Unknown,
}

fn initializer_shape(declarator: Node<'_>, source: &str) -> InitializerShape {
    let Some(initializer) = declarator_initializer(declarator) else {
        return InitializerShape::Unknown;
    };
    match initializer.kind() {
        "array_initializer_expression" | "initializer_expression" => list_shape(initializer),
        "implicit_array_creation_expression" => descendants(initializer)
            .into_iter()
            .find(|node| {
                matches!(
                    node.kind(),
                    "array_initializer_expression" | "initializer_expression"
                )
            })
            .map_or(InitializerShape::Unknown, |initializer| {
                list_shape(initializer)
            }),
        "array_creation_expression" => array_creation_shape(initializer, source),
        _ => InitializerShape::Unknown,
    }
}

fn array_creation_shape(node: Node<'_>, source: &str) -> InitializerShape {
    if let Some(initializer) = descendants(node).into_iter().find(|child| {
        matches!(
            child.kind(),
            "array_initializer_expression" | "initializer_expression"
        )
    }) {
        return list_shape(initializer);
    }
    if array_creation_is_empty(node, source) {
        InitializerShape::Empty
    } else {
        InitializerShape::Unknown
    }
}

fn list_shape(initializer: Node<'_>) -> InitializerShape {
    if initializer.named_child_count() == 0 {
        InitializerShape::Empty
    } else {
        InitializerShape::NonEmpty
    }
}

fn array_creation_is_empty(node: Node<'_>, source: &str) -> bool {
    descendants(node).into_iter().any(|rank| {
        rank.kind() == "array_rank_specifier"
            && rank.named_child_count() == 1
            && rank
                .named_child(0)
                .and_then(|size| csharp_integer_literal_value(size, source))
                .and_then(|value| value.decimal)
                .is_some_and(|value| value == "0")
    })
}

#[derive(Clone)]
struct ConstantSite {
    owner_id: usize,
    initializer_range: Range,
    value: IntegerLiteralValue,
}

fn number_constant_uses(
    tree: &Tree,
    source: &str,
    fields: &[FieldSite],
    undecided: &mut Vec<UndecidedSite>,
) -> Vec<Range> {
    let mut constants = Vec::new();
    for declaration in descendants(tree.root_node()) {
        if declaration.kind() != "field_declaration" {
            continue;
        }
        let owner_id = enclosing_type(declaration).map_or(0, |owner| owner.id());
        for declarator in field_declarators(declaration) {
            let Some(site) = field_site_for(fields, declarator) else {
                continue;
            };
            if !site.metadata.field_is_static()
                || !site.metadata.field_is_final()
                || !site.metadata.field_has_initializer()
            {
                continue;
            }
            let Some(initializer) = declarator_initializer(declarator) else {
                continue;
            };
            let Some(literal) = direct_integer_initializer(initializer) else {
                continue;
            };
            let Some(value) = csharp_integer_literal_value(literal, source) else {
                undecided.push(UndecidedSite::at(
                    node_range(literal),
                    "the constant's integer literal value is not decoded",
                ));
                continue;
            };
            constants.push(ConstantSite {
                owner_id,
                initializer_range: node_range(literal),
                value,
            });
        }
    }

    let mut matches = Vec::new();
    for literal in integer_literal_nodes(tree.root_node()) {
        let literal_range = node_range(literal);
        if constants
            .iter()
            .any(|constant| constant.initializer_range.contains(&literal_range))
        {
            continue;
        }
        let owner_id = enclosing_type(literal).map_or(0, |owner| owner.id());
        let Some(value) = csharp_integer_literal_value(literal, source) else {
            if constants.iter().any(|constant| constant.owner_id == owner_id) {
                undecided.push(UndecidedSite::at(
                    literal_range,
                    "the integer literal value is not decoded",
                ));
            }
            continue;
        };
        if constants
            .iter()
            .any(|constant| constant.owner_id == owner_id && constant.value == value)
        {
            matches.push(literal_range);
        }
    }
    matches
}

fn field_site_for<'a>(fields: &'a [FieldSite], declarator: Node<'_>) -> Option<&'a FieldSite> {
    let range = node_range(declarator);
    fields.iter().find(|site| site.range == range)
}

fn field_declarators(field: Node<'_>) -> Vec<Node<'_>> {
    let Some(declaration) = field.child_by_field_name("declaration").or_else(|| {
        named_children(field)
            .into_iter()
            .find(|node| node.kind() == "variable_declaration")
    }) else {
        return Vec::new();
    };
    named_children(declaration)
        .into_iter()
        .filter(|node| node.kind() == "variable_declarator")
        .collect()
}

fn integer_literal_nodes(root: Node<'_>) -> Vec<Node<'_>> {
    descendants(root)
        .into_iter()
        .filter(|node| {
            node.kind() == "integer_literal"
                && !node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "prefix_unary_expression")
        })
        .collect()
}

fn direct_integer_initializer(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "integer_literal" => Some(node),
        "prefix_unary_expression" => {
            let operator = node.child(0)?;
            (operator.kind() == "+").then(|| last_named_child(node))?
        }
        _ => None,
    }
}

fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).last()
}

fn enclosing_type(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "record_struct_declaration"
        ) {
            return Some(parent);
        }
        current = parent.parent();
    }
    None
}

fn descendants(root: Node<'_>) -> Vec<Node<'_>> {
    let mut pending = vec![root];
    let mut nodes = Vec::new();
    while let Some(node) = pending.pop() {
        nodes.push(node);
        pending.extend(named_children(node));
    }
    nodes
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row.saturating_add(1),
        end_line: node.end_position().row.saturating_add(1),
    }
}
