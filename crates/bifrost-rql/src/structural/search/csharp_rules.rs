// Closed C# structural relations used by the CodeQL parity lane.
//
// These relations select AST nodes first and use persisted declaration
// metadata for member modifiers and type shape. Source text is read only for
// values of already-selected identifiers, literals, and type nodes; syntax
// selection stays in tree-sitter nodes and fields.

use crate::analyzer::common::language_for_file;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, parse_tree_for_language_preprocessed,
    resolve_definition_batch_with_source,
};
use crate::analyzer::{IAnalyzer, Language, ProjectFile, Range};
use crate::query::CSharpRule;
use brokk_bifrost_analysis::analyzer::structural::lexical_environment::{
    BindingOfOutcome, EnvironmentFileResult, binding_of, environment_for_file,
};
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    csharp_integer_literal_value, declaration_modifier_words, declarator_initializer,
};
use brokk_bifrost_core::analyzer::structural::conditional_regions::Activation;
use brokk_bifrost_core::analyzer::structural::facts::IntegerLiteralValue;
use brokk_bifrost_core::analyzer::structural::occurrences::Namespace;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_core::analyzer::tree_walk::expression_target_node;
use tree_sitter::{Node, Tree};

use super::field_metadata::{FieldSite, field_sites};
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
    let Some((tree, preprocessor)) = parse_tree_for_language_preprocessed(file, Language::CSharp, source) else {
        return LanguageRuleMatches::default();
    };
    let fields = field_sites(analyzer, file);
    let mut undecided = Vec::new();
    let ranges = match rule {
        CSharpRule::StaticArray => {
            static_array_fields(analyzer, file, &tree, source, &fields, &mut undecided, &preprocessor.as_ref().map(|p| p.conditional_regions(source)).unwrap_or_default())
        }
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
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    tree: &Tree,
    source: &str,
    fields: &[FieldSite],
    undecided: &mut Vec<UndecidedSite>,
    regions: &brokk_bifrost_core::analyzer::structural::conditional_regions::ConditionalRegions,
) -> Vec<Range> {
    let environment = environment_for_file(analyzer, file);
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
            let Some(owner) = enclosing_type(declarator) else {
                continue;
            };
            if declaration_modifier_words(owner, source)
                .iter()
                .any(|word| word == "partial")
            {
                undecided.push(UndecidedSite::at(
                    node_range(declarator),
                    "a partial type can define the field in another file",
                ));
                continue;
            }
            let mut shapes = Vec::new();
            if let Some(value) = declarator_initializer(declarator) {
                shapes.push(expression_shape(value, source));
            }
            let mut uncertain = regions.has_uncertain_text(declarator.byte_range());
            for constructor in descendants(owner).into_iter().filter(|child| {
                child.kind() == "constructor_declaration" && enclosing_type(*child) == Some(owner)
            }) {
                if !declaration_modifier_words(constructor, source)
                    .iter()
                    .any(|word| word == "static")
                {
                    continue;
                }
                if regions.activation_at(constructor.start_byte()) == Activation::DecidedInactive {
                    continue;
                }
                // Omitted conditional text can contain a definition that is not in the tree.
                uncertain |= regions.has_uncertain_omission(constructor.byte_range());
                for definition in descendants(constructor) {
                    if regions.activation_at(definition.start_byte()) == Activation::DecidedInactive
                    {
                        continue;
                    }
                    if definition.kind() == "assignment_expression" {
                        if let Some(left) = definition.child_by_field_name("left") {
                            let target = field_target(
                                left,
                                declarator,
                                source,
                                &environment,
                                analyzer,
                                file,
                            );
                            uncertain |= target.is_none();
                            if target == Some(true) {
                                if regions.has_uncertain_text(definition.byte_range()) {
                                    uncertain = true;
                                    continue;
                                }
                                let simple = definition
                                    .child_by_field_name("operator")
                                    .is_some_and(|op| op.kind() == "=");
                                shapes.push(if simple {
                                    definition
                                        .child_by_field_name("right")
                                        .map_or(DefinitionShape::Disqualifies, |value| {
                                            expression_shape(value, source)
                                        })
                                } else {
                                    DefinitionShape::Disqualifies
                                });
                            }
                        }
                    } else if definition.kind() == "argument" {
                        let children = {
                            let mut cursor = definition.walk();
                            definition.children(&mut cursor).collect::<Vec<_>>()
                        };
                        if children
                            .iter()
                            .any(|child| matches!(child.kind(), "out" | "ref"))
                        {
                            for child in children.iter().filter(|child| child.is_named()) {
                                let target = field_target(
                                    *child,
                                    declarator,
                                    source,
                                    &environment,
                                    analyzer,
                                    file,
                                );
                                uncertain |= target.is_none();
                                if target == Some(true) {
                                    if regions.has_uncertain_text(definition.byte_range()) {
                                        uncertain = true;
                                    } else {
                                        shapes.push(DefinitionShape::Disqualifies);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if uncertain {
                undecided.push(UndecidedSite::at(
                    node_range(declarator),
                    "a field definition has an unproven binding or conditional activation",
                ));
            } else if shapes.contains(&DefinitionShape::Undecided) {
                undecided.push(UndecidedSite::at(
                    node_range(declarator),
                    "an array length may be a compile-time constant that is not folded",
                ));
            } else if shapes
                .iter()
                .all(|shape| *shape == DefinitionShape::Qualifies)
            {
                matches.push(node_range(declarator));
            }
        }
    }
    matches
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DefinitionShape {
    Qualifies,
    Disqualifies,
    Undecided,
}

fn field_target(
    node: Node<'_>,
    declarator: Node<'_>,
    source: &str,
    environment: &EnvironmentFileResult,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Option<bool> {
    let node = expression_target_node(node);
    let spelling = |node: Node<'_>| source[node.byte_range()].trim_start_matches('@');
    let name = spelling(declarator.child_by_field_name("name").expect("field name"));
    match node.kind() {
        "identifier" if spelling(node) == name => {
            match binding_of(environment, name, node.start_byte(), Some(Namespace::Value)) {
                BindingOfOutcome::NoBinding => Some(true),
                BindingOfOutcome::Incomplete(_) => None,
                _ => Some(false),
            }
        }
        "member_access_expression"
            if node
                .child_by_field_name("name")
                .is_some_and(|member| spelling(member) == name) =>
        {
            // Qualified targets use the resolver, including aliases, nested types,
            // and a qualifier shadowed by a local value.
            let member = node.child_by_field_name("name").expect("member name");
            let outcomes = resolve_definition_batch_with_source(
                analyzer,
                vec![DefinitionLookupRequest {
                    file: file.clone(),
                    line: None,
                    column: None,
                    start_byte: Some(member.start_byte()),
                    end_byte: Some(member.end_byte()),
                }],
                file.clone(),
                std::sync::Arc::from(source),
            );
            let outcome = outcomes.first()?;
            if outcome.status != DefinitionLookupStatus::Resolved || outcome.definitions.len() != 1
            {
                return None;
            }
            Some(
                outcome.definitions[0].is_field()
                    && outcome.definitions[0].source() == file
                    && analyzer
                        .ranges_of(&outcome.definitions[0])
                        .contains(&node_range(declarator)),
            )
        }
        _ => Some(false),
    }
}

fn expression_shape(root: Node<'_>, source: &str) -> DefinitionShape {
    let mut pending = vec![root];
    let mut undecided = false;
    while let Some(node) = pending.pop() {
        match node.kind() {
            "parenthesized_expression" => pending.extend(named_children(node)),
            "conditional_expression" => {
                pending.extend(node.child_by_field_name("consequence"));
                pending.extend(node.child_by_field_name("alternative"));
            }
            "null_literal" => {}
            "array_initializer_expression" | "initializer_expression" => {
                if list_shape(node) == DefinitionShape::Disqualifies {
                    return DefinitionShape::Disqualifies;
                }
            }
            "array_creation_expression" | "implicit_array_creation_expression" => {
                if let Some(initializer) = named_children(node).into_iter().find(|child| {
                    matches!(
                        child.kind(),
                        "array_initializer_expression" | "initializer_expression"
                    )
                }) {
                    if list_shape(initializer) == DefinitionShape::Disqualifies {
                        return DefinitionShape::Disqualifies;
                    }
                } else {
                    for rank in descendants(node)
                        .into_iter()
                        .filter(|child| child.kind() == "array_rank_specifier")
                    {
                        for size in named_children(rank) {
                            let size = expression_target_node(size);
                            match csharp_integer_literal_value(size, source)
                                .and_then(|value| value.decimal)
                            {
                                // A zero dimension makes the created array empty.
                                Some(value) if value == "0" => {
                                    return DefinitionShape::Disqualifies;
                                }
                                Some(_) => {}
                                None => {
                                    // CodeQL tests the absence of a length whose constant value is 0.
                                    // Calls and object creations cannot be C# constants, so they
                                    // qualify. Other expressions may fold to 0; until we fold
                                    // constants, those sites remain undecided.
                                    if !matches!(
                                        expression_target_node(size).kind(),
                                        "invocation_expression"
                                            | "object_creation_expression"
                                            | "implicit_object_creation_expression"
                                    ) {
                                        undecided = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => return DefinitionShape::Disqualifies,
        }
    }
    if undecided {
        DefinitionShape::Undecided
    } else {
        DefinitionShape::Qualifies
    }
}

fn list_shape(initializer: Node<'_>) -> DefinitionShape {
    if initializer.named_child_count() == 0 {
        // An initializer with no elements creates an empty array.
        DefinitionShape::Disqualifies
    } else {
        DefinitionShape::Qualifies
    }
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
            if constants
                .iter()
                .any(|constant| constant.owner_id == owner_id)
            {
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
