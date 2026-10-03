//! Declaration properties interpreted while the coordinated producer owns syntax.

use crate::declarations::{
    cpp_callable_identity_suffix, cpp_callable_is_structural_constructor,
    cpp_comparable_parameter_shapes, cpp_declarator_adds_indirection, node_text,
};
use crate::graph::resolver::{
    cpp_template_reference_arguments, cpp_type_name_components, declarator_name_node,
    declarator_names_function_type, declared_name_binding, structured_alias_type_target,
};
use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::cpp_facts::*;
use brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId;
use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;
use tree_sitter::Node;

pub(crate) fn base_specifier_from_node(
    node: Node<'_>,
    source: &str,
    is_virtual: bool,
) -> Option<CppBaseSpecifierFact> {
    let components = cpp_type_name_components(node, source)?;
    (!components.is_empty()).then_some(CppBaseSpecifierFact {
        absolute: node.child(0).is_some_and(|token| token.kind() == "::"),
        components,
        is_virtual,
    })
}

pub(crate) fn declaration_name<'tree>(
    node: Node<'tree>,
    unit: &CodeUnit,
    source: &str,
) -> Option<Node<'tree>> {
    if let Some(name) = node.child_by_field_name("name") {
        return crate::structural::declarator_name_node(name);
    }
    let mut cursor = node.walk();
    node.children_by_field_name("declarator", &mut cursor)
        .find_map(|declarator| {
            let name = crate::structural::declarator_name_node(declarator)?;
            (node_text(name, source) == unit.identifier()).then_some(name)
        })
}

/// Capture the structured type properties of one field declaration while its
/// declaration AST is still available.
pub(crate) fn capture_field_type(
    node: Node<'_>,
    field_name: &str,
    source: &str,
) -> (Option<CppDeclaredFieldTypeFact>, bool) {
    if let Some(recovered) = crate::declarations::recovered_pyobject_head_field(node, source)
        && node_text(recovered.name, source) == field_name
    {
        return (
            Some(CppDeclaredFieldTypeFact {
                type_text: node_text(recovered.type_node, source).to_owned(),
                indirection: recovered.pointer_depth(),
                binds_indirectly: recovered.pointer_depth() > 0,
                template_arguments: None,
            }),
            false,
        );
    }
    let Some(type_node) = node.child_by_field_name("type") else {
        return (None, false);
    };
    let mut cursor = node.walk();
    let declarator = node
        .children_by_field_name("declarator", &mut cursor)
        .find(|declarator| {
            crate::structural::declarator_name_node(*declarator)
                .is_some_and(|name| node_text(name, source) == field_name)
        });
    let names_function_type = declarator.is_some_and(declarator_names_function_type);
    let field_type = declared_name_binding(node, type_node, field_name, source).map(|binding| {
        let ty = if matches!(
            type_node.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) {
            type_node.child_by_field_name("name")
        } else {
            Some(type_node)
        };
        CppDeclaredFieldTypeFact {
            type_text: ty.map_or_else(
                || field_name.to_owned(),
                |ty| node_text(ty, source).to_owned(),
            ),
            indirection: binding.pointer_depth,
            binds_indirectly: binding.indirect,
            template_arguments: ty.and_then(|ty| cpp_template_reference_arguments(ty, source)),
        }
    });
    (field_type, names_function_type)
}

pub(crate) fn capture_declaration(
    declaration: SourceDeclarationId,
    node: Node<'_>,
    unit: &CodeUnit,
    source: &str,
    ancestry: &ParentIndex<'_>,
) -> CppDeclarationSourceFact {
    let mut fact = CppDeclarationSourceFact::new(declaration);
    if matches!(node.kind(), "alias_declaration" | "type_definition")
        && crate::graph::resolver::alias_has_visible_file_scope(node)
        && let Some(name) = declaration_name(node, unit, source)
        && let Some(name) =
            crate::graph::resolver::normalize_reference_name(node_text(name, source))
        && let Some(target) = node.child_by_field_name("type")
        && let Some(target) =
            crate::graph::resolver::normalize_reference_name(node_text(target, source))
    {
        fact.file_scope_alias = Some(CppFileScopeAliasFact {
            name,
            target,
            namespace: crate::graph::resolver::enclosing_namespace_context(node, source),
        });
    }
    let mut owners = Vec::new();
    let mut current = ancestry.parent(node);
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "namespace_definition"
                | "class_specifier"
                | "struct_specifier"
                | "union_specifier"
                | "enum_specifier"
        ) && let Some(name) = parent.child_by_field_name("name")
        {
            owners.push(node_text(name, source).to_owned());
        }
        current = ancestry.parent(parent);
    }
    owners.reverse();
    owners.push(unit.identifier().to_owned());
    fact.lexical_path = owners;
    if matches!(
        node.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
    ) {
        fact.class_strength = if node.child_by_field_name("body").is_some() {
            CppClassDeclarationStrength::Full
        } else {
            CppClassDeclarationStrength::Forward
        };
        if node.kind() == "enum_specifier" {
            let mut cursor = node.walk();
            fact.enum_kind = if node
                .children(&mut cursor)
                .any(|child| matches!(child.kind(), "class" | "struct"))
            {
                CppEnumOwnerKind::Scoped
            } else {
                CppEnumOwnerKind::Unscoped
            };
        }
        let mut cursor = node.walk();
        for base_clause in node
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "base_class_clause")
        {
            let mut is_virtual = false;
            let mut cursor = base_clause.walk();
            for child in base_clause.children(&mut cursor) {
                match child.kind() {
                    "," => is_virtual = false,
                    "virtual" => is_virtual = true,
                    "type_identifier"
                    | "qualified_identifier"
                    | "scoped_type_identifier"
                    | "template_type" => {
                        if let Some(base) = base_specifier_from_node(child, source, is_virtual) {
                            fact.bases.push(base);
                        }
                        is_virtual = false;
                    }
                    _ => {}
                }
            }
        }
    }
    let mut cursor = node.walk();
    let declarator = node
        .children_by_field_name("declarator", &mut cursor)
        .find(|declarator| {
            crate::structural::declarator_name_node(*declarator)
                .is_some_and(|name| node_text(name, source) == unit.identifier())
        });
    if unit.is_function() {
        let callable = if node.kind() == "function_declarator" {
            Some(node)
        } else {
            node.child_by_field_name("declarator")
        };
        if let Some(declarator) = callable {
            if let Some(name) = declarator_name_node(declarator)
                && let Some(mut components) = cpp_type_name_components(name, source)
            {
                components.pop();
                fact.written_owner = components;
            }
            let mut chain = Some(declarator);
            while let Some(current) = chain {
                if current.kind() == "function_declarator" {
                    fact.callable_comparable_shapes =
                        Some(cpp_comparable_parameter_shapes(current, source, ancestry));
                    fact.callable_identity_suffix = cpp_callable_identity_suffix(current, source);
                    fact.callable_is_constructor =
                        cpp_callable_is_structural_constructor(current, source, ancestry);
                    fact.callable_is_deduction_guide =
                        cpp_callable_is_deduction_guide(node, current, unit, source);
                    fact.callable_is_template = ancestry.parent(node).is_some_and(|parent| {
                        parent.kind() == "template_declaration"
                            && parent
                                .named_child(parent.named_child_count().saturating_sub(1))
                                .is_some_and(|declaration| declaration.id() == node.id())
                    });
                    // Only identity qualifiers participate in overload hiding.
                    // The declarator can also contain override/final specifiers.
                    fact.trailing_qualifiers =
                        fact.callable_identity_suffix.clone().unwrap_or_default();
                    break;
                }
                chain = current.child_by_field_name("declarator");
            }
        }
    }
    if unit.is_field() {
        let (field_type, names_function_type) = capture_field_type(node, unit.identifier(), source);
        fact.field_type = field_type;
        fact.names_function_type = names_function_type;
    }
    let alias_type = if matches!(node.kind(), "alias_declaration" | "type_definition") {
        node.child_by_field_name("type")
    } else if unit.is_class() {
        crate::declarations::recovered_alias_type_node(node, unit.identifier(), source)
    } else {
        None
    };
    if let Some(alias_type) = alias_type {
        let alias_declarator = if node.kind() == "type_definition" {
            declarator
        } else {
            alias_type.child_by_field_name("declarator")
        };
        fact.names_function_type = alias_declarator.is_some_and(declarator_names_function_type);
        fact.adds_indirection = alias_declarator.is_some_and(cpp_declarator_adds_indirection);
        if !fact.names_function_type {
            fact.alias_target = structured_alias_type_target(alias_type, source);
            let mut target = alias_type;
            while target.kind() == "type_descriptor" {
                let Some(inner) = target.child_by_field_name("type") else {
                    break;
                };
                target = inner;
            }
            if matches!(
                target.kind(),
                "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
            ) && let Some(name) = target.child_by_field_name("name")
            {
                target = name;
            }
            fact.alias_target_text = Some(node_text(target, source).to_owned());
        }
    }
    fact
}

fn cpp_callable_is_deduction_guide(
    declaration: Node<'_>,
    function_declarator: Node<'_>,
    unit: &CodeUnit,
    source: &str,
) -> bool {
    if declaration.kind() != "declaration"
        || declaration.child_by_field_name("type").is_some()
        || function_declarator.kind() != "function_declarator"
    {
        return false;
    }
    let mut cursor = function_declarator.walk();
    function_declarator
        .named_children(&mut cursor)
        .any(|child| child.kind() == "trailing_return_type")
        && declarator_name_node(function_declarator)
            .is_some_and(|name| node_text(name, source) == unit.identifier())
}

/// One mounted, generation-selected canonical declaration family.
#[derive(Debug, Clone)]
pub struct CppFileSourceFacts {
    pub source: brokk_bifrost_core::analyzer::source_facts::SourceFactRows,
    pub facts: CppSourceFacts,
    pub declaration_units: brokk_bifrost_core::hash::HashMap<SourceDeclarationId, Vec<CodeUnit>>,
    by_unit: brokk_bifrost_core::hash::HashMap<CodeUnit, Vec<usize>>,
}

impl CppFileSourceFacts {
    pub fn new(
        source: brokk_bifrost_core::analyzer::source_facts::SourceFactRows,
        facts: CppSourceFacts,
        declaration_units: brokk_bifrost_core::hash::HashMap<SourceDeclarationId, Vec<CodeUnit>>,
    ) -> Self {
        assert!(
            facts.valid_links(&source),
            "invalid C++ canonical source links"
        );
        let mut by_unit: brokk_bifrost_core::hash::HashMap<_, Vec<_>> = Default::default();
        for (index, fact) in facts.declarations.iter().enumerate() {
            if let Some(units) = declaration_units.get(&fact.declaration) {
                for unit in units {
                    by_unit.entry(unit.clone()).or_default().push(index);
                }
            }
        }
        Self {
            source,
            facts,
            declaration_units,
            by_unit,
        }
    }

    pub fn for_unit(&self, unit: &CodeUnit) -> impl Iterator<Item = &CppDeclarationSourceFact> {
        self.by_unit
            .get(unit)
            .into_iter()
            .flatten()
            .map(|index| &self.facts.declarations[*index])
    }

    pub fn estimated_retained_bytes(&self) -> usize {
        self.source.estimated_bytes()
            + self.facts.estimated_retained_bytes()
            + self
                .declaration_units
                .values()
                .map(|units| units.capacity() * std::mem::size_of::<CodeUnit>())
                .sum::<usize>()
            + self
                .by_unit
                .values()
                .map(|indices| indices.capacity() * std::mem::size_of::<usize>())
                .sum::<usize>()
    }
}

/// One source-backed navigation alternative for a mounted declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CppNavigationOccurrence {
    pub range: brokk_bifrost_core::analyzer::Range,
    pub role: CppOccurrenceRole,
    pub conditional_family: Option<(usize, usize)>,
}

/// Canonical declaration context with IDs resolved in its own dialect arena.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppDeclarationOccurrence {
    pub fact: CppDeclarationSourceFact,
    pub range: brokk_bifrost_core::analyzer::Range,
    pub name_range: Option<brokk_bifrost_core::analyzer::Range>,
    pub exhaustive_family: Option<(usize, usize)>,
    pub displaced_namespace_closing_brace: Option<usize>,
}

impl CppFileSourceFacts {
    pub fn declaration_occurrences(&self, unit: &CodeUnit) -> Vec<CppDeclarationOccurrence> {
        self.for_unit(unit)
            .map(|fact| {
                let declaration = self.source.declaration(fact.declaration);
                CppDeclarationOccurrence {
                    range: self.source.occurrence(declaration.occurrence).range,
                    name_range: declaration.name.map(|id| self.source.occurrence(id).range),
                    exhaustive_family: fact.exhaustive_conditional_family.map(|id| {
                        let range = self.source.occurrence(id).range;
                        (range.start_byte, range.end_byte)
                    }),
                    displaced_namespace_closing_brace: fact
                        .displaced_namespace_closing_brace
                        .map(|id| self.source.occurrence(id).range.start_byte),
                    fact: fact.clone(),
                }
            })
            .collect()
    }
}
