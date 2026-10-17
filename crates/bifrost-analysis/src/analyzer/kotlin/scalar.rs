//! Kotlin-declared scalar types for semantic and scalar-condition analysis.

use crate::analyzer::declared_scalar::{DeclaredScalarType, binding_nodes};
use crate::analyzer::semantic::{ProcedureHandle, ValueId};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::tree_walk::named_children;
use brokk_bifrost_jvm::kotlin::syntax::{
    KotlinScalarType, kotlin_binding_type_node, kotlin_declared_scalar_type,
    kotlin_literal_scalar_type,
};
use tree_sitter::Node;

/// The declared type of each Kotlin local or by-value formal whose type is a
/// supported non-nullable primitive, or whose initializer is a decimal integer
/// or Boolean literal. Delegated properties and members have no entry because
/// their access can dispatch to user code.
pub fn kotlin_declared_scalar_types(
    procedure: &ProcedureHandle,
    prepared: &PreparedSyntaxTree,
) -> Vec<(ValueId, DeclaredScalarType)> {
    let source = prepared.source();
    let from_type = |node: Node<'_>| match kotlin_declared_scalar_type(node, source)? {
        KotlinScalarType::Int => Some(DeclaredScalarType::Signed(32)),
        KotlinScalarType::Long => Some(DeclaredScalarType::Signed(64)),
        KotlinScalarType::Short => Some(DeclaredScalarType::Signed(16)),
        KotlinScalarType::Byte => Some(DeclaredScalarType::Signed(8)),
        KotlinScalarType::Boolean => Some(DeclaredScalarType::Boolean),
    };
    binding_nodes(procedure, prepared)
        .into_iter()
        .filter_map(|(value, parameter, node)| {
            if parameter {
                let declaration = match node.kind() {
                    "parameter" | "class_parameter" => node,
                    "simple_identifier" => node.parent()?,
                    _ => return None,
                };
                // A `val`/`var` class parameter declares a member. Its
                // receiver-less uses resolve through the property, so the
                // local/parameter scalar contract does not apply.
                if declaration.kind() == "class_parameter"
                    && declaration
                        .named_children(&mut declaration.walk())
                        .any(|child| child.kind() == "binding_pattern_kind")
                {
                    return None;
                }
                return Some((value, from_type(kotlin_binding_type_node(declaration)?)?));
            }
            let binding = match node.kind() {
                "variable_declaration" => node,
                "simple_identifier" => node.parent()?,
                _ => return None,
            };
            if binding.kind() != "variable_declaration" {
                return None;
            }
            let property = binding
                .parent()
                .filter(|parent| parent.kind() == "property_declaration")?;
            if named_children(property)
                .into_iter()
                .any(|child| child.kind() == "property_delegate")
            {
                return None;
            }
            let scalar = if let Some(written) = kotlin_binding_type_node(binding) {
                from_type(written)
            } else {
                kotlin_property_initializer(property)
                    .and_then(|initializer| kotlin_literal_scalar_type(initializer, source))
                    .map(|scalar| match scalar {
                        KotlinScalarType::Int => DeclaredScalarType::Signed(32),
                        KotlinScalarType::Long => DeclaredScalarType::Signed(64),
                        KotlinScalarType::Short => DeclaredScalarType::Signed(16),
                        KotlinScalarType::Byte => DeclaredScalarType::Signed(8),
                        KotlinScalarType::Boolean => DeclaredScalarType::Boolean,
                    })
            }?;
            Some((value, scalar))
        })
        .collect()
}

fn kotlin_property_initializer<'tree>(property: Node<'tree>) -> Option<Node<'tree>> {
    let mut seen_binding = false;
    for child in named_children(property) {
        match child.kind() {
            "modifiers" | "binding_pattern_kind" | "type_constraints" => continue,
            "variable_declaration" | "multi_variable_declaration" => {
                seen_binding = true;
            }
            "getter" | "setter" | "property_delegate" | "receiver_type" => continue,
            _ if seen_binding => return Some(child),
            _ => continue,
        }
    }
    None
}
