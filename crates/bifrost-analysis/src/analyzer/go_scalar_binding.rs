//! Numeric types for Go formal parameters and locals.
//!
//! Like [`super::java_integral_parameter`], this joins one parameter or local
//! value's exact source mapping to its declaration and reads the declared
//! type, so the scalar solver can store each binding's facts in Go's
//! representation. A short variable declaration or an untyped `var` takes
//! the default type of an integer, rune or Boolean literal initializer. Every
//! other binding has no entry; the caller keeps no numeric fact for it,
//! because a Go integer's width decides where its arithmetic wraps.
//!
//! `int`, `uint` and `uintptr` are read as 64 bits wide, their size on every
//! 64-bit target. Predeclared type names are read as the predeclared types:
//! a program that redeclares `int` is not supported, as the Go lowering does
//! not support one that redeclares `true`.

use crate::analyzer::semantic::lowering::children_by_field_name;
use crate::analyzer::semantic::{ProcedureHandle, SemanticValueKind, SourceMappingKind, ValueId};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use tree_sitter::Node;

/// A Go scalar type that the scalar solver models. Floating-point types are
/// absent: the Go lowering folds `!(f < c)` into `f >= c`, which a NaN
/// operand falsifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoScalarType {
    Signed(u16),
    Unsigned(u16),
    Boolean,
}

impl GoScalarType {
    fn from_type(source: &str, type_node: Node<'_>) -> Option<Self> {
        if type_node.kind() != "type_identifier" || type_node.has_error() {
            return None;
        }
        match source.get(type_node.byte_range())? {
            "int8" => Some(Self::Signed(8)),
            "int16" => Some(Self::Signed(16)),
            "int32" | "rune" => Some(Self::Signed(32)),
            "int64" | "int" => Some(Self::Signed(64)),
            "uint8" | "byte" => Some(Self::Unsigned(8)),
            "uint16" => Some(Self::Unsigned(16)),
            "uint32" => Some(Self::Unsigned(32)),
            "uint64" | "uint" | "uintptr" => Some(Self::Unsigned(64)),
            "bool" => Some(Self::Boolean),
            _ => None,
        }
    }

    /// The default type of an untyped constant initializer.
    fn of_initializer(node: Node<'_>) -> Option<Self> {
        match node.kind() {
            "int_literal" => Some(Self::Signed(64)),
            "rune_literal" => Some(Self::Signed(32)),
            "true" | "false" => Some(Self::Boolean),
            "unary_expression" => {
                let operator = node.child_by_field_name("operator")?;
                let operand = node.child_by_field_name("operand")?;
                (operator.kind() == "-" && operand.kind() == "int_literal")
                    .then_some(Self::Signed(64))
            }
            _ => None,
        }
    }
}

/// Return the type of each formal parameter and local of the procedure whose
/// declaration states a modeled scalar type or initializes it from a literal.
/// `prepared` must be the same source revision as the semantic artifact;
/// callers acquire them from one analyzer snapshot.
///
/// A parameter or local value maps exactly to its name identifier. A
/// parameter's `parameter_declaration` and a `var_spec` state the type. A
/// `var_spec` without a type, or a `short_var_declaration`, has a literal at
/// the name's position in its value list. Variadic parameters, receivers,
/// multi-value initializers, named and floating types, and recovered syntax
/// have no entry.
pub fn go_scalar_binding_types(
    procedure: &ProcedureHandle,
    prepared: &PreparedSyntaxTree,
) -> Vec<(ValueId, GoScalarType)> {
    let semantics = procedure.semantics();
    let procedure_mapping = semantics
        .source_mapping(semantics.source())
        .expect("validated procedure owns its source mapping");
    if procedure_mapping.kind != SourceMappingKind::Exact {
        return Vec::new();
    }
    let span = procedure_mapping.locator.anchor().span();
    let Some(callable) = prepared
        .tree()
        .root_node()
        .descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
        .filter(|callable| {
            callable.start_byte() == span.start_byte() as usize
                && callable.end_byte() == span.end_byte() as usize
                && !callable.has_error()
        })
    else {
        return Vec::new();
    };
    let source = prepared.source();
    semantics
        .values()
        .iter()
        .filter_map(|value| {
            let parameter = match value.kind {
                SemanticValueKind::Parameter { .. } => true,
                SemanticValueKind::Local => false,
                _ => return None,
            };
            let mapping = semantics
                .source_mapping(value.source)
                .expect("validated value owns its source mapping");
            if mapping.kind != SourceMappingKind::Exact {
                return None;
            }
            let span = mapping.locator.anchor().span();
            let (start, end) = (span.start_byte() as usize, span.end_byte() as usize);
            let name = callable.named_descendant_for_byte_range(start, end)?;
            if name.kind() != "identifier" || name.start_byte() != start || name.end_byte() != end {
                return None;
            }
            let declaration = name.parent()?;
            if declaration.has_error() {
                return None;
            }
            let scalar_type = match (parameter, declaration.kind()) {
                (true, "parameter_declaration") => {
                    GoScalarType::from_type(source, declaration.child_by_field_name("type")?)
                }
                (false, "var_spec") => match declaration.child_by_field_name("type") {
                    Some(type_node) => GoScalarType::from_type(source, type_node),
                    None => {
                        let names = children_by_field_name(declaration, "name");
                        let index = names.iter().position(|candidate| *candidate == name)?;
                        initializer_type(
                            names.len(),
                            index,
                            declaration.child_by_field_name("value")?,
                        )
                    }
                },
                (false, "expression_list") => {
                    let statement = declaration.parent()?;
                    if statement.kind() != "short_var_declaration"
                        || statement.child_by_field_name("left") != Some(declaration)
                    {
                        return None;
                    }
                    let mut cursor = declaration.walk();
                    let names = declaration.named_children(&mut cursor).collect::<Vec<_>>();
                    let index = names.iter().position(|candidate| *candidate == name)?;
                    initializer_type(names.len(), index, statement.child_by_field_name("right")?)
                }
                _ => None,
            }?;
            Some((value.id, scalar_type))
        })
        .collect()
}

/// The literal default type of the initializer at `index`, when the value
/// list assigns exactly one value to each of `count` names.
fn initializer_type(count: usize, index: usize, values: Node<'_>) -> Option<GoScalarType> {
    if values.kind() != "expression_list" || values.named_child_count() != count {
        return None;
    }
    GoScalarType::of_initializer(values.named_child(index)?)
}
