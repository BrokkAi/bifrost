//! Declared scalar types for Rust, Go, C#, Kotlin and Scala formal parameters and locals.
//!
//! Like [`super::java_integral_parameter`], this joins one parameter or local
//! value's exact source mapping to its declaration and reads the declared
//! type, so the scalar solver can store each binding's facts in the
//! language's representation. A local without a written type takes the
//! default type of an integer or Boolean literal initializer. Every other
//! binding has no entry; the caller keeps no numeric fact for it, because an
//! integer's width decides where its arithmetic wraps.
//!
//! Floating-point types have no entry: a NaN operand falsifies both `f < c`
//! and its negation, which the Go lowering folds into `f >= c`.

use crate::analyzer::semantic::lowering::children_by_field_name;
use crate::analyzer::semantic::{
    ProcedureHandle, SemanticRole, SemanticValueKind, SourceMappingKind, ValueId,
};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use tree_sitter::Node;

/// A scalar type that the scalar solver models.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclaredScalarType {
    Signed(u16),
    Unsigned(u16),
    Boolean,
}

/// Each parameter and local value of the procedure, whether it is a
/// parameter, and the syntax node its source mapping names exactly.
#[doc(hidden)]
pub fn binding_nodes<'tree>(
    procedure: &ProcedureHandle,
    prepared: &'tree PreparedSyntaxTree,
) -> Vec<(ValueId, bool, Node<'tree>)> {
    let semantics = procedure.semantics();
    let procedure_mapping = semantics
        .source_mappings()
        .iter()
        .find(|mapping| {
            mapping.kind == SourceMappingKind::Exact
                && mapping.locator.role() == SemanticRole::SourceMapping
        })
        .or_else(|| semantics.source_mapping(semantics.source()))
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
            let node = callable.named_descendant_for_byte_range(start, end)?;
            (node.start_byte() == start && node.end_byte() == end && !node.has_error())
                .then_some((value.id, parameter, node))
        })
        .collect()
}

/// The declared type of each Go formal parameter and local whose declaration
/// states a modeled type or initializes it from a literal. `prepared` must be
/// the same source revision as the semantic artifact; callers acquire them
/// from one analyzer snapshot.
///
/// A parameter or local value maps exactly to its name identifier. A
/// parameter's `parameter_declaration` and a `var_spec` state the type. A
/// `var_spec` without a type, or a `short_var_declaration`, has a literal at
/// the name's position in its value list. Variadic parameters, receivers,
/// multi-value initializers, named and floating types, and recovered syntax
/// have no entry.
///
/// `int`, `uint` and `uintptr` are read as 64 bits wide, their size on every
/// 64-bit target. Predeclared type names are read as the predeclared types:
/// a program that redeclares `int` is not supported, as the Go lowering does
/// not support one that redeclares `true`.
pub fn go_declared_scalar_types(
    procedure: &ProcedureHandle,
    prepared: &PreparedSyntaxTree,
) -> Vec<(ValueId, DeclaredScalarType)> {
    let source = prepared.source();
    let from_type = |type_node: Node<'_>| {
        if type_node.kind() != "type_identifier" {
            return None;
        }
        match source.get(type_node.byte_range())? {
            "int8" => Some(DeclaredScalarType::Signed(8)),
            "int16" => Some(DeclaredScalarType::Signed(16)),
            "int32" | "rune" => Some(DeclaredScalarType::Signed(32)),
            "int64" | "int" => Some(DeclaredScalarType::Signed(64)),
            "uint8" | "byte" => Some(DeclaredScalarType::Unsigned(8)),
            "uint16" => Some(DeclaredScalarType::Unsigned(16)),
            "uint32" => Some(DeclaredScalarType::Unsigned(32)),
            "uint64" | "uint" | "uintptr" => Some(DeclaredScalarType::Unsigned(64)),
            "bool" => Some(DeclaredScalarType::Boolean),
            _ => None,
        }
    };
    // The default type of an untyped constant initializer.
    let of_initializer = |node: Node<'_>| match node.kind() {
        "int_literal" => Some(DeclaredScalarType::Signed(64)),
        "rune_literal" => Some(DeclaredScalarType::Signed(32)),
        "true" | "false" => Some(DeclaredScalarType::Boolean),
        "unary_expression" => {
            let operator = node.child_by_field_name("operator")?;
            let operand = node.child_by_field_name("operand")?;
            (operator.kind() == "-" && operand.kind() == "int_literal")
                .then_some(DeclaredScalarType::Signed(64))
        }
        _ => None,
    };
    // The literal default type of the initializer at `index`, when the value
    // list assigns exactly one value to each of `count` names.
    let initializer_type = |count: usize, index: usize, values: Node<'_>| {
        if values.kind() != "expression_list" || values.named_child_count() != count {
            return None;
        }
        of_initializer(values.named_child(index)?)
    };
    binding_nodes(procedure, prepared)
        .into_iter()
        .filter_map(|(value, parameter, name)| {
            if name.kind() != "identifier" {
                return None;
            }
            let declaration = name.parent()?;
            if declaration.has_error() {
                return None;
            }
            let scalar_type = match (parameter, declaration.kind()) {
                (true, "parameter_declaration") => {
                    from_type(declaration.child_by_field_name("type")?)
                }
                (false, "var_spec") => match declaration.child_by_field_name("type") {
                    Some(type_node) => from_type(type_node),
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
            Some((value, scalar_type))
        })
        .collect()
}

/// The declared type of each C# by-value formal parameter and local whose
/// declaration names a predefined integral type or `bool`, or a `var` local
/// initialized from a decimal integer or Boolean literal. `prepared` must be
/// the same source revision as the semantic artifact.
///
/// A parameter value maps exactly to its `parameter`; `ref`, `out`, `in`,
/// `params` and `this` parameters alias or wrap other storage and have no
/// entry. A local value maps exactly to the `name` identifier of its
/// `variable_declarator`, whose `variable_declaration` states the type.
/// `nint`/`nuint` have a platform width; nullable, floating, `decimal` and
/// user types have no entry either.
pub fn csharp_declared_scalar_types(
    procedure: &ProcedureHandle,
    prepared: &PreparedSyntaxTree,
) -> Vec<(ValueId, DeclaredScalarType)> {
    let source = prepared.source();
    let from_type = |type_node: Node<'_>| {
        if type_node.kind() != "predefined_type" {
            return None;
        }
        match source.get(type_node.byte_range())? {
            "sbyte" => Some(DeclaredScalarType::Signed(8)),
            "byte" => Some(DeclaredScalarType::Unsigned(8)),
            "short" => Some(DeclaredScalarType::Signed(16)),
            "ushort" | "char" => Some(DeclaredScalarType::Unsigned(16)),
            "int" => Some(DeclaredScalarType::Signed(32)),
            "uint" => Some(DeclaredScalarType::Unsigned(32)),
            "long" => Some(DeclaredScalarType::Signed(64)),
            "ulong" => Some(DeclaredScalarType::Unsigned(64)),
            "bool" => Some(DeclaredScalarType::Boolean),
            _ => None,
        }
    };
    // The type of a `var` local's literal initializer: a decimal integer
    // literal without a suffix takes the first of `int`, `uint`, `long` and
    // `ulong` that holds its value.
    let of_initializer = |node: Node<'_>| match node.kind() {
        "integer_literal" => {
            let value = source.get(node.byte_range())?.parse::<u64>().ok()?;
            Some(if value <= i32::MAX as u64 {
                DeclaredScalarType::Signed(32)
            } else if value <= u32::MAX as u64 {
                DeclaredScalarType::Unsigned(32)
            } else if value <= i64::MAX as u64 {
                DeclaredScalarType::Signed(64)
            } else {
                DeclaredScalarType::Unsigned(64)
            })
        }
        "boolean_literal" => Some(DeclaredScalarType::Boolean),
        _ => None,
    };
    binding_nodes(procedure, prepared)
        .into_iter()
        .filter_map(|(value, parameter, node)| {
            let scalar_type = if parameter {
                if node.kind() != "parameter" {
                    return None;
                }
                let mut cursor = node.walk();
                if node.children(&mut cursor).any(|child| {
                    child.kind() == "modifier"
                        || matches!(child.kind(), "ref" | "out" | "in" | "params" | "this")
                }) {
                    return None;
                }
                from_type(node.child_by_field_name("type")?)
            } else {
                let declarator = node.parent()?;
                if node.kind() != "identifier"
                    || declarator.kind() != "variable_declarator"
                    || declarator.child_by_field_name("name") != Some(node)
                {
                    return None;
                }
                let declaration = declarator.parent()?;
                if declaration.kind() != "variable_declaration" || declaration.has_error() {
                    return None;
                }
                let type_node = declaration.child_by_field_name("type")?;
                if type_node.kind() == "implicit_type" {
                    // The grammar spells the initializer as the named child
                    // after the name, possibly inside an `equals_value_clause`.
                    let mut cursor = declarator.walk();
                    let initializer = declarator
                        .named_children(&mut cursor)
                        .find(|child| child.start_byte() > node.end_byte())?;
                    let initializer = if initializer.kind() == "equals_value_clause" {
                        initializer.named_child(0)?
                    } else {
                        initializer
                    };
                    of_initializer(initializer)
                } else {
                    from_type(type_node)
                }
            }?;
            Some((value, scalar_type))
        })
        .collect()
}

#[doc(hidden)]
pub fn rust_scalar_type_from_type(source: &str, type_node: Node<'_>) -> Option<DeclaredScalarType> {
    if type_node.kind() != "primitive_type" {
        return None;
    }
    match source.get(type_node.byte_range())? {
        "i8" => Some(DeclaredScalarType::Signed(8)),
        "i16" => Some(DeclaredScalarType::Signed(16)),
        "i32" => Some(DeclaredScalarType::Signed(32)),
        "i64" => Some(DeclaredScalarType::Signed(64)),
        "i128" => Some(DeclaredScalarType::Signed(128)),
        "isize" => Some(DeclaredScalarType::Signed(usize::BITS as u16)),
        "u8" => Some(DeclaredScalarType::Unsigned(8)),
        "u16" => Some(DeclaredScalarType::Unsigned(16)),
        "u32" => Some(DeclaredScalarType::Unsigned(32)),
        "u64" => Some(DeclaredScalarType::Unsigned(64)),
        "u128" => Some(DeclaredScalarType::Unsigned(128)),
        "usize" => Some(DeclaredScalarType::Unsigned(usize::BITS as u16)),
        "bool" => Some(DeclaredScalarType::Boolean),
        _ => None,
    }
}

#[doc(hidden)]
pub fn rust_scalar_type_from_literal(source: &str, node: Node<'_>) -> Option<DeclaredScalarType> {
    match node.kind() {
        "boolean_literal" | "true" | "false" => Some(DeclaredScalarType::Boolean),
        "integer_literal" => {
            let text = source.get(node.byte_range())?;
            let (digits, scalar_type) = if let Some(digits) = text.strip_suffix("isize") {
                (digits, DeclaredScalarType::Signed(usize::BITS as u16))
            } else if let Some(digits) = text.strip_suffix("usize") {
                (digits, DeclaredScalarType::Unsigned(usize::BITS as u16))
            } else {
                let suffix = [
                    ("u128", DeclaredScalarType::Unsigned(128)),
                    ("i128", DeclaredScalarType::Signed(128)),
                    ("u64", DeclaredScalarType::Unsigned(64)),
                    ("i64", DeclaredScalarType::Signed(64)),
                    ("u32", DeclaredScalarType::Unsigned(32)),
                    ("i32", DeclaredScalarType::Signed(32)),
                    ("u16", DeclaredScalarType::Unsigned(16)),
                    ("i16", DeclaredScalarType::Signed(16)),
                    ("u8", DeclaredScalarType::Unsigned(8)),
                    ("i8", DeclaredScalarType::Signed(8)),
                ];
                suffix
                    .into_iter()
                    .find_map(|(suffix, scalar_type)| {
                        text.strip_suffix(suffix)
                            .map(|digits| (digits, scalar_type))
                    })
                    .unwrap_or((text, DeclaredScalarType::Signed(32)))
            };
            if !digits
                .as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_digit())
                || digits.starts_with("0b")
                || digits.starts_with("0o")
                || digits.starts_with("0x")
                || digits
                    .chars()
                    .any(|character| !character.is_ascii_digit() && character != '_')
                || digits.replace('_', "").parse::<u128>().is_err()
            {
                return None;
            }
            Some(scalar_type)
        }
        "unary_expression" => {
            let operator = node.child(0)?;
            let operand = node.named_child(0)?;
            (operator.kind() == "-" && operand.kind() == "integer_literal")
                .then(|| rust_scalar_type_from_literal(source, operand))
                .flatten()
                .map(|scalar_type| match scalar_type {
                    DeclaredScalarType::Unsigned(bits) => DeclaredScalarType::Signed(bits),
                    scalar_type => scalar_type,
                })
        }
        _ => None,
    }
}

/// The declared scalar type of each Rust by-value formal parameter and local
/// whose declaration states a primitive integer or Boolean type, or whose
/// initializer is a decimal integer or Boolean literal. Rust comparison
/// operators on these types are built in; every other type can dispatch to a
/// user implementation and is left untyped for scalar analysis.
///
/// Unsuffixed integer literals use Rust's default `i32` type. `isize` and
/// `usize` use the analyzer platform width. Inference from any expression
/// other than a direct literal is intentionally excluded.
pub fn rust_declared_scalar_types(
    procedure: &ProcedureHandle,
    prepared: &PreparedSyntaxTree,
) -> Vec<(ValueId, DeclaredScalarType)> {
    let source = prepared.source();
    binding_nodes(procedure, prepared)
        .into_iter()
        .filter_map(|(value, parameter, node)| {
            let scalar_type = if parameter {
                (node.kind() == "parameter")
                    .then(|| node.child_by_field_name("type"))
                    .flatten()
                    .and_then(|type_node| rust_scalar_type_from_type(source, type_node))
            } else {
                let declaration = std::iter::successors(node.parent(), |parent| parent.parent())
                    .find(|ancestor| ancestor.kind() == "let_declaration")?;
                if declaration.has_error() {
                    return None;
                }
                declaration
                    .child_by_field_name("type")
                    .and_then(|type_node| rust_scalar_type_from_type(source, type_node))
                    .or_else(|| {
                        declaration
                            .child_by_field_name("value")
                            .and_then(|initializer| {
                                rust_scalar_type_from_literal(source, initializer)
                            })
                    })
            }?;
            Some((value, scalar_type))
        })
        .collect()
}
