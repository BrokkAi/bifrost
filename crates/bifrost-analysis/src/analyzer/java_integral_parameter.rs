//! Exact primitive numeric types for Java formal parameters and locals.
//!
//! The scalar solver accepts typed entry facts and binding types, but
//! semantic values deliberately carry binding identity independently of type.
//! This joins one parameter or local value's exact source mapping to the
//! prepared Java declaration node, retaining no type for inferred, array,
//! recovered or otherwise unsupported declaration shapes. A numeric wrapper
//! type (`Integer`, `Double`, ...) keeps its primitive type and is marked
//! boxed, because a boxed binding can also hold `null`.

use crate::analyzer::semantic::{ProcedureHandle, SemanticValueKind, SourceMappingKind, ValueId};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaIntegralDomain {
    Signed(u16),
    Unsigned(u16),
}

impl JavaIntegralDomain {
    pub(crate) fn from_type(type_node: Node<'_>) -> Option<Self> {
        if type_node.kind() != "integral_type" || type_node.has_error() {
            return None;
        }
        match type_node.child(0)?.kind() {
            "byte" => Some(Self::Signed(8)),
            "short" => Some(Self::Signed(16)),
            "int" => Some(Self::Signed(32)),
            "long" => Some(Self::Signed(64)),
            "char" => Some(Self::Unsigned(16)),
            _ => None,
        }
    }

    /// Java's unsuffixed decimal literal after unary sign has `int` value.
    /// Assignment to a narrower primitive is legal only when its compile-time
    /// value fits; assignment to `long` widens without changing the value.
    pub(crate) fn accepts_decimal_int_literal(self, value: i64) -> bool {
        if !(i32::MIN as i64..=i32::MAX as i64).contains(&value) {
            return false;
        }
        let value = i128::from(value);
        match self {
            Self::Signed(bits) => {
                let magnitude = 1_i128 << (bits - 1);
                -magnitude <= value && value < magnitude
            }
            Self::Unsigned(bits) => 0 <= value && value < (1_i128 << bits),
        }
    }
}

/// Parse one unsuffixed decimal-literal token before Java's `int` range check.
pub(crate) fn decimal_integer_value(source: &str, node: Node<'_>) -> Option<i64> {
    (node.kind() == "decimal_integer_literal")
        .then(|| source.get(node.byte_range()))
        .flatten()
        .and_then(|text| text.parse::<i64>().ok())
}

/// Decode an unsuffixed Java decimal `int` literal and its direct unary sign.
/// The out-of-range magnitude 2147483648 is legal only under direct unary
/// minus, where it denotes `Integer.MIN_VALUE`. Radix, suffix, and arithmetic
/// forms remain unrepresented scalar constants.
pub(crate) fn java_decimal_int_value(source: &str, mut node: Node<'_>) -> Option<i64> {
    let mut layers = 0_usize;
    while node.kind() == "parenthesized_expression" && node.named_child_count() == 1 {
        layers += 1;
        if layers > 64 {
            return None;
        }
        node = node.named_child(0)?;
    }
    match node.kind() {
        "decimal_integer_literal" => {
            let value = decimal_integer_value(source, node)?;
            (0..=i32::MAX as i64).contains(&value).then_some(value)
        }
        "unary_expression" => {
            let operator = node.child_by_field_name("operator")?;
            let operand = node.child_by_field_name("operand")?;
            let magnitude = decimal_integer_value(source, operand)?;
            match operator.kind() {
                "+" => (0..=i32::MAX as i64)
                    .contains(&magnitude)
                    .then_some(magnitude),
                "-" => (0..=i32::MAX as i64 + 1)
                    .contains(&magnitude)
                    .then_some(-magnitude),
                _ => None,
            }
        }
        _ => None,
    }
}

/// A Java primitive scalar type that the scalar solver models.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaScalarType {
    Integral(JavaIntegralDomain),
    Float,
    Double,
    Boolean,
}

impl JavaScalarType {
    pub(crate) fn from_type(type_node: Node<'_>) -> Option<Self> {
        if type_node.kind() == "boolean_type" && !type_node.has_error() {
            return Some(Self::Boolean);
        }
        if type_node.kind() == "floating_point_type" && !type_node.has_error() {
            return match type_node.child(0)?.kind() {
                "float" => Some(Self::Float),
                "double" => Some(Self::Double),
                _ => None,
            };
        }
        JavaIntegralDomain::from_type(type_node).map(Self::Integral)
    }

    /// The primitive type a wrapper type name unboxes to (JLS 5.1.8).
    ///
    /// The name is read from its `type_identifier` node, so a user class that
    /// shares the name also matches. That is sound wherever the caller uses
    /// the result only for an operation that unboxes: a relational operator,
    /// a comparison with a numeric operand, or a condition compiles only on a
    /// primitive or on one of the wrapper classes, so in compilable code the
    /// name denotes the wrapper there. A typed store of a fact the type
    /// cannot hold makes the binding unknown.
    pub(crate) fn from_wrapper_type(type_node: Node<'_>, source: &str) -> Option<Self> {
        if type_node.kind() != "type_identifier" || type_node.has_error() {
            return None;
        }
        match source.get(type_node.byte_range())? {
            "Byte" => Some(Self::Integral(JavaIntegralDomain::Signed(8))),
            "Short" => Some(Self::Integral(JavaIntegralDomain::Signed(16))),
            "Integer" => Some(Self::Integral(JavaIntegralDomain::Signed(32))),
            "Long" => Some(Self::Integral(JavaIntegralDomain::Signed(64))),
            "Character" => Some(Self::Integral(JavaIntegralDomain::Unsigned(16))),
            "Float" => Some(Self::Float),
            "Double" => Some(Self::Double),
            "Boolean" => Some(Self::Boolean),
            _ => None,
        }
    }
}

/// One formal parameter or local with a modeled numeric type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JavaScalarBinding {
    pub value: ValueId,
    pub scalar_type: JavaScalarType,
    /// Declared as the numeric wrapper type, so the binding may be `null`.
    pub boxed: bool,
}

/// Return the declared numeric type of each formal parameter and local
/// variable of the procedure whose declaration is a scalar primitive or a
/// numeric wrapper type.
/// `prepared` must be the same source revision as the semantic artifact;
/// callers acquire them from one analyzer snapshot.
///
/// A parameter value maps exactly to its `formal_parameter`. A local value
/// maps exactly to the `name` identifier of its `variable_declarator`, whose
/// enclosing `local_variable_declaration` states the type. Arrays (in the
/// type or as declarator dimensions), `var`, other reference types, and
/// recovered syntax have no entry.
pub fn java_scalar_binding_types(
    procedure: &ProcedureHandle,
    prepared: &PreparedSyntaxTree,
) -> Vec<JavaScalarBinding> {
    let semantics = procedure.semantics();
    let procedure_mapping = semantics
        .source_mapping(semantics.source())
        .expect("validated procedure owns its source mapping");
    if procedure_mapping.kind != SourceMappingKind::Exact {
        return Vec::new();
    }
    let source = procedure_mapping.locator.anchor().span();
    let root = prepared.tree().root_node();
    let Some(callable) =
        root.descendant_for_byte_range(source.start_byte() as usize, source.end_byte() as usize)
    else {
        return Vec::new();
    };
    if callable.start_byte() != source.start_byte() as usize
        || callable.end_byte() != source.end_byte() as usize
        || callable.has_error()
    {
        return Vec::new();
    }
    semantics
        .values()
        .iter()
        .filter_map(|value| {
            if !matches!(
                value.kind,
                SemanticValueKind::Parameter { .. } | SemanticValueKind::Local
            ) {
                return None;
            }
            let mapping = semantics
                .source_mapping(value.source)
                .expect("validated value owns its source mapping");
            if mapping.kind != SourceMappingKind::Exact {
                return None;
            }
            let span = mapping.locator.anchor().span();
            let (start, end) = (span.start_byte() as usize, span.end_byte() as usize);
            let node = callable.named_descendant_for_byte_range(start, end)?;
            if node.start_byte() != start || node.end_byte() != end || node.has_error() {
                return None;
            }
            let type_node = match (&value.kind, node.kind()) {
                (SemanticValueKind::Parameter { .. }, "formal_parameter") => {
                    // `int[] x` and `int x[]` are arrays even though an
                    // `integral_type` occurs in the declaration.
                    let mut cursor = node.walk();
                    if node.child_by_field_name("dimensions").is_some()
                        || node
                            .named_children(&mut cursor)
                            .any(|child| child.kind() == "dimensions")
                    {
                        return None;
                    }
                    node.child_by_field_name("type")?
                }
                (SemanticValueKind::Local, "identifier") => {
                    let declarator = node.parent()?;
                    if declarator.kind() != "variable_declarator"
                        || declarator.child_by_field_name("name") != Some(node)
                        || declarator.child_by_field_name("dimensions").is_some()
                    {
                        return None;
                    }
                    let declaration = declarator.parent()?;
                    if declaration.kind() != "local_variable_declaration" {
                        return None;
                    }
                    declaration.child_by_field_name("type")?
                }
                _ => return None,
            };
            let primitive = JavaScalarType::from_type(type_node);
            primitive
                .or_else(|| JavaScalarType::from_wrapper_type(type_node, prepared.source()))
                .map(|scalar_type| JavaScalarBinding {
                    value: value.id,
                    scalar_type,
                    boxed: primitive.is_none(),
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::JavaIntegralDomain;

    #[test]
    fn unsuffixed_decimal_assignment_respects_java_primitive_ranges() {
        assert!(JavaIntegralDomain::Signed(8).accepts_decimal_int_literal(127));
        assert!(!JavaIntegralDomain::Signed(8).accepts_decimal_int_literal(128));
        assert!(JavaIntegralDomain::Unsigned(16).accepts_decimal_int_literal(65535));
        assert!(!JavaIntegralDomain::Unsigned(16).accepts_decimal_int_literal(65536));
        assert!(JavaIntegralDomain::Signed(64).accepts_decimal_int_literal(i32::MAX as i64));
        assert!(!JavaIntegralDomain::Signed(64).accepts_decimal_int_literal(i32::MAX as i64 + 1));
        assert!(JavaIntegralDomain::Signed(32).accepts_decimal_int_literal(-1));
        assert!(JavaIntegralDomain::Signed(8).accepts_decimal_int_literal(-128));
        assert!(!JavaIntegralDomain::Signed(8).accepts_decimal_int_literal(-129));
        assert!(!JavaIntegralDomain::Unsigned(16).accepts_decimal_int_literal(-1));
        assert!(JavaIntegralDomain::Signed(32).accepts_decimal_int_literal(i32::MIN as i64));
        assert!(!JavaIntegralDomain::Signed(64).accepts_decimal_int_literal(i32::MIN as i64 - 1));
    }
}
