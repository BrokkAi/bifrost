//! Java numeric literal values and primitive numeric types (JLS 3.10.1,
//! 3.10.2, 4.2, 5.1.2).
//!
//! A literal's value is its token: tree-sitter classifies the literal but does
//! not decode it, so decoding the token text is the structured answer here.
//! Everything around the token (parentheses, the unary sign, the declared
//! type) is read from tree-sitter fields.

use tree_sitter::Node;

use crate::analyzer::java_integral_parameter::JavaIntegralDomain;
use crate::analyzer::semantic::SemanticValueKind;

/// A Java numeric literal's type and exact value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum JavaNumericLiteral {
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
}

impl JavaNumericLiteral {
    /// The integer value of an `int` or `long` literal.
    pub(super) fn integer(self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(i64::from(value)),
            Self::Long(value) => Some(value),
            Self::Float(_) | Self::Double(_) => None,
        }
    }

    /// The typed constant a primitive integral subject compares against.
    /// A floating literal has none: the comparison promotes the subject.
    pub(super) fn integer_kind(self) -> Option<SemanticValueKind> {
        self.integer().map(integer_value_kind)
    }

    /// The typed constant a primitive floating subject of type `subject`
    /// compares against after binary numeric promotion (JLS 5.6). A floating
    /// literal widens to binary64 exactly. An integer literal converts to the
    /// promoted type, which is `float` for a `float` subject; the constant is
    /// published only when that conversion is exact, so rounding never
    /// changes the compared value.
    pub(super) fn floating_kind(self, subject: JavaFloatingType) -> Option<SemanticValueKind> {
        let value = match self {
            Self::Float(value) => f64::from(value),
            Self::Double(value) => value,
            Self::Int(_) | Self::Long(_) => {
                let integer = self.integer().expect("integer literal");
                let exact_bits = match subject {
                    JavaFloatingType::Float => f32::MANTISSA_DIGITS,
                    JavaFloatingType::Double => f64::MANTISSA_DIGITS,
                };
                if integer.unsigned_abs() > 1_u64 << exact_bits {
                    return None;
                }
                integer as f64
            }
        };
        assert!(value.is_finite(), "decoded literals are finite: {self:?}");
        Some(SemanticValueKind::FloatingPoint {
            bits: value.to_bits(),
        })
    }

    /// Whether a literal of this type may initialize or be assigned to a
    /// variable of `domain` (JLS 5.2): an `int` constant narrows when its
    /// value fits, and a `long` literal is assignable only to `long`.
    pub(super) fn assignable_to_integral(self, domain: JavaIntegralDomain) -> bool {
        match self {
            Self::Int(value) => domain.accepts_decimal_int_literal(i64::from(value)),
            Self::Long(_) => domain == JavaIntegralDomain::Signed(64),
            Self::Float(_) | Self::Double(_) => false,
        }
    }
}

/// The published constant for one exact Java integer value.
fn integer_value_kind(value: i64) -> SemanticValueKind {
    if value < 0 {
        SemanticValueKind::SignedInteger(i128::from(value))
    } else {
        SemanticValueKind::UnsignedInteger(u128::from(value.unsigned_abs()))
    }
}

/// A primitive floating type named by a `floating_point_type` node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JavaFloatingType {
    Float,
    Double,
}

impl JavaFloatingType {
    pub(super) fn from_type(type_node: Node<'_>) -> Option<Self> {
        if type_node.kind() != "floating_point_type" || type_node.has_error() {
            return None;
        }
        match type_node.child(0)?.kind() {
            "float" => Some(Self::Float),
            "double" => Some(Self::Double),
            _ => None,
        }
    }
}

/// Whether every value of `source` is a value of `target`, so a primitive
/// cast from `source` to `target` is an identity or widening conversion that
/// preserves the value (JLS 5.1.2). `char` to `short` and `byte` to `char`
/// are not.
pub(super) fn integral_domain_contains(
    target: JavaIntegralDomain,
    source: JavaIntegralDomain,
) -> bool {
    match (target, source) {
        (JavaIntegralDomain::Signed(target), JavaIntegralDomain::Signed(source))
        | (JavaIntegralDomain::Unsigned(target), JavaIntegralDomain::Unsigned(source)) => {
            source <= target
        }
        (JavaIntegralDomain::Signed(target), JavaIntegralDomain::Unsigned(source)) => {
            source < target
        }
        (JavaIntegralDomain::Unsigned(_), JavaIntegralDomain::Signed(_)) => false,
    }
}

/// Decode one numeric literal token and a direct unary sign, peeling
/// enclosing parentheses.
///
/// A decimal integer denotes a nonnegative value, and the magnitude 2^31
/// (2^63 with an `L` suffix) is legal only as the direct operand of unary
/// minus. A hexadecimal, octal or binary integer is the two's-complement bit
/// pattern of its type, so `0xFFFFFFFF` is -1, and unary minus wraps as the
/// operator does. A floating literal rounds to its `float` or `double` type;
/// an overflowing or hexadecimal floating literal stays unrepresented, as
/// does any sign applied to a parenthesized operand.
pub(super) fn java_numeric_literal(source: &str, mut node: Node<'_>) -> Option<JavaNumericLiteral> {
    while node.kind() == "parenthesized_expression" && node.named_child_count() == 1 {
        node = node.named_child(0)?;
    }
    let mut negative = false;
    if node.kind() == "unary_expression" {
        negative = match node.child_by_field_name("operator")?.kind() {
            "-" => true,
            "+" => false,
            _ => return None,
        };
        node = node.child_by_field_name("operand")?;
    }
    if node.has_error() || node.is_missing() {
        return None;
    }
    let radix = match node.kind() {
        "decimal_integer_literal" => 10,
        "hex_integer_literal" => 16,
        "octal_integer_literal" => 8,
        "binary_integer_literal" => 2,
        "decimal_floating_point_literal" => {
            return decode_floating(source.get(node.byte_range())?, negative);
        }
        _ => return None,
    };
    let token = source
        .get(node.byte_range())?
        .chars()
        .filter(|character| *character != '_')
        .collect::<String>();
    let (digits, long) = match token.strip_suffix(['l', 'L']) {
        Some(digits) => (digits, true),
        None => (token.as_str(), false),
    };
    // The grammar's prefixes: `0x`/`0X`, `0b`/`0B`, and a leading `0` for
    // octal. The grammar also admits an `0o` octal prefix Java does not; its
    // `o` is not an octal digit, so the parse below rejects it.
    let digits = match radix {
        16 | 2 => digits.get(2..)?,
        8 => digits.get(1..)?,
        _ => digits,
    };
    let magnitude = u64::from_str_radix(digits, radix).ok()?;
    if radix == 10 {
        let limit = if long { 1_u64 << 63 } else { 1_u64 << 31 };
        if magnitude > limit || (magnitude == limit && !negative) {
            return None;
        }
        let value = if negative {
            -i128::from(magnitude)
        } else {
            i128::from(magnitude)
        };
        return Some(if long {
            JavaNumericLiteral::Long(i64::try_from(value).ok()?)
        } else {
            JavaNumericLiteral::Int(i32::try_from(value).ok()?)
        });
    }
    Some(if long {
        let value = magnitude as i64;
        JavaNumericLiteral::Long(if negative {
            value.wrapping_neg()
        } else {
            value
        })
    } else {
        let value = u32::try_from(magnitude).ok()? as i32;
        JavaNumericLiteral::Int(if negative {
            value.wrapping_neg()
        } else {
            value
        })
    })
}

/// Round a decimal floating token to its type. Rust's float parsing is
/// correctly rounded, which is the rounding JLS 3.10.2 requires, and accepts
/// every digit shape the grammar admits (`1.`, `.5`, `1e+5`).
fn decode_floating(token: &str, negative: bool) -> Option<JavaNumericLiteral> {
    let token = token
        .chars()
        .filter(|character| *character != '_')
        .collect::<String>();
    let (body, single) = match token.as_bytes().last()? {
        b'f' | b'F' => (&token[..token.len() - 1], true),
        b'd' | b'D' => (&token[..token.len() - 1], false),
        _ => (token.as_str(), false),
    };
    if single {
        let value = body.parse::<f32>().ok().filter(|value| value.is_finite())?;
        Some(JavaNumericLiteral::Float(if negative {
            -value
        } else {
            value
        }))
    } else {
        let value = body.parse::<f64>().ok().filter(|value| value.is_finite())?;
        Some(JavaNumericLiteral::Double(if negative {
            -value
        } else {
            value
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use JavaNumericLiteral::{Double, Float, Int, Long};

    /// Decode the initializer of the single `x` declaration in `expression`.
    fn decode(expression: &str) -> Option<JavaNumericLiteral> {
        let source = format!("class A {{ void m() {{ var x = {expression}; }} }}");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("Java grammar must load");
        let tree = parser.parse(&source, None).expect("Java source must parse");
        assert!(!tree.root_node().has_error(), "{source}");
        let mut value = None;
        crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(
            tree.root_node(),
            true,
            |node| {
                if node.kind() == "variable_declarator" {
                    value = node.child_by_field_name("value");
                    crate::analyzer::tree_sitter_analyzer::WalkControl::Break
                } else {
                    crate::analyzer::tree_sitter_analyzer::WalkControl::Continue
                }
            },
        );
        java_numeric_literal(&source, value.expect("initializer"))
    }

    #[test]
    fn decimal_integers_respect_the_unary_minus_boundary() {
        assert_eq!(decode("0"), Some(Int(0)));
        assert_eq!(decode("1_000"), Some(Int(1000)));
        assert_eq!(decode("2147483647"), Some(Int(i32::MAX)));
        assert_eq!(decode("-2147483648"), Some(Int(i32::MIN)));
        assert_eq!(decode("(-2147483648)"), Some(Int(i32::MIN)));
        assert_eq!(decode("2147483648"), None);
        assert_eq!(decode("+2147483648"), None);
        assert_eq!(decode("-(2147483648)"), None);
        assert_eq!(decode("-2147483649"), None);
        assert_eq!(decode("2147483648L"), Some(Long(1 << 31)));
        assert_eq!(decode("-1L"), Some(Long(-1)));
        assert_eq!(decode("-9223372036854775808L"), Some(Long(i64::MIN)));
        assert_eq!(decode("9223372036854775808L"), None);
        assert_eq!(decode("9223372036854775807l"), Some(Long(i64::MAX)));
    }

    #[test]
    fn radix_integers_are_twos_complement_bit_patterns() {
        assert_eq!(decode("0xFFFFFFFF"), Some(Int(-1)));
        assert_eq!(decode("0x7fff_ffff"), Some(Int(i32::MAX)));
        assert_eq!(decode("0x80000000"), Some(Int(i32::MIN)));
        assert_eq!(decode("-0x80000000"), Some(Int(i32::MIN)));
        assert_eq!(decode("0x1_0000_0000"), None);
        assert_eq!(decode("0x8000000000000000L"), Some(Long(i64::MIN)));
        assert_eq!(decode("0xFFFFFFFFFFFFFFFFL"), Some(Long(-1)));
        assert_eq!(decode("0x1_0000_0000_0000_0000L"), None);
        assert_eq!(decode("017"), Some(Int(15)));
        assert_eq!(decode("037777777777"), Some(Int(-1)));
        assert_eq!(decode("0b1010"), Some(Int(10)));
        assert_eq!(decode("-0B1_1L"), Some(Long(-3)));
    }

    #[test]
    fn floating_literals_round_to_their_type() {
        assert_eq!(decode("1.5"), Some(Double(1.5)));
        assert_eq!(decode("-2.5e3"), Some(Double(-2500.0)));
        assert_eq!(decode("1."), Some(Double(1.0)));
        assert_eq!(decode(".5f"), Some(Float(0.5)));
        assert_eq!(decode("1_0e+1d"), Some(Double(100.0)));
        assert_eq!(decode("3F"), Some(Float(3.0)));
        assert_eq!(decode("1e400"), None);
        assert_eq!(decode("3.5e38f"), None);
        assert_eq!(decode("0x1p3"), None);
        let Some(Float(tenth)) = decode("0.1f") else {
            panic!("0.1f is a float literal");
        };
        assert_eq!(tenth.to_bits(), 0x3dcc_cccd);
        // The binary64 pattern of 0.100000001490116119384765625, the exact
        // value of the nearest float to 0.1.
        assert_eq!(
            Float(tenth).floating_kind(JavaFloatingType::Double),
            Some(SemanticValueKind::FloatingPoint {
                bits: 0x3fb9_9999_a000_0000
            })
        );
        assert_ne!(f64::from(tenth), 0.1);
    }

    #[test]
    fn integer_constants_convert_to_floating_only_when_exact() {
        let exact = |literal: JavaNumericLiteral, subject| literal.floating_kind(subject);
        let bits = |value: f64| {
            Some(SemanticValueKind::FloatingPoint {
                bits: value.to_bits(),
            })
        };
        assert_eq!(
            exact(Int(1 << 24), JavaFloatingType::Float),
            bits(16_777_216.0)
        );
        assert_eq!(exact(Int((1 << 24) + 1), JavaFloatingType::Float), None);
        assert_eq!(
            exact(Int((1 << 24) + 1), JavaFloatingType::Double),
            bits(16_777_217.0)
        );
        assert_eq!(
            exact(Long(-(1 << 53)), JavaFloatingType::Double),
            bits(-9_007_199_254_740_992.0)
        );
        assert_eq!(exact(Long((1 << 53) + 1), JavaFloatingType::Double), None);
        assert_eq!(exact(Long(i64::MIN), JavaFloatingType::Double), None);
    }

    #[test]
    fn integer_literals_follow_assignment_conversion() {
        let byte = JavaIntegralDomain::Signed(8);
        let char_domain = JavaIntegralDomain::Unsigned(16);
        let int = JavaIntegralDomain::Signed(32);
        let long = JavaIntegralDomain::Signed(64);
        assert!(Int(127).assignable_to_integral(byte));
        assert!(!Int(128).assignable_to_integral(byte));
        assert!(Int(65_535).assignable_to_integral(char_domain));
        assert!(!Int(-1).assignable_to_integral(char_domain));
        assert!(Int(i32::MIN).assignable_to_integral(long));
        assert!(!Long(1).assignable_to_integral(int));
        assert!(Long(i64::MIN).assignable_to_integral(long));
        assert!(!Double(1.0).assignable_to_integral(long));
    }

    #[test]
    fn widening_casts_preserve_every_source_value() {
        use JavaIntegralDomain::{Signed, Unsigned};
        assert!(integral_domain_contains(Signed(32), Signed(8)));
        assert!(integral_domain_contains(Signed(32), Signed(32)));
        assert!(integral_domain_contains(Signed(32), Unsigned(16)));
        assert!(integral_domain_contains(Unsigned(16), Unsigned(16)));
        assert!(!integral_domain_contains(Signed(16), Unsigned(16)));
        assert!(!integral_domain_contains(Unsigned(16), Signed(8)));
        assert!(!integral_domain_contains(Signed(32), Signed(64)));
    }
}
