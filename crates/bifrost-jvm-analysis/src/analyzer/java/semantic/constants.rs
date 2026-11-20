//! The one Java constant evaluator (#10905, #13763).
//!
//! A condition or switch selector built from literals, effectively final
//! constant locals and the fixed `String` allowlist below is decided at
//! lowering time: only the feasible edge is built, so the missing edge is the
//! whole representation (no value or unreachable marker is stored). Evaluating
//! such an expression has no side effects and cannot throw, so dropping the
//! arm it never selects is exact.

use tree_sitter::Node;

use brokk_bifrost_analysis::analyzer::semantic::ValueFlowKind;
use brokk_bifrost_jvm::java::{decoded_char_literal_value, decoded_string_literal_value};

use crate::analyzer::java::semantic::numeric::{
    JavaNumericLiteral, java_integral_binary, java_integral_comparison, java_integral_negate,
    java_numeric_literal,
};
use crate::analyzer::java::semantic::syntax::{first_named_child, named_children};
use crate::analyzer::java::semantic::*;

/// A compile-time value. `Str` holds UTF-16 code units, so `charAt` and
/// `length` follow Java exactly, surrogate pairs included.
#[derive(Debug, Clone, PartialEq)]
pub(in crate::analyzer::java::semantic) enum JavaConstant {
    Int(i32),
    Long(i64),
    Char(u16),
    Str(Vec<u16>),
    Bool(bool),
}

impl JavaConstant {
    /// The value after unary or binary numeric promotion (JLS 5.6): `char`
    /// is an `int`. `String` and `boolean` are not numeric.
    fn promoted(&self) -> Option<JavaNumericLiteral> {
        match self {
            Self::Int(value) => Some(JavaNumericLiteral::Int(*value)),
            Self::Long(value) => Some(JavaNumericLiteral::Long(*value)),
            Self::Char(unit) => Some(JavaNumericLiteral::Int(i32::from(*unit))),
            Self::Str(_) | Self::Bool(_) => None,
        }
    }

    fn from_numeric(literal: JavaNumericLiteral) -> Option<Self> {
        match literal {
            JavaNumericLiteral::Int(value) => Some(Self::Int(value)),
            JavaNumericLiteral::Long(value) => Some(Self::Long(value)),
            JavaNumericLiteral::Float(_) | JavaNumericLiteral::Double(_) => None,
        }
    }

    /// Whether a switch label equal to `label` selects this value. `char`
    /// and integral labels compare by promoted value, `String` labels by
    /// `equals`. A label of another kind never type-checks, so it has no answer.
    pub(in crate::analyzer::java::semantic) fn selected_by(&self, label: &Self) -> Option<bool> {
        match (self, label) {
            (Self::Str(selector), Self::Str(label)) => Some(selector == label),
            (Self::Bool(_), _) | (_, Self::Bool(_)) | (Self::Str(_), _) | (_, Self::Str(_)) => None,
            _ => Some(self.promoted()?.integer()? == label.promoted()?.integer()?),
        }
    }
}

/// A library method that folds on a `String` constant receiver. This table is
/// the only place a library method folds. The receiver being a `Str` constant
/// proves its runtime class is the final `java.lang.String`, so the selected
/// method is String's own and no pack is consulted. Each further method needs
/// a coordinator ruling and goes here.
struct StringIntrinsic {
    name: &'static str,
    arity: usize,
    fold: fn(receiver: &[u16], arguments: &[JavaConstant]) -> Option<JavaConstant>,
}

const STRING_INTRINSICS: &[StringIntrinsic] = &[
    // An index outside 0..len throws, so it does not fold and the call keeps
    // its throw edge.
    StringIntrinsic {
        name: "charAt",
        arity: 1,
        fold: |receiver, arguments| {
            let index = arguments[0].promoted()?.integer()?;
            let index = usize::try_from(index).ok()?;
            receiver.get(index).map(|unit| JavaConstant::Char(*unit))
        },
    },
    StringIntrinsic {
        name: "length",
        arity: 0,
        fold: |receiver, _| Some(JavaConstant::Int(i32::try_from(receiver.len()).ok()?)),
    },
    // Folds only when the argument is also a constant `String`; any other
    // argument may be null or of another type.
    StringIntrinsic {
        name: "equals",
        arity: 1,
        fold: |receiver, arguments| match &arguments[0] {
            JavaConstant::Str(other) => Some(JavaConstant::Bool(receiver == other.as_slice())),
            _ => None,
        },
    },
];

/// The constant an initializer gives a local of the declared type, converted
/// by assignment (JLS 5.2). `byte`, `short`, `boolean`, floating and every
/// other declared type have no constant here; `var` takes the initializer's
/// own type.
fn local_initializer_value(
    source: &str,
    declared: Option<Node<'_>>,
    value: JavaConstant,
) -> Option<JavaConstant> {
    let declared = declared?;
    match (declared.kind(), &value) {
        ("integral_type", _) => match (declared.child(0)?.kind(), &value) {
            ("int", JavaConstant::Int(_)) | ("long", JavaConstant::Long(_)) => Some(value),
            ("char", JavaConstant::Char(_)) => Some(value),
            ("int", JavaConstant::Char(unit)) => Some(JavaConstant::Int(i32::from(*unit))),
            ("long", JavaConstant::Int(_) | JavaConstant::Char(_)) => Some(JavaConstant::Long(
                value.promoted()?.integer().expect("integral value"),
            )),
            // An int constant narrows to char when it fits (JLS 5.2).
            ("char", JavaConstant::Int(int)) => u16::try_from(*int).ok().map(JavaConstant::Char),
            _ => None,
        },
        ("type_identifier", _) => match (source.get(declared.byte_range())?, &value) {
            ("String", JavaConstant::Str(_)) => Some(value),
            ("var", JavaConstant::Bool(_)) => None,
            ("var", _) => Some(value),
            _ => None,
        },
        _ => None,
    }
}

impl<'tree> LoweringContext<'tree, '_> {
    /// Evaluate every candidate constant local in declaration order. A
    /// legal initializer reads only locals declared before it, so one pass in
    /// source order needs neither recursion nor a memo and cannot meet a cycle.
    /// A local written anywhere (assignment, compound assignment, `++`, `--`)
    /// is not effectively final (JLS 4.12.4) and has no constant; a reader of
    /// it finds nothing in `constant_locals` and does not fold.
    pub(in crate::analyzer::java::semantic) fn evaluate_constant_locals(&mut self) {
        let candidates = std::mem::take(&mut self.constant_local_candidates);
        debug_assert!(
            candidates
                .windows(2)
                .all(|pair| pair[0].1.start_byte() < pair[1].1.start_byte()),
            "candidates arrive in declaration order"
        );
        for (binding, declarator, declared) in candidates {
            if self.written_bindings.contains(&binding) {
                continue;
            }
            let Some(initializer) = declarator.child_by_field_name("value") else {
                continue;
            };
            debug_assert!(
                !self.constant_locals.contains_key(&binding),
                "a local is declared once"
            );
            if let Some(value) = self
                .java_constant(initializer)
                .and_then(|value| local_initializer_value(self.prepared.source(), declared, value))
            {
                self.constant_locals.insert(binding, value);
            }
        }
    }

    /// Whether a switch label selects a constant selector: `Some(true)` when
    /// one of its values equals the selector, `Some(false)` when every value
    /// is a constant and none does, and `None` when some value is not a
    /// constant of the selector's kind (so both edges stay).
    pub(in crate::analyzer::java::semantic) fn switch_label_verdict(
        &self,
        selector: &JavaConstant,
        label: Node<'tree>,
    ) -> Option<bool> {
        let mut undecided = false;
        for value in named_children(label)
            .into_iter()
            .filter(|child| child.kind() != "guard")
        {
            match self
                .java_constant(value)
                .and_then(|constant| selector.selected_by(&constant))
            {
                Some(true) => return Some(true),
                Some(false) => {}
                None => undecided = true,
            }
        }
        (!undecided).then_some(false)
    }

    /// The truth of a condition that is a constant `boolean`, such as a
    /// comparison of constants or `"ABC".equals("ABC")`.
    pub(in crate::analyzer::java::semantic) fn constant_truth(
        &self,
        node: Node<'tree>,
    ) -> Option<bool> {
        match self.java_constant(node)? {
            JavaConstant::Bool(value) => Some(value),
            _ => None,
        }
    }

    /// The value of an expression built from literals, effectively final
    /// constant locals, parentheses, unary `+ - !`, binary `+ - * / %`,
    /// numeric comparisons and the `STRING_INTRINSICS` calls. Anything else,
    /// including a division by zero, has no value. The walk is iterative
    /// because generated conditions can nest deeply.
    pub(in crate::analyzer::java::semantic) fn java_constant(
        &self,
        root: Node<'tree>,
    ) -> Option<JavaConstant> {
        enum Step<'tree> {
            Visit(Node<'tree>),
            Apply(Node<'tree>),
        }
        let source = self.prepared.source();
        let mut work = vec![Step::Visit(root)];
        let mut values: Vec<JavaConstant> = Vec::new();
        while let Some(step) = work.pop() {
            match step {
                Step::Visit(node) => {
                    if let Some(literal) = java_numeric_literal(source, node) {
                        values.push(JavaConstant::from_numeric(literal)?);
                        continue;
                    }
                    match node.kind() {
                        "character_literal" => {
                            values.push(JavaConstant::Char(decoded_char_literal_value(
                                node, source,
                            )?));
                        }
                        "string_literal" => {
                            let value = decoded_string_literal_value(node, source)?;
                            values.push(JavaConstant::Str(value.encode_utf16().collect()));
                        }
                        "parenthesized_expression" => {
                            work.push(Step::Visit(first_named_child(node)?));
                        }
                        "identifier" => {
                            let (binding, kind) = self.lexical_reference_binding(node)?;
                            if kind != ValueFlowKind::Local {
                                return None;
                            }
                            values.push(self.constant_locals.get(&binding)?.clone());
                        }
                        "unary_expression" => {
                            let operator = node.child_by_field_name("operator")?.kind();
                            if !matches!(operator, "+" | "-" | "!") {
                                return None;
                            }
                            work.push(Step::Apply(node));
                            work.push(Step::Visit(node.child_by_field_name("operand")?));
                        }
                        "binary_expression"
                            if node
                                .child_by_field_name("operator")
                                .is_some_and(|operator| {
                                    matches!(
                                        operator.kind(),
                                        "+" | "-"
                                            | "*"
                                            | "/"
                                            | "%"
                                            | "=="
                                            | "!="
                                            | "<"
                                            | "<="
                                            | ">"
                                            | ">="
                                    )
                                }) =>
                        {
                            work.push(Step::Apply(node));
                            work.push(Step::Visit(node.child_by_field_name("right")?));
                            work.push(Step::Visit(node.child_by_field_name("left")?));
                        }
                        "method_invocation" => {
                            let receiver = node.child_by_field_name("object")?;
                            let name = node_text(source, node.child_by_field_name("name")?)?;
                            let arguments = named_children(node.child_by_field_name("arguments")?);
                            if !STRING_INTRINSICS
                                .iter()
                                .any(|m| m.name == name && m.arity == arguments.len())
                            {
                                return None;
                            }
                            work.push(Step::Apply(node));
                            for argument in arguments.into_iter().rev() {
                                work.push(Step::Visit(argument));
                            }
                            work.push(Step::Visit(receiver));
                        }
                        _ => return None,
                    }
                }
                Step::Apply(node) if node.kind() == "unary_expression" => {
                    let operand = values.pop().expect("a visited unary operand has a value");
                    let operator = node.child_by_field_name("operator")?.kind();
                    values.push(match (operator, operand) {
                        ("!", JavaConstant::Bool(value)) => JavaConstant::Bool(!value),
                        ("!", _) => return None,
                        ("-", operand) => {
                            JavaConstant::from_numeric(java_integral_negate(operand.promoted()?)?)?
                        }
                        (_, operand) => JavaConstant::from_numeric(operand.promoted()?)?,
                    });
                }
                Step::Apply(node) if node.kind() == "binary_expression" => {
                    let right = values.pop().expect("a visited right operand has a value");
                    let left = values.pop().expect("a visited left operand has a value");
                    let operator = node.child_by_field_name("operator")?.kind();
                    let (left, right) = (left.promoted()?, right.promoted()?);
                    values.push(if matches!(operator, "+" | "-" | "*" | "/" | "%") {
                        JavaConstant::from_numeric(java_integral_binary(operator, left, right)?)?
                    } else {
                        JavaConstant::Bool(java_integral_comparison(operator, left, right)?)
                    });
                }
                Step::Apply(node) => {
                    debug_assert_eq!(node.kind(), "method_invocation");
                    let name = node_text(source, node.child_by_field_name("name")?)?;
                    let arity = named_children(node.child_by_field_name("arguments")?).len();
                    let arguments = values.split_off(values.len() - arity);
                    let JavaConstant::Str(receiver) =
                        values.pop().expect("a visited receiver has a value")
                    else {
                        return None;
                    };
                    let intrinsic = STRING_INTRINSICS
                        .iter()
                        .find(|m| m.name == name && m.arity == arity)
                        .expect("Visit admitted only allowlisted calls");
                    values.push((intrinsic.fold)(&receiver, &arguments)?);
                }
            }
        }
        let value = values.pop();
        debug_assert!(values.is_empty(), "every operand was consumed: {values:?}");
        value
    }
}
