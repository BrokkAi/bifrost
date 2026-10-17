//! Python special-method contracts derived from persisted signatures and the
//! declaration's prepared syntax.

use super::super::provider::StructuralSyntaxLimitedOutcome;
use super::*;
use brokk_bifrost_analysis::analyzer::python_function_has_decorator;
use brokk_bifrost_core::analyzer::model::CallableArity;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use tree_sitter::Node;

const MAX_SPECIAL_METHOD_SOURCE_BYTES: usize = 1024 * 1024;

const UNARY_SPECIAL_METHODS: &[&str] = &[
    "__del__",
    "__repr__",
    "__neg__",
    "__pos__",
    "__abs__",
    "__invert__",
    "__complex__",
    "__int__",
    "__float__",
    "__long__",
    "__oct__",
    "__hex__",
    "__str__",
    "__index__",
    "__enter__",
    "__hash__",
    "__bool__",
    "__nonzero__",
    "__unicode__",
    "__len__",
    "__iter__",
    "__reversed__",
    "__aenter__",
    "__aiter__",
    "__anext__",
    "__await__",
    "__ceil__",
    "__floor__",
    "__trunc__",
    "__length_hint__",
    "__dir__",
    "__bytes__",
];

const BINARY_SPECIAL_METHODS: &[&str] = &[
    "__lt__",
    "__le__",
    "__delattr__",
    "__delete__",
    "__instancecheck__",
    "__subclasscheck__",
    "__getitem__",
    "__delitem__",
    "__contains__",
    "__add__",
    "__sub__",
    "__mul__",
    "__eq__",
    "__floordiv__",
    "__div__",
    "__truediv__",
    "__mod__",
    "__divmod__",
    "__lshift__",
    "__rshift__",
    "__and__",
    "__xor__",
    "__or__",
    "__ne__",
    "__radd__",
    "__rsub__",
    "__rmul__",
    "__rfloordiv__",
    "__rdiv__",
    "__rtruediv__",
    "__rmod__",
    "__rdivmod__",
    "__rpow__",
    "__rlshift__",
    "__gt__",
    "__rrshift__",
    "__rand__",
    "__rxor__",
    "__ror__",
    "__iadd__",
    "__isub__",
    "__imul__",
    "__ifloordiv__",
    "__idiv__",
    "__itruediv__",
    "__ge__",
    "__imod__",
    "__ipow__",
    "__ilshift__",
    "__irshift__",
    "__iand__",
    "__ixor__",
    "__ior__",
    "__coerce__",
    "__cmp__",
    "__rcmp__",
    "__getattr__",
    "__getattribute__",
    "__buffer__",
    "__release_buffer__",
    "__matmul__",
    "__rmatmul__",
    "__imatmul__",
    "__missing__",
    "__class_getitem__",
    "__mro_entries__",
    "__format__",
];

const TERNARY_SPECIAL_METHODS: &[&str] = &[
    "__setattr__",
    "__set__",
    "__setitem__",
    "__getslice__",
    "__delslice__",
    "__set_name__",
];

const QUAD_SPECIAL_METHODS: &[&str] = &["__setslice__", "__exit__", "__aexit__"];

#[derive(Debug, Clone, Copy)]
enum SpecialMethodArity {
    Fixed { minimum: usize, maximum: usize },
    Power,
    Get,
    Round,
}

#[derive(Debug, Clone, Copy)]
enum PlaceholderBody {
    Placeholder,
    Concrete,
    Unknown(&'static str),
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PythonSpecialMethodContract {
    pub(super) status: &'static str,
    pub(super) expected_minimum: Option<usize>,
    pub(super) expected_maximum: Option<usize>,
    pub(super) reason: Option<&'static str>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PythonSpecialMethodContext {
    arity: SpecialMethodArity,
    staticmethod: Option<bool>,
    body: PlaceholderBody,
}

impl PythonSpecialMethodContext {
    pub(super) fn contract(self, actual: Option<CallableArity>) -> PythonSpecialMethodContract {
        let Some(staticmethod) = self.staticmethod else {
            let reason = match self.body {
                PlaceholderBody::Unknown(reason) => reason,
                PlaceholderBody::Placeholder | PlaceholderBody::Concrete => {
                    "declaration_unavailable"
                }
            };
            return PythonSpecialMethodContract::incomplete(reason);
        };
        let correction = if staticmethod { 1 } else { 0 };
        let (base_minimum, base_maximum) = self.arity.bounds();
        let expected_minimum = base_minimum.saturating_sub(correction);
        let expected_maximum = base_maximum.saturating_sub(correction);

        match self.body {
            PlaceholderBody::Placeholder => {
                return PythonSpecialMethodContract {
                    status: "placeholder",
                    expected_minimum: Some(expected_minimum),
                    expected_maximum: Some(expected_maximum),
                    reason: None,
                };
            }
            PlaceholderBody::Unknown(reason) => {
                return PythonSpecialMethodContract {
                    status: "incomplete",
                    expected_minimum: Some(expected_minimum),
                    expected_maximum: Some(expected_maximum),
                    reason: Some(reason),
                };
            }
            PlaceholderBody::Concrete => {}
        }

        let Some(actual) = actual else {
            return PythonSpecialMethodContract {
                status: "incomplete",
                expected_minimum: Some(expected_minimum),
                expected_maximum: Some(expected_maximum),
                reason: Some("signature_unrecorded"),
            };
        };
        let status = match self.arity {
            SpecialMethodArity::Fixed { .. } | SpecialMethodArity::Get => {
                if !actual.is_repeated() && actual.total() < expected_minimum {
                    "too_few"
                } else if actual.required() > expected_maximum {
                    "too_many"
                } else {
                    "compatible"
                }
            }
            SpecialMethodArity::Power => {
                if !actual.is_repeated() && actual.total() < expected_minimum {
                    "too_few"
                } else if actual.required() > expected_maximum {
                    "too_many"
                } else if actual.required() == expected_maximum {
                    "required_optional_third"
                } else {
                    "compatible"
                }
            }
            SpecialMethodArity::Round => {
                if !actual.is_repeated() && actual.total() < expected_minimum {
                    "too_few"
                } else if actual.required() > expected_maximum {
                    "too_many"
                } else if actual.required() == expected_maximum {
                    "required_optional_second"
                } else {
                    "compatible"
                }
            }
        };
        PythonSpecialMethodContract {
            status,
            expected_minimum: Some(expected_minimum),
            expected_maximum: Some(expected_maximum),
            reason: None,
        }
    }
}

impl PythonSpecialMethodContract {
    fn incomplete(reason: &'static str) -> Self {
        Self {
            status: "incomplete",
            expected_minimum: None,
            expected_maximum: None,
            reason: Some(reason),
        }
    }
}

impl SpecialMethodArity {
    fn for_name(name: &str) -> Option<Self> {
        if UNARY_SPECIAL_METHODS.contains(&name) {
            Some(Self::Fixed {
                minimum: 1,
                maximum: 1,
            })
        } else if BINARY_SPECIAL_METHODS.contains(&name) {
            Some(Self::Fixed {
                minimum: 2,
                maximum: 2,
            })
        } else if TERNARY_SPECIAL_METHODS.contains(&name) {
            Some(Self::Fixed {
                minimum: 3,
                maximum: 3,
            })
        } else if QUAD_SPECIAL_METHODS.contains(&name) {
            Some(Self::Fixed {
                minimum: 4,
                maximum: 4,
            })
        } else {
            match name {
                "__pow__" => Some(Self::Power),
                "__get__" => Some(Self::Get),
                "__round__" => Some(Self::Round),
                _ => None,
            }
        }
    }

    fn bounds(self) -> (usize, usize) {
        match self {
            Self::Fixed { minimum, maximum } => (minimum, maximum),
            Self::Power => (2, 3),
            Self::Get => (3, 3),
            Self::Round => (1, 2),
        }
    }
}

pub(super) fn python_special_method_context(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
) -> Option<PythonSpecialMethodContext> {
    if declaration.unit.source().language() != Language::Python
        || !analyzer
            .parent_of(&declaration.unit)
            .is_some_and(|owner| owner.is_class())
    {
        return None;
    }
    let arity = SpecialMethodArity::for_name(declaration.unit.identifier())?;
    let cancellation = analyzer.active_query_cancellation();
    let provider = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::Python);
    let Some(provider) = provider else {
        return Some(PythonSpecialMethodContext {
            arity,
            staticmethod: None,
            body: PlaceholderBody::Unknown("syntax_unavailable"),
        });
    };
    let syntax = match provider.structural_syntax_limited(
        declaration.unit.source(),
        MAX_SPECIAL_METHOD_SOURCE_BYTES,
        cancellation.as_ref(),
    ) {
        StructuralSyntaxLimitedOutcome::Available(syntax) => syntax,
        StructuralSyntaxLimitedOutcome::Exceeded { .. } => {
            return Some(PythonSpecialMethodContext {
                arity,
                staticmethod: None,
                body: PlaceholderBody::Unknown("source_limit"),
            });
        }
        StructuralSyntaxLimitedOutcome::Cancelled => {
            return Some(PythonSpecialMethodContext {
                arity,
                staticmethod: None,
                body: PlaceholderBody::Unknown("cancelled"),
            });
        }
        StructuralSyntaxLimitedOutcome::Unavailable => {
            return Some(PythonSpecialMethodContext {
                arity,
                staticmethod: None,
                body: PlaceholderBody::Unknown("syntax_unavailable"),
            });
        }
    };
    let prepared = syntax.prepared();
    let Some(function) = python_function_node(prepared, declaration) else {
        return Some(PythonSpecialMethodContext {
            arity,
            staticmethod: None,
            body: PlaceholderBody::Unknown("declaration_unavailable"),
        });
    };
    let source = prepared.source();
    let staticmethod = python_function_has_decorator(function, source, "staticmethod");
    let body = python_placeholder_body(function);
    Some(PythonSpecialMethodContext {
        arity,
        staticmethod: Some(staticmethod),
        body,
    })
}

fn python_function_node<'tree>(
    prepared: &'tree PreparedSyntaxTree,
    declaration: &DeclarationValue,
) -> Option<Node<'tree>> {
    let start = declaration.range.start_byte;
    let end = declaration.range.end_byte;
    // The limited structural syntax provider returns an exact prepared source
    // snapshot, which intentionally has no declaration index. The exact
    // declaration range is already available from this query row, so locate
    // the function by walking its parsed tree instead of asking the snapshot
    // for declaration facts it cannot carry.
    let root = prepared.tree().root_node();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition"
            && node.start_byte() >= start
            && node.end_byte() <= end
            && node
                .child_by_field_name("name")
                .and_then(|name| prepared.source().get(name.byte_range()))
                == Some(declaration.unit.identifier())
        {
            return Some(node);
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    None
}

fn python_placeholder_body(function: Node<'_>) -> PlaceholderBody {
    if function.has_error() {
        return PlaceholderBody::Unknown("recovered_syntax");
    }
    let Some(body) = function.child_by_field_name("body") else {
        return PlaceholderBody::Unknown("body_unavailable");
    };
    if body.kind() != "block" || body.has_error() {
        return PlaceholderBody::Unknown("recovered_syntax");
    }
    let mut cursor = body.walk();
    let statements = body
        .named_children(&mut cursor)
        .filter(|statement| statement.kind() != "comment")
        .collect::<Vec<_>>();
    if statements.len() != 1 {
        return PlaceholderBody::Concrete;
    }
    let statement = statements[0];
    if matches!(statement.kind(), "pass_statement" | "raise_statement") {
        return PlaceholderBody::Placeholder;
    }
    if statement.kind() == "expression_statement"
        && statement
            .named_child(0)
            .is_some_and(|value| matches!(value.kind(), "string" | "concatenated_string"))
    {
        return PlaceholderBody::Placeholder;
    }
    PlaceholderBody::Concrete
}
