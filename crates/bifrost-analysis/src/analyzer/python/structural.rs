//! Python structural spec: maps tree-sitter-python node types onto the
//! normalized kind vocabulary and extracts role edges from AST fields.
//! See `src/analyzer/structural/spec.rs` for the contract and
//! `.agent/ISSUE_328_SEARCH_AST_EXECPLAN.md` for the design.

use crate::analyzer::Language;
use crate::analyzer::structural::adapter_helpers::{
    attach_argument_role_with_derived_name, attach_role_with_derived_name, attach_terminal_callee,
    first_named_child,
};
use crate::analyzer::structural::{NormalizedKind, Role, RoleSink, StructuralSpec};
use tree_sitter::Node;

use super::syntax::expression_name_node;

#[derive(Debug, Default)]
pub(crate) struct PythonStructuralSpec;

pub(crate) static PYTHON_STRUCTURAL_SPEC: PythonStructuralSpec = PythonStructuralSpec;

/// Grammar node-type → normalized kind. Every name here must exist in the
/// tree-sitter-python grammar; `tests::python_kind_table_matches_grammar`
/// asserts that, so a grammar bump that renames a node fails loudly.
const PYTHON_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("call", NormalizedKind::Call),
    ("attribute", NormalizedKind::FieldAccess),
    ("function_definition", NormalizedKind::Function),
    ("lambda", NormalizedKind::Lambda),
    ("class_definition", NormalizedKind::Class),
    ("assignment", NormalizedKind::Assignment),
    ("import_statement", NormalizedKind::Import),
    ("import_from_statement", NormalizedKind::Import),
    ("identifier", NormalizedKind::Identifier),
    ("string", NormalizedKind::StringLiteral),
    ("concatenated_string", NormalizedKind::StringLiteral),
    ("integer", NormalizedKind::NumericLiteral),
    ("float", NormalizedKind::NumericLiteral),
    ("true", NormalizedKind::BooleanLiteral),
    ("false", NormalizedKind::BooleanLiteral),
    ("none", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("raise_statement", NormalizedKind::Throw),
    ("except_clause", NormalizedKind::Catch),
    ("if_statement", NormalizedKind::If),
    ("for_statement", NormalizedKind::Loop),
    ("while_statement", NormalizedKind::Loop),
    ("decorator", NormalizedKind::Decorator),
];

/// Attach `decorators` edges for a definition wrapped in Python's
/// `decorated_definition` node (which itself is not normalized).
fn attach_decorators(sink: &mut RoleSink<'_>, definition: Node<'_>) {
    let Some(parent) = definition.parent() else {
        return;
    };
    if parent.kind() != "decorated_definition" {
        return;
    }
    for index in 0..parent.named_child_count() {
        let Some(child) = parent.named_child(index) else {
            continue;
        };
        if child.kind() == "decorator" {
            attach_role_with_derived_name(sink, Role::Decorator, child, expression_name_node);
        }
    }
}

impl StructuralSpec for PythonStructuralSpec {
    fn language(&self) -> Language {
        Language::Python
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        PYTHON_KIND_TABLE
    }

    fn refine_kind(
        &self,
        _node: Node<'_>,
        kind: NormalizedKind,
        enclosing: Option<NormalizedKind>,
        _source: &str,
    ) -> NormalizedKind {
        // A def whose nearest normalized ancestor is a class body is a
        // method; nested defs inside methods stay functions.
        if kind == NormalizedKind::Function && enclosing == Some(NormalizedKind::Class) {
            NormalizedKind::Method
        } else {
            kind
        }
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        kind != NormalizedKind::Assignment || node.child_by_field_name("right").is_some()
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        kind == NormalizedKind::Method
            || self
                .kind_table()
                .iter()
                .any(|(_, fact_kind)| fact_kind.satisfies(kind))
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        match kind {
            NormalizedKind::Call => {
                if let Some(function) = node.child_by_field_name("function") {
                    // A call's own name is its callee's, so
                    // { "kind": "call", "name": "eval" } reads naturally.
                    attach_terminal_callee(sink, function, expression_name_node(function));
                    if function.kind() == "attribute"
                        && let Some(object) = function.child_by_field_name("object")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            object,
                            expression_name_node,
                        );
                    }
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    for index in 0..arguments.named_child_count() {
                        if !sink.should_continue() {
                            break;
                        }
                        let Some(argument) = arguments.named_child(index) else {
                            continue;
                        };
                        match argument.kind() {
                            "comment" => {}
                            "keyword_argument" => {
                                if let (Some(keyword), Some(value)) = (
                                    argument.child_by_field_name("name"),
                                    argument.child_by_field_name("value"),
                                ) {
                                    sink.kwarg(keyword, value);
                                }
                            }
                            _ => attach_argument_role_with_derived_name(
                                sink,
                                argument,
                                expression_name_node,
                            ),
                        }
                    }
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(attribute) = node.child_by_field_name("attribute") {
                    sink.set_name(attribute);
                    sink.role_named(Role::Field, attribute, attribute);
                }
                if let Some(object) = node.child_by_field_name("object") {
                    attach_role_with_derived_name(sink, Role::Object, object, expression_name_node);
                }
            }
            NormalizedKind::Function | NormalizedKind::Method | NormalizedKind::Class => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
                attach_decorators(sink, node);
            }
            NormalizedKind::Assignment => {
                if let Some(left) = node.child_by_field_name("left") {
                    attach_role_with_derived_name(sink, Role::Left, left, expression_name_node);
                }
                if let Some(right) = node.child_by_field_name("right") {
                    attach_role_with_derived_name(sink, Role::Right, right, expression_name_node);
                }
            }
            NormalizedKind::Import => match node.kind() {
                "import_from_statement" => {
                    if let Some(module) = node.child_by_field_name("module_name") {
                        sink.role_named(Role::Module, module, module);
                    }
                }
                _ => {
                    for index in 0..node.named_child_count() {
                        if !sink.should_continue() {
                            break;
                        }
                        let Some(child) = node.named_child(index) else {
                            continue;
                        };
                        match child.kind() {
                            "dotted_name" => sink.role_named(Role::Module, child, child),
                            "aliased_import" => {
                                if let Some(name) = child.child_by_field_name("name") {
                                    sink.role_named(Role::Module, name, name);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            },
            NormalizedKind::Identifier => sink.set_name(node),
            NormalizedKind::Decorator => {
                if let Some(name) = first_named_child(node).and_then(expression_name_node) {
                    sink.set_name(name);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod structural_spec_tests {
    use super::*;

    /// Every node-type name in the kind table must exist in the grammar, so a
    /// tree-sitter-python bump that renames nodes fails here instead of
    /// silently dropping facts.
    #[test]
    fn python_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_python::LANGUAGE.into(),
            "tree-sitter-python",
            PYTHON_KIND_TABLE,
        );
    }
}
