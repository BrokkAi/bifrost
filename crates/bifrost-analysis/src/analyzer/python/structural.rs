//! Python structural spec: maps tree-sitter-python node types onto the
//! normalized kind vocabulary and extracts role edges from AST fields.
//! See `src/analyzer/structural/spec.rs` for the contract and
//! `.agent/ISSUE_328_SEARCH_AST_EXECPLAN.md` for the design.

use crate::analyzer::Language;
use crate::analyzer::structural::adapter_helpers::{
    attach_argument_role_with_derived_name, attach_role_with_derived_name, attach_terminal_callee,
    field_name_in_parent, first_named_child,
};
use crate::analyzer::structural::{
    Namespace, NormalizedKind, OccurrenceRole, OccurrenceRoleSupport, Role, RoleSink,
    StructuralSpec, default_occurrence_namespace,
};
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
    ("for_statement", NormalizedKind::ForLoop),
    ("while_statement", NormalizedKind::WhileLoop),
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

static PYTHON_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport = OccurrenceRoleSupport::NONE
    .supported(OccurrenceRole::DeclarationName)
    .supported(OccurrenceRole::Binder)
    .supported(OccurrenceRole::LabelOrKey)
    .supported(OccurrenceRole::TypeOperand)
    .supported(OccurrenceRole::PathSegment)
    .supported(OccurrenceRole::ImportAlias)
    .supported(OccurrenceRole::ImportTarget)
    .supported(OccurrenceRole::ReceiverPosition)
    .supported(OccurrenceRole::MemberPosition)
    .supported(OccurrenceRole::ValueReference);

/// Whether a `dotted_name` names an imported module rather than an ordinary
/// attribute chain, which decides whether its tail is an import target.
fn python_dotted_name_is_import(dotted_name: Node<'_>) -> bool {
    let mut current = dotted_name;
    loop {
        let Some(parent) = current.parent() else {
            return false;
        };
        match parent.kind() {
            "import_statement" | "import_from_statement" | "future_import_statement" => {
                return true;
            }
            "aliased_import" | "dotted_name" => current = parent,
            _ => return false,
        }
    }
}

/// Classify one Python identifier token by its AST position.
///
/// Python has no separate type-identifier node, so annotation operands are
/// recognized by their enclosing `type` node — the same field the parser uses
/// to separate `def f(x: T)`'s binder from its annotation.
fn python_occurrence_role(node: Node<'_>) -> Option<OccurrenceRole> {
    if node.kind() != "identifier" {
        return None;
    }
    let parent = node.parent()?;
    let field = field_name_in_parent(parent, node);
    let role = match parent.kind() {
        "function_definition" | "class_definition" if field == Some("name") => {
            OccurrenceRole::DeclarationName
        }
        // Every annotation, return type and type-alias operand is wrapped in a
        // `type` node; `generic_type`/`type_parameter` nest inside one.
        "type" | "generic_type" | "type_parameter" | "constrained_type" | "union_type" => {
            OccurrenceRole::TypeOperand
        }
        "parameters"
        | "lambda_parameters"
        | "typed_parameter"
        | "list_splat_pattern"
        | "dictionary_splat_pattern"
        | "tuple_pattern"
        | "list_pattern"
        | "pattern_list"
        | "as_pattern_target" => OccurrenceRole::Binder,
        "default_parameter" | "typed_default_parameter" if field == Some("name") => {
            OccurrenceRole::Binder
        }
        "for_statement" | "for_in_clause" if field == Some("left") => OccurrenceRole::Binder,
        "keyword_argument" if field == Some("name") => OccurrenceRole::LabelOrKey,
        "attribute" => match field {
            Some("attribute") => OccurrenceRole::MemberPosition,
            Some("object") => OccurrenceRole::ReceiverPosition,
            _ => OccurrenceRole::ValueReference,
        },
        "aliased_import" if field == Some("alias") => OccurrenceRole::ImportAlias,
        "import_from_statement" if field == Some("name") => OccurrenceRole::ImportTarget,
        "dotted_name" => {
            let is_tail =
                parent.named_child(parent.named_child_count().saturating_sub(1)) == Some(node);
            match (is_tail, python_dotted_name_is_import(parent)) {
                (true, true) => OccurrenceRole::ImportTarget,
                (true, false) => OccurrenceRole::ValueReference,
                (false, _) => OccurrenceRole::PathSegment,
            }
        }
        _ => OccurrenceRole::ValueReference,
    };
    Some(role)
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

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &PYTHON_OCCURRENCE_ROLE_SUPPORT
    }

    /// Python only classifies a scope segment inside a `dotted_name`, and every
    /// non-tail segment of a dotted name is a module.
    fn occurrence_namespace(
        &self,
        role: OccurrenceRole,
        declares: Option<NormalizedKind>,
    ) -> Option<Namespace> {
        match role {
            OccurrenceRole::PathSegment => Some(Namespace::Module),
            _ => default_occurrence_namespace(role, declares),
        }
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        if let Some(role) = python_occurrence_role(node) {
            sink.occurrence_role(node, role);
        }
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

    use crate::analyzer::structural::adapter_helpers::{
        assert_occurrence_role, occurrence_roles_of,
    };

    /// Python's role trap is the annotation: `label: str` puts a binder and a
    /// type operand one token apart, distinguished only by the `type` node the
    /// parser wraps the annotation in.
    #[test]
    fn python_separates_annotations_from_the_parameters_they_annotate() {
        let source = concat!(
            "import os.path\n",
            "from typing import List as Sequence\n",
            "\n",
            "class Widget:\n",
            "    def render(self, label: str, count: int = 0) -> Sequence:\n",
            "        return os.path.join(label, key=count)\n",
        );
        let found = occurrence_roles_of(
            &PYTHON_STRUCTURAL_SPEC,
            &tree_sitter_python::LANGUAGE.into(),
            source,
        );

        let at = |needle: &str| source.find(needle).expect("fixture token");
        assert_occurrence_role(&found, at("os.path"), OccurrenceRole::PathSegment);
        assert_occurrence_role(&found, at("path\n"), OccurrenceRole::ImportTarget);
        assert_occurrence_role(&found, at("List as"), OccurrenceRole::ImportTarget);
        assert_occurrence_role(&found, at("Sequence\n"), OccurrenceRole::ImportAlias);
        assert_occurrence_role(&found, at("Widget"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("render"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("label: str"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("str,"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("count: int"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("int ="), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("Sequence:"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("os.path.join"), OccurrenceRole::ReceiverPosition);
        assert_occurrence_role(&found, at("join"), OccurrenceRole::MemberPosition);
        assert_occurrence_role(&found, at("label,"), OccurrenceRole::ValueReference);
        assert_occurrence_role(&found, at("key="), OccurrenceRole::LabelOrKey);
    }

    #[test]
    fn python_emits_only_roles_it_declares_as_supported() {
        let source = "def f(a):\n    return a.b(a)\n";
        let found = occurrence_roles_of(
            &PYTHON_STRUCTURAL_SPEC,
            &tree_sitter_python::LANGUAGE.into(),
            source,
        );
        assert!(!found.is_empty());
        for (_, text, role) in &found {
            assert!(
                PYTHON_STRUCTURAL_SPEC
                    .occurrence_role_support()
                    .is_supported(*role),
                "python emitted undeclared role {role:?} for {text:?}"
            );
        }
    }

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
