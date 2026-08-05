//! Python structural spec: maps tree-sitter-python node types onto the
//! normalized kind vocabulary and extracts role edges from AST fields.
//! See `src/analyzer/structural/spec.rs` for the contract and
//! `.agent/ISSUE_328_SEARCH_AST_EXECPLAN.md` for the design.

use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_argument_role_with_derived_name, attach_role_with_derived_name, attach_terminal_callee,
    field_name_in_parent, first_named_child, nearest_ancestor, node_range,
};
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::occurrences::{
    Namespace, OccurrenceRole, OccurrenceRoleSupport, default_occurrence_namespace,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    BindingActivation, BindingKind, DEEP_LEXICAL_ENVIRONMENT_SUPPORT, HoistingClass,
    LexicalEnvironmentSupport,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    DEEP_IDENTITY_AXES, IdentityRouteSupport, RouteHopKind,
};
use brokk_bifrost_core::analyzer::structural::spec::{EmbeddedLeafFact, RoleSink, StructuralSpec};
use brokk_bifrost_core::analyzer::{Language, Range};
use brokk_bifrost_core::cancellation::CancellationToken;
use tree_sitter::Node;

use crate::syntax::{
    expression_name_node, python_deferred_annotation_identifier_ranges,
    python_node_is_in_annotation,
};

#[derive(Debug, Default)]
pub struct PythonStructuralSpec;

pub static PYTHON_STRUCTURAL_SPEC: PythonStructuralSpec = PythonStructuralSpec;

/// Grammar node-type → normalized kind. Every name here must exist in the
/// tree-sitter-python grammar; `tests::python_kind_table_matches_grammar`
/// asserts that, so a grammar bump that renames a node fails loudly.
pub const PYTHON_KIND_TABLE: &[(&str, NormalizedKind)] = &[
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
    // Python's indented suite. The module node is deliberately absent: a file
    // scope is not a statement list nested inside another one, and making the
    // root a fact in one language only would give Python a scope shape no
    // other adapter has.
    ("block", NormalizedKind::Block),
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

/// Whether a `def` declares a method, that is, whether the suite it sits in
/// belongs to a `class_definition`.
///
/// This reads the parse tree rather than the nearest enclosing normalized kind
/// because the suite between a class and its methods is itself a normalized
/// node now (`NormalizedKind::Block`, issue #1474). Walking the concrete
/// ancestors is also the more direct statement of the rule: a nested `def`
/// inside a method reaches its enclosing `function_definition` first and stays
/// a function.
fn python_definition_is_method(definition: Node<'_>) -> bool {
    let mut current = definition;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "class_definition" => return true,
            // The suite that holds the members, and the wrapper a decorated
            // definition sits in, are pass-through on the way to the owner.
            "block" | "decorated_definition" => current = parent,
            _ => return false,
        }
    }
    false
}

/// The binding one Python binder token introduces, and the interval it is in
/// effect over.
///
/// Python's function locals are scope-categorical rather than positional: a
/// name assigned anywhere in a function body is a local of that function for
/// the whole body, which is why a read above the assignment is an
/// `UnboundLocalError` rather than a read of an outer name. That is exactly
/// `ScopeWide`. The one positional exception is a comprehension target, which
/// lives in the comprehension's own implicit scope; the same exception
/// `analyzer::python::bindings` records as `PythonComprehensionBinding`.
fn python_binding_activation(binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
    let form = nearest_ancestor(binder, |kind| {
        matches!(
            kind,
            "parameters"
                | "lambda_parameters"
                | "for_statement"
                | "for_in_clause"
                | "as_pattern"
                | "list_comprehension"
                | "set_comprehension"
                | "dictionary_comprehension"
                | "generator_expression"
                | "function_definition"
        )
    })?;
    match form.kind() {
        "parameters" | "lambda_parameters" | "function_definition" => Some(BindingActivation {
            kind: BindingKind::Parameter,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
        "for_in_clause" => {
            // A comprehension clause binds only inside the comprehension.
            let comprehension = nearest_ancestor(form, |kind| {
                matches!(
                    kind,
                    "list_comprehension"
                        | "set_comprehension"
                        | "dictionary_comprehension"
                        | "generator_expression"
                )
            })?;
            Some(BindingActivation {
                kind: BindingKind::LoopVariable,
                hoisting: HoistingClass::DeclaredHead,
                activation: node_range(comprehension),
            })
        }
        "for_statement" => Some(BindingActivation {
            kind: BindingKind::LoopVariable,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
        "as_pattern" => Some(BindingActivation {
            kind: BindingKind::PatternBinder,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
        _ => Some(BindingActivation {
            kind: BindingKind::Local,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
    }
}

impl StructuralSpec for PythonStructuralSpec {
    fn language(&self) -> Language {
        Language::Python
    }

    fn identity_route_support(&self) -> &IdentityRouteSupport {
        // `import x as y` is an alias. Python's re-export shapes (an
        // `__init__` facade, `__all__`) are conventions over files rather
        // than statements a parse tree names, so the relation stays
        // unclaimed until a producer models them (see the #1475 ExecPlan
        // Decision Log, M3).
        static SUPPORT: IdentityRouteSupport = DEEP_IDENTITY_AXES
            .supported_relation(RouteHopKind::Alias)
            .supported_relation(RouteHopKind::Import)
            .supported_relation(RouteHopKind::NestedOwner);
        &SUPPORT
    }

    /// Python's one qualified-path chain is `dotted_name`, which is flat
    /// rather than left-nested: its named children are the segments in order.
    fn qualified_path_root<'tree>(&self, token: Node<'tree>) -> Option<Node<'tree>> {
        if token.kind() != "identifier" {
            return None;
        }
        token
            .parent()
            .filter(|parent| parent.kind() == "dotted_name")
    }

    fn path_segment_tokens<'tree>(&self, root: Node<'tree>) -> Vec<Node<'tree>> {
        if root.kind() != "dotted_name" {
            return Vec::new();
        }
        let mut cursor = root.walk();
        root.named_children(&mut cursor)
            .filter(|child| child.kind() == "identifier")
            .collect()
    }

    fn indirection_relation(&self, token: Node<'_>) -> Option<RouteHopKind> {
        nearest_ancestor(token, |kind| {
            matches!(kind, "import_statement" | "import_from_statement")
        })
        .map(|_| RouteHopKind::Import)
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        PYTHON_KIND_TABLE
    }

    fn refine_kind(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        _enclosing: Option<NormalizedKind>,
        _source: &str,
    ) -> NormalizedKind {
        if kind == NormalizedKind::Function && python_definition_is_method(node) {
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

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        &DEEP_LEXICAL_ENVIRONMENT_SUPPORT
    }

    fn binding_activation(&self, binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
        python_binding_activation(binder, scope)
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

    fn embedded_leaf_facts(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        source: &str,
        cancellation: Option<&CancellationToken>,
    ) -> Vec<EmbeddedLeafFact> {
        if kind != NormalizedKind::StringLiteral
            || node.kind() != "string"
            || !python_node_is_in_annotation(node)
        {
            return Vec::new();
        }

        python_deferred_annotation_identifier_ranges(node, source, cancellation)
            .unwrap_or_default()
            .into_iter()
            .map(|range| EmbeddedLeafFact {
                kind: NormalizedKind::Identifier,
                range,
                occurrence_role: OccurrenceRole::TypeOperand,
            })
            .collect()
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
