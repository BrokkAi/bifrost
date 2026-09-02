//! C++ structural spec for `query_code`.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_positional_argument_roles, attach_role_with_derived_name, attach_terminal_callee,
    first_named_child,
};
use brokk_bifrost_core::analyzer::structural::callable::{
    CallKind, CallShapeCoverage, CallSiteContext, CallSiteFacts,
};
use brokk_bifrost_core::analyzer::structural::edges::{
    INVERSE_REFERENCE_EDGE_SUPPORT, ReferenceEdgeSupport,
};
use brokk_bifrost_core::analyzer::structural::facts::Span;
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::materialization::{
    CPP_MATERIALIZATION_SUPPORT, DeclarationMaterializationSupport,
};
use brokk_bifrost_core::analyzer::structural::occurrences::{
    OccurrenceRole, OccurrenceRoleSupport,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    CALLABLE_APPLICABILITY_ONLY_SUPPORT, LexicalEnvironmentSupport,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    IdentityAxis, IdentityRouteSupport, RouteHopKind,
};
use brokk_bifrost_core::analyzer::structural::spec::{RoleSink, StructuralSpec};
use brokk_bifrost_core::hash::HashSet;
use tree_sitter::Node;

#[derive(Debug, Default)]
pub struct CppStructuralSpec;

pub static CPP_STRUCTURAL_SPEC: CppStructuralSpec = CppStructuralSpec;

pub const CPP_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("call_expression", NormalizedKind::Call),
    ("new_expression", NormalizedKind::Call),
    ("field_expression", NormalizedKind::FieldAccess),
    ("function_definition", NormalizedKind::Function),
    ("lambda_expression", NormalizedKind::Lambda),
    ("class_specifier", NormalizedKind::Class),
    ("struct_specifier", NormalizedKind::Class),
    ("union_specifier", NormalizedKind::Class),
    ("alias_declaration", NormalizedKind::Declaration),
    ("namespace_definition", NormalizedKind::Module),
    ("assignment_expression", NormalizedKind::Assignment),
    ("init_declarator", NormalizedKind::Assignment),
    ("preproc_include", NormalizedKind::Import),
    ("identifier", NormalizedKind::Identifier),
    ("field_identifier", NormalizedKind::Identifier),
    ("namespace_identifier", NormalizedKind::Identifier),
    ("qualified_identifier", NormalizedKind::Identifier),
    ("type_identifier", NormalizedKind::Identifier),
    ("template_function", NormalizedKind::Identifier),
    ("template_method", NormalizedKind::Identifier),
    ("template_type", NormalizedKind::Identifier),
    ("dependent_name", NormalizedKind::Identifier),
    ("destructor_name", NormalizedKind::Identifier),
    ("operator_name", NormalizedKind::Identifier),
    ("primitive_type", NormalizedKind::Identifier),
    ("char_literal", NormalizedKind::StringLiteral),
    ("string_literal", NormalizedKind::StringLiteral),
    ("raw_string_literal", NormalizedKind::StringLiteral),
    ("number_literal", NormalizedKind::NumericLiteral),
    ("true", NormalizedKind::BooleanLiteral),
    ("false", NormalizedKind::BooleanLiteral),
    ("null", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("throw_statement", NormalizedKind::Throw),
    ("catch_clause", NormalizedKind::Catch),
    ("if_statement", NormalizedKind::If),
    ("for_statement", NormalizedKind::Loop),
    ("while_statement", NormalizedKind::WhileLoop),
    ("do_statement", NormalizedKind::WhileLoop),
];

/// Whether tree-sitter recovered `.field = value` as a declaration child pair:
/// an `ERROR` containing only the anonymous dot immediately followed by an
/// `init_declarator` whose declarator is a real identifier.
///
/// This is intentionally narrower than rejecting declarators below `ERROR` in
/// general: macro-decorated declarations and ordinary comma-separated initialized
/// declarations also use recovery nodes and remain real declarations.
pub fn is_recovered_designator_init_declarator(node: Node<'_>) -> bool {
    if node.kind() != "init_declarator" {
        return false;
    }
    let Some(identifier) = node.child_by_field_name("declarator") else {
        return false;
    };
    if identifier.kind() != "identifier" || identifier.is_missing() {
        return false;
    }
    let Some(previous) = node.prev_named_sibling() else {
        return false;
    };
    if previous.kind() != "ERROR"
        || previous.named_child_count() != 0
        || previous.child_count() != 1
        || previous.end_byte() != node.start_byte()
    {
        return false;
    }
    previous.child(0).is_some_and(|child| {
        child.kind() == "."
            && !child.is_named()
            && child.start_byte() == previous.start_byte()
            && child.end_byte() == previous.end_byte()
    })
}

fn last_named_field_child<'tree>(node: Node<'tree>, field: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.children_by_field_name(field, &mut cursor)
        .filter(|child| child.is_named())
        .last()
}

/// The declared name of a `namespace_definition`.
///
/// `namespace a::b { }` spells a `nested_namespace_specifier` that nests to
/// the right, so the innermost specifier's last child is the terminal segment.
/// An anonymous namespace has no `name` field at all and stays unnamed.
fn namespace_name_node<'tree>(namespace: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = namespace.child_by_field_name("name")?;
    while current.kind() == "nested_namespace_specifier" {
        current = current.named_child(current.named_child_count().checked_sub(1)?)?;
    }
    Some(current)
}

fn declarator_name_node<'tree>(declarator: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = declarator;
    loop {
        match current.kind() {
            "identifier"
            | "field_identifier"
            | "namespace_identifier"
            | "type_identifier"
            | "destructor_name"
            | "operator_name"
            | "primitive_type" => return Some(current),
            "qualified_identifier" => current = last_named_field_child(current, "name")?,
            "dependent_name" | "template_function" | "template_method" | "template_type" => {
                current = current.child_by_field_name("name")?;
            }
            "function_declarator"
            | "pointer_declarator"
            | "array_declarator"
            | "init_declarator" => current = current.child_by_field_name("declarator")?,
            "reference_declarator" | "parenthesized_declarator" => {
                current = first_named_child(current)?;
            }
            _ => return None,
        }
    }
}

fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression;
    loop {
        match current.kind() {
            "identifier"
            | "field_identifier"
            | "namespace_identifier"
            | "type_identifier"
            | "destructor_name"
            | "operator_name"
            | "primitive_type"
            | "this" => return Some(current),
            "qualified_identifier" => current = last_named_field_child(current, "name")?,
            "dependent_name" | "template_function" | "template_method" | "template_type" => {
                current = current.child_by_field_name("name")?;
            }
            "field_expression" => current = current.child_by_field_name("field")?,
            "call_expression" => current = current.child_by_field_name("function")?,
            "new_expression" => current = current.child_by_field_name("type")?,
            "parenthesized_expression" => current = first_named_child(current)?,
            _ => return declarator_name_node(current),
        }
    }
}

fn attach_qualified_scope_receiver(sink: &mut RoleSink<'_>, function: Node<'_>) {
    if function.kind() != "qualified_identifier" {
        return;
    }
    if let Some(scope) = function.child_by_field_name("scope") {
        attach_role_with_derived_name(sink, Role::Receiver, scope, expression_name_node);
    }
}

fn qualified_declarator_node(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "qualified_identifier" {
            return Some(node);
        }
        node = node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| first_named_child(node))?;
    }
}

fn node_text<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    node.utf8_text(source.as_bytes()).ok()
}

fn scoped_function_definition(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("declarator")
        .and_then(qualified_declarator_node)
        .and_then(|qualified| qualified.child_by_field_name("scope"))
}

fn is_constructor_definition(node: Node<'_>, source: &str) -> bool {
    node.child_by_field_name("declarator")
        .and_then(qualified_declarator_node)
        .and_then(|qualified| {
            Some((
                expression_name_node(qualified.child_by_field_name("scope")?)?,
                expression_name_node(last_named_field_child(qualified, "name")?)?,
            ))
        })
        .is_some_and(|(scope, name)| node_text(scope, source) == node_text(name, source))
}

fn unquoted_include_span(node: Node<'_>) -> Option<Span> {
    if !matches!(node.kind(), "string_literal" | "system_lib_string") {
        return None;
    }
    let start = node.start_byte().checked_add(1)?;
    let end = node.end_byte().checked_sub(1)?;
    (start <= end).then_some(Span {
        start_byte: start,
        end_byte: end,
    })
}

/// The names of every function-like macro this translation unit defines, read
/// from `preproc_function_def` name fields.
///
/// The walk is iterative and descends only through preprocessor conditional
/// blocks, which is where a definition can nest. A `#define` written inside a
/// function body is not collected; that is a known and stated boundary, not an
/// approximation of one.
fn function_like_macro_names(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut names = HashSet::default();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        for index in 0..node.named_child_count() {
            let Some(child) = node.named_child(index) else {
                continue;
            };
            match child.kind() {
                "preproc_function_def" => {
                    if let Some(name) = child.child_by_field_name("name") {
                        names.insert(source[name.start_byte()..name.end_byte()].to_owned());
                    }
                }
                "preproc_if" | "preproc_ifdef" | "preproc_else" | "preproc_elif"
                | "preproc_elifdef" => stack.push(child),
                _ => {}
            }
        }
    }
    names
}

fn cpp_member_terminal_name<'tree>(field: Node<'tree>) -> Option<Node<'tree>> {
    let field = if field.kind() == "dependent_name" {
        first_named_child(field)?
    } else {
        field
    };
    expression_name_node(field)
}

/// Return the one identifier-bearing node that spells a member in a C++
/// `field_expression`.
///
/// The grammar permits the `field` child to be a qualified name, a dependent
/// name, a template method, or a destructor name. `expression_name_node`
/// already follows those wrappers to their terminal name. Walking upward from
/// the candidate and comparing that terminal node keeps receiver identifiers,
/// declaration names, field-designator labels, and path prefixes out of the
/// member role without looking at source text.
fn cpp_member_position(node: Node<'_>) -> Option<OccurrenceRole> {
    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "type_identifier" | "operator_name" | "destructor_name"
    ) {
        return None;
    }

    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "field_expression" {
            let field = parent.child_by_field_name("field")?;
            return cpp_member_terminal_name(field)
                .filter(|name| name.id() == node.id())
                .map(|_| OccurrenceRole::MemberPosition);
        }

        // These are the only named wrappers that can occur between the
        // terminal field name and its owning field expression.
        if matches!(
            parent.kind(),
            "qualified_identifier" | "dependent_name" | "template_method" | "destructor_name"
        ) {
            current = parent;
        } else {
            return None;
        }
    }
    None
}

impl StructuralSpec for CppStructuralSpec {
    fn language(&self) -> Language {
        Language::Cpp
    }

    fn supports_boolean_literal_value(&self) -> bool {
        true
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        CPP_KIND_TABLE
    }

    fn refine_kind(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        enclosing: Option<NormalizedKind>,
        source: &str,
        _context: &CallSiteContext,
    ) -> NormalizedKind {
        if kind == NormalizedKind::Function
            && (enclosing == Some(NormalizedKind::Class)
                || scoped_function_definition(node).is_some())
        {
            if is_constructor_definition(node, source) {
                NormalizedKind::Constructor
            } else {
                NormalizedKind::Method
            }
        } else {
            kind
        }
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        matches!(kind, NormalizedKind::Method | NormalizedKind::Constructor)
            || self
                .kind_table()
                .iter()
                .any(|(_, fact_kind)| fact_kind.satisfies(kind))
    }

    fn supports_role(&self, role: Role) -> bool {
        !matches!(
            role,
            Role::Kwarg | Role::Decorator | Role::Iterable | Role::Element
        )
    }

    fn call_site_context(&self, root: Node<'_>, source: &str) -> CallSiteContext {
        CallSiteContext::with_macro_derived_callees(function_like_macro_names(root, source))
    }

    /// A `new_expression` is a constructor call, and a call whose callee names
    /// a function-like macro of this translation unit has an argument list
    /// that belongs to the macro, not to the callable that finally runs
    /// (#1478). `CALL_TWICE(2)` parses as an ordinary call of two source
    /// arguments even when the expansion calls a three-parameter callable, so
    /// the honest answer is unknown coverage and no argument rows at all —
    /// never a fabricated list an exact-arity assertion could read as clean.
    ///
    /// The boundary is deliberate: only macros defined in this file are
    /// known here, because that is what this file's parse tree contains. A
    /// macro defined in an included header leaves the site exact, which is
    /// the same answer the analyzer gives today.
    fn call_site_facts(
        &self,
        node: Node<'_>,
        source: &str,
        context: &CallSiteContext,
    ) -> Option<CallSiteFacts> {
        if node.kind() == "new_expression" {
            return Some(CallSiteFacts::of_kind(CallKind::Constructor));
        }
        let callee = node.child_by_field_name("function")?;
        (callee.kind() == "identifier"
            && context.is_macro_derived_callee(&source[callee.start_byte()..callee.end_byte()]))
        .then(|| CallSiteFacts::of_coverage(CallShapeCoverage::UnknownMacroDerived))
    }

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        static SUPPORT: OccurrenceRoleSupport =
            OccurrenceRoleSupport::NONE.supported(OccurrenceRole::MemberPosition);
        &SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        // C and C++ classify no scopes, binding intervals, import binders or
        // package clause, but the call seams report per-candidate callable
        // applicability (#1478 M3). The per-axis table states exactly that.
        &CALLABLE_APPLICABILITY_ONLY_SUPPORT
    }

    fn materialization_support(&self) -> &DeclarationMaterializationSupport {
        &CPP_MATERIALIZATION_SUPPORT
    }

    fn reference_edge_support(&self) -> &ReferenceEdgeSupport {
        &INVERSE_REFERENCE_EDGE_SUPPORT
    }

    fn identity_route_support(&self) -> &IdentityRouteSupport {
        // C++'s occurrence adapter is shallow, so it claims no path axes. Its
        // declaration layer keeps prototype/body occurrences distinct, which
        // the physical-grouping axis carries; the declaration-definition peer
        // *relation* stays unclaimed until a producer emits typed peer rows
        // rather than merged ranges (see the #1475 ExecPlan Decision Log, M6,
        // and its follow-up issue).
        static SUPPORT: IdentityRouteSupport = IdentityRouteSupport::NONE
            .supported_axis(IdentityAxis::CanonicalIdentity)
            .supported_axis(IdentityAxis::PhysicalGrouping)
            .supported_relation(RouteHopKind::NestedOwner);
        &SUPPORT
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        if let Some(role) = cpp_member_position(node) {
            sink.occurrence_role(node, role);
        }

        match kind {
            NormalizedKind::Call => {
                let function_field = if node.kind() == "new_expression" {
                    "type"
                } else {
                    "function"
                };
                if let Some(function) = node.child_by_field_name(function_field) {
                    attach_terminal_callee(sink, function, expression_name_node(function));
                    if function.kind() == "field_expression"
                        && let Some(argument) = function.child_by_field_name("argument")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            argument,
                            expression_name_node,
                        );
                    }
                    attach_qualified_scope_receiver(sink, function);
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    attach_positional_argument_roles(sink, arguments, expression_name_node);
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(field) = node.child_by_field_name("field") {
                    attach_role_with_derived_name(sink, Role::Field, field, expression_name_node);
                    if let Some(name) = expression_name_node(field) {
                        sink.set_name(name);
                    }
                }
                if let Some(argument) = node.child_by_field_name("argument") {
                    attach_role_with_derived_name(
                        sink,
                        Role::Object,
                        argument,
                        expression_name_node,
                    );
                }
            }
            NormalizedKind::Function | NormalizedKind::Method | NormalizedKind::Constructor => {
                if let Some(name) = node
                    .child_by_field_name("declarator")
                    .and_then(declarator_name_node)
                {
                    sink.set_name(name);
                }
            }
            NormalizedKind::Module => {
                if let Some(name) = namespace_name_node(node) {
                    sink.set_name(name);
                }
            }
            NormalizedKind::Class | NormalizedKind::Declaration => {
                if let Some(name) = node
                    .child_by_field_name("name")
                    .and_then(declarator_name_node)
                    .or_else(|| node.child_by_field_name("name"))
                {
                    sink.set_name(name);
                }
            }
            NormalizedKind::Assignment => match node.kind() {
                "init_declarator" => {
                    if let Some(declarator) = node.child_by_field_name("declarator") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Left,
                            declarator,
                            declarator_name_node,
                        );
                        if let Some(name) = declarator_name_node(declarator) {
                            sink.set_name(name);
                        }
                    }
                    if let Some(value) = node.child_by_field_name("value") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            value,
                            expression_name_node,
                        );
                    }
                }
                "assignment_expression" => {
                    if let Some(left) = node.child_by_field_name("left") {
                        attach_role_with_derived_name(sink, Role::Left, left, expression_name_node);
                    }
                    if let Some(right) = node.child_by_field_name("right") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            right,
                            expression_name_node,
                        );
                    }
                }
                _ => {}
            },
            NormalizedKind::Import => {
                if let Some(path) = node.child_by_field_name("path") {
                    if let Some(name) = unquoted_include_span(path) {
                        sink.role_named_span(Role::Module, path, name);
                    } else {
                        attach_role_with_derived_name(
                            sink,
                            Role::Module,
                            path,
                            expression_name_node,
                        );
                    }
                }
            }
            NormalizedKind::Identifier => match expression_name_node(node) {
                Some(name) => sink.set_name(name),
                None => sink.set_name(node),
            },
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::cpp_member_position;
    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;
    use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
    use tree_sitter::Parser;

    fn member_occurrences(source: &str) -> Vec<(usize, &str, OccurrenceRole)> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("C++ parse");
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let mut found = Vec::new();
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
            if let Some(role) = cpp_member_position(node) {
                found.push((
                    node.start_byte(),
                    &source[node.start_byte()..node.end_byte()],
                    role,
                ));
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    pending.push(child);
                }
            }
        }
        found
    }

    #[test]
    fn cpp_member_position_is_limited_to_member_access_and_calls() {
        let source = concat!(
            "struct Widget {\n",
            "    int value;\n",
            "    int method(int label) {\n",
            "        return this->value + label.value + label.method()\n",
            "            + label.template convert<int>() + label.ns::member;\n",
            "    }\n",
            "};\n",
            "int build(Widget widget) {\n",
            "    Widget result{.value = widget.value};\n",
            "    return widget.method(result.value);\n",
            "}\n",
        );
        let found = member_occurrences(source);
        let member_texts = found
            .iter()
            .map(|(_, text, role)| (*text, *role))
            .collect::<Vec<_>>();

        assert_eq!(
            member_texts,
            vec![
                ("value", OccurrenceRole::MemberPosition),
                ("value", OccurrenceRole::MemberPosition),
                ("method", OccurrenceRole::MemberPosition),
                ("convert", OccurrenceRole::MemberPosition),
                ("member", OccurrenceRole::MemberPosition),
                ("value", OccurrenceRole::MemberPosition),
                ("method", OccurrenceRole::MemberPosition),
                ("value", OccurrenceRole::MemberPosition),
            ]
        );

        let at = |needle: &str| source.find(needle).expect("fixture token");
        for receiver in ["this->", "label.value", "widget.value", "result.value"] {
            let receiver_start = at(receiver);
            assert!(
                found.iter().all(|(offset, _, _)| *offset != receiver_start),
                "receiver was classified: {receiver:?}"
            );
        }
        let non_members = [
            at("Widget {"),
            at("int value") + "int ".len(),
            at("int method") + "int ".len(),
            at(".value =") + 1,
        ];
        for unrelated_start in non_members {
            assert!(
                found
                    .iter()
                    .all(|(offset, _, _)| *offset != unrelated_start),
                "non-member identifier at byte {unrelated_start} was classified"
            );
        }
    }

    #[test]
    fn cpp_member_position_support_declares_only_member_position() {
        let support = super::CPP_STRUCTURAL_SPEC.occurrence_role_support();
        assert!(support.is_supported(OccurrenceRole::MemberPosition));
        for role in [
            OccurrenceRole::ReceiverPosition,
            OccurrenceRole::LabelOrKey,
            OccurrenceRole::DeclarationName,
            OccurrenceRole::ValueReference,
        ] {
            assert!(
                !support.is_supported(role),
                "unexpected C++ support for {role:?}"
            );
        }
    }
}
