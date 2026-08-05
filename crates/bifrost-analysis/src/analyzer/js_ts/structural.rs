//! Shared JavaScript/TypeScript structural specs for `query_code`.

use crate::analyzer::structural::adapter_helpers::{
    attach_positional_argument_roles, attach_role_with_derived_name, attach_terminal_callee,
    field_name_in_parent, first_named_child, nearest_ancestor, node_range,
};
use crate::analyzer::structural::adapter_helpers::{
    linear_chain_tokens, qualified_chain_root, spelled_generic_arity,
};
use crate::analyzer::structural::{
    BindingActivation, BindingKind, DEEP_LEXICAL_ENVIRONMENT_SUPPORT, HoistingClass,
    LexicalEnvironmentSupport, Namespace, NormalizedKind, OccurrenceRole, OccurrenceRoleSupport,
    Role, RoleSink, Span, StructuralSpec, default_occurrence_namespace,
};
use crate::analyzer::structural::{DEEP_IDENTITY_AXES, IdentityRouteSupport, RouteHopKind};
use crate::analyzer::{Language, Range};
use tree_sitter::Node;

/// The left-nested qualified chains of both grammars: expression namespace
/// qualifiers (`nested_identifier`, naming its segment through `property`)
/// and TypeScript qualified type names (`nested_type_identifier`, through
/// `name`).
const JS_TS_PATH_CHAIN: &[(&str, Option<&str>)] = &[
    ("nested_identifier", Some("property")),
    ("nested_type_identifier", Some("name")),
];

#[derive(Debug)]
pub(crate) struct JsTsStructuralSpec {
    language: Language,
}

pub(crate) static JAVASCRIPT_STRUCTURAL_SPEC: JsTsStructuralSpec = JsTsStructuralSpec {
    language: Language::JavaScript,
};

pub(crate) static TYPESCRIPT_STRUCTURAL_SPEC: JsTsStructuralSpec = JsTsStructuralSpec {
    language: Language::TypeScript,
};

macro_rules! js_ts_kind_table {
    ($($ts_only:expr,)*) => {
        &[
            ("call_expression", NormalizedKind::Call),
            ("new_expression", NormalizedKind::Call),
            ("member_expression", NormalizedKind::FieldAccess),
            ("function_declaration", NormalizedKind::Function),
            ("function_expression", NormalizedKind::Function),
            ("generator_function_declaration", NormalizedKind::Function),
            ("generator_function", NormalizedKind::Function),
            ("method_definition", NormalizedKind::Method),
            ("arrow_function", NormalizedKind::Lambda),
            ("class", NormalizedKind::Class),
            ("class_declaration", NormalizedKind::Class),
            ("assignment_expression", NormalizedKind::Assignment),
            ("variable_declarator", NormalizedKind::Assignment),
            ("import_statement", NormalizedKind::Import),
            ("identifier", NormalizedKind::Identifier),
            ("property_identifier", NormalizedKind::Identifier),
            ("private_property_identifier", NormalizedKind::Identifier),
            ("shorthand_property_identifier", NormalizedKind::Identifier),
            (
                "shorthand_property_identifier_pattern",
                NormalizedKind::Identifier,
            ),
            ("string", NormalizedKind::StringLiteral),
            ("template_string", NormalizedKind::StringLiteral),
            ("number", NormalizedKind::NumericLiteral),
            ("true", NormalizedKind::BooleanLiteral),
            ("false", NormalizedKind::BooleanLiteral),
            ("null", NormalizedKind::NullLiteral),
            ("return_statement", NormalizedKind::Return),
            ("throw_statement", NormalizedKind::Throw),
            ("catch_clause", NormalizedKind::Catch),
            ("if_statement", NormalizedKind::If),
            ("for_statement", NormalizedKind::Loop),
            ("for_in_statement", NormalizedKind::ForLoop),
            ("while_statement", NormalizedKind::WhileLoop),
            ("do_statement", NormalizedKind::WhileLoop),
            // `statement_block` is every braced body in both grammars;
            // `switch_body` is the statement list of a switch.
            ("statement_block", NormalizedKind::Block),
            ("switch_body", NormalizedKind::Block),
            ("decorator", NormalizedKind::Decorator),
            $($ts_only,)*
        ]
    };
}

const JS_KIND_TABLE: &[(&str, NormalizedKind)] = js_ts_kind_table!();

const TS_KIND_TABLE: &[(&str, NormalizedKind)] = js_ts_kind_table!(
    ("abstract_class_declaration", NormalizedKind::Class),
    ("interface_declaration", NormalizedKind::Class),
    ("enum_declaration", NormalizedKind::Class),
    ("type_alias_declaration", NormalizedKind::Declaration),
    ("type_identifier", NormalizedKind::Identifier),
    ("nested_identifier", NormalizedKind::Identifier),
);

fn node_text<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    node.utf8_text(source.as_bytes()).ok()
}

fn unquoted_string_span(node: Node<'_>) -> Option<Span> {
    if node.kind() != "string" {
        return None;
    }
    let start = node.start_byte().checked_add(1)?;
    let end = node.end_byte().checked_sub(1)?;
    (start <= end).then_some(Span {
        start_byte: start,
        end_byte: end,
    })
}

fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression;
    loop {
        match current.kind() {
            "identifier"
            | "property_identifier"
            | "private_property_identifier"
            | "shorthand_property_identifier"
            | "shorthand_property_identifier_pattern"
            | "type_identifier" => return Some(current),
            "nested_identifier" | "member_expression" => {
                current = current.child_by_field_name("property")?;
            }
            "call_expression" => current = current.child_by_field_name("function")?,
            "new_expression" => current = current.child_by_field_name("constructor")?,
            "decorator" | "parenthesized_expression" | "non_null_expression" => {
                current = first_named_child(current)?;
            }
            _ => return None,
        }
    }
}

fn attach_argument_roles(sink: &mut RoleSink<'_>, arguments: Node<'_>) {
    if arguments.kind() == "template_string" {
        sink.role(Role::Arg, arguments);
        return;
    }
    attach_positional_argument_roles(sink, arguments, expression_name_node);
}

fn attach_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    for index in 0..declaration.named_child_count() {
        let Some(child) = declaration.named_child(index) else {
            continue;
        };
        if child.kind() == "decorator" {
            attach_role_with_derived_name(sink, Role::Decorator, child, expression_name_node);
        }
    }
    attach_preceding_class_body_decorators(sink, declaration);
}

fn attach_preceding_class_body_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    let Some(parent) = declaration.parent() else {
        return;
    };
    if parent.kind() != "class_body" {
        return;
    }
    let mut pending = Vec::new();
    for index in 0..parent.named_child_count() {
        let Some(child) = parent.named_child(index) else {
            continue;
        };
        if child.id() == declaration.id() {
            for decorator in pending {
                attach_role_with_derived_name(
                    sink,
                    Role::Decorator,
                    decorator,
                    expression_name_node,
                );
            }
            return;
        }
        if child.kind() == "decorator" {
            pending.push(child);
        } else {
            pending.clear();
        }
    }
}

static JS_TS_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport = OccurrenceRoleSupport::NONE
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

const JS_TS_DECLARATION_HEADS: &[&str] = &[
    "function_declaration",
    "generator_function_declaration",
    "function_expression",
    "generator_function",
    "class_declaration",
    "abstract_class_declaration",
    "class",
    "method_definition",
    "abstract_method_signature",
    "interface_declaration",
    "enum_declaration",
    "type_alias_declaration",
    "module",
    "internal_module",
    "public_field_definition",
    "property_signature",
    "method_signature",
    "enum_assignment",
    "type_parameter",
];

/// Whether a binding pattern position encloses this node, which is what
/// separates `const { a } = x` (a binder) from `f({ a })` (a read of `a`).
///
/// The two shapes use different grammar nodes —
/// `shorthand_property_identifier_pattern` inside `object_pattern` versus
/// `shorthand_property_identifier` inside `object` — so this never has to guess
/// from source text.
fn js_ts_is_binding_pattern(node: Node<'_>) -> bool {
    let mut current = node;
    // At least one destructuring node must sit between the token and the
    // binding form; otherwise `const x = source` would bind its right-hand
    // side as eagerly as its left.
    let mut through_pattern = false;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "object_pattern"
            | "array_pattern"
            | "rest_pattern"
            | "pair_pattern"
            | "object_assignment_pattern"
            | "assignment_pattern"
            | "formal_parameters"
            | "required_parameter"
            | "optional_parameter" => {
                through_pattern = true;
                current = parent;
            }
            "variable_declarator"
            | "for_in_statement"
            | "catch_clause"
            | "arrow_function"
            | "function_declaration"
            | "function_expression"
            | "method_definition" => {
                return through_pattern;
            }
            _ => return false,
        }
    }
    false
}

/// Classify one JavaScript/TypeScript identifier token by its AST position.
fn js_ts_occurrence_role(node: Node<'_>) -> Option<OccurrenceRole> {
    let node_kind = node.kind();
    if !matches!(
        node_kind,
        "identifier"
            | "property_identifier"
            | "private_property_identifier"
            | "shorthand_property_identifier"
            | "shorthand_property_identifier_pattern"
            | "type_identifier"
    ) {
        return None;
    }
    if node_kind == "shorthand_property_identifier_pattern" {
        return Some(OccurrenceRole::Binder);
    }
    if node_kind == "shorthand_property_identifier" {
        return Some(OccurrenceRole::ValueReference);
    }

    let mut anchor = node;
    let mut parent = anchor.parent()?;
    while parent.kind() == "nested_identifier" {
        if field_name_in_parent(parent, anchor) != Some("property") {
            return Some(OccurrenceRole::PathSegment);
        }
        anchor = parent;
        parent = anchor.parent()?;
    }

    let field = field_name_in_parent(parent, anchor);
    let parent_kind = parent.kind();
    let role = match parent_kind {
        "import_specifier" | "export_specifier" => match field {
            Some("alias") => OccurrenceRole::ImportAlias,
            _ => OccurrenceRole::ImportTarget,
        },
        "namespace_import" | "import_clause" => OccurrenceRole::ImportAlias,
        "member_expression" => match field {
            Some("property") => OccurrenceRole::MemberPosition,
            Some("object") => OccurrenceRole::ReceiverPosition,
            _ => OccurrenceRole::ValueReference,
        },
        "pair" if field == Some("key") => OccurrenceRole::LabelOrKey,
        "pair_pattern" if field == Some("key") => OccurrenceRole::LabelOrKey,
        _ if field == Some("name") && JS_TS_DECLARATION_HEADS.contains(&parent_kind) => {
            OccurrenceRole::DeclarationName
        }
        "catch_clause" if field == Some("parameter") => OccurrenceRole::Binder,
        "for_in_statement" if field == Some("left") => OccurrenceRole::Binder,
        "variable_declarator" if field == Some("name") => OccurrenceRole::Binder,
        "required_parameter" | "optional_parameter" if field == Some("pattern") => {
            OccurrenceRole::Binder
        }
        "formal_parameters" | "rest_pattern" => OccurrenceRole::Binder,
        _ if node_kind == "property_identifier" || node_kind == "private_property_identifier" => {
            OccurrenceRole::MemberPosition
        }
        _ if node_kind == "type_identifier" => OccurrenceRole::TypeOperand,
        _ if js_ts_is_binding_pattern(anchor) => OccurrenceRole::Binder,
        _ => OccurrenceRole::ValueReference,
    };
    Some(role)
}

/// The JavaScript and TypeScript node kinds that own a body scope.
const JS_TS_FUNCTION_KINDS: &[&str] = &[
    "function_declaration",
    "function_expression",
    "generator_function",
    "generator_function_declaration",
    "arrow_function",
    "method_definition",
];

/// The binding one JavaScript/TypeScript binder token introduces, and the
/// interval it is in effect over.
///
/// Declaration order is deliberately not a factor, which is the same decision
/// `analyzer::js_ts::syntax`'s `JsTsLexicalBindingIndex` records: `var` and
/// function declarations hoist, and a `let`/`const` name is in its temporal
/// dead zone for the rest of its scope, so in both cases the name belongs to
/// the whole scope and a read above the declaration is a read of *this*
/// binding, not of an outer one.
///
/// The one shape this refuses to model is a `var` declared inside a nested
/// block: `var` is function-scoped, so its declaring scope is not the block
/// the token sits in, and stating the block would be wrong. Returning `None`
/// marks the file's binding intervals incomplete instead.
fn js_ts_binding_activation(binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
    let form = nearest_ancestor(binder, |kind| {
        matches!(
            kind,
            "variable_declarator"
                | "catch_clause"
                | "for_in_statement"
                | "required_parameter"
                | "optional_parameter"
                | "formal_parameters"
                | "arrow_function"
        )
    })?;
    match form.kind() {
        "required_parameter" | "optional_parameter" | "formal_parameters" | "arrow_function" => {
            Some(BindingActivation {
                kind: BindingKind::Parameter,
                hoisting: HoistingClass::ScopeWide,
                activation: scope,
            })
        }
        "catch_clause" => {
            let body = form.child_by_field_name("body")?;
            Some(BindingActivation {
                kind: BindingKind::CatchOrResource,
                hoisting: HoistingClass::DeclaredHead,
                activation: node_range(body),
            })
        }
        "for_in_statement" => Some(BindingActivation {
            kind: BindingKind::LoopVariable,
            hoisting: HoistingClass::DeclaredHead,
            activation: node_range(form),
        }),
        _ => {
            let declaration = form.parent()?;
            if declaration.kind() == "variable_declaration" && !js_ts_var_scope_is_exact(form) {
                return None;
            }
            Some(BindingActivation {
                kind: BindingKind::Local,
                hoisting: HoistingClass::ScopeWide,
                activation: scope,
            })
        }
    }
}

/// Whether the innermost scope containing this `var` declarator is also the
/// scope `var` actually binds in — the enclosing function body or the module
/// top level. A `var` inside any other block binds wider than the block that
/// contains it, which this layer does not model.
fn js_ts_var_scope_is_exact(declarator: Node<'_>) -> bool {
    let Some(scope) = nearest_ancestor(declarator, |kind| {
        matches!(kind, "statement_block" | "switch_body" | "program")
    }) else {
        return false;
    };
    scope.kind() == "program"
        || scope
            .parent()
            .is_some_and(|owner| JS_TS_FUNCTION_KINDS.contains(&owner.kind()))
}

impl StructuralSpec for JsTsStructuralSpec {
    fn language(&self) -> Language {
        self.language
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        match self.language {
            Language::JavaScript => JS_KIND_TABLE,
            Language::TypeScript => TS_KIND_TABLE,
            _ => unreachable!("JS/TS structural spec only supports JavaScript and TypeScript"),
        }
    }

    fn refine_kind(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        _enclosing: Option<NormalizedKind>,
        source: &str,
    ) -> NormalizedKind {
        if kind == NormalizedKind::Method
            && node.kind() == "method_definition"
            && node
                .child_by_field_name("name")
                .and_then(|name| node_text(name, source))
                == Some("constructor")
        {
            NormalizedKind::Constructor
        } else {
            kind
        }
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        kind != NormalizedKind::Assignment
            || node.kind() != "variable_declarator"
            || node.child_by_field_name("value").is_some()
    }

    fn supports_role(&self, role: Role) -> bool {
        role != Role::Kwarg
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        kind == NormalizedKind::Constructor
            || self
                .kind_table()
                .iter()
                .any(|(_, fact_kind)| fact_kind.satisfies(kind))
    }

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &JS_TS_OCCURRENCE_ROLE_SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        &DEEP_LEXICAL_ENVIRONMENT_SUPPORT
    }

    fn identity_route_support(&self) -> &IdentityRouteSupport {
        // `export { x }` resolves through the local binding (including an
        // imported one) to the origin declaration, so the export relation has
        // a producer. Import specifiers and `export ... from` specifiers
        // resolve to NoDefinition today -- a resolver gap, not a modeling
        // choice -- so the import, alias and re-export relations stay
        // unclaimed until the resolver answers them (see the #1475 ExecPlan
        // Decision Log, M3, and its follow-up issue).
        static SUPPORT: IdentityRouteSupport = DEEP_IDENTITY_AXES
            .supported_relation(RouteHopKind::Export)
            .supported_relation(RouteHopKind::NestedOwner);
        &SUPPORT
    }

    fn binding_activation(&self, binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
        js_ts_binding_activation(binder, scope)
    }

    fn qualified_path_root<'tree>(&self, token: Node<'tree>) -> Option<Node<'tree>> {
        if !matches!(
            token.kind(),
            "identifier" | "property_identifier" | "type_identifier"
        ) {
            return None;
        }
        qualified_chain_root(token, JS_TS_PATH_CHAIN)
    }

    fn path_segment_tokens<'tree>(&self, root: Node<'tree>) -> Vec<Node<'tree>> {
        linear_chain_tokens(root, JS_TS_PATH_CHAIN, &[])
    }

    fn segment_generic_arity(&self, token: Node<'_>) -> Option<u32> {
        spelled_generic_arity(token, JS_TS_PATH_CHAIN, &["generic_type"])
    }

    fn indirection_relation(&self, token: Node<'_>) -> Option<RouteHopKind> {
        if let Some(export) = nearest_ancestor(token, |kind| kind == "export_statement") {
            return Some(if export.child_by_field_name("source").is_some() {
                RouteHopKind::ReExport
            } else {
                RouteHopKind::Export
            });
        }
        nearest_ancestor(token, |kind| kind == "import_statement").map(|_| RouteHopKind::Import)
    }

    /// The only scope segments this adapter classifies come from
    /// `nested_identifier`, which is a namespace qualifier in both grammars.
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
        if let Some(role) = js_ts_occurrence_role(node) {
            sink.occurrence_role(node, role);
        }
        match kind {
            NormalizedKind::Call => {
                let callee_field = if node.kind() == "new_expression" {
                    "constructor"
                } else {
                    "function"
                };
                if let Some(function) = node.child_by_field_name(callee_field) {
                    attach_terminal_callee(sink, function, expression_name_node(function));
                    if function.kind() == "member_expression"
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
                    attach_argument_roles(sink, arguments);
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(property) = node.child_by_field_name("property") {
                    sink.set_name(property);
                    sink.role_named(Role::Field, property, property);
                }
                if let Some(object) = node.child_by_field_name("object") {
                    attach_role_with_derived_name(sink, Role::Object, object, expression_name_node);
                }
            }
            NormalizedKind::Function
            | NormalizedKind::Method
            | NormalizedKind::Constructor
            | NormalizedKind::Class
            | NormalizedKind::Declaration => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
                attach_decorators(sink, node);
            }
            NormalizedKind::Assignment => match node.kind() {
                "variable_declarator" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        attach_role_with_derived_name(sink, Role::Left, name, expression_name_node);
                        if let Some(name_node) = expression_name_node(name) {
                            sink.set_name(name_node);
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
                if let Some(source) = node.child_by_field_name("source") {
                    if let Some(name) = unquoted_string_span(source) {
                        sink.role_named_span(Role::Module, source, name);
                    } else {
                        attach_role_with_derived_name(
                            sink,
                            Role::Module,
                            source,
                            expression_name_node,
                        );
                    }
                }
            }
            NormalizedKind::Identifier => match expression_name_node(node) {
                Some(name) => sink.set_name(name),
                None => sink.set_name(node),
            },
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
        assert_occurrence_role, block_facts_of, occurrence_roles_of,
    };

    /// The JS/TS scope-forming statement lists are `statement_block` and
    /// `switch_body`; a class body is a member list and stays out.
    #[test]
    fn js_ts_statement_blocks_and_switch_bodies_become_scope_facts() {
        let source = concat!(
            "function demo(flag) {\n",
            "  if (flag) {\n",
            "    work();\n",
            "  }\n",
            "  switch (flag) {\n",
            "    default:\n",
            "      break;\n",
            "  }\n",
            "}\n",
        );

        assert_eq!(
            block_facts_of(
                &JAVASCRIPT_STRUCTURAL_SPEC,
                &tree_sitter_javascript::LANGUAGE.into(),
                source,
            ),
            vec![
                concat!(
                    "{\n",
                    "  if (flag) {\n",
                    "    work();\n",
                    "  }\n",
                    "  switch (flag) {\n",
                    "    default:\n",
                    "      break;\n",
                    "  }\n",
                    "}",
                ),
                concat!("{\n", "    work();\n", "  }"),
                concat!("{\n", "    default:\n", "      break;\n", "  }"),
            ]
        );
    }

    /// The JS/TS trap #1473 names: shorthand `{ alpha }` binds in a pattern and
    /// reads in an expression. The grammar already distinguishes the two
    /// (`shorthand_property_identifier_pattern` vs
    /// `shorthand_property_identifier`), so the classification must never come
    /// down to what the token looks like.
    #[test]
    fn js_ts_separates_destructuring_binders_from_expression_shorthand_reads() {
        let source = concat!(
            "import { readFile as read } from \"fs\";\n",
            "\n",
            "const { alpha, beta: gamma } = source;\n",
            "const payload = { alpha, delta: gamma };\n",
            "\n",
            "function render(label) {\n",
            "  return payload.alpha;\n",
            "}\n",
        );
        let found = occurrence_roles_of(
            &JAVASCRIPT_STRUCTURAL_SPEC,
            &tree_sitter_javascript::LANGUAGE.into(),
            source,
        );

        let at = |needle: &str| source.find(needle).expect("fixture token");
        assert_occurrence_role(&found, at("readFile"), OccurrenceRole::ImportTarget);
        assert_occurrence_role(&found, at("read }"), OccurrenceRole::ImportAlias);
        // `alpha` in the destructuring pattern binds; `alpha` in the object
        // literal three lines down reads the binding it just created.
        assert_occurrence_role(&found, at("alpha, beta"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("beta"), OccurrenceRole::LabelOrKey);
        assert_occurrence_role(&found, at("gamma }"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("source;"), OccurrenceRole::ValueReference);
        assert_occurrence_role(&found, at("payload ="), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("alpha, delta"), OccurrenceRole::ValueReference);
        assert_occurrence_role(&found, at("delta"), OccurrenceRole::LabelOrKey);
        assert_occurrence_role(&found, at("gamma };"), OccurrenceRole::ValueReference);
        assert_occurrence_role(&found, at("render"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("label)"), OccurrenceRole::Binder);
        assert_occurrence_role(
            &found,
            at("payload.alpha"),
            OccurrenceRole::ReceiverPosition,
        );
        assert_occurrence_role(&found, at("alpha;"), OccurrenceRole::MemberPosition);
    }

    /// TypeScript adds `type_identifier`, whose every position is a type
    /// operand except the declaration heads that introduce it.
    #[test]
    fn typescript_separates_type_declaration_heads_from_type_operands() {
        let source = concat!(
            "interface Widget {\n",
            "  label: string;\n",
            "}\n",
            "\n",
            "function render(widget: Widget): Widget {\n",
            "  return widget;\n",
            "}\n",
        );
        let found = occurrence_roles_of(
            &TYPESCRIPT_STRUCTURAL_SPEC,
            &tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            source,
        );

        let at = |needle: &str| source.find(needle).expect("fixture token");
        assert_occurrence_role(&found, at("Widget {"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("label"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("widget: Widget"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("Widget)"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(
            &found,
            at("Widget {\n  return"),
            OccurrenceRole::TypeOperand,
        );
        assert_occurrence_role(&found, at("widget;"), OccurrenceRole::ValueReference);
    }

    #[test]
    fn js_ts_emits_only_roles_it_declares_as_supported() {
        let source = "const { a } = b; function f(c) { return a.d(c); }\n";
        let found = occurrence_roles_of(
            &JAVASCRIPT_STRUCTURAL_SPEC,
            &tree_sitter_javascript::LANGUAGE.into(),
            source,
        );
        assert!(!found.is_empty());
        for (_, text, role) in &found {
            assert!(
                JAVASCRIPT_STRUCTURAL_SPEC
                    .occurrence_role_support()
                    .is_supported(*role),
                "javascript emitted undeclared role {role:?} for {text:?}"
            );
        }
    }

    #[test]
    fn javascript_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_javascript::LANGUAGE.into(),
            "tree-sitter-javascript",
            JS_KIND_TABLE,
        );
    }

    #[test]
    fn typescript_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            "tree-sitter-typescript",
            TS_KIND_TABLE,
        );
    }

    #[test]
    fn tsx_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_typescript::LANGUAGE_TSX.into(),
            "tree-sitter-tsx",
            TS_KIND_TABLE,
        );
    }
}
