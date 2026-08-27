//! Shared JavaScript/TypeScript structural specs for `query_code`.

use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_positional_argument_roles, attach_role_with_derived_name, attach_terminal_callee,
    field_name_in_parent, first_named_child, nearest_ancestor, node_range,
};
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    linear_chain_tokens, qualified_chain_root, spelled_generic_arity,
};
use brokk_bifrost_core::analyzer::structural::callable::CallSiteContext;
use brokk_bifrost_core::analyzer::structural::edges::{
    DEEP_REFERENCE_EDGE_SUPPORT, ReferenceEdgeSupport,
};
use brokk_bifrost_core::analyzer::structural::facts::Span;
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::materialization::{
    DeclarationMaterializationSupport, JS_TS_MATERIALIZATION_SUPPORT,
};
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
use brokk_bifrost_core::analyzer::structural::spec::{RoleSink, StructuralSpec};
use brokk_bifrost_core::analyzer::{Language, Range};
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
pub struct JsTsStructuralSpec {
    language: Language,
}

pub static JAVASCRIPT_STRUCTURAL_SPEC: JsTsStructuralSpec = JsTsStructuralSpec {
    language: Language::JavaScript,
};

pub static TYPESCRIPT_STRUCTURAL_SPEC: JsTsStructuralSpec = JsTsStructuralSpec {
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
            ("array", NormalizedKind::CollectionLiteral),
            ("object", NormalizedKind::CollectionLiteral),
            ("jsx_element", NormalizedKind::JsxElement),
            ("jsx_self_closing_element", NormalizedKind::JsxElement),
            ("jsx_attribute", NormalizedKind::JsxAttribute),
            // JSX spread attributes are represented by a jsx_expression whose
            // only named child is a spread_element. `should_extract` below
            // admits this grammar node only in that opening-element context.
            ("jsx_expression", NormalizedKind::JsxSpreadAttribute),
            ("pair", NormalizedKind::ObjectProperty),
            ("computed_property_name", NormalizedKind::ComputedProperty),
            // `spread_element` is shared by object/array literals and call
            // arguments. Keep that shared syntax kind context-free; the
            // enclosing role and parent fact retain whether it is an object,
            // array, or argument spread.
            ("spread_element", NormalizedKind::SpreadElement),
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

pub const JS_KIND_TABLE: &[(&str, NormalizedKind)] = js_ts_kind_table!();

pub const TS_KIND_TABLE: &[(&str, NormalizedKind)] = js_ts_kind_table!(
    ("abstract_class_declaration", NormalizedKind::Class),
    ("interface_declaration", NormalizedKind::Class),
    ("enum_declaration", NormalizedKind::Class),
    ("type_alias_declaration", NormalizedKind::Declaration),
    ("type_identifier", NormalizedKind::Identifier),
    ("nested_identifier", NormalizedKind::Identifier),
    // Bodiless callable declarations: overload signatures, ambient
    // declarations, interface members, and abstract methods (#1658). They
    // are declarations, so their nodes are facts a query can address.
    ("function_signature", NormalizedKind::Function),
    ("method_signature", NormalizedKind::Method),
    ("abstract_method_signature", NormalizedKind::Method),
    // TypeScript formal parameters are declarations in their own right. The
    // grammar also uses `rest_pattern` for array/object destructuring, so it
    // is intentionally not normalized here: the context-free kind table
    // cannot soundly distinguish a rest parameter from a destructuring rest.
    // Rest-parameter matching remains an explicit unsupported case until the
    // adapter can refine that context without overclassifying ordinary code.
    ("required_parameter", NormalizedKind::Parameter),
    ("optional_parameter", NormalizedKind::Parameter),
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

/// A JSX tag has intrinsic/component identity only after resolution. The
/// structural fact keeps a name span for simple identifiers, while qualified
/// and namespaced tags remain unnamed so a later projection cannot mistake a
/// terminal member segment for the tag's identity.
fn jsx_simple_tag_name<'tree>(tag: Node<'tree>) -> Option<Node<'tree>> {
    matches!(tag.kind(), "identifier" | "property_identifier").then_some(tag)
}

fn jsx_opening_element<'tree>(element: Node<'tree>) -> Option<Node<'tree>> {
    match element.kind() {
        "jsx_element" => element.child_by_field_name("open_tag"),
        "jsx_self_closing_element" => Some(element),
        _ => None,
    }
}

fn jsx_expression_operand<'tree>(value: Node<'tree>) -> Option<Node<'tree>> {
    if value.kind() == "jsx_expression" {
        first_named_child(value)
    } else {
        Some(value)
    }
}

fn jsx_spread_operand<'tree>(attribute: Node<'tree>) -> Option<Node<'tree>> {
    let spread = first_named_child(attribute).filter(|child| child.kind() == "spread_element")?;
    first_named_child(spread)
}

fn jsx_attribute_value<'tree>(attribute: Node<'tree>) -> Option<Node<'tree>> {
    attribute
        .named_child(1)
        .and_then(jsx_expression_operand)
        .and_then(|value| {
            if value.kind() == "spread_element" {
                first_named_child(value)
            } else {
                Some(value)
            }
        })
}

fn attach_jsx_element_roles(sink: &mut RoleSink<'_>, element: Node<'_>) {
    let Some(opening) = jsx_opening_element(element) else {
        return;
    };
    if let Some(tag) = opening.child_by_field_name("name") {
        let name = jsx_simple_tag_name(tag);
        sink.role_maybe_named(Role::Tag, tag, name);
        if let Some(name) = name {
            sink.set_name(name);
        }
    }
    for index in 0..opening.named_child_count() {
        let Some(child) = opening.named_child(index) else {
            continue;
        };
        if matches!(child.kind(), "jsx_attribute" | "jsx_expression") {
            sink.role(Role::Attributes, child);
        }
    }
    if element.kind() == "jsx_element" {
        for index in 0..element.named_child_count() {
            let Some(child) = element.named_child(index) else {
                continue;
            };
            if !matches!(child.kind(), "jsx_opening_element" | "jsx_closing_element") {
                sink.role(Role::Children, child);
            }
        }
    }
}

fn attach_object_property_roles(sink: &mut RoleSink<'_>, property: Node<'_>) {
    let Some(key) = property.child_by_field_name("key") else {
        return;
    };
    if key.kind() != "computed_property_name" {
        if let Some(name) = unquoted_string_span(key) {
            sink.role_named_span(Role::Key, key, name);
        } else {
            sink.set_name(key);
            sink.role_named(Role::Key, key, key);
        }
    }
    if let Some(value) = property.child_by_field_name("value") {
        sink.role(Role::Value, value);
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

fn parameter_name_node<'tree>(parameter: Node<'tree>) -> Option<Node<'tree>> {
    match parameter.kind() {
        "required_parameter" | "optional_parameter" | "rest_pattern" => parameter
            .child_by_field_name("pattern")
            .or_else(|| parameter.child_by_field_name("name")),
        _ => expression_name_node(parameter),
    }
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
    "function_signature",
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

    fn supports_boolean_literal_value(&self) -> bool {
        true
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
        _context: &CallSiteContext,
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
        if kind == NormalizedKind::JsxSpreadAttribute
            && !(node.kind() == "jsx_expression"
                && node.parent().is_some_and(|parent| {
                    matches!(
                        parent.kind(),
                        "jsx_opening_element" | "jsx_self_closing_element"
                    )
                })
                && first_named_child(node).is_some_and(|child| child.kind() == "spread_element"))
        {
            return false;
        }
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

    fn materialization_support(&self) -> &DeclarationMaterializationSupport {
        &JS_TS_MATERIALIZATION_SUPPORT
    }

    fn reference_edge_support(&self) -> &ReferenceEdgeSupport {
        &DEEP_REFERENCE_EDGE_SUPPORT
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
            NormalizedKind::Parameter => {
                if let Some(name) = parameter_name_node(node) {
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
            NormalizedKind::ForLoop => {
                if let Some(right) = node.child_by_field_name("right") {
                    attach_role_with_derived_name(
                        sink,
                        Role::Iterable,
                        right,
                        expression_name_node,
                    );
                }
            }
            NormalizedKind::CollectionLiteral => {
                attach_collection_elements(sink, node);
            }
            NormalizedKind::JsxElement => {
                attach_jsx_element_roles(sink, node);
            }
            NormalizedKind::JsxAttribute => {
                if let Some(name) = node
                    .named_child(0)
                    .filter(|name| name.kind() == "property_identifier")
                {
                    sink.set_name(name);
                }
                if let Some(value) = jsx_attribute_value(node) {
                    sink.role(Role::Value, value);
                }
            }
            NormalizedKind::JsxSpreadAttribute => {
                if let Some(value) = jsx_spread_operand(node) {
                    sink.role(Role::Value, value);
                }
            }
            NormalizedKind::ObjectProperty => {
                attach_object_property_roles(sink, node);
            }
            NormalizedKind::ComputedProperty => {
                if let Some(value) = first_named_child(node) {
                    sink.role(Role::Value, value);
                }
            }
            NormalizedKind::SpreadElement => {
                if let Some(value) = first_named_child(node) {
                    sink.role(Role::Value, value);
                }
            }
            _ => {}
        }
    }
}

/// One `elements` role edge per element of an `array` or `object` literal.
/// Every named child except comments is an element: array entries, object
/// pairs, spreads, shorthand properties, and object methods all count toward
/// the literal's element count.
fn attach_collection_elements(sink: &mut RoleSink<'_>, literal: Node<'_>) {
    for index in 0..literal.named_child_count() {
        let Some(child) = literal.named_child(index) else {
            continue;
        };
        if child.kind() == "comment" {
            continue;
        }
        attach_role_with_derived_name(sink, Role::Element, child, expression_name_node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::structural::spec::RoleSink;
    use brokk_bifrost_core::hash::HashMap;

    #[test]
    fn typescript_parameter_extracts_name_and_decorator_role() {
        let source = "class Controller { handle(@Query value: string) {} }";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("TypeScript grammar");
        let tree = parser.parse(source, None).expect("TypeScript tree");

        let mut fact_by_ts_node = HashMap::default();
        let mut parameter = None;
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            let fact_id = fact_by_ts_node.len() as u32;
            fact_by_ts_node.insert(node.id(), fact_id);
            if node.kind() == "required_parameter" {
                parameter = Some(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        let parameter = parameter.expect("decorated required parameter");

        let mut roles = Vec::new();
        let mut occurrence_roles = Vec::new();
        let mut sink = RoleSink::new(
            &fact_by_ts_node,
            &mut roles,
            &mut occurrence_roles,
            32,
            None,
        );
        TYPESCRIPT_STRUCTURAL_SPEC.extract(parameter, NormalizedKind::Parameter, &mut sink);
        let (name, stop) = sink.into_parts();

        assert_eq!(stop, None);
        assert_eq!(
            name,
            Some(Span {
                start_byte: 33,
                end_byte: 38
            })
        );
        let decorator = roles
            .iter()
            .find(|target| target.role == Role::Decorator)
            .expect("parameter decorator role");
        assert_eq!(decorator.span.text(source), "@Query");
        assert_eq!(decorator.name.map(|span| span.text(source)), Some("Query"));
    }

    #[test]
    fn tsx_parameter_extracts_name_and_decorator_role() {
        let source = "class Controller { handle(@Query value: string) {} }";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TSX.into())
            .expect("TSX grammar");
        let tree = parser.parse(source, None).expect("TSX tree");

        let mut fact_by_ts_node = HashMap::default();
        let mut parameter = None;
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            let fact_id = fact_by_ts_node.len() as u32;
            fact_by_ts_node.insert(node.id(), fact_id);
            if node.kind() == "required_parameter" {
                parameter = Some(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        let parameter = parameter.expect("decorated required parameter");

        let mut roles = Vec::new();
        let mut occurrence_roles = Vec::new();
        let mut sink = RoleSink::new(
            &fact_by_ts_node,
            &mut roles,
            &mut occurrence_roles,
            32,
            None,
        );
        TYPESCRIPT_STRUCTURAL_SPEC.extract(parameter, NormalizedKind::Parameter, &mut sink);
        let (name, stop) = sink.into_parts();

        assert_eq!(stop, None);
        assert_eq!(
            name,
            Some(Span {
                start_byte: 33,
                end_byte: 38
            })
        );
        let decorator = roles
            .iter()
            .find(|target| target.role == Role::Decorator)
            .expect("parameter decorator role");
        assert_eq!(decorator.span.text(source), "@Query");
        assert_eq!(decorator.name.map(|span| span.text(source)), Some("Query"));
    }
}
