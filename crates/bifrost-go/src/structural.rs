//! Go structural spec for `query_code`.

use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_positional_argument_roles, attach_role_with_derived_name, attach_terminal_callee,
    field_name_in_parent, first_named_child, unquoted_string_content_span,
};
use brokk_bifrost_core::analyzer::structural::edges::{
    INVERSE_REFERENCE_EDGE_SUPPORT, ReferenceEdgeSupport,
};
use brokk_bifrost_core::analyzer::structural::facts::Span;
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::materialization::{
    DeclarationMaterializationSupport, NO_MATERIALIZATION_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::occurrences::{
    OccurrenceRole, OccurrenceRoleSupport,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    BindingActivation, BindingKind, EnvironmentAxis, HoistingClass, LexicalEnvironmentSupport,
    ScopeFormation, default_scope_formation,
};
use brokk_bifrost_core::analyzer::structural::result_use::{
    CallResultUse, CallResultUseFact, CallResultUseIndex, CallResultUseOpenReason,
    CallResultUseSite, IntentionalDiscardKind,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    IdentityRouteSupport, NO_IDENTITY_ROUTE_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::spec::{RoleSink, StructuralSpec};
use brokk_bifrost_core::analyzer::tree_walk::{
    ParentIndex, node_range, unwrap_parenthesized_expression_with,
};
use brokk_bifrost_core::analyzer::{Language, Range};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub struct GoStructuralSpec;

pub static GO_STRUCTURAL_SPEC: GoStructuralSpec = GoStructuralSpec;

/// Classify the syntax around one exact Go call expression.  Result arity is
/// deliberately not guessed here: the site default applies to every semantic
/// result port, while blank-assignment overrides are keyed by ordinal.
pub fn go_call_result_use(call: Node<'_>, source: &str) -> CallResultUseSite {
    let default = if call.has_error() || has_recovery_ancestor(call) {
        CallResultUse::Open(CallResultUseOpenReason::RecoveredSyntax)
    } else if has_deferred_ancestor(call) {
        CallResultUse::Open(CallResultUseOpenReason::DeferredContext)
    } else {
        let mut expression = call;
        loop {
            let Some(parent) = expression.parent() else {
                break CallResultUse::Open(CallResultUseOpenReason::UnclassifiedSyntax);
            };
            if parent.is_error() || parent.is_missing() {
                break CallResultUse::Open(CallResultUseOpenReason::RecoveredSyntax);
            }
            match parent.kind() {
                "parenthesized_expression"
                    if parent.named_child_count() == 1
                        && parent
                            .named_child(0)
                            .is_some_and(|child| child.id() == expression.id()) =>
                {
                    expression = parent;
                }
                "expression_statement"
                    if parent.named_child_count() == 1
                        && parent
                            .named_child(0)
                            .is_some_and(|child| child.id() == expression.id()) =>
                {
                    break CallResultUse::Discarded;
                }
                "for_clause"
                    if matches!(
                        field_name_in_parent(parent, expression),
                        Some("initializer" | "update")
                    ) =>
                {
                    break CallResultUse::Discarded;
                }
                "expression_list" => {
                    if let Some(site) = go_assignment_result_use(call, parent, source) {
                        return site;
                    }
                    expression = parent;
                }
                "go_statement" | "defer_statement" => {
                    break CallResultUse::Open(CallResultUseOpenReason::DeferredContext);
                }
                "func_literal" => {
                    break CallResultUse::Open(CallResultUseOpenReason::DeferredContext);
                }
                _ => break CallResultUse::Consumed,
            }
        }
    };
    CallResultUseSite::new(call.start_byte(), call.end_byte(), default)
}

fn has_recovery_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.is_error() || parent.is_missing() {
            return true;
        }
        node = parent;
    }
    false
}

fn has_deferred_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == "func_literal" {
            return true;
        }
        node = parent;
    }
    false
}

fn go_assignment_result_use(
    call: Node<'_>,
    right: Node<'_>,
    source: &str,
) -> Option<CallResultUseSite> {
    if !matches!(
        right.parent()?.kind(),
        "assignment_statement" | "short_var_declaration"
    ) || right.parent()?.child_by_field_name("right")?.id() != right.id()
    {
        return None;
    }
    let assignment = right.parent()?;
    let left = assignment.child_by_field_name("left")?;
    let right_index = right
        .named_children(&mut right.walk())
        .position(|child| child.id() == call.id())?;
    let right_count = right.named_child_count();
    let left_children = left.named_children(&mut left.walk()).collect::<Vec<_>>();
    let mut overrides = Vec::new();
    if right_count == 1 && right_index == 0 {
        for (ordinal, target) in left_children.into_iter().enumerate() {
            if target.kind() == "identifier"
                && target
                    .utf8_text(source.as_bytes())
                    .is_ok_and(|text| text == "_")
            {
                overrides.push(CallResultUseFact {
                    result_ordinal: u32::try_from(ordinal).expect("Go result ordinal fits u32"),
                    result_use: CallResultUse::IntentionalDiscard(
                        IntentionalDiscardKind::GoBlankAssignment,
                    ),
                });
            }
        }
    } else if let Some(target) = left_children.get(right_index)
        && target.kind() == "identifier"
        && target
            .utf8_text(source.as_bytes())
            .is_ok_and(|text| text == "_")
    {
        overrides.push(CallResultUseFact {
            result_ordinal: u32::try_from(right_index).expect("Go result ordinal fits u32"),
            result_use: CallResultUse::IntentionalDiscard(
                IntentionalDiscardKind::GoBlankAssignment,
            ),
        });
    }
    Some(
        CallResultUseSite::new(call.start_byte(), call.end_byte(), CallResultUse::Consumed)
            .with_overrides(overrides),
    )
}

/// One source-snapshot index of exact Go call spans.
#[derive(Debug, Clone)]
pub struct GoCallResultUseIndex {
    inner: CallResultUseIndex,
}

impl GoCallResultUseIndex {
    pub fn new(root: Node<'_>, source: &str) -> Self {
        let mut sites = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression" {
                sites.push(go_call_result_use(node, source));
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child exists"));
            }
        }
        Self {
            inner: CallResultUseIndex::new(sites),
        }
    }

    pub fn at_span(
        &self,
        start_byte: usize,
        end_byte: usize,
    ) -> Result<&CallResultUseSite, CallResultUseOpenReason> {
        self.inner.at_span(start_byte, end_byte)
    }

    pub fn sites(&self) -> &[CallResultUseSite] {
        self.inner.sites()
    }
}

const GO_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("comment", NormalizedKind::Comment),
    ("call_expression", NormalizedKind::Call),
    ("go_statement", NormalizedKind::ConcurrentSpawn),
    ("selector_expression", NormalizedKind::FieldAccess),
    ("function_declaration", NormalizedKind::Function),
    ("method_declaration", NormalizedKind::Method),
    ("func_literal", NormalizedKind::Lambda),
    ("type_spec", NormalizedKind::Class),
    ("type_alias", NormalizedKind::Declaration),
    ("assignment_statement", NormalizedKind::Assignment),
    ("short_var_declaration", NormalizedKind::Assignment),
    ("var_spec", NormalizedKind::Assignment),
    ("const_spec", NormalizedKind::Assignment),
    ("import_declaration", NormalizedKind::Import),
    ("identifier", NormalizedKind::Identifier),
    ("field_identifier", NormalizedKind::Identifier),
    ("package_identifier", NormalizedKind::Identifier),
    ("type_identifier", NormalizedKind::Identifier),
    ("interpreted_string_literal", NormalizedKind::StringLiteral),
    ("raw_string_literal", NormalizedKind::StringLiteral),
    ("int_literal", NormalizedKind::NumericLiteral),
    ("float_literal", NormalizedKind::NumericLiteral),
    ("true", NormalizedKind::BooleanLiteral),
    ("false", NormalizedKind::BooleanLiteral),
    ("nil", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("if_statement", NormalizedKind::If),
    ("for_statement", NormalizedKind::Loop),
    // Explicit and implicit blocks: a braced block, each case clause, and a
    // switch, whose initializer is scoped to the whole switch.
    ("block", NormalizedKind::Block),
    ("expression_case", NormalizedKind::Block),
    ("type_case", NormalizedKind::Block),
    ("communication_case", NormalizedKind::Block),
    ("default_case", NormalizedKind::Block),
    ("expression_switch_statement", NormalizedKind::Block),
    ("type_switch_statement", NormalizedKind::Block),
];

fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression;
    loop {
        match current.kind() {
            "identifier" | "field_identifier" | "package_identifier" | "type_identifier" => {
                return Some(current);
            }
            "selector_expression" => current = current.child_by_field_name("field")?,
            "call_expression" => current = current.child_by_field_name("function")?,
            "qualified_type" => current = current.child_by_field_name("name")?,
            "parenthesized_expression" | "expression_list" => current = first_named_child(current)?,
            _ => return None,
        }
    }
}

fn call_callee_expression<'tree>(mut expression: Node<'tree>) -> Node<'tree> {
    loop {
        expression = match expression.kind() {
            "index_expression" => {
                let Some(operand) = expression.child_by_field_name("operand") else {
                    return expression;
                };
                operand
            }
            "parenthesized_expression" => {
                let Some(inner) = first_named_child(expression) else {
                    return expression;
                };
                inner
            }
            _ => return expression,
        };
    }
}

fn transparent_parenthesized_expression<'tree>(expression: Node<'tree>) -> Node<'tree> {
    unwrap_parenthesized_expression_with(expression, first_named_child)
}

fn attach_call_roles(sink: &mut RoleSink<'_>, node: Node<'_>) {
    if let Some(function) = node.child_by_field_name("function") {
        let callee = call_callee_expression(function);
        attach_terminal_callee(sink, function, expression_name_node(callee));
        if callee.kind() == "selector_expression"
            && let Some(operand) = callee.child_by_field_name("operand")
        {
            let operand = transparent_parenthesized_expression(operand);
            attach_role_with_derived_name(sink, Role::Receiver, operand, expression_name_node);
        }
    }
    if let Some(arguments) = node.child_by_field_name("arguments") {
        attach_positional_argument_roles(sink, arguments, expression_name_node);
    }
}

fn unquoted_go_string_span(node: Node<'_>) -> Option<Span> {
    if !matches!(
        node.kind(),
        "interpreted_string_literal" | "raw_string_literal"
    ) {
        return None;
    }
    unquoted_string_content_span(node)
}

fn attach_import_spec_module(sink: &mut RoleSink<'_>, import_spec: Node<'_>) {
    if let Some(path) = import_spec.child_by_field_name("path") {
        if let Some(name) = unquoted_go_string_span(path) {
            sink.role_named_span(Role::Module, path, name);
        } else {
            sink.role(Role::Module, path);
        }
    }
}

fn attach_import_modules(sink: &mut RoleSink<'_>, import: Node<'_>) {
    if import.kind() == "import_spec" {
        attach_import_spec_module(sink, import);
        return;
    }

    for index in 0..import.named_child_count() {
        let Some(child) = import.named_child(index) else {
            continue;
        };
        match child.kind() {
            "import_spec" => attach_import_spec_module(sink, child),
            "import_spec_list" => {
                for spec_index in 0..child.named_child_count() {
                    let Some(spec) = child.named_child(spec_index) else {
                        continue;
                    };
                    if spec.kind() == "import_spec" {
                        attach_import_spec_module(sink, spec);
                    }
                }
            }
            _ => {}
        }
    }
}

fn attach_role_target<'tree>(
    sink: &mut RoleSink<'_>,
    role: Role,
    target: Node<'tree>,
    first_name: &mut Option<Node<'tree>>,
) {
    attach_role_with_derived_name(sink, role, target, expression_name_node);
    if first_name.is_none() {
        *first_name = expression_name_node(target);
    }
}

fn attach_role_targets<'tree>(
    sink: &mut RoleSink<'_>,
    role: Role,
    target: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut first_name = None;
    if target.kind() == "expression_list" {
        for index in 0..target.named_child_count() {
            let Some(child) = target.named_child(index) else {
                continue;
            };
            attach_role_target(sink, role, child, &mut first_name);
        }
    } else {
        attach_role_target(sink, role, target, &mut first_name);
    }
    first_name
}

fn attach_name_field_targets<'tree>(
    sink: &mut RoleSink<'_>,
    role: Role,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut first_name = None;
    let mut cursor = node.walk();
    for name in node.children_by_field_name("name", &mut cursor) {
        if !name.is_named() {
            continue;
        }
        attach_role_target(sink, role, name, &mut first_name);
    }
    first_name
}

fn attach_value_field_targets<'tree>(
    sink: &mut RoleSink<'_>,
    role: Role,
    node: Node<'tree>,
    field: &str,
) -> Option<Node<'tree>> {
    node.child_by_field_name(field)
        .and_then(|target| attach_role_targets(sink, role, target))
}

static GO_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport = OccurrenceRoleSupport::NONE
    .supported(OccurrenceRole::MemberPosition)
    .supported(OccurrenceRole::Binder);

/// Go derives its scope tree from the callable, loop, `if`, switch, case and
/// block facts in [`GO_KIND_TABLE`], and every binder it classifies states an
/// interval through [`go_binding_activation`]. Import binders and the package
/// clause are not derived.
static GO_LEXICAL_ENVIRONMENT_SUPPORT: LexicalEnvironmentSupport = LexicalEnvironmentSupport::NONE
    .supported(EnvironmentAxis::Scopes)
    .supported(EnvironmentAxis::BindingIntervals);

/// Whether `node` has a direct `:=` token child, which is what makes a range
/// or receive clause declare its left-hand names rather than assign them.
fn declares_with_walrus(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| child.kind() == ":=")
}

/// Whether an identifier is a Go binder: a parameter, receiver or result
/// name; a `:=` name; a function-local `var` or `const` name; a `:=` range or
/// receive name; or a type switch alias. A package-level `var` or `const`
/// names a package member, not a lexical binding.
fn go_is_binder(node: Node<'_>, parents: &ParentIndex<'_>) -> bool {
    if node.kind() != "identifier" {
        return false;
    }
    let Some(parent) = parents.parent(node) else {
        return false;
    };
    let field = field_name_in_parent(parent, node);
    match parent.kind() {
        "parameter_declaration" | "variadic_parameter_declaration" => field == Some("name"),
        "var_spec" | "const_spec" => {
            field == Some("name")
                && std::iter::successors(parents.parent(parent), |node| parents.parent(*node))
                    .any(|ancestor| ancestor.kind() == "block")
        }
        "expression_list" => {
            let Some(owner) = parents.parent(parent) else {
                return false;
            };
            let side = field_name_in_parent(owner, parent);
            match owner.kind() {
                "short_var_declaration" => side == Some("left"),
                "range_clause" | "receive_statement" => {
                    side == Some("left") && declares_with_walrus(owner)
                }
                "type_switch_statement" => side == Some("alias"),
                _ => false,
            }
        }
        _ => false,
    }
}

/// The binding one Go binder token introduces, and the interval it is in
/// effect over.
///
/// A parameter, receiver or named result is in effect over its whole
/// function. A `:=`, `var` or `const` name is in effect from the end of its
/// statement or spec to the end of its block, so `x := x` reads an outer `x`.
/// A `:=` range variable is in effect over the loop body, a select case's
/// received names over that case, and a type switch alias over the switch.
///
/// A multi-name `:=` may redeclare a name the same block already declares;
/// Go then assigns the existing variable. Each declaration still gets its
/// own row here, and in valid Go two rows with one name in one block are
/// therefore one variable.
fn go_binding_activation(binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
    let binding = |kind, hoisting, activation| {
        Some(BindingActivation {
            kind,
            hoisting,
            activation,
        })
    };
    let after = |node: Node<'_>| Range {
        start_byte: node.end_byte(),
        end_byte: scope.end_byte,
        start_line: node.end_position().row + 1,
        end_line: scope.end_line,
    };
    let parent = binder.parent()?;
    match parent.kind() {
        "parameter_declaration" | "variadic_parameter_declaration" => {
            binding(BindingKind::Parameter, HoistingClass::ScopeWide, scope)
        }
        "var_spec" | "const_spec" => binding(
            BindingKind::Local,
            HoistingClass::SourceOrder,
            after(parent),
        ),
        "expression_list" => {
            let owner = parent.parent()?;
            match owner.kind() {
                "short_var_declaration" => {
                    binding(BindingKind::Local, HoistingClass::SourceOrder, after(owner))
                }
                "range_clause" => binding(
                    BindingKind::LoopVariable,
                    HoistingClass::DeclaredHead,
                    node_range(owner.parent()?.child_by_field_name("body")?),
                ),
                "receive_statement" => binding(
                    BindingKind::Local,
                    HoistingClass::DeclaredHead,
                    node_range(owner.parent()?),
                ),
                "type_switch_statement" => binding(
                    BindingKind::PatternBinder,
                    HoistingClass::DeclaredHead,
                    node_range(owner),
                ),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Classify the selector member token in a Go `selector_expression`.
///
/// The Go grammar gives a selector its two semantic positions as named
/// fields: `operand` is the receiver and `field` is the member. Keeping this
/// check on the field relationship means a declaration, keyed literal, label,
/// or ordinary identifier with the same spelling cannot be mistaken for a
/// member occurrence.
/// Classify one identifier's occurrence role.
///
/// Takes the walk's parent index rather than calling `Node::parent`: this runs
/// for every identifier fact in the file, and tree-sitter recovers a parent by
/// re-descending from the root, so asking directly is quadratic in file size.
/// On goqu's vendored 248k-line `sqlite3-binding.c` that was 97% of process CPU
/// and timed out 100 probes at the 600s budget.
fn go_occurrence_role<'tree>(
    node: Node<'tree>,
    parents: &ParentIndex<'tree>,
) -> Option<OccurrenceRole> {
    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "package_identifier" | "type_identifier"
    ) {
        return None;
    }

    let parent = parents.parent(node)?;
    if parent.kind() == "selector_expression" && field_name_in_parent(parent, node) == Some("field")
    {
        return Some(OccurrenceRole::MemberPosition);
    }
    go_is_binder(node, parents).then_some(OccurrenceRole::Binder)
}

impl StructuralSpec for GoStructuralSpec {
    fn language(&self) -> Language {
        Language::Go
    }

    fn supports_boolean_literal_value(&self) -> bool {
        true
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        GO_KIND_TABLE
    }

    fn reparse_grammar_gap(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> Option<tree_sitter::Tree> {
        crate::parse::go_reparse_grammar_gap(source, tree, cancellation)
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        kind != NormalizedKind::Assignment
            || !matches!(node.kind(), "var_spec" | "const_spec")
            || node.child_by_field_name("value").is_some()
    }

    fn supports_role(&self, role: Role) -> bool {
        !matches!(
            role,
            Role::Kwarg | Role::Decorator | Role::Iterable | Role::Element
        )
    }

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &GO_OCCURRENCE_ROLE_SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        &GO_LEXICAL_ENVIRONMENT_SUPPORT
    }

    /// An `if` statement is an implicit block: a name its initializer
    /// declares is in effect in every branch and nowhere after.
    fn scope_formation(&self, kind: NormalizedKind) -> ScopeFormation {
        if kind == NormalizedKind::If {
            ScopeFormation::BindingScope
        } else {
            default_scope_formation(kind)
        }
    }

    fn binding_activation(&self, binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
        go_binding_activation(binder, scope)
    }

    fn materialization_support(&self) -> &DeclarationMaterializationSupport {
        &NO_MATERIALIZATION_SUPPORT
    }

    fn reference_edge_support(&self) -> &ReferenceEdgeSupport {
        &INVERSE_REFERENCE_EDGE_SUPPORT
    }

    fn identity_route_support(&self) -> &IdentityRouteSupport {
        &NO_IDENTITY_ROUTE_SUPPORT
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        if let Some(role) = go_occurrence_role(node, sink.parents()) {
            sink.occurrence_role(node, role);
        }
        match kind {
            NormalizedKind::Call => attach_call_roles(sink, node),
            NormalizedKind::ConcurrentSpawn => {
                if let Some(call) = first_named_child(node)
                    && call.kind() == "call_expression"
                {
                    attach_call_roles(sink, call);
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(field) = node.child_by_field_name("field") {
                    sink.set_name(field);
                    sink.role_named(Role::Field, field, field);
                }
                if let Some(operand) = node.child_by_field_name("operand") {
                    let operand = transparent_parenthesized_expression(operand);
                    attach_role_with_derived_name(
                        sink,
                        Role::Object,
                        operand,
                        expression_name_node,
                    );
                }
            }
            NormalizedKind::Function
            | NormalizedKind::Method
            | NormalizedKind::Class
            | NormalizedKind::Declaration => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
            }
            NormalizedKind::Assignment => {
                let first_left_name = match node.kind() {
                    "var_spec" | "const_spec" => attach_name_field_targets(sink, Role::Left, node),
                    _ => attach_value_field_targets(sink, Role::Left, node, "left"),
                };
                if let Some(name) = first_left_name {
                    sink.set_name(name);
                }
                match node.kind() {
                    "var_spec" | "const_spec" => {
                        attach_value_field_targets(sink, Role::Right, node, "value");
                    }
                    _ => {
                        attach_value_field_targets(sink, Role::Right, node, "right");
                    }
                }
            }
            NormalizedKind::Import => attach_import_modules(sink, node),
            NormalizedKind::Identifier => sink.set_name(node),
            _ => {}
        }
    }
}

#[cfg(test)]
mod structural_spec_tests {
    use super::*;
    use brokk_bifrost_core::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar;

    fn parse(source: &str) -> tree_sitter::Tree {
        crate::declarations::parse_go_tree(source)
    }

    #[test]
    fn go_kind_table_matches_grammar() {
        let grammar: tree_sitter::Language = tree_sitter_go::LANGUAGE.into();
        assert_kind_table_matches_grammar(grammar, "tree-sitter-go", GO_KIND_TABLE);
    }

    #[test]
    fn selector_members_are_member_positions_and_near_misses_are_not() {
        let source = concat!(
            "package example\n\n",
            "type Widget struct {\n",
            "\tMember int\n",
            "}\n\n",
            "func render(receiver Widget, label string) int {\n",
            "\tvalue := receiver.Member\n",
            "\tkeyed := Widget{Member: value}\n",
            "label: for value < 2 {\n",
            "\t\tbreak label\n",
            "\t}\n",
            "\treturn value + unrelated\n",
            "}\n",
        );
        let tree = parse(source);
        let mut selectors = Vec::new();
        let mut identifiers = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "selector_expression" {
                selectors.push(node);
            }
            if matches!(
                node.kind(),
                "identifier" | "field_identifier" | "package_identifier" | "type_identifier"
            ) {
                identifiers.push(node);
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }

        // Same index the extraction driver builds; the classifier must answer
        // exactly what `Node::parent` answered before it was threaded through.
        let parents = ParentIndex::new(tree.root_node());

        assert_eq!(selectors.len(), 1, "fixture should contain one selector");
        let selector = selectors[0];
        let member = selector
            .child_by_field_name("field")
            .expect("selector member");
        let receiver = selector
            .child_by_field_name("operand")
            .expect("selector receiver");
        assert_eq!(
            go_occurrence_role(member, &parents),
            Some(OccurrenceRole::MemberPosition)
        );
        assert_eq!(go_occurrence_role(receiver, &parents), None);

        let keyed_member = identifiers
            .iter()
            .copied()
            .find(|node| {
                node.parent().is_some_and(|literal| {
                    literal.parent().is_some_and(|keyed| {
                        keyed.kind() == "keyed_element"
                            && keyed.child_by_field_name("key") == Some(literal)
                    })
                })
            })
            .expect("keyed literal member name");
        assert_eq!(go_occurrence_role(keyed_member, &parents), None);

        for identifier in identifiers {
            let parent = identifier.parent();
            let is_selector_member = parent.is_some_and(|parent| {
                parent.kind() == "selector_expression"
                    && field_name_in_parent(parent, identifier) == Some("field")
            });
            if !is_selector_member {
                assert_ne!(
                    go_occurrence_role(identifier, &parents),
                    Some(OccurrenceRole::MemberPosition),
                    "non-selector identifier at {} must not be a member position",
                    identifier.start_byte()
                );
            }
        }

        assert!(
            GO_STRUCTURAL_SPEC
                .occurrence_role_support()
                .is_supported(OccurrenceRole::MemberPosition)
        );
        assert!(
            GO_STRUCTURAL_SPEC
                .occurrence_role_support()
                .iter()
                .filter(|(_, support)| support.is_supported())
                .all(|(role, _)| matches!(
                    role,
                    OccurrenceRole::MemberPosition | OccurrenceRole::Binder
                ))
        );
    }
}

#[cfg(test)]
mod result_use_tests {
    use super::{GoCallResultUseIndex, go_call_result_use};
    use brokk_bifrost_core::analyzer::structural::result_use::{
        CallResultUse, IntentionalDiscardKind,
    };
    use tree_sitter::Parser;

    fn tree(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("Go grammar");
        parser.parse(source, None).expect("Go tree")
    }

    fn calls(source: &str) -> Vec<(usize, String, CallResultUse)> {
        let tree = tree(source);
        let mut found = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression" {
                found.push((
                    node.start_byte(),
                    source[node.byte_range()].to_owned(),
                    go_call_result_use(node, source).for_port(0),
                ));
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child"));
            }
        }
        found.sort_by_key(|(start, _, _)| *start);
        found
    }

    #[test]
    fn direct_statement_loop_slots_and_nested_near_misses_are_distinct() {
        let source = concat!(
            "package p\n",
            "func sink(intValue int) {}\n",
            "func run() int {\n",
            "    f()\n",
            "    for f(); ready(); f() {}\n",
            "    sink(f())\n",
            "    return f()\n",
            "}\n",
        );
        let result = calls(source);
        assert_eq!(result[0].2, CallResultUse::Discarded);
        assert_eq!(result[1].2, CallResultUse::Discarded);
        assert_eq!(result[2].2, CallResultUse::Consumed);
        assert_eq!(result[3].2, CallResultUse::Discarded);
        assert_eq!(result[4].2, CallResultUse::Discarded);
        assert_eq!(result[5].2, CallResultUse::Consumed);
        assert_eq!(result[6].2, CallResultUse::Consumed);
    }

    #[test]
    fn blank_assignments_override_each_go_result_port() {
        let source = "package p\nfunc run() { _, _ = pair(); value, _ := pair(); }\n";
        let tree = tree(source);
        let mut pair_calls = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression" {
                pair_calls.push(node);
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child"));
            }
        }
        pair_calls.sort_by_key(|node| node.start_byte());
        let first = go_call_result_use(pair_calls[0], source);
        assert!(matches!(
            first.for_port(0),
            CallResultUse::IntentionalDiscard(IntentionalDiscardKind::GoBlankAssignment)
        ));
        assert!(matches!(
            first.for_port(1),
            CallResultUse::IntentionalDiscard(IntentionalDiscardKind::GoBlankAssignment)
        ));
        let second = go_call_result_use(pair_calls[1], source);
        assert_eq!(second.for_port(0), CallResultUse::Consumed);
        assert!(matches!(
            second.for_port(1),
            CallResultUse::IntentionalDiscard(IntentionalDiscardKind::GoBlankAssignment)
        ));
    }

    #[test]
    fn recovered_call_is_open_and_index_is_exact() {
        let source = "package p\nfunc run() { f(,); }\n";
        let tree = tree(source);
        assert!(tree.root_node().has_error());
        let call = {
            let mut stack = vec![tree.root_node()];
            let mut found = None;
            while let Some(node) = stack.pop() {
                if node.kind() == "call_expression" {
                    found = Some(node);
                    break;
                }
                for index in (0..node.named_child_count()).rev() {
                    stack.push(node.named_child(index).expect("named child"));
                }
            }
            found.expect("recovered call")
        };
        assert!(matches!(
            go_call_result_use(call, source).for_port(0),
            CallResultUse::Open(_)
        ));
        let index = GoCallResultUseIndex::new(tree.root_node(), source);
        assert!(index.at_span(call.start_byte(), call.end_byte()).is_ok());
    }
}
