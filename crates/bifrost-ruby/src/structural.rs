//! Ruby structural spec for `query_code`.

use crate::local_bindings::{
    LocalBindingTimeline, UnboundedLocalBindingBudget, collect_local_bindings,
};
use crate::syntax::single_static_string_content_node;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_argument_role_with_derived_name, attach_role_with_derived_name, attach_terminal_callee,
    field_name_in_parent, first_named_child, nearest_ancestor,
};
use brokk_bifrost_core::analyzer::structural::callable::CallSiteContext;
use brokk_bifrost_core::analyzer::structural::edges::{
    INVERSE_REFERENCE_EDGE_SUPPORT, ReferenceEdgeSupport,
};
use brokk_bifrost_core::analyzer::structural::facts::Span;
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::materialization::{
    DeclarationMaterializationSupport, RUBY_MATERIALIZATION_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::occurrences::{
    OccurrenceRole, OccurrenceRoleSupport,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    BindingActivation, BindingKind, EnvironmentAxis, HoistingClass, LexicalEnvironmentSupport,
    ScopeFormation,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    IdentityRouteSupport, NO_IDENTITY_ROUTE_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::spec::{RoleSink, StructuralSpec};
use brokk_bifrost_core::analyzer::{Language, Range};
use brokk_bifrost_core::hash::HashSet;
use tree_sitter::Node;

#[derive(Debug, Default)]
pub struct RubyStructuralSpec;

pub static RUBY_STRUCTURAL_SPEC: RubyStructuralSpec = RubyStructuralSpec;

pub const RUBY_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("call", NormalizedKind::Call),
    ("method", NormalizedKind::Function),
    ("singleton_method", NormalizedKind::Method),
    ("block", NormalizedKind::Lambda),
    ("do_block", NormalizedKind::Lambda),
    ("lambda", NormalizedKind::Lambda),
    ("class", NormalizedKind::Class),
    // `class << self` reopens the singleton class: a class-like declaration
    // that, like every other Ruby class body, opens its own local scope.
    ("singleton_class", NormalizedKind::Class),
    ("module", NormalizedKind::Module),
    ("assignment", NormalizedKind::Assignment),
    ("operator_assignment", NormalizedKind::Assignment),
    ("scope_resolution", NormalizedKind::FieldAccess),
    ("unary", NormalizedKind::NumericLiteral),
    ("identifier", NormalizedKind::Identifier),
    ("constant", NormalizedKind::Identifier),
    ("instance_variable", NormalizedKind::Identifier),
    ("class_variable", NormalizedKind::Identifier),
    ("global_variable", NormalizedKind::Identifier),
    ("self", NormalizedKind::Identifier),
    ("simple_symbol", NormalizedKind::Identifier),
    ("delimited_symbol", NormalizedKind::Identifier),
    ("hash_key_symbol", NormalizedKind::Identifier),
    ("string", NormalizedKind::StringLiteral),
    ("integer", NormalizedKind::NumericLiteral),
    ("float", NormalizedKind::NumericLiteral),
    ("true", NormalizedKind::BooleanLiteral),
    ("false", NormalizedKind::BooleanLiteral),
    ("nil", NormalizedKind::NullLiteral),
    ("return", NormalizedKind::Return),
    ("rescue", NormalizedKind::Catch),
    ("if", NormalizedKind::If),
    ("unless", NormalizedKind::If),
    ("while", NormalizedKind::WhileLoop),
    ("until", NormalizedKind::WhileLoop),
    ("for", NormalizedKind::ForLoop),
];

fn expression_target_node(mut node: Node<'_>) -> Node<'_> {
    while matches!(node.kind(), "parenthesized_statements") {
        let Some(child) = first_named_child(node) else {
            break;
        };
        node = child;
    }
    node
}

fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression_target_node(expression);
    loop {
        match current.kind() {
            "identifier" | "constant" | "instance_variable" | "class_variable"
            | "global_variable" | "self" | "hash_key_symbol" => return Some(current),
            "simple_symbol" | "delimited_symbol" => return symbol_name_node(current),
            "scope_resolution" => current = current.child_by_field_name("name")?,
            "call" => current = current.child_by_field_name("method")?,
            "pair" => current = current.child_by_field_name("key")?,
            _ => return None,
        }
    }
}

fn symbol_name_node(node: Node<'_>) -> Option<Node<'_>> {
    first_named_child_of_kind(node, "string_content").or(Some(node))
}

fn first_named_child_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .find(|child| child.kind() == kind)
}

fn is_numeric_literal_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "integer" | "float")
}

fn is_signed_numeric_unary(node: Node<'_>) -> bool {
    node.kind() == "unary"
        && node
            .child_by_field_name("operator")
            .is_some_and(|operator| matches!(operator.kind(), "+" | "-"))
        && node
            .child_by_field_name("operand")
            .map(expression_target_node)
            .is_some_and(is_numeric_literal_node)
}

fn is_inside_signed_numeric_wrapper(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    is_signed_numeric_unary(parent)
}

fn call_method_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("method")
}

/// Whether `node` opens a new local-variable scope nested inside another
/// scope's walk. The `block`/`do_block` wrapper directly under a `lambda` is
/// the lambda's own body, not a nested scope, matching the semantic
/// lowering's `callable_shape`.
fn is_nested_scope_root(node: Node<'_>) -> bool {
    match node.kind() {
        "method" | "singleton_method" | "class" | "module" | "singleton_class" | "lambda" => true,
        "block" | "do_block" => node.parent().is_none_or(|parent| parent.kind() != "lambda"),
        _ => false,
    }
}

/// Whether an identifier at this grammatical position is a value read: a
/// position where Ruby evaluates the name, so an identifier that is not an
/// active local variable is a zero-argument bare call. The list is a closed
/// whitelist over parent node kinds and AST fields; every position not on it
/// (parameter lists, assignment targets, pattern binders, method name fields)
/// keeps its `Identifier` kind, preserving the honest status quo for
/// constructs this pass does not understand.
fn is_value_read_position(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let is_field = |field: &str| {
        parent
            .child_by_field_name(field)
            .is_some_and(|child| child.id() == node.id())
    };
    match parent.kind() {
        // Statement containers.
        "program" | "body_statement" | "then" | "else" | "do" | "block_body" | "begin"
        | "interpolation" => true,
        // A parenthesized expression reads its content wherever the
        // parentheses themselves are read -- except under `defined?`, whose
        // operand arrives wrapped in parentheses and is observed, not
        // evaluated.
        "parenthesized_statements" => {
            let mut ancestor = parent;
            while ancestor.kind() == "parenthesized_statements" {
                match ancestor.parent() {
                    Some(next) => ancestor = next,
                    None => return true,
                }
            }
            !(ancestor.kind() == "unary"
                && ancestor
                    .child_by_field_name("operator")
                    .is_some_and(|operator| operator.kind() == "defined?"))
        }
        // Argument positions, including spread and block-pass wrappers.
        "argument_list" | "splat_argument" | "hash_splat_argument" | "block_argument" => true,
        // Operand positions.
        "binary" | "range" | "array" | "element_reference" => true,
        // `defined?(x)` observes the name without evaluating it, so its
        // operand stays an identifier.
        "unary" => {
            is_field("operand")
                && parent
                    .child_by_field_name("operator")
                    .is_none_or(|operator| operator.kind() != "defined?")
        }
        // Conditions, case subjects, `when` values, and ternary branches.
        "if" | "unless" | "elsif" | "while" | "until" | "conditional" | "case" | "case_match"
        | "when" | "rescue_modifier" => true,
        "pair" => is_field("value"),
        "assignment" | "operator_assignment" => is_field("right"),
        "call" => is_field("receiver"),
        _ => false,
    }
}

/// One iterative pass over the file: the start byte of every identifier that
/// is a value-position bare call. Scopes are walked outermost-first so each
/// nested block or lambda can inherit the bindings active at its creation
/// byte, exactly as the semantic lowering's `collect_local_bindings` callers
/// do; identifiers are classified against their scope's precomputed
/// [`LocalBindingTimeline`], never by a per-identifier backward scan.
fn bare_call_identifier_starts(root: Node<'_>, source: &str) -> HashSet<usize> {
    let mut starts = HashSet::default();
    let mut timelines: Vec<LocalBindingTimeline> = Vec::new();
    let mut scopes: Vec<(Node<'_>, Option<usize>)> = vec![(root, None)];
    while let Some((scope, inherited)) = scopes.pop() {
        let body = scope.child_by_field_name("body").unwrap_or(scope);
        let inherited_bindings = matches!(scope.kind(), "lambda" | "block" | "do_block")
            .then(|| inherited.map(|index| (&timelines[index], scope.start_byte())))
            .flatten();
        let collection = collect_local_bindings(
            source,
            scope,
            body,
            inherited_bindings,
            &mut UnboundedLocalBindingBudget,
        )
        .unwrap_or_else(|impossible| match impossible {});
        let timeline_index = timelines.len();
        timelines.push(collection.timeline);
        let timeline = &timelines[timeline_index];

        let mut walk = vec![scope];
        while let Some(node) = walk.pop() {
            for index in (0..node.named_child_count()).rev() {
                let Some(child) = node.named_child(index) else {
                    continue;
                };
                if is_nested_scope_root(child) {
                    scopes.push((child, Some(timeline_index)));
                } else {
                    walk.push(child);
                }
            }
            if node.kind() == "identifier"
                && is_value_read_position(node)
                && !timeline.is_active_at(node_text(node, source), node.start_byte())
            {
                starts.insert(node.start_byte());
            }
        }
    }
    starts
}

fn attach_argument_roles(sink: &mut RoleSink<'_>, arguments: Node<'_>) {
    for index in 0..arguments.named_child_count() {
        if !sink.should_continue() {
            break;
        }
        let Some(argument) = arguments.named_child(index) else {
            continue;
        };
        if argument.kind() == "pair" {
            if let Some(key) = argument.child_by_field_name("key")
                && let Some(value) = argument
                    .child_by_field_name("value")
                    .map(expression_target_node)
            {
                sink.kwarg(expression_name_node(key).unwrap_or(key), value);
            }
        } else {
            attach_argument_role_with_derived_name(sink, argument, expression_name_node);
        }
    }
}

fn node_text<'source>(node: Node<'_>, source: &'source str) -> &'source str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}

fn module_argument_node(node: Node<'_>) -> Option<Node<'_>> {
    let arguments = node.child_by_field_name("arguments")?;
    (0..arguments.named_child_count())
        .filter_map(|index| arguments.named_child(index))
        .find(|argument| argument.kind() == "string")
}

fn is_import_call(node: Node<'_>, source: &str) -> bool {
    if node.child_by_field_name("receiver").is_some() {
        return false;
    }

    let Some(method) = call_method_node(node) else {
        return false;
    };
    matches!(
        node_text(method, source).trim(),
        "require" | "require_relative" | "load" | "autoload"
    ) && module_argument_node(node).is_some()
}

fn static_string_content_span(node: Node<'_>) -> Option<Span> {
    if node.kind() != "string" {
        return None;
    }
    let content = single_static_string_content_node(node)?;
    Some(Span {
        start_byte: content.start_byte(),
        end_byte: content.end_byte(),
    })
}

/// Climb the one grammar wrapper that stands between a bare name and the node
/// whose field position classifies it.
///
/// Both `def name=(value)` and `receiver.name = value` put the bare name under
/// a `setter` node that occupies its owner's `name`/`method` field, so the
/// position that decides the role belongs to the wrapper, not the identifier.
fn setter_wrapper<'tree>(node: Node<'tree>) -> Node<'tree> {
    node.parent()
        .filter(|parent| {
            parent.kind() == "setter"
                && parent
                    .child_by_field_name("name")
                    .is_some_and(|name| name.id() == node.id())
        })
        .unwrap_or(node)
}

/// Classify one Ruby name token by its AST position.
///
/// Ruby's grammar separates the kinds of name that can never be a lexical
/// binding into their own node types, which is what makes this classification
/// structural rather than a spelling test: `@x`, `@@x` and `$x` are
/// `instance_variable`, `class_variable` and `global_variable`, and no binder
/// introduces them -- an assignment to one writes a member or a global that
/// exists independently of any scope. They are therefore value references
/// wherever they appear and never [`OccurrenceRole::Binder`].
///
/// `identifier` and `constant` are the two kinds a position can bind, and only
/// an `identifier` ever does: a `constant` on the left of an assignment
/// declares a constant, which Ruby resolves through module nesting rather than
/// through the lexical environment.
fn ruby_occurrence_role(node: Node<'_>) -> Option<OccurrenceRole> {
    match node.kind() {
        "instance_variable" | "class_variable" | "global_variable" => {
            return Some(OccurrenceRole::ValueReference);
        }
        // A valueless pattern key (`in {name:}`) binds the key's own spelling.
        // Every other `hash_key_symbol` is a label, which this adapter does not
        // classify.
        "hash_key_symbol" => {
            let parent = node.parent()?;
            return (parent.kind() == "keyword_pattern"
                && field_name_in_parent(parent, node) == Some("key")
                && parent.child_by_field_name("value").is_none())
            .then_some(OccurrenceRole::Binder);
        }
        "identifier" | "constant" => {}
        _ => return None,
    }
    let binds = node.kind() == "identifier";
    let subject = setter_wrapper(node);
    let parent = subject.parent()?;
    let field = field_name_in_parent(parent, subject);
    let role = match parent.kind() {
        "method" | "singleton_method" | "class" | "module" if field == Some("name") => {
            OccurrenceRole::DeclarationName
        }
        // `CONST = 1` names the constant the assignment declares.
        "assignment" if field == Some("left") && !binds => OccurrenceRole::DeclarationName,
        "call" => match field {
            Some("method") if parent.child_by_field_name("receiver").is_some() => {
                OccurrenceRole::MemberPosition
            }
            Some("receiver") => OccurrenceRole::ReceiverPosition,
            _ => OccurrenceRole::ValueReference,
        },
        // `A::B` is the same two-part shape as a member access: the scope is
        // the receiver, the name is the member selected from it.
        "scope_resolution" => match field {
            Some("name") => OccurrenceRole::MemberPosition,
            Some("scope") => OccurrenceRole::ReceiverPosition,
            _ => OccurrenceRole::ValueReference,
        },
        "method_parameters"
        | "lambda_parameters"
        | "block_parameters"
        | "destructured_parameter"
            if binds =>
        {
            OccurrenceRole::Binder
        }
        "optional_parameter"
        | "keyword_parameter"
        | "splat_parameter"
        | "hash_splat_parameter"
        | "block_parameter"
            if binds && field == Some("name") =>
        {
            OccurrenceRole::Binder
        }
        "assignment" | "operator_assignment" if binds && field == Some("left") => {
            OccurrenceRole::Binder
        }
        "left_assignment_list" | "destructured_left_assignment" | "rest_assignment" if binds => {
            OccurrenceRole::Binder
        }
        "for" if binds && field == Some("pattern") => OccurrenceRole::Binder,
        "exception_variable" if binds => OccurrenceRole::Binder,
        // Pattern binders. `variable_reference_pattern` is deliberately absent:
        // `in ^pinned` reads the name it pins instead of binding it, and a
        // pattern's `class` field names the constant being matched against.
        "array_pattern" | "find_pattern" | "alternative_pattern" | "parenthesized_pattern"
            if binds && field != Some("class") =>
        {
            OccurrenceRole::Binder
        }
        "as_pattern" if binds => OccurrenceRole::Binder,
        "keyword_pattern" if binds && field == Some("value") => OccurrenceRole::Binder,
        "in_clause" if binds && field == Some("pattern") => OccurrenceRole::Binder,
        _ => OccurrenceRole::ValueReference,
    };
    Some(role)
}

/// The binding one Ruby binder token introduces, and the interval it is in
/// effect over.
///
/// Ruby's rule for a local is positional and not scope-categorical: the parser
/// declares the name when it reads the assignment, so the local is in effect
/// from the end of its binder token to the end of the scope it is written in.
/// `x = x` is the sharpest statement of that boundary -- the right-hand `x` is
/// already the (nil) local, not a method call -- which is why the interval
/// starts at the binder's own end rather than at the end of the whole
/// assignment.
///
/// Parameters are the exception: a method, block or lambda parameter is in
/// effect over the whole callable whatever the position, which is `ScopeWide`.
///
/// No arm answers `None`: every position this adapter classifies as a binder
/// introduces a local of its declaring scope even when the surrounding form is
/// one this match does not name, so an unrecognized shape falls through to the
/// general Ruby rule instead of making the file's binding set incomplete.
fn ruby_binding_activation(binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
    let from_binder = |kind: BindingKind| {
        Some(BindingActivation {
            kind,
            hoisting: HoistingClass::SourceOrder,
            activation: Range {
                start_byte: binder.end_byte(),
                end_byte: scope.end_byte,
                start_line: binder.end_position().row + 1,
                end_line: scope.end_line,
            },
        })
    };
    let form = nearest_ancestor(binder, |kind| {
        matches!(
            kind,
            "method_parameters"
                | "lambda_parameters"
                | "block_parameters"
                | "exception_variable"
                | "for"
                | "in_clause"
                | "match_pattern"
                | "test_pattern"
                | "assignment"
                | "operator_assignment"
        )
    });
    match form.map(|form| form.kind()) {
        Some("method_parameters" | "lambda_parameters") => Some(BindingActivation {
            kind: BindingKind::Parameter,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
        Some("block_parameters") => {
            // `|value; scratch|` declares `scratch` as a fresh local of the
            // block rather than as one of its parameters, and the grammar puts
            // it in the parameter list's own `locals` field.
            let block_local = binder
                .parent()
                .is_some_and(|parent| field_name_in_parent(parent, binder) == Some("locals"));
            Some(BindingActivation {
                kind: if block_local {
                    BindingKind::Local
                } else {
                    BindingKind::Parameter
                },
                hoisting: HoistingClass::ScopeWide,
                activation: scope,
            })
        }
        // `rescue => error` assigns an ordinary local of the enclosing scope:
        // Ruby's parser declares the name in that scope's local table, so it
        // outlives the rescue clause.
        Some("exception_variable") => from_binder(BindingKind::CatchOrResource),
        // `for` is the Ruby loop that does *not* scope its variable: the name
        // survives the loop, which is the documented difference from `each`.
        Some("for") => from_binder(BindingKind::LoopVariable),
        Some("in_clause" | "match_pattern" | "test_pattern") => {
            from_binder(BindingKind::PatternBinder)
        }
        _ => from_binder(BindingKind::Local),
    }
}

static RUBY_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport = OccurrenceRoleSupport::NONE
    .supported(OccurrenceRole::DeclarationName)
    .supported(OccurrenceRole::Binder)
    .supported(OccurrenceRole::ReceiverPosition)
    .supported(OccurrenceRole::MemberPosition)
    .supported(OccurrenceRole::ValueReference);

/// Ruby answers its scope tree and its binding intervals, and deliberately
/// nothing else (#2962).
///
/// `ImportBinders` stays unsupported because Ruby has no import binder:
/// `require` and `require_relative` load a file and introduce no local name,
/// and a constant written after them resolves through module nesting rather
/// than through a name the statement bound. Declaring the axis supported would
/// make an empty import-binder row set read as "nothing reaches this file's
/// names from elsewhere", which is false.
///
/// `PackageClause` stays unsupported for the same reason in the other
/// direction: a Ruby file states no package, and its namespacing is
/// `module`/`class` nesting -- a scope fact this adapter does answer, and one
/// that belongs to declarations rather than to the file.
///
/// The two candidate axes stay unsupported: no tier of the Ruby resolver
/// reports the candidates it considered or discarded.
static RUBY_LEXICAL_ENVIRONMENT_SUPPORT: LexicalEnvironmentSupport =
    LexicalEnvironmentSupport::NONE
        .supported(EnvironmentAxis::Scopes)
        .supported(EnvironmentAxis::BindingIntervals);

impl StructuralSpec for RubyStructuralSpec {
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn supports_boolean_literal_value(&self) -> bool {
        true
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        RUBY_KIND_TABLE
    }

    /// One scan of the file for the identifiers that are value-position bare
    /// calls: whether `x` reads a local or calls a method depends on the
    /// assignments and parameters lexically before it, which `refine_kind`
    /// cannot see per node.
    fn call_site_context(&self, root: Node<'_>, source: &str) -> CallSiteContext {
        CallSiteContext::with_identifier_call_starts(bare_call_identifier_starts(root, source))
    }

    fn refine_kind(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        enclosing: Option<NormalizedKind>,
        source: &str,
        context: &CallSiteContext,
    ) -> NormalizedKind {
        if node.kind() == "identifier" && context.is_identifier_call_at(node.start_byte()) {
            NormalizedKind::Call
        } else if node.kind() == "call" && is_import_call(node, source) {
            NormalizedKind::Import
        } else if node.kind() == "method"
            && kind == NormalizedKind::Function
            && enclosing == Some(NormalizedKind::Class)
        {
            NormalizedKind::Method
        } else {
            kind
        }
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        if kind == NormalizedKind::Lambda
            && matches!(node.kind(), "block" | "do_block")
            && node
                .parent()
                .is_some_and(|parent| parent.kind() == "lambda")
        {
            return false;
        }

        if kind == NormalizedKind::NumericLiteral {
            if node.kind() == "unary" {
                return is_signed_numeric_unary(node);
            }
            if is_numeric_literal_node(node) && is_inside_signed_numeric_wrapper(node) {
                return false;
            }
        }

        true
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        kind == NormalizedKind::Import
            || self
                .kind_table()
                .iter()
                .any(|(_, fact_kind)| fact_kind.satisfies(kind))
    }

    fn supports_role(&self, role: Role) -> bool {
        !matches!(role, Role::Decorator | Role::Iterable | Role::Element)
    }

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &RUBY_OCCURRENCE_ROLE_SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        &RUBY_LEXICAL_ENVIRONMENT_SUPPORT
    }

    /// Ruby opens a fresh local-variable scope at exactly these forms:
    /// `method`, `singleton_method`, `block`, `do_block`, `lambda`, `class`,
    /// `singleton_class` and `module`, plus the file itself (which the
    /// derivation layer synthesizes). That set is the one the crate's own
    /// `collect_local_bindings` walks, and it excludes the two the shared
    /// default would add: a Ruby `while`/`until`/`for` and a `rescue` clause
    /// do not scope anything, so a local first assigned inside one is still in
    /// effect after it. Ruby also has no member space -- a bare `x = 1` in a
    /// class or module body is an ordinary local of that body, while its
    /// members are `def`s and instance variables, which are not binder tokens.
    fn scope_formation(&self, kind: NormalizedKind) -> ScopeFormation {
        if kind.satisfies(NormalizedKind::Callable)
            || kind.satisfies(NormalizedKind::Class)
            || kind == NormalizedKind::Module
        {
            ScopeFormation::BindingScope
        } else {
            ScopeFormation::NotAScope
        }
    }

    fn binding_activation(&self, binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
        ruby_binding_activation(binder, scope)
    }

    fn materialization_support(&self) -> &DeclarationMaterializationSupport {
        &RUBY_MATERIALIZATION_SUPPORT
    }

    fn reference_edge_support(&self) -> &ReferenceEdgeSupport {
        &INVERSE_REFERENCE_EDGE_SUPPORT
    }

    fn identity_route_support(&self) -> &IdentityRouteSupport {
        &NO_IDENTITY_ROUTE_SUPPORT
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        if let Some(role) = ruby_occurrence_role(node) {
            sink.occurrence_role(node, role);
        }

        match kind {
            NormalizedKind::Call => {
                // An identifier fact only carries the Call kind through the
                // bare-call refinement above, and it is its own callee.
                if node.kind() == "identifier" {
                    attach_terminal_callee(sink, node, Some(node));
                } else if let Some(method) = call_method_node(node) {
                    attach_terminal_callee(sink, method, expression_name_node(method));
                }
                if let Some(receiver) = node.child_by_field_name("receiver") {
                    attach_role_with_derived_name(
                        sink,
                        Role::Receiver,
                        receiver,
                        expression_name_node,
                    );
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    attach_argument_roles(sink, arguments);
                }
                if let Some(block) = node.child_by_field_name("block") {
                    attach_role_with_derived_name(sink, Role::Arg, block, expression_name_node);
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(field) = node.child_by_field_name("name") {
                    attach_role_with_derived_name(sink, Role::Field, field, expression_name_node);
                    if let Some(name) = expression_name_node(field) {
                        sink.set_name(name);
                    }
                }
                if let Some(object) = node.child_by_field_name("scope") {
                    attach_role_with_derived_name(sink, Role::Object, object, expression_name_node);
                }
            }
            NormalizedKind::Function
            | NormalizedKind::Method
            | NormalizedKind::Class
            | NormalizedKind::Module
            | NormalizedKind::Declaration => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(expression_name_node(name).unwrap_or(name));
                }
            }
            NormalizedKind::Assignment => {
                if let Some(left) = node.child_by_field_name("left") {
                    let left = expression_target_node(left);
                    attach_role_with_derived_name(sink, Role::Left, left, expression_name_node);
                    if let Some(name) = expression_name_node(left) {
                        sink.set_name(name);
                    }
                }
                if let Some(right) = node.child_by_field_name("right") {
                    let right = expression_target_node(right);
                    attach_role_with_derived_name(sink, Role::Right, right, expression_name_node);
                }
            }
            NormalizedKind::Import => {
                if let Some(module) = module_argument_node(node)
                    && let Some(name) = static_string_content_span(module)
                {
                    sink.role_named_span(Role::Module, module, name);
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
    use super::*;

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_ruby::LANGUAGE.into())
            .expect("Ruby grammar is valid");
        parser.parse(source, None).expect("source parses")
    }

    /// The start byte of the `occurrence`-th (0-based) appearance of `needle`
    /// as a whole identifier in `source`.
    fn identifier_start(source: &str, needle: &str, occurrence: usize) -> usize {
        let mut found = 0;
        let mut from = 0;
        loop {
            let start = from
                + source[from..]
                    .find(needle)
                    .unwrap_or_else(|| panic!("needle {needle:?} occurrence {occurrence}"));
            let boundary = |byte: Option<u8>| {
                byte.is_none_or(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_'))
            };
            if boundary(source.as_bytes().get(start.wrapping_sub(1)).copied())
                && boundary(source.as_bytes().get(start + needle.len()).copied())
            {
                if found == occurrence {
                    return start;
                }
                found += 1;
            }
            from = start + needle.len();
        }
    }

    fn bare_call_starts(source: &str) -> HashSet<usize> {
        let tree = parse(source);
        bare_call_identifier_starts(tree.root_node(), source)
    }

    /// Every token this adapter classifies, in source order, as
    /// `(start byte, text, role)`.
    fn occurrence_roles(source: &str) -> Vec<(usize, String, OccurrenceRole)> {
        let tree = parse(source);
        let mut found = Vec::new();
        let mut walk = vec![tree.root_node()];
        while let Some(node) = walk.pop() {
            if let Some(role) = ruby_occurrence_role(node) {
                found.push((
                    node.start_byte(),
                    node.utf8_text(source.as_bytes())
                        .expect("a classified token is valid UTF-8")
                        .to_owned(),
                    role,
                ));
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    walk.push(child);
                }
            }
        }
        found.sort_by_key(|(start, _, _)| *start);
        found
    }

    /// The tokens classified with `role`, in source order.
    fn tokens_with_role(source: &str, role: OccurrenceRole) -> Vec<String> {
        occurrence_roles(source)
            .into_iter()
            .filter(|(_, _, found)| *found == role)
            .map(|(_, text, _)| text)
            .collect()
    }

    fn member_positions(source: &str) -> Vec<(usize, String)> {
        occurrence_roles(source)
            .into_iter()
            .filter(|(_, _, role)| *role == OccurrenceRole::MemberPosition)
            .map(|(start, text, _)| (start, text))
            .collect()
    }

    fn assert_bare_call(source: &str, needle: &str, occurrence: usize, expected: bool) {
        let starts = bare_call_starts(source);
        let start = identifier_start(source, needle, occurrence);
        assert_eq!(
            starts.contains(&start),
            expected,
            "{needle:?} occurrence {occurrence} at byte {start} in {source:?}; classified starts: {starts:?}"
        );
    }

    /// The issue's smallest fixture: the bare source call in argument
    /// position is a call; the enclosing `dfb_sink(...)` is a `call` grammar
    /// node whose method identifier is not separately classified.
    #[test]
    fn argument_position_bare_call_is_classified() {
        let source = "def dfb_source\n  \"tainted\"\nend\n\ndef dfb_sink(value)\nend\n\ndef run\n  dfb_sink(dfb_source)\nend\n";
        assert_bare_call(source, "dfb_source", 1, true);
        assert_bare_call(source, "dfb_sink", 1, false);
    }

    /// The assignment-value form: the right side is a call, the assigned
    /// local on the left is not, and the later read of the local is not.
    #[test]
    fn assignment_value_bare_call_is_classified_and_the_local_is_not() {
        let source = "def dfb_source\n  \"tainted\"\nend\n\ndef dfb_sink(value)\nend\n\ndef run\n  value = dfb_source\n  dfb_sink(value)\nend\n";
        assert_bare_call(source, "dfb_source", 1, true);
        assert_bare_call(source, "value", 1, false);
        assert_bare_call(source, "value", 2, false);
    }

    /// A statement-position bare call keeps its classification, and the
    /// parenthesized form never enters the identifier path (its `call` node
    /// is the call; the method identifier is a field of it).
    #[test]
    fn statement_position_and_parenthesized_forms_are_unchanged() {
        let source =
            "def dfb_source\n  \"tainted\"\nend\n\ndef run\n  dfb_source\n  dfb_source()\nend\n";
        assert_bare_call(source, "dfb_source", 1, true);
        assert_bare_call(source, "dfb_source", 2, false);
    }

    /// A local variable named like the source method shadows the bare call:
    /// once assigned, reads of the name stay identifiers. The assignment's
    /// own right side is a bare call to another name.
    #[test]
    fn assigned_local_shadows_the_same_named_bare_call() {
        let source = "def run\n  dfb_source = compute\n  dfb_sink(dfb_source)\nend\n";
        assert_bare_call(source, "compute", 0, true);
        assert_bare_call(source, "dfb_source", 0, false);
        assert_bare_call(source, "dfb_source", 1, false);
    }

    /// A parameter named like the source method makes every read a local
    /// read over the whole body.
    #[test]
    fn parameter_shadows_the_same_named_bare_call() {
        let source = "def run(dfb_source)\n  dfb_sink(dfb_source)\nend\n";
        assert_bare_call(source, "dfb_source", 1, false);
    }

    /// A same-named method call on a receiver is the `call` node's own
    /// business: its method identifier is not classified, its bound receiver
    /// is a local read, and an unbound receiver is itself a bare call.
    #[test]
    fn receiver_calls_classify_only_the_unbound_receiver() {
        let source =
            "def run\n  helper = Helper.new\n  helper.dfb_source\n  unbound.dfb_source\nend\n";
        assert_bare_call(source, "dfb_source", 0, false);
        assert_bare_call(source, "dfb_source", 1, false);
        assert_bare_call(source, "helper", 1, false);
        assert_bare_call(source, "unbound", 0, true);
    }

    /// Nested argument positions classify the innermost bare call.
    #[test]
    fn nested_argument_positions_are_classified() {
        let source = "def run\n  dfb_sink(wrap(dfb_source))\nend\n";
        assert_bare_call(source, "dfb_source", 0, true);
        assert_bare_call(source, "wrap", 0, false);
    }

    /// Blocks inherit the bindings active at their creation byte: a local
    /// assigned before the block stays a local inside it, and a free name
    /// inside the block is a bare call.
    #[test]
    fn blocks_inherit_active_bindings() {
        let source = "def run\n  captured = 1\n  items.each do |x|\n    dfb_sink(captured)\n    dfb_sink(free_name)\n    dfb_sink(x)\n  end\nend\n";
        assert_bare_call(source, "captured", 1, false);
        assert_bare_call(source, "free_name", 0, true);
        assert_bare_call(source, "x", 1, false);
        assert_bare_call(source, "items", 0, true);
    }

    /// The binding rule is lexical: a read before the assignment to the same
    /// name is a bare call at that byte.
    #[test]
    fn reads_before_the_activating_assignment_are_bare_calls() {
        let source = "def run\n  dfb_sink(v)\n  v = 1\n  dfb_sink(v)\nend\n";
        assert_bare_call(source, "v", 0, true);
        assert_bare_call(source, "v", 1, false);
        assert_bare_call(source, "v", 2, false);
    }

    /// The statement-position rule is timeline-gated too: a trailing read of
    /// a parameter is a local read, not a call (parity with the semantic
    /// lowering, which models it as a lexical input flow).
    #[test]
    fn trailing_local_reads_in_statement_position_stay_identifiers() {
        let source = "def run(x)\n  compute\n  x\nend\n";
        assert_bare_call(source, "compute", 0, true);
        assert_bare_call(source, "x", 1, false);
    }

    /// `defined?(name)` observes the name without evaluating it, in both the
    /// parenthesized and the bare-operand spelling.
    #[test]
    fn defined_operands_are_not_classified() {
        let source = "def run\n  defined?(maybe_missing)\n  defined? bare_operand\nend\n";
        assert_bare_call(source, "maybe_missing", 0, false);
        assert_bare_call(source, "bare_operand", 0, false);
    }

    /// Top-level program statements are a scope of their own.
    #[test]
    fn top_level_reads_follow_the_program_scope_timeline() {
        let source = "x = 1\nx\nfree_top_level\n";
        assert_bare_call(source, "x", 1, false);
        assert_bare_call(source, "free_top_level", 0, true);
    }

    /// Value reads in conditions, ternaries, operands, and interpolations
    /// are classified; binder positions (parameters, assignment targets,
    /// pattern binders) never are.
    #[test]
    fn condition_and_operand_positions_are_classified() {
        let source = "def run(bound)\n  if cond_call\n    bound + operand_call\n  end\n  cond_call ? bound : other_call\n  \"#{interp_call}\"\nend\n";
        assert_bare_call(source, "cond_call", 0, true);
        assert_bare_call(source, "operand_call", 0, true);
        assert_bare_call(source, "other_call", 0, true);
        assert_bare_call(source, "interp_call", 0, true);
        assert_bare_call(source, "bound", 1, false);
        assert_bare_call(source, "bound", 2, false);
    }

    /// Pattern-match binders and their reads stay identifiers; the matched
    /// subject is a read.
    #[test]
    fn pattern_binders_are_preserved_as_identifiers() {
        let source =
            "def run\n  case subject_call\n  in [first, second]\n    dfb_sink(first)\n  end\nend\n";
        assert_bare_call(source, "subject_call", 0, true);
        assert_bare_call(source, "first", 0, false);
        assert_bare_call(source, "first", 1, false);
        assert_bare_call(source, "second", 0, false);
    }

    /// Methods do not inherit enclosing locals: the same name that is a local
    /// outside is a bare call inside a nested method or class body.
    #[test]
    fn methods_and_classes_do_not_inherit_locals() {
        let source = "outer = 1\nouter\ndef run\n  outer\nend\nclass Widget\n  outer\nend\n";
        assert_bare_call(source, "outer", 1, false);
        assert_bare_call(source, "outer", 2, true);
        assert_bare_call(source, "outer", 3, true);
    }

    /// Ruby places ordinary and safe-navigation member names in the `method`
    /// field of a `call` node. The receiver, declaration and parameter names,
    /// hash key, bare call, and unrelated identifier in this fixture all have
    /// different AST positions and must remain unclassified.
    #[test]
    fn member_positions_are_limited_to_receiver_calls() {
        let source = concat!(
            "class Widget\n",
            "  def run(target, label:)\n",
            "    declared = compute\n",
            "    target.run\n",
            "    target&.safe_call\n",
            "    target.assigned = declared\n",
            "    bare_call\n",
            "    process(label: target)\n",
            "    { label: target }\n",
            "    unrelated_identifier\n",
            "  end\n",
            "end\n",
        );
        let expected = vec![
            (
                source.find("target.run").expect("ordinary member call") + "target.".len(),
                "run".to_owned(),
            ),
            (
                source
                    .find("target&.safe_call")
                    .expect("safe-navigation member call")
                    + "target&.".len(),
                "safe_call".to_owned(),
            ),
            (
                source.find("target.assigned").expect("setter member call") + "target.".len(),
                "assigned".to_owned(),
            ),
        ];
        assert_eq!(member_positions(source), expected);

        let support = RUBY_STRUCTURAL_SPEC.occurrence_role_support();
        let supported: Vec<OccurrenceRole> = support
            .iter()
            .filter(|(_, support)| support.is_supported())
            .map(|(role, _)| role)
            .collect();
        assert_eq!(
            supported,
            vec![
                OccurrenceRole::DeclarationName,
                OccurrenceRole::Binder,
                OccurrenceRole::ReceiverPosition,
                OccurrenceRole::MemberPosition,
                OccurrenceRole::ValueReference,
            ],
            "the declared role set is exactly what `ruby_occurrence_role` \
             classifies; a role this adapter cannot establish structurally \
             (an import binder, a label, a type operand) must stay unsupported"
        );
    }

    /// Every position that introduces a local, in one file: method and block
    /// parameters in each spelling, a plain and a multiple assignment, a `for`
    /// variable, a rescue exception variable, and pattern binders. The tokens
    /// that look like binders but are not -- a pinned pattern read, a pattern
    /// class, an instance variable, a constant -- are absent by construction.
    #[test]
    fn every_local_introducing_position_is_classified_as_a_binder() {
        let source = concat!(
            "def run(plain, opt = 1, *rest, key:, **kw, &blk)\n",
            "  total = 0\n",
            "  first, second = pair\n",
            "  for step in 1..3\n",
            "    total += step\n",
            "  end\n",
            "  rows.each do |row, (left, right); scratch|\n",
            "    scratch = row\n",
            "  end\n",
            "  begin\n",
            "    risky\n",
            "  rescue => error\n",
            "    error\n",
            "  end\n",
            "  case value\n",
            "  in [head, *tail]\n",
            "    head\n",
            "  in {name:, age: years}\n",
            "    name\n",
            "  in Point(x:)\n",
            "    x\n",
            "  in ^pinned\n",
            "    1\n",
            "  in other => whole\n",
            "    whole\n",
            "  end\n",
            "  @member = total\n",
            "  CONST = total\n",
            "end\n",
        );
        assert_eq!(
            tokens_with_role(source, OccurrenceRole::Binder),
            vec![
                "plain", "opt", "rest", "key", "kw", "blk", "total", "first", "second", "step",
                // `total += step` rebinds the local, exactly as a second
                // assignment to the same name would.
                "total", "row", "left", "right", "scratch", "scratch", "error", "head", "tail",
                "name", "years", "x", "other", "whole",
            ],
            "classified roles: {:?}",
            occurrence_roles(source)
        );
        assert!(
            !tokens_with_role(source, OccurrenceRole::Binder)
                .iter()
                .any(|token| matches!(token.as_str(), "pinned" | "Point" | "@member" | "CONST")),
            "a pinned read, a pattern class, an instance variable and a \
             constant are never lexical binders"
        );
    }

    /// `@x`, `@@x` and `$x` are their own grammar node kinds, so excluding
    /// them from the binder role needs no spelling test: they are value
    /// references wherever they appear, including on the left of an
    /// assignment, because no binder introduces them.
    #[test]
    fn member_and_global_variables_are_value_references_never_binders() {
        let source = "def run(seed)\n  @size = seed\n  @@count = @size\n  $global = @@count\nend\n";
        assert_eq!(
            tokens_with_role(source, OccurrenceRole::Binder),
            vec!["seed"]
        );
        assert_eq!(
            tokens_with_role(source, OccurrenceRole::ValueReference),
            vec!["@size", "seed", "@@count", "@size", "$global", "@@count"]
        );
    }

    /// Declaration names cover every named declaration form, and a constant
    /// assignment names the constant it declares rather than binding a local.
    #[test]
    fn declaration_names_cover_the_named_declaration_forms() {
        let source = concat!(
            "module Api\n",
            "  class Widget\n",
            "    LIMIT = 3\n",
            "    def render\n",
            "    end\n",
            "    def self.build\n",
            "    end\n",
            "    def size=(value)\n",
            "    end\n",
            "  end\n",
            "end\n",
        );
        assert_eq!(
            tokens_with_role(source, OccurrenceRole::DeclarationName),
            vec!["Api", "Widget", "LIMIT", "render", "build", "size"],
            "classified roles: {:?}",
            occurrence_roles(source)
        );
    }

    /// `A::B` is the same two-part shape as `receiver.member`, so the scope is
    /// a receiver and the selected name is a member position.
    #[test]
    fn a_scope_resolution_reads_as_a_receiver_and_a_member() {
        let source = "value = Api::Widget\n";
        assert_eq!(
            tokens_with_role(source, OccurrenceRole::ReceiverPosition),
            vec!["Api"]
        );
        assert_eq!(
            tokens_with_role(source, OccurrenceRole::MemberPosition),
            vec!["Widget"]
        );
    }

    /// Ruby's scope set is exactly the forms that open a local-variable
    /// scope. A `while`, a `for` and a `rescue` normalize to kinds every
    /// C-family adapter scopes; Ruby must not, because a local first assigned
    /// inside one is still in effect after it.
    #[test]
    fn only_the_local_variable_forms_open_a_ruby_scope() {
        for kind in [
            NormalizedKind::Function,
            NormalizedKind::Method,
            NormalizedKind::Lambda,
            NormalizedKind::Class,
            NormalizedKind::Module,
        ] {
            assert_eq!(
                RUBY_STRUCTURAL_SPEC.scope_formation(kind),
                ScopeFormation::BindingScope,
                "{kind:?} opens a Ruby local-variable scope whose binders are locals"
            );
        }
        for kind in [
            NormalizedKind::ForLoop,
            NormalizedKind::WhileLoop,
            NormalizedKind::Catch,
            NormalizedKind::Block,
            NormalizedKind::If,
        ] {
            assert_eq!(
                RUBY_STRUCTURAL_SPEC.scope_formation(kind),
                ScopeFormation::NotAScope,
                "{kind:?} does not scope a Ruby local"
            );
        }
    }

    /// The activation each binder form states: parameters are scope-wide over
    /// their callable, every other binder is in effect from the end of its own
    /// token to the end of its scope, and no form answers `None` -- an
    /// unstated interval would make the whole file's binding set incomplete.
    #[test]
    fn binder_forms_state_their_kind_and_interval() {
        let source = concat!(
            "def run(param)\n",
            "  local = 1\n",
            "  for step in 1..3\n",
            "  end\n",
            "  begin\n",
            "  rescue => error\n",
            "  end\n",
            "  case local\n",
            "  in [head]\n",
            "  end\n",
            "end\n",
        );
        let tree = parse(source);
        let scope = Range {
            start_byte: 0,
            end_byte: source.len(),
            start_line: 1,
            end_line: source.lines().count(),
        };
        let mut seen: Vec<(String, BindingKind, HoistingClass, usize)> = Vec::new();
        let mut walk = vec![tree.root_node()];
        while let Some(node) = walk.pop() {
            if ruby_occurrence_role(node) == Some(OccurrenceRole::Binder) {
                let activation = ruby_binding_activation(node, scope)
                    .unwrap_or_else(|| panic!("every binder states an interval: {node:?}"));
                seen.push((
                    node_text(node, source).to_owned(),
                    activation.kind,
                    activation.hoisting,
                    activation.activation.start_byte,
                ));
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    walk.push(child);
                }
            }
        }
        seen.sort_by_key(|(_, _, _, start)| *start);
        assert_eq!(
            seen,
            vec![
                (
                    "param".to_owned(),
                    BindingKind::Parameter,
                    HoistingClass::ScopeWide,
                    0
                ),
                (
                    "local".to_owned(),
                    BindingKind::Local,
                    HoistingClass::SourceOrder,
                    source.find("local").expect("local") + "local".len()
                ),
                (
                    "step".to_owned(),
                    BindingKind::LoopVariable,
                    HoistingClass::SourceOrder,
                    source.find("step").expect("step") + "step".len()
                ),
                (
                    "error".to_owned(),
                    BindingKind::CatchOrResource,
                    HoistingClass::SourceOrder,
                    source.find("error").expect("error") + "error".len()
                ),
                (
                    "head".to_owned(),
                    BindingKind::PatternBinder,
                    HoistingClass::SourceOrder,
                    source.find("head").expect("head") + "head".len()
                ),
            ],
        );
    }

    /// The support table names exactly the two producer axes Ruby answers.
    /// The other two are not gaps in the implementation but statements about
    /// the language: a `require` binds no local name, and a Ruby file states
    /// no package.
    #[test]
    fn ruby_declares_scopes_and_binding_intervals_only() {
        let support = RUBY_STRUCTURAL_SPEC.lexical_environment_support();
        let supported: Vec<EnvironmentAxis> = support
            .iter()
            .filter(|(_, support)| support.is_supported())
            .map(|(axis, _)| axis)
            .collect();
        assert_eq!(
            supported,
            vec![EnvironmentAxis::Scopes, EnvironmentAxis::BindingIntervals]
        );
    }

    /// `field_name_in_parent` answers exactly what indexing the child list
    /// answers, for every (parent, child) pair in a parsed tree.
    ///
    /// The indexed form is the oracle: it is what the helper did before it was
    /// rewritten to walk with a cursor. That rewrite exists purely to drop the
    /// quadratic `Node::child(i)` re-descent (it was 98% of the property
    /// fuzzer's CPU on a wide-node file), so it must not move a single answer.
    /// Ruby carries the check because Ruby is where the pathology surfaced,
    /// but the helper is shared by every language adapter.
    #[test]
    fn field_name_in_parent_matches_the_indexed_reference() {
        fn indexed_reference(
            parent: tree_sitter::Node<'_>,
            child: tree_sitter::Node<'_>,
        ) -> Option<&'static str> {
            (0..parent.child_count()).find_map(|index| {
                (parent.child(index) == Some(child))
                    .then(|| parent.field_name_for_child(index as u32))
                    .flatten()
            })
        }

        let source = r#"
module Codec
  class Data < Base
    include Enumerable
    CONST = [1, 2, 3].map { |value| value * 2 }

    def initialize(capacity: 16, **options)
      @impl = options.fetch(:impl) { Impl.new(capacity) }
      super()
    end

    def each(&block)
      rewind
      while (node = self.next)
        yield node
      end
    rescue StopIteration => error
      raise error unless block
    end

    def to_h
      { name: @name, size: @size, nested: { a: 1, b: 2 } }
    end
  end
end
"#;
        let tree = parse(source);
        let mut stack = vec![tree.root_node()];
        let mut pairs = 0_usize;
        let mut with_field = 0_usize;
        while let Some(parent) = stack.pop() {
            let mut cursor = parent.walk();
            let children: Vec<_> = parent.children(&mut cursor).collect();
            for child in children {
                let actual = field_name_in_parent(parent, child);
                assert_eq!(
                    actual,
                    indexed_reference(parent, child),
                    "field name disagreed for {:?} inside {:?}",
                    child.kind(),
                    parent.kind()
                );
                pairs += 1;
                if actual.is_some() {
                    with_field += 1;
                }
                stack.push(child);
            }
        }
        // Guard the guard: a tree that produced no field-carrying pairs would
        // let a broken implementation pass by answering `None` everywhere.
        assert!(
            pairs > 100,
            "expected a substantial tree, walked {pairs} pairs"
        );
        assert!(
            with_field > 20,
            "expected many named fields, found {with_field}"
        );
    }
}
