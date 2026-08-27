//! Ruby structural spec for `query_code`.

use crate::local_bindings::{
    LocalBindingTimeline, UnboundedLocalBindingBudget, collect_local_bindings,
};
use crate::syntax::single_static_string_content_node;
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_argument_role_with_derived_name, attach_role_with_derived_name, attach_terminal_callee,
    first_named_child,
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
    LexicalEnvironmentSupport, NO_LEXICAL_ENVIRONMENT_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    IdentityRouteSupport, NO_IDENTITY_ROUTE_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::spec::{RoleSink, StructuralSpec};
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
    ("module", NormalizedKind::Class),
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

/// Classify the method token of a Ruby member call.
///
/// Ruby's tree-sitter grammar represents both ordinary (`receiver.member`)
/// and safe-navigation (`receiver&.member`) access as `call` nodes. The
/// receiver and member are separate named fields, so requiring both fields on
/// the owning node keeps bare calls, receiver identifiers, declaration names,
/// and hash keys or labels out of this occurrence role.
fn ruby_member_position(node: Node<'_>) -> Option<OccurrenceRole> {
    // Setter calls put the member identifier below a `setter` wrapper in the
    // call's `method` field. Climb that one grammar-defined wrapper so the
    // identifier fact receives the role during extraction as well.
    let member = node
        .parent()
        .filter(|parent| {
            parent.kind() == "setter"
                && parent
                    .child_by_field_name("name")
                    .is_some_and(|name| name == node)
        })
        .unwrap_or(node);
    let call = member.parent()?;
    (call.kind() == "call"
        && call.child_by_field_name("receiver")?.id() != member.id()
        && call.child_by_field_name("method")?.id() == member.id())
    .then_some(OccurrenceRole::MemberPosition)
}

static RUBY_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport =
    OccurrenceRoleSupport::NONE.supported(OccurrenceRole::MemberPosition);

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
        &NO_LEXICAL_ENVIRONMENT_SUPPORT
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
        if let Some(role) = ruby_member_position(node) {
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

    fn member_positions(source: &str) -> Vec<(usize, String)> {
        let tree = parse(source);
        let mut found = Vec::new();
        let mut walk = vec![tree.root_node()];
        while let Some(node) = walk.pop() {
            if ruby_member_position(node).is_some() {
                found.push((
                    node.start_byte(),
                    node.utf8_text(source.as_bytes())
                        .expect("member token is valid UTF-8")
                        .to_owned(),
                ));
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    walk.push(child);
                }
            }
        }
        found
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
        assert!(support.is_supported(OccurrenceRole::MemberPosition));
        assert!(
            support
                .iter()
                .filter(|(_, support)| support.is_supported())
                .all(|(role, _)| role == OccurrenceRole::MemberPosition)
        );
    }
}
