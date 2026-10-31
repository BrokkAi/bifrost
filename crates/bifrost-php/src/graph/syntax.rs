use super::resolver::node_text;
use crate::aliases::{
    PhpDeclaredType, PhpFileContext, resolve_php_function_node, resolve_php_type,
};
use crate::graph::PhpGraphSource;
use crate::graph_support::PhpSource;
use crate::graph_support::php_direct_declared_class_parent;
use crate::graph_support::php_is_constructor_name;
use crate::phpdoc::parameter_element_type as phpdoc_parameter_element_type;
use brokk_bifrost_core::analyzer::php_facts::{
    PhpDeclarationSourceFact, PhpDeclaredSourceType, PhpFieldWriteKind,
};
use brokk_bifrost_core::analyzer::tree_walk::{is_comment_kind, unwrap_parenthesized_expression};
use brokk_bifrost_core::analyzer::usages::local_inference::{
    LocalInferenceConfig, LocalInferenceEngine, SymbolResolution,
};
use brokk_bifrost_core::analyzer::{CodeUnit, Range};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

const LOCAL_SCOPE_NODES: &[&str] = &[
    "function_definition",
    "method_declaration",
    "anonymous_function",
    "anonymous_function_creation",
    "arrow_function",
];

pub fn is_local_scope(node: Node<'_>) -> bool {
    LOCAL_SCOPE_NODES.contains(&node.kind())
}

/// Construct the binding state visible inside one nested PHP callable.
///
/// Arrow functions capture every visible lexical variable. Anonymous
/// functions capture only the variables named by their structured `use`
/// clause. Named functions and methods begin with a fresh local scope.
pub fn captured_local_scope_bindings<T>(
    node: Node<'_>,
    source: &str,
    outer: &LocalInferenceEngine<T>,
) -> LocalInferenceEngine<T>
where
    T: Clone + Eq + std::hash::Hash,
{
    let snapshot = match node.kind() {
        "arrow_function" => outer.snapshot(),
        "anonymous_function" | "anonymous_function_creation" => {
            let captured = anonymous_function_capture_names(node, source);
            outer
                .snapshot()
                .filtered_visible_bindings(|symbol, _| captured.contains(symbol))
        }
        _ => {
            return LocalInferenceEngine::new(LocalInferenceConfig::default());
        }
    };
    LocalInferenceEngine::from_snapshot(LocalInferenceConfig::default(), snapshot)
}

/// Names explicitly captured by a PHP anonymous function's `use (...)`
/// clause. Arrow functions have implicit capture and do not use this helper.
pub fn anonymous_function_capture_names(node: Node<'_>, source: &str) -> HashSet<String> {
    let mut captured = HashSet::default();
    let mut cursor = node.walk();
    let Some(clause) = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "anonymous_function_use_clause")
    else {
        return captured;
    };
    let mut stack = vec![clause];
    while let Some(current) = stack.pop() {
        if current.kind() == "variable_name" {
            captured.insert(variable_identifier(current, source).to_string());
            continue;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    captured
}

/// Seed every declared parameter of `node` into a local binding scope.
///
/// `resolve_type` receives the parameter's name and its declared type text, and
/// answers with every class that type names: one for an ordinary or nullable
/// type, several for a finite union, and none when the declaration proves
/// nothing. A union is seeded as the whole arm set rather than dropped, so a
/// surface that can carry bounded ambiguity sees it while every single-owner
/// reader still fails closed on it.
///
/// The name travels to `resolve_type` because a declared type can prove more
/// than the classes it names -- `object` and `mixed` prove the parameter's
/// member surface is dynamic -- and only the caller knows whether it records
/// that (#2030).
pub fn seed_parameter_types<F>(
    node: Node<'_>,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
    mut resolve_type: F,
) where
    F: FnMut(&str, &str) -> Vec<String>,
{
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return;
    };
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if !matches!(
            child.kind(),
            "simple_parameter" | "property_promotion_parameter"
        ) {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let name = variable_identifier(name_node, source);
        if name.is_empty() {
            continue;
        }
        let arms = child
            .child_by_field_name("type")
            .map(|type_node| resolve_type(name, node_text(type_node, source)))
            .unwrap_or_default();
        if arms.is_empty() {
            bindings.declare_shadow(name.to_string());
        } else {
            bindings.seed_symbol_many(name.to_string(), arms);
        }
    }
}

pub fn assignment_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    (node.kind() == "assignment_expression")
        .then(|| {
            node.child_by_field_name("left")
                .zip(node.child_by_field_name("right"))
        })
        .flatten()
}

/// Reduce nested `parenthesized_expression` nodes to their innermost child.
pub fn unwrap_parenthesized(node: Node<'_>) -> Node<'_> {
    unwrap_parenthesized_expression(node)
}

/// Apply one PHP assignment to a local binding scope.
///
/// This is the single interpretation of what an assignment tells local
/// inference, shared by the targeted usage scan, the whole-workspace inverted
/// scan, forward definition lookup, and semantic diagnostics. Only a plain
/// `$name = ...` binds: an array element, property, or list target says nothing
/// about a local symbol. The right-hand side is unwrapped through parentheses
/// and then offered to `resolve_value`, which is the surface's own structured
/// type evaluator (it also receives the bindings in force before this
/// assignment, because a right-hand side may read them).
///
/// A resolvable right-hand side seeds the symbol with that type. A plain
/// `$a = $b` aliases, which is sound single-assignment flow. Anything else
/// declares a shadow so a later read of the name fails closed rather than
/// reaching an outer binding of the same name.
pub fn seed_assignment_binding<'tree, F>(
    node: Node<'tree>,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
    resolve_value: F,
) where
    F: FnOnce(Node<'tree>, &LocalInferenceEngine<String>) -> Option<String>,
{
    let Some((left, right)) = assignment_parts(node) else {
        return;
    };
    if left.kind() != "variable_name" {
        return;
    }
    let name = variable_identifier(left, source);
    if name.is_empty() {
        return;
    }
    let right = unwrap_parenthesized(right);
    if let Some(fq_name) = resolve_value(right, bindings) {
        bindings.seed_symbol(name.to_string(), fq_name);
        return;
    }
    if right.kind() == "variable_name" {
        let alias = variable_identifier(right, source);
        if !alias.is_empty() {
            bindings.alias_symbol(name.to_string(), alias);
            return;
        }
    }
    bindings.declare_shadow(name.to_string());
}

/// Resolve the declared object type an assignment's right-hand side produces,
/// for the two usage-graph surfaces. The shared receiver evaluator preserves
/// constructions, direct calls, and structured member chains. Existing local
/// bindings are available because an assignment can derive its type from an
/// earlier local (`$next = $client->service()`).
pub fn assignment_value_type_fq_name<F>(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    bindings: &LocalInferenceEngine<String>,
    enclosing_owner: F,
) -> Option<String>
where
    F: FnMut(usize, usize) -> Option<String>,
{
    instance_receiver_type_fq_name(php, analyzer, node, source, ctx, bindings, enclosing_owner)
}

pub fn object_creation_type(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "name" | "qualified_name" | "relative_scope"))
}

/// Return the object operand of a PHP clone expression.
///
/// Legacy cloning stores its operand as the clone expression's first named
/// child. PHP 8.5 clone-with stores an argument list in the `arguments` field;
/// the object may be the first positional argument or a named `object`
/// argument after the property-update argument. Variadic operands do not prove
/// an object identity, so this helper fails closed for them.
pub fn clone_object_operand<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    debug_assert_eq!(node.kind(), "clone_expression");

    let Some(arguments) = node.child_by_field_name("arguments") else {
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .find(|child| !is_comment_kind(child.kind()));
    };

    let mut cursor = arguments.walk();
    let mut named_object = None;
    let mut first_positional = None;
    for argument in arguments.named_children(&mut cursor) {
        if is_comment_kind(argument.kind()) {
            continue;
        }
        if is_clone_variadic_kind(argument.kind())
            || argument.kind() != "argument"
            || clone_argument_value(argument)
                .is_some_and(|value| is_clone_variadic_kind(value.kind()))
        {
            return None;
        }

        if let Some(name) = argument.child_by_field_name("name") {
            if name
                .utf8_text(source.as_bytes())
                .ok()
                .is_some_and(|name| name == "object")
            {
                if named_object.is_some() || first_positional.is_some() {
                    return None;
                }
                named_object = Some(argument);
            }
        } else {
            if named_object.is_some() {
                return None;
            }
            if first_positional.is_none() {
                first_positional = Some(argument);
            }
        }
    }

    named_object
        .or(first_positional)
        .and_then(|argument| clone_argument_value(argument))
}

fn clone_argument_value(argument: Node<'_>) -> Option<Node<'_>> {
    if is_clone_variadic_kind(argument.kind()) {
        return None;
    }

    if let Some(value) = argument.child_by_field_name("value") {
        return Some(value);
    }

    let name = argument.child_by_field_name("name");
    let reference_modifier = argument.child_by_field_name("reference_modifier");
    let mut cursor = argument.walk();
    let values = argument
        .named_children(&mut cursor)
        .filter(|child| {
            !is_comment_kind(child.kind())
                && Some(child.id()) != name.map(|name| name.id())
                && Some(child.id()) != reference_modifier.map(|modifier| modifier.id())
        })
        .collect::<Vec<_>>();
    let [value] = values.as_slice() else {
        return None;
    };
    Some(*value)
}

fn is_clone_variadic_kind(kind: &str) -> bool {
    matches!(
        kind,
        "variadic_placeholder" | "variadic_unpacking" | "argument_placeholder"
    )
}

/// Return the type name a `binary_expression` spells on the right of
/// `instanceof`. The grammar publishes that operand as a plain `name` or
/// `qualified_name`, so identify it from the operator field rather than
/// interpreting source text.
pub fn instanceof_type_node(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "binary_expression" {
        return None;
    }
    let operator = node.child_by_field_name("operator")?;
    if operator.kind() != "instanceof" {
        return None;
    }
    node.child_by_field_name("right")
}

pub fn static_member_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let scope = node
        .child_by_field_name("scope")
        .or_else(|| node.child_by_field_name("class"))
        .or_else(|| node.named_child(0))?;
    let name = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("constant"))
        .or_else(|| node.named_child(1))?;
    Some((scope, name))
}

/// Resolve the class named by a PHP static scope. Unlike ordinary type syntax,
/// `self`, `static`, and `parent` are relative to the lexically enclosing class.
/// Keep that interpretation shared by the targeted and inverted usage walkers
/// so return-type inference for assignments follows the same owner semantics as
/// the static call edge itself.
pub fn static_scope_type_fq_name(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    raw: &str,
    ctx: &PhpFileContext,
    enclosing_owner: Option<&str>,
) -> Option<String> {
    match raw {
        raw if raw.eq_ignore_ascii_case("self") || raw.eq_ignore_ascii_case("static") => {
            enclosing_owner.map(str::to_string)
        }
        raw if raw.eq_ignore_ascii_case("parent") => {
            let enclosing_owner = enclosing_owner?;
            let mut definitions = analyzer
                .index
                .definitions(enclosing_owner)
                .filter(CodeUnit::is_class);
            let enclosing_class = definitions.next()?;
            if definitions.next().is_some() {
                return None;
            }
            php_direct_declared_class_parent(php, &enclosing_class).map(|parent| parent.fq_name())
        }
        _ => resolve_php_type(raw, ctx),
    }
}

pub fn variable_identifier<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node_text(node, source).trim_start_matches('$')
}

/// Return the class type that structured control flow proves for a variable.
///
/// Positive `instanceof` facts dominate the right side of `&&`/`and` and true
/// `if` bodies. A negative `instanceof` dominates the right side of `||`/`or`.
/// A preceding guard whose negative condition cannot fall through also proves
/// the positive type after the guard, provided no intervening assignment
/// replaces the variable.
pub fn dominating_instanceof_type_node<'tree, F>(
    reference: Node<'tree>,
    source: &str,
    mut step: F,
) -> Option<Node<'tree>>
where
    F: FnMut() -> bool,
{
    if reference.kind() != "variable_name" {
        return None;
    }
    let variable = variable_identifier(reference, source);
    let mut child = reference;
    let mut ancestor = reference.parent();
    while let Some(node) = ancestor {
        if !step() {
            return None;
        }
        if is_local_scope(node) {
            break;
        }
        if node.kind() == "binary_expression"
            && binary_operator_is(node, &["&&", "and"])
            && node.child_by_field_name("right").is_some_and(|right| {
                right.start_byte() <= child.start_byte() && child.end_byte() <= right.end_byte()
            })
            && let Some(left) = node.child_by_field_name("left")
            && let Some(found) = positive_instanceof_type(left, variable, source, &mut step)
        {
            return Some(found);
        }
        if node.kind() == "binary_expression"
            && binary_operator_is(node, &["||", "or"])
            && node.child_by_field_name("right").is_some_and(|right| {
                right.start_byte() <= child.start_byte() && child.end_byte() <= right.end_byte()
            })
            && let Some(left) = node.child_by_field_name("left")
            && let Some(found) = negative_instanceof_type(left, variable, source, &mut step)
        {
            return Some(found);
        }
        if node.kind() == "if_statement"
            && node.child_by_field_name("body").is_some_and(|body| {
                body.start_byte() <= reference.start_byte()
                    && reference.end_byte() <= body.end_byte()
            })
            && let Some(condition) = node.child_by_field_name("condition")
            && let Some(found) = positive_instanceof_type(condition, variable, source, &mut step)
        {
            return Some(found);
        }
        child = node;
        ancestor = node.parent();
    }
    preceding_guard_instanceof_type(reference, variable, source, &mut step)
}

/// Return the collection expression that binds one direct `foreach` value.
///
/// PHP's grammar does not assign fields to the iterable and value children, so
/// this follows the grammar's named-child order while still requiring the
/// reference to be inside the loop body and the value binder to be one plain
/// variable. Key/value pairs use the pair's final named child. Destructuring,
/// by-reference values, and references outside the loop deliberately prove
/// nothing.
pub fn enclosing_foreach_collection<'tree, F>(
    reference: Node<'tree>,
    source: &str,
    mut step: F,
) -> Option<Node<'tree>>
where
    F: FnMut() -> bool,
{
    if reference.kind() != "variable_name" {
        return None;
    }
    let reference_name = variable_identifier(reference, source);
    let mut ancestor = reference.parent();
    while let Some(node) = ancestor {
        if !step() || is_local_scope(node) {
            return None;
        }
        if node.kind() == "foreach_statement" {
            let body = node.child_by_field_name("body")?;
            if !(body.start_byte() <= reference.start_byte()
                && reference.end_byte() <= body.end_byte())
            {
                return None;
            }
            let mut cursor = node.walk();
            let mut operands = node
                .named_children(&mut cursor)
                .filter(|child| child.id() != body.id() && child.kind() != "by_ref");
            let collection = operands.next()?;
            let binder = operands.next()?;
            if operands.next().is_some() {
                return None;
            }
            let value = if binder.kind() == "pair" {
                binder.named_child(binder.named_child_count().checked_sub(1)?)?
            } else {
                binder
            };
            return (value.kind() == "variable_name"
                && variable_identifier(value, source) == reference_name)
                .then_some(collection);
        }
        ancestor = node.parent();
    }
    None
}

pub fn foreach_value_reassigned_before(reference: Node<'_>, source: &str) -> bool {
    if reference.kind() != "variable_name"
        || enclosing_foreach_collection(reference, source, || true).is_none()
    {
        return false;
    }
    let name = variable_identifier(reference, source);
    let mut foreach = reference.parent();
    while foreach.is_some_and(|node| node.kind() != "foreach_statement") {
        foreach = foreach.and_then(|node| node.parent());
    }
    let Some(body) = foreach.and_then(|node| node.child_by_field_name("body")) else {
        return false;
    };
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= reference.start_byte() {
            continue;
        }
        if node != body && is_local_scope(node) {
            continue;
        }
        if assignment_parts(node).is_some_and(|(left, _)| {
            left.kind() == "variable_name" && variable_identifier(left, source) == name
        }) {
            return true;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    false
}

/// Return the collection whose element is bound to one direct `array_map`
/// callback parameter.
///
/// The callback must be the call's first argument and the reference must be in
/// that callback's body. Parameter position selects the corresponding
/// collection argument. An unqualified `array_map` is accepted only when no
/// indexed namespace-local function shadows PHP's global builtin; qualified
/// or imported spellings must resolve to the global name exactly.
pub fn enclosing_array_map_collection<'tree, F, I>(
    reference: Node<'tree>,
    source: &str,
    ctx: &PhpFileContext,
    mut step: F,
    mut is_indexed_function: I,
) -> Option<Node<'tree>>
where
    F: FnMut() -> bool,
    I: FnMut(&str) -> bool,
{
    if reference.kind() != "variable_name" {
        return None;
    }
    let reference_name = variable_identifier(reference, source);
    let mut callback = reference.parent();
    while let Some(node) = callback {
        if !step() {
            return None;
        }
        if is_local_scope(node) {
            callback = Some(node);
            break;
        }
        callback = node.parent();
    }
    let callback = callback?;
    if !matches!(
        callback.kind(),
        "arrow_function" | "anonymous_function" | "anonymous_function_creation"
    ) {
        return None;
    }
    let body = callback.child_by_field_name("body")?;
    if !(body.start_byte() <= reference.start_byte() && reference.end_byte() <= body.end_byte()) {
        return None;
    }
    let parameters = callback.child_by_field_name("parameters")?;
    let mut parameter_index = None;
    let mut cursor = parameters.walk();
    for (index, parameter) in parameters.named_children(&mut cursor).enumerate() {
        if !step()
            || !matches!(
                parameter.kind(),
                "simple_parameter" | "property_promotion_parameter"
            )
        {
            return None;
        }
        if parameter.child_by_field_name("name").is_some_and(|name| {
            name.kind() == "variable_name" && variable_identifier(name, source) == reference_name
        }) && parameter_index.replace(index).is_some()
        {
            return None;
        }
    }
    let parameter_index = parameter_index?;

    let callback_parent = callback.parent()?;
    let (arguments, callback_argument_id) = if callback_parent.kind() == "argument" {
        if callback_parent.named_child_count() != 1
            || callback_parent.named_child(0)?.id() != callback.id()
        {
            return None;
        }
        (callback_parent.parent()?, callback_parent.id())
    } else {
        (callback_parent, callback.id())
    };
    if arguments.kind() != "arguments" || arguments.parent()?.kind() != "function_call_expression" {
        return None;
    }
    let call = arguments.parent()?;
    let mut cursor = arguments.walk();
    let arguments = arguments.named_children(&mut cursor).collect::<Vec<_>>();
    if arguments
        .first()
        .is_none_or(|first| first.id() != callback_argument_id)
    {
        return None;
    }
    let function = call.child_by_field_name("function")?;
    let candidates = resolve_php_function_node(function, source, ctx, &mut step)?;
    let mut reaches_builtin = false;
    for candidate in candidates.iter() {
        if candidate == "array_map" {
            reaches_builtin = true;
            break;
        }
        if is_indexed_function(candidate) {
            return None;
        }
    }
    if !reaches_builtin {
        return None;
    }
    let collection = *arguments.get(parameter_index + 1)?;
    if collection.kind() == "argument" {
        (collection.named_child_count() == 1).then(|| collection.named_child(0))?
    } else {
        Some(collection)
    }
}

fn positive_instanceof_type<'tree, F>(
    root: Node<'tree>,
    variable: &str,
    source: &str,
    step: &mut F,
) -> Option<Node<'tree>>
where
    F: FnMut() -> bool,
{
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !step() {
            return None;
        }
        if node.kind() == "parenthesized_expression" {
            if let Some(inner) = node.named_child(0) {
                stack.push(inner);
            }
            continue;
        }
        if node.kind() != "binary_expression" {
            continue;
        }
        if binary_operator_is(node, &["instanceof"])
            && node
                .child_by_field_name("left")
                .and_then(instanceof_left_variable)
                .is_some_and(|left| variable_identifier(left, source) == variable)
        {
            return node.child_by_field_name("right");
        }
        if binary_operator_is(node, &["&&", "and"]) {
            if let Some(right) = node.child_by_field_name("right") {
                stack.push(right);
            }
            if let Some(left) = node.child_by_field_name("left") {
                stack.push(left);
            }
        }
    }
    None
}

fn negative_instanceof_type<'tree, F>(
    root: Node<'tree>,
    variable: &str,
    source: &str,
    step: &mut F,
) -> Option<Node<'tree>>
where
    F: FnMut() -> bool,
{
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !step() {
            return None;
        }
        if node.kind() == "parenthesized_expression" {
            if let Some(inner) = node.named_child(0) {
                stack.push(inner);
            }
            continue;
        }
        if node
            .child_by_field_name("operator")
            .is_some_and(|operator| operator.kind() == "!")
            && let Some(operand) = node.named_child(0)
            && let Some(found) = positive_instanceof_type(operand, variable, source, step)
        {
            return Some(found);
        }
        if node.kind() == "binary_expression" && binary_operator_is(node, &["||", "or"]) {
            if let Some(right) = node.child_by_field_name("right") {
                stack.push(right);
            }
            if let Some(left) = node.child_by_field_name("left") {
                stack.push(left);
            }
        }
    }
    None
}

fn instanceof_left_variable(mut node: Node<'_>) -> Option<Node<'_>> {
    while node.kind() == "parenthesized_expression" {
        node = node.named_child(0)?;
    }
    if node.kind() == "assignment_expression" {
        node = node.child_by_field_name("left")?;
        while node.kind() == "parenthesized_expression" {
            node = node.named_child(0)?;
        }
    }
    (node.kind() == "variable_name").then_some(node)
}

fn preceding_guard_instanceof_type<'tree, F>(
    reference: Node<'tree>,
    variable: &str,
    source: &str,
    step: &mut F,
) -> Option<Node<'tree>>
where
    F: FnMut() -> bool,
{
    let mut child = reference;
    let mut parent = reference.parent();
    while let Some(node) = parent {
        if !step() || is_local_scope(node) {
            return None;
        }
        if node.kind() == "compound_statement" {
            let mut cursor = node.walk();
            let preceding = node
                .named_children(&mut cursor)
                .take_while(|sibling| sibling.end_byte() <= child.start_byte())
                .collect::<Vec<_>>();
            for sibling in preceding.into_iter().rev() {
                if let Some(found) =
                    exiting_negative_instanceof_guard(sibling, variable, source, step)
                {
                    return Some(found);
                }
                if subtree_assigns_variable(sibling, variable, source, step) {
                    return None;
                }
            }
        }
        child = node;
        parent = node.parent();
    }
    None
}

fn exiting_negative_instanceof_guard<'tree, F>(
    node: Node<'tree>,
    variable: &str,
    source: &str,
    step: &mut F,
) -> Option<Node<'tree>>
where
    F: FnMut() -> bool,
{
    if node.kind() != "if_statement" || node.child_by_field_name("alternative").is_some() {
        return None;
    }
    let condition = node.child_by_field_name("condition")?;
    let body = node.child_by_field_name("body")?;
    statement_prevents_following_sibling(body, step)
        .then(|| negative_instanceof_type(condition, variable, source, step))
        .flatten()
}

fn statement_prevents_following_sibling<F>(mut node: Node<'_>, step: &mut F) -> bool
where
    F: FnMut() -> bool,
{
    loop {
        if !step() {
            return false;
        }
        if matches!(node.kind(), "return_statement" | "continue_statement") {
            return true;
        }
        if node.kind() == "expression_statement"
            && node
                .named_child(0)
                .is_some_and(|child| child.kind() == "throw_expression")
        {
            return true;
        }
        if node.kind() != "compound_statement" {
            return false;
        }
        let Some(last) = node
            .named_child_count()
            .checked_sub(1)
            .and_then(|i| node.named_child(i))
        else {
            return false;
        };
        node = last;
    }
}

fn subtree_assigns_variable<F>(root: Node<'_>, variable: &str, source: &str, step: &mut F) -> bool
where
    F: FnMut() -> bool,
{
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !step() {
            return true;
        }
        if node != root && is_local_scope(node) {
            continue;
        }
        if assignment_parts(node).is_some_and(|(left, _)| {
            instanceof_left_variable(left)
                .is_some_and(|left| variable_identifier(left, source) == variable)
        }) {
            return true;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    false
}

fn binary_operator_is(node: Node<'_>, expected: &[&str]) -> bool {
    node.child_by_field_name("operator")
        .is_some_and(|operator| expected.contains(&operator.kind()))
}

/// The source range of the token a PHP declaration name is written as.
///
/// [`variable_identifier`] above strips the `$` so that one identity spells a
/// property the same way at its declaration (`$last`) and at every `->last`
/// access -- the only spelling the two sites share. The stored identifier is
/// therefore sigil-free, and generic name-range selection resolves it to the
/// `name` child of `variable_name`, one column right of the token an editor
/// highlights.
///
/// PHP's grammar makes `variable_name` exactly `$` + `name`, so widening to the
/// parent restores the sigil and nothing else. This matches what Intelephense
/// and phpactor return for a property declarator, and it changes only the
/// reported range: the identifier keeps its sigil-free form.
///
/// A `->last` access is a bare `name` with no `variable_name` parent, so it is
/// left alone -- correct, because that source token carries no sigil.
pub fn php_declaration_name_range(node: Node<'_>) -> Range {
    let token = match node.parent() {
        Some(parent) if parent.kind() == "variable_name" => parent,
        _ => node,
    };
    Range {
        start_byte: token.start_byte(),
        end_byte: token.end_byte(),
        start_line: token.start_position().row,
        end_line: token.end_position().row,
    }
}

pub fn literal_member_identifier<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    (node.kind() == "name").then(|| node_text(node, source))
}

/// The immediately preceding PHPDoc comment for one declaration. Tree-sitter
/// owns comment boundaries; the PHPDoc parser decides whether the comment is a
/// valid docblock and which structured tags it contains.
pub fn declaration_doc_comment<'a>(declaration: Node<'_>, source: &'a str) -> Option<&'a str> {
    let comment = declaration.prev_named_sibling()?;
    (comment.kind() == "comment").then(|| node_text(comment, source))
}

pub fn static_property_identifier<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    (node.kind() == "variable_name").then(|| variable_identifier(node, source))
}

pub fn declared_field_type_fq_name(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    field: &CodeUnit,
) -> Option<String> {
    if !field.is_field() {
        return None;
    }
    declared_relative_field_type_fq_name(php, analyzer, field)
        .or_else(|| indexed_declared_type_fq_name(analyzer, field))
        .or_else(|| canonical_declared_type_fq_name(php, field))
        .or_else(|| canonical_doc_nominal_type(php, field))
        .or_else(|| inferred_constructor_field_type_fq_name(php, analyzer, field))
}

fn declared_relative_field_type_fq_name(
    php: &dyn PhpSource,
    _analyzer: PhpGraphSource<'_>,
    field: &CodeUnit,
) -> Option<String> {
    let source = php.php_source_facts(field.source())?;
    let mut declarations = source.declarations_for(field);
    let first = &declarations.next()?.declared_type;
    if declarations.any(|declaration| &declaration.declared_type != first) {
        return None;
    }
    let owner = php.parent_of(field).filter(CodeUnit::is_class)?;
    match first {
        PhpDeclaredSourceType::SelfType | PhpDeclaredSourceType::StaticType => {
            Some(owner.fq_name())
        }
        PhpDeclaredSourceType::ParentType => {
            php_direct_declared_class_parent(php, &owner).map(|parent| parent.fq_name())
        }
        _ => None,
    }
}

/// Return the single relative class keyword proved by a declared type node.
///
/// Nullable syntax and a union containing exactly one relative class plus
/// `null` retain that class. Multiple nominal arms, primitives other than
/// `null`, intersections, and malformed wrappers remain unresolved.
pub fn relative_declared_type_keyword<'a>(
    mut node: Node<'_>,
    source: &'a str,
    mut step: impl FnMut() -> bool,
) -> Option<&'a str> {
    loop {
        if !step() {
            return None;
        }
        match node.kind() {
            "optional_type" | "named_type" => {
                if node.named_child_count() != 1 || !step() {
                    return None;
                }
                node = node.named_child(0)?;
            }
            "union_type" => {
                let mut nominal = None;
                for index in 0..node.named_child_count() {
                    if !step() {
                        return None;
                    }
                    let child = node.named_child(index)?;
                    if child.kind() == "primitive_type"
                        && node_text(child, source).eq_ignore_ascii_case("null")
                    {
                        continue;
                    }
                    if nominal.replace(child).is_some() {
                        return None;
                    }
                }
                node = nominal?;
            }
            "name" | "relative_scope" => {
                let text = node_text(node, source);
                return ["self", "static", "parent"]
                    .into_iter()
                    .find(|keyword| text.eq_ignore_ascii_case(keyword));
            }
            _ => return None,
        }
    }
}

/// Infer the element type of one property-backed collection from its complete
/// structured indexed-write set.
pub fn declared_field_element_type_fq_name(
    php: &dyn PhpSource,
    _analyzer: PhpGraphSource<'_>,
    field: &CodeUnit,
) -> Option<String> {
    canonical_field_element_type(php, field)
}

pub fn canonical_field_element_type(php: &dyn PhpSource, field: &CodeUnit) -> Option<String> {
    if !field.is_field() {
        return None;
    }
    canonical_field_write_type(php, field, PhpFieldWriteKind::Indexed)
        .or_else(|| canonical_doc_element_type(php, field))
        .or_else(|| canonical_constructor_doc_element(php, field))
}

fn inferred_constructor_field_type_fq_name(
    php: &dyn PhpSource,
    _analyzer: PhpGraphSource<'_>,
    field: &CodeUnit,
) -> Option<String> {
    canonical_inferred_field_type(php, field)
}

pub fn canonical_inferred_field_type(php: &dyn PhpSource, field: &CodeUnit) -> Option<String> {
    let metadata = php.signature_metadata(field);
    if let Some(first) = metadata.first() {
        let is_static = first.field_is_static();
        if metadata
            .iter()
            .any(|row| row.field_is_static() != is_static)
        {
            return None;
        }
        let kind = if is_static {
            PhpFieldWriteKind::Static
        } else {
            PhpFieldWriteKind::Instance
        };
        return canonical_field_write_type(php, field, kind);
    }
    canonical_field_write_type(php, field, PhpFieldWriteKind::Instance)
        .or_else(|| canonical_field_write_type(php, field, PhpFieldWriteKind::Static))
}

fn canonical_field_write_type(
    php: &dyn PhpSource,
    field: &CodeUnit,
    kind: PhpFieldWriteKind,
) -> Option<String> {
    let owner = php.parent_of(field).filter(CodeUnit::is_class)?;
    let source = php.php_source_facts(field.source())?;
    let mut result = None;
    let mut found_owner = false;
    for class in source.declarations_for(&owner) {
        found_owner = true;
        let mut inferred = None;
        for write in source.facts.writes.iter().filter(|write| {
            write.class == class.declaration
                && write.field == field.identifier()
                && write.kind == kind
        }) {
            if kind == PhpFieldWriteKind::Instance && !write.directly_in_constructor {
                return None;
            }
            let value = match &write.value_type {
                PhpDeclaredSourceType::Nominal(arms) => {
                    let [value] = arms.as_slice() else {
                        return None;
                    };
                    value.clone()
                }
                PhpDeclaredSourceType::SelfType | PhpDeclaredSourceType::StaticType => {
                    owner.fq_name()
                }
                PhpDeclaredSourceType::ParentType => {
                    php_direct_declared_class_parent(php, &owner)?.fq_name()
                }
                _ => return None,
            };
            if inferred.as_ref().is_some_and(|known| known != &value) {
                return None;
            }
            inferred = Some(value);
        }
        let inferred = inferred?;
        if result.as_ref().is_some_and(|known| known != &inferred) {
            return None;
        }
        result = Some(inferred);
    }
    found_owner.then_some(result).flatten()
}

fn canonical_constructor_doc_element(php: &dyn PhpSource, field: &CodeUnit) -> Option<String> {
    let owner = php.parent_of(field).filter(CodeUnit::is_class)?;
    let source = php.php_source_facts(field.source())?;
    let mut result = None;
    for class in source.declarations_for(&owner) {
        let mut inferred = None;
        for write in source.facts.writes.iter().filter(|write| {
            write.class == class.declaration
                && write.field == field.identifier()
                && write.kind == PhpFieldWriteKind::Instance
        }) {
            if !write.directly_in_constructor {
                return None;
            }
            let value = write.doc_element_type.as_ref()?;
            if inferred.is_some_and(|known| known != value) {
                return None;
            }
            inferred = Some(value);
        }
        let inferred = inferred?;
        if result.as_ref().is_some_and(|known| known != inferred) {
            return None;
        }
        result = Some(inferred.clone());
    }
    result
}

/// The declared type node for a constructor parameter read. This deliberately
/// answers only a direct `$parameter` expression whose nearest local scope is
/// `__construct`; callers decide whether that declaration proves one type.
pub fn constructor_parameter_type_node<'tree, F>(
    value: Node<'tree>,
    source: &str,
    mut step: F,
) -> Option<Node<'tree>>
where
    F: FnMut() -> bool,
{
    let parameter = parameter_type_node(value, source, &mut step)?;
    let mut ancestor = value.parent();
    while let Some(node) = ancestor {
        if !step() {
            return None;
        }
        if node.kind() == "method_declaration" {
            let name = node.child_by_field_name("name")?;
            return php_is_constructor_name(node_text(name, source)).then_some(parameter);
        }
        if is_local_scope(node) {
            return None;
        }
        ancestor = node.parent();
    }
    None
}

/// The declared type node for a direct parameter read in its nearest local
/// scope. Callers decide whether the declaration proves one nominal type.
pub fn parameter_type_node<'tree, F>(
    value: Node<'tree>,
    source: &str,
    step: F,
) -> Option<Node<'tree>>
where
    F: FnMut() -> bool,
{
    parameter_node_for_value(value, source, step)?
        .0
        .child_by_field_name("type")
}

fn parameter_node_for_value<'tree, F>(
    value: Node<'tree>,
    source: &str,
    mut step: F,
) -> Option<(Node<'tree>, Node<'tree>)>
where
    F: FnMut() -> bool,
{
    if value.kind() != "variable_name" {
        return None;
    }
    let parameter_name = variable_identifier(value, source);
    let mut ancestor = value.parent();
    let scope = loop {
        let node = ancestor?;
        if !step() {
            return None;
        }
        if is_local_scope(node) {
            break node;
        }
        ancestor = node.parent();
    };
    let parameters = scope.child_by_field_name("parameters")?;
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        if !step()
            || !matches!(
                parameter.kind(),
                "simple_parameter" | "property_promotion_parameter"
            )
        {
            continue;
        }
        let Some(name) = parameter.child_by_field_name("name") else {
            continue;
        };
        if variable_identifier(name, source) == parameter_name {
            return Some((parameter, scope));
        }
    }
    None
}

/// The PHPDoc element type for a direct parameter read in its nearest local
/// scope. The parameter binder must exist structurally; the external PHPDoc
/// parser matches its `$name` tag and parses the type expression.
pub fn parameter_doc_element_type<F>(value: Node<'_>, source: &str, mut step: F) -> Option<String>
where
    F: FnMut() -> bool,
{
    let (parameter, scope) = parameter_node_for_value(value, source, &mut step)?;
    let parameter_name = variable_identifier(parameter.child_by_field_name("name")?, source);
    phpdoc_parameter_element_type(declaration_doc_comment(scope, source)?, parameter_name)
}

/// The PHPDoc element type for a promoted property parameter.
///
/// Promotion is the constructor assignment, so there is no assignment node
/// for the ordinary constructor-flow inference to inspect. The parser-owned
/// parameter binder and enclosing method still provide the same `@param`
/// fact without interpreting source text.
pub fn promoted_property_doc_element_type<F>(
    declaration: Node<'_>,
    source: &str,
    mut step: F,
) -> Option<String>
where
    F: FnMut() -> bool,
{
    if declaration.kind() != "property_promotion_parameter" || !step() {
        return None;
    }
    let name = declaration.child_by_field_name("name")?;
    let parameter_name = variable_identifier(name, source);
    let mut ancestor = declaration.parent();
    let scope = loop {
        let node = ancestor?;
        if !step() {
            return None;
        }
        if is_local_scope(node) {
            break node;
        }
        ancestor = node.parent();
    };
    phpdoc_parameter_element_type(declaration_doc_comment(scope, source)?, parameter_name)
}

pub fn infer_indexed_local_element_type(
    collection: Node<'_>,
    source: &str,
    before_byte: usize,
    resolve_value: &mut dyn FnMut(Node<'_>) -> Option<String>,
) -> Option<String> {
    if collection.kind() != "variable_name" {
        return None;
    }
    let collection_name = variable_identifier(collection, source);
    let mut scope = collection.parent();
    while scope.is_some_and(|node| !is_local_scope(node)) {
        scope = scope.and_then(|node| node.parent());
    }
    let scope = scope?;
    let mut inferred = None;
    let mut invalidated = false;
    let mut stack = vec![scope];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= before_byte {
            continue;
        }
        if node != scope && is_local_scope(node) {
            continue;
        }
        if node.end_byte() <= before_byte
            && let Some((left, right)) = assignment_parts(node)
        {
            if left.kind() == "variable_name"
                && variable_identifier(left, source) == collection_name
            {
                let right = unwrap_parenthesized(right);
                // A replacement can discard earlier uncertainty only when it
                // executes unconditionally in this local scope. A reset in a
                // branch or loop does not prove the post-branch contents.
                let mut ancestor = node.parent();
                while ancestor.is_some_and(|parent| {
                    matches!(parent.kind(), "expression_statement" | "compound_statement")
                }) {
                    ancestor = ancestor.expect("checked assignment parent").parent();
                }
                invalidated = ancestor != Some(scope)
                    || right.kind() != "array_creation_expression"
                    || right.named_child_count() != 0;
                inferred = None;
            } else if left.kind() == "subscript_expression"
                && left.named_child(0).is_some_and(|base| {
                    base.kind() == "variable_name"
                        && variable_identifier(base, source) == collection_name
                })
            {
                if let Some(value) = resolve_value(right) {
                    if inferred.as_ref().is_some_and(|known| known != &value) {
                        invalidated = true;
                    }
                    inferred = Some(value);
                } else {
                    invalidated = true;
                }
            }
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    (!invalidated).then_some(inferred).flatten()
}

pub(crate) fn this_field_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    if !matches!(
        node.kind(),
        "member_access_expression" | "nullsafe_member_access_expression"
    ) {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    let name = node.child_by_field_name("name")?;
    (object.kind() == "variable_name" && variable_identifier(object, source) == "this")
        .then(|| literal_member_identifier(name, source))
        .flatten()
}

pub(crate) fn static_self_field_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "scoped_property_access_expression" {
        return None;
    }
    let (scope, name) = static_member_parts(node)?;
    let scope = node_text(scope, source);
    ((scope.eq_ignore_ascii_case("self") || scope.eq_ignore_ascii_case("static"))
        && name.kind() == "variable_name")
        .then(|| variable_identifier(name, source))
}

pub(crate) fn assignment_is_directly_in_constructor<F>(
    assignment: Node<'_>,
    source: &str,
    class: Node<'_>,
    step: &mut F,
) -> bool
where
    F: FnMut() -> bool,
{
    let mut current = assignment.parent();
    while let Some(node) = current {
        if !step() || node == class {
            return false;
        }
        if node.kind() == "method_declaration" {
            return node
                .child_by_field_name("name")
                .is_some_and(|name| php_is_constructor_name(node_text(name, source)));
        }
        if is_local_scope(node) {
            return false;
        }
        current = node.parent();
    }
    false
}

pub fn declared_callable_return_type_fq_name(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    callable: &CodeUnit,
) -> Option<String> {
    if !callable.is_function() {
        return None;
    }
    indexed_declared_type_fq_name(analyzer, callable)
        .or_else(|| canonical_declared_type_fq_name(php, callable))
        .or_else(|| canonical_doc_nominal_type(php, callable))
}

pub fn declared_callable_return_element_type_fq_name(
    php: &dyn PhpSource,
    callable: &CodeUnit,
) -> Option<String> {
    if !callable.is_function() {
        return None;
    }
    canonical_doc_element_type(php, callable)
}

pub fn canonical_doc_nominal_type(php: &dyn PhpSource, unit: &CodeUnit) -> Option<String> {
    canonical_doc_value(php, unit, |declaration| {
        declaration.doc_nominal_type.as_ref()
    })
}

pub fn canonical_doc_element_type(php: &dyn PhpSource, unit: &CodeUnit) -> Option<String> {
    canonical_doc_value(php, unit, |declaration| {
        declaration.doc_element_type.as_ref()
    })
}

fn canonical_doc_value(
    php: &dyn PhpSource,
    unit: &CodeUnit,
    value: impl for<'a> Fn(&'a PhpDeclarationSourceFact) -> Option<&'a String>,
) -> Option<String> {
    let source = php.php_source_facts(unit.source())?;
    let mut declarations = source.declarations_for(unit);
    let first = value(declarations.next()?)?;
    declarations
        .all(|declaration| value(declaration) == Some(first))
        .then(|| first.clone())
}

pub fn collection_element_type_fq_name(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    collection: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    bindings: &LocalInferenceEngine<String>,
    enclosing_owner: &mut dyn FnMut(usize, usize) -> Option<String>,
) -> Option<String> {
    collection_element_type_fq_name_inner(
        php,
        analyzer,
        collection,
        source,
        ctx,
        bindings,
        enclosing_owner,
        MAX_NESTED_COLLECTION_INFERENCE_DEPTH,
    )
}

/// PHP syntax shapes that can name a collection whose element type is queried.
pub enum CollectionElementTypeAccess<'tree> {
    IndexedLocal,
    ThisField(Node<'tree>),
    MemberCall(Node<'tree>),
}

/// Classify the supported PHP collection expression without resolving its type.
pub fn collection_element_type_access<'tree>(
    collection: Node<'tree>,
    source: &str,
) -> Option<CollectionElementTypeAccess<'tree>> {
    match collection.kind() {
        "variable_name" => Some(CollectionElementTypeAccess::IndexedLocal),
        "member_access_expression" | "nullsafe_member_access_expression" => {
            let object = collection.child_by_field_name("object")?;
            if object.kind() != "variable_name" || variable_identifier(object, source) != "this" {
                return None;
            }
            Some(CollectionElementTypeAccess::ThisField(collection))
        }
        "member_call_expression" | "nullsafe_member_call_expression" => {
            Some(CollectionElementTypeAccess::MemberCall(collection))
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn collection_element_type_fq_name_inner(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    collection: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    bindings: &LocalInferenceEngine<String>,
    enclosing_owner: &mut dyn FnMut(usize, usize) -> Option<String>,
    remaining_collection_depth: usize,
) -> Option<String> {
    match collection_element_type_access(collection, source)? {
        CollectionElementTypeAccess::IndexedLocal if remaining_collection_depth > 0 => {
            infer_indexed_local_element_type(
                collection,
                source,
                collection.start_byte(),
                &mut |right| {
                    instance_receiver_type_fq_name_inner(
                        php,
                        analyzer,
                        right,
                        source,
                        ctx,
                        bindings,
                        enclosing_owner,
                        remaining_collection_depth - 1,
                    )
                },
            )
        }
        CollectionElementTypeAccess::IndexedLocal => None,
        CollectionElementTypeAccess::ThisField(collection) => {
            let member = collection.child_by_field_name("name")?;
            let field_name = literal_member_identifier(member, source)?;
            let owner = enclosing_owner(collection.start_byte(), collection.end_byte())?;
            collapsed_declared_member_fact(
                php,
                analyzer,
                &owner,
                field_name,
                CodeUnit::is_field,
                |field| declared_field_element_type_fq_name(php, analyzer, field),
            )
        }
        CollectionElementTypeAccess::MemberCall(collection) => {
            let remaining_collection_depth = remaining_collection_depth.checked_sub(1)?;
            let object = collection.child_by_field_name("object")?;
            let owner = instance_receiver_type_fq_name_inner(
                php,
                analyzer,
                object,
                source,
                ctx,
                bindings,
                enclosing_owner,
                remaining_collection_depth,
            )?;
            let member = collection.child_by_field_name("name")?;
            collapsed_declared_member_fact(
                php,
                analyzer,
                &owner,
                literal_member_identifier(member, source)?,
                CodeUnit::is_function,
                |callable| declared_callable_return_element_type_fq_name(php, callable),
            )
        }
    }
}

/// Resolve the declared object return type of one literal free or scoped PHP
/// call. Dynamic callable names and ambiguous physical declarations fail
/// closed. This is shared by direct receiver chains and assignment inference so
/// both usage-graph surfaces apply the same namespace and relative-scope rules.
pub fn direct_call_return_type_fq_name(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    enclosing_owner: Option<&str>,
) -> Option<String> {
    let callable_fq_name = match node.kind() {
        "function_call_expression" => {
            let function = node.child_by_field_name("function")?;
            let candidates = resolve_php_function_node(function, source, ctx, || true)?;
            candidates
                .first_indexed(|candidate| {
                    analyzer
                        .index
                        .definitions(candidate)
                        .any(|unit| unit.is_function())
                })
                .to_string()
        }
        "scoped_call_expression" => {
            let (scope, member) = static_member_parts(node)?;
            let owner = static_scope_type_fq_name(
                php,
                analyzer,
                node_text(scope, source),
                ctx,
                enclosing_owner,
            )?;
            let member = literal_member_identifier(member, source)?;
            format!("{owner}.{member}")
        }
        _ => return None,
    };

    if let Some(return_type) = analyzer.facts.callable_return_type_fqn(&callable_fq_name) {
        return Some(return_type);
    }

    let mut definitions = analyzer
        .index
        .definitions(&callable_fq_name)
        .filter(CodeUnit::is_function);
    let callable = definitions.next()?;
    if definitions.next().is_some() {
        return None;
    }
    declared_callable_return_type_fq_name(php, analyzer, &callable)
}

/// Resolve the declared object type of a PHP instance receiver without walking
/// the source tree recursively. Method-call and field-access chains are reduced
/// from their innermost receiver outward, and every step fails closed unless it
/// has one structured declaration with a class return/type fact.
pub fn instance_receiver_type_fq_name<F>(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    root: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    bindings: &LocalInferenceEngine<String>,
    mut enclosing_owner: F,
) -> Option<String>
where
    F: FnMut(usize, usize) -> Option<String>,
{
    instance_receiver_type_fq_name_inner(
        php,
        analyzer,
        root,
        source,
        ctx,
        bindings,
        &mut enclosing_owner,
        MAX_NESTED_COLLECTION_INFERENCE_DEPTH,
    )
}

// Collection element inference can follow values written from another local
// collection. Source-order checks make every such step move backward, while
// this cap keeps the best-effort dataflow walk stack-safe for generated chains.
const MAX_NESTED_COLLECTION_INFERENCE_DEPTH: usize = 8;

#[allow(clippy::too_many_arguments)]
fn instance_receiver_type_fq_name_inner(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    root: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    bindings: &LocalInferenceEngine<String>,
    enclosing_owner: &mut dyn FnMut(usize, usize) -> Option<String>,
    remaining_collection_depth: usize,
) -> Option<String> {
    enum Visit<'tree> {
        Resolve(Node<'tree>),
        Finish(Node<'tree>),
    }

    let mut resolved = HashMap::default();
    let mut stack = vec![Visit::Resolve(root)];
    while let Some(visit) = stack.pop() {
        let node = match visit {
            Visit::Resolve(node) => {
                match node.kind() {
                    "variable_name" => {
                        let name = variable_identifier(node, source);
                        let value = if let Some(type_node) =
                            dominating_instanceof_type_node(node, source, || true)
                        {
                            resolve_php_type(node_text(type_node, source), ctx)
                        } else if name == "this" {
                            enclosing_owner(node.start_byte(), node.end_byte())
                        } else if let Some(collection) =
                            enclosing_foreach_collection(node, source, || true)
                        {
                            if foreach_value_reassigned_before(node, source) {
                                match bindings.resolve_symbol(name) {
                                    SymbolResolution::Precise(targets) if targets.len() == 1 => {
                                        targets.into_iter().next()
                                    }
                                    _ => None,
                                }
                            } else {
                                collection_element_type_fq_name_inner(
                                    php,
                                    analyzer,
                                    collection,
                                    source,
                                    ctx,
                                    bindings,
                                    enclosing_owner,
                                    remaining_collection_depth,
                                )
                            }
                        } else if let SymbolResolution::Precise(targets) =
                            bindings.resolve_symbol(name)
                            && targets.len() == 1
                        {
                            targets.into_iter().next()
                        } else if let Some(collection) = enclosing_array_map_collection(
                            node,
                            source,
                            ctx,
                            || true,
                            |candidate| {
                                analyzer
                                    .index
                                    .definitions(candidate)
                                    .any(|unit| unit.is_function())
                            },
                        ) {
                            collection_element_type_fq_name_inner(
                                php,
                                analyzer,
                                collection,
                                source,
                                ctx,
                                bindings,
                                enclosing_owner,
                                remaining_collection_depth,
                            )
                        } else {
                            None
                        };
                        if let Some(value) = value {
                            resolved.insert(node.id(), value);
                        }
                    }
                    "object_creation_expression" => {
                        if let Some(type_node) = object_creation_type(node) {
                            let raw = node_text(type_node, source);
                            let owner =
                                enclosing_owner(type_node.start_byte(), type_node.end_byte());
                            if let Some(value) =
                                static_scope_type_fq_name(php, analyzer, raw, ctx, owner.as_deref())
                            {
                                resolved.insert(node.id(), value);
                            }
                        }
                    }
                    "subscript_expression" => {
                        let Some(collection) = node.named_child(0) else {
                            continue;
                        };
                        if let Some(value) = collection_element_type_fq_name_inner(
                            php,
                            analyzer,
                            collection,
                            source,
                            ctx,
                            bindings,
                            enclosing_owner,
                            remaining_collection_depth,
                        ) {
                            resolved.insert(node.id(), value);
                        }
                    }
                    "function_call_expression" | "scoped_call_expression" => {
                        let owner = (node.kind() == "scoped_call_expression")
                            .then(|| enclosing_owner(node.start_byte(), node.end_byte()))
                            .flatten();
                        if let Some(value) = direct_call_return_type_fq_name(
                            php,
                            analyzer,
                            node,
                            source,
                            ctx,
                            owner.as_deref(),
                        ) {
                            resolved.insert(node.id(), value);
                        }
                    }
                    "scoped_property_access_expression" => {
                        let (scope, member) = static_member_parts(node)?;
                        let owner = enclosing_owner(node.start_byte(), node.end_byte());
                        let owner = static_scope_type_fq_name(
                            php,
                            analyzer,
                            node_text(scope, source),
                            ctx,
                            owner.as_deref(),
                        )?;
                        let value = collapsed_declared_member_fact(
                            php,
                            analyzer,
                            &owner,
                            static_property_identifier(member, source)?,
                            CodeUnit::is_field,
                            |field| declared_field_type_fq_name(php, analyzer, field),
                        );
                        if let Some(value) = value {
                            resolved.insert(node.id(), value);
                        }
                    }
                    "parenthesized_expression"
                    | "clone_expression"
                    | "member_access_expression"
                    | "nullsafe_member_access_expression"
                    | "member_call_expression"
                    | "nullsafe_member_call_expression" => {
                        let dependency = if node.kind() == "parenthesized_expression" {
                            node.named_child(0)
                        } else if node.kind() == "clone_expression" {
                            clone_object_operand(node, source)
                        } else {
                            node.child_by_field_name("object")
                        };
                        if let Some(dependency) = dependency {
                            stack.push(Visit::Finish(node));
                            stack.push(Visit::Resolve(dependency));
                        }
                    }
                    _ => {}
                }
                continue;
            }
            Visit::Finish(node) => node,
        };

        let dependency = if node.kind() == "parenthesized_expression" {
            node.named_child(0)
        } else if node.kind() == "clone_expression" {
            clone_object_operand(node, source)
        } else {
            node.child_by_field_name("object")
        }?;
        let owner = resolved.get(&dependency.id())?;
        let value = match node.kind() {
            "parenthesized_expression" | "clone_expression" => Some(owner.clone()),
            "member_access_expression" | "nullsafe_member_access_expression" => {
                let member = node.child_by_field_name("name")?;
                collapsed_declared_member_fact(
                    php,
                    analyzer,
                    owner,
                    literal_member_identifier(member, source)?,
                    CodeUnit::is_field,
                    |field| declared_field_type_fq_name(php, analyzer, field),
                )
            }
            "member_call_expression" | "nullsafe_member_call_expression" => {
                let member = node.child_by_field_name("name")?;
                collapsed_declared_member_fact(
                    php,
                    analyzer,
                    owner,
                    literal_member_identifier(member, source)?,
                    CodeUnit::is_function,
                    |callable| declared_callable_return_type_fq_name(php, analyzer, callable),
                )
            }
            _ => None,
        };
        if let Some(value) = value {
            resolved.insert(node.id(), value);
        }
    }
    resolved.remove(&root.id())
}

/// Every nominal type a direct local variable receiver proves.
///
/// The ordinary receiver evaluator deliberately returns one type or none. A
/// target-aware usage route can be more precise: when a finite union's arms
/// collapse to one declared member, that one member is authoritative even
/// though the receiver itself has no single nominal type. Keep this helper
/// restricted to the direct variable position; union-valued interior chain
/// steps still fail closed.
pub fn direct_variable_receiver_type_fq_names(
    node: Node<'_>,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
) -> Vec<String> {
    if node.kind() != "variable_name" {
        return Vec::new();
    }
    let name = variable_identifier(node, source);
    if name == "this" {
        return Vec::new();
    }
    let Some(SymbolResolution::Precise(targets)) = bindings.resolve_symbol_ref(name) else {
        return Vec::new();
    };
    let mut owners = targets.iter().cloned().collect::<Vec<_>>();
    owners.sort();
    owners.dedup();
    owners
}

pub(super) fn direct_receiver_union_member(
    receiver: Node<'_>,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
    mut lookup: impl FnMut(&str) -> Option<CodeUnit>,
) -> Option<CodeUnit> {
    let owners = direct_variable_receiver_type_fq_names(receiver, source, bindings);
    if owners.len() < 2 {
        return None;
    }
    let mut candidates = owners
        .into_iter()
        .filter_map(|owner| lookup(&owner))
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    let [candidate] = candidates.as_slice() else {
        return None;
    };
    Some(candidate.clone())
}

pub fn declared_instance_callable(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    owner_fq_name: &str,
    member: &str,
) -> Option<CodeUnit> {
    declared_member(php, analyzer, owner_fq_name, member, CodeUnit::is_function)
}

pub fn declared_instance_field(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    owner_fq_name: &str,
    member: &str,
) -> Option<CodeUnit> {
    declared_member(php, analyzer, owner_fq_name, member, CodeUnit::is_field)
}

fn declared_member(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    owner_fq_name: &str,
    member: &str,
    wanted: fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    let family = declared_member_family(php, analyzer, owner_fq_name, member, wanted)?;
    let [candidate] = family.as_slice() else {
        return None;
    };
    Some(candidate.clone())
}

fn declared_member_family(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    owner_fq_name: &str,
    member: &str,
    wanted: fn(&CodeUnit) -> bool,
) -> Option<Vec<CodeUnit>> {
    let direct: Vec<_> = analyzer
        .index
        .definitions(owner_fq_name)
        .filter(CodeUnit::is_class)
        .flat_map(|owner| analyzer.index.direct_children(&owner))
        .filter(wanted)
        .filter(|candidate| {
            if candidate.is_function() {
                candidate.identifier().eq_ignore_ascii_case(member)
            } else {
                candidate.identifier() == member
            }
        })
        .collect();
    if !direct.is_empty() {
        return Some(direct);
    }

    let owners: Vec<_> = analyzer
        .index
        .definitions(owner_fq_name)
        .filter(CodeUnit::is_class)
        .collect();
    if owners.is_empty() {
        return None;
    }
    let mut seen = HashSet::default();
    let mut level: Vec<_> = owners
        .iter()
        .flat_map(|owner| php.get_direct_ancestors(owner).definite().to_vec())
        .collect();
    while !level.is_empty() {
        let mut families: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        let mut next_level = Vec::new();
        for ancestor in level {
            if !seen.insert(ancestor.clone()) {
                continue;
            }
            let ancestor_fq_name = ancestor.fq_name();
            let definitions = analyzer
                .index
                .definitions(&ancestor_fq_name)
                .filter(CodeUnit::is_class)
                .flat_map(|owner| analyzer.index.direct_children(&owner))
                .filter(wanted)
                .filter(|candidate| {
                    if candidate.is_function() {
                        candidate.identifier().eq_ignore_ascii_case(member)
                    } else {
                        candidate.identifier() == member
                    }
                });
            for definition in definitions {
                families
                    .entry(definition.fq_name())
                    .or_default()
                    .push(definition);
            }
            next_level.extend(php.get_direct_ancestors(&ancestor).definite().to_vec());
        }
        if !families.is_empty() {
            let mut families = families.into_values();
            let family = families.next()?;
            if families.next().is_some() {
                return None;
            }
            return Some(family);
        }
        level = next_level;
    }
    None
}

fn collapsed_declared_member_fact<F>(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    owner_fq_name: &str,
    member: &str,
    wanted: fn(&CodeUnit) -> bool,
    mut fact: F,
) -> Option<String>
where
    F: FnMut(&CodeUnit) -> Option<String>,
{
    let family = declared_member_family(php, analyzer, owner_fq_name, member, wanted)?;
    let mut answer = None;
    for declaration in family {
        let value = fact(&declaration)?;
        if answer.as_ref().is_some_and(|known| known != &value) {
            return None;
        }
        answer = Some(value);
    }
    answer
}

fn indexed_declared_type_fq_name(analyzer: PhpGraphSource<'_>, unit: &CodeUnit) -> Option<String> {
    analyzer.facts.declaration_return_type_fqn(unit)
}

/// What the declared type of one field or callable proves, including dynamic types.
pub fn declared_type_of(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    unit: &CodeUnit,
) -> PhpDeclaredType {
    if !unit.is_field() && !unit.is_function() {
        return PhpDeclaredType::Unknown;
    }
    if let Some(indexed) = indexed_declared_type_fq_name(analyzer, unit) {
        return PhpDeclaredType::Nominal(vec![indexed]);
    }
    let signature = canonical_declared_type(php, unit);
    if signature != PhpDeclaredType::Unknown {
        return signature;
    }
    PhpDeclaredType::nominal(canonical_doc_nominal_type(php, unit).into_iter().collect())
}

fn canonical_declared_type_fq_name(php: &dyn PhpSource, unit: &CodeUnit) -> Option<String> {
    let mut arms = canonical_declared_type(php, unit).arms();
    (arms.len() == 1).then(|| arms.remove(0))
}

pub fn canonical_declared_type(php: &dyn PhpSource, unit: &CodeUnit) -> PhpDeclaredType {
    let Some(source) = php.php_source_facts(unit.source()) else {
        return PhpDeclaredType::Unknown;
    };
    let mut declarations = source.declarations_for(unit);
    let Some(first) = declarations.next() else {
        return PhpDeclaredType::Unknown;
    };
    if declarations.any(|declaration| declaration.declared_type != first.declared_type) {
        return PhpDeclaredType::Unknown;
    }
    match &first.declared_type {
        PhpDeclaredSourceType::Unknown => PhpDeclaredType::Unknown,
        PhpDeclaredSourceType::Nominal(arms) => PhpDeclaredType::nominal(arms.clone()),
        PhpDeclaredSourceType::DynamicObject => PhpDeclaredType::Dynamic("object"),
        PhpDeclaredSourceType::DynamicMixed => PhpDeclaredType::Dynamic("mixed"),
        PhpDeclaredSourceType::SelfType | PhpDeclaredSourceType::StaticType => {
            PhpDeclaredType::nominal(
                php.parent_of(unit)
                    .map(|owner| owner.fq_name())
                    .into_iter()
                    .collect(),
            )
        }
        PhpDeclaredSourceType::ParentType => PhpDeclaredType::nominal(
            php.parent_of(unit)
                .and_then(|owner| php_direct_declared_class_parent(php, &owner))
                .map(|parent| parent.fq_name())
                .into_iter()
                .collect(),
        ),
    }
}

/// The member surface a PHP reference addresses.
///
/// PHP resolves an absent member through a different magic method for each
/// surface, and [`magic_member_names`] is the one table of those methods that
/// both the semantic-diagnostics pass and forward definition lookup read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhpMagicSurface {
    InstanceCall,
    InstanceProperty,
    StaticCall,
    /// A static property or class constant: PHP has no magic hook for either,
    /// so an absent member on this surface really is absent.
    StaticData,
}

/// The magic methods through which an owner resolves an absent member of
/// `surface` at run time.
pub fn magic_member_names(surface: PhpMagicSurface) -> &'static [&'static str] {
    match surface {
        PhpMagicSurface::InstanceCall => &["__call"],
        PhpMagicSurface::InstanceProperty => &["__get", "__set"],
        PhpMagicSurface::StaticCall => &["__callStatic"],
        PhpMagicSurface::StaticData => &[],
    }
}

#[cfg(test)]
mod declaration_name_range_tests {
    use super::php_declaration_name_range;
    use brokk_bifrost_test_macros::hardwon;
    use tree_sitter::Node;

    fn parse(source: &str) -> tree_sitter::Tree {
        crate::aliases::parse_php_tree(source).expect("PHP tree")
    }

    /// The node generic name-range selection lands on: the `name` whose text is
    /// the stored, sigil-free identifier.
    fn identifier_node<'tree>(root: Node<'tree>, identifier: &str, source: &str) -> Node<'tree> {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "name" && node.utf8_text(source.as_bytes()) == Ok(identifier) {
                return node;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        panic!("no `name` node spelling {identifier} in {source:?}");
    }

    fn range_text<'s>(source: &'s str, identifier: &str) -> &'s str {
        let tree = parse(source);
        let node = identifier_node(tree.root_node(), identifier, source);
        let range = php_declaration_name_range(node);
        &source[range.start_byte..range.end_byte]
    }

    /// A property declarator's token includes the `$`, so its reported range
    /// must too -- even though the identity stays sigil-free so that the
    /// declaration and every `->last` access share one name.
    #[test]
    #[hardwon(
        "#2416: PHP property declaration ranges omitted the variable sigil or widened to unrelated names"
    )]
    fn a_property_declarator_range_covers_the_sigil() {
        assert_eq!(
            range_text(
                "<?php\nclass R {\n    public string $last = '';\n}\n",
                "last"
            ),
            "$last"
        );
    }

    /// The static form parses to the same `property_element -> variable_name`
    /// shape; `static` only changes the modifier text.
    #[test]
    #[hardwon("#2416: PHP property declaration ranges omitted the leading dollar sigil")]
    fn a_static_property_declarator_range_covers_the_sigil() {
        assert_eq!(
            range_text(
                "<?php\nclass C {\n    public static int $sent = 0;\n}\n",
                "sent"
            ),
            "$sent"
        );
    }
    /// A constructor-promoted property is declared with the same `$` token.
    #[test]
    #[hardwon(
        "#2416: PHP property declaration ranges omitted the variable sigil or widened to unrelated names"
    )]
    fn a_promoted_property_declarator_range_covers_the_sigil() {
        assert_eq!(
            range_text(
                "<?php\nclass S {\n    public function __construct(private string $repo) {}\n}\n",
                "repo"
            ),
            "$repo"
        );
    }

    /// A method name is a bare `name` with no `variable_name` parent. Widening
    /// must not reach it, and must not reach a sigil-free `->last` access.
    #[test]
    fn a_name_without_a_variable_parent_is_left_alone() {
        assert_eq!(
            range_text("<?php\nclass F {\n    public function bar() {}\n}\n", "bar"),
            "bar"
        );
        assert_eq!(range_text("<?php\n$r->last;\n", "last"), "last");
    }
}

#[cfg(test)]
mod clone_object_operand_tests {
    use super::clone_object_operand;
    use crate::aliases::parse_php_tree;
    use brokk_bifrost_test_macros::hardwon;
    use tree_sitter::Node;

    fn clone_expression<'tree>(root: Node<'tree>) -> Node<'tree> {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "clone_expression" {
                return node;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        panic!("source has no clone expression: {root:?}");
    }

    #[test]
    #[hardwon("#4408: PHP clone consumers treated the new arguments node as the object")]
    fn clone_object_operand_reads_structured_arguments_and_fails_closed_on_near_misses() {
        for (source, expected) in [
            ("<?php clone /* comment */ $object;", Some("$object")),
            (
                "<?php clone(/* object */ $object, /* properties */ withProperties: ['x' => $value]);",
                Some("$object"),
            ),
            (
                "<?php clone(withProperties: ['x' => $value], object: $object);",
                Some("$object"),
            ),
            ("<?php clone(namedObject: $object);", None),
            ("<?php clone(Object: $object);", None),
            ("<?php clone(...);", None),
            ("<?php clone($first, ...$args);", None),
            ("<?php clone(...$args, object: $object);", None),
            ("<?php clone(object: $first, object: $second);", None),
            ("<?php clone($first, object: $second);", None),
        ] {
            let tree = parse_php_tree(source).expect("PHP tree");
            let clone = clone_expression(tree.root_node());
            let actual = clone_object_operand(clone, source)
                .map(|node| &source[node.start_byte()..node.end_byte()]);
            assert_eq!(actual, expected, "source: {source}");
        }
    }
}

#[cfg(test)]
pub(crate) mod graph_boundary_tests {
    use super::*;
    use crate::graph::PhpCallableFacts;
    use crate::source_facts::{PhpFileSourceFacts, PhpSourceFactProvider};
    use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;
    use brokk_bifrost_core::analyzer::model::{Language, Range};
    use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
    use brokk_bifrost_core::analyzer::project::{Project, ProjectSourceSnapshot};
    use brokk_bifrost_core::analyzer::usages::inverted_edges::{
        FileDeclarations, FileEdgeScanInput,
    };
    use brokk_bifrost_core::analyzer::{CodeUnitIndex, ProjectFile};
    use brokk_bifrost_test_macros::hardwon;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    // A single-file index at the parser/graph boundary. All declaration and
    // type facts come from the production parser, not a hand-authored model.
    pub(crate) struct Fixture {
        pub source: String,
        pub tree: tree_sitter::Tree,
        pub file: ProjectFile,
        pub parsed: ParsedFile,
        facts: Arc<PhpFileSourceFacts>,
    }
    impl Fixture {
        pub fn new(source: &str) -> Self {
            let tree = crate::aliases::parse_php_tree(source).unwrap();
            assert!(
                !tree.root_node().has_error(),
                "{}",
                tree.root_node().to_sexp()
            );
            let file = ProjectFile::new(std::env::temp_dir(), PathBuf::from("qs9-boundary.php"));
            let mut parsed = crate::declarations::parse_php_file(&file, source, &tree);
            let rows = parsed.source_facts.as_mut().unwrap();
            let mut units: HashMap<_, Vec<_>> = HashMap::default();
            for (id, unit) in &parsed.source_declaration_units {
                units.entry(*id).or_default().push(unit.clone());
            }
            let facts = Arc::new(PhpFileSourceFacts {
                source: rows.occurrences.clone(),
                imports: rows.imports.clone(),
                facts: rows.php.clone().unwrap(),
                declaration_units: units,
            });
            Self {
                source: source.into(),
                tree,
                file,
                parsed,
                facts,
            }
        }
        pub fn add_definition_file(&mut self, name: &str, source: &str) {
            let tree = crate::aliases::parse_php_tree(source).unwrap();
            let file = ProjectFile::new(std::env::temp_dir(), PathBuf::from(name));
            let parsed = crate::declarations::parse_php_file(&file, source, &tree);
            for (unit, ranges) in &parsed.ranges {
                let parent = parsed
                    .children
                    .iter()
                    .find(|(_, children)| children.contains(unit))
                    .map(|(owner, _)| owner.clone());
                for range in ranges {
                    self.parsed.add_code_unit_with_range(
                        unit.clone(),
                        *range,
                        parent.clone(),
                        None,
                    );
                }
            }
        }
        pub fn graph(&self) -> PhpGraphSource<'_> {
            PhpGraphSource {
                index: self,
                facts: self,
            }
        }
        pub fn unit(&self, name: &str) -> CodeUnit {
            self.definitions(name)
                .next()
                .unwrap_or_else(|| panic!("missing {name}: {:?}", self.parsed.declarations()))
        }
        pub fn reference_targets(&self) -> Vec<(String, String)> {
            let nodes: HashSet<_> = self.all_declarations().map(|unit| unit.fq_name()).collect();
            let declarations = FileDeclarations {
                enclosing_units: HashMap::default(),
                enclosers: self
                    .parsed
                    .ranges
                    .iter()
                    .filter(|(unit, _)| unit.source() == &self.file)
                    .flat_map(|(unit, ranges)| {
                        ranges
                            .iter()
                            .map(|r| (r.start_byte, r.end_byte, unit.fq_name()))
                    })
                    .collect(),
                definitions: self
                    .parsed
                    .ranges
                    .iter()
                    .filter(|(unit, _)| unit.source() == &self.file)
                    .map(|(unit, ranges)| {
                        (
                            unit.fq_name(),
                            ranges.iter().map(|r| (r.start_byte, r.end_byte)).collect(),
                        )
                    })
                    .collect(),
            };
            let lines = brokk_bifrost_core::text_utils::compute_line_starts(&self.source);
            let terminal_catalog =
                brokk_bifrost_core::analyzer::usages::inverted_edges::terminal_index(
                    &crate::PhpKnowledge,
                    &nodes,
                    |key| self.definitions(key).map(|unit| unit.kind()).collect(),
                );
            let input = FileEdgeScanInput::new(
                brokk_bifrost_core::analyzer::usages::inverted_edges::FileEdgeSyntax {
                    tree: &self.tree,
                    source: &self.source,
                    line_starts: &lines,
                },
                &crate::PhpKnowledge,
                Some(&nodes),
                Some(&nodes),
                &declarations,
                &terminal_catalog,
            );
            crate::graph::inverted::scan_php_file(self.graph(), self, &self.file, &input)
                .edge_lines
                .into_keys()
                .collect()
        }
    }
    impl Project for Fixture {
        fn root(&self) -> &Path {
            self.file.root()
        }
        fn analyzer_languages(&self) -> BTreeSet<Language> {
            BTreeSet::from([Language::Php])
        }
        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            Ok(BTreeSet::from([self.file.clone()]))
        }
        fn analyzable_files(&self, _: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.all_files()
        }
        fn file_by_rel_path(&self, path: &Path) -> Option<ProjectFile> {
            (path == self.file.rel_path()).then(|| self.file.clone())
        }
        fn read_source(&self, _: &ProjectFile) -> std::io::Result<String> {
            Ok(self.source.clone())
        }
        fn read_source_snapshot(&self, _: &ProjectFile) -> std::io::Result<ProjectSourceSnapshot> {
            Ok(ProjectSourceSnapshot::disk(self.source.as_str()))
        }
    }
    impl CodeUnitIndex for Fixture {
        fn project(&self) -> &dyn Project {
            self
        }
        fn languages(&self) -> BTreeSet<Language> {
            self.analyzer_languages()
        }
        fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
            Box::new(self.parsed.declarations().iter().cloned())
        }
        fn definitions(&self, name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
            let name = name.to_string();
            Box::new(
                self.parsed
                    .declarations()
                    .iter()
                    .filter(move |unit| unit.fq_name() == name)
                    .cloned(),
            )
        }
        fn search_definitions(&self, _: &str, _: bool) -> BTreeSet<CodeUnit> {
            unimplemented!()
        }
        fn enclosing_code_unit(&self, _: &ProjectFile, range: &Range) -> Option<CodeUnit> {
            self.parsed
                .ranges
                .iter()
                .flat_map(|(unit, ranges)| ranges.iter().map(move |r| (unit, r)))
                .filter(|(_, r)| r.start_byte <= range.start_byte && range.end_byte <= r.end_byte)
                .min_by_key(|(_, r)| r.end_byte - r.start_byte)
                .map(|(u, _)| u.clone())
        }
        fn enclosing_code_unit_for_lines(
            &self,
            _: &ProjectFile,
            _: usize,
            _: usize,
        ) -> Option<CodeUnit> {
            unimplemented!()
        }
        fn get_skeleton(&self, _: &CodeUnit) -> Option<String> {
            unimplemented!()
        }
        fn get_skeleton_header(&self, _: &CodeUnit) -> Option<String> {
            unimplemented!()
        }
        fn get_sources(&self, _: &CodeUnit, _: bool) -> BTreeSet<String> {
            unimplemented!()
        }
        fn direct_children(&self, unit: &CodeUnit) -> Vec<CodeUnit> {
            self.parsed.children.get(unit).cloned().unwrap_or_default()
        }
        fn ranges(&self, unit: &CodeUnit) -> Vec<Range> {
            self.parsed.ranges.get(unit).cloned().unwrap_or_default()
        }
        fn signature_metadata(
            &self,
            unit: &CodeUnit,
        ) -> Vec<brokk_bifrost_core::analyzer::model::SignatureMetadata> {
            self.parsed
                .signature_metadata
                .get(unit)
                .cloned()
                .unwrap_or_default()
        }
        fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
            self.all_declarations()
                .filter(|unit| unit.source() == file)
                .collect()
        }
    }
    impl TypeHierarchyProvider for Fixture {
        fn get_direct_ancestors(
            &self,
            unit: &CodeUnit,
        ) -> brokk_bifrost_core::analyzer::capabilities::HierarchyAnswer {
            let edges: Vec<CodeUnit> = {
                self.facts
                    .declarations_for(unit)
                    .flat_map(|d| &d.supertypes)
                    .flat_map(|name| self.definitions(name))
                    .collect()
            };
            brokk_bifrost_core::analyzer::capabilities::HierarchyAnswer::complete(edges)
        }
        fn get_direct_descendants(
            &self,
            _: &CodeUnit,
        ) -> brokk_bifrost_core::analyzer::capabilities::HierarchyAnswer {
            unimplemented!()
        }
    }
    impl PhpSourceFactProvider for Fixture {
        fn php_source_facts_while(
            &self,
            file: &ProjectFile,
            _: &dyn Fn() -> bool,
        ) -> Option<Arc<PhpFileSourceFacts>> {
            (file == &self.file).then(|| self.facts.clone())
        }
    }
    impl PhpCallableFacts for Fixture {
        fn declaration_return_type_fqn(&self, unit: &CodeUnit) -> Option<String> {
            canonical_declared_type_fq_name(self, unit)
                .or_else(|| canonical_doc_nominal_type(self, unit))
        }
        fn callable_return_type_fqn(&self, name: &str) -> Option<String> {
            self.definitions(name)
                .find(CodeUnit::is_function)
                .and_then(|unit| self.declaration_return_type_fqn(&unit))
        }
    }

    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: static field inference used dynamic instance writes"
    )]
    fn static_field_inference_respects_declaration_storage() {
        let fixture = Fixture::new(
            "<?php class A {} class B {} class C { public static $value; function __construct() { $this->value=new A(); } static function init() { self::$value=new B(); } }",
        );
        assert_eq!(
            canonical_inferred_field_type(&fixture, &fixture.unit("C.value")),
            Some("B".into())
        );
    }

    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: empty array assignment retained historical element types"
    )]
    fn indexed_collection_reset_replaces_historical_values() {
        for (program, expected) in [
            ("$items=[]; $items[]=new A(); $items=[];", None),
            (
                "$items=[]; $items[]=new A(); $items=[]; $items[]=new B();",
                Some("B"),
            ),
            (
                "$items=[]; $items[]=new A(); $items[]=new B(); $items=[]; $items[]=new B();",
                Some("B"),
            ),
            ("$items=unknown(); $items=[]; $items[]=new B();", Some("B")),
            (
                "$items=[]; $items[]=new A(); if ($choice) { $items=[]; $items[]=new B(); }",
                None,
            ),
        ] {
            let source = format!("<?php function f() {{ {program} consume($items); }}");
            let tree = crate::aliases::parse_php_tree(&source).unwrap();
            let mut stack = vec![tree.root_node()];
            let mut refs = Vec::new();
            while let Some(node) = stack.pop() {
                if node.kind() == "variable_name" && node_text(node, &source) == "$items" {
                    refs.push(node);
                }
                for i in 0..node.named_child_count() {
                    stack.push(node.named_child(i).unwrap());
                }
            }
            let collection = refs.into_iter().max_by_key(Node::start_byte).unwrap();
            let inferred = infer_indexed_local_element_type(
                collection,
                &source,
                collection.start_byte(),
                &mut |right| object_creation_type(right).map(|ty| node_text(ty, &source).into()),
            );
            assert_eq!(inferred.as_deref(), expected, "{source}");
        }
    }
    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: typed foreach collection hid a receiver reassignment"
    )]
    fn typed_foreach_reassignment_uses_the_current_value() {
        let fixture = Fixture::new(
            r"<?php
class A { function touch() {} }
class B { function touch() {} }
class Owner {
/** @var A[] */ public $items;
function caller() {
    foreach ($this->items as $item) {
        $item = new B();
        $item->touch();
    }
}
}",
        );
        let targets = fixture.reference_targets();
        assert!(
            targets.contains(&("Owner.caller".into(), "B.touch".into())),
            "{targets:?}"
        );
        assert!(
            !targets.contains(&("Owner.caller".into(), "A.touch".into())),
            "{targets:?}"
        );
    }

    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: qualified instanceof operands were omitted from inverse edges"
    )]
    fn qualified_instanceof_publishes_the_type_edge() {
        let fixture = Fixture::new(
            r"<?php namespace App; class Target {} function check($value) { return $value instanceof \App\Target; }",
        );
        assert!(
            fixture
                .reference_targets()
                .contains(&("App.check".into(), "App.Target".into()))
        );
    }

    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: mixed-case method names lost targeted references"
    )]
    fn mixed_case_method_calls_reach_targeted_and_inverse_scans() {
        let fixture = Fixture::new(
            "<?php class Service { public $Value; const FLAG=1; function run() {} } function caller(Service $s) { $s->RUN(); $s->Value; $s->value; Service::FLAG; Service::flag; }",
        );
        let spec =
            crate::graph::resolver::TargetSpec::from_target(&fixture, &fixture.unit("Service.run"))
                .unwrap();
        let hierarchy =
            crate::graph::resolver::PhpHierarchyIndex::for_target_owner(&fixture, &spec);
        let mut hits = BTreeSet::new();
        crate::graph::extractor::scan_file(
            &fixture,
            fixture.graph(),
            &fixture.file,
            &spec,
            &hierarchy,
            &mut hits,
        );
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(
            fixture
                .reference_targets()
                .contains(&("caller".into(), "Service.run".into()))
        );
        for target in ["Service.Value", "Service.FLAG"] {
            let spec =
                crate::graph::resolver::TargetSpec::from_target(&fixture, &fixture.unit(target))
                    .unwrap();
            let hierarchy =
                crate::graph::resolver::PhpHierarchyIndex::for_target_owner(&fixture, &spec);
            let mut hits = BTreeSet::new();
            crate::graph::extractor::scan_file(
                &fixture,
                fixture.graph(),
                &fixture.file,
                &spec,
                &hierarchy,
                &mut hits,
            );
            assert_eq!(hits.len(), 1, "case-sensitive {target}: {hits:?}");
            let hit = hits.first().unwrap();
            assert_eq!(
                &fixture.source[hit.start_offset..hit.end_offset],
                spec.member_name
            );
        }
    }
    #[test]
    fn php_receiver_flow_golden() {
        let fixture = Fixture::new(include_str!(
            "../../tests/fixtures/golden/receiver-flow/input.php"
        ));
        let mut rendered: Vec<_> = fixture
            .reference_targets()
            .into_iter()
            .filter(|(_, callee)| {
                ["A.touch", "A.run", "B.touch", "Both.run", "Base.run"].contains(&callee.as_str())
            })
            .map(|(caller, callee)| format!("{caller} -> {callee}\n"))
            .collect();
        let mut targeted = Vec::new();
        for callee in ["A.touch", "A.run", "B.touch", "Both.run", "Base.run"] {
            let spec =
                crate::graph::resolver::TargetSpec::from_target(&fixture, &fixture.unit(callee))
                    .unwrap();
            let hierarchy =
                crate::graph::resolver::PhpHierarchyIndex::for_target_owner(&fixture, &spec);
            let mut hits = BTreeSet::new();
            crate::graph::extractor::scan_file(
                &fixture,
                fixture.graph(),
                &fixture.file,
                &spec,
                &hierarchy,
                &mut hits,
            );
            for hit in hits {
                targeted.push(format!("{} -> {callee}\n", hit.enclosing.fq_name()));
            }
        }
        targeted.sort();
        assert_eq!(
            targeted.concat(),
            include_str!("../../tests/fixtures/golden/receiver-flow/expected.txt")
        );
        rendered.sort();
        assert_eq!(
            rendered.concat(),
            include_str!("../../tests/fixtures/golden/receiver-flow/expected.txt")
        );
    }
    #[test]
    fn php_conditional_declarations_golden() {
        let mut fixture = Fixture::new(include_str!(
            "../../tests/fixtures/golden/conditional-declarations/input.php"
        ));
        fixture.add_definition_file(
            "qs9-duplicate.php",
            "<?php class Ambiguous { function touch() {} }",
        );
        let rendered = fixture
            .reference_targets()
            .into_iter()
            .filter(|(_, callee)| callee.ends_with(".touch"))
            .map(|(caller, callee)| format!("{caller} -> {callee}\n"))
            .collect::<String>();
        assert_eq!(
            rendered,
            include_str!("../../tests/fixtures/golden/conditional-declarations/expected.txt")
        );
    }

    #[test]
    fn php_function_fallback_golden() {
        let fixture = Fixture::new(include_str!(
            "../../tests/fixtures/golden/function-fallback/input.php"
        ));
        let rendered = fixture
            .reference_targets()
            .into_iter()
            .filter(|(_, callee)| callee.ends_with(".touch"))
            .map(|(caller, callee)| format!("{caller} -> {callee}\n"))
            .collect::<String>();
        assert_eq!(
            rendered,
            include_str!("../../tests/fixtures/golden/function-fallback/expected.txt")
        );
    }

    #[test]
    #[hardwon(
        "#7228: review: member-call collection inference recursed without consuming its depth budget"
    )]
    fn deep_member_collection_chain_is_bounded() {
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                let fixture =
                    Fixture::new("<?php class A { /** @return A[] */ function items() {} }");
                let source = format!("<?php $a{};", "->items()[0]".repeat(2048));
                let tree = crate::aliases::parse_php_tree(&source).unwrap();
                assert!(!tree.root_node().has_error());
                let expression = tree
                    .root_node()
                    .named_child(1)
                    .unwrap()
                    .named_child(0)
                    .unwrap();
                assert_eq!(expression.kind(), "subscript_expression");
                let bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
                let actual = instance_receiver_type_fq_name(
                    &fixture,
                    fixture.graph(),
                    expression,
                    &source,
                    &PhpFileContext {
                        namespace: String::new(),
                        aliases: Default::default(),
                    },
                    &bindings,
                    |_, _| Some("A".into()),
                );
                assert_eq!(actual, None);
            })
            .unwrap()
            .join()
            .expect("bounded member collection inference");
    }

    #[test]
    fn supported_nested_collection_depths_preserve_the_receiver() {
        let mut source = String::from("<?php class A { function touch() {} }\n");
        for depth in 0..8 {
            source.push_str(&format!(
                "function depth{depth}() {{ $a0=[]; $a0[]=new A();\n"
            ));
            for hop in 1..=depth {
                source.push_str(&format!("$a{hop}=[]; $a{hop}[]=$a{}[0];\n", hop - 1));
            }
            source.push_str(&format!("$a{depth}[0]->touch(); }}\n"));
        }
        let fixture = Fixture::new(&source);
        let actual: Vec<_> = fixture
            .reference_targets()
            .into_iter()
            .filter(|(_, callee)| callee == "A.touch")
            .map(|(caller, _)| caller)
            .collect();
        assert_eq!(
            actual,
            (0..8)
                .map(|depth| format!("depth{depth}"))
                .collect::<Vec<_>>()
        );
    }
    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: canonical field writes mixed static and instance storage"
    )]
    fn field_write_inference_respects_published_storage_metadata() {
        let source = "<?php class A {} class B {} class C { public static $value; function __construct() { $this->value=new A(); } static function init() { self::$value=new B(); } }";
        let mut fixture = Fixture::new(source);
        let field = fixture.unit("C.value");
        for (is_static, expected) in [(true, "B"), (false, "A")] {
            for metadata in fixture.parsed.signature_metadata.get_mut(&field).unwrap() {
                *metadata = metadata.clone().with_field_modifiers(is_static, false);
            }
            assert_eq!(
                canonical_inferred_field_type(&fixture, &field).as_deref(),
                Some(expected)
            );
        }
        fixture.parsed.signature_metadata.remove(&field).unwrap();
        assert_eq!(
            canonical_inferred_field_type(&fixture, &field).as_deref(),
            Some("A")
        );
    }

    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: uppercase relative scopes lost or misclassified static calls"
    )]
    fn relative_static_scopes_and_method_names_ignore_ascii_case() {
        let fixture = Fixture::new(
            "<?php class Base { static function run() {} } class Child extends Base { function caller() { PARENT::RUN(); SELF::RUN(); STATIC::RUN(); } }",
        );
        let methods: Vec<_> = fixture
            .reference_targets()
            .into_iter()
            .filter(|(_, callee)| callee.ends_with(".run") || callee.ends_with(".RUN"))
            .collect();
        assert_eq!(methods, vec![("Child.caller".into(), "Base.run".into())]);
        let spec =
            crate::graph::resolver::TargetSpec::from_target(&fixture, &fixture.unit("Base.run"))
                .unwrap();
        let hierarchy =
            crate::graph::resolver::PhpHierarchyIndex::for_target_owner(&fixture, &spec);
        let mut hits = BTreeSet::new();
        crate::graph::extractor::scan_file(
            &fixture,
            fixture.graph(),
            &fixture.file,
            &spec,
            &hierarchy,
            &mut hits,
        );
        assert_eq!(hits.len(), 3, "{hits:?}");
        assert_eq!(
            hits.iter()
                .filter(|hit| hit.kind
                    == brokk_bifrost_core::analyzer::usages::model::UsageHitKind::SelfReceiver)
                .count(),
            2
        );
    }
    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: PHP graph and exit-guard walks recursively consumed the Rust stack"
    )]
    fn deep_syntax_uses_bounded_rust_stack_through_both_usage_scans() {
        std::thread::Builder::new().stack_size(256 * 1024).spawn(|| {
            let depth = 2048;
            let source = format!("<?php class A {{ function touch() {{}} }} function caller($value) {{ if (!($value instanceof A)) {}return;{} $value->touch(); new A(); }}", "{".repeat(depth), "}".repeat(depth));
            let fixture = Fixture::new(&source);
            assert!(fixture.reference_targets().contains(&("caller".into(), "A.touch".into())));
            for (target, expected) in [("A", 2), ("A.touch", 1)] {
                let spec = crate::graph::resolver::TargetSpec::from_target(&fixture, &fixture.unit(target)).unwrap();
                let hierarchy = crate::graph::resolver::PhpHierarchyIndex::for_target_owner(&fixture, &spec);
                let mut hits = BTreeSet::new();
                crate::graph::extractor::scan_file(&fixture, fixture.graph(), &fixture.file, &spec, &hierarchy, &mut hits);
                assert_eq!(hits.len(), expected, "{target}: {hits:?}");
            }
        }).unwrap().join().expect("bounded-stack graph scans");
    }
}
