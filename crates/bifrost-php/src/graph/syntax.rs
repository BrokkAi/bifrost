use super::resolver::node_text;
use crate::adapter::php_signature_return_type_text;
use crate::aliases::{
    PhpDeclaredType, PhpFileContext, PhpFileContextIndex, php_dynamic_type_keyword,
    resolve_php_function_node, resolve_php_type, resolve_php_type_arms,
};
use crate::graph::PhpGraphSource;
use crate::graph_support::PhpSource;
use crate::graph_support::php_direct_declared_class_parent;
use crate::phpdoc::{
    parameter_element_type as phpdoc_parameter_element_type,
    return_element_type as phpdoc_return_element_type,
    return_nominal_type as phpdoc_return_nominal_type, var_element_type as phpdoc_var_element_type,
    var_nominal_type as phpdoc_var_nominal_type,
};
use brokk_bifrost_core::analyzer::usages::local_inference::{
    LocalInferenceConfig, LocalInferenceEngine, SymbolResolution,
};
use brokk_bifrost_core::analyzer::{CodeUnit, Range};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::{Node, Parser};

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

/// Reduce `((expr))` to `expr`. Parentheses nest without bound in generated
/// source, so this descends with a loop instead of a recursive call.
pub fn unwrap_parenthesized(node: Node<'_>) -> Node<'_> {
    let mut current = node;
    while current.kind() == "parenthesized_expression" {
        let Some(inner) = current.named_child(0) else {
            break;
        };
        current = inner;
    }
    current
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

/// The type name a `binary_expression` spells on the right of `instanceof`.
///
/// `$x instanceof Foo` is a type reference like any other, but the grammar
/// spells it as a plain `name`/`qualified_name` under the operator rather than
/// as a `named_type`, so the shape has to be recognized from the operator.
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
        "self" | "static" => enclosing_owner.map(str::to_string),
        "parent" => {
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

fn statement_prevents_following_sibling<F>(node: Node<'_>, step: &mut F) -> bool
where
    F: FnMut() -> bool,
{
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
    node.named_child_count()
        .checked_sub(1)
        .and_then(|index| node.named_child(index))
        .is_some_and(|last| statement_prevents_following_sibling(last, step))
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
        .or_else(|| signature_declared_type_fq_name(php, analyzer, field))
        .or_else(|| phpdoc_declared_type_fact_fq_name(php, field, phpdoc_var_nominal_type))
        .or_else(|| inferred_constructor_field_type_fq_name(php, analyzer, field))
}

fn declared_relative_field_type_fq_name(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    field: &CodeUnit,
) -> Option<String> {
    let owner = php.parent_of(field).filter(CodeUnit::is_class)?;
    let source = php.project().read_source(field.source()).ok()?;
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    let tree = parser.parse(source.as_str(), None)?;
    let declaration = declaration_node_for_unit(
        tree.root_node(),
        &source,
        field,
        php.ranges(field).as_slice(),
        || true,
    )?;
    let type_node = declaration.child_by_field_name("type")?;
    let keyword = relative_declared_type_keyword(type_node, &source, || true)?;
    let contexts = PhpFileContextIndex::from_tree(tree.root_node(), &source, || true)?;
    let ctx = contexts.context_at(declaration.start_byte());
    static_scope_type_fq_name(php, analyzer, keyword, ctx, Some(owner.fq_name().as_str()))
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
    analyzer: PhpGraphSource<'_>,
    field: &CodeUnit,
) -> Option<String> {
    if !field.is_field() {
        return None;
    }
    let owner = php.parent_of(field)?;
    if !owner.is_class() {
        return None;
    }
    let source = php.project().read_source(field.source()).ok()?;
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    let tree = parser.parse(source.as_str(), None)?;
    let declaration = enclosing_class_declaration_for_field(
        tree.root_node(),
        &source,
        &owner,
        php.ranges(field).as_slice(),
        || true,
    )?;
    let contexts = PhpFileContextIndex::from_tree(tree.root_node(), &source, || true)?;
    let ctx = contexts.context_at(declaration.start_byte());
    infer_indexed_field_element_type(
        declaration,
        &source,
        field.identifier(),
        || true,
        |right| {
            let right = unwrap_parenthesized(right);
            if right.kind() == "object_creation_expression" {
                let type_node = object_creation_type(right)?;
                return static_scope_type_fq_name(
                    php,
                    analyzer,
                    node_text(type_node, &source),
                    ctx,
                    Some(owner.fq_name().as_str()),
                );
            }
            let type_node = parameter_type_node(right, &source, || true)?;
            let mut arms = resolve_php_type_arms(node_text(type_node, &source), ctx);
            (arms.len() == 1).then(|| arms.remove(0))
        },
    )
    .or_else(|| {
        let field_declaration = declaration_node_for_unit(
            tree.root_node(),
            &source,
            field,
            php.ranges(field).as_slice(),
            || true,
        )?;
        let raw = phpdoc_var_element_type(declaration_doc_comment(field_declaration, &source)?)?;
        resolve_php_type(&raw, ctx)
    })
    .or_else(|| {
        let field_declaration = declaration_node_for_unit(
            tree.root_node(),
            &source,
            field,
            php.ranges(field).as_slice(),
            || true,
        )?;
        let raw = promoted_property_doc_element_type(field_declaration, &source, || true)?;
        resolve_php_type(&raw, ctx)
    })
    .or_else(|| {
        infer_constructor_assigned_field_type(
            declaration,
            &source,
            field.identifier(),
            || true,
            |right| {
                let raw = parameter_doc_element_type(right, &source, || true)?;
                resolve_php_type(&raw, ctx)
            },
        )
    })
}

/// Infer one untyped property's nominal type from direct constructor writes.
///
/// This is deliberately narrower than general PHP data flow. Every explicit
/// `$this->field = ...` write in the declaring class must occur directly in
/// `__construct`; each right-hand side must be a structured object creation or
/// a directly declared, singly nominal constructor parameter; and all writes
/// must name the same class. A setter write, closure write, untyped/union
/// parameter, unresolved construction, or competing type therefore fails closed.
fn inferred_constructor_field_type_fq_name(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    field: &CodeUnit,
) -> Option<String> {
    let owner = php.parent_of(field)?;
    if !owner.is_class() {
        return None;
    }
    let source = php.project().read_source(field.source()).ok()?;
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    let tree = parser.parse(source.as_str(), None)?;
    let declaration = enclosing_class_declaration_for_field(
        tree.root_node(),
        &source,
        &owner,
        php.ranges(field).as_slice(),
        || true,
    )?;
    let contexts = PhpFileContextIndex::from_tree(tree.root_node(), &source, || true)?;
    let ctx = contexts.context_at(declaration.start_byte());
    infer_constructor_assigned_field_type(
        declaration,
        &source,
        field.identifier(),
        || true,
        |right| {
            let right = unwrap_parenthesized(right);
            if right.kind() == "object_creation_expression" {
                let type_node = object_creation_type(right)?;
                return static_scope_type_fq_name(
                    php,
                    analyzer,
                    node_text(type_node, &source),
                    ctx,
                    Some(owner.fq_name().as_str()),
                );
            }
            let type_node = constructor_parameter_type_node(right, &source, || true)?;
            let mut arms = resolve_php_type_arms(node_text(type_node, &source), ctx);
            (arms.len() == 1).then(|| arms.remove(0))
        },
    )
    .or_else(|| {
        infer_static_assigned_field_type(
            declaration,
            &source,
            field.identifier(),
            || true,
            |right| {
                let right = unwrap_parenthesized(right);
                let type_node = (right.kind() == "object_creation_expression")
                    .then(|| object_creation_type(right))
                    .flatten()?;
                static_scope_type_fq_name(
                    php,
                    analyzer,
                    node_text(type_node, &source),
                    ctx,
                    Some(owner.fq_name().as_str()),
                )
            },
        )
    })
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
            return node_text(name, source)
                .eq_ignore_ascii_case("__construct")
                .then_some(parameter);
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
    mut step: F,
) -> Option<Node<'tree>>
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
            return parameter.child_by_field_name("type");
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
    let declared = parameters.named_children(&mut cursor).any(|parameter| {
        step()
            && matches!(
                parameter.kind(),
                "simple_parameter" | "property_promotion_parameter"
            )
            && parameter
                .child_by_field_name("name")
                .is_some_and(|name| variable_identifier(name, source) == parameter_name)
    });
    if !declared {
        return None;
    }
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

/// Locate the declaring class for one field declaration without interpreting
/// source text. The owner name and indexed field range jointly disambiguate
/// repeated short class names in the same file.
pub fn enclosing_class_declaration_for_field<'tree, F>(
    root: Node<'tree>,
    source: &str,
    owner: &CodeUnit,
    ranges: &[Range],
    mut step: F,
) -> Option<Node<'tree>>
where
    F: FnMut() -> bool,
{
    let mut candidates = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !step() {
            return None;
        }
        if node.kind() == "class_declaration"
            && node
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == owner.identifier())
            && ranges.iter().any(|range| {
                node.start_byte() <= range.start_byte && range.end_byte <= node.end_byte()
            })
        {
            candidates.push(node);
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if !step() {
                return None;
            }
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    let [candidate] = candidates.as_slice() else {
        return None;
    };
    Some(*candidate)
}

/// Fold all structured writes to one `$this` field into a single constructor
/// type. The traversal is iterative because generated PHP classes can be deep.
pub fn infer_constructor_assigned_field_type<'tree, F, R>(
    class: Node<'tree>,
    source: &str,
    field_name: &str,
    mut step: F,
    mut resolve_value: R,
) -> Option<String>
where
    F: FnMut() -> bool,
    R: FnMut(Node<'tree>) -> Option<String>,
{
    let mut inferred = None;
    let mut stack = vec![class];
    while let Some(node) = stack.pop() {
        if !step() {
            return None;
        }
        if let Some((left, right)) = assignment_parts(node)
            && this_field_name(left, source) == Some(field_name)
        {
            if !assignment_is_directly_in_constructor(node, source, class, &mut step) {
                return None;
            }
            let value = resolve_value(right)?;
            if inferred.as_ref().is_some_and(|known| known != &value) {
                return None;
            }
            inferred = Some(value);
        }
        for index in (0..node.named_child_count()).rev() {
            if !step() {
                return None;
            }
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    inferred
}

/// Fold all structured writes to one `self::$field`/`static::$field` into a
/// single type. Unlike instance-property recovery, these writes may occur in
/// any method because a static property's storage is shared; every explicit
/// write in the class must still be a consistent resolvable construction.
pub fn infer_static_assigned_field_type<'tree, F, R>(
    class: Node<'tree>,
    source: &str,
    field_name: &str,
    mut step: F,
    mut resolve_value: R,
) -> Option<String>
where
    F: FnMut() -> bool,
    R: FnMut(Node<'tree>) -> Option<String>,
{
    let mut inferred = None;
    let mut stack = vec![class];
    while let Some(node) = stack.pop() {
        if !step() {
            return None;
        }
        if let Some((left, right)) = assignment_parts(node)
            && static_self_field_name(left, source) == Some(field_name)
        {
            let value = resolve_value(right)?;
            if inferred.as_ref().is_some_and(|known| known != &value) {
                return None;
            }
            inferred = Some(value);
        }
        for index in (0..node.named_child_count()).rev() {
            if !step() {
                return None;
            }
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    inferred
}

/// Fold every indexed write to one `$this->field[...]` collection into one
/// element type. Direct container initialization does not describe an element
/// and is ignored; each actual element write must have a resolvable value and
/// all such values must agree. Nested class declarations are separate `$this`
/// domains and are not traversed.
pub fn infer_indexed_field_element_type<'tree, F, R>(
    class: Node<'tree>,
    source: &str,
    field_name: &str,
    mut step: F,
    mut resolve_value: R,
) -> Option<String>
where
    F: FnMut() -> bool,
    R: FnMut(Node<'tree>) -> Option<String>,
{
    let mut inferred = None;
    let mut stack = vec![class];
    while let Some(node) = stack.pop() {
        if !step() {
            return None;
        }
        if node != class && node.kind() == "class_declaration" {
            continue;
        }
        if let Some((left, right)) = assignment_parts(node)
            && left.kind() == "subscript_expression"
            && left
                .named_child(0)
                .is_some_and(|collection| this_field_name(collection, source) == Some(field_name))
        {
            let value = resolve_value(right)?;
            if inferred.as_ref().is_some_and(|known| known != &value) {
                return None;
            }
            inferred = Some(value);
        }
        for index in (0..node.named_child_count()).rev() {
            if !step() {
                return None;
            }
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    inferred
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
    let mut stack = vec![scope];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= before_byte {
            continue;
        }
        if node != scope && is_local_scope(node) {
            continue;
        }
        if let Some((left, right)) = assignment_parts(node) {
            if left.kind() == "variable_name"
                && variable_identifier(left, source) == collection_name
            {
                let right = unwrap_parenthesized(right);
                if right.kind() != "array_creation_expression" || right.named_child_count() != 0 {
                    return None;
                }
            } else if left.kind() == "subscript_expression"
                && left.named_child(0).is_some_and(|base| {
                    base.kind() == "variable_name"
                        && variable_identifier(base, source) == collection_name
                })
            {
                let value = resolve_value(right)?;
                if inferred.as_ref().is_some_and(|known| known != &value) {
                    return None;
                }
                inferred = Some(value);
            }
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    inferred
}

fn this_field_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
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

fn static_self_field_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "scoped_property_access_expression" {
        return None;
    }
    let (scope, name) = static_member_parts(node)?;
    let scope = node_text(scope, source);
    ((scope.eq_ignore_ascii_case("self") || scope.eq_ignore_ascii_case("static"))
        && name.kind() == "variable_name")
        .then(|| variable_identifier(name, source))
}

fn assignment_is_directly_in_constructor<F>(
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
                .is_some_and(|name| node_text(name, source).eq_ignore_ascii_case("__construct"));
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
        .or_else(|| signature_declared_type_fq_name(php, analyzer, callable))
        .or_else(|| phpdoc_declared_type_fact_fq_name(php, callable, phpdoc_return_nominal_type))
}

pub fn declared_callable_return_element_type_fq_name(
    php: &dyn PhpSource,
    callable: &CodeUnit,
) -> Option<String> {
    if !callable.is_function() {
        return None;
    }
    phpdoc_declared_type_fact_fq_name(php, callable, phpdoc_return_element_type)
}

fn phpdoc_declared_type_fact_fq_name<F>(
    php: &dyn PhpSource,
    unit: &CodeUnit,
    fact: F,
) -> Option<String>
where
    F: FnOnce(&str) -> Option<String>,
{
    let source = php.project().read_source(unit.source()).ok()?;
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    let tree = parser.parse(source.as_str(), None)?;
    let declaration = declaration_node_for_unit(
        tree.root_node(),
        &source,
        unit,
        php.ranges(unit).as_slice(),
        || true,
    )?;
    let raw = fact(declaration_doc_comment(declaration, &source)?)?;
    let contexts = PhpFileContextIndex::from_tree(tree.root_node(), &source, || true)?;
    let ctx = contexts.context_at(declaration.start_byte());
    resolve_php_type(&raw, ctx)
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
    match collection.kind() {
        "variable_name" => infer_indexed_local_element_type(
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
                )
            },
        ),
        "member_access_expression" | "nullsafe_member_access_expression" => {
            let object = collection.child_by_field_name("object")?;
            if object.kind() != "variable_name" || variable_identifier(object, source) != "this" {
                return None;
            }
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
        "member_call_expression" | "nullsafe_member_call_expression" => {
            let object = collection.child_by_field_name("object")?;
            let owner = instance_receiver_type_fq_name_inner(
                php,
                analyzer,
                object,
                source,
                ctx,
                bindings,
                enclosing_owner,
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
        _ => None,
    }
}

/// Locate one callable or field declaration using its indexed name ranges.
pub fn declaration_node_for_unit<'tree, F>(
    root: Node<'tree>,
    source: &str,
    unit: &CodeUnit,
    ranges: &[Range],
    mut step: F,
) -> Option<Node<'tree>>
where
    F: FnMut() -> bool,
{
    let mut candidates = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !step() {
            return None;
        }
        let name = match node.kind() {
            "function_definition" | "method_declaration" if unit.is_function() => {
                node.child_by_field_name("name")
            }
            "property_promotion_parameter" if unit.is_field() => node.child_by_field_name("name"),
            _ => None,
        };
        if let Some(name) = name
            && variable_identifier(name, source) == unit.identifier()
            && ranges.iter().any(|range| {
                node.start_byte() <= range.start_byte && range.end_byte <= node.end_byte()
            })
        {
            candidates.push(node);
            continue;
        }
        if node.kind() == "property_declaration" && unit.is_field() {
            let mut cursor = node.walk();
            let matches = node.named_children(&mut cursor).any(|element| {
                step()
                    && element.kind() == "property_element"
                    && element
                        .child_by_field_name("name")
                        .is_some_and(|name| variable_identifier(name, source) == unit.identifier())
                    && ranges.iter().any(|range| {
                        node.start_byte() <= range.start_byte && range.end_byte <= node.end_byte()
                    })
            });
            if matches {
                candidates.push(node);
                continue;
            }
        }
        for index in (0..node.named_child_count()).rev() {
            if !step() {
                return None;
            }
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    let [candidate] = candidates.as_slice() else {
        return None;
    };
    Some(*candidate)
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
    )
}

fn instance_receiver_type_fq_name_inner(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    root: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    bindings: &LocalInferenceEngine<String>,
    enclosing_owner: &mut dyn FnMut(usize, usize) -> Option<String>,
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
                            collection_element_type_fq_name(
                                php,
                                analyzer,
                                collection,
                                source,
                                ctx,
                                bindings,
                                enclosing_owner,
                            )
                            .or_else(|| {
                                foreach_value_reassigned_before(node, source)
                                    .then(|| match bindings.resolve_symbol(name) {
                                        SymbolResolution::Precise(targets)
                                            if targets.len() == 1 =>
                                        {
                                            targets.into_iter().next()
                                        }
                                        SymbolResolution::Unknown
                                        | SymbolResolution::Ambiguous
                                        | SymbolResolution::Precise(_) => None,
                                    })
                                    .flatten()
                            })
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
                            collection_element_type_fq_name(
                                php,
                                analyzer,
                                collection,
                                source,
                                ctx,
                                bindings,
                                enclosing_owner,
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
                        if let Some(value) = collection_element_type_fq_name(
                            php,
                            analyzer,
                            collection,
                            source,
                            ctx,
                            bindings,
                            enclosing_owner,
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
                        let dependency = if matches!(
                            node.kind(),
                            "parenthesized_expression" | "clone_expression"
                        ) {
                            node.named_child(0)
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

        let dependency = if matches!(node.kind(), "parenthesized_expression" | "clone_expression") {
            node.named_child(0)
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
        .definitions(&format!("{owner_fq_name}.{member}"))
        .filter(wanted)
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
        .flat_map(|owner| php.get_direct_ancestors(owner))
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
                .definitions(&format!("{ancestor_fq_name}.{member}"))
                .filter(wanted);
            for definition in definitions {
                families
                    .entry(definition.fq_name())
                    .or_default()
                    .push(definition);
            }
            next_level.extend(php.get_direct_ancestors(&ancestor));
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

/// Every class the declared type of one field or callable names.
///
/// This is the arms-aware form of [`declared_field_type_fq_name`] and
/// [`declared_callable_return_type_fq_name`], for the one surface that can
/// carry bounded ambiguity (forward definition lookup). A union declaration
/// yields one entry per arm; every other declaration yields at most one.
pub fn declared_type_arm_fq_names(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    unit: &CodeUnit,
) -> Vec<String> {
    declared_type_of(php, analyzer, unit).arms()
}

/// What the declared type of one field or callable proves, including the case
/// where it proves the value is dynamic (`object`/`mixed`) rather than nothing.
///
/// [`declared_type_arm_fq_names`] is this computation read for its classes
/// only; forward definition lookup reads the whole answer so it can tell a
/// proven-dynamic declaration from one it does not follow (#2030).
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
    let signature = signature_declared_type(php, analyzer, unit);
    if signature != PhpDeclaredType::Unknown {
        return signature;
    }
    if unit.is_field() {
        return PhpDeclaredType::nominal(
            phpdoc_declared_type_fact_fq_name(php, unit, phpdoc_var_nominal_type)
                .into_iter()
                .collect(),
        );
    }
    PhpDeclaredType::nominal(
        phpdoc_declared_type_fact_fq_name(php, unit, phpdoc_return_nominal_type)
            .into_iter()
            .collect(),
    )
}

fn signature_declared_type_fq_name(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    unit: &CodeUnit,
) -> Option<String> {
    let mut arms = signature_declared_type(php, analyzer, unit).arms();
    (arms.len() == 1).then(|| arms.remove(0))
}

fn signature_declared_type(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    unit: &CodeUnit,
) -> PhpDeclaredType {
    let signatures = analyzer.index.signatures(unit);
    let Some(raw) = signatures
        .iter()
        .find_map(|signature| php_signature_return_type_text(signature))
    else {
        return PhpDeclaredType::Unknown;
    };
    if let Some(keyword) = php_dynamic_type_keyword(raw) {
        return PhpDeclaredType::Dynamic(keyword);
    }
    if matches!(raw, "self" | "static") {
        return PhpDeclaredType::nominal(
            php.parent_of(unit)
                .map(|owner| owner.fq_name())
                .into_iter()
                .collect(),
        );
    }
    let Ok(source) = unit.source().read_to_string() else {
        return PhpDeclaredType::Unknown;
    };
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .is_err()
    {
        return PhpDeclaredType::Unknown;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return PhpDeclaredType::Unknown;
    };
    let Some(contexts) = PhpFileContextIndex::from_tree(tree.root_node(), &source, || true) else {
        return PhpDeclaredType::Unknown;
    };
    let Some(declaration) = declaration_node_for_unit(
        tree.root_node(),
        &source,
        unit,
        php.ranges(unit).as_slice(),
        || true,
    ) else {
        return PhpDeclaredType::Unknown;
    };
    let ctx = contexts.context_at(declaration.start_byte());
    PhpDeclaredType::nominal(resolve_php_type_arms(raw, ctx))
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
    use tree_sitter::{Node, Parser};

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .expect("PHP grammar");
        parser.parse(source, None).expect("PHP tree")
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
