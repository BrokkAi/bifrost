use tree_sitter::Node;
use tree_sitter::Tree;

use crate::analyzer::reference_candidates::reference_candidate_requires_point_lookup;

use crate::analyzer::structural::FileFacts;
use crate::analyzer::structural::NormalizedKind;
use crate::analyzer::structural::Role;

use crate::analyzer::usages::range_for_span;

use crate::analyzer::Language;
use crate::analyzer::ProjectFile;
use crate::analyzer::Range;

use brokk_bifrost_core::analyzer::usages::reference_site::node_range;

use super::parse_tree_for_language;

use crate::analyzer::common::language_for_file;

use brokk_bifrost_ruby::graph::syntax::is_call_method_identifier as ruby_is_call_method_identifier;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallSignatureContext {
    pub callee_range: Range,
    pub active_parameter: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallSyntaxKind {
    Function,
    Method,
    Constructor,
    Super,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct CallArgumentSyntax {
    #[doc(hidden)]
    pub range: Range,
    #[doc(hidden)]
    pub name: Option<String>,
    #[doc(hidden)]
    pub position: Option<usize>,
    #[doc(hidden)]
    pub spread: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct CallSiteSyntax {
    #[doc(hidden)]
    pub range: Range,
    #[doc(hidden)]
    pub callee_range: Range,
    #[doc(hidden)]
    pub receiver: Option<Range>,
    #[doc(hidden)]
    pub arguments: Vec<CallArgumentSyntax>,
    #[doc(hidden)]
    pub kind: CallSyntaxKind,
}

/// Structured result of mapping one exact whole-call span to its dispatch
/// reference. Some call expressions do not name a statically resolvable
/// declaration; retaining that shape keeps exact dispatch from degrading them
/// to an `InvalidLocation` parse failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExactCallReference {
    Resolvable(Range),
    Unsupported(ExactCallReferenceGap),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExactCallReferenceGap {
    /// `proc.(value)` invokes the value held by the receiver. Resolving its
    /// target requires value/heap information rather than a method-name lookup.
    RubyCallableObject,
    /// The callee is a value expression, not a declaration name.
    CallOfValue,
}

#[doc(hidden)]
pub fn call_reference_ranges_in_tree(
    tree: &Tree,
    language: Language,
    search_range: &Range,
    limit: usize,
) -> Vec<Range> {
    collect_call_reference_ranges(tree.root_node(), language, search_range, limit)
}

/// Resolve one exact whole-call source span to the precise reference token
/// that names its callee.
///
/// Semantic CFG call sites are anchored to the complete call expression, not
/// merely its callee token.  Matching the complete node range first is what
/// keeps nested calls such as `outer(inner())` unambiguous: the outer and inner
/// calls have different exact spans even when a cursor-based lookup would land
/// inside both.  Callee selection remains tree-sitter-structured through the
/// language's named fields and call-reference predicate.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn call_reference_range_for_call(
    tree: &Tree,
    language: Language,
    call_span: &Range,
) -> Option<Range> {
    match exact_call_reference_for_call(tree, language, call_span)? {
        ExactCallReference::Resolvable(range) => Some(range),
        ExactCallReference::Unsupported(_) => None,
    }
}

pub(crate) fn exact_call_reference_for_call(
    tree: &Tree,
    language: Language,
    call_span: &Range,
) -> Option<ExactCallReference> {
    if call_span.start_byte >= call_span.end_byte {
        return None;
    }
    let mut node = tree
        .root_node()
        .named_descendant_for_byte_range(call_span.start_byte, call_span.end_byte)?;
    loop {
        if node.start_byte() == call_span.start_byte && node.end_byte() == call_span.end_byte {
            // A Ruby implicit-receiver call without arguments has no `call`
            // wrapper in tree-sitter; its complete expression is the
            // identifier itself. Semantic lowering has already classified the
            // exact span as a call after accounting for parser-ordered lexical
            // locals. Legacy outgoing discovery keeps its narrower structural
            // classification for body-statement bare calls.
            if language == Language::Ruby && ruby_exact_bare_call_identifier(node) {
                return Some(ExactCallReference::Resolvable(node_range(node)));
            }
            if is_call_expression_node(node, language) {
                if language == Language::Ruby && ruby_callable_object_call(node) {
                    return Some(ExactCallReference::Unsupported(
                        ExactCallReferenceGap::RubyCallableObject,
                    ));
                }
                let callee = callee_node_for_call(node, language)?;
                return Some(match call_reference_leaf(callee, language) {
                    Some(leaf) => ExactCallReference::Resolvable(node_range(leaf)),
                    None if matches!(
                        language,
                        Language::Go | Language::Java | Language::Kotlin | Language::Scala
                    ) =>
                    {
                        return None;
                    }
                    None => ExactCallReference::Unsupported(ExactCallReferenceGap::CallOfValue),
                });
            }
        }
        let parent = node.parent()?;
        if parent.start_byte() != call_span.start_byte || parent.end_byte() != call_span.end_byte {
            return None;
        }
        node = parent;
    }
}

/// Map a reverse site's whole-call span or exact callee span to the same
/// cache key used by forward dispatch. An arbitrary operand inside a call
/// cannot qualify: the site's range must equal the call or its callee leaf.
#[doc(hidden)]
pub fn exact_call_reference_for_reverse_site(
    tree: &Tree,
    language: Language,
    site: &Range,
) -> Option<Range> {
    if let Some(ExactCallReference::Resolvable(range)) =
        exact_call_reference_for_call(tree, language, site)
    {
        return Some(range);
    }
    let mut node = tree
        .root_node()
        .named_descendant_for_byte_range(site.start_byte, site.end_byte)?;
    loop {
        if is_call_expression_node(node, language)
            && let Some(ExactCallReference::Resolvable(range)) =
                exact_call_reference_for_call(tree, language, &node_range(node))
            && (range.start_byte, range.end_byte) == (site.start_byte, site.end_byte)
        {
            return Some(range);
        }
        node = node.parent()?;
    }
}

pub(crate) fn is_call_reference_range_in_tree(
    tree: &Tree,
    language: Language,
    start_byte: usize,
    end_byte: usize,
) -> bool {
    let Some(node) = tree
        .root_node()
        .named_descendant_for_byte_range(start_byte, end_byte)
    else {
        return false;
    };
    is_call_reference_candidate(node, language)
}

/// Some C++ callable names are composite grammar nodes beginning with the
/// identifier token `operator`. The general definition-location contract
/// rejects a byte range extending beyond that first token, so dispatch uses a
/// point request while retaining the full structured callee range as its call
/// identity.
pub(crate) fn call_reference_requires_point_lookup(
    tree: &Tree,
    language: Language,
    range: &Range,
) -> bool {
    reference_candidate_requires_point_lookup(tree.root_node(), language, range)
}

/// Whether an exact reference range is a call's keyword-argument label.
///
/// A named argument's label names a parameter of the callee, so an analyzer
/// that resolves the label reports a reference to the callable. The label is
/// still not a call site: the call's own name span is elsewhere. Call-relation
/// projection reads that distinction from the structural facts instead of
/// treating the label as a call whose syntax could not be read.
pub(crate) fn range_is_call_keyword_label(
    facts: &FileFacts,
    start_byte: usize,
    end_byte: usize,
) -> bool {
    facts
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| node.kind.satisfies(NormalizedKind::Call))
        .any(|(call_id, _)| {
            facts.roles(call_id as u32).iter().any(|target| {
                target.role == Role::Kwarg
                    && target.keyword.is_some_and(|keyword| {
                        keyword.start_byte <= start_byte && end_byte <= keyword.end_byte
                    })
            })
        })
}

#[doc(hidden)]
pub fn call_site_syntax_for_reference(
    facts: &FileFacts,
    start_byte: usize,
    end_byte: usize,
) -> Option<CallSiteSyntax> {
    let (call_id, call) = facts
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| node.kind.satisfies(NormalizedKind::Call))
        .filter(|(_, node)| {
            node.name
                .is_some_and(|name| name.start_byte <= start_byte && end_byte <= name.end_byte)
        })
        .min_by_key(|(_, node)| node.range.end_byte.saturating_sub(node.range.start_byte))?;
    let call_id = call_id as u32;
    let callee = call.name?;
    let receiver = facts
        .role_targets(call_id, Role::Receiver)
        .next()
        .map(|target| range_for_span(facts, target.span));
    let mut position = 0;
    let arguments = facts
        .roles(call_id)
        .iter()
        .filter_map(|target| match target.role {
            Role::Arg => {
                let current = position;
                position += 1;
                Some(CallArgumentSyntax {
                    range: range_for_span(facts, target.span),
                    name: None,
                    position: Some(current),
                    spread: target.spread,
                })
            }
            Role::Kwarg => Some(CallArgumentSyntax {
                range: range_for_span(facts, target.span),
                name: target
                    .keyword
                    .map(|keyword| keyword.text(facts.source()).to_owned()),
                position: None,
                spread: target.spread,
            }),
            _ => None,
        })
        .collect();
    let kind = match receiver {
        Some(range)
            if matches!(
                facts.source().get(range.start_byte..range.end_byte),
                Some("super" | "base")
            ) =>
        {
            CallSyntaxKind::Super
        }
        Some(_) => CallSyntaxKind::Method,
        None => CallSyntaxKind::Function,
    };
    Some(CallSiteSyntax {
        range: call.range,
        callee_range: range_for_span(facts, callee),
        receiver,
        arguments,
        kind,
    })
}

pub fn call_signature_context(
    file: &ProjectFile,
    source: &str,
    byte_offset: usize,
) -> Option<CallSignatureContext> {
    let language = language_for_file(file);
    let tree = parse_tree_for_language(file, language, source)?;
    find_innermost_call_signature_context(tree.root_node(), language, source, byte_offset)
}

fn find_innermost_call_signature_context(
    root: Node<'_>,
    language: Language,
    source: &str,
    byte_offset: usize,
) -> Option<CallSignatureContext> {
    let mut best: Option<(usize, CallSignatureContext)> = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() > byte_offset || node.end_byte() < byte_offset {
            continue;
        }
        if let Some(context) = call_signature_context_for_node(node, language, source, byte_offset)
        {
            let width = node.end_byte().saturating_sub(node.start_byte());
            if best.is_none_or(|(best_width, _)| width < best_width) {
                best = Some((width, context));
            }
        }
        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        for child in children {
            stack.push(child);
        }
    }
    best.map(|(_, context)| context)
}

fn call_signature_context_for_node(
    node: Node<'_>,
    language: Language,
    source: &str,
    byte_offset: usize,
) -> Option<CallSignatureContext> {
    if language == Language::Scala
        && let Some(context) = crate::analyzer::languages::language_support(language)
            .and_then(|support| support.definition_call_signature_context(node, byte_offset))
    {
        return Some(context);
    }
    if language == Language::Rust && node.kind() == "macro_invocation" {
        return None;
    }
    if !is_call_expression_node(node, language) {
        return None;
    }
    let argument_nodes = argument_nodes_for_call(node, language);
    let [arguments] = argument_nodes.as_slice() else {
        return None;
    };
    let arguments = *arguments;
    if byte_offset < arguments.start_byte() || byte_offset > arguments.end_byte() {
        return None;
    }
    let callee = callee_node_for_call(node, language)?;
    if callee_argument_gap_has_completed_call(callee, arguments, source) {
        return None;
    }
    if is_call_expression_node(callee, language) || contains_call_expression_node(callee, language)
    {
        return None;
    }
    let callee_reference = call_reference_leaf(callee, language)?;
    Some(CallSignatureContext {
        callee_range: node_range(callee_reference),
        active_parameter: active_parameter(arguments, byte_offset),
    })
}

#[doc(hidden)]
pub fn is_call_expression_node(node: Node<'_>, language: Language) -> bool {
    match language {
        Language::Java => matches!(
            node.kind(),
            "method_invocation" | "object_creation_expression"
        ),
        Language::Go => node.kind() == "call_expression",
        Language::Cpp => matches!(node.kind(), "call_expression" | "new_expression"),
        Language::JavaScript | Language::TypeScript => {
            matches!(node.kind(), "call_expression" | "new_expression")
        }
        Language::Python => node.kind() == "call",
        Language::Rust => matches!(node.kind(), "call_expression" | "macro_invocation"),
        Language::Php => matches!(
            node.kind(),
            "function_call_expression"
                | "member_call_expression"
                | "nullsafe_member_call_expression"
                | "scoped_call_expression"
                | "object_creation_expression"
        ),
        Language::Scala => matches!(
            node.kind(),
            "call_expression" | "instance_expression" | "infix_expression" | "postfix_expression"
        ),
        Language::CSharp => matches!(
            node.kind(),
            "invocation_expression" | "object_creation_expression"
        ),
        Language::Ruby => node.kind() == "call",
        Language::Kotlin => matches!(node.kind(), "call_expression" | "constructor_invocation"),
        Language::None => false,
    }
}

#[doc(hidden)]
pub fn callee_node_for_call<'tree>(node: Node<'tree>, language: Language) -> Option<Node<'tree>> {
    match language {
        Language::Rust if node.kind() == "macro_invocation" => node.child_by_field_name("macro"),
        Language::Java => node
            .child_by_field_name("name")
            .or_else(|| node.child_by_field_name("type")),
        Language::JavaScript | Language::TypeScript if node.kind() == "new_expression" => node
            .child_by_field_name("constructor")
            .or_else(|| node.child_by_field_name("function")),
        Language::CSharp => node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("type")),
        Language::Cpp => match node.kind() {
            "call_expression" => {
                cpp_explicit_operator_name(node).or_else(|| node.child_by_field_name("function"))
            }
            "new_expression" => node
                .child_by_field_name("type")
                .or_else(|| first_named_child_not_arguments(node, language)),
            _ => None,
        },
        Language::Scala => crate::analyzer::languages::language_support(Language::Scala)?
            .definition_call_callee(node),
        Language::Kotlin => {
            crate::analyzer::languages::language_knowledge(language)?.call_callee_node(node)
        }
        Language::Ruby => node.child_by_field_name("method"),
        _ => node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.child_by_field_name("type"))
            .or_else(|| first_named_child_not_arguments(node, language)),
    }
}

fn arguments_node_for_call(node: Node<'_>, language: Language) -> Option<Node<'_>> {
    argument_nodes_for_call(node, language).into_iter().next()
}

fn argument_nodes_for_call(node: Node<'_>, language: Language) -> Vec<Node<'_>> {
    // A language whose argument list neither the field lookup nor the shared child-kind
    // list below can reach answers here instead, and its answer is the whole answer.
    if let Some(nodes) = crate::analyzer::languages::language_knowledge(language)
        .and_then(|support| support.call_argument_nodes(node))
    {
        return nodes;
    }
    let mut nodes = Vec::new();
    if let Some(arguments) = node
        .child_by_field_name("arguments")
        .or_else(|| node.child_by_field_name("argument"))
    {
        nodes.push(arguments);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(
            child.kind(),
            "arguments"
                | "argument"
                | "argument_list"
                | "argument_clause"
                | "arguments_list"
                | "block"
        ) && !nodes.contains(&child)
            && !(language == Language::Ruby && matches!(child.kind(), "block" | "do_block"))
        {
            nodes.push(child);
        }
    }
    nodes
}

fn first_named_child_not_arguments(node: Node<'_>, language: Language) -> Option<Node<'_>> {
    let arguments = arguments_node_for_call(node, language);
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| Some(*child) != arguments)
}

pub(crate) fn scala_constructor_type_node(node: Node<'_>) -> Option<Node<'_>> {
    let arguments = node.child_by_field_name("arguments");
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|child| {
        Some(*child) != arguments && !matches!(child.kind(), "arguments" | "template_body")
    })
}

pub(crate) fn scala_terminal_callee_leaf(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        node = match node.kind() {
            "identifier" | "operator_identifier" | "type_identifier" => return Some(node),
            "call_expression" | "infix_expression" | "postfix_expression" => {
                crate::analyzer::languages::language_support(Language::Scala)?
                    .definition_call_callee(node)?
            }
            "instance_expression" => scala_constructor_type_node(node)?,
            "generic_function" | "generic_type" => node
                .child_by_field_name("function")
                .or_else(|| node.child_by_field_name("type"))?,
            "field_expression" => node.child_by_field_name("field")?,
            "projected_type" => node.child_by_field_name("selector")?,
            "stable_identifier" | "stable_type_identifier" => {
                let mut cursor = node.walk();
                node.named_children(&mut cursor).last()?
            }
            "annotated_type" | "applied_constructor_type" | "parenthesized_expression" => {
                let mut cursor = node.walk();
                let mut children = node
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() != "arguments");
                let child = children.next()?;
                if children.next().is_some() {
                    return None;
                }
                child
            }
            _ => return None,
        };
    }
}

fn call_reference_leaf(node: Node<'_>, language: Language) -> Option<Node<'_>> {
    if !matches!(
        language,
        Language::Go | Language::Java | Language::Kotlin | Language::Scala
    ) {
        return terminal_callee_leaf(node, language);
    }
    // #5019 follow-up: Go and JVM resolution are being rewritten concurrently.
    // Preserve their existing descendant selection until that work owns the spine.
    if node.named_child_count() == 0 {
        return is_call_reference_candidate(node, language).then_some(node);
    }
    let mut best = None;
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.named_child_count() == 0 && is_call_reference_candidate(current, language) {
            best = Some(current);
            continue;
        }
        let mut cursor = current.walk();
        let mut children: Vec<_> = current.named_children(&mut cursor).collect();
        children.reverse();
        for child in children {
            stack.push(child);
        }
    }
    best
}

/// Exact dispatch and structural call facts share the same callee spine.
#[doc(hidden)]
pub fn terminal_callee_leaf(node: Node<'_>, language: Language) -> Option<Node<'_>> {
    use brokk_bifrost_core::analyzer::structural::adapter_helpers::terminal_callee_leaf as follow_spine;
    let hook = match language {
        Language::Cpp => brokk_bifrost_cpp::structural::callee_spine_step,
        Language::Python => brokk_bifrost_python::structural::callee_spine_step,
        Language::JavaScript | Language::TypeScript => {
            brokk_bifrost_js_ts::structural::callee_spine_step
        }
        Language::Rust => brokk_bifrost_rust::structural::callee_spine_step,
        Language::CSharp => brokk_bifrost_csharp::structural::callee_spine_step,
        Language::Php => brokk_bifrost_php::structural::callee_spine_step,
        Language::Ruby => brokk_bifrost_ruby::structural::callee_spine_step,
        _ => return None,
    };
    follow_spine(node, hook)
}

fn contains_call_expression_node(node: Node<'_>, language: Language) -> bool {
    let mut stack = Vec::new();
    let mut cursor = node.walk();
    stack.extend(node.named_children(&mut cursor));
    while let Some(current) = stack.pop() {
        if is_call_expression_node(current, language) {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn callee_argument_gap_has_completed_call(
    callee: Node<'_>,
    arguments: Node<'_>,
    source: &str,
) -> bool {
    if callee.end_byte() >= arguments.start_byte() {
        return false;
    }
    source
        .get(callee.end_byte()..arguments.start_byte())
        .is_some_and(|gap| gap.contains(')'))
}

fn active_parameter(arguments: Node<'_>, byte_offset: usize) -> u32 {
    let mut active = 0;
    let mut cursor = arguments.walk();
    for child in arguments.named_children(&mut cursor) {
        if child.end_byte() < byte_offset {
            active += 1;
        }
    }
    active
}

fn collect_call_reference_ranges(
    root: Node<'_>,
    language: Language,
    search_range: &Range,
    limit: usize,
) -> Vec<Range> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if out.len() >= limit {
            break;
        }
        if node.end_byte() <= search_range.start_byte || node.start_byte() >= search_range.end_byte
        {
            continue;
        }
        if is_nested_callable_node(node, language, search_range) {
            continue;
        }
        if language == Language::Cpp
            && cpp_composite_call_name(node)
            && is_call_reference_candidate(node, language)
            && node.start_byte() >= search_range.start_byte
            && node.end_byte() <= search_range.end_byte
            && node.start_byte() < node.end_byte()
        {
            out.push(node_range(node));
            continue;
        }
        if node.named_child_count() == 0 {
            if is_call_reference_candidate(node, language)
                && node.start_byte() >= search_range.start_byte
                && node.end_byte() <= search_range.end_byte
                && node.start_byte() < node.end_byte()
            {
                out.push(Range {
                    start_byte: node.start_byte(),
                    end_byte: node.end_byte(),
                    start_line: node.start_position().row,
                    end_line: node.end_position().row,
                });
            }
            continue;
        }
        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        for child in children {
            stack.push(child);
        }
    }
    out.sort_by_key(|range| (range.start_byte, range.end_byte));
    out.dedup_by_key(|range| (range.start_byte, range.end_byte));
    out
}

fn is_nested_callable_node(node: Node<'_>, language: Language, search_range: &Range) -> bool {
    if node.start_byte() <= search_range.start_byte || node.end_byte() >= search_range.end_byte {
        return false;
    }
    if crate::analyzer::languages::language_support(language)
        .is_some_and(|support| support.definition_nested_callable(node))
    {
        return true;
    }
    if language == Language::Ruby && ruby_nested_callable_node(node) {
        return true;
    }
    matches!(
        node.kind(),
        "function_declaration"
            | "function_definition"
            | "method_declaration"
            | "constructor_declaration"
            | "method_definition"
            | "function_expression"
            | "arrow_function"
            | "lambda_expression"
            | "lambda"
            | "func_literal"
            | "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "class_definition"
            | "method"
            | "singleton_method"
            | "module"
            | "struct_declaration"
            | "union_declaration"
            | "trait_item"
            | "impl_item"
            | "object_definition"
    )
}

fn ruby_nested_callable_node(node: Node<'_>) -> bool {
    match node.kind() {
        // The block nested directly under `lambda` is the lambda's body, not
        // a second callable. Attached blocks and do-blocks are independently
        // invoked Ruby closures and must not leak their calls into the method
        // or initializer that creates them.
        "block" | "do_block" => node.parent().is_none_or(|parent| parent.kind() != "lambda"),
        // Ruby type and singleton-class bodies execute in their own semantic
        // initializer contexts. The leading range guard above still permits a
        // query rooted at one of these exact nodes to traverse its own body.
        "class" | "singleton_class" => true,
        // BEGIN/END bodies execute at load/exit lifecycle boundaries. They are
        // represented by semantic gaps, not as calls of the lexically
        // surrounding method or type initializer.
        "begin_block" | "end_block" => true,
        _ => false,
    }
}

fn is_call_reference_candidate(node: Node<'_>, language: Language) -> bool {
    let php_relative_constructor_scope =
        language == Language::Php && node.kind() == "relative_scope";
    if !is_reference_candidate_kind(node.kind()) && !php_relative_constructor_scope {
        return false;
    }
    match language {
        // #4452: Kotlin stays on its held definition route.
        Language::Kotlin => super::kotlin::kotlin_call_reference_candidate(node),
        _ => crate::analyzer::languages::language_support(language)
            .is_some_and(|support| support.definition_call_reference_candidate(node)),
    }
}

fn is_reference_candidate_kind(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "type_identifier"
            | "field_identifier"
            | "property_identifier"
            | "constant"
            | "scope_resolution"
            | "simple_identifier"
            | "scoped_identifier"
            | "namespace_identifier"
            | "variable_name"
            | "name"
            | "simple_name"
            | "identifier_token"
            | "operator_identifier"
            | "operator"
            | "operator_name"
            | "operator_cast"
            | "destructor_name"
            | "literal_operator_name"
    )
}

fn cpp_composite_call_name(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "operator_name" | "operator_cast" | "destructor_name" | "literal_operator_name"
    )
}

/// The C++ grammar currently recovers an explicitly named operator call such
/// as `value.operator+(1)` as a normal call whose `function` field is the
/// receiver plus an adjacent `ERROR(operator_name)` node. Retain the parser's
/// structured operator node instead of treating the receiver as the callee.
fn cpp_explicit_operator_name(call: Node<'_>) -> Option<Node<'_>> {
    if call.kind() != "call_expression" {
        return None;
    }
    let arguments = call.child_by_field_name("arguments");
    let mut cursor = call.walk();
    let errors = call
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "ERROR" && Some(*child) != arguments);
    for error in errors {
        let mut stack = vec![error];
        while let Some(node) = stack.pop() {
            if cpp_composite_call_name(node) {
                return Some(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
    }
    None
}

pub(crate) fn enclosing_call_reference_candidate<'tree>(
    node: Node<'tree>,
    is_call_target: impl Fn(Node<'tree>, Node<'tree>) -> bool,
    is_transparent_wrapper: impl Fn(Node<'tree>) -> bool,
) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if is_call_target(parent, current) {
            return true;
        }
        if is_transparent_wrapper(parent) {
            current = parent;
        } else {
            return false;
        }
    }
    false
}

#[doc(hidden)]
pub fn ruby_bare_call_identifier(node: Node<'_>) -> bool {
    node.kind() == "identifier"
        && node
            .parent()
            .is_some_and(|parent| parent.kind() == "body_statement")
}

fn ruby_callable_object_call(node: Node<'_>) -> bool {
    node.kind() == "call"
        && node.child_by_field_name("receiver").is_some()
        && node.child_by_field_name("operator").is_some()
        && node.child_by_field_name("method").is_none()
        && node.child_by_field_name("arguments").is_some()
}

fn ruby_exact_bare_call_identifier(node: Node<'_>) -> bool {
    node.kind() == "identifier" && !ruby_is_call_method_identifier(node)
}

#[cfg(test)]
mod tests {
    use super::test_support::*;

    use crate::analyzer::usages::get_definition::call_sites::cpp_test_support::*;

    use super::ExactCallReference;
    use super::ExactCallReferenceGap;
    use super::call_reference_range_for_call;
    use super::call_reference_ranges_in_tree;
    use super::call_signature_context;
    use super::call_site_syntax_for_reference;
    use super::exact_call_reference_for_call;

    use crate::analyzer::Language;

    use crate::analyzer::structural::extract::extract_file_facts;

    use crate::analyzer::usages::get_definition::parse_tree_for_language;

    use brokk_bifrost_ruby::structural::RUBY_STRUCTURAL_SPEC;

    fn offset_after(source: &str, needle: &str) -> usize {
        source.find(needle).expect("needle exists") + needle.len()
    }

    fn assert_signature_context(
        path: &str,
        source: &str,
        cursor_after: &str,
        callee: &str,
        active_parameter: u32,
    ) {
        let context =
            call_signature_context(&file(path), source, offset_after(source, cursor_after))
                .expect("signature context");
        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            callee
        );
        assert_eq!(context.active_parameter, active_parameter);
    }

    fn assert_nested_call_reference_names(path: &str, language: Language, source: &str) {
        let file = file(path);
        let tree = parse_tree_for_language(&file, language, source).expect("syntax tree");
        for (call, expected) in [("outer(inner())", "outer"), ("inner()", "inner")] {
            let reference =
                call_reference_range_for_call(&tree, language, &byte_range(source, call))
                    .expect("call reference");
            assert_eq!(&source[reference.start_byte..reference.end_byte], expected);
        }
    }

    #[test]
    fn exact_call_span_distinguishes_outer_and_inner_callees() {
        let source = "function outer(value: number) { return value; }\nfunction inner() { return 1; }\nouter(inner());\n";
        assert_nested_call_reference_names("nested.ts", Language::TypeScript, source);
    }

    #[test]
    fn exact_java_call_span_uses_the_named_method_field() {
        let source = "class Nested { static int outer(int value) { return value; } static int inner() { return 1; } int call() { return outer(inner()); } }";
        assert_nested_call_reference_names("Nested.java", Language::Java, source);
    }

    #[test]
    fn exact_rust_turbofish_call_span_uses_the_wrapped_function() {
        let source = "fn leaf<T>() {}\nstruct Worker;\nimpl Worker { fn make<T>(&self) {} }\nfn caller(worker: Worker) { leaf::<u8>(); worker.make::<u8>(); }\n";
        let file = file("lib.rs");
        let tree =
            parse_tree_for_language(&file, Language::Rust, source).expect("Rust syntax tree");

        let leaf = call_reference_range_for_call(
            &tree,
            Language::Rust,
            &byte_range(source, "leaf::<u8>()"),
        )
        .expect("generic free-function reference");
        let make = call_reference_range_for_call(
            &tree,
            Language::Rust,
            &byte_range(source, "worker.make::<u8>()"),
        )
        .expect("generic method reference");

        assert_eq!(&source[leaf.start_byte..leaf.end_byte], "leaf");
        assert_eq!(&source[make.start_byte..make.end_byte], "make");
    }

    #[test]
    fn exact_cpp_call_spans_follow_only_the_terminal_callable_spine() {
        let source = CPP_CALL_SITE_SOURCE;
        let file = file("calls.cpp");
        let tree = parse_tree_for_language(&file, Language::Cpp, source).expect("C++ syntax tree");
        for (call, callee) in [
            ("ns::make<int>(1)", "make"),
            ("receiver.run<int>(1)", "run"),
            ("new ns::Box<int>()", "Box"),
            ("receiver.operator+(1)", "operator+"),
            ("receiver.~Widget()", "~Widget"),
        ] {
            let reference =
                call_reference_range_for_call(&tree, Language::Cpp, &byte_range(source, call))
                    .unwrap_or_else(|| panic!("missing exact C++ call reference for `{call}`"));
            assert_eq!(
                &source[reference.start_byte..reference.end_byte],
                callee,
                "wrong exact C++ callee for `{call}`"
            );
        }
    }

    #[test]
    fn exact_scala_call_spans_use_the_terminal_direct_callee() {
        let source = r#"
object Calls {
  class Box[A](value: Int)
  class Curried(value: Int)(label: String)
  class Service {
    def curried[A](value: Int)(label: String): Int = value
    def combine(other: Service): Service = this
    def ping: Int = 1
  }
  def ordinary(value: Int): Int = value
  def caller(service: Service, other: Service, head: Int, tail: List[Int]): Unit = {
    ordinary(1)
    ordinary[Int](1)
    service.curried[Int](1)("label")
    new Box[Int](1)
    new Curried(1)("label")
    service combine other
    service ping
    head :: tail
  }
}
"#;
        let file = file("Calls.scala");
        let tree =
            parse_tree_for_language(&file, Language::Scala, source).expect("Scala syntax tree");

        for (call, callee) in [
            ("ordinary(1)", "ordinary"),
            ("ordinary[Int](1)", "ordinary"),
            ("service.curried[Int](1)(\"label\")", "curried"),
            ("new Box[Int](1)", "Box"),
            ("new Curried(1)(\"label\")", "Curried"),
            ("service combine other", "combine"),
            ("service ping", "ping"),
            ("head :: tail", "::"),
        ] {
            let reference =
                call_reference_range_for_call(&tree, Language::Scala, &byte_range(source, call))
                    .unwrap_or_else(|| panic!("missing exact Scala call reference for `{call}`"));
            assert_eq!(
                &source[reference.start_byte..reference.end_byte],
                callee,
                "wrong exact Scala callee for `{call}`"
            );
        }
    }

    #[test]
    fn scala_parameterless_selection_is_not_an_immediate_call_candidate() {
        let source = "object Calls { def caller(service: Service) = service.value }";
        let file = file("Calls.scala");
        let tree =
            parse_tree_for_language(&file, Language::Scala, source).expect("Scala syntax tree");
        let selection = byte_range(source, "service.value");

        let references = call_reference_ranges_in_tree(&tree, Language::Scala, &selection, 20);

        assert!(references.is_empty(), "{references:#?}");
    }

    #[test]
    fn scala_call_candidates_prune_partial_functions_and_givens_but_not_match_cases() {
        let outer = r#"def outer(value: Int): Int = {
    val partial: PartialFunction[Int, Int] = { case _ => nestedCall() }
    given generated: Int = nestedCall()
    val matched = value match { case _ => matchCall() }
    directCall()
  }"#;
        let source = format!(
            "object Calls {{ def nestedCall(): Int = 1; def matchCall(): Int = 2; def directCall(): Int = 3; {outer} }}"
        );
        let file = file("Calls.scala");
        let tree =
            parse_tree_for_language(&file, Language::Scala, &source).expect("Scala syntax tree");
        let search_range = byte_range(&source, outer);

        let references = call_reference_ranges_in_tree(&tree, Language::Scala, &search_range, 20);
        let names = references
            .iter()
            .map(|range| &source[range.start_byte..range.end_byte])
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["matchCall", "directCall"]);
    }

    #[test]
    fn exact_ruby_call_spans_use_the_terminal_callee_for_every_ordinary_form() {
        let source = r#"def caller(service)
  bare_target
  parenthesized(1)
  command 2
  service.received(3)
  service&.safe_call(4)
  Service::scoped(5)
  with_block(6) { block_only() }
  with_do 7 do
    do_only()
  end
end
"#;
        let file = file("calls.rb");
        let tree =
            parse_tree_for_language(&file, Language::Ruby, source).expect("Ruby syntax tree");

        for (call, callee) in [
            ("bare_target", "bare_target"),
            ("parenthesized(1)", "parenthesized"),
            ("command 2", "command"),
            ("service.received(3)", "received"),
            ("service&.safe_call(4)", "safe_call"),
            ("Service::scoped(5)", "scoped"),
            ("with_block(6) { block_only() }", "with_block"),
            ("with_do 7 do\n    do_only()\n  end", "with_do"),
        ] {
            let reference =
                call_reference_range_for_call(&tree, Language::Ruby, &byte_range(source, call))
                    .unwrap_or_else(|| panic!("missing exact Ruby call reference for `{call}`"));
            assert_eq!(
                &source[reference.start_byte..reference.end_byte],
                callee,
                "wrong exact Ruby callee for `{call}`"
            );
        }

        assert!(
            call_reference_range_for_call(
                &tree,
                Language::Ruby,
                &byte_range(source, "parenthesized")
            )
            .is_none(),
            "the callee token alone is not the exact span of a wrapped call"
        );
    }

    #[test]
    fn exact_ruby_operator_calls_and_callable_objects_keep_their_structured_shape() {
        let source = r#"def caller(obj, callable)
  obj.+(1)
  obj.[](2)
  callable.(3)
end
"#;
        let file = file("operators.rb");
        let tree =
            parse_tree_for_language(&file, Language::Ruby, source).expect("Ruby syntax tree");

        for (call, callee) in [("obj.+(1)", "+"), ("obj.[](2)", "[]")] {
            let reference =
                call_reference_range_for_call(&tree, Language::Ruby, &byte_range(source, call))
                    .unwrap_or_else(|| {
                        panic!("missing exact Ruby operator reference for `{call}`")
                    });
            assert_eq!(
                &source[reference.start_byte..reference.end_byte],
                callee,
                "wrong exact Ruby operator callee for `{call}`"
            );
        }

        assert_eq!(
            exact_call_reference_for_call(
                &tree,
                Language::Ruby,
                &byte_range(source, "callable.(3)")
            ),
            Some(ExactCallReference::Unsupported(
                ExactCallReferenceGap::RubyCallableObject
            ))
        );
    }

    #[test]
    fn signature_context_prefers_innermost_call() {
        let source = "function inner(value: number) { return value; }\nfunction outer(value: number) { return value; }\nouter(inner(1));\n";
        assert_signature_context("sample.ts", source, "outer(inner(", "inner", 0);
    }

    #[test]
    fn signature_context_handles_scala_brace_argument_block() {
        let source =
            "object App {\n  def target(value: Int): Int = value\n  val result = target { 1 }\n}\n";
        let context = call_signature_context(
            &file("App.scala"),
            source,
            offset_after(source, "target { "),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "target"
        );
        assert_eq!(context.active_parameter, 0);
    }

    #[test]
    fn signature_context_handles_ruby_command_call_with_block() {
        let source = "target 1, 2 do |item|\n  item\nend\n";
        let context = call_signature_context(
            &file("sample.rb"),
            source,
            offset_after(source, "target 1, "),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "target"
        );
        assert_eq!(context.active_parameter, 1);
    }

    #[test]
    fn signature_context_prefers_innermost_ruby_call() {
        let source = "outer(inner(1), 2)\n";
        assert_signature_context("sample.rb", source, "inner(", "inner", 0);
    }

    #[test]
    fn signature_context_handles_scala_infix_call() {
        let source = "object App {\n  class Box { def combine(value: Int): Int = value }\n  val box = new Box\n  val result = box combine 1\n}\n";
        let context = call_signature_context(
            &file("App.scala"),
            source,
            offset_after(source, "box combine "),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "combine"
        );
        assert_eq!(context.active_parameter, 0);
    }

    #[test]
    fn signature_context_handles_scala_postfix_operator_call() {
        let source = "object App {\n  class Box { def ! : Boolean = true }\n  val box = new Box\n  val result = box !\n}\n";
        let context =
            call_signature_context(&file("App.scala"), source, offset_after(source, "box !"))
                .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "!"
        );
        assert_eq!(context.active_parameter, 0);
    }

    #[test]
    fn signature_context_rejects_higher_order_call_callee() {
        let source = "function factory() { return (value: number) => value; }\nconst result = factory()(1);\n";
        let context = call_signature_context(
            &file("sample.ts"),
            source,
            offset_after(source, "factory()("),
        );

        assert_eq!(context, None);
    }

    #[test]
    fn scala_call_candidates_exclude_receivers_arguments_and_type_arguments() {
        let source = "object Calls { def caller(service: Service, value: Int, label: String) = service.curried[String](value)(label) }";
        let file = file("Calls.scala");
        let tree =
            parse_tree_for_language(&file, Language::Scala, source).expect("Scala syntax tree");
        let call = byte_range(source, "service.curried[String](value)(label)");

        let references = call_reference_ranges_in_tree(&tree, Language::Scala, &call, 20);
        let names = references
            .iter()
            .map(|range| &source[range.start_byte..range.end_byte])
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["curried"]);
    }

    #[test]
    fn scala_constructor_candidates_exclude_qualifiers_arguments_and_type_arguments() {
        let source = "object Calls { def caller(value: Int) = new pkg.Box[String](value) }";
        let file = file("Calls.scala");
        let tree =
            parse_tree_for_language(&file, Language::Scala, source).expect("Scala syntax tree");
        let call = byte_range(source, "new pkg.Box[String](value)");

        let references = call_reference_ranges_in_tree(&tree, Language::Scala, &call, 20);
        let names = references
            .iter()
            .map(|range| &source[range.start_byte..range.end_byte])
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["Box"]);
    }

    #[test]
    fn exact_call_span_rejects_an_enclosing_statement() {
        let source = "function target() {}\ntarget();\n";
        let file = file("statement.ts");
        let tree = parse_tree_for_language(&file, Language::TypeScript, source)
            .expect("TypeScript syntax tree");

        assert!(
            call_reference_range_for_call(
                &tree,
                Language::TypeScript,
                &byte_range(source, "target();"),
            )
            .is_none()
        );
    }

    #[test]
    fn ruby_bare_call_has_a_structured_call_site() {
        let source = "def target; end\ndef caller; target; end\n";
        let grammar = tree_sitter_ruby::LANGUAGE.into();
        let facts = extract_file_facts(&RUBY_STRUCTURAL_SPEC, &grammar, source)
            .expect("Ruby structural facts");
        let start = source.rfind("target").expect("call target");
        let site = call_site_syntax_for_reference(&facts, start, start + "target".len())
            .expect("bare Ruby call site");
        assert_eq!(
            &source[site.callee_range.start_byte..site.callee_range.end_byte],
            "target"
        );
        assert_eq!(
            &source[site.range.start_byte..site.range.end_byte],
            "target"
        );
    }

    #[test]
    fn signature_context_counts_active_parameter_after_comma() {
        let source =
            "class A { int target(int left, int right) { return 0; } void f() { target(1, 2); } }";
        assert_signature_context("A.java", source, "1, ", "target", 1);
    }

    #[test]
    fn signature_context_handles_empty_argument_list() {
        let source = "fn target() {}\nfn caller() { target(); }\n";
        let context = call_signature_context(
            &file("lib.rs"),
            source,
            offset_after(source, "caller() { target("),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "target"
        );
        assert_eq!(context.active_parameter, 0);
    }

    #[test]
    fn signature_context_handles_ruby_bare_call() {
        let source = "def target(left, right)\nend\n\ntarget(1, 2)\n";
        assert_signature_context("sample.rb", source, "target(1, ", "target", 1);
    }

    #[test]
    fn signature_context_handles_ruby_receiver_call() {
        let source = "user.target(1, 2)\n";
        let context = call_signature_context(
            &file("sample.rb"),
            source,
            offset_after(source, "target(1, "),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "target"
        );
        assert_eq!(context.active_parameter, 1);
    }

    #[test]
    fn signature_context_handles_ruby_parenthesized_call_with_block() {
        let source = "target(1, 2) { |item| item }\n";
        let context = call_signature_context(
            &file("sample.rb"),
            source,
            offset_after(source, "target(1, "),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "target"
        );
        assert_eq!(context.active_parameter, 1);
    }

    #[test]
    fn signature_context_handles_scala_postfix_call() {
        let source = "object App {\n  class Box { def ready: Boolean = true }\n  val box = new Box\n  val result = box ready\n}\n";
        let context = call_signature_context(
            &file("App.scala"),
            source,
            offset_after(source, "box ready"),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "ready"
        );
        assert_eq!(context.active_parameter, 0);
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod cpp_test_support;
