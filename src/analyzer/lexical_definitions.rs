//! Query-local resolution for lexical definitions that are deliberately not
//! persisted as [`CodeUnit`](super::CodeUnit)s.
//!
//! Parameter bindings belong to a callable invocation, not to the workspace
//! symbol graph.  Resolving them from the current syntax tree keeps overlays
//! authoritative and avoids adding short-lived lexical facts to the store.

use tree_sitter::Node;

use super::rust::field_roles::{RustFieldNameRole, classify_rust_field_name};
use super::{DeclarationKind, Language, Range};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LexicalDefinition {
    pub(crate) identifier: String,
    pub(crate) kind: DeclarationKind,
    pub(crate) name_range: Range,
    pub(crate) declaration_range: Range,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LexicalBindingResolution {
    Parameter(LexicalDefinition),
    OtherLocal,
}

#[derive(Clone, Copy)]
struct ParameterBinding<'tree> {
    name: Node<'tree>,
    declaration: Node<'tree>,
    kind: DeclarationKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FormalParameterSlot {
    pub(crate) names: Vec<String>,
    pub(crate) declaration_range: Range,
    pub(crate) receiver: bool,
    pub(crate) variadic: Option<FormalVariadicKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FormalVariadicKind {
    Positional,
    Keyword,
    Both,
}

impl FormalVariadicKind {
    pub(crate) fn accepts_positional(self) -> bool {
        matches!(self, Self::Positional | Self::Both)
    }

    pub(crate) fn accepts_keyword(self) -> bool {
        matches!(self, Self::Keyword | Self::Both)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PythonMethodBinding {
    Instance,
    Class,
    Static,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct FormalParameterLayout {
    pub(crate) slots: Vec<FormalParameterSlot>,
    pub(crate) python_binding: Option<PythonMethodBinding>,
}

/// Return the formal parameter slots owned by the callable at
/// `declaration_range`. The result is syntax-derived so it remains correct for
/// overlays and does not require parameter declarations to be persisted as
/// workspace symbols.
pub(crate) fn formal_parameter_slots(
    language: Language,
    root: Node<'_>,
    source: &str,
    declaration_range: &Range,
) -> FormalParameterLayout {
    let Some(owner) = parameter_owner_for_range(language, root, declaration_range) else {
        return FormalParameterLayout::default();
    };
    let python_binding = (language == Language::Python)
        .then(|| python_method_binding(owner, source, declaration_range));
    let lambda = is_lambda_owner(language, owner.kind());
    let (ordinary_roots, receiver_roots) = parameter_roots(language, owner);
    let mut bindings = ordinary_roots
        .into_iter()
        .map(|root| (root, None))
        .chain(
            receiver_roots
                .into_iter()
                .map(|root| (root, Some(DeclarationKind::ReceiverParameter))),
        )
        .flat_map(|(root, forced_kind)| parameter_bindings(language, root, lambda, forced_kind))
        .collect::<Vec<_>>();
    bindings.sort_by_key(|binding| {
        (
            binding.declaration.start_byte(),
            binding.name.start_byte(),
            binding.name.end_byte(),
        )
    });

    let mut slots: Vec<FormalParameterSlot> = Vec::new();
    for binding in bindings {
        let Some(name) = source.get(binding.name.byte_range()) else {
            continue;
        };
        let receiver = binding.kind == DeclarationKind::ReceiverParameter;
        let declaration_range = node_range(binding.declaration);
        let variadic = is_variadic_parameter(language, binding.declaration.kind());
        let can_share_slot = language != Language::Go;
        if can_share_slot
            && let Some(slot) = slots.last_mut()
            && slot.declaration_range.start_byte == declaration_range.start_byte
            && slot.declaration_range.end_byte == declaration_range.end_byte
            && slot.receiver == receiver
        {
            if !slot.names.iter().any(|candidate| candidate == name) {
                slot.names.push(name.to_owned());
            }
            slot.variadic = slot.variadic.or(variadic);
            continue;
        }
        slots.push(FormalParameterSlot {
            names: vec![name.to_owned()],
            declaration_range,
            receiver,
            variadic,
        });
    }

    FormalParameterLayout {
        slots,
        python_binding,
    }
}

fn python_method_binding(
    owner: Node<'_>,
    source: &str,
    declaration_range: &Range,
) -> PythonMethodBinding {
    let Some(decorated) = owner.parent().filter(|parent| {
        parent.kind() == "decorated_definition"
            && parent.start_byte() >= declaration_range.start_byte
            && parent.end_byte() <= declaration_range.end_byte
    }) else {
        return PythonMethodBinding::Instance;
    };
    let mut stack = Vec::new();
    let mut cursor = decorated.walk();
    stack.extend(
        decorated
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "decorator"),
    );
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier" {
            match source.get(node.byte_range()) {
                Some("staticmethod") => return PythonMethodBinding::Static,
                Some("classmethod") => return PythonMethodBinding::Class,
                _ => {}
            }
        }
        push_named_children(node, &mut stack);
    }
    PythonMethodBinding::Instance
}

fn parameter_owner_for_range<'tree>(
    language: Language,
    root: Node<'tree>,
    declaration_range: &Range,
) -> Option<Node<'tree>> {
    let mut best: Option<(usize, Node<'tree>)> = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.end_byte() <= declaration_range.start_byte
            || node.start_byte() >= declaration_range.end_byte
        {
            continue;
        }
        if is_parameter_owner(language, node.kind())
            && node.start_byte() >= declaration_range.start_byte
            && node.end_byte() <= declaration_range.end_byte
        {
            let distance = node
                .start_byte()
                .abs_diff(declaration_range.start_byte)
                .saturating_add(node.end_byte().abs_diff(declaration_range.end_byte));
            if best.is_none_or(|(best_distance, _)| distance < best_distance) {
                best = Some((distance, node));
            }
        }
        push_named_children(node, &mut stack);
    }
    best.map(|(_, owner)| owner)
}

/// Resolve `identifier` at the supplied byte range to the nearest lexical
/// parameter binding.  `None` means that the structured syntax did not prove a
/// lexical answer, so callers should continue with ordinary indexed lookup.
/// A nearer local declaration is reported separately so callers do not fall
/// through and accidentally resolve an outer parameter or workspace symbol.
pub(crate) fn resolve_lexical_binding(
    language: Language,
    root: Node<'_>,
    source: &str,
    focus_start: usize,
    focus_end: usize,
    identifier: &str,
) -> Option<LexicalBindingResolution> {
    if language == Language::None
        || focus_start > focus_end
        || focus_end > source.len()
        || identifier.is_empty()
    {
        return None;
    }

    let focus = smallest_named_node(root, focus_start, focus_end)?;
    if !focus_can_resolve_lexical(language, focus) {
        return None;
    }
    let mut ancestors = Vec::new();
    let mut cursor = Some(focus);
    while let Some(node) = cursor {
        ancestors.push(node);
        cursor = node.parent();
    }

    // Walk lexical scopes from the focus outwards.  A local in an inner block
    // must win before an enclosing callable's parameters are considered.
    for node in ancestors {
        if is_lexical_scope(language, node.kind())
            && scope_has_matching_local(language, node, source, focus_start, identifier)
        {
            return Some(LexicalBindingResolution::OtherLocal);
        }

        if is_parameter_owner(language, node.kind())
            && let Some(binding) = matching_parameter(language, node, source, identifier)
        {
            return Some(LexicalBindingResolution::Parameter(LexicalDefinition {
                identifier: identifier.to_owned(),
                kind: binding.kind,
                name_range: node_range(binding.name),
                declaration_range: node_range(binding.declaration),
            }));
        }
    }

    None
}

fn smallest_named_node(root: Node<'_>, start: usize, end: usize) -> Option<Node<'_>> {
    let end = end.max(start.saturating_add(1)).min(root.end_byte());
    root.named_descendant_for_byte_range(start, end)
        .or_else(|| root.descendant_for_byte_range(start, end))
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    }
}

fn focus_can_resolve_lexical(language: Language, focus: Node<'_>) -> bool {
    if language == Language::Rust
        && !matches!(classify_rust_field_name(focus), RustFieldNameRole::Other)
    {
        return false;
    }

    let mut current = focus;
    while let Some(parent) = current.parent() {
        if ["type", "return_type", "superclass", "interfaces"]
            .into_iter()
            .any(|field| parent.child_by_field_name(field) == Some(current))
        {
            return false;
        }
        if is_parameter_declaration(language, parent.kind()) {
            return true;
        }
        if is_parameter_owner(language, parent.kind()) || is_lexical_scope(language, parent.kind())
        {
            break;
        }
        current = parent;
    }
    true
}

fn matching_parameter<'tree>(
    language: Language,
    owner: Node<'tree>,
    source: &str,
    identifier: &str,
) -> Option<ParameterBinding<'tree>> {
    let lambda = is_lambda_owner(language, owner.kind());
    let (ordinary_roots, receiver_roots) = parameter_roots(language, owner);

    // Scala lambda parameters are repeated fields and can be naked identifiers
    // or a bindings node; the field walk above captures both.
    let mut best = None;
    for (root, forced_kind) in ordinary_roots.into_iter().map(|root| (root, None)).chain(
        receiver_roots
            .into_iter()
            .map(|root| (root, Some(DeclarationKind::ReceiverParameter))),
    ) {
        for binding in parameter_bindings(language, root, lambda, forced_kind) {
            if identifier_matches(language, binding.name, source, identifier) {
                best = Some(binding);
                break;
            }
        }
        if best.is_some() {
            break;
        }
    }
    best
}

fn parameter_roots<'tree>(
    language: Language,
    owner: Node<'tree>,
) -> (Vec<Node<'tree>>, Vec<Node<'tree>>) {
    let mut ordinary_roots = Vec::new();
    push_field_children(owner, "parameters", &mut ordinary_roots);
    push_field_children(owner, "parameter", &mut ordinary_roots);
    push_field_children(owner, "class_parameters", &mut ordinary_roots);
    if language == Language::CSharp
        && matches!(
            owner.kind(),
            "class_declaration" | "struct_declaration" | "record_declaration"
        )
    {
        let mut cursor = owner.walk();
        ordinary_roots.extend(
            owner
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "parameter_list"),
        );
    }
    let mut receiver_roots = Vec::new();
    push_field_children(owner, "receiver", &mut receiver_roots);

    // C++ stores the parameter list below the callable declarator rather than
    // directly on the function/lambda node.
    if language == Language::Cpp
        && let Some(declarator) = owner.child_by_field_name("declarator")
    {
        let mut stack = vec![declarator];
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "parameter_list" | "parameters") {
                ordinary_roots.push(node);
                continue;
            }
            push_named_children(node, &mut stack);
        }
    }
    (ordinary_roots, receiver_roots)
}

fn is_variadic_parameter(language: Language, kind: &str) -> Option<FormalVariadicKind> {
    use FormalVariadicKind::{Both, Keyword, Positional};
    match language {
        Language::Java => (kind == "spread_parameter").then_some(Positional),
        Language::Go => (kind == "variadic_parameter_declaration").then_some(Positional),
        Language::JavaScript | Language::TypeScript => {
            (kind == "rest_pattern").then_some(Positional)
        }
        Language::Python => match kind {
            "list_splat_pattern" => Some(Positional),
            "dictionary_splat_pattern" => Some(Keyword),
            _ => None,
        },
        Language::Rust => (kind == "variadic_parameter").then_some(Positional),
        Language::Php => (kind == "variadic_parameter").then_some(Both),
        Language::Ruby => match kind {
            "splat_parameter" => Some(Positional),
            "hash_splat_parameter" => Some(Keyword),
            _ => None,
        },
        Language::Cpp | Language::Scala | Language::CSharp | Language::None => None,
    }
}

fn parameter_bindings(
    language: Language,
    root: Node<'_>,
    lambda: bool,
    forced_kind: Option<DeclarationKind>,
) -> Vec<ParameterBinding<'_>> {
    let mut bindings = Vec::new();
    if !is_parameter_container(language, root.kind())
        && is_direct_parameter_binding(language, root.kind())
    {
        let kind = forced_kind.unwrap_or(if lambda {
            DeclarationKind::LambdaParameter
        } else {
            DeclarationKind::Parameter
        });
        for name in binding_name_nodes(language, root, true) {
            bindings.push(ParameterBinding {
                name,
                declaration: root,
                kind,
            });
        }
        return bindings;
    }
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node != root && is_parameter_owner(language, node.kind()) {
            continue;
        }

        if is_parameter_declaration(language, node.kind()) {
            let kind = forced_kind.unwrap_or_else(|| {
                if matches!(
                    (language, node.kind()),
                    (Language::Rust, "self_parameter") | (Language::Java, "receiver_parameter")
                ) {
                    DeclarationKind::ReceiverParameter
                } else if lambda {
                    DeclarationKind::LambdaParameter
                } else {
                    DeclarationKind::Parameter
                }
            });
            for name in binding_name_nodes(language, node, true) {
                bindings.push(ParameterBinding {
                    name,
                    declaration: node,
                    kind,
                });
            }
            continue;
        }

        // Several grammars represent untyped lambda/closure parameters as a
        // naked binding pattern directly beneath their parameter container.
        if is_parameter_container(language, root.kind())
            && node != root
            && is_direct_parameter_binding(language, node.kind())
        {
            for name in binding_name_nodes(language, node, true) {
                bindings.push(ParameterBinding {
                    name,
                    declaration: node,
                    kind: forced_kind.unwrap_or(if lambda {
                        DeclarationKind::LambdaParameter
                    } else {
                        DeclarationKind::Parameter
                    }),
                });
            }
            continue;
        }

        push_named_children(node, &mut stack);
    }
    bindings
}

fn scope_has_matching_local(
    language: Language,
    scope: Node<'_>,
    source: &str,
    focus_start: usize,
    identifier: &str,
) -> bool {
    let mut stack = Vec::new();
    push_named_children(scope, &mut stack);
    while let Some(node) = stack.pop() {
        if node.start_byte() > focus_start {
            continue;
        }
        if is_parameter_owner(language, node.kind())
            || is_nested_scope(language, node.kind())
            || is_parameter_declaration(language, node.kind())
        {
            continue;
        }
        if is_local_declaration(language, node.kind()) {
            if language == Language::Rust && node.end_byte() > focus_start {
                continue;
            }
            if language == Language::Scala
                && node.kind() == "enumerator"
                && !scala_enumerator_binding_visible_at(node, focus_start)
            {
                continue;
            }
            if language == Language::Scala
                && matches!(node.kind(), "val_definition" | "var_definition")
                && (!scala_has_value_definition_keyword(node)
                    || node.child_by_field_name("pattern").is_none())
            {
                continue;
            }
            if binding_name_nodes(language, node, false)
                .into_iter()
                .any(|name| identifier_matches(language, name, source, identifier))
            {
                return true;
            }
            continue;
        }
        push_named_children(node, &mut stack);
    }
    false
}

fn scala_enumerator_binding_visible_at(enumerator: Node<'_>, focus_start: usize) -> bool {
    let Some(pattern) = enumerator
        .named_child(0)
        .filter(|child| child.kind() != "guard")
    else {
        return false;
    };
    enumerator
        .named_children(&mut enumerator.walk())
        .find(|child| child.start_byte() >= pattern.end_byte() && child.kind() != "guard")
        .is_some_and(|expression| expression.end_byte() <= focus_start)
}

fn scala_has_value_definition_keyword(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| matches!(child.kind(), "val" | "var"))
}

fn binding_name_nodes(language: Language, declaration: Node<'_>, parameter: bool) -> Vec<Node<'_>> {
    let mut roots = Vec::new();
    if language == Language::Scala && declaration.kind() == "enumerator" {
        // tree-sitter-scala represents both generators (`pattern <- expression`)
        // and value enumerators (`pattern = expression`) with an `enumerator`
        // node. Its first named child is the binding pattern; guard-only
        // enumerators instead begin with a `guard` and declare nothing.
        if let Some(pattern) = declaration
            .named_child(0)
            .filter(|child| child.kind() != "guard")
        {
            roots.push(pattern);
        }
    }
    for field in ["name", "pattern", "declarator", "left"] {
        push_field_children(declaration, field, &mut roots);
    }

    // Some wrappers deliberately have no named field (Python typed params,
    // Java spread params, Rust self params, and naked pattern nodes).
    if roots.is_empty() {
        roots.push(declaration);
    }

    let mut names = Vec::new();
    for root in roots {
        collect_binding_leaves(language, root, parameter, &mut names);
    }
    names.sort_by_key(Node::start_byte);
    names.dedup_by_key(|node| (node.start_byte(), node.end_byte()));
    names
}

fn collect_binding_leaves<'tree>(
    language: Language,
    root: Node<'tree>,
    parameter: bool,
    output: &mut Vec<Node<'tree>>,
) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if is_binding_leaf(language, node.kind()) {
            output.push(node);
            continue;
        }

        if language == Language::Rust && node.kind() == "field_pattern" {
            let mut pattern = Vec::new();
            push_field_children(node, "pattern", &mut pattern);
            if pattern.is_empty() {
                push_field_children(node, "name", &mut pattern);
            }
            stack.extend(pattern);
            continue;
        }

        let mut selected = Vec::new();
        for field in binding_child_fields(language, node.kind(), parameter) {
            push_field_children(node, field, &mut selected);
        }
        if selected.is_empty() && binding_container(language, node.kind()) {
            push_named_children(node, &mut selected);
        }
        stack.extend(selected);
    }
}

fn binding_child_fields(
    language: Language,
    kind: &str,
    parameter: bool,
) -> &'static [&'static str] {
    match (language, kind) {
        (Language::Java, "spread_parameter") => &["declarator"],
        (Language::Cpp, _) => &["declarator"],
        (Language::JavaScript | Language::TypeScript, "assignment_pattern") => &["left"],
        (Language::JavaScript | Language::TypeScript, "pair_pattern") => &["value"],
        (Language::JavaScript | Language::TypeScript, "object_assignment_pattern") => &["left"],
        (Language::Rust, "field_pattern") => &["pattern", "name"],
        (Language::Python, "default_parameter" | "typed_default_parameter") => &["name"],
        (Language::Php, _) if parameter => &["name"],
        (_, _) => &["name", "pattern", "argument", "left"],
    }
}

fn push_field_children<'tree>(node: Node<'tree>, field: &str, output: &mut Vec<Node<'tree>>) {
    for index in 0..node.child_count() {
        if node.field_name_for_child(index as u32) == Some(field)
            && let Some(child) = node.child(index)
            && child.is_named()
        {
            output.push(child);
        }
    }
}

fn push_named_children<'tree>(node: Node<'tree>, output: &mut Vec<Node<'tree>>) {
    let mut cursor = node.walk();
    output.extend(node.named_children(&mut cursor));
}

fn identifier_matches(language: Language, node: Node<'_>, source: &str, identifier: &str) -> bool {
    let Some(text) = source.get(node.byte_range()) else {
        return false;
    };
    if language == Language::Php {
        text == identifier
            || text.strip_prefix('$') == Some(identifier)
            || identifier.strip_prefix('$') == Some(text)
    } else {
        text == identifier
    }
}

fn is_parameter_owner(language: Language, kind: &str) -> bool {
    match language {
        Language::Java => matches!(
            kind,
            "method_declaration"
                | "constructor_declaration"
                | "lambda_expression"
                | "record_declaration"
        ),
        Language::Go => matches!(
            kind,
            "function_declaration" | "method_declaration" | "method_elem" | "func_literal"
        ),
        Language::Cpp => matches!(
            kind,
            "function_definition" | "lambda_expression" | "function_declarator"
        ),
        Language::JavaScript | Language::TypeScript => matches!(
            kind,
            "function_declaration"
                | "function_expression"
                | "generator_function_declaration"
                | "generator_function"
                | "arrow_function"
                | "method_definition"
        ),
        Language::Python => matches!(kind, "function_definition" | "lambda"),
        Language::Rust => matches!(kind, "function_item" | "closure_expression"),
        Language::Php => matches!(
            kind,
            "function_definition" | "method_declaration" | "anonymous_function" | "arrow_function"
        ),
        Language::Scala => matches!(
            kind,
            "function_definition"
                | "function_declaration"
                | "lambda_expression"
                | "class_definition"
                | "trait_definition"
                | "object_definition"
                | "enum_definition"
        ),
        Language::CSharp => matches!(
            kind,
            "method_declaration"
                | "constructor_declaration"
                | "local_function_statement"
                | "lambda_expression"
                | "anonymous_method_expression"
                | "class_declaration"
                | "struct_declaration"
                | "record_declaration"
        ),
        Language::Ruby => matches!(kind, "method" | "singleton_method" | "lambda" | "block"),
        Language::None => false,
    }
}

fn is_lambda_owner(language: Language, kind: &str) -> bool {
    match language {
        Language::Java => kind == "lambda_expression",
        Language::Go => kind == "func_literal",
        Language::Cpp => kind == "lambda_expression",
        Language::JavaScript | Language::TypeScript => {
            matches!(kind, "arrow_function" | "function_expression")
        }
        Language::Python => kind == "lambda",
        Language::Rust => kind == "closure_expression",
        Language::Php => matches!(kind, "anonymous_function" | "arrow_function"),
        Language::Scala => kind == "lambda_expression",
        Language::CSharp => matches!(kind, "lambda_expression" | "anonymous_method_expression"),
        Language::Ruby => matches!(kind, "lambda" | "block"),
        Language::None => false,
    }
}

fn is_parameter_declaration(language: Language, kind: &str) -> bool {
    match language {
        Language::Java => matches!(
            kind,
            "formal_parameter" | "spread_parameter" | "receiver_parameter"
        ),
        Language::Go => matches!(
            kind,
            "parameter_declaration" | "variadic_parameter_declaration"
        ),
        Language::Cpp => matches!(
            kind,
            "parameter_declaration" | "optional_parameter_declaration"
        ),
        Language::JavaScript => matches!(kind, "assignment_pattern" | "rest_pattern"),
        Language::TypeScript => matches!(
            kind,
            "required_parameter" | "optional_parameter" | "assignment_pattern" | "rest_pattern"
        ),
        Language::Python => matches!(
            kind,
            "default_parameter"
                | "typed_parameter"
                | "typed_default_parameter"
                | "list_splat_pattern"
                | "dictionary_splat_pattern"
        ),
        Language::Rust => matches!(kind, "parameter" | "self_parameter" | "variadic_parameter"),
        Language::Php => matches!(
            kind,
            "simple_parameter" | "variadic_parameter" | "property_promotion_parameter"
        ),
        Language::Scala => matches!(kind, "parameter" | "class_parameter" | "binding"),
        Language::CSharp => matches!(kind, "parameter" | "implicit_parameter"),
        Language::Ruby => matches!(
            kind,
            "optional_parameter"
                | "keyword_parameter"
                | "splat_parameter"
                | "hash_splat_parameter"
                | "block_parameter"
                | "destructured_parameter"
        ),
        Language::None => false,
    }
}

fn is_parameter_container(language: Language, kind: &str) -> bool {
    match language {
        Language::Java => matches!(kind, "formal_parameters" | "inferred_parameters"),
        Language::Go => kind == "parameter_list",
        Language::Cpp => matches!(kind, "parameter_list" | "parameters"),
        Language::JavaScript | Language::TypeScript => kind == "formal_parameters",
        Language::Python => matches!(kind, "parameters" | "lambda_parameters"),
        Language::Rust => matches!(kind, "parameters" | "closure_parameters"),
        Language::Php => kind == "formal_parameters",
        Language::Scala => matches!(kind, "parameters" | "class_parameters" | "bindings"),
        Language::CSharp => kind == "parameter_list",
        Language::Ruby => matches!(
            kind,
            "method_parameters" | "lambda_parameters" | "block_parameters"
        ),
        Language::None => false,
    }
}

fn is_direct_parameter_binding(language: Language, kind: &str) -> bool {
    match language {
        Language::Java
        | Language::Go
        | Language::Cpp
        | Language::Python
        | Language::Scala
        | Language::CSharp
        | Language::Ruby => {
            matches!(kind, "identifier" | "operator_identifier")
        }
        Language::JavaScript | Language::TypeScript => {
            is_binding_leaf(language, kind) || binding_container(language, kind)
        }
        Language::Rust => binding_container(language, kind) || kind == "identifier",
        Language::Php => kind == "name",
        Language::None => false,
    }
}

fn is_binding_leaf(language: Language, kind: &str) -> bool {
    match language {
        Language::Php => matches!(kind, "variable_name" | "name"),
        Language::Rust => matches!(kind, "identifier" | "self"),
        Language::Java => matches!(kind, "identifier" | "this"),
        Language::Scala => matches!(kind, "identifier" | "operator_identifier"),
        Language::JavaScript | Language::TypeScript => {
            matches!(kind, "identifier" | "shorthand_property_identifier_pattern")
        }
        _ => kind == "identifier",
    }
}

fn binding_container(language: Language, kind: &str) -> bool {
    match language {
        Language::JavaScript | Language::TypeScript => matches!(
            kind,
            "array_pattern"
                | "object_pattern"
                | "assignment_pattern"
                | "object_assignment_pattern"
                | "pair_pattern"
                | "rest_pattern"
                | "required_parameter"
                | "optional_parameter"
        ),
        Language::Java => matches!(kind, "spread_parameter" | "receiver_parameter"),
        Language::Python => matches!(
            kind,
            "tuple_pattern" | "list_splat_pattern" | "dictionary_splat_pattern" | "typed_parameter"
        ),
        Language::Rust => matches!(
            kind,
            "tuple_pattern"
                | "tuple_struct_pattern"
                | "struct_pattern"
                | "field_pattern"
                | "reference_pattern"
                | "mut_pattern"
                | "slice_pattern"
                | "captured_pattern"
                | "ref_pattern"
                | "self_parameter"
        ),
        Language::Ruby => kind == "destructured_parameter",
        Language::Php => kind == "variable_name",
        Language::Go => kind == "expression_list",
        Language::Cpp => matches!(
            kind,
            "identifier"
                | "pointer_declarator"
                | "reference_declarator"
                | "array_declarator"
                | "parenthesized_declarator"
        ),
        _ => false,
    }
}

fn is_lexical_scope(language: Language, kind: &str) -> bool {
    match language {
        Language::Java => matches!(kind, "block" | "switch_block"),
        Language::Go => kind == "block",
        Language::Cpp => kind == "compound_statement",
        Language::JavaScript | Language::TypeScript => {
            matches!(kind, "statement_block" | "switch_body")
        }
        Language::Python => matches!(kind, "block" | "module"),
        Language::Rust => kind == "block",
        Language::Php => kind == "compound_statement",
        Language::Scala => matches!(kind, "block" | "indented_block"),
        Language::CSharp => matches!(kind, "block" | "switch_body"),
        Language::Ruby => matches!(kind, "body_statement" | "do_block" | "block"),
        Language::None => false,
    }
}

fn is_nested_scope(language: Language, kind: &str) -> bool {
    is_lexical_scope(language, kind)
        || match language {
            Language::Java => matches!(kind, "class_body" | "interface_body" | "enum_body"),
            Language::Cpp => matches!(kind, "class_specifier" | "namespace_definition"),
            Language::JavaScript | Language::TypeScript => matches!(kind, "class_body"),
            Language::Python => matches!(kind, "class_definition"),
            Language::Php => matches!(kind, "declaration_list"),
            Language::Scala => matches!(kind, "template_body" | "case_block"),
            Language::CSharp => matches!(kind, "declaration_list"),
            Language::Ruby => matches!(kind, "class" | "module"),
            _ => false,
        }
}

fn is_local_declaration(language: Language, kind: &str) -> bool {
    match language {
        Language::Java => matches!(
            kind,
            "variable_declarator"
                | "catch_formal_parameter"
                | "resource"
                | "enhanced_for_statement"
                | "type_pattern"
        ),
        Language::Go => matches!(kind, "var_spec" | "short_var_declaration" | "range_clause"),
        Language::Cpp => matches!(kind, "init_declarator" | "condition_clause"),
        Language::JavaScript | Language::TypeScript => matches!(
            kind,
            "variable_declarator" | "catch_clause" | "for_in_statement"
        ),
        // Assignment in Python/PHP/Ruby may merely rebind an existing
        // parameter.  Without a distinct declaration construct it must not be
        // misclassified as a fresh shadow.
        Language::Python | Language::Php | Language::Ruby => false,
        Language::Rust => matches!(kind, "let_declaration" | "for_expression"),
        Language::Scala => matches!(
            kind,
            "val_definition" | "var_definition" | "enumerator" | "case_clause"
        ),
        Language::CSharp => matches!(
            kind,
            "variable_declarator"
                | "for_each_statement"
                | "catch_declaration"
                | "declaration_expression"
        ),
        Language::None => false,
    }
}
