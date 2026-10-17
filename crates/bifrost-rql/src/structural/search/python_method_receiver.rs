//! Query-time Python method receiver evidence for callable-signature rows.

use super::python_rule_facts::named_children;
use super::*;
use crate::analyzer::semantic::ContentIdentity;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, ResolvedValueIdentityKind, resolve_value_identity_with_source,
};
use crate::analyzer::usages::python_class_hierarchy::PythonHierarchyOutcome;
use brokk_bifrost_python::bindings::{
    PythonDirectScopeBindingKind, PythonLexicalNameResolution,
    python_direct_scope_bindings_bounded, python_executable_scope_children,
    python_name_resolution_at,
};
use brokk_bifrost_python::imports::python_import_bindings_from_tree;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct PythonMethodReceiverEvidence {
    pub(super) kind: Option<&'static str>,
    pub(super) owner_is_metaclass: Option<bool>,
    pub(super) owner_is_zope_interface: Option<bool>,
    pub(super) used_in_class_body: Option<bool>,
    pub(super) no_args_with_decorator: Option<bool>,
}

pub(super) fn receiver_evidence(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    declaration: &DeclarationValue,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PythonMethodReceiverEvidence {
    if crate::analyzer::common::language_for_file(declaration.unit.source()) != Language::Python
        || !declaration.unit.is_function()
        || !declaration.unit.owner_is_type_scope()
    {
        return PythonMethodReceiverEvidence::default();
    }

    let owner = analyzer.parent_of(&declaration.unit);
    let source = analyzer.get_source(
        &CodeUnit::file_scope(declaration.unit.source().clone()),
        false,
    );
    let (Some(owner), Some(source)) = (owner.filter(CodeUnit::is_class), source) else {
        return PythonMethodReceiverEvidence::default();
    };
    let Ok(tree) = environment_cache.python_syntax_tree_for(
        declaration.unit.source(),
        ContentIdentity::hash_bytes(source.as_bytes()),
        &source,
    ) else {
        return PythonMethodReceiverEvidence {
            kind: Some("unknown"),
            ..PythonMethodReceiverEvidence::default()
        };
    };
    let Some(function) = super::python_rule_facts::python_definition_node(
        &tree,
        &declaration.unit,
        &declaration.range,
    ) else {
        return PythonMethodReceiverEvidence {
            kind: Some("unknown"),
            ..PythonMethodReceiverEvidence::default()
        };
    };
    let Some(class) = analyzer
        .ranges(&owner)
        .into_iter()
        .find_map(|range| super::python_rule_facts::python_definition_node(&tree, &owner, &range))
    else {
        return PythonMethodReceiverEvidence {
            kind: Some("unknown"),
            ..PythonMethodReceiverEvidence::default()
        };
    };
    let Some(body) = class.child_by_field_name("body") else {
        return PythonMethodReceiverEvidence {
            kind: Some("unknown"),
            ..PythonMethodReceiverEvidence::default()
        };
    };
    if !is_direct_class_method(function, class) {
        return PythonMethodReceiverEvidence::default();
    }

    let name = function
        .child_by_field_name("name")
        .and_then(|node| super::python_rule_facts::node_text(&source, node));
    let Some(name) = name else {
        return PythonMethodReceiverEvidence {
            kind: Some("unknown"),
            ..PythonMethodReceiverEvidence::default()
        };
    };
    let has_static_decorator = has_plain_name_decorator(function, &source, "staticmethod");
    let has_class_decorator = has_plain_name_decorator(function, &source, "classmethod");
    let assigned_kind = assigned_descriptor_kind(
        analyzer,
        environment_cache,
        &declaration.unit,
        MethodDefinition {
            function,
            class_body: body,
            name,
            source: &source,
        },
        cancellation,
        diagnostics,
    );
    let kind = match assigned_kind {
        Some(Some(kind)) => kind,
        Some(None) => "unknown",
        // CodeQL's `isStaticmethod` and `isClassmethod` are independent
        // predicates. If both syntactic decorators are present, both kinds
        // are excluded from the two naming rules, so static is the safe
        // representative kind for the policy evidence.
        None if has_static_decorator => "static",
        None if has_class_decorator => "class",
        None if matches!(name, "__new__" | "__init_subclass__" | "__class_getitem__") => "class",
        None => "instance",
    };
    let (owner_is_metaclass, owner_is_zope_interface) = owner_hierarchy_membership(
        analyzer,
        environment_cache,
        &owner,
        class,
        &source,
        cancellation,
        diagnostics,
    );
    let used_in_class_body =
        class_body_uses_function(analyzer, &declaration.unit, body, &source, cancellation);
    let has_any_arguments = function
        .child_by_field_name("parameters")
        .is_some_and(|parameters| {
            named_children(parameters).into_iter().any(|parameter| {
                brokk_bifrost_python::declarations::python_parameter_label_node(parameter).is_some()
            })
        });
    let no_args_with_decorator = !has_any_arguments && has_any_decorator(function);

    PythonMethodReceiverEvidence {
        kind: Some(kind),
        owner_is_metaclass,
        owner_is_zope_interface,
        used_in_class_body,
        no_args_with_decorator: Some(no_args_with_decorator),
    }
}

fn is_direct_class_method(function: Node<'_>, class: Node<'_>) -> bool {
    let mut current = function.parent();
    while let Some(node) = current {
        if node.id() == class.id() {
            return true;
        }
        if matches!(
            node.kind(),
            "function_definition" | "class_definition" | "lambda"
        ) {
            return false;
        }
        current = node.parent();
    }
    false
}

fn has_plain_name_decorator(function: Node<'_>, source: &str, expected: &str) -> bool {
    // CodeQL's isStaticmethod/isClassmethod predicates match a direct Name
    // decorator syntactically; aliases and attribute expressions do not count.
    let Some(decorated) = function
        .parent()
        .filter(|parent| parent.kind() == "decorated_definition")
    else {
        return false;
    };
    named_children(decorated).into_iter().any(|child| {
        child.kind() == "decorator"
            && child.named_child(0).is_some_and(|expression| {
                expression.kind() == "identifier"
                    && super::python_rule_facts::node_text(source, expression) == Some(expected)
            })
    })
}

fn has_any_decorator(function: Node<'_>) -> bool {
    function
        .parent()
        .filter(|parent| parent.kind() == "decorated_definition")
        .is_some_and(|parent| {
            named_children(parent)
                .into_iter()
                .any(|child| child.kind() == "decorator")
        })
}

#[derive(Clone, Copy)]
struct MethodDefinition<'tree, 'source> {
    function: Node<'tree>,
    class_body: Node<'tree>,
    name: &'source str,
    source: &'source str,
}

fn assigned_descriptor_kind(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    declaration: &CodeUnit,
    method: MethodDefinition<'_, '_>,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Option<Option<&'static str>> {
    let mut latest = None;
    let mut assignments = Vec::new();
    let mut stack = named_children(method.class_body)
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "function_definition" | "class_definition" | "lambda"
        ) {
            continue;
        }
        if matches!(
            node.kind(),
            "assignment" | "augmented_assignment" | "named_expression"
        ) && node.start_byte() > method.function.start_byte()
            && node
                .child_by_field_name("left")
                .is_some_and(|left| assignment_writes_method_name(left, method.source, method.name))
        {
            let direct_class_assignment = is_direct_class_assignment(node, method.class_body);
            assignments.push((node, direct_class_assignment));
        };
        stack.extend(named_children(node).into_iter().rev());
    }
    assignments.sort_unstable_by_key(|(node, _)| node.start_byte());
    for (statement, direct_class_assignment) in assignments {
        // Any later write replaces the definition's decorator result. A write
        // whose descriptor/value identity is not proven leaves receiver kind
        // unknown; it must not silently fall back to an instance method.
        latest = Some(None);
        if !direct_class_assignment || statement.kind() != "assignment" {
            continue;
        }
        let Some(call) = statement
            .child_by_field_name("right")
            .filter(|right| right.kind() == "call")
        else {
            continue;
        };
        let Some(descriptor) = call.child_by_field_name("function") else {
            continue;
        };
        let descriptor_name = match descriptor.kind() {
            "identifier" => super::python_rule_facts::node_text(method.source, descriptor),
            _ => None,
        };
        let expected_identity = match descriptor_name {
            Some("staticmethod") => "builtins.staticmethod",
            Some("classmethod") => "builtins.classmethod",
            _ => continue,
        };
        let is_builtin_descriptor = super::python_rule_facts::builtin_value_identity_at_range(
            analyzer,
            environment_cache,
            declaration.source(),
            method.source,
            descriptor.start_byte(),
            descriptor.end_byte(),
            cancellation,
            diagnostics,
        )
        .ok()
        .flatten()
        .is_some_and(|identity| identity == expected_identity);
        if !is_builtin_descriptor {
            continue;
        }
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let Some(argument) = named_children(arguments)
            .into_iter()
            .find(|argument| argument.kind() != "comment")
            .filter(|argument| argument.kind() == "identifier")
        else {
            continue;
        };
        if resolves_to_declaration(analyzer, declaration, method.source, argument, cancellation) {
            latest = Some(Some(if expected_identity == "builtins.staticmethod" {
                "static"
            } else {
                "class"
            }));
        }
    }
    latest
}

fn is_direct_class_assignment(node: Node<'_>, class_body: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.id() == class_body.id() {
            return true;
        }
        if parent.kind() != "expression_statement" {
            return false;
        }
        current = parent;
    }
    false
}

fn assignment_writes_method_name(left: Node<'_>, source: &str, method_name: &str) -> bool {
    let mut stack = vec![left];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier"
            && super::python_rule_facts::node_text(source, node) == Some(method_name)
        {
            return true;
        }
        if matches!(node.kind(), "pattern_list" | "tuple_pattern" | "tuple") {
            stack.extend(named_children(node));
        }
    }
    false
}

fn class_body_uses_function(
    analyzer: &dyn IAnalyzer,
    declaration: &CodeUnit,
    class_body: Node<'_>,
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Option<bool> {
    let mut stack = named_children(class_body);
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "function_definition" | "class_definition" | "lambda"
        ) {
            continue;
        }
        if node.kind() == "call"
            && let Some(function) = node.child_by_field_name("function")
            && resolves_to_declaration(analyzer, declaration, source, function, cancellation)
        {
            return Some(true);
        }
        if node.kind() == "decorator"
            && let Some(expression) = node.named_child(0)
            && decorator_callee(expression).is_some_and(|callee| {
                resolves_to_declaration(analyzer, declaration, source, callee, cancellation)
            })
        {
            return Some(true);
        }
        stack.extend(named_children(node));
    }
    Some(false)
}

fn decorator_callee(mut expression: Node<'_>) -> Option<Node<'_>> {
    while expression.kind() == "call" {
        expression = expression.child_by_field_name("function")?;
    }
    Some(expression)
}

fn owner_hierarchy_membership(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    owner: &CodeUnit,
    class: Node<'_>,
    source: &str,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> (Option<bool>, Option<bool>) {
    let answer = analyzer
        .python_class_hierarchy_provider_for(owner)
        .map(|provider| provider.class_hierarchy(owner, cancellation));
    if let Some(answer) = answer {
        match answer.outcome {
            PythonHierarchyOutcome::Complete => {
                let has = |expected_fq_name| {
                    answer
                        .mro
                        .iter()
                        .any(|ancestor| ancestor.fq_name_str() == expected_fq_name)
                };
                (
                    Some(has("builtins.type")),
                    Some(has("zope.interface.Interface")),
                )
            }
            PythonHierarchyOutcome::Inconsistent => {
                let has = |expected_fq_name| {
                    answer
                        .mro
                        .iter()
                        .any(|ancestor| ancestor.fq_name_str() == expected_fq_name)
                };
                (
                    has("builtins.type").then_some(true),
                    has("zope.interface.Interface").then_some(true),
                )
            }
            PythonHierarchyOutcome::Incomplete | PythonHierarchyOutcome::Unsupported => {
                ordinary_object_root_membership(
                    analyzer,
                    environment_cache,
                    owner,
                    class,
                    source,
                    cancellation,
                    diagnostics,
                )
            }
        }
    } else {
        ordinary_object_root_membership(
            analyzer,
            environment_cache,
            owner,
            class,
            source,
            cancellation,
            diagnostics,
        )
    }
}

fn ordinary_object_root_membership(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    owner: &CodeUnit,
    class: Node<'_>,
    source: &str,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> (Option<bool>, Option<bool>) {
    let Some(bases) = class.child_by_field_name("superclasses") else {
        // Python gives a class with no explicit bases the implicit `object`
        // base. That proves it is neither a metaclass nor a Zope interface.
        return (Some(false), Some(false));
    };
    let base_nodes = named_children(bases)
        .into_iter()
        .filter(|node| node.kind() != "comment")
        .collect::<Vec<_>>();
    if base_nodes.is_empty() {
        return (Some(false), Some(false));
    }

    let zope_interface = base_nodes.iter().any(|base| {
        imported_class_path(base, class, source).as_deref() == Some("zope.interface.Interface")
    });
    if zope_interface {
        // The imported CodeQL API class is a normal interface base, not a
        // subclass of `type`; its descendants are excluded from not-named-self.
        return (Some(false), Some(true));
    }

    if let [base] = base_nodes.as_slice()
        && base.kind() == "identifier"
    {
        return match super::python_rule_facts::builtin_value_identity_at_range(
            analyzer,
            environment_cache,
            owner.source(),
            source,
            base.start_byte(),
            base.end_byte(),
            cancellation,
            diagnostics,
        ) {
            Ok(Some(identity)) if identity == "builtins.object" => (Some(false), Some(false)),
            Ok(Some(identity)) if identity == "builtins.type" => (Some(true), Some(false)),
            Ok(_) | Err(_) => (None, None),
        };
    }
    (None, None)
}

fn imported_class_path<'tree>(
    expression: &Node<'tree>,
    class: Node<'tree>,
    source: &str,
) -> Option<String> {
    let (root, attributes) = static_attribute_path(*expression, source)?;
    let root_name = super::python_rule_facts::node_text(source, root)?;
    if matches!(
        python_name_resolution_at(root_name, root, source),
        PythonLexicalNameResolution::Local | PythonLexicalNameResolution::Nonlocal
    ) {
        return None;
    }

    let mut module = class;
    while let Some(parent) = module.parent() {
        module = parent;
        if module.kind() == "module" {
            break;
        }
    }
    if module.kind() != "module" {
        return None;
    }
    let imports = python_import_bindings_from_tree(module, source);
    let binding = imports
        .iter()
        .filter(|binding| {
            binding.local_name == root_name
                && binding.start_byte <= root.start_byte()
                && binding.scope_start_byte <= root.start_byte()
                && root.end_byte() <= binding.scope_end_byte
                && !binding.is_function_scoped()
        })
        .max_by_key(|binding| binding.start_byte)?;
    if !module_scope_has_only_this_import(module, root_name, binding.start_byte, class, source) {
        return None;
    }

    // `import pkg.child` binds `pkg` but consumes the `child` attribute;
    // aliased imports and from-imports consume no attribute from the use.
    let mut qualified = binding.qualified_name.clone();
    for attribute in attributes.into_iter().skip(binding.consumed_attributes) {
        qualified.push('.');
        qualified.push_str(&attribute);
    }
    Some(qualified)
}

fn module_scope_has_only_this_import(
    module: Node<'_>,
    name: &str,
    import_start: usize,
    class: Node<'_>,
    source: &str,
) -> bool {
    let mut bindings = Vec::new();
    let mut stack = vec![module];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= class.start_byte() {
            continue;
        }
        for binding in python_direct_scope_bindings_bounded(node, source, || true)
            .into_iter()
            .flatten()
        {
            if super::python_rule_facts::node_text(source, binding.declaration) == Some(name)
                && binding.declaration.start_byte() < class.start_byte()
            {
                bindings.push((binding.declaration.start_byte(), binding.kind, node));
            }
        }
        stack.extend(python_executable_scope_children(node));
    }
    bindings.sort_unstable_by_key(|(start, _, _)| *start);
    let [(binding_start, PythonDirectScopeBindingKind::Import, import_node)] = bindings.as_slice()
    else {
        return false;
    };
    *binding_start > import_start
        && import_node.start_byte() == import_start
        && import_node
            .parent()
            .is_some_and(|parent| parent.id() == module.id())
}

fn static_attribute_path<'tree>(
    mut expression: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, Vec<String>)> {
    let mut attributes = Vec::new();
    loop {
        if expression.kind() == "identifier" {
            attributes.reverse();
            return Some((expression, attributes));
        }
        if expression.kind() != "attribute" {
            return None;
        }
        let attribute = expression.child_by_field_name("attribute")?;
        attributes.push(super::python_rule_facts::node_text(source, attribute)?.to_owned());
        expression = expression.child_by_field_name("object")?;
    }
}

fn resolves_to_declaration(
    analyzer: &dyn IAnalyzer,
    declaration: &CodeUnit,
    source: &str,
    node: Node<'_>,
    cancellation: Option<&CancellationToken>,
) -> bool {
    let request = DefinitionLookupRequest {
        file: declaration.source().clone(),
        line: None,
        column: None,
        start_byte: Some(node.start_byte()),
        end_byte: Some(node.end_byte()),
    };
    resolve_value_identity_with_source(
        analyzer,
        request,
        declaration.source().clone(),
        Arc::<str>::from(source),
        cancellation,
    )
    .is_some_and(|identity| {
        identity.kind == ResolvedValueIdentityKind::WorkspaceDeclaration
            && identity.identity == declaration.declaration_id().as_str()
    })
}
