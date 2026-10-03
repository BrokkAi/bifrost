//! AST-owned context captured alongside canonical C++ declaration facts.

use crate::graph::resolver::{
    BooleanGuardExpression, PreprocessorGuard, callable_preprocessor_guard_requirements,
    direct_unmatched_closing_brace, flattened_macro_namespace_components,
    is_recovered_declaration_scope_container, preprocessor_conditional_family_for_declaration,
    preprocessor_guard_environment,
};
use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::cpp_facts::{CppGuardNode, CppGuardSet};
use brokk_bifrost_core::hash::HashSet;
use tree_sitter::Node;

pub(crate) struct CppSourceContext<'tree> {
    pub guard_requirements: Option<CppGuardSet>,
    pub callable_guards: Option<CppGuardSet>,
    pub callable_activation: Option<usize>,
    pub callable_guard_completion_byte: Option<usize>,
    pub exhaustive_conditional_family: Option<Node<'tree>>,
    pub flattened_macro_namespace: Option<Vec<String>>,
    pub displaced_namespace_closing_brace: Option<Node<'tree>>,
}

pub(crate) fn capture_declaration_context<'tree>(
    node: Node<'tree>,
    unit: &CodeUnit,
    source: &str,
) -> CppSourceContext<'tree> {
    let declaration = callable_declaration_node(node);
    // The visibility resolver also uses declaration activation for fields.
    // Capture that structured context while their declaration AST is present;
    // an absent activation otherwise hides every field outside class context.
    let callable = (unit.is_function() || unit.is_field()) && declaration.is_some();
    let callable_nameable =
        callable && declaration.is_some_and(|node| callable_declaration_is_nameable(node, source));
    let callable_declarator = declaration.and_then(function_declarator);
    let callable_guards = callable_nameable
        .then(|| declaration.expect("callable declaration"))
        .and_then(|declaration| callable_preprocessor_guard_requirements(declaration, source))
        .map(|guards| cpp_guard_set_from_runtime(&guards));
    let callable_activation = callable_nameable.then(|| {
        let declaration = declaration.expect("callable declaration");
        if declaration.kind() == "function_definition" {
            callable_declarator.map_or(declaration.end_byte(), |node| node.end_byte())
        } else {
            declaration.end_byte()
        }
    });
    let flattened_macro_namespace = flattened_macro_namespace_components(node, source);
    let displaced_namespace_closing_brace = declaration
        .filter(|declaration| {
            declaration
                .parent()
                .is_some_and(|parent| parent.kind() == "translation_unit")
                && macro_displaced_return_type(*declaration, source)
        })
        .and_then(namespace_closing_brace);

    CppSourceContext {
        guard_requirements: preprocessor_guard_environment(node, source)
            .as_ref()
            .map(cpp_guard_set_from_runtime),
        callable_guards,
        callable_activation,
        callable_guard_completion_byte: crate::graph::resolver::callable_guard_completion_byte(
            node, source,
        ),
        exhaustive_conditional_family: preprocessor_conditional_family_for_declaration(node),
        flattened_macro_namespace,
        displaced_namespace_closing_brace,
    }
}

fn callable_declaration_node<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = node;
    loop {
        if matches!(
            current.kind(),
            "declaration" | "field_declaration" | "function_definition"
        ) {
            return Some(current);
        }
        current = current.parent()?;
    }
}

fn function_declarator(declaration: Node<'_>) -> Option<Node<'_>> {
    if declaration.kind() == "function_declarator" {
        return Some(declaration);
    }
    let mut current = declaration.child_by_field_name("declarator")?;
    loop {
        if current.kind() == "function_declarator" {
            return Some(current);
        }
        current = current.child_by_field_name("declarator")?;
    }
}

fn callable_declaration_is_nameable(declaration: Node<'_>, source: &str) -> bool {
    let mut ancestor = declaration.parent();
    while let Some(node) = ancestor {
        if node.kind() == "function_definition"
            && is_recovered_declaration_scope_container(node, source)
        {
            ancestor = node.parent();
            continue;
        }
        if node.kind() == "compound_statement"
            && node
                .parent()
                .is_some_and(|parent| is_recovered_declaration_scope_container(parent, source))
        {
            ancestor = node.parent().and_then(|parent| parent.parent());
            continue;
        }
        if matches!(
            node.kind(),
            "compound_statement" | "function_definition" | "lambda_expression"
        ) {
            return false;
        }
        ancestor = node.parent();
    }
    true
}

// A macro parsed as the return type can displace the real type into an
// ERROR child. A later unmatched brace is independent evidence of a lost
// namespace owner, even when that owner's name did not survive recovery.
fn macro_displaced_return_type(declaration: Node<'_>, source: &str) -> bool {
    let Some(ty) = declaration.child_by_field_name("type") else {
        return false;
    };
    let name = crate::declarations::node_text(ty, source).trim();
    !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
        && (0..declaration.named_child_count()).any(|index| {
            declaration
                .named_child(index)
                .is_some_and(|child| child.kind() == "ERROR")
        })
}

fn namespace_closing_brace(node: Node<'_>) -> Option<Node<'_>> {
    let mut root = node;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let mut cursor = root.walk();
    root.named_children(&mut cursor).find(|sibling| {
        sibling.start_byte() >= node.end_byte() && direct_unmatched_closing_brace(*sibling)
    })
}

pub(crate) fn cpp_guard_set_from_runtime(guards: &HashSet<PreprocessorGuard>) -> CppGuardSet {
    let mut encoded = guards
        .iter()
        .map(|guard| {
            let mut nodes = Vec::new();
            let root = append_guard(guard, &mut nodes);
            (nodes, root)
        })
        .collect::<Vec<_>>();
    encoded.sort_unstable_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let mut nodes = Vec::new();
    let mut roots = Vec::with_capacity(encoded.len());
    for (mut guard_nodes, root) in encoded {
        let offset = nodes.len();
        for node in &mut guard_nodes {
            remap_guard_node(node, offset);
        }
        nodes.extend(guard_nodes);
        roots.push(root + offset);
    }
    CppGuardSet::new(nodes, roots)
}

fn remap_guard_node(node: &mut CppGuardNode, offset: usize) {
    match node {
        CppGuardNode::Boolean(child) => *child += offset,
        CppGuardNode::All(children) | CppGuardNode::Any(children) => {
            for child in children {
                *child += offset;
            }
        }
        CppGuardNode::Defined(_)
        | CppGuardNode::Undefined(_)
        | CppGuardNode::Expression(_)
        | CppGuardNode::NegatedExpression(_)
        | CppGuardNode::Constant(_)
        | CppGuardNode::Truthy(_)
        | CppGuardNode::Falsy(_)
        | CppGuardNode::Opaque(_)
        | CppGuardNode::NegatedOpaque(_) => {}
    }
}

enum GuardWork<'a> {
    Guard(&'a PreprocessorGuard),
    Boolean(&'a BooleanGuardExpression),
    EmitBoolean,
    EmitChildren { all: bool, count: usize },
}

fn append_guard(guard: &PreprocessorGuard, nodes: &mut Vec<CppGuardNode>) -> usize {
    let mut work = vec![GuardWork::Guard(guard)];
    let mut values = Vec::new();
    while let Some(work_item) = work.pop() {
        match work_item {
            GuardWork::Guard(guard) => match guard {
                PreprocessorGuard::Defined(value) => {
                    values.push(push_guard_node(nodes, CppGuardNode::Defined(value.clone())))
                }
                PreprocessorGuard::Undefined(value) => values.push(push_guard_node(
                    nodes,
                    CppGuardNode::Undefined(value.clone()),
                )),
                PreprocessorGuard::Boolean(expression) => {
                    work.push(GuardWork::EmitBoolean);
                    work.push(GuardWork::Boolean(expression));
                }
                PreprocessorGuard::Expression(value) => values.push(push_guard_node(
                    nodes,
                    CppGuardNode::Expression(value.clone()),
                )),
                PreprocessorGuard::NegatedExpression(value) => values.push(push_guard_node(
                    nodes,
                    CppGuardNode::NegatedExpression(value.clone()),
                )),
                PreprocessorGuard::Constant(value) => {
                    values.push(push_guard_node(nodes, CppGuardNode::Constant(*value)))
                }
            },
            GuardWork::Boolean(expression) => match expression {
                BooleanGuardExpression::Defined(value) => {
                    values.push(push_guard_node(nodes, CppGuardNode::Defined(value.clone())))
                }
                BooleanGuardExpression::Undefined(value) => values.push(push_guard_node(
                    nodes,
                    CppGuardNode::Undefined(value.clone()),
                )),
                BooleanGuardExpression::Truthy(value) => {
                    values.push(push_guard_node(nodes, CppGuardNode::Truthy(value.clone())))
                }
                BooleanGuardExpression::Falsy(value) => {
                    values.push(push_guard_node(nodes, CppGuardNode::Falsy(value.clone())))
                }
                BooleanGuardExpression::Opaque(value) => {
                    values.push(push_guard_node(nodes, CppGuardNode::Opaque(value.clone())))
                }
                BooleanGuardExpression::NegatedOpaque(value) => values.push(push_guard_node(
                    nodes,
                    CppGuardNode::NegatedOpaque(value.clone()),
                )),
                BooleanGuardExpression::All(expressions) => {
                    work.push(GuardWork::EmitChildren {
                        all: true,
                        count: expressions.len(),
                    });
                    for expression in expressions.iter().rev() {
                        work.push(GuardWork::Boolean(expression));
                    }
                }
                BooleanGuardExpression::Any(expressions) => {
                    work.push(GuardWork::EmitChildren {
                        all: false,
                        count: expressions.len(),
                    });
                    for expression in expressions.iter().rev() {
                        work.push(GuardWork::Boolean(expression));
                    }
                }
                BooleanGuardExpression::Constant(value) => {
                    values.push(push_guard_node(nodes, CppGuardNode::Constant(*value)))
                }
            },
            GuardWork::EmitBoolean => {
                let root = values.pop().expect("boolean guard root");
                values.push(push_guard_node(nodes, CppGuardNode::Boolean(root)));
            }
            GuardWork::EmitChildren { all, count } => {
                let start = values.len().checked_sub(count).expect("guard children");
                let children = values.split_off(start);
                values.push(push_guard_node(
                    nodes,
                    if all {
                        CppGuardNode::All(children)
                    } else {
                        CppGuardNode::Any(children)
                    },
                ));
            }
        }
    }
    values.pop().expect("guard root")
}

fn push_guard_node(nodes: &mut Vec<CppGuardNode>, node: CppGuardNode) -> usize {
    let index = nodes.len();
    nodes.push(node);
    index
}

pub(crate) fn cpp_guard_set_to_runtime(guards: &CppGuardSet) -> Option<HashSet<PreprocessorGuard>> {
    if !guards.valid() {
        return None;
    }
    let mut boolean_nodes = vec![None; guards.nodes.len()];
    for (index, node) in guards.nodes.iter().enumerate() {
        boolean_nodes[index] = match node {
            CppGuardNode::Defined(value) => Some(BooleanGuardExpression::Defined(value.clone())),
            CppGuardNode::Undefined(value) => {
                Some(BooleanGuardExpression::Undefined(value.clone()))
            }
            CppGuardNode::Truthy(value) => Some(BooleanGuardExpression::Truthy(value.clone())),
            CppGuardNode::Falsy(value) => Some(BooleanGuardExpression::Falsy(value.clone())),
            CppGuardNode::Opaque(value) => Some(BooleanGuardExpression::Opaque(value.clone())),
            CppGuardNode::NegatedOpaque(value) => {
                Some(BooleanGuardExpression::NegatedOpaque(value.clone()))
            }
            CppGuardNode::All(children) => Some(BooleanGuardExpression::All(
                children
                    .iter()
                    .map(|child| boolean_nodes[*child].take())
                    .collect::<Option<Vec<_>>>()?,
            )),
            CppGuardNode::Any(children) => Some(BooleanGuardExpression::Any(
                children
                    .iter()
                    .map(|child| boolean_nodes[*child].take())
                    .collect::<Option<Vec<_>>>()?,
            )),
            CppGuardNode::Constant(value) => Some(BooleanGuardExpression::Constant(*value)),
            CppGuardNode::Boolean(child) => boolean_nodes[*child].take(),
            CppGuardNode::Expression(_) | CppGuardNode::NegatedExpression(_) => None,
        };
    }
    let mut result = HashSet::default();
    for root in &guards.roots {
        let guard = match &guards.nodes[*root] {
            CppGuardNode::Defined(value) => PreprocessorGuard::Defined(value.clone()),
            CppGuardNode::Undefined(value) => PreprocessorGuard::Undefined(value.clone()),
            CppGuardNode::Boolean(_) => PreprocessorGuard::Boolean(boolean_nodes[*root].take()?),
            CppGuardNode::Expression(value) => PreprocessorGuard::Expression(value.clone()),
            CppGuardNode::NegatedExpression(value) => {
                PreprocessorGuard::NegatedExpression(value.clone())
            }
            CppGuardNode::Constant(value) => PreprocessorGuard::Constant(*value),
            CppGuardNode::Truthy(_)
            | CppGuardNode::Falsy(_)
            | CppGuardNode::Opaque(_)
            | CppGuardNode::NegatedOpaque(_)
            | CppGuardNode::All(_)
            | CppGuardNode::Any(_) => return None,
        };
        result.insert(guard);
    }
    Some(result)
}
