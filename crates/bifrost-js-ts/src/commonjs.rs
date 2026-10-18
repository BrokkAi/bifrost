//! Source-time evidence that a receiver denotes this file's CommonJS object.
//!
//! A spelling such as `exports` is not evidence when a factory binds it. Follow
//! immutable local values and direct calls (including a callback passed to an
//! IIFE) instead. This is a per-blob syntax projection, dropped after extraction.

use crate::syntax::{JsTsLexicalBindingIndex, slice};
use crate::ts_owners::ts_unwrap_expression;
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum ModuleObject {
    Exports,
    Module,
    Ambiguous,
}

#[derive(Clone)]
pub(crate) struct CommonJsObjects {
    exports: HashSet<usize>,
}

impl CommonJsObjects {
    pub fn new(root: Node<'_>, source: &str, lexical: &JsTsLexicalBindingIndex) -> Self {
        // Keys are exact binder tokens selected by the lexical index, never
        // display names or a containing declaration chosen by its range.
        let mut values: HashMap<usize, Vec<Node<'_>>> = HashMap::default();
        let mut inert_vars = HashSet::default();
        let mut calls = Vec::new();
        let mut receivers = Vec::new();
        let mut object_names = HashSet::from_iter(["exports", "module"]);
        let mut has_module_object_seed = false;
        walk_named_tree_preorder(root, true, |node| {
            match node.kind() {
                "variable_declarator" => {
                    if let Some(name) = node.child_by_field_name("name")
                        && name.kind() == "identifier"
                    {
                        if let Some(value) = node.child_by_field_name("value") {
                            if ts_unwrap_expression(value).is_some_and(|value| {
                                matches!(value.kind(), "identifier" | "member_expression")
                            }) {
                                object_names.insert(slice(name, source));
                            }
                            values.entry(name.start_byte()).or_default().push(value);
                        } else if !node.has_error()
                            && !node.is_missing()
                            && node.parent().is_some_and(|declaration| {
                                declaration.kind() == "variable_declaration"
                            })
                        {
                            // Only a plain, uninitialized var is inert. Other
                            // binders remain evidence that a cohort is ambiguous.
                            inert_vars.insert(name.start_byte());
                        }
                    }
                }
                "function_declaration" | "generator_function_declaration" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        values.entry(name.start_byte()).or_default().push(node);
                    }
                }
                "formal_parameters" => {
                    for parameter in node.named_children(&mut node.walk()) {
                        for binder in crate::syntax::pattern_binder_identifiers(parameter) {
                            object_names.insert(slice(binder, source));
                        }
                    }
                }
                "arrow_function" => {
                    if let Some(parameter) = node.child_by_field_name("parameter") {
                        object_names.insert(slice(parameter, source));
                    }
                }
                "call_expression" => calls.push(node),
                "identifier" => {
                    let name = slice(node, source);
                    has_module_object_seed |= matches!(name, "exports" | "module")
                        && !lexical.is_bound_at(name, node.start_byte());
                    receivers.push(node);
                }
                "member_expression"
                | "parenthesized_expression"
                | "as_expression"
                | "satisfies_expression"
                | "type_assertion" => receivers.push(node),
                _ => {}
            }
            WalkControl::Continue
        });

        if !has_module_object_seed {
            return Self {
                exports: HashSet::default(),
            };
        }

        // A function expression immediately used as a callee has one exact
        // invocation. Its callback parameters can be followed without guessing
        // what an arbitrary caller supplied to a named or escaping wrapper.
        for call in &calls {
            if let Some(function) = call
                .child_by_field_name("function")
                .and_then(ts_unwrap_expression)
                && matches!(function.kind(), "function_expression" | "arrow_function")
            {
                for (parameter, argument) in parameter_arguments(function, *call) {
                    values
                        .entry(parameter.start_byte())
                        .or_default()
                        .push(argument);
                }
            }
        }
        let mut module_bindings = HashSet::default();
        let mut changed = true;
        while changed {
            changed = false;
            for call in &calls {
                let Some(callee) = call.child_by_field_name("function") else {
                    continue;
                };
                let Some(function) = unique_function(callee, source, lexical, &values, &inert_vars)
                else {
                    continue;
                };
                for (parameter, argument) in parameter_arguments(function, *call) {
                    if let Some(object) = module_object(
                        argument,
                        source,
                        lexical,
                        &values,
                        &inert_vars,
                        &module_bindings,
                    ) {
                        changed |= module_bindings.insert((parameter.start_byte(), object));
                    }
                }
            }
        }
        let mut objects = Self {
            exports: HashSet::default(),
        };
        for receiver in receivers {
            if receiver.kind() == "identifier" && !object_names.contains(slice(receiver, source)) {
                continue;
            }
            match module_object(
                receiver,
                source,
                lexical,
                &values,
                &inert_vars,
                &module_bindings,
            ) {
                Some(ModuleObject::Exports) => {
                    objects.exports.insert(receiver.id());
                }
                Some(ModuleObject::Module | ModuleObject::Ambiguous) | None => {}
            }
        }
        objects
    }

    pub fn is_exports(&self, node: Node<'_>) -> bool {
        self.exports.contains(&node.id())
    }
}

fn binding_token(
    node: Node<'_>,
    source: &str,
    lexical: &JsTsLexicalBindingIndex,
    inert_vars: &HashSet<usize>,
) -> Option<usize> {
    let name = slice(node, source);
    if lexical.is_binding_reassigned_at(name, node.start_byte()) {
        return None;
    }
    // The index already proves which declaration tokens share one binding.
    // Repeated no-initializer vars add no origin, but two effective seeds or
    // any unknown extra binder still cannot establish exact provenance.
    let binders = lexical.binding_identifier_ranges_at(name, node.start_byte());
    let mut seeds = binders
        .iter()
        .filter(|binder| !inert_vars.contains(&binder.start_byte));
    let seed = seeds.next()?;
    seeds.next().is_none().then_some(seed.start_byte)
}

fn unique_function<'tree>(
    node: Node<'tree>,
    source: &str,
    lexical: &JsTsLexicalBindingIndex,
    values: &HashMap<usize, Vec<Node<'tree>>>,
    inert_vars: &HashSet<usize>,
) -> Option<Node<'tree>> {
    let mut stack = vec![node];
    let mut seen = HashSet::default();
    let mut function = None;
    while let Some(node) = stack.pop() {
        let node = ts_unwrap_expression(node)?;
        if !seen.insert(node.id()) {
            return None;
        }
        match node.kind() {
            "function_expression" | "arrow_function" | "function_declaration" => {
                if function.is_some_and(|previous: Node<'_>| previous.id() != node.id()) {
                    return None;
                }
                function = Some(node);
            }
            "identifier" => {
                let token = binding_token(node, source, lexical, inert_vars)?;
                stack.extend(values.get(&token)?.iter().copied());
            }
            _ => return None,
        }
    }
    function
}

fn module_object(
    node: Node<'_>,
    source: &str,
    lexical: &JsTsLexicalBindingIndex,
    values: &HashMap<usize, Vec<Node<'_>>>,
    inert_vars: &HashSet<usize>,
    module_bindings: &HashSet<(usize, ModuleObject)>,
) -> Option<ModuleObject> {
    let mut current = node;
    let mut seen = HashSet::default();
    let mut through_exports = false;
    loop {
        let node = ts_unwrap_expression(current)?;
        if !seen.insert(node.id()) {
            return None;
        }
        match node.kind() {
            "identifier" => {
                let name = slice(node, source);
                let object = if !lexical.is_bound_at(name, node.start_byte()) {
                    match name {
                        "exports" => ModuleObject::Exports,
                        "module" => ModuleObject::Module,
                        _ => return None,
                    }
                } else {
                    let token = binding_token(node, source, lexical, inert_vars)?;
                    if module_bindings.contains(&(token, ModuleObject::Ambiguous))
                        || (module_bindings.contains(&(token, ModuleObject::Exports))
                            && module_bindings.contains(&(token, ModuleObject::Module)))
                    {
                        ModuleObject::Ambiguous
                    } else if let Some(object) = [ModuleObject::Exports, ModuleObject::Module]
                        .into_iter()
                        .find(|object| module_bindings.contains(&(token, *object)))
                    {
                        object
                    } else {
                        let origins = values.get(&token)?;
                        if origins.len() != 1 {
                            return None;
                        }
                        current = origins[0];
                        continue;
                    }
                };
                return if through_exports {
                    match object {
                        ModuleObject::Module => Some(ModuleObject::Exports),
                        ModuleObject::Ambiguous => Some(ModuleObject::Ambiguous),
                        ModuleObject::Exports => None,
                    }
                } else {
                    Some(object)
                };
            }
            "member_expression"
                if !through_exports
                    && node
                        .child_by_field_name("property")
                        .is_some_and(|property| slice(property, source) == "exports") =>
            {
                through_exports = true;
                current = node.child_by_field_name("object")?;
            }
            _ => return None,
        }
    }
}

fn parameter_arguments<'tree>(
    function: Node<'tree>,
    call: Node<'tree>,
) -> Vec<(Node<'tree>, Node<'tree>)> {
    let parameters = if let Some(parameters) = function.child_by_field_name("parameters") {
        parameters
            .named_children(&mut parameters.walk())
            .filter(|node| node.kind() != "comment")
            .collect::<Vec<_>>()
    } else {
        function
            .child_by_field_name("parameter")
            .into_iter()
            .collect()
    };
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let arguments = arguments
        .named_children(&mut arguments.walk())
        .filter(|node| node.kind() != "comment")
        .collect::<Vec<_>>();
    let mut pairs = Vec::new();
    for (parameter, argument) in parameters.into_iter().zip(arguments) {
        // A spread shifts all following positions. Defaults and destructuring
        // require more than a direct argument-to-parameter proof.
        if argument.kind() == "spread_element" {
            break;
        }
        let parameter = if matches!(
            parameter.kind(),
            "required_parameter" | "optional_parameter"
        ) {
            if parameter.child_by_field_name("value").is_some() {
                continue;
            }
            parameter
                .child_by_field_name("pattern")
                .expect("parameter wrapper has a pattern")
        } else {
            parameter
        };
        if parameter.kind() == "identifier" {
            pairs.push((parameter, argument));
        }
    }
    pairs
}
