//! Structured lexical bindings introduced by C function-like macros.
//!
//! Tree-sitter keeps a function-like replacement as one preprocessor argument,
//! so the replacement is reparsed in the resolver's source-preserving
//! sentinel.  This module only uses the resulting AST nodes and byte ranges;
//! it never recovers a binding by searching replacement text.

use super::resolver::{
    MacroLexicalBinding, MacroLexicalBindingKind, MacroLexicalReferences, MacroLocalBinding,
    ParsedReplacementBody, VisibilityIndex, argument_children, declaration_declarator,
    declarator_name_node, declared_name_binding, extract_variable_name, macro_type_argument_node,
};
use crate::declarations::node_text;
use crate::graph::syntax::function_macro_replacement_span;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::tree_walk::push_named_children_reversed;
use std::collections::HashMap;
use std::ops::Range;
use tree_sitter::Node;

const MAX_MACRO_LEXICAL_NODES: usize = 250_000;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ScopeKey {
    start: usize,
    end: usize,
    kind: String,
}

#[derive(Clone)]
struct LocalTemplate {
    name: String,
    name_range: Range<usize>,
    declaration_range: Range<usize>,
    scope: ScopeKey,
    type_name: String,
    pointer_depth: i32,
}

#[derive(Clone)]
struct BodyBinding {
    name: String,
    binding: MacroLexicalBinding,
    type_name: String,
    pointer_depth: i32,
}

#[derive(Clone, Default)]
pub(crate) struct MacroTemplate {
    parameters: Vec<String>,
    references: Vec<(Range<usize>, MacroLexicalBinding)>,
    formal_locals: HashMap<usize, Vec<BodyBinding>>,
    escaped_locals: Vec<BodyBinding>,
    declarations: Vec<(Range<usize>, MacroLexicalBinding)>,
}

pub(crate) fn binding(
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    root: Node<'_>,
    source: &str,
    start_byte: usize,
    end_byte: usize,
) -> Option<MacroLexicalBinding> {
    if start_byte >= end_byte || end_byte > source.len() {
        return None;
    }
    let mut found = Vec::new();
    let mut cancelled = || false;
    let result = references(
        || visibility,
        file,
        root,
        source,
        usize::MAX,
        &mut cancelled,
        Some(start_byte..end_byte),
        &mut found,
    );
    if result.cancelled || result.truncated {
        return None;
    }
    if let Some(binding) = found
        .into_iter()
        .find(|(range, _)| start_byte >= range.start && end_byte <= range.end)
        .map(|(_, binding)| binding)
    {
        return Some(binding);
    }

    // Definition spellings are intentionally omitted from the inverse list,
    // but goto-definition may start on one of those spellings. Keep the
    // declaration check structurally separate from reference enumeration.
    let mut stack = vec![root];
    while let Some(definition) = stack.pop() {
        if definition.kind() == "preproc_function_def"
            && let Some(template) = definition_template(visibility, file, definition, source)
            && let Some((_, binding)) = template
                .declarations
                .into_iter()
                .find(|(range, _)| start_byte >= range.start && end_byte <= range.end)
        {
            return Some(binding);
        }
        if definition.kind() == "call_expression"
            && let Some(function) = definition
                .child_by_field_name("function")
                .filter(|node| node.kind() == "identifier")
            && let Some((definition_file, definition_byte)) = visibility.function_macro_binding_at(
                file,
                node_text(function, source),
                definition.start_byte(),
            )
            && let Some(template) =
                active_definition_template(visibility, &definition_file, definition_byte)
            && let Some(arguments) = definition.child_by_field_name("arguments")
        {
            let actuals = argument_children(arguments).collect::<Vec<_>>();
            if actuals.len() == template.parameters.len() {
                for local in template
                    .escaped_locals
                    .iter()
                    .chain(template.formal_locals.values().flatten())
                {
                    if let Some(instantiated) = instantiate_binding(
                        local,
                        &template.parameters,
                        &actuals,
                        source,
                        file,
                        definition,
                    ) && instantiated.binding.definition == *file
                        && start_byte >= instantiated.binding.name_range.start
                        && end_byte <= instantiated.binding.name_range.end
                    {
                        return Some(instantiated.binding);
                    }
                }
            }
        }
        push_named_children_reversed(definition, &mut stack);
    }
    None
}

pub(crate) fn all_references<'visibility, 'source: 'visibility, Factory>(
    visibility: Factory,
    file: &ProjectFile,
    root: Node<'_>,
    source: &str,
    max_references: usize,
    mut cancelled: impl FnMut() -> bool,
) -> MacroLexicalReferences
where
    Factory: FnOnce() -> &'visibility VisibilityIndex<'source>,
{
    let mut records = Vec::new();
    let result = references(
        visibility,
        file,
        root,
        source,
        max_references,
        &mut cancelled,
        None,
        &mut records,
    );
    let mut references = result.references;
    references.extend(records);
    references.sort_by_key(|record| (record.0.start, record.0.end));
    references.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1);
    MacroLexicalReferences {
        references,
        truncated: result.truncated,
        cancelled: result.cancelled,
    }
}

struct ReferenceState {
    references: Vec<(Range<usize>, MacroLexicalBinding)>,
    truncated: bool,
    cancelled: bool,
}

#[allow(clippy::too_many_arguments)]
fn references<'visibility, 'source: 'visibility>(
    visibility: impl FnOnce() -> &'visibility VisibilityIndex<'source>,
    file: &ProjectFile,
    root: Node<'_>,
    source: &str,
    max_references: usize,
    cancelled: &mut impl FnMut() -> bool,
    focus: Option<Range<usize>>,
    output: &mut Vec<(Range<usize>, MacroLexicalBinding)>,
) -> ReferenceState {
    let mut state = ReferenceState {
        references: Vec::new(),
        truncated: false,
        cancelled: false,
    };
    let mut definitions = Vec::new();
    let mut calls = Vec::new();
    let mut stack = vec![root];
    let mut visited = 0usize;
    while let Some(node) = stack.pop() {
        visited += 1;
        if cancelled() {
            state.cancelled = true;
            return state;
        }
        if visited > MAX_MACRO_LEXICAL_NODES {
            state.truncated = true;
            return state;
        }
        match node.kind() {
            "preproc_function_def" => definitions.push(node),
            "call_expression"
                if node
                    .child_by_field_name("function")
                    .is_some_and(|function| function.kind() == "identifier") =>
            {
                calls.push(node)
            }
            _ => {}
        }
        push_named_children_reversed(node, &mut stack);
    }

    if definitions.is_empty() && calls.is_empty() {
        return state;
    }
    let visibility = visibility();

    // A definition's formal references are source-backed even when no
    // invocation is present in this file.  This is intentionally restricted
    // to definitions in the supplied source tree; included definitions are
    // visited when their own file is scanned.
    for definition in definitions.iter().copied() {
        if cancelled() {
            state.cancelled = true;
            return state;
        }
        let Some(template) = definition_template(visibility, file, definition, source) else {
            continue;
        };
        for record in template.references {
            if focus
                .as_ref()
                .is_none_or(|range| ranges_overlap(range, &record.0))
                && !push_record(output, record, max_references)
            {
                state.truncated = true;
                return state;
            }
        }
    }

    // Invocation arguments inherit the replacement scope at each formal use.
    // The actual's own declarations remain ordinary lexical bindings and are
    // therefore excluded when one is structurally visible at the use.
    for call in calls.iter().copied() {
        if cancelled() {
            state.cancelled = true;
            return state;
        }
        let Some(function) = call.child_by_field_name("function") else {
            continue;
        };
        let function_name = node_text(function, source);
        let Some((definition_file, definition_byte)) =
            visibility.function_macro_binding_at(file, function_name, call.start_byte())
        else {
            continue;
        };
        let Some(template) =
            active_definition_template(visibility, &definition_file, definition_byte)
        else {
            continue;
        };
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let actuals = argument_children(arguments).collect::<Vec<_>>();
        if actuals.len() != template.parameters.len() {
            continue;
        }
        let instantiate = |binding: &BodyBinding| {
            instantiate_binding(binding, &template.parameters, &actuals, source, file, call)
        };
        for (index, actual) in actuals.iter().copied().enumerate() {
            if focus
                .as_ref()
                .is_some_and(|range| !ranges_overlap(range, &actual.byte_range()))
            {
                continue;
            }
            let Some(bindings) = template.formal_locals.get(&index) else {
                continue;
            };
            let bindings = bindings.iter().filter_map(instantiate).collect::<Vec<_>>();
            let mut actual_stack = vec![actual];
            while let Some(node) = actual_stack.pop() {
                if cancelled() {
                    state.cancelled = true;
                    return state;
                }
                if is_identifier_node(node)
                    && let Some(binding) =
                        unique_binding_for_name(&bindings, node_text(node, source))
                    && !is_declaration_name_in(node, actual)
                    && !actual_has_prior_declaration(actual, node, source, &binding.name)
                {
                    let range = node.start_byte()..node.end_byte();
                    if focus
                        .as_ref()
                        .is_none_or(|focused| ranges_overlap(focused, &range))
                        && !push_record(output, (range, binding.binding), max_references)
                    {
                        state.truncated = true;
                        return state;
                    }
                }
                push_named_children_reversed(node, &mut actual_stack);
            }
        }

        // A declaration at the replacement body's synthetic top level is in
        // the caller's scope after expansion.  Find later references in the
        // same AST scope and retain the nearest preceding macro invocation.
        if !template.escaped_locals.is_empty()
            && call
                .parent()
                .is_some_and(|parent| parent.kind() == "expression_statement")
        {
            collect_escaped_references(
                visibility,
                file,
                root,
                source,
                call,
                &template
                    .escaped_locals
                    .iter()
                    .filter_map(instantiate)
                    .collect::<Vec<_>>(),
                focus.as_ref(),
                max_references,
                cancelled,
                output,
                &mut state,
            );
            if state.cancelled || state.truncated {
                return state;
            }
        }
    }
    state
}

fn definition_template(
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    definition: Node<'_>,
    source: &str,
) -> Option<MacroTemplate> {
    let key = (file.clone(), definition.start_byte());
    if let Some(template) = visibility
        .macro_lexical_templates
        .lock()
        .expect("macro lexical template cache poisoned")
        .get(&key)
    {
        return template.clone();
    }
    let template = (|| {
        let body = visibility.function_macro_replacement_body(file, definition, source)?;
        let replacement_start = function_macro_replacement_span(definition, source)?.start;
        build_template(file, definition, source, &body, replacement_start)
    })();
    visibility
        .macro_lexical_templates
        .lock()
        .expect("macro lexical template cache poisoned")
        .insert(key, template.clone());
    template
}

fn active_definition_template(
    visibility: &VisibilityIndex<'_>,
    definition_file: &ProjectFile,
    definition_byte: usize,
) -> Option<MacroTemplate> {
    let prepared = visibility
        .cpp()
        .prepared_syntax(visibility.token(), definition_file)?;
    let source = prepared.source();
    let definition = find_definition(prepared.tree().root_node(), definition_byte)?;
    definition_template(visibility, definition_file, definition, source)
}

fn find_definition(root: Node<'_>, byte: usize) -> Option<Node<'_>> {
    let end = byte.saturating_add(1).min(root.end_byte());
    let mut current = root.descendant_for_byte_range(byte.min(end), end)?;
    loop {
        if current.kind() == "preproc_function_def" {
            return Some(current);
        }
        current = current.parent()?;
    }
}

fn build_template(
    definition_file: &ProjectFile,
    definition: Node<'_>,
    definition_source: &str,
    body: &ParsedReplacementBody,
    replacement_start: usize,
) -> Option<MacroTemplate> {
    let statements = body.statements()?;
    let formal_nodes = definition
        .child_by_field_name("parameters")
        .map(|parameters| {
            (0..parameters.named_child_count())
                .filter_map(|index| parameters.named_child(index))
                .filter_map(|node| {
                    let name = node_text(node, definition_source).trim();
                    (!name.is_empty()).then(|| (name.to_owned(), node))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let formal_by_name = formal_nodes
        .iter()
        .enumerate()
        .map(|(index, (name, _))| (name.as_str(), index))
        .collect::<HashMap<_, _>>();
    let mut locals = Vec::new();
    let mut stack = vec![statements];
    while let Some(node) = stack.pop() {
        if node.kind() == "declaration" {
            let scope = scope_key(node, statements);
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                let Some(declarator) = declaration_declarator(node, child) else {
                    continue;
                };
                let Some(name_node) = declarator_name_node(declarator) else {
                    continue;
                };
                let Some(name) = extract_variable_name(declarator, &body.source) else {
                    continue;
                };
                locals.push(LocalTemplate {
                    name: name.clone(),
                    name_range: body.file_range(name_node, replacement_start),
                    declaration_range: body.file_range(node, replacement_start),
                    scope: scope.clone(),
                    type_name: node
                        .child_by_field_name("type")
                        .map(|ty| node_text(ty, &body.source).to_owned())
                        .unwrap_or_default(),
                    pointer_depth: node
                        .child_by_field_name("type")
                        .and_then(|ty| declared_name_binding(node, ty, &name, &body.source))
                        .map_or(0, |binding| binding.pointer_depth),
                });
            }
        }
        push_named_children_reversed(node, &mut stack);
    }

    let mut template = MacroTemplate {
        parameters: formal_nodes.iter().map(|(name, _)| name.clone()).collect(),
        ..MacroTemplate::default()
    };
    for (name, formal) in &formal_nodes {
        let binding = MacroLexicalBinding {
            definition: definition_file.clone(),
            kind: MacroLexicalBindingKind::Parameter,
            name: name.clone(),
            name_range: formal.start_byte()..formal.end_byte(),
            declaration_range: formal.start_byte()..formal.end_byte(),
        };
        template
            .declarations
            .push((formal.start_byte()..formal.end_byte(), binding));
    }
    let mut stack = vec![statements];
    while let Some(node) = stack.pop() {
        if (is_identifier_node(node) || node.kind() == "field_identifier")
            && !is_declaration_name_in(node, statements)
        {
            let name = node_text(node, &body.source);
            let scope = scope_key(node, statements);
            let local = locals
                .iter()
                .filter(|local| {
                    is_identifier_node(node)
                        && local.name == name
                        && local.name_range.start < body.file_range(node, replacement_start).start
                        && scope_contains(&local.scope, &scope)
                })
                .max_by_key(|local| local.scope.start);
            let body_range = body.file_range(node, replacement_start);
            if let Some(local) = local {
                let binding = body_binding(definition_file, local);
                template
                    .references
                    .push((body_range, binding.binding.clone()));
            } else if let Some(index) = formal_by_name.get(name).copied() {
                let (_, formal) = &formal_nodes[index];
                template.references.push((
                    body_range.clone(),
                    MacroLexicalBinding {
                        definition: definition_file.clone(),
                        kind: MacroLexicalBindingKind::Parameter,
                        name: name.to_owned(),
                        name_range: formal.start_byte()..formal.end_byte(),
                        declaration_range: formal.start_byte()..formal.end_byte(),
                    },
                ));

                // The actual argument is substituted at this formal's
                // lexical position. Every local visible there is therefore
                // also visible to identifiers written in that argument.
                if node.kind() == "field_identifier" {
                    continue;
                }
                let mut visible = HashMap::new();
                for local in locals.iter().filter(|local| {
                    local.name_range.start < body_range.start
                        && scope_contains(&local.scope, &scope)
                }) {
                    let entry = visible.entry(local.name.as_str()).or_insert(local);
                    if (local.scope.start, local.name_range.start)
                        > (entry.scope.start, entry.name_range.start)
                    {
                        *entry = local;
                    }
                }
                for local in visible.into_values() {
                    template
                        .formal_locals
                        .entry(index)
                        .or_default()
                        .push(body_binding(definition_file, local));
                }
            }
        }
        push_named_children_reversed(node, &mut stack);
    }
    for local in locals {
        let binding = body_binding(definition_file, &local);
        template
            .declarations
            .push((binding.binding.name_range.clone(), binding.binding.clone()));
        if local.scope == scope_key(statements, statements) {
            template.escaped_locals.push(binding);
        }
    }
    Some(template)
}

fn body_binding(definition_file: &ProjectFile, local: &LocalTemplate) -> BodyBinding {
    BodyBinding {
        name: local.name.clone(),
        type_name: local.type_name.clone(),
        pointer_depth: local.pointer_depth,
        binding: MacroLexicalBinding {
            definition: definition_file.clone(),
            kind: MacroLexicalBindingKind::Local,
            name: local.name.clone(),
            name_range: local.name_range.clone(),
            declaration_range: local.declaration_range.clone(),
        },
    }
}

fn scope_key(node: Node<'_>, body: Node<'_>) -> ScopeKey {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.id() == body.id() {
            return ScopeKey {
                start: body.start_byte(),
                end: body.end_byte(),
                kind: "macro_body".to_owned(),
            };
        }
        if is_scope_node(candidate) {
            return ScopeKey {
                start: candidate.start_byte(),
                end: candidate.end_byte(),
                kind: candidate.kind().to_owned(),
            };
        }
        current = candidate.parent();
    }
    ScopeKey {
        start: body.start_byte(),
        end: body.end_byte(),
        kind: "macro_body".to_owned(),
    }
}

fn is_scope_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "compound_statement"
            | "for_statement"
            | "for_range_loop"
            | "while_statement"
            | "do_statement"
            | "if_statement"
            | "switch_statement"
            | "lambda_expression"
    )
}

fn scope_contains(outer: &ScopeKey, inner: &ScopeKey) -> bool {
    outer.start <= inner.start && outer.end >= inner.end
}

fn unique_binding_for_name(bindings: &[BodyBinding], name: &str) -> Option<BodyBinding> {
    let mut matching = bindings.iter().filter(|binding| binding.name == name);
    let first = matching.next()?.clone();
    matching
        .all(|binding| binding.binding == first.binding)
        .then_some(first)
}

#[allow(clippy::too_many_arguments)]
fn collect_escaped_references(
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    root: Node<'_>,
    source: &str,
    call: Node<'_>,
    locals: &[BodyBinding],
    focus: Option<&Range<usize>>,
    max_references: usize,
    cancelled: &mut impl FnMut() -> bool,
    output: &mut Vec<(Range<usize>, MacroLexicalBinding)>,
    state: &mut ReferenceState,
) {
    let call_scope = scope_key(call, root);
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if cancelled() {
            state.cancelled = true;
            return;
        }
        if is_identifier_node(node)
            && node.start_byte() > call.end_byte()
            && scope_contains(&call_scope, &scope_key(node, root))
            && !is_declaration_name_in(node, root)
        {
            let name = node_text(node, source);
            if let Some(local) = locals.iter().find(|local| local.name == name)
                && !has_intervening_declaration(visibility, file, root, call, node, source, name)
            {
                let range = node.start_byte()..node.end_byte();
                if focus.is_none_or(|focused| ranges_overlap(focused, &range))
                    && !push_record(output, (range, local.binding.clone()), max_references)
                {
                    state.truncated = true;
                    return;
                }
            }
        }
        push_named_children_reversed(node, &mut stack);
    }
}

fn has_intervening_declaration(
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    root: Node<'_>,
    call: Node<'_>,
    target: Node<'_>,
    source: &str,
    name: &str,
) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() <= call.end_byte() || node.start_byte() >= target.start_byte() {
            push_named_children_reversed(node, &mut stack);
            continue;
        }
        if node.kind() == "declaration"
            && declaration_has_name(node, source, name)
            && scope_contains(&scope_key(node, root), &scope_key(target, root))
        {
            return true;
        }
        if node.kind() == "call_expression"
            && scope_contains(&scope_key(node, root), &scope_key(target, root))
            && let Some(function) = node
                .child_by_field_name("function")
                .filter(|function| function.kind() == "identifier")
            && let Some((definition_file, definition_byte)) = visibility.function_macro_binding_at(
                file,
                node_text(function, source),
                node.start_byte(),
            )
            && let Some(template) =
                active_definition_template(visibility, &definition_file, definition_byte)
            && let Some(arguments) = node.child_by_field_name("arguments")
        {
            let actuals = argument_children(arguments).collect::<Vec<_>>();
            if actuals.len() == template.parameters.len()
                && template
                    .escaped_locals
                    .iter()
                    .filter_map(|local| {
                        instantiate_binding(
                            local,
                            &template.parameters,
                            &actuals,
                            source,
                            file,
                            node,
                        )
                    })
                    .any(|local| local.name == name)
            {
                return true;
            }
        }
        push_named_children_reversed(node, &mut stack);
    }
    false
}

fn actual_has_prior_declaration(
    actual: Node<'_>,
    target: Node<'_>,
    source: &str,
    name: &str,
) -> bool {
    let target_scope = scope_key(target, actual);
    let mut stack = vec![actual];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= target.start_byte() {
            continue;
        }
        if node.kind() == "declaration"
            && declaration_has_name(node, source, name)
            && scope_contains(&scope_key(node, actual), &target_scope)
        {
            return true;
        }
        push_named_children_reversed(node, &mut stack);
    }
    false
}

fn declaration_has_name(node: Node<'_>, source: &str, expected: &str) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).any(|child| {
        declaration_declarator(node, child)
            .and_then(|declarator| extract_variable_name(declarator, source))
            .is_some_and(|name| name == expected)
    })
}

fn is_declaration_name_in(node: Node<'_>, scope: Node<'_>) -> bool {
    let mut current = Some(node);
    while let Some(parent) = current.and_then(|current| current.parent()) {
        if parent.kind() == "declaration" {
            let mut cursor = parent.walk();
            if parent.named_children(&mut cursor).any(|child| {
                declaration_declarator(parent, child)
                    .and_then(declarator_name_node)
                    .is_some_and(|name| name.id() == node.id())
            }) {
                return true;
            }
        }
        if parent.id() == scope.id() {
            break;
        }
        current = Some(parent);
    }
    false
}

fn is_identifier_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "type_identifier" | "namespace_identifier"
    )
}

fn ranges_overlap(left: &Range<usize>, right: &Range<usize>) -> bool {
    left.start < right.end && right.start < left.end
}

fn push_record(
    output: &mut Vec<(Range<usize>, MacroLexicalBinding)>,
    record: (Range<usize>, MacroLexicalBinding),
    max_references: usize,
) -> bool {
    if output.len() >= max_references {
        return false;
    }
    output.push(record);
    true
}

fn instantiate_binding(
    binding: &BodyBinding,
    parameters: &[String],
    actuals: &[Node<'_>],
    source: &str,
    file: &ProjectFile,
    call: Node<'_>,
) -> Option<BodyBinding> {
    let mut instantiated = binding.clone();
    if let Some(index) = parameters.iter().position(|name| name == &binding.name) {
        let actual = *actuals.get(index)?;
        if actual.kind() != "identifier" {
            return None;
        }
        instantiated.name = node_text(actual, source).to_owned();
        instantiated.binding.name = instantiated.name.clone();
        instantiated.binding.definition = file.clone();
        instantiated.binding.name_range = actual.byte_range();
        instantiated.binding.declaration_range = call.byte_range();
    }
    Some(instantiated)
}

/// Instantiate the declared type of the macro-local binding visible at one
/// source reference. Type formal nodes retain their invocation syntax; fixed
/// type spellings come from the parsed declaration, not a source-text parser.
pub(crate) fn typed_binding<'tree>(
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    root: Node<'tree>,
    source: &str,
    start: usize,
    end: usize,
) -> Option<MacroLocalBinding<'tree>> {
    let lexical = binding(visibility, file, root, source, start, end)?;
    let target = root.descendant_for_byte_range(start, end)?;
    if lexical.kind != MacroLexicalBindingKind::Local {
        return None;
    }
    let mut stack = vec![root];
    let mut candidates = Vec::new();
    while let Some(call) = stack.pop() {
        push_named_children_reversed(call, &mut stack);
        if call.kind() != "call_expression" {
            continue;
        }
        let Some(function) = call
            .child_by_field_name("function")
            .filter(|node| node.kind() == "identifier")
        else {
            continue;
        };
        let Some((definition_file, definition_byte)) = visibility.function_macro_binding_at(
            file,
            node_text(function, source),
            call.start_byte(),
        ) else {
            continue;
        };
        let Some(template) =
            active_definition_template(visibility, &definition_file, definition_byte)
        else {
            continue;
        };
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let actuals = argument_children(arguments).collect::<Vec<_>>();
        if actuals.len() != template.parameters.len() {
            continue;
        }
        let matches_lexical = |local: &&BodyBinding| {
            instantiate_binding(local, &template.parameters, &actuals, source, file, call)
                .is_some_and(|binding| binding.binding == lexical)
        };
        let local = if let Some(index) = actuals
            .iter()
            .position(|actual| actual.start_byte() <= start && actual.end_byte() >= end)
        {
            template
                .formal_locals
                .get(&index)
                .into_iter()
                .flatten()
                .find(matches_lexical)
        } else if call.end_byte() < start
            && scope_contains(&scope_key(call, root), &scope_key(target, root))
        {
            template.escaped_locals.iter().find(matches_lexical)
        } else {
            None
        };
        let Some(local) = local else {
            continue;
        };
        let (type_name, type_node) = if let Some(index) = template
            .parameters
            .iter()
            .position(|name| name == &local.type_name)
        {
            let actual = macro_type_argument_node(actuals[index], source)?;
            (node_text(actual, source).to_owned(), Some(actual))
        } else {
            (local.type_name.clone(), None)
        };
        candidates.push((
            call.start_byte(),
            MacroLocalBinding {
                name: lexical.name.clone(),
                type_name,
                type_node,
                pointer_depth: local.pointer_depth,
                proven_unit: None,
            },
        ));
    }
    candidates
        .into_iter()
        .max_by_key(|(byte, _)| *byte)
        .map(|(_, binding)| binding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_free_scan_does_not_construct_visibility() {
        let source = "struct Owner { int value; };";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = std::env::current_dir().unwrap();
        let file = ProjectFile::new(&root, "owner.cpp");
        let result = all_references(
            || panic!("candidate-free scan must not construct visibility"),
            &file,
            tree.root_node(),
            source,
            100,
            || false,
        );
        assert!(result.references.is_empty());
        assert!(!result.cancelled);
        assert!(!result.truncated);
    }

    #[test]
    fn cancelled_scan_does_not_construct_visibility() {
        let source = "#define USE(value) value\nvoid caller() { USE(1); }";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = std::env::current_dir().unwrap();
        let file = ProjectFile::new(&root, "use.c");
        let result = all_references(
            || panic!("cancelled scan must not construct visibility"),
            &file,
            tree.root_node(),
            source,
            100,
            || true,
        );
        assert!(result.references.is_empty());
        assert!(result.cancelled);
        assert!(!result.truncated);
    }
}
