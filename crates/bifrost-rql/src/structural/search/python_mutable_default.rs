//! Query-time facts for mutations that can change a Python mutable parameter default.

use super::python_rule_facts::{
    call_name, contains_alias, direct_identifier, in_control_branch, make_row, named_children,
    node_text, parameter_name, parse_python, python_definition_node, row_range, scope_nodes,
};
use super::*;
use tree_sitter::Node;

const RELATION: &str = "modification_of_default_value";
const REASON: &str = "python_modification_of_default_value_incomplete";

#[derive(Clone, Copy)]
enum CollectionKind {
    List,
    Dictionary,
    Set,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Emptiness {
    Empty,
    NonEmpty,
    Unknown,
}

struct MutableDefault {
    name: String,
    kind: CollectionKind,
    emptiness: Emptiness,
}

struct MutableDefaultFlow<'a, 'tree> {
    incompleteness: Incompleteness,
    source: &'a str,
    aliases: HashMap<String, HashSet<usize>>,
    defaults: &'a [MutableDefault],
    uncertain_sources: HashSet<usize>,
    function: Node<'tree>,
    reasons: Vec<&'static str>,
    expansions: Vec<PipelineExpansion>,
    emitted: HashSet<String>,
    mutations: Vec<(Node<'tree>, usize, bool, bool, bool)>,
}

pub(super) fn expansions(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    cancellation: Option<&CancellationToken>,
) -> Vec<PipelineExpansion> {
    let unit = &declaration.unit;
    if crate::analyzer::common::language_for_file(unit.source())
        != crate::analyzer::Language::Python
        || !unit.is_function()
    {
        return Vec::new();
    }

    let file = unit.source();
    let Some(source) = analyzer.get_source(&CodeUnit::file_scope(file.clone()), false) else {
        return vec![open_fact(
            Incompleteness::Operational(DerivationExecutionCause::Provider),
            file,
            declaration,
            None,
            "source_unavailable",
        )];
    };
    let Some(tree) = parse_python(&source) else {
        return vec![open_fact(
            Incompleteness::Operational(DerivationExecutionCause::Provider),
            file,
            declaration,
            Some(&source),
            "syntax_unavailable",
        )];
    };
    if tree.root_node().has_error() {
        return vec![open_fact(
            Incompleteness::Content,
            file,
            declaration,
            Some(&source),
            "recovered_python_syntax",
        )];
    }
    let Some(function) = python_definition_node(&tree, unit, &declaration.range) else {
        return vec![open_fact(
            Incompleteness::Content,
            file,
            declaration,
            Some(&source),
            "function_range_unavailable",
        )];
    };
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return vec![open_fact(
            Incompleteness::Content,
            file,
            declaration,
            Some(&source),
            "parameters_unavailable",
        )];
    };
    let sources = named_children(parameters)
        .into_iter()
        .filter_map(|parameter| {
            let default = parameter.child_by_field_name("value")?;
            let (kind, emptiness) = mutable_default(default)?;
            let name = parameter_name(parameter, &source)?;
            Some(MutableDefault {
                name,
                kind,
                emptiness,
            })
        })
        .collect::<Vec<_>>();
    if sources.is_empty() {
        return Vec::new();
    }
    let Some(body) = function.child_by_field_name("body") else {
        return vec![open_fact(
            Incompleteness::Content,
            file,
            declaration,
            Some(&source),
            "function_body_unavailable",
        )];
    };

    let mut aliases = HashMap::<String, HashSet<usize>>::default();
    for (source_index, default) in sources.iter().enumerate() {
        aliases
            .entry(default.name.clone())
            .or_default()
            .insert(source_index);
    }
    let mut events = scope_nodes(body)
        .into_iter()
        .filter(|node| {
            matches!(
                node.kind(),
                "assignment"
                    | "annotated_assignment"
                    | "augmented_assignment"
                    | "named_expression"
                    | "call"
                    | "delete_statement"
                    | "return_statement"
                    | "yield"
                    | "function_definition"
                    | "lambda"
            )
        })
        .collect::<Vec<_>>();
    events.sort_by_key(|node| (node.end_byte(), node.start_byte()));

    let mut flow = MutableDefaultFlow {
        incompleteness: Incompleteness::Content,
        source: &source,
        aliases,
        defaults: &sources,
        uncertain_sources: HashSet::default(),
        function,
        reasons: Vec::new(),
        expansions: Vec::new(),
        emitted: HashSet::default(),
        mutations: Vec::new(),
    };

    for event in events {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            flow.incompleteness = Incompleteness::Operational(DerivationExecutionCause::Cancelled);
            flow.reasons.push("cancelled");
            break;
        }
        match event.kind() {
            "assignment" | "annotated_assignment" | "named_expression" => {
                let left = event
                    .child_by_field_name("left")
                    .or_else(|| event.child_by_field_name("name"));
                let right = event
                    .child_by_field_name("right")
                    .or_else(|| event.child_by_field_name("value"));
                if let Some(left) = left {
                    record_subscript_mutations(left, event, &mut flow);
                    if left.kind() == "identifier" {
                        let Some(name) = node_text(flow.source, left) else {
                            flow.reasons.push("assignment_name_unresolved");
                            continue;
                        };
                        let new_sources = right
                            .and_then(|right| direct_identifier(right, flow.source))
                            .and_then(|right_name| flow.aliases.get(right_name))
                            .cloned()
                            .unwrap_or_default();
                        let old_sources = flow.aliases.get(name).cloned().unwrap_or_default();
                        if in_control_branch(event, flow.function)
                            && (!new_sources.is_empty() || !old_sources.is_empty())
                        {
                            for source_index in old_sources.union(&new_sources) {
                                flow.uncertain_sources.insert(*source_index);
                            }
                            flow.reasons.push("conditional_local_rebinding");
                            flow.aliases
                                .entry(name.to_owned())
                                .or_default()
                                .extend(new_sources);
                        } else {
                            flow.aliases.remove(name);
                            if !new_sources.is_empty() {
                                flow.aliases.insert(name.to_owned(), new_sources);
                            } else if right.is_some_and(|right| {
                                contains_alias(right, flow.source, &alias_names(&flow.aliases))
                                    && !is_copy_expression(right, flow.source, &flow.aliases)
                            }) {
                                flow.reasons.push("unresolved_local_assignment_flow");
                                flow.uncertain_sources.extend(old_sources);
                            }
                        }
                    } else if right.is_some_and(|right| {
                        contains_alias(right, flow.source, &alias_names(&flow.aliases))
                    }) {
                        flow.reasons.push("default_value_escapes_through_store");
                        flow.uncertain_sources
                            .extend(flow.aliases.values().flatten().copied());
                    }
                } else {
                    flow.reasons.push("assignment_target_unavailable");
                }
            }
            "augmented_assignment" => {
                if let Some(target) = event.child_by_field_name("left") {
                    if target.kind() == "identifier" {
                        emit_for_name(target, event, &mut flow);
                    }
                } else {
                    flow.reasons.push("augmented_assignment_shape_unresolved");
                }
            }
            "delete_statement" => {
                for target in named_children(event) {
                    if target.kind() == "identifier" {
                        if let Some(name) = node_text(flow.source, target) {
                            let old_sources = flow.aliases.get(name).cloned().unwrap_or_default();
                            if in_control_branch(event, flow.function) && !old_sources.is_empty() {
                                flow.uncertain_sources.extend(old_sources);
                                flow.reasons.push("conditional_local_rebinding");
                            } else {
                                flow.aliases.remove(name);
                            }
                        }
                    } else {
                        record_subscript_mutations(target, event, &mut flow);
                    }
                }
            }
            "call" => analyze_call(event, &mut flow),
            "return_statement" | "yield" | "function_definition" | "lambda" => {
                let names = alias_names(&flow.aliases);
                if contains_alias(event, flow.source, &names) {
                    flow.reasons.push(
                        if matches!(event.kind(), "function_definition" | "lambda") {
                            "default_value_captured_by_nested_scope"
                        } else {
                            "default_value_escapes_function"
                        },
                    );
                }
            }
            _ => unreachable!("mutable-default event list contains known node kinds"),
        }
    }

    let mut reachable = flow
        .defaults
        .iter()
        .map(|default| {
            (
                default.emptiness != Emptiness::NonEmpty,
                default.emptiness != Emptiness::Empty,
            )
        })
        .collect::<Vec<_>>();
    loop {
        let mut changed = false;
        for (_, index, excludes_empty, excludes_nonempty, cannot_empty) in &flow.mutations {
            let (empty, nonempty) = reachable[*index];
            if empty && !excludes_empty && !nonempty {
                reachable[*index].1 = true;
                changed = true;
            }
            if nonempty && !excludes_nonempty && !cannot_empty && !empty {
                reachable[*index].0 = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for (operation, index, excludes_empty, excludes_nonempty, _) in &flow.mutations {
        let (empty, nonempty) = reachable[*index];
        if flow.defaults[*index].emptiness == Emptiness::Unknown
            || (empty && !excludes_empty)
            || (nonempty && !excludes_nonempty)
        {
            emit_mutation(
                *operation,
                &source,
                file,
                declaration,
                &mut flow.expansions,
                &mut flow.emitted,
            );
        }
    }

    flow.reasons.sort_unstable();
    flow.reasons.dedup();
    if !flow.reasons.is_empty() {
        let reason = flow.reasons.join(", ");
        flow.expansions.push(open_fact(
            flow.incompleteness,
            file,
            declaration,
            Some(&source),
            &reason,
        ));
    }
    flow.expansions
}

fn mutable_default(expression: Node<'_>) -> Option<(CollectionKind, Emptiness)> {
    let mut expression = expression;
    while expression.kind() == "parenthesized_expression" {
        expression = expression.named_child(0)?;
    }
    let kind = match expression.kind() {
        "list" | "list_comprehension" => CollectionKind::List,
        "dictionary" | "dictionary_comprehension" => CollectionKind::Dictionary,
        "set" | "set_comprehension" => CollectionKind::Set,
        _ => return None,
    };
    let emptiness = match expression.kind() {
        "list" | "dictionary" | "set" => {
            if named_children(expression).is_empty() {
                Emptiness::Empty
            } else {
                Emptiness::NonEmpty
            }
        }
        _ => Emptiness::Unknown,
    };
    Some((kind, emptiness))
}

fn analyze_call<'tree>(call: Node<'tree>, flow: &mut MutableDefaultFlow<'_, 'tree>) {
    let names = alias_names(&flow.aliases);
    let call_target = call
        .child_by_field_name("function")
        .and_then(|target| target.kind().eq("attribute").then_some(target));
    let mut handled_receiver = false;
    if let Some(target) = call_target {
        let receiver = target
            .child_by_field_name("object")
            .and_then(|object| direct_identifier(object, flow.source));
        let method = target
            .child_by_field_name("attribute")
            .and_then(|attribute| node_text(flow.source, attribute));
        if let (Some(receiver), Some(method)) = (receiver, method)
            && let Some(source_indices) = flow.aliases.get(receiver)
        {
            handled_receiver = true;
            for source_index in source_indices {
                if flow.uncertain_sources.contains(source_index) {
                    continue;
                }
                if is_mutating_method(flow.defaults[*source_index].kind, method) {
                    flow.mutations.push((
                        call,
                        *source_index,
                        branch_excludes_mutation(
                            call,
                            flow.function,
                            flow.source,
                            &flow.aliases,
                            *source_index,
                            Emptiness::Empty,
                        ),
                        branch_excludes_mutation(
                            call,
                            flow.function,
                            flow.source,
                            &flow.aliases,
                            *source_index,
                            Emptiness::NonEmpty,
                        ),
                        matches!(
                            method,
                            "append" | "add" | "insert" | "extend" | "update" | "setdefault"
                        ),
                    ));
                } else if !is_known_read_method(flow.defaults[*source_index].kind, method) {
                    flow.reasons.push("unknown_receiver_method_flow");
                }
            }
        }
    }

    let arguments = call
        .child_by_field_name("arguments")
        .map(named_children)
        .unwrap_or_default();
    let aliases_in_arguments = arguments
        .iter()
        .any(|argument| contains_alias(*argument, flow.source, &names));
    if aliases_in_arguments && !handled_receiver {
        let function_name = call
            .child_by_field_name("function")
            .and_then(|target| call_name(target, flow.source));
        if !matches!(
            function_name,
            Some("len" | "bool" | "iter" | "repr" | "hash")
        ) && !is_copy_expression(call, flow.source, &flow.aliases)
        {
            flow.reasons.push("default_value_escapes_to_call");
        }
    }
}

fn record_subscript_mutations<'tree>(
    target: Node<'tree>,
    operation: Node<'tree>,
    flow: &mut MutableDefaultFlow<'_, 'tree>,
) {
    let mut stack = vec![target];
    while let Some(node) = stack.pop() {
        if node.kind() == "subscript"
            && let Some(object) = node
                .child_by_field_name("value")
                .or_else(|| node.child_by_field_name("object"))
            && direct_identifier(object, flow.source).is_some()
        {
            emit_for_name(object, operation, flow);
            continue;
        }
        stack.extend(named_children(node));
    }
}

fn emit_for_name<'tree>(
    identifier: Node<'tree>,
    operation: Node<'tree>,
    flow: &mut MutableDefaultFlow<'_, 'tree>,
) {
    let Some(name) = node_text(flow.source, identifier) else {
        return;
    };
    let Some(source_indices) = flow.aliases.get(name) else {
        return;
    };
    for source_index in source_indices {
        if !flow.uncertain_sources.contains(source_index) {
            flow.mutations.push((
                operation,
                *source_index,
                branch_excludes_mutation(
                    operation,
                    flow.function,
                    flow.source,
                    &flow.aliases,
                    *source_index,
                    Emptiness::Empty,
                ),
                branch_excludes_mutation(
                    operation,
                    flow.function,
                    flow.source,
                    &flow.aliases,
                    *source_index,
                    Emptiness::NonEmpty,
                ),
                operation.kind() == "assignment"
                    && operation.child_by_field_name("left").is_some_and(|left| {
                        left.kind() == "subscript"
                            && !named_children(left)
                                .iter()
                                .any(|node| node.kind() == "slice")
                    }),
            ));
        }
    }
}

fn branch_excludes_mutation(
    mutation: Node<'_>,
    function: Node<'_>,
    source: &str,
    aliases: &HashMap<String, HashSet<usize>>,
    source_index: usize,
    emptiness: Emptiness,
) -> bool {
    if emptiness == Emptiness::Unknown {
        return false;
    }
    let names = aliases
        .iter()
        .filter(|(_, indices)| indices.contains(&source_index))
        .map(|(name, _)| name.as_str())
        .collect::<HashSet<_>>();
    let mut node = mutation;
    while node != function {
        let Some(parent) = node.parent() else {
            break;
        };
        if matches!(parent.kind(), "if_statement" | "elif_clause")
            && let Some(condition) = parent.child_by_field_name("condition")
            && let Some(condition_implies_nonempty) =
                condition_nonempty_truth(condition, source, &names)
        {
            let consequence = parent.child_by_field_name("consequence");
            let alternative = parent.child_by_field_name("alternative");
            let in_consequence =
                consequence.is_some_and(|branch| is_descendant_or_same(node, branch));
            let in_alternative =
                alternative.is_some_and(|branch| is_descendant_or_same(node, branch));
            let branch_implies_nonempty = if in_consequence {
                Some(condition_implies_nonempty)
            } else if in_alternative {
                Some(!condition_implies_nonempty)
            } else {
                None
            };
            if branch_implies_nonempty.is_some_and(|nonempty| {
                (emptiness == Emptiness::Empty && nonempty)
                    || (emptiness == Emptiness::NonEmpty && !nonempty)
            }) {
                return true;
            }
        }
        node = parent;
    }
    false
}

fn condition_nonempty_truth(
    condition: Node<'_>,
    source: &str,
    aliases: &HashSet<&str>,
) -> Option<bool> {
    if let Some(name) = direct_identifier(condition, source) {
        return aliases.contains(name).then_some(true);
    }
    if condition.kind() == "not_operator" {
        let argument = condition
            .child_by_field_name("argument")
            .or_else(|| named_children(condition).into_iter().next())?;
        let name = direct_identifier(argument, source)?;
        return aliases.contains(name).then_some(false);
    }
    None
}

fn is_descendant_or_same(mut node: Node<'_>, ancestor: Node<'_>) -> bool {
    loop {
        if node == ancestor {
            return true;
        }
        let Some(parent) = node.parent() else {
            return false;
        };
        node = parent;
    }
}

fn is_mutating_method(kind: CollectionKind, method: &str) -> bool {
    match kind {
        CollectionKind::List => matches!(
            method,
            "append" | "extend" | "insert" | "remove" | "pop" | "clear" | "sort" | "reverse"
        ),
        CollectionKind::Dictionary => {
            matches!(
                method,
                "clear" | "pop" | "popitem" | "setdefault" | "update"
            )
        }
        CollectionKind::Set => matches!(
            method,
            "add"
                | "clear"
                | "difference_update"
                | "discard"
                | "intersection_update"
                | "pop"
                | "remove"
                | "symmetric_difference_update"
                | "update"
        ),
    }
}

fn is_known_read_method(kind: CollectionKind, method: &str) -> bool {
    match kind {
        CollectionKind::List => matches!(method, "copy" | "count" | "index"),
        CollectionKind::Dictionary => {
            matches!(method, "copy" | "get" | "items" | "keys" | "values")
        }
        CollectionKind::Set => matches!(
            method,
            "copy"
                | "difference"
                | "intersection"
                | "isdisjoint"
                | "issubset"
                | "issuperset"
                | "symmetric_difference"
                | "union"
        ),
    }
}

fn is_copy_expression(
    expression: Node<'_>,
    source: &str,
    aliases: &HashMap<String, HashSet<usize>>,
) -> bool {
    if expression.kind() != "call" {
        return false;
    }
    let Some(function) = expression.child_by_field_name("function") else {
        return false;
    };
    if function.kind() == "attribute" {
        let method = function
            .child_by_field_name("attribute")
            .and_then(|attribute| node_text(source, attribute));
        let receiver = function
            .child_by_field_name("object")
            .and_then(|object| direct_identifier(object, source));
        return match (receiver, method) {
            (Some(receiver), Some("copy")) => aliases.contains_key(receiver),
            (Some(receiver), Some("deepcopy")) => {
                use brokk_bifrost_python::bindings::{
                    PythonDirectScopeBindingKind, PythonLexicalNameResolution,
                    python_name_resolution_at, python_unambiguous_module_binding_node_bounded,
                };
                use brokk_bifrost_python::imports::python_import_bindings_from_tree;
                if !matches!(
                    python_name_resolution_at(receiver, function, source),
                    PythonLexicalNameResolution::Global | PythonLexicalNameResolution::Unbound
                ) {
                    return false;
                }
                let mut module = function;
                while let Some(parent) = module.parent() {
                    module = parent;
                }
                let Some(Some(binder)) = python_unambiguous_module_binding_node_bounded(
                    module,
                    source,
                    receiver,
                    || true,
                ) else {
                    return false;
                };
                if binder.kind != PythonDirectScopeBindingKind::Import {
                    return false;
                }
                python_import_bindings_from_tree(module, source)
                    .iter()
                    .any(|binding| {
                        binding.local_name == receiver
                            && binding.qualified_name == "copy"
                            && binding.start_byte <= binder.declaration.start_byte()
                            && binder.declaration.end_byte() <= binding.scope_end_byte
                            && !binding.is_function_scoped()
                    })
            }
            _ => false,
        };
    }
    false
}

fn alias_names(aliases: &HashMap<String, HashSet<usize>>) -> HashSet<String> {
    aliases.keys().cloned().collect()
}

fn emit_mutation(
    mutation: Node<'_>,
    source: &str,
    file: &ProjectFile,
    declaration: &DeclarationValue,
    expansions: &mut Vec<PipelineExpansion>,
    emitted: &mut HashSet<String>,
) {
    let span = mutation.start_byte()..mutation.end_byte();
    let fact = make_row(
        Incompleteness::Content,
        RELATION,
        file,
        span.clone(),
        row_range(source, span),
        Some(declaration.declaration_id().to_string()),
        "issue",
        "proven",
        true,
        None,
    );
    if emitted.insert(fact.row.id.clone()) {
        expansions.push(pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
            fact,
        ))));
    }
}

fn open_fact(
    incompleteness: Incompleteness,
    file: &ProjectFile,
    declaration: &DeclarationValue,
    source: Option<&str>,
    detail: &str,
) -> PipelineExpansion {
    let anchor = declaration.range.start_byte..declaration.range.end_byte;
    let range = source.map_or_else(
        || row_range("", 0..0),
        |source| row_range(source, anchor.clone()),
    );
    let fact = make_row(
        incompleteness,
        RELATION,
        file,
        anchor,
        range,
        Some(declaration.declaration_id().to_string()),
        "open",
        "none",
        false,
        Some(format!("{REASON}: {detail}")),
    );
    pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(fact)))
}
