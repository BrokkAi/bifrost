//! Query-time Python string-format checks over structural call and binary rows.

use super::environment::EnvironmentTraversalCache;
use super::python_rule_facts::{builtin_identity_at_identifier, make_row, row_range};
use super::python_variables::{PythonInitializerFailure, PythonInitializerProof};
use super::*;
use crate::analyzer::structural::lexical_environment::{
    BindingOfOutcome, EnvironmentFileResult, binding_of,
};
use crate::analyzer::structural::occurrences::Namespace;
use crate::analyzer::structural::resolution::EnvironmentAxis;
use brokk_bifrost_python::decode_python_string_value;
use brokk_bifrost_python::format_string::{
    BraceFormat, PercentFormat, parse_brace_format, parse_percent_format,
};
use std::collections::{HashMap, HashSet};
use tree_sitter::{Node, Tree};

const STR_FORMAT_RELATIONS: [&str; 5] = [
    "str_format_missing_argument",
    "str_format_missing_named_argument",
    "str_format_mixed_fields",
    "str_format_surplus_argument",
    "str_format_surplus_named_argument",
];
const PERCENT_FORMAT_RELATIONS: [&str; 3] = [
    "percent_format_wrong_arguments",
    "percent_format_unsupported_character",
    "percent_format_not_mapping",
];

#[derive(Default)]
pub(super) struct PythonFormatSyntaxCache {
    file: Option<ProjectFile>,
    tree: Option<Tree>,
}

impl PythonFormatSyntaxCache {
    pub(super) fn tree(&mut self, file: &ProjectFile, source: &str) -> Option<Tree> {
        if self.file.as_ref() != Some(file) {
            self.tree = crate::analyzer::usages::get_definition::parse_tree_for_language(
                file,
                Language::Python,
                source,
            );
            self.file = Some(file.clone());
        }
        self.tree.clone()
    }
}

#[derive(Clone, Copy)]
enum IssueState {
    Issue,
    Clear,
    Unknown(&'static str),
}

#[derive(Clone)]
pub(super) struct FormatArguments<'tree> {
    positional: usize,
    named: HashSet<String>,
    pub(super) positional_open: bool,
    pub(super) named_open: bool,
    pub(super) positional_nodes: Vec<Node<'tree>>,
    pub(super) named_nodes: HashMap<String, Node<'tree>>,
}

#[derive(Clone, Copy)]
struct PercentRhs {
    is_mapping: bool,
    tuple_arity: Option<usize>,
    single_positional: bool,
}

/// Expand one Python call or binary-expression structural match into its
/// rule-specific rows. The syntax and lexical environment stay query-local.
pub(super) fn expansions_for_seed(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    environment_cache: &mut EnvironmentTraversalCache,
    syntax_cache: &mut PythonFormatSyntaxCache,
) -> Vec<PipelineExpansion> {
    if seed.language != Language::Python {
        return Vec::new();
    }
    let fact = seed.facts.node(seed.fact_match.node);
    let source = seed.facts.source();
    let anchor = fact.range.start_byte..fact.range.end_byte;
    let tree = syntax_cache.tree(&seed.file, source);
    match fact.kind {
        NormalizedKind::Call => {
            if !call_fact_names_format(&seed.facts, seed.fact_match.node, source) {
                return Vec::new();
            }
            let Some(tree) = tree else {
                return rows_for_states(
                    seed,
                    anchor,
                    STR_FORMAT_RELATIONS
                        .map(|_| IssueState::Unknown("python_format_syntax_unavailable")),
                );
            };
            let Some(call) = exact_node(&tree, fact.range.start_byte, fact.range.end_byte)
                .filter(|node| node.kind() == "call" && !node.has_error())
            else {
                return rows_for_states(
                    seed,
                    anchor,
                    STR_FORMAT_RELATIONS
                        .map(|_| IssueState::Unknown("python_format_call_shape_incomplete")),
                );
            };
            str_format_rows(analyzer, seed, call, &tree, environment_cache, anchor)
        }
        NormalizedKind::BinaryExpression => {
            if !binary_fact_is_modulo(&seed.facts, seed.fact_match.node, source) {
                return Vec::new();
            }
            let Some(tree) = tree else {
                return rows_for_states(
                    seed,
                    anchor,
                    PERCENT_FORMAT_RELATIONS
                        .map(|_| IssueState::Unknown("python_percent_syntax_unavailable")),
                );
            };
            let Some(binary) = exact_node(&tree, fact.range.start_byte, fact.range.end_byte)
                .filter(|node| node.kind() == "binary_operator" && !node.has_error())
            else {
                return rows_for_states(
                    seed,
                    anchor,
                    PERCENT_FORMAT_RELATIONS
                        .map(|_| IssueState::Unknown("python_percent_binary_shape_incomplete")),
                );
            };
            percent_format_rows(analyzer, seed, binary, &tree, environment_cache, anchor)
        }
        _ => Vec::new(),
    }
}

fn call_fact_names_format(facts: &FileFacts, fact_id: u32, source: &str) -> bool {
    let name = facts.node(fact_id).name;
    name.and_then(|span| source.get(span.start_byte..span.end_byte)) == Some("format")
}

fn binary_fact_is_modulo(facts: &FileFacts, fact_id: u32, source: &str) -> bool {
    let mut operators = facts.role_targets(fact_id, Role::Operator);
    let Some(operator) = operators.next() else {
        return false;
    };
    operators.next().is_none()
        && source.get(operator.span.start_byte..operator.span.end_byte) == Some("%")
}

pub(super) fn exact_node<'tree>(
    tree: &'tree Tree,
    start: usize,
    end: usize,
) -> Option<Node<'tree>> {
    let node = tree.root_node().descendant_for_byte_range(start, end)?;
    (node.start_byte() == start && node.end_byte() == end).then_some(node)
}

pub(super) fn unwrap_parentheses(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" {
        let Some(child) = node.named_child(0) else {
            break;
        };
        if node.named_child_count() != 1 {
            break;
        }
        node = child;
    }
    node
}

fn str_format_rows(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    call: Node<'_>,
    tree: &Tree,
    environment_cache: &mut EnvironmentTraversalCache,
    anchor: std::ops::Range<usize>,
) -> Vec<PipelineExpansion> {
    let source = seed.facts.source();
    let Some(function) = call.child_by_field_name("function") else {
        return rows_for_states(
            seed,
            anchor,
            STR_FORMAT_RELATIONS.map(|_| IssueState::Unknown("python_format_callee_missing")),
        );
    };
    let environment = environment_cache.environment_for(analyzer, &seed.file);
    let initializers =
        environment_cache.python_initializer_proof_for(analyzer, &seed.file, &seed.facts);
    let receiver = match function.kind() {
        "attribute"
            if function
                .child_by_field_name("attribute")
                .and_then(|node| node_text(source, node))
                == Some("format") =>
        {
            let Some(receiver) = function.child_by_field_name("object") else {
                return rows_for_states(
                    seed,
                    anchor,
                    STR_FORMAT_RELATIONS
                        .map(|_| IssueState::Unknown("python_format_receiver_missing")),
                );
            };
            receiver
        }
        _ => return Vec::new(),
    };
    let (format_value, decoded) = match resolved_string_operand(
        receiver,
        source,
        &seed.facts,
        tree,
        &environment,
        initializers.as_ref(),
    ) {
        Ok(Some((node, value))) => (node, value),
        Ok(None) => return Vec::new(),
        Err(reason) => {
            return rows_for_states(
                seed,
                anchor,
                STR_FORMAT_RELATIONS.map(|_| IssueState::Unknown(reason)),
            );
        }
    };
    let format_anchor = format_value.start_byte()..format_value.end_byte();
    let parsed = parse_brace_format(&decoded);
    if !parsed.complete {
        return rows_for_states(
            seed,
            anchor,
            STR_FORMAT_RELATIONS
                .map(|_| IssueState::Unknown("python_brace_format_parse_incomplete")),
        );
    }
    let arguments = match call_arguments(call, source) {
        Ok(arguments) => arguments,
        Err(reason) => {
            let mut states = brace_issue_states(&parsed, None);
            states[0] = IssueState::Unknown(reason);
            states[3] = IssueState::Unknown(reason);
            states[1] = IssueState::Unknown(reason);
            states[4] = IssueState::Unknown(reason);
            return rows_for_states_with_anchors(
                seed,
                [
                    anchor.clone(),
                    anchor.clone(),
                    format_anchor,
                    anchor.clone(),
                    anchor,
                ],
                states,
            );
        }
    };
    rows_for_states_with_anchors(
        seed,
        [
            anchor.clone(),
            anchor.clone(),
            format_anchor,
            anchor.clone(),
            anchor,
        ],
        brace_issue_states(&parsed, Some(arguments)),
    )
}

fn brace_issue_states(
    parsed: &BraceFormat,
    arguments: Option<FormatArguments<'_>>,
) -> [IssueState; 5] {
    let mut states = [IssueState::Clear; 5];
    states[2] = if parsed.mixes_numbering() {
        IssueState::Issue
    } else {
        IssueState::Clear
    };
    let Some(arguments) = arguments else {
        states[0] = IssueState::Unknown("python_format_positional_arguments_incomplete");
        states[3] = IssueState::Unknown("python_format_positional_arguments_incomplete");
        states[1] = IssueState::Unknown("python_format_named_arguments_incomplete");
        states[4] = IssueState::Unknown("python_format_named_arguments_incomplete");
        return states;
    };
    states[0] = if arguments.positional_open {
        IssueState::Unknown("python_format_starred_arguments")
    } else if arguments.positional < parsed.max_positional_count {
        IssueState::Issue
    } else {
        IssueState::Clear
    };
    states[3] = if arguments.positional_open {
        IssueState::Unknown("python_format_starred_arguments")
    } else if parsed.max_positional_count > 0 && arguments.positional > parsed.max_positional_count
    {
        IssueState::Issue
    } else {
        IssueState::Clear
    };
    states[1] = if arguments.named_open {
        IssueState::Unknown("python_format_expanded_keywords")
    } else if parsed
        .named_fields
        .iter()
        .any(|name| !arguments.named.contains(name))
    {
        IssueState::Issue
    } else {
        IssueState::Clear
    };
    // Named keywords are retained in the parser result for exact set comparison.
    // `call_arguments` stores them in a side table attached below.
    states[4] = if arguments.named_open {
        IssueState::Unknown("python_format_expanded_keywords")
    } else if arguments
        .named
        .iter()
        .any(|name| !parsed.named_fields.contains(name))
    {
        IssueState::Issue
    } else {
        IssueState::Clear
    };
    states
}

pub(super) fn call_arguments<'tree>(
    call: Node<'tree>,
    source: &str,
) -> Result<FormatArguments<'tree>, &'static str> {
    let arguments = call
        .child_by_field_name("arguments")
        .ok_or("python_format_arguments_missing")?;
    let mut result = FormatArguments {
        positional: 0,
        named: HashSet::new(),
        positional_open: false,
        named_open: false,
        positional_nodes: Vec::new(),
        named_nodes: HashMap::new(),
    };
    let mut names = HashSet::new();
    let mut cursor = arguments.walk();
    for argument in arguments.named_children(&mut cursor) {
        match argument.kind() {
            "comment" => continue,
            "list_splat" => result.positional_open = true,
            "dictionary_splat" => result.named_open = true,
            "keyword_argument" => {
                let Some(name) = argument
                    .child_by_field_name("name")
                    .and_then(|node| node_text(source, node))
                else {
                    return Err("python_format_keyword_name_incomplete");
                };
                if !names.insert(name.to_owned()) {
                    return Err("python_format_duplicate_keyword");
                }
                result.named.insert(name.to_owned());
                let value = argument
                    .child_by_field_name("value")
                    .ok_or("python_format_keyword_value_missing")?;
                result.named_nodes.insert(name.to_owned(), value);
            }
            _ => {
                result.positional += 1;
                result.positional_nodes.push(argument);
            }
        }
    }
    Ok(result)
}

fn percent_format_rows(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    binary: Node<'_>,
    tree: &Tree,
    environment_cache: &mut EnvironmentTraversalCache,
    anchor: std::ops::Range<usize>,
) -> Vec<PipelineExpansion> {
    let source = seed.facts.source();
    let Some(left) = binary.child_by_field_name("left") else {
        return rows_for_states(
            seed,
            anchor,
            PERCENT_FORMAT_RELATIONS.map(|_| IssueState::Unknown("python_percent_left_missing")),
        );
    };
    let environment = environment_cache.environment_for(analyzer, &seed.file);
    let initializers =
        environment_cache.python_initializer_proof_for(analyzer, &seed.file, &seed.facts);
    let (format_value, decoded) = match resolved_string_operand(
        left,
        source,
        &seed.facts,
        tree,
        &environment,
        initializers.as_ref(),
    ) {
        Ok(Some((node, value))) => (node, value),
        Ok(None) => return Vec::new(),
        Err(reason) => {
            return rows_for_states(
                seed,
                anchor,
                PERCENT_FORMAT_RELATIONS.map(|_| IssueState::Unknown(reason)),
            );
        }
    };
    let format_anchor = format_value.start_byte()..format_value.end_byte();
    let parsed = parse_percent_format(&decoded);
    if !parsed.complete {
        return rows_for_states(
            seed,
            anchor,
            PERCENT_FORMAT_RELATIONS
                .map(|_| IssueState::Unknown("python_percent_format_parse_incomplete")),
        );
    }
    let rhs = binary
        .child_by_field_name("right")
        .map(|right| percent_rhs(right, seed, tree, &environment, environment_cache, analyzer));
    let rhs = match rhs {
        Some(Ok(rhs)) => Some(rhs),
        Some(Err(_)) | None => None,
    };
    let states = percent_issue_states(&parsed, rhs);
    rows_for_states_with_anchors(seed, [anchor.clone(), format_anchor, anchor], states)
}

fn percent_issue_states(parsed: &PercentFormat, rhs: Option<PercentRhs>) -> [IssueState; 3] {
    let wrong_arguments = if parsed.has_named_items && parsed.has_positional_items {
        IssueState::Unknown("python_percent_mixed_mapping_and_positional_fields")
    } else if let Some(rhs) = rhs {
        if parsed.has_named_items {
            IssueState::Clear
        } else if let Some(arity) = rhs.tuple_arity {
            if arity == parsed.positional_slots {
                IssueState::Clear
            } else {
                IssueState::Issue
            }
        } else if rhs.single_positional {
            if parsed.positional_slots == 1 {
                IssueState::Clear
            } else {
                IssueState::Issue
            }
        } else {
            IssueState::Unknown("python_percent_rhs_arity_incomplete")
        }
    } else {
        IssueState::Unknown("python_percent_rhs_value_incomplete")
    };
    let unsupported = if !parsed.unsupported_conversions.is_empty() {
        IssueState::Issue
    } else {
        IssueState::Clear
    };
    let not_mapping = if !parsed.has_named_items {
        IssueState::Clear
    } else if let Some(rhs) = rhs {
        if rhs.is_mapping {
            IssueState::Clear
        } else {
            IssueState::Issue
        }
    } else {
        IssueState::Unknown("python_percent_rhs_mapping_incomplete")
    };
    [wrong_arguments, unsupported, not_mapping]
}

fn percent_rhs(
    node: Node<'_>,
    seed: &SeedMatch,
    tree: &Tree,
    environment: &EnvironmentFileResult,
    environment_cache: &mut EnvironmentTraversalCache,
    analyzer: &dyn IAnalyzer,
) -> Result<PercentRhs, &'static str> {
    let source = seed.facts.source();
    let node = unwrap_parentheses(node);
    let node = if node.kind() == "identifier" {
        let name = node_text(source, node).ok_or("python_percent_rhs_name_unreadable")?;
        let initializers =
            environment_cache.python_initializer_proof_for(analyzer, &seed.file, &seed.facts);
        one_same_scope_initializer(
            node,
            name,
            &seed.facts,
            tree,
            environment,
            initializers.as_ref(),
        )?
    } else {
        node
    };
    classify_percent_rhs(
        node,
        source,
        environment,
        environment_cache,
        analyzer,
        &seed.file,
    )
}

fn classify_percent_rhs(
    node: Node<'_>,
    source: &str,
    environment: &EnvironmentFileResult,
    environment_cache: &mut EnvironmentTraversalCache,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Result<PercentRhs, &'static str> {
    let node = unwrap_parentheses(node);
    match node.kind() {
        "tuple" => {
            let mut arity = 0usize;
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "comment" {
                    continue;
                }
                if matches!(child.kind(), "list_splat" | "dictionary_splat") {
                    return Ok(PercentRhs {
                        is_mapping: false,
                        tuple_arity: None,
                        single_positional: false,
                    });
                }
                arity += 1;
            }
            Ok(PercentRhs {
                is_mapping: false,
                tuple_arity: Some(arity),
                single_positional: false,
            })
        }
        "dictionary" | "dictionary_comprehension" => Ok(PercentRhs {
            is_mapping: true,
            tuple_arity: None,
            single_positional: true,
        }),
        "list" | "set" | "string" | "concatenated_string" | "integer" | "float" | "imaginary" => {
            Ok(PercentRhs {
                is_mapping: false,
                tuple_arity: None,
                single_positional: true,
            })
        }
        "call" => builtin_call_rhs(node, source, environment, environment_cache, analyzer, file)
            .ok_or("python_percent_rhs_value_incomplete"),
        "list_comprehension"
        | "set_comprehension"
        | "generator_expression"
        | "parenthesized_expression" => Err("python_percent_rhs_value_incomplete"),
        _ => Err("python_percent_rhs_value_incomplete"),
    }
}

fn builtin_call_rhs(
    call: Node<'_>,
    source: &str,
    environment: &EnvironmentFileResult,
    environment_cache: &mut EnvironmentTraversalCache,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Option<PercentRhs> {
    let function = call.child_by_field_name("function")?;
    if function.kind() != "identifier" {
        return None;
    }
    let name = node_text(source, function)?;
    let is_mapping = match name {
        "dict" => true,
        "len" | "int" => false,
        _ => return None,
    };
    if !environment.completeness.covers(EnvironmentAxis::Scopes)
        || !environment
            .completeness
            .covers(EnvironmentAxis::BindingIntervals)
    {
        return None;
    }
    let scope = environment.innermost_scope(function.start_byte())?;
    let ancestry = environment.scope_ancestry(scope);
    if environment
        .bindings_named(name)
        .iter()
        .any(|index| ancestry.contains(&environment.bindings[*index].declaring_scope))
    {
        return None;
    }
    if environment_cache
        .python_dynamic_scope_calls(analyzer, file)
        .iter()
        .any(|range| {
            environment
                .innermost_scope(range.start_byte)
                .is_some_and(|call_scope| ancestry.contains(&call_scope))
        })
    {
        return None;
    }
    let identity =
        builtin_identity_at_identifier(analyzer, file, source, function, environment, None)
            .expect("the selected call name is a Python builtin");
    // Only the successful return shape matters, not the argument's value.
    // Shared identity resolution also keeps active wildcard imports open.
    identity.is_proven_builtin().then_some(PercentRhs {
        is_mapping,
        tuple_arity: None,
        single_positional: true,
    })
}

pub(super) fn decoded_string_operand(
    node: Node<'_>,
    source: &str,
    facts: &FileFacts,
    tree: &Tree,
    environment: &EnvironmentFileResult,
    initializers: Option<&PythonInitializerProof>,
) -> Result<Option<String>, &'static str> {
    Ok(
        resolved_string_operand(node, source, facts, tree, environment, initializers)?
            .map(|(_, value)| value),
    )
}

fn resolved_string_operand<'tree>(
    node: Node<'tree>,
    source: &str,
    facts: &FileFacts,
    tree: &'tree Tree,
    environment: &EnvironmentFileResult,
    initializers: Option<&PythonInitializerProof>,
) -> Result<Option<(Node<'tree>, String)>, &'static str> {
    let node = unwrap_parentheses(node);
    let node = if node.kind() == "identifier" {
        let name = node_text(source, node).ok_or("python_format_name_unreadable")?;
        one_same_scope_initializer(node, name, facts, tree, environment, initializers)?
    } else {
        node
    };
    let node = unwrap_parentheses(node);
    match node.kind() {
        "string" | "concatenated_string" => {
            decode_python_string_value(node, source).map(|value| Some((node, value)))
        }
        "integer" | "float" | "imaginary" | "true" | "false" | "none" | "tuple" | "list"
        | "set" | "dictionary" => Ok(None),
        _ => Err("python_format_dynamic_string_value"),
    }
}

fn one_same_scope_initializer<'tree>(
    use_node: Node<'tree>,
    name: &str,
    facts: &FileFacts,
    tree: &'tree Tree,
    environment: &EnvironmentFileResult,
    initializers: Option<&PythonInitializerProof>,
) -> Result<Node<'tree>, &'static str> {
    if !environment.completeness.covers(EnvironmentAxis::Scopes)
        || !environment
            .completeness
            .covers(EnvironmentAxis::BindingIntervals)
    {
        return Err("python_format_binding_environment_incomplete");
    }
    let use_scope = environment
        .innermost_scope(use_node.start_byte())
        .ok_or("python_format_use_scope_unresolved")?;
    let binding = match binding_of(
        environment,
        name,
        use_node.start_byte(),
        Some(Namespace::Value),
    ) {
        BindingOfOutcome::Reached(index) => index,
        BindingOfOutcome::Shadowed { .. } => return Err("python_format_binding_ambiguous"),
        BindingOfOutcome::NoBinding => return Err("python_format_name_unresolved"),
        BindingOfOutcome::Incomplete(_) => {
            return Err("python_format_binding_environment_incomplete");
        }
    };
    if environment.bindings[binding].declaring_scope != use_scope {
        return Err("python_format_binding_crosses_scope");
    }
    let initializers = initializers.ok_or("python_format_binding_environment_incomplete")?;
    let (value_start, value_end) = initializers
        .for_binding_read(
            &environment.bindings[binding],
            (use_node.start_byte(), use_node.end_byte()),
        )
        .map_err(|reason| match reason {
            PythonInitializerFailure::Incomplete => "python_format_binding_environment_incomplete",
            PythonInitializerFailure::DifferentOwner => "python_format_binding_crosses_scope",
            PythonInitializerFailure::ExternalWrite => "python_format_global_written_elsewhere",
            PythonInitializerFailure::OpenNamespace => {
                "python_format_namespace_write_inventory_open"
            }
            PythonInitializerFailure::DynamicWrite => "python_format_dynamic_scope_write",
            PythonInitializerFailure::AugmentedWrite => "python_format_augmented_assignment",
            PythonInitializerFailure::MultipleDefinitions => "python_format_initializer_ambiguous",
            PythonInitializerFailure::NotAssignment => "python_format_initializer_missing",
            PythonInitializerFailure::Conditional => "python_format_initializer_conditional",
            PythonInitializerFailure::MissingValue => "python_format_assignment_target_incomplete",
            PythonInitializerFailure::AfterUse => "python_format_initializer_after_use",
        })?;
    let right =
        exact_node(tree, value_start, value_end).ok_or("python_format_initializer_missing")?;
    let assignment = right
        .parent()
        .filter(|parent| parent.kind() == "assignment")
        .ok_or("python_format_assignment_shape_incomplete")?;
    let left = assignment
        .child_by_field_name("left")
        .ok_or("python_format_assignment_target_incomplete")?;
    if left.start_byte() != environment.bindings[binding].range.start_byte
        || left.end_byte() != environment.bindings[binding].range.end_byte
    {
        return Err("python_format_assignment_target_incomplete");
    }
    let fact_index = facts
        .nodes()
        .iter()
        .position(|fact| {
            fact.kind == NormalizedKind::Assignment
                && fact.range.start_byte == assignment.start_byte()
                && fact.range.end_byte == assignment.end_byte()
        })
        .ok_or("python_format_assignment_shape_incomplete")?;
    let left_roles = facts
        .role_targets(
            u32::try_from(fact_index).expect("fact ids fit in u32"),
            Role::Left,
        )
        .collect::<Vec<_>>();
    if left_roles.len() != 1
        || left_roles[0].span.start_byte != left.start_byte()
        || left_roles[0].span.end_byte != left.end_byte()
    {
        return Err("python_format_assignment_left_role_incomplete");
    }
    if left.kind() != "identifier" {
        return Err("python_format_assignment_target_incomplete");
    }
    let right = assignment
        .child_by_field_name("right")
        .ok_or("python_format_initializer_missing")?;
    let right_roles = facts
        .role_targets(
            u32::try_from(fact_index).expect("fact ids fit in u32"),
            Role::Right,
        )
        .collect::<Vec<_>>();
    if right_roles.len() != 1
        || right_roles[0].span.start_byte != right.start_byte()
        || right_roles[0].span.end_byte != right.end_byte()
    {
        return Err("python_format_assignment_right_role_incomplete");
    }
    Ok(right)
}

fn node_text<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    source.get(node.start_byte()..node.end_byte())
}

fn rows_for_states<const N: usize>(
    seed: &SeedMatch,
    anchor: std::ops::Range<usize>,
    states: [IssueState; N],
) -> Vec<PipelineExpansion> {
    rows_for_states_with_anchors(seed, std::array::from_fn(|_| anchor.clone()), states)
}

fn rows_for_states_with_anchors<const N: usize>(
    seed: &SeedMatch,
    anchors: [std::ops::Range<usize>; N],
    states: [IssueState; N],
) -> Vec<PipelineExpansion> {
    let relations: &[&str] = match N {
        5 => &STR_FORMAT_RELATIONS,
        3 => &PERCENT_FORMAT_RELATIONS,
        _ => unreachable!("Python format relations have fixed row counts"),
    };
    relations
        .iter()
        .zip(states)
        .zip(anchors)
        .map(|((relation, state), anchor)| {
            let (outcome, proof, complete, reason) = match state {
                IssueState::Issue => ("issue", "proven", true, None),
                IssueState::Clear => ("no_issue", "proven", true, None),
                IssueState::Unknown(reason) => ("unknown", "none", false, Some(reason.to_owned())),
            };
            let range = row_range(seed.facts.source(), anchor.clone());
            let value = make_row(
                Incompleteness::Content,
                relation,
                &seed.file,
                anchor.clone(),
                range,
                None,
                outcome,
                proof,
                complete,
                reason,
            );
            pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(value)))
        })
        .collect()
}
