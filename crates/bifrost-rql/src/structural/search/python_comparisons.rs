use super::environment::{BINDING_QUERY_AXES, BindingValue, EnvironmentTraversalCache};
use super::occurrences::OccurrenceTraversalCache;
use super::python_class_hierarchy::{HierarchyDecision, attach_hierarchy_premises, member_premise};
use super::row_relations::binding_of_expansions;
use super::{PipelineExpansion, PipelineValue, SeedMatch, pipeline_expansion, rel_path_string};
use crate::analyzer::IAnalyzer;
use crate::analyzer::Language;
use crate::analyzer::structural::occurrences::OccurrenceRole;
use crate::analyzer::structural::{OccurrenceFileResult, OccurrenceRow, RoleTarget};
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus,
    resolve_definition_batch_with_source_and_cancellation,
};
use crate::analyzer::usages::python_class_hierarchy::PythonHierarchyOutcome;
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::resolution::BindingKind;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_rql::{OccurrenceClass, OccurrenceFilter};
use std::sync::Arc;
use tree_sitter::{Node, Tree};

const BINDING_IDENTITY_ROLES: [OccurrenceRole; 2] = [
    OccurrenceRole::ValueReference,
    OccurrenceRole::ReceiverPosition,
];
const REQUIRED_PYTHON_OCCURRENCE_ROLES: [OccurrenceRole; 4] = [
    OccurrenceRole::ValueReference,
    OccurrenceRole::ReceiverPosition,
    OccurrenceRole::GlobalDirective,
    OccurrenceRole::NonlocalDirective,
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum OperandIdentity {
    Binding(String),
    AttributePath {
        binding: String,
        members: Vec<String>,
    },
}

enum BindingLookup {
    Bound(BindingValue),
    NoBinding,
    Incomplete,
}

enum OperandShape {
    Name {
        node: u32,
        spelling: String,
    },
    AttributePath {
        root: u32,
        root_spelling: String,
        members: Vec<String>,
    },
}

enum SelfAttributeWitness {
    Found,
    Absent,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperandClass {
    Singleton,
    ValueEquality,
    IdentityOnly,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiteralInterning {
    Universal,
    CpythonOnly,
    Other,
    Unknown,
}

pub(super) fn comparison_constants_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    seed: &Arc<SeedMatch>,
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if !is_python_comparison(seed, diagnostics) {
        return Vec::new();
    }
    let Some(tree) = parse_comparison_source(analyzer, environment_cache, seed, diagnostics) else {
        return Vec::new();
    };
    let Some((comparison, left, right, _operator)) =
        ast_comparison(tree.as_ref(), seed, diagnostics)
    else {
        return Vec::new();
    };
    if direct_assert_test(comparison)
        || !python_constant_expression(left, seed.facts.source())
        || !python_constant_expression(right, seed.facts.source())
    {
        return Vec::new();
    }
    vec![pipeline_expansion(PipelineValue::StructuralMatch(
        Arc::clone(seed),
    ))]
}

pub(super) fn comparison_using_is_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    seed: &Arc<SeedMatch>,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if !is_python_comparison(seed, diagnostics) {
        return Vec::new();
    }
    let Some(tree) = parse_comparison_source(analyzer, environment_cache, seed, diagnostics) else {
        return Vec::new();
    };
    let Some((_comparison, left, right, operator)) =
        ast_comparison(tree.as_ref(), seed, diagnostics)
    else {
        return Vec::new();
    };
    if !matches!(operator.as_str(), "is" | "is not") {
        return Vec::new();
    }
    if proven_singleton_operand(
        analyzer,
        environment_cache,
        seed,
        left,
        cancellation,
        diagnostics,
    ) || proven_singleton_operand(
        analyzer,
        environment_cache,
        seed,
        right,
        cancellation,
        diagnostics,
    ) {
        return Vec::new();
    }

    let left_class = operand_class(
        analyzer,
        environment_cache,
        seed,
        left,
        cancellation,
        diagnostics,
    );
    let right_class = operand_class(
        analyzer,
        environment_cache,
        seed,
        right,
        cancellation,
        diagnostics,
    );
    let mut premises = left_class.premises;
    premises.extend(right_class.premises);
    let (left_class, right_class) = (left_class.value, right_class.value);
    if matches!(left_class, OperandClass::Singleton)
        || matches!(right_class, OperandClass::Singleton)
    {
        return Vec::new();
    }
    if matches!(left_class, OperandClass::Unknown) || matches!(right_class, OperandClass::Unknown) {
        resolution_incomplete(
            diagnostics,
            seed,
            "the runtime class of a comparison operand is unresolved",
        );
    }
    if comparison_has_value_equality(left_class, right_class) {
        return {
            let mut expansion =
                pipeline_expansion(PipelineValue::StructuralMatch(Arc::clone(seed)));
            attach_hierarchy_premises(&mut expansion, &premises);
            vec![expansion]
        };
    }
    Vec::new()
}

pub(super) fn comparison_using_is_non_portable_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    seed: &Arc<SeedMatch>,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if !is_python_comparison(seed, diagnostics) {
        return Vec::new();
    }
    let Some(tree) = parse_comparison_source(analyzer, environment_cache, seed, diagnostics) else {
        return Vec::new();
    };
    let Some((_comparison, left, right, operator)) =
        ast_comparison(tree.as_ref(), seed, diagnostics)
    else {
        return Vec::new();
    };
    if !matches!(operator.as_str(), "is" | "is not") {
        return Vec::new();
    }

    let left_interning = python_literal_interning(left, seed.facts.source());
    let right_interning = python_literal_interning(right, seed.facts.source());
    if matches!(left_interning, LiteralInterning::Universal)
        || matches!(right_interning, LiteralInterning::Universal)
    {
        return Vec::new();
    }
    if !matches!(left_interning, LiteralInterning::CpythonOnly)
        && !matches!(right_interning, LiteralInterning::CpythonOnly)
    {
        if matches!(left_interning, LiteralInterning::Unknown)
            || matches!(right_interning, LiteralInterning::Unknown)
        {
            resolution_incomplete(
                diagnostics,
                seed,
                "the literal value needed for CPython interning classification is unresolved",
            );
        }
        return Vec::new();
    }

    let left_class = if matches!(left_interning, LiteralInterning::CpythonOnly) {
        HierarchyDecision::plain(OperandClass::ValueEquality)
    } else {
        operand_class(
            analyzer,
            environment_cache,
            seed,
            left,
            cancellation,
            diagnostics,
        )
    };
    let right_class = if matches!(right_interning, LiteralInterning::CpythonOnly) {
        HierarchyDecision::plain(OperandClass::ValueEquality)
    } else {
        operand_class(
            analyzer,
            environment_cache,
            seed,
            right,
            cancellation,
            diagnostics,
        )
    };
    let mut premises = left_class.premises;
    premises.extend(right_class.premises);
    let (left_class, right_class) = (left_class.value, right_class.value);
    if matches!(left_class, OperandClass::Singleton)
        || matches!(right_class, OperandClass::Singleton)
    {
        return Vec::new();
    }
    if matches!(left_class, OperandClass::Unknown) || matches!(right_class, OperandClass::Unknown) {
        resolution_incomplete(
            diagnostics,
            seed,
            "the runtime class of a non-portable identity operand is unresolved",
        );
    }
    if !comparison_has_value_equality(left_class, right_class) {
        return Vec::new();
    }
    let mut expansion = pipeline_expansion(PipelineValue::StructuralMatch(Arc::clone(seed)));
    attach_hierarchy_premises(&mut expansion, &premises);
    vec![expansion]
}

fn comparison_has_value_equality(left: OperandClass, right: OperandClass) -> bool {
    matches!(
        (left, right),
        (OperandClass::ValueEquality, OperandClass::ValueEquality)
            | (OperandClass::ValueEquality, OperandClass::Unknown)
            | (OperandClass::Unknown, OperandClass::ValueEquality)
    )
}

fn parse_comparison_source(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    seed: &SeedMatch,
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
) -> Option<Arc<Tree>> {
    environment_cache
        .python_syntax_tree_for(
            analyzer,
            &seed.file,
            seed.facts.source_identity(),
            seed.facts.source(),
        )
        .map_err(|reason| resolution_incomplete(diagnostics, seed, reason))
        .ok()
}

fn ast_comparison<'tree>(
    tree: &'tree Tree,
    seed: &SeedMatch,
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
) -> Option<(Node<'tree>, Node<'tree>, Node<'tree>, String)> {
    let comparison = seed.facts.node(seed.fact_match.node);
    let left_role = role_target(&seed.facts, seed.fact_match.node, Role::Left);
    let right_role = role_target(&seed.facts, seed.fact_match.node, Role::Right);
    let operator_role = role_target(&seed.facts, seed.fact_match.node, Role::Operator);
    let (Some(left_role), Some(right_role), Some(operator_role)) =
        (left_role, right_role, operator_role)
    else {
        unsupported(
            diagnostics,
            seed,
            "the selected comparison has no complete pairwise operand and operator roles",
        );
        return None;
    };
    let source = seed.facts.source();
    let Some(left) = exact_ast_node(
        tree.root_node(),
        left_role.span.start_byte,
        left_role.span.end_byte,
    ) else {
        resolution_incomplete(
            diagnostics,
            seed,
            "the left operand AST range is unavailable",
        );
        return None;
    };
    let Some(right) = exact_ast_node(
        tree.root_node(),
        right_role.span.start_byte,
        right_role.span.end_byte,
    ) else {
        resolution_incomplete(
            diagnostics,
            seed,
            "the right operand AST range is unavailable",
        );
        return None;
    };
    let Some(ast_comparison) = exact_ast_node(
        tree.root_node(),
        comparison.range.start_byte,
        comparison.range.end_byte,
    ) else {
        resolution_incomplete(diagnostics, seed, "the comparison AST range is unavailable");
        return None;
    };
    let Some(operator) = source.get(operator_role.span.start_byte..operator_role.span.end_byte)
    else {
        resolution_incomplete(
            diagnostics,
            seed,
            "the selected operator text is unavailable",
        );
        return None;
    };
    Some((ast_comparison, left, right, operator.to_owned()))
}

fn exact_ast_node<'tree>(root: Node<'tree>, start: usize, end: usize) -> Option<Node<'tree>> {
    let mut current = root;
    loop {
        if current.start_byte() == start && current.end_byte() == end {
            return Some(current);
        }
        let mut next = None;
        for index in 0..current.child_count() {
            let child = current.child(index)?;
            if child.start_byte() <= start && end <= child.end_byte() {
                next = Some(child);
                break;
            }
        }
        current = next?;
    }
}

fn direct_assert_test(comparison: Node<'_>) -> bool {
    let mut expression = comparison;
    while let Some(parent) = expression.parent() {
        if parent.kind() == "parenthesized_expression"
            && parent.named_child_count() == 1
            && parent
                .named_child(0)
                .is_some_and(|child| child.id() == expression.id())
        {
            expression = parent;
            continue;
        }
        return parent.kind() == "assert_statement"
            && parent
                .named_child(0)
                .is_some_and(|test| test.id() == expression.id());
    }
    false
}

fn python_constant_expression(node: Node<'_>, source: &str) -> bool {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        match current.kind() {
            "parenthesized_expression" => {
                let Some(inner) = (current.named_child_count() == 1)
                    .then(|| current.named_child(0))
                    .flatten()
                else {
                    return false;
                };
                pending.push(inner);
            }
            "integer" | "float" | "true" | "false" | "none" => {}
            "string" | "concatenated_string" => {
                if !python_string_expression(current) {
                    return false;
                }
            }
            "tuple" => {
                let mut cursor = current.walk();
                pending.extend(
                    current
                        .named_children(&mut cursor)
                        .filter(|child| child.kind() != "comment"),
                );
            }
            "not_operator" => {
                let Some(argument) = current.child_by_field_name("argument") else {
                    return false;
                };
                pending.push(argument);
            }
            "unary_operator" => {
                let Some(operator) = current.child_by_field_name("operator") else {
                    return false;
                };
                let Some(argument) = current.child_by_field_name("argument") else {
                    return false;
                };
                let operator = operator.utf8_text(source.as_bytes()).ok();
                match operator {
                    Some("+" | "-") if python_numeric_constant(argument) => {
                        pending.push(argument);
                    }
                    Some("~") if python_integer_constant(argument) => {
                        pending.push(argument);
                    }
                    _ => return false,
                }
            }
            "binary_operator" => {
                let Some(operator) = current.child_by_field_name("operator") else {
                    return false;
                };
                if operator.utf8_text(source.as_bytes()).ok() != Some("+")
                    || !python_string_expression(current)
                {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

fn python_numeric_constant(node: Node<'_>) -> bool {
    python_numeric_or_integer_constant(node, true)
}

fn python_integer_constant(node: Node<'_>) -> bool {
    python_numeric_or_integer_constant(node, false)
}

fn python_numeric_or_integer_constant(node: Node<'_>, allow_float: bool) -> bool {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        match current.kind() {
            "parenthesized_expression" if current.named_child_count() == 1 => {
                let Some(inner) = current.named_child(0) else {
                    return false;
                };
                pending.push(inner);
            }
            "integer" | "true" | "false" => {}
            "float" if allow_float => {}
            "unary_operator" => {
                let Some(operator) = current.child_by_field_name("operator") else {
                    return false;
                };
                let Some(argument) = current.child_by_field_name("argument") else {
                    return false;
                };
                if !matches!(operator.kind(), "+" | "-" | "~") {
                    return false;
                }
                pending.push(argument);
            }
            _ => return false,
        }
    }
    true
}

fn python_string_expression(node: Node<'_>) -> bool {
    let mut pending = vec![node];
    let mut saw_string = false;
    while let Some(current) = pending.pop() {
        match current.kind() {
            "parenthesized_expression" if current.named_child_count() == 1 => {
                let Some(inner) = current.named_child(0) else {
                    return false;
                };
                pending.push(inner);
            }
            "string" => {
                if contains_python_interpolation(current) {
                    return false;
                }
                saw_string = true;
            }
            "concatenated_string" => {
                let mut cursor = current.walk();
                let children = current.named_children(&mut cursor).collect::<Vec<_>>();
                if children.is_empty() {
                    return false;
                }
                pending.extend(children);
            }
            "binary_operator" => {
                let Some(operator) = current.child_by_field_name("operator") else {
                    return false;
                };
                if operator.kind() != "+" {
                    return false;
                }
                let (Some(left), Some(right)) = (
                    current.child_by_field_name("left"),
                    current.child_by_field_name("right"),
                ) else {
                    return false;
                };
                pending.push(left);
                pending.push(right);
            }
            _ => return false,
        }
    }
    saw_string
}

fn contains_python_interpolation(node: Node<'_>) -> bool {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if current.kind() == "interpolation" {
            return true;
        }
        let mut cursor = current.walk();
        pending.extend(current.named_children(&mut cursor));
    }
    false
}

fn operand_class(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    seed: &SeedMatch,
    operand: Node<'_>,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
) -> HierarchyDecision<OperandClass> {
    let mut unwrapped = operand;
    while unwrapped.kind() == "parenthesized_expression" {
        let Some(inner) = unwrapped.named_child(0) else {
            break;
        };
        unwrapped = inner;
    }
    if unwrapped.kind() == "call" {
        return class_of_constructor_call(
            analyzer,
            environment_cache,
            seed,
            unwrapped,
            cancellation,
            diagnostics,
        );
    }
    let value = (|| {
        let mut expression = operand;
        while expression.kind() == "parenthesized_expression" {
            let Some(inner) = expression.named_child(0) else {
                return unresolved_operand_class(
                    seed,
                    diagnostics,
                    "a parenthesized operand is empty",
                );
            };
            expression = inner;
        }
        match expression.kind() {
            "none" | "true" | "false" | "ellipsis" => OperandClass::Singleton,
            "integer"
            | "float"
            | "string"
            | "concatenated_string"
            | "tuple"
            | "list"
            | "dictionary"
            | "set" => OperandClass::ValueEquality,
            "binary_operator" if python_string_expression(expression) => {
                OperandClass::ValueEquality
            }
            "identifier"
                if matches!(
                    node_text(seed.facts.source(), expression),
                    Some("NotImplemented" | "Ellipsis")
                ) =>
            {
                let expected_identity = format!(
                    "builtins.{}",
                    node_text(seed.facts.source(), expression)
                        .expect("guard matched an identifier")
                );
                match super::python_rule_facts::builtin_value_identity_at_range(
                    analyzer,
                    environment_cache,
                    &seed.file,
                    seed.facts.source(),
                    expression.start_byte(),
                    expression.end_byte(),
                    cancellation,
                    diagnostics,
                ) {
                    Ok(Some(identity)) if identity == expected_identity => OperandClass::Singleton,
                    Ok(Some(_)) => unresolved_operand_class(
                        seed,
                        diagnostics,
                        "the NotImplemented spelling resolved to a different builtin",
                    ),
                    Ok(None) => unresolved_operand_class(
                        seed,
                        diagnostics,
                        "NotImplemented is not proven to be the builtin singleton",
                    ),
                    Err(reason) => unresolved_operand_class(seed, diagnostics, &reason),
                }
            }
            "call" => unreachable!("constructor handled before literal classification"),
            _ => unresolved_operand_class(
                seed,
                diagnostics,
                "the operand form does not establish a runtime class",
            ),
        }
    })();
    HierarchyDecision::plain(value)
}

fn proven_singleton_operand(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    seed: &SeedMatch,
    mut expression: Node<'_>,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
) -> bool {
    while expression.kind() == "parenthesized_expression" {
        let Some(inner) = expression.named_child(0) else {
            return false;
        };
        expression = inner;
    }
    if matches!(expression.kind(), "none" | "true" | "false" | "ellipsis") {
        return true;
    }
    let Some(name @ ("NotImplemented" | "Ellipsis")) = (expression.kind() == "identifier")
        .then(|| node_text(seed.facts.source(), expression))
        .flatten()
    else {
        return false;
    };
    super::python_rule_facts::builtin_value_identity_at_range(
        analyzer,
        environment_cache,
        &seed.file,
        seed.facts.source(),
        expression.start_byte(),
        expression.end_byte(),
        cancellation,
        diagnostics,
    )
    .is_ok_and(|identity| {
        identity.as_deref()
            == Some(if name == "NotImplemented" {
                "builtins.NotImplemented"
            } else {
                "builtins.Ellipsis"
            })
    })
}

fn class_of_constructor_call(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    seed: &SeedMatch,
    call: Node<'_>,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
) -> HierarchyDecision<OperandClass> {
    let mut premises = Vec::new();
    let value = (|| {
        let Some(function) = call.child_by_field_name("function") else {
            return unresolved_operand_class(seed, diagnostics, "a constructor call has no callee");
        };
        if function.kind() == "identifier"
            && let Ok(Some(identity)) = super::python_rule_facts::builtin_value_identity_at_range(
                analyzer,
                environment_cache,
                &seed.file,
                seed.facts.source(),
                function.start_byte(),
                function.end_byte(),
                cancellation,
                diagnostics,
            )
            && let Some(class) = builtin_value_class(&identity)
        {
            return class;
        }
        let fallback = CancellationToken::default();
        let lookup = resolve_definition_batch_with_source_and_cancellation(
            analyzer,
            vec![DefinitionLookupRequest {
                file: seed.file.clone(),
                line: None,
                column: None,
                start_byte: Some(function.start_byte()),
                end_byte: Some(function.end_byte()),
            }],
            seed.file.clone(),
            Arc::<str>::from(seed.facts.source()),
            cancellation.unwrap_or(&fallback),
        );
        let [outcome] = lookup.as_slice() else {
            return unresolved_operand_class(
                seed,
                diagnostics,
                "the constructor target lookup is missing",
            );
        };
        if outcome.status != DefinitionLookupStatus::Resolved || outcome.definitions.len() != 1 {
            return unresolved_operand_class(
                seed,
                diagnostics,
                "the constructor target is unresolved or ambiguous",
            );
        }
        let class = &outcome.definitions[0];
        if !class.is_class() {
            return unresolved_operand_class(seed, diagnostics, "the call target is not a class");
        }
        let Some(provider) = analyzer.python_class_hierarchy_provider_for(class) else {
            return unresolved_operand_class(
                seed,
                diagnostics,
                "the class hierarchy provider is unavailable",
            );
        };
        let answer = provider.mro_members(class, cancellation);
        let Some(premise) = member_premise(analyzer, class, &answer) else {
            return unresolved_operand_class(
                seed,
                diagnostics,
                "the class hierarchy source anchor is unavailable",
            );
        };
        premises.push(premise);
        if answer
            .members
            .iter()
            .any(|member| member.name == "__eq__" && member.member.is_callable())
        {
            OperandClass::ValueEquality
        } else if answer.outcome == PythonHierarchyOutcome::Complete {
            OperandClass::IdentityOnly
        } else {
            unresolved_operand_class(
                seed,
                diagnostics,
                "the class member inventory is incomplete",
            )
        }
    })();
    HierarchyDecision { value, premises }
}

fn builtin_value_class(identity: &str) -> Option<OperandClass> {
    match identity {
        "builtins.int" | "builtins.str" | "builtins.float" | "builtins.tuple" | "builtins.list"
        | "builtins.dict" | "builtins.set" | "builtins.bytes" => Some(OperandClass::ValueEquality),
        "builtins.bool" | "builtins.type" | "builtins.object" => Some(OperandClass::IdentityOnly),
        "builtins.None"
        | "builtins.True"
        | "builtins.False"
        | "builtins.Ellipsis"
        | "builtins.NotImplemented" => Some(OperandClass::Singleton),
        _ => None,
    }
}

fn unresolved_operand_class(
    seed: &SeedMatch,
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
    detail: &str,
) -> OperandClass {
    resolution_incomplete(diagnostics, seed, detail);
    OperandClass::Unknown
}

fn node_text<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    source.get(node.start_byte()..node.end_byte())
}

fn python_literal_interning(node: Node<'_>, source: &str) -> LiteralInterning {
    let mut expression = node;
    let mut negative = false;
    while expression.kind() == "parenthesized_expression" || expression.kind() == "unary_operator" {
        if expression.kind() == "parenthesized_expression" {
            let Some(inner) = (expression.named_child_count() == 1)
                .then(|| expression.named_child(0))
                .flatten()
            else {
                return LiteralInterning::Unknown;
            };
            expression = inner;
            continue;
        }
        let Some(operator) = expression.child_by_field_name("operator") else {
            return LiteralInterning::Unknown;
        };
        match operator.utf8_text(source.as_bytes()).ok() {
            Some("+") => {}
            Some("-") => negative = !negative,
            _ => return LiteralInterning::Other,
        }
        let Some(argument) = expression.child_by_field_name("argument") else {
            return LiteralInterning::Unknown;
        };
        expression = argument;
    }
    match expression.kind() {
        "integer" => match python_integer_magnitude(expression, source) {
            Some(magnitude) if magnitude <= 256 && (!negative || magnitude <= 5) => {
                if magnitude == 0 {
                    LiteralInterning::Universal
                } else {
                    LiteralInterning::CpythonOnly
                }
            }
            Some(_) | None => LiteralInterning::Other,
        },
        "string" | "concatenated_string" => match python_plain_string_value(expression, source) {
            Some(value) if value.is_empty() => LiteralInterning::Universal,
            Some(value)
                if value.chars().count() == 1
                    && value
                        .chars()
                        .next()
                        .is_some_and(|character| character as u32 <= 0xff) =>
            {
                LiteralInterning::CpythonOnly
            }
            Some(_) => LiteralInterning::Other,
            None => LiteralInterning::Unknown,
        },
        "tuple" if expression.named_child_count() == 0 => LiteralInterning::Universal,
        "tuple" | "list" | "dictionary" | "set" | "float" => LiteralInterning::Other,
        _ => LiteralInterning::Other,
    }
}

fn python_integer_magnitude(node: Node<'_>, source: &str) -> Option<u128> {
    let raw = node_text(source, node)?;
    let compact = raw.replace('_', "");
    let (radix, digits) = match compact.as_bytes().get(0..2) {
        Some([b'0', b'b' | b'B']) => (2, &compact[2..]),
        Some([b'0', b'o' | b'O']) => (8, &compact[2..]),
        Some([b'0', b'x' | b'X']) => (16, &compact[2..]),
        _ => (10, compact.as_str()),
    };
    u128::from_str_radix(digits, radix).ok()
}

fn python_plain_string_value(node: Node<'_>, source: &str) -> Option<String> {
    let mut parts = vec![node];
    let mut value = String::new();
    while let Some(current) = parts.pop() {
        match current.kind() {
            "string" => {
                let mut content = None;
                let mut cursor = current.walk();
                for child in current.named_children(&mut cursor) {
                    match child.kind() {
                        "string_start" | "string_end" => {
                            let delimiter = child.utf8_text(source.as_bytes()).ok()?;
                            if delimiter
                                .chars()
                                .any(|character| character != '\'' && character != '"')
                            {
                                return None;
                            }
                        }
                        "string_content" if child.named_child_count() == 0 && content.is_none() => {
                            content = Some(child);
                        }
                        _ => return None,
                    }
                }
                let Some(content) = content else {
                    value.push_str("");
                    continue;
                };
                let text = content.utf8_text(source.as_bytes()).ok()?;
                if text.contains('\\') {
                    return None;
                }
                value.push_str(text);
            }
            "concatenated_string" => {
                let mut cursor = current.walk();
                let children = current.named_children(&mut cursor).collect::<Vec<_>>();
                if children.is_empty() || children.iter().any(|child| child.kind() != "string") {
                    return None;
                }
                parts.extend(children.into_iter().rev());
            }
            _ => return None,
        }
    }
    Some(value)
}

pub(super) fn identical_operands_expansions(
    analyzer: &dyn IAnalyzer,
    occurrence_cache: &mut OccurrenceTraversalCache,
    environment_cache: &mut EnvironmentTraversalCache,
    seed: &Arc<SeedMatch>,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
    row_exhausted: &mut bool,
) -> Vec<PipelineExpansion> {
    if !is_python_comparison(seed, diagnostics) {
        return Vec::new();
    }
    let Some((left, right)) = comparison_operands(seed, diagnostics) else {
        return Vec::new();
    };
    let Some(left) = operand_shape(seed, left) else {
        return Vec::new();
    };
    let Some(right) = operand_shape(seed, right) else {
        return Vec::new();
    };
    let (left_root, left_spelling) = operand_root(&left);
    let (right_root, right_spelling) = operand_root(&right);
    if left_spelling != right_spelling || !same_path_shape(&left, &right) {
        return Vec::new();
    }

    let Some(occurrences) = identity_occurrences(
        analyzer,
        occurrence_cache,
        seed,
        cancellation,
        diagnostics,
        row_exhausted,
    ) else {
        return Vec::new();
    };
    if complete_binding_environment(analyzer, environment_cache, seed, diagnostics).is_none() {
        return Vec::new();
    }
    let left_binding = binding_for_identifier(
        analyzer,
        environment_cache,
        seed,
        left_root,
        &occurrences,
        true,
        diagnostics,
    );
    let right_binding = binding_for_identifier(
        analyzer,
        environment_cache,
        seed,
        right_root,
        &occurrences,
        true,
        diagnostics,
    );
    let (BindingLookup::Bound(left_binding), BindingLookup::Bound(right_binding)) =
        (left_binding, right_binding)
    else {
        return Vec::new();
    };
    let identity = match left {
        OperandShape::Name { .. } => OperandIdentity::Binding(left_binding.id()),
        OperandShape::AttributePath { members, .. } => OperandIdentity::AttributePath {
            binding: left_binding.id(),
            members,
        },
    };
    let other_identity = match right {
        OperandShape::Name { .. } => OperandIdentity::Binding(right_binding.id()),
        OperandShape::AttributePath { members, .. } => OperandIdentity::AttributePath {
            binding: right_binding.id(),
            members,
        },
    };
    if identity == other_identity {
        vec![pipeline_expansion(PipelineValue::StructuralMatch(
            Arc::clone(seed),
        ))]
    } else {
        Vec::new()
    }
}

pub(super) fn python_missing_self_expansions(
    analyzer: &dyn IAnalyzer,
    occurrence_cache: &mut OccurrenceTraversalCache,
    environment_cache: &mut EnvironmentTraversalCache,
    seed: &Arc<SeedMatch>,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
    row_exhausted: &mut bool,
) -> Vec<PipelineExpansion> {
    if !is_python_comparison(seed, diagnostics) {
        return Vec::new();
    }
    let Some((left, right)) = comparison_operands(seed, diagnostics) else {
        return Vec::new();
    };
    let (
        Some(OperandShape::Name {
            node: left_node,
            spelling: left_name,
        }),
        Some(OperandShape::Name {
            node: right_node,
            spelling: right_name,
        }),
    ) = (operand_shape(seed, left), operand_shape(seed, right))
    else {
        return Vec::new();
    };
    if left_name != right_name {
        return Vec::new();
    }
    let comparison_node = seed.facts.node(seed.fact_match.node);
    let Some(method) = nearest_callable(seed, seed.fact_match.node) else {
        return Vec::new();
    };
    if seed.facts.node(method).kind != NormalizedKind::Method {
        return Vec::new();
    }
    let Some(class) = nearest_ancestor(seed, method, NormalizedKind::Class) else {
        return Vec::new();
    };
    let Some(environment) =
        complete_binding_environment(analyzer, environment_cache, seed, diagnostics)
    else {
        return Vec::new();
    };
    let Some(method_scope) = scope_for_fact(&environment, method) else {
        resolution_incomplete(
            diagnostics,
            seed,
            "the method's lexical scope has no matching binding scope",
        );
        return Vec::new();
    };
    let Some(comparison_scope) = environment.innermost_scope(comparison_node.range.start_byte)
    else {
        return Vec::new();
    };
    if !scope_is_within(&environment, comparison_scope, method_scope)
        || has_explicit_scope_directive(seed, method, class, &left_name)
    {
        return Vec::new();
    }

    let Some(occurrences) = identity_occurrences(
        analyzer,
        occurrence_cache,
        seed,
        cancellation,
        diagnostics,
        row_exhausted,
    ) else {
        return Vec::new();
    };
    let left_binding = binding_for_identifier(
        analyzer,
        environment_cache,
        seed,
        left_node,
        &occurrences,
        false,
        diagnostics,
    );
    let right_binding = binding_for_identifier(
        analyzer,
        environment_cache,
        seed,
        right_node,
        &occurrences,
        false,
        diagnostics,
    );
    match (&left_binding, &right_binding) {
        (BindingLookup::Incomplete, _) | (_, BindingLookup::Incomplete) => return Vec::new(),
        (BindingLookup::Bound(left), BindingLookup::Bound(right)) if left.id() != right.id() => {
            return Vec::new();
        }
        (BindingLookup::Bound(_), BindingLookup::NoBinding)
        | (BindingLookup::NoBinding, BindingLookup::Bound(_)) => {
            resolution_incomplete(
                diagnostics,
                seed,
                "the two same-spelled operands have different binding outcomes",
            );
            return Vec::new();
        }
        _ => {}
    }

    match self_attribute_witness(
        analyzer,
        environment_cache,
        seed,
        class,
        &left_name,
        &occurrences,
        cancellation,
        &environment,
        diagnostics,
        row_exhausted,
    ) {
        SelfAttributeWitness::Found => vec![pipeline_expansion(PipelineValue::StructuralMatch(
            Arc::clone(seed),
        ))],
        SelfAttributeWitness::Absent | SelfAttributeWitness::Incomplete => Vec::new(),
    }
}

fn is_python_comparison(
    seed: &SeedMatch,
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
) -> bool {
    if seed.language != Language::Python {
        unsupported(
            diagnostics,
            seed,
            "comparison identity filters currently support Python only",
        );
        return false;
    }
    match seed.facts.node(seed.fact_match.node).kind {
        NormalizedKind::Comparison => true,
        NormalizedKind::ComparisonChain => {
            unsupported(
                diagnostics,
                seed,
                "Python comparison chains do not expose pairwise operand identity",
            );
            false
        }
        _ => {
            unsupported(
                diagnostics,
                seed,
                "the selected structural row is not a pairwise comparison",
            );
            false
        }
    }
}

fn comparison_operands(
    seed: &SeedMatch,
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
) -> Option<(u32, u32)> {
    let comparison = seed.fact_match.node;
    let left = role_target_node(&seed.facts, comparison, Role::Left);
    let right = role_target_node(&seed.facts, comparison, Role::Right);
    match (left, right) {
        (Some(left), Some(right)) => Some((left, right)),
        _ => {
            unsupported(
                diagnostics,
                seed,
                "a pairwise comparison is missing its grammar-selected left or right operand",
            );
            None
        }
    }
}

fn operand_shape(seed: &SeedMatch, mut node: u32) -> Option<OperandShape> {
    let mut members = Vec::new();
    loop {
        let fact = seed.facts.node(node);
        match fact.kind {
            NormalizedKind::Identifier => {
                let spelling = fact_text(&seed.facts, fact.range.start_byte, fact.range.end_byte)?;
                return Some(if members.is_empty() {
                    OperandShape::Name { node, spelling }
                } else {
                    members.reverse();
                    OperandShape::AttributePath {
                        root: node,
                        root_spelling: spelling,
                        members,
                    }
                });
            }
            NormalizedKind::FieldAccess => {
                let field = role_target(&seed.facts, node, Role::Field)?;
                members.push(fact_text(
                    &seed.facts,
                    field.span.start_byte,
                    field.span.end_byte,
                )?);
                node = role_target_node(&seed.facts, node, Role::Object)?;
            }
            _ => return None,
        }
    }
}

fn operand_root(shape: &OperandShape) -> (u32, &str) {
    match shape {
        OperandShape::Name { node, spelling } => (*node, spelling),
        OperandShape::AttributePath {
            root,
            root_spelling,
            ..
        } => (*root, root_spelling),
    }
}

fn same_path_shape(left: &OperandShape, right: &OperandShape) -> bool {
    match (left, right) {
        (OperandShape::Name { .. }, OperandShape::Name { .. }) => true,
        (
            OperandShape::AttributePath { members: left, .. },
            OperandShape::AttributePath { members: right, .. },
        ) => left == right,
        _ => false,
    }
}

fn role_target(
    facts: &super::super::facts::FileFacts,
    node: u32,
    role: Role,
) -> Option<&RoleTarget> {
    let mut targets = facts.role_targets(node, role);
    let target = targets.next()?;
    if targets.next().is_some() {
        return None;
    }
    Some(target)
}

fn role_target_node(facts: &super::super::facts::FileFacts, owner: u32, role: Role) -> Option<u32> {
    let target = role_target(facts, owner, role)?;
    if let Some(node) = target.node {
        return Some(node);
    }
    let end = facts.node(owner).subtree_end;
    let mut candidate = None;
    for node_id in owner.saturating_add(1)..end {
        let node = facts.node(node_id);
        if node.parent == Some(owner)
            && node.range.start_byte >= target.span.start_byte
            && node.range.end_byte <= target.span.end_byte
            && (!matches!(
                node.kind,
                NormalizedKind::Identifier | NormalizedKind::FieldAccess
            ) || candidate.replace(node_id).is_some())
        {
            return None;
        }
    }
    candidate
}

fn fact_text(facts: &super::super::facts::FileFacts, start: usize, end: usize) -> Option<String> {
    facts.source().get(start..end).map(ToOwned::to_owned)
}

fn identity_occurrences(
    analyzer: &dyn IAnalyzer,
    occurrence_cache: &mut OccurrenceTraversalCache,
    seed: &SeedMatch,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
    row_exhausted: &mut bool,
) -> Option<Arc<OccurrenceFileResult>> {
    let filter = OccurrenceFilter {
        classes: vec![OccurrenceClass::Reference],
        roles: REQUIRED_PYTHON_OCCURRENCE_ROLES.to_vec(),
        ..OccurrenceFilter::default()
    };
    let Some(result) = occurrence_cache.rows_for_file(analyzer, &seed.file, &filter, cancellation)
    else {
        *row_exhausted = true;
        return None;
    };
    occurrence_cache.report_completeness(&seed.file, &result, &filter, diagnostics);
    if !REQUIRED_PYTHON_OCCURRENCE_ROLES
        .iter()
        .all(|role| result.completeness.covers(*role))
    {
        return None;
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        *row_exhausted = true;
        return None;
    }
    Some(result)
}

fn complete_binding_environment(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    seed: &SeedMatch,
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
) -> Option<Arc<super::super::lexical_environment::EnvironmentFileResult>> {
    let result = environment_cache.environment_for(analyzer, &seed.file);
    environment_cache.report_completeness(&seed.file, &result, BINDING_QUERY_AXES, diagnostics);
    BINDING_QUERY_AXES
        .iter()
        .all(|axis| result.completeness.covers(*axis))
        .then_some(result)
}

fn occurrence_for_identifier<'a>(
    seed: &SeedMatch,
    occurrences: &'a OccurrenceFileResult,
    identifier: u32,
) -> Option<&'a OccurrenceRow> {
    let range = seed.facts.node(identifier).range;
    let mut rows = occurrences.rows.iter().filter(|row| {
        row.class == OccurrenceClass::Reference
            && BINDING_IDENTITY_ROLES.contains(&row.role)
            && row.range.start_byte == range.start_byte
            && row.range.end_byte == range.end_byte
    });
    let row = rows.next()?;
    debug_assert!(
        rows.next().is_none(),
        "one reference row per identifier token"
    );
    Some(row)
}

fn binding_for_identifier(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    seed: &SeedMatch,
    identifier: u32,
    occurrences: &OccurrenceFileResult,
    unresolved_is_incomplete: bool,
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
) -> BindingLookup {
    let Some(occurrence) = occurrence_for_identifier(seed, occurrences, identifier) else {
        resolution_incomplete(
            diagnostics,
            seed,
            "a grammar-selected identifier operand has no classified reference occurrence",
        );
        return BindingLookup::Incomplete;
    };
    let mut bindings =
        binding_of_expansions(analyzer, environment_cache, occurrence, false, diagnostics)
            .into_iter()
            .filter_map(|expansion| match expansion.value {
                PipelineValue::Binding(binding) => Some(binding),
                _ => None,
            });
    if let Some(binding) = bindings.next() {
        debug_assert!(
            bindings.next().is_none(),
            "binding-of emits only its winner"
        );
        return BindingLookup::Bound(binding);
    }
    if unresolved_is_incomplete {
        resolution_incomplete(
            diagnostics,
            seed,
            "a supported comparison operand has no exact lexical binding identity",
        );
        BindingLookup::Incomplete
    } else {
        BindingLookup::NoBinding
    }
}

fn nearest_callable(seed: &SeedMatch, node: u32) -> Option<u32> {
    let mut parent = seed.facts.node(node).parent;
    while let Some(current) = parent {
        match seed.facts.node(current).kind {
            NormalizedKind::Method | NormalizedKind::Function | NormalizedKind::Lambda => {
                return Some(current);
            }
            _ => parent = seed.facts.node(current).parent,
        }
    }
    None
}

fn nearest_ancestor(seed: &SeedMatch, node: u32, kind: NormalizedKind) -> Option<u32> {
    let mut parent = seed.facts.node(node).parent;
    while let Some(current) = parent {
        if seed.facts.node(current).kind == kind {
            return Some(current);
        }
        parent = seed.facts.node(current).parent;
    }
    None
}

fn scope_for_fact(
    environment: &super::super::lexical_environment::EnvironmentFileResult,
    fact: u32,
) -> Option<u32> {
    environment
        .scopes
        .iter()
        .find(|scope| scope.anchor.node() == Some(fact))
        .map(|scope| scope.index)
}

fn scope_is_within(
    environment: &super::super::lexical_environment::EnvironmentFileResult,
    mut scope: u32,
    outer: u32,
) -> bool {
    loop {
        if scope == outer {
            return true;
        }
        let Some(parent) = environment.scope(scope).parent_scope else {
            return false;
        };
        scope = parent;
    }
}

fn has_explicit_scope_directive(seed: &SeedMatch, method: u32, class: u32, name: &str) -> bool {
    let end = seed.facts.node(method).subtree_end;
    (method.saturating_add(1)..end).any(|node_id| {
        let roles = seed.facts.occurrence_roles(node_id);
        if !roles.contains(&OccurrenceRole::GlobalDirective)
            && !roles.contains(&OccurrenceRole::NonlocalDirective)
        {
            return false;
        }
        if nearest_callable(seed, node_id) != Some(method)
            || nearest_ancestor(seed, node_id, NormalizedKind::Class) != Some(class)
        {
            return false;
        }
        let range = seed.facts.node(node_id).range;
        fact_text(&seed.facts, range.start_byte, range.end_byte).as_deref() == Some(name)
    })
}

#[allow(clippy::too_many_arguments)]
fn self_attribute_witness(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    seed: &SeedMatch,
    class: u32,
    name: &str,
    occurrences: &OccurrenceFileResult,
    cancellation: Option<&CancellationToken>,
    environment: &super::super::lexical_environment::EnvironmentFileResult,
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
    row_exhausted: &mut bool,
) -> SelfAttributeWitness {
    let end = seed.facts.node(class).subtree_end;
    let mut open = false;
    for field_access in class.saturating_add(1)..end {
        if field_access % 128 == 0 && cancellation.is_some_and(CancellationToken::is_cancelled) {
            *row_exhausted = true;
            return SelfAttributeWitness::Incomplete;
        }
        let fact = seed.facts.node(field_access);
        if fact.kind != NormalizedKind::FieldAccess
            || nearest_ancestor(seed, field_access, NormalizedKind::Class) != Some(class)
        {
            continue;
        }
        let Some(field) = role_target(&seed.facts, field_access, Role::Field) else {
            continue;
        };
        if fact_text(&seed.facts, field.span.start_byte, field.span.end_byte).as_deref()
            != Some(name)
        {
            continue;
        }
        let Some(receiver) = role_target_node(&seed.facts, field_access, Role::Object) else {
            continue;
        };
        if seed.facts.node(receiver).kind != NormalizedKind::Identifier
            || fact_text(
                &seed.facts,
                seed.facts.node(receiver).range.start_byte,
                seed.facts.node(receiver).range.end_byte,
            )
            .as_deref()
                != Some("self")
        {
            continue;
        }
        let Some(receiver_method) = nearest_callable(seed, field_access) else {
            continue;
        };
        if seed.facts.node(receiver_method).kind != NormalizedKind::Method {
            continue;
        }
        let Some(receiver_method_scope) = scope_for_fact(environment, receiver_method) else {
            open = true;
            continue;
        };
        match binding_for_identifier(
            analyzer,
            environment_cache,
            seed,
            receiver,
            occurrences,
            false,
            diagnostics,
        ) {
            BindingLookup::Bound(binding)
                if binding.row().kind == BindingKind::Parameter
                    && binding.row().name == "self"
                    && binding.row().declaring_scope == receiver_method_scope =>
            {
                return SelfAttributeWitness::Found;
            }
            BindingLookup::Incomplete => open = true,
            BindingLookup::Bound(_) | BindingLookup::NoBinding => {}
        }
    }
    if open {
        resolution_incomplete(
            diagnostics,
            seed,
            "a candidate self-attribute access could not be resolved to a method parameter",
        );
        SelfAttributeWitness::Incomplete
    } else {
        SelfAttributeWitness::Absent
    }
}

fn unsupported(
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
    seed: &SeedMatch,
    detail: &str,
) {
    push_incomplete_diagnostic(
        diagnostics,
        seed,
        detail,
        super::results::CodeQueryDiagnosticCode::UnsupportedStructuralFeature,
    );
}

fn resolution_incomplete(
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
    seed: &SeedMatch,
    detail: &str,
) {
    push_incomplete_diagnostic(
        diagnostics,
        seed,
        detail,
        super::results::CodeQueryDiagnosticCode::OccurrenceResolutionIncomplete,
    );
}

fn push_incomplete_diagnostic(
    diagnostics: &mut Vec<super::results::CodeQueryDiagnostic>,
    seed: &SeedMatch,
    detail: &str,
    code: super::results::CodeQueryDiagnosticCode,
) {
    use super::results::{CodeQueryDiagnostic, CodeQueryDiagnosticImpact};
    let comparison = seed.facts.node(seed.fact_match.node);
    let message = format!(
        "{detail} in {} at bytes {}..{}",
        rel_path_string(&seed.file),
        comparison.range.start_byte,
        comparison.range.end_byte
    );
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == code && diagnostic.message == message)
    {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        related: Vec::new(),
        source: None,
        code,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: seed.language.config_label(),
        message,
        exhausted_roots: Vec::new(),
        withheld_rows_path: None,
    });
}
