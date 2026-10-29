//! On-demand, typed Python rule facts projected from one exact query input.

use super::python_class_hierarchy::{
    HierarchyDecision, hierarchy_premise, member_premise, override_premise,
};
use super::*;
use crate::analyzer::semantic::{
    CandidateCoverage, ControlEdgeKind, LengthDelimitedDigest, SemanticCapability, SemanticEffect,
    SemanticGapDischarge, SemanticGapImpact, SemanticGapKind,
};
use crate::analyzer::usages::get_definition::{
    DefinitionLookupOutcome, DefinitionLookupRequest, DefinitionLookupStatus,
    resolve_definition_batch_with_source_and_cancellation,
};
use crate::analyzer::usages::python_class_hierarchy::{
    PythonBaseResolution, PythonHierarchyOutcome, PythonHierarchyReason, PythonOverrideAnswer,
    PythonOverrideOutcome,
};
use crate::cancellation::CancellationToken;
use brokk_bifrost_analysis::analyzer::semantic::type_flow::{
    ClassIdentity, MemberAccessKind, MemberLookup, type_flow_adapter,
};
use brokk_bifrost_core::analyzer::tree_walk::children_by_field_name;
use brokk_bifrost_flow::type_flow::{ClassSetStatus, TypeFlowSitePurpose};
use brokk_bifrost_python::declarations::{
    PythonParameterSplat, python_parameter_label_node, python_parameter_splat,
};
use brokk_bifrost_python::exception_identity::{
    python_builtin_exception_is_subclass, python_builtin_exception_name,
};
use brokk_bifrost_python::imports::{
    PythonImportDetails, python_import_details, python_import_infos_from_node,
};
use tree_sitter::Node;

const PYTHON_RULE_FACT_ID_DOMAIN: &[u8] = b"bifrost.code_query.python_rule_fact.v1";
const PYTHON_RETURN_PROFILE_REASON: &str = "python_return_profile_incomplete";
const PYTHON_TUPLE_GROUP_REASON: &str = "python_tuple_return_group_incomplete";
const PYTHON_LAMBDA_REASON: &str = "python_lambda_forwarding_incomplete";
const PYTHON_CALL_USE_REASON: &str = "python_call_result_use_incomplete";
const PYTHON_RAISE_REASON: &str = "python_raise_resolution_incomplete";
const PYTHON_SPECIAL_RAISE_REASON: &str = "python_special_method_raise_incomplete";
const MAX_PYTHON_EXCEPTION_HIERARCHY_VISITS: usize = 4096;
const PYTHON_ITERATOR_RETURN_REASON: &str = "python_iterator_return_incomplete";
const PYTHON_BUILTIN_IDENTITY_REASON: &str = "python_builtin_identity_incomplete";
const PYTHON_RAISE_NOT_IMPLEMENTED_REASON: &str = "python_raise_not_implemented_incomplete";
const PYTHON_UNINITIALIZED_VARIABLE_REASON: &str = "python_uninitialized_variable_incomplete";
const PYTHON_DOCUMENTATION_REASON: &str = "python_documentation_incomplete";
const PYTHON_USELESS_CLASS_REASON: &str = "python_useless_class_incomplete";
const PYTHON_COMPLEX_DELETE_REASON: &str = "python_overly_complex_delete_incomplete";
const MAX_PYTHON_TUPLE_RETURN_ARITIES: usize = 32;

#[derive(Debug, Clone)]
pub(super) struct PythonRuleFactValue {
    pub(super) hierarchy_premises: Vec<PythonHierarchyFactValue>,
    pub(super) file: ProjectFile,
    pub(super) anchor: Range,
    pub(super) row: CodeQueryPythonRuleFact,
    pub(super) lexical_variable:
        Option<std::sync::Arc<super::python_variables::PythonVariableFacts>>,
}

pub(super) fn detailed_key(value: &PythonRuleFactValue) -> DetailedCodeQueryKey {
    DetailedCodeQueryKey::PythonRuleFact {
        id: value.row.id.clone(),
        relation: value.row.relation.to_string(),
    }
}

pub(super) fn result_ref(value: &PythonRuleFactValue) -> CodeQueryResultRef {
    CodeQueryResultRef::PythonRuleFact {
        id: value.row.id.clone(),
        path: value.row.path.clone(),
        range: value.row.range,
        relation: value.row.relation,
        outcome: value.row.outcome,
    }
}

#[derive(Debug, Clone)]
struct ReturnObservation {
    is_value: bool,
    tuple_arity: Option<usize>,
    tuple_complete: bool,
    exact: bool,
}

#[derive(Debug, Clone)]
struct ProcedureReturnFacts {
    explicit_value_returns: usize,
    none_returns: usize,
    explicit_return_statements: usize,
    fallthrough_none_returns: usize,
    /// One arity per reachable tuple-valued return. Repeated equal arities are
    /// retained so `tuple_return_count` remains a return count.
    tuple_arities: Vec<usize>,
    tuple_complete: bool,
    tuple_reason: Option<String>,
    /// A tuple-only proof; it does not complete the control/return profile.
    proved_absent_tuple_returns: bool,
    annotated: bool,
    is_async: bool,
    is_generator: bool,
    complete: bool,
    reason: Option<String>,
}

pub(super) fn row_range(source: &str, range: std::ops::Range<usize>) -> CodeQueryRange {
    let line_starts = compute_line_starts(source);
    render::range_for_offsets(source, &line_starts, range.start, range.end)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn make_row(
    relation: &'static str,
    file: &ProjectFile,
    anchor: std::ops::Range<usize>,
    range: CodeQueryRange,
    owner_id: Option<String>,
    outcome: &'static str,
    proof: &'static str,
    complete: bool,
    reason: Option<String>,
) -> PythonRuleFactValue {
    let mut digest = LengthDelimitedDigest::new(PYTHON_RULE_FACT_ID_DOMAIN);
    digest.push(relation.as_bytes());
    digest.push(rel_path_string(file).as_bytes());
    digest.push(&(anchor.start as u64).to_le_bytes());
    digest.push(&(anchor.end as u64).to_le_bytes());
    if let Some(owner_id) = &owner_id {
        digest.push(owner_id.as_bytes());
    }
    PythonRuleFactValue {
        hierarchy_premises: Vec::new(),
        file: file.clone(),
        anchor: Range {
            start_byte: anchor.start,
            end_byte: anchor.end,
            start_line: range.start_line,
            end_line: range.end_line,
        },
        row: CodeQueryPythonRuleFact {
            id: digest.finish().to_string(),
            relation,
            owner_id,
            path: rel_path_string(file),
            language: "python",
            range,
            outcome,
            proof,
            completeness: if complete { "complete" } else { "partial" },
            reason,
            explicit_value_returns: None,
            none_returns: None,
            explicit_return_statements: None,
            fallthrough_none_returns: None,
            mixed_returns: None,
            is_async: None,
            is_generator: None,
            test_scope: None,
            terminal_elif_else: None,
            tuple_return_count: None,
            distinct_tuple_arities: None,
            tuple_return_arities: None,
            assignment_target_count: None,
            assignment_arity_match: None,
            mixed_tuple_arities: None,
            annotated: None,
            return_contract: None,
            result_use: None,
            forwarded: None,
            callable_evaluation_time: None,
            default_equivalent: None,
            target_id: None,
            returns_receiver: None,
            parameter_count: None,
            raised_expression: None,
            operand_kind: None,
            exception_class: None,
            expected_exception: None,
            scope_is_public: None,
            docstring_present: None,
            docstring_value: None,
            comment_block_text: None,
            comment_block_lines: None,
            lines_of_code: None,
            decorator_count: None,
            is_override: None,
            is_property_accessor: None,
            public_method_count: None,
            has_inheritance: None,
            has_subclasses: None,
            has_special_method: None,
            is_decorated: None,
            is_probable_mixin: None,
            is_stateful: None,
            is_top_level: None,
            cyclomatic_complexity: None,
            url_prefix: None,
            variable_id: None,
            name: None,
            scope_kind: None,
            is_global: None,
            is_nonlocal: None,
            is_builtin: None,
            call_callee: None,
            has_read: None,
            definition_kind: None,
            definition_order: None,
            first_definition: None,
            definition_is_unused: None,
            annotation_only: None,
            annotated_assignment: None,
            is_abstract: None,
            is_overriding_method: None,
            is_overridden_method: None,
            reachability: None,
            access_kind: None,
            nested_scope: None,
            in_main_guard: None,
            optimizing_parameter: None,
            self_assignment: None,
            related_scope_kind: None,
            related_has_definition_outside_main: None,
            related_has_deletion: None,
            related_has_import: None,
            related_is_pytest_fixture: None,
            loop_has_body_read: None,
            loop_policy_excluded: None,
            nested_loop_reused: None,
            nested_loop_has_outer_use: None,
        },
        lexical_variable: None,
    }
}

pub(super) fn parse_python(source: &str) -> Option<tree_sitter::Tree> {
    let language = crate::analyzer::parser_language_for(crate::analyzer::Language::Python)?;
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).ok()?;
    parser.parse(source, None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PythonTestScope {
    Yes,
    No,
    Unknown,
}

#[derive(Default)]
struct PythonTestImports {
    pytest_or_nose: bool,
    module_aliases: Vec<(String, String)>,
    unittest_test_case_aliases: Vec<(String, String, String)>,
}

fn python_test_imports(root: Node<'_>, source: &str) -> PythonTestImports {
    let mut imports = PythonTestImports::default();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "import_statement" | "import_from_statement") {
            for import in python_import_infos_from_node(node, source) {
                let Some(details) = python_import_details(&import) else {
                    continue;
                };
                match details {
                    PythonImportDetails::Import { module, alias } => {
                        imports.pytest_or_nose |= module == "pytest"
                            || module.starts_with("pytest.")
                            || module == "nose"
                            || module.starts_with("nose.");
                        if let Some(local) = import.local_name() {
                            imports.module_aliases.push((
                                local.to_owned(),
                                alias.map_or_else(|| local.to_owned(), |_| module.clone()),
                            ));
                        }
                    }
                    PythonImportDetails::FromImport {
                        module,
                        name,
                        alias,
                        wildcard,
                    } => {
                        imports.pytest_or_nose |= module == "pytest"
                            || module.starts_with("pytest.")
                            || module == "nose"
                            || module.starts_with("nose.");
                        if wildcard {
                            continue;
                        }
                        let local = alias.as_deref().unwrap_or(&name);
                        if (module == "unittest" || module == "unittest.case") && name == "TestCase"
                        {
                            imports.unittest_test_case_aliases.push((
                                local.to_owned(),
                                module,
                                name,
                            ));
                        } else if module == "unittest" && name == "case" {
                            imports
                                .module_aliases
                                .push((local.to_owned(), "unittest.case".to_owned()));
                        }
                    }
                }
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    imports
}

fn python_attribute_path(mut node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut path = Vec::new();
    loop {
        match node.kind() {
            "identifier" => {
                path.push(node_text(source, node)?.to_owned());
                path.reverse();
                return Some(path);
            }
            "attribute" => {
                path.push(node_text(source, node.child_by_field_name("attribute")?)?.to_owned());
                node = node.child_by_field_name("object")?;
            }
            _ => return None,
        }
    }
}

fn python_base_is_unittest_test_case(
    base: Node<'_>,
    imports: &PythonTestImports,
    source: &str,
) -> bool {
    let Some(mut path) = python_attribute_path(base, source) else {
        return false;
    };
    if path.len() == 1
        && imports
            .unittest_test_case_aliases
            .iter()
            .any(|(local, _, _)| local == &path[0])
    {
        return true;
    }
    for (local, module) in &imports.module_aliases {
        if path.first() == Some(local) {
            path[0] = module.clone();
            break;
        }
    }
    matches!(
        path.iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice(),
        ["unittest", "TestCase"] | ["unittest", "case", "TestCase"]
    )
}

fn python_class_directly_extends_unittest_test_case(class: Node<'_>, source: &str) -> bool {
    let mut root = class;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let imports = python_test_imports(root, source);
    python_class_base_nodes(class)
        .into_iter()
        .any(|base| python_base_is_unittest_test_case(base, &imports, source))
}

fn python_class_test_scope(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    class: Node<'_>,
) -> HierarchyDecision<PythonTestScope> {
    let mut premises = Vec::new();
    let value = (|| {
        if python_class_directly_extends_unittest_test_case(class, source) {
            return PythonTestScope::Yes;
        }
        let Some(name) = class.child_by_field_name("name") else {
            return PythonTestScope::Unknown;
        };
        let Some(definition) = resolve_identifier(analyzer, file, source, name, None) else {
            return PythonTestScope::Unknown;
        };
        if definition.status != DefinitionLookupStatus::Resolved {
            return PythonTestScope::Unknown;
        }
        let [unit] = definition.definitions.as_slice() else {
            return PythonTestScope::Unknown;
        };
        if !unit.is_class() {
            return PythonTestScope::Unknown;
        }
        let Some(provider) = analyzer.python_class_hierarchy_provider_for(unit) else {
            return PythonTestScope::Unknown;
        };
        let hierarchy = provider.class_hierarchy(unit, None);
        let Some(premise) = hierarchy_premise(analyzer, unit, &hierarchy) else {
            return PythonTestScope::Unknown;
        };
        premises.push(premise);
        if hierarchy.outcome != PythonHierarchyOutcome::Complete {
            return PythonTestScope::Unknown;
        }
        for ancestor in &hierarchy.mro {
            let fqn = ancestor.qualified_name();
            if matches!(fqn, "unittest.TestCase" | "unittest.case.TestCase") {
                return PythonTestScope::Yes;
            }
            let ClassIdentity::Workspace(ancestor) = ancestor else {
                continue;
            };
            let Some(ancestor_source) =
                analyzer.get_source(&CodeUnit::file_scope(ancestor.source().clone()), false)
            else {
                continue;
            };
            let Some(tree) =
                parse_python(&ancestor_source).filter(|tree| !tree.root_node().has_error())
            else {
                return PythonTestScope::Unknown;
            };
            let Some(ancestor_class) = python_class_node_for_unit(analyzer, ancestor, &tree) else {
                return PythonTestScope::Unknown;
            };
            if python_class_directly_extends_unittest_test_case(ancestor_class, &ancestor_source) {
                return PythonTestScope::Yes;
            }
        }
        PythonTestScope::No
    })();
    HierarchyDecision { value, premises }
}

fn python_function_is_test(function: Node<'_>, source: &str) -> bool {
    function
        .child_by_field_name("name")
        .and_then(|name| node_text(source, name))
        .is_some_and(|name| name.starts_with("test"))
}

fn python_assertion_test_scope(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    assertion: Node<'_>,
) -> HierarchyDecision<PythonTestScope> {
    let mut premises = Vec::new();
    let value = (|| {
        let imports = python_test_imports(root, source);
        let fallback_file = file
            .rel_path()
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("test_") && name.ends_with(".py"));
        let mut current = Some(assertion);
        let mut unknown_class = false;
        while let Some(node) = current {
            match node.kind() {
                "class_definition" => {
                    let decision = python_class_test_scope(analyzer, file, source, node);
                    premises.extend(decision.premises);
                    match decision.value {
                        PythonTestScope::Yes => return PythonTestScope::Yes,
                        PythonTestScope::Unknown => unknown_class = true,
                        PythonTestScope::No => {}
                    }
                }
                "function_definition"
                    if python_function_is_test(node, source)
                        && (imports.pytest_or_nose || fallback_file) =>
                {
                    return PythonTestScope::Yes;
                }
                _ => {}
            }
            current = node.parent();
        }
        if unknown_class {
            PythonTestScope::Unknown
        } else {
            PythonTestScope::No
        }
    })();
    HierarchyDecision { value, premises }
}

fn python_assertion_is_terminal_elif_else(assertion: Node<'_>) -> bool {
    let Some(block) = assertion.parent() else {
        return false;
    };
    if block.kind() != "block" {
        return false;
    }
    let Some(else_clause) = block.parent() else {
        return false;
    };
    if else_clause.kind() != "else_clause" {
        return false;
    }
    let Some(if_statement) = else_clause
        .parent()
        .filter(|parent| parent.kind() == "if_statement")
    else {
        return false;
    };
    named_children(if_statement)
        .iter()
        .any(|child| child.kind() == "elif_clause")
}

pub(super) fn python_assertion_context_expansions(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
) -> Vec<PipelineExpansion> {
    if seed.language != crate::analyzer::Language::Python {
        return Vec::new();
    }
    let source = seed.facts.source();
    let span = seed.facts.node(seed.fact_match.node).range;
    let bytes = span.start_byte..span.end_byte;
    let Some(tree) = parse_python(source) else {
        return Vec::new();
    };
    let assertion = find_exact_node(tree.root_node(), &bytes, &["assert_statement"]);
    let range = row_range(source, bytes.clone());
    let mut fact = make_row(
        "assertion_context",
        &seed.file,
        bytes,
        range,
        None,
        "open",
        "none",
        false,
        Some("assertion_context_unresolved".to_owned()),
    );
    fact.row.test_scope = Some("unknown");
    fact.row.terminal_elif_else = Some("unknown");
    if let Some(assertion) = assertion.filter(|_| !tree.root_node().has_error()) {
        let test_scope =
            python_assertion_test_scope(analyzer, &seed.file, source, tree.root_node(), assertion);
        fact.hierarchy_premises.extend(test_scope.premises);
        let test_scope = test_scope.value;
        fact.row.test_scope = Some(match test_scope {
            PythonTestScope::Yes => "yes",
            PythonTestScope::No => "no",
            PythonTestScope::Unknown => "unknown",
        });
        fact.row.terminal_elif_else = Some(if python_assertion_is_terminal_elif_else(assertion) {
            "yes"
        } else {
            "no"
        });
        if test_scope == PythonTestScope::Unknown {
            fact.row.reason = Some("unittest_test_scope_unresolved".to_owned());
        } else {
            fact.row.outcome = "no_issue";
            fact.row.proof = "proven";
            fact.row.completeness = "complete";
            fact.row.reason = None;
        }
    }
    vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
        fact,
    )))]
}

fn python_is_string_constant(node: Node<'_>) -> bool {
    if node.kind() != "string" {
        return false;
    }
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "interpolation" {
            return false;
        }
        stack.extend(named_children(current));
    }
    true
}

fn python_list_element_is_string_constant(root: Node<'_>, source: &str) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let Some(node) = unwrap_parenthesized(node) else {
            return false;
        };
        match node.kind() {
            "string" if python_is_string_constant(node) => {}
            "concatenated_string" => {
                let parts = named_children(node);
                if parts.is_empty() {
                    return false;
                }
                stack.extend(parts);
            }
            "binary_operator"
                if node
                    .child_by_field_name("operator")
                    .and_then(|operator| node_text(source, operator))
                    == Some("+") =>
            {
                let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    return false;
                };
                stack.push(right);
                stack.push(left);
            }
            _ => return false,
        }
    }
    true
}

pub(super) fn implicit_string_concatenation_expansions(seed: &SeedMatch) -> Vec<PipelineExpansion> {
    if seed.language != crate::analyzer::Language::Python {
        return Vec::new();
    }
    let source = seed.facts.source();
    let seed_span = seed.facts.node(seed.fact_match.node).range;
    let seed_bytes = seed_span.start_byte..seed_span.end_byte;
    let Some(tree) = parse_python(source).filter(|tree| !tree.root_node().has_error()) else {
        return Vec::new();
    };
    let Some(node) = find_exact_node(
        tree.root_node(),
        &seed_bytes,
        &["string", "concatenated_string"],
    ) else {
        return Vec::new();
    };
    let seed_is_group = node.kind() == "concatenated_string";
    let group = if seed_is_group {
        node
    } else if let Some(parent) = node
        .parent()
        .filter(|parent| parent.kind() == "concatenated_string")
    {
        parent
    } else {
        return Vec::new();
    };
    if !seed_is_group
        && named_children(group)
            .first()
            .is_none_or(|first| first.start_byte() != node.start_byte())
    {
        return Vec::new();
    }
    let mut list_element = group;
    let list = loop {
        let Some(parent) = list_element.parent() else {
            return Vec::new();
        };
        match parent.kind() {
            "parenthesized_expression" => list_element = parent,
            "list" => break parent,
            _ => return Vec::new(),
        }
    };
    let other_string_element = named_children(list).iter().any(|element| {
        (element.start_byte() != list_element.start_byte()
            || element.end_byte() != list_element.end_byte())
            && python_list_element_is_string_constant(*element, source)
    });
    let parts = named_children(group)
        .into_iter()
        .filter(|part| python_is_string_constant(*part))
        .collect::<Vec<_>>();
    if parts.len() < 2
        || !other_string_element
        || !named_children(list).iter().any(|element| {
            element.start_byte() == list_element.start_byte()
                && element.end_byte() == list_element.end_byte()
        })
    {
        return Vec::new();
    }
    parts
        .into_iter()
        .map(|part| {
            let bytes = part.start_byte()..part.end_byte();
            let range = row_range(source, bytes.clone());
            let fact = make_row(
                "implicit_string_concatenation",
                &seed.file,
                bytes,
                range,
                None,
                "issue",
                "proven",
                true,
                None,
            );
            pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(fact)))
        })
        .collect()
}

pub(super) fn node_text<'a>(source: &'a str, node: Node<'_>) -> Option<&'a str> {
    source.get(node.start_byte()..node.end_byte())
}

pub(super) fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .collect()
}

pub(super) fn parameter_name(parameter: Node<'_>, source: &str) -> Option<String> {
    if parameter.kind() == "identifier" {
        return node_text(source, parameter).map(str::to_owned);
    }
    if !matches!(
        parameter.kind(),
        "typed_parameter" | "typed_default_parameter" | "default_parameter"
    ) {
        return None;
    }
    parameter
        .child_by_field_name("name")
        .or_else(|| {
            named_children(parameter)
                .into_iter()
                .find(|child| child.kind() == "identifier")
        })
        .and_then(|name| node_text(source, name))
        .map(str::to_owned)
}

pub(super) fn direct_identifier<'a>(mut expression: Node<'_>, source: &'a str) -> Option<&'a str> {
    while expression.kind() == "parenthesized_expression" {
        let children = named_children(expression);
        let [inner] = children.as_slice() else {
            return None;
        };
        expression = *inner;
    }
    (expression.kind() == "identifier")
        .then(|| node_text(source, expression))
        .flatten()
}

pub(super) fn call_name<'a>(function: Node<'_>, source: &'a str) -> Option<&'a str> {
    match function.kind() {
        "identifier" => node_text(source, function),
        "attribute" => function
            .child_by_field_name("attribute")
            .and_then(|name| node_text(source, name)),
        _ => None,
    }
}

pub(super) fn contains_alias(node: Node<'_>, source: &str, aliases: &HashSet<String>) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "identifier"
            && node_text(source, current).is_some_and(|name| aliases.contains(name))
        {
            return true;
        }
        stack.extend(named_children(current));
    }
    false
}

pub(super) fn scope_nodes(root: Node<'_>) -> Vec<Node<'_>> {
    let mut nodes = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        nodes.push(node);
        if node != root
            && matches!(
                node.kind(),
                "function_definition" | "class_definition" | "lambda"
            )
        {
            continue;
        }
        stack.extend(named_children(node).into_iter().rev());
    }
    nodes
}

pub(super) fn in_control_branch(mut node: Node<'_>, scope: Node<'_>) -> bool {
    while node != scope {
        let Some(parent) = node.parent() else {
            return true;
        };
        if matches!(
            parent.kind(),
            "if_statement"
                | "elif_clause"
                | "for_statement"
                | "while_statement"
                | "try_statement"
                | "with_statement"
                | "match_statement"
        ) {
            return true;
        }
        node = parent;
    }
    false
}

fn find_exact_node<'tree>(
    root: Node<'tree>,
    source_range: &std::ops::Range<usize>,
    kinds: &[&str],
) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    let mut found = None;
    while let Some(node) = stack.pop() {
        if kinds.contains(&node.kind())
            && node.start_byte() == source_range.start
            && node.end_byte() == source_range.end
        {
            if found.is_some() {
                return None;
            }
            found = Some(node);
        }
        stack.extend(named_children(node).into_iter().rev());
    }
    found
}

fn python_first_docstring_expression(scope: Node<'_>) -> Result<Option<Node<'_>>, ()> {
    let body = match scope.kind() {
        "module" => scope,
        "class_definition" | "function_definition" => scope.child_by_field_name("body").ok_or(())?,
        _ => return Err(()),
    };
    let Some(statement) = named_children(body)
        .into_iter()
        .find(|child| child.kind() != "comment")
    else {
        return Ok(None);
    };
    if statement.kind() != "expression_statement" {
        return Ok(None);
    }
    let expressions = named_children(statement);
    let [expression] = expressions.as_slice() else {
        return Ok(None);
    };
    let mut expression = *expression;
    while expression.kind() == "parenthesized_expression" {
        let children = named_children(expression);
        let [child] = children.as_slice() else {
            return Ok(None);
        };
        expression = *child;
    }
    Ok(matches!(expression.kind(), "string" | "concatenated_string").then_some(expression))
}

fn python_code_line_count(scope: Node<'_>) -> usize {
    let mut docstrings = HashSet::default();
    let mut scopes = vec![scope];
    while let Some(node) = scopes.pop() {
        if matches!(
            node.kind(),
            "module" | "class_definition" | "function_definition"
        ) && let Ok(Some(docstring)) = python_first_docstring_expression(node)
        {
            docstrings.insert(docstring.id());
        }
        scopes.extend(named_children(node));
    }

    let mut lines = HashSet::default();
    let mut pending = vec![scope];
    while let Some(node) = pending.pop() {
        if node.kind() == "comment" || docstrings.contains(&node.id()) {
            continue;
        }
        if node.child_count() == 0 {
            let start = node.start_position().row;
            let end_position = node.end_position();
            let end = end_position.row.saturating_sub(usize::from(
                end_position.row > start && end_position.column == 0,
            ));
            lines.extend(start..=end);
        } else {
            for index in (0..node.child_count()).rev() {
                if let Some(child) = node.child(index) {
                    pending.push(child);
                }
            }
        }
    }
    lines.len()
}

pub(super) fn python_definition_decorators(definition: Node<'_>) -> Vec<Node<'_>> {
    definition
        .parent()
        .filter(|parent| parent.kind() == "decorated_definition")
        .map(named_children)
        .unwrap_or_default()
        .into_iter()
        .filter(|child| child.kind() == "decorator")
        .collect()
}

fn python_enclosing_class_node(mut definition: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = definition.parent() {
        match parent.kind() {
            "class_definition" => return Some(parent),
            "function_definition" | "lambda" => return None,
            _ => definition = parent,
        }
    }
    None
}

fn python_property_decorator(definition: Node<'_>, source: &str) -> Option<bool> {
    let definition_name = definition
        .child_by_field_name("name")
        .and_then(|name| node_text(source, name));
    let definition_name = definition_name?;
    if brokk_bifrost_python::declarations::python_function_has_decorator(
        definition, source, "property",
    ) {
        return Some(true);
    }
    let mut unresolved_property_mutator = false;
    for decorator in python_definition_decorators(definition) {
        let Some(expression) = named_children(decorator).into_iter().next() else {
            continue;
        };
        if expression.kind() == "attribute"
            && let Some(attribute) = expression.child_by_field_name("attribute")
            && matches!(node_text(source, attribute), Some("setter" | "deleter"))
        {
            let Some(object) = expression.child_by_field_name("object") else {
                unresolved_property_mutator = true;
                continue;
            };
            let Some(property_name) = node_text(source, object) else {
                unresolved_property_mutator = true;
                continue;
            };
            if property_name != definition_name {
                unresolved_property_mutator = true;
                continue;
            }
            let Some(class) = python_enclosing_class_node(definition) else {
                unresolved_property_mutator = true;
                continue;
            };
            let body = class.child_by_field_name("body").expect("class has a body");
            let mut getter_found = false;
            for member in named_children(body) {
                if member.start_byte() >= definition.start_byte() {
                    break;
                }
                let candidate = if member.kind() == "decorated_definition" {
                    named_children(member)
                        .into_iter()
                        .find(|child| child.kind() == "function_definition")
                } else {
                    (member.kind() == "function_definition").then_some(member)
                };
                let Some(candidate) = candidate else {
                    continue;
                };
                if candidate
                    .child_by_field_name("name")
                    .and_then(|name| node_text(source, name))
                    != Some(property_name)
                {
                    continue;
                }
                getter_found = brokk_bifrost_python::declarations::python_function_has_decorator(
                    candidate, source, "property",
                );
                if getter_found {
                    break;
                }
            }
            if getter_found {
                return Some(true);
            }
            unresolved_property_mutator = true;
        }
    }
    if unresolved_property_mutator {
        None
    } else {
        Some(false)
    }
}

fn python_scope_is_public(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<bool> {
    let mut current = unit.clone();
    let mut visited = HashSet::default();
    loop {
        if !visited.insert(current.clone()) {
            return None;
        }
        if current.is_module() || current.is_file_scope() {
            return Some(
                brokk_bifrost_python::declarations::python_project_module_components(
                    current.source(),
                )
                .iter()
                .all(|component| !component.starts_with('_')),
            );
        }
        if current.terminal_name().starts_with('_') {
            return Some(false);
        }
        current = analyzer.parent_of(&current)?;
    }
}

pub(super) fn python_definition_node<'tree>(
    tree: &'tree tree_sitter::Tree,
    unit: &CodeUnit,
    range: &Range,
) -> Option<Node<'tree>> {
    let kind = if unit.is_module() {
        "module"
    } else if unit.is_class() {
        "class_definition"
    } else if unit.is_function() {
        "function_definition"
    } else {
        return None;
    };
    let target_range = range.start_byte..range.end_byte;
    find_exact_node(tree.root_node(), &target_range, &[kind]).or_else(|| {
        if !unit.is_function() {
            return None;
        }
        named_children(find_exact_node(
            tree.root_node(),
            &target_range,
            &["decorated_definition"],
        )?)
        .into_iter()
        .find(|child| child.kind() == "function_definition")
    })
}

pub(super) fn python_range_for_unit(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<Range> {
    analyzer.ranges(unit).into_iter().last()
}

pub(super) fn python_method_non_trivial(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    method: &CodeUnit,
    occurrences: &[crate::analyzer::structural::occurrence_rows::OccurrenceRow],
) -> Option<bool> {
    let range = python_range_for_unit(analyzer, method)?;
    let source = analyzer.get_source(&CodeUnit::file_scope(method.source().clone()), false)?;
    let tree = parse_python(&source).filter(|tree| !tree.root_node().has_error())?;
    let definition = python_definition_node(&tree, method, &range)?;
    let body = definition.child_by_field_name("body")?;
    let receiver = python_first_parameter(definition, &source);
    let procedure = {
        let mut cfg = semantic.cfg();
        let mut procedures =
            cfg.procedure_of_declaration(&DeclarationValue::new(method.clone(), range));
        if procedures.len() != 1 {
            return None;
        }
        procedures.remove(0)
    };
    let has_normal_exit = normal_exit_reachable(&procedure)?;
    let mut has_substantive_statement = false;
    for statement in named_children(body) {
        if matches!(statement.kind(), "comment" | "pass_statement") {
            continue;
        }
        match python_method_delegates_same_name(
            statement,
            method.terminal_name(),
            receiver.as_ref(),
            &source,
            occurrences,
        )? {
            true => {}
            false => has_substantive_statement = true,
        }
    }
    Some(has_normal_exit && has_substantive_statement)
}

fn python_first_parameter(
    definition: Node<'_>,
    source: &str,
) -> Option<(String, std::ops::Range<usize>)> {
    let parameters = definition.child_by_field_name("parameters")?;
    let (name, parameter) = named_children(parameters)
        .into_iter()
        .find_map(|parameter| parameter_name(parameter, source).map(|name| (name, parameter)))?;
    let name_node = python_parameter_name_node(parameter)?;
    Some((name, name_node.start_byte()..name_node.end_byte()))
}

fn python_parameter_name_node(parameter: Node<'_>) -> Option<Node<'_>> {
    if parameter.kind() == "identifier" {
        return Some(parameter);
    }
    matches!(
        parameter.kind(),
        "typed_parameter" | "typed_default_parameter" | "default_parameter"
    )
    .then(|| {
        parameter.child_by_field_name("name").or_else(|| {
            named_children(parameter)
                .into_iter()
                .find(|child| child.kind() == "identifier")
        })
    })
    .flatten()
}

fn python_method_delegates_same_name(
    statement: Node<'_>,
    method_name: &str,
    receiver: Option<&(String, std::ops::Range<usize>)>,
    source: &str,
    occurrences: &[crate::analyzer::structural::occurrence_rows::OccurrenceRow],
) -> Option<bool> {
    if statement.kind() != "expression_statement" {
        return Some(false);
    }
    let statement_children = named_children(statement);
    let [call] = statement_children.as_slice() else {
        return Some(false);
    };
    if call.kind() != "call" {
        return Some(false);
    }
    let function = call.child_by_field_name("function")?;
    if function.kind() != "attribute"
        || function
            .child_by_field_name("attribute")
            .and_then(|attribute| node_text(source, attribute))
            != Some(method_name)
    {
        return Some(false);
    }
    let object = function.child_by_field_name("object")?;
    if object.kind() == "call"
        && object
            .child_by_field_name("function")
            .filter(|name| name.kind() == "identifier")
            .and_then(|name| node_text(source, name))
            == Some("super")
    {
        let super_name = object.child_by_field_name("function")?;
        let row = python_reference_at(occurrences, super_name)?;
        return python_builtin_super_identity(row);
    }

    let Some((receiver_name, receiver_range)) = receiver else {
        return Some(false);
    };
    if object.kind() != "identifier" {
        return Some(false);
    }
    let arguments = call.child_by_field_name("arguments")?;
    let Some(argument) = named_children(arguments).into_iter().next() else {
        return Some(false);
    };
    if direct_identifier(argument, source) != Some(receiver_name) {
        return Some(false);
    }
    let argument_row = python_reference_at(occurrences, argument)?;
    if !python_reference_is_parameter(argument_row, receiver_range) {
        return Some(false);
    }
    let class_row = python_reference_at(occurrences, object)?;
    python_reference_is_class(class_row)
}

fn python_reference_at<'a>(
    rows: &'a [crate::analyzer::structural::occurrence_rows::OccurrenceRow],
    node: Node<'_>,
) -> Option<&'a crate::analyzer::structural::occurrence_rows::OccurrenceRow> {
    rows.iter().find(|row| {
        row.class == crate::analyzer::structural::OccurrenceClass::Reference
            && row.range.start_byte == node.start_byte()
            && row.range.end_byte == node.end_byte()
    })
}

fn python_builtin_super_identity(
    row: &crate::analyzer::structural::occurrence_rows::OccurrenceRow,
) -> Option<bool> {
    use crate::analyzer::structural::occurrence_rows::OccurrenceTarget;
    match &row.target {
        OccurrenceTarget::Resolved(targets) if targets.len() == 1 => {
            let target = targets.first()?;
            Some(
                target.kind() == crate::analyzer::CodeUnitType::Function
                    && target.package_name() == "builtins"
                    && target.terminal_name() == "super",
            )
        }
        OccurrenceTarget::Lexical(_) => Some(false),
        OccurrenceTarget::Unresolved(DefinitionLookupStatus::NoDefinition)
            if row.effective_spelling() == "super" =>
        {
            Some(true)
        }
        _ => None,
    }
}

fn python_reference_is_parameter(
    row: &crate::analyzer::structural::occurrence_rows::OccurrenceRow,
    parameter_range: &std::ops::Range<usize>,
) -> bool {
    use crate::analyzer::structural::occurrence_rows::OccurrenceTarget;
    matches!(&row.target, OccurrenceTarget::Lexical(definition)
        if definition.name_range.start_byte == parameter_range.start
            && definition.name_range.end_byte == parameter_range.end)
}

fn python_reference_is_class(
    row: &crate::analyzer::structural::occurrence_rows::OccurrenceRow,
) -> Option<bool> {
    use crate::analyzer::structural::occurrence_rows::OccurrenceTarget;
    match &row.target {
        OccurrenceTarget::Resolved(targets) if targets.len() == 1 => {
            Some(targets.first()?.is_class())
        }
        OccurrenceTarget::Lexical(_) => Some(false),
        OccurrenceTarget::Unresolved(_) => None,
        _ => None,
    }
}

pub(super) fn python_method_reads_receiver(
    analyzer: &dyn IAnalyzer,
    method: &CodeUnit,
) -> Option<bool> {
    let range = python_range_for_unit(analyzer, method)?;
    let source = analyzer.get_source(&CodeUnit::file_scope(method.source().clone()), false)?;
    let tree = parse_python(&source).filter(|tree| !tree.root_node().has_error())?;
    let definition = python_definition_node(&tree, method, &range)?;
    let parameters = definition.child_by_field_name("parameters")?;
    let receiver = named_children(parameters)
        .into_iter()
        .find_map(|parameter| parameter_name(parameter, &source))?;
    let body = definition.child_by_field_name("body")?;

    let mut pending = vec![body];
    while let Some(node) = pending.pop() {
        if node.id() != body.id()
            && matches!(
                node.kind(),
                "function_definition" | "class_definition" | "lambda"
            )
        {
            continue;
        }
        if python_store_targets(node)
            .into_iter()
            .any(|target| direct_identifier(target, &source) == Some(receiver.as_str()))
        {
            return None;
        }
        if node.kind() == "global_statement" || node.kind() == "nonlocal_statement" {
            return None;
        }
        if node.kind() == "identifier"
            && node_text(&source, node) == Some(receiver.as_str())
            && python_receiver_identifier_is_read(node)
        {
            return Some(true);
        }
        pending.extend(named_children(node));
    }
    Some(false)
}

fn python_receiver_identifier_is_read(identifier: Node<'_>) -> bool {
    let Some(parent) = identifier.parent() else {
        return false;
    };
    if parent.kind() == "argument_list" {
        return true;
    }
    if parent.kind() != "attribute"
        || !parent
            .child_by_field_name("object")
            .is_some_and(|object| object.id() == identifier.id())
    {
        return false;
    }
    let attribute = parent;
    let mut child = attribute;
    while let Some(ancestor) = child.parent() {
        if ancestor.kind() == "augmented_assignment" {
            return true;
        }
        let store_fields = python_store_targets(ancestor);
        if !store_fields.is_empty() {
            return !store_fields.iter().any(|target| {
                target.start_byte() <= attribute.start_byte()
                    && target.end_byte() >= attribute.end_byte()
            });
        }
        if ancestor.kind() == "delete_statement" {
            return false;
        }
        if matches!(
            ancestor.kind(),
            "expression_statement" | "return_statement" | "if_statement"
        ) {
            return true;
        }
        child = ancestor;
    }
    true
}

fn python_function_intrinsic_needs_docstring(
    definition: Node<'_>,
    source: &str,
) -> Result<bool, &'static str> {
    let name = definition
        .child_by_field_name("name")
        .and_then(|name| node_text(source, name))
        .ok_or("missing_function_name")?;
    if name == "lambda" {
        return Ok(false);
    }
    let (metric_node, decorator_count) = match definition
        .parent()
        .filter(|parent| parent.kind() == "decorated_definition")
    {
        Some(parent) => (
            parent,
            named_children(parent)
                .into_iter()
                .filter(|child| child.kind() == "decorator")
                .count(),
        ),
        None => (definition, 0),
    };
    let lines = python_code_line_count(metric_node);
    assert!(
        lines >= decorator_count,
        "decorator count is bounded by code lines"
    );
    if lines - decorator_count <= 2 {
        return Ok(false);
    }
    match python_property_decorator(definition, source) {
        Some(true) => Ok(false),
        Some(false) => Ok(true),
        None => Err("property_accessor_unresolved"),
    }
}

fn python_method_needs_docstring(
    analyzer: &dyn IAnalyzer,
    start: &CodeUnit,
    cancellation: Option<&CancellationToken>,
) -> HierarchyDecision<Result<bool, &'static str>> {
    let mut premises = Vec::new();
    let value = (|| {
        let Some(provider) = analyzer.python_class_hierarchy_provider_for(start) else {
            return Err("python_hierarchy_provider_unavailable");
        };
        let mut current = start.clone();
        let mut visited = HashSet::default();
        loop {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err("cancelled");
            }
            if !visited.insert(current.clone()) {
                return Err("override_cycle");
            }
            let range =
                python_range_for_unit(analyzer, &current).ok_or("override_range_unavailable")?;
            let source = analyzer
                .get_source(&CodeUnit::file_scope(current.source().clone()), false)
                .ok_or("override_source_unavailable")?;
            let tree = parse_python(&source).ok_or("override_syntax_unavailable")?;
            if tree.root_node().has_error() {
                return Err("override_syntax_recovered");
            }
            let definition = python_definition_node(&tree, &current, &range)
                .ok_or("override_definition_unavailable")?;
            let needs_docstring = python_function_intrinsic_needs_docstring(definition, &source)?;
            if !needs_docstring {
                return Ok(false);
            }
            let answer = provider.method_override(&current, cancellation);
            premises.push(
                override_premise(analyzer, &current, &answer)
                    .ok_or("override_premise_anchor_unavailable")?,
            );
            match answer.outcome {
                PythonOverrideOutcome::NoOverride => return Ok(true),
                PythonOverrideOutcome::Overrides => {
                    let target = answer.target.ok_or("override_target_unavailable")?;
                    current = target;
                }
                PythonOverrideOutcome::Incomplete | PythonOverrideOutcome::Unsupported => {
                    return Err("override_resolution_incomplete");
                }
            }
        }
    })();
    HierarchyDecision { value, premises }
}

fn python_method_override_answer(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    cancellation: Option<&CancellationToken>,
) -> HierarchyDecision<Result<Option<PythonOverrideAnswer>, &'static str>> {
    let mut premises = Vec::new();
    let value = (|| {
        if !analyzer
            .parent_of(unit)
            .is_some_and(|parent| parent.is_class())
        {
            return Ok(None);
        }
        let Some(provider) = analyzer.python_class_hierarchy_provider_for(unit) else {
            return Err("python_hierarchy_provider_unavailable");
        };
        let answer = provider.method_override(unit, cancellation);
        premises.push(
            override_premise(analyzer, unit, &answer)
                .ok_or("override_premise_anchor_unavailable")?,
        );
        match answer.outcome {
            PythonOverrideOutcome::Overrides | PythonOverrideOutcome::NoOverride => {
                Ok(Some(answer))
            }
            PythonOverrideOutcome::Incomplete | PythonOverrideOutcome::Unsupported => {
                Err("override_resolution_incomplete")
            }
        }
    })();
    HierarchyDecision { value, premises }
}

fn report_rule_fact_incomplete(
    file: &ProjectFile,
    namespace: &str,
    reason: &'static str,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    let message = format!("{namespace}: {reason} at {}", rel_path_string(file));
    if diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::SemanticAnalysisPartial
            && diagnostic.language == "python"
            && diagnostic.message == message
    }) {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        related: Vec::new(),
        source: None,
        code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "python",
        message,
        exhausted_roots: Vec::new(),
        withheld_rows_path: None,
    });
}

fn report_documentation_incomplete(
    file: &ProjectFile,
    reason: &'static str,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    report_rule_fact_incomplete(file, PYTHON_DOCUMENTATION_REASON, reason, diagnostics);
}

fn report_useless_class_incomplete(
    file: &ProjectFile,
    reason: &'static str,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    report_rule_fact_incomplete(file, PYTHON_USELESS_CLASS_REASON, reason, diagnostics);
}

pub(super) fn documentation_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    declaration: &DeclarationValue,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let unit = &declaration.unit;
    if crate::analyzer::common::language_for_file(unit.source())
        != crate::analyzer::Language::Python
        || !(unit.is_module() || unit.is_class() || unit.is_function())
    {
        return Vec::new();
    }
    let file = unit.source();
    let Some(source) = analyzer.get_source(&CodeUnit::file_scope(file.clone()), false) else {
        report_documentation_incomplete(file, "source unavailable", diagnostics);
        return Vec::new();
    };
    let anchor = declaration.range.start_byte..declaration.range.end_byte;
    let Some(tree) = parse_python(&source).filter(|tree| !tree.root_node().has_error()) else {
        report_documentation_incomplete(file, "syntax unavailable", diagnostics);
        return Vec::new();
    };
    let Some(node) = python_definition_node(&tree, unit, &declaration.range) else {
        report_documentation_incomplete(file, "declaration range unavailable", diagnostics);
        return Vec::new();
    };
    let Some(public) = python_scope_is_public(analyzer, unit) else {
        let mut fact = make_row(
            "documentation",
            file,
            anchor.clone(),
            row_range(&source, anchor),
            Some(declaration.declaration_id()),
            "open",
            "none",
            false,
            Some(format!(
                "{PYTHON_DOCUMENTATION_REASON}: enclosing scope unavailable"
            )),
        );
        fact.row.lines_of_code = Some(python_code_line_count(node));
        return vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
            fact,
        )))];
    };
    let docstring = match python_first_docstring_expression(node) {
        Ok(None) => Some((false, None)),
        Ok(Some(expression)) => {
            match brokk_bifrost_python::decode_python_string_value(expression, &source) {
                Ok(value) => Some((true, Some(value))),
                Err(_) => None,
            }
        }
        Err(()) => None,
    };
    let docstring_lines_node = if unit.is_function() {
        node.parent()
            .filter(|parent| parent.kind() == "decorated_definition")
            .unwrap_or(node)
    } else {
        node
    };
    let lines_of_code = python_code_line_count(docstring_lines_node);
    let decorator_count = unit
        .is_function()
        .then(|| python_definition_decorators(node).len());
    let environment = environment_cache.environment_for(analyzer, file);
    if unit.is_function() {
        environment_cache.report_completeness(
            file,
            &environment,
            super::environment::BINDING_QUERY_AXES,
            diagnostics,
        );
    }
    let is_property_accessor = if unit.is_function()
        && analyzer
            .parent_of(unit)
            .is_some_and(|parent| parent.is_class())
    {
        python_property_decorator(node, &source)
    } else if unit.is_function() {
        Some(false)
    } else {
        None
    };
    let override_answer = if unit.is_function() {
        python_method_override_answer(analyzer, unit, cancellation)
    } else {
        HierarchyDecision::plain(Ok(None))
    };
    let mut hierarchy_premises = override_answer.premises;
    let override_answer = override_answer.value;
    let is_override = if unit.is_function() {
        match &override_answer {
            Ok(Some(answer)) => Some(answer.outcome == PythonOverrideOutcome::Overrides),
            Ok(None) => Some(false),
            Err(_) => None,
        }
    } else {
        None
    };

    let mut reason = None;
    let mut complete = true;
    let (docstring_present, docstring_value) = match docstring {
        Some((present, value)) => (Some(present), value),
        None => {
            complete = false;
            reason = Some("docstring_value_unsupported".to_string());
            (Some(true), None)
        }
    };
    if unit.is_function() && is_property_accessor.is_none() {
        complete = false;
        reason.get_or_insert_with(|| "property_accessor_unresolved".to_string());
    }
    if unit.is_function() && is_override.is_none() {
        complete = false;
        reason.get_or_insert_with(|| "override_resolution_incomplete".to_string());
    }

    let package_module = unit.is_module()
        && file.rel_path().file_name().and_then(|name| name.to_str()) == Some("__init__.py");
    let mut needs_docstring = public && !package_module;
    if unit.is_function() && needs_docstring {
        match python_function_intrinsic_needs_docstring(node, &source) {
            Err(intrinsic_reason) => {
                complete = false;
                reason.get_or_insert_with(|| intrinsic_reason.to_string());
                needs_docstring = false;
            }
            Ok(false) => needs_docstring = false,
            Ok(true) => match &override_answer {
                Err(override_reason) => {
                    complete = false;
                    reason.get_or_insert_with(|| override_reason.to_string());
                    needs_docstring = false;
                }
                Ok(None) => {}
                Ok(Some(answer)) if answer.outcome == PythonOverrideOutcome::NoOverride => {}
                Ok(Some(answer)) => {
                    let Some(target) = answer.target.as_ref() else {
                        let mut fact = make_row(
                            "documentation",
                            file,
                            anchor.clone(),
                            row_range(&source, anchor),
                            Some(declaration.declaration_id()),
                            "open",
                            "none",
                            false,
                            Some("override_target_unavailable".to_string()),
                        );
                        fact.hierarchy_premises = hierarchy_premises;
                        fact.row.scope_is_public = Some(public);
                        fact.row.docstring_present = docstring_present;
                        fact.row.docstring_value = docstring_value;
                        fact.row.lines_of_code = Some(lines_of_code);
                        fact.row.decorator_count = decorator_count;
                        fact.row.is_override = is_override;
                        fact.row.is_property_accessor = is_property_accessor;
                        return vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
                            fact,
                        )))];
                    };
                    let inherited = python_method_needs_docstring(analyzer, target, cancellation);
                    hierarchy_premises.extend(inherited.premises);
                    match inherited.value {
                        Ok(base_needs_docstring) => {
                            needs_docstring = base_needs_docstring;
                        }
                        Err(override_reason) => {
                            complete = false;
                            reason.get_or_insert_with(|| override_reason.to_string());
                            needs_docstring = false;
                        }
                    }
                }
            },
        }
    }

    let has_docstring = docstring_present == Some(true);
    let outcome = if !complete {
        "open"
    } else if !public || package_module || !needs_docstring {
        "excluded"
    } else if has_docstring {
        "no_issue"
    } else {
        "issue"
    };
    let anchor = declaration.range.start_byte..declaration.range.end_byte;
    let mut fact = make_row(
        "documentation",
        file,
        anchor.clone(),
        row_range(&source, anchor),
        Some(declaration.declaration_id()),
        outcome,
        if complete { "proven" } else { "none" },
        complete,
        reason.map(|reason| format!("{PYTHON_DOCUMENTATION_REASON}: {reason}")),
    );
    fact.hierarchy_premises = hierarchy_premises;
    fact.row.scope_is_public = Some(public);
    fact.row.docstring_present = docstring_present;
    fact.row.docstring_value = docstring_value;
    fact.row.lines_of_code = Some(lines_of_code);
    fact.row.decorator_count = decorator_count;
    fact.row.is_override = is_override;
    fact.row.is_property_accessor = is_property_accessor;
    vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
        fact,
    )))]
}

fn python_target_stores_attribute_or_subscript(target: Node<'_>) -> bool {
    let mut pending = vec![target];
    while let Some(node) = pending.pop() {
        if matches!(node.kind(), "attribute" | "subscript") {
            return true;
        }
        pending.extend(named_children(node));
    }
    false
}

fn python_store_targets(node: Node<'_>) -> Vec<Node<'_>> {
    let fields: &[&str] = match node.kind() {
        "assignment"
        | "annotated_assignment"
        | "augmented_assignment"
        | "for_statement"
        | "for_in_clause" => &["left"],
        "named_expression" => &["left", "name"],
        "with_item" | "except_clause" => &["alias", "name"],
        _ => &[],
    };
    fields
        .iter()
        .filter_map(|field| node.child_by_field_name(field))
        .collect()
}

fn python_method_is_stateful(method: Node<'_>, source: &str) -> Option<bool> {
    let body = method.child_by_field_name("body")?;
    let mut pending = vec![body];
    while let Some(node) = pending.pop() {
        if node.id() != body.id()
            && matches!(
                node.kind(),
                "function_definition" | "class_definition" | "lambda"
            )
        {
            continue;
        }
        if python_store_targets(node)
            .into_iter()
            .any(python_target_stores_attribute_or_subscript)
        {
            return Some(true);
        }
        if node.kind() == "call"
            && call_function(node)
                .and_then(unwrap_parenthesized)
                .filter(|function| function.kind() == "attribute")
                .and_then(|function| function.child_by_field_name("attribute"))
                .and_then(|attribute| node_text(source, attribute))
                .is_some_and(|name| {
                    matches!(name, "pop" | "remove" | "discard" | "extend" | "append")
                })
        {
            return Some(true);
        }
        pending.extend(named_children(node));
    }
    Some(false)
}

fn python_special_method_name(name: &str) -> bool {
    name.len() > 4
        && name.starts_with("__")
        && name.ends_with("__")
        && !matches!(name, "__init__" | "__new__")
}

pub(super) fn useless_class_expansions(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let unit = &declaration.unit;
    if crate::analyzer::common::language_for_file(unit.source())
        != crate::analyzer::Language::Python
        || !unit.is_class()
    {
        return Vec::new();
    }
    let file = unit.source();
    let source = analyzer.get_source(&CodeUnit::file_scope(file.clone()), false);
    let anchor = declaration.range.start_byte..declaration.range.end_byte;
    let Some(source) = source else {
        report_useless_class_incomplete(file, "source unavailable", diagnostics);
        return Vec::new();
    };
    let Some(tree) = parse_python(&source) else {
        report_useless_class_incomplete(file, "syntax unavailable", diagnostics);
        return Vec::new();
    };
    let Some(class) = python_class_node_for_unit(analyzer, unit, &tree) else {
        report_useless_class_incomplete(file, "class range unavailable", diagnostics);
        return Vec::new();
    };
    let Some(name) = class
        .child_by_field_name("name")
        .and_then(|name| node_text(&source, name))
    else {
        report_useless_class_incomplete(file, "class name unavailable", diagnostics);
        return Vec::new();
    };

    let mut reason = None;
    let mut complete = !tree.root_node().has_error();
    if !complete {
        reason = Some("recovered_python_syntax");
    }
    let parent = analyzer.parent_of(unit);
    let is_top_level = parent
        .as_ref()
        .map(|parent| parent.is_module() || parent.is_file_scope());
    if is_top_level.is_none() {
        complete = false;
        reason.get_or_insert("enclosing_scope_unavailable");
    }
    let scope_is_public = python_scope_is_public(analyzer, unit);
    if scope_is_public.is_none() {
        complete = false;
        reason.get_or_insert("public_scope_unavailable");
    }

    let mut has_inheritance = false;
    for base in python_class_base_nodes(class) {
        if base.kind() != "identifier" || node_text(&source, base) != Some("object") {
            has_inheritance = true;
            break;
        }
    }

    let token = cancellation.cloned().unwrap_or_default();
    let has_subclasses = if let Some(provider) = analyzer.type_hierarchy_provider() {
        provider
            .get_direct_descendants_within(
                unit,
                &crate::analyzer::DescendantIndexScope::whole_workspace(&token),
            )
            .map(|descendants| !descendants.is_empty())
    } else {
        None
    };
    if has_subclasses.is_none() {
        complete = false;
        reason.get_or_insert("subclass_index_unavailable");
    }

    let children = analyzer.direct_children(unit);
    let mut public_method_count = 0usize;
    let mut has_special_method = false;
    let mut is_stateful = false;
    for method_unit in children.iter().filter(|child| child.is_function()) {
        let Some(range) = python_range_for_unit(analyzer, method_unit) else {
            complete = false;
            reason.get_or_insert("method_range_unavailable");
            continue;
        };
        let Some(method) = python_definition_node(&tree, method_unit, &range) else {
            complete = false;
            reason.get_or_insert("method_node_unavailable");
            continue;
        };
        let Some(method_name) = method
            .child_by_field_name("name")
            .and_then(|name| node_text(&source, name))
        else {
            complete = false;
            reason.get_or_insert("method_name_unavailable");
            continue;
        };
        if !method_name.starts_with('_') && !matches!(method_name, "__init__" | "__new__") {
            public_method_count = public_method_count.saturating_add(1);
        }
        has_special_method |= python_special_method_name(method_name);
        match python_method_is_stateful(method, &source) {
            Some(stateful) => is_stateful |= stateful,
            None => {
                complete = false;
                reason.get_or_insert("method_body_unavailable");
            }
        }
    }

    let is_decorated = !python_definition_decorators(class).is_empty();
    let is_probable_mixin = if name.to_lowercase().contains("mixin") {
        true
    } else {
        match python_first_docstring_expression(class) {
            Ok(None) => false,
            Ok(Some(expression)) => {
                match brokk_bifrost_python::decode_python_string_value(expression, &source) {
                    Ok(docstring) => {
                        let docstring = docstring.to_lowercase();
                        docstring.contains("mixin") || docstring.contains("mix-in")
                    }
                    Err(_) => {
                        complete = false;
                        reason.get_or_insert("mixin_docstring_unavailable");
                        false
                    }
                }
            }
            Err(()) => {
                complete = false;
                reason.get_or_insert("mixin_docstring_unavailable");
                false
            }
        }
    };
    let eligible = complete
        && is_top_level == Some(true)
        && scope_is_public == Some(true)
        && !has_inheritance
        && has_subclasses == Some(false)
        && public_method_count <= 1
        && !has_special_method
        && !is_decorated
        && !is_probable_mixin
        && !is_stateful;
    let mut fact = make_row(
        "useless_class",
        file,
        anchor.clone(),
        row_range(&source, anchor),
        Some(declaration.declaration_id()),
        if complete {
            if eligible { "issue" } else { "excluded" }
        } else {
            "open"
        },
        if complete { "proven" } else { "none" },
        complete,
        reason.map(|reason| format!("{PYTHON_USELESS_CLASS_REASON}: {reason}")),
    );
    fact.row.scope_is_public = scope_is_public;
    fact.row.public_method_count = Some(public_method_count);
    fact.row.has_inheritance = Some(has_inheritance);
    fact.row.has_subclasses = has_subclasses;
    fact.row.has_special_method = Some(has_special_method);
    fact.row.is_decorated = Some(is_decorated);
    fact.row.is_probable_mixin = Some(is_probable_mixin);
    fact.row.is_stateful = Some(is_stateful);
    fact.row.is_top_level = is_top_level;
    if !complete {
        report_useless_class_incomplete(file, "useless-class evidence unavailable", diagnostics);
    }
    debug_assert!(!eligible || complete);
    vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
        fact,
    )))]
}

#[allow(clippy::too_many_arguments)]
pub(super) fn overly_complex_delete_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    semantic: &mut SemanticQueryContext<'_>,
    bindings: &mut CallBindingCache,
    declaration: &DeclarationValue,
    procedures: &[SemanticProcedureValue],
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let unit = &declaration.unit;
    if crate::analyzer::common::language_for_file(unit.source())
        != crate::analyzer::Language::Python
        || !unit.is_function()
        || unit.terminal_name() != "__del__"
        || !analyzer
            .parent_of(unit)
            .is_some_and(|parent| parent.is_class())
    {
        return Vec::new();
    }

    let file = unit.source();
    let anchor = declaration.range.start_byte..declaration.range.end_byte;
    let source = analyzer.get_source(&CodeUnit::file_scope(file.clone()), false);
    let mut reason = None;
    let mut hierarchy_premises = Vec::new();
    let complexity = match source.as_deref() {
        None => {
            reason = Some("source_unavailable");
            None
        }
        Some(source) => {
            let Some(tree) = parse_python(source) else {
                let fact = make_row(
                    "overly_complex_delete",
                    file,
                    anchor.clone(),
                    row_range(source, anchor.clone()),
                    Some(declaration.declaration_id()),
                    "open",
                    "none",
                    false,
                    Some(format!("{PYTHON_COMPLEX_DELETE_REASON}_syntax_unavailable")),
                );
                report_rule_fact_incomplete(
                    file,
                    PYTHON_COMPLEX_DELETE_REASON,
                    "syntax_unavailable",
                    diagnostics,
                );
                return vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
                    fact,
                )))];
            };
            if tree.root_node().has_error() {
                reason = Some("recovered_python_syntax");
                None
            } else if let Some(procedure) = procedures.first().filter(|_| procedures.len() == 1) {
                let complexity = python_destructor_complexity(
                    analyzer,
                    environment_cache,
                    PythonDestructorComplexityInput {
                        file,
                        source,
                        tree: &tree,
                        unit,
                        declaration_range: &declaration.range,
                        procedure,
                        semantic,
                        bindings,
                        diagnostics,
                        cancellation,
                    },
                );
                hierarchy_premises.extend(complexity.premises);
                match complexity.value {
                    Ok(complexity) => Some(complexity),
                    Err(incomplete_reason) => {
                        reason = Some(incomplete_reason);
                        None
                    }
                }
            } else {
                reason = Some("semantic_procedure_unavailable");
                None
            }
        }
    };

    let complete = complexity.is_some();
    let mut fact = make_row(
        "overly_complex_delete",
        file,
        anchor.clone(),
        source
            .as_deref()
            .map_or_else(|| row_range("", 0..0), |source| row_range(source, anchor)),
        Some(declaration.declaration_id()),
        complexity.map_or("open", |count| if count > 3 { "issue" } else { "no_issue" }),
        if complete { "proven" } else { "none" },
        complete,
        reason.map(|reason| format!("{PYTHON_COMPLEX_DELETE_REASON}_{reason}")),
    );
    fact.hierarchy_premises = hierarchy_premises;
    fact.row.cyclomatic_complexity = complexity;
    if !complete {
        report_rule_fact_incomplete(
            file,
            PYTHON_COMPLEX_DELETE_REASON,
            reason.unwrap_or("CFG_unavailable"),
            diagnostics,
        );
    }
    vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
        fact,
    )))]
}

struct PythonDestructorComplexityInput<'a, 'workspace> {
    file: &'a ProjectFile,
    source: &'a str,
    tree: &'a tree_sitter::Tree,
    unit: &'a CodeUnit,
    declaration_range: &'a Range,
    procedure: &'a SemanticProcedureValue,
    semantic: &'a mut SemanticQueryContext<'workspace>,
    bindings: &'a mut CallBindingCache,
    diagnostics: &'a mut Vec<CodeQueryDiagnostic>,
    cancellation: Option<&'a CancellationToken>,
}

fn python_destructor_complexity<'a, 'workspace>(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    input: PythonDestructorComplexityInput<'a, 'workspace>,
) -> HierarchyDecision<Result<usize, &'static str>> {
    let mut premises = Vec::new();
    let value = (|| {
        let PythonDestructorComplexityInput {
            file,
            source,
            tree,
            unit,
            declaration_range,
            procedure,
            semantic,
            bindings,
            diagnostics,
            cancellation,
        } = input;
        if procedure.exact_selection_incomplete_reason().is_some() {
            return Err("procedure_selection_incomplete");
        }
        let semantics = procedure.handle.semantics();
        let capabilities = procedure.handle.artifact().capabilities();
        if !capabilities.is_complete(SemanticCapability::BasicBlocks)
            || !capabilities.is_complete(SemanticCapability::ProgramPoints)
            || !capabilities.is_complete(SemanticCapability::EntryBoundary)
        {
            return Err("cfg_structure_incomplete");
        }
        let method = python_definition_node(tree, unit, declaration_range)
            .ok_or("method_syntax_unavailable")?;
        let pruned_edges = python_unlikely_exception_edges(
            analyzer,
            environment_cache,
            file,
            source,
            method,
            semantics,
            cancellation,
        );
        premises.extend(pruned_edges.premises);
        let pruned_edges = pruned_edges.value?;
        let pruned_edges = python_unlikely_call_edges(
            analyzer,
            environment_cache,
            semantic,
            bindings,
            file,
            source,
            method,
            semantics,
            cancellation,
            diagnostics,
            pruned_edges,
        )?;
        let constant_branches = python_constant_branch_edges(source, tree.root_node(), semantics);

        let blocks = semantics.blocks();
        let points = semantics.points();
        let Some(entry) = semantics.point(semantics.entry_point()) else {
            return Err("entry_point_unavailable");
        };
        let mut reachable_blocks = vec![false; blocks.len()];
        let mut reachable_points = vec![false; points.len()];
        let mut pending = vec![entry.block.index()];
        let mut edges = HashSet::default();
        while let Some(block_index) = pending.pop() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err("cancelled");
            }
            let Some(block) = blocks.get(block_index) else {
                return Err("block_identity_unavailable");
            };
            if std::mem::replace(&mut reachable_blocks[block_index], true) {
                continue;
            }
            let Some(block_evidence) = semantics.evidence_row(block.evidence) else {
                return Err("block_evidence_unavailable");
            };
            if !matches!(
                block_evidence.proof,
                crate::analyzer::semantic::ProofStatus::Proven
            ) || !matches!(
                block_evidence.completeness,
                crate::analyzer::semantic::EvidenceCompleteness::Complete
            ) {
                return Err("block_evidence_incomplete");
            }
            for point_id in block.points.iter().copied() {
                let Some(point) = semantics.point(point_id) else {
                    return Err("program_point_unavailable");
                };
                reachable_points[point_id.index()] = true;
                let Some(point_evidence) = semantics.evidence_row(point.evidence) else {
                    return Err("program_point_evidence_unavailable");
                };
                if !matches!(
                    point_evidence.proof,
                    crate::analyzer::semantic::ProofStatus::Proven
                ) || !matches!(
                    point_evidence.completeness,
                    crate::analyzer::semantic::EvidenceCompleteness::Complete
                ) {
                    return Err("program_point_evidence_incomplete");
                }
                for (_, edge) in semantics.successor_edges(point_id) {
                    let Some(edge_evidence) = semantics.evidence_row(edge.evidence) else {
                        return Err("control_edge_evidence_unavailable");
                    };
                    if !matches!(
                        edge_evidence.proof,
                        crate::analyzer::semantic::ProofStatus::Proven
                    ) || !matches!(
                        edge_evidence.completeness,
                        crate::analyzer::semantic::EvidenceCompleteness::Complete
                    ) {
                        return Err("control_edge_evidence_incomplete");
                    }
                    if edge.kind == ControlEdgeKind::Exceptional
                        && edge.target_point == semantics.exceptional_exit_point()
                    {
                        continue;
                    }
                    if pruned_edges.contains(&(
                        edge.source_point.index(),
                        edge.target_point.index(),
                        edge.kind,
                    )) {
                        continue;
                    }
                    if constant_branches.contains(&(
                        edge.source_point.index(),
                        edge.target_point.index(),
                        edge.kind,
                    )) {
                        continue;
                    }
                    let Some(target) = semantics.point(edge.target_point) else {
                        return Err("control_edge_target_unavailable");
                    };
                    let target_block = target.block.index();
                    let sequential = target_block == block_index
                        && block.points.windows(2).any(|pair| {
                            pair[0] == edge.source_point && pair[1] == edge.target_point
                        });
                    if !sequential {
                        edges.insert((block_index, target_block));
                        pending.push(target_block);
                    }
                }
            }
        }

        for gap in semantics.gaps() {
            if !reachable_points
                .get(gap.point.index())
                .copied()
                .unwrap_or(false)
                || !matches!(
                    gap.capability,
                    SemanticCapability::NormalControlFlow
                        | SemanticCapability::ExceptionalControlFlow
                        | SemanticCapability::CleanupControlFlow
                        | SemanticCapability::NonLocalControl
                        | SemanticCapability::NormalCallContinuation
                        | SemanticCapability::ExceptionalCallContinuation
                        | SemanticCapability::GeneratorSuspension
                        | SemanticCapability::AsyncSuspendResume
                        | SemanticCapability::DeferredExecution
                )
            {
                continue;
            }
            if gap.kind == SemanticGapKind::ExceededBudget
                || gap.discharge != SemanticGapDischarge::RetainedControlTopology
            {
                return Err("control_flow_gap");
            }
        }

        let node_count = reachable_blocks
            .iter()
            .filter(|reachable| **reachable)
            .count();
        assert!(node_count > 0, "a procedure entry belongs to a basic block");
        assert!(
            edges.len().saturating_add(1) >= node_count,
            "entry-reachable basic blocks form a connected control-flow graph"
        );
        Ok(edges.len().saturating_add(2).saturating_sub(node_count))
    })();
    HierarchyDecision { value, premises }
}

type PrunedControlEdgeKey = (usize, usize, ControlEdgeKind);

fn python_constant_branch_edges(
    source: &str,
    root: Node<'_>,
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
) -> HashSet<PrunedControlEdgeKey> {
    let mut pruned = HashSet::default();
    for point in semantics.points() {
        let Some(span) = semantic_mapping_span(semantics, point.source) else {
            continue;
        };
        let range = span.0 as usize..span.1 as usize;
        let Some(node) = find_exact_node(
            root,
            &range,
            &[
                "if_statement",
                "while_statement",
                "conditional_expression",
                "true",
                "false",
                "none",
                "integer",
                "float",
                "unary_operator",
                "not_operator",
                "parenthesized_expression",
            ],
        ) else {
            continue;
        };
        let condition = match node.kind() {
            "if_statement" | "while_statement" => {
                let Some(condition) = node.child_by_field_name("condition") else {
                    continue;
                };
                condition
            }
            "conditional_expression" => {
                let Some(condition) = node.child_by_field_name("condition") else {
                    continue;
                };
                condition
            }
            _ => node,
        };
        let Some(value) = python_literal_truth(source, condition) else {
            continue;
        };
        for (_, edge) in semantics.successor_edges(point.id) {
            let impossible = match edge.kind {
                ControlEdgeKind::ConditionalTrue => !value,
                ControlEdgeKind::ConditionalFalse => value,
                _ => false,
            };
            if impossible {
                pruned.insert((
                    edge.source_point.index(),
                    edge.target_point.index(),
                    edge.kind,
                ));
            }
        }
    }
    pruned
}

fn python_literal_truth(source: &str, node: Node<'_>) -> Option<bool> {
    match node.kind() {
        "true" => Some(true),
        "false" | "none" => Some(false),
        "parenthesized_expression" => {
            let children = named_children(node);
            let [inner] = children.as_slice() else {
                return None;
            };
            python_literal_truth(source, *inner)
        }
        "not_operator" => {
            let argument = node.child_by_field_name("argument")?;
            Some(!python_literal_truth(source, argument)?)
        }
        "integer" => {
            let value = node_text(source, node)?.replace('_', "");
            let digits = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .or_else(|| value.strip_prefix("0o"))
                .or_else(|| value.strip_prefix("0O"))
                .or_else(|| value.strip_prefix("0b"))
                .or_else(|| value.strip_prefix("0B"))
                .unwrap_or(&value);
            Some(digits.bytes().any(|byte| byte != b'0'))
        }
        "float" => {
            let value = node_text(source, node)?.replace('_', "");
            let value = value
                .strip_suffix('j')
                .or_else(|| value.strip_suffix('J'))
                .unwrap_or(&value);
            let value = value.parse::<f64>().ok()?;
            (!value.is_nan()).then_some(value != 0.0)
        }
        "unary_operator" => {
            let operator = node.child_by_field_name("operator")?;
            let argument = node.child_by_field_name("argument")?;
            (operator.kind() == "-")
                .then(|| python_literal_truth(source, argument))
                .flatten()
        }
        _ => None,
    }
}

fn python_unlikely_exception_edges(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    file: &ProjectFile,
    source: &str,
    method: Node<'_>,
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    cancellation: Option<&CancellationToken>,
) -> HierarchyDecision<Result<HashSet<PrunedControlEdgeKey>, &'static str>> {
    let mut premises = Vec::new();
    let value = (|| {
        let Some(body) = method.child_by_field_name("body") else {
            return Ok(HashSet::default());
        };
        let mut pruned = HashSet::default();
        let mut pending = vec![body];
        while let Some(node) = pending.pop() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err("cancelled");
            }
            if node.id() != body.id()
                && matches!(
                    node.kind(),
                    "function_definition" | "lambda" | "class_definition"
                )
            {
                continue;
            }
            if node.kind() == "try_statement" {
                let clauses = named_children(node)
                    .into_iter()
                    .filter(|child| child.kind() == "except_clause")
                    .collect::<Vec<_>>();
                if named_children(node)
                    .iter()
                    .any(|child| child.kind() == "except_group_clause")
                {
                    return Err("exception_group_handler_unsupported");
                }
                if !clauses.is_empty() {
                    let selected_handler = if let Some(raise) = python_single_raise_try_body(node)
                        .filter(|raise| python_raise_has_semantic_throw(*raise, semantics))
                    {
                        let raised = python_legal_raised_class(
                            analyzer,
                            environment_cache,
                            file,
                            source,
                            raise,
                            cancellation,
                        );
                        premises.extend(raised.premises);
                        if let Some(raised_class) = raised.value {
                            let handler = python_first_matching_handler(
                                analyzer,
                                environment_cache,
                                file,
                                source,
                                node,
                                &raised_class,
                                cancellation,
                            );
                            premises.extend(handler.premises);
                            handler.value
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    let try_span = (node.start_byte() as u32, node.end_byte() as u32);
                    for point in semantics.points() {
                        if semantic_mapping_span(semantics, point.source) != Some(try_span) {
                            continue;
                        }
                        let outgoing = semantics
                            .successor_edges(point.id)
                            .map(|(_, edge)| edge)
                            .collect::<Vec<_>>();
                        let switch_edges = outgoing
                            .iter()
                            .copied()
                            .filter(|edge| edge.kind == ControlEdgeKind::SwitchCase)
                            .collect::<Vec<_>>();
                        let unmatched_edges = outgoing
                            .iter()
                            .copied()
                            .filter(|edge| {
                                edge.kind == ControlEdgeKind::Exceptional
                                    && semantic_mapping_span(
                                        semantics,
                                        semantics
                                            .point(edge.target_point)
                                            .expect("control edge target is validated")
                                            .source,
                                    ) == Some(try_span)
                            })
                            .collect::<Vec<_>>();
                        if switch_edges.is_empty() && unmatched_edges.is_empty() {
                            continue;
                        }
                        if switch_edges.len() != clauses.len() || unmatched_edges.len() > 1 {
                            return Err("exception_handler_topology_unavailable");
                        }
                        let mut case_ordinals = Vec::with_capacity(switch_edges.len());
                        for edge in &switch_edges {
                            let Some(target) = semantics.point(edge.target_point) else {
                                return Err("exception_handler_mapping_unavailable");
                            };
                            let Some(span) = semantic_mapping_span(semantics, target.source) else {
                                return Err("exception_handler_mapping_unavailable");
                            };
                            let Some(ordinal) = clauses.iter().position(|clause| {
                                (clause.start_byte() as u32, clause.end_byte() as u32) == span
                            }) else {
                                return Err("exception_handler_mapping_unavailable");
                            };
                            case_ordinals.push(ordinal);
                        }
                        if case_ordinals.len() != clauses.len()
                            || case_ordinals.iter().copied().collect::<HashSet<_>>().len()
                                != clauses.len()
                        {
                            return Err("exception_handler_mapping_unavailable");
                        }
                        for (edge, ordinal) in switch_edges.iter().zip(case_ordinals) {
                            if selected_handler.is_some_and(|handler| Some(ordinal) != handler) {
                                pruned.insert((
                                    edge.source_point.index(),
                                    edge.target_point.index(),
                                    edge.kind,
                                ));
                            }
                        }
                        for edge in unmatched_edges {
                            pruned.insert((
                                edge.source_point.index(),
                                edge.target_point.index(),
                                edge.kind,
                            ));
                        }
                        if selected_handler == Some(None)
                            && let Some(raise) = python_single_raise_try_body(node)
                        {
                            let raise_span = (raise.start_byte() as u32, raise.end_byte() as u32);
                            for raising_point in semantics.points().iter().filter(|point| {
                                point.events.iter().any(|event| {
                                    matches!(event.effect, SemanticEffect::Throw { .. })
                                        && semantic_mapping_span(semantics, event.source)
                                            == Some(raise_span)
                                })
                            }) {
                                for (_, edge) in semantics.successor_edges(raising_point.id) {
                                    if edge.kind == ControlEdgeKind::Exceptional
                                        && semantics.point(edge.target_point).is_some_and(
                                            |target| {
                                                semantic_mapping_span(semantics, target.source)
                                                    == Some(try_span)
                                            },
                                        )
                                    {
                                        pruned.insert((
                                            edge.source_point.index(),
                                            edge.target_point.index(),
                                            edge.kind,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            pending.extend(named_children(node).into_iter().rev());
        }
        Ok(pruned)
    })();
    HierarchyDecision { value, premises }
}

#[allow(clippy::too_many_arguments)]
fn python_unlikely_call_edges(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    semantic: &mut SemanticQueryContext<'_>,
    bindings: &mut CallBindingCache,
    file: &ProjectFile,
    source: &str,
    method: Node<'_>,
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    mut pruned: HashSet<PrunedControlEdgeKey>,
) -> Result<HashSet<PrunedControlEdgeKey>, &'static str> {
    for call in semantics.call_sites() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err("cancelled");
        }
        let Some(mapping) = semantics.source_mapping(call.source) else {
            continue;
        };
        if mapping.kind != crate::analyzer::semantic::SourceMappingKind::Exact {
            continue;
        }
        let span = mapping.locator.anchor().span();
        let byte_range = span.start_byte() as usize..span.end_byte() as usize;
        let Some(call_node) = find_exact_node(method, &byte_range, &["call"]) else {
            continue;
        };
        let call_range = Range {
            start_byte: byte_range.start,
            end_byte: byte_range.end,
            start_line: span.start().line() as usize + 1,
            end_line: span.end().line() as usize + 1,
        };
        let Some(normal_successor) = call.normal_continuation.target() else {
            continue;
        };

        let function = call_function(call_node).and_then(unwrap_parenthesized);
        let exact_external = function.and_then(|function| {
            let callee_reference = function
                .child_by_field_name("attribute")
                .unwrap_or(function);
            let callee_range = Range {
                start_byte: callee_reference.start_byte(),
                end_byte: callee_reference.end_byte(),
                start_line: callee_reference.start_position().row + 1,
                end_line: callee_reference.end_position().row + 1,
            };
            bindings.resolved_exact_external_callee(analyzer, file, callee_range, cancellation)
        });
        let exact_builtin = function
            .filter(|function| {
                function.kind() == "identifier"
                    && matches!(node_text(source, *function), Some("exit" | "quit"))
            })
            .and_then(|function| {
                builtin_value_identity_at_range(
                    analyzer,
                    environment_cache,
                    file,
                    source,
                    function.start_byte(),
                    function.end_byte(),
                    cancellation,
                    diagnostics,
                )
                .ok()
                .flatten()
            });
        let identity = exact_external.or(exact_builtin);
        let quitter = identity.as_deref().is_some_and(|identity| {
            matches!(
                identity,
                "sys.exit" | "os._exit" | "builtins.exit" | "builtins.quit"
            )
        });

        let never_returns = if quitter {
            false
        } else if let Some((_, target_unit)) =
            exact_local_dispatch_target(semantic, file, call_range)
        {
            let declaration =
                render::declaration_value_for_unit(analyzer, &target_unit, call_range);
            let procedures = semantic.cfg().procedure_of_declaration(&declaration);
            matches!(procedures.as_slice(), [callee] if normal_exit_reachable(callee) == Some(false))
        } else {
            false
        };
        if !quitter && !never_returns {
            continue;
        }
        if never_returns
            && python_normal_successor_is_yield(semantics, method, normal_successor) != Some(false)
        {
            continue;
        }
        for (_, edge) in semantics.successor_edges(call.point) {
            if edge.target_point == normal_successor && edge.kind != ControlEdgeKind::Exceptional {
                pruned.insert((
                    edge.source_point.index(),
                    edge.target_point.index(),
                    edge.kind,
                ));
            }
        }
    }
    Ok(pruned)
}

fn python_normal_successor_is_yield(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    method: Node<'_>,
    successor: crate::analyzer::semantic::ProgramPointId,
) -> Option<bool> {
    let point = semantics.point(successor)?;
    let mapping = semantics.source_mapping(point.source)?;
    if mapping.kind != crate::analyzer::semantic::SourceMappingKind::Exact {
        return None;
    }
    let span = mapping.locator.anchor().span();
    Some(
        find_exact_node(
            method,
            &(span.start_byte() as usize..span.end_byte() as usize),
            &["yield"],
        )
        .is_some(),
    )
}

fn python_raise_has_semantic_throw(
    raise: Node<'_>,
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
) -> bool {
    let span = (raise.start_byte() as u32, raise.end_byte() as u32);
    semantics.points().iter().any(|point| {
        point.events.iter().any(|event| {
            matches!(event.effect, SemanticEffect::Throw { .. })
                && semantic_mapping_span(semantics, event.source) == Some(span)
        })
    })
}

fn semantic_mapping_span(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    mapping: crate::analyzer::semantic::SourceMappingId,
) -> Option<(u32, u32)> {
    let span = semantics.source_mapping(mapping)?.locator.anchor().span();
    Some((span.start_byte(), span.end_byte()))
}

fn python_single_raise_try_body(try_statement: Node<'_>) -> Option<Node<'_>> {
    let body = try_statement.child_by_field_name("body")?;
    let statements = named_children(body)
        .into_iter()
        .filter(|statement| statement.kind() != "comment")
        .collect::<Vec<_>>();
    match statements.as_slice() {
        [raise] if raise.kind() == "raise_statement" => Some(*raise),
        _ => None,
    }
}

fn python_legal_raised_class(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    file: &ProjectFile,
    source: &str,
    raise: Node<'_>,
    cancellation: Option<&CancellationToken>,
) -> HierarchyDecision<Option<ResolvedExceptionClass>> {
    let mut premises = Vec::new();
    let value = (|| {
        let operand = unwrap_parenthesized(raise_operand(raise)?)?;
        let class_node = if operand.kind() == "call" {
            operand.child_by_field_name("function")?
        } else {
            operand
        };
        if class_node.kind() != "identifier" {
            return None;
        }
        let class = resolved_exception_class(
            analyzer,
            environment_cache,
            file,
            source,
            class_node,
            cancellation,
        );
        let proof = resolved_class_subclass_of_builtin(
            analyzer,
            environment_cache,
            &class,
            "BaseException",
            cancellation,
        );
        premises.extend(proof.premises);
        (proof.relation == ExceptionProof::Yes).then_some(class)
    })();
    HierarchyDecision { value, premises }
}

fn python_first_matching_handler(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    file: &ProjectFile,
    source: &str,
    try_statement: Node<'_>,
    raised: &ResolvedExceptionClass,
    cancellation: Option<&CancellationToken>,
) -> HierarchyDecision<Option<Option<usize>>> {
    let mut premises = Vec::new();
    let value = (|| {
        let clauses = named_children(try_statement)
            .into_iter()
            .filter(|child| child.kind() == "except_clause")
            .collect::<Vec<_>>();
        for (index, clause) in clauses.iter().copied().enumerate() {
            let type_nodes = python_except_type_nodes(clause)?;
            let Some(type_nodes) = type_nodes else {
                return Some(Some(index));
            };
            let mut matches = false;
            let mut open = false;
            for type_node in type_nodes {
                let caught = resolved_exception_class(
                    analyzer,
                    environment_cache,
                    file,
                    source,
                    type_node,
                    cancellation,
                );
                let legality = resolved_class_subclass_of_builtin(
                    analyzer,
                    environment_cache,
                    &caught,
                    "BaseException",
                    cancellation,
                );
                premises.extend(legality.premises);
                if legality.relation != ExceptionProof::Yes {
                    open = true;
                    continue;
                }
                let subclass = python_exception_is_subclass(
                    analyzer,
                    environment_cache,
                    raised,
                    &caught,
                    cancellation,
                );
                premises.extend(subclass.premises);
                match subclass.value {
                    Some(true) => matches = true,
                    Some(false) => {}
                    None => open = true,
                }
            }
            if open {
                return None;
            }
            if matches {
                return Some(Some(index));
            }
        }
        Some(None)
    })();
    HierarchyDecision { value, premises }
}

fn python_except_type_nodes(clause: Node<'_>) -> Option<Option<Vec<Node<'_>>>> {
    let Some(value) = clause.child_by_field_name("value") else {
        return Some(None);
    };
    let type_node = if value.kind() == "as_pattern" {
        let alias = value.child_by_field_name("alias")?;
        named_children(value)
            .into_iter()
            .find(|child| child.id() != alias.id())?
    } else {
        value
    };
    let mut nodes = vec![type_node];
    let mut names = Vec::new();
    while let Some(node) = nodes.pop() {
        match node.kind() {
            "parenthesized_expression" => nodes.extend(named_children(node)),
            "tuple" => nodes.extend(named_children(node).into_iter().rev()),
            "identifier" => names.push(node),
            _ => return None,
        }
    }
    Some(Some(names))
}

pub(super) fn python_except_clause_catches_builtin(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    file: &ProjectFile,
    source: &str,
    clause: Node<'_>,
    builtin_name: &str,
    cancellation: Option<&CancellationToken>,
) -> Option<bool> {
    let Some(type_nodes) = python_except_type_nodes(clause)? else {
        return Some(false);
    };
    let mut unresolved = false;
    for type_node in type_nodes {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return None;
        }
        match resolved_exception_class(
            analyzer,
            environment_cache,
            file,
            source,
            type_node,
            cancellation,
        ) {
            ResolvedExceptionClass::Builtin(name) if name == builtin_name => return Some(true),
            ResolvedExceptionClass::Open => unresolved = true,
            ResolvedExceptionClass::Builtin(_)
            | ResolvedExceptionClass::Workspace(_)
            | ResolvedExceptionClass::OtherBuiltin(_)
            | ResolvedExceptionClass::NonClass(_) => {}
        }
    }
    (!unresolved).then_some(false)
}

fn python_exception_is_subclass(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    raised: &ResolvedExceptionClass,
    caught: &ResolvedExceptionClass,
    cancellation: Option<&CancellationToken>,
) -> HierarchyDecision<Option<bool>> {
    let mut premises = Vec::new();
    let value = (|| match (raised, caught) {
        (ResolvedExceptionClass::Builtin(raised), ResolvedExceptionClass::Builtin(caught)) => {
            python_builtin_exception_is_subclass(raised, caught)
        }
        (ResolvedExceptionClass::Workspace(raised), ResolvedExceptionClass::Workspace(caught)) => {
            if raised == caught {
                return Some(true);
            }
            let provider = analyzer.python_class_hierarchy_provider_for(raised)?;
            let hierarchy = provider.class_hierarchy(raised, cancellation);
            premises.push(hierarchy_premise(analyzer, raised, &hierarchy)?);
            (hierarchy.outcome == PythonHierarchyOutcome::Complete).then(|| {
                hierarchy
                    .mro
                    .contains(&ClassIdentity::Workspace(caught.clone()))
            })
        }
        (ResolvedExceptionClass::Workspace(raised), ResolvedExceptionClass::Builtin(caught)) => {
            let proof = workspace_class_subclass_of_builtin(
                analyzer,
                environment_cache,
                raised,
                caught,
                cancellation,
            );
            premises.extend(proof.premises);
            match proof.relation {
                ExceptionProof::Yes => Some(true),
                ExceptionProof::No => Some(false),
                ExceptionProof::Open => None,
            }
        }
        (ResolvedExceptionClass::Builtin(_), ResolvedExceptionClass::Workspace(_)) => Some(false),
        _ => None,
    })();
    HierarchyDecision { value, premises }
}

/// Classify the exact Python call parent used by both the generic
/// `call_result_use` relation and reviewed result-use obligations. An ordinary
/// assignment is intentional consumption, including `_ = value`; only a
/// direct expression statement discards the result.
pub(super) fn python_result_use_for_call_shape(
    shape: &CallShapeValue,
) -> Result<&'static str, &'static str> {
    let source = shape.source().ok_or("missing_call")?;
    let call_span = shape.report.outcome.range.start_byte..shape.report.outcome.range.end_byte;
    let tree = parse_python(source).ok_or("unsupported_syntax")?;
    if tree.root_node().has_error() {
        return Err("recovered_syntax");
    }
    let node = find_exact_node(tree.root_node(), &call_span, &["call"]).ok_or("missing_call")?;
    let mut parent = node.parent();
    while parent.is_some_and(|parent| parent.kind() == "parenthesized_expression") {
        parent = parent.and_then(|parent| parent.parent());
    }
    Ok(
        if parent.is_some_and(|parent| parent.kind() == "expression_statement") {
            "discarded"
        } else {
            "consumed"
        },
    )
}

fn find_callable<'tree>(
    root: Node<'tree>,
    source_range: &std::ops::Range<usize>,
) -> Option<Node<'tree>> {
    find_exact_node(root, source_range, &["function_definition", "lambda"])
}

fn callable_body(callable: Node<'_>) -> Option<Node<'_>> {
    callable.child_by_field_name("body")
}

fn callable_return_nodes(callable: Node<'_>) -> (Vec<Node<'_>>, bool) {
    let Some(body) = callable_body(callable) else {
        return (Vec::new(), false);
    };
    if callable.kind() == "lambda" {
        return (Vec::new(), false);
    }
    let mut stack = vec![body];
    let mut returns = Vec::new();
    let mut has_boundary = false;
    while let Some(node) = stack.pop() {
        if node.id() != body.id()
            && matches!(
                node.kind(),
                "function_definition" | "lambda" | "class_definition"
            )
        {
            continue;
        }
        if node.kind() == "try_statement" || node.kind() == "with_statement" {
            has_boundary = true;
        }
        if node.kind() == "return_statement" {
            returns.push(node);
            continue;
        }
        stack.extend(named_children(node).into_iter().rev());
    }
    (returns, has_boundary)
}

fn reachable_points(procedure: &SemanticProcedureValue) -> Vec<bool> {
    let semantics = procedure.handle.semantics();
    let mut reachable = vec![false; semantics.points().len()];
    let mut stack = vec![semantics.entry_point()];
    while let Some(point) = stack.pop() {
        let index = point.index();
        if std::mem::replace(&mut reachable[index], true) {
            continue;
        }
        stack.extend(
            semantics
                .successor_edges(point)
                .map(|(_, edge)| edge.target_point),
        );
    }
    reachable
}

fn syntax_return_observation(
    source: &str,
    callable: Node<'_>,
    syntax_return: Option<Node<'_>>,
) -> Option<ReturnObservation> {
    let Some(return_node) = syntax_return else {
        let body = callable_body(callable)?;
        if callable.kind() == "lambda" {
            let expression = body;
            let is_value = !is_none_value(expression);
            let (tuple_arity, tuple_complete) = match tuple_arity(expression) {
                Ok(arity) => (arity, true),
                Err(()) => (None, false),
            };
            return Some(ReturnObservation {
                is_value,
                tuple_arity,
                tuple_complete,
                exact: true,
            });
        }
        return None;
    };
    let expressions = named_children(return_node)
        .into_iter()
        .filter(|child| !child.is_extra())
        .collect::<Vec<_>>();
    match expressions.as_slice() {
        [] => Some(ReturnObservation {
            is_value: false,
            tuple_arity: None,
            tuple_complete: true,
            exact: true,
        }),
        [expression] => {
            let (tuple_arity, tuple_complete) =
                match returned_tuple_arity(*expression, return_node, source) {
                    Ok(tuple_arity) => (tuple_arity, true),
                    Err(()) => (None, false),
                };
            Some(ReturnObservation {
                is_value: !is_none_value(*expression),
                tuple_arity,
                tuple_complete,
                exact: true,
            })
        }
        expressions => {
            let tuple_complete = !expressions.iter().any(|child| {
                matches!(
                    child.kind(),
                    "list_splat" | "dictionary_splat" | "parenthesized_list_splat"
                )
            });
            Some(ReturnObservation {
                is_value: true,
                tuple_arity: tuple_complete.then_some(expressions.len()),
                tuple_complete,
                exact: true,
            })
        }
    }
}

/// Distinguish non-tuple syntax from an explicit tuple of unknown arity.
/// Tuple elements may have unknown values without changing their outer count.
fn tuple_arity(mut expression: Node<'_>) -> Result<Option<usize>, ()> {
    while expression.kind() == "parenthesized_expression" {
        expression = named_children(expression)
            .into_iter()
            .find(|child| !child.is_extra())
            .ok_or(())?;
    }
    if !matches!(expression.kind(), "tuple" | "expression_list") {
        return Ok(None);
    }
    let mut arity = 0;
    for child in named_children(expression) {
        if child.is_extra() {
            continue;
        }
        if matches!(
            child.kind(),
            "list_splat" | "dictionary_splat" | "parenthesized_list_splat"
        ) {
            return Err(());
        }
        arity += 1;
    }
    Ok(Some(arity))
}

fn is_none_value(mut expression: Node<'_>) -> bool {
    while expression.kind() == "parenthesized_expression" {
        let Some(inner) = named_children(expression)
            .into_iter()
            .find(|child| !child.is_extra())
        else {
            return false;
        };
        expression = inner;
    }
    expression.kind() == "none"
}

/// Follow one same-block assignment immediately preceding `return name`.
/// Anything more involved needs Python local-flow facts and stays open.
fn returned_tuple_arity(
    expression: Node<'_>,
    return_node: Node<'_>,
    source: &str,
) -> Result<Option<usize>, ()> {
    if let Some(arity) = tuple_arity(expression)? {
        return Ok(Some(arity));
    }
    if expression.kind() != "identifier" {
        return if is_proven_non_tuple_expression(expression) {
            Ok(None)
        } else {
            Err(())
        };
    }
    let Some(block) = return_node.parent().filter(|node| node.kind() == "block") else {
        return Err(());
    };
    let siblings = named_children(block);
    let Some(return_index) = siblings
        .iter()
        .position(|node| node.id() == return_node.id())
    else {
        return Err(());
    };
    let Some(assignment_statement) = return_index
        .checked_sub(1)
        .and_then(|index| siblings.get(index))
        .copied()
    else {
        return Err(());
    };
    let assignment = match assignment_statement.kind() {
        "assignment" => assignment_statement,
        "expression_statement" => {
            let children = named_children(assignment_statement);
            let [assignment] = children.as_slice() else {
                return Err(());
            };
            if assignment.kind() != "assignment" {
                return Err(());
            }
            *assignment
        }
        _ => return Err(()),
    };
    let (Some(left), Some(right)) = (
        assignment.child_by_field_name("left"),
        assignment.child_by_field_name("right"),
    ) else {
        return Err(());
    };
    if left.kind() != "identifier" || node_text(source, left) != node_text(source, expression) {
        return Err(());
    }
    if let Some(arity) = tuple_arity(right)? {
        return Ok(Some(arity));
    }
    if is_proven_non_tuple_expression(right) {
        return Ok(None);
    }
    Err(())
}

fn is_proven_non_tuple_expression(mut expression: Node<'_>) -> bool {
    while expression.kind() == "parenthesized_expression" {
        let Some(inner) = expression.named_child(0) else {
            return false;
        };
        expression = inner;
    }
    if expression.kind() == "comparison_operator" {
        let operators = children_by_field_name(expression, "operators");
        // Membership coerces its successful result to bool, even when the
        // operands dispatch user code. Equality and chained comparisons do
        // not provide this narrow result-shape proof.
        return matches!(operators.as_slice(), [operator] if matches!(operator.kind(), "in" | "not in"))
            && named_children(expression)
                .into_iter()
                .filter(|child| !child.is_extra())
                .count()
                == 2;
    }
    matches!(
        expression.kind(),
        "integer"
            | "float"
            | "string"
            | "concatenated_string"
            | "true"
            | "false"
            | "none"
            | "list"
            | "set"
            | "dictionary"
    )
}

fn is_python_procedure(procedure: &SemanticProcedureValue) -> bool {
    procedure.handle.artifact().key().language().language() == crate::analyzer::Language::Python
}

fn procedure_return_facts(
    analyzer: &dyn IAnalyzer,
    traversal: &mut EnvironmentTraversalCache,
    procedure: &SemanticProcedureValue,
) -> Option<ProcedureReturnFacts> {
    if !is_python_procedure(procedure) {
        return None;
    }
    let source = procedure.source_text();
    let tree = parse_python(source)?;
    if tree.root_node().has_error() {
        return None;
    }
    let semantics = procedure.handle.semantics();
    let callable_range = semantics.locator().anchor().span();
    let callable_span = callable_range.start_byte() as usize..callable_range.end_byte() as usize;
    let callable = find_callable(tree.root_node(), &callable_span)?;
    let body = callable_body(callable)?;
    let properties = semantics.properties();
    let (return_nodes, has_source_boundary) = callable_return_nodes(callable);
    let ordinary = callable.kind() == "function_definition"
        && !properties.is_async
        && !properties.is_generator;
    let mut binding_proof = None;
    let mut all_source_returns_non_tuple = true;
    let mut returns_by_span = HashMap::default();
    for node in return_nodes {
        let mut observation = syntax_return_observation(source, callable, Some(node));
        let expressions = named_children(node)
            .into_iter()
            .filter(|child| !child.is_extra())
            .collect::<Vec<_>>();
        let fresh_function = ordinary
            && matches!(expressions.as_slice(), [expression]
            if unwrap_parenthesized(*expression).is_some_and(|expression| {
                expression.kind() == "identifier"
                    && binding_proof.get_or_insert_with(||
                        traversal.python_return_binding_proof_for(analyzer, procedure))
                        .as_ref().is_some_and(|proof|
                            proof.is_fresh_function_return(callable, node, expression))
            }));
        if fresh_function && let Some(observation) = &mut observation {
            // Returning the function object is still an explicit VALUE return.
            observation.tuple_arity = None;
            observation.tuple_complete = true;
        }
        all_source_returns_non_tuple &= observation
            .as_ref()
            .is_some_and(|observation| !observation.is_value || fresh_function);
        returns_by_span.insert((node.start_byte(), node.end_byte()), observation);
    }
    // Inspect all own source returns, including ones omitted by lowering or
    // hidden behind a finally return. Full-profile gaps remain independent.
    let proved_absent_tuple_returns = ordinary && all_source_returns_non_tuple;
    let reachable = reachable_points(procedure);
    let mut explicit_value_returns = 0;
    let mut none_returns = 0;
    let mut explicit_return_statements = 0;
    let mut fallthrough_none_returns = 0;
    let mut tuple_arities = Vec::new();
    let mut tuple_complete = true;
    let mut tuple_reason = None;
    let mut complete = !properties.is_async && !properties.is_generator && !has_source_boundary;
    let mut reason = if complete {
        None
    } else {
        Some(PYTHON_RETURN_PROFILE_REASON.to_string())
    };
    if semantics
        .guard_facts()
        .iter()
        .any(|guard| guard.predicate.constant_value().is_some())
    {
        complete = false;
        reason = Some("constant_branch_boundary".to_string());
    }
    for gap in semantics.gaps() {
        if reachable[gap.point.index()] && gap.impacts.contains(SemanticGapImpact::ReturnTransfer) {
            complete = false;
            reason.get_or_insert_with(|| gap.detail.to_string());
        }
    }
    for edge in semantics.control_edges() {
        if reachable[edge.source_point.index()]
            && matches!(
                edge.kind,
                crate::analyzer::semantic::ControlEdgeKind::Cleanup
                    | crate::analyzer::semantic::ControlEdgeKind::AsyncNormal
                    | crate::analyzer::semantic::ControlEdgeKind::AsyncExceptional
            )
        {
            complete = false;
            reason.get_or_insert_with(|| "cleanup_or_async_control_flow".to_string());
        }
    }
    for point in semantics.points() {
        if !reachable[point.id.index()] {
            continue;
        }
        for event in &point.events {
            if !matches!(event.effect, SemanticEffect::ProcedureReturn { .. }) {
                continue;
            }
            let Some(mapping) = semantics.source_mapping(event.source) else {
                complete = false;
                reason.get_or_insert_with(|| "return_source_mapping_unresolved".to_string());
                continue;
            };
            let span = mapping.locator.anchor().span();
            let event_span = span.start_byte() as usize..span.end_byte() as usize;
            let syntax_return = returns_by_span.get(&(event_span.start, event_span.end));
            let is_fallthrough = callable.kind() != "lambda"
                && event_span.start == body.start_byte()
                && event_span.end == body.end_byte()
                && syntax_return.is_none();
            let observation = if is_fallthrough {
                Some(ReturnObservation {
                    is_value: false,
                    tuple_arity: None,
                    tuple_complete: true,
                    exact: true,
                })
            } else {
                match syntax_return {
                    Some(observation) => observation.clone(),
                    None => syntax_return_observation(source, callable, None),
                }
            };
            let Some(observation) = observation else {
                complete = false;
                reason.get_or_insert_with(|| "return_source_mapping_unresolved".to_string());
                continue;
            };
            if !observation.exact {
                complete = false;
                reason.get_or_insert_with(|| "return_value_shape_unsupported".to_string());
            }
            if !observation.tuple_complete {
                tuple_complete = false;
                tuple_reason.get_or_insert_with(|| "tuple_return_origin_unresolved".to_string());
            }
            if observation.is_value {
                if syntax_return.is_some() {
                    explicit_value_returns += 1;
                }
            } else {
                none_returns += 1;
            }
            if is_fallthrough {
                fallthrough_none_returns += 1;
            } else if syntax_return.is_some() {
                explicit_return_statements += 1;
            }
            if let Some(arity) = observation.tuple_arity {
                tuple_arities.push(arity);
            }
        }
    }
    debug_assert!(!proved_absent_tuple_returns || tuple_arities.is_empty());
    Some(ProcedureReturnFacts {
        explicit_value_returns,
        none_returns,
        explicit_return_statements,
        fallthrough_none_returns,
        tuple_arities,
        tuple_complete,
        tuple_reason,
        proved_absent_tuple_returns,
        annotated: callable.child_by_field_name("return_type").is_some(),
        is_async: properties.is_async,
        is_generator: properties.is_generator,
        complete,
        reason,
    })
}

pub(super) fn procedure_return_profile_expansions(
    analyzer: &dyn IAnalyzer,
    traversal: &mut EnvironmentTraversalCache,
    procedure: &SemanticProcedureValue,
) -> Vec<PipelineExpansion> {
    if !is_python_procedure(procedure) {
        return Vec::new();
    }
    let public = procedure.public();
    let span = procedure.byte_span();
    let mut value = make_row(
        "procedure_return_profile",
        procedure.file(),
        span,
        public.range,
        Some(public.id),
        "open",
        "none",
        false,
        Some(PYTHON_RETURN_PROFILE_REASON.to_string()),
    );
    if let Some(facts) = procedure_return_facts(analyzer, traversal, procedure) {
        value.row.explicit_value_returns = Some(facts.explicit_value_returns);
        value.row.none_returns = Some(facts.none_returns);
        value.row.explicit_return_statements = Some(facts.explicit_return_statements);
        value.row.fallthrough_none_returns = Some(facts.fallthrough_none_returns);
        value.row.mixed_returns =
            Some(facts.explicit_value_returns > 0 && facts.fallthrough_none_returns > 0);
        value.row.is_async = Some(facts.is_async);
        value.row.is_generator = Some(facts.is_generator);
        value.row.return_contract = Some(if !facts.complete {
            "unknown"
        } else if facts.explicit_return_statements == 0 && facts.fallthrough_none_returns > 0 {
            "always_none"
        } else if facts.explicit_value_returns > 0 {
            "may_return_value"
        } else if facts.explicit_return_statements > 0 && facts.none_returns > 0 {
            "explicit_none"
        } else {
            "unknown"
        });
        value.row.outcome = if facts.complete
            && facts.explicit_value_returns > 0
            && facts.fallthrough_none_returns > 0
        {
            "mixed_returns"
        } else if facts.complete {
            "uniform_returns"
        } else {
            "open"
        };
        value.row.proof = if facts.complete { "proven" } else { "none" };
        value.row.completeness = if facts.complete {
            "complete"
        } else {
            "partial"
        };
        value.row.reason = facts.reason;
    }
    vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
        value,
    )))]
}

fn iterator_return_site_key(
    set: &super::type_flow::OwnedReceiverClassSet,
) -> (String, u32, u32, String) {
    (
        rel_path_string(&set.site.file),
        set.site.span.start_byte(),
        set.site.span.end_byte(),
        set.site.procedure.public_digest().to_string(),
    )
}

fn iterator_set_has_complete_classes(set: &super::type_flow::OwnedReceiverClassSet) -> bool {
    set.status == ClassSetStatus::Known && set.unknown.is_empty() && set.flow_unknown.is_empty()
}

fn iterator_protocol_members(
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    class: &ClassIdentity,
    cancellation: Option<&CancellationToken>,
) -> HierarchyDecision<Option<(bool, bool)>> {
    let mut premises = Vec::new();
    let value = (|| {
        let unit = match class {
            ClassIdentity::Workspace(unit) => unit,
            ClassIdentity::External { .. } => {
                let workspace = workspace?;
                let adapter = type_flow_adapter(Language::Python)
                    .expect("Python supports iterator type flow");
                let lookup = |member| match adapter.member_lookup(
                    workspace,
                    MemberAccessKind::Load,
                    class,
                    member,
                ) {
                    MemberLookup::Present(hit)
                        if hit.dispatch_coverage == CandidateCoverage::Exhaustive =>
                    {
                        Some(true)
                    }
                    MemberLookup::Absent => Some(false),
                    MemberLookup::Present(_)
                    | MemberLookup::DeclarationAbsent
                    | MemberLookup::Unknown(_) => None,
                };
                return Some((lookup("__iter__")?, lookup("__next__")?));
            }
            ClassIdentity::Intrinsic { qualified_name } => {
                // The sole intrinsic root is `builtins.object`, which
                // implements neither iterator protocol member.
                debug_assert_eq!(qualified_name.as_ref(), "builtins.object");
                return Some((false, false));
            }
        };
        let provider = analyzer.python_class_hierarchy_provider_for(unit)?;
        let answer = provider.mro_members(unit, cancellation);
        premises.push(member_premise(analyzer, unit, &answer)?);
        let has_iter = answer
            .members
            .iter()
            .any(|member| member.name == "__iter__");
        let has_next = answer
            .members
            .iter()
            .any(|member| member.name == "__next__");
        let has_dynamic_hook = answer
            .members
            .iter()
            .any(|member| matches!(member.name.as_str(), "__getattr__" | "__getattribute__"));
        if !(has_iter && has_next)
            && (has_dynamic_hook || answer.outcome != PythonHierarchyOutcome::Complete)
        {
            return None;
        }
        Some((has_iter, has_next))
    })();
    HierarchyDecision { value, premises }
}

pub(super) fn iterator_return_protocol_expansions(
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    class_sets: &[super::type_flow::OwnedReceiverClassSet],
    cancellation: Option<&CancellationToken>,
) -> Vec<PipelineExpansion> {
    let mut by_return = HashMap::default();
    for set in class_sets {
        assert_eq!(
            set.site.purpose,
            TypeFlowSitePurpose::PythonIteratorReturn,
            "the iterator return query receives only its typed sink rows"
        );
        let pair = by_return
            .entry(iterator_return_site_key(set))
            .or_insert((None, None));
        match set.site.member.as_ref() {
            "__iter__" => {
                assert!(
                    pair.0.replace(set).is_none(),
                    "one __iter__ sink per return"
                );
            }
            "__next__" => {
                assert!(
                    pair.1.replace(set).is_none(),
                    "one __next__ sink per return"
                );
            }
            member => panic!("unexpected iterator protocol member: {member}"),
        }
    }

    let mut expansions = Vec::new();
    for iter_set in class_sets
        .iter()
        .filter(|set| set.site.member.as_ref() == "__iter__")
    {
        let (Some(iter_set), Some(next_set)) = by_return
            .get(&iterator_return_site_key(iter_set))
            .copied()
            .expect("both protocol sinks share the same return site")
        else {
            unreachable!("each return installs both protocol sinks")
        };
        let source = analyzer
            .get_source(&CodeUnit::file_scope(iter_set.site.file.clone()), false)
            .expect("an iterator return sink retains its source file");
        let return_anchor =
            iter_set.site.span.start_byte() as usize..iter_set.site.span.end_byte() as usize;
        let procedure_id = iter_set.site.procedure.public_digest().to_string();
        let (method_anchor, returns_receiver) = python_iterator_return_facts(
            &iter_set.site.procedure,
            iter_set.site.is_generator,
            &source,
            return_anchor,
        );
        let method_range = row_range(&source, method_anchor.clone());
        let same_classes = iter_set.classes.len() == next_set.classes.len()
            && iter_set
                .classes
                .iter()
                .zip(&next_set.classes)
                .all(|((left, _), (right, _))| left == right);
        let candidate_classes = if same_classes
            && !iter_set.classes.is_empty()
            && iterator_set_has_complete_classes(iter_set)
            && iterator_set_has_complete_classes(next_set)
        {
            Some(
                iter_set
                    .classes
                    .iter()
                    .map(|(class, _)| class.clone())
                    .collect::<Vec<_>>(),
            )
        } else {
            None
        };
        let protocol_classes = candidate_classes.map(|classes| {
            classes
                .into_iter()
                .map(|class| {
                    let decision =
                        iterator_protocol_members(analyzer, workspace, &class, cancellation);
                    (class, decision)
                })
                .collect::<Vec<_>>()
        });
        let open_premises = protocol_classes
            .as_ref()
            .into_iter()
            .flatten()
            .flat_map(|(_, decision)| decision.premises.iter().cloned())
            .collect::<Vec<_>>();
        if let Some(protocol_classes) = protocol_classes
            .filter(|classes| classes.iter().all(|(_, decision)| decision.value.is_some()))
        {
            for (class, decision) in protocol_classes {
                let (has_iter, has_next) =
                    decision.value.expect("checked complete protocol decision");
                let target_id = render::python_hierarchy_endpoint_id(analyzer, &class);
                let is_iterator = has_iter && has_next;
                let mut fact = if is_iterator {
                    make_row(
                        "iterator_return_protocol",
                        &iter_set.site.file,
                        method_anchor.clone(),
                        method_range,
                        Some(procedure_id.clone()),
                        "iterator",
                        "proven",
                        true,
                        None,
                    )
                } else if let ClassIdentity::Workspace(class_unit) = &class
                    && let Some(class_anchor) = python_range_for_unit(analyzer, class_unit)
                {
                    let class_file = class_unit.source();
                    if let Some(class_source) =
                        analyzer.get_source(&CodeUnit::file_scope(class_file.clone()), false)
                    {
                        let anchor = class_anchor.start_byte..class_anchor.end_byte;
                        make_row(
                            "iterator_return_protocol",
                            class_file,
                            anchor.clone(),
                            row_range(&class_source, anchor),
                            Some(render::canonical_member_digest(analyzer, class_unit)),
                            "non_iterator",
                            "proven",
                            true,
                            None,
                        )
                    } else {
                        make_row(
                            "iterator_return_protocol",
                            &iter_set.site.file,
                            method_anchor.clone(),
                            method_range,
                            Some(procedure_id.clone()),
                            "open",
                            "none",
                            false,
                            Some("returned_class_source_unavailable".to_owned()),
                        )
                    }
                } else {
                    // A class without a source range still has a complete
                    // protocol verdict. Anchor its witness at the returning method.
                    make_row(
                        "iterator_return_protocol",
                        &iter_set.site.file,
                        method_anchor.clone(),
                        method_range,
                        Some(procedure_id.clone()),
                        "non_iterator",
                        "proven",
                        true,
                        None,
                    )
                };
                fact.hierarchy_premises = decision.premises;
                fact.row.target_id = Some(target_id.clone());
                fact.row.returns_receiver = returns_receiver;
                let mut digest = LengthDelimitedDigest::new(PYTHON_RULE_FACT_ID_DOMAIN);
                digest.push(fact.row.id.as_bytes());
                digest.push(target_id.as_bytes());
                digest.push(procedure_id.as_bytes());
                fact.row.id = digest.finish().to_string();
                expansions.push(pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
                    fact,
                ))));
            }
        } else {
            let reason = format!(
                "{PYTHON_ITERATOR_RETURN_REASON}: __iter__ status={:?}, unknown={:?}, flow_unknown={:?}; __next__ status={:?}, unknown={:?}, flow_unknown={:?}; same_classes={same_classes}",
                iter_set.status,
                iter_set.unknown,
                iter_set.flow_unknown,
                next_set.status,
                next_set.unknown,
                next_set.flow_unknown
            );
            let mut fact = make_row(
                "iterator_return_protocol",
                &iter_set.site.file,
                method_anchor,
                method_range,
                Some(procedure_id.clone()),
                "open",
                "none",
                false,
                Some(reason),
            );
            fact.hierarchy_premises = open_premises;
            fact.row.returns_receiver = returns_receiver;
            expansions.push(pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
                fact,
            ))));
        }
    }
    expansions
}

fn python_iterator_return_facts(
    procedure: &crate::analyzer::semantic::SemanticProcedureReference,
    is_generator: bool,
    source: &str,
    return_range: std::ops::Range<usize>,
) -> (std::ops::Range<usize>, Option<bool>) {
    let span = procedure.locator.anchor().span();
    let procedure_range = span.start_byte() as usize..span.end_byte() as usize;
    if is_generator {
        return (procedure_range, Some(false));
    }
    let Some(tree) = parse_python(source).filter(|tree| !tree.root_node().has_error()) else {
        return (procedure_range, None);
    };
    let function = find_exact_node(tree.root_node(), &procedure_range, &["function_definition"])
        .or_else(|| {
            let decorated = find_exact_node(
                tree.root_node(),
                &procedure_range,
                &["decorated_definition"],
            )?;
            named_children(decorated)
                .into_iter()
                .find(|child| child.kind() == "function_definition")
        });
    let Some(function) = function else {
        return (procedure_range, None);
    };
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return (procedure_range, None);
    };
    let Some(receiver) = named_children(parameters)
        .into_iter()
        .find_map(|parameter| parameter_name(parameter, source))
    else {
        return (procedure_range, None);
    };
    let Some(return_node) = tree
        .root_node()
        .named_descendant_for_byte_range(return_range.start, return_range.end)
    else {
        return (procedure_range, None);
    };
    if return_node.start_byte() != return_range.start || return_node.end_byte() != return_range.end
    {
        return (procedure_range, None);
    }
    let expression = if return_node.kind() == "return_statement" {
        let expressions = named_children(return_node);
        let [expression] = expressions.as_slice() else {
            return (procedure_range, Some(false));
        };
        *expression
    } else {
        return_node
    };
    let Some(expression) = unwrap_parenthesized(expression) else {
        return (procedure_range, None);
    };
    let returns_receiver = Some(
        expression.kind() == "identifier"
            && node_text(source, expression) == Some(receiver.as_str()),
    );
    (procedure_range, returns_receiver)
}

pub(super) fn builtin_identity_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    occurrence: &OccurrenceValue,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let row = &occurrence.row;
    if crate::analyzer::common::language_for_file(&row.file) != crate::analyzer::Language::Python
        || row.class != crate::analyzer::structural::OccurrenceClass::Reference
        || row.role != crate::analyzer::structural::OccurrenceRole::ValueReference
    {
        return Vec::new();
    }
    let name = row.effective_spelling();
    if !brokk_bifrost_python::diagnostics::is_python_builtin_or_constant(name) {
        return Vec::new();
    }

    let source = analyzer
        .get_source(&CodeUnit::file_scope(row.file.clone()), false)
        .expect("an occurrence row retains its source file");
    let anchor = row.range.start_byte..row.range.end_byte;
    let range = row_range(&source, anchor.clone());
    let environment = environment_cache.environment_for(analyzer, &row.file);
    environment_cache.report_completeness(
        &row.file,
        &environment,
        super::environment::BINDING_QUERY_AXES,
        diagnostics,
    );
    let definition =
        resolve_identifier_range(analyzer, &row.file, &source, anchor.start, anchor.end, None);
    let resolution = resolve_builtin_identity(
        &environment,
        name,
        row.range.start_byte,
        Some(row.namespace),
        definition.as_ref(),
    )
    .expect("the spelling was checked as a Python builtin above");
    let mut fact = builtin_identity_row(
        "builtin_identity",
        &row.file,
        anchor,
        range,
        name,
        resolution,
    );
    let call_callee =
        environment_cache.python_syntax_tree_for(&row.file, row.content_identity, &source);
    if call_callee.is_ok_and(|tree| {
        python_call_callee_at(&tree, &(row.range.start_byte..row.range.end_byte)) == Some(true)
    }) {
        fact.row.call_callee = Some(true);
    }
    vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
        fact,
    )))]
}

fn python_call_callee_at(
    tree: &tree_sitter::Tree,
    occurrence: &std::ops::Range<usize>,
) -> Option<bool> {
    let identifier = find_exact_node(tree.root_node(), occurrence, &["identifier"])?;
    let parent = identifier.parent()?;
    (parent.kind() == "call").then(|| {
        parent
            .child_by_field_name("function")
            .is_some_and(|function| function.id() == identifier.id())
    })
}

fn report_uninitialized_variable_incomplete(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    row: &crate::analyzer::structural::occurrence_rows::OccurrenceRow,
    reason: impl std::fmt::Display,
) {
    let message = format!(
        "{PYTHON_UNINITIALIZED_VARIABLE_REASON}: {} at {}:{} ({reason})",
        row.effective_spelling(),
        super::rel_path_string(&row.file),
        row.range.start_byte,
    );
    if diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::SemanticAnalysisPartial
            && diagnostic.language == "python"
            && diagnostic.message == message
    }) {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        related: Vec::new(),
        source: None,
        code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "python",
        message,
        exhausted_roots: Vec::new(),
        withheld_rows_path: None,
    });
}

/// Check one exact Python value reference against its lexical binding and the
/// local-flow proof for the same source-backed read. Findings are emitted only
/// for a complete may-be-uninitialized answer; module/class/global lookups,
/// builtins and any unmatched flow identity stay typed-incomplete.
#[allow(clippy::too_many_arguments)]
pub(super) fn uninitialized_variable_expansions(
    analyzer: &dyn IAnalyzer,
    workspace: &WorkspaceAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    flow_state_cache: &mut FlowStateTraversalCache,
    environment_cache: &mut EnvironmentTraversalCache,
    occurrence: &OccurrenceValue,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let row = &occurrence.row;
    if crate::analyzer::common::language_for_file(&row.file) != crate::analyzer::Language::Python
        || row.class != crate::analyzer::structural::OccurrenceClass::Reference
        || !matches!(
            row.role,
            crate::analyzer::structural::OccurrenceRole::ValueReference
                | crate::analyzer::structural::OccurrenceRole::ReceiverPosition
        )
    {
        return Vec::new();
    }

    let source = analyzer
        .get_source(&CodeUnit::file_scope(row.file.clone()), false)
        .expect("an occurrence row retains its source file");
    let anchor = row.range.start_byte..row.range.end_byte;
    let rendered_range = row_range(&source, anchor.clone());
    let environment = environment_cache.environment_for(analyzer, &row.file);
    environment_cache.report_completeness(
        &row.file,
        &environment,
        super::environment::BINDING_QUERY_AXES,
        diagnostics,
    );

    let binding_index = match crate::analyzer::structural::lexical_environment::binding_of(
        &environment,
        row.effective_spelling(),
        row.range.start_byte,
        Some(row.namespace),
    ) {
        crate::analyzer::structural::lexical_environment::BindingOfOutcome::Reached(index) => index,
        crate::analyzer::structural::lexical_environment::BindingOfOutcome::Shadowed {
            winner,
            ..
        } => winner,
        crate::analyzer::structural::lexical_environment::BindingOfOutcome::NoBinding => {
            report_uninitialized_variable_incomplete(
                diagnostics,
                row,
                "global or builtin lookup is outside local binding flow",
            );
            return Vec::new();
        }
        crate::analyzer::structural::lexical_environment::BindingOfOutcome::Incomplete(axis) => {
            report_uninitialized_variable_incomplete(
                diagnostics,
                row,
                format!("lexical binding axis {axis:?} is incomplete"),
            );
            return Vec::new();
        }
    };
    let binding = &environment.bindings[binding_index];
    if !matches!(
        binding.kind,
        crate::analyzer::structural::resolution::BindingKind::Local
            | crate::analyzer::structural::resolution::BindingKind::Parameter
            | crate::analyzer::structural::resolution::BindingKind::LoopVariable
    ) {
        report_uninitialized_variable_incomplete(
            diagnostics,
            row,
            format!(
                "binding kind {:?} is outside local-flow coverage",
                binding.kind
            ),
        );
        return Vec::new();
    }
    let binding_scope = environment.scope(binding.declaring_scope);
    if !matches!(
        binding_scope.anchor.kind(),
        Some(
            crate::analyzer::structural::kinds::NormalizedKind::Function
                | crate::analyzer::structural::kinds::NormalizedKind::Method
        )
    ) {
        report_uninitialized_variable_incomplete(
            diagnostics,
            row,
            format!(
                "binding scope {:?} is outside function-local flow",
                binding_scope.anchor.kind()
            ),
        );
        return Vec::new();
    }

    let procedures = semantic.procedure_of_source_range(&row.file, row.range, row.content_identity);
    let [procedure] = procedures.as_slice() else {
        report_uninitialized_variable_incomplete(
            diagnostics,
            row,
            "enclosing procedure is unavailable or ambiguous",
        );
        return Vec::new();
    };
    let procedure_span = procedure.handle.semantics().locator().anchor().span();
    if procedure_span.start_byte() as usize > binding_scope.range.start_byte
        || (procedure_span.end_byte() as usize) < binding_scope.range.end_byte
    {
        report_uninitialized_variable_incomplete(
            diagnostics,
            row,
            "binding belongs to an enclosing procedure or closure",
        );
        return Vec::new();
    }

    let Some(outcome) = semantic.materialized_outcome(&row.file) else {
        report_uninitialized_variable_incomplete(
            diagnostics,
            row,
            "semantic artifact is unavailable",
        );
        return Vec::new();
    };
    let state = flow_state_cache.for_materialized_procedure(
        workspace,
        &row.file,
        outcome,
        &procedure.handle,
        cancellation,
    );
    let Some(derivation) = state
        .procedures
        .iter()
        .find(|derived| derived.procedure == procedure.handle.id())
    else {
        report_uninitialized_variable_incomplete(diagnostics, row, "procedure flow is unavailable");
        return Vec::new();
    };
    let occurrence_ast_id = row.ast_id();
    let semantics = procedure.handle.semantics();
    let matching_events = derivation
        .events
        .iter()
        .filter(|event| {
            let brokk_bifrost_flow::flow_state::FlowSubject::Binding { value } = &event.subject
            else {
                return false;
            };
            let same_binder = semantics.value(*value).is_some_and(|semantic_value| {
                matches!(
                    &semantic_value.kind,
                    crate::analyzer::semantic::SemanticValueKind::Local
                        | crate::analyzer::semantic::SemanticValueKind::Parameter { .. }
                        | crate::analyzer::semantic::SemanticValueKind::Receiver { .. }
                ) && semantics
                    .source_mapping(semantic_value.source)
                    .is_some_and(|source_mapping| {
                        let binder_span = source_mapping.locator.anchor().span();
                        environment.bindings.iter().any(|candidate| {
                            candidate.name == binding.name
                                && candidate.declaring_scope == binding.declaring_scope
                                && candidate.range.start_byte == binder_span.start_byte() as usize
                                && candidate.range.end_byte == binder_span.end_byte() as usize
                        })
                    })
            });
            event.event_class == brokk_bifrost_flow::flow_state::StateEventClass::Read
                && event.site.file == row.file
                && (event.site.ast_id.as_deref() == Some(occurrence_ast_id.as_str())
                    || (event.site.range.start_byte <= row.range.start_byte
                        && row.range.end_byte <= event.site.range.end_byte))
                && same_binder
        })
        .collect::<Vec<_>>();
    let [read] = matching_events.as_slice() else {
        report_uninitialized_variable_incomplete(
            diagnostics,
            row,
            format!(
                "unique CFG read/binder/site join matched {} events",
                matching_events.len()
            ),
        );
        return Vec::new();
    };
    let brokk_bifrost_flow::flow_state::FlowSubject::Binding { value } = &read.subject else {
        report_uninitialized_variable_incomplete(
            diagnostics,
            row,
            "CFG read is a property rather than an ordinary local binding",
        );
        return Vec::new();
    };

    let Some(semantic_value) = semantics.value(*value) else {
        report_uninitialized_variable_incomplete(
            diagnostics,
            row,
            "CFG binding identity is absent",
        );
        return Vec::new();
    };
    if !matches!(
        &semantic_value.kind,
        crate::analyzer::semantic::SemanticValueKind::Local
            | crate::analyzer::semantic::SemanticValueKind::Parameter { .. }
            | crate::analyzer::semantic::SemanticValueKind::Receiver { .. }
    ) {
        report_uninitialized_variable_incomplete(
            diagnostics,
            row,
            format!(
                "CFG value kind {:?} is not a local binding",
                semantic_value.kind
            ),
        );
        return Vec::new();
    }
    let source_mapping = semantics
        .source_mapping(semantic_value.source)
        .expect("semantic binding values retain their source mapping");
    let binder_span = source_mapping.locator.anchor().span();
    let maps_to_lexical_binding = environment.bindings.iter().any(|candidate| {
        candidate.name == binding.name
            && candidate.declaring_scope == binding.declaring_scope
            && candidate.range.start_byte == binder_span.start_byte() as usize
            && candidate.range.end_byte == binder_span.end_byte() as usize
    });
    if !maps_to_lexical_binding {
        report_uninitialized_variable_incomplete(
            diagnostics,
            row,
            "CFG value source does not identify the resolved lexical binder",
        );
        return Vec::new();
    }

    let read_failure_is_handled =
        derivation.binding_read_failure_is_handled(&procedure.handle, read.event);
    let initialization = derivation.binding_initialization_at_read(&procedure.handle, read.event);
    if read_failure_is_handled {
        return Vec::new();
    }

    match initialization {
        brokk_bifrost_flow::flow_state::BindingInitializationAnswer::Proven
        | brokk_bifrost_flow::flow_state::BindingInitializationAnswer::Unreachable => Vec::new(),
        brokk_bifrost_flow::flow_state::BindingInitializationAnswer::MayBeUninitialized => {
            let fact = make_row(
                "undefined_placeholder_variable",
                &row.file,
                anchor,
                rendered_range,
                Some(procedure.wire_id().to_owned()),
                "may_be_uninitialized",
                "proven",
                true,
                None,
            );
            vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
                fact,
            )))]
        }
        brokk_bifrost_flow::flow_state::BindingInitializationAnswer::Open { reasons } => {
            report_uninitialized_variable_incomplete(
                diagnostics,
                row,
                format!("CFG initialization proof is open: {reasons:?}"),
            );
            Vec::new()
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn builtin_value_identity_at_range(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    file: &ProjectFile,
    source: &str,
    start_byte: usize,
    end_byte: usize,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Result<Option<String>, String> {
    if crate::analyzer::common::language_for_file(file) != crate::analyzer::Language::Python {
        return Ok(None);
    }
    let Some(tree) = parse_python(source).filter(|tree| !tree.root_node().has_error()) else {
        return Err(format!(
            "{PYTHON_BUILTIN_IDENTITY_REASON}: Python syntax unavailable"
        ));
    };
    let Some(identifier) =
        find_exact_node(tree.root_node(), &(start_byte..end_byte), &["identifier"])
    else {
        return Ok(None);
    };
    let Some(name) = node_text(source, identifier) else {
        return Err(format!(
            "{PYTHON_BUILTIN_IDENTITY_REASON}: identifier source unavailable"
        ));
    };
    if !brokk_bifrost_python::diagnostics::is_python_builtin_or_constant(name) {
        return Ok(None);
    }
    let environment = environment_cache.environment_for(analyzer, file);
    environment_cache.report_completeness(
        file,
        &environment,
        super::environment::BINDING_QUERY_AXES,
        diagnostics,
    );
    let resolution = builtin_identity_at_identifier(
        analyzer,
        file,
        source,
        identifier,
        &environment,
        cancellation,
    )
    .expect("the spelling was checked as a Python builtin above");
    match resolution.outcome {
        "builtin" if resolution.complete => Ok(Some(format!("builtins.{name}"))),
        "shadowed" | "open" => Err(resolution
            .reason
            .unwrap_or_else(|| format!("{PYTHON_BUILTIN_IDENTITY_REASON}: identity unresolved"))),
        _ => Ok(None),
    }
}

/// Resolve an already selected identifier without reparsing its source tree.
pub(super) fn builtin_identity_at_identifier(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    identifier: Node<'_>,
    environment: &super::super::lexical_environment::EnvironmentFileResult,
    cancellation: Option<&CancellationToken>,
) -> Option<BuiltinIdentityResolution> {
    let name = node_text(source, identifier)?;
    let definition = resolve_identifier_range(
        analyzer,
        file,
        source,
        identifier.start_byte(),
        identifier.end_byte(),
        cancellation,
    );
    resolve_builtin_identity(
        environment,
        name,
        identifier.start_byte(),
        Some(crate::analyzer::structural::Namespace::Value),
        definition.as_ref(),
    )
}

#[derive(Debug)]
pub(super) struct BuiltinIdentityResolution {
    outcome: &'static str,
    proof: &'static str,
    complete: bool,
    reason: Option<String>,
}

impl BuiltinIdentityResolution {
    pub(super) fn is_proven_builtin(&self) -> bool {
        self.outcome == "builtin" && self.complete
    }
}

fn builtin_identity_resolution(
    environment: &super::super::lexical_environment::EnvironmentFileResult,
    name: &str,
    position: usize,
    namespace: Option<crate::analyzer::structural::Namespace>,
    resolver_has_declaration_candidate: bool,
) -> BuiltinIdentityResolution {
    let maybe_wildcard_binding = environment.innermost_scope(position).is_some_and(|scope| {
        let ancestry = environment.scope_ancestry(scope);
        environment.bindings.iter().any(|binding| {
            binding.is_active_at(position)
                && ancestry.contains(&binding.declaring_scope)
                && binding
                    .import
                    .as_ref()
                    .is_some_and(|import| import.wildcard)
        })
    });
    if resolver_has_declaration_candidate {
        return BuiltinIdentityResolution {
            outcome: "shadowed",
            proof: "none",
            complete: false,
            reason: Some(format!(
                "{PYTHON_BUILTIN_IDENTITY_REASON}: a resolved declaration shadows the builtin"
            )),
        };
    }
    match super::super::lexical_environment::binding_of(environment, name, position, namespace) {
        BindingOfOutcome::Reached(_) | BindingOfOutcome::Shadowed { .. } => {
            BuiltinIdentityResolution {
                outcome: "shadowed",
                proof: "none",
                complete: false,
                reason: Some(format!(
                    "{PYTHON_BUILTIN_IDENTITY_REASON}: a local or module binding shadows the builtin"
                )),
            }
        }
        BindingOfOutcome::NoBinding if maybe_wildcard_binding => BuiltinIdentityResolution {
            outcome: "open",
            proof: "none",
            complete: false,
            reason: Some(format!("{PYTHON_BUILTIN_IDENTITY_REASON}: wildcard import")),
        },
        BindingOfOutcome::NoBinding => BuiltinIdentityResolution {
            outcome: "builtin",
            proof: "proven",
            complete: true,
            reason: None,
        },
        BindingOfOutcome::Incomplete(axis) => BuiltinIdentityResolution {
            outcome: "open",
            proof: "none",
            complete: false,
            reason: Some(format!(
                "{PYTHON_BUILTIN_IDENTITY_REASON}: lexical axis {axis:?}"
            )),
        },
    }
}

fn resolve_builtin_identity(
    environment: &super::super::lexical_environment::EnvironmentFileResult,
    name: &str,
    position: usize,
    namespace: Option<crate::analyzer::structural::Namespace>,
    definition: Option<&DefinitionLookupOutcome>,
) -> Option<BuiltinIdentityResolution> {
    brokk_bifrost_python::diagnostics::is_python_builtin_or_constant(name).then(|| {
        let resolver_has_declaration_candidate = definition.is_some_and(|outcome| {
            // An incomplete native candidate still prevents proving builtin
            // identity. Binding certainty and absence of a shadow are distinct.
            !outcome.definitions.is_empty() || outcome.lexical_definition.is_some()
        });
        builtin_identity_resolution(
            environment,
            name,
            position,
            namespace,
            resolver_has_declaration_candidate,
        )
    })
}

fn builtin_identity_row(
    relation: &'static str,
    file: &ProjectFile,
    anchor: std::ops::Range<usize>,
    range: CodeQueryRange,
    name: &str,
    resolution: BuiltinIdentityResolution,
) -> PythonRuleFactValue {
    let mut fact = make_row(
        relation,
        file,
        anchor,
        range,
        None,
        resolution.outcome,
        resolution.proof,
        resolution.complete,
        resolution.reason,
    );
    if resolution.outcome == "builtin" {
        fact.row.target_id = Some(format!("builtins.{name}"));
    }
    fact
}

fn unwrapped_raise_value(mut value: Node<'_>) -> Node<'_> {
    while value.kind() == "parenthesized_expression" {
        let Some(inner) = value.named_child(0) else {
            return value;
        };
        value = inner;
    }
    value
}

fn assignment_expression(statement: Node<'_>) -> Option<Node<'_>> {
    match statement.kind() {
        "assignment" => Some(statement),
        "expression_statement" => {
            let children = named_children(statement);
            let [assignment] = children.as_slice() else {
                return None;
            };
            (assignment.kind() == "assignment").then_some(*assignment)
        }
        _ => None,
    }
}

fn preceding_not_implemented_alias<'tree>(
    alias: Node<'tree>,
    raise_statement: Node<'tree>,
    source: &str,
    environment: &super::super::lexical_environment::EnvironmentFileResult,
) -> Option<(Node<'tree>, bool)> {
    if alias.kind() != "identifier" {
        return None;
    }
    let alias_name = node_text(source, alias)?;
    let block = raise_statement
        .parent()
        .filter(|parent| parent.kind() == "block")?;
    let siblings = named_children(block);
    let raise_index = siblings
        .iter()
        .position(|node| node.id() == raise_statement.id())?;
    let previous = raise_index
        .checked_sub(1)
        .and_then(|index| siblings.get(index))?;
    let assignment = assignment_expression(*previous)?;
    let left = assignment.child_by_field_name("left")?;
    let right = assignment.child_by_field_name("right")?;
    if left.kind() != "identifier"
        || node_text(source, left) != Some(alias_name)
        || right.kind() != "identifier"
        || node_text(source, right) != Some("NotImplemented")
    {
        return None;
    }
    let binding_index = environment.bindings.iter().position(|binding| {
        binding.name == alias_name
            && binding.node.is_some()
            && binding.range.start_byte == left.start_byte()
            && binding.range.end_byte == left.end_byte()
    })?;
    let binding_matches_read = match super::super::lexical_environment::binding_of(
        environment,
        alias_name,
        alias.start_byte(),
        Some(crate::analyzer::structural::Namespace::Value),
    ) {
        BindingOfOutcome::Reached(winner) => winner == binding_index,
        BindingOfOutcome::Shadowed { winner, .. } => winner == binding_index,
        BindingOfOutcome::NoBinding | BindingOfOutcome::Incomplete(_) => false,
    };
    Some((right, binding_matches_read))
}

pub(super) fn raise_not_implemented_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    seed: &SeedMatch,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if seed.language != crate::analyzer::Language::Python {
        return Vec::new();
    }
    let source = seed.facts.source();
    let seed_range = seed.facts.node(seed.fact_match.node).range;
    let seed_bytes = seed_range.start_byte..seed_range.end_byte;
    let Some(tree) = parse_python(source).filter(|tree| !tree.root_node().has_error()) else {
        let range = row_range(source, seed_bytes.clone());
        let fact = make_row(
            "raise_not_implemented",
            &seed.file,
            seed_bytes,
            range,
            None,
            "open",
            "none",
            false,
            Some(format!(
                "{PYTHON_RAISE_NOT_IMPLEMENTED_REASON}: syntax unavailable"
            )),
        );
        return vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
            fact,
        )))];
    };
    let Some(raise_statement) =
        find_exact_node(tree.root_node(), &seed_bytes, &["raise_statement"])
    else {
        return Vec::new();
    };
    let Some(raised_value) = raise_statement.named_child(0) else {
        return Vec::new();
    };
    let raised_value = unwrapped_raise_value(raised_value);
    let candidate = raised_value;
    let environment = environment_cache.environment_for(analyzer, &seed.file);
    environment_cache.report_completeness(
        &seed.file,
        &environment,
        super::environment::BINDING_QUERY_AXES,
        diagnostics,
    );
    let (identity_node, alias_binding_matches) = match candidate.kind() {
        "call" => {
            let Some(function) = call_function(candidate).and_then(unwrap_parenthesized) else {
                return Vec::new();
            };
            if function.kind() != "identifier"
                || node_text(source, function) != Some("NotImplemented")
            {
                return Vec::new();
            }
            (function, true)
        }
        "identifier" => {
            let Some(direct_name) = node_text(source, candidate) else {
                return Vec::new();
            };
            if direct_name == "NotImplemented" {
                (candidate, true)
            } else if let Some((identity_node, binding_matches)) =
                preceding_not_implemented_alias(candidate, raise_statement, source, &environment)
            {
                (identity_node, binding_matches)
            } else {
                return Vec::new();
            }
        }
        _ => return Vec::new(),
    };
    let definition = resolve_identifier(analyzer, &seed.file, source, identity_node, None);
    let mut resolution = resolve_builtin_identity(
        &environment,
        "NotImplemented",
        identity_node.start_byte(),
        Some(crate::analyzer::structural::Namespace::Value),
        definition.as_ref(),
    )
    .expect("NotImplemented is in Python's builtin inventory");
    if !alias_binding_matches {
        resolution.outcome = "open";
        resolution.proof = "none";
        resolution.complete = false;
        resolution.reason = Some(format!(
            "{PYTHON_RAISE_NOT_IMPLEMENTED_REASON}: alias binding is unresolved"
        ));
    }
    let anchor = candidate.start_byte()..candidate.end_byte();
    let range = row_range(source, anchor.clone());
    let mut fact = builtin_identity_row(
        "raise_not_implemented",
        &seed.file,
        anchor,
        range,
        "NotImplemented",
        resolution,
    );
    fact.row.raised_expression = node_text(source, candidate).map(str::to_owned);
    vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
        fact,
    )))]
}

pub(super) fn tuple_return_group_expansions(
    analyzer: &dyn IAnalyzer,
    traversal: &mut EnvironmentTraversalCache,
    procedure: &SemanticProcedureValue,
) -> Vec<PipelineExpansion> {
    if !is_python_procedure(procedure) {
        return Vec::new();
    }
    let public = procedure.public();
    let span = procedure.byte_span();
    let mut value = make_row(
        "tuple_return_groups",
        procedure.file(),
        span,
        public.range,
        Some(public.id),
        "open",
        "none",
        false,
        Some(PYTHON_TUPLE_GROUP_REASON.to_string()),
    );
    if let Some(facts) = procedure_return_facts(analyzer, traversal, procedure) {
        let tuple_count = facts.tuple_arities.len();
        let distinct_tuple_arities = facts
            .tuple_arities
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .len();
        let mut tuple_return_arities = facts
            .tuple_arities
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        tuple_return_arities.sort_unstable();
        value.row.tuple_return_count = Some(tuple_count);
        value.row.distinct_tuple_arities = Some(distinct_tuple_arities);
        if tuple_return_arities.len() <= MAX_PYTHON_TUPLE_RETURN_ARITIES {
            value.row.tuple_return_arities = Some(
                tuple_return_arities
                    .into_iter()
                    .map(|arity| {
                        u64::try_from(arity).expect("Python tuple arity fits a public integer")
                    })
                    .collect(),
            );
        }
        value.row.mixed_tuple_arities = Some(distinct_tuple_arities > 1);
        value.row.annotated = Some(facts.annotated);
        value.row.is_async = Some(facts.is_async);
        value.row.is_generator = Some(facts.is_generator);
        if facts.annotated {
            value.row.outcome = "excluded";
            value.row.proof = "proven";
            value.row.completeness = "complete";
            value.row.reason = None;
        } else {
            let complete =
                (facts.complete && facts.tuple_complete) || facts.proved_absent_tuple_returns;
            value.row.outcome = if !complete {
                "open"
            } else if distinct_tuple_arities > 1 {
                "mixed_tuple_arities"
            } else {
                "uniform_tuple_arities"
            };
            value.row.proof = if complete { "proven" } else { "none" };
            value.row.completeness = if complete { "complete" } else { "partial" };
            value.row.reason = if facts.proved_absent_tuple_returns {
                None
            } else {
                facts.reason.or(facts.tuple_reason)
            };
        }
        if !facts.annotated && distinct_tuple_arities > MAX_PYTHON_TUPLE_RETURN_ARITIES {
            value.row.outcome = "open";
            value.row.proof = "none";
            value.row.completeness = "partial";
            value.row.reason = Some("tuple_return_arity_limit_exceeded".to_owned());
        }
    }
    vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
        value,
    )))]
}

fn python_direct_assignment_target_count(left: Node<'_>) -> Option<usize> {
    let left = unwrap_parenthesized(left)?;
    if !matches!(
        left.kind(),
        "tuple_pattern" | "pattern_list" | "list_pattern"
    ) {
        return None;
    }
    let targets = named_children(left)
        .into_iter()
        .filter(|target| target.kind() != "comment")
        .collect::<Vec<_>>();
    if targets.is_empty()
        || targets
            .iter()
            .any(|target| matches!(target.kind(), "list_splat_pattern" | "splat_pattern"))
    {
        return None;
    }
    Some(targets.len())
}

pub(super) fn tuple_return_assignment_expansions(
    analyzer: &dyn IAnalyzer,
    traversal: &mut EnvironmentTraversalCache,
    seed: &SeedMatch,
    semantic: &mut SemanticQueryContext<'_>,
) -> Vec<PipelineExpansion> {
    if seed.language != crate::analyzer::Language::Python {
        return Vec::new();
    }
    let source = seed.facts.source();
    let assignment_span = seed.facts.node(seed.fact_match.node).range;
    let assignment_bytes = assignment_span.start_byte..assignment_span.end_byte;
    let Some(tree) = parse_python(source).filter(|tree| !tree.root_node().has_error()) else {
        return Vec::new();
    };
    let Some(assignment) = find_exact_node(tree.root_node(), &assignment_bytes, &["assignment"])
    else {
        return Vec::new();
    };
    let Some(target_count) = assignment
        .child_by_field_name("left")
        .and_then(python_direct_assignment_target_count)
    else {
        return Vec::new();
    };
    let Some(call) = assignment
        .child_by_field_name("right")
        .and_then(unwrap_parenthesized)
        .filter(|right| right.kind() == "call")
    else {
        return Vec::new();
    };
    let assignment_range = row_range(source, assignment_bytes.clone());
    let mut value = make_row(
        "tuple_return_groups",
        &seed.file,
        assignment_bytes,
        assignment_range,
        None,
        "open",
        "none",
        false,
        Some(PYTHON_TUPLE_GROUP_REASON.to_owned()),
    );
    value.row.assignment_target_count = Some(target_count);
    value.row.assignment_arity_match = Some("unknown");
    let call_bytes = call.start_byte()..call.end_byte();
    let call_range = row_range(source, call_bytes.clone());
    let dispatch_range = Range {
        start_byte: call_bytes.start,
        end_byte: call_bytes.end,
        start_line: call_range.start_line,
        end_line: call_range.end_line,
    };
    let Some((target_id, unit)) = exact_local_dispatch_target(semantic, &seed.file, dispatch_range)
    else {
        return vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
            value,
        )))];
    };
    value.row.target_id = Some(target_id);
    let declaration = render::declaration_value_for_unit(analyzer, &unit, dispatch_range);
    let procedures = semantic.cfg().procedure_of_declaration(&declaration);
    if procedures.len() != 1 || procedures[0].exact_selection_incomplete_reason().is_some() {
        value.row.reason = Some("tuple_return_target_procedure_unresolved".to_owned());
        return vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
            value,
        )))];
    }
    let Some(facts) = procedure_return_facts(analyzer, traversal, &procedures[0]) else {
        value.row.reason = Some("tuple_return_target_profile_unavailable".to_owned());
        return vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
            value,
        )))];
    };
    value.row.tuple_return_count = Some(facts.tuple_arities.len());
    value.row.annotated = Some(facts.annotated);
    value.row.is_async = Some(facts.is_async);
    value.row.is_generator = Some(facts.is_generator);
    let distinct = facts.tuple_arities.iter().copied().collect::<HashSet<_>>();
    value.row.distinct_tuple_arities = Some(distinct.len());
    value.row.mixed_tuple_arities = Some(distinct.len() > 1);
    if distinct.len() <= MAX_PYTHON_TUPLE_RETURN_ARITIES {
        let mut arities = distinct.iter().copied().collect::<Vec<_>>();
        arities.sort_unstable();
        value.row.tuple_return_arities = Some(
            arities
                .into_iter()
                .map(|arity| {
                    u64::try_from(arity).expect("Python tuple arity fits a public integer")
                })
                .collect(),
        );
    }
    if facts.annotated {
        value.row.outcome = "excluded";
        value.row.proof = "proven";
        value.row.completeness = "complete";
        value.row.assignment_arity_match = Some("unknown");
        value.row.reason = None;
    } else if facts.complete && facts.tuple_complete && !facts.tuple_arities.is_empty() {
        let matches = facts
            .tuple_arities
            .iter()
            .all(|arity| *arity == target_count);
        value.row.assignment_arity_match = Some(if matches { "yes" } else { "no" });
        value.row.outcome = if distinct.len() > 1 {
            "mixed_tuple_arities"
        } else {
            "uniform_tuple_arities"
        };
        value.row.proof = "proven";
        value.row.completeness = "complete";
        value.row.reason = None;
    } else {
        value.row.reason = facts.reason.or(facts.tuple_reason);
    }
    if !facts.annotated && distinct.len() > MAX_PYTHON_TUPLE_RETURN_ARITIES {
        value.row.outcome = "open";
        value.row.proof = "none";
        value.row.completeness = "partial";
        value.row.assignment_arity_match = Some("unknown");
        value.row.reason = Some("tuple_return_arity_limit_exceeded".to_owned());
    }
    vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
        value,
    )))]
}

fn exact_local_dispatch_target(
    semantic: &mut SemanticQueryContext<'_>,
    file: &ProjectFile,
    range: Range,
) -> Option<(String, CodeUnit)> {
    let answer = semantic.dispatch_at_source(file, range);
    if answer.outcome != "resolved"
        || !answer.coverage.is_exhaustive()
        || answer.call_site_count != 1
        || !answer.unnamed_boundaries.is_empty()
    {
        return None;
    }
    let [arm] = answer.arms.as_slice() else {
        return None;
    };
    if arm.proof != "proven" || arm.completeness != "complete" {
        return None;
    }
    Some((arm.target_id.clone(), arm.target_unit.clone()?))
}

pub(super) fn call_result_use_expansions(
    analyzer: &dyn IAnalyzer,
    traversal: &mut EnvironmentTraversalCache,
    semantic: &mut SemanticQueryContext<'_>,
    shape: &CallShapeValue,
) -> Vec<PipelineExpansion> {
    if shape.report.outcome.file.language() != crate::analyzer::Language::Python {
        return Vec::new();
    }
    let source = shape
        .source()
        .expect("public call-shape rows retain their exact source snapshot");
    let call_span = shape.report.outcome.range.start_byte..shape.report.outcome.range.end_byte;
    let result_use = python_result_use_for_call_shape(shape).ok();
    let file = &shape.report.outcome.file;
    let public_range = row_range(source, call_span.clone());
    let mut value = make_row(
        "call_result_use",
        file,
        call_span.clone(),
        public_range,
        None,
        "open",
        "none",
        false,
        Some(PYTHON_CALL_USE_REASON.to_string()),
    );
    if let Some(result_use) = result_use {
        value.row.result_use = Some(result_use);
        value.row.outcome = result_use;
        value.row.proof = "proven";
        value.row.reason = Some("call_return_contract_unresolved".to_string());
        let range = shape.report.outcome.range;
        if let Some((target_id, unit)) = exact_local_dispatch_target(semantic, file, range) {
            value.row.target_id = Some(target_id);
            let declaration = render::declaration_value_for_unit(analyzer, &unit, range);
            let procedures = semantic.cfg().procedure_of_declaration(&declaration);
            if procedures.len() == 1
                && procedures[0].exact_selection_incomplete_reason().is_none()
                && let Some(facts) = procedure_return_facts(analyzer, traversal, &procedures[0])
                && facts.complete
            {
                let contract = if facts.explicit_return_statements == 0
                    && facts.fallthrough_none_returns > 0
                {
                    "always_none"
                } else if facts.explicit_value_returns > 0 {
                    "may_return_value"
                } else if facts.explicit_return_statements > 0 && facts.none_returns > 0 {
                    "explicit_none"
                } else {
                    "unknown"
                };
                value.row.return_contract = Some(contract);
                if contract == "unknown" {
                    value.row.reason = Some("call_return_profile_has_no_normal_result".to_string());
                } else {
                    value.row.completeness = "complete";
                    value.row.reason = None;
                }
            } else if procedures.len() == 1 {
                value.row.reason = Some("call_return_profile_incomplete".to_string());
            }
        }
    }
    vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
        value,
    )))]
}

fn lambda_parameters(
    lambda: Node<'_>,
    source: &str,
) -> Option<Vec<(String, Option<PythonParameterSplat>)>> {
    let parameters = lambda.child_by_field_name("parameters")?;
    named_children(parameters)
        .into_iter()
        .map(|parameter| {
            let name = python_parameter_label_node(parameter)?;
            Some((
                node_text(source, name)?.to_owned(),
                python_parameter_splat(parameter),
            ))
        })
        .collect()
}

fn lambda_default_equivalence(lambda: Node<'_>) -> &'static str {
    let Some(parameters) = lambda.child_by_field_name("parameters") else {
        return "unknown";
    };
    let mut has_default = false;
    for parameter in named_children(parameters) {
        match parameter.kind() {
            "identifier"
            | "typed_parameter"
            | "list_splat_pattern"
            | "dictionary_splat_pattern" => {}
            "default_parameter" | "typed_default_parameter" => has_default = true,
            _ => return "unknown",
        }
    }
    if has_default { "no" } else { "yes" }
}

fn lambda_call_arguments(call: Node<'_>) -> Option<Vec<Node<'_>>> {
    let arguments = call.child_by_field_name("arguments")?;
    Some(named_children(arguments))
}

fn forwarded_identifier<'a>(mut argument: Node<'_>, source: &'a str) -> Option<&'a str> {
    while argument.kind() == "parenthesized_expression" {
        argument = argument.named_child(0)?;
    }
    (argument.kind() == "identifier")
        .then(|| node_text(source, argument))
        .flatten()
}

fn lambda_callable_evaluation_time(
    mut callable: Node<'_>,
    parameters: &[(String, Option<PythonParameterSplat>)],
    source: &str,
) -> &'static str {
    loop {
        match callable.kind() {
            "call" => return "invocation",
            "identifier" => {
                let Some(name) = node_text(source, callable) else {
                    return "unknown";
                };
                return if parameters.iter().any(|(parameter, _)| parameter == name) {
                    "invocation"
                } else {
                    "stable_at_creation"
                };
            }
            "attribute" => {
                let Some(object) = callable.child_by_field_name("object") else {
                    return "unknown";
                };
                callable = object;
            }
            _ => return "unknown",
        }
    }
}

fn lambda_argument_forwards_parameter(
    name: &str,
    parameter_splat: Option<PythonParameterSplat>,
    mut argument: Node<'_>,
    source: &str,
) -> bool {
    let argument_splat = match argument.kind() {
        "list_splat" => Some(PythonParameterSplat::Positional),
        "dictionary_splat" => Some(PythonParameterSplat::Keyword),
        _ => None,
    };
    if parameter_splat != argument_splat {
        return false;
    }
    if argument_splat.is_some() {
        let Some(inner) = argument.named_child(0) else {
            return false;
        };
        argument = inner;
    }
    forwarded_identifier(argument, source) == Some(name)
}

pub(super) fn lambda_forwarding_expansions(
    _analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    semantic: &mut SemanticQueryContext<'_>,
) -> Vec<PipelineExpansion> {
    if seed.language != crate::analyzer::Language::Python {
        return Vec::new();
    }
    let source = seed.facts.source();
    let lambda_span = seed.facts.node(seed.fact_match.node).range;
    let lambda_bytes = lambda_span.start_byte..lambda_span.end_byte;
    let tree = parse_python(source);
    let lambda = tree
        .as_ref()
        .filter(|tree| !tree.root_node().has_error())
        .and_then(|tree| find_exact_node(tree.root_node(), &lambda_bytes, &["lambda"]));
    let row_range = row_range(source, lambda_bytes.clone());
    let mut value = make_row(
        "lambda_forwarding",
        &seed.file,
        lambda_bytes,
        row_range,
        None,
        "open",
        "none",
        false,
        Some(PYTHON_LAMBDA_REASON.to_string()),
    );
    if let Some(lambda) = lambda {
        value.row.default_equivalent = Some(lambda_default_equivalence(lambda));
    }
    if let Some(lambda) = lambda
        && let Some(parameters) = lambda_parameters(lambda, source)
    {
        value.row.parameter_count = Some(parameters.len());
        if let Some(body) = callable_body(lambda)
            && body.kind() == "call"
            && let Some(arguments) = lambda_call_arguments(body)
        {
            let callable = call_function(body);
            let evaluation_time = callable
                .map(|function| lambda_callable_evaluation_time(function, &parameters, source))
                .unwrap_or("unknown");
            value.row.callable_evaluation_time = Some(evaluation_time);
            let forwarded = parameters.len() == arguments.len()
                && parameters
                    .iter()
                    .zip(&arguments)
                    .all(|((name, parameter_splat), argument)| {
                        lambda_argument_forwards_parameter(
                            name,
                            *parameter_splat,
                            *argument,
                            source,
                        )
                    });
            value.row.forwarded = Some(forwarded);
            let range = Range {
                start_byte: body.start_byte(),
                end_byte: body.end_byte(),
                start_line: row_range.start_line,
                end_line: row_range.end_line,
            };
            if !forwarded {
                value.row.outcome = "changed";
                value.row.proof = "proven";
                value.row.completeness = "complete";
                value.row.reason = None;
            } else if value.row.default_equivalent == Some("no") || evaluation_time == "invocation"
            {
                value.row.outcome = "excluded";
                value.row.proof = "proven";
                value.row.completeness = "complete";
                value.row.reason = None;
            } else if evaluation_time == "stable_at_creation"
                && value.row.default_equivalent == Some("yes")
            {
                if let Some((target_id, _)) =
                    exact_local_dispatch_target(semantic, &seed.file, range)
                {
                    value.row.target_id = Some(target_id);
                }
                value.row.outcome = "forwarded";
                value.row.proof = "proven";
                value.row.completeness = "complete";
                value.row.reason = None;
            }
        }
    }
    vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
        value,
    )))]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExceptionProof {
    Yes,
    No,
    Open,
}

#[derive(Debug, Clone)]
enum ResolvedExceptionClass {
    Builtin(&'static str),
    Workspace(CodeUnit),
    OtherBuiltin(String),
    NonClass(CodeUnit),
    Open,
}

#[derive(Debug, Clone)]
struct WorkspaceClassProof {
    relation: ExceptionProof,
    default_metaclass: bool,
    premises: Vec<PythonHierarchyFactValue>,
}

fn raise_operand(raise: Node<'_>) -> Option<Node<'_>> {
    raise
        .child_by_field_name("value")
        .or_else(|| raise.named_child(0))
}

fn unwrap_parenthesized(mut node: Node<'_>) -> Option<Node<'_>> {
    while node.kind() == "parenthesized_expression" {
        node = node.named_child(0)?;
    }
    Some(node)
}

fn call_function(call: Node<'_>) -> Option<Node<'_>> {
    call.child_by_field_name("function")
        .or_else(|| call.named_child(0))
}

fn resolve_identifier(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    identifier: Node<'_>,
    cancellation: Option<&CancellationToken>,
) -> Option<DefinitionLookupOutcome> {
    if identifier.kind() != "identifier" {
        return None;
    }
    resolve_identifier_range(
        analyzer,
        file,
        source,
        identifier.start_byte(),
        identifier.end_byte(),
        cancellation,
    )
}

fn resolve_identifier_range(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    start_byte: usize,
    end_byte: usize,
    cancellation: Option<&CancellationToken>,
) -> Option<DefinitionLookupOutcome> {
    let fallback = CancellationToken::default();
    let cancellation = cancellation.unwrap_or(&fallback);
    let outcomes = resolve_definition_batch_with_source_and_cancellation(
        analyzer,
        vec![DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start_byte),
            end_byte: Some(end_byte),
        }],
        file.clone(),
        Arc::<str>::from(source),
        cancellation,
    );
    let [outcome] = outcomes.as_slice() else {
        return None;
    };
    Some(outcome.clone())
}

fn exception_class_from_builtin_identity(
    environment: &super::super::lexical_environment::EnvironmentFileResult,
    name: &str,
    position: usize,
    definition: Option<&DefinitionLookupOutcome>,
) -> Option<ResolvedExceptionClass> {
    let resolution = resolve_builtin_identity(
        environment,
        name,
        position,
        Some(crate::analyzer::structural::Namespace::Value),
        definition,
    )?;
    match resolution.outcome {
        "builtin" => Some(match python_builtin_exception_name(name) {
            Some(name) => ResolvedExceptionClass::Builtin(name),
            None => ResolvedExceptionClass::OtherBuiltin(name.to_owned()),
        }),
        "open" => Some(ResolvedExceptionClass::Open),
        "shadowed" => None,
        _ => unreachable!("builtin identity resolution has a closed outcome set"),
    }
}

fn resolved_exception_class(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    file: &ProjectFile,
    source: &str,
    identifier: Node<'_>,
    cancellation: Option<&CancellationToken>,
) -> ResolvedExceptionClass {
    let Some(name) = node_text(source, identifier) else {
        return ResolvedExceptionClass::Open;
    };
    let environment = environment_cache.environment_for(analyzer, file);
    let outcome = resolve_identifier(analyzer, file, source, identifier, cancellation);
    if let Some(class) = exception_class_from_builtin_identity(
        &environment,
        name,
        identifier.start_byte(),
        outcome.as_ref(),
    ) {
        return class;
    }
    let Some(outcome) = outcome else {
        return ResolvedExceptionClass::Open;
    };
    if outcome.status != DefinitionLookupStatus::Resolved {
        return ResolvedExceptionClass::Open;
    }
    let [unit] = outcome.definitions.as_slice() else {
        return ResolvedExceptionClass::Open;
    };
    if unit.is_class() {
        ResolvedExceptionClass::Workspace(unit.clone())
    } else {
        ResolvedExceptionClass::NonClass(unit.clone())
    }
}

pub(super) fn python_class_node_for_unit<'tree>(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    tree: &'tree tree_sitter::Tree,
) -> Option<Node<'tree>> {
    for range in analyzer.ranges(unit) {
        let Some(mut node) = tree
            .root_node()
            .named_descendant_for_byte_range(range.start_byte, range.end_byte)
        else {
            continue;
        };
        if node.kind() == "decorated_definition"
            && let Some(class) = named_children(node)
                .into_iter()
                .find(|child| child.kind() == "class_definition")
        {
            return Some(class);
        }
        loop {
            if node.kind() == "class_definition" {
                return Some(node);
            }
            if node.kind() == "decorated_definition"
                && let Some(class) = named_children(node)
                    .into_iter()
                    .find(|child| child.kind() == "class_definition")
            {
                return Some(class);
            }
            let Some(parent) = node.parent() else {
                break;
            };
            node = parent;
        }
    }
    None
}

fn python_class_base_nodes(class: Node<'_>) -> Vec<Node<'_>> {
    let Some(superclasses) = class.child_by_field_name("superclasses") else {
        return Vec::new();
    };
    named_children(superclasses)
        .into_iter()
        .filter(|base| base.kind() != "keyword_argument")
        .map(|base| {
            if base.kind() == "subscript"
                && let Some(value) = base.child_by_field_name("value")
                && matches!(value.kind(), "identifier" | "attribute")
            {
                value
            } else {
                base
            }
        })
        .collect()
}

fn has_explicit_metaclass(class: Node<'_>, source: &str) -> bool {
    class
        .child_by_field_name("superclasses")
        .is_some_and(|superclasses| {
            named_children(superclasses).into_iter().any(|base| {
                base.kind() == "keyword_argument"
                    && base
                        .child_by_field_name("name")
                        .is_some_and(|name| node_text(source, name) == Some("metaclass"))
            })
        })
}

fn known_non_exception_builtin_class(name: &str) -> bool {
    matches!(
        name,
        "object"
            | "bool"
            | "bytearray"
            | "bytes"
            | "complex"
            | "dict"
            | "enumerate"
            | "filter"
            | "float"
            | "frozenset"
            | "int"
            | "list"
            | "map"
            | "memoryview"
            | "range"
            | "reversed"
            | "set"
            | "slice"
            | "str"
            | "tuple"
            | "zip"
            | "property"
            | "classmethod"
            | "staticmethod"
            | "super"
    )
}

fn workspace_class_subclass_of_builtin(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    selected: &CodeUnit,
    expected: &str,
    cancellation: Option<&CancellationToken>,
) -> WorkspaceClassProof {
    let mut premises = Vec::new();
    let mut proof = (|| {
        let mut stack = vec![selected.clone()];
        let mut visited = HashSet::<CodeUnit>::default();
        let mut visits = 0usize;
        let mut default_metaclass = true;

        while let Some(unit) = stack.pop() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return WorkspaceClassProof {
                    relation: ExceptionProof::Open,
                    default_metaclass,
                    premises: Vec::new(),
                };
            }
            if !visited.insert(unit.clone()) {
                continue;
            }
            if visits == MAX_PYTHON_EXCEPTION_HIERARCHY_VISITS {
                return WorkspaceClassProof {
                    relation: ExceptionProof::Open,
                    default_metaclass,
                    premises: Vec::new(),
                };
            }
            visits += 1;

            let Some(provider) = analyzer.python_class_hierarchy_provider_for(&unit) else {
                return WorkspaceClassProof {
                    relation: ExceptionProof::Open,
                    default_metaclass,
                    premises: Vec::new(),
                };
            };
            let hierarchy = provider.class_hierarchy(&unit, cancellation);
            let Some(premise) = hierarchy_premise(analyzer, &unit, &hierarchy) else {
                return WorkspaceClassProof {
                    relation: ExceptionProof::Open,
                    default_metaclass,
                    premises: Vec::new(),
                };
            };
            premises.push(premise);
            match hierarchy.outcome {
                PythonHierarchyOutcome::Complete => {}
                PythonHierarchyOutcome::Incomplete
                    if hierarchy.reason == Some(PythonHierarchyReason::UnresolvedBase) => {}
                _ => {
                    return WorkspaceClassProof {
                        relation: ExceptionProof::Open,
                        default_metaclass,
                        premises: Vec::new(),
                    };
                }
            }

            let Ok(source) = analyzer.project().read_source(unit.source()) else {
                return WorkspaceClassProof {
                    relation: ExceptionProof::Open,
                    default_metaclass,
                    premises: Vec::new(),
                };
            };
            let Some(tree) = parse_python(&source) else {
                return WorkspaceClassProof {
                    relation: ExceptionProof::Open,
                    default_metaclass,
                    premises: Vec::new(),
                };
            };
            if tree.root_node().has_error() {
                return WorkspaceClassProof {
                    relation: ExceptionProof::Open,
                    default_metaclass,
                    premises: Vec::new(),
                };
            }
            let Some(class) = python_class_node_for_unit(analyzer, &unit, &tree) else {
                return WorkspaceClassProof {
                    relation: ExceptionProof::Open,
                    default_metaclass,
                    premises: Vec::new(),
                };
            };
            default_metaclass &= !has_explicit_metaclass(class, &source);
            let base_nodes = python_class_base_nodes(class);
            if base_nodes.is_empty() && hierarchy.outcome == PythonHierarchyOutcome::Complete {
                continue;
            }
            if base_nodes.len() != hierarchy.bases.len()
                || (hierarchy.outcome != PythonHierarchyOutcome::Complete && base_nodes.len() > 1)
            {
                return WorkspaceClassProof {
                    relation: ExceptionProof::Open,
                    default_metaclass,
                    premises: Vec::new(),
                };
            }
            if base_nodes.is_empty() {
                continue;
            }

            for (ordinal, (base_node, base_fact)) in
                base_nodes.iter().zip(&hierarchy.bases).enumerate()
            {
                if base_fact.ordinal != ordinal {
                    return WorkspaceClassProof {
                        relation: ExceptionProof::Open,
                        default_metaclass,
                        premises: Vec::new(),
                    };
                }
                match base_fact.resolution {
                    PythonBaseResolution::Resolved => {
                        let Some(base) = &base_fact.target else {
                            return WorkspaceClassProof {
                                relation: ExceptionProof::Open,
                                default_metaclass,
                                premises: Vec::new(),
                            };
                        };
                        let base = match base {
                            ClassIdentity::Workspace(base) => base,
                            ClassIdentity::External { qualified_name, .. }
                            | ClassIdentity::Intrinsic { qualified_name } => {
                                // The provider proved this canonical identity; never
                                // reinterpret an unresolved source spelling as a builtin.
                                let Some(name) = qualified_name.strip_prefix("builtins.") else {
                                    return WorkspaceClassProof {
                                        relation: ExceptionProof::Open,
                                        default_metaclass,
                                        premises: Vec::new(),
                                    };
                                };
                                match python_builtin_exception_is_subclass(name, expected) {
                                    Some(true) => {
                                        return WorkspaceClassProof {
                                            relation: ExceptionProof::Yes,
                                            default_metaclass,
                                            premises: Vec::new(),
                                        };
                                    }
                                    Some(false) => continue,
                                    None if known_non_exception_builtin_class(name) => continue,
                                    None => {
                                        return WorkspaceClassProof {
                                            relation: ExceptionProof::Open,
                                            default_metaclass,
                                            premises: Vec::new(),
                                        };
                                    }
                                }
                            }
                        };
                        if !base.is_class() || base.is_synthetic() {
                            return WorkspaceClassProof {
                                relation: ExceptionProof::Open,
                                default_metaclass,
                                premises: Vec::new(),
                            };
                        }
                        stack.push(base.clone());
                    }
                    PythonBaseResolution::Unresolved if base_node.kind() == "identifier" => {
                        let spelling = node_text(&source, *base_node).unwrap_or_default();
                        let environment =
                            environment_cache.environment_for(analyzer, unit.source());
                        let definition = resolve_identifier(
                            analyzer,
                            unit.source(),
                            &source,
                            *base_node,
                            cancellation,
                        );
                        match exception_class_from_builtin_identity(
                            &environment,
                            spelling,
                            base_node.start_byte(),
                            definition.as_ref(),
                        ) {
                            Some(ResolvedExceptionClass::Builtin(name)) => {
                                if python_builtin_exception_is_subclass(name, expected)
                                    == Some(true)
                                {
                                    return WorkspaceClassProof {
                                        relation: ExceptionProof::Yes,
                                        default_metaclass,
                                        premises: Vec::new(),
                                    };
                                }
                                if python_builtin_exception_is_subclass(name, expected).is_none() {
                                    return WorkspaceClassProof {
                                        relation: ExceptionProof::Open,
                                        default_metaclass,
                                        premises: Vec::new(),
                                    };
                                }
                            }
                            Some(ResolvedExceptionClass::OtherBuiltin(name))
                                if known_non_exception_builtin_class(&name) => {}
                            _ => {
                                return WorkspaceClassProof {
                                    relation: ExceptionProof::Open,
                                    default_metaclass,
                                    premises: Vec::new(),
                                };
                            }
                        }
                    }
                    _ => {
                        return WorkspaceClassProof {
                            relation: ExceptionProof::Open,
                            default_metaclass,
                            premises: Vec::new(),
                        };
                    }
                }
            }
        }

        WorkspaceClassProof {
            relation: ExceptionProof::No,
            default_metaclass,
            premises: Vec::new(),
        }
    })();
    proof.premises = premises;
    proof
}

fn resolved_class_subclass_of_builtin(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    class: &ResolvedExceptionClass,
    expected: &str,
    cancellation: Option<&CancellationToken>,
) -> WorkspaceClassProof {
    match class {
        ResolvedExceptionClass::Builtin(name) => WorkspaceClassProof {
            relation: match python_builtin_exception_is_subclass(name, expected) {
                Some(true) => ExceptionProof::Yes,
                Some(false) => ExceptionProof::No,
                None => ExceptionProof::Open,
            },
            default_metaclass: true,
            premises: Vec::new(),
        },
        ResolvedExceptionClass::Workspace(unit) => workspace_class_subclass_of_builtin(
            analyzer,
            environment_cache,
            unit,
            expected,
            cancellation,
        ),
        ResolvedExceptionClass::OtherBuiltin(name) if known_non_exception_builtin_class(name) => {
            WorkspaceClassProof {
                relation: ExceptionProof::No,
                default_metaclass: true,
                premises: Vec::new(),
            }
        }
        ResolvedExceptionClass::OtherBuiltin(_)
        | ResolvedExceptionClass::NonClass(_)
        | ResolvedExceptionClass::Open => WorkspaceClassProof {
            relation: ExceptionProof::Open,
            default_metaclass: false,
            premises: Vec::new(),
        },
    }
}

fn exception_class_label(class: &ResolvedExceptionClass) -> Option<String> {
    match class {
        ResolvedExceptionClass::Builtin(name) => Some(format!("builtins.{name}")),
        ResolvedExceptionClass::Workspace(unit) => Some(unit.fq_name()),
        ResolvedExceptionClass::OtherBuiltin(_)
        | ResolvedExceptionClass::NonClass(_)
        | ResolvedExceptionClass::Open => None,
    }
}

fn exception_class_target_id(
    analyzer: &dyn IAnalyzer,
    class: &ResolvedExceptionClass,
) -> Option<String> {
    match class {
        ResolvedExceptionClass::Workspace(unit) => {
            Some(render::canonical_member_digest(analyzer, unit))
        }
        _ => None,
    }
}

fn literal_raise_operand(mut expression: Node<'_>) -> bool {
    while expression.kind() == "parenthesized_expression" {
        let Some(inner) = expression.named_child(0) else {
            return false;
        };
        expression = inner;
    }
    matches!(
        expression.kind(),
        "integer"
            | "float"
            | "string"
            | "concatenated_string"
            | "true"
            | "false"
            | "none"
            | "tuple"
            | "list"
            | "set"
            | "dictionary"
            | "lambda"
            | "list_comprehension"
            | "set_comprehension"
            | "dictionary_comprehension"
            | "generator_expression"
    )
}

#[allow(clippy::too_many_arguments)]
fn make_raise_row(
    relation: &'static str,
    seed: &SeedMatch,
    source: &str,
    anchor: std::ops::Range<usize>,
    owner_id: Option<String>,
    operand: Option<Node<'_>>,
    operand_kind: &'static str,
    outcome: &'static str,
    complete: bool,
    reason: Option<String>,
    exception_class: Option<String>,
    target_id: Option<String>,
    expected_exception: Option<String>,
) -> PythonRuleFactValue {
    let range = row_range(source, anchor.clone());
    let mut value = make_row(
        relation,
        &seed.file,
        anchor,
        range,
        owner_id,
        outcome,
        if complete { "proven" } else { "none" },
        complete,
        reason,
    );
    value.row.raised_expression =
        operand.and_then(|node| node_text(source, node).map(str::to_owned));
    value.row.operand_kind = Some(operand_kind);
    value.row.exception_class = exception_class;
    value.row.target_id = target_id;
    value.row.expected_exception = expected_exception;
    value
}

fn python_raise_legality_fact(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    seed: &SeedMatch,
    source: &str,
    raise: Node<'_>,
    cancellation: Option<&CancellationToken>,
) -> PythonRuleFactValue {
    let operand = raise_operand(raise);
    let mut value = make_raise_row(
        "illegal_raise",
        seed,
        source,
        raise.start_byte()..raise.end_byte(),
        None,
        operand,
        if operand.is_none() {
            "bare_raise"
        } else {
            "dynamic"
        },
        "open",
        false,
        Some(PYTHON_RAISE_REASON.to_string()),
        None,
        None,
        None,
    );
    let Some(mut expression) = operand.and_then(unwrap_parenthesized) else {
        value.row.reason = Some("bare_raise_handler_identity_unresolved".to_string());
        return value;
    };
    if literal_raise_operand(expression) {
        value.row.operand_kind = Some("literal");
        value.row.outcome = "illegal";
        value.row.proof = "proven";
        value.row.completeness = "complete";
        value.row.reason = Some("raise_operand_is_not_an_exception".to_string());
        return value;
    }

    let is_call = expression.kind() == "call";
    let exception_target = if is_call {
        let Some(function) = call_function(expression).and_then(unwrap_parenthesized) else {
            value.row.reason = Some("raise_constructor_target_unresolved".to_string());
            return value;
        };
        function
    } else {
        expression
    };
    if exception_target.kind() == "identifier"
        && node_text(source, exception_target) == Some("NotImplemented")
    {
        let environment = environment_cache.environment_for(analyzer, &seed.file);
        let definition = resolve_identifier(analyzer, &seed.file, source, exception_target, None);
        let resolution = resolve_builtin_identity(
            &environment,
            "NotImplemented",
            exception_target.start_byte(),
            Some(crate::analyzer::structural::Namespace::Value),
            definition.as_ref(),
        )
        .expect("NotImplemented is in Python's builtin inventory");
        if resolution.outcome == "builtin" && resolution.complete {
            value.row.operand_kind = Some("excluded_not_implemented");
            value.row.outcome = "excluded";
            value.row.proof = "proven";
            value.row.completeness = "complete";
            value.row.reason = Some("not_implemented_is_reported_separately".to_string());
            return value;
        }
    }
    if is_call {
        expression = exception_target;
    }
    if expression.kind() != "identifier" {
        value.row.operand_kind = Some("dynamic");
        value.row.reason = Some("raise_operand_shape_unresolved".to_string());
        return value;
    }

    let class = resolved_exception_class(
        analyzer,
        environment_cache,
        &seed.file,
        source,
        expression,
        cancellation,
    );
    value.row.exception_class = exception_class_label(&class);
    value.row.target_id = exception_class_target_id(analyzer, &class);
    value.row.operand_kind = Some(match &class {
        ResolvedExceptionClass::Builtin(_) | ResolvedExceptionClass::Workspace(_) => {
            if is_call {
                "exception_instance"
            } else {
                "class_object"
            }
        }
        ResolvedExceptionClass::OtherBuiltin(name) if known_non_exception_builtin_class(name) => {
            if is_call {
                "exception_instance"
            } else {
                "class_object"
            }
        }
        ResolvedExceptionClass::OtherBuiltin(_)
        | ResolvedExceptionClass::NonClass(_)
        | ResolvedExceptionClass::Open => "dynamic",
    });
    match &class {
        ResolvedExceptionClass::Builtin(name) => {
            let proof = python_builtin_exception_is_subclass(name, "BaseException").map_or(
                ExceptionProof::Open,
                |is_exception| {
                    if is_exception {
                        ExceptionProof::Yes
                    } else {
                        ExceptionProof::No
                    }
                },
            );
            finish_raise_legality(&mut value, proof, "raise_operand_is_not_an_exception");
        }
        ResolvedExceptionClass::Workspace(_) => {
            let proof = resolved_class_subclass_of_builtin(
                analyzer,
                environment_cache,
                &class,
                "BaseException",
                cancellation,
            );
            value.hierarchy_premises.extend(proof.premises);
            if is_call && !proof.default_metaclass {
                value.row.reason = Some("dynamic_exception_metaclass".to_string());
                return value;
            }
            finish_raise_legality(
                &mut value,
                proof.relation,
                "raise_operand_is_not_an_exception",
            );
        }
        ResolvedExceptionClass::OtherBuiltin(name) => {
            if is_call {
                if known_non_exception_builtin_class(name) {
                    finish_raise_legality(
                        &mut value,
                        ExceptionProof::No,
                        "raise_operand_is_not_an_exception",
                    );
                } else {
                    value.row.reason = Some("builtin_call_result_type_unknown".to_string());
                }
            } else {
                finish_raise_legality(
                    &mut value,
                    ExceptionProof::No,
                    "raise_operand_is_not_an_exception",
                );
            }
        }
        ResolvedExceptionClass::NonClass(unit) if !is_call && unit.is_function() => {
            finish_raise_legality(
                &mut value,
                ExceptionProof::No,
                "raise_operand_is_not_an_exception",
            );
        }
        ResolvedExceptionClass::NonClass(_) | ResolvedExceptionClass::Open => {
            value.row.reason = Some("raise_operand_binding_is_dynamic".to_string());
        }
    }
    value
}

fn finish_raise_legality(
    value: &mut PythonRuleFactValue,
    proof: ExceptionProof,
    negative_reason: &'static str,
) {
    match proof {
        ExceptionProof::Yes => {
            value.row.outcome = "legal";
            value.row.proof = "proven";
            value.row.completeness = "complete";
            value.row.reason = None;
        }
        ExceptionProof::No => {
            value.row.outcome = "illegal";
            value.row.proof = "proven";
            value.row.completeness = "complete";
            value.row.reason = Some(negative_reason.to_string());
        }
        ExceptionProof::Open => {
            value.row.reason = Some(PYTHON_RAISE_REASON.to_string());
        }
    }
}

pub(super) fn python_raise_legality_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    seed: &SeedMatch,
    cancellation: Option<&CancellationToken>,
) -> Vec<PipelineExpansion> {
    if seed.language != crate::analyzer::Language::Python {
        return Vec::new();
    }
    let source = seed.facts.source();
    let fact_range = seed.facts.node(seed.fact_match.node).range;
    let span = fact_range.start_byte..fact_range.end_byte;
    let tree = parse_python(source);
    let raise = tree
        .as_ref()
        .and_then(|tree| find_exact_node(tree.root_node(), &span, &["raise_statement"]));
    let Some(raise) = raise else {
        let fallback = make_row(
            "illegal_raise",
            &seed.file,
            span.clone(),
            row_range(source, span),
            None,
            "open",
            "none",
            false,
            Some("raise_statement_parse_or_range_unresolved".to_string()),
        );
        return vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
            fallback,
        )))];
    };
    let mut value = python_raise_legality_fact(
        analyzer,
        environment_cache,
        seed,
        source,
        raise,
        cancellation,
    );
    if tree.is_some_and(|tree| tree.root_node().has_error()) {
        value.row.outcome = "open";
        value.row.proof = "none";
        value.row.completeness = "partial";
        value.row.reason = Some("recovered_python_syntax".to_string());
    }
    vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
        value,
    )))]
}

#[derive(Clone, Copy)]
struct SpecialMethodContract {
    expected: Option<&'static str>,
    permits_type_error: bool,
    hash: bool,
    cast: bool,
}

fn special_method_contract(name: &str) -> Option<SpecialMethodContract> {
    if name == "__hash__" {
        return Some(SpecialMethodContract {
            expected: None,
            permits_type_error: false,
            hash: true,
            cast: false,
        });
    }
    if matches!(
        name,
        "__int__" | "__float__" | "__index__" | "__trunc__" | "__complex__"
    ) {
        return Some(SpecialMethodContract {
            expected: None,
            permits_type_error: false,
            hash: false,
            cast: true,
        });
    }
    let expected = if matches!(name, "__getattribute__" | "__getattr__" | "__delattr__") {
        "AttributeError"
    } else if matches!(name, "__getitem__" | "__delitem__") {
        "LookupError"
    } else if matches!(
        name,
        "__add__"
            | "__sub__"
            | "__and__"
            | "__or__"
            | "__xor__"
            | "__lshift__"
            | "__rshift__"
            | "__pow__"
            | "__mul__"
            | "__div__"
            | "__divmod__"
            | "__truediv__"
            | "__floordiv__"
            | "__matmul__"
            | "__radd__"
            | "__rsub__"
            | "__rand__"
            | "__ror__"
            | "__rxor__"
            | "__rlshift__"
            | "__rrshift__"
            | "__rpow__"
            | "__rmul__"
            | "__rdiv__"
            | "__rdivmod__"
            | "__rtruediv__"
            | "__rfloordiv__"
            | "__rmatmul__"
            | "__iadd__"
            | "__isub__"
            | "__iand__"
            | "__ior__"
            | "__ixor__"
            | "__ilshift__"
            | "__irshift__"
            | "__ipow__"
            | "__imul__"
            | "__idiv__"
            | "__idivmod__"
            | "__itruediv__"
            | "__ifloordiv__"
            | "__imatmul__"
            | "__pos__"
            | "__neg__"
            | "__abs__"
            | "__invert__"
    ) {
        "ArithmeticError"
    } else if matches!(name, "__lt__" | "__le__" | "__gt__" | "__ge__" | "__bool__") {
        "TypeError"
    } else {
        return None;
    };
    Some(SpecialMethodContract {
        expected: Some(expected),
        permits_type_error: matches!(
            name,
            "__getattribute__"
                | "__getattr__"
                | "__delattr__"
                | "__getitem__"
                | "__delitem__"
                | "__add__"
                | "__iadd__"
                | "__radd__"
        ),
        hash: false,
        cast: false,
    })
}

fn enclosing_method_and_class<'tree>(raise: Node<'tree>) -> Option<(Node<'tree>, Node<'tree>)> {
    let mut current = raise.parent()?;
    let function = loop {
        if current.kind() == "function_definition" {
            break current;
        }
        if matches!(current.kind(), "lambda" | "class_definition") {
            return None;
        }
        current = current.parent()?;
    };
    let mut current = function.parent()?;
    loop {
        match current.kind() {
            "class_definition" => return Some((function, current)),
            "function_definition" | "lambda" => return None,
            _ => current = current.parent()?,
        }
    }
}

pub(super) fn is_abstract_method(function: Node<'_>, source: &str) -> bool {
    let Some(decorated) = function
        .parent()
        .filter(|parent| parent.kind() == "decorated_definition")
    else {
        return false;
    };
    named_children(decorated).into_iter().any(|child| {
        if child.kind() != "decorator" {
            return false;
        }
        let mut stack = vec![child];
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier"
                && node_text(source, node).is_some_and(|text| text.contains("abstract"))
            {
                return true;
            }
            stack.extend(named_children(node));
        }
        false
    })
}

fn direct_call_raises<'tree>(function: Node<'tree>) -> Vec<(Node<'tree>, Node<'tree>)> {
    let Some(body) = callable_body(function) else {
        return Vec::new();
    };
    let mut stack = vec![body];
    let mut raises = Vec::new();
    while let Some(node) = stack.pop() {
        if node.id() != body.id()
            && matches!(
                node.kind(),
                "function_definition" | "class_definition" | "lambda"
            )
        {
            continue;
        }
        if node.kind() == "raise_statement" {
            if let Some(operand) = raise_operand(node).and_then(unwrap_parenthesized)
                && operand.kind() == "call"
            {
                raises.push((node, operand));
            }
            continue;
        }
        stack.extend(named_children(node).into_iter().rev());
    }
    raises
}

fn method_contains_try(function: Node<'_>) -> bool {
    let Some(body) = callable_body(function) else {
        return false;
    };
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node.id() != body.id()
            && matches!(
                node.kind(),
                "function_definition" | "class_definition" | "lambda"
            )
        {
            continue;
        }
        if node.kind() == "try_statement" {
            return true;
        }
        stack.extend(named_children(node));
    }
    false
}

fn normal_exit_reachable(procedure: &SemanticProcedureValue) -> Option<bool> {
    if procedure.exact_selection_incomplete_reason().is_some() {
        return None;
    }
    let semantics = procedure.handle.semantics();
    let reachable = reachable_points(procedure);
    if semantics.gaps().iter().any(|gap| {
        reachable.get(gap.point.index()).copied().unwrap_or(false)
            && gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
    }) {
        return None;
    }
    Some(
        reachable
            .get(semantics.normal_exit_point().index())
            .copied()
            .unwrap_or(false),
    )
}

fn raise_class_for_special_method(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    file: &ProjectFile,
    source: &str,
    call: Node<'_>,
    cancellation: Option<&CancellationToken>,
) -> ResolvedExceptionClass {
    let Some(function) = call_function(call).and_then(unwrap_parenthesized) else {
        return ResolvedExceptionClass::Open;
    };
    if function.kind() != "identifier" {
        return ResolvedExceptionClass::Open;
    }
    resolved_exception_class(
        analyzer,
        environment_cache,
        file,
        source,
        function,
        cancellation,
    )
}

fn set_special_raise_result(
    value: &mut PythonRuleFactValue,
    outcome: &'static str,
    reason: Option<&'static str>,
) {
    let complete = outcome != "open";
    value.row.outcome = outcome;
    value.row.proof = if complete { "proven" } else { "none" };
    value.row.completeness = if complete { "complete" } else { "partial" };
    value.row.reason = reason.map(str::to_owned);
}

fn python_function_header_range(function: Node<'_>) -> std::ops::Range<usize> {
    let body = function
        .child_by_field_name("body")
        .expect("Python function definitions have a body node");
    let mut header_end = None;
    let mut cursor = function.walk();
    for child in function.children(&mut cursor) {
        if child.id() == body.id() {
            break;
        }
        if child.kind() == ":" {
            header_end = Some(child.end_byte());
        }
    }
    function.start_byte()..header_end.expect("Python function definitions have a suite delimiter")
}

#[allow(clippy::too_many_arguments)]
fn python_special_method_raise_fact(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    seed: &SeedMatch,
    source: &str,
    raise: Node<'_>,
    function: Node<'_>,
    class: Node<'_>,
    method_name: &str,
    call: Node<'_>,
    direct_raise_count: usize,
    semantic: &mut SemanticQueryContext<'_>,
    cancellation: Option<&CancellationToken>,
) -> PythonRuleFactValue {
    let contract = special_method_contract(method_name)
        .expect("caller selected a supported special method name");
    let expected = contract
        .expected
        .map(|expected| {
            if contract.permits_type_error && expected != "TypeError" {
                format!("{expected} or TypeError")
            } else {
                expected.to_owned()
            }
        })
        .or_else(|| {
            if contract.hash {
                Some("__hash__ = None".to_string())
            } else {
                Some("no implementation required unless overriding inherited behavior".to_string())
            }
        });
    let operand = raise_operand(raise);
    let anchor = function.start_byte()..function.end_byte();
    let anchor_range = row_range(source, anchor.clone());
    let procedure_range = crate::analyzer::Range {
        start_byte: anchor.start,
        end_byte: anchor.end,
        start_line: anchor_range.start_line,
        end_line: anchor_range.end_line,
    };
    let procedures = semantic.procedure_of_source_range(
        &seed.file,
        procedure_range,
        seed.facts.source_identity(),
    );
    let [procedure] = procedures.as_slice() else {
        let mut value = make_raise_row(
            "unexpected_raise_in_special_method",
            seed,
            source,
            python_function_header_range(function),
            None,
            operand,
            "exception_instance",
            "open",
            false,
            Some("special_method_procedure_identity_unresolved".to_string()),
            None,
            None,
            expected,
        );
        value.row.raised_expression =
            operand.and_then(|node| node_text(source, node).map(str::to_owned));
        return value;
    };
    let owner_id = Some(procedure.wire_id());
    let mut value = make_raise_row(
        "unexpected_raise_in_special_method",
        seed,
        source,
        python_function_header_range(function),
        owner_id,
        operand,
        "exception_instance",
        "open",
        false,
        Some(PYTHON_SPECIAL_RAISE_REASON.to_string()),
        None,
        None,
        expected,
    );
    if is_abstract_method(function, source) {
        set_special_raise_result(&mut value, "excluded", Some("abstract_method"));
        return value;
    }
    let has_try = method_contains_try(function);
    if has_try && (contract.hash || contract.cast) {
        value.row.reason = Some("handler_dependent_raise".to_string());
        return value;
    }

    let class_identity = raise_class_for_special_method(
        analyzer,
        environment_cache,
        &seed.file,
        source,
        call,
        cancellation,
    );
    value.row.exception_class = exception_class_label(&class_identity);
    value.row.target_id = exception_class_target_id(analyzer, &class_identity);

    let function_name = function
        .child_by_field_name("name")
        .and_then(|name| node_text(source, name));
    if function_name != Some(method_name) {
        value.row.reason = Some("special_method_identity_unresolved".to_string());
        return value;
    }

    let proof = resolved_class_subclass_of_builtin(
        analyzer,
        environment_cache,
        &class_identity,
        "BaseException",
        cancellation,
    );
    value.hierarchy_premises.extend(proof.premises);
    if proof.relation == ExceptionProof::Open {
        value.row.reason = Some("special_method_exception_class_incomplete".to_string());
        return value;
    }
    if matches!(class_identity, ResolvedExceptionClass::Workspace(_)) && !proof.default_metaclass {
        value.row.reason = Some("dynamic_exception_metaclass".to_string());
        return value;
    }

    let not_implemented_error = matches!(
        class_identity,
        ResolvedExceptionClass::Builtin("NotImplementedError")
    );
    if contract.hash || contract.cast {
        let procedures = semantic.procedure_of_match(seed);
        let [procedure] = procedures.as_slice() else {
            value.row.reason = Some("special_method_cfg_unresolved".to_string());
            return value;
        };
        let Some(has_normal_exit) = normal_exit_reachable(procedure) else {
            value.row.reason = Some("special_method_cfg_incomplete".to_string());
            return value;
        };
        let always_raises = direct_raise_count == 1 && !has_normal_exit;
        if !always_raises {
            set_special_raise_result(&mut value, "allowed", None);
            return value;
        }
        if contract.hash {
            set_special_raise_result(&mut value, "unexpected", Some("always_raises_hash_method"));
            return value;
        }
        if not_implemented_error {
            set_special_raise_result(&mut value, "allowed", None);
            return value;
        }
        if python_class_base_nodes(class).is_empty() {
            set_special_raise_result(&mut value, "unexpected", Some("always_raises_cast_method"));
        } else {
            value.row.reason = Some("inherited_cast_behavior_unresolved".to_string());
        }
        return value;
    }

    if not_implemented_error {
        set_special_raise_result(&mut value, "allowed", None);
        return value;
    }
    let expected = contract
        .expected
        .expect("ordinary method has an expected type");
    let expected_proof = resolved_class_subclass_of_builtin(
        analyzer,
        environment_cache,
        &class_identity,
        expected,
        cancellation,
    );
    let type_error_proof = if contract.permits_type_error && expected != "TypeError" {
        resolved_class_subclass_of_builtin(
            analyzer,
            environment_cache,
            &class_identity,
            "TypeError",
            cancellation,
        )
    } else {
        WorkspaceClassProof {
            relation: ExceptionProof::No,
            default_metaclass: true,
            premises: Vec::new(),
        }
    };
    value.hierarchy_premises.extend(expected_proof.premises);
    value.hierarchy_premises.extend(type_error_proof.premises);
    if (expected_proof.relation == ExceptionProof::Yes && !expected_proof.default_metaclass)
        || (type_error_proof.relation == ExceptionProof::Yes && !type_error_proof.default_metaclass)
    {
        value.row.reason = Some("dynamic_exception_metaclass".to_string());
        return value;
    }
    if expected_proof.relation == ExceptionProof::Yes
        || type_error_proof.relation == ExceptionProof::Yes
    {
        set_special_raise_result(&mut value, "allowed", None);
    } else if expected_proof.relation == ExceptionProof::Open
        || type_error_proof.relation == ExceptionProof::Open
    {
        value.row.reason = Some("special_method_exception_family_incomplete".to_string());
    } else if has_try {
        // A permitted operand needs no escape proof. A mismatched operand may
        // be handled, so it still requires handler-dependent reasoning.
        value.row.reason = Some("handler_dependent_raise".to_string());
    } else {
        set_special_raise_result(&mut value, "unexpected", Some("exception_family_mismatch"));
    }
    value
}

pub(super) fn python_special_method_raise_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    seed: &SeedMatch,
    semantic: &mut SemanticQueryContext<'_>,
    cancellation: Option<&CancellationToken>,
) -> Vec<PipelineExpansion> {
    if seed.language != crate::analyzer::Language::Python {
        return Vec::new();
    }
    let source = seed.facts.source();
    let fact_range = seed.facts.node(seed.fact_match.node).range;
    let span = fact_range.start_byte..fact_range.end_byte;
    let Some(tree) = parse_python(source) else {
        return Vec::new();
    };
    let Some(raise) = find_exact_node(tree.root_node(), &span, &["raise_statement"]) else {
        return Vec::new();
    };
    let Some(call) = raise_operand(raise)
        .and_then(unwrap_parenthesized)
        .filter(|operand| operand.kind() == "call")
    else {
        return Vec::new();
    };
    let Some((function, class)) = enclosing_method_and_class(raise) else {
        return Vec::new();
    };
    let Some(method_name) = function
        .child_by_field_name("name")
        .and_then(|name| node_text(source, name))
    else {
        return Vec::new();
    };
    if special_method_contract(method_name).is_none() {
        return Vec::new();
    }
    let direct_raise_count = direct_call_raises(function).len();
    let mut value = python_special_method_raise_fact(
        analyzer,
        environment_cache,
        seed,
        source,
        raise,
        function,
        class,
        method_name,
        call,
        direct_raise_count,
        semantic,
        cancellation,
    );
    if tree.root_node().has_error() {
        value.row.outcome = "open";
        value.row.proof = "none";
        value.row.completeness = "partial";
        value.row.reason = Some("recovered_python_syntax".to_string());
    }
    vec![pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
        value,
    )))]
}
