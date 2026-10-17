// Closed C/C++ declaration and preprocessor relations used by CodeQL parity.
//
// These relations are deliberately evaluated from the request's source trees.
// They are not source-text parsers: syntax selection comes from tree-sitter
// nodes and the C++ adapter's declarator/include helpers, while strings are
// used only as values of already-selected AST nodes.

use crate::analyzer::common::language_for_file;
use crate::analyzer::usages::get_definition::parse_tree_for_language;
use crate::analyzer::{CppAnalyzer, IAnalyzer, Language, ProjectFile, Range, resolve_analyzer};
use crate::hash::{HashMap, HashSet};
use crate::query::CppRule;
use brokk_bifrost_cpp::graph_support::CppSource;
use brokk_bifrost_cpp::imports::{include_path_from_node, resolve_include_targets_with_index};
use brokk_bifrost_cpp::structural::declarator_name_node;
use tree_sitter::Node;

use super::language_rules::LanguageRuleMatches;

/// Return the exact structural spans selected by one closed C/C++ relation.
///
/// `source` is the same source snapshot used to produce the root structural
/// facts, so the returned AST ranges can be compared directly with fact ranges.
pub(super) fn matches_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    rule: CppRule,
) -> LanguageRuleMatches {
    let Some(tree) = parse_tree_for_language(file, Language::Cpp, source) else {
        return LanguageRuleMatches::default();
    };
    let root = tree.root_node();
    let mut ranges = match rule {
        CppRule::DuplicateIncludeGuard => duplicate_include_guard(analyzer, file, source),
        CppRule::MissingHeaderGuard => missing_header_guard(analyzer, file, source, root),
        CppRule::DeclarationHidesParameter => declaration_hides_parameter(root, source),
        CppRule::DeclarationHidesVariable => declaration_hides_variable(root, source),
        CppRule::FunctionInBlock => function_in_block(root, source),
        CppRule::LocalVariableHidesGlobalVariable => {
            local_variable_hides_global_variable(root, source)
        }
        CppRule::ShortGlobalName => short_global_name(root, source),
        CppRule::CallWithNullSal => call_with_null_sal(analyzer, file, source, root),
        CppRule::IgnoreReturnValueSal => ignore_return_value_sal(analyzer, file, source, root),
        CppRule::InconsistentSal => inconsistent_sal(analyzer, file, source, root),
    };
    ranges.sort();
    ranges.dedup();
    LanguageRuleMatches::from_ranges(ranges)
}

#[derive(Clone, Copy)]
struct DeclarationSite<'tree> {
    owner: Node<'tree>,
    name: Node<'tree>,
    function: bool,
    parameter: bool,
    global: bool,
    static_storage: bool,
    scope: Option<Node<'tree>>,
    function_owner: Option<Node<'tree>>,
}

#[derive(Clone)]
struct CallableContract {
    name: String,
    annotated_parameters: HashSet<usize>,
    check_return: bool,
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row.saturating_add(1),
        end_line: node.end_position().row.saturating_add(1),
    }
}

fn text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(node.byte_range())
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.children(&mut cursor).collect()
}

fn descendants(root: Node<'_>) -> Vec<Node<'_>> {
    let mut pending = vec![root];
    let mut nodes = Vec::new();
    while let Some(node) = pending.pop() {
        nodes.push(node);
        pending.extend(named_children(node));
    }
    nodes
}

fn ancestor_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == kind {
            return Some(parent);
        }
        current = parent.parent();
    }
    None
}

fn nearest_scope(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(parent.kind(), "compound_statement" | "switch_statement") {
            return Some(parent);
        }
        current = parent.parent();
    }
    None
}

fn contains_node(outer: Node<'_>, inner: Node<'_>) -> bool {
    outer.start_byte() <= inner.start_byte() && outer.end_byte() >= inner.end_byte()
}

fn is_function_declarator(node: Node<'_>) -> bool {
    descendants(node).into_iter().any(|child| {
        matches!(
            child.kind(),
            "function_declarator" | "abstract_function_declarator"
        )
    })
}

fn has_structured_token(node: Node<'_>, token_kind: &str, source: &str) -> bool {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if current.kind() == token_kind || text(current, source) == Some(token_kind) {
            return true;
        }
        pending.extend(children(current));
    }
    false
}

fn direct_declarators(node: Node<'_>) -> Vec<Node<'_>> {
    let mut field_declarators = Vec::new();
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            if cursor.node().is_named() && cursor.field_name() == Some("declarator") {
                field_declarators.push(cursor.node());
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    if !field_declarators.is_empty() {
        return field_declarators;
    }
    let type_node = node.child_by_field_name("type");
    named_children(node)
        .into_iter()
        .filter(|child| {
            Some(*child) != type_node
                && (child.kind().contains("declarator")
                    || matches!(
                        child.kind(),
                        "identifier"
                            | "field_identifier"
                            | "qualified_identifier"
                            | "operator_name"
                    ))
        })
        .collect()
}

fn declaration_names(node: Node<'_>) -> Vec<Node<'_>> {
    direct_declarators(node)
        .into_iter()
        .filter_map(declarator_name_node)
        .collect()
}

fn declaration_sites<'tree>(root: Node<'tree>, source: &str) -> Vec<DeclarationSite<'tree>> {
    let mut sites = Vec::new();
    for node in descendants(root) {
        let (parameter, function) = match node.kind() {
            "parameter_declaration"
            | "optional_parameter_declaration"
            | "variadic_parameter_declaration" => (true, false),
            "function_definition" => (false, true),
            "declaration" => (false, is_function_declarator(node)),
            _ => continue,
        };
        let function_owner = ancestor_kind(node, "function_definition");
        let scope = nearest_scope(node);
        let global = !parameter && function_owner.is_none() && scope.is_none();
        let static_storage = !parameter && has_structured_token(node, "static", source);
        for name in declaration_names(node) {
            sites.push(DeclarationSite {
                owner: node,
                name,
                function,
                parameter,
                global,
                static_storage,
                scope,
                function_owner,
            });
        }
    }
    sites
}

fn same_name(left: Node<'_>, right: Node<'_>, source: &str) -> bool {
    text(left, source) == text(right, source)
}

fn declaration_hides_parameter(root: Node<'_>, source: &str) -> Vec<Range> {
    let sites = declaration_sites(root, source);
    sites
        .iter()
        .filter(|local| !local.parameter && !local.function)
        .filter(|local| {
            sites.iter().any(|parameter| {
                parameter.parameter
                    && parameter.function_owner == local.function_owner
                    && local.function_owner.is_some()
                    && same_name(local.name, parameter.name, source)
            })
        })
        .map(|site| node_range(site.name))
        .collect()
}

fn declaration_hides_variable(root: Node<'_>, source: &str) -> Vec<Range> {
    let sites = declaration_sites(root, source);
    sites
        .iter()
        .filter(|inner| !inner.parameter && !inner.function && inner.function_owner.is_some())
        .filter(|inner| {
            sites.iter().any(|outer| {
                !outer.parameter
                    && !outer.function
                    && outer.function_owner == inner.function_owner
                    && outer.scope.is_some()
                    && inner.scope.is_some()
                    && outer.scope != inner.scope
                    && outer.name.start_byte() < inner.name.start_byte()
                    && same_name(inner.name, outer.name, source)
                    && contains_node(
                        outer.scope.expect("checked scope"),
                        inner.scope.expect("checked scope"),
                    )
            })
        })
        .map(|site| node_range(site.name))
        .collect()
}

fn function_in_block(root: Node<'_>, source: &str) -> Vec<Range> {
    declaration_sites(root, source)
        .into_iter()
        .filter(|site| {
            site.function
                && !site.parameter
                && ancestor_kind(site.owner, "compound_statement").is_some()
        })
        .map(|site| node_range(site.name))
        .collect()
}

fn local_variable_hides_global_variable(root: Node<'_>, source: &str) -> Vec<Range> {
    let sites = declaration_sites(root, source);
    let globals: Vec<_> = sites
        .iter()
        .filter(|site| site.global && !site.function)
        .collect();
    sites
        .iter()
        .filter(|local| !local.global && !local.function)
        .filter(|local| {
            globals
                .iter()
                .any(|global| same_name(local.name, global.name, source))
        })
        .map(|site| node_range(site.name))
        .collect()
}

fn short_global_name(root: Node<'_>, source: &str) -> Vec<Range> {
    declaration_sites(root, source)
        .into_iter()
        .filter(|site| site.global && !site.function && !site.static_storage)
        .filter(|site| text(site.name, source).is_some_and(|name| name.chars().count() <= 2))
        .map(|site| node_range(site.name))
        .collect()
}

fn include_guard<'tree>(root: Node<'tree>, source: &str) -> Option<(String, Node<'tree>)> {
    for node in descendants(root) {
        if node.kind() != "preproc_ifdef"
            || !text(node, source).is_some_and(|value| value.starts_with("#ifndef"))
        {
            continue;
        }
        let name = node.child_by_field_name("name").or_else(|| {
            named_children(node)
                .into_iter()
                .find(|child| child.kind() == "identifier")
        })?;
        let macro_name = text(name, source)?.to_owned();
        let defines_same_name = descendants(node).into_iter().any(|child| {
            child.kind() == "preproc_def"
                && child
                    .child_by_field_name("name")
                    .and_then(|candidate| text(candidate, source))
                    == Some(macro_name.as_str())
        });
        if defines_same_name {
            return Some((macro_name, name));
        }
    }
    None
}

fn cpp_files(analyzer: &dyn IAnalyzer) -> Vec<ProjectFile> {
    analyzer
        .analyzed_files()
        .into_iter()
        .filter(|file| language_for_file(file) == Language::Cpp)
        .collect()
}

fn source_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    target: &ProjectFile,
    target_source: &str,
) -> Option<String> {
    if file == target {
        Some(target_source.to_owned())
    } else {
        analyzer.indexed_source(file)
    }
}

fn duplicate_include_guard(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> Vec<Range> {
    let mut counts: HashMap<String, usize> = HashMap::default();
    for candidate in cpp_files(analyzer) {
        let Some(candidate_source) = source_for_file(analyzer, &candidate, file, source) else {
            continue;
        };
        let Some(tree) = parse_tree_for_language(&candidate, Language::Cpp, &candidate_source)
        else {
            continue;
        };
        if let Some((name, _)) = include_guard(tree.root_node(), &candidate_source) {
            *counts.entry(name).or_default() += 1;
        }
    }
    let Some(tree) = parse_tree_for_language(file, Language::Cpp, source) else {
        return Vec::new();
    };
    include_guard(tree.root_node(), source)
        .filter(|(name, _)| counts.get(name).copied().unwrap_or_default() > 1)
        .map(|(_, node)| node_range(node))
        .into_iter()
        .collect()
}

fn is_header(file: &ProjectFile) -> bool {
    file.rel_path()
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "h" | "hh" | "hpp" | "hxx" | "h++" | "hin"))
}

fn missing_header_guard(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
) -> Vec<Range> {
    if !is_header(file) || include_guard(root, source).is_some() {
        return Vec::new();
    }
    let Some(cpp) = resolve_analyzer::<CppAnalyzer>(analyzer) else {
        return Vec::new();
    };
    let mut include_count = 0usize;
    for candidate in cpp_files(analyzer) {
        let Some(candidate_source) = source_for_file(analyzer, &candidate, file, source) else {
            continue;
        };
        let Some(tree) = parse_tree_for_language(&candidate, Language::Cpp, &candidate_source)
        else {
            continue;
        };
        for node in descendants(tree.root_node()) {
            let Some((include, _)) = include_path_from_node(node, &candidate_source) else {
                continue;
            };
            if resolve_include_targets_with_index(&candidate, include, cpp.include_target_index())
                .into_iter()
                .any(|target| target == *file)
            {
                include_count = include_count.saturating_add(1);
            }
        }
    }
    if include_count < 2 {
        return Vec::new();
    }
    descendants(root)
        .into_iter()
        .filter(|node| node.kind() == "class_specifier")
        .map(node_range)
        .collect()
}

fn annotation_nodes<'tree>(node: Node<'tree>, source: &str) -> Vec<Node<'tree>> {
    descendants(node)
        .into_iter()
        .filter(|child| {
            matches!(
                text(*child, source),
                Some("_In_")
                    | Some("_In_opt_")
                    | Some("_Out_")
                    | Some("_Out_opt_")
                    | Some("_Check_return_")
            )
        })
        .collect()
}

fn parameter_list(node: Node<'_>) -> Option<Node<'_>> {
    descendants(node)
        .into_iter()
        .find(|child| child.kind() == "parameter_list")
}

fn callable_contract(node: Node<'_>, source: &str) -> Option<CallableContract> {
    if !matches!(node.kind(), "declaration" | "function_definition")
        || !is_function_declarator(node)
    {
        return None;
    }
    let name = declaration_names(node).into_iter().next()?;
    let mut annotated_parameters = HashSet::default();
    if let Some(parameters) = parameter_list(node) {
        for (index, parameter) in named_children(parameters)
            .into_iter()
            .filter(|child| {
                matches!(
                    child.kind(),
                    "parameter_declaration"
                        | "optional_parameter_declaration"
                        | "variadic_parameter_declaration"
                )
            })
            .enumerate()
        {
            if annotation_nodes(parameter, source)
                .iter()
                .any(|annotation| {
                    matches!(
                        text(*annotation, source),
                        Some("_In_") | Some("_In_opt_") | Some("_Out_") | Some("_Out_opt_")
                    )
                })
            {
                annotated_parameters.insert(index);
            }
        }
    }
    Some(CallableContract {
        name: text(name, source)?.to_owned(),
        annotated_parameters,
        check_return: annotation_nodes(node, source)
            .iter()
            .any(|annotation| text(*annotation, source) == Some("_Check_return_")),
    })
}

fn workspace_contracts(
    analyzer: &dyn IAnalyzer,
    target: &ProjectFile,
    target_source: &str,
) -> Vec<CallableContract> {
    let mut contracts = Vec::new();
    for file in cpp_files(analyzer) {
        let Some(source) = source_for_file(analyzer, &file, target, target_source) else {
            continue;
        };
        let Some(tree) = parse_tree_for_language(&file, Language::Cpp, &source) else {
            continue;
        };
        for node in descendants(tree.root_node()) {
            if let Some(contract) = callable_contract(node, &source) {
                contracts.push(contract);
            }
        }
    }
    contracts
}

fn call_name<'source>(call: Node<'_>, source: &'source str) -> Option<&'source str> {
    let function = call.child_by_field_name("function")?;
    let name = declarator_name_node(function).or(Some(function))?;
    text(name, source)
}

fn call_arguments(call: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    named_children(arguments)
}

fn call_with_null_sal(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
) -> Vec<Range> {
    let mut annotated = HashSet::default();
    for contract in workspace_contracts(analyzer, file, source) {
        if contract.annotated_parameters.contains(&0) {
            annotated.insert(contract.name);
        }
    }
    descendants(root)
        .into_iter()
        .filter(|node| node.kind() == "call_expression")
        .filter(|call| call_name(*call, source).is_some_and(|name| annotated.contains(name)))
        .filter(|call| {
            call_arguments(*call).first().is_some_and(|argument| {
                matches!(argument.kind(), "null" | "nullptr")
                    || text(*argument, source) == Some("nullptr")
            })
        })
        .map(node_range)
        .collect()
}

fn ignore_return_value_sal(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
) -> Vec<Range> {
    let checked: HashSet<String> = workspace_contracts(analyzer, file, source)
        .into_iter()
        .filter(|contract| contract.check_return)
        .map(|contract| contract.name)
        .collect();
    descendants(root)
        .into_iter()
        .filter(|node| node.kind() == "call_expression")
        .filter(|call| call_name(*call, source).is_some_and(|name| checked.contains(name)))
        .filter(|call| {
            call.parent()
                .is_some_and(|parent| parent.kind() == "expression_statement")
        })
        .map(node_range)
        .collect()
}

fn inconsistent_sal(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
) -> Vec<Range> {
    let mut declarations: HashMap<String, HashSet<usize>> = HashMap::default();
    for contract in workspace_contracts(analyzer, file, source) {
        if !contract.annotated_parameters.is_empty() {
            declarations
                .entry(contract.name)
                .or_default()
                .extend(contract.annotated_parameters);
        }
    }
    descendants(root)
        .into_iter()
        .filter(|node| node.kind() == "function_definition")
        .filter_map(|node| callable_contract(node, source).map(|contract| (node, contract)))
        .filter(|(_, contract)| {
            declarations.get(&contract.name).is_some_and(|annotated| {
                annotated
                    .iter()
                    .any(|index| !contract.annotated_parameters.contains(index))
            })
        })
        .map(|(node, _)| node_range(node))
        .collect()
}
