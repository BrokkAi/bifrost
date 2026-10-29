//! Shared mechanics for language-specific exception-handling smell detectors.
//!
//! Syntax extraction stays in each language module. This module owns the
//! project-reading, grammar-resolving dispatch; the language-independent
//! scoring, stable ordering, compact excerpts and stack-safe tree traversal the
//! detectors share moved down to [`brokk_bifrost_core::analyzer::exception_handling`]
//! when Java's detector moved into `brokk-bifrost-jvm` and needed them across
//! the crate line.

use crate::analyzer::common::{is_unparseable_source, language_for_file};
use crate::analyzer::tree_walk::{children_iter, named_children_iter};
use crate::analyzer::{
    ExceptionHandlingAnalysis, ExceptionHandlingSmell, ExceptionSmellWeights, IAnalyzer, Language,
    ProjectFile, parser_language_for_path,
};
use brokk_bifrost_core::analyzer::common::{
    nonempty_node_source_text as node_text, try_node_source_text,
};
use brokk_bifrost_core::analyzer::exception_handling::{
    HandlerScoreInput, build_handler_smell, collect_nodes_by_kind, find_first_named_descendant,
    has_descendant_of_kind, sort_findings,
};
use brokk_bifrost_core::analyzer::structural::adapter_helpers::first_named_child;
use brokk_bifrost_core::analyzer::tree_walk::{
    children_by_field_name, find_ancestor, first_named_child_matching,
    first_named_child_of_kind as named_child_by_kind, has_child_of_kind as has_direct_child_kind,
    last_named_child as last_named_child_for_handler,
};
use tree_sitter::{Node, Parser};

pub(crate) fn analyze_for_file(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
    weights: ExceptionSmellWeights,
) -> ExceptionHandlingAnalysis {
    let language = language_for_file(file);
    if language == Language::None || language == Language::Java {
        return ExceptionHandlingAnalysis::Unsupported {
            reason: format!(
                "exception-handling smell semantics are unavailable for {}",
                file.rel_path().display()
            ),
        };
    }
    if language == Language::Cpp
        && file
            .rel_path()
            .extension()
            .is_some_and(|extension| extension == "c")
    {
        return ExceptionHandlingAnalysis::Unsupported {
            reason: "C return-code and errno handling semantics are not implemented".to_string(),
        };
    }
    let source = match analyzer.project().read_source(file) {
        Ok(source) => source,
        Err(error) => {
            return ExceptionHandlingAnalysis::Failed {
                message: format!("failed to read {}: {error}", file.rel_path().display()),
            };
        }
    };
    if is_unparseable_source(&source) {
        return ExceptionHandlingAnalysis::Failed {
            message: format!("failed to parse {}", file.rel_path().display()),
        };
    }
    let Some(grammar) = parser_language_for_path(language, file.rel_path()) else {
        return ExceptionHandlingAnalysis::Unsupported {
            reason: format!("no parser is registered for {}", file.rel_path().display()),
        };
    };
    let mut parser = Parser::new();
    parser
        .set_language(&grammar)
        .expect("registered parser grammar must load");
    let Some(tree) = parser.parse(&source, None) else {
        return ExceptionHandlingAnalysis::Failed {
            message: format!("failed to parse {}", file.rel_path().display()),
        };
    };
    let tree = crate::analyzer::repaired_grammar_gap_tree(language, &source, tree);
    // Tree-sitter error nodes are recoverable syntax, not a failed parse. Real
    // C++ headers and C# files with preprocessor branches routinely contain
    // them while still exposing usable catch-clause fields elsewhere in the tree.
    let findings = match language {
        Language::Cpp => analyze_cpp(analyzer, file, &source, tree.root_node(), &weights),
        Language::JavaScript | Language::TypeScript => {
            analyze_js_ts(analyzer, file, &source, tree.root_node(), &weights)
        }
        Language::Python => analyze_python(analyzer, file, &source, tree.root_node(), &weights),
        Language::Go => analyze_go(analyzer, file, &source, tree.root_node(), &weights),
        Language::Rust => analyze_rust(analyzer, file, &source, tree.root_node(), &weights),
        Language::Php => analyze_php(analyzer, file, &source, tree.root_node(), &weights),
        Language::Scala => analyze_scala(analyzer, file, &source, tree.root_node(), &weights),
        Language::CSharp => analyze_csharp(analyzer, file, &source, tree.root_node(), &weights),
        Language::Ruby => analyze_ruby(analyzer, file, &source, tree.root_node(), &weights),
        Language::Kotlin => analyze_kotlin(analyzer, file, &source, tree.root_node(), &weights),
        _ => {
            return ExceptionHandlingAnalysis::Unsupported {
                reason: format!(
                    "exception-handling smell semantics are unavailable for {}",
                    file.rel_path().display()
                ),
            };
        }
    };
    ExceptionHandlingAnalysis::Analyzed(findings)
}

fn analyze_cpp(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    weights: &ExceptionSmellWeights,
) -> Vec<ExceptionHandlingSmell> {
    analyze_handler_nodes(
        analyzer,
        file,
        source,
        collect_nodes_by_kind(root, "catch_clause"),
        weights,
        |node, source| {
            let body = node.child_by_field_name("body")?;
            let parameters = node.child_by_field_name("parameters")?;
            let catch_type = cpp_catch_type(parameters, source);
            let broad = if let Some(ty) = cpp_catch_type_node(parameters) {
                if has_descendant_of_kind(ty, "template_argument_list") {
                    None
                } else {
                    brokk_bifrost_cpp::declarations::cpp_structured_type_path(ty, source)
                        .and_then(|path| classify_cpp_type(&path.join("::"), weights))
                }
            } else {
                classify_cpp_type(&catch_type, weights)
            };
            Some((body, catch_type, broad))
        },
        cpp_statement_count,
        &["throw_statement"],
    )
}

fn analyze_js_ts(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    weights: &ExceptionSmellWeights,
) -> Vec<ExceptionHandlingSmell> {
    analyze_handler_nodes(
        analyzer,
        file,
        source,
        collect_nodes_by_kind(root, "catch_clause"),
        weights,
        |node, source| {
            let body = node.child_by_field_name("body")?;
            let type_node = node.child_by_field_name("type").and_then(first_named_child);
            let catch_type = type_node
                .and_then(|kind| node_text(kind, source))
                .unwrap_or_else(|| "<untyped>".to_string());
            let broad = if matches!(catch_type.as_str(), "<untyped>" | "any" | "unknown") {
                Some((
                    weights.generic_exception_weight,
                    format!("generic-catch:{catch_type}"),
                ))
            } else if type_node.is_some_and(|node| {
                contains_identifier(node, source, "Error")
                    || contains_identifier(node, source, "Exception")
            }) {
                Some((
                    weights.generic_runtime_exception_weight,
                    format!("generic-catch:{catch_type}"),
                ))
            } else {
                None
            };
            Some((body, catch_type, broad))
        },
        js_ts_statement_count,
        &["throw_statement"],
    )
}

fn analyze_python(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    weights: &ExceptionSmellWeights,
) -> Vec<ExceptionHandlingSmell> {
    analyze_handler_nodes(
        analyzer,
        file,
        source,
        collect_nodes_by_kind(root, "except_clause"),
        weights,
        |node, source| {
            let body = named_child_by_kind(node, "block")?;
            let values = children_by_field_name(node, "value");
            let catch_type = if values.is_empty() {
                "<bare>".to_string()
            } else {
                values
                    .iter()
                    .filter_map(|value| node_text(*value, source))
                    .collect::<Vec<_>>()
                    .join(" | ")
            };
            let broad = if catch_type == "<bare>"
                || values
                    .iter()
                    .any(|value| contains_identifier(*value, source, "BaseException"))
            {
                Some((
                    weights.generic_throwable_weight,
                    format!("generic-catch:{catch_type}"),
                ))
            } else if values
                .iter()
                .any(|value| contains_identifier(*value, source, "Exception"))
            {
                Some((
                    weights.generic_exception_weight,
                    format!("generic-catch:{catch_type}"),
                ))
            } else {
                None
            };
            Some((body, catch_type, broad))
        },
        python_statement_count,
        &["raise_statement"],
    )
}

fn analyze_go(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    weights: &ExceptionSmellWeights,
) -> Vec<ExceptionHandlingSmell> {
    let mut handlers = Vec::new();
    for defer in collect_nodes_by_kind(root, "defer_statement") {
        let Some(function) = find_first_named_descendant(defer, "func_literal") else {
            continue;
        };
        let Some(function_body) = function.child_by_field_name("body") else {
            continue;
        };
        for if_node in collect_nodes_by_kind(function_body, "if_statement") {
            if find_ancestor(if_node, |parent| parent.kind() == "func_literal") != Some(function) {
                continue;
            }
            if let Some(body) = if_node.child_by_field_name("consequence")
                && contains_call_named_before(if_node, source, "recover", body.start_byte())
            {
                handlers.push((
                    if_node,
                    body,
                    "recover()".to_string(),
                    Some((
                        weights.generic_throwable_weight,
                        "generic-catch:recover()".to_string(),
                    )),
                ));
            }
        }
    }
    for if_node in collect_nodes_by_kind(root, "if_statement") {
        let Some(condition) = if_node.child_by_field_name("condition") else {
            continue;
        };
        if go_condition_is_err_not_nil(condition, source)
            && let Some(body) = if_node.child_by_field_name("consequence")
        {
            if go_body_is_error_propagation(body, source) {
                continue;
            }
            handlers.push((
                if_node,
                body,
                "error".to_string(),
                Some((
                    weights.generic_exception_weight,
                    "generic-catch:error".to_string(),
                )),
            ));
        }
    }
    analyze_preextracted_handlers(analyzer, file, source, handlers, weights, |body| {
        contains_call_named(body, source, "panic")
    })
}

fn analyze_rust(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    weights: &ExceptionSmellWeights,
) -> Vec<ExceptionHandlingSmell> {
    let mut handlers = Vec::new();
    for match_node in collect_nodes_by_kind(root, "match_expression") {
        let catches_unwind = match_node
            .child_by_field_name("value")
            .is_some_and(|value| contains_call_named(value, source, "catch_unwind"));
        for arm in collect_nodes_by_kind(match_node, "match_arm") {
            if find_ancestor(arm, |parent| parent.kind() == "match_expression") != Some(match_node)
            {
                continue;
            }
            let pattern = arm
                .child_by_field_name("pattern")
                .or_else(|| first_named_child(arm));
            if !pattern.is_some_and(|pattern| contains_identifier(pattern, source, "Err")) {
                continue;
            }
            let body = arm
                .child_by_field_name("value")
                .or_else(|| last_named_child_for_handler(arm));
            let Some(body) = body else {
                continue;
            };
            if rust_body_is_result_propagation(body, source) {
                continue;
            }
            let (catch_type, score, reason) = if catches_unwind {
                (
                    "catch_unwind",
                    weights.generic_throwable_weight,
                    "generic-catch:catch_unwind",
                )
            } else {
                ("Err", weights.generic_exception_weight, "generic-catch:Err")
            };
            handlers.push((
                arm,
                body,
                catch_type.to_string(),
                Some((score, reason.to_string())),
            ));
        }
    }
    for if_node in collect_nodes_by_kind(root, "if_expression") {
        let Some(condition) = if_node.child_by_field_name("condition") else {
            continue;
        };
        if contains_identifier(condition, source, "Err")
            && let Some(body) = if_node.child_by_field_name("consequence")
        {
            if rust_body_is_result_propagation(body, source) {
                continue;
            }
            handlers.push((
                if_node,
                body,
                "Err".to_string(),
                Some((
                    weights.generic_exception_weight,
                    "generic-catch:Err".to_string(),
                )),
            ));
        }
    }
    analyze_preextracted_handlers(analyzer, file, source, handlers, weights, |body| {
        contains_call_named(body, source, "panic")
            || contains_call_named(body, source, "resume_unwind")
    })
}

fn analyze_php(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    weights: &ExceptionSmellWeights,
) -> Vec<ExceptionHandlingSmell> {
    analyze_handler_nodes(
        analyzer,
        file,
        source,
        collect_nodes_by_kind(root, "catch_clause"),
        weights,
        |node, source| {
            let body = node.child_by_field_name("body")?;
            let type_node = node.child_by_field_name("type")?;
            let catch_type = node_text(type_node, source)?;
            let broad = classify_exact_java_family(type_node, source, weights);
            Some((body, catch_type, broad))
        },
        handler_statement_count,
        &["throw_expression"],
    )
}

fn analyze_csharp(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    weights: &ExceptionSmellWeights,
) -> Vec<ExceptionHandlingSmell> {
    analyze_handler_nodes(
        analyzer,
        file,
        source,
        collect_nodes_by_kind(root, "catch_clause"),
        weights,
        |node, source| {
            let body = node.child_by_field_name("body")?;
            let declaration = named_child_by_kind(node, "catch_declaration");
            let catch_type = declaration
                .and_then(|value| value.child_by_field_name("type"))
                .and_then(|value| node_text(value, source))
                .unwrap_or_else(|| "Exception".to_string());
            let broad = if let Some(type_node) =
                declaration.and_then(|value| value.child_by_field_name("type"))
            {
                classify_exact_java_family(type_node, source, weights)
            } else {
                Some((
                    weights.generic_exception_weight,
                    "generic-catch:Exception".to_string(),
                ))
            };
            Some((body, catch_type, broad))
        },
        handler_statement_count,
        &["throw_statement"],
    )
}

fn analyze_scala(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    weights: &ExceptionSmellWeights,
) -> Vec<ExceptionHandlingSmell> {
    let mut cases = Vec::new();
    for catch_clause in collect_nodes_by_kind(root, "catch_clause") {
        for case_clause in collect_nodes_by_kind(catch_clause, "case_clause") {
            if find_ancestor(case_clause, |parent| parent.kind() == "catch_clause")
                == Some(catch_clause)
            {
                cases.push(case_clause);
            }
        }
    }
    analyze_handler_nodes(
        analyzer,
        file,
        source,
        cases,
        weights,
        |node, source| {
            let pattern = node.child_by_field_name("pattern")?;
            let (catch_type, broad) = scala_catch_pattern(pattern, source, weights)?;
            Some((node, catch_type, broad))
        },
        handler_statement_count,
        &["throw_expression"],
    )
}

/// Reads the caught types of a Scala catch case without its binding names. A
/// typed pattern reports its type and an extractor pattern its extractor. A
/// variable or wildcard pattern catches every `Throwable` and is reported as
/// `<untyped>`, like an unannotated JavaScript catch. Alternatives join their
/// types the way Python's tuple handlers do and take the broadest
/// alternative's classification.
fn scala_catch_pattern(
    pattern: Node<'_>,
    source: &str,
    weights: &ExceptionSmellWeights,
) -> Option<(String, Option<(i32, String)>)> {
    let mut catch_types = Vec::new();
    let mut broad: Option<(i32, String)> = None;
    let mut pending = vec![pattern];
    while let Some(node) = pending.pop() {
        let (catch_type, alternative_broad) = match node.kind() {
            "alternative_pattern" => {
                let alternatives = scala_pattern_children(node).collect::<Vec<_>>();
                pending.extend(alternatives.into_iter().rev());
                continue;
            }
            // The grammar has no parenthesized pattern: `(pattern)` is a
            // one-element tuple pattern.
            "tuple_pattern" if scala_pattern_children(node).count() == 1 => {
                pending.extend(scala_pattern_children(node));
                continue;
            }
            "capture_pattern" => {
                pending.push(node.child_by_field_name("pattern")?);
                continue;
            }
            "typed_pattern" | "case_class_pattern" => {
                let type_node = node.child_by_field_name("type")?;
                (
                    node_text(type_node, source)?,
                    classify_exact_java_family(type_node, source, weights),
                )
            }
            "wildcard" => scala_catch_all(weights),
            // Scala binds a lowercase identifier but compares against the
            // stable value an uppercase or backquoted identifier names.
            "identifier"
                if node_text(node, source)?
                    .starts_with(|first: char| first.is_lowercase() || first == '_') =>
            {
                scala_catch_all(weights)
            }
            _ => (
                node_text(node, source)?,
                classify_exact_java_family(node, source, weights),
            ),
        };
        catch_types.push(catch_type);
        if let Some((weight, _)) = alternative_broad
            && broad
                .as_ref()
                .is_none_or(|(broadest, _)| weight > *broadest)
        {
            broad = alternative_broad;
        }
    }
    Some((catch_types.join(" | "), broad))
}

fn scala_pattern_children<'tree>(node: Node<'tree>) -> impl Iterator<Item = Node<'tree>> {
    named_children_iter(node).filter(|child| !child.kind().ends_with("comment"))
}

fn scala_catch_all(weights: &ExceptionSmellWeights) -> (String, Option<(i32, String)>) {
    (
        "<untyped>".to_string(),
        Some((
            weights.generic_throwable_weight,
            "generic-catch:<untyped>".to_string(),
        )),
    )
}

fn analyze_ruby(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    weights: &ExceptionSmellWeights,
) -> Vec<ExceptionHandlingSmell> {
    let mut handlers = Vec::new();
    for rescue in collect_nodes_by_kind(root, "rescue") {
        if !rescue.is_named() {
            continue;
        }
        let catch_type = rescue
            .child_by_field_name("exceptions")
            .and_then(|node| node_text(node, source))
            .unwrap_or_else(|| "StandardError".to_string());
        let broad = rescue
            .child_by_field_name("exceptions")
            .map(|node| classify_ruby_type(node, source, weights))
            .unwrap_or_else(|| classify_ruby_name("StandardError", weights));
        handlers.push((rescue, rescue, catch_type, broad));
    }
    for rescue in collect_nodes_by_kind(root, "rescue_modifier") {
        let Some(handler) = rescue.child_by_field_name("handler") else {
            continue;
        };
        handlers.push((
            rescue,
            handler,
            "StandardError".to_string(),
            classify_ruby_name("StandardError", weights),
        ));
    }
    analyze_preextracted_handlers(analyzer, file, source, handlers, weights, |body| {
        has_descendant_of_kind(body, "retry") || contains_identifier(body, source, "raise")
    })
}

fn analyze_kotlin(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    weights: &ExceptionSmellWeights,
) -> Vec<ExceptionHandlingSmell> {
    analyze_handler_nodes(
        analyzer,
        file,
        source,
        collect_nodes_by_kind(root, "catch_block"),
        weights,
        |node, source| {
            let type_node = direct_named_child_matching(node, |kind| {
                matches!(
                    kind,
                    "user_type"
                        | "nullable_type"
                        | "not_nullable_type"
                        | "parenthesized_type"
                        | "function_type"
                )
            })?;
            let catch_type = node_text(type_node, source)?;
            let broad = classify_exact_java_family(type_node, source, weights);
            Some((node, catch_type, broad))
        },
        handler_statement_count,
        &["jump_expression"],
    )
}

#[allow(clippy::too_many_arguments)]
fn analyze_handler_nodes<'tree>(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
    source: &str,
    nodes: Vec<Node<'tree>>,
    weights: &ExceptionSmellWeights,
    mut extract: impl FnMut(Node<'tree>, &str) -> Option<(Node<'tree>, String, Option<(i32, String)>)>,
    statement_count: impl Fn(Node<'tree>) -> u32,
    rethrow_kinds: &[&str],
) -> Vec<ExceptionHandlingSmell> {
    let mut findings = Vec::new();
    for handler in nodes {
        let Some((body, catch_type, broad_handler)) = extract(handler, source) else {
            continue;
        };
        let body_statement_count = statement_count(body);
        let has_comment = contains_comment(body);
        let rethrow_present = rethrow_kinds
            .iter()
            .any(|kind| has_descendant_of_kind(body, kind));
        let log_only =
            body_statement_count == 1 && !rethrow_present && contains_logging_call(body, source);
        let Some(finding) = build_handler_smell(
            analyzer,
            file,
            source,
            handler,
            catch_type,
            weights,
            HandlerScoreInput {
                broad_handler,
                body_statement_count,
                has_comment,
                log_only,
            },
        ) else {
            continue;
        };
        findings.push(finding);
    }
    sort_findings(&mut findings);
    findings
}

type PreextractedHandler<'tree> = (Node<'tree>, Node<'tree>, String, Option<(i32, String)>);

fn analyze_preextracted_handlers<'tree>(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
    source: &str,
    handlers: Vec<PreextractedHandler<'tree>>,
    weights: &ExceptionSmellWeights,
    mut is_rethrow: impl FnMut(Node<'tree>) -> bool,
) -> Vec<ExceptionHandlingSmell> {
    let mut findings = Vec::new();
    for (handler, body, catch_type, broad_handler) in handlers {
        let body_statement_count = handler_statement_count(body);
        let has_comment = contains_comment(body);
        let log_only =
            body_statement_count == 1 && !is_rethrow(body) && contains_logging_call(body, source);
        let Some(finding) = build_handler_smell(
            analyzer,
            file,
            source,
            handler,
            catch_type,
            weights,
            HandlerScoreInput {
                broad_handler,
                body_statement_count,
                has_comment,
                log_only,
            },
        ) else {
            continue;
        };
        findings.push(finding);
    }
    sort_findings(&mut findings);
    findings
}

#[derive(Clone, Copy)]
enum ExceptionFamilyWeight {
    Throwable,
    RuntimeException,
    Exception,
}

const JAVA_EXCEPTION_FAMILIES: &[(&str, ExceptionFamilyWeight)] = &[
    ("Throwable", ExceptionFamilyWeight::Throwable),
    ("RuntimeException", ExceptionFamilyWeight::RuntimeException),
    ("Exception", ExceptionFamilyWeight::Exception),
];

const RUBY_EXCEPTION_FAMILIES: &[(&str, ExceptionFamilyWeight)] = &[
    ("Exception", ExceptionFamilyWeight::Throwable),
    ("RuntimeError", ExceptionFamilyWeight::RuntimeException),
    ("StandardError", ExceptionFamilyWeight::Exception),
];

fn classify_exception_family(
    weights: &ExceptionSmellWeights,
    families: &[(&str, ExceptionFamilyWeight)],
    mut matches: impl FnMut(&str) -> bool,
) -> Option<(i32, String)> {
    let (label, family) = families.iter().copied().find(|(name, _)| matches(name))?;
    let weight = match family {
        ExceptionFamilyWeight::Throwable => weights.generic_throwable_weight,
        ExceptionFamilyWeight::RuntimeException => weights.generic_runtime_exception_weight,
        ExceptionFamilyWeight::Exception => weights.generic_exception_weight,
    };
    Some((weight, format!("generic-catch:{label}")))
}

fn classify_exact_java_family(
    type_node: Node<'_>,
    source: &str,
    weights: &ExceptionSmellWeights,
) -> Option<(i32, String)> {
    classify_exception_family(weights, JAVA_EXCEPTION_FAMILIES, |name| {
        contains_identifier(type_node, source, name)
    })
}

/// Classifies a canonical type path rendered from grammar fields.
fn classify_cpp_type(catch_type: &str, weights: &ExceptionSmellWeights) -> Option<(i32, String)> {
    match catch_type {
        "..." => Some((
            weights.generic_throwable_weight,
            "generic-catch:catch-all".to_string(),
        )),
        "runtime_error" | "std::runtime_error" | "::std::runtime_error" => Some((
            weights.generic_runtime_exception_weight,
            "generic-catch:runtime_error".to_string(),
        )),
        "exception" | "std::exception" | "::std::exception" => Some((
            weights.generic_exception_weight,
            "generic-catch:exception".to_string(),
        )),
        _ => None,
    }
}

fn classify_ruby_type(
    type_node: Node<'_>,
    source: &str,
    weights: &ExceptionSmellWeights,
) -> Option<(i32, String)> {
    classify_exception_family(weights, RUBY_EXCEPTION_FAMILIES, |name| {
        contains_identifier(type_node, source, name)
    })
}

fn classify_ruby_name(catch_type: &str, weights: &ExceptionSmellWeights) -> Option<(i32, String)> {
    classify_exception_family(weights, RUBY_EXCEPTION_FAMILIES, |name| catch_type == name)
}

fn cpp_catch_type_node(parameters: Node<'_>) -> Option<Node<'_>> {
    named_child_by_kind(parameters, "parameter_declaration")
        .and_then(|parameter| parameter.child_by_field_name("type"))
}

fn cpp_catch_type(parameters: Node<'_>, source: &str) -> String {
    cpp_catch_type_node(parameters)
        .and_then(|ty| node_text(ty, source))
        .unwrap_or_else(|| "...".to_string())
}

fn handler_statement_count(mut body: Node<'_>) -> u32 {
    loop {
        let inner = match body.kind() {
            "catch_block" => named_child_by_kind(body, "statements"),
            "rescue" => body.child_by_field_name("body"),
            _ => break,
        };
        let Some(inner) = inner else {
            return 0;
        };
        body = inner;
    }
    if body.kind() == "case_clause" {
        return children_by_field_name(body, "body").len() as u32;
    }
    if !matches!(
        body.kind(),
        "block"
            | "compound_statement"
            | "statement_block"
            | "indented_block"
            | "statements"
            | "then"
    ) {
        return 1;
    }
    let mut cursor = body.walk();
    body.named_children(&mut cursor)
        .filter(|child| !child.kind().ends_with("comment") && child.kind() != "comment")
        .count() as u32
}

fn cpp_statement_count(body: Node<'_>) -> u32 {
    let mut statements = 0_u32;
    let mut pending = vec![body];
    while let Some(node) = pending.pop() {
        // Defining a callable does not execute the statements in its body.
        if matches!(node.kind(), "lambda_expression" | "function_definition") {
            continue;
        }
        let kind = node.kind();
        let is_wrapper = matches!(
            kind,
            "compound_statement"
                | "if_statement"
                | "for_statement"
                | "while_statement"
                | "do_statement"
                | "switch_statement"
                | "try_statement"
                | "labeled_statement"
        );
        if kind == "declaration" || (kind.ends_with("_statement") && !is_wrapper) {
            statements = statements.saturating_add(1);
        }
        pending.extend(named_children_iter(node));
    }
    statements
}

fn js_ts_statement_count(body: Node<'_>) -> u32 {
    direct_statement_count(
        body,
        &[
            "lexical_declaration",
            "variable_declaration",
            "using_declaration",
            "function_declaration",
            "generator_function_declaration",
            "class_declaration",
            "statement_block",
            "debugger_statement",
            "with_statement",
            "labeled_statement",
            "expression_statement",
            "throw_statement",
            "return_statement",
            "break_statement",
            "continue_statement",
            "if_statement",
            "for_statement",
            "for_in_statement",
            "while_statement",
            "do_statement",
            "switch_statement",
            "try_statement",
            "ternary_expression",
        ],
    )
}

fn python_statement_count(body: Node<'_>) -> u32 {
    direct_statement_count(
        body,
        &[
            // pass is deliberately empty; definitions execute their binding,
            // but their deferred bodies are not counted as handler statements.
            "future_import_statement",
            "import_statement",
            "import_from_statement",
            "print_statement",
            "assert_statement",
            "delete_statement",
            "global_statement",
            "nonlocal_statement",
            "exec_statement",
            "type_alias_statement",
            "with_statement",
            "function_definition",
            "class_definition",
            "decorated_definition",
            "expression_statement",
            "raise_statement",
            "return_statement",
            "break_statement",
            "continue_statement",
            "if_statement",
            "for_statement",
            "while_statement",
            "try_statement",
            "match_statement",
        ],
    )
}

fn direct_statement_count(body: Node<'_>, kinds: &[&str]) -> u32 {
    let mut cursor = body.walk();
    body.named_children(&mut cursor)
        .filter(|child| kinds.contains(&child.kind()))
        .count() as u32
}

fn contains_comment(root: Node<'_>) -> bool {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.kind().ends_with("comment") || node.kind() == "comment" {
            return true;
        }
        pending.extend(children_iter(node));
    }
    false
}

fn contains_logging_call(root: Node<'_>, source: &str) -> bool {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node != root
            && matches!(
                node.kind(),
                "function_definition"
                    | "function_declaration"
                    | "func_literal"
                    | "lambda"
                    | "lambda_expression"
                    | "lambda_literal"
                    | "arrow_function"
                    | "closure_expression"
            )
        {
            continue;
        }
        if matches!(
            node.kind(),
            "call_expression"
                | "call"
                | "invocation_expression"
                | "method_invocation"
                | "function_call_expression"
                | "member_call_expression"
                | "scoped_call_expression"
                | "method_call"
        ) && call_target_is_logging(node, source)
        {
            return true;
        }
        pending.extend(children_iter(node));
    }
    false
}

fn call_target_is_logging(call: Node<'_>, source: &str) -> bool {
    let target = ["function", "expression", "method", "name"]
        .into_iter()
        .find_map(|field| call.child_by_field_name(field))
        .or_else(|| {
            let mut cursor = call.walk();
            call.named_children(&mut cursor).find(|child| {
                !matches!(
                    child.kind(),
                    "arguments" | "argument_list" | "type_arguments" | "block"
                )
            })
        });
    let Some(target) = target else {
        return false;
    };
    let mut identifiers = Vec::new();
    let mut pending = vec![target];
    while let Some(node) = pending.pop() {
        if matches!(
            node.kind(),
            "identifier" | "field_identifier" | "name" | "simple_identifier"
        ) && let Some(name) = node_text_ref(node, source)
        {
            identifiers.push((node.start_byte(), name));
        }
        pending.extend(children_iter(node));
    }
    identifiers.sort_unstable_by_key(|(start, _)| *start);
    identifiers
        .first()
        .is_some_and(|(_, name)| is_logging_receiver(name))
        || identifiers
            .last()
            .is_some_and(|(_, name)| is_logging_method(name))
}

fn is_logging_receiver(name: &str) -> bool {
    ["log", "logger", "logging"]
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

fn is_logging_method(name: &str) -> bool {
    [
        "error",
        "warn",
        "warning",
        "severe",
        "info",
        "debug",
        "trace",
        "error_log",
    ]
    .iter()
    .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

fn contains_call_named(root: Node<'_>, source: &str, target: &str) -> bool {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.kind() == "call_expression"
            && let Some(function) = node.child_by_field_name("function")
            && contains_identifier(function, source, target)
        {
            return true;
        }
        pending.extend(children_iter(node));
    }
    false
}

fn contains_call_named_before(
    root: Node<'_>,
    source: &str,
    target: &str,
    before_byte: usize,
) -> bool {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.start_byte() >= before_byte {
            continue;
        }
        if node.kind() == "call_expression"
            && let Some(function) = node.child_by_field_name("function")
            && contains_identifier(function, source, target)
        {
            return true;
        }
        pending.extend(children_iter(node));
    }
    false
}

fn contains_identifier(root: Node<'_>, source: &str, target: &str) -> bool {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if matches!(
            node.kind(),
            "identifier" | "field_identifier" | "name" | "simple_identifier" | "type_identifier"
        ) && node_text_ref(node, source) == Some(target)
        {
            return true;
        }
        pending.extend(children_iter(node));
    }
    false
}

fn go_condition_is_err_not_nil(condition: Node<'_>, source: &str) -> bool {
    for binary in collect_nodes_by_kind(condition, "binary_expression") {
        let Some(left) = binary.child_by_field_name("left") else {
            continue;
        };
        let Some(right) = binary.child_by_field_name("right") else {
            continue;
        };
        if node_text_ref(left, source) == Some("err")
            && right.kind() == "nil"
            && has_direct_child_kind(binary, "!=")
        {
            return true;
        }
    }
    false
}

fn go_body_is_error_propagation(body: Node<'_>, source: &str) -> bool {
    single_statement_through_wrappers(body).is_some_and(|statement| {
        statement.kind() == "return_statement" && contains_identifier(statement, source, "err")
    })
}

fn rust_body_is_result_propagation(body: Node<'_>, source: &str) -> bool {
    let statement = if body.kind() == "return_expression" {
        Some(body)
    } else {
        single_statement_through_wrappers(body)
    };
    statement.is_some_and(|statement| {
        statement.kind() == "return_expression" && contains_identifier(statement, source, "Err")
    })
}

fn single_statement_through_wrappers(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        let child = single_non_comment_named_child(node)?;
        if matches!(
            child.kind(),
            "block" | "statement_list" | "block_expression" | "statements" | "expression_statement"
        ) {
            node = child;
        } else {
            return Some(child);
        }
    }
}

fn single_non_comment_named_child(node: Node<'_>) -> Option<Node<'_>> {
    crate::analyzer::tree_walk::single_named_child_matching(node, |child| {
        !child.kind().ends_with("comment") && child.kind() != "comment"
    })
}

fn node_text_ref<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    try_node_source_text(node, source)
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

fn direct_named_child_matching(
    node: Node<'_>,
    mut predicate: impl FnMut(&str) -> bool,
) -> Option<Node<'_>> {
    first_named_child_matching(node, |child| predicate(child.kind()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    fn parse(path: &str, language: Language, source: &str) -> tree_sitter::Tree {
        let grammar = parser_language_for_path(language, std::path::Path::new(path)).unwrap();
        let mut parser = Parser::new();
        parser.set_language(&grammar).unwrap();
        parser.parse(source, None).unwrap()
    }

    #[test]
    #[hardwon(
        "97a35feae74c: quicksilver round 12 on brokk-bifrost-analysis: declarations and Python statements were counted as empty handlers"
    )]
    fn handler_statement_grammar_categories() {
        let mut failures = Vec::new();
        for (path, language, source, body_kind, expected) in [
            (
                "sample.js",
                Language::JavaScript,
                "try {} catch(e) { const value = logger.error(e); let other = work(); var third = work(); }",
                "statement_block",
                vec![
                    "lexical_declaration",
                    "lexical_declaration",
                    "variable_declaration",
                ],
            ),
            (
                "sample.ts",
                Language::TypeScript,
                "try {} catch(e) { const value = logger.error(e); let other = work(); var third = work(); }",
                "statement_block",
                vec![
                    "lexical_declaration",
                    "lexical_declaration",
                    "variable_declaration",
                ],
            ),
            (
                "sample.py",
                Language::Python,
                "try:\n work()\nexcept DomainError:\n assert ready\n del old\n global state\n nonlocal outer\n with lock:\n  work()\n",
                "block",
                vec![
                    "assert_statement",
                    "delete_statement",
                    "global_statement",
                    "nonlocal_statement",
                    "with_statement",
                ],
            ),
        ] {
            let tree = parse(path, language, source);
            assert!(
                !tree.root_node().has_error(),
                "{}",
                tree.root_node().to_sexp()
            );
            let handler = collect_nodes_by_kind(
                tree.root_node(),
                if language == Language::Python {
                    "except_clause"
                } else {
                    "catch_clause"
                },
            )[0];
            let body = named_child_by_kind(handler, body_kind).unwrap();
            let kinds: Vec<_> = named_children_iter(body).map(|node| node.kind()).collect();
            assert_eq!(kinds, expected);
            let count = if language == Language::Python {
                python_statement_count(body)
            } else {
                js_ts_statement_count(body)
            };
            if count as usize != expected.len() {
                failures.push(format!("{path}: expected {}, got {count}", expected.len()));
            }
        }
        assert!(failures.is_empty(), "{failures:?}");
    }

    #[test]
    #[hardwon(
        "97a35feae74c: quicksilver round 12 on brokk-bifrost-analysis: C++ catch type came from nested template arguments"
    )]
    fn cpp_parameter_type_field_owns_the_caught_type() {
        for caught in [
            "Box<std::exception>",
            "std::vector<int>",
            "std::exception",
            "std::runtime_error",
        ] {
            let source = format!("void run() {{ try {{}} catch ({caught}& error) {{}} }}");
            let tree = parse("sample.cpp", Language::Cpp, &source);
            assert!(!tree.root_node().has_error());
            let handler = collect_nodes_by_kind(tree.root_node(), "catch_clause")[0];
            let parameters = handler.child_by_field_name("parameters").unwrap();
            let declaration = named_child_by_kind(parameters, "parameter_declaration").unwrap();
            let ty = declaration.child_by_field_name("type").unwrap();
            assert_eq!(node_text_ref(ty, &source), Some(caught));
            assert_eq!(cpp_catch_type(parameters, &source), caught);
        }
    }

    #[test]
    #[hardwon(
        "97a35feae74c: quicksilver round 12 on brokk-bifrost-analysis: narrow C++ names received broad exception weights"
    )]
    fn cpp_broad_families_require_exact_type_names() {
        let weights = ExceptionSmellWeights::defaults();
        for (name, expected) in [
            ("std::runtime_error", Some(2)),
            ("std::exception", Some(3)),
            ("...", Some(5)),
            ("DomainException", None),
            ("my_runtime_error_wrapper", None),
            ("Box<std::exception>", None),
        ] {
            assert_eq!(
                classify_cpp_type(name, &weights).map(|value| value.0),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    #[hardwon(
        "97a35feae74c: quicksilver round 12 on brokk-bifrost-analysis: C++ statement credit entered deferred lambda bodies"
    )]
    fn cpp_statement_credit_stops_at_deferred_bodies() {
        for (body, expected) in [
            ("auto f = [] { audit(); notify_ops(); };", 1),
            (
                "if (recoverable()) { audit(); notify_ops(); recover(); }",
                3,
            ),
        ] {
            let source = format!("void run() {{ try {{}} catch (...) {{ {body} }} }}");
            let tree = parse("sample.cpp", Language::Cpp, &source);
            assert!(!tree.root_node().has_error());
            let handler = collect_nodes_by_kind(tree.root_node(), "catch_clause")[0];
            assert_eq!(
                cpp_statement_count(handler.child_by_field_name("body").unwrap()),
                expected,
                "{body}"
            );
        }
    }

    #[test]
    #[hardwon(
        "97a35feae74c: quicksilver round 12 on brokk-bifrost-analysis: Rust semicolon return wrappers hid explicit Err propagation"
    )]
    fn explicit_propagation_grammar_wrappers() {
        let source = "// UTF-8: \u{e9}\nfn run() { match work() { Err(e) => return Err(e), Err(e) => { /* note */ return Err(e); }, Err(e) => { /* note */ }, Err(e) => { log(e); return Err(e); }, _ => {} } }";
        let tree = parse("sample.rs", Language::Rust, source);
        assert!(!tree.root_node().has_error());
        let arms = collect_nodes_by_kind(tree.root_node(), "match_arm");
        assert_eq!(arms.len(), 5);
        let expected = [
            ("return_expression", true),
            ("block", true),
            ("block", false),
            ("block", false),
            ("block", false),
        ];
        let markers = [
            "return Err(e)",
            "{ /* note */ return Err(e); }",
            "{ /* note */ }",
            "{ log(e); return Err(e); }",
            "{}",
        ];
        for ((arm, (kind, propagates)), marker) in arms.into_iter().zip(expected).zip(markers) {
            let body = arm.child_by_field_name("value").unwrap();
            assert_eq!(body.kind(), kind);
            let start = source.find(marker).unwrap();
            assert_eq!(body.byte_range(), start..start + marker.len());
            if propagates && kind == "block" {
                let statement = single_non_comment_named_child(body).unwrap();
                assert_eq!(statement.kind(), "expression_statement");
                assert_eq!(
                    first_named_child(statement).unwrap().kind(),
                    "return_expression"
                );
            }
            assert_eq!(
                rust_body_is_result_propagation(body, source),
                propagates,
                "{}",
                body.to_sexp()
            );
        }
        let source =
            "package p\n// UTF-8: \u{e9}\nfunc run() { if err != nil { /* note */ return err } }";
        let tree = parse("sample.go", Language::Go, source);
        assert!(!tree.root_node().has_error());
        let conditional = collect_nodes_by_kind(tree.root_node(), "if_statement")[0];
        let body = conditional.child_by_field_name("consequence").unwrap();
        assert_eq!(body.kind(), "block");
        let marker = "{ /* note */ return err }";
        let start = source.find(marker).unwrap();
        assert_eq!(body.byte_range(), start..start + marker.len());
        let statements = named_child_by_kind(body, "statement_list").unwrap();
        assert_eq!(
            single_non_comment_named_child(statements).unwrap().kind(),
            "return_statement"
        );
        assert!(go_body_is_error_propagation(body, source));
    }
    fn reports(
        path: &str,
        language: Language,
        source: &str,
        weights: ExceptionSmellWeights,
    ) -> String {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(path), source).unwrap();
        let analyzer = crate::analyzer::workspace::EmptyAnalyzer::new(std::sync::Arc::new(
            crate::TestProject::new(directory.path(), language),
        ));
        let file = ProjectFile::new(directory.path(), std::path::Path::new(path));
        let ExceptionHandlingAnalysis::Analyzed(findings) =
            analyzer.find_exception_handling_smells(&file, weights)
        else {
            panic!("expected analyzed handlers for {path}");
        };
        findings
            .iter()
            .map(|finding| {
                format!(
                    "{}; {}; {}; {}\n",
                    finding.catch_type,
                    finding.body_statement_count,
                    finding.score,
                    finding.reasons.join(", ")
                )
            })
            .collect()
    }

    #[test]
    fn handler_reports_cover_executed_body_shapes() {
        // Known answers use the public default scoring contract: broad families
        // 5/3/2, empty/comment 5/4, small/log-only 2, one credit per statement.
        for (path, language, source, expected) in [
            (
                "sample.cpp",
                Language::Cpp,
                "void run() { try {} catch (std /* type */ :: exception& e) {} }",
                "std /* type */ :: exception; 0; 10; generic-catch:exception, empty-body, small-body:0\n",
            ),
            (
                "sample.cpp",
                Language::Cpp,
                "void run() { try {} catch (Box<std::exception>& e) {} }",
                "Box<std::exception>; 0; 7; empty-body, small-body:0\n",
            ),
            (
                "sample.cpp",
                Language::Cpp,
                "void run() { try {} catch (DomainException& e) {} }",
                "DomainException; 0; 7; empty-body, small-body:0\n",
            ),
            (
                "sample.cpp",
                Language::Cpp,
                "void run() { try {} catch (...) { auto f = [] { audit(); notify_ops(); }; } }",
                "...; 1; 6; generic-catch:catch-all, small-body:1, meaningful-body-credit:1\n",
            ),
            (
                "sample.js",
                Language::JavaScript,
                "try {} catch(e) { const value = logger.error(e); }",
                "<untyped>; 1; 6; generic-catch:<untyped>, small-body:1, log-only-body, meaningful-body-credit:1\n",
            ),
            (
                "sample.py",
                Language::Python,
                "try:\n work()\nexcept DomainError:\n assert ready\n",
                "DomainError; 1; 1; small-body:1, meaningful-body-credit:1\n",
            ),
            (
                "sample.rs",
                Language::Rust,
                "fn run() { match work() { Err(e) => { /* note */ return Err(e); }, _ => {} } }",
                "",
            ),
            (
                "sample.rs",
                Language::Rust,
                "fn run() { match work() { Err(e) => { log(e); return Err(e); }, _ => {} } }",
                "Err; 2; 3; generic-catch:Err, small-body:2, meaningful-body-credit:2\n",
            ),
            (
                "sample.cpp",
                Language::Cpp,
                "void run() { try {} catch (...) { throw logger.error(e); } }",
                "...; 1; 6; generic-catch:catch-all, small-body:1, meaningful-body-credit:1\n",
            ),
            (
                "sample.cpp",
                Language::Cpp,
                "void run() { try {} catch (...) { logger.error(e); } }",
                "...; 1; 8; generic-catch:catch-all, small-body:1, log-only-body, meaningful-body-credit:1\n",
            ),
            (
                "sample.py",
                Language::Python,
                "try:\n work()\nexcept DomainError:\n if flag:\n  def report():\n   logger.error(e)\n",
                "DomainError; 1; 1; small-body:1, meaningful-body-credit:1\n",
            ),
            (
                "sample.py",
                Language::Python,
                "try:\n work()\nexcept DomainError:\n callback = lambda: logger.error(e)\n",
                "DomainError; 1; 1; small-body:1, meaningful-body-credit:1\n",
            ),
            (
                "sample.py",
                Language::Python,
                "try:\n work()\nexcept DomainError:\n logger.emit(e)\n",
                "DomainError; 1; 3; small-body:1, log-only-body, meaningful-body-credit:1\n",
            ),
            (
                "sample.py",
                Language::Python,
                "try:\n work()\nexcept DomainError:\n log.emit(e)\n",
                "DomainError; 1; 3; small-body:1, log-only-body, meaningful-body-credit:1\n",
            ),
            (
                "sample.py",
                Language::Python,
                "try:\n work()\nexcept DomainError:\n logging.emit(e)\n",
                "DomainError; 1; 3; small-body:1, log-only-body, meaningful-body-credit:1\n",
            ),
            (
                "sample.py",
                Language::Python,
                "try:\n work()\nexcept DomainError:\n sink.error(e)\n",
                "DomainError; 1; 3; small-body:1, log-only-body, meaningful-body-credit:1\n",
            ),
            (
                "sample.py",
                Language::Python,
                "try:\n work()\nexcept DomainError:\n sink.warn(e)\n",
                "DomainError; 1; 3; small-body:1, log-only-body, meaningful-body-credit:1\n",
            ),
            (
                "sample.py",
                Language::Python,
                "try:\n work()\nexcept DomainError:\n process(logger)\n",
                "DomainError; 1; 1; small-body:1, meaningful-body-credit:1\n",
            ),
            (
                "sample.py",
                Language::Python,
                "try:\n work()\nexcept DomainError:\n raise e\n",
                "DomainError; 1; 1; small-body:1, meaningful-body-credit:1\n",
            ),
            (
                "sample.py",
                Language::Python,
                "try:\n work()\nexcept DomainError:\n return e\n",
                "DomainError; 1; 1; small-body:1, meaningful-body-credit:1\n",
            ),
            (
                "sample.py",
                Language::Python,
                "try:\n work()\nexcept DomainError:\n pass\n",
                "DomainError; 0; 7; empty-body, small-body:0\n",
            ),
            (
                "sample.py",
                Language::Python,
                "try:\n work()\nexcept DomainError:\n pass\n # handled by caller\n pass\n",
                "DomainError; 0; 6; comment-only-body, small-body:0\n",
            ),
            (
                "Sample.cs",
                Language::CSharp,
                "class Sample { void Run() { try {} catch {} } }",
                "Exception; 0; 10; generic-catch:Exception, empty-body, small-body:0\n",
            ),
            (
                "Sample.kt",
                Language::Kotlin,
                "fun run() { try {} catch (e: Exception) { // explanation\n } }",
                "Exception; 0; 9; generic-catch:Exception, comment-only-body, small-body:0\n",
            ),
            (
                "Sample.kt",
                Language::Kotlin,
                "fun run() { try {} catch (e: Exception) { /* explanation */ } }",
                "Exception; 0; 9; generic-catch:Exception, comment-only-body, small-body:0\n",
            ),
            (
                "Sample.kt",
                Language::Kotlin,
                "fun run() { try {} catch (e: Exception) {} }",
                "Exception; 0; 10; generic-catch:Exception, empty-body, small-body:0\n",
            ),
            (
                "sample.rs",
                Language::Rust,
                "fn run() { match work() { Err(e) => recover(e), _ => {} } }",
                "Err; 1; 4; generic-catch:Err, small-body:1, meaningful-body-credit:1\n",
            ),
        ] {
            assert_eq!(
                reports(path, language, source, ExceptionSmellWeights::defaults()),
                expected,
                "{path}: {source}"
            );
        }
    }

    #[test]
    fn python_repeated_exception_fields_preserve_broad_alternatives() {
        for (alternatives, count, weight) in [
            ("BaseException, ValueError", 2, 5),
            ("ValueError, BaseException", 2, 5),
            ("Exception, ValueError", 2, 3),
            ("ValueError, Exception", 2, 3),
            ("(BaseException, ValueError)", 1, 5),
            ("(Exception, ValueError)", 1, 3),
        ] {
            let source = format!("try:\n work()\nexcept {alternatives}:\n pass\n");
            let tree = parse("sample.py", Language::Python, &source);
            assert!(
                !tree.root_node().has_error(),
                "{}",
                tree.root_node().to_sexp()
            );
            let clause = collect_nodes_by_kind(tree.root_node(), "except_clause")[0];
            let values = children_by_field_name(clause, "value");
            assert_eq!(values.len(), count);
            if count == 1 {
                assert_eq!(values[0].kind(), "tuple");
            }
            let expected_type = if count == 2 {
                alternatives.replace(", ", " | ")
            } else {
                alternatives.to_string()
            };
            let expected = format!(
                "{expected_type}; 0; {}; generic-catch:{expected_type}, empty-body, small-body:0\n",
                weight + 7
            );
            assert_eq!(
                reports(
                    "sample.py",
                    Language::Python,
                    &source,
                    ExceptionSmellWeights::defaults()
                ),
                expected
            );
        }
    }

    #[test]
    fn scala_equal_weight_alternatives_keep_the_first_reason() {
        let mut weights = ExceptionSmellWeights::defaults();
        weights.generic_throwable_weight = 3;
        weights.generic_runtime_exception_weight = 3;
        for (types, reason) in [
            ("_: Throwable | _: Exception", "Throwable"),
            ("_: Exception | _: Throwable", "Exception"),
            ("_: RuntimeException | _: Exception", "RuntimeException"),
        ] {
            let source = format!(
                "object Sample {{ def run(): Unit = try work() catch {{ case {types} => }} }}"
            );
            let expected_types = types.replace("_: ", "");
            let expected = format!(
                "{expected_types}; 0; 10; generic-catch:{reason}, empty-body, small-body:0\n"
            );
            assert_eq!(
                reports("Sample.scala", Language::Scala, &source, weights),
                expected
            );
        }
    }
}
