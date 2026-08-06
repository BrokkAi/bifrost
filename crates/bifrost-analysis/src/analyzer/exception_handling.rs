//! Shared mechanics for language-specific exception-handling smell detectors.
//!
//! Syntax extraction stays in each language module. This module owns the
//! project-reading, grammar-resolving dispatch; the language-independent
//! scoring, stable ordering, compact excerpts and stack-safe tree traversal the
//! detectors share moved down to [`brokk_bifrost_core::analyzer::exception_handling`]
//! when Java's detector moved into `brokk-bifrost-jvm` and needed them across
//! the crate line.

use crate::analyzer::common::{is_unparseable_source, language_for_file};
use crate::analyzer::{
    ExceptionHandlingAnalysis, ExceptionHandlingSmell, ExceptionSmellWeights, IAnalyzer, Language,
    ProjectFile, parser_language_for_path,
};
use crate::path_utils::rel_path_string;
use brokk_bifrost_core::analyzer::exception_handling::{
    HandlerScoreInput, collect_nodes_by_kind, compact_excerpt, find_first_named_descendant,
    has_descendant_of_kind, score_handler, sort_findings,
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
            Some((
                body,
                catch_type.clone(),
                classify_cpp_type(&catch_type, weights),
            ))
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
            if nearest_ancestor_of_kind(if_node, "func_literal") != Some(function) {
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
            if nearest_ancestor_of_kind(arm, "match_expression") != Some(match_node) {
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
            if nearest_ancestor_of_kind(case_clause, "catch_clause") == Some(catch_clause) {
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
            let catch_type = node_text(pattern, source)?;
            let broad = classify_exact_java_family(pattern, source, weights);
            Some((node, catch_type, broad))
        },
        handler_statement_count,
        &["throw_expression"],
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
        let Some(scored) = score_handler(
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
        let enclosing_fq_name = analyzer
            .enclosing_code_unit_for_lines(
                file,
                handler.start_position().row,
                handler.end_position().row,
            )
            .map(|unit| unit.fq_name())
            .unwrap_or_else(|| rel_path_string(file));
        findings.push(ExceptionHandlingSmell {
            file: file.clone(),
            enclosing_fq_name,
            catch_type,
            score: scored.score,
            body_statement_count,
            reasons: scored.reasons,
            excerpt: node_text(handler, source)
                .map(|text| compact_excerpt(&text))
                .unwrap_or_default(),
            start_byte: handler.start_byte(),
        });
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
        let Some(scored) = score_handler(
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
        findings.push(ExceptionHandlingSmell {
            file: file.clone(),
            enclosing_fq_name: analyzer
                .enclosing_code_unit_for_lines(
                    file,
                    handler.start_position().row,
                    handler.end_position().row,
                )
                .map(|unit| unit.fq_name())
                .unwrap_or_else(|| rel_path_string(file)),
            catch_type,
            score: scored.score,
            body_statement_count,
            reasons: scored.reasons,
            excerpt: node_text(handler, source)
                .map(|text| compact_excerpt(&text))
                .unwrap_or_default(),
            start_byte: handler.start_byte(),
        });
    }
    sort_findings(&mut findings);
    findings
}

fn classify_exact_java_family(
    type_node: Node<'_>,
    source: &str,
    weights: &ExceptionSmellWeights,
) -> Option<(i32, String)> {
    if contains_identifier(type_node, source, "Throwable") {
        Some((
            weights.generic_throwable_weight,
            "generic-catch:Throwable".to_string(),
        ))
    } else if contains_identifier(type_node, source, "RuntimeException") {
        Some((
            weights.generic_runtime_exception_weight,
            "generic-catch:RuntimeException".to_string(),
        ))
    } else if contains_identifier(type_node, source, "Exception") {
        Some((
            weights.generic_exception_weight,
            "generic-catch:Exception".to_string(),
        ))
    } else {
        None
    }
}

fn classify_cpp_type(catch_type: &str, weights: &ExceptionSmellWeights) -> Option<(i32, String)> {
    let normalized = catch_type.to_ascii_lowercase();
    if normalized == "..." {
        Some((
            weights.generic_throwable_weight,
            "generic-catch:catch-all".to_string(),
        ))
    } else if normalized.contains("runtime_error") {
        Some((
            weights.generic_runtime_exception_weight,
            "generic-catch:runtime_error".to_string(),
        ))
    } else if normalized.contains("exception") {
        Some((
            weights.generic_exception_weight,
            "generic-catch:exception".to_string(),
        ))
    } else {
        None
    }
}

fn classify_ruby_type(
    type_node: Node<'_>,
    source: &str,
    weights: &ExceptionSmellWeights,
) -> Option<(i32, String)> {
    if contains_identifier(type_node, source, "Exception") {
        Some((
            weights.generic_throwable_weight,
            "generic-catch:Exception".to_string(),
        ))
    } else if contains_identifier(type_node, source, "RuntimeError") {
        Some((
            weights.generic_runtime_exception_weight,
            "generic-catch:RuntimeError".to_string(),
        ))
    } else if contains_identifier(type_node, source, "StandardError") {
        Some((
            weights.generic_exception_weight,
            "generic-catch:StandardError".to_string(),
        ))
    } else {
        None
    }
}

fn classify_ruby_name(catch_type: &str, weights: &ExceptionSmellWeights) -> Option<(i32, String)> {
    match catch_type {
        "Exception" => Some((
            weights.generic_throwable_weight,
            "generic-catch:Exception".to_string(),
        )),
        "RuntimeError" => Some((
            weights.generic_runtime_exception_weight,
            "generic-catch:RuntimeError".to_string(),
        )),
        "StandardError" => Some((
            weights.generic_exception_weight,
            "generic-catch:StandardError".to_string(),
        )),
        _ => None,
    }
}

fn cpp_catch_type(parameters: Node<'_>, source: &str) -> String {
    for kind in [
        "qualified_identifier",
        "template_type",
        "type_identifier",
        "primitive_type",
    ] {
        if let Some(node) = find_first_named_descendant(parameters, kind)
            && let Some(text) = node_text(node, source)
        {
            return text;
        }
    }
    "...".to_string()
}

fn handler_statement_count(body: Node<'_>) -> u32 {
    if body.kind() == "catch_block" {
        return named_child_by_kind(body, "statements")
            .map(handler_statement_count)
            .unwrap_or(0);
    }
    if body.kind() == "rescue" {
        return body
            .child_by_field_name("body")
            .map(handler_statement_count)
            .unwrap_or(0);
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
        pending.extend((0..node.named_child_count()).filter_map(|index| node.named_child(index)));
    }
    statements
}

fn js_ts_statement_count(body: Node<'_>) -> u32 {
    direct_statement_count(
        body,
        &[
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
        pending.extend((0..node.child_count()).filter_map(|index| node.child(index)));
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
        pending.extend((0..node.child_count()).filter_map(|index| node.child(index)));
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
        pending.extend((0..node.child_count()).filter_map(|index| node.child(index)));
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
        pending.extend((0..node.child_count()).filter_map(|index| node.child(index)));
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
        pending.extend((0..node.child_count()).filter_map(|index| node.child(index)));
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
        pending.extend((0..node.child_count()).filter_map(|index| node.child(index)));
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
            "block" | "statement_list" | "block_expression" | "statements"
        ) {
            node = child;
        } else {
            return Some(child);
        }
    }
}

fn single_non_comment_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let mut children = node
        .named_children(&mut cursor)
        .filter(|child| !child.kind().ends_with("comment") && child.kind() != "comment");
    let only = children.next()?;
    children.next().is_none().then_some(only)
}

fn has_direct_child_kind(node: Node<'_>, kind: &str) -> bool {
    (0..node.child_count()).any(|index| node.child(index).is_some_and(|child| child.kind() == kind))
}

fn node_text(node: Node<'_>, source: &str) -> Option<String> {
    node_text_ref(node, source).map(str::to_string)
}

fn node_text_ref<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    source
        .get(node.start_byte()..node.end_byte())
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next()
}

fn last_named_child_for_handler(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).last()
}

fn named_child_by_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn direct_named_child_matching(
    node: Node<'_>,
    mut predicate: impl FnMut(&str) -> bool,
) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| predicate(child.kind()))
}

fn children_by_field_name<'tree>(node: Node<'tree>, field: &str) -> Vec<Node<'tree>> {
    let mut values = Vec::new();
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            if cursor.field_name() == Some(field) {
                values.push(cursor.node());
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    values
}

fn nearest_ancestor_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == kind {
            return Some(parent);
        }
        current = parent.parent();
    }
    None
}
