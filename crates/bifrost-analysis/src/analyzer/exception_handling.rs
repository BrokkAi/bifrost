//! Shared mechanics for language-specific exception-handling smell detectors.
//!
//! Syntax extraction stays in each language module. This module owns the
//! language-independent scoring, stable ordering, compact excerpts, and
//! stack-safe tree traversal used by those detectors.

use crate::analyzer::common::{is_unparseable_source, language_for_file};
use crate::analyzer::{
    ExceptionHandlingAnalysis, ExceptionHandlingSmell, ExceptionSmellWeights, IAnalyzer, Language,
    ProjectFile, parser_language_for_path,
};
use crate::path_utils::rel_path_string;
use tree_sitter::{Node, Parser};

const EXCEPTION_EXCERPT_MAX_LEN: usize = 180;

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

pub(crate) struct HandlerScoreInput {
    pub(crate) broad_handler: Option<(i32, String)>,
    pub(crate) body_statement_count: u32,
    pub(crate) has_comment: bool,
    pub(crate) log_only: bool,
}

pub(crate) struct HandlerScore {
    pub(crate) score: i32,
    pub(crate) reasons: Vec<String>,
}

pub(crate) fn score_handler(
    weights: &ExceptionSmellWeights,
    input: HandlerScoreInput,
) -> Option<HandlerScore> {
    let empty_body = input.body_statement_count == 0 && !input.has_comment;
    let comment_only_body = input.body_statement_count == 0 && input.has_comment;
    let small_body =
        (input.body_statement_count as i32) <= weights.small_body_max_statements.max(0);
    let (mut score, mut reasons) = match input.broad_handler {
        Some((score, reason)) => (score, vec![reason]),
        None => (0, Vec::new()),
    };

    if empty_body {
        score += weights.empty_body_weight;
        reasons.push("empty-body".to_string());
    }
    if comment_only_body {
        score += weights.comment_only_body_weight;
        reasons.push("comment-only-body".to_string());
    }
    if small_body {
        score += weights.small_body_weight;
        reasons.push(format!("small-body:{}", input.body_statement_count));
    }
    if input.log_only {
        score += weights.log_only_weight;
        reasons.push("log-only-body".to_string());
    }

    let threshold = weights.meaningful_body_statement_threshold.max(0) as u32;
    let credit_statements = input.body_statement_count.min(threshold);
    let body_credit = weights
        .meaningful_body_credit_per_statement
        .max(0)
        .saturating_mul(credit_statements as i32);
    if body_credit > 0 {
        score -= body_credit;
        reasons.push(format!("meaningful-body-credit:{body_credit}"));
    }

    (score > 0).then_some(HandlerScore { score, reasons })
}

pub(crate) fn sort_findings(findings: &mut [ExceptionHandlingSmell]) {
    findings.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.file.to_string().cmp(&right.file.to_string()))
            .then_with(|| left.enclosing_fq_name.cmp(&right.enclosing_fq_name))
            .then_with(|| left.start_byte.cmp(&right.start_byte))
    });
}

pub(crate) fn collect_nodes_by_kind<'tree>(root: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut matches = Vec::new();
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.kind() == kind {
            matches.push(node);
        }
        for index in (0..node.child_count()).rev() {
            if let Some(child) = node.child(index) {
                pending.push(child);
            }
        }
    }
    matches
}

pub(crate) fn has_descendant_of_any_kind_inclusive(root: Node<'_>, kinds: &[&str]) -> bool {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if kinds.contains(&node.kind()) {
            return true;
        }
        pending.extend((0..node.child_count()).filter_map(|index| node.child(index)));
    }
    false
}

pub(crate) fn has_descendant_of_kind(root: Node<'_>, kind: &str) -> bool {
    let mut pending: Vec<Node<'_>> = (0..root.child_count())
        .filter_map(|index| root.child(index))
        .collect();
    while let Some(node) = pending.pop() {
        if node.kind() == kind {
            return true;
        }
        pending.extend((0..node.child_count()).filter_map(|index| node.child(index)));
    }
    false
}

pub(crate) fn find_first_named_descendant<'tree>(
    root: Node<'tree>,
    kind: &str,
) -> Option<Node<'tree>> {
    let mut pending = Vec::new();
    let mut cursor = root.walk();
    let children: Vec<_> = root.named_children(&mut cursor).collect();
    pending.extend(children.into_iter().rev());
    while let Some(node) = pending.pop() {
        if node.kind() == kind {
            return Some(node);
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        pending.extend(children.into_iter().rev());
    }
    None
}

pub(crate) fn compact_excerpt(text: &str) -> String {
    let mut compact = String::with_capacity(text.len());
    let mut seen_non_whitespace = false;
    let mut pending_space = false;
    for character in text.chars() {
        if character.is_whitespace() {
            if seen_non_whitespace {
                pending_space = true;
            }
            continue;
        }
        if pending_space && !compact.is_empty() {
            compact.push(' ');
        }
        compact.push(character);
        pending_space = false;
        seen_non_whitespace = true;
    }
    if compact.chars().count() <= EXCEPTION_EXCERPT_MAX_LEN {
        return compact;
    }
    let mut truncated: String = compact.chars().take(EXCEPTION_EXCERPT_MAX_LEN).collect();
    truncated.push_str("...");
    truncated
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
            let catch_type = node
                .child_by_field_name("type")
                .and_then(first_named_child)
                .and_then(|kind| node_text(kind, source))
                .unwrap_or_else(|| "<untyped>".to_string());
            let broad = if matches!(catch_type.as_str(), "<untyped>" | "any" | "unknown") {
                Some((
                    weights.generic_exception_weight,
                    format!("generic-catch:{catch_type}"),
                ))
            } else if catch_type.contains("Error") || catch_type.contains("Exception") {
                Some((
                    weights.generic_runtime_exception_weight,
                    format!("generic-catch:{catch_type}"),
                ))
            } else {
                None
            };
            Some((body, catch_type, broad))
        },
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
            let broad = if catch_type == "<bare>" || catch_type.contains("BaseException") {
                Some((
                    weights.generic_throwable_weight,
                    format!("generic-catch:{catch_type}"),
                ))
            } else if catch_type.contains("Exception") {
                Some((
                    weights.generic_exception_weight,
                    format!("generic-catch:{catch_type}"),
                ))
            } else {
                None
            };
            Some((body, catch_type, broad))
        },
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
        let catches_unwind = contains_call_named(match_node, source, "catch_unwind");
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
            let broad = classify_java_family(&catch_type, weights);
            Some((body, catch_type, broad))
        },
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
                .unwrap_or_else(|| "<catch-all>".to_string());
            let broad = if catch_type == "<catch-all>" {
                Some((
                    weights.generic_throwable_weight,
                    "generic-catch:catch-all".to_string(),
                ))
            } else {
                classify_java_family(&catch_type, weights)
            };
            Some((body, catch_type, broad))
        },
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
            let broad = classify_java_family(&catch_type, weights);
            Some((node, catch_type, broad))
        },
        &["throw_expression"],
    )
}

fn analyze_handler_nodes<'tree>(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
    source: &str,
    nodes: Vec<Node<'tree>>,
    weights: &ExceptionSmellWeights,
    mut extract: impl FnMut(Node<'tree>, &str) -> Option<(Node<'tree>, String, Option<(i32, String)>)>,
    rethrow_kinds: &[&str],
) -> Vec<ExceptionHandlingSmell> {
    let mut findings = Vec::new();
    for handler in nodes {
        let Some((body, catch_type, broad_handler)) = extract(handler, source) else {
            continue;
        };
        let body_statement_count = handler_statement_count(body);
        let has_comment = contains_comment(body);
        let rethrow_present = rethrow_kinds
            .iter()
            .any(|kind| has_descendant_of_kind(body, kind));
        let log_only =
            body_statement_count == 1 && !rethrow_present && contains_log_identifier(body, source);
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

fn analyze_preextracted_handlers<'tree>(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
    source: &str,
    handlers: Vec<(Node<'tree>, Node<'tree>, String, Option<(i32, String)>)>,
    weights: &ExceptionSmellWeights,
    mut is_rethrow: impl FnMut(Node<'tree>) -> bool,
) -> Vec<ExceptionHandlingSmell> {
    let mut findings = Vec::new();
    for (handler, body, catch_type, broad_handler) in handlers {
        let body_statement_count = handler_statement_count(body);
        let has_comment = contains_comment(body);
        let log_only =
            body_statement_count == 1 && !is_rethrow(body) && contains_log_identifier(body, source);
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

fn classify_java_family(
    catch_type: &str,
    weights: &ExceptionSmellWeights,
) -> Option<(i32, String)> {
    if catch_type.contains("Throwable") {
        Some((
            weights.generic_throwable_weight,
            "generic-catch:Throwable".to_string(),
        ))
    } else if catch_type.contains("RuntimeException") {
        Some((
            weights.generic_runtime_exception_weight,
            "generic-catch:RuntimeException".to_string(),
        ))
    } else if catch_type.contains("Exception") {
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

fn contains_log_identifier(root: Node<'_>, source: &str) -> bool {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if matches!(
            node.kind(),
            "identifier" | "field_identifier" | "name" | "simple_identifier"
        ) && let Some(text) = node_text(node, source)
            && matches!(
                text.to_ascii_lowercase().as_str(),
                "log" | "logger" | "logging" | "error" | "warn" | "warning" | "severe"
            )
        {
            return true;
        }
        pending.extend((0..node.child_count()).filter_map(|index| node.child(index)));
    }
    false
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
        ) && node_text(node, source).as_deref() == Some(target)
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
        if node_text(left, source).as_deref() == Some("err")
            && right.kind() == "nil"
            && has_direct_child_kind(binary, "!=")
        {
            return true;
        }
    }
    false
}

fn has_direct_child_kind(node: Node<'_>, kind: &str) -> bool {
    (0..node.child_count()).any(|index| node.child(index).is_some_and(|child| child.kind() == kind))
}

fn node_text(node: Node<'_>, source: &str) -> Option<String> {
    source
        .get(node.start_byte()..node.end_byte())
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
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
