use super::*;
use crate::path_utils::rel_path_string;
use tree_sitter::Node;

// heuristic. Kept as a private const list so the port stays explicit; do
// not collapse with `is_declaration_parent` — these are *statement* kinds.
const CATCH_BODY_MEANINGFUL_STATEMENT_TYPES: &[&str] = &[
    "expression_statement",
    "throw_statement",
    "return_statement",
    "break_statement",
    "continue_statement",
    "if_statement",
    "for_statement",
    "enhanced_for_statement",
    "while_statement",
    "do_statement",
    "switch_expression",
    "try_statement",
    "try_with_resources_statement",
];

const JAVA_COMMENT_NODE_TYPES: &[&str] = &["line_comment", "block_comment"];

const LOG_RECEIVER_NAMES: &[&str] = &["log", "logger"];

const EXCEPTION_EXCERPT_MAX_LEN: usize = 180;

pub(super) fn detect_exception_handling_smells_java(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    weights: &ExceptionSmellWeights,
) -> Vec<ExceptionHandlingSmell> {
    let Some(tree) = parse_tree(source) else {
        return Vec::new();
    };
    let mut catches: Vec<Node<'_>> = Vec::new();
    collect_catch_clauses(tree.root_node(), &mut catches);

    let mut findings: Vec<ExceptionHandlingSmell> = catches
        .into_iter()
        .filter_map(|catch_node| analyze_catch_clause(analyzer, file, source, catch_node, weights))
        .collect();

    findings.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.file.to_string().cmp(&b.file.to_string()))
            .then_with(|| a.enclosing_fq_name.cmp(&b.enclosing_fq_name))
            .then_with(|| a.start_byte.cmp(&b.start_byte))
    });
    findings
}

fn collect_catch_clauses<'tree>(node: Node<'tree>, out: &mut Vec<Node<'tree>>) {
    if node.kind() == "catch_clause" {
        out.push(node);
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_catch_clauses(child, out);
        }
    }
}

fn analyze_catch_clause(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    catch_node: Node<'_>,
    weights: &ExceptionSmellWeights,
) -> Option<ExceptionHandlingSmell> {
    let catch_param = named_child_by_kind(catch_node, "catch_formal_parameter")?;
    let catch_type = extract_catch_type(catch_param, source)?;
    let body_node = catch_node
        .child_by_field_name("body")
        .or_else(|| named_child_by_kind(catch_node, "block"))?;

    let body_statements = count_body_meaningful_statements(body_node);
    let has_any_comment = has_descendant_of_any_kind_inclusive(body_node, JAVA_COMMENT_NODE_TYPES);
    let empty_body = body_statements == 0 && !has_any_comment;
    let comment_only_body = body_statements == 0 && has_any_comment;
    let small_body = (body_statements as i32) <= weights.small_body_max_statements.max(0);
    let throw_present = has_descendant_of_kind(body_node, "throw_statement");
    let log_only =
        body_statements == 1 && !throw_present && is_likely_log_only_body(body_node, source);

    let mut score: i32 = 0;
    let mut reasons: Vec<String> = Vec::new();
    if catch_type.contains("Throwable") {
        score += weights.generic_throwable_weight;
        reasons.push("generic-catch:Throwable".to_string());
    } else if catch_type.contains("Exception") {
        if catch_type.contains("RuntimeException") {
            score += weights.generic_runtime_exception_weight;
            reasons.push("generic-catch:RuntimeException".to_string());
        } else {
            score += weights.generic_exception_weight;
            reasons.push("generic-catch:Exception".to_string());
        }
    }
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
        reasons.push(format!("small-body:{body_statements}"));
    }
    if log_only {
        score += weights.log_only_weight;
        reasons.push("log-only-body".to_string());
    }

    let threshold = weights.meaningful_body_statement_threshold.max(0) as u32;
    let credit_per = weights.meaningful_body_credit_per_statement.max(0);
    let credit_statements = body_statements.min(threshold);
    let body_credit = credit_per.saturating_mul(credit_statements as i32);
    if body_credit > 0 {
        score -= body_credit;
        reasons.push(format!("meaningful-body-credit:{body_credit}"));
    }

    if score <= 0 {
        return None;
    }

    let enclosing = analyzer
        .enclosing_code_unit_for_lines(
            file,
            catch_node.start_position().row,
            catch_node.end_position().row,
        )
        .map(|cu| cu.fq_name())
        .unwrap_or_else(|| rel_path_string(file));
    let excerpt = compact_catch_excerpt(
        source
            .get(catch_node.start_byte()..catch_node.end_byte())
            .unwrap_or(""),
    );
    Some(ExceptionHandlingSmell {
        file: file.clone(),
        enclosing_fq_name: enclosing,
        catch_type,
        score,
        body_statement_count: body_statements,
        reasons,
        excerpt,
        start_byte: catch_node.start_byte(),
    })
}

pub(super) fn named_child_by_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn extract_catch_type(catch_param: Node<'_>, source: &str) -> Option<String> {
    if let Some(type_node) = catch_param.child_by_field_name("type")
        && let Some(text) = source.get(type_node.start_byte()..type_node.end_byte())
    {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    let param_text = source
        .get(catch_param.start_byte()..catch_param.end_byte())?
        .trim()
        .to_string();
    if let Some(name_node) = catch_param.child_by_field_name("name")
        && let Some(name) = source.get(name_node.start_byte()..name_node.end_byte())
    {
        let name = name.trim();
        if let Some(idx) = param_text.rfind(name)
            && idx > 0
        {
            let prefix = param_text[..idx].trim();
            if !prefix.is_empty() {
                return Some(prefix.to_string());
            }
        }
    }
    if param_text.is_empty() {
        None
    } else {
        Some(param_text)
    }
}

fn count_body_meaningful_statements(body: Node<'_>) -> u32 {
    let mut cursor = body.walk();
    let mut count: u32 = 0;
    for child in body.named_children(&mut cursor) {
        let kind = child.kind();
        if JAVA_COMMENT_NODE_TYPES.contains(&kind) {
            continue;
        }
        if CATCH_BODY_MEANINGFUL_STATEMENT_TYPES.contains(&kind) {
            count += 1;
        }
    }
    count
}

/// True when `root` itself or any descendant has a kind in `kinds`. Matches
/// brokk-shared `hasDescendantOfAnyTypeInclusive` (root-inclusive).
fn has_descendant_of_any_kind_inclusive(root: Node<'_>, kinds: &[&str]) -> bool {
    if kinds.contains(&root.kind()) {
        return true;
    }
    for i in 0..root.child_count() {
        if let Some(child) = root.child(i)
            && has_descendant_of_any_kind_inclusive(child, kinds)
        {
            return true;
        }
    }
    false
}

/// True when any descendant (excluding the root itself) has the given kind.
/// Matches brokk-shared `hasDescendantOfType` (descendant-only).
fn has_descendant_of_kind(root: Node<'_>, kind: &str) -> bool {
    for i in 0..root.child_count() {
        if let Some(child) = root.child(i)
            && (child.kind() == kind || has_descendant_of_kind(child, kind))
        {
            return true;
        }
    }
    false
}

fn first_non_comment_named_child<'tree>(
    node: Node<'tree>,
    comment_kinds: &[&str],
) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| !comment_kinds.contains(&child.kind()))
}

fn find_first_named_descendant<'tree>(root: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() == kind {
            return Some(child);
        }
        if let Some(found) = find_first_named_descendant(child, kind) {
            return Some(found);
        }
    }
    None
}

fn is_likely_log_only_body(body: Node<'_>, source: &str) -> bool {
    let Some(stmt) = first_non_comment_named_child(body, JAVA_COMMENT_NODE_TYPES) else {
        return false;
    };
    if stmt.kind() != "expression_statement" {
        return false;
    }
    let Some(invocation) = find_first_named_descendant(stmt, "method_invocation") else {
        return false;
    };
    let Some(object_node) = invocation.child_by_field_name("object") else {
        return false;
    };
    let Some(receiver_text) = source.get(object_node.start_byte()..object_node.end_byte()) else {
        return false;
    };
    let receiver = receiver_text.trim().to_ascii_lowercase();
    if receiver.is_empty() {
        return false;
    }
    LOG_RECEIVER_NAMES.contains(&receiver.as_str())
        || LOG_RECEIVER_NAMES
            .iter()
            .any(|name| receiver.ends_with(&format!(".{name}")))
}

fn compact_catch_excerpt(text: &str) -> String {
    let compact = compact_whitespace_for_excerpt(text);
    if compact.chars().count() <= EXCEPTION_EXCERPT_MAX_LEN {
        return compact;
    }
    let mut truncated: String = compact.chars().take(EXCEPTION_EXCERPT_MAX_LEN).collect();
    truncated.push_str("...");
    truncated
}

fn compact_whitespace_for_excerpt(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut seen_non_ws = false;
    let mut pending_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            if seen_non_ws {
                pending_space = true;
            }
            continue;
        }
        if pending_space && !out.is_empty() {
            out.push(' ');
        }
        out.push(ch);
        pending_space = false;
        seen_non_ws = true;
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out
}
