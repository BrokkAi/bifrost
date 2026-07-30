//! Shared mechanics for language-specific exception-handling smell detectors.
//!
//! Syntax extraction stays in each language module. This module owns the
//! language-independent scoring, stable ordering, compact excerpts, and
//! stack-safe tree traversal used by those detectors.

use crate::analyzer::{ExceptionHandlingSmell, ExceptionSmellWeights};
use tree_sitter::Node;

const EXCEPTION_EXCERPT_MAX_LEN: usize = 180;

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
