//! Language-independent mechanics for exception-handling smell detection.
//!
//! Syntax extraction stays in each language module; the scoring, stable
//! ordering, compact excerpts and stack-safe traversal below know no language
//! and are shared by every detector. They sit here rather than in
//! `brokk-bifrost-analysis` because Java's detector moved into
//! `brokk-bifrost-jvm` and needs them across the crate line -- the same reason
//! [`crate::analyzer::test_assertions`] and [`crate::analyzer::tree_walk`] are
//! core-owned.
//!
//! What stays in analysis is `exception_handling::analyze_for_file`: it reads
//! the project through an `IAnalyzer`, resolves a grammar by language, and
//! dispatches to the per-language detectors.

use crate::analyzer::common::try_node_source_text;
use crate::analyzer::model::{ExceptionHandlingSmell, ExceptionSmellWeights};
use crate::analyzer::tree_walk::children_iter;
use crate::analyzer::{CodeUnitIndex, ProjectFile};
use crate::path_utils::rel_path_string;
use tree_sitter::Node;

const EXCEPTION_EXCERPT_MAX_LEN: usize = 180;

pub struct HandlerScoreInput {
    pub broad_handler: Option<(i32, String)>,
    pub body_statement_count: u32,
    pub has_comment: bool,
    pub log_only: bool,
}

pub struct HandlerScore {
    pub score: i32,
    pub reasons: Vec<String>,
}

pub fn score_handler(
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
        score = score.saturating_add(weights.empty_body_weight);
        reasons.push("empty-body".to_string());
    }
    if comment_only_body {
        score = score.saturating_add(weights.comment_only_body_weight);
        reasons.push("comment-only-body".to_string());
    }
    if small_body {
        score = score.saturating_add(weights.small_body_weight);
        reasons.push(format!("small-body:{}", input.body_statement_count));
    }
    if input.log_only {
        score = score.saturating_add(weights.log_only_weight);
        reasons.push("log-only-body".to_string());
    }

    let threshold = weights.meaningful_body_statement_threshold.max(0) as u32;
    let credit_statements = input.body_statement_count.min(threshold);
    let body_credit = weights
        .meaningful_body_credit_per_statement
        .max(0)
        .saturating_mul(credit_statements as i32);
    if body_credit > 0 {
        score = score.saturating_sub(body_credit);
        reasons.push(format!("meaningful-body-credit:{body_credit}"));
    }

    (score > 0).then_some(HandlerScore { score, reasons })
}

pub fn build_handler_smell(
    analyzer: &(impl CodeUnitIndex + ?Sized),
    file: &ProjectFile,
    source: &str,
    handler: Node<'_>,
    catch_type: String,
    weights: &ExceptionSmellWeights,
    input: HandlerScoreInput,
) -> Option<ExceptionHandlingSmell> {
    let body_statement_count = input.body_statement_count;
    let scored = score_handler(weights, input)?;
    let enclosing_fq_name = analyzer
        .enclosing_code_unit_for_lines(
            file,
            handler.start_position().row,
            handler.end_position().row,
        )
        .map(|unit| unit.fq_name())
        .unwrap_or_else(|| rel_path_string(file));
    let excerpt = try_node_source_text(handler, source)
        .map(compact_excerpt)
        .unwrap_or_default();

    Some(ExceptionHandlingSmell {
        file: file.clone(),
        enclosing_fq_name,
        catch_type,
        score: scored.score,
        body_statement_count,
        reasons: scored.reasons,
        excerpt,
        start_byte: handler.start_byte(),
    })
}

pub fn sort_findings(findings: &mut [ExceptionHandlingSmell]) {
    findings.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.file.to_string().cmp(&right.file.to_string()))
            .then_with(|| left.enclosing_fq_name.cmp(&right.enclosing_fq_name))
            .then_with(|| left.start_byte.cmp(&right.start_byte))
    });
}

pub fn collect_nodes_by_kind<'tree>(root: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut matches = Vec::new();
    crate::analyzer::tree_walk::walk_tree_preorder(root, true, |node| {
        if node.kind() == kind {
            matches.push(node);
        }
        crate::analyzer::tree_walk::WalkControl::Continue
    });
    matches
}

pub fn has_descendant_of_any_kind_inclusive(root: Node<'_>, kinds: &[&str]) -> bool {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if kinds.contains(&node.kind()) {
            return true;
        }
        pending.extend(children_iter(node));
    }
    false
}

pub fn has_descendant_of_kind(root: Node<'_>, kind: &str) -> bool {
    let mut pending: Vec<Node<'_>> = (0..root.child_count())
        .filter_map(|index| root.child(index))
        .collect();
    while let Some(node) = pending.pop() {
        if node.kind() == kind {
            return true;
        }
        pending.extend(children_iter(node));
    }
    false
}

pub fn find_first_named_descendant<'tree>(root: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut found = None;
    crate::analyzer::tree_walk::walk_named_tree_preorder(root, false, |node| {
        if node.kind() == kind {
            found = Some(node);
            crate::analyzer::tree_walk::WalkControl::Break
        } else {
            crate::analyzer::tree_walk::WalkControl::Continue
        }
    });
    found
}

pub fn compact_excerpt(text: &str) -> String {
    crate::analyzer::test_assertions::compact_assertion_excerpt(text, EXCEPTION_EXCERPT_MAX_LEN)
}
