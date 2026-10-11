//! Shared shaping for the per-language test-assertion smell detectors.
//!
//! Pure functions over core's own [`TestAssertionSmell`]/[`TestAssertionWeights`]
//! model types, so every language's detector can reach them wherever it lives:
//! Java's and Ruby's stay in `brokk-bifrost-analysis`, Python's moved to
//! `brokk-bifrost-python`.

use super::ProjectFile;
use super::model::{TestAssertionSmell, TestAssertionWeights};

/// A shared assertion category whose score and shallow status are language-neutral.
#[derive(Clone, Copy)]
pub enum CommonTestAssertionKind {
    ConstantEquality,
    SelfComparison,
    ConstantTruth,
    NullnessOnly,
    Meaningful,
}

/// The common classification fields consumed by language-specific signals.
#[derive(Clone, Copy)]
pub struct CommonTestAssertionClassification {
    pub kind: &'static str,
    pub score: i32,
    pub shallow: bool,
}

/// Assign shared names, weights, and shallow status to a common assertion class.
pub fn classify_common_test_assertion(
    kind: CommonTestAssertionKind,
    weights: &TestAssertionWeights,
) -> CommonTestAssertionClassification {
    let (name, score, shallow) = match kind {
        CommonTestAssertionKind::ConstantEquality => {
            ("constant-equality", weights.constant_equality_weight, false)
        }
        CommonTestAssertionKind::SelfComparison => (
            "self-comparison",
            weights.tautological_assertion_weight,
            false,
        ),
        CommonTestAssertionKind::ConstantTruth => {
            ("constant-truth", weights.constant_truth_weight, true)
        }
        CommonTestAssertionKind::NullnessOnly => {
            ("nullness-only", weights.nullness_only_weight, true)
        }
        CommonTestAssertionKind::Meaningful => ("meaningful-assertion", 0, false),
    };
    CommonTestAssertionClassification {
        kind: name,
        score,
        shallow,
    }
}

/// Normalize a captured assertion expression after its language adapter has
/// removed any language-specific trailing punctuation.
pub fn normalize_assertion_expression(expression: &str) -> String {
    expression
        .trim()
        .trim_matches(|ch| matches!(ch, '(' | ')' | ' '))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The literal spellings common to the language-specific assertion detectors.
pub fn is_common_assertion_literal(expression: &str) -> bool {
    let trimmed = expression.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || trimmed.parse::<i64>().is_ok()
        || trimmed.parse::<f64>().is_ok()
}
/// Find the first quoted test expression whose contents exceed the configured
/// large-literal threshold.
pub fn oversized_quoted_literal(
    left: &str,
    right: &str,
    weights: &TestAssertionWeights,
    quote_delimiters: &[char],
) -> Option<String> {
    [left, right].into_iter().find_map(|expression| {
        let trimmed = expression.trim();
        let unquoted = quote_delimiters.iter().find_map(|delimiter| {
            trimmed
                .strip_prefix(*delimiter)
                .and_then(|value| value.strip_suffix(*delimiter))
        })?;
        (unquoted.len() >= weights.large_literal_length_threshold.max(0) as usize)
            .then(|| trimmed.to_string())
    })
}

#[derive(Clone)]
pub struct TestAssertionSignal {
    pub kind: String,
    pub score: i32,
    pub shallow: bool,
    pub meaningful: bool,
    pub reasons: Vec<String>,
    pub excerpt: String,
    pub start_byte: usize,
}

pub fn append_test_assertion_findings(
    file: &ProjectFile,
    symbol: String,
    body_excerpt: String,
    test_start_byte: usize,
    assertions: &[TestAssertionSignal],
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let assertion_count = assertions.len() as i32;
    if assertions.is_empty() {
        out.push(TestAssertionSmell {
            file: file.clone(),
            enclosing_fq_name: symbol,
            assertion_kind: "no-assertions".to_string(),
            score: weights.no_assertion_weight,
            assertion_count: 0,
            reasons: vec!["no-assertions".to_string()],
            excerpt: body_excerpt,
            start_byte: test_start_byte,
        });
        return;
    }

    for assertion in assertions {
        if assertion.score <= 0 {
            continue;
        }
        out.push(TestAssertionSmell {
            file: file.clone(),
            enclosing_fq_name: symbol.clone(),
            assertion_kind: assertion.kind.clone(),
            score: assertion.score,
            assertion_count,
            reasons: assertion.reasons.clone(),
            excerpt: assertion.excerpt.clone(),
            start_byte: assertion.start_byte,
        });
    }

    if assertions.iter().all(|assertion| assertion.shallow) {
        let meaningful = assertions
            .iter()
            .filter(|assertion| assertion.meaningful)
            .count() as i32;
        let creditable = meaningful.min(weights.meaningful_assertion_credit_cap.max(0));
        let score = (weights.shallow_assertion_only_weight
            - weights.meaningful_assertion_credit.max(0) * creditable)
            .max(0);
        if score > 0 {
            out.push(TestAssertionSmell {
                file: file.clone(),
                enclosing_fq_name: symbol,
                assertion_kind: "shallow-assertions-only".to_string(),
                score,
                assertion_count,
                reasons: vec!["shallow-assertions-only".to_string()],
                excerpt: body_excerpt,
                start_byte: test_start_byte,
            });
        }
    }
}

pub fn compact_assertion_excerpt(text: &str, max_chars: usize) -> String {
    let mut compact = String::with_capacity(text.len().min(max_chars.saturating_add(3)));
    let mut char_count = 0usize;
    let mut pending_space = false;
    let mut truncated = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            pending_space = !compact.is_empty();
            continue;
        }
        if pending_space {
            if char_count >= max_chars {
                truncated = true;
                break;
            }
            compact.push(' ');
            char_count += 1;
            pending_space = false;
        }
        if char_count >= max_chars {
            truncated = true;
            break;
        }
        compact.push(ch);
        char_count += 1;
    }
    if truncated {
        compact.push_str("...");
    }
    compact
}
