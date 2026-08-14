//! Shared shaping for the per-language test-assertion smell detectors.
//!
//! Pure functions over core's own [`TestAssertionSmell`]/[`TestAssertionWeights`]
//! model types, so every language's detector can reach them wherever it lives:
//! Java's and Ruby's stay in `brokk-bifrost-analysis`, Python's moved to
//! `brokk-bifrost-python`.

use super::ProjectFile;
use super::model::{TestAssertionSmell, TestAssertionWeights};

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
