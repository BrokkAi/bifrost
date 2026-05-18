use crate::analyzer::{CloneSmellWeights, CodeUnit};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub(crate) struct CloneCandidateData {
    pub(crate) unit: CodeUnit,
    pub(crate) normalized_tokens: Vec<String>,
    pub(crate) ast_signature: String,
    pub(crate) excerpt: String,
}

#[derive(Debug, Clone)]
pub(crate) struct CloneCandidateProfile {
    pub(crate) data: CloneCandidateData,
    pub(crate) shingles: LongShingles,
    pub(crate) shingle_count: usize,
}

impl CloneCandidateProfile {
    pub(crate) fn create(data: CloneCandidateData, weights: CloneSmellWeights) -> Self {
        let shingles = hashed_shingle_array(&data.normalized_tokens, weights.shingle_size);
        let shingle_count = shingles.size();
        Self {
            data,
            shingles,
            shingle_count,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LongShingles {
    values: Box<[u64]>,
}

impl LongShingles {
    pub(crate) fn empty() -> Self {
        Self {
            values: Box::new([]),
        }
    }

    pub(crate) fn size(&self) -> usize {
        self.values.len()
    }

    pub(crate) fn values(&self) -> &[u64] {
        &self.values
    }

    fn from_unsorted(mut values: Vec<u64>) -> Self {
        if values.is_empty() {
            return Self::empty();
        }
        values.sort_unstable();
        values.dedup();
        Self {
            values: values.into_boxed_slice(),
        }
    }
}

pub(crate) fn compute_ast_refinement_similarity_percent(
    left_ast_signature: &str,
    right_ast_signature: &str,
) -> i32 {
    let broad_similarity =
        compute_ast_label_multiset_similarity_percent(left_ast_signature, right_ast_signature);
    if broad_similarity == 0 {
        return 0;
    }
    let control_similarity =
        compute_ast_control_flow_similarity_percent(left_ast_signature, right_ast_signature);
    if control_similarity < 0 {
        return broad_similarity;
    }
    (((broad_similarity * 2) as f64 + control_similarity as f64) / 3.0).round() as i32
}

pub(crate) fn hashed_shingle_array(tokens: &[String], shingle_size: i32) -> LongShingles {
    let k = shingle_size.max(1) as usize;
    if tokens.len() < k {
        return LongShingles::empty();
    }
    let mut shingles = Vec::with_capacity(tokens.len() - k + 1);
    for start in 0..=(tokens.len() - k) {
        shingles.push(hash_shingle(tokens, start, k));
    }
    LongShingles::from_unsorted(shingles)
}

pub(crate) fn compute_clone_token_similarity(
    left_shingles: &LongShingles,
    right_shingles: &LongShingles,
    weights: CloneSmellWeights,
) -> i32 {
    if !can_reach_clone_similarity(left_shingles.size(), right_shingles.size(), weights) {
        return 0;
    }
    let intersection_size = intersection_size(left_shingles, right_shingles);
    if intersection_size < weights.min_shared_shingles.max(0) as usize {
        return 0;
    }
    let union_size = left_shingles.size() + right_shingles.size() - intersection_size;
    if union_size == 0 {
        return 0;
    }
    ((intersection_size as f64 * 100.0) / union_size as f64).round() as i32
}

pub(crate) fn can_reach_clone_similarity(
    left_shingle_count: usize,
    right_shingle_count: usize,
    weights: CloneSmellWeights,
) -> bool {
    let min_shared = weights.min_shared_shingles.max(0) as usize;
    if left_shingle_count < min_shared || right_shingle_count < min_shared {
        return false;
    }
    let smaller_count = left_shingle_count.min(right_shingle_count);
    let larger_count = left_shingle_count.max(right_shingle_count);
    if larger_count == 0 {
        return false;
    }
    let max_possible_similarity = ((smaller_count as f64 * 100.0) / larger_count as f64).round();
    max_possible_similarity as i32 >= weights.min_similarity_percent
}

pub(crate) fn compact_clone_excerpt(raw: &str) -> String {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(6)
        .collect::<Vec<_>>()
        .join(" ")
        .replace('|', "\\|")
}

pub(crate) fn build_clone_reason(token_similarity: i32, refined_similarity: i32) -> String {
    if refined_similarity == token_similarity {
        return format!("token-similarity:{token_similarity}");
    }
    format!("token-similarity:{token_similarity}, refined-similarity:{refined_similarity}")
}

pub(crate) fn compare_clone_units(left: &CodeUnit, right: &CodeUnit) -> std::cmp::Ordering {
    left.source()
        .to_string()
        .cmp(&right.source().to_string())
        .then_with(|| left.fq_name().cmp(&right.fq_name()))
}

fn compute_ast_label_multiset_similarity_percent(left: &str, right: &str) -> i32 {
    let left_counts = ast_label_counts(left);
    let right_counts = ast_label_counts(right);
    if left_counts.is_empty() || right_counts.is_empty() {
        return 0;
    }
    let all_labels: HashSet<&str> = left_counts
        .keys()
        .map(String::as_str)
        .chain(right_counts.keys().map(String::as_str))
        .collect();
    let mut intersection = 0usize;
    let mut union = 0usize;
    for label in all_labels {
        let left_count = left_counts.get(label).copied().unwrap_or_default();
        let right_count = right_counts.get(label).copied().unwrap_or_default();
        intersection += left_count.min(right_count);
        union += left_count.max(right_count);
    }
    if union == 0 {
        return 0;
    }
    ((intersection as f64 * 100.0) / union as f64).round() as i32
}

fn ast_label_counts(ast_signature: &str) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for label in ast_signature
        .split('|')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        *counts.entry(label.to_string()).or_insert(0) += 1;
    }
    counts
}

fn compute_ast_control_flow_similarity_percent(left: &str, right: &str) -> i32 {
    let left_control = extract_control_flow_signature(left);
    let right_control = extract_control_flow_signature(right);
    if left_control.is_empty() || right_control.is_empty() {
        return -1;
    }
    compute_ast_label_multiset_similarity_percent(&left_control, &right_control)
}

fn extract_control_flow_signature(ast_signature: &str) -> String {
    ast_signature
        .split('|')
        .map(str::trim)
        .filter(|label| label.starts_with("N:") && is_control_flow_label(label))
        .collect::<Vec<_>>()
        .join("|")
}

fn is_control_flow_label(label: &str) -> bool {
    [
        "if", "else", "while", "for", "switch", "case", "try", "catch", "finally", "return",
        "throw", "break", "continue",
    ]
    .iter()
    .any(|needle| label.contains(needle))
}

fn hash_shingle(tokens: &[String], start: usize, length: usize) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for token in tokens.iter().skip(start).take(length) {
        hash = fnv1a(hash, token.len() as u64);
        for ch in token.chars() {
            hash = fnv1a(hash, ch as u64);
        }
    }
    hash
}

fn fnv1a(hash: u64, value: u64) -> u64 {
    (hash ^ value).wrapping_mul(0x100000001b3)
}

fn intersection_size(left: &LongShingles, right: &LongShingles) -> usize {
    let smaller = if left.size() <= right.size() {
        left.values()
    } else {
        right.values()
    };
    let larger = if left.size() <= right.size() {
        right.values()
    } else {
        left.values()
    };
    let mut count = 0usize;
    let mut smaller_index = 0usize;
    let mut larger_index = 0usize;
    while smaller_index < smaller.len() && larger_index < larger.len() {
        match smaller[smaller_index].cmp(&larger[larger_index]) {
            std::cmp::Ordering::Equal => {
                count += 1;
                smaller_index += 1;
                larger_index += 1;
            }
            std::cmp::Ordering::Less => smaller_index += 1,
            std::cmp::Ordering::Greater => larger_index += 1,
        }
    }
    count
}
