use crate::analyzer::common::language_for_file;
use crate::analyzer::{
    CloneSmell, CloneSmellWeights, CodeUnit, IAnalyzer, Language, ProjectFile, parser_language_for,
};
use std::collections::{HashMap, HashSet};
use tree_sitter::{Node, Parser};

#[derive(Debug, Clone, Copy)]
pub(crate) struct CloneSyntaxProfile {
    language: Language,
    candidate_kinds: &'static [&'static str],
    identifier_kinds: &'static [&'static str],
    string_kinds: &'static [&'static str],
    number_kinds: &'static [&'static str],
    comment_kinds: &'static [&'static str],
}

impl CloneSyntaxProfile {
    pub(crate) const fn new(
        language: Language,
        candidate_kinds: &'static [&'static str],
        identifier_kinds: &'static [&'static str],
        string_kinds: &'static [&'static str],
        number_kinds: &'static [&'static str],
        comment_kinds: &'static [&'static str],
    ) -> Self {
        Self {
            language,
            candidate_kinds,
            identifier_kinds,
            string_kinds,
            number_kinds,
            comment_kinds,
        }
    }
}

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

pub(crate) fn build_tree_sitter_clone_candidate_data(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
    profile: CloneSyntaxProfile,
) -> Option<CloneCandidateData> {
    let source = analyzer.get_source(code_unit, false)?.trim().to_string();
    if source.is_empty() {
        return None;
    }

    let (normalized_tokens, ast_signature, has_candidate) =
        normalize_tree_sitter_clone_source(&source, profile);
    if !has_candidate {
        return None;
    }
    if normalized_tokens.len() < weights.min_normalized_tokens.max(0) as usize {
        return None;
    }

    Some(CloneCandidateData {
        unit: code_unit.clone(),
        normalized_tokens,
        ast_signature,
        excerpt: compact_clone_excerpt(&source),
    })
}

fn normalize_tree_sitter_clone_source(
    source: &str,
    profile: CloneSyntaxProfile,
) -> (Vec<String>, String, bool) {
    let mut parser = Parser::new();
    let language = parser_language_for(profile.language)
        .expect("clone syntax profile must use a registered parser language");
    parser
        .set_language(&language)
        .expect("failed to load clone syntax parser");
    let Some(tree) = parser.parse(source, None) else {
        return (Vec::new(), String::new(), false);
    };

    let mut normalized_tokens = Vec::new();
    let mut ast_labels = Vec::new();
    let mut has_candidate = false;
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if profile.comment_kinds.contains(&node.kind()) {
            continue;
        }
        has_candidate |= profile.candidate_kinds.contains(&node.kind());
        ast_labels.push(normalize_clone_ast_label(node, source, profile));
        if node.named_child_count() == 0 {
            let token = normalize_clone_leaf_token(node, source, profile);
            if !token.is_empty() {
                normalized_tokens.push(token);
            }
            // Do not descend further: anonymous children of an emitted leaf
            // would double-count it. Kotlin's soft-keyword identifiers
            // (`value`, `field`) parse as a `simple_identifier` wrapping an
            // anonymous keyword token, and emitting both breaks rename
            // invariance against ordinary identifiers.
            continue;
        }
        for index in (0..node.child_count()).rev() {
            if let Some(child) = node.child(index) {
                stack.push(child);
            }
        }
    }

    (normalized_tokens, ast_labels.join("|"), has_candidate)
}

fn normalize_clone_leaf_token(node: Node<'_>, source: &str, profile: CloneSyntaxProfile) -> String {
    let kind = node.kind();
    let token = node_text(node, source);
    if token.is_empty() || profile.comment_kinds.contains(&kind) {
        return String::new();
    }
    if profile.identifier_kinds.contains(&kind) {
        return "ID".to_string();
    }
    if profile.string_kinds.contains(&kind) {
        return "STR".to_string();
    }
    if profile.number_kinds.contains(&kind) {
        return "NUM".to_string();
    }
    if matches!(token, "true" | "false") {
        return "BOOL".to_string();
    }
    if token.chars().count() == 1 && token.chars().all(|ch| !ch.is_alphanumeric()) {
        return format!("OP:{token}");
    }
    format!("T:{kind}")
}

fn normalize_clone_ast_label(node: Node<'_>, source: &str, profile: CloneSyntaxProfile) -> String {
    let kind = node.kind();
    let text = node_text(node, source);
    if profile.identifier_kinds.contains(&kind) {
        return "ID".to_string();
    }
    if profile.string_kinds.contains(&kind) {
        return "STR".to_string();
    }
    if profile.number_kinds.contains(&kind) {
        return "NUM".to_string();
    }
    if matches!(text, "true" | "false") {
        return "BOOL".to_string();
    }
    format!("N:{kind}")
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim()
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

pub(crate) fn refine_clone_similarity_with_ast(
    left: &CloneCandidateData,
    right: &CloneCandidateData,
    token_similarity: i32,
    weights: CloneSmellWeights,
) -> i32 {
    if left.ast_signature.is_empty() || right.ast_signature.is_empty() {
        return token_similarity;
    }
    let ast_similarity =
        compute_ast_refinement_similarity_percent(&left.ast_signature, &right.ast_signature);
    if ast_similarity == 0 {
        return token_similarity;
    }
    if ast_similarity < weights.ast_similarity_percent {
        return 0;
    }
    token_similarity.min(ast_similarity)
}

pub(crate) fn compare_clone_units(left: &CodeUnit, right: &CodeUnit) -> std::cmp::Ordering {
    left.source()
        .to_string()
        .cmp(&right.source().to_string())
        .then_with(|| left.fq_name().cmp(&right.fq_name()))
}

pub(crate) fn detect_structural_clone_smells<F>(
    requested_files: &[ProjectFile],
    all_candidates: Vec<CloneCandidateProfile>,
    weights: CloneSmellWeights,
    refine_similarity: F,
) -> Vec<CloneSmell>
where
    F: Fn(&CloneCandidateData, &CloneCandidateData, i32, CloneSmellWeights) -> i32,
{
    let requested_files: HashSet<ProjectFile> = requested_files.iter().cloned().collect();
    if requested_files.is_empty() || all_candidates.is_empty() {
        return Vec::new();
    }

    let requested_candidates: Vec<&CloneCandidateProfile> = all_candidates
        .iter()
        .filter(|candidate| requested_files.contains(candidate.data.unit.source()))
        .collect();
    if requested_candidates.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for left in requested_candidates {
        for right in &all_candidates {
            if left.data.unit == right.data.unit {
                continue;
            }
            if requested_files.contains(right.data.unit.source())
                && compare_clone_units(&left.data.unit, &right.data.unit).is_gt()
            {
                continue;
            }
            if !can_reach_clone_similarity(left.shingle_count, right.shingle_count, weights) {
                continue;
            }
            let token_similarity =
                compute_clone_token_similarity(&left.shingles, &right.shingles, weights);
            if token_similarity < weights.min_similarity_percent {
                continue;
            }
            let refined_similarity =
                refine_similarity(&left.data, &right.data, token_similarity, weights);
            if refined_similarity < weights.min_similarity_percent {
                continue;
            }
            findings.push(CloneSmell {
                file: left.data.unit.source().clone(),
                enclosing_fq_name: left.data.unit.fq_name(),
                peer_file: right.data.unit.source().clone(),
                peer_enclosing_fq_name: right.data.unit.fq_name(),
                score: refined_similarity,
                normalized_token_count: left
                    .data
                    .normalized_tokens
                    .len()
                    .min(right.data.normalized_tokens.len())
                    as i32,
                reasons: vec![build_clone_reason(token_similarity, refined_similarity)],
                excerpt: left.data.excerpt.clone(),
                peer_excerpt: right.data.excerpt.clone(),
            });
        }
    }

    findings.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.file.to_string().cmp(&right.file.to_string()))
            .then_with(|| left.enclosing_fq_name.cmp(&right.enclosing_fq_name))
            .then_with(|| left.peer_file.to_string().cmp(&right.peer_file.to_string()))
            .then_with(|| {
                left.peer_enclosing_fq_name
                    .cmp(&right.peer_enclosing_fq_name)
            })
    });
    findings
}

pub(crate) fn detect_language_structural_clone_smells<F>(
    analyzer: &dyn IAnalyzer,
    files: &[ProjectFile],
    weights: CloneSmellWeights,
    language: Language,
    build_candidate: F,
) -> Vec<CloneSmell>
where
    F: Fn(&CodeUnit) -> Option<CloneCandidateData>,
{
    let requested_files: Vec<ProjectFile> = files
        .iter()
        .filter(|file| language_for_file(file) == language)
        .cloned()
        .collect();
    if requested_files.is_empty() {
        return Vec::new();
    }

    let all_candidates = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|code_unit| {
            code_unit.is_function() && language_for_file(code_unit.source()) == language
        })
        .filter_map(|code_unit| build_candidate(&code_unit))
        .map(|candidate| CloneCandidateProfile::create(candidate, weights))
        .collect();

    detect_structural_clone_smells(
        &requested_files,
        all_candidates,
        weights,
        refine_clone_similarity_with_ast,
    )
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

#[cfg(test)]
mod tests {
    use super::{
        LongShingles, can_reach_clone_similarity, compute_clone_token_similarity,
        hashed_shingle_array,
    };
    use crate::analyzer::CloneSmellWeights;
    use std::collections::HashSet;

    #[test]
    fn hashed_similarity_matches_string_shingle_similarity_for_identical_tokens() {
        let tokens = vec!["ID", "OP:=", "NUM", "OP:+", "ID"];
        let weights = weights(1, 1, 2, 1, 70);

        assert_similarity_matches_string_shingles(&tokens, &tokens, weights);
    }

    #[test]
    fn hashed_similarity_matches_string_shingle_similarity_for_partial_overlap() {
        let left = vec!["ID", "OP:=", "NUM", "OP:+", "ID", "OP:;", "return", "ID"];
        let right = vec!["ID", "OP:=", "NUM", "OP:-", "ID", "OP:;", "return", "NUM"];
        let weights = weights(1, 1, 2, 1, 70);

        assert_similarity_matches_string_shingles(&left, &right, weights);
    }

    #[test]
    fn hashed_similarity_matches_string_shingle_similarity_below_min_shared_shingles() {
        let left = vec!["ID", "OP:=", "NUM", "OP:+", "ID"];
        let right = vec!["return", "STR", "OP:;", "throw", "ID"];
        let weights = weights(1, 1, 2, 3, 70);

        assert_similarity_matches_string_shingles(&left, &right, weights);
    }

    #[test]
    fn hashed_similarity_matches_string_shingle_similarity_when_shorter_than_shingle_size() {
        let left = vec!["ID", "OP:="];
        let right = vec!["ID", "OP:="];
        let weights = weights(1, 1, 3, 1, 70);

        assert_similarity_matches_string_shingles(&left, &right, weights);
    }

    #[test]
    fn returns_zero_when_shingle_size_skew_cannot_meet_similarity_threshold() {
        let left = vec!["A", "B", "C"];
        let right = vec!["A", "B", "C", "D", "E", "F", "G", "H"];
        let weights = weights(1, 80, 1, 1, 70);

        assert_eq!(
            0,
            compute_clone_token_similarity(
                &hashed(left, weights.shingle_size),
                &hashed(right, weights.shingle_size),
                weights,
            )
        );
    }

    #[test]
    fn upper_bound_uses_rounded_similarity_threshold() {
        let left: Vec<String> = (0..699).map(|n| n.to_string()).collect();
        let right: Vec<String> = (0..1000).map(|n| n.to_string()).collect();
        let weights = weights(1, 70, 1, 1, 70);

        assert_eq!(
            70,
            compute_clone_token_similarity(
                &hashed_strings(&left, weights.shingle_size),
                &hashed_strings(&right, weights.shingle_size),
                weights,
            )
        );
    }

    #[test]
    fn candidate_prefilter_rejects_pairs_below_min_shared_shingles() {
        let weights = weights(1, 50, 1, 3, 70);

        assert!(!can_reach_clone_similarity(2, 5, weights));
    }

    #[test]
    fn candidate_prefilter_rejects_pairs_whose_rounded_upper_bound_misses_threshold() {
        let weights = weights(1, 71, 1, 1, 70);

        assert!(!can_reach_clone_similarity(699, 1000, weights));
    }

    #[test]
    fn candidate_prefilter_keeps_pairs_at_rounded_upper_bound_threshold() {
        let weights = weights(1, 70, 1, 1, 70);

        assert!(can_reach_clone_similarity(699, 1000, weights));
    }

    #[test]
    fn candidate_prefilter_stays_conservative_for_repetitive_token_streams() {
        let left = repeated_tokens("A", "B", "C", 50);
        let right = repeated_tokens("A", "B", "C", 100);
        let weights = weights(1, 70, 2, 1, 70);
        let left_shingles = hashed(left.clone(), weights.shingle_size);
        let right_shingles = hashed(right.clone(), weights.shingle_size);

        assert!(can_reach_clone_similarity(
            left_shingles.size(),
            right_shingles.size(),
            weights
        ));
        assert_eq!(
            100,
            compute_clone_token_similarity(&left_shingles, &right_shingles, weights)
        );
    }

    fn assert_similarity_matches_string_shingles(
        left: &[&str],
        right: &[&str],
        weights: CloneSmellWeights,
    ) {
        let expected = string_shingle_similarity(left, right, weights);
        let actual = compute_clone_token_similarity(
            &hashed(left.to_vec(), weights.shingle_size),
            &hashed(right.to_vec(), weights.shingle_size),
            weights,
        );
        assert_eq!(expected, actual);
    }

    fn string_shingle_similarity(left: &[&str], right: &[&str], weights: CloneSmellWeights) -> i32 {
        let left_shingles = string_shingles(left, weights.shingle_size);
        let right_shingles = string_shingles(right, weights.shingle_size);
        if left_shingles.len() < weights.min_shared_shingles as usize
            || right_shingles.len() < weights.min_shared_shingles as usize
        {
            return 0;
        }
        let intersection = left_shingles.intersection(&right_shingles).count();
        if intersection < weights.min_shared_shingles as usize {
            return 0;
        }
        let union = left_shingles.union(&right_shingles).count();
        if union == 0 {
            return 0;
        }
        ((intersection as f64 * 100.0) / union as f64).round() as i32
    }

    fn string_shingles(tokens: &[&str], shingle_size: i32) -> HashSet<String> {
        let k = shingle_size.max(1) as usize;
        if tokens.len() < k {
            return HashSet::new();
        }
        let mut shingles = HashSet::new();
        for start in 0..=(tokens.len() - k) {
            shingles.insert(tokens[start..start + k].join("|"));
        }
        shingles
    }

    fn hashed(tokens: Vec<&str>, shingle_size: i32) -> LongShingles {
        let tokens = tokens.into_iter().map(str::to_string).collect::<Vec<_>>();
        hashed_shingle_array(&tokens, shingle_size)
    }

    fn hashed_strings(tokens: &[String], shingle_size: i32) -> LongShingles {
        hashed_shingle_array(tokens, shingle_size)
    }

    fn repeated_tokens<'a>(
        first: &'a str,
        second: &'a str,
        third: &'a str,
        repetitions: usize,
    ) -> Vec<&'a str> {
        let mut tokens = Vec::with_capacity(repetitions * 3);
        for _ in 0..repetitions {
            tokens.push(first);
            tokens.push(second);
            tokens.push(third);
        }
        tokens
    }

    fn weights(
        min_normalized_tokens: i32,
        min_similarity_percent: i32,
        shingle_size: i32,
        min_shared_shingles: i32,
        ast_similarity_percent: i32,
    ) -> CloneSmellWeights {
        CloneSmellWeights {
            min_normalized_tokens,
            min_similarity_percent,
            shingle_size,
            min_shared_shingles,
            ast_similarity_percent,
        }
    }
}
