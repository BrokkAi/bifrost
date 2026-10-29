use crate::analyzer::common::language_for_file;
use crate::analyzer::tree_walk::push_children_reversed;
use crate::analyzer::{
    CloneSmell, CloneSmellWeights, CodeUnit, IAnalyzer, Language, ProjectFile, parser_language_for,
};
use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;
use brokk_bifrost_core::clones::{
    CloneNormalizationRules, normalize_clone_ast_label, normalize_clone_leaf_token,
};
use std::collections::{HashMap, HashSet};
use tree_sitter::Parser;

#[derive(Debug, Clone, Copy)]
#[doc(hidden)]
pub struct CloneSyntaxProfile {
    language: Language,
    candidate_kinds: &'static [&'static str],
    identifier_kinds: &'static [&'static str],
    string_kinds: &'static [&'static str],
    number_kinds: &'static [&'static str],
    comment_kinds: &'static [&'static str],
}

impl CloneSyntaxProfile {
    #[doc(hidden)]
    pub const fn new(
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
#[doc(hidden)]
pub struct CloneCandidateData {
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

#[doc(hidden)]
pub fn build_clone_candidate_data(
    source: Option<String>,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
    prepare: impl FnOnce(&str, usize) -> Option<(Vec<String>, String)>,
) -> Option<CloneCandidateData> {
    let source = source?;
    let source = source.trim();
    if source.is_empty() {
        return None;
    }

    let min_normalized_tokens = weights.min_normalized_tokens.max(0) as usize;
    let (normalized_tokens, ast_signature) = prepare(source, min_normalized_tokens)?;
    if normalized_tokens.len() < min_normalized_tokens {
        return None;
    }

    Some(CloneCandidateData {
        unit: code_unit.clone(),
        normalized_tokens,
        ast_signature,
        excerpt: compact_clone_excerpt(source),
    })
}

#[doc(hidden)]
pub fn build_tree_sitter_clone_candidate_data(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
    profile: CloneSyntaxProfile,
) -> Option<CloneCandidateData> {
    build_clone_candidate_data(
        analyzer.get_source(code_unit, false),
        code_unit,
        weights,
        |source, _| {
            let (tokens, signature, has_candidate) =
                normalize_tree_sitter_clone_source(source, profile);
            has_candidate.then_some((tokens, signature))
        },
    )
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
    let tree = crate::analyzer::repaired_grammar_gap_tree(profile.language, source, tree);

    let normalization_rules = CloneNormalizationRules {
        identifier_kinds: profile.identifier_kinds,
        string_kinds: profile.string_kinds,
        number_kinds: profile.number_kinds,
        boolean_kinds: &[],
        boolean_values: &["true", "false"],
        null_kinds: &[],
        null_values: &[],
        comment_kinds: profile.comment_kinds,
        ignored_ast_kinds: &[],
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
        ast_labels.push(normalize_clone_ast_label(node, source, normalization_rules));
        if node.named_child_count() == 0 {
            let token = normalize_clone_leaf_token(node, source, normalization_rules);
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
        push_children_reversed(node, &mut stack);
    }

    (normalized_tokens, ast_labels.join("|"), has_candidate)
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
    kind_table: &[(&str, NormalizedKind)],
) -> i32 {
    let broad_similarity =
        compute_ast_label_multiset_similarity_percent(left_ast_signature, right_ast_signature);
    if broad_similarity == 0 {
        return 0;
    }
    let control_similarity = compute_ast_control_flow_similarity_percent(
        left_ast_signature,
        right_ast_signature,
        kind_table,
    );
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
    let spec = crate::analyzer::structural_spec_for(language_for_file(left.unit.source()))
        .expect("clone candidates require registered structural syntax");
    let kind_table = spec.kind_table();
    let ast_similarity = compute_ast_refinement_similarity_percent(
        &left.ast_signature,
        &right.ast_signature,
        kind_table,
    );
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

    let candidate_index = CloneCandidateIndex::new(&all_candidates);

    let mut findings = Vec::new();
    for left in requested_candidates {
        let peer_indices = candidate_index.peer_indices(left, &all_candidates, weights);
        for peer_index in peer_indices {
            let right = &all_candidates[peer_index];
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

struct CloneCandidateIndex {
    candidates_by_shingle: HashMap<u64, Vec<usize>>,
}

impl CloneCandidateIndex {
    fn new(all_candidates: &[CloneCandidateProfile]) -> Self {
        let mut candidates_by_shingle: HashMap<u64, Vec<usize>> = HashMap::new();
        for (candidate_index, candidate) in all_candidates.iter().enumerate() {
            for shingle in candidate.shingles.values() {
                candidates_by_shingle
                    .entry(*shingle)
                    .or_default()
                    .push(candidate_index);
            }
        }
        Self {
            candidates_by_shingle,
        }
    }

    fn peer_indices(
        &self,
        left: &CloneCandidateProfile,
        all_candidates: &[CloneCandidateProfile],
        weights: CloneSmellWeights,
    ) -> Vec<usize> {
        let min_shared_shingles = weights.min_shared_shingles.max(0) as usize;
        if min_shared_shingles == 0 {
            return (0..all_candidates.len())
                .filter(|index| {
                    can_reach_clone_similarity(
                        left.shingle_count,
                        all_candidates[*index].shingle_count,
                        weights,
                    )
                })
                .collect();
        }

        let mut shared_shingle_counts = HashMap::new();
        for shingle in left.shingles.values() {
            let Some(candidate_indices) = self.candidates_by_shingle.get(shingle) else {
                continue;
            };
            for candidate_index in candidate_indices {
                *shared_shingle_counts
                    .entry(*candidate_index)
                    .or_insert(0usize) += 1;
            }
        }

        shared_shingle_counts
            .into_iter()
            .filter_map(|(candidate_index, shared_shingles)| {
                (shared_shingles >= min_shared_shingles
                    && can_reach_clone_similarity(
                        left.shingle_count,
                        all_candidates[candidate_index].shingle_count,
                        weights,
                    ))
                .then_some(candidate_index)
            })
            .collect()
    }
}

#[doc(hidden)]
pub fn detect_language_structural_clone_smells<F>(
    analyzer: &dyn IAnalyzer,
    files: &[ProjectFile],
    weights: CloneSmellWeights,
    language: Language,
    build_candidate: F,
) -> Vec<CloneSmell>
where
    F: FnMut(&CodeUnit) -> Option<CloneCandidateData>,
{
    let requested_files: Vec<ProjectFile> = files
        .iter()
        .filter(|file| language_for_file(file) == language)
        .cloned()
        .collect();
    if requested_files.is_empty() {
        return Vec::new();
    }

    let corpus_units = clone_corpus_function_units(analyzer, language);
    detect_structural_clone_smells_for_corpus(
        analyzer,
        &requested_files,
        &corpus_units,
        weights,
        build_candidate,
    )
}

#[doc(hidden)]
pub fn detect_structural_clone_smells_for_corpus<F>(
    analyzer: &dyn IAnalyzer,
    requested_files: &[ProjectFile],
    corpus_units: &[CodeUnit],
    weights: CloneSmellWeights,
    build_candidate: F,
) -> Vec<CloneSmell>
where
    F: FnMut(&CodeUnit) -> Option<CloneCandidateData>,
{
    // Hold one query scope over the whole corpus build: per-unit source
    // assembly re-reads each file's declaration state once per function it
    // declares, and the scope's file-state snapshot serves those repeats
    // from memory instead of the store.
    let _query_scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
    let all_candidates = corpus_units
        .iter()
        .filter_map(build_candidate)
        .map(|candidate| CloneCandidateProfile::create(candidate, weights))
        .collect();

    detect_structural_clone_smells(
        requested_files,
        all_candidates,
        weights,
        refine_clone_similarity_with_ast,
    )
}

/// The whole-workspace clone corpus: every function declaration of one
/// language. Shared by the generic driver above and the language modules
/// that build candidates with language-specific state.
pub(crate) fn clone_corpus_function_units(
    analyzer: &dyn IAnalyzer,
    language: Language,
) -> Vec<CodeUnit> {
    analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|code_unit| {
            code_unit.is_function() && language_for_file(code_unit.source()) == language
        })
        .collect()
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
    debug_assert!(union > 0, "nonempty label bags have a nonempty union");
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

fn compute_ast_control_flow_similarity_percent(
    left: &str,
    right: &str,
    kind_table: &[(&str, NormalizedKind)],
) -> i32 {
    let left_control = extract_control_flow_signature(left, kind_table);
    let right_control = extract_control_flow_signature(right, kind_table);
    if left_control.is_empty() || right_control.is_empty() {
        return -1;
    }
    compute_ast_label_multiset_similarity_percent(&left_control, &right_control)
}

fn extract_control_flow_signature(
    ast_signature: &str,
    kind_table: &[(&str, NormalizedKind)],
) -> String {
    ast_signature
        .split('|')
        .map(str::trim)
        .filter(|label| label.starts_with("N:") && is_control_flow_label(label, kind_table))
        .collect::<Vec<_>>()
        .join("|")
}

fn is_control_flow_label(label: &str, kind_table: &[(&str, NormalizedKind)]) -> bool {
    let Some(node_kind) = label.strip_prefix("N:") else {
        return false;
    };
    // Grammar spelling belongs to each language's structural adapter. In
    // particular, formal_parameters and modifiers are not loops or branches.
    kind_table.iter().any(|(name, kind)| {
        *name == node_kind
            && (kind.satisfies(NormalizedKind::Loop)
                || matches!(
                    kind,
                    NormalizedKind::If
                        | NormalizedKind::Switch
                        | NormalizedKind::Case
                        | NormalizedKind::Catch
                        | NormalizedKind::Return
                        | NormalizedKind::Throw
                        | NormalizedKind::Break
                        | NormalizedKind::Continue
                ))
    })
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
        CloneCandidateData, CloneCandidateIndex, CloneCandidateProfile, LongShingles,
        can_reach_clone_similarity, compute_clone_token_similarity, hashed_shingle_array,
    };
    use crate::analyzer::{CloneSmellWeights, CodeUnit, CodeUnitType, ProjectFile};
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "97a35feae74c: quicksilver round 12 on brokk-bifrost-analysis: formal parameters and modifiers polluted clone control signatures"
    )]
    fn declaration_control_signatures_exclude_parameters_and_modifiers() {
        let java = brokk_bifrost_jvm::java::clones::prepare_java_clone(
            "class Example { public int f(int x) { return x; } }",
            0,
        )
        .unwrap()
        .ast_signature;
        let csharp = brokk_bifrost_csharp::clones::build_csharp_clone_ast_signature(
            "class Example { public int F(int x) { return x; } }",
        );
        for (language, signature, table, declaration_kind) in [
            (
                "java",
                java,
                brokk_bifrost_jvm::java::structural::JAVA_KIND_TABLE,
                "N:formal_parameters",
            ),
            (
                "csharp",
                csharp,
                brokk_bifrost_csharp::structural::CSHARP_KIND_TABLE,
                "N:modifier",
            ),
        ] {
            assert!(
                signature.split('|').any(|label| label == declaration_kind),
                "{language}: {signature}"
            );
            assert_eq!(
                super::extract_control_flow_signature(&signature, table),
                "N:return_statement",
                "{language}",
            );
        }
    }

    #[test]
    fn ast_multiset_similarity_known_answers() {
        let table = brokk_bifrost_jvm::java::structural::JAVA_KIND_TABLE;
        // Independent bag arithmetic: broad intersection/union, control
        // intersection/union, then round((2 * broad + control) / 3).
        for (left, right, broad, control, refined) in [
            (
                "N:block|N:if_statement",
                "N:block|N:while_statement",
                33,
                0,
                22,
            ),
            (
                "N:block|N:if_statement",
                "N:block|N:if_statement|N:while_statement",
                67,
                50,
                61,
            ),
            (
                "N:block|N:if_statement|N:if_statement",
                "N:block|N:if_statement",
                67,
                50,
                61,
            ),
            ("N:block|N:if_statement", "N:block", 50, -1, 50),
            ("N:block|ID", "N:block|NUM", 33, -1, 33),
            ("N:block|ID|ID", "N:block|ID", 67, -1, 67),
        ] {
            assert_eq!(
                super::compute_ast_label_multiset_similarity_percent(left, right),
                broad
            );
            assert_eq!(
                super::compute_ast_control_flow_similarity_percent(left, right, table),
                control
            );
            assert_eq!(
                super::compute_ast_refinement_similarity_percent(left, right, table),
                refined
            );
            for threshold in [refined, refined + 1] {
                let weights = weights(1, threshold, 1, 1, threshold);
                let mut first = candidate("same.java", "alpha", &["A"], weights);
                let mut second = candidate("same.java", "beta", &["A"], weights);
                first.data.ast_signature = left.to_string();
                second.data.ast_signature = right.to_string();
                let file = first.data.unit.source().clone();
                let findings = super::detect_structural_clone_smells(
                    &[file],
                    vec![second, first],
                    weights,
                    super::refine_clone_similarity_with_ast,
                );
                let scores: Vec<_> = findings.iter().map(|finding| finding.score).collect();
                assert_eq!(
                    scores,
                    if threshold == refined {
                        vec![refined]
                    } else {
                        vec![]
                    }
                );
                if let Some(finding) = findings.first() {
                    assert_eq!(finding.enclosing_fq_name.as_str(), "alpha");
                    assert_eq!(finding.peer_enclosing_fq_name.as_str(), "beta");
                }
            }
        }
    }

    #[test]
    fn shingle_detector_agrees_with_token_tuple_sets() {
        use std::collections::HashSet;
        // Enumerate all streams of length <= 3, plus final-window and
        // repetition cases. The oracle stores token tuples, never hashes.
        let mut streams = vec![Vec::new()];
        for length in 1..=3 {
            for mut number in 0..3usize.pow(length) {
                streams.push(
                    (0..length)
                        .map(|_| {
                            let token = ["A", "B", "C"][number % 3];
                            number /= 3;
                            token
                        })
                        .collect(),
                );
            }
        }
        streams.extend([
            vec!["A", "A", "A", "A"],
            vec!["A", "B", "B", "C"],
            vec!["C", "A", "B", "C"],
        ]);
        for width in 1..=3 {
            for left in &streams {
                for right in &streams {
                    let tuples = |tokens: &[&str]| -> HashSet<Vec<String>> {
                        tokens
                            .windows(width)
                            .map(|window| window.iter().map(|s| s.to_string()).collect())
                            .collect()
                    };
                    let left_set = tuples(left);
                    let right_set = tuples(right);
                    let overlap = left_set.intersection(&right_set).count();
                    let union = left_set.union(&right_set).count();
                    let score = if union == 0 {
                        0
                    } else {
                        (100.0 * overlap as f64 / union as f64).round() as i32
                    };
                    for minimum in [0, 1, overlap, overlap + 1] {
                        for threshold in [0, 33, 100] {
                            let weights = weights(0, threshold, width as i32, minimum as i32, 0);
                            let first = candidate("same.cpp", "alpha", left, weights);
                            let second = candidate("same.cpp", "beta", right, weights);
                            let file = first.data.unit.source().clone();
                            let findings = super::detect_structural_clone_smells(
                                &[file],
                                vec![second, first],
                                weights,
                                super::refine_clone_similarity_with_ast,
                            );
                            let expected = union != 0 && overlap >= minimum && score >= threshold;
                            assert_eq!(
                                findings.len(),
                                usize::from(expected),
                                "left={left:?}, right={right:?}, width={width}, minShared={minimum}, threshold={threshold}"
                            );
                            if let Some(finding) = findings.first() {
                                assert_eq!(finding.score, score);
                                assert_eq!(finding.enclosing_fq_name.as_str(), "alpha");
                                assert_eq!(finding.peer_enclosing_fq_name.as_str(), "beta");
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn candidate_token_minimum_is_inclusive() {
        let unit = candidate("same.cpp", "alpha", &["A", "B"], weights(0, 100, 1, 1, 0))
            .data
            .unit;
        for minimum in [1, 2, 3] {
            let weights = weights(minimum, 100, 1, 1, 0);
            let data = super::build_clone_candidate_data(
                Some("nonempty source".to_string()),
                &unit,
                weights,
                |_, _| Some((vec!["A".into(), "B".into()], String::new())),
            );
            assert_eq!(data.is_some(), minimum <= 2);
            if let Some(data) = data {
                let second = candidate("same.cpp", "beta", &["A", "B"], weights);
                let findings = super::detect_structural_clone_smells(
                    std::slice::from_ref(unit.source()),
                    vec![CloneCandidateProfile::create(data, weights), second],
                    weights,
                    super::refine_clone_similarity_with_ast,
                );
                assert_eq!(findings.len(), 1);
                assert_eq!(findings[0].normalized_token_count, 2);
            }
        }
    }

    #[test]
    fn rounded_similarity_threshold_is_preserved_by_candidate_prefilter() {
        let left: Vec<String> = (0..699).map(|n| n.to_string()).collect();
        let right: Vec<String> = (0..1000).map(|n| n.to_string()).collect();
        let weights = weights(1, 70, 1, 1, 70);
        let left_shingles = hashed_strings(&left, weights.shingle_size);
        let right_shingles = hashed_strings(&right, weights.shingle_size);

        assert_eq!(
            70,
            compute_clone_token_similarity(&left_shingles, &right_shingles, weights,)
        );
        assert!(can_reach_clone_similarity(
            left_shingles.size(),
            right_shingles.size(),
            weights,
        ));
    }

    #[test]
    fn candidate_prefilter_rejects_pairs_whose_rounded_upper_bound_misses_threshold() {
        let weights = weights(1, 71, 1, 1, 70);

        assert!(!can_reach_clone_similarity(699, 1000, weights));
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

    #[test]
    #[hardwon("#1421: shingle index prunes workspace peers that cannot meet the overlap budget")]
    fn shingle_index_excludes_workspace_peers_without_enough_overlap() {
        let weights = weights(1, 70, 1, 3, 70);
        let mut candidates = vec![candidate(
            "probe.cpp",
            "probe",
            &["A", "B", "C", "D"],
            weights,
        )];
        candidates.extend((0..1_000).map(|index| {
            candidate(
                "workspace.cpp",
                &format!("unrelated_{index}"),
                &[
                    &format!("X{index}"),
                    &format!("Y{index}"),
                    &format!("Z{index}"),
                ],
                weights,
            )
        }));
        candidates.push(candidate(
            "workspace.cpp",
            "clone",
            &["A", "B", "C", "D"],
            weights,
        ));
        let candidate_index = CloneCandidateIndex::new(&candidates);
        let mut peers = candidate_index.peer_indices(&candidates[0], &candidates, weights);
        peers.sort_unstable();

        assert_eq!(peers, vec![0, 1_001]);
    }

    fn hashed(tokens: Vec<&str>, shingle_size: i32) -> LongShingles {
        let tokens = tokens.into_iter().map(str::to_string).collect::<Vec<_>>();
        hashed_shingle_array(&tokens, shingle_size)
    }

    fn hashed_strings(tokens: &[String], shingle_size: i32) -> LongShingles {
        hashed_shingle_array(tokens, shingle_size)
    }

    fn candidate(
        path: &str,
        name: &str,
        tokens: &[&str],
        weights: CloneSmellWeights,
    ) -> CloneCandidateProfile {
        let project_root =
            std::env::current_dir().expect("test working directory must be available");
        let file = ProjectFile::new(project_root, path);
        let data = CloneCandidateData {
            unit: CodeUnit::new(file, CodeUnitType::Function, "", name),
            normalized_tokens: tokens.iter().map(|token| (*token).to_string()).collect(),
            ast_signature: String::new(),
            excerpt: String::new(),
        };
        CloneCandidateProfile::create(data, weights)
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
