//! Candidate pruning for structural queries.
//!
//! The planner's contract: it may only *skip* files that provably cannot
//! contain a match, and only based on **positive** constraints. Negative
//! constraints (`not_kind`, `not_has`, `not_inside`) are verifier-only — they
//! never contribute to pruning, because "file lacks X" makes a negation
//! *easier* to satisfy, not harder.
//!
//! Seed-query pruning is literal-anchor based: every exact `name` predicate (and
//! every `kwargs` keyword) reachable through conjunctive positive pattern
//! positions matches a span of the file's own source text, so a file whose
//! source does not contain one of those strings cannot match. Anchors are
//! checked against the analyzer's retained in-memory source before any parse
//! happens. This subsumes declaration-index pruning: a declared name is a
//! source span like any other.

use super::capabilities::QueryFeatures;
use super::query::{CodeQuerySeed, Pattern, StringPredicate};
use crate::analyzer::structural::Role;

/// Language-independent execution plan derived from a parsed query.
///
/// The plan is intentionally conservative: it only records facts that are safe
/// to use before verification, while keeping the original [`CodeQuery`] as the
/// semantic authority for matching.
#[derive(Debug, Clone)]
pub(crate) struct QueryPlan {
    positive_source_anchors: Vec<SourceAnchorGroup>,
    structural_access: StructuralAccessRequirements,
    features: QueryFeatures,
}

/// One conjunctive anchor requirement: a file whose source contains none of
/// the alternatives cannot match. A single-element group is the classic exact
/// name anchor; multi-element groups come from anchored literal alternation
/// regexes such as `^(read|read_to_string)$`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SourceAnchorGroup {
    alternatives: Vec<String>,
}

impl SourceAnchorGroup {
    pub(crate) fn new(alternatives: Vec<String>) -> Self {
        debug_assert!(!alternatives.is_empty());
        Self { alternatives }
    }

    pub(crate) fn alternatives(&self) -> &[String] {
        &self.alternatives
    }

    pub(crate) fn may_match_source(&self, source: &str) -> bool {
        self.alternatives
            .iter()
            .any(|alternative| source.contains(alternative))
    }
}

impl QueryPlan {
    pub(crate) fn for_query(query: &CodeQuerySeed) -> Self {
        Self {
            positive_source_anchors: collect_positive_source_anchors(query),
            structural_access: StructuralAccessRequirements::for_query(query),
            features: QueryFeatures::for_query(query),
        }
    }

    pub(crate) fn features(&self) -> &QueryFeatures {
        &self.features
    }

    pub(crate) fn has_source_anchors(&self) -> bool {
        !self.positive_source_anchors.is_empty()
    }

    pub(crate) fn build_source_index(&self) -> SourceCandidateIndex<'_> {
        SourceCandidateIndex {
            required_anchors: &self.positive_source_anchors,
        }
    }

    pub(crate) fn structural_access(&self) -> &StructuralAccessRequirements {
        &self.structural_access
    }
}

/// Names are always non-empty, sorted, deduplicated alternative sets: the
/// seed fact's attribute must equal one of them, so the index unions the
/// per-name postings for one term and intersects across terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StructuralPostingTerm {
    Kinds(Vec<super::NormalizedKind>),
    ExactName(Vec<String>),
    RoleName { role: Role, names: Vec<String> },
    KwargKeyword(String),
}

impl StructuralPostingTerm {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Kinds(_) => "kind",
            Self::ExactName(_) => "name",
            Self::RoleName { .. } => "role_name",
            Self::KwargKeyword(_) => "kwarg",
        }
    }
}

/// Representation-neutral positive constraints available to a physical
/// structural index. The matcher still verifies every selected fact.
#[derive(Debug, Clone, Default)]
pub(crate) struct StructuralAccessRequirements {
    terms: Vec<StructuralPostingTerm>,
}

impl StructuralAccessRequirements {
    fn for_query(query: &CodeQuerySeed) -> Self {
        let mut terms = Vec::new();
        if !query.root.kinds.is_empty() {
            terms.push(StructuralPostingTerm::Kinds(query.root.kinds.clone()));
        }
        if let Some(names) = query
            .root
            .name
            .as_ref()
            .and_then(StringPredicate::exact_alternatives)
        {
            terms.push(StructuralPostingTerm::ExactName(names));
        }
        for &role in Role::single_target_roles() {
            if let Some(pattern) = query.root.single_role_pattern(role) {
                push_role_name_term(&mut terms, role, pattern);
            }
        }
        for &role in Role::list_target_roles() {
            for pattern in query.root.list_role_patterns(role) {
                push_role_name_term(&mut terms, role, pattern);
            }
        }
        for (keyword, pattern) in &query.root.kwargs {
            terms.push(StructuralPostingTerm::KwargKeyword(keyword.clone()));
            push_role_name_term(&mut terms, Role::Kwarg, pattern);
        }
        let mut unique = Vec::with_capacity(terms.len());
        for term in terms {
            if !unique.contains(&term) {
                unique.push(term);
            }
        }
        Self { terms: unique }
    }

    pub(crate) fn terms(&self) -> &[StructuralPostingTerm] {
        &self.terms
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(terms: Vec<StructuralPostingTerm>) -> Self {
        Self { terms }
    }
}

/// Storage-independent description of the access path selected for one
/// provider scope. Concrete posting layouts remain private to the index; the
/// planner, profile, and benchmark consume only these cardinalities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StructuralAccessPathKind {
    ScanOnly,
    Posting,
}

impl StructuralAccessPathKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::ScanOnly => "scan_only",
            Self::Posting => "posting",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StructuralPostingEstimate {
    pub(crate) label: &'static str,
    pub(crate) candidate_facts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StructuralAccessPathEstimate {
    pub(crate) kind: StructuralAccessPathKind,
    pub(crate) provider_files: u64,
    pub(crate) scoped_files: u64,
    pub(crate) scoped_fact_nodes: u64,
    pub(crate) candidate_files: u64,
    pub(crate) candidate_facts: u64,
    pub(crate) selected_terms: Vec<StructuralPostingEstimate>,
    pub(crate) source_verification_required: bool,
    pub(crate) cache_ready_before_lookup: bool,
}

fn push_role_name_term(terms: &mut Vec<StructuralPostingTerm>, role: Role, pattern: &Pattern) {
    if !supports_exact_role_name_posting(role) {
        return;
    }
    if let Some(names) = pattern
        .name
        .as_ref()
        .and_then(StringPredicate::exact_alternatives)
    {
        terms.push(StructuralPostingTerm::RoleName { role, names });
    }
}

pub(crate) fn supports_exact_role_name_posting(role: Role) -> bool {
    matches!(role, Role::Callee | Role::Module)
}

/// Source-level candidate index for a single planned query.
///
/// The index uses only the query's required literal anchors and checks them against
/// each file's retained source text. Keeping this behind a named index boundary
/// lets richer candidate indexes replace the implementation without changing
/// search execution.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SourceCandidateIndex<'a> {
    required_anchors: &'a [SourceAnchorGroup],
}

impl SourceCandidateIndex<'_> {
    pub(crate) fn requires_source(&self) -> bool {
        !self.required_anchors.is_empty()
    }

    pub(crate) fn required_anchors(&self) -> &[SourceAnchorGroup] {
        self.required_anchors
    }

    pub(crate) fn may_match(&self, source: &str) -> bool {
        self.required_anchors
            .iter()
            .all(|group| group.may_match_source(source))
    }
}

/// Anchor groups that must each be satisfied (at least one alternative
/// present in the file's source) for the query's root (plus positive
/// containment) constraints to possibly match. Empty when the query has no
/// exact-name anchors (opaque-regex/text/kind-only queries prune nothing).
fn collect_positive_source_anchors(query: &CodeQuerySeed) -> Vec<SourceAnchorGroup> {
    let mut anchors = Vec::new();
    collect_pattern_anchors(&query.root, &mut anchors);
    if let Some(inside) = &query.inside {
        collect_pattern_anchors(inside, &mut anchors);
    }
    if let Some(inside_decl) = &query.inside_decl {
        collect_pattern_anchors(inside_decl, &mut anchors);
    }
    // query.not_inside intentionally ignored: verifier-only.
    anchors.sort_unstable();
    anchors.dedup();
    anchors
}

/// Recurses over pattern nesting (bounded by the query the caller wrote, same
/// as the matcher). Only conjunctive positive positions contribute; `not_has`
/// is skipped.
fn collect_pattern_anchors(pattern: &Pattern, out: &mut Vec<SourceAnchorGroup>) {
    if let Some(alternatives) = pattern
        .name
        .as_ref()
        .and_then(StringPredicate::exact_alternatives)
    {
        out.push(SourceAnchorGroup::new(alternatives));
    }
    for &role in Role::single_target_roles() {
        if let Some(sub) = pattern.single_role_pattern(role) {
            collect_pattern_anchors(sub, out);
        }
    }
    if let Some(sub) = &pattern.has {
        collect_pattern_anchors(sub, out);
    }
    for &role in Role::list_target_roles() {
        for sub in pattern.list_role_patterns(role) {
            collect_pattern_anchors(sub, out);
        }
    }
    for (keyword, sub) in &pattern.kwargs {
        // The keyword itself is spelled in source (`shell=True`).
        out.push(SourceAnchorGroup::new(vec![keyword.clone()]));
        collect_pattern_anchors(sub, out);
    }
    // pattern.not_has intentionally ignored: verifier-only.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::structural::CodeQuery;
    use serde_json::json;

    fn anchors_of(query: serde_json::Value) -> Vec<Vec<String>> {
        let query = CodeQuery::from_json(&query).expect("query should parse");
        QueryPlan::for_query(query.seed().unwrap())
            .positive_source_anchors
            .into_iter()
            .map(|group| group.alternatives)
            .collect()
    }

    fn group(alternatives: &[&str]) -> Vec<String> {
        alternatives
            .iter()
            .map(|alternative| alternative.to_string())
            .collect()
    }

    #[test]
    fn collects_conjunctive_positive_anchors() {
        let anchors = anchors_of(json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "subprocess" },
                "kwargs": { "shell": { "kind": "boolean_literal" } }
            },
            "inside": { "kind": "class", "name": "Controller" }
        }));
        assert_eq!(
            anchors,
            vec![
                group(&["Controller"]),
                group(&["run"]),
                group(&["shell"]),
                group(&["subprocess"]),
            ]
        );
    }

    #[test]
    fn declaration_bounded_containment_contributes_positive_anchors() {
        let anchors = anchors_of(json!({
            "schema_version": 1,
            "match": { "kind": "call", "name": "run" },
            "inside_decl": { "kind": "loop", "name": "retry" }
        }));
        assert_eq!(anchors, vec![group(&["retry"]), group(&["run"])]);
    }

    #[test]
    fn anchored_literal_alternation_regexes_contribute_anchor_groups() {
        let anchors = anchors_of(json!({
            "match": {
                "kind": "call",
                "callee": { "name": { "regex": "^(read|read_to_string)$" } }
            }
        }));
        assert_eq!(anchors, vec![group(&["read", "read_to_string"])]);

        let anchors = anchors_of(json!({
            "match": { "kind": "call", "name": { "regex": "^eval$" } }
        }));
        assert_eq!(anchors, vec![group(&["eval"])]);
    }

    #[test]
    fn negation_and_opaque_regexes_contribute_no_anchors() {
        let anchors = anchors_of(json!({
            "match": {
                "kind": "call",
                "name": { "regex": "^eval_[a-z]+$" },
                "not_has": { "name": "Sandbox" }
            },
            "not_inside": { "kind": "class", "name": "Sandbox" }
        }));
        assert!(
            anchors.is_empty(),
            "negations/opaque regexes must never prune: {anchors:?}"
        );
    }

    #[test]
    fn reports_whether_a_query_has_source_anchors() {
        let anchored_query = CodeQuery::from_json(&json!({
            "match": { "kind": "call", "callee": { "name": "eval" } }
        }))
        .expect("query should parse");
        let anchored = QueryPlan::for_query(anchored_query.seed().unwrap());
        assert!(anchored.has_source_anchors());

        let unanchored_query = CodeQuery::from_json(&json!({
            "match": { "kind": "call", "callee": { "name": { "regex": "eval" } } }
        }))
        .expect("query should parse");
        let unanchored = QueryPlan::for_query(unanchored_query.seed().unwrap());
        assert!(!unanchored.has_source_anchors());
    }

    #[test]
    fn alternation_regexes_contribute_posting_terms() {
        let query = CodeQuery::from_json(&json!({
            "match": {
                "kind": "call",
                "callee": { "name": { "regex": "^(sort|sort_by|sort_unstable)$" } }
            }
        }))
        .expect("query should parse");
        let plan = QueryPlan::for_query(query.seed().unwrap());
        assert!(
            plan.structural_access()
                .terms()
                .contains(&StructuralPostingTerm::RoleName {
                    role: Role::Callee,
                    names: vec![
                        "sort".to_string(),
                        "sort_by".to_string(),
                        "sort_unstable".to_string(),
                    ],
                }),
            "callee alternation should produce a role-name posting term: {:?}",
            plan.structural_access().terms()
        );
    }

    #[test]
    fn source_prefilter_requires_every_anchor_group() {
        let anchors = vec![
            SourceAnchorGroup::new(vec!["eval".to_string()]),
            SourceAnchorGroup::new(vec!["shell".to_string(), "spawn".to_string()]),
        ];
        let plan = QueryPlan {
            positive_source_anchors: anchors,
            structural_access: StructuralAccessRequirements::default(),
            features: QueryFeatures::default(),
        };
        let index = plan.build_source_index();
        assert!(index.may_match("eval(x, shell=True)"));
        assert!(index.may_match("eval(x, spawn=True)"));
        assert!(!index.may_match("eval(x)"));
        assert!(!index.may_match("shell(x)"));

        let plan = QueryPlan {
            positive_source_anchors: Vec::new(),
            structural_access: StructuralAccessRequirements::default(),
            features: QueryFeatures::default(),
        };
        assert!(plan.build_source_index().may_match("anything"));
    }
}
