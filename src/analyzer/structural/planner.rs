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
    positive_source_anchors: Vec<String>,
    structural_access: StructuralAccessRequirements,
    features: QueryFeatures,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StructuralPostingTerm {
    Kinds(Vec<super::NormalizedKind>),
    ExactName(String),
    RoleName { role: Role, name: String },
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
        if let Some(StringPredicate::Exact(name)) = &query.root.name {
            terms.push(StructuralPostingTerm::ExactName(name.clone()));
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
    if let Some(StringPredicate::Exact(name)) = &pattern.name {
        terms.push(StructuralPostingTerm::RoleName {
            role,
            name: name.clone(),
        });
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
    required_anchors: &'a [String],
}

impl SourceCandidateIndex<'_> {
    pub(crate) fn requires_source(&self) -> bool {
        !self.required_anchors.is_empty()
    }

    pub(crate) fn required_anchors(&self) -> &[String] {
        self.required_anchors
    }

    pub(crate) fn may_match(&self, source: &str) -> bool {
        self.required_anchors
            .iter()
            .all(|anchor| source.contains(anchor))
    }
}

/// Literal strings that must all appear in a file's source for the query's
/// root (plus `inside`) constraints to possibly match. Empty when the query
/// has no exact-name anchors (regex/text/kind-only queries prune nothing).
fn collect_positive_source_anchors(query: &CodeQuerySeed) -> Vec<String> {
    let mut anchors = Vec::new();
    collect_pattern_anchors(&query.root, &mut anchors);
    if let Some(inside) = &query.inside {
        collect_pattern_anchors(inside, &mut anchors);
    }
    // query.not_inside intentionally ignored: verifier-only.
    anchors.sort_unstable();
    anchors.dedup();
    anchors
}

/// Recurses over pattern nesting (bounded by the query the caller wrote, same
/// as the matcher). Only conjunctive positive positions contribute; `not_has`
/// is skipped.
fn collect_pattern_anchors(pattern: &Pattern, out: &mut Vec<String>) {
    if let Some(StringPredicate::Exact(name)) = &pattern.name {
        out.push(name.clone());
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
        out.push(keyword.clone());
        collect_pattern_anchors(sub, out);
    }
    // pattern.not_has intentionally ignored: verifier-only.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::structural::CodeQuery;
    use serde_json::json;

    fn anchors_of(query: serde_json::Value) -> Vec<String> {
        let query = CodeQuery::from_json(&query).expect("query should parse");
        QueryPlan::for_query(query.seed().unwrap()).positive_source_anchors
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
        assert_eq!(anchors, vec!["Controller", "run", "shell", "subprocess"]);
    }

    #[test]
    fn negation_and_regex_contribute_no_anchors() {
        let anchors = anchors_of(json!({
            "match": {
                "kind": "call",
                "name": { "regex": "^eval$" },
                "not_has": { "name": "Sandbox" }
            },
            "not_inside": { "kind": "class", "name": "Sandbox" }
        }));
        assert!(
            anchors.is_empty(),
            "negations/regexes must never prune: {anchors:?}"
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
            "match": { "kind": "call", "callee": { "name": { "regex": "^eval$" } } }
        }))
        .expect("query should parse");
        let unanchored = QueryPlan::for_query(unanchored_query.seed().unwrap());
        assert!(!unanchored.has_source_anchors());
    }

    #[test]
    fn source_prefilter_requires_every_anchor() {
        let anchors = vec!["eval".to_string(), "shell".to_string()];
        let plan = QueryPlan {
            positive_source_anchors: anchors,
            structural_access: StructuralAccessRequirements::default(),
            features: QueryFeatures::default(),
        };
        let index = plan.build_source_index();
        assert!(index.may_match("eval(x, shell=True)"));
        assert!(!index.may_match("eval(x)"));

        let plan = QueryPlan {
            positive_source_anchors: Vec::new(),
            structural_access: StructuralAccessRequirements::default(),
            features: QueryFeatures::default(),
        };
        assert!(plan.build_source_index().may_match("anything"));
    }
}
