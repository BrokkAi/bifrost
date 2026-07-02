//! Candidate pruning for structural queries.
//!
//! The planner's contract: it may only *skip* files that provably cannot
//! contain a match, and only based on **positive** constraints. Negative
//! constraints (`not_kind`, `not_has`, `not_inside`) are verifier-only — they
//! never contribute to pruning, because "file lacks X" makes a negation
//! *easier* to satisfy, not harder.
//!
//! v1 pruning is literal-anchor based: every exact `name` predicate (and
//! every `kwargs` keyword) reachable through conjunctive positive pattern
//! positions matches a span of the file's own source text, so a file whose
//! source does not contain one of those strings cannot match. Anchors are
//! checked against the analyzer's retained in-memory source before any parse
//! happens. This subsumes declaration-index pruning: a declared name is a
//! source span like any other.

use super::query::{AstQuery, Pattern, StringPredicate};
use crate::analyzer::structural::Role;

/// Literal strings that must all appear in a file's source for the query's
/// root (plus `inside`) constraints to possibly match. Empty when the query
/// has no exact-name anchors (regex/text/kind-only queries prune nothing).
pub(crate) fn collect_anchors(query: &AstQuery) -> Vec<String> {
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

pub(crate) fn source_may_match(source: &str, anchors: &[String]) -> bool {
    anchors.iter().all(|anchor| source.contains(anchor))
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
    use serde_json::json;

    fn anchors_of(query: serde_json::Value) -> Vec<String> {
        collect_anchors(&AstQuery::from_json(&query).expect("query should parse"))
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
    fn source_prefilter_requires_every_anchor() {
        let anchors = vec!["eval".to_string(), "shell".to_string()];
        assert!(source_may_match("eval(x, shell=True)", &anchors));
        assert!(!source_may_match("eval(x)", &anchors));
        assert!(source_may_match("anything", &[]));
    }
}
