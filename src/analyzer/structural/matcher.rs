//! Pattern evaluation over one file's normalized facts.
//!
//! The matcher never sees JSON or grammar node names: patterns are the typed
//! IR from `query`, facts the arena from `facts`. Negative constraints
//! (`not_has`, `not_inside`) are evaluated here and only here — planners must
//! never prune on them.
//!
//! Recursion note: `eval_pattern` recurses over *pattern* nesting, which is
//! bounded by the query the caller wrote (and by serde_json's 128-level parse
//! limit), not by source file shape — the fact arena itself is walked with
//! loops and parent links.

use super::facts::{FileFacts, RoleTarget, Span};
use super::kinds::{NormalizedKind, Role};
use super::query::{CodeQuerySeed, Pattern};

#[derive(Debug)]
pub(crate) struct CaptureBinding {
    pub name: String,
    pub span: Span,
    pub kind: Option<NormalizedKind>,
}

/// One match of the query's root pattern: the matched fact plus every capture
/// collected along the accepted pattern path, in pattern order.
#[derive(Debug)]
pub(crate) struct FactMatch {
    pub node: u32,
    pub captures: Vec<CaptureBinding>,
}

/// Evaluate `query` against one file's facts, in source order, stopping after
/// `max_matches` hits. Callers pass one more than they can return so global
/// truncation stays detectable without collecting unbounded per-file results.
pub(crate) fn match_query(
    query: &CodeQuerySeed,
    facts: &FileFacts,
    max_matches: usize,
) -> Vec<FactMatch> {
    match_query_candidates(
        query,
        facts,
        0..u32::try_from(facts.nodes().len()).expect("FileFacts node ids fit in u32"),
        max_matches,
    )
}

/// Evaluate a sound candidate slice in source order. Candidate selection is
/// never authoritative: this invokes the exact same pattern and containment
/// verifier as the scan path.
pub(crate) fn match_query_candidates(
    query: &CodeQuerySeed,
    facts: &FileFacts,
    candidates: impl IntoIterator<Item = u32>,
    max_matches: usize,
) -> Vec<FactMatch> {
    let mut matches = Vec::new();
    let mut previous = None;
    for id in candidates {
        debug_assert!((id as usize) < facts.nodes().len());
        debug_assert!(previous.is_none_or(|previous| previous < id));
        previous = Some(id);
        if matches.len() >= max_matches {
            break;
        }
        let mut captures = Vec::new();
        if !eval_pattern(&query.root, facts, id, &mut captures) {
            continue;
        }
        if let Some(inside) = &query.inside
            && !eval_containment(inside, facts, id, &mut captures)
        {
            continue;
        }
        if let Some(not_inside) = &query.not_inside {
            // Verifier-only negation: captures inside a failed positive probe
            // must not leak into the result.
            let mut discarded = Vec::new();
            if eval_containment(not_inside, facts, id, &mut discarded) {
                continue;
            }
        }
        matches.push(FactMatch { node: id, captures });
    }
    matches
}

/// Does some strict ancestor of `node` match `pattern`? The nearest matching
/// ancestor wins (its captures are kept).
fn eval_containment(
    pattern: &Pattern,
    facts: &FileFacts,
    node: u32,
    captures: &mut Vec<CaptureBinding>,
) -> bool {
    let mut current = facts.node(node).parent;
    while let Some(ancestor) = current {
        if eval_pattern(pattern, facts, ancestor, captures) {
            return true;
        }
        current = facts.node(ancestor).parent;
    }
    false
}

/// Evaluate `pattern` against the fact `node`. On success the pattern's
/// captures (including nested ones) are appended to `captures`; on failure
/// `captures` is left exactly as it was.
fn eval_pattern(
    pattern: &Pattern,
    facts: &FileFacts,
    node: u32,
    captures: &mut Vec<CaptureBinding>,
) -> bool {
    let checkpoint = captures.len();
    if eval_pattern_inner(pattern, facts, node, captures) {
        true
    } else {
        captures.truncate(checkpoint);
        false
    }
}

fn eval_pattern_inner(
    pattern: &Pattern,
    facts: &FileFacts,
    node: u32,
    captures: &mut Vec<CaptureBinding>,
) -> bool {
    eval_pattern_inner_with_name(pattern, facts, node, None, captures)
}

fn eval_pattern_inner_with_name(
    pattern: &Pattern,
    facts: &FileFacts,
    node: u32,
    name_override: Option<Span>,
    captures: &mut Vec<CaptureBinding>,
) -> bool {
    let fact = facts.node(node);
    if !pattern.kinds.is_empty() && !pattern.kinds.iter().any(|&kind| fact.kind.satisfies(kind)) {
        return false;
    }
    if pattern
        .not_kinds
        .iter()
        .any(|&kind| fact.kind.satisfies(kind))
    {
        return false;
    }
    if let Some(predicate) = &pattern.name {
        let Some(name) = name_override.or(fact.name) else {
            return false;
        };
        if !predicate.matches(name.text(facts.source())) {
            return false;
        }
    }
    if let Some(predicate) = &pattern.text
        && !predicate.matches(fact.span().text(facts.source()))
    {
        return false;
    }
    let roles = facts.roles(node);

    // Single-target roles: the first (typically only) edge of that role must
    // match the sub-pattern; a role constraint on a fact without that edge
    // fails.
    for &role in Role::single_target_roles() {
        if let Some(sub_pattern) = pattern.single_role_pattern(role) {
            let matched = roles
                .iter()
                .filter(|target| target.role == role)
                .any(|target| eval_target(sub_pattern, facts, target, captures));
            if !matched {
                return false;
            }
        }
    }

    // Positional args: the listed patterns must match distinct arguments in
    // order, but not necessarily contiguously (greedy subsequence).
    if !pattern.args.is_empty() {
        let targets: Vec<&RoleTarget> = roles
            .iter()
            .filter(|target| target.role == Role::Arg)
            .collect();
        let mut cursor = 0usize;
        for arg_pattern in &pattern.args {
            let mut advanced = None;
            for (offset, target) in targets[cursor..].iter().enumerate() {
                if eval_target(arg_pattern, facts, target, captures) {
                    advanced = Some(cursor + offset + 1);
                    break;
                }
            }
            match advanced {
                Some(next) => cursor = next,
                None => return false,
            }
        }
    }

    // Keyword args match by keyword name.
    for (keyword, value_pattern) in &pattern.kwargs {
        let matched = roles
            .iter()
            .filter(|target| target.role == Role::Kwarg)
            .any(|target| {
                target
                    .keyword
                    .is_some_and(|span| span.text(facts.source()) == keyword)
                    && eval_target(value_pattern, facts, target, captures)
            });
        if !matched {
            return false;
        }
    }

    // Each decorator pattern must match some decorator edge.
    for decorator_pattern in &pattern.decorators {
        let matched = roles
            .iter()
            .filter(|target| target.role == Role::Decorator)
            .any(|target| eval_target(decorator_pattern, facts, target, captures));
        if !matched {
            return false;
        }
    }

    if let Some(has) = &pattern.has
        && !some_descendant_matches(has, facts, node, captures)
    {
        return false;
    }
    if let Some(not_has) = &pattern.not_has {
        let mut discarded = Vec::new();
        if some_descendant_matches(not_has, facts, node, &mut discarded) {
            return false;
        }
    }

    if let Some(label) = &pattern.capture
        && !add_capture(label, fact.span(), Some(fact.kind), facts, captures)
    {
        return false;
    }
    true
}

fn some_descendant_matches(
    pattern: &Pattern,
    facts: &FileFacts,
    node: u32,
    captures: &mut Vec<CaptureBinding>,
) -> bool {
    // Facts are stored in pre-order with subtree intervals, so this walks
    // only actual descendants and returns immediately for leaves.
    for candidate in (node + 1)..facts.subtree_end(node) {
        if eval_pattern(pattern, facts, candidate, captures) {
            return true;
        }
    }
    false
}

/// Evaluate a sub-pattern against a role target. When the target is itself a
/// normalized fact, full pattern semantics apply to that fact while name
/// predicates prefer the role-derived name when present; otherwise only
/// name/text/capture can be satisfied from the edge's raw span and derived
/// name (kind or nested constraints fail).
fn eval_target(
    pattern: &Pattern,
    facts: &FileFacts,
    target: &RoleTarget,
    captures: &mut Vec<CaptureBinding>,
) -> bool {
    let checkpoint = captures.len();
    let matched = match target.node {
        Some(node) => eval_pattern_inner_with_name(pattern, facts, node, target.name, captures),
        None => eval_span_only(pattern, facts, target, captures),
    };
    if !matched {
        captures.truncate(checkpoint);
    }
    matched
}

fn eval_span_only(
    pattern: &Pattern,
    facts: &FileFacts,
    target: &RoleTarget,
    captures: &mut Vec<CaptureBinding>,
) -> bool {
    // An un-normalized target has no fact kind: positive kind constraints
    // fail, while `not_kind` is vacuously satisfied (the target provably is
    // none of the normalized kinds).
    if !pattern.kinds.is_empty()
        || pattern.has.is_some()
        || pattern.not_has.is_some()
        || !pattern.args.is_empty()
        || !pattern.kwargs.is_empty()
        || pattern.has_role_constraints()
    {
        return false;
    }
    if let Some(predicate) = &pattern.name {
        let Some(name) = target.name else {
            return false;
        };
        if !predicate.matches(name.text(facts.source())) {
            return false;
        }
    }
    if let Some(predicate) = &pattern.text
        && !predicate.matches(target.span.text(facts.source()))
    {
        return false;
    }
    if let Some(label) = &pattern.capture
        && !add_capture(label, target.span, None, facts, captures)
    {
        return false;
    }
    true
}

fn add_capture(
    label: &str,
    span: Span,
    kind: Option<NormalizedKind>,
    facts: &FileFacts,
    captures: &mut Vec<CaptureBinding>,
) -> bool {
    if captures
        .iter()
        .filter(|capture| capture.name == label)
        .any(|capture| capture.span.text(facts.source()) != span.text(facts.source()))
    {
        return false;
    }
    captures.push(CaptureBinding {
        name: label.to_string(),
        span,
        kind,
    });
    true
}
