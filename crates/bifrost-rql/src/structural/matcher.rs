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
use crate::analyzer::Range;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_rql::{CodeQuerySeed, Pattern};
use std::cell::Cell;

/// Recorded callable-signature facts for one declaration range, looked up from
/// persisted `SignatureMetadata` rather than from FileFacts.
pub(crate) struct CallableSignatureFacts {
    pub modifiers_recorded: bool,
    pub visibility: Option<DeclaredVisibility>,
    pub parameter_types: Option<Vec<String>>,
}

/// Workspace-backed lookup from a callable fact's exact range to its recorded
/// signature metadata. Nested `:has` patterns use the same oracle as the root.
pub(crate) trait CallableSignatureOracle {
    fn lookup(&self, range: Range) -> Option<CallableSignatureFacts>;
}

/// Flags set when a callable-signature predicate cannot be answered because
/// the adapter did not record modifiers or parameter types.
#[derive(Debug, Default)]
pub(crate) struct CallableSignatureIncomplete {
    pub visibility_unrecorded: Cell<bool>,
    pub parameter_types_unrecorded: Cell<bool>,
}

#[derive(Debug)]
pub(crate) struct CaptureBinding {
    pub name: String,
    pub span: Span,
    pub kind: Option<NormalizedKind>,
    /// Facts-arena id of the captured node, when the capture bound a fact
    /// rather than a role target's raw span. Together with the file's
    /// `ContentIdentity` this is the AST identity occurrence rows join on.
    pub node: Option<u32>,
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
#[cfg(test)]
pub(crate) fn match_query(
    query: &CodeQuerySeed,
    facts: &FileFacts,
    max_matches: usize,
) -> Vec<FactMatch> {
    let mut examined = 0u64;
    let incomplete = CallableSignatureIncomplete::default();
    match_query_candidates(
        query,
        facts,
        0..u32::try_from(facts.nodes().len()).expect("FileFacts node ids fit in u32"),
        max_matches,
        &mut examined,
        None,
        &incomplete,
    )
}

/// Evaluate a sound candidate slice in source order. Candidate selection is
/// never authoritative: this invokes the exact same pattern and containment
/// verifier as the scan path.
/// `examined_facts` accumulates every fact node and role edge the verifier
/// evaluates, including containment ancestor probes and `has`/`not_has`
/// subtree walks; posting-based callers charge execution budget from it.
pub(crate) fn match_query_candidates(
    query: &CodeQuerySeed,
    facts: &FileFacts,
    candidates: impl IntoIterator<Item = u32>,
    max_matches: usize,
    examined_facts: &mut u64,
    oracle: Option<&dyn CallableSignatureOracle>,
    incomplete: &CallableSignatureIncomplete,
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
        if !eval_pattern(
            &query.root,
            facts,
            id,
            &mut captures,
            examined_facts,
            oracle,
            incomplete,
        ) {
            continue;
        }
        if let Some(inside) = &query.inside
            && !eval_containment(
                inside,
                facts,
                id,
                &mut captures,
                examined_facts,
                oracle,
                incomplete,
            )
        {
            continue;
        }
        if let Some(inside_decl) = &query.inside_decl
            && !eval_declaration_containment(
                inside_decl,
                facts,
                id,
                &mut captures,
                examined_facts,
                oracle,
                incomplete,
            )
        {
            continue;
        }
        if let Some(not_inside) = &query.not_inside {
            // Verifier-only negation: captures inside a failed positive probe
            // must not leak into the result.
            let mut discarded = Vec::new();
            if eval_containment(
                not_inside,
                facts,
                id,
                &mut discarded,
                examined_facts,
                oracle,
                incomplete,
            ) {
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
    examined_facts: &mut u64,
    oracle: Option<&dyn CallableSignatureOracle>,
    incomplete: &CallableSignatureIncomplete,
) -> bool {
    let mut current = facts.node(node).parent;
    while let Some(ancestor) = current {
        if eval_pattern(
            pattern,
            facts,
            ancestor,
            captures,
            examined_facts,
            oracle,
            incomplete,
        ) {
            return true;
        }
        current = facts.node(ancestor).parent;
    }
    false
}

/// Does some strict ancestor of `node` match `pattern` before a non-matching
/// callable declaration boundary? A matching callable ancestor itself remains
/// visible, so direct contents of a function or lambda can select that owner.
fn eval_declaration_containment(
    pattern: &Pattern,
    facts: &FileFacts,
    node: u32,
    captures: &mut Vec<CaptureBinding>,
    examined_facts: &mut u64,
    oracle: Option<&dyn CallableSignatureOracle>,
    incomplete: &CallableSignatureIncomplete,
) -> bool {
    let mut current = facts.node(node).parent;
    while let Some(ancestor) = current {
        if eval_pattern(
            pattern,
            facts,
            ancestor,
            captures,
            examined_facts,
            oracle,
            incomplete,
        ) {
            return true;
        }
        if facts
            .node(ancestor)
            .kind
            .satisfies(NormalizedKind::Callable)
        {
            return false;
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
    examined_facts: &mut u64,
    oracle: Option<&dyn CallableSignatureOracle>,
    incomplete: &CallableSignatureIncomplete,
) -> bool {
    let checkpoint = captures.len();
    if eval_pattern_inner_with_name(
        pattern,
        facts,
        node,
        None,
        captures,
        examined_facts,
        oracle,
        incomplete,
    ) {
        true
    } else {
        captures.truncate(checkpoint);
        false
    }
}

#[allow(clippy::too_many_arguments)]
fn eval_pattern_inner_with_name(
    pattern: &Pattern,
    facts: &FileFacts,
    node: u32,
    name_override: Option<Span>,
    captures: &mut Vec<CaptureBinding>,
    examined_facts: &mut u64,
    oracle: Option<&dyn CallableSignatureOracle>,
    incomplete: &CallableSignatureIncomplete,
) -> bool {
    *examined_facts = examined_facts.saturating_add(1);
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
    if let Some(expected) = pattern.boolean_value
        && fact.boolean_value != Some(expected)
    {
        return false;
    }
    let roles = facts.roles(node);

    // Arity constrains the matched fact's positional-child count, read
    // straight from the already-extracted role edges -- no re-parse. On a
    // call that is the `Arg` edges; on a collection literal the `Element`
    // edges (#2647). No fact carries both families, so the union is
    // unambiguous, and a fact with neither has arity zero.
    if let Some(arity) = &pattern.arity {
        let positional = roles
            .iter()
            .filter(|target| matches!(target.role, Role::Arg | Role::Element))
            .count();
        if !arity.matches(positional) {
            return false;
        }
    }

    if !eval_callable_signature(pattern, facts, node, oracle, incomplete) {
        return false;
    }

    // Single-target roles: the first (typically only) edge of that role must
    // match the sub-pattern; a role constraint on a fact without that edge
    // fails.
    for &role in Role::single_target_roles() {
        if let Some(sub_pattern) = pattern.single_role_pattern(role) {
            let matched = roles
                .iter()
                .filter(|target| target.role == role)
                .any(|target| {
                    eval_target(
                        sub_pattern,
                        facts,
                        target,
                        captures,
                        examined_facts,
                        oracle,
                        incomplete,
                    )
                });
            if !matched {
                return false;
            }
        }
    }

    // List roles: the listed patterns must match distinct edges of that role
    // in source order, but not necessarily contiguously (greedy subsequence).
    // Arguments, collection elements, JSX attributes, and JSX children are all
    // spelled in order and a decorator list reads the same way, so one rule
    // serves every list role. Reading the roles from the registry rather than
    // naming them is what makes a new list role enforced on arrival: `args`
    // and `decorators` were once hand-written arms and `elements`,
    // `attributes`, and `children` were silently unverified (#2647).
    for &role in Role::list_target_roles() {
        let sub_patterns = pattern.list_role_patterns(role);
        if sub_patterns.is_empty() {
            continue;
        }
        let targets: Vec<&RoleTarget> = roles.iter().filter(|target| target.role == role).collect();
        let mut cursor = 0usize;
        for sub_pattern in sub_patterns {
            let mut advanced = None;
            for (offset, target) in targets[cursor..].iter().enumerate() {
                if eval_target(
                    sub_pattern,
                    facts,
                    target,
                    captures,
                    examined_facts,
                    oracle,
                    incomplete,
                ) {
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
                    && eval_target(
                        value_pattern,
                        facts,
                        target,
                        captures,
                        examined_facts,
                        oracle,
                        incomplete,
                    )
            });
        if !matched {
            return false;
        }
    }

    if let Some(has) = &pattern.has
        && !some_descendant_matches(
            has,
            facts,
            node,
            captures,
            examined_facts,
            oracle,
            incomplete,
        )
    {
        return false;
    }
    if let Some(not_has) = &pattern.not_has {
        let mut discarded = Vec::new();
        if some_descendant_matches(
            not_has,
            facts,
            node,
            &mut discarded,
            examined_facts,
            oracle,
            incomplete,
        ) {
            return false;
        }
    }

    if let Some(label) = &pattern.capture
        && !add_capture(
            label,
            fact.span(),
            Some(fact.kind),
            Some(node),
            facts,
            captures,
        )
    {
        return false;
    }
    true
}

fn eval_callable_signature(
    pattern: &Pattern,
    facts: &FileFacts,
    node: u32,
    oracle: Option<&dyn CallableSignatureOracle>,
    incomplete: &CallableSignatureIncomplete,
) -> bool {
    let constrains_visibility = !pattern.visibility.is_empty();
    let constrains_parameter_type = pattern.parameter_type.is_some();
    if !constrains_visibility && !constrains_parameter_type {
        return true;
    }
    let fact = facts.node(node);
    if !fact.kind.satisfies(NormalizedKind::Callable) {
        return false;
    }
    let Some(oracle) = oracle else {
        if constrains_visibility {
            incomplete.visibility_unrecorded.set(true);
        }
        if constrains_parameter_type {
            incomplete.parameter_types_unrecorded.set(true);
        }
        return false;
    };
    let span = fact.span();
    let Some(recorded) = oracle.lookup(Range {
        start_byte: span.start_byte,
        end_byte: span.end_byte,
        start_line: fact.range.start_line,
        end_line: fact.range.end_line,
    }) else {
        // No indexed declaration sits exactly on this callable fact, so nothing
        // recorded its signature. A lambda is the common case: it satisfies
        // Callable but has no declaration row. That is an unanswered constraint,
        // not a clean miss.
        if constrains_visibility {
            incomplete.visibility_unrecorded.set(true);
        }
        if constrains_parameter_type {
            incomplete.parameter_types_unrecorded.set(true);
        }
        return false;
    };
    if constrains_visibility {
        if !recorded.modifiers_recorded {
            incomplete.visibility_unrecorded.set(true);
            return false;
        }
        let Some(visibility) = recorded.visibility else {
            incomplete.visibility_unrecorded.set(true);
            return false;
        };
        if !pattern.visibility.contains(&visibility) {
            return false;
        }
    }
    if let Some(predicate) = &pattern.parameter_type {
        let Some(types) = recorded.parameter_types.as_deref() else {
            incomplete.parameter_types_unrecorded.set(true);
            return false;
        };
        if !types.iter().any(|spelling| predicate.matches(spelling)) {
            return false;
        }
    }
    true
}

fn some_descendant_matches(
    pattern: &Pattern,
    facts: &FileFacts,
    node: u32,
    captures: &mut Vec<CaptureBinding>,
    examined_facts: &mut u64,
    oracle: Option<&dyn CallableSignatureOracle>,
    incomplete: &CallableSignatureIncomplete,
) -> bool {
    // Facts are stored in pre-order with subtree intervals, so this walks
    // only actual descendants and returns immediately for leaves.
    for candidate in (node + 1)..facts.subtree_end(node) {
        if eval_pattern(
            pattern,
            facts,
            candidate,
            captures,
            examined_facts,
            oracle,
            incomplete,
        ) {
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
    examined_facts: &mut u64,
    oracle: Option<&dyn CallableSignatureOracle>,
    incomplete: &CallableSignatureIncomplete,
) -> bool {
    let checkpoint = captures.len();
    let matched = match target.node {
        Some(node) => eval_pattern_inner_with_name(
            pattern,
            facts,
            node,
            target.name,
            captures,
            examined_facts,
            oracle,
            incomplete,
        ),
        None => eval_span_only(pattern, facts, target, captures, examined_facts),
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
    examined_facts: &mut u64,
) -> bool {
    *examined_facts = examined_facts.saturating_add(1);
    // An un-normalized target has no fact kind: positive kind constraints
    // fail, while `not_kind` is vacuously satisfied (the target provably is
    // none of the normalized kinds).
    if !pattern.kinds.is_empty()
        || pattern.boolean_value.is_some()
        || pattern.arity.is_some()
        || !pattern.visibility.is_empty()
        || pattern.parameter_type.is_some()
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
        && !add_capture(label, target.span, None, None, facts, captures)
    {
        return false;
    }
    true
}

fn add_capture(
    label: &str,
    span: Span,
    kind: Option<NormalizedKind>,
    node: Option<u32>,
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
        node,
    });
    true
}
