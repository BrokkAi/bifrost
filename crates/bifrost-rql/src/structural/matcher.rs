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
use crate::analyzer::semantic::ContentIdentity;
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

/// Query-local lookup from a Python variable read to the exact normalized RHS
/// node of its unique direct function-local assignment guaranteed before this
/// read: scope-unconditional or an earlier statement in the identical immediate
/// suite. An empty slice is a proven absence of such a value; `None` means the
/// relation is incomplete.
pub(crate) trait LocalValueOracle {
    fn lookup(&self, range: Range) -> Option<&[u32]>;
}

/// Workspace-backed semantic owner lookup for declaration containment that
/// cannot be represented by one file's lexical fact parents. Rust impl blocks
/// use this path because the impl's type declaration is a separate syntax
/// tree node and can live in another file.
pub(crate) trait DeclarationOwnerOracle {
    fn owner_matches(
        &self,
        declaration: Range,
        pattern: &Pattern,
        captures: &mut Vec<CaptureBinding>,
        examined_facts: &mut u64,
        incomplete: &CallableSignatureIncomplete,
    ) -> bool;
}

/// Flags set when a callable-signature predicate cannot be answered because
/// the adapter did not record modifiers or parameter types.
#[derive(Debug, Default)]
pub(crate) struct CallableSignatureIncomplete {
    pub visibility_unrecorded: Cell<bool>,
    pub parameter_types_unrecorded: Cell<bool>,
    pub duplicate_dictionary_key_unrecorded: Cell<bool>,
    pub string_literal_value_unrecorded: Cell<bool>,
    pub local_value_unresolved: Cell<bool>,
}

#[derive(Debug, Clone)]
pub(crate) struct CaptureBinding {
    pub name: String,
    pub span: Span,
    pub text: String,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub kind: Option<NormalizedKind>,
    pub source_identity: ContentIdentity,
    /// Facts-arena id of the captured node, when the capture bound a fact
    /// rather than a role target's raw span. Together with the file's
    /// `ContentIdentity` this is the AST identity occurrence rows join on.
    pub node: Option<u32>,
}

/// One match of the query's root pattern: the matched fact plus every capture
/// collected along the accepted pattern path, in pattern order.
#[derive(Debug, Clone)]
pub(crate) struct FactMatch {
    pub node: u32,
    pub captures: Vec<CaptureBinding>,
    /// A closed language relation may select a source span nested inside the
    /// normalized root fact. The root still owns matching, identity, and
    /// relational semantics; this optional span is only its reported source
    /// location.
    pub reported_range: Option<Range>,
}

impl FactMatch {
    pub(crate) fn display_span(&self, facts: &FileFacts) -> Span {
        self.reported_range.map_or_else(
            || facts.node(self.node).span(),
            |range| Span {
                start_byte: range.start_byte,
                end_byte: range.end_byte,
            },
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct CommentBlockMember {
    node: u32,
    span: Span,
}

#[derive(Debug, Default)]
struct CommentBlockRelation {
    members: Vec<CommentBlockMember>,
}

impl CommentBlockRelation {
    fn for_file(facts: &FileFacts, examined_facts: &mut u64) -> Self {
        let mut comments = facts
            .nodes()
            .iter()
            .enumerate()
            .filter(|(_, fact)| fact.kind == NormalizedKind::Comment)
            .map(|(node, fact)| {
                (
                    u32::try_from(node).expect("FileFacts node ids fit in u32"),
                    fact.span(),
                )
            })
            .collect::<Vec<_>>();
        comments.sort_unstable_by_key(|&(node, span)| (span.start_byte, span.end_byte, node));
        *examined_facts =
            examined_facts.saturating_add(u64::try_from(comments.len()).unwrap_or(u64::MAX));
        if comments.is_empty() {
            return Self::default();
        }

        let mut relation = Self {
            members: Vec::with_capacity(comments.len()),
        };
        let mut group_start = 0;
        for index in 1..=comments.len() {
            let connected = index < comments.len()
                && comment_tokens_are_consecutive(
                    facts.source(),
                    comments[index - 1].1,
                    comments[index].1,
                );
            if connected {
                continue;
            }
            let block_span = Span {
                start_byte: comments[group_start].1.start_byte,
                end_byte: comments[index - 1].1.end_byte,
            };
            relation
                .members
                .extend(
                    comments[group_start..index]
                        .iter()
                        .map(|&(node, _)| CommentBlockMember {
                            node,
                            span: block_span,
                        }),
                );
            group_start = index;
        }
        relation.members.sort_unstable_by_key(|member| member.node);
        relation
    }

    fn span_for(&self, node: u32) -> Option<Span> {
        self.members
            .binary_search_by_key(&node, |member| member.node)
            .ok()
            .map(|index| self.members[index].span)
    }
}

pub(super) fn comment_tokens_are_consecutive(source: &str, previous: Span, next: Span) -> bool {
    assert!(previous.end_byte <= next.start_byte);
    let gap = source
        .get(previous.end_byte..next.start_byte)
        .expect("comment spans must be UTF-8 aligned source ranges");
    gap.chars().all(char::is_whitespace) && gap.bytes().filter(|byte| *byte == b'\n').count() <= 1
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
        None,
        None,
        &incomplete,
    )
}

struct PatternEvalContext<'a> {
    examined_facts: &'a mut u64,
    oracle: Option<&'a dyn CallableSignatureOracle>,
    local_value_oracle: Option<&'a dyn LocalValueOracle>,
    incomplete: &'a CallableSignatureIncomplete,
    comment_blocks: Option<&'a CommentBlockRelation>,
}

pub(crate) struct PatternEvalInputs<'a> {
    pub(crate) examined_facts: &'a mut u64,
    pub(crate) oracle: Option<&'a dyn CallableSignatureOracle>,
    pub(crate) local_value_oracle: Option<&'a dyn LocalValueOracle>,
    pub(crate) incomplete: &'a CallableSignatureIncomplete,
}

/// Evaluate a sound candidate slice in source order. Candidate selection is
/// never authoritative: this invokes the exact same pattern and containment
/// verifier as the scan path.
/// `examined_facts` accumulates every fact node and role edge the verifier
/// evaluates, including containment ancestor probes and `has`/`not_has`
/// subtree walks; posting-based callers charge execution budget from it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn match_query_candidates(
    query: &CodeQuerySeed,
    facts: &FileFacts,
    candidates: impl IntoIterator<Item = u32>,
    max_matches: usize,
    examined_facts: &mut u64,
    oracle: Option<&dyn CallableSignatureOracle>,
    local_value_oracle: Option<&dyn LocalValueOracle>,
    owner_oracle: Option<&dyn DeclarationOwnerOracle>,
    incomplete: &CallableSignatureIncomplete,
) -> Vec<FactMatch> {
    let mut matches = Vec::new();
    let comment_blocks = query
        .constrains_comment_block_text()
        .then(|| CommentBlockRelation::for_file(facts, examined_facts));
    let mut context = PatternEvalContext {
        examined_facts,
        oracle,
        local_value_oracle,
        incomplete,
        comment_blocks: comment_blocks.as_ref(),
    };
    let mut previous = None;
    for id in candidates {
        debug_assert!((id as usize) < facts.nodes().len());
        debug_assert!(previous.is_none_or(|previous| previous < id));
        previous = Some(id);
        if matches.len() >= max_matches {
            break;
        }
        let mut captures = Vec::new();
        if !eval_pattern(&query.root, facts, id, &mut captures, &mut context) {
            continue;
        }
        if let Some(inside) = &query.inside
            && !eval_containment(inside, facts, id, &mut captures, &mut context)
        {
            continue;
        }
        if let Some(inside_decl) = &query.inside_decl
            && !eval_declaration_containment(
                inside_decl,
                facts,
                id,
                &mut captures,
                owner_oracle,
                &mut context,
            )
        {
            continue;
        }
        if let Some(not_inside) = &query.not_inside {
            // Verifier-only negation: captures inside a failed positive probe
            // must not leak into the result.
            let mut discarded = Vec::new();
            if eval_containment(not_inside, facts, id, &mut discarded, &mut context) {
                continue;
            }
        }
        matches.push(FactMatch {
            node: id,
            captures,
            reported_range: None,
        });
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
    context: &mut PatternEvalContext<'_>,
) -> bool {
    let mut current = facts.node(node).parent;
    while let Some(ancestor) = current {
        if eval_pattern(pattern, facts, ancestor, captures, context) {
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
    owner_oracle: Option<&dyn DeclarationOwnerOracle>,
    context: &mut PatternEvalContext<'_>,
) -> bool {
    let mut current = facts.node(node).parent;
    while let Some(ancestor) = current {
        if eval_pattern(pattern, facts, ancestor, captures, context) {
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
    let fact = facts.node(node);
    owner_oracle.is_some_and(|oracle| {
        oracle.owner_matches(
            fact.range,
            pattern,
            captures,
            context.examined_facts,
            context.incomplete,
        )
    })
}

/// Evaluate one declaration pattern against a fact selected by a workspace
/// owner oracle. This deliberately reuses the exact verifier used for ordinary
/// lexical containment, including roles, descendants, signature predicates,
/// and captures.
pub(crate) fn match_owner_pattern(
    pattern: &Pattern,
    facts: &FileFacts,
    node: u32,
    captures: &mut Vec<CaptureBinding>,
    inputs: PatternEvalInputs<'_>,
) -> bool {
    let comment_blocks = pattern
        .constrains_comment_block_text()
        .then(|| CommentBlockRelation::for_file(facts, inputs.examined_facts));
    let mut context = PatternEvalContext {
        examined_facts: inputs.examined_facts,
        oracle: inputs.oracle,
        local_value_oracle: inputs.local_value_oracle,
        incomplete: inputs.incomplete,
        comment_blocks: comment_blocks.as_ref(),
    };
    eval_pattern(pattern, facts, node, captures, &mut context)
}

/// Evaluate `pattern` against the fact `node`. On success the pattern's
/// captures (including nested ones) are appended to `captures`; on failure
/// `captures` is left exactly as it was.
fn eval_pattern(
    pattern: &Pattern,
    facts: &FileFacts,
    node: u32,
    captures: &mut Vec<CaptureBinding>,
    context: &mut PatternEvalContext<'_>,
) -> bool {
    eval_with_capture_rollback(captures, |captures| {
        eval_pattern_inner_with_name(pattern, facts, node, None, captures, context)
    })
}

fn eval_with_capture_rollback(
    captures: &mut Vec<CaptureBinding>,
    evaluate: impl FnOnce(&mut Vec<CaptureBinding>) -> bool,
) -> bool {
    let checkpoint = captures.len();
    if !evaluate(captures) {
        captures.truncate(checkpoint);
        return false;
    }
    true
}

fn eval_pattern_inner_with_name(
    pattern: &Pattern,
    facts: &FileFacts,
    node: u32,
    name_override: Option<Span>,
    captures: &mut Vec<CaptureBinding>,
    context: &mut PatternEvalContext<'_>,
) -> bool {
    *context.examined_facts = context.examined_facts.saturating_add(1);
    let fact = facts.node(node);
    // Root modifier predicates are supplied by the source-backed seed
    // relation. Nested modifier predicates have no role edge and therefore
    // cannot be evaluated by this normalized fact matcher.
    if pattern.modifier.is_some() {
        return false;
    }
    if !pattern.kinds.is_empty()
        && !pattern
            .kinds
            .iter()
            .any(|&kind| fact_matches_query_kind(facts, node, kind))
    {
        return false;
    }
    if pattern
        .not_kinds
        .iter()
        .any(|&kind| fact_matches_query_kind(facts, node, kind))
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
    if let Some(value) = &pattern.string_value {
        if fact.kind != NormalizedKind::StringLiteral {
            context.incomplete.string_literal_value_unrecorded.set(true);
            return false;
        }
        let Some(actual) = fact.string_value.as_deref() else {
            context.incomplete.string_literal_value_unrecorded.set(true);
            return false;
        };
        if !value.matches(actual) {
            return false;
        }
    }
    if let Some(predicate) = &pattern.text
        && !predicate.matches(fact.span().text(facts.source()))
    {
        return false;
    }
    if let Some(predicate) = &pattern.comment_block_text {
        if fact.kind != NormalizedKind::Comment {
            return false;
        }
        let Some(block_span) = context
            .comment_blocks
            .and_then(|relation| relation.span_for(node))
        else {
            return false;
        };
        if !predicate.matches(block_span.text(facts.source())) {
            return false;
        }
    }
    if let Some(expected) = pattern.boolean_value
        && fact.boolean_value != Some(expected)
    {
        return false;
    }
    if let Some(expected) = pattern.is_async
        && fact.is_async != Some(expected)
    {
        return false;
    }
    if let Some(expected) = pattern.parenthesized
        && fact.parenthesized != Some(expected)
    {
        return false;
    }
    if let Some(expected) = &pattern.integer_value
        && fact
            .integer_literal_value
            .as_ref()
            .filter(|value| !value.negative)
            .and_then(|value| value.decimal.as_ref())
            != Some(expected)
    {
        return false;
    }
    if let Some(expected) = pattern.duplicate_key {
        if fact.kind != NormalizedKind::ObjectProperty {
            return false;
        }
        if let Some(parent) = fact.parent {
            for role in facts.roles(parent) {
                if role.role != Role::Element {
                    continue;
                }
                let Some(sibling) = role.node else {
                    continue;
                };
                if facts.node(sibling).kind == NormalizedKind::ObjectProperty
                    && facts.node(sibling).duplicate_key.is_none()
                {
                    context
                        .incomplete
                        .duplicate_dictionary_key_unrecorded
                        .set(true);
                }
            }
        }
        let Some(actual) = fact.duplicate_key else {
            context
                .incomplete
                .duplicate_dictionary_key_unrecorded
                .set(true);
            return false;
        };
        if actual != expected {
            return false;
        }
    }
    if pattern.integer_has_any_bits.is_some()
        || pattern.integer_has_all_bits.is_some()
        || pattern.integer_has_no_bits.is_some()
    {
        let Some(value) = fact.integer_literal_value.as_ref() else {
            return false;
        };
        let low_bits = value.low_bits;
        if pattern
            .integer_has_any_bits
            .is_some_and(|mask| low_bits & mask == 0)
            || pattern
                .integer_has_all_bits
                .is_some_and(|mask| low_bits & mask != mask)
            || pattern
                .integer_has_no_bits
                .is_some_and(|mask| low_bits & mask != 0)
        {
            return false;
        }
    }
    if (pattern.assignment_target_kind.is_some()
        || pattern.assignment_value_kind.is_some()
        || pattern.assignment_target_unstarred_count.is_some()
        || pattern.assignment_value_unstarred_count.is_some()
        || pattern.assignment_target_starred.is_some()
        || pattern.assignment_value_starred.is_some()
        || pattern.assignment_unstarred_count_mismatch.is_some())
        && fact.assignment_shape.is_none()
    {
        return false;
    }
    if let Some(shape) = fact.assignment_shape
        && (pattern
            .assignment_target_kind
            .is_some_and(|expected| expected != shape.target_kind)
            || pattern
                .assignment_value_kind
                .is_some_and(|expected| expected != shape.value_kind)
            || pattern
                .assignment_target_unstarred_count
                .is_some_and(|expected| expected != shape.target_unstarred_count)
            || pattern
                .assignment_value_unstarred_count
                .is_some_and(|expected| expected != shape.value_unstarred_count)
            || pattern
                .assignment_target_starred
                .is_some_and(|expected| expected != shape.target_starred)
            || pattern
                .assignment_value_starred
                .is_some_and(|expected| expected != shape.value_starred)
            || pattern
                .assignment_unstarred_count_mismatch
                .is_some_and(|expected| {
                    expected != (shape.target_unstarred_count != shape.value_unstarred_count)
                }))
    {
        return false;
    }

    if let Some(negated) = &pattern.not {
        let checkpoint = captures.len();
        let matched =
            eval_pattern_inner_with_name(negated, facts, node, name_override, captures, context);
        captures.truncate(checkpoint);
        if matched {
            return false;
        }
    }
    for sub_pattern in &pattern.all {
        if !eval_same_node_pattern(sub_pattern, facts, node, name_override, captures, context) {
            return false;
        }
    }
    if !pattern.any.is_empty()
        && !pattern.any.iter().any(|sub_pattern| {
            eval_same_node_pattern(sub_pattern, facts, node, name_override, captures, context)
        })
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

    if !eval_callable_signature(pattern, facts, node, context.oracle, context.incomplete) {
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
                        IndexedRoleTarget {
                            target,
                            index: None,
                        },
                        captures,
                        context,
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
                    IndexedRoleTarget {
                        target,
                        index: Some(cursor + offset),
                    },
                    captures,
                    context,
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
                        IndexedRoleTarget {
                            target,
                            index: None,
                        },
                        captures,
                        context,
                    )
            });
        if !matched {
            return false;
        }
    }

    if let Some(has) = &pattern.has
        && !some_descendant_matches(has, facts, node, captures, context)
    {
        return false;
    }
    if let Some(not_has) = &pattern.not_has {
        let mut discarded = Vec::new();
        if some_descendant_matches(not_has, facts, node, &mut discarded, context) {
            return false;
        }
    }

    if let Some(value_pattern) = &pattern.local_value {
        if fact.kind != NormalizedKind::Identifier {
            return false;
        }
        let Some(oracle) = context.local_value_oracle else {
            context.incomplete.local_value_unresolved.set(true);
            return false;
        };
        let Some(targets) = oracle.lookup(fact.range) else {
            context.incomplete.local_value_unresolved.set(true);
            return false;
        };
        let matched = targets.iter().any(|target| {
            let mut value_captures = Vec::new();
            eval_pattern(value_pattern, facts, *target, &mut value_captures, context)
        });
        if !matched {
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

fn fact_matches_query_kind(facts: &FileFacts, node_id: u32, query_kind: NormalizedKind) -> bool {
    let fact = facts.node(node_id);
    if fact.kind == NormalizedKind::ConcurrentSpawn
        && query_kind == NormalizedKind::Call
        && (node_id + 1..fact.subtree_end).any(|candidate_id| {
            let candidate = facts.node(candidate_id);
            candidate.parent == Some(node_id) && candidate.kind == NormalizedKind::Call
        })
    {
        // A Go `go_statement` wraps its actual call expression. Select the
        // child as the call site; the wrapper remains selectable as
        // `concurrent_spawn`.
        return false;
    }
    fact.kind.satisfies(query_kind)
}

#[allow(clippy::too_many_arguments)]
fn eval_same_node_pattern(
    pattern: &Pattern,
    facts: &FileFacts,
    node: u32,
    name_override: Option<Span>,
    captures: &mut Vec<CaptureBinding>,
    context: &mut PatternEvalContext<'_>,
) -> bool {
    let checkpoint = captures.len();
    let matched =
        eval_pattern_inner_with_name(pattern, facts, node, name_override, captures, context);
    if !matched {
        captures.truncate(checkpoint);
    }
    matched
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
        // `unknown` is the adapter's own statement that it read the
        // declaration and could not classify it, so a constraint on a concrete
        // label is unanswered rather than refuted: `unknown` is never equal to
        // `public`. Only a query that names `unknown` is answered by it.
        // Without this, an adapter that started recording modifiers (JS/TS,
        // Rust, and now Python) would turn every such constraint into a silent
        // clean miss.
        if visibility == DeclaredVisibility::Unknown
            && !pattern.visibility.contains(&DeclaredVisibility::Unknown)
        {
            incomplete.visibility_unrecorded.set(true);
            return false;
        }
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
    context: &mut PatternEvalContext<'_>,
) -> bool {
    // Facts are stored in pre-order with subtree intervals, so this walks
    // only actual descendants and returns immediately for leaves.
    for candidate in (node + 1)..facts.subtree_end(node) {
        if eval_pattern(pattern, facts, candidate, captures, context) {
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
struct IndexedRoleTarget<'a> {
    target: &'a RoleTarget,
    index: Option<usize>,
}

fn eval_target(
    pattern: &Pattern,
    facts: &FileFacts,
    indexed: IndexedRoleTarget<'_>,
    captures: &mut Vec<CaptureBinding>,
    context: &mut PatternEvalContext<'_>,
) -> bool {
    let IndexedRoleTarget { target, index } = indexed;
    eval_with_capture_rollback(captures, |captures| {
        pattern.index.is_none_or(|expected| {
            index.is_some_and(|index| u32::try_from(index).ok() == Some(expected))
        }) && match target.node {
            Some(node) => {
                eval_pattern_inner_with_name(pattern, facts, node, target.name, captures, context)
            }
            None => eval_span_only(pattern, facts, target, captures, context),
        }
    })
}

fn eval_span_only(
    pattern: &Pattern,
    facts: &FileFacts,
    target: &RoleTarget,
    captures: &mut Vec<CaptureBinding>,
    context: &mut PatternEvalContext<'_>,
) -> bool {
    *context.examined_facts = context.examined_facts.saturating_add(1);
    // An un-normalized target has no fact kind: positive kind constraints
    // fail, while `not_kind` is vacuously satisfied (the target provably is
    // none of the normalized kinds).
    if pattern.string_value.is_some() {
        context.incomplete.string_literal_value_unrecorded.set(true);
        return false;
    }
    if !pattern.kinds.is_empty()
        || pattern.boolean_value.is_some()
        || pattern.string_value.is_some()
        || pattern.language_rule.is_some()
        || pattern.body_state.is_some()
        || pattern.body_owner.is_some()
        || pattern.is_async.is_some()
        || pattern.parenthesized.is_some()
        || pattern.integer_value.is_some()
        || pattern.duplicate_key.is_some()
        || pattern.integer_has_any_bits.is_some()
        || pattern.integer_has_all_bits.is_some()
        || pattern.integer_has_no_bits.is_some()
        || pattern.assignment_target_kind.is_some()
        || pattern.assignment_value_kind.is_some()
        || pattern.assignment_target_unstarred_count.is_some()
        || pattern.assignment_value_unstarred_count.is_some()
        || pattern.assignment_target_starred.is_some()
        || pattern.assignment_value_starred.is_some()
        || pattern.assignment_unstarred_count_mismatch.is_some()
        || pattern.arity.is_some()
        || !pattern.visibility.is_empty()
        || pattern.parameter_type.is_some()
        || pattern.comment_block_text.is_some()
        || pattern.has.is_some()
        || pattern.local_value.is_some()
        || pattern.not_has.is_some()
        || pattern.not.is_some()
        || !pattern.all.is_empty()
        || !pattern.any.is_empty()
        || !pattern.args.is_empty()
        || !pattern.kwargs.is_empty()
        || pattern.has_role_constraints()
    {
        return false;
    }
    if !pattern.name_text_matches(
        target.name.map(|name| name.text(facts.source())),
        target.span.text(facts.source()),
    ) {
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
    let text = span.text(facts.source());
    if captures
        .iter()
        .filter(|capture| capture.name == label)
        .any(|capture| capture.text != text)
    {
        return false;
    }
    let (start_line, start_column) = facts.line_column_of_byte(span.start_byte);
    let (end_line, end_column) = facts.line_column_of_byte(span.end_byte);
    captures.push(CaptureBinding {
        name: label.to_string(),
        span,
        text: text.to_string(),
        start_line,
        start_column,
        end_line,
        end_column,
        kind,
        source_identity: facts.source_identity(),
        node,
    });
    true
}
