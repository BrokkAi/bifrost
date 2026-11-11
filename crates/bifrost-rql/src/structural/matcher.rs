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
use crate::cancellation::CancellationToken;
use brokk_bifrost_core::analyzer::structural::facts::ArgumentMode;
use brokk_bifrost_core::analyzer::structural::kinds::RoleCoverage;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_rql::{CodeQuerySeed, Pattern};

/// The fact budget of [`match_query`], which runs outside any query execution.
#[cfg(any(test, feature = "test-support"))]
const MAX_PATTERN_EXAMINED_FACTS: u64 = 2_000_000;
pub(super) const MAX_RENDERED_CAPTURE_BYTES_PER_RESPONSE: usize = 16 * 1024 * 1024;
const MAX_EACH_CAPTURE_BYTES_PER_ROW: usize = 1024 * 1024;
/// Fixed charge per binding created under `each`, for its label and metadata,
/// added to the length of its copied text.
pub(super) const EACH_CAPTURE_BINDING_OVERHEAD_BYTES: usize = 64;
/// Bindings copied under `each`, so a test can see that an exhausted row
/// budget stops binding creation instead of only discarding the bindings.
#[cfg(test)]
pub(crate) static EACH_BINDINGS_BUILT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

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
    fn qualifying_type_matches(
        &self,
        _range: Range,
        _expected: &crate::query::InstantiatedType,
    ) -> Option<bool> {
        None
    }
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
    #[allow(clippy::too_many_arguments)]
    fn owner_matches(
        &self,
        declaration: Range,
        pattern: &Pattern,
        captures: &mut Vec<CaptureBinding>,
        examined_facts: &mut u64,
        incomplete: &CallableSignatureIncomplete,
        cancellation: Option<&CancellationToken>,
        max_examined_facts: u64,
    ) -> bool;
}

/// Resolution's answer for one selection whose call-ness depends on the
/// member it resolves to, such as Scala's parameterless `entry.getName`
/// (`LanguageKnowledge::resolution_decided_application`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectionApplication {
    /// The member resolves to a callable: the selection is a call site.
    Call,
    /// The member resolves to a non-callable: the selection is a field read.
    NotCall,
    /// Resolution did not decide, so neither answer is proven.
    Undecided,
}

/// One file's resolution-decided selections, keyed by `FieldAccess` fact id.
/// A fact absent from the map is not such a selection.
pub(crate) type SelectionApplications = crate::hash::HashMap<u32, SelectionApplication>;

/// Flags set when a callable-signature predicate cannot be answered because
/// the adapter did not record modifiers or parameter types.
#[derive(Debug)]
pub(crate) struct CountGap {
    pub owner: Range,
    pub role: Role,
    pub lower: usize,
    pub upper: Option<usize>,
    pub min: u32,
    pub max: Option<u32>,
    pub coverage: Option<RoleCoverage>,
}

#[derive(Debug, Default)]
pub(crate) struct CallableSignatureIncomplete {
    pub visibility_unrecorded: Cell<bool>,
    pub parameter_types_unrecorded: Cell<bool>,
    pub duplicate_dictionary_key_unrecorded: Cell<bool>,
    pub string_literal_value_unrecorded: Cell<bool>,
    pub local_value_unresolved: Cell<bool>,
    pub qualifying_type_unresolved: Cell<bool>,
    pub qualifying_type_sites: RefCell<Vec<FactMatch>>,
    pub role_target_unrecorded: Cell<bool>,
    /// An `each` subtree holds recovered syntax, so its answer is incomplete.
    pub each_incomplete: Cell<bool>,
    pub argument_mode_unrecorded: Cell<bool>,
    /// `each`, an argument-mode owner lookup or a descendant walk under
    /// `each` stopped at the fact budget or the per-row capture budget. The
    /// answer is incomplete for an execution budget, not for missing support.
    pub fact_budget_exhausted: Cell<bool>,
    pub role_coverage_incomplete: Cell<bool>,
    pub selection_application_undecided: Cell<bool>,
    /// A role whose absence needs certification was missing from a fact whose
    /// adapter does not certify it (`Role::absence_needs_certification`).
    pub role_absence_uncertified: Cell<bool>,
    /// The roles the language of the facts being matched certifies; the scan
    /// sets it for each provider it visits.
    pub certified_roles: Cell<&'static [Role]>,
    /// The roles behind `role_absence_uncertified`, for the diagnostic.
    pub uncertified_role_absences: RefCell<Vec<Role>>,
    pub role_coverage_gaps: RefCell<Vec<(Range, Role, Option<RoleCoverage>)>>,
    pub count_gaps: RefCell<Vec<CountGap>>,
    /// Set when `each` or `argument-mode` work observed cancellation. It is
    /// not an incompleteness flag: the caller abandons the plan instead of
    /// reporting a partial answer.
    pub cancelled: Cell<bool>,
}

impl CallableSignatureIncomplete {
    fn flags(&self) -> [&Cell<bool>; 13] {
        let Self {
            visibility_unrecorded,
            parameter_types_unrecorded,
            duplicate_dictionary_key_unrecorded,
            string_literal_value_unrecorded,
            local_value_unresolved,
            qualifying_type_unresolved,
            qualifying_type_sites: _,
            role_target_unrecorded,
            each_incomplete,
            argument_mode_unrecorded,
            fact_budget_exhausted,
            role_coverage_incomplete,
            selection_application_undecided,
            role_absence_uncertified,
            certified_roles: _,
            uncertified_role_absences: _,
            role_coverage_gaps: _,
            count_gaps: _,
            cancelled: _,
        } = self;
        [
            visibility_unrecorded,
            parameter_types_unrecorded,
            duplicate_dictionary_key_unrecorded,
            string_literal_value_unrecorded,
            local_value_unresolved,
            qualifying_type_unresolved,
            role_target_unrecorded,
            each_incomplete,
            argument_mode_unrecorded,
            fact_budget_exhausted,
            role_coverage_incomplete,
            selection_application_undecided,
            role_absence_uncertified,
        ]
    }

    // Unknown is not absence. Keep diagnostics sticky while withholding an
    // unproved positive from a negated predicate.
    fn negate(&self, evaluate: impl FnOnce() -> bool) -> bool {
        let flags = self.flags();
        // Isolate this probe so an earlier incomplete candidate cannot mask
        // the same missing capability on this candidate (or a nested not).
        let before = flags.map(|flag| flag.replace(false));
        let matched = evaluate();
        let unknown = flags.iter().any(|flag| flag.get());
        for (flag, previous) in flags.into_iter().zip(before) {
            flag.set(flag.get() || previous);
        }
        !matched && !unknown
    }

    /// Isolate only the additive qualifying predicate. Other capability and
    /// execution-budget diagnostics remain attributed to their original cause.
    fn qualifying_probe(&self, evaluate: impl FnOnce() -> bool) -> (bool, bool) {
        let previous = self.qualifying_type_unresolved.replace(false);
        let matched = evaluate();
        let unknown = self.qualifying_type_unresolved.replace(previous);
        (matched, unknown)
    }

    pub(crate) fn isolated(&self, evaluate: impl FnOnce() -> bool) -> (bool, bool) {
        let flags = self.flags();
        let before = flags.map(|flag| flag.replace(false));
        let role_gaps = self.role_coverage_gaps.borrow().len();
        let count_gaps = self.count_gaps.borrow().len();
        let uncertified = self.uncertified_role_absences.borrow().len();
        let matched = evaluate();
        let unknown = flags.iter().any(|flag| flag.get());
        for (flag, previous) in flags.into_iter().zip(before) {
            flag.set(previous);
        }
        self.role_coverage_gaps.borrow_mut().truncate(role_gaps);
        self.count_gaps.borrow_mut().truncate(count_gaps);
        self.uncertified_role_absences
            .borrow_mut()
            .truncate(uncertified);
        (matched, unknown)
    }
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
    pub captures: Arc<[CaptureBinding]>,
    /// A closed language relation may select a source span nested inside the
    /// normalized root fact. The root still owns matching, identity, and
    /// relational semantics; this optional span is only its reported source
    /// location.
    pub reported_range: Option<Range>,
    /// Set when the language relation that selected this match is a
    /// heuristic: the reason it may not hold. Never part of the match's
    /// identity.
    pub heuristic: Option<&'static str>,
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
#[cfg(any(test, feature = "test-support"))]
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
        None,
        &incomplete,
        &[ArgumentMode::Plain, ArgumentMode::Spread],
        None,
        MAX_PATTERN_EXAMINED_FACTS,
    )
}

/// The row's `each` capture charge. A rollback point restores both fields
/// together, so a discarded alternative neither keeps its bytes charged nor
/// leaves the budget marked exhausted for a later alternative.
#[derive(Clone, Copy, Default)]
struct EachCaptureBudget {
    bytes: usize,
    /// The charge reached the row cap: no more `each` descendants are tried.
    exhausted: bool,
}

struct PatternEvalContext<'a> {
    qualifying_type_requested: bool,
    examined_facts: &'a mut u64,
    oracle: Option<&'a dyn CallableSignatureOracle>,
    selection_applications: Option<&'a SelectionApplications>,
    local_value_oracle: Option<&'a dyn LocalValueOracle>,
    incomplete: &'a CallableSignatureIncomplete,
    comment_blocks: Option<&'a CommentBlockRelation>,
    recorded_argument_modes: &'a [ArgumentMode],
    each_budget: EachCaptureBudget,
    /// Captures the per-row budget refused so far. No rollback restores it,
    /// so an `each` walk can tell that a failed descendant met the cap even
    /// after the descendant's own rollback cleared `each_budget.exhausted`.
    capture_refusals: u64,
    /// The labels each `each` pattern exports, computed once per matcher call
    /// from the pattern alone and keyed by its address, which is stable while
    /// the query is borrowed.
    each_exports: crate::hash::HashMap<*const Pattern, Rc<std::collections::HashSet<String>>>,
    /// Nesting depth of `each` patterns being evaluated; bindings are charged
    /// to `each_budget` only when it is nonzero.
    each_depth: usize,
    cancellation: Option<&'a CancellationToken>,
    max_examined_facts: u64,
}

/// `each` and `argument-mode` work polls cancellation once per this many units.
const CANCELLATION_POLL_INTERVAL: u64 = 256;

/// An `args` or `kwargs` sub-pattern that found no argument can still be
/// asking for a passing mode the adapter never records, even when the role has
/// no edge at all (PHP `f(...$a)` emits none). The absence then proves nothing.
fn flag_unrecorded_argument_modes(sub_pattern: &Pattern, context: &PatternEvalContext<'_>) {
    let mut stack = vec![sub_pattern];
    while let Some(pattern) = stack.pop() {
        if pattern
            .argument_modes
            .iter()
            .any(|mode| !context.recorded_argument_modes.contains(mode))
        {
            context.incomplete.argument_mode_unrecorded.set(true);
            return;
        }
        stack.extend(pattern.nested_patterns());
    }
}

impl PatternEvalContext<'_> {
    /// Poll the token every `CANCELLATION_POLL_INTERVAL` units of new work and
    /// remember a cancellation so the candidate loop and the caller see it.
    fn cancelled_at(&self, work: u64) -> bool {
        if self.incomplete.cancelled.get() {
            return true;
        }
        if work.is_multiple_of(CANCELLATION_POLL_INTERVAL)
            && self
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
        {
            self.incomplete.cancelled.set(true);
            return true;
        }
        false
    }
}

pub(crate) struct PatternEvalInputs<'a> {
    pub(crate) examined_facts: &'a mut u64,
    pub(crate) oracle: Option<&'a dyn CallableSignatureOracle>,
    pub(crate) selection_applications: Option<&'a SelectionApplications>,
    pub(crate) local_value_oracle: Option<&'a dyn LocalValueOracle>,
    pub(crate) incomplete: &'a CallableSignatureIncomplete,
    pub(crate) cancellation: Option<&'a CancellationToken>,
    pub(crate) max_examined_facts: u64,
    pub(crate) recorded_argument_modes: &'a [ArgumentMode],
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
    selection_applications: Option<&SelectionApplications>,
    local_value_oracle: Option<&dyn LocalValueOracle>,
    owner_oracle: Option<&dyn DeclarationOwnerOracle>,
    incomplete: &CallableSignatureIncomplete,
    recorded_argument_modes: &[ArgumentMode],
    cancellation: Option<&CancellationToken>,
    max_examined_facts: u64,
) -> Vec<FactMatch> {
    let mut matches = Vec::new();
    let comment_blocks = query
        .constrains_comment_block_text()
        .then(|| CommentBlockRelation::for_file(facts, examined_facts));
    let mut context = PatternEvalContext {
        qualifying_type_requested: seed_constrains_qualifying_type(query),
        examined_facts,
        oracle,
        selection_applications,
        local_value_oracle,
        incomplete,
        comment_blocks: comment_blocks.as_ref(),
        recorded_argument_modes,
        each_budget: EachCaptureBudget::default(),
        capture_refusals: 0,
        each_exports: crate::hash::HashMap::default(),
        each_depth: 0,
        cancellation,
        max_examined_facts,
    };
    let mut previous = None;
    for id in candidates {
        // Only `each` and `argument-mode` work polls the token, so ordinary
        // matching consumes the same cancellation checks it always did.
        if context.incomplete.cancelled.get() {
            break;
        }
        debug_assert!((id as usize) < facts.nodes().len());
        debug_assert!(previous.is_none_or(|previous| previous < id));
        previous = Some(id);
        if matches.len() >= max_matches {
            break;
        }
        context.incomplete.qualifying_type_unresolved.set(false);
        let mut captures = Vec::new();
        context.each_budget = EachCaptureBudget::default();
        let probe = context
            .qualifying_type_requested
            .then_some(context.incomplete);
        let (matched, mut unknown) = probe_candidate_constraint(probe, || {
            eval_pattern(&query.root, facts, id, &mut captures, &mut context)
        });
        if !matched {
            continue;
        }
        if let Some(inside) = &query.inside {
            let (matched, undecided) = probe_candidate_constraint(probe, || {
                eval_containment(inside, facts, id, &mut captures, &mut context)
            });
            if !matched {
                continue;
            }
            unknown |= undecided;
        }
        if let Some(inside_decl) = &query.inside_decl {
            let (matched, undecided) = probe_candidate_constraint(probe, || {
                eval_declaration_containment(
                    inside_decl,
                    facts,
                    id,
                    &mut captures,
                    owner_oracle,
                    &mut context,
                )
            });
            if !matched {
                continue;
            }
            unknown |= undecided;
        }
        if let Some(not_inside) = &query.not_inside {
            let mut discarded = Vec::new();
            let incomplete = context.incomplete;
            let previous_budget = context.each_budget;
            let (absent, undecided) = probe_candidate_constraint(probe, || {
                incomplete.negate(|| {
                    eval_containment(not_inside, facts, id, &mut discarded, &mut context)
                })
            });
            context.each_budget = previous_budget;
            if !absent {
                continue;
            }
            unknown |= undecided;
        }
        if unknown {
            context
                .incomplete
                .qualifying_type_sites
                .borrow_mut()
                .push(FactMatch {
                    node: id,
                    captures: Default::default(),
                    reported_range: None,
                    heuristic: None,
                });
            continue;
        }
        matches.push(FactMatch {
            node: id,
            captures: captures.into(),
            reported_range: None,
            heuristic: None,
        });
    }
    matches
}

fn seed_constrains_qualifying_type(seed: &CodeQuerySeed) -> bool {
    std::iter::once(&seed.root)
        .chain(seed.inside.iter())
        .chain(seed.inside_decl.iter())
        .chain(seed.not_inside.iter())
        .any(Pattern::constrains_qualifying_type)
}

/// For the new semantic predicate, Unknown is a provisional conjunction
/// operand; another proven false can still decide this candidate.
fn probe_candidate_constraint(
    incomplete: Option<&CallableSignatureIncomplete>,
    evaluate: impl FnOnce() -> bool,
) -> (bool, bool) {
    match incomplete {
        Some(incomplete) => {
            let (matched, unknown) = incomplete.qualifying_probe(evaluate);
            (matched || unknown, unknown)
        }
        None => (evaluate(), false),
    }
}

/// Whether choosing a different positive witness can change exported captures.
/// Predicate-only children (`not`, counts and local-value) keep their captures local.
fn pattern_exports_captures(pattern: &Pattern) -> bool {
    pattern.capture.is_some()
        || pattern.has.as_deref().is_some_and(pattern_exports_captures)
        || pattern
            .each
            .as_deref()
            .is_some_and(pattern_exports_captures)
        || pattern.all.iter().any(pattern_exports_captures)
        || pattern.any.iter().any(pattern_exports_captures)
        || Role::single_target_roles().iter().any(|role| {
            pattern
                .single_role_pattern(*role)
                .is_some_and(pattern_exports_captures)
        })
        || Role::list_target_roles().iter().any(|role| {
            pattern
                .list_role_patterns(*role)
                .iter()
                .any(pattern_exports_captures)
        })
        || pattern
            .kwargs
            .iter()
            .any(|(_, child)| pattern_exports_captures(child))
}

/// Existential relations discard qualifying uncertainty only when a candidate
/// proves the relation. Returning provisional true keeps Unknown available to
/// later conjunctions; the enclosing pattern withholds that candidate's row.
fn qualifying_any<'a, T>(
    incomplete: Option<&CallableSignatureIncomplete>,
    exports_captures: impl FnOnce() -> bool,
    candidates: impl IntoIterator<Item = T>,
    captures: &mut Vec<CaptureBinding>,
    context: &mut PatternEvalContext<'a>,
    mut evaluate: impl FnMut(T, &mut Vec<CaptureBinding>, &mut PatternEvalContext<'a>) -> bool,
) -> bool {
    let Some(incomplete) = incomplete else {
        return candidates
            .into_iter()
            .any(|candidate| evaluate(candidate, captures, context));
    };
    let checkpoint = captures.len();
    let previous_budget = context.each_budget;
    let mut unknown = false;
    for candidate in candidates {
        let (matched, undecided) =
            incomplete.qualifying_probe(|| evaluate(candidate, captures, context));
        if matched && !undecided {
            // An earlier possible witness wins if it resolves to true. Its
            // captures have not been proved equivalent to this later witness.
            if unknown && exports_captures() {
                incomplete.qualifying_type_unresolved.set(true);
                captures.truncate(checkpoint);
                context.each_budget = previous_budget;
            }
            return true;
        }
        unknown |= undecided;
    }
    if unknown {
        incomplete.qualifying_type_unresolved.set(true);
    }
    unknown
}

/// Greedy subsequence scan under one interpretation of a qualifying unknown.
/// The known scan proves a complete witness; the possible scan preserves earlier
/// undecided positions when a later known position is needed by the next pattern.
fn ordered_role_scan(
    patterns: &[Pattern],
    targets: &[&RoleTarget],
    facts: &FileFacts,
    captures: &mut Vec<CaptureBinding>,
    context: &mut PatternEvalContext<'_>,
    accepts: fn(bool, bool) -> bool,
) -> (Result<(), usize>, bool, bool) {
    let mut cursor = 0;
    let mut unknown = false;
    let mut capture_uncertain = false;
    for (pattern_index, pattern) in patterns.iter().enumerate() {
        let mut advanced = false;
        while let Some(target) = targets.get(cursor) {
            let index = cursor;
            cursor += 1;
            let incomplete = context.incomplete;
            let (matched, undecided) = if pattern.constrains_qualifying_type() {
                incomplete.qualifying_probe(|| {
                    eval_target(
                        pattern,
                        facts,
                        IndexedRoleTarget {
                            target,
                            index: Some(index),
                        },
                        captures,
                        context,
                    )
                })
            } else {
                (
                    eval_target(
                        pattern,
                        facts,
                        IndexedRoleTarget {
                            target,
                            index: Some(index),
                        },
                        captures,
                        context,
                    ),
                    false,
                )
            };
            unknown |= undecided;
            capture_uncertain |= undecided
                && patterns[pattern_index..]
                    .iter()
                    .any(pattern_exports_captures);
            if accepts(matched, undecided) {
                advanced = true;
                break;
            }
        }
        if !advanced {
            return (Err(pattern_index), unknown, capture_uncertain);
        }
    }
    (Ok(()), unknown, capture_uncertain)
}

fn ordered_roles_match(
    patterns: &[Pattern],
    targets: &[&RoleTarget],
    facts: &FileFacts,
    captures: &mut Vec<CaptureBinding>,
    context: &mut PatternEvalContext<'_>,
) -> Result<(), usize> {
    let checkpoint = captures.len();
    let previous_budget = context.each_budget;
    let (matched, unknown, capture_uncertain) = ordered_role_scan(
        patterns,
        targets,
        facts,
        captures,
        context,
        |matched, unknown| matched && !unknown,
    );
    if matched.is_ok() || !unknown {
        if matched.is_ok() && capture_uncertain {
            context.incomplete.qualifying_type_unresolved.set(true);
            captures.truncate(checkpoint);
            context.each_budget = previous_budget;
        }
        return matched;
    }
    captures.truncate(checkpoint);
    context.each_budget = previous_budget;
    let (possible, _, _) = ordered_role_scan(
        patterns,
        targets,
        facts,
        captures,
        context,
        |matched, unknown| matched || unknown,
    );
    // A possible witness exports no captures; the enclosing candidate is withheld.
    captures.truncate(checkpoint);
    context.each_budget = previous_budget;
    if possible.is_ok() {
        context.incomplete.qualifying_type_unresolved.set(true);
    }
    possible
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
    let ancestors = std::iter::from_fn(|| {
        let ancestor = current?;
        current = facts.node(ancestor).parent;
        Some(ancestor)
    });
    qualifying_any(
        pattern
            .constrains_qualifying_type()
            .then_some(context.incomplete),
        || pattern_exports_captures(pattern),
        ancestors,
        captures,
        context,
        |ancestor, captures, context| eval_pattern(pattern, facts, ancestor, captures, context),
    )
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
    let mut boundary = false;
    let ancestors = std::iter::from_fn(|| {
        let ancestor = current?;
        boundary = facts
            .node(ancestor)
            .kind
            .satisfies(NormalizedKind::Callable);
        current = if boundary {
            None
        } else {
            facts.node(ancestor).parent
        };
        Some(ancestor)
    });
    if qualifying_any(
        pattern
            .constrains_qualifying_type()
            .then_some(context.incomplete),
        || pattern_exports_captures(pattern),
        ancestors,
        captures,
        context,
        |ancestor, captures, context| eval_pattern(pattern, facts, ancestor, captures, context),
    ) {
        return true;
    }
    if boundary {
        return false;
    }
    let fact = facts.node(node);
    owner_oracle.is_some_and(|oracle| {
        oracle.owner_matches(
            fact.range,
            pattern,
            captures,
            context.examined_facts,
            context.incomplete,
            context.cancellation,
            context.max_examined_facts,
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
        qualifying_type_requested: pattern.constrains_qualifying_type(),
        examined_facts: inputs.examined_facts,
        oracle: inputs.oracle,
        selection_applications: inputs.selection_applications,
        local_value_oracle: inputs.local_value_oracle,
        incomplete: inputs.incomplete,
        comment_blocks: comment_blocks.as_ref(),
        recorded_argument_modes: inputs.recorded_argument_modes,
        each_budget: EachCaptureBudget::default(),
        capture_refusals: 0,
        each_exports: crate::hash::HashMap::default(),
        each_depth: 0,
        cancellation: inputs.cancellation,
        max_examined_facts: inputs.max_examined_facts,
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
    eval_same_node_pattern(pattern, facts, node, None, captures, context)
}

/// Run `evaluate`; on failure restore `captures` and the row's `each` capture
/// budget to their state before the call.
fn eval_with_rollback<'a>(
    captures: &mut Vec<CaptureBinding>,
    context: &mut PatternEvalContext<'a>,
    evaluate: impl FnOnce(&mut Vec<CaptureBinding>, &mut PatternEvalContext<'a>) -> bool,
) -> bool {
    let checkpoint = captures.len();
    let previous_budget = context.each_budget;
    if !evaluate(captures, context) {
        captures.truncate(checkpoint);
        context.each_budget = previous_budget;
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
    if let Some(modifier) = pattern.modifier
        && !fact
            .declaration_attributes
            .as_ref()
            .is_some_and(|attributes| {
                attributes
                    .modifiers
                    .iter()
                    .any(|word| word == modifier.label())
            })
    {
        return false;
    }
    if let Some(type_kind) = &pattern.type_kind
        && fact
            .declaration_attributes
            .as_ref()
            .and_then(|attributes| attributes.type_kind.as_ref())
            != Some(type_kind)
    {
        return false;
    }
    // A kind resolution has not decided keeps evaluating the rest of the
    // pattern: only a candidate that would otherwise match is reported as
    // incomplete, and it is withheld rather than matched.
    let mut undecided_kind = false;
    if !pattern.kinds.is_empty() {
        let answers = pattern
            .kinds
            .iter()
            .map(|&kind| fact_matches_query_kind(facts, node, kind, context))
            .collect::<Vec<_>>();
        if !answers.contains(&Some(true)) {
            if !answers.contains(&None) {
                return false;
            }
            undecided_kind = true;
        }
    }
    // An undecided excluded kind excludes the candidate: withholding an
    // unproved positive is the negation's fail-closed answer.
    for &kind in &pattern.not_kinds {
        match fact_matches_query_kind(facts, node, kind, context) {
            Some(false) => {}
            Some(true) => return false,
            None => {
                context.incomplete.selection_application_undecided.set(true);
                return false;
            }
        }
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
    if let Some(expected) = pattern.unsafe_context
        && fact.unsafe_context != Some(expected)
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
        let previous_budget = context.each_budget;
        let incomplete = context.incomplete;
        let absent = if negated.constrains_qualifying_type() {
            let (absent, unknown) = incomplete.qualifying_probe(|| {
                incomplete.negate(|| {
                    eval_same_node_pattern(negated, facts, node, name_override, captures, context)
                })
            });
            if unknown {
                incomplete.qualifying_type_unresolved.set(true);
                true
            } else {
                absent
            }
        } else {
            incomplete.negate(|| {
                eval_pattern_inner_with_name(negated, facts, node, name_override, captures, context)
            })
        };
        captures.truncate(checkpoint);
        context.each_budget = previous_budget;
        if !absent {
            return false;
        }
    }
    if pattern.all.iter().any(Pattern::constrains_qualifying_type) {
        let mut unknown = false;
        for sub_pattern in &pattern.all {
            let incomplete = context.incomplete;
            let (matched, undecided) = incomplete.qualifying_probe(|| {
                eval_same_node_pattern(sub_pattern, facts, node, name_override, captures, context)
            });
            if !matched && !undecided {
                return false;
            }
            unknown |= undecided;
        }
        if unknown {
            context.incomplete.qualifying_type_unresolved.set(true);
        }
    } else {
        for sub_pattern in &pattern.all {
            if !eval_same_node_pattern(sub_pattern, facts, node, name_override, captures, context) {
                return false;
            }
        }
    }
    if !pattern.any.is_empty() {
        if pattern.any.iter().any(Pattern::constrains_qualifying_type) {
            let checkpoint = captures.len();
            let original_budget = context.each_budget;
            let mut matched = false;
            let mut unknown = false;
            let mut capture_uncertain = false;
            for sub_pattern in &pattern.any {
                captures.truncate(checkpoint);
                context.each_budget = original_budget;
                let incomplete = context.incomplete;
                let (accepted, undecided) = incomplete.qualifying_probe(|| {
                    eval_same_node_pattern(
                        sub_pattern,
                        facts,
                        node,
                        name_override,
                        captures,
                        context,
                    )
                });
                if accepted && !undecided {
                    matched = true;
                    if capture_uncertain || (unknown && pattern_exports_captures(sub_pattern)) {
                        context.incomplete.qualifying_type_unresolved.set(true);
                        captures.truncate(checkpoint);
                        context.each_budget = original_budget;
                    }
                    break;
                }
                unknown |= undecided;
                capture_uncertain |= undecided && pattern_exports_captures(sub_pattern);
            }
            if !matched {
                captures.truncate(checkpoint);
                context.each_budget = original_budget;
                if !unknown {
                    return false;
                }
                context.incomplete.qualifying_type_unresolved.set(true);
            }
        } else if !pattern.any.iter().any(|sub_pattern| {
            eval_same_node_pattern(sub_pattern, facts, node, name_override, captures, context)
        }) {
            return false;
        }
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

    if !pattern.argument_modes.is_empty() {
        let mut matched = false;
        let mut owner = fact.parent;
        let mut parent = true;
        while let Some(id) = owner {
            *context.examined_facts = context.examined_facts.saturating_add(1);
            if *context.examined_facts >= context.max_examined_facts {
                context.incomplete.fact_budget_exhausted.set(true);
                return false;
            }
            if context.cancelled_at(*context.examined_facts) {
                return false;
            }
            // An argument's path to its call crosses no statement, block,
            // declaration, callable or type, so past the parent (which may
            // own the node whatever its kind) such an ancestor ends the walk
            // without a match. A wrapper such as a keyword-argument node still
            // reaches its call.
            let kind = facts.node(id).kind;
            if !parent
                && (kind.is_statement_level()
                    || matches!(
                        kind,
                        NormalizedKind::Block
                            | NormalizedKind::Declaration
                            | NormalizedKind::Parameter
                            | NormalizedKind::Callable
                            | NormalizedKind::Function
                            | NormalizedKind::Method
                            | NormalizedKind::Constructor
                            | NormalizedKind::Lambda
                            | NormalizedKind::Class
                            | NormalizedKind::Module
                            | NormalizedKind::Import
                    ))
            {
                break;
            }
            parent = false;
            let roles = facts.roles(id);
            let mut has_arguments = false;
            let mut owns_node = false;
            for target in roles {
                *context.examined_facts = context.examined_facts.saturating_add(1);
                if *context.examined_facts >= context.max_examined_facts {
                    context.incomplete.fact_budget_exhausted.set(true);
                    return false;
                }
                if context.cancelled_at(*context.examined_facts) {
                    return false;
                }
                let argument = matches!(target.role, Role::Arg | Role::Kwarg);
                has_arguments |= argument;
                if target.node == Some(node) {
                    owns_node = true;
                    matched |= argument && pattern.argument_modes.contains(&target.mode);
                }
            }
            // The nearest ancestor with an edge to the node owns its role, and
            // the nearest argument owner decides whether it is an argument:
            // either ends the walk.
            if has_arguments || owns_node {
                break;
            }
            owner = facts.node(id).parent;
        }
        if !matched {
            if pattern
                .argument_modes
                .iter()
                .any(|mode| !context.recorded_argument_modes.contains(mode))
            {
                context.incomplete.argument_mode_unrecorded.set(true);
            }
            return false;
        }
    }
    if let Some(count) = &pattern.count {
        let mut lower = 0usize;
        let mut unknown_children = 0usize;
        let mut other_unknown_children = 0usize;
        for (index, target) in roles
            .iter()
            .filter(|target| target.role == count.role)
            .enumerate()
        {
            // A count is a predicate: captures and incompleteness from each child
            // belong to that child, never to its siblings or the candidate. The
            // child starts from no captures, so a label the candidate already
            // bound is not an equality constraint on the child.
            let mut child_captures = Vec::new();
            let previous_budget = context.each_budget;
            let incomplete = context.incomplete;
            let mut qualifying_only = false;
            let (matched, unknown) = incomplete.isolated(|| {
                let matched = eval_target(
                    &count.pattern,
                    facts,
                    IndexedRoleTarget {
                        target,
                        index: Some(index),
                    },
                    &mut child_captures,
                    context,
                );
                qualifying_only = incomplete.qualifying_type_unresolved.get()
                    && incomplete.flags().into_iter().all(|flag| {
                        std::ptr::eq(flag, &incomplete.qualifying_type_unresolved) || !flag.get()
                    });
                matched
            });
            context.each_budget = previous_budget;
            if matched {
                lower += 1;
            } else if unknown {
                unknown_children += 1;
                other_unknown_children += usize::from(!qualifying_only);
            }
        }
        let coverage = facts.role_coverage(node, count.role);
        let upper =
            matches!(coverage, Some(RoleCoverage::Complete)).then_some(lower + unknown_children);
        let min = count.min as usize;
        let max = count.max.map(|max| max as usize);
        if upper.is_some_and(|upper| upper < min) || max.is_some_and(|max| lower > max) {
            return false;
        }
        if lower < min || max.is_some_and(|max| upper.is_none_or(|upper| upper > max)) {
            if matches!(coverage, Some(RoleCoverage::Complete)) && other_unknown_children == 0 {
                // Coverage and every other child capability are proved. Only
                // qualifying answers can change these bounds, so Boolean
                // composition may still decide this candidate.
                context.incomplete.qualifying_type_unresolved.set(true);
            } else {
                context.incomplete.role_coverage_incomplete.set(true);
                context.incomplete.count_gaps.borrow_mut().push(CountGap {
                    owner: fact.range,
                    role: count.role,
                    lower,
                    upper,
                    min: count.min,
                    max: count.max,
                    coverage,
                });
                return false;
            }
        }
    }

    if !eval_callable_signature(pattern, facts, node, context.oracle, context.incomplete) {
        return false;
    }

    // Single-target roles: the first (typically only) edge of that role must
    // match the sub-pattern; a role constraint on a fact without that edge
    // fails.
    let selection_call = match selection_application(context, node) {
        Some(SelectionApplication::Call) => true,
        Some(SelectionApplication::Undecided) => undecided_kind,
        Some(SelectionApplication::NotCall) | None => false,
    };
    for &role in Role::single_target_roles() {
        if let Some(sub_pattern) = pattern.single_role_pattern(role) {
            let matched = qualifying_any(
                sub_pattern
                    .constrains_qualifying_type()
                    .then_some(context.incomplete),
                || pattern_exports_captures(sub_pattern),
                roles
                    .iter()
                    .filter(|target| target_has_role(target, role, selection_call)),
                captures,
                context,
                |target, captures, context| {
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
                },
            );
            if !matched {
                // A fact with no edge for a role proves the role absent only
                // when the adapter emits every edge of that role. A fact whose
                // own kind cannot carry the role (an identifier under a
                // pattern that also admits assignments) is a plain non-match.
                if role.absence_needs_certification()
                    && role.valid_for(fact.kind)
                    && !roles.iter().any(|target| target.role == role)
                    && !context.incomplete.certified_roles.get().contains(&role)
                {
                    context.incomplete.role_absence_uncertified.set(true);
                    let mut absences = context.incomplete.uncertified_role_absences.borrow_mut();
                    if !absences.contains(&role) {
                        absences.push(role);
                    }
                }
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
        if let Err(failed) = ordered_roles_match(sub_patterns, &targets, facts, captures, context) {
            if role == Role::Arg {
                flag_unrecorded_argument_modes(&sub_patterns[failed], context);
            }
            if role.has_coverage() {
                let coverage = facts.role_coverage(node, role);
                if !matches!(coverage, Some(RoleCoverage::Complete)) {
                    context.incomplete.role_coverage_incomplete.set(true);
                    let gap = (facts.node(node).range, role, coverage);
                    let mut gaps = context.incomplete.role_coverage_gaps.borrow_mut();
                    if !gaps.contains(&gap) {
                        gaps.push(gap);
                    }
                }
            }
            return false;
        }
    }

    // Keyword args match by keyword name.
    for (keyword, value_pattern) in &pattern.kwargs {
        let matched = qualifying_any(
            value_pattern
                .constrains_qualifying_type()
                .then_some(context.incomplete),
            || pattern_exports_captures(value_pattern),
            roles.iter().filter(|target| target.role == Role::Kwarg),
            captures,
            context,
            |target, captures, context| {
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
            },
        );
        if !matched {
            flag_unrecorded_argument_modes(value_pattern, context);
            return false;
        }
    }

    if let Some(has) = &pattern.has
        && !some_descendant_matches(has, facts, node, captures, context)
    {
        return false;
    }
    if let Some(each) = &pattern.each {
        let mut matched = false;
        let mut unknown = false;
        let subtree = facts.node(node).span();
        // A zero-width region (an inserted missing token) touching either
        // boundary belongs to the subtree too: it may close the quantified fact.
        // The regions are in source order without overlaps, so a binary search
        // finds the first one that does not end before the subtree, and at most
        // the boundary regions after it fail the overlap test.
        let regions = facts.recovered_regions();
        let first = regions.partition_point(|region| region.range.end_byte < subtree.start_byte);
        if regions[first..]
            .iter()
            .take_while(|region| region.range.start_byte <= subtree.end_byte)
            .any(|region| {
                let range = &region.range;
                if range.start_byte == range.end_byte {
                    true
                } else {
                    range.start_byte < subtree.end_byte && range.end_byte > subtree.start_byte
                }
            })
        {
            context.incomplete.each_incomplete.set(true);
        }
        // Only the labels the child guarantees leave the `each`; a label
        // bound by some `any` alternatives alone is dropped, so no row
        // carries a capture that a match may lack.
        let exported = Rc::clone(
            context
                .each_exports
                .entry(std::ptr::from_ref(each.as_ref()))
                .or_insert_with(|| Rc::new(each.guaranteed_capture_names())),
        );
        context.each_depth += 1;
        for candidate in node..facts.subtree_end(node) {
            if *context.examined_facts >= context.max_examined_facts {
                context.incomplete.fact_budget_exhausted.set(true);
                break;
            }
            if context.each_budget.exhausted {
                context.incomplete.fact_budget_exhausted.set(true);
                break;
            }
            if context.cancelled_at(u64::from(candidate - node)) {
                break;
            }
            let candidate_span = facts.node(candidate).span();
            if candidate_span.start_byte == candidate_span.end_byte {
                // A missing grammar token can be represented as an empty
                // normalized fact without a recovered-region row.
                context.incomplete.each_incomplete.set(true);
                continue;
            }
            if facts.node(candidate).kind == NormalizedKind::SyntaxError {
                context.incomplete.each_incomplete.set(true);
            }
            let mut child_captures = Vec::new();
            let previously_charged = context.each_budget.bytes;
            let previous_refusals = context.capture_refusals;
            let (child_matched, undecided) = if each.constrains_qualifying_type() {
                let incomplete = context.incomplete;
                incomplete.qualifying_probe(|| {
                    eval_pattern(each, facts, candidate, &mut child_captures, context)
                })
            } else {
                (
                    eval_pattern(each, facts, candidate, &mut child_captures, context),
                    false,
                )
            };
            unknown |= undecided;
            if child_matched && !undecided && !context.each_budget.exhausted {
                // Refund the charge of every binding the `each` does not export.
                child_captures.retain(|binding| {
                    let keep = exported.contains(&binding.name);
                    if !keep {
                        context.each_budget.bytes = context.each_budget.bytes.saturating_sub(
                            binding
                                .text
                                .len()
                                .saturating_add(EACH_CAPTURE_BINDING_OVERHEAD_BYTES),
                        );
                    }
                    keep
                });
                matched = true;
                captures.extend(child_captures);
            } else {
                // Drop this descendant's bindings, including nested `each`
                // charges. A descendant that failed after the cap refused one
                // of its captures may have failed only for the cap, and later
                // descendants would build and drop the same bindings again,
                // so the walk ends at the next candidate. An enclosing
                // rollback point clears the mark with the bytes.
                context.each_budget.bytes = previously_charged;
                if context.capture_refusals > previous_refusals {
                    context.each_budget.exhausted = true;
                }
            }
        }
        context.each_depth -= 1;
        if unknown {
            context.incomplete.qualifying_type_unresolved.set(true);
        }
        if context.incomplete.cancelled.get() || (!matched && !unknown) {
            return false;
        }
    }
    if let Some(not_has) = &pattern.not_has {
        let mut discarded = Vec::new();
        let previous_budget = context.each_budget;
        let incomplete = context.incomplete;
        let absent = if not_has.constrains_qualifying_type() {
            let (absent, unknown) = incomplete.qualifying_probe(|| {
                incomplete.negate(|| {
                    some_descendant_matches(not_has, facts, node, &mut discarded, context)
                })
            });
            if unknown {
                incomplete.qualifying_type_unresolved.set(true);
            }
            absent || unknown
        } else {
            incomplete
                .negate(|| some_descendant_matches(not_has, facts, node, &mut discarded, context))
        };
        context.each_budget = previous_budget;
        if !absent {
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
        let previous_budget = context.each_budget;
        let matched = qualifying_any(
            value_pattern
                .constrains_qualifying_type()
                .then_some(context.incomplete),
            || false,
            targets.iter(),
            captures,
            context,
            |target, _, context| {
                let mut value_captures = Vec::new();
                eval_pattern(value_pattern, facts, *target, &mut value_captures, context)
            },
        );
        // The value captures are dropped even when the value matches.
        context.each_budget = previous_budget;
        if !matched {
            return false;
        }
    }

    if let Some(expected) = &pattern.qualifying_type {
        match context
            .oracle
            .and_then(|oracle| oracle.qualifying_type_matches(fact.range, expected))
        {
            Some(true) => {}
            Some(false) => return false,
            None => {
                context.incomplete.qualifying_type_unresolved.set(true);
            }
        }
    }

    if undecided_kind {
        context.incomplete.selection_application_undecided.set(true);
        return false;
    }
    if let Some(label) = &pattern.capture
        && !add_capture(
            label,
            fact.span(),
            Some(fact.kind),
            Some(node),
            facts,
            captures,
            context,
        )
    {
        return false;
    }
    true
}

/// Whether `node_id` is a `query_kind` fact; `None` when resolution has not
/// decided whether a resolution-decided selection is a call.
fn fact_matches_query_kind(
    facts: &FileFacts,
    node_id: u32,
    query_kind: NormalizedKind,
    context: &PatternEvalContext<'_>,
) -> Option<bool> {
    let fact = facts.node(node_id);
    if query_kind == NormalizedKind::Call
        && let Some(application) = selection_application(context, node_id)
    {
        return match application {
            SelectionApplication::Call => Some(true),
            SelectionApplication::NotCall => Some(false),
            SelectionApplication::Undecided => None,
        };
    }
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
        return Some(false);
    }
    Some(fact.kind.satisfies(query_kind))
}

fn selection_application(
    context: &PatternEvalContext<'_>,
    node: u32,
) -> Option<SelectionApplication> {
    context
        .selection_applications
        .and_then(|applications| applications.get(&node).copied())
}

/// Whether `target` fills `role` of the fact it belongs to. A selection that
/// resolution admits as a call reads its member as the callee and its object
/// as the receiver, as the same selection written with arguments does.
fn target_has_role(target: &RoleTarget, role: Role, selection_call: bool) -> bool {
    target.role == role
        || (selection_call
            && matches!(
                (target.role, role),
                (Role::Field, Role::Callee) | (Role::Object, Role::Receiver)
            ))
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
    if !context.qualifying_type_requested || !pattern.constrains_qualifying_type() {
        return eval_with_rollback(captures, context, |captures, context| {
            eval_pattern_inner_with_name(pattern, facts, node, name_override, captures, context)
        });
    }
    let previous = context.incomplete.qualifying_type_unresolved.replace(false);
    eval_with_rollback(captures, context, |captures, context| {
        let matched =
            eval_pattern_inner_with_name(pattern, facts, node, name_override, captures, context);
        let unknown = context.incomplete.qualifying_type_unresolved.get();
        context
            .incomplete
            .qualifying_type_unresolved
            .set(previous || (matched && unknown));
        matched && !unknown
    })
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
    // Facts are stored in pre-order with subtree intervals.
    let stopped = Cell::new(false);
    qualifying_any(
        pattern
            .constrains_qualifying_type()
            .then_some(context.incomplete),
        || pattern_exports_captures(pattern),
        ((node + 1)..facts.subtree_end(node)).take_while(|_| !stopped.get()),
        captures,
        context,
        |candidate, captures, context| {
            if context.each_depth > 0 {
                if *context.examined_facts >= context.max_examined_facts {
                    context.incomplete.fact_budget_exhausted.set(true);
                    stopped.set(true);
                    return false;
                }
                if context.cancelled_at(*context.examined_facts) {
                    stopped.set(true);
                    return false;
                }
            }
            eval_pattern(pattern, facts, candidate, captures, context)
        },
    )
}

/// Evaluate a sub-pattern against a role target. When the target is itself a
/// normalized fact, full pattern semantics apply to that fact while name
/// predicates prefer the role-derived name when present; otherwise only
/// name/text/capture and boolean combinations can be satisfied from the edge's
/// raw span and derived name. Kind-specific predicates are false on a target
/// without a normalized kind (string-value keeps its existing unrecorded-value
/// diagnostic). Predicates requiring unread structure below or around the
/// target report incomplete: has, not_has, local_value, arguments, keyword
/// arguments, and role constraints.
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
    eval_with_rollback(captures, context, |captures, context| {
        pattern.index.is_none_or(|expected| {
            index.is_some_and(|index| u32::try_from(index).ok() == Some(expected))
        }) && match target.node {
            Some(node) => {
                eval_same_node_pattern(pattern, facts, node, target.name, captures, context)
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
    if !pattern.kinds.is_empty() {
        return false;
    }
    if !pattern.argument_modes.is_empty()
        && (!matches!(target.role, Role::Arg | Role::Kwarg)
            || !pattern.argument_modes.contains(&target.mode))
    {
        if pattern
            .argument_modes
            .iter()
            .any(|mode| !context.recorded_argument_modes.contains(mode))
        {
            context.incomplete.argument_mode_unrecorded.set(true);
        }
        return false;
    }
    if pattern.boolean_value.is_some()
        || pattern.string_value.is_some()
        || pattern.language_rule.is_some()
        || pattern.body_state.is_some()
        || pattern.body_owner.is_some()
        || pattern.is_async.is_some()
        || pattern.unsafe_context.is_some()
        || pattern.modifier.is_some()
        || pattern.type_kind.is_some()
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
    {
        return false;
    }
    // These predicates need structure that a raw role span does not expose.
    // A count reads the target's own role children, which a span-only target
    // never recorded, so it is unknown rather than a proven miss (#9613).
    if pattern.has.is_some()
        || pattern.each.is_some()
        || pattern.count.is_some()
        || pattern.local_value.is_some()
        || pattern.not_has.is_some()
        || !pattern.args.is_empty()
        || !pattern.kwargs.is_empty()
        || pattern.has_role_constraints()
    {
        context.incomplete.role_target_unrecorded.set(true);
        return false;
    }
    if let Some(negated) = &pattern.not {
        let checkpoint = captures.len();
        let previous_budget = context.each_budget;
        let incomplete = context.incomplete;
        let absent =
            incomplete.negate(|| eval_span_only(negated, facts, target, captures, context));
        captures.truncate(checkpoint);
        context.each_budget = previous_budget;
        if !absent {
            return false;
        }
    }
    for child in &pattern.all {
        if !eval_with_rollback(captures, context, |captures, context| {
            eval_span_only(child, facts, target, captures, context)
        }) {
            return false;
        }
    }
    if !pattern.any.is_empty()
        && !pattern.any.iter().any(|child| {
            eval_with_rollback(captures, context, |captures, context| {
                eval_span_only(child, facts, target, captures, context)
            })
        })
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
        && !add_capture(label, target.span, None, None, facts, captures, context)
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
    context: &mut PatternEvalContext<'_>,
) -> bool {
    let text = span.text(facts.source());
    if captures
        .iter()
        .filter(|capture| capture.name == label)
        .any(|capture| capture.text != text)
    {
        return false;
    }
    if context.each_depth > 0 {
        // Charge before copying the text, so a child with many capture
        // predicates over a large node stops at the budget instead of
        // allocating every binding first.
        let charge = text
            .len()
            .saturating_add(EACH_CAPTURE_BINDING_OVERHEAD_BYTES);
        if context.each_budget.bytes.saturating_add(charge) > MAX_EACH_CAPTURE_BYTES_PER_ROW {
            context.incomplete.fact_budget_exhausted.set(true);
            context.each_budget.exhausted = true;
            context.capture_refusals += 1;
            return false;
        }
        context.each_budget.bytes += charge;
        #[cfg(test)]
        EACH_BINDINGS_BUILT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
