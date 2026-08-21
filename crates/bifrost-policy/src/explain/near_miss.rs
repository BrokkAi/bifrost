//! Bounded near-miss ranking: which subjects came closest to satisfying one
//! policy, and which of its own declared predicates each of them missed.
//!
//! # The question this answers
//!
//! `why-not` answers about one position the caller already suspects. Rule
//! refinement asks the opposite question: *which* positions nearly matched, so
//! an author can see whether the rule is too narrow, too wide, or aimed at the
//! wrong predicate. That needs a candidate set and a distance over it, and
//! neither falls out of a candidate-specific walk (issue 2500).
//!
//! # The ladder
//!
//! A policy's selector is a seed plus typed steps. The seed carries two very
//! different kinds of constraint:
//!
//! - **scope**: the kind union, the language filter, and the path globs. This
//!   is what makes a search bounded, so it is never relaxed.
//! - **predicates**: everything else the author declared -- the root's name,
//!   text, arity, visibility, parameter type, role sub-patterns, and the
//!   `inside`/`inside_decl`/`not_inside` containment.
//!
//! The ladder is the sequence of selectors obtained by starting from scope
//! alone and restoring one declared predicate at a time, in the fixed order of
//! [`SeedPredicate::ALL`], until the exact authored selector is reached. Every
//! rung runs the policy's *whole* pipeline -- the same steps, over a relaxed
//! seed -- so its rows are subjects in the policy's own final domain, not
//! intermediate seed rows.
//!
//! Rung 0 is the scope rung. It is also the enumeration: in
//! [`NearMissCandidates::PolicySeedSearch`] its rows *are* the candidate set.
//! This is what "never a default whole-repository scan" means concretely: the
//! search is the policy's own selector with its own kind, language and path
//! pruning intact, and a policy whose seed declares no kind union has no
//! bounded scope at all and is refused with
//! [`ExplainError::NearMissScopeUnavailable`].
//!
//! # The distance
//!
//! For one candidate, walk the rungs in order and find the first one whose rows
//! do not cover it. That rung's conjunct is the failing one, everything before
//! it is satisfied, and everything from it onward is unsatisfied:
//!
//! ```text
//! declared_conjuncts   = 1 (scope) + declared predicates (+ 1 per further row binding)
//! satisfied_conjuncts  = index of the first rung that does not cover the candidate
//! unsatisfied_conjuncts = declared_conjuncts - satisfied_conjuncts
//! ```
//!
//! A candidate no rung dropped has distance 0. Nothing else contributes: no
//! embedding, no model score, no text similarity, no proximity heuristic. The
//! only inputs are the policy's own declared predicates and the typed rows the
//! analyzer returned for them.
//!
//! # `failed` is not `unknown`, and `unknown` is not distance
//!
//! A candidate is `failed` only when the rung that dropped it completed and
//! declared itself exhaustive. When that rung was a proven subset, incomplete,
//! cancelled or invalid, the candidate is `unknown` and carries the mapped
//! [`PolicyIncompleteReason`]s. When the execution budget stopped the ladder
//! before the exact selector was reached, every candidate still standing is
//! `unknown` with `report_retention_budget`.
//!
//! Crucially, `unknown` never *adds* distance. An undecided candidate reports
//! the conjunct count it was observed to reach, exactly as a decided one does;
//! the difference is the outcome tag, and the sort breaks ties by it. So a
//! consumer can never mistake incompleteness for semantic distance.
//!
//! # Determinism
//!
//! Candidates are ordered by
//! `(unsatisfied_conjuncts, outcome, path, byte_start, byte_end)`, all of which
//! come from the policy and the analyzer rows rather than from any iteration
//! order over a hash container, a clock, or an address. Two rankings built from
//! the same inputs serialize to byte-identical JSON.
//!
//! # A sibling document, not a node kind
//!
//! A ranking is published as `bifrost_policy_near_miss/v1`
//! ([`POLICY_NEAR_MISS_FORMAT`]), not as a new node kind inside
//! `bifrost_policy_explanation/v1`. The two answer different shapes of
//! question: an explanation is a tree about one subject, a ranking is an
//! ordered list over many, and forcing the list into the tree would have made
//! every existing consumer's root-outcome contract ambiguous. The explanation
//! schema is therefore untouched, and the ranking reuses its vocabulary --
//! [`ExplanationOutcome`], [`ExplanationSubject`], [`PolicyIncompleteReason`],
//! [`ExplanationLimits`], and the `*_truncated` plus `omitted_*_lower_bound`
//! convention -- so a consumer learns one set of rules.

use std::collections::HashMap;
use std::ops::Range;

use serde::Serialize;

use brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath;
use brokk_bifrost_analysis::analyzer::structural::search::{
    execute_code_query_detailed_eager_index, execute_code_query_detailed_eager_index_workspace,
};
use brokk_bifrost_analysis::analyzer::structural::{
    CodeQuery, CodeQueryCompletion, CodeQueryResultDetail,
};
use brokk_bifrost_rql::{CodeQueryPlanSource, CodeQuerySeed, Pattern};

use crate::budget::PolicyBudget;
use crate::definition::{
    PolicyAnalysis, PolicyAnalysisType, PolicyId, RelationalAssertionPlan, RowBinding,
    RowBindingSource, relational_binding_selector_path,
};
use crate::evaluator::PolicyEvaluationContext;
use crate::finding::PolicyIncompleteReason;
use crate::identity::PolicySemanticHash;
use crate::resolved::LoadedPolicy;
use crate::retained::{RetainedSize, retained_extra};

use super::model::{
    ExplainError, ExplanationBudgetLimit, ExplanationLimits, ExplanationOutcome,
    ExplanationQuestion, ExplanationSubject, truncate_text_to,
};
use super::why_not::{
    ExplanationCandidate, MATCH_SELECTOR_PATH, PrefixExecution, absence_reasons,
    row_covers_candidate,
};

/// The versioned format tag every near-miss ranking carries.
pub const POLICY_NEAR_MISS_FORMAT: &str = "bifrost_policy_near_miss/v1";

/// Where a ranking's candidate subjects come from.
///
/// There is deliberately no third option. Enumeration is either the caller's
/// own list or the policy's own bounded seed scope; nothing here ever walks a
/// workspace that the policy did not already prune.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NearMissCandidates {
    /// The caller nominated every subject. Nothing is searched for, and a
    /// nominated subject outside the policy's own scope reports `scope` as its
    /// failing conjunct rather than being silently dropped.
    Supplied(Vec<ExplanationCandidate>),
    /// A separately budgeted search whose scope is the policy's own seed: its
    /// kind union, language filter and path globs, with every other declared
    /// predicate relaxed.
    PolicySeedSearch,
}

/// How one ranking obtained its candidates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NearMissEnumeration {
    /// The caller supplied the list.
    Supplied { supplied: u64 },
    /// The policy's own seed scope was searched.
    PolicySeed {
        /// The scope that bounded the search, rendered for a reader.
        scope: String,
        /// Distinct subjects the scope rung returned.
        rows: u64,
        /// True when the scope query completed and declared itself exhaustive,
        /// so the candidate set is the whole of what the scope contains.
        exhaustive: bool,
    },
}

impl RetainedSize for NearMissEnumeration {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::Supplied { .. } => 0,
            Self::PolicySeed { scope, .. } => scope.capacity(),
        })
    }
}

/// One ranked subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NearMissEntry {
    /// Position in the ranking, 1-based and dense.
    rank: u64,
    subject: ExplanationSubject,
    /// `satisfied` means every declared conjunct held, `failed` means an
    /// exhaustive rung dropped the subject, and `unknown` means no rung could
    /// decide it. `unknown` is never evidence of distance.
    outcome: ExplanationOutcome,
    declared_conjuncts: u64,
    satisfied_conjuncts: u64,
    /// The distance. Smaller is nearer.
    unsatisfied_conjuncts: u64,
    /// The first declared conjunct the subject did not satisfy, absent when it
    /// satisfied them all or when no rung could decide.
    #[serde(skip_serializing_if = "Option::is_none")]
    failing_conjunct: Option<String>,
    /// Why an `unknown` outcome could not be decided.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reasons: Vec<PolicyIncompleteReason>,
    /// What the ladder observed, in prose.
    actual: String,
}

impl NearMissEntry {
    pub const fn rank(&self) -> u64 {
        self.rank
    }
    pub const fn subject(&self) -> &ExplanationSubject {
        &self.subject
    }
    pub const fn outcome(&self) -> ExplanationOutcome {
        self.outcome
    }
    pub const fn declared_conjuncts(&self) -> u64 {
        self.declared_conjuncts
    }
    pub const fn satisfied_conjuncts(&self) -> u64 {
        self.satisfied_conjuncts
    }
    pub const fn unsatisfied_conjuncts(&self) -> u64 {
        self.unsatisfied_conjuncts
    }
    pub fn failing_conjunct(&self) -> Option<&str> {
        self.failing_conjunct.as_deref()
    }
    pub fn reasons(&self) -> &[PolicyIncompleteReason] {
        &self.reasons
    }
    pub fn actual(&self) -> &str {
        &self.actual
    }

    fn own_bytes(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.subject))
            .saturating_add(self.failing_conjunct.as_ref().map_or(0, String::capacity))
            .saturating_add(
                self.reasons
                    .len()
                    .saturating_mul(size_of::<PolicyIncompleteReason>()),
            )
            .saturating_add(self.actual.capacity())
    }
}

impl RetainedSize for NearMissEntry {
    fn retained_size(&self) -> usize {
        self.own_bytes()
    }
}

/// What the explicit bounds removed from one ranking.
///
/// The crate's `*_truncated` plus `omitted_*_lower_bound` convention: the flag
/// is true exactly when the bound is non-zero, and the bound is a lower bound
/// because an execution that never ran cannot report what it would have found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct NearMissTruncation {
    candidates_truncated: bool,
    omitted_candidates_lower_bound: u64,
    executions_truncated: bool,
    omitted_executions_lower_bound: u64,
    bytes_truncated: bool,
    omitted_bytes_lower_bound: u64,
    text_truncated: bool,
    omitted_text_bytes_lower_bound: u64,
}

impl NearMissTruncation {
    pub const fn candidates_truncated(&self) -> bool {
        self.candidates_truncated
    }
    pub const fn omitted_candidates_lower_bound(&self) -> u64 {
        self.omitted_candidates_lower_bound
    }
    pub const fn executions_truncated(&self) -> bool {
        self.executions_truncated
    }
    pub const fn omitted_executions_lower_bound(&self) -> u64 {
        self.omitted_executions_lower_bound
    }
    pub const fn bytes_truncated(&self) -> bool {
        self.bytes_truncated
    }
    pub const fn omitted_bytes_lower_bound(&self) -> u64 {
        self.omitted_bytes_lower_bound
    }
    pub const fn text_truncated(&self) -> bool {
        self.text_truncated
    }
    pub const fn omitted_text_bytes_lower_bound(&self) -> u64 {
        self.omitted_text_bytes_lower_bound
    }
    /// True when any bound removed anything.
    pub const fn is_truncated(&self) -> bool {
        self.candidates_truncated
            || self.executions_truncated
            || self.bytes_truncated
            || self.text_truncated
    }

    fn omit_candidates(&mut self, count: u64) {
        if count == 0 {
            return;
        }
        self.candidates_truncated = true;
        self.omitted_candidates_lower_bound =
            self.omitted_candidates_lower_bound.saturating_add(count);
    }

    fn omit_executions(&mut self, count: u64) {
        if count == 0 {
            return;
        }
        self.executions_truncated = true;
        self.omitted_executions_lower_bound =
            self.omitted_executions_lower_bound.saturating_add(count);
    }

    fn omit_bytes(&mut self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.bytes_truncated = true;
        self.omitted_bytes_lower_bound = self.omitted_bytes_lower_bound.saturating_add(bytes);
    }

    fn omit_text_bytes(&mut self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.text_truncated = true;
        self.omitted_text_bytes_lower_bound =
            self.omitted_text_bytes_lower_bound.saturating_add(bytes);
    }
}

impl RetainedSize for NearMissTruncation {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
    }
}

/// A complete near-miss ranking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyNearMissRanking {
    format: &'static str,
    question: ExplanationQuestion,
    policy_id: PolicyId,
    policy_hash: PolicySemanticHash,
    analysis_type: PolicyAnalysisType,
    enumeration: NearMissEnumeration,
    /// The declared conjuncts in ladder order, `scope` first. An entry's
    /// `failing_conjunct` is always one of these labels.
    conjuncts: Vec<String>,
    /// Distinct subjects the ladder measured, before the retention bound.
    candidates_considered: u64,
    /// Bounded queries this ranking actually ran, the scope rung included.
    executions_used: u64,
    entries: Vec<NearMissEntry>,
    truncation: NearMissTruncation,
}

impl PolicyNearMissRanking {
    pub const fn format(&self) -> &'static str {
        self.format
    }
    pub const fn question(&self) -> ExplanationQuestion {
        self.question
    }
    pub const fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }
    pub const fn policy_hash(&self) -> PolicySemanticHash {
        self.policy_hash
    }
    pub const fn analysis_type(&self) -> PolicyAnalysisType {
        self.analysis_type
    }
    pub const fn enumeration(&self) -> &NearMissEnumeration {
        &self.enumeration
    }
    pub fn conjuncts(&self) -> &[String] {
        &self.conjuncts
    }
    pub const fn candidates_considered(&self) -> u64 {
        self.candidates_considered
    }
    pub const fn executions_used(&self) -> u64 {
        self.executions_used
    }
    pub fn entries(&self) -> &[NearMissEntry] {
        &self.entries
    }
    pub const fn truncation(&self) -> &NearMissTruncation {
        &self.truncation
    }

    /// Serialize to canonical JSON. Field order is declaration order, so two
    /// equal rankings render byte-identically.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("the near-miss model is serializable")
    }
}

impl RetainedSize for PolicyNearMissRanking {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.policy_id))
            .saturating_add(retained_extra(&self.enumeration))
            .saturating_add(self.conjuncts.iter().fold(0usize, |total, label| {
                total.saturating_add(label.capacity())
            }))
            .saturating_add(retained_extra(&self.entries))
    }
}

/// Rank the subjects that came closest to satisfying one policy.
///
/// # Errors
///
/// - [`ExplainError::ExplanationAdapterUnavailable`] for a `flow`, `taint` or
///   `typestate` policy. The error names the families that *are* served.
/// - [`ExplainError::SelectorUnavailable`] when a match policy carries no
///   resolved `/analysis/selector`, and
///   [`ExplainError::RelationalPlanUnavailable`] /
///   [`ExplainError::BindingSelectorUnavailable`] for the relational cases.
/// - [`ExplainError::NearMissScopeUnavailable`] when the policy's seed declares
///   no bounded scope to enumerate from.
/// - [`ExplainError::BudgetExhausted`] when the limits allow no execution or no
///   retained candidate.
pub fn rank_near_misses(
    policy: &LoadedPolicy,
    context: &PolicyEvaluationContext<'_>,
    candidates: &NearMissCandidates,
    budget: &PolicyBudget,
    limits: &ExplanationLimits,
) -> Result<PolicyNearMissRanking, ExplainError> {
    if limits.max_near_miss_executions() == 0 {
        return Err(ExplainError::BudgetExhausted {
            limit: ExplanationBudgetLimit::NearMissExecutions,
        });
    }
    if limits.max_near_miss_candidates() == 0 {
        return Err(ExplainError::BudgetExhausted {
            limit: ExplanationBudgetLimit::NearMissCandidates,
        });
    }

    let plan = match &policy.definition().analysis {
        PolicyAnalysis::Match { .. } => LadderPlan::match_selector(policy)?,
        PolicyAnalysis::Assertion { spec } => {
            let relational = spec
                .relational
                .as_ref()
                .ok_or(ExplainError::RelationalPlanUnavailable)?;
            LadderPlan::relational(policy, relational)?
        }
        other => {
            return Err(ExplainError::adapter_unavailable(
                other.analysis_type(),
                ExplanationQuestion::NearMiss,
            ));
        }
    };

    let ladder = plan.execute(context, budget, limits);
    let (subjects, enumeration) = match candidates {
        NearMissCandidates::Supplied(supplied) => (
            supplied.clone(),
            NearMissEnumeration::Supplied {
                supplied: u64::try_from(supplied.len()).unwrap_or(u64::MAX),
            },
        ),
        NearMissCandidates::PolicySeedSearch => ladder.enumerate_scope_subjects(&plan.scope_label),
    };

    Ok(build_ranking(
        policy,
        plan,
        ladder,
        subjects,
        enumeration,
        limits,
    ))
}

// ---------------------------------------------------------------------------
// The declared predicates of a seed
// ---------------------------------------------------------------------------

/// One relaxable predicate a seed can declare.
///
/// The order of [`Self::ALL`] is the ladder's restore order, and it is the
/// "priority" the ranking is defined against: the root's own predicates first,
/// then its role sub-patterns, then containment. Containment is restored last
/// on purpose -- a subject that satisfies everything about itself but sits in
/// the wrong context is the *nearest* kind of miss, and this order is what
/// makes it rank that way.
///
/// Scope is not on this list. `kinds`, `languages`, `where_globs` and the
/// root's `capture` are carried by every rung: the first three are what bounds
/// the search, and the fourth is a binding name later steps may reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeedPredicate {
    RootName,
    RootText,
    RootArity,
    RootVisibility,
    RootParameterType,
    RootNotKinds,
    RootHas,
    RootNotHas,
    RootCallee,
    RootReceiver,
    RootArgs,
    RootKwargs,
    RootLeft,
    RootRight,
    RootModule,
    RootDecorators,
    RootObject,
    RootField,
    Inside,
    InsideDecl,
    NotInside,
}

impl SeedPredicate {
    const ALL: &'static [Self] = &[
        Self::RootName,
        Self::RootText,
        Self::RootArity,
        Self::RootVisibility,
        Self::RootParameterType,
        Self::RootNotKinds,
        Self::RootHas,
        Self::RootNotHas,
        Self::RootCallee,
        Self::RootReceiver,
        Self::RootArgs,
        Self::RootKwargs,
        Self::RootLeft,
        Self::RootRight,
        Self::RootModule,
        Self::RootDecorators,
        Self::RootObject,
        Self::RootField,
        Self::Inside,
        Self::InsideDecl,
        Self::NotInside,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::RootName => "root.name",
            Self::RootText => "root.text",
            Self::RootArity => "root.arity",
            Self::RootVisibility => "root.visibility",
            Self::RootParameterType => "root.parameter_type",
            Self::RootNotKinds => "root.not_kind",
            Self::RootHas => "root.has",
            Self::RootNotHas => "root.not_has",
            Self::RootCallee => "root.callee",
            Self::RootReceiver => "root.receiver",
            Self::RootArgs => "root.args",
            Self::RootKwargs => "root.kwargs",
            Self::RootLeft => "root.left",
            Self::RootRight => "root.right",
            Self::RootModule => "root.module",
            Self::RootDecorators => "root.decorators",
            Self::RootObject => "root.object",
            Self::RootField => "root.field",
            Self::Inside => "inside",
            Self::InsideDecl => "inside_decl",
            Self::NotInside => "not_inside",
        }
    }

    fn declared_by(self, seed: &CodeQuerySeed) -> bool {
        let root = &seed.root;
        match self {
            Self::RootName => root.name.is_some(),
            Self::RootText => root.text.is_some(),
            Self::RootArity => root.arity.is_some(),
            Self::RootVisibility => !root.visibility.is_empty(),
            Self::RootParameterType => root.parameter_type.is_some(),
            Self::RootNotKinds => !root.not_kinds.is_empty(),
            Self::RootHas => root.has.is_some(),
            Self::RootNotHas => root.not_has.is_some(),
            Self::RootCallee => root.callee.is_some(),
            Self::RootReceiver => root.receiver.is_some(),
            Self::RootArgs => !root.args.is_empty(),
            Self::RootKwargs => !root.kwargs.is_empty(),
            Self::RootLeft => root.left.is_some(),
            Self::RootRight => root.right.is_some(),
            Self::RootModule => root.module.is_some(),
            Self::RootDecorators => !root.decorators.is_empty(),
            Self::RootObject => root.object.is_some(),
            Self::RootField => root.field.is_some(),
            Self::Inside => seed.inside.is_some(),
            Self::InsideDecl => seed.inside_decl.is_some(),
            Self::NotInside => seed.not_inside.is_some(),
        }
    }

    /// Copy this one predicate from the authored seed onto a relaxed one.
    fn restore(self, relaxed: &mut CodeQuerySeed, authored: &CodeQuerySeed) {
        let root = &authored.root;
        match self {
            Self::RootName => relaxed.root.name = root.name.clone(),
            Self::RootText => relaxed.root.text = root.text.clone(),
            Self::RootArity => relaxed.root.arity = root.arity,
            Self::RootVisibility => relaxed.root.visibility = root.visibility.clone(),
            Self::RootParameterType => relaxed.root.parameter_type = root.parameter_type.clone(),
            Self::RootNotKinds => relaxed.root.not_kinds = root.not_kinds.clone(),
            Self::RootHas => relaxed.root.has = root.has.clone(),
            Self::RootNotHas => relaxed.root.not_has = root.not_has.clone(),
            Self::RootCallee => relaxed.root.callee = root.callee.clone(),
            Self::RootReceiver => relaxed.root.receiver = root.receiver.clone(),
            Self::RootArgs => relaxed.root.args = root.args.clone(),
            Self::RootKwargs => relaxed.root.kwargs = root.kwargs.clone(),
            Self::RootLeft => relaxed.root.left = root.left.clone(),
            Self::RootRight => relaxed.root.right = root.right.clone(),
            Self::RootModule => relaxed.root.module = root.module.clone(),
            Self::RootDecorators => relaxed.root.decorators = root.decorators.clone(),
            Self::RootObject => relaxed.root.object = root.object.clone(),
            Self::RootField => relaxed.root.field = root.field.clone(),
            Self::Inside => relaxed.inside = authored.inside.clone(),
            Self::InsideDecl => relaxed.inside_decl = authored.inside_decl.clone(),
            Self::NotInside => relaxed.not_inside = authored.not_inside.clone(),
        }
    }
}

/// The bounded scope one selector's structural seed reduces to.
///
/// `Err` carries the reason the selector has none: either the plan does not
/// start from a structural seed at all, or its root declares no kind union. A
/// root without a kind union has no bounded scope, because relaxing its name
/// would leave a wildcard that matches every node in the workspace -- exactly
/// the whole-repository scan this mode does not do.
fn relaxable_scope(query: &CodeQuery) -> Result<CodeQuerySeed, &'static str> {
    let CodeQueryPlanSource::Seed(seed) = &query.plan.source else {
        return Err(
            "does not start from a structural seed, so it has no kind or language pruning to \
             scope a bounded search by",
        );
    };
    if seed.root.kinds.is_empty() {
        return Err(
            "declares no kind union on its seed root, so relaxing its predicates would leave an \
             unbounded match over every node in the workspace",
        );
    }
    Ok(CodeQuerySeed {
        where_globs: seed.where_globs.clone(),
        languages: seed.languages.clone(),
        root: Pattern {
            kinds: seed.root.kinds.clone(),
            capture: seed.root.capture.clone(),
            ..Pattern::default()
        },
        inside: None,
        inside_decl: None,
        not_inside: None,
    })
}

fn authored_seed(query: &CodeQuery) -> &CodeQuerySeed {
    let CodeQueryPlanSource::Seed(seed) = &query.plan.source else {
        unreachable!("relaxable_scope refuses a non-seed plan source before this is reached")
    };
    seed
}

fn render_scope(seed: &CodeQuerySeed) -> String {
    let kinds = seed
        .root
        .kinds
        .iter()
        .map(|kind| kind.label())
        .collect::<Vec<_>>()
        .join(", ");
    let languages = if seed.languages.is_empty() {
        String::from("every analyzable language")
    } else {
        seed.languages
            .iter()
            .map(|language| language.config_label())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let globs = if seed.where_globs.is_empty() {
        String::from("the whole workspace")
    } else {
        seed.where_globs
            .iter()
            .map(|pattern| pattern.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!("kind [{kinds}] in [{languages}] under [{globs}]")
}

// ---------------------------------------------------------------------------
// The ladder
// ---------------------------------------------------------------------------

/// What satisfying every rung of a ladder means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LadderVerdict {
    /// Every conjunct is the selector itself, so satisfying all of them is
    /// exactly selection: the subject is one the policy reports.
    Selected,
    /// Row-binding membership is not a finding. The plan's joins, group keys
    /// and aggregates still stand between the row and a violation, and this
    /// adapter replays none of them (issue 2509), so a subject that clears
    /// every binding is `unknown`, never `satisfied`.
    MembershipOnly,
}

/// One executable rung: a selector, or a conjunct this adapter cannot replay.
struct LadderRung {
    label: String,
    /// The query this rung runs. `None` for a conjunct that is not replayable,
    /// such as a row-expansion binding.
    query: Option<CodeQuery>,
    execution: PrefixExecution,
    /// Set for a rung that cannot run at all, carrying the reason.
    unreplayable: Option<(String, PolicyIncompleteReason)>,
}

/// The ladder before it runs.
struct LadderPlan {
    rungs: Vec<LadderRung>,
    verdict: LadderVerdict,
    analysis_type: PolicyAnalysisType,
    scope_label: String,
}

impl LadderPlan {
    /// A match policy's ladder: scope, then one rung per declared seed
    /// predicate, ending at the authored selector.
    fn match_selector(policy: &LoadedPolicy) -> Result<Self, ExplainError> {
        let selector = policy
            .resolved_selectors()
            .iter()
            .find(|selector| selector.path.as_str() == MATCH_SELECTOR_PATH)
            .ok_or(ExplainError::SelectorUnavailable)?;
        let scope = relaxable_scope(&selector.query).map_err(|reason| {
            ExplainError::NearMissScopeUnavailable {
                reason: format!("the match policy's selector {reason}"),
            }
        })?;
        let scope_label = render_scope(&scope);
        // The match evaluator reads the analyzer directly and bounds its
        // selector by the finding budget, so a faithful re-execution does too.
        let rungs = relaxation_rungs(&selector.query, scope, PrefixExecution::AnalyzerOnly, "");
        Ok(Self {
            rungs,
            verdict: LadderVerdict::Selected,
            analysis_type: PolicyAnalysisType::Match,
            scope_label,
        })
    }

    /// A relational policy's ladder: the first row binding's source query
    /// relaxed the same way, then one membership rung per further binding, in
    /// plan order.
    fn relational(
        policy: &LoadedPolicy,
        plan: &RelationalAssertionPlan,
    ) -> Result<Self, ExplainError> {
        let Some(first) = plan.bindings.first() else {
            return Err(ExplainError::RelationalPlanUnavailable);
        };
        if !matches!(first.source, RowBindingSource::Query(_)) {
            return Err(ExplainError::NearMissScopeUnavailable {
                reason: format!(
                    "the relational plan's first row binding `{}` is a row expansion, so it \
                     carries no source query to scope a bounded search by",
                    first.name.as_str()
                ),
            });
        }
        let query = binding_query(policy, first)?;
        // The enumeration is the first binding's source query, as issue 2500
        // specifies for a relational plan. When that query is a structural
        // seed its declared predicates also become ladder rungs, which is the
        // cheap filter-satisfaction the ticket asks for; when it is not -- an
        // occurrence, scope, binding, path, generation-site or export source --
        // the authored query is the whole of rung 0 and every rung after it is
        // row-binding membership.
        let (scope_label, mut rungs) = match relaxable_scope(query) {
            Ok(scope) => (
                render_scope(&scope),
                relaxation_rungs(
                    query,
                    scope,
                    PrefixExecution::PreferWorkspace,
                    first.name.as_str(),
                ),
            ),
            Err(_) => (
                format!(
                    "the row binding `{}` source query, which declares no relaxable structural \
                     seed",
                    first.name.as_str()
                ),
                vec![LadderRung {
                    label: format!("binding:{}/scope", first.name.as_str()),
                    query: Some(with_seed_unchanged(query)),
                    execution: PrefixExecution::PreferWorkspace,
                    unreplayable: None,
                }],
            ),
        };
        for binding in plan.bindings.iter().skip(1) {
            rungs.push(match &binding.source {
                RowBindingSource::Query(_) => LadderRung {
                    label: format!("binding:{}", binding.name.as_str()),
                    query: Some(binding_query(policy, binding)?.clone()),
                    execution: PrefixExecution::PreferWorkspace,
                    unreplayable: None,
                },
                RowBindingSource::Expansion { from, step } => LadderRung {
                    label: format!("binding:{}", binding.name.as_str()),
                    query: None,
                    execution: PrefixExecution::PreferWorkspace,
                    unreplayable: Some((
                        format!(
                            "the row expansion `{}` of binding `{from}` is not replayed by this \
                             adapter",
                            step.label()
                        ),
                        PolicyIncompleteReason::CapabilityIncomplete,
                    )),
                },
            });
        }
        Ok(Self {
            rungs,
            verdict: LadderVerdict::MembershipOnly,
            analysis_type: PolicyAnalysisType::Assertion,
            scope_label,
        })
    }

    fn execute(
        &self,
        context: &PolicyEvaluationContext<'_>,
        budget: &PolicyBudget,
        limits: &ExplanationLimits,
    ) -> Ladder {
        let executable = self.rungs.len().min(limits.max_near_miss_executions());
        let mut executed = Vec::with_capacity(executable);
        for rung in self.rungs.iter().take(executable) {
            executed.push(execute_rung(rung, context, budget));
        }
        let omitted =
            u64::try_from(self.rungs.len().saturating_sub(executable)).unwrap_or(u64::MAX);
        Ladder {
            rungs: executed,
            declared_conjuncts: u64::try_from(self.rungs.len()).unwrap_or(u64::MAX),
            omitted_executions: omitted,
        }
    }
}

/// The relaxation rungs of one selector: scope first, then one rung per
/// declared predicate in [`SeedPredicate::ALL`] order.
fn relaxation_rungs(
    authored: &CodeQuery,
    scope: CodeQuerySeed,
    execution: PrefixExecution,
    binding: &str,
) -> Vec<LadderRung> {
    let seed = authored_seed(authored);
    let prefix = if binding.is_empty() {
        String::new()
    } else {
        format!("binding:{binding}/")
    };
    let mut relaxed = scope;
    let mut rungs = vec![LadderRung {
        label: format!("{prefix}scope"),
        query: Some(with_seed(authored, relaxed.clone())),
        execution,
        unreplayable: None,
    }];
    for predicate in SeedPredicate::ALL
        .iter()
        .filter(|predicate| predicate.declared_by(seed))
    {
        predicate.restore(&mut relaxed, seed);
        rungs.push(LadderRung {
            label: format!("{prefix}{}", predicate.label()),
            query: Some(with_seed(authored, relaxed.clone())),
            execution,
            unreplayable: None,
        });
    }
    rungs
}

/// Clone one selector, swap in a relaxed seed, and apply the execution bounds
/// the evaluator would.
///
/// Author-controlled presentation is not policy semantics: the evaluator
/// forces full detail and its own row bound, and a faithful re-execution must
/// do the same.
fn with_seed(authored: &CodeQuery, seed: CodeQuerySeed) -> CodeQuery {
    let mut query = with_seed_unchanged(authored);
    query.plan.source = CodeQueryPlanSource::Seed(Box::new(seed));
    query
}

/// The authored query under the evaluator's execution bounds, with its source
/// left alone.
fn with_seed_unchanged(authored: &CodeQuery) -> CodeQuery {
    let mut query = authored.clone();
    query.result_detail = CodeQueryResultDetail::Full;
    query
}

fn binding_query<'a>(
    policy: &'a LoadedPolicy,
    binding: &RowBinding,
) -> Result<&'a CodeQuery, ExplainError> {
    let path = relational_binding_selector_path(&binding.name);
    policy
        .resolved_selectors()
        .iter()
        .find(|selector| selector.path.as_str() == path)
        .map(|selector| &selector.query)
        .ok_or_else(|| ExplainError::BindingSelectorUnavailable {
            binding: binding.name.as_str().to_string(),
        })
}

/// One executed rung: which subjects it returned, and whether its answer was
/// exhaustive enough to make an absence evidence of absence.
struct ExecutedRung {
    label: String,
    /// Returned rows grouped by workspace-relative path. `None` in the span
    /// slot is a whole-file row.
    rows: HashMap<String, Vec<Option<Range<usize>>>>,
    /// Rows in returned order, kept so enumeration is deterministic.
    ordered: Vec<(WorkspaceRelativePath, Range<usize>)>,
    exhaustive: bool,
    reasons: Vec<PolicyIncompleteReason>,
    /// Set when this rung could not be replayed at all.
    unreplayable: Option<String>,
}

impl ExecutedRung {
    fn covers(&self, candidate: &ExplanationCandidate) -> bool {
        self.rows
            .get(candidate.path().as_str())
            .is_some_and(|spans| {
                spans
                    .iter()
                    .any(|span| row_covers_candidate(span.as_ref(), candidate))
            })
    }
}

fn execute_rung(
    rung: &LadderRung,
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
) -> ExecutedRung {
    if let Some((message, reason)) = &rung.unreplayable {
        return ExecutedRung {
            label: rung.label.clone(),
            rows: HashMap::new(),
            ordered: Vec::new(),
            exhaustive: false,
            reasons: vec![*reason],
            unreplayable: Some(message.clone()),
        };
    }
    let mut query = rung
        .query
        .clone()
        .expect("a replayable rung carries its query");
    // A relaxed rung returns strictly more rows than the authored selector, so
    // the ranking bounds every rung by the caller's pipeline-row budget rather
    // than by the finding budget, and reports the truncation honestly instead
    // of ranking a silent prefix.
    query.limit = budget.query_limits().max_pipeline_rows;
    if query.validate_steps().is_err() {
        return ExecutedRung {
            label: rung.label.clone(),
            rows: HashMap::new(),
            ordered: Vec::new(),
            exhaustive: false,
            reasons: vec![PolicyIncompleteReason::CapabilityIncomplete],
            unreplayable: Some(String::from(
                "the relaxed selector for this conjunct is not executable",
            )),
        };
    }

    let executed = match (rung.execution, context.workspace) {
        (PrefixExecution::PreferWorkspace, Some(workspace)) => {
            execute_code_query_detailed_eager_index_workspace(
                workspace,
                &query,
                budget.query_limits(),
                context.cancellation,
            )
        }
        _ => execute_code_query_detailed_eager_index(
            context.analyzer,
            &query,
            budget.query_limits(),
            context.cancellation,
        ),
    };
    let completion = executed.result.completion();
    let exhaustive = matches!(completion, CodeQueryCompletion::Complete);
    let reasons = absence_reasons(&completion, executed.result.truncated);

    let mut rows: HashMap<String, Vec<Option<Range<usize>>>> = HashMap::new();
    let mut ordered = Vec::new();
    for evidence in &executed.evidence {
        let Some(path) = evidence
            .file
            .rel_path()
            .to_str()
            .and_then(|path| WorkspaceRelativePath::new(path).ok())
        else {
            continue;
        };
        rows.entry(path.as_str().to_string())
            .or_default()
            .push(evidence.byte_span.clone());
        if let Some(span) = evidence.byte_span.as_ref() {
            ordered.push((path, span.clone()));
        }
    }
    ExecutedRung {
        label: rung.label.clone(),
        rows,
        ordered,
        exhaustive,
        reasons,
        unreplayable: None,
    }
}

/// Every rung that ran, plus what the execution bound cut.
struct Ladder {
    rungs: Vec<ExecutedRung>,
    declared_conjuncts: u64,
    omitted_executions: u64,
}

impl Ladder {
    /// The distinct subjects the scope rung returned, in deterministic order.
    fn enumerate_scope_subjects(
        &self,
        scope_label: &str,
    ) -> (Vec<ExplanationCandidate>, NearMissEnumeration) {
        let Some(scope) = self.rungs.first() else {
            return (
                Vec::new(),
                NearMissEnumeration::PolicySeed {
                    scope: scope_label.to_string(),
                    rows: 0,
                    exhaustive: false,
                },
            );
        };
        let mut subjects = scope
            .ordered
            .iter()
            .filter_map(|(path, span)| {
                ExplanationCandidate::in_range(
                    path.as_str(),
                    u64::try_from(span.start).unwrap_or(u64::MAX),
                    u64::try_from(span.end).unwrap_or(u64::MAX),
                )
                .ok()
            })
            .collect::<Vec<_>>();
        subjects.sort_by(candidate_order);
        subjects.dedup();
        let rows = u64::try_from(subjects.len()).unwrap_or(u64::MAX);
        (
            subjects,
            NearMissEnumeration::PolicySeed {
                scope: scope_label.to_string(),
                rows,
                exhaustive: scope.exhaustive,
            },
        )
    }

    /// Where one subject stopped satisfying the ladder.
    fn measure(&self, candidate: &ExplanationCandidate, verdict: LadderVerdict) -> Measurement {
        for (index, rung) in self.rungs.iter().enumerate() {
            if let Some(message) = &rung.unreplayable {
                return Measurement {
                    satisfied: u64::try_from(index).unwrap_or(u64::MAX),
                    outcome: ExplanationOutcome::Unknown,
                    failing: Some(rung.label.clone()),
                    reasons: rung.reasons.clone(),
                    actual: message.clone(),
                };
            }
            if rung.covers(candidate) {
                continue;
            }
            let satisfied = u64::try_from(index).unwrap_or(u64::MAX);
            return if rung.exhaustive {
                Measurement {
                    satisfied,
                    outcome: ExplanationOutcome::Failed,
                    failing: Some(rung.label.clone()),
                    reasons: Vec::new(),
                    actual: format!(
                        "the exhaustive rung `{}` returned no row covering the subject",
                        rung.label
                    ),
                }
            } else {
                Measurement {
                    satisfied,
                    outcome: ExplanationOutcome::Unknown,
                    failing: Some(rung.label.clone()),
                    reasons: rung.reasons.clone(),
                    actual: format!(
                        "the rung `{}` returned no row covering the subject, from a \
                         non-exhaustive query",
                        rung.label
                    ),
                }
            };
        }
        let executed = u64::try_from(self.rungs.len()).unwrap_or(u64::MAX);
        if executed < self.declared_conjuncts {
            return Measurement {
                satisfied: executed,
                outcome: ExplanationOutcome::Unknown,
                failing: None,
                reasons: vec![PolicyIncompleteReason::ReportRetentionBudget],
                actual: String::from(
                    "the execution limit stopped the ladder before every declared conjunct ran",
                ),
            };
        }
        match verdict {
            LadderVerdict::Selected => Measurement {
                satisfied: executed,
                outcome: ExplanationOutcome::Satisfied,
                failing: None,
                reasons: Vec::new(),
                actual: String::from("every declared conjunct retains the subject"),
            },
            LadderVerdict::MembershipOnly => Measurement {
                satisfied: executed,
                outcome: ExplanationOutcome::Unknown,
                failing: None,
                reasons: vec![PolicyIncompleteReason::CapabilityIncomplete],
                actual: String::from(
                    "every row binding contains a row covering the subject; whether those rows \
                     join into a violated group is not replayed by this adapter",
                ),
            },
        }
    }
}

struct Measurement {
    satisfied: u64,
    outcome: ExplanationOutcome,
    failing: Option<String>,
    reasons: Vec<PolicyIncompleteReason>,
    actual: String,
}

fn candidate_order(
    left: &ExplanationCandidate,
    right: &ExplanationCandidate,
) -> std::cmp::Ordering {
    left.path()
        .as_str()
        .cmp(right.path().as_str())
        .then(left.byte_start().cmp(&right.byte_start()))
        .then(left.byte_end().cmp(&right.byte_end()))
}

/// Ranking order among outcomes. A decided answer precedes an undecided one at
/// the same distance; the outcome never changes the distance itself.
const fn outcome_rank(outcome: ExplanationOutcome) -> u8 {
    match outcome {
        ExplanationOutcome::Satisfied => 0,
        ExplanationOutcome::Failed => 1,
        ExplanationOutcome::Unknown => 2,
    }
}

fn build_ranking(
    policy: &LoadedPolicy,
    plan: LadderPlan,
    ladder: Ladder,
    subjects: Vec<ExplanationCandidate>,
    enumeration: NearMissEnumeration,
    limits: &ExplanationLimits,
) -> PolicyNearMissRanking {
    let declared = ladder.declared_conjuncts;
    let mut measured = subjects
        .iter()
        .map(|candidate| {
            let measurement = ladder.measure(candidate, plan.verdict);
            (candidate, measurement)
        })
        .collect::<Vec<_>>();
    measured.sort_by(|(left_candidate, left), (right_candidate, right)| {
        let left_distance = declared.saturating_sub(left.satisfied);
        let right_distance = declared.saturating_sub(right.satisfied);
        left_distance
            .cmp(&right_distance)
            .then(outcome_rank(left.outcome).cmp(&outcome_rank(right.outcome)))
            .then(candidate_order(left_candidate, right_candidate))
    });

    let considered = u64::try_from(measured.len()).unwrap_or(u64::MAX);
    let mut truncation = NearMissTruncation::default();
    truncation.omit_executions(ladder.omitted_executions);

    let mut entries = Vec::new();
    let mut bytes_used = 0usize;
    for (index, (candidate, measurement)) in measured.into_iter().enumerate() {
        if index >= limits.max_near_miss_candidates() {
            truncation.omit_candidates(1);
            continue;
        }
        let mut failing = measurement.failing;
        let mut actual = measurement.actual;
        if let Some(failing) = failing.as_mut() {
            truncation.omit_text_bytes(truncate_text_to(failing, limits.max_text_bytes()));
        }
        truncation.omit_text_bytes(truncate_text_to(&mut actual, limits.max_text_bytes()));
        let entry = NearMissEntry {
            rank: u64::try_from(entries.len().saturating_add(1)).unwrap_or(u64::MAX),
            subject: ExplanationSubject::Candidate {
                path: candidate.path().as_str().to_string(),
                byte_start: candidate.byte_start(),
                byte_end: candidate.byte_end(),
            },
            outcome: measurement.outcome,
            declared_conjuncts: declared,
            satisfied_conjuncts: measurement.satisfied,
            unsatisfied_conjuncts: declared.saturating_sub(measurement.satisfied),
            failing_conjunct: failing,
            reasons: measurement.reasons,
            actual,
        };
        let entry_bytes = entry.own_bytes();
        if bytes_used.saturating_add(entry_bytes) > limits.max_retained_bytes() {
            truncation.omit_candidates(1);
            truncation.omit_bytes(u64::try_from(entry_bytes).unwrap_or(u64::MAX));
            continue;
        }
        bytes_used = bytes_used.saturating_add(entry_bytes);
        entries.push(entry);
    }

    PolicyNearMissRanking {
        format: POLICY_NEAR_MISS_FORMAT,
        question: ExplanationQuestion::NearMiss,
        policy_id: policy.definition().metadata.id.clone(),
        policy_hash: policy.semantic_hash(),
        analysis_type: plan.analysis_type,
        enumeration,
        conjuncts: plan.rungs.iter().map(|rung| rung.label.clone()).collect(),
        candidates_considered: considered,
        executions_used: u64::try_from(ladder.rungs.len()).unwrap_or(u64::MAX),
        entries,
        truncation,
    }
}
