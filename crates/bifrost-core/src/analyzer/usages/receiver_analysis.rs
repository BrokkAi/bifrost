//! Demand-driven receiver/value analysis contracts.
//!
//! This module owns the shared object-sensitive vocabulary for issue #394. It
//! deliberately does not walk any language ASTs; language-specific providers
//! implement the trait and return these bounded outcomes.

#![allow(dead_code)]

use crate::analyzer::{CodeUnit, Language, ProjectFile, Range};
use crate::cancellation::CancellationToken;
use std::any::Any;
use std::sync::Arc;

pub const DEFAULT_RECEIVER_CONTEXT_DEPTH: usize = 1;
pub const DEFAULT_RECEIVER_MAX_TARGETS: usize = 4;
pub const DEFAULT_RECEIVER_MAX_SUMMARY_EXPANSIONS: usize = 64;
// Native Go/JVM/Rust point and receiver calibration used at most 147 rounds.
// Four times that maximum, rounded up to a power of two, is 1024.
pub const DEFAULT_RECEIVER_MAX_RESOLUTION_ROUNDS: usize = 1_024;
pub const DEFAULT_RECEIVER_MAX_SCOPE_NODES: usize = 20_000;
pub const DEFAULT_RECEIVER_MAX_HIERARCHY_ORDER_STEPS: usize = DEFAULT_RECEIVER_MAX_SCOPE_NODES;

/// Budget for one interactive `get_type_by_location` request.
///
/// The receiver-query default above is sized for one receiver among many inside
/// a larger graph analysis, where an expensive site must not starve its
/// neighbors. An interactive type lookup is the user's whole request: it runs
/// once, for one location, and a wrong "no type" from an early cutoff costs
/// more than the extra work. Each axis is therefore several times the default,
/// while still bounding a pathological site to a fixed amount of work.
pub const INTERACTIVE_TYPE_LOOKUP_BUDGET: ReceiverAnalysisBudget = ReceiverAnalysisBudget {
    context_depth: 2,
    max_targets: 32,
    max_summary_expansions: 256,
    max_resolution_rounds: DEFAULT_RECEIVER_MAX_RESOLUTION_ROUNDS,
    max_scope_nodes: 200_000,
    max_hierarchy_order_steps: 200_000,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReceiverAnalysisOutcome<T> {
    Precise(Vec<T>),
    Ambiguous(Vec<T>),
    Unknown,
    Unsupported { reason: &'static str },
    ExceededBudget { limit: &'static str },
}

impl<T> ReceiverAnalysisOutcome<T> {
    pub fn values(&self) -> Option<&[T]> {
        match self {
            Self::Precise(values) | Self::Ambiguous(values) => Some(values),
            Self::Unknown | Self::Unsupported { .. } | Self::ExceededBudget { .. } => None,
        }
    }

    fn truncate_values(&mut self, limit: usize) {
        match self {
            Self::Precise(values) | Self::Ambiguous(values) => values.truncate(limit),
            Self::Unknown | Self::Unsupported { .. } | Self::ExceededBudget { .. } => {}
        }
    }

    pub fn is_precise(&self) -> bool {
        matches!(self, Self::Precise(_))
    }

    pub fn is_terminal_for_graph(&self) -> bool {
        matches!(
            self,
            Self::Ambiguous(_) | Self::Unsupported { .. } | Self::ExceededBudget { .. }
        )
    }

    pub fn into_precise(self) -> Option<Vec<T>> {
        match self {
            Self::Precise(values) => Some(values),
            Self::Ambiguous(_)
            | Self::Unknown
            | Self::Unsupported { .. }
            | Self::ExceededBudget { .. } => None,
        }
    }
}

fn unique_targets_within_budget<T: Eq>(
    values: impl IntoIterator<Item = T>,
    max_targets: usize,
) -> Result<Vec<T>, Vec<T>> {
    let mut unique = Vec::new();
    for value in values {
        if unique.contains(&value) {
            continue;
        }
        unique.push(value);
        if unique.len() > max_targets {
            return Err(unique);
        }
    }
    Ok(unique)
}

impl<T> ReceiverAnalysisOutcome<T>
where
    T: Eq,
{
    pub fn bounded_precise(
        values: impl IntoIterator<Item = T>,
        budget: ReceiverAnalysisBudget,
    ) -> Self {
        let unique = match unique_targets_within_budget(values, budget.max_targets) {
            Ok(unique) => unique,
            Err(unique) => return Self::Ambiguous(unique),
        };
        if unique.is_empty() {
            Self::Unknown
        } else {
            Self::Precise(unique)
        }
    }

    pub fn single_precise_or_ambiguous(
        values: impl IntoIterator<Item = T>,
        budget: ReceiverAnalysisBudget,
    ) -> Self {
        let unique = match unique_targets_within_budget(values, budget.max_targets) {
            Ok(unique) => unique,
            Err(unique) => return Self::Ambiguous(unique),
        };
        match unique.len() {
            0 => Self::Unknown,
            1 => Self::Precise(unique),
            _ => Self::Ambiguous(unique),
        }
    }

    pub fn merge_branch_outcomes(
        outcomes: impl IntoIterator<Item = Self>,
        budget: ReceiverAnalysisBudget,
    ) -> Self {
        let mut values = Vec::new();
        let mut saw_non_precise = false;
        for outcome in outcomes {
            match outcome {
                Self::Precise(mut precise) => values.append(&mut precise),
                Self::Ambiguous(mut ambiguous) => {
                    saw_non_precise = true;
                    values.append(&mut ambiguous);
                }
                Self::Unknown => saw_non_precise = true,
                Self::Unsupported { reason } => return Self::Unsupported { reason },
                Self::ExceededBudget { limit } => return Self::ExceededBudget { limit },
            }
        }
        if values.is_empty() {
            return Self::Unknown;
        }
        let merged = Self::single_precise_or_ambiguous(values, budget);
        if saw_non_precise {
            match merged {
                Self::Precise(values) | Self::Ambiguous(values) => Self::Ambiguous(values),
                other => other,
            }
        } else {
            merged
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReceiverValue {
    AllocationSite {
        ty: CodeUnit,
        file: ProjectFile,
        range: Range,
    },
    InstanceType(CodeUnit),
    ClassOrStaticObject(CodeUnit),
    ModuleOrExportObject(CodeUnit),
    CurrentReceiver(CodeUnit),
    FactoryReturn {
        factory: CodeUnit,
        value: Box<ReceiverValue>,
    },
}

impl ReceiverValue {
    pub fn owner(&self) -> &CodeUnit {
        match self {
            ReceiverValue::AllocationSite { ty, .. }
            | ReceiverValue::InstanceType(ty)
            | ReceiverValue::ClassOrStaticObject(ty)
            | ReceiverValue::ModuleOrExportObject(ty)
            | ReceiverValue::CurrentReceiver(ty) => ty,
            ReceiverValue::FactoryReturn { value, .. } => value.owner(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReceiverAnalysisBudget {
    pub context_depth: usize,
    pub max_targets: usize,
    /// Distinct owner/summary expansions within one query.
    pub max_summary_expansions: usize,
    /// Typed convergence and lexical frontier iterations within one query.
    pub max_resolution_rounds: usize,
    pub max_scope_nodes: usize,
    /// Optional hierarchy discharge ordering; exhaustion never stops aggregate resolution.
    pub max_hierarchy_order_steps: usize,
}

impl Default for ReceiverAnalysisBudget {
    fn default() -> Self {
        Self {
            context_depth: DEFAULT_RECEIVER_CONTEXT_DEPTH,
            max_targets: DEFAULT_RECEIVER_MAX_TARGETS,
            max_summary_expansions: DEFAULT_RECEIVER_MAX_SUMMARY_EXPANSIONS,
            max_resolution_rounds: DEFAULT_RECEIVER_MAX_RESOLUTION_ROUNDS,
            max_scope_nodes: DEFAULT_RECEIVER_MAX_SCOPE_NODES,
            max_hierarchy_order_steps: DEFAULT_RECEIVER_MAX_HIERARCHY_ORDER_STEPS,
        }
    }
}

impl ReceiverAnalysisBudget {
    pub fn tiny() -> Self {
        Self {
            context_depth: 0,
            max_targets: 1,
            max_summary_expansions: 1,
            max_resolution_rounds: 1,
            max_scope_nodes: 1,
            max_hierarchy_order_steps: 1,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ReceiverContext<'a> {
    pub enclosing_unit: Option<&'a CodeUnit>,
    pub byte: usize,
    pub context_depth: usize,
}

impl<'a> ReceiverContext<'a> {
    pub fn new(enclosing_unit: Option<&'a CodeUnit>, byte: usize) -> Self {
        Self {
            enclosing_unit,
            byte,
            context_depth: DEFAULT_RECEIVER_CONTEXT_DEPTH,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ReceiverAnalysisQuery<'a> {
    pub language: Language,
    pub file: &'a ProjectFile,
    pub receiver_text: &'a str,
    pub receiver_range: Option<Range>,
    pub member_name: Option<&'a str>,
    pub context: ReceiverContext<'a>,
    pub budget: ReceiverAnalysisBudget,
}

#[derive(Debug, Clone, Copy)]
pub struct ReceiverSummaryQuery<'a> {
    pub language: Language,
    pub file: &'a ProjectFile,
    pub call_text: &'a str,
    pub call_range: Option<Range>,
    pub callee: Option<&'a CodeUnit>,
    pub context: ReceiverContext<'a>,
    pub budget: ReceiverAnalysisBudget,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReceiverAnalysisCacheKey {
    pub language: Language,
    pub file: ProjectFile,
    pub start_byte: usize,
    pub end_byte: usize,
    pub member_name: Option<String>,
    pub context_depth: usize,
    pub max_targets: usize,
    pub max_summary_expansions: usize,
    pub max_resolution_rounds: usize,
    pub max_scope_nodes: usize,
    pub max_hierarchy_order_steps: usize,
}

impl ReceiverAnalysisCacheKey {
    pub fn for_receiver(query: &ReceiverAnalysisQuery<'_>) -> Self {
        let (start_byte, end_byte) = query
            .receiver_range
            .map(|range| (range.start_byte, range.end_byte))
            .unwrap_or((query.context.byte, query.context.byte));
        Self {
            language: query.language,
            file: query.file.clone(),
            start_byte,
            end_byte,
            member_name: query.member_name.map(str::to_string),
            context_depth: query.context.context_depth,
            max_targets: query.budget.max_targets,
            max_summary_expansions: query.budget.max_summary_expansions,
            max_resolution_rounds: query.budget.max_resolution_rounds,
            max_scope_nodes: query.budget.max_scope_nodes,
            max_hierarchy_order_steps: query.budget.max_hierarchy_order_steps,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiverAnalysisBudgetTracker {
    budget: ReceiverAnalysisBudget,
    summary_expansions: usize,
    scope_nodes: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ReceiverAnalysisWork {
    pub setup_nodes: usize,
    pub summary_expansions: usize,
    pub resolution_rounds: usize,
    pub scope_nodes: usize,
}

impl ReceiverAnalysisWork {
    /// Combine independently measured work without charging or clamping budgets.
    pub fn saturating_add(self, other: Self) -> Self {
        Self {
            setup_nodes: self.setup_nodes.saturating_add(other.setup_nodes),
            summary_expansions: self
                .summary_expansions
                .saturating_add(other.summary_expansions),
            resolution_rounds: self
                .resolution_rounds
                .saturating_add(other.resolution_rounds),
            scope_nodes: self.scope_nodes.saturating_add(other.scope_nodes),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverAnalysisReport<T> {
    pub outcome: ReceiverAnalysisOutcome<T>,
    pub work: ReceiverAnalysisWork,
    pub candidates_truncated: bool,
}

/// The proof that a receiver expression denotes one exact value identity at a
/// member-access site. Static type resolution alone is not such a proof: a
/// mutable binding can retain the same declared type after being reassigned to
/// a different runtime value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReceiverIdentityProof {
    /// Bounded receiver/value analysis produced one complete value identity.
    ExactValueAnalysis,
    /// The receiver syntax names one exact static type declaration.
    ExactStaticTypeReference,
    /// The receiver is a simple identifier bound by one immutable declaration.
    ImmutableBinding {
        file: ProjectFile,
        declaration_range: Range,
    },
}

/// A member-target resolution together with the receiver it was resolved against. The
/// caller re-derives the member expression to validate the site; the provider re-derives it
/// to answer, and reports back which receiver and member name it actually used so the two
/// cannot silently disagree about the site being described.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverMemberTargetReport {
    pub receiver_range: Range,
    pub member_range: Range,
    pub member_name: String,
    pub receiver_analysis: ReceiverAnalysisReport<ReceiverValue>,
    pub receiver_identity: ReceiverAnalysisReport<ReceiverIdentityProof>,
    pub analysis: ReceiverAnalysisReport<CodeUnit>,
}

impl<T> ReceiverAnalysisReport<T> {
    pub fn without_work(
        mut outcome: ReceiverAnalysisOutcome<T>,
        budget: ReceiverAnalysisBudget,
    ) -> Self {
        let candidates_truncated = outcome
            .values()
            .is_some_and(|values| values.len() > budget.max_targets);
        if candidates_truncated {
            crate::analyzer::carried_context::mark_execution_dependent();
            outcome.truncate_values(budget.max_targets);
        }
        Self {
            outcome,
            work: ReceiverAnalysisWork::default(),
            candidates_truncated,
        }
    }
}

impl ReceiverAnalysisBudgetTracker {
    pub fn new(budget: ReceiverAnalysisBudget) -> Self {
        Self {
            budget,
            summary_expansions: 0,
            scope_nodes: 0,
        }
    }

    pub fn record_summary_expansion(&mut self) -> Result<(), ReceiverBudgetLimit> {
        self.summary_expansions += 1;
        if !crate::analyzer::work_budget::LimitedCounter::from_usage(
            self.summary_expansions,
            self.budget.max_summary_expansions,
        )
        .allows(0)
        {
            Err(ReceiverBudgetLimit::SummaryExpansions)
        } else {
            Ok(())
        }
    }

    pub fn record_scope_node(&mut self) -> Result<(), ReceiverBudgetLimit> {
        self.scope_nodes += 1;
        if !crate::analyzer::work_budget::LimitedCounter::from_usage(
            self.scope_nodes,
            self.budget.max_scope_nodes,
        )
        .allows(0)
        {
            Err(ReceiverBudgetLimit::ScopeNodes)
        } else {
            Ok(())
        }
    }

    pub fn work(&self) -> ReceiverAnalysisWork {
        ReceiverAnalysisWork {
            setup_nodes: 0,
            summary_expansions: self.summary_expansions,
            resolution_rounds: 0,
            scope_nodes: self.scope_nodes,
        }
    }

    pub fn report<T>(&self, mut outcome: ReceiverAnalysisOutcome<T>) -> ReceiverAnalysisReport<T> {
        let candidates_truncated = outcome
            .values()
            .is_some_and(|values| values.len() > self.budget.max_targets);
        if candidates_truncated {
            crate::analyzer::carried_context::mark_execution_dependent();
            outcome.truncate_values(self.budget.max_targets);
        }
        ReceiverAnalysisReport {
            outcome,
            work: self.work(),
            candidates_truncated,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReceiverBudgetLimit {
    SummaryExpansions,
    ResolutionRounds,
    ScopeNodes,
    TotalWork,
}

impl ReceiverBudgetLimit {
    pub fn as_str(self) -> &'static str {
        match self {
            ReceiverBudgetLimit::SummaryExpansions => "summary_expansions",
            ReceiverBudgetLimit::ResolutionRounds => "resolution_rounds",
            ReceiverBudgetLimit::ScopeNodes => "scope_nodes",
            ReceiverBudgetLimit::TotalWork => "total_work",
        }
    }

    pub fn exceeded<T>(self) -> ReceiverAnalysisOutcome<T> {
        ReceiverAnalysisOutcome::ExceededBudget {
            limit: self.as_str(),
        }
    }
}

pub trait ReceiverFactProvider {
    fn resolve_receiver(
        &self,
        query: ReceiverAnalysisQuery<'_>,
    ) -> ReceiverAnalysisOutcome<ReceiverValue>;

    fn summarize_call_result(
        &self,
        query: ReceiverSummaryQuery<'_>,
    ) -> ReceiverAnalysisOutcome<ReceiverValue>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoopReceiverFactProvider;

impl ReceiverFactProvider for NoopReceiverFactProvider {
    fn resolve_receiver(
        &self,
        _query: ReceiverAnalysisQuery<'_>,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        ReceiverAnalysisOutcome::Unknown
    }

    fn summarize_call_result(
        &self,
        _query: ReceiverSummaryQuery<'_>,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        ReceiverAnalysisOutcome::Unknown
    }
}

/// Per-file receiver state a language builds once and reuses across the receiver queries of
/// one request.
///
/// Opaque to the framework, which only stores it: the language that produced it is the only
/// thing that reads it back. Retention is the point -- the JS/TS index and import binder
/// cost a full tree walk each, so a query service prepares a file once and every later query
/// against that file borrows the same value.
pub struct ReceiverFileFacts(Arc<dyn Any + Send + Sync>);

impl ReceiverFileFacts {
    pub fn new<T: Any + Send + Sync>(facts: T) -> Self {
        Self(Arc::new(facts))
    }

    /// `None` when `T` is not the type the producing language stored. The
    /// framework cannot know which type that is, so the invariant "read it back
    /// as what you wrote" belongs to the language that registered the factory,
    /// and only that caller can fail on a mismatch.
    pub fn downcast<T: Any + Send + Sync>(&self) -> Option<&T> {
        self.0.downcast_ref()
    }
}

/// What preparing one file for receiver queries produced, or why it produced nothing.
///
/// The three failure shapes are distinct observable outcomes, not degrees of one: an
/// unparseable file is reported as unsupported, an oversized one charges its partial
/// traversal and reports a budget limit, and a cancelled one aborts the query.
pub enum ReceiverFileSetup {
    Ready {
        tree: tree_sitter::Tree,
        facts: ReceiverFileFacts,
        /// Nodes the setup traversal visited, charged against the query's scope budget.
        visited: usize,
    },
    ParseFailed,
    ExceededScope {
        visited: usize,
    },
    Cancelled,
}

pub struct ReceiverFileCtx<'a> {
    pub file: &'a ProjectFile,
    pub language: Language,
    pub source: &'a str,
    pub max_scope_nodes: usize,
    pub cancellation: Option<&'a CancellationToken>,
}

/// The operations a receiver query performs against one prepared file.
///
/// `'tree` is a trait parameter rather than a per-method one because an implementation
/// borrows exactly one tree: a method-level `'tree` would demand an implementation valid for
/// every tree, which a provider holding a root node cannot be.
pub trait ReceiverFacts<'tree> {
    /// The member expression this site names, or `None` when the site is not a member
    /// access at all.
    fn member_expression_at_site(
        &self,
        node: tree_sitter::Node<'tree>,
    ) -> Option<tree_sitter::Node<'tree>>;

    fn resolve_receiver(
        &self,
        node: tree_sitter::Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisReport<ReceiverValue>;

    /// `None` means `site` is not a member access; the caller validates the site first, so
    /// reaching `None` after that validation is a contradiction the caller treats as a bug.
    fn resolve_member_targets_at_site(
        &self,
        site: tree_sitter::Node<'tree>,
        expected_member: Option<&str>,
        before_byte: usize,
        budget: ReceiverAnalysisBudget,
    ) -> Option<ReceiverMemberTargetReport>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_precise_returns_unknown_for_empty_values() {
        let outcome = ReceiverAnalysisOutcome::<ReceiverValue>::bounded_precise(
            [],
            ReceiverAnalysisBudget::default(),
        );

        assert_eq!(outcome, ReceiverAnalysisOutcome::Unknown);
    }
}
