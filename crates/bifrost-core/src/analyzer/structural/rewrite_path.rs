//! The bounded rewrite-domain contract: what one structured rewrite chase
//! walks, what one step of it did, and how the chase terminated (issue #1480).
//!
//! A *rewrite domain* is a declared finite state space with a rewrite rule.
//! Three things make a chase over it analysable rather than merely terminating:
//!
//! 1. A **semantic state key** per step. The rewritten object usually grows on
//!    every hop, so it can never repeat; the state that actually cycles is
//!    smaller. In the first domain -- the Rust import-alias chase -- the
//!    rewrite replaces only the specifier's root, so the specifier grows every
//!    hop and a whole-string visited set never trips; the cycle lives in root
//!    space (mined commit `9deded6f5`).
//! 2. A **declared finite bound**: the size of the state space the chase walks,
//!    named by the chase itself rather than an arbitrary iteration cap.
//! 3. An **explicit terminal outcome**: [`RewriteOutcome::Converged`] with the
//!    fixed point, [`RewriteOutcome::Cycle`] with the ordered repeated-state
//!    witness, or [`RewriteOutcome::ExceededBudget`] with the work performed.
//!
//! The three outcomes are deliberately distinct values and mean different
//! things to a consumer: a cycle is a concrete counterexample, convergence is a
//! positive answer, and budget exhaustion is *absence of evidence* -- it is
//! never a finding, only an unreliable result.
//!
//! This vocabulary lives in `brokk-bifrost-core` because the production chase
//! that emits steps (`brokk-bifrost-rust`) and the query registry that spells
//! these values (`brokk-bifrost-rql`) are sibling crates, and neither may own
//! a private spelling table the other copies.

use super::occurrences::labelled_enum;
use crate::analyzer::{ProjectFile, Range};
use serde::{Deserialize, Serialize};
use std::fmt;

labelled_enum! {
    /// One declared finite rewrite domain.
    ///
    /// Extensible by construction: a second domain is a new variant plus its
    /// own production chase, and every consumer that spells a domain reads
    /// this table. A domain earns a variant only when a real chase declares
    /// its semantic state key and its bound.
    RewriteDomainKind, ALL_REWRITE_DOMAIN_KINDS {
        RustImportAlias => "rust_import_alias",
    }
}

impl RewriteDomainKind {
    /// What the domain's semantic state key is, for hover, docs and tests.
    pub const fn state_key_description(self) -> &'static str {
        match self {
            Self::RustImportAlias => {
                "the leading segment (root) of the module specifier, because the rewrite replaces \
                 only the root and the specifier grows every hop"
            }
        }
    }

    /// What the domain's declared bound counts.
    pub const fn bound_description(self) -> &'static str {
        match self {
            Self::RustImportAlias => {
                "the number of roots the importing file's import binder can rewrite"
            }
        }
    }
}

labelled_enum! {
    /// How a bounded chase terminated.
    ///
    /// Only [`Self::Cycle`] carries a counterexample. [`Self::ExceededBudget`]
    /// is absence of evidence and must map to an unreliable result, never to a
    /// finding and never to a clean pass.
    RewriteOutcomeKind, ALL_REWRITE_OUTCOME_KINDS {
        Converged => "converged",
        Cycle => "cycle",
        ExceededBudget => "exceeded_budget",
    }
}

/// The human-stable rule label of the Rust import-alias substitution step.
///
/// A rule label names *which* rewrite fired, so a step sequence reads as a
/// derivation rather than as a list of strings. It is free-form text, not a
/// constrained value: a domain may add rules without touching the query
/// vocabulary.
pub const ALIAS_SUBSTITUTION_RULE: &str = "alias-substitution";

/// One rewrite step: the state it was taken from, what it rewrote, and which
/// rule fired.
///
/// `state_key` is the semantic state of the *input*, which is what the cycle
/// check keys on. `input` and `output` are the full rewritten objects, which
/// may grow without bound and therefore cannot be the state key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteStep {
    pub state_key: String,
    pub input: String,
    pub output: String,
    pub rule: &'static str,
}

/// How one chase terminated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RewriteOutcome {
    /// The chase reached a state no rule rewrites. `fixed_point` is the object
    /// the chase stopped on -- the answer the production resolution then used.
    Converged { fixed_point: String },
    /// A semantic state repeated. `witness` is the ordered state-key sequence,
    /// whose last element repeats an earlier one and closes the cycle, so a
    /// reader can replay the loop.
    Cycle { witness: Vec<String> },
    /// The declared bound was reached while a rewrite was still available.
    /// `explored` is the number of steps taken. This is not evidence of a
    /// cycle and not evidence of convergence.
    ExceededBudget { explored: usize },
}

impl RewriteOutcome {
    /// The constrained value a query filters on.
    pub const fn kind(&self) -> RewriteOutcomeKind {
        match self {
            Self::Converged { .. } => RewriteOutcomeKind::Converged,
            Self::Cycle { .. } => RewriteOutcomeKind::Cycle,
            Self::ExceededBudget { .. } => RewriteOutcomeKind::ExceededBudget,
        }
    }

    /// The fixed point of a converged chase.
    pub fn fixed_point(&self) -> Option<&str> {
        match self {
            Self::Converged { fixed_point } => Some(fixed_point),
            Self::Cycle { .. } | Self::ExceededBudget { .. } => None,
        }
    }

    /// The ordered repeated-state witness of a cycle.
    pub fn witness(&self) -> &[String] {
        match self {
            Self::Cycle { witness } => witness,
            Self::Converged { .. } | Self::ExceededBudget { .. } => &[],
        }
    }

    /// The steps a budget-exhausted chase performed.
    pub fn explored(&self) -> Option<usize> {
        match self {
            Self::ExceededBudget { explored } => Some(*explored),
            Self::Converged { .. } | Self::Cycle { .. } => None,
        }
    }
}

/// The step collector a production chase writes into when it is instrumented.
///
/// The chase that resolves and the chase that records are the same loop: this
/// is passed as `Option<&mut RewriteTrace>` and every recording site is a no-op
/// when it is absent, so an uninstrumented resolution allocates nothing here
/// and takes the same branches.
#[derive(Debug, Default)]
pub struct RewriteTrace {
    steps: Vec<RewriteStep>,
    outcome: Option<RewriteOutcome>,
    declared_bound: usize,
}

impl RewriteTrace {
    /// The bound the chase declared for itself, once it knows it.
    pub fn declare_bound(&mut self, bound: usize) {
        self.declared_bound = bound;
    }

    pub fn record_step(&mut self, step: RewriteStep) {
        self.steps.push(step);
    }

    /// Record how the chase terminated. The first terminal wins: a chase has
    /// exactly one outcome, and a later caller must not overwrite it.
    pub fn finish(&mut self, outcome: RewriteOutcome) {
        debug_assert!(
            self.outcome.is_none(),
            "a bounded chase terminates once; {:?} would overwrite {:?}",
            outcome,
            self.outcome
        );
        if self.outcome.is_none() {
            self.outcome = Some(outcome);
        }
    }

    pub fn declared_bound(&self) -> usize {
        self.declared_bound
    }

    pub fn steps(&self) -> &[RewriteStep] {
        &self.steps
    }

    /// The recorded outcome, or `None` when the chase never engaged the
    /// rewrite rule at all.
    pub fn outcome(&self) -> Option<&RewriteOutcome> {
        self.outcome.as_ref()
    }

    /// Consume the trace into its parts, for the derivation that turns one
    /// chase into one row.
    pub fn into_parts(self) -> (usize, Vec<RewriteStep>, Option<RewriteOutcome>) {
        (self.declared_bound, self.steps, self.outcome)
    }
}

/// Where one chase started: the file whose analysis engaged it, the object it
/// started from, and the source range that spells that object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteOrigin {
    pub file: ProjectFile,
    /// The object the chase started from, exactly as the source spells it.
    pub specifier: String,
    pub range: Range,
}

/// One bounded chase through one rewrite domain.
///
/// `declared_bound` is the domain's own finite bound, not an arbitrary cap, and
/// `steps` is the ordered derivation that bound governs. `generation` is the
/// workspace generation the chase ran in, so two rows from two snapshots are
/// never silently compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewritePath {
    pub domain: RewriteDomainKind,
    pub origin: RewriteOrigin,
    pub declared_bound: usize,
    pub steps: Vec<RewriteStep>,
    pub outcome: RewriteOutcome,
    pub generation: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_vocabulary_round_trips_its_labels() {
        for domain in ALL_REWRITE_DOMAIN_KINDS {
            assert_eq!(RewriteDomainKind::from_label(domain.label()), Some(*domain));
            assert!(!domain.state_key_description().is_empty());
            assert!(!domain.bound_description().is_empty());
        }
        for outcome in ALL_REWRITE_OUTCOME_KINDS {
            assert_eq!(
                RewriteOutcomeKind::from_label(outcome.label()),
                Some(*outcome)
            );
        }
    }

    #[test]
    fn each_outcome_carries_only_its_own_payload() {
        let converged = RewriteOutcome::Converged {
            fixed_point: "c::d".to_string(),
        };
        assert_eq!(converged.kind(), RewriteOutcomeKind::Converged);
        assert_eq!(converged.fixed_point(), Some("c::d"));
        assert!(converged.witness().is_empty());
        assert_eq!(converged.explored(), None);

        let cycle = RewriteOutcome::Cycle {
            witness: vec!["c".to_string(), "a".to_string(), "c".to_string()],
        };
        assert_eq!(cycle.kind(), RewriteOutcomeKind::Cycle);
        assert_eq!(cycle.fixed_point(), None);
        assert_eq!(cycle.witness().len(), 3);
        assert_eq!(
            cycle.witness().first(),
            cycle.witness().last(),
            "the last state closes the cycle it repeats"
        );

        let exceeded = RewriteOutcome::ExceededBudget { explored: 4 };
        assert_eq!(exceeded.kind(), RewriteOutcomeKind::ExceededBudget);
        assert_eq!(exceeded.explored(), Some(4));
        assert_eq!(exceeded.fixed_point(), None);
    }

    #[test]
    fn a_trace_records_one_terminal_outcome_and_its_steps() {
        let mut trace = RewriteTrace::default();
        assert_eq!(trace.outcome(), None);
        trace.declare_bound(3);
        trace.record_step(RewriteStep {
            state_key: "h8".to_string(),
            input: "h8".to_string(),
            output: "h7::l7".to_string(),
            rule: ALIAS_SUBSTITUTION_RULE,
        });
        trace.finish(RewriteOutcome::Converged {
            fixed_point: "h7::l7".to_string(),
        });
        let (bound, steps, outcome) = trace.into_parts();
        assert_eq!(bound, 3);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].rule, ALIAS_SUBSTITUTION_RULE);
        assert_eq!(
            outcome.expect("the chase terminated").kind(),
            RewriteOutcomeKind::Converged
        );
    }
}
