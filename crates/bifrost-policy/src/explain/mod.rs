//! Bounded, versioned why/why-not explanations for policy findings and
//! candidates. Tracked by issue #2433.
//!
//! Two questions, two adapters, one schema:
//!
//! - [`explain_match_finding`] answers **why** a retained `match` finding
//!   exists, by projecting the evidence the run already kept. It executes
//!   nothing, so it can never disagree with the report it reads.
//! - [`explain_match_candidate`] answers **why not** for one explicit
//!   candidate position, by re-executing bounded prefixes of the policy's
//!   selector plan and reporting the first stage at which the candidate
//!   stopped being covered.
//!
//! Both return a [`PolicyExplanation`]: a versioned root
//! (`bifrost_policy_explanation/v1`) over a bounded tree of nodes, each with a
//! content-derived identifier, a kind, an outcome, optional expected/actual
//! prose, an exact location where one exists, and per-node truncation
//! counters.
//!
//! # `failed` is not `unknown`
//!
//! The schema keeps the two apart everywhere. `failed` means the analyzer
//! finished, declared its result exhaustive, and the candidate was still not
//! there. `unknown` means the analyzer did not establish that: the query was
//! incomplete, cancelled, invalid, or a declared proven subset. A consumer may
//! act on `failed`; a consumer must not read `unknown` as evidence of absence.
//!
//! # Zero cost when unused
//!
//! This module is additive. Ordinary policy evaluation calls nothing here, and
//! nothing here mutates analyzer or evaluator state.

mod model;
mod why;
mod why_not;

#[cfg(test)]
mod tests;

pub use model::{
    ExplainError, ExplanationBudgetLimit, ExplanationLimits, ExplanationNode, ExplanationNodeId,
    ExplanationNodeKind, ExplanationOutcome, ExplanationQuestion, ExplanationSubject,
    ExplanationTruncation, POLICY_EXPLANATION_FORMAT, PolicyExplanation,
};
pub use why::explain_match_finding;
pub use why_not::{ExplanationCandidate, explain_match_candidate};
