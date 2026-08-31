//! Bounded, versioned why/why-not explanations for policy findings and
//! candidates. Tracked by issue #2433.
//!
//! Two questions, one schema:
//!
//! - [`explain_finding`] answers **why** a retained finding exists, by
//!   projecting the evidence the run already kept. It executes nothing, so it
//!   can never disagree with the report it reads. It serves `match`,
//!   `assertion`, `flow` and `taint` findings, dispatching on the evidence the
//!   finding carries; [`explain_match_finding`] is the `match` adapter a
//!   caller that already knows the family can call directly.
//! - [`rank_near_misses`] answers **which came closest**, by relaxing the
//!   policy's own declared predicates one at a time over a bounded candidate
//!   set the caller either supplies or asks to have searched inside the
//!   policy's own seed scope. It publishes the sibling
//!   `bifrost_policy_near_miss/v1` document rather than a node tree, because a
//!   ranking is an ordered list over many subjects rather than a tree about
//!   one.
//! - [`explain_candidate`] answers **why not** for one explicit candidate
//!   position, by re-executing bounded prefixes of the policy's selector plan
//!   and reporting the first stage at which the candidate stopped being
//!   covered. It serves `match` and `assertion` policies;
//!   [`explain_match_candidate`] is its `match` adapter.
//!
//! `why-not` for a flow or taint policy is deliberately not answered here. It
//! is not a projection of anything retained: it needs candidate-specific
//! solver queries, and it is designed separately.
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
//! This module is additive. Ordinary policy evaluation calls nothing here. A
//! host-facing explanation activates semantic sources only when it owns the
//! disposable analyzer snapshot; a caller-owned analyzer is read under one
//! pinned active-model publication and is not re-activated.

mod host;
mod model;
mod near_miss;
mod why;
mod why_assertion;
mod why_flow;
mod why_not;
mod why_not_relational;

#[cfg(test)]
mod tests;

pub use host::{
    ExplanationTarget, explain_loaded_policy, explain_policy_inputs, rank_policy_near_misses,
};
pub use model::{
    ExplainError, ExplanationBudgetLimit, ExplanationLimits, ExplanationNode, ExplanationNodeId,
    ExplanationNodeKind, ExplanationOutcome, ExplanationQuestion, ExplanationSubject,
    ExplanationTruncation, NEAR_MISS_ADAPTER_ANALYSIS_TYPES, POLICY_EXPLANATION_FORMAT,
    PolicyExplanation, WHY_ADAPTER_ANALYSIS_TYPES, WHY_NOT_ADAPTER_ANALYSIS_TYPES,
};
pub use near_miss::{
    NearMissCandidates, NearMissEntry, NearMissEnumeration, NearMissTruncation,
    POLICY_NEAR_MISS_FORMAT, PolicyNearMissRanking, rank_near_misses,
};
pub use why::{explain_finding, explain_match_finding};
pub use why_not::{ExplanationCandidate, explain_candidate, explain_match_candidate};
