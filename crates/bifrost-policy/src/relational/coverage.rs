//! What an empty or passing relation proves.
//!
//! Coverage answers "did I see every row that exists?" and is orthogonal to
//! certainty, which answers "is a row I did see real?". Merging the two is what
//! produces false greens: a relation can be exactly proven and still be a
//! subset, and an assertion that reads absence needs the second property, not
//! the first.
//!
//! Two derived properties travel with a relation:
//!
//! * coverage, a lattice meet over the operators that produced the relation;
//! * witness soundness, a per-row property. A row is witness-sound when its
//!   presence is established. Anti-join output over a non-exhaustive right side
//!   is present only because nothing was found to remove it, so it is not
//!   witness-sound and can never support a finding.

use brokk_bifrost_analysis::analyzer::structural::search::CodeQueryResultItem;

use crate::definition::{PolicyAssertId, RowBindingName, RowGroupName};
use crate::finding::{PolicyCapability, PolicyIncompleteReason};

use super::ir::RowScalar;

/// One bound relation's executed rows and what they prove.
#[derive(Debug, Clone)]
pub struct RelationalInput<'a> {
    pub binding: &'a RowBindingName,
    pub rows: &'a [CodeQueryResultItem],
    pub coverage: RelationCoverage,
}

/// What a relation's row set proves about the rows it does not contain.
///
/// Ordered from most to least informative. The evaluator never upgrades a
/// coverage; it only meets, so a derivation is exactly as trustworthy as its
/// weakest input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelationCoverage {
    /// Every row that exists is present.
    Exhaustive,
    /// Every present row is proven, and rows may be missing by a stated,
    /// deliberate restriction rather than by a failure.
    ProvenSubset,
    /// Rows may be missing because something could not be read or finished.
    Incomplete {
        reasons: Vec<PolicyIncompleteReason>,
    },
    /// The producer cannot describe this relation at all.
    Unsupported { capability: PolicyCapability },
}

impl RelationCoverage {
    /// The coverage of a relation whose rows were bounded by a plan limit.
    pub fn row_budget() -> Self {
        Self::incomplete(vec![PolicyIncompleteReason::PipelineRowBudget])
    }

    /// The coverage of a relation whose producer deliberately suppressed the
    /// row set it heads (the non-`exact` call-shape rule).
    pub fn unsupported_row_set() -> Self {
        Self::Unsupported {
            capability: PolicyCapability::query_feature("relational", "suppressed_row_set")
                .expect("a static capability identifier is a valid report identifier"),
        }
    }

    /// An incomplete coverage with canonical reasons. An empty reason list is
    /// normalized to `PartialDiscovery` so a coverage never claims to be
    /// incomplete for no stated reason.
    pub fn incomplete(mut reasons: Vec<PolicyIncompleteReason>) -> Self {
        reasons.sort();
        reasons.dedup();
        if reasons.is_empty() {
            reasons.push(PolicyIncompleteReason::PartialDiscovery);
        }
        Self::Incomplete { reasons }
    }

    pub const fn is_exhaustive(&self) -> bool {
        matches!(self, Self::Exhaustive)
    }

    /// Position in the lattice; higher is more informative.
    const fn rank(&self) -> u8 {
        match self {
            Self::Exhaustive => 3,
            Self::ProvenSubset => 2,
            Self::Incomplete { .. } => 1,
            Self::Unsupported { .. } => 0,
        }
    }

    /// The greatest lower bound of two coverages: a derivation reading both is
    /// no more trustworthy than the weaker one. `Exhaustive` is the identity,
    /// `Unsupported` dominates, and two incomplete inputs keep both reason
    /// sets so the run states every cause.
    pub fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Incomplete { reasons: left }, Self::Incomplete { reasons: right }) => {
                let mut reasons = left;
                reasons.extend(right);
                Self::incomplete(reasons)
            }
            (Self::Unsupported { capability: left }, Self::Unsupported { capability: right }) => {
                Self::Unsupported {
                    // Deterministic and independent of operand order.
                    capability: left.min(right),
                }
            }
            (left, right) => {
                if left.rank() <= right.rank() {
                    left
                } else {
                    right
                }
            }
        }
    }

    /// The typed run-level reasons this coverage contributes when an assertion
    /// needed a completeness it does not have. Exhaustive coverage contributes
    /// nothing, because it blocks nothing.
    pub fn incomplete_reasons(&self) -> Vec<PolicyIncompleteReason> {
        match self {
            Self::Exhaustive => Vec::new(),
            Self::ProvenSubset => vec![PolicyIncompleteReason::PartialDiscovery],
            Self::Incomplete { reasons } => reasons.clone(),
            Self::Unsupported { .. } => vec![PolicyIncompleteReason::CapabilityIncomplete],
        }
    }
}

/// Why one assertion could not publish the verdict its rows suggested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelationalObligationKind {
    /// The verdict is a claim about rows that were not observed -- a clean pass
    /// of an upper bound, or a violation of a lower bound. Only an exhaustively
    /// covered derivation can support it.
    AbsenceRequiresExhaustiveCoverage,
    /// The contributing rows are not witness-sound, so the aggregate value
    /// itself is not established and neither verdict may be published.
    VerdictRequiresWitnessedRows,
}

impl RelationalObligationKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::AbsenceRequiresExhaustiveCoverage => "absence-requires-exhaustive-coverage",
            Self::VerdictRequiresWitnessedRows => "verdict-requires-witnessed-rows",
        }
    }
}

/// One unmet proof obligation: the assertion whose verdict is blocked, the
/// group key it was blocked at, and the typed reasons.
///
/// Obligations are the reason a relational run cannot be clean over an
/// incomplete relation without discarding the findings it did prove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationalObligation {
    pub assertion: PolicyAssertId,
    pub kind: RelationalObligationKind,
    /// The authored group whose derived relation the assertion read.
    pub group: RowGroupName,
    /// The group key the obligation is about. Empty when the obligation is
    /// about the group relation as a whole rather than one observed group.
    pub key: Vec<Option<RowScalar>>,
    pub reasons: Vec<PolicyIncompleteReason>,
}

impl RelationalObligation {
    /// Build one obligation with canonical, non-empty reasons.
    pub fn new(
        assertion: PolicyAssertId,
        kind: RelationalObligationKind,
        group: RowGroupName,
        key: Vec<Option<RowScalar>>,
        mut reasons: Vec<PolicyIncompleteReason>,
    ) -> Self {
        reasons.sort();
        reasons.dedup();
        if reasons.is_empty() {
            reasons.push(PolicyIncompleteReason::PartialDiscovery);
        }
        Self {
            assertion,
            kind,
            group,
            key,
            reasons,
        }
    }
}

/// The number of unmet obligations one evaluation retains. The run's typed
/// incomplete reasons are folded from every obligation before this bound
/// applies, so truncation loses detail for reporting, never soundness.
pub const MAX_RETAINED_RELATIONAL_OBLIGATIONS: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    fn incomplete(reason: PolicyIncompleteReason) -> RelationCoverage {
        RelationCoverage::incomplete(vec![reason])
    }

    #[test]
    fn exhaustive_is_the_identity_of_meet() {
        for coverage in [
            RelationCoverage::Exhaustive,
            RelationCoverage::ProvenSubset,
            incomplete(PolicyIncompleteReason::Cancelled),
            RelationCoverage::unsupported_row_set(),
        ] {
            assert_eq!(
                RelationCoverage::Exhaustive.meet(coverage.clone()),
                coverage,
                "exhaustive coverage adds no restriction"
            );
            assert_eq!(
                coverage.clone().meet(RelationCoverage::Exhaustive),
                coverage
            );
        }
    }

    #[test]
    fn a_proven_subset_met_with_an_incomplete_relation_is_incomplete() {
        assert_eq!(
            RelationCoverage::ProvenSubset.meet(incomplete(PolicyIncompleteReason::Cancelled)),
            incomplete(PolicyIncompleteReason::Cancelled)
        );
    }

    #[test]
    fn unsupported_dominates_every_other_coverage() {
        let unsupported = RelationCoverage::unsupported_row_set();
        for coverage in [
            RelationCoverage::Exhaustive,
            RelationCoverage::ProvenSubset,
            incomplete(PolicyIncompleteReason::Cancelled),
        ] {
            assert_eq!(unsupported.clone().meet(coverage.clone()), unsupported);
            assert_eq!(coverage.meet(unsupported.clone()), unsupported);
        }
    }

    #[test]
    fn two_incomplete_relations_keep_both_reason_sets() {
        let met = incomplete(PolicyIncompleteReason::Cancelled)
            .meet(incomplete(PolicyIncompleteReason::PipelineRowBudget));
        assert_eq!(
            met,
            RelationCoverage::Incomplete {
                reasons: vec![
                    PolicyIncompleteReason::Cancelled,
                    PolicyIncompleteReason::PipelineRowBudget
                ]
            },
            "reasons are canonical and both survive"
        );
    }

    #[test]
    fn meet_is_commutative_over_the_whole_lattice() {
        let coverages = [
            RelationCoverage::Exhaustive,
            RelationCoverage::ProvenSubset,
            incomplete(PolicyIncompleteReason::Cancelled),
            incomplete(PolicyIncompleteReason::PipelineRowBudget),
            RelationCoverage::unsupported_row_set(),
        ];
        for left in &coverages {
            for right in &coverages {
                assert_eq!(
                    left.clone().meet(right.clone()),
                    right.clone().meet(left.clone()),
                    "{left:?} meet {right:?}"
                );
            }
        }
    }

    #[test]
    fn an_incomplete_coverage_always_states_a_reason() {
        assert_eq!(
            RelationCoverage::incomplete(Vec::new()),
            incomplete(PolicyIncompleteReason::PartialDiscovery)
        );
    }
}
