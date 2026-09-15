//! What an empty or passing relation proves, and the partition it proves it for.
//!
//! Coverage answers "did I see every row that exists?" and is orthogonal to
//! certainty, which answers "is a row I did see real?". Merging the two is what
//! produces false greens: a relation can be exactly proven and still be a
//! subset, and an assertion that reads absence needs the second property, not
//! the first.
//!
//! Three derived properties travel with a relation:
//!
//! * coverage, a lattice meet over the operators that produced the relation;
//! * the partition that coverage is a statement about. A value-flow, taint or
//!   typestate solve enumerates one root at a time, so "exhaustive" is always
//!   exhaustive *for something*, and an unmet obligation has to be able to name
//!   which solve left the claim open (#3205);
//! * witness soundness, a per-row property. A row is witness-sound when its
//!   presence is established. Anti-join output over a non-exhaustive right side
//!   is present only because nothing was found to remove it, so it is not
//!   witness-sound and can never support a finding.
//!
//! The envelope is built from two independent sources, met together. The
//! executed query's `CodeQueryCompletion` says whether the row *set* is the
//! complete one. Each analysis row's own `CodeQueryRowCoverage` says whether
//! the partition that row came from was enumerated. Neither implies the other:
//! a flow query can return every endpoint it has while the solve that produced
//! them stopped against a budget, and the query envelope alone would read that
//! run as exhaustive.

use brokk_bifrost_rql::structural::search::{
    CodeQueryRowCoverage, CodeQueryRowCoverageExtent, DetailedCodeQueryDomain, UnitRowItem,
};

use crate::definition::{PolicyAssertId, RowBindingName, RowGroupName};
use crate::finding::{PolicyCapability, PolicyIncompleteReason};

use super::ir::RowScalar;

/// One analysis partition a coverage statement is about: the value-flow plan,
/// typestate protocol, taint sink, class set or call site one solve enumerated.
///
/// The family is the row domain that minted the partition, so two families that
/// happen to publish the same identity string stay distinct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageRoot {
    pub family: DetailedCodeQueryDomain,
    pub root: Box<str>,
}

impl CoverageRoot {
    /// The stable ordering key. `DetailedCodeQueryDomain` has no `Ord` of its
    /// own, and its declaration order is not a contract; its published label
    /// is, so the sort is by label and then by the family's own identity.
    fn order_key(&self) -> (&'static str, &str) {
        (self.family.label(), self.root.as_ref())
    }
}

impl PartialOrd for CoverageRoot {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CoverageRoot {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.order_key().cmp(&other.order_key())
    }
}

/// How many analysis roots one coverage value names.
///
/// A relation can hold one row per call site, so the fold has to be bounded.
/// Losing a name costs detail in the obligation that reports it, never the
/// obligation itself: the extent and its reasons are complete whatever this
/// bound drops, and `truncated` says a name was lost.
pub const MAX_COVERAGE_PARTITION_ROOTS: usize = 8;

/// The scope one coverage value states its claim about.
///
/// An empty partition is the executed query's own scope: no analysis narrowed
/// the claim, so the statement is about every row the query admits. A non-empty
/// partition names the analysis roots the statement is about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoveragePartition {
    roots: Vec<CoverageRoot>,
    truncated: bool,
}

impl CoveragePartition {
    /// The partition of a relation no analysis narrowed: the query's own scope.
    pub const fn query_scope() -> Self {
        Self {
            roots: Vec::new(),
            truncated: false,
        }
    }

    /// The partition of one analysis root.
    pub fn of_root(root: CoverageRoot) -> Self {
        Self {
            roots: vec![root],
            truncated: false,
        }
    }

    pub fn roots(&self) -> &[CoverageRoot] {
        &self.roots
    }

    /// Whether a fold dropped a root name against the retention bound.
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Whether this claim is about the query's own scope rather than about
    /// named analysis roots.
    pub const fn is_query_scope(&self) -> bool {
        self.roots.is_empty() && !self.truncated
    }

    /// The partition a statement about both operands is about: both scopes.
    ///
    /// Canonical and order independent, so the same relation built by two
    /// operator orders names the same partition.
    pub fn union(mut self, other: Self) -> Self {
        self.truncated |= other.truncated;
        for root in other.roots {
            if self.roots.len() >= MAX_COVERAGE_PARTITION_ROOTS {
                self.truncated = true;
                break;
            }
            if !self.roots.contains(&root) {
                self.roots.push(root);
            }
        }
        self.roots.sort();
        self.roots.dedup();
        self
    }
}

/// One bound relation's executed rows and what they prove.
///
/// The rows are the projected form every policy path carries: a whole
/// execution projects its rendered rows into it before evaluating, and a
/// sliced execution merges its units' products, which are already that
/// projection. One shape means the evaluation cannot depend on which path
/// produced its rows.
#[derive(Debug, Clone)]
pub struct RelationalInput<'a> {
    pub binding: &'a RowBindingName,
    pub rows: &'a [UnitRowItem],
    pub coverage: RelationCoverage,
}

/// What a relation's row set proves about the rows it does not contain, and
/// which partition that statement is about.
///
/// The evaluator never upgrades a coverage; it only meets, so a derivation is
/// exactly as trustworthy as its weakest input, and it names the partition of
/// the input that made it so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationCoverage {
    extent: CoverageExtent,
    partition: CoveragePartition,
}

/// How much of the stated partition a relation contains.
///
/// Ordered from most to least informative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageExtent {
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

impl CoverageExtent {
    /// Position in the lattice; higher is more informative.
    const fn rank(&self) -> u8 {
        match self {
            Self::Exhaustive => 3,
            Self::ProvenSubset => 2,
            Self::Incomplete { .. } => 1,
            Self::Unsupported { .. } => 0,
        }
    }
}

impl RelationCoverage {
    /// Apply the same row-set and query-completion contract to runs and replay.
    ///
    /// Two independent statements are met here. The query envelope answers
    /// whether this is the whole row set; each analysis row's own published
    /// coverage answers whether the partition it came from was enumerated. A
    /// flow, taint or typestate binding needs the second: its rows can all be
    /// present and proven while the solve behind them abstained, ran out of
    /// budget, or found the capability unavailable.
    pub(crate) fn from_query(
        rows: &[UnitRowItem],
        completion: &brokk_bifrost_rql::structural::CodeQueryCompletion,
        truncated: bool,
    ) -> Self {
        use brokk_bifrost_rql::structural::CodeQueryCompletion;
        let mut coverage = match completion {
            CodeQueryCompletion::Complete if !truncated => Self::exhaustive(),
            CodeQueryCompletion::ProvenSubset { .. } => Self::proven_subset(),
            _ => Self::incomplete(crate::evaluator::incomplete_reasons(completion, truncated)),
        };
        for row in rows {
            // A family that runs no solver enumerates no partition, and adds no
            // restriction.
            let Some(row_coverage) = row.coverage.as_ref() else {
                continue;
            };
            // A relation carries up to `max_pipeline_rows` rows, so a row whose
            // meet provably returns the accumulator unchanged is not projected
            // at all. An exhaustive row cannot weaken an already weaker
            // accumulator, and cannot rename the partition that weaker input
            // named; once the bounded partition fold is full it cannot add a
            // name to an exhaustive one either.
            if matches!(row_coverage.extent, CodeQueryRowCoverageExtent::Exhaustive)
                && (!coverage.is_exhaustive()
                    || coverage.partition.roots().len() >= MAX_COVERAGE_PARTITION_ROOTS)
            {
                continue;
            }
            coverage = coverage.meet(Self::of_row(row.domain, row_coverage));
        }
        coverage
    }

    /// The coverage one executed row publishes about its own partition.
    fn of_row(family: DetailedCodeQueryDomain, row: &CodeQueryRowCoverage) -> Self {
        let CodeQueryRowCoverage { partition, extent } = row;
        let partition = CoveragePartition::of_root(CoverageRoot {
            family,
            root: partition.clone(),
        });
        let extent = match extent {
            CodeQueryRowCoverageExtent::Exhaustive => CoverageExtent::Exhaustive,
            CodeQueryRowCoverageExtent::Incomplete { codes } => CoverageExtent::Incomplete {
                reasons: canonical_reasons(
                    codes
                        .iter()
                        .map(crate::evaluator::incomplete_reason_for_code)
                        .collect(),
                ),
            },
            CodeQueryRowCoverageExtent::Unsupported { capability } => CoverageExtent::Unsupported {
                capability: PolicyCapability::query_feature("relational", capability.as_ref())
                    .expect("a published row capability is a valid report identifier"),
            },
        };
        Self { extent, partition }
    }

    /// Every row that exists is present, over the query's own scope.
    pub const fn exhaustive() -> Self {
        Self {
            extent: CoverageExtent::Exhaustive,
            partition: CoveragePartition::query_scope(),
        }
    }

    /// Every present row is proven, and the producer stated the restriction
    /// that leaves rows out.
    pub const fn proven_subset() -> Self {
        Self {
            extent: CoverageExtent::ProvenSubset,
            partition: CoveragePartition::query_scope(),
        }
    }

    /// The coverage of a relation whose rows were bounded by a plan limit.
    pub fn row_budget() -> Self {
        Self::incomplete(vec![PolicyIncompleteReason::PipelineRowBudget])
    }

    /// The coverage of a relation whose producer deliberately suppressed the
    /// row set it heads (the non-`exact` call-shape rule).
    pub fn unsupported_row_set() -> Self {
        Self {
            extent: CoverageExtent::Unsupported {
                capability: PolicyCapability::query_feature(
                    "relational",
                    brokk_bifrost_rql::structural::search::SUPPRESSED_ROW_SET_CAPABILITY,
                )
                .expect("a static capability identifier is a valid report identifier"),
            },
            partition: CoveragePartition::query_scope(),
        }
    }

    /// An incomplete coverage with canonical reasons. An empty reason list is
    /// normalized to `PartialDiscovery` so a coverage never claims to be
    /// incomplete for no stated reason.
    pub fn incomplete(reasons: Vec<PolicyIncompleteReason>) -> Self {
        Self {
            extent: CoverageExtent::Incomplete {
                reasons: canonical_reasons(reasons),
            },
            partition: CoveragePartition::query_scope(),
        }
    }

    /// State that this coverage is about one named analysis partition rather
    /// than about the query's own scope.
    #[cfg(test)]
    pub(crate) fn in_partition(mut self, partition: CoveragePartition) -> Self {
        self.partition = partition;
        self
    }

    pub const fn extent(&self) -> &CoverageExtent {
        &self.extent
    }

    /// The partition this coverage states its claim about.
    pub const fn partition(&self) -> &CoveragePartition {
        &self.partition
    }

    pub const fn is_exhaustive(&self) -> bool {
        matches!(self.extent, CoverageExtent::Exhaustive)
    }

    /// The greatest lower bound of two coverages: a derivation reading both is
    /// no more trustworthy than the weaker one. `Exhaustive` is the identity of
    /// the extent, `Unsupported` dominates, and two incomplete inputs keep both
    /// reason sets so the run states every cause.
    ///
    /// The partition follows the extent. When one side is strictly weaker the
    /// result is a statement about *that* side's partition, because that is the
    /// scope a reader has to look at; when both sides are equally informative
    /// the result is a statement about both.
    pub fn meet(self, other: Self) -> Self {
        let partition = match self.extent.rank().cmp(&other.extent.rank()) {
            std::cmp::Ordering::Less => self.partition.clone(),
            std::cmp::Ordering::Greater => other.partition.clone(),
            std::cmp::Ordering::Equal => self.partition.clone().union(other.partition.clone()),
        };
        let extent = match (self.extent, other.extent) {
            (
                CoverageExtent::Incomplete { reasons: left },
                CoverageExtent::Incomplete { reasons: right },
            ) => {
                let mut reasons = left;
                reasons.extend(right);
                CoverageExtent::Incomplete {
                    reasons: canonical_reasons(reasons),
                }
            }
            (
                CoverageExtent::Unsupported { capability: left },
                CoverageExtent::Unsupported { capability: right },
            ) => CoverageExtent::Unsupported {
                // Deterministic and independent of operand order.
                capability: left.min(right),
            },
            (left, right) => {
                if left.rank() <= right.rank() {
                    left
                } else {
                    right
                }
            }
        };
        Self { extent, partition }
    }

    /// The typed run-level reasons this coverage contributes when an assertion
    /// needed a completeness it does not have. Exhaustive coverage contributes
    /// nothing, because it blocks nothing.
    pub fn incomplete_reasons(&self) -> Vec<PolicyIncompleteReason> {
        match &self.extent {
            CoverageExtent::Exhaustive => Vec::new(),
            CoverageExtent::ProvenSubset => vec![PolicyIncompleteReason::PartialDiscovery],
            CoverageExtent::Incomplete { reasons } => reasons.clone(),
            CoverageExtent::Unsupported { .. } => {
                vec![PolicyIncompleteReason::CapabilityIncomplete]
            }
        }
    }
}

/// Sort, deduplicate, and guarantee at least one stated reason.
fn canonical_reasons(mut reasons: Vec<PolicyIncompleteReason>) -> Vec<PolicyIncompleteReason> {
    reasons.sort();
    reasons.dedup();
    if reasons.is_empty() {
        reasons.push(PolicyIncompleteReason::PartialDiscovery);
    }
    reasons
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
/// group key it was blocked at, the analysis partition the blocked claim is
/// about, and the typed reasons.
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
    /// The partition of the coverage that blocked the verdict. A query-scope
    /// partition means the row set itself was short; a named partition means one
    /// solver root did not finish, and says which (#3205).
    pub partition: CoveragePartition,
    pub reasons: Vec<PolicyIncompleteReason>,
}

impl RelationalObligation {
    /// Build one obligation with canonical, non-empty reasons.
    pub fn new(
        assertion: PolicyAssertId,
        kind: RelationalObligationKind,
        group: RowGroupName,
        key: Vec<Option<RowScalar>>,
        partition: CoveragePartition,
        reasons: Vec<PolicyIncompleteReason>,
    ) -> Self {
        Self {
            assertion,
            kind,
            group,
            key,
            partition,
            reasons: canonical_reasons(reasons),
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
            RelationCoverage::exhaustive(),
            RelationCoverage::proven_subset(),
            incomplete(PolicyIncompleteReason::Cancelled),
            RelationCoverage::unsupported_row_set(),
        ] {
            assert_eq!(
                RelationCoverage::exhaustive().meet(coverage.clone()),
                coverage,
                "exhaustive coverage adds no restriction"
            );
            assert_eq!(
                coverage.clone().meet(RelationCoverage::exhaustive()),
                coverage
            );
        }
    }

    #[test]
    fn a_proven_subset_met_with_an_incomplete_relation_is_incomplete() {
        assert_eq!(
            RelationCoverage::proven_subset().meet(incomplete(PolicyIncompleteReason::Cancelled)),
            incomplete(PolicyIncompleteReason::Cancelled)
        );
    }

    #[test]
    fn unsupported_dominates_every_other_coverage() {
        let unsupported = RelationCoverage::unsupported_row_set();
        for coverage in [
            RelationCoverage::exhaustive(),
            RelationCoverage::proven_subset(),
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
            RelationCoverage::incomplete(vec![
                PolicyIncompleteReason::Cancelled,
                PolicyIncompleteReason::PipelineRowBudget
            ]),
            "reasons are canonical and both survive"
        );
    }

    #[test]
    fn meet_is_commutative_over_the_whole_lattice() {
        let coverages = [
            RelationCoverage::exhaustive(),
            RelationCoverage::proven_subset(),
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

    fn root(family: DetailedCodeQueryDomain, root: &str) -> CoveragePartition {
        CoveragePartition::of_root(CoverageRoot {
            family,
            root: Box::from(root),
        })
    }

    fn named(partition: &CoveragePartition) -> Vec<(&'static str, String)> {
        partition
            .roots()
            .iter()
            .map(|root| (root.family.label(), root.root.to_string()))
            .collect()
    }

    /// The partition follows the extent: the result is a statement about the
    /// scope that made it weaker, because that is the scope a reader has to
    /// look at to lift the restriction.
    #[test]
    fn a_meet_names_the_partition_of_its_weaker_operand() {
        let exhaustive = RelationCoverage::exhaustive()
            .in_partition(root(DetailedCodeQueryDomain::FlowEndpoint, "plan-a"));
        let blocked = incomplete(PolicyIncompleteReason::Cancelled)
            .in_partition(root(DetailedCodeQueryDomain::FlowEndpoint, "plan-b"));
        for met in [
            exhaustive.clone().meet(blocked.clone()),
            blocked.clone().meet(exhaustive),
        ] {
            assert_eq!(
                named(met.partition()),
                vec![("flow_endpoint", "plan-b".to_string())]
            );
        }
    }

    /// Two equally informative operands are a statement about both scopes, in a
    /// canonical order that does not depend on which operator ran first.
    #[test]
    fn equally_informative_operands_name_both_partitions() {
        let left = incomplete(PolicyIncompleteReason::Cancelled)
            .in_partition(root(DetailedCodeQueryDomain::TaintFinding, "sink-b"));
        let right = incomplete(PolicyIncompleteReason::PipelineRowBudget)
            .in_partition(root(DetailedCodeQueryDomain::FlowEndpoint, "plan-a"));
        let expected = vec![
            ("flow_endpoint", "plan-a".to_string()),
            ("taint_finding", "sink-b".to_string()),
        ];
        assert_eq!(
            named(left.clone().meet(right.clone()).partition()),
            expected
        );
        assert_eq!(named(right.meet(left).partition()), expected);
    }

    /// The fold is bounded, and a fold that drops a name says so rather than
    /// publishing a partition list that reads as complete.
    #[test]
    fn a_partition_fold_is_bounded_and_records_what_it_dropped() {
        let mut coverage = incomplete(PolicyIncompleteReason::Cancelled)
            .in_partition(root(DetailedCodeQueryDomain::FlowEndpoint, "plan-0"));
        for index in 1..=MAX_COVERAGE_PARTITION_ROOTS {
            coverage = coverage.meet(incomplete(PolicyIncompleteReason::Cancelled).in_partition(
                root(
                    DetailedCodeQueryDomain::FlowEndpoint,
                    &format!("plan-{index}"),
                ),
            ));
        }
        assert_eq!(
            coverage.partition().roots().len(),
            MAX_COVERAGE_PARTITION_ROOTS
        );
        assert!(coverage.partition().truncated());
    }

    /// A coverage nothing narrowed is a claim about the query's own scope, and
    /// says so rather than naming an empty partition set that reads the same as
    /// a dropped one.
    #[test]
    fn an_unnarrowed_coverage_is_a_query_scope_claim() {
        assert!(RelationCoverage::exhaustive().partition().is_query_scope());
        assert!(RelationCoverage::row_budget().partition().is_query_scope());
        assert!(
            !RelationCoverage::exhaustive()
                .in_partition(root(DetailedCodeQueryDomain::FlowEndpoint, "plan-a"))
                .partition()
                .is_query_scope()
        );
    }

    #[test]
    fn an_incomplete_coverage_always_states_a_reason() {
        assert_eq!(
            RelationCoverage::incomplete(Vec::new()),
            incomplete(PolicyIncompleteReason::PartialDiscovery)
        );
    }
}
