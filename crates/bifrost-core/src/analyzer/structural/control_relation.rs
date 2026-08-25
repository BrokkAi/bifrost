//! The control-relation vocabulary: how two program points of one procedure's
//! control-flow graph relate, and which exits that claim was computed against
//! (issue #2443).
//!
//! These enums are the constrained values the query surface spells and the
//! derivation layer stamps on every row. They live here, beside the flow-state
//! vocabulary of [`super::flow_state`], because the RQL registries and the
//! derivation layer are in two different crates and must not each own a private
//! spelling table.
//!
//! Nothing here is itself a control-flow algorithm. Every label is attached to
//! a row one of the shared control-flow algorithms produced; this module only
//! names the answers.

use super::occurrences::labelled_enum;
use serde::{Deserialize, Serialize};
use std::fmt;

labelled_enum! {
    /// How two program points of one procedure relate along its control-flow
    /// graph.
    ///
    /// - `Dominates`: every path from the procedure entry to the target passes
    ///   the source point.
    /// - `Postdominates`: every path from the target to a procedure exit passes
    ///   the source point.
    /// - `ControlDependsOn`: the target executes only because one outgoing
    ///   branch of the source point was taken; the branch itself travels on the
    ///   row as the controlling control edge.
    /// - `Reachable`: some path from the source point reaches the target. The
    ///   derivation publishes this from the procedure entry, so the row states
    ///   that the target executes on at least one path through the procedure.
    /// - `InLoop`: the target is a member of the cyclic region entered at the
    ///   source point.
    ///
    /// Structural containment and textual order are never any of these.
    ControlRelationKind, ALL_CONTROL_RELATION_KINDS {
        Dominates => "dominates",
        Postdominates => "postdominates",
        ControlDependsOn => "control_depends_on",
        Reachable => "reachable",
        InLoop => "in_loop",
    }
}

impl ControlRelationKind {
    /// Whether the relation's meaning depends on which exits the derivation
    /// treated as the procedure's exits.
    ///
    /// Dominance, reachability and loop membership are computed forward from
    /// the entry and say nothing about how the procedure leaves; postdominance
    /// and control dependence are computed backward from the exits and change
    /// meaning when the exit universe changes.
    pub const fn depends_on_exit_partition(self) -> bool {
        matches!(self, Self::Postdominates | Self::ControlDependsOn)
    }
}

labelled_enum! {
    /// Which procedure exits a backward control claim was computed against.
    ///
    /// Only `NormalAndExceptional` is ever emitted today: the shared
    /// control-flow algorithms compute postdominance and control dependence
    /// against one universe holding both the normal and the exceptional exit,
    /// and no partitioned derivation exists yet. The other labels are reserved
    /// so a partitioned derivation is an added value rather than a changed
    /// column, and so a policy that spells one of them is rejected at load time
    /// with "no row carries this value" instead of matching nothing forever.
    ///
    /// - `NormalAndExceptional`: both real exits, the single universe today.
    /// - `NormalOnly`: the normal return exit alone.
    /// - `ExceptionalOnly`: the exceptional (thrown) exit alone.
    /// - `WithCancellation`: a universe that also treats a cancellation point
    ///   as an exit.
    /// - `WithSuspension`: a universe that also treats an asynchronous
    ///   suspension as an exit.
    ControlExitPartition, ALL_CONTROL_EXIT_PARTITIONS {
        NormalAndExceptional => "normal_and_exceptional",
        NormalOnly => "normal_only",
        ExceptionalOnly => "exceptional_only",
        WithCancellation => "with_cancellation",
        WithSuspension => "with_suspension",
    }
}

impl ControlExitPartition {
    /// The one partition the current derivation computes. Named so a producer
    /// cannot spell a partition it did not actually compute against.
    pub const DERIVED_TODAY: Self = Self::NormalAndExceptional;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_relation_vocabulary_round_trips_its_labels() {
        for kind in ALL_CONTROL_RELATION_KINDS {
            assert_eq!(ControlRelationKind::from_label(kind.label()), Some(*kind));
        }
        for partition in ALL_CONTROL_EXIT_PARTITIONS {
            assert_eq!(
                ControlExitPartition::from_label(partition.label()),
                Some(*partition)
            );
        }
        assert_eq!(
            ControlExitPartition::DERIVED_TODAY,
            ControlExitPartition::NormalAndExceptional
        );
        assert!(ControlRelationKind::Postdominates.depends_on_exit_partition());
        assert!(!ControlRelationKind::Dominates.depends_on_exit_partition());
    }
}
