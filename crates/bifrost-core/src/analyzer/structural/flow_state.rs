//! The flow-sensitive state vocabulary: what one state event does to its
//! subject, and how two state events relate along a control-flow graph (issue
//! #1480).
//!
//! These enums are the constrained values the query surface spells and the
//! derivation layer stamps on every row. They live here, beside the
//! reference-edge vocabulary of [`super::edges`], because the RQL registries
//! and the derivation layer are in two different crates and must not each own
//! a private spelling table.
//!
//! Nothing here is a control-flow *claim*. The derivation that mints these
//! values reads the production semantic IR and nothing else; a label is only
//! ever attached to a row a control-flow algorithm produced.

use super::occurrences::labelled_enum;
use serde::{Deserialize, Serialize};
use std::fmt;

labelled_enum! {
    /// What one state event does to its subject.
    ///
    /// A rebind emits both a `Kill` and an `Establish` at the same program
    /// point: the write terminates every other definition of the subject and
    /// creates a new one.
    StateEventClass, ALL_STATE_EVENT_CLASSES {
        Establish => "establish",
        Kill => "kill",
        Read => "read",
    }
}

labelled_enum! {
    /// What a state event is about: a named binding, or a property of one.
    ///
    /// The subject *identity* is a lowered value (plus a member name for a
    /// property); this is only the coarse axis a query filters on.
    FlowSubjectKind, ALL_FLOW_SUBJECT_KINDS {
        Binding => "binding",
        Property => "property",
    }
}

labelled_enum! {
    /// How two state events relate along the production control-flow graph.
    ///
    /// - `Reaching`: some CFG path carries the establishment to the read with
    ///   no intervening kill of the same subject.
    /// - `Dominates`: every entry-to-target path passes the source event's
    ///   program point.
    /// - `SameEvaluation`: the read feeds the very value the establishment
    ///   assigns, so the establishment cannot serve that read.
    ///
    /// Structural containment and textual order are never any of these.
    FlowRelation, ALL_FLOW_RELATIONS {
        Reaching => "reaching",
        Dominates => "dominates",
        SameEvaluation => "same_evaluation",
    }
}

impl FlowRelation {
    /// The derivation axis this relation belongs to, so a row can state
    /// whether its own family was completely enumerated.
    pub const fn axis(self) -> FlowStateAxis {
        match self {
            Self::Reaching => FlowStateAxis::ReachingRelation,
            Self::Dominates => FlowStateAxis::DominanceRelation,
            Self::SameEvaluation => FlowStateAxis::SameEvaluationRelation,
        }
    }
}

labelled_enum! {
    /// Whether a relation holds on every path or only on some path.
    FlowCertainty, ALL_FLOW_CERTAINTIES {
        Exact => "exact",
        May => "may",
    }
}

macro_rules! flow_state_axes {
    ($($variant:ident => $label:literal: $description:literal,)+) => {
        /// One independently answerable part of the flow-state domain.
        ///
        /// Unlike [`super::edges::EdgeAxis`], no adapter declares support for
        /// these: the honest source is the per-procedure lowering result, so
        /// an axis is reported uncovered by the derivation that ran, never by
        /// a static capability table.
        #[repr(u8)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum FlowStateAxis {
            $($variant,)+
        }

        /// Every axis, in declaration order, for iteration in validation,
        /// docs and tests.
        pub const ALL_FLOW_STATE_AXES: &[FlowStateAxis] = &[
            $(FlowStateAxis::$variant,)+
        ];

        impl FlowStateAxis {
            pub const COUNT: usize = ALL_FLOW_STATE_AXES.len();

            pub const fn label(self) -> &'static str {
                match self {
                    $(FlowStateAxis::$variant => $label,)+
                }
            }

            pub fn from_label(label: &str) -> Option<FlowStateAxis> {
                ALL_FLOW_STATE_AXES
                    .iter()
                    .copied()
                    .find(|axis| axis.label() == label)
            }

            pub const fn description(self) -> &'static str {
                match self {
                    $(FlowStateAxis::$variant => $description,)+
                }
            }
        }

        impl fmt::Display for FlowStateAxis {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.label())
            }
        }
    };
}

flow_state_axes! {
    BindingEvents => "binding_events":
        "Establishment, kill, and read events of named bindings (locals, parameters, receivers).",
    PropertyEvents => "property_events":
        "Establishment, kill, and read events of object properties of a canonical binding base.",
    ReachingRelation => "reaching_relation":
        "Reaching-definition rows relating an establishment to a read it can serve.",
    DominanceRelation => "dominance_relation":
        "Dominance rows stating that every entry-to-read path passes an establishment.",
    SameEvaluationRelation => "same_evaluation_relation":
        "Same-evaluation rows stating that a read feeds the value an establishment assigns.",
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_state_vocabulary_round_trips_its_labels() {
        for class in ALL_STATE_EVENT_CLASSES {
            assert_eq!(StateEventClass::from_label(class.label()), Some(*class));
        }
        for kind in ALL_FLOW_SUBJECT_KINDS {
            assert_eq!(FlowSubjectKind::from_label(kind.label()), Some(*kind));
        }
        for relation in ALL_FLOW_RELATIONS {
            assert_eq!(FlowRelation::from_label(relation.label()), Some(*relation));
        }
        for certainty in ALL_FLOW_CERTAINTIES {
            assert_eq!(
                FlowCertainty::from_label(certainty.label()),
                Some(*certainty)
            );
        }
        for axis in ALL_FLOW_STATE_AXES {
            assert_eq!(FlowStateAxis::from_label(axis.label()), Some(*axis));
            assert!(!axis.description().is_empty());
        }
        for relation in ALL_FLOW_RELATIONS {
            assert!(ALL_FLOW_STATE_AXES.contains(&relation.axis()));
        }
        assert_eq!(FlowStateAxis::COUNT, 5);
    }
}
