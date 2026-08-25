//! The projection between the query engine and the semantic IR's guard facts
//! (#2443 slice 2).
//!
//! A *guard* is one decision point's normalized condition, as the language
//! adapter recorded it while lowering: a compile-time constant, a comparison
//! against null, a comparison against a constant, or an explicitly opaque
//! condition it declined to normalize. Every row joins on the same stable wire
//! ids the `program_point` and `control_edge` rows publish, so a policy relates
//! "the guard on this branch" to "the edge it makes infeasible" by id equality.
//!
//! Nothing is derived here. Unlike the control-relation family, which runs five
//! algorithms per procedure, a guard row is a row of the frozen artifact: the
//! lowerer already made the decision, and this module makes it addressable. The
//! consequence is that a guard needs no budget, no completeness account of its
//! own, and no memo -- its proof and completeness are the IR evidence row's,
//! and its absence is answered by the adapter's `guard_facts` capability rather
//! than by a diagnostic.

use super::results::{CodeQueryGuard, CodeQueryResultRef, DetailedCodeQueryKey};
use super::semantic::SemanticProcedureValue;
use crate::analyzer::semantic::{
    EvidenceCompleteness, GuardFact, GuardId, LengthDelimitedDigest, ProofStatus,
};
use crate::analyzer::{ProjectFile, Range};

/// One guard row travelling through the pipeline.
///
/// The seed procedure travels with the dense guard id because a wire id can
/// only be minted from the handle the artifact was read through, which is the
/// same property that makes a guard's `point_id` literally a `program_point`
/// row's id.
#[derive(Debug, Clone)]
pub(super) struct GuardValue {
    pub(super) procedure: SemanticProcedureValue,
    pub(super) guard: GuardId,
}

impl GuardValue {
    pub(super) fn fact(&self) -> &GuardFact {
        self.procedure
            .handle
            .semantics()
            .guard_fact(self.guard)
            .expect("a validated procedure owns the guard its own row names")
    }

    pub(super) fn key(&self) -> GuardKey {
        GuardKey {
            procedure: self.procedure.wire_id(),
            guard: self.guard,
        }
    }
}

/// Dedup identity of a guard row: the seed procedure's wire id plus the dense
/// id the lowerer minted.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct GuardKey {
    pub(super) procedure: String,
    pub(super) guard: GuardId,
}

/// Every guard of one procedure, in the dense order the lowerer minted them.
pub(super) fn guards_of_procedure(procedure: &SemanticProcedureValue) -> Vec<GuardValue> {
    procedure
        .handle
        .semantics()
        .guard_facts()
        .iter()
        .map(|fact| GuardValue {
            procedure: procedure.clone(),
            guard: fact.id,
        })
        .collect()
}

/// Domain separator for the row family's stable ids.
const GUARD_ID_DOMAIN: &[u8] = b"bifrost.code_query.guard.v1";

/// The public projection of one guard row.
pub(super) fn public_guard(value: &GuardValue) -> CodeQueryGuard {
    let fact = value.fact();
    let point = value
        .procedure
        .point_value(fact.point)
        .expect("a validated procedure owns the point its own guard names")
        .point_ref();
    let edge_id = |edge| {
        value
            .procedure
            .edge_value(edge)
            .expect("a validated procedure owns the edge its own guard names")
            .public()
            .id
    };
    let true_edge_id = fact.true_edge.map(edge_id);
    let false_edge_id = fact.false_edge.map(edge_id);
    let evidence = value
        .procedure
        .handle
        .semantics()
        .evidence_row(fact.evidence)
        .expect("a validated guard has evidence");
    let procedure = value.procedure.public();
    let mut digest = LengthDelimitedDigest::new(GUARD_ID_DOMAIN);
    digest.push(procedure.id.as_bytes());
    digest.push(point.id.as_bytes());
    digest.push(fact.predicate.label().as_bytes());
    // Two guards of one procedure could in principle agree on point and
    // predicate. Keep the dense id private, but use it as the artifact-scoped
    // discriminator that makes the public digest injective, exactly as the
    // program-point wire id does.
    digest.push(&fact.id.get().to_le_bytes());
    CodeQueryGuard {
        id: digest.finish().to_string(),
        procedure_id: procedure.id,
        path: procedure.path,
        language: procedure.language,
        range: point.range,
        point,
        predicate: fact.predicate.label(),
        constant: fact.predicate.constant_value(),
        subject_value: fact.subject.map(|subject| u64::from(subject.get())),
        true_edge_id,
        false_edge_id,
        proof: proof_label(&evidence.proof),
        completeness: completeness_label(&evidence.completeness),
    }
}

const fn proof_label(proof: &ProofStatus) -> &'static str {
    match proof {
        ProofStatus::Proven => "proven",
        ProofStatus::Unproven(_) => "unproven",
    }
}

const fn completeness_label(completeness: &EvidenceCompleteness) -> &'static str {
    match completeness {
        EvidenceCompleteness::Complete => "complete",
        EvidenceCompleteness::Partial(_) => "partial",
    }
}

/// The typed key that addresses one guard row in detailed evidence.
pub(super) fn detailed_key(value: &GuardValue) -> DetailedCodeQueryKey {
    let public = public_guard(value);
    DetailedCodeQueryKey::Guard {
        id: public.id,
        procedure_id: public.procedure_id,
        point_id: public.point.id,
        predicate: public.predicate.to_string(),
    }
}

/// The row's own source anchor: the decision point the condition sits on.
pub(super) fn anchor(value: &GuardValue) -> (ProjectFile, Range) {
    let point = value
        .procedure
        .point_value(value.fact().point)
        .expect("a validated procedure owns the point its own guard names");
    (value.procedure.file().clone(), point.source_range())
}

/// The trace reference of one guard row.
pub(super) fn guard_ref(value: &GuardValue) -> CodeQueryResultRef {
    let public = public_guard(value);
    CodeQueryResultRef::Guard {
        id: public.id,
        path: public.path,
        range: public.range,
        procedure_id: public.procedure_id,
        predicate: public.predicate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::GuardPredicate;

    /// The row's `predicate` column and the IR enum it projects are one
    /// vocabulary, so a predicate added to the IR cannot reach the row surface
    /// without a label.
    #[test]
    fn every_guard_predicate_publishes_a_row_label() {
        for predicate in [
            GuardPredicate::ConstantBoolean { value: true },
            GuardPredicate::NullComparison { null_on_true: true },
            GuardPredicate::ConstantEquality {
                negated: false,
                constant: crate::analyzer::semantic::ValueId::new(0),
            },
            GuardPredicate::Opaque {
                digest: crate::analyzer::semantic::GuardConditionDigest::from_syntax_kind(
                    "method_invocation",
                ),
            },
        ] {
            assert!(
                GuardPredicate::LABELS.contains(&predicate.label()),
                "{predicate:?}"
            );
        }
        assert_eq!(GuardPredicate::LABELS.len(), 4);
    }

    /// A constant condition proves one arm cannot execute, and which arm that
    /// is depends on the constant, not on which edge happens to be present.
    #[test]
    fn a_constant_guard_names_the_arm_its_value_excludes() {
        use crate::analyzer::semantic::{ControlEdgeId, ProgramPointId, SourceMappingId};
        let guard = |value: bool| GuardFact {
            id: GuardId::new(0),
            point: ProgramPointId::new(0),
            subject: None,
            predicate: GuardPredicate::ConstantBoolean { value },
            true_edge: Some(ControlEdgeId::new(1)),
            false_edge: Some(ControlEdgeId::new(2)),
            source: SourceMappingId::new(0),
            evidence: crate::analyzer::semantic::EvidenceId::new(0),
        };
        assert_eq!(guard(true).infeasible_edge(), Some(ControlEdgeId::new(2)));
        assert_eq!(guard(false).infeasible_edge(), Some(ControlEdgeId::new(1)));

        // A folded arm leaves nothing to exclude: the edge is already gone.
        let folded = GuardFact {
            true_edge: None,
            ..guard(false)
        };
        assert_eq!(folded.infeasible_edge(), None);

        // A predicate that proves no constant excludes nothing at all.
        let opaque = GuardFact {
            predicate: GuardPredicate::NullComparison { null_on_true: true },
            ..guard(true)
        };
        assert_eq!(opaque.infeasible_edge(), None);
    }
}
