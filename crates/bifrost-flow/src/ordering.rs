use std::{cmp::Ordering, sync::Arc};

use crate::analyzer::semantic::{
    CallSiteHandle, ControlContinuation, EvidenceCompleteness, OracleCallContext,
    OracleRelationHandle, ProcedureHandle, ProgramPointHandle, ProofStatus, ReturnTransferKind,
    compare_relation_provenance,
};
use crate::dataflow::SummaryEntry;

pub(crate) fn compare_procedures(left: &ProcedureHandle, right: &ProcedureHandle) -> Ordering {
    left.artifact()
        .key()
        .cmp(right.artifact().key())
        .then_with(|| left.semantics().locator().cmp(right.semantics().locator()))
        .then_with(|| left.id().cmp(&right.id()))
        .then_with(|| {
            Arc::as_ptr(left.artifact())
                .cast::<()>()
                .cmp(&Arc::as_ptr(right.artifact()).cast::<()>())
        })
}

pub(crate) fn compare_points(left: &ProgramPointHandle, right: &ProgramPointHandle) -> Ordering {
    compare_procedures(left.procedure(), right.procedure()).then_with(|| left.id().cmp(&right.id()))
}

pub(crate) fn compare_call_sites(left: &CallSiteHandle, right: &CallSiteHandle) -> Ordering {
    compare_procedures(left.procedure(), right.procedure()).then_with(|| left.id().cmp(&right.id()))
}

pub(crate) fn compare_summary_entries(left: &SummaryEntry, right: &SummaryEntry) -> Ordering {
    compare_procedures(left.procedure(), right.procedure())
        .then_with(|| left.entry_point().id().cmp(&right.entry_point().id()))
        .then_with(|| left.entry_fact().cmp(&right.entry_fact()))
        .then_with(|| compare_call_contexts(left.call_context(), right.call_context()))
}

pub(crate) fn compare_call_contexts(
    left: &OracleCallContext,
    right: &OracleCallContext,
) -> Ordering {
    left.calls()
        .iter()
        .zip(right.calls())
        .find_map(|(left, right)| {
            let ordering = compare_call_sites(left, right);
            (ordering != Ordering::Equal).then_some(ordering)
        })
        .unwrap_or_else(|| {
            left.calls()
                .len()
                .cmp(&right.calls().len())
                .then_with(|| left.was_truncated().cmp(&right.was_truncated()))
        })
}

pub(crate) fn compare_optional_call_sites(
    left: Option<&CallSiteHandle>,
    right: Option<&CallSiteHandle>,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => compare_call_sites(left, right),
    }
}

pub(crate) fn compare_proof(left: &ProofStatus, right: &ProofStatus) -> Ordering {
    match (left, right) {
        (ProofStatus::Proven, ProofStatus::Proven) => Ordering::Equal,
        (ProofStatus::Proven, ProofStatus::Unproven(_)) => Ordering::Less,
        (ProofStatus::Unproven(_), ProofStatus::Proven) => Ordering::Greater,
        (ProofStatus::Unproven(left), ProofStatus::Unproven(right)) => left.cmp(right),
    }
}

pub(crate) fn compare_completeness(
    left: &EvidenceCompleteness,
    right: &EvidenceCompleteness,
) -> Ordering {
    match (left, right) {
        (EvidenceCompleteness::Complete, EvidenceCompleteness::Complete) => Ordering::Equal,
        (EvidenceCompleteness::Complete, EvidenceCompleteness::Partial(_)) => Ordering::Less,
        (EvidenceCompleteness::Partial(_), EvidenceCompleteness::Complete) => Ordering::Greater,
        (EvidenceCompleteness::Partial(left), EvidenceCompleteness::Partial(right)) => {
            left.cmp(right)
        }
    }
}

pub(crate) fn compare_optional_proof(
    left: Option<&ProofStatus>,
    right: Option<&ProofStatus>,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => compare_proof(left, right),
    }
}

pub(crate) fn compare_optional_completeness(
    left: Option<&EvidenceCompleteness>,
    right: Option<&EvidenceCompleteness>,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => compare_completeness(left, right),
    }
}

pub(crate) fn compare_boundary_evidence(
    left_proof: Option<&ProofStatus>,
    left_completeness: Option<&EvidenceCompleteness>,
    left_provenance: &[OracleRelationHandle],
    right_proof: Option<&ProofStatus>,
    right_completeness: Option<&EvidenceCompleteness>,
    right_provenance: &[OracleRelationHandle],
) -> Ordering {
    compare_optional_proof(left_proof, right_proof)
        .then_with(|| compare_optional_completeness(left_completeness, right_completeness))
        .then_with(|| compare_relation_provenance(left_provenance, right_provenance))
}

pub(crate) fn compare_continuations(
    left: ControlContinuation,
    right: ControlContinuation,
) -> Ordering {
    let rank = |continuation| match continuation {
        ControlContinuation::Target(_) => 0,
        ControlContinuation::Absent => 1,
        ControlContinuation::Unknown => 2,
        ControlContinuation::Unsupported => 3,
        ControlContinuation::Unproven => 4,
        ControlContinuation::ExceededBudget => 5,
    };
    rank(left)
        .cmp(&rank(right))
        .then_with(|| match (left, right) {
            (ControlContinuation::Target(left), ControlContinuation::Target(right)) => {
                left.cmp(&right)
            }
            _ => Ordering::Equal,
        })
}

pub(crate) const fn return_kind_ordinal(kind: ReturnTransferKind) -> u8 {
    match kind {
        ReturnTransferKind::Normal => 0,
        ReturnTransferKind::Exceptional => 1,
    }
}
