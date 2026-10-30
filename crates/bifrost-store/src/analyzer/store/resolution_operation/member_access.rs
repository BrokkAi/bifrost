//! Query-local access reduction. Languages describe one row; shared code owns
//! dictionary selection, alternatives, prerequisite state and exact exclusions.
#![allow(dead_code)] // Dormant until a language opts into access, #5658.
use super::demand_closure::{CloserWork, Read, SelectedMemberRouteTarget, closer_step};
use super::*;
use crate::analyzer::resolution::{
    DemandMemberSelection, DemandMemberSelectionRequest, DemandReferenceKey,
    DemandRootUnavailableReason, FactResolutionAnswer, HierarchyOrderOutcomeId,
    HierarchyProvenanceView, HierarchyProviderKey, HierarchyProviderObservation,
    HierarchyProviderVisit, HierarchyRequestIdentity, ProviderObservationStore, ResolutionAnswer,
    ResolutionSlotValue,
};
use std::cmp::Ordering;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AccessCandidateId {
    request: HierarchyRequestIdentity,
    reference: SemanticId,
    lookup: SemanticId,
    step: usize,
    slot: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AccessAlternativeId(pub SemanticId);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AccessGroupId(pub u32);
#[derive(Clone, Debug)]
pub(super) enum AccessKey {
    Fixed(u32),
    Owner {
        order: HierarchyOrderOutcomeId,
        root: SemanticId,
        owner: SemanticId,
    },
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AccessOrderedRange {
    pub order: HierarchyOrderOutcomeId,
    pub root: SemanticId,
    pub start_after: SemanticId,
}
#[derive(Clone, Debug)]
pub(super) enum MemberBinding {
    Unchanged,
    Receiver {
        parameter: SemanticId,
        value: ResolutionSlotValue,
    },
    Unknown,
}
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct AccessFacts {
    pub(super) ordered_range: Option<AccessOrderedRange>,
    pub(super) alternative: AccessAlternativeId,
    pub(super) group: AccessGroupId,
    pub(super) within_group: Box<[AccessKey]>,
    pub(super) between_groups: Box<[AccessKey]>,
    pub(super) provider: HierarchyProviderKey,
    pub(super) occurrence: SemanticId,
    pub(super) binding: MemberBinding,
    pub(super) completion: ResolutionCompletion,
    pub(super) coverage: Box<[HierarchyProviderKey]>,
    pub(super) witnesses: Box<[ProviderReasonSubset]>,
}
pub(super) struct ProjectedAccessRow {
    pub id: AccessCandidateId,
    pub target: Option<SelectedMemberRouteTarget>,
    pub facts: AccessFacts,
}
#[doc(hidden)]
pub enum AccessPrerequisiteReply {
    Members {
        reference: SemanticId,
        lookup: SemanticId,
        selection: DemandMemberSelection,
    },
    Reference {
        key: DemandReferenceKey,
        answer: Box<FactResolutionAnswer>,
    },
}
#[doc(hidden)]
pub enum AccessRowInput<'a> {
    Start,
    Replies(&'a [AccessPrerequisiteReply]),
}
#[doc(hidden)]
pub enum AccessRowPoll {
    Observed(ResolutionCompletion),
    Ready(Read<Box<AccessFacts>>),
    Members(DemandMemberSelectionRequest),
    Reference(DemandReferenceKey),
}
pub(super) enum AccessPrerequisiteRequest {
    Members(DemandMemberSelectionRequest),
    Reference(DemandReferenceKey),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccessWait {
    Members {
        reference: SemanticId,
        lookup: SemanticId,
    },
    Reference(DemandReferenceKey),
}
#[doc(hidden)]
pub trait MemberAccessRules<Row>: std::fmt::Debug {
    /// Runs once before shared reduction certifies absence or exclusion. An
    /// already-open miss skips this hook. Rows use the same retained cursor
    /// and prerequisite pump as declared members.
    fn late_inventory(
        &self,
        _context: &MemberAccessContext<'_>,
        _owners: &[SemanticId],
        _name: SemanticId,
    ) -> Result<Read<Vec<Row>>> {
        Ok(Read::ready(Vec::new()))
    }

    /// The returned completion covers every reply this call read; the cursor
    /// merges reply completions only on cancellation. Member selections also
    /// retain their completion in the cursor through `resume_members`.
    fn classify_row(
        &self,
        context: &MemberAccessContext<'_>,
        row: &Row,
        target: Option<&SelectedMemberRouteTarget>,
        input: AccessRowInput<'_>,
    ) -> Result<AccessRowPoll>;
}
#[doc(hidden)]
pub struct MemberAccessContext<'a> {
    pub(super) session: &'a ResolutionSession,
    pub(super) selection: &'a DemandMemberSelection,
    pub(super) provenance: HierarchyProvenanceView<'a>,
    pub(super) providers: &'a ProviderObservationStore,
    pub(super) input_completion: &'a ResolutionCompletion,
    pub(super) reference: SemanticId,
    pub(super) lookup: SemanticId,
    pub(super) step: usize,
    pub(super) namespace: ResolutionNamespace,
}
#[derive(Debug)]
pub(crate) struct MemberAccessEvidence {
    pub(super) bindings: Vec<(AccessCandidateId, MemberBinding)>,
    pub(super) certificates: Vec<MemberAccessCertificate>,
    pub(super) range_certificates: Vec<MemberAccessRangeCertificate>,
    pub(super) outcome: AccessOutcome,
}
pub(crate) struct MemberAccessResult {
    pub targets: Vec<SelectedMemberRouteTarget>,
    pub evidence: MemberAccessEvidence,
    pub completion: ResolutionCompletion,
}
impl MemberAccessResult {
    /// Typed consumers retain the access proof separately from binding targets.
    /// A missing projection can still carry binding evidence, so never zip the
    /// target and binding vectors or turn binding metadata into body execution.
    pub(crate) fn into_typed_answer(
        self,
        reference: SemanticId,
        session: Option<&ResolutionSession>,
        cancellation: &CancellationToken,
    ) -> Result<Read<(ResolutionAnswer, MemberAccessEvidence)>> {
        use crate::analyzer::resolution::{ResolutionWitness, WitnessStep};
        use crate::analyzer::structural::CandidateOutcome;
        let mut targets = Vec::new();
        let mut witnesses = Vec::new();
        let mut completion = self.completion;
        for target in self.targets {
            if cancellation.is_cancelled()
                || session.is_some_and(|session| {
                    !closer_step(session, cancellation, CloserWork::CandidateClassification)
                })
            {
                return Ok(Read::Cancelled(completion.combine(&cancelled_completion())));
            }
            let row_completion = target.target.completion;
            completion = completion.combine(&row_completion);
            let target = target.target.token;
            targets.push(target);
            witnesses.push(ResolutionWitness::new(
                reference,
                target,
                vec![WitnessStep::Candidate {
                    semantic: target,
                    outcome: CandidateOutcome::Selected,
                }],
                row_completion,
            ));
        }
        if cancellation.is_cancelled() {
            return Ok(Read::Cancelled(completion.combine(&cancelled_completion())));
        }
        Ok(Read::ready((
            ResolutionAnswer::new(targets, witnesses, completion),
            self.evidence,
        )))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AccessOutcome {
    Unique,
    Plural,
    Empty,
    Open,
}
#[derive(Clone, Debug)]
pub(super) struct ProviderReasonSubset {
    pub provider: HierarchyProviderKey,
    pub reasons: Box<[ResolutionIncompleteReason]>,
}
#[derive(Clone, Debug)]
pub(super) struct MemberAccessCertificate {
    pub order: HierarchyOrderOutcomeId,
    pub winner: AccessCandidateId,
    pub excluded: AccessCandidateId,
    pub coverage: Box<[HierarchyProviderKey]>,
    pub discharges: Box<[ProviderReasonSubset]>,
}

#[derive(Clone, Debug)]
pub(super) struct MemberAccessRangeCertificate {
    pub range: AccessOrderedRange,
    pub excluded: AccessCandidateId,
    pub coverage: Box<[HierarchyProviderKey]>,
    pub discharges: Box<[ProviderReasonSubset]>,
}

fn compare_keys(
    view: HierarchyProvenanceView<'_>,
    left: &[AccessKey],
    right: &[AccessKey],
    cancelled: &mut dyn FnMut() -> bool,
) -> Result<Option<Ordering>> {
    for (left, right) in left.iter().zip(right) {
        if cancelled() {
            return Ok(None);
        }
        let comparison = match (left, right) {
            (AccessKey::Fixed(left), AccessKey::Fixed(right)) => left.cmp(right),
            (
                AccessKey::Owner {
                    order: lo,
                    root: lr,
                    owner: left,
                },
                AccessKey::Owner {
                    order: ro,
                    root: rr,
                    owner: right,
                },
            ) if lo == ro && lr == rr => {
                let status = view.order_status(*lo);
                if !status.complete
                    || status.required_base.is_some()
                    || *status.completion != ResolutionCompletion::Complete
                {
                    return Ok(None);
                }
                let mut positions = (None, None);
                let mut index = 0;
                if !view.visit_order(*lo, cancelled, &mut |entry| {
                    if entry.root == *lr {
                        if entry.owner == *left {
                            positions.0 = Some(index);
                        }
                        if entry.owner == *right {
                            positions.1 = Some(index);
                        }
                        index += 1;
                    }
                    Ok(())
                })? {
                    return Ok(None);
                }
                let (Some(left), Some(right)) = positions else {
                    return Ok(None);
                };
                left.cmp(&right)
            }
            _ => return Ok(None),
        };
        if comparison != Ordering::Equal {
            return Ok(Some(comparison));
        }
    }
    Ok(Some(left.len().cmp(&right.len())))
}

fn required_coverage(
    rows: &[ProjectedAccessRow],
    alternative: AccessAlternativeId,
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<Box<[HierarchyProviderKey]>> {
    let mut coverage = Vec::new();
    for row in rows
        .iter()
        .filter(|row| row.facts.alternative == alternative)
    {
        if cancelled() {
            return None;
        }
        for key in &row.facts.coverage {
            if cancelled() {
                return None;
            }
            if !coverage.contains(key) {
                coverage.push(key.clone());
            }
        }
    }
    Some(coverage.into_boxed_slice())
}

fn validate_access_provider_inputs(
    context: &MemberAccessContext<'_>,
    rows: &[ProjectedAccessRow],
    alternative: AccessAlternativeId,
    coverage: &[HierarchyProviderKey],
    discharges: &[ProviderReasonSubset],
    cancellation: &CancellationToken,
) -> Result<Read<()>> {
    let refused = || Read::Unavailable {
        reason: crate::analyzer::resolution::DemandRootUnavailableReason::IncompletePreparation,
        completion: context.input_completion.clone(),
    };
    let Some(expected) = required_coverage(rows, alternative, &mut || {
        !closer_step(
            context.session,
            cancellation,
            CloserWork::CandidateClassification,
        )
    }) else {
        return Ok(Read::Cancelled(context.input_completion.clone()));
    };
    if coverage.len() != expected.len() || expected.iter().any(|key| !coverage.contains(key)) {
        return Ok(refused());
    }
    let mut observations = ProviderObservationStore::default();
    let mut kept = true;
    if !context.provenance.visit(
        context.selection.provenance,
        &mut || {
            !closer_step(
                context.session,
                cancellation,
                CloserWork::CandidateClassification,
            )
        },
        &mut |observation| {
            kept &= observations.retain(observation.clone(), &mut || {
                !closer_step(
                    context.session,
                    cancellation,
                    CloserWork::CandidateClassification,
                )
            });
            Ok(())
        },
    )? {
        return Ok(Read::Cancelled(context.input_completion.clone()));
    }
    if !context.providers.visit(
        &mut || {
            !closer_step(
                context.session,
                cancellation,
                CloserWork::CandidateClassification,
            )
        },
        &mut |observation| {
            kept &= observations.retain(observation.clone(), &mut || {
                !closer_step(
                    context.session,
                    cancellation,
                    CloserWork::CandidateClassification,
                )
            });
            Ok(())
        },
    )? {
        return Ok(Read::Cancelled(context.input_completion.clone()));
    }
    if !kept {
        return Ok(Read::Cancelled(context.input_completion.clone()));
    }
    if expected.is_empty() {
        return Ok(refused());
    }
    for row in rows
        .iter()
        .filter(|row| row.facts.alternative == alternative)
    {
        let Some(observation) = observations.get(&row.facts.provider) else {
            return Ok(refused());
        };
        if observation.visit != HierarchyProviderVisit::Observed
            || row.facts.provider.lookup != context.lookup
            || row.facts.provider.namespace != context.namespace
        {
            return Ok(refused());
        }
    }

    for key in &expected {
        if !closer_step(
            context.session,
            cancellation,
            CloserWork::CandidateClassification,
        ) {
            return Ok(Read::Cancelled(context.input_completion.clone()));
        }
        let Some(observation) = observations.get(key) else {
            return Ok(refused());
        };
        if observation.visit != HierarchyProviderVisit::Observed
            || observation.inventory_complete != Some(true)
        {
            return Ok(refused());
        }
    }
    for witness in discharges {
        let Some(observation) = observations.get(&witness.provider) else {
            return Ok(refused());
        };
        if !expected.contains(&witness.provider) {
            return Ok(refused());
        }
        for &reason in &witness.reasons {
            if !closer_step(
                context.session,
                cancellation,
                CloserWork::CandidateClassification,
            ) {
                return Ok(Read::Cancelled(context.input_completion.clone()));
            }
            if !observation.completion.contains_reason(reason)
                || !context.input_completion.contains_reason(reason)
            {
                return Ok(refused());
            }
        }
    }
    Ok(Read::ready(()))
}

pub(super) fn validate_member_access_range_certificate(
    context: &MemberAccessContext<'_>,
    rows: &[ProjectedAccessRow],
    certificate: &MemberAccessRangeCertificate,
    cancellation: &CancellationToken,
) -> Result<Read<()>> {
    let refused = || Read::Unavailable {
        reason: crate::analyzer::resolution::DemandRootUnavailableReason::IncompletePreparation,
        completion: context.input_completion.clone(),
    };
    if !closer_step(
        context.session,
        cancellation,
        CloserWork::CandidateClassification,
    ) {
        return Ok(Read::Cancelled(context.input_completion.clone()));
    }
    let candidate = certificate.excluded;
    if candidate.request != context.provenance.identity()
        || (candidate.reference, candidate.lookup, candidate.step)
            != (context.reference, context.lookup, context.step)
        || context.selection.order != Some(certificate.range.order)
    {
        return Ok(refused());
    }
    let Some(row) = rows.get(candidate.slot).filter(|row| row.id == candidate) else {
        return Ok(refused());
    };
    if row.facts.ordered_range != Some(certificate.range) {
        return Ok(refused());
    }
    let status = context.provenance.order_status(certificate.range.order);
    if !status.complete
        || status.required_base.is_some()
        || *status.completion != ResolutionCompletion::Complete
    {
        return Ok(refused());
    }
    let Some(scope) = status.cursor_scope else {
        return Ok(refused());
    };
    if scope.start_after != certificate.range.start_after {
        return Ok(refused());
    }
    let mut root_present = false;
    for &root in &scope.roots {
        if !closer_step(
            context.session,
            cancellation,
            CloserWork::CandidateClassification,
        ) {
            return Ok(Read::Cancelled(context.input_completion.clone()));
        }
        root_present |= root == certificate.range.root;
    }
    if !root_present {
        return Ok(refused());
    }
    let mut in_range = false;
    if !context.provenance.visit_order(
        certificate.range.order,
        &mut || {
            !closer_step(
                context.session,
                cancellation,
                CloserWork::CandidateClassification,
            )
        },
        &mut |entry| {
            in_range |=
                entry.root == certificate.range.root && entry.owner == row.facts.provider.owner;
            Ok(())
        },
    )? {
        return Ok(Read::Cancelled(context.input_completion.clone()));
    }
    if in_range {
        return Ok(refused());
    }
    validate_access_provider_inputs(
        context,
        rows,
        row.facts.alternative,
        &certificate.coverage,
        &certificate.discharges,
        cancellation,
    )
}

pub(super) fn validate_member_access_certificate(
    context: &MemberAccessContext<'_>,
    rows: &[ProjectedAccessRow],
    certificate: &MemberAccessCertificate,
    cancellation: &CancellationToken,
) -> Result<Read<()>> {
    let refused = || Read::Unavailable {
        reason: crate::analyzer::resolution::DemandRootUnavailableReason::IncompletePreparation,
        completion: context.input_completion.clone(),
    };
    if cancellation.is_cancelled() {
        return Ok(Read::Cancelled(
            context.input_completion.combine(&cancelled_completion()),
        ));
    }
    assert_eq!(
        certificate.winner.request,
        context.provenance.identity(),
        "access candidate belongs to this request"
    );
    assert_eq!(
        certificate.excluded.request,
        context.provenance.identity(),
        "access candidate belongs to this request"
    );
    for candidate in [certificate.winner, certificate.excluded] {
        assert_eq!(
            (candidate.reference, candidate.lookup, candidate.step),
            (context.reference, context.lookup, context.step),
            "access candidate belongs to this source continuation"
        );
    }
    let winner = &rows[certificate.winner.slot];
    let excluded = &rows[certificate.excluded.slot];
    assert_eq!(winner.id, certificate.winner);
    assert_eq!(excluded.id, certificate.excluded);
    if winner.facts.alternative != excluded.facts.alternative
        || context.selection.order != Some(certificate.order)
    {
        return Ok(refused());
    }
    let status = context.provenance.order_status(certificate.order);
    if !status.complete
        || status.required_base.is_some()
        || *status.completion != ResolutionCompletion::Complete
    {
        return Ok(refused());
    }
    match validate_access_provider_inputs(
        context,
        rows,
        winner.facts.alternative,
        &certificate.coverage,
        &certificate.discharges,
        cancellation,
    )? {
        Read::Ready { .. } => {}
        other => return Ok(other),
    }
    for row in rows
        .iter()
        .filter(|row| row.facts.alternative == winner.facts.alternative)
    {
        if let Some(range) = row.facts.ordered_range {
            let range_certificate = MemberAccessRangeCertificate {
                range,
                excluded: row.id,
                coverage: certificate.coverage.clone(),
                discharges: Box::new([]),
            };
            match validate_member_access_range_certificate(
                context,
                rows,
                &range_certificate,
                cancellation,
            )? {
                Read::Ready { .. } => continue,
                Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                _ => {}
            }
        }
        let mut member = false;
        if !context.provenance.visit_order(
            certificate.order,
            &mut || {
                !closer_step(
                    context.session,
                    cancellation,
                    CloserWork::CandidateClassification,
                )
            },
            &mut |entry| {
                member |= entry.owner == row.facts.provider.owner;
                Ok(())
            },
        )? {
            return Ok(Read::Cancelled(context.input_completion.clone()));
        }
        for key in row
            .facts
            .within_group
            .iter()
            .chain(row.facts.between_groups.iter())
        {
            if let AccessKey::Owner { order, root, owner } = key {
                let status = context.provenance.order_status(*order);
                if !status.complete
                    || status.required_base.is_some()
                    || *status.completion != ResolutionCompletion::Complete
                {
                    return Ok(refused());
                }
                let mut found = false;
                if !context.provenance.visit_order(
                    *order,
                    &mut || {
                        !closer_step(
                            context.session,
                            cancellation,
                            CloserWork::CandidateClassification,
                        )
                    },
                    &mut |entry| {
                        found |= entry.root == *root && entry.owner == *owner;
                        Ok(())
                    },
                )? {
                    return Ok(Read::Cancelled(context.input_completion.clone()));
                }
                if !found {
                    return Ok(refused());
                }
                member |= *owner == row.facts.provider.owner;
            }
        }
        if !member {
            return Ok(refused());
        }
    }
    let mut cancelled = || {
        !closer_step(
            context.session,
            cancellation,
            CloserWork::CandidateClassification,
        )
    };
    let (left, right) = if winner.facts.group == excluded.facts.group {
        (&winner.facts.within_group, &excluded.facts.within_group)
    } else {
        (&winner.facts.between_groups, &excluded.facts.between_groups)
    };
    if compare_keys(context.provenance, left, right, &mut cancelled)? != Some(Ordering::Less) {
        return Ok(refused());
    }
    if cancellation.is_cancelled() {
        return Ok(Read::Cancelled(context.input_completion.clone()));
    }
    Ok(Read::ready(()))
}

pub(super) fn reduce_member_access(
    context: &MemberAccessContext<'_>,
    rows: Vec<ProjectedAccessRow>,
    session: &ResolutionSession,
    cancellation: &CancellationToken,
) -> Result<Read<MemberAccessResult>> {
    match select_member_access(
        context,
        &rows,
        &ResolutionCompletion::Complete,
        session,
        cancellation,
    )? {
        Read::Ready { value, completion } => Ok(Read::Ready {
            value: value.finish(rows),
            completion,
        }),
        Read::Cancelled(completion) => Ok(Read::Cancelled(completion)),
        Read::Unavailable { reason, completion } => Ok(Read::Unavailable { reason, completion }),
    }
}

struct MemberAccessReduction {
    retained: Vec<bool>,
    certificates: Vec<MemberAccessCertificate>,
    range_certificates: Vec<MemberAccessRangeCertificate>,
    outcome: AccessOutcome,
    completion: ResolutionCompletion,
}
impl MemberAccessReduction {
    fn finish(self, rows: Vec<ProjectedAccessRow>) -> MemberAccessResult {
        let mut targets = Vec::new();
        let mut bindings = Vec::new();
        for (keep, row) in self.retained.into_iter().zip(rows) {
            if keep {
                bindings.push((row.id, row.facts.binding));
                if let Some(target) = row.target {
                    targets.push(target);
                }
            }
        }
        MemberAccessResult {
            targets,
            evidence: MemberAccessEvidence {
                bindings,
                certificates: self.certificates,
                range_certificates: self.range_certificates,
                outcome: self.outcome,
            },
            completion: self.completion,
        }
    }
}

fn select_member_access(
    context: &MemberAccessContext<'_>,
    rows: &[ProjectedAccessRow],
    observed: &ResolutionCompletion,
    session: &ResolutionSession,
    cancellation: &CancellationToken,
) -> Result<Read<MemberAccessReduction>> {
    let mut completion = context.input_completion.combine(observed);
    for row in rows {
        completion = completion.combine(&row.facts.completion);
    }
    let mut retained = vec![true; rows.len()];
    let mut certificates = Vec::new();
    let mut open = context.selection.order.is_none_or(|order| {
        let status = context.provenance.order_status(order);
        !status.complete
            || status.required_base.is_some()
            || *status.completion != ResolutionCompletion::Complete
    });
    let mut range_certificates = Vec::new();
    if observed == &ResolutionCompletion::Complete {
        for (slot, row) in rows.iter().enumerate() {
            let Some(range) = row.facts.ordered_range else {
                continue;
            };
            let Some(coverage) = required_coverage(rows, row.facts.alternative, &mut || {
                !closer_step(session, cancellation, CloserWork::CandidateClassification)
            }) else {
                return Ok(Read::Cancelled(completion));
            };
            let certificate = MemberAccessRangeCertificate {
                range,
                excluded: row.id,
                coverage,
                discharges: row.facts.witnesses.clone(),
            };
            match validate_member_access_range_certificate(
                context,
                rows,
                &certificate,
                cancellation,
            )? {
                Read::Ready { .. } => {
                    retained[slot] = false;
                    range_certificates.push(certificate);
                }
                Read::Cancelled(read) => return Ok(Read::Cancelled(completion.combine(&read))),
                _ => {
                    // Being inside the range is ordinary applicability, not an
                    // exclusion failure. Other refusals must keep this row open.
                    let status = context.provenance.order_status(range.order);
                    let scope_matches = context.selection.order == Some(range.order)
                        && status.complete
                        && status.required_base.is_none()
                        && *status.completion == ResolutionCompletion::Complete
                        && status.cursor_scope.is_some_and(|scope| {
                            scope.start_after == range.start_after
                                && scope.roots.contains(&range.root)
                        });
                    let mut inside = false;
                    if scope_matches
                        && !context.provenance.visit_order(
                            range.order,
                            &mut || {
                                !closer_step(
                                    session,
                                    cancellation,
                                    CloserWork::CandidateClassification,
                                )
                            },
                            &mut |entry| {
                                inside |= entry.root == range.root
                                    && entry.owner == row.facts.provider.owner;
                                Ok(())
                            },
                        )?
                    {
                        return Ok(Read::Cancelled(completion));
                    }
                    open |= !inside;
                }
            }
        }
        // Dictionary reduction precedes inter-dictionary precedence. Losers are
        // provisional until their exact certificate validates; no targets publish here.
        for within in [true, false] {
            let eligible = retained.clone();
            for (ri, right) in rows.iter().enumerate() {
                if !eligible[ri] {
                    continue;
                }
                for (li, left) in rows.iter().enumerate() {
                    if li == ri
                        || !eligible[li]
                        || left.facts.alternative != right.facts.alternative
                        || (left.facts.group == right.facts.group) != within
                    {
                        continue;
                    }
                    if !closer_step(session, cancellation, CloserWork::CandidateClassification) {
                        return Ok(Read::Cancelled(completion));
                    }
                    let (lk, rk) = if within {
                        (&left.facts.within_group, &right.facts.within_group)
                    } else {
                        (&left.facts.between_groups, &right.facts.between_groups)
                    };
                    let comparison = compare_keys(context.provenance, lk, rk, &mut || {
                        !closer_step(
                            context.session,
                            cancellation,
                            CloserWork::CandidateClassification,
                        )
                    })?;
                    if comparison.is_none() {
                        open = true;
                        continue;
                    }
                    if comparison != Some(Ordering::Less) {
                        continue;
                    }
                    let Some(order) = context.selection.order else {
                        open = true;
                        continue;
                    };
                    let Some(coverage) =
                        required_coverage(rows, left.facts.alternative, &mut || {
                            !closer_step(
                                context.session,
                                cancellation,
                                CloserWork::CandidateClassification,
                            )
                        })
                    else {
                        return Ok(Read::Cancelled(completion));
                    };
                    let certificate = MemberAccessCertificate {
                        order,
                        winner: left.id,
                        excluded: right.id,
                        coverage,
                        discharges: left
                            .facts
                            .witnesses
                            .iter()
                            .chain(right.facts.witnesses.iter())
                            .cloned()
                            .collect(),
                    };
                    match validate_member_access_certificate(
                        context,
                        rows,
                        &certificate,
                        cancellation,
                    )? {
                        Read::Ready {
                            completion: ResolutionCompletion::Complete,
                            ..
                        } => {
                            retained[ri] = false;
                            certificates.push(certificate);
                            break;
                        }
                        Read::Cancelled(read) => {
                            return Ok(Read::Cancelled(completion.combine(&read)));
                        }
                        _ => open = true,
                    }
                }
            }
        }
    } else {
        open = true;
    }
    if cancellation.is_cancelled()
        || !matches!(
            session.finish(()),
            brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution::Complete { .. }
        )
    {
        return Ok(Read::Cancelled(completion));
    }
    let mut target_keys = HashSet::default();
    for (keep, row) in retained.iter().zip(rows) {
        if !closer_step(session, cancellation, CloserWork::CandidateClassification) {
            return Ok(Read::Cancelled(completion));
        }
        if !keep {
            continue;
        }
        open |= row.target.is_none() || matches!(row.facts.binding, MemberBinding::Unknown);
        if let Some(target) = &row.target {
            target_keys.insert((target.target.fragment, target.target.definition));
        }
    }
    let outcome = if open || completion != ResolutionCompletion::Complete {
        AccessOutcome::Open
    } else {
        match target_keys.len() {
            0 => AccessOutcome::Empty,
            1 => AccessOutcome::Unique,
            _ => AccessOutcome::Plural,
        }
    };
    if cancellation.is_cancelled() {
        return Ok(Read::Cancelled(completion));
    }
    Ok(Read::ready(MemberAccessReduction {
        retained,
        certificates,
        range_certificates,
        outcome,
        completion,
    }))
}

/// Site and immutable selected inputs shared by ROOT and typed member access.
pub(super) struct MemberAccessSite<'a> {
    pub session: &'a ResolutionSession,
    pub selection: &'a DemandMemberSelection,
    pub provenance: HierarchyProvenanceView<'a>,
    pub input_completion: &'a ResolutionCompletion,
    pub reference: SemanticId,
    pub lookup: SemanticId,
    pub step: usize,
    pub namespace: ResolutionNamespace,
}

pub(super) enum MemberAccessProgress {
    Awaiting(AccessPrerequisiteRequest),
    Ready(MemberAccessResult),
}

/// Retain the exact provider snapshots before a suspended row or reduction.
/// This is also used by the source closure outside member access.
#[allow(clippy::too_many_arguments)]
pub(super) fn retain_member_providers(
    observations: Read<Vec<HierarchyProviderObservation>>,
    providers: &mut ProviderObservationStore,
    completion: &mut ResolutionCompletion,
    cancellation_evidence: &mut ResolutionCompletion,
    session: &ResolutionSession,
    cancellation: &CancellationToken,
) -> Result<Read<()>> {
    let observations = match observations {
        Read::Ready {
            value,
            completion: read,
        } => {
            if read != ResolutionCompletion::Complete {
                *completion = completion.combine(&read);
            }
            value
        }
        Read::Cancelled(read) => {
            return Ok(Read::Cancelled(
                completion.combine(cancellation_evidence).combine(&read),
            ));
        }
        Read::Unavailable {
            reason,
            completion: read,
        } => {
            return Ok(Read::Unavailable {
                reason,
                completion: completion.combine(cancellation_evidence).combine(&read),
            });
        }
    };
    for observation in observations {
        if !closer_step(session, cancellation, CloserWork::CoverageBranch) {
            return Ok(Read::Cancelled(
                completion
                    .combine(cancellation_evidence)
                    .combine(&cancelled_completion()),
            ));
        }
        *cancellation_evidence = cancellation_evidence.combine(&observation.completion);
        if !providers.retain(observation, &mut || {
            !closer_step(session, cancellation, CloserWork::CompletionPacking)
        }) {
            return Ok(Read::Cancelled(
                completion
                    .combine(cancellation_evidence)
                    .combine(&cancelled_completion()),
            ));
        }
    }
    Ok(Read::ready(()))
}

/// One row cursor and reducer for every member entry. Callers retain only their
/// own route/typed commit state; neither caller performs candidate selection.
#[allow(clippy::too_many_arguments)]
pub(super) fn poll_member_access<Row>(
    rows: &mut MemberAccessRows<Row>,
    site: &MemberAccessSite<'_>,
    rules: &dyn MemberAccessRules<Row>,
    providers: &mut ProviderObservationStore,
    hook_completion: &mut ResolutionCompletion,
    cancellation_evidence: &mut ResolutionCompletion,
    cancellation: &CancellationToken,
    mut read_owner: impl FnMut(SemanticId) -> Result<Read<Vec<Row>>>,
    mut project: impl FnMut(&Row) -> Result<Read<Option<SelectedMemberRouteTarget>>>,
    mut observations: impl FnMut() -> Result<Read<Vec<HierarchyProviderObservation>>>,
) -> Result<Read<MemberAccessProgress>> {
    if !rows.order_completion_applied {
        rows.order_completion_applied = true;
        if site.selection.completion == ResolutionCompletion::Complete
            && site
                .selection
                .order
                .is_some_and(|order| !site.provenance.order_status(order).complete)
        {
            rows.completion = rows.completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(site.reference),
            ]));
        }
    }
    loop {
        let context = MemberAccessContext {
            session: site.session,
            selection: site.selection,
            provenance: site.provenance,
            providers,
            input_completion: site.input_completion,
            reference: site.reference,
            lookup: site.lookup,
            step: site.step,
            namespace: site.namespace,
        };
        let request =
            match rows.poll(&context, rules, cancellation, &mut read_owner, &mut project)? {
                Read::Ready { value, completion } => (value, completion),
                Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                Read::Unavailable { reason, completion } => {
                    return Ok(Read::Unavailable { reason, completion });
                }
            };
        match retain_member_providers(
            observations()?,
            providers,
            hook_completion,
            cancellation_evidence,
            site.session,
            cancellation,
        )? {
            Read::Ready { .. } => {}
            Read::Cancelled(completion) => {
                return Ok(Read::Cancelled(
                    rows.cancellation_completion()
                        .combine(&request.1)
                        .combine(&completion),
                ));
            }
            Read::Unavailable { reason, completion } => {
                return Ok(Read::Unavailable {
                    reason,
                    completion: if request.0.is_some() {
                        request.1.combine(&completion)
                    } else {
                        rows.completion.combine(&completion)
                    },
                });
            }
        }
        if let Some(pending) = request.0 {
            return Ok(Read::Ready {
                value: MemberAccessProgress::Awaiting(pending),
                completion: hook_completion.combine(&request.1),
            });
        }
        let input = hook_completion
            .combine(site.input_completion)
            .combine(&rows.completion);
        let context = MemberAccessContext {
            session: site.session,
            selection: site.selection,
            provenance: site.provenance,
            providers,
            input_completion: &input,
            reference: site.reference,
            lookup: site.lookup,
            step: site.step,
            namespace: site.namespace,
        };
        let reduction = match select_member_access(
            &context,
            &rows.projected,
            &rows.observed,
            site.session,
            cancellation,
        )? {
            Read::Ready { value, completion } => {
                *hook_completion = hook_completion.combine(&completion);
                value
            }
            Read::Cancelled(completion) => {
                return Ok(Read::Cancelled(input.combine(&completion)));
            }
            Read::Unavailable { reason, completion } => {
                return Ok(Read::Unavailable {
                    reason,
                    completion: input.combine(&completion),
                });
            }
        };
        if reduction.outcome == AccessOutcome::Empty && !rows.late_inventory_read {
            rows.late_inventory_read = true;
            let late = rules.late_inventory(&context, &site.selection.owners, site.lookup)?;
            let (late, completion) = match late {
                Read::Ready { value, completion } => (value, completion),
                Read::Cancelled(completion) => {
                    return Ok(Read::Cancelled(input.combine(&completion)));
                }
                Read::Unavailable { reason, completion } => {
                    return Ok(Read::Unavailable {
                        reason,
                        completion: input.combine(&completion),
                    });
                }
            };
            let late_observations = observations()?;
            let changed = !late.is_empty()
                || completion != ResolutionCompletion::Complete
                || !matches!(&late_observations, Read::Ready { value, completion: ResolutionCompletion::Complete } if value.is_empty());
            rows.completion = rows.completion.combine(&completion);
            rows.observed = rows.observed.combine(&completion);
            match retain_member_providers(
                late_observations,
                providers,
                hook_completion,
                cancellation_evidence,
                site.session,
                cancellation,
            )? {
                Read::Ready { .. } => {}
                Read::Cancelled(completion) => {
                    return Ok(Read::Cancelled(input.combine(&completion)));
                }
                Read::Unavailable { reason, completion } => {
                    return Ok(Read::Unavailable {
                        reason,
                        completion: input.combine(&completion),
                    });
                }
            }
            if changed {
                assert!(rows.pending.is_none() && rows.queue.len() == 0 && rows.owners.len() == 0);
                rows.queue = late.into_iter();
                continue;
            }
        }
        let result = reduction.finish(std::mem::take(&mut rows.projected));
        if result.evidence.outcome == AccessOutcome::Open
            && result.completion == ResolutionCompletion::Complete
        {
            // The reduction left this access open without recording why, and
            // its completion unions `input`, so `input` is Complete too. Name
            // the open access here: an unavailable root must carry a reason
            // before a closure settles it.
            return Ok(Read::Unavailable {
                reason: DemandRootUnavailableReason::IncompletePreparation,
                completion: input.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(site.reference),
                ])),
            });
        }
        return Ok(Read::ready(MemberAccessProgress::Ready(result)));
    }
}

/// Shared preparation cursor for a language-supplied inventory of selected
/// references (for example a structured proxy call's callee and arguments).
/// Languages provide the inventory and interpret replies; this cursor owns
/// ordering, exact-token validation, copying, suspension, and cancellation.
pub(super) struct QualifiedReferenceInputs {
    keys: Vec<DemandReferenceKey>,
    cursor: usize,
    answers: Vec<(DemandReferenceKey, Box<FactResolutionAnswer>)>,
    outstanding: Option<(
        crate::analyzer::resolution::CloseContinuationId,
        DemandReferenceKey,
    )>,
    pub completion: ResolutionCompletion,
}
impl QualifiedReferenceInputs {
    pub fn new(keys: impl IntoIterator<Item = DemandReferenceKey>) -> Self {
        let mut seen = HashSet::default();
        Self {
            keys: keys.into_iter().filter(|key| seen.insert(*key)).collect(),
            cursor: 0,
            answers: Vec::new(),
            outstanding: None,
            completion: ResolutionCompletion::Complete,
        }
    }
    pub fn answers(&self) -> impl Iterator<Item = (DemandReferenceKey, &FactResolutionAnswer)> {
        self.answers
            .iter()
            .map(|(key, answer)| (*key, answer.as_ref()))
    }
    pub fn poll(
        &mut self,
        provenance: HierarchyProvenanceView<'_>,
        resume: crate::analyzer::resolution::CloseResume<'_>,
        session: &ResolutionSession,
        cancellation: &CancellationToken,
    ) -> Result<crate::analyzer::resolution::CloseProgress<()>> {
        use crate::analyzer::resolution::{CloseContinuationId, CloseProgress, CloseResume};
        match resume {
            CloseResume::Start => {
                assert!(
                    self.outstanding.is_none() && self.cursor == 0,
                    "preparation starts once before any reference reply"
                );
            }
            CloseResume::Reference {
                continuation,
                key,
                answer,
            } => {
                assert_eq!(
                    self.outstanding.take(),
                    Some((continuation, key)),
                    "preparation consumes its exact reference wait once"
                );
                continuation.assert_current(provenance);
                assert_eq!(self.keys[self.cursor], key);
                self.completion = self.completion.combine(answer.completion());
                let Some(answer) = answer.clone_with_poll(&mut || {
                    !closer_step(session, cancellation, CloserWork::CandidateClassification)
                }) else {
                    return Ok(CloseProgress::Cancelled(self.completion.clone()));
                };
                self.answers.push((key, Box::new(answer)));
                self.cursor += 1;
            }
            CloseResume::Members { .. } => {
                panic!("a selected-reference inventory never requests Members")
            }
        }
        if cancellation.is_cancelled() {
            return Ok(CloseProgress::Cancelled(
                self.completion.combine(&cancelled_completion()),
            ));
        }
        let Some(&key) = self.keys.get(self.cursor) else {
            return Ok(CloseProgress::Ready(()));
        };
        if !closer_step(session, cancellation, CloserWork::CandidateClassification) {
            return Ok(CloseProgress::Cancelled(self.completion.clone()));
        }
        let continuation = CloseContinuationId::issue(provenance);
        self.outstanding = Some((continuation, key));
        Ok(CloseProgress::Reference {
            continuation,
            key,
            completion: self.completion.clone(),
        })
    }
}

/// A provider owns this slot for one typed request, dropping it on terminal
/// read or cancellation. Context is owned data; hooks borrow it only for a poll.
pub(super) struct QualifiedMemberSlot<Context, Row> {
    pub context: Context,
    pub access: QualifiedMemberAccessSlot<Row>,
}
pub(super) struct QualifiedMemberAccessSlot<Row> {
    pub input: crate::analyzer::resolution::QualifiedMemberInput,
    access: Option<MemberAccessState<Row>>,
    providers: ProviderObservationStore,
    completion: ResolutionCompletion,
    cancellation_evidence: ResolutionCompletion,
    continuation: Option<crate::analyzer::resolution::CloseContinuationId>,
}
impl<Context, Row> QualifiedMemberSlot<Context, Row> {
    pub fn new(context: Context, input: crate::analyzer::resolution::QualifiedMemberInput) -> Self {
        Self {
            context,
            access: QualifiedMemberAccessSlot {
                input,
                access: None,
                providers: ProviderObservationStore::default(),
                completion: ResolutionCompletion::Complete,
                cancellation_evidence: ResolutionCompletion::Complete,
                continuation: None,
            },
        }
    }
}
impl<Row> QualifiedMemberAccessSlot<Row> {
    #[allow(clippy::too_many_arguments)]
    pub fn poll(
        &mut self,
        id: crate::analyzer::resolution::QualifiedMemberId,
        selection: &DemandMemberSelection,
        provenance: HierarchyProvenanceView<'_>,
        resume: crate::analyzer::resolution::CloseResume<'_>,
        session: &ResolutionSession,
        cancellation: &CancellationToken,
        rules: &dyn MemberAccessRules<Row>,
        read_owner: impl FnMut(SemanticId) -> Result<Read<Vec<Row>>>,
        project: impl FnMut(&Row) -> Result<Read<Option<SelectedMemberRouteTarget>>>,
        observations: impl FnMut() -> Result<Read<Vec<HierarchyProviderObservation>>>,
    ) -> Result<crate::analyzer::resolution::CloseProgress<Read<MemberAccessResult>>> {
        use crate::analyzer::resolution::{CloseContinuationId, CloseProgress, CloseResume};
        id.assert_current(provenance);
        match resume {
            CloseResume::Start => {
                assert!(self.access.is_none() && self.continuation.is_none());
                self.access = Some(MemberAccessState::new(selection));
            }
            CloseResume::Members {
                continuation,
                selection,
            } => {
                assert_eq!(self.continuation.take(), Some(continuation));
                continuation.assert_current(provenance);
                self.access
                    .as_mut()
                    .expect("member row is suspended")
                    .rows
                    .resume_members(selection);
            }
            CloseResume::Reference {
                continuation,
                key,
                answer,
            } => {
                assert_eq!(self.continuation.take(), Some(continuation));
                continuation.assert_current(provenance);
                match self
                    .access
                    .as_mut()
                    .expect("member row is suspended")
                    .rows
                    .resume_reference(key, answer, session, cancellation)?
                {
                    Read::Ready { .. } => {}
                    Read::Cancelled(completion) => return Ok(CloseProgress::Cancelled(completion)),
                    Read::Unavailable { reason, completion } => {
                        return Ok(CloseProgress::Ready(Read::Unavailable {
                            reason,
                            completion,
                        }));
                    }
                }
            }
        }
        let state = self.access.as_mut().expect("active member access");
        let site = MemberAccessSite {
            session,
            selection: &state.selection,
            provenance,
            input_completion: &self.input.completion,
            reference: self.input.reference.reference,
            lookup: self.input.lookup,
            step: self.input.route_ordinal,
            namespace: self.input.namespace,
        };
        match poll_member_access(
            &mut state.rows,
            &site,
            rules,
            &mut self.providers,
            &mut self.completion,
            &mut self.cancellation_evidence,
            cancellation,
            read_owner,
            project,
            observations,
        )? {
            Read::Ready {
                value: MemberAccessProgress::Ready(result),
                completion,
            } => Ok(CloseProgress::Ready(Read::Ready {
                value: result,
                completion,
            })),
            Read::Ready {
                value: MemberAccessProgress::Awaiting(request),
                completion,
            } => {
                let continuation = CloseContinuationId::issue(provenance);
                self.continuation = Some(continuation);
                Ok(match request {
                    AccessPrerequisiteRequest::Members(request) => CloseProgress::Members {
                        continuation,
                        request,
                        completion,
                    },
                    AccessPrerequisiteRequest::Reference(key) => CloseProgress::Reference {
                        continuation,
                        key,
                        completion,
                    },
                })
            }
            Read::Cancelled(completion) => Ok(CloseProgress::Cancelled(completion)),
            Read::Unavailable { reason, completion } => {
                Ok(CloseProgress::Ready(Read::Unavailable {
                    reason,
                    completion,
                }))
            }
        }
    }
}

/// The shared source cursor owns this state across scheduler suspensions.
pub(super) struct MemberAccessState<Row> {
    pub selection: DemandMemberSelection,
    pub rows: MemberAccessRows<Row>,
}
pub(super) struct MemberAccessRows<Row> {
    pub owners: std::vec::IntoIter<SemanticId>,
    pub queue: std::vec::IntoIter<Row>,
    pub pending: Option<(Row, Option<SelectedMemberRouteTarget>)>,
    pending_base: Option<ResolutionCompletion>,
    pub replies: Vec<AccessPrerequisiteReply>,
    outstanding: Option<AccessWait>,
    pub projected: Vec<ProjectedAccessRow>,
    pub completion: ResolutionCompletion,
    order_completion_applied: bool,
    late_inventory_read: bool,
    observed: ResolutionCompletion,
}
impl<Row> MemberAccessState<Row> {
    pub fn new(selection: &DemandMemberSelection) -> Self {
        Self {
            selection: selection.clone(),
            rows: MemberAccessRows {
                owners: selection.owners.clone().into_iter(),
                queue: Vec::new().into_iter(),
                pending: None,
                pending_base: None,
                replies: Vec::new(),
                outstanding: None,
                projected: Vec::new(),
                late_inventory_read: false,
                observed: ResolutionCompletion::Complete,
                completion: selection.completion.clone(),
                order_completion_applied: false,
            },
        }
    }
}
impl<Row> MemberAccessRows<Row> {
    fn cancellation_completion(&self) -> ResolutionCompletion {
        self.replies
            .iter()
            .fold(self.completion.clone(), |completion, reply| match reply {
                AccessPrerequisiteReply::Reference { answer, .. } => {
                    completion.combine(answer.completion())
                }
                AccessPrerequisiteReply::Members { .. } => completion,
            })
    }

    pub fn resume_members(&mut self, reply: &DemandMemberSelection) {
        let AccessWait::Members { reference, lookup } = self
            .outstanding
            .take()
            .expect("one outstanding prerequisite")
        else {
            panic!("member reply must match member wait");
        };
        self.completion = self.completion.combine(&reply.completion);
        self.replies.push(AccessPrerequisiteReply::Members {
            reference,
            lookup,
            selection: reply.clone(),
        });
    }
    pub fn resume_reference(
        &mut self,
        key: DemandReferenceKey,
        answer: &FactResolutionAnswer,
        session: &ResolutionSession,
        cancellation: &CancellationToken,
    ) -> Result<Read<()>> {
        assert_eq!(
            self.outstanding,
            Some(AccessWait::Reference(key)),
            "reference reply matches the exact wait"
        );
        if !closer_step(session, cancellation, CloserWork::CandidateClassification) {
            return Ok(Read::Cancelled(
                self.cancellation_completion().combine(answer.completion()),
            ));
        }
        let Some(answer) = answer.clone_with_poll(&mut || {
            !closer_step(session, cancellation, CloserWork::CandidateClassification)
        }) else {
            return Ok(Read::Cancelled(
                self.cancellation_completion().combine(answer.completion()),
            ));
        };
        let answer = Box::new(answer);
        if cancellation.is_cancelled() {
            return Ok(Read::Cancelled(
                self.cancellation_completion().combine(answer.completion()),
            ));
        }
        self.outstanding
            .take()
            .expect("consume the exact reference wait once");
        self.replies
            .push(AccessPrerequisiteReply::Reference { key, answer });
        Ok(Read::ready(()))
    }
    pub fn poll(
        &mut self,
        context: &MemberAccessContext<'_>,
        rules: &dyn MemberAccessRules<Row>,
        cancellation: &CancellationToken,
        mut read_owner: impl FnMut(SemanticId) -> Result<Read<Vec<Row>>>,
        mut project: impl FnMut(&Row) -> Result<Read<Option<SelectedMemberRouteTarget>>>,
    ) -> Result<Read<Option<AccessPrerequisiteRequest>>> {
        loop {
            if cancellation.is_cancelled() {
                return Ok(Read::Cancelled(
                    self.cancellation_completion()
                        .combine(&cancelled_completion()),
                ));
            }
            if self.pending.is_none() {
                if let Some(row) = self.queue.next() {
                    if !closer_step(
                        context.session,
                        cancellation,
                        CloserWork::CandidateClassification,
                    ) {
                        return Ok(Read::Cancelled(self.cancellation_completion()));
                    }
                    assert!(self.pending_base.replace(self.completion.clone()).is_none());
                    let target = match project(&row)? {
                        Read::Ready { value, completion } => {
                            self.completion = self.completion.combine(&completion);
                            value
                        }
                        Read::Cancelled(completion) => {
                            return Ok(Read::Cancelled(
                                self.cancellation_completion().combine(&completion),
                            ));
                        }
                        Read::Unavailable { reason, completion } => {
                            return Ok(Read::Unavailable {
                                reason,
                                completion: self.completion.combine(&completion),
                            });
                        }
                    };
                    self.pending = Some((row, target));
                } else if let Some(owner) = self.owners.next() {
                    match read_owner(owner)? {
                        Read::Ready { value, completion } => {
                            self.completion = self.completion.combine(&completion);
                            self.queue = value.into_iter();
                        }
                        Read::Cancelled(completion) => {
                            return Ok(Read::Cancelled(
                                self.cancellation_completion().combine(&completion),
                            ));
                        }
                        Read::Unavailable { reason, completion } => {
                            return Ok(Read::Unavailable {
                                reason,
                                completion: self.completion.combine(&completion),
                            });
                        }
                    }
                    continue;
                } else {
                    return Ok(Read::ready(None));
                }
            }
            let (row, target) = self.pending.as_ref().expect("one pending access row");
            let input = if self.replies.is_empty() {
                AccessRowInput::Start
            } else {
                AccessRowInput::Replies(&self.replies)
            };
            match rules.classify_row(context, row, target.as_ref(), input)? {
                AccessRowPoll::Members(request) => {
                    if !closer_step(
                        context.session,
                        cancellation,
                        CloserWork::CandidateClassification,
                    ) {
                        return Ok(Read::Cancelled(self.cancellation_completion()));
                    }
                    assert!(!self.replies.iter().any(|reply| matches!(reply, AccessPrerequisiteReply::Members { reference, lookup, .. } if *reference==request.reference && *lookup==request.lookup)), "consult existing row replies before requesting a member again");
                    self.outstanding = Some(AccessWait::Members {
                        reference: request.reference,
                        lookup: request.lookup,
                    });
                    return Ok(Read::Ready {
                        value: Some(AccessPrerequisiteRequest::Members(request)),
                        completion: self.completion.clone(),
                    });
                }
                AccessRowPoll::Reference(key) => {
                    assert!(!self.replies.iter().any(|reply| matches!(reply, AccessPrerequisiteReply::Reference { key: answered, .. } if *answered==key)), "consult existing row replies before requesting a reference again");
                    if !closer_step(
                        context.session,
                        cancellation,
                        CloserWork::CandidateClassification,
                    ) {
                        return Ok(Read::Cancelled(self.cancellation_completion()));
                    }
                    assert!(
                        self.outstanding
                            .replace(AccessWait::Reference(key))
                            .is_none()
                    );
                    return Ok(Read::Ready {
                        value: Some(AccessPrerequisiteRequest::Reference(key)),
                        completion: self.completion.clone(),
                    });
                }
                AccessRowPoll::Observed(completion) => {
                    self.observed = self.observed.combine(&completion);
                    // A complete no-effect proof discards this row's provisional
                    // projection/prerequisite evidence, not earlier rows' inputs.
                    self.completion = self
                        .pending_base
                        .take()
                        .expect("one observed row base")
                        .combine(&completion);
                    self.pending.take().expect("consume one observed row");
                    self.replies.clear();
                }
                AccessRowPoll::Ready(Read::Ready { value, completion }) => {
                    self.completion = self
                        .completion
                        .combine(&completion)
                        .combine(&value.completion);
                    self.pending_base
                        .take()
                        .expect("consume one classified row base");
                    let (_, target) = self.pending.take().expect("consume one classified row");
                    self.projected.push(ProjectedAccessRow::new(
                        context,
                        self.projected.len(),
                        target,
                        *value,
                    ));
                    self.replies.clear();
                }
                AccessRowPoll::Ready(Read::Cancelled(completion)) => {
                    return Ok(Read::Cancelled(
                        self.cancellation_completion().combine(&completion),
                    ));
                }
                AccessRowPoll::Ready(Read::Unavailable { reason, completion }) => {
                    return Ok(Read::Unavailable {
                        reason,
                        completion: self.completion.combine(&completion),
                    });
                }
            }
        }
    }
}

impl ProjectedAccessRow {
    pub(super) fn new(
        context: &MemberAccessContext<'_>,
        slot: usize,
        target: Option<SelectedMemberRouteTarget>,
        facts: AccessFacts,
    ) -> Self {
        assert_eq!(
            facts.provider.occurrence(),
            facts.occurrence,
            "access row retains exact provider occurrence"
        );
        Self {
            id: AccessCandidateId {
                request: context.provenance.identity(),
                reference: context.reference,
                lookup: context.lookup,
                step: context.step,
                slot,
            },
            target,
            facts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::resolution::{
        HierarchyOrderOutcome, HierarchyOrderedOwner, HierarchyProviderAuthority,
        HierarchyProviderObservation, HierarchyProviderOperand, with_test_member_order,
    };
    fn id(name: &str) -> SemanticId {
        SemanticId::for_test(name)
    }
    fn provider(owner: SemanticId) -> HierarchyProviderKey {
        HierarchyProviderKey::source(
            owner,
            id("lookup"),
            ResolutionNamespace::Value,
            HierarchyProviderAuthority::Declaration(owner),
            HierarchyProviderOperand::CandidateInventory,
            owner,
            0,
        )
    }
    fn fixture<T>(run: impl FnOnce(HierarchyProvenanceView<'_>, DemandMemberSelection) -> T) -> T {
        let owners = [id("first"), id("second"), id("third")];
        let observations = owners
            .iter()
            .map(|&owner| HierarchyProviderObservation {
                provider: provider(owner),
                visit: HierarchyProviderVisit::Observed,
                completion: ResolutionCompletion::Complete,
                inventory_complete: Some(true),
            })
            .collect();
        with_test_member_order(
            observations,
            |provenance| HierarchyOrderOutcome {
                cursor_scope: None,
                owners: owners
                    .into_iter()
                    .map(|owner| HierarchyOrderedOwner {
                        root: id("root"),
                        owner,
                        provenance,
                    })
                    .collect(),
                complete: true,
                required_base: None,
                completion: ResolutionCompletion::Complete,
            },
            run,
        )
    }
    fn target(slot: usize) -> SelectedMemberRouteTarget {
        let identity = [id("first"), id("second"), id("third")][slot];
        SelectedMemberRouteTarget {
            target: super::super::demand_closure::SelectedMemberTarget {
                fragment: BindingFragmentId::for_test("access-fragment"),
                token: identity,
                definition: BindingNodeId::for_test(format!("access-definition-{slot}")),
                lookup: ResolutionLookupSemanticRecipe::new(
                    Language::Rust,
                    ResolutionNamespace::Value,
                    "member",
                ),
                completion: ResolutionCompletion::Complete,
            },
            location: super::super::demand_closure::RouteLocation::Owner {
                definition: identity,
                scope: None,
            },
            namespace: ResolutionNamespace::Value,
            material: super::super::demand_closure::BridgeMaterial::same_language(Language::Rust),
        }
    }
    fn row(
        view: HierarchyProvenanceView<'_>,
        slot: usize,
        group: u32,
        within: AccessKey,
        between: AccessKey,
    ) -> ProjectedAccessRow {
        let owner = [id("first"), id("second"), id("third")][slot];
        ProjectedAccessRow {
            id: AccessCandidateId {
                request: view.identity(),
                reference: id("reference"),
                lookup: id("lookup"),
                step: 0,
                slot,
            },
            target: Some(target(slot)),
            facts: AccessFacts {
                ordered_range: None,
                alternative: AccessAlternativeId(id("receiver")),
                group: AccessGroupId(group),
                within_group: Box::new([within]),
                between_groups: Box::new([between]),
                provider: provider(owner),
                occurrence: owner,
                binding: MemberBinding::Unchanged,
                completion: ResolutionCompletion::Complete,
                coverage: Box::new([provider(owner)]),
                witnesses: Box::new([]),
            },
        }
    }
    fn session() -> ResolutionSession {
        ResolutionSession::unbounded()
    }
    fn context<'a>(
        session: &'a ResolutionSession,
        selection: &'a DemandMemberSelection,
        view: HierarchyProvenanceView<'a>,
        providers: &'a ProviderObservationStore,
    ) -> MemberAccessContext<'a> {
        MemberAccessContext {
            session,
            selection,
            provenance: view,
            providers,
            input_completion: &selection.completion,
            reference: id("reference"),
            lookup: id("lookup"),
            step: 0,
            namespace: ResolutionNamespace::Value,
        }
    }
    fn cursor_fixture<T>(
        complete: bool,
        required_base: Option<SemanticId>,
        owners: &[SemanticId],
        run: impl FnOnce(HierarchyProvenanceView<'_>, DemandMemberSelection) -> T,
    ) -> T {
        let observations = [id("first"), id("second"), id("third")]
            .into_iter()
            .map(|owner| HierarchyProviderObservation {
                provider: provider(owner),
                visit: HierarchyProviderVisit::Observed,
                completion: ResolutionCompletion::Complete,
                inventory_complete: Some(true),
            })
            .collect();
        with_test_member_order(
            observations,
            |provenance| HierarchyOrderOutcome {
                owners: owners
                    .iter()
                    .map(|&owner| HierarchyOrderedOwner {
                        root: id("root"),
                        owner,
                        provenance,
                    })
                    .collect(),
                complete,
                required_base,
                completion: ResolutionCompletion::Complete,
                cursor_scope: Some(Box::new(
                    crate::analyzer::resolution::HierarchyCursorScope {
                        start_after: id("first"),
                        roots: Box::new([id("root")]),
                    },
                )),
            },
            run,
        )
    }

    #[test]
    fn member_access_complete_cursor_excludes_before_cursor_and_preserves_empty_tail() {
        for tail in [vec![id("second"), id("third")], vec![]] {
            cursor_fixture(true, None, &tail, |view, mut selection| {
                selection.owners.insert(0, id("first"));
                let original_owners = selection.owners.clone();
                let providers = ProviderObservationStore::default();
                let session = session();
                let context = context(&session, &selection, view, &providers);
                let range = AccessOrderedRange {
                    order: selection.order.unwrap(),
                    root: id("root"),
                    start_after: id("first"),
                };
                let mut rows = vec![row(view, 0, 0, AccessKey::Unknown, AccessKey::Fixed(0))];
                if !tail.is_empty() {
                    rows.push(row(
                        view,
                        1,
                        0,
                        AccessKey::Owner {
                            order: range.order,
                            root: range.root,
                            owner: id("second"),
                        },
                        AccessKey::Fixed(0),
                    ));
                    rows.push(row(
                        view,
                        2,
                        0,
                        AccessKey::Owner {
                            order: range.order,
                            root: range.root,
                            owner: id("third"),
                        },
                        AccessKey::Fixed(0),
                    ));
                }
                for row in &mut rows {
                    row.facts.ordered_range = Some(range);
                }
                let Read::Ready { value, .. } =
                    reduce_member_access(&context, rows, &session, &CancellationToken::new())
                        .unwrap()
                else {
                    panic!("ready");
                };
                assert_eq!(value.evidence.range_certificates.len(), 1);
                if tail.is_empty() {
                    assert_eq!(value.evidence.outcome, AccessOutcome::Empty);
                    assert!(value.targets.is_empty());
                } else {
                    assert_eq!(value.evidence.outcome, AccessOutcome::Unique);
                    assert_eq!(
                        value.targets[0].target.definition,
                        BindingNodeId::for_test("access-definition-1")
                    );
                }
                assert_eq!(selection.owners, original_owners);
            });
        }
    }

    #[test]
    fn member_access_cursor_refuses_foreign_scope_partial_orders_and_input_reasons() {
        for (complete, required_base, tail) in [
            (true, None, vec![id("second")]),
            (false, None, vec![id("second")]),
            (false, None, vec![]),
            (true, Some(id("unknown")), vec![]),
        ] {
            cursor_fixture(complete, required_base, &tail, |view, selection| {
                let providers = ProviderObservationStore::default();
                let session = session();
                let context = context(&session, &selection, view, &providers);
                for (root, start_after, foreign_provider, foreign_reason) in [
                    (id("root"), id("first"), false, false),
                    (id("foreign-root"), id("first"), false, false),
                    (id("root"), id("foreign-cursor"), false, false),
                    (id("root"), id("first"), true, false),
                    (id("root"), id("first"), false, true),
                ] {
                    let range = AccessOrderedRange {
                        order: selection.order.unwrap(),
                        root,
                        start_after,
                    };
                    let mut rows = vec![row(view, 0, 0, AccessKey::Unknown, AccessKey::Fixed(0))];
                    rows[0].facts.ordered_range = Some(range);
                    if foreign_provider {
                        rows[0].facts.provider = provider(id("foreign-owner"));
                    }
                    let certificate = MemberAccessRangeCertificate {
                        range,
                        excluded: rows[0].id,
                        coverage: rows[0].facts.coverage.clone(),
                        discharges: if foreign_reason {
                            Box::new([ProviderReasonSubset {
                                provider: rows[0].facts.provider.clone(),
                                reasons: Box::new([
                                    ResolutionIncompleteReason::UnsupportedSemantic(id("foreign")),
                                ]),
                            }])
                        } else {
                            Box::new([])
                        },
                    };
                    let result = validate_member_access_range_certificate(
                        &context,
                        &rows,
                        &certificate,
                        &CancellationToken::new(),
                    )
                    .unwrap();
                    let valid = complete
                        && required_base.is_none()
                        && root == id("root")
                        && start_after == id("first")
                        && !foreign_provider
                        && !foreign_reason;
                    assert_eq!(matches!(result, Read::Ready { .. }), valid);
                    let token = CancellationToken::new();
                    token.cancel();
                    assert!(matches!(
                        reduce_member_access(&context, rows, &session, &token).unwrap(),
                        Read::Cancelled(_)
                    ));
                }
            });
        }
    }

    #[test]
    fn member_access_groups_preserve_equal_and_unknown_alternatives() {
        fixture(|view, selection| {
            let providers = ProviderObservationStore::default();
            let session = session();
            let context = context(&session, &selection, view, &providers);
            let rows = vec![
                row(view, 0, 0, AccessKey::Fixed(0), AccessKey::Fixed(2)),
                row(view, 1, 1, AccessKey::Fixed(0), AccessKey::Fixed(2)),
                row(view, 2, 2, AccessKey::Fixed(0), AccessKey::Unknown),
            ];
            let Read::Ready { value, .. } =
                reduce_member_access(&context, rows, &session, &CancellationToken::new()).unwrap()
            else {
                panic!("ready");
            };
            assert_eq!(value.evidence.bindings.len(), 3);
            assert!(value.evidence.certificates.is_empty());
            assert_eq!(value.evidence.outcome, AccessOutcome::Open);
        });
    }
    #[test]
    fn member_access_dictionary_definition_precedes_later_descriptor() {
        fixture(|view, selection| {
            let providers = ProviderObservationStore::default();
            let session = session();
            let context = context(&session, &selection, view, &providers);
            let order = selection.order.unwrap();
            let key = |owner| AccessKey::Owner {
                order,
                root: id("root"),
                owner: id(owner),
            };
            // Same dictionary: its first ordinary definition wins before the
            // later descriptor's stronger inter-dictionary priority participates.
            let rows = vec![
                row(view, 0, 0, key("first"), AccessKey::Fixed(2)),
                row(view, 1, 0, key("second"), AccessKey::Fixed(0)),
                row(view, 2, 1, AccessKey::Fixed(0), AccessKey::Fixed(1)),
            ];
            let Read::Ready { value, .. } =
                reduce_member_access(&context, rows, &session, &CancellationToken::new()).unwrap()
            else {
                panic!("ready");
            };
            assert_eq!(
                value
                    .evidence
                    .bindings
                    .iter()
                    .map(|(id, _)| id.slot)
                    .collect::<Vec<_>>(),
                [2]
            );
            assert_eq!(value.evidence.certificates.len(), 2);
            assert_eq!(value.evidence.certificates[0].winner.slot, 0);
            assert_eq!(value.evidence.certificates[0].excluded.slot, 1);
            assert_eq!(value.evidence.outcome, AccessOutcome::Unique);
            assert_eq!(
                value.targets[0].target.definition,
                BindingNodeId::for_test("access-definition-2")
            );
        });
    }
    #[test]
    fn member_access_refuses_incomplete_required_and_capped_order_certificates() {
        for (complete, required_base, owners) in [
            (false, None, vec![id("first"), id("second")]),
            (false, Some(id("unknown")), vec![]),
            (false, None, vec![]),
        ] {
            with_test_member_order(
                Vec::new(),
                |provenance| HierarchyOrderOutcome {
                    cursor_scope: None,
                    owners: owners
                        .into_iter()
                        .map(|owner| HierarchyOrderedOwner {
                            root: id("root"),
                            owner,
                            provenance,
                        })
                        .collect(),
                    complete,
                    required_base,
                    completion: ResolutionCompletion::Complete,
                },
                |view, selection| {
                    let providers = ProviderObservationStore::default();
                    let session = session();
                    let context = context(&session, &selection, view, &providers);
                    let rows = vec![
                        row(view, 0, 0, AccessKey::Fixed(0), AccessKey::Fixed(0)),
                        row(view, 1, 0, AccessKey::Fixed(1), AccessKey::Fixed(1)),
                    ];
                    let certificate = MemberAccessCertificate {
                        order: selection.order.unwrap(),
                        winner: rows[0].id,
                        excluded: rows[1].id,
                        coverage: required_coverage(&rows, rows[0].facts.alternative, &mut || {
                            false
                        })
                        .unwrap(),
                        discharges: Box::new([]),
                    };
                    assert!(matches!(
                        validate_member_access_certificate(
                            &context,
                            &rows,
                            &certificate,
                            &CancellationToken::new()
                        )
                        .unwrap(),
                        Read::Unavailable { .. }
                    ));
                },
            );
        }
    }
    #[test]
    fn member_access_refuses_foreign_provider_and_outside_reason() {
        fixture(|view, selection| {
            let providers = ProviderObservationStore::default();
            let session = session();
            let context = context(&session, &selection, view, &providers);
            let rows = vec![
                row(view, 0, 0, AccessKey::Fixed(0), AccessKey::Fixed(0)),
                row(view, 1, 0, AccessKey::Fixed(1), AccessKey::Fixed(1)),
            ];
            let mut certificate = MemberAccessCertificate {
                order: selection.order.unwrap(),
                winner: rows[0].id,
                excluded: rows[1].id,
                coverage: required_coverage(&rows, rows[0].facts.alternative, &mut || false)
                    .unwrap(),
                discharges: Box::new([]),
            };
            certificate.coverage[0] = HierarchyProviderKey::source(
                id("first"),
                id("lookup"),
                ResolutionNamespace::Value,
                HierarchyProviderAuthority::Context {
                    mount: 7,
                    version: 1,
                    order: 0,
                    blob: None,
                },
                HierarchyProviderOperand::CandidateInventory,
                id("first"),
                0,
            );
            assert!(matches!(
                validate_member_access_certificate(
                    &context,
                    &rows,
                    &certificate,
                    &CancellationToken::new()
                )
                .unwrap(),
                Read::Unavailable { .. }
            ));
            certificate.coverage =
                required_coverage(&rows, rows[0].facts.alternative, &mut || false).unwrap();
            let reason = ResolutionIncompleteReason::UnsupportedSemantic(id("foreign-reason"));
            let input = ResolutionCompletion::incomplete([reason]);
            let context = MemberAccessContext {
                input_completion: &input,
                ..context
            };
            certificate.discharges = Box::new([ProviderReasonSubset {
                provider: provider(id("first")),
                reasons: Box::new([reason]),
            }]);
            assert!(matches!(
                validate_member_access_certificate(
                    &context,
                    &rows,
                    &certificate,
                    &CancellationToken::new()
                )
                .unwrap(),
                Read::Unavailable { .. }
            ));
        });
    }
    #[test]
    fn member_access_cancellation_returns_no_partial_targets() {
        fixture(|view, selection| {
            let providers = ProviderObservationStore::default();
            let session = session();
            let context = context(&session, &selection, view, &providers);
            let mut cancelled = 0;
            let mut complete = false;
            for checks in 0..1024 {
                let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
                let rows = (0..3)
                    .map(|slot| {
                        row(
                            view,
                            slot,
                            0,
                            AccessKey::Fixed(slot as u32),
                            AccessKey::Fixed(0),
                        )
                    })
                    .collect();
                match reduce_member_access(&context, rows, &session, &cancellation).unwrap() {
                    Read::Cancelled(_) => cancelled += 1,
                    Read::Ready { value, .. } => {
                        // Even cancellation after provisional exclusions may
                        // return only the full certified result, never a prefix.
                        assert_eq!(
                            value
                                .evidence
                                .bindings
                                .iter()
                                .map(|(id, _)| id.slot)
                                .collect::<Vec<_>>(),
                            [0]
                        );
                        assert_eq!(value.evidence.certificates.len(), 2);
                        assert_eq!(value.targets.len(), 1);
                        assert_eq!(
                            value.targets[0].target.definition,
                            BindingNodeId::for_test("access-definition-0")
                        );
                        complete = true;
                        break;
                    }
                    _ => panic!("cancelled or fully reduced"),
                }
            }
            assert!(cancelled > 0 && complete);
        });
    }
    #[derive(Debug)]
    struct WaitingRules;
    impl MemberAccessRules<u32> for WaitingRules {
        fn classify_row(
            &self,
            context: &MemberAccessContext<'_>,
            _: &u32,
            _: Option<&SelectedMemberRouteTarget>,
            input: AccessRowInput<'_>,
        ) -> Result<AccessRowPoll> {
            let count = match input {
                AccessRowInput::Start => 0,
                AccessRowInput::Replies(replies) => {
                    for (i, reply) in replies.iter().enumerate() {
                        let AccessPrerequisiteReply::Members {
                            reference,
                            lookup,
                            selection,
                        } = reply
                        else {
                            panic!("member fixture reply");
                        };
                        assert_eq!(*reference, id(&format!("dependency-{i}")));
                        assert_eq!(*lookup, id("lookup"));
                        assert_eq!(selection.owners, context.selection.owners);
                    }
                    replies.len()
                }
            };
            if count < 2 {
                return Ok(AccessRowPoll::Members(DemandMemberSelectionRequest {
                    policy: &crate::analyzer::resolution::DEFAULT_HIERARCHY_POLICY,
                    order: None,
                    reference: id(&format!("dependency-{count}")),
                    values: Vec::new(),
                    lookup: id("lookup"),
                    namespace: ResolutionNamespace::Value,
                    language: Language::Rust,
                }));
            }
            Ok(AccessRowPoll::Ready(Read::ready(Box::new(
                row(
                    context.provenance,
                    0,
                    0,
                    AccessKey::Fixed(0),
                    AccessKey::Fixed(0),
                )
                .facts,
            ))))
        }
    }
    #[test]
    fn member_access_prerequisites_resume_without_repeated_rows_or_projections() {
        fixture(|view, selection| {
            let providers = ProviderObservationStore::default();
            let session = session();
            let context = context(&session, &selection, view, &providers);
            let cancellation = CancellationToken::new();
            let mut state = MemberAccessState::<u32>::new(&selection);
            let reads = std::cell::Cell::new(0);
            let projections = std::cell::Cell::new(0);
            for turn in 0..3 {
                let result = state
                    .rows
                    .poll(
                        &context,
                        &WaitingRules,
                        &cancellation,
                        |owner| {
                            reads.set(reads.get() + 1);
                            Ok(Read::ready(if owner == id("first") {
                                vec![0]
                            } else {
                                vec![]
                            }))
                        },
                        |_| {
                            projections.set(projections.get() + 1);
                            Ok(Read::ready(None))
                        },
                    )
                    .unwrap();
                match result {
                    Read::Ready {
                        value: Some(request),
                        ..
                    } => {
                        assert!(turn < 2);
                        let AccessPrerequisiteRequest::Members(request) = request else {
                            panic!("member fixture wait");
                        };
                        assert_eq!(request.reference, id(&format!("dependency-{turn}")));
                        assert_eq!(reads.get(), 1);
                        assert_eq!(projections.get(), 1);
                        assert!(state.rows.projected.is_empty());
                        state.rows.resume_members(&selection);
                    }
                    Read::Ready { value: None, .. } => assert_eq!(turn, 2),
                    _ => panic!("ready or suspended"),
                }
            }
            assert_eq!(reads.get(), 3);
            assert_eq!(projections.get(), 1);
            assert_eq!(state.rows.projected.len(), 1);
            assert!(state.rows.pending.is_none());
        });
    }
    #[test]
    fn member_access_unprojected_complete_row_settles_with_reference_reason() {
        #[derive(Debug)]
        struct DeclaredRules;
        impl MemberAccessRules<u32> for DeclaredRules {
            fn classify_row(
                &self,
                context: &MemberAccessContext<'_>,
                _: &u32,
                target: Option<&SelectedMemberRouteTarget>,
                _: AccessRowInput<'_>,
            ) -> Result<AccessRowPoll> {
                assert!(target.is_none());
                Ok(AccessRowPoll::Ready(Read::ready(Box::new(
                    row(
                        context.provenance,
                        0,
                        0,
                        AccessKey::Fixed(0),
                        AccessKey::Fixed(0),
                    )
                    .facts,
                ))))
            }
        }
        fixture(|view, mut selection| {
            selection.owners = vec![id("first")];
            assert_eq!(selection.completion, ResolutionCompletion::Complete);
            assert!(view.order_status(selection.order.unwrap()).complete);
            let session = session();
            let mut state = MemberAccessState::<u32>::new(&selection);
            let site = MemberAccessSite {
                session: &session,
                selection: &selection,
                provenance: view,
                input_completion: &ResolutionCompletion::Complete,
                reference: id("reference"),
                lookup: id("lookup"),
                step: 0,
                namespace: ResolutionNamespace::Value,
            };
            let projections = std::cell::Cell::new(0);
            let read = poll_member_access(
                &mut state.rows,
                &site,
                &DeclaredRules,
                &mut ProviderObservationStore::default(),
                &mut ResolutionCompletion::Complete,
                &mut ResolutionCompletion::Complete,
                &CancellationToken::new(),
                |_| Ok(Read::ready(vec![0])),
                |_| {
                    projections.set(projections.get() + 1);
                    Ok(Read::ready(None))
                },
                || Ok(Read::ready(Vec::new())),
            )
            .unwrap();
            assert_eq!(projections.get(), 1);
            let Read::Unavailable { completion, .. } = read else {
                panic!("a complete declared row without a target leaves access open");
            };
            // The source closer passes unavailable evidence to this checked
            // constructor. A reasonless open access used to panic here.
            let root = crate::analyzer::resolution::RootClosure::settled(completion);
            assert!(matches!(
                root,
                crate::analyzer::resolution::RootClosure::Settled(_)
            ));
            assert_eq!(
                root.completion(),
                &ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(site.reference),
                ])
            );
        });
    }
    #[test]
    fn member_access_empty_owner_keeps_its_observation_and_completion() {
        fixture(|view, selection| {
            let providers = ProviderObservationStore::default();
            let session = session();
            let context = context(&session, &selection, view, &providers);
            let mut state = MemberAccessState::<u32>::new(&selection);
            let gap = ResolutionIncompleteReason::UnsupportedSemantic(id("empty-inventory-gap"));
            let read = state
                .rows
                .poll(
                    &context,
                    &WaitingRules,
                    &CancellationToken::new(),
                    |_| {
                        Ok(Read::Ready {
                            value: vec![],
                            completion: ResolutionCompletion::incomplete([gap]),
                        })
                    },
                    |_| panic!("empty owner has no row to project"),
                )
                .unwrap();
            assert!(matches!(read, Read::Ready { value: None, .. }));
            assert!(state.rows.completion.contains_reason(gap));
            assert!(state.rows.projected.is_empty());
        });
    }
    #[derive(Debug)]
    struct ReferenceRules<'a> {
        cancellation: &'a CancellationToken,
        cancel_at_yield: bool,
    }
    impl MemberAccessRules<u32> for ReferenceRules<'_> {
        fn classify_row(
            &self,
            context: &MemberAccessContext<'_>,
            _: &u32,
            _: Option<&SelectedMemberRouteTarget>,
            input: AccessRowInput<'_>,
        ) -> Result<AccessRowPoll> {
            let replies = match input {
                AccessRowInput::Start => &[][..],
                AccessRowInput::Replies(replies) => replies,
            };
            let mut completion = ResolutionCompletion::Complete;
            for name in ["row-dependency", "second-row-dependency"] {
                let key = DemandReferenceKey::caller(id(name));
                let answer = replies.iter().find_map(|reply| match reply {
                    AccessPrerequisiteReply::Reference {
                        key: answered,
                        answer,
                    } if *answered == key => Some(answer),
                    _ => None,
                });
                let Some(answer) = answer else {
                    if self.cancel_at_yield {
                        self.cancellation.cancel();
                    }
                    return Ok(AccessRowPoll::Reference(key));
                };
                if answer.binding().completion() == &ResolutionCompletion::Complete {
                    assert_eq!(answer.binding().targets(), &[id("selected-dependency")]);
                } else {
                    assert!(answer.binding().targets().is_empty());
                }
                completion = completion.combine(answer.binding().completion());
            }
            let mut facts = row(
                context.provenance,
                0,
                0,
                AccessKey::Fixed(0),
                AccessKey::Fixed(0),
            )
            .facts;
            facts.completion = completion;
            Ok(AccessRowPoll::Ready(Read::ready(Box::new(facts))))
        }
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "61ec19c10b5e: already-open misses incorrectly queried late inventory"
    )]
    fn late_inventory_observation_suspends_once_and_never_runs_for_a_hit_or_open_miss() {
        use crate::analyzer::resolution::FactReferenceSiteMetadata;
        use brokk_bifrost_core::analyzer::resolution_facts::{
            ResolutionSiteId, ResolutionSiteKind,
        };
        #[derive(Debug)]
        struct Rules {
            calls: std::cell::Cell<u32>,
            completion: ResolutionCompletion,
            observations: std::cell::RefCell<Vec<HierarchyProviderObservation>>,
        }
        impl MemberAccessRules<u32> for Rules {
            fn late_inventory(
                &self,
                _: &MemberAccessContext<'_>,
                _: &[SemanticId],
                _: SemanticId,
            ) -> Result<Read<Vec<u32>>> {
                self.calls.set(self.calls.get() + 1);
                Ok(Read::ready(vec![1]))
            }
            fn classify_row(
                &self,
                context: &MemberAccessContext<'_>,
                row_id: &u32,
                _: Option<&SelectedMemberRouteTarget>,
                input: AccessRowInput<'_>,
            ) -> Result<AccessRowPoll> {
                if *row_id == 0 {
                    return Ok(AccessRowPoll::Ready(Read::ready(Box::new(
                        row(
                            context.provenance,
                            0,
                            0,
                            AccessKey::Fixed(0),
                            AccessKey::Fixed(0),
                        )
                        .facts,
                    ))));
                }
                let key = DemandReferenceKey::caller(id("late-reference"));
                let AccessRowInput::Replies(replies) = input else {
                    return Ok(AccessRowPoll::Reference(key));
                };
                assert!(
                    matches!(replies, [AccessPrerequisiteReply::Reference { key: answered, .. }] if *answered==key)
                );
                self.observations
                    .borrow_mut()
                    .push(HierarchyProviderObservation {
                        provider: provider(id("late-inventory")),
                        visit: HierarchyProviderVisit::Observed,
                        completion: self.completion.clone(),
                        inventory_complete: Some(self.completion == ResolutionCompletion::Complete),
                    });
                Ok(AccessRowPoll::Observed(self.completion.clone()))
            }
        }
        let gap = ResolutionIncompleteReason::UnsupportedSemantic(id("late-gap"));
        for (hit, initially_open, completion) in [
            (true, false, ResolutionCompletion::Complete),
            (false, false, ResolutionCompletion::Complete),
            (false, false, ResolutionCompletion::incomplete([gap])),
            (false, true, ResolutionCompletion::incomplete([gap])),
        ] {
            fixture(|view, mut selection| {
                if initially_open {
                    selection.completion = completion.clone();
                }
                let rules = Rules {
                    calls: std::cell::Cell::new(0),
                    completion: completion.clone(),
                    observations: Default::default(),
                };
                let session = session();
                let cancellation = CancellationToken::new();
                let site = MemberAccessSite {
                    session: &session,
                    selection: &selection,
                    provenance: view,
                    input_completion: &selection.completion,
                    reference: id("reference"),
                    lookup: id("lookup"),
                    step: 0,
                    namespace: ResolutionNamespace::Value,
                };
                let mut rows = MemberAccessState::new(&selection).rows;
                let mut providers = ProviderObservationStore::default();
                let mut hooks = ResolutionCompletion::Complete;
                let mut evidence = ResolutionCompletion::Complete;
                let reads = std::cell::Cell::new(0);
                let mut poll = |rows: &mut MemberAccessRows<u32>| {
                    poll_member_access(
                        rows,
                        &site,
                        &rules,
                        &mut providers,
                        &mut hooks,
                        &mut evidence,
                        &cancellation,
                        |owner| {
                            reads.set(reads.get() + 1);
                            Ok(Read::ready(if hit && owner == id("first") {
                                vec![0]
                            } else {
                                vec![]
                            }))
                        },
                        |row_id| Ok(Read::ready((*row_id == 0).then(|| target(0)))),
                        || {
                            Ok(Read::ready(std::mem::take(
                                &mut *rules.observations.borrow_mut(),
                            )))
                        },
                    )
                };
                let first = poll(&mut rows).unwrap();
                let result = if hit || initially_open {
                    first
                } else {
                    let Read::Ready {
                        value:
                            MemberAccessProgress::Awaiting(AccessPrerequisiteRequest::Reference(key)),
                        ..
                    } = first
                    else {
                        panic!("late reference suspension");
                    };
                    assert_eq!(reads.get(), 3);
                    let answer = FactResolutionAnswer::from_selected_summary_binding(
                        FactReferenceSiteMetadata::new(
                            ResolutionSiteId::new(0),
                            ResolutionNamespace::Value,
                            ResolutionSiteKind::ValueReference,
                            0,
                            1,
                            true,
                            None,
                            None,
                        ),
                        vec![id("unrelated")],
                        ResolutionCompletion::Complete,
                    );
                    assert!(matches!(
                        rows.resume_reference(key, &answer, &session, &cancellation)
                            .unwrap(),
                        Read::Ready { .. }
                    ));
                    poll(&mut rows).unwrap()
                };
                let Read::Ready {
                    value: MemberAccessProgress::Ready(result),
                    ..
                } = result
                else {
                    panic!("ready access");
                };
                assert_eq!(rules.calls.get(), u32::from(!hit && !initially_open));
                assert_eq!(
                    reads.get(),
                    3,
                    "owner rows are never replayed after late suspension"
                );
                assert_eq!(result.targets.len(), usize::from(hit));
                assert_eq!(result.completion, completion);
                assert_eq!(
                    result.evidence.outcome,
                    if hit {
                        AccessOutcome::Unique
                    } else if completion == ResolutionCompletion::Complete {
                        AccessOutcome::Empty
                    } else {
                        AccessOutcome::Open
                    }
                );
                assert!(result.evidence.certificates.is_empty());
                if !hit && !initially_open {
                    assert_eq!(
                        providers
                            .get(&provider(id("late-inventory")))
                            .unwrap()
                            .completion,
                        completion
                    );
                }
            });
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5658+#6509: reference waits retain rows while binding evidence excludes unrelated type gaps"
    )]
    fn member_access_reference_wait_retains_row_and_observes_yield_and_resume_cancellation() {
        use crate::analyzer::resolution::FactReferenceSiteMetadata;
        use brokk_bifrost_core::analyzer::resolution_facts::{
            ResolutionSiteId, ResolutionSiteKind,
        };
        fixture(|view, selection| {
            let session = session();
            let providers = ProviderObservationStore::default();
            let context = context(&session, &selection, view, &providers);
            for cancel in 0..8 {
                let answer = FactResolutionAnswer::from_selected_summary_binding(
                    FactReferenceSiteMetadata::new(
                        ResolutionSiteId::new(0),
                        ResolutionNamespace::Value,
                        ResolutionSiteKind::ValueReference,
                        0,
                        1,
                        true,
                        None,
                        None,
                    ),
                    if cancel == 3 {
                        Vec::new()
                    } else {
                        vec![id("selected-dependency")]
                    },
                    if cancel == 3 {
                        ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(id(
                                "missing-prerequisite-source",
                            )),
                        ])
                    } else {
                        ResolutionCompletion::Complete
                    },
                );

                let type_gap =
                    ResolutionIncompleteReason::UnsupportedSemantic(id("missing-type-property"));
                let answer = if cancel >= 4 {
                    crate::analyzer::resolution::fact_resolution::fixture_support::answer_with_frontier(
                        answer,
                        crate::analyzer::resolution::TypedFrontierState::new(
                            id("dependency-type"),
                            Vec::new(),
                            ResolutionCompletion::incomplete([type_gap]),
                        ),
                    )
                } else {
                    answer
                };
                let cancellation = CancellationToken::new();
                let rules = ReferenceRules {
                    cancellation: &cancellation,
                    cancel_at_yield: cancel == 1,
                };
                let reads = std::cell::Cell::new(0);
                let projections = std::cell::Cell::new(0);
                let mut state = MemberAccessState::new(&selection);
                let polled = state
                    .rows
                    .poll(
                        &context,
                        &rules,
                        &cancellation,
                        |owner| {
                            reads.set(reads.get() + 1);
                            Ok(Read::ready(if owner == id("first") {
                                vec![0]
                            } else {
                                vec![]
                            }))
                        },
                        |_| {
                            projections.set(projections.get() + 1);
                            Ok(Read::ready(Some(target(0))))
                        },
                    )
                    .unwrap();
                if cancel == 1 {
                    assert!(matches!(polled, Read::Cancelled(_)));
                    assert!(state.rows.projected.is_empty());
                    continue;
                }
                let Read::Ready {
                    value: Some(AccessPrerequisiteRequest::Reference(key)),
                    ..
                } = polled
                else {
                    panic!("row reference wait");
                };
                assert_eq!((reads.get(), projections.get()), (1, 1));
                if cancel == 2 || cancel == 5 {
                    cancellation.cancel();
                }
                let resumed = state
                    .rows
                    .resume_reference(key, &answer, &session, &cancellation)
                    .unwrap();
                if cancel == 2 || cancel == 5 {
                    let Read::Cancelled(completion) = resumed else {
                        panic!("cancelled resume");
                    };
                    if cancel == 5 {
                        assert!(completion.contains_reason(type_gap));
                    }
                    assert!(state.rows.projected.is_empty());
                    continue;
                }
                assert!(matches!(resumed, Read::Ready { .. }));
                if cancel == 7 {
                    // A provider read can cancel while the second reference
                    // wait still retains the first reply's type evidence.
                    let site = MemberAccessSite {
                        session: &session,
                        selection: &selection,
                        provenance: view,
                        input_completion: &selection.completion,
                        reference: id("reference"),
                        lookup: id("lookup"),
                        step: 0,
                        namespace: ResolutionNamespace::Value,
                    };
                    let mut providers = ProviderObservationStore::default();
                    let mut hooks = ResolutionCompletion::Complete;
                    let mut evidence = ResolutionCompletion::Complete;
                    let read = poll_member_access(
                        &mut state.rows,
                        &site,
                        &rules,
                        &mut providers,
                        &mut hooks,
                        &mut evidence,
                        &cancellation,
                        |_| panic!("held row must not read owners again"),
                        |_| panic!("held row must not project again"),
                        || Ok(Read::Cancelled(ResolutionCompletion::Complete)),
                    )
                    .unwrap();
                    let Read::Cancelled(completion) = read else {
                        panic!("cancelled provider read");
                    };
                    assert!(completion.contains_reason(type_gap));
                    assert_eq!(
                        state.rows.outstanding,
                        Some(AccessWait::Reference(DemandReferenceKey::caller(id(
                            "second-row-dependency"
                        ))))
                    );
                    continue;
                }
                if cancel == 6 {
                    cancellation.cancel();
                }
                let second = state
                    .rows
                    .poll(
                        &context,
                        &rules,
                        &cancellation,
                        |_| panic!("held row must not read owners again"),
                        |_| panic!("held row must not project again"),
                    )
                    .unwrap();
                if cancel == 6 {
                    let Read::Cancelled(completion) = second else {
                        panic!("cancelled held row");
                    };
                    assert!(completion.contains_reason(type_gap));
                    continue;
                }
                let Read::Ready {
                    value: Some(AccessPrerequisiteRequest::Reference(key)),
                    ..
                } = second
                else {
                    panic!("second reference wait");
                };
                assert_eq!(key, DemandReferenceKey::caller(id("second-row-dependency")));
                assert!(matches!(
                    state
                        .rows
                        .resume_reference(key, &answer, &session, &cancellation)
                        .unwrap(),
                    Read::Ready { .. }
                ));
                let polled = state
                    .rows
                    .poll(
                        &context,
                        &rules,
                        &cancellation,
                        |_| {
                            reads.set(reads.get() + 1);
                            Ok(Read::ready(vec![]))
                        },
                        |_| panic!("held row must not project again"),
                    )
                    .unwrap();
                assert!(matches!(polled, Read::Ready { value: None, .. }));
                if cancel == 4 {
                    assert_eq!(
                        answer.binding().completion(),
                        &ResolutionCompletion::Complete
                    );
                    assert!(answer.completion().contains_reason(type_gap));
                    assert_eq!(state.rows.completion, ResolutionCompletion::Complete);
                    assert_eq!(
                        state.rows.projected[0].facts.completion,
                        ResolutionCompletion::Complete
                    );
                }
                assert_eq!((reads.get(), projections.get()), (3, 1));
                assert_eq!(state.rows.projected.len(), 1);
                assert!(
                    state.rows.projected[0].target.is_some(),
                    "incomplete reply keeps the declaration"
                );
                if cancel == 3 {
                    assert!(state.rows.completion.contains_reason(
                        ResolutionIncompleteReason::UnsupportedSemantic(id(
                            "missing-prerequisite-source"
                        ))
                    ));
                }
                assert!(state.rows.replies.is_empty());
            }
        });
    }
}

// A contract provider, rather than a second evaluator: actual typed inputs and
// hierarchy/order certificates come from the scheduler. These tables describe
// rows and deliberately suspend their classification across both wait kinds.
#[cfg(test)]
pub(crate) mod bridge_contract {
    use super::super::demand_closure::{BridgeMaterial, RouteLocation, SelectedMemberTarget};
    use super::*;
    use crate::analyzer::resolution::*;
    use std::cell::{Cell, RefCell};

    #[derive(Debug)]
    pub(crate) struct Collection;
    pub(crate) static COLLECTION: Collection = Collection;
    impl HierarchyPolicy for Collection {
        fn identity(&self) -> HierarchyPolicyId {
            HierarchyPolicyId(0x434f_4e54)
        }
        fn edge_provider(&self) -> &'static dyn HierarchyEdgeProvider {
            &EXPLICIT_HIERARCHY_EDGES
        }
        fn compare_distance(&self, _: HierarchyLookupShape, _: u32, _: u32) -> Ordering {
            Ordering::Equal
        }
        fn retain_owner(&self, _: bool) -> bool {
            true
        }
        fn direct_hit_stops(&self, _: HierarchyLookupShape) -> bool {
            false
        }
        fn evidence_cutoff(&self, _: HierarchyLookupShape, _: Option<u32>) -> Option<u32> {
            None
        }
    }

    pub(crate) struct Provider {
        pub rows: Vec<(SemanticId, SemanticId, BindingNodeId)>,
        pub expected_root: SemanticId,
        pub prerequisite: DemandReferenceKey,
        pub reads: RefCell<Vec<SemanticId>>,
        pub projects: Cell<usize>,
        pub phases: RefCell<Vec<&'static str>>,
        pub written: Vec<SemanticId>,
        pub preparations: usize,
        input: Option<QualifiedMemberInput>,
        slot: Option<(QualifiedMemberId, QualifiedMemberAccessSlot<usize>)>,
        observations: RefCell<Vec<HierarchyProviderObservation>>,
        session: ResolutionSession,
        cancellation: CancellationToken,
    }
    impl std::fmt::Debug for Provider {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("QualifiedContractProvider")
                .finish_non_exhaustive()
        }
    }
    impl Provider {
        pub fn new(
            rows: Vec<(SemanticId, SemanticId, BindingNodeId)>,
            expected_root: SemanticId,
            prerequisite: DemandReferenceKey,
        ) -> Self {
            Self {
                rows,
                expected_root,
                prerequisite,
                reads: RefCell::new(Vec::new()),
                projects: Cell::new(0),
                phases: RefCell::new(Vec::new()),
                written: Vec::new(),
                preparations: 0,
                input: None,
                slot: None,
                observations: RefCell::new(Vec::new()),
                session: ResolutionSession::unbounded(),
                cancellation: CancellationToken::new(),
            }
        }
        fn provider(&self, owner: SemanticId) -> HierarchyProviderKey {
            let input = self.input.as_ref().unwrap();
            HierarchyProviderKey::source(
                owner,
                input.lookup,
                input.namespace,
                HierarchyProviderAuthority::Declaration(owner),
                HierarchyProviderOperand::CandidateInventory,
                input.reference.reference,
                input.route_ordinal as u32,
            )
        }
        fn request(&self, reference: SemanticId) -> DemandMemberSelectionRequest {
            let input = self.input.as_ref().unwrap();
            DemandMemberSelectionRequest {
                policy: &COLLECTION,
                order: Some(HierarchyOrderRequest {
                    policy: &super::super::python_members::PYTHON_C3,
                    start_after: None,
                }),
                reference,
                values: input.values.clone(),
                lookup: input.lookup,
                namespace: input.namespace,
                language: input.registration.language,
            }
        }
    }
    impl DemandRootProvider for Provider {
        fn qualified_members(&mut self) -> Option<&mut dyn QualifiedMemberProvider> {
            Some(self)
        }
        fn discover(&mut self, _: &DemandRelationKey) -> Result<DemandRootDiscovery> {
            Ok(DemandRootDiscovery::AlreadyReady {
                completion: ResolutionCompletion::Complete,
            })
        }
        fn close(
            &mut self,
            _: &DemandRelationKey,
            _: &[(DemandReferenceKey, &FactResolutionAnswer)],
        ) -> Result<crate::analyzer::resolution::RootClosure> {
            unreachable!("fixture lexical source is assembled")
        }
    }
    impl QualifiedMemberProvider for Provider {
        fn prepare_qualified_member(
            &mut self,
            id: QualifiedMemberId,
            input: &QualifiedMemberInput,
            _: HierarchyProvenanceView<'_>,
            resume: CloseResume<'_>,
        ) -> Result<CloseProgress<DemandMemberSelectionOutcome>> {
            assert!(matches!(resume, CloseResume::Start));
            // Registered hooks may prepare structural proxy prerequisites
            // before a typed receiver exists. This contract has no proxy rule.
            if input.values.is_empty() {
                return Ok(CloseProgress::Ready(
                    DemandMemberSelectionOutcome::Unavailable(input.completion.clone()),
                ));
            }
            assert_eq!(
                input.values.len(),
                1,
                "the real typed qualifier supplies a value"
            );
            assert_eq!(input.values[0].ty().identity(), self.expected_root);
            self.preparations += 1;
            self.reads.borrow_mut().clear();
            self.projects.set(0);
            self.phases.borrow_mut().clear();
            self.written.clear();
            self.input = Some(input.clone());
            self.slot = Some((id, QualifiedMemberSlot::new((), input.clone()).access));
            Ok(CloseProgress::Ready(DemandMemberSelectionOutcome::Ready {
                request: Some(self.request(input.reference.reference)),
                completion: ResolutionCompletion::Complete,
            }))
        }
        fn poll_qualified_member(
            &mut self,
            id: QualifiedMemberId,
            selection: &DemandMemberSelection,
            provenance: HierarchyProvenanceView<'_>,
            resume: CloseResume<'_>,
        ) -> Result<CloseProgress<Read<MemberAccessResult>>> {
            if matches!(resume, CloseResume::Start) {
                let order = selection
                    .order
                    .expect("C3 order produced by MemberSelectionFrame");
                assert!(provenance.order_status(order).complete);
                provenance.visit_order(order, &mut || false, &mut |entry| {
                    self.written.push(entry.owner);
                    Ok(())
                })?;
            }
            let (held, mut slot) = self.slot.take().unwrap();
            assert_eq!(id, held);
            let progress = slot.poll(
                id,
                selection,
                provenance,
                resume,
                &self.session,
                &self.cancellation,
                self,
                |owner| {
                    assert!(
                        !self.reads.borrow().contains(&owner),
                        "suspended rows are not reread"
                    );
                    self.reads.borrow_mut().push(owner);
                    self.observations
                        .borrow_mut()
                        .push(HierarchyProviderObservation {
                            provider: self.provider(owner),
                            visit: HierarchyProviderVisit::Observed,
                            completion: ResolutionCompletion::Complete,
                            inventory_complete: Some(true),
                        });
                    Ok(Read::ready(
                        self.rows
                            .iter()
                            .enumerate()
                            .filter_map(|(index, row)| (row.0 == owner).then_some(index))
                            .collect(),
                    ))
                },
                |index| {
                    self.projects.set(self.projects.get() + 1);
                    let (_, token, definition) = self.rows[*index];
                    let input = self.input.as_ref().unwrap();
                    Ok(Read::ready(Some(SelectedMemberRouteTarget {
                        target: SelectedMemberTarget {
                            fragment: input.fragment,
                            token,
                            definition,
                            lookup: ResolutionLookupSemanticRecipe::new(
                                input.registration.language,
                                input.namespace,
                                "m",
                            ),
                            completion: ResolutionCompletion::Complete,
                        },
                        location: RouteLocation::Owner {
                            definition: token,
                            scope: None,
                        },
                        namespace: input.namespace,
                        material: BridgeMaterial::same_language(input.registration.language),
                    })))
                },
                || {
                    Ok(Read::ready(std::mem::take(
                        &mut *self.observations.borrow_mut(),
                    )))
                },
            )?;
            self.slot = Some((id, slot));
            Ok(progress)
        }
        fn cancel_qualified_member(&mut self, id: QualifiedMemberId) {
            if let Some((held, _)) = self.slot.take() {
                assert_eq!(id, held);
            }
        }
    }
    impl MemberAccessRules<usize> for Provider {
        fn classify_row(
            &self,
            context: &MemberAccessContext<'_>,
            index: &usize,
            _: Option<&SelectedMemberRouteTarget>,
            input: AccessRowInput<'_>,
        ) -> Result<AccessRowPoll> {
            let replies = match input {
                AccessRowInput::Start => &[][..],
                AccessRowInput::Replies(replies) => replies,
            };
            if *index == 0 {
                let phase = replies.len();
                match phase {
                    0 => {
                        self.phases.borrow_mut().push("Members");
                        return Ok(AccessRowPoll::Members(self.request(context.reference)));
                    }
                    1 => {
                        self.phases.borrow_mut().push("Reference");
                        return Ok(AccessRowPoll::Reference(self.prerequisite));
                    }
                    2 => {
                        self.phases.borrow_mut().push("Members");
                        return Ok(AccessRowPoll::Members(
                            self.request(self.prerequisite.reference),
                        ));
                    }
                    3 => {
                        self.phases.borrow_mut().push("Ready");
                    }
                    _ => unreachable!(),
                }
            }
            let owner = self.rows[*index].0;
            let provider = self.provider(owner);
            Ok(AccessRowPoll::Ready(Read::ready(Box::new(AccessFacts {
                ordered_range: None,
                alternative: AccessAlternativeId(self.expected_root),
                group: AccessGroupId(0),
                within_group: Box::new([AccessKey::Owner {
                    order: context.selection.order.unwrap(),
                    root: self.expected_root,
                    owner,
                }]),
                between_groups: Box::new([AccessKey::Fixed(0)]),
                occurrence: provider.occurrence(),
                provider: provider.clone(),
                binding: MemberBinding::Unchanged,
                completion: replies.iter().fold(
                    ResolutionCompletion::Complete,
                    |completion, reply| match reply {
                        AccessPrerequisiteReply::Reference { answer, .. } => {
                            completion.combine(answer.completion())
                        }
                        AccessPrerequisiteReply::Members { .. } => completion,
                    },
                ),
                coverage: Box::new([provider]),
                witnesses: Box::new([]),
            }))))
        }
    }
}
