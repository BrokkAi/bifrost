//! Bounded reads over caller-supplied immutable lexical and typed fragments.
//! Construction is tokenless; individual source reads observe cancellation.
//! This source transports normalized facts and does not evaluate typed answers.

use super::batch::{
    BatchCandidateCompletionOutcome, BatchCandidateMatch, BatchCandidateOutcome,
    BatchCandidateRequest, BatchDefinitionNode, BatchEndpointClassification,
    BatchResolutionFragmentSource, CandidatePathIdentity, ReferenceSeed, ReferenceSeedBatch,
    ReferenceSeedReadOutcome, ReverseReferenceSeedRequest,
};
use super::coverage::{LoweringCoverageFrontier, LoweringGapOrigin};
use super::engine::{CANCELLATION_QUANTUM, PreloadedFragmentSource, ResolutionQuery};
use super::fact_lowering::{LoweredResolutionFragment, LoweredSemanticRole};
use super::fact_source::{
    MAX_TYPED_FACT_ROWS_PER_PAGE, QualifiedRouteSlotLookup, SelectedGapReasonProvenance,
    SelectedQualifiedRoute as SourceSelectedQualifiedRoute, SelectedTypeFrontierCompletion,
    SelectedTypedFactSource, SelectedTypedRow, TypedFactPageVisitor, TypedFactReadOutcome,
    TypedFactRequest,
};
use super::model::{
    BindingFragmentId, BindingNodeId, BindingNodeKind, PartialPath, ResolutionCompletion,
    ResolutionIncompleteReason, SemanticId, TypeTransferRule, TypedFrontierState,
    clone_completion_with_poll as clone_resolution_completion_with_poll,
};
use super::typed_fact_lowering::{
    LoweredBindingProjection, LoweredCallApplicabilityObligation, LoweredCallableSignatureProperty,
    LoweredConstructionRequirementProperty, LoweredDeclarationTypeProperty,
    LoweredDeclarationVisibilityProperty, LoweredDefinitionPropertyGap, LoweredIntrinsicSeed,
    LoweredMemberOwnerProperty, LoweredMemberScopeProperty, LoweredQualifiedSeededRoute,
    LoweredSupertypeProperty, LoweredTypeTransfer, LoweredTypedFragment, LoweredTypedFrontier,
    declaration_type_role_rank, member_kind_rank, member_qualifier_compatibility_rank,
    projection_kind_rank,
};
use crate::CancellationToken;
use crate::analyzer::store::Result as StoreResult;
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap};

#[derive(Debug, Default)]
struct ExactPolledCompletionAccumulator {
    state: ExactCompletionState,
}

#[derive(Debug, Default)]
enum ExactCompletionState {
    #[default]
    Complete,
    Single(Vec<ResolutionIncompleteReason>),
    Union(BTreeSet<ResolutionIncompleteReason>),
}

impl ExactPolledCompletionAccumulator {
    fn include(
        &mut self,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
        work: &mut usize,
        cancellation_observed: &mut bool,
    ) {
        let ResolutionCompletion::Incomplete(incoming) = completion else {
            *cancellation_observed |= cancellation.is_cancelled();
            return;
        };
        let state = std::mem::take(&mut self.state);
        self.state = match state {
            ExactCompletionState::Complete => {
                *cancellation_observed |= cancellation.is_cancelled();
                let mut reasons = Vec::with_capacity(incoming.len());
                for &reason in incoming.iter() {
                    observe_completion_reason(reason, cancellation, work, cancellation_observed);
                    reasons.push(reason);
                }
                ExactCompletionState::Single(reasons)
            }
            ExactCompletionState::Single(existing) => {
                assert!(
                    !existing.is_empty() || !incoming.is_empty(),
                    "incomplete resolution requires a reason"
                );
                let mut reasons = BTreeSet::new();
                for reason in existing {
                    observe_completion_reason(reason, cancellation, work, cancellation_observed);
                    reasons.insert(reason);
                }
                for &reason in incoming.iter() {
                    observe_completion_reason(reason, cancellation, work, cancellation_observed);
                    reasons.insert(reason);
                }
                ExactCompletionState::Union(reasons)
            }
            ExactCompletionState::Union(mut reasons) => {
                for &reason in incoming.iter() {
                    observe_completion_reason(reason, cancellation, work, cancellation_observed);
                    reasons.insert(reason);
                }
                ExactCompletionState::Union(reasons)
            }
        };
        *cancellation_observed |= cancellation.is_cancelled();
    }

    fn include_reason(
        &mut self,
        reason: ResolutionIncompleteReason,
        cancellation: &CancellationToken,
        work: &mut usize,
        cancellation_observed: &mut bool,
    ) {
        let state = std::mem::take(&mut self.state);
        self.state = match state {
            ExactCompletionState::Complete => {
                observe_completion_reason(reason, cancellation, work, cancellation_observed);
                ExactCompletionState::Single(vec![reason])
            }
            ExactCompletionState::Single(existing) => {
                let mut reasons = BTreeSet::new();
                for existing_reason in existing {
                    observe_completion_reason(
                        existing_reason,
                        cancellation,
                        work,
                        cancellation_observed,
                    );
                    reasons.insert(existing_reason);
                }
                observe_completion_reason(reason, cancellation, work, cancellation_observed);
                reasons.insert(reason);
                ExactCompletionState::Union(reasons)
            }
            ExactCompletionState::Union(mut reasons) => {
                observe_completion_reason(reason, cancellation, work, cancellation_observed);
                reasons.insert(reason);
                ExactCompletionState::Union(reasons)
            }
        };
        *cancellation_observed |= cancellation.is_cancelled();
    }

    fn finish_semantic(
        self,
        cancellation: &CancellationToken,
        work: &mut usize,
        cancellation_observed: &mut bool,
    ) -> ResolutionCompletion {
        *cancellation_observed |= cancellation.is_cancelled();
        let (has_incomplete_operand, reasons) = match self.state {
            ExactCompletionState::Complete => (false, Vec::new()),
            ExactCompletionState::Single(single) => {
                let mut reasons = Vec::with_capacity(single.len());
                for reason in single {
                    observe_completion_reason(reason, cancellation, work, cancellation_observed);
                    reasons.push(reason);
                }
                (true, reasons)
            }
            ExactCompletionState::Union(mut union) => {
                let mut reasons = Vec::with_capacity(union.len());
                while let Some(reason) = union.pop_first() {
                    observe_completion_reason(reason, cancellation, work, cancellation_observed);
                    reasons.push(reason);
                }
                assert!(
                    !reasons.is_empty(),
                    "incomplete resolution requires a reason"
                );
                (true, reasons)
            }
        };
        *cancellation_observed |= cancellation.is_cancelled();
        if has_incomplete_operand {
            ResolutionCompletion::Incomplete(reasons.into_boxed_slice().into())
        } else {
            ResolutionCompletion::Complete
        }
    }
}
fn observe_completion_reason(
    reason: ResolutionIncompleteReason,
    cancellation: &CancellationToken,
    work: &mut usize,
    cancellation_observed: &mut bool,
) {
    *cancellation_observed |= poll_cancelled(cancellation, work);
    *cancellation_observed |= reason == ResolutionIncompleteReason::Cancelled;
    *cancellation_observed |= cancellation.is_cancelled();
}

fn poll_cancelled(cancellation: &CancellationToken, work: &mut usize) -> bool {
    *work += 1;
    (*work).is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled()
}

/// Immutable normalized facts supplied by the caller for bounded lexical and typed reads.
/// Fragment membership is validated here; persisted selection authority is external.
pub struct PreloadedFactSource {
    source: PreloadedFragmentSource,
    typed: TypedSelection,
    selected_fragments: Box<[BindingFragmentId]>,
    reverse_inventory_completion: ResolutionCompletion,
}

impl PreloadedFactSource {
    /// Combine matching lexical and typed artifacts without losing coverage.
    ///
    /// A qualified reference's coarse lexical gap is omitted from preload
    /// coverage only when the typed artifact owns an exact seeded route with
    /// the same stable reason. The incomplete lexical dead-end path remains in
    /// the graph, so an unseeded lookup still cannot claim false completeness.
    pub fn from_lowered_fragments(
        lexical_fragments: impl IntoIterator<Item = LoweredResolutionFragment>,
        typed_fragments: impl IntoIterator<Item = LoweredTypedFragment>,
    ) -> Self {
        Self::from_selection_parts(
            lexical_fragments,
            typed_fragments,
            [],
            ResolutionCompletion::Complete,
        )
    }

    fn from_selection_parts(
        lexical_fragments: impl IntoIterator<Item = LoweredResolutionFragment>,
        typed_fragments: impl IntoIterator<Item = LoweredTypedFragment>,
        boundaries: impl IntoIterator<Item = BindingNodeId>,
        reverse_inventory_completion: ResolutionCompletion,
    ) -> Self {
        let typed_fragments = typed_fragments.into_iter().collect::<Vec<_>>();
        let lexical_fragments = lexical_fragments.into_iter().collect::<Vec<_>>();
        let mut lexical_node_owners = HashMap::default();
        for lexical in &lexical_fragments {
            for &(node, kind) in lexical.nodes() {
                assert!(
                    lexical_node_owners
                        .insert(node, (lexical.fragment(), kind))
                        .is_none(),
                    "selected lexical node {node} has multiple fragment owners"
                );
            }
        }
        for typed in &typed_fragments {
            for member_scope in typed.member_scopes() {
                assert_eq!(
                    lexical_node_owners.get(&member_scope.scope_head()),
                    Some(&(typed.fragment(), BindingNodeKind::Scope)),
                    "member scope for definition {} must name a Scope node in its exact selected fragment",
                    member_scope.definition()
                );
            }
        }
        let qualified_references = typed_fragments
            .iter()
            .flat_map(|fragment| {
                fragment
                    .qualified_routes()
                    .iter()
                    .map(LoweredQualifiedSeededRoute::reference)
            })
            .collect::<HashSet<_>>();
        let mut qualified_reference_nodes = HashMap::default();
        for lexical in &lexical_fragments {
            for site in lexical.semantics().iter().filter(|site| {
                site.role() == LoweredSemanticRole::Reference
                    && qualified_references.contains(&site.semantic())
            }) {
                assert!(
                    qualified_reference_nodes
                        .insert(site.semantic(), (lexical.fragment(), site.node()))
                        .is_none(),
                    "qualified reference semantic {} names multiple selected nodes",
                    site.semantic()
                );
            }
        }
        assert_eq!(
            qualified_reference_nodes.len(),
            qualified_references.len(),
            "every selected qualified route must name one lexical reference node"
        );
        let (typed, member_scope_owners) = TypedSelection::new(
            &typed_fragments,
            &lexical_fragments,
            &qualified_reference_nodes,
        );

        let mut selected_fragments = HashSet::default();
        let mut preloaded = Vec::new();
        for lexical in lexical_fragments {
            let fragment = lexical.fragment();
            assert!(
                selected_fragments.insert(fragment),
                "duplicate lowered lexical fragment {fragment}"
            );
            let references_by_site = lexical
                .semantics()
                .iter()
                .filter(|site| site.role() == LoweredSemanticRole::Reference)
                .map(|site| (site.site(), site.semantic()))
                .collect::<HashMap<_, _>>();
            let (preloaded_fragment, gaps) = lexical.into_preloaded_parts();
            let retained_gaps = gaps.into_vec().into_iter().filter(|gap| {
                if gap.origin() != LoweringGapOrigin::QualifiedReference {
                    true
                } else {
                    let reference = *references_by_site.get(&gap.site()).unwrap_or_else(|| {
                        panic!(
                            "qualified gap at site {} has no selected reference semantic",
                            gap.site()
                        )
                    });
                    !typed.owns_qualified_gap(fragment, reference, gap.reason_semantic())
                }
            });
            let owners = member_scope_owners.iter().filter_map(|(&head, &owner)| {
                (lexical_node_owners[&head].0 == fragment).then_some((head, owner))
            });
            preloaded.push(
                preloaded_fragment
                    .with_coverage(retained_gaps)
                    .with_member_scope_owners(owners),
            );
        }

        assert_eq!(
            selected_fragments, typed.fragments,
            "lexical and typed preload selections must name the same fragments"
        );
        let mut selected_fragments = selected_fragments.into_iter().collect::<Vec<_>>();
        selected_fragments.sort_unstable();
        let transfer_rules = typed_fragments.iter().flat_map(|fragment| {
            fragment
                .transfers()
                .iter()
                .map(|transfer| (transfer.source_slot(), transfer.rule().clone()))
        });
        let mut boundaries = boundaries.into_iter().collect::<BTreeSet<_>>();
        boundaries.insert(BindingNodeId::universal_root());
        let source = PreloadedFragmentSource::from_fragments_with_boundaries(
            boundaries.iter().copied(),
            preloaded,
        )
        .with_type_transfer_rules(transfer_rules);
        assert!(
            !reverse_inventory_completion.contains_reason(ResolutionIncompleteReason::Cancelled),
            "selected reverse inventory cannot persist operation cancellation"
        );
        Self {
            source,
            typed,
            selected_fragments: selected_fragments.into_boxed_slice(),
            reverse_inventory_completion,
        }
    }
}

enum PreloadedTypedStreamControl {
    Continue,
    Stopped,
    Cancelled,
}

/// Exact semantic evidence observed while streaming selected preload rows.
///
/// The first public incomplete box is retained byte-for-byte. Once a second
/// incomplete operand is observed, evidence is canonicalized incrementally.
#[derive(Debug, Default)]
struct PreloadedTypedEvidenceLedger {
    completion: ExactPolledCompletionAccumulator,
    cancellation_observed: bool,
}

impl PreloadedTypedEvidenceLedger {
    fn include(
        &mut self,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> bool {
        self.completion.include(
            completion,
            cancellation,
            work,
            &mut self.cancellation_observed,
        );
        self.cancellation_observed
    }

    fn include_reason(
        &mut self,
        reason: ResolutionIncompleteReason,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> bool {
        self.completion
            .include_reason(reason, cancellation, work, &mut self.cancellation_observed);
        self.cancellation_observed
    }

    fn finish_semantic(
        self,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> (ResolutionCompletion, bool) {
        let mut cancellation_observed = self.cancellation_observed;
        let completion =
            self.completion
                .finish_semantic(cancellation, work, &mut cancellation_observed);
        (completion, cancellation_observed)
    }
}

fn walk_preloaded_typed_streams<R, K>(
    streams: &[&[R]],
    natural_identity: &impl Fn(&R) -> K,
    cancellation: &CancellationToken,
    work: &mut usize,
    mut visitor: impl FnMut(&R, &mut usize) -> StoreResult<PreloadedTypedStreamControl>,
) -> StoreResult<PreloadedTypedStreamControl>
where
    K: Copy + Ord,
{
    if cancellation.is_cancelled() {
        return Ok(PreloadedTypedStreamControl::Cancelled);
    }
    let mut positions = vec![0_usize; streams.len()];
    let mut pending = BinaryHeap::new();
    for (stream, rows) in streams.iter().enumerate() {
        *work = work
            .checked_add(1)
            .expect("preloaded typed stream work must fit usize");
        if work.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
            return Ok(PreloadedTypedStreamControl::Cancelled);
        }
        if let Some(row) = rows.first() {
            pending.push(Reverse((natural_identity(row), stream)));
        }
    }
    let mut previous = None;
    while let Some(Reverse((identity, stream))) = pending.pop() {
        *work = work
            .checked_add(1)
            .expect("preloaded typed stream work must fit usize");
        if work.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
            return Ok(PreloadedTypedStreamControl::Cancelled);
        }
        let position = positions[stream];
        let row = &streams[stream][position];
        debug_assert!(natural_identity(row) == identity);
        positions[stream] = position
            .checked_add(1)
            .expect("preloaded typed stream position must fit usize");
        if let Some(next) = streams[stream].get(positions[stream]) {
            pending.push(Reverse((natural_identity(next), stream)));
        }
        if previous == Some(identity) {
            continue;
        }
        debug_assert!(previous.is_none_or(|prior| prior < identity));
        previous = Some(identity);
        match visitor(row, work)? {
            PreloadedTypedStreamControl::Continue => {}
            terminal => return Ok(terminal),
        }
        if cancellation.is_cancelled() {
            return Ok(PreloadedTypedStreamControl::Cancelled);
        }
    }
    Ok(PreloadedTypedStreamControl::Continue)
}

fn visit_preloaded_typed_pages<R, T, K>(
    streams: &[&[R]],
    natural_identity: impl Fn(&R) -> K,
    mut include_evidence: impl FnMut(
        &R,
        &mut PreloadedTypedEvidenceLedger,
        &CancellationToken,
        &mut usize,
    ) -> bool,
    mut clone_row: impl FnMut(&R, &mut dyn FnMut() -> bool) -> Option<T>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, T>,
) -> StoreResult<TypedFactReadOutcome>
where
    K: Copy + Ord,
{
    let mut work = 0_usize;
    let mut evidence = PreloadedTypedEvidenceLedger::default();
    let maximum_rows = visitor.maximum_rows();
    let mut page = Vec::with_capacity(maximum_rows);
    let emission_terminal = walk_preloaded_typed_streams(
        streams,
        &natural_identity,
        cancellation,
        &mut work,
        |row, callback_work| {
            if include_evidence(row, &mut evidence, cancellation, callback_work) {
                return Ok(PreloadedTypedStreamControl::Cancelled);
            }
            let mut entry_poll = true;
            let mut cancelled = || {
                *callback_work = callback_work
                    .checked_add(1)
                    .expect("preloaded typed clone work must fit usize");
                let poll = entry_poll || callback_work.is_multiple_of(CANCELLATION_QUANTUM);
                entry_poll = false;
                poll && cancellation.is_cancelled()
            };
            let Some(row) = clone_row(row, &mut cancelled) else {
                return Ok(PreloadedTypedStreamControl::Cancelled);
            };
            if cancellation.is_cancelled() {
                return Ok(PreloadedTypedStreamControl::Cancelled);
            }
            page.push(row);
            if page.len() < maximum_rows {
                return Ok(PreloadedTypedStreamControl::Continue);
            }
            let keep_going = visitor.visit_page(&page)?;
            page.clear();
            Ok(if cancellation.is_cancelled() {
                PreloadedTypedStreamControl::Cancelled
            } else if keep_going {
                PreloadedTypedStreamControl::Continue
            } else {
                PreloadedTypedStreamControl::Stopped
            })
        },
    )?;
    match emission_terminal {
        PreloadedTypedStreamControl::Cancelled => {
            let (evidence, _) = evidence.finish_semantic(cancellation, &mut work);
            return Ok(TypedFactReadOutcome::cancelled(evidence));
        }
        PreloadedTypedStreamControl::Stopped => {
            let (evidence, cancelled) = evidence.finish_semantic(cancellation, &mut work);
            return Ok(if cancelled || cancellation.is_cancelled() {
                TypedFactReadOutcome::cancelled(evidence)
            } else {
                TypedFactReadOutcome::stopped(evidence)
            });
        }
        PreloadedTypedStreamControl::Continue => {}
    }
    if cancellation.is_cancelled() {
        let (evidence, _) = evidence.finish_semantic(cancellation, &mut work);
        return Ok(TypedFactReadOutcome::cancelled(evidence));
    }
    if !page.is_empty() {
        let keep_going = visitor.visit_page(&page)?;
        if cancellation.is_cancelled() {
            let (evidence, _) = evidence.finish_semantic(cancellation, &mut work);
            return Ok(TypedFactReadOutcome::cancelled(evidence));
        }
        if !keep_going {
            let (evidence, cancelled) = evidence.finish_semantic(cancellation, &mut work);
            return Ok(if cancelled || cancellation.is_cancelled() {
                TypedFactReadOutcome::cancelled(evidence)
            } else {
                TypedFactReadOutcome::stopped(evidence)
            });
        }
    }
    Ok(TypedFactReadOutcome::exhausted(
        ResolutionCompletion::Complete,
    ))
}

fn clone_type_transfer_with_poll(
    row: &LoweredTypeTransfer,
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<LoweredTypeTransfer> {
    let rule = row.rule();
    let completion = {
        let mut poll = || cancelled();
        clone_resolution_completion_with_poll(rule.completion(), &mut poll)?
    };
    Some(LoweredTypeTransfer::new(
        row.source_slot(),
        row.kind(),
        TypeTransferRule::new(
            rule.semantic(),
            rule.target_slot(),
            rule.indirection_delta(),
            rule.value_transform(),
            completion,
        ),
    ))
}

fn clone_intrinsic_seed_with_poll(
    row: &LoweredIntrinsicSeed,
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<LoweredIntrinsicSeed> {
    let frontier = row.frontier();
    if cancelled() {
        return None;
    }
    let mut values = Vec::with_capacity(frontier.possible_values().len());
    for &value in frontier.possible_values() {
        if cancelled() {
            return None;
        }
        values.push(value);
    }
    let completion = {
        let mut poll = || cancelled();
        clone_resolution_completion_with_poll(frontier.completion(), &mut poll)?
    };
    Some(LoweredIntrinsicSeed::new(
        row.kind(),
        TypedFrontierState::from_canonical_parts(
            frontier.slot(),
            values.into_boxed_slice(),
            completion,
            cancelled,
        )?,
    ))
}

fn clone_call_obligation_with_poll(
    row: &LoweredCallApplicabilityObligation,
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<LoweredCallApplicabilityObligation> {
    if cancelled() {
        return None;
    }
    let mut arguments = Vec::with_capacity(row.argument_slots().len());
    for &argument in row.argument_slots() {
        if cancelled() {
            return None;
        }
        arguments.push(argument);
    }
    let mut eligible_rules = Vec::with_capacity(row.eligible_rules().len());
    for &rule in row.eligible_rules() {
        if cancelled() {
            return None;
        }
        eligible_rules.push(rule);
    }
    let completion = {
        let mut poll = || cancelled();
        clone_resolution_completion_with_poll(row.completion(), &mut poll)?
    };
    Some(LoweredCallApplicabilityObligation::new(
        row.call(),
        row.callee_reference(),
        row.receiver_slot(),
        row.result_slot(),
        arguments,
        eligible_rules,
        row.explicit_type_argument_count(),
        row.applicability_reason(),
        completion,
    ))
}

fn no_preloaded_typed_evidence<R>(
    _row: &R,
    _evidence: &mut PreloadedTypedEvidenceLedger,
    _cancellation: &CancellationToken,
    _work: &mut usize,
) -> bool {
    false
}

fn visit_preloaded_qualified_route_pages(
    service: &PreloadedFactSource,
    streams: &[&[usize]],
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SourceSelectedQualifiedRoute>,
) -> StoreResult<TypedFactReadOutcome> {
    visit_preloaded_typed_pages(
        streams,
        |route_id| {
            service
                .typed
                .selected_source_route(*route_id)
                .natural_identity()
        },
        |route_id, evidence, token, work| {
            evidence.include_reason(
                ResolutionIncompleteReason::UnsupportedSemantic(
                    service.typed.qualified_routes[*route_id]
                        .row
                        .coarse_gap_reason(),
                ),
                token,
                work,
            )
        },
        |route_id, _| Some(service.typed.selected_source_route(*route_id)),
        cancellation,
        visitor,
    )
}

fn preloaded_reverse_prefix_evidence(
    reasons: Vec<ResolutionIncompleteReason>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> ResolutionCompletion {
    if reasons.is_empty() {
        return ResolutionCompletion::Complete;
    }
    let mut exact = Vec::with_capacity(reasons.len());
    for reason in reasons {
        *work = work
            .checked_add(1)
            .expect("reverse inventory prefix rebox work must fit usize");
        if work.is_multiple_of(CANCELLATION_QUANTUM) {
            let _ = cancellation.is_cancelled();
        }
        exact.push(reason);
    }
    ResolutionCompletion::Incomplete(exact.into_boxed_slice().into())
}

impl BatchResolutionFragmentSource for PreloadedFactSource {
    fn reference_seed(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ReferenceSeed>> {
        BatchResolutionFragmentSource::reference_seed(&self.source, query, cancellation)
    }

    fn lookup_reference_seeds(
        &self,
        queries: &[ResolutionQuery],
        cancellation: &CancellationToken,
    ) -> StoreResult<ReferenceSeedReadOutcome> {
        BatchResolutionFragmentSource::lookup_reference_seeds(&self.source, queries, cancellation)
    }

    fn lookup_definition_node(
        &self,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<BindingNodeId>> {
        BatchResolutionFragmentSource::lookup_definition_node(
            &self.source,
            definition,
            cancellation,
        )
    }

    fn lookup_definition_nodes(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<BatchDefinitionNode>> {
        BatchResolutionFragmentSource::lookup_definition_nodes(
            &self.source,
            definitions,
            cancellation,
        )
    }

    fn issue_reverse_reference_seeds(
        &self,
        requests: &[ReverseReferenceSeedRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<ReferenceSeed>> {
        BatchResolutionFragmentSource::issue_reverse_reference_seeds(
            &self.source,
            requests,
            cancellation,
        )
    }

    fn visit_reference_seed_batches(
        &self,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        BatchResolutionFragmentSource::visit_reference_seed_batches(
            &self.source,
            maximum_batch_size,
            cancellation,
            visitor,
        )
    }

    fn classify_endpoint_nodes(
        &self,
        nodes: &[BindingNodeId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<BatchEndpointClassification>> {
        BatchResolutionFragmentSource::classify_endpoint_nodes(&self.source, nodes, cancellation)
    }

    fn match_forward_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<BatchCandidateOutcome> {
        BatchResolutionFragmentSource::match_forward_candidates(
            &self.source,
            requests,
            cancellation,
        )
    }

    fn visit_forward_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        BatchResolutionFragmentSource::visit_forward_candidate_match_pages(
            &self.source,
            requests,
            cancellation,
            visitor,
        )
    }

    fn visit_forward_candidate_match_pages_limited(
        &self,
        requests: &[BatchCandidateRequest],
        maximum_page_rows: usize,
        resolution_session: Option<&ResolutionSession>,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        BatchResolutionFragmentSource::visit_forward_candidate_match_pages_limited(
            &self.source,
            requests,
            maximum_page_rows,
            resolution_session,
            cancellation,
            visitor,
        )
    }

    fn match_reverse_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<BatchCandidateOutcome> {
        BatchResolutionFragmentSource::match_reverse_candidates(
            &self.source,
            requests,
            cancellation,
        )
    }

    fn visit_reverse_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        BatchResolutionFragmentSource::visit_reverse_candidate_match_pages(
            &self.source,
            requests,
            cancellation,
            visitor,
        )
    }

    fn hydrate_candidate_paths(
        &self,
        candidates: &[CandidatePathIdentity],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<(CandidatePathIdentity, PartialPath)>> {
        BatchResolutionFragmentSource::hydrate_candidate_paths(
            &self.source,
            candidates,
            cancellation,
        )
    }

    fn visit_type_transfer_rules(
        &self,
        source_slot: SemanticId,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&TypeTransferRule) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        BatchResolutionFragmentSource::visit_type_transfer_rules(
            &self.source,
            source_slot,
            cancellation,
            visitor,
        )
    }
}

impl SelectedTypedFactSource for PreloadedFactSource {
    fn visit_selected_fragment_pages(
        &self,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, BindingFragmentId>,
    ) -> StoreResult<TypedFactReadOutcome> {
        if cancellation.is_cancelled() {
            return Ok(TypedFactReadOutcome::cancelled(
                ResolutionCompletion::Complete,
            ));
        }
        for chunk in self.selected_fragments.chunks(MAX_TYPED_FACT_ROWS_PER_PAGE) {
            let mut page = Vec::with_capacity(chunk.len());
            for &fragment in chunk {
                if cancellation.is_cancelled() {
                    return Ok(TypedFactReadOutcome::cancelled(
                        ResolutionCompletion::Complete,
                    ));
                }
                page.push(fragment);
            }
            let keep_going = visitor.visit_page(&page)?;
            if cancellation.is_cancelled() {
                return Ok(TypedFactReadOutcome::cancelled(
                    ResolutionCompletion::Complete,
                ));
            }
            if !keep_going {
                return Ok(TypedFactReadOutcome::stopped(
                    ResolutionCompletion::Complete,
                ));
            }
        }
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
        } else {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        })
    }

    fn read_selected_reverse_inventory_completion(
        &self,
        cancellation: &CancellationToken,
    ) -> StoreResult<TypedFactReadOutcome> {
        if cancellation.is_cancelled() {
            return Ok(TypedFactReadOutcome::cancelled(
                ResolutionCompletion::Complete,
            ));
        }
        let mut work = 0_usize;
        let mut reasons = Vec::new();
        if let ResolutionCompletion::Incomplete(selected) = &self.reverse_inventory_completion {
            reasons = Vec::with_capacity(selected.len());
            for &reason in selected.iter() {
                work = work
                    .checked_add(1)
                    .expect("reverse inventory completion work must fit usize");
                if work.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
                    let evidence =
                        preloaded_reverse_prefix_evidence(reasons, cancellation, &mut work);
                    return Ok(TypedFactReadOutcome::cancelled(evidence));
                }
                reasons.push(reason);
            }
        }
        let evidence = if reasons.is_empty() {
            self.reverse_inventory_completion.clone()
        } else {
            ResolutionCompletion::Incomplete(reasons.into_boxed_slice().into())
        };
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(evidence)
        } else {
            TypedFactReadOutcome::exhausted(evidence)
        })
    }

    fn visit_typed_frontier_pages(
        &self,
        slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypedFrontier>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let mut rows = slots
            .as_slice()
            .iter()
            .filter_map(|slot| self.typed.frontiers_by_slot.get(slot))
            .collect::<Vec<_>>();
        rows.sort_unstable_by_key(|row| (self.typed.source_fragment(row.slot()), row.slot()));
        let streams = [rows.as_slice()];
        visit_preloaded_typed_pages(
            &streams,
            |row| (self.typed.source_fragment(row.slot()), row.slot()),
            no_preloaded_typed_evidence,
            |row, _| Some(self.typed.selected_source_row(row.slot(), **row)),
            cancellation,
            visitor,
        )
    }

    fn visit_type_frontier_completion_pages(
        &self,
        frontiers: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypeFrontierCompletion>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let mut rows = frontiers
            .as_slice()
            .iter()
            .filter_map(|frontier| self.typed.frontier_completion_by_frontier.get(frontier))
            .collect::<Vec<_>>();
        rows.sort_unstable_by_key(|row| row.natural_identity());
        let streams = [rows.as_slice()];
        visit_preloaded_typed_pages(
            &streams,
            |row| row.natural_identity(),
            |row, evidence, token, work| evidence.include(row.completion(), token, work),
            |row, cancelled| {
                let completion = {
                    let mut poll = || cancelled();
                    clone_resolution_completion_with_poll(row.completion(), &mut poll)?
                };
                Some(SelectedTypeFrontierCompletion::new(
                    row.fragment(),
                    row.frontier(),
                    completion,
                ))
            },
            cancellation,
            visitor,
        )
    }

    fn visit_type_transfer_pages_from_sources(
        &self,
        source_slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeTransfer>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = source_slots
            .as_slice()
            .iter()
            .filter_map(|source| {
                self.typed
                    .transfers_by_source
                    .get(source)
                    .map(Vec::as_slice)
            })
            .collect::<Vec<_>>();
        visit_preloaded_typed_pages(
            &streams,
            |row| {
                (
                    self.typed.source_fragment(row.rule().semantic()),
                    row.source_slot(),
                    row.rule().semantic(),
                )
            },
            |row, evidence, token, work| evidence.include(row.rule().completion(), token, work),
            |row, cancelled| {
                Some(self.typed.selected_source_row(
                    row.rule().semantic(),
                    clone_type_transfer_with_poll(row, cancelled)?,
                ))
            },
            cancellation,
            visitor,
        )
    }

    fn visit_type_transfer_pages_to_targets(
        &self,
        target_slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeTransfer>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = target_slots
            .as_slice()
            .iter()
            .filter_map(|target| {
                self.typed
                    .transfers_by_target
                    .get(target)
                    .map(Vec::as_slice)
            })
            .collect::<Vec<_>>();
        visit_preloaded_typed_pages(
            &streams,
            |row| {
                (
                    self.typed.source_fragment(row.rule().semantic()),
                    row.rule().target_slot(),
                    row.rule().semantic(),
                )
            },
            |row, evidence, token, work| evidence.include(row.rule().completion(), token, work),
            |row, cancelled| {
                Some(self.typed.selected_source_row(
                    row.rule().semantic(),
                    clone_type_transfer_with_poll(row, cancelled)?,
                ))
            },
            cancellation,
            visitor,
        )
    }

    fn visit_intrinsic_seed_pages_for_slots(
        &self,
        slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredIntrinsicSeed>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let mut rows = slots
            .as_slice()
            .iter()
            .filter_map(|slot| self.typed.intrinsic_seed_by_slot.get(slot))
            .collect::<Vec<_>>();
        rows.sort_unstable_by_key(|row| {
            (
                self.typed.source_fragment(row.frontier().slot()),
                row.frontier().slot(),
            )
        });
        let streams = [rows.as_slice()];
        visit_preloaded_typed_pages(
            &streams,
            |row| {
                (
                    self.typed.source_fragment(row.frontier().slot()),
                    row.frontier().slot(),
                )
            },
            |row, evidence, token, work| evidence.include(row.frontier().completion(), token, work),
            |row, cancelled| {
                Some(self.typed.selected_source_row(
                    row.frontier().slot(),
                    clone_intrinsic_seed_with_poll(row, cancelled)?,
                ))
            },
            cancellation,
            visitor,
        )
    }

    fn visit_intrinsic_seed_pages_for_type_identities(
        &self,
        type_identities: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredIntrinsicSeed>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = type_identities
            .as_slice()
            .iter()
            .filter_map(|identity| {
                self.typed
                    .intrinsic_slots_by_identity
                    .get(identity)
                    .map(Vec::as_slice)
            })
            .collect::<Vec<_>>();
        visit_preloaded_typed_pages(
            &streams,
            |slot| (self.typed.source_fragment(*slot), *slot),
            |slot, evidence, token, work| {
                evidence.include(
                    self.typed.intrinsic_seed_by_slot[slot]
                        .frontier()
                        .completion(),
                    token,
                    work,
                )
            },
            |slot, cancelled| {
                let row = &self.typed.intrinsic_seed_by_slot[slot];
                Some(
                    self.typed.selected_source_row(
                        *slot,
                        clone_intrinsic_seed_with_poll(row, cancelled)?,
                    ),
                )
            },
            cancellation,
            visitor,
        )
    }

    fn visit_binding_projection_pages_for_references(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredBindingProjection>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = references
            .as_slice()
            .iter()
            .filter_map(|reference| {
                self.typed
                    .projections_by_reference
                    .get(reference)
                    .map(Vec::as_slice)
            })
            .collect::<Vec<_>>();
        visit_preloaded_typed_pages(
            &streams,
            |row| (self.typed.source_fragment(row.reference()), row.reference()),
            no_preloaded_typed_evidence,
            |row, _| Some(self.typed.selected_source_row(row.reference(), *row)),
            cancellation,
            visitor,
        )
    }

    fn visit_binding_projection_pages_for_outputs(
        &self,
        output_slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredBindingProjection>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let mut rows = output_slots
            .as_slice()
            .iter()
            .filter_map(|slot| self.typed.projection_by_output.get(slot))
            .collect::<Vec<_>>();
        rows.sort_unstable_by_key(|row| {
            (self.typed.source_fragment(row.reference()), row.reference())
        });
        let streams = [rows.as_slice()];
        visit_preloaded_typed_pages(
            &streams,
            |row| (self.typed.source_fragment(row.reference()), row.reference()),
            no_preloaded_typed_evidence,
            |row, _| Some(self.typed.selected_source_row(row.reference(), **row)),
            cancellation,
            visitor,
        )
    }

    fn visit_qualified_route_pages_for_references(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SourceSelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = references
            .as_slice()
            .iter()
            .filter_map(|reference| {
                self.typed
                    .qualified_route_ids_by_reference
                    .get(reference)
                    .map(Vec::as_slice)
            })
            .collect::<Vec<_>>();
        visit_preloaded_qualified_route_pages(self, &streams, cancellation, visitor)
    }

    fn visit_qualified_route_pages_for_slot_lookups(
        &self,
        requests: TypedFactRequest<'_, QualifiedRouteSlotLookup>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SourceSelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = requests
            .as_slice()
            .iter()
            .filter_map(|request| {
                self.typed
                    .qualified_route_ids_by_slot_lookup
                    .get(&(request.qualifier_slot(), request.lookup()))
                    .map(Vec::as_slice)
            })
            .collect::<Vec<_>>();
        visit_preloaded_qualified_route_pages(self, &streams, cancellation, visitor)
    }

    fn visit_qualified_route_pages_for_qualifier_slots(
        &self,
        qualifier_slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SourceSelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = qualifier_slots
            .as_slice()
            .iter()
            .filter_map(|slot| {
                self.typed
                    .qualified_route_ids_by_qualifier_slot
                    .get(slot)
                    .map(Vec::as_slice)
            })
            .collect::<Vec<_>>();
        visit_preloaded_qualified_route_pages(self, &streams, cancellation, visitor)
    }

    fn visit_qualified_route_pages_for_lookups(
        &self,
        lookups: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SourceSelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = lookups
            .as_slice()
            .iter()
            .filter_map(|lookup| {
                self.typed
                    .qualified_route_ids_by_completion_lookup
                    .get(lookup)
                    .map(Vec::as_slice)
            })
            .collect::<Vec<_>>();
        visit_preloaded_qualified_route_pages(self, &streams, cancellation, visitor)
    }

    fn visit_qualified_route_pages_for_gap_reasons(
        &self,
        reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SourceSelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = reasons
            .as_slice()
            .iter()
            .filter_map(|reason| {
                self.typed
                    .qualified_gap_owner_by_reason
                    .get(reason)
                    .and_then(|(fragment, reference)| {
                        self.typed
                            .qualified_route_ids_by_gap_owner
                            .get(&(*fragment, *reference, *reason))
                            .map(Vec::as_slice)
                    })
            })
            .collect::<Vec<_>>();
        visit_preloaded_qualified_route_pages(self, &streams, cancellation, visitor)
    }

    fn visit_qualified_route_inventory_pages(
        &self,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SourceSelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = [self.typed.qualified_route_inventory.as_slice()];
        visit_preloaded_qualified_route_pages(self, &streams, cancellation, visitor)
    }

    fn visit_declaration_type_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeclarationTypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = definitions
            .as_slice()
            .iter()
            .filter_map(|definition| {
                self.typed
                    .declaration_types_by_definition
                    .get(definition)
                    .map(Vec::as_slice)
            })
            .collect::<Vec<_>>();
        visit_preloaded_typed_pages(
            &streams,
            |row| {
                self.typed
                    .selected_source_row(row.definition(), *row)
                    .natural_identity()
            },
            no_preloaded_typed_evidence,
            |row, _| Some(self.typed.selected_source_row(row.definition(), *row)),
            cancellation,
            visitor,
        )
    }

    fn visit_declaration_type_pages_for_slots(
        &self,
        slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeclarationTypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = slots
            .as_slice()
            .iter()
            .filter_map(|slot| {
                self.typed
                    .declaration_types_by_slot
                    .get(slot)
                    .map(Vec::as_slice)
            })
            .collect::<Vec<_>>();
        visit_preloaded_typed_pages(
            &streams,
            |row| {
                self.typed
                    .selected_source_row(row.definition(), *row)
                    .natural_identity()
            },
            no_preloaded_typed_evidence,
            |row, _| Some(self.typed.selected_source_row(row.definition(), *row)),
            cancellation,
            visitor,
        )
    }

    fn visit_declaration_visibility_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<
            '_,
            SelectedTypedRow<LoweredDeclarationVisibilityProperty>,
        >,
    ) -> StoreResult<TypedFactReadOutcome> {
        let mut rows = definitions
            .as_slice()
            .iter()
            .filter_map(|definition| {
                self.typed
                    .declaration_visibility_by_definition
                    .get(definition)
            })
            .collect::<Vec<_>>();
        rows.sort_unstable_by_key(|row| {
            (
                self.typed.source_fragment(row.definition()),
                row.definition(),
            )
        });
        let streams = [rows.as_slice()];
        visit_preloaded_typed_pages(
            &streams,
            |row| {
                (
                    self.typed.source_fragment(row.definition()),
                    row.definition(),
                )
            },
            no_preloaded_typed_evidence,
            |row, _| Some(self.typed.selected_source_row(row.definition(), **row)),
            cancellation,
            visitor,
        )
    }

    fn visit_member_scope_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberScopeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let mut rows = definitions
            .as_slice()
            .iter()
            .copied()
            .filter(|definition| {
                self.typed
                    .member_scope_by_definition
                    .contains_key(definition)
            })
            .collect::<Vec<_>>();
        rows.sort_unstable_by_key(|definition| {
            (self.typed.source_fragment(*definition), *definition)
        });
        let streams = [rows.as_slice()];
        visit_preloaded_typed_pages(
            &streams,
            |definition| (self.typed.source_fragment(*definition), *definition),
            no_preloaded_typed_evidence,
            |definition, _| {
                let definition = *definition;
                Some(self.typed.selected_source_row(
                    definition,
                    LoweredMemberScopeProperty::new(
                        definition,
                        self.typed.member_scope_by_definition[&definition],
                    ),
                ))
            },
            cancellation,
            visitor,
        )
    }

    fn visit_member_scope_pages_for_heads(
        &self,
        heads: TypedFactRequest<'_, BindingNodeId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberScopeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let mut rows = heads
            .as_slice()
            .iter()
            .filter_map(|head| {
                self.typed
                    .member_scope_definition_by_head
                    .get(head)
                    .copied()
                    .map(|definition| LoweredMemberScopeProperty::new(definition, *head))
            })
            .collect::<Vec<_>>();
        rows.sort_unstable_by_key(|row| {
            (
                self.typed.source_fragment(row.definition()),
                row.definition(),
            )
        });
        let streams = [rows.as_slice()];
        visit_preloaded_typed_pages(
            &streams,
            |row| {
                (
                    self.typed.source_fragment(row.definition()),
                    row.definition(),
                )
            },
            no_preloaded_typed_evidence,
            |row, _| Some(self.typed.selected_source_row(row.definition(), *row)),
            cancellation,
            visitor,
        )
    }

    fn visit_member_scope_inventory_pages(
        &self,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberScopeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = [self.typed.member_scope_inventory.as_slice()];
        visit_preloaded_typed_pages(
            &streams,
            |definition| (self.typed.source_fragment(*definition), *definition),
            no_preloaded_typed_evidence,
            |definition, _| {
                let definition = *definition;
                Some(self.typed.selected_source_row(
                    definition,
                    LoweredMemberScopeProperty::new(
                        definition,
                        self.typed.member_scope_by_definition[&definition],
                    ),
                ))
            },
            cancellation,
            visitor,
        )
    }

    fn visit_member_owner_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberOwnerProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = definitions
            .as_slice()
            .iter()
            .filter_map(|definition| {
                self.typed
                    .member_owners_by_definition
                    .get(definition)
                    .map(Vec::as_slice)
            })
            .collect::<Vec<_>>();
        visit_preloaded_typed_pages(
            &streams,
            |row| {
                self.typed
                    .selected_source_row(row.definition(), *row)
                    .natural_identity()
            },
            no_preloaded_typed_evidence,
            |row, _| Some(self.typed.selected_source_row(row.definition(), *row)),
            cancellation,
            visitor,
        )
    }

    fn visit_member_owner_pages_for_owners(
        &self,
        owner_definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberOwnerProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = owner_definitions
            .as_slice()
            .iter()
            .filter_map(|owner| {
                self.typed
                    .member_definitions_by_owner
                    .get(owner)
                    .map(Vec::as_slice)
            })
            .collect::<Vec<_>>();
        visit_preloaded_typed_pages(
            &streams,
            |row| {
                self.typed
                    .selected_source_row(row.definition(), *row)
                    .natural_identity()
            },
            no_preloaded_typed_evidence,
            |row, _| Some(self.typed.selected_source_row(row.definition(), *row)),
            cancellation,
            visitor,
        )
    }

    fn visit_construction_requirement_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<
            '_,
            SelectedTypedRow<LoweredConstructionRequirementProperty>,
        >,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = definitions
            .as_slice()
            .iter()
            .filter_map(|definition| {
                self.typed
                    .construction_requirements_by_definition
                    .get(definition)
                    .map(Vec::as_slice)
            })
            .collect::<Vec<_>>();
        visit_preloaded_typed_pages(
            &streams,
            |row| {
                self.typed
                    .selected_source_row(row.definition(), *row)
                    .natural_identity()
            },
            no_preloaded_typed_evidence,
            |row, _| Some(self.typed.selected_source_row(row.definition(), *row)),
            cancellation,
            visitor,
        )
    }

    fn visit_supertype_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = definitions
            .as_slice()
            .iter()
            .filter_map(|definition| {
                self.typed
                    .supertypes_by_definition
                    .get(definition)
                    .map(Vec::as_slice)
            })
            .collect::<Vec<_>>();
        let outcome = visit_preloaded_typed_pages(
            &streams,
            |row| {
                self.typed
                    .selected_source_row(row.reference(), *row)
                    .natural_identity()
            },
            no_preloaded_typed_evidence,
            |row, _| Some(self.typed.selected_source_row(row.reference(), *row)),
            cancellation,
            visitor,
        )?;
        Ok(outcome)
    }

    fn visit_supertype_pages_for_references(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = references
            .as_slice()
            .iter()
            .filter_map(|reference| {
                self.typed
                    .supertypes_by_reference
                    .get(reference)
                    .map(Vec::as_slice)
            })
            .collect::<Vec<_>>();
        visit_preloaded_typed_pages(
            &streams,
            |row| {
                self.typed
                    .selected_source_row(row.reference(), *row)
                    .natural_identity()
            },
            no_preloaded_typed_evidence,
            |row, _| Some(self.typed.selected_source_row(row.reference(), *row)),
            cancellation,
            visitor,
        )
    }

    fn visit_supertype_pages_for_frontiers(
        &self,
        frontiers: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = frontiers
            .as_slice()
            .iter()
            .filter_map(|frontier| {
                self.typed
                    .supertypes_by_frontier
                    .get(frontier)
                    .map(Vec::as_slice)
            })
            .collect::<Vec<_>>();
        visit_preloaded_typed_pages(
            &streams,
            |row| {
                self.typed
                    .selected_source_row(row.reference(), *row)
                    .natural_identity()
            },
            no_preloaded_typed_evidence,
            |row, _| Some(self.typed.selected_source_row(row.reference(), *row)),
            cancellation,
            visitor,
        )
    }

    fn visit_definition_property_gap_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDefinitionPropertyGap>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let streams = definitions
            .as_slice()
            .iter()
            .filter_map(|definition| {
                self.typed
                    .property_gaps_by_definition
                    .get(definition)
                    .map(Vec::as_slice)
            })
            .collect::<Vec<_>>();
        visit_preloaded_typed_pages(
            &streams,
            |row| {
                self.typed
                    .selected_source_row(row.reason_semantic(), *row)
                    .natural_identity()
            },
            |row, evidence, token, work| {
                evidence.include_reason(
                    ResolutionIncompleteReason::UnsupportedSemantic(row.reason_semantic()),
                    token,
                    work,
                )
            },
            |row, _| Some(self.typed.selected_source_row(row.reason_semantic(), *row)),
            cancellation,
            visitor,
        )
    }

    fn visit_call_applicability_pages_for_callee_references(
        &self,
        callee_references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<
            '_,
            SelectedTypedRow<LoweredCallApplicabilityObligation>,
        >,
    ) -> StoreResult<TypedFactReadOutcome> {
        let mut rows = callee_references
            .as_slice()
            .iter()
            .filter_map(|reference| self.typed.call_obligation_by_reference.get(reference))
            .collect::<Vec<_>>();
        rows.sort_unstable_by_key(|row| (self.typed.source_fragment(row.call()), row.call()));
        let streams = [rows.as_slice()];
        visit_preloaded_typed_pages(
            &streams,
            |row| (self.typed.source_fragment(row.call()), row.call()),
            |row, evidence, token, work| evidence.include(row.completion(), token, work),
            |row, cancelled| {
                Some(self.typed.selected_source_row(
                    row.call(),
                    clone_call_obligation_with_poll(row, cancelled)?,
                ))
            },
            cancellation,
            visitor,
        )
    }

    fn visit_callable_signature_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredCallableSignatureProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let mut rows = definitions
            .as_slice()
            .iter()
            .filter_map(|definition| self.typed.callable_signature_by_definition.get(definition))
            .collect::<Vec<_>>();
        rows.sort_unstable_by_key(|row| {
            (
                self.typed.source_fragment(row.definition()),
                row.definition(),
            )
        });
        let streams = [rows.as_slice()];
        visit_preloaded_typed_pages(
            &streams,
            |row| {
                (
                    self.typed.source_fragment(row.definition()),
                    row.definition(),
                )
            },
            |row, evidence, token, work| evidence.include(row.completion(), token, work),
            |row, cancelled| {
                let cloned = {
                    let mut poll = || cancelled();
                    row.clone_with_poll(&mut poll)?
                };
                Some(self.typed.selected_source_row(row.definition(), cloned))
            },
            cancellation,
            visitor,
        )
    }

    fn visit_gap_reason_provenance_pages_for_reasons(
        &self,
        reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedGapReasonProvenance>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let mut rows = reasons
            .as_slice()
            .iter()
            .filter_map(|reason| self.typed.gap_reason_provenance_by_reason.get(reason))
            .collect::<Vec<_>>();
        rows.sort_unstable_by_key(|row| row.natural_identity());
        let streams = [rows.as_slice()];
        visit_preloaded_typed_pages(
            &streams,
            |row| row.natural_identity(),
            no_preloaded_typed_evidence,
            |row, _| Some(**row),
            cancellation,
            visitor,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SelectedQualifiedRoute {
    fragment: BindingFragmentId,
    reference_node: BindingNodeId,
    row: LoweredQualifiedSeededRoute,
}

#[derive(Debug, Default)]
struct TypedSelection {
    fragments: HashSet<BindingFragmentId>,
    source_row_fragments: HashMap<SemanticId, BindingFragmentId>,
    frontiers_by_slot: HashMap<SemanticId, LoweredTypedFrontier>,
    frontier_completion_by_frontier: HashMap<SemanticId, SelectedTypeFrontierCompletion>,
    projections_by_reference: HashMap<SemanticId, Vec<LoweredBindingProjection>>,
    projection_by_output: HashMap<SemanticId, LoweredBindingProjection>,
    qualified_routes: Vec<SelectedQualifiedRoute>,
    qualified_route_inventory: Vec<usize>,
    qualified_route_ids_by_reference: HashMap<SemanticId, Vec<usize>>,
    qualified_route_ids_by_slot_lookup: HashMap<(SemanticId, SemanticId), Vec<usize>>,
    qualified_route_ids_by_qualifier_slot: HashMap<SemanticId, Vec<usize>>,
    /// Completion classification only. Candidate discovery never uses this
    /// lookup-only index; it must first reach an exact qualifier slot.
    qualified_route_ids_by_completion_lookup: HashMap<SemanticId, Vec<usize>>,
    qualified_route_ids_by_gap_owner:
        HashMap<(BindingFragmentId, SemanticId, SemanticId), Vec<usize>>,
    qualified_gap_owner_by_reason: HashMap<SemanticId, (BindingFragmentId, SemanticId)>,
    intrinsic_seed_by_slot: HashMap<SemanticId, LoweredIntrinsicSeed>,
    intrinsic_slots_by_identity: HashMap<SemanticId, Vec<SemanticId>>,
    transfers_by_source: HashMap<SemanticId, Vec<LoweredTypeTransfer>>,
    transfers_by_target: HashMap<SemanticId, Vec<LoweredTypeTransfer>>,
    declaration_types_by_definition: HashMap<SemanticId, Vec<LoweredDeclarationTypeProperty>>,
    declaration_types_by_slot: HashMap<SemanticId, Vec<LoweredDeclarationTypeProperty>>,
    declaration_visibility_by_definition: HashMap<SemanticId, LoweredDeclarationVisibilityProperty>,
    member_scope_by_definition: HashMap<SemanticId, BindingNodeId>,
    member_scope_definition_by_head: HashMap<BindingNodeId, SemanticId>,
    member_scope_inventory: Vec<SemanticId>,
    member_owners_by_definition: HashMap<SemanticId, Vec<LoweredMemberOwnerProperty>>,
    member_definitions_by_owner: HashMap<SemanticId, Vec<LoweredMemberOwnerProperty>>,
    construction_requirements_by_definition:
        HashMap<SemanticId, Vec<LoweredConstructionRequirementProperty>>,
    supertypes_by_definition: HashMap<SemanticId, Vec<LoweredSupertypeProperty>>,
    supertypes_by_reference: HashMap<SemanticId, Vec<LoweredSupertypeProperty>>,
    supertypes_by_frontier: HashMap<SemanticId, Vec<LoweredSupertypeProperty>>,
    property_gaps_by_definition: HashMap<SemanticId, Vec<LoweredDefinitionPropertyGap>>,
    call_obligation_by_reference: HashMap<SemanticId, LoweredCallApplicabilityObligation>,
    callable_signature_by_definition: HashMap<SemanticId, LoweredCallableSignatureProperty>,
    gap_reason_provenance_by_reason: HashMap<SemanticId, SelectedGapReasonProvenance>,
}

fn retain_source_row_fragment(
    owners: &mut HashMap<SemanticId, BindingFragmentId>,
    identity: SemanticId,
    fragment: BindingFragmentId,
) {
    if let Some(previous) = owners.insert(identity, fragment) {
        assert_eq!(
            previous, fragment,
            "typed source identity {identity} crosses selected fragment ownership"
        );
    }
}

impl TypedSelection {
    fn insert_flow_rows(
        &mut self,
        fragment: &LoweredTypedFragment,
        qualified_reference_nodes: &HashMap<SemanticId, (BindingFragmentId, BindingNodeId)>,
    ) {
        let fragment_id = fragment.fragment();
        for frontier in fragment.frontiers().iter().copied() {
            retain_source_row_fragment(
                &mut self.source_row_fragments,
                frontier.slot(),
                fragment_id,
            );
            assert!(
                self.frontiers_by_slot
                    .insert(frontier.slot(), frontier)
                    .is_none(),
                "duplicate selected typed frontier {}",
                frontier.slot()
            );
            assert!(
                self.frontier_completion_by_frontier
                    .insert(
                        frontier.slot(),
                        SelectedTypeFrontierCompletion::new(
                            fragment_id,
                            frontier.slot(),
                            ResolutionCompletion::Complete,
                        ),
                    )
                    .is_none(),
                "duplicate selected typed frontier completion {}",
                frontier.slot()
            );
        }
        for seed in fragment.intrinsic_seeds() {
            let state = seed.frontier();
            retain_source_row_fragment(&mut self.source_row_fragments, state.slot(), fragment_id);
            for value in state.possible_values() {
                self.intrinsic_slots_by_identity
                    .entry(value.ty().identity())
                    .or_default()
                    .push(state.slot());
            }
            assert!(
                self.intrinsic_seed_by_slot
                    .insert(state.slot(), seed.clone())
                    .is_none(),
                "duplicate selected intrinsic seed for typed slot {}",
                seed.frontier().slot()
            );
        }
        for projection in fragment.projections().iter().copied() {
            retain_source_row_fragment(
                &mut self.source_row_fragments,
                projection.reference(),
                fragment_id,
            );
            self.projections_by_reference
                .entry(projection.reference())
                .or_default()
                .push(projection);
            assert!(
                self.projection_by_output
                    .insert(projection.output_slot(), projection)
                    .is_none(),
                "duplicate projection producer for typed slot {}",
                projection.output_slot()
            );
        }
        for route in fragment.qualified_routes().iter().copied() {
            let &(reference_fragment, reference_node) = qualified_reference_nodes
                .get(&route.reference())
                .unwrap_or_else(|| {
                    panic!(
                        "qualified route reference {} has no selected lexical node",
                        route.reference()
                    )
                });
            assert_eq!(
                reference_fragment,
                fragment_id,
                "qualified route reference {} crosses fragment ownership",
                route.reference()
            );
            self.qualified_routes.push(SelectedQualifiedRoute {
                fragment: fragment_id,
                reference_node,
                row: route,
            });
        }
        for transfer in fragment.transfers() {
            let source = transfer.source_slot();
            let target = transfer.rule().target_slot();
            retain_source_row_fragment(
                &mut self.source_row_fragments,
                transfer.rule().semantic(),
                fragment_id,
            );
            self.transfers_by_source
                .entry(source)
                .or_default()
                .push(transfer.clone());
            self.transfers_by_target
                .entry(target)
                .or_default()
                .push(transfer.clone());
        }
    }

    fn insert_declaration_rows(
        &mut self,
        fragment: &LoweredTypedFragment,
        member_scope_owner_by_head: &mut HashMap<BindingNodeId, SemanticId>,
    ) {
        let fragment_id = fragment.fragment();
        for property in fragment.declaration_types().iter().copied() {
            retain_source_row_fragment(
                &mut self.source_row_fragments,
                property.definition(),
                fragment_id,
            );
            self.declaration_types_by_definition
                .entry(property.definition())
                .or_default()
                .push(property);
            self.declaration_types_by_slot
                .entry(property.slot())
                .or_default()
                .push(property);
        }
        for property in fragment.declaration_visibilities().iter().copied() {
            retain_source_row_fragment(
                &mut self.source_row_fragments,
                property.definition(),
                fragment_id,
            );
            assert!(
                self.declaration_visibility_by_definition
                    .insert(property.definition(), property)
                    .is_none(),
                "one selected visibility row per declaration is required: {}",
                property.definition()
            );
        }
        for property in fragment.member_scopes() {
            retain_source_row_fragment(
                &mut self.source_row_fragments,
                property.definition(),
                fragment_id,
            );
            assert!(
                self.member_scope_by_definition
                    .insert(property.definition(), property.scope_head())
                    .is_none(),
                "duplicate member scope for definition {}",
                property.definition()
            );
            assert!(
                member_scope_owner_by_head
                    .insert(property.scope_head(), property.definition())
                    .is_none(),
                "member scope head {} names multiple owners",
                property.scope_head()
            );
            assert!(
                self.member_scope_definition_by_head
                    .insert(property.scope_head(), property.definition())
                    .is_none(),
                "selected member scope head {} names multiple owners",
                property.scope_head()
            );
            self.member_scope_inventory.push(property.definition());
        }
        for property in fragment.member_owners().iter().copied() {
            retain_source_row_fragment(
                &mut self.source_row_fragments,
                property.definition(),
                fragment_id,
            );
            self.member_owners_by_definition
                .entry(property.definition())
                .or_default()
                .push(property);
            self.member_definitions_by_owner
                .entry(property.owner_definition())
                .or_default()
                .push(property);
        }
        for property in fragment.construction_requirements().iter().copied() {
            retain_source_row_fragment(
                &mut self.source_row_fragments,
                property.definition(),
                fragment_id,
            );
            self.construction_requirements_by_definition
                .entry(property.definition())
                .or_default()
                .push(property);
        }
        for property in fragment.supertypes().iter().copied() {
            retain_source_row_fragment(
                &mut self.source_row_fragments,
                property.reference(),
                fragment_id,
            );
            self.supertypes_by_definition
                .entry(property.definition())
                .or_default()
                .push(property);
            self.supertypes_by_reference
                .entry(property.reference())
                .or_default()
                .push(property);
            self.supertypes_by_frontier
                .entry(property.frontier())
                .or_default()
                .push(property);
        }
        for gap in fragment.property_gaps().iter().copied() {
            retain_source_row_fragment(
                &mut self.source_row_fragments,
                gap.reason_semantic(),
                fragment_id,
            );
            self.property_gaps_by_definition
                .entry(gap.definition())
                .or_default()
                .push(gap);
        }
        for obligation in fragment.call_obligations().iter().cloned() {
            let reference = obligation.callee_reference();
            retain_source_row_fragment(
                &mut self.source_row_fragments,
                obligation.call(),
                fragment_id,
            );
            assert!(
                self.call_obligation_by_reference
                    .insert(reference, obligation)
                    .is_none(),
                "one call-applicability obligation per callee reference is required: {reference}"
            );
        }
        for signature in fragment.callable_signatures().iter().cloned() {
            let definition = signature.definition();
            retain_source_row_fragment(&mut self.source_row_fragments, definition, fragment_id);
            assert!(
                self.callable_signature_by_definition
                    .insert(definition, signature)
                    .is_none(),
                "one callable signature per definition is required: {definition}"
            );
        }
    }

    fn insert_lexical_gap_provenance(&mut self, lexical: &LoweredResolutionFragment) {
        let fragment = lexical.fragment();
        assert!(
            self.fragments.contains(&fragment),
            "lexical gap provenance names unselected typed fragment {fragment}"
        );
        for gap in lexical.gaps() {
            let provenance = SelectedGapReasonProvenance::new(
                fragment,
                gap.reason_semantic(),
                gap.site(),
                gap.origin(),
            );
            if let Some(previous) = self
                .gap_reason_provenance_by_reason
                .insert(gap.reason_semantic(), provenance)
            {
                assert_eq!(
                    previous, provenance,
                    "one selected gap reason must retain one exact lowering provenance"
                );
            }
            let LoweringCoverageFrontier::Type { frontier } = gap.frontier() else {
                continue;
            };
            let local = ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(gap.reason_semantic()),
            ]);
            if let Some(previous) = self.frontier_completion_by_frontier.get(&frontier) {
                assert_eq!(
                    previous.fragment(),
                    fragment,
                    "typed frontier {frontier} crosses selected fragment ownership"
                );
                let completion = previous.completion().combine(&local);
                self.frontier_completion_by_frontier.insert(
                    frontier,
                    SelectedTypeFrontierCompletion::new(fragment, frontier, completion),
                );
            } else {
                self.frontier_completion_by_frontier.insert(
                    frontier,
                    SelectedTypeFrontierCompletion::new(fragment, frontier, local),
                );
            }
        }
    }

    fn new(
        fragments: &[LoweredTypedFragment],
        lexical_fragments: &[LoweredResolutionFragment],
        qualified_reference_nodes: &HashMap<SemanticId, (BindingFragmentId, BindingNodeId)>,
    ) -> (Self, HashMap<BindingNodeId, SemanticId>) {
        let mut member_scope_owner_by_head = HashMap::default();
        let mut selection = Self::default();

        for fragment in fragments {
            let fragment_id = fragment.fragment();
            assert!(
                selection.fragments.insert(fragment_id),
                "duplicate lowered typed fragment {}",
                fragment_id
            );
            selection.insert_flow_rows(fragment, qualified_reference_nodes);
            selection.insert_declaration_rows(fragment, &mut member_scope_owner_by_head);
        }
        for lexical in lexical_fragments {
            selection.insert_lexical_gap_provenance(lexical);
        }
        for projections in selection.projections_by_reference.values_mut() {
            projections.sort_by_key(|projection| {
                (
                    projection.output_slot(),
                    projection_kind_rank(projection.kind()),
                )
            });
            projections.dedup();
        }
        selection.qualified_routes.sort_by_key(|route| {
            (
                route.row.reference(),
                route.fragment,
                route.reference_node,
                route.row.qualifier_slot(),
                route.row.lookup(),
                route.row.namespace(),
                route.row.precedence_ordinal(),
                route.row.projection_output_slot(),
                projection_kind_rank(route.row.projection_kind()),
                route.row.coarse_gap_reason(),
            )
        });
        selection.qualified_routes.dedup();
        for (route_id, route) in selection.qualified_routes.iter().enumerate() {
            let gap_owner = (route.fragment, route.row.reference());
            if let Some(previous) = selection
                .qualified_gap_owner_by_reason
                .insert(route.row.coarse_gap_reason(), gap_owner)
            {
                assert_eq!(
                    previous, gap_owner,
                    "one typed-owned qualified reason must name one fragment/reference owner"
                );
            }
            selection
                .qualified_route_ids_by_reference
                .entry(route.row.reference())
                .or_default()
                .push(route_id);
            selection
                .qualified_route_ids_by_slot_lookup
                .entry((route.row.qualifier_slot(), route.row.lookup()))
                .or_default()
                .push(route_id);
            selection
                .qualified_route_ids_by_qualifier_slot
                .entry(route.row.qualifier_slot())
                .or_default()
                .push(route_id);
            selection
                .qualified_route_ids_by_completion_lookup
                .entry(route.row.lookup())
                .or_default()
                .push(route_id);
            selection
                .qualified_route_ids_by_gap_owner
                .entry((
                    route.fragment,
                    route.row.reference(),
                    route.row.coarse_gap_reason(),
                ))
                .or_default()
                .push(route_id);
        }
        assert_eq!(
            selection
                .qualified_route_ids_by_reference
                .values()
                .map(Vec::len)
                .sum::<usize>(),
            selection.qualified_routes.len(),
            "each selected qualified route must have one reference index entry"
        );
        assert_eq!(
            selection
                .qualified_route_ids_by_slot_lookup
                .values()
                .map(Vec::len)
                .sum::<usize>(),
            selection.qualified_routes.len(),
            "each selected qualified route must have one composite slot/lookup index entry"
        );
        assert_eq!(
            selection
                .qualified_route_ids_by_qualifier_slot
                .values()
                .map(Vec::len)
                .sum::<usize>(),
            selection.qualified_routes.len(),
            "each selected qualified route must have one qualifier-slot index entry"
        );
        assert_eq!(
            selection
                .qualified_route_ids_by_completion_lookup
                .values()
                .map(Vec::len)
                .sum::<usize>(),
            selection.qualified_routes.len(),
            "each selected qualified route must have one completion-only lookup entry"
        );
        assert_eq!(
            selection
                .qualified_route_ids_by_gap_owner
                .values()
                .map(Vec::len)
                .sum::<usize>(),
            selection.qualified_routes.len(),
            "each selected qualified route must retain one exact coarse-gap owner entry"
        );
        assert!(
            selection
                .qualified_route_ids_by_gap_owner
                .values()
                .all(|route_ids| route_ids.windows(2).all(|pair| pair[0] < pair[1])),
            "qualified coarse-gap route groups must be strictly sorted and deduplicated"
        );
        let qualified_routes = &selection.qualified_routes;
        let route_identity = |route_id: &usize| {
            let route = qualified_routes[*route_id];
            (
                route.fragment,
                route.row.reference(),
                route.row.precedence_ordinal(),
            )
        };
        selection.qualified_route_inventory = (0..selection.qualified_routes.len()).collect();
        selection
            .qualified_route_inventory
            .sort_unstable_by_key(&route_identity);
        for route_ids in selection
            .qualified_route_ids_by_reference
            .values_mut()
            .chain(selection.qualified_route_ids_by_slot_lookup.values_mut())
            .chain(selection.qualified_route_ids_by_qualifier_slot.values_mut())
            .chain(
                selection
                    .qualified_route_ids_by_completion_lookup
                    .values_mut(),
            )
            .chain(selection.qualified_route_ids_by_gap_owner.values_mut())
        {
            route_ids.sort_unstable_by_key(&route_identity);
            assert!(route_ids.windows(2).all(|pair| pair[0] != pair[1]));
        }
        let source_row_fragments = &selection.source_row_fragments;
        for slots in selection.intrinsic_slots_by_identity.values_mut() {
            slots.sort_unstable_by_key(|slot| (source_row_fragments[slot], *slot));
            slots.dedup();
        }
        for transfers in selection.transfers_by_source.values_mut() {
            transfers.sort_by_key(|transfer| {
                (
                    source_row_fragments[&transfer.rule().semantic()],
                    transfer.rule().semantic(),
                )
            });
            transfers.dedup();
        }
        for transfers in selection.transfers_by_target.values_mut() {
            transfers.sort_by_key(|transfer| {
                (
                    source_row_fragments[&transfer.rule().semantic()],
                    transfer.rule().semantic(),
                )
            });
            transfers.dedup();
        }
        for values in selection.declaration_types_by_definition.values_mut() {
            values.sort_by_key(|property| {
                (declaration_type_role_rank(property.role()), property.slot())
            });
            values.dedup();
        }
        for values in selection.declaration_types_by_slot.values_mut() {
            values.sort_by_key(|property| {
                (
                    property.definition(),
                    declaration_type_role_rank(property.role()),
                )
            });
            values.dedup();
        }
        for values in selection.member_owners_by_definition.values_mut() {
            values.sort_by_key(|property| {
                (
                    property.owner_definition(),
                    property.owner_scope_head(),
                    member_kind_rank(property.kind()),
                    property.access(),
                    member_qualifier_compatibility_rank(property.qualifier_compatibility()),
                )
            });
            values.dedup();
        }
        for values in selection.member_definitions_by_owner.values_mut() {
            values.sort_by_key(|property| {
                (
                    source_row_fragments[&property.definition()],
                    property.definition(),
                    property.owner_scope_head(),
                    member_kind_rank(property.kind()),
                    property.access(),
                    member_qualifier_compatibility_rank(property.qualifier_compatibility()),
                )
            });
            values.dedup();
        }
        for values in selection
            .construction_requirements_by_definition
            .values_mut()
        {
            values.sort_by_key(|property| (property.kind(), property.required_owner_definition()));
            values.dedup();
        }
        let source_row_fragments = &selection.source_row_fragments;
        for values in selection.supertypes_by_definition.values_mut() {
            values.sort_by_key(|property| {
                (
                    source_row_fragments[&property.reference()],
                    property.definition(),
                    property.kind(),
                    property.reference(),
                    property.frontier(),
                )
            });
            values.dedup();
        }
        for values in selection.supertypes_by_reference.values_mut() {
            values.sort_by_key(|property| {
                (
                    source_row_fragments[&property.reference()],
                    property.definition(),
                    property.kind(),
                    property.reference(),
                    property.frontier(),
                )
            });
            values.dedup();
        }
        for values in selection.supertypes_by_frontier.values_mut() {
            values.sort_by_key(|property| {
                (
                    source_row_fragments[&property.reference()],
                    property.definition(),
                    property.kind(),
                    property.reference(),
                    property.frontier(),
                )
            });
            values.dedup();
        }
        for values in selection.property_gaps_by_definition.values_mut() {
            values.sort_by_key(|gap| {
                (
                    source_row_fragments[&gap.reason_semantic()],
                    gap.definition(),
                    gap.reason_semantic(),
                    gap.frontier(),
                )
            });
            values.dedup();
        }
        selection
            .member_scope_inventory
            .sort_unstable_by_key(|definition| {
                (selection.source_row_fragments[definition], *definition)
            });
        (selection, member_scope_owner_by_head)
    }

    fn owns_qualified_gap(
        &self,
        fragment: BindingFragmentId,
        reference: SemanticId,
        reason: SemanticId,
    ) -> bool {
        self.qualified_route_ids_by_gap_owner
            .contains_key(&(fragment, reference, reason))
    }

    fn selected_source_row<T>(&self, owner_identity: SemanticId, row: T) -> SelectedTypedRow<T> {
        let fragment = self.source_fragment(owner_identity);
        SelectedTypedRow::new(fragment, row)
    }

    fn source_fragment(&self, owner_identity: SemanticId) -> BindingFragmentId {
        self.source_row_fragments
            .get(&owner_identity)
            .copied()
            .unwrap_or_else(|| {
                panic!("typed source row {owner_identity} has no selected fragment owner")
            })
    }

    fn selected_source_route(&self, route_id: usize) -> SourceSelectedQualifiedRoute {
        let route = self.qualified_routes[route_id];
        SourceSelectedQualifiedRoute::new(route.fragment, route.reference_node, route.row)
    }
}

#[cfg(test)]
mod tests {
    use super::super::batch::BatchResolutionEngine;
    use super::super::batch::{ReverseCandidateGapExclusionPlan, ReverseCandidateGapIdentity};
    use super::super::coverage::LoweredCandidateDirection;
    use super::super::fact_lowering::lower_file_resolution_facts;
    use super::super::fact_source::TypedFactReadTerminal;
    use super::super::fact_source::{FactResolutionSource, MAX_TYPED_FACT_REQUESTS_PER_BATCH};
    use super::super::model::{ResolutionSlotValue, ResolutionTypeRef};
    use super::super::typed_fact_lowering::lower_typed_resolution_facts;
    use super::*;
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
    use brokk_bifrost_core::analyzer::resolution_facts::{
        BindingProjectionFact, BindingProjectionKind, DeclarationTypeRole, DeclarationTypeSlotFact,
        FileResolutionFacts, IntrinsicTypeKind, IntrinsicTypeSeedFact, PositionedIdentifierFact,
        ResolutionBinderFact, ResolutionBinderKind, ResolutionCallFact,
        ResolutionCallableSignatureFact, ResolutionDeclarationVisibilityFact, ResolutionGapFact,
        ResolutionGapKind, ResolutionIdentifierRole, ResolutionMemberAccess, ResolutionMemberKind,
        ResolutionMemberOwnerFact, ResolutionMemberQualifierCompatibility, ResolutionNameFact,
        ResolutionNameId, ResolutionNamespace, ResolutionScopeFact, ResolutionScopeId,
        ResolutionScopeKind, ResolutionSiteFact, ResolutionSiteId, ResolutionSiteKind,
        ResolutionSupertypeFact, ResolutionSupertypeKind, ResolutionTypeSlotFact,
        ResolutionTypeSlotId, ResolutionTypeSlotRole, ResolutionTypeTransferFact,
        ResolutionTypeTransferKind, ResolutionTypeTransferValueTransform,
        ResolutionVisibilityEligibilityFact,
    };
    use brokk_bifrost_core::analyzer::resolution_facts::{
        ResolutionCallableReceiverOrigin, ResolutionCallableReceiverOriginFact,
        ResolutionRootExportFact,
    };
    use brokk_bifrost_core::analyzer::structural::resolution::{DeclaredVisibility, HoistingClass};
    use std::collections::BTreeMap;
    fn fragment() -> BindingFragmentId {
        BindingFragmentId::hash_bytes(b"fact-resolution-java-fixture")
    }

    fn name(id: u32, spelling: &str) -> ResolutionNameFact {
        ResolutionNameFact {
            id: ResolutionNameId::new(id),
            spelling: spelling.into(),
        }
    }

    fn scope(
        id: u32,
        parent: Option<u32>,
        owner: Option<u32>,
        kind: ResolutionScopeKind,
        start_byte: usize,
        end_byte: usize,
    ) -> ResolutionScopeFact {
        ResolutionScopeFact {
            id: ResolutionScopeId::new(id),
            parent: parent.map(ResolutionScopeId::new),
            owner: owner.map(ResolutionSiteId::new),
            kind,
            start_byte,
            end_byte,
        }
    }

    fn site(id: u32, scope: u32, kind: ResolutionSiteKind, position: usize) -> ResolutionSiteFact {
        ResolutionSiteFact {
            id: ResolutionSiteId::new(id),
            scope: ResolutionScopeId::new(scope),
            kind,
            start_byte: position,
            end_byte: position + 1,
        }
    }

    fn identifier(
        site: u32,
        name: u32,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
        qualifier: Option<u32>,
    ) -> PositionedIdentifierFact {
        PositionedIdentifierFact {
            site: ResolutionSiteId::new(site),
            name: ResolutionNameId::new(name),
            role,
            namespace,
            qualifier: qualifier.map(ResolutionTypeSlotId::new),
        }
    }

    fn binder(
        declaration: u32,
        scope: u32,
        kind: ResolutionBinderKind,
        hoisting: HoistingClass,
        activation_start: usize,
        activation_end: usize,
    ) -> ResolutionBinderFact {
        ResolutionBinderFact {
            declaration: ResolutionSiteId::new(declaration),
            scope: ResolutionScopeId::new(scope),
            kind,
            hoisting,
            activation_start,
            activation_end,
        }
    }

    fn slot(id: u32, site: u32, role: ResolutionTypeSlotRole) -> ResolutionTypeSlotFact {
        ResolutionTypeSlotFact {
            id: ResolutionTypeSlotId::new(id),
            site: ResolutionSiteId::new(site),
            role,
        }
    }

    fn transfer(
        input: u32,
        output: u32,
        kind: ResolutionTypeTransferKind,
        value_transform: ResolutionTypeTransferValueTransform,
    ) -> ResolutionTypeTransferFact {
        ResolutionTypeTransferFact {
            input: ResolutionTypeSlotId::new(input),
            output: ResolutionTypeSlotId::new(output),
            kind,
            indirection_delta: 0,
            value_transform,
        }
    }

    fn java_chain_facts() -> FileResolutionFacts {
        FileResolutionFacts {
            names: vec![
                name(0, "A"),
                name(1, "B"),
                name(2, "a"),
                name(3, "b"),
                name(4, "c"),
                name(5, "f"),
                name(6, "int"),
            ],
            scopes: vec![
                scope(
                    0,
                    None,
                    None,
                    ResolutionScopeKind::CompilationUnit,
                    0,
                    1_000,
                ),
                scope(1, Some(0), Some(0), ResolutionScopeKind::TypeBody, 10, 190),
                scope(2, Some(0), Some(1), ResolutionScopeKind::TypeBody, 210, 390),
            ],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeDeclaration, 1),
                site(1, 0, ResolutionSiteKind::TypeDeclaration, 201),
                site(2, 0, ResolutionSiteKind::ValueDeclaration, 600),
                site(3, 1, ResolutionSiteKind::CallableDeclaration, 20),
                site(4, 1, ResolutionSiteKind::ValueDeclaration, 30),
                site(5, 2, ResolutionSiteKind::ValueDeclaration, 220),
                site(6, 1, ResolutionSiteKind::ConstructorDeclaration, 40),
                site(7, 0, ResolutionSiteKind::TypeReference, 590),
                site(8, 0, ResolutionSiteKind::ValueReference, 610),
                site(9, 0, ResolutionSiteKind::MemberReference, 611),
                site(10, 0, ResolutionSiteKind::ValueReference, 620),
                site(11, 0, ResolutionSiteKind::MemberReference, 621),
                site(12, 0, ResolutionSiteKind::MemberReference, 622),
                site(13, 1, ResolutionSiteKind::TypeReference, 21),
                site(14, 1, ResolutionSiteKind::TypeReference, 31),
                site(15, 2, ResolutionSiteKind::TypeReference, 221),
                site(16, 0, ResolutionSiteKind::Call, 619),
                site(17, 0, ResolutionSiteKind::TypeReference, 630),
                site(18, 0, ResolutionSiteKind::ConstructorReference, 631),
                site(19, 0, ResolutionSiteKind::Call, 629),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                    None,
                ),
                identifier(
                    1,
                    1,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                    None,
                ),
                identifier(
                    2,
                    2,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                    None,
                ),
                identifier(
                    3,
                    3,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Callable,
                    None,
                ),
                identifier(
                    4,
                    5,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                    None,
                ),
                identifier(
                    5,
                    4,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                    None,
                ),
                identifier(
                    6,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Constructor,
                    None,
                ),
                identifier(
                    7,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                    None,
                ),
                identifier(
                    8,
                    2,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::TypeOrValue,
                    None,
                ),
                identifier(
                    9,
                    5,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::TypeOrValue,
                    Some(3),
                ),
                identifier(
                    10,
                    2,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::TypeOrValue,
                    None,
                ),
                identifier(
                    11,
                    3,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Callable,
                    Some(8),
                ),
                identifier(
                    12,
                    4,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::TypeOrValue,
                    Some(12),
                ),
                identifier(
                    13,
                    1,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                    None,
                ),
                identifier(
                    17,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                    None,
                ),
                identifier(
                    18,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Constructor,
                    Some(16),
                ),
            ],
            binders: vec![
                binder(
                    0,
                    0,
                    ResolutionBinderKind::Type,
                    HoistingClass::ScopeWide,
                    0,
                    1_000,
                ),
                binder(
                    1,
                    0,
                    ResolutionBinderKind::Type,
                    HoistingClass::ScopeWide,
                    0,
                    1_000,
                ),
                binder(
                    2,
                    0,
                    ResolutionBinderKind::Local,
                    HoistingClass::SourceOrder,
                    601,
                    1_000,
                ),
                binder(
                    3,
                    1,
                    ResolutionBinderKind::Callable,
                    HoistingClass::ScopeWide,
                    10,
                    190,
                ),
                binder(
                    4,
                    1,
                    ResolutionBinderKind::Field,
                    HoistingClass::ScopeWide,
                    10,
                    190,
                ),
                binder(
                    5,
                    2,
                    ResolutionBinderKind::Field,
                    HoistingClass::ScopeWide,
                    210,
                    390,
                ),
                binder(
                    6,
                    1,
                    ResolutionBinderKind::Constructor,
                    HoistingClass::ScopeWide,
                    10,
                    190,
                ),
            ],
            type_slots: vec![
                slot(0, 7, ResolutionTypeSlotRole::TargetTypeIdentity),
                slot(1, 2, ResolutionTypeSlotRole::DeclaredValue),
                slot(2, 8, ResolutionTypeSlotRole::ExpressionValue),
                slot(3, 9, ResolutionTypeSlotRole::Receiver),
                slot(4, 9, ResolutionTypeSlotRole::ExpressionValue),
                slot(5, 14, ResolutionTypeSlotRole::TargetTypeIdentity),
                slot(6, 4, ResolutionTypeSlotRole::DeclaredValue),
                slot(7, 10, ResolutionTypeSlotRole::ExpressionValue),
                slot(8, 16, ResolutionTypeSlotRole::Receiver),
                slot(9, 16, ResolutionTypeSlotRole::CallResult),
                slot(10, 13, ResolutionTypeSlotRole::TargetTypeIdentity),
                slot(11, 3, ResolutionTypeSlotRole::DeclaredValue),
                slot(12, 12, ResolutionTypeSlotRole::Receiver),
                slot(13, 12, ResolutionTypeSlotRole::ExpressionValue),
                slot(14, 15, ResolutionTypeSlotRole::TargetTypeIdentity),
                slot(15, 5, ResolutionTypeSlotRole::DeclaredValue),
                slot(16, 17, ResolutionTypeSlotRole::TargetTypeIdentity),
                slot(17, 19, ResolutionTypeSlotRole::CallResult),
            ],
            declaration_type_slots: vec![
                DeclarationTypeSlotFact {
                    declaration: ResolutionSiteId::new(2),
                    slot: ResolutionTypeSlotId::new(1),
                    role: DeclarationTypeRole::Value,
                },
                DeclarationTypeSlotFact {
                    declaration: ResolutionSiteId::new(4),
                    slot: ResolutionTypeSlotId::new(6),
                    role: DeclarationTypeRole::Value,
                },
                DeclarationTypeSlotFact {
                    declaration: ResolutionSiteId::new(3),
                    slot: ResolutionTypeSlotId::new(11),
                    role: DeclarationTypeRole::Return,
                },
                DeclarationTypeSlotFact {
                    declaration: ResolutionSiteId::new(5),
                    slot: ResolutionTypeSlotId::new(15),
                    role: DeclarationTypeRole::Value,
                },
            ],
            binding_projections: vec![
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(7),
                    output: ResolutionTypeSlotId::new(0),
                    kind: BindingProjectionKind::TargetTypeIdentity,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(8),
                    output: ResolutionTypeSlotId::new(2),
                    kind: BindingProjectionKind::TargetTypeOrDeclaredValueType,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(9),
                    output: ResolutionTypeSlotId::new(4),
                    kind: BindingProjectionKind::TargetTypeOrDeclaredValueType,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(10),
                    output: ResolutionTypeSlotId::new(7),
                    kind: BindingProjectionKind::TargetTypeOrDeclaredValueType,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(11),
                    output: ResolutionTypeSlotId::new(9),
                    kind: BindingProjectionKind::TargetCallableResultType,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(12),
                    output: ResolutionTypeSlotId::new(13),
                    kind: BindingProjectionKind::TargetTypeOrDeclaredValueType,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(13),
                    output: ResolutionTypeSlotId::new(10),
                    kind: BindingProjectionKind::TargetTypeIdentity,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(17),
                    output: ResolutionTypeSlotId::new(16),
                    kind: BindingProjectionKind::TargetTypeIdentity,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(18),
                    output: ResolutionTypeSlotId::new(17),
                    kind: BindingProjectionKind::TargetConstructorOwnerType,
                },
            ],
            type_transfers: vec![
                transfer(
                    0,
                    1,
                    ResolutionTypeTransferKind::DeclaredType,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                ),
                transfer(
                    2,
                    3,
                    ResolutionTypeTransferKind::Receiver,
                    ResolutionTypeTransferValueTransform::Preserve,
                ),
                transfer(
                    5,
                    6,
                    ResolutionTypeTransferKind::DeclaredType,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                ),
                transfer(
                    7,
                    8,
                    ResolutionTypeTransferKind::Receiver,
                    ResolutionTypeTransferValueTransform::Preserve,
                ),
                transfer(
                    10,
                    11,
                    ResolutionTypeTransferKind::DeclaredType,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                ),
                transfer(
                    9,
                    12,
                    ResolutionTypeTransferKind::Receiver,
                    ResolutionTypeTransferValueTransform::Preserve,
                ),
                transfer(
                    14,
                    15,
                    ResolutionTypeTransferKind::DeclaredType,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                ),
            ],
            intrinsic_type_seeds: vec![
                IntrinsicTypeSeedFact {
                    output: ResolutionTypeSlotId::new(5),
                    name: ResolutionNameId::new(6),
                    kind: IntrinsicTypeKind::Primitive,
                    indirection: 0,
                },
                IntrinsicTypeSeedFact {
                    output: ResolutionTypeSlotId::new(14),
                    name: ResolutionNameId::new(6),
                    kind: IntrinsicTypeKind::Primitive,
                    indirection: 0,
                },
            ],
            calls: vec![
                ResolutionCallFact {
                    call: ResolutionSiteId::new(16),
                    callee: ResolutionSiteId::new(11),
                    receiver: Some(ResolutionTypeSlotId::new(8)),
                    result: ResolutionTypeSlotId::new(9),
                    explicit_type_argument_count: 0,
                },
                ResolutionCallFact {
                    call: ResolutionSiteId::new(19),
                    callee: ResolutionSiteId::new(18),
                    receiver: None,
                    result: ResolutionTypeSlotId::new(17),
                    explicit_type_argument_count: 0,
                },
            ],
            callable_receiver_origins: vec![ResolutionCallableReceiverOriginFact {
                reference: ResolutionSiteId::new(11),
                origin: ResolutionCallableReceiverOrigin::ExplicitExpression,
            }],
            callable_signatures: vec![
                ResolutionCallableSignatureFact {
                    callable: ResolutionSiteId::new(3),
                    type_parameter_count: 0,
                },
                ResolutionCallableSignatureFact {
                    callable: ResolutionSiteId::new(6),
                    type_parameter_count: 0,
                },
            ],
            member_owners: vec![
                ResolutionMemberOwnerFact {
                    member: ResolutionSiteId::new(3),
                    owner: ResolutionSiteId::new(0),
                    kind: ResolutionMemberKind::Method,
                    access: ResolutionMemberAccess::Instance,
                    qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOnly,
                },
                ResolutionMemberOwnerFact {
                    member: ResolutionSiteId::new(4),
                    owner: ResolutionSiteId::new(0),
                    kind: ResolutionMemberKind::Field,
                    access: ResolutionMemberAccess::Instance,
                    qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOnly,
                },
                ResolutionMemberOwnerFact {
                    member: ResolutionSiteId::new(5),
                    owner: ResolutionSiteId::new(1),
                    kind: ResolutionMemberKind::Field,
                    access: ResolutionMemberAccess::Instance,
                    qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOnly,
                },
                ResolutionMemberOwnerFact {
                    member: ResolutionSiteId::new(6),
                    owner: ResolutionSiteId::new(0),
                    kind: ResolutionMemberKind::Constructor,
                    access: ResolutionMemberAccess::Type,
                    qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
                },
            ],
            declaration_visibilities: [0, 1, 3, 4, 5, 6]
                .map(|declaration| ResolutionDeclarationVisibilityFact {
                    declaration: ResolutionSiteId::new(declaration),
                    visibility: DeclaredVisibility::Public,
                })
                .to_vec(),
            visibility_eligibilities: [0, 1, 3, 4, 5, 6]
                .map(|declaration| ResolutionVisibilityEligibilityFact {
                    declaration: ResolutionSiteId::new(declaration),
                })
                .to_vec(),
            ..FileResolutionFacts::default()
        }
    }

    fn all_typed_source_facts() -> FileResolutionFacts {
        let mut facts = java_chain_facts();
        facts.supertypes.push(ResolutionSupertypeFact {
            subtype: ResolutionSiteId::new(0),
            supertype_reference: ResolutionSiteId::new(13),
            supertype_slot: ResolutionTypeSlotId::new(10),
            kind: ResolutionSupertypeKind::Superclass,
        });
        facts.gaps.extend([
            ResolutionGapFact {
                site: ResolutionSiteId::new(1),
                kind: ResolutionGapKind::ImplicitConstructor,
            },
            ResolutionGapFact {
                site: ResolutionSiteId::new(13),
                kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
            },
        ]);
        facts
    }

    fn collect_typed_read<T, F>(read: F) -> (Vec<T>, Vec<usize>, TypedFactReadOutcome)
    where
        T: Clone,
        F: FnOnce(&mut TypedFactPageVisitor<'_, T>) -> StoreResult<TypedFactReadOutcome>,
    {
        let mut rows = Vec::new();
        let mut page_sizes = Vec::new();
        let mut callback = |page: &[T]| {
            page_sizes.push(page.len());
            rows.extend_from_slice(page);
            Ok(true)
        };
        let mut visitor = TypedFactPageVisitor::new(&mut callback);
        let outcome = read(&mut visitor).expect("preloaded typed reads are infallible");
        (rows, page_sizes, outcome)
    }

    fn assert_exhausted_typed_rows<T, F>(expected: Vec<T>, read: F)
    where
        T: Clone + std::fmt::Debug + PartialEq,
        F: FnOnce(&mut TypedFactPageVisitor<'_, T>) -> StoreResult<TypedFactReadOutcome>,
    {
        let (actual, page_sizes, outcome) = collect_typed_read(read);
        assert_eq!(actual, expected);
        assert!(
            page_sizes
                .iter()
                .all(|&size| size <= MAX_TYPED_FACT_ROWS_PER_PAGE)
        );
        assert_eq!(outcome.terminal(), TypedFactReadTerminal::Exhausted);
        assert_eq!(outcome.evidence(), &ResolutionCompletion::Complete);
    }

    fn reversed_unique<T>(values: impl IntoIterator<Item = T>) -> Vec<T>
    where
        T: Ord,
    {
        values
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    fn java_fixture() -> PreloadedFactSource {
        let facts = java_chain_facts();
        PreloadedFactSource::from_lowered_fragments(
            [lower_file_resolution_facts(
                fragment(),
                Language::Java,
                &facts,
            )],
            [lower_typed_resolution_facts(
                fragment(),
                Language::Java,
                &facts,
            )],
        )
    }

    fn service_reason(kind: &[u8], fields: &[&[u8]]) -> SemanticId {
        let mut hasher = CanonicalHasher::new(b"bifrost-resolution-fact-service-reason:v1");
        hasher.field("kind", kind);
        for (index, field) in fields.iter().enumerate() {
            hasher.field(&format!("field-{index}"), field);
        }
        SemanticId::from_digest(hasher.finish())
    }

    #[test]
    fn preloaded_composite_source_matches_every_selected_typed_access_shape() {
        fn assert_composite_source(_source: &dyn FactResolutionSource) {}

        let owner = fragment();
        let facts = all_typed_source_facts();
        let lexical = lower_file_resolution_facts(owner, Language::Java, &facts);
        let typed = lower_typed_resolution_facts(owner, Language::Java, &facts);
        let service =
            PreloadedFactSource::from_lowered_fragments([lexical.clone()], [typed.clone()]);
        assert_composite_source(&service);
        let cancellation = CancellationToken::new();

        let frontier_slots = reversed_unique(typed.frontiers().iter().map(|row| row.slot()));
        let mut expected = typed
            .frontiers()
            .iter()
            .copied()
            .map(|row| SelectedTypedRow::new(owner, row))
            .collect::<Vec<_>>();
        expected.sort_unstable_by_key(|row| row.natural_identity());
        assert_exhausted_typed_rows(expected, |visitor| {
            service.visit_typed_frontier_pages(
                TypedFactRequest::new(&frontier_slots),
                &cancellation,
                visitor,
            )
        });

        let mut frontier_completions = BTreeMap::new();
        for frontier in typed.frontiers() {
            assert!(
                frontier_completions
                    .insert(frontier.slot(), ResolutionCompletion::Complete)
                    .is_none()
            );
        }
        for gap in lexical.gaps() {
            let LoweringCoverageFrontier::Type { frontier } = gap.frontier() else {
                continue;
            };
            let local = ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(gap.reason_semantic()),
            ]);
            frontier_completions
                .entry(frontier)
                .and_modify(|completion| *completion = completion.combine(&local))
                .or_insert(local);
        }
        let completion_keys = reversed_unique(frontier_completions.keys().copied());
        let expected = frontier_completions
            .into_iter()
            .map(|(frontier, completion)| {
                SelectedTypeFrontierCompletion::new(owner, frontier, completion)
            })
            .collect();
        assert_exhausted_typed_rows(expected, |visitor| {
            service.visit_type_frontier_completion_pages(
                TypedFactRequest::new(&completion_keys),
                &cancellation,
                visitor,
            )
        });

        let expected_transfers = typed
            .transfers()
            .iter()
            .cloned()
            .map(|row| SelectedTypedRow::new(owner, row))
            .collect::<Vec<_>>();
        let mut expected_source_transfers = expected_transfers.clone();
        expected_source_transfers.sort_by_key(|row| row.source_access_order());
        let transfer_sources = reversed_unique(
            typed
                .transfers()
                .iter()
                .map(LoweredTypeTransfer::source_slot),
        );
        assert_exhausted_typed_rows(expected_source_transfers, |visitor| {
            service.visit_type_transfer_pages_from_sources(
                TypedFactRequest::new(&transfer_sources),
                &cancellation,
                visitor,
            )
        });
        let transfer_targets =
            reversed_unique(typed.transfers().iter().map(|row| row.rule().target_slot()));
        let mut expected_target_transfers = expected_transfers;
        expected_target_transfers.sort_by_key(|row| row.target_access_order());
        assert_exhausted_typed_rows(expected_target_transfers, |visitor| {
            service.visit_type_transfer_pages_to_targets(
                TypedFactRequest::new(&transfer_targets),
                &cancellation,
                visitor,
            )
        });

        let mut expected_intrinsics = typed
            .intrinsic_seeds()
            .iter()
            .cloned()
            .map(|row| SelectedTypedRow::new(owner, row))
            .collect::<Vec<_>>();
        expected_intrinsics.sort_by_key(|row| row.natural_identity());
        let intrinsic_slots = reversed_unique(
            typed
                .intrinsic_seeds()
                .iter()
                .map(|row| row.frontier().slot()),
        );
        assert_exhausted_typed_rows(expected_intrinsics.clone(), |visitor| {
            service.visit_intrinsic_seed_pages_for_slots(
                TypedFactRequest::new(&intrinsic_slots),
                &cancellation,
                visitor,
            )
        });
        let intrinsic_identities = reversed_unique(
            typed
                .intrinsic_seeds()
                .iter()
                .flat_map(|row| row.frontier().possible_values())
                .map(|value| value.ty().identity()),
        );
        assert_exhausted_typed_rows(expected_intrinsics, |visitor| {
            service.visit_intrinsic_seed_pages_for_type_identities(
                TypedFactRequest::new(&intrinsic_identities),
                &cancellation,
                visitor,
            )
        });

        let mut expected_projections = typed
            .projections()
            .iter()
            .copied()
            .map(|row| SelectedTypedRow::new(owner, row))
            .collect::<Vec<_>>();
        expected_projections.sort_unstable_by_key(|row| row.natural_identity());
        let projection_references = reversed_unique(
            typed
                .projections()
                .iter()
                .map(LoweredBindingProjection::reference),
        );
        assert_exhausted_typed_rows(expected_projections.clone(), |visitor| {
            service.visit_binding_projection_pages_for_references(
                TypedFactRequest::new(&projection_references),
                &cancellation,
                visitor,
            )
        });
        let projection_outputs = reversed_unique(
            typed
                .projections()
                .iter()
                .map(LoweredBindingProjection::output_slot),
        );
        assert_exhausted_typed_rows(expected_projections, |visitor| {
            service.visit_binding_projection_pages_for_outputs(
                TypedFactRequest::new(&projection_outputs),
                &cancellation,
                visitor,
            )
        });

        let reference_nodes = lexical
            .semantics()
            .iter()
            .filter(|semantic| semantic.role() == LoweredSemanticRole::Reference)
            .map(|semantic| (semantic.semantic(), semantic.node()))
            .collect::<HashMap<_, _>>();
        let mut expected_routes = typed
            .qualified_routes()
            .iter()
            .copied()
            .map(|row| {
                SourceSelectedQualifiedRoute::new(owner, reference_nodes[&row.reference()], row)
            })
            .collect::<Vec<_>>();
        expected_routes.sort_unstable_by_key(|route| route.natural_identity());
        assert!(expected_routes.iter().all(|route| {
            route.fragment() == owner
                && route.reference_node() == reference_nodes[&route.row().reference()]
                && route.natural_identity()
                    == (
                        owner,
                        route.row().reference(),
                        route.row().precedence_ordinal(),
                    )
        }));
        let route_references = reversed_unique(
            typed
                .qualified_routes()
                .iter()
                .map(LoweredQualifiedSeededRoute::reference),
        );
        assert_exhausted_typed_rows(expected_routes.clone(), |visitor| {
            service.visit_qualified_route_pages_for_references(
                TypedFactRequest::new(&route_references),
                &cancellation,
                visitor,
            )
        });
        let route_slot_lookups = reversed_unique(
            typed
                .qualified_routes()
                .iter()
                .map(|row| QualifiedRouteSlotLookup::new(row.qualifier_slot(), row.lookup())),
        );
        assert_exhausted_typed_rows(expected_routes.clone(), |visitor| {
            service.visit_qualified_route_pages_for_slot_lookups(
                TypedFactRequest::new(&route_slot_lookups),
                &cancellation,
                visitor,
            )
        });
        let qualifier_slots = reversed_unique(
            typed
                .qualified_routes()
                .iter()
                .map(LoweredQualifiedSeededRoute::qualifier_slot),
        );
        assert_exhausted_typed_rows(expected_routes.clone(), |visitor| {
            service.visit_qualified_route_pages_for_qualifier_slots(
                TypedFactRequest::new(&qualifier_slots),
                &cancellation,
                visitor,
            )
        });
        let route_lookups = reversed_unique(
            typed
                .qualified_routes()
                .iter()
                .map(LoweredQualifiedSeededRoute::lookup),
        );
        assert_exhausted_typed_rows(expected_routes.clone(), |visitor| {
            service.visit_qualified_route_pages_for_lookups(
                TypedFactRequest::new(&route_lookups),
                &cancellation,
                visitor,
            )
        });
        let route_reasons = reversed_unique(
            typed
                .qualified_routes()
                .iter()
                .map(LoweredQualifiedSeededRoute::coarse_gap_reason),
        );
        assert_exhausted_typed_rows(expected_routes.clone(), |visitor| {
            service.visit_qualified_route_pages_for_gap_reasons(
                TypedFactRequest::new(&route_reasons),
                &cancellation,
                visitor,
            )
        });
        assert_exhausted_typed_rows(expected_routes, |visitor| {
            service.visit_qualified_route_inventory_pages(&cancellation, visitor)
        });

        let mut expected_declarations = typed
            .declaration_types()
            .iter()
            .copied()
            .map(|row| SelectedTypedRow::new(owner, row))
            .collect::<Vec<_>>();
        expected_declarations.sort_unstable_by_key(|row| row.natural_identity());
        let declaration_definitions = reversed_unique(
            typed
                .declaration_types()
                .iter()
                .map(LoweredDeclarationTypeProperty::definition),
        );
        assert_exhausted_typed_rows(expected_declarations.clone(), |visitor| {
            service.visit_declaration_type_pages_for_definitions(
                TypedFactRequest::new(&declaration_definitions),
                &cancellation,
                visitor,
            )
        });
        let declaration_slots = reversed_unique(
            typed
                .declaration_types()
                .iter()
                .map(LoweredDeclarationTypeProperty::slot),
        );
        assert_exhausted_typed_rows(expected_declarations, |visitor| {
            service.visit_declaration_type_pages_for_slots(
                TypedFactRequest::new(&declaration_slots),
                &cancellation,
                visitor,
            )
        });

        let mut expected_scopes = typed
            .member_scopes()
            .iter()
            .copied()
            .map(|row| SelectedTypedRow::new(owner, row))
            .collect::<Vec<_>>();
        expected_scopes.sort_unstable_by_key(|row| row.natural_identity());
        let scope_definitions = reversed_unique(
            typed
                .member_scopes()
                .iter()
                .map(LoweredMemberScopeProperty::definition),
        );
        assert_exhausted_typed_rows(expected_scopes.clone(), |visitor| {
            service.visit_member_scope_pages_for_definitions(
                TypedFactRequest::new(&scope_definitions),
                &cancellation,
                visitor,
            )
        });
        let scope_heads = reversed_unique(
            typed
                .member_scopes()
                .iter()
                .map(LoweredMemberScopeProperty::scope_head),
        );
        assert_exhausted_typed_rows(expected_scopes.clone(), |visitor| {
            service.visit_member_scope_pages_for_heads(
                TypedFactRequest::new(&scope_heads),
                &cancellation,
                visitor,
            )
        });
        assert_exhausted_typed_rows(expected_scopes, |visitor| {
            service.visit_member_scope_inventory_pages(&cancellation, visitor)
        });

        let mut expected_owners = typed
            .member_owners()
            .iter()
            .copied()
            .map(|row| SelectedTypedRow::new(owner, row))
            .collect::<Vec<_>>();
        expected_owners.sort_unstable_by_key(|row| row.natural_identity());
        let member_definitions = reversed_unique(
            typed
                .member_owners()
                .iter()
                .map(LoweredMemberOwnerProperty::definition),
        );
        assert_exhausted_typed_rows(expected_owners.clone(), |visitor| {
            service.visit_member_owner_pages_for_definitions(
                TypedFactRequest::new(&member_definitions),
                &cancellation,
                visitor,
            )
        });
        let owner_definitions = reversed_unique(
            typed
                .member_owners()
                .iter()
                .map(LoweredMemberOwnerProperty::owner_definition),
        );
        assert_exhausted_typed_rows(expected_owners, |visitor| {
            service.visit_member_owner_pages_for_owners(
                TypedFactRequest::new(&owner_definitions),
                &cancellation,
                visitor,
            )
        });

        let mut expected_construction = typed
            .construction_requirements()
            .iter()
            .copied()
            .map(|row| SelectedTypedRow::new(owner, row))
            .collect::<Vec<_>>();
        expected_construction.sort_unstable_by_key(|row| row.natural_identity());
        let construction_definitions = reversed_unique(
            typed
                .construction_requirements()
                .iter()
                .map(LoweredConstructionRequirementProperty::definition),
        );
        assert_exhausted_typed_rows(expected_construction, |visitor| {
            service.visit_construction_requirement_pages_for_definitions(
                TypedFactRequest::new(&construction_definitions),
                &cancellation,
                visitor,
            )
        });

        let mut expected_supertypes = typed
            .supertypes()
            .iter()
            .copied()
            .map(|row| SelectedTypedRow::new(owner, row))
            .collect::<Vec<_>>();
        expected_supertypes.sort_unstable_by_key(|row| row.natural_identity());
        let supertype_definitions = reversed_unique(
            typed
                .supertypes()
                .iter()
                .map(LoweredSupertypeProperty::definition),
        );
        assert_exhausted_typed_rows(expected_supertypes.clone(), |visitor| {
            service.visit_supertype_pages_for_definitions(
                TypedFactRequest::new(&supertype_definitions),
                &cancellation,
                visitor,
            )
        });
        let supertype_references = reversed_unique(
            typed
                .supertypes()
                .iter()
                .map(LoweredSupertypeProperty::reference),
        );
        assert_exhausted_typed_rows(expected_supertypes.clone(), |visitor| {
            service.visit_supertype_pages_for_references(
                TypedFactRequest::new(&supertype_references),
                &cancellation,
                visitor,
            )
        });
        let supertype_frontiers = reversed_unique(
            typed
                .supertypes()
                .iter()
                .map(LoweredSupertypeProperty::frontier),
        );
        assert_exhausted_typed_rows(expected_supertypes, |visitor| {
            service.visit_supertype_pages_for_frontiers(
                TypedFactRequest::new(&supertype_frontiers),
                &cancellation,
                visitor,
            )
        });

        let mut expected_property_gaps = typed
            .property_gaps()
            .iter()
            .copied()
            .map(|row| SelectedTypedRow::new(owner, row))
            .collect::<Vec<_>>();
        expected_property_gaps.sort_unstable_by_key(|row| row.natural_identity());
        let property_gap_definitions = reversed_unique(
            typed
                .property_gaps()
                .iter()
                .map(LoweredDefinitionPropertyGap::definition),
        );
        assert_exhausted_typed_rows(expected_property_gaps, |visitor| {
            service.visit_definition_property_gap_pages_for_definitions(
                TypedFactRequest::new(&property_gap_definitions),
                &cancellation,
                visitor,
            )
        });

        let mut expected_calls = typed
            .call_obligations()
            .iter()
            .cloned()
            .map(|row| SelectedTypedRow::new(owner, row))
            .collect::<Vec<_>>();
        expected_calls.sort_unstable_by_key(|row| row.natural_identity());
        let callees = reversed_unique(
            typed
                .call_obligations()
                .iter()
                .map(LoweredCallApplicabilityObligation::callee_reference),
        );
        assert_exhausted_typed_rows(expected_calls, |visitor| {
            service.visit_call_applicability_pages_for_callee_references(
                TypedFactRequest::new(&callees),
                &cancellation,
                visitor,
            )
        });

        let mut expected_signatures = typed
            .callable_signatures()
            .iter()
            .cloned()
            .map(|row| SelectedTypedRow::new(owner, row))
            .collect::<Vec<_>>();
        expected_signatures.sort_unstable_by_key(|row| row.natural_identity());
        let callable_definitions = reversed_unique(
            typed
                .callable_signatures()
                .iter()
                .map(LoweredCallableSignatureProperty::definition),
        );
        assert_exhausted_typed_rows(expected_signatures, |visitor| {
            service.visit_callable_signature_pages_for_definitions(
                TypedFactRequest::new(&callable_definitions),
                &cancellation,
                visitor,
            )
        });

        let mut expected_provenance = lexical
            .gaps()
            .iter()
            .map(|gap| {
                SelectedGapReasonProvenance::new(
                    owner,
                    gap.reason_semantic(),
                    gap.site(),
                    gap.origin(),
                )
            })
            .collect::<Vec<_>>();
        expected_provenance.sort_unstable_by_key(|row| row.natural_identity());
        expected_provenance.dedup_by_key(|row| row.natural_identity());
        let provenance_reasons = reversed_unique(
            expected_provenance
                .iter()
                .map(|provenance| provenance.reason()),
        );
        assert_exhausted_typed_rows(expected_provenance, |visitor| {
            service.visit_gap_reason_provenance_pages_for_reasons(
                TypedFactRequest::new(&provenance_reasons),
                &cancellation,
                visitor,
            )
        });
    }

    #[test]
    fn preloaded_typed_pager_obeys_empty_maximum_remainder_stop_and_cancellation_laws() {
        let fixture = java_fixture();
        let live = CancellationToken::new();
        let empty = Vec::<SemanticId>::new();
        let (rows, pages, outcome) = collect_typed_read(|visitor| {
            fixture.visit_typed_frontier_pages(TypedFactRequest::new(&empty), &live, visitor)
        });
        assert!(rows.is_empty());
        assert!(pages.is_empty());
        assert_eq!(outcome.terminal(), TypedFactReadTerminal::Exhausted);
        assert_eq!(outcome.evidence(), &ResolutionCompletion::Complete);

        let missing = (0..MAX_TYPED_FACT_REQUESTS_PER_BATCH)
            .map(|ordinal| {
                let bytes = ordinal.to_le_bytes();
                service_reason(b"typed-source-missing", &[&bytes])
            })
            .collect::<Vec<_>>();
        let (rows, pages, outcome) = collect_typed_read(|visitor| {
            fixture.visit_typed_frontier_pages(TypedFactRequest::new(&missing), &live, visitor)
        });
        assert!(rows.is_empty());
        assert!(pages.is_empty());
        assert_eq!(outcome.terminal(), TypedFactReadTerminal::Exhausted);

        let source_rows = (0_u16..257)
            .map(|ordinal| {
                let bytes = ordinal.to_le_bytes();
                (
                    ordinal,
                    service_reason(b"typed-source-page-reason", &[&bytes]),
                )
            })
            .collect::<Vec<_>>();
        let streams = [source_rows.as_slice()];
        let mut emitted = Vec::new();
        let mut page_sizes = Vec::new();
        let mut callback = |page: &[(u16, SemanticId)]| {
            page_sizes.push(page.len());
            emitted.extend_from_slice(page);
            Ok(true)
        };
        let mut visitor = TypedFactPageVisitor::new(&mut callback);
        let outcome = visit_preloaded_typed_pages(
            &streams,
            |row| row.0,
            |row, evidence, cancellation, work| {
                evidence.include_reason(
                    ResolutionIncompleteReason::UnsupportedSemantic(row.1),
                    cancellation,
                    work,
                )
            },
            |row, _| Some(*row),
            &live,
            &mut visitor,
        )
        .expect("preloaded pager is infallible");
        assert_eq!(emitted, source_rows);
        assert_eq!(page_sizes, [MAX_TYPED_FACT_ROWS_PER_PAGE, 1]);
        assert_eq!(outcome.terminal(), TypedFactReadTerminal::Exhausted);
        assert_eq!(outcome.evidence(), &ResolutionCompletion::Complete);

        let mut limited_count = 0_usize;
        let mut callback = |page: &[(u16, SemanticId)]| {
            limited_count += page.len();
            Ok(false)
        };
        let mut visitor = TypedFactPageVisitor::with_maximum_rows(&mut callback, 3);
        let outcome = visit_preloaded_typed_pages(
            &streams,
            |row| row.0,
            |row, evidence, cancellation, work| {
                evidence.include_reason(
                    ResolutionIncompleteReason::UnsupportedSemantic(row.1),
                    cancellation,
                    work,
                )
            },
            |row, _| Some(*row),
            &live,
            &mut visitor,
        )
        .expect("preloaded limited pager is infallible");
        assert_eq!(limited_count, 3);
        assert_eq!(outcome.terminal(), TypedFactReadTerminal::Stopped);
        assert_eq!(
            outcome.evidence(),
            &ResolutionCompletion::incomplete(
                source_rows[..3]
                    .iter()
                    .map(|row| ResolutionIncompleteReason::UnsupportedSemantic(row.1)),
            )
        );

        let emitted_prefix_evidence = ResolutionCompletion::incomplete(
            source_rows[..MAX_TYPED_FACT_ROWS_PER_PAGE]
                .iter()
                .map(|row| ResolutionIncompleteReason::UnsupportedSemantic(row.1)),
        );
        let mut callback_count = 0_usize;
        let mut clone_count = 0_usize;
        let mut callback = |_page: &[(u16, SemanticId)]| {
            callback_count += 1;
            Ok(false)
        };
        let mut visitor = TypedFactPageVisitor::new(&mut callback);
        let outcome = visit_preloaded_typed_pages(
            &streams,
            |row| row.0,
            |row, evidence, cancellation, work| {
                evidence.include_reason(
                    ResolutionIncompleteReason::UnsupportedSemantic(row.1),
                    cancellation,
                    work,
                )
            },
            |row, _| {
                clone_count += 1;
                Some(*row)
            },
            &live,
            &mut visitor,
        )
        .expect("preloaded pager is infallible");
        assert_eq!(callback_count, 1);
        assert_eq!(clone_count, MAX_TYPED_FACT_ROWS_PER_PAGE);
        assert_eq!(outcome.terminal(), TypedFactReadTerminal::Stopped);
        assert_eq!(outcome.evidence(), &emitted_prefix_evidence);

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let mut callback_count = 0_usize;
        let mut callback = |_page: &[(u16, SemanticId)]| {
            callback_count += 1;
            Ok(true)
        };
        let mut visitor = TypedFactPageVisitor::new(&mut callback);
        let outcome = visit_preloaded_typed_pages(
            &streams,
            |row| row.0,
            |row, evidence, cancellation, work| {
                evidence.include_reason(
                    ResolutionIncompleteReason::UnsupportedSemantic(row.1),
                    cancellation,
                    work,
                )
            },
            |row, _| Some(*row),
            &cancelled,
            &mut visitor,
        )
        .expect("preloaded pager is infallible");
        assert_eq!(callback_count, 0);
        assert_eq!(outcome.terminal(), TypedFactReadTerminal::Cancelled);
        assert_eq!(outcome.evidence(), &ResolutionCompletion::Complete);

        let cancelled = CancellationToken::new();
        let mut callback_count = 0_usize;
        let mut callback = |_page: &[(u16, SemanticId)]| {
            callback_count += 1;
            cancelled.cancel();
            Ok(false)
        };
        let mut visitor = TypedFactPageVisitor::new(&mut callback);
        let outcome = visit_preloaded_typed_pages(
            &streams,
            |row| row.0,
            |row, evidence, cancellation, work| {
                evidence.include_reason(
                    ResolutionIncompleteReason::UnsupportedSemantic(row.1),
                    cancellation,
                    work,
                )
            },
            |row, _| Some(*row),
            &cancelled,
            &mut visitor,
        )
        .expect("preloaded pager is infallible");
        let emitted_prefix_evidence = ResolutionCompletion::incomplete(
            source_rows[..MAX_TYPED_FACT_ROWS_PER_PAGE]
                .iter()
                .map(|row| ResolutionIncompleteReason::UnsupportedSemantic(row.1)),
        );
        assert_eq!(callback_count, 1);
        assert_eq!(outcome.terminal(), TypedFactReadTerminal::Cancelled);
        assert_eq!(outcome.evidence(), &emitted_prefix_evidence);
        assert!(!outcome.evidence().contains_reason(
            ResolutionIncompleteReason::UnsupportedSemantic(source_rows[256].1)
        ));
    }

    #[test]
    fn preloaded_reverse_inventory_returns_exact_live_and_decoded_prefix_evidence() {
        let mut service = java_fixture();
        let reasons = (0..(CANCELLATION_QUANTUM + 7))
            .map(|ordinal| {
                let bytes = ordinal.to_le_bytes();
                ResolutionIncompleteReason::UnsupportedSemantic(service_reason(
                    b"reverse-inventory-law",
                    &[&bytes],
                ))
            })
            .collect::<Vec<_>>();
        service.reverse_inventory_completion =
            ResolutionCompletion::Incomplete(reasons.clone().into_boxed_slice().into());

        let outcome = service
            .read_selected_reverse_inventory_completion(&CancellationToken::new())
            .expect("preloaded reverse inventory is infallible");
        assert_eq!(outcome.terminal(), TypedFactReadTerminal::Exhausted);
        assert_eq!(
            outcome.evidence(),
            &ResolutionCompletion::Incomplete(reasons.clone().into_boxed_slice().into())
        );

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let outcome = service
            .read_selected_reverse_inventory_completion(&cancelled)
            .expect("preloaded reverse inventory is infallible");
        assert_eq!(outcome.terminal(), TypedFactReadTerminal::Cancelled);
        assert_eq!(outcome.evidence(), &ResolutionCompletion::Complete);

        let cancellation = CancellationToken::cancel_after_checks_for_test(2);
        let outcome = service
            .read_selected_reverse_inventory_completion(&cancellation)
            .expect("preloaded reverse inventory is infallible");
        assert_eq!(outcome.terminal(), TypedFactReadTerminal::Cancelled);
        assert_eq!(
            outcome.evidence(),
            &ResolutionCompletion::Incomplete(
                reasons[..CANCELLATION_QUANTUM - 1]
                    .to_vec()
                    .into_boxed_slice()
                    .into()
            )
        );
    }

    #[test]
    fn preloaded_variable_child_rows_clone_live_and_cancel_without_partial_parents() {
        let arguments = (0_u32..300)
            .map(|ordinal| {
                let bytes = ordinal.to_le_bytes();
                service_reason(b"call-argument", &[&bytes])
            })
            .collect::<Vec<_>>();
        let completion = ResolutionCompletion::incomplete((0_u32..300).map(|ordinal| {
            let bytes = ordinal.to_le_bytes();
            ResolutionIncompleteReason::UnsupportedSemantic(service_reason(
                b"variable-child-reason",
                &[&bytes],
            ))
        }));
        let call = LoweredCallApplicabilityObligation::new(
            SemanticId::hash_bytes(b"variable-child-call"),
            SemanticId::hash_bytes(b"variable-child-callee"),
            None,
            SemanticId::hash_bytes(b"variable-child-result"),
            arguments,
            Vec::new(),
            0,
            SemanticId::hash_bytes(b"variable-child-applicability"),
            completion.clone(),
        );
        assert_eq!(
            clone_call_obligation_with_poll(&call, &mut || false),
            Some(call.clone())
        );
        let mut call_polls = 0_usize;
        assert!(
            clone_call_obligation_with_poll(&call, &mut || {
                call_polls += 1;
                call_polls == 17
            })
            .is_none()
        );
        assert_eq!(call_polls, 17);

        let values = (0_u32..300)
            .map(|ordinal| {
                let bytes = ordinal.to_le_bytes();
                ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                    service_reason(b"intrinsic-child-type", &[&bytes]),
                    0,
                ))
            })
            .collect::<Vec<_>>();
        let seed = LoweredIntrinsicSeed::new(
            IntrinsicTypeKind::Primitive,
            TypedFrontierState::new(
                SemanticId::hash_bytes(b"variable-child-intrinsic"),
                values,
                completion,
            ),
        );
        assert_eq!(
            clone_intrinsic_seed_with_poll(&seed, &mut || false),
            Some(seed.clone())
        );
        let mut seed_polls = 0_usize;
        assert!(
            clone_intrinsic_seed_with_poll(&seed, &mut || {
                seed_polls += 1;
                seed_polls == 17
            })
            .is_none()
        );
        assert_eq!(seed_polls, 17);
    }

    #[test]
    fn selected_inventory_includes_empty_fragments_and_visibility_rows_are_exact() {
        let owner = fragment();
        let empty_owner = BindingFragmentId::hash_bytes(b"empty-selected-fragment");
        let facts = all_typed_source_facts();
        let typed = lower_typed_resolution_facts(owner, Language::Java, &facts);
        let empty = FileResolutionFacts::default();
        let source = PreloadedFactSource::from_lowered_fragments(
            [
                lower_file_resolution_facts(owner, Language::Java, &facts),
                lower_file_resolution_facts(empty_owner, Language::Java, &empty),
            ],
            [
                typed.clone(),
                lower_typed_resolution_facts(empty_owner, Language::Java, &empty),
            ],
        );
        let cancellation = CancellationToken::new();
        let mut expected = vec![owner, empty_owner];
        expected.sort_unstable();
        assert_exhausted_typed_rows(expected, |visitor| {
            source.visit_selected_fragment_pages(&cancellation, visitor)
        });
        let mut expected = typed
            .declaration_visibilities()
            .iter()
            .copied()
            .map(|row| SelectedTypedRow::new(owner, row))
            .collect::<Vec<_>>();
        assert!(!expected.is_empty());
        expected.sort_unstable_by_key(|row| row.natural_identity());
        let mut definitions = reversed_unique(expected.iter().map(|row| row.row().definition()));
        definitions.push(SemanticId::hash_bytes(b"missing-visibility-definition"));
        assert_exhausted_typed_rows(expected, |visitor| {
            source.visit_declaration_visibility_pages_for_definitions(
                TypedFactRequest::new(&definitions),
                &cancellation,
                visitor,
            )
        });
    }

    #[test]
    #[should_panic(expected = "lexical and typed preload selections must name the same fragments")]
    fn constructor_rejects_mismatched_fragment_sets() {
        let empty = FileResolutionFacts::default();
        PreloadedFactSource::from_lowered_fragments(
            [],
            [lower_typed_resolution_facts(
                fragment(),
                Language::Rust,
                &empty,
            )],
        );
    }

    fn member_scope_fragment(
        owner: BindingFragmentId,
        head: BindingNodeId,
    ) -> LoweredTypedFragment {
        LoweredTypedFragment::new(
            owner,
            Language::Rust,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![LoweredMemberScopeProperty::new(
                SemanticId::hash_bytes(b"member-definition"),
                head,
            )],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        )
    }

    #[test]
    #[should_panic(expected = "must name a Scope node in its exact selected fragment")]
    fn constructor_rejects_member_scope_with_wrong_node_kind() {
        let lexical = lower_file_resolution_facts(fragment(), Language::Java, &java_chain_facts());
        let head = lexical
            .nodes()
            .iter()
            .find(|(_, kind)| *kind != BindingNodeKind::Scope)
            .expect("the fixture includes non-scope nodes")
            .0;
        let typed = member_scope_fragment(fragment(), head);
        PreloadedFactSource::from_lowered_fragments([lexical], [typed]);
    }

    #[test]
    #[should_panic(expected = "must name a Scope node in its exact selected fragment")]
    fn constructor_rejects_member_scope_owned_by_another_fragment() {
        let lexical = lower_file_resolution_facts(fragment(), Language::Java, &java_chain_facts());
        let head = lexical
            .nodes()
            .iter()
            .find(|(_, kind)| *kind == BindingNodeKind::Scope)
            .expect("the fixture includes scope nodes")
            .0;
        let other = BindingFragmentId::hash_bytes(b"other-scope-owner");
        let typed = member_scope_fragment(other, head);
        PreloadedFactSource::from_lowered_fragments([lexical], [typed]);
    }

    fn qualified_fragment(
        owner: BindingFragmentId,
        source: &LoweredTypedFragment,
        routes: Vec<LoweredQualifiedSeededRoute>,
    ) -> LoweredTypedFragment {
        LoweredTypedFragment::new(
            owner,
            Language::Rust,
            source.frontiers().to_vec(),
            vec![],
            vec![],
            source.projections().to_vec(),
            routes,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        )
    }

    #[test]
    #[should_panic(expected = "crosses fragment ownership")]
    fn constructor_rejects_qualified_reference_owned_by_another_fragment() {
        let facts = java_chain_facts();
        let lexical = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let typed = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
        assert!(!typed.qualified_routes().is_empty());
        let other = BindingFragmentId::hash_bytes(b"other-reference-owner");
        let wrong_owner = qualified_fragment(other, &typed, typed.qualified_routes().to_vec());
        PreloadedFactSource::from_lowered_fragments([lexical], [wrong_owner]);
    }

    #[test]
    fn qualified_gap_filter_requires_exact_fragment_reference_and_reason() {
        let facts = java_chain_facts();
        let lexical = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let typed = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
        let route = typed.qualified_routes()[0];
        let source = PreloadedFactSource::from_lowered_fragments([lexical], [typed]);
        assert!(source.typed.owns_qualified_gap(
            fragment(),
            route.reference(),
            route.coarse_gap_reason()
        ));
        assert!(!source.typed.owns_qualified_gap(
            BindingFragmentId::hash_bytes(b"foreign-gap-owner"),
            route.reference(),
            route.coarse_gap_reason()
        ));
        assert!(!source.typed.owns_qualified_gap(
            fragment(),
            SemanticId::hash_bytes(b"foreign-reference"),
            route.coarse_gap_reason()
        ));
        assert!(!source.typed.owns_qualified_gap(
            fragment(),
            route.reference(),
            SemanticId::hash_bytes(b"foreign-gap")
        ));
        let answer = BatchResolutionEngine::new(&source)
            .resolve_reference(
                ResolutionQuery::new(route.reference()),
                &CancellationToken::new(),
            )
            .unwrap();
        assert!(
            matches!(answer.completion(), ResolutionCompletion::Incomplete(_)),
            "typed route ownership must not complete an unseeded lexical lookup"
        );
    }

    #[test]
    fn exact_raw_evidence_preserves_first_operand_and_canonicalizes_union() {
        let a = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(b"a"));
        let b = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(b"b"));
        let raw = ResolutionCompletion::Incomplete(vec![b, a, b].into_boxed_slice().into());
        let live = CancellationToken::new();
        let mut work = 0;
        let mut cancelled = false;
        let mut first = ExactPolledCompletionAccumulator::default();
        first.include(&raw, &live, &mut work, &mut cancelled);
        assert_eq!(first.finish_semantic(&live, &mut work, &mut cancelled), raw);
        assert!(!cancelled);
        let mut union = ExactPolledCompletionAccumulator::default();
        union.include(&raw, &live, &mut work, &mut cancelled);
        union.include(&raw, &live, &mut work, &mut cancelled);
        assert_eq!(
            union.finish_semantic(&live, &mut work, &mut cancelled),
            ResolutionCompletion::incomplete([a, b])
        );
        live.cancel();
        let mut stopped = ExactPolledCompletionAccumulator::default();
        stopped.include(&raw, &live, &mut work, &mut cancelled);
        assert_eq!(
            stopped.finish_semantic(&live, &mut work, &mut cancelled),
            raw
        );
        assert!(
            cancelled,
            "cancellation is observed without dropping decoded evidence"
        );
    }

    #[test]
    #[should_panic(
        expected = "one typed-owned qualified reason must name one fragment/reference owner"
    )]
    fn constructor_rejects_qualified_gap_reason_shared_between_references() {
        let facts = java_chain_facts();
        let other = BindingFragmentId::hash_bytes(b"other-qualified-gap-fragment");
        let lexical = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let other_lexical = lower_file_resolution_facts(other, Language::Java, &facts);
        let typed = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
        let other_typed = lower_typed_resolution_facts(other, Language::Java, &facts);
        assert_ne!(fragment(), other);
        let original_nodes = lexical
            .nodes()
            .iter()
            .map(|(node, _)| *node)
            .collect::<HashSet<_>>();
        assert!(
            other_lexical
                .nodes()
                .iter()
                .all(|(node, _)| !original_nodes.contains(node))
        );
        let original_references = typed
            .qualified_routes()
            .iter()
            .map(|row| row.reference())
            .collect::<HashSet<_>>();
        assert!(
            other_typed
                .qualified_routes()
                .iter()
                .all(|row| !original_references.contains(&row.reference()))
        );
        let reason = typed.qualified_routes()[0].coarse_gap_reason();
        let other_reference = other_typed.qualified_routes()[0].reference();
        let routes = other_typed
            .qualified_routes()
            .iter()
            .map(|row| {
                LoweredQualifiedSeededRoute::new(
                    row.reference(),
                    row.qualifier_slot(),
                    row.lookup(),
                    row.namespace(),
                    row.precedence_ordinal(),
                    row.projection_output_slot(),
                    row.projection_kind(),
                    if row.reference() == other_reference {
                        reason
                    } else {
                        row.coarse_gap_reason()
                    },
                )
            })
            .collect();
        let conflicting = qualified_fragment(other, &other_typed, routes);
        assert_eq!(conflicting.fragment(), other);
        assert!(
            conflicting
                .qualified_routes()
                .iter()
                .all(|row| (row.coarse_gap_reason() == reason)
                    == (row.reference() == other_reference))
        );
        PreloadedFactSource::from_lowered_fragments([lexical, other_lexical], [typed, conflicting]);
    }

    #[test]
    fn normalized_root_export_registers_and_hydrates_universal_root_candidate() {
        let mut facts = java_chain_facts();
        facts.root_exports.push(ResolutionRootExportFact {
            root_scope: ResolutionScopeId::new(0),
            declaration: ResolutionSiteId::new(0),
            namespace: ResolutionNamespace::Type,
        });
        let lexical = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let typed = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
        let (path, expected) = lexical
            .paths()
            .iter()
            .find(|(_, path)| path.start().node() == BindingNodeId::universal_root())
            .map(|(identity, path)| (*identity, path.clone()))
            .expect("root export emits a root path");
        let source = PreloadedFactSource::from_lowered_fragments([lexical], [typed]);
        let live = CancellationToken::new();
        let root = BindingNodeId::universal_root();
        assert_eq!(
            source.classify_endpoint_nodes(&[root], &live).unwrap(),
            [BatchEndpointClassification::new(root, None, None)]
        );
        let candidate = CandidatePathIdentity::new(fragment(), path);
        let matches = source
            .match_forward_candidates(
                &[BatchCandidateRequest::new(0, expected.start().clone())],
                &live,
            )
            .unwrap();
        assert!(
            matches
                .matches()
                .iter()
                .any(|row| row.candidate() == candidate && row.request_ordinal() == 0)
        );
        assert_eq!(
            source.hydrate_candidate_paths(&[candidate], &live).unwrap(),
            [(candidate, expected)]
        );
    }

    #[test]
    fn selected_inventory_stop_and_cancellation_are_not_exhaustion() {
        let source = java_fixture();
        let live = CancellationToken::new();
        let mut count = 0;
        let mut callback = |page: &[BindingFragmentId]| {
            count += page.len();
            Ok(false)
        };
        let mut visitor = TypedFactPageVisitor::new(&mut callback);
        let outcome = source
            .visit_selected_fragment_pages(&live, &mut visitor)
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(outcome.terminal(), TypedFactReadTerminal::Stopped);
        assert_eq!(outcome.evidence(), &ResolutionCompletion::Complete);
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let (rows, pages, outcome) =
            collect_typed_read(|visitor| source.visit_selected_fragment_pages(&cancelled, visitor));
        assert!(rows.is_empty() && pages.is_empty());
        assert_eq!(outcome.terminal(), TypedFactReadTerminal::Cancelled);
        let mut callback = |_: &[BindingFragmentId]| {
            live.cancel();
            Ok(false)
        };
        let mut visitor = TypedFactPageVisitor::new(&mut callback);
        assert_eq!(
            source
                .visit_selected_fragment_pages(&live, &mut visitor)
                .unwrap()
                .terminal(),
            TypedFactReadTerminal::Cancelled
        );
    }

    fn retained_reverse_inventory_gap_fixture() -> (
        PreloadedFactSource,
        BindingFragmentId,
        SemanticId,
        SemanticId,
    ) {
        let owner = fragment();
        let facts = all_typed_source_facts();
        let lexical = lower_file_resolution_facts(owner, Language::Java, &facts);
        let (gap_id, reason) = lexical
            .gaps()
            .iter()
            .find(|gap| {
                gap.origin() != LoweringGapOrigin::QualifiedReference
                    && gap.frontier()
                        == (LoweringCoverageFrontier::CandidateInventory {
                            direction: LoweredCandidateDirection::Reverse,
                        })
            })
            .map(|gap| (gap.id(), gap.reason_semantic()))
            .expect("the typed Java fixture retains one raw reverse inventory gap");
        let typed = lower_typed_resolution_facts(owner, Language::Java, &facts);
        (
            PreloadedFactSource::from_lowered_fragments([lexical], [typed]),
            owner,
            gap_id,
            reason,
        )
    }

    #[test]
    fn empty_reverse_gap_plan_delegates_exactly_through_compatibility_source() {
        let (mut service, _, _, reason) = retained_reverse_inventory_gap_fixture();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut raw_callback_count = 0_usize;
        let raw = BatchResolutionFragmentSource::visit_reverse_candidate_match_pages(
            &service,
            &[],
            &cancellation,
            &mut |_| {
                raw_callback_count += 1;
                Ok(true)
            },
        )
        .expect("the compatibility source returns raw cancellation evidence");
        let mut empty = ReverseCandidateGapExclusionPlan::default();
        let mut filtered_callback_count = 0_usize;
        let delegated =
            BatchResolutionFragmentSource::visit_reverse_candidate_match_pages_with_gap_exclusions(
                &mut service,
                &[],
                &mut empty,
                &cancellation,
                &mut |_| {
                    filtered_callback_count += 1;
                    Ok(true)
                },
            )
            .expect("an empty plan delegates through the compatibility default");

        assert_eq!(delegated, raw);
        assert_eq!(raw_callback_count, 0);
        assert_eq!(filtered_callback_count, 0);
        assert!(
            delegated
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(reason)),
            "delegation must retain raw semantic evidence even for an already-cancelled token"
        );
    }

    #[test]
    fn flattened_preload_reverse_gap_rejects_same_id_under_wrong_fragment() {
        let (mut service, owner, gap_id, _) = retained_reverse_inventory_gap_fixture();
        let wrong_owner = BindingFragmentId::hash_bytes(b"wrong-flattened-reverse-gap-owner");
        assert_ne!(wrong_owner, owner);

        let mut exact = ReverseCandidateGapExclusionPlan::new([ReverseCandidateGapIdentity::new(
            owner, gap_id,
        )]);
        BatchResolutionFragmentSource::visit_reverse_candidate_match_pages_with_gap_exclusions(
            &mut service.source,
            &[],
            &mut exact,
            &CancellationToken::new(),
            &mut |_| panic!("an empty reverse request set cannot emit a callback"),
        )
        .expect("flattening retains the exact owner with its reverse gap");

        let mut wrong = ReverseCandidateGapExclusionPlan::new([ReverseCandidateGapIdentity::new(
            wrong_owner,
            gap_id,
        )]);
        let mut callback_count = 0_usize;
        let error =
            BatchResolutionFragmentSource::visit_reverse_candidate_match_pages_with_gap_exclusions(
                &mut service.source,
                &[],
                &mut wrong,
                &CancellationToken::new(),
                &mut |_| {
                    callback_count += 1;
                    Ok(true)
                },
            )
            .expect_err("the same bare gap id under a different fragment must fail closed");
        assert!(error.to_string().contains("no exact gap"));
        assert_eq!(callback_count, 0);
    }
}
