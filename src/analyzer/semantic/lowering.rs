//! Shared emission mechanics for language-owned semantic lowerers.
//!
//! This module deliberately knows nothing about tree-sitter node kinds or
//! language syntax. Adapters choose source anchors, evaluation order, control
//! topology, and uncertainty; the session owns dense IDs, exact provenance,
//! common call rows, and batch-level budget/cancellation semantics.

use crate::hash::HashMap;

use super::cfg::{ProcedureCfgBuilder, ScopeBinding, ScopeFrameId};
use super::{
    AllocationId, AllocationKind, AllocationSite, CallContinuationKind, CallSiteId,
    CallableTargetResolution, CancellationToken, CaptureBinding, CaptureId, CaptureMode,
    CaptureSource, ControlContinuation, ControlEdge, ControlEdgeKind, Evidence,
    EvidenceCompleteness, EvidenceId, MemoryLocation, MemoryLocationId, MemoryLocationKind,
    ProcedureId, ProcedureSemanticsParts, ProgramPointId, ProofStatus, SemanticBudget,
    SemanticBudgetExceeded, SemanticCallArgument, SemanticCallSite, SemanticCapability,
    SemanticEffect, SemanticEvent, SemanticGap, SemanticGapId, SemanticGapImpacts, SemanticGapKind,
    SemanticGapSubject, SemanticLocator, SemanticOutcome, SemanticProviderError, SemanticRole,
    SemanticValue, SemanticValueKind, SemanticWork, SourceAnchor, SourceMapping, SourceMappingId,
    SourceMappingKind, ValueId,
};

/// Common operational failures produced while lowering one procedure.
#[derive(Debug)]
pub(crate) enum ProcedureLoweringError {
    Cancelled(Box<SemanticWork>),
    Budget(SemanticBudgetExceeded, Box<SemanticWork>),
    Invalid(String),
}

impl From<SemanticBudgetExceeded> for ProcedureLoweringError {
    fn from(error: SemanticBudgetExceeded) -> Self {
        Self::Budget(error, Box::default())
    }
}

pub(crate) fn sum_lowering_work(left: SemanticWork, right: SemanticWork) -> SemanticWork {
    left.checked_add(right)
        .unwrap_or_else(|| SemanticWork::uniform(usize::MAX))
}

/// Lower an adapter-owned sequence of procedure specs with one consistent
/// staging, cancellation, and error-to-outcome policy.
pub(crate) fn lower_procedure_batch<I, F>(
    items: I,
    initial_work: SemanticWork,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
    mut lower: F,
) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError>
where
    I: IntoIterator,
    F: FnMut(
        I::Item,
        &SemanticBudget,
        &CancellationToken,
    ) -> Result<(ProcedureSemanticsParts, SemanticWork), ProcedureLoweringError>,
{
    let iterator = items.into_iter();
    let mut procedures = Vec::with_capacity(iterator.size_hint().0);
    let mut observed = initial_work;

    for item in iterator {
        if cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: observed,
            });
        }
        let mut staged_budget = budget.clone();
        if let Err(exceeded) = staged_budget.charge(observed) {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work: observed,
            });
        }
        match lower(item, &staged_budget, cancellation) {
            Ok((parts, work)) => {
                let candidate = sum_lowering_work(observed, work);
                if let Err(exceeded) = budget.check(candidate) {
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work: candidate,
                    });
                }
                observed = candidate;
                procedures.push(parts);
            }
            Err(ProcedureLoweringError::Cancelled(work)) => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: sum_lowering_work(observed, *work),
                });
            }
            Err(ProcedureLoweringError::Budget(exceeded, work)) => {
                let work = sum_lowering_work(observed, *work);
                let exceeded = budget.check(work).err().unwrap_or(exceeded);
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                });
            }
            Err(ProcedureLoweringError::Invalid(detail)) => {
                return Err(SemanticProviderError::internal(detail));
            }
        }
    }

    Ok(SemanticOutcome::Complete {
        value: procedures,
        work: observed,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PointMetadata {
    pub(crate) source: SourceMappingId,
    pub(crate) evidence: EvidenceId,
}

/// Adapter-supplied values needed to publish one ordinary call row and its
/// matched continuation events. Syntax evaluation and control edges remain
/// adapter-owned.
pub(crate) struct CallSiteScaffold {
    pub(crate) point: ProgramPointId,
    pub(crate) callee: ValueId,
    pub(crate) receiver: Option<ValueId>,
    pub(crate) arguments: Box<[SemanticCallArgument]>,
    pub(crate) result: Option<ValueId>,
    pub(crate) thrown: Option<ValueId>,
    pub(crate) declared_targets: CallableTargetResolution,
    pub(crate) normal_continuation: ProgramPointId,
    pub(crate) exceptional_continuation: ProgramPointId,
}

pub(crate) struct ProcedureLoweringStart<'a> {
    pub(crate) builder: ProcedureCfgBuilder,
    pub(crate) session: ProcedureLoweringSession<'a>,
    pub(crate) entry: ProgramPointId,
    pub(crate) normal_exit: ProgramPointId,
    pub(crate) exceptional_exit: ProgramPointId,
    pub(crate) function_scope: ScopeFrameId,
}

/// Source-anchor-aware emission state shared by every language adapter.
pub(crate) struct ProcedureLoweringSession<'a> {
    locator: SemanticLocator,
    point_metadata: Vec<PointMetadata>,
    next_source: usize,
    next_evidence: usize,
    next_value: usize,
    next_allocation: usize,
    next_memory_location: usize,
    next_capture: usize,
    next_call_site: usize,
    next_gap: usize,
    source_occurrences: HashMap<(usize, usize), u32>,
    cancellation: &'a CancellationToken,
}

impl<'a> ProcedureLoweringSession<'a> {
    /// Seed the exact procedure provenance, entry/exit points, and function
    /// completion scope used by every production adapter.
    pub(crate) fn start(
        parts: ProcedureSemanticsParts,
        budget: &SemanticBudget,
        cancellation: &'a CancellationToken,
    ) -> Result<ProcedureLoweringStart<'a>, SemanticBudgetExceeded> {
        Self::start_with_function_throw_boundary(parts, budget, cancellation, false)
            .map(|(start, _)| start)
    }

    /// Seed ordinary boundaries while optionally routing function-level throws
    /// to a distinct, adapter-owned terminal point. This preserves the common
    /// setup for languages whose procedure contract has a second exceptional
    /// terminal, such as unconditional C++ `noexcept` termination.
    pub(crate) fn start_with_function_throw_boundary(
        mut parts: ProcedureSemanticsParts,
        budget: &SemanticBudget,
        cancellation: &'a CancellationToken,
        separate_throw_boundary: bool,
    ) -> Result<(ProcedureLoweringStart<'a>, Option<ProgramPointId>), SemanticBudgetExceeded> {
        assert!(
            parts.source_mappings.is_empty() && parts.evidence_rows.is_empty(),
            "procedure lowering session requires fresh provenance tables"
        );
        assert_eq!(parts.source.index(), 0, "base source mapping must be dense");
        assert_eq!(parts.evidence.index(), 0, "base evidence row must be dense");

        let locator = parts.locator.clone();
        let base_source = parts.source;
        let base_evidence = parts.evidence;
        parts.source_mappings.push(SourceMapping {
            id: base_source,
            locator: locator.clone(),
            kind: SourceMappingKind::Exact,
        });
        parts.evidence_rows.push(Evidence {
            id: base_evidence,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            sources: Box::new([base_source]),
        });

        let mut builder = ProcedureCfgBuilder::new(parts, budget)?;
        let entry = builder.add_point(
            vec![SemanticEvent::new(
                SemanticEffect::Entry,
                base_source,
                base_evidence,
            )],
            base_source,
            base_evidence,
        )?;
        let normal_exit = builder.add_point(
            vec![SemanticEvent::new(
                SemanticEffect::NormalExit,
                base_source,
                base_evidence,
            )],
            base_source,
            base_evidence,
        )?;
        let exceptional_exit = builder.add_point(
            vec![SemanticEvent::new(
                SemanticEffect::ExceptionalExit,
                base_source,
                base_evidence,
            )],
            base_source,
            base_evidence,
        )?;
        let separate_throw_target = separate_throw_boundary
            .then(|| builder.add_point(Vec::new(), base_source, base_evidence))
            .transpose()?;
        let function_scope = builder.push_scope(
            None,
            ScopeBinding::Function {
                return_target: normal_exit,
                throw_target: separate_throw_target.unwrap_or(exceptional_exit),
            },
        );
        let metadata = PointMetadata {
            source: base_source,
            evidence: base_evidence,
        };
        let session = Self {
            locator,
            point_metadata: vec![metadata; 3 + usize::from(separate_throw_target.is_some())],
            next_source: 1,
            next_evidence: 1,
            next_value: 0,
            next_allocation: 0,
            next_memory_location: 0,
            next_capture: 0,
            next_call_site: 0,
            next_gap: 0,
            source_occurrences: HashMap::default(),
            cancellation,
        };
        Ok((
            ProcedureLoweringStart {
                builder,
                session,
                entry,
                normal_exit,
                exceptional_exit,
                function_scope,
            },
            separate_throw_target,
        ))
    }

    pub(crate) const fn cancellation(&self) -> &'a CancellationToken {
        self.cancellation
    }

    pub(crate) const fn locator(&self) -> &SemanticLocator {
        &self.locator
    }

    /// Return the next deterministic occurrence for an adapter-selected byte
    /// span. The adapter remains responsible for constructing the anchor.
    pub(crate) fn next_source_occurrence(&mut self, start: usize, end: usize) -> u32 {
        let occurrence = self.source_occurrences.entry((start, end)).or_default();
        let current = *occurrence;
        *occurrence = occurrence
            .checked_add(1)
            .expect("one source span cannot have more than u32::MAX semantic occurrences");
        current
    }

    pub(crate) fn add_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        anchor: SourceAnchor,
        kind: SourceMappingKind,
    ) -> Result<PointMetadata, ProcedureLoweringError> {
        let source = SourceMappingId::try_from_index(self.next_source)
            .map_err(|_| ProcedureLoweringError::Invalid("too many source mappings".into()))?;
        let evidence = EvidenceId::try_from_index(self.next_evidence)
            .map_err(|_| ProcedureLoweringError::Invalid("too many evidence rows".into()))?;
        let locator = SemanticLocator::new(
            self.locator.mount(),
            self.locator.path().clone(),
            self.locator.language(),
            self.locator.declaration().clone(),
            SemanticRole::ProgramPoint,
            anchor,
        );
        builder.add_source_mapping(SourceMapping {
            id: source,
            locator,
            kind,
        })?;
        builder.add_evidence(Evidence {
            id: evidence,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            sources: Box::new([source]),
        })?;
        self.next_source += 1;
        self.next_evidence += 1;
        Ok(PointMetadata { source, evidence })
    }

    pub(crate) fn add_point(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        metadata: PointMetadata,
        effects: Vec<SemanticEffect>,
    ) -> Result<ProgramPointId, ProcedureLoweringError> {
        let events = effects
            .into_iter()
            .map(|effect| SemanticEvent::new(effect, metadata.source, metadata.evidence))
            .collect();
        let point = builder.add_point(events, metadata.source, metadata.evidence)?;
        self.register_point(point, metadata, "program-point allocation is not dense")?;
        Ok(point)
    }

    pub(crate) fn register_point(
        &mut self,
        point: ProgramPointId,
        metadata: PointMetadata,
        invalid_detail: &'static str,
    ) -> Result<(), ProcedureLoweringError> {
        if point.index() != self.point_metadata.len() {
            return Err(ProcedureLoweringError::Invalid(invalid_detail.into()));
        }
        self.point_metadata.push(metadata);
        Ok(())
    }

    pub(crate) fn metadata(
        &self,
        point: ProgramPointId,
    ) -> Result<PointMetadata, ProcedureLoweringError> {
        self.point_metadata
            .get(point.index())
            .copied()
            .ok_or_else(|| {
                ProcedureLoweringError::Invalid(format!(
                    "missing metadata for program point {point}"
                ))
            })
    }

    pub(crate) fn add_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, ProcedureLoweringError> {
        let metadata = self.metadata(point)?;
        self.add_value_with_metadata(builder, metadata, kind)
    }

    pub(crate) fn add_value_with_metadata(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        metadata: PointMetadata,
        kind: SemanticValueKind,
    ) -> Result<ValueId, ProcedureLoweringError> {
        let id = ValueId::try_from_index(self.next_value)
            .map_err(|_| ProcedureLoweringError::Invalid("too many semantic values".into()))?;
        builder.add_value(SemanticValue {
            id,
            kind,
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_value += 1;
        Ok(id)
    }

    pub(crate) fn add_allocation(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        result: ValueId,
        kind: AllocationKind,
    ) -> Result<AllocationId, ProcedureLoweringError> {
        let metadata = self.metadata(point)?;
        let id = AllocationId::try_from_index(self.next_allocation)
            .map_err(|_| ProcedureLoweringError::Invalid("too many allocations".into()))?;
        builder.add_allocation(AllocationSite {
            id,
            point,
            result,
            kind,
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_allocation += 1;
        self.append_effect(
            builder,
            point,
            SemanticEffect::Allocation { allocation: id },
        )?;
        Ok(id)
    }

    pub(crate) fn add_memory_location(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: MemoryLocationKind,
    ) -> Result<MemoryLocationId, ProcedureLoweringError> {
        let metadata = self.metadata(point)?;
        let id = MemoryLocationId::try_from_index(self.next_memory_location)
            .map_err(|_| ProcedureLoweringError::Invalid("too many memory locations".into()))?;
        builder.add_memory_location(MemoryLocation {
            id,
            kind,
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_memory_location += 1;
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_capture(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        callable: ValueId,
        target: ProcedureId,
        environment: AllocationId,
        captured: CaptureSource,
        destination: MemoryLocationId,
        mode: CaptureMode,
    ) -> Result<CaptureId, ProcedureLoweringError> {
        let metadata = self.metadata(point)?;
        let id = CaptureId::try_from_index(self.next_capture)
            .map_err(|_| ProcedureLoweringError::Invalid("too many captures".into()))?;
        builder.add_capture(CaptureBinding {
            id,
            point,
            callable,
            target,
            environment,
            captured,
            destination,
            mode,
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_capture += 1;
        self.append_effect(builder, point, SemanticEffect::CaptureBind { capture: id })?;
        Ok(id)
    }

    pub(crate) fn append_effect(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        effect: SemanticEffect,
    ) -> Result<(), ProcedureLoweringError> {
        let metadata = self.metadata(point)?;
        builder.append_event(
            point,
            SemanticEvent::new(effect, metadata.source, metadata.evidence),
        )?;
        Ok(())
    }

    pub(crate) fn add_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
        kind: SemanticGapKind,
        detail: impl Into<Box<str>>,
    ) -> Result<SemanticGapId, ProcedureLoweringError> {
        self.add_gap_with_impacts(
            builder,
            point,
            subject,
            capability,
            SemanticGapImpacts::for_gap(capability, subject),
            kind,
            detail,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_gap_with_impacts(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
        impacts: SemanticGapImpacts,
        kind: SemanticGapKind,
        detail: impl Into<Box<str>>,
    ) -> Result<SemanticGapId, ProcedureLoweringError> {
        let metadata = self.metadata(point)?;
        let id = SemanticGapId::try_from_index(self.next_gap)
            .map_err(|_| ProcedureLoweringError::Invalid("too many semantic gaps".into()))?;
        builder.add_gap(SemanticGap {
            id,
            point,
            subject,
            capability,
            impacts,
            kind,
            budget: None,
            detail: detail.into(),
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_gap += 1;
        self.append_effect(builder, point, SemanticEffect::Gap { gap: id })?;
        Ok(id)
    }

    pub(crate) fn add_edge(
        &self,
        builder: &mut ProcedureCfgBuilder,
        source_point: ProgramPointId,
        target_point: ProgramPointId,
        kind: ControlEdgeKind,
    ) -> Result<(), ProcedureLoweringError> {
        let metadata = self.metadata(source_point)?;
        builder.add_edge(ControlEdge {
            source_point,
            target_point,
            kind,
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        Ok(())
    }

    pub(crate) fn add_call_site(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        call: CallSiteScaffold,
    ) -> Result<CallSiteId, ProcedureLoweringError> {
        let metadata = self.metadata(call.point)?;
        let id = CallSiteId::try_from_index(self.next_call_site)
            .map_err(|_| ProcedureLoweringError::Invalid("too many call sites".into()))?;
        builder.add_call_site(SemanticCallSite {
            id,
            point: call.point,
            callee: call.callee,
            receiver: call.receiver,
            arguments: call.arguments,
            result: call.result,
            thrown: call.thrown,
            declared_targets: call.declared_targets,
            target_evidence: metadata.evidence,
            normal_continuation: ControlContinuation::Target(call.normal_continuation),
            exceptional_continuation: ControlContinuation::Target(call.exceptional_continuation),
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_call_site += 1;
        self.append_effect(
            builder,
            call.point,
            SemanticEffect::Invoke { call_site: id },
        )?;
        self.append_effect(
            builder,
            call.normal_continuation,
            SemanticEffect::CallContinuation {
                call_site: id,
                kind: CallContinuationKind::Normal,
            },
        )?;
        self.append_effect(
            builder,
            call.exceptional_continuation,
            SemanticEffect::CallContinuation {
                call_site: id,
                kind: CallContinuationKind::Exceptional,
            },
        )?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::analyzer::semantic::{
        DeclarationLocator, DeclarationSegment, DeclarationSegmentKind, ProcedureId, ProcedureKind,
        SemanticLanguage, SourcePosition, SourceSpan, WorkspaceMountId, WorkspaceRelativePath,
    };

    fn anchor(start: u32, end: u32, occurrence: u32) -> SourceAnchor {
        SourceAnchor::new(
            SourceSpan::new(
                SourcePosition::new(start, 0, start),
                SourcePosition::new(end, 0, end),
            )
            .expect("test span"),
            occurrence,
        )
    }

    fn parts() -> ProcedureSemanticsParts {
        let declaration_anchor = anchor(0, 7, 0);
        let declaration = DeclarationLocator::new(vec![
            DeclarationSegment::named(
                DeclarationSegmentKind::Function,
                "fixture",
                declaration_anchor,
                0,
            )
            .expect("declaration segment"),
        ])
        .expect("declaration locator");
        let locator = SemanticLocator::new(
            WorkspaceMountId::hash_bytes(b"lowering-session-test"),
            WorkspaceRelativePath::new("fixture.ts").expect("path"),
            SemanticLanguage::Standard(crate::analyzer::Language::TypeScript),
            declaration,
            SemanticRole::Procedure,
            declaration_anchor,
        );
        ProcedureSemanticsParts::new(
            ProcedureId::new(0),
            locator,
            ProcedureKind::Function,
            SourceMappingId::new(0),
            EvidenceId::new(0),
        )
    }

    #[test]
    fn session_seeds_exact_boundaries_and_dense_provenance() {
        let cancellation = CancellationToken::default();
        let start =
            ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
                .expect("lowering start");

        assert_eq!(start.entry.index(), 0);
        assert_eq!(start.normal_exit.index(), 1);
        assert_eq!(start.exceptional_exit.index(), 2);
        assert_eq!(
            start.session.metadata(start.entry).unwrap().source.index(),
            0
        );
        assert_eq!(start.session.point_metadata.len(), 3);
    }

    #[test]
    fn batch_lowering_preserves_initial_and_per_procedure_work() {
        let cancellation = CancellationToken::default();
        let initial = SemanticWork {
            nested_entries: 2,
            ..SemanticWork::default()
        };
        let per_procedure = SemanticWork {
            program_points: 3,
            ..SemanticWork::default()
        };
        let outcome = lower_procedure_batch(
            [(), ()],
            initial,
            &SemanticBudget::default(),
            &cancellation,
            |(), _, _| Ok((parts(), per_procedure)),
        )
        .expect("batch outcome");

        assert!(outcome.is_complete());
        assert_eq!(
            outcome.work(),
            sum_lowering_work(initial, sum_lowering_work(per_procedure, per_procedure))
        );
    }

    #[test]
    fn batch_cancellation_retains_precomputed_work_without_lowering() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let called = Cell::new(false);
        let initial = SemanticWork {
            source_bytes: 17,
            ..SemanticWork::default()
        };
        let outcome = lower_procedure_batch(
            [()],
            initial,
            &SemanticBudget::default(),
            &cancellation,
            |(), _, _| {
                called.set(true);
                Ok((parts(), SemanticWork::default()))
            },
        )
        .expect("batch outcome");

        assert!(matches!(outcome, SemanticOutcome::Cancelled { .. }));
        assert_eq!(outcome.work(), initial);
        assert!(!called.get());
    }

    #[test]
    fn occurrence_allocation_is_span_local_and_deterministic() {
        let cancellation = CancellationToken::default();
        let mut start =
            ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
                .expect("lowering start");

        assert_eq!(start.session.next_source_occurrence(10, 20), 0);
        assert_eq!(start.session.next_source_occurrence(10, 20), 1);
        assert_eq!(start.session.next_source_occurrence(11, 20), 0);
    }

    #[test]
    fn separate_function_throw_boundary_remains_dense_and_adapter_visible() {
        let cancellation = CancellationToken::default();
        let (start, throw_boundary) = ProcedureLoweringSession::start_with_function_throw_boundary(
            parts(),
            &SemanticBudget::default(),
            &cancellation,
            true,
        )
        .expect("lowering start");
        let throw_boundary = throw_boundary.expect("separate throw boundary");

        assert_eq!(throw_boundary.index(), 3);
        assert_eq!(start.session.point_metadata.len(), 4);
        assert_eq!(
            start.session.metadata(throw_boundary).unwrap(),
            start.session.metadata(start.exceptional_exit).unwrap()
        );
    }

    #[test]
    fn shared_call_scaffold_publishes_matched_events_and_metadata() {
        let cancellation = CancellationToken::default();
        let ProcedureLoweringStart {
            mut builder,
            mut session,
            normal_exit,
            exceptional_exit,
            ..
        } = ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
            .expect("lowering start");
        let mapping = session
            .add_mapping(&mut builder, anchor(8, 14, 0), SourceMappingKind::Exact)
            .expect("call mapping");
        let invoke = session
            .add_point(&mut builder, mapping, Vec::new())
            .expect("invoke point");
        let callee = session
            .add_value(&mut builder, invoke, SemanticValueKind::Callable)
            .expect("callee value");
        let call_site = session
            .add_call_site(
                &mut builder,
                CallSiteScaffold {
                    point: invoke,
                    callee,
                    receiver: None,
                    arguments: Box::new([]),
                    result: None,
                    thrown: None,
                    declared_targets: CallableTargetResolution::Unknown,
                    normal_continuation: normal_exit,
                    exceptional_continuation: exceptional_exit,
                },
            )
            .expect("call scaffold");
        let (parts, _) = builder.finish_with_work().expect("finished parts");

        assert_eq!(call_site.index(), 0);
        assert_eq!(parts.call_sites.len(), 1);
        assert_eq!(parts.call_sites[0].source, mapping.source);
        assert!(
            parts.points[invoke.index()]
                .events
                .iter()
                .any(|event| event.effect == SemanticEffect::Invoke { call_site })
        );
        assert!(
            parts.points[normal_exit.index()]
                .events
                .iter()
                .any(|event| {
                    event.effect
                        == SemanticEffect::CallContinuation {
                            call_site,
                            kind: CallContinuationKind::Normal,
                        }
                })
        );
        assert!(
            parts.points[exceptional_exit.index()]
                .events
                .iter()
                .any(|event| {
                    event.effect
                        == SemanticEffect::CallContinuation {
                            call_site,
                            kind: CallContinuationKind::Exceptional,
                        }
                })
        );
    }
}
