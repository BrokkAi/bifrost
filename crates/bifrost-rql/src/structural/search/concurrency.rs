//! Workspace binding and source projection for spawn-rooted concurrency facts.

use std::sync::Arc;

use super::{ProjectFile, Range, SemanticProcedureValue, WorkspaceAnalyzer};
use crate::analyzer::semantic::{
    AccessPath, AccessPathAtPoint, AccessPathRoot, AccessSelector, AllocationId, CallSiteHandle,
    CallableTarget, CallableTargetResolution, CandidateCoverage, DispatchOracle,
    EvidenceCompleteness, HeapOracle, IndexSelector, IndexedLocationIdentity, MemoryLocationId,
    MemoryLocationKind, ObjectCardinality, ObservationPhase, OracleCallContext, OracleLimits,
    ProcedureHandle, ProgramPointId, ProofStatus, ScopedSemanticLocator, SemanticEffect,
    SemanticProviderError, SemanticRequest, ValueAtPoint, ValueHandle, ValueId,
};
use crate::analyzer::semantic_model::{
    ActiveSemanticModelSnapshot, CompiledAtomicOperation, CompiledConcurrencyEffect,
    CompiledLockMode, CompiledSummaryInput, Completeness, ProcedureSummaryDeclarationKey,
    ProcedureSummaryMemberKey, SemanticModelMatchDisposition,
};
use brokk_bifrost_flow::concurrency::{
    CanonicalConcurrencyLocation, ConcurrencyAnswer, ConcurrencyAtomicOperation,
    ConcurrencyLockMode, ConcurrencyOpenReason, ConcurrencyProvider, ConcurrentAccessConflict,
    ResolvedConcurrencyEffect, ResolvedConcurrencySubject,
};
use brokk_bifrost_flow::typestate::TypestateObjectKey;

pub(super) struct WorkspaceConcurrencyProvider<'a> {
    workspace: &'a WorkspaceAnalyzer,
    active_models: Option<Arc<ActiveSemanticModelSnapshot>>,
}

impl<'a> WorkspaceConcurrencyProvider<'a> {
    pub(super) fn new(
        workspace: &'a WorkspaceAnalyzer,
        active_models: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Self {
        Self {
            workspace,
            active_models,
        }
    }

    fn actual_input(
        call: &crate::analyzer::semantic::SemanticCallSite,
        input: &CompiledSummaryInput,
    ) -> Option<ValueId> {
        match input {
            CompiledSummaryInput::Receiver {} => call.receiver,
            CompiledSummaryInput::Parameter { ordinal } => call
                .arguments
                .get(usize::try_from(*ordinal).ok()?)
                .map(|argument| argument.value),
        }
    }

    fn canonical_actual(
        &self,
        call: &CallSiteHandle,
        input: &CompiledSummaryInput,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Option<ResolvedConcurrencySubject>>, SemanticProviderError> {
        let row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("validated call handle resolves");
        let Some(value) = Self::actual_input(row, input) else {
            return Ok(ConcurrencyAnswer::Open {
                partial: None,
                reasons: vec![ConcurrencyOpenReason::UnknownLocation],
            });
        };
        let (canonical, mut reasons) = self
            .canonical_value(call.procedure(), row.point, value, request)?
            .into_parts();
        if canonical.is_none() && reasons.is_empty() {
            reasons.push(ConcurrencyOpenReason::UnknownLocation);
        }
        let subject = ResolvedConcurrencySubject {
            value,
            canonical,
            reasons: reasons.clone(),
        };
        Ok(if reasons.is_empty() {
            ConcurrencyAnswer::Proven(Some(subject))
        } else {
            ConcurrencyAnswer::Open {
                partial: Some(subject),
                reasons,
            }
        })
    }

    fn canonical_value_at(
        &self,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        value: ValueId,
        phase: ObservationPhase,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>
    {
        let query = ValueAtPoint::new(
            value_handle(procedure, value)?,
            procedure
                .point_handle(point)
                .expect("validated program point exists"),
            phase,
            OracleCallContext::empty(),
        )
        .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
        let outcome = self
            .workspace
            .semantic_oracle_provider()
            .pointees(&query, request)?;
        let Some(result) = outcome.available_value() else {
            return Ok(open_location());
        };
        let [candidate] = result.objects().candidates() else {
            return Ok(open_location());
        };
        if !outcome.is_complete()
            || !result.objects().coverage().is_exhaustive()
            || !candidate.is_proven_complete()
        {
            return Ok(open_location());
        }
        let object = candidate.value();
        if object.cardinality() != ObjectCardinality::Singleton
            || matches!(
                object.identity(),
                AccessPathRoot::CallResult(_)
                    | AccessPathRoot::ProcedurePort(_)
                    | AccessPathRoot::CaptureSlot(_)
            )
        {
            return Ok(open_location());
        }
        Ok(ConcurrencyAnswer::Proven(Some(
            CanonicalConcurrencyLocation::new(
                TypestateObjectKey::for_object(object).public_canonical_rendering(),
                "object",
            ),
        )))
    }

    fn callback_targets(
        call: &CallSiteHandle,
        input: &CompiledSummaryInput,
    ) -> ConcurrencyAnswer<Vec<ProcedureHandle>> {
        let semantics = call.procedure().semantics();
        let row = semantics
            .call_site(call.id())
            .expect("validated call handle resolves");
        let Some(value) = Self::actual_input(row, input) else {
            return ConcurrencyAnswer::Open {
                partial: Vec::new(),
                reasons: vec![ConcurrencyOpenReason::UnresolvedTarget],
            };
        };
        let mut targets = Vec::new();
        let mut open = false;
        for point in semantics.points() {
            for event in &point.events {
                let callable = match &event.effect {
                    SemanticEffect::CallableCreation { result, callable }
                    | SemanticEffect::CallableReference { result, callable }
                        if *result == value =>
                    {
                        callable
                    }
                    SemanticEffect::ValueFlow {
                        source,
                        target,
                        kind: crate::analyzer::semantic::ValueFlowKind::Local,
                    } if *target == value => {
                        for source_point in semantics.points() {
                            for source_event in &source_point.events {
                                let source_callable = match &source_event.effect {
                                    SemanticEffect::CallableCreation { result, callable }
                                    | SemanticEffect::CallableReference { result, callable }
                                        if result == source =>
                                    {
                                        callable
                                    }
                                    _ => continue,
                                };
                                collect_local_callable_targets(
                                    call.procedure(),
                                    &source_callable.targets,
                                    &mut targets,
                                    &mut open,
                                );
                            }
                        }
                        continue;
                    }
                    _ => continue,
                };
                collect_local_callable_targets(
                    call.procedure(),
                    &callable.targets,
                    &mut targets,
                    &mut open,
                );
            }
        }
        targets.sort_by_key(|target| format!("{:?}", target.durable_key()));
        targets.dedup();
        if !open && !targets.is_empty() {
            ConcurrencyAnswer::Proven(targets)
        } else {
            ConcurrencyAnswer::Open {
                partial: targets,
                reasons: vec![ConcurrencyOpenReason::UnresolvedTarget],
            }
        }
    }

    fn exact_model_effects(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Vec<ResolvedConcurrencyEffect>>, SemanticProviderError> {
        let outcome = self
            .workspace
            .semantic_oracle_provider()
            .resolve_call(call, request)?;
        let Some(dispatch) = outcome.available_value() else {
            return Ok(ConcurrencyAnswer::Open {
                partial: Vec::new(),
                reasons: vec![ConcurrencyOpenReason::UnresolvedTarget],
            });
        };
        let mut targets = dispatch
            .boundaries()
            .iter()
            .filter_map(|boundary| {
                if let Some(target) = boundary.exact_external_target() {
                    let (owner, member) =
                        crate::analyzer::semantic::split_qualified_member(target.symbol())?;
                    return Some((
                        target.artifact().language().semantic_pack_label(),
                        owner.to_owned(),
                        member.to_owned(),
                        target.has_receiver(),
                        target.parameter_count(),
                    ));
                }
                let target = boundary.unmaterialized_external_target()?;
                Some((
                    target.language().semantic_pack_label(),
                    target.owner_fqn().to_owned(),
                    target.member().to_owned(),
                    target.has_receiver(),
                    target.arity(),
                ))
            })
            .collect::<Vec<_>>();
        targets.sort();
        targets.dedup();
        let Some(active) = self.active_models.as_ref() else {
            return Ok(ConcurrencyAnswer::Proven(Vec::new()));
        };
        let matched = if let [target] = targets.as_slice() {
            active
                .active_models()
                .procedure_summaries_for_member(ProcedureSummaryMemberKey::new(
                    target.0, &target.1, &target.2, target.3, target.4,
                ))
        } else if targets.is_empty() {
            let row = call
                .procedure()
                .semantics()
                .call_site(call.id())
                .expect("validated call handle resolves");
            let locator = match &row.declared_targets {
                CallableTargetResolution::Proven(
                    CallableTarget::External(locator) | CallableTarget::Unmaterialized(locator),
                ) => locator,
                _ => return Ok(ConcurrencyAnswer::Proven(Vec::new())),
            };
            let Some(member) = locator
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
            else {
                return Ok(ConcurrencyAnswer::Proven(Vec::new()));
            };
            active.active_models().procedure_summaries_for_declaration(
                ProcedureSummaryDeclarationKey::new(
                    locator.language().semantic_pack_label(),
                    locator.path().as_str(),
                    member,
                    row.receiver.is_some(),
                    u32::try_from(row.arguments.len())
                        .expect("validated call argument count fits u32"),
                ),
            )
        } else {
            return Ok(ConcurrencyAnswer::Open {
                partial: Vec::new(),
                reasons: vec![ConcurrencyOpenReason::AmbiguousTarget],
            });
        };
        if matched.disposition == SemanticModelMatchDisposition::Conflict {
            return Ok(ConcurrencyAnswer::Open {
                partial: Vec::new(),
                reasons: vec![ConcurrencyOpenReason::AmbiguousTarget],
            });
        }
        let Some(selected) = matched.records.first() else {
            return Ok(ConcurrencyAnswer::Proven(Vec::new()));
        };
        if selected.record.completeness != Completeness::Complete {
            return Ok(ConcurrencyAnswer::Open {
                partial: Vec::new(),
                reasons: vec![ConcurrencyOpenReason::UnresolvedTarget],
            });
        }
        let mut effects = Vec::new();
        let mut reasons = Vec::new();
        for effect in selected.concurrency_effects() {
            match self.bind_effect(call, effect, request)? {
                ConcurrencyAnswer::Proven(Some(effect)) => effects.push(effect),
                ConcurrencyAnswer::Proven(None) => {}
                ConcurrencyAnswer::Open {
                    partial: Some(effect),
                    reasons: effect_reasons,
                } => {
                    effects.push(effect);
                    reasons.extend(effect_reasons);
                }
                ConcurrencyAnswer::Open {
                    partial: None,
                    reasons: effect_reasons,
                } => reasons.extend(effect_reasons),
            }
        }
        Ok(if reasons.is_empty() {
            ConcurrencyAnswer::Proven(effects)
        } else {
            ConcurrencyAnswer::Open {
                partial: effects,
                reasons,
            }
        })
    }

    fn bind_effect(
        &self,
        call: &CallSiteHandle,
        effect: &CompiledConcurrencyEffect,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Option<ResolvedConcurrencyEffect>>, SemanticProviderError> {
        let location =
            |answer: ConcurrencyAnswer<Option<ResolvedConcurrencySubject>>,
             mapper: &dyn Fn(ResolvedConcurrencySubject) -> ResolvedConcurrencyEffect| {
                match answer {
                    ConcurrencyAnswer::Proven(Some(location)) => {
                        ConcurrencyAnswer::Proven(Some(mapper(location)))
                    }
                    ConcurrencyAnswer::Proven(None) => ConcurrencyAnswer::Open {
                        partial: None,
                        reasons: vec![ConcurrencyOpenReason::UnknownLocation],
                    },
                    ConcurrencyAnswer::Open { partial, reasons } => ConcurrencyAnswer::Open {
                        partial: partial.map(mapper),
                        reasons,
                    },
                }
            };
        Ok(match effect {
            CompiledConcurrencyEffect::Unsupported { protocol } => ConcurrencyAnswer::Open {
                partial: None,
                reasons: vec![ConcurrencyOpenReason::UnsupportedSynchronization(
                    protocol.clone().into_boxed_str(),
                )],
            },
            CompiledConcurrencyEffect::TaskSpawn { callable, group } => {
                let (targets, mut reasons) = Self::callback_targets(call, callable).into_parts();
                let group = if let Some(group) = group {
                    let (group, group_reasons) =
                        self.canonical_actual(call, group, request)?.into_parts();
                    reasons.extend(group_reasons);
                    group
                } else {
                    None
                };
                let effect = (!targets.is_empty())
                    .then_some(ResolvedConcurrencyEffect::TaskSpawn { targets, group });
                if reasons.is_empty() {
                    ConcurrencyAnswer::Proven(effect)
                } else {
                    ConcurrencyAnswer::Open {
                        partial: effect,
                        reasons,
                    }
                }
            }
            CompiledConcurrencyEffect::TaskJoin { group } => {
                location(self.canonical_actual(call, group, request)?, &|group| {
                    ResolvedConcurrencyEffect::TaskJoin { group }
                })
            }
            CompiledConcurrencyEffect::LockAcquire { lock, mode } => {
                location(self.canonical_actual(call, lock, request)?, &|lock| {
                    ResolvedConcurrencyEffect::LockAcquire {
                        lock,
                        mode: lock_mode(*mode),
                    }
                })
            }
            CompiledConcurrencyEffect::LockRelease { lock, mode } => {
                location(self.canonical_actual(call, lock, request)?, &|lock| {
                    ResolvedConcurrencyEffect::LockRelease {
                        lock,
                        mode: lock_mode(*mode),
                    }
                })
            }
            CompiledConcurrencyEffect::WaitGroupAdd { group, delta } => {
                location(self.canonical_actual(call, group, request)?, &|group| {
                    ResolvedConcurrencyEffect::WaitGroupAdd {
                        group,
                        delta: exact_integer_input(call, delta),
                    }
                })
            }
            CompiledConcurrencyEffect::WaitGroupDone { group } => {
                location(self.canonical_actual(call, group, request)?, &|group| {
                    ResolvedConcurrencyEffect::WaitGroupDone { group }
                })
            }
            CompiledConcurrencyEffect::WaitGroupWait { group } => {
                location(self.canonical_actual(call, group, request)?, &|group| {
                    ResolvedConcurrencyEffect::WaitGroupWait { group }
                })
            }
            CompiledConcurrencyEffect::Atomic {
                location: input,
                operation,
            } => location(self.canonical_actual(call, input, request)?, &|location| {
                ResolvedConcurrencyEffect::Atomic {
                    location,
                    operation: atomic_operation(*operation),
                }
            }),
        })
    }
}

impl ConcurrencyProvider for WorkspaceConcurrencyProvider<'_> {
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Vec<ProcedureHandle>>, SemanticProviderError> {
        let outcome = self
            .workspace
            .semantic_oracle_provider()
            .resolve_call(call, request)?;
        let partial = outcome
            .available_value()
            .map(|result| {
                result
                    .candidates()
                    .iter()
                    .filter(|candidate| dispatch_candidate_is_exact(candidate))
                    .map(|candidate| candidate.target().clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let proven = outcome.is_complete()
            && outcome.available_value().is_some_and(|result| {
                result.coverage() == CandidateCoverage::Exhaustive
                    && result.candidates().iter().all(dispatch_candidate_is_exact)
                    && result.boundaries().iter().all(|boundary| {
                        matches!(boundary.proof, ProofStatus::Proven)
                            && (boundary.exact_external_target().is_some()
                                || boundary.unmaterialized_external_target().is_some())
                    })
            });
        Ok(if proven {
            ConcurrencyAnswer::Proven(partial)
        } else {
            ConcurrencyAnswer::Open {
                partial,
                reasons: vec![ConcurrencyOpenReason::UnresolvedTarget],
            }
        })
    }

    fn modeled_effects(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Vec<ResolvedConcurrencyEffect>>, SemanticProviderError> {
        self.exact_model_effects(call, request)
    }

    fn canonical_location(
        &self,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        location: MemoryLocationId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>
    {
        let row = procedure
            .semantics()
            .memory_location(location)
            .expect("validated memory location exists");
        if let MemoryLocationKind::Index {
            base,
            identity: IndexedLocationIdentity::Aggregate,
            ..
        } = row.kind
        {
            return Ok(
                match self.canonical_value(procedure, point, base, request)? {
                    ConcurrencyAnswer::Proven(Some(base)) => {
                        ConcurrencyAnswer::Proven(Some(CanonicalConcurrencyLocation::new(
                            format!("{}/index:aggregate", base.identity),
                            row.kind.label(),
                        )))
                    }
                    ConcurrencyAnswer::Proven(None) => open_location(),
                    ConcurrencyAnswer::Open { partial, reasons } => ConcurrencyAnswer::Open {
                        partial: partial.map(|base| {
                            CanonicalConcurrencyLocation::new(
                                format!("{}/index:aggregate", base.identity),
                                row.kind.label(),
                            )
                        }),
                        reasons,
                    },
                },
            );
        }
        let point = procedure
            .point_handle(point)
            .expect("validated program point exists");
        let scoped = |locator| {
            ScopedSemanticLocator::new(Arc::clone(procedure.artifact()), locator)
                .map_err(|error| SemanticProviderError::internal(error.to_string()))
        };
        let (root, selectors) = match &row.kind {
            MemoryLocationKind::Field { base, member } => (
                AccessPathRoot::Value(value_handle(procedure, *base)?),
                vec![AccessSelector::Field(scoped(member.clone())?)],
            ),
            MemoryLocationKind::Index {
                base,
                index,
                constant_index,
                ..
            } => {
                let selector = match (constant_index, index) {
                    (Some(index), _) => IndexSelector::Constant(*index),
                    (None, Some(index)) => IndexSelector::Exact(value_handle(procedure, *index)?),
                    (None, None) => IndexSelector::Any,
                };
                (
                    AccessPathRoot::Value(value_handle(procedure, *base)?),
                    vec![AccessSelector::Index(selector)],
                )
            }
            MemoryLocationKind::Static { .. }
            | MemoryLocationKind::LexicalCell { .. }
            | MemoryLocationKind::Capture { .. } => {
                unreachable!("the concurrency solver canonicalizes non-heap locations directly")
            }
        };
        let path = AccessPath::exact(root, selectors, OracleLimits::default())
            .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
        let query = AccessPathAtPoint::new(
            path,
            point,
            ObservationPhase::BeforeEffects,
            OracleCallContext::empty(),
        )
        .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
        let outcome = self
            .workspace
            .semantic_oracle_provider()
            .locations(&query, request)?;
        let Some(result) = outcome.available_value() else {
            return Ok(open_location());
        };
        let [candidate] = result.locations().candidates() else {
            return Ok(open_location());
        };
        if !outcome.is_complete()
            || !result.locations().coverage().is_exhaustive()
            || !candidate.is_proven_complete()
        {
            return Ok(open_location());
        }
        let location = candidate.value();
        if location.object().cardinality() != ObjectCardinality::Singleton {
            return Ok(open_location());
        }
        let Some(path_identity) = exact_path_identity(location.path()) else {
            return Ok(open_location());
        };
        let object = TypestateObjectKey::for_object(location.object()).public_canonical_rendering();
        Ok(ConcurrencyAnswer::Proven(Some(
            CanonicalConcurrencyLocation::new(
                format!("{object}/{path_identity}"),
                row.kind.label(),
            ),
        )))
    }

    fn canonical_value(
        &self,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        value: ValueId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>
    {
        self.canonical_value_at(
            procedure,
            point,
            value,
            ObservationPhase::BeforeEffects,
            request,
        )
    }

    fn canonical_allocation(
        &self,
        procedure: &ProcedureHandle,
        allocation: AllocationId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>
    {
        let allocation = procedure
            .semantics()
            .allocation(allocation)
            .expect("validated allocation exists");
        self.canonical_value_at(
            procedure,
            allocation.point,
            allocation.result,
            ObservationPhase::AfterEffects,
            request,
        )
    }
}

fn collect_local_callable_targets(
    procedure: &ProcedureHandle,
    resolution: &CallableTargetResolution,
    targets: &mut Vec<ProcedureHandle>,
    open: &mut bool,
) {
    match resolution {
        CallableTargetResolution::Proven(CallableTarget::Local(target)) => targets.push(
            procedure
                .artifact()
                .procedure_handle(*target)
                .expect("validated local callable target exists"),
        ),
        CallableTargetResolution::Proven(_) => *open = true,
        CallableTargetResolution::Ambiguous(candidates)
        | CallableTargetResolution::Unproven(candidates)
        | CallableTargetResolution::ExceededBudget(candidates) => {
            *open = true;
            for target in candidates {
                if let CallableTarget::Local(target) = target {
                    targets.push(
                        procedure
                            .artifact()
                            .procedure_handle(*target)
                            .expect("validated local callable target exists"),
                    );
                }
            }
        }
        CallableTargetResolution::Unknown | CallableTargetResolution::Unsupported => *open = true,
    }
}

fn dispatch_candidate_is_exact(candidate: &crate::analyzer::semantic::DispatchCandidate) -> bool {
    matches!(candidate.proof(), ProofStatus::Proven)
        && matches!(candidate.completeness(), EvidenceCompleteness::Complete)
}

fn value_handle(
    procedure: &ProcedureHandle,
    value: ValueId,
) -> Result<ValueHandle, SemanticProviderError> {
    procedure.value_handle(value).ok_or_else(|| {
        SemanticProviderError::internal("concurrency input names a stale semantic value")
    })
}

fn open_location<T>() -> ConcurrencyAnswer<Option<T>> {
    ConcurrencyAnswer::Open {
        partial: None,
        reasons: vec![ConcurrencyOpenReason::UnknownLocation],
    }
}

fn exact_path_identity(path: &AccessPath) -> Option<String> {
    let [selector] = path.selectors() else {
        return Some("root".to_string());
    };
    match selector {
        AccessSelector::Field(field) => Some(format!("field:{:?}", field.locator())),
        AccessSelector::Index(IndexSelector::Constant(index)) => Some(format!("index:{index}")),
        AccessSelector::Index(IndexSelector::Exact(_) | IndexSelector::Any) => None,
    }
}

fn lock_mode(mode: CompiledLockMode) -> ConcurrencyLockMode {
    match mode {
        CompiledLockMode::Shared => ConcurrencyLockMode::Shared,
        CompiledLockMode::Exclusive => ConcurrencyLockMode::Exclusive,
    }
}

fn atomic_operation(operation: CompiledAtomicOperation) -> ConcurrencyAtomicOperation {
    match operation {
        CompiledAtomicOperation::Load => ConcurrencyAtomicOperation::Load,
        CompiledAtomicOperation::Store => ConcurrencyAtomicOperation::Store,
        CompiledAtomicOperation::ReadModifyWrite => ConcurrencyAtomicOperation::ReadModifyWrite,
    }
}

fn exact_integer_input(call: &CallSiteHandle, input: &CompiledSummaryInput) -> Option<i64> {
    let semantics = call.procedure().semantics();
    let row = semantics.call_site(call.id())?;
    let value = WorkspaceConcurrencyProvider::actual_input(row, input)?;
    let value = semantics.value(value)?;
    match value.kind {
        crate::analyzer::semantic::SemanticValueKind::UnsignedInteger(value) => {
            i64::try_from(value).ok()
        }
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub(super) struct ConcurrentAccessConflictValue {
    pub(super) conflict: ConcurrentAccessConflict,
    pub(super) id: String,
    pub(super) root_procedure_id: String,
    pub(super) file: ProjectFile,
    pub(super) range: Range,
    pub(super) ast_id: Option<String>,
    pub(super) first_file: ProjectFile,
    pub(super) first_range: Range,
    pub(super) second_file: ProjectFile,
    pub(super) second_range: Range,
}

impl ConcurrentAccessConflictValue {
    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }
}

pub(super) fn project_conflict(
    workspace: &WorkspaceAnalyzer,
    root: &SemanticProcedureValue,
    conflict: ConcurrentAccessConflict,
) -> ConcurrentAccessConflictValue {
    let source_site = |site: &brokk_bifrost_flow::concurrency::ConcurrentAccessSite| {
        let mapping = site
            .procedure
            .semantics()
            .source_mapping(site.source)
            .expect("validated conflict access has a source mapping");
        let span = mapping.locator.anchor().span();
        (
            super::witness_projection::locator_file(workspace, &mapping.locator),
            Range {
                start_byte: span.start_byte() as usize,
                end_byte: span.end_byte() as usize,
                start_line: span.start().line() as usize + 1,
                end_line: span.end().line() as usize + 1,
            },
        )
    };
    let (first_file, first_range) = source_site(&conflict.first);
    let (second_file, second_range) = source_site(&conflict.second);
    let anchor = conflict_anchor(&conflict);
    let mapping = anchor
        .procedure
        .semantics()
        .source_mapping(anchor.source)
        .expect("validated conflict access has a source mapping");
    let span = mapping.locator.anchor().span();
    let file = super::witness_projection::locator_file(workspace, &mapping.locator);
    let ast_identity = mapping.ast_identity;
    let mut digest = crate::analyzer::semantic::LengthDelimitedDigest::new(
        b"bifrost.code_query.concurrent_access_conflict.v1",
    );
    digest.push(format!("{:?}", root.handle.durable_key()).as_bytes());
    digest.push(conflict.location.identity.as_bytes());
    let mut sites = [stable_site(&conflict.first), stable_site(&conflict.second)];
    sites.sort();
    digest.push(sites[0].as_bytes());
    digest.push(sites[1].as_bytes());
    ConcurrentAccessConflictValue {
        conflict,
        id: digest.finish().to_string(),
        root_procedure_id: format!("{:?}", root.handle.durable_key()),
        file,
        range: Range {
            start_byte: span.start_byte() as usize,
            end_byte: span.end_byte() as usize,
            start_line: span.start().line() as usize + 1,
            end_line: span.end().line() as usize + 1,
        },
        ast_id: ast_identity.map(|identity| {
            super::super::occurrence_rows::ast_id(identity.content(), identity.node_id())
        }),
        first_file,
        first_range,
        second_file,
        second_range,
    }
}

fn conflict_anchor(
    conflict: &ConcurrentAccessConflict,
) -> &brokk_bifrost_flow::concurrency::ConcurrentAccessSite {
    match (conflict.first.mode, conflict.second.mode) {
        (brokk_bifrost_flow::concurrency::ConcurrentAccessMode::Write, _) => &conflict.first,
        (_, brokk_bifrost_flow::concurrency::ConcurrentAccessMode::Write) => &conflict.second,
        _ => &conflict.first,
    }
}

fn stable_site(site: &brokk_bifrost_flow::concurrency::ConcurrentAccessSite) -> String {
    format!(
        "{:?}:{}:{}",
        site.procedure.durable_key(),
        site.point.get(),
        site.source.get()
    )
}
