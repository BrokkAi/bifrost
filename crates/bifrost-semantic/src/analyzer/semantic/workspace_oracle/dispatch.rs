//! Exact, location-first workspace dispatch and candidate materialization.
//!
//! Control-flow stitching consumes the workspace-oracle facade; it does not
//! reach into the usage-graph dispatch resolver directly.

use std::cmp::Ordering;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::analyzer::semantic::FormalParameterPassingMode;

use crate::analyzer::semantic::lexical_definitions::FormalParameterSlot;

use crate::analyzer::semantic::CallSiteHandle;

use crate::analyzer::semantic::CallableTarget;

use crate::analyzer::semantic::CallableTargetResolution;

use brokk_bifrost_core::cancellation::CancellationToken;

use crate::analyzer::semantic::ContentIdentity;

use crate::analyzer::semantic::DeclarationSegment;

use crate::analyzer::semantic::DeclarationSegmentKind;

use crate::analyzer::semantic::DispatchBoundaryKind;

use crate::analyzer::semantic::DispatchCandidate;

use brokk_bifrost_core::analyzer::model::DispatchExtensibility;

use crate::analyzer::semantic::EvidenceCompleteness;

use crate::analyzer::semantic::ExactExternalFormalContract;

use crate::analyzer::semantic::ProcedureHandle;

use crate::analyzer::semantic::ProcedureKind;

use crate::analyzer::semantic::ProcedureSemantics;

use crate::analyzer::semantic::ProofStatus;

use crate::analyzer::semantic::SemanticArtifact;

use crate::analyzer::semantic::SemanticBudgetExceeded;

use crate::analyzer::semantic::SemanticCallSite;

use crate::analyzer::semantic::SemanticCapability;

use crate::analyzer::semantic::SemanticEffect;

use crate::analyzer::semantic::SemanticGap;

use crate::analyzer::semantic::SemanticGapImpact;

use crate::analyzer::semantic::SemanticGapKind;

use crate::analyzer::semantic::SemanticGapSubject;

use crate::analyzer::semantic::SemanticLocator;

use crate::analyzer::semantic::SemanticOutcome;

use crate::analyzer::semantic::SemanticProviderError;

use crate::analyzer::semantic::SemanticRequest;

use crate::analyzer::semantic::SemanticRole;

use crate::analyzer::semantic::SemanticValueKind;

use crate::analyzer::semantic::SemanticWork;

use crate::analyzer::semantic::SourceAnchor;

use crate::analyzer::semantic::SourceMappingKind;

use crate::analyzer::semantic::SourcePosition;

use crate::analyzer::semantic::SourceSpan;

use crate::analyzer::semantic::StableDigest;

use crate::analyzer::semantic::ValueFlowKind;

use crate::analyzer::semantic::ValueId;

use crate::analyzer::semantic_model::ParameterPassingMode;

use crate::analyzer::semantic_model::Signature;

use crate::analyzer::semantic::trace::DispatchQuality;

use crate::analyzer::semantic::call_relations::CallRelationWork;

use brokk_bifrost_core::analyzer::usages::model::UsageProof;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::LanguageDialect;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;

#[derive(Debug)]
#[doc(hidden)]
pub struct DispatchTargetGroup {
    #[doc(hidden)]
    pub representative: CodeUnit,
    #[doc(hidden)]
    pub proof: ProofStatus,
    #[doc(hidden)]
    pub completeness: EvidenceCompleteness,
    #[doc(hidden)]
    pub receiver_hint: bool,
    #[doc(hidden)]
    pub native_incomplete_source_reason: Option<Box<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum MaterializationInterruption {
    Budget,
    Cancelled,
}

#[doc(hidden)]
pub fn materialization_interruption(
    quality: DispatchQuality,
    budget_exceeded: bool,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Option<MaterializationInterruption> {
    if quality == DispatchQuality::Cancelled || cancellation.is_cancelled() {
        Some(MaterializationInterruption::Cancelled)
    } else if budget_exceeded {
        Some(MaterializationInterruption::Budget)
    } else {
        None
    }
}

/// Walk one invocation's local callee value back to the unique call result it
/// derives from, requiring the path to cross a local binding.
///
/// Follow assignments, local bindings and uniquely defined Go assignment
/// conversions, which preserve a function value and its captured environment.
/// A callable creation, a loaded value, a callable reference, any
/// other flow kind, and any competing call result all refuse the walk instead
/// of choosing one producer. Requiring at least one `Local` edge keeps an
/// immediately invoked call result (`factory()()`) off this route, which
/// answers only the bound-and-then-invoked shape.
#[doc(hidden)]
pub fn returned_callable_producer(
    procedure: &ProcedureHandle,
    callee: ValueId,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<Option<(CallSiteHandle, ValueId)>>, SemanticProviderError> {
    let semantics = procedure.semantics();
    let mut staged = crate::analyzer::semantic::workspace_oracle::common::WorkStager::new(request);
    let mut current = callee;
    let mut crossed_local_binding = false;
    let mut visited = HashSet::default();
    loop {
        if !visited.insert(current) {
            return Ok(finish_callable_producer_walk(request, staged, None));
        }
        let mut definition: Option<ValueId> = None;
        let mut definition_is_local = false;
        for point in semantics.points() {
            if request.cancellation.is_cancelled() {
                *request.budget = staged.budget;
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: staged.work,
                });
            }
            staged.charge_work(SemanticWork {
                program_points: 1,
                nested_entries: point.events.len(),
                ..SemanticWork::default()
            });
            for event in point.events.iter() {
                match &event.effect {
                    SemanticEffect::Assignment { target, value } if *target == current => {
                        if !semantics
                            .evidence_row(event.evidence)
                            .is_some_and(|evidence| {
                                evidence.proof == ProofStatus::Proven
                                    && evidence.completeness == EvidenceCompleteness::Complete
                            })
                            || definition.is_some_and(|existing| existing != *value)
                        {
                            return Ok(finish_callable_producer_walk(request, staged, None));
                        }
                        definition = Some(*value);
                    }
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        source,
                        target,
                    } if *target == current => {
                        if !semantics
                            .evidence_row(event.evidence)
                            .is_some_and(|evidence| {
                                evidence.proof == ProofStatus::Proven
                                    && evidence.completeness == EvidenceCompleteness::Complete
                            })
                            || definition.is_some_and(|existing| existing != *source)
                        {
                            return Ok(finish_callable_producer_walk(request, staged, None));
                        }
                        definition = Some(*source);
                        definition_is_local = true;
                    }
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::LanguageDefined,
                        source,
                        target,
                    } if *target == current
                        && crate::analyzer::semantic::workspace_oracle::value_flow::is_go_assignment_conversion(semantics, *target) =>
                    {
                        let evidence = semantics.evidence_row(event.evidence).ok_or_else(|| {
                            SemanticProviderError::internal("conversion evidence is absent")
                        })?;
                        if evidence.proof != ProofStatus::Proven
                            || evidence.completeness != EvidenceCompleteness::Complete
                            || definition.is_some_and(|existing| existing != *source)
                        {
                            return Ok(finish_callable_producer_walk(request, staged, None));
                        }
                        definition = Some(*source);
                    }
                    SemanticEffect::ValueFlow { target, .. }
                    | SemanticEffect::MemoryLoad { result: target, .. }
                    | SemanticEffect::CallableCreation { result: target, .. }
                        if *target == current =>
                    {
                        return Ok(finish_callable_producer_walk(request, staged, None));
                    }
                    // An operand annotation with no proven target says only
                    // that the value is callable. It is not a competing
                    // definition of the value.
                    SemanticEffect::CallableReference { result, callable }
                        if *result == current =>
                    {
                        if matches!(
                            callable.targets,
                            CallableTargetResolution::Unknown
                                | CallableTargetResolution::Unsupported
                        ) {
                            continue;
                        }
                        return Ok(finish_callable_producer_walk(request, staged, None));
                    }
                    _ => {}
                }
            }
        }
        let mut producer: Option<CallSiteHandle> = None;
        for call_site in semantics.call_sites() {
            if request.cancellation.is_cancelled() {
                *request.budget = staged.budget;
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: staged.work,
                });
            }
            staged.charge_work(SemanticWork {
                call_sites: 1,
                ..SemanticWork::default()
            });
            if call_site
                .normal_result_values()
                .any(|result| result == current)
            {
                if producer.is_some() {
                    return Ok(finish_callable_producer_walk(request, staged, None));
                }
                producer = Some(procedure.call_site_handle(call_site.id).ok_or_else(|| {
                    SemanticProviderError::internal("semantic call site has no handle")
                })?);
            }
        }
        match (producer, definition) {
            (Some(producer), None) => {
                if !crossed_local_binding {
                    return Ok(finish_callable_producer_walk(request, staged, None));
                }
                return Ok(finish_callable_producer_walk(
                    request,
                    staged,
                    Some((producer, current)),
                ));
            }
            (None, Some(next)) => {
                crossed_local_binding |= definition_is_local;
                current = next;
            }
            _ => return Ok(finish_callable_producer_walk(request, staged, None)),
        }
    }
}

fn finish_callable_producer_walk(
    request: &mut SemanticRequest<'_>,
    staged: crate::analyzer::semantic::workspace_oracle::common::WorkStager,
    producer: Option<(CallSiteHandle, ValueId)>,
) -> SemanticOutcome<Option<(CallSiteHandle, ValueId)>> {
    *request.budget = staged.budget;
    SemanticOutcome::Complete {
        value: producer,
        work: staged.work,
    }
}

#[doc(hidden)]
pub fn exact_call_range(call: &CallSiteHandle) -> Result<Range, SemanticProviderError> {
    let semantic_call = call
        .procedure()
        .semantics()
        .call_site(call.id())
        .ok_or_else(|| SemanticProviderError::internal("semantic call-site handle is stale"))?;
    let mapping = call
        .procedure()
        .semantics()
        .source_mapping(semantic_call.source)
        .ok_or_else(|| {
            SemanticProviderError::internal("semantic call site has no source mapping")
        })?;
    let span = mapping.locator.anchor().span();
    Ok(Range {
        start_byte: span.start_byte() as usize,
        end_byte: span.end_byte() as usize,
        start_line: span.start().line() as usize,
        end_line: span.end().line() as usize,
    })
}

/// Walk only uniquely proven identity-preserving definitions to a formal slot.
#[doc(hidden)]
pub fn callback_parameter(
    procedure: &ProcedureHandle,
    value: ValueId,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<Option<u32>>, SemanticProviderError> {
    let semantics = procedure.semantics();
    let mut staged = crate::analyzer::semantic::workspace_oracle::common::WorkStager::new(request);
    let mut current = value;
    let mut visited = HashSet::default();
    loop {
        if !visited.insert(current) {
            break;
        }
        let mut definition = None;
        let mut refused = false;
        for point in semantics.points() {
            if request.cancellation.is_cancelled() {
                *request.budget = staged.budget;
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: staged.work,
                });
            }
            staged.charge_work(SemanticWork {
                program_points: 1,
                nested_entries: point.events.len(),
                ..SemanticWork::default()
            });
            for event in point.events.iter() {
                let source = match &event.effect {
                    SemanticEffect::Assignment { target, value } if *target == current => {
                        Some(*value)
                    }
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local | ValueFlowKind::Parameter,
                        source,
                        target,
                    } if *target == current => Some(*source),
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::LanguageDefined,
                        source,
                        target,
                    } if *target == current
                        && crate::analyzer::semantic::workspace_oracle::value_flow::is_go_assignment_conversion(semantics, *target) =>
                    {
                        Some(*source)
                    }
                    SemanticEffect::ValueFlow { target, .. }
                    | SemanticEffect::MemoryLoad { result: target, .. }
                    | SemanticEffect::CallableCreation { result: target, .. }
                        if *target == current =>
                    {
                        refused = true;
                        None
                    }
                    SemanticEffect::CallableReference { result, callable }
                        if *result == current
                            && !matches!(
                                callable.targets,
                                CallableTargetResolution::Unknown
                                    | CallableTargetResolution::Unsupported
                            ) =>
                    {
                        refused = true;
                        None
                    }
                    _ => None,
                };
                if let Some(source) = source {
                    let evidence = semantics.evidence_row(event.evidence).ok_or_else(|| {
                        SemanticProviderError::internal("callback definition evidence is absent")
                    })?;
                    if evidence.proof != ProofStatus::Proven
                        || evidence.completeness != EvidenceCompleteness::Complete
                        || definition.is_some_and(|previous| previous != source)
                    {
                        refused = true;
                    }
                    definition = Some(source);
                }
            }
        }
        if refused {
            break;
        }
        if let Some(next) = definition {
            current = next;
            continue;
        }
        staged.charge_work(SemanticWork {
            values: semantics.values().len(),
            ..SemanticWork::default()
        });
        let ordinal = semantics.values().iter().find_map(|row| match row.kind {
            SemanticValueKind::Parameter { ordinal, .. } if row.id == current => Some(ordinal),
            _ => None,
        });
        *request.budget = staged.budget;
        return Ok(SemanticOutcome::Complete {
            value: ordinal,
            work: staged.work,
        });
    }
    *request.budget = staged.budget;
    Ok(SemanticOutcome::Complete {
        value: None,
        work: staged.work,
    })
}

/// Whether `BIFROST_DEBUG_CHA` asks for the class-hierarchy dispatch trace.
/// Read once: the trace is a development aid, and re-reading the environment on
/// every call site of a corpus run would dominate the measurement it exists to
/// take.
#[doc(hidden)]
pub fn debug_cha_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("BIFROST_DEBUG_CHA").is_some())
}

#[doc(hidden)]
pub fn closed_dispatch_discharges_gap(candidates: &[DispatchCandidate], gap: &SemanticGap) -> bool {
    gap.capability == SemanticCapability::DynamicDispatch
        && !candidates.is_empty()
        && candidates.iter().all(|candidate| {
            candidate
                .target()
                .semantics()
                .properties()
                .dispatch_extensibility
                == DispatchExtensibility::Closed
        })
}

#[doc(hidden)]
pub fn resolver_proven_external_static_dispatch_discharges_gap(
    resolver_proven_external_static: bool,
    gap: &SemanticGap,
) -> bool {
    gap.capability == SemanticCapability::DynamicDispatch
        && matches!(
            gap.kind,
            SemanticGapKind::Unknown | SemanticGapKind::Unproven
        )
        && resolver_proven_external_static
}

/// Whether a retained candidate is a member callable, which is the only
/// callable an object receiver can select another body for.
///
/// The semantic model lowers a callable reached through a receiver as
/// [`ProcedureKind::Method`], including the out-of-line definition that
/// repeats its owner's qualified name through a namespace; a namespace or
/// file scope free function, where [`candidate_has_free_target`] answers
/// `false` because a namespace is not a type, lowers as a function. A free
/// function has no override set and the receiverless proof already covers its
/// exact call, so keeping this arm to members is what keeps the two proofs
/// from answering for each other. The other member kinds C++ can write --
/// constructors, operators, accessors -- keep the gap: their call sites are
/// not the plain member calls this proof is written for.
#[doc(hidden)]
pub fn candidate_is_type_owned_member(candidate: &DispatchCandidate) -> bool {
    matches!(candidate.target().semantics().kind(), ProcedureKind::Method)
}

/// Whether one Ruby call is written on a receiver the language itself fixes at
/// compile time.
///
/// A Ruby constant path is not a temporary: `Net::HTTP` evaluates the one
/// constant object the path names, so the member selected on it comes from
/// that object's own method set rather than from a receiver class only known
/// at run time. Other receiver spellings keep their blanket dynamic-dispatch
/// gap, because a Ruby receiver value's class can be anything a subclass,
/// mixin, or refinement supplies at run time.
#[doc(hidden)]
pub fn ruby_constant_receiver_selection(caller: &ProcedureHandle, gap: &SemanticGap) -> bool {
    matches!(
        caller.artifact().key().language(),
        LanguageDialect::Standard(Language::Ruby)
    ) && matches!(gap.subject, SemanticGapSubject::CallSite(id)
    if matches!(
        caller
            .semantics()
            .call_site(id)
            .and_then(|call_site| call_site.receiver)
            .and_then(|receiver| caller.semantics().value(receiver))
            .map(|value| &value.kind),
        Some(&SemanticValueKind::Constant)
    ))
}

/// Whether a retained candidate's target is a *free* callable: one that no type
/// or namespace owns, so no override of it can exist to enumerate.
///
/// The obvious spelling is the procedure kind, and for adapters that lower
/// their file-scope declarations as `Function` (Python, PHP, JavaScript) it is
/// enough. Ruby lowers every `def` as `ProcedureKind::Method`, including a
/// top-level `def` that is not a member of anything, so the kind alone would
/// keep every Ruby call open forever (#2637). The declaration path answers the
/// real question the kind is standing in for: a callable whose enclosing
/// segments contain no `Type` and no `Namespace` is declared directly in the
/// file, so it has no owning class or module, so it has no override set that
/// the proven candidate list could be missing. A `def` inside a Ruby `class`
/// or `module` body carries that ancestor segment and stays open here, which
/// is exactly the case a subclass can override.
///
/// The invariant this relies on: a procedure's *own* trailing segment is never
/// `Type` or `Namespace` -- those kinds name containers, not callables -- so
/// scanning the whole path is the same test as scanning the ancestors.
#[doc(hidden)]
pub fn candidate_has_free_target(candidate: &DispatchCandidate) -> bool {
    matches!(
        candidate.target().semantics().kind(),
        ProcedureKind::Function | ProcedureKind::LocalFunction
    ) || candidate
        .target()
        .semantics()
        .locator()
        .declaration()
        .segments()
        .iter()
        .all(|segment| {
            !matches!(
                segment.kind(),
                DeclarationSegmentKind::Type | DeclarationSegmentKind::Namespace
            )
        })
}

#[doc(hidden)]
pub fn candidate_matches_declared_target(
    caller: &ProcedureHandle,
    candidate: &DispatchCandidate,
    target: &CallableTarget,
) -> bool {
    match target {
        // The descriptor must be freshly rebound and materialized before a
        // candidate can carry artifact-backed execution provenance. Ordinary
        // locator matching cannot establish that proof.
        CallableTarget::Artifact(_) => false,
        CallableTarget::Local(id) => {
            candidate.target().artifact().key() == caller.artifact().key()
                && candidate.target().id() == *id
        }
        CallableTarget::Unmaterialized(locator) | CallableTarget::External(locator) => {
            let candidate_locator = candidate.target().semantics().locator();
            candidate_locator.path() == locator.path()
                && candidate_locator.declaration() == locator.declaration()
        }
    }
}

#[doc(hidden)]
pub fn merge_dispatch_quality(
    current: DispatchQuality,
    incoming: DispatchQuality,
) -> DispatchQuality {
    use crate::analyzer::semantic::workspace_oracle::dispatch::DispatchQuality::*;
    match (current, incoming) {
        (Cancelled, _) | (_, Cancelled) => Cancelled,
        (Truncated, _) | (_, Truncated) => Truncated,
        (Unsupported(capability), _) => Unsupported(capability),
        (_, Unsupported(capability)) => Unsupported(capability),
        (Unknown, _) | (_, Unknown) => Unknown,
        (Unproven, _) | (_, Unproven) => Unproven,
        (Ambiguous, _) | (_, Ambiguous) => Ambiguous,
        (Complete, Complete) => Complete,
    }
}

#[doc(hidden)]
pub fn low_level_dispatch_work(work: CallRelationWork) -> SemanticWork {
    SemanticWork {
        source_bytes: work.scanned_source_bytes,
        call_sites: usize::from(work.examined_candidates > 0),
        // Resolver rows are transient. Final retained candidates and
        // boundaries are charged exactly once after materialization.
        nested_entries: work.examined_candidates,
        ..SemanticWork::default()
    }
}

#[doc(hidden)]
pub const CANCELLED_TARGET_REASON: &str =
    "resolved target was not materialized because dispatch was cancelled";

#[doc(hidden)]
pub fn semantic_locator_work(locator: &SemanticLocator) -> SemanticWork {
    SemanticWork {
        nested_entries: locator.declaration().segments().len(),
        owned_text_bytes: locator
            .declaration()
            .segments()
            .iter()
            .filter_map(DeclarationSegment::name)
            .map(str::len)
            .fold(locator.path().as_str().len(), usize::saturating_add),
        ..SemanticWork::default()
    }
}

#[doc(hidden)]
pub fn dispatch_boundary_kind_locator_work(kind: &DispatchBoundaryKind) -> SemanticWork {
    match kind {
        DispatchBoundaryKind::External(Some(locator))
        | DispatchBoundaryKind::Unmaterialized(locator)
        | DispatchBoundaryKind::Deferred {
            target: locator, ..
        } => semantic_locator_work(locator),
        DispatchBoundaryKind::External(None)
        | DispatchBoundaryKind::Unresolved
        | DispatchBoundaryKind::Truncated => SemanticWork::default(),
    }
}

#[doc(hidden)]
pub fn source_budget_exceeded(
    request: &SemanticRequest<'_>,
    maximum_source_bytes: usize,
) -> (SemanticBudgetExceeded, SemanticWork) {
    let work = SemanticWork {
        source_bytes: maximum_source_bytes.saturating_add(1),
        ..SemanticWork::default()
    };
    let exceeded = request.budget.check_admission(work).map_or_else(
        |exceeded| exceeded,
        |_| unreachable!("bounded source omission must exceed the remaining budget"),
    );
    (exceeded, work)
}

#[doc(hidden)]
pub fn python_external_model_formals(signature: &Signature) -> Vec<FormalParameterSlot> {
    let call_range = Range {
        start_byte: 0,
        end_byte: 0,
        start_line: 0,
        end_line: 0,
    };
    signature
        .parameters
        .iter()
        .map(|parameter| {
            let passing_mode = match parameter.passing_mode {
                ParameterPassingMode::PositionalOnly => FormalParameterPassingMode::PositionalOnly,
                ParameterPassingMode::PositionalOrNamed => {
                    FormalParameterPassingMode::PositionalOrNamed
                }
                ParameterPassingMode::NamedOnly => FormalParameterPassingMode::NamedOnly,
            };
            FormalParameterSlot {
                names: parameter.name.clone().into_iter().collect(),
                declaration_range: call_range,
                receiver: false,
                variadic: parameter.variadic_kind(),
                passing_mode,
                default_range: parameter.optional.then_some(call_range),
            }
        })
        .collect()
}

#[doc(hidden)]
pub fn zero_source_anchor() -> SourceAnchor {
    let position = SourcePosition::new(0, 0, 0);
    let span = SourceSpan::new(position, position).expect("zero-width sentinel span is ordered");
    SourceAnchor::new(span, 0)
}

#[doc(hidden)]
pub fn proof_from_usage(proof: UsageProof) -> ProofStatus {
    match proof {
        UsageProof::Proven => ProofStatus::Proven,
        UsageProof::Unproven => ProofStatus::Unproven("dispatch target is ambiguous".into()),
    }
}

#[doc(hidden)]
pub fn completeness_from_usage(proof: UsageProof) -> EvidenceCompleteness {
    match proof {
        UsageProof::Proven => EvidenceCompleteness::Complete,
        UsageProof::Unproven => EvidenceCompleteness::Partial(
            "dispatch cannot prove one complete target identity".into(),
        ),
    }
}

#[doc(hidden)]
pub fn scoped_call_dispatch_gap<'a>(
    procedure: &'a ProcedureSemantics,
    call: &SemanticCallSite,
) -> Option<&'a SemanticGap> {
    scoped_dispatch_gap(procedure.gaps(), |gap| {
        gap.point == call.point
            && match gap.subject {
                SemanticGapSubject::Point => true,
                SemanticGapSubject::CallSite(call_site) => call_site == call.id,
                _ => false,
            }
    })
}

#[doc(hidden)]
pub fn scoped_procedure_dispatch_gap(procedure: &ProcedureHandle) -> Option<&SemanticGap> {
    scoped_dispatch_gap(procedure.semantics().gaps(), |gap| {
        gap.subject == SemanticGapSubject::Procedure
    })
}

fn scoped_dispatch_gap(
    gaps: &[SemanticGap],
    matches_scope: impl Fn(&SemanticGap) -> bool,
) -> Option<&SemanticGap> {
    gaps.iter()
        .filter(|gap| {
            gap.impacts.contains(SemanticGapImpact::DispatchCoverage) && matches_scope(gap)
        })
        .max_by_key(|gap| dynamic_dispatch_gap_rank(gap.kind))
}

fn dynamic_dispatch_gap_rank(kind: SemanticGapKind) -> u8 {
    match kind {
        SemanticGapKind::Unproven => 0,
        SemanticGapKind::Ambiguous => 1,
        SemanticGapKind::Unknown => 2,
        SemanticGapKind::Unsupported => 3,
        SemanticGapKind::ExceededBudget => 4,
    }
}

#[doc(hidden)]
pub fn dispatch_gap_quality(gap: &SemanticGap) -> DispatchQuality {
    match gap.kind {
        SemanticGapKind::Ambiguous => DispatchQuality::Ambiguous,
        SemanticGapKind::Unsupported => DispatchQuality::Unsupported(gap.capability),
        SemanticGapKind::ExceededBudget => DispatchQuality::Truncated,
        SemanticGapKind::Unknown | SemanticGapKind::Unproven => DispatchQuality::Unproven,
    }
}

#[doc(hidden)]
pub fn retain_dispatch_candidate(
    candidates: &mut Vec<DispatchCandidate>,
    indexes: &mut HashMap<ProcedureHandle, usize>,
    candidate: DispatchCandidate,
    max_candidates: usize,
) -> bool {
    if let Some(existing) = indexes
        .get(&candidate.target)
        .and_then(|index| candidates.get_mut(*index))
    {
        if matches!(candidate.proof, ProofStatus::Proven) {
            existing.proof = ProofStatus::Proven;
        }
        if matches!(candidate.completeness, EvidenceCompleteness::Complete) {
            existing.completeness = EvidenceCompleteness::Complete;
        }
        return false;
    }
    if candidates.len() >= max_candidates {
        return true;
    }
    indexes.insert(candidate.target.clone(), candidates.len());
    candidates.push(candidate);
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcedureRangeLookupStatus {
    Complete,
    BudgetExhausted,
    Cancelled,
    SourceChanged,
}

pub struct ProcedureRangeLookup {
    pub handles: Vec<ProcedureHandle>,
    pub examined: usize,
    pub status: ProcedureRangeLookupStatus,
}

#[doc(hidden)]
pub struct ProcedureLookupProgress<'a> {
    max_examined: usize,
    cancellation: &'a CancellationToken,
    #[doc(hidden)]
    pub examined: usize,
}

impl<'a> ProcedureLookupProgress<'a> {
    #[doc(hidden)]
    pub const fn new(max_examined: usize, cancellation: &'a CancellationToken) -> Self {
        Self {
            max_examined,
            cancellation,
            examined: 0,
        }
    }

    #[doc(hidden)]
    pub fn examine(&mut self) -> Result<(), ProcedureRangeLookupStatus> {
        self.examine_many(1)
    }

    /// Charge `count` examination steps at once.
    ///
    /// A caller that knows the cost of the whole unit it is about to inspect
    /// charges it here instead of looping over [`Self::examine`], so the
    /// budget sees one decision per unit.
    fn examine_many(&mut self, count: usize) -> Result<(), ProcedureRangeLookupStatus> {
        if self.cancellation.is_cancelled() {
            return Err(ProcedureRangeLookupStatus::Cancelled);
        }
        let examined = self.examined.saturating_add(count);
        if examined > self.max_examined {
            return Err(ProcedureRangeLookupStatus::BudgetExhausted);
        }
        self.examined = examined;
        Ok(())
    }

    #[doc(hidden)]
    pub const fn remaining(&self) -> usize {
        self.max_examined.saturating_sub(self.examined)
    }

    #[doc(hidden)]
    pub fn failed(&self, status: ProcedureRangeLookupStatus) -> ProcedureRangeLookup {
        ProcedureRangeLookup {
            handles: Vec::new(),
            examined: self.examined,
            status,
        }
    }
}

#[doc(hidden)]
pub fn content_identity_with_progress(
    source: &str,
    progress: &mut ProcedureLookupProgress<'_>,
) -> Result<ContentIdentity, ProcedureRangeLookupStatus> {
    const HASH_CHUNK_BYTES: usize = 64 * 1024;

    let mut digest = Sha256::new();
    if source.is_empty() {
        progress.examine()?;
    } else {
        for chunk in source.as_bytes().chunks(HASH_CHUNK_BYTES) {
            progress.examine()?;
            digest.update(chunk);
        }
    }
    let bytes: [u8; 32] = digest.finalize().into();
    Ok(ContentIdentity::from_digest(StableDigest::from_array(
        bytes,
    )))
}

#[doc(hidden)]
pub fn sort_procedures_by_locator<'a>(
    mut source: Vec<&'a ProcedureSemantics>,
    progress: &mut ProcedureLookupProgress<'_>,
) -> Result<Vec<&'a ProcedureSemantics>, ProcedureRangeLookupStatus> {
    let len = source.len();
    let mut width = 1usize;
    let mut target = Vec::with_capacity(len);
    while width < len {
        target.clear();
        let run_width = width.saturating_mul(2);
        for start in (0..len).step_by(run_width) {
            let middle = start.saturating_add(width).min(len);
            let end = start.saturating_add(run_width).min(len);
            let mut left = start;
            let mut right = middle;
            while left < middle && right < end {
                progress.examine()?;
                if source[left].locator() <= source[right].locator() {
                    target.push(source[left]);
                    left += 1;
                } else {
                    target.push(source[right]);
                    right += 1;
                }
            }
            while left < middle {
                progress.examine()?;
                target.push(source[left]);
                left += 1;
            }
            while right < end {
                progress.examine()?;
                target.push(source[right]);
                right += 1;
            }
        }
        std::mem::swap(&mut source, &mut target);
        width = run_width;
    }
    Ok(source)
}

pub fn procedures_for_source_ranges(
    artifact: &Arc<SemanticArtifact>,
    ranges: &[Range],
    max_examined: usize,
    cancellation: &CancellationToken,
) -> ProcedureRangeLookup {
    let mut progress = ProcedureLookupProgress::new(max_examined, cancellation);
    let mut exact = Vec::new();
    let mut enclosing = Vec::new();
    for procedure in artifact.procedures() {
        if let Err(status) = progress.examine() {
            return progress.failed(status);
        }
        let span = procedure
            .source_mappings()
            .iter()
            .find(|mapping| {
                mapping.kind == SourceMappingKind::Exact
                    && mapping.locator.role() == SemanticRole::SourceMapping
            })
            .map(|mapping| mapping.locator.anchor().span())
            .unwrap_or_else(|| procedure.locator().anchor().span());
        let mut exact_match = false;
        let mut enclosing_match = false;
        for range in ranges {
            if let Err(status) = progress.examine() {
                return progress.failed(status);
            }
            if range.start_byte < span.start_byte() as usize
                || (span.end_byte() as usize) < range.end_byte
            {
                continue;
            }
            let mut excluded = false;
            for hole in procedure.source_range_holes() {
                if let Err(status) = progress.examine() {
                    return progress.failed(status);
                }
                // A surrounding call or declaration can contain a nested
                // body's span and still be owned here. Exclude only inputs
                // inside that unlowered body, not their enclosing syntax.
                if hole.start_byte() as usize <= range.start_byte
                    && range.end_byte <= hole.end_byte() as usize
                {
                    excluded = true;
                    break;
                }
            }
            if excluded {
                continue;
            }
            if range.start_byte == span.start_byte() as usize
                && range.end_byte == span.end_byte() as usize
            {
                exact_match = true;
                break;
            }
            enclosing_match |= span.start_byte() as usize <= range.start_byte
                && span.end_byte() as usize >= range.end_byte;
        }
        if exact_match {
            exact.push(procedure);
        } else if enclosing_match {
            enclosing.push(procedure);
        }
    }
    let matches = if exact.is_empty() { enclosing } else { exact };
    let matches = match sort_procedures_by_locator(matches, &mut progress) {
        Ok(matches) => matches,
        Err(status) => return progress.failed(status),
    };
    let mut handles = Vec::with_capacity(matches.len());
    for procedure in matches {
        if let Err(status) = progress.examine() {
            return progress.failed(status);
        }
        if let Some(handle) = artifact.procedure_handle(procedure.id()) {
            handles.push(handle);
        }
    }
    ProcedureRangeLookup {
        handles,
        examined: progress.examined,
        status: ProcedureRangeLookupStatus::Complete,
    }
}

/// Every procedure in one file artifact, charged against the shared traversal
/// budget.
///
/// Policy call binding uses this instead of narrowing by procedure-anchor
/// containment. Narrowing loses calls in languages whose procedure anchors
/// cover only the declaration header: Ruby anchors `def name`, not the body,
/// so no procedure ever contains a body span (#1953 for taint, #1957 for
/// typestate). The call site's own source anchor, which the caller compares
/// when it selects a call, is the identity that decides the binding.
///
/// Each procedure costs `1 + call_sites().len()` because the caller inspects
/// every call site of every returned procedure.
pub fn procedures_in_artifact(
    artifact: &Arc<SemanticArtifact>,
    max_examined: usize,
    cancellation: &CancellationToken,
) -> ProcedureRangeLookup {
    let mut progress = ProcedureLookupProgress::new(max_examined, cancellation);
    let mut handles = Vec::with_capacity(artifact.procedures().len());
    for procedure in artifact.procedures() {
        if let Err(status) = progress.examine_many(1 + procedure.call_sites().len()) {
            return progress.failed(status);
        }
        handles.push(
            artifact
                .procedure_handle(procedure.id())
                .expect("validated artifact procedure has a scoped handle"),
        );
    }
    ProcedureRangeLookup {
        handles,
        examined: progress.examined,
        status: ProcedureRangeLookupStatus::Complete,
    }
}

#[doc(hidden)]
pub fn procedure_matches_definition(procedure: &ProcedureSemantics, definition: &CodeUnit) -> bool {
    if definition.is_class() {
        return procedure.kind() == ProcedureKind::Constructor;
    }
    if !definition.is_callable() {
        return false;
    }
    let Some(name) = procedure
        .locator()
        .declaration()
        .segments()
        .last()
        .and_then(DeclarationSegment::name)
    else {
        return definition.is_anonymous();
    };
    name == definition.identifier()
        || (procedure.kind() == ProcedureKind::Constructor && name == definition.short_name())
        // A JS/TS static member's declaration identity carries a `$static`
        // suffix (`read$static`); its semantic procedure is the class method
        // `read` with `is_static`. Both spellings assert the same fact, so
        // accept the stripped name exactly when the procedure declares static
        // (#2717).
        || (procedure.properties().is_static
            && definition
                .identifier()
                .strip_suffix("$static")
                .is_some_and(|stripped| name == stripped))
}

#[doc(hidden)]
pub fn agreed_external_formal_contract(
    metadata: impl IntoIterator<Item = brokk_bifrost_core::analyzer::model::SignatureMetadata>,
) -> Option<ExactExternalFormalContract> {
    let mut agreed = None;
    for candidate in metadata {
        let candidate = ExactExternalFormalContract::from_metadata(&candidate)?;
        match &agreed {
            None => agreed = Some(candidate),
            Some(existing) if existing == &candidate => {}
            Some(_) => return None,
        }
    }
    agreed
}

#[doc(hidden)]
pub fn source_anchor_for_range(
    source: &str,
    range: &Range,
) -> Result<SourceAnchor, SemanticProviderError> {
    let start = source_position(source, range.start_byte)?;
    let end = source_position(source, range.end_byte)?;
    let span = SourceSpan::new(start, end)
        .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    Ok(SourceAnchor::new(span, 0))
}

fn source_position(source: &str, offset: usize) -> Result<SourcePosition, SemanticProviderError> {
    if offset > source.len() || !source.is_char_boundary(offset) {
        return Err(SemanticProviderError::invalid_identity(
            "resolved declaration range is outside its UTF-8 source",
        ));
    }
    let bytes = source.as_bytes();
    let line_start = bytes[..offset]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |newline| newline.saturating_add(1));
    let line = bytes[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count();
    Ok(SourcePosition::new(
        u32::try_from(offset)
            .map_err(|_| SemanticProviderError::invalid_identity("source offset exceeds u32"))?,
        u32::try_from(line)
            .map_err(|_| SemanticProviderError::invalid_identity("source line exceeds u32"))?,
        u32::try_from(offset.saturating_sub(line_start))
            .map_err(|_| SemanticProviderError::invalid_identity("source column exceeds u32"))?,
    ))
}

#[doc(hidden)]
pub const fn dispatch_boundary_rank(kind: &DispatchBoundaryKind) -> u8 {
    match kind {
        DispatchBoundaryKind::External(_) => 0,
        DispatchBoundaryKind::Unmaterialized(_) => 1,
        DispatchBoundaryKind::Deferred { .. } => 2,
        DispatchBoundaryKind::Unresolved => 3,
        DispatchBoundaryKind::Truncated => 4,
    }
}

#[doc(hidden)]
pub fn compare_optional_locators(
    left: Option<&SemanticLocator>,
    right: Option<&SemanticLocator>,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => compare_locator_fields(left, right),
    }
}

#[doc(hidden)]
pub fn compare_locator_fields(left: &SemanticLocator, right: &SemanticLocator) -> Ordering {
    let left_anchor = left.anchor();
    let right_anchor = right.anchor();
    let left_span = left_anchor.span();
    let right_span = right_anchor.span();
    left.path()
        .cmp(right.path())
        .then_with(|| left_span.start_byte().cmp(&right_span.start_byte()))
        .then_with(|| left_span.end_byte().cmp(&right_span.end_byte()))
        .then_with(|| left_anchor.occurrence().cmp(&right_anchor.occurrence()))
        // Source anchors ordinarily distinguish dispatch targets. Retain the
        // locator's complete stable identity as a deterministic tie-breaker.
        .then_with(|| left.cmp(right))
}
