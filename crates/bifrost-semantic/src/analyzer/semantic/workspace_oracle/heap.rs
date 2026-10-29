//! Bounded point-sensitive heap, alias, and update-oracle materialization.
//!
//! The implementation follows semantic IR edges and effects only. It does not
//! reparse source, infer identities from names, or upgrade allocation-site
//! identities into runtime singletons.

use crate::analyzer::semantic::MemoryLocationKind;

use crate::analyzer::semantic::workspace_oracle::common::Interruption;

use crate::analyzer::semantic::workspace_oracle::common::WorkStager;

use crate::analyzer::semantic::workspace_oracle::common::dedup_evidence;

use crate::analyzer::semantic::workspace_oracle::common::evidence_handle;

use crate::analyzer::semantic::workspace_oracle::common::evidence_quality;

use crate::analyzer::semantic::workspace_oracle::common::internal_contract;

use crate::analyzer::semantic::workspace_oracle::common::value_flow_core_capabilities_are_open;

use crate::analyzer::semantic::workspace_oracle::value_flow::call_target_refinement_call;

use crate::analyzer::semantic::workspace_oracle::value_flow::is_go_assignment_conversion;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmBudget;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmRequest;

use crate::analyzer::semantic::cfg_algorithms::forward_reachability;

use crate::analyzer::semantic::cfg_algorithms::loop_regions;

use crate::analyzer::semantic::cfg_algorithms::reverse_reachability;

use crate::analyzer::semantic::AbstractLocation;

use crate::analyzer::semantic::AbstractObject;

use crate::analyzer::semantic::AbstractObjectIdentity;

use crate::analyzer::semantic::AccessPathAtPoint;

use crate::analyzer::semantic::AccessPathRoot;

use crate::analyzer::semantic::AliasExclusivity;

use crate::analyzer::semantic::AliasExclusivityWitness;

use crate::analyzer::semantic::AliasQuery;

use crate::analyzer::semantic::AliasRelation;

use crate::analyzer::semantic::AliasResult;

use crate::analyzer::semantic::CandidateCoverage;

use crate::analyzer::semantic::CaptureSource;

use crate::analyzer::semantic::EscapeStatus;

use crate::analyzer::semantic::EscapeWitness;

use crate::analyzer::semantic::EvidenceCompleteness;

use crate::analyzer::semantic::EvidenceHandle;

use crate::analyzer::semantic::FreshObjectPublication;

use crate::analyzer::semantic::FreshObjectPublicationKind;

use crate::analyzer::semantic::FreshObjectPublicationQuery;

use crate::analyzer::semantic::FreshObjectPublicationResult;

use crate::analyzer::semantic::LocationResult;

use crate::analyzer::semantic::ObjectCardinality;

use crate::analyzer::semantic::OracleCandidate;

use crate::analyzer::semantic::OracleRelationArena;

use crate::analyzer::semantic::OracleRelationId;

use crate::analyzer::semantic::OracleRelationKind;

use crate::analyzer::semantic::OracleRelationOwner;

use crate::analyzer::semantic::OracleRelationRecord;

use crate::analyzer::semantic::OracleSet;

use crate::analyzer::semantic::PointsToResult;

use crate::analyzer::semantic::ProcedureHandle;

use crate::analyzer::semantic::ProcedurePortHandle;

use crate::analyzer::semantic::ProcedurePortKind;

use crate::analyzer::semantic::ProofStatus;

use crate::analyzer::semantic::SemanticCallSite;

use crate::analyzer::semantic::SemanticCapability;

use crate::analyzer::semantic::SemanticEffect;

use crate::analyzer::semantic::SemanticGap;

use crate::analyzer::semantic::SemanticGapDischarge;

use crate::analyzer::semantic::SemanticGapImpact;

use crate::analyzer::semantic::SemanticGapSubject;

use crate::analyzer::semantic::SemanticOutcome;

use crate::analyzer::semantic::SemanticProviderError;

use crate::analyzer::semantic::SemanticValueKind;

use crate::analyzer::semantic::SemanticWork;

use crate::analyzer::semantic::StoreAtPoint;

use crate::analyzer::semantic::StrongUpdateEvidence;

use crate::analyzer::semantic::TransferKind;

use crate::analyzer::semantic::UpdateEligibility;

use crate::analyzer::semantic::ValueAtPoint;

use crate::analyzer::semantic::ValueFlowKind;

use crate::analyzer::semantic::ValueHandle;

use crate::analyzer::semantic::WeakUpdateReason;

use crate::analyzer::semantic::assignment_transfer;

use crate::analyzer::semantic_model::CompiledProcedureSummary;

use crate::analyzer::semantic_model::CompiledSummaryEffect;

use crate::analyzer::semantic_model::CompiledSummaryExitKind;

use crate::analyzer::semantic_model::CompiledSummaryInput;

use crate::analyzer::semantic_model::CompiledSummaryOutput;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;
use std::sync::Arc;

#[derive(Clone)]
#[doc(hidden)]
pub struct ObjectDraft {
    #[doc(hidden)]
    pub object: AbstractObject,
    #[doc(hidden)]
    pub evidence: Vec<EvidenceHandle>,
    #[doc(hidden)]
    pub proof: ProofStatus,
    #[doc(hidden)]
    pub completeness: EvidenceCompleteness,
    #[doc(hidden)]
    pub runtime_read: Option<crate::analyzer::semantic::RuntimeReadRelationEvidence>,
}

#[doc(hidden)]
pub fn transfer_stops_identity_trace(
    effect: &SemanticEffect,
    value: crate::analyzer::semantic::ValueId,
) -> bool {
    matches!(
        effect,
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Transfer(transfer),
            source,
            target,
        } if *target == value
            || (*source == value && matches!(transfer.kind, TransferKind::Move { .. }))
    ) || matches!(
        effect,
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::ReferenceBoxing | ValueFlowKind::ReferenceUnboxing,
            source,
            target,
        } if *source == value || *target == value
    )
}

#[derive(Clone)]
#[doc(hidden)]
pub struct LocationDraft {
    #[doc(hidden)]
    pub location: AbstractLocation,
    #[doc(hidden)]
    pub evidence: Vec<EvidenceHandle>,
    #[doc(hidden)]
    pub proof: ProofStatus,
    #[doc(hidden)]
    pub completeness: EvidenceCompleteness,
}

#[derive(Clone)]
#[doc(hidden)]
pub struct PublicationDraft {
    publication: FreshObjectPublication,
    #[doc(hidden)]
    pub evidence: Vec<EvidenceHandle>,
    #[doc(hidden)]
    pub proof: ProofStatus,
    #[doc(hidden)]
    pub completeness: EvidenceCompleteness,
}

#[doc(hidden)]
pub struct DraftSet<T> {
    #[doc(hidden)]
    pub candidates: Vec<T>,
    #[doc(hidden)]
    pub coverage: CandidateCoverage,
    #[doc(hidden)]
    pub ambiguous: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct TraceState {
    #[doc(hidden)]
    pub value: crate::analyzer::semantic::ValueId,
    #[doc(hidden)]
    pub point: crate::analyzer::semantic::ProgramPointId,
    #[doc(hidden)]
    pub event_limit: usize,
    /// Number of transitive value-flow producers followed from the queried
    /// value. Keeping this in the visited identity bounds value cycles while
    /// allowing a shallower route to the same semantic state to retain facts
    /// that a deeper, truncated route could not reach.
    #[doc(hidden)]
    pub summary_depth: usize,
    /// Quality forced by a finite runtime alternative. The alternatives are
    /// exhaustive when retained, but neither arm is selected by the IR.
    #[doc(hidden)]
    pub alternative_quality: Option<(ProofStatus, EvidenceCompleteness)>,
}

#[doc(hidden)]
pub fn merge_quality(
    left: &(ProofStatus, EvidenceCompleteness),
    right: &(ProofStatus, EvidenceCompleteness),
) -> (ProofStatus, EvidenceCompleteness) {
    let proof = if matches!(left.0, ProofStatus::Proven) {
        right.0.clone()
    } else {
        left.0.clone()
    };
    let completeness = if matches!(left.1, EvidenceCompleteness::Complete) {
        right.1.clone()
    } else {
        left.1.clone()
    };
    (proof, completeness)
}

#[doc(hidden)]
pub fn candidate_cardinality_for_root(root: &AccessPathRoot) -> ObjectCardinality {
    match root {
        AccessPathRoot::Static(_) | AccessPathRoot::LexicalCell(_) => ObjectCardinality::Singleton,
        AccessPathRoot::CaptureSlot(_) | AccessPathRoot::TypeSummary(_) => {
            ObjectCardinality::Summary
        }
        AccessPathRoot::Value(_)
        | AccessPathRoot::CallResult(_)
        | AccessPathRoot::ProcedurePort(_)
        | AccessPathRoot::Allocation(_)
        | AccessPathRoot::ModuleObject(_)
        | AccessPathRoot::External(_) => ObjectCardinality::Unknown,
        AccessPathRoot::FieldPath { base, .. } => candidate_cardinality_for_root(base),
        AccessPathRoot::CallSubstitution {
            base_cardinality, ..
        } => *base_cardinality,
        AccessPathRoot::RuntimeObject(root) => {
            if root.singleton_proven() {
                ObjectCardinality::Singleton
            } else {
                ObjectCardinality::Unknown
            }
        }
    }
}

#[doc(hidden)]
pub fn root_evidence(
    procedure: &ProcedureHandle,
    root: &AccessPathRoot,
) -> Result<Vec<EvidenceHandle>, SemanticProviderError> {
    if let AccessPathRoot::FieldPath { base, .. } = root {
        let base_procedure = base.scoped_procedure().unwrap_or(procedure);
        return root_evidence(base_procedure, base);
    }
    let evidence = match root {
        AccessPathRoot::Value(value) => procedure
            .semantics()
            .value(value.id())
            .map(|row| row.evidence),
        AccessPathRoot::CallResult(result) => procedure
            .semantics()
            .call_site(result.call().id())
            .map(|row| row.evidence),
        AccessPathRoot::Allocation(allocation) => procedure
            .semantics()
            .allocation(allocation.id())
            .map(|row| row.evidence),
        AccessPathRoot::LexicalCell(location) => procedure
            .semantics()
            .memory_location(location.id())
            .map(|row| row.evidence),
        AccessPathRoot::CaptureSlot(port) => match port.kind() {
            crate::analyzer::semantic::ProcedurePortKind::Capture { slot } => port
                .procedure()
                .semantics()
                .memory_location(slot)
                .map(|row| row.evidence),
            _ => None,
        },
        AccessPathRoot::ProcedurePort(port) => {
            let semantics = port.procedure().semantics();
            match port.kind() {
                crate::analyzer::semantic::ProcedurePortKind::IndexedNormalReturn { ordinal } => {
                    semantics
                        .points()
                        .iter()
                        .flat_map(|point| &point.events)
                        .find_map(|event| match event.effect {
                            SemanticEffect::ValueFlow {
                                kind:
                                    crate::analyzer::semantic::ValueFlowKind::IndexedReturn {
                                        ordinal: actual,
                                    },
                                target,
                                ..
                            } if actual == ordinal => {
                                semantics.value(target).map(|value| value.evidence)
                            }
                            _ => None,
                        })
                }
                kind => semantics
                    .values()
                    .iter()
                    .find(|value| match kind {
                        crate::analyzer::semantic::ProcedurePortKind::Receiver => {
                            matches!(value.kind, SemanticValueKind::Receiver { .. })
                        }
                        crate::analyzer::semantic::ProcedurePortKind::Parameter { ordinal } => {
                            matches!(
                                value.kind,
                                SemanticValueKind::Parameter { ordinal: actual, .. }
                                    if actual == ordinal
                            )
                        }
                        crate::analyzer::semantic::ProcedurePortKind::NormalReturn => {
                            value.kind == SemanticValueKind::Return
                        }
                        crate::analyzer::semantic::ProcedurePortKind::ExceptionalReturn => {
                            value.kind == SemanticValueKind::Exception
                        }
                        crate::analyzer::semantic::ProcedurePortKind::Capture { .. }
                        | crate::analyzer::semantic::ProcedurePortKind::IndexedNormalReturn {
                            ..
                        } => false,
                    })
                    .map(|value| value.evidence),
            }
        }
        AccessPathRoot::Static(_)
        | AccessPathRoot::TypeSummary(_)
        | AccessPathRoot::ModuleObject(_)
        | AccessPathRoot::External(_)
        | AccessPathRoot::RuntimeObject(_)
        | AccessPathRoot::CallSubstitution { .. } => Some(procedure.semantics().evidence()),
        AccessPathRoot::FieldPath { .. } => unreachable!("field-path evidence handled above"),
    };
    Ok(vec![evidence_handle(
        procedure,
        evidence.unwrap_or_else(|| procedure.semantics().evidence()),
    )?])
}

#[doc(hidden)]
pub fn gap_impacts_heap(gap: &SemanticGap) -> bool {
    gap.impacts.contains(SemanticGapImpact::HeapRead)
        || gap.impacts.contains(SemanticGapImpact::HeapWrite)
        || gap.impacts.contains(SemanticGapImpact::Aliasing)
}

/// Whether a modeled read partition leaves this exact allocation result's
/// object identity unchanged.
///
/// The missing read can still make values copied into the object incomplete;
/// it cannot change the identity created by the allocation at the same point.
/// Keep the discharge tied to all three structured facts so a general heap
/// read that produces a pointer remains relevant to points-to resolution.
#[doc(hidden)]
pub fn allocation_owns_modeled_read_partition(
    procedure: &ProcedureHandle,
    gap: &SemanticGap,
    value: crate::analyzer::semantic::ValueId,
) -> bool {
    gap.discharge == SemanticGapDischarge::ModeledEffectPartition
        && gap.impacts
            == crate::analyzer::semantic::SemanticGapImpacts::single(SemanticGapImpact::HeapRead)
        && gap.subject == SemanticGapSubject::Value(value)
        && procedure
            .semantics()
            .allocations()
            .iter()
            .any(|allocation| allocation.point == gap.point && allocation.result == value)
}

/// Whether `gap` can open a heap, alias, or points-to answer at all.
///
/// An adapter's implicit-abort gap states that a runtime operation's edge to
/// the exceptional exit is not lowered. Heap and points-to answers are may
/// analyses, so a missing edge can only remove paths from them -- unless a
/// handler or cleanup body on some abort path runs user code, which is the one
/// way the removed path could have carried a store. That is exactly the rule
/// the value-flow plan already applies to the same gap (#1952); applying it
/// here keeps one rule instead of two, and stops an adapter that scopes its
/// implicit-abort gap to the program point, as JavaScript, C# and Python do,
/// from opening every traced value in the procedure (#2495).
///
/// `abort_user_code` memoizes the CFG walk: the answer is a property of the
/// procedure, and most gaps never reach the question.
#[doc(hidden)]
pub fn gap_can_open_heap(
    procedure: &ProcedureHandle,
    gap: &SemanticGap,
    abort_user_code: &mut Option<bool>,
) -> bool {
    if !gap_impacts_heap(gap) {
        return false;
    }
    if gap.capability != SemanticCapability::ExceptionalControlFlow {
        return true;
    }
    let user_code = *abort_user_code.get_or_insert_with(|| {
        crate::analyzer::semantic::workspace_oracle::abort_paths_run_user_code(
            procedure.semantics(),
        )
    });
    !crate::analyzer::semantic::workspace_oracle::implicit_abort_gap_is_discharged(gap, user_code)
}

#[doc(hidden)]
pub fn heap_gaps_are_open(
    procedure: &ProcedureHandle,
    staged: &mut WorkStager,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    mut relevant: impl FnMut(&SemanticGap) -> bool,
) -> Result<bool, Interruption> {
    let mut open = false;
    let mut abort_user_code = None;
    for gap in procedure.semantics().gaps() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge_work(SemanticWork {
            gaps: 1,
            ..SemanticWork::default()
        });
        open |= relevant(gap) && gap_can_open_heap(procedure, gap, &mut abort_user_code);
    }
    Ok(open)
}

#[doc(hidden)]
pub fn traced_gap_affects_value(
    procedure: &ProcedureHandle,
    gap: &SemanticGap,
    value: crate::analyzer::semantic::ValueId,
    staged: &mut WorkStager,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<bool, InterruptionOrProvider> {
    if cancellation.is_cancelled() {
        return Err(InterruptionOrProvider::Interruption(
            Interruption::Cancelled,
        ));
    }
    Ok(match gap.subject {
        // Procedure gaps are handled before tracing because they apply even
        // when an exact producer cuts the trace short.
        SemanticGapSubject::Procedure => false,
        SemanticGapSubject::Point
        | SemanticGapSubject::CallContinuation { .. }
        | SemanticGapSubject::AsyncContinuation { .. } => true,
        SemanticGapSubject::Value(subject) => subject == value,
        SemanticGapSubject::MemoryLocation(location) => {
            staged.charge_work(SemanticWork {
                memory_locations: 1,
                ..SemanticWork::default()
            });
            let _location = procedure
                .semantics()
                .memory_location(location)
                .ok_or_else(|| {
                    InterruptionOrProvider::Provider(SemanticProviderError::internal(
                        "semantic gap has a stale memory location",
                    ))
                })?;
            // A location's base and index determine which cell an operation
            // addresses; uncertainty about that cell does not flow backward
            // into either operand's own pointee identity. A MemoryLoad opens
            // its result explicitly when this trace reaches the load effect.
            // Location and alias queries retain the gap independently.
            false
        }
        SemanticGapSubject::Capture(capture) => {
            staged.charge_work(SemanticWork {
                captures: 1,
                ..SemanticWork::default()
            });
            let capture = procedure.semantics().capture(capture).ok_or_else(|| {
                InterruptionOrProvider::Provider(SemanticProviderError::internal(
                    "semantic gap has a stale capture binding",
                ))
            })?;
            let captured_value = match capture.captured {
                CaptureSource::Value(captured) => captured == value,
                CaptureSource::Location(location) => {
                    staged.charge_work(SemanticWork {
                        memory_locations: 1,
                        ..SemanticWork::default()
                    });
                    procedure
                        .semantics()
                        .memory_location(location)
                        .is_some_and(|location| location.kind.uses_value(value))
                }
            };
            staged.charge_work(SemanticWork {
                allocations: 1,
                ..SemanticWork::default()
            });
            let environment_value = procedure
                .semantics()
                .allocation(capture.environment)
                .is_some_and(|allocation| allocation.result == value);
            capture.callable == value || captured_value || environment_value
        }
        SemanticGapSubject::CallSite(call_site) => {
            staged.charge_work(SemanticWork {
                call_sites: 1,
                ..SemanticWork::default()
            });
            let call = procedure.semantics().call_site(call_site).ok_or_else(|| {
                InterruptionOrProvider::Provider(SemanticProviderError::internal(
                    "semantic gap has a stale call site",
                ))
            })?;
            // A call-site gap can weaken values produced by the call without
            // weakening caller-side values that were evaluated before it.
            // Adapters attach CallEvaluation explicitly when the callee,
            // receiver, or argument evaluation is itself incomplete.
            if call.normal_result_values().any(|result| result == value)
                || call.thrown == Some(value)
            {
                true
            } else if gap.impacts.contains(SemanticGapImpact::CallEvaluation) {
                if call.callee == value || call.receiver == Some(value) {
                    return Ok(true);
                }
                let mut argument_matches = false;
                for argument in &call.arguments {
                    if cancellation.is_cancelled() {
                        return Err(InterruptionOrProvider::Interruption(
                            Interruption::Cancelled,
                        ));
                    }
                    staged.charge_work(SemanticWork {
                        nested_entries: 1,
                        ..SemanticWork::default()
                    });
                    if argument.value == value {
                        argument_matches = true;
                        break;
                    }
                }
                argument_matches
            } else {
                false
            }
        }
    })
}

/// Whether call-result materialization owns the answer to this refinement gap.
///
/// The backward trace encounters a call's generic target-refinement gap before
/// it invokes `materialize_call_result`. Opening the result at that point would
/// make the later complete dispatch, binding, and callee-flow proof unable to
/// close coverage. Defer only this exact result-value question to the
/// materializer. It retains open coverage for unresolved, external, ambiguous,
/// or otherwise incomplete callees, while gaps on the callee value, receiver,
/// arguments, and thrown value keep their ordinary heap meaning.
#[doc(hidden)]
pub fn call_result_materialization_owns_gap(
    procedure: &ProcedureHandle,
    gap: &SemanticGap,
    value: crate::analyzer::semantic::ValueId,
) -> bool {
    call_target_refinement_call(procedure.semantics(), gap)
        .and_then(|call| procedure.semantics().call_site(call))
        .is_some_and(|call| call.normal_result_values().any(|result| result == value))
}

#[doc(hidden)]
pub fn complete_external_summary_escapes_value(
    summary: &CompiledProcedureSummary,
    call_row: &SemanticCallSite,
    value: crate::analyzer::semantic::ValueId,
) -> bool {
    let inputs = std::iter::once((CompiledSummaryInput::Receiver {}, call_row.receiver)).chain(
        call_row
            .arguments
            .iter()
            .enumerate()
            .filter_map(|(ordinal, argument)| {
                Some((
                    CompiledSummaryInput::Parameter {
                        ordinal: u32::try_from(ordinal).ok()?,
                    },
                    Some(argument.value),
                ))
            }),
    );
    inputs
        .filter(|(_, actual)| *actual == Some(value))
        .any(|(input, _)| {
            summary.effects.iter().any(|effect| {
                matches!(
                    effect,
                    CompiledSummaryEffect::Escape {
                        input: escaped_input,
                        ..
                    } if *escaped_input == input
                )
            })
        })
}

#[doc(hidden)]
pub fn complete_external_summary_preserves_receiver(
    summary: &CompiledProcedureSummary,
    call_row: &SemanticCallSite,
    value: crate::analyzer::semantic::ValueId,
) -> bool {
    call_row.receiver == Some(value)
        && summary.transfers.iter().any(|transfer| {
            transfer.exit_kind == CompiledSummaryExitKind::Normal
                && matches!(transfer.input, CompiledSummaryInput::Receiver {})
                && matches!(
                    transfer.output,
                    CompiledSummaryOutput::NormalReturn {} | CompiledSummaryOutput::Receiver {}
                )
        })
}

#[doc(hidden)]
pub fn points_to_capabilities_are_open(procedure: &ProcedureHandle) -> bool {
    let capabilities = procedure.artifact().capabilities();
    value_flow_core_capabilities_are_open(procedure)
        || !capabilities.is_available(SemanticCapability::Captures)
}

#[doc(hidden)]
pub fn points_to_capability_surface_is_incomplete(procedure: &ProcedureHandle) -> bool {
    let capabilities = procedure.artifact().capabilities();
    [
        SemanticCapability::Values,
        SemanticCapability::Assignments,
        SemanticCapability::Allocations,
        SemanticCapability::LocalFlow,
        SemanticCapability::ParameterFlow,
        SemanticCapability::ReceiverFlow,
        SemanticCapability::ReturnFlow,
        SemanticCapability::Captures,
    ]
    .into_iter()
    .any(|capability| !capabilities.is_complete(capability))
}

#[doc(hidden)]
pub fn location_capabilities_are_open(access: &AccessPathAtPoint) -> bool {
    let procedure = access.point().procedure();
    let capabilities = procedure.artifact().capabilities();
    points_to_capabilities_are_open(procedure)
        || matches!(access.path().root(), AccessPathRoot::Static(_))
            && !capabilities.is_available(SemanticCapability::StaticMemory)
        || access
            .path()
            .selectors()
            .iter()
            .any(|selector| match selector {
                crate::analyzer::semantic::AccessSelector::Field(_)
                | crate::analyzer::semantic::AccessSelector::Property(_) => {
                    !capabilities.is_available(SemanticCapability::FieldMemory)
                }
                crate::analyzer::semantic::AccessSelector::Index(_) => {
                    !capabilities.is_available(SemanticCapability::IndexMemory)
                }
            })
}

/// Cyclic control-flow membership for one procedure, derived once per query.
///
/// `loop_regions` (#2102) is the workspace's one loop-membership algorithm and
/// it is SCC-based, so it names an irreducible cycle as well as a natural loop.
/// Membership is the whole allocation-cardinality question: a site inside a
/// cyclic region runs an unbounded number of times per activation, so its
/// abstraction summarizes many runtime objects, while a site outside every
/// cyclic region runs at most once. The region's back edges are the exact
/// evidence for that claim, which a per-allocation reachability walk could only
/// approximate with every edge it happened to visit.
#[doc(hidden)]
pub struct CyclicRegions {
    region_by_point: Box<[Option<usize>]>,
    back_edge_evidence: Box<[Box<[crate::analyzer::semantic::EvidenceId]>]>,
}

impl CyclicRegions {
    /// Evidence that the allocation point is inside a cyclic region, or `None`
    /// when it is not.
    fn cycle_evidence(
        &self,
        point: crate::analyzer::semantic::ProgramPointId,
    ) -> Option<&[crate::analyzer::semantic::EvidenceId]> {
        self.region_by_point
            .get(point.index())
            .copied()
            .flatten()
            .map(|region| self.back_edge_evidence[region].as_ref())
    }
}

/// Derive cyclic membership, or `None` when the bounded algorithm could not
/// answer. A caller that receives `None` must not claim a singleton.
fn cyclic_regions(
    procedure: &ProcedureHandle,
    staged: &mut WorkStager,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<Option<CyclicRegions>, Interruption> {
    let semantics = procedure.semantics();
    staged.charge_work(SemanticWork {
        program_points: semantics.points().len(),
        control_edges: semantics.control_edges().len(),
        ..SemanticWork::default()
    });
    let mut budget = CfgAlgorithmBudget::default();
    let regions = match loop_regions(
        semantics,
        &mut CfgAlgorithmRequest::new(&mut budget, cancellation),
    ) {
        Ok(regions) => regions,
        Err(CfgAlgorithmError::Cancelled { .. }) => return Err(Interruption::Cancelled),
        Err(CfgAlgorithmError::ExceededBudget(_) | CfgAlgorithmError::InvalidNode(_)) => {
            return Ok(None);
        }
    };
    let mut region_by_point = vec![None; semantics.points().len()];
    let mut back_edge_evidence = Vec::with_capacity(regions.regions.len());
    for (index, region) in regions.regions.iter().enumerate() {
        for member in &region.members {
            region_by_point[member.index()] = Some(index);
        }
        back_edge_evidence.push(
            region
                .back_edges
                .iter()
                .filter_map(|edge| semantics.control_edge(*edge).map(|row| row.evidence))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
    }
    Ok(Some(CyclicRegions {
        region_by_point: region_by_point.into_boxed_slice(),
        back_edge_evidence: back_edge_evidence.into_boxed_slice(),
    }))
}

/// Whether a closure publishes this allocation outside its own activation.
///
/// A captured allocation is reachable from another procedure's activation, and
/// this procedure's loop and recursion evidence says nothing about how many
/// times that activation ran the site. The same rule already makes a
/// [`AccessPathRoot::CaptureSlot`] root a summary object; applying it to the
/// allocation the capture names keeps the two answers consistent.
#[doc(hidden)]
pub fn allocation_is_captured(
    procedure: &ProcedureHandle,
    allocation: crate::analyzer::semantic::AllocationId,
    result: crate::analyzer::semantic::ValueId,
) -> bool {
    procedure.semantics().captures().iter().any(|capture| {
        capture.environment == allocation
            || capture.callable == result
            || match capture.captured {
                CaptureSource::Value(value) => value == result,
                CaptureSource::Location(location) => procedure
                    .semantics()
                    .memory_location(location)
                    .is_some_and(|row| row.kind.uses_value(result)),
            }
    })
}

fn push_object(
    drafts: &mut Vec<ObjectDraft>,
    object: AbstractObject,
    evidence: Vec<EvidenceHandle>,
) {
    let evidence = dedup_evidence(evidence);
    let quality = evidence_quality(&evidence);
    push_object_with_quality(drafts, object, evidence, quality);
}

#[doc(hidden)]
pub fn push_object_with_quality(
    drafts: &mut Vec<ObjectDraft>,
    object: AbstractObject,
    evidence: Vec<EvidenceHandle>,
    quality: (ProofStatus, EvidenceCompleteness),
) {
    let evidence = dedup_evidence(evidence);
    let quality = merge_quality(&quality, &evidence_quality(&evidence));
    if let Some(existing) = drafts
        .iter_mut()
        .find(|candidate| candidate.object == object)
    {
        existing.evidence = dedup_evidence(existing.evidence.iter().cloned().chain(evidence));
        let merged = merge_quality(
            &(existing.proof.clone(), existing.completeness.clone()),
            &quality,
        );
        existing.proof = merged.0;
        existing.completeness = merged.1;
    } else {
        drafts.push(ObjectDraft {
            object,
            evidence,
            proof: quality.0,
            completeness: quality.1,
            runtime_read: None,
        });
    }
}

#[doc(hidden)]
pub fn push_trace_object(
    drafts: &mut Vec<ObjectDraft>,
    object: AbstractObject,
    evidence: Vec<EvidenceHandle>,
    alternative_quality: &Option<(ProofStatus, EvidenceCompleteness)>,
) {
    if let Some(quality) = alternative_quality {
        push_object_with_quality(
            drafts,
            object,
            evidence.clone(),
            merge_quality(quality, &evidence_quality(&evidence)),
        );
    } else {
        push_object(drafts, object, evidence);
    }
}

#[doc(hidden)]
pub fn truncate_object_drafts(
    drafts: &mut Vec<ObjectDraft>,
    limits: crate::analyzer::semantic::OracleLimits,
) {
    drafts.truncate(limits.objects_per_value().min(limits.provenance_records()));
    let mut remaining_evidence = limits.evidence_handles();
    let mut retained = 0usize;
    for draft in drafts.iter_mut() {
        if remaining_evidence == 0 {
            break;
        }
        if draft.evidence.len() > remaining_evidence {
            draft.evidence.truncate(remaining_evidence);
            draft.completeness = EvidenceCompleteness::Partial(
                "points-to provenance was truncated by the oracle evidence limit".into(),
            );
        }
        remaining_evidence = remaining_evidence.saturating_sub(draft.evidence.len());
        retained += 1;
    }
    drafts.truncate(retained);
}

#[doc(hidden)]
pub fn symbolic_object(
    procedure: &ProcedureHandle,
    value: ValueHandle,
    evidence: Vec<EvidenceHandle>,
) -> Result<ObjectDraft, SemanticProviderError> {
    let row = procedure
        .semantics()
        .value(value.id())
        .ok_or_else(|| SemanticProviderError::internal("value handle is stale"))?;
    let identity = match &row.kind {
        SemanticValueKind::Parameter { ordinal, .. } => AbstractObjectIdentity::ProcedurePort(
            ProcedurePortHandle::parameter(procedure.clone(), *ordinal)
                .map_err(|error| internal_contract("invalid parameter object", error))?,
        ),
        SemanticValueKind::Receiver { .. } => AbstractObjectIdentity::ProcedurePort(
            ProcedurePortHandle::receiver(procedure.clone())
                .map_err(|error| internal_contract("invalid receiver object", error))?,
        ),
        _ => AbstractObjectIdentity::Value(value),
    };
    let object = AbstractObject::new(identity, ObjectCardinality::Unknown)
        .map_err(|error| internal_contract("invalid symbolic object", error))?;
    let evidence = dedup_evidence(evidence);
    let quality = evidence_quality(&evidence);
    Ok(ObjectDraft {
        object,
        evidence,
        proof: quality.0,
        completeness: quality.1,
        runtime_read: None,
    })
}

/// The evidence a reverse trace has collected on its way to a state.
///
/// A trace extends its evidence by one handle per step, so a copy per step costs
/// time quadratic in the trace length, and every store of a large array literal
/// traces back across the whole literal. The trail is a persistent list: a step
/// is one shared node, and the deduplicated, first-seen-ordered handles are
/// materialized only where a draft or a callee needs them.
#[derive(Clone, Default)]
#[doc(hidden)]
pub struct EvidenceTrail(Option<Arc<EvidenceTrailNode>>);

struct EvidenceTrailNode {
    parent: EvidenceTrail,
    handle: EvidenceHandle,
}

impl EvidenceTrail {
    #[doc(hidden)]
    pub fn with(self, handle: EvidenceHandle) -> Self {
        Self(Some(Arc::new(EvidenceTrailNode {
            parent: self,
            handle,
        })))
    }

    /// The trail's handles from the trace's start, each kept at its first
    /// occurrence.
    #[doc(hidden)]
    pub fn to_vec(&self) -> Vec<EvidenceHandle> {
        let mut newest_first = Vec::new();
        let mut node = self.0.as_deref();
        while let Some(current) = node {
            newest_first.push(&current.handle);
            node = current.parent.0.as_deref();
        }
        dedup_evidence(newest_first.into_iter().rev().cloned())
    }

    #[doc(hidden)]
    pub fn to_vec_with(&self, handle: EvidenceHandle) -> Vec<EvidenceHandle> {
        dedup_evidence(self.to_vec().into_iter().chain(std::iter::once(handle)))
    }
}

impl Drop for EvidenceTrailNode {
    /// Release a long trail iteratively so its drop does not recurse once per
    /// step.
    fn drop(&mut self) {
        let mut next = self.parent.0.take();
        while let Some(node) = next {
            match Arc::try_unwrap(node) {
                Ok(mut node) => next = node.parent.0.take(),
                Err(_) => break,
            }
        }
    }
}

/// How the evidence of the state a trace step produces relates to the evidence
/// the step inherited.
#[doc(hidden)]
pub enum ProducerEvidence {
    /// The produced state starts a new evidence trail.
    Fresh,
    /// The produced state continues the inherited trail with this handle.
    Extends(EvidenceHandle),
}

#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn allocation_object_draft(
    procedure: &ProcedureHandle,
    query: &ValueAtPoint,
    allocation: crate::analyzer::semantic::AllocationId,
    inherited_evidence: &[EvidenceHandle],
    event_evidence: EvidenceHandle,
    cyclic: &mut Option<Option<CyclicRegions>>,
    staged: &mut WorkStager,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<ObjectDraft, InterruptionOrProvider> {
    let allocation_row = procedure
        .semantics()
        .allocation(allocation)
        .ok_or_else(|| {
            InterruptionOrProvider::Provider(SemanticProviderError::internal(
                "allocation effect has a stale allocation ID",
            ))
        })?;
    staged.charge_work(SemanticWork {
        allocations: 1,
        ..SemanticWork::default()
    });
    if cyclic.is_none() {
        *cyclic = Some(
            cyclic_regions(procedure, staged, cancellation)
                .map_err(InterruptionOrProvider::Interruption)?,
        );
    }
    let regions = cyclic
        .as_ref()
        .expect("cyclic membership was derived above")
        .as_ref();
    let cycle_evidence = regions
        .and_then(|regions| regions.cycle_evidence(allocation_row.point))
        .map(<[_]>::to_vec);
    let handle = procedure.allocation_handle(allocation).ok_or_else(|| {
        InterruptionOrProvider::Provider(SemanticProviderError::internal(
            "allocation handle is stale",
        ))
    })?;
    let recursive_context = query
        .context()
        .calls()
        .iter()
        .any(|call| call.procedure() == procedure);
    let cardinality = if cycle_evidence.is_some() || recursive_context {
        ObjectCardinality::Summary
    } else if regions.is_some()
        && !allocation_is_captured(procedure, allocation, allocation_row.result)
    {
        ObjectCardinality::Singleton
    } else {
        ObjectCardinality::Unknown
    };
    let object = AbstractObject::new(AbstractObjectIdentity::Allocation(handle), cardinality)
        .map_err(|error| {
            InterruptionOrProvider::Provider(internal_contract("invalid allocation object", error))
        })?;
    let cycle_evidence = cycle_evidence
        .unwrap_or_default()
        .into_iter()
        .map(|id| evidence_handle(procedure, id))
        .collect::<Result<Vec<_>, _>>()
        .map_err(InterruptionOrProvider::Provider)?;
    let recursive_evidence = query
        .context()
        .calls()
        .iter()
        .filter(|call| call.procedure() == procedure)
        .map(|call| {
            let row = call
                .procedure()
                .semantics()
                .call_site(call.id())
                .ok_or_else(|| {
                    SemanticProviderError::internal(
                        "oracle call context contains a stale call site",
                    )
                })?;
            evidence_handle(call.procedure(), row.evidence)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(InterruptionOrProvider::Provider)?;
    let evidence = dedup_evidence(
        inherited_evidence
            .iter()
            .cloned()
            .chain([
                event_evidence,
                evidence_handle(procedure, allocation_row.evidence)
                    .map_err(InterruptionOrProvider::Provider)?,
            ])
            .chain(cycle_evidence)
            .chain(recursive_evidence),
    );
    let quality = evidence_quality(&evidence);
    Ok(ObjectDraft {
        object,
        evidence,
        proof: quality.0,
        completeness: quality.1,
        runtime_read: None,
    })
}

#[derive(Debug, Default)]
#[doc(hidden)]
pub struct CallResultResolution {
    #[doc(hidden)]
    pub open: bool,
    #[doc(hidden)]
    pub truncated: bool,
    #[doc(hidden)]
    pub ambiguous: bool,
}

impl CallResultResolution {
    #[doc(hidden)]
    pub fn absorb_coverage(&mut self, coverage: CandidateCoverage) {
        match coverage {
            CandidateCoverage::Exhaustive => {}
            CandidateCoverage::Open => self.open = true,
            CandidateCoverage::Truncated => self.truncated = true,
        }
    }
}

#[derive(Debug, Clone)]
#[doc(hidden)]
pub enum ModeledExternalCallResult {
    Fresh,
    Receiver(ValueHandle),
}

#[doc(hidden)]
pub fn outcome_is_open<T>(outcome: &SemanticOutcome<T>) -> bool {
    matches!(
        outcome,
        SemanticOutcome::Unknown { .. }
            | SemanticOutcome::Unsupported { .. }
            | SemanticOutcome::Unproven { .. }
    )
}

#[doc(hidden)]
pub fn outcome_is_ambiguous<T>(outcome: &SemanticOutcome<T>) -> bool {
    matches!(outcome, SemanticOutcome::Ambiguous { .. })
}

#[doc(hidden)]
pub fn outcome_interruption<T>(outcome: &SemanticOutcome<T>) -> Option<Interruption> {
    match outcome {
        SemanticOutcome::ExceededBudget { exceeded, .. } => Some(Interruption::Budget(*exceeded)),
        SemanticOutcome::Cancelled { .. } => Some(Interruption::Cancelled),
        SemanticOutcome::Complete { .. }
        | SemanticOutcome::Ambiguous { .. }
        | SemanticOutcome::Unknown { .. }
        | SemanticOutcome::Unsupported { .. }
        | SemanticOutcome::Unproven { .. } => None,
    }
}

/// Rust field identity is closed only when the adapter retained either the
/// declaration locator or its cross-file canonical AST-selector locator.
/// Other languages and unsupported Rust selectors keep their prior open
/// field-load behavior.
#[doc(hidden)]
pub fn rust_field_identity_is_supported(
    procedure: &ProcedureHandle,
    member: &crate::analyzer::semantic::SemanticLocator,
) -> bool {
    matches!(
        procedure.artifact().key().language(),
        crate::analyzer::semantic::SemanticLanguage::Standard(
            brokk_bifrost_core::analyzer::model::Language::Rust
        )
    ) && (member.is_artifact_independent_field()
        || member.declaration() != procedure.semantics().locator().declaration())
}

#[derive(Clone)]
#[doc(hidden)]
pub struct IncomingActualQuery {
    /// The caller storage whose address supplies a deferred receiver.
    pub addressed_root: Option<AccessPathRoot>,
    #[doc(hidden)]
    pub observation: ValueAtPoint,
    #[doc(hidden)]
    pub proof: ProofStatus,
    #[doc(hidden)]
    pub completeness: EvidenceCompleteness,
    #[doc(hidden)]
    pub identity_context: crate::analyzer::semantic::OracleCallContext,
}

#[doc(hidden)]
pub type IncomingActualKey = (
    (
        crate::analyzer::semantic::SemanticArtifactKey,
        crate::analyzer::semantic::ProcedureId,
    ),
    crate::analyzer::semantic::ValueId,
    crate::analyzer::semantic::OracleCallContext,
);

#[derive(Clone)]
#[doc(hidden)]
pub struct IncomingActualSet {
    #[doc(hidden)]
    pub candidates: Vec<IncomingActualQuery>,
    #[doc(hidden)]
    pub open: bool,
}

#[derive(Clone, Copy)]
#[doc(hidden)]
pub struct IncomingActualContext<'a> {
    #[doc(hidden)]
    pub query: &'a crate::analyzer::semantic::OracleCallContext,
    #[doc(hidden)]
    pub limits: crate::analyzer::semantic::OracleLimits,
    #[doc(hidden)]
    pub proven_incoming_relation: bool,
}

#[doc(hidden)]
pub fn substitute_object_into_callee(
    object: AbstractObject,
    procedure: &ProcedureHandle,
    context: &crate::analyzer::semantic::OracleCallContext,
) -> Result<AbstractObject, SemanticProviderError> {
    let base = object.identity().durable_identity().map_err(|error| {
        SemanticProviderError::internal(format!(
            "could not make incoming object identity durable: {error}"
        ))
    })?;
    let cardinality = object.cardinality();
    // The handle scope is rehomed to the result procedure. Keep the bounded
    // query context in the durable identity, while incoming edges only select
    // possible actuals; encoding each enumerated edge here would split one
    // caller object into several identities for a context-insensitive query.
    AbstractObject::new(
        AbstractObjectIdentity::CallSubstitution {
            procedure: procedure.clone(),
            context: context.clone(),
            base: Box::new(base),
            base_cardinality: cardinality,
        },
        cardinality,
    )
    .map_err(|error| internal_contract("invalid incoming object substitution", error))
}

#[doc(hidden)]
pub enum InterruptionOrProvider {
    Interruption(Interruption),
    Provider(SemanticProviderError),
}

impl From<Interruption> for InterruptionOrProvider {
    fn from(interruption: Interruption) -> Self {
        Self::Interruption(interruption)
    }
}

#[doc(hidden)]
pub fn materialize_points_to(
    query: &ValueAtPoint,
    drafts: DraftSet<ObjectDraft>,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<PointsToResult, SemanticProviderError> {
    let records = drafts
        .candidates
        .iter()
        .map(|draft| {
            OracleRelationRecord::new(OracleRelationKind::PointsTo, draft.evidence.clone(), limits)
                .map(|record| match &draft.runtime_read {
                    Some(evidence) => record.with_runtime_read(evidence.clone()),
                    None => record,
                })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| internal_contract("could not create points-to provenance", error))?;
    let arena = OracleRelationArena::new(
        OracleRelationOwner::PointsTo(Box::new(query.clone())),
        records,
        limits,
    )
    .map_err(|error| internal_contract("could not create points-to arena", error))?;
    let candidates = drafts
        .candidates
        .into_iter()
        .enumerate()
        .map(|(index, draft)| {
            let id = u32::try_from(index)
                .map(OracleRelationId::new)
                .map_err(|_| SemanticProviderError::internal("points-to relation ID overflow"))?;
            OracleCandidate::new(
                draft.object,
                draft.proof,
                draft.completeness,
                [arena
                    .handle(id)
                    .expect("points-to record was inserted into the arena")],
                limits,
            )
            .map_err(|error| internal_contract("invalid points-to candidate", error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    PointsToResult::new(query.clone(), candidates, drafts.coverage, limits)
        .map_err(|error| internal_contract("invalid points-to result", error))
}

#[doc(hidden)]
pub fn candidate_publication_work(candidate_count: usize, evidence_count: usize) -> SemanticWork {
    SemanticWork {
        evidence: evidence_count,
        nested_entries: candidate_count,
        ..SemanticWork::default()
    }
}

#[doc(hidden)]
pub fn materialize_locations(
    query: &AccessPathAtPoint,
    drafts: DraftSet<LocationDraft>,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<LocationResult, SemanticProviderError> {
    let records = drafts
        .candidates
        .iter()
        .map(|draft| {
            OracleRelationRecord::new(OracleRelationKind::Location, draft.evidence.clone(), limits)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| internal_contract("could not create location provenance", error))?;
    let arena = OracleRelationArena::new(
        OracleRelationOwner::Locations(Box::new(query.clone())),
        records,
        limits,
    )
    .map_err(|error| internal_contract("could not create location arena", error))?;
    let candidates = drafts
        .candidates
        .into_iter()
        .enumerate()
        .map(|(index, draft)| {
            let id = u32::try_from(index)
                .map(OracleRelationId::new)
                .map_err(|_| SemanticProviderError::internal("location relation ID overflow"))?;
            OracleCandidate::new(
                draft.location,
                draft.proof,
                draft.completeness,
                [arena
                    .handle(id)
                    .expect("location record was inserted into the arena")],
                limits,
            )
            .map_err(|error| internal_contract("invalid location candidate", error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    LocationResult::new(query.clone(), candidates, drafts.coverage, limits)
        .map_err(|error| internal_contract("invalid location result", error))
}

#[doc(hidden)]
pub fn candidates_proven_complete<T>(candidates: &[T], quality: impl Fn(&T) -> bool) -> bool {
    candidates.iter().all(quality)
}

#[doc(hidden)]
pub fn publish_set_outcome<T>(
    value: T,
    coverage: CandidateCoverage,
    proven_complete: bool,
    ambiguous: bool,
    interruption: Option<Interruption>,
    work: SemanticWork,
) -> SemanticOutcome<T> {
    match interruption {
        Some(Interruption::Budget(exceeded)) => SemanticOutcome::ExceededBudget {
            partial: Some(value),
            exceeded,
            work,
        },
        Some(Interruption::Cancelled) => SemanticOutcome::Cancelled {
            partial: Some(value),
            work,
        },
        None if coverage == CandidateCoverage::Truncated || !proven_complete => {
            SemanticOutcome::Unproven {
                partial: value,
                work,
            }
        }
        None if coverage == CandidateCoverage::Open => SemanticOutcome::Unknown {
            partial: Some(value),
            work,
        },
        None if ambiguous => SemanticOutcome::Ambiguous {
            candidates: value,
            work,
        },
        None => SemanticOutcome::Complete { value, work },
    }
}

fn paths_structurally_disjoint(left: &AbstractLocation, right: &AbstractLocation) -> bool {
    use crate::analyzer::semantic::workspace_oracle::heap::AbstractObjectIdentity as Identity;
    if left.object().identity() != right.object().identity() {
        return matches!(
            (left.object().identity(), right.object().identity()),
            (Identity::Allocation(_), Identity::Allocation(_))
                | (Identity::LexicalCell(_), Identity::LexicalCell(_))
                | (Identity::CaptureSlot(_), Identity::CaptureSlot(_))
                | (Identity::Static(_), Identity::Static(_))
                | (Identity::Allocation(_), Identity::LexicalCell(_))
                | (Identity::LexicalCell(_), Identity::Allocation(_))
                | (Identity::Allocation(_), Identity::CaptureSlot(_))
                | (Identity::CaptureSlot(_), Identity::Allocation(_))
                | (Identity::LexicalCell(_), Identity::CaptureSlot(_))
                | (Identity::CaptureSlot(_), Identity::LexicalCell(_))
        );
    }
    if !left.path().is_exact() || !right.path().is_exact() {
        return false;
    }
    left.path()
        .selectors()
        .iter()
        .zip(right.path().selectors())
        .find(|(left, right)| left != right)
        .is_some_and(|(left, right)| {
            matches!(
                (left, right),
                (
                    crate::analyzer::semantic::AccessSelector::Field(_),
                    crate::analyzer::semantic::AccessSelector::Field(_)
                ) | (
                    crate::analyzer::semantic::AccessSelector::Property(_),
                    crate::analyzer::semantic::AccessSelector::Property(_)
                )
            )
        })
}

#[doc(hidden)]
pub fn alias_relation(
    query: &AliasQuery,
    left: &DraftSet<LocationDraft>,
    right: &DraftSet<LocationDraft>,
) -> AliasRelation {
    let exhaustive = left.coverage == CandidateCoverage::Exhaustive
        && right.coverage == CandidateCoverage::Exhaustive
        && left.candidates.iter().all(|candidate| {
            matches!(candidate.proof, ProofStatus::Proven)
                && matches!(candidate.completeness, EvidenceCompleteness::Complete)
        })
        && right.candidates.iter().all(|candidate| {
            matches!(candidate.proof, ProofStatus::Proven)
                && matches!(candidate.completeness, EvidenceCompleteness::Complete)
        });
    if query.left() == query.right() {
        return AliasRelation::MustAlias;
    }
    if exhaustive
        && left.candidates.len() == 1
        && right.candidates.len() == 1
        && left.candidates[0].location == right.candidates[0].location
        && left.candidates[0].location.path().is_exact()
        && left.candidates[0].location.object().cardinality() == ObjectCardinality::Singleton
    {
        return AliasRelation::MustAlias;
    }
    if exhaustive
        && !left.candidates.is_empty()
        && !right.candidates.is_empty()
        && left.candidates.iter().all(|left| {
            right
                .candidates
                .iter()
                .all(|right| paths_structurally_disjoint(&left.location, &right.location))
        })
    {
        AliasRelation::Disjoint
    } else {
        AliasRelation::MayAlias
    }
}

#[doc(hidden)]
pub fn materialize_alias(
    query: &AliasQuery,
    relation: AliasRelation,
    evidence: Vec<EvidenceHandle>,
    quality: (ProofStatus, EvidenceCompleteness),
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<AliasResult, SemanticProviderError> {
    let record = OracleRelationRecord::new(OracleRelationKind::Alias, evidence, limits)
        .map_err(|error| internal_contract("could not create alias provenance", error))?;
    let arena = OracleRelationArena::new(
        OracleRelationOwner::Alias(Box::new(query.clone())),
        vec![record],
        limits,
    )
    .map_err(|error| internal_contract("could not create alias arena", error))?;
    let answer = OracleCandidate::new(
        relation,
        quality.0,
        quality.1,
        [arena
            .handle(OracleRelationId::new(0))
            .expect("alias record was inserted into the arena")],
        limits,
    )
    .map_err(|error| internal_contract("invalid alias answer", error))?;
    AliasResult::new(query.clone(), answer, limits)
        .map_err(|error| internal_contract("invalid alias result", error))
}

fn direct_weak_reasons(
    coverage: CandidateCoverage,
    locations: &[LocationDraft],
) -> Box<[WeakUpdateReason]> {
    let mut reasons = Vec::new();
    match coverage {
        CandidateCoverage::Exhaustive => {}
        CandidateCoverage::Open => {
            reasons.push(WeakUpdateReason::NonExhaustiveLocations);
            reasons.push(WeakUpdateReason::NonExhaustiveObjects);
        }
        CandidateCoverage::Truncated => {
            reasons.push(WeakUpdateReason::TruncatedLocations);
            reasons.push(WeakUpdateReason::TruncatedObjects);
        }
    }
    if locations.is_empty() {
        reasons.push(WeakUpdateReason::NoLocation);
        reasons.push(WeakUpdateReason::NoObject);
    }
    reasons.sort_unstable_by_key(|reason| *reason as u8);
    reasons.dedup();
    reasons.into_boxed_slice()
}

fn push_publication(
    drafts: &mut Vec<PublicationDraft>,
    publication: FreshObjectPublication,
    evidence: Vec<EvidenceHandle>,
    candidate_identity: bool,
) {
    let evidence = dedup_evidence(evidence);
    let mut quality = evidence_quality(&evidence);
    if candidate_identity {
        quality = merge_quality(
            &quality,
            &(
                ProofStatus::Unproven(
                    "fresh-object identity crosses a Go assignment conversion".into(),
                ),
                EvidenceCompleteness::Partial(
                    "fresh-object identity crosses a Go assignment conversion".into(),
                ),
            ),
        );
    }
    if let Some(existing) = drafts
        .iter_mut()
        .find(|candidate| candidate.publication == publication)
    {
        existing.evidence = dedup_evidence(existing.evidence.iter().cloned().chain(evidence));
        quality = merge_quality(
            &(existing.proof.clone(), existing.completeness.clone()),
            &quality,
        );
        existing.proof = quality.0;
        existing.completeness = quality.1;
    } else {
        drafts.push(PublicationDraft {
            publication,
            evidence,
            proof: quality.0,
            completeness: quality.1,
        });
    }
}

fn fresh_object_seed_value(
    query: &FreshObjectPublicationQuery,
) -> Option<crate::analyzer::semantic::ValueId> {
    let procedure = query.observation().procedure();
    match query.object().identity() {
        AccessPathRoot::Value(value) if value.procedure() == procedure => Some(value.id()),
        AccessPathRoot::Allocation(allocation) if allocation.procedure() == procedure => procedure
            .semantics()
            .allocation(allocation.id())
            .map(|row| row.result),
        AccessPathRoot::CallResult(result) if result.result().procedure() == procedure => {
            Some(result.result().id())
        }
        _ => None,
    }
}

#[doc(hidden)]
pub fn call_names_any(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    call: &SemanticCallSite,
    names: &HashSet<crate::analyzer::semantic::ValueId>,
) -> bool {
    first_call_name(semantics, call, names).is_some()
}

fn first_call_name(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    call: &SemanticCallSite,
    names: &HashSet<crate::analyzer::semantic::ValueId>,
) -> Option<crate::analyzer::semantic::ValueId> {
    std::iter::once(call.callee)
        .chain(call.receiver)
        .chain(call.arguments.iter().map(|argument| argument.value))
        .find(|value| names.contains(value))
        .or_else(|| {
            let selection = call.member_selection.as_ref()?;
            if selection
                .receiver_pointer_depth
                .is_some_and(|depth| depth > 0)
            {
                return None;
            }
            match selection.receiver_place.as_ref()? {
                crate::analyzer::semantic::SemanticPlace::MemoryLocation(location) => {
                    let kind = &semantics.memory_location(*location)?.kind;
                    names.iter().copied().find(|name| kind.uses_value(*name))
                }
                crate::analyzer::semantic::SemanticPlace::LocalBinding(expected) => {
                    names.iter().copied().find(|name| {
                        semantics
                            .value(*name)
                            .and_then(|value| semantics.source_mapping(value.source))
                            .is_some_and(|mapping| same_place_source(&mapping.locator, expected))
                    })
                }
            }
        })
}

fn same_place_source(
    actual: &crate::analyzer::semantic::SemanticLocator,
    expected: &crate::analyzer::semantic::SemanticLocator,
) -> bool {
    actual.mount() == expected.mount()
        && actual.path() == expected.path()
        && actual.language() == expected.language()
        && actual.declaration() == expected.declaration()
        && actual.anchor() == expected.anchor()
}

/// Convert a retained addressable frame place into its existing object root.
/// Complex places without an exact object root remain open in the caller.
#[doc(hidden)]
pub fn addressed_place_root(
    procedure: &ProcedureHandle,
    place: &crate::analyzer::semantic::SemanticPlace,
) -> Option<AccessPathRoot> {
    use crate::analyzer::semantic::{MemoryLocationKind, SemanticPlace};
    let semantics = procedure.semantics();
    let location = match place {
        SemanticPlace::MemoryLocation(location) => *location,
        SemanticPlace::LocalBinding(expected) => {
            let binding = semantics.values().iter().find(|value| {
                matches!(
                    value.kind,
                    crate::analyzer::semantic::SemanticValueKind::Local
                        | crate::analyzer::semantic::SemanticValueKind::Parameter { .. }
                        | crate::analyzer::semantic::SemanticValueKind::Receiver { .. }
                ) && semantics
                    .source_mapping(value.source)
                    .is_some_and(|mapping| same_place_source(&mapping.locator, expected))
            })?;
            semantics.binding_memory_location(binding.id)?
        }
    };
    match semantics.memory_location(location)?.kind {
        MemoryLocationKind::LexicalCell { .. } => Some(AccessPathRoot::LexicalCell(
            procedure.memory_location_handle(location)?,
        )),
        MemoryLocationKind::Capture { .. } => Some(AccessPathRoot::CaptureSlot(
            ProcedurePortHandle::new(
                procedure.clone(),
                ProcedurePortKind::Capture { slot: location },
            )
            .expect("a capture memory location has a capture port"),
        )),
        _ => None,
    }
}

/// An exact address of a frame place, with the alias and origin's own proof.
/// Pointer variables and offset/may aliases cannot establish this identity.
#[doc(hidden)]
pub fn exact_addressed_pointer_root(
    procedure: &ProcedureHandle,
    alias: &crate::analyzer::semantic::PointerAlias,
) -> Option<AccessPathRoot> {
    use crate::analyzer::semantic::{
        PointerByteOffset, PointerOriginKind, PointerRelationStrength, SemanticValueKind,
    };
    let semantics = procedure.semantics();
    if semantics.value(alias.pointer)?.kind != SemanticValueKind::Address
        || alias.byte_offset != PointerByteOffset::Exact(0)
        || alias.strength != PointerRelationStrength::Must
    {
        return None;
    }
    let origin = semantics.pointer_origins().get(alias.origin.index())?;
    for evidence in [alias.evidence, origin.evidence] {
        let evidence = semantics.evidence_row(evidence)?;
        if !evidence
            .proof
            .establishes_complete_evidence(&evidence.completeness)
        {
            return None;
        }
    }
    let PointerOriginKind::StackPlace { place } = &origin.kind else {
        return None;
    };
    addressed_place_root(procedure, place)
}

pub(super) fn effect_names_any(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    effect: &SemanticEffect,
    names: &HashSet<crate::analyzer::semantic::ValueId>,
) -> bool {
    match effect {
        SemanticEffect::Assignment { target, value } => {
            names.contains(target) || names.contains(value)
        }
        SemanticEffect::ValueFlow { source, target, .. } => {
            names.contains(source) || names.contains(target)
        }
        SemanticEffect::AggregateInitializer {
            aggregate, value, ..
        } => names.contains(aggregate) || names.contains(value),
        SemanticEffect::ValueUse { value, .. } => names.contains(value),
        SemanticEffect::MemoryLoad {
            location, result, ..
        } => {
            names.contains(result)
                || semantics
                    .memory_location(*location)
                    .is_some_and(|location| {
                        names.iter().any(|value| location.kind.uses_value(*value))
                    })
        }
        SemanticEffect::MemoryStore {
            location, value, ..
        } => {
            names.contains(value)
                || semantics
                    .memory_location(*location)
                    .is_some_and(|location| {
                        names.iter().any(|value| location.kind.uses_value(*value))
                    })
        }
        SemanticEffect::CallableCreation {
            result, callable, ..
        }
        | SemanticEffect::CallableReference {
            result, callable, ..
        } => {
            names.contains(result)
                || callable
                    .bound_receiver
                    .is_some_and(|receiver| names.contains(&receiver))
        }
        SemanticEffect::CaptureBind { capture } => semantics
            .captures()
            .iter()
            .find(|row| row.id == *capture)
            .is_some_and(|capture| match capture.captured {
                CaptureSource::Value(value) => names.contains(&value),
                CaptureSource::Location(location) => {
                    semantics.memory_location(location).is_some_and(|location| {
                        names.iter().any(|value| location.kind.uses_value(*value))
                    })
                }
            }),
        SemanticEffect::Invoke { call_site }
        | SemanticEffect::CallContinuation { call_site, .. } => semantics
            .call_site(*call_site)
            .is_some_and(|call| call_names_any(semantics, call, names)),
        SemanticEffect::ProcedureReturn { value } | SemanticEffect::Throw { value } => {
            value.is_some_and(|value| names.contains(&value))
        }
        SemanticEffect::AsyncSuspend { awaited, .. } => {
            awaited.is_some_and(|value| names.contains(&value))
        }
        SemanticEffect::AsyncResume { result, .. } => {
            result.is_some_and(|value| names.contains(&value))
        }
        SemanticEffect::Synchronization {
            subject, payload, ..
        } => {
            names.contains(subject)
                || matches!(payload, Some(crate::analyzer::semantic::SynchronizationPayload::Send { value, .. }) if names.contains(value))
        }
        SemanticEffect::Entry
        | SemanticEffect::NormalExit
        | SemanticEffect::ExceptionalExit
        | SemanticEffect::Allocation { .. }
        | SemanticEffect::Gap { .. } => false,
    }
}

#[doc(hidden)]
pub fn publication_gap_affects_names(
    procedure: &ProcedureHandle,
    gap: &SemanticGap,
    names: &HashSet<crate::analyzer::semantic::ValueId>,
) -> bool {
    let semantics = procedure.semantics();
    match gap.subject {
        SemanticGapSubject::Procedure => true,
        // A point-scoped gap is deliberately broader than its retained
        // events: the missing event may be the operation that publishes the
        // object. Only an explicit adapter-authored discharge can narrow it.
        SemanticGapSubject::Point => true,
        SemanticGapSubject::Value(value) => names.contains(&value),
        SemanticGapSubject::MemoryLocation(location) => semantics
            .memory_location(location)
            .is_some_and(|location| names.iter().any(|value| location.kind.uses_value(*value))),
        SemanticGapSubject::Capture(capture) => semantics
            .captures()
            .iter()
            .find(|row| row.id == capture)
            .is_some_and(|capture| match capture.captured {
                CaptureSource::Value(value) => names.contains(&value),
                CaptureSource::Location(location) => {
                    semantics.memory_location(location).is_some_and(|location| {
                        names.iter().any(|value| location.kind.uses_value(*value))
                    })
                }
            }),
        SemanticGapSubject::CallSite(call_site)
        | SemanticGapSubject::CallContinuation { call_site, .. } => semantics
            .call_site(call_site)
            .is_some_and(|call| call_names_any(semantics, call, names)),
        SemanticGapSubject::AsyncContinuation { suspend, .. } => {
            semantics.point(suspend).is_some_and(|point| {
                point
                    .events
                    .iter()
                    .any(|event| effect_names_any(semantics, &event.effect, names))
            })
        }
    }
}

/// Enumerate operations that can publish a fresh object's local aliases on
/// the CFG slice between ownership establishment and one observation.
#[doc(hidden)]
pub fn formal_value_id(
    procedure: &ProcedureHandle,
    kind: ProcedurePortKind,
) -> Option<crate::analyzer::semantic::ValueId> {
    procedure.semantics().values().iter().find_map(|value| {
        let matches = match kind {
            ProcedurePortKind::Receiver => {
                matches!(value.kind, SemanticValueKind::Receiver { .. })
            }
            ProcedurePortKind::Parameter { ordinal } => matches!(
                value.kind,
                SemanticValueKind::Parameter {
                    ordinal: actual,
                    ..
                } if actual == ordinal
            ),
            ProcedurePortKind::NormalReturn => value.kind == SemanticValueKind::Return,
            ProcedurePortKind::IndexedNormalReturn { .. }
            | ProcedurePortKind::ExceptionalReturn
            | ProcedurePortKind::Capture { .. } => false,
        };
        matches.then_some(value.id)
    })
}

#[doc(hidden)]
pub fn mapped_formals_for_actual(
    bindings: &crate::analyzer::semantic::CallBindings,
    actual: crate::analyzer::semantic::ValueId,
) -> Vec<ProcedurePortHandle> {
    let mut formals = Vec::new();
    for binding in bindings.bindings() {
        match binding {
            crate::analyzer::semantic::CallBinding::Receiver {
                actual: binding_actual,
                formal,
                ..
            } if binding_actual.id() == actual
                && !matches!(
                    bindings.candidate().member_receiver_preparation(),
                    Some(
                        crate::analyzer::semantic::MemberReceiverPreparation::CopyValue
                            | crate::analyzer::semantic::MemberReceiverPreparation::CopyPointee
                    )
                ) =>
            {
                formals.push(formal.clone())
            }
            crate::analyzer::semantic::CallBinding::ArgumentGroup(group) => {
                formals.extend(
                    group
                        .mappings()
                        .iter()
                        .filter(|mapping| {
                            mapping.value().actual().value().id() == actual
                                && mapping.value().preserves_reference_identity()
                                && mapping.is_proven_complete()
                        })
                        .map(|mapping| mapping.value().formal().clone()),
                );
            }
            crate::analyzer::semantic::CallBinding::ImplicitArgument { source, formal, .. }
                if source.id() == actual =>
            {
                formals.push(formal.clone())
            }
            crate::analyzer::semantic::CallBinding::NormalReturn { .. }
            | crate::analyzer::semantic::CallBinding::ExceptionalReturn { .. }
            | crate::analyzer::semantic::CallBinding::Receiver { .. }
            | crate::analyzer::semantic::CallBinding::ImplicitArgument { .. } => {}
        }
    }
    formals.dedup();
    formals
}

#[doc(hidden)]
pub fn resolve_fresh_object_publications(
    query: &FreshObjectPublicationQuery,
    limits: crate::analyzer::semantic::OracleLimits,
    staged: &mut WorkStager,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    mut private_cell_binding: impl FnMut(
        crate::analyzer::semantic::MemoryLocationId,
        &mut WorkStager,
    ) -> Result<
        Option<crate::analyzer::semantic::ValueId>,
        InterruptionOrProvider,
    >,
) -> Result<DraftSet<PublicationDraft>, InterruptionOrProvider> {
    let procedure = query.observation().procedure();
    let semantics = procedure.semantics();
    let Some(seed) = fresh_object_seed_value(query) else {
        return Ok(DraftSet {
            candidates: Vec::new(),
            coverage: CandidateCoverage::Open,
            ambiguous: false,
        });
    };
    if query.context().was_truncated() {
        return Ok(DraftSet {
            candidates: Vec::new(),
            coverage: CandidateCoverage::Open,
            ambiguous: false,
        });
    }

    staged.charge_work(SemanticWork {
        program_points: semantics.points().len().saturating_mul(2),
        control_edges: semantics.control_edges().len().saturating_mul(2),
        ..SemanticWork::default()
    });
    let mut cfg_budget = CfgAlgorithmBudget::default();
    let from_start = match forward_reachability(
        semantics,
        query.ownership_start().id(),
        &mut CfgAlgorithmRequest::new(&mut cfg_budget, cancellation),
    ) {
        Ok(reachability) => reachability,
        Err(CfgAlgorithmError::Cancelled { .. }) => {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        Err(CfgAlgorithmError::ExceededBudget(_) | CfgAlgorithmError::InvalidNode(_)) => {
            return Ok(DraftSet {
                candidates: Vec::new(),
                coverage: CandidateCoverage::Open,
                ambiguous: false,
            });
        }
    };
    let to_observation = match reverse_reachability(
        semantics,
        query.observation().id(),
        &mut CfgAlgorithmRequest::new(&mut cfg_budget, cancellation),
    ) {
        Ok(reachability) => reachability,
        Err(CfgAlgorithmError::Cancelled { .. }) => {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        Err(CfgAlgorithmError::ExceededBudget(_) | CfgAlgorithmError::InvalidNode(_)) => {
            return Ok(DraftSet {
                candidates: Vec::new(),
                coverage: CandidateCoverage::Open,
                ambiguous: false,
            });
        }
    };
    if !from_start.contains(semantics, query.observation().id()) {
        return Ok(DraftSet {
            candidates: Vec::new(),
            coverage: CandidateCoverage::Exhaustive,
            ambiguous: false,
        });
    }
    let in_slice = |point| {
        point != query.observation().id()
            && from_start.contains(semantics, point)
            && to_observation.contains(semantics, point)
    };

    // Ownership can be established by a guard after the fresh result was
    // copied into its local binding. Build the alias-name closure over every
    // predecessor of the observation, while publication candidates below
    // remain restricted to the post-ownership slice.
    let before_observation =
        |point| point != query.observation().id() && to_observation.contains(semantics, point);
    let root_evidence = root_evidence(procedure, query.object().identity())
        .map_err(InterruptionOrProvider::Provider)?;
    struct NameCopy {
        source: crate::analyzer::semantic::ValueId,
        target: crate::analyzer::semantic::ValueId,
        evidence: EvidenceHandle,
        identity_preserving: bool,
    }
    let mut copies = Vec::new();
    for point in semantics
        .points()
        .iter()
        .filter(|point| before_observation(point.id))
    {
        staged.charge_work(SemanticWork {
            program_points: 1,
            events: point.events.len(),
            ..SemanticWork::default()
        });
        if cancellation.is_cancelled() {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        for (event_index, event) in point.events.iter().enumerate() {
            match event.effect {
                SemanticEffect::Assignment { target, value }
                    if assignment_transfer(&point.events, event_index, value, target).is_none() =>
                {
                    copies.push(NameCopy {
                        source: value,
                        target,
                        evidence: evidence_handle(procedure, event.evidence)
                            .map_err(InterruptionOrProvider::Provider)?,
                        identity_preserving: true,
                    })
                }
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    source: value,
                    target,
                } => copies.push(NameCopy {
                    source: value,
                    target,
                    evidence: evidence_handle(procedure, event.evidence)
                        .map_err(InterruptionOrProvider::Provider)?,
                    identity_preserving: true,
                }),
                SemanticEffect::MemoryLoad {
                    location, result, ..
                } if matches!(
                    semantics
                        .memory_location(location)
                        .map(|location| &location.kind),
                    Some(MemoryLocationKind::LexicalCell { .. })
                ) =>
                {
                    if let Some(binding) = private_cell_binding(location, staged)? {
                        copies.push(NameCopy {
                            source: binding,
                            target: result,
                            evidence: evidence_handle(procedure, event.evidence)
                                .map_err(InterruptionOrProvider::Provider)?,
                            identity_preserving: true,
                        });
                    }
                }
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source,
                    target,
                } if is_go_assignment_conversion(semantics, target) => {
                    copies.push(NameCopy {
                        source,
                        target,
                        evidence: evidence_handle(procedure, event.evidence)
                            .map_err(InterruptionOrProvider::Provider)?,
                        // Go assignment conversion is structured dependence,
                        // not exact resource identity. Retain it as a
                        // candidate so a following field/index store cannot
                        // disappear, while keeping the published relation
                        // explicitly unproven and partial.
                        identity_preserving: false,
                    });
                }
                _ => {}
            }
        }
    }
    let mut name_exactness = HashMap::default();
    name_exactness.insert(seed, true);
    let mut name_evidence = HashMap::default();
    name_evidence.insert(seed, root_evidence);
    let mut pending = vec![seed];
    while let Some(current) = pending.pop() {
        staged.charge_work(SemanticWork {
            values: 1,
            ..SemanticWork::default()
        });
        let current_exact = *name_exactness
            .get(&current)
            .expect("pending publication name has an exactness row");
        for copy in &copies {
            if copy.source == current {
                let target_exact = current_exact && copy.identity_preserving;
                if name_exactness
                    .get(&copy.target)
                    .is_some_and(|existing| *existing || !target_exact)
                {
                    continue;
                }
                let evidence = dedup_evidence(
                    name_evidence
                        .get(&copy.source)
                        .into_iter()
                        .flatten()
                        .cloned()
                        .chain(std::iter::once(copy.evidence.clone())),
                );
                name_exactness.insert(copy.target, target_exact);
                name_evidence.insert(copy.target, evidence);
                pending.push(copy.target);
            }
        }
    }
    let exact_names = name_exactness
        .iter()
        .filter_map(|(name, exact)| exact.then_some(*name))
        .collect::<HashSet<_>>();
    let candidate_names = name_exactness
        .iter()
        .filter_map(|(name, exact)| (!exact).then_some(*name))
        .collect::<HashSet<_>>();
    let names = exact_names
        .iter()
        .chain(&candidate_names)
        .copied()
        .collect::<HashSet<_>>();

    let mut drafts = Vec::new();
    let mut open = false;
    let mut abort_user_code = None;
    for gap in semantics.gaps().iter().filter(|gap| in_slice(gap.point)) {
        staged.charge_work(SemanticWork {
            gaps: 1,
            ..SemanticWork::default()
        });
        // Publication asks whether the object crosses an effect boundary, not
        // which resolved target receives it or how retained evaluations are
        // ordered. Those two structured proof obligations are therefore
        // irrelevant; every other gap remains conservative.
        if gap.discharge != SemanticGapDischarge::RetainedEvaluationOrder
            && call_target_refinement_call(semantics, gap).is_none()
            && publication_gap_affects_names(procedure, gap, &names)
            && gap_can_open_heap(procedure, gap, &mut abort_user_code)
        {
            open = true;
        }
    }
    for point in semantics.points().iter().filter(|point| in_slice(point.id)) {
        let point_handle = procedure
            .point_handle(point.id)
            .expect("validated publication slice retains its program point");
        for (event_index, event) in point.events.iter().enumerate() {
            let publication = match &event.effect {
                SemanticEffect::MemoryStore {
                    location, value, ..
                } if names.contains(value)
                    && !(matches!(
                        semantics
                            .memory_location(*location)
                            .map(|location| &location.kind),
                        Some(MemoryLocationKind::LexicalCell { .. })
                    ) && private_cell_binding(*location, staged)?.is_some()) =>
                {
                    Some((
                        FreshObjectPublication::at_event(
                            point_handle.clone(),
                            event_index,
                            FreshObjectPublicationKind::MemoryStore,
                        )
                        .expect("matched memory store is a valid publication event"),
                        *value,
                    ))
                }
                SemanticEffect::ProcedureReturn { value }
                    if value.is_some_and(|value| names.contains(&value)) =>
                {
                    Some((
                        FreshObjectPublication::at_event(
                            point_handle.clone(),
                            event_index,
                            FreshObjectPublicationKind::Return,
                        )
                        .expect("matched return is a valid publication event"),
                        value.expect("matched return value"),
                    ))
                }
                SemanticEffect::Throw { value }
                    if value.is_some_and(|value| names.contains(&value)) =>
                {
                    Some((
                        FreshObjectPublication::at_event(
                            point_handle.clone(),
                            event_index,
                            FreshObjectPublicationKind::Throw,
                        )
                        .expect("matched throw is a valid publication event"),
                        value.expect("matched throw value"),
                    ))
                }
                SemanticEffect::AsyncSuspend { awaited, .. }
                    if awaited.is_some_and(|value| names.contains(&value)) =>
                {
                    Some((
                        FreshObjectPublication::at_event(
                            point_handle.clone(),
                            event_index,
                            FreshObjectPublicationKind::AsyncSuspend,
                        )
                        .expect("matched suspension is a valid publication event"),
                        awaited.expect("matched awaited value"),
                    ))
                }
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Return | ValueFlowKind::IndexedReturn { .. },
                    source,
                    ..
                } if names.contains(source) => Some((
                    FreshObjectPublication::at_event(
                        point_handle.clone(),
                        event_index,
                        FreshObjectPublicationKind::Return,
                    )
                    .expect("matched return flow is a valid publication event"),
                    *source,
                )),
                SemanticEffect::CallableCreation { callable, .. }
                | SemanticEffect::CallableReference { callable, .. }
                    if callable
                        .bound_receiver
                        .is_some_and(|receiver| names.contains(&receiver))
                        && !super::value_flow::callable_selection_is_non_escaping(
                            semantics,
                            point.id,
                            event_index,
                        ) =>
                {
                    Some((
                        FreshObjectPublication::at_event(
                            point_handle.clone(),
                            event_index,
                            FreshObjectPublicationKind::Capture,
                        )
                        .expect("matched bound receiver is a valid publication event"),
                        callable.bound_receiver.expect("matched bound receiver"),
                    ))
                }
                SemanticEffect::CaptureBind { capture } => semantics
                    .captures()
                    .iter()
                    .find(|row| row.id == *capture)
                    .and_then(|capture| match capture.captured {
                        CaptureSource::Value(value) if names.contains(&value) => Some((
                            FreshObjectPublication::at_event(
                                point_handle.clone(),
                                event_index,
                                FreshObjectPublicationKind::Capture,
                            )
                            .expect("matched capture is a valid publication event"),
                            value,
                        )),
                        CaptureSource::Value(_) | CaptureSource::Location(_) => None,
                    }),
                SemanticEffect::Invoke { call_site } => semantics
                    .call_site(*call_site)
                    .and_then(|call| {
                        // A call is one publication even when several
                        // operands name the object. Preserve an exact witness
                        // when it coexists with a conversion-derived candidate.
                        first_call_name(semantics, call, &exact_names)
                            .or_else(|| first_call_name(semantics, call, &candidate_names))
                            .map(|name| (call, name))
                    })
                    .and_then(|(call, name)| {
                        procedure.call_site_handle(call.id).map(|call| {
                            FreshObjectPublication::call(call)
                                .map(|publication| (publication, name))
                        })
                    })
                    .transpose()
                    .map_err(|error| {
                        InterruptionOrProvider::Provider(internal_contract(
                            "could not retain fresh-object call publication",
                            error,
                        ))
                    })?,
                _ => None,
            };
            if let Some((publication, published_name)) = publication {
                let event_evidence = evidence_handle(procedure, event.evidence)
                    .map_err(InterruptionOrProvider::Provider)?;
                let candidate_identity = !name_exactness
                    .get(&published_name)
                    .copied()
                    .expect("published fresh-object name has an exactness row");
                if candidate_identity {
                    // The row is a useful structured positive, but the set of
                    // actual publications remains open because the assignment
                    // conversion did not preserve exact object identity.
                    open = true;
                }
                push_publication(
                    &mut drafts,
                    publication,
                    name_evidence
                        .get(&published_name)
                        .into_iter()
                        .flatten()
                        .cloned()
                        .chain(std::iter::once(event_evidence))
                        .collect(),
                    candidate_identity,
                );
            }
        }
        if drafts.len() > limits.provenance_records()
            || drafts
                .iter()
                .map(|draft| draft.evidence.len())
                .sum::<usize>()
                > limits.evidence_handles()
        {
            drafts.truncate(limits.provenance_records());
            return Ok(DraftSet {
                candidates: drafts,
                coverage: CandidateCoverage::Truncated,
                ambiguous: false,
            });
        }
    }
    Ok(DraftSet {
        candidates: drafts,
        coverage: if open {
            CandidateCoverage::Open
        } else {
            CandidateCoverage::Exhaustive
        },
        ambiguous: false,
    })
}

#[doc(hidden)]
pub fn materialize_fresh_object_publications(
    query: &FreshObjectPublicationQuery,
    drafts: DraftSet<PublicationDraft>,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<FreshObjectPublicationResult, SemanticProviderError> {
    let records = drafts
        .candidates
        .iter()
        .map(|draft| {
            OracleRelationRecord::new(
                OracleRelationKind::Publication,
                draft.evidence.clone(),
                limits,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| internal_contract("could not create publication provenance", error))?;
    let arena = OracleRelationArena::new(
        OracleRelationOwner::FreshObjectPublications(Box::new(query.clone())),
        records,
        limits,
    )
    .map_err(|error| internal_contract("could not create publication arena", error))?;
    let candidates = drafts
        .candidates
        .into_iter()
        .enumerate()
        .map(|(index, draft)| {
            let id = u32::try_from(index)
                .map(OracleRelationId::new)
                .map_err(|_| SemanticProviderError::internal("publication relation ID overflow"))?;
            OracleCandidate::new(
                draft.publication,
                draft.proof,
                draft.completeness,
                [arena
                    .handle(id)
                    .expect("publication relation was inserted into the arena")],
                limits,
            )
            .map_err(|error| internal_contract("invalid publication candidate", error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    FreshObjectPublicationResult::new(query.clone(), candidates, drafts.coverage, limits)
        .map_err(|error| internal_contract("invalid fresh-object publication result", error))
}

#[doc(hidden)]
pub fn materialize_update(
    store: &StoreAtPoint,
    drafts: DraftSet<LocationDraft>,
    escape: EscapeStatus,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<UpdateEligibility, SemanticProviderError> {
    if drafts.candidates.is_empty() {
        return Ok(UpdateEligibility::Weak(direct_weak_reasons(
            drafts.coverage,
            &drafts.candidates,
        )));
    }
    if drafts.ambiguous || drafts.candidates.len() != 1 {
        let mut reasons = vec![
            WeakUpdateReason::MultipleLocations,
            WeakUpdateReason::MultipleObjects,
            WeakUpdateReason::PotentialAliases,
        ];
        match drafts.coverage {
            CandidateCoverage::Exhaustive => {}
            CandidateCoverage::Open => {
                reasons.push(WeakUpdateReason::NonExhaustiveLocations);
                reasons.push(WeakUpdateReason::NonExhaustiveObjects);
            }
            CandidateCoverage::Truncated => {
                reasons.push(WeakUpdateReason::TruncatedLocations);
                reasons.push(WeakUpdateReason::TruncatedObjects);
            }
        }
        reasons.sort_unstable_by_key(|reason| *reason as u8);
        reasons.dedup();
        return Ok(UpdateEligibility::Weak(reasons.into_boxed_slice()));
    }
    let first = &drafts.candidates[0];
    // Strong-update locations must retain the exact store target, because the
    // certificate is bound to this store's own IR address.
    //
    // A resolved location can differ from that target only in its root:
    // `resolve_locations` copies the query's selectors and tail verbatim and
    // rewrites the root to the object the root value was proven to denote. That
    // refinement is not discarded here. Cardinality is a property of the
    // runtime object, not of the syntactic root that names it, so when the
    // resolution proved the root value denotes one object, the store target
    // names one location -- which is exactly what a strong update needs. The
    // syntactic default stands only when the two paths disagree about more than
    // the root, which resolution does not produce.
    let certificate_location = if first.location.path() == store.target().path() {
        first.location.clone()
    } else {
        let refines_root = first.location.path().selectors() == store.target().path().selectors()
            && first.location.path().tail() == store.target().path().tail();
        let cardinality = if refines_root {
            first.location.object().cardinality()
        } else {
            candidate_cardinality_for_root(store.target().path().root())
        };
        let object = AbstractObject::new(store.target().path().root().clone(), cardinality)
            .map_err(|error| internal_contract("invalid store object", error))?;
        AbstractLocation::new(object, store.target().path().clone())
            .map_err(|error| internal_contract("invalid store location", error))?
    };
    let object = certificate_location.object().clone();
    let evidence = dedup_evidence(
        drafts
            .candidates
            .iter()
            .flat_map(|candidate| candidate.evidence.iter().cloned()),
    );
    let quality = evidence_quality(&evidence);
    let records = [
        OracleRelationKind::Location,
        OracleRelationKind::PointsTo,
        OracleRelationKind::Alias,
        OracleRelationKind::Escape,
    ]
    .into_iter()
    .map(|kind| OracleRelationRecord::new(kind, evidence.clone(), limits))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|error| internal_contract("could not create strong-update provenance", error))?;
    let arena = OracleRelationArena::new(
        OracleRelationOwner::StrongUpdate(Box::new(store.clone())),
        records,
        limits,
    )
    .map_err(|error| internal_contract("could not create strong-update arena", error))?;
    let relation = |index| {
        arena
            .handle(OracleRelationId::new(index))
            .expect("strong-update record was inserted into the arena")
    };
    let location_candidate = OracleCandidate::new(
        certificate_location.clone(),
        quality.0.clone(),
        quality.1.clone(),
        [relation(0)],
        limits,
    )
    .map_err(|error| internal_contract("invalid update location", error))?;
    let object_candidate = OracleCandidate::new(
        object.clone(),
        quality.0.clone(),
        quality.1.clone(),
        [relation(1)],
        limits,
    )
    .map_err(|error| internal_contract("invalid update object", error))?;
    let unique_exact = drafts.coverage == CandidateCoverage::Exhaustive
        && drafts.candidates.len() == 1
        && certificate_location.path().is_exact();
    let alias = OracleCandidate::new(
        AliasExclusivityWitness::new(
            store.clone(),
            certificate_location.clone(),
            if unique_exact {
                AliasExclusivity::Exclusive
            } else {
                AliasExclusivity::PotentialAliases
            },
        )
        .map_err(|error| internal_contract("invalid alias-exclusivity witness", error))?,
        quality.0.clone(),
        quality.1.clone(),
        [relation(2)],
        limits,
    )
    .map_err(|error| internal_contract("invalid alias-exclusivity evidence", error))?;
    let escape = OracleCandidate::new(
        EscapeWitness::new(store.clone(), object.clone(), escape)
            .map_err(|error| internal_contract("invalid escape witness", error))?,
        quality.0,
        quality.1,
        [relation(3)],
        limits,
    )
    .map_err(|error| internal_contract("invalid escape evidence", error))?;
    let evidence = StrongUpdateEvidence::new(
        OracleSet::bounded_locations([location_candidate], drafts.coverage, limits),
        OracleSet::bounded_objects([object_candidate], drafts.coverage, limits),
        alias,
        escape,
        limits,
    )
    .map_err(|error| internal_contract("invalid strong-update evidence", error))?;
    Ok(UpdateEligibility::evaluate(store.clone(), evidence))
}

impl crate::analyzer::semantic::workspace_oracle::IncomingActualCache {
    /// Temporary union of caller artifacts held by completed incoming queries.
    #[doc(hidden)]
    #[doc(hidden)]
    pub fn artifact_bytes(&self) -> u64 {
        let mut census = crate::analyzer::semantic::service::ArtifactRetentionCensus::default();
        for (key, actuals) in self
            .actuals
            .lock()
            .expect("incoming actual cache lock")
            .iter()
        {
            census.context(&key.2);
            for candidate in &actuals.candidates {
                census.context(candidate.observation.context());
                census.context(&candidate.identity_context);
                census.procedure(candidate.observation.point().procedure());
            }
        }
        census.artifact_bytes()
    }
}
