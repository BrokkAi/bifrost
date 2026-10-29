use std::{cmp::Ordering, error::Error, fmt, hash::Hash, mem::size_of_val, sync::Arc};

use crate::taint::TaintClassSet;

use crate::ordering::{compare_call_sites as compare_calls, compare_points, compare_procedures};

use crate::analyzer::semantic::{
    AbstractLocation, AbstractObject, AccessPath, AccessPathRoot, AccessPathTail, AccessSelector,
    CallArgumentEndpoint, CallBinding, CallBindings, CallSiteHandle, CallSiteId, CallableTarget,
    CallableTargetResolution, CandidateCoverage, ControlEdgeKind, DeclarationLocator,
    DeclarationSegmentKind, DispatchBoundaryKind, EvidenceCompleteness, IcfgEdgeKind,
    LengthDelimitedDigest, MemoryLocationId, MemoryLocationKind, ObjectCardinality,
    OracleCallContext, OracleLimits, ProcedureHandle, ProcedurePortHandle, ProcedurePortKind,
    ProgramPointHandle, ProgramPointId, ProofStatus, SemanticArtifact, SemanticArtifactKey,
    SemanticCapability, SemanticEffect, SemanticGapHandle, SemanticGapImpact, SemanticGapKind,
    SemanticGapSubject, SemanticLocator, SemanticValueKind, StableDigest, ValueFlowEndpoint,
    ValueFlowKind, ValueFlowRelationKind, ValueFlowSnapshot, ValueTransfer,
};
use crate::dataflow::{
    CuratedCallModel, CuratedCallModelFingerprint, ExternalSemanticSummarySet,
    ExternalSummaryOrigin, ExternalSummarySetFingerprint, MAX_SUMMARY_BOUNDARY_BINDINGS,
    SemanticInputStatus, SemanticProcedureSummary, SummaryBoundary, SummaryBoundaryKind,
    SummaryDataflowResult, SummaryEffect, SummaryEffectKey, SummaryEvidence, SummaryExitKind,
    SummaryOrigin, SummaryPort, SummaryTransfer, SummaryWitness, SummaryWitnessStepKind,
    UnmodeledCallBehavior,
};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_analysis::analyzer::semantic::ids::{
    push_declaration_shape, push_evidence_completeness, push_proof_status,
};
use brokk_bifrost_analysis::analyzer::semantic::partial_flow::rules::procedure_infeasible_points;

use crate::analyzer::semantic::workspace_oracle::{GapOpenness, classify_gap_openness};

use super::model::push_summary_identity;
use super::{
    ValueFlowCarrier, ValueFlowCarrierId, ValueFlowCarrierKey, ValueFlowEventKey,
    ValueFlowModelError, ValueFlowObservationPhase, ValueFlowSinkId, ValueFlowSinkSpec,
    ValueFlowSourceId, ValueFlowSourceListId, ValueFlowSourceLists, ValueFlowSourceSpec,
    ValueFlowSources,
};

/// Target-directed binding of an external summary's formal ports to one call.
#[derive(Clone, Copy, Default)]
pub struct SummaryCallBinding<'a> {
    actual_to_formal: Option<&'a [u32]>,
    has_receiver: bool,
}

impl<'a> SummaryCallBinding<'a> {
    pub fn new(target: &SemanticLocator, actual_to_formal: Option<&'a [u32]>) -> Self {
        Self {
            actual_to_formal,
            has_receiver: target
                .declaration()
                .segments()
                .last()
                .is_some_and(|segment| segment.kind() == DeclarationSegmentKind::Method),
        }
    }

    pub fn parameter_index(self, call: &CallSiteHandle, formal: u32) -> Option<usize> {
        actual_argument_index_for_formal(formal, self.actual_to_formal)
            .and_then(|actual| call.target_argument_index(self.has_receiver, actual))
    }

    pub fn receiver_value(
        self,
        call: &CallSiteHandle,
    ) -> Option<crate::analyzer::semantic::ValueId> {
        call.target_receiver_value(self.has_receiver)
    }
}

pub const MAX_VALUE_FLOW_CARRIERS: usize = 262_144;
pub const MAX_VALUE_FLOW_RELATIONS: usize = 1_000_000;
pub const MAX_VALUE_FLOW_SOURCES: usize = 65_536;
pub const MAX_VALUE_FLOW_SINKS: usize = 65_536;
pub const MAX_VALUE_FLOW_ACCESS_PATH: usize = 64;
const DEFAULT_VALUE_FLOW_ACCESS_PATH: usize = 8;
const FALLBACK_COMPONENT_SUMMARY_IDENTITY: &[u8] =
    b"bifrost-value-flow-fallback-component-summary-identity-v1";

/// Remove selected source facts from one carrier while traversing one exact
/// intraprocedural edge.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValueFlowEdgeKillSpec {
    pub point: ProgramPointHandle,
    pub target: ProgramPointId,
    pub kind: ControlEdgeKind,
    pub carrier: ValueFlowCarrier,
    pub sources: ValueFlowSourceListId,
    /// Optional taint-label narrowing; None removes all labels of the selected sources.
    pub labels: Option<TaintClassSet>,
}

/// One policy-authored point-local carrier relation.
///
/// The relation is deliberately separate from the analyzer snapshot: policy
/// transforms add topology between two already-structured carriers, but do
/// not claim that the language adapter observed that topology in the body.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValueFlowLocalRuleSpec {
    point: ProgramPointHandle,
    source: ValueFlowCarrier,
    target: ValueFlowCarrier,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

impl ValueFlowLocalRuleSpec {
    pub const fn new(
        point: ProgramPointHandle,
        source: ValueFlowCarrier,
        target: ValueFlowCarrier,
        proof: ProofStatus,
        completeness: EvidenceCompleteness,
    ) -> Self {
        Self {
            point,
            source,
            target,
            proof,
            completeness,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundValueFlowEdgeKill {
    pub carrier: ValueFlowCarrierId,
    pub sources: ValueFlowSourceListId,
    pub labels: Option<TaintClassSet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EdgeKillKey {
    point: ProgramPointHandle,
    target: ProgramPointId,
    kind: ControlEdgeKind,
}

#[derive(Debug, Clone, Default)]
struct EdgeKillIndex {
    by_edge: HashMap<EdgeKillKey, Box<[BoundValueFlowEdgeKill]>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueFlowPlanLimits {
    max_carriers: usize,
    max_relations: usize,
    max_sources: usize,
    max_sinks: usize,
    max_access_path: usize,
}

impl ValueFlowPlanLimits {
    /// The most sinks one plan observes.
    pub const fn max_sinks(&self) -> usize {
        self.max_sinks
    }

    pub fn new(
        max_carriers: usize,
        max_relations: usize,
        max_sources: usize,
        max_sinks: usize,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::with_access_path_limit(
            max_carriers,
            max_relations,
            max_sources,
            max_sinks,
            DEFAULT_VALUE_FLOW_ACCESS_PATH,
        )
    }

    /// Construct plan limits with an explicit bound for paths projected over
    /// an exact call binding. Snapshot paths are already bounded by the
    /// semantic oracle; this second bound controls the caller-path plus
    /// callee-selector concatenation performed by this plan.
    pub fn with_access_path_limit(
        max_carriers: usize,
        max_relations: usize,
        max_sources: usize,
        max_sinks: usize,
        max_access_path: usize,
    ) -> Result<Self, ValueFlowPlanError> {
        if max_carriers == 0
            || max_carriers > MAX_VALUE_FLOW_CARRIERS
            || max_relations == 0
            || max_relations > MAX_VALUE_FLOW_RELATIONS
            || max_sources == 0
            || max_sources > MAX_VALUE_FLOW_SOURCES
            || max_sinks == 0
            || max_sinks > MAX_VALUE_FLOW_SINKS
            || max_access_path == 0
            || max_access_path > MAX_VALUE_FLOW_ACCESS_PATH
        {
            return Err(ValueFlowPlanError::InvalidLimits);
        }
        Ok(Self {
            max_carriers,
            max_relations,
            max_sources,
            max_sinks,
            max_access_path,
        })
    }
}

impl Default for ValueFlowPlanLimits {
    fn default() -> Self {
        Self {
            max_carriers: MAX_VALUE_FLOW_CARRIERS,
            max_relations: MAX_VALUE_FLOW_RELATIONS,
            max_sources: MAX_VALUE_FLOW_SOURCES,
            max_sinks: MAX_VALUE_FLOW_SINKS,
            max_access_path: DEFAULT_VALUE_FLOW_ACCESS_PATH,
        }
    }
}

/// One discovered oracle payload and the semantic outcome that produced it.
#[derive(Debug, Clone)]
pub struct ValueFlowInput<T> {
    value: T,
    status: SemanticInputStatus,
}

impl<T> ValueFlowInput<T> {
    pub const fn new(value: T, status: SemanticInputStatus) -> Self {
        Self { value, status }
    }

    pub const fn value(&self) -> &T {
        &self.value
    }

    pub const fn status(&self) -> SemanticInputStatus {
        self.status
    }

    pub fn into_parts(self) -> (T, SemanticInputStatus) {
        (self.value, self.status)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct LocalFlowRule {
    pub point: ProgramPointHandle,
    pub event_index: u32,
    pub kind: ValueFlowRelationKind,
    pub transfer: Option<ValueTransfer>,
    pub source: ValueFlowCarrierId,
    pub target: ValueFlowCarrierId,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
    /// This topology was injected by a policy-local transform. Taint attaches
    /// label rewriting to this exact relation instead of to a carrier phase.
    pub policy_local: bool,
    /// The heap oracle certified this store as a strong update (#2444), so a
    /// client may replace rather than join the facts at `target`.
    pub strong_update: bool,
    /// Independent native proof of a direct, unexposed lexical-cell overwrite.
    pub direct_cell_overwrite: bool,
}

/// One point-local rule as the flow clients read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalRuleView {
    pub event_index: u32,
    pub source: ValueFlowCarrierId,
    pub target: ValueFlowCarrierId,
    pub kind: ValueFlowRelationKind,
    pub transfer: Option<ValueTransfer>,
    /// The rule's own evidence is proven and complete.
    pub complete: bool,
    /// Whether a policy-local transform owns this exact relation.
    pub policy_local: bool,
    /// The store this rule publishes overwrites `target` outright (#2444).
    pub strong_update: bool,
    /// Independent native proof of a direct, unexposed lexical-cell overwrite.
    pub direct_cell_overwrite: bool,
}

fn local_rule_view(rule: &LocalFlowRule) -> LocalRuleView {
    LocalRuleView {
        event_index: rule.event_index,
        source: rule.source,
        target: rule.target,
        kind: rule.kind,
        transfer: rule.transfer,
        complete: matches!(rule.proof, ProofStatus::Proven)
            && matches!(rule.completeness, EvidenceCompleteness::Complete),
        policy_local: rule.policy_local,
        strong_update: rule.strong_update,
        direct_cell_overwrite: rule.direct_cell_overwrite,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CallFlowRuleKind {
    Call,
    NormalReturn,
    ExceptionalReturn,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowLocalSummaryRule {
    point: ProgramPointId,
    event_index: u32,
    kind: ValueFlowRelationKind,
    transfer: Option<ValueTransfer>,
    source: ValueFlowCarrierKey,
    target: ValueFlowCarrierKey,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    policy_local: bool,
    /// Part of the identity: two plans that disagree about whether a store
    /// kills its target do not compute the same summary.
    strong_update: bool,
    direct_cell_overwrite: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowCallSummaryRule {
    call: CallSiteId,
    callee_artifact: SemanticArtifactKey,
    callee_declaration: DeclarationLocator,
    kind: CallFlowRuleKind,
    transfer: Option<ValueTransfer>,
    source: ValueFlowCarrierKey,
    target: ValueFlowCarrierKey,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowCuratedModelSummaryRule {
    call: CallSiteId,
    model: CuratedCallModelFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowFallbackSummaryRule {
    call: CallSiteId,
    inputs: Box<[ValueFlowCarrierKey]>,
    reachable_components: Box<[StableDigest]>,
    normal_output: Option<ValueFlowCarrierKey>,
    exceptional_output: Option<ValueFlowCarrierKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowLocationBindingSummaryRule {
    call: CallSiteId,
    port: SummaryPort,
    carrier: Option<ValueFlowCarrierKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowEdgeKillSummaryRule {
    point: ProgramPointId,
    target: ProgramPointId,
    kind: ControlEdgeKind,
    carrier: ValueFlowCarrierKey,
    sources: Box<[ValueFlowEventKey]>,
    labels: Option<TaintClassSet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowConditionalSourceSummaryRule {
    point: ProgramPointId,
    phase: ValueFlowObservationPhase,
    key: ValueFlowEventKey,
    carrier: ValueFlowCarrierKey,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    triggers: Box<[ValueFlowEventKey]>,
}

/// Stable, procedure-local value-flow identity used by reusable client summaries.
///
/// Ordinary source, sink, sanitizer, and transform matching are intentionally
/// absent; clients add those independently according to their invalidation
/// contract. Conditional sources are included because their trigger relation
/// changes transfer behavior.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowCarrierSummaryIdentity {
    unmodeled_call_behavior: UnmodeledCallBehavior,
    external_summaries: Box<[ExternalSummarySetFingerprint]>,
    fallback_globals: Box<[ValueFlowCarrierKey]>,
    has_snapshot: bool,
    local_rules: Box<[ValueFlowLocalSummaryRule]>,
    call_rules: Box<[ValueFlowCallSummaryRule]>,
    curated_models: Box<[ValueFlowCuratedModelSummaryRule]>,
    fallback_rules: Box<[ValueFlowFallbackSummaryRule]>,
    location_bindings: Box<[ValueFlowLocationBindingSummaryRule]>,
    conditional_sources: Box<[ValueFlowConditionalSourceSummaryRule]>,
    edge_kills: Box<[ValueFlowEdgeKillSummaryRule]>,
}

/// Canonical query-local source-selective behavior needed to partition
/// reusable entries. It includes guard edge kills and source activations whose
/// membership depends on the incoming source.
#[derive(Debug, Clone)]
pub(crate) struct ValueFlowSourceBehaviorIdentity {
    conditional_sources: Box<[ValueFlowConditionalSourceSummaryRule]>,
    edge_kills: Box<[ValueFlowEdgeKillSummaryRule]>,
}

impl ValueFlowSourceBehaviorIdentity {
    pub(crate) fn work_units(&self) -> usize {
        1usize
            .saturating_add(self.conditional_sources.len())
            .saturating_add(self.edge_kills.len())
    }

    pub(crate) fn fingerprint(
        &self,
        procedure: &crate::analyzer::semantic::SemanticLocator,
        source: &ValueFlowEventKey,
    ) -> StableDigest {
        let mut digest =
            LengthDelimitedDigest::new(b"bifrost-value-flow-source-selective-behavior-v2");
        push_summary_len(&mut digest, self.conditional_sources.len());
        for row in &self.conditional_sources {
            digest.push(b"conditional_source");
            digest.push(&row.point.get().to_le_bytes());
            digest.push(match row.phase {
                ValueFlowObservationPhase::BeforeEffects => b"before_effects",
                ValueFlowObservationPhase::AfterEffects => b"after_effects",
            });
            push_summary_event(&mut digest, &row.key, Some(procedure));
            push_summary_carrier(&mut digest, &row.carrier, Some(procedure));
            push_proof_status(&mut digest, &row.proof);
            push_evidence_completeness(&mut digest, &row.completeness);
            push_summary_len(&mut digest, row.triggers.len());
            push_summary_bool(&mut digest, row.triggers.binary_search(source).is_ok());
        }
        push_summary_len(&mut digest, self.edge_kills.len());
        for kill in &self.edge_kills {
            digest.push(&kill.point.get().to_le_bytes());
            digest.push(&kill.target.get().to_le_bytes());
            digest.push(kill.kind.label().as_bytes());
            push_summary_carrier(&mut digest, &kill.carrier, Some(procedure));
            push_summary_bool(&mut digest, kill.sources.binary_search(source).is_ok());
            push_edge_kill_labels(&mut digest, kill.labels.as_ref());
        }
        digest.finish()
    }
}

impl ValueFlowCarrierSummaryIdentity {
    /// Whether this procedure's transfer relation can distinguish entry
    /// sources. Callers propagate this bit through their dependency closure.
    pub(crate) fn has_source_selective_edge_kills(&self) -> bool {
        !self.edge_kills.is_empty() || !self.conditional_sources.is_empty()
    }
    pub(crate) fn procedure_local_fingerprint(
        &self,
        procedure: &crate::analyzer::semantic::SemanticLocator,
    ) -> StableDigest {
        self.fingerprint_with(Some(procedure), None)
    }

    #[cfg(test)]
    pub(crate) fn fallback_component_reference_count(&self) -> usize {
        self.fallback_rules.iter().fold(0usize, |total, rule| {
            total.saturating_add(rule.reachable_components.len())
        })
    }

    /// Procedure-local carrier identity with entry-parametric source events
    /// removed from edge-kill membership. Sources declared by this procedure
    /// or a transitive callee remain exact internal transfer semantics.
    pub(crate) fn procedure_closure_fingerprint(
        &self,
        procedure: &crate::analyzer::semantic::SemanticLocator,
        internal_source_owners: &HashMap<
            ValueFlowEventKey,
            crate::analyzer::semantic::SemanticLocator,
        >,
    ) -> StableDigest {
        self.fingerprint_with(Some(procedure), Some(internal_source_owners))
    }

    pub(crate) fn edge_kill_sources(&self) -> impl Iterator<Item = &ValueFlowEventKey> {
        self.edge_kills
            .iter()
            .flat_map(|kill| kill.sources.iter())
            .chain(
                self.conditional_sources
                    .iter()
                    .flat_map(|source| source.triggers.iter()),
            )
    }

    /// Source-parametric transfer behavior at this procedure's guard edges.
    ///
    /// Exact source event identity selects membership but is never hashed. The
    /// result therefore groups distinct callers and classes when they take the
    /// same normalized set of kill loci, while rotating when an adapter edit
    /// changes which arm kills the source.
    pub(crate) fn source_behavior_identity(&self) -> ValueFlowSourceBehaviorIdentity {
        ValueFlowSourceBehaviorIdentity {
            conditional_sources: self.conditional_sources.clone(),
            edge_kills: self.edge_kills.clone(),
        }
    }

    fn fingerprint_with(
        &self,
        procedure: Option<&crate::analyzer::semantic::SemanticLocator>,
        internal_source_owners: Option<
            &HashMap<ValueFlowEventKey, crate::analyzer::semantic::SemanticLocator>,
        >,
    ) -> StableDigest {
        let domain: &[u8] = if internal_source_owners.is_some() {
            b"bifrost-value-flow-procedure-closure-summary-identity-v8"
        } else if procedure.is_some() {
            b"bifrost-value-flow-procedure-local-summary-identity-v6"
        } else {
            b"bifrost-value-flow-carrier-summary-identity-v5"
        };
        let mut digest = LengthDelimitedDigest::new(domain);
        digest.push(self.unmodeled_call_behavior.label().as_bytes());
        push_summary_len(&mut digest, self.external_summaries.len());
        for summary in &self.external_summaries {
            digest.push(summary.as_bytes());
        }
        push_summary_len(&mut digest, self.fallback_globals.len());
        for carrier in &self.fallback_globals {
            push_summary_carrier(&mut digest, carrier, procedure);
        }
        push_summary_bool(&mut digest, self.has_snapshot);

        push_summary_len(&mut digest, self.local_rules.len());
        for rule in &self.local_rules {
            digest.push(b"local_rule");
            digest.push(&rule.point.get().to_le_bytes());
            digest.push(&rule.event_index.to_le_bytes());
            push_relation_kind(&mut digest, rule.kind);
            push_value_transfer(&mut digest, rule.transfer);
            push_summary_carrier(&mut digest, &rule.source, procedure);
            push_summary_carrier(&mut digest, &rule.target, procedure);
            push_proof_status(&mut digest, &rule.proof);
            push_evidence_completeness(&mut digest, &rule.completeness);
            if rule.policy_local {
                digest.push(b"policy-local");
            }
            push_summary_bool(&mut digest, rule.strong_update);
            push_summary_bool(&mut digest, rule.direct_cell_overwrite);
        }

        push_summary_len(&mut digest, self.call_rules.len());
        for rule in &self.call_rules {
            digest.push(b"call_rule");
            digest.push(&rule.call.get().to_le_bytes());
            if procedure.is_some() {
                digest.push(
                    rule.callee_artifact
                        .procedure_environment_fingerprint()
                        .as_bytes(),
                );
                push_declaration_shape(&mut digest, &rule.callee_declaration);
            } else {
                digest.push(rule.callee_artifact.public_fingerprint().as_bytes());
                push_declaration(&mut digest, &rule.callee_declaration);
            }
            digest.push(match rule.kind {
                CallFlowRuleKind::Call => b"call",
                CallFlowRuleKind::NormalReturn => b"normal_return",
                CallFlowRuleKind::ExceptionalReturn => b"exceptional_return",
            });
            push_value_transfer(&mut digest, rule.transfer);
            push_summary_carrier(&mut digest, &rule.source, procedure);
            push_summary_carrier(&mut digest, &rule.target, procedure);
            push_proof_status(&mut digest, &rule.proof);
            push_evidence_completeness(&mut digest, &rule.completeness);
        }

        push_summary_len(&mut digest, self.curated_models.len());
        for rule in &self.curated_models {
            digest.push(b"curated_model");
            digest.push(&rule.call.get().to_le_bytes());
            digest.push(rule.model.as_bytes());
        }

        push_summary_len(&mut digest, self.fallback_rules.len());
        for rule in &self.fallback_rules {
            digest.push(b"fallback_rule");
            digest.push(&rule.call.get().to_le_bytes());
            push_summary_len(&mut digest, rule.inputs.len());
            for input in &rule.inputs {
                push_summary_carrier(&mut digest, input, procedure);
            }
            push_summary_len(&mut digest, rule.reachable_components.len());
            for component in &rule.reachable_components {
                digest.push(component.as_bytes());
            }
            push_optional_carrier(&mut digest, rule.normal_output.as_ref(), procedure);
            push_optional_carrier(&mut digest, rule.exceptional_output.as_ref(), procedure);
        }

        push_summary_len(&mut digest, self.location_bindings.len());
        for binding in &self.location_bindings {
            digest.push(b"location_binding");
            digest.push(&binding.call.get().to_le_bytes());
            push_summary_port(&mut digest, &binding.port);
            push_optional_carrier(&mut digest, binding.carrier.as_ref(), procedure);
        }

        push_summary_len(&mut digest, self.conditional_sources.len());
        for source in &self.conditional_sources {
            digest.push(b"conditional_source");
            digest.push(&source.point.get().to_le_bytes());
            digest.push(match source.phase {
                ValueFlowObservationPhase::BeforeEffects => b"before_effects",
                ValueFlowObservationPhase::AfterEffects => b"after_effects",
            });
            push_summary_event(&mut digest, &source.key, procedure);
            push_summary_carrier(&mut digest, &source.carrier, procedure);
            push_proof_status(&mut digest, &source.proof);
            push_evidence_completeness(&mut digest, &source.completeness);
            let triggers = source
                .triggers
                .iter()
                .filter(|trigger| {
                    internal_source_owners.is_none_or(|owners| owners.contains_key(*trigger))
                })
                .collect::<Vec<_>>();
            push_summary_len(&mut digest, triggers.len());
            for trigger in triggers {
                let source_procedure = internal_source_owners
                    .and_then(|owners| owners.get(trigger))
                    .or(procedure);
                push_summary_event(&mut digest, trigger, source_procedure);
            }
        }

        // Runtime transfer unions source membership for duplicate structural
        // kill rows. Canonicalize that same algebra before hashing, especially
        // because removing external entry sources can make previously distinct
        // rows identical.
        let mut normalized_kills = Vec::<(
            ProgramPointId,
            ProgramPointId,
            ControlEdgeKind,
            &ValueFlowCarrierKey,
            Option<&TaintClassSet>,
            Vec<&ValueFlowEventKey>,
        )>::new();
        for kill in &self.edge_kills {
            let sources = kill
                .sources
                .iter()
                .filter(|source| {
                    internal_source_owners.is_none_or(|owners| owners.contains_key(source))
                })
                .collect::<Vec<_>>();
            if let Some((point, target, kind, carrier, labels, retained)) =
                normalized_kills.last_mut()
                && *point == kill.point
                && *target == kill.target
                && *kind == kill.kind
                && *carrier == &kill.carrier
                && *labels == kill.labels.as_ref()
            {
                retained.extend(sources);
                retained.sort_unstable();
                retained.dedup();
            } else {
                normalized_kills.push((
                    kill.point,
                    kill.target,
                    kill.kind,
                    &kill.carrier,
                    kill.labels.as_ref(),
                    sources,
                ));
            }
        }
        push_summary_len(&mut digest, normalized_kills.len());
        for (point, target, kind, carrier, labels, sources) in normalized_kills {
            digest.push(b"edge_kill");
            digest.push(&point.get().to_le_bytes());
            digest.push(&target.get().to_le_bytes());
            digest.push(kind.label().as_bytes());
            push_summary_carrier(&mut digest, carrier, procedure);
            push_edge_kill_labels(&mut digest, labels);
            // An external source arrives as the reusable entry placeholder;
            // its exact membership is keyed by that entry's behavior
            // partition. Internal sources remain fixed procedure semantics
            // and therefore retain their exact local identities here.
            push_summary_len(&mut digest, sources.len());
            for source in sources {
                let source_procedure = internal_source_owners
                    .and_then(|owners| owners.get(source))
                    .or(procedure)
                    .expect("a retained source has a procedure-local owner");
                push_summary_event(&mut digest, source, Some(source_procedure));
            }
        }
        digest.finish()
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        let local = size_of_val(self.local_rules.as_ref()).saturating_add(
            self.local_rules.iter().fold(0usize, |total, rule| {
                total
                    .saturating_add(rule.source.retained_bytes())
                    .saturating_add(rule.target.retained_bytes())
                    .saturating_add(rule.proof.retained_heap_bytes())
                    .saturating_add(rule.completeness.retained_heap_bytes())
            }),
        );
        let calls = size_of_val(self.call_rules.as_ref()).saturating_add(
            self.call_rules.iter().fold(0usize, |total, rule| {
                total
                    .saturating_add(rule.callee_artifact.path().as_str().len())
                    .saturating_add(crate::dataflow::declaration_locator_heap_bytes(
                        &rule.callee_declaration,
                    ))
                    .saturating_add(rule.source.retained_bytes())
                    .saturating_add(rule.target.retained_bytes())
                    .saturating_add(rule.proof.retained_heap_bytes())
                    .saturating_add(rule.completeness.retained_heap_bytes())
            }),
        );
        let fallbacks = size_of_val(self.fallback_rules.as_ref()).saturating_add(
            self.fallback_rules.iter().fold(0usize, |total, rule| {
                total
                    .saturating_add(size_of_val(rule.inputs.as_ref()))
                    .saturating_add(
                        rule.inputs
                            .iter()
                            .map(ValueFlowCarrierKey::retained_bytes)
                            .fold(0usize, usize::saturating_add),
                    )
                    .saturating_add(size_of_val(rule.reachable_components.as_ref()))
                    .saturating_add(
                        rule.normal_output
                            .as_ref()
                            .map_or(0, ValueFlowCarrierKey::retained_bytes),
                    )
                    .saturating_add(
                        rule.exceptional_output
                            .as_ref()
                            .map_or(0, ValueFlowCarrierKey::retained_bytes),
                    )
            }),
        );
        let location_bindings = size_of_val(self.location_bindings.as_ref()).saturating_add(
            self.location_bindings
                .iter()
                .map(|binding| {
                    binding
                        .carrier
                        .as_ref()
                        .map_or(0, ValueFlowCarrierKey::retained_bytes)
                })
                .fold(0usize, usize::saturating_add),
        );
        let edge_kills = size_of_val(self.edge_kills.as_ref()).saturating_add(
            self.edge_kills
                .iter()
                .map(|kill| {
                    kill.carrier
                        .retained_bytes()
                        .saturating_add(size_of_val(kill.sources.as_ref()))
                        .saturating_add(
                            kill.labels
                                .as_ref()
                                .map_or(0, TaintClassSet::retained_heap_bytes),
                        )
                        .saturating_add(
                            kill.sources
                                .iter()
                                .map(ValueFlowEventKey::retained_bytes)
                                .fold(0usize, usize::saturating_add),
                        )
                })
                .fold(0usize, usize::saturating_add),
        );
        let conditional_sources = size_of_val(self.conditional_sources.as_ref()).saturating_add(
            self.conditional_sources
                .iter()
                .map(|source| {
                    source
                        .key
                        .retained_bytes()
                        .saturating_add(source.carrier.retained_bytes())
                        .saturating_add(source.proof.retained_heap_bytes())
                        .saturating_add(source.completeness.retained_heap_bytes())
                        .saturating_add(size_of_val(source.triggers.as_ref()))
                        .saturating_add(
                            source
                                .triggers
                                .iter()
                                .map(ValueFlowEventKey::retained_bytes)
                                .fold(0usize, usize::saturating_add),
                        )
                })
                .fold(0usize, usize::saturating_add),
        );
        std::mem::size_of::<Self>()
            .saturating_add(local)
            .saturating_add(calls)
            .saturating_add(size_of_val(self.curated_models.as_ref()))
            .saturating_add(size_of_val(self.external_summaries.as_ref()))
            .saturating_add(size_of_val(self.fallback_globals.as_ref()))
            .saturating_add(
                self.fallback_globals
                    .iter()
                    .map(ValueFlowCarrierKey::retained_bytes)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(fallbacks)
            .saturating_add(location_bindings)
            .saturating_add(conditional_sources)
            .saturating_add(edge_kills)
    }
}

fn push_summary_len(digest: &mut LengthDelimitedDigest, len: usize) {
    digest.push(
        &u64::try_from(len)
            .expect("value-flow summary collection length fits in u64")
            .to_le_bytes(),
    );
}

fn push_summary_bool(digest: &mut LengthDelimitedDigest, value: bool) {
    digest.push(&[u8::from(value)]);
}

fn fallback_component_fingerprint(
    component: usize,
    procedure: &crate::analyzer::semantic::SemanticLocator,
    locations: &FallbackLocationIndex,
    carrier_keys: &[ValueFlowCarrierKey],
) -> StableDigest {
    let mut targets = locations
        .by_component
        .get(&component)
        .into_iter()
        .flatten()
        .map(|carrier| &carrier_keys[carrier.index()])
        .collect::<Vec<_>>();
    targets.sort_unstable();
    targets.dedup();
    let mut digest = LengthDelimitedDigest::new(FALLBACK_COMPONENT_SUMMARY_IDENTITY);
    push_summary_len(&mut digest, targets.len());
    for target in targets {
        push_summary_carrier(&mut digest, target, Some(procedure));
    }
    digest.finish()
}

fn push_optional_carrier(
    digest: &mut LengthDelimitedDigest,
    carrier: Option<&ValueFlowCarrierKey>,
    procedure: Option<&crate::analyzer::semantic::SemanticLocator>,
) {
    match carrier {
        Some(carrier) => {
            digest.push(b"some");
            push_summary_carrier(digest, carrier, procedure);
        }
        None => digest.push(b"none"),
    }
}

fn push_summary_carrier(
    digest: &mut LengthDelimitedDigest,
    carrier: &ValueFlowCarrierKey,
    procedure: Option<&crate::analyzer::semantic::SemanticLocator>,
) {
    push_summary_identity(digest, carrier, procedure);
}

fn push_summary_event(
    digest: &mut LengthDelimitedDigest,
    event: &ValueFlowEventKey,
    procedure: Option<&crate::analyzer::semantic::SemanticLocator>,
) {
    push_summary_identity(digest, event, procedure);
}

fn push_declaration(digest: &mut LengthDelimitedDigest, declaration: &DeclarationLocator) {
    push_summary_len(digest, declaration.segments().len());
    for segment in declaration.segments() {
        digest.push(segment.kind().stable_label().as_bytes());
        match segment.name() {
            Some(name) => {
                digest.push(b"named");
                digest.push(name.as_bytes());
            }
            None => digest.push(b"anonymous"),
        }
        digest.push_anchor(segment.anchor());
        digest.push(&segment.sibling_ordinal().to_le_bytes());
    }
}

fn push_relation_kind(digest: &mut LengthDelimitedDigest, kind: ValueFlowRelationKind) {
    digest.push(match kind {
        ValueFlowRelationKind::Assignment => b"assignment",
        ValueFlowRelationKind::Parameter => b"parameter",
        ValueFlowRelationKind::Receiver => b"receiver",
        ValueFlowRelationKind::NormalReturn => b"normal_return",
        ValueFlowRelationKind::ExceptionalReturn => b"exceptional_return",
        ValueFlowRelationKind::Allocation => b"allocation",
        ValueFlowRelationKind::MemoryLoad => b"memory_load",
        ValueFlowRelationKind::MemoryStore => b"memory_store",
        ValueFlowRelationKind::Capture => b"capture",
        ValueFlowRelationKind::HandlerBinding => b"handler_binding",
        ValueFlowRelationKind::ContainerCollapse => b"container_collapse",
        ValueFlowRelationKind::LanguageDefined => b"language_defined",
    });
}

fn push_value_transfer(digest: &mut LengthDelimitedDigest, transfer: Option<ValueTransfer>) {
    use crate::analyzer::semantic::{
        MoveInvalidation, TransferKind, TransferOperation, ValuePreservation,
    };

    let Some(transfer) = transfer else {
        digest.push(b"no_transfer");
        return;
    };
    digest.push(b"transfer");
    match transfer.kind {
        TransferKind::Copy => digest.push(b"copy"),
        TransferKind::AggregateCopy => digest.push(b"aggregate_copy"),
        TransferKind::Move { invalidation } => {
            digest.push(b"move");
            digest.push(match invalidation {
                MoveInvalidation::Invalidated => b"invalidated",
                MoveInvalidation::Unknown => b"unknown",
            });
        }
        TransferKind::Conversion { preservation } => {
            digest.push(b"conversion");
            digest.push(match preservation {
                ValuePreservation::Identity => b"identity",
                ValuePreservation::Preserving => b"preserving",
                ValuePreservation::Changing => b"changing",
            });
        }
        TransferKind::Boxing => digest.push(b"boxing"),
        TransferKind::Unboxing => digest.push(b"unboxing"),
    }
    match transfer.operation {
        TransferOperation::None => digest.push(b"no_operation"),
        TransferOperation::CallSite(call) => {
            digest.push(b"call_site_operation");
            digest.push(&call.get().to_le_bytes());
        }
        TransferOperation::CallArgumentConversion(conversion) => {
            digest.push(b"call_argument_conversion_operation");
            digest.push(conversion.as_bytes());
        }
        TransferOperation::ValueCarrierAdaptation(adaptation) => {
            digest.push(b"value_carrier_adaptation_operation");
            digest.push(adaptation.as_bytes());
        }
        TransferOperation::Unknown => digest.push(b"unknown_operation"),
    }
}

fn push_summary_port(digest: &mut LengthDelimitedDigest, port: &SummaryPort) {
    match port {
        SummaryPort::Receiver => digest.push(b"receiver"),
        SummaryPort::Parameter(ordinal) => {
            digest.push(b"parameter");
            digest.push(&ordinal.to_le_bytes());
        }
        SummaryPort::NormalReturn => digest.push(b"normal_return"),
        SummaryPort::IndexedNormalReturn(ordinal) => {
            digest.push(b"indexed_normal_return");
            digest.push(&ordinal.to_le_bytes());
        }
        SummaryPort::ExceptionalReturn => digest.push(b"exceptional_return"),
        SummaryPort::Capture(location) => {
            digest.push(b"capture");
            digest.push(location.as_bytes());
        }
        SummaryPort::Heap(location) => {
            digest.push(b"heap");
            digest.push(location.as_bytes());
        }
    }
}

/// Classify a snapshot's residual openness (#1952). `Blocked(Some(...))`
/// retains the first relevant producer gap; `Blocked(None)` means a required
/// capability is unavailable without one scoped gap. `Refinable(residual)`
/// means every relevant gap is either discharged or a call-target refinement
/// gap, and lists the calls without complete bindings (empty when the plan's
/// own bindings answer them all).
enum SnapshotOpenness {
    Refinable(Vec<CallSiteHandle>),
    Blocked(Option<(SemanticGapHandle, SemanticCapability)>),
}

#[allow(clippy::too_many_arguments)]
fn classify_snapshot_openness<'snapshot>(
    snapshot: &ValueFlowSnapshot,
    binding_complete: &HashMap<CallSiteHandle, bool>,
    bindings: &[ValueFlowInput<CallBindings>],
    snapshots: &'snapshot [ValueFlowInput<ValueFlowSnapshot>],
    limits: ValueFlowPlanLimits,
    sources: &[ValueFlowSourceSpec],
    sinks: &[ValueFlowSinkSpec],
    caller_origins: &mut CallerOriginIndexes<'snapshot>,
    resolved_external_calls: &HashSet<CallSiteHandle>,
) -> SnapshotOpenness {
    let procedure = snapshot.procedure();
    let infeasible = procedure_infeasible_points(procedure.semantics());
    if snapshot.member_receivers().iter().any(|receiver| {
        !receiver.selection_is_complete()
            && procedure
                .semantics()
                .call_site(receiver.call().id())
                .is_some_and(|call| infeasible.binary_search(&call.point).is_err())
    }) {
        return SnapshotOpenness::Blocked(None);
    }
    // A typed gap may outrank an unproven retained relation in the oracle's
    // top-level outcome, but refining that gap does not prove the relation.
    // Preserve the relation's independent quality floor before considering
    // whether the typed gaps can be discharged by this plan (#2835).
    if snapshot
        .relations()
        .iter()
        .any(|relation| !relation.is_proven_complete())
    {
        return SnapshotOpenness::Blocked(None);
    }
    if crate::analyzer::semantic::workspace_oracle::value_flow_capabilities_are_open(procedure) {
        return SnapshotOpenness::Blocked(None);
    }
    let abort_user_code = crate::analyzer::semantic::workspace_oracle::abort_paths_run_user_code(
        procedure.semantics(),
    );
    let relevant_value_gaps = relevant_value_gap_carriers(snapshot, sources, sinks);
    let mut residual = Vec::new();
    for gap in procedure.semantics().gaps() {
        let classification = classify_gap_openness(procedure.semantics(), gap, abort_user_code);
        if matches!(
            classification,
            GapOpenness::Irrelevant | GapOpenness::Discharged
        ) {
            continue;
        }
        if parameter_index_gap_is_refined_by_call_bindings(
            snapshot,
            gap,
            bindings,
            snapshots,
            limits,
            caller_origins,
        ) {
            continue;
        }
        // A refinement call whose handle does not resolve takes the same path
        // as a gap with no refinement call.
        let refinement_call = match classification {
            GapOpenness::RefinementCall(call) => procedure.call_site_handle(call),
            _ => None,
        };
        match refinement_call {
            Some(call) => {
                if !resolved_external_calls.is_empty() && resolved_external_calls.contains(&call) {
                    continue;
                }
                if !binding_complete.get(&call).copied().unwrap_or(false)
                    && !residual.contains(&call)
                {
                    residual.push(call);
                }
            }
            // Not a call-target refinement gap. It still does not have to
            // block this snapshot: a gap of any other capability (for
            // example `FieldMemory`, #2538/#2545) can be proven discharged
            // by a predicate that needs query-time analyzer access this
            // pure re-derivation does not have. `snapshot` itself already
            // ran that predicate while it was materialized
            // (`WorkspaceSemanticOracle::procedure_relations`'s own-gap
            // sweep) and recorded the answer; trust it here rather than
            // either duplicating every such predicate or treating every
            // non-refinement gap as permanently blocking. A gap this
            // snapshot did *not* prove discharged still ends this function
            // with `None`, exactly as before -- the fails-closed path is
            // unchanged.
            None if snapshot.gap_is_discharged(gap.id) => {}
            None if value_call_gap_is_local_dead_end(snapshot, gap, &relevant_value_gaps) => {}
            None => {
                let handle = procedure
                    .gap_handle(gap.id)
                    .expect("a snapshot gap remains live in its procedure");
                return SnapshotOpenness::Blocked(Some((handle, gap.capability)));
            }
        }
    }
    SnapshotOpenness::Refinable(residual)
}

/// Refine only the parameter-backed constant-index partition that an exact
/// caller binding models. The canonical-index marker alone remains the narrow
/// #2831 proof; this additional discharge requires every entered call to bind
/// the exact formal to one complete structured caller origin.
fn parameter_index_gap_is_refined_by_call_bindings<'snapshot>(
    snapshot: &ValueFlowSnapshot,
    gap: &crate::analyzer::semantic::SemanticGap,
    bindings: &[ValueFlowInput<CallBindings>],
    snapshots: &'snapshot [ValueFlowInput<ValueFlowSnapshot>],
    limits: ValueFlowPlanLimits,
    caller_origins: &mut CallerOriginIndexes<'snapshot>,
) -> bool {
    if gap.discharge != crate::analyzer::semantic::SemanticGapDischarge::CanonicalIndexIdentity {
        return false;
    }
    let crate::analyzer::semantic::SemanticGapSubject::MemoryLocation(location) = gap.subject
    else {
        return false;
    };
    let Some(crate::analyzer::semantic::MemoryLocationKind::Index {
        base,
        constant_index: Some(_),
        ..
    }) = snapshot
        .procedure()
        .semantics()
        .memory_location(location)
        .map(|location| &location.kind)
    else {
        return false;
    };

    let mut pending = vec![*base];
    let mut visited = HashSet::default();
    let mut ordinal = None;
    while let Some(current) = pending.pop() {
        if !visited.insert(current) {
            continue;
        }
        if let Some(crate::analyzer::semantic::SemanticValueKind::Parameter {
            ordinal: current_ordinal,
            ..
        }) = snapshot
            .procedure()
            .semantics()
            .value(current)
            .map(|value| &value.kind)
            && ordinal
                .replace(*current_ordinal)
                .is_some_and(|old| old != *current_ordinal)
        {
            return false;
        }
        for point in snapshot.procedure().semantics().points() {
            for event in &point.events {
                match event.effect {
                    SemanticEffect::Assignment { target, value } if target == current => {
                        pending.push(value);
                    }
                    SemanticEffect::ValueFlow {
                        kind:
                            ValueFlowKind::Local
                            | ValueFlowKind::BackingStore { .. }
                            | ValueFlowKind::Parameter,
                        source,
                        target,
                    } if target == current => pending.push(source),
                    _ => {}
                }
            }
        }
    }
    let Some(ordinal) = ordinal else {
        return false;
    };

    let matching = bindings
        .iter()
        .filter(|input| input.value().callee().durable_key() == snapshot.procedure().durable_key())
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return false;
    }
    let path_limits = call_location_oracle_limits(limits.max_access_path);
    matching.into_iter().all(|input| {
        let binding = input.value();
        if !input.status().is_complete()
            || binding.coverage() != CandidateCoverage::Exhaustive
            || binding.context().was_truncated()
            || !matches!(binding.candidate().proof(), ProofStatus::Proven)
            || !matches!(
                binding.candidate().completeness(),
                EvidenceCompleteness::Complete
            )
        {
            return false;
        }
        let caller_snapshot = snapshot_for_procedure(snapshots, binding.call().procedure());
        let actuals = binding.bindings().iter().flat_map(|binding| match binding {
            CallBinding::ArgumentGroup(group) => group
                .mappings()
                .iter()
                .filter(|mapping| {
                    mapping.value().preserves_reference_identity()
                        && matches!(
                            mapping.value().formal().kind(),
                            ProcedurePortKind::Parameter { ordinal: actual } if actual == ordinal
                        )
                })
                .map(|mapping| {
                    (
                        mapping.value().actual(),
                        mapping.proof(),
                        mapping.completeness(),
                    )
                })
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        });
        let actuals = actuals.collect::<Vec<_>>();
        actuals.len() == 1
            && matches!(actuals[0].1, ProofStatus::Proven)
            && matches!(actuals[0].2, EvidenceCompleteness::Complete)
            && {
                let origins = caller_storage_origins(
                    actuals[0].0,
                    caller_snapshot,
                    limits.max_carriers,
                    path_limits,
                    caller_origins,
                );
                !origins.incomplete
                    && origins.origins.len() == 1
                    && origins.origins[0].location.path().is_exact()
                    && matches!(origins.origins[0].proof, ProofStatus::Proven)
                    && matches!(
                        origins.origins[0].completeness,
                        EvidenceCompleteness::Complete
                    )
            }
    })
}

/// The value carriers whose incomplete semantics can affect a selected source
/// or sink, or escape this procedure through a port, memory location, or call
/// operand.
///
/// Build the reverse closure once per snapshot rather than walking every
/// relation once per gap. The seed set is conservative at every boundary: a
/// value passed to a call or projected onto heap/port state stays relevant even
/// when this plan has no local sink for it (#2600).
fn relevant_value_gap_carriers(
    snapshot: &ValueFlowSnapshot,
    sources: &[ValueFlowSourceSpec],
    sinks: &[ValueFlowSinkSpec],
) -> HashSet<ValueFlowCarrier> {
    let mut predecessors: HashMap<ValueFlowCarrier, Vec<ValueFlowCarrier>> = HashMap::default();
    let mut pending = sources
        .iter()
        .map(|source| source.carrier().clone())
        .chain(sinks.iter().map(|sink| sink.carrier().clone()))
        .collect::<Vec<_>>();
    for relation in snapshot.relations() {
        let source = ValueFlowCarrier::from(&relation.source);
        let target = ValueFlowCarrier::from(&relation.target);
        if matches!(
            source,
            ValueFlowCarrier::Port(_) | ValueFlowCarrier::Location(_)
        ) {
            pending.push(source.clone());
        }
        if matches!(
            target,
            ValueFlowCarrier::Port(_) | ValueFlowCarrier::Location(_)
        ) {
            pending.push(target.clone());
        }
        predecessors.entry(target).or_default().push(source);
    }
    for call in snapshot.procedure().semantics().call_sites() {
        pending.extend(
            std::iter::once(call.callee)
                .chain(call.receiver)
                .chain(call.arguments.iter().map(|argument| argument.value))
                .filter_map(|value| snapshot.procedure().value_handle(value))
                .map(ValueFlowCarrier::for_value),
        );
    }

    let mut reached = HashSet::default();
    while let Some(carrier) = pending.pop() {
        if !reached.insert(carrier.clone()) {
            continue;
        }
        if let Some(sources) = predecessors.get(&carrier) {
            pending.extend(sources.iter().cloned());
        }
    }
    reached
}

/// Whether a value-scoped call-semantics gap is trapped in unobserved local
/// values. Other capabilities, including callable-reference construction, keep
/// their existing fail-closed behavior even when their subject looks dead.
fn value_call_gap_is_local_dead_end(
    snapshot: &ValueFlowSnapshot,
    gap: &crate::analyzer::semantic::SemanticGap,
    relevant: &HashSet<ValueFlowCarrier>,
) -> bool {
    if gap.capability != crate::analyzer::semantic::SemanticCapability::Calls {
        return false;
    }
    let SemanticGapSubject::Value(value) = gap.subject else {
        return false;
    };
    let Some(value) = snapshot.procedure().value_handle(value) else {
        debug_assert!(false, "validated gap subject must name a live value");
        return false;
    };
    !relevant.contains(&ValueFlowCarrier::for_value(value))
}

fn summary_evidence_is_proven_complete(evidence: &SummaryEvidence) -> bool {
    evidence
        .alternatives()
        .iter()
        .any(|alternative| alternative.quality().is_proven() && alternative.quality().is_complete())
}

/// The labels a sanitize effect removes on the `input`-to-`output` transfer, or
/// an empty slice when no sanitize effect names that exact port pair (#1923).
/// A summary declares at most one sanitize per port pair, so the first match
/// is the answer.
fn sanitize_removed_labels<'a>(
    effects: &'a [SummaryEffect],
    input: &SummaryPort,
    output: &SummaryPort,
) -> &'a [Box<str>] {
    effects
        .iter()
        .find_map(|effect| match effect.key() {
            SummaryEffectKey::Sanitize {
                input: sanitize_input,
                output: sanitize_output,
                removed,
            } if sanitize_input == input && sanitize_output == output => Some(removed.as_ref()),
            _ => None,
        })
        .unwrap_or(&[])
}

/// How strong a dispatch boundary's proof must be for it to count as fully
/// modeled.
///
/// `execution_result_complete` asks with `Derived`: a boundary is modeled only
/// when the solver derived a proof for it. The `ProvenBySummary` completion
/// tier (#1916) asks the weaker question with `AcceptAuthoredComplete` -- would
/// the run be complete if an authored-complete external procedure summary were
/// accepted as closing its boundary, even though `bind_compiled_procedure_summaries`
/// deliberately stamps that boundary's proof authored rather than derived. The
/// relaxation touches only the external-summary branch; a curated model, a
/// limit, a continuation, or a partial summary is unaffected.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SummaryProofRequirement {
    Derived,
    AcceptAuthoredComplete,
}

/// How one summary transfer input binds at a concrete call.
///
/// Constants deliberately have no value-flow carrier: no caller fact can flow
/// into a literal. A transfer sourced by such a parameter is therefore an
/// empty, vacuously modeled transfer rather than a missing-model gap (#2455).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SummaryInputBinding {
    Carrier(ValueFlowCarrierId),
    VacuousConstant,
    /// An exact constructor binding proves that this optional or variadic
    /// formal received no caller argument, so no caller fact enters it.
    OmittedArgument,
    /// The call names a live value for this port, but the plan retains no
    /// carrier for it. No caller fact can enter through the port, and no fact
    /// the transfer would produce at it can be observed, so the transfer is
    /// vacuous over this plan's carriers rather than a missing-model gap
    /// (#3406). Distinct from `Unbound`, where the port has no value at all
    /// and the model genuinely does not describe this call.
    CarrierlessValue,
    Unbound,
}

/// One dispatch boundary closed by an authored-complete external summary
/// (#2342).
///
/// A run that concludes `ProvenBySummary` because of such a closure is trusting
/// an authored claim to model an external target. When the dispatch result also
/// retained a residual arm, the claim describes that target's whole target set,
/// not only its behavior. The run records which claim it was in both cases: the
/// call whose boundary was closed, the exact target the summary was selected by,
/// and the summary's authored origin -- model id, content hash, and contract
/// version. A consumer rendering the run can state what proved the closure
/// instead of reporting an unexplained conclusion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoredArmClosure {
    call: CallSiteHandle,
    context: OracleCallContext,
    target: SemanticLocator,
    origin: ExternalSummaryOrigin,
}

impl AuthoredArmClosure {
    /// Exact caller context whose boundary the authored claim discharged.
    pub const fn call_context(&self) -> &OracleCallContext {
        &self.context
    }

    /// The call whose dispatch boundary this closure discharged.
    pub const fn call(&self) -> &CallSiteHandle {
        &self.call
    }

    /// The exact target the discharging summary was selected by.
    pub const fn target(&self) -> &SemanticLocator {
        &self.target
    }

    /// The authored identity of the discharging summary.
    pub const fn origin(&self) -> &ExternalSummaryOrigin {
        &self.origin
    }

    pub(crate) fn retained_heap_bytes(&self) -> usize {
        super::semantic_locator_heap_bytes(&self.target)
            .saturating_add(self.origin.model().as_str().len())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CallFlowRule {
    pub context: OracleCallContext,
    pub call: CallSiteHandle,
    pub callee: ProcedureHandle,
    pub kind: CallFlowRuleKind,
    /// Optional proven conversion annotation on a value-dependence edge.
    /// Absence does not prove an identity conversion or transport heap aliases.
    pub transfer: Option<ValueTransfer>,
    pub source: ValueFlowCarrierId,
    pub target: ValueFlowCarrierId,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

/// A call-location rule before its endpoints receive dense plan-local IDs.
///
/// Keeping this intermediate form lets projected locations participate in the
/// same carrier and relation limits as snapshot rows. It also means a path is
/// never synthesized after `carrier_ids` has been assigned, where a forgotten
/// endpoint would otherwise become a partial, unindexed transfer.
#[derive(Debug, Clone)]
struct PendingCallFlowRule {
    context: OracleCallContext,
    call: CallSiteHandle,
    callee: ProcedureHandle,
    kind: CallFlowRuleKind,
    source: ValueFlowCarrier,
    target: ValueFlowCarrier,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

#[derive(Debug, Clone)]
struct CallerOrigin {
    location: AbstractLocation,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

#[derive(Debug, Default)]
struct CallerOriginSearch {
    origins: Vec<CallerOrigin>,
    incomplete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CallFallbackProfile {
    call: CallSiteHandle,
    inputs: Box<[ValueFlowCarrierId]>,
    reachable_components: Box<[usize]>,
    normal_output: Option<ValueFlowCarrierId>,
    exceptional_output: Option<ValueFlowCarrierId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BoundaryTransferApplication {
    pub modeled: bool,
    pub complete: bool,
    pub abstained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundBoundaryTransfer {
    pub target: ValueFlowCarrierId,
    pub proven_complete: bool,
    /// A complete, exactly bound authored summary closes this transfer. It
    /// is an authored claim, never source-derived proof.
    pub authored_complete: bool,
    /// Stable labels a matching sanitize effect removes on this modeled
    /// transfer (#1923). It is empty for a plain flow-through. When this
    /// transfer's own input was composed from a sibling transfer's output on
    /// the same call (#2567), this is the *union* of every sanitize
    /// encountered along the composed path, not only this transfer's own
    /// effect -- see `visit_modeled_transfers` for why that union is exactly
    /// equivalent to chaining `TaintEdgeFunction::kill` once per hop. Owned
    /// (not borrowed) because a composed path's label set does not live
    /// inside any single transfer's own effect record. The taint client
    /// resolves these labels against its run universe and composes a kill.
    pub removed_labels: Vec<Box<str>>,
}

/// One curated transfer model after its selector has been bound to a live
/// semantic call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueFlowCuratedCallModel {
    call: CallSiteHandle,
    model: CuratedCallModel,
}

/// Structured binding from a summary heap/capture port to one live bounded
/// value-flow carrier at a call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueFlowSummaryLocationBinding {
    call: CallSiteHandle,
    port: SummaryPort,
    carrier: ValueFlowCarrier,
}

impl ValueFlowSummaryLocationBinding {
    pub fn new(call: CallSiteHandle, port: SummaryPort, carrier: ValueFlowCarrier) -> Self {
        Self {
            call,
            port,
            carrier,
        }
    }
}

/// One proven returned-callable association: a call whose result is exactly
/// one local closure, and the environment slots that closure captured.
///
/// The producing call returned the callable, and the closure's creation in the
/// producing procedure bound each listed slot. The slots are the closure's own
/// memory locations -- the same identities its body reads and writes through
/// its capture ports -- so a consumer knows that this callable's closed-over
/// storage stays live for as long as the callable itself does. Because the
/// callable escapes through the producing call's result, that storage also
/// survives the call's normal return: a plan can connect each capture port
/// across that return edge without re-deriving which callable the result
/// names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueFlowReturnedCallable {
    producer: CallSiteHandle,
    producer_callee: ProcedureHandle,
    closure: ProcedureHandle,
    captures: Box<[MemoryLocationId]>,
}

impl ValueFlowReturnedCallable {
    pub fn new(
        producer: CallSiteHandle,
        producer_callee: ProcedureHandle,
        closure: ProcedureHandle,
        captures: Vec<MemoryLocationId>,
    ) -> Self {
        Self {
            producer,
            producer_callee,
            closure,
            captures: captures.into_boxed_slice(),
        }
    }

    /// The call whose result supplied the callable value.
    pub const fn producer(&self) -> &CallSiteHandle {
        &self.producer
    }

    /// The procedure the producing call resolved to.
    pub const fn producer_callee(&self) -> &ProcedureHandle {
        &self.producer_callee
    }

    /// The local callable body the returned value names.
    pub const fn closure(&self) -> &ProcedureHandle {
        &self.closure
    }

    /// The closure's environment slots, in the closure's own procedure.
    pub fn captures(&self) -> &[MemoryLocationId] {
        &self.captures
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BoundSummaryLocationBinding {
    call: CallSiteHandle,
    port: SummaryPort,
    // None explicitly keeps an unproven receiver storage port unbound.
    carrier: Option<ValueFlowCarrierId>,
}

impl ValueFlowCuratedCallModel {
    pub fn new(call: CallSiteHandle, model: CuratedCallModel) -> Self {
        Self { call, model }
    }

    pub fn call(&self) -> &CallSiteHandle {
        &self.call
    }

    pub const fn model(&self) -> &CuratedCallModel {
        &self.model
    }
}

/// How one snapshot input participates in discovery completeness (#1952).
///
/// `Refinable` records a snapshot left `Unknown` only by call-target
/// refinement gaps whose calls have no complete binding in this plan. Such a
/// snapshot does not make discovery complete by itself, but an execution
/// result that fully models exactly those calls (a complete external summary
/// or curated model closing their boundaries) answers the same gaps, so
/// `execution_result_complete` treats it as closed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SnapshotDiscovery {
    Complete,
    Refinable {
        calls: Box<[CallSiteHandle]>,
    },
    Incomplete {
        gap: Option<(SemanticGapHandle, SemanticCapability)>,
    },
}

/// The first discovery input, in the plan's deterministic input order
/// (sorted snapshots, then sorted bindings, then sources, then sinks), that
/// prevented `discovery_complete` (#1952).
///
/// The cause keeps the typed `SemanticInputStatus`, so a downstream client can
/// distinguish a missing capability from an unproven or budget-limited input
/// instead of collapsing every incomplete run into one generic reason.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValueFlowIncompleteCause {
    Snapshot {
        procedure: ProcedureHandle,
        status: SemanticInputStatus,
    },
    SnapshotCoverage {
        procedure: ProcedureHandle,
    },
    /// The snapshot retained usable local relations, but one exact producer
    /// gap still blocks a complete verdict. Keeping the gap handle and its
    /// capability prevents access-path, control-flow, and other semantic
    /// blockers from being flattened into an "unknown snapshot" diagnosis.
    SemanticGap {
        gap: SemanticGapHandle,
        capability: SemanticCapability,
        status: SemanticInputStatus,
    },
    /// The snapshot's local relations are usable, but one call-target
    /// refinement gap has no complete binding in this plan. The execution
    /// layer may still close this boundary with a complete model; until then
    /// the run remains typed incomplete.
    CallResolution {
        call: CallSiteHandle,
        status: SemanticInputStatus,
    },
    CallBinding {
        call: CallSiteHandle,
        callee: ProcedureHandle,
        status: SemanticInputStatus,
    },
    CallBindingCoverage {
        call: CallSiteHandle,
        callee: ProcedureHandle,
    },
    /// A source or sink was observed in a procedure this plan mounts but the
    /// solve cannot enter (#2640).
    UnenteredProcedure {
        procedure: ProcedureHandle,
    },
    SourceEvidence {
        point: ProgramPointHandle,
    },
    SinkEvidence {
        point: ProgramPointHandle,
    },
    /// A policy-local relation was structurally bound, but its selector or
    /// port evidence was not both proven and complete.
    LocalRuleEvidence {
        point: ProgramPointHandle,
    },
}

impl ValueFlowIncompleteCause {
    pub const fn status(&self) -> Option<SemanticInputStatus> {
        match self {
            Self::Snapshot { status, .. }
            | Self::SemanticGap { status, .. }
            | Self::CallResolution { status, .. }
            | Self::CallBinding { status, .. } => Some(*status),
            Self::SnapshotCoverage { .. }
            | Self::CallBindingCoverage { .. }
            | Self::UnenteredProcedure { .. }
            | Self::SourceEvidence { .. }
            | Self::SinkEvidence { .. }
            | Self::LocalRuleEvidence { .. } => None,
        }
    }

    pub fn procedure(&self) -> &ProcedureHandle {
        match self {
            Self::Snapshot { procedure, .. }
            | Self::SnapshotCoverage { procedure }
            | Self::UnenteredProcedure { procedure } => procedure,
            Self::SemanticGap { gap, .. } => gap.procedure(),
            Self::CallResolution { call, .. } => call.procedure(),
            Self::CallBinding { callee, .. } | Self::CallBindingCoverage { callee, .. } => callee,
            Self::SourceEvidence { point }
            | Self::SinkEvidence { point }
            | Self::LocalRuleEvidence { point } => point.procedure(),
        }
    }

    pub const fn label(&self) -> &'static str {
        match self {
            Self::Snapshot { .. } => "procedure value-flow snapshot",
            Self::SnapshotCoverage { .. } => "procedure value-flow coverage",
            Self::SemanticGap { capability, .. } => match capability {
                SemanticCapability::FieldMemory | SemanticCapability::IndexMemory => {
                    "access-path resolution"
                }
                _ => "procedure semantics",
            },
            Self::CallResolution { .. } => "call resolution",
            Self::CallBinding { .. } => "call binding",
            Self::CallBindingCoverage { .. } => "call binding coverage",
            Self::UnenteredProcedure { .. } => "procedure entry",
            Self::SourceEvidence { .. } => "source evidence",
            Self::SinkEvidence { .. } => "sink evidence",
            Self::LocalRuleEvidence { .. } => "policy-local flow-rule evidence",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct BoundValueFlowSource {
    pub id: ValueFlowSourceId,
    pub spec: ValueFlowSourceSpec,
    pub carrier: ValueFlowCarrierId,
    pub activation_triggers: Option<ValueFlowSourceListId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct BoundValueFlowSink {
    pub id: ValueFlowSinkId,
    pub spec: ValueFlowSinkSpec,
    pub carrier: ValueFlowCarrierId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CallRuleTargetKey {
    call: CallSiteHandle,
    callee: ProcedureHandle,
    kind: CallFlowRuleKind,
    target: ValueFlowCarrierId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ObservationKey {
    point: ProgramPointHandle,
    phase: ValueFlowObservationPhase,
}

fn event_key_index<T, F>(entries: &[T], key: &ValueFlowEventKey, event_key: F) -> Option<usize>
where
    F: for<'entry> Fn(&'entry T) -> &'entry ValueFlowEventKey,
{
    entries
        .binary_search_by(|entry| event_key(entry).cmp(key))
        .ok()
}

fn indexed_entries<'a, T>(
    entries: &'a [T],
    indexes: Option<&'a [usize]>,
    feasible: bool,
) -> impl Iterator<Item = &'a T> + 'a {
    indexes
        .into_iter()
        .flatten()
        .filter(move |_| feasible)
        .map(move |index| &entries[*index])
}

fn same_propagation_configuration(left: &ValueFlowPlan, right: &ValueFlowPlan) -> bool {
    left.root == right.root
        && left.contextual_bindings == right.contextual_bindings
        && left.unmodeled_call_behavior == right.unmodeled_call_behavior
        && left.external_summaries == right.external_summaries
        && left.curated_call_models == right.curated_call_models
        && left.edge_kills.len() == right.edge_kills.len()
        && left.edge_kills.iter().zip(&right.edge_kills).all(|(a, b)| {
            a.point == b.point
                && a.target == b.target
                && a.kind == b.kind
                && a.carrier == b.carrier
                && a.labels == b.labels
                && left.source_list_keys(a.sources) == right.source_list_keys(b.sources)
        })
        && left.snapshot_procedures == right.snapshot_procedures
        && left.binding_pairs == right.binding_pairs
        && left.discovery_status == right.discovery_status
        && left.discovery_complete == right.discovery_complete
        && left.structural_discovery_complete == right.structural_discovery_complete
}

/// Immutable point lookup tables derived from the canonical local rule array.
/// The values are rule-array positions in canonical forward order rather than
/// cloned rules, so every lookup retains the plan's one authoritative rule
/// representation; the backward accessor reverses a bucket only while reading.
#[derive(Debug, Clone, Default)]
struct LocalRulePointIndex {
    /// Every local rule at a point. A backward preimage may change carriers,
    /// so a target-only bucket is insufficient for chained same-point rules.
    by_point: HashMap<ProgramPointHandle, Box<[usize]>>,
}

/// Immutable reverse lookup tables derived from the canonical call rule array.
/// Entries for one target retain the canonical source ordering used by the
/// forward client.
#[derive(Debug, Clone, Default)]
struct CallRuleReverseIndex {
    by_target: HashMap<CallRuleTargetKey, Box<[usize]>>,
}

/// Immutable point/phase lookup table for one observation kind.
#[derive(Debug, Clone, Default)]
struct ObservationIndex {
    by_point_phase: HashMap<ObservationKey, Box<[usize]>>,
}

impl LocalRulePointIndex {
    fn retained_heap_bytes(&self) -> usize {
        reverse_index_heap_bytes(&self.by_point)
    }
}

impl CallRuleReverseIndex {
    fn retained_heap_bytes(&self) -> usize {
        reverse_index_heap_bytes(&self.by_target)
    }
}

impl ObservationIndex {
    fn retained_heap_bytes(&self) -> usize {
        reverse_index_heap_bytes(&self.by_point_phase)
    }
}

impl EdgeKillIndex {
    fn retained_heap_bytes(&self) -> usize {
        self.by_edge
            .capacity()
            .saturating_mul(
                std::mem::size_of::<(EdgeKillKey, Box<[BoundValueFlowEdgeKill]>)>()
                    .saturating_add(1),
            )
            .saturating_add(
                self.by_edge
                    .values()
                    .map(|kills| size_of_val(kills.as_ref()))
                    .fold(0usize, usize::saturating_add),
            )
    }
}

fn reverse_index_heap_bytes<K>(index: &HashMap<K, Box<[usize]>>) -> usize {
    index
        .capacity()
        .saturating_mul(std::mem::size_of::<(K, Box<[usize]>)>().saturating_add(1))
        .saturating_add(
            index
                .values()
                .map(|positions| size_of_val(positions.as_ref()))
                .fold(0usize, usize::saturating_add),
        )
}

/// Immutable, canonical, already-resolved transfer plan for one solver run.
#[derive(Debug, Clone)]
pub struct ValueFlowPlan {
    root: ProcedureHandle,
    unmodeled_call_behavior: UnmodeledCallBehavior,
    external_summaries: ExternalSemanticSummarySet,
    curated_call_models: Box<[ValueFlowCuratedCallModel]>,
    carriers: Box<[ValueFlowCarrier]>,
    carrier_keys: Box<[ValueFlowCarrierKey]>,
    carrier_ids: HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
    local_rules: Box<[LocalFlowRule]>,
    /// Derived lookup only; canonical rule identity remains `local_rules`.
    /// This field is intentionally absent from `PartialEq`, `Hash`, and
    /// propagation compatibility; `retained_bytes` still charges its storage.
    local_rule_point_index: LocalRulePointIndex,
    call_rules: Box<[CallFlowRule]>,
    contextual_bindings: bool,
    /// Derived lookup only; canonical rule identity remains `call_rules`.
    /// This field is intentionally absent from `PartialEq`, `Hash`, and
    /// propagation compatibility; `retained_bytes` still charges its storage.
    call_rule_reverse_index: CallRuleReverseIndex,
    fallback_profiles: Box<[CallFallbackProfile]>,
    fallback_locations: FallbackLocationIndex,
    summary_location_bindings: Box<[BoundSummaryLocationBinding]>,
    sources: Box<[BoundValueFlowSource]>,
    /// Canonical event-key order for external identity lookup; IDs remain insertion-local.
    source_key_order: Box<[ValueFlowSourceId]>,
    /// Derived point/phase lookup; observation identity remains `sources`.
    source_index: ObservationIndex,
    sinks: Box<[BoundValueFlowSink]>,
    /// Derived point/phase lookup; observation identity remains `sinks`.
    sink_index: ObservationIndex,
    source_lists: Box<[Box<[ValueFlowSourceId]>]>,
    edge_kills: Box<[ValueFlowEdgeKillSpec]>,
    /// Derived dense-ID lookup; canonical identity remains `edge_kills`.
    edge_kill_index: EdgeKillIndex,
    snapshot_procedures: Box<[ProcedureHandle]>,
    /// Derived from the same procedures the plan was built over, so it is
    /// deliberately absent from `PartialEq` and `Hash`: two plans that agree on
    /// their inputs cannot disagree here (#2443 slice 2).
    infeasible_points: ConstantInfeasiblePoints,
    binding_pairs: Box<[(CallSiteHandle, ProcedureHandle)]>,
    resolved_external_calls: Box<[CallSiteHandle]>,
    discovery_status: SemanticInputStatus,
    first_incomplete_cause: Option<ValueFlowIncompleteCause>,
    snapshot_discoveries: Box<[SnapshotDiscovery]>,
    non_snapshot_discovery_complete: bool,
    /// Endpoint-only slice of `non_snapshot_discovery_complete`: whether every
    /// source and sink spec is proven, complete, and entered. Binding-input
    /// incompleteness is tracked per call in `incomplete_binding_calls` so a
    /// curated model that claims a call's whole behavior can answer it at
    /// result time.
    endpoint_discovery_complete: bool,
    /// Calls whose `CallBindings` input stayed incomplete. Discovery closes
    /// only when each is answered by a curated model over a fully modeled
    /// result boundary; without a curated model the plan stays exactly as
    /// strict as the combined flag was.
    incomplete_binding_calls: Box<[CallSiteHandle]>,
    ambiguous_dispatch: bool,
    discovery_complete: bool,
    structural_discovery_complete: bool,
    owner: Arc<()>,
}

fn same_plan_structure(left: &ValueFlowPlan, right: &ValueFlowPlan) -> bool {
    same_propagation_configuration(left, right)
        && left.carriers == right.carriers
        && left.carrier_keys == right.carrier_keys
        && left.carrier_ids == right.carrier_ids
        && left.local_rules == right.local_rules
        && left.call_rules == right.call_rules
        && left.fallback_profiles == right.fallback_profiles
        && left.fallback_locations == right.fallback_locations
        && left.summary_location_bindings == right.summary_location_bindings
        && left.sinks == right.sinks
        && left.resolved_external_calls == right.resolved_external_calls
        && left.first_incomplete_cause == right.first_incomplete_cause
        && left.snapshot_discoveries == right.snapshot_discoveries
        && left.non_snapshot_discovery_complete == right.non_snapshot_discovery_complete
        && left.ambiguous_dispatch == right.ambiguous_dispatch
}

impl PartialEq for ValueFlowPlan {
    fn eq(&self, other: &Self) -> bool {
        same_plan_structure(self, other) && same_source_specs(self, other)
    }
}

impl Eq for ValueFlowPlan {}

impl Hash for ValueFlowPlan {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.root.hash(state);
        self.unmodeled_call_behavior.hash(state);
        self.external_summaries.fingerprint().hash(state);
        self.curated_call_models.len().hash(state);
        for model in &self.curated_call_models {
            model.call.hash(state);
            model.model.fingerprint().hash(state);
        }
        self.carrier_keys.hash(state);
        self.local_rules.hash(state);
        self.contextual_bindings.hash(state);
        self.call_rules.hash(state);
        self.fallback_profiles.hash(state);
        self.summary_location_bindings.hash(state);
        let sources = self
            .source_key_order
            .iter()
            .map(|id| &self.sources[id.index()])
            .collect::<Vec<_>>();
        // Keep SourceId as the element type: registration digests also encode
        // Hasher write boundaries, which primitive slice hashing can combine.
        let mut ranks = vec![ValueFlowSourceId::new(0); self.sources.len()];
        for (rank, source) in sources.iter().enumerate() {
            ranks[source.id.index()] =
                ValueFlowSourceId::try_from_index(rank).expect("a validated source rank fits u32");
        }
        sources.len().hash(state);
        for source in sources {
            ranks[source.id.index()].hash(state);
            hash_source_spec(self, &source.spec, state);
            source.carrier.hash(state);
            source
                .activation_triggers
                .map(|list| {
                    let mut ids = self
                        .source_list(list)
                        .iter()
                        .map(|id| ranks[id.index()])
                        .collect::<Vec<_>>();
                    ids.sort_unstable();
                    ids
                })
                .hash(state);
        }
        self.sinks.hash(state);
        self.edge_kills.len().hash(state);
        for kill in &self.edge_kills {
            kill.point.hash(state);
            kill.target.hash(state);
            kill.kind.hash(state);
            kill.carrier.hash(state);
            self.source_list_keys(kill.sources).hash(state);
            if let Some(labels) = &kill.labels {
                b"edge_kill_labels".hash(state);
                labels.hash(state);
            }
        }
        self.snapshot_procedures.hash(state);
        self.binding_pairs.hash(state);
        self.resolved_external_calls.hash(state);
        self.discovery_status.hash(state);
        self.first_incomplete_cause.hash(state);
        self.snapshot_discoveries.hash(state);
        self.non_snapshot_discovery_complete.hash(state);
        self.ambiguous_dispatch.hash(state);
        self.discovery_complete.hash(state);
        self.structural_discovery_complete.hash(state);
    }
}

/// The program points a constant branch condition proves cannot execute, for
/// every procedure in one plan that has any (#2443 slice 2).
///
/// Almost always empty, and the empty case costs one length check: a lowerer
/// that folds `if (false)` emits no excluded edge at all -- the guard row
/// records the fold, and the dead region is unreachable without help from
/// here. What this covers is a condition a lowerer normalizes but does not
/// fold, such as Java's `!true`, where both arms are real edges and the solver
/// would otherwise walk the one that cannot execute.
///
/// A procedure with any infeasible point keeps its points sorted, so a lookup
/// is a scan of a list that is normally length zero followed by a binary
/// search.
type ConstantInfeasiblePoints = Box<[(ProcedureHandle, Box<[ProgramPointId]>)]>;

fn constant_infeasible_points<'a>(
    procedures: impl IntoIterator<Item = &'a ProcedureHandle>,
) -> ConstantInfeasiblePoints {
    let mut index: Vec<(ProcedureHandle, Box<[ProgramPointId]>)> = Vec::new();
    for procedure in procedures {
        if index.iter().any(|(known, _)| known == procedure) {
            continue;
        }
        let points = procedure_infeasible_points(procedure.semantics());
        if !points.is_empty() {
            index.push((procedure.clone(), points));
        }
    }
    index.into_boxed_slice()
}

impl ValueFlowPlan {
    /// Keep element values from defining the class of language-known rest
    /// parameter containers in a class-set projection. General value-flow
    /// plans retain these argument-to-formal transfers unchanged.
    pub(crate) fn without_call_value_inputs_to(
        mut self,
        container_parameters: &HashSet<ProcedurePortHandle>,
    ) -> Self {
        let container_parameter_ids = container_parameters
            .iter()
            .filter_map(|parameter| {
                self.carrier_ids
                    .get(&ValueFlowCarrier::Port(parameter.clone()))
                    .copied()
            })
            .collect::<HashSet<_>>();
        if container_parameter_ids.is_empty() {
            return self;
        }
        let mut call_rules = self.call_rules.into_vec();
        call_rules.retain(|rule| {
            rule.kind != CallFlowRuleKind::Call || !container_parameter_ids.contains(&rule.target)
        });
        self.call_rule_reverse_index = build_call_rule_reverse_index(&call_rules);
        self.call_rules = call_rules.into_boxed_slice();
        self
    }

    /// Retain only sources and transfer rules that can contribute to `demands`.
    ///
    /// This is a solve-plan slice, not a discovery slice. All carriers, sinks,
    /// semantic input status, coverage, and typed incomplete causes remain
    /// unchanged; only sources proven unable to reach a demand are omitted.
    /// The reverse walk follows the already validated, direction-aware local
    /// and call rules. Call fallback profiles add the conservative
    /// input-to-result relation used by unmodeled and externally summarized
    /// calls, so a summary-controlled boundary cannot be mistaken for an
    /// irrelevant local computation.
    pub(crate) fn retain_flows_reaching(
        mut self,
        demands: impl IntoIterator<Item = ValueFlowCarrier>,
    ) -> Self {
        if self.sinks.is_empty() {
            return self;
        }
        let mut relevant = demands
            .into_iter()
            .filter_map(|carrier| self.carrier_ids.get(&carrier).copied())
            .collect::<HashSet<_>>();
        relevant.extend(self.sinks.iter().map(|sink| sink.carrier));
        relevant.extend(
            self.edge_kills
                .iter()
                .filter_map(|kill| self.carrier_ids.get(&kill.carrier).copied()),
        );
        // A retained summary-location binding may be read or written by a
        // semantic summary without a concrete local rule spelling that
        // transfer. Keep its component demanded rather than trying to infer a
        // smaller contract from summary internals.
        relevant.extend(
            self.summary_location_bindings
                .iter()
                .filter_map(|binding| binding.carrier),
        );
        // The root's procedure ports and all abstract locations are public
        // summary and heap boundaries. They may be demanded by a caller,
        // persisted summary, or later refinement even when this root has no
        // local sink on the same carrier. Callee ports are internal to this
        // root solve, however: exact call rules, fallback profiles, and
        // summary-location bindings above retain the ones that can contribute
        // to a demanded root boundary or receiver observation.
        relevant.extend(
            self.carriers
                .iter()
                .enumerate()
                .filter(|(_, carrier)| {
                    matches!(carrier, ValueFlowCarrier::Location(_))
                        || matches!(carrier, ValueFlowCarrier::Port(port) if port.procedure() == &self.root)
                })
                .map(|(index, _)| {
                    ValueFlowCarrierId::try_from_index(index)
                        .expect("a retained carrier ID fits u32")
                }),
        );

        let mut changed = true;
        while changed {
            changed = false;
            for rule in self.local_rules.iter().rev() {
                if relevant.contains(&rule.target) && relevant.insert(rule.source) {
                    changed = true;
                }
            }
            for rule in self.call_rules.iter().rev() {
                if relevant.contains(&rule.target) && relevant.insert(rule.source) {
                    changed = true;
                }
            }
            for profile in &self.fallback_profiles {
                let output_is_relevant = profile
                    .normal_output
                    .into_iter()
                    .chain(profile.exceptional_output)
                    .any(|output| relevant.contains(&output));
                if output_is_relevant {
                    for input in &profile.inputs {
                        if relevant.insert(*input) {
                            changed = true;
                        }
                    }
                }
            }
        }

        // Source facts that cannot reach any demand cannot affect a class-set
        // observation. Removing them is important as well as removing their
        // transfer rules: reusable-summary preparation otherwise still stages
        // every dead source witness and can exhaust the solver before the
        // smaller rule graph is evaluated. Keep all source-driven guard
        // machinery conservative by retaining every edge-kill carrier above;
        // sources named by a retained kill are therefore already relevant.
        let mut retained_source_ids = self
            .sources
            .iter()
            .filter_map(|source| relevant.contains(&source.carrier).then_some(source.id))
            .collect::<HashSet<_>>();
        retained_source_ids.extend(
            self.edge_kills
                .iter()
                .flat_map(|kill| self.source_list(kill.sources))
                .copied(),
        );
        let mut changed = true;
        while changed {
            changed = false;
            for source in &self.sources {
                if retained_source_ids.contains(&source.id)
                    && let Some(triggers) = &source.activation_triggers
                {
                    for trigger in self.source_list(*triggers) {
                        changed |= retained_source_ids.insert(*trigger);
                    }
                }
            }
        }
        let mut old_to_new_source_ids = HashMap::default();
        let mut sources = Vec::new();
        for source in &self.sources {
            if retained_source_ids.contains(&source.id) {
                let id = ValueFlowSourceId::try_from_index(sources.len())
                    .expect("a retained source ID fits u32");
                old_to_new_source_ids.insert(source.id, id);
                let mut source = source.clone();
                source.id = id;
                sources.push(source);
            }
        }
        let mut source_lists = ValueFlowSourceLists::default();
        let mut list_remap = HashMap::default();
        for list in sources
            .iter()
            .filter_map(|source| source.activation_triggers)
            .chain(self.edge_kills.iter().map(|kill| kill.sources))
        {
            list_remap.entry(list).or_insert_with(|| {
                source_lists.intern(
                    self.source_list(list)
                        .iter()
                        .map(|id| {
                            *old_to_new_source_ids
                                .get(id)
                                .expect("retained source keeps its dependencies")
                        })
                        .collect(),
                )
            });
        }
        for source in &mut sources {
            source.activation_triggers = source.activation_triggers.map(|list| list_remap[&list]);
            if let Some(list) = source.activation_triggers {
                source.spec = source.spec.clone().when_sources_reach(list);
            }
        }
        for kill in &mut self.edge_kills {
            kill.sources = list_remap[&kill.sources];
        }
        self.source_lists = source_lists.into_lists();
        self.source_key_order = source_key_order(&sources);
        self.sources = sources.into_boxed_slice();
        self.source_index = build_observation_index(&self.sources, |source| ObservationKey {
            point: source.spec.point().clone(),
            phase: source.spec.phase(),
        });
        self.edge_kill_index = build_edge_kill_index(&self.edge_kills, &self.carrier_ids)
            .expect("retained kills keep their carriers");

        self.local_rules = self
            .local_rules
            .iter()
            .filter(|rule| relevant.contains(&rule.target))
            .cloned()
            .collect();
        self.call_rules = self
            .call_rules
            .iter()
            .filter(|rule| relevant.contains(&rule.target))
            .cloned()
            .collect();
        self.local_rule_point_index = build_local_rule_point_index(&self.local_rules);
        self.call_rule_reverse_index = build_call_rule_reverse_index(&self.call_rules);
        // Keep the original fallback components and profiles. They are a
        // conservative boundary contract and participate in reusable-summary
        // identity; deriving them from the smaller execution slice would turn
        // an optimization into a semantic change.
        self
    }

    pub fn try_new(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: impl Into<ValueFlowSources>,
        sinks: Vec<ValueFlowSinkSpec>,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::try_new_with_edge_kills(root, snapshots, bindings, sources, sinks, Vec::new())
    }

    pub fn try_new_with_edge_kills(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: impl Into<ValueFlowSources>,
        sinks: Vec<ValueFlowSinkSpec>,
        edge_kills: Vec<ValueFlowEdgeKillSpec>,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::with_call_behavior_and_edge_kills(
            root,
            snapshots,
            bindings,
            sources,
            sinks,
            edge_kills,
            UnmodeledCallBehavior::default(),
        )
    }

    pub fn with_call_behavior(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: impl Into<ValueFlowSources>,
        sinks: Vec<ValueFlowSinkSpec>,
        unmodeled_call_behavior: UnmodeledCallBehavior,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::with_limits_and_call_behavior(
            root,
            snapshots,
            bindings,
            sources,
            sinks,
            ValueFlowPlanLimits::default(),
            unmodeled_call_behavior,
        )
    }

    pub fn with_call_behavior_and_edge_kills(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: impl Into<ValueFlowSources>,
        sinks: Vec<ValueFlowSinkSpec>,
        edge_kills: Vec<ValueFlowEdgeKillSpec>,
        unmodeled_call_behavior: UnmodeledCallBehavior,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::with_call_behavior_and_edge_kills_and_resolved_external_calls(
            root,
            snapshots,
            bindings,
            sources,
            sinks,
            edge_kills,
            unmodeled_call_behavior,
            Vec::new(),
        )
    }

    /// Treat exact resolver-owned external boundaries as call resolutions
    /// while classifying only their matching call-site gaps. Their transfer
    /// behavior remains governed by the external summary set installed later.
    #[allow(clippy::too_many_arguments)]
    pub fn with_call_behavior_and_edge_kills_and_resolved_external_calls(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: impl Into<ValueFlowSources>,
        sinks: Vec<ValueFlowSinkSpec>,
        edge_kills: Vec<ValueFlowEdgeKillSpec>,
        unmodeled_call_behavior: UnmodeledCallBehavior,
        resolved_external_calls: Vec<CallSiteHandle>,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::with_limits_and_call_behavior_and_edge_kills_and_resolved_external_calls(
            root,
            snapshots,
            bindings,
            sources.into(),
            sinks,
            edge_kills,
            ValueFlowPlanLimits::default(),
            unmodeled_call_behavior,
            resolved_external_calls,
        )
    }

    pub fn with_limits(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: impl Into<ValueFlowSources>,
        sinks: Vec<ValueFlowSinkSpec>,
        limits: ValueFlowPlanLimits,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::with_limits_and_call_behavior(
            root,
            snapshots,
            bindings,
            sources,
            sinks,
            limits,
            UnmodeledCallBehavior::default(),
        )
    }

    pub fn with_limits_and_call_behavior(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: impl Into<ValueFlowSources>,
        sinks: Vec<ValueFlowSinkSpec>,
        limits: ValueFlowPlanLimits,
        unmodeled_call_behavior: UnmodeledCallBehavior,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::with_limits_and_call_behavior_and_edge_kills(
            root,
            snapshots,
            bindings,
            sources,
            sinks,
            Vec::new(),
            limits,
            unmodeled_call_behavior,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_limits_and_call_behavior_and_edge_kills(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: impl Into<ValueFlowSources>,
        sinks: Vec<ValueFlowSinkSpec>,
        edge_kills: Vec<ValueFlowEdgeKillSpec>,
        limits: ValueFlowPlanLimits,
        unmodeled_call_behavior: UnmodeledCallBehavior,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::with_limits_and_call_behavior_and_edge_kills_and_resolved_external_calls(
            root,
            snapshots,
            bindings,
            sources.into(),
            sinks,
            edge_kills,
            limits,
            unmodeled_call_behavior,
            Vec::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn with_limits_and_call_behavior_and_edge_kills_and_resolved_external_calls(
        root: ProcedureHandle,
        mut snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        mut bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: ValueFlowSources,
        mut sinks: Vec<ValueFlowSinkSpec>,
        mut edge_kills: Vec<ValueFlowEdgeKillSpec>,
        limits: ValueFlowPlanLimits,
        unmodeled_call_behavior: UnmodeledCallBehavior,
        resolved_external_calls: Vec<CallSiteHandle>,
    ) -> Result<Self, ValueFlowPlanError> {
        let ValueFlowSources {
            specs: sources,
            lists: source_lists,
        } = sources;
        if sources.len() > limits.max_sources || sinks.len() > limits.max_sinks {
            return Err(ValueFlowPlanError::LimitExceeded);
        }
        if snapshots.iter().any(|input| {
            !input.value().context().calls().is_empty() || input.value().context().was_truncated()
        }) || bindings
            .iter()
            .any(|input| input.value().context().was_truncated())
        {
            return Err(ValueFlowPlanError::ContextSensitiveInputUnsupported);
        }
        snapshots.sort_by(|left, right| compare_snapshots(left.value(), right.value()));
        bindings.sort_by(|left, right| compare_bindings(left.value(), right.value()));
        sinks.sort_by(|left, right| left.key().cmp(right.key()));
        if duplicate_source_keys(&sources)
            || adjacent_duplicate(sinks.iter().map(ValueFlowSinkSpec::key))
        {
            return Err(ValueFlowPlanError::DuplicateEventKey);
        }
        validate_source_lists(&sources, &edge_kills, &source_lists)?;
        edge_kills.sort_by(|left, right| compare_edge_kills(left, right, &sources, &source_lists));
        edge_kills.dedup();

        let mount = root.artifact().key().mount();
        let mut discovery_status = SemanticInputStatus::Complete;
        let ambiguous_dispatch = snapshots.iter().any(|input| {
            input
                .value()
                .procedure()
                .semantics()
                .gaps()
                .iter()
                .any(|gap| {
                    gap.kind == SemanticGapKind::Ambiguous
                        && gap.impacts.contains(SemanticGapImpact::DispatchCoverage)
                })
        });
        let mut discovery_complete = true;
        let mut structural_discovery_complete = true;
        let mut first_incomplete_cause: Option<ValueFlowIncompleteCause> = None;
        let mut carrier_candidates = Vec::new();
        let mut relation_count = 0usize;
        let mut unavailable_receivers = Vec::new();
        for input in &snapshots {
            for receiver in input.value().member_receivers() {
                if receiver.preparation()
                    != Some(crate::analyzer::semantic::MemberReceiverPreparation::CopyValue)
                    && receiver.storage().is_empty()
                {
                    unavailable_receivers.push(BoundSummaryLocationBinding {
                        call: receiver.call().clone(),
                        port: SummaryPort::Receiver,
                        carrier: None,
                    });
                }
            }
        }
        unavailable_receivers.sort_by(|left, right| {
            compare_calls(&left.call, &right.call).then_with(|| left.port.cmp(&right.port))
        });
        unavailable_receivers.dedup();
        if unavailable_receivers.len() > MAX_SUMMARY_BOUNDARY_BINDINGS {
            return Err(ValueFlowPlanError::LimitExceeded);
        }
        let mut resolved_external_calls = resolved_external_calls;
        resolved_external_calls.sort_by(compare_calls);
        resolved_external_calls
            .dedup_by(|left, right| compare_calls(left, right) == Ordering::Equal);
        for call in &resolved_external_calls {
            validate_mount(call.procedure(), mount)?;
            if call.procedure().semantics().call_site(call.id()).is_none() {
                return Err(ValueFlowPlanError::StaleExternalCallResolution);
            }
        }
        let resolved_external_call_set = resolved_external_calls
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        let snapshot_procedures = snapshots
            .iter()
            .map(|input| input.value().procedure().clone())
            .collect::<Vec<_>>();
        let contextual_bindings = bindings
            .iter()
            .any(|input| !input.value().context().calls().is_empty());
        let binding_pairs = bindings
            .iter()
            .map(|input| (input.value().call().clone(), input.value().callee().clone()))
            .collect::<Vec<_>>();
        // An exhaustive candidate-specific receiver proof may also prove that
        // resolver alternatives cannot be entered by that call. Preserve that
        // negative identity evidence so an endpoint in an excluded anonymous
        // sibling does not make an otherwise closed plan inconclusive. Merely
        // mounting a lexical child still proves nothing: #2640 shapes without
        // this explicit exclusion continue to report an unentered procedure.
        let excluded = bindings
            .iter()
            .filter(|input| {
                !contextual_bindings
                    && input.status().is_complete()
                    && input.value().coverage() == CandidateCoverage::Exhaustive
                    && !input.value().context().was_truncated()
            })
            .flat_map(|input| input.value().candidate().excluded_targets())
            .map(ProcedureHandle::durable_key)
            .collect::<HashSet<_>>();
        let mut non_snapshot_discovery_complete = true;
        let mut endpoint_discovery_complete = true;
        let mut incomplete_binding_calls: Vec<CallSiteHandle> = Vec::new();
        let mut pending_call_location_rules = Vec::new();
        let mut binding_complete = HashMap::<CallSiteHandle, bool>::default();
        for input in &bindings {
            let complete = input.status().is_complete()
                && input.value().coverage() == CandidateCoverage::Exhaustive
                && !input.value().context().was_truncated();
            binding_complete
                .entry(input.value().call().clone())
                .and_modify(|value| *value &= complete)
                .or_insert(complete);
        }
        // The procedures the solve can actually visit (#2640). An IDE solve
        // seeds at the root's entry point and reaches every other procedure
        // through a mounted call binding's flow rules, so a mounted procedure
        // that is neither the root nor any binding's callee holds no reachable
        // program point. A region mounts such a procedure when it is lexically
        // part of the region but nothing in the region dispatches to it: a
        // lambda, closure, or block body whose invocation resolves to an
        // interface method or a runtime block rather than to the body itself.
        // Before nested bodies were mounted, every snapshot was the root or
        // some binding's callee, so this set changes nothing for the plans that
        // already existed.
        //
        // Membership is durable identity -- artifact key plus procedure ID --
        // not handle identity, because a binding's callee handle comes from the
        // oracle and a snapshot's procedure handle from discovery, and the two
        // can name one procedure through two materializations of its file
        // (#2289). Comparing handles would then read a genuinely entered
        // procedure as unreachable and abstain a decidable region.
        let entered = std::iter::once(&root)
            .chain(binding_pairs.iter().map(|(_, callee)| callee))
            .map(ProcedureHandle::durable_key)
            .collect::<HashSet<_>>();
        let mut caller_origins = CallerOriginIndexes::default();
        let mut snapshot_discoveries = Vec::with_capacity(snapshots.len());
        for input in &snapshots {
            validate_mount(input.value().procedure(), mount)?;
            // An unentered procedure's own input quality cannot change a
            // verdict, because no point in it is reachable. Its relations still
            // mount, but it opens no discovery here; otherwise a lambda with an
            // unlowered construct would abstain a region that never runs it.
            // What the region must not do is decide an endpoint bound inside
            // one, and the source and sink loops below catch exactly that.
            let entered_procedure = entered.contains(&input.value().procedure().durable_key());
            // A typed incomplete snapshot can still be answered by this plan's
            // own exact call evidence: call-target gaps by complete resolution
            // (#1952), or a formal constant-index identity by its exact caller
            // binding (#2856). The classifier closes only the matching gap
            // partition; every residual gap stays open.
            let discovery = if !entered_procedure
                || (input.status().is_complete()
                    && input.value().coverage() == CandidateCoverage::Exhaustive)
            {
                SnapshotDiscovery::Complete
            } else if !input.status().is_complete()
                && input.value().coverage() == CandidateCoverage::Open
            {
                match classify_snapshot_openness(
                    input.value(),
                    &binding_complete,
                    &bindings,
                    &snapshots,
                    limits,
                    &sources,
                    &sinks,
                    &mut caller_origins,
                    &resolved_external_call_set,
                ) {
                    SnapshotOpenness::Refinable(residual) if residual.is_empty() => {
                        SnapshotDiscovery::Complete
                    }
                    SnapshotOpenness::Refinable(residual) => SnapshotDiscovery::Refinable {
                        calls: residual.into_boxed_slice(),
                    },
                    SnapshotOpenness::Blocked(gap) => SnapshotDiscovery::Incomplete { gap },
                }
            } else {
                SnapshotDiscovery::Incomplete { gap: None }
            };
            let refined = discovery == SnapshotDiscovery::Complete && !input.status().is_complete();
            let complete = discovery == SnapshotDiscovery::Complete;
            if entered_procedure && !refined {
                discovery_status = discovery_status.merge(input.status());
            }
            if first_incomplete_cause.is_none() && !complete {
                first_incomplete_cause = Some(match &discovery {
                    SnapshotDiscovery::Refinable { calls } => {
                        let call = calls
                            .first()
                            .expect("a non-complete refinable snapshot retains a residual call")
                            .clone();
                        ValueFlowIncompleteCause::CallResolution {
                            call,
                            status: input.status(),
                        }
                    }
                    SnapshotDiscovery::Incomplete {
                        gap: Some((gap, capability)),
                    } => ValueFlowIncompleteCause::SemanticGap {
                        gap: gap.clone(),
                        capability: *capability,
                        status: input.status(),
                    },
                    SnapshotDiscovery::Incomplete { gap: None }
                        if !input.status().is_complete() =>
                    {
                        ValueFlowIncompleteCause::Snapshot {
                            procedure: input.value().procedure().clone(),
                            status: input.status(),
                        }
                    }
                    SnapshotDiscovery::Incomplete { gap: None } => {
                        ValueFlowIncompleteCause::SnapshotCoverage {
                            procedure: input.value().procedure().clone(),
                        }
                    }
                    SnapshotDiscovery::Complete => {
                        unreachable!("a complete snapshot discovery cannot be incomplete")
                    }
                });
            }
            snapshot_discoveries.push(discovery);
            discovery_complete &= complete;
            relation_count = relation_count.saturating_add(input.value().relations().len());
            for relation in input.value().relations() {
                carrier_candidates.push(ValueFlowCarrier::from(&relation.source));
                carrier_candidates.push(ValueFlowCarrier::from(&relation.target));
            }
            // Curated call models can transfer through a temporary receiver or
            // result before either value participates in a local relation, and
            // authored external summaries can transfer a receiver or argument
            // into a call result even when the language adapter emitted no
            // ordinary value-flow relation for that result. Dispatch refinement
            // happens after this plan is constructed, so the declared target
            // shape cannot decide which calls will acquire a model. Keep every
            // structured call port in the demand set so a later model install
            // can bind the exact value instead of treating the transfer as
            // carrierless. The carrier index remains bounded by max_carriers.
            let procedure = input.value().procedure();
            for call in procedure.semantics().call_sites() {
                std::iter::once(call.callee)
                    .chain(call.receiver)
                    .chain(call.arguments.iter().map(|argument| argument.value))
                    .chain(call.normal_result_values())
                    .chain(call.thrown)
                    .filter_map(|value| procedure.value_handle(value))
                    .map(ValueFlowCarrier::for_value)
                    .for_each(|carrier| carrier_candidates.push(carrier));
            }
        }
        for input in &bindings {
            validate_mount(input.value().call().procedure(), mount)?;
            validate_mount(input.value().callee(), mount)?;
            for entering in input.value().context().calls() {
                validate_mount(entering.procedure(), mount)?;
            }
            discovery_status = discovery_status.merge(input.status());
            if first_incomplete_cause.is_none() {
                if !input.status().is_complete() {
                    first_incomplete_cause = Some(ValueFlowIncompleteCause::CallBinding {
                        call: input.value().call().clone(),
                        callee: input.value().callee().clone(),
                        status: input.status(),
                    });
                } else if input.value().coverage() != CandidateCoverage::Exhaustive
                    || input.value().context().was_truncated()
                {
                    first_incomplete_cause = Some(ValueFlowIncompleteCause::CallBindingCoverage {
                        call: input.value().call().clone(),
                        callee: input.value().callee().clone(),
                    });
                }
            }
            let complete = input.status().is_complete()
                && input.value().coverage() == CandidateCoverage::Exhaustive
                && !input.value().context().was_truncated();
            non_snapshot_discovery_complete &= complete;
            if !complete
                && !incomplete_binding_calls
                    .iter()
                    .any(|call| compare_calls(call, input.value().call()) == Ordering::Equal)
            {
                incomplete_binding_calls.push(input.value().call().clone());
            }
            discovery_complete &= complete;
            structural_discovery_complete &= !input.value().context().was_truncated();
            for binding in input.value().bindings() {
                relation_count = relation_count.saturating_add(call_binding_rule_count(binding));
                append_binding_carriers(binding, &mut carrier_candidates)?;
            }
        }
        // Whole-value call rules above are sufficient for scalar values, but a
        // formal slice/array view also names element locations. Project those
        // locations only when both sides of the exact binding have structured
        // snapshot evidence. Open bindings remain represented by their normal
        // conservative value rules and never acquire an optimistic location
        // transfer here.
        for input in &bindings {
            if !append_call_location_rules(
                input.value(),
                &snapshots,
                limits.max_carriers,
                limits.max_access_path,
                &mut caller_origins,
                &mut pending_call_location_rules,
            )? {
                discovery_complete = false;
                non_snapshot_discovery_complete = false;
                discovery_status = discovery_status.merge(SemanticInputStatus::Unknown);
                if !incomplete_binding_calls
                    .iter()
                    .any(|call| compare_calls(call, input.value().call()) == Ordering::Equal)
                {
                    incomplete_binding_calls.push(input.value().call().clone());
                }
                first_incomplete_cause.get_or_insert_with(|| {
                    ValueFlowIncompleteCause::CallBindingCoverage {
                        call: input.value().call().clone(),
                        callee: input.value().callee().clone(),
                    }
                });
            }
        }
        drop(caller_origins);
        relation_count = relation_count.saturating_add(pending_call_location_rules.len());
        for rule in &pending_call_location_rules {
            carrier_candidates.push(rule.source.clone());
            carrier_candidates.push(rule.target.clone());
        }
        // An endpoint observed in a procedure the solve cannot enter was not
        // analyzed: a sink there can never report, and calling the region clean
        // would claim a verdict for a site the solve never visited (#2640).
        let mut source_events = sources.iter().collect::<Vec<_>>();
        source_events.sort_unstable_by(|left, right| left.key().cmp(right.key()));
        for source in source_events {
            validate_event(source.point(), source.carrier(), mount)?;
            let evidence_complete = matches!(source.proof(), ProofStatus::Proven)
                && matches!(source.completeness(), EvidenceCompleteness::Complete);
            let entered_procedure = entered.contains(&source.point().procedure().durable_key());
            let excluded_procedure = excluded.contains(&source.point().procedure().durable_key());
            if first_incomplete_cause.is_none() {
                if !evidence_complete {
                    first_incomplete_cause = Some(ValueFlowIncompleteCause::SourceEvidence {
                        point: source.point().clone(),
                    });
                } else if !entered_procedure && !excluded_procedure {
                    first_incomplete_cause = Some(ValueFlowIncompleteCause::UnenteredProcedure {
                        procedure: source.point().procedure().clone(),
                    });
                }
            }
            let complete = evidence_complete && (entered_procedure || excluded_procedure);
            non_snapshot_discovery_complete &= complete;
            endpoint_discovery_complete &= complete;
            discovery_complete &= complete;
            structural_discovery_complete &= evidence_complete;
            carrier_candidates.push(source.carrier().clone());
        }
        for sink in &sinks {
            validate_event(sink.point(), sink.carrier(), mount)?;
            let evidence_complete = matches!(sink.proof(), ProofStatus::Proven)
                && matches!(sink.completeness(), EvidenceCompleteness::Complete);
            let entered_procedure = entered.contains(&sink.point().procedure().durable_key());
            let excluded_procedure = excluded.contains(&sink.point().procedure().durable_key());
            if first_incomplete_cause.is_none() {
                if !evidence_complete {
                    first_incomplete_cause = Some(ValueFlowIncompleteCause::SinkEvidence {
                        point: sink.point().clone(),
                    });
                } else if !entered_procedure && !excluded_procedure {
                    first_incomplete_cause = Some(ValueFlowIncompleteCause::UnenteredProcedure {
                        procedure: sink.point().procedure().clone(),
                    });
                }
            }
            let complete = evidence_complete && (entered_procedure || excluded_procedure);
            non_snapshot_discovery_complete &= complete;
            endpoint_discovery_complete &= complete;
            discovery_complete &= complete;
            structural_discovery_complete &= evidence_complete;
            carrier_candidates.push(sink.carrier().clone());
        }
        for kill in &edge_kills {
            validate_event(&kill.point, &kill.carrier, mount)?;
            let edge_exists = kill
                .point
                .procedure()
                .semantics()
                .successor_edges(kill.point.id())
                .any(|(_, edge)| edge.target_point == kill.target && edge.kind == kill.kind);
            if !edge_exists {
                return Err(ValueFlowPlanError::InvalidEdgeKill);
            }
            carrier_candidates.push(kill.carrier.clone());
        }
        if relation_count > limits.max_relations {
            return Err(ValueFlowPlanError::LimitExceeded);
        }
        debug_assert_eq!(
            first_incomplete_cause.is_some(),
            !discovery_complete,
            "the retained cause and discovery completeness must agree"
        );

        let CarrierIndex {
            carriers,
            carrier_keys,
            carrier_ids,
        } = assign_carrier_ids(carrier_candidates, limits.max_carriers)?;

        let mut local_rules = Vec::new();
        for input in snapshots {
            let (snapshot, _) = input.into_parts();
            for relation in snapshot.relations() {
                local_rules.push(LocalFlowRule {
                    point: relation.point().clone(),
                    event_index: relation.event_index(),
                    kind: relation.kind,
                    transfer: relation.transfer,
                    source: lookup_carrier(&carrier_ids, &relation.source)?,
                    target: lookup_carrier(&carrier_ids, &relation.target)?,
                    proof: relation.proof.clone(),
                    completeness: relation.completeness.clone(),
                    policy_local: false,
                    strong_update: relation.strong_update,
                    direct_cell_overwrite: relation.direct_cell_overwrite,
                });
            }
        }
        local_rules.sort_by(compare_local_rules);
        local_rules.dedup();

        let mut call_rules = Vec::new();
        for input in &bindings {
            append_call_rules(input.value(), &carrier_ids, &mut call_rules)?;
        }
        for rule in pending_call_location_rules {
            call_rules.push(CallFlowRule {
                context: rule.context,
                transfer: None,
                call: rule.call,
                callee: rule.callee,
                kind: rule.kind,
                source: *carrier_ids
                    .get(&rule.source)
                    .ok_or(ValueFlowPlanError::MissingCarrier)?,
                target: *carrier_ids
                    .get(&rule.target)
                    .ok_or(ValueFlowPlanError::MissingCarrier)?,
                proof: rule.proof,
                completeness: rule.completeness,
            });
        }
        call_rules.sort_by(compare_call_rules);
        merge_duplicate_call_rules(&mut call_rules);

        let carrier_components = build_carrier_components(carriers.len(), &local_rules);
        let fallback_locations =
            build_fallback_location_index(&carriers, &carrier_ids, &carrier_components);
        let fallback_profiles = build_call_fallback_profiles(
            std::iter::once(&root)
                .chain(snapshot_procedures.iter())
                .collect::<Vec<_>>(),
            &carrier_ids,
            &carrier_components,
        );

        let edge_kill_index = build_edge_kill_index(&edge_kills, &carrier_ids)?;
        let bound_sources = sources
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                Ok(BoundValueFlowSource {
                    id: ValueFlowSourceId::try_from_index(index)
                        .map_err(|_| ValueFlowPlanError::SourceIdOverflow)?,
                    carrier: *carrier_ids
                        .get(spec.carrier())
                        .ok_or(ValueFlowPlanError::MissingCarrier)?,
                    activation_triggers: spec.activation_triggers(),
                    spec,
                })
            })
            .collect::<Result<Vec<_>, ValueFlowPlanError>>()?;
        let bound_sinks = sinks
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                Ok(BoundValueFlowSink {
                    id: ValueFlowSinkId::try_from_index(index)
                        .map_err(|_| ValueFlowPlanError::SinkIdOverflow)?,
                    carrier: *carrier_ids
                        .get(spec.carrier())
                        .ok_or(ValueFlowPlanError::MissingCarrier)?,
                    spec,
                })
            })
            .collect::<Result<Vec<_>, ValueFlowPlanError>>()?;

        let local_rule_point_index = build_local_rule_point_index(&local_rules);
        let call_rule_reverse_index = build_call_rule_reverse_index(&call_rules);
        let source_index = build_observation_index(&bound_sources, |source| ObservationKey {
            point: source.spec.point().clone(),
            phase: source.spec.phase(),
        });
        let sink_index = build_observation_index(&bound_sinks, |sink| ObservationKey {
            point: sink.spec.point().clone(),
            phase: sink.spec.phase(),
        });
        let infeasible_points =
            constant_infeasible_points(std::iter::once(&root).chain(snapshot_procedures.iter()));
        Ok(Self {
            root,
            unmodeled_call_behavior,
            external_summaries: ExternalSemanticSummarySet::default(),
            curated_call_models: Box::default(),
            carriers: carriers.into_boxed_slice(),
            carrier_keys: carrier_keys.into_boxed_slice(),
            carrier_ids,
            local_rules: local_rules.into_boxed_slice(),
            local_rule_point_index,
            call_rules: call_rules.into_boxed_slice(),
            contextual_bindings,
            call_rule_reverse_index,
            fallback_profiles: fallback_profiles.into_boxed_slice(),
            fallback_locations,
            summary_location_bindings: unavailable_receivers.into_boxed_slice(),
            source_key_order: source_key_order(&bound_sources),
            sources: bound_sources.into_boxed_slice(),
            source_index,
            sinks: bound_sinks.into_boxed_slice(),
            sink_index,
            source_lists: source_lists.into_lists(),
            edge_kills: edge_kills.into_boxed_slice(),
            edge_kill_index,
            infeasible_points,
            snapshot_procedures: snapshot_procedures.into_boxed_slice(),
            binding_pairs: binding_pairs.into_boxed_slice(),
            resolved_external_calls: resolved_external_calls.into_boxed_slice(),
            discovery_status,
            first_incomplete_cause,
            snapshot_discoveries: snapshot_discoveries.into_boxed_slice(),
            non_snapshot_discovery_complete,
            endpoint_discovery_complete,
            incomplete_binding_calls: incomplete_binding_calls.into_boxed_slice(),
            ambiguous_dispatch,
            discovery_complete,
            structural_discovery_complete,
            owner: Arc::new(()),
        })
    }

    pub fn root(&self) -> &ProcedureHandle {
        &self.root
    }

    /// Visit every concrete semantic artifact allocation retained by handles
    /// in this immutable plan. Duplicate allocations are intentional: bounded
    /// host registries deduplicate them while accounting and validating.
    pub fn for_each_retained_artifact(&self, mut visit: impl FnMut(&Arc<SemanticArtifact>)) {
        visit(self.root.artifact());
        for procedure in &self.snapshot_procedures {
            visit(procedure.artifact());
        }
        for (call, callee) in &self.binding_pairs {
            visit(call.procedure().artifact());
            visit(callee.artifact());
        }
        for call in &self.resolved_external_calls {
            visit(call.procedure().artifact());
        }
        for carrier in &self.carriers {
            carrier.for_each_retained_artifact(&mut visit);
        }
        for rule in &self.call_rules {
            for call in rule.context.calls() {
                visit(call.procedure().artifact());
            }
        }
        for rule in &self.local_rules {
            visit(rule.point.procedure().artifact());
        }
        for rule in &self.call_rules {
            visit(rule.call.procedure().artifact());
            visit(rule.callee.artifact());
        }
        for profile in &self.fallback_profiles {
            visit(profile.call.procedure().artifact());
        }
        for model in &self.curated_call_models {
            visit(model.call.procedure().artifact());
        }
        for binding in &self.summary_location_bindings {
            visit(binding.call.procedure().artifact());
        }
        for source in &self.sources {
            visit(source.spec.point().procedure().artifact());
        }
        for sink in &self.sinks {
            visit(sink.spec.point().procedure().artifact());
        }
        for kill in &self.edge_kills {
            visit(kill.point.procedure().artifact());
            kill.carrier.for_each_retained_artifact(&mut visit);
        }
        if let Some(cause) = &self.first_incomplete_cause {
            visit(cause.procedure().artifact());
            if let ValueFlowIncompleteCause::CallResolution { call, .. }
            | ValueFlowIncompleteCause::CallBinding { call, .. }
            | ValueFlowIncompleteCause::CallBindingCoverage { call, .. } = cause
            {
                visit(call.procedure().artifact());
            }
        }
    }

    /// Visit every semantic artifact identity retained by this plan.
    pub fn for_each_retained_artifact_key(&self, mut visit: impl FnMut(&SemanticArtifactKey)) {
        self.for_each_retained_artifact(|artifact| visit(artifact.key()));
    }

    /// Conservative retained size of plan-owned metadata, excluding semantic
    /// artifact allocations which host registries account separately.
    pub fn retained_bytes(&self) -> usize {
        let carrier_key_bytes = self
            .carrier_keys
            .iter()
            .map(ValueFlowCarrierKey::retained_bytes)
            .fold(0usize, usize::saturating_add);
        let local_rule_heap = self.local_rules.iter().fold(0usize, |total, rule| {
            total
                .saturating_add(rule.proof.retained_heap_bytes())
                .saturating_add(rule.completeness.retained_heap_bytes())
        });
        let call_rule_heap = self.call_rules.iter().fold(0usize, |total, rule| {
            total
                .saturating_add(size_of_val(rule.context.calls()))
                .saturating_add(rule.proof.retained_heap_bytes())
                .saturating_add(rule.completeness.retained_heap_bytes())
        });
        let source_heap = self.sources.iter().fold(0usize, |total, source| {
            total
                .saturating_add(source.spec.key().retained_bytes())
                .saturating_add(size_of_val(source.spec.dispatch_obligations()))
                .saturating_add(self.carrier_keys[source.carrier.index()].retained_bytes())
                .saturating_add(source.spec.proof().retained_heap_bytes())
                .saturating_add(source.spec.completeness().retained_heap_bytes())
        });
        let sink_heap = self.sinks.iter().fold(0usize, |total, sink| {
            total
                .saturating_add(sink.spec.key().retained_bytes())
                .saturating_add(size_of_val(sink.spec.dispatch_obligations()))
                .saturating_add(self.carrier_keys[sink.carrier.index()].retained_bytes())
                .saturating_add(sink.spec.proof().retained_heap_bytes())
                .saturating_add(sink.spec.completeness().retained_heap_bytes())
        });
        let edge_kill_heap = self.edge_kills.iter().fold(0usize, |total, kill| {
            total.saturating_add(
                kill.carrier
                    .stable_key()
                    .map_or(0, |key| key.retained_bytes()),
            )
        });

        std::mem::size_of::<Self>()
            .saturating_add(self.external_summaries.retained_heap_bytes())
            .saturating_add(size_of_val(self.curated_call_models.as_ref()))
            .saturating_add(
                self.curated_call_models
                    .iter()
                    .map(|model| model.model.retained_heap_bytes())
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(size_of_val(self.carriers.as_ref()))
            // Locations own an access path in addition to the carrier enum.
            // Its stable key is a conservative structural estimate of that path.
            .saturating_add(carrier_key_bytes)
            .saturating_add(size_of_val(self.carrier_keys.as_ref()))
            .saturating_add(carrier_key_bytes)
            .saturating_add(
                self.carrier_ids
                    .capacity()
                    .saturating_mul(
                        std::mem::size_of::<(ValueFlowCarrier, ValueFlowCarrierId)>()
                            .saturating_add(1),
                    )
                    // The map clones every carrier; charge the structural keys
                    // again to conservatively cover cloned locations.
                    .saturating_add(carrier_key_bytes),
            )
            .saturating_add(size_of_val(self.local_rules.as_ref()))
            .saturating_add(local_rule_heap)
            .saturating_add(self.local_rule_point_index.retained_heap_bytes())
            .saturating_add(size_of_val(self.call_rules.as_ref()))
            .saturating_add(call_rule_heap)
            .saturating_add(self.call_rule_reverse_index.retained_heap_bytes())
            .saturating_add(size_of_val(self.fallback_profiles.as_ref()))
            .saturating_add(
                self.fallback_profiles
                    .iter()
                    .map(|profile| {
                        size_of_val(profile.inputs.as_ref())
                            .saturating_add(size_of_val(profile.reachable_components.as_ref()))
                    })
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(self.fallback_locations.retained_heap_bytes())
            .saturating_add(size_of_val(self.summary_location_bindings.as_ref()))
            .saturating_add(size_of_val(self.sources.as_ref()))
            .saturating_add(size_of_val(self.source_key_order.as_ref()))
            .saturating_add(self.source_index.retained_heap_bytes())
            .saturating_add(source_heap)
            .saturating_add(size_of_val(self.sinks.as_ref()))
            .saturating_add(self.sink_index.retained_heap_bytes())
            .saturating_add(sink_heap)
            .saturating_add(size_of_val(self.source_lists.as_ref()))
            .saturating_add(
                self.source_lists
                    .iter()
                    .map(|list| size_of_val(list.as_ref()))
                    .sum::<usize>(),
            )
            .saturating_add(size_of_val(self.edge_kills.as_ref()))
            .saturating_add(edge_kill_heap)
            .saturating_add(self.edge_kill_index.retained_heap_bytes())
            .saturating_add(size_of_val(self.snapshot_procedures.as_ref()))
            .saturating_add(size_of_val(self.binding_pairs.as_ref()))
            .saturating_add(size_of_val(self.resolved_external_calls.as_ref()))
            // Account for the plan-ownership Arc allocation and reference counts.
            .saturating_add(
                std::mem::size_of::<usize>()
                    .saturating_mul(2)
                    .saturating_add(1),
            )
    }

    pub const fn unmodeled_call_behavior(&self) -> UnmodeledCallBehavior {
        self.unmodeled_call_behavior
    }

    /// Install complete external semantic summaries used before the configured
    /// fallback profile. The set owns its content-addressed validity identity,
    /// so changing a model partitions value-flow and downstream taint caches.
    pub fn with_external_summaries(
        mut self,
        summaries: ExternalSemanticSummarySet,
    ) -> Result<Self, ValueFlowPlanError> {
        if summaries.compatibility().is_some_and(|compatibility| {
            compatibility.unmodeled_call_behavior() != self.unmodeled_call_behavior
                || compatibility.dependencies() != self.root.artifact().key().dependencies()
        }) {
            return Err(ValueFlowPlanError::IncompatibleExternalSummary);
        }
        self.external_summaries = summaries;
        Ok(self)
    }

    pub const fn external_summaries(&self) -> &ExternalSemanticSummarySet {
        &self.external_summaries
    }

    /// Install selector-bound curated models, merging with any models already
    /// installed (external-model and persistence-store declarations each
    /// contribute their own). Exactly one model may own a call site -- two
    /// declarations claiming one call, within or across categories, are a
    /// duplicate -- and exact target summaries are still selected first
    /// during transfer.
    pub fn with_curated_call_models(
        mut self,
        mut models: Vec<ValueFlowCuratedCallModel>,
    ) -> Result<Self, ValueFlowPlanError> {
        let mount = self.root.artifact().key().mount();
        for model in &models {
            validate_mount(model.call.procedure(), mount)?;
            if model
                .call
                .procedure()
                .semantics()
                .call_site(model.call.id())
                .is_none()
            {
                return Err(ValueFlowPlanError::StaleCallModel);
            }
        }
        models.extend(self.curated_call_models.iter().cloned());
        models.sort_by(|left, right| compare_calls(&left.call, &right.call));
        if models.windows(2).any(|pair| pair[0].call == pair[1].call) {
            return Err(ValueFlowPlanError::DuplicateCallModel);
        }
        self.curated_call_models = models.into_boxed_slice();
        Ok(self)
    }

    /// Bind the stable heap/capture ports referenced by exact or curated
    /// models. The carriers must already belong to the demand-driven plan.
    pub fn with_summary_location_bindings(
        mut self,
        mut bindings: Vec<ValueFlowSummaryLocationBinding>,
    ) -> Result<Self, ValueFlowPlanError> {
        if bindings.len() > MAX_SUMMARY_BOUNDARY_BINDINGS {
            return Err(ValueFlowPlanError::LimitExceeded);
        }
        let mount = self.root.artifact().key().mount();
        for binding in &bindings {
            validate_mount(binding.call.procedure(), mount)?;
            if !matches!(binding.port, SummaryPort::Capture(_) | SummaryPort::Heap(_)) {
                return Err(ValueFlowPlanError::InvalidSummaryLocationPort);
            }
        }
        bindings.sort_by(|left, right| {
            compare_calls(&left.call, &right.call).then_with(|| left.port.cmp(&right.port))
        });
        if bindings
            .windows(2)
            .any(|pair| pair[0].call == pair[1].call && pair[0].port == pair[1].port)
        {
            return Err(ValueFlowPlanError::DuplicateSummaryLocationBinding);
        }
        // Preserve internal unavailable-receiver markers while replacing the
        // caller-supplied heap/capture bindings, as this setter always did.
        let mut bound = self
            .summary_location_bindings
            .iter()
            .filter(|binding| binding.port == SummaryPort::Receiver)
            .cloned()
            .collect::<Vec<_>>();
        for binding in bindings {
            bound.push(BoundSummaryLocationBinding {
                call: binding.call,
                port: binding.port,
                carrier: Some(
                    self.carrier_id(&binding.carrier)
                        .ok_or(ValueFlowPlanError::MissingCarrier)?,
                ),
            });
        }
        if bound.len() > MAX_SUMMARY_BOUNDARY_BINDINGS {
            return Err(ValueFlowPlanError::LimitExceeded);
        }
        bound.sort_by(|left, right| {
            compare_calls(&left.call, &right.call).then_with(|| left.port.cmp(&right.port))
        });
        if bound
            .windows(2)
            .any(|pair| pair[0].call == pair[1].call && pair[0].port == pair[1].port)
        {
            return Err(ValueFlowPlanError::DuplicateSummaryLocationBinding);
        }
        self.summary_location_bindings = bound.into_boxed_slice();
        Ok(self)
    }

    /// Keep every returned closure's captured environment connected across the
    /// call that returned it.
    ///
    /// A producing call that returned a callable handed the caller the exact
    /// closure whose environment slots the same procedure bound at the
    /// closure's creation. Those slots therefore stay live across the
    /// producing call's normal return, and this method adds one identity rule
    /// per slot on that return edge: the closure's capture port is re-emitted
    /// when the producing call returns, so a later invocation of the returned
    /// value observes the same closed-over storage it would observe if the
    /// closure had been created in the caller. The rule carries proven
    /// complete evidence, because it does not claim new reachability -- it
    /// keeps the closure's own environment stable across a boundary the
    /// callable itself crossed.
    ///
    /// A row whose closure's capture port the plan did not retain contributes
    /// no rule: the plan holds no carrier for that slot, so there is no fact to
    /// transport across the return edge.
    pub fn with_returned_callable_captures(
        mut self,
        mut rows: Vec<ValueFlowReturnedCallable>,
    ) -> Result<Self, ValueFlowPlanError> {
        let mount = self.root.artifact().key().mount();
        for row in &rows {
            validate_mount(row.producer.procedure(), mount)?;
            if row
                .producer
                .procedure()
                .semantics()
                .call_site(row.producer.id())
                .is_none()
            {
                return Err(ValueFlowPlanError::StaleReturnedCallable);
            }
        }
        rows.sort_by(|left, right| {
            compare_calls(&left.producer, &right.producer)
                .then_with(|| compare_procedures(&left.producer_callee, &right.producer_callee))
                .then_with(|| compare_procedures(&left.closure, &right.closure))
                .then_with(|| left.captures.cmp(&right.captures))
        });
        rows.dedup();
        let mut bound = Vec::new();
        for row in rows {
            for slot in row.captures.iter() {
                let port = ProcedurePortHandle::capture(row.closure.clone(), *slot)
                    .expect("a returned closure names its own capture slots");
                let carrier = ValueFlowCarrier::Port(port);
                let Some(id) = self.carrier_id_for_key(&carrier.stable_key()?) else {
                    continue;
                };
                bound.push((row.producer.clone(), row.producer_callee.clone(), id));
            }
        }
        if self.call_rules.len().saturating_add(bound.len()) > MAX_VALUE_FLOW_RELATIONS {
            return Err(ValueFlowPlanError::LimitExceeded);
        }
        let mut rules = self.call_rules.into_vec();
        rules.extend(
            bound
                .into_iter()
                .map(|(call, callee, carrier)| CallFlowRule {
                    context: OracleCallContext::empty(),
                    call,
                    callee,
                    kind: CallFlowRuleKind::NormalReturn,
                    transfer: None,
                    source: carrier,
                    target: carrier,
                    proof: ProofStatus::Proven,
                    completeness: EvidenceCompleteness::Complete,
                }),
        );
        rules.sort_by(compare_call_rules);
        merge_duplicate_call_rules(&mut rules);
        self.call_rule_reverse_index = build_call_rule_reverse_index(&rules);
        self.call_rules = rules.into_boxed_slice();
        Ok(self)
    }

    /// Inject policy-authored point-local relations between carriers that the
    /// analyzer has already mounted in this plan.
    ///
    /// The exact relation is retained in propagation and reusable-summary
    /// identity. Evidence quality belongs to the rule, so a partial selector
    /// can carry a may-flow but cannot make that path or a clean result
    /// conclusive.
    pub fn with_local_rules(
        mut self,
        rules: Vec<ValueFlowLocalRuleSpec>,
    ) -> Result<Self, ValueFlowPlanError> {
        if self.local_rules.len().saturating_add(rules.len()) > MAX_VALUE_FLOW_RELATIONS {
            return Err(ValueFlowPlanError::LimitExceeded);
        }
        let mount = self.root.artifact().key().mount();
        let mut bound = Vec::with_capacity(rules.len());
        for rule in rules {
            validate_event(&rule.point, &rule.source, mount)?;
            validate_event(&rule.point, &rule.target, mount)?;
            bound.push(LocalFlowRule {
                point: rule.point,
                event_index: u32::MAX,
                kind: ValueFlowRelationKind::LanguageDefined,
                transfer: None,
                source: self
                    .carrier_id(&rule.source)
                    .ok_or(ValueFlowPlanError::MissingCarrier)?,
                target: self
                    .carrier_id(&rule.target)
                    .ok_or(ValueFlowPlanError::MissingCarrier)?,
                proof: rule.proof,
                completeness: rule.completeness,
                policy_local: true,
                strong_update: false,
                direct_cell_overwrite: false,
            });
        }
        bound.sort_by(compare_local_rules);
        if bound.windows(2).any(|pair| {
            pair[0].point == pair[1].point
                && pair[0].source == pair[1].source
                && pair[0].target == pair[1].target
        }) {
            return Err(ValueFlowPlanError::DuplicateLocalRule);
        }
        for rule in &bound {
            let evidence_complete = matches!(rule.proof, ProofStatus::Proven)
                && matches!(rule.completeness, EvidenceCompleteness::Complete);
            if !evidence_complete && self.first_incomplete_cause.is_none() {
                self.first_incomplete_cause = Some(ValueFlowIncompleteCause::LocalRuleEvidence {
                    point: rule.point.clone(),
                });
            }
            self.non_snapshot_discovery_complete &= evidence_complete;
            self.discovery_complete &= evidence_complete;
            self.structural_discovery_complete &= evidence_complete;
        }
        let mut local_rules = self.local_rules.into_vec();
        local_rules.extend(bound);
        local_rules.sort_by(compare_local_rules);
        let carrier_components = build_carrier_components(self.carriers.len(), &local_rules);
        self.fallback_locations =
            build_fallback_location_index(&self.carriers, &self.carrier_ids, &carrier_components);
        self.fallback_profiles = build_call_fallback_profiles(
            std::iter::once(&self.root)
                .chain(self.snapshot_procedures.iter())
                .collect::<Vec<_>>(),
            &self.carrier_ids,
            &carrier_components,
        )
        .into_boxed_slice();
        self.local_rule_point_index = build_local_rule_point_index(&local_rules);
        self.local_rules = local_rules.into_boxed_slice();
        Ok(self)
    }

    pub fn carriers(&self) -> &[ValueFlowCarrier] {
        &self.carriers
    }

    pub fn carrier(&self, id: ValueFlowCarrierId) -> Option<&ValueFlowCarrier> {
        self.carriers.get(id.index())
    }

    pub fn carrier_key(&self, id: ValueFlowCarrierId) -> Option<&ValueFlowCarrierKey> {
        self.carrier_keys.get(id.index())
    }

    /// Stable keys in the same dense-ID order as [`Self::carriers`].
    pub(crate) fn carrier_keys(&self) -> &[ValueFlowCarrierKey] {
        &self.carrier_keys
    }

    /// Stable carriers that an interprocedural call can seed at this callee's
    /// summary entry. These are usually formal ports, but an exact structured
    /// call binding can also seed a callee location projected from the caller.
    /// Root summaries begin with Zero and need no carrier row.
    pub(crate) fn summary_entry_carriers_by_procedure(
        &self,
    ) -> HashMap<ProcedureHandle, Box<[ValueFlowCarrierKey]>> {
        let mut by_procedure = HashMap::<ProcedureHandle, Vec<ValueFlowCarrierKey>>::default();
        for rule in self
            .call_rules
            .iter()
            .filter(|rule| rule.kind == CallFlowRuleKind::Call)
        {
            by_procedure
                .entry(rule.callee.clone())
                .or_default()
                .push(self.carrier_keys[rule.target.index()].clone());
        }
        by_procedure
            .into_iter()
            .map(|(procedure, mut carriers)| {
                carriers.sort_unstable();
                carriers.dedup();
                (procedure, carriers.into_boxed_slice())
            })
            .collect()
    }

    pub(crate) fn carrier_id_for_key(
        &self,
        key: &ValueFlowCarrierKey,
    ) -> Option<ValueFlowCarrierId> {
        self.carrier_keys
            .binary_search(key)
            .ok()
            .and_then(|index| ValueFlowCarrierId::try_from_index(index).ok())
    }

    pub(crate) fn sink_id_for_key(
        &self,
        key: &super::ValueFlowEventKey,
    ) -> Option<ValueFlowSinkId> {
        event_key_index(&self.sinks, key, |sink| sink.spec.key()).map(|index| self.sinks[index].id)
    }

    pub(crate) fn source_id_for_key(
        &self,
        key: &super::ValueFlowEventKey,
    ) -> Option<ValueFlowSourceId> {
        self.source_key_order
            .binary_search_by(|id| self.sources[id.index()].spec.key().cmp(key))
            .ok()
            .map(|index| self.source_key_order[index])
    }

    /// Hash only the transfer semantics that determine propagation. Source and
    /// sink observations are deliberately excluded so compatible clients can
    /// union their demand sets and share one fixed-point solve.
    pub fn propagation_semantics_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Parameter and receiver transfers can replace a mutable local carrier
        // and therefore change the fixed-point result. Rotate retained summary
        // identities when that propagation relation changes.
        state.write(b"bifrost-value-flow-propagation-semantics-v10");
        self.root.hash(state);
        self.unmodeled_call_behavior.hash(state);
        self.external_summaries.fingerprint().hash(state);
        self.curated_call_models.len().hash(state);
        for model in &self.curated_call_models {
            model.call.hash(state);
            model.model.fingerprint().hash(state);
        }
        for rule in &self.local_rules {
            rule.point.hash(state);
            rule.event_index.hash(state);
            rule.kind.hash(state);
            rule.transfer.hash(state);
            self.carrier_keys[rule.source.index()].hash(state);
            self.carrier_keys[rule.target.index()].hash(state);
            rule.proof.hash(state);
            rule.completeness.hash(state);
            if rule.policy_local {
                state.write(b"policy-local");
            }
            rule.strong_update.hash(state);
            rule.direct_cell_overwrite.hash(state);
        }
        self.contextual_bindings.hash(state);
        for rule in &self.call_rules {
            rule.context.hash(state);
            rule.call.hash(state);
            rule.callee.hash(state);
            rule.kind.hash(state);
            rule.transfer.hash(state);
            self.carrier_keys[rule.source.index()].hash(state);
            self.carrier_keys[rule.target.index()].hash(state);
            rule.proof.hash(state);
            rule.completeness.hash(state);
        }
        for binding in &self.summary_location_bindings {
            binding.call.hash(state);
            binding.port.hash(state);
            binding
                .carrier
                .map(|carrier| &self.carrier_keys[carrier.index()])
                .hash(state);
        }
        for kill in &self.edge_kills {
            kill.point.hash(state);
            kill.target.hash(state);
            kill.kind.hash(state);
            self.carrier_ids
                .get(&kill.carrier)
                .map(|id| &self.carrier_keys[id.index()])
                .expect("a validated edge-kill carrier is bound")
                .hash(state);
            self.source_list_keys(kill.sources).hash(state);
        }
        let conditional_sources = self
            .sources
            .iter()
            .filter(|source| source.spec.activation_triggers().is_some())
            .collect::<Vec<_>>();
        conditional_sources.len().hash(state);
        let mut conditional_sources = conditional_sources;
        conditional_sources.sort_unstable_by(|left, right| left.spec.key().cmp(right.spec.key()));
        for source in conditional_sources {
            source.spec.key().hash(state);
            source.spec.point().hash(state);
            source.spec.phase().hash(state);
            self.carrier_keys[source.carrier.index()].hash(state);
            source.spec.proof().hash(state);
            source.spec.completeness().hash(state);
            source
                .spec
                .activation_triggers()
                .map(|list| self.source_list_keys(list))
                .hash(state);
        }
        self.snapshot_procedures.hash(state);
        self.binding_pairs.hash(state);
        self.resolved_external_calls.hash(state);
        self.discovery_status.hash(state);
        self.discovery_complete.hash(state);
        self.structural_discovery_complete.hash(state);
    }

    pub(crate) fn has_same_propagation_semantics(&self, other: &Self) -> bool {
        same_propagation_configuration(self, other)
            && same_local_rules(self, other)
            && same_call_rules(self, other)
            && same_summary_location_bindings(self, other)
            && same_conditional_source_specs(self, other)
            && self.resolved_external_calls == other.resolved_external_calls
    }

    /// Compare immutable inputs through stable source keys. A caller may keep
    /// the old plan and its matching facts on equality; it must never interpret
    /// an old source ID through the rebuilt plan's coordinates.
    pub(crate) fn has_same_inputs(&self, other: &Self) -> bool {
        same_plan_structure(self, other) && same_keyed_source_specs(self, other)
    }

    /// Rebind source observations and source-selective edge kills after a
    /// refinement pass. Retained snapshots, call bindings, sinks, models, and
    /// call behavior remain the same; only demand observations and their
    /// source IDs are replaced. Reassigning every carrier through the stable
    /// key index keeps IDs valid when refinement introduces a new carrier.
    pub(crate) fn with_replaced_sources_and_edge_kills(
        &self,
        sources: ValueFlowSources,
        mut edge_kills: Vec<ValueFlowEdgeKillSpec>,
        uncertain_field_stores: &HashSet<(ProgramPointHandle, u32)>,
        descriptor_field_stores: &HashSet<(ProgramPointHandle, u32)>,
    ) -> Result<Self, ValueFlowPlanError> {
        let ValueFlowSources {
            specs: sources,
            lists: source_lists,
        } = sources;
        if sources.len() > MAX_VALUE_FLOW_SOURCES {
            return Err(ValueFlowPlanError::LimitExceeded);
        }
        if duplicate_source_keys(&sources) {
            return Err(ValueFlowPlanError::DuplicateEventKey);
        }

        let mount = self.root.artifact().key().mount();
        let mut source_events = sources.iter().collect::<Vec<_>>();
        source_events.sort_unstable_by(|left, right| left.key().cmp(right.key()));
        for source in source_events {
            validate_event(source.point(), source.carrier(), mount)?;
        }

        validate_source_lists(&sources, &edge_kills, &source_lists)?;
        edge_kills.sort_by(|left, right| compare_edge_kills(left, right, &sources, &source_lists));
        edge_kills.dedup();
        for kill in &edge_kills {
            validate_event(&kill.point, &kill.carrier, mount)?;
            let edge_exists = kill
                .point
                .procedure()
                .semantics()
                .successor_edges(kill.point.id())
                .any(|(_, edge)| edge.target_point == kill.target && edge.kind == kill.kind);
            if !edge_exists {
                return Err(ValueFlowPlanError::InvalidEdgeKill);
            }
        }

        let mut carrier_candidates = self.carriers.to_vec();
        carrier_candidates.extend(sources.iter().map(|source| source.carrier().clone()));
        carrier_candidates.extend(edge_kills.iter().map(|kill| kill.carrier.clone()));
        let CarrierIndex {
            carriers,
            carrier_keys,
            carrier_ids,
        } = assign_carrier_ids(carrier_candidates, MAX_VALUE_FLOW_CARRIERS)?;
        let remap = |id: ValueFlowCarrierId| {
            carrier_ids
                .get(&self.carriers[id.index()])
                .copied()
                .ok_or(ValueFlowPlanError::MissingCarrier)
        };

        let mut local_rules = self.local_rules.to_vec();
        local_rules.retain(|rule| {
            rule.kind != ValueFlowRelationKind::MemoryStore
                || !descriptor_field_stores.contains(&(rule.point.clone(), rule.event_index))
        });
        for rule in &mut local_rules {
            if rule.kind == ValueFlowRelationKind::MemoryStore
                && uncertain_field_stores.contains(&(rule.point.clone(), rule.event_index))
            {
                rule.proof =
                    ProofStatus::Unproven("field store receiver class set is incomplete".into());
                rule.completeness = EvidenceCompleteness::Partial(
                    "field store may be intercepted by a descriptor".into(),
                );
                rule.strong_update = false;
            }
            rule.source = remap(rule.source)?;
            rule.target = remap(rule.target)?;
        }
        let mut call_rules = self.call_rules.to_vec();
        for rule in &mut call_rules {
            rule.source = remap(rule.source)?;
            rule.target = remap(rule.target)?;
        }
        let mut summary_location_bindings = self.summary_location_bindings.to_vec();
        for binding in &mut summary_location_bindings {
            binding.carrier = binding.carrier.map(remap).transpose()?;
        }

        let edge_kill_index = build_edge_kill_index(&edge_kills, &carrier_ids)?;
        let bound_sources = sources
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                Ok(BoundValueFlowSource {
                    id: ValueFlowSourceId::try_from_index(index)
                        .map_err(|_| ValueFlowPlanError::SourceIdOverflow)?,
                    carrier: *carrier_ids
                        .get(spec.carrier())
                        .ok_or(ValueFlowPlanError::MissingCarrier)?,
                    activation_triggers: spec.activation_triggers(),
                    spec,
                })
            })
            .collect::<Result<Vec<_>, ValueFlowPlanError>>()?;
        let mut bound_sinks = self.sinks.to_vec();
        for sink in &mut bound_sinks {
            sink.carrier = remap(sink.carrier)?;
        }

        let carrier_components = build_carrier_components(carriers.len(), &local_rules);
        let fallback_locations =
            build_fallback_location_index(&carriers, &carrier_ids, &carrier_components);
        let fallback_profiles = build_call_fallback_profiles(
            std::iter::once(&self.root)
                .chain(self.snapshot_procedures.iter())
                .collect::<Vec<_>>(),
            &carrier_ids,
            &carrier_components,
        );
        let local_rule_point_index = build_local_rule_point_index(&local_rules);
        let call_rule_reverse_index = build_call_rule_reverse_index(&call_rules);
        let source_index = build_observation_index(&bound_sources, |source| ObservationKey {
            point: source.spec.point().clone(),
            phase: source.spec.phase(),
        });
        let sink_index = build_observation_index(&bound_sinks, |sink| ObservationKey {
            point: sink.spec.point().clone(),
            phase: sink.spec.phase(),
        });

        Ok(Self {
            root: self.root.clone(),
            unmodeled_call_behavior: self.unmodeled_call_behavior,
            external_summaries: self.external_summaries.clone(),
            curated_call_models: self.curated_call_models.clone(),
            carriers: carriers.into_boxed_slice(),
            carrier_keys: carrier_keys.into_boxed_slice(),
            carrier_ids,
            local_rules: local_rules.into_boxed_slice(),
            local_rule_point_index,
            call_rules: call_rules.into_boxed_slice(),
            contextual_bindings: self.contextual_bindings,
            call_rule_reverse_index,
            fallback_profiles: fallback_profiles.into_boxed_slice(),
            fallback_locations,
            summary_location_bindings: summary_location_bindings.into_boxed_slice(),
            source_key_order: source_key_order(&bound_sources),
            sources: bound_sources.into_boxed_slice(),
            source_index,
            sinks: bound_sinks.into_boxed_slice(),
            sink_index,
            source_lists: source_lists.into_lists(),
            edge_kills: edge_kills.into_boxed_slice(),
            edge_kill_index,
            infeasible_points: self.infeasible_points.clone(),
            snapshot_procedures: self.snapshot_procedures.clone(),
            binding_pairs: self.binding_pairs.clone(),
            resolved_external_calls: self.resolved_external_calls.clone(),
            discovery_status: self.discovery_status,
            first_incomplete_cause: self.first_incomplete_cause.clone(),
            snapshot_discoveries: self.snapshot_discoveries.clone(),
            non_snapshot_discovery_complete: self.non_snapshot_discovery_complete,
            endpoint_discovery_complete: self.endpoint_discovery_complete,
            incomplete_binding_calls: self.incomplete_binding_calls.clone(),
            ambiguous_dispatch: self.ambiguous_dispatch,
            discovery_complete: self.discovery_complete,
            structural_discovery_complete: self.structural_discovery_complete,
            owner: Arc::new(()),
        })
    }

    /// Union endpoint observations from transfer-compatible plans and rebind
    /// their dense carrier/source/sink IDs once. This is the only supported
    /// path for sharing propagation across different policy demand sets.
    pub(crate) fn union_observations(plans: &[&Self]) -> Result<Self, ValueFlowPlanError> {
        let first = plans.first().ok_or(ValueFlowPlanError::MissingCarrier)?;
        if plans
            .iter()
            .skip(1)
            .any(|plan| !first.has_same_propagation_semantics(plan))
        {
            return Err(ValueFlowPlanError::IncompatibleObservationUnion);
        }

        let CarrierIndex {
            carriers,
            carrier_keys,
            carrier_ids,
        } = assign_carrier_ids(
            plans
                .iter()
                .flat_map(|plan| plan.carriers.iter().cloned())
                .collect(),
            MAX_VALUE_FLOW_CARRIERS,
        )?;
        let remap = |id: ValueFlowCarrierId| {
            carrier_ids
                .get(&first.carriers[id.index()])
                .copied()
                .ok_or(ValueFlowPlanError::MissingCarrier)
        };
        let mut local_rules = first.local_rules.to_vec();
        for rule in &mut local_rules {
            rule.source = remap(rule.source)?;
            rule.target = remap(rule.target)?;
        }
        let mut call_rules = first.call_rules.to_vec();
        for rule in &mut call_rules {
            rule.source = remap(rule.source)?;
            rule.target = remap(rule.target)?;
        }
        let mut summary_location_bindings = first.summary_location_bindings.to_vec();
        for binding in &mut summary_location_bindings {
            binding.carrier = binding.carrier.map(remap).transpose()?;
        }

        let mut source_origins = plans
            .iter()
            .flat_map(|plan| plan.sources.iter().map(move |source| (*plan, source)))
            .collect::<Vec<_>>();
        source_origins
            .sort_unstable_by(|(_, left), (_, right)| left.spec.key().cmp(right.spec.key()));
        let mut unique: Vec<(&ValueFlowPlan, &BoundValueFlowSource)> = Vec::new();
        for (plan, source) in source_origins {
            if let Some((previous_plan, previous_source)) = unique.last().copied()
                && source.spec.key() == previous_source.spec.key()
            {
                if !same_source_spec(previous_plan, &previous_source.spec, plan, &source.spec) {
                    return Err(ValueFlowPlanError::DuplicateEventKey);
                }
            } else {
                unique.push((plan, source));
            }
        }
        if unique.len() > MAX_VALUE_FLOW_SOURCES {
            return Err(ValueFlowPlanError::LimitExceeded);
        }
        let ids_by_key = unique
            .iter()
            .enumerate()
            .map(|(index, (_, source))| {
                (
                    source.spec.key(),
                    ValueFlowSourceId::try_from_index(index).expect("source ID fits u32"),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut source_lists = ValueFlowSourceLists::default();
        let mut source_specs = Vec::new();
        for (plan, source) in &unique {
            let mut spec = source.spec.clone();
            if let Some(list) = spec.activation_triggers() {
                let list = source_lists.intern(
                    plan.source_list(list)
                        .iter()
                        .map(|id| ids_by_key[plan.sources[id.index()].spec.key()])
                        .collect(),
                );
                spec = spec.when_sources_reach(list);
            }
            source_specs.push(spec);
        }
        let mut edge_kills = first.edge_kills.to_vec();
        for kill in &mut edge_kills {
            kill.sources = source_lists.intern(
                first
                    .source_list(kill.sources)
                    .iter()
                    .map(|id| ids_by_key[first.sources[id.index()].spec.key()])
                    .collect(),
            );
        }
        let edge_kill_index = build_edge_kill_index(&edge_kills, &carrier_ids)?;
        let sources = source_specs
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                Ok(BoundValueFlowSource {
                    id: ValueFlowSourceId::try_from_index(index)
                        .map_err(|_| ValueFlowPlanError::SourceIdOverflow)?,
                    carrier: *carrier_ids
                        .get(spec.carrier())
                        .ok_or(ValueFlowPlanError::MissingCarrier)?,
                    activation_triggers: spec.activation_triggers(),
                    spec,
                })
            })
            .collect::<Result<Vec<_>, ValueFlowPlanError>>()?;
        let mut sink_specs = plans
            .iter()
            .flat_map(|plan| plan.sinks.iter().map(|sink| sink.spec.clone()))
            .collect::<Vec<_>>();
        sink_specs.sort_by(|left, right| left.key().cmp(right.key()));
        sink_specs.dedup();
        if sink_specs.len() > MAX_VALUE_FLOW_SINKS
            || sink_specs
                .windows(2)
                .any(|pair| pair[0].key() == pair[1].key())
        {
            return Err(ValueFlowPlanError::DuplicateEventKey);
        }
        let sinks = sink_specs
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                Ok(BoundValueFlowSink {
                    id: ValueFlowSinkId::try_from_index(index)
                        .map_err(|_| ValueFlowPlanError::SinkIdOverflow)?,
                    carrier: *carrier_ids
                        .get(spec.carrier())
                        .ok_or(ValueFlowPlanError::MissingCarrier)?,
                    spec,
                })
            })
            .collect::<Result<Vec<_>, ValueFlowPlanError>>()?;

        let carrier_components = build_carrier_components(carriers.len(), &local_rules);
        let fallback_locations =
            build_fallback_location_index(&carriers, &carrier_ids, &carrier_components);
        let fallback_profiles = build_call_fallback_profiles(
            std::iter::once(&first.root)
                .chain(first.snapshot_procedures.iter())
                .collect::<Vec<_>>(),
            &carrier_ids,
            &carrier_components,
        );
        let local_rule_point_index = build_local_rule_point_index(&local_rules);
        let call_rule_reverse_index = build_call_rule_reverse_index(&call_rules);
        let source_index = build_observation_index(&sources, |source| ObservationKey {
            point: source.spec.point().clone(),
            phase: source.spec.phase(),
        });
        let sink_index = build_observation_index(&sinks, |sink| ObservationKey {
            point: sink.spec.point().clone(),
            phase: sink.spec.phase(),
        });

        Ok(Self {
            root: first.root.clone(),
            unmodeled_call_behavior: first.unmodeled_call_behavior,
            external_summaries: first.external_summaries.clone(),
            curated_call_models: first.curated_call_models.clone(),
            carriers: carriers.into_boxed_slice(),
            carrier_keys: carrier_keys.into_boxed_slice(),
            carrier_ids,
            local_rules: local_rules.into_boxed_slice(),
            local_rule_point_index,
            call_rules: call_rules.into_boxed_slice(),
            contextual_bindings: first.contextual_bindings,
            call_rule_reverse_index,
            fallback_profiles: fallback_profiles.into_boxed_slice(),
            fallback_locations,
            summary_location_bindings: summary_location_bindings.into_boxed_slice(),
            source_key_order: source_key_order(&sources),
            sources: sources.into_boxed_slice(),
            source_index,
            sinks: sinks.into_boxed_slice(),
            sink_index,
            source_lists: source_lists.into_lists(),
            edge_kills: edge_kills.into_boxed_slice(),
            edge_kill_index,
            infeasible_points: first.infeasible_points.clone(),
            snapshot_procedures: first.snapshot_procedures.clone(),
            binding_pairs: first.binding_pairs.clone(),
            resolved_external_calls: first.resolved_external_calls.clone(),
            discovery_status: first.discovery_status,
            first_incomplete_cause: plans
                .iter()
                .find_map(|plan| plan.first_incomplete_cause.clone()),
            snapshot_discoveries: first.snapshot_discoveries.clone(),
            non_snapshot_discovery_complete: plans
                .iter()
                .all(|plan| plan.non_snapshot_discovery_complete),
            endpoint_discovery_complete: plans.iter().all(|plan| plan.endpoint_discovery_complete),
            incomplete_binding_calls: {
                let mut calls: Vec<CallSiteHandle> = Vec::new();
                for plan in plans {
                    for call in plan.incomplete_binding_calls.iter() {
                        if !calls
                            .iter()
                            .any(|known| compare_calls(known, call) == Ordering::Equal)
                        {
                            calls.push(call.clone());
                        }
                    }
                }
                calls.sort_by(compare_calls);
                calls.into_boxed_slice()
            },
            ambiguous_dispatch: plans.iter().any(|plan| plan.ambiguous_dispatch),
            discovery_complete: plans.iter().all(|plan| plan.discovery_complete),
            structural_discovery_complete: plans
                .iter()
                .all(|plan| plan.structural_discovery_complete),
            owner: Arc::new(()),
        })
    }

    pub fn carrier_id(&self, carrier: &ValueFlowCarrier) -> Option<ValueFlowCarrierId> {
        self.carrier_ids.get(carrier).copied().or_else(|| {
            // A call boundary can be re-materialized after the plan inputs
            // were collected. Stable carrier identity still proves that the
            // live handle names the plan's retained entity, even when pointer
            // equality misses the per-materialization reverse map.
            carrier
                .stable_key()
                .ok()
                .and_then(|key| self.carrier_id_for_key(&key))
        })
    }

    pub const fn discovery_status(&self) -> SemanticInputStatus {
        self.discovery_status
    }

    /// The first discovery input, in the plan's deterministic input order, that
    /// prevented `discovery_complete` (#1952). `None` exactly when discovery is
    /// complete.
    pub const fn first_incomplete_cause(&self) -> Option<&ValueFlowIncompleteCause> {
        self.first_incomplete_cause.as_ref()
    }

    pub const fn has_ambiguous_dispatch(&self) -> bool {
        self.ambiguous_dispatch
    }

    pub const fn discovery_complete(&self) -> bool {
        self.discovery_complete
    }

    pub(crate) fn owner(&self) -> &Arc<()> {
        &self.owner
    }

    /// Whether every row this run reached sits in a procedure this plan has a
    /// snapshot for, with every call at that point either bound by this plan or
    /// fully modeled by this result's boundaries.
    ///
    /// This quantifier ranges over `result.reached()`, so a result with fewer
    /// rows satisfies it more easily. That matters because a reuse-backed solve
    /// really does have fewer: binding a reusable summary for a callee replaces
    /// the callee's whole body, so nothing that callee calls is entered and the
    /// subtree contributes no reached row and no coverage row (#2291).
    ///
    /// A replay therefore cannot report a completeness the fresh solve refuses,
    /// but not because of anything in this predicate. Two properties of the
    /// summary itself carry it, and #2296 constructed the three subtree shapes
    /// -- an unmodeled dispatch boundary, an unproven relation, a capability
    /// gap -- that would otherwise break it.
    ///
    /// First, a summary exists only because some solve reported itself complete.
    /// `solve_taint_with_reusable_summaries` in
    /// `crate::taint::summary` returns
    /// `TaintTransferSummaryCacheStatus::Incomplete` and publishes nothing when
    /// its own result's `is_complete()` is false, and
    /// `project_complete_taint_summaries` refuses the projection for the same
    /// reason. That verdict is this predicate, applied by a solve that did walk
    /// the subtree. So the subtree's state is recorded in the summary's
    /// existence, not in the rows the replay drops.
    ///
    /// Second, the summary is looked up under a key that pins the analysis
    /// inputs of that subtree. The taint summary key carries a dependency
    /// contract: the transitive closure of the summarized procedure's declared
    /// dependencies, each with the value-flow carrier identity this plan would
    /// give it (`Self::carrier_summary_identities`), which includes the curated
    /// call models, external summary fingerprints, snapshot presence, local and
    /// call rules, and unmodeled call behavior that decide whether a construct
    /// in that subtree is discharged. A summary published under a plan that
    /// models the subtree cannot be bound by a plan that does not.
    ///
    /// Both rest on the dependency closure naming what the body calls. When it
    /// does not, the solver refuses the summary rather than trusting it: see
    /// `SummaryCalledProcedures` in `crate::dataflow`. The tests that
    /// pin all of this are in `tests/suite_semantic/taint_client.rs`, named for
    /// the three subtree shapes.
    ///
    /// One coverage-derived projection does diverge, deliberately and
    /// documented: `Self::public_semantic_status` merges retained semantic
    /// boundary statuses without applying the models that discharge them, so a
    /// replay that retained no boundary reports `Complete` where the fresh
    /// solve reports the subtree's raw status. CodeQuery's ordinary value-flow
    /// search paths still use the non-reusable entry point. Class-set type flow
    /// is a reuse-backed consumer, but it never uses an omitted row to prove a
    /// root sink absent: a zero-entry root row is admitted only when every
    /// current sink has a remapped Meeting, under the exact procedure,
    /// dependency, dispatch-read, and root-surface identities. Otherwise it
    /// continues with the ordinary root solve while retaining eligible callee
    /// reuse. The tests
    /// `a_modeled_subtree_construct_reuses_a_non_leaf_callee_without_claiming_more_completeness`,
    /// `complete_root_meetings_skip_fresh_solving_with_identical_class_sets`,
    /// and `root_summary_missing_a_current_sink_continues_with_callee_reuse`
    /// pin those two contracts.
    fn execution_discovery_modeled<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
        requirement: SummaryProofRequirement,
    ) -> bool {
        // The plan retains contextual transfer rows, but this completeness
        // predicate still quantifies origin-only binding coverage. It cannot
        // certify a contextual execution (or an unsupported client's refusal)
        // until the exact execution-context coverage ledger is retained here.
        !self.contextual_bindings
            && result.reached().iter().all(|reached| {
                reached.entry().call_context().calls().is_empty()
                    && !reached.entry().call_context().was_truncated()
            })
            && self.structural_discovery_complete
            && result.reached().iter().all(|reached| {
                let procedure = reached.point().procedure();
                self.has_snapshot(procedure)
                    && procedure
                        .semantics()
                        .point(reached.point().id())
                        .is_some_and(|point| {
                            point.events.iter().all(|event| match event.effect {
                                SemanticEffect::Invoke { call_site } => {
                                    procedure.call_site_handle(call_site).is_some_and(|call| {
                                        self.has_binding_for_call(&call)
                                            || self.call_boundaries_are_fully_modeled(
                                                result,
                                                &call,
                                                reached.entry().call_context(),
                                                requirement,
                                            )
                                    })
                                }
                                _ => true,
                            })
                        })
            })
    }

    pub(crate) fn execution_result_complete<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
    ) -> bool {
        self.execution_result_modeled(result, SummaryProofRequirement::Derived)
    }

    /// Whether the run is complete once authored-complete external procedure
    /// summaries are accepted as closing their boundaries. A run that is already
    /// complete on derived proof also satisfies this, so callers that want the
    /// distinct `ProvenBySummary` case must additionally require
    /// `!execution_result_complete`.
    pub(crate) fn execution_result_complete_accepting_authored_summaries<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
    ) -> bool {
        self.execution_result_modeled(result, SummaryProofRequirement::AcceptAuthoredComplete)
    }

    /// Whether this run terminated precisely and every open edge and boundary
    /// it retained is discharged.
    ///
    /// Like `Self::execution_discovery_modeled`, every quantifier here ranges
    /// over rows a reuse-backed solve can be missing: `result.coverage()` is
    /// accumulated as the solver walks edges and materializes call transfers,
    /// so a skipped subtree contributes no unproven edge, no partial edge, and
    /// no boundary. See that function's comment for why a replay still cannot
    /// claim a completeness the fresh solve refuses (#2296), and for the one
    /// coverage-derived projection that does diverge.
    fn execution_result_modeled<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
        requirement: SummaryProofRequirement,
    ) -> bool {
        let fixed_point = result.termination().is_fixed_point();
        let execution_discovery =
            fixed_point && self.execution_discovery_modeled(result, requirement);
        let discovery_closed = execution_discovery && self.discovery_closed_by(result, requirement);
        if !fixed_point || !execution_discovery || !discovery_closed {
            return false;
        }
        let fully_modeled_calls = result
            .coverage()
            .boundaries()
            .iter()
            .filter_map(|boundary| {
                let call = boundary.origin()?;
                self.call_boundaries_are_fully_modeled(
                    result,
                    call,
                    boundary.call_context(),
                    requirement,
                )
                .then_some((call, boundary.call_context()))
            })
            .collect::<Vec<_>>();
        let abort_paths_only_unwind = std::cell::OnceCell::new();
        let edge_is_discharged = |edge: &crate::dataflow::SummaryEdge| {
            (matches!(
                edge.kind(),
                IcfgEdgeKind::CallToNormalContinuation
                    | IcfgEdgeKind::CallToExceptionalContinuation
            ) && edge
                .origin()
                .is_some_and(|origin| fully_modeled_calls.contains(&(origin, edge.call_context()))))
                || self.exceptional_return_edge_is_abort_only(edge, &abort_paths_only_unwind)
        };
        result
            .coverage()
            .unproven_edges()
            .iter()
            .all(edge_is_discharged)
            && result
                .coverage()
                .partial_edges()
                .iter()
                .all(edge_is_discharged)
            && result.coverage().boundaries().iter().all(|boundary| {
                self.boundary_is_fully_modeled(
                    result,
                    boundary,
                    requirement,
                    &abort_paths_only_unwind,
                )
            })
    }

    /// Whether typed discovery is closed for this execution result (#1952):
    /// every non-snapshot input is complete, and every snapshot is either
    /// complete (possibly refined by this plan's own bindings) or refinable
    /// with each residual call fully modeled by this result's boundaries (a
    /// complete external summary or curated model).
    fn discovery_closed_by<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
        requirement: SummaryProofRequirement,
    ) -> bool {
        self.endpoint_discovery_complete
            && self.incomplete_binding_calls.iter().all(|call| {
                // Only a curated model may answer an incomplete binding input:
                // it is an authored claim about the call's whole behavior. An
                // external pack summary keeps the pre-existing strictness.
                self.curated_model_for_call(call).is_some()
                    && self.call_boundaries_are_fully_modeled(
                        result,
                        call,
                        &OracleCallContext::empty(),
                        requirement,
                    )
            })
            && self
                .snapshot_discoveries
                .iter()
                .all(|discovery| match discovery {
                    SnapshotDiscovery::Complete => true,
                    SnapshotDiscovery::Incomplete { .. } => false,
                    SnapshotDiscovery::Refinable { calls } => calls.iter().all(|call| {
                        self.call_boundaries_are_fully_modeled(
                            result,
                            call,
                            &OracleCallContext::empty(),
                            requirement,
                        )
                    }),
                })
    }

    fn call_boundaries_are_fully_modeled<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
        call: &CallSiteHandle,
        context: &OracleCallContext,
        requirement: SummaryProofRequirement,
    ) -> bool {
        let mut saw_dispatch = false;
        let allocation_call =
            crate::analyzer::semantic::workspace_oracle::allocation_call_is_dischargeable(
                call.procedure().semantics(),
                call.procedure()
                    .semantics()
                    .call_site(call.id())
                    .expect("call boundary origin must remain live"),
            );
        for boundary in result.coverage().boundaries().iter().filter(|boundary| {
            boundary.origin() == Some(call) && boundary.call_context() == context
        }) {
            match boundary.kind() {
                SummaryBoundaryKind::Dispatch(_) => {
                    saw_dispatch = true;
                    if !allocation_call {
                        let modeled =
                            self.dispatch_boundary_is_fully_modeled(result, boundary, requirement);
                        if !modeled {
                            return false;
                        }
                    }
                }
                SummaryBoundaryKind::Semantic(_) => {}
                SummaryBoundaryKind::Limit(_) | SummaryBoundaryKind::Continuation { .. } => {
                    return false;
                }
            }
        }
        // A fully bindable curated model answers a residual refinement call
        // even when the run recorded no dispatch boundary for it: a plan that
        // deliberately binds no callee for a modeled call (a policy-declared
        // external model, #2691) leaves the call with neither a binding nor a
        // boundary, and the model's transfers are the call's complete
        // semantics, exactly as in `dispatch_boundary_is_fully_modeled`.
        saw_dispatch
            || allocation_call
            || self.curated_model_for_call(call).is_some_and(|model| {
                self.model_is_fully_bindable(
                    call,
                    model.transfers(),
                    SummaryProofRequirement::Derived,
                    SummaryCallBinding::default(),
                )
            })
    }

    fn boundary_is_fully_modeled<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
        boundary: &SummaryBoundary,
        requirement: SummaryProofRequirement,
        abort_paths_only_unwind: &std::cell::OnceCell<bool>,
    ) -> bool {
        if matches!(boundary.kind(), SummaryBoundaryKind::Semantic(_)) {
            if self.exceptional_exit_boundary_is_abort_only(boundary, abort_paths_only_unwind) {
                return true;
            }
            return boundary.origin().is_some_and(|call| {
                self.call_boundaries_are_fully_modeled(
                    result,
                    call,
                    boundary.call_context(),
                    requirement,
                )
            });
        }
        if boundary.origin().is_some_and(|call| {
            crate::analyzer::semantic::workspace_oracle::allocation_call_is_dischargeable(
                call.procedure().semantics(),
                call.procedure()
                    .semantics()
                    .call_site(call.id())
                    .expect("call boundary origin must remain live"),
            )
        }) {
            return true;
        }
        self.dispatch_boundary_is_fully_modeled(result, boundary, requirement)
    }

    /// Whether an exceptional-exit profile boundary reports only unlowered
    /// implicit abort edges that cannot carry a value (#1952).
    ///
    /// The exit profile keeps an `Unsupported` exceptional-control-flow status
    /// when a procedure's implicit abort edges are not lowered. When no
    /// procedure in this plan runs user code on an abort path -- no handler
    /// and no cleanup body anywhere in the analyzed region -- those edges can
    /// only unwind, so the boundary cannot hide a flow the demanded endpoints
    /// could observe. One handler anywhere keeps every such boundary open,
    /// because a callee's implicit throw decides that handler's reachability.
    /// The solver coverage's semantic-status merge, minus the abort-only
    /// exceptional-exit boundaries this plan's completion logic discharges
    /// (#1952), so public projections and completion agree on one status.
    pub fn public_semantic_status<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
    ) -> SemanticInputStatus {
        // A solve that replayed a cross-query reusable summary retained none of
        // the skipped subtree's coverage boundaries, so folding the boundaries
        // that are present would answer `Complete` for material this result
        // never looked at (#2296). The envelope for that subtree is not in the
        // result at all, which is exactly what `Unknown` states; a consumer
        // that needs the raw statuses must solve through the non-reusable
        // entry point, as the CodeQuery value-flow search paths do.
        let seed = if result.metrics().reusable_summary_hits > 0 {
            SemanticInputStatus::Unknown
        } else {
            SemanticInputStatus::Complete
        };
        let abort_paths_only_unwind = std::cell::OnceCell::new();
        result
            .coverage()
            .boundaries()
            .iter()
            .filter(|boundary| {
                !self.exceptional_exit_boundary_is_abort_only(boundary, &abort_paths_only_unwind)
            })
            .filter_map(|boundary| match boundary.kind() {
                SummaryBoundaryKind::Semantic(status) => Some(*status),
                SummaryBoundaryKind::Dispatch(_)
                | SummaryBoundaryKind::Limit(_)
                | SummaryBoundaryKind::Continuation { .. } => None,
            })
            .fold(seed, |current, incoming| current.merge(incoming))
    }

    fn exceptional_exit_boundary_is_abort_only(
        &self,
        boundary: &SummaryBoundary,
        abort_paths_only_unwind: &std::cell::OnceCell<bool>,
    ) -> bool {
        let SummaryBoundaryKind::Semantic(SemanticInputStatus::Unsupported {
            capability: crate::analyzer::semantic::SemanticCapability::ExceptionalControlFlow,
        }) = boundary.kind()
        else {
            return false;
        };
        if boundary.origin().is_some()
            || boundary.at().id()
                != boundary
                    .at()
                    .procedure()
                    .semantics()
                    .exceptional_exit_point()
        {
            return false;
        }
        *abort_paths_only_unwind.get_or_init(|| self.abort_paths_only_unwind())
    }

    /// Whether an exceptional-return edge was weakened only by the same
    /// implicit-abort profile that completion discharges at the callee's
    /// exceptional-exit boundary.
    ///
    /// Return projection attaches the profile's proof and completeness to the
    /// edge as well as publishing its semantic boundary. Its structured marker
    /// is present only when the incoming call transfer was independently
    /// proven and complete, so this discharge cannot forgive dispatch or call
    /// evaluation uncertainty. Rendered proof text is deliberately not parsed.
    fn exceptional_return_edge_is_abort_only(
        &self,
        edge: &crate::dataflow::SummaryEdge,
        abort_paths_only_unwind: &std::cell::OnceCell<bool>,
    ) -> bool {
        if edge.kind() != IcfgEdgeKind::ExceptionalReturn || !edge.implicit_abort_only() {
            return false;
        }
        *abort_paths_only_unwind.get_or_init(|| self.abort_paths_only_unwind())
    }

    fn abort_paths_only_unwind(&self) -> bool {
        self.summary_procedures().all(|procedure| {
            !crate::analyzer::semantic::workspace_oracle::abort_paths_run_user_code(
                procedure.semantics(),
            )
        })
    }

    fn dispatch_boundary_is_fully_modeled<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
        boundary: &SummaryBoundary,
        requirement: SummaryProofRequirement,
    ) -> bool {
        let Some(call) = boundary.origin() else {
            return false;
        };
        let SummaryBoundaryKind::Dispatch(kind) = boundary.kind() else {
            return false;
        };
        if let Some((summary, actual_to_formal)) = self.external_summary_for_boundary(kind) {
            let summary_complete = summary.completeness().is_complete();
            let bindable = self.model_is_fully_bindable(
                call,
                summary.transfers(),
                requirement,
                actual_to_formal,
            );
            let authored_complete = summary_complete && bindable;
            return match requirement {
                SummaryProofRequirement::Derived => {
                    // An empty authored relation still closes a call by a
                    // model claim; vacuous transfer checks are not body proof.
                    matches!(summary.key().identity().origin(), SummaryOrigin::Inferred)
                        && matches!(boundary.proof(), Some(ProofStatus::Proven))
                        && authored_complete
                }
                // A retained canonical callee from an unresolved lookup can
                // select and contribute an authored model, but the model is
                // not proof that the unresolved target set was complete.
                SummaryProofRequirement::AcceptAuthoredComplete => {
                    matches!(boundary.proof(), Some(ProofStatus::Proven)) && authored_complete
                }
            };
        }
        if matches!(kind, DispatchBoundaryKind::Unresolved)
            && matches!(requirement, SummaryProofRequirement::AcceptAuthoredComplete)
            && self
                .authored_arm_closure(result, call, boundary.call_context())
                .is_some()
        {
            return true;
        }
        if self.resolved_constructor_boundary(call, kind) {
            return true;
        }
        // A curated model is a Bifrost-authored fallback, not an external pack
        // summary, so it always answers to the derived requirement.
        self.curated_model_for_call(call).is_some_and(|model| {
            self.model_is_fully_bindable(
                call,
                model.transfers(),
                SummaryProofRequirement::Derived,
                SummaryCallBinding::default(),
            )
        })
    }

    /// The contract-claiming external summary that closes this call's named
    /// external boundary or residual blanket-refinement arm, if the guards
    /// permit the closure (#2342, #2371).
    ///
    /// The named-target arm is addressed directly by its activated summary. A
    /// call whose language adapter also retained a blanket "the target may
    /// select an override" gap carries a residual `Unresolved` arm beside it.
    /// That residual names no target, so `external_summary_for_boundary` cannot
    /// address it directly.
    ///
    /// A contract-claiming summary for the exact target named on the call is an
    /// assertion about every implementation of that target, so it answers the
    /// residual arm too -- that is the "external residual" half of #2371's
    /// discharge rule. The guards keep that from becoming a blanket amnesty:
    ///
    ///   * The caller admits only `AcceptAuthoredComplete`, so `Complete` keeps
    ///     asking `Derived` and authored trust still cannot launder into it
    ///     (#1916).
    ///   * Only a sibling `External` or `Unmaterialized` arm that names its
    ///     target qualifies. `External(None)`, `Deferred`, `Truncated`, and a
    ///     second `Unresolved` arm name none, and a `Limit` or `Continuation`
    ///     boundary is not a dispatch arm at all -- none of them can carry the
    ///     summary, so a genuinely ambiguous target set still refuses.
    ///   * A receiver-bearing summary must carry an explicit
    ///     `covers_overrides` claim (#2371). A receiverless target has no
    ///     overrides to cover, so authored completeness is already a statement
    ///     about its whole target set. In both cases the summary must be fully
    ///     bindable at this call.
    ///   * The call must have no analyzed callee of its own. A call that both
    ///     enters a workspace body and names an unmaterialized declaration --
    ///     an interface member with one visible implementor, say -- has a
    ///     target set the summary does not describe, and its residual arm is
    ///     about the implementors nobody enumerated. That is exactly the
    ///     genuine ambiguity the residual arm exists to report, so it refuses.
    ///
    /// When a residual exists, this closure is the "external residual" half of
    /// the discharge rule only. The "workspace half" -- CHA proving the
    /// workspace implementors of the resolved declaring member enumerated,
    /// possibly empty -- is proven upstream in `workspace_oracle::dispatch`.
    /// A call whose only named target is an unmaterialized external member
    /// carries no workspace declaration to run CHA against, so that half is
    /// proven instead from the analyzer's complete short-name index. When it
    /// cannot be proven the call gets an additional `Truncated` arm that this
    /// closure cannot address (`Truncated` is excluded above), so
    /// `call_boundaries_are_fully_modeled` still refuses the call as a whole.
    /// This closure never has to ask that question itself.
    ///
    /// A sibling arm that names a target the activated packs do not summarize
    /// fails `call_boundaries_are_fully_modeled` on its own turn through the
    /// loop, so this closure cannot rescue a call that has an unmodeled arm.
    fn authored_arm_closure<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
        call: &CallSiteHandle,
        context: &OracleCallContext,
    ) -> Option<AuthoredArmClosure> {
        let target = result
            .coverage()
            .boundaries()
            .iter()
            .filter(|sibling| sibling.origin() == Some(call) && sibling.call_context() == context)
            .find_map(|sibling| {
                let SummaryBoundaryKind::Dispatch(kind) = sibling.kind() else {
                    return None;
                };
                Self::authored_dispatch_target(kind)
            })?;
        self.authored_target_closure(call, context, target)
    }

    fn authored_dispatch_target(kind: &DispatchBoundaryKind) -> Option<&SemanticLocator> {
        match kind {
            DispatchBoundaryKind::External(Some(target))
            | DispatchBoundaryKind::Unmaterialized(target) => Some(target),
            DispatchBoundaryKind::External(None)
            | DispatchBoundaryKind::Deferred { .. }
            | DispatchBoundaryKind::Unresolved
            | DispatchBoundaryKind::Truncated => None,
        }
    }

    fn authored_target_closure(
        &self,
        call: &CallSiteHandle,
        context: &OracleCallContext,
        target: &SemanticLocator,
    ) -> Option<AuthoredArmClosure> {
        if context.was_truncated() || self.has_binding_for_call(call) {
            return None;
        }
        authored_summary_closure(
            call,
            context,
            target,
            &self.external_summaries,
            self.is_resolved_external_call(call),
            |transfers, actual_to_formal| {
                self.model_is_fully_bindable(
                    call,
                    transfers,
                    SummaryProofRequirement::AcceptAuthoredComplete,
                    actual_to_formal,
                )
            },
        )
    }

    /// Validate one retained path and its endpoint call obligations. Exact
    /// call/target association comes from the path, never a run-wide closure list.
    /// Returns the authored closures the path relies on when every hop is
    /// proven and complete, counting a complete, exactly bound authored
    /// summary from an active pack as closing its call (#5218); `None` when
    /// the path cannot establish certainty. Raw authored edge proof remains
    /// unchanged.
    pub(crate) fn certain_witness_closures<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
        witness: &SummaryWitness,
        source: &ValueFlowSourceSpec,
        sink: &ValueFlowSinkSpec,
    ) -> Option<Vec<AuthoredArmClosure>> {
        // Contextual execution lacks a retained binding-coverage ledger, as
        // in execution_discovery_modeled. A local suffix cannot supply it.
        if self.contextual_bindings || witness.truncated() || witness.steps().is_empty() {
            return None;
        }
        let mut closures = Vec::new();
        let first = witness
            .steps()
            .iter()
            .position(|step| step.source() == source.point())?;
        // Endpoint selection can require dispatch even when the witness stops
        // before the invocation edge. Structural syntax and declared signatures
        // establish their endpoints independently of executable dispatch.
        for call in source
            .dispatch_obligations()
            .iter()
            .chain(sink.dispatch_obligations())
        {
            let context = OracleCallContext::empty();
            let has_open_boundary = result.coverage().boundaries().iter().any(|boundary| {
                boundary.origin() == Some(call) && boundary.call_context() == &context
            });
            if self.has_binding_for_call(call)
                && !self.incomplete_binding_calls.contains(call)
                && !has_open_boundary
            {
                continue;
            }
            if !self.call_boundaries_are_fully_modeled(
                result,
                call,
                &context,
                SummaryProofRequirement::AcceptAuthoredComplete,
            ) {
                return None;
            }
            // A summary that closes an endpoint dispatch is a dependency
            // even when the witness does not traverse a model transfer.
            for boundary in result.coverage().boundaries().iter().filter(|boundary| {
                boundary.origin() == Some(call) && boundary.call_context() == &context
            }) {
                let SummaryBoundaryKind::Dispatch(kind) = boundary.kind() else {
                    continue;
                };
                let closure =
                    if self
                        .external_summary_for_boundary(kind)
                        .is_some_and(|(summary, _)| {
                            matches!(
                                summary.key().identity().origin(),
                                SummaryOrigin::External(_)
                            )
                        })
                    {
                        let target = Self::authored_dispatch_target(kind)?;
                        Some(self.authored_target_closure(call, &context, target)?)
                    } else if matches!(kind, DispatchBoundaryKind::Unresolved) {
                        self.authored_arm_closure(result, call, &context)
                    } else {
                        None
                    };
                if let Some(closure) = closure
                    && !closures.contains(&closure)
                {
                    closures.push(closure);
                }
            }
        }
        for step in &witness.steps()[first..] {
            if matches!(step.kind(), SummaryWitnessStepKind::EndSummaryGap(_)) {
                return None;
            }
            let continuation = matches!(
                step.kind(),
                SummaryWitnessStepKind::Edge(
                    IcfgEdgeKind::CallToNormalContinuation
                        | IcfgEdgeKind::CallToExceptionalContinuation
                )
            );
            let closure = if continuation && !self.has_binding_for_call(step.origin()?) {
                let call = step.origin()?;
                if !self.call_boundaries_are_fully_modeled(
                    result,
                    call,
                    &OracleCallContext::empty(),
                    SummaryProofRequirement::AcceptAuthoredComplete,
                ) {
                    return None;
                }
                match step.boundary().and_then(Self::authored_dispatch_target) {
                    Some(target) => {
                        self.authored_target_closure(call, &OracleCallContext::empty(), target)
                    }
                    None => self.authored_arm_closure(result, call, &OracleCallContext::empty()),
                }
            } else {
                None
            };
            if let Some(closure) = closure {
                if !closures.contains(&closure) {
                    closures.push(closure);
                }
            } else if !matches!(step.proof(), ProofStatus::Proven)
                || !matches!(step.completeness(), EvidenceCompleteness::Complete)
            {
                // A derived modeled continuation can carry raw adapter gaps.
                // It is discharged only by the existing derived call guards.
                if !continuation
                    || !self.call_boundaries_are_fully_modeled(
                        result,
                        step.origin()?,
                        &OracleCallContext::empty(),
                        SummaryProofRequirement::Derived,
                    )
                {
                    return None;
                }
            }
        }
        Some(closures)
    }

    /// Retain valid authored identities on this source-to-sink path even when
    /// review or some other step prevents the path from establishing certainty.
    pub(crate) fn witness_arm_closures(
        &self,
        witness: &SummaryWitness,
        source: &ProgramPointHandle,
    ) -> Vec<AuthoredArmClosure> {
        let Some(first) = witness
            .steps()
            .iter()
            .position(|step| step.source() == source)
        else {
            return Vec::new();
        };
        let mut closures = Vec::new();
        for step in &witness.steps()[first..] {
            let Some(call) = step.origin() else {
                continue;
            };
            let Some(target) = step.boundary().and_then(Self::authored_dispatch_target) else {
                continue;
            };
            if let Some(closure) =
                self.authored_target_closure(call, &OracleCallContext::empty(), target)
                && !closures.contains(&closure)
            {
                closures.push(closure);
            }
        }
        closures
    }

    /// Every dispatch boundary this result closed by an authored-complete
    /// external summary, in call order (#2342).
    ///
    /// A run that concludes `ProvenBySummary` because of such a closure must be
    /// able to say which authored claim proved it, so this is retained on the
    /// result rather than recomputed by a consumer that would have to
    /// re-derive the guards.
    pub fn authored_arm_closures<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
    ) -> Vec<AuthoredArmClosure> {
        let mut closures = Vec::new();
        for boundary in result.coverage().boundaries() {
            let (Some(call), SummaryBoundaryKind::Dispatch(kind)) =
                (boundary.origin(), boundary.kind())
            else {
                continue;
            };
            let closure = if matches!(kind, DispatchBoundaryKind::Unresolved) {
                self.authored_arm_closure(result, call, boundary.call_context())
            } else {
                Self::authored_dispatch_target(kind).and_then(|target| {
                    self.authored_target_closure(call, boundary.call_context(), target)
                })
            };
            if let Some(closure) = closure
                && !closures.iter().any(|existing: &AuthoredArmClosure| {
                    existing.call == closure.call
                        && existing.context == closure.context
                        && existing.target == closure.target
                })
            {
                closures.push(closure);
            }
        }
        closures
    }

    fn model_is_fully_bindable(
        &self,
        call: &CallSiteHandle,
        transfers: &[SummaryTransfer],
        requirement: SummaryProofRequirement,
        actual_to_formal: SummaryCallBinding<'_>,
    ) -> bool {
        transfers.iter().all(|transfer| {
            let evidence = transfer.evidence();
            let evidence_ok = match requirement {
                SummaryProofRequirement::Derived => summary_evidence_is_proven_complete(evidence),
                // `bind_compiled_procedure_summaries` stamps an external transfer
                // unproven, because a summary is an authored assertion about a
                // body Bifrost never analyzed (#1916). An authored-complete
                // summary still carries complete evidence, so accept completeness
                // alone when the summary-backed tier is the question.
                SummaryProofRequirement::AcceptAuthoredComplete => evidence.is_complete(),
            };
            evidence_ok
                && match self.summary_input_binding(call, transfer.input(), actual_to_formal) {
                    SummaryInputBinding::Carrier(_) => {
                        self.summary_port_carrier(
                            call,
                            transfer.exit().port(),
                            actual_to_formal,
                        )
                            .is_some()
                            // A live exit value without a carrier makes the
                            // transfer's output unobservable over this plan's
                            // carriers, which is vacuous rather than a
                            // missing-model gap (#3406).
                            || self
                                .summary_port_value(
                                    call,
                                    transfer.exit().port(),
                                    actual_to_formal,
                                )
                                .is_some()
                    }
                    SummaryInputBinding::VacuousConstant
                    | SummaryInputBinding::OmittedArgument
                    | SummaryInputBinding::CarrierlessValue => true,
                    SummaryInputBinding::Unbound => false,
                }
        })
    }

    pub(crate) fn has_snapshot(&self, procedure: &ProcedureHandle) -> bool {
        self.snapshot_procedures
            .iter()
            .any(|candidate| candidate == procedure)
    }

    /// Every procedure the plan mounts: the root and each snapshot.
    pub fn mounted_procedures(&self) -> impl Iterator<Item = &ProcedureHandle> {
        self.summary_procedures()
    }

    /// Whether a curated model already owns `call`.
    pub fn has_curated_call_model(&self, call: &CallSiteHandle) -> bool {
        self.curated_model_for_call(call).is_some()
    }

    /// Whether a curated model owns `call` and every transfer it states is
    /// proven and complete, so the model is the call's whole behavior at the
    /// derived tier (#3757).
    pub fn curated_model_is_proven_complete(&self, call: &CallSiteHandle) -> bool {
        self.curated_model_for_call(call)
            .is_some_and(CuratedCallModel::is_proven_complete)
    }

    pub(crate) fn summary_procedures(&self) -> impl Iterator<Item = &ProcedureHandle> {
        std::iter::once(&self.root).chain(self.snapshot_procedures.iter())
    }

    pub(crate) fn has_binding_for_call(&self, call: &CallSiteHandle) -> bool {
        self.binding_pairs
            .iter()
            .any(|(candidate, _)| candidate == call)
    }

    /// Every callee this plan can enter through a concrete call binding.
    ///
    /// An unbound or open call has no pair and therefore cannot consume a
    /// reusable procedure summary. Callees may repeat when several call sites
    /// bind the same procedure; consumers that only test existence can stop at
    /// the first match without allocating a deduplication index.
    pub(crate) fn bound_callees(&self) -> impl Iterator<Item = &ProcedureHandle> {
        self.binding_pairs.iter().map(|(_, callee)| callee)
    }

    /// Every analyzed procedure this plan binds a call of `procedure` to
    /// (#2296).
    ///
    /// A bound call is the only kind that `execution_discovery_modeled` above
    /// accepts without a fully modeled dispatch boundary, so it is also the
    /// only kind whose callee can contribute reached rows to a complete run
    /// without appearing in this plan's own boundary coverage. A reusable
    /// summary provider uses this to check that its summary's validity
    /// contract names those callees, because they are exactly the procedures a
    /// replay skips whose analysis inputs the contract would otherwise not
    /// pin.
    pub(crate) fn bound_callees_of<'plan>(
        &'plan self,
        procedure: &'plan ProcedureHandle,
    ) -> impl Iterator<Item = &'plan ProcedureHandle> {
        self.binding_pairs
            .iter()
            .filter(move |(call, _)| call.procedure() == procedure)
            .map(|(_, callee)| callee)
    }

    pub(crate) fn carrier_summary_identities(
        &self,
    ) -> HashMap<ProcedureHandle, ValueFlowCarrierSummaryIdentity> {
        if self.has_contextual_bindings() {
            return HashMap::default();
        }
        #[derive(Default)]
        struct Builder {
            has_snapshot: bool,
            local_rules: Vec<ValueFlowLocalSummaryRule>,
            call_rules: Vec<ValueFlowCallSummaryRule>,
            curated_models: Vec<ValueFlowCuratedModelSummaryRule>,
            fallback_rules: Vec<ValueFlowFallbackSummaryRule>,
            location_bindings: Vec<ValueFlowLocationBindingSummaryRule>,
            conditional_sources: Vec<ValueFlowConditionalSourceSummaryRule>,
            edge_kills: Vec<ValueFlowEdgeKillSummaryRule>,
        }

        let mut builders = HashMap::<ProcedureHandle, Builder>::default();
        for procedure in self.summary_procedures() {
            builders.entry(procedure.clone()).or_default().has_snapshot |=
                self.has_snapshot(procedure);
        }
        for rule in &self.local_rules {
            builders
                .entry(rule.point.procedure().clone())
                .or_default()
                .local_rules
                .push(ValueFlowLocalSummaryRule {
                    point: rule.point.id(),
                    event_index: rule.event_index,
                    kind: rule.kind,
                    transfer: rule.transfer,
                    source: self.carrier_keys[rule.source.index()].clone(),
                    target: self.carrier_keys[rule.target.index()].clone(),
                    proof: rule.proof.clone(),
                    completeness: rule.completeness.clone(),
                    policy_local: rule.policy_local,
                    strong_update: rule.strong_update,
                    direct_cell_overwrite: rule.direct_cell_overwrite,
                });
        }
        for rule in &self.call_rules {
            builders
                .entry(rule.call.procedure().clone())
                .or_default()
                .call_rules
                .push(ValueFlowCallSummaryRule {
                    transfer: rule.transfer,
                    call: rule.call.id(),
                    callee_artifact: rule.callee.artifact().key().clone(),
                    callee_declaration: rule.callee.semantics().locator().declaration().clone(),
                    kind: rule.kind,
                    source: self.carrier_keys[rule.source.index()].clone(),
                    target: self.carrier_keys[rule.target.index()].clone(),
                    proof: rule.proof.clone(),
                    completeness: rule.completeness.clone(),
                });
        }
        for model in &self.curated_call_models {
            builders
                .entry(model.call.procedure().clone())
                .or_default()
                .curated_models
                .push(ValueFlowCuratedModelSummaryRule {
                    call: model.call.id(),
                    model: model.model.fingerprint(),
                });
        }
        let mut fallback_component_identities =
            HashMap::<(usize, ProcedureHandle), StableDigest>::default();
        for profile in &self.fallback_profiles {
            let procedure = profile.call.procedure();
            let mut reachable_components = profile
                .reachable_components
                .iter()
                .map(|component| {
                    *fallback_component_identities
                        .entry((*component, procedure.clone()))
                        .or_insert_with(|| {
                            fallback_component_fingerprint(
                                *component,
                                procedure.semantics().locator(),
                                &self.fallback_locations,
                                &self.carrier_keys,
                            )
                        })
                })
                .collect::<Vec<_>>();
            reachable_components.sort_unstable();
            reachable_components.dedup();
            builders
                .entry(profile.call.procedure().clone())
                .or_default()
                .fallback_rules
                .push(ValueFlowFallbackSummaryRule {
                    call: profile.call.id(),
                    inputs: profile
                        .inputs
                        .iter()
                        .map(|carrier| self.carrier_keys[carrier.index()].clone())
                        .collect(),
                    // Dense union-find roots are plan-local. Each digest names
                    // the exact stable location set the component exposes.
                    reachable_components: reachable_components.into_boxed_slice(),
                    normal_output: profile
                        .normal_output
                        .map(|carrier| self.carrier_keys[carrier.index()].clone()),
                    exceptional_output: profile
                        .exceptional_output
                        .map(|carrier| self.carrier_keys[carrier.index()].clone()),
                });
        }
        for binding in &self.summary_location_bindings {
            builders
                .entry(binding.call.procedure().clone())
                .or_default()
                .location_bindings
                .push(ValueFlowLocationBindingSummaryRule {
                    call: binding.call.id(),
                    port: binding.port.clone(),
                    carrier: binding
                        .carrier
                        .map(|carrier| self.carrier_keys[carrier.index()].clone()),
                });
        }
        for source in &self.sources {
            let Some(triggers) = source.spec.activation_triggers() else {
                continue;
            };
            builders
                .entry(source.spec.point().procedure().clone())
                .or_default()
                .conditional_sources
                .push(ValueFlowConditionalSourceSummaryRule {
                    point: source.spec.point().id(),
                    phase: source.spec.phase(),
                    key: source.spec.key().clone(),
                    carrier: self.carrier_keys[source.carrier.index()].clone(),
                    proof: source.spec.proof().clone(),
                    completeness: source.spec.completeness().clone(),
                    triggers: self
                        .source_list_keys(triggers)
                        .into_iter()
                        .cloned()
                        .collect(),
                });
        }
        for kill in &self.edge_kills {
            let carrier = self
                .carrier_ids
                .get(&kill.carrier)
                .copied()
                .expect("a validated edge-kill carrier is bound");
            builders
                .entry(kill.point.procedure().clone())
                .or_default()
                .edge_kills
                .push(ValueFlowEdgeKillSummaryRule {
                    point: kill.point.id(),
                    target: kill.target,
                    kind: kill.kind,
                    carrier: self.carrier_keys[carrier.index()].clone(),
                    labels: kill.labels.clone(),
                    sources: self
                        .source_list_keys(kill.sources)
                        .into_iter()
                        .cloned()
                        .collect(),
                });
        }
        builders
            .into_iter()
            .map(|(procedure, builder)| {
                let external_summaries = self.external_summary_fingerprints_for(&procedure);
                let fallback_globals = if builder.fallback_rules.is_empty() {
                    Box::default()
                } else {
                    self.fallback_locations
                        .bounded_globals
                        .iter()
                        .map(|carrier| self.carrier_keys[carrier.index()].clone())
                        .collect()
                };
                (
                    procedure,
                    ValueFlowCarrierSummaryIdentity {
                        unmodeled_call_behavior: self.unmodeled_call_behavior,
                        external_summaries,
                        fallback_globals,
                        has_snapshot: builder.has_snapshot,
                        local_rules: builder.local_rules.into_boxed_slice(),
                        call_rules: builder.call_rules.into_boxed_slice(),
                        curated_models: builder.curated_models.into_boxed_slice(),
                        fallback_rules: builder.fallback_rules.into_boxed_slice(),
                        location_bindings: builder.location_bindings.into_boxed_slice(),
                        conditional_sources: normalize_summary_conditional_sources(
                            builder.conditional_sources,
                        ),
                        edge_kills: normalize_summary_edge_kills(builder.edge_kills),
                    },
                )
            })
            .collect()
    }

    pub(crate) fn carrier_summary_identity_total_rows(&self) -> usize {
        self.local_rules
            .len()
            .saturating_add(self.call_rules.len())
            .saturating_add(self.curated_call_models.len())
            .saturating_add(self.summary_location_bindings.len())
            .saturating_add(
                self.sources
                    .iter()
                    .filter(|source| source.spec.activation_triggers().is_some())
                    .count(),
            )
            .saturating_add(self.edge_kills.len())
            .saturating_add(
                self.fallback_profiles
                    .iter()
                    .fold(0usize, |total, profile| {
                        total
                            .saturating_add(1)
                            .saturating_add(profile.inputs.len())
                            .saturating_add(profile.reachable_components.len())
                            .saturating_add(usize::from(profile.normal_output.is_some()))
                            .saturating_add(usize::from(profile.exceptional_output.is_some()))
                    }),
            )
            .saturating_add(self.fallback_component_identity_work_rows())
            .saturating_add(self.fallback_locations.bounded_globals.len())
    }

    fn fallback_component_identity_work_rows(&self) -> usize {
        self.fallback_component_identity_work_rows_for(self.fallback_profiles.iter().flat_map(
            |profile| {
                profile
                    .reachable_components
                    .iter()
                    .map(|component| (*component, profile.call.procedure().clone()))
            },
        ))
    }

    fn fallback_component_identity_work_rows_for(
        &self,
        components: impl IntoIterator<Item = (usize, ProcedureHandle)>,
    ) -> usize {
        let components = components.into_iter().collect::<HashSet<_>>();
        components
            .into_iter()
            .fold(0usize, |total, (component, _)| {
                total.saturating_add(1).saturating_add(
                    self.fallback_locations
                        .by_component
                        .get(&component)
                        .map_or(0, Vec::len),
                )
            })
    }

    #[cfg(test)]
    pub(crate) fn fallback_component_identity_rows_of(&self, procedure: &ProcedureHandle) -> usize {
        self.fallback_component_identity_work_rows_for(
            self.fallback_component_ordinals_for(procedure)
                .map(|component| (component, procedure.clone())),
        )
    }

    #[cfg(test)]
    pub(crate) fn fallback_reachable_location_count_of(
        &self,
        procedure: &ProcedureHandle,
    ) -> usize {
        let components = self
            .fallback_component_ordinals_for(procedure)
            .collect::<HashSet<_>>();
        components.into_iter().fold(0usize, |total, component| {
            total.saturating_add(
                self.fallback_locations
                    .by_component
                    .get(&component)
                    .map_or(0, Vec::len),
            )
        })
    }

    #[cfg(test)]
    pub(crate) fn fallback_component_ordinals_of(&self, procedure: &ProcedureHandle) -> Vec<usize> {
        self.fallback_component_ordinals_for(procedure).collect()
    }

    #[cfg(test)]
    fn fallback_component_ordinals_for<'a>(
        &'a self,
        procedure: &'a ProcedureHandle,
    ) -> impl Iterator<Item = usize> + 'a {
        self.fallback_profiles
            .iter()
            .filter(move |profile| profile.call.procedure() == procedure)
            .flat_map(|profile| profile.reachable_components.iter().copied())
    }

    fn external_summary_fingerprints_for(
        &self,
        procedure: &ProcedureHandle,
    ) -> Box<[ExternalSummarySetFingerprint]> {
        let mut fingerprints = Vec::new();
        for call in procedure.semantics().call_sites() {
            let targets: &[CallableTarget] = match &call.declared_targets {
                CallableTargetResolution::Proven(target) => std::slice::from_ref(target),
                CallableTargetResolution::Ambiguous(targets)
                | CallableTargetResolution::Unproven(targets)
                | CallableTargetResolution::ExceededBudget(targets) => targets,
                CallableTargetResolution::Unknown | CallableTargetResolution::Unsupported => {
                    return vec![self.external_summaries.fingerprint()].into_boxed_slice();
                }
            };
            fingerprints.extend(targets.iter().filter_map(|target| match target {
                CallableTarget::Local(_) => None,
                // An artifact descriptor has not selected an executable body
                // or a locator-keyed summary yet. Keep the whole summary set
                // in the validity key until demand materialization binds it.
                CallableTarget::Artifact(_) => Some(self.external_summaries.fingerprint()),
                CallableTarget::Unmaterialized(locator) | CallableTarget::External(locator) => {
                    self.external_summaries.fingerprint_for(locator)
                }
            }));
        }
        fingerprints.sort_unstable();
        fingerprints.dedup();
        fingerprints.into_boxed_slice()
    }

    pub(crate) fn is_call_input(&self, call: &CallSiteHandle, carrier: ValueFlowCarrierId) -> bool {
        let Some(profile) = self.fallback_profile(call) else {
            return false;
        };
        profile.inputs.binary_search(&carrier).is_ok()
            || self
                .fallback_locations
                .bounded_globals
                .binary_search(&carrier)
                .is_ok()
            || self
                .fallback_locations
                .location_components
                .get(&carrier)
                .is_some_and(|component| {
                    profile
                        .reachable_components
                        .binary_search(component)
                        .is_ok()
                })
    }

    /// The bound external summary that closes one dispatch boundary, with its
    /// actual-to-formal mapping.
    pub fn external_summary_for_boundary(
        &self,
        boundary: &DispatchBoundaryKind,
    ) -> Option<(&SemanticProcedureSummary, SummaryCallBinding<'_>)> {
        let target = boundary.target_locator()?;
        self.external_summaries
            .summary_for_boundary(boundary)
            .map(|(summary, mapping)| (summary, SummaryCallBinding::new(target, mapping)))
    }

    pub fn curated_model_for_call(&self, call: &CallSiteHandle) -> Option<&CuratedCallModel> {
        self.curated_call_models
            .binary_search_by(|candidate| compare_calls(&candidate.call, call))
            .ok()
            .map(|index| &self.curated_call_models[index].model)
    }

    fn summary_port_carrier(
        &self,
        call: &CallSiteHandle,
        port: &SummaryPort,
        actual_to_formal: SummaryCallBinding<'_>,
    ) -> Option<ValueFlowCarrierId> {
        if matches!(
            port,
            SummaryPort::Receiver | SummaryPort::Capture(_) | SummaryPort::Heap(_)
        ) {
            let binding = self
                .summary_location_bindings
                .binary_search_by(|binding| {
                    compare_calls(&binding.call, call).then_with(|| binding.port.cmp(port))
                })
                .ok()
                .map(|index| &self.summary_location_bindings[index]);
            if let Some(binding) = binding {
                return binding.carrier;
            }
            if !matches!(port, SummaryPort::Receiver) {
                return None;
            }
        }
        let value = self.summary_port_value(call, port, actual_to_formal)?;
        self.carrier_id(&ValueFlowCarrier::for_value(value))
    }

    /// The call's live value for one summary port, whether or not the plan
    /// retains a carrier for it. `None` means the port names no value at this
    /// call at all, so a model port that references it is genuinely unbound.
    fn summary_port_value(
        &self,
        call: &CallSiteHandle,
        port: &SummaryPort,
        actual_to_formal: SummaryCallBinding<'_>,
    ) -> Option<crate::analyzer::semantic::ValueHandle> {
        if matches!(port, SummaryPort::Receiver) && !self.receiver_storage_is_available(call) {
            return None;
        }
        call_port_value(
            call,
            port,
            actual_to_formal,
            self.is_resolved_external_constructor(call),
        )
    }

    /// Whether receiver-consuming models have a proven storage binding.
    /// A fresh-result model that never uses the receiver port needs no binding.
    pub fn receiver_storage_is_available(&self, call: &CallSiteHandle) -> bool {
        !self
            .summary_location_bindings
            .binary_search_by(|binding| {
                compare_calls(&binding.call, call)
                    .then_with(|| binding.port.cmp(&SummaryPort::Receiver))
            })
            .ok()
            .is_some_and(|index| self.summary_location_bindings[index].carrier.is_none())
    }

    fn is_resolved_external_call(&self, call: &CallSiteHandle) -> bool {
        self.resolved_external_calls
            .binary_search_by(|candidate| compare_calls(candidate, call))
            .is_ok()
    }

    fn is_resolved_external_constructor(&self, call: &CallSiteHandle) -> bool {
        self.is_resolved_external_call(call)
    }

    /// Whether a dispatch boundary of `call` closes with no authored summary:
    /// a resolved external constructor with a complete exact class identity
    /// but no applicable initializer summary is a resolved no-flow boundary.
    /// The ICFG's full-model check and the composition's covering check both
    /// read this rule.
    pub fn resolved_constructor_boundary(
        &self,
        call: &CallSiteHandle,
        kind: &DispatchBoundaryKind,
    ) -> bool {
        self.is_resolved_external_constructor(call) && closes_as_resolved_constructor(kind)
    }

    fn summary_input_binding(
        &self,
        call: &CallSiteHandle,
        port: &SummaryPort,
        actual_to_formal: SummaryCallBinding<'_>,
    ) -> SummaryInputBinding {
        if let Some(carrier) = self.summary_port_carrier(call, port, actual_to_formal) {
            return SummaryInputBinding::Carrier(carrier);
        }
        let Some(row) = call.procedure().semantics().call_site(call.id()) else {
            return SummaryInputBinding::Unbound;
        };
        if self.is_resolved_external_call(call)
            && let (SummaryPort::Parameter(formal), Some(mapping)) =
                (port, actual_to_formal.actual_to_formal)
            && actual_argument_index_for_formal(*formal, Some(mapping)).is_none()
        {
            return SummaryInputBinding::OmittedArgument;
        }
        let value_kind = match port {
            SummaryPort::Parameter(formal) => actual_to_formal
                .parameter_index(call, *formal)
                .and_then(|actual| row.arguments.get(actual))
                .and_then(|argument| call.procedure().semantics().value(argument.value))
                .map(|value| &value.kind),
            _ => None,
        };
        if carrierless_summary_input_is_vacuous(port, value_kind) {
            SummaryInputBinding::VacuousConstant
        } else if self
            .summary_port_value(call, port, actual_to_formal)
            .is_some()
        {
            SummaryInputBinding::CarrierlessValue
        } else {
            SummaryInputBinding::Unbound
        }
    }

    pub(crate) fn visit_boundary_transfers(
        &self,
        call: &CallSiteHandle,
        boundary: Option<&DispatchBoundaryKind>,
        kind: IcfgEdgeKind,
        input: ValueFlowCarrierId,
        mut visitor: impl FnMut(BoundBoundaryTransfer) -> bool,
    ) -> BoundaryTransferApplication {
        if let Some((summary, actual_to_formal)) =
            boundary.and_then(|boundary| self.external_summary_for_boundary(boundary))
        {
            return self.visit_modeled_transfers(
                call,
                kind,
                input,
                summary.transfers(),
                summary.effects(),
                actual_to_formal,
                summary.completeness().is_complete(),
                |mut transfer| {
                    transfer.authored_complete = matches!(
                        summary.key().identity().origin(),
                        SummaryOrigin::External(_)
                    ) && summary.completeness().is_complete()
                        && self.model_is_fully_bindable(
                            call,
                            summary.transfers(),
                            SummaryProofRequirement::AcceptAuthoredComplete,
                            actual_to_formal,
                        );
                    visitor(transfer)
                },
            );
        }
        if let Some(model) = self.curated_model_for_call(call) {
            return self.visit_modeled_transfers(
                call,
                kind,
                input,
                model.transfers(),
                model.effects(),
                SummaryCallBinding::default(),
                true,
                visitor,
            );
        }

        // A call this plan bound is modeled by its call/return rules; the
        // caller-side continuation edge preserves unrelated facts as identity
        // (#1952). Neither the paranoid fallback smear nor the require-model
        // abstention applies to it.
        if boundary.is_none() && self.has_binding_for_call(call) {
            return BoundaryTransferApplication {
                modeled: true,
                complete: true,
                abstained: false,
            };
        }
        let is_input = self.is_call_input(call, input);
        if self.unmodeled_call_behavior == UnmodeledCallBehavior::Paranoid && is_input {
            self.visit_fallback_outputs(call, kind, |target| {
                visitor(BoundBoundaryTransfer {
                    target,
                    proven_complete: false,
                    authored_complete: false,
                    removed_labels: Vec::new(),
                })
            });
        }
        BoundaryTransferApplication {
            modeled: false,
            complete: false,
            abstained: self.unmodeled_call_behavior == UnmodeledCallBehavior::RequireModel
                && is_input,
        }
    }

    /// Applies one call's modeled transfers to one already-active incoming
    /// fact (`input`), composing sibling transfers on the *same* call so a
    /// value one transfer just wrote to a port (typically `Receiver`) can
    /// feed a second transfer that reads that same port (#2567).
    ///
    /// Before this fix, the loop below tested every transfer's own `input`
    /// port against `input` only -- the one fact this invocation started
    /// with -- so a summary like `HashMap.put`'s, whose authored transfers
    /// deliberately chain through the receiver (`parameter[1] -> receiver`,
    /// then `receiver -> normal_return`, so "the value just written" can be
    /// read back through the method's own return value), never composed:
    /// the second transfer's `input` (`Receiver`) only ever matched a fact
    /// that already carried the receiver's value *before* the call, which a
    /// freshly constructed or freshly received map never does. A run could
    /// then reach `ProvenBySummary` (every transfer's ports structurally
    /// bind, which is all `model_is_fully_bindable`'s completion-time check
    /// asks) while silently dropping the one flow the fixture carries -- a
    /// false green in the sense the project's own no-false-greens property
    /// forbids.
    ///
    /// The fix below runs a small, local fixed point over `transfers`
    /// (bounded by `transfers.len()`, since every transfer fires at most
    /// once): `reached` starts containing only `input`, and a transfer fires
    /// once its own `input` port's live carrier appears in `reached`,
    /// whether that is because `input` itself is that carrier (an ordinary,
    /// direct one-hop transfer, unchanged from before this fix) or because
    /// an earlier-firing sibling transfer *on this same call* just wrote
    /// that carrier as its own output. This is deliberately scoped to one
    /// call's own transfer list -- it never reads or writes any state
    /// outside this one invocation, so it cannot compose a value across two
    /// different calls (that composition, when it happens at all, still
    /// only happens because two calls' `Receiver` ports resolve to the same
    /// underlying carrier, which is the ordinary cross-call value-flow
    /// carrier identity this function never touches).
    ///
    /// A transfer fires **at most once** per invocation (`fired`), which
    /// bounds every pass to firing at least one new transfer or terminating,
    /// so the loop always halts within `transfers.len()` passes even for a
    /// pathological cyclic or self-referencing (`receiver -> receiver`)
    /// summary -- it can never double-apply a transfer to its own output.
    ///
    /// Sanitize composition: `reached` also carries, for every carrier it
    /// contains, the union of every sanitize effect's removed labels along
    /// whichever path first reached that carrier (`sanitize_removed_labels`,
    /// #1923). A transfer that fires by composition (not directly against
    /// `input`) reports that accumulated union as its own `removed_labels`,
    /// not only its own effect. This is exactly equivalent to composing one
    /// `TaintEdgeFunction::kill` per hop: `kill(A)` composed with `kill(B)`
    /// is `kill(A ∪ B)`, because both are monotonic label removals over
    /// independent label dimensions, so the order they are removed in
    /// cannot matter (verified against `TaintEdgeFunction::compose`'s own
    /// definition in `taint/client.rs`). A sanitize declared on a *second*
    /// hop of a chain therefore still cuts labels a *first* hop let through,
    /// exactly as a single-hop sanitize already did.
    ///
    /// Scope note, checked against every sanitize effect shipped in this
    /// repository (`semantic-packs/sanitizers/**/*.json`): every one is a
    /// direct `parameter[n] -> normal_return` pair, never a self-loop
    /// (`port -> itself`) and never downstream of a port two or more
    /// transfers also write to. `reached` therefore records the *first*
    /// path that reaches a given carrier and does not update it if a later
    /// transfer reaches that same carrier by a different path with a
    /// different accumulated label set (which would matter only for a
    /// summary with divergent per-path sanitize outcomes converging on one
    /// port, or a self-loop transfer carrying its own sanitize -- neither
    /// occurs in any shipped content today). Deterministic either way
    /// (`transfers` is a stable slice, walked in the same index order every
    /// pass, with no unordered collection involved), but this is the one
    /// documented limitation of the composition below.
    #[allow(clippy::too_many_arguments)]
    fn visit_modeled_transfers<'a>(
        &'a self,
        call: &CallSiteHandle,
        kind: IcfgEdgeKind,
        input: ValueFlowCarrierId,
        transfers: &'a [SummaryTransfer],
        effects: &'a [SummaryEffect],
        actual_to_formal: SummaryCallBinding<'_>,
        mut complete: bool,
        mut visitor: impl FnMut(BoundBoundaryTransfer) -> bool,
    ) -> BoundaryTransferApplication {
        let exit = match kind {
            IcfgEdgeKind::CallToNormalContinuation => SummaryExitKind::Normal,
            IcfgEdgeKind::CallToExceptionalContinuation => SummaryExitKind::Exceptional,
            _ => {
                return BoundaryTransferApplication {
                    modeled: false,
                    complete: false,
                    abstained: false,
                };
            }
        };

        // Resolve every relevant transfer's static binding once, up front.
        // `summary_input_binding`/`summary_port_carrier` read only this call
        // site's own live value slots -- never which carrier this invocation
        // started from -- so nothing about the composition below changes
        // their answer. This also settles `complete` for every transfer
        // exactly once, unconditionally (matching the pre-fix behavior for
        // `VacuousConstant`/`Unbound`/an unbound output port), rather than
        // interleaving it with firing: `complete` is not read by any current
        // caller (only `.abstained` is), so decoupling it from the
        // composition loop below is a deliberate simplification, not a
        // behavior this function's callers depend on.
        let mut carrier_bound: Vec<(ValueFlowCarrierId, ValueFlowCarrierId, &'a SummaryTransfer)> =
            Vec::new();
        for transfer in transfers
            .iter()
            .filter(|transfer| transfer.exit().kind() == exit)
        {
            match self.summary_input_binding(call, transfer.input(), actual_to_formal) {
                SummaryInputBinding::Carrier(source) => {
                    match self.summary_port_carrier(call, transfer.exit().port(), actual_to_formal)
                    {
                        Some(target) => {
                            complete &= summary_evidence_is_proven_complete(transfer.evidence());
                            carrier_bound.push((source, target, transfer));
                        }
                        None => complete = false,
                    }
                }
                SummaryInputBinding::VacuousConstant | SummaryInputBinding::OmittedArgument => {
                    complete &= summary_evidence_is_proven_complete(transfer.evidence());
                }
                // A live value without a carrier cannot receive a fact through
                // this transfer either, so it is incomplete for this plan just
                // like a genuinely unbound port. `model_is_fully_bindable`
                // distinguishes the two; the solve only needs the shared
                // incomplete answer.
                SummaryInputBinding::CarrierlessValue | SummaryInputBinding::Unbound => {
                    complete = false
                }
            }
        }

        // The composition fixed point (see the doc comment above for the
        // full rationale). `reached` maps a carrier this call's own transfer
        // graph has made active, starting from `input`, to the accumulated
        // union of sanitize labels removed along the path that reached it.
        let mut reached: Vec<(ValueFlowCarrierId, Vec<Box<str>>)> = vec![(input, Vec::new())];
        let mut fired = vec![false; carrier_bound.len()];
        'compose: loop {
            let mut progressed = false;
            for (index, (source, target, transfer)) in carrier_bound.iter().enumerate() {
                if fired[index] {
                    continue;
                }
                let Some(prefix) = reached
                    .iter()
                    .find(|(carrier, _)| carrier == source)
                    .map(|(_, labels)| labels.clone())
                else {
                    continue;
                };
                fired[index] = true;
                progressed = true;
                let mut removed_labels = prefix;
                removed_labels.extend(
                    sanitize_removed_labels(effects, transfer.input(), transfer.exit().port())
                        .iter()
                        .cloned(),
                );
                if !reached.iter().any(|(carrier, _)| carrier == target) {
                    reached.push((*target, removed_labels.clone()));
                }
                let keep_going = visitor(BoundBoundaryTransfer {
                    target: *target,
                    proven_complete: summary_evidence_is_proven_complete(transfer.evidence()),
                    authored_complete: false,
                    removed_labels,
                });
                if !keep_going {
                    break 'compose;
                }
            }
            if !progressed {
                break;
            }
        }

        BoundaryTransferApplication {
            modeled: true,
            complete,
            abstained: false,
        }
    }

    fn visit_fallback_outputs(
        &self,
        call: &CallSiteHandle,
        kind: IcfgEdgeKind,
        mut visitor: impl FnMut(ValueFlowCarrierId) -> bool,
    ) {
        let Some(profile) = self.fallback_profile(call) else {
            return;
        };
        for target in self.fallback_locations.bounded_globals.iter().copied() {
            if !visitor(target) {
                return;
            }
        }
        for component in &profile.reachable_components {
            if let Some(targets) = self.fallback_locations.by_component.get(component) {
                for target in targets.iter().copied() {
                    if !visitor(target) {
                        return;
                    }
                }
            }
        }
        let result = match kind {
            IcfgEdgeKind::CallToNormalContinuation => profile.normal_output,
            IcfgEdgeKind::CallToExceptionalContinuation => profile.exceptional_output,
            _ => None,
        };
        if let Some(result) = result {
            let already_emitted = self
                .fallback_locations
                .bounded_globals
                .binary_search(&result)
                .is_ok()
                || profile.reachable_components.iter().any(|component| {
                    self.fallback_locations
                        .by_component
                        .get(component)
                        .is_some_and(|targets| targets.binary_search(&result).is_ok())
                });
            if !already_emitted {
                let _ = visitor(result);
            }
        }
    }

    fn fallback_profile(&self, call: &CallSiteHandle) -> Option<&CallFallbackProfile> {
        self.fallback_profiles
            .binary_search_by(|profile| compare_calls(&profile.call, call))
            .ok()
            .map(|index| &self.fallback_profiles[index])
    }

    pub(crate) fn is_callee_port(
        &self,
        carrier: ValueFlowCarrierId,
        callee: &ProcedureHandle,
    ) -> bool {
        matches!(self.carrier(carrier), Some(ValueFlowCarrier::Port(port)) if port.procedure() == callee)
    }

    /// Whether `carrier` is the callee-owned saved value for a default
    /// argument. A default value is evaluated at definition time and cannot
    /// be reconstructed as a caller-side preimage at a call edge. The flow
    /// clients consume its entry source directly when the binding selects it.
    pub(crate) fn is_default_argument_carrier(
        &self,
        carrier: ValueFlowCarrierId,
        callee: &ProcedureHandle,
    ) -> bool {
        let Some(ValueFlowCarrier::Value(value)) = self.carrier(carrier) else {
            return false;
        };
        value.procedure().durable_key() == callee.durable_key()
            && value
                .procedure()
                .semantics()
                .value(value.id())
                .is_some_and(|value| {
                    matches!(value.kind, SemanticValueKind::DefaultArgument { .. })
                })
    }

    pub fn source(&self, id: ValueFlowSourceId) -> Option<&ValueFlowSourceSpec> {
        self.sources.get(id.index()).map(|source| &source.spec)
    }

    pub fn sources(
        &self,
    ) -> impl ExactSizeIterator<Item = (ValueFlowSourceId, &ValueFlowSourceSpec)> {
        self.sources.iter().map(|source| (source.id, &source.spec))
    }

    pub fn sink(&self, id: ValueFlowSinkId) -> Option<&ValueFlowSinkSpec> {
        self.sinks.get(id.index()).map(|sink| &sink.spec)
    }

    pub fn sinks(&self) -> impl ExactSizeIterator<Item = (ValueFlowSinkId, &ValueFlowSinkSpec)> {
        self.sinks.iter().map(|sink| (sink.id, &sink.spec))
    }

    /// Conservative fan-out inputs for a bounded forward estimate.
    ///
    /// The estimate counts every retained local and call transfer relation,
    /// fallback profile, and bound source once.  It is intentionally a cheap
    /// upper-bound proxy; the snapshot reachability walk supplies the graph
    /// topology separately.
    pub(crate) fn forward_transfer_fanout_estimate(&self) -> usize {
        self.local_rules
            .len()
            .saturating_add(self.call_rules.len())
            .saturating_add(self.fallback_profiles.len())
            .saturating_add(self.sources.len())
    }

    /// Conservative fan-out inputs for a bounded backward estimate.
    ///
    /// Reverse transfer uses the same retained relations but starts from
    /// bound sinks, so sink bindings are counted independently of sources.
    pub(crate) fn backward_transfer_fanout_estimate(&self) -> usize {
        self.local_rules
            .len()
            .saturating_add(self.call_rules.len())
            .saturating_add(self.fallback_profiles.len())
            .saturating_add(self.sinks.len())
    }

    /// Whether a constant branch condition proves this point cannot execute.
    ///
    /// Gating the three point-keyed accessors below on this is what makes the
    /// exclusion total: no source produces at the point, no sink observes
    /// there, no local rule propagates through it, and both flow clients
    /// therefore lose the fact at the dead point rather than at some later
    /// place each would have to remember to check (#2443 slice 2).
    fn point_is_infeasible(&self, point: &ProgramPointHandle) -> bool {
        self.infeasible_points
            .iter()
            .find(|(procedure, _)| procedure == point.procedure())
            .is_some_and(|(_, points)| points.binary_search(&point.id()).is_ok())
    }

    pub(crate) fn local_rules_at(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = &LocalFlowRule> {
        let feasible = !self.point_is_infeasible(point);
        self.local_rule_point_index
            .by_point
            .get(point)
            .into_iter()
            .flatten()
            .filter(move |_| feasible)
            .map(move |index| &self.local_rules[*index])
    }

    pub(crate) fn source_list(&self, id: ValueFlowSourceListId) -> &[ValueFlowSourceId] {
        &self.source_lists[id.index()]
    }

    fn source_list_keys(&self, id: ValueFlowSourceListId) -> Vec<&ValueFlowEventKey> {
        let mut keys = self
            .source_list(id)
            .iter()
            .map(|id| self.sources[id.index()].spec.key())
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys
    }

    pub(crate) fn edge_kills(
        &self,
        point: &ProgramPointHandle,
        target: ProgramPointId,
        kind: ControlEdgeKind,
    ) -> &[BoundValueFlowEdgeKill] {
        self.edge_kill_index
            .by_edge
            .get(&EdgeKillKey {
                point: point.clone(),
                target,
                kind,
            })
            .map_or(&[], Box::as_ref)
    }

    pub(crate) fn edge_kill_label_sets(&self) -> impl Iterator<Item = &TaintClassSet> {
        self.edge_kills
            .iter()
            .filter_map(|kill| kill.labels.as_ref())
    }

    /// Whether the forward-only client is required because propagation
    /// depends on the incoming source identity. Conditional sources have the
    /// same restriction as source-selective edge kills: the backward client
    /// cannot reconstruct their activation from a demand alone.
    pub(crate) fn has_edge_kills(&self) -> bool {
        !self.edge_kills.is_empty()
            || self
                .sources
                .iter()
                .any(|source| source.spec.activation_triggers().is_some())
    }

    pub(crate) fn local_rule_views(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = LocalRuleView> {
        self.local_rules_at(point).map(local_rule_view)
    }

    /// Return every local rule at `point` in reverse event order. A backward
    /// client must use this when a rule's source becomes the demanded carrier,
    /// because the next preimage may be produced by a different target.
    pub(crate) fn local_rule_views_reverse_at(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = LocalRuleView> {
        let feasible = !self.point_is_infeasible(point);
        self.local_rule_point_index
            .by_point
            .get(point)
            .into_iter()
            .flatten()
            .rev()
            .filter(move |_| feasible)
            .map(move |index| local_rule_view(&self.local_rules[*index]))
    }

    pub(crate) fn has_policy_local_rule(
        &self,
        point: &ProgramPointHandle,
        source: ValueFlowCarrierId,
        target: ValueFlowCarrierId,
    ) -> bool {
        self.local_rules_at(point)
            .any(|rule| rule.policy_local && rule.source == source && rule.target == target)
    }

    pub(crate) fn has_contextual_bindings(&self) -> bool {
        self.contextual_bindings
    }

    pub(crate) fn call_rules_in_context<'a>(
        &'a self,
        call: &'a CallSiteHandle,
        callee: &'a ProcedureHandle,
        kind: CallFlowRuleKind,
        context: Option<&'a OracleCallContext>,
    ) -> impl Iterator<Item = &'a CallFlowRule> + 'a {
        let contextual = self.has_contextual_bindings();
        self.call_rules.iter().filter(move |rule| {
            &rule.call == call
                && &rule.callee == callee
                && rule.kind == kind
                && (!contextual || context == Some(&rule.context))
        })
    }

    pub(crate) fn call_targets_in_context<'a>(
        &'a self,
        call: &'a CallSiteHandle,
        callee: &'a ProcedureHandle,
        source: ValueFlowCarrierId,
        context: Option<&'a OracleCallContext>,
    ) -> impl Iterator<Item = (ValueFlowCarrierId, bool)> + 'a {
        self.call_rules_from_source_in_context(
            call,
            callee,
            CallFlowRuleKind::Call,
            source,
            context,
        )
        .map(rule_target)
    }

    pub(crate) fn normal_return_targets_in_context<'a>(
        &'a self,
        call: &'a CallSiteHandle,
        callee: &'a ProcedureHandle,
        source: ValueFlowCarrierId,
        context: Option<&'a OracleCallContext>,
    ) -> impl Iterator<Item = (ValueFlowCarrierId, bool)> + 'a {
        self.call_rules_from_source_in_context(
            call,
            callee,
            CallFlowRuleKind::NormalReturn,
            source,
            context,
        )
        .map(rule_target)
    }

    pub(crate) fn exceptional_return_targets_in_context<'a>(
        &'a self,
        call: &'a CallSiteHandle,
        callee: &'a ProcedureHandle,
        source: ValueFlowCarrierId,
        context: Option<&'a OracleCallContext>,
    ) -> impl Iterator<Item = (ValueFlowCarrierId, bool)> + 'a {
        self.call_rules_from_source_in_context(
            call,
            callee,
            CallFlowRuleKind::ExceptionalReturn,
            source,
            context,
        )
        .map(rule_target)
    }

    pub(crate) fn call_rules_from_source_in_context<'a>(
        &'a self,
        call: &'a CallSiteHandle,
        callee: &'a ProcedureHandle,
        kind: CallFlowRuleKind,
        source: ValueFlowCarrierId,
        context: Option<&'a OracleCallContext>,
    ) -> impl Iterator<Item = &'a CallFlowRule> + 'a {
        self.call_rules_in_context(call, callee, kind, context)
            .filter(move |rule| rule.source == source)
    }

    /// Return call-boundary rules whose target is `target`. Entries retain the
    /// canonical source order for one call, callee, and rule kind.
    pub(crate) fn call_rules_to_target<'a>(
        &'a self,
        call: &CallSiteHandle,
        callee: &ProcedureHandle,
        kind: CallFlowRuleKind,
        target: ValueFlowCarrierId,
    ) -> impl Iterator<Item = &'a CallFlowRule> + 'a {
        self.call_rules_to_target_in_context(call, callee, kind, target, None)
    }

    pub(crate) fn call_rules_to_target_in_context<'a>(
        &'a self,
        call: &CallSiteHandle,
        callee: &ProcedureHandle,
        kind: CallFlowRuleKind,
        target: ValueFlowCarrierId,
        context: Option<&'a OracleCallContext>,
    ) -> impl Iterator<Item = &'a CallFlowRule> + 'a {
        let contextual = self.has_contextual_bindings();
        let key = CallRuleTargetKey {
            call: call.clone(),
            callee: callee.clone(),
            kind,
            target,
        };
        self.call_rule_reverse_index
            .by_target
            .get(&key)
            .into_iter()
            .flatten()
            .map(move |index| &self.call_rules[*index])
            .filter(move |rule| !contextual || context == Some(&rule.context))
    }

    pub(crate) fn sources_at<'a>(
        &'a self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
    ) -> impl Iterator<Item = &'a BoundValueFlowSource> + 'a {
        let feasible = !self.point_is_infeasible(point);
        let key = ObservationKey {
            point: point.clone(),
            phase,
        };
        indexed_entries(
            &self.sources,
            self.source_index.by_point_phase.get(&key).map(Box::as_ref),
            feasible,
        )
    }

    pub(crate) fn source_bindings_at(
        &self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
    ) -> impl Iterator<Item = (ValueFlowSourceId, ValueFlowCarrierId)> {
        self.sources_at(point, phase)
            .map(|source| (source.id, source.carrier))
    }

    pub(crate) fn sinks_at<'a>(
        &'a self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
    ) -> impl Iterator<Item = &'a BoundValueFlowSink> + 'a {
        let feasible = !self.point_is_infeasible(point);
        let key = ObservationKey {
            point: point.clone(),
            phase,
        };
        indexed_entries(
            &self.sinks,
            self.sink_index.by_point_phase.get(&key).map(Box::as_ref),
            feasible,
        )
    }

    pub(crate) fn sink_bindings_at(
        &self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
    ) -> impl Iterator<Item = (ValueFlowSinkId, ValueFlowCarrierId)> {
        self.sinks_at(point, phase)
            .map(|sink| (sink.id, sink.carrier))
    }
}

/// The caller-side argument index a callee formal binds, through the summary's
/// actual-to-formal mapping when it has one.
pub fn actual_argument_index_for_formal(
    formal: u32,
    actual_to_formal: Option<&[u32]>,
) -> Option<usize> {
    match actual_to_formal {
        Some(mapping) => mapping
            .iter()
            .position(|mapped_formal| *mapped_formal == formal),
        None => usize::try_from(formal).ok(),
    }
}

fn carrierless_summary_input_is_vacuous(
    port: &SummaryPort,
    value_kind: Option<&SemanticValueKind>,
) -> bool {
    matches!(port, SummaryPort::Parameter(_))
        && matches!(value_kind, Some(SemanticValueKind::Constant))
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use crate::analyzer::semantic::{
        CancellationToken, OracleCallContext, SemanticBudget, SemanticRequest, ValueFlowOracle,
    };
    use crate::analyzer::{AnalyzerConfig, Language};
    use crate::value_flow::ValueFlowEventKind;

    use super::*;
    use crate::inline_project::InlineTestProject;

    #[derive(Default)]
    struct HashTrace(Vec<u8>);

    impl Hasher for HashTrace {
        fn finish(&self) -> u64 {
            0
        }

        fn write(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
    }

    fn propagation_hash_trace(plan: &ValueFlowPlan) -> Vec<u8> {
        let mut trace = HashTrace::default();
        plan.propagation_semantics_hash(&mut trace);
        trace.0
    }

    fn value_flow_plan_from_source(source: &str) -> ValueFlowPlan {
        let project = InlineTestProject::with_language(Language::Go)
            .file("flow.go", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("flow.go"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture semantics materialize")
            .available_value()
            .cloned()
            .expect("fixture semantics remain available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("run")
            })
            .expect("fixture declares run");
        let root = artifact
            .procedure_handle(procedure.id())
            .expect("fixture procedure remains live");

        let mut budget = SemanticBudget::default();
        let outcome = workspace
            .semantic_oracle_provider()
            .procedure_relations(
                &root,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture value-flow snapshot materializes");
        let status = SemanticInputStatus::from_outcome(&outcome);
        let snapshot = outcome
            .available_value()
            .cloned()
            .expect("fixture value-flow snapshot remains available");
        ValueFlowPlan::try_new(
            root,
            vec![ValueFlowInput::new(snapshot, status)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("fixture value-flow plan")
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3450: absent-member flow retained unrelated local transfers outside the sink slice"
    )]
    fn receiver_slice_drops_only_local_rules_that_cannot_reach_a_sink() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "flow.go",
                "package fixture\nfunc run(input string, other string) string {\n    observed := input\n    dead := other\n    _ = dead\n    return observed\n}\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("flow.go"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture semantics materialize")
            .available_value()
            .cloned()
            .expect("fixture semantics remain available");
        let root = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("run")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture declares run");
        let mut budget = SemanticBudget::default();
        let snapshot_outcome = workspace
            .semantic_oracle_provider()
            .procedure_relations(
                &root,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture value-flow snapshot materializes");
        let status = SemanticInputStatus::from_outcome(&snapshot_outcome);
        let snapshot = snapshot_outcome
            .available_value()
            .cloned()
            .expect("fixture value-flow snapshot remains available");
        let relations = snapshot.relations().to_vec();
        let observed = relations.last().expect("fixture retains a return relation");
        let sink_carrier = ValueFlowCarrier::from(&observed.target);
        let sink = ValueFlowSinkSpec::new(
            ValueFlowEventKey::at_point(observed.point(), 0, ValueFlowEventKind::Sink)
                .expect("fixture sink key is valid"),
            observed.point().clone(),
            ValueFlowObservationPhase::AfterEffects,
            sink_carrier,
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
        );
        let plan = ValueFlowPlan::try_new(
            root,
            vec![ValueFlowInput::new(snapshot, status)],
            Vec::new(),
            Vec::new(),
            vec![sink],
        )
        .expect("fixture value-flow plan");
        let before = plan.local_rules.len();
        let sliced = plan.retain_flows_reaching(std::iter::empty());

        assert!(
            sliced.local_rules.len() < before,
            "the dead assignment is sliced"
        );
        assert!(
            sliced
                .local_rules
                .iter()
                .any(|rule| rule.target == sliced.sinks[0].carrier),
            "the observed receiver chain remains"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3446: 9e032012f530: indexed forward and reverse rule views must match the filtered reference under root scoping"
    )]
    fn local_rule_point_index_matches_filtered_reference_and_preserves_order() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "flow.go",
                "package fixture\nfunc run(input string) string {\n    output := input\n    return output\n}\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("flow.go"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture semantics materialize")
            .available_value()
            .cloned()
            .expect("fixture semantics remain available");
        let root = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("run")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture declares run");
        let mut budget = SemanticBudget::default();
        let snapshot_outcome = workspace
            .semantic_oracle_provider()
            .procedure_relations(
                &root,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture value-flow snapshot materializes");
        let status = SemanticInputStatus::from_outcome(&snapshot_outcome);
        let snapshot = snapshot_outcome
            .available_value()
            .cloned()
            .expect("fixture value-flow snapshot remains available");
        let mut plan = ValueFlowPlan::try_new(
            root.clone(),
            vec![ValueFlowInput::new(snapshot, status)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("fixture value-flow plan");

        let mut points = Vec::new();
        for rule in &plan.local_rules {
            if !points.contains(&rule.point) {
                points.push(rule.point.clone());
            }
        }
        assert!(points.len() >= 2, "fixture has rules at multiple points");

        let mut rules = plan.local_rules.to_vec();
        for (ordinal, rule) in rules.iter_mut().enumerate() {
            rule.point = points[ordinal % points.len()].clone();
            rule.event_index = u32::try_from(ordinal / points.len())
                .expect("fixture relation count fits an event index");
        }
        rules.sort_by(compare_local_rules);
        plan.local_rules = rules.into_boxed_slice();
        plan.local_rule_point_index = build_local_rule_point_index(&plan.local_rules);

        let expected_by_point = points
            .iter()
            .map(|point| {
                let expected_rules = plan
                    .local_rules
                    .iter()
                    .filter(|rule| &rule.point == point)
                    .cloned()
                    .collect::<Vec<_>>();
                let expected_views = expected_rules
                    .iter()
                    .map(|rule| LocalRuleView {
                        event_index: rule.event_index,
                        source: rule.source,
                        target: rule.target,
                        kind: rule.kind,
                        transfer: rule.transfer,
                        complete: matches!(rule.proof, ProofStatus::Proven)
                            && matches!(rule.completeness, EvidenceCompleteness::Complete),
                        policy_local: rule.policy_local,
                        strong_update: rule.strong_update,
                        direct_cell_overwrite: rule.direct_cell_overwrite,
                    })
                    .collect::<Vec<_>>();
                (point.clone(), expected_rules, expected_views)
            })
            .collect::<Vec<_>>();

        for (point, expected_rules, expected_views) in &expected_by_point {
            let expected = plan
                .local_rules
                .iter()
                .enumerate()
                .filter(|(_, rule)| &rule.point == point)
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            let indexed = plan
                .local_rule_point_index
                .by_point
                .get(point)
                .map(|positions| positions.as_ref())
                .unwrap_or_default();
            assert_eq!(indexed, expected.as_slice(), "index positions differ");

            let forward_rules = plan.local_rules_at(point).cloned().collect::<Vec<_>>();
            assert_eq!(forward_rules, *expected_rules, "forward rules differ");

            let mut reverse_views = expected_views.clone();
            reverse_views.reverse();
            assert_eq!(
                plan.local_rule_views(point).collect::<Vec<_>>(),
                *expected_views,
                "forward views differ"
            );
            assert_eq!(
                plan.local_rule_views_reverse_at(point).collect::<Vec<_>>(),
                reverse_views,
                "reverse views differ"
            );
        }

        plan.infeasible_points =
            Box::new([(root.clone(), vec![points[1].id()].into_boxed_slice())]);
        assert_eq!(
            plan.local_rule_views(&points[0]).collect::<Vec<_>>(),
            expected_by_point[0].2
        );
        assert!(
            plan.local_rule_views(&points[1]).next().is_none(),
            "infeasible point suppresses forward rules"
        );
        assert_eq!(
            plan.local_rule_views_reverse_at(&points[0])
                .collect::<Vec<_>>(),
            expected_by_point[0]
                .2
                .iter()
                .copied()
                .rev()
                .collect::<Vec<_>>()
        );
        assert!(
            plan.local_rule_views_reverse_at(&points[1])
                .next()
                .is_none(),
            "infeasible point suppresses reverse rules"
        );

        plan.local_rules = Box::default();
        plan.local_rule_point_index = build_local_rule_point_index(&plan.local_rules);
        assert!(
            plan.local_rule_views(&points[0]).next().is_none(),
            "empty local-rule array yields no forward rules"
        );
        assert!(
            plan.local_rule_views_reverse_at(&points[0])
                .next()
                .is_none(),
            "empty local-rule array yields no reverse rules"
        );
    }

    #[test]
    fn caller_origin_indexes_preserve_formal_identity_across_snapshots() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "flow.go",
                "package fixture\nfunc first(input []string) []string { alias := input; return alias }\nfunc second(input []string) []string { alias := input; return alias }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("flow.go"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture semantics materialize")
            .available_value()
            .cloned()
            .expect("fixture artifact");
        let snapshots = ["first", "second"].map(|name| {
            let procedure = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .expect("fixture procedure");
            let mut budget = SemanticBudget::default();
            workspace
                .semantic_oracle_provider()
                .procedure_relations(
                    &procedure,
                    &OracleCallContext::empty(),
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("fixture relations")
                .available_value()
                .cloned()
                .expect("snapshot")
        });
        let actuals = snapshots.each_ref().map(|snapshot| {
            snapshot
                .relations()
                .iter()
                .find_map(|relation| {
                    if relation.kind == ValueFlowRelationKind::NormalReturn
                        && let ValueFlowEndpoint::Value(value) = &relation.source
                    {
                        Some(value.clone())
                    } else {
                        None
                    }
                })
                .expect("returned alias")
        });
        assert_eq!(actuals[0].id(), actuals[1].id(), "same local numbering");
        let limits = call_location_oracle_limits(8);
        let mut indexes = CallerOriginIndexes::default();
        let limited = caller_storage_origins(
            &CallArgumentEndpoint::Value(actuals[0].clone()),
            Some(&snapshots[0]),
            0,
            limits,
            &mut indexes,
        );
        assert!(limited.incomplete);
        assert!(limited.origins.is_empty());
        for ordinal in [0, 1, 0, 1] {
            let snapshot = &snapshots[ordinal];
            let search = caller_storage_origins(
                &CallArgumentEndpoint::Value(actuals[ordinal].clone()),
                Some(snapshot),
                8,
                limits,
                &mut indexes,
            );
            assert!(!search.incomplete);
            assert_eq!(search.origins.len(), 1);
            let expected = crate::analyzer::semantic::ProcedurePortHandle::parameter(
                snapshot.procedure().clone(),
                0,
            )
            .expect("input formal");
            assert_eq!(
                search.origins[0].location.path().root(),
                &AccessPathRoot::ProcedurePort(expected)
            );
            assert_eq!(search.origins[0].proof, ProofStatus::Proven);
            assert_eq!(
                search.origins[0].completeness,
                EvidenceCompleteness::Complete
            );
        }
        let foreign = caller_storage_origins(
            &CallArgumentEndpoint::Value(actuals[1].clone()),
            Some(&snapshots[0]),
            8,
            limits,
            &mut indexes,
        );
        assert!(foreign.incomplete);
        assert!(foreign.origins.is_empty());
        assert_eq!(indexes.entries.len(), 2, "one index per exact snapshot");
    }

    #[test]
    fn call_rule_quality_includes_dispatch_candidate_quality() {
        let candidate_proof = ProofStatus::Unproven("multi-class dispatch".into());
        let candidate_completeness =
            EvidenceCompleteness::Partial("receiver set is incomplete".into());

        assert_eq!(
            merge_call_rule_proof(&candidate_proof, ProofStatus::Proven),
            candidate_proof
        );
        assert_eq!(
            merge_call_rule_completeness(&candidate_completeness, EvidenceCompleteness::Complete,),
            candidate_completeness
        );
    }

    #[test]
    fn summary_parameter_ports_invert_the_proven_actual_to_formal_mapping() {
        let reordered = [1, 0];
        let identity = [0, 1];
        assert_eq!(
            actual_argument_index_for_formal(0, Some(&reordered)),
            Some(1)
        );
        assert_eq!(
            actual_argument_index_for_formal(1, Some(&reordered)),
            Some(0)
        );
        let three_way = [2, 0, 1];
        assert_eq!(
            actual_argument_index_for_formal(0, Some(&three_way)),
            Some(1)
        );
        assert_eq!(
            actual_argument_index_for_formal(1, Some(&three_way)),
            Some(2)
        );
        assert_eq!(
            actual_argument_index_for_formal(2, Some(&three_way)),
            Some(0)
        );
        assert_eq!(
            actual_argument_index_for_formal(0, Some(&identity)),
            Some(0)
        );
        assert_eq!(
            actual_argument_index_for_formal(1, Some(&identity)),
            Some(1)
        );
        assert_eq!(actual_argument_index_for_formal(0, None), Some(0));
        assert_eq!(actual_argument_index_for_formal(2, Some(&reordered)), None);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2455: The issue #2455 relaxation applies only to a constant parameter; a local, receiver, or unknown value kind must remain non-vacuous."
    )]
    fn only_carrierless_constant_parameters_are_vacuous_summary_inputs() {
        assert!(carrierless_summary_input_is_vacuous(
            &SummaryPort::Parameter(0),
            Some(&SemanticValueKind::Constant),
        ));
        assert!(!carrierless_summary_input_is_vacuous(
            &SummaryPort::Parameter(0),
            Some(&SemanticValueKind::Local),
        ));
        assert!(!carrierless_summary_input_is_vacuous(
            &SummaryPort::Receiver,
            Some(&SemanticValueKind::Constant),
        ));
        assert!(!carrierless_summary_input_is_vacuous(
            &SummaryPort::Parameter(0),
            None,
        ));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4295: resolved external call coverage was omitted from propagation identity"
    )]
    fn resolved_external_call_set_has_order_independent_propagation_identity() {
        let plan = value_flow_plan_from_source(
            "package fixture\nfunc first() {}\nfunc second() {}\nfunc run() { first(); second() }\n",
        );
        let calls = plan
            .root()
            .semantics()
            .call_sites()
            .iter()
            .map(|call| plan.root().call_site_handle(call.id).expect("live call"))
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 2);
        let build = |resolved| {
            ValueFlowPlan::with_call_behavior_and_edge_kills_and_resolved_external_calls(
                plan.root().clone(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                UnmodeledCallBehavior::default(),
                resolved,
            )
            .expect("valid exact-call set")
        };
        let first = build(vec![calls[0].clone()]);
        let second = build(vec![calls[1].clone()]);
        let both = build(calls.clone());
        let reordered = build(vec![calls[1].clone(), calls[0].clone(), calls[1].clone()]);
        assert!(both.has_same_propagation_semantics(&reordered));
        assert_eq!(
            propagation_hash_trace(&both),
            propagation_hash_trace(&reordered)
        );
        assert!(!first.has_same_propagation_semantics(&second));
        assert!(matches!(
            ValueFlowPlan::union_observations(&[&first, &second]),
            Err(ValueFlowPlanError::IncompatibleObservationUnion)
        ));
        assert_ne!(
            propagation_hash_trace(&first),
            propagation_hash_trace(&second)
        );
        assert_ne!(
            propagation_hash_trace(&first),
            propagation_hash_trace(&both)
        );
    }

    #[test]
    fn strong_update_changes_propagation_compatibility_hash() {
        let plan = value_flow_plan_from_source(
            r#"
package fixture

type box struct {
    value string
}

func run(input string) string {
    holder := &box{}
    holder.value = input
    return holder.value
}
"#,
        );
        let store = plan
            .local_rules
            .iter()
            .position(|rule| rule.kind == ValueFlowRelationKind::MemoryStore)
            .expect("fixture publishes a memory-store rule");

        let mut changed = plan.clone();
        changed.local_rules[store].strong_update = !changed.local_rules[store].strong_update;

        assert!(
            !plan.has_same_propagation_semantics(&changed),
            "strong-update eligibility changes exact propagation semantics"
        );
        assert_ne!(
            propagation_hash_trace(&plan),
            propagation_hash_trace(&changed),
            "the compatibility hash must partition every distinction enforced by exact compatibility"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2873: snapshot incompleteness reported a later non-blocking cause"
    )]
    fn first_incomplete_cause_retains_the_blocking_semantic_gap() {
        const SOURCE: &str = r#"package fixture

import external "example.com/external"

type branch struct { leaf external.Leaf }

func run(input string) string {
    holder := branch{}
    holder.leaf.Value = input
    return holder.leaf.Value
}
"#;

        let project = InlineTestProject::with_language(Language::Go)
            .file("flow.go", SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("flow.go"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture semantics materialize")
            .available_value()
            .cloned()
            .expect("fixture semantics remain available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("run")
            })
            .expect("fixture declares run");
        let root = artifact
            .procedure_handle(procedure.id())
            .expect("fixture procedure remains live");
        let mut budget = SemanticBudget::default();
        let snapshot_outcome = workspace
            .semantic_oracle_provider()
            .procedure_relations(
                &root,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture value-flow snapshot materializes");
        let status = SemanticInputStatus::from_outcome(&snapshot_outcome);
        let snapshot = snapshot_outcome
            .available_value()
            .cloned()
            .expect("fixture value-flow snapshot remains available");
        let plan = ValueFlowPlan::try_new(
            root,
            vec![ValueFlowInput::new(snapshot, status)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("fixture value-flow plan");

        assert!(
            matches!(
                plan.first_incomplete_cause(),
                Some(ValueFlowIncompleteCause::SemanticGap {
                    capability: SemanticCapability::FieldMemory,
                    status: SemanticInputStatus::Unknown,
                    ..
                })
            ),
            "the generic plan must retain the exact structured blocker: {:?}",
            plan.first_incomplete_cause()
        );
        assert_eq!(
            plan.first_incomplete_cause()
                .expect("incomplete fixture has a cause")
                .label(),
            "access-path resolution"
        );
    }

    #[test]
    fn transfer_metadata_changes_propagation_compatibility_hash() {
        use crate::analyzer::semantic::{
            TransferKind, TransferOperation, ValuePreservation, ValueTransfer,
        };

        let mut plan = value_flow_plan_from_source(
            r#"package fixture
func run() [1]int {
    first := [1]int{}
    second := first
    return second
}
"#,
        );
        let transfer = plan
            .local_rules
            .iter()
            .position(|rule| rule.transfer.is_some())
            .expect("array copy publishes transfer metadata");
        let mut changed = plan.clone();
        changed.local_rules[transfer].transfer = Some(ValueTransfer {
            kind: TransferKind::Conversion {
                preservation: ValuePreservation::Changing,
            },
            operation: TransferOperation::None,
        });

        assert!(!plan.has_same_propagation_semantics(&changed));
        assert_ne!(
            propagation_hash_trace(&plan),
            propagation_hash_trace(&changed)
        );
        plan.local_rules[transfer].transfer = changed.local_rules[transfer].transfer;
        assert!(plan.has_same_propagation_semantics(&changed));
    }
}

fn rule_target(rule: &CallFlowRule) -> (ValueFlowCarrierId, bool) {
    (
        rule.target,
        matches!(rule.proof, ProofStatus::Proven)
            && matches!(rule.completeness, EvidenceCompleteness::Complete),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueFlowPlanError {
    InvalidLimits,
    LimitExceeded,
    ForeignWorkspace,
    InvalidEventCarrier,
    ContextSensitiveInputUnsupported,
    InvalidCallArgumentLocation,
    DuplicateEventKey,
    DuplicateLocalRule,
    InvalidEdgeKill,
    InvalidSourceActivation,
    DuplicateCallModel,
    StaleCallModel,
    StaleExternalCallResolution,
    StaleReturnedCallable,
    InvalidSummaryLocationPort,
    DuplicateSummaryLocationBinding,
    IncompatibleExternalSummary,
    IncompatibleObservationUnion,
    StableCarrierCollision,
    CarrierIdOverflow,
    SourceIdOverflow,
    SinkIdOverflow,
    MissingCarrier,
    Model(ValueFlowModelError),
}

impl fmt::Display for ValueFlowPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("invalid value-flow plan limits"),
            Self::LimitExceeded => formatter.write_str("value-flow plan limit exceeded"),
            Self::ForeignWorkspace => {
                formatter.write_str("value-flow input belongs to another workspace mount")
            }
            Self::InvalidEventCarrier => {
                formatter.write_str("value-flow event carrier belongs to another procedure")
            }
            Self::ContextSensitiveInputUnsupported => formatter.write_str(
                "context-sensitive oracle input cannot be flattened into a value-flow plan",
            ),
            Self::InvalidCallArgumentLocation => {
                formatter.write_str("call argument contains an invalid abstract location")
            }
            Self::DuplicateEventKey => formatter.write_str("duplicate value-flow event key"),
            Self::DuplicateLocalRule => {
                formatter.write_str("duplicate policy-local value-flow rule")
            }
            Self::InvalidEdgeKill => {
                formatter.write_str("value-flow edge kill names an absent edge, source, or carrier")
            }
            Self::InvalidSourceActivation => formatter
                .write_str("value-flow source activation names an empty or absent trigger source"),
            Self::DuplicateCallModel => {
                formatter.write_str("multiple curated call models target the same call site")
            }
            Self::StaleCallModel => formatter.write_str("curated call model targets a stale call"),
            Self::StaleExternalCallResolution => {
                formatter.write_str("resolved external call targets a stale call")
            }
            Self::StaleReturnedCallable => {
                formatter.write_str("returned callable provenance names a stale producing call")
            }
            Self::InvalidSummaryLocationPort => {
                formatter.write_str("summary location binding requires a heap or capture port")
            }
            Self::DuplicateSummaryLocationBinding => formatter
                .write_str("multiple summary location bindings target the same call and port"),
            Self::IncompatibleExternalSummary => formatter
                .write_str("external summaries are incompatible with the active analysis contract"),
            Self::IncompatibleObservationUnion => {
                formatter.write_str("value-flow observations have different propagation semantics")
            }
            Self::StableCarrierCollision => {
                formatter.write_str("distinct value-flow carriers share one stable key")
            }
            Self::CarrierIdOverflow => formatter.write_str("value-flow carrier ID overflow"),
            Self::SourceIdOverflow => formatter.write_str("value-flow source ID overflow"),
            Self::SinkIdOverflow => formatter.write_str("value-flow sink ID overflow"),
            Self::MissingCarrier => formatter.write_str("value-flow plan carrier is missing"),
            Self::Model(error) => error.fmt(formatter),
        }
    }
}

impl Error for ValueFlowPlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Model(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ValueFlowModelError> for ValueFlowPlanError {
    fn from(error: ValueFlowModelError) -> Self {
        Self::Model(error)
    }
}

/// Whether a dispatch boundary of a resolved external constructor call closes
/// with no authored summary: the boundary names an exact external class
/// identity. [`ValueFlowPlan::resolved_constructor_boundary`] and the taint
/// composition's per-call answer both read this rule.
pub fn closes_as_resolved_constructor(kind: &DispatchBoundaryKind) -> bool {
    matches!(
        kind,
        DispatchBoundaryKind::External(Some(_)) | DispatchBoundaryKind::Unmaterialized(_)
    )
}

/// The call's live value for one summary port. `None` means the port names no
/// value at this call at all. A receiver port of a resolved external
/// constructor, which has no receiver, is the constructed result.
fn call_port_value(
    call: &CallSiteHandle,
    port: &SummaryPort,
    actual_to_formal: SummaryCallBinding<'_>,
    resolved_external_constructor: bool,
) -> Option<crate::analyzer::semantic::ValueHandle> {
    let row = call.procedure().semantics().call_site(call.id())?;
    let value = match port {
        SummaryPort::Receiver => match actual_to_formal.receiver_value(call).or(row.receiver) {
            Some(receiver) => receiver,
            None if resolved_external_constructor => row.result?,
            None => return None,
        },
        SummaryPort::Parameter(formal) => {
            row.arguments
                .get(actual_to_formal.parameter_index(call, *formal)?)?
                .value
        }
        SummaryPort::NormalReturn => row.result?,
        SummaryPort::IndexedNormalReturn(index) => row.normal_result(*index as usize)?,
        SummaryPort::ExceptionalReturn => row.thrown?,
        SummaryPort::Capture(_) | SummaryPort::Heap(_) => return None,
    };
    call.procedure().value_handle(value)
}

/// The closure an authored-complete external summary gives the dispatch arm
/// of `call` that names `target`, under the guards both engines apply
/// ([`ValueFlowPlan::authored_arm_closures`] explains them): the summary is
/// authored and complete, a receiver-bearing target carries a
/// `covers_overrides` claim unless `exact_external_receiver` proves the
/// receiver class, and `bindable` accepts its transfers at the call. The
/// caller checks the call context and that the call has no analyzed callee.
fn authored_summary_closure(
    call: &CallSiteHandle,
    context: &OracleCallContext,
    target: &SemanticLocator,
    summaries: &ExternalSemanticSummarySet,
    exact_external_receiver: bool,
    bindable: impl FnOnce(&[SummaryTransfer], SummaryCallBinding<'_>) -> bool,
) -> Option<AuthoredArmClosure> {
    let (summary, actual_to_formal) = summaries.summary_and_actual_to_formal_for(target)?;
    let SummaryOrigin::External(origin) = summary.key().identity().origin() else {
        // An inferred summary is derived from a body Bifrost read, so it is
        // not an authored claim and has no authored identity to record.
        return None;
    };
    // #2371: receiver-bearing calls need an explicit claim about every
    // implementation. A receiverless target has no implementations selected
    // by override dispatch, so its complete summary already describes the
    // entire target set. An exact Python receiver proof names the class
    // whose C3 lookup selected this declaration and ruled out workspace
    // replacement, so it closes the receiver override set for this call.
    let target_has_receiver = target
        .declaration()
        .segments()
        .last()
        .is_some_and(|segment| segment.kind() == DeclarationSegmentKind::Method);
    if (target_has_receiver && !origin.covers_overrides() && !exact_external_receiver)
        || !summary.completeness().is_complete()
        || !bindable(
            summary.transfers(),
            SummaryCallBinding::new(target, actual_to_formal),
        )
    {
        return None;
    }
    Some(AuthoredArmClosure {
        call: call.clone(),
        context: context.clone(),
        target: target.clone(),
        origin: origin.clone(),
    })
}

/// The authored-complete external summaries that close one call's dispatch
/// boundaries, for an engine that solves no result and holds no region plan:
/// the taint composition, which answers models per call. `kinds` are the
/// boundary kinds of the call's own dispatch, `summaries` the summaries bound
/// for the targets they name, and `resolved_external` whether the call is an
/// exact resolved external call. These are the closures
/// [`ValueFlowPlan::authored_arm_closures`] records for the same call in the
/// empty context: a named target is closed by its own summary, and a
/// residual `Unresolved` arm by the summary of a sibling named target. The
/// caller asks only for a call with no analyzed callee.
///
/// The composition carries every value of the call as a port, so a transfer
/// binds when its input is a vacuous constant, an omitted argument of a
/// resolved external call, or a value whose output port names a value too,
/// as a plan binds an input it holds a carrier for.
pub fn authored_call_closures(
    call: &CallSiteHandle,
    kinds: &[&DispatchBoundaryKind],
    summaries: &ExternalSemanticSummarySet,
    resolved_external: bool,
) -> Vec<AuthoredArmClosure> {
    let context = OracleCallContext::empty();
    let bindable = |transfers: &[SummaryTransfer], actual_to_formal: SummaryCallBinding<'_>| {
        let Some(row) = call.procedure().semantics().call_site(call.id()) else {
            return false;
        };
        transfers.iter().all(|transfer| {
            let input = transfer.input();
            let value_kind = match input {
                SummaryPort::Parameter(formal) => actual_to_formal
                    .parameter_index(call, *formal)
                    .and_then(|actual| row.arguments.get(actual))
                    .and_then(|argument| call.procedure().semantics().value(argument.value))
                    .map(|value| &value.kind),
                _ => None,
            };
            let omitted = resolved_external
                && actual_to_formal.actual_to_formal.is_some()
                && matches!(input, SummaryPort::Parameter(formal)
                    if actual_to_formal.parameter_index(call, *formal).is_none());
            let bound = omitted
                || carrierless_summary_input_is_vacuous(input, value_kind)
                || (call_port_value(call, input, actual_to_formal, resolved_external).is_some()
                    && call_port_value(
                        call,
                        transfer.exit().port(),
                        actual_to_formal,
                        resolved_external,
                    )
                    .is_some());
            transfer.evidence().is_complete() && bound
        })
    };
    let sibling = kinds
        .iter()
        .find_map(|kind| ValueFlowPlan::authored_dispatch_target(kind));
    let mut closures = Vec::new();
    for kind in kinds {
        let target = if matches!(kind, DispatchBoundaryKind::Unresolved) {
            sibling
        } else {
            ValueFlowPlan::authored_dispatch_target(kind)
        };
        if let Some(closure) = target.and_then(|target| {
            authored_summary_closure(
                call,
                &context,
                target,
                summaries,
                resolved_external,
                bindable,
            )
        }) && !closures.contains(&closure)
        {
            closures.push(closure);
        }
    }
    closures
}

fn validate_mount(
    procedure: &ProcedureHandle,
    mount: crate::analyzer::semantic::WorkspaceMountId,
) -> Result<(), ValueFlowPlanError> {
    if procedure.artifact().key().mount() == mount {
        Ok(())
    } else {
        Err(ValueFlowPlanError::ForeignWorkspace)
    }
}

fn validate_event(
    point: &ProgramPointHandle,
    carrier: &ValueFlowCarrier,
    mount: crate::analyzer::semantic::WorkspaceMountId,
) -> Result<(), ValueFlowPlanError> {
    validate_mount(point.procedure(), mount)?;
    if carrier
        .procedure()
        .is_some_and(|procedure| procedure != point.procedure())
    {
        return Err(ValueFlowPlanError::InvalidEventCarrier);
    }
    Ok(())
}

/// One dense carrier per stable key, plus the reverse map from every handle
/// that named it.
struct CarrierIndex {
    carriers: Vec<ValueFlowCarrier>,
    carrier_keys: Vec<ValueFlowCarrierKey>,
    carrier_ids: HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
}

/// Give every named carrier one dense ID, keyed by its stable identity.
///
/// The stable key is the plan's carrier identity: `carrier_keys` is the sorted
/// domain `carrier_id_for_key` searches, and it is what
/// `propagation_semantics_hash` hashes. Handle equality is finer than that,
/// because a `ProcedureHandle` compares its owning `Arc<SemanticArtifact>` by
/// pointer. A caller that walks an interprocedural closure can therefore
/// present one procedure twice: the byte-bounded artifact cache may evict an
/// artifact that a later call resolution re-materializes, and both handles then
/// reach the plan. Those candidates name one entity, so they share one dense
/// ID, and `carrier_ids` retains every handle that named it so a client holding
/// either materialization still resolves it.
///
/// Two candidates that share a key but do not name one entity are a real
/// identity failure: `stable_key` lost a distinction the plan cannot recover,
/// and merging them would silently join two entities' flows. The plan refuses
/// that input instead.
fn assign_carrier_ids(
    candidates: Vec<ValueFlowCarrier>,
    max_carriers: usize,
) -> Result<CarrierIndex, ValueFlowPlanError> {
    let mut keyed = candidates
        .into_iter()
        .map(|carrier| Ok((carrier.stable_key()?, carrier)))
        .collect::<Result<Vec<_>, ValueFlowPlanError>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));

    let mut groups = Vec::new();
    let mut start = 0usize;
    while start < keyed.len() {
        let end = start + keyed[start..].partition_point(|entry| entry.0 == keyed[start].0);
        groups.push((start, end));
        start = end;
    }
    if groups.len() > max_carriers {
        return Err(ValueFlowPlanError::LimitExceeded);
    }

    let mut index = CarrierIndex {
        carriers: Vec::with_capacity(groups.len()),
        carrier_keys: Vec::with_capacity(groups.len()),
        carrier_ids: HashMap::default(),
    };
    for (ordinal, (start, end)) in groups.into_iter().enumerate() {
        let (key, representative) = &keyed[start];
        if keyed[start + 1..end]
            .iter()
            .any(|(_, carrier)| !carrier.denotes_same_entity(representative))
        {
            return Err(ValueFlowPlanError::StableCarrierCollision);
        }
        let id = ValueFlowCarrierId::try_from_index(ordinal)
            .map_err(|_| ValueFlowPlanError::CarrierIdOverflow)?;
        for (_, carrier) in &keyed[start..end] {
            index.carrier_ids.insert(carrier.clone(), id);
        }
        index.carrier_keys.push(key.clone());
        index.carriers.push(representative.clone());
    }
    Ok(index)
}

fn lookup_carrier(
    ids: &HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
    endpoint: &crate::analyzer::semantic::ValueFlowEndpoint,
) -> Result<ValueFlowCarrierId, ValueFlowPlanError> {
    ids.get(&ValueFlowCarrier::from(endpoint))
        .copied()
        .ok_or(ValueFlowPlanError::MissingCarrier)
}

fn append_binding_carriers(
    binding: &CallBinding,
    output: &mut Vec<ValueFlowCarrier>,
) -> Result<(), ValueFlowPlanError> {
    match binding {
        CallBinding::Receiver { actual, formal, .. } => {
            output.push(ValueFlowCarrier::for_value(actual.clone()));
            output.push(ValueFlowCarrier::Port(formal.clone()));
        }
        CallBinding::ArgumentGroup(group) => {
            for mapping in group.mappings() {
                output.push(argument_carrier(mapping.value().actual())?);
                output.push(ValueFlowCarrier::Port(mapping.value().formal().clone()));
            }
        }
        CallBinding::ImplicitArgument { source, formal, .. } => {
            output.push(ValueFlowCarrier::for_value(source.clone()));
            output.push(ValueFlowCarrier::Port(formal.clone()));
        }
        CallBinding::NormalReturn { formal, result, .. }
        | CallBinding::ExceptionalReturn { formal, result, .. } => {
            output.push(ValueFlowCarrier::Port(formal.clone()));
            output.push(ValueFlowCarrier::for_value(result.clone()));
        }
    }
    Ok(())
}

fn call_binding_rule_count(binding: &CallBinding) -> usize {
    match binding {
        CallBinding::ArgumentGroup(group) => group.mappings().len(),
        _ => 1,
    }
}

fn call_location_oracle_limits(max_access_path: usize) -> OracleLimits {
    let mut values = OracleLimits::default().values();
    values.access_path_length = max_access_path;
    OracleLimits::new(values).expect("validated value-flow access-path limit is positive")
}

fn snapshot_for_procedure<'a>(
    snapshots: &'a [ValueFlowInput<ValueFlowSnapshot>],
    procedure: &ProcedureHandle,
) -> Option<&'a ValueFlowSnapshot> {
    snapshots
        .iter()
        .find(|input| input.value().procedure().durable_key() == procedure.durable_key())
        .map(ValueFlowInput::value)
}

fn binding_coverage_quality(bindings: &CallBindings) -> (ProofStatus, EvidenceCompleteness) {
    if bindings.coverage() == CandidateCoverage::Exhaustive && !bindings.context().was_truncated() {
        (ProofStatus::Proven, EvidenceCompleteness::Complete)
    } else {
        (
            ProofStatus::Unproven("call binding coverage is incomplete".into()),
            EvidenceCompleteness::Partial("call binding coverage is incomplete".into()),
        )
    }
}

fn formal_location_carriers(
    snapshot: &ValueFlowSnapshot,
    formal: &crate::analyzer::semantic::ProcedurePortHandle,
) -> Vec<CallerOrigin> {
    let mut locations = Vec::<CallerOrigin>::new();
    for relation in snapshot.relations() {
        for endpoint in [&relation.source, &relation.target] {
            let ValueFlowEndpoint::Location(location) = endpoint else {
                continue;
            };
            if !matches!(
                location.path().root(),
                AccessPathRoot::ProcedurePort(port) if port == formal
            ) {
                continue;
            }
            if let Some(existing) = locations
                .iter_mut()
                .find(|existing| existing.location == **location)
            {
                existing.proof = merge_call_rule_proof(&existing.proof, relation.proof.clone());
                existing.completeness = merge_call_rule_completeness(
                    &existing.completeness,
                    relation.completeness.clone(),
                );
            } else {
                locations.push(CallerOrigin {
                    location: (**location).clone(),
                    proof: relation.proof.clone(),
                    completeness: relation.completeness.clone(),
                });
            }
        }
    }
    locations
}

fn port_location(
    port: &crate::analyzer::semantic::ProcedurePortHandle,
    limits: OracleLimits,
) -> Result<AbstractLocation, ValueFlowPlanError> {
    let root = match port.kind() {
        ProcedurePortKind::Capture { .. } => AccessPathRoot::CaptureSlot(port.clone()),
        ProcedurePortKind::Receiver
        | ProcedurePortKind::Parameter { .. }
        | ProcedurePortKind::NormalReturn
        | ProcedurePortKind::IndexedNormalReturn { .. }
        | ProcedurePortKind::ExceptionalReturn => AccessPathRoot::ProcedurePort(port.clone()),
    };
    let object = AbstractObject::new(root.clone(), ObjectCardinality::Unknown)
        .map_err(|_| ValueFlowPlanError::InvalidCallArgumentLocation)?;
    let path = AccessPath::exact(root, Vec::new(), limits)
        .map_err(|_| ValueFlowPlanError::InvalidCallArgumentLocation)?;
    AbstractLocation::new(object, path).map_err(|_| ValueFlowPlanError::InvalidCallArgumentLocation)
}

fn value_location(
    value: &crate::analyzer::semantic::ValueHandle,
    limits: OracleLimits,
) -> Result<AbstractLocation, ValueFlowPlanError> {
    let root = AccessPathRoot::Value(value.clone());
    let object = AbstractObject::new(root.clone(), ObjectCardinality::Unknown)
        .map_err(|_| ValueFlowPlanError::InvalidCallArgumentLocation)?;
    let path = AccessPath::exact(root, Vec::new(), limits)
        .map_err(|_| ValueFlowPlanError::InvalidCallArgumentLocation)?;
    AbstractLocation::new(object, path).map_err(|_| ValueFlowPlanError::InvalidCallArgumentLocation)
}

fn relation_has_identity_barrier(relation: &crate::analyzer::semantic::ValueFlowRelation) -> bool {
    relation_transfer(relation).is_some()
}

/// Whether this relation stops the source's member *contents* from reaching the
/// other side.
///
/// A duplicating transfer separates storage while starting the destination out
/// holding what the source held, so a member read on the destination still
/// observes the source's member. Only a transfer that restructures or changes
/// the value stops that.
fn relation_discards_copied_contents(
    relation: &crate::analyzer::semantic::ValueFlowRelation,
) -> bool {
    relation_transfer(relation)
        .is_some_and(|transfer| !transfer.is_some_and(ValueTransfer::preserves_member_contents))
}

/// The transfer this relation crosses, when it crosses one.
///
/// The outer `Option` is whether a transfer applies at all; the inner one is
/// whether its exact payload is retained on the relation.
fn relation_transfer(
    relation: &crate::analyzer::semantic::ValueFlowRelation,
) -> Option<Option<ValueTransfer>> {
    if let Some(transfer) = relation.transfer {
        return Some(Some(transfer));
    }
    let Some(point) = relation
        .point
        .procedure()
        .semantics()
        .point(relation.point.id())
    else {
        debug_assert!(false, "validated value-flow relation names a live point");
        return Some(None);
    };
    match point
        .events
        .get(relation.event_index as usize)
        .map(|event| &event.effect)
    {
        Some(SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Transfer(transfer),
            ..
        }) => Some(Some(*transfer)),
        // An exact transfer is one definition written as two adjacent events,
        // and the oracle publishes a relation for each. Reading the assignment
        // alone would let a walk cross the very barrier its paired transfer
        // states, so the pair is resolved here exactly as the IR contract
        // spells it.
        Some(SemanticEffect::Assignment { target, value }) => point
            .events
            .get(relation.event_index as usize + 1)
            .and_then(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Transfer(transfer),
                    source,
                    target: flow_target,
                } if source == *value && flow_target == *target => Some(Some(transfer)),
                _ => None,
            }),
        _ => None,
    }
}

fn append_origin(
    search: &mut CallerOriginSearch,
    location: AbstractLocation,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    max_origins: usize,
) {
    if let Some(existing) = search
        .origins
        .iter_mut()
        .find(|existing| existing.location == location)
    {
        existing.proof = merge_call_rule_proof(&existing.proof, proof);
        existing.completeness = merge_call_rule_completeness(&existing.completeness, completeness);
        return;
    }
    if search.origins.len() >= max_origins {
        search.incomplete = true;
        return;
    }
    search.origins.push(CallerOrigin {
        location,
        proof,
        completeness,
    });
}

/// The caller locations whose *storage* the formal shares.
///
/// Any transfer stops this walk: an identity-separating copy means a callee
/// write can never be observed through the caller's own storage.
fn caller_storage_origins<'snapshot>(
    actual: &CallArgumentEndpoint,
    snapshot: Option<&'snapshot ValueFlowSnapshot>,
    max_origins: usize,
    path_limits: OracleLimits,
    indexes: &mut CallerOriginIndexes<'snapshot>,
) -> CallerOriginSearch {
    caller_origin_paths(
        actual,
        snapshot,
        max_origins,
        path_limits,
        indexes,
        relation_has_identity_barrier,
    )
}

/// The caller locations whose *contents* the formal starts out holding.
///
/// A duplicating transfer is crossed here: passing an aggregate by value gives
/// the callee its own storage holding the caller's members, so a member read in
/// the callee observes the caller's member even though a write does not travel
/// back.
fn caller_content_origins<'snapshot>(
    actual: &CallArgumentEndpoint,
    snapshot: Option<&'snapshot ValueFlowSnapshot>,
    max_origins: usize,
    path_limits: OracleLimits,
    indexes: &mut CallerOriginIndexes<'snapshot>,
) -> CallerOriginSearch {
    caller_origin_paths(
        actual,
        snapshot,
        max_origins,
        path_limits,
        indexes,
        relation_discards_copied_contents,
    )
}

/// One caller location whose contents a formal bound to an actual starts out
/// holding. `proven_complete` is whether the walk that found it crossed only
/// proven and complete relations.
#[derive(Debug, Clone)]
pub struct CallerContentLocation {
    pub location: AbstractLocation,
    pub proven_complete: bool,
}

/// The caller locations whose contents a formal bound to the value `actual`
/// starts out holding, found by the walk the call-location rules of this plan
/// use (`caller_content_origins`). `complete` is false when the walk could not
/// account for every backing location of the actual.
#[derive(Debug, Clone)]
pub struct CallerContentLocations {
    pub locations: Vec<CallerContentLocation>,
    pub complete: bool,
}

/// The caller locations backing the contents of `actual`, in the caller's
/// own `snapshot`. The composition engine roots a callee's heap input port at
/// these locations, as the plan's call-location rules do.
pub fn caller_content_locations(
    actual: &crate::analyzer::semantic::ValueHandle,
    snapshot: &ValueFlowSnapshot,
    limits: ValueFlowPlanLimits,
) -> CallerContentLocations {
    assert!(
        actual.procedure() == snapshot.procedure(),
        "a caller's content origins are read from the caller's own snapshot"
    );
    let search = caller_content_origins(
        &CallArgumentEndpoint::Value(actual.clone()),
        Some(snapshot),
        limits.max_carriers,
        call_location_oracle_limits(limits.max_access_path),
        &mut CallerOriginIndexes::default(),
    );
    CallerContentLocations {
        locations: search
            .origins
            .into_iter()
            .map(|origin| CallerContentLocation {
                proven_complete: origin.proof == ProofStatus::Proven
                    && origin.completeness == EvidenceCompleteness::Complete,
                location: origin.location,
            })
            .collect(),
        complete: !search.incomplete,
    }
}

// One temporary index per exact snapshot, shared by gap checks and call
// projection. Full handles preserve materialization identity; bare ValueIds
// would conflate different files or two materializations of the same file.
#[derive(Default)]
struct CallerOriginIndexes<'snapshot> {
    entries: Vec<CallerOriginIndex<'snapshot>>,
}

struct CallerOriginIndex<'snapshot> {
    snapshot: &'snapshot ValueFlowSnapshot,
    incoming: HashMap<
        &'snapshot crate::analyzer::semantic::ValueHandle,
        Vec<&'snapshot crate::analyzer::semantic::ValueFlowRelation>,
    >,
    member_owners: HashSet<&'snapshot crate::analyzer::semantic::ValueHandle>,
    addressed_places: HashMap<crate::analyzer::semantic::ValueId, Vec<Option<AccessPathRoot>>>,
}

impl<'snapshot> CallerOriginIndexes<'snapshot> {
    fn for_snapshot(
        &mut self,
        snapshot: &'snapshot ValueFlowSnapshot,
    ) -> &CallerOriginIndex<'snapshot> {
        let index = if let Some(index) = self
            .entries
            .iter()
            .position(|entry| std::ptr::eq(entry.snapshot, snapshot))
        {
            index
        } else {
            let mut incoming = HashMap::<_, Vec<_>>::default();
            let mut member_owners = HashSet::default();
            for relation in snapshot.relations() {
                if let ValueFlowEndpoint::Value(target) = &relation.target {
                    incoming.entry(target).or_default().push(relation);
                }
                if relation.kind == ValueFlowRelationKind::MemoryStore
                    && let ValueFlowEndpoint::Location(location) = &relation.target
                    && !location.path().selectors().is_empty()
                    && let AccessPathRoot::Value(owner) = location.path().root()
                {
                    member_owners.insert(owner);
                }
            }
            let mut addressed_places = HashMap::<_, Vec<_>>::default();
            for alias in snapshot.procedure().semantics().pointer_aliases() {
                if snapshot
                    .procedure()
                    .semantics()
                    .value(alias.pointer)
                    .is_some_and(|value| value.kind == SemanticValueKind::Address)
                {
                    addressed_places.entry(alias.pointer).or_default().push(
                        crate::analyzer::semantic::workspace_oracle::heap::exact_addressed_pointer_root(snapshot.procedure(), alias));
                }
            }
            self.entries.push(CallerOriginIndex {
                snapshot,
                incoming,
                member_owners,
                addressed_places,
            });
            self.entries.len() - 1
        };
        &self.entries[index]
    }
}

fn caller_origin_paths<'snapshot>(
    actual: &CallArgumentEndpoint,
    snapshot: Option<&'snapshot ValueFlowSnapshot>,
    max_origins: usize,
    path_limits: OracleLimits,
    indexes: &mut CallerOriginIndexes<'snapshot>,
    stops_walk: fn(&crate::analyzer::semantic::ValueFlowRelation) -> bool,
) -> CallerOriginSearch {
    if let CallArgumentEndpoint::Location { location, .. } = actual {
        let mut search = CallerOriginSearch::default();
        let mut completeness = EvidenceCompleteness::Complete;
        if !location.path().is_exact() {
            completeness = EvidenceCompleteness::Partial(
                "caller argument location retains an unresolved access path".into(),
            );
        }
        let Ok(ValueFlowCarrier::Location(location)) = argument_carrier(actual) else {
            search.incomplete = true;
            return search;
        };
        append_origin(
            &mut search,
            *location,
            ProofStatus::Proven,
            completeness,
            max_origins,
        );
        return search;
    }

    let Some(snapshot) = snapshot else {
        return CallerOriginSearch {
            incomplete: true,
            ..CallerOriginSearch::default()
        };
    };
    let CallArgumentEndpoint::Value(actual) = actual else {
        unreachable!("location call argument endpoint returned above")
    };
    let index = indexes.for_snapshot(snapshot);
    let incoming = &index.incoming;
    let member_owners = &index.member_owners;

    #[derive(Debug, Clone)]
    struct PendingOrigin {
        value: crate::analyzer::semantic::ValueHandle,
        proof: ProofStatus,
        completeness: EvidenceCompleteness,
        depth: usize,
    }
    let mut pending = vec![PendingOrigin {
        value: actual.clone(),
        proof: ProofStatus::Proven,
        completeness: EvidenceCompleteness::Complete,
        depth: 0,
    }];
    let mut visited = HashSet::default();
    let mut search = CallerOriginSearch::default();
    while let Some(current) = pending.pop() {
        if !visited.insert(current.value.clone()) {
            continue;
        }
        if current.depth >= path_limits.access_path_length() {
            search.incomplete = true;
            continue;
        }
        if current.value.procedure() != snapshot.procedure() {
            search.incomplete = true;
            continue;
        }
        // Taking an address does not load the value of the place. A pointer
        // receiver shares that place's storage, including fields written by
        // its body; rooting it at the Address temporary loses those writes.
        if let Some(places) = index.addressed_places.get(&current.value.id()) {
            for root in places {
                let Some(root) = root else {
                    search.incomplete = true;
                    continue;
                };
                let location = AbstractObject::new(root.clone(), ObjectCardinality::Unknown)
                    .and_then(|object| {
                        AccessPath::exact(root.clone(), Vec::new(), path_limits)
                            .and_then(|path| AbstractLocation::new(object, path))
                    });
                match location {
                    Ok(location) => append_origin(
                        &mut search,
                        location,
                        current.proof.clone(),
                        current.completeness.clone(),
                        max_origins,
                    ),
                    Err(_) => search.incomplete = true,
                }
            }
            continue;
        }
        // Explicit destination members are the caller's current snapshot.
        // Walking back across a copy would instead read the source at call
        // time, after intervening writes may have changed it.
        if member_owners.contains(&current.value) {
            match value_location(&current.value, path_limits) {
                Ok(location) => append_origin(
                    &mut search,
                    location,
                    current.proof,
                    current.completeness,
                    max_origins,
                ),
                Err(_) => search.incomplete = true,
            }
            continue;
        }
        let Some(relations) = incoming.get(&current.value) else {
            // A value no relation defines is its own storage root, the same
            // canonicalization the oracle applies to a value with no load
            // origin.
            match value_location(&current.value, path_limits) {
                Ok(location) => append_origin(
                    &mut search,
                    location,
                    current.proof.clone(),
                    current.completeness.clone(),
                    max_origins,
                ),
                Err(_) => search.incomplete = true,
            }
            continue;
        };
        for relation in relations {
            let proof = merge_call_rule_proof(&current.proof, relation.proof.clone());
            let completeness =
                merge_call_rule_completeness(&current.completeness, relation.completeness.clone());
            if stops_walk(relation) {
                // A transfer may carry ordinary value dependence but never
                // proves that the caller and callee observe one backing store.
                continue;
            }
            match (&relation.source, relation.kind) {
                (ValueFlowEndpoint::Location(location), ValueFlowRelationKind::MemoryLoad)
                | (ValueFlowEndpoint::Location(location), ValueFlowRelationKind::Assignment)
                | (ValueFlowEndpoint::Location(location), ValueFlowRelationKind::Allocation) => {
                    let location = if relation.kind == ValueFlowRelationKind::Allocation {
                        match value_location(&current.value, path_limits) {
                            Ok(location) => location,
                            Err(_) => {
                                search.incomplete = true;
                                continue;
                            }
                        }
                    } else {
                        (**location).clone()
                    };
                    append_origin(&mut search, location, proof, completeness, max_origins);
                }
                (ValueFlowEndpoint::Port(port), ValueFlowRelationKind::Parameter)
                | (ValueFlowEndpoint::Port(port), ValueFlowRelationKind::Receiver) => {
                    match port_location(port, path_limits) {
                        Ok(location) => {
                            append_origin(&mut search, location, proof, completeness, max_origins)
                        }
                        Err(_) => search.incomplete = true,
                    }
                }
                (ValueFlowEndpoint::Value(source), ValueFlowRelationKind::Assignment) => {
                    pending.push(PendingOrigin {
                        value: source.clone(),
                        proof,
                        completeness,
                        depth: current.depth.saturating_add(1),
                    });
                }
                _ => {}
            }
        }
    }
    search
}

struct ProjectedLocationRuleInputs<'input, 'snapshot> {
    bindings: &'input CallBindings,
    actual: &'input CallArgumentEndpoint,
    mapping_proof: ProofStatus,
    mapping_completeness: EvidenceCompleteness,
    kind: CallFlowRuleKind,
    callee_locations: &'input [CallerOrigin],
    caller_snapshot: Option<&'snapshot ValueFlowSnapshot>,
    max_origins: usize,
    path_limits: OracleLimits,
}

fn append_projected_location_rules<'snapshot>(
    inputs: ProjectedLocationRuleInputs<'_, 'snapshot>,
    caller_origins: &mut CallerOriginIndexes<'snapshot>,
    output: &mut Vec<PendingCallFlowRule>,
) -> bool {
    let ProjectedLocationRuleInputs {
        bindings,
        actual,
        mapping_proof,
        mapping_completeness,
        kind,
        callee_locations,
        caller_snapshot,
        max_origins,
        path_limits,
    } = inputs;
    // Scalar-only formals have no location projection to consume an origin.
    if callee_locations.is_empty() {
        return true;
    }
    let origins = match kind {
        // Reading the formal's member at entry observes the caller's member,
        // whether the actual was aliased or duplicated by value.
        CallFlowRuleKind::Call => caller_content_origins(
            actual,
            caller_snapshot,
            max_origins,
            path_limits,
            caller_origins,
        ),
        // Observing a callee write in the caller requires shared storage.
        CallFlowRuleKind::NormalReturn | CallFlowRuleKind::ExceptionalReturn => {
            caller_storage_origins(
                actual,
                caller_snapshot,
                max_origins,
                path_limits,
                caller_origins,
            )
        }
    };
    if origins.origins.is_empty() {
        return !origins.incomplete;
    }
    let mut complete = !origins.incomplete;
    let multiple_origins = origins.incomplete || origins.origins.len() > 1;
    for origin in origins.origins {
        for formal_location in callee_locations {
            let (location, truncated) = match substitute_call_location(
                &origin.location,
                &formal_location.location,
                bindings.call().procedure(),
                path_limits,
            ) {
                Ok(location) => location,
                Err(_) => {
                    complete = false;
                    continue;
                }
            };
            let mut proof = bindings.candidate().proof().clone();
            proof = merge_call_rule_proof(&proof, mapping_proof.clone());
            proof = merge_call_rule_proof(&proof, origin.proof.clone());
            proof = merge_call_rule_proof(&proof, formal_location.proof.clone());
            let mut completeness = bindings.candidate().completeness().clone();
            completeness =
                merge_call_rule_completeness(&completeness, mapping_completeness.clone());
            completeness = merge_call_rule_completeness(&completeness, origin.completeness.clone());
            completeness =
                merge_call_rule_completeness(&completeness, formal_location.completeness.clone());
            if multiple_origins {
                completeness = merge_call_rule_completeness(
                    &completeness,
                    EvidenceCompleteness::Partial(
                        "caller actual has multiple or incomplete backing origins".into(),
                    ),
                );
            }
            if truncated {
                completeness = merge_call_rule_completeness(
                    &completeness,
                    EvidenceCompleteness::Partial("call-location access path was bounded".into()),
                );
            }
            output.push(PendingCallFlowRule {
                context: bindings.context().clone(),
                call: bindings.call().clone(),
                callee: bindings.callee().clone(),
                kind,
                // The caller side of both directions is the same projected
                // location: the actual's own storage with the formal's
                // selectors appended. Using the bare origin in the call
                // direction asked whether the whole container is tainted rather
                // than the member the callee reads, so no member rule fired.
                source: if kind == CallFlowRuleKind::Call {
                    ValueFlowCarrier::Location(Box::new(location.clone()))
                } else {
                    ValueFlowCarrier::Location(Box::new(formal_location.location.clone()))
                },
                target: if kind == CallFlowRuleKind::Call {
                    ValueFlowCarrier::Location(Box::new(formal_location.location.clone()))
                } else {
                    ValueFlowCarrier::Location(Box::new(location))
                },
                proof,
                completeness,
            });
        }
    }
    complete
}

fn append_call_location_rules<'snapshot>(
    bindings: &CallBindings,
    snapshots: &'snapshot [ValueFlowInput<ValueFlowSnapshot>],
    max_origins: usize,
    max_access_path: usize,
    caller_origins: &mut CallerOriginIndexes<'snapshot>,
    output: &mut Vec<PendingCallFlowRule>,
) -> Result<bool, ValueFlowPlanError> {
    let caller_snapshot = snapshot_for_procedure(snapshots, bindings.call().procedure());
    let callee_snapshot = snapshot_for_procedure(snapshots, bindings.callee());
    let Some(callee_snapshot) = callee_snapshot else {
        return Ok(true);
    };
    let path_limits = call_location_oracle_limits(max_access_path);
    let (coverage_proof, coverage_completeness) = binding_coverage_quality(bindings);
    let mut complete = true;
    for binding in bindings.bindings() {
        match binding {
            CallBinding::Receiver { actual, formal, .. } => {
                let actual = CallArgumentEndpoint::Value(actual.clone());
                let formal_locations = formal_location_carriers(callee_snapshot, formal);
                if matches!(
                    bindings.candidate().member_receiver_preparation(),
                    Some(
                        crate::analyzer::semantic::MemberReceiverPreparation::CopyValue
                            | crate::analyzer::semantic::MemberReceiverPreparation::CopyPointee
                    )
                ) {
                    // Per-file unknown selection cannot snapshot these fields.
                    // Preserve the copy barrier and open coverage until the
                    // selected receiver's copied contents are represented.
                    complete &= formal_locations.is_empty();
                    continue;
                }
                complete &= append_projected_location_rules(
                    ProjectedLocationRuleInputs {
                        bindings,
                        actual: &actual,
                        mapping_proof: coverage_proof.clone(),
                        mapping_completeness: coverage_completeness.clone(),
                        kind: CallFlowRuleKind::Call,
                        callee_locations: &formal_locations,
                        caller_snapshot,
                        max_origins,
                        path_limits,
                    },
                    caller_origins,
                    output,
                );
                complete &= append_projected_location_rules(
                    ProjectedLocationRuleInputs {
                        bindings,
                        actual: &actual,
                        mapping_proof: coverage_proof.clone(),
                        mapping_completeness: coverage_completeness.clone(),
                        kind: CallFlowRuleKind::NormalReturn,
                        callee_locations: &formal_locations,
                        caller_snapshot,
                        max_origins,
                        path_limits,
                    },
                    caller_origins,
                    output,
                );
            }
            CallBinding::ArgumentGroup(group) => {
                for mapping in group.mappings() {
                    let mapping_value = mapping.value();
                    if !mapping_value.preserves_reference_identity() {
                        continue;
                    }
                    let actual = mapping_value.actual();
                    let formal_locations =
                        formal_location_carriers(callee_snapshot, mapping_value.formal());
                    let mapping_completeness = merge_call_rule_completeness(
                        &coverage_completeness,
                        mapping.completeness().clone(),
                    );
                    let mapping_proof =
                        merge_call_rule_proof(&coverage_proof, mapping.proof().clone());
                    complete &= append_projected_location_rules(
                        ProjectedLocationRuleInputs {
                            bindings,
                            actual,
                            mapping_proof: mapping_proof.clone(),
                            mapping_completeness: mapping_completeness.clone(),
                            kind: CallFlowRuleKind::Call,
                            callee_locations: &formal_locations,
                            caller_snapshot,
                            max_origins,
                            path_limits,
                        },
                        caller_origins,
                        output,
                    );
                    complete &= append_projected_location_rules(
                        ProjectedLocationRuleInputs {
                            bindings,
                            actual,
                            mapping_proof,
                            mapping_completeness,
                            kind: CallFlowRuleKind::NormalReturn,
                            callee_locations: &formal_locations,
                            caller_snapshot,
                            max_origins,
                            path_limits,
                        },
                        caller_origins,
                        output,
                    );
                }
            }
            CallBinding::NormalReturn { formal, result, .. } => {
                let actual = CallArgumentEndpoint::Value(result.clone());
                let formal_locations = formal_location_carriers(callee_snapshot, formal);
                complete &= append_projected_location_rules(
                    ProjectedLocationRuleInputs {
                        bindings,
                        actual: &actual,
                        mapping_proof: coverage_proof.clone(),
                        mapping_completeness: coverage_completeness.clone(),
                        kind: CallFlowRuleKind::NormalReturn,
                        callee_locations: &formal_locations,
                        caller_snapshot,
                        max_origins,
                        path_limits,
                    },
                    caller_origins,
                    output,
                );
            }
            CallBinding::ImplicitArgument { .. } | CallBinding::ExceptionalReturn { .. } => {}
        }
    }
    Ok(complete)
}

/// Spell one callee member selector the way the caller spells the same member.
///
/// A member locator carries the enclosing declaration chain of the *use site*,
/// which is why the storage key in
/// [`crate::dataflow::reusable_summary::SummaryLocationKey::from_locator`]
/// deliberately leaves that chain out: one field declaration is shared by
/// accesses from different procedures. Grafting the callee's spelling onto a
/// caller root would therefore build a location the caller never names, and the
/// caller's own store or load of that member could never meet it. Respelling
/// keeps the declaration-backed identity -- path, language, role and anchor --
/// and takes only the accessor chain from the caller. A member declared outside
/// the caller's own artifact keeps its spelling, because the caller has no
/// scope to name it in.
fn caller_member_selector(selector: &AccessSelector, caller: &ProcedureHandle) -> AccessSelector {
    let AccessSelector::Field(member) = selector else {
        return selector.clone();
    };
    if !Arc::ptr_eq(member.scope(), caller.artifact()) {
        return selector.clone();
    }
    let locator = member.locator();
    let respelled = crate::analyzer::semantic::SemanticLocator::new(
        locator.mount(),
        locator.path().clone(),
        locator.language(),
        caller.semantics().locator().declaration().clone(),
        locator.role(),
        locator.anchor(),
    );
    crate::analyzer::semantic::ScopedSemanticLocator::new(member.scope().clone(), respelled)
        .map_or_else(|_| selector.clone(), AccessSelector::Field)
}

/// Match two already retained member locations beneath one proven capture cell.
/// Exact index handles can differ across procedures only when their typed
/// constant payload establishes equality. Opaque constants and dynamic values
/// do not establish it; unequal strings can still be unresolved spellings.
pub(crate) fn is_capture_location_projection(
    cell: &AbstractLocation,
    source: &AbstractLocation,
    target: &AbstractLocation,
    producer: &ProcedureHandle,
) -> bool {
    if source.path().root() != cell.path().root()
        || !source.path().is_exact()
        || !target.path().is_exact()
        || source.path().selectors().len() != target.path().selectors().len()
    {
        return false;
    }
    source.path().selectors().iter().zip(target.path().selectors()).all(|(source, target)| {
        use crate::analyzer::semantic::IndexSelector;
        match (source, target) {
            (AccessSelector::Index(IndexSelector::Exact(source)),
             AccessSelector::Index(IndexSelector::Exact(target))) => {
                match (source.procedure().semantics().value(source.id()),
                       target.procedure().semantics().value(target.id())) {
                    (Some(source), Some(target)) => matches!(
                        (&source.kind, &target.kind),
                        (SemanticValueKind::ConstantString(left), SemanticValueKind::ConstantString(right)) if left == right
                    ),
                    _ => false,
                }
            }
            _ => *source == caller_member_selector(target, producer),
        }
    })
}

fn substitute_call_location(
    actual: &AbstractLocation,
    formal: &AbstractLocation,
    caller: &ProcedureHandle,
    limits: OracleLimits,
) -> Result<(AbstractLocation, bool), ValueFlowPlanError> {
    let mut selectors = actual.path().selectors().to_vec();
    let mut lossy = !actual.path().is_exact() || !formal.path().is_exact();
    for selector in formal.path().selectors() {
        selectors.push(match selector {
            AccessSelector::Field(_) => caller_member_selector(selector, caller),
            AccessSelector::Property(property) => AccessSelector::Property(property.clone()),
            AccessSelector::Index(crate::analyzer::semantic::IndexSelector::Constant(value)) => {
                AccessSelector::Index(crate::analyzer::semantic::IndexSelector::Constant(*value))
            }
            AccessSelector::Index(crate::analyzer::semantic::IndexSelector::Any) => {
                lossy = true;
                AccessSelector::Index(crate::analyzer::semantic::IndexSelector::Any)
            }
            AccessSelector::Index(crate::analyzer::semantic::IndexSelector::Exact(_)) => {
                // The exact index handle belongs to the callee procedure. A
                // caller plan cannot retain it after root substitution; the
                // structured wildcard is the precise bounded approximation.
                lossy = true;
                AccessSelector::Index(crate::analyzer::semantic::IndexSelector::Any)
            }
        });
    }
    if selectors.len() > limits.access_path_length() {
        selectors.truncate(limits.access_path_length());
        lossy = true;
    }
    let tail = if lossy
        || actual.path().tail() == AccessPathTail::Summary
        || formal.path().tail() == AccessPathTail::Summary
    {
        AccessPathTail::Summary
    } else {
        AccessPathTail::Exact
    };
    let root = actual.path().root().clone();
    let object = AbstractObject::new(root.clone(), actual.object().cardinality())
        .map_err(|_| ValueFlowPlanError::InvalidCallArgumentLocation)?;
    let path = AccessPath::bounded(root, selectors, tail, limits)
        .map_err(|_| ValueFlowPlanError::InvalidCallArgumentLocation)?;
    let location = AbstractLocation::new(object, path)
        .map_err(|_| ValueFlowPlanError::InvalidCallArgumentLocation)?;
    Ok((location, lossy))
}

fn append_call_rules(
    bindings: &CallBindings,
    ids: &HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
    output: &mut Vec<CallFlowRule>,
) -> Result<(), ValueFlowPlanError> {
    let candidate_proof = bindings.candidate().proof();
    let candidate_completeness = bindings.candidate().completeness();
    let mut append = |kind,
                      source: ValueFlowCarrier,
                      target: ValueFlowCarrier,
                      proof,
                      completeness,
                      transfer| {
        output.push(CallFlowRule {
            context: bindings.context().clone(),
            call: bindings.call().clone(),
            callee: bindings.callee().clone(),
            kind,
            transfer,
            source: *ids.get(&source).ok_or(ValueFlowPlanError::MissingCarrier)?,
            target: *ids.get(&target).ok_or(ValueFlowPlanError::MissingCarrier)?,
            proof: merge_call_rule_proof(candidate_proof, proof),
            completeness: merge_call_rule_completeness(candidate_completeness, completeness),
        });
        Ok::<_, ValueFlowPlanError>(())
    };
    for binding in bindings.bindings() {
        match binding {
            CallBinding::Receiver { actual, formal, .. } => append(
                CallFlowRuleKind::Call,
                ValueFlowCarrier::for_value(actual.clone()),
                ValueFlowCarrier::Port(formal.clone()),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                None,
            )?,
            CallBinding::ArgumentGroup(group) => {
                for mapping in group.mappings() {
                    // Exact mapping proves value dependence independently of
                    // conversion typing. Alias transport is separately gated
                    // by preserves_reference_identity in location lowering.
                    append(
                        CallFlowRuleKind::Call,
                        argument_carrier(mapping.value().actual())?,
                        ValueFlowCarrier::Port(mapping.value().formal().clone()),
                        mapping.proof().clone(),
                        mapping.completeness().clone(),
                        mapping.value().transfer(),
                    )?;
                }
            }
            CallBinding::ImplicitArgument { source, formal, .. } => append(
                CallFlowRuleKind::Call,
                ValueFlowCarrier::for_value(source.clone()),
                ValueFlowCarrier::Port(formal.clone()),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                None,
            )?,
            CallBinding::NormalReturn { formal, result, .. } => append(
                CallFlowRuleKind::NormalReturn,
                ValueFlowCarrier::Port(formal.clone()),
                ValueFlowCarrier::for_value(result.clone()),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                None,
            )?,
            CallBinding::ExceptionalReturn { formal, result, .. } => append(
                CallFlowRuleKind::ExceptionalReturn,
                ValueFlowCarrier::Port(formal.clone()),
                ValueFlowCarrier::for_value(result.clone()),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                None,
            )?,
        }
    }
    Ok(())
}

fn merge_call_rule_proof(candidate: &ProofStatus, binding: ProofStatus) -> ProofStatus {
    match (candidate, binding) {
        (ProofStatus::Proven, binding) => binding,
        (candidate @ ProofStatus::Unproven(_), ProofStatus::Proven) => candidate.clone(),
        (ProofStatus::Unproven(candidate), ProofStatus::Unproven(binding)) => {
            ProofStatus::Unproven(format!("{candidate}; {binding}").into())
        }
    }
}

fn merge_call_rule_completeness(
    candidate: &EvidenceCompleteness,
    binding: EvidenceCompleteness,
) -> EvidenceCompleteness {
    match (candidate, binding) {
        (EvidenceCompleteness::Complete, binding) => binding,
        (candidate @ EvidenceCompleteness::Partial(_), EvidenceCompleteness::Complete) => {
            candidate.clone()
        }
        (EvidenceCompleteness::Partial(candidate), EvidenceCompleteness::Partial(binding)) => {
            EvidenceCompleteness::Partial(format!("{candidate}; {binding}").into())
        }
    }
}

fn build_local_rule_point_index(rules: &[LocalFlowRule]) -> LocalRulePointIndex {
    let mut by_point = HashMap::<ProgramPointHandle, Vec<usize>>::default();
    for (index, rule) in rules.iter().enumerate() {
        by_point.entry(rule.point.clone()).or_default().push(index);
    }
    // `rules` is canonicalized in forward event order. Keep each bucket in
    // that order; the backward accessor reverses it while reading so strong
    // updates are still followed by weak rules at the same target.
    let by_point = by_point
        .into_iter()
        .map(|(point, positions)| (point, positions.into_boxed_slice()))
        .collect();
    LocalRulePointIndex { by_point }
}

fn build_call_rule_reverse_index(rules: &[CallFlowRule]) -> CallRuleReverseIndex {
    let mut by_target = HashMap::<CallRuleTargetKey, Vec<usize>>::default();
    for (index, rule) in rules.iter().enumerate() {
        by_target
            .entry(CallRuleTargetKey {
                call: rule.call.clone(),
                callee: rule.callee.clone(),
                kind: rule.kind,
                target: rule.target,
            })
            .or_default()
            .push(index);
    }
    CallRuleReverseIndex {
        by_target: by_target
            .into_iter()
            .map(|(key, positions)| (key, positions.into_boxed_slice()))
            .collect(),
    }
}

fn build_observation_index<T>(
    observations: &[T],
    key: impl Fn(&T) -> ObservationKey,
) -> ObservationIndex {
    let mut by_point_phase = HashMap::<ObservationKey, Vec<usize>>::default();
    for (index, observation) in observations.iter().enumerate() {
        by_point_phase
            .entry(key(observation))
            .or_default()
            .push(index);
    }
    ObservationIndex {
        by_point_phase: by_point_phase
            .into_iter()
            .map(|(key, positions)| (key, positions.into_boxed_slice()))
            .collect(),
    }
}

fn argument_carrier(
    endpoint: &CallArgumentEndpoint,
) -> Result<ValueFlowCarrier, ValueFlowPlanError> {
    match endpoint {
        CallArgumentEndpoint::Value(value) => Ok(ValueFlowCarrier::for_value(value.clone())),
        CallArgumentEndpoint::Location { location, .. } => {
            let endpoint = ValueFlowEndpoint::for_path(location.path().clone())
                .map_err(|_| ValueFlowPlanError::InvalidCallArgumentLocation)?;
            Ok(ValueFlowCarrier::from(endpoint))
        }
    }
}

fn build_call_fallback_profiles(
    mut procedures: Vec<&ProcedureHandle>,
    carrier_ids: &HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
    carrier_components: &[usize],
) -> Vec<CallFallbackProfile> {
    procedures.sort_by(|left, right| compare_procedures(left, right));
    procedures.dedup_by(|left, right| *left == *right);
    let mut profiles = Vec::new();
    for procedure in procedures {
        for row in procedure.semantics().call_sites() {
            let Some(call) = procedure.call_site_handle(row.id) else {
                continue;
            };
            let mut input_values = Vec::with_capacity(row.arguments.len().saturating_add(1));
            if let Some(receiver) = row.receiver.and_then(|value| procedure.value_handle(value)) {
                input_values.push(receiver);
            }
            input_values.extend(
                row.arguments
                    .iter()
                    .filter_map(|argument| procedure.value_handle(argument.value)),
            );

            let mut inputs = input_values
                .iter()
                .filter_map(|value| {
                    carrier_ids
                        .get(&ValueFlowCarrier::for_value(value.clone()))
                        .copied()
                })
                .collect::<Vec<_>>();
            let mut input_components = inputs
                .iter()
                .map(|carrier| carrier_components[carrier.index()])
                .collect::<Vec<_>>();
            input_components.sort_unstable();
            input_components.dedup();
            inputs.sort_unstable();
            inputs.dedup();
            let result_carrier = |value| {
                procedure.value_handle(value).and_then(|value| {
                    carrier_ids
                        .get(&ValueFlowCarrier::for_value(value))
                        .copied()
                })
            };
            profiles.push(CallFallbackProfile {
                call,
                inputs: inputs.into_boxed_slice(),
                reachable_components: input_components.into_boxed_slice(),
                normal_output: row.result.and_then(result_carrier),
                exceptional_output: row.thrown.and_then(result_carrier),
            });
        }
    }
    profiles.sort_by(|left, right| compare_calls(&left.call, &right.call));
    profiles
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FallbackLocationIndex {
    by_component: HashMap<usize, Vec<ValueFlowCarrierId>>,
    bounded_globals: Vec<ValueFlowCarrierId>,
    location_components: HashMap<ValueFlowCarrierId, usize>,
}

impl FallbackLocationIndex {
    fn retained_heap_bytes(&self) -> usize {
        let by_component = self
            .by_component
            .capacity()
            .saturating_mul(
                std::mem::size_of::<(usize, Vec<ValueFlowCarrierId>)>().saturating_add(1),
            )
            .saturating_add(
                self.by_component
                    .values()
                    .map(|carriers| {
                        carriers
                            .capacity()
                            .saturating_mul(std::mem::size_of::<ValueFlowCarrierId>())
                    })
                    .fold(0usize, usize::saturating_add),
            );
        let bounded_globals = self
            .bounded_globals
            .capacity()
            .saturating_mul(std::mem::size_of::<ValueFlowCarrierId>());
        let location_components = self
            .location_components
            .capacity()
            .saturating_mul(std::mem::size_of::<(ValueFlowCarrierId, usize)>().saturating_add(1));
        by_component
            .saturating_add(bounded_globals)
            .saturating_add(location_components)
    }
}

fn build_fallback_location_index(
    carriers: &[ValueFlowCarrier],
    carrier_ids: &HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
    carrier_components: &[usize],
) -> FallbackLocationIndex {
    let mut index = FallbackLocationIndex::default();
    for (position, carrier) in carriers.iter().enumerate() {
        let ValueFlowCarrier::Location(location) = carrier else {
            continue;
        };
        let id = ValueFlowCarrierId::try_from_index(position)
            .expect("canonical carrier count is bounded before fallback indexing");
        let root = location.path().root();
        if matches!(
            root,
            AccessPathRoot::Static(_)
                | AccessPathRoot::TypeSummary(_)
                | AccessPathRoot::ModuleObject(_)
                | AccessPathRoot::External(_)
                | AccessPathRoot::RuntimeObject(_)
                | AccessPathRoot::CallSubstitution { .. }
        ) {
            index.bounded_globals.push(id);
        } else if let Some(component) = root_carrier(root)
            .and_then(|carrier| carrier_ids.get(&carrier).copied())
            .map(|carrier| carrier_components[carrier.index()])
        {
            index.location_components.insert(id, component);
            index.by_component.entry(component).or_default().push(id);
        }
    }
    index.bounded_globals.sort_unstable();
    for locations in index.by_component.values_mut() {
        locations.sort_unstable();
    }
    index
}

fn root_carrier(root: &AccessPathRoot) -> Option<ValueFlowCarrier> {
    match root {
        // Field paths are durable object identities, but they are not backed
        // by a value-flow carrier row in this index.
        AccessPathRoot::FieldPath { .. } => None,
        AccessPathRoot::Value(value) => Some(ValueFlowCarrier::for_value(value.clone())),
        AccessPathRoot::CallResult(result) => {
            Some(ValueFlowCarrier::for_value(result.result().clone()))
        }
        AccessPathRoot::ProcedurePort(port) | AccessPathRoot::CaptureSlot(port) => {
            Some(ValueFlowCarrier::Port(port.clone()))
        }
        AccessPathRoot::Allocation(allocation) => allocation
            .procedure()
            .semantics()
            .allocation(allocation.id())
            .and_then(|row| allocation.procedure().value_handle(row.result))
            .map(ValueFlowCarrier::for_value),
        AccessPathRoot::LexicalCell(location) => location
            .procedure()
            .semantics()
            .memory_location(location.id())
            .and_then(|row| match row.kind {
                MemoryLocationKind::LexicalCell { binding } => {
                    location.procedure().value_handle(binding)
                }
                _ => None,
            })
            .map(ValueFlowCarrier::for_value),
        AccessPathRoot::Static(_)
        | AccessPathRoot::TypeSummary(_)
        | AccessPathRoot::ModuleObject(_)
        | AccessPathRoot::External(_)
        | AccessPathRoot::RuntimeObject(_)
        | AccessPathRoot::CallSubstitution { .. } => None,
    }
}

fn build_carrier_components(carrier_count: usize, local_rules: &[LocalFlowRule]) -> Vec<usize> {
    fn find_root(parents: &mut [usize], mut index: usize) -> usize {
        while parents[index] != index {
            parents[index] = parents[parents[index]];
            index = parents[index];
        }
        index
    }

    let mut parents = (0..carrier_count).collect::<Vec<_>>();
    let mut ranks = vec![0_u8; carrier_count];
    for rule in local_rules {
        let source = find_root(&mut parents, rule.source.index());
        let target = find_root(&mut parents, rule.target.index());
        if source == target {
            continue;
        }
        match ranks[source].cmp(&ranks[target]) {
            Ordering::Less => parents[source] = target,
            Ordering::Greater => parents[target] = source,
            Ordering::Equal => {
                parents[target] = source;
                ranks[source] = ranks[source].saturating_add(1);
            }
        }
    }
    (0..carrier_count)
        .map(|index| find_root(&mut parents, index))
        .collect()
}

fn compare_snapshots(left: &ValueFlowSnapshot, right: &ValueFlowSnapshot) -> Ordering {
    compare_procedures(left.procedure(), right.procedure()).then_with(|| {
        compare_call_contexts(left.context().calls(), right.context().calls()).then_with(|| {
            left.context()
                .was_truncated()
                .cmp(&right.context().was_truncated())
        })
    })
}

fn compare_bindings(left: &CallBindings, right: &CallBindings) -> Ordering {
    compare_calls(left.call(), right.call())
        .then_with(|| compare_procedures(left.callee(), right.callee()))
        .then_with(|| compare_call_contexts(left.context().calls(), right.context().calls()))
        .then_with(|| {
            left.context()
                .was_truncated()
                .cmp(&right.context().was_truncated())
        })
}

fn compare_call_contexts(left: &[CallSiteHandle], right: &[CallSiteHandle]) -> Ordering {
    left.iter()
        .zip(right)
        .find_map(|(left, right)| {
            let ordering = compare_calls(left, right);
            (ordering != Ordering::Equal).then_some(ordering)
        })
        .unwrap_or_else(|| left.len().cmp(&right.len()))
}

fn compare_local_rules(left: &LocalFlowRule, right: &LocalFlowRule) -> Ordering {
    compare_points(&left.point, &right.point)
        .then_with(|| left.event_index.cmp(&right.event_index))
        .then_with(|| left.source.cmp(&right.source))
        .then_with(|| left.target.cmp(&right.target))
        .then_with(|| relation_kind_rank(left.kind).cmp(&relation_kind_rank(right.kind)))
        .then_with(|| transfer_rank(left.transfer).cmp(&transfer_rank(right.transfer)))
        .then_with(|| left.policy_local.cmp(&right.policy_local))
}

fn transfer_rank(transfer: Option<ValueTransfer>) -> (u8, u8, u32, StableDigest) {
    use crate::analyzer::semantic::{
        MoveInvalidation, TransferKind, TransferOperation, ValuePreservation,
    };

    let Some(transfer) = transfer else {
        return (0, 0, 0, StableDigest::from_array([0; 32]));
    };
    let zero_digest = StableDigest::from_array([0; 32]);
    let (operation, call_site, conversion) = match transfer.operation {
        TransferOperation::None => (0, 0, zero_digest),
        TransferOperation::CallSite(call) => (1, call.get(), zero_digest),
        TransferOperation::Unknown => (2, 0, zero_digest),
        TransferOperation::CallArgumentConversion(conversion) => (3, 0, conversion),
        TransferOperation::ValueCarrierAdaptation(adaptation) => (4, 0, adaptation),
    };
    let kind = match transfer.kind {
        TransferKind::Copy => 1,
        TransferKind::AggregateCopy => 2,
        TransferKind::Move {
            invalidation: MoveInvalidation::Invalidated,
        } => 3,
        TransferKind::Move {
            invalidation: MoveInvalidation::Unknown,
        } => 4,
        TransferKind::Conversion {
            preservation: ValuePreservation::Identity,
        } => 5,
        TransferKind::Conversion {
            preservation: ValuePreservation::Preserving,
        } => 6,
        TransferKind::Conversion {
            preservation: ValuePreservation::Changing,
        } => 7,
        TransferKind::Boxing => 8,
        TransferKind::Unboxing => 9,
    };
    (kind, operation, call_site, conversion)
}

fn same_local_rules(left: &ValueFlowPlan, right: &ValueFlowPlan) -> bool {
    left.local_rules.len() == right.local_rules.len()
        && left
            .local_rules
            .iter()
            .zip(&right.local_rules)
            .all(|(left_rule, right_rule)| {
                left_rule.point == right_rule.point
                    && left_rule.event_index == right_rule.event_index
                    && left_rule.kind == right_rule.kind
                    && left_rule.transfer == right_rule.transfer
                    && left.carrier_keys[left_rule.source.index()]
                        == right.carrier_keys[right_rule.source.index()]
                    && left.carrier_keys[left_rule.target.index()]
                        == right.carrier_keys[right_rule.target.index()]
                    && left_rule.proof == right_rule.proof
                    && left_rule.completeness == right_rule.completeness
                    && left_rule.policy_local == right_rule.policy_local
                    && left_rule.strong_update == right_rule.strong_update
                    && left_rule.direct_cell_overwrite == right_rule.direct_cell_overwrite
            })
}

fn same_call_rules(left: &ValueFlowPlan, right: &ValueFlowPlan) -> bool {
    left.call_rules.len() == right.call_rules.len()
        && left
            .call_rules
            .iter()
            .zip(&right.call_rules)
            .all(|(left_rule, right_rule)| {
                left_rule.context == right_rule.context
                    && left_rule.call == right_rule.call
                    && left_rule.callee == right_rule.callee
                    && left_rule.kind == right_rule.kind
                    && left_rule.transfer == right_rule.transfer
                    && left.carrier_keys[left_rule.source.index()]
                        == right.carrier_keys[right_rule.source.index()]
                    && left.carrier_keys[left_rule.target.index()]
                        == right.carrier_keys[right_rule.target.index()]
                    && left_rule.proof == right_rule.proof
                    && left_rule.completeness == right_rule.completeness
            })
}

fn same_summary_location_bindings(left: &ValueFlowPlan, right: &ValueFlowPlan) -> bool {
    left.summary_location_bindings.len() == right.summary_location_bindings.len()
        && left
            .summary_location_bindings
            .iter()
            .zip(&right.summary_location_bindings)
            .all(|(left_binding, right_binding)| {
                left_binding.call == right_binding.call
                    && left_binding.port == right_binding.port
                    && left_binding
                        .carrier
                        .map(|carrier| &left.carrier_keys[carrier.index()])
                        == right_binding
                            .carrier
                            .map(|carrier| &right.carrier_keys[carrier.index()])
            })
}

fn same_conditional_source_specs(left: &ValueFlowPlan, right: &ValueFlowPlan) -> bool {
    let a = left
        .source_key_order
        .iter()
        .map(|id| &left.sources[id.index()])
        .filter(|source| source.activation_triggers.is_some())
        .collect::<Vec<_>>();
    let b = right
        .source_key_order
        .iter()
        .map(|id| &right.sources[id.index()])
        .filter(|source| source.activation_triggers.is_some())
        .collect::<Vec<_>>();
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(a, b)| same_source_spec(left, &a.spec, right, &b.spec))
}

// Full plan equality must preserve source coordinates: retained solver facts
// name insertion IDs. Propagation compatibility separately compares keys.
fn same_source_specs(left: &ValueFlowPlan, right: &ValueFlowPlan) -> bool {
    left.sources.len() == right.sources.len()
        && left.sources.iter().zip(&right.sources).all(|(a, b)| {
            a.id == b.id
                && a.carrier == b.carrier
                && same_source_spec(left, &a.spec, right, &b.spec)
        })
}

fn same_keyed_source_specs(left: &ValueFlowPlan, right: &ValueFlowPlan) -> bool {
    left.sources.len() == right.sources.len()
        && left
            .source_key_order
            .iter()
            .zip(&right.source_key_order)
            .all(|(a, b)| {
                let a = &left.sources[a.index()];
                let b = &right.sources[b.index()];
                a.carrier == b.carrier && same_source_spec(left, &a.spec, right, &b.spec)
            })
}

fn same_source_spec(
    left: &ValueFlowPlan,
    a: &ValueFlowSourceSpec,
    right: &ValueFlowPlan,
    b: &ValueFlowSourceSpec,
) -> bool {
    a.key() == b.key()
        && a.point() == b.point()
        && a.phase() == b.phase()
        && a.carrier() == b.carrier()
        && a.proof() == b.proof()
        && a.completeness() == b.completeness()
        && a.dispatch_obligations() == b.dispatch_obligations()
        && a.activation_triggers()
            .map(|list| left.source_list_keys(list))
            == b.activation_triggers()
                .map(|list| right.source_list_keys(list))
}

fn hash_source_spec<H: std::hash::Hasher>(
    plan: &ValueFlowPlan,
    spec: &ValueFlowSourceSpec,
    state: &mut H,
) {
    spec.key().hash(state);
    spec.point().hash(state);
    spec.phase().hash(state);
    spec.carrier().hash(state);
    spec.proof().hash(state);
    spec.completeness().hash(state);
    spec.activation_triggers()
        .map(|list| plan.source_list_keys(list))
        .hash(state);
    spec.dispatch_obligations().hash(state);
}

fn relation_kind_rank(kind: ValueFlowRelationKind) -> u8 {
    match kind {
        ValueFlowRelationKind::Assignment => 0,
        ValueFlowRelationKind::Parameter => 1,
        ValueFlowRelationKind::Receiver => 2,
        ValueFlowRelationKind::NormalReturn => 3,
        ValueFlowRelationKind::ExceptionalReturn => 4,
        ValueFlowRelationKind::Allocation => 5,
        ValueFlowRelationKind::MemoryLoad => 6,
        ValueFlowRelationKind::MemoryStore => 7,
        ValueFlowRelationKind::Capture => 8,
        ValueFlowRelationKind::LanguageDefined => 9,
        ValueFlowRelationKind::HandlerBinding => 10,
        ValueFlowRelationKind::ContainerCollapse => 11,
    }
}

fn compare_call_rules(left: &CallFlowRule, right: &CallFlowRule) -> Ordering {
    compare_calls(&left.call, &right.call)
        .then_with(|| compare_call_contexts(left.context.calls(), right.context.calls()))
        .then_with(|| {
            left.context
                .was_truncated()
                .cmp(&right.context.was_truncated())
        })
        .then_with(|| compare_procedures(&left.callee, &right.callee))
        .then_with(|| call_rule_rank(left.kind).cmp(&call_rule_rank(right.kind)))
        .then_with(|| transfer_rank(left.transfer).cmp(&transfer_rank(right.transfer)))
        .then_with(|| left.source.cmp(&right.source))
        .then_with(|| left.target.cmp(&right.target))
}

fn merge_duplicate_call_rules(rules: &mut Vec<CallFlowRule>) {
    let mut merged: Vec<CallFlowRule> = Vec::with_capacity(rules.len());
    for rule in rules.drain(..) {
        if let Some(previous) = merged.last_mut()
            && previous.context == rule.context
            && previous.call == rule.call
            && previous.callee == rule.callee
            && previous.kind == rule.kind
            && previous.transfer == rule.transfer
            && previous.source == rule.source
            && previous.target == rule.target
        {
            previous.proof = merge_call_rule_proof(&previous.proof, rule.proof);
            previous.completeness =
                merge_call_rule_completeness(&previous.completeness, rule.completeness);
        } else {
            merged.push(rule);
        }
    }
    *rules = merged;
}

fn call_rule_rank(kind: CallFlowRuleKind) -> u8 {
    match kind {
        CallFlowRuleKind::Call => 0,
        CallFlowRuleKind::NormalReturn => 1,
        CallFlowRuleKind::ExceptionalReturn => 2,
    }
}

// None deliberately emits no bytes: automatic comparison kills retain their identity.
fn push_edge_kill_labels(digest: &mut LengthDelimitedDigest, labels: Option<&TaintClassSet>) {
    if let Some(labels) = labels {
        digest.push(b"edge_kill_labels");
        digest.push(&labels.universe().bytes());
        digest.push(&(labels.class_count() as u64).to_le_bytes());
        for class in labels.iter_dense() {
            digest.push(&class.get().to_le_bytes());
        }
    }
}

fn compare_edge_kills(
    left: &ValueFlowEdgeKillSpec,
    right: &ValueFlowEdgeKillSpec,
    sources: &[ValueFlowSourceSpec],
    lists: &ValueFlowSourceLists,
) -> Ordering {
    compare_points(&left.point, &right.point)
        .then_with(|| left.target.cmp(&right.target))
        .then_with(|| left.kind.label().cmp(right.kind.label()))
        .then_with(|| {
            left.carrier
                .stable_key()
                .ok()
                .cmp(&right.carrier.stable_key().ok())
        })
        .then_with(|| left.labels.cmp(&right.labels))
        .then_with(|| {
            let keys = |list| {
                let mut keys = lists
                    .get(list)
                    .iter()
                    .map(|id| sources[id.index()].key())
                    .collect::<Vec<_>>();
                keys.sort_unstable();
                keys
            };
            keys(left.sources).cmp(&keys(right.sources))
        })
}

fn normalize_summary_edge_kills(
    rows: Vec<ValueFlowEdgeKillSummaryRule>,
) -> Box<[ValueFlowEdgeKillSummaryRule]> {
    let mut normalized = Vec::<ValueFlowEdgeKillSummaryRule>::new();
    for row in rows {
        if let Some(previous) = normalized.last_mut()
            && previous.point == row.point
            && previous.target == row.target
            && previous.kind == row.kind
            && previous.carrier == row.carrier
            && previous.labels == row.labels
        {
            let mut sources = std::mem::take(&mut previous.sources).into_vec();
            sources.extend(row.sources);
            sources.sort_unstable();
            sources.dedup();
            previous.sources = sources.into_boxed_slice();
        } else {
            normalized.push(row);
        }
    }
    normalized.into_boxed_slice()
}

fn normalize_summary_conditional_sources(
    mut rows: Vec<ValueFlowConditionalSourceSummaryRule>,
) -> Box<[ValueFlowConditionalSourceSummaryRule]> {
    rows.sort_by(|left, right| {
        left.point
            .cmp(&right.point)
            .then_with(|| left.phase.cmp(&right.phase))
            .then_with(|| left.key.cmp(&right.key))
            .then_with(|| left.carrier.cmp(&right.carrier))
    });
    rows.dedup();
    rows.into_boxed_slice()
}

fn source_key_order(sources: &[BoundValueFlowSource]) -> Box<[ValueFlowSourceId]> {
    let mut ids = sources.iter().map(|source| source.id).collect::<Vec<_>>();
    ids.sort_unstable_by_key(|id| sources[id.index()].spec.key());
    ids.into_boxed_slice()
}

fn duplicate_source_keys(sources: &[ValueFlowSourceSpec]) -> bool {
    let mut keys = HashSet::default();
    sources.iter().any(|source| !keys.insert(source.key()))
}

fn validate_source_lists(
    sources: &[ValueFlowSourceSpec],
    kills: &[ValueFlowEdgeKillSpec],
    lists: &ValueFlowSourceLists,
) -> Result<(), ValueFlowPlanError> {
    let valid = |list| {
        let ids = lists.get(list);
        !ids.is_empty() && ids.iter().all(|id| id.index() < sources.len())
    };
    for source in sources {
        if source
            .activation_triggers()
            .is_some_and(|list| !valid(list))
        {
            return Err(ValueFlowPlanError::InvalidSourceActivation);
        }
    }
    if kills.iter().any(|kill| !valid(kill.sources)) {
        return Err(ValueFlowPlanError::InvalidEdgeKill);
    }
    Ok(())
}

fn build_edge_kill_index(
    specs: &[ValueFlowEdgeKillSpec],
    carrier_ids: &HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
) -> Result<EdgeKillIndex, ValueFlowPlanError> {
    let mut by_edge = HashMap::<EdgeKillKey, Vec<BoundValueFlowEdgeKill>>::default();
    for spec in specs {
        let carrier = *carrier_ids
            .get(&spec.carrier)
            .ok_or(ValueFlowPlanError::MissingCarrier)?;
        by_edge
            .entry(EdgeKillKey {
                point: spec.point.clone(),
                target: spec.target,
                kind: spec.kind,
            })
            .or_default()
            .push(BoundValueFlowEdgeKill {
                carrier,
                sources: spec.sources,
                labels: spec.labels.clone(),
            });
    }
    Ok(EdgeKillIndex {
        by_edge: by_edge
            .into_iter()
            .map(|(key, kills)| (key, kills.into_boxed_slice()))
            .collect(),
    })
}

fn adjacent_duplicate<'a, T: Eq + 'a>(mut values: impl Iterator<Item = &'a T>) -> bool {
    let Some(mut previous) = values.next() else {
        return false;
    };
    for value in values {
        if value == previous {
            return true;
        }
        previous = value;
    }
    false
}

#[cfg(test)]
mod activation_properties {
    use super::*;
    use crate::analyzer::semantic::{CancellationToken, SemanticBudget, SemanticRequest};
    use crate::analyzer::{AnalyzerConfig, Language};
    use crate::inline_project::InlineTestProject;
    use crate::value_flow::ValueFlowEventKind;
    use brokk_bifrost_test_macros::hardwon;
    use proptest::prelude::*;

    #[test]
    #[hardwon("#5113: guard plans replicated full source keys in every kill and trigger list")]
    fn source_binding_round_trips_keys_and_rejects_missing_sources() {
        // Materialize once; generated cases only exercise immutable event keys.
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "flow.go",
                "package fixture\nfunc run(value string) string { return value }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("flow.go"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture materialization")
            .available_value()
            .cloned()
            .expect("artifact");
        let root = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("run")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("run");
        let entry = root
            .point_handle(root.semantics().entry_point())
            .expect("entry");
        let carrier = ValueFlowCarrier::Port(
            crate::analyzer::semantic::ProcedurePortHandle::parameter(root.clone(), 0)
                .expect("parameter port"),
        );
        let source = |ordinal| {
            ValueFlowSourceSpec::new(
                ValueFlowEventKey::at_point(&entry, ordinal, ValueFlowEventKind::Source)
                    .expect("source key"),
                entry.clone(),
                ValueFlowObservationPhase::BeforeEffects,
                carrier.clone(),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            )
        };
        proptest!(ProptestConfig::with_cases(32), |(
            count in 1u32..65,
            ordinals in prop::collection::vec(0u32..128, 1..33),
        )| {
            let mut sources = ValueFlowSources::from((0..count).rev().map(&source).collect::<Vec<_>>());
            let ids = ordinals.iter().map(|ordinal| ValueFlowSourceId::new(ordinal % count)).collect::<Vec<_>>();
            let list = sources.intern_list(ids.clone());
            let mut repeated = ids.clone(); repeated.reverse(); repeated.extend(ids);
            prop_assert_eq!(list, sources.intern_list(repeated));
            sources.push(source(count).when_sources_reach(list));
            prop_assert!(validate_source_lists(&sources.specs, &[], &sources.lists).is_ok());
            let mut expected = ordinals.iter().map(|ordinal| source(count - 1 - ordinal % count).key().clone()).collect::<Vec<_>>();
            expected.sort_unstable(); expected.dedup();
            let mut restored = sources.lists.get(list).iter().map(|id| sources.specs[id.index()].key().clone()).collect::<Vec<_>>();
            restored.sort_unstable();
            prop_assert_eq!(restored, expected);
            let mut reordered = ValueFlowSources::from(sources.specs.iter().rev().cloned().collect::<Vec<_>>());
            // A different list-allocation order must not alter input identity.
            reordered.intern_list(Vec::new());
            let reordered_triggers = sources.lists.get(list).iter().map(|id|
                reordered.id_for_key(sources.specs[id.index()].key()).expect("source key is retained")
            ).collect();
            let reordered_list = reordered.intern_list(reordered_triggers);
            reordered.specs[0] = reordered.specs[0].clone().when_sources_reach(reordered_list);
            let first = ValueFlowPlan::try_new(root.clone(), Vec::new(), Vec::new(), sources.clone(), Vec::new()).expect("conditional plan");
            let second = ValueFlowPlan::try_new(root.clone(), Vec::new(), Vec::new(), reordered, Vec::new()).expect("reordered conditional plan");
            prop_assert!(first.has_same_inputs(&second));
            prop_assert_ne!(&first, &second);
            let hash = |plan: &ValueFlowPlan| {
                let mut state = std::collections::hash_map::DefaultHasher::new();
                plan.hash(&mut state);
                std::hash::Hasher::finish(&state)
            };
            prop_assert_eq!(hash(&first), hash(&second));
            let invalid = sources.intern_list(vec![ValueFlowSourceId::new(count + 1)]);
            sources.specs[count as usize] = source(count).when_sources_reach(invalid);
            prop_assert!(matches!(validate_source_lists(&sources.specs, &[], &sources.lists), Err(ValueFlowPlanError::InvalidSourceActivation)));
            sources.specs[count as usize] = source(count).when_sources_reach(list);
            let kill = ValueFlowEdgeKillSpec {
                point: entry.clone(), target: entry.id(), kind: ControlEdgeKind::Normal,
                carrier: carrier.clone(), sources: invalid, labels: None,
            };
            prop_assert!(matches!(validate_source_lists(&sources.specs, &[kill], &sources.lists), Err(ValueFlowPlanError::InvalidEdgeKill)));

        });
    }
}
