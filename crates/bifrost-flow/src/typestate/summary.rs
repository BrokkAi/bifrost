//! Stable, reusable protocol summaries projected from complete typestate solves.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::mem::{size_of, size_of_val};
use std::sync::Arc;

use crate::analyzer::semantic::{
    DurableValueIdentity, IcfgProvider, ProcedureHandle, ReturnTransferKind, SemanticBudget,
    SemanticLocator,
};
use crate::dataflow::{
    DataflowRequest, FactId, MemberReadReceipt, PathQuality, PathQualityFrontier,
    ProcedureSummaryKey, QualityEvidence, ReusableEndSummary, ReusableProcedureSummary,
    ReusableReachedFact, ReusableSummaryError, ReusableSummaryProvider, SemanticProcedureSummary,
    SemanticSummaryArtifactIndex, SemanticSummarySetValidationError, SolverTermination,
    SummaryCallCycle, SummaryCalledProcedures, SummaryDependencyKey, SummaryDimension,
    SummaryDimensionState, SummaryExitKind, SummaryRecursiveGroupKey, SummaryWitness,
    SummaryWitnessStepKind, WitnessFragment, WitnessReconstructionLimits, WitnessStepRow,
    canonical_protocol_summaries_by_artifact, path_evidence_from_frontier,
    path_evidence_has_complete_path, path_evidence_has_proven_complete_path,
    path_evidence_has_proven_path, path_evidence_qualities, validate_recursive_summary_batch,
};

use super::client::solve_typestate_with_reusable_provider_with_receipts;
use super::{
    CompiledProtocol, ProtocolEventKey, ProtocolExpectationKey, ProtocolStateKey,
    TypestateBindingPlan, TypestateBindingSummaryHash, TypestateContextKey, TypestateFact,
    TypestateObjectKey, TypestateObjectRole, TypestateProtocolHash, TypestateSolveError,
    TypestateSubjectKey, TypestateSummaryResult, TypestateUncertainty, TypestateUncertaintySet,
};

pub const PROTOCOL_SUMMARY_SCHEMA_VERSION: u32 = 1;
pub const MAX_PROTOCOL_SUMMARY_ROWS: usize = 65_536;
pub const MAX_PROTOCOL_SUMMARY_EFFECTS: usize = 65_536;
pub const DEFAULT_PROTOCOL_SUMMARY_REPOSITORY_ENTRIES: usize = 4_096;
pub const DEFAULT_PROTOCOL_SUMMARY_REPOSITORY_BYTES: usize = 64 * 1024 * 1024;

fn receipt_is_admissible(receipt: &MemberReadReceipt) -> bool {
    receipt.channels.unattributed_reads == 0
        && receipt.channels.execution_dependences == 0
        && !receipt.channels.reuse_refused
}

/// A key in a protocol receipt. The representation is private so that only
/// `new` (which refuses raw `ReadKey::Index`) and the certifying conversion in
/// `from_member` can construct one: a protocol receipt can never hold a raw
/// Index read.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolReadKey(ProtocolKey);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ProtocolKey {
    Read(crate::analyzer::ReadKey),
    DefinitionIndexInventory(DefinitionIndexInventory),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DefinitionIndexInventory {
    pub raw: crate::analyzer::ReadKey,
    pub normalization_version: Option<u32>,
    pub delegates: Vec<crate::analyzer::Language>,
    pub digest: crate::analyzer::semantic::ids::StableDigest,
}

/// A solve-bound authority over definition buckets. Implementations must use
/// the solve's exact selected snapshots and delegate set, return None when any
/// inventory input is unknown, and never record into an enclosing capture.
pub trait ProtocolInventorySource: fmt::Debug + Send + Sync {
    fn certify(&self, key: &crate::analyzer::ReadKey) -> Option<DefinitionIndexInventory>;
}

impl ProtocolReadKey {
    fn new(key: crate::analyzer::ReadKey) -> Option<Self> {
        if matches!(key, crate::analyzer::ReadKey::Index { .. }) {
            None
        } else {
            Some(Self(ProtocolKey::Read(key)))
        }
    }

    pub fn as_read_key(&self) -> &crate::analyzer::ReadKey {
        match &self.0 {
            ProtocolKey::Read(key) => key,
            ProtocolKey::DefinitionIndexInventory(certificate) => &certificate.raw,
        }
    }

    /// The definition-index certificate this key carries, if it is one.
    pub(super) fn certificate(&self) -> Option<&DefinitionIndexInventory> {
        match &self.0 {
            ProtocolKey::Read(_) => None,
            ProtocolKey::DefinitionIndexInventory(certificate) => Some(certificate),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtocolMemberReceipt {
    keys: HashSet<ProtocolReadKey>,
    channels: brokk_bifrost_core::analyzer::memo_attribution::ReadChannels,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UncoveredProtocolIndexReads(pub Vec<crate::analyzer::ReadKey>);

impl ProtocolMemberReceipt {
    /// The only path from a member receipt to a protocol receipt. A raw
    /// `ReadKey::Index` read names an index bucket, not the answer the probe
    /// consumed. The snapshot-bound inventory capability covers the three
    /// definition families; every other raw Index read refuses publication.
    pub(super) fn from_member(
        member: &MemberReadReceipt,
        inventory: Option<&dyn ProtocolInventorySource>,
    ) -> Result<Self, UncoveredProtocolIndexReads> {
        let _suppression = crate::analyzer::ReadAttribution::for_receipt_verification().install();
        let mut uncovered = Vec::new();
        let mut keys = HashSet::default();
        for key in &member.keys {
            match ProtocolReadKey::new(key.clone()) {
                Some(key) => {
                    keys.insert(key);
                }
                None => {
                    let certificate = match key {
                        crate::analyzer::ReadKey::Index {
                            family:
                                crate::analyzer::IndexFamily::DefinitionExact
                                | crate::analyzer::IndexFamily::DefinitionNormalizedTail
                                | crate::analyzer::IndexFamily::DefinitionIdentifier,
                            ..
                        } => inventory.and_then(|source| source.certify(key)),
                        _ => None,
                    };
                    if let Some(certificate) = certificate {
                        assert_eq!(&certificate.raw, key);
                        keys.insert(ProtocolReadKey(ProtocolKey::DefinitionIndexInventory(
                            certificate,
                        )));
                    } else {
                        uncovered.push(key.clone());
                    }
                }
            }
        }
        if !uncovered.is_empty() {
            uncovered.sort();
            return Err(UncoveredProtocolIndexReads(uncovered));
        }
        Ok(Self {
            keys,
            channels: member.channels,
        })
    }

    pub(super) fn protocol_keys(&self) -> impl Iterator<Item = &ProtocolReadKey> {
        self.keys.iter()
    }

    pub fn keys(&self) -> impl Iterator<Item = &crate::analyzer::ReadKey> {
        self.keys.iter().map(ProtocolReadKey::as_read_key)
    }

    fn is_admissible(&self) -> bool {
        self.channels.unattributed_reads == 0
            && self.channels.execution_dependences == 0
            && !self.channels.reuse_refused
    }
}

#[derive(Default)]
struct ProtocolBindingContracts {
    by_procedure: HashMap<ProcedureSummaryKey, TypestateBindingSummaryHash>,
    recursive_manifests: HashMap<SummaryRecursiveGroupKey, Box<[ProcedureSummaryKey]>>,
}

impl ProtocolBindingContracts {
    fn get(&self, key: &ProcedureSummaryKey) -> Option<&TypestateBindingSummaryHash> {
        self.by_procedure.get(key)
    }

    fn contains_key(&self, key: &ProcedureSummaryKey) -> bool {
        self.by_procedure.contains_key(key)
    }

    fn recursive_manifest(
        &self,
        group: SummaryRecursiveGroupKey,
    ) -> Option<&[ProcedureSummaryKey]> {
        self.recursive_manifests.get(&group).map(Box::as_ref)
    }
}

/// Exact validity identity for one protocol projection of a procedure summary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolSummaryKey {
    procedure: ProcedureSummaryKey,
    protocol: TypestateProtocolHash,
    bindings: TypestateBindingSummaryHash,
    schema_version: u32,
    entry_facts: Box<[ProtocolFactKey]>,
}

impl ProtocolSummaryKey {
    pub fn try_from_semantic_summary(
        semantic_summary: &SemanticProcedureSummary,
        protocol: TypestateProtocolHash,
        bindings: TypestateBindingSummaryHash,
        entry_facts: Vec<ProtocolFactKey>,
    ) -> Result<Self, ProtocolSummaryError> {
        if !matches!(
            semantic_summary
                .coverage()
                .state(SummaryDimension::Protocol),
            SummaryDimensionState::Complete
        ) {
            return Err(ProtocolSummaryError::IncompleteSemanticSummary);
        }
        let mut entry_facts = entry_facts;
        entry_facts.push(ProtocolFactKey::Zero);
        entry_facts.sort_unstable();
        entry_facts.dedup();
        Ok(Self {
            procedure: semantic_summary.key().clone(),
            protocol,
            bindings,
            schema_version: PROTOCOL_SUMMARY_SCHEMA_VERSION,
            entry_facts: entry_facts.into_boxed_slice(),
        })
    }

    pub const fn procedure(&self) -> &ProcedureSummaryKey {
        &self.procedure
    }

    pub const fn protocol(&self) -> TypestateProtocolHash {
        self.protocol
    }

    pub const fn bindings(&self) -> TypestateBindingSummaryHash {
        self.bindings
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn entry_facts(&self) -> &[ProtocolFactKey] {
        &self.entry_facts
    }
}

/// Query-scoped set of complete semantic summaries that authorizes protocol keys.
#[derive(Debug)]
pub struct ProtocolSemanticSummarySet<'summary> {
    summaries: Box<[&'summary SemanticProcedureSummary]>,
    by_artifact: SemanticSummaryArtifactIndex,
}

impl<'summary> ProtocolSemanticSummarySet<'summary> {
    pub fn try_new(
        summaries: Vec<&'summary SemanticProcedureSummary>,
    ) -> Result<Self, ProtocolSummaryError> {
        let (summaries, by_artifact) = canonical_protocol_summaries_by_artifact(summaries)
            .map_err(|error| match error {
                SemanticSummarySetValidationError::Incomplete => {
                    ProtocolSummaryError::IncompleteSemanticSummary
                }
                SemanticSummarySetValidationError::AmbiguousKey => {
                    ProtocolSummaryError::AmbiguousSemanticSummary
                }
            })?;
        Ok(Self {
            summaries,
            by_artifact,
        })
    }

    fn unique_summary_for(&self, procedure: &ProcedureHandle) -> Option<&SemanticProcedureSummary> {
        crate::semantic_summary::unique_semantic_summary(
            &self.by_artifact,
            &self.summaries,
            procedure,
        )
    }

    /// Diagnostic presence only: never serves rows and never records a read.
    pub(super) fn has_compatible_rows_for_diagnostics(
        &self,
        repository: &CompleteProtocolSummaryStorage,
        protocol: &CompiledProtocol,
        bindings: &TypestateBindingPlan,
    ) -> bool {
        let Some(contracts) = self.compute_binding_contracts(bindings, || false) else {
            return false;
        };
        repository.entries.values().any(|summary| {
            summary.key().protocol() == protocol.hash()
                && contracts.get(summary.key().procedure()) == Some(&summary.key().bindings())
        })
    }

    /// The stored rows this solve may consult, copied from borrowed storage so
    /// that only compatible rows are cloned, not the whole repository.
    pub(super) fn compatible_repository(
        &self,
        storage: &CompleteProtocolSummaryStorage,
        attribution: crate::analyzer::workspace_authority::OwnedMemoCapability,
        protocol: &CompiledProtocol,
        bindings: &TypestateBindingPlan,
    ) -> CompleteProtocolSummaryRepository {
        let mut compatible =
            CompleteProtocolSummaryRepository::with_limits(storage.limits(), attribution);
        let Some(contracts) = self.compute_binding_contracts(bindings, || false) else {
            return compatible;
        };
        for summary in storage.entries.values() {
            if summary.key().protocol() == protocol.hash()
                && contracts.get(summary.key().procedure()) == Some(&summary.key().bindings())
            {
                compatible.insert(summary.clone());
            }
        }
        compatible
    }

    /// Compute the propagation-relevant binding closure for a protocol artifact.
    ///
    /// Dependency-free procedures use only their local bindings. Recursive
    /// groups share one hash over every member's local contract. Non-recursive
    /// composed procedures and SCCs with external dependencies fail closed
    /// until protocol effects can be flattened with an exact outer-entry map.
    fn binding_contract_for(
        &self,
        summary: &SemanticProcedureSummary,
        bindings: &TypestateBindingPlan,
    ) -> Option<TypestateBindingSummaryHash> {
        self.compute_binding_contracts(bindings, || false)?
            .by_procedure
            .remove(summary.key())
    }

    fn build_binding_contracts(
        &self,
        bindings: &TypestateBindingPlan,
        request: &mut DataflowRequest<'_>,
    ) -> Option<ProtocolBindingContracts> {
        let work = self.summaries.iter().fold(0_usize, |work, summary| {
            work.saturating_add(1)
                .saturating_add(summary.dependencies().len())
                .saturating_add(summary.recursive_topology().len())
        });
        if request
            .reserve(crate::dataflow::SolverWork {
                callback_rows: work,
                ..crate::dataflow::SolverWork::default()
            })
            .is_some()
        {
            return None;
        }
        self.compute_binding_contracts(bindings, || request.cancellation.is_cancelled())
    }

    fn compute_binding_contracts<Cancelled>(
        &self,
        bindings: &TypestateBindingPlan,
        cancelled: Cancelled,
    ) -> Option<ProtocolBindingContracts>
    where
        Cancelled: Fn() -> bool,
    {
        let mut contracts = ProtocolBindingContracts {
            by_procedure: HashMap::with_capacity(self.summaries.len()),
            recursive_manifests: HashMap::new(),
        };
        let mut recursive_groups =
            HashMap::<SummaryRecursiveGroupKey, Vec<&SemanticProcedureSummary>>::new();
        for summary in &self.summaries {
            if cancelled() {
                return None;
            }
            if let Some(group) = summary.key().recursive_group() {
                recursive_groups.entry(group).or_default().push(summary);
            } else if summary.dependencies().is_empty() {
                contracts.by_procedure.insert(
                    summary.key().clone(),
                    bindings
                        .summary_hash_for(summary.key().artifact(), summary.key().declaration()),
                );
            }
        }
        for members in recursive_groups.into_values() {
            if cancelled() {
                return None;
            }
            if members.iter().any(|member| {
                member.dependencies().iter().any(|dependency| {
                    cancelled() || matches!(dependency, SummaryDependencyKey::Complete(_))
                })
            }) || validate_recursive_summary_batch(&members).is_err()
            {
                if cancelled() {
                    return None;
                }
                continue;
            }
            let mut bytes =
                Vec::with_capacity(32_usize.saturating_add(members.len().saturating_mul(64)));
            bytes.extend_from_slice(b"bifrost-protocol-binding-recursive-closure/v1");
            for member in &members {
                if cancelled() {
                    return None;
                }
                bytes.extend_from_slice(member.key().fingerprint().as_bytes());
                bytes.extend_from_slice(
                    bindings
                        .summary_hash_for(member.key().artifact(), member.key().declaration())
                        .as_bytes(),
                );
            }
            let contract = TypestateBindingSummaryHash::from_canonical_bytes(&bytes);
            let group = members[0]
                .key()
                .recursive_group()
                .expect("validated recursive members share a group");
            let manifest = members
                .iter()
                .map(|member| member.key().clone())
                .collect::<Vec<_>>()
                .into_boxed_slice();
            for member in members {
                contracts
                    .by_procedure
                    .insert(member.key().clone(), contract);
            }
            contracts.recursive_manifests.insert(group, manifest);
        }
        Some(contracts)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolEventBindingKey {
    event: ProtocolEventKey,
    subject: TypestateSubjectKey,
    site: SemanticLocator,
    context: TypestateContextKey,
    order: u32,
    role: TypestateObjectRole,
}

impl ProtocolEventBindingKey {
    pub const fn event(&self) -> &ProtocolEventKey {
        &self.event
    }

    pub const fn subject(&self) -> &TypestateSubjectKey {
        &self.subject
    }

    pub const fn site(&self) -> &SemanticLocator {
        &self.site
    }

    pub const fn context(&self) -> &TypestateContextKey {
        &self.context
    }

    pub const fn order(&self) -> u32 {
        self.order
    }

    pub const fn role(&self) -> TypestateObjectRole {
        self.role
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolTerminalBindingKey {
    expectation: ProtocolExpectationKey,
    subject: TypestateSubjectKey,
    site: SemanticLocator,
    context: TypestateContextKey,
    role: TypestateObjectRole,
}

impl ProtocolTerminalBindingKey {
    pub const fn expectation(&self) -> &ProtocolExpectationKey {
        &self.expectation
    }

    pub const fn subject(&self) -> &TypestateSubjectKey {
        &self.subject
    }

    pub const fn site(&self) -> &SemanticLocator {
        &self.site
    }

    pub const fn context(&self) -> &TypestateContextKey {
        &self.context
    }

    pub const fn role(&self) -> TypestateObjectRole {
        self.role
    }
}

/// Canonical uncertainty identity independent of the live compact bit layout.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolUncertaintyKey(Box<[TypestateUncertainty]>);

impl ProtocolUncertaintyKey {
    pub fn values(&self) -> &[TypestateUncertainty] {
        &self.0
    }

    fn from_live(live: TypestateUncertaintySet) -> Self {
        const ALL: [TypestateUncertainty; 7] = [
            TypestateUncertainty::AmbiguousDispatch,
            TypestateUncertainty::UnknownCall,
            TypestateUncertainty::ExternalCall,
            TypestateUncertainty::Escape,
            TypestateUncertainty::IncompleteAnalysis,
            TypestateUncertainty::UnmatchedEvent,
            TypestateUncertainty::ConditionalAlias,
        ];
        Self(
            ALL.into_iter()
                .filter(|uncertainty| live.contains(*uncertainty))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        )
    }

    fn to_live(&self) -> TypestateUncertaintySet {
        self.0
            .iter()
            .copied()
            .fold(TypestateUncertaintySet::default(), |set, uncertainty| {
                set.with(uncertainty)
            })
    }
}

/// Stable counterpart of every live typestate fact kind.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolFactKey {
    Zero,
    State {
        subject: TypestateSubjectKey,
        state: ProtocolStateKey,
        uncertainty: ProtocolUncertaintyKey,
        abstained: bool,
    },
    Violation {
        event: ProtocolEventBindingKey,
        from: ProtocolStateKey,
        to: ProtocolStateKey,
        uncertainty: ProtocolUncertaintyKey,
        abstained: bool,
    },
    NonViolation {
        event: ProtocolEventBindingKey,
        uncertainty: ProtocolUncertaintyKey,
        abstained: bool,
    },
    Terminal {
        expectation: ProtocolTerminalBindingKey,
        state: ProtocolStateKey,
        uncertainty: ProtocolUncertaintyKey,
        abstained: bool,
    },
}

impl ProtocolFactKey {
    pub fn from_live(
        fact: TypestateFact,
        protocol: &CompiledProtocol,
        bindings: &TypestateBindingPlan,
    ) -> Result<Self, ProtocolSummaryError> {
        if let Some(plan) = fact.binding_plan_hash()
            && plan != bindings.hash()
        {
            return Err(ProtocolSummaryError::FactBindingPlanMismatch);
        }
        let uncertainty = ProtocolUncertaintyKey::from_live(fact.uncertainty());
        let abstained = fact.abstained();
        if fact == TypestateFact::zero() {
            return Ok(Self::Zero);
        }
        let subject_id = fact.subject().ok_or(ProtocolSummaryError::InvalidFact)?;
        let subject = bindings
            .subject(subject_id)
            .ok_or(ProtocolSummaryError::UnknownSubject)?
            .key()
            .clone();
        if let Some((_, state, _, _)) = fact.state_observation() {
            return Ok(Self::State {
                subject,
                state: state_key(protocol, state)?,
                uncertainty,
                abstained,
            });
        }
        if let Some(violation) = fact.violation() {
            return Ok(Self::Violation {
                event: event_binding_key(protocol, bindings, violation.event_binding())?,
                from: state_key(protocol, violation.from())?,
                to: state_key(protocol, violation.to())?,
                uncertainty,
                abstained,
            });
        }
        if let Some(event_binding) = fact.non_violation_binding() {
            return Ok(Self::NonViolation {
                event: event_binding_key(protocol, bindings, event_binding)?,
                uncertainty,
                abstained,
            });
        }
        if let Some((terminal_binding, state)) = fact.terminal_observation() {
            return Ok(Self::Terminal {
                expectation: terminal_binding_key(protocol, bindings, terminal_binding)?,
                state: state_key(protocol, state)?,
                uncertainty,
                abstained,
            });
        }
        Err(ProtocolSummaryError::InvalidFact)
    }
}

struct ProtocolLiveRemap<'live> {
    bindings: &'live TypestateBindingPlan,
    states: HashMap<ProtocolStateKey, super::ProtocolStateId>,
    subjects: HashMap<TypestateSubjectKey, super::TypestateSubjectId>,
    events: HashMap<ProtocolEventBindingKey, super::TypestateEventBindingId>,
    terminals: HashMap<ProtocolTerminalBindingKey, super::TypestateTerminalBindingId>,
}

impl<'live> ProtocolLiveRemap<'live> {
    fn try_new(
        protocol: &CompiledProtocol,
        bindings: &'live TypestateBindingPlan,
    ) -> Result<Self, ProtocolSummaryError> {
        let states = protocol
            .states()
            .map(|(id, key)| (key.clone(), id))
            .collect();
        let subjects = bindings
            .subjects()
            .iter()
            .map(|subject| (subject.key().clone(), subject.id()))
            .collect();
        let events = bindings
            .event_bindings()
            .iter()
            .map(|binding| {
                event_binding_key(protocol, bindings, binding.id()).map(|key| (key, binding.id()))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;
        let terminals = bindings
            .terminal_bindings()
            .iter()
            .map(|binding| {
                terminal_binding_key(protocol, bindings, binding.id())
                    .map(|key| (key, binding.id()))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;
        Ok(Self {
            bindings,
            states,
            subjects,
            events,
            terminals,
        })
    }

    fn fact(&self, fact: &ProtocolFactKey) -> Result<TypestateFact, ProtocolSummaryError> {
        if matches!(fact, ProtocolFactKey::Zero) {
            Ok(TypestateFact::zero())
        } else {
            self.nonzero_fact(fact)
        }
    }

    fn nonzero_fact(&self, fact: &ProtocolFactKey) -> Result<TypestateFact, ProtocolSummaryError> {
        match fact {
            ProtocolFactKey::Zero => Ok(TypestateFact::zero()),
            ProtocolFactKey::State {
                subject,
                state,
                uncertainty,
                abstained,
            } => Ok(TypestateFact::summary_state(
                self.bindings.hash(),
                self.subject(subject)?,
                self.state(state)?,
                uncertainty.to_live(),
                *abstained,
            )),
            ProtocolFactKey::Violation {
                event,
                from,
                to,
                uncertainty,
                abstained,
            } => Ok(TypestateFact::summary_violation(
                self.bindings.hash(),
                self.subject(event.subject())?,
                self.event(event)?,
                self.state(from)?,
                self.state(to)?,
                uncertainty.to_live(),
                *abstained,
            )),
            ProtocolFactKey::NonViolation {
                event,
                uncertainty,
                abstained,
            } => Ok(TypestateFact::summary_non_violation(
                self.bindings.hash(),
                self.subject(event.subject())?,
                self.event(event)?,
                uncertainty.to_live(),
                *abstained,
            )),
            ProtocolFactKey::Terminal {
                expectation,
                state,
                uncertainty,
                abstained,
            } => Ok(TypestateFact::summary_terminal(
                self.bindings.hash(),
                self.subject(expectation.subject())?,
                self.terminal(expectation)?,
                self.state(state)?,
                uncertainty.to_live(),
                *abstained,
            )),
        }
    }

    fn state(
        &self,
        key: &ProtocolStateKey,
    ) -> Result<super::ProtocolStateId, ProtocolSummaryError> {
        self.states
            .get(key)
            .copied()
            .ok_or(ProtocolSummaryError::UnknownState)
    }

    fn subject(
        &self,
        key: &TypestateSubjectKey,
    ) -> Result<super::TypestateSubjectId, ProtocolSummaryError> {
        self.subjects
            .get(key)
            .copied()
            .ok_or(ProtocolSummaryError::UnknownSubject)
    }

    fn event(
        &self,
        key: &ProtocolEventBindingKey,
    ) -> Result<super::TypestateEventBindingId, ProtocolSummaryError> {
        self.events
            .get(key)
            .copied()
            .ok_or(ProtocolSummaryError::UnknownEventBinding)
    }

    fn terminal(
        &self,
        key: &ProtocolTerminalBindingKey,
    ) -> Result<super::TypestateTerminalBindingId, ProtocolSummaryError> {
        self.terminals
            .get(key)
            .copied()
            .ok_or(ProtocolSummaryError::UnknownTerminalBinding)
    }
}

impl ProtocolFactKey {
    pub(crate) fn retained_bytes(&self) -> usize {
        size_of::<Self>().saturating_add(protocol_fact_heap_bytes(self))
    }

    fn is_observed_effect(&self) -> bool {
        match self {
            Self::Zero => false,
            Self::State {
                uncertainty,
                abstained,
                ..
            } => !uncertainty.values().is_empty() || *abstained,
            Self::Violation { .. } | Self::NonViolation { .. } | Self::Terminal { .. } => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolPathEvidence(u8);

type ProtocolWitnessFragments = Box<[(PathQuality, Box<[WitnessStepRow<ProtocolFactKey>]>)]>;

impl ProtocolPathEvidence {
    pub const fn has_proven_path(self) -> bool {
        path_evidence_has_proven_path(self.0)
    }

    pub const fn has_complete_path(self) -> bool {
        path_evidence_has_complete_path(self.0)
    }

    pub const fn has_proven_complete_path(self) -> bool {
        path_evidence_has_proven_complete_path(self.0)
    }

    fn from_frontier(frontier: PathQualityFrontier) -> Self {
        Self(path_evidence_from_frontier(frontier))
    }

    fn qualities(self) -> Box<[PathQuality]> {
        path_evidence_qualities(self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolSummaryRow {
    input: ProtocolFactKey,
    exit_kind: SummaryExitKind,
    output: ProtocolFactKey,
    evidence: ProtocolPathEvidence,
    fragments: ProtocolWitnessFragments,
}

impl ProtocolSummaryRow {
    pub const fn input(&self) -> &ProtocolFactKey {
        &self.input
    }

    pub const fn exit_kind(&self) -> SummaryExitKind {
        self.exit_kind
    }

    pub const fn output(&self) -> &ProtocolFactKey {
        &self.output
    }

    pub const fn evidence(&self) -> ProtocolPathEvidence {
        self.evidence
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolObservedEffect {
    input: ProtocolFactKey,
    site: SemanticLocator,
    observation: ProtocolFactKey,
    evidence: ProtocolPathEvidence,
    fragments: ProtocolWitnessFragments,
}

impl ProtocolObservedEffect {
    pub const fn input(&self) -> &ProtocolFactKey {
        &self.input
    }

    pub const fn observation(&self) -> &ProtocolFactKey {
        &self.observation
    }

    pub const fn site(&self) -> &SemanticLocator {
        &self.site
    }

    pub const fn evidence(&self) -> ProtocolPathEvidence {
        self.evidence
    }
}

/// A complete, canonical procedure relation without dense IDs or witnesses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolSummary {
    key: ProtocolSummaryKey,
    rows: Box<[ProtocolSummaryRow]>,
    effects: Box<[ProtocolObservedEffect]>,
    receipt: ProtocolMemberReceipt,
}

impl ProtocolSummary {
    fn try_new(
        key: ProtocolSummaryKey,
        mut rows: Vec<ProtocolSummaryRow>,
        mut effects: Vec<ProtocolObservedEffect>,
    ) -> Result<Self, ProtocolSummaryError> {
        if rows
            .iter()
            .any(|row| key.entry_facts.binary_search(&row.input).is_err())
            || effects
                .iter()
                .any(|effect| key.entry_facts.binary_search(&effect.input).is_err())
        {
            return Err(ProtocolSummaryError::EntryFactCoverageMismatch);
        }
        canonicalize_rows(&mut rows)?;
        canonicalize_effects(&mut effects)?;
        Ok(Self {
            key,
            rows: rows.into_boxed_slice(),
            effects: effects.into_boxed_slice(),
            receipt: ProtocolMemberReceipt::default(),
        })
    }

    pub fn receipt(&self) -> &ProtocolMemberReceipt {
        &self.receipt
    }

    pub const fn key(&self) -> &ProtocolSummaryKey {
        &self.key
    }

    pub fn rows(&self) -> &[ProtocolSummaryRow] {
        &self.rows
    }

    pub fn effects(&self) -> &[ProtocolObservedEffect] {
        &self.effects
    }

    fn row_range(&self, input: &ProtocolFactKey) -> std::ops::Range<usize> {
        crate::dataflow::sorted_equal_range_by(&self.rows, input, |row, input| row.input.cmp(input))
    }

    fn effect_range(&self, input: &ProtocolFactKey) -> std::ops::Range<usize> {
        let start = self.effects.partition_point(|effect| effect.input < *input);
        let end = start + self.effects[start..].partition_point(|effect| effect.input == *input);
        start..end
    }

    pub fn apply(
        &self,
        entry_facts: &[TypestateFact],
        protocol: &CompiledProtocol,
        bindings: &TypestateBindingPlan,
        semantic_summaries: &ProtocolSemanticSummarySet<'_>,
    ) -> Result<ProtocolSummaryApplication, ProtocolSummaryError> {
        let semantic = semantic_summaries
            .summaries
            .iter()
            .copied()
            .find(|summary| summary.key() == self.key.procedure())
            .ok_or(ProtocolSummaryError::ProcedureMismatch)?;
        let expected_bindings = semantic_summaries
            .binding_contract_for(semantic, bindings)
            .ok_or(ProtocolSummaryError::KeyBindingPlanMismatch)?;
        self.apply_with_binding_contract(entry_facts, protocol, bindings, expected_bindings)
    }

    fn apply_with_binding_contract(
        &self,
        entry_facts: &[TypestateFact],
        protocol: &CompiledProtocol,
        bindings: &TypestateBindingPlan,
        expected_bindings: TypestateBindingSummaryHash,
    ) -> Result<ProtocolSummaryApplication, ProtocolSummaryError> {
        validate_key_inputs(&self.key, protocol, expected_bindings)?;
        let mut inputs = entry_facts
            .iter()
            .copied()
            .map(|fact| ProtocolFactKey::from_live(fact, protocol, bindings))
            .collect::<Result<Vec<_>, _>>()?;
        inputs.push(ProtocolFactKey::Zero);
        inputs.sort_unstable();
        inputs.dedup();
        if inputs.as_slice() != self.key.entry_facts() {
            return Err(ProtocolSummaryError::EntryFactCoverageMismatch);
        }
        let remap = ProtocolLiveRemap::try_new(protocol, bindings)?;

        let mut outcomes = Vec::new();
        for input in &inputs {
            for row in &self.rows[self.row_range(input)] {
                outcomes.push(ProtocolSummaryOutcome {
                    exit_kind: row.exit_kind,
                    fact: remap.fact(&row.output)?,
                    stable_fact: row.output.clone(),
                    evidence: row.evidence,
                });
            }
        }
        outcomes.sort_unstable();
        outcomes.dedup();

        let mut effects = Vec::new();
        for input in &inputs {
            for effect in &self.effects[self.effect_range(input)] {
                effects.push(ProtocolAppliedEffect {
                    site: effect.site.clone(),
                    fact: remap.fact(&effect.observation)?,
                    stable_fact: effect.observation.clone(),
                    evidence: effect.evidence,
                });
            }
        }
        effects.sort_unstable();
        effects.dedup();
        Ok(ProtocolSummaryApplication {
            outcomes: outcomes.into_boxed_slice(),
            effects: effects.into_boxed_slice(),
        })
    }

    pub fn retained_bytes(&self) -> usize {
        let mut receipt_heap = crate::analyzer::store::cache_budget::RetainedHeap::default();
        receipt_heap.add(
            self.receipt
                .keys
                .capacity()
                .saturating_mul(size_of::<ProtocolReadKey>()),
        );
        for key in self.receipt.keys() {
            crate::analyzer::store::cache_budget::retained_read_key(&mut receipt_heap, key);
        }
        for key in self.receipt.protocol_keys() {
            if let Some(certificate) = key.certificate() {
                receipt_heap
                    .add(certificate.delegates.capacity() * size_of::<crate::analyzer::Language>());
            }
        }
        size_of::<Self>()
            .saturating_add(receipt_heap.total())
            .saturating_add(protocol_key_heap_bytes(&self.key))
            .saturating_add(size_of::<ProtocolSummaryKey>())
            .saturating_add(protocol_key_heap_bytes(&self.key))
            .saturating_add(size_of_val(self.rows()))
            .saturating_add(self.rows.iter().fold(0_usize, |total, row| {
                total
                    .saturating_add(protocol_fact_heap_bytes(&row.input))
                    .saturating_add(protocol_fact_heap_bytes(&row.output))
                    .saturating_add(protocol_fragment_bytes(&row.fragments))
            }))
            .saturating_add(size_of_val(self.effects()))
            .saturating_add(self.effects.iter().fold(0_usize, |total, effect| {
                total
                    .saturating_add(protocol_fact_heap_bytes(&effect.input))
                    .saturating_add(crate::value_flow::semantic_locator_heap_bytes(&effect.site))
                    .saturating_add(protocol_fact_heap_bytes(&effect.observation))
                    .saturating_add(protocol_fragment_bytes(&effect.fragments))
            }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolSummaryOutcome {
    exit_kind: SummaryExitKind,
    fact: TypestateFact,
    stable_fact: ProtocolFactKey,
    evidence: ProtocolPathEvidence,
}

impl ProtocolSummaryOutcome {
    pub const fn exit_kind(&self) -> SummaryExitKind {
        self.exit_kind
    }

    pub const fn fact(&self) -> TypestateFact {
        self.fact
    }

    pub const fn stable_fact(&self) -> &ProtocolFactKey {
        &self.stable_fact
    }

    pub const fn evidence(&self) -> ProtocolPathEvidence {
        self.evidence
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolAppliedEffect {
    site: SemanticLocator,
    fact: TypestateFact,
    stable_fact: ProtocolFactKey,
    evidence: ProtocolPathEvidence,
}

impl ProtocolAppliedEffect {
    pub const fn site(&self) -> &SemanticLocator {
        &self.site
    }

    pub const fn fact(&self) -> TypestateFact {
        self.fact
    }

    pub const fn stable_fact(&self) -> &ProtocolFactKey {
        &self.stable_fact
    }

    pub const fn evidence(&self) -> ProtocolPathEvidence {
        self.evidence
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolSummaryApplication {
    outcomes: Box<[ProtocolSummaryOutcome]>,
    effects: Box<[ProtocolAppliedEffect]>,
}

impl ProtocolSummaryApplication {
    pub fn outcomes(&self) -> &[ProtocolSummaryOutcome] {
        &self.outcomes
    }

    pub fn effects(&self) -> &[ProtocolAppliedEffect] {
        &self.effects
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolSummaryPublicationOutcome {
    Inserted,
    AlreadyPresent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolSummaryRepositoryLimits {
    pub max_entries: usize,
    pub max_bytes: usize,
}

impl Default for ProtocolSummaryRepositoryLimits {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_PROTOCOL_SUMMARY_REPOSITORY_ENTRIES,
            max_bytes: DEFAULT_PROTOCOL_SUMMARY_REPOSITORY_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProtocolSummaryLookupKey {
    procedure: ProcedureSummaryKey,
    protocol: TypestateProtocolHash,
    bindings: TypestateBindingSummaryHash,
    schema_version: u32,
    entry: ProtocolFactKey,
}

impl ProtocolSummaryLookupKey {
    fn new(key: &ProtocolSummaryKey, entry: &ProtocolFactKey) -> Self {
        Self {
            procedure: key.procedure.clone(),
            protocol: key.protocol,
            bindings: key.bindings,
            schema_version: key.schema_version,
            entry: entry.clone(),
        }
    }
}

/// A query-bound view; shared owners retain only CompleteProtocolSummaryStorage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolReceiptVerdict {
    Current,
    Stale,
    Unverifiable,
}

pub trait ProtocolReceiptVerifier: fmt::Debug + Send + Sync {
    fn verify(&self, receipt: &ProtocolMemberReceipt) -> ProtocolReceiptVerdict;
}

#[derive(Debug, Clone)]
pub struct CompleteProtocolSummaryRepository {
    storage: CompleteProtocolSummaryStorage,
    attribution: crate::analyzer::workspace_authority::OwnedMemoCapability,
    receipt_verifier: Option<Arc<dyn ProtocolReceiptVerifier>>,
    inventory_source: Option<Arc<dyn ProtocolInventorySource>>,
}

impl CompleteProtocolSummaryRepository {
    pub fn new(attribution: crate::analyzer::workspace_authority::OwnedMemoCapability) -> Self {
        Self::with_limits(ProtocolSummaryRepositoryLimits::default(), attribution)
    }
    pub fn with_limits(
        limits: ProtocolSummaryRepositoryLimits,
        attribution: crate::analyzer::workspace_authority::OwnedMemoCapability,
    ) -> Self {
        Self {
            storage: CompleteProtocolSummaryStorage::with_limits(limits),
            attribution,
            receipt_verifier: None,
            inventory_source: None,
        }
    }

    pub fn bind_inventory_source(&mut self, source: Arc<dyn ProtocolInventorySource>) {
        self.inventory_source = Some(source);
    }

    /// Bind a verifier for this request's selected snapshot.
    pub fn bind_receipt_verifier(&mut self, verifier: Arc<dyn ProtocolReceiptVerifier>) {
        self.receipt_verifier = Some(verifier);
    }

    pub fn clear_receipt_verifier(&mut self) {
        self.receipt_verifier = None;
    }
    pub fn get(&self, key: &ProtocolSummaryKey) -> Option<&ProtocolSummary> {
        self.storage.get(key)
    }
    pub fn len(&self) -> usize {
        self.storage.len()
    }
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty()
    }
    pub const fn limits(&self) -> ProtocolSummaryRepositoryLimits {
        self.storage.limits()
    }
    pub const fn retained_bytes(&self) -> usize {
        self.storage.retained_bytes()
    }
    pub fn publish(
        &mut self,
        summary: ProtocolSummary,
    ) -> Result<ProtocolSummaryPublicationOutcome, ProtocolSummaryPublicationError> {
        self.storage.publish(summary)
    }
    pub fn publish_scc(
        &mut self,
        summaries: Vec<ProtocolSummary>,
        semantic: &[&SemanticProcedureSummary],
    ) -> Result<ProtocolSummaryPublicationOutcome, ProtocolSummaryPublicationError> {
        self.storage.publish_scc(summaries, semantic)
    }
    fn publish_scc_with_manifest(
        &mut self,
        summaries: Vec<ProtocolSummary>,
        group: SummaryRecursiveGroupKey,
        keys: &[ProcedureSummaryKey],
    ) -> Result<ProtocolSummaryPublicationOutcome, ProtocolSummaryPublicationError> {
        self.storage
            .publish_scc_with_manifest(summaries, group, keys)
    }
    fn insert(&mut self, summary: ProtocolSummary) {
        self.storage.insert(summary);
    }
    fn matching_summary_for_entry(
        &self,
        procedure: &ProcedureSummaryKey,
        protocol: TypestateProtocolHash,
        bindings: TypestateBindingSummaryHash,
        entry: &ProtocolFactKey,
    ) -> Option<&ProtocolSummary> {
        self.storage
            .matching_summary_for_entry(procedure, protocol, bindings, entry)
    }
    pub(super) fn into_publication_batches(self) -> ProtocolSummaryPublicationBatches {
        self.storage.into_publication_batches()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CompleteProtocolSummaryStorage {
    entries: HashMap<ProtocolSummaryKey, ProtocolSummary>,
    by_entry: HashMap<ProtocolSummaryLookupKey, ProtocolSummaryKey>,
    retained_bytes: usize,
    limits: ProtocolSummaryRepositoryLimits,
}

impl Default for CompleteProtocolSummaryStorage {
    fn default() -> Self {
        Self::with_limits(ProtocolSummaryRepositoryLimits::default())
    }
}

impl CompleteProtocolSummaryStorage {
    pub fn with_limits(limits: ProtocolSummaryRepositoryLimits) -> Self {
        Self {
            entries: HashMap::new(),
            by_entry: HashMap::new(),
            retained_bytes: 0,
            limits,
        }
    }

    pub fn get(&self, key: &ProtocolSummaryKey) -> Option<&ProtocolSummary> {
        self.entries.get(key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub const fn limits(&self) -> ProtocolSummaryRepositoryLimits {
        self.limits
    }

    pub fn publish(
        &mut self,
        summary: ProtocolSummary,
    ) -> Result<ProtocolSummaryPublicationOutcome, ProtocolSummaryPublicationError> {
        if summary.key.procedure().is_recursive() {
            return Err(ProtocolSummaryPublicationError::RecursiveSummaryRequiresBatch);
        }
        self.publish_preflighted(summary)
    }

    pub fn publish_scc(
        &mut self,
        summaries: Vec<ProtocolSummary>,
        semantic_summaries: &[&SemanticProcedureSummary],
    ) -> Result<ProtocolSummaryPublicationOutcome, ProtocolSummaryPublicationError> {
        let first = summaries
            .first()
            .ok_or(ProtocolSummaryPublicationError::EmptyRecursiveBatch)?;
        let group = first
            .key
            .procedure()
            .recursive_group()
            .ok_or(ProtocolSummaryPublicationError::NonRecursiveSummaryInBatch)?;
        if summaries.len() != group.member_count() as usize {
            return Err(ProtocolSummaryPublicationError::IncompleteRecursiveBatch);
        }
        if semantic_summaries.len() != summaries.len() {
            return Err(ProtocolSummaryPublicationError::IncompleteRecursiveBatch);
        }
        let validated = validate_recursive_summary_batch(semantic_summaries)
            .map_err(|_| ProtocolSummaryPublicationError::InvalidRecursiveManifest)?;
        if validated.group != group {
            return Err(ProtocolSummaryPublicationError::MismatchedRecursiveManifest);
        }
        let semantic_keys = semantic_summaries
            .iter()
            .map(|summary| summary.key().clone())
            .collect::<Vec<_>>();
        self.publish_scc_with_manifest(summaries, group, &semantic_keys)
    }

    fn publish_scc_with_manifest(
        &mut self,
        summaries: Vec<ProtocolSummary>,
        group: SummaryRecursiveGroupKey,
        semantic_keys: &[ProcedureSummaryKey],
    ) -> Result<ProtocolSummaryPublicationOutcome, ProtocolSummaryPublicationError> {
        let first = summaries
            .first()
            .ok_or(ProtocolSummaryPublicationError::EmptyRecursiveBatch)?;
        if summaries.len() != group.member_count() as usize
            || semantic_keys.len() != summaries.len()
        {
            return Err(ProtocolSummaryPublicationError::IncompleteRecursiveBatch);
        }
        let semantic_keys = semantic_keys.iter().collect::<HashSet<_>>();
        let mut keys = HashSet::with_capacity(summaries.len());
        let mut identities = HashSet::with_capacity(summaries.len());
        for summary in &summaries {
            if summary.key.procedure().recursive_group() != Some(group) {
                return Err(ProtocolSummaryPublicationError::MismatchedRecursiveGroup);
            }
            if !semantic_keys.contains(summary.key.procedure()) {
                return Err(ProtocolSummaryPublicationError::MismatchedRecursiveGroup);
            }
            if !keys.insert(summary.key.clone()) {
                return Err(ProtocolSummaryPublicationError::DuplicateKey);
            }
            if !identities.insert(summary.key.procedure().identity().clone()) {
                return Err(ProtocolSummaryPublicationError::DuplicateProcedure);
            }
            if summary.key.protocol != first.key.protocol
                || summary.key.bindings != first.key.bindings
                || summary.key.schema_version != first.key.schema_version
            {
                return Err(ProtocolSummaryPublicationError::MismatchedProtocolContract);
            }
            if let Some(existing) = self.entries.get(summary.key())
                && existing != summary
            {
                return Err(ProtocolSummaryPublicationError::ConflictingEntry);
            }
        }
        let additions = summaries
            .iter()
            .filter(|summary| !self.entries.contains_key(summary.key()))
            .collect::<Vec<_>>();
        self.preflight_entry_index(&additions)?;
        self.preflight_capacity(&additions)?;
        if additions.is_empty() {
            return Ok(ProtocolSummaryPublicationOutcome::AlreadyPresent);
        }
        for summary in summaries {
            if !self.entries.contains_key(summary.key()) {
                self.insert(summary);
            }
        }
        Ok(ProtocolSummaryPublicationOutcome::Inserted)
    }

    fn publish_preflighted(
        &mut self,
        summary: ProtocolSummary,
    ) -> Result<ProtocolSummaryPublicationOutcome, ProtocolSummaryPublicationError> {
        if let Some(existing) = self.entries.get(summary.key()) {
            return if existing == &summary {
                Ok(ProtocolSummaryPublicationOutcome::AlreadyPresent)
            } else {
                Err(ProtocolSummaryPublicationError::ConflictingEntry)
            };
        }
        self.preflight_entry_index(&[&summary])?;
        self.preflight_capacity(&[&summary])?;
        self.insert(summary);
        Ok(ProtocolSummaryPublicationOutcome::Inserted)
    }

    fn preflight_capacity(
        &self,
        additions: &[&ProtocolSummary],
    ) -> Result<(), ProtocolSummaryPublicationError> {
        let added_bytes = additions.iter().fold(0_usize, |total, summary| {
            total.saturating_add(protocol_repository_entry_bytes(summary))
        });
        let (entries, bytes) = crate::dataflow::summary_capacity_totals(
            self.entries.len(),
            self.retained_bytes,
            additions.len(),
            added_bytes,
        );
        if entries > self.limits.max_entries {
            return Err(ProtocolSummaryPublicationError::EntryLimitExceeded);
        }
        if bytes > self.limits.max_bytes {
            return Err(ProtocolSummaryPublicationError::ByteLimitExceeded);
        }
        Ok(())
    }

    fn preflight_entry_index(
        &self,
        additions: &[&ProtocolSummary],
    ) -> Result<(), ProtocolSummaryPublicationError> {
        let mut staged = HashMap::<ProtocolSummaryLookupKey, &ProtocolSummary>::new();
        for summary in additions {
            for entry in summary.key.entry_facts() {
                let lookup = ProtocolSummaryLookupKey::new(summary.key(), entry);
                if let Some(existing_key) = self.by_entry.get(&lookup) {
                    let existing = self
                        .entries
                        .get(existing_key)
                        .expect("entry index points to a retained protocol summary");
                    if !entry_projections_match(existing, summary, entry) {
                        return Err(ProtocolSummaryPublicationError::OverlappingEntryManifest);
                    }
                    continue;
                }
                if let Some(existing) = staged.get(&lookup) {
                    if !entry_projections_match(existing, summary, entry) {
                        return Err(ProtocolSummaryPublicationError::OverlappingEntryManifest);
                    }
                    continue;
                }
                staged.insert(lookup, summary);
            }
        }
        Ok(())
    }

    fn insert(&mut self, summary: ProtocolSummary) {
        let key = summary.key.clone();
        for entry in key.entry_facts() {
            self.by_entry
                .entry(ProtocolSummaryLookupKey::new(&key, entry))
                .or_insert_with(|| key.clone());
        }
        self.retained_bytes = self
            .retained_bytes
            .saturating_add(protocol_repository_entry_bytes(&summary));
        self.entries.insert(key, summary);
    }

    fn matching_summary_for_entry(
        &self,
        procedure: &ProcedureSummaryKey,
        protocol: TypestateProtocolHash,
        bindings: TypestateBindingSummaryHash,
        entry: &ProtocolFactKey,
    ) -> Option<&ProtocolSummary> {
        let lookup = ProtocolSummaryLookupKey {
            procedure: procedure.clone(),
            protocol,
            bindings,
            schema_version: PROTOCOL_SUMMARY_SCHEMA_VERSION,
            entry: entry.clone(),
        };
        self.by_entry
            .get(&lookup)
            .and_then(|key| self.entries.get(key))
    }

    pub(super) fn into_publication_batches(self) -> ProtocolSummaryPublicationBatches {
        partition_protocol_summaries(self.entries.into_values())
    }

    pub(super) fn absorb_batches(
        &mut self,
        batches: ProtocolSummaryPublicationBatches,
        semantic_summaries: &ProtocolSemanticSummarySet<'_>,
    ) -> Result<usize, ProtocolSummaryPublicationError> {
        let started = self.len();
        for summary in batches.ordinary {
            self.publish(summary)?;
        }
        for (group, summaries) in batches.recursive {
            let semantic = semantic_summaries
                .summaries
                .iter()
                .copied()
                .filter(|summary| summary.key().recursive_group() == Some(group))
                .collect::<Vec<_>>();
            self.publish_scc(summaries, &semantic)?;
        }
        Ok(self.len().saturating_sub(started))
    }
}

pub(super) struct ProtocolSummaryPublicationBatches {
    ordinary: Vec<ProtocolSummary>,
    recursive: Vec<(SummaryRecursiveGroupKey, Vec<ProtocolSummary>)>,
}

fn partition_protocol_summaries(
    summaries: impl IntoIterator<Item = ProtocolSummary>,
) -> ProtocolSummaryPublicationBatches {
    let mut ordinary = Vec::new();
    let mut recursive = HashMap::<SummaryRecursiveGroupKey, Vec<ProtocolSummary>>::new();
    for summary in summaries {
        match summary.key().procedure().recursive_group() {
            Some(group) => recursive.entry(group).or_default().push(summary),
            None => ordinary.push(summary),
        }
    }
    ordinary.sort_unstable_by(|left, right| left.key().cmp(right.key()));
    let mut recursive = recursive.into_iter().collect::<Vec<_>>();
    recursive.sort_unstable_by_key(|(group, _)| *group);
    for (_, summaries) in &mut recursive {
        summaries.sort_unstable_by(|left, right| left.key().cmp(right.key()));
    }
    ProtocolSummaryPublicationBatches {
        ordinary,
        recursive,
    }
}

fn entry_projections_match(
    left: &ProtocolSummary,
    right: &ProtocolSummary,
    entry: &ProtocolFactKey,
) -> bool {
    left.rows[left.row_range(entry)] == right.rows[right.row_range(entry)]
        && left.effects[left.effect_range(entry)] == right.effects[right.effect_range(entry)]
}

struct ProtocolSummaryOracle<'query, 'semantic> {
    repository: &'query CompleteProtocolSummaryRepository,
    receipt_verifier: Option<Arc<dyn ProtocolReceiptVerifier>>,
    protocol: &'query CompiledProtocol,
    bindings: &'query TypestateBindingPlan,
    semantic_summaries: &'query ProtocolSemanticSummarySet<'semantic>,
    binding_contracts: &'query ProtocolBindingContracts,
    remap: Option<ProtocolLiveRemap<'query>>,
    points: HashMap<
        ProcedureHandle,
        HashMap<SemanticLocator, Option<crate::analyzer::semantic::ProgramPointHandle>>,
    >,
}

impl ReusableSummaryProvider<TypestateFact> for ProtocolSummaryOracle<'_, '_> {
    fn summary_for(
        &mut self,
        procedure: &ProcedureHandle,
        root: &ProcedureHandle,
        entry_fact: TypestateFact,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<ReusableProcedureSummary<TypestateFact>>, ReusableSummaryError> {
        if request.cancellation.is_cancelled() {
            return Err(SolverTermination::Cancelled.into());
        }
        let Some(semantic) = self.semantic_summaries.unique_summary_for(procedure) else {
            return Ok(None);
        };
        // #2285. Protocol summaries are published for whole call cycles at
        // once, so the repository really can answer for a callee that calls
        // back into the procedure this solve is rooted at. Report that and let
        // the solver refuse the summary and solve the body. Without the root's
        // own semantic summary there is nothing to compare, so report the
        // cycle: refusing reuse costs recomputation, and a wrong answer here
        // costs a fact.
        let call_cycle = match self.semantic_summaries.unique_summary_for(root) {
            Some(root_semantic) => semantic.key().call_cycle_with_root(root_semantic.key()),
            None if semantic.key().recursive_group().is_some() => SummaryCallCycle::IncludesRoot,
            None => SummaryCallCycle::ExcludesRoot,
        };
        let Some(binding_contract) = self.binding_contracts.get(semantic.key()).copied() else {
            return Ok(None);
        };
        let Ok(entry) = ProtocolFactKey::from_live(entry_fact, self.protocol, self.bindings) else {
            return Ok(None);
        };
        let Some(summary) = self.repository.matching_summary_for_entry(
            semantic.key(),
            self.protocol.hash(),
            binding_contract,
            &entry,
        ) else {
            return Ok(None);
        };
        let Some(verifier) = &self.receipt_verifier else {
            return Ok(None);
        };
        if summary.receipt.keys.is_empty()
            || !summary.receipt.is_admissible()
            || verifier.verify(&summary.receipt) != ProtocolReceiptVerdict::Current
        {
            return Ok(None);
        }
        let row_range = summary.row_range(&entry);
        let effect_range = summary.effect_range(&entry);
        let exit_count = row_range.len();
        let effect_count = effect_range.len();
        if self.remap.is_none() {
            let remap_rows = self
                .protocol
                .states()
                .count()
                .saturating_add(self.bindings.subjects().len())
                .saturating_add(self.bindings.event_bindings().len())
                .saturating_add(self.bindings.terminal_bindings().len());
            if let Some(termination) = request.reserve(crate::dataflow::SolverWork {
                callback_rows: remap_rows,
                ..crate::dataflow::SolverWork::default()
            }) {
                return Err(termination.into());
            }
            if request.cancellation.is_cancelled() {
                return Err(SolverTermination::Cancelled.into());
            }
            let Ok(remap) = ProtocolLiveRemap::try_new(self.protocol, self.bindings) else {
                return Ok(None);
            };
            self.remap = Some(remap);
        }
        if effect_count > 0 && !self.points.contains_key(procedure) {
            let point_count = procedure.semantics().points().len();
            if let Some(termination) = request.reserve(crate::dataflow::SolverWork {
                callback_rows: point_count,
                ..crate::dataflow::SolverWork::default()
            }) {
                return Err(termination.into());
            }
            let mut points = HashMap::with_capacity(point_count);
            for point in procedure.semantics().points() {
                if request.cancellation.is_cancelled() {
                    return Err(SolverTermination::Cancelled.into());
                }
                let Some(handle) = procedure.point_handle(point.id) else {
                    return Ok(None);
                };
                points
                    .entry(super::binding::program_point_locator(&handle))
                    .and_modify(|existing| *existing = None)
                    .or_insert(Some(handle));
            }
            self.points.insert(procedure.clone(), points);
        }
        let remap = self.remap.as_ref().expect("live remap was initialized");
        let points = self.points.get(procedure);
        for row in &summary.rows[row_range.clone()] {
            if request.cancellation.is_cancelled() || remap.fact(&row.output).is_err() {
                return if request.cancellation.is_cancelled() {
                    Err(SolverTermination::Cancelled.into())
                } else {
                    Ok(None)
                };
            }
        }
        for effect in &summary.effects[effect_range.clone()] {
            if request.cancellation.is_cancelled() {
                return Err(SolverTermination::Cancelled.into());
            }
            if remap.fact(&effect.observation).is_err()
                || points.is_none_or(|points| !points.contains_key(&effect.site))
            {
                return Ok(None);
            }
        }
        let relation_rows = exit_count.saturating_add(effect_count);
        if let Some(termination) = request.reserve(crate::dataflow::SolverWork {
            callback_rows: relation_rows,
            propagated_outputs: relation_rows,
            ..crate::dataflow::SolverWork::default()
        }) {
            return Err(termination.into());
        }
        let rebound_rows = summary.rows[row_range.clone()]
            .iter()
            .map(|row| rebind_protocol_fragments(&row.fragments, procedure, remap))
            .collect::<Option<Vec<_>>>();
        let rebound_effects = summary.effects[effect_range.clone()]
            .iter()
            .map(|effect| rebind_protocol_fragments(&effect.fragments, procedure, remap))
            .collect::<Option<Vec<_>>>();
        let evidence_complete = rebound_rows.is_some() && rebound_effects.is_some();
        let mut row_evidence = rebound_rows.unwrap_or_default().into_iter();
        let mut effect_evidence = rebound_effects.unwrap_or_default().into_iter();
        let mut exits = Vec::with_capacity(exit_count);
        for row in &summary.rows[row_range] {
            if request.cancellation.is_cancelled() {
                return Err(SolverTermination::Cancelled.into());
            }
            exits.push(ReusableEndSummary {
                exit_kind: match row.exit_kind {
                    SummaryExitKind::Normal => ReturnTransferKind::Normal,
                    SummaryExitKind::Exceptional => ReturnTransferKind::Exceptional,
                },
                exit_fact: remap
                    .fact(&row.output)
                    .expect("validated protocol summary output remaps"),
                qualities: row.evidence.qualities(),
                evidence: evidence_complete
                    .then(|| row_evidence.next().expect("one row evidence per row")),
            });
        }
        let mut reached = Vec::with_capacity(effect_count);
        for effect in &summary.effects[effect_range] {
            if request.cancellation.is_cancelled() {
                return Err(SolverTermination::Cancelled.into());
            }
            let evidence = evidence_complete.then(|| {
                effect_evidence
                    .next()
                    .expect("one effect evidence per effect")
            });
            let point = if let Some(evidence) = evidence.as_ref() {
                let Some(point) = rebound_effect_point(evidence, &effect.site) else {
                    return Ok(None);
                };
                point
            } else {
                let Some(point) = points
                    .and_then(|points| points.get(&effect.site))
                    .and_then(Option::as_ref)
                else {
                    return Ok(None);
                };
                point.clone()
            };
            reached.push(ReusableReachedFact {
                point,
                fact: remap
                    .fact(&effect.observation)
                    .expect("validated protocol summary observation remaps"),
                evidence,
                qualities: effect.evidence.qualities(),
            });
        }
        crate::analyzer::i_analyzer::replay_query_read_receipt(
            self.repository.attribution.analyzer(),
            summary.receipt.keys().cloned(),
            summary.receipt.channels,
        );
        Ok(Some(ReusableProcedureSummary {
            exits: exits.into_boxed_slice(),
            reached: reached.into_boxed_slice(),
            call_cycle,
            // #2296. A protocol summary is offered only for a procedure that
            // holds a binding contract, and `build_binding_contracts` above
            // grants one only to a procedure whose semantic summary has no
            // dependencies -- a leaf -- or to a validated recursive group whose
            // members all name one another. A leaf calls no analyzed procedure,
            // and a validated group names every member, so in both cases the
            // contract already covers everything the summarized body can call.
            // `typestate_client::mutual_recursive_protocol_summaries_project_and_reuse_atomically`
            // and the published-summary count asserted in the same file pin
            // that restriction; relaxing it means computing this the way
            // `TaintSummaryOracle::called_procedures` does.
            called_procedures: SummaryCalledProcedures::CoveredByContract,
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolSummaryPublicationError {
    RecursiveSummaryRequiresBatch,
    EmptyRecursiveBatch,
    NonRecursiveSummaryInBatch,
    IncompleteRecursiveBatch,
    MismatchedRecursiveGroup,
    DuplicateKey,
    DuplicateProcedure,
    MismatchedProtocolContract,
    InvalidRecursiveManifest,
    MismatchedRecursiveManifest,
    ConflictingEntry,
    OverlappingEntryManifest,
    EntryLimitExceeded,
    ByteLimitExceeded,
}

impl fmt::Display for ProtocolSummaryPublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RecursiveSummaryRequiresBatch => {
                "recursive protocol summaries require atomic SCC publication"
            }
            Self::EmptyRecursiveBatch => "recursive protocol summary batch is empty",
            Self::NonRecursiveSummaryInBatch => {
                "recursive protocol summary batch contains a non-recursive member"
            }
            Self::IncompleteRecursiveBatch => {
                "recursive protocol summary batch does not contain every member"
            }
            Self::MismatchedRecursiveGroup => {
                "recursive protocol summary batch mixes SCC identities"
            }
            Self::DuplicateKey => "protocol summary batch contains a duplicate key",
            Self::DuplicateProcedure => {
                "protocol summary batch contains more than one entry for a procedure"
            }
            Self::MismatchedProtocolContract => {
                "recursive protocol summary batch mixes protocol or binding contracts"
            }
            Self::InvalidRecursiveManifest => "recursive protocol summary manifest is invalid",
            Self::MismatchedRecursiveManifest => {
                "recursive protocol summary batch does not match its exact semantic SCC manifest"
            }
            Self::ConflictingEntry => {
                "protocol summary repository already contains a different value for this key"
            }
            Self::OverlappingEntryManifest => {
                "protocol summary entry manifests overlap for one exact reusable contract"
            }
            Self::EntryLimitExceeded => "protocol summary repository entry limit exceeded",
            Self::ByteLimitExceeded => "protocol summary repository byte limit exceeded",
        })
    }
}

impl std::error::Error for ProtocolSummaryPublicationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolSummaryError {
    IncompleteSemanticSummary,
    AmbiguousSemanticSummary,
    KeyProtocolMismatch,
    KeyBindingPlanMismatch,
    ResultProtocolMismatch,
    ResultBindingPlanMismatch,
    IncompleteResult,
    EntryFactCoverageMismatch,
    ProcedureMismatch,
    FactBindingPlanMismatch,
    InvalidFact,
    UnknownSubject,
    UnknownState,
    UnknownEventBinding,
    UnknownTerminalBinding,
    TooManyRows,
    TooManyEffects,
}

impl fmt::Display for ProtocolSummaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::IncompleteSemanticSummary => {
                "protocol summaries require a complete validated semantic summary"
            }
            Self::AmbiguousSemanticSummary => {
                "protocol reuse requires one exact semantic context per procedure"
            }
            Self::KeyProtocolMismatch => "protocol summary key was built for a different protocol",
            Self::KeyBindingPlanMismatch => {
                "protocol summary key was built for a different binding plan"
            }
            Self::ResultProtocolMismatch => "typestate result was produced by a different protocol",
            Self::ResultBindingPlanMismatch => {
                "typestate result was produced by a different binding plan"
            }
            Self::IncompleteResult => {
                "incomplete typestate results cannot become reusable protocol summaries"
            }
            Self::EntryFactCoverageMismatch => {
                "protocol summary does not cover this exact canonical entry-fact set"
            }
            Self::ProcedureMismatch => "protocol summary key does not identify the live procedure",
            Self::FactBindingPlanMismatch => "typestate fact belongs to a different binding plan",
            Self::InvalidFact => "typestate result contains an invalid fact reference",
            Self::UnknownSubject => "protocol summary references an unknown subject",
            Self::UnknownState => "protocol summary references an unknown state",
            Self::UnknownEventBinding => "protocol summary references an unknown event binding",
            Self::UnknownTerminalBinding => {
                "protocol summary references an unknown terminal binding"
            }
            Self::TooManyRows => "protocol summary row limit exceeded",
            Self::TooManyEffects => "protocol summary effect limit exceeded",
        })
    }
}

impl std::error::Error for ProtocolSummaryError {}

#[derive(Debug)]
pub enum ProtocolSummarySolveError {
    Solve(TypestateSolveError),
    Summary(ProtocolSummaryError),
    Publication(ProtocolSummaryPublicationError),
}

impl fmt::Display for ProtocolSummarySolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Solve(error) => error.fmt(formatter),
            Self::Summary(error) => error.fmt(formatter),
            Self::Publication(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ProtocolSummarySolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Solve(error) => Some(error),
            Self::Summary(error) => Some(error),
            Self::Publication(error) => Some(error),
        }
    }
}

impl From<TypestateSolveError> for ProtocolSummarySolveError {
    fn from(error: TypestateSolveError) -> Self {
        Self::Solve(error)
    }
}

impl From<ProtocolSummaryError> for ProtocolSummarySolveError {
    fn from(error: ProtocolSummaryError) -> Self {
        Self::Summary(error)
    }
}

impl From<ProtocolSummaryPublicationError> for ProtocolSummarySolveError {
    fn from(error: ProtocolSummaryPublicationError) -> Self {
        Self::Publication(error)
    }
}

#[derive(Debug)]
pub struct ProtocolSummarySolveResult {
    result: Box<TypestateSummaryResult>,
    application: Option<ProtocolSummaryApplication>,
    cache_status: ProtocolSummaryCacheStatus,
    published_summaries: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolSummaryCacheStatus {
    Published,
    AlreadyPresent,
    Incomplete,
    RecursiveBatchRequired,
    CapacityExceeded,
    Conflict,
    ProjectionSkipped,
    FragmentUnavailable,
    ReceiptUnavailable,
}

impl ProtocolSummarySolveResult {
    pub fn was_reused(&self) -> bool {
        self.result.result().metrics().reusable_summary_hits > 0
    }

    pub const fn application(&self) -> Option<&ProtocolSummaryApplication> {
        self.application.as_ref()
    }

    pub const fn cache_status(&self) -> ProtocolSummaryCacheStatus {
        self.cache_status
    }

    pub fn computed_result(&self) -> &TypestateSummaryResult {
        self.result.as_ref()
    }

    pub const fn published_summaries(&self) -> usize {
        self.published_summaries
    }

    pub fn into_computed_result(self) -> TypestateSummaryResult {
        *self.result
    }
}

/// Opt-in reusable solve path. The existing source-backed solver remains unchanged.
#[allow(clippy::too_many_arguments)]
pub fn solve_typestate_with_reusable_summaries<Provider>(
    root: &ProcedureHandle,
    entry_facts: &[TypestateFact],
    provider: &Provider,
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
    semantic_summaries: &ProtocolSemanticSummarySet<'_>,
    repository: &mut CompleteProtocolSummaryRepository,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<ProtocolSummarySolveResult, ProtocolSummarySolveError>
where
    Provider: IcfgProvider + ?Sized,
{
    let root_semantic = semantic_summaries
        .unique_summary_for(root)
        .ok_or(ProtocolSummaryError::ProcedureMismatch)?;
    if !root_semantic.key().matches_procedure(root) {
        return Err(ProtocolSummaryError::ProcedureMismatch.into());
    }
    let binding_contracts = semantic_summaries
        .build_binding_contracts(bindings, request)
        .unwrap_or_default();
    let inventory_source = repository.inventory_source.take();
    let receipt_verifier = repository.receipt_verifier.take();
    let attribution = provider.memo_attribution();
    let result = {
        let mut reusable = ProtocolSummaryOracle {
            repository,
            receipt_verifier,
            protocol,
            bindings,
            semantic_summaries,
            binding_contracts: &binding_contracts,
            remap: None,
            points: HashMap::new(),
        };
        solve_typestate_with_reusable_provider_with_receipts(
            root,
            entry_facts,
            provider,
            &mut reusable,
            protocol,
            bindings,
            attribution.analyzer(),
            semantic_budget,
            request,
        )?
    };
    if !result.is_summary_publication_complete() {
        return Ok(ProtocolSummarySolveResult {
            result: Box::new(result),
            application: None,
            cache_status: ProtocolSummaryCacheStatus::Incomplete,
            published_summaries: 0,
        });
    }
    let projection_rows = result
        .result()
        .end_summaries()
        .len()
        .saturating_add(result.result().reached().len());
    if request.cancellation.is_cancelled()
        || request
            .reserve(crate::dataflow::SolverWork {
                callback_rows: projection_rows,
                ..crate::dataflow::SolverWork::default()
            })
            .is_some()
    {
        return Ok(ProtocolSummarySolveResult {
            result: Box::new(result),
            application: None,
            cache_status: ProtocolSummaryCacheStatus::ProjectionSkipped,
            published_summaries: 0,
        });
    }
    let projection = project_complete_protocol_summaries(
        semantic_summaries,
        &binding_contracts,
        protocol,
        bindings,
        &result,
        request,
        inventory_source.as_deref(),
    )?;
    let root_entries = canonical_entry_facts(entry_facts, protocol, bindings)?;
    let application = projection
        .summaries
        .iter()
        .find(|summary| {
            summary.key.procedure().matches_procedure(root)
                && summary.key.entry_facts() == root_entries.as_slice()
        })
        .map(|summary| {
            let binding_contract = binding_contracts
                .get(summary.key().procedure())
                .copied()
                .ok_or(ProtocolSummaryError::KeyBindingPlanMismatch)?;
            summary.apply_with_binding_contract(entry_facts, protocol, bindings, binding_contract)
        })
        .transpose()?;
    let (cache_status, published_summaries) = publish_protocol_summaries(
        repository,
        projection.summaries,
        &binding_contracts,
        projection.skipped,
        projection.fragment_refused,
        projection.receipt_refused,
    )?;
    Ok(ProtocolSummarySolveResult {
        result: Box::new(result),
        application,
        cache_status,
        published_summaries,
    })
}

fn canonical_entry_facts(
    entry_facts: &[TypestateFact],
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
) -> Result<Vec<ProtocolFactKey>, ProtocolSummaryError> {
    let mut canonical = entry_facts
        .iter()
        .copied()
        .map(|fact| ProtocolFactKey::from_live(fact, protocol, bindings))
        .collect::<Result<Vec<_>, _>>()?;
    canonical.push(ProtocolFactKey::Zero);
    canonical.sort_unstable();
    canonical.dedup();
    Ok(canonical)
}

#[derive(Default)]
struct ProcedureProtocolProjection {
    entries: HashSet<ProtocolFactKey>,
    rows: Vec<ProtocolSummaryRow>,
    effects: Vec<ProtocolObservedEffect>,
    oversized: bool,
    fragment_refused: bool,
}

struct ProtocolProjectionBatch {
    summaries: Vec<ProtocolSummary>,
    skipped: bool,
    fragment_refused: bool,
    receipt_refused: bool,
}

fn encode_protocol_fragment(
    witness: &SummaryWitness,
    quality: PathQuality,
    entry_point: &crate::analyzer::semantic::ProgramPointHandle,
    entry_fact: FactId,
    end_point: &crate::analyzer::semantic::ProgramPointHandle,
    end_fact: FactId,
    mut canonical_fact: impl FnMut(FactId) -> Option<ProtocolFactKey>,
) -> Option<Box<[WitnessStepRow<ProtocolFactKey>]>> {
    let steps = witness.steps();
    let (seed, edges) = steps.split_first()?;
    if witness.truncated()
        || witness.omitted_steps_lower_bound() != 0
        || witness.quality() != quality
        || steps.len() > WitnessReconstructionLimits::default().max_steps()
        || seed.kind() != SummaryWitnessStepKind::Seed
        || seed.source() != entry_point
        || seed.target().is_some()
        || seed.origin().is_some()
        || seed.boundary().is_some()
        || seed.receiver_operand().is_some()
        || !matches!(seed.proof(), crate::analyzer::semantic::ProofStatus::Proven)
        || !matches!(
            seed.completeness(),
            crate::analyzer::semantic::EvidenceCompleteness::Complete
        )
        || seed.input_fact() != entry_fact
        || seed.output_fact() != entry_fact
    {
        return None;
    }
    let mut folded = PathQuality::PROVEN_COMPLETE;
    let mut previous = seed;
    for step in edges {
        if !matches!(step.kind(), SummaryWitnessStepKind::Edge(_))
            || step.target().is_none()
            || step.receiver_operand().is_some()
            || step.source() != previous.target().unwrap_or(previous.source())
            || step.input_fact() != previous.output_fact()
        {
            return None;
        }
        folded = folded.through_evidence(step.proof(), step.completeness());
        previous = step;
    }
    if folded != quality
        || previous.target().unwrap_or(previous.source()) != end_point
        || previous.output_fact() != end_fact
    {
        return None;
    }
    steps
        .iter()
        .map(|step| WitnessStepRow::encode(step, &mut canonical_fact).ok())
        .collect()
}

fn rebind_protocol_fragments(
    fragments: &[(PathQuality, Box<[WitnessStepRow<ProtocolFactKey>]>)],
    procedure: &ProcedureHandle,
    remap: &ProtocolLiveRemap<'_>,
) -> Option<Box<[QualityEvidence<TypestateFact>]>> {
    fragments
        .iter()
        .map(|(quality, fragment)| {
            let steps = fragment
                .iter()
                .map(|step| {
                    step.rebind(
                        |locator, ordinal| {
                            // A callee-relative path may traverse a call edge
                            // into another procedure in this artifact.
                            procedure.artifact().procedures().iter().find_map(|owner| {
                                owner
                                    .points()
                                    .get(ordinal)
                                    .filter(|point| point.id.index() == ordinal)
                                    .and_then(|point| {
                                        procedure
                                            .artifact()
                                            .procedure_handle(owner.id())?
                                            .point_handle(point.id)
                                    })
                                    .filter(|point| point.locator() == Some(locator))
                            })
                        },
                        |locator| {
                            procedure
                                .artifact()
                                .procedures()
                                .iter()
                                .flat_map(|owner| {
                                    owner.call_sites().iter().filter_map(|call| {
                                        procedure
                                            .artifact()
                                            .procedure_handle(owner.id())?
                                            .call_site_handle(call.id)
                                    })
                                })
                                .find(|call| call.locator() == Some(locator))
                        },
                        |fact| remap.fact(fact).ok(),
                    )
                    .ok()
                })
                .collect::<Option<Vec<_>>>()?;
            Some(QualityEvidence {
                quality: *quality,
                fragment: WitnessFragment {
                    steps: steps.into_boxed_slice(),
                },
            })
        })
        .collect::<Option<Vec<_>>>()
        .map(Vec::into_boxed_slice)
}

fn rebound_effect_point(
    evidence: &[QualityEvidence<TypestateFact>],
    site: &SemanticLocator,
) -> Option<crate::analyzer::semantic::ProgramPointHandle> {
    // Source locators can alias points. The fragment carries the exact point
    // chosen by the body solve, including for an observed call effect.
    let point = evidence.first()?.fragment.steps.last()?.output_point();
    (point.locator() == Some(site)
        && evidence.iter().all(|quality| {
            quality
                .fragment
                .steps
                .last()
                .is_some_and(|step| step.output_point() == point)
        }))
    .then(|| point.clone())
}

#[allow(clippy::too_many_arguments)]
fn project_complete_protocol_summaries(
    semantic_summaries: &ProtocolSemanticSummarySet<'_>,
    binding_contracts: &ProtocolBindingContracts,
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
    result: &TypestateSummaryResult,
    request: &DataflowRequest<'_>,
    inventory: Option<&dyn ProtocolInventorySource>,
) -> Result<ProtocolProjectionBatch, ProtocolSummaryError> {
    if result.protocol_hash() != protocol.hash() {
        return Err(ProtocolSummaryError::ResultProtocolMismatch);
    }
    if result.binding_plan_hash() != bindings.hash() {
        return Err(ProtocolSummaryError::ResultBindingPlanMismatch);
    }
    if !result.is_summary_publication_complete() {
        return Err(ProtocolSummaryError::IncompleteResult);
    }

    let mut projections = HashMap::<ProcedureHandle, ProcedureProtocolProjection>::new();
    let mut ineligible = HashSet::<ProcedureHandle>::new();
    let mut ignored = HashSet::<ProcedureHandle>::new();
    let mut effectful_recursive_groups = HashSet::new();
    for summary in result.result().end_summaries() {
        if request.cancellation.is_cancelled() {
            return Ok(ProtocolProjectionBatch {
                summaries: Vec::new(),
                skipped: true,
                fragment_refused: false,
                receipt_refused: false,
            });
        }
        let procedure = summary.entry().procedure();
        if !projections.contains_key(procedure)
            && !ineligible.contains(procedure)
            && !ignored.contains(procedure)
        {
            match semantic_summaries.unique_summary_for(procedure) {
                Some(semantic) if binding_contracts.contains_key(semantic.key()) => {
                    projections.insert(procedure.clone(), ProcedureProtocolProjection::default());
                }
                Some(_) => {
                    ineligible.insert(procedure.clone());
                }
                None => {
                    ignored.insert(procedure.clone());
                }
            }
        }
        let Some(projection) = projections.get_mut(procedure) else {
            continue;
        };
        let input = result
            .result()
            .fact(summary.entry().entry_fact())
            .ok_or(ProtocolSummaryError::InvalidFact)?;
        let input = ProtocolFactKey::from_live(*input, protocol, bindings)?;
        projection.entries.insert(input.clone());
        if projection.rows.len() == MAX_PROTOCOL_SUMMARY_ROWS {
            projection.oversized = true;
            continue;
        }
        let output = result
            .result()
            .fact(summary.exit_fact())
            .ok_or(ProtocolSummaryError::InvalidFact)?;
        let mut fragments = Vec::new();
        for quality in summary.path_qualities().iter() {
            let Ok(witness) = result.result().witness_for_end_summary(
                summary,
                quality,
                WitnessReconstructionLimits::default(),
            ) else {
                projection.fragment_refused = true;
                break;
            };
            let Some(fragment) = encode_protocol_fragment(
                &witness,
                quality,
                summary.entry().entry_point(),
                summary.entry().entry_fact(),
                summary.exit_point(),
                summary.exit_fact(),
                |id| {
                    result
                        .result()
                        .fact(id)
                        .and_then(|fact| ProtocolFactKey::from_live(*fact, protocol, bindings).ok())
                },
            ) else {
                projection.fragment_refused = true;
                break;
            };
            fragments.push((quality, fragment));
        }
        if projection.fragment_refused {
            continue;
        }
        projection.rows.push(ProtocolSummaryRow {
            input,
            exit_kind: exit_kind(summary.exit_kind()),
            output: ProtocolFactKey::from_live(*output, protocol, bindings)?,
            evidence: ProtocolPathEvidence::from_frontier(summary.path_qualities()),
            fragments: fragments.into_boxed_slice(),
        });
    }
    for reached in result.result().reached() {
        if request.cancellation.is_cancelled() {
            return Ok(ProtocolProjectionBatch {
                summaries: Vec::new(),
                skipped: true,
                fragment_refused: false,
                receipt_refused: false,
            });
        }
        let procedure = reached.entry().procedure();
        if !projections.contains_key(procedure)
            && !ineligible.contains(procedure)
            && !ignored.contains(procedure)
        {
            match semantic_summaries.unique_summary_for(procedure) {
                Some(semantic) if binding_contracts.contains_key(semantic.key()) => {
                    projections.insert(procedure.clone(), ProcedureProtocolProjection::default());
                }
                Some(_) => {
                    ineligible.insert(procedure.clone());
                }
                None => {
                    ignored.insert(procedure.clone());
                }
            }
        }
        let Some(projection) = projections.get_mut(procedure) else {
            continue;
        };
        let input = result
            .result()
            .fact(reached.entry().entry_fact())
            .ok_or(ProtocolSummaryError::InvalidFact)?;
        let input = ProtocolFactKey::from_live(*input, protocol, bindings)?;
        projection.entries.insert(input.clone());
        let observation = result
            .result()
            .fact(reached.fact())
            .ok_or(ProtocolSummaryError::InvalidFact)?;
        let observation = ProtocolFactKey::from_live(*observation, protocol, bindings)?;
        if !observation.is_observed_effect() {
            continue;
        }
        if let Some(group) = semantic_summaries
            .unique_summary_for(procedure)
            .and_then(|semantic| semantic.key().recursive_group())
        {
            effectful_recursive_groups.insert(group);
        }
        if projection.effects.len() == MAX_PROTOCOL_SUMMARY_EFFECTS {
            projection.oversized = true;
            continue;
        }
        let mut fragments = Vec::new();
        for quality in reached.path_qualities().iter() {
            let Ok(witness) = result.result().witness_for_reached(
                reached,
                quality,
                WitnessReconstructionLimits::default(),
            ) else {
                projection.fragment_refused = true;
                break;
            };
            let Some(fragment) = encode_protocol_fragment(
                &witness,
                quality,
                reached.entry().entry_point(),
                reached.entry().entry_fact(),
                reached.point(),
                reached.fact(),
                |id| {
                    result
                        .result()
                        .fact(id)
                        .and_then(|fact| ProtocolFactKey::from_live(*fact, protocol, bindings).ok())
                },
            ) else {
                projection.fragment_refused = true;
                break;
            };
            fragments.push((quality, fragment));
        }
        if projection.fragment_refused {
            continue;
        }
        projection.effects.push(ProtocolObservedEffect {
            input,
            site: super::binding::program_point_locator(reached.point()),
            observation,
            evidence: ProtocolPathEvidence::from_frontier(reached.path_qualities()),
            fragments: fragments.into_boxed_slice(),
        });
    }

    let mut skipped = !ineligible.is_empty();
    let mut fragment_refused = false;
    let mut receipt_refused = false;
    let mut summaries = Vec::with_capacity(projections.len());
    for (procedure, projection) in projections {
        let semantic = semantic_summaries
            .unique_summary_for(&procedure)
            .ok_or(ProtocolSummaryError::ProcedureMismatch)?;
        if projection.oversized
            || projection.fragment_refused
            || semantic
                .key()
                .recursive_group()
                .is_some_and(|group| effectful_recursive_groups.contains(&group))
        {
            skipped = true;
            fragment_refused |= projection.fragment_refused;
            continue;
        }
        let mut receipt = ProtocolMemberReceipt::default();
        let members = semantic
            .key()
            .recursive_group()
            .and_then(|group| binding_contracts.recursive_manifest(group));
        let member_keys: Vec<&ProcedureSummaryKey> = match members {
            Some(members) => members.iter().collect(),
            None => vec![semantic.key()],
        };
        let member_receipts = result.result().member_receipts();
        let mut complete_receipt = true;
        for member_key in member_keys {
            let member = member_receipts.and_then(|receipts| {
                receipts.iter().find_map(|(handle, receipt)| {
                    member_key.matches_procedure(handle).then_some(receipt)
                })
            });
            let Some(member) = member else {
                complete_receipt = false;
                break;
            };
            if !receipt_is_admissible(member) || member.keys.is_empty() {
                complete_receipt = false;
                break;
            }
            let Ok(converted) = ProtocolMemberReceipt::from_member(member, inventory) else {
                complete_receipt = false;
                break;
            };
            receipt.keys.extend(converted.keys);
            receipt.channels.unattributed_reads |= converted.channels.unattributed_reads;
            receipt.channels.execution_dependences |= converted.channels.execution_dependences;
            receipt.channels.reuse_refused |= converted.channels.reuse_refused;
        }
        if !complete_receipt {
            receipt_refused = true;
            continue;
        }
        let mut entry_facts = projection.entries.into_iter().collect::<Vec<_>>();
        entry_facts.sort_unstable();
        let binding_contract = binding_contracts
            .get(semantic.key())
            .copied()
            .ok_or(ProtocolSummaryError::KeyBindingPlanMismatch)?;
        let key = ProtocolSummaryKey::try_from_semantic_summary(
            semantic,
            protocol.hash(),
            binding_contract,
            entry_facts,
        )?;
        validate_key_inputs(&key, protocol, binding_contract)?;
        let mut summary = ProtocolSummary::try_new(key, projection.rows, projection.effects)?;
        summary.receipt = receipt;
        summaries.push(summary);
    }
    summaries.sort_unstable_by(|left, right| left.key.cmp(&right.key));
    Ok(ProtocolProjectionBatch {
        summaries,
        skipped,
        fragment_refused,
        receipt_refused,
    })
}

fn publish_protocol_summaries(
    repository: &mut CompleteProtocolSummaryRepository,
    summaries: Vec<ProtocolSummary>,
    binding_contracts: &ProtocolBindingContracts,
    projection_skipped: bool,
    fragment_refused: bool,
    receipt_refused: bool,
) -> Result<(ProtocolSummaryCacheStatus, usize), ProtocolSummarySolveError> {
    let mut receipt_refused = receipt_refused;
    let summaries: Vec<_> = summaries
        .into_iter()
        .filter(|summary| {
            let admissible = summary.receipt.is_admissible() && !summary.receipt.keys.is_empty();
            receipt_refused |= !admissible;
            admissible
        })
        .collect();
    let batches = partition_protocol_summaries(summaries);

    let mut published_any = false;
    let mut recursive_batch_required = false;
    let mut capacity_exceeded = false;
    let mut conflict = false;
    let mut published = 0usize;
    for summary in batches.ordinary {
        match repository.publish(summary) {
            Ok(ProtocolSummaryPublicationOutcome::Inserted) => {
                published_any = true;
                published = published.saturating_add(1);
            }
            Ok(ProtocolSummaryPublicationOutcome::AlreadyPresent) => {}
            Err(
                ProtocolSummaryPublicationError::EntryLimitExceeded
                | ProtocolSummaryPublicationError::ByteLimitExceeded,
            ) => capacity_exceeded = true,
            Err(
                ProtocolSummaryPublicationError::ConflictingEntry
                | ProtocolSummaryPublicationError::OverlappingEntryManifest,
            ) => conflict = true,
            Err(error) => return Err(error.into()),
        }
    }

    for (group, batch) in batches.recursive {
        let semantic_manifest = binding_contracts
            .recursive_manifest(group)
            .ok_or(ProtocolSummaryError::ProcedureMismatch)?;
        let batch_len = batch.len();
        match repository.publish_scc_with_manifest(batch, group, semantic_manifest) {
            Ok(ProtocolSummaryPublicationOutcome::Inserted) => {
                published_any = true;
                published = published.saturating_add(batch_len);
            }
            Ok(ProtocolSummaryPublicationOutcome::AlreadyPresent) => {}
            Err(
                ProtocolSummaryPublicationError::IncompleteRecursiveBatch
                | ProtocolSummaryPublicationError::MismatchedRecursiveManifest,
            ) => recursive_batch_required = true,
            Err(
                ProtocolSummaryPublicationError::EntryLimitExceeded
                | ProtocolSummaryPublicationError::ByteLimitExceeded,
            ) => capacity_exceeded = true,
            Err(
                ProtocolSummaryPublicationError::ConflictingEntry
                | ProtocolSummaryPublicationError::OverlappingEntryManifest,
            ) => conflict = true,
            Err(error) => return Err(error.into()),
        }
    }
    let status = if conflict {
        ProtocolSummaryCacheStatus::Conflict
    } else if capacity_exceeded {
        ProtocolSummaryCacheStatus::CapacityExceeded
    } else if fragment_refused {
        ProtocolSummaryCacheStatus::FragmentUnavailable
    } else if receipt_refused {
        ProtocolSummaryCacheStatus::ReceiptUnavailable
    } else if projection_skipped {
        ProtocolSummaryCacheStatus::ProjectionSkipped
    } else if recursive_batch_required {
        ProtocolSummaryCacheStatus::RecursiveBatchRequired
    } else if published_any {
        ProtocolSummaryCacheStatus::Published
    } else {
        ProtocolSummaryCacheStatus::AlreadyPresent
    };
    Ok((status, published))
}

fn validate_key_inputs(
    key: &ProtocolSummaryKey,
    protocol: &CompiledProtocol,
    expected_bindings: TypestateBindingSummaryHash,
) -> Result<(), ProtocolSummaryError> {
    if key.protocol != protocol.hash() {
        return Err(ProtocolSummaryError::KeyProtocolMismatch);
    }
    if key.bindings != expected_bindings {
        return Err(ProtocolSummaryError::KeyBindingPlanMismatch);
    }
    Ok(())
}

fn exit_kind(kind: ReturnTransferKind) -> SummaryExitKind {
    match kind {
        ReturnTransferKind::Normal => SummaryExitKind::Normal,
        ReturnTransferKind::Exceptional => SummaryExitKind::Exceptional,
    }
}

fn canonicalize_rows(rows: &mut Vec<ProtocolSummaryRow>) -> Result<(), ProtocolSummaryError> {
    if rows.len() > MAX_PROTOCOL_SUMMARY_ROWS {
        return Err(ProtocolSummaryError::TooManyRows);
    }
    rows.sort_unstable_by(|left, right| {
        (&left.input, left.exit_kind, &left.output).cmp(&(
            &right.input,
            right.exit_kind,
            &right.output,
        ))
    });
    let mut joined: Vec<ProtocolSummaryRow> = Vec::with_capacity(rows.len());
    for row in rows.drain(..) {
        if let Some(previous) = joined.last_mut()
            && previous.input == row.input
            && previous.exit_kind == row.exit_kind
            && previous.output == row.output
        {
            previous.evidence.0 |= row.evidence.0;
            let mut fragments = previous.fragments.to_vec();
            for fragment in row.fragments.iter() {
                if !fragments.iter().any(|(quality, _)| *quality == fragment.0) {
                    fragments.push(fragment.clone());
                }
            }
            previous.fragments = fragments.into_boxed_slice();
        } else {
            joined.push(row);
        }
    }
    *rows = joined;
    Ok(())
}

fn canonicalize_effects(
    effects: &mut Vec<ProtocolObservedEffect>,
) -> Result<(), ProtocolSummaryError> {
    if effects.len() > MAX_PROTOCOL_SUMMARY_EFFECTS {
        return Err(ProtocolSummaryError::TooManyEffects);
    }
    effects.sort_unstable_by(|left, right| {
        (&left.input, &left.site, &left.observation).cmp(&(
            &right.input,
            &right.site,
            &right.observation,
        ))
    });
    let mut joined: Vec<ProtocolObservedEffect> = Vec::with_capacity(effects.len());
    for effect in effects.drain(..) {
        if let Some(previous) = joined.last_mut()
            && previous.input == effect.input
            && previous.site == effect.site
            && previous.observation == effect.observation
        {
            previous.evidence.0 |= effect.evidence.0;
            let mut fragments = previous.fragments.to_vec();
            for fragment in effect.fragments.iter() {
                if !fragments.iter().any(|(quality, _)| *quality == fragment.0) {
                    fragments.push(fragment.clone());
                }
            }
            previous.fragments = fragments.into_boxed_slice();
        } else {
            joined.push(effect);
        }
    }
    *effects = joined;
    Ok(())
}

fn state_key(
    protocol: &CompiledProtocol,
    state: super::ProtocolStateId,
) -> Result<ProtocolStateKey, ProtocolSummaryError> {
    protocol
        .state_key(state)
        .cloned()
        .ok_or(ProtocolSummaryError::UnknownState)
}

fn event_binding_key(
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
    id: super::TypestateEventBindingId,
) -> Result<ProtocolEventBindingKey, ProtocolSummaryError> {
    let binding = bindings
        .event_binding(id)
        .ok_or(ProtocolSummaryError::UnknownEventBinding)?;
    let event = protocol
        .event(binding.event())
        .ok_or(ProtocolSummaryError::UnknownEventBinding)?;
    let subject = bindings
        .subject(binding.subject())
        .ok_or(ProtocolSummaryError::UnknownSubject)?;
    Ok(ProtocolEventBindingKey {
        event: event.key().clone(),
        subject: subject.key().clone(),
        site: binding.site().identity().clone(),
        context: binding.site().context().key().clone(),
        order: binding.order(),
        role: binding.role(),
    })
}

fn terminal_binding_key(
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
    id: super::TypestateTerminalBindingId,
) -> Result<ProtocolTerminalBindingKey, ProtocolSummaryError> {
    let binding = bindings
        .terminal_binding(id)
        .ok_or(ProtocolSummaryError::UnknownTerminalBinding)?;
    let expectation = protocol
        .terminal_expectation(binding.expectation())
        .ok_or(ProtocolSummaryError::UnknownTerminalBinding)?;
    let subject = bindings
        .subject(binding.subject())
        .ok_or(ProtocolSummaryError::UnknownSubject)?;
    Ok(ProtocolTerminalBindingKey {
        expectation: expectation.key().clone(),
        subject: subject.key().clone(),
        site: binding.site().identity().clone(),
        context: binding.site().context().key().clone(),
        role: binding.role(),
    })
}

fn protocol_repository_entry_bytes(summary: &ProtocolSummary) -> usize {
    summary
        .retained_bytes()
        .saturating_add(
            summary
                .key
                .entry_facts()
                .iter()
                .fold(0_usize, |total, entry| {
                    total
                        .saturating_add(size_of::<ProtocolSummaryLookupKey>())
                        .saturating_add(
                            summary
                                .key
                                .procedure
                                .retained_bytes()
                                .saturating_sub(size_of::<ProcedureSummaryKey>()),
                        )
                        .saturating_add(protocol_fact_heap_bytes(entry))
                        .saturating_add(size_of::<ProtocolSummaryKey>())
                        .saturating_add(protocol_key_heap_bytes(&summary.key))
                }),
        )
}

fn protocol_fragment_bytes(
    fragments: &[(PathQuality, Box<[WitnessStepRow<ProtocolFactKey>]>)],
) -> usize {
    fragments
        .iter()
        .fold(size_of_val(fragments), |total, (_, steps)| {
            total
                .saturating_add(size_of_val(steps.as_ref()))
                .saturating_add(steps.iter().fold(0usize, |bytes, step| {
                    bytes
                        .saturating_add(protocol_fact_heap_bytes(&step.input_fact))
                        .saturating_add(protocol_fact_heap_bytes(&step.output_fact))
                        .saturating_add(crate::value_flow::semantic_locator_heap_bytes(
                            &step.source.locator,
                        ))
                        .saturating_add(step.target.as_ref().map_or(0, |point| {
                            crate::value_flow::semantic_locator_heap_bytes(&point.locator)
                        }))
                        .saturating_add(
                            step.origin
                                .as_ref()
                                .map_or(0, crate::value_flow::semantic_locator_heap_bytes),
                        )
                        .saturating_add(step.proof.retained_heap_bytes())
                        .saturating_add(step.completeness.retained_heap_bytes())
                        .saturating_add(
                            step.boundary
                                .as_ref()
                                .and_then(|boundary| boundary.target_locator())
                                .map_or(0, crate::value_flow::semantic_locator_heap_bytes),
                        )
                        .saturating_add(match &step.typed {
                            crate::dataflow::WitnessStepState::None => 0,
                            crate::dataflow::WitnessStepState::ModeledReceiver { operand } => {
                                crate::value_flow::semantic_locator_heap_bytes(operand)
                            }
                        })
                }))
        })
}

fn protocol_key_heap_bytes(key: &ProtocolSummaryKey) -> usize {
    key.procedure
        .retained_bytes()
        .saturating_sub(size_of::<ProcedureSummaryKey>())
        .saturating_add(size_of_val(key.entry_facts()))
        .saturating_add(key.entry_facts.iter().fold(0_usize, |total, fact| {
            total.saturating_add(protocol_fact_heap_bytes(fact))
        }))
}

fn protocol_fact_heap_bytes(fact: &ProtocolFactKey) -> usize {
    match fact {
        ProtocolFactKey::Zero => 0,
        ProtocolFactKey::State {
            subject,
            state,
            uncertainty,
            ..
        } => subject_key_heap_bytes(subject)
            .saturating_add(state.as_str().len())
            .saturating_add(size_of_val(uncertainty.values())),
        ProtocolFactKey::Violation {
            event,
            from,
            to,
            uncertainty,
            ..
        } => event_key_heap_bytes(event)
            .saturating_add(from.as_str().len())
            .saturating_add(to.as_str().len())
            .saturating_add(size_of_val(uncertainty.values())),
        ProtocolFactKey::NonViolation {
            event, uncertainty, ..
        } => event_key_heap_bytes(event).saturating_add(size_of_val(uncertainty.values())),
        ProtocolFactKey::Terminal {
            expectation,
            state,
            uncertainty,
            ..
        } => terminal_key_heap_bytes(expectation)
            .saturating_add(state.as_str().len())
            .saturating_add(size_of_val(uncertainty.values())),
    }
}

fn event_key_heap_bytes(key: &ProtocolEventBindingKey) -> usize {
    observation_key_heap_bytes(key.event.as_str(), &key.subject, &key.site, &key.context)
}

fn terminal_key_heap_bytes(key: &ProtocolTerminalBindingKey) -> usize {
    observation_key_heap_bytes(
        key.expectation.as_str(),
        &key.subject,
        &key.site,
        &key.context,
    )
}

fn observation_key_heap_bytes(
    name: &str,
    subject: &TypestateSubjectKey,
    site: &SemanticLocator,
    context: &TypestateContextKey,
) -> usize {
    name.len()
        .saturating_add(subject_key_heap_bytes(subject))
        .saturating_add(crate::value_flow::semantic_locator_heap_bytes(site))
        .saturating_add(context_key_heap_bytes(context))
}

fn subject_key_heap_bytes(key: &TypestateSubjectKey) -> usize {
    key.class()
        .as_str()
        .len()
        .saturating_add(object_key_heap_bytes(key.object()))
}

fn object_key_heap_bytes(key: &TypestateObjectKey) -> usize {
    match key {
        TypestateObjectKey::FieldPath { base, member } => object_key_heap_bytes(base)
            .saturating_add(size_of::<TypestateObjectKey>())
            .saturating_add(crate::value_flow::semantic_locator_heap_bytes(member)),
        TypestateObjectKey::CallSubstitution { context, base } => context_key_heap_bytes(context)
            .saturating_add(size_of::<TypestateObjectKey>())
            .saturating_add(object_key_heap_bytes(base)),
        TypestateObjectKey::Value(locator)
        | TypestateObjectKey::Allocation(locator)
        | TypestateObjectKey::Static(locator)
        | TypestateObjectKey::TypeSummary(locator)
        | TypestateObjectKey::ModuleObject(locator)
        | TypestateObjectKey::External(locator) => {
            crate::value_flow::semantic_locator_heap_bytes(locator)
        }
        TypestateObjectKey::LexicalCell { locator, binding } => {
            crate::value_flow::semantic_locator_heap_bytes(locator)
                .saturating_add(durable_value_identity_heap_bytes(binding))
        }
        TypestateObjectKey::CallResult {
            call,
            result,
            callee,
            caller_context,
            callee_context,
        } => crate::value_flow::semantic_locator_heap_bytes(call)
            .saturating_add(crate::value_flow::semantic_locator_heap_bytes(result))
            .saturating_add(crate::value_flow::semantic_locator_heap_bytes(callee))
            .saturating_add(context_key_heap_bytes(caller_context))
            .saturating_add(context_key_heap_bytes(callee_context)),
        TypestateObjectKey::ProcedurePort { procedure, .. }
        | TypestateObjectKey::CaptureSlot { procedure, .. } => {
            crate::value_flow::semantic_locator_heap_bytes(procedure)
        }
        TypestateObjectKey::RuntimeObject {
            runtime_profile_digest,
            realm,
            exposure_id,
            container_member,
            state_boundary,
            active_model_set_hash,
            manifest_digest,
            shard_id,
            behavior_id,
            activation_source,
            ..
        } => runtime_profile_digest
            .len()
            .saturating_add(realm.len())
            .saturating_add(exposure_id.len())
            .saturating_add(container_member.len())
            .saturating_add(state_boundary.len())
            .saturating_add(active_model_set_hash.len())
            .saturating_add(manifest_digest.len())
            .saturating_add(shard_id.len())
            .saturating_add(behavior_id.len())
            .saturating_add(activation_source.len())
            .saturating_add(std::mem::size_of::<crate::analyzer::semantic::StableDigest>()),
    }
}

fn durable_value_identity_heap_bytes(value: &DurableValueIdentity) -> usize {
    crate::value_flow::semantic_locator_heap_bytes(&value.locator).saturating_add(value.role.len())
}

fn context_key_heap_bytes(key: &TypestateContextKey) -> usize {
    size_of_val(key.calls()).saturating_add(
        key.calls()
            .iter()
            .map(crate::value_flow::semantic_locator_heap_bytes)
            .fold(0_usize, usize::saturating_add),
    )
}

#[cfg(test)]
mod attribution_tests {
    use super::*;
    use crate::analyzer::{ReadKey, capture_query_reads};
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn unattributed_member_receipts_are_ineligible_for_publication() {
        let mut receipt = MemberReadReceipt::default();
        receipt.channels.unattributed_reads = 1;
        assert!(!receipt_is_admissible(&receipt));
        receipt.channels.unattributed_reads = 0;
        receipt.channels.execution_dependences = 1;
        assert!(!receipt_is_admissible(&receipt));
        receipt.channels.execution_dependences = 0;
        receipt.channels.reuse_refused = true;
        assert!(!receipt_is_admissible(&receipt));
    }

    #[test]
    #[hardwon(
        "#10187: raw definition index reads could enter protocol receipts without answer certification"
    )]
    fn raw_index_member_receipts_are_ineligible_for_publication() {
        let mut receipt = MemberReadReceipt::default();
        receipt.keys.insert(ReadKey::index(
            crate::analyzer::IndexFamily::DefinitionExact,
            "new_target",
        ));
        assert_eq!(
            ProtocolMemberReceipt::from_member(&receipt, None),
            Err(UncoveredProtocolIndexReads(vec![ReadKey::index(
                crate::analyzer::IndexFamily::DefinitionExact,
                "new_target",
            )]))
        );
    }

    #[test]
    fn a_certificate_does_not_cover_a_raw_definition_probe() {
        use crate::analyzer::semantic::read_ledger::CertifiedDefinitionKind;
        use crate::analyzer::{IndexFamily, LookupKind, LookupQuestion};
        // No producer certifies a definition probe yet (#10325), so even a
        // matching certificate beside the raw key must not publish the row.
        let raw = ReadKey::index(IndexFamily::DefinitionExact, "new_target");
        let mut receipt = MemberReadReceipt::default();
        receipt.keys.insert(raw.clone());
        receipt.keys.insert(ReadKey::lookup(
            LookupKind::CertifiedDefinitionAnswer,
            LookupQuestion::certified_definition(
                CertifiedDefinitionKind::Exact,
                "new_target",
                [brokk_bifrost_core::analyzer::model::Language::Go],
            ),
            crate::analyzer::semantic::ids::StableDigest::sha256([]),
        ));
        assert_eq!(
            ProtocolMemberReceipt::from_member(&receipt, None),
            Err(UncoveredProtocolIndexReads(vec![raw]))
        );
    }

    #[test]
    #[hardwon("#10187: a changed definition answer was accepted as a current protocol receipt")]
    fn changed_definition_certificate_is_stale() {
        use crate::analyzer::semantic::read_ledger::CertifiedDefinitionKind;
        use crate::analyzer::{LookupKind, LookupQuestion};
        let project = crate::inline_project::InlineTestProject::with_language(
            brokk_bifrost_core::analyzer::model::Language::Go,
        )
        .file("main.go", "package main\nfunc helper() {}\n")
        .file("added.go", "package main\nfunc unrelated() {}\n")
        .build();
        let base = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        // Receipts hold certificates only in this verifier test: the conversion
        // never produces one, but the verifier must stay sound for when it does.
        let certified = |name: &str| {
            let question = LookupQuestion::certified_definition(
                CertifiedDefinitionKind::Identifier,
                name,
                base.analyzer().languages(),
            );
            let digest = crate::analyzer::read_verification::certified_definition_answer_digest(
                base.analyzer(),
                &question,
            )
            .unwrap();
            let mut member = MemberReadReceipt::default();
            member.keys.insert(ReadKey::lookup(
                LookupKind::CertifiedDefinitionAnswer,
                question,
                digest,
            ));
            ProtocolMemberReceipt::from_member(&member, None).unwrap()
        };
        let receipt = certified("helper");
        let negative = certified("later");
        std::fs::write(
            project.root().join("added.go"),
            "package main\nfunc helper() {}\nfunc later() {}\n",
        )
        .unwrap();
        let changed = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        let verifier = crate::typestate::production::ProductionProtocolReceiptVerifier {
            workspace: changed,
            memo: Default::default(),
        };
        assert_eq!(verifier.verify(&receipt), ProtocolReceiptVerdict::Stale);
        assert_eq!(verifier.verify(&negative), ProtocolReceiptVerdict::Stale);
    }

    fn empty_protocol(state: &str) -> CompiledProtocol {
        use crate::typestate::{
            ProtocolAnalysisMode, ProtocolSemantics, ProtocolSpec, ProtocolUncertaintyBehavior,
            ProtocolUncertaintySemantics, ProtocolUnmatchedEventBehavior,
        };
        let uncertainty = ProtocolUncertaintyBehavior::PreserveUncertainty;
        ProtocolSpec {
            schema_version: crate::typestate::PROTOCOL_SCHEMA_VERSION,
            states: vec![state.into()],
            initial_state: state.into(),
            accepting_states: vec![state.into()],
            error_states: vec![],
            events: vec![],
            transitions: vec![],
            terminal_expectations: vec![],
            semantics: ProtocolSemantics {
                analysis_mode: ProtocolAnalysisMode::May,
                unmatched_event: ProtocolUnmatchedEventBehavior::MarkInconclusive,
                uncertainty: ProtocolUncertaintySemantics {
                    ambiguous_dispatch: uncertainty,
                    unknown_call: uncertainty,
                    external_call: uncertainty,
                    escape: uncertainty,
                    incomplete_analysis: uncertainty,
                },
            },
        }
        .compile()
        .expect("valid fixture protocol")
    }

    fn with_production_result_cache(
        limits: crate::typestate::TypestateSummaryRepositoryLimits,
        check: impl FnOnce(
            &crate::analyzer::WorkspaceAnalyzer,
            &crate::typestate::ProductionTypestateSummaryRepository,
            &dyn Fn() -> super::super::TypestateProductionCacheStatus,
        ),
    ) {
        with_production_result_cache_budgeted(limits, None, |workspace, repository, solve| {
            let status = || solve().cache_status();
            check(workspace, repository, &status);
        });
    }

    fn with_production_result_cache_budgeted(
        limits: crate::typestate::TypestateSummaryRepositoryLimits,
        application_limit: Option<usize>,
        check: impl FnOnce(
            &crate::analyzer::WorkspaceAnalyzer,
            &crate::typestate::ProductionTypestateSummaryRepository,
            &dyn Fn() -> crate::typestate::ProductionTypestateSolveResult,
        ),
    ) {
        use crate::analyzer::semantic::{CancellationToken, SemanticRequest};
        use crate::dataflow::{NoSummaryReadObserver, SolverBudget};
        use crate::typestate::{
            ProductionTypestateExecutionContext, ProductionTypestateSummaryRepository,
            solve_typestate_with_production_summaries,
        };
        let project = crate::inline_project::InlineTestProject::with_language(
            crate::analyzer::Language::TypeScript,
        )
        .file(
            "leaf.ts",
            "function leaf() { return 1; }\nexport function root() { return leaf(); }\n",
        )
        .build();
        let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("leaf.ts"),
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
            )
            .unwrap()
            .available_value()
            .cloned()
            .unwrap();
        let root = artifact
            .procedures()
            .iter()
            .find(|p| {
                p.locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|s| s.name())
                    == Some("root")
            })
            .and_then(|p| artifact.procedure_handle(p.id()))
            .unwrap();
        let protocol = empty_protocol("ready");
        let bindings =
            TypestateBindingPlan::try_new(&protocol, vec![], vec![], vec![], vec![]).unwrap();
        let repository = ProductionTypestateSummaryRepository::with_limits(
            limits,
            crate::analyzer::workspace_authority::workspace_memo_attribution(&workspace),
        );
        let provider = workspace.icfg_provider();
        let projection_provider = workspace.icfg_provider();
        let solve_with = |repository: &ProductionTypestateSummaryRepository,
                          semantic_budget: &mut SemanticBudget| {
            let mut solver_limits = SolverBudget::default().limits();
            if let Some(limit) = application_limit {
                solver_limits.summary_applications = limit;
            }
            let mut solver_budget = SolverBudget::new(solver_limits);
            solve_typestate_with_production_summaries(
                repository,
                &NoSummaryReadObserver,
                &root,
                &[],
                &provider,
                &projection_provider,
                None,
                ProductionTypestateExecutionContext::Workspace,
                &protocol,
                &bindings,
                semantic_budget,
                &mut DataflowRequest::new(&mut solver_budget, &cancellation),
            )
            .unwrap()
        };
        // Keep the real provider-owned dependencies resident, so these read
        // attribution tests exercise hits that pass cold-admission checks.
        let mut baseline = SemanticBudget::default();
        baseline.charge_complete_artifact(&artifact).unwrap();
        {
            let priming = ProductionTypestateSummaryRepository::with_limits(
                limits,
                crate::analyzer::workspace_authority::workspace_memo_attribution(&workspace),
            );
            drop(solve_with(&priming, &mut baseline));
        }
        baseline.release_transient_residency();
        let solve = || solve_with(&repository, &mut baseline.clone());
        check(&workspace, &repository, &solve);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2445: a same-capture result-cache hit refused unit reuse"
    )]
    fn same_capture_result_cache_hits_preserve_attributable_reads() {
        use crate::typestate::TypestateProductionCacheStatus::{Hit, MissPublished};
        with_production_result_cache(Default::default(), |workspace, _repository, solve| {
            let (_, reads) = capture_query_reads(workspace.analyzer(), || {
                assert_eq!(solve(), MissPublished);
                assert_eq!(solve(), Hit);
            });
            assert_eq!(reads.unattributed_reads(), 0);
            assert!(
                !reads.keys().is_empty(),
                "the fill must have recorded inputs"
            );
        });
    }

    #[test]
    fn budget_stopped_production_solve_does_not_publish_certified_results() {
        use crate::dataflow::SolverBudgetDimension;
        use crate::typestate::TypestateProductionCacheStatus::{Hit, MissPublished};
        with_production_result_cache_budgeted(
            Default::default(),
            Some(0),
            |_workspace, repository, solve| {
                for _ in 0..2 {
                    let result = solve();
                    assert_eq!(
                        result
                            .result()
                            .result()
                            .termination()
                            .budget_exceeded()
                            .unwrap()
                            .dimension(),
                        SolverBudgetDimension::SummaryApplications
                    );
                    assert_ne!(result.cache_status(), MissPublished);
                    assert_ne!(result.cache_status(), Hit);
                    assert_eq!(result.published_protocol_summaries(), 0);
                }
                assert_eq!(repository.retained_result_count(), 0);
            },
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2445: a same-capture result-cache hit refused unit reuse"
    )]
    fn later_capture_result_cache_hits_replay_the_fills_reads() {
        use crate::typestate::TypestateProductionCacheStatus::{Hit, MissPublished};
        with_production_result_cache(Default::default(), |workspace, _repository, solve| {
            let (_, fill) = capture_query_reads(workspace.analyzer(), || {
                assert_eq!(solve(), MissPublished);
            });
            assert_eq!(fill.unattributed_reads(), 0);
            assert!(!fill.keys().is_empty());
            let (_, hit) = capture_query_reads(workspace.analyzer(), || {
                assert_eq!(solve(), Hit);
            });
            assert_eq!(hit.keys(), fill.keys());
            assert_eq!(hit.unattributed_reads(), 0);
            assert!(hit.is_bounded());
        });
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2445: a same-capture result-cache hit refused unit reuse"
    )]
    fn nested_capture_result_cache_hits_replay_the_fills_reads() {
        use crate::typestate::TypestateProductionCacheStatus::{Hit, MissPublished};
        with_production_result_cache(Default::default(), |workspace, _repository, solve| {
            let (nested, outer) = capture_query_reads(workspace.analyzer(), || {
                assert_eq!(solve(), MissPublished);
                let (_, nested) = capture_query_reads(workspace.analyzer(), || {
                    assert_eq!(solve(), Hit);
                });
                assert_eq!(nested.unattributed_reads(), 0);
                assert!(nested.is_bounded());
                assert!(!nested.keys().is_empty());
                assert_eq!(solve(), Hit);
                nested
            });
            assert_eq!(outer.unattributed_reads(), 0);
            assert_eq!(outer.keys(), nested.keys());
        });
    }

    #[test]
    fn production_cache_hits_replay_direct_solve_reads() {
        use crate::analyzer::LookupKind;
        use crate::typestate::TypestateProductionCacheStatus::{Hit, MissPublished};
        with_production_result_cache(Default::default(), |workspace, _repository, solve| {
            let (_, fill) = capture_query_reads(workspace.analyzer(), || {
                assert_eq!(solve(), MissPublished);
            });
            let summary_reads = |keys: &[ReadKey]| {
                keys.iter()
                    .filter(|key| {
                        matches!(
                            key,
                            ReadKey::Lookup {
                                kind: LookupKind::ProcedureSummary,
                                ..
                            }
                        )
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            };
            let expected = summary_reads(&fill.keys());
            assert!(expected.is_empty(), "refused summaries have no lookup rows");
            assert!(!fill.keys().is_empty());
            let (_, hit) = capture_query_reads(workspace.analyzer(), || {
                assert_eq!(solve(), Hit);
            });
            assert_eq!(summary_reads(&hit.keys()), expected);
            assert_eq!(hit.keys(), fill.keys());
            assert_eq!(hit.unattributed_reads(), 0);
            assert!(hit.is_bounded());
        });
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2445: a same-capture result-cache hit refused unit reuse"
    )]
    fn uncaptured_result_cache_fills_replay_into_later_captures() {
        use crate::typestate::TypestateProductionCacheStatus::{Hit, MissPublished};
        with_production_result_cache(Default::default(), |workspace, _repository, solve| {
            assert_eq!(solve(), MissPublished);
            let (_, hit) = capture_query_reads(workspace.analyzer(), || {
                assert_eq!(solve(), Hit);
            });
            assert_eq!(hit.unattributed_reads(), 0);
            assert!(hit.is_bounded());
            assert!(!hit.keys().is_empty());
        });
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2445: over-budget exact-result receipts must refuse every later capture"
    )]
    fn oversized_result_cache_receipts_retain_only_a_bounded_refusal_marker() {
        use crate::typestate::{
            TypestateProductionCacheStatus::{Hit, MissPublished},
            TypestateSummaryRepositoryLimits,
        };
        let mut full_bytes = 0;
        with_production_result_cache(Default::default(), |_workspace, repository, solve| {
            assert_eq!(solve(), MissPublished);
            assert_eq!(repository.retained_result_count(), 1);
            full_bytes = repository.retained_result_bytes();
            assert!(repository.retained_result_receipt_bytes() > 0);
        });
        let limits = TypestateSummaryRepositoryLimits {
            max_result_bytes: full_bytes - 1,
            ..Default::default()
        };
        with_production_result_cache(limits, |workspace, repository, solve| {
            assert_eq!(solve(), MissPublished);
            assert_eq!(repository.retained_result_count(), 1);
            assert!(repository.retained_result_bytes() < full_bytes - 1);
            assert_eq!(repository.retained_result_receipt_bytes(), 0);
            for _ in 0..2 {
                let (_, hit) = capture_query_reads(workspace.analyzer(), || {
                    assert_eq!(solve(), Hit);
                });
                assert_eq!(
                    hit.unattributed_reads(),
                    2,
                    "both exact-result probes refuse"
                );
                assert!(!hit.is_bounded());
                assert_eq!(
                    repository.retained_result_receipt_bytes(),
                    0,
                    "an oversized receipt retains no keys"
                );
            }
        });
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2445: a diagnostic protocol probe refused typestate unit publication"
    )]
    fn diagnostic_protocol_presence_matches_row_filter_without_recording_reads() {
        crate::test_support::with_leaf_semantic_summary(|workspace, semantic| {
            let protocol = empty_protocol("ready");
            let other_protocol = empty_protocol("other");
            let bindings =
                TypestateBindingPlan::try_new(&protocol, vec![], vec![], vec![], vec![]).unwrap();
            let semantic_set = ProtocolSemanticSummarySet::try_new(vec![&semantic]).unwrap();
            let mut repository = CompleteProtocolSummaryRepository::new(
                crate::analyzer::workspace_authority::workspace_memo_attribution(workspace),
            );
            let check = |repository: &CompleteProtocolSummaryRepository,
                         protocol: &CompiledProtocol,
                         expected| {
                let (present, reads) = capture_query_reads(workspace.analyzer(), || {
                    semantic_set.has_compatible_rows_for_diagnostics(
                        &repository.storage,
                        protocol,
                        &bindings,
                    )
                });
                assert_eq!(present, expected);
                assert!(reads.keys().is_empty());
                assert_eq!(reads.unattributed_reads(), 0);
                assert_eq!(
                    present,
                    !semantic_set
                        .compatible_repository(
                            &repository.storage,
                            repository.attribution.clone(),
                            protocol,
                            &bindings
                        )
                        .is_empty()
                );
            };
            check(&repository, &protocol, false);
            let mut key = ProtocolSummaryKey::try_from_semantic_summary(
                &semantic,
                protocol.hash(),
                bindings.summary_hash_for(semantic.key().artifact(), semantic.key().declaration()),
                vec![],
            )
            .unwrap();
            repository
                .publish(ProtocolSummary::try_new(key.clone(), vec![], vec![]).unwrap())
                .unwrap();
            check(&repository, &protocol, true);
            check(&repository, &other_protocol, false);
            let mut repository = CompleteProtocolSummaryRepository::new(
                crate::analyzer::workspace_authority::workspace_memo_attribution(workspace),
            );
            key.bindings =
                TypestateBindingSummaryHash::from_canonical_bytes(b"different binding contract");
            repository
                .publish(ProtocolSummary::try_new(key, vec![], vec![]).unwrap())
                .unwrap();
            check(&repository, &protocol, false);
        });
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9642: conflicting effect fragments must refuse a reusable row"
    )]
    fn compatible_protocol_rows_consumed_by_a_standalone_solve_replay_receipts() {
        use crate::analyzer::semantic::{CancellationToken, SemanticRequest};
        use crate::dataflow::SolverBudget;
        let project = crate::inline_project::InlineTestProject::with_language(
            crate::analyzer::Language::TypeScript,
        )
        .file(
            "calls.ts",
            "export function leaf() { return 1; }\nexport function root() { return leaf(); }\n",
        )
        .build();
        let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("calls.ts"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap()
            .available_value()
            .cloned()
            .unwrap();
        let root = artifact
            .procedures()
            .iter()
            .find(|p| {
                p.locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|s| s.name())
                    == Some("root")
            })
            .and_then(|p| artifact.procedure_handle(p.id()))
            .unwrap();
        let summaries = crate::typestate::project_production_semantic_summaries(
            std::slice::from_ref(&root),
            &workspace.icfg_provider(),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap();
        // The standalone repository test supplies complete synthetic summaries.
        // Production projection itself must refuse reusable completeness.
        assert!(summaries.protocol_summaries().is_err());
        let complete = summaries
            .summaries()
            .iter()
            .map(|projected| {
                crate::dataflow::SemanticProcedureSummary::try_new_with_coverage(
                    projected.key().clone(),
                    projected.transfers().to_vec(),
                    projected.effects().to_vec(),
                    projected.dependencies().to_vec(),
                    crate::dataflow::SummaryCompleteness::Complete,
                    crate::test_support::complete_summary_coverage(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let semantic_set = ProtocolSemanticSummarySet::try_new(complete.iter().collect()).unwrap();
        let protocol = empty_protocol("ready");
        let bindings =
            TypestateBindingPlan::try_new(&protocol, vec![], vec![], vec![], vec![]).unwrap();
        let mut repository = CompleteProtocolSummaryRepository::new(
            crate::analyzer::workspace_authority::workspace_memo_attribution(&workspace),
        );
        let mut solver_budget = SolverBudget::default();
        let first = solve_typestate_with_reusable_summaries(
            &root,
            &[],
            &workspace.icfg_provider(),
            &protocol,
            &bindings,
            &semantic_set,
            &mut repository,
            &mut SemanticBudget::default(),
            &mut DataflowRequest::new(&mut solver_budget, &cancellation),
        )
        .unwrap();
        assert!(first.published_summaries() > 0);
        let fragment_row = repository
            .storage
            .entries
            .values()
            .find(|summary| {
                summary.rows.iter().any(|row| !row.fragments.is_empty())
                    || summary
                        .effects
                        .iter()
                        .any(|effect| !effect.fragments.is_empty())
            })
            .expect("published summary has witness fragments")
            .clone();
        let mut without_fragments = fragment_row.clone();
        for row in &mut without_fragments.rows {
            row.fragments = Box::default();
        }
        for effect in &mut without_fragments.effects {
            effect.fragments = Box::default();
        }
        let limit = protocol_repository_entry_bytes(&fragment_row) - 1;
        assert!(protocol_repository_entry_bytes(&without_fragments) <= limit);
        let mut limited = CompleteProtocolSummaryRepository::with_limits(
            ProtocolSummaryRepositoryLimits {
                max_entries: 1,
                max_bytes: limit,
            },
            crate::analyzer::workspace_authority::workspace_memo_attribution(&workspace),
        );
        assert_eq!(
            limited.publish(fragment_row),
            Err(ProtocolSummaryPublicationError::ByteLimitExceeded)
        );
        assert_eq!(
            limited.publish(without_fragments),
            Ok(ProtocolSummaryPublicationOutcome::Inserted)
        );
        assert!(
            repository
                .storage
                .entries
                .values()
                .all(|summary| !summary.receipt.keys.is_empty()),
            "published summaries need member reads: {:#?}",
            repository.storage.entries
        );
        let contracts = semantic_set
            .compute_binding_contracts(&bindings, || false)
            .unwrap();
        let strict_solve = |repository: &CompleteProtocolSummaryRepository,
                            witness_limit: Option<usize>,
                            application_limit: Option<usize>,
                            cancel_before_commit: bool| {
            #[derive(Debug)]
            struct CurrentReceipt;
            impl ProtocolReceiptVerifier for CurrentReceipt {
                fn verify(&self, _: &ProtocolMemberReceipt) -> ProtocolReceiptVerdict {
                    ProtocolReceiptVerdict::Current
                }
            }
            let mut oracle = ProtocolSummaryOracle {
                repository,
                receipt_verifier: Some(Arc::new(CurrentReceipt)),
                protocol: &protocol,
                bindings: &bindings,
                semantic_summaries: &semantic_set,
                binding_contracts: &contracts,
                remap: None,
                points: HashMap::new(),
            };
            let mut limits = SolverBudget::default().limits();
            if let Some(limit) = witness_limit {
                limits.witness_relations = limit;
            }
            if let Some(limit) = application_limit {
                limits.summary_applications = limit;
            }
            let mut solver_budget = SolverBudget::new(limits);
            let cancellation = CancellationToken::default();
            if cancel_before_commit {
                crate::dataflow::cancel_next_reusable_entry_before_commit();
            }
            super::super::client::solve_typestate_with_reusable_provider_with_retention(
                &root,
                &[],
                &workspace.icfg_provider(),
                &mut oracle,
                &protocol,
                &bindings,
                crate::dataflow::WitnessRetentionLimits::new(1).unwrap(),
                None,
                &mut SemanticBudget::default(),
                &mut DataflowRequest::new(&mut solver_budget, &cancellation),
            )
            .unwrap()
        };
        let empty = CompleteProtocolSummaryRepository::new(
            crate::analyzer::workspace_authority::workspace_memo_attribution(&workspace),
        );
        let fresh_strict = strict_solve(&empty, None, None, false);
        let served_strict = strict_solve(&repository, None, None, false);
        assert!(served_strict.result().metrics().reusable_summary_hits > 0);
        let fresh_end = fresh_strict.result().end_summaries().first().unwrap();
        let served_end = served_strict.result().end_summaries().first().unwrap();
        let quality = fresh_end.path_qualities().iter().next().unwrap();
        let fresh_witness = fresh_strict
            .result()
            .witness_for_end_summary(fresh_end, quality, WitnessReconstructionLimits::default())
            .unwrap();
        let served_witness = served_strict
            .result()
            .witness_for_end_summary(served_end, quality, WitnessReconstructionLimits::default())
            .unwrap();
        assert_eq!(fresh_witness.steps(), served_witness.steps());
        // Strict replay reserves all of an entry's witness nodes in one charge.
        // Find the first witness budget that admits the served entry, then
        // check both sides of that boundary on the same fixture.
        let full_witness_work = served_strict.result().work().witness_relations;
        let entry_boundary = (0..=full_witness_work)
            .find(|&limit| {
                strict_solve(&repository, Some(limit), None, false)
                    .result()
                    .metrics()
                    .reusable_summary_hits
                    > 0
            })
            .expect("the unbounded served solve admitted an entry");
        assert!(entry_boundary > 0);
        let below = strict_solve(&repository, Some(entry_boundary - 1), None, false);
        let staged_reservation = crate::dataflow::take_last_reusable_entry_reservation()
            .expect("the served entry reached its installation reservation");
        let below_result = below.result();
        let exceeded = below_result
            .termination()
            .budget_exceeded()
            .expect("below the atomic installation reservation must stop on budget");
        assert_eq!(
            exceeded.dimension(),
            crate::dataflow::SolverBudgetDimension::WitnessRelations
        );
        assert_eq!(below_result.metrics().reusable_summary_hits, 0);
        assert!(!below_result.is_complete());
        assert_eq!(
            below_result.witness_node_count(),
            below_result.work().witness_relations
        );
        assert!(below_result.work().witness_relations < entry_boundary);
        // The failed charge reports the prospective total. Subtracting the
        // committed work measures the entry's staged witness reservation,
        // independently of the search that found the boundary.
        let entry_witness_reservation =
            exceeded.attempted() - below_result.work().witness_relations;
        assert!(entry_witness_reservation > 0);
        assert_eq!(
            staged_reservation.witness_relations,
            entry_witness_reservation
        );
        assert_eq!(exceeded.limit(), entry_boundary - 1);
        assert_eq!(
            below_result.work().witness_relations + entry_witness_reservation,
            entry_boundary,
            "the whole staged entry is charged once"
        );
        assert!(below_result.reached().iter().all(
            |row| row.entry().procedure() == &root || row.point() == row.entry().entry_point()
        ));
        assert!(
            below_result
                .end_summaries()
                .iter()
                .all(|row| row.entry().procedure() == &root)
        );
        for limit in [entry_boundary, entry_boundary + 1] {
            let admitted = strict_solve(&repository, Some(limit), None, false);
            assert!(admitted.result().metrics().reusable_summary_hits > 0);
            assert!(admitted.result().work().witness_relations <= limit);
            if limit == entry_boundary {
                assert_eq!(
                    admitted.result().work().witness_relations,
                    below_result.work().witness_relations + entry_witness_reservation,
                    "entry admission charges its staged witnesses exactly once"
                );
            }
        }
        let rows_before_cancel = repository.storage.entries.clone();
        let cancelled = strict_solve(&repository, Some(entry_boundary), None, true);
        let cancelled_result = cancelled.result();
        assert_eq!(
            cancelled_result.termination(),
            crate::dataflow::SolverTermination::Cancelled
        );
        assert_eq!(cancelled_result.metrics().reusable_summary_hits, 0);
        assert!(!cancelled_result.is_complete());
        assert_eq!(repository.storage.entries, rows_before_cancel);
        assert_eq!(cancelled_result.facts(), below_result.facts());
        assert_eq!(cancelled_result.reached(), below_result.reached());
        assert_eq!(
            cancelled_result.witness_node_count(),
            below_result.witness_node_count()
        );
        assert_eq!(cancelled_result.work().witness_relations, entry_boundary);
        assert_eq!(
            cancelled_result.work().interned_facts,
            below_result.work().interned_facts + staged_reservation.interned_facts
        );
        assert_eq!(
            cancelled_result.work().reached_states,
            below_result.work().reached_states + staged_reservation.reached_states
        );
        assert_eq!(
            cancelled_result.work().end_summaries,
            below_result.work().end_summaries + staged_reservation.end_summaries
        );
        assert!(cancelled_result.reached().iter().all(
            |row| row.entry().procedure() == &root || row.point() == row.entry().entry_point()
        ));
        assert!(
            cancelled_result
                .end_summaries()
                .iter()
                .all(|row| row.entry().procedure() == &root)
        );
        // The reserved work stays charged: cancellation ends this solve before
        // any later application can consume its remaining budget.
        let application_stopped = strict_solve(&repository, None, Some(0), false);
        let application_result = application_stopped.result();
        let exceeded = application_result
            .termination()
            .budget_exceeded()
            .expect("application after entry installation must stop on budget");
        assert_eq!(
            exceeded.dimension(),
            crate::dataflow::SolverBudgetDimension::SummaryApplications
        );
        assert!(application_result.metrics().reusable_summary_hits > 0);
        assert_eq!(application_result.work().summary_applications, 0);
        assert!(application_result.work().witness_relations < full_witness_work);
        assert!(!application_result.is_complete());
        // The public publication path must leave the retained repository
        // unchanged when normal caller application runs out of budget.
        let mut budget_stopped_repository = repository.clone();
        #[derive(Debug)]
        struct CurrentReceipt;
        impl ProtocolReceiptVerifier for CurrentReceipt {
            fn verify(&self, _: &ProtocolMemberReceipt) -> ProtocolReceiptVerdict {
                ProtocolReceiptVerdict::Current
            }
        }
        budget_stopped_repository.bind_receipt_verifier(Arc::new(CurrentReceipt));
        let original_rows = budget_stopped_repository.storage.entries.clone();
        let mut limits = SolverBudget::default().limits();
        limits.summary_applications = 0;
        let mut solver_budget = SolverBudget::new(limits);
        let budget_stopped = solve_typestate_with_reusable_summaries(
            &root,
            &[],
            &workspace.icfg_provider(),
            &protocol,
            &bindings,
            &semantic_set,
            &mut budget_stopped_repository,
            &mut SemanticBudget::default(),
            &mut DataflowRequest::new(&mut solver_budget, &cancellation),
        )
        .unwrap();
        assert!(
            budget_stopped
                .result
                .result()
                .metrics()
                .reusable_summary_hits
                > 0
        );
        assert_eq!(
            budget_stopped
                .result
                .result()
                .termination()
                .budget_exceeded()
                .unwrap()
                .dimension(),
            crate::dataflow::SolverBudgetDimension::SummaryApplications
        );
        assert_eq!(budget_stopped.published_summaries(), 0);
        assert_eq!(budget_stopped_repository.storage.entries, original_rows);
        assert!(!budget_stopped.result.is_complete());
        let (_, reads) = capture_query_reads(workspace.analyzer(), || {
            let mut compatible = semantic_set.compatible_repository(
                &repository.storage,
                repository.attribution.clone(),
                &protocol,
                &bindings,
            );
            #[derive(Debug)]
            struct CurrentReceipt;
            impl ProtocolReceiptVerifier for CurrentReceipt {
                fn verify(&self, _: &ProtocolMemberReceipt) -> ProtocolReceiptVerdict {
                    ProtocolReceiptVerdict::Current
                }
            }
            compatible.bind_receipt_verifier(Arc::new(CurrentReceipt));
            assert!(!compatible.is_empty());
            let mut solver_budget = SolverBudget::default();
            let result = solve_typestate_with_reusable_summaries(
                &root,
                &[],
                &workspace.icfg_provider(),
                &protocol,
                &bindings,
                &semantic_set,
                &mut compatible,
                &mut SemanticBudget::default(),
                &mut DataflowRequest::new(&mut solver_budget, &cancellation),
            )
            .unwrap();
            assert!(result.was_reused(), "the solve must consume a retained row");
            assert!(
                result
                    .computed_result()
                    .result()
                    .metrics()
                    .reusable_summary_hits
                    > 0
            );
            assert!(
                repository
                    .storage
                    .entries
                    .values()
                    .any(|summary| summary.rows.iter().any(|row| !row.fragments.is_empty()))
            );
        });
        assert_eq!(reads.unattributed_reads(), 0);
        assert!(!reads.keys().is_empty());
        let fragment = repository
            .storage
            .entries
            .values_mut()
            .flat_map(|summary| summary.rows.iter_mut())
            .find_map(|row| row.fragments.first_mut())
            .expect("published row carries a fragment");
        let leaf = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("leaf")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .unwrap();
        let remap = ProtocolLiveRemap::try_new(&protocol, &bindings).unwrap();
        assert!(rebind_protocol_fragments(std::slice::from_ref(fragment), &leaf, &remap).is_some());
        let rebound = rebind_protocol_fragments(std::slice::from_ref(fragment), &leaf, &remap)
            .expect("published fragment rebinds");
        let point = rebound[0]
            .fragment
            .steps
            .last()
            .expect("fragment has an ending point")
            .output_point();
        let site = point.locator().expect("ending point has a locator");
        assert_eq!(rebound_effect_point(&rebound, site), Some(point.clone()));
        let mut disagreeing = rebound.to_vec();
        disagreeing.push(disagreeing[0].clone());
        let alternative = leaf
            .point_handle(leaf.semantics().entry_point())
            .expect("different point");
        assert_ne!(&alternative, point);
        disagreeing[1]
            .fragment
            .steps
            .last_mut()
            .expect("fragment has an ending point")
            .target = Some(alternative);
        assert!(rebound_effect_point(&disagreeing, site).is_none());
        let original_ordinal = fragment.1[0].source.ordinal;
        fragment.1[0].source.ordinal = usize::MAX;
        assert!(rebind_protocol_fragments(std::slice::from_ref(fragment), &leaf, &remap).is_none());
        let missed_strict = strict_solve(&repository, None, None, false);
        assert_eq!(missed_strict.result().metrics().reusable_summary_hits, 0);
        let leaf_summary = repository
            .storage
            .entries
            .values_mut()
            .find(|summary| summary.key.procedure.matches_procedure(&leaf))
            .expect("leaf summary was published");
        leaf_summary.rows[0].fragments[0].1[0].source.ordinal = original_ordinal;
        let row = leaf_summary.rows.first().expect("leaf has a row").clone();
        let mut fragments = row.fragments.to_vec();
        let mut changed = fragments[0].clone();
        changed
            .1
            .last_mut()
            .expect("fragment has a last step")
            .target = Some(crate::dataflow::WitnessPointRow {
            locator: leaf
                .point_handle(leaf.semantics().entry_point())
                .expect("leaf entry")
                .locator()
                .expect("leaf entry locator")
                .clone(),
            ordinal: leaf.semantics().entry_point().index(),
        });
        fragments.push(changed);
        leaf_summary.effects = vec![ProtocolObservedEffect {
            input: row.input,
            site: site.clone(),
            observation: row.output,
            evidence: row.evidence,
            fragments: fragments.into_boxed_slice(),
        }]
        .into_boxed_slice();
        let disagreement_miss = strict_solve(&repository, None, None, false);
        assert_eq!(
            disagreement_miss.result().metrics().reusable_summary_hits,
            0
        );
        assert_eq!(
            disagreement_miss.result().end_summaries().len(),
            fresh_strict.result().end_summaries().len(),
            "a refused row falls back to the fresh body solve"
        );
    }

    #[test]
    fn protocol_direct_and_entry_index_lookups_do_not_attribute_before_verification() {
        crate::test_support::with_leaf_semantic_summary(|workspace, semantic| {
            let key = ProtocolSummaryKey {
                procedure: semantic.key().clone(),
                protocol: TypestateProtocolHash::from_canonical_bytes(b"protocol memo fixture"),
                bindings: TypestateBindingSummaryHash::from_canonical_bytes(
                    b"binding memo fixture",
                ),
                schema_version: PROTOCOL_SUMMARY_SCHEMA_VERSION,
                entry_facts: vec![ProtocolFactKey::Zero].into_boxed_slice(),
            };
            let summary = ProtocolSummary::try_new(key.clone(), Vec::new(), Vec::new())
                .expect("empty complete fixture summary");
            let mut repository = CompleteProtocolSummaryRepository::new(
                crate::analyzer::workspace_authority::workspace_memo_attribution(workspace),
            );
            repository.publish(summary).expect("publish fixture");
            let (_, reads) = capture_query_reads(workspace.analyzer(), || {
                assert!(repository.get(&key).is_some());
            });
            assert!(reads.keys().is_empty());
            assert_eq!(reads.unattributed_reads(), 0);
            let (_, reads) = capture_query_reads(workspace.analyzer(), || {
                assert!(
                    repository
                        .matching_summary_for_entry(
                            &key.procedure,
                            key.protocol,
                            key.bindings,
                            &ProtocolFactKey::Zero
                        )
                        .is_some()
                );
            });
            assert!(reads.keys().is_empty());
            assert_eq!(reads.unattributed_reads(), 0);
        });
    }
}
