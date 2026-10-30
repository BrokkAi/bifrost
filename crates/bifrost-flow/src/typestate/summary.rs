//! Stable, reusable protocol summaries projected from complete typestate solves.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::mem::size_of;

use crate::analyzer::semantic::{
    DurableValueIdentity, IcfgProvider, ProcedureHandle, ReturnTransferKind, SemanticBudget,
    SemanticLocator,
};
use crate::dataflow::{
    DataflowRequest, PathQuality, PathQualityFrontier, ProcedureSummaryKey, ReusableEndSummary,
    ReusableProcedureSummary, ReusableReachedFact, ReusableSummaryError, ReusableSummaryProvider,
    SemanticProcedureSummary, SemanticSummaryArtifactIndex, SemanticSummarySetValidationError,
    SolverTermination, SummaryCallCycle, SummaryCalledProcedures, SummaryDependencyKey,
    SummaryExitKind, SummaryRecursiveGroupKey, canonical_semantic_summaries_by_artifact,
    path_evidence_from_frontier, path_evidence_has_complete_path,
    path_evidence_has_proven_complete_path, path_evidence_has_proven_path, path_evidence_qualities,
    validate_recursive_summary_batch,
};

use super::client::solve_typestate_with_reusable_provider;
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
        if !semantic_summary.completeness().is_complete() {
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
        let (summaries, by_artifact) = canonical_semantic_summaries_by_artifact(summaries)
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
    /// Any path serving rows to a solve must use compatible_repository, which
    /// retains record_protocol_repository_read and its unattributed refusal.
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

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Production rejects row reuse; row-serving paths must retain attribution"
        )
    )]
    pub(super) fn compatible_repository(
        &self,
        repository: &CompleteProtocolSummaryRepository,
        protocol: &CompiledProtocol,
        bindings: &TypestateBindingPlan,
    ) -> CompleteProtocolSummaryRepository {
        if !repository.storage.entries.is_empty() {
            repository.record_read();
        }
        let mut compatible = CompleteProtocolSummaryRepository::with_limits(
            repository.limits(),
            repository.attribution.clone(),
        );
        let Some(contracts) = self.compute_binding_contracts(bindings, || false) else {
            return compatible;
        };
        for summary in repository.storage.entries.values() {
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
        const ALL: [TypestateUncertainty; 6] = [
            TypestateUncertainty::AmbiguousDispatch,
            TypestateUncertainty::UnknownCall,
            TypestateUncertainty::ExternalCall,
            TypestateUncertainty::Escape,
            TypestateUncertainty::IncompleteAnalysis,
            TypestateUncertainty::UnmatchedEvent,
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolSummaryRow {
    input: ProtocolFactKey,
    exit_kind: SummaryExitKind,
    output: ProtocolFactKey,
    evidence: ProtocolPathEvidence,
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolObservedEffect {
    input: ProtocolFactKey,
    site: SemanticLocator,
    observation: ProtocolFactKey,
    evidence: ProtocolPathEvidence,
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
        })
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
        size_of::<Self>()
            .saturating_add(protocol_key_heap_bytes(&self.key))
            .saturating_add(size_of::<ProtocolSummaryKey>())
            .saturating_add(protocol_key_heap_bytes(&self.key))
            .saturating_add(size_of_val(self.rows()))
            .saturating_add(self.rows.iter().fold(0_usize, |total, row| {
                total
                    .saturating_add(protocol_fact_heap_bytes(&row.input))
                    .saturating_add(protocol_fact_heap_bytes(&row.output))
            }))
            .saturating_add(size_of_val(self.effects()))
            .saturating_add(self.effects.iter().fold(0_usize, |total, effect| {
                total
                    .saturating_add(protocol_fact_heap_bytes(&effect.input))
                    .saturating_add(crate::value_flow::semantic_locator_heap_bytes(&effect.site))
                    .saturating_add(protocol_fact_heap_bytes(&effect.observation))
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
#[derive(Debug, Clone)]
pub struct CompleteProtocolSummaryRepository {
    storage: CompleteProtocolSummaryStorage,
    attribution: crate::analyzer::workspace_authority::OwnedMemoCapability,
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
        }
    }
    fn record_read(&self) {
        record_protocol_repository_read(&self.attribution);
    }
    pub fn get(&self, key: &ProtocolSummaryKey) -> Option<&ProtocolSummary> {
        let answer = self.storage.get(key);
        if answer.is_some() {
            self.record_read();
        }
        answer
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
        let answer = self
            .storage
            .matching_summary_for_entry(procedure, protocol, bindings, entry);
        if answer.is_some() {
            self.record_read();
        }
        answer
    }
    pub(super) fn into_publication_batches(self) -> ProtocolSummaryPublicationBatches {
        self.storage.into_publication_batches()
    }
}

/// Source keys cover the complete index, including negative membership. Until
/// non-source protocol inputs have a replay receipt, refuse unit reuse too.
pub(super) fn record_protocol_repository_read(
    attribution: &crate::analyzer::workspace_authority::OwnedMemoCapability,
) {
    let analyzer = attribution.analyzer();
    crate::analyzer::workspace_authority::record_workspace_authority_read(
        analyzer,
        crate::analyzer::WorkspaceFactFamily::ProtocolSummaries,
        crate::analyzer::workspace_authority::AuthorityInputs::SourceOf(
            &crate::analyzer::Language::ALL,
        ),
    );
    if attribution.capability().is_capturing() {
        attribution.capability().record_unattributed();
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
    protocol: &'query CompiledProtocol,
    bindings: &'query TypestateBindingPlan,
    semantic_summaries: &'query ProtocolSemanticSummarySet<'semantic>,
    binding_contracts: &'query ProtocolBindingContracts,
    remap: Option<ProtocolLiveRemap<'query>>,
    points: HashMap<
        ProcedureHandle,
        HashMap<SemanticLocator, crate::analyzer::semantic::ProgramPointHandle>,
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
                points.insert(super::binding::program_point_locator(&handle), handle);
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
            });
        }
        let mut reached = Vec::with_capacity(effect_count);
        for effect in &summary.effects[effect_range] {
            if request.cancellation.is_cancelled() {
                return Err(SolverTermination::Cancelled.into());
            }
            reached.push(ReusableReachedFact {
                point: points
                    .and_then(|points| points.get(&effect.site))
                    .expect("validated protocol summary effect site remaps")
                    .clone(),
                fact: remap
                    .fact(&effect.observation)
                    .expect("validated protocol summary observation remaps"),
                qualities: effect.evidence.qualities(),
            });
        }
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
    let result = {
        let mut reusable = ProtocolSummaryOracle {
            repository,
            protocol,
            bindings,
            semantic_summaries,
            binding_contracts: &binding_contracts,
            remap: None,
            points: HashMap::new(),
        };
        solve_typestate_with_reusable_provider(
            root,
            entry_facts,
            provider,
            &mut reusable,
            protocol,
            bindings,
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
}

struct ProtocolProjectionBatch {
    summaries: Vec<ProtocolSummary>,
    skipped: bool,
}

fn project_complete_protocol_summaries(
    semantic_summaries: &ProtocolSemanticSummarySet<'_>,
    binding_contracts: &ProtocolBindingContracts,
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
    result: &TypestateSummaryResult,
    request: &DataflowRequest<'_>,
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
        projection.rows.push(ProtocolSummaryRow {
            input,
            exit_kind: exit_kind(summary.exit_kind()),
            output: ProtocolFactKey::from_live(*output, protocol, bindings)?,
            evidence: ProtocolPathEvidence::from_frontier(summary.path_qualities()),
        });
    }
    for reached in result.result().reached() {
        if request.cancellation.is_cancelled() {
            return Ok(ProtocolProjectionBatch {
                summaries: Vec::new(),
                skipped: true,
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
        projection.effects.push(ProtocolObservedEffect {
            input,
            site: super::binding::program_point_locator(reached.point()),
            observation,
            evidence: ProtocolPathEvidence::from_frontier(reached.path_qualities()),
        });
    }

    let mut skipped = !ineligible.is_empty();
    let mut summaries = Vec::with_capacity(projections.len());
    for (procedure, projection) in projections {
        let semantic = semantic_summaries
            .unique_summary_for(&procedure)
            .ok_or(ProtocolSummaryError::ProcedureMismatch)?;
        if projection.oversized
            || semantic
                .key()
                .recursive_group()
                .is_some_and(|group| effectful_recursive_groups.contains(&group))
        {
            skipped = true;
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
        summaries.push(ProtocolSummary::try_new(
            key,
            projection.rows,
            projection.effects,
        )?);
    }
    summaries.sort_unstable_by(|left, right| left.key.cmp(&right.key));
    Ok(ProtocolProjectionBatch { summaries, skipped })
}

fn publish_protocol_summaries(
    repository: &mut CompleteProtocolSummaryRepository,
    summaries: Vec<ProtocolSummary>,
    binding_contracts: &ProtocolBindingContracts,
    projection_skipped: bool,
) -> Result<(ProtocolSummaryCacheStatus, usize), ProtocolSummarySolveError> {
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
        let solve = || {
            solve_typestate_with_production_summaries(
                &repository,
                &NoSummaryReadObserver,
                &root,
                &[],
                &workspace.icfg_provider(),
                &workspace.icfg_provider(),
                ProductionTypestateExecutionContext::Workspace,
                &protocol,
                &bindings,
                &mut SemanticBudget::default(),
                &mut DataflowRequest::new(&mut SolverBudget::default(), &cancellation),
            )
            .unwrap()
            .cache_status()
        };
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
    #[brokk_bifrost_test_macros::hardwon(
        "#7884: a typestate production-cache hit recorded no callee-summary reads"
    )]
    fn production_cache_hits_replay_callee_summary_reads() {
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
            assert!(
                expected.len() >= 2,
                "root and callee must both be recorded: {fill:?}"
            );
            let (_, hit) = capture_query_reads(workspace.analyzer(), || {
                assert_eq!(solve(), Hit);
            });
            assert_eq!(summary_reads(&hit.keys()), expected);
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
                        .compatible_repository(repository, protocol, &bindings)
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
    fn compatible_protocol_rows_consumed_by_a_standalone_solve_remain_unattributed() {
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
        let semantic_set = summaries.protocol_summaries().unwrap();
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
        let (_, reads) = capture_query_reads(workspace.analyzer(), || {
            let mut compatible =
                semantic_set.compatible_repository(&repository, &protocol, &bindings);
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
        });
        assert!(reads.unattributed_reads() > 0);
        assert!(
            reads
                .keys()
                .iter()
                .any(|key| matches!(key, ReadKey::Scope { .. }))
        );
    }

    #[test]
    fn protocol_direct_and_entry_index_hits_record_inputs_and_refuse_unnamed_reads() {
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
            assert!(
                reads
                    .keys()
                    .iter()
                    .any(|key| matches!(key, ReadKey::Scope { .. }))
            );
            assert!(reads.unattributed_reads() > 0);
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
            assert!(
                reads
                    .keys()
                    .iter()
                    .any(|key| matches!(key, ReadKey::Scope { .. }))
            );
            assert!(reads.unattributed_reads() > 0);
        });
    }
}
