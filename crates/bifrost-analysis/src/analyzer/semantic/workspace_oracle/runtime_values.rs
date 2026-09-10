//! Activation-bound evidence for source-owned runtime keyed loads.
//!
//! Runtime model records identify an exposure and read behavior; syntax identifies
//! an occurrence. Neither is an executable value until it joins a MemoryLoad in
//! the exact immutable semantic artifact. This module owns that join.

use std::sync::Arc;

use crate::analyzer::semantic::{
    EvidenceCompleteness, MemoryLocationId, ProofStatus, SemanticGapId, StableDigest, ValueAtPoint,
};
use crate::analyzer::{ProjectFile, Range};

/// Identity filters applied only after structured runtime binding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct RuntimeKeyedReadFilter {
    pub runtime: String,
    pub global: String,
    pub container: String,
    pub property: Option<String>,
    pub index: Option<u128>,
    pub pristine_input: bool,
}

/// Static value-access identity, independent of declaration identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RuntimeAccessKey {
    Property(String),
    Index(u128),
}

/// One executable result under an exact captured runtime-model snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuntimeKeyedReadEndpoint {
    pub file: ProjectFile,
    pub expression: Range,
    pub candidate_anchor: Range,
    pub structural_identity: crate::analyzer::semantic::StructuralNodeIdentity,
    pub runtime: String,
    pub global: String,
    pub container: String,
    pub key: RuntimeAccessKey,
    pub observation: ValueAtPoint,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
    pub active_model_set_hash: String,
    pub refinement_identity: StableDigest,
    pub exposure_id: String,
    pub behavior_id: String,
    pub manifest_digest: String,
    pub shard_id: String,
    pub activation_source: String,
    pub producer: String,
    pub runtime_profile_digest: String,
    pub source_origin: RuntimeReadSourceOrigin,
    pub(crate) location: MemoryLocationId,
    pub(crate) container_observation: ValueAtPoint,
    pub(crate) container_location: MemoryLocationId,
    pub(crate) runtime_object: crate::analyzer::semantic::RuntimeObjectRoot,
    pub(crate) discharged_gaps: Arc<[SemanticGapId]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeReadSourceOrigin {
    PristineRuntimeInput,
    Mutated,
    Indeterminate,
}

/// Typed residual boundaries; absence of an exact endpoint is not a clean zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeReadLimitation {
    ActivationMissing,
    ActivationConflict,
    ActivationUnsupported,
    LexicalBindingIndeterminate,
    RebindingIndeterminate,
    MutationIncomplete,
    AccessorOrProxyIncomplete,
    MaterializationIncomplete,
    ExceptionBehaviorIndeterminate,
    DynamicKey,
    UnsupportedIndex,
    Cancelled,
    BudgetExhausted,
    StaleEvidence,
    AmbiguousOwner,
    CoverageLimited,
}

impl RuntimeReadLimitation {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ActivationMissing => "activation-missing",
            Self::ActivationConflict => "activation-conflict",
            Self::ActivationUnsupported => "activation-unsupported",
            Self::LexicalBindingIndeterminate => "lexical-binding-indeterminate",
            Self::RebindingIndeterminate => "rebinding-indeterminate",
            Self::MutationIncomplete => "mutation-incomplete",
            Self::AccessorOrProxyIncomplete => "accessor-or-proxy-incomplete",
            Self::MaterializationIncomplete => "materialization-incomplete",
            Self::ExceptionBehaviorIndeterminate => "exception-behavior-indeterminate",
            Self::DynamicKey => "dynamic-key",
            Self::UnsupportedIndex => "unsupported-index",
            Self::Cancelled => "cancelled",
            Self::BudgetExhausted => "budget-exhausted",
            Self::StaleEvidence => "stale-evidence",
            Self::AmbiguousOwner => "ambiguous-owner",
            Self::CoverageLimited => "coverage-limited",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeKeyedReadResult {
    pub endpoints: Vec<RuntimeKeyedReadEndpoint>,
    pub limitations: Vec<RuntimeReadLimitation>,
    pub conclusive_exclusion: bool,
    candidates: Vec<RuntimeKeyedReadCandidate>,
}

#[derive(Debug, Clone)]
struct RuntimeKeyedReadCandidate {
    anchor: Range,
    global: String,
    container: String,
    key: Option<RuntimeAccessKey>,
    excluded: bool,
}

use super::{WorkspaceSemanticOracle, exact_source_for_procedure};
use crate::analyzer::semantic::{
    LengthDelimitedDigest, ObservationPhase, OracleCallContext, ProcedureHandle,
    SemanticCapability, SemanticEffect, SemanticGap, SemanticGapSubject, SemanticOutcome,
    SemanticProviderError, SemanticRequest, SemanticWork,
};
use crate::analyzer::{Language, parser_language_for_dialect};

impl WorkspaceSemanticOracle<'_> {
    /// Bind a structured source candidate to its exact executable load.
    pub fn runtime_keyed_read_at_source(
        &self,
        file: &ProjectFile,
        range: Range,
        filter: &RuntimeKeyedReadFilter,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<RuntimeKeyedReadResult>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let materialized = self
            .workspace
            .materialize_program_semantics(file, request)?;
        let Some(artifact) = materialized.available_value() else {
            return Ok(materialized.map(|_| RuntimeKeyedReadResult::default()));
        };
        if !matches!(
            artifact.key().language().language(),
            Language::JavaScript | Language::TypeScript
        ) {
            return Ok(SemanticOutcome::Unsupported {
                capability: SemanticCapability::Values,
                partial: None,
                work: materialized.work(),
            });
        }
        let mut result = RuntimeKeyedReadResult::default();
        if !matches!(materialized, SemanticOutcome::Complete { .. }) {
            result
                .limitations
                .push(RuntimeReadLimitation::MaterializationIncomplete);
        }
        let mut work = materialized.work();
        for procedure in artifact.procedures() {
            let handle = artifact
                .procedure_handle(procedure.id())
                .expect("artifact procedure exists");
            let outcome = self.runtime_reads_for_procedure(&handle, request)?;
            work = work.conservative_add(outcome.work());
            if let Some(reads) = outcome.available_value() {
                let candidate_matches = |candidate: &RuntimeKeyedReadCandidate| {
                    same_byte_span(candidate.anchor, range)
                        && candidate.global == filter.global
                        && candidate.container == filter.container
                        && candidate.key.as_ref().is_none_or(|candidate_key| {
                            filter.property.as_ref().is_none_or(|key| {
                                candidate_key == &RuntimeAccessKey::Property(key.clone())
                            }) && filter.index.is_none_or(|index| {
                                candidate_key == &RuntimeAccessKey::Index(index)
                            })
                        })
                };
                for endpoint in &reads.endpoints {
                    if (same_byte_span(endpoint.expression, range)
                        || same_byte_span(endpoint.candidate_anchor, range))
                        && endpoint.runtime == filter.runtime
                        && endpoint.global == filter.global
                        && endpoint.container == filter.container
                        && filter.property.as_ref().is_none_or(|key| {
                            endpoint.key == RuntimeAccessKey::Property(key.clone())
                        })
                        && filter
                            .index
                            .is_none_or(|index| endpoint.key == RuntimeAccessKey::Index(index))
                        && (!filter.pristine_input
                            || endpoint.source_origin
                                == RuntimeReadSourceOrigin::PristineRuntimeInput)
                    {
                        result.endpoints.push(endpoint.clone());
                    }
                }
                if reads.candidates.iter().any(candidate_matches) {
                    for limitation in &reads.limitations {
                        if !result.limitations.contains(limitation) {
                            result.limitations.push(*limitation);
                        }
                    }
                }
                result.conclusive_exclusion |= reads
                    .candidates
                    .iter()
                    .any(|candidate| candidate.excluded && candidate_matches(candidate));
            }
            if !outcome.is_complete() && outcome.available_value().is_none() {
                result
                    .limitations
                    .push(RuntimeReadLimitation::MaterializationIncomplete);
            }
            match outcome {
                SemanticOutcome::Cancelled { .. } => {
                    return Ok(SemanticOutcome::Cancelled {
                        partial: Some(result),
                        work,
                    });
                }
                SemanticOutcome::ExceededBudget { exceeded, .. } => {
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: Some(result),
                        exceeded,
                        work,
                    });
                }
                _ => {}
            }
        }
        if !result.limitations.is_empty() {
            result.conclusive_exclusion = false;
        }
        Ok(if result.limitations.is_empty() {
            SemanticOutcome::Complete {
                value: result,
                work,
            }
        } else {
            SemanticOutcome::Unproven {
                partial: result,
                work,
            }
        })
    }
}

/// Only an effect's own source mapping and result mapping can select a load.
/// Container and terminal loads are returned separately to retain gap ownership.
fn loads_at_range(
    procedure: &ProcedureHandle,
    range: Range,
) -> Vec<(ValueAtPoint, MemoryLocationId)> {
    let mut loads = Vec::new();
    for point in procedure.semantics().points() {
        for event in &point.events {
            let SemanticEffect::MemoryLoad {
                location, result, ..
            } = event.effect
            else {
                continue;
            };
            let Some(value) = procedure.semantics().value(result) else {
                continue;
            };
            let Some(mapping) = procedure.semantics().source_mapping(value.source) else {
                continue;
            };
            let span = mapping.locator.anchor().span();
            if span.start_byte() as usize != range.start_byte
                || span.end_byte() as usize != range.end_byte
            {
                continue;
            }
            let value = procedure
                .value_handle(result)
                .expect("validated load result");
            let point = procedure
                .point_handle(point.id)
                .expect("validated load point");
            let observation = ValueAtPoint::new(
                value,
                point,
                ObservationPhase::AfterEffects,
                OracleCallContext::empty(),
            )
            .expect("load and result share their procedure");
            loads.push((observation, location));
        }
    }
    loads
}

fn gap_belongs_to_load(
    gap: &SemanticGap,
    observation: &ValueAtPoint,
    location: MemoryLocationId,
) -> bool {
    gap.discharge == crate::analyzer::semantic::SemanticGapDischarge::RuntimeReadBehavior
        && gap.point == observation.point().id()
        && ((gap.subject == SemanticGapSubject::MemoryLocation(location)
            && matches!(
                gap.capability,
                SemanticCapability::FieldMemory | SemanticCapability::IndexMemory
            ))
            || (gap.subject == SemanticGapSubject::Point
                && gap.capability == SemanticCapability::ExceptionalControlFlow))
}

use crate::analyzer::complete_value_cache::{CompleteValueAcquisition, CompleteValueCache};
use brokk_bifrost_js_ts::syntax::{
    JsTsRuntimeAccessKey, JsTsRuntimeMutationEvidence, JsTsRuntimeRootResolution,
    extract_js_ts_runtime_reads,
};

pub(super) type RuntimeReadCache = CompleteValueCache<ProcedureHandle, RuntimeKeyedReadResult>;

pub(super) fn runtime_read_cache() -> RuntimeReadCache {
    CompleteValueCache::new(
        8 * 1024 * 1024,
        |_, result: &Arc<RuntimeKeyedReadResult>| {
            result
                .endpoints
                .iter()
                .fold(
                    256usize.saturating_add(result.candidates.iter().fold(
                        0usize,
                        |total, candidate| {
                            total.saturating_add(
                                std::mem::size_of::<RuntimeKeyedReadCandidate>()
                                    + candidate.global.len()
                                    + candidate.container.len()
                                    + candidate.key.as_ref().map_or(0, |key| match key {
                                        RuntimeAccessKey::Property(property) => property.len(),
                                        RuntimeAccessKey::Index(_) => 0,
                                    }),
                            )
                        },
                    )),
                    |total, endpoint| {
                        total.saturating_add(
                            512 + endpoint.runtime.len()
                                + endpoint.global.len()
                                + endpoint.container.len()
                                + endpoint.active_model_set_hash.len()
                                + endpoint.manifest_digest.len()
                                + endpoint.shard_id.len()
                                + endpoint.activation_source.len()
                                + endpoint.producer.len()
                                + endpoint.runtime_profile_digest.len()
                                + endpoint.exposure_id.len()
                                + endpoint.behavior_id.len()
                                + match &endpoint.key {
                                    RuntimeAccessKey::Property(key) => key.len(),
                                    RuntimeAccessKey::Index(_) => 16,
                                }
                                + endpoint.discharged_gaps.len()
                                    * std::mem::size_of::<SemanticGapId>(),
                        )
                    },
                )
                .min(u32::MAX as usize) as u32
        },
    )
}

impl WorkspaceSemanticOracle<'_> {
    /// Ordinary semantic consumers pay no parse cost when the captured model
    /// snapshot has no runtime-value contracts to apply.
    pub(crate) fn runtime_refinements_for_procedure(
        &self,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<RuntimeKeyedReadResult>, SemanticProviderError> {
        if !self
            .active_semantic_models()
            .is_some_and(|active| active.runtime_values().next().is_some())
        {
            return Ok(SemanticOutcome::Complete {
                value: RuntimeKeyedReadResult::default(),
                work: SemanticWork::default(),
            });
        }
        self.runtime_reads_for_procedure(procedure, request)
    }

    /// The cache is owned by this immutable oracle activation snapshot, and the
    /// key retains exact artifact-instance identity. It never crosses snapshots.
    pub(super) fn runtime_reads_for_procedure(
        &self,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<RuntimeKeyedReadResult>, SemanticProviderError> {
        if !matches!(
            procedure.artifact().key().language().language(),
            Language::JavaScript | Language::TypeScript
        ) {
            return Ok(SemanticOutcome::Complete {
                value: RuntimeKeyedReadResult::default(),
                work: SemanticWork::default(),
            });
        }
        // Validate the current source before a hit as well as before a build.
        // An oracle may outlive an editor update; a retained artifact must not.
        let source = exact_source_for_procedure(
            self.workspace,
            procedure,
            request.budget.remaining().source_bytes,
        );
        match source {
            Err(SemanticProviderError::InvalidIdentity(_)) => {
                return Ok(SemanticOutcome::Unproven {
                    partial: RuntimeKeyedReadResult {
                        limitations: vec![RuntimeReadLimitation::StaleEvidence],
                        ..RuntimeKeyedReadResult::default()
                    },
                    work: SemanticWork::default(),
                });
            }
            Err(error) => return Err(error),
            Ok(None) => {
                return Ok(SemanticOutcome::Unknown {
                    partial: None,
                    work: SemanticWork::default(),
                });
            }
            Ok(Some(_)) => {}
        }
        let (acquisition, _) = self.runtime_reads.acquire(procedure, request.cancellation);
        let permit = match acquisition {
            CompleteValueAcquisition::Cached { value } => {
                let work = SemanticWork {
                    nested_entries: value.endpoints.len()
                        + value.limitations.len()
                        + value.candidates.len()
                        + 1,
                    ..SemanticWork::default()
                };
                if let Err(exceeded) = request.budget.charge(work) {
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    });
                }
                return Ok(SemanticOutcome::Complete {
                    value: (*value).clone(),
                    work,
                });
            }
            CompleteValueAcquisition::Leader { permit } => permit,
            CompleteValueAcquisition::Cancelled => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: SemanticWork::default(),
                });
            }
            CompleteValueAcquisition::Rejected => {
                return Ok(SemanticOutcome::Unknown {
                    partial: None,
                    work: SemanticWork::default(),
                });
            }
        };
        let outcome = self.build_runtime_reads(procedure, request)?;
        if let SemanticOutcome::Complete { value, .. } = &outcome {
            permit.publish_complete(Arc::new(value.clone()));
        }
        Ok(outcome)
    }

    fn build_runtime_reads(
        &self,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<RuntimeKeyedReadResult>, SemanticProviderError> {
        let mut result = RuntimeKeyedReadResult::default();
        let max_bytes = request.budget.remaining().source_bytes;
        // The initial effect proof closes one source module. A profile assertion
        // cannot discharge writes in sibling modules that have not been inspected.
        if self.workspace.project_file_count() != 1 {
            result
                .limitations
                .push(RuntimeReadLimitation::MutationIncomplete);
            return Ok(SemanticOutcome::Unproven {
                partial: result,
                work: SemanticWork::default(),
            });
        }
        let Some((file, source)) =
            exact_source_for_procedure(self.workspace, procedure, max_bytes)?
        else {
            result
                .limitations
                .push(RuntimeReadLimitation::MaterializationIncomplete);
            return Ok(SemanticOutcome::Unproven {
                partial: result,
                work: SemanticWork::default(),
            });
        };
        let mut work = SemanticWork {
            source_bytes: source.len(),
            procedures: 1,
            ..SemanticWork::default()
        };
        if let Err(exceeded) = request.budget.charge(work) {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work,
            });
        }
        let grammar = parser_language_for_dialect(procedure.artifact().key().language())
            .ok_or_else(|| SemanticProviderError::internal("runtime-read dialect has no parser"))?;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&grammar)
            .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
        let mut input = |offset: usize, _| &source.as_bytes()[offset..];
        let mut progress = |_: &tree_sitter::ParseState| request.cancellation.is_cancelled();
        let tree = parser.parse_with_options(
            &mut input,
            None,
            Some(tree_sitter::ParseOptions::new().progress_callback(&mut progress)),
        );
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work,
            });
        }
        let Some(tree) = tree else {
            result
                .limitations
                .push(RuntimeReadLimitation::MaterializationIncomplete);
            return Ok(SemanticOutcome::Unproven {
                partial: result,
                work,
            });
        };
        let facts = extract_js_ts_runtime_reads(
            tree.root_node(),
            &source,
            request.budget.remaining().nested_entries,
        );
        let fact_work = SemanticWork {
            nested_entries: facts
                .visited_nodes
                .saturating_add(facts.reads.len())
                .saturating_add(facts.writes.len()),
            ..SemanticWork::default()
        };
        work = work.conservative_add(fact_work);
        if let Err(exceeded) = request.budget.charge(fact_work) {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work,
            });
        }
        if !request.charge_execution_traversal(facts.visited_nodes) {
            result
                .limitations
                .push(RuntimeReadLimitation::BudgetExhausted);
            return Ok(SemanticOutcome::Unproven {
                partial: result,
                work,
            });
        }
        if !facts.complete || tree.root_node().has_error() {
            result
                .limitations
                .push(RuntimeReadLimitation::CoverageLimited);
        }
        for read in &facts.reads {
            let loads = loads_at_range(procedure, read.range);
            if loads.is_empty() {
                continue;
            }
            let key = match &read.access {
                JsTsRuntimeAccessKey::Property(property) => {
                    Some(RuntimeAccessKey::Property(property.clone()))
                }
                JsTsRuntimeAccessKey::Index(index) => {
                    Some(RuntimeAccessKey::Index(u128::from(*index)))
                }
                JsTsRuntimeAccessKey::Dynamic => {
                    result.limitations.push(RuntimeReadLimitation::DynamicKey);
                    None
                }
                JsTsRuntimeAccessKey::Unsupported => {
                    result
                        .limitations
                        .push(RuntimeReadLimitation::UnsupportedIndex);
                    None
                }
            };
            result.candidates.push(RuntimeKeyedReadCandidate {
                anchor: match read.access {
                    JsTsRuntimeAccessKey::Property(_) => read.range,
                    _ => read.container_range,
                },
                global: read.root_name.clone(),
                container: read.container.clone(),
                key: key.clone(),
                excluded: read.lexical_resolution == JsTsRuntimeRootResolution::LexicallyBound,
            });
            let Some(key) = key else {
                continue;
            };
            if read.lexical_resolution == JsTsRuntimeRootResolution::LexicallyBound {
                continue;
            }
            if facts.accessor_coverage
                != brokk_bifrost_js_ts::syntax::JsTsRuntimeAccessorCoverage::NoKnownAccessorEffects
            {
                result
                    .limitations
                    .push(RuntimeReadLimitation::AccessorOrProxyIncomplete);
                continue;
            }
            if read.lexical_resolution != JsTsRuntimeRootResolution::UnboundGlobal {
                result
                    .limitations
                    .push(RuntimeReadLimitation::LexicalBindingIndeterminate);
                continue;
            }
            if loads.len() != 1 {
                result
                    .limitations
                    .push(RuntimeReadLimitation::AmbiguousOwner);
                continue;
            }
            if read.mutation != JsTsRuntimeMutationEvidence::NoKnownWrite {
                result
                    .limitations
                    .push(RuntimeReadLimitation::MutationIncomplete);
                continue;
            }
            // Model selection and effect closure must precede publication. This
            // helper binds only contracts from the captured activation snapshot.
            self.bind_runtime_read_contract(procedure, &file, read, key, &loads[0], &mut result)?;
        }
        // Every runtime-shaped read in the closed footprint needs a modeled
        // effect contract. An unmodeled sibling may mutate the selected root.
        if !result.limitations.is_empty() {
            result.endpoints.clear();
        }
        result.limitations.sort_by_key(|limit| limit.label());
        result.limitations.dedup();
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: Some(result),
                work,
            });
        }
        Ok(if result.limitations.is_empty() {
            SemanticOutcome::Complete {
                value: result,
                work,
            }
        } else {
            SemanticOutcome::Unproven {
                partial: result,
                work,
            }
        })
    }
}

fn same_byte_span(left: Range, right: Range) -> bool {
    left.start_byte == right.start_byte && left.end_byte == right.end_byte
}

use crate::analyzer::semantic_model::{
    RuntimeAcceptedKeys, RuntimeCoverageStatus, RuntimeExceptionBehavior,
    RuntimeExposureActivation, RuntimeMaterialization, RuntimeMutationModel,
};
use brokk_bifrost_js_ts::syntax::JsTsRuntimeRead;

impl WorkspaceSemanticOracle<'_> {
    fn bind_runtime_read_contract(
        &self,
        procedure: &ProcedureHandle,
        file: &ProjectFile,
        read: &JsTsRuntimeRead,
        key: RuntimeAccessKey,
        load: &(ValueAtPoint, MemoryLocationId),
        result: &mut RuntimeKeyedReadResult,
    ) -> Result<(), SemanticProviderError> {
        let Some(active) = self.active_semantic_models() else {
            result
                .limitations
                .push(RuntimeReadLimitation::ActivationMissing);
            return Ok(());
        };
        if active
            .activation_report()
            .explanations
            .iter()
            .any(|explanation| {
                explanation.status
                    == crate::analyzer::semantic_model::SemanticModelActivationStatus::Conflict
            })
        {
            result
                .limitations
                .push(RuntimeReadLimitation::ActivationConflict);
            return Ok(());
        }
        let mut matches = Vec::new();
        for (payload, shard) in active.runtime_values() {
            for exposure in &payload.exposures {
                if exposure.binding_name != read.root_name
                    || !exposure
                        .languages
                        .contains(&shard.matched_evidence.language)
                    || !exposure.members.contains(&read.container)
                {
                    continue;
                }
                // A host must explicitly select the complete execution profile.
                // Catalog availability and the source language do not establish it.
                if shard.matched_evidence.configuration.as_deref()
                    != Some(&exposure.runtime_profile_digest)
                    || !shard
                        .matched_evidence
                        .package
                        .as_ref()
                        .is_some_and(|package| package.name == exposure.runtime.runtime_artifact)
                    || shard.matched_evidence.artifact_sha256.as_deref()
                        != Some(&exposure.runtime.runtime_artifact_digest)
                    || exposure.activation != RuntimeExposureActivation::Enabled
                {
                    continue;
                }
                for behavior in &payload.behaviors {
                    if behavior.exposure_id == exposure.exposure_id
                        && behavior.container_member == read.container
                    {
                        matches.push((exposure, behavior, shard));
                    }
                }
            }
        }
        let [(exposure, behavior, shard)] = matches.as_slice() else {
            result.limitations.push(if matches.is_empty() {
                RuntimeReadLimitation::ActivationMissing
            } else {
                RuntimeReadLimitation::ActivationConflict
            });
            return Ok(());
        };
        let identity = &exposure.root_identity;
        let runtime_identity_matches = identity.scheme == "csmi.runtime-global"
            && identity.scheme_version == "0.1.0"
            && identity.descriptors.len() == 2
            && identity.descriptors.iter().any(|descriptor| {
                descriptor.role == crate::analyzer::semantic_model::RuntimeRootRole::Runtime
                    && descriptor.name == exposure.runtime.runtime_family
            })
            && identity.descriptors.iter().any(|descriptor| {
                descriptor.role == crate::analyzer::semantic_model::RuntimeRootRole::Global
                    && descriptor.name == exposure.binding_name
            });
        if !runtime_identity_matches {
            result
                .limitations
                .push(RuntimeReadLimitation::ActivationUnsupported);
            return Ok(());
        }
        if exposure.coverage.status != RuntimeCoverageStatus::Complete
            || behavior.coverage.status != RuntimeCoverageStatus::Complete
            || !exposure.coverage.limitations.is_empty()
            || !behavior.coverage.limitations.is_empty()
            || active.activation_report().suppressed_explanations != 0
        {
            result
                .limitations
                .push(RuntimeReadLimitation::CoverageLimited);
            return Ok(());
        }
        if !matches!(
            (&key, behavior.accepted_keys),
            (
                RuntimeAccessKey::Property(_),
                RuntimeAcceptedKeys::StaticProperty
            ) | (RuntimeAccessKey::Index(_), RuntimeAcceptedKeys::StaticIndex)
        ) {
            result
                .limitations
                .push(RuntimeReadLimitation::UnsupportedIndex);
            return Ok(());
        }
        if behavior.exception_behavior != RuntimeExceptionBehavior::Nonthrowing {
            result
                .limitations
                .push(RuntimeReadLimitation::ExceptionBehaviorIndeterminate);
            return Ok(());
        }
        if behavior.materialization != RuntimeMaterialization::Eager {
            result
                .limitations
                .push(RuntimeReadLimitation::MaterializationIncomplete);
            return Ok(());
        }
        // These are explicit authored analysis assumptions. They are not
        // inferred from a file extension, Node declarations, or an absent binder.
        if exposure.runtime.initialization_boundary != "pristine-runtime-at-entry"
            || !exposure
                .runtime
                .host_assumptions
                .iter()
                .any(|assumption| assumption == "closed-workspace-no-preloads")
            || exposure.runtime.realm != "main"
            || exposure.runtime.platform.as_deref() != Some("linux")
        {
            result
                .limitations
                .push(RuntimeReadLimitation::MutationIncomplete);
            return Ok(());
        }
        if behavior.mutation_model != RuntimeMutationModel::PristineInputUntilWrite {
            result
                .limitations
                .push(RuntimeReadLimitation::MutationIncomplete);
            return Ok(());
        }
        let containers = loads_at_range(procedure, read.container_range);
        let [(container, container_location)] = containers.as_slice() else {
            result
                .limitations
                .push(RuntimeReadLimitation::AmbiguousOwner);
            return Ok(());
        };
        let terminal = procedure
            .semantics()
            .memory_location(load.1)
            .expect("validated load location");
        let base = match terminal.kind {
            crate::analyzer::semantic::MemoryLocationKind::Field { base, .. }
            | crate::analyzer::semantic::MemoryLocationKind::Property { base, .. }
            | crate::analyzer::semantic::MemoryLocationKind::Index { base, .. } => base,
            _ => {
                result
                    .limitations
                    .push(RuntimeReadLimitation::AmbiguousOwner);
                return Ok(());
            }
        };
        let key_agrees = match (&terminal.kind, &key) {
            (
                crate::analyzer::semantic::MemoryLocationKind::Property { key: actual, .. },
                RuntimeAccessKey::Property(expected),
            ) => actual == expected,
            (
                crate::analyzer::semantic::MemoryLocationKind::Index {
                    constant_index: Some(actual),
                    ..
                },
                RuntimeAccessKey::Index(expected),
            ) => actual == expected,
            _ => false,
        };
        if !key_agrees {
            result
                .limitations
                .push(RuntimeReadLimitation::AmbiguousOwner);
            return Ok(());
        }
        if base != container.value().id() {
            result
                .limitations
                .push(RuntimeReadLimitation::AmbiguousOwner);
            return Ok(());
        }
        let identity_observation = match key {
            RuntimeAccessKey::Index(_) => container,
            RuntimeAccessKey::Property(_) => &load.0,
        };
        let identity_row = procedure
            .semantics()
            .value(identity_observation.value().id())
            .expect("validated runtime identity observation");
        let identity_mapping = procedure
            .semantics()
            .source_mapping(identity_row.source)
            .expect("validated runtime identity source");
        let Some(structural_identity) = identity_mapping.ast_identity else {
            result
                .limitations
                .push(RuntimeReadLimitation::MaterializationIncomplete);
            return Ok(());
        };
        let mut identity = LengthDelimitedDigest::new(b"bifrost.runtime-read.v1");
        identity.push(procedure.artifact().key().public_fingerprint().as_bytes());
        identity.push(active.active_model_set_hash().as_bytes());
        identity.push(exposure.runtime_profile_digest.as_bytes());
        identity.push(shard.manifest.content_sha256.as_bytes());
        procedure
            .semantics()
            .locator()
            .push_stable_identity(&mut identity);
        identity.push(exposure.exposure_id.as_bytes());
        identity.push(behavior.behavior_id.as_bytes());
        identity.push(&(read.range.start_byte as u64).to_le_bytes());
        identity.push(&(read.range.end_byte as u64).to_le_bytes());
        let discharged_gaps = procedure
            .semantics()
            .gaps()
            .iter()
            .filter(|gap| {
                gap_belongs_to_load(gap, &load.0, load.1)
                    || gap_belongs_to_load(gap, container, *container_location)
            })
            .map(|gap| gap.id)
            .collect::<Vec<_>>();
        let refinement_identity = identity.finish();
        let mut object_identity = LengthDelimitedDigest::new(b"bifrost.runtime-object.v1");
        object_identity.push(procedure.artifact().key().public_fingerprint().as_bytes());
        object_identity.push(active.active_model_set_hash().as_bytes());
        object_identity.push(exposure.runtime_profile_digest.as_bytes());
        object_identity.push(exposure.exposure_id.as_bytes());
        object_identity.push(read.container.as_bytes());
        object_identity.push(exposure.runtime.initialization_boundary.as_bytes());
        let activation = crate::analyzer::semantic::RuntimeObjectActivation::captured(
            active.active_model_set_hash().to_owned(),
            exposure.runtime_profile_digest.clone(),
            shard.manifest.content_sha256.clone(),
            shard.shard.shard_id().to_owned(),
            exposure.exposure_id.clone(),
            behavior.behavior_id.clone(),
            shard.source_id.clone(),
        )
        .expect("validated runtime activation retains nonempty ownership");
        let runtime_object = crate::analyzer::semantic::RuntimeObjectRoot::captured_single_realm(
            exposure.runtime_profile_digest.clone(),
            exposure.runtime.realm.clone(),
            exposure.exposure_id.clone(),
            read.container.clone(),
            exposure.runtime.initialization_boundary.clone(),
            object_identity.finish(),
            activation,
        )
        .expect("unique main realm runtime proof agrees with captured activation");
        result.endpoints.push(RuntimeKeyedReadEndpoint {
            file: file.clone(),
            expression: read.range,
            candidate_anchor: match key {
                RuntimeAccessKey::Index(_) => read.container_range,
                _ => read.range,
            },
            structural_identity,
            runtime: exposure.runtime.runtime_family.clone(),
            global: read.root_name.clone(),
            container: read.container.clone(),
            key,
            observation: load.0.clone(),
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            active_model_set_hash: active.active_model_set_hash().to_owned(),
            refinement_identity,
            exposure_id: exposure.exposure_id.clone(),
            behavior_id: behavior.behavior_id.clone(),
            manifest_digest: shard.manifest.content_sha256.clone(),
            shard_id: shard.shard.shard_id().to_owned(),
            activation_source: shard.source_id.clone(),
            producer: format!(
                "{}@{}",
                shard.manifest.producer.name, shard.manifest.producer.version
            ),
            runtime_profile_digest: exposure.runtime_profile_digest.clone(),
            source_origin: RuntimeReadSourceOrigin::PristineRuntimeInput,
            location: load.1,
            container_observation: container.clone(),
            container_location: *container_location,
            runtime_object,
            discharged_gaps: discharged_gaps.into(),
        });
        Ok(())
    }
}

impl RuntimeKeyedReadResult {
    pub(crate) fn discharges(&self, gap: SemanticGapId) -> bool {
        self.endpoints
            .iter()
            .any(|endpoint| endpoint.discharged_gaps.contains(&gap))
    }
}

impl WorkspaceSemanticOracle<'_> {
    /// Reacquire the activation-bound proof before consuming a retained endpoint.
    /// The ordinary full-expression source projection remains the only heap path.
    pub fn pointees_for_keyed_read(
        &self,
        endpoint: &RuntimeKeyedReadEndpoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<super::SourcePointsToResult>, SemanticProviderError> {
        let filter = RuntimeKeyedReadFilter {
            runtime: endpoint.runtime.clone(),
            global: endpoint.global.clone(),
            container: endpoint.container.clone(),
            property: match &endpoint.key {
                RuntimeAccessKey::Property(key) => Some(key.clone()),
                _ => None,
            },
            index: match endpoint.key {
                RuntimeAccessKey::Index(index) => Some(index),
                _ => None,
            },
            pristine_input: true,
        };
        let rebound = self.runtime_keyed_read_at_source(
            &endpoint.file,
            endpoint.expression,
            &filter,
            request,
        )?;
        match &rebound {
            SemanticOutcome::Cancelled { work, .. } => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: *work,
                });
            }
            SemanticOutcome::ExceededBudget { exceeded, work, .. } => {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded: *exceeded,
                    work: *work,
                });
            }
            _ => {}
        }
        let valid = matches!(rebound, SemanticOutcome::Complete { .. })
            && rebound.available_value().is_some_and(|reads| {
                reads.endpoints.iter().any(|current| {
                    current.refinement_identity == endpoint.refinement_identity
                        && current.observation == endpoint.observation
                        && current.location == endpoint.location
                        && current.structural_identity == endpoint.structural_identity
                        && current.container_observation == endpoint.container_observation
                        && current.container_location == endpoint.container_location
                        && current.runtime_object == endpoint.runtime_object
                })
            });
        if !valid {
            return Ok(SemanticOutcome::Unknown {
                partial: None,
                work: rebound.work(),
            });
        }
        let mut outcome = self.pointees_at_source(&endpoint.file, endpoint.expression, request)?;
        let work = match &mut outcome {
            SemanticOutcome::Complete { work, .. }
            | SemanticOutcome::Unproven { work, .. }
            | SemanticOutcome::Unknown { work, .. }
            | SemanticOutcome::Ambiguous { work, .. }
            | SemanticOutcome::Unsupported { work, .. }
            | SemanticOutcome::Cancelled { work, .. }
            | SemanticOutcome::ExceededBudget { work, .. } => work,
        };
        *work = work.conservative_add(rebound.work());
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::SemanticBudget;
    use crate::test_support::AnalyzerFixture;

    #[test]
    fn absent_runtime_activation_is_not_an_exact_or_clean_source() {
        let source = "function run() { return process.env.DFB_INPUT; }";
        let fixture =
            AnalyzerFixture::new_for_language(Language::JavaScript, &[("probe.js", source)]);
        let file = ProjectFile::new(fixture.project_root(), "probe.js");
        let start = source.find("process.env.DFB_INPUT").unwrap();
        let range = Range {
            start_byte: start,
            end_byte: start + "process.env.DFB_INPUT".len(),
            start_line: 0,
            end_line: 0,
        };
        let filter = RuntimeKeyedReadFilter {
            runtime: "node".into(),
            global: "process".into(),
            container: "env".into(),
            property: Some("DFB_INPUT".into()),
            pristine_input: true,
            ..RuntimeKeyedReadFilter::default()
        };
        let mut budget = SemanticBudget::default();
        let cancellation = crate::CancellationToken::default();
        let outcome = fixture
            .analyzer
            .semantic_oracle_provider()
            .runtime_keyed_read_at_source(
                &file,
                range,
                &filter,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("runtime candidate query runs");
        assert!(
            !outcome.is_complete(),
            "missing activation must not certify absence"
        );
        let result = outcome
            .available_value()
            .expect("typed runtime limitation is retained");
        assert!(result.endpoints.is_empty());
        assert!(!result.conclusive_exclusion);
        assert!(
            result
                .limitations
                .contains(&RuntimeReadLimitation::ActivationMissing)
        );
    }

    #[test]
    fn runtime_query_budget_exhaustion_does_not_certify_absence() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::JavaScript,
            &[("probe.js", "const value = process.argv[2];")],
        );
        let cancellation = crate::CancellationToken::default();
        let mut budget = SemanticBudget::uniform(1).unwrap();
        let file = ProjectFile::new(fixture.project_root(), "probe.js");
        let range = Range {
            start_byte: 14,
            end_byte: 29,
            start_line: 0,
            end_line: 0,
        };
        let outcome = fixture
            .analyzer
            .semantic_oracle_provider()
            .runtime_keyed_read_at_source(
                &file,
                range,
                &RuntimeKeyedReadFilter::default(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("budget interruption is a semantic outcome");
        assert!(matches!(outcome, SemanticOutcome::ExceededBudget { .. }));
        assert!(
            outcome
                .available_value()
                .is_none_or(|result| result.endpoints.is_empty() && !result.conclusive_exclusion)
        );
    }

    #[test]
    fn cancelled_runtime_query_does_not_materialize_or_publish() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::JavaScript,
            &[("probe.js", "const value = process.argv[2];")],
        );
        let cancellation = crate::CancellationToken::default();
        cancellation.cancel();
        let mut budget = SemanticBudget::default();
        let file = ProjectFile::new(fixture.project_root(), "probe.js");
        let range = Range {
            start_byte: 14,
            end_byte: 29,
            start_line: 0,
            end_line: 0,
        };
        let outcome = fixture
            .analyzer
            .semantic_oracle_provider()
            .runtime_keyed_read_at_source(
                &file,
                range,
                &RuntimeKeyedReadFilter::default(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("cancellation is semantic, not provider failure");
        assert!(
            matches!(outcome, SemanticOutcome::Cancelled { partial: None, work } if work == SemanticWork::default())
        );
    }
}
