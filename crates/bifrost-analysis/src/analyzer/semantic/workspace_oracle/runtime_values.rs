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
    pub key_kind: Option<RuntimeKeyedReadKeyKind>,
    pub index_min: Option<u128>,
    pub index_max: Option<u128>,
    pub pristine_input: bool,
}

/// Select a family of already resolved keys without creating binding evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeKeyedReadKeyKind {
    StaticProperty,
    StaticIndex,
}

impl RuntimeKeyedReadFilter {
    fn accepts_key(&self, key: &RuntimeAccessKey) -> bool {
        match key {
            RuntimeAccessKey::Property(property) => {
                self.index.is_none()
                    && self.index_min.is_none()
                    && self.index_max.is_none()
                    && self.key_kind != Some(RuntimeKeyedReadKeyKind::StaticIndex)
                    && self
                        .property
                        .as_ref()
                        .is_none_or(|expected| expected == property)
            }
            RuntimeAccessKey::Index(index) => {
                self.property.is_none()
                    && self.key_kind != Some(RuntimeKeyedReadKeyKind::StaticProperty)
                    && self.index.is_none_or(|expected| expected == *index)
                    && self.index_min.is_none_or(|minimum| minimum <= *index)
                    && self.index_max.is_none_or(|maximum| *index <= maximum)
            }
        }
    }
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
use crate::analyzer::{Language, LanguageDialect, parser_language_for_dialect};

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
        if !RUNTIME_KEYED_READ_LANGUAGES.contains(&artifact.key().language().language()) {
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
                        // Missing key identity retains dynamic/unsupported
                        // limitations for this surface; it is not a filtered zero.
                        && candidate.key.as_ref().is_none_or(|key| filter.accepts_key(key))
                };
                for endpoint in &reads.endpoints {
                    if (same_byte_span(endpoint.expression, range)
                        || same_byte_span(endpoint.candidate_anchor, range))
                        && endpoint.runtime == filter.runtime
                        && endpoint.global == filter.global
                        && endpoint.container == filter.container
                        && filter.accepts_key(&endpoint.key)
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

/// Whether one lowering claim about a load is answered by the reviewed
/// keyed-read behavior.
///
/// `nonthrowing` is the reviewed behavior's own claim. A container whose keyed
/// read may raise answers the key's identity but not the load's exceptional
/// control flow, so that claim stays open for the flow analysis to carry.
fn gap_belongs_to_load(
    gap: &SemanticGap,
    observation: &ValueAtPoint,
    location: MemoryLocationId,
    nonthrowing: bool,
) -> bool {
    if gap.discharge != crate::analyzer::semantic::SemanticGapDischarge::RuntimeReadBehavior {
        return false;
    }
    // The claim about what produced the loaded value is published ahead of the
    // load, so it is matched by the value it names rather than by its point.
    if gap.capability == SemanticCapability::Calls
        && gap.subject == SemanticGapSubject::Value(observation.value().id())
    {
        return true;
    }
    gap.point == observation.point().id()
        && ((gap.subject == SemanticGapSubject::MemoryLocation(location)
            && matches!(
                gap.capability,
                SemanticCapability::FieldMemory | SemanticCapability::IndexMemory
            ))
            || (nonthrowing
                && gap.subject == SemanticGapSubject::Point
                && gap.capability == SemanticCapability::ExceptionalControlFlow))
}

use crate::analyzer::complete_value_cache::{CompleteValueAcquisition, CompleteValueCache};
use brokk_bifrost_js_ts::syntax::{
    JsTsRuntimeAccessKey, JsTsRuntimeAccessorCoverage, JsTsRuntimeMutationEvidence,
    JsTsRuntimeReadFacts, JsTsRuntimeRootResolution, extract_js_ts_runtime_reads,
};
use brokk_bifrost_python::runtime_values::{
    PythonRuntimeAccessKey, PythonRuntimeAccessorCoverage, PythonRuntimeMutationEvidence,
    PythonRuntimeReadFacts, PythonRuntimeRootResolution, extract_python_runtime_reads,
};

/// What one language's bounded syntax pass proves about the root identifier of
/// a runtime-shaped access path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeSyntaxRoot {
    /// The path's root is the modeled runtime exposure.
    Modeled,
    /// A declaration in the source proves the root is something else. This is
    /// a conclusive exclusion, not an absent answer.
    Excluded,
    /// The binder evidence does not decide the root.
    Indeterminate,
}

/// One runtime-shaped keyed read, in the shape the activation join consumes.
///
/// Each frontend proves this with its own binder and scope facts; the join
/// below is language neutral so one reviewed contract, one gap discharge, and
/// one endpoint identity serve every language.
#[derive(Debug, Clone)]
struct RuntimeSyntaxRead {
    root_name: String,
    container: String,
    /// The static key, or the typed limitation that replaces it.
    key: Result<RuntimeAccessKey, RuntimeReadLimitation>,
    range: Range,
    container_range: Range,
    candidate_anchor: Range,
    root: RuntimeSyntaxRoot,
    /// Something that can run before this read could intercept the access.
    accessor_open: bool,
    /// This module writes the container the read observes.
    mutated: bool,
}

#[derive(Debug, Clone, Default)]
struct RuntimeSyntaxFacts {
    reads: Vec<RuntimeSyntaxRead>,
    /// The runtime root each write in this module reaches. A write refutes
    /// the pristine-input claim of every read of that root.
    writes: Vec<String>,
    visited_nodes: usize,
    complete: bool,
}

impl From<JsTsRuntimeReadFacts> for RuntimeSyntaxFacts {
    fn from(facts: JsTsRuntimeReadFacts) -> Self {
        Self {
            reads: facts
                .reads
                .iter()
                .map(|read| RuntimeSyntaxRead {
                    root_name: read.root_name.clone(),
                    container: read.container.clone(),
                    key: match &read.access {
                        JsTsRuntimeAccessKey::Property(property) => {
                            Ok(RuntimeAccessKey::Property(property.clone()))
                        }
                        JsTsRuntimeAccessKey::Index(index) => {
                            Ok(RuntimeAccessKey::Index(u128::from(*index)))
                        }
                        JsTsRuntimeAccessKey::Dynamic => Err(RuntimeReadLimitation::DynamicKey),
                        JsTsRuntimeAccessKey::Unsupported => {
                            Err(RuntimeReadLimitation::UnsupportedIndex)
                        }
                    },
                    range: read.range,
                    container_range: read.container_range,
                    candidate_anchor: read.candidate_anchor,
                    root: match read.lexical_resolution {
                        JsTsRuntimeRootResolution::UnboundGlobal => RuntimeSyntaxRoot::Modeled,
                        JsTsRuntimeRootResolution::LexicallyBound => RuntimeSyntaxRoot::Excluded,
                        JsTsRuntimeRootResolution::ProvenGlobalAlias
                        | JsTsRuntimeRootResolution::Unknown => RuntimeSyntaxRoot::Indeterminate,
                    },
                    accessor_open: read.accessor
                        != JsTsRuntimeAccessorCoverage::NoKnownAccessorEffects,
                    mutated: read.mutation != JsTsRuntimeMutationEvidence::NoKnownWrite,
                })
                .collect(),
            // `root_name` is the canonical global root the extractor proved:
            // direct `process` writes and the reflective `globalThis.process`
            // routes all arrive as `process`, and a lexically bound `process`
            // is never reported as one.
            writes: facts
                .writes
                .iter()
                .filter(|write| write.root_name == "process")
                .map(|write| write.root_name.clone())
                .collect(),
            visited_nodes: facts.visited_nodes,
            complete: facts.complete,
        }
    }
}

impl From<PythonRuntimeReadFacts> for RuntimeSyntaxFacts {
    fn from(facts: PythonRuntimeReadFacts) -> Self {
        Self {
            reads: facts
                .reads
                .iter()
                .map(|read| RuntimeSyntaxRead {
                    root_name: read.root_name.clone(),
                    container: read.container.clone(),
                    key: match &read.access {
                        PythonRuntimeAccessKey::Property(property) => {
                            Ok(RuntimeAccessKey::Property(property.clone()))
                        }
                        PythonRuntimeAccessKey::Index(index) => Ok(RuntimeAccessKey::Index(*index)),
                        PythonRuntimeAccessKey::Dynamic => Err(RuntimeReadLimitation::DynamicKey),
                        PythonRuntimeAccessKey::Unsupported => {
                            Err(RuntimeReadLimitation::UnsupportedIndex)
                        }
                    },
                    range: read.range,
                    container_range: read.container_range,
                    candidate_anchor: read.candidate_anchor,
                    root: match read.lexical_resolution {
                        PythonRuntimeRootResolution::ImportedModule => RuntimeSyntaxRoot::Modeled,
                        PythonRuntimeRootResolution::LexicallyBound => RuntimeSyntaxRoot::Excluded,
                        PythonRuntimeRootResolution::Unknown => RuntimeSyntaxRoot::Indeterminate,
                    },
                    accessor_open: read.accessor
                        != PythonRuntimeAccessorCoverage::NoKnownAccessorEffects,
                    mutated: read.mutation != PythonRuntimeMutationEvidence::NoKnownWrite,
                })
                .collect(),
            writes: facts
                .writes
                .iter()
                .map(|write| write.root_name.clone())
                .collect(),
            visited_nodes: facts.visited_nodes,
            complete: facts.complete,
        }
    }
}

/// Whether the evidence that selected a shard binds the artifact applicability
/// its exposure claims.
fn evidence_binds_runtime_artifact(
    evidence: &crate::analyzer::semantic_model::SemanticModelActivationEvidence,
    runtime: &crate::analyzer::semantic_model::RuntimeApplicability,
) -> bool {
    match (
        runtime.runtime_artifact.as_deref(),
        runtime.runtime_artifact_digest.as_deref(),
    ) {
        (Some(artifact), Some(digest)) => {
            evidence
                .package
                .as_ref()
                .is_some_and(|package| package.name == artifact)
                && evidence.artifact_sha256.as_deref() == Some(digest)
        }
        _ => evidence.package.is_none() && evidence.artifact_sha256.is_none(),
    }
}

/// The reviewed execution profiles whose keyed-read semantics this engine
/// implements.
///
/// These are explicit authored analysis assumptions, never inferred from a
/// file extension, a declaration pack, or an absent binder. The engine cannot
/// observe a platform, an architecture, or a module mode in a workspace, so it
/// must refuse a profile that scopes itself to one it does not implement
/// instead of silently publishing under it.
fn engine_implements_profile(
    runtime: &crate::analyzer::semantic_model::RuntimeApplicability,
) -> bool {
    if runtime.initialization_boundary != "pristine-runtime-at-entry"
        || runtime.realm != "main"
        || !runtime
            .host_assumptions
            .iter()
            .any(|assumption| assumption == "closed-workspace-no-preloads")
    {
        return false;
    }
    match runtime.runtime_family.as_str() {
        // Node's `process` containers are scoped by the build that publishes
        // them, so exactly one reviewed distribution profile is implemented.
        "node" => {
            runtime.module_mode.as_deref() == Some("commonjs")
                && runtime.platform.as_deref() == Some("linux")
                && runtime.architecture.as_deref() == Some("x64")
        }
        // The Python standard library specifies `os.environ` and `sys.argv`
        // for every conforming implementation and every platform, so the
        // reviewed contract declares no distribution scope. A record that
        // declares one is outside what this engine implements.
        "python" => {
            runtime.module_mode.is_none()
                && runtime.platform.is_none()
                && runtime.architecture.is_none()
        }
        _ => false,
    }
}

/// Languages whose frontend proves runtime keyed-read syntax evidence.
const RUNTIME_KEYED_READ_LANGUAGES: [Language; 3] =
    [Language::JavaScript, Language::TypeScript, Language::Python];

/// Run the frontend pass that owns this language's binder and scope facts.
fn runtime_syntax_facts(
    language: Language,
    root: tree_sitter::Node<'_>,
    source: &str,
    max_facts: usize,
) -> RuntimeSyntaxFacts {
    match language {
        Language::JavaScript | Language::TypeScript => {
            extract_js_ts_runtime_reads(root, source, max_facts).into()
        }
        Language::Python => extract_python_runtime_reads(root, source, max_facts).into(),
        _ => RuntimeSyntaxFacts {
            complete: false,
            ..RuntimeSyntaxFacts::default()
        },
    }
}

pub(super) type RuntimeReadCache = CompleteValueCache<ProcedureHandle, RuntimeKeyedReadResult>;

/// The runtime initialization and mutation footprint of every other
/// JavaScript or TypeScript module in the workspace.
///
/// The reviewed runtime model states that a keyed read observes pristine input
/// until a write. This is the workspace-derived half of that claim: the
/// modules that the analyzer can read and parse, and the runtime-root writes
/// they spell. It is deliberately not an authoring claim, because a pack
/// cannot describe the mutations of a particular workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkspaceRuntimeWriteFootprint {
    /// Every other module reads, parses, and spells no runtime-root write.
    Closed,
    /// Another module spells a write to `process`, `globalThis`, or `global`
    /// that reaches the runtime container.
    RuntimeRootWrite,
    /// Another module's source or syntax could not be inspected completely.
    CoverageLimited,
}

pub(super) type WorkspaceRuntimeWriteFootprintCache =
    CompleteValueCache<ProjectFile, WorkspaceRuntimeWriteFootprint>;

pub(super) fn workspace_runtime_write_footprint_cache() -> WorkspaceRuntimeWriteFootprintCache {
    CompleteValueCache::new(1024 * 1024, |_, _| 256)
}

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
    /// Inspect every other JavaScript or TypeScript module once per captured
    /// oracle for the runtime-root writes the pristine-input model names.
    ///
    /// The scan is bounded by the request budget: a module the budget cannot
    /// cover keeps the answer incomplete rather than clean. Results are cached
    /// per current module, because one keyed-read request evaluates every
    /// procedure of that module.
    fn workspace_runtime_write_footprint(
        &self,
        current: &ProjectFile,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(WorkspaceRuntimeWriteFootprint, SemanticWork), SemanticProviderError> {
        let (acquisition, _) = self
            .runtime_write_footprints
            .acquire(current, request.cancellation);
        let permit = match acquisition {
            CompleteValueAcquisition::Cached { value } => {
                let work = SemanticWork {
                    nested_entries: 1,
                    ..SemanticWork::default()
                };
                if request.budget.charge(work).is_err() {
                    return Ok((WorkspaceRuntimeWriteFootprint::CoverageLimited, work));
                }
                return Ok((*value, work));
            }
            CompleteValueAcquisition::Leader { permit } => permit,
            CompleteValueAcquisition::Cancelled | CompleteValueAcquisition::Rejected => {
                return Ok((
                    WorkspaceRuntimeWriteFootprint::CoverageLimited,
                    SemanticWork::default(),
                ));
            }
        };
        let (footprint, work) = self.scan_workspace_runtime_writes(current, request)?;
        if footprint != WorkspaceRuntimeWriteFootprint::CoverageLimited {
            permit.publish_complete(Arc::new(footprint));
        }
        Ok((footprint, work))
    }

    fn scan_workspace_runtime_writes(
        &self,
        current: &ProjectFile,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(WorkspaceRuntimeWriteFootprint, SemanticWork), SemanticProviderError> {
        let mut footprint = WorkspaceRuntimeWriteFootprint::Closed;
        let mut work = SemanticWork::default();
        let project = self.workspace.analyzer().project();
        let files = project
            .all_files_shared()
            .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
        let mut parser = tree_sitter::Parser::new();
        for file in files.iter() {
            // Only a module of the same language can spell a write to this
            // runtime root: the exposure's binder is that language's own.
            if file == current || file.language() != current.language() {
                continue;
            }
            if request.cancellation.is_cancelled() {
                return Ok((WorkspaceRuntimeWriteFootprint::CoverageLimited, work));
            }
            let max_bytes = request.budget.remaining().source_bytes;
            let snapshot = project
                .read_source_snapshot_limited(file, max_bytes)
                .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
            let Some(snapshot) = snapshot else {
                return Ok((WorkspaceRuntimeWriteFootprint::CoverageLimited, work));
            };
            let source = snapshot.source().to_owned();
            let file_work = SemanticWork {
                source_bytes: source.len(),
                ..SemanticWork::default()
            };
            work = work.conservative_add(file_work);
            if request.budget.charge(file_work).is_err() {
                return Ok((WorkspaceRuntimeWriteFootprint::CoverageLimited, work));
            }
            let dialect = LanguageDialect::for_path(file.language(), file.rel_path());
            let Some(grammar) = parser_language_for_dialect(dialect) else {
                return Ok((WorkspaceRuntimeWriteFootprint::CoverageLimited, work));
            };
            parser
                .set_language(&grammar)
                .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
            let mut input = |offset: usize, _| &source.as_bytes()[offset..];
            let Some(tree) = parser.parse_with_options(&mut input, None, None) else {
                return Ok((WorkspaceRuntimeWriteFootprint::CoverageLimited, work));
            };
            if tree.root_node().has_error() {
                return Ok((WorkspaceRuntimeWriteFootprint::CoverageLimited, work));
            }
            let facts = runtime_syntax_facts(
                file.language(),
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
            if request.budget.charge(fact_work).is_err() || !facts.complete {
                return Ok((WorkspaceRuntimeWriteFootprint::CoverageLimited, work));
            }
            if !facts.writes.is_empty() {
                footprint = WorkspaceRuntimeWriteFootprint::RuntimeRootWrite;
            }
        }
        Ok((footprint, work))
    }

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
        if !RUNTIME_KEYED_READ_LANGUAGES.contains(&procedure.artifact().key().language().language())
        {
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
        // The runtime initialization footprint spans the whole workspace, not
        // only the module that spells the read. Every other JavaScript or
        // TypeScript module is inspected for the runtime-root writes that the
        // reviewed `pristine-input-until-write` model names; an unreadable or
        // unparseable sibling keeps the answer incomplete instead of clean.
        let (footprint, footprint_work) = self.workspace_runtime_write_footprint(&file, request)?;
        work = work.conservative_add(footprint_work);
        // A footprint that is not closed still reports the read's own typed
        // limitation. The extraction below keeps every candidate so a query
        // anchored on this read sees the boundary instead of an empty answer.
        let footprint_limitation = match footprint {
            WorkspaceRuntimeWriteFootprint::Closed => None,
            WorkspaceRuntimeWriteFootprint::RuntimeRootWrite => {
                Some(RuntimeReadLimitation::MutationIncomplete)
            }
            WorkspaceRuntimeWriteFootprint::CoverageLimited => {
                Some(RuntimeReadLimitation::CoverageLimited)
            }
        };
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
        let facts = runtime_syntax_facts(
            procedure.artifact().key().language().language(),
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
            if let Err(limitation) = read.key {
                result.limitations.push(limitation);
            }
            result.candidates.push(RuntimeKeyedReadCandidate {
                anchor: read.candidate_anchor,
                global: read.root_name.clone(),
                container: read.container.clone(),
                key: read.key.clone().ok(),
                excluded: read.root == RuntimeSyntaxRoot::Excluded,
            });
            let Ok(key) = read.key.clone() else {
                continue;
            };
            if read.root == RuntimeSyntaxRoot::Excluded {
                continue;
            }
            // Accessor and effect hazards are scoped to the read's own
            // execution context; direct writes stay module-wide in the
            // extractor's mutation evidence. An external call in a sibling
            // function must not poison this read, or a reviewed sink call
            // could never share a module with its source.
            if read.accessor_open {
                result
                    .limitations
                    .push(RuntimeReadLimitation::AccessorOrProxyIncomplete);
                continue;
            }
            if read.root != RuntimeSyntaxRoot::Modeled {
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
            if read.mutated {
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
        if let Some(limitation) = footprint_limitation {
            result.limitations.push(limitation);
        }
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
impl WorkspaceSemanticOracle<'_> {
    fn bind_runtime_read_contract(
        &self,
        procedure: &ProcedureHandle,
        file: &ProjectFile,
        read: &RuntimeSyntaxRead,
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
        if active.runtime_contracts().next().is_some() {
            // Portable bindings carry producer-owned locator schemes and effect
            // evidence. Until those join this artifact through a supported
            // producer adapter, catalog presence cannot authorize a native load
            // or silently fall back to a potentially conflicting older profile.
            result
                .limitations
                .push(RuntimeReadLimitation::ActivationUnsupported);
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
                // A host must explicitly select the complete execution
                // profile. Catalog availability and the source language do not
                // establish it. An exposure authored as `enabled` is
                // intrinsically eligible within its model; it does not bypass
                // pack activation. The pack-level `safety.review_required`
                // gate remains the explicit user authorization, enforced by
                // the activation resolver before this join ever runs.
                //
                // The evidence must bind exactly the applicability the
                // exposure claims. A build-specific contract is selected only
                // by its own artifact coordinates and digest; a contract the
                // language's standard library guarantees claims no artifact,
                // and evidence naming one would bind something it never said.
                if shard.matched_evidence.configuration.as_deref()
                    != Some(&exposure.runtime_profile_digest)
                    || !evidence_binds_runtime_artifact(&shard.matched_evidence, &exposure.runtime)
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
        // A reviewed behavior that may raise still observes exactly the
        // reviewed input on the normal path: a read that abandons control
        // produces no result at all. What it cannot do is discharge the
        // load's exceptional-control-flow claim, which stays open below.
        if behavior.exception_behavior == RuntimeExceptionBehavior::Unknown {
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
        if !engine_implements_profile(&exposure.runtime) {
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
        // The load's own result mapping carries the structural identity of the
        // AST-derived seed the query addresses. A dot-member read is its own
        // field access; a subscript read is represented by the base of its
        // access chain, and the lowerer publishes that seed identity on the
        // subscript load. A mapping without one stays a typed materialization
        // boundary instead of being re-derived from the container occurrence.
        let identity_row = procedure
            .semantics()
            .value(load.0.value().id())
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
        let nonthrowing = behavior.exception_behavior == RuntimeExceptionBehavior::Nonthrowing;
        let discharged_gaps = procedure
            .semantics()
            .gaps()
            .iter()
            .filter(|gap| {
                gap_belongs_to_load(gap, &load.0, load.1, nonthrowing)
                    || gap_belongs_to_load(gap, container, *container_location, nonthrowing)
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
            candidate_anchor: read.candidate_anchor,
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
            ..RuntimeKeyedReadFilter::default()
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
