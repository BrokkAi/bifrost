//! Activation-bound evidence for source-owned runtime keyed loads.
//!
//! Runtime model records identify an exposure and read behavior; syntax identifies
//! an occurrence. Neither is an executable value until it joins a MemoryLoad in
//! the exact immutable semantic artifact. This module owns that join.

use std::sync::Arc;

use crate::analyzer::semantic::EvidenceCompleteness;

use crate::analyzer::semantic::MemoryLocationId;

use crate::analyzer::semantic::ProofStatus;

use crate::analyzer::semantic::SemanticGapId;

use crate::analyzer::semantic::StableDigest;

use crate::analyzer::semantic::ValueAtPoint;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::Range;

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
    #[doc(hidden)]
    pub fn accepts_key(&self, key: &RuntimeAccessKey) -> bool {
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
    #[doc(hidden)]
    pub location: MemoryLocationId,
    #[doc(hidden)]
    pub container_observation: ValueAtPoint,
    #[doc(hidden)]
    pub container_location: MemoryLocationId,
    #[doc(hidden)]
    pub runtime_object: crate::analyzer::semantic::RuntimeObjectRoot,
    #[doc(hidden)]
    pub discharged_gaps: Arc<[SemanticGapId]>,
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
    #[doc(hidden)]
    pub candidates: Vec<RuntimeKeyedReadCandidate>,
}

#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct RuntimeKeyedReadCandidate {
    #[doc(hidden)]
    pub anchor: Range,
    #[doc(hidden)]
    pub global: String,
    #[doc(hidden)]
    pub container: String,
    #[doc(hidden)]
    pub key: Option<RuntimeAccessKey>,
    #[doc(hidden)]
    pub excluded: bool,
}

use crate::analyzer::semantic::ObservationPhase;

use crate::analyzer::semantic::OracleCallContext;

use crate::analyzer::semantic::ProcedureHandle;

use crate::analyzer::semantic::SemanticCapability;

use crate::analyzer::semantic::SemanticEffect;

use crate::analyzer::semantic::SemanticGap;

use crate::analyzer::semantic::SemanticGapSubject;

use brokk_bifrost_core::analyzer::model::Language;

/// Only an effect's own source mapping and result mapping can select a load.
/// Container and terminal loads are returned separately to retain gap ownership.
#[doc(hidden)]
pub fn loads_at_range(
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
#[doc(hidden)]
pub fn gap_belongs_to_load(
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

use brokk_bifrost_core::complete_value_cache::CompleteValueCache;
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
#[doc(hidden)]
pub enum RuntimeSyntaxRoot {
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
#[doc(hidden)]
pub struct RuntimeSyntaxRead {
    #[doc(hidden)]
    pub root_name: String,
    #[doc(hidden)]
    pub container: String,
    /// The static key, or the typed limitation that replaces it.
    #[doc(hidden)]
    pub key: Result<RuntimeAccessKey, RuntimeReadLimitation>,
    #[doc(hidden)]
    pub range: Range,
    #[doc(hidden)]
    pub container_range: Range,
    #[doc(hidden)]
    pub candidate_anchor: Range,
    #[doc(hidden)]
    pub root: RuntimeSyntaxRoot,
    /// Something that can run before this read could intercept the access.
    #[doc(hidden)]
    pub accessor_open: bool,
    /// This module writes the container the read observes.
    #[doc(hidden)]
    pub mutated: bool,
}

#[derive(Debug, Clone, Default)]
#[doc(hidden)]
pub struct RuntimeSyntaxFacts {
    #[doc(hidden)]
    pub reads: Vec<RuntimeSyntaxRead>,
    /// The runtime root each write in this module reaches. A write refutes
    /// the pristine-input claim of every read of that root.
    #[doc(hidden)]
    pub writes: Vec<String>,
    #[doc(hidden)]
    pub visited_nodes: usize,
    #[doc(hidden)]
    pub complete: bool,
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
#[doc(hidden)]
pub fn evidence_binds_runtime_artifact(
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
#[doc(hidden)]
pub fn engine_implements_profile(
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
#[doc(hidden)]
pub const RUNTIME_KEYED_READ_LANGUAGES: [Language; 3] =
    [Language::JavaScript, Language::TypeScript, Language::Python];

/// Run the frontend pass that owns this language's binder and scope facts.
#[doc(hidden)]
pub fn runtime_syntax_facts(
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

#[doc(hidden)]
pub type RuntimeReadCache = CompleteValueCache<ProcedureHandle, RuntimeKeyedReadResult>;

/// Pure frontend facts, before model activation or procedure-local projection.
/// A complete census can still describe invalid syntax; consumers must retain
/// that coverage boundary instead of treating the snapshot as semantic proof.
#[derive(Debug)]
#[doc(hidden)]
pub struct RuntimeSyntaxSnapshot {
    #[doc(hidden)]
    pub facts: RuntimeSyntaxFacts,
    #[doc(hidden)]
    pub has_error: bool,
    #[doc(hidden)]
    pub work: crate::analyzer::semantic::SemanticBudgetReplay,
    #[doc(hidden)]
    pub owner: Arc<()>,
}

#[doc(hidden)]
pub type RuntimeSyntaxCache = CompleteValueCache<StableDigest, RuntimeSyntaxSnapshot>;

#[doc(hidden)]
pub fn runtime_syntax_cache() -> RuntimeSyntaxCache {
    CompleteValueCache::new(8 * 1024 * 1024, |_, value: &Arc<RuntimeSyntaxSnapshot>| {
        let facts = &value.facts;
        let weight = std::mem::size_of::<RuntimeSyntaxSnapshot>()
            + facts.reads.capacity() * std::mem::size_of::<RuntimeSyntaxRead>()
            + facts.writes.capacity() * std::mem::size_of::<String>();
        facts
            .reads
            .iter()
            .fold(
                facts.writes.iter().fold(weight, |total, write| {
                    total.saturating_add(write.capacity())
                }),
                |total, read| {
                    total.saturating_add(
                        read.root_name.capacity()
                            + read.container.capacity()
                            + match &read.key {
                                Ok(RuntimeAccessKey::Property(key)) => key.capacity(),
                                _ => 0,
                            },
                    )
                },
            )
            .min(u32::MAX as usize) as u32
    })
}

/// The runtime initialization and mutation footprint of every other
/// JavaScript or TypeScript module in the workspace.
///
/// The reviewed runtime model states that a keyed read observes pristine input
/// until a write. This is the workspace-derived half of that claim: the
/// modules that the analyzer can read and parse, and the runtime-root writes
/// they spell. It is deliberately not an authoring claim, because a pack
/// cannot describe the mutations of a particular workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum WorkspaceRuntimeWriteFootprint {
    /// Every other module reads, parses, and spells no runtime-root write.
    Closed,
    /// Another module spells a write to `process`, `globalThis`, or `global`
    /// that reaches the runtime container.
    RuntimeRootWrite,
    /// Another module's source or syntax could not be inspected completely.
    CoverageLimited,
}

#[doc(hidden)]
pub type WorkspaceRuntimeWriteFootprintCache =
    CompleteValueCache<ProjectFile, WorkspaceRuntimeWriteFootprint>;

#[doc(hidden)]
pub fn workspace_runtime_write_footprint_cache() -> WorkspaceRuntimeWriteFootprintCache {
    CompleteValueCache::new(1024 * 1024, |_, _| 256)
}

#[doc(hidden)]
pub fn runtime_read_cache() -> RuntimeReadCache {
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

impl RuntimeKeyedReadResult {
    #[doc(hidden)]
    pub fn discharges(&self, gap: SemanticGapId) -> bool {
        self.endpoints
            .iter()
            .any(|endpoint| endpoint.discharged_gaps.contains(&gap))
    }
}
