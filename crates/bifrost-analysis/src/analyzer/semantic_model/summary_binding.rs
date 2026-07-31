//! Pure binding from selected compiled procedure summaries to reusable data-flow summaries.
//!
//! Selection and exact target resolution happen before this module. The binder consumes those
//! explicit results, verifies that they still agree, and never searches source or manufactures a
//! declaration from the compiled target's display strings.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fmt;

use crate::analyzer::canonical_hash::{CanonicalHasher, parse_lower_sha256};
use crate::analyzer::dataflow::{
    ExternalSemanticSummarySet, ExternalSummaryCompatibilityKey, ExternalSummaryContentHash,
    ExternalSummaryModelId, ExternalSummaryOrigin, ExternalSummarySetError,
    ProcedureSummaryIdentity, ProcedureSummaryKey, SemanticProcedureSummary, SummaryCompleteness,
    SummaryDependencyKey, SummaryEffect, SummaryEffectKey, SummaryEventKey, SummaryEvidence,
    SummaryExit, SummaryExitKind, SummaryIncompleteReason, SummaryLocationKey, SummaryOrigin,
    SummaryPort, SummaryRecursiveEdge, SummaryRecursiveGroupKey, SummaryTransfer,
    SummaryValidationError,
};
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmRequest, DenseBidirectionalGraph, strongly_connected_components,
};
use crate::analyzer::semantic::{SemanticArtifactKey, SemanticLocator, SemanticRole, StableDigest};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, map_with_capacity};

use super::{
    CompiledProcedureSummary, CompiledProcedureTarget, CompiledSummaryEffect,
    CompiledSummaryExitKind, CompiledSummaryInput, CompiledSummaryLocationKind,
    CompiledSummaryOutput, Completeness,
};

const LOCATION_KEY_DOMAIN: &[u8] = b"bifrost.semantic-model.procedure-summary.location.v1";
const EVENT_KEY_DOMAIN: &[u8] = b"bifrost.semantic-model.procedure-summary.event.v1";
const MODEL_UNPROVEN_REASON: &str = "external semantic model row is not source-backed proof";
const MODEL_INCOMPLETE_REASON: &str = "external semantic model summary is partial";

/// Explicit receiver metadata for one exact bound procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ExactProcedureSummaryReceiver;

/// Explicit zero-based formal parameter metadata for one exact bound procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExactProcedureSummaryParameter {
    ordinal: u32,
}

impl ExactProcedureSummaryParameter {
    pub const fn new(ordinal: u32) -> Self {
        Self { ordinal }
    }

    pub const fn ordinal(self) -> u32 {
        self.ordinal
    }
}

/// Exact receiver and formal-parameter shape observed by the target resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactProcedureSummaryBoundary {
    receiver: Option<ExactProcedureSummaryReceiver>,
    parameters: Box<[ExactProcedureSummaryParameter]>,
}

impl ExactProcedureSummaryBoundary {
    pub fn new(
        receiver: Option<ExactProcedureSummaryReceiver>,
        parameters: Vec<ExactProcedureSummaryParameter>,
    ) -> Self {
        Self {
            receiver,
            parameters: parameters.into_boxed_slice(),
        }
    }

    pub const fn receiver(&self) -> Option<ExactProcedureSummaryReceiver> {
        self.receiver
    }

    pub fn parameters(&self) -> &[ExactProcedureSummaryParameter] {
        &self.parameters
    }
}

/// Resolver-owned proof that one compiled target names one exact mounted procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactProcedureSummaryTargetBinding {
    summary_id: Box<str>,
    target: CompiledProcedureTarget,
    artifact: SemanticArtifactKey,
    procedure: SemanticLocator,
    boundary: ExactProcedureSummaryBoundary,
}

impl ExactProcedureSummaryTargetBinding {
    pub fn new(
        summary_id: impl Into<String>,
        target: CompiledProcedureTarget,
        artifact: SemanticArtifactKey,
        procedure: SemanticLocator,
        boundary: ExactProcedureSummaryBoundary,
    ) -> Self {
        Self {
            summary_id: summary_id.into().into_boxed_str(),
            target,
            artifact,
            procedure,
            boundary,
        }
    }

    pub fn summary_id(&self) -> &str {
        &self.summary_id
    }

    pub const fn target(&self) -> &CompiledProcedureTarget {
        &self.target
    }

    pub const fn artifact(&self) -> &SemanticArtifactKey {
        &self.artifact
    }

    pub const fn procedure(&self) -> &SemanticLocator {
        &self.procedure
    }

    pub const fn boundary(&self) -> &ExactProcedureSummaryBoundary {
        &self.boundary
    }
}

/// Fail-closed errors from compiled procedure-summary binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcedureSummaryBindingError {
    MissingBinding {
        summary_id: String,
    },
    UnknownBinding {
        summary_id: String,
    },
    AmbiguousTarget {
        summary_id: String,
    },
    TargetMismatch {
        summary_id: String,
    },
    IncompatibleCompatibilityKey {
        summary_id: String,
    },
    UnboundCallee {
        summary_id: String,
        callee_id: String,
    },
    InvalidRecursion,
    UnsupportedLocationBinding {
        summary_id: String,
        location_id: String,
    },
    InvalidContentHash {
        summary_id: String,
    },
    InvalidSummary {
        summary_id: String,
        source: SummaryValidationError,
    },
}

impl fmt::Display for ProcedureSummaryBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBinding { summary_id } => {
                write!(
                    formatter,
                    "compiled summary `{summary_id}` has no exact target binding"
                )
            }
            Self::UnknownBinding { summary_id } => {
                write!(
                    formatter,
                    "exact target binding `{summary_id}` has no compiled summary"
                )
            }
            Self::AmbiguousTarget { summary_id } => write!(
                formatter,
                "compiled summary `{summary_id}` does not have one unique exact target"
            ),
            Self::TargetMismatch { summary_id } => write!(
                formatter,
                "compiled summary `{summary_id}` disagrees with its exact structured target"
            ),
            Self::IncompatibleCompatibilityKey { summary_id } => write!(
                formatter,
                "compiled summary `{summary_id}` is incompatible with the consumer summary family"
            ),
            Self::UnboundCallee {
                summary_id,
                callee_id,
            } => write!(
                formatter,
                "compiled summary `{summary_id}` references unbound callee `{callee_id}`"
            ),
            Self::InvalidRecursion => {
                formatter.write_str("compiled summary dependency recursion is invalid")
            }
            Self::UnsupportedLocationBinding {
                summary_id,
                location_id,
            } => write!(
                formatter,
                "compiled summary `{summary_id}` has unsupported location binding `{location_id}`"
            ),
            Self::InvalidContentHash { summary_id } => write!(
                formatter,
                "compiled summary `{summary_id}` has an invalid content SHA-256"
            ),
            Self::InvalidSummary { summary_id, source } => {
                write!(
                    formatter,
                    "compiled summary `{summary_id}` lowered to invalid IR: {source}"
                )
            }
        }
    }
}

impl std::error::Error for ProcedureSummaryBindingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidSummary { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Bind one already-selected compiled summary family to exact mounted procedures.
pub fn bind_compiled_procedure_summaries(
    summaries: &[CompiledProcedureSummary],
    bindings: Vec<ExactProcedureSummaryTargetBinding>,
    compatibility: ExternalSummaryCompatibilityKey,
) -> Result<ExternalSemanticSummarySet, ProcedureSummaryBindingError> {
    let mut records = summaries.iter().collect::<Vec<_>>();
    records.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    if let Some(pair) = records.windows(2).find(|pair| pair[0].id == pair[1].id) {
        return Err(ProcedureSummaryBindingError::AmbiguousTarget {
            summary_id: pair[0].id.clone(),
        });
    }

    let mut bindings = bindings;
    bindings.sort_unstable_by(|left, right| left.summary_id.cmp(&right.summary_id));
    if let Some(pair) = bindings
        .windows(2)
        .find(|pair| pair[0].summary_id == pair[1].summary_id)
    {
        return Err(ProcedureSummaryBindingError::AmbiguousTarget {
            summary_id: pair[0].summary_id().to_owned(),
        });
    }

    let index_by_id = records
        .iter()
        .enumerate()
        .map(|(index, summary)| (summary.id.as_str(), index))
        .collect::<HashMap<_, _>>();
    for binding in &bindings {
        if !index_by_id.contains_key(binding.summary_id()) {
            return Err(ProcedureSummaryBindingError::UnknownBinding {
                summary_id: binding.summary_id().to_owned(),
            });
        }
    }
    let binding_by_id = bindings
        .iter()
        .map(|binding| (binding.summary_id(), binding))
        .collect::<HashMap<_, _>>();

    let mut exact_targets = bindings.iter().collect::<Vec<_>>();
    exact_targets.sort_unstable_by(|left, right| {
        left.artifact
            .mount()
            .cmp(&right.artifact.mount())
            .then_with(|| left.artifact.path().cmp(right.artifact.path()))
            .then_with(|| left.artifact.language().cmp(&right.artifact.language()))
            .then_with(|| {
                left.procedure
                    .declaration()
                    .cmp(right.procedure.declaration())
            })
    });
    if let Some(pair) = exact_targets.windows(2).find(|pair| {
        pair[0].artifact.mount() == pair[1].artifact.mount()
            && pair[0].artifact.path() == pair[1].artifact.path()
            && pair[0].artifact.language() == pair[1].artifact.language()
            && pair[0].procedure.declaration() == pair[1].procedure.declaration()
    }) {
        return Err(ProcedureSummaryBindingError::AmbiguousTarget {
            summary_id: pair[1].summary_id().to_owned(),
        });
    }

    let mut identities = Vec::with_capacity(records.len());
    let mut origins = Vec::with_capacity(records.len());
    for summary in &records {
        let binding = binding_by_id
            .get(summary.id.as_str())
            .copied()
            .ok_or_else(|| ProcedureSummaryBindingError::MissingBinding {
                summary_id: summary.id.clone(),
            })?;
        verify_target(summary, binding, compatibility)?;
        let origin = external_origin(summary)?;
        identities.push(ProcedureSummaryIdentity::new(
            binding.artifact.clone(),
            binding.procedure.declaration().clone(),
            compatibility.schema(),
            compatibility.semantics(),
            compatibility.context(),
            compatibility.behavior(),
            SummaryOrigin::External(origin.clone()),
        ));
        origins.push(origin);
    }

    let graph = resolve_dependency_graph(&records, &index_by_id)?;
    let cancellation = CancellationToken::new();
    let mut budget = CfgAlgorithmBudget::default();
    let mut request = CfgAlgorithmRequest::new(&mut budget, &cancellation);
    let sccs = strongly_connected_components(&graph, &mut request)
        .map_err(|_| ProcedureSummaryBindingError::InvalidRecursion)?;

    build_summary_set(
        &records,
        &bindings,
        &identities,
        &origins,
        &graph,
        &sccs.components,
        compatibility,
    )
}

fn verify_target(
    summary: &CompiledProcedureSummary,
    binding: &ExactProcedureSummaryTargetBinding,
    compatibility: ExternalSummaryCompatibilityKey,
) -> Result<(), ProcedureSummaryBindingError> {
    let target = &summary.target;
    let exact_artifact_locator = binding.procedure.role() == SemanticRole::Procedure
        && binding.artifact.mount() == binding.procedure.mount()
        && binding.artifact.path() == binding.procedure.path()
        && binding.artifact.language() == binding.procedure.language();
    if binding.target != *target
        || target.path != binding.artifact.path().as_str()
        || !exact_artifact_locator
    {
        return Err(ProcedureSummaryBindingError::TargetMismatch {
            summary_id: summary.id.clone(),
        });
    }

    let mut ordinals = binding
        .boundary
        .parameters()
        .iter()
        .map(|parameter| parameter.ordinal())
        .collect::<Vec<_>>();
    ordinals.sort_unstable();
    let expected_count = usize::try_from(target.parameter_count).map_err(|_| {
        ProcedureSummaryBindingError::TargetMismatch {
            summary_id: summary.id.clone(),
        }
    })?;
    let exact_parameters = ordinals.len() == expected_count
        && ordinals
            .iter()
            .enumerate()
            .all(|(ordinal, actual)| u32::try_from(ordinal) == Ok(*actual));
    if binding.boundary.receiver().is_some() != target.has_receiver || !exact_parameters {
        return Err(ProcedureSummaryBindingError::TargetMismatch {
            summary_id: summary.id.clone(),
        });
    }
    if summary.contract_version != compatibility.schema().get()
        || binding.artifact.dependencies() != compatibility.dependencies()
    {
        return Err(ProcedureSummaryBindingError::IncompatibleCompatibilityKey {
            summary_id: summary.id.clone(),
        });
    }
    Ok(())
}

fn external_origin(
    summary: &CompiledProcedureSummary,
) -> Result<ExternalSummaryOrigin, ProcedureSummaryBindingError> {
    let content = parse_content_hash(&summary.content_sha256).ok_or_else(|| {
        ProcedureSummaryBindingError::InvalidContentHash {
            summary_id: summary.id.clone(),
        }
    })?;
    let model = ExternalSummaryModelId::new(summary.model_id.clone()).map_err(|source| {
        ProcedureSummaryBindingError::InvalidSummary {
            summary_id: summary.id.clone(),
            source,
        }
    })?;
    ExternalSummaryOrigin::new(model, content, summary.contract_version).map_err(|source| {
        ProcedureSummaryBindingError::InvalidSummary {
            summary_id: summary.id.clone(),
            source,
        }
    })
}

fn parse_content_hash(value: &str) -> Option<ExternalSummaryContentHash> {
    let bytes = parse_lower_sha256(value)?;
    Some(ExternalSummaryContentHash::from_digest(
        StableDigest::from_array(bytes),
    ))
}

fn resolve_dependency_graph(
    records: &[&CompiledProcedureSummary],
    index_by_id: &HashMap<&str, usize>,
) -> Result<ProcedureDependencyGraph, ProcedureSummaryBindingError> {
    let mut dependencies = vec![Vec::new(); records.len()];
    for (caller, summary) in records.iter().enumerate() {
        for effect in &summary.effects {
            match effect {
                CompiledSummaryEffect::Call { callee, .. } => {
                    dependencies[caller].push(resolve_callee_index(summary, callee, index_by_id)?)
                }
                CompiledSummaryEffect::AmbiguousCall { candidates, .. } => {
                    for callee in candidates {
                        dependencies[caller].push(resolve_callee_index(
                            summary,
                            callee,
                            index_by_id,
                        )?);
                    }
                }
                CompiledSummaryEffect::Allocation { .. }
                | CompiledSummaryEffect::Escape { .. }
                | CompiledSummaryEffect::UnknownCall { .. }
                | CompiledSummaryEffect::UnknownCallBoundary { .. } => {}
            }
        }
        dependencies[caller].sort_unstable();
        dependencies[caller].dedup();
    }
    Ok(ProcedureDependencyGraph::new(dependencies))
}

fn resolve_callee_index(
    summary: &CompiledProcedureSummary,
    callee_id: &str,
    index_by_id: &HashMap<&str, usize>,
) -> Result<usize, ProcedureSummaryBindingError> {
    index_by_id
        .get(callee_id)
        .copied()
        .ok_or_else(|| ProcedureSummaryBindingError::UnboundCallee {
            summary_id: summary.id.clone(),
            callee_id: callee_id.to_owned(),
        })
}

#[allow(clippy::too_many_arguments)]
fn build_summary_set(
    records: &[&CompiledProcedureSummary],
    bindings: &[ExactProcedureSummaryTargetBinding],
    identities: &[ProcedureSummaryIdentity],
    origins: &[ExternalSummaryOrigin],
    graph: &ProcedureDependencyGraph,
    components: &[Box<[usize]>],
    compatibility: ExternalSummaryCompatibilityKey,
) -> Result<ExternalSemanticSummarySet, ProcedureSummaryBindingError> {
    let binding_by_id = bindings
        .iter()
        .map(|binding| (binding.summary_id(), binding))
        .collect::<HashMap<_, _>>();
    let mut component_by_node = vec![0usize; records.len()];
    for (component, members) in components.iter().enumerate() {
        for &member in members.iter() {
            component_by_node[member] = component;
        }
    }

    let mut dependencies_by_component = vec![Vec::<usize>::new(); components.len()];
    for (component, members) in components.iter().enumerate() {
        for &member in members.iter() {
            dependencies_by_component[component].extend(
                graph.outgoing[member]
                    .iter()
                    .map(|edge| component_by_node[graph.edges[*edge].1])
                    .filter(|&target| target != component),
            );
        }
        dependencies_by_component[component].sort_unstable();
        dependencies_by_component[component].dedup();
    }
    let mut dependents_by_component = vec![Vec::<usize>::new(); components.len()];
    for (dependent, dependencies) in dependencies_by_component.iter().enumerate() {
        for &dependency in dependencies {
            dependents_by_component[dependency].push(dependent);
        }
    }
    for dependents in &mut dependents_by_component {
        dependents.sort_unstable();
        dependents.dedup();
    }
    let mut remaining_dependencies = dependencies_by_component
        .iter()
        .map(Vec::len)
        .collect::<Vec<_>>();
    let mut ready = remaining_dependencies
        .iter()
        .enumerate()
        .filter_map(|(component, &remaining)| (remaining == 0).then_some(Reverse(component)))
        .collect::<BinaryHeap<_>>();

    let mut key_by_node = vec![None::<ProcedureSummaryKey>; records.len()];
    let mut summaries = Vec::with_capacity(records.len());
    let mut emitted_components = 0usize;
    while let Some(Reverse(component)) = ready.pop() {
        emitted_components += 1;
        let mut members = components[component].to_vec();
        members.sort_unstable();
        let recursive = members.len() > 1
            || graph.outgoing[members[0]]
                .iter()
                .any(|edge| graph.edges[*edge].1 == members[0]);
        let mut recursive_edges = Vec::new();
        for &caller in &members {
            for &edge in &graph.outgoing[caller] {
                let callee = graph.edges[edge].1;
                if component_by_node[callee] == component {
                    recursive_edges.push(SummaryRecursiveEdge::new(
                        identities[caller].clone(),
                        identities[callee].clone(),
                    ));
                }
            }
        }
        let mut external_keys = members
            .iter()
            .flat_map(|&member| {
                graph.outgoing[member].iter().filter_map(|&edge| {
                    let callee = graph.edges[edge].1;
                    (component_by_node[callee] != component).then(|| {
                        key_by_node[callee]
                            .clone()
                            .expect("dependency component emitted first")
                    })
                })
            })
            .collect::<Vec<_>>();
        external_keys.sort_unstable();
        external_keys.dedup();
        let recursive_group = recursive
            .then(|| {
                let member_identities = members
                    .iter()
                    .map(|&member| identities[member].clone())
                    .collect::<Vec<_>>();
                SummaryRecursiveGroupKey::from_closure(
                    &member_identities,
                    &recursive_edges,
                    &external_keys,
                )
            })
            .transpose()
            .map_err(|_| ProcedureSummaryBindingError::InvalidRecursion)?;

        for &member in &members {
            let dependencies = dependency_keys(
                member,
                component,
                graph,
                &component_by_node,
                identities,
                &key_by_node,
            );
            let key = ProcedureSummaryKey::try_new(
                identities[member].clone(),
                &dependencies,
                recursive_group,
            )
            .map_err(|source| invalid_summary(records[member], source))?;
            key_by_node[member] = Some(key);
        }

        for &member in &members {
            let summary = records[member];
            let binding = binding_by_id[summary.id.as_str()];
            let dependencies = dependency_keys(
                member,
                component,
                graph,
                &component_by_node,
                identities,
                &key_by_node,
            );
            let locations = bind_locations(summary)?;
            let evidence = model_evidence(summary)?;
            let transfers = summary
                .transfers
                .iter()
                .map(|transfer| lower_transfer(summary, binding, &locations, transfer, &evidence))
                .collect::<Result<Vec<_>, _>>()?;
            let effects = summary
                .effects
                .iter()
                .map(|effect| {
                    lower_effect(
                        summary,
                        binding,
                        &locations,
                        effect,
                        &evidence,
                        &dependencies,
                        &key_by_node,
                        records,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            let completeness = match summary.completeness {
                Completeness::Complete => SummaryCompleteness::Complete,
                Completeness::Partial => SummaryCompleteness::partial(vec![
                    SummaryIncompleteReason::ExternalModelIncomplete(origins[member].content()),
                ])
                .map_err(|source| invalid_summary(summary, source))?,
            };
            let lowered = SemanticProcedureSummary::try_new(
                key_by_node[member]
                    .clone()
                    .expect("member key created before lowering"),
                transfers,
                effects,
                dependencies,
                completeness,
            )
            .map_err(|source| invalid_summary(summary, source))?;
            summaries.push(lowered);
        }

        for &dependent in &dependents_by_component[component] {
            remaining_dependencies[dependent] = remaining_dependencies[dependent]
                .checked_sub(1)
                .ok_or(ProcedureSummaryBindingError::InvalidRecursion)?;
            if remaining_dependencies[dependent] == 0 {
                ready.push(Reverse(dependent));
            }
        }
    }
    if emitted_components != components.len() {
        return Err(ProcedureSummaryBindingError::InvalidRecursion);
    }

    ExternalSemanticSummarySet::try_new(summaries, compatibility).map_err(|error| match error {
        ExternalSummarySetError::AmbiguousTarget => ProcedureSummaryBindingError::AmbiguousTarget {
            summary_id: "<structured target>".to_owned(),
        },
        ExternalSummarySetError::IncompatibleSummary | ExternalSummarySetError::InferredSummary => {
            ProcedureSummaryBindingError::IncompatibleCompatibilityKey {
                summary_id: "<summary family>".to_owned(),
            }
        }
    })
}

fn dependency_keys(
    member: usize,
    component: usize,
    graph: &ProcedureDependencyGraph,
    component_by_node: &[usize],
    identities: &[ProcedureSummaryIdentity],
    key_by_node: &[Option<ProcedureSummaryKey>],
) -> Vec<SummaryDependencyKey> {
    graph.outgoing[member]
        .iter()
        .map(|&edge| {
            let callee = graph.edges[edge].1;
            if component_by_node[callee] == component {
                SummaryDependencyKey::recursive(identities[callee].clone())
            } else {
                SummaryDependencyKey::complete(
                    key_by_node[callee]
                        .clone()
                        .expect("dependency component emitted first"),
                )
            }
        })
        .collect()
}

fn bind_locations(
    summary: &CompiledProcedureSummary,
) -> Result<
    HashMap<&str, (CompiledSummaryLocationKind, SummaryLocationKey)>,
    ProcedureSummaryBindingError,
> {
    let mut locations = map_with_capacity(summary.locations.len());
    for location in &summary.locations {
        if locations
            .insert(
                location.id.as_str(),
                (
                    location.location_kind,
                    SummaryLocationKey::from_digest(stable_record_key(
                        LOCATION_KEY_DOMAIN,
                        summary,
                        &location.id,
                    )),
                ),
            )
            .is_some()
        {
            return Err(ProcedureSummaryBindingError::UnsupportedLocationBinding {
                summary_id: summary.id.clone(),
                location_id: location.id.clone(),
            });
        }
    }
    Ok(locations)
}

fn model_evidence(
    summary: &CompiledProcedureSummary,
) -> Result<SummaryEvidence, ProcedureSummaryBindingError> {
    let incomplete = match summary.completeness {
        Completeness::Complete => Vec::new(),
        Completeness::Partial => vec![MODEL_INCOMPLETE_REASON.to_owned()],
    };
    SummaryEvidence::try_new(vec![MODEL_UNPROVEN_REASON.to_owned()], incomplete)
        .map_err(|source| invalid_summary(summary, source))
}

fn lower_transfer(
    summary: &CompiledProcedureSummary,
    binding: &ExactProcedureSummaryTargetBinding,
    locations: &HashMap<&str, (CompiledSummaryLocationKind, SummaryLocationKey)>,
    transfer: &super::CompiledSummaryTransfer,
    evidence: &SummaryEvidence,
) -> Result<SummaryTransfer, ProcedureSummaryBindingError> {
    let input = lower_input(summary, binding, &transfer.input)?;
    let kind = match transfer.exit_kind {
        CompiledSummaryExitKind::Normal => SummaryExitKind::Normal,
        CompiledSummaryExitKind::Exceptional => SummaryExitKind::Exceptional,
    };
    let output = lower_output(summary, binding, locations, &transfer.output)?;
    let exit =
        SummaryExit::try_new(kind, output).map_err(|source| invalid_summary(summary, source))?;
    SummaryTransfer::try_new(input, exit, evidence.clone())
        .map_err(|source| invalid_summary(summary, source))
}

#[allow(clippy::too_many_arguments)]
fn lower_effect(
    summary: &CompiledProcedureSummary,
    binding: &ExactProcedureSummaryTargetBinding,
    locations: &HashMap<&str, (CompiledSummaryLocationKind, SummaryLocationKey)>,
    effect: &CompiledSummaryEffect,
    evidence: &SummaryEvidence,
    dependencies: &[SummaryDependencyKey],
    key_by_node: &[Option<ProcedureSummaryKey>],
    records: &[&CompiledProcedureSummary],
) -> Result<SummaryEffect, ProcedureSummaryBindingError> {
    let event_name = match effect {
        CompiledSummaryEffect::Allocation { event, .. }
        | CompiledSummaryEffect::Call { event, .. }
        | CompiledSummaryEffect::Escape { event, .. }
        | CompiledSummaryEffect::UnknownCall { event, .. }
        | CompiledSummaryEffect::UnknownCallBoundary { event }
        | CompiledSummaryEffect::AmbiguousCall { event, .. } => event,
    };
    let event =
        SummaryEventKey::from_digest(stable_record_key(EVENT_KEY_DOMAIN, summary, event_name));
    let key = match effect {
        CompiledSummaryEffect::Allocation { output, .. } => SummaryEffectKey::Allocation {
            event,
            output: lower_output(summary, binding, locations, output)?,
        },
        CompiledSummaryEffect::Call { callee, .. } => SummaryEffectKey::Call {
            event,
            callee: Box::new(find_dependency(
                summary,
                callee,
                dependencies,
                key_by_node,
                records,
            )?),
        },
        CompiledSummaryEffect::Escape { input, .. } => SummaryEffectKey::Escape {
            event,
            input: lower_input(summary, binding, input)?,
        },
        CompiledSummaryEffect::UnknownCall { input, .. } => SummaryEffectKey::UnknownCall {
            event,
            input: lower_input(summary, binding, input)?,
        },
        CompiledSummaryEffect::UnknownCallBoundary { .. } => {
            SummaryEffectKey::UnknownCallBoundary { event }
        }
        CompiledSummaryEffect::AmbiguousCall {
            input, candidates, ..
        } => {
            let candidates = candidates
                .iter()
                .map(|callee| find_dependency(summary, callee, dependencies, key_by_node, records))
                .collect::<Result<Vec<_>, _>>()?;
            SummaryEffectKey::ambiguous_call(
                event,
                lower_input(summary, binding, input)?,
                candidates,
            )
            .map_err(|source| invalid_summary(summary, source))?
        }
    };
    Ok(SummaryEffect::new(key, evidence.clone()))
}

fn find_dependency(
    summary: &CompiledProcedureSummary,
    callee_id: &str,
    dependencies: &[SummaryDependencyKey],
    key_by_node: &[Option<ProcedureSummaryKey>],
    records: &[&CompiledProcedureSummary],
) -> Result<SummaryDependencyKey, ProcedureSummaryBindingError> {
    let callee = records
        .binary_search_by(|record| record.id.as_str().cmp(callee_id))
        .map_err(|_| ProcedureSummaryBindingError::UnboundCallee {
            summary_id: summary.id.clone(),
            callee_id: callee_id.to_owned(),
        })?;
    let identity = key_by_node[callee]
        .as_ref()
        .expect("callee key created before effect lowering")
        .identity();
    dependencies
        .iter()
        .find(|dependency| dependency.identity() == identity)
        .cloned()
        .ok_or_else(|| ProcedureSummaryBindingError::UnboundCallee {
            summary_id: summary.id.clone(),
            callee_id: callee_id.to_owned(),
        })
}

fn lower_input(
    summary: &CompiledProcedureSummary,
    binding: &ExactProcedureSummaryTargetBinding,
    input: &CompiledSummaryInput,
) -> Result<SummaryPort, ProcedureSummaryBindingError> {
    match input {
        CompiledSummaryInput::Receiver {} if binding.boundary.receiver().is_some() => {
            Ok(SummaryPort::Receiver)
        }
        CompiledSummaryInput::Parameter { ordinal }
            if binding
                .boundary
                .parameters()
                .iter()
                .any(|parameter| parameter.ordinal() == *ordinal) =>
        {
            Ok(SummaryPort::Parameter(*ordinal))
        }
        CompiledSummaryInput::Receiver {} | CompiledSummaryInput::Parameter { .. } => {
            Err(ProcedureSummaryBindingError::TargetMismatch {
                summary_id: summary.id.clone(),
            })
        }
    }
}

fn lower_output(
    summary: &CompiledProcedureSummary,
    binding: &ExactProcedureSummaryTargetBinding,
    locations: &HashMap<&str, (CompiledSummaryLocationKind, SummaryLocationKey)>,
    output: &CompiledSummaryOutput,
) -> Result<SummaryPort, ProcedureSummaryBindingError> {
    match output {
        CompiledSummaryOutput::NormalReturn {} => Ok(SummaryPort::NormalReturn),
        CompiledSummaryOutput::ExceptionalReturn {} => Ok(SummaryPort::ExceptionalReturn),
        CompiledSummaryOutput::Receiver {} if binding.boundary.receiver().is_some() => {
            Ok(SummaryPort::Receiver)
        }
        CompiledSummaryOutput::Receiver {} => Err(ProcedureSummaryBindingError::TargetMismatch {
            summary_id: summary.id.clone(),
        }),
        CompiledSummaryOutput::Capture { location } => lower_location(
            summary,
            locations,
            location,
            CompiledSummaryLocationKind::Capture,
        )
        .map(SummaryPort::Capture),
        CompiledSummaryOutput::Heap { location } => lower_location(
            summary,
            locations,
            location,
            CompiledSummaryLocationKind::Heap,
        )
        .map(SummaryPort::Heap),
    }
}

fn lower_location(
    summary: &CompiledProcedureSummary,
    locations: &HashMap<&str, (CompiledSummaryLocationKind, SummaryLocationKey)>,
    location_id: &str,
    expected_kind: CompiledSummaryLocationKind,
) -> Result<SummaryLocationKey, ProcedureSummaryBindingError> {
    locations
        .get(location_id)
        .filter(|(actual_kind, _)| *actual_kind == expected_kind)
        .map(|(_, key)| *key)
        .ok_or_else(
            || ProcedureSummaryBindingError::UnsupportedLocationBinding {
                summary_id: summary.id.clone(),
                location_id: location_id.to_owned(),
            },
        )
}

fn stable_record_key(
    domain: &[u8],
    summary: &CompiledProcedureSummary,
    local_id: &str,
) -> StableDigest {
    let mut hasher = CanonicalHasher::new(domain);
    hasher.field("model_id", summary.model_id.as_bytes());
    hasher.field("record_id", summary.id.as_bytes());
    hasher.field("local_id", local_id.as_bytes());
    StableDigest::from_array(hasher.finish())
}

fn invalid_summary(
    summary: &CompiledProcedureSummary,
    source: SummaryValidationError,
) -> ProcedureSummaryBindingError {
    ProcedureSummaryBindingError::InvalidSummary {
        summary_id: summary.id.clone(),
        source,
    }
}

#[derive(Debug)]
struct ProcedureDependencyGraph {
    edges: Vec<(usize, usize)>,
    outgoing: Vec<Vec<usize>>,
    incoming: Vec<Vec<usize>>,
}

impl ProcedureDependencyGraph {
    fn new(dependencies: Vec<Vec<usize>>) -> Self {
        let mut edges = dependencies
            .iter()
            .enumerate()
            .flat_map(|(caller, callees)| callees.iter().map(move |&callee| (caller, callee)))
            .collect::<Vec<_>>();
        edges.sort_unstable();
        edges.dedup();
        let mut outgoing = vec![Vec::new(); dependencies.len()];
        let mut incoming = vec![Vec::new(); dependencies.len()];
        for (edge, &(caller, callee)) in edges.iter().enumerate() {
            outgoing[caller].push(edge);
            incoming[callee].push(edge);
        }
        Self {
            edges,
            outgoing,
            incoming,
        }
    }
}

impl DenseBidirectionalGraph for ProcedureDependencyGraph {
    type Node = usize;
    type Edge = usize;

    fn node_count(&self) -> usize {
        self.outgoing.len()
    }

    fn node_at(&self, index: usize) -> Option<Self::Node> {
        (index < self.outgoing.len()).then_some(index)
    }

    fn node_index(&self, node: Self::Node) -> Option<usize> {
        (node < self.outgoing.len()).then_some(node)
    }

    fn successors(
        &self,
        node: Self::Node,
    ) -> impl DoubleEndedIterator<Item = (Self::Edge, Self::Node)> + ExactSizeIterator + '_ {
        self.outgoing[node]
            .iter()
            .copied()
            .map(|edge| (edge, self.edges[edge].1))
    }

    fn predecessors(
        &self,
        node: Self::Node,
    ) -> impl DoubleEndedIterator<Item = (Self::Edge, Self::Node)> + ExactSizeIterator + '_ {
        self.incoming[node]
            .iter()
            .copied()
            .map(|edge| (edge, self.edges[edge].0))
    }

    fn edge_endpoints(&self, edge: Self::Edge) -> Option<(Self::Node, Self::Node)> {
        self.edges.get(edge).copied()
    }
}
